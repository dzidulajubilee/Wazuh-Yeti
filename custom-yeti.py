# Copyright (C) 2025, DZIDULA JUBILEE GATI

#!/usr/bin/env python3
# ==============================================================================
# Wazuh → Yeti Threat Intelligence Integration
# File: /var/ossec/integrations/custom-yeti
# ==============================================================================
# This script is called by Wazuh whenever an alert fires.
# It extracts observables (IPs, domains, hashes, URLs) from the alert,
# queries Yeti for matching IOCs, and if any are found it injects a new
# high-severity alert back into Wazuh so the dashboard shows
# "Threat and IOC Found".
# ==============================================================================

import json
import logging
import re
import socket
import sys
from datetime import datetime, timezone

import requests

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# Wazuh calls this script as:
#   custom-yeti <alert_file> <hook_url> <api_key>
# Those map to sys.argv[1], sys.argv[2], sys.argv[3] respectively.
# All three come straight from ossec.conf — no environment variables needed.
# ──────────────────────────────────────────────────────────────────────────────
LOG_FILE     = "/var/ossec/logs/yeti-integration.log"
WAZUH_SOCKET = "/var/ossec/queue/sockets/queue"

# Wazuh rule IDs that should trigger an IOC lookup (empty list = all alerts)
# Example: TRIGGER_RULE_IDS = {5501, 5502, 31103}
TRIGGER_RULE_IDS: set = set()

# Minimum Wazuh alert level that triggers an IOC lookup (0 = all alerts)
MIN_ALERT_LEVEL = 0

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("yeti-integration")


# ──────────────────────────────────────────────────────────────────────────────
# Yeti API helpers
# ──────────────────────────────────────────────────────────────────────────────
class YetiClient:
    """Minimal Yeti v2 API client with automatic JWT refresh."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._access_token: str | None = None

    # ── Authentication ────────────────────────────────────────────────────────
    def authenticate(self) -> bool:
        """Exchange API key for a Bearer JWT access token."""
        try:
            resp = self.session.post(
                f"{self.base_url}/api/v2/auth/api-token",
                headers={"x-yeti-apikey": self.api_key},
                timeout=10,
            )
            resp.raise_for_status()
            self._access_token = resp.json().get("access_token")
            if not self._access_token:
                log.error("Yeti auth: no access_token in response: %s", resp.text)
                return False
            self.session.headers.update(
                {"Authorization": f"Bearer {self._access_token}"}
            )
            log.info("Yeti authentication successful.")
            return True
        except Exception as exc:
            log.error("Yeti authentication failed: %s", exc)
            return False

    # ── Observable lookup ─────────────────────────────────────────────────────
    def search_observable(self, value: str) -> list[dict]:
        """
        Search Yeti for a single observable value.
        Returns a list of matching observable objects (may be empty).
        """
        if not self._access_token and not self.authenticate():
            return []
        try:
            payload = {
                "query": {"value": value},
                "count": 10,
                "page": 0,
            }
            resp = self.session.post(
                f"{self.base_url}/api/v2/observables/search",
                json=payload,
                timeout=10,
            )
            if resp.status_code == 401:
                # Token expired – refresh once
                log.info("Token expired, re-authenticating …")
                if self.authenticate():
                    resp = self.session.post(
                        f"{self.base_url}/api/v2/observables/search",
                        json=payload,
                        timeout=10,
                    )
                else:
                    return []
            resp.raise_for_status()
            data = resp.json()
            return data.get("observables", [])
        except Exception as exc:
            log.error("Yeti search_observable(%r) failed: %s", value, exc)
            return []

    def enrich_observable(self, yeti_id: str) -> dict:
        """Fetch full observable detail (tags, context, relationships) by ID."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v2/observables/{yeti_id}",
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.warning("Could not enrich observable %s: %s", yeti_id, exc)
            return {}


# ──────────────────────────────────────────────────────────────────────────────
# Observable extraction from Wazuh alert JSON
# ──────────────────────────────────────────────────────────────────────────────
# Regex patterns for each observable type
_RE_IPV4    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                         r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_DOMAIN  = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                         r"[a-zA-Z]{2,}\b")
_RE_MD5     = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1    = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256  = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_URL     = re.compile(r"https?://[^\s\"'<>]+")

def _flatten(obj, prefix="") -> dict[str, str]:
    """Recursively flatten a nested dict to {dotted.path: value} strings."""
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flat.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flat.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        flat[prefix] = str(obj)
    return flat


def extract_observables(alert: dict) -> dict[str, set[str]]:
    """
    Walk every field in the Wazuh alert JSON and collect candidate observables.
    Returns a dict keyed by type: {'ip': {...}, 'domain': {...}, 'hash': {...}, 'url': {...}}
    """
    ips, domains, hashes, urls = set(), set(), set(), set()

    flat = _flatten(alert)
    all_values = " ".join(flat.values())

    # ── URLs (extract first, then strip from further analysis) ────────────────
    for url in _RE_URL.findall(all_values):
        urls.add(url[:512])  # cap length

    # Strip URLs from the string before hunting for loose IPs / domains
    stripped = _RE_URL.sub(" ", all_values)

    # ── IPs ───────────────────────────────────────────────────────────────────
    for ip in _RE_IPV4.findall(stripped):
        ips.add(ip)

    # ── Domains (avoid false-positives from file paths / Windows paths) ───────
    for dom in _RE_DOMAIN.findall(stripped):
        # Filter out obvious non-domains (single TLD artefacts, local names)
        if "." in dom and not dom.endswith(".log") and not dom.endswith(".conf"):
            domains.add(dom.lower())

    # ── Hashes (priority: longest first to avoid substring collisions) ────────
    for h in _RE_SHA256.findall(all_values):
        hashes.add(h.lower())
    for h in _RE_SHA1.findall(all_values):
        hashes.add(h.lower())
    for h in _RE_MD5.findall(all_values):
        hashes.add(h.lower())

    return {"ip": ips, "domain": domains, "hash": hashes, "url": urls}


# ──────────────────────────────────────────────────────────────────────────────
# Wazuh socket – inject a synthetic alert
# ──────────────────────────────────────────────────────────────────────────────
def send_to_wazuh(event: dict) -> None:
    """
    Write a synthetic alert into the Wazuh manager queue socket.
    Format expected by the manager:  1:<location>:<json_event>
    """
    try:
        msg = "1:yeti-ioc-integration:" + json.dumps(event)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(WAZUH_SOCKET)
            sock.send(msg.encode("utf-8"))
        log.info("Event sent to Wazuh socket: %s", msg[:200])
    except Exception as exc:
        log.error("Failed to send event to Wazuh socket: %s", exc)


def build_ioc_alert(original_alert: dict, matches: list[dict]) -> dict:
    """
    Construct the synthetic alert payload that Wazuh will index and display.
    The custom rule (rule ID 100200) will surface this as "Threat and IOC Found".
    """
    agent  = original_alert.get("agent", {})
    rule   = original_alert.get("rule", {})
    ioc_summary = []

    for m in matches:
        obs   = m.get("observable", {})
        tags  = [t.get("name", "") for t in obs.get("tags", [])]
        ioc_summary.append({
            "value":     obs.get("value", m.get("queried_value", "unknown")),
            "type":      obs.get("type", "unknown"),
            "tags":      tags,
            "context":   obs.get("context", []),
            "yeti_id":   obs.get("id", ""),
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "integration": "yeti",
        "yeti": {
            "result": "Threat and IOC Found",
            "ioc_count": len(ioc_summary),
            "iocs": ioc_summary,
            "source_rule": {
                "id":    rule.get("id", ""),
                "level": rule.get("level", ""),
                "description": rule.get("description", ""),
            },
        },
        "agent": {
            "id":   agent.get("id", ""),
            "name": agent.get("name", ""),
            "ip":   agent.get("ip", ""),
        },
        "original_alert_id": original_alert.get("id", ""),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # Wazuh calls:  custom-yeti <alert_file> <hook_url> <api_key>
    if len(sys.argv) < 4:
        log.error("Usage: custom-yeti <alert_file> <yeti_url> <api_key>")
        sys.exit(1)

    alert_file = sys.argv[1]
    YETI_URL   = sys.argv[2].rstrip("/")
    YETI_APIKEY = sys.argv[3]
    try:
        with open(alert_file, "r", encoding="utf-8") as fh:
            alert = json.load(fh)
    except Exception as exc:
        log.error("Cannot read alert file %r: %s", alert_file, exc)
        sys.exit(1)

    # ── Filtering: skip if rule ID / level doesn't meet threshold ─────────────
    rule_id    = int(alert.get("rule", {}).get("id", 0))
    rule_level = int(alert.get("rule", {}).get("level", 0))

    if TRIGGER_RULE_IDS and rule_id not in TRIGGER_RULE_IDS:
        log.debug("Rule %d not in TRIGGER_RULE_IDS – skipping.", rule_id)
        sys.exit(0)

    if rule_level < MIN_ALERT_LEVEL:
        log.debug("Rule level %d below MIN_ALERT_LEVEL %d – skipping.",
                  rule_level, MIN_ALERT_LEVEL)
        sys.exit(0)

    log.info("Processing alert: rule=%d level=%d agent=%s",
             rule_id, rule_level, alert.get("agent", {}).get("name", "?"))

    # ── Observable extraction ──────────────────────────────────────────────────
    observables = extract_observables(alert)
    all_values  = (
        observables["ip"]     |
        observables["domain"] |
        observables["hash"]   |
        observables["url"]
    )

    if not all_values:
        log.info("No observables found in alert %d – skipping.", rule_id)
        sys.exit(0)

    log.info("Extracted %d observable(s): %s",
             len(all_values), ", ".join(list(all_values)[:10]))

    # ── Yeti lookups ───────────────────────────────────────────────────────────
    client = YetiClient(YETI_URL, YETI_APIKEY)
    matches = []

    for value in all_values:
        results = client.search_observable(value)
        for obs in results:
            log.info("IOC MATCH: %r → %s (tags: %s)",
                     value,
                     obs.get("value", "?"),
                     [t.get("name") for t in obs.get("tags", [])])
            matches.append({"queried_value": value, "observable": obs})

    # ── Report findings ────────────────────────────────────────────────────────
    if not matches:
        log.info("No IOC matches for alert %d.", rule_id)
        sys.exit(0)

    log.warning("THREAT DETECTED – %d IOC(s) matched for alert %d",
                len(matches), rule_id)

    ioc_alert = build_ioc_alert(alert, matches)
    send_to_wazuh(ioc_alert)
    sys.exit(0)


if __name__ == "__main__":
    main()      
