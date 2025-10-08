#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2025, DZIDULA JUBILEE GATI
#
# Licensed under the AGPL-3.0 License.
# Based on Wazuh's official integration framework and MISP integration.
#
# Description:
#   Wazuh - Yeti integration.
#   Enriches Sysmon/syscheck alerts with Yeti threat intelligence.
#   Sends Threat Found: Yeti Intel Matches back to Wazuh via socket when a match is found.

import json
import os
import sys
import re
from socket import AF_UNIX, SOCK_DGRAM, socket

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install it with: pip install requests")
    sys.exit(1)

# === Exit codes (consistent with Wazuh official style) ===
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_SOCKET_OPERATION = 3
ERR_FILE_NOT_FOUND = 4
ERR_INVALID_JSON = 5
ERR_YETI_AUTH = 6
ERR_YETI_RESPONSE = 7

# === Globals ===
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

# === Argument indexes ===
ALERT_INDEX = 1
APIKEY_INDEX = 2
YETI_URL_INDEX = 3

# IOC mappings
IOCS = [
    ("ip_src", ["src_ip", "source_ip", "srcip", "SourceIP", "client_ip", "IPAddress", "CallerIPAddress"]),
    ("ip_dst", ["dst_ip", "destination_ip", "dstip", "DestinationIP", "remote_ip", "external_ip"]),
    ("sha1",   ["sha1", "sha1sum", "file_sha1"]),
    ("sha256", ["sha256", "sha256sum", "file_sha256"]),
    ("md5",    ["md5", "md5sum", "file_md5"]),
    ("url",    ["url", "source_url", "TargetURL", "download_url"]),
    ("domain", ["domain", "hostname", "base_domain", "fqdn", "TargetDestination"])
]


# === Utility functions ===
def debug(msg: str) -> None:
    """Write debug messages to integration log."""
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def send_msg(msg: any, agent: any = None) -> None:
    """Send message back to Wazuh via the UNIX socket."""
    if not agent or agent.get("id") == "000":
        string = "1:yeti_integration:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(
            agent["id"],
            agent["name"],
            agent.get("ip", "any")
        ).replace("|", "||").replace(":", "|:")
        string = "1:{0}->yeti_integration:{1}".format(location, json.dumps(msg))

    debug(f"# Sending result back to Wazuh: {string}")

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug(f"# Error: Unable to open socket connection at {SOCKET_ADDR}")
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert from file."""
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug(f"# JSON alert file not found at {file_location}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug(f"Failed to parse JSON alert file: {e}")
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> dict:
    """Load JSON options from file if exists."""
    if not file_location:
        return {}
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug(f"# Options file not found at {file_location}")
        return {}
    except Exception as e:
        debug(f"# Failed parsing options JSON: {e}")
        sys.exit(ERR_INVALID_JSON)


def extract_iocs(alert: dict) -> dict:
    """Extract IOCs from alert JSON based on mapping."""
    found = {}

    def flatten(obj):
        flat = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                flat[k] = v
                if isinstance(v, dict):
                    flat.update(flatten(v))
                elif isinstance(v, list):
                    for i, it in enumerate(v):
                        if isinstance(it, dict):
                            flat.update(flatten(it))
        return flat

    flat = flatten(alert)
    for canon, keys in IOCS:
        vals = set()
        for key in keys:
            for k, v in flat.items():
                if key.lower() in k.lower() and isinstance(v, (str, int, float)):
                    vals.add(str(v))
        if vals:
            found[canon] = list(vals)
    return found


def get_yeti_token(yeti_url, api_key):
    """Authenticate to Yeti using API key -> JWT token."""
    try:
        response = requests.post(
            f"{yeti_url.rstrip('/')}/auth/api-token",
            headers={"x-yeti-apikey": api_key},
            timeout=timeout
        )
        if response.status_code not in (200, 201):
            raise Exception(f"Bad status {response.status_code}: {response.text}")
        data = response.json()
        token = data.get("access_token") or data.get("token")
        if not token:
            raise Exception("No token returned from Yeti")
        return token
    except Exception as e:
        debug(f"# Error authenticating to Yeti: {e}")
        sys.exit(ERR_YETI_AUTH)


def query_yeti(yeti_url, token, value):
    """Query Yeti for an observable."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            f"{yeti_url.rstrip('/')}/observables?value={value}",
            headers=headers,
            timeout=timeout
        )
        if response.status_code == 200 and response.text.strip():
            return response.json()
        return {}
    except Timeout:
        debug("# Error: Yeti query timed out")
        return {}
    except Exception as e:
        debug(f"# Error querying Yeti: {e}")
        return {}


def process_alert(alert, yeti_url, api_key):
    """Main logic â€” extract IOCs, query Yeti, and send alert if found."""
    token = get_yeti_token(yeti_url, api_key)
    iocs = extract_iocs(alert)

    if not iocs:
        debug("# No IOCs found in alert.")
        return

    matches = []
    for ioc_type, values in iocs.items():
        for val in values:
            res = query_yeti(yeti_url, token, val)
            if res:
                matches.append({"ioc": val, "type": ioc_type, "result": res})

    msg = {
        "integration": "yeti_integration",
        "event": "Threat Found: Yeti Intel Match",
        "found": len(matches),
        "yeti_matches": matches
    }

    if matches:
        debug(f"# Threat Found: {len(matches)} match(es) found in Yeti.")
        send_msg(msg, alert.get("agent"))
    else:
        debug("# No matches found in Yeti.")


def main(args):
    global debug_enabled
    global timeout
    global retries

    if len(args) < 4:
        print("Usage: custom-yeti.py <alert_file> <api_key> <yeti_url> [options]")
        sys.exit(ERR_BAD_ARGUMENTS)

    alert_file = args[ALERT_INDEX]
    api_key = args[APIKEY_INDEX]
    yeti_url = args[YETI_URL_INDEX]

    # Locate optional options file
    options_file = ""
    for arg in args[4:]:
        if arg.endswith("options"):
            options_file = arg
            break

    json_options = get_json_options(options_file)
    debug(f"# Loaded options: {json_options}")

    # Apply options
    if "timeout" in json_options and isinstance(json_options["timeout"], int):
        timeout = json_options["timeout"]

    if "retries" in json_options and isinstance(json_options["retries"], int):
        retries = json_options["retries"]

    if "debug" in json_options and isinstance(json_options["debug"], bool):
        debug_enabled = json_options["debug"]

    alert = get_json_alert(alert_file)
    process_alert(alert, yeti_url, api_key)


if __name__ == "__main__":
    main(sys.argv)

