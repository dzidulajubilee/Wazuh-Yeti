# Wazuh ↔ Yeti Threat Intelligence Integration

Whenever a Wazuh alert fires this integration automatically queries your Yeti
instance for matching Indicators of Compromise (IOCs).  If any are found, a
new alert is injected back into Wazuh at severity **level 12** so the
Wazuh dashboard displays **"Threat and IOC Found"**.

---

## Architecture

```
Wazuh Agent  ──►  Wazuh Manager  ──►  custom-yeti script
                                              │
                                              ▼
                                      Yeti  /api/v2/observables/search
                                              │
                              IOC found?   ◄──┘ 
                                    │
                                    ▼
                      Wazuh queue socket  ──►  Rule 100201 fires
                                                    │
                                                    ▼
                                          Wazuh Dashboard
                                      "Threat and IOC Found"
```

Observables extracted from every alert:

| Type    | Example                                    |
|---------|--------------------------------------------|
| IPv4    | `192.0.2.1`                                |
| Domain  | `malicious-c2.example.com`                 |
| MD5     | `d41d8cd98f00b204e9800998ecf8427e`         |
| SHA1    | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256  | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4…` |
| URL     | `https://malware.example.com/payload.exe`  |

All IPs are looked up without exception, including private and loopback ranges — useful for tracking lateral movement and internal IOCs tagged in Yeti.

---

## File Layout

```
/var/ossec/
├── integrations/
│   └── custom-yeti              ← main Python script
├── etc/
│   ├── ossec.conf               ← add <integration> block from docs/
│   ├── decoders/
│   │   └── yeti-decoder.xml     ← custom decoder
│   └── rules/
│       └── yeti-rules.xml       ← custom rules (100200–100205)
└── logs/
    └── yeti-integration.log     ← written by the script
```

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Wazuh Manager | ≥ 4.4  |
| Python | ≥ 3.10 on the manager node |
| `requests` library | `pip3 install requests` |
| Yeti | ≥ v2 (REST API v2) |
| Network access | Manager → Yeti TCP (default port 8000) |

---

## Installation

### 1 – Copy the integration script

```bash
# Copy the script
cp integrations/custom-yeti /var/ossec/integrations/custom-yeti

# The file must be owned by root and executable
chmod 750  /var/ossec/integrations/custom-yeti
chown root:wazuh /var/ossec/integrations/custom-yeti
```

### 2 – Copy the decoder

```bash
cp rules/yeti-decoder.xml /var/ossec/etc/decoders/yeti-decoder.xml
chown root:wazuh /var/ossec/etc/decoders/yeti-decoder.xml
chmod 640  /var/ossec/etc/decoders/yeti-decoder.xml
```

### 3 – Copy the rules

```bash
cp rules/yeti-rules.xml /var/ossec/etc/rules/yeti-rules.xml
chown root:wazuh /var/ossec/etc/rules/yeti-rules.xml
chmod 640  /var/ossec/etc/rules/yeti-rules.xml
```

### 4 – Configure ossec.conf

Open `/var/ossec/etc/ossec.conf` and paste the `<integration>` block from
`docs/ossec-conf-snippet.xml` inside `<ossec_config>`.

Replace the two placeholder values:

| Placeholder | Replace with |
|---|---|
| `YOUR_YETI_HOST` | Hostname or IP of your Yeti server |
| `YOUR_YETI_API_KEY` | Your Yeti user API key (from Yeti → profile) |

### 5 – Install Python dependency

```bash
pip3 install requests
```

### 6 – Validate configuration and restart

```bash
# Validate ossec.conf
/var/ossec/bin/wazuh-logtest -t

# Restart the manager
systemctl restart wazuh-manager

# Tail the integration log
tail -f /var/ossec/logs/yeti-integration.log
```

---

## Testing the Integration

### Test Yeti connectivity

```bash
python3 - <<'EOF'
import requests
YETI_URL    = "http://YOUR_YETI_HOST:8000"
YETI_APIKEY = "YOUR_KEY_HERE"

r = requests.post(f"{YETI_URL}/api/v2/auth/api-token",
                  headers={"x-yeti-apikey": YETI_APIKEY})
print("Auth status:", r.status_code)
token = r.json().get("access_token")

s = requests.Session()
s.headers["Authorization"] = f"Bearer {token}"
r2 = s.post(f"{YETI_URL}/api/v2/observables/search",
            json={"query": {"value": "8.8.8.8"}, "count": 5})
print("Search status:", r2.status_code, r2.json())
EOF
```

### Inject a synthetic alert to trigger the script

```bash
# Create a minimal alert JSON file
cat > /tmp/test-alert.json << 'EOF'
{
  "id": "test-001",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "rule": { "id": "5501", "level": 7, "description": "SSH brute force" },
  "agent": { "id": "001", "name": "test-agent", "ip": "10.0.0.1" },
  "data": { "srcip": "1.2.3.4", "dstip": "8.8.8.8" }
}
EOF

# Run the script manually — same arg order Wazuh uses
python3 /var/ossec/integrations/custom-yeti \
  /tmp/test-alert.json \
  http://YOUR_YETI_HOST:8000 \
  YOUR_KEY
```

---

## Wazuh Dashboard Visualisation

After the integration fires and rule **100201** triggers you will see alerts
grouped under:

* **Module**: Custom rules  
* **Rule ID**: 100201  
* **Description**: `Threat and IOC Found: <N> indicator(s) matched in Yeti …`  
* **Group**: `yeti`, `ioc_found`, `threat_intel`

### Recommended dashboard saved search fields

| Field | Purpose |
|---|---|
| `rule.description` | Shows "Threat and IOC Found …" |
| `agent.name` | Which endpoint triggered |
| `yeti.ioc_count` | How many IOCs matched |
| `yeti.iocs.value` | The matched observable value |
| `yeti.iocs.type` | ip / hostname / hash / url |
| `yeti.iocs.tags` | Threat tags from Yeti |
| `yeti.source_rule.description` | Original alert that triggered the lookup |

---

## Tuning

### Reduce API noise

Set `MIN_ALERT_LEVEL` in the script or use the `<level>` tag in `ossec.conf`
to only forward alerts of sufficient severity (recommended ≥ 7).

Use `<rule_id>` or `<group>` filters in `ossec.conf` to target only
network/authentication events.

### Increase coverage

Lower `MIN_ALERT_LEVEL` to `3` and remove the group filter to scan every
single alert — keep an eye on Yeti API rate limits in that case.

### Custom rule severity

Edit `yeti-rules.xml`:
* Level 12 = High (default for IP/domain/URL matches)
* Level 14 = Critical (default for hash/malware matches)
* Raise to 15 to trigger PagerDuty / email alerts via Wazuh active response

---

## Troubleshooting

| Symptom | Check |
|---|---|
| No log entries at all | `ls -la /var/ossec/integrations/custom-yeti` — must be executable |
| `Authentication failed` | Verify the `<api_key>` value in `ossec.conf` and Yeti URL reachability |
| Alerts injected but rule 100201 never fires | Confirm `yeti-decoder.xml` and `yeti-rules.xml` are deployed and manager restarted |
| Too many / too few lookups | Adjust `<level>` and `<rule_id>` in `ossec.conf` |
| `requests` not found | `pip3 install requests` on the manager node |

---

## Security Notes

* The Yeti API key lives in `ossec.conf` inside the `<api_key>` tag — the standard Wazuh way.
* In production, ensure the manager → Yeti connection is over TLS (`<hook_url>https://…</hook_url>`).
* The integration script runs as the `ossec` user — keep file permissions at `750 root:wazuh`.
