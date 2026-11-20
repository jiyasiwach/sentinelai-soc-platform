# Sample data

Files for trying the ingest and import features. All indicators are documentation-safe:
RFC 5737 IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), private 10.x addresses, `.example`
domains and well-known test hashes. Nothing here refers to a real network.

| File | Use it in | Format picker |
|---|---|---|
| `wazuh_alerts.json` | Alerts -> Ingest -> upload | `auto` or `wazuh` |
| `splunk_alerts.json` | Alerts -> Ingest -> upload | `auto` or `splunk` |
| `elastic_alerts.json` | Alerts -> Ingest -> upload | `auto` or `elastic` |
| `generic_alerts.jsonl` | Alerts -> Ingest -> upload (JSON Lines, one alert per line) | `auto` or `generic` |
| `nmap_scan.xml` | Vulnerabilities -> Import -> Nmap XML | - |
| `va_findings.json` | Vulnerabilities -> Import -> Findings JSON | - |

`nmap_scan.xml` mimics the output of an **authorised** scan (`nmap -sV -O -oX nmap_scan.xml <scope>`).
Importing it creates `legacy-ftp-01` and `cache-01`, updates `hr-ws-03`, and raises findings for the
risky exposed services (FTP 21, Telnet 23, VNC 5900, Redis 6379, Elasticsearch 9200, RDP 3389).

From the command line (after logging in to get a token):

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -d 'username=analyst&password=Analyst@12345' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" -F file=@sample-data/wazuh_alerts.json -F format=auto -F investigate=true localhost:8000/api/alerts/upload
curl -s -H "Authorization: Bearer $TOKEN" -F file=@sample-data/nmap_scan.xml localhost:8000/api/va/import/nmap
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data @sample-data/va_findings.json localhost:8000/api/va/vulnerabilities
```
