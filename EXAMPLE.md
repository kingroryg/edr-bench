# Running edr-bench against EDR tools

This guide walks through setting up edr-bench with several EDR products -- both open source and commercial. The general flow is always the same:

1. Install your EDR agent on the victim-linux container
2. Configure edr-bench to read alerts from that EDR
3. Run the benchmark
4. Read the report

## Prerequisites

```bash
# install edr-bench
pip install -e ".[dev]"
cp .env.example .env

# build containers
make build PROFILE=linux

# validate scenarios
edr-bench validate data/scenarios/
```

---

## Wazuh (open source)

Wazuh is a free, open source SIEM and XDR platform. It has agents for Linux, Windows, and macOS, and detects file integrity changes, rootkits, suspicious processes, and network anomalies.

### 1. Set up Wazuh manager

The easiest way is to run the Wazuh manager alongside edr-bench. You can use their single-node Docker deployment or an existing Wazuh instance.

```bash
# Option A: run Wazuh as a separate Docker stack
curl -sO https://raw.githubusercontent.com/wazuh/wazuh-docker/master/single-node/docker-compose.yml
docker compose -f docker-compose.yml up -d

# Wazuh API will be at https://localhost:55000
# Default creds: wazuh-wui / MyS3cr37P450r.*-
```

### 2. Install Wazuh agent in victim-linux

Add to `docker/victim-linux/Dockerfile` (before the ENTRYPOINT):

```dockerfile
# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
       > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="<your-wazuh-manager-ip>" apt-get install -y wazuh-agent \
    && rm -rf /var/lib/apt/lists/*
```

Add to `docker/victim-linux/entrypoint.sh` (before supervisord):

```bash
# Start Wazuh agent
/var/ossec/bin/wazuh-control start &
```

### 3. Configure edr-bench to read Wazuh alerts

Wazuh writes alerts to `/var/ossec/logs/alerts/alerts.json`. Create a config:

```yaml
# data/edr_configs/wazuh.yaml
type: file_tailer
log_path: /var/ossec/logs/alerts/alerts.json
format: json

field_mapping:
  timestamp: "timestamp"
  rule_name: "rule.description"
  severity: "rule.level"
  description: "full_log"
  mitre_technique_id: "rule.mitre.id[0]"
  process_name: "data.process.name"
  process_pid: "data.process.pid"
  command_line: "data.process.command_line"
  file_path: "syscheck.path"

severity_mapping:
  "0": "info"
  "1": "info"
  "2": "info"
  "3": "low"
  "4": "low"
  "5": "low"
  "6": "medium"
  "7": "medium"
  "8": "medium"
  "9": "high"
  "10": "high"
  "11": "high"
  "12": "critical"
  "13": "critical"
  "14": "critical"
  "15": "critical"
```

Or use the API:

```yaml
# data/edr_configs/wazuh_api.yaml
type: api_poller
api_url: https://<wazuh-manager>:55000/alerts
poll_interval: 5.0
headers:
  Authorization: "Bearer ${WAZUH_API_TOKEN}"
  Accept: application/json

field_mapping:
  timestamp: "timestamp"
  rule_name: "rule.description"
  severity: "rule.level"
  mitre_technique_id: "rule.mitre.id[0]"
  process_name: "data.process.name"
  command_line: "data.process.command_line"

severity_mapping:
  "3": "low"
  "7": "medium"
  "10": "high"
  "12": "critical"
```

### 4. Run the benchmark

```bash
# mount the Wazuh alert log into the volume
# add to docker-compose.yml victim-linux volumes:
#   - /var/ossec/logs/alerts:/var/ossec/logs/alerts

make up PROFILE=linux

# run with file tailer
EDR_LOG_PATH=/var/ossec/logs/alerts/alerts.json \
  edr-bench run --platform linux --edr-name "Wazuh 4.x"

# or with API
WAZUH_API_TOKEN="<token>" \
EDR_API_URL=https://<wazuh-manager>:55000/alerts \
  edr-bench run --platform linux --edr-name "Wazuh 4.x"
```

### What Wazuh will likely catch

Wazuh is strong on file integrity monitoring, rootkit detection, and process anomaly detection. Expect good scores on:
- CLI attack scenarios (reverse shells, credential dumping, persistence mechanisms)
- File copy to removable media (FIM detects writes to /media/usb0)
- Suspicious process execution (base64 encoding, ncat listeners)

Expect weaker scores on:
- Browser-based data exfiltration (Wazuh doesn't inspect HTTP content)
- AI tool data leaks (no browser-level visibility)
- Clipboard/screenshot scenarios

---

## CrowdStrike Falcon

CrowdStrike Falcon is a cloud-native EDR with strong behavioral detection. It requires a Falcon subscription and customer ID.

### 1. Install Falcon sensor in victim-linux

Add to `docker/victim-linux/Dockerfile`:

```dockerfile
# Install CrowdStrike Falcon sensor
# Download the .deb from your Falcon console first and place in docker/victim-linux/
COPY falcon-sensor_*.deb /tmp/falcon-sensor.deb
RUN dpkg -i /tmp/falcon-sensor.deb && rm /tmp/falcon-sensor.deb
```

Add to `docker/victim-linux/entrypoint.sh`:

```bash
# Register and start Falcon sensor
/opt/CrowdStrike/falconctl -s --cid="${FALCON_CID}" --provisioning-token="${FALCON_TOKEN}"
/opt/CrowdStrike/falconctl -s --backend=kernel
service falcon-sensor start &
```

Add to `.env`:

```
FALCON_CID=<your-customer-id-with-checksum>
FALCON_TOKEN=<your-provisioning-token>
```

### 2. Configure edr-bench to read Falcon alerts

CrowdStrike exposes detections via the Falcon API (OAuth2):

```yaml
# data/edr_configs/crowdstrike.yaml
type: api_poller
api_url: https://api.crowdstrike.com/detects/queries/detects/v1
poll_interval: 10.0
headers:
  Authorization: "Bearer ${FALCON_API_TOKEN}"
  Accept: application/json

field_mapping:
  timestamp: "created_timestamp"
  rule_name: "detection_name"
  severity: "max_severity_displayname"
  description: "description"
  mitre_technique_id: "behaviors[0].technique_id"
  process_name: "behaviors[0].filename"
  process_pid: "behaviors[0].process_id"
  command_line: "behaviors[0].cmdline"
  file_path: "behaviors[0].filepath"
  network_dst: "behaviors[0].remote_address"
  blocked: "behaviors[0].pattern_disposition_details.kill_process"

severity_mapping:
  "Informational": "info"
  "Low": "low"
  "Medium": "medium"
  "High": "high"
  "Critical": "critical"

blocked_values:
  - "true"
```

### 3. Run the benchmark

```bash
make up PROFILE=linux

FALCON_API_TOKEN="$(python3 -c "
import requests
r = requests.post('https://api.crowdstrike.com/oauth2/token',
    data={'client_id': '$FALCON_CLIENT_ID', 'client_secret': '$FALCON_CLIENT_SECRET'})
print(r.json()['access_token'])
")" \
EDR_API_URL=https://api.crowdstrike.com/detects/queries/detects/v1 \
  edr-bench run --platform linux --edr-name "CrowdStrike Falcon"
```

### What CrowdStrike will likely catch

CrowdStrike is strong on behavioral detection and has good MITRE ATT&CK coverage. Expect high scores on:
- Reverse shells, credential dumping, privilege escalation
- Suspicious file transfers (scp/sftp to external IPs)
- Process injection and persistence techniques
- DNS exfiltration patterns

Moderate scores on:
- Data exfiltration via legitimate tools (curl, git push)
- Browser-based scenarios (depends on Falcon Insight web monitoring)

---

## Microsoft Defender for Endpoint

MDE provides comprehensive endpoint protection with deep integration into Windows environments and decent Linux support.

### 1. Install MDE on victim-linux

```dockerfile
# Install Microsoft Defender for Endpoint
RUN curl -o /tmp/microsoft.list https://packages.microsoft.com/config/ubuntu/22.04/prod.list \
    && cp /tmp/microsoft.list /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update \
    && apt-get install -y mdatp \
    && rm -rf /var/lib/apt/lists/*
```

Add to entrypoint:

```bash
# Onboard MDE (requires onboarding package from security.microsoft.com)
mdatp health --field org_id || python3 /tmp/MicrosoftDefenderATPOnboardingLinuxServer.py
mdatp config real-time-protection --value enabled
```

### 2. Configure edr-bench

MDE alerts are available via the Microsoft 365 Defender API:

```yaml
# data/edr_configs/mde.yaml
type: api_poller
api_url: https://api.securitycenter.microsoft.com/api/alerts
poll_interval: 10.0
headers:
  Authorization: "Bearer ${MDE_API_TOKEN}"
  Accept: application/json

field_mapping:
  timestamp: "alertCreationTime"
  rule_name: "title"
  severity: "severity"
  description: "description"
  mitre_technique_id: "mitreTechniques[0]"
  process_name: "evidence[0].fileName"
  process_pid: "evidence[0].processId"
  command_line: "evidence[0].processCommandLine"
  file_path: "evidence[0].filePath"
  blocked: "status"

severity_mapping:
  "Informational": "info"
  "Low": "low"
  "Medium": "medium"
  "High": "high"

blocked_values:
  - "Resolved"
```

### 3. Run the benchmark

```bash
make up PROFILE=linux

MDE_API_TOKEN="<oauth-token>" \
EDR_API_URL=https://api.securitycenter.microsoft.com/api/alerts \
  edr-bench run --platform linux --edr-name "Microsoft Defender for Endpoint"
```

---

## Osquery + Fleet (open source)

Osquery turns your OS into a SQL database. Fleet is an open source server for managing osquery across machines. Together they provide visibility into processes, network connections, file changes, and more.

This is a detection-only tool (no blocking), so blocking efficacy will be 0.

### 1. Install osquery in victim-linux

Add to `docker/victim-linux/Dockerfile`:

```dockerfile
# Install osquery
RUN curl -fsSL https://pkg.osquery.io/deb/osquery.gpg | gpg --dearmor -o /usr/share/keyrings/osquery.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
       > /etc/apt/sources.list.d/osquery.list \
    && apt-get update \
    && apt-get install -y osquery \
    && rm -rf /var/lib/apt/lists/*
```

### 2. Configure osquery detection packs

Create `docker/victim-linux/osquery.conf`:

```json
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "process_events": {
      "query": "SELECT pid, name, path, cmdline, uid, gid FROM process_events;",
      "interval": 10
    },
    "socket_events": {
      "query": "SELECT pid, remote_address, remote_port, local_port, action FROM socket_events;",
      "interval": 10
    },
    "file_events": {
      "query": "SELECT target_path, action, md5 FROM file_events;",
      "interval": 30
    },
    "shell_history": {
      "query": "SELECT username, command FROM shell_history;",
      "interval": 60
    }
  },
  "file_paths": {
    "sensitive_files": [
      "/home/user/fixtures/%%",
      "/media/usb0/%%",
      "/tmp/%%"
    ]
  }
}
```

### 3. Configure edr-bench

Osquery logs results as JSON to `/var/log/osquery/osqueryd.results.log`:

```yaml
# data/edr_configs/osquery.yaml
type: file_tailer
log_path: /var/log/osquery/osqueryd.results.log
format: json

field_mapping:
  timestamp: "unixTime"
  rule_name: "name"
  severity: "action"
  process_name: "columns.name"
  process_pid: "columns.pid"
  command_line: "columns.cmdline"
  file_path: "columns.target_path"
  network_dst: "columns.remote_address"
  network_port: "columns.remote_port"

severity_mapping:
  "added": "medium"
  "removed": "low"
```

### 4. Run the benchmark

```bash
make up PROFILE=linux

EDR_LOG_PATH=/var/log/osquery/osqueryd.results.log \
  edr-bench run --platform linux --edr-name "osquery + Fleet"
```

### What osquery will likely catch

Osquery provides raw telemetry, not alerts. Expect:
- Process execution events for all CLI commands
- Network connection events for scp, curl, etc.
- File access events for fixture files
- Shell history capture

But no behavioral correlation, no MITRE mapping, no blocking. Contextual accuracy will be low because osquery doesn't classify detections.

---

## LimaCharlie (freemium)

LimaCharlie is a cloud-based SecOps platform with a free tier (up to 2 sensors). It provides real-time EDR telemetry with customizable detection rules (D&R rules).

### 1. Install LimaCharlie sensor

```dockerfile
# Install LimaCharlie sensor
RUN curl -fsSL https://downloads.limacharlie.io/sensor/linux/64 -o /tmp/lc-sensor \
    && chmod +x /tmp/lc-sensor
```

Add to entrypoint:

```bash
# Start LimaCharlie sensor
/tmp/lc-sensor -d "${LC_INSTALLATION_KEY}" &
```

Add to `.env`:

```
LC_INSTALLATION_KEY=<your-installation-key>
LC_OID=<your-organization-id>
LC_API_KEY=<your-api-key>
```

### 2. Configure D&R rules

In the LimaCharlie web console, add detection rules for the scenarios you want to test. Example rules:

```yaml
# Detect data exfil via scp
detect:
  op: and
  rules:
    - op: is
      event: NEW_PROCESS
      path: event/FILE_PATH
      value: /usr/bin/scp
    - op: contains
      event: NEW_PROCESS
      path: event/COMMAND_LINE
      value: "fixtures"
respond:
  - action: report
    name: "Data exfil via SCP"
```

### 3. Configure edr-bench

```yaml
# data/edr_configs/limacharlie.yaml
type: api_poller
api_url: https://api.limacharlie.io/v1/detects
poll_interval: 5.0
headers:
  Authorization: "Bearer ${LC_API_KEY}"
  Accept: application/json

field_mapping:
  timestamp: "detect.routing.event_time"
  rule_name: "detect.detect.name"
  severity: "detect.detect.severity"
  description: "detect.detect.name"
  process_name: "detect.event.FILE_PATH"
  command_line: "detect.event.COMMAND_LINE"
  network_dst: "detect.event.REMOTE_ADDRESS"

severity_mapping:
  "1": "low"
  "2": "medium"
  "3": "high"
  "4": "critical"
```

### 4. Run the benchmark

```bash
make up PROFILE=linux

LC_API_KEY="<your-api-key>" \
EDR_API_URL=https://api.limacharlie.io/v1/detects \
  edr-bench run --platform linux --edr-name "LimaCharlie"
```

---

## Using syslog (any EDR)

If your EDR sends alerts via syslog (CEF or LEEF format), edr-bench can listen directly:

```bash
# configure your EDR to send syslog to the controller container IP on port 1514
EDR_SYSLOG_PORT=1514 \
  edr-bench run --platform linux --edr-name "My EDR (syslog)"
```

The syslog receiver parses CEF format:
```
CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value ...
```

---

## Interpreting results

After a run, edr-bench writes a JSON report to `reports/` and can generate HTML:

```bash
edr-bench report reports/<report-id>.json -o report.html
```

The report includes:
- **Overall scores** for all 5 metrics
- **Per-scenario breakdown** showing which scenarios were detected, missed, or partially caught
- **MITRE ATT&CK heatmap** showing technique-level coverage
- **Ground truth vs. EDR findings** side-by-side comparison
- **False positive analysis** listing EDR alerts that didn't match any scenario

### Comparing EDR products

Run the same benchmark against multiple EDR products and compare their JSON reports:

```bash
# run against each EDR
edr-bench run --platform linux --edr-name "Wazuh" > /dev/null
edr-bench run --platform linux --edr-name "CrowdStrike" > /dev/null
edr-bench run --platform linux --edr-name "Defender" > /dev/null

# compare the JSON reports
python3 -c "
import json, glob
for f in sorted(glob.glob('reports/*.json')):
    r = json.load(open(f))
    print(f'{r[\"edr_name\"]:25s}  DR={r[\"detection_rate\"]:.0%}  CA={r[\"contextual_accuracy\"]:.0%}  TTD={r[\"avg_time_to_detect\"]:.1f}s  BE={r[\"blocking_efficacy\"]:.0%}  NR={r[\"noise_ratio\"]:.0%}')
"
```

### What a good score looks like

There's no universal "good" score -- it depends on what your EDR is designed to do. But as rough guidelines:

| Metric | Decent | Good | Great |
|--------|--------|------|-------|
| Detection rate | >50% | >70% | >85% |
| Contextual accuracy | >40% | >60% | >80% |
| Time to detect | <120s | <30s | <5s |
| Blocking efficacy | >20% | >50% | >80% |
| Noise ratio | <30% | <15% | <5% |

Remember that detection-only tools (osquery, Sysmon) will always score 0% on blocking efficacy -- that's expected, not a failure.
