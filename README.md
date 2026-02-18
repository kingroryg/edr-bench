# edr-bench

A tool for testing how well your EDR (endpoint detection and response) product actually catches threats. It spins up Docker containers, runs realistic attacks inside them, watches what happens with eBPF and network proxies, then checks whether your EDR noticed.

## What it does

1. **Runs attacks in sandboxed containers** — CLI commands, browser-based actions through AI agents, phishing campaigns, cloud misconfigs, the works.
2. **Records exactly what happened** — using Tracee (eBPF), mitmproxy, and Docker events so you have solid ground truth.
3. **Checks your EDR's homework** — pulls in alerts from your EDR (log files, API, or syslog) and matches them against what actually happened.
4. **Gives you a score** — detection rate, how fast it caught things, whether it blocked anything, how noisy it was, and whether it got the context right.
5. **Generates a report** — HTML with a MITRE ATT&CK heatmap so you can see coverage gaps at a glance.

## Quick start

```bash
# install the package
pip install -e ".[dev]"

# bring up the linux containers
make build PROFILE=linux
make up PROFILE=linux

# check your scenario files are valid
edr-bench validate data/scenarios/

# do a dry run first to see what would happen
edr-bench run --platform linux --dry-run

# run it for real
edr-bench run --platform linux --edr-name "My EDR"

# generate an html report from the json output
edr-bench report reports/<report-id>.json -o report.html
```

## How it's set up

The project has a few main pieces:

- **Scenarios** live in CSV files under `data/scenarios/`. Each row is an attack scenario with steps described as embedded JSON. This makes it easy to edit in a spreadsheet and share with your security team.
- **Executors** handle running the attacks — there's one for shell commands, one for UI actions (via AI computer-use agents), one for Atomic Red Team, Caldera, phishing (GoPhish), cloud stuff (Terraform + LocalStack), and USB simulation.
- **Ground truth collectors** watch everything that happens using Tracee eBPF events, mitmproxy HTTP flows, and Docker container events.
- **EDR listeners** pull alerts from your EDR product — tail a log file, poll a REST API, or listen for syslog (CEF/LEEF).
- **Scoring** matches ground truth against EDR findings using time windows and attribute overlap, then calculates five metrics.
- **Reporting** spits out JSON for machines and HTML (with a MITRE heatmap) for humans.

## Docker services

Everything runs in Docker. You pick a profile depending on what you need:

| Profile | What you get |
|---------|-------------|
| `linux` | Linux victim + MockNet + mitmproxy + Tracee + controller |
| `windows` | Windows victim + MockNet + mitmproxy + controller |
| `cloud` | Controller + LocalStack |
| `phishing` | Controller + GoPhish |
| `full` | Everything |

```bash
# start specific profile
make up PROFILE=linux

# check what's running
make ps

# tear it down
make down
```

The victim-linux container runs Ubuntu 22.04 with an XFCE desktop, VNC, noVNC (accessible at `localhost:6080`), Firefox, PowerShell, and Atomic Red Team pre-installed. MockNet fakes popular websites (ChatGPT, Salesforce, GitHub) with login pages that log whatever gets submitted.

## Writing scenarios

Scenarios are CSV files. Here's what a row looks like:

| Column | What it is |
|--------|-----------|
| `id` | Something unique like `LIN-CLI-001` |
| `name` | Short name for the attack |
| `description` | What the scenario does |
| `platform` | `linux`, `windows`, or `cloud` |
| `attack_type` | MITRE tactic like `execution`, `persistence`, `exfiltration` |
| `mitre_technique_id` | The technique ID, e.g. `T1059.001` |
| `mitre_technique_name` | Human name for the technique |
| `complexity` | `low`, `medium`, or `high` |
| `simulation_steps` | JSON array of steps (see below) |
| `expected_detections` | JSON array of detection rule names you expect to fire |
| `tags` | JSON array of tags for filtering |

Each step in `simulation_steps` looks like this:

```json
{
  "order": 1,
  "role": "cli",
  "command": "whoami",
  "description": "Check current user",
  "expected_artifact": "whoami process",
  "timeout_seconds": 10
}
```

For UI steps, use `"role": "ui"` and add `"ui_instructions"` with plain English telling the AI agent what to do on screen.

## Scoring

Five metrics, each between 0 and 1 (except time-to-detect which is in seconds):

- **Detection rate** — what fraction of real events did the EDR catch?
- **Contextual accuracy** — when it caught something, did it get the details right? (technique ID, severity, process info)
- **Time to detect** — how many seconds between the event and the alert?
- **Blocking efficacy** — of the things it detected, how many did it actually block?
- **Noise ratio** — what fraction of alerts were false positives?

## Connecting your EDR

You need to tell edr-bench where to find your EDR's alerts. Three options:

**Tail a log file** — if your EDR writes JSON alerts to a file:
```bash
EDR_LOG_PATH=/var/log/edr/alerts.json edr-bench run --platform linux
```

**Poll an API** — if your EDR has a REST API:
```bash
EDR_API_URL=https://edr-console.example.com/api/v1 EDR_API_KEY=xxx edr-bench run --platform linux
```

**Syslog** — if your EDR sends CEF/LEEF syslog:
```bash
EDR_SYSLOG_PORT=1514 edr-bench run --platform linux
```

Check `data/edr_configs/` for example field mapping configs.

## AI agents for UI attacks

Some scenarios need an AI to drive a desktop — clicking around in Firefox, filling in forms, that sort of thing. This uses computer-use APIs:

- **Anthropic Claude** (primary) — set `ANTHROPIC_API_KEY`
- **OpenAI** (secondary) — set `OPENAI_API_KEY`

The agent connects to the victim's VNC, takes screenshots, figures out what to click, and executes the steps. You don't need API keys if you're only running CLI scenarios.

## Running tests

```bash
# unit tests only
make test

# integration tests (needs Docker running)
make test-integration

# everything
make test-all

# linting
make lint
```

## Config

Copy `.env.example` to `.env` and fill in what you need. Most things have sensible defaults. You can also pass a YAML config file:

```bash
edr-bench run --config my-config.yaml --platform linux
```

See `src/edr_bench/config/defaults.yaml` for all the options.

## Project layout

```
src/edr_bench/
├── cli.py              # command line interface
├── config/             # settings and defaults
├── models/             # data models (scenarios, findings, metrics)
├── orchestrator/       # runs the whole benchmark
├── agents/             # AI computer-use agents (Claude, OpenAI)
├── executors/          # attack execution (CLI, UI, Caldera, etc.)
├── ground_truth/       # captures what actually happened
├── edr_interface/      # pulls alerts from your EDR
├── scoring/            # matches events, calculates scores
├── reporting/          # generates HTML and JSON reports
└── utils/              # shared helpers

docker/                 # all the container configs
data/scenarios/         # attack scenario CSVs
tests/                  # unit and integration tests
```

## Requirements

- Python 3.11+
- Docker and Docker Compose
- An EDR product to test (that's kind of the point)
- Anthropic or OpenAI API key (only if you want UI attack scenarios)
