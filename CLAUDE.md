# CLAUDE.md

## What this project is

edr-bench: a sandboxed benchmarking suite that evaluates EDR tools. It runs 77 attack scenarios in Docker containers, captures ground truth (what actually happened), and scores how well an EDR detected and responded.

## Key commands

```bash
# Install
pip install -e ".[dev]"

# Validate all scenarios parse correctly
PYTHONPATH=src python3 -c "from edr_bench.utils.csv_loader import CSVLoader; s = CSVLoader.load_directory('data/scenarios'); print(f'{len(s)} scenarios loaded')"

# Build and run Docker containers
make build PROFILE=linux
make up PROFILE=linux

# Run benchmark (CLI scenarios only)
edr-bench run --platform linux --edr-name "My EDR"

# Run benchmark with UI scenarios (needs Anthropic API key)
AGENT_ANTHROPIC_API_KEY="sk-ant-..." \
AGENT_ANTHROPIC_MODEL="claude-sonnet-4-20250514" \
VNC_HOST=localhost VNC_PORT=5900 VNC_PASSWORD=changeme \
VNC_CONTAINER_NAME=docker-victim-linux-1 \
edr-bench run --platform linux --edr-name "My EDR" --no-lifecycle --edr-settle 60

# Tests
make test          # unit (146 tests)
make test-all      # unit + integration
make lint          # ruff + mypy
```

## Project structure

- `src/edr_bench/` -- Python package (Typer CLI, Pydantic models, async orchestrator)
- `docker/` -- Docker Compose + Dockerfiles for all containers
- `docker/mocknet/sites/` -- 25+ mock website HTML files served by nginx
- `docker/mocknet/app.py` -- Flask app that logs all form submissions as ground truth
- `docker/mocknet/dnsmasq.conf` -- DNS spoofing (all domains resolve to mocknet)
- `docker/mocknet/nginx.conf` -- nginx server blocks for each mock domain
- `docker/victim-linux/` -- Ubuntu 22.04 with XFCE, VNC, Firefox ESR, VS Code, Node.js, Terraform, etc.
- `data/scenarios/` -- 15 CSV files with 77 scenarios (50 Coach + 27 classic)
- `data/fixtures/` -- 15 test data files (PII, credentials, source code, financial data)
- `data/edr_configs/` -- example YAML configs for connecting EDR tools

## Conventions

- Scenarios are CSV with embedded JSON in `simulation_steps` and `expected_detections` columns
- Coach scenarios (COACH-xxx) have extra fields: category, sub_category, risk_level, deploy_surfaces, etc.
- Classic scenarios (LIN-CLI-xxx, etc.) are traditional MITRE ATT&CK techniques
- Mock sites post form data to Flask endpoints (`/api/capture`, `/api/send`, `/api/login`, etc.)
- Ground truth is logged to `/var/log/mocknet/traffic.jsonl` (no truncation)
- External IPs (203.0.113.x, 192.168.1.x) are iptables-DNAT'd to mocknet inside victim-linux
- All DNS queries are redirected to dnsmasq for logging; `/etc/hosts` entries are added as fallback (Docker Desktop macOS blocks inter-container UDP)
- The `Role` enum determines execution: `cli` = docker exec, `ui` = VNC + AI agent
- UI scenarios use Claude Computer Use API -- the AI agent runs on the host, connects to VNC, sends mouse/keyboard events, and captures screenshots via `docker exec` + ImageMagick
- Screenshots use `docker exec <container> bash -c "DISPLAY=:1 import -window root png:-"` (not asyncvnc's screenshot which hangs on static screens)
- Compound key combos from Claude CU (e.g. `alt+F2`) are split on `+` and mapped to asyncvnc key names via `_KEY_ALIASES` in `vnc_client.py`
- Fictional company name is "Meridian Systems" (domain: meridian-sys.com) -- used in all fixtures and scenarios
- LIN-CLI C2 domain is `cdn-update.s3.amazonaws.com` (resolved to mocknet via dnsmasq)
- `internal-api.meridian-sys.com` is the mock internal API (also resolved to mocknet)
- Fixture files must look realistic -- no `FAKE`, `EXAMPLE`, `555-0xxx`, `@example.com`, or test credit card numbers
- Stripe-like keys in fixtures must use `sk_test_FAKE` prefix to pass GitHub push protection
- Firefox ESR is installed from Mozilla tarball (not snap) -- Ubuntu 22.04's `firefox` apt package is a snap shim that doesn't work in Docker
- Tracee (eBPF) doesn't work on macOS Docker Desktop (needs /boot, /lib/modules). auditd in the container is the alternative for command monitoring
- Pydantic-settings nested classes (e.g. `AgentSettings`) don't load from `.env` -- pass env vars directly on the command line

## Important files to know

- `src/edr_bench/models/scenario.py` -- Scenario and SimulationStep Pydantic models
- `src/edr_bench/models/enums.py` -- all enums (Platform, Role, AttackType, CoachCategory, etc.)
- `src/edr_bench/utils/csv_loader.py` -- CSVLoader.load_directory() parses all scenario CSVs
- `src/edr_bench/orchestrator/engine.py` -- BenchmarkOrchestrator (hub of hub-and-spoke)
- `src/edr_bench/edr_interface/normalizer.py` -- normalizes vendor-specific EDR output to Finding model
- `src/edr_bench/scoring/metrics.py` -- the 5 scoring metric calculators
- `src/edr_bench/agents/vnc_client.py` -- VNC client with key mapping, docker exec screenshots
- `src/edr_bench/agents/anthropic_agent.py` -- Claude Computer Use agent (primary)
- `src/edr_bench/agents/openai_agent.py` -- OpenAI computer-use-preview agent (secondary)
- `src/edr_bench/config/settings.py` -- all Pydantic settings (VNC, Agent, EDR, Wazuh, etc.)
- `src/edr_bench/reporting/progress.py` -- Rich live progress display
- `docker/victim-linux/entrypoint.sh` -- container startup (iptables, /etc/hosts, auditd, VNC)

## Git

- Remote: git@github.com:kingroryg/edr-bench.git
- Short commit messages, no co-author lines
- Don't commit real API keys or secrets -- fixture files use fake/example values
- GitHub push protection is enabled; use `sk_test_FAKE` prefix for Stripe-like keys in fixtures
