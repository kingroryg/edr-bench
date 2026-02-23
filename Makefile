.PHONY: build up down logs test lint format clean \
       build-wazuh up-wazuh run-wazuh down-wazuh \
       build-falco up-falco run-falco down-falco

COMPOSE := docker compose -f docker/docker-compose.yml
PROFILE ?= linux
REPORT_FILE ?= reports/latest.json
REPORT_OUTPUT ?= reports/report.html

build:
	$(COMPOSE) --profile $(PROFILE) build

up:
	$(COMPOSE) --profile $(PROFILE) up -d

down:
	$(COMPOSE) --profile $(PROFILE) down -v

logs:
	$(COMPOSE) --profile $(PROFILE) logs -f

restart:
	$(COMPOSE) --profile $(PROFILE) restart

ps:
	$(COMPOSE) --profile $(PROFILE) ps

test:
	pytest -m unit

test-integration:
	pytest -m integration

test-all:
	pytest

lint:
	ruff check src/ tests/
	mypy src/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

validate:
	edr-bench validate data/scenarios/

run-linux:
	edr-bench run --platform linux

run-dry:
	edr-bench run --platform linux --dry-run

report:
	edr-bench report $(REPORT_FILE) -o $(REPORT_OUTPUT)

# --- Wazuh targets ---
build-wazuh:
	$(COMPOSE) --profile linux --profile wazuh build
	@echo "Remember to set WAZUH_AGENT_ENABLED=true in .env"

up-wazuh:
	WAZUH_AGENT_ENABLED=true $(COMPOSE) --profile linux --profile wazuh up -d

run-wazuh:
	edr-bench run --platform linux --edr-name Wazuh

down-wazuh:
	$(COMPOSE) --profile linux --profile wazuh down -v

# --- Falco targets ---
build-falco:
	$(COMPOSE) --profile linux --profile falco build

up-falco:
	$(COMPOSE) --profile linux --profile falco up -d

run-falco:
	edr-bench run --platform linux --edr-name Falco

down-falco:
	$(COMPOSE) --profile linux --profile falco down -v

clean:
	$(COMPOSE) down -v --rmi local
	rm -rf reports/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

install:
	pip install -e ".[dev]"
