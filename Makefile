.PHONY: build up down logs test lint format clean

COMPOSE := docker compose -f docker/docker-compose.yml
PROFILE ?= linux

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
	edr-bench report

clean:
	$(COMPOSE) down -v --rmi local
	rm -rf reports/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

install:
	pip install -e ".[dev]"
