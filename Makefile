SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE := docker compose
VENV    := backend/.venv
PY      := $(VENV)/bin/python

.PHONY: help up down test lint seed bench

help: ## List available targets
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Build and start the full stack in the background
	$(COMPOSE) up -d --build

down: ## Stop the stack (volumes are kept)
	$(COMPOSE) down

test: ## Run backend tests with coverage and build the frontend
	cd backend && .venv/bin/pytest --cov --cov-report=term-missing
	cd frontend && npm run build

lint: ## Run ruff, mypy, bandit (backend) and oxlint (frontend)
	cd backend && .venv/bin/ruff check . && .venv/bin/ruff format --check . \
		&& .venv/bin/mypy app tests && .venv/bin/bandit -q -c pyproject.toml -r app
	cd frontend && npm run lint

seed: ## (not implemented yet) Load demo data
	@echo "make seed: not implemented yet (scripts/seed_demo_data.py is a placeholder; see README Roadmap)" >&2
	@exit 1

bench: ## (not implemented yet) Run API benchmark metrics
	@echo "make bench: not implemented yet (scripts/benchmark_metrics.py is a placeholder; see README Roadmap)" >&2
	@exit 1
