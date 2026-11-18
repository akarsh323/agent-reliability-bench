.PHONY: help install lint format types test check reference clean

help:  ## Show this help.
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

install:  ## Install the package and dev tools into the active environment.
	pip install -e . -r requirements-dev.txt

lint:  ## Lint and check formatting.
	ruff check .
	ruff format --check .

format:  ## Apply formatting and safe lint fixes.
	ruff format .
	ruff check --fix .

types:  ## Type-check with mypy --strict.
	mypy

test:  ## Run the tests, including the end-to-end pipeline tests.
	pytest --cov=reliabench --cov-report=term-missing

check: lint types test  ## Everything CI runs.

reference:  ## Regenerate results/reference from the scripted agents.
	rm -rf logs/reference
	reliabench run --epochs 1 --simulate-infra-failures --log-dir logs/reference \
		--model reliabench/careful \
		--model reliabench/obedient
	reliabench report logs/reference --out results/reference

clean:  ## Remove caches and build output.
	rm -rf build dist .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
