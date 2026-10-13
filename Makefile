PY      ?= .venv/bin/python
FIGSHARE = https://ndownloader.figshare.com/files
export PYTHONPATH := src

.DEFAULT_GOAL := help
.PHONY: help install download extract evaluate test lint format clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install the package with dev tools
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

download: ## Download CERT r4.2 (4.8 GB) and the answer key from KiltHub (CC BY 4.0), check MD5
	mkdir -p data/raw
	curl -fL --retry 3 -o data/raw/answers.tar.bz2 $(FIGSHARE)/24857828
	curl -fL --retry 3 -o data/raw/r4.2.tar.bz2 $(FIGSHARE)/24856766
	$(PY) -c "import hashlib, sys; bad = [n for h, n in map(str.split, open('checksums.md5')) if hashlib.file_digest(open('data/raw/' + n, 'rb'), 'md5').hexdigest() != h]; print('MD5 mismatch:', *bad) if bad else print('MD5 OK'); sys.exit(bool(bad))"

extract: ## Stream the archive once: keep only the columns used, aggregate the 14.5 GB web log (35-55 min)
	$(PY) -m ueba extract

evaluate: ## Features, detectors and evaluation against the answer key -> reports/ (~2 min)
	$(PY) -m ueba evaluate

test: ## Run the test suite (miniature archive, no download needed)
	$(PY) -m pytest --cov --cov-report=term-missing

lint: ## Lint and check formatting
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests

format: ## Auto-format the code
	$(PY) -m ruff check --fix src tests
	$(PY) -m ruff format src tests

clean: ## Remove caches (keeps data/ and reports/)
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
