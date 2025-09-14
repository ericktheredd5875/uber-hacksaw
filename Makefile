# Makefile for uber_hacksaw

APP_NAME=uber_hacksaw

.PHONY: test lint fmt run commit corpus-init corpus-eicar corpus-benign corpus-manifest corpus-eicar-real scan-stdin scan-path

SHELL := /bin/bash
PY := python3.13
AUTO_MSG := "auto-commit: $(shell date)"

pip-reset:
	uv pip install -e .

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

sec:
	uv run bandit -c pyproject.toml -r .

run:
	uv run ${APP_NAME} start

commit-auto:
	@echo "📁 Adding changes for ${APP_NAME}..."
	git add .
	@echo "📝 Auto-Committing with message: ${AUTO_MSG}"
	git commit -m "${AUTO_MSG}"
	@echo "🚀 Pushing to remote for ${APP_NAME}..."
	git push
	@echo "✅ Done!"

commit:
	@echo "📁 Adding changes for ${APP_NAME}..."
	git add .

	@echo "📝 Committing with message: ${MSG}"
	git commit -m "${MSG}"

	@echo "🚀 Pushing to remote for ${APP_NAME}..."
	git push

	@echo "✅ Done!"

git-dir-change:
	git mv ${ORG} ${NEW}

corpus-init:
	uv run python scripts/corpus_cli.py init
corpus-eicar:
	# uv run python scripts/corpus_cli.py add-eicar
	uv run python -m tests.tools.generate_corpus
corpus-benign:
	uv run python scripts/corpus_cli.py gen-benign
corpus-manifest:
	uv run python scripts/corpus_cli.py manifest

# Optional: stream REAL EICAR to your scanner via stdin without touching disk.
# Example:
#   make corpus-eicar-real | python -m uber_hacksaw.scan --stdin
corpus-eicar-real:
	uv run python -m tests.tools.generate_corpus --also-stream-real \
	| uv run python -m uber_hacksaw scan --stdin
	# make corpus-eicar-real | uv run python -m uber_hacksaw scan --stdin

# Pipe real EICAR (from generator) into the scanner without touching disk
scan-stdin:
	uv run python -m uber_hacksaw scan --stdin

# Scan a file or directory

scan-path:
	# SCAN_PATH ?= .
	uv run python -m uber_hacksaw scan -p ${SCAN_PATH} --recursive