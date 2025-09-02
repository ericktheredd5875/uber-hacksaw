# Makefile for uber-hacksaw

APP_NAME=uber-hacksaw

.PHONY: test

SHELL := /bin/bash
PY := python3.13

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

run:
	uv run ${APP_NAME} start

commit:
	COMMIT_MSG=${1:-"auto-commit: $(date)"}

	echo "📁 Adding changes for ${APP_NAME}..."
	git add .

	echo "📝 Committing with message: $COMMIT_MSG"
	git commit -m "$COMMIT_MSG"

	echo "🚀 Pushing to remote for ${APP_NAME}..."
	git push

	echo "✅ Done!"