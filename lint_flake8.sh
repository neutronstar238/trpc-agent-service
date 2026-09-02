#!/usr/bin/env sh
set -eu

# Compatibility entry point for environments that still call the old
# ``lint_flake8.sh`` name.  Ruff is the repository's locked linter; keeping one
# command here avoids installing a second, differently configured linter.
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run mypy trpc_service scripts
