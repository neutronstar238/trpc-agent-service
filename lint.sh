#!/usr/bin/env sh
set -eu

uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run mypy trpc_service scripts
