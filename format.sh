#!/usr/bin/env sh
set -eu

uv run ruff format .
uv run ruff check --fix .
