#!/usr/bin/env sh
set -eu

if command -v uv >/dev/null 2>&1; then
  uv run pytest tests/unit --cov=trpc_service --cov-branch --cov-report=term-missing \
    --cov-report=html --cov-report=json:runs/multitenant/coverage.json
else
  python -m pytest tests/unit --cov=trpc_service --cov-branch --cov-report=term-missing \
    --cov-report=html --cov-report=json:runs/multitenant/coverage.json
fi
python -m scripts.check_coverage runs/multitenant/coverage.json \
  --output runs/multitenant/coverage-gate.json
