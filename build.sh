#!/usr/bin/env sh
set -eu

uv sync --extra dev --locked
uv build
docker build --tag "${TRPC_SERVICE_IMAGE:-trpc-agent-service:dev}" .
