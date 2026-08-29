#!/usr/bin/env sh
set -eu

docker compose config --quiet
docker compose up --build --detach
docker compose ps
