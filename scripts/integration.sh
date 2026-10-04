#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

cleanup() { docker compose down --volumes --remove-orphans; }
trap cleanup EXIT INT TERM
docker compose up -d --build --wait
go test -tags=integration -count=1 ./...
