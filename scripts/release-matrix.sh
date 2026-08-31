#!/usr/bin/env sh
set -eu

ROOT="$(dirname "$0")/.."

cd "$ROOT"
./scripts/check-trusted-ref.sh --strict
./scripts/check-rns-lite-ref.sh --strict
./scripts/test-matrix.sh
