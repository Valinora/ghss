#!/usr/bin/env bash
set -euo pipefail

DB="/tmp/ghss-demo.db"

cd "$(dirname "$0")/.."

rm -f "$DB"
cargo run -p ghss-scanner -- --config ghss-scanner/examples/demo-config.toml -v
