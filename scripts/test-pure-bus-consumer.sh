#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

pure_consumer=crates/tinybox-bus/pure-consumer/Cargo.toml
cargo run --locked --manifest-path "$pure_consumer" --target-dir target
workspace_version="$(awk '
  /^\[workspace\.package\]$/ { in_package = 1; next }
  /^\[/ { in_package = 0 }
  in_package && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
' Cargo.toml)"
if [[ -z "$workspace_version" ]]; then
  echo "could not read the TinyBox workspace version" >&2
  exit 1
fi

dependency_tree="$(cargo tree --locked --manifest-path "$pure_consumer" --prefix none --format '{p} {f}' -e normal,build)"
printf '%s\n' "$dependency_tree"
python3 scripts/check_pure_bus_consumer.py \
  "$workspace_version" "$pure_consumer" crates/tinybox-bus/pure-consumer/Cargo.lock \
  <<< "$dependency_tree"
