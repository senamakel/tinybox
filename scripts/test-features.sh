#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# macOS does not ship setsid; the Docker supervisor fixtures need its real
# process-session semantics even though they run without a Docker daemon.
case "${RUNNER_OS:-$(uname -s)}" in
  macOS|Darwin)
    brew install util-linux
    export PATH="$(brew --prefix util-linux)/bin:$PATH"
    ;;
  Windows|MINGW*|MSYS*|CYGWIN*)
    # Native Rust commands resolve /bin/sh at the current drive root, while
    # Git Bash resolves it inside its installation. Supply that same shell.
    pwsh -NoProfile -File scripts/test-windows-fixtures.ps1
    pwsh -NoProfile -File scripts/prepare-windows-fixtures.ps1 -PosixBin "$(cygpath -w /usr/bin)"
    export PATH="/usr/bin:$PATH"
    ;;
esac
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
cargo test --locked --workspace --all-features
pure_consumer=crates/tinybox-bus/pure-consumer/Cargo.toml
cargo run --locked --manifest-path "$pure_consumer" --target-dir target
workspace_version="$(awk '
  /^\[workspace\.package\]$/ { in_package = 1; next }
  /^\[/ { in_package = 0 }
  in_package && $1 == "version" { gsub(/\"/, "", $3); print $3; exit }
' Cargo.toml)"
if [[ -z "$workspace_version" ]]; then
  echo "could not read the TinyBox workspace version" >&2
  exit 1
fi
dependency_tree="$(cargo tree --locked --manifest-path "$pure_consumer" --prefix none --format '{p} {f}' -e normal,build)"
printf '%s\n' "$dependency_tree"
tinybox_bus_found=false
storage_bus_found=false
while read -r package version details; do
  case "$package" in
    tinybox-bus)
      if [[ "$version" != "v$workspace_version" ]]; then
        echo "pure consumer resolved tinybox-bus $version, expected workspace version $workspace_version" >&2
        exit 1
      fi
      tinybox_bus_found=true
      ;;
    tinystoragedrivers-bus)
      if [[ "$version" != "v1.3.0" ]]; then
        echo "pure consumer resolved tinystoragedrivers-bus $version, expected v1.3.0" >&2
        exit 1
      fi
      if [[ "$details" == *client* ]]; then
        echo "pure consumer unexpectedly enabled tinystoragedrivers-bus client" >&2
        exit 1
      fi
      storage_bus_found=true
      ;;
    tinystoragedrivers-*)
      echo "pure consumer unexpectedly depends on storage implementation crate $package" >&2
      exit 1
      ;;
    tinybox-*)
      if [[ "$package" != "tinybox-bus" && "$package" != "tinybox-bus-pure-consumer" ]]; then
        echo "pure consumer unexpectedly depends on TinyBox implementation crate $package" >&2
        exit 1
      fi
      ;;
    tinybus|tinybus-*|tokio|async-std|smol|axum|hyper|hyper-util|http|http-body|http-body-util|reqwest|ureq|tower|tower-http|rusqlite|sqlite|mongodb|sqlx|sled|redb|rocksdb|redis)
      echo "pure consumer unexpectedly depends on runtime, HTTP, bus, or database crate $package" >&2
      exit 1
      ;;
  esac
done <<< "$dependency_tree"
if [[ "$tinybox_bus_found" != true || "$storage_bus_found" != true ]]; then
  echo "pure consumer graph is missing tinybox-bus or tinystoragedrivers-bus" >&2
  exit 1
fi
storage_bus_lock="$(sed -n '/^name = "tinystoragedrivers-bus"$/,/^\[\[package\]\]$/p' crates/tinybox-bus/pure-consumer/Cargo.lock)"
if ! grep -Fq 'version = "1.3.0"' <<<"$storage_bus_lock" || \
  ! grep -Fq 'rev=08caa16d1d4e3c6b8d649e4f26fe1a426ee1d168' <<<"$storage_bus_lock"; then
  echo "pure consumer lockfile does not pin the released storage metadata contract" >&2
  exit 1
fi
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*) ;;
  *)
    python3 scripts/test-feature-environment.py
    python3 scripts/test-package-layout.py
    ;;
esac
