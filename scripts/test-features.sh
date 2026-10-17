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
python3 scripts/test-pure-bus-consumer.py
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
pure_consumer=crates/tinybox-bus/pure-consumer/Cargo.toml
scripts/test-pure-bus-consumer.sh
cargo test --locked --workspace --all-features
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*) ;;
  *)
    python3 scripts/test-feature-environment.py
    python3 scripts/test-package-layout.py
    ;;
esac
