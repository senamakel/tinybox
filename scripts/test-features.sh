#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# macOS does not ship setsid; the Docker supervisor fixtures need its real
# process-session semantics even though they run without a Docker daemon.
case "${RUNNER_OS:-$(uname -s)}" in
  macOS|Darwin)
    brew install util-linux
    export PATH="$(brew --prefix util-linux)/bin:$PATH"
    if [ -x /usr/bin/sandbox-exec ]; then
      TINYBOX_REQUIRE_SEATBELT_TESTS=1 cargo test --locked -p tinybox-jail live_seatbelt_ -- --nocapture
    else
      echo "[seatbelt-live] SKIP: /usr/bin/sandbox-exec is absent on this macOS runner"
    fi
    ;;
  Windows|MINGW*|MSYS*|CYGWIN*)
    # Native Rust commands resolve /bin/sh at the current drive root, while
    # Git Bash resolves it inside its installation. Supply that same shell.
    pwsh -NoProfile -File scripts/test-windows-fixtures.ps1
    pwsh -NoProfile -File scripts/prepare-windows-fixtures.ps1 -PosixBin "$(cygpath -w /usr/bin)"
    export PATH="/usr/bin:$PATH"
    if [ "${GITHUB_HEAD_REF:-}" = "tinybox-27-win-diagnostic" ]; then
      # This short-lived diagnostic PR isolates the Windows AppContainer
      # failures and makes Rust emit each test's assertion before another
      # Windows process-limit fixture can hang the full suite.
      for test_name in \
        windows::tests::appcontainer_denies_reads_and_writes_outside_granted_roots \
        windows::tests::appcontainer_untyped_owned_launch_does_not_inherit_the_host_environment \
        windows::tests::windows_appcontainer_process_limit_refuses_child_creation; do
        cargo test --locked -p tinybox-jail "$test_name" -- --exact --nocapture --test-threads=1
      done
      exit 0
    fi
    ;;
esac
case "${RUNNER_OS:-$(uname -s)}" in
  Linux)
    # The bubblewrap jail backend needs `bwrap` and unprivileged user
    # namespaces. Install them where we can and make a missing sandbox a test
    # failure (TINYBOX_REQUIRE_BWRAP=1) so the real isolation tests can never
    # pass by skipping.
    sudo_cmd=""
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then sudo_cmd="sudo"; fi
    if ! command -v bwrap >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
      $sudo_cmd apt-get update -qq
      $sudo_cmd apt-get install -y -qq bubblewrap
    fi
    # Ubuntu 24.04 blocks unprivileged user namespaces for unprofiled binaries.
    $sudo_cmd sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null || true
    export TINYBOX_REQUIRE_BWRAP=1
    bwrap --version
    log="$(mktemp)"
    cargo test --locked -p tinybox-jail --test bwrap_isolation --test bwrap_fd_leak -- --nocapture --test-threads=1 2>&1 | tee "$log"
    ran="$(grep -c '\[bwrap-real\] .* ok in ' "$log" || true)"
    echo "bwrap real isolation tests that ran: $ran"
    if [ "$ran" -lt 22 ]; then
      echo "expected at least 22 real bwrap tests to run, saw $ran" >&2
      exit 1
    fi
    ;;
esac
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/check-library-engines.py
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*) ;;
  *)
    python3 scripts/test-feature-environment.py
    python3 scripts/test-package-layout.py
    ;;
esac
