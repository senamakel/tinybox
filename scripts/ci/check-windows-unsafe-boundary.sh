#!/usr/bin/env bash
set -euo pipefail

allowed_file="crates/tinybox-jail/src/windows.rs"
mapfile -t allowance_files < <(
  rg -l -U '#\s*!?\s*\[\s*allow\s*\([^]]*unsafe_code' crates --glob '*.rs' || true
)

if [[ "${#allowance_files[@]}" -ne 1 || "${allowance_files[0]}" != "$allowed_file" ]]; then
  printf 'unsafe_code allowances must appear only in %s\n' "$allowed_file" >&2
  printf 'found: %s\n' "${allowance_files[*]:-(none)}" >&2
  exit 1
fi

if ! rg -q '^unsafe_code = "deny"$' Cargo.toml; then
  echo 'workspace unsafe_code lint must remain deny by default' >&2
  exit 1
fi

if ! rg -q '^#!\[allow\(unsafe_code\)\]$' "$allowed_file"; then
  echo 'Windows FFI exception must remain a file-scoped allowance' >&2
  exit 1
fi
