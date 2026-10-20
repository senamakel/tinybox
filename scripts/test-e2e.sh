#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
target="$(rustc -vV | sed -n 's/^host: //p')"
version="$(cargo metadata --manifest-path Cargo.toml --format-version 1 --no-deps | jq -er '.packages[] | select(.name == "tinybox-module") | .version')"
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*)
    pwsh -NoProfile -File scripts/build-module.ps1 -Crate tinybox-module -Version "$version" -Target "$target" -HostKey ci -OutputDir target/module-e2e
    pwsh -NoProfile -File scripts/verify-module.ps1 -Archive "target/module-e2e/tinybox-$version-ci.zip"
    module_library="${CARGO_TARGET_DIR:-$PWD/target}/module-package/tinybox.dll"
    ;;
  *)
    scripts/build-module.sh --crate tinybox-module --version "$version" --target "$target" --host ci --output-dir target/module-e2e
    scripts/verify-module.sh --archive "target/module-e2e/tinybox-$version-ci.tar.gz"
    case "${RUNNER_OS:-$(uname -s)}" in
      macOS|Darwin) module_library="libtinybox.dylib" ;;
      *) module_library="libtinybox.so" ;;
    esac
    module_library="${CARGO_TARGET_DIR:-$PWD/target}/module-package/$module_library"
    ;;
esac

# Exercise the packaged compiled module with its migration endpoint before a
# host exposes the ordinary TinyBox storage interface.
TINYBOX_TEST_MODULE="$module_library" cargo test --locked \
  --package tinybox-module --test module_e2e \
  compiled_module_migrates_owner_data_before_storage_is_served \
  -- --ignored --exact --nocapture
