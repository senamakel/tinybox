"""Check that feature CI supplies the tools its host fixtures require."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
PURE_CONSUMER = "crates/tinybox-bus/pure-consumer/Cargo.toml"

def workspace_version():
    in_package = False
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        line = line.strip()
        if line.startswith("["):
            in_package = line == "[workspace.package]"
        elif in_package and line.startswith("version ="):
            return line.split('"')[1]
    raise AssertionError("[workspace.package] has no version")

EXPECTED_CARGO_CALLS = [
    "test --locked --workspace",
    f"run --locked --manifest-path {PURE_CONSUMER} --target-dir target",
    f"tree --locked --manifest-path {PURE_CONSUMER} --prefix none --format {{p}} {{f}} -e normal,build",
    "tree --locked -p tinybox-bus --all-features --prefix none --format {p} {f} -e normal,build",
    "test --locked --workspace --all-features",
]

def fake_cargo():
    return '''#!/bin/sh
set -eu
[ "$(command -v setsid)" = "$FIXTURE_PREFIX/bin/setsid" ] || exit 1
printf "%s\\n" "$*" >> "$FIXTURE_CALLS"
case "$1" in
  run) exit 0 ;;
  tree)
    case " $* " in
      *" -p tinybox-bus --all-features "*)
        printf "%s\\n" \\
          "tinybox-bus v$FIXTURE_WORKSPACE_VERSION [default,storage]" \\
          "tinystoragedrivers-bus v1.5.0 []"
        ;;
      *)
        printf "%s\\n" \\
          "tinybox-bus-pure-consumer v0.1.0" \\
          "tinybox-bus v$FIXTURE_WORKSPACE_VERSION [default]" \\
          "tinystoragedrivers-bus v1.5.0 []"
        ;;
    esac
    ;;
  test) ;;
  *) exit 2 ;;
esac
'''

class FeatureEnvironmentTests(unittest.TestCase):
    def test_macos_exposes_util_linux_before_all_feature_checks(self):
        """The keg-only setsid must be on PATH for every Cargo invocation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            prefix = root / "util-linux"
            (prefix / "bin").mkdir(parents=True)
            (prefix / "bin/setsid").write_text("#!/bin/sh\nexit 0\n")
            (prefix / "bin/setsid").chmod(0o755)
            fixtures = {
                "brew": '#!/bin/sh\ncase "$1" in\ninstall) exit 0 ;;\n--prefix) printf "%s\\n" "$FIXTURE_PREFIX" ;;\n*) exit 1 ;;\nesac\n',
                "python3": "#!/bin/sh\nexit 0\n",
                "cargo": fake_cargo(),
            }
            for name, source in fixtures.items():
                path = tools / name
                path.write_text(source)
                path.chmod(0o755)
            calls = root / "calls"
            env = dict(os.environ, RUNNER_OS="macOS", FIXTURE_PREFIX=str(prefix),
                       FIXTURE_CALLS=str(calls), FIXTURE_WORKSPACE_VERSION=workspace_version(),
                       PATH=str(tools) + os.pathsep + "/usr/bin:/bin")
            result = subprocess.run(["bash", str(ROOT / "scripts/test-features.sh")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), EXPECTED_CARGO_CALLS)

class WindowsFeatureEnvironmentTests(unittest.TestCase):
    def test_windows_supplies_native_shell_before_all_feature_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            calls = root / "calls"
            ready = root / "ready"
            fixtures = {
                "cygpath": "#!/bin/sh\n[ \"$*\" = \"-w /usr/bin\" ] || exit 1\nprintf \"%s\\n\" \"$FIXTURE_BIN\"\n",
                "pwsh": "#!/bin/sh\n[ \"$*\" = \"-NoProfile -File scripts/test-windows-fixtures.ps1\" ] && exit 0\n[ \"$*\" = \"-NoProfile -File scripts/prepare-windows-fixtures.ps1 -PosixBin $FIXTURE_BIN\" ] || exit 1\ntouch \"$FIXTURE_READY\"\n",
                "python3": "#!/bin/sh\nexit 0\n",
                "cargo": '#!/bin/sh\nset -eu\n[ -f "$FIXTURE_READY" ] || exit 1\nprintf "%s\\n" "$*" >> "$FIXTURE_CALLS"\ncase "$1" in\n  run) exit 0 ;;\n  tree) case " $* " in *" -p tinybox-bus --all-features "*) printf "%s\\n" "tinybox-bus v$FIXTURE_WORKSPACE_VERSION [default,storage]" "tinystoragedrivers-bus v1.5.0 []" ;; *) printf "%s\\n" "tinybox-bus-pure-consumer v0.1.0" "tinybox-bus v$FIXTURE_WORKSPACE_VERSION [default]" "tinystoragedrivers-bus v1.5.0 []" ;; esac ;;\n  test) ;;\n  *) exit 2 ;;\nesac\n',
            }
            for name, source in fixtures.items():
                path = tools / name
                path.write_text(source)
                path.chmod(0o755)
            bash_env = root / "bash-env"
            bash_env.write_text(
                'python3() { "$FIXTURE_TOOL_DIR/python3" "$@"; }\n'
                'cargo() { "$FIXTURE_TOOL_DIR/cargo" "$@"; }\n'
            )
            env = dict(os.environ, RUNNER_OS="Windows", FIXTURE_BIN="C:/Git/usr/bin",
                       FIXTURE_READY=str(ready), FIXTURE_CALLS=str(calls),
                       FIXTURE_WORKSPACE_VERSION=workspace_version(),
                       FIXTURE_TOOL_DIR=str(tools), BASH_ENV=str(bash_env),
                       PATH=str(tools) + os.pathsep + "/usr/bin:/bin")
            result = subprocess.run(["bash", str(ROOT / "scripts/test-features.sh")],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), EXPECTED_CARGO_CALLS)

if __name__ == "__main__":
    unittest.main()
