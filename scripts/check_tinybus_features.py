"""Guard TinyBox's TinyBus dependency edges against workspace feature leakage."""

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_REV = "207a9a7df15e44fdba00a807d0f7eaf21904ba0e"
EXPECTED_GIT = "https://github.com/tinyhumansai/tinybus"


def effective_features(workspace: dict, dependency: dict) -> set[str]:
    """Resolve a workspace-inherited dependency's effective feature list."""
    if dependency.get("workspace") is not True:
        raise AssertionError("TinyBus consumer must inherit the canonical workspace dependency")
    shared = workspace["workspace"]["dependencies"]["tinybus"]
    return set(shared.get("features", ())) | set(dependency.get("features", ()))


def check() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    tinybus = workspace["workspace"]["dependencies"]["tinybus"]
    if tinybus.get("default-features") is not False or tinybus.get("features", []):
        raise AssertionError("shared TinyBus dependency must disable defaults and enable no optional features")
    if (tinybus.get("version"), tinybus.get("git"), tinybus.get("rev")) != (
        ">=0.3.3, <0.4.0", EXPECTED_GIT, EXPECTED_REV
    ):
        raise AssertionError("shared TinyBus dependency must retain its canonical compatible source pin")

    module_manifest = tomllib.loads((ROOT / "crates/tinybox-module/Cargo.toml").read_text(encoding="utf-8"))
    module_features = effective_features(workspace, module_manifest["dependencies"]["tinybus"])
    if module_features != {"macros", "modules"}:
        raise AssertionError(f"module TinyBus edge must enable macros and modules, got {module_features}")

    client_manifest = tomllib.loads((ROOT / "crates/tinybox-client/Cargo.toml").read_text(encoding="utf-8"))
    client_normal = effective_features(workspace, client_manifest["dependencies"]["tinybus"])
    if client_normal:
        raise AssertionError(f"client normal TinyBus edge must remain feature-free, got {client_normal}")
    client_dev = effective_features(workspace, client_manifest["dev-dependencies"]["tinybus"])
    if client_dev != {"macros", "modules"}:
        raise AssertionError(f"client test TinyBus edge must explicitly retain macros and modules, got {client_dev}")

    module_sdk = workspace["workspace"]["dependencies"]["tinybus-module"]
    if (module_sdk.get("version"), module_sdk.get("git"), module_sdk.get("rev")) != (
        ">=0.3.3, <0.4.0", EXPECTED_GIT, EXPECTED_REV
    ):
        raise AssertionError("module SDK must retain its canonical compatible source pin")
    expected_patches = {
        "tinybus": {"path": "vendor/tinybus/crates/tinybus"},
        "tinybus-module": {"path": "vendor/tinybus/crates/tinybus-module"},
    }
    if workspace["patch"].get("crates-io") != expected_patches:
        raise AssertionError("standalone crates.io patches must continue unifying both SDK crates")
    if workspace["patch"].get(EXPECTED_GIT) != expected_patches:
        raise AssertionError("canonical TinyBus source patches must continue unifying both SDK crates")


if __name__ == "__main__":
    check()
    print("TinyBus source identity and consumer feature edges are isolated")
