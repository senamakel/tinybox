"""Guard TinyBox's direct TinyBus feature edges against workspace leakage."""

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def _features(workspace: dict, dependency: dict) -> set[str]:
    """Return enabled direct features after resolving workspace inheritance."""
    inherited = workspace["workspace"]["dependencies"]["tinybus"]
    if dependency.get("workspace") is not True:
        raise AssertionError("TinyBus consumer must inherit the canonical workspace dependency")
    return set(inherited.get("features", ())) | set(dependency.get("features", ()))


def check() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if _features(workspace, {"workspace": True}) != set():
        raise AssertionError("shared TinyBus dependency must not activate optional features")
    if workspace["workspace"]["dependencies"]["tinybus"].get("default-features") is not False:
        raise AssertionError("shared TinyBus dependency must disable default features")

    module = tomllib.loads((ROOT / "crates/tinybox-module/Cargo.toml").read_text(encoding="utf-8"))
    module_features = _features(workspace, module["dependencies"]["tinybus"])
    if module_features != {"macros", "modules"}:
        raise AssertionError(f"module TinyBus edge must enable macros and modules, got {module_features}")

    client = tomllib.loads((ROOT / "crates/tinybox-client/Cargo.toml").read_text(encoding="utf-8"))
    client_normal = _features(workspace, client["dependencies"]["tinybus"])
    if client_normal != {"modules"}:
        raise AssertionError(f"client normal TinyBus edge must enable only required modules, got {client_normal}")
    client_dev = _features(workspace, client["dev-dependencies"]["tinybus"])
    if client_dev != {"macros", "modules"}:
        raise AssertionError(f"client test TinyBus edge must retain macros and modules, got {client_dev}")

    client_source = (ROOT / "crates/tinybox-client/src/lib.rs").read_text(encoding="utf-8")
    if "tinybus::module::{ModuleCallError, ModuleClient}" not in client_source:
        raise AssertionError("client's normal modules feature must remain justified by its public ModuleClient API")


if __name__ == "__main__":
    check()
    print("TinyBus workspace and consumer feature edges are isolated")
