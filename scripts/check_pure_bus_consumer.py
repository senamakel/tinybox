"""Fail-closed checks for TinyBox's isolated storage-needs consumer graph."""

from pathlib import Path
import re
import sys
import tomllib

STORAGE_BUS_NAME = "tinystoragedrivers-bus"
STORAGE_BUS_VERSION = "1.5.0"
STORAGE_BUS_URL = "https://github.com/tinyhumansai/tinystoragedrivers"
STORAGE_BUS_REV = "c9ea6ff1615b77b55d7269403af5fd11bedc9ce8"
STORAGE_BUS_SOURCE = f"git+{STORAGE_BUS_URL}?rev={STORAGE_BUS_REV}#{STORAGE_BUS_REV}"
PURE_CONSUMER_NAME = "tinybox-bus-pure-consumer"

FORBIDDEN_PACKAGES = {
    "async-std", "mio", "socket2", "polling", "tokio", "tokio-util",
    "smol", "axum", "hyper", "hyper-util", "http", "http-body",
    "http-body-util", "reqwest", "ureq", "tower", "tower-http",
    "rusqlite", "sqlite", "mongodb", "sqlx", "sled", "redb",
    "rocksdb", "redis",
}


class ProofError(ValueError):
    """The pure consumer did not resolve to the reviewed contract graph."""


def _load_toml(contents: str, label: str) -> dict:
    try:
        value = tomllib.loads(contents)
    except (tomllib.TOMLDecodeError, TypeError) as error:
        raise ProofError(f"{label} is missing or malformed TOML") from error
    if not isinstance(value, dict):
        raise ProofError(f"{label} is missing or malformed TOML")
    return value


def validate_manifest(contents: str) -> None:
    """Require a direct dependency on the canonical data-only storage bus."""
    manifest = _load_toml(contents, "pure consumer manifest")
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict) or set(dependencies) != {
        "tinybox-bus", STORAGE_BUS_NAME,
    }:
        raise ProofError("pure consumer direct dependencies are not the exact bus pair")
    if dependencies["tinybox-bus"] != {"path": ".."}:
        raise ProofError("pure consumer tinybox-bus dependency is not the local bus crate")
    expected = {
        "version": STORAGE_BUS_VERSION,
        "git": STORAGE_BUS_URL,
        "rev": STORAGE_BUS_REV,
        "default-features": False,
    }
    if dependencies[STORAGE_BUS_NAME] != expected:
        raise ProofError("pure consumer storage bus dependency is not the exact data-only pin")


def validate_lockfile(contents: str) -> None:
    """Require one lock resolution with the exact canonical source identity."""
    lockfile = _load_toml(contents, "pure consumer lockfile")
    packages = lockfile.get("package")
    if not isinstance(packages, list):
        raise ProofError("pure consumer lockfile has no package resolution evidence")
    matches = [package for package in packages
               if isinstance(package, dict) and package.get("name") == STORAGE_BUS_NAME]
    if len(matches) != 1:
        raise ProofError("pure consumer lockfile must resolve exactly one storage bus package")
    package = matches[0]
    if package.get("version") != STORAGE_BUS_VERSION or package.get("source") != STORAGE_BUS_SOURCE:
        raise ProofError("pure consumer lockfile storage bus version and source do not match the published pin")


def validate_dependency_graph(contents: str, workspace_version: str) -> None:
    """Check the complete normal/build Cargo tree and its activated features."""
    versions = {"tinybox-bus": set(), STORAGE_BUS_NAME: set()}
    lines = [line for line in contents.splitlines() if line.strip()]
    if not lines:
        raise ProofError("normal/build dependency graph is missing")
    for line in lines:
        fields = line.split(maxsplit=2)
        if len(fields) < 2 or not fields[1].startswith("v"):
            raise ProofError(f"normal/build dependency graph has an unrecognized package line: {line}")
        name, version = fields[:2]
        features = set(re.findall(r"[A-Za-z0-9_-]+", fields[2] if len(fields) == 3 else ""))

        if name == "tinybox-bus":
            versions[name].add(version)
        elif name == STORAGE_BUS_NAME:
            versions[name].add(version)
            if "client" in features:
                raise ProofError("pure consumer unexpectedly enabled the storage bus client feature")
        elif name.startswith("tinystoragedrivers-"):
            raise ProofError(f"pure consumer unexpectedly depends on storage implementation crate {name}")
        elif name.startswith("tinybox-") and name != PURE_CONSUMER_NAME:
            raise ProofError(f"pure consumer unexpectedly depends on TinyBox implementation crate {name}")
        elif name == "tinybus" or name.startswith("tinybus-"):
            raise ProofError(f"pure consumer unexpectedly depends on TinyBus runtime crate {name}")
        elif name in FORBIDDEN_PACKAGES:
            raise ProofError(f"pure consumer unexpectedly depends on runtime, HTTP, or database crate {name}")

    expected_versions = {
        "tinybox-bus": {f"v{workspace_version}"},
        STORAGE_BUS_NAME: {f"v{STORAGE_BUS_VERSION}"},
    }
    if versions != expected_versions:
        raise ProofError(
            "normal/build dependency graph is missing or duplicates TinyBox/storage bus "
            "versions: " + repr(versions)
        )


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: check_pure_bus_consumer.py WORKSPACE_VERSION MANIFEST LOCKFILE", file=sys.stderr)
        return 2
    workspace_version, manifest_path, lock_path = sys.argv[1:]
    try:
        validate_manifest(Path(manifest_path).read_text(encoding="utf-8"))
        validate_lockfile(Path(lock_path).read_text(encoding="utf-8"))
        validate_dependency_graph(sys.stdin.read(), workspace_version)
    except (OSError, ProofError) as error:
        print(f"pure consumer proof refused: {error}", file=sys.stderr)
        return 1
    print("pure consumer resolves only the canonical data-only storage contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
