"""Regression tests for the isolated TinyBox storage-contract consumer proof."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_pure_bus_consumer import (  # noqa: E402
    ProofError,
    validate_dependency_graph,
    validate_lockfile,
    validate_manifest,
)


STORAGE_URL = "https://github.com/tinyhumansai/tinystoragedrivers"
STORAGE_REV = "c9ea6ff1615b77b55d7269403af5fd11bedc9ce8"
STORAGE_SOURCE = f"git+{STORAGE_URL}?rev={STORAGE_REV}#{STORAGE_REV}"


def manifest(storage_dependency=None):
    storage_dependency = storage_dependency or {
        "version": "1.5.0",
        "git": STORAGE_URL,
        "rev": STORAGE_REV,
        "default-features": False,
    }
    extra_features = ', features = ["client"]' if "features" in storage_dependency else ""
    return f'''[package]
name = "tinybox-bus-pure-consumer"
version = "0.1.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
tinybox-bus = {{ path = ".." }}
tinystoragedrivers-bus = {{ version = "{storage_dependency['version']}", git = "{storage_dependency['git']}", rev = "{storage_dependency['rev']}", default-features = {str(storage_dependency['default-features']).lower()}{extra_features} }}
'''


def lockfile(version="1.5.0", source=STORAGE_SOURCE):
    return f'''version = 4

[[package]]
name = "tinybox-bus-pure-consumer"
version = "0.1.0"
dependencies = [
 "tinystoragedrivers-bus",
 "tinybox-bus",
]

[[package]]
name = "tinystoragedrivers-bus"
version = "{version}"
source = "{source}"
'''


VALID_TREE = """tinybox-bus-pure-consumer v0.1.0
tinybox-bus v0.1.39 [default]
tinystoragedrivers-bus v1.5.0 []
serde v1.0.0 [default, derive, std]
"""


class PureBusConsumerProofTests(unittest.TestCase):
    def test_accepts_exact_published_dependency_and_normal_build_feature_graph(self):
        validate_manifest(manifest())
        validate_lockfile(lockfile())
        validate_dependency_graph(VALID_TREE, "0.1.39")

    def test_rejects_old_published_release_even_when_it_was_the_previous_expected_pin(self):
        with self.assertRaisesRegex(ProofError, "version and source"):
            validate_lockfile(lockfile("1.3.0", "git+" + STORAGE_URL + "?rev=08caa16d1d4e3c6b8d649e4f26fe1a426ee1d168#08caa16d1d4e3c6b8d649e4f26fe1a426ee1d168"))

    def test_rejects_wrong_revision_with_the_correct_version_and_url(self):
        wrong_rev = "a" * 40
        with self.assertRaisesRegex(ProofError, "version and source"):
            validate_lockfile(lockfile("1.5.0", f"git+{STORAGE_URL}?rev={wrong_rev}#{wrong_rev}"))

    def test_rejects_missing_or_duplicate_lock_resolution_evidence(self):
        with self.assertRaisesRegex(ProofError, "resolution evidence"):
            validate_lockfile("version = 4\n")
        duplicate_package = lockfile().split("[[package]]\n")[2]
        duplicated = lockfile() + "\n[[package]]\n" + duplicate_package
        with self.assertRaisesRegex(ProofError, "exactly one"):
            validate_lockfile(duplicated)

    def test_rejects_noncanonical_or_featureful_direct_manifest_dependency(self):
        for dependency in (
            {"version": "1.5.0", "git": STORAGE_URL + ".git", "rev": STORAGE_REV, "default-features": False},
            {"version": "1.5.0", "git": STORAGE_URL, "rev": "08caa16d1d4e3c6b8d649e4f26fe1a426ee1d168", "default-features": False},
            {"version": "1.5.0", "git": STORAGE_URL, "rev": STORAGE_REV, "default-features": True},
            {"version": "1.5.0", "git": STORAGE_URL, "rev": STORAGE_REV, "default-features": False, "features": ["client"]},
        ):
            with self.subTest(dependency=dependency), self.assertRaises(ProofError):
                validate_manifest(manifest(dependency))

    def test_rejects_client_feature_and_implementation_runtime_or_database_nodes(self):
        bad_trees = (
            VALID_TREE.replace("tinystoragedrivers-bus v1.5.0 []", "tinystoragedrivers-bus v1.5.0 [client]"),
            VALID_TREE + "tinystoragedrivers-client v1.5.0\n",
            VALID_TREE + "tinybox-module v0.1.39\n",
            VALID_TREE + "tokio v1.0.0 [rt]\n",
            VALID_TREE + "sqlx v0.8.0\n",
        )
        for tree in bad_trees:
            with self.subTest(tree=tree), self.assertRaises(ProofError):
                validate_dependency_graph(tree, "0.1.39")

    def test_rejects_missing_duplicate_or_wrong_versions_in_the_resolved_graph(self):
        for tree in (
            "tinybox-bus-pure-consumer v0.1.0\ntinybox-bus v0.1.39\n",
            VALID_TREE + "tinystoragedrivers-bus v1.3.0\n",
            VALID_TREE + "tinybox-bus v0.1.36\n",
        ):
            with self.subTest(tree=tree), self.assertRaises(ProofError):
                validate_dependency_graph(tree, "0.1.39")

    def test_proof_command_covers_normal_build_edges_and_enabled_features(self):
        script = (ROOT / "scripts/test-pure-bus-consumer.sh").read_text()
        self.assertIn("--format '{p} {f}' -e normal,build", script)


if __name__ == "__main__":
    unittest.main()
