"""Exercise TinyBox's release routing and input guards without network access."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/release.yml"


def resolve_script(workflow):
    match = re.search(
        r"(?ms)^      - id: tag\n.*?^        run: \|\n((?:^          .*\n|^\n)+)",
        workflow,
    )
    if not match:
        raise AssertionError("release resolve script was not found")
    return "\n".join(
        line[10:] if line.startswith("          ") else ""
        for line in match[1].splitlines()
    )


def job_block(workflow, name):
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", workflow
    )
    if not match:
        raise AssertionError(f"release job {name} was not found")
    return match[1]


def job_permissions(block):
    match = re.search(r"(?ms)^    permissions:\n((?:^      [a-z-]+: [a-z]+\n)+)", block)
    if not match:
        raise AssertionError("job permissions were not found")
    return dict(re.findall(r"(?m)^      ([a-z-]+): ([a-z]+)$", match[1]))


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.script = resolve_script(cls.workflow)

    def run_resolve(self, mode="main", reviewed_pr=""):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = dict(
                os.environ,
                TAG="v1.2.3",
                RELEASE_MODE=mode,
                REVIEWED_PR=reviewed_pr,
                GITHUB_OUTPUT=str(output),
            )
            result = subprocess.run(
                ["bash", "-c", self.script],
                cwd=directory,
                env=env,
                text=True,
                capture_output=True,
            )
            return result, output.read_text() if output.exists() else ""

    def test_manual_default_and_tag_push_use_the_ordinary_route(self):
        self.assertIn("default: main", self.workflow)
        self.assertIn("github.event_name == 'push' && 'main' || inputs.release_mode", self.workflow)
        self.assertIn("github.event_name == 'push' && github.ref_name || inputs.tag", self.workflow)
        result, output = self.run_resolve()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release_mode=main", output)
        self.assertIn("reviewed_pr=0", output)

    def test_resolve_script_runs_without_a_repository_checkout_as_cwd(self):
        result, output = self.run_resolve()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tag=v1.2.3", output)
        self.assertIn("version=1.2.3", output)
        self.assertIn("reviewed_pr=0", output)

    def test_reviewed_epic_accepts_and_forwards_positive_integer_pr(self):
        result, output = self.run_resolve("reviewed-epic", "91")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release_mode=reviewed-epic", output)
        self.assertIn("reviewed_pr=91", output)

    def test_reviewed_epic_rejects_missing_zero_negative_fractional_and_text_prs(self):
        for value in ("", "0", "-1", "1.5", "abc"):
            with self.subTest(value=value):
                result, _ = self.run_resolve("reviewed-epic", value)
                self.assertEqual(result.returncode, 2)
                self.assertIn("reviewed_pr must be a positive integer", result.stderr)

    def test_ordinary_route_rejects_reviewed_pr_and_emits_zero_sentinel(self):
        result, _ = self.run_resolve("main", "91")
        self.assertEqual(result.returncode, 2)
        self.assertIn("reviewed_pr is only valid", result.stderr)
        result, output = self.run_resolve("main", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reviewed_pr=0", output)

    def test_unrecognized_release_mode_fails_closed(self):
        result, _ = self.run_resolve("arbitrary", "")
        self.assertEqual(result.returncode, 2)
        self.assertIn("release_mode must be main or reviewed-epic", result.stderr)

    def test_only_fixed_package_and_reviewed_workflow_profile_are_callable(self):
        self.assertIn("module-crate: tinybox-module", self.workflow)
        self.assertIn("asset-name: tinybox", self.workflow)
        self.assertIn(
            "uses: tinyhumansai/.github/.github/workflows/module-release.yml@"
            "4adc1080fb495098e7af1aade82ed7e6e3c69bb7",
            self.workflow,
        )
        self.assertIn(
            "uses: tinyhumansai/.github/.github/workflows/module-reviewed-epic-release.yml@"
            "6ed83b04aab2d8977ec62e966cb914531e534fa4",
            self.workflow,
        )
        self.assertIn(
            "reviewed-pr: ${{ fromJSON(needs.resolve.outputs.reviewed_pr || '0') }}",
            self.workflow,
        )
        self.assertNotIn("inputs.package", self.workflow)
        self.assertNotIn("inputs.repo", self.workflow)

    def test_reviewed_route_uses_the_pinned_canonical_admission_workflow(self):
        reviewed = job_block(self.workflow, "module-reviewed-epic-release")
        self.assertRegex(
            reviewed,
            r"(?m)^    uses: tinyhumansai/\.github/\.github/workflows/"
            r"module-reviewed-epic-release\.yml@6ed83b04aab2d8977ec62e966cb914531e534fa4$",
        )
        self.assertIn(
            "reviewed-pr: ${{ fromJSON(needs.resolve.outputs.reviewed_pr || '0') }}",
            reviewed,
        )
        self.assertNotRegex(reviewed, r"(?m)^      - uses: actions/checkout@")

    def test_sdk_and_release_versions_are_exactly_pinned(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        client = tomllib.loads((ROOT / "crates/tinybox-client/Cargo.toml").read_text())
        self.assertEqual(workspace["workspace"]["package"]["version"], "0.1.39")
        self.assertEqual(
            workspace["workspace"]["dependencies"]["tinybox-client"],
            {"path": "crates/tinybox-client", "version": "0.1.39"},
        )
        self.assertEqual(
            workspace["workspace"]["dependencies"]["tinybus"]["version"], "=0.3.3"
        )
        self.assertEqual(
            workspace["workspace"]["dependencies"]["tinybus-module"], "=0.3.3"
        )
        for table_name in ("dependencies", "dev-dependencies"):
            dependencies = client[table_name]
            self.assertEqual(dependencies["tinybus"]["version"], "=0.3.3")
            self.assertEqual(dependencies["tinybus"]["path"], "../../vendor/tinybus/crates/tinybus")
        self.assertEqual(
            client["dev-dependencies"]["tinybus-module"]["version"], "=0.3.3"
        )
        self.assertEqual(
            client["dev-dependencies"]["tinybus-module"]["path"],
            "../../vendor/tinybus/crates/tinybus-module",
        )
        gitlink = subprocess.run(
            ["git", "ls-files", "-s", "vendor/tinybus"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.split()
        self.assertGreaterEqual(len(gitlink), 3)
        self.assertEqual(gitlink[1], "207a9a7df15e44fdba00a807d0f7eaf21904ba0e")

    def test_release_caller_keeps_ordinary_route_and_pins_current_reviewed_route(self):
        ordinary = "4adc1080fb495098e7af1aade82ed7e6e3c69bb7"
        reviewed = "6ed83b04aab2d8977ec62e966cb914531e534fa4"
        self.assertIn(f"module-ci.yml@{ordinary}", (ROOT / ".github/workflows/ci.yml").read_text())
        self.assertIn(f"module-release.yml@{ordinary}", self.workflow)
        self.assertIn(f"module-reviewed-epic-release.yml@{reviewed}", self.workflow)
        self.assertNotIn("837d0424c7f38e4293f41c795f12ed5eb5dd7280", self.workflow)

    def test_release_routes_are_exclusive_and_permissions_are_minimal(self):
        ordinary = job_block(self.workflow, "module-release")
        reviewed = job_block(self.workflow, "module-reviewed-epic-release")
        self.assertRegex(ordinary, r"(?m)^    if: needs\.resolve\.outputs\.release_mode == 'main'$")
        self.assertRegex(
            reviewed,
            r"(?m)^    if: needs\.resolve\.outputs\.release_mode == 'reviewed-epic'$")
        self.assertEqual(job_permissions(ordinary), {"contents": "write"})
        self.assertEqual(job_permissions(reviewed), {
            "contents": "write",
            "pull-requests": "read",
            "checks": "read",
            "actions": "read",
        })
        self.assertRegex(self.workflow, r"(?m)^permissions: \{\}$")


if __name__ == "__main__":
    unittest.main()
