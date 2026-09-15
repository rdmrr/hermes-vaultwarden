from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_hermes_fixture


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHECKER = PROJECT_ROOT / "scripts" / "check_hermes_fixture.py"
WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "repository-safety.yml"


class HermesFixtureTests(unittest.TestCase):
    @staticmethod
    def _write_fixture_skeleton(root: Path) -> None:
        for relative in check_hermes_fixture._REQUIRED_PATHS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

    def test_fixture_at_wrong_commit_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture_skeleton(root)
            env = {
                "HERMES_AGENT_SRC": str(root),
                "PYTHONPATH": str(root),
            }
            git_result = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout="0" * 40 + "\n",
                stderr="",
            )
            with mock.patch.object(
                check_hermes_fixture.subprocess,
                "run",
                return_value=git_result,
            ):
                with self.assertRaisesRegex(
                    check_hermes_fixture.HermesFixtureError,
                    "pinned commit",
                ):
                    check_hermes_fixture.require_hermes_fixture(env)

    def test_fixture_discovery_error_is_reported_as_fixture_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture_skeleton(root)
            env = {
                "HERMES_AGENT_SRC": str(root),
                "PYTHONPATH": str(root),
            }
            git_result = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=check_hermes_fixture.HERMES_FIXTURE_COMMIT + "\n",
                stderr="",
            )
            with (
                mock.patch.object(
                    check_hermes_fixture.subprocess,
                    "run",
                    return_value=git_result,
                ),
                mock.patch.object(
                    check_hermes_fixture.importlib.util,
                    "find_spec",
                    side_effect=ImportError("synthetic discovery failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    check_hermes_fixture.HermesFixtureError,
                    "not importable",
                ):
                    check_hermes_fixture.require_hermes_fixture(env)

    def test_ci_uses_pinned_official_fixture_and_explicit_pythonpath(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("repository: NousResearch/hermes-agent", workflow)
        self.assertIn("ref: fef0bc56b2f622ffe124835fbf57adfd10aa17e6", workflow)
        self.assertIn("HERMES_AGENT_SRC:", workflow)
        self.assertIn("PYTHONPATH:", workflow)
        self.assertIn("python3 scripts/check_hermes_fixture.py", workflow)
        self.assertIn('python3 -m pip install --editable "$HERMES_AGENT_SRC"', workflow)

    def test_contract_profile_and_process_tests_require_declared_fixture(self):
        env = os.environ.copy()
        env.pop("HERMES_AGENT_SRC", None)
        env["PYTHONPATH"] = str(PROJECT_ROOT)

        for pattern in (
            "test_hermes_contract.py",
            "test_profile_integration.py",
            "test_process_paths.py",
        ):
            with self.subTest(pattern=pattern):
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        "tests",
                        "-p",
                        pattern,
                        "-v",
                    ],
                    cwd=PROJECT_ROOT,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    check=False,
                )

                combined_output = proc.stdout + proc.stderr
                self.assertNotEqual(0, proc.returncode)
                self.assertIn("HERMES_AGENT_SRC", combined_output)
                self.assertNotIn("skipped", combined_output)

    def test_missing_fixture_fails_with_clear_error(self):
        env = os.environ.copy()
        env.pop("HERMES_AGENT_SRC", None)
        proc = subprocess.run(
            [sys.executable, str(CHECKER)],
            cwd=PROJECT_ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )

        self.assertNotEqual(0, proc.returncode)
        self.assertIn("HERMES_AGENT_SRC", proc.stderr)
        self.assertNotIn("skipped", proc.stdout + proc.stderr)

    def test_incomplete_fixture_fails_with_required_contract_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["HERMES_AGENT_SRC"] = tmp
            proc = subprocess.run(
                [sys.executable, str(CHECKER)],
                cwd=PROJECT_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )

        self.assertNotEqual(0, proc.returncode)
        self.assertIn("agent/secret_sources/base.py", proc.stderr)


if __name__ == "__main__":
    unittest.main()
