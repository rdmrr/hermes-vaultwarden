from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts.check_hermes_fixture import require_hermes_fixture


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "run_profile_integration.py"


def setUpModule() -> None:
    require_hermes_fixture()


class PortableProfileIntegrationTests(unittest.TestCase):
    EXPECTED_REPORT = {
        "initial": {
            "started": True,
            "applied": True,
            "source": "vaultwarden",
        },
        "rotation": {
            "started": True,
            "recognized": True,
            "source": "vaultwarden",
        },
        "missing_bootstrap": {
            "started": True,
            "applied": False,
            "error_kind": "not_configured",
        },
        "authentication_failure": {
            "started": True,
            "applied": False,
            "error_kind": "auth_failed",
        },
        "binary_tamper": {
            "started": True,
            "applied": False,
            "error_kind": "binary_missing",
        },
    }

    def test_profile_start_rotation_and_failure_contract(self):
        from scripts.run_profile_integration import run_profile_integration

        report = run_profile_integration(PROJECT_ROOT)

        self.assertEqual(self.EXPECTED_REPORT, report)

    def test_runner_does_not_mutate_caller_environment_or_registry(self):
        from agent.secret_sources.base import FetchResult, SecretSource
        from agent.secret_sources.registry import get_source, register_source
        from scripts.run_profile_integration import run_profile_integration

        class SentinelSource(SecretSource):
            name = "profiletestsentinel"

            def fetch(self, cfg, home_path):
                return FetchResult()

        sentinel = SentinelSource()
        self.assertTrue(register_source(sentinel))
        try:
            with mock.patch.dict(
                os.environ,
                {"SYNTHETIC_PROFILE_API_KEY": "caller-owned-value"},
                clear=False,
            ):
                self.assertEqual(self.EXPECTED_REPORT, run_profile_integration(PROJECT_ROOT))
                self.assertEqual(
                    "caller-owned-value",
                    os.environ["SYNTHETIC_PROFILE_API_KEY"],
                )
            self.assertIs(sentinel, get_source("profiletestsentinel"))
        finally:
            from agent.secret_sources import registry

            registry._reset_registry_for_tests()

    def test_start_probe_reports_exceptions_as_not_started(self):
        from scripts.run_profile_integration import _start_profile

        class BrokenManager:
            def discover_and_load(self, force=False):
                raise RuntimeError("synthetic startup failure")

        self.assertFalse(_start_profile(BrokenManager(), force=True))

    def test_report_validation_fails_closed(self):
        from scripts.run_profile_integration import validate_report

        self.assertTrue(validate_report(self.EXPECTED_REPORT))
        incomplete = dict(self.EXPECTED_REPORT)
        incomplete.pop("binary_tamper")
        self.assertFalse(validate_report(incomplete))
        wrong_rotation = json.loads(json.dumps(self.EXPECTED_REPORT))
        wrong_rotation["rotation"]["recognized"] = False
        self.assertFalse(validate_report(wrong_rotation))

    def test_cli_emits_only_non_secret_json_evidence(self):
        proc = subprocess.run(
            [sys.executable, str(RUNNER), "--project-root", str(PROJECT_ROOT)],
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )

        self.assertEqual(0, proc.returncode, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["rotation"]["recognized"])
        combined_output = proc.stdout + proc.stderr
        self.assertNotIn("synthetic-value-one", combined_output)
        self.assertNotIn("synthetic-value-two", combined_output)
        self.assertNotIn("synthetic-client-secret", combined_output)
        self.assertNotIn("synthetic-master-credential", combined_output)


if __name__ == "__main__":
    unittest.main()
