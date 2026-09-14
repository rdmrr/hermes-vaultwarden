from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "run_process_path_integration.py"


class ProcessPathIntegrationTests(unittest.TestCase):
    EXPECTED_REPORT = {
        "cron": {
            "ambient_rejected": True,
            "profile_resolved": True,
            "scope_restored": True,
        },
        "gateway": {
            "ambient_rejected": True,
            "profile_resolved": True,
            "scope_restored": True,
        },
        "multiplex_gateway": {
            "cross_profile_rejected": True,
            "primary_resolved": True,
            "scope_restored": True,
            "secondary_resolved": True,
        },
        "subagent": {
            "ambient_rejected": True,
            "credential_inherited": True,
            "scope_restored": True,
        },
    }

    def test_each_process_path_passes_its_isolated_contract(self):
        from scripts.run_process_path_integration import run_process_path_integration

        self.assertEqual(self.EXPECTED_REPORT, run_process_path_integration(PROJECT_ROOT))

    def test_report_validation_fails_closed(self):
        from scripts.run_process_path_integration import validate_report

        self.assertTrue(validate_report(self.EXPECTED_REPORT))
        incomplete = dict(self.EXPECTED_REPORT)
        incomplete.pop("cron")
        self.assertFalse(validate_report(incomplete))
        wrong_scope = json.loads(json.dumps(self.EXPECTED_REPORT))
        wrong_scope["multiplex_gateway"]["cross_profile_rejected"] = False
        self.assertFalse(validate_report(wrong_scope))

    def test_worker_failure_does_not_relay_stderr(self):
        from scripts.run_process_path_integration import run_process_path_integration

        failed = subprocess.CompletedProcess(
            args=["synthetic-worker"],
            returncode=1,
            stdout="",
            stderr="synthetic-master-credential",
        )
        with mock.patch(
            "scripts.run_process_path_integration.subprocess.run",
            return_value=failed,
        ):
            with self.assertRaises(RuntimeError) as raised:
                run_process_path_integration(PROJECT_ROOT)

        self.assertNotIn("synthetic-master-credential", str(raised.exception))

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
            timeout=60,
            check=False,
        )

        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(self.EXPECTED_REPORT, json.loads(proc.stdout))
        combined_output = proc.stdout + proc.stderr
        for secret in (
            "synthetic-path-primary",
            "synthetic-path-secondary",
            "ambient-wrong-profile",
            "synthetic-client-secret",
            "synthetic-master-credential",
        ):
            self.assertNotIn(secret, combined_output)


if __name__ == "__main__":
    unittest.main()
