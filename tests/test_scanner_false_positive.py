"""Regression test for VW-016: the community-plugin scanner must not flag
render_env_script()'s legitimate systemd LoadCredential read as
`read_secrets_file` (severity critical) just because the shell it renders
reads $CREDENTIALS_DIRECTORY (which happens to contain the substring
"credentials") via `cat` on the same source line.

This test exercises Hermes' *real* scanner (tools/skills_guard.py /
tools/plugin_guard.py) from the pinned Hermes fixture (HERMES_AGENT_SRC,
see scripts/check_hermes_fixture.py) against:

1. scripts/hermes_vaultwarden_bootstrap.py itself (the Python source), and
2. the actual string produced by render_env_script() (the generated
   /bin/sh script that systemd's ExecStartPre= runs).

Neither must produce a "critical" finding, and the pinned plugin repo
verdict must not be "dangerous" (which blocks `hermes plugins install`
even with --force).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.check_hermes_fixture import require_hermes_fixture
from scripts.hermes_vaultwarden_bootstrap import InstallLayout, render_env_script


def setUpModule() -> None:
    require_hermes_fixture()


class ScannerFalsePositiveTests(unittest.TestCase):
    """VW-016 regression: scanner must not flag the credential read as critical."""

    @staticmethod
    def _critical_findings(findings):
        return [finding for finding in findings if finding.severity == "critical"]

    def test_python_source_has_no_critical_findings(self):
        from tools.skills_guard import scan_file

        source_path = Path(__file__).resolve().parents[1] / "scripts" / "hermes_vaultwarden_bootstrap.py"
        self.assertTrue(source_path.is_file(), f"missing source file: {source_path}")

        findings = scan_file(source_path, rel_path="scripts/hermes_vaultwarden_bootstrap.py")
        critical = self._critical_findings(findings)
        self.assertEqual(
            [],
            critical,
            f"scripts/hermes_vaultwarden_bootstrap.py has critical scanner findings: {critical}",
        )

    def test_rendered_env_script_has_no_critical_findings(self):
        from tools.skills_guard import scan_file

        layout = InstallLayout.for_system(
            profile="scanner-regression-demo",
            unit="hermes-vaultwarden-scanner-regression-demo.service",
            root=Path("/"),
        )
        rendered = render_env_script(layout)

        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "hermes-vaultwarden-env.sh"
            script_path.write_text(rendered, encoding="utf-8")
            findings = scan_file(script_path, rel_path="hermes-vaultwarden-env.sh")

        critical = self._critical_findings(findings)
        self.assertEqual(
            [],
            critical,
            f"rendered env script has critical scanner findings: {critical}",
        )

    def test_full_plugin_scan_is_not_dangerous(self):
        from tools.plugin_guard import scan_plugin

        project_root = Path(__file__).resolve().parents[1]
        result = scan_plugin(project_root, source="rdmrr/hermes-vaultwarden")

        self.assertNotEqual(
            "dangerous",
            result.verdict,
            f"plugin scan verdict is 'dangerous' (blocks install): findings={result.findings}",
        )
        critical = self._critical_findings(result.findings)
        self.assertEqual(
            [],
            critical,
            f"full repository scan still has critical findings: {critical}",
        )


if __name__ == "__main__":
    unittest.main()
