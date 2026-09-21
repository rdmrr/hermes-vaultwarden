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

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_hermes_fixture import require_hermes_fixture
from scripts.hermes_vaultwarden_bootstrap import InstallLayout, render_env_script


def _copy_tracked_repo_content(project_root: Path, dest: Path) -> None:
    """Copy only this repo's own Git-tracked files into ``dest``.

    ``git ls-files`` lists exactly the versioned content of this repository --
    never anything checked out alongside or underneath it (e.g. a pinned
    fixture repo checked out as a sibling directory locally, or as a
    subdirectory of the same checkout in CI, see .github/workflows/
    repository-safety.yml's ".hermes-fixture" checkout path). This keeps the
    scan scoped to our own repo regardless of where such a fixture physically
    lands relative to project_root.
    """
    result = subprocess.run(
        ["git", "-C", str(project_root), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    tracked = [p for p in result.stdout.decode("utf-8").split("\0") if p]
    for rel in tracked:
        src_file = project_root / rel
        if not src_file.is_file():
            continue
        dest_file = dest / rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_file, dest_file)


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

        # Scan a copy of ONLY this repo's Git-tracked files, never the whole
        # project_root directory tree. project_root may have extra content
        # sitting next to (locally) or inside (CI: .hermes-fixture/, see
        # .github/workflows/repository-safety.yml) our own checkout -- e.g.
        # the pinned Hermes fixture repo used elsewhere in this test module.
        # That fixture is a real, independent project with its own findings
        # profile and must never be attributed to *our* plugin scan verdict.
        with tempfile.TemporaryDirectory() as tmp:
            scan_root = Path(tmp) / "hermes-vaultwarden"
            scan_root.mkdir()
            _copy_tracked_repo_content(project_root, scan_root)
            result = scan_plugin(scan_root, source="rdmrr/hermes-vaultwarden")

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
