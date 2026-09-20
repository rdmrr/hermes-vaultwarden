"""Regression test for VW-012: real systemd must actually deliver the three
BW_* environment variables that render_drop_in() configures.

The 17 pre-existing tests in test_bootstrap.py only assert on the *string*
render_drop_in() produces; none of them ever started a real systemd unit.
That is how the "%d" specifier bug (systemd never expands %d in
EnvironmentFile=) went unnoticed until it broke a live cutover. This test
takes the literal directives render_drop_in() emits, feeds them to a real
transient systemd-run unit (system scope, TPM2-encrypted credentials, no
mocking), and asserts BW_CLIENTID / BW_CLIENTSECRET / BW_PASSWORD arrive in
the child process environment. It never asserts or prints their values.

Requires: root (passwordless sudo), systemd-run, systemd-creds with TPM2
support. Skips (not fails) when the host cannot support it, so it stays
CI-safe on hosts without TPM2/root while still running on real targets such
as a production host.
"""

import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from scripts.hermes_vaultwarden_bootstrap import (
    CREDENTIAL_NAMES,
    InstallLayout,
    encrypt_credential,
    render_drop_in,
    render_env_script,
)


def _sudo_n(*argv: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, **kwargs)


def _can_run_real_systemd_test() -> str | None:
    """Return a skip reason, or None if the environment supports this test."""
    if shutil.which("systemd-run") is None or shutil.which("systemd-creds") is None:
        return "systemd-run/systemd-creds not available"
    probe = _sudo_n("true")
    if probe.returncode != 0:
        return "passwordless sudo is required to exercise a real system-scope unit"
    tpm = _sudo_n("systemd-creds", "has-tpm2", "-q")
    if tpm.returncode != 0:
        return "TPM2 support is not available on this host"
    return None


def _render_directives(layout: InstallLayout) -> list[str]:
    """Turn render_drop_in()'s [Service] section into systemd-run -p values."""
    directives = []
    for line in render_drop_in(layout).splitlines():
        if not line or line.startswith("#") or line == "[Service]":
            continue
        directives.append(line)
    return directives


@unittest.skipIf(
    (_skip_reason := _can_run_real_systemd_test()) is not None,
    _skip_reason or "",
)
class RealSystemdDropInTests(unittest.TestCase):
    """Starts an actual transient systemd unit using the exact directives
    render_drop_in() would install, against real (TPM2) systemd-creds."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.layout = InstallLayout.for_system(
            profile="regression-test",
            unit="hermes-vw-regression-test.service",
            root=root,
        )
        # encrypt_credential() shells out to the real systemd-creds binary
        # with --with-key=tpm2; these are synthetic, throwaway values. In
        # production the whole bootstrap script runs as root (setup --apply
        # enforces euid() == 0); mirror that here since only root can access
        # /dev/tpmrm0, by routing the encrypt subprocess through sudo -n.
        def _run_as_root(argv, **kwargs):
            return subprocess.run(["sudo", "-n", *argv], **kwargs)

        credential_dir = Path(self.tmp.name) / "creds"
        credential_dir.mkdir()
        self.credential_files: dict[str, Path] = {}
        for name in CREDENTIAL_NAMES:
            encrypted = encrypt_credential(
                name,
                f"synthetic-{name.lower()}-{uuid.uuid4()}",
                run=_run_as_root,
            )
            path = credential_dir / f"{name}.cred"
            path.write_bytes(encrypted)
            path.chmod(0o644)  # world-readable so systemd (running as root) can load it
            self.credential_files[name] = path

        # render_drop_in()'s ExecStartPre= now only names the on-disk env
        # script's path (VW-013); materialize that script for real so
        # systemd-run can actually execute it, world-readable/executable
        # like the credential files above.
        env_script_path = Path(self.tmp.name) / "write-env.sh"
        env_script_path.write_text(render_env_script(self.layout))
        env_script_path.chmod(0o755)

        # render_drop_in() encodes paths relative to layout.root; rewrite the
        # rendered LoadCredentialEncrypted= directive and the ExecStartPre=
        # script path to point at our real, throwaway files instead of
        # layout.root's (nonexistent) /etc/... paths.
        raw_directives = _render_directives(self.layout)
        self.directives = []
        for directive in raw_directives:
            if directive.startswith("LoadCredentialEncrypted="):
                name = directive.split("=", 1)[1].split(":", 1)[0]
                self.directives.append(
                    f"LoadCredentialEncrypted={name}:{self.credential_files[name]}"
                )
            elif directive.startswith("ExecStartPre="):
                interpreter, _, _old_path = directive.removeprefix("ExecStartPre=").partition(" ")
                self.directives.append(f"ExecStartPre={interpreter} {env_script_path}")
            else:
                self.directives.append(directive)

        self.unit_name = f"hermes-vw-bootstrap-regression-{uuid.uuid4().hex[:12]}"
        self.addCleanup(lambda: _sudo_n("systemctl", "reset-failed", f"{self.unit_name}.service"))

    def _run_transient_unit(self, *command: str) -> subprocess.CompletedProcess:
        argv = ["systemd-run", f"--unit={self.unit_name}", "--wait", "--pipe"]
        for directive in self.directives:
            argv += ["-p", directive]
        argv += list(command)
        return _sudo_n(*argv)

    def test_real_systemd_start_is_green_and_delivers_all_three_variables(self):
        probe_script = (
            "for n in BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD; do "
            'eval v=\\$$n; '
            'if [ -n "$v" ]; then echo present:$n; else echo missing:$n; fi; '
            "done"
        )
        result = self._run_transient_unit("/bin/sh", "-c", probe_script)

        self.assertEqual(
            0,
            result.returncode,
            msg=f"transient unit failed to start green: {result.stderr}",
        )
        for name in CREDENTIAL_NAMES:
            self.assertIn(
                f"present:{name}",
                result.stdout,
                msg=f"{name} did not reach the child process environment",
            )
        # Never assert on or print the actual synthetic secret values.
        self.assertNotIn("synthetic-", result.stdout)
        self.assertNotIn("synthetic-", result.stderr)


if __name__ == "__main__":
    unittest.main()
