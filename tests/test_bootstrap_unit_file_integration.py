"""Regression test for VW-013: a real unit file loaded via daemon-reload must
never let systemd's own Exec*= command-line substitution mangle a literal
"$name" before the shell ever sees it.

tests/test_bootstrap_systemd_integration.py (VW-012's regression test) proved
insufficient because it sets directives via `systemd-run -p <directive>`,
which does not go through the same command-line parsing path as a directive
loaded from an actual unit file on disk. This test instead:

  1. writes the *actual* rendered drop-in (render_drop_in()) and env script
     (render_env_script()) that setup --apply would install, verbatim, to a
     throwaway unit under /etc/systemd/system/<random>.service;
  2. runs `systemctl daemon-reload` so systemd parses the unit file exactly
     as it would in production;
  3. starts the unit with `systemctl start` (not systemd-run) and inspects
     the real child process environment.

Requires: root (passwordless sudo), systemd-creds with TPM2 support. Skips
(not fails) when the host cannot support it, so it stays CI-safe elsewhere
while still running the real deploy path on hosts such as a production host.
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


def _can_run_real_unit_file_test() -> str | None:
    """Return a skip reason, or None if the environment supports this test."""
    if shutil.which("systemctl") is None or shutil.which("systemd-creds") is None:
        return "systemctl/systemd-creds not available"
    probe = _sudo_n("true")
    if probe.returncode != 0:
        return "passwordless sudo is required to install a real system unit"
    tpm = _sudo_n("systemd-creds", "has-tpm2", "-q")
    if tpm.returncode != 0:
        return "TPM2 support is not available on this host"
    return None


@unittest.skipIf(
    (_skip_reason := _can_run_real_unit_file_test()) is not None,
    _skip_reason or "",
)
class RealUnitFileDropInTests(unittest.TestCase):
    """Installs the exact rendered drop-in + env script under a throwaway
    unit file loaded via daemon-reload -- the real deploy path, not
    systemd-run -p -- and asserts all three BW_* variables reach a real
    child process."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.unit_name = f"hermes-vw-bootstrap-regression-{uuid.uuid4().hex[:12]}"
        self.layout = InstallLayout.for_system(
            profile="regression-test",
            unit=f"{self.unit_name}.service",
            root=root,
        )

        def _run_as_root(argv, **kwargs):
            return subprocess.run(["sudo", "-n", *argv], **kwargs)

        # Encrypted credentials, the env script, and the runtime dir all
        # live under a throwaway system path (not layout.root, which is
        # only used to relativize the rendered directive strings) so the
        # real systemd manager can read them as root.
        state_dir = Path("/etc/hermes-vw-bootstrap-regression") / self.unit_name
        self.addCleanup(lambda: _sudo_n("rm", "-rf", str(state_dir)))
        _sudo_n("mkdir", "-p", str(state_dir))
        _sudo_n("chmod", "0755", str(state_dir))

        self.credential_files: dict[str, Path] = {}
        for name in CREDENTIAL_NAMES:
            encrypted = encrypt_credential(
                name,
                f"synthetic-{name.lower()}-{uuid.uuid4()}",
                run=_run_as_root,
            )
            path = state_dir / f"{name}.cred"
            _write_root_file(path, encrypted, mode="0644")
            self.credential_files[name] = path

        env_script_path = state_dir / "write-env.sh"
        _write_root_file(env_script_path, render_env_script(self.layout).encode(), mode="0755")

        # Rewrite the rendered directives to point LoadCredentialEncrypted=
        # and the ExecStartPre= script path at our real, throwaway files
        # instead of layout.root's (nonexistent) /etc paths -- everything
        # else (RuntimeDirectory=, EnvironmentFile=, the ExecStartPre=
        # shape itself) stays exactly what render_drop_in() produced.
        service_lines = ["[Unit]", f"Description=hermes-vaultwarden VW-013 regression {self.unit_name}"]
        for line in render_drop_in(self.layout).splitlines():
            if line.startswith("LoadCredentialEncrypted="):
                name = line.split("=", 1)[1].split(":", 1)[0]
                service_lines.append(f"LoadCredentialEncrypted={name}:{self.credential_files[name]}")
            elif line.startswith("ExecStartPre="):
                interpreter, _, _old_path = line.removeprefix("ExecStartPre=").partition(" ")
                service_lines.append(f"ExecStartPre={interpreter} {env_script_path}")
            elif line == "[Service]":
                service_lines.append(line)
            elif line.startswith("#"):
                continue
            else:
                service_lines.append(line)
        probe_script = (
            "for n in BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD; do "
            'eval v=\\$$n; '
            'if [ -n "$v" ]; then echo present:$n >> /tmp/hermes-vw-vw013-probe.out; '
            'else echo missing:$n >> /tmp/hermes-vw-vw013-probe.out; fi; '
            "done"
        )
        self.probe_output = Path("/tmp/hermes-vw-vw013-probe.out")
        self.addCleanup(lambda: _sudo_n("rm", "-f", str(self.probe_output)))
        service_lines.append("Type=oneshot")
        service_lines.append(f'ExecStart=/bin/sh -c "{probe_script}"')

        self.unit_path = Path(f"/etc/systemd/system/{self.unit_name}.service")
        _write_root_file(self.unit_path, ("\n".join(service_lines) + "\n").encode(), mode="0644")

        def _teardown_unit():
            _sudo_n("systemctl", "stop", f"{self.unit_name}.service")
            _sudo_n("rm", "-f", str(self.unit_path))
            _sudo_n("systemctl", "daemon-reload")
            _sudo_n("systemctl", "reset-failed", f"{self.unit_name}.service")

        self.addCleanup(_teardown_unit)

        result = _sudo_n("systemctl", "daemon-reload")
        self.assertEqual(0, result.returncode, msg=f"daemon-reload failed: {result.stderr}")

    def test_real_unit_file_start_delivers_all_three_variables(self):
        _sudo_n("rm", "-f", str(self.probe_output))
        result = _sudo_n("systemctl", "start", f"{self.unit_name}.service")
        self.assertEqual(
            0,
            result.returncode,
            msg=f"real unit file failed to start green: {result.stderr}",
        )

        probe = _sudo_n("cat", str(self.probe_output))
        self.assertEqual(0, probe.returncode, msg=f"could not read probe output: {probe.stderr}")
        for name in CREDENTIAL_NAMES:
            self.assertIn(
                f"present:{name}",
                probe.stdout,
                msg=(
                    f"{name} did not reach the child process environment "
                    f"via the real unit-file + daemon-reload deploy path "
                    f"(VW-013 regression); probe output: {probe.stdout!r}"
                ),
            )
        # Never assert on or print the actual synthetic secret values.
        self.assertNotIn("synthetic-", probe.stdout)


def _write_root_file(path: Path, content: bytes, *, mode: str) -> None:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(content)
        temp_path = handle.name
    try:
        subprocess.run(["sudo", "-n", "install", "-m", mode, temp_path, str(path)], check=True)
    finally:
        Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
