"""Regression test for VW-014: env_script must be readable by the *target*
unit's own User=, not just by root.

The VW-013 regression test (tests/test_bootstrap_unit_file_integration.py)
proved insufficient because it (a) wrote the env script into a separately,
more permissively chmod'd `state_dir` instead of the real, produktive
directory layout that install() creates (in particular the manifest's own
0700 root-only parent directory), and (b) ran its throwaway test unit with
no User= at all, so it executed implicitly as root -- root can always
traverse a 0700 directory it owns, so the test could not have caught a
permission problem even if one existed.

This test instead:

  1. actually calls install() against a throwaway --root, producing the
     real produktive layout on disk (env_script.parent created 0755,
     layout.manifest.parent created 0700, exactly like a live /etc
     cutover);
  2. copies only the files systemd itself needs to read as root (encrypted
     credentials, the env script) into real system paths, preserving the
     *same* 0700-manifest-directory-is-not-env_script's-parent shape;
  3. loads a throwaway real unit file via daemon-reload with an explicit,
     non-root User= (the "nobody" account, which exists on every Linux
     system without needing a dedicated fixture user); and
  4. starts it with `systemctl start` and asserts the service goes green
     and all three BW_* variables reach the real child process.

Requires: root (passwordless sudo), systemd-creds with TPM2 support, and a
"nobody" account. Skips (not fails) when the host cannot support it.
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
    install,
    render_env_script,
)


def _sudo_n(*argv: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo", "-n", *argv], capture_output=True, text=True, **kwargs)


def _can_run_real_non_root_user_test() -> str | None:
    """Return a skip reason, or None if the environment supports this test."""
    if shutil.which("systemctl") is None or shutil.which("systemd-creds") is None:
        return "systemctl/systemd-creds not available"
    probe = _sudo_n("true")
    if probe.returncode != 0:
        return "passwordless sudo is required to install a real system unit"
    tpm = _sudo_n("systemd-creds", "has-tpm2", "-q")
    if tpm.returncode != 0:
        return "TPM2 support is not available on this host"
    getent = _sudo_n("getent", "passwd", "nobody")
    if getent.returncode != 0:
        return "a 'nobody' account is required as the non-root test User="
    return None


def _write_root_file(path: Path, content: bytes, *, mode: str) -> None:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(content)
        temp_path = handle.name
    try:
        subprocess.run(["sudo", "-n", "install", "-m", mode, temp_path, str(path)], check=True)
    finally:
        Path(temp_path).unlink(missing_ok=True)


@unittest.skipIf(
    (_skip_reason := _can_run_real_non_root_user_test()) is not None,
    _skip_reason or "",
)
class RealNonRootExecStartPreTests(unittest.TestCase):
    """Runs ExecStartPre= as an explicit non-root User= against the exact
    directory layout install() produces (0700 manifest parent included),
    not a separately, more permissively chmod'd fixture directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        staging_root = Path(self.tmp.name)
        self.unit_name = f"hermes-vw-vw014-regression-{uuid.uuid4().hex[:12]}"
        self.layout = InstallLayout.for_system(
            profile="regression-test",
            unit=f"{self.unit_name}.service",
            root=staging_root,
        )

        def _run_as_root(argv, **kwargs):
            return subprocess.run(["sudo", "-n", *argv], **kwargs)

        secrets = {
            name: f"synthetic-{name.lower()}-{uuid.uuid4()}" for name in CREDENTIAL_NAMES
        }
        # install() itself creates the real layout on a throwaway --root:
        # env_script.parent as its own 0755 directory, and (crucially for
        # VW-014) layout.manifest.parent as a *separate* 0700 directory --
        # exactly the produktive shape, not a hand-picked lenient fixture.
        install(
            self.layout,
            secrets,
            encrypt=lambda name, value: encrypt_credential(name, value, run=_run_as_root),
            reload_systemd=lambda: None,
        )
        self.assertNotEqual(
            self.layout.manifest.parent,
            self.layout.env_script.parent,
            "test setup sanity check: install() must isolate env_script "
            "from the 0700 manifest directory (VW-014)",
        )

        # systemd (running as root) needs to read the encrypted credentials
        # from real system paths; copy them there preserving the installed
        # modes -- credentials 0600 (root reads fine via LoadCredential),
        # env_script 0755 under its own 0755 parent (never the manifest's
        # 0700 parent), matching install()'s real produktive layout.
        state_root = Path("/etc/hermes-vw-vw014-regression") / self.unit_name
        self.addCleanup(lambda: _sudo_n("rm", "-rf", str(state_root)))
        credential_dir = state_root / "creds"
        env_script_dir = state_root / "scripts"
        _sudo_n("mkdir", "-p", str(credential_dir))
        _sudo_n("chmod", "0700", str(credential_dir))
        _sudo_n("mkdir", "-p", str(env_script_dir))
        _sudo_n("chmod", "0755", str(env_script_dir))

        self.credential_files: dict[str, Path] = {}
        for name in CREDENTIAL_NAMES:
            source = self.layout.credentials[name]
            dest = credential_dir / f"{name}.cred"
            _write_root_file(dest, source.read_bytes(), mode="0600")
            self.credential_files[name] = dest

        env_script_path = env_script_dir / "write-env.sh"
        _write_root_file(
            env_script_path, render_env_script(self.layout).encode(), mode="0755"
        )

        runtime_directory = f"hermes-vw014-{self.unit_name}"
        service_lines = [
            "[Unit]",
            f"Description=hermes-vaultwarden VW-014 regression {self.unit_name}",
            "[Service]",
            # This is the crux of VW-014: ExecStartPre= has no User= of its
            # own, so it inherits this unit's own explicit, non-root User=
            # -- exactly like the real the target gateway service
            # (User=svc-hermes) that crash-looped in production.
            "User=nobody",
        ]
        for name in CREDENTIAL_NAMES:
            service_lines.append(
                f"LoadCredentialEncrypted={name}:{self.credential_files[name]}"
            )
        service_lines.append(f"RuntimeDirectory={runtime_directory}")
        service_lines.append("RuntimeDirectoryMode=0700")
        service_lines.append(f"ExecStartPre=/bin/sh {env_script_path}")
        service_lines.append(f"EnvironmentFile=-/run/{runtime_directory}/env")

        probe_script = (
            "for n in BW_CLIENTID BW_CLIENTSECRET BW_PASSWORD; do "
            'eval v=\\$$n; '
            'if [ -n "$v" ]; then echo present:$n >> /tmp/hermes-vw-vw014-probe.out; '
            'else echo missing:$n >> /tmp/hermes-vw-vw014-probe.out; fi; '
            "done"
        )
        self.probe_output = Path("/tmp/hermes-vw-vw014-probe.out")
        self.addCleanup(lambda: _sudo_n("rm", "-f", str(self.probe_output)))
        service_lines.append("Type=oneshot")
        service_lines.append(f'ExecStart=/bin/sh -c "{probe_script}"')

        self.unit_path = Path(f"/etc/systemd/system/{self.unit_name}.service")
        _write_root_file(
            self.unit_path, ("\n".join(service_lines) + "\n").encode(), mode="0644"
        )

        def _teardown_unit():
            _sudo_n("systemctl", "stop", f"{self.unit_name}.service")
            _sudo_n("rm", "-f", str(self.unit_path))
            _sudo_n("systemctl", "daemon-reload")
            _sudo_n("systemctl", "reset-failed", f"{self.unit_name}.service")

        self.addCleanup(_teardown_unit)

        result = _sudo_n("systemctl", "daemon-reload")
        self.assertEqual(0, result.returncode, msg=f"daemon-reload failed: {result.stderr}")

    def test_execstartpre_under_non_root_user_reads_env_script_and_delivers_variables(self):
        _sudo_n("rm", "-f", str(self.probe_output))
        result = _sudo_n("systemctl", "start", f"{self.unit_name}.service")
        self.assertEqual(
            0,
            result.returncode,
            msg=(
                "real unit failed to start green under a non-root User= "
                f"(VW-014 regression): {result.stderr}"
            ),
        )

        probe = _sudo_n("cat", str(self.probe_output))
        self.assertEqual(0, probe.returncode, msg=f"could not read probe output: {probe.stderr}")
        for name in CREDENTIAL_NAMES:
            self.assertIn(
                f"present:{name}",
                probe.stdout,
                msg=(
                    f"{name} did not reach the child process environment "
                    f"when ExecStartPre= ran as a non-root User= against "
                    f"the produktive directory layout (VW-014 regression); "
                    f"probe output: {probe.stdout!r}"
                ),
            )
        # Never assert on or print the actual synthetic secret values.
        self.assertNotIn("synthetic-", probe.stdout)


if __name__ == "__main__":
    unittest.main()
