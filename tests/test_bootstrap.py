import unittest
import json
import io
import os
import stat
import tempfile
from pathlib import Path
from subprocess import CompletedProcess

from scripts.hermes_vaultwarden_bootstrap import (
    InstallLayout,
    check_prerequisites,
    encrypt_credential,
    install,
    is_installed,
    main,
    remove,
    render_drop_in,
)


class InstallLayoutTests(unittest.TestCase):
    def test_profile_and_unit_select_isolated_absolute_targets(self):
        layout = InstallLayout.for_system(
            profile="profile-a",
            unit="hermes-profile-a.service",
            root=Path("/staging"),
        )

        self.assertEqual(
            Path("/staging/etc/credstore.encrypted/hermes-vaultwarden/profile-a"),
            layout.credential_dir,
        )
        self.assertEqual(
            Path("/staging/etc/systemd/system/hermes-profile-a.service.d/50-hermes-vaultwarden.conf"),
            layout.drop_in,
        )
        self.assertEqual(
            Path("/staging/etc/hermes-vaultwarden/profile-a.json"),
            layout.manifest,
        )
        self.assertEqual(
            {
                "BW_CLIENTID": layout.credential_dir / "BW_CLIENTID.cred",
                "BW_CLIENTSECRET": layout.credential_dir / "BW_CLIENTSECRET.cred",
                "BW_PASSWORD": layout.credential_dir / "BW_PASSWORD.cred",
            },
            layout.credentials,
        )

    def test_rejects_traversal_and_non_service_unit_names(self):
        invalid_pairs = (
            ("../profile-a", "hermes.service"),
            ("profile/a", "hermes.service"),
            ("profile-a", "../hermes.service"),
            ("profile-a", "hermes.socket"),
        )

        for profile, unit in invalid_pairs:
            with self.subTest(profile=profile, unit=unit):
                with self.assertRaisesRegex(ValueError, "invalid"):
                    InstallLayout.for_system(profile=profile, unit=unit)

    def test_drop_in_loads_three_separate_environment_credentials(self):
        layout = InstallLayout.for_system(
            profile="profile-a",
            unit="hermes-profile-a.service",
            root=Path("/staging"),
        )

        rendered = render_drop_in(layout)

        for name in ("BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"):
            self.assertIn(
                f"LoadCredentialEncrypted={name}:/etc/credstore.encrypted/"
                f"hermes-vaultwarden/profile-a/{name}.cred",
                rendered,
            )
        # Regression guard for the %d-in-EnvironmentFile= bug (VW-012):
        # systemd never expands the "%d" credentials-directory specifier
        # inside EnvironmentFile=, so that pattern must never come back.
        self.assertNotIn("%d", rendered)
        self.assertIn("RuntimeDirectory=", rendered)
        self.assertIn("ExecStartPre=", rendered)
        self.assertIn("EnvironmentFile=-/run/", rendered)
        self.assertNotIn("BW_SESSION", rendered)
        self.assertNotIn("/staging", rendered)


class CredentialEncryptionTests(unittest.TestCase):
    def test_secret_is_only_sent_on_stdin_and_payload_is_environment_safe(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            return CompletedProcess(argv, 0, stdout=b"encrypted-bytes", stderr=b"")

        encrypted = encrypt_credential(
            "BW_PASSWORD",
            'synthetic value with "quotes" and \\slashes',
            run=fake_run,
        )

        self.assertEqual(b"encrypted-bytes", encrypted)
        argv, kwargs = calls[0]
        self.assertEqual(
            [
                "systemd-creds",
                "encrypt",
                "--with-key=tpm2",
                "--name=BW_PASSWORD",
                "-",
                "-",
            ],
            argv,
        )
        self.assertNotIn("synthetic value", " ".join(argv))
        self.assertEqual(
            b'BW_PASSWORD="synthetic value with \\"quotes\\" and \\\\slashes"\n',
            kwargs["input"],
        )
        self.assertEqual({"LANG": "C.UTF-8", "PATH": os.defpath}, kwargs["env"])
        self.assertNotIn("BW_SESSION", kwargs["env"])
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])


class InstallTests(unittest.TestCase):
    def test_install_is_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            encrypt_calls = []
            reload_calls = []

            def fake_encrypt(name, value):
                encrypt_calls.append((name, value))
                return f"encrypted-{name}".encode()

            secrets = {
                "BW_CLIENTID": "synthetic-client-id",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }

            self.assertTrue(
                install(layout, secrets, encrypt=fake_encrypt, reload_systemd=lambda: reload_calls.append(True))
            )
            self.assertFalse(
                install(layout, {}, encrypt=fake_encrypt, reload_systemd=lambda: reload_calls.append(True))
            )

            self.assertEqual(list(secrets.items()), encrypt_calls)
            self.assertEqual([True], reload_calls)
            self.assertEqual(render_drop_in(layout), layout.drop_in.read_text())
            manifest = json.loads(layout.manifest.read_text())
            self.assertEqual("profile-a", manifest["profile"])
            self.assertEqual("hermes-profile-a.service", manifest["unit"])
            self.assertNotIn("synthetic", layout.manifest.read_text())
            for path in layout.credentials.values():
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(layout.manifest.stat().st_mode))
            self.assertEqual(0o644, stat.S_IMODE(layout.drop_in.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(layout.credential_dir.stat().st_mode))

    def test_wrong_permissions_are_not_treated_as_an_idempotent_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            install(
                layout,
                {name: f"synthetic-{name}" for name in layout.credentials},
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )
            os.chmod(layout.credentials["BW_PASSWORD"], 0o644)

            self.assertFalse(is_installed(layout))
            with self.assertRaisesRegex(RuntimeError, "conflicting"):
                install(layout, {}, encrypt=lambda name, value: b"", reload_systemd=lambda: None)

    def test_existing_unsafe_credential_directory_fails_before_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            layout.credential_dir.mkdir(parents=True, mode=0o755)
            os.chmod(layout.credential_dir, 0o755)
            encrypt_calls = []

            with self.assertRaisesRegex(RuntimeError, "unsafe managed directory"):
                install(
                    layout,
                    {name: f"synthetic-{name}" for name in layout.credentials},
                    encrypt=lambda name, value: encrypt_calls.append(name) or b"encrypted",
                    reload_systemd=lambda: None,
                )

            self.assertEqual([], encrypt_calls)

    def test_daemon_reload_failure_rolls_back_every_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            reload_calls = []

            def fail_reload():
                reload_calls.append(True)
                raise RuntimeError("synthetic reload failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic reload failure"):
                install(
                    layout,
                    {name: f"synthetic-{name}" for name in layout.credentials},
                    encrypt=lambda name, value: f"encrypted-{name}".encode(),
                    reload_systemd=fail_reload,
                )

            self.assertEqual([True, True], reload_calls)
            for path in (*layout.credentials.values(), layout.drop_in, layout.manifest):
                self.assertFalse(path.exists())

    def test_remove_deletes_only_managed_profile_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=root,
            )
            sibling = root / "etc/credstore.encrypted/hermes-vaultwarden/profile-b/keep.cred"
            sibling.parent.mkdir(parents=True)
            sibling.write_bytes(b"encrypted-sibling")
            install(
                layout,
                {name: f"synthetic-{name}" for name in layout.credentials},
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )
            reload_calls = []

            self.assertTrue(remove(layout, reload_systemd=lambda: reload_calls.append(True)))
            self.assertFalse(remove(layout, reload_systemd=lambda: reload_calls.append(True)))

            self.assertEqual([True], reload_calls)
            self.assertEqual(b"encrypted-sibling", sibling.read_bytes())
            for path in (*layout.credentials.values(), layout.drop_in, layout.manifest):
                self.assertFalse(path.exists())

    def test_remove_restores_files_when_daemon_reload_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            install(
                layout,
                {name: f"synthetic-{name}" for name in layout.credentials},
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )
            before = {
                path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for path in (*layout.credentials.values(), layout.drop_in, layout.manifest)
            }
            reload_calls = []

            def fail_reload():
                reload_calls.append(True)
                if len(reload_calls) == 1:
                    raise RuntimeError("synthetic reload failure")

            with self.assertRaisesRegex(RuntimeError, "synthetic reload failure"):
                remove(layout, reload_systemd=fail_reload)

            self.assertEqual([True, True], reload_calls)
            for path, (content, mode) in before.items():
                self.assertEqual(content, path.read_bytes())
                self.assertEqual(mode, stat.S_IMODE(path.stat().st_mode))


class CommandLineTests(unittest.TestCase):
    def test_setup_without_apply_is_a_non_interactive_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            stderr = io.StringIO()

            result = main(
                [
                    "setup",
                    "--profile",
                    "profile-a",
                    "--unit",
                    "hermes-profile-a.service",
                    "--root",
                    tmp,
                ],
                stdout=stdout,
                stderr=stderr,
                prompt_secret=lambda prompt: self.fail("preview prompted for a secret"),
            )

            self.assertEqual(0, result)
            self.assertEqual("", stderr.getvalue())
            self.assertIn("PREVIEW", stdout.getvalue())
            self.assertIn("no files were changed", stdout.getvalue())
            self.assertIn("BW_CLIENTID.cred", stdout.getvalue())
            self.assertFalse((Path(tmp) / "etc").exists())

    def test_prerequisite_check_fails_closed_without_leaking_tool_output(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[:2] == ["systemd-creds", "has-tpm2"]:
                return CompletedProcess(argv, 1, stdout="partial\n", stderr="sensitive diagnostic")
            return CompletedProcess(argv, 0, stdout="not-found\n", stderr="")

        issues = check_prerequisites(
            "hermes-profile-a.service",
            which=lambda command: f"/usr/bin/{command}",
            run=fake_run,
        )

        self.assertEqual(
            ["TPM2 support is not fully available", "systemd unit is not loaded"],
            issues,
        )
        self.assertNotIn("sensitive diagnostic", " ".join(issues))
        self.assertEqual(
            [
                ["systemd-creds", "has-tpm2", "-q"],
                [
                    "systemctl",
                    "show",
                    "--property=LoadState",
                    "--value",
                    "hermes-profile-a.service",
                ],
            ],
            [argv for argv, kwargs in calls],
        )

    def test_setup_apply_prompts_twice_and_never_emits_secret_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            stderr = io.StringIO()
            answers = iter(
                [
                    "synthetic-client-id",
                    "synthetic-client-id",
                    "synthetic-client-secret",
                    "synthetic-client-secret",
                    "synthetic-master-credential",
                    "synthetic-master-credential",
                ]
            )
            prompts = []

            def prompt_secret(prompt):
                prompts.append(prompt)
                return next(answers)

            result = main(
                [
                    "setup",
                    "--profile",
                    "profile-a",
                    "--unit",
                    "hermes-profile-a.service",
                    "--root",
                    tmp,
                    "--apply",
                    "--yes",
                ],
                stdout=stdout,
                stderr=stderr,
                prompt_secret=prompt_secret,
                euid=lambda: 0,
                prerequisite_check=lambda unit: [],
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )

            self.assertEqual(0, result)
            self.assertEqual(6, len(prompts))
            combined = stdout.getvalue() + stderr.getvalue() + " ".join(prompts)
            for secret in (
                "synthetic-client-id",
                "synthetic-client-secret",
                "synthetic-master-credential",
            ):
                self.assertNotIn(secret, combined)
            self.assertIn("installed", stdout.getvalue())

    def test_status_reports_structure_without_reading_credential_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            install(
                layout,
                {name: f"synthetic-{name}" for name in layout.credentials},
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )
            stdout = io.StringIO()

            result = main(
                [
                    "status",
                    "--profile",
                    "profile-a",
                    "--unit",
                    "hermes-profile-a.service",
                    "--root",
                    tmp,
                ],
                stdout=stdout,
            )

            self.assertEqual(0, result)
            self.assertIn("installed", stdout.getvalue())
            self.assertIn("BW_CLIENTID.cred: present", stdout.getvalue())
            self.assertNotIn("encrypted-BW_CLIENTID", stdout.getvalue())

    def test_status_reports_inaccessible_paths_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocked = Path(tmp) / "etc/credstore.encrypted"
            blocked.mkdir(parents=True)
            os.chmod(blocked, 0)
            stdout = io.StringIO()
            try:
                result = main(
                    [
                        "status",
                        "--profile",
                        "profile-a",
                        "--unit",
                        "hermes-profile-a.service",
                        "--root",
                        tmp,
                    ],
                    stdout=stdout,
                )
            finally:
                os.chmod(blocked, 0o700)

            self.assertEqual(1, result)
            self.assertIn("inaccessible", stdout.getvalue())

    def test_prereq_command_returns_machine_usable_exit_status(self):
        stdout = io.StringIO()
        self.assertEqual(
            0,
            main(
                [
                    "prereq",
                    "--profile",
                    "profile-a",
                    "--unit",
                    "hermes-profile-a.service",
                ],
                stdout=stdout,
                prerequisite_check=lambda unit: [],
            ),
        )
        self.assertEqual("prerequisites: ok\n", stdout.getvalue())

        stderr = io.StringIO()
        self.assertEqual(
            1,
            main(
                [
                    "prereq",
                    "--profile",
                    "profile-a",
                    "--unit",
                    "hermes-profile-a.service",
                ],
                stderr=stderr,
                prerequisite_check=lambda unit: ["TPM2 unavailable"],
            ),
        )
        self.assertEqual("prerequisite failed: TPM2 unavailable\n", stderr.getvalue())

    def test_remove_requires_apply_and_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = InstallLayout.for_system(
                profile="profile-a",
                unit="hermes-profile-a.service",
                root=Path(tmp),
            )
            install(
                layout,
                {name: f"synthetic-{name}" for name in layout.credentials},
                encrypt=lambda name, value: f"encrypted-{name}".encode(),
                reload_systemd=lambda: None,
            )
            base_args = [
                "remove",
                "--profile",
                "profile-a",
                "--unit",
                "hermes-profile-a.service",
                "--root",
                tmp,
            ]
            preview = io.StringIO()

            self.assertEqual(0, main(base_args, stdout=preview))
            self.assertTrue(is_installed(layout))
            self.assertIn("PREVIEW", preview.getvalue())

            stderr = io.StringIO()
            self.assertEqual(
                1,
                main(
                    base_args + ["--apply", "--yes"],
                    stdout=io.StringIO(),
                    stderr=stderr,
                    euid=lambda: 1000,
                ),
            )
            self.assertTrue(is_installed(layout))
            self.assertIn("must run as root", stderr.getvalue())

            stdout = io.StringIO()
            self.assertEqual(
                0,
                main(
                    base_args + ["--apply", "--yes"],
                    stdout=stdout,
                    euid=lambda: 0,
                    reload_systemd=lambda: None,
                ),
            )
            self.assertFalse(is_installed(layout))
            self.assertIn("removed", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
