from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import argparse
import contextlib
import io
import subprocess
import sys
import time
import types
import unittest
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "__init__.py"
MANIFEST_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "plugin.yaml"


def _pin_binary(cfg: dict, binary: Path) -> None:
    cfg["binary_path"] = str(binary)
    cfg["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    first_line = binary.read_text(encoding="utf-8").splitlines()[0]
    if first_line.startswith("#!"):
        interpreter = Path(first_line[2:])
        cfg["binary_interpreter_sha256"] = hashlib.sha256(interpreter.read_bytes()).hexdigest()


class ErrorKind(str, Enum):
    NOT_CONFIGURED = "not_configured"
    BINARY_MISSING = "binary_missing"
    AUTH_FAILED = "auth_failed"
    AUTH_EXPIRED = "auth_expired"
    REF_INVALID = "ref_invalid"
    NETWORK = "network"
    EMPTY_VALUE = "empty_value"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


@dataclass
class FetchResult:
    secrets: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: ErrorKind | None = None
    binary_path: Path | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def fail(self, error: str, kind: ErrorKind):
        self.error = error
        self.error_kind = kind
        return self


class SecretSource:
    override_existing_default = False

    def token_env(self, cfg: dict) -> str:
        return str(cfg.get(self.token_env_key) or self.default_token_env)

    def is_enabled(self, cfg: dict) -> bool:
        return bool(isinstance(cfg, dict) and cfg.get("enabled"))

    def override_existing(self, cfg: dict) -> bool:
        return bool(
            isinstance(cfg, dict)
            and cfg.get("override_existing", self.override_existing_default)
        )


def _install_contract_stub() -> None:
    base = types.ModuleType("agent.secret_sources.base")
    base.ErrorKind = ErrorKind
    base.FetchResult = FetchResult
    base.SecretSource = SecretSource
    base.get_source_environment = lambda: os.environ
    base.is_valid_env_name = lambda value: bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value or ""))
    base.scrub_ansi = lambda value: value
    def run_cli(argv, *, env, timeout, label, timeout_message, stdin=subprocess.DEVNULL):
        try:
            return subprocess.run(
                list(argv),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                stdin=stdin,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(timeout_message) from exc
        except OSError as exc:
            raise RuntimeError(f"failed to invoke {label}: {exc}") from exc

    base.run_cli = run_cli

    agent = types.ModuleType("agent")
    secret_sources = types.ModuleType("agent.secret_sources")
    sys.modules["agent"] = agent
    sys.modules["agent.secret_sources"] = secret_sources
    sys.modules["agent.secret_sources.base"] = base


def _load_plugin():
    _install_contract_stub()
    spec = importlib.util.spec_from_file_location("vaultwarden_secret_source", PLUGIN_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("plugin module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RegistrationTests(unittest.TestCase):
    def test_manifest_v2_declares_native_plugin_settings_schema(self):
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")

        self.assertIn("name: hermes-vaultwarden", manifest)
        self.assertIn("config_schema:", manifest)
        for key, type_name in {
            "enabled": "bool",
            "server_url": "str",
            "collection_id": "str",
            "allowed_item_ids": "list",
            "env": "dict",
            "binary_path": "str",
            "binary_sha256": "str",
        }.items():
            self.assertRegex(
                manifest,
                rf"(?m)^  {re.escape(key)}:.*type: {type_name}",
            )

    def test_register_uses_plugin_context_settings_and_registers_native_cli(self):
        module = _load_plugin()
        item_id = "00000000-0000-4000-8000-000000000002"
        settings = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }
        sources = []
        commands = []
        ctx = types.SimpleNamespace(
            get_config=lambda key, default=None: settings.get(key, default),
            register_secret_source=sources.append,
            register_cli_command=lambda **kwargs: commands.append(kwargs),
        )

        module.register(ctx)

        self.assertEqual(1, len(sources))
        self.assertFalse(sources[0].is_enabled({}))
        self.assertFalse(sources[0].is_enabled({"enabled": False}))
        self.assertTrue(sources[0].is_enabled({"enabled": True}))
        self.assertEqual("vaultwarden", sources[0].name)
        self.assertEqual(["vaultwarden"], [command["name"] for command in commands])
        parser = argparse.ArgumentParser()
        commands[0]["setup_fn"](parser)
        for action in ("lookup", "status", "doctor", "config"):
            with self.subTest(action=action):
                parsed = parser.parse_args([action, "synthetic"] if action == "lookup" else [action])
                self.assertEqual(action, parsed.vaultwarden_action)

    def test_status_prints_only_safe_configuration_metadata(self):
        module = _load_plugin()
        item_id = "00000000-0000-4000-8000-000000000002"
        settings = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "client_secret_env": "BW_CLIENTSECRET",
        }
        args = argparse.Namespace(vaultwarden_action="status")

        with mock.patch.dict(os.environ, {"BW_CLIENTSECRET": "must-not-leak"}, clear=True):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = module.vaultwarden_command(args, settings)

        payload = __import__("json").loads(stdout.getvalue())
        self.assertEqual(0, result)
        self.assertEqual(item_id, payload["bindings"]["SYNTHETIC_API_KEY"]["item_id"])
        self.assertTrue(payload["bootstrap_environment"]["BW_CLIENTSECRET"])
        self.assertNotIn("must-not-leak", stdout.getvalue())

    def test_status_drops_untrusted_binding_values_and_non_uuid_references(self):
        module = _load_plugin()
        settings = {
            "collection_id": "not-a-uuid-must-not-leak-collection",
            "allowed_item_ids": ["not-a-uuid-must-not-leak-item"],
            "binary_path": "/must-not-leak/private/bw",
            "env": {
                "VALID_NAME": {
                    "item_id": "not-a-uuid-must-not-leak",
                    "field": "login.password",
                    "value": "must-not-leak-secret",
                },
                "INVALID-NAME": "must-not-leak-scalar",
            },
        }
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            result = module.vaultwarden_command(
                argparse.Namespace(vaultwarden_action="status"),
                settings,
            )

        payload = __import__("json").loads(stdout.getvalue())
        self.assertEqual(0, result)
        self.assertEqual({}, payload["bindings"])
        self.assertIsNone(payload["collection_id"])
        self.assertEqual([], payload["allowed_item_ids"])
        self.assertTrue(payload["binary_path_configured"])
        self.assertNotIn("must-not-leak", stdout.getvalue())

    def test_config_help_uses_only_plugin_settings_namespace(self):
        module = _load_plugin()
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            result = module.vaultwarden_command(
                argparse.Namespace(vaultwarden_action="config"),
                {},
            )

        output = stdout.getvalue()
        self.assertEqual(0, result)
        self.assertIn("hermes config set plugins.entries.hermes-vaultwarden.settings.enabled true", output)
        self.assertIn("plugins.entries.hermes-vaultwarden.settings.env", output)
        self.assertIn("hermes config set secrets.vaultwarden.enabled true", output)
        self.assertNotIn("secrets.vaultwarden.env", output)

    def test_doctor_checks_pinned_binary_and_bootstrap_without_remote_access(self):
        module = _load_plugin()
        item_id = "00000000-0000-4000-8000-000000000002"
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "bw"
            binary.write_text("#!/usr/bin/python3\nprint('2026.8.0')\n", encoding="utf-8")
            binary.chmod(0o700)
            settings = {
                "enabled": True,
                "server_url": "https://vault.example.invalid",
                "collection_id": "00000000-0000-4000-8000-000000000001",
                "allowed_item_ids": [item_id],
                "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            }
            _pin_binary(settings, binary)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "must-not-leak",
                "BW_PASSWORD": "synthetic-master",
            }
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stdout(stdout):
                    result = module.vaultwarden_command(
                        argparse.Namespace(vaultwarden_action="doctor"),
                        settings,
                    )

        payload = __import__("json").loads(stdout.getvalue())
        self.assertEqual(0, result)
        self.assertTrue(payload["ok"])
        self.assertEqual("2026.8.0", payload["bw_version"])
        self.assertNotIn("must-not-leak", stdout.getvalue())

    def test_doctor_reports_invalid_settings_without_raising(self):
        module = _load_plugin()
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            result = module.vaultwarden_command(
                argparse.Namespace(vaultwarden_action="doctor"),
                {"enabled": True},
            )

        payload = __import__("json").loads(stdout.getvalue())
        self.assertEqual(1, result)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["issues"])

    def test_lookup_returns_only_sanitized_metadata_and_uuids(self):
        module = _load_plugin()
        item_id = "00000000-0000-4000-8000-000000000002"
        collection_id = "00000000-0000-4000-8000-000000000001"
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "bw"
            binary.write_text(
                "#!/usr/bin/python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "if args[0] == '--version': print('2026.8.0')\n"
                "elif args[:2] == ['unlock', '--passwordenv']: print('must-not-leak-session')\n"
                "elif args[:2] == ['list', 'collections']:\n"
                f"    print(json.dumps([{{'id': '{collection_id}', 'name': 'Synthetic Collection'}}]))\n"
                "elif args[:2] == ['list', 'items']:\n"
                f"    print(json.dumps([{{'id': '{item_id}', 'name': 'Synthetic Item', "
                f"'type': 1, 'collectionIds': ['{collection_id}'], "
                "'login': {'username': 'must-not-leak-user', 'password': 'must-not-leak-password'}, "
                "'notes': 'must-not-leak-notes', "
                "'fields': [{'name': 'api-token', 'value': 'must-not-leak-field'}]}]))\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            settings = {
                "server_url": "https://vault.example.invalid",
                "binary_path": str(binary),
            }
            _pin_binary(settings, binary)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "must-not-leak-bootstrap",
                "BW_PASSWORD": "synthetic-master",
            }
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stdout(stdout):
                    result = module.vaultwarden_command(
                        argparse.Namespace(
                            vaultwarden_action="lookup",
                            query="Synthetic",
                            collection="Synthetic Collection",
                        ),
                        settings,
                    )

        payload = __import__("json").loads(stdout.getvalue())
        self.assertEqual(0, result)
        self.assertEqual(item_id, payload["items"][0]["id"])
        self.assertEqual([collection_id], payload["items"][0]["collection_ids"])
        self.assertEqual(
            ["fields.api-token", "login.password", "login.username", "notes"],
            payload["items"][0]["available_fields"],
        )
        for secret in (
            "must-not-leak-session",
            "must-not-leak-user",
            "must-not-leak-password",
            "must-not-leak-notes",
            "must-not-leak-field",
            "must-not-leak-bootstrap",
        ):
            self.assertNotIn(secret, stdout.getvalue())

    def test_directory_plugin_manifest_declares_compatible_api_and_pinned_cli(self):
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")

        self.assertIn("manifest_version: 2", manifest)
        self.assertIn("api_version: 1", manifest)
        self.assertIn('version: "0.2.0"', manifest)
        self.assertIn("platforms: [linux]", manifest)
        self.assertIn("bw-cli-version: 2026.8.0", manifest)

    def test_registers_mapped_source_with_schema_and_protected_bootstrap_vars(self):
        module = _load_plugin()
        registered = []
        module.register(types.SimpleNamespace(
            get_config=lambda _key, default=None: default,
            register_secret_source=registered.append,
            register_cli_command=lambda **_kwargs: None,
        ))

        self.assertEqual(1, len(registered))
        source = registered[0]
        self.assertEqual("vaultwarden", source.name)
        self.assertEqual("Vaultwarden", source.label)
        self.assertEqual("mapped", source.shape)
        self.assertEqual(
            {
                "enabled",
                "server_url",
                "collection_id",
                "allowed_item_ids",
                "env",
                "client_id_env",
                "client_secret_env",
                "master_password_env",
                "binary_path",
                "binary_sha256",
                "binary_interpreter_sha256",
                "cli_timeout_seconds",
                "timeout_seconds",
                "override_existing",
            },
            set(source.config_schema()),
        )
        self.assertEqual(
            frozenset({"BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"}),
            source.protected_env_vars({}),
        )

    def test_custom_bootstrap_names_protect_defaults_and_valid_overrides(self):
        module = _load_plugin()
        source = module.VaultwardenSource()

        protected = source.protected_env_vars(
            {
                "client_id_env": "VW_CLIENT_ID",
                "client_secret_env": "VW_CLIENT_SECRET",
                "master_password_env": "VW_MASTER_PASSWORD",
            }
        )

        self.assertEqual(
            frozenset(
                {
                    "BW_CLIENTID",
                    "BW_CLIENTSECRET",
                    "BW_PASSWORD",
                    "VW_CLIENT_ID",
                    "VW_CLIENT_SECRET",
                    "VW_MASTER_PASSWORD",
                }
            ),
            protected,
        )


class ValidationTests(unittest.TestCase):
    def test_boolean_switches_reject_truthy_string_values(self):
        module = _load_plugin()
        source = module.VaultwardenSource()

        self.assertFalse(source.is_enabled({"enabled": "false"}))
        self.assertTrue(source.is_enabled({"enabled": True}))
        self.assertFalse(source.override_existing({"override_existing": "false"}))
        self.assertTrue(source.override_existing({}))

    def test_non_finite_or_non_positive_cli_timeout_uses_safe_default(self):
        module = _load_plugin()

        for value in (float("inf"), float("-inf"), float("nan"), 0, -1):
            with self.subTest(value=value):
                self.assertEqual(30.0, module._positive_timeout(value))

    def test_malformed_config_never_raises(self):
        module = _load_plugin()
        source = module.VaultwardenSource()

        for cfg in ({}, {"enabled": True}, {"server_url": "https://["}, {"env": "not-a-map"}, None):
            with self.subTest(cfg=cfg):
                result = source.fetch(cfg, Path("/tmp"))
                self.assertIsInstance(result, FetchResult)
                self.assertIsNotNone(result.error_kind)

    def test_rejects_item_outside_explicit_allowlist_before_running_cli(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": ["00000000-0000-4000-8000-000000000002"],
            "env": {
                "SYNTHETIC_API_KEY": {
                    "item_id": "00000000-0000-4000-8000-000000000003",
                    "field": "login.password",
                }
            },
        }

        with mock.patch.object(module, "_run_bw", side_effect=AssertionError("CLI ran"), create=True):
            result = source.fetch(cfg, Path("/tmp/hermes-test"))

        self.assertEqual(ErrorKind.REF_INVALID, result.error_kind)
        self.assertEqual({}, result.secrets)

    def test_rejects_server_url_with_credentials_query_or_fragment(self):
        module = _load_plugin()
        source = module.VaultwardenSource()

        for server_url in (
            "https://user@vault.example.invalid",
            "https://vault.example.invalid?target=elsewhere",
            "https://vault.example.invalid#fragment",
        ):
            with self.subTest(server_url=server_url):
                result = source.fetch({"enabled": True, "server_url": server_url}, Path("/tmp"))
                self.assertEqual(ErrorKind.REF_INVALID, result.error_kind)

    def test_rejects_unsupported_field_selector_before_running_cli(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "card.number"}},
        }

        with mock.patch.object(module, "_run_bw", side_effect=AssertionError("CLI ran")):
            result = source.fetch(cfg, Path("/tmp"))

        self.assertEqual(ErrorKind.REF_INVALID, result.error_kind)


class FetchTests(unittest.TestCase):
    def test_staging_closes_reader_fd_when_identity_check_fails(self):
        module = _load_plugin()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.write_bytes(b"#!/bin/true\n")
            source.chmod(0o500)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            real_fstat = module.os.fstat
            calls = 0

            def fail_reader_fstat(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("synthetic reader fstat failure")
                return real_fstat(fd)

            open_fds_before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(module.os, "fstat", side_effect=fail_reader_fstat):
                with self.assertRaises(module._BwFailure):
                    module._open_verified_fd(
                        source,
                        root / "staged",
                        digest,
                        "test executable",
                        time.monotonic() + 10,
                    )
            self.assertEqual(open_fds_before, len(os.listdir("/proc/self/fd")))

    def test_pinned_script_closes_interpreter_fd_when_format_read_fails(self):
        module = _load_plugin()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            interpreter = Path(sys.executable).resolve()
            script = root / "bw"
            script.write_text(f"#!{interpreter}\n", encoding="utf-8")
            script.chmod(0o500)
            cfg = {
                "binary_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                "binary_interpreter_sha256": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
            }
            real_pread = module.os.pread

            def fail_interpreter_pread(fd, size, offset):
                if size == 4:
                    raise OSError("synthetic interpreter pread failure")
                return real_pread(fd, size, offset)

            open_fds_before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(module.os, "pread", side_effect=fail_interpreter_pread):
                with self.assertRaises(OSError):
                    module._open_pinned_executable(
                        script,
                        cfg,
                        time.monotonic() + 10,
                    )
            self.assertEqual(open_fds_before, len(os.listdir("/proc/self/fd")))

    def test_pinned_executable_retries_transient_stage_cleanup_failure(self):
        module = _load_plugin()
        binary = Path(sys.executable).resolve()
        executable = module._open_pinned_executable(
            binary,
            {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            time.monotonic() + 10,
        )
        staged_root = executable.binary_path.parent
        real_cleanup = executable.stage_dir.cleanup
        calls = 0

        def flaky_cleanup():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic transient cleanup failure")
            real_cleanup()

        with mock.patch.object(executable.stage_dir, "cleanup", side_effect=flaky_cleanup):
            executable.close()

        self.assertEqual(2, calls)
        self.assertFalse(staged_root.exists())

    def test_pinned_executable_reports_persistent_stage_cleanup_failure(self):
        module = _load_plugin()
        binary = Path(sys.executable).resolve()
        executable = module._open_pinned_executable(
            binary,
            {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
            time.monotonic() + 10,
        )
        real_cleanup = executable.stage_dir.cleanup

        try:
            with mock.patch.object(
                executable.stage_dir,
                "cleanup",
                side_effect=OSError("synthetic persistent cleanup failure"),
            ):
                self.assertIs(executable.close(), False)
        finally:
            real_cleanup()

    def test_pinned_native_executable_can_reopen_its_proc_exe_target(self):
        module = _load_plugin()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_file = root / "self_reopening_bw.c"
            binary = root / "bw"
            source_file.write_text(
                "#include <fcntl.h>\n"
                "#include <limits.h>\n"
                "#include <stdio.h>\n"
                "#include <sys/stat.h>\n"
                "#include <unistd.h>\n"
                "int main(void) {\n"
                "    char target[PATH_MAX];\n"
                "    ssize_t size = readlink(\"/proc/self/exe\", target, sizeof(target) - 1);\n"
                "    if (size < 0) return 41;\n"
                "    target[size] = '\\0';\n"
                "    int fd = open(target, O_RDONLY | O_CLOEXEC);\n"
                "    if (fd < 0) return 42;\n"
                "    struct stat reopened;\n"
                "    struct stat running;\n"
                "    if (fstat(fd, &reopened) < 0) return 43;\n"
                "    if (stat(\"/proc/self/exe\", &running) < 0) return 44;\n"
                "    if (reopened.st_dev != running.st_dev || reopened.st_ino != running.st_ino) return 45;\n"
                "    close(fd);\n"
                "    puts(\"2026.8.0\");\n"
                "    return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-O2", "-o", str(binary), str(source_file)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            cfg = {
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            executable = module._open_pinned_executable(
                binary,
                cfg,
                time.monotonic() + 10,
            )
            staged_root = executable.binary_path.parent

            try:
                proc = module._run_pinned_bw(
                    executable,
                    ["--version"],
                    env={"NO_COLOR": "1"},
                    cli_timeout=5,
                    deadline=time.monotonic() + 10,
                )
                self.assertEqual("2026.8.0", proc.stdout.strip())
            finally:
                executable.close()

            self.assertFalse(staged_root.exists())

    def test_output_read_failure_kills_credential_bearing_process_group(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "read-failure-descendant-survived"
            fake_bw = root / "bw"
            descendant = f"import time; time.sleep(0.3); open({str(sentinel)!r}, 'w').close()"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import subprocess, sys, time\n"
                f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                "print('ready', flush=True)\n"
                "time.sleep(2)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }

            real_selector = module.selectors.DefaultSelector()

            class FailingSelector:
                def register(self, *args, **kwargs):
                    return real_selector.register(*args, **kwargs)

                def get_map(self):
                    return real_selector.get_map()

                def select(self, _timeout):
                    time.sleep(0.05)
                    raise OSError("synthetic selector failure")

                def close(self):
                    real_selector.close()

            with mock.patch.object(module.selectors, "DefaultSelector", return_value=FailingSelector()):
                with mock.patch.dict(os.environ, env, clear=True):
                    result = source.fetch(cfg, root)
            time.sleep(0.5)

            self.assertEqual(ErrorKind.INTERNAL, result.error_kind)
            self.assertFalse(sentinel.exists())

    def test_nonzero_cli_exit_kills_descendants_even_when_they_close_output_pipes(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "descendant-survived"
            fake_bw = root / "bw"
            descendant = f"import time; time.sleep(0.3); open({str(sentinel)!r}, 'w').close()"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import subprocess, sys\n"
                "if '--version' in sys.argv:\n"
                "    print('2026.8.0')\n"
                "    raise SystemExit(0)\n"
                f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                "raise SystemExit(7)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, root)
            time.sleep(0.5)

            self.assertEqual(ErrorKind.INTERNAL, result.error_kind)
            self.assertFalse(sentinel.exists())

    def test_timeout_kills_descendants_that_keep_output_pipes_open(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "cli_timeout_seconds": 0.05,
        }

        with TemporaryDirectory() as tmp:
            fake_bw = Path(tmp) / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import subprocess, sys\n"
                "if '--version' in sys.argv:\n"
                "    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'])\n"
                "    print('2026.8.0')\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            started = time.monotonic()
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, Path(tmp))
            elapsed = time.monotonic() - started

        self.assertEqual(ErrorKind.TIMEOUT, result.error_kind)
        self.assertLess(elapsed, 1.0)

    def test_rejects_excessive_cli_output_without_buffering_it(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }

        with TemporaryDirectory() as tmp:
            fake_bw = Path(tmp) / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\nprint('x' * 4096)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.object(module, "_MAX_OUTPUT_BYTES", 1024):
                with mock.patch.dict(os.environ, env, clear=True):
                    result = source.fetch(cfg, Path(tmp))

        self.assertEqual(ErrorKind.INTERNAL, result.error_kind)
        self.assertIn("output limit", result.error)
        self.assertNotIn("x" * 1024, result.error)

    def test_rejects_unpinned_cli_version_before_exposing_bootstrap_credentials(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }

        with TemporaryDirectory() as tmp:
            fake_bw = Path(tmp) / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import os, sys\n"
                "if any(name in os.environ for name in ('BW_CLIENTID', 'BW_CLIENTSECRET', 'BW_PASSWORD')):\n"
                "    raise SystemExit(92)\n"
                "if '--version' in sys.argv:\n"
                "    print('2025.1.0')\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(93)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, Path(tmp))

        self.assertEqual(ErrorKind.BINARY_MISSING, result.error_kind)
        self.assertIn("2026.8.0", result.error)

    def test_fetches_allowlisted_field_with_transient_session_and_minimal_environment(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        collection_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": collection_id.upper(),
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bw = root / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "if 'LEAK_ME' in os.environ:\n"
                "    raise SystemExit(90)\n"
                "if args[0] == '--version':\n"
                "    assert 'BW_CLIENTID' not in os.environ\n"
                "    assert 'BW_CLIENTSECRET' not in os.environ\n"
                "    assert 'BW_PASSWORD' not in os.environ\n"
                "    assert os.path.isdir(os.environ['BITWARDENCLI_APPDATA_DIR'])\n"
                "    print('2026.8.0')\n"
                "    raise SystemExit(0)\n"
                "if args[:2] == ['config', 'server']:\n"
                "    raise SystemExit(0)\n"
                "if args[:2] == ['login', '--apikey']:\n"
                "    assert os.environ.get('BW_CLIENTID') == 'synthetic-client'\n"
                "    assert os.environ.get('BW_CLIENTSECRET') == 'synthetic-client-secret'\n"
                "    raise SystemExit(0)\n"
                "if args[:2] == ['unlock', '--passwordenv']:\n"
                "    assert args[2] == 'BW_PASSWORD'\n"
                "    print('synthetic-session')\n"
                "    raise SystemExit(0)\n"
                "if args[0] == 'sync':\n"
                "    assert os.environ.get('BW_SESSION') == 'synthetic-session'\n"
                "    raise SystemExit(0)\n"
                "if args[:2] == ['get', 'item']:\n"
                "    assert os.environ.get('BW_SESSION') == 'synthetic-session'\n"
                "    print(json.dumps({'id': args[2], 'collectionIds': [\n"
                f"        '{collection_id}'\n"
                "    ], 'login': {'password': 'synthetic-fetched-value'}}))\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(91)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "PATH": os.environ.get("PATH", ""),
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
                "LEAK_ME": "must-not-reach-child",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, root)

        self.assertTrue(result.ok, result.error)
        self.assertEqual({"SYNTHETIC_API_KEY": "synthetic-fetched-value"}, result.secrets)
        self.assertFalse(any(root.glob("**/*")), "temporary CLI state survived fetch")

    def test_classifies_cli_failures_without_exposing_cli_output(self):
        module = _load_plugin()
        cases = {
            "operation timed out": ErrorKind.TIMEOUT,
            "session key is invalid": ErrorKind.AUTH_EXPIRED,
            "invalid master password": ErrorKind.AUTH_FAILED,
            "OAuth error: invalid_client": ErrorKind.AUTH_FAILED,
            "request failed: 401 unauthorized": ErrorKind.AUTH_FAILED,
            "Object Not found.": ErrorKind.REF_INVALID,
            "getaddrinfo ENOTFOUND": ErrorKind.NETWORK,
            "connection refused": ErrorKind.NETWORK,
            "unexpected response": ErrorKind.INTERNAL,
        }

        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(expected, module._classify_bw_error(message))

        failure = module._bw_failure(7, "invalid master password synthetic-secret")
        self.assertEqual(ErrorKind.AUTH_FAILED, failure.kind)
        self.assertNotIn("synthetic-secret", str(failure))

    def test_cli_timeout_returns_timeout_error_without_raising(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "cli_timeout_seconds": 0.01,
        }

        with TemporaryDirectory() as tmp:
            fake_bw = Path(tmp) / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\nimport time\ntime.sleep(1)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, Path(tmp))

        self.assertEqual(ErrorKind.TIMEOUT, result.error_kind)
        self.assertEqual({}, result.secrets)

    def test_rejects_binary_digest_mismatch_before_exposing_bootstrap_credentials(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "binary_sha256": "0" * 64,
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "bootstrap-exposed"
            fake_bw = root / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import os, pathlib, sys\n"
                f"sentinel = pathlib.Path({str(sentinel)!r})\n"
                "if any(name in os.environ for name in ('BW_CLIENTID', 'BW_CLIENTSECRET', 'BW_PASSWORD')):\n"
                "    sentinel.touch()\n"
                "if '--version' in sys.argv:\n"
                "    print('2026.8.0')\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            cfg["binary_path"] = str(fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, root)

            self.assertEqual(ErrorKind.BINARY_MISSING, result.error_kind)
            self.assertFalse(sentinel.exists())

    def test_fetch_enforces_internal_budget_before_hermes_wall_clock_timeout(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        collection_id = "00000000-0000-4000-8000-000000000001"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": collection_id,
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "cli_timeout_seconds": 1,
            "timeout_seconds": 3,
        }

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bw = root / "bw"
            fake_bw.write_text(
                "#!/usr/bin/python3\n"
                "import json, sys, time\n"
                "time.sleep(0.12)\n"
                "args = sys.argv[1:]\n"
                "if args[0] == '--version': print('2026.8.0')\n"
                "elif args[:2] == ['unlock', '--passwordenv']: print('synthetic-session')\n"
                f"elif args[:2] == ['get', 'item']: print(json.dumps({{'id': args[2], 'collectionIds': ['{collection_id}'], 'login': {{'password': 'synthetic'}}}}))\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            fake_bw.chmod(0o700)
            _pin_binary(cfg, fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            started = time.monotonic()
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, root)
            elapsed = time.monotonic() - started

        self.assertEqual(ErrorKind.TIMEOUT, result.error_kind)
        self.assertLess(elapsed, cfg["timeout_seconds"])

    def test_rejects_oversized_executable_without_reading_it(self):
        module = _load_plugin()
        source = module.VaultwardenSource()
        item_id = "00000000-0000-4000-8000-000000000002"
        cfg = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [item_id],
            "env": {"SYNTHETIC_API_KEY": {"item_id": item_id, "field": "login.password"}},
            "binary_sha256": "0" * 64,
        }

        with TemporaryDirectory() as tmp:
            fake_bw = Path(tmp) / "bw"
            fake_bw.write_bytes(b"#!/usr/bin/python3\n")
            fake_bw.chmod(0o700)
            with fake_bw.open("r+b") as handle:
                handle.truncate(module._MAX_EXECUTABLE_BYTES + 1)
            cfg["binary_path"] = str(fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }
            with mock.patch.dict(os.environ, env, clear=True):
                result = source.fetch(cfg, Path(tmp))

        self.assertEqual(ErrorKind.BINARY_MISSING, result.error_kind)
        self.assertIn("size limit", result.error)


if __name__ == "__main__":
    unittest.main()
