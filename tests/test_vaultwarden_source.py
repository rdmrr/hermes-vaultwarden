from __future__ import annotations

import hashlib
import importlib.util
import os
import re
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
    def test_directory_plugin_manifest_declares_compatible_api_and_pinned_cli(self):
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")

        self.assertIn("manifest_version: 2", manifest)
        self.assertIn("api_version: 1", manifest)
        self.assertIn('version: "0.1.0"', manifest)
        self.assertIn("platforms: [linux]", manifest)
        self.assertIn("bw-cli-version: 2026.8.0", manifest)

    def test_registers_mapped_source_with_schema_and_protected_bootstrap_vars(self):
        module = _load_plugin()
        registered = []
        module.register(types.SimpleNamespace(register_secret_source=registered.append))

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
