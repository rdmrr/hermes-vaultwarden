"""Unit tests for the ``vaultwarden_browser_fill`` tool (VW-020).

These tests exercise the pure/synchronous logic paths without a live browser or Bitwarden
CLI: argument validation, the cross-origin guard, and the handler's "never raises, never
leaks the secret" contract on validation/configuration failure paths.

The full, real (non-mocked) end-to-end path — actual Chromium via CDP, an actual pinned
fake-``bw`` executable, and a real HTML page — is covered separately by
``scripts/run_browser_fill_e2e.py`` (see VW-019's mandatory leak-test acceptance
criterion), which this suite does not duplicate.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import re
import subprocess
import sys
import types
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_INIT_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "__init__.py"
BROWSER_FILL_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "browser_fill.py"


def _install_contract_stub() -> None:
    from enum import Enum

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

    base = types.ModuleType("agent.secret_sources.base")
    base.ErrorKind = ErrorKind
    base.get_source_environment = lambda: {}
    base.is_valid_env_name = lambda value: bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value or ""))
    base.scrub_ansi = lambda value: value

    def run_cli(argv, *, env, timeout, label, timeout_message, stdin=subprocess.DEVNULL):
        try:
            return subprocess.run(
                list(argv), env=env, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, stdin=stdin,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(timeout_message) from exc
        except OSError as exc:
            raise RuntimeError(f"failed to invoke {label}: {exc}") from exc

    base.run_cli = run_cli

    from dataclasses import dataclass, field as dc_field

    @dataclass
    class FetchResult:
        secrets: dict = dc_field(default_factory=dict)
        warnings: list = dc_field(default_factory=list)
        error: "str | None" = None
        error_kind: "ErrorKind | None" = None
        binary_path: "Path | None" = None

        @property
        def ok(self) -> bool:
            return self.error is None

        def fail(self, error, kind):
            self.error = error
            self.error_kind = kind
            return self

    base.FetchResult = FetchResult

    class SecretSource:
        override_existing_default = False

    base.SecretSource = SecretSource

    agent = types.ModuleType("agent")
    secret_sources = types.ModuleType("agent.secret_sources")
    sys.modules["agent"] = agent
    sys.modules["agent.secret_sources"] = secret_sources
    sys.modules["agent.secret_sources.base"] = base


def tearDownModule() -> None:
    # The stub installed by _install_contract_stub() replaces the real
    # ``agent`` package tree in sys.modules for the duration of this test
    # module. Other test modules (test_hermes_contract, test_process_paths,
    # test_profile_integration, test_scanner_false_positive) require the
    # real pinned Hermes fixture's ``agent.secret_sources.base`` to be
    # importable, so this stub must not leak past this module's tests.
    for name in ("vaultwarden_secret_source.browser_fill", "vaultwarden_secret_source"):
        sys.modules.pop(name, None)
    for name in ("agent.secret_sources.base", "agent.secret_sources", "agent"):
        sys.modules.pop(name, None)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"{name} could not be loaded from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_browser_fill():
    _install_contract_stub()
    _load_module(PLUGIN_INIT_PATH, "vaultwarden_secret_source")
    return _load_module(BROWSER_FILL_PATH, "vaultwarden_secret_source.browser_fill")


VALID_ITEM_ID = "00000000-0000-4000-8000-000000000002"


class ValidateArgsTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_browser_fill()

    def test_accepts_well_formed_arguments_and_normalizes_them(self):
        parsed = self.module._validate_args({
            "item_id": f"  {VALID_ITEM_ID}  ",
            "field": " login.password ",
            "selector": "#password",
            "target_id": " ABCDEF123 ",
            "clear_first": False,
        })
        self.assertEqual((VALID_ITEM_ID, "login.password", "#password", "ABCDEF123", False), parsed)

    def test_defaults_clear_first_to_true_when_omitted(self):
        parsed = self.module._validate_args({
            "item_id": VALID_ITEM_ID, "field": "login.password",
            "selector": "#password", "target_id": "T1",
        })
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed[4])

    def test_rejects_missing_or_blank_required_fields(self):
        base_args = {
            "item_id": VALID_ITEM_ID, "field": "login.password",
            "selector": "#password", "target_id": "T1",
        }
        for missing_key in ("item_id", "field", "selector", "target_id"):
            with self.subTest(missing=missing_key):
                args = dict(base_args)
                args[missing_key] = "   "
                self.assertIsNone(self.module._validate_args(args))
                del args[missing_key]
                self.assertIsNone(self.module._validate_args(args))

    def test_rejects_non_string_types(self):
        args = {"item_id": 123, "field": "login.password", "selector": "#password", "target_id": "T1"}
        self.assertIsNone(self.module._validate_args(args))

    def test_rejects_overlong_selector(self):
        args = {
            "item_id": VALID_ITEM_ID, "field": "login.password",
            "selector": "#" + ("a" * self.module._MAX_SELECTOR_LENGTH),
            "target_id": "T1",
        }
        self.assertIsNone(self.module._validate_args(args))


class OriginAllowedTests(unittest.TestCase):
    def setUp(self):
        self.module = _load_browser_fill()

    def test_no_uris_configured_skips_the_check(self):
        allowed, reason = self.module._origin_allowed("https://anything.example/", [])
        self.assertTrue(allowed)
        self.assertEqual("skipped_no_uris_on_item", reason)

    def test_matching_hostname_is_allowed(self):
        allowed, reason = self.module._origin_allowed(
            "https://login.example.com/account", ["https://login.example.com/signin"],
        )
        self.assertTrue(allowed)
        self.assertEqual("matched", reason)

    def test_bare_host_uri_without_scheme_is_still_matched(self):
        allowed, _ = self.module._origin_allowed("https://login.example.com/", ["login.example.com"])
        self.assertTrue(allowed)

    def test_mismatched_hostname_is_refused(self):
        allowed, reason = self.module._origin_allowed(
            "https://evil.example.net/", ["https://login.example.com/"],
        )
        self.assertFalse(allowed)
        self.assertEqual("no_configured_login_uri_matched_the_current_page", reason)

    def test_unparseable_current_url_is_refused(self):
        allowed, reason = self.module._origin_allowed("http://[::1", ["https://login.example.com/"])
        self.assertFalse(allowed)
        self.assertEqual("current_page_url_could_not_be_parsed", reason)

    def test_subdomain_is_not_treated_as_a_match(self):
        allowed, _ = self.module._origin_allowed(
            "https://evil.login.example.com/", ["https://login.example.com/"],
        )
        self.assertFalse(allowed)


class HandlerNeverRaisesTests(unittest.TestCase):
    """The handler must never raise and must never leak a value on failure paths that
    don't require a live browser/CLI (missing args, unconfigured CDP endpoint)."""

    def setUp(self):
        self.module = _load_browser_fill()

    def test_missing_required_argument_returns_status_only_json(self):
        result_str = self.module.handle_vaultwarden_browser_fill({"item_id": VALID_ITEM_ID}, {})
        result = json.loads(result_str)
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertEqual("ref_invalid", result["error_kind"])

    def test_no_cdp_endpoint_configured_returns_not_configured_status(self):
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(self.module, "load_config_readonly", None, create=True):
                result_str = self.module.handle_vaultwarden_browser_fill(
                    {"item_id": VALID_ITEM_ID, "field": "login.password",
                     "selector": "#password", "target_id": "T1"},
                    {},
                )
        result = json.loads(result_str)
        self.assertFalse(result["success"])
        self.assertEqual("not_configured", result.get("error_kind"))

    def test_handler_never_lets_an_unexpected_exception_escape(self):
        """Even if a lower layer raises something unexpected, the handler's outer guard
        must convert it to a status-only JSON string, never propagate the exception."""
        import os
        from unittest import mock

        def _boom(*_args, **_kwargs):
            raise RuntimeError("synthetic failure containing s3cr3t-should-not-leak")

        with mock.patch.dict(os.environ, {"BROWSER_CDP_URL": "ws://127.0.0.1:1/devtools/browser/x"}, clear=True):
            with mock.patch.object(self.module, "_fetch_single_field", _boom):
                result_str = self.module.handle_vaultwarden_browser_fill(
                    {"item_id": VALID_ITEM_ID, "field": "login.password",
                     "selector": "#password", "target_id": "T1"},
                    {},
                )
        self.assertNotIn("s3cr3t-should-not-leak", result_str)
        result = json.loads(result_str)
        self.assertFalse(result["success"])


class RegistrationWiringTests(unittest.TestCase):
    """Verifies ``register()`` in the plugin's ``__init__.py`` actually wires the new tool
    when the plugin host provides ``register_tool`` (the failure-tolerant path already
    covered by ``test_vaultwarden_source.py`` for hosts that don't)."""

    def test_register_calls_register_tool_with_a_working_handler_and_check_fn(self):
        _install_contract_stub()
        plugin_module = _load_module(PLUGIN_INIT_PATH, "vaultwarden_secret_source")

        settings = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [VALID_ITEM_ID],
            "env": {},
        }
        registered_tools = []
        ctx = types.SimpleNamespace(
            get_config=lambda key, default=None: settings.get(key, default),
            register_secret_source=lambda source: None,
            register_cli_command=lambda **kwargs: None,
            register_tool=lambda **kwargs: registered_tools.append(kwargs),
        )

        plugin_module.register(ctx)

        self.assertEqual(1, len(registered_tools))
        tool = registered_tools[0]
        self.assertEqual("vaultwarden_browser_fill", tool["name"])
        self.assertIn("properties", tool["schema"]["parameters"])

        # The wired handler must behave exactly like calling the module function directly
        # (i.e. register() must not have dropped or reordered the settings argument).
        result_str = tool["handler"]({"item_id": VALID_ITEM_ID}, extra_kwarg="ignored")
        result = json.loads(result_str)
        self.assertFalse(result["success"])

    def test_register_works_when_installer_renames_the_package_directory(self):
        """Regression: `hermes plugins install` clones this repo's `vaultwarden_secret_source/`
        directory under the plugin's manifest slug (e.g. `hermes-vaultwarden`), so the module
        never actually lives at the literal name `vaultwarden_secret_source` in production. Both
        __init__.py and browser_fill.py must resolve their cross-imports via package-relative
        imports (with an absolute-import fallback for direct/dev loads), not a hardcoded absolute
        `vaultwarden_secret_source` import — that silently failed in production (v0.4.0), the tool
        was never registered, and agents had no way to notice because the plugin still "loaded".

        This test mirrors the real loader: hermes_cli/plugins_loader.py's
        `_load_directory_plugin` imports `__init__.py` via
        `spec_from_file_location(module_name, init_file, submodule_search_locations=[plugin_dir])`
        with `module_name` derived from the plugin's manifest slug, not from the source directory
        name on disk.
        """
        renamed_pkg_name = "hermes_plugins_test_slug_hermes_vaultwarden"
        for name in list(sys.modules):
            if name == renamed_pkg_name or name.startswith(renamed_pkg_name + "."):
                del sys.modules[name]
        # The real bug only shows up when the plugin directory has actually been renamed
        # on disk by the installer, so `import vaultwarden_secret_source` (an absolute,
        # non-relative import) cannot resolve at all — not merely under a different
        # sys.modules key. PROJECT_ROOT is on sys.path in this repo checkout, so the
        # literal package still exists there; block it with a MetaPathFinder so the
        # absolute import genuinely fails, exactly like it does after installation.
        import importlib.abc

        class _BlockVaultwardenSecretSource(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                if fullname == "vaultwarden_secret_source" or fullname.startswith(
                    "vaultwarden_secret_source."
                ):
                    raise ModuleNotFoundError(fullname)
                return None

        blocker = _BlockVaultwardenSecretSource()
        sys.meta_path.insert(0, blocker)
        self.addCleanup(lambda: sys.meta_path.remove(blocker))
        _install_contract_stub()

        plugin_dir = PLUGIN_INIT_PATH.parent
        spec = importlib.util.spec_from_file_location(
            renamed_pkg_name, PLUGIN_INIT_PATH, submodule_search_locations=[str(plugin_dir)]
        )
        module = importlib.util.module_from_spec(spec)
        module.__package__ = renamed_pkg_name
        module.__path__ = [str(plugin_dir)]
        sys.modules[renamed_pkg_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # pragma: no cover - failure path is the point of this test
            self.fail(f"plugin failed to load under a renamed package name: {exc!r}")

        registered_tools = []
        settings = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": "00000000-0000-4000-8000-000000000001",
            "allowed_item_ids": [VALID_ITEM_ID],
            "env": {},
        }
        ctx = types.SimpleNamespace(
            get_config=lambda key, default=None: settings.get(key, default),
            register_secret_source=lambda source: None,
            register_cli_command=lambda **kwargs: None,
            register_tool=lambda **kwargs: registered_tools.append(kwargs),
        )
        module.register(ctx)

        self.assertEqual(
            1,
            len(registered_tools),
            "vaultwarden_browser_fill must be registered even when the plugin directory "
            "was renamed by the installer away from 'vaultwarden_secret_source'",
        )
        self.assertEqual("vaultwarden_browser_fill", registered_tools[0]["name"])


class BrowserFillSecurityInvariantTests(unittest.TestCase):
    """Static invariants mirroring ``test_plugin_security.py``'s checks for ``__init__.py``,
    applied to ``browser_fill.py`` — adjusted for its legitimate CDP-only network usage
    (``requests``/``websockets`` to talk to a *local* Chromium debug port, never a model or
    MCP endpoint)."""

    @classmethod
    def setUpClass(cls):
        cls.source = BROWSER_FILL_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_has_no_direct_model_or_mcp_client_imports(self):
        prohibited_roots = {"anthropic", "openai", "mcp", "httpx", "urllib3"}
        imported_roots = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertEqual(set(), imported_roots & prohibited_roots)

    def test_subprocess_execution_never_enables_a_shell(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "subprocess"
            ):
                continue
            shell_keyword = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            self.assertTrue(
                shell_keyword is None
                or (isinstance(shell_keyword.value, ast.Constant) and shell_keyword.value.value is False)
            )

    def test_fill_failure_messages_never_interpolate_the_secret_value(self):
        """``_FillFailure`` messages may safely interpolate static protocol identifiers (e.g.
        the CDP method name), but must never interpolate ``value`` (the fetched secret) or
        any CDP response payload that could carry it — VW-019's core acceptance criterion,
        enforced structurally in addition to the runtime leak test in
        ``scripts/run_browser_fill_e2e.py``."""
        banned_names = {"value", "msg", "result", "loc", "doc", "query", "resolved", "attach", "fetched", "item"}
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_FillFailure"):
                continue
            if not node.args or not isinstance(node.args[0], ast.JoinedStr):
                continue
            for part in node.args[0].values:
                if not isinstance(part, ast.FormattedValue):
                    continue
                names_used = {n.id for n in ast.walk(part.value) if isinstance(n, ast.Name)}
                self.assertFalse(
                    names_used & banned_names,
                    msg=f"_FillFailure message interpolates {names_used & banned_names} — "
                        "this could leak the fetched secret or a raw CDP payload.",
                )


class DynamicCdpEndpointResolutionTests(unittest.TestCase):
    """v0.4.2 fix: the tool only ever worked when an operator hardcoded a static
    ``browser.cdp_url`` in config.yaml, which no production profile does — browser sessions
    are started dynamically per task by browser_exec itself. ``_resolve_cdp_endpoint`` must
    reuse that live, per-task session before falling back to the static config precedence."""

    def setUp(self):
        self.module = _load_browser_fill()

    def test_prefers_the_live_per_task_session_endpoint_over_static_config(self):
        fake_browser_tool = types.ModuleType("tools.browser_tool")
        fake_browser_tool._last_session_key = lambda task_id: f"session-for-{task_id}"

        fake_browser_tool_session = types.ModuleType("tools.browser_tool_session")

        def _fake_run_browser_command(session_key, verb, args):
            self.assertEqual("get", verb)
            self.assertEqual(["cdp-url"], args)
            return {
                "success": True,
                "data": {"cdpUrl": f"ws://127.0.0.1:9999/devtools/browser/{session_key}"},
            }

        fake_browser_tool_session._run_browser_command = _fake_run_browser_command

        sys.modules["tools.browser_tool"] = fake_browser_tool
        sys.modules["tools.browser_tool_session"] = fake_browser_tool_session
        self.addCleanup(sys.modules.pop, "tools.browser_tool", None)
        self.addCleanup(sys.modules.pop, "tools.browser_tool_session", None)

        endpoint = self.module._resolve_cdp_endpoint("my-task-id")
        self.assertEqual("ws://127.0.0.1:9999/devtools/browser/session-for-my-task-id", endpoint)

    def test_falls_back_to_static_config_when_no_live_session_exists(self):
        # No tools.browser_tool / tools.browser_tool_session available (or they raise/return
        # failure) — must fall through silently to BROWSER_CDP_URL, never raise.
        import os

        os.environ["BROWSER_CDP_URL"] = "ws://127.0.0.1:1234/devtools/browser/static-fallback"
        self.addCleanup(os.environ.pop, "BROWSER_CDP_URL", None)

        endpoint = self.module._resolve_cdp_endpoint("some-task-with-no-active-session")
        self.assertEqual("ws://127.0.0.1:1234/devtools/browser/static-fallback", endpoint)

    def test_missing_task_id_falls_back_to_static_config_without_raising(self):
        import os

        os.environ["BROWSER_CDP_URL"] = "ws://127.0.0.1:1234/devtools/browser/no-task-id"
        self.addCleanup(os.environ.pop, "BROWSER_CDP_URL", None)

        endpoint = self.module._resolve_cdp_endpoint(None)
        self.assertEqual("ws://127.0.0.1:1234/devtools/browser/no-task-id", endpoint)

    def test_check_fn_no_longer_requires_a_static_cdp_url(self):
        """check_fn is always called with zero arguments (tools/registry.py's
        _run_check_fn_uncached), so it cannot know whether a live per-task session exists.
        It must only gate on cheap, context-free preconditions (websockets installed, plugin
        enabled) — the per-call handler is where a missing live session correctly fails."""
        settings = {"enabled": True}
        self.assertTrue(self.module.check_vaultwarden_browser_fill(settings))


if __name__ == "__main__":
    unittest.main()
