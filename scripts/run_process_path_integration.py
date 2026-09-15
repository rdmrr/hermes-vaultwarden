from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

try:
    from scripts.run_profile_integration import (
        _TARGET_ENV,
        _bootstrap,
        _source_config,
        _write_fake_bw,
        _write_profile_config,
    )
except ModuleNotFoundError:
    from run_profile_integration import (
        _TARGET_ENV,
        _bootstrap,
        _source_config,
        _write_fake_bw,
        _write_profile_config,
    )


_PATHS = ("gateway", "multiplex_gateway", "cron", "subagent")
_AMBIENT_VALUE = "ambient-wrong-profile"
_PRIMARY_VALUE = "synthetic-path-primary"
_SECONDARY_VALUE = "synthetic-path-secondary"
_EXPECTED_REPORT = {
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


def _write_bootstrap_env(home: Path) -> None:
    home.joinpath(".env").write_text(
        "\n".join(f"{name}={value}" for name, value in _bootstrap().items()) + "\n",
        encoding="utf-8",
    )


def _prepare_profile(project_root: Path, root: Path, name: str, value: str) -> Path:
    home = root / "profiles" / name
    plugin_target = home / "plugins" / "hermes-vaultwarden"
    plugin_target.parent.mkdir(parents=True)
    shutil.copytree(project_root / "vaultwarden_secret_source", plugin_target)

    value_path = root / f"{name}-resolved-value"
    mode_path = root / f"{name}-mode"
    binary = root / f"{name}-bw"
    value_path.write_text(value, encoding="utf-8")
    mode_path.write_text("success", encoding="utf-8")
    _write_fake_bw(binary, value_path, mode_path)
    _write_profile_config(home, _source_config(binary))
    _write_bootstrap_env(home)
    return home


@contextmanager
def _profiles(project_root: Path):
    with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-paths-") as tmp:
        root = Path(tmp)
        primary = _prepare_profile(project_root, root, "primary", _PRIMARY_VALUE)
        secondary = _prepare_profile(project_root, root, "secondary", _SECONDARY_VALUE)
        yield primary, secondary


def _discover_primary(primary: Path):
    from agent.secret_sources import registry
    from hermes_cli import env_loader
    from hermes_cli.plugins import get_plugin_manager

    registry._reset_registry_for_tests()
    env_loader.reset_secret_source_cache()
    manager = get_plugin_manager()
    if manager.home_path.resolve() != primary.resolve():
        raise RuntimeError("plugin manager initialized outside isolated profile")
    manager.discover_and_load(force=True)
    return manager


def _cleanup(manager) -> None:
    from agent.secret_scope import set_multiplex_active
    from agent.secret_sources import registry
    from hermes_cli import env_loader

    set_multiplex_active(False)
    try:
        manager.unload()
    finally:
        registry._reset_registry_for_tests()
        env_loader.reset_secret_source_cache()


def _gateway_probe(project_root: Path) -> dict:
    from agent.secret_scope import current_secret_scope
    from agent.secret_sources import registry
    from hermes_cli import env_loader
    from hermes_cli.plugins import get_plugin_manager
    from hermes_constants import get_hermes_home_override

    with _profiles(project_root) as (primary, _secondary):
        os.environ["HERMES_HOME"] = str(primary)
        os.environ.update(_bootstrap())
        os.environ[_TARGET_ENV] = _AMBIENT_VALUE
        registry._reset_registry_for_tests()
        env_loader.reset_secret_source_cache()
        from gateway.run_startup import GatewayStartupMixin

        GatewayStartupMixin._start_register_plugins_relay_hooks()
        manager = get_plugin_manager()
        try:
            resolved = os.environ.get(_TARGET_ENV)
            return {
                "ambient_rejected": resolved != _AMBIENT_VALUE,
                "profile_resolved": resolved == _PRIMARY_VALUE,
                "scope_restored": (
                    current_secret_scope() is None and get_hermes_home_override() is None
                ),
            }
        finally:
            _cleanup(manager)


def _multiplex_gateway_probe(project_root: Path) -> dict:
    from agent.secret_scope import (
        build_profile_secret_scope,
        current_secret_scope,
        get_secret,
        set_multiplex_active,
    )
    from hermes_cli.env_loader import hydrate_profile_secret_sources
    from hermes_cli.plugins import PluginManager
    from hermes_constants import get_hermes_home_override

    with _profiles(project_root) as (primary, secondary):
        os.environ["HERMES_HOME"] = str(primary)
        os.environ.update(_bootstrap())
        manager = _discover_primary(primary)
        secondary_manager = PluginManager(scope_key=str(secondary.resolve()))
        try:
            hydrate_profile_secret_sources(primary)
            primary_scope = build_profile_secret_scope(primary)
            secondary_manager.discover_and_load()
            hydrate_profile_secret_sources(secondary)
            secondary_scope = build_profile_secret_scope(secondary)
            from gateway.run import _profile_runtime_scope

            os.environ[_TARGET_ENV] = _AMBIENT_VALUE
            set_multiplex_active(True)
            with _profile_runtime_scope(primary, prepared_secret_scope=primary_scope):
                primary_value = get_secret(_TARGET_ENV)
            with _profile_runtime_scope(secondary, prepared_secret_scope=secondary_scope):
                secondary_value = get_secret(_TARGET_ENV)
            return {
                "cross_profile_rejected": (
                    primary_value != secondary_value
                    and primary_value != _AMBIENT_VALUE
                    and secondary_value != _AMBIENT_VALUE
                ),
                "primary_resolved": primary_value == _PRIMARY_VALUE,
                "scope_restored": (
                    current_secret_scope() is None and get_hermes_home_override() is None
                ),
                "secondary_resolved": secondary_value == _SECONDARY_VALUE,
            }
        finally:
            try:
                secondary_manager.unload()
            finally:
                _cleanup(manager)


def _cron_probe(project_root: Path) -> dict:
    from agent.secret_scope import current_secret_scope, get_secret, set_multiplex_active
    import cron.scheduler as scheduler
    from cron.scheduler_provider import _profile_cron_scope
    from hermes_cli.env_loader import hydrate_profile_secret_sources
    from hermes_constants import get_hermes_home_override
    from tools import terminal_scope

    with _profiles(project_root) as (primary, _secondary):
        os.environ["HERMES_HOME"] = str(primary)
        os.environ.update(_bootstrap())
        manager = _discover_primary(primary)
        try:
            hydrate_profile_secret_sources(primary)
            os.environ[_TARGET_ENV] = _AMBIENT_VALUE
            set_multiplex_active(True)
            observed = {}

            def fake_run_job(job, **kwargs):
                observed["value"] = get_secret(_TARGET_ENV)
                return True, "synthetic-output", "synthetic-final", None

            with (
                mock.patch.object(scheduler, "claim_dispatch", return_value=True),
                mock.patch.object(scheduler, "mark_execution_running", return_value={}),
                mock.patch.object(scheduler, "run_job", side_effect=fake_run_job),
                mock.patch.object(scheduler, "_save_compose_deliver", return_value=None),
                mock.patch.object(scheduler, "_consume_interrupted_flag", return_value=False),
                mock.patch.object(scheduler, "_finish_completed_run", return_value=True),
                mock.patch.object(terminal_scope, "install_profile_terminal_scope", return_value=object()),
                mock.patch.object(terminal_scope, "reset_terminal_scope", return_value=None),
            ):
                with _profile_cron_scope(primary):
                    processed = scheduler._run_one_job_body(
                        {
                            "id": "synthetic-process-path",
                            "name": "synthetic-process-path",
                            "execution_id": "synthetic-execution",
                        }
                    )
            resolved = observed.get("value")
            return {
                "ambient_rejected": resolved != _AMBIENT_VALUE,
                "profile_resolved": processed is True and resolved == _PRIMARY_VALUE,
                "scope_restored": (
                    current_secret_scope() is None and get_hermes_home_override() is None
                ),
            }
        finally:
            _cleanup(manager)


def _subagent_probe(project_root: Path) -> dict:
    from agent.secret_scope import current_secret_scope, get_secret, set_multiplex_active
    from hermes_constants import get_hermes_home_override
    import run_agent
    from tools.delegate_tool import _build_child_agent, _run_single_child

    class ParentAgent:
        def __init__(self, credential: str) -> None:
            self._credential = credential

        @property
        def api_key(self) -> str:
            return self._credential

        model = "synthetic/model"
        provider = "openrouter"
        base_url = "https://openrouter.ai/api/v1"
        api_mode = "chat_completions"
        acp_command = None
        acp_args = []
        reasoning_config = None
        request_overrides = {}
        capabilities = None
        max_tokens = None
        enabled_toolsets = []
        disabled_toolsets = []
        session_id = None
        _active_children = []
        _delegate_depth = 0
        _session_db = None
        tool_progress_callback = None

    class FakeChild:
        def __init__(self, **kwargs) -> None:
            self.__dict__.update(kwargs)
            self.session_id = "synthetic-child-session"
            self._session_init_model_config = {}
            self.session_estimated_cost_usd = 0.0
            self.session_cost_status = None
            self.observed = None

        def run_conversation(self, **kwargs):
            self.observed = get_secret(_TARGET_ENV)
            return {
                "api_calls": 0,
                "completed": True,
                "final_response": "synthetic-complete",
                "messages": [],
            }

        def close(self) -> None:
            return None

    with _profiles(project_root) as (primary, _secondary):
        os.environ["HERMES_HOME"] = str(primary)
        os.environ.update(_bootstrap())
        manager = _discover_primary(primary)
        try:
            from gateway.run import _profile_runtime_scope

            os.environ[_TARGET_ENV] = _AMBIENT_VALUE
            set_multiplex_active(True)
            with _profile_runtime_scope(primary):
                parent = ParentAgent(get_secret(_TARGET_ENV))
                with mock.patch.object(run_agent, "AIAgent", FakeChild):
                    child = _build_child_agent(
                        task_index=0,
                        goal="synthetic scope probe",
                        context=None,
                        toolsets=None,
                        model=None,
                        max_iterations=1,
                        task_count=1,
                        parent_agent=parent,
                    )
                entry = _run_single_child(
                    task_index=0,
                    goal="synthetic scope probe",
                    child=child,
                    parent_agent=parent,
                )
            inherited = child.api_key
            inherited_scope_value = child.observed
            return {
                "ambient_rejected": (
                    inherited != _AMBIENT_VALUE
                    and inherited_scope_value != _AMBIENT_VALUE
                ),
                "credential_inherited": (
                    entry.get("status") == "completed"
                    and child not in parent._active_children
                    and inherited == _PRIMARY_VALUE
                    and inherited_scope_value == _PRIMARY_VALUE
                ),
                "scope_restored": (
                    current_secret_scope() is None and get_hermes_home_override() is None
                ),
            }
        finally:
            _cleanup(manager)


def _run_worker(path: str, project_root: Path) -> dict:
    probes = {
        "gateway": _gateway_probe,
        "multiplex_gateway": _multiplex_gateway_probe,
        "cron": _cron_probe,
        "subagent": _subagent_probe,
    }
    return probes[path](project_root)


def run_process_path_integration(project_root: Path) -> dict:
    report = {}
    runner = Path(__file__).resolve()
    for path in _PATHS:
        proc = subprocess.run(
            [
                sys.executable,
                str(runner),
                "--worker",
                path,
                "--project-root",
                str(Path(project_root).resolve()),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"isolated {path} probe failed with exit code {proc.returncode}"
            )
        try:
            report[path] = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"isolated {path} probe returned invalid JSON") from exc
    if not validate_report(report):
        raise RuntimeError("isolated process-path probes returned a failing report")
    return report


def validate_report(report: object) -> bool:
    return report == _EXPECTED_REPORT


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify isolated Hermes gateway, cron and subagent credential paths."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--worker", choices=_PATHS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    report = (
        _run_worker(args.worker, args.project_root)
        if args.worker
        else run_process_path_integration(args.project_root)
    )
    print(json.dumps(report, sort_keys=True))
    if args.worker:
        return 0
    return 0 if validate_report(report) else 1


if __name__ == "__main__":
    sys.exit(main())
