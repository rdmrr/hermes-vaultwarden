from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Protocol
from unittest import mock


_ITEM_ID = "00000000-0000-4000-8000-000000000002"
_COLLECTION_ID = "00000000-0000-4000-8000-000000000001"
_TARGET_ENV = "SYNTHETIC_PROFILE_API_KEY"
_EXPECTED_REPORT = {
    "initial": {
        "started": True,
        "applied": True,
        "source": "vaultwarden",
    },
    "rotation": {
        "started": True,
        "recognized": True,
        "source": "vaultwarden",
    },
    "missing_bootstrap": {
        "started": True,
        "applied": False,
        "error_kind": "not_configured",
    },
    "authentication_failure": {
        "started": True,
        "applied": False,
        "error_kind": "auth_failed",
    },
    "binary_tamper": {
        "started": True,
        "applied": False,
        "error_kind": "binary_missing",
    },
}


class _PluginManagerLike(Protocol):
    def discover_and_load(self, force: bool = False) -> None: ...


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fake_bw(path: Path, value_path: Path, mode_path: Path) -> None:
    path.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, pathlib, sys\n"
        f"value_path = pathlib.Path({str(value_path)!r})\n"
        f"mode_path = pathlib.Path({str(mode_path)!r})\n"
        "args = sys.argv[1:]\n"
        "mode = mode_path.read_text(encoding='utf-8').strip()\n"
        "if args[0] == '--version':\n"
        "    assert 'BW_CLIENTID' not in os.environ\n"
        "    assert 'BW_CLIENTSECRET' not in os.environ\n"
        "    assert 'BW_PASSWORD' not in os.environ\n"
        "    print('2026.8.0')\n"
        "    raise SystemExit(0)\n"
        "if args[:2] == ['config', 'server']:\n"
        "    raise SystemExit(0)\n"
        "if args[:2] == ['login', '--apikey']:\n"
        "    if mode == 'authentication_failure':\n"
        "        print('unauthorized synthetic request', file=sys.stderr)\n"
        "        raise SystemExit(1)\n"
        "    raise SystemExit(0)\n"
        "if args[:2] == ['unlock', '--passwordenv']:\n"
        "    print('synthetic-session')\n"
        "    raise SystemExit(0)\n"
        "if args[0] == 'sync':\n"
        "    raise SystemExit(0)\n"
        "if args[:2] == ['get', 'item']:\n"
        "    print(json.dumps({'id': args[2], "
        f"'collectionIds': ['{_COLLECTION_ID}'], "
        "'login': {'password': value_path.read_text(encoding='utf-8')}}))\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _source_config(binary: Path) -> dict:
    interpreter = Path(binary.read_text(encoding="utf-8").splitlines()[0][2:])
    return {
        "enabled": True,
        "server_url": "https://vault.example.invalid",
        "collection_id": _COLLECTION_ID,
        "allowed_item_ids": [_ITEM_ID],
        "env": {
            _TARGET_ENV: {
                "item_id": _ITEM_ID,
                "field": "login.password",
            }
        },
        "binary_path": str(binary),
        "binary_sha256": _digest(binary),
        "binary_interpreter_sha256": _digest(interpreter),
        "cli_timeout_seconds": 5,
        "timeout_seconds": 15,
        "override_existing": True,
    }


def _write_profile_config(home: Path, cfg: dict) -> None:
    binary = cfg["binary_path"]
    home.joinpath("config.yaml").write_text(
        "plugins:\n"
        "  enabled: [hermes-vaultwarden]\n"
        "  entries:\n"
        "    hermes-vaultwarden:\n"
        "      settings:\n"
        "        enabled: true\n"
        "        server_url: https://vault.example.invalid\n"
        f"        collection_id: {_COLLECTION_ID}\n"
        "        allowed_item_ids:\n"
        f"          - {_ITEM_ID}\n"
        "        env:\n"
        f"          {_TARGET_ENV}:\n"
        f"            item_id: {_ITEM_ID}\n"
        "            field: login.password\n"
        f"        binary_path: {binary}\n"
        f"        binary_sha256: {cfg['binary_sha256']}\n"
        f"        binary_interpreter_sha256: {cfg['binary_interpreter_sha256']}\n"
        "        cli_timeout_seconds: 5\n"
        "        timeout_seconds: 15\n"
        "        override_existing: true\n"
        "secrets:\n"
        "  sources: [vaultwarden]\n"
        "  vaultwarden:\n"
        "    enabled: true\n",
        encoding="utf-8",
    )


def _bootstrap() -> dict[str, str]:
    return {
        "BW_CLIENTID": "synthetic-client",
        "BW_CLIENTSECRET": "synthetic-client-secret",
        "BW_PASSWORD": "synthetic-master-credential",
    }


def _start_profile(manager: _PluginManagerLike, *, force: bool = False) -> bool:
    """Run the real discovery/startup hook and report whether it returned."""
    try:
        manager.discover_and_load(force=force)
    except Exception:
        return False
    return True


def _failure_result(
    manager: _PluginManagerLike,
    cfg: dict,
    home: Path,
    environ: dict[str, str],
) -> dict:
    from agent.secret_sources.registry import apply_all

    with mock.patch.dict(
        os.environ,
        {"HERMES_HOME": str(home), **environ},
        clear=False,
    ):
        for name in ("BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"):
            if name not in environ:
                os.environ.pop(name, None)
        os.environ.pop(_TARGET_ENV, None)
        started = _start_profile(manager, force=True)

    report = apply_all(
        {"sources": ["vaultwarden"], "vaultwarden": cfg},
        home,
        environ=environ,
    )
    source = report.sources[0]
    return {
        "started": started,
        "applied": bool(source.applied),
        "error_kind": source.result.error_kind.value,
    }


def _run_profile_integration_worker(project_root: Path) -> dict:
    """Exercise a disposable profile inside an isolated worker process."""
    from agent.secret_sources import registry
    from hermes_cli import env_loader
    from hermes_cli.plugins import PluginManager

    project_root = Path(project_root).resolve()
    with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-profile-") as tmp:
        root = Path(tmp)
        home = root / "profiles" / "portable-test"
        plugin_target = home / "plugins" / "hermes-vaultwarden"
        plugin_target.parent.mkdir(parents=True)
        shutil.copytree(project_root / "vaultwarden_secret_source", plugin_target)

        value_path = root / "resolved-value"
        mode_path = root / "mode"
        binary = root / "bw"
        value_path.write_text("synthetic-value-one", encoding="utf-8")
        mode_path.write_text("success", encoding="utf-8")
        _write_fake_bw(binary, value_path, mode_path)
        cfg = _source_config(binary)
        _write_profile_config(home, cfg)

        runtime_env = {
            "HERMES_HOME": str(home),
            **_bootstrap(),
        }
        manager = PluginManager(scope_key=str(home.resolve()))
        registry._reset_registry_for_tests()
        env_loader.reset_secret_source_cache()
        try:
            with mock.patch.dict(os.environ, runtime_env, clear=False):
                os.environ.pop(_TARGET_ENV, None)
                initial_started = _start_profile(manager)
                first_value = os.environ.get(_TARGET_ENV)
                initial = {
                    "started": initial_started,
                    "applied": first_value == "synthetic-value-one",
                    "source": env_loader.get_secret_source(_TARGET_ENV),
                }

                value_path.write_text("synthetic-value-two", encoding="utf-8")
                os.environ.pop(_TARGET_ENV, None)
                rotation_started = _start_profile(manager, force=True)
                rotated_value = os.environ.get(_TARGET_ENV)
                rotation = {
                    "started": rotation_started,
                    "recognized": (
                        first_value == "synthetic-value-one"
                        and rotated_value == "synthetic-value-two"
                    ),
                    "source": env_loader.get_secret_source(_TARGET_ENV),
                }

                missing_env = _bootstrap()
                missing_env.pop("BW_PASSWORD")
                missing_bootstrap = _failure_result(
                    manager,
                    cfg,
                    home,
                    missing_env,
                )

                mode_path.write_text("authentication_failure", encoding="utf-8")
                authentication_failure = _failure_result(
                    manager,
                    cfg,
                    home,
                    _bootstrap(),
                )
                mode_path.write_text("success", encoding="utf-8")

                binary.write_text(
                    binary.read_text(encoding="utf-8") + "# post-pin change\n",
                    encoding="utf-8",
                )
                binary_tamper = _failure_result(
                    manager,
                    cfg,
                    home,
                    _bootstrap(),
                )
        finally:
            try:
                manager.unload()
            finally:
                registry._reset_registry_for_tests()
                env_loader.reset_secret_source_cache()

    return {
        "initial": initial,
        "rotation": rotation,
        "missing_bootstrap": missing_bootstrap,
        "authentication_failure": authentication_failure,
        "binary_tamper": binary_tamper,
    }


def run_profile_integration(project_root: Path) -> dict:
    """Run the disposable profile check without mutating caller process state."""
    proc = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            "--project-root",
            str(Path(project_root).resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "isolated profile integration worker failed "
            f"with exit code {proc.returncode}: {proc.stderr.strip()}"
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("isolated profile integration worker returned invalid JSON") from exc
    if not validate_report(report):
        raise RuntimeError("isolated profile integration worker returned a failing report")
    return report


def validate_report(report: object) -> bool:
    """Fail closed unless every integration phase has its exact safe outcome."""
    return report == _EXPECTED_REPORT


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the disposable Hermes Vaultwarden profile integration check."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    report = (
        _run_profile_integration_worker(args.project_root)
        if args.worker
        else run_profile_integration(args.project_root)
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if validate_report(report) else 1


if __name__ == "__main__":
    sys.exit(main())
