#!/usr/bin/env python3
"""Validate the pinned Hermes source fixture used by integration tests."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping


HERMES_FIXTURE_COMMIT = "fef0bc56b2f622ffe124835fbf57adfd10aa17e6"
_REQUIRED_PATHS = (
    Path("agent/secret_sources/base.py"),
    Path("agent/secret_sources/registry.py"),
    Path("agent/secret_scope.py"),
    Path("hermes_cli/plugins.py"),
    Path("gateway/run.py"),
    Path("gateway/run_startup.py"),
    Path("cron/scheduler.py"),
    Path("cron/scheduler_provider.py"),
    Path("tools/delegate_tool.py"),
)


class HermesFixtureError(RuntimeError):
    """Raised when integration tests cannot use the declared Hermes fixture."""


def require_hermes_fixture(environ: Mapping[str, str] | None = None) -> Path:
    """Return a verified source fixture or fail with an actionable error."""
    env = os.environ if environ is None else environ
    configured = env.get("HERMES_AGENT_SRC", "").strip()
    if not configured:
        raise HermesFixtureError(
            "HERMES_AGENT_SRC is required; integration tests never skip a missing Hermes fixture"
        )

    root = Path(configured).expanduser().resolve()
    if not root.is_dir():
        raise HermesFixtureError(f"HERMES_AGENT_SRC is not a directory: {root}")

    for relative in _REQUIRED_PATHS:
        if not root.joinpath(relative).is_file():
            raise HermesFixtureError(f"Hermes fixture is missing required path: {relative}")

    try:
        git_result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HermesFixtureError("Hermes fixture Git identity could not be verified") from exc
    if git_result.returncode != 0:
        raise HermesFixtureError("HERMES_AGENT_SRC is not a Git checkout")
    if git_result.stdout.strip() != HERMES_FIXTURE_COMMIT:
        raise HermesFixtureError(
            f"Hermes fixture must be at pinned commit {HERMES_FIXTURE_COMMIT}"
        )

    python_paths = {
        Path(entry).expanduser().resolve()
        for entry in env.get("PYTHONPATH", "").split(os.pathsep)
        if entry
    }
    if root not in python_paths:
        raise HermesFixtureError("PYTHONPATH must explicitly include HERMES_AGENT_SRC")

    try:
        spec = importlib.util.find_spec("agent.secret_sources.base")
    except Exception as exc:
        raise HermesFixtureError(
            "Hermes fixture module agent.secret_sources.base is not importable"
        ) from exc
    if spec is None or spec.origin is None:
        raise HermesFixtureError("Hermes fixture module agent.secret_sources.base is not importable")
    try:
        Path(spec.origin).resolve().relative_to(root)
    except ValueError as exc:
        raise HermesFixtureError(
            "agent.secret_sources.base resolves outside HERMES_AGENT_SRC"
        ) from exc

    return root


def main() -> int:
    try:
        root = require_hermes_fixture()
    except HermesFixtureError as exc:
        print(f"Hermes fixture error: {exc}", file=sys.stderr)
        return 1
    print(f"Hermes fixture ready: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
