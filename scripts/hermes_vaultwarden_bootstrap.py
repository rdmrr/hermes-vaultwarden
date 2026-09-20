#!/usr/bin/env python3
"""Install TPM2-backed systemd credentials for the Vaultwarden source."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO


CREDENTIAL_NAMES = ("BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD")
PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.service\Z")


@dataclass(frozen=True)
class InstallLayout:
    profile: str
    unit: str
    root: Path
    credential_dir: Path
    drop_in: Path
    manifest: Path
    env_script: Path
    credentials: dict[str, Path]

    @classmethod
    def for_system(cls, *, profile: str, unit: str, root: Path = Path("/")) -> "InstallLayout":
        if not PROFILE_RE.fullmatch(profile):
            raise ValueError("invalid profile name")
        if not SERVICE_RE.fullmatch(unit):
            raise ValueError("invalid systemd service unit")
        if not root.is_absolute():
            raise ValueError("invalid non-absolute root")
        credential_dir = root / "etc/credstore.encrypted/hermes-vaultwarden" / profile
        return cls(
            profile=profile,
            unit=unit,
            root=root,
            credential_dir=credential_dir,
            drop_in=root / "etc/systemd/system" / f"{unit}.d/50-hermes-vaultwarden.conf",
            manifest=root / "etc/hermes-vaultwarden" / f"{profile}.json",
            # NOTE (VW-014): this directory is deliberately NOT
            # etc/hermes-vaultwarden (the manifest's parent) or anything
            # nested under it. That directory is 0700 root-only so that the
            # manifest and other root-only state stay unreadable to the
            # service user; ExecStartPre= processes in the rendered unit
            # inherit the *target* unit's own User= (e.g. User=svc-hermes) --
            # not root -- and a non-root process cannot open a file inside a
            # 0700 directory it cannot traverse (x), regardless of the
            # file's own mode. env_script instead lives in its own sibling
            # directory that install() creates as 0755 (world-traversable)
            # so any service User= can read and execute it. See
            # docs/systemd-bootstrap.md for the chosen fix (option a).
            env_script=root / "etc/hermes-vaultwarden-scripts" / f"{profile}-write-env.sh",
            credentials={name: credential_dir / f"{name}.cred" for name in CREDENTIAL_NAMES},
        )


def _unit_path(layout: InstallLayout, path: Path) -> str:
    return "/" + path.relative_to(layout.root).as_posix()


def _runtime_directory_name(layout: InstallLayout) -> str:
    # RuntimeDirectory= must be a single path component; the unit name (minus
    # ".service") plus the profile keeps it unique per managed installation
    # without needing any specifier expansion.
    return f"hermes-vaultwarden-{layout.unit.removesuffix('.service')}-{layout.profile}"


def _runtime_env_path(layout: InstallLayout) -> str:
    return f"/run/{_runtime_directory_name(layout)}/env"


def render_env_script(layout: InstallLayout) -> str:
    # This script's *content* is never parsed or substituted by systemd --
    # only its path appears in the unit's ExecStartPre= directive (see
    # render_drop_in()). $CREDENTIALS_DIRECTORY and $RUNTIME_DIRECTORY are
    # real process environment variables systemd sets before exec'ing this
    # script's interpreter, and "$n" is an ordinary POSIX shell loop
    # variable -- both are safe here because the shell that evaluates them
    # is /bin/sh reading this file, not systemd's own command-line parser.
    lines = [
        "#!/bin/sh",
        "# Managed by hermes-vaultwarden-bootstrap. Do not add plaintext secrets.",
        "set -eu",
        "umask 077",
        ': > "$RUNTIME_DIRECTORY/env"',
        f"for n in {' '.join(CREDENTIAL_NAMES)}; do",
        '    printf "%s=%s\\n" "$n" "$(cat "$CREDENTIALS_DIRECTORY/$n")" >> "$RUNTIME_DIRECTORY/env"',
        "done",
    ]
    return "\n".join(lines) + "\n"


def render_drop_in(layout: InstallLayout) -> str:
    # NOTE: systemd does NOT expand the "%d" (credentials directory)
    # specifier inside EnvironmentFile= -- confirmed against systemd
    # 255.4-1ubuntu8.17 with both TPM2-encrypted and plaintext credentials.
    # EnvironmentFile= values are only specifier-expanded as *paths*; the
    # runtime credentials directory ($CREDENTIALS_DIRECTORY / %d) is only
    # populated once the service's credential machinery has already run and
    # by then EnvironmentFile= has already been resolved, so a literal
    # "%d/<name>" is never a valid path and the unit fails closed
    # (Result=resources, "Failed to load environment files"). (VW-012)
    #
    # NOTE (VW-013): the VW-012 fix originally inlined a "for n in ...; do
    # ... \"$n\" ... done" loop directly into ExecStartPre=/bin/sh -c '...'.
    # That works when set via `systemd-run -p ExecStartPre=...`, but when
    # the identical directive is loaded from a real unit file on disk (via
    # a drop-in + `systemctl daemon-reload`), systemd performs its own
    # "$VARIABLE"/"${VARIABLE}" substitution on Exec*= command lines BEFORE
    # handing them to the shell -- confirmed against systemd
    # 255.4-1ubuntu8.17. Since "$n" is not a real environment variable known
    # to systemd, that substitution silently replaces every "$n" with an
    # unrelated value (observed: the manager's $SHELL), so the loop variable
    # never reaches the shell and every written line collapses to the same
    # (wrong) text. `systemd-run -p` does not exhibit this because it wires
    # the directive through a different, non-unit-file code path.
    #
    # Fix: an Exec*= directive must never contain a literal "$"-prefixed
    # token that is not one of systemd's own recognized variables. The loop
    # now lives entirely inside a separate, on-disk shell script
    # (render_env_script()) whose *content* systemd never parses; the
    # ExecStartPre= directive itself only names that script's path, so
    # there is nothing left for systemd's command-line substitution to
    # (mis)interpret.
    runtime_directory = _runtime_directory_name(layout)
    lines = [
        "# Managed by hermes-vaultwarden-bootstrap. Do not add plaintext secrets.",
        "[Service]",
    ]
    for name, path in layout.credentials.items():
        lines.append(f"LoadCredentialEncrypted={name}:{_unit_path(layout, path)}")
    lines.append(f"RuntimeDirectory={runtime_directory}")
    lines.append("RuntimeDirectoryMode=0700")
    lines.append(f"ExecStartPre=/bin/sh {_unit_path(layout, layout.env_script)}")
    lines.append(f"EnvironmentFile=-{_runtime_env_path(layout)}")
    return "\n".join(lines) + "\n"


def _environment_payload(name: str, value: str) -> bytes:
    if name not in CREDENTIAL_NAMES:
        raise ValueError("invalid credential name")
    if not value or any(character in value for character in ("\0", "\r", "\n")):
        raise ValueError("credential must be non-empty and single-line")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{name}="{escaped}"\n'.encode("utf-8")


def encrypt_credential(
    name: str,
    value: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> bytes:
    result = run(
        [
            "systemd-creds",
            "encrypt",
            "--with-key=tpm2",
            f"--name={name}",
            "-",
            "-",
        ],
        input=_environment_payload(name, value),
        capture_output=True,
        check=False,
        env={"LANG": "C.UTF-8", "PATH": os.defpath},
    )
    if result.returncode != 0 or not result.stdout:
        raise RuntimeError(f"systemd-creds failed for {name}")
    return result.stdout


def _manifest_bytes(layout: InstallLayout) -> bytes:
    return (
        json.dumps(
            {
                "credential_names": list(CREDENTIAL_NAMES),
                "profile": layout.profile,
                "schema": 1,
                "unit": layout.unit,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _regular_file_matches(path: Path, expected: bytes | None = None) -> bool:
    try:
        if not path.is_file() or path.is_symlink():
            return False
        return expected is None or path.read_bytes() == expected
    except OSError:
        return False


def _secure_file_matches(
    path: Path,
    *,
    mode: int,
    owner: tuple[int, int],
    expected: bytes | None = None,
) -> bool:
    if not _regular_file_matches(path, expected):
        return False
    file_stat = path.stat()
    return (file_stat.st_mode & 0o777) == mode and (file_stat.st_uid, file_stat.st_gid) == owner


def is_installed(layout: InstallLayout) -> bool:
    try:
        root_stat = layout.root.stat()
        owner = (root_stat.st_uid, root_stat.st_gid)
        credential_dir_stat = layout.credential_dir.stat()
        return (
            layout.credential_dir.is_dir()
            and not layout.credential_dir.is_symlink()
            and (credential_dir_stat.st_mode & 0o777) == 0o700
            and (credential_dir_stat.st_uid, credential_dir_stat.st_gid) == owner
            and _secure_file_matches(
                layout.drop_in,
                mode=0o644,
                owner=owner,
                expected=render_drop_in(layout).encode("utf-8"),
            )
            and _secure_file_matches(
                layout.env_script,
                mode=0o755,
                owner=owner,
                expected=render_env_script(layout).encode("utf-8"),
            )
            and _secure_file_matches(
                layout.manifest,
                mode=0o600,
                owner=owner,
                expected=_manifest_bytes(layout),
            )
            and all(
                _secure_file_matches(path, mode=0o600, owner=owner)
                for path in layout.credentials.values()
            )
        )
    except OSError:
        return False


def _path_state(path: Path) -> str:
    try:
        if path.is_symlink():
            return "unsafe-symlink"
        return "present" if path.exists() else "missing"
    except OSError:
        return "inaccessible"


def _make_directory(path: Path, mode: int, created: list[Path]) -> None:
    missing: list[Path] = []
    candidate = path
    while not candidate.exists():
        missing.append(candidate)
        candidate = candidate.parent
    if candidate.is_symlink() or not candidate.is_dir():
        raise RuntimeError(f"unsafe parent path: {candidate}")
    for directory in reversed(missing):
        directory.mkdir(mode=mode)
        os.chmod(directory, mode)
        created.append(directory)


def _validate_existing_directory(
    path: Path,
    *,
    mode: int,
    owner: tuple[int, int],
) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"unsafe managed directory: {path}")
    directory_stat = path.stat()
    if (directory_stat.st_mode & 0o777) != mode:
        raise RuntimeError(f"unsafe managed directory: {path}")
    if (directory_stat.st_uid, directory_stat.st_gid) != owner:
        raise RuntimeError(f"unsafe managed directory: {path}")


def _write_new(path: Path, content: bytes, mode: int, created: list[Path]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to replace existing path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        created.append(path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def install(
    layout: InstallLayout,
    secrets: dict[str, str],
    *,
    encrypt: Callable[[str, str], bytes] = encrypt_credential,
    reload_systemd: Callable[[], None],
) -> bool:
    """Install one profile transactionally; return False for an exact no-op."""
    if is_installed(layout):
        return False
    targets = [*layout.credentials.values(), layout.drop_in, layout.env_script, layout.manifest]
    if any(path.exists() or path.is_symlink() for path in targets):
        raise RuntimeError("partial or conflicting installation exists")
    if set(secrets) != set(CREDENTIAL_NAMES):
        raise ValueError("all three bootstrap credentials are required")

    root_stat = layout.root.stat()
    owner = (root_stat.st_uid, root_stat.st_gid)
    _validate_existing_directory(layout.credential_dir, mode=0o700, owner=owner)
    encrypted = {name: encrypt(name, secrets[name]) for name in CREDENTIAL_NAMES}
    created_files: list[Path] = []
    created_directories: list[Path] = []
    reload_attempted = False
    try:
        _make_directory(layout.credential_dir, 0o700, created_directories)
        _make_directory(layout.drop_in.parent, 0o755, created_directories)
        _make_directory(layout.manifest.parent, 0o700, created_directories)
        _make_directory(layout.env_script.parent, 0o755, created_directories)
        for name, path in layout.credentials.items():
            _write_new(path, encrypted[name], 0o600, created_files)
        _write_new(layout.drop_in, render_drop_in(layout).encode("utf-8"), 0o644, created_files)
        _write_new(layout.env_script, render_env_script(layout).encode("utf-8"), 0o755, created_files)
        _write_new(layout.manifest, _manifest_bytes(layout), 0o600, created_files)
        reload_attempted = True
        reload_systemd()
    except BaseException:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for directory in reversed(created_directories):
            try:
                directory.rmdir()
            except OSError:
                pass
        if reload_attempted:
            try:
                reload_systemd()
            except BaseException:
                pass
        raise
    return True


def remove(layout: InstallLayout, *, reload_systemd: Callable[[], None]) -> bool:
    """Remove one exact managed installation; return False when absent."""
    targets = [*layout.credentials.values(), layout.drop_in, layout.env_script, layout.manifest]
    if not any(path.exists() or path.is_symlink() for path in targets):
        return False
    if not is_installed(layout):
        raise RuntimeError("partial or conflicting installation exists")

    snapshots = {
        path: (path.read_bytes(), path.stat().st_mode & 0o777)
        for path in targets
    }
    try:
        for path in targets:
            path.unlink()
        for directory in (
            layout.credential_dir,
            layout.drop_in.parent,
            layout.manifest.parent,
            layout.env_script.parent,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        reload_systemd()
    except BaseException:
        restored_files: list[Path] = []
        restored_directories: list[Path] = []
        _make_directory(layout.credential_dir, 0o700, restored_directories)
        _make_directory(layout.drop_in.parent, 0o755, restored_directories)
        _make_directory(layout.manifest.parent, 0o700, restored_directories)
        _make_directory(layout.env_script.parent, 0o755, restored_directories)
        for path, (content, mode) in snapshots.items():
            if not path.exists():
                _write_new(path, content, mode, restored_files)
        try:
            reload_systemd()
        except BaseException:
            pass
        raise
    return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage TPM2-backed systemd credentials for a Hermes profile."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prereq", "status", "setup", "remove"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--profile", required=True)
        subparser.add_argument("--unit", required=True)
        subparser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
        if command in {"setup", "remove"}:
            subparser.add_argument("--apply", action="store_true")
            subparser.add_argument("--yes", action="store_true")
    return parser


def check_prerequisites(
    unit: str,
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[str]:
    if not SERVICE_RE.fullmatch(unit):
        raise ValueError("invalid systemd service unit")
    issues = []
    missing = [command for command in ("systemd-creds", "systemctl") if which(command) is None]
    issues.extend(f"required command is missing: {command}" for command in missing)
    if "systemd-creds" not in missing:
        tpm = run(
            ["systemd-creds", "has-tpm2", "-q"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if tpm.returncode != 0:
            issues.append("TPM2 support is not fully available")
    if "systemctl" not in missing:
        unit_state = run(
            ["systemctl", "show", "--property=LoadState", "--value", unit],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if unit_state.returncode != 0 or unit_state.stdout.strip() != "loaded":
            issues.append("systemd unit is not loaded")
    return issues


def _show_plan(layout: InstallLayout, *, action: str, stdout: TextIO) -> None:
    print(f"PREVIEW: {action} profile {layout.profile} for {layout.unit}", file=stdout)
    for path in (*layout.credentials.values(), layout.drop_in, layout.env_script, layout.manifest):
        print(f"  {_unit_path(layout, path)}", file=stdout)
    print("no files were changed; pass --apply to execute", file=stdout)


def _reload_systemd() -> None:
    result = subprocess.run(
        ["systemctl", "daemon-reload"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("systemctl daemon-reload failed")


def _collect_secrets(prompt_secret: Callable[[str], str]) -> dict[str, str]:
    labels = {
        "BW_CLIENTID": "Bitwarden API client ID",
        "BW_CLIENTSECRET": "Bitwarden API client secret",
        "BW_PASSWORD": "separate Bitwarden master credential",
    }
    secrets = {}
    for name in CREDENTIAL_NAMES:
        while True:
            first = prompt_secret(f"{labels[name]}: ")
            second = prompt_secret(f"Repeat {labels[name]}: ")
            if first == second:
                _environment_payload(name, first)
                secrets[name] = first
                break
            first = second = ""
    return secrets


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    prompt_secret: Callable[[str], str] = getpass.getpass,
    prompt_text: Callable[[str], str] = input,
    euid: Callable[[], int] = os.geteuid,
    prerequisite_check: Callable[[str], list[str]] = check_prerequisites,
    encrypt: Callable[[str, str], bytes] = encrypt_credential,
    reload_systemd: Callable[[], None] = _reload_systemd,
) -> int:
    args = _parser().parse_args(argv)
    layout = InstallLayout.for_system(profile=args.profile, unit=args.unit, root=args.root)
    if args.command == "prereq":
        issues = prerequisite_check(layout.unit)
        if issues:
            for issue in issues:
                print(f"prerequisite failed: {issue}", file=stderr)
            return 1
        print("prerequisites: ok", file=stdout)
        return 0
    if args.command == "status":
        targets = [*layout.credentials.values(), layout.drop_in, layout.env_script, layout.manifest]
        path_states = [_path_state(path) for path in targets]
        if is_installed(layout):
            state = "installed"
        elif all(path_state == "missing" for path_state in path_states):
            state = "absent"
        else:
            state = "partial-or-conflicting"
        print(f"status: {state}", file=stdout)
        for path, path_state in zip(targets, path_states):
            print(f"{path.name}: {path_state}", file=stdout)
        return 0 if state == "installed" else 1
    if args.command == "setup":
        _show_plan(layout, action="install", stdout=stdout)
        if not args.apply:
            return 0
        if euid() != 0:
            print("setup --apply must run as root", file=stderr)
            return 1
        issues = prerequisite_check(layout.unit)
        if issues:
            for issue in issues:
                print(f"prerequisite failed: {issue}", file=stderr)
            return 1
        if is_installed(layout):
            print("already installed; no changes", file=stdout)
            return 0
        if not args.yes and prompt_text("Apply this plan? [y/N] ").strip().lower() != "y":
            print("cancelled; no files were changed", file=stdout)
            return 0
        secrets: dict[str, str] = {}
        try:
            secrets = _collect_secrets(prompt_secret)
            install(layout, secrets, encrypt=encrypt, reload_systemd=reload_systemd)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"setup failed: {error}", file=stderr)
            return 1
        finally:
            secrets.clear()
        print("installed; restart the service explicitly after reviewing its impact", file=stdout)
        return 0
    if args.command == "remove":
        _show_plan(layout, action="remove", stdout=stdout)
        if not args.apply:
            return 0
        if euid() != 0:
            print("remove --apply must run as root", file=stderr)
            return 1
        if not args.yes and prompt_text("Apply this removal? [y/N] ").strip().lower() != "y":
            print("cancelled; no files were changed", file=stdout)
            return 0
        try:
            changed = remove(layout, reload_systemd=reload_systemd)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"remove failed: {error}", file=stderr)
            return 1
        if changed:
            print("removed; restart the service explicitly after reviewing its impact", file=stdout)
        else:
            print("already absent; no changes", file=stdout)
        return 0
    raise NotImplementedError(f"{args.command} is not implemented")


if __name__ == "__main__":
    raise SystemExit(main())
