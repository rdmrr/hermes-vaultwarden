"""Vaultwarden-backed Hermes secret source."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
    is_valid_env_name,
    scrub_ansi,
)

_BASE_CHILD_ENV = (
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "TMPDIR",
    "TEMP",
    "LANG",
    "LC_ALL",
)
_BW_CLI_VERSION = "2026.8.0"
_MAX_OUTPUT_BYTES = 1_048_576
_MAX_EXECUTABLE_BYTES = 256 * 1_048_576
_DEFAULT_FETCH_TIMEOUT_SECONDS = 120.0
_MIN_FETCH_TIMEOUT_SECONDS = 3.0
_FETCH_CLEANUP_RESERVE_SECONDS = 2.5
_PLUGIN_SETTING_DEFAULTS = {
    "enabled": False,
    "server_url": "",
    "collection_id": "",
    "allowed_item_ids": [],
    "env": {},
    "client_id_env": "BW_CLIENTID",
    "client_secret_env": "BW_CLIENTSECRET",
    "master_password_env": "BW_PASSWORD",
    "binary_path": "",
    "binary_sha256": "",
    "binary_interpreter_sha256": "",
    "cli_timeout_seconds": 30,
    "timeout_seconds": 120,
    "override_existing": True,
}


@dataclass(frozen=True)
class _Binding:
    item_id: str
    field: str


@dataclass
class _PinnedExecutable:
    binary_path: Path
    binary_fd: int
    binary_sha256: str
    stage_dir: tempfile.TemporaryDirectory
    interpreter_path: Path | None = None
    interpreter_fd: int | None = None
    interpreter_sha256: str | None = None

    def verify(self, deadline: float) -> None:
        _verify_fd(self.binary_fd, self.binary_sha256, "bw executable", deadline)
        if self.interpreter_fd is not None and self.interpreter_sha256 is not None:
            _verify_fd(
                self.interpreter_fd,
                self.interpreter_sha256,
                "bw script interpreter",
                deadline,
            )

    def command(self, args: list[str]) -> tuple[list[str], tuple[int, ...]]:
        binary_fd_path = f"/proc/self/fd/{self.binary_fd}"
        if self.interpreter_fd is None:
            return [binary_fd_path, *args, "--nointeraction"], (self.binary_fd,)
        interpreter_fd_path = f"/proc/self/fd/{self.interpreter_fd}"
        return (
            [interpreter_fd_path, binary_fd_path, *args, "--nointeraction"],
            (self.binary_fd, self.interpreter_fd),
        )

    def close(self) -> bool:
        for fd in (self.binary_fd, self.interpreter_fd):
            if fd is not None:
                _close_fd(fd)
        return _cleanup_stage_dir(self.stage_dir)


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _cleanup_stage_dir(stage_dir: tempfile.TemporaryDirectory) -> bool:
    for _attempt in range(2):
        try:
            stage_dir.cleanup()
            return True
        except OSError:
            continue
        except Exception:  # noqa: BLE001 - cleanup must not escape the source contract
            return False
    return False


def _canonical_uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        return None
    return str(parsed) if str(parsed) == value.lower() else None


def _validate_config(cfg: dict, deadline: float) -> tuple[dict[str, _Binding], str | None, ErrorKind | None]:
    server_url = cfg.get("server_url")
    try:
        parsed_url = urlparse(server_url) if isinstance(server_url, str) else None
    except ValueError:
        parsed_url = None
    if not parsed_url or parsed_url.scheme != "https" or not parsed_url.hostname:
        return {}, "secrets.vaultwarden.server_url must be an HTTPS URL.", ErrorKind.NOT_CONFIGURED
    if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        return {}, "secrets.vaultwarden.server_url must not contain credentials, query, or fragment.", ErrorKind.REF_INVALID

    if _canonical_uuid(cfg.get("collection_id")) is None:
        return {}, "secrets.vaultwarden.collection_id must be a UUID.", ErrorKind.NOT_CONFIGURED

    raw_allowlist = cfg.get("allowed_item_ids")
    if not isinstance(raw_allowlist, list) or not raw_allowlist:
        return {}, "secrets.vaultwarden.allowed_item_ids must be a non-empty UUID list.", ErrorKind.NOT_CONFIGURED
    allowlist = set()
    for value in raw_allowlist:
        _check_deadline(deadline)
        canonical = _canonical_uuid(value)
        if canonical is None:
            return {}, "secrets.vaultwarden.allowed_item_ids contains an invalid UUID.", ErrorKind.REF_INVALID
        allowlist.add(canonical)

    raw_env = cfg.get("env")
    if not isinstance(raw_env, dict) or not raw_env:
        return {}, "secrets.vaultwarden.env must contain explicit environment bindings.", ErrorKind.NOT_CONFIGURED

    bindings: dict[str, _Binding] = {}
    for env_name, raw_binding in raw_env.items():
        _check_deadline(deadline)
        if not isinstance(env_name, str) or not is_valid_env_name(env_name):
            return {}, "secrets.vaultwarden.env contains an invalid environment name.", ErrorKind.REF_INVALID
        if not isinstance(raw_binding, dict):
            return {}, f"secrets.vaultwarden.env.{env_name} must be a mapping.", ErrorKind.REF_INVALID
        item_id = _canonical_uuid(raw_binding.get("item_id"))
        if item_id is None or item_id not in allowlist:
            return {}, f"secrets.vaultwarden.env.{env_name} references an item outside the allowlist.", ErrorKind.REF_INVALID
        field = raw_binding.get("field")
        if not isinstance(field, str) or not field.strip():
            return {}, f"secrets.vaultwarden.env.{env_name}.field must be non-empty.", ErrorKind.REF_INVALID
        field = field.strip()
        if field not in {"login.username", "login.password", "notes"} and not (
            field.startswith("fields.") and field != "fields."
        ):
            return {}, f"secrets.vaultwarden.env.{env_name}.field is unsupported.", ErrorKind.REF_INVALID
        bindings[env_name] = _Binding(item_id=item_id, field=field)

    binary_sha256 = cfg.get("binary_sha256")
    if not isinstance(binary_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", binary_sha256):
        return {}, "secrets.vaultwarden.binary_sha256 must be a lowercase SHA-256 digest.", ErrorKind.NOT_CONFIGURED
    interpreter_sha256 = cfg.get("binary_interpreter_sha256")
    if interpreter_sha256 not in (None, "") and (
        not isinstance(interpreter_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", interpreter_sha256)
    ):
        return {}, "secrets.vaultwarden.binary_interpreter_sha256 must be a lowercase SHA-256 digest.", ErrorKind.REF_INVALID
    return bindings, None, None


def _positive_timeout(value: object, default: float = 30.0) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return default
    return timeout if math.isfinite(timeout) and timeout > 0 else default


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise _BwFailure("Vaultwarden fetch exhausted its internal wall-clock budget.", ErrorKind.TIMEOUT)


def _sha256_fd(fd: int, deadline: float) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        _check_deadline(deadline)
        chunk = os.pread(fd, 1_048_576, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _verify_fd(fd: int, expected_sha256: str, label: str, deadline: float) -> None:
    try:
        actual_sha256 = _sha256_fd(fd, deadline)
    except OSError as exc:
        raise _BwFailure(f"The pinned {label} could not be read.", ErrorKind.BINARY_MISSING) from exc
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise _BwFailure(f"The pinned {label} digest does not match configuration.", ErrorKind.BINARY_MISSING)


def _open_verified_fd(
    path: Path,
    staged_path: Path,
    expected_sha256: str,
    label: str,
    deadline: float,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    source_fd = None
    writer_fd = None
    readonly_fd = None
    try:
        source_fd = os.open(path, flags)
        file_stat = os.fstat(source_fd)
        if not stat.S_ISREG(file_stat.st_mode) or not file_stat.st_mode & 0o111:
            raise OSError("not an executable regular file")
        if file_stat.st_size > _MAX_EXECUTABLE_BYTES:
            raise _BwFailure(f"The pinned {label} exceeds the executable size limit.", ErrorKind.BINARY_MISSING)
        writer_fd = os.open(
            staged_path,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL,
            0o500,
        )
        offset = 0
        while True:
            _check_deadline(deadline)
            chunk = os.pread(source_fd, 1_048_576, offset)
            if not chunk:
                break
            written = 0
            while written < len(chunk):
                _check_deadline(deadline)
                written += os.write(writer_fd, chunk[written:])
            offset += len(chunk)
            if offset > _MAX_EXECUTABLE_BYTES:
                raise _BwFailure(f"The pinned {label} exceeds the executable size limit.", ErrorKind.BINARY_MISSING)
        os.fchmod(writer_fd, 0o500)
        _verify_fd(writer_fd, expected_sha256, label, deadline)
        readonly_fd = os.open(staged_path, flags)
        readonly_stat = os.fstat(readonly_fd)
        pinned_stat = os.fstat(writer_fd)
        if (readonly_stat.st_dev, readonly_stat.st_ino) != (pinned_stat.st_dev, pinned_stat.st_ino):
            raise OSError("staged executable identity changed")
        os.close(writer_fd)
        writer_fd = None
        result_fd = readonly_fd
        readonly_fd = None
        return result_fd
    except _BwFailure:
        raise
    except OSError as exc:
        raise _BwFailure(f"The pinned {label} could not be opened safely.", ErrorKind.BINARY_MISSING) from exc
    finally:
        _close_fd(source_fd)
        _close_fd(writer_fd)
        _close_fd(readonly_fd)


def _open_pinned_executable(binary: Path, cfg: dict, deadline: float) -> _PinnedExecutable:
    binary_sha256 = str(cfg["binary_sha256"])
    stage_dir = tempfile.TemporaryDirectory(
        prefix="hermes-vaultwarden-executable-",
        dir="/tmp",
    )
    stage_root = Path(stage_dir.name)
    binary_path = stage_root / "bw"
    binary_fd = None
    interpreter_fd = None
    opened = False
    try:
        os.chmod(stage_root, 0o700)
        binary_fd = _open_verified_fd(
            binary,
            binary_path,
            binary_sha256,
            "bw executable",
            deadline,
        )
        header = os.pread(binary_fd, 512, 0)
        if header.startswith(b"\x7fELF"):
            executable = _PinnedExecutable(binary_path, binary_fd, binary_sha256, stage_dir)
            opened = True
            return executable
        if not header.startswith(b"#!"):
            raise _BwFailure("The pinned bw executable format is unsupported.", ErrorKind.BINARY_MISSING)
        try:
            shebang = header.splitlines()[0][2:].decode("ascii").strip().split()
        except UnicodeDecodeError as exc:
            raise _BwFailure("The pinned bw script shebang is invalid.", ErrorKind.BINARY_MISSING) from exc
        if len(shebang) != 1 or not Path(shebang[0]).is_absolute():
            raise _BwFailure("The pinned bw script must use one absolute interpreter.", ErrorKind.BINARY_MISSING)
        interpreter_sha256 = cfg.get("binary_interpreter_sha256")
        if not isinstance(interpreter_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", interpreter_sha256):
            raise _BwFailure("A pinned bw script requires binary_interpreter_sha256.", ErrorKind.BINARY_MISSING)
        try:
            interpreter_path = Path(shebang[0]).resolve(strict=True)
        except OSError as exc:
            raise _BwFailure("The pinned bw script interpreter could not be resolved.", ErrorKind.BINARY_MISSING) from exc
        staged_interpreter_path = stage_root / "interpreter"
        interpreter_fd = _open_verified_fd(
            interpreter_path,
            staged_interpreter_path,
            interpreter_sha256,
            "bw script interpreter",
            deadline,
        )
        if not os.pread(interpreter_fd, 4, 0).startswith(b"\x7fELF"):
            raise _BwFailure("The pinned bw script interpreter must be a native executable.", ErrorKind.BINARY_MISSING)
        executable = _PinnedExecutable(
            binary_path,
            binary_fd,
            binary_sha256,
            stage_dir,
            staged_interpreter_path,
            interpreter_fd,
            interpreter_sha256,
        )
        opened = True
        return executable
    finally:
        if not opened:
            _close_fd(binary_fd)
            _close_fd(interpreter_fd)
            _cleanup_stage_dir(stage_dir)


def _remaining_timeout(deadline: float, cli_timeout: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _BwFailure("Vaultwarden fetch exhausted its internal wall-clock budget.", ErrorKind.TIMEOUT)
    return min(cli_timeout, remaining)


class _BwFailure(RuntimeError):
    def __init__(self, message: str, kind: ErrorKind):
        super().__init__(message)
        self.kind = kind


def _classify_bw_error(message: str) -> ErrorKind:
    lowered = message.lower()
    if "timed out" in lowered or "timeout" in lowered:
        return ErrorKind.TIMEOUT
    if any(token in lowered for token in ("session key is invalid", "session expired", "vault is locked")):
        return ErrorKind.AUTH_EXPIRED
    if any(token in lowered for token in (
        "invalid master password", "invalid api key", "invalid_client", "unauthorized", "not logged in",
        "401", "403",
    )):
        return ErrorKind.AUTH_FAILED
    if any(token in lowered for token in (
        "enotfound", "connection", "network", "resolve", "dns", "socket", "econnrefused",
    )):
        return ErrorKind.NETWORK
    if "not found" in lowered:
        return ErrorKind.REF_INVALID
    if "failed to invoke" in lowered:
        return ErrorKind.BINARY_MISSING
    return ErrorKind.INTERNAL


def _bw_failure(exit_code: int, private_detail: str) -> _BwFailure:
    kind = _classify_bw_error(private_detail)
    return _BwFailure(f"bw command failed with exit code {exit_code}; output was redacted.", kind)


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def _run_bw(
    executable: _PinnedExecutable,
    args: list[str],
    *,
    env: dict[str, str],
    timeout: float,
    deadline: float,
):
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise _BwFailure("This plugin release requires Linux procfs process semantics.",
                         ErrorKind.BINARY_MISSING)
    command, pass_fds = executable.command(args)
    _check_deadline(deadline)
    try:
        process = subprocess.Popen(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        raise _BwFailure("bw could not be invoked; diagnostic output was redacted.",
                         ErrorKind.BINARY_MISSING) from exc

    stdout = bytearray()
    stderr = bytearray()
    output_selector = None
    process_group_terminated = False
    try:
        output_selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        output_selector.register(process.stdout, selectors.EVENT_READ, stdout)
        output_selector.register(process.stderr, selectors.EVENT_READ, stderr)
        while output_selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise _BwFailure(f"bw command timed out after {timeout:.0f}s.", ErrorKind.TIMEOUT)
            for key, _mask in output_selector.select(remaining_time):
                target = key.data
                remaining_bytes = _MAX_OUTPUT_BYTES + 1 - len(target)
                chunk = os.read(key.fd, min(65_536, remaining_bytes))
                if not chunk:
                    output_selector.unregister(key.fileobj)
                    continue
                target.extend(chunk)
                if len(target) > _MAX_OUTPUT_BYTES:
                    raise _BwFailure("bw output limit exceeded; output was discarded.",
                                     ErrorKind.INTERNAL)

        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise _BwFailure(f"bw command timed out after {timeout:.0f}s.", ErrorKind.TIMEOUT)
        # Kill descendants while the direct child is still unreaped, preventing
        # PID/PGID reuse between cleanup and wait(). A well-behaved CLI has
        # already exited when both output pipes reach EOF.
        _kill_process_group(process)
        process_group_terminated = True
        returncode = process.returncode
        if returncode is None:
            raise _BwFailure(f"bw command timed out after {timeout:.0f}s.", ErrorKind.TIMEOUT)
    finally:
        # Always terminate descendants, including on selector/read failures.
        if not process_group_terminated:
            _kill_process_group(process)
        if output_selector is not None:
            output_selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    proc = subprocess.CompletedProcess(
        command,
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )
    if proc.returncode != 0:
        detail = scrub_ansi(proc.stderr or proc.stdout or "").strip()[:200]
        raise _bw_failure(proc.returncode, detail)
    return proc


def _run_pinned_bw(
    executable: _PinnedExecutable,
    args: list[str],
    *,
    env: dict[str, str],
    cli_timeout: float,
    deadline: float,
):
    executable.verify(deadline)
    command_timeout = _remaining_timeout(deadline, cli_timeout)
    command_deadline = time.monotonic() + command_timeout
    return _run_bw(
        executable,
        args,
        env=env,
        timeout=command_timeout,
        deadline=command_deadline,
    )


def _field_value(item: dict, field: str, deadline: float) -> str | None:
    if field == "notes":
        value = item.get("notes")
    elif field in {"login.username", "login.password"}:
        login = item.get("login")
        value = login.get(field.split(".", 1)[1]) if isinstance(login, dict) else None
    elif field.startswith("fields.") and field != "fields.":
        field_name = field.split(".", 1)[1]
        custom_fields = item.get("fields")
        value = None
        if isinstance(custom_fields, list):
            for candidate in custom_fields:
                _check_deadline(deadline)
                if isinstance(candidate, dict) and candidate.get("name") == field_name:
                    value = candidate.get("value")
                    break
    else:
        return None
    return value if isinstance(value, str) and value.strip() else None


class VaultwardenSource(SecretSource):
    """Resolve explicitly allowlisted Vaultwarden items through the ``bw`` CLI."""

    name = "vaultwarden"
    label = "Vaultwarden"
    shape = "mapped"
    token_env_key = "client_secret_env"
    default_token_env = "BW_CLIENTSECRET"
    override_existing_default = True

    def __init__(self, settings: dict | None = None):
        self._settings = dict(settings) if isinstance(settings, dict) else None

    def _effective_config(self, cfg: dict | None) -> dict:
        if self._settings is not None:
            return dict(self._settings)
        return dict(cfg) if isinstance(cfg, dict) else {}

    def is_enabled(self, cfg: dict) -> bool:
        return (
            isinstance(cfg, dict)
            and cfg.get("enabled") is True
            and self._effective_config(cfg).get("enabled") is True
        )

    def override_existing(self, cfg: dict) -> bool:
        cfg = self._effective_config(cfg)
        return cfg.get("override_existing", self.override_existing_default) is True

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "server_url": {"description": "Vaultwarden HTTPS URL", "default": ""},
            "collection_id": {"description": "Allowed collection UUID", "default": ""},
            "allowed_item_ids": {"description": "Item UUID allowlist", "default": []},
            "env": {
                "description": "Map of ENV_VAR to {item_id, field}",
                "default": {},
            },
            "client_id_env": {
                "description": "Env var holding the Bitwarden API client ID",
                "default": "BW_CLIENTID",
            },
            "client_secret_env": {
                "description": "Env var holding the Bitwarden API client secret",
                "default": "BW_CLIENTSECRET",
            },
            "master_password_env": {
                "description": "Env var holding the separately protected master credential",
                "default": "BW_PASSWORD",
            },
            "binary_path": {
                "description": "Absolute path to the pinned bw binary",
                "default": "",
            },
            "binary_sha256": {
                "description": "Lowercase SHA-256 digest of the pinned bw binary",
                "default": "",
            },
            "binary_interpreter_sha256": {
                "description": "Required digest when binary_path is a script",
                "default": "",
            },
            "cli_timeout_seconds": {
                "description": "Per-command timeout",
                "default": 30,
            },
            "timeout_seconds": {
                "description": "Hermes wall-clock fetch budget",
                "default": 120,
            },
            "override_existing": {
                "description": "Resolved values overwrite .env/shell values",
                "default": True,
            },
        }

    def protected_env_vars(self, cfg: dict) -> frozenset[str]:
        cfg = self._effective_config(cfg)
        protected = {"BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"}
        configured = {
            str(cfg.get("client_id_env") or ""),
            str(cfg.get("client_secret_env") or ""),
            str(cfg.get("master_password_env") or ""),
        }
        protected.update(name for name in configured if is_valid_env_name(name))
        return frozenset(protected)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        cfg = self._effective_config(cfg)
        configured = _positive_timeout(
            cfg.get("timeout_seconds"),
            _DEFAULT_FETCH_TIMEOUT_SECONDS,
        )
        return max(configured, _MIN_FETCH_TIMEOUT_SECONDS)

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = self._effective_config(cfg)
        result = FetchResult()
        fetch_timeout = self.fetch_timeout_seconds(cfg)
        deadline = time.monotonic() + fetch_timeout - _FETCH_CLEANUP_RESERVE_SECONDS
        try:
            bindings, error, kind = _validate_config(cfg, deadline)
        except _BwFailure as exc:
            return result.fail(str(exc), exc.kind)
        if error and kind:
            return result.fail(error, kind)
        collection_id = _canonical_uuid(cfg.get("collection_id"))
        if collection_id is None:  # defensive; validation above already rejected it
            return result.fail("secrets.vaultwarden.collection_id must be a UUID.", ErrorKind.REF_INVALID)

        source_env = get_source_environment()
        credential_vars = {
            "BW_CLIENTID": str(cfg.get("client_id_env") or "BW_CLIENTID"),
            "BW_CLIENTSECRET": str(cfg.get("client_secret_env") or "BW_CLIENTSECRET"),
            "BW_PASSWORD": str(cfg.get("master_password_env") or "BW_PASSWORD"),
        }
        if any(not is_valid_env_name(name) for name in credential_vars.values()):
            return result.fail("Vaultwarden bootstrap environment names are invalid.", ErrorKind.REF_INVALID)
        missing = [target for target, source in credential_vars.items() if not source_env.get(source, "").strip()]
        if missing:
            return result.fail(
                "Vaultwarden bootstrap credentials are not available in the source environment.",
                ErrorKind.NOT_CONFIGURED,
            )

        configured_binary = str(cfg.get("binary_path") or "").strip()
        binary = Path(configured_binary)
        if (
            not configured_binary
            or not binary.is_absolute()
        ):
            return result.fail(
                "secrets.vaultwarden.binary_path must be an absolute file path.",
                ErrorKind.BINARY_MISSING,
            )
        result.binary_path = binary

        child_env = {name: source_env[name] for name in _BASE_CHILD_ENV if name in source_env}
        child_env["NO_COLOR"] = "1"
        cli_timeout = _positive_timeout(cfg.get("cli_timeout_seconds"))
        executable = None

        try:
            executable = _open_pinned_executable(binary, cfg, deadline)

            def run(args: list[str], env: dict[str, str]):
                return _run_pinned_bw(
                    executable,
                    args,
                    env=env,
                    cli_timeout=cli_timeout,
                    deadline=deadline,
                )

            with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-") as state_dir:
                child_env["BITWARDENCLI_APPDATA_DIR"] = state_dir
                version_proc = run(["--version"], child_env)
                if (version_proc.stdout or "").strip() != _BW_CLI_VERSION:
                    return result.fail(
                        f"Bitwarden CLI {_BW_CLI_VERSION} is required by this plugin release.",
                        ErrorKind.BINARY_MISSING,
                    )
                child_env.update({target: source_env[source] for target, source in credential_vars.items()})
                run(["config", "server", str(cfg["server_url"])], child_env)
                run(["login", "--apikey"], child_env)
                unlocked = run(
                    ["unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
                    child_env,
                )
                session = (unlocked.stdout or "").strip()
                if not session:
                    return result.fail("bw unlock returned an empty session key.", ErrorKind.AUTH_FAILED)
                child_env["BW_SESSION"] = session
                run(["sync"], child_env)

                items: dict[str, dict] = {}
                for item_id in sorted({binding.item_id for binding in bindings.values()}):
                    fetched = run(["get", "item", item_id], child_env)
                    _check_deadline(deadline)
                    try:
                        item = json.loads(fetched.stdout or "")
                    except json.JSONDecodeError:
                        return result.fail("bw get item returned invalid JSON.", ErrorKind.INTERNAL)
                    if not isinstance(item, dict) or item.get("id") != item_id:
                        return result.fail("bw get item returned an unexpected item.", ErrorKind.REF_INVALID)
                    collection_ids = item.get("collectionIds")
                    _check_deadline(deadline)
                    if not isinstance(collection_ids, list) or collection_id not in collection_ids:
                        return result.fail("An allowlisted item is outside the configured collection.",
                                           ErrorKind.REF_INVALID)
                    items[item_id] = item

                for env_name, binding in bindings.items():
                    _check_deadline(deadline)
                    value = _field_value(items[binding.item_id], binding.field, deadline)
                    if value is None:
                        return result.fail(f"Vaultwarden returned an empty or unsupported field for {env_name}.",
                                           ErrorKind.EMPTY_VALUE)
                    result.secrets[env_name] = value
                return result
        except _BwFailure as exc:
            return result.fail(str(exc), exc.kind)
        except RuntimeError:
            return result.fail("Vaultwarden fetch failed safely; diagnostic output was redacted.",
                               ErrorKind.INTERNAL)
        except Exception as exc:  # noqa: BLE001 - the SecretSource contract forbids propagation
            return result.fail(f"Vaultwarden fetch failed safely ({type(exc).__name__}).", ErrorKind.INTERNAL)
        finally:
            if executable is not None and not executable.close():
                result.secrets.clear()
                result.fail("Vaultwarden executable cleanup failed safely.", ErrorKind.INTERNAL)


def register_vaultwarden_cli(subparser: argparse.ArgumentParser) -> None:
    actions = subparser.add_subparsers(dest="vaultwarden_action", required=True)
    lookup = actions.add_parser("lookup", help="Find item UUIDs without printing secret values")
    lookup.add_argument("query", help="Item name search text")
    lookup.add_argument("--collection", default="", help="Collection name search text")
    actions.add_parser("status", help="Show safe configuration status")
    actions.add_parser("doctor", help="Validate configuration and prerequisites")
    actions.add_parser("config", help="Show safe hermes config set examples")


def _doctor(settings: dict) -> tuple[dict, int]:
    issues: list[str] = []
    bw_version = None
    deadline = time.monotonic() + _positive_timeout(settings.get("cli_timeout_seconds"))
    try:
        _bindings, error, _kind = _validate_config(settings, deadline)
        if error:
            issues.append(error.replace("secrets.vaultwarden", "plugin settings"))
    except _BwFailure as exc:
        issues.append(str(exc))

    source_env = get_source_environment()
    credential_names = [
        str(settings.get("client_id_env") or "BW_CLIENTID"),
        str(settings.get("client_secret_env") or "BW_CLIENTSECRET"),
        str(settings.get("master_password_env") or "BW_PASSWORD"),
    ]
    for name in credential_names:
        if not is_valid_env_name(name):
            issues.append("A bootstrap environment name is invalid.")
        elif not source_env.get(name, "").strip():
            issues.append(f"Bootstrap environment variable {name} is unavailable.")

    configured_binary = str(settings.get("binary_path") or "").strip()
    binary = Path(configured_binary)
    if not configured_binary or not binary.is_absolute():
        issues.append("plugin settings.binary_path must be an absolute file path.")
    elif not issues:
        executable = None
        try:
            executable = _open_pinned_executable(binary, settings, deadline)
            with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-doctor-") as state_dir:
                proc = _run_pinned_bw(
                    executable,
                    ["--version"],
                    env={"NO_COLOR": "1", "BITWARDENCLI_APPDATA_DIR": state_dir},
                    cli_timeout=_positive_timeout(settings.get("cli_timeout_seconds")),
                    deadline=deadline,
                )
            if (proc.stdout or "").strip() == _BW_CLI_VERSION:
                bw_version = _BW_CLI_VERSION
            else:
                issues.append(f"Bitwarden CLI {_BW_CLI_VERSION} is required.")
        except _BwFailure as exc:
            issues.append(str(exc))
        except Exception as exc:  # noqa: BLE001 - doctor must remain diagnostic
            issues.append(f"Local prerequisite check failed safely ({type(exc).__name__}).")
        finally:
            if executable is not None and not executable.close():
                issues.append("Vaultwarden executable cleanup failed safely.")

    report = {
        "ok": not issues,
        "issues": issues,
        "bw_version": bw_version,
        "remote_access_attempted": False,
    }
    return report, 0 if not issues else 1


def _safe_metadata_text(value: object, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value if character.isprintable())[:limit]


def _json_list(raw: str, label: str) -> list:
    try:
        payload = json.loads(raw or "")
    except json.JSONDecodeError as exc:
        raise _BwFailure(f"bw {label} returned invalid JSON.", ErrorKind.INTERNAL) from exc
    if not isinstance(payload, list):
        raise _BwFailure(f"bw {label} returned an unexpected result.", ErrorKind.INTERNAL)
    return payload


def _available_fields(item: dict) -> list[str]:
    fields: list[str] = []
    login = item.get("login")
    if isinstance(login, dict):
        for name in ("password", "username"):
            if isinstance(login.get(name), str) and login[name].strip():
                fields.append(f"login.{name}")
    if isinstance(item.get("notes"), str) and item["notes"].strip():
        fields.append("notes")
    custom_fields = item.get("fields")
    if isinstance(custom_fields, list):
        for candidate in custom_fields:
            if not isinstance(candidate, dict):
                continue
            name = _safe_metadata_text(candidate.get("name"))
            if name and isinstance(candidate.get("value"), str) and candidate["value"].strip():
                fields.append(f"fields.{name}")
    return sorted(set(fields))


def _lookup(settings: dict, query: str, collection_query: str) -> tuple[dict, int]:
    query = query.strip()
    collection_query = collection_query.strip()
    if not query:
        return {"ok": False, "error": "A non-empty item search query is required."}, 2
    server_url = settings.get("server_url")
    try:
        parsed_url = urlparse(server_url) if isinstance(server_url, str) else None
    except ValueError:
        parsed_url = None
    if (
        not parsed_url
        or parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.query
        or parsed_url.fragment
    ):
        return {"ok": False, "error": "Plugin server_url must be an HTTPS URL without credentials, query, or fragment."}, 1

    source_env = get_source_environment()
    credential_vars = {
        "BW_CLIENTID": str(settings.get("client_id_env") or "BW_CLIENTID"),
        "BW_CLIENTSECRET": str(settings.get("client_secret_env") or "BW_CLIENTSECRET"),
        "BW_PASSWORD": str(settings.get("master_password_env") or "BW_PASSWORD"),
    }
    if any(not is_valid_env_name(name) for name in credential_vars.values()):
        return {"ok": False, "error": "Bootstrap environment names are invalid."}, 1
    if any(not source_env.get(name, "").strip() for name in credential_vars.values()):
        return {"ok": False, "error": "Bootstrap credentials are unavailable."}, 1

    configured_binary = str(settings.get("binary_path") or "").strip()
    binary = Path(configured_binary)
    if not configured_binary or not binary.is_absolute():
        return {"ok": False, "error": "Plugin binary_path must be absolute."}, 1
    cli_timeout = _positive_timeout(settings.get("cli_timeout_seconds"))
    deadline = time.monotonic() + max(cli_timeout * 8, _MIN_FETCH_TIMEOUT_SECONDS)
    executable = None
    result: tuple[dict, int]
    try:
        executable = _open_pinned_executable(binary, settings, deadline)

        def run(command: list[str], env: dict[str, str]):
            return _run_pinned_bw(
                executable,
                command,
                env=env,
                cli_timeout=cli_timeout,
                deadline=deadline,
            )

        with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-lookup-") as state_dir:
            child_env = {name: source_env[name] for name in _BASE_CHILD_ENV if name in source_env}
            child_env.update({"NO_COLOR": "1", "BITWARDENCLI_APPDATA_DIR": state_dir})
            version = run(["--version"], child_env)
            if (version.stdout or "").strip() != _BW_CLI_VERSION:
                raise _BwFailure(f"Bitwarden CLI {_BW_CLI_VERSION} is required.", ErrorKind.BINARY_MISSING)
            child_env.update({target: source_env[source] for target, source in credential_vars.items()})
            run(["config", "server", str(server_url)], child_env)
            run(["login", "--apikey"], child_env)
            unlocked = run(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"], child_env)
            session = (unlocked.stdout or "").strip()
            if not session:
                raise _BwFailure("bw unlock returned an empty session key.", ErrorKind.AUTH_FAILED)
            child_env["BW_SESSION"] = session
            run(["sync"], child_env)

            collections = []
            collection_id = None
            if collection_query:
                raw_collections = _json_list(
                    run(["list", "collections", "--search", collection_query], child_env).stdout,
                    "list collections",
                )
                for candidate in raw_collections:
                    if not isinstance(candidate, dict):
                        continue
                    candidate_id = _canonical_uuid(candidate.get("id"))
                    if candidate_id:
                        collections.append({
                            "id": candidate_id,
                            "name": _safe_metadata_text(candidate.get("name")),
                        })
                if len(collections) != 1:
                    result = ({
                        "ok": False,
                        "error": "Collection search must resolve to exactly one UUID.",
                        "collections": collections,
                        "items": [],
                    }, 1)
                    return result
                collection_id = collections[0]["id"]

            command = ["list", "items", "--search", query]
            if collection_id:
                command.extend(["--collectionid", collection_id])
            raw_items = _json_list(run(command, child_env).stdout, "list items")
            items = []
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                item_id = _canonical_uuid(item.get("id"))
                if item_id is None:
                    continue
                collection_ids = [
                    canonical
                    for raw_id in item.get("collectionIds", [])
                    if (canonical := _canonical_uuid(raw_id)) is not None
                ] if isinstance(item.get("collectionIds"), list) else []
                items.append({
                    "id": item_id,
                    "name": _safe_metadata_text(item.get("name")),
                    "type": item.get("type") if isinstance(item.get("type"), int) else None,
                    "collection_ids": collection_ids,
                    "available_fields": _available_fields(item),
                })
            result = ({"ok": True, "collections": collections, "items": items}, 0)
    except _BwFailure as exc:
        result = ({"ok": False, "error": str(exc), "error_kind": exc.kind.value}, 1)
    except Exception as exc:  # noqa: BLE001 - CLI diagnostics must never expose raw output
        result = ({"ok": False, "error": f"Lookup failed safely ({type(exc).__name__})."}, 1)
    finally:
        if executable is not None and not executable.close():
            result = ({"ok": False, "error": "Vaultwarden executable cleanup failed safely."}, 1)
    return result


def vaultwarden_command(args: argparse.Namespace, settings: dict) -> int:
    action = getattr(args, "vaultwarden_action", "")
    if action == "status":
        source_env = get_source_environment()
        bootstrap_names = [
            str(settings.get("client_id_env") or "BW_CLIENTID"),
            str(settings.get("client_secret_env") or "BW_CLIENTSECRET"),
            str(settings.get("master_password_env") or "BW_PASSWORD"),
        ]
        raw_bindings = settings.get("env")
        bindings = {}
        if isinstance(raw_bindings, dict):
            for env_name, raw_binding in raw_bindings.items():
                if not isinstance(env_name, str) or not is_valid_env_name(env_name):
                    continue
                if not isinstance(raw_binding, dict):
                    continue
                item_id = _canonical_uuid(raw_binding.get("item_id"))
                field = raw_binding.get("field")
                if item_id is None or not isinstance(field, str):
                    continue
                field = field.strip()
                if field not in {"login.username", "login.password", "notes"} and not (
                    field.startswith("fields.") and field != "fields."
                ):
                    continue
                bindings[env_name] = {"item_id": item_id, "field": field}
        collection_id = _canonical_uuid(settings.get("collection_id"))
        raw_allowed_item_ids = settings.get("allowed_item_ids")
        allowed_item_ids = []
        if isinstance(raw_allowed_item_ids, list):
            allowed_item_ids = sorted({
                item_id
                for raw_item_id in raw_allowed_item_ids
                if (item_id := _canonical_uuid(raw_item_id)) is not None
            })
        print(json.dumps({
            "enabled": settings.get("enabled") is True,
            "server_url_configured": bool(str(settings.get("server_url") or "").strip()),
            "collection_id": collection_id,
            "allowed_item_ids": allowed_item_ids,
            "bindings": bindings,
            "bootstrap_environment": {
                name: bool(source_env.get(name, "").strip())
                for name in bootstrap_names if is_valid_env_name(name)
            },
            "binary_path_configured": bool(str(settings.get("binary_path") or "").strip()),
            "binary_sha256_configured": bool(settings.get("binary_sha256")),
        }, indent=2, sort_keys=True))
        return 0
    if action == "config":
        prefix = "plugins.entries.hermes-vaultwarden.settings"
        item_id = "00000000-0000-4000-8000-000000000002"
        print("Configure non-secret settings with Hermes' supported config writer:")
        print(f"hermes config set {prefix}.server_url https://vault.example.invalid")
        print(f"hermes config set {prefix}.collection_id 00000000-0000-4000-8000-000000000001")
        print(f"hermes config set {prefix}.allowed_item_ids '[\"{item_id}\"]'")
        print(
            f"hermes config set {prefix}.env "
            f"'{{\"SYNTHETIC_API_KEY\":{{\"item_id\":\"{item_id}\","
            "\"field\":\"login.password\"}}'"
        )
        print(f"hermes config set {prefix}.binary_path /opt/example/bin/bw")
        print(f"hermes config set {prefix}.binary_sha256 '<64-lowercase-hex-characters>'")
        print(f"hermes config set {prefix}.enabled true")
        print("hermes config set secrets.sources '[\"vaultwarden\"]'")
        print("hermes config set secrets.vaultwarden.enabled true")
        print("Bootstrap credential values do not belong in config.yaml.")
        return 0
    if action == "doctor":
        report, exit_code = _doctor(settings)
        print(json.dumps(report, indent=2, sort_keys=True))
        return exit_code
    if action == "lookup":
        report, exit_code = _lookup(
            settings,
            str(getattr(args, "query", "") or ""),
            str(getattr(args, "collection", "") or ""),
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return exit_code
    return 2


def register(ctx) -> None:
    """Register the source without import-time side effects."""

    settings = {
        key: ctx.get_config(key, default)
        for key, default in _PLUGIN_SETTING_DEFAULTS.items()
    }
    ctx.register_secret_source(VaultwardenSource(settings))
    ctx.register_cli_command(
        name="vaultwarden",
        help="Inspect and configure the Hermes Vaultwarden secret source",
        setup_fn=register_vaultwarden_cli,
        handler_fn=lambda args: vaultwarden_command(args, settings),
        description="Safe UUID lookup, status, doctor, and configuration help.",
    )
    try:
        from vaultwarden_secret_source.browser_fill import (
            VAULTWARDEN_BROWSER_FILL_SCHEMA,
            check_vaultwarden_browser_fill,
            handle_vaultwarden_browser_fill,
        )
        ctx.register_tool(
            name="vaultwarden_browser_fill",
            toolset="hermes-vaultwarden",
            schema=VAULTWARDEN_BROWSER_FILL_SCHEMA,
            handler=lambda args, **kw: handle_vaultwarden_browser_fill(args, settings, **kw),
            check_fn=lambda: check_vaultwarden_browser_fill(settings),
            emoji="\U0001f510",
        )
    except Exception:  # noqa: BLE001 - a broken optional tool must never break plugin load
        pass
    register_skill = getattr(ctx, "register_skill", None)
    if callable(register_skill):
        skill_path = Path(__file__).parent / "skills" / "vaultwarden-secrets"
        try:
            register_skill("vaultwarden-secrets", skill_path)
        except Exception:  # noqa: BLE001 - skill bundling must never break plugin load
            pass
