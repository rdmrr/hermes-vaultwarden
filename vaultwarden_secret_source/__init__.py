"""Vaultwarden-backed Hermes secret source."""

from __future__ import annotations

import fcntl
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
_F_ADD_SEALS = 1033
_F_SEAL_ALL = 0x000F


@dataclass(frozen=True)
class _Binding:
    item_id: str
    field: str


@dataclass
class _PinnedExecutable:
    binary_path: Path
    binary_fd: int
    binary_sha256: str
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

    def close(self) -> None:
        for fd in (self.binary_fd, self.interpreter_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


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


def _open_verified_fd(path: Path, expected_sha256: str, label: str, deadline: float) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    source_fd = None
    pinned_fd = None
    try:
        source_fd = os.open(path, flags)
        file_stat = os.fstat(source_fd)
        if not stat.S_ISREG(file_stat.st_mode) or not file_stat.st_mode & 0o111:
            raise OSError("not an executable regular file")
        if file_stat.st_size > _MAX_EXECUTABLE_BYTES:
            raise _BwFailure(f"The pinned {label} exceeds the executable size limit.", ErrorKind.BINARY_MISSING)
        pinned_fd = os.memfd_create(
            "hermes-vaultwarden-executable",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
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
                written += os.write(pinned_fd, chunk[written:])
            offset += len(chunk)
            if offset > _MAX_EXECUTABLE_BYTES:
                raise _BwFailure(f"The pinned {label} exceeds the executable size limit.", ErrorKind.BINARY_MISSING)
        os.fchmod(pinned_fd, 0o500)
        fcntl.fcntl(pinned_fd, _F_ADD_SEALS, _F_SEAL_ALL)
        _verify_fd(pinned_fd, expected_sha256, label, deadline)
        return pinned_fd
    except _BwFailure:
        if pinned_fd is not None:
            os.close(pinned_fd)
        raise
    except OSError as exc:
        if pinned_fd is not None:
            os.close(pinned_fd)
        raise _BwFailure(f"The pinned {label} could not be opened safely.", ErrorKind.BINARY_MISSING) from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)


def _open_pinned_executable(binary: Path, cfg: dict, deadline: float) -> _PinnedExecutable:
    binary_sha256 = str(cfg["binary_sha256"])
    binary_fd = _open_verified_fd(binary, binary_sha256, "bw executable", deadline)
    try:
        header = os.pread(binary_fd, 512, 0)
        if header.startswith(b"\x7fELF"):
            return _PinnedExecutable(binary, binary_fd, binary_sha256)
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
        interpreter_fd = _open_verified_fd(
            interpreter_path,
            interpreter_sha256,
            "bw script interpreter",
            deadline,
        )
        if not os.pread(interpreter_fd, 4, 0).startswith(b"\x7fELF"):
            os.close(interpreter_fd)
            raise _BwFailure("The pinned bw script interpreter must be a native executable.", ErrorKind.BINARY_MISSING)
        return _PinnedExecutable(
            binary,
            binary_fd,
            binary_sha256,
            interpreter_path,
            interpreter_fd,
            interpreter_sha256,
        )
    except Exception:
        os.close(binary_fd)
        raise


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

    def is_enabled(self, cfg: dict) -> bool:
        return isinstance(cfg, dict) and cfg.get("enabled") is True

    def override_existing(self, cfg: dict) -> bool:
        if not isinstance(cfg, dict):
            return False
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
        cfg = cfg if isinstance(cfg, dict) else {}
        protected = {"BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"}
        configured = {
            str(cfg.get("client_id_env") or ""),
            str(cfg.get("client_secret_env") or ""),
            str(cfg.get("master_password_env") or ""),
        }
        protected.update(name for name in configured if is_valid_env_name(name))
        return frozenset(protected)

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        configured = _positive_timeout(
            (cfg or {}).get("timeout_seconds") if isinstance(cfg, dict) else None,
            _DEFAULT_FETCH_TIMEOUT_SECONDS,
        )
        return max(configured, _MIN_FETCH_TIMEOUT_SECONDS)

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
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

            version_proc = run(["--version"], child_env)
            if (version_proc.stdout or "").strip() != _BW_CLI_VERSION:
                return result.fail(
                    f"Bitwarden CLI {_BW_CLI_VERSION} is required by this plugin release.",
                    ErrorKind.BINARY_MISSING,
                )
            child_env.update({target: source_env[source] for target, source in credential_vars.items()})
            with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-") as state_dir:
                child_env["BITWARDENCLI_APPDATA_DIR"] = state_dir
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
            if executable is not None:
                executable.close()


def register(ctx) -> None:
    """Register the source without import-time side effects."""

    ctx.register_secret_source(VaultwardenSource())
