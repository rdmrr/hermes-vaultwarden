"""``vaultwarden_browser_fill`` tool: types a Vaultwarden field value directly into a
browser input via CDP, without the value ever passing through the tool's return value.

Architecture (binding contract from VW-018/VW-019, see
``nexi-brain/04 - Home/Hermes-Vaultwarden Secret Source.md``):

1. The value flows ONLY server-side inside this plugin process: fetched from Vaultwarden
   via the existing pinned ``bw`` CLI mechanism, then written straight into the page via
   ``Input.insertText`` over a CDP WebSocket this module opens itself. It is never packed
   into a Python value that becomes the tool's return string (which the agent loop would
   read into the LLM conversation context and which could later be persisted verbatim by
   ``dump_api_request_debug()`` on a provider error — ``redact_sensitive_text`` is
   pattern-based and does not reliably catch an arbitrary Vaultwarden secret).
2. The tool's return value is a status object only: ``{"success", "field",
   "chars_written"}`` (or ``{"error": ..., "error_kind": ...}``) — never the value, not
   even partially masked.
3. Every error path formats only ``type(exc).__name__`` plus, for CDP protocol errors, the
   numeric CDP error code — never a raw exception message that could (even accidentally)
   carry the fetched value. This module must never let an exception escape unhandled: the
   registry's own dispatch loop formats ``str(exc)`` into its own generic error text on any
   *uncaught* exception, which would defeat the guarantee above.
4. Item access reuses the exact same UUID-allowlist + collection-membership boundary as
   ``VaultwardenSource.fetch()`` — no free-form item name lookup at this layer.
5. Cross-origin guard: if the target Vaultwarden item has one or more configured Bitwarden
   ``login.uris``, the current page's hostname must match at least one of them before any
   value is written — a manipulated prompt cannot walk the agent into typing a credential
   into an unrelated site's form. Items with no configured URIs skip this check (reported
   as such in the success/failure metadata) since Vaultwarden itself gives us nothing to
   compare against; operators who want a hard guarantee should set ``login.uris`` on the
   item, which is a normal Vaultwarden/Bitwarden feature, not a plugin-specific extension.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from agent.secret_sources.base import ErrorKind, get_source_environment, is_valid_env_name

from vaultwarden_secret_source import (
    _BASE_CHILD_ENV,
    _BW_CLI_VERSION,
    _BwFailure,
    _canonical_uuid,
    _field_value,
    _open_pinned_executable,
    _positive_timeout,
    _run_pinned_bw,
)

_MIN_FILL_TIMEOUT_SECONDS = 3.0
_DEFAULT_FILL_TIMEOUT_SECONDS = 30.0
_MAX_SELECTOR_LENGTH = 500

# No secret is ever embedded in this string — it only clears whatever text a controlled
# (e.g. React) input currently holds, using the framework-visible native setter so the
# framework's own state stays in sync, then fires input/change so listeners re-render.
_CLEAR_VALUE_JS = """
function() {
  const proto = Object.getPrototypeOf(this);
  const desc = (proto && Object.getOwnPropertyDescriptor(proto, 'value'))
    || Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')
    || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
  if (desc && desc.set) { desc.set.call(this, ''); } else { this.value = ''; }
  this.dispatchEvent(new Event('input', {bubbles: true}));
  this.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}
"""

try:
    import websockets

    _WS_AVAILABLE = True
except ImportError:  # pragma: no cover — defensive
    websockets = None  # type: ignore[assignment]
    _WS_AVAILABLE = False


class _FillFailure(RuntimeError):
    """Internal-only failure. ``message`` MUST NEVER contain the fetched secret value —
    every raise site in this module is reviewed for that; do not add a new one that embeds
    exception text sourced from a CDP payload without checking it can't carry the value."""

    def __init__(self, message: str, *, cdp_error_code: Optional[int] = None):
        super().__init__(message)
        self.cdp_error_code = cdp_error_code


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        import contextvars

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(contextvars.copy_context().run, asyncio.run, coro).result()
    return asyncio.run(coro)


def _resolve_cdp_endpoint() -> str:
    """Same precedence as the built-in ``browser_cdp`` tool (``BROWSER_CDP_URL`` env, then
    ``browser.cdp_url``), reimplemented here rather than imported from ``tools.browser_*``
    per the VW-018 decision to keep this plugin free of a hard dependency on Hermes' internal
    browser-tool modules — only the documented config read is used."""
    import os

    raw = os.environ.get("BROWSER_CDP_URL", "").strip()
    if not raw:
        try:
            from hermes_cli.config import load_config_readonly

            cfg = load_config_readonly() or {}
            browser_cfg = cfg.get("browser") if isinstance(cfg.get("browser"), dict) else {}
            raw = str(browser_cfg.get("cdp_url", "") or "").strip()
        except Exception:  # noqa: BLE001 - config read must never break the tool
            raw = ""
    if not raw:
        return ""
    if "/devtools/browser/" in raw.lower():
        return raw
    lowered = raw.lower()
    discovery_url = raw
    if lowered.startswith(("ws://", "wss://")):
        discovery_url = ("http://" if lowered.startswith("ws://") else "https://") + raw.split("://", 1)[1]
    version_url = discovery_url if discovery_url.lower().endswith("/json/version") else discovery_url.rstrip("/") + "/json/version"
    try:
        import requests

        from agent.proxy_bypass import loopback_request_kwargs

        response = requests.get(version_url, timeout=10, **loopback_request_kwargs(version_url))
        response.raise_for_status()
        payload = response.json()
    except Exception:  # noqa: BLE001 - fall back to the raw endpoint, same as browser_tool_cdp
        return raw
    ws_url = str(payload.get("webSocketDebuggerUrl") or "").strip()
    return ws_url or raw


def _cdp_endpoint_configured_raw() -> bool:
    """Non-network availability probe for ``check_fn`` (no HTTP discovery)."""
    import os

    if os.environ.get("BROWSER_CDP_URL", "").strip():
        return True
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly() or {}
        browser_cfg = cfg.get("browser") if isinstance(cfg.get("browser"), dict) else {}
        return bool(str(browser_cfg.get("cdp_url", "") or "").strip())
    except Exception:  # noqa: BLE001
        return False


def _origin_allowed(current_url: str, uris: List[str]) -> Tuple[bool, str]:
    if not uris:
        return True, "skipped_no_uris_on_item"
    try:
        current_host = urlparse(current_url).hostname
    except ValueError:
        current_host = None
    if not current_host:
        return False, "current_page_url_could_not_be_parsed"
    for uri in uris:
        candidate = uri if "://" in uri else f"https://{uri}"
        try:
            item_host = urlparse(candidate).hostname
        except ValueError:
            item_host = None
        if item_host and item_host.lower() == current_host.lower():
            return True, "matched"
    return False, "no_configured_login_uri_matched_the_current_page"


def _fetch_single_field(
    cfg: Dict[str, Any], item_id: str, field: str, deadline: float,
) -> Tuple[Optional[str], List[str], Optional[str], Optional[ErrorKind]]:
    """Fetch exactly one allowlisted item's field, server-side. Returns
    ``(value, login_uris, error_message, error_kind)`` — ``value`` is ``None`` on any
    failure and the caller must not proceed to CDP in that case."""
    canonical_item_id = _canonical_uuid(item_id)
    if canonical_item_id is None:
        return None, [], "item_id must be a canonical UUID.", ErrorKind.REF_INVALID

    raw_allowlist = cfg.get("allowed_item_ids")
    allowlist = {c for raw in (raw_allowlist or []) if (c := _canonical_uuid(raw)) is not None}
    if canonical_item_id not in allowlist:
        return None, [], "item_id is outside the configured allowlist.", ErrorKind.REF_INVALID

    if field not in {"login.username", "login.password", "notes"} and not (
        field.startswith("fields.") and field != "fields."
    ):
        return None, [], "field is unsupported.", ErrorKind.REF_INVALID

    collection_id = _canonical_uuid(cfg.get("collection_id"))
    if collection_id is None:
        return None, [], "collection_id must be a UUID.", ErrorKind.NOT_CONFIGURED

    server_url = cfg.get("server_url")
    try:
        parsed_url = urlparse(server_url) if isinstance(server_url, str) else None
    except ValueError:
        parsed_url = None
    if (
        not parsed_url or parsed_url.scheme != "https" or not parsed_url.hostname
        or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment
    ):
        return None, [], "server_url must be an HTTPS URL without credentials, query, or fragment.", ErrorKind.NOT_CONFIGURED

    binary_sha256 = cfg.get("binary_sha256")
    if not isinstance(binary_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", binary_sha256):
        return None, [], "binary_sha256 must be a lowercase SHA-256 digest.", ErrorKind.NOT_CONFIGURED

    source_env = get_source_environment()
    credential_vars = {
        "BW_CLIENTID": str(cfg.get("client_id_env") or "BW_CLIENTID"),
        "BW_CLIENTSECRET": str(cfg.get("client_secret_env") or "BW_CLIENTSECRET"),
        "BW_PASSWORD": str(cfg.get("master_password_env") or "BW_PASSWORD"),
    }
    if any(not is_valid_env_name(name) for name in credential_vars.values()):
        return None, [], "Vaultwarden bootstrap environment names are invalid.", ErrorKind.REF_INVALID
    missing = [target for target, source in credential_vars.items() if not source_env.get(source, "").strip()]
    if missing:
        return None, [], "Vaultwarden bootstrap credentials are not available in the source environment.", ErrorKind.NOT_CONFIGURED

    configured_binary = str(cfg.get("binary_path") or "").strip()
    binary = Path(configured_binary)
    if not configured_binary or not binary.is_absolute():
        return None, [], "binary_path must be an absolute file path.", ErrorKind.BINARY_MISSING

    child_env = {name: source_env[name] for name in _BASE_CHILD_ENV if name in source_env}
    child_env["NO_COLOR"] = "1"
    cli_timeout = _positive_timeout(cfg.get("cli_timeout_seconds"))
    executable = None
    try:
        executable = _open_pinned_executable(binary, cfg, deadline)

        def run(args: List[str], env: Dict[str, str]):
            return _run_pinned_bw(executable, args, env=env, cli_timeout=cli_timeout, deadline=deadline)

        with tempfile.TemporaryDirectory(prefix="hermes-vaultwarden-fill-") as state_dir:
            child_env["BITWARDENCLI_APPDATA_DIR"] = state_dir
            version_proc = run(["--version"], child_env)
            if (version_proc.stdout or "").strip() != _BW_CLI_VERSION:
                return None, [], f"Bitwarden CLI {_BW_CLI_VERSION} is required by this plugin release.", ErrorKind.BINARY_MISSING
            child_env.update({target: source_env[source] for target, source in credential_vars.items()})
            run(["config", "server", str(cfg["server_url"])], child_env)
            run(["login", "--apikey"], child_env)
            unlocked = run(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"], child_env)
            session = (unlocked.stdout or "").strip()
            if not session:
                return None, [], "bw unlock returned an empty session key.", ErrorKind.AUTH_FAILED
            child_env["BW_SESSION"] = session
            run(["sync"], child_env)

            fetched = run(["get", "item", canonical_item_id], child_env)
            try:
                item = json.loads(fetched.stdout or "")
            except json.JSONDecodeError:
                return None, [], "bw get item returned invalid JSON.", ErrorKind.INTERNAL
            if not isinstance(item, dict) or item.get("id") != canonical_item_id:
                return None, [], "bw get item returned an unexpected item.", ErrorKind.REF_INVALID
            collection_ids = item.get("collectionIds")
            if not isinstance(collection_ids, list) or collection_id not in collection_ids:
                return None, [], "The allowlisted item is outside the configured collection.", ErrorKind.REF_INVALID

            value = _field_value(item, field, deadline)
            if value is None:
                return None, [], "Vaultwarden returned an empty or unsupported field.", ErrorKind.EMPTY_VALUE

            uris: List[str] = []
            login = item.get("login")
            if isinstance(login, dict) and isinstance(login.get("uris"), list):
                for entry in login["uris"]:
                    if isinstance(entry, dict) and isinstance(entry.get("uri"), str) and entry["uri"].strip():
                        uris.append(entry["uri"].strip())
            return value, uris, None, None
    except _BwFailure as exc:
        return None, [], str(exc), exc.kind
    except Exception as exc:  # noqa: BLE001 - contract forbids raw propagation
        return None, [], f"Vaultwarden fetch failed safely ({type(exc).__name__}).", ErrorKind.INTERNAL
    finally:
        if executable is not None and not executable.close():
            return None, [], "Vaultwarden executable cleanup failed safely.", ErrorKind.INTERNAL


def _status(success: bool, **fields: Any) -> str:
    payload = {"success": success, **fields}
    return json.dumps(payload, ensure_ascii=False)


def _validate_args(args: Dict[str, Any]) -> Optional[Tuple[str, str, str, str, bool]]:
    """Returns ``(item_id, field, selector, target_id, clear_first)`` when all required
    arguments are present and well-formed, else ``None`` (caller renders a status-only
    validation error)."""
    item_id = args.get("item_id")
    field = args.get("field")
    selector = args.get("selector")
    target_id = args.get("target_id")
    clear_first = args.get("clear_first", True)
    if not isinstance(item_id, str) or not item_id.strip():
        return None
    if not isinstance(field, str) or not field.strip():
        return None
    if not isinstance(selector, str) or not selector.strip() or len(selector) > _MAX_SELECTOR_LENGTH:
        return None
    if not isinstance(target_id, str) or not target_id.strip():
        return None
    return item_id.strip(), field.strip(), selector, target_id.strip(), bool(clear_first)


def handle_vaultwarden_browser_fill(args: Dict[str, Any], settings: Dict[str, Any], **_kwargs: Any) -> str:
    """Tool handler. Never raises — every path returns a status-only JSON string, and no
    branch may format the fetched value into that string or into any exception message."""
    try:
        parsed = _validate_args(args or {})
        if parsed is None:
            return _status(False, error="item_id, field, selector, and target_id are required non-empty strings.",
                           error_kind=ErrorKind.REF_INVALID.value)
        item_id, field, selector, target_id, clear_first = parsed

        if not _WS_AVAILABLE:
            return _status(False, error="The 'websockets' Python package is required but not installed.",
                           error_kind=ErrorKind.BINARY_MISSING.value)

        endpoint = _resolve_cdp_endpoint()
        if not endpoint:
            return _status(False, error=("No CDP endpoint is available. Run '/browser connect' to attach to a "
                                          "running Chromium-family browser, or set 'browser.cdp_url' in config.yaml."),
                           error_kind=ErrorKind.NOT_CONFIGURED.value)
        if not endpoint.startswith(("ws://", "wss://")):
            return _status(False, error="Resolved CDP endpoint is not a WebSocket URL.",
                           error_kind=ErrorKind.INTERNAL.value)

        cli_timeout = _positive_timeout(settings.get("cli_timeout_seconds"))
        deadline = time.monotonic() + max(cli_timeout * 8, _MIN_FILL_TIMEOUT_SECONDS)

        value, uris, error, kind = _fetch_single_field(settings, item_id, field, deadline)
        if value is None:
            return _status(False, error=error or "Vaultwarden fetch failed.",
                           error_kind=(kind or ErrorKind.INTERNAL).value)

        fill_timeout = max(cli_timeout, _DEFAULT_FILL_TIMEOUT_SECONDS)
        chars_written = len(value)
        try:
            _current_url, origin_ok, origin_reason = _run_fill_with_origin_guard(
                endpoint, target_id, selector, value, clear_first, fill_timeout, uris,
            )
        except _FillFailure as exc:
            detail: Dict[str, Any] = {"error": f"CDP fill failed ({type(exc).__name__})."}
            if exc.cdp_error_code is not None:
                detail["cdp_error_code"] = exc.cdp_error_code
            return _status(False, **detail)
        finally:
            value = None  # noqa: F841 - drop the local reference to the secret as soon as possible

        if not origin_ok:
            return _status(False, error="Refused: current page origin does not match any configured login URI for this item.",
                           uri_check=origin_reason)

        return _status(True, field=field, chars_written=chars_written, uri_check=origin_reason)
    except Exception as exc:  # noqa: BLE001 - last-resort net; must never surface exception text
        return _status(False, error=f"Unexpected error: {type(exc).__name__}")


def _run_fill_with_origin_guard(
    endpoint: str, target_id: str, selector: str, value: str, clear_first: bool, timeout: float,
    uris: List[str],
) -> Tuple[str, bool, str]:
    """Runs the CDP session once: reads the live page URL, checks it against ``uris`` BEFORE
    writing anything, and only then performs the fill. Raises ``_FillFailure`` on any CDP
    problem (never containing ``value``)."""

    async def _flow() -> Tuple[str, bool, str]:
        from agent.proxy_bypass import loopback_connect_kwargs

        assert websockets is not None
        async with websockets.connect(endpoint, max_size=None, open_timeout=timeout, close_timeout=5,
                                      ping_interval=None, **loopback_connect_kwargs(endpoint)) as ws:
            next_id = 1
            session_id: Optional[str] = None

            async def send(method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
                nonlocal next_id
                call_id, next_id = next_id, next_id + 1
                req: Dict[str, Any] = {"id": call_id, "method": method, "params": params or {}}
                if session_id:
                    req["sessionId"] = session_id
                await ws.send(json.dumps(req))
                deadline = asyncio.get_running_loop().time() + timeout
                while True:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise _FillFailure(f"Timed out waiting for {method}")
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=remaining))
                    if msg.get("id") == call_id:
                        if "error" in msg:
                            raise _FillFailure(f"CDP error during {method}",
                                               cdp_error_code=(msg["error"] or {}).get("code"))
                        return msg.get("result", {})

            attach = await send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
            session_id = attach.get("sessionId")
            if not session_id:
                raise _FillFailure("Target.attachToTarget did not return a sessionId")

            loc = await send("Runtime.evaluate", {"expression": "location.href", "returnByValue": True})
            current_url = str(((loc.get("result") or {}).get("value")) or "")

            origin_ok, origin_reason = _origin_allowed(current_url, uris)
            if not origin_ok:
                return current_url, False, origin_reason

            doc = await send("DOM.getDocument", {"depth": 0})
            root_node_id = (doc.get("root") or {}).get("nodeId")
            if not root_node_id:
                raise _FillFailure("DOM.getDocument did not return a root node")

            query = await send("DOM.querySelector", {"nodeId": root_node_id, "selector": selector})
            node_id = query.get("nodeId")
            if not node_id:
                raise _FillFailure("selector did not match any element")

            if clear_first:
                resolved = await send("DOM.resolveNode", {"nodeId": node_id})
                object_id = (resolved.get("object") or {}).get("objectId")
                if object_id:
                    await send("Runtime.callFunctionOn", {
                        "objectId": object_id, "functionDeclaration": _CLEAR_VALUE_JS,
                        "returnByValue": True,
                    })

            await send("DOM.focus", {"nodeId": node_id})
            await send("Input.insertText", {"text": value})
            return current_url, True, origin_reason

    return _run_async(_flow())


VAULTWARDEN_BROWSER_FILL_SCHEMA: Dict[str, Any] = {
    "name": "vaultwarden_browser_fill",
    "description": (
        "Type a Vaultwarden item's field value directly into a browser input over CDP. "
        "The value NEVER appears in this tool's result or in any error message — only a "
        "status object ({\"success\", \"field\", \"chars_written\"}) is returned. Use this "
        "instead of fetching a Vaultwarden value into the conversation and typing it "
        "yourself.\n\n"
        "Requires: (1) a reachable CDP endpoint ('/browser connect' or 'browser.cdp_url' in "
        "config.yaml — same requirement as the built-in browser_cdp tool), (2) 'item_id' in "
        "the plugin's 'allowed_item_ids' allowlist and inside the configured "
        "'collection_id', (3) if the item has Bitwarden login URIs configured, the current "
        "page's hostname must match one of them — otherwise the fill is refused before "
        "anything is written."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string", "description": "Exact Vaultwarden item UUID (must be in allowed_item_ids)."},
            "field": {"type": "string", "description": "'login.username' | 'login.password' | 'notes' | 'fields.<name>'."},
            "selector": {"type": "string", "description": "CSS selector of the target <input>/<textarea>, as passed to fill_input."},
            "target_id": {"type": "string", "description": "CDP target/tab id from Target.getTargets (browser_snapshot exposes it too)."},
            "clear_first": {"type": "boolean", "default": True, "description": "Clear the field before writing (default true)."},
        },
        "required": ["item_id", "field", "selector", "target_id"],
    },
}


def check_vaultwarden_browser_fill(settings: Dict[str, Any]) -> bool:
    """Availability gate: no network I/O (matches browser_cdp's own check_fn contract)."""
    return bool(_WS_AVAILABLE and settings.get("enabled") is True and _cdp_endpoint_configured_raw())
