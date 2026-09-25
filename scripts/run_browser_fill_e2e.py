"""VW-020 real end-to-end verification for ``vaultwarden_browser_fill``.

Runs entirely against real, locally-controlled infrastructure — no mocks of the code
under test:

- a real headless Chromium instance with a real CDP debug port,
- a real local HTTP server serving an actual HTML login form,
- a real (synthetic) fake ``bw`` executable, pinned exactly like ``VaultwardenSource``
  pins the real Bitwarden CLI (SHA-256 digest, script + interpreter digests, executed
  through the same ``/proc/self/fd`` mechanism as production),
- the actual ``handle_vaultwarden_browser_fill`` handler from this repository, called the
  same way the plugin loader would call it.

Verifies, against real observed values (not assumptions):
1. Happy path: the synthetic test secret ends up in the page's DOM input value, the tool
   return string contains no fragment of the secret, and the return status matches
   ``{"success": true, "field": ..., "chars_written": len(secret)}``.
2. Leak test (VW-019 mandatory acceptance criterion): forces a CDP-level failure (a
   selector that matches nothing) and verifies the synthetic secret appears NOWHERE in the
   tool's return string.
3. Cross-origin guard: an item configured with a login URI for a different host is refused
   before anything is written to the page, and the field remains empty.

Requires: chromium(-browser) and the pinned ``bw`` mechanism's Python interpreter on PATH.
Prints a JSON report and exits non-zero on any check failure.
"""
from __future__ import annotations

import contextlib
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ITEM_ID = "11111111-1111-4111-8111-111111111111"
OTHER_HOST_ITEM_ID = "22222222-2222-4222-8222-222222222222"
COLLECTION_ID = "33333333-3333-4333-8333-333333333333"
SECRET_VALUE = "Sup3r$ecret-VW020-Synthetic-Marker-9f81"

LOGIN_PAGE = """<!doctype html>
<html><body>
<form>
  <input id="password" type="password" name="password" value="" />
</form>
</body></html>
"""


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fake_bw(path: Path, mode_path: Path) -> None:
    path.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, sys, pathlib\n"
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
        "    raise SystemExit(0)\n"
        "if args[:2] == ['unlock', '--passwordenv']:\n"
        "    print('synthetic-session')\n"
        "    raise SystemExit(0)\n"
        "if args[0] == 'sync':\n"
        "    raise SystemExit(0)\n"
        "if args[:2] == ['get', 'item']:\n"
        "    item_id = args[2]\n"
        f"    secret = {SECRET_VALUE!r}\n"
        f"    if item_id == {ITEM_ID!r}:\n"
        "        print(json.dumps({'id': item_id, "
        f"'collectionIds': ['{COLLECTION_ID}'], "
        "'login': {'password': secret, 'uris': []}}))\n"
        f"    elif item_id == {OTHER_HOST_ITEM_ID!r}:\n"
        "        print(json.dumps({'id': item_id, "
        f"'collectionIds': ['{COLLECTION_ID}'], "
        "'login': {'password': secret, "
        "'uris': [{'uri': 'https://not-this-host.example.invalid'}]}}))\n"
        "    else:\n"
        "        raise SystemExit(1)\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _LoginPageHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib method name
        body = LOGIN_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@contextlib.contextmanager
def _http_server():
    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _LoginPageHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@contextlib.contextmanager
def _chromium(profile_dir: str):
    external_port = os.environ.get("VW020_EXTERNAL_CDP_PORT", "").strip()
    if external_port:
        import requests

        port = int(external_port)
        response = requests.get(f"http://127.0.0.1:{port}/json/version", timeout=3)
        response.raise_for_status()
        yield port
        return

    port = _free_port()
    binary = None
    for candidate in ("chromium-browser", "chromium", "google-chrome", "google-chrome-stable"):
        from shutil import which

        if which(candidate):
            binary = candidate
            break
    if binary is None:
        raise RuntimeError("no Chromium-family browser found on PATH")
    proc = subprocess.Popen(
        [binary, "--headless=new", f"--remote-debugging-port={port}", "--no-sandbox",
         f"--user-data-dir={profile_dir}", "about:blank"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        import requests

        deadline = time.monotonic() + 30
        version = None
        while time.monotonic() < deadline:
            try:
                response = requests.get(f"http://127.0.0.1:{port}/json/version", timeout=1)
                response.raise_for_status()
                version = response.json()
                break
            except Exception:
                time.sleep(0.3)
        if version is None:
            returncode = proc.poll()
            tail = ""
            if returncode is not None:
                try:
                    tail = proc.stdout.read().decode("utf-8", errors="replace")[-2000:] if proc.stdout else ""
                except Exception:
                    tail = ""
            raise RuntimeError(f"Chromium did not expose a CDP endpoint in time (binary={binary}, "
                               f"returncode={returncode}, tail={tail!r})")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _new_target(port: int, url: str) -> str:
    import requests

    response = requests.put(f"http://127.0.0.1:{port}/json/new?{url}", timeout=5)
    response.raise_for_status()
    return response.json()["id"]


def _close_target(port: int, target_id: str) -> None:
    import requests

    try:
        requests.get(f"http://127.0.0.1:{port}/json/close/{target_id}", timeout=5)
    except Exception:
        pass


def _read_input_value(port: int, target_id: str, page_url: str) -> str:
    """Reads the live DOM value via a *fresh* page navigation + eval — independent of the
    module under test, so this is a real external observation, not a self-check."""
    import asyncio

    import websockets

    async def _read() -> str:
        async with websockets.connect(f"ws://127.0.0.1:{port}/devtools/page/{target_id}", max_size=None) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                                       "params": {"expression": "document.getElementById('password').value",
                                                  "returnByValue": True}}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == 1:
                    return str(((msg.get("result") or {}).get("result") or {}).get("value") or "")

    return asyncio.run(_read())


def main() -> int:
    sys.path.insert(0, str(PROJECT_ROOT))
    hermes_agent_src = os.environ.get("HERMES_AGENT_SRC", "").strip()
    if hermes_agent_src:
        sys.path.insert(0, hermes_agent_src)
    from vaultwarden_secret_source.browser_fill import handle_vaultwarden_browser_fill

    report: dict = {}
    ok = True

    with tempfile.TemporaryDirectory(prefix="vw020-bw-") as bw_dir, \
     tempfile.TemporaryDirectory(prefix="vw020-chromium-", dir="/tmp") as chrome_profile:
        bw_path = Path(bw_dir) / "bw"
        mode_path = Path(bw_dir) / "mode"
        mode_path.write_text("happy", encoding="utf-8")
        _write_fake_bw(bw_path, mode_path)
        interpreter = Path(bw_path.read_text(encoding="utf-8").splitlines()[0][2:]).resolve()

        settings = {
            "enabled": True,
            "server_url": "https://vault.example.invalid",
            "collection_id": COLLECTION_ID,
            "allowed_item_ids": [ITEM_ID, OTHER_HOST_ITEM_ID],
            "env": {},
            "client_id_env": "BW_CLIENTID",
            "client_secret_env": "BW_CLIENTSECRET",
            "master_password_env": "BW_PASSWORD",
            "binary_path": str(bw_path),
            "binary_sha256": _digest(bw_path),
            "binary_interpreter_sha256": _digest(interpreter),
            "cli_timeout_seconds": 10,
            "timeout_seconds": 30,
        }

        os.environ["BW_CLIENTID"] = "synthetic-client"
        os.environ["BW_CLIENTSECRET"] = "synthetic-client-secret"
        os.environ["BW_PASSWORD"] = "synthetic-master-credential"

        with _http_server() as page_url, _chromium(chrome_profile) as cdp_port:
            os.environ["BROWSER_CDP_URL"] = f"ws://127.0.0.1:{cdp_port}"

            # --- Check 1: happy path -----------------------------------------------
            target_id = _new_target(cdp_port, page_url)
            time.sleep(0.5)
            try:
                result_str = handle_vaultwarden_browser_fill(
                    {"item_id": ITEM_ID, "field": "login.password", "selector": "#password",
                     "target_id": target_id, "clear_first": True},
                    settings,
                )
                result = json.loads(result_str)
                actual_value = _read_input_value(cdp_port, target_id, page_url)

                check1 = {
                    "tool_result": result,
                    "secret_absent_from_tool_result": SECRET_VALUE not in result_str,
                    "dom_value_matches_secret": actual_value == SECRET_VALUE,
                    "chars_written_matches": result.get("chars_written") == len(SECRET_VALUE),
                    "success_true": result.get("success") is True,
                }
                report["happy_path"] = check1
                ok = ok and all([
                    check1["secret_absent_from_tool_result"],
                    check1["dom_value_matches_secret"],
                    check1["chars_written_matches"],
                    check1["success_true"],
                ])
            finally:
                _close_target(cdp_port, target_id)

            # --- Check 2: leak test (VW-019 mandatory) ------------------------------
            target_id = _new_target(cdp_port, page_url)
            time.sleep(0.5)
            try:
                result_str = handle_vaultwarden_browser_fill(
                    {"item_id": ITEM_ID, "field": "login.password", "selector": "#does-not-exist",
                     "target_id": target_id, "clear_first": True},
                    settings,
                )
                result = json.loads(result_str)
                check2 = {
                    "tool_result": result,
                    "secret_absent_from_tool_result": SECRET_VALUE not in result_str,
                    "success_false": result.get("success") is False,
                }
                report["leak_test_forced_cdp_error"] = check2
                ok = ok and check2["secret_absent_from_tool_result"] and check2["success_false"]
            finally:
                _close_target(cdp_port, target_id)

            # --- Check 3: cross-origin guard ----------------------------------------
            target_id = _new_target(cdp_port, page_url)
            time.sleep(0.5)
            try:
                result_str = handle_vaultwarden_browser_fill(
                    {"item_id": OTHER_HOST_ITEM_ID, "field": "login.password", "selector": "#password",
                     "target_id": target_id, "clear_first": True},
                    settings,
                )
                result = json.loads(result_str)
                actual_value = _read_input_value(cdp_port, target_id, page_url)
                check3 = {
                    "tool_result": result,
                    "secret_absent_from_tool_result": SECRET_VALUE not in result_str,
                    "success_false": result.get("success") is False,
                    "dom_value_still_empty": actual_value == "",
                }
                report["cross_origin_guard"] = check3
                ok = ok and all([
                    check3["secret_absent_from_tool_result"],
                    check3["success_false"],
                    check3["dom_value_still_empty"],
                ])
            finally:
                _close_target(cdp_port, target_id)

        os.environ.pop("BROWSER_CDP_URL", None)
        os.environ.pop("BW_CLIENTID", None)
        os.environ.pop("BW_CLIENTSECRET", None)
        os.environ.pop("BW_PASSWORD", None)

    report["ok"] = ok
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
