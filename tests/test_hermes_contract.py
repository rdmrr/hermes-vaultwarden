from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _hermes_available() -> bool:
    try:
        return importlib.util.find_spec("agent.secret_sources.base") is not None
    except (ImportError, ModuleNotFoundError):
        return False


HERMES_AVAILABLE = _hermes_available()


@unittest.skipUnless(HERMES_AVAILABLE, "set PYTHONPATH to a compatible Hermes Agent checkout")
class HermesContractIntegrationTests(unittest.TestCase):
    @staticmethod
    def _pin_fake_bw(cfg: dict, fake_bw: Path) -> None:
        cfg["binary_path"] = str(fake_bw)
        cfg["binary_sha256"] = hashlib.sha256(fake_bw.read_bytes()).hexdigest()
        interpreter = Path(fake_bw.read_text(encoding="utf-8").splitlines()[0][2:])
        cfg["binary_interpreter_sha256"] = hashlib.sha256(interpreter.read_bytes()).hexdigest()

    @staticmethod
    def _write_fake_bw(root: Path, collection_id: str) -> Path:
        fake_bw = root / "bw"
        fake_bw.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "if args[0] == '--version':\n"
            "    assert 'BW_CLIENTID' not in os.environ\n"
            "    assert 'BW_CLIENTSECRET' not in os.environ\n"
            "    assert 'BW_PASSWORD' not in os.environ\n"
            "    print('2026.8.0')\n"
            "    raise SystemExit(0)\n"
            "if args[:2] == ['config', 'server'] or args[:2] == ['login', '--apikey'] or args[0] == 'sync':\n"
            "    raise SystemExit(0)\n"
            "if args[:2] == ['unlock', '--passwordenv']:\n"
            "    print('synthetic-session')\n"
            "    raise SystemExit(0)\n"
            "if args[:2] == ['get', 'item']:\n"
            f"    print(json.dumps({{'id': args[2], 'collectionIds': ['{collection_id}'], "
            "'login': {'password': 'synthetic-fetched-value'}}))\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        fake_bw.chmod(0o700)
        return fake_bw

    def test_real_orchestrator_applies_secret_and_records_provenance(self):
        from agent.secret_sources.registry import (
            _reset_registry_for_tests,
            apply_all,
            register_source,
        )

        from vaultwarden_secret_source import VaultwardenSource

        item_id = "00000000-0000-4000-8000-000000000002"
        collection_id = "00000000-0000-4000-8000-000000000001"
        cfg = {
            "sources": ["vaultwarden"],
            "vaultwarden": {
                "enabled": True,
                "server_url": "https://vault.example.invalid",
                "collection_id": collection_id,
                "allowed_item_ids": [item_id],
                "env": {
                    "SYNTHETIC_API_KEY": {
                        "item_id": item_id,
                        "field": "login.password",
                    }
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bw = self._write_fake_bw(root, collection_id)
            self._pin_fake_bw(cfg["vaultwarden"], fake_bw)
            env = {
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }

            _reset_registry_for_tests()
            try:
                self.assertTrue(register_source(VaultwardenSource()))
                report = apply_all(cfg, root, environ=env)
            finally:
                _reset_registry_for_tests()

        self.assertEqual("synthetic-fetched-value", env["SYNTHETIC_API_KEY"])
        provenance = report.provenance["SYNTHETIC_API_KEY"]
        self.assertEqual("vaultwarden", provenance.source)
        self.assertEqual("mapped", provenance.shape)
        self.assertFalse(provenance.overrode_env)

    def test_real_plugin_manager_discovers_and_refreshes_source(self):
        from agent.secret_sources import registry
        from hermes_cli import env_loader
        from hermes_cli.plugins import PluginManager

        project_root = Path(__file__).resolve().parents[1]
        item_id = "00000000-0000-4000-8000-000000000002"
        collection_id = "00000000-0000-4000-8000-000000000001"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "hermes-home"
            plugin_target = home / "plugins" / "vaultwarden-secret-source"
            plugin_target.parent.mkdir(parents=True)
            shutil.copytree(project_root / "vaultwarden_secret_source", plugin_target)
            fake_bw = self._write_fake_bw(root, collection_id)
            fake_bw_sha256 = hashlib.sha256(fake_bw.read_bytes()).hexdigest()
            interpreter = Path(fake_bw.read_text(encoding="utf-8").splitlines()[0][2:])
            interpreter_sha256 = hashlib.sha256(interpreter.read_bytes()).hexdigest()
            (home / "config.yaml").write_text(
                "plugins:\n"
                "  enabled: [vaultwarden-secret-source]\n"
                "secrets:\n"
                "  sources: [vaultwarden]\n"
                "  vaultwarden:\n"
                "    enabled: true\n"
                "    server_url: https://vault.example.invalid\n"
                f"    collection_id: {collection_id}\n"
                "    allowed_item_ids:\n"
                f"      - {item_id}\n"
                "    env:\n"
                "      SYNTHETIC_PLUGIN_DISCOVERY:\n"
                f"        item_id: {item_id}\n"
                "        field: login.password\n"
                f"    binary_path: {fake_bw}\n"
                f"    binary_sha256: {fake_bw_sha256}\n"
                f"    binary_interpreter_sha256: {interpreter_sha256}\n",
                encoding="utf-8",
            )
            runtime_env = {
                "HERMES_HOME": str(home),
                "BW_CLIENTID": "synthetic-client",
                "BW_CLIENTSECRET": "synthetic-client-secret",
                "BW_PASSWORD": "synthetic-master-credential",
            }

            registry._reset_registry_for_tests()
            env_loader.reset_secret_source_cache()
            try:
                with mock.patch.dict(os.environ, runtime_env, clear=False):
                    os.environ.pop("SYNTHETIC_PLUGIN_DISCOVERY", None)
                    PluginManager().discover_and_load()
                    self.assertEqual(
                        "synthetic-fetched-value",
                        os.environ["SYNTHETIC_PLUGIN_DISCOVERY"],
                    )
                    self.assertIn(
                        "vaultwarden",
                        [source.name for source in registry.list_plugin_sources()],
                    )
            finally:
                os.environ.pop("SYNTHETIC_PLUGIN_DISCOVERY", None)
                registry._reset_registry_for_tests()
                env_loader.reset_secret_source_cache()


if __name__ == "__main__":
    unittest.main()
