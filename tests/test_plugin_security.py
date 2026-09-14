from __future__ import annotations

import ast
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "__init__.py"
MANIFEST_PATH = PROJECT_ROOT / "vaultwarden_secret_source" / "plugin.yaml"


class PluginSecurityInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PLUGIN_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_has_no_direct_network_model_or_mcp_imports(self):
        prohibited_roots = {
            "anthropic",
            "httpx",
            "mcp",
            "openai",
            "requests",
            "socket",
            "urllib3",
        }
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

    def test_manifest_declares_exact_external_cli_version_and_digest_requirement(self):
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")
        self.assertIn('"bw-cli-version: 2026.8.0"', manifest)
        self.assertIn('"bw-cli-sha256: required-config"', manifest)
        self.assertIn('"bw-cli-script-interpreter-sha256: required-if-script"', manifest)


if __name__ == "__main__":
    unittest.main()
