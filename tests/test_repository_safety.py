import tempfile
import unittest
from pathlib import Path

from scripts.check_repository_safety import scan_paths


class RepositorySafetyTests(unittest.TestCase):
    def scan(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = []
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                paths.append(path)
            return scan_paths(root, paths)

    def test_rejects_secret_assignment(self):
        findings = self.scan({"config.txt": "API_KEY=live-value-123\n"})  # repo-safety: allow
        self.assertTrue(any(f.rule == "secret-assignment" for f in findings))

    def test_rejects_private_key_material(self):
        findings = self.scan({"key.txt": "-----BEGIN PRIVATE KEY-----\n"})  # repo-safety: allow
        self.assertTrue(any(f.rule == "private-key" for f in findings))

    def test_rejects_local_user_path(self):
        findings = self.scan({"notes.md": "Stored in /home/alice/project\n"})  # repo-safety: allow
        self.assertTrue(any(f.rule == "local-user-path" for f in findings))

    def test_rejects_private_network_address(self):
        findings = self.scan({"notes.md": "Connect to 192.168.10.5\n"})  # repo-safety: allow
        self.assertTrue(any(f.rule == "private-ip" for f in findings))

    def test_rejects_sensitive_filename(self):
        findings = self.scan({"auth.json": "{}\n"})
        self.assertTrue(any(f.rule == "sensitive-filename" for f in findings))

    def test_allows_documented_placeholders(self):
        findings = self.scan(
            {
                "example.env": "API_KEY=${API_KEY}\nPASSWORD=<set-at-runtime>\n",
                "docs.md": "Use ${HERMES_HOME}/plugins and example.invalid.\n",
            }
        )
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
