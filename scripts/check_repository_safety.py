#!/usr/bin/env python3
"""Reject likely secrets and deployment-specific data in tracked files.

Output intentionally contains only file, line, and rule identifiers. Matched
values are never printed.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ALLOW_MARKER = "repo-safety: allow"
MAX_TEXT_BYTES = 2_000_000

SENSITIVE_FILENAMES = {
    ".env",
    "auth.json",
    "hosts.yml",
    "hosts.yaml",
    ".git-credentials",
    "vault.json",
    "vault-export.json",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".cred"}

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")  # repo-safety: allow
KNOWN_TOKEN_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|secret)"
    r"\s*[:=]\s*[\"']?([^\s\"'#]+)"
)
LOCAL_USER_PATH_RE = re.compile(r"(?:/home/[^/\s]+|/Users/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)")  # repo-safety: allow
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
USERINFO_URL_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)

PLACEHOLDER_VALUES = {
    "changeme",
    "example",
    "placeholder",
    "redacted",
    "unset",
    "none",
    "null",
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    return (
        normalized.startswith("${")
        or normalized.startswith("<")
        or normalized.startswith("example.")
        or normalized in PLACEHOLDER_VALUES
    )


def _private_ip_present(line: str) -> bool:
    for candidate in IPV4_RE.findall(line):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and address.is_private and not address.is_loopback:
            return True
    return False


def _filename_is_sensitive(relative: Path) -> bool:
    name = relative.name.lower()
    if name in SENSITIVE_FILENAMES:
        return True
    if name.startswith(".env.") and name not in {".env.example", ".env.sample", ".env.template"}:
        return True
    return relative.suffix.lower() in SENSITIVE_SUFFIXES


def scan_paths(root: Path, paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    root = root.resolve()

    for supplied_path in paths:
        path = supplied_path if supplied_path.is_absolute() else root / supplied_path
        try:
            relative = path.resolve().relative_to(root)
        except ValueError:
            findings.append(Finding(path=Path("<outside-root>"), line=0, rule="outside-root"))
            continue

        if _filename_is_sensitive(relative):
            findings.append(Finding(path=relative, line=0, rule="sensitive-filename"))

        try:
            raw = path.read_bytes()
        except (OSError, IsADirectoryError):
            continue
        if len(raw) > MAX_TEXT_BYTES or b"\x00" in raw:
            continue

        text = raw.decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if ALLOW_MARKER in line:
                continue
            rules: list[str] = []
            if PRIVATE_KEY_RE.search(line):
                rules.append("private-key")
            if KNOWN_TOKEN_RE.search(line):
                rules.append("known-token")
            if USERINFO_URL_RE.search(line):
                rules.append("credential-in-url")
            if LOCAL_USER_PATH_RE.search(line):
                rules.append("local-user-path")
            if _private_ip_present(line):
                rules.append("private-ip")
            assignment = SECRET_ASSIGNMENT_RE.search(line)
            if assignment and not _is_placeholder(assignment.group(1)):
                rules.append("secret-assignment")
            findings.extend(Finding(path=relative, line=number, rule=rule) for rule in rules)

    return findings


def _tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def main() -> int:
    root = Path.cwd().resolve()
    paths = [Path(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else _tracked_paths(root)
    findings = scan_paths(root, paths)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: [{finding.rule}]")
    if findings:
        print(f"repository safety check failed: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("repository safety check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
