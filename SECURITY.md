# Security Policy

## Repository boundary

This repository contains portable source code, tests, generic examples, and
system-independent documentation only. It must not contain runtime credentials,
Vault exports, encrypted bootstrap credentials, local client state, production
identifiers, or deployment-specific inventory.

## Reporting a vulnerability

Use GitHub's private security-advisory feature for this repository. Do not open
a public issue containing credentials, access details, host inventory, or
reproduction data copied from a real environment.

If a credential may have entered Git history, stop further pushes, revoke or
rotate it first, then remove it from every reachable ref. Rewriting history is
not a substitute for revocation.

## Required checks

Before every commit and push:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_repository_safety.py
```

Review the complete staged diff manually as a separate control:

```bash
git diff --cached --check
git diff --cached
```

The automated scanner reports only file, line, and rule identifiers. It never
prints the matched value.
