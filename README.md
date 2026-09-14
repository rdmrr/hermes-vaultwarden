# Hermes Vaultwarden Secret Source

Portable Hermes secret-source integration for retrieving allowlisted runtime
credentials from a Bitwarden-compatible Vaultwarden service. The bootstrap is
designed for systemd credential delivery and optional TPM2 protection without
persisting plaintext credentials in Hermes profile files.

## Status

Design and security baseline. Implementation begins after the documented design
gates are approved.

## Security boundary

This repository contains no real credentials or deployment inventory. Read
[SECURITY.md](SECURITY.md) and the
[repository safety policy](docs/security/repository-policy.md) before changing
code or documentation.

Run the mandatory local checks with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_repository_safety.py
git diff --cached --check
```

Deployment-specific configuration and verification evidence belong outside Git.
Only generic templates with placeholders may be committed.
