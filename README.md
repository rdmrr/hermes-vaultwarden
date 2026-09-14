# Hermes Vaultwarden Secret Source

Portable Hermes secret-source integration for retrieving allowlisted runtime
credentials from a Bitwarden-compatible Vaultwarden service. The bootstrap is
designed for systemd credential delivery and optional TPM2 protection without
persisting plaintext credentials in Hermes profile files.

## Status

The portable directory plugin, its synthetic unit/contract tests, and a
disposable Hermes profile integration check are implemented. Host-specific
service deployment remains a separate gated task.

## Plugin

Deploy `vaultwarden_secret_source/` unchanged as a directory below
`${HERMES_HOME}/plugins/`. It implements Hermes Secret Source API v1 and uses
the externally managed Bitwarden CLI pinned for this release to version
`2026.8.0` and to operator-supplied SHA-256 digests for its executable and any
script interpreter. Verified bytes execute from sealed in-memory files. The
plugin never installs a binary, persists a session key, or writes to the process
environment directly.

Configuration, allowlist semantics, supported fields, bootstrap variables and
failure behavior are documented in [docs/configuration.md](docs/configuration.md).
The portable profile, rotation and fail-open integration procedure is documented
in [docs/testing.md](docs/testing.md).

## Security boundary

This repository contains no real credentials or deployment inventory. Read
[SECURITY.md](SECURITY.md) and the
[repository safety policy](docs/security/repository-policy.md) before changing
code or documentation.

Run the mandatory local checks with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/run_profile_integration.py
PYTHONPATH="${PROJECT_ROOT}:${HERMES_AGENT_SRC}" \
  python3 -m unittest discover -s tests -p 'test_hermes_contract.py' -v
python3 scripts/check_repository_safety.py
git diff --cached --check
```

Deployment-specific configuration and verification evidence belong outside Git.
Only generic templates with placeholders may be committed.
