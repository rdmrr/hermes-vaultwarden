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
script interpreter. Verified bytes execute from retained read-only descriptors
backed by a private temporary staging directory. The plugin never installs a
binary, persists a session key, or writes to the process environment directly.

Configuration, allowlist semantics, supported fields, bootstrap variables and
failure behavior are documented in [docs/configuration.md](docs/configuration.md).
The portable profile, rotation and fail-open integration procedure is documented
in [docs/testing.md](docs/testing.md).
The preview-first TPM2/systemd helper, its isolated per-profile paths and its
rollback behavior are documented in
[docs/systemd-bootstrap.md](docs/systemd-bootstrap.md).

## Security boundary

This repository contains no real credentials or deployment inventory. Read
[SECURITY.md](SECURITY.md) and the
[repository safety policy](docs/security/repository-policy.md) before changing
code or documentation.

Run the mandatory local checks with:

```bash
export HERMES_AGENT_SRC=/path/to/pinned/hermes-agent
export PYTHONPATH="${PWD}:${HERMES_AGENT_SRC}"
python3 -m pip install --editable "${HERMES_AGENT_SRC}"
python3 scripts/check_hermes_fixture.py
python3 -m unittest discover -s tests -v
python3 scripts/run_profile_integration.py
python3 scripts/run_process_path_integration.py
python3 scripts/check_repository_safety.py
git diff --cached --check
```

Use the official `NousResearch/hermes-agent` source fixture pinned to commit
`fef0bc56b2f622ffe124835fbf57adfd10aa17e6`. The CI workflow checks it out and
installs it independently; the integration suites fail rather than skip when
the declared fixture is unavailable.

Deployment-specific configuration and verification evidence belong outside Git.
Only generic templates with placeholders may be committed.
