# Portable profile integration test

The repository includes a disposable end-to-end check for the Vaultwarden
secret source. It uses the installed Hermes runtime, a temporary
`${HERMES_HOME}` shaped as a named profile, the real Hermes plugin manager and
secret-source orchestrator, and a synthetic `bw` executable generated outside
the repository checkout. The profile exercise runs in an isolated subprocess,
so it cannot clear or overwrite the caller's environment, plugin registry or
secret-source cache.

Run it from the repository root with a Python environment that can import the
Hermes Agent packages:

```bash
python3 scripts/run_profile_integration.py
```

The command exits successfully only when all of these phases produce their
exact expected result:

1. Hermes discovers the directory plugin for the disposable profile and applies
   one synthetic mapped value with `vaultwarden` provenance.
2. The backing synthetic value changes, the Hermes secret-source cache is
   explicitly refreshed, and the next profile load observes the rotated value.
3. Missing bootstrap material is passed through the real plugin discovery and
   profile refresh path; startup continues without applying a value and the
   direct orchestrator report is `not_configured`.
4. A rejected synthetic login follows the same startup path, applies no value,
   and reports `auth_failed`.
5. A post-pin executable change follows the same startup path, applies no value,
   and reports `binary_missing`.

The JSON result contains booleans, provenance and error kinds only. Synthetic
secret values are never printed. All generated profile files, executable state
and values live in a temporary directory and are deleted when the command
finishes.

The same behavior is covered by the normal test suite:

```bash
python3 -m unittest tests.test_profile_integration -v
```

## Operational evidence boundary

This check is portable evidence for the repository contract. It does not claim
that a particular host, TPM, systemd credential, Vaultwarden endpoint or
production profile was exercised. Run deployment-specific checks only in the
approved operational environment and record their command output, timestamps
and host/service findings in the operational checkpoint store. Do not copy that
evidence, profile configuration, credential files, Vault identifiers or local
inventory into Git.
