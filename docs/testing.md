# Portable profile integration test

The repository includes a disposable end-to-end check for the Vaultwarden
secret source. It uses the installed Hermes runtime, a temporary
`${HERMES_HOME}` shaped as a named profile, the real Hermes plugin manager and
secret-source orchestrator, and a synthetic `bw` executable generated outside
the repository checkout. The profile exercise runs in an isolated subprocess,
so it cannot clear or overwrite the caller's environment, plugin registry or
secret-source cache.

The tests require an explicit source fixture; they fail instead of skipping when
it is absent or resolves to another installation. Use a separate checkout of
`NousResearch/hermes-agent` pinned to commit
`fef0bc56b2f622ffe124835fbf57adfd10aa17e6`, install its dependencies in the
test environment, and expose both source roots explicitly:

```bash
export HERMES_AGENT_SRC=/path/to/pinned/hermes-agent
export PYTHONPATH="${PWD}:${HERMES_AGENT_SRC}"
python3 -m pip install --editable "${HERMES_AGENT_SRC}"
python3 scripts/check_hermes_fixture.py
python3 -m unittest discover -s tests -v
```

GitHub Actions creates that checkout independently on every run. No pre-existing
Hermes installation or developer checkout is used as CI evidence.

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

## Gateway, cron and subagent process paths

The separate process-path runner verifies the credential boundary at the
independent Hermes initialization seams used by gateway startup, multiplexed
profile turns, scheduled execution and delegated children:

```bash
python3 scripts/run_process_path_integration.py
```

Each path runs in its own subprocess with disposable profiles, the real plugin
manager, real secret-source orchestration and synthetic `bw` executables. The
gateway check verifies startup discovery and application. The multiplexed check
discovers the plugin independently for two profiles, hydrates separate secret
snapshots and enters Hermes' real per-profile runtime scopes. The cron check
uses Hermes' profile cron scope and the same scoped-secret construction used by
the job execution seam. The subagent check uses Hermes' child-runtime credential
resolver and the context-copy behavior used by delegated worker threads.

Every check places a different value in the ambient process environment and
fails unless the profile-owned value wins. The multiplexed check additionally
fails unless both profiles resolve their own different value. All scopes must
be removed after the path returns. The final JSON contains only booleans and
path names; workers' synthetic values and bootstrap material are never emitted.

These probes establish a portable contract against the installed Hermes
runtime. They do not replace the deployment checkpoint required before a
production credential migration.

## Operational evidence boundary

This check is portable evidence for the repository contract. It does not claim
that a particular host, TPM, systemd credential, Vaultwarden endpoint or
production profile was exercised. Run deployment-specific checks only in the
approved operational environment and record their command output, timestamps
and host/service findings in the operational checkpoint store. Do not copy that
evidence, profile configuration, credential files, Vault identifiers or local
inventory into Git.
