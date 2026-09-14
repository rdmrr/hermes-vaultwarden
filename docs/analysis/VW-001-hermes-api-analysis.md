# Hermes Secret Source API Analysis

## Purpose

This document captures the portable API contract and design constraints needed
to implement a Vaultwarden-backed Hermes secret source. Environment-specific
versions, paths, commits, host capabilities, and test evidence are deliberately
kept outside the repository.

## Secret source contract

The implementation must subclass Hermes' `SecretSource` abstraction and return
a `FetchResult` from `fetch(cfg, home_path)`. Fetching is synchronous,
non-interactive, bounded by a timeout, and must convert failures into the
framework's machine-readable error categories rather than raising exceptions to
the caller.

The source returns a mapping to the orchestrator and does not write directly to
`os.environ`. Bootstrap variables are declared through `protected_env_vars()` so
that fetched values cannot replace them. Non-sensitive settings are exposed via
`config_schema()`.

The implementation must use argument-vector subprocess execution without shell
interpolation, a minimal environment, disabled interactive input, bounded output
handling, and redacted diagnostics. Empty or missing values must never replace a
valid existing credential.

## Plugin integration

Package the source as an external Hermes plugin. A directory plugin contains a
manifest and a module exposing `register(ctx)`, which registers the source with
`ctx.register_secret_source(...)`. An installable package may expose the same
registration through the supported plugin entry-point mechanism.

Plugin discovery can occur after the initial environment-loading pass. The
source must therefore tolerate the framework's idempotent refresh behavior and
must not depend on import-time side effects.

## Relevant process paths

Verification must cover each process path that initializes Hermes independently:

- interactive and one-shot CLI;
- agent initialization;
- gateway startup;
- profile-multiplexed gateway startup;
- scheduled execution;
- supported adapter/subagent paths.

Profile-scoped environments must remain isolated. The plugin must use the home
and environment supplied by the framework and must not create global process
state that crosses profile boundaries.

## Consequences for implementation

- Keep Vaultwarden-specific behavior outside Hermes core.
- Keep bootstrap material outside profile configuration and repository files.
- Support explicit item and environment-name allowlists.
- Preserve provenance without exposing values.
- Test real plugin discovery, refresh behavior, conflict handling, timeout and
  error isolation with temporary, synthetic environments.
- Keep runtime evidence and deployment-specific findings in the approved
  operational checkpoint store, not in Git.

This document contains design findings only. It makes no claim about any
particular host, installation, version, or production deployment.
