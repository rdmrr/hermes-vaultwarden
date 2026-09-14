# Configuration contract

The directory `vaultwarden_secret_source/` is a Hermes directory plugin. Deploy
that directory unchanged as `${HERMES_HOME}/plugins/vaultwarden-secret-source/`.
The runtime dependency is the externally managed Bitwarden CLI version
`2026.8.0`; the plugin never downloads or updates executables. The absolute,
non-symlink binary path and its lowercase SHA-256 digest are both mandatory.
The verified bytes are copied into a mode-0700 private temporary directory and
opened through a mode-0500 regular file. Every invocation executes the retained,
read-only descriptor through procfs, including after bootstrap credentials are
added to the child environment. Keeping the verified file named allows native
executables such as the official `bw` package to resolve and reopen
`/proc/self/exe`. The private staging directory and retained descriptors are
removed after every successful fetch; a persistent cleanup failure clears any
resolved secrets and fails the fetch closed. If the configured executable is a
script, its single absolute native interpreter must also be SHA-256 pinned and
privately staged.
Each binary is limited to 256 MiB, and copying plus hashing obeys the cumulative
fetch deadline.

The private directory protects staging from other operating-system users and
the retained descriptor prevents a later replacement of the configured source
path from changing the executed inode. A process already running as the Hermes
service user is outside this boundary: it can inspect the same process
environment and therefore already has access to the bootstrap credentials.
This release targets Linux/POSIX service environments so it can isolate each CLI
invocation in a process group and terminate inherited descendants on failure.

The following shows the `secrets.vaultwarden` data shape. Values in angle
brackets are placeholders, not usable identifiers:

```yaml
secrets:
  sources:
    - vaultwarden
  vaultwarden:
    enabled: true
    server_url: https://vault.example.invalid
    collection_id: <collection-uuid>
    allowed_item_ids:
      - <item-uuid>
    env:
      SYNTHETIC_API_KEY:
        item_id: <item-uuid>
        field: login.password
    client_id_env: BW_CLIENTID
    client_secret_env: BW_CLIENTSECRET
    master_password_env: BW_PASSWORD
    binary_path: /opt/example/bin/bw
    binary_sha256: <64-lowercase-hex-characters>
    # Required only if binary_path contains a script rather than a native binary:
    binary_interpreter_sha256: <64-lowercase-hex-characters>
    cli_timeout_seconds: 30
    timeout_seconds: 120
    override_existing: true
```

Configure these values through the supported Hermes configuration command or
the deployment configuration manager; do not place bootstrap values in
`config.yaml`. `server_url` must use HTTPS and must not contain user info, a
query, or a fragment. Collection and item references must be UUIDs. Every
binding's item must occur in `allowed_item_ids`, and the fetched item must report
membership in `collection_id`. `binary_path` must identify an executable regular
file directly; PATH lookup and symbolic links are rejected. `binary_sha256` must
match that file, while the executable must also report version `2026.8.0`.
Script interpreters are resolved to their canonical absolute path, copied into a
separate private staged file and checked against `binary_interpreter_sha256`.

Supported field selectors are `login.username`, `login.password`, `notes`, and
`fields.<custom-field-name>`. Empty values fail the entire fetch and never
replace an existing environment value.

## Bootstrap and process behavior

The source reads three bootstrap values from its per-profile Hermes source
environment:

- `BW_CLIENTID` (or `client_id_env`)
- `BW_CLIENTSECRET` (or `client_secret_env`)
- `BW_PASSWORD` (or `master_password_env`)

Hermes protects all three names from overwrite by any secret source. A systemd
unit can materialize those values from TPM2-protected credentials in its
runtime credential directory and expose them only to the service process. The
plugin does not read credential files directly.

Each fetch uses a fresh `BITWARDENCLI_APPDATA_DIR`, configures only the declared
Vaultwarden HTTPS endpoint, and performs API-key login and password unlock. The
resulting `BW_SESSION` exists transiently in the Hermes worker's memory and the
child-process environment; it is never exported to the parent process
environment. The temporary
CLI state is deleted at the end of the fetch. No session key is stored in the
Hermes profile or repository.

The child receives only platform basics, the three bootstrap values, the
transient session, `BITWARDENCLI_APPDATA_DIR`, and `NO_COLOR`. Commands use an
argument vector with closed stdin and `--nointeraction`; no shell is involved,
and `PATH` is not inherited by the child.
CLI stdout and stderr are each capped at 1 MiB; exceeding either limit kills the
entire child process group and fails closed. The same group cleanup applies to a
timeout. The plugin keeps its own cumulative deadline below Hermes' outer
`timeout_seconds` budget, so a credential-bearing process is terminated before
the orchestrator can abandon its worker thread. CLI output is never included in
returned error text.

## Failure behavior

`fetch()` is synchronous and never intentionally raises. It returns a
`FetchResult` using Hermes error kinds: `NOT_CONFIGURED`, `BINARY_MISSING`,
`AUTH_FAILED`, `AUTH_EXPIRED`, `REF_INVALID`, `NETWORK`, `EMPTY_VALUE`,
`TIMEOUT`, or `INTERNAL`. Hermes owns the outer wall-clock timeout, application
precedence, protected-variable checks, and provenance. Successfully applied
values are attributed to source `vaultwarden` with label `Vaultwarden`.
