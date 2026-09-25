---
name: vaultwarden-secrets
description: Use when operating the hermes-vaultwarden plugin (lookup/status/doctor/config, rotation, uninstall). Never print secret values.
version: 0.2.0
author: hermes-vaultwarden
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [secrets, vaultwarden, bitwarden, plugin]
---

# Vaultwarden Secrets (hermes-vaultwarden)

Bundled operator skill for the `hermes-vaultwarden` plugin: an allowlisted
Hermes secret source that resolves specific Vaultwarden/Bitwarden items into
environment variables at process startup. This skill is about *safe,
non-interactive operation* of an already-installed plugin, not about
implementing the plugin.

## When to use

Load this skill whenever a task touches the `hermes-vaultwarden` plugin:
installing it, configuring `plugins.entries.hermes-vaultwarden.settings.*`,
looking up item UUIDs, running `doctor`/`status`, rotating bootstrap
credentials, or uninstalling the TPM2/systemd bootstrap.

## Hard rules

- Never print, log, or paste a secret *value* (password, API key, session,
  master credential). Only UUIDs, field names, booleans, and error kinds are
  safe to show.
- Never put bootstrap credentials (`BW_CLIENTID`, `BW_CLIENTSECRET`,
  `BW_PASSWORD`) in `config.yaml`, shell history, or a Kanban comment. They
  only exist as process environment, ideally systemd-injected from a
  TPM2-sealed credential (see `docs/systemd-bootstrap.md`).
- `hermes vaultwarden lookup` returns metadata (id, name, type,
  collection_ids, available_fields) only — never the field values themselves.
  Use its output to fill `allowed_item_ids` / `env.<VAR>.item_id`, not to read
  a password.
- All `<uuid>` placeholders in examples below are synthetic
  (`00000000-0000-4000-8000-00000000000X`) and `server_url` uses
  `https://vault.example.invalid`. Never substitute real Vault hosts,
  collection IDs, or item IDs into shared documentation, commits, or Kanban
  comments — those belong only in the operator's local, untracked config.

## Quickstart

1. Install the plugin (pin to a reviewed commit):
   ```bash
   hermes plugins install <owner>/<repo> --ref <full-40-char-sha> --no-enable
   hermes plugins enable hermes-vaultwarden
   ```
2. Set the non-secret plugin settings:
   ```bash
   hermes vaultwarden config
   ```
   prints the exact `hermes config set plugins.entries.hermes-vaultwarden.settings.*`
   commands to run (server URL, collection UUID, allowlist, env bindings,
   pinned `bw` binary path + SHA-256).
3. Provide the three bootstrap credentials (`BW_CLIENTID`, `BW_CLIENTSECRET`,
   `BW_PASSWORD`) to the service's process environment — via the bundled
   TPM2/systemd bootstrap (see below) or, for local testing only, exported
   shell variables that are never committed.
4. Verify:
   ```bash
   hermes vaultwarden doctor
   ```
   Exit code 0 and `"ok": true` means the pinned binary, config shape, and
   bootstrap credentials are all present. No network call to Vaultwarden is
   made by `doctor`.
5. Restart the Hermes gateway/profile so plugin discovery re-pulls secret
   sources:
   ```bash
   hermes gateway restart
   ```

## Prerequisites

- Hermes profile with plugin support (manifest_version 2).
- `bw` (Bitwarden CLI) version `2026.8.0`, deployed by the operator (the
  plugin never downloads or updates it). Absolute path + SHA-256 digest
  required. See `docs/configuration.md`.
- A Vaultwarden technical account (see below) with API-key login enabled.
- For the TPM2 bootstrap: `systemd-creds`, `systemctl`, and
  `systemd-creds has-tpm2 -q` succeeding. See `docs/systemd-bootstrap.md`.

## Vaultwarden technical account and collections

Create a dedicated Vaultwarden user for Hermes (not a personal account):

- Grant it access to exactly one collection scoped to the secrets Hermes
  needs — do not reuse a broad "everything" collection.
- Note the collection's UUID (Vaultwarden web vault → collection → URL or
  admin panel); this becomes `collection_id`.
- Enable API-key login for that user (My Account → API Key) to obtain a
  client_id/client_secret pair. Set a separate master password (not the
  personal account's password) — this becomes the bootstrap `BW_PASSWORD`.
- Never store the technical account's client secret or master password in
  the repository, `config.yaml`, or Kanban — only in the systemd-managed
  TPM2 credential store or an untracked local `.env`.

## UUID lookup (no secret values)

```bash
hermes vaultwarden lookup "item name search text" --collection "collection search text"
```

Returns JSON with `items: [{id, name, type, collection_ids, available_fields}]`
and, if `--collection` was given, the resolved `collections: [{id, name}]`.
Use the returned `id` values to populate:

```bash
hermes config set plugins.entries.hermes-vaultwarden.settings.collection_id <collection-uuid>
hermes config set plugins.entries.hermes-vaultwarden.settings.allowed_item_ids '["<item-uuid>"]'
```

If the collection search does not resolve to exactly one UUID, the lookup
fails closed (`"ok": false`) rather than guessing.

## Bindings (env var → item + field)

```bash
hermes config set plugins.entries.hermes-vaultwarden.settings.env \
  '{"SYNTHETIC_API_KEY":{"item_id":"<item-uuid>","field":"login.password"}}'
```

- `field` is one of `login.username`, `login.password`, `notes`, or
  `fields.<custom-field-name>`.
- Every bound `item_id` must also appear in `allowed_item_ids`.
- `SYNTHETIC_API_KEY` (or whatever name you choose) must not collide with the
  three protected bootstrap names (`BW_CLIENTID`, `BW_CLIENTSECRET`,
  `BW_PASSWORD`, or their configured overrides) — Hermes' orchestrator
  refuses to let a fetched value replace a protected var.

## Diagnose

```bash
hermes vaultwarden status    # safe config snapshot: enabled?, bindings, bootstrap env presence
hermes vaultwarden doctor    # validates config + pinned binary + bootstrap env, exit 0/1
```

Neither command performs a remote Vaultwarden call (`doctor`'s
`remote_access_attempted` is always `false`). Both redact everything except
UUIDs, booleans, and short diagnostic strings.

If `doctor` reports an issue:

| Issue text contains | Likely cause | Fix |
|---|---|---|
| `binary_path must be an absolute file path` | `binary_path` unset or relative | `hermes config set plugins.entries.hermes-vaultwarden.settings.binary_path /abs/path/bw` |
| `Bitwarden CLI 2026.8.0 is required` | wrong bw version pinned | install the exact pinned `bw` release |
| `Bootstrap environment variable BW_* is unavailable` | credential not in process env | check the systemd drop-in / TPM2 credential, see Rotation below |
| `allowed_item_ids must be a non-empty UUID list` | no items allowlisted | run `lookup`, then `config set ... allowed_item_ids` |
| `references an item outside the allowlist` | `env.<VAR>.item_id` not in `allowed_item_ids` | add the UUID to `allowed_item_ids` too |

## TPM2/systemd bootstrap (rotation, upgrade, uninstall)

`scripts/hermes_vaultwarden_bootstrap.py` manages exactly one isolated
bootstrap set per (Hermes profile, systemd unit) pair. Every `setup`/`remove`
is a **preview by default** — nothing changes without `--apply`, and without
`--yes` it also asks for a visible confirmation.

```bash
# 1. Check host readiness (read-only)
python3 scripts/hermes_vaultwarden_bootstrap.py prereq --profile <profile> --unit <unit>.service

# 2. Preview what setup would create
python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profile> --unit <unit>.service

# 3. Apply (asks for BW_CLIENTID / BW_CLIENTSECRET / BW_PASSWORD, hidden input, twice each)
sudo python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profile> --unit <unit>.service --apply

# 4. Check installed state without decrypting anything
python3 scripts/hermes_vaultwarden_bootstrap.py status --profile <profile> --unit <unit>.service
```

Rotation = re-running `setup --apply` is **not** idempotent over changed
secrets by itself: `status` fails closed on any modified/partial state, so to
rotate credentials, `remove --apply` the old set first, then `setup --apply`
with the new values. The service is never restarted automatically — restart
it yourself after rotation so the new credential set is picked up:

```bash
sudo python3 scripts/hermes_vaultwarden_bootstrap.py remove --profile <profile> --unit <unit>.service --apply
sudo python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profile> --unit <unit>.service --apply
sudo systemctl restart <unit>.service
```

Upgrade (new `bw` binary): update `binary_path`/`binary_sha256` via
`hermes config set`, no bootstrap change needed — the TPM2 credentials are
independent of the pinned binary.

Uninstall (remove the plugin entirely):

```bash
sudo python3 scripts/hermes_vaultwarden_bootstrap.py remove --profile <profile> --unit <unit>.service --apply
hermes plugins disable hermes-vaultwarden
hermes plugins remove hermes-vaultwarden
hermes config unset secrets.vaultwarden
hermes config unset plugins.entries.hermes-vaultwarden
```

`remove --apply` restores the previous exact state on any failure (atomic
snapshot/rollback) and never touches a sibling profile's credentials.

## How agents actually consume a secret (no browser_vault_*, no fetch code)

This plugin's whole job ends at Hermes' gateway startup: it resolves each
`env.<VAR>` binding from Vaultwarden and injects the *value* directly into
the running gateway process's environment — the same mechanism Hermes uses
for provider API keys. An agent never calls anything to "get" the secret; it
already exists as `$TASMOTA_PASSWORD` (or whatever var name was bound) in the
process environment the moment the gateway is up.

To actually use it, an agent writes a `terminal`/`execute_code` command that
*references* the variable by name and lets the shell substitute it at
execution time — for example an authenticated HTTP request built with the
username/password variables interpolated by the shell, or a script that
reads the value from the process environment by name. The agent's own
context never contains the literal value; Hermes forwards it into the child
process at execution time (and only if the variable is declared in
`terminal.env_passthrough` or the skill's `required_environment_variables` —
see `secrets.md#secrets-in-child-processes` in the Hermes docs).

**This only works for non-interactive tools that read environment
variables** (terminal commands, HTTP requests, scripts). It does **not**
apply to typing a password into a live browser form — there is no
`env.<VAR>` equivalent for that.

### `browser_vault_*` is a different, unrelated system — never use it for this plugin's secrets

Hermes ships a separate, built-in vault backend (`browser_vault_list`,
`browser_vault_fill`, `browser_vault_save_login`, `browser_vault_unlock`)
that talks to the *operator's own* Bitwarden/1Password account for filling
*browser login forms*. It is unrelated to this plugin, has its own unlock
flow (interactive master-password prompt), and — critically — **requires an
actual Bitwarden/1Password subscription bound to that Hermes install**. If
the operator has no such subscription, this backend is permanently
`locked`/`unavailable_in_this_session`; that is not a transient state to
wait out, it is a dead end.

If a task needs a secret that this plugin manages, the only two ways to
reach it are:

1. A shell/env-based tool (see above) — works today for whatever is already
   bound in `plugins.entries.hermes-vaultwarden.settings.env`.
2. The secret isn't bound yet: ask the operator to add an `env:` binding for
   it (`hermes vaultwarden lookup` to find the UUID, then `hermes config
   set plugins.entries.hermes-vaultwarden.settings.env ...`, then restart
   the gateway) — never reach for `browser_vault_*` as a workaround, and
   never suggest the operator "unlock Bitwarden" for this plugin's secrets.

## Pitfalls

- `doctor`/`status`/`lookup` never make Hermes apply a secret — only a real
  `fetch()` during startup/refresh does that. A green `doctor` does not
  guarantee `fetch()` succeeds against the live Vaultwarden server (network,
  auth, or collection-membership failures still show up only at fetch time).
- `binary_path` must be an absolute, non-symlink, executable regular file;
  PATH lookup is rejected on purpose (supply-chain pinning).
- Empty or missing values from Vaultwarden never overwrite an existing env
  value — a partially-filled item fails that one binding, not the whole
  fetch, only if it is not required elsewhere; if it *is* required, the fetch
  fails closed with `EMPTY_VALUE`.
- Changing `collection_id` after allowlisting items requires re-verifying
  every allowlisted item is still a member, or `fetch()` will start failing
  with `REF_INVALID`.
