# TPM2/systemd bootstrap

`scripts/hermes_vaultwarden_bootstrap.py` manages one isolated bootstrap set for
one Hermes profile and one system service. It does not install packages, change
the Hermes configuration, restart a service, contact Vaultwarden, or create a
Bitwarden session.

## Commands

Use a profile identifier and the exact systemd service unit on every call:

```text
python3 scripts/hermes_vaultwarden_bootstrap.py prereq --profile example-profile --unit hermes-example.service
python3 scripts/hermes_vaultwarden_bootstrap.py status --profile example-profile --unit hermes-example.service
python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile example-profile --unit hermes-example.service
python3 scripts/hermes_vaultwarden_bootstrap.py remove --profile example-profile --unit hermes-example.service
```

`setup` and `remove` are previews by default. They list every target and make no
changes. Add `--apply` only after reviewing the preview. Without `--yes`, the
helper also asks for a visible confirmation. Applying either command requires
root because it changes `/etc` and reloads the systemd manager configuration.
It deliberately does not restart the selected service; restarting can cause an
interruption and remains a separate operator action.

`prereq` checks that `systemd-creds` and `systemctl` are available, that
`systemd-creds has-tpm2 -q` succeeds, and that the selected service unit is
loaded. It does not install missing software. `status` checks paths, managed
content, ownership, and modes without decrypting or printing credential data.
A non-zero status means absent, partial, conflicting, or unsafe state.

## Credential flow

During `setup --apply`, the helper asks twice, with terminal echo disabled, for:

- Bitwarden API client ID;
- Bitwarden API client secret;
- a separate Bitwarden master credential.

Each value is converted in memory into a single-variable environment file and
sent only on standard input to a separate invocation of:

```text
systemd-creds encrypt --with-key=tpm2 --name=<credential-name> - -
```

No value appears in an argument, YAML, manifest, status output, or diagnostic.
Empty values, NUL bytes, and line breaks are rejected. The encrypted outputs are
stored independently. No `BW_SESSION` value is accepted or persisted.

The generated service drop-in uses `LoadCredentialEncrypted=` for the three
encrypted-at-rest bootstrap variables, plus a private `RuntimeDirectory=`, a
minimal `ExecStartPre=` helper, and `EnvironmentFile=-<runtime-path>`. systemd
decrypts the credential files into its protected runtime credential
directory when it starts the service; the `ExecStartPre=` helper then reads
`$CREDENTIALS_DIRECTORY` and writes the three `BW_*` assignments into a
mode-0700 runtime directory that only this unit owns, and `EnvironmentFile=`
loads them for the service process from there.

This two-step indirection exists because systemd does **not** expand the
`%d` (credentials directory) specifier inside `EnvironmentFile=` — verified
against systemd 255.4-1ubuntu8.17: a literal `EnvironmentFile=%d/<NAME>`
directive fails every service start with `Failed to load environment files:
No such file or directory`, because `EnvironmentFile=` paths are resolved
before the credential machinery populates `%d`. The `-` prefix on
`EnvironmentFile=-...` tolerates the file being briefly absent (e.g. during
service reload) without failing the unit.

## Isolated paths and transactions

For profile `example-profile`, the managed targets are:

```text
/etc/credstore.encrypted/hermes-vaultwarden/example-profile/BW_CLIENTID.cred
/etc/credstore.encrypted/hermes-vaultwarden/example-profile/BW_CLIENTSECRET.cred
/etc/credstore.encrypted/hermes-vaultwarden/example-profile/BW_PASSWORD.cred
/etc/systemd/system/hermes-example.service.d/50-hermes-vaultwarden.conf
/etc/hermes-vaultwarden/example-profile.json
```

Profile and unit names are strictly validated and cannot contain path
traversal. Credential files and the manifest use mode `0600`; the profile
credential directory uses `0700`; the non-secret systemd drop-in uses `0644`.
A complete matching installation is an idempotent no-op. Partial, modified,
symlinked, incorrectly owned, or incorrectly permissioned targets fail closed
rather than being overwritten.

Installation writes new files atomically. If a write or `systemctl
daemon-reload` fails, every newly installed target is removed and the manager
is reloaded again after rollback. Removal first snapshots only the encrypted
files and non-secret metadata in memory; if its reload fails, it restores their
exact content and modes and reloads again. Sibling profiles are never removed.
