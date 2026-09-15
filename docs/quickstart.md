# Anwenderdokumentation — hermes-vaultwarden

Diese Seite ist für Operator:innen gedacht, die das Plugin installieren und
betreiben. Für den Vertrag/die Implementierung siehe
[configuration.md](configuration.md), [testing.md](testing.md) und
[systemd-bootstrap.md](systemd-bootstrap.md). Für Tagesbetrieb (Lookup,
Diagnose, Rotation) lädt der gebündelte Skill
[`vaultwarden_secret_source/skills/vaultwarden-secrets/SKILL.md`](../vaultwarden_secret_source/skills/vaultwarden-secrets/SKILL.md)
die vollständige Anleitung inklusive Sicherheitsregeln direkt in Hermes.

Alle Beispiele unten verwenden ausschließlich `https://vault.example.invalid`
und synthetische UUIDs der Form `00000000-0000-4000-8000-00000000000X`. Echte
Werte gehören nie in Git, Kanban-Kommentare oder geteilte Notizen.

## Quickstart

1. **Voraussetzungen prüfen** (siehe Abschnitt weiter unten).
2. **Plugin installieren**, auf einen geprüften Commit gepinnt:
   ```bash
   hermes plugins install <owner>/<repo> --ref <voller-40-stelliger-sha> --no-enable
   hermes plugins enable hermes-vaultwarden
   ```
3. **Nicht-geheime Settings setzen** — die exakten Befehle liefert das Plugin
   selbst:
   ```bash
   hermes vaultwarden config
   ```
   Das gibt u. a. folgende Muster aus (Platzhalter ersetzen):
   ```bash
   hermes config set plugins.entries.hermes-vaultwarden.settings.server_url https://vault.example.invalid
   hermes config set plugins.entries.hermes-vaultwarden.settings.collection_id 00000000-0000-4000-8000-000000000001
   hermes config set plugins.entries.hermes-vaultwarden.settings.allowed_item_ids '["00000000-0000-4000-8000-000000000002"]'
   hermes config set plugins.entries.hermes-vaultwarden.settings.env '{"SYNTHETIC_API_KEY":{"item_id":"00000000-0000-4000-8000-000000000002","field":"login.password"}}'
   hermes config set plugins.entries.hermes-vaultwarden.settings.binary_path /opt/example/bin/bw
   hermes config set plugins.entries.hermes-vaultwarden.settings.binary_sha256 '<64-lowercase-hex-characters>'
   hermes config set plugins.entries.hermes-vaultwarden.settings.enabled true
   hermes config set secrets.sources '["vaultwarden"]'
   hermes config set secrets.vaultwarden.enabled true
   ```
4. **Bootstrap-Credentials bereitstellen** (`BW_CLIENTID`, `BW_CLIENTSECRET`,
   `BW_PASSWORD`) — produktiv über den TPM2/systemd-Bootstrap, siehe
   [TPM2/systemd-Setup](#tpm2systemd-setup); für lokale Tests genügen
   exportierte Shell-Variablen, die nie committet werden.
5. **Verifizieren**, ohne dass ein Secret-Wert je ausgegeben wird:
   ```bash
   hermes vaultwarden doctor
   ```
6. **Gateway/Profil neu starten**, damit die Secret-Source-Discovery erneut
   läuft:
   ```bash
   hermes gateway restart
   ```

Details zu jedem Schritt folgen unten.

## Voraussetzungen

- Hermes-Profil mit Plugin-Unterstützung, `manifest_version` 2 kompatibel.
- Bitwarden-CLI `bw` in Version `2026.8.0`, vom Betreiber bereitgestellt und
  per absolutem Pfad + SHA-256 gepinnt. Das Plugin lädt oder aktualisiert `bw`
  nie selbst.
- Ein Vaultwarden-Technikaccount mit einer eigenen, eng gescopten Collection
  (siehe nächster Abschnitt).
- Für den TPM2-Bootstrap: `systemd-creds`, `systemctl`, und ein Host, bei dem
  `systemd-creds has-tpm2 -q` erfolgreich zurückkehrt.

## Vaultwarden-Technikaccount und Collections

- Eigenen Vaultwarden-Benutzer für Hermes anlegen, keinen persönlichen
  Account wiederverwenden.
- Genau eine Collection zuweisen, die auf die von Hermes benötigten Secrets
  begrenzt ist — keine "Alles"-Collection.
- Die Collection-UUID notieren (Vaultwarden-Weboberfläche → Collection → URL,
  oder Admin-Panel); das wird `collection_id`.
- API-Key-Login für diesen Benutzer aktivieren (Mein Konto → API-Schlüssel),
  um Client-ID/Client-Secret zu erhalten. Ein separates Master-Passwort
  setzen (nicht das des persönlichen Accounts) — das wird der Bootstrap-Wert
  `BW_PASSWORD`.
- Client-Secret und Master-Passwort des Technikaccounts niemals im
  Repository, in `config.yaml` oder in Kanban ablegen — nur im
  TPM2-verwalteten Credential-Store oder einer nicht versionierten lokalen
  `.env`.

## bw-Installation

Die Bitwarden-CLI wird extern verwaltet und muss vom Betreiber bezogen und
verifiziert werden (offizielles Release, Version `2026.8.0`). Nach der
Installation:

```bash
sha256sum /pfad/zu/bw
```

Den Digest und den absoluten Pfad in `binary_sha256` bzw. `binary_path`
eintragen (siehe Quickstart-Schritt 3). Bei script-basierten `bw`-Auslieferungen
ist zusätzlich `binary_interpreter_sha256` für den Interpreter-Pfad aus dem
Shebang erforderlich; siehe [configuration.md](configuration.md) für die
exakte Verifikationskette.

## TPM2/systemd-Setup

Vollständige Details und Sicherheitsgarantien stehen in
[systemd-bootstrap.md](systemd-bootstrap.md). Kurzfassung:

```bash
# Host-Voraussetzungen prüfen (read-only)
python3 scripts/hermes_vaultwarden_bootstrap.py prereq --profile <profil> --unit <unit>.service

# Vorschau, was setup anlegen würde (keine Änderung)
python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profil> --unit <unit>.service

# Anwenden (fragt verdeckt zweimal nach BW_CLIENTID/BW_CLIENTSECRET/BW_PASSWORD)
sudo python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profil> --unit <unit>.service --apply
```

Der Dienst wird dabei nicht automatisch neu gestartet — das bleibt ein
separater Schritt (`systemctl restart <unit>.service`), damit ein Restart nie
unbeabsichtigt Downtime auslöst.

## Settings über hermes config set

Alle nicht-geheimen Einstellungen liegen unter
`plugins.entries.hermes-vaultwarden.settings.*` in `config.yaml`. Bootstrap-
Credentials gehören dort **nicht** hin. Die vollständige Liste der Settings
und ihrer Bedeutung steht im [`plugin.yaml`-Schema](../vaultwarden_secret_source/plugin.yaml)
und in [configuration.md](configuration.md).

## UUID-Lookup

```bash
hermes vaultwarden lookup "Suchtext für Item-Name" --collection "Suchtext für Collection"
```

Liefert ausschließlich Metadaten (`id`, `name`, `type`, `collection_ids`,
`available_fields`) — niemals Feldwerte. Ergebnis-UUIDs direkt in
`allowed_item_ids` / `env.<VAR>.item_id` übernehmen.

## Bindings

```bash
hermes config set plugins.entries.hermes-vaultwarden.settings.env \
  '{"SYNTHETIC_API_KEY":{"item_id":"00000000-0000-4000-8000-000000000002","field":"login.password"}}'
```

`field` ist eines von `login.username`, `login.password`, `notes` oder
`fields.<eigener-Feldname>`. Jede referenzierte `item_id` muss auch in
`allowed_item_ids` stehen.

## Diagnose

```bash
hermes vaultwarden status   # sicherer Konfigurations-Snapshot
hermes vaultwarden doctor   # validiert Config + gepinntes Binary + Bootstrap-Env, Exit 0/1
```

Beide Befehle führen keinen Netzwerkzugriff auf Vaultwarden aus und geben nie
Secret-Werte aus.

## Rotation

Zertifikatswechsel/Credential-Rotation erfolgt nicht durch erneutes
`setup --apply` (das ist absichtlich nicht idempotent über geänderte Werte).
Stattdessen:

```bash
sudo python3 scripts/hermes_vaultwarden_bootstrap.py remove --profile <profil> --unit <unit>.service --apply
sudo python3 scripts/hermes_vaultwarden_bootstrap.py setup --profile <profil> --unit <unit>.service --apply
sudo systemctl restart <unit>.service
```

## Upgrade

Ein neues `bw`-Binary erfordert nur ein Update von `binary_path` /
`binary_sha256` über `hermes config set`; die TPM2-Credentials sind davon
unabhängig und müssen nicht neu erstellt werden.

## Uninstall

```bash
sudo python3 scripts/hermes_vaultwarden_bootstrap.py remove --profile <profil> --unit <unit>.service --apply
hermes plugins disable hermes-vaultwarden
hermes plugins remove hermes-vaultwarden
hermes config unset secrets.vaultwarden
hermes config unset plugins.entries.hermes-vaultwarden
```

`remove --apply` stellt bei jedem Fehler den vorherigen Zustand exakt wieder
her (atomarer Snapshot/Rollback) und lässt Credentials anderer Profile
unangetastet.
