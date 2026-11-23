# Confidentiality (P4)

[Français](CONFIDENTIALITE.md) | [English](CONFIDENTIALITE.en.md)

## Transport — TLS
The daemon serves HTTP on the loopback by default (bind configurable through `PLUME_ADDR`). For the network, two ways:
- **Native TLS**: `PLUME_TLS_CERT` + `PLUME_TLS_KEY` (PEM paths readable by the daemon's user). An unreadable PEM
  stops the daemon instead of letting it fall back to HTTP; HSTS and the `Secure` attribute of cookies are emitted with this TLS, or behind a proxy (below).
  No client certificate is verified: mTLS is set up on a proxy.
- **TLS termination in front** (the session cookie is only marked `Secure` there, with HSTS, if `PLUME_TLS_TERMINATED_UPSTREAM=1`, or if the proxy is listed in `PLUME_TRUSTED_PROXIES` and sends `X-Forwarded-Proto: https`; otherwise, do not serve the same name in plaintext):
  - **Caddy**: `soc.tondomaine.tld { reverse_proxy 127.0.0.1:7000 }` (automatic Let's Encrypt TLS).
  - **nginx / traefik**: `proxy_pass http://127.0.0.1:7000;` + certificate.
- **k3s**: the shipped Ingress is TLS only (entrypoint `websecure`, certificate from the `Secret` `soc-tls`, see `deploy/k3s.yaml`), `Host` = `PLUME_HOST`.
- Quick self-signed cert: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj /CN=soc.local`.

## Agent authentication — tokens (recommended)
On the central, create one token per machine (revocable, ≠ shared password). **The scope is DECLARED**:
```
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token agent-example agent.example.org   # MACHINE: bound to this host (host attested on write)
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token relais-siem --relais             # RELAY: multi-host forwarder (host NOT attested)
```
This is the native host form: `sudo` does not pass on the unit's `PLUME_CONFIG`, and without it the token
is written into another database than the daemon's. In Docker and in k3s, the subcommand runs in the
daemon's container (`docker compose exec soc plume-daemon token …`,
`kubectl -n soc exec deploy/soc -- plume-daemon token …`). On a new central, the daemon starts **before** any subcommand
([`../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).
The two-argument form (`plume-daemon token <nom>`) is **refused**: it produced an unbound token,
with which an envelope `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` was accepted (202) and stored under that
very name (measured on 2026-08-02). The token is displayed **only once**.

Then on the agent, in `/etc/plume/plume.conf`: `PLUME_TOKEN=<token>`. **Never pass it on a command
line**: `sudo` logs its full command, and the `journal` sensor ships those lines to the SOC —
the token would arrive there in plaintext (see the warning in `README.md`).

**Real scope of an agent token** — an agent Bearer only establishes an identity on the **9 machine
paths** below (closed by default: everywhere else → 401, never any UI/admin access) — see
`agent_bearer_path`, `daemon/src/auth.rs`:

| Use | Paths |
|---|---|
| Ingestion | `/api/ingest` · `/api/ingest/minio` · `/api/ingest/journal` |
| Metrics / logs / traces | `/api/metrics/prom` · `/api/metrics/write` · `/loki/api/v1/push` · `/v1/traces` |
| Responder (actions) | `/api/actions/pending` · `/api/actions/result` |
| Engagement mode (enforcer pull) | `/api/engagements/active` |

Being authenticated is not being authorized: authorization remains `route_min_role` **plus** a
**host-bound** `role=='agent'` re-check in the handler (an agent can only act on its own host's actions).

## At rest — database encryption
- **Native (SQLCipher) — no recompilation needed.** SQLCipher is **already compiled** into the shipped
  binary (`rusqlite` with `bundled-sqlcipher-vendored-openssl`, see `daemon/Cargo.toml`); only the
  **key** is missing. Set `PLUME_DB_KEY_FILE=/chemin/vers/la/cle` (preferred: file mounted read-only,
  **fail-closed** if absent → the daemon refuses to start rather than open the database in plaintext) or
  `PLUME_DB_KEY=<passphrase>` (readable via `/proc/<pid>/environ`), **before the first start**.
  **With no key supplied, a NEW database is born encrypted anyway** (`P9.6-a`): the daemon generates a
  `0600` key at `PLUME_DB_KEY_AUTO_PATH`, otherwise `<PLUME_DB>.key`, and announces it; to be stored safely off the
  machine, then `PLUME_DB_KEY_ESCROWED=1`. It protects against theft of the disk, not against a compromised machine.
  **An EXISTING plaintext database is never converted by a start**: a key set on it makes the start
  refuse, naming the explicit operation `plume-daemon chiffrer-au-repos` (irreversible); a
  database put into service before `P9.6-a` without a key therefore stays in plaintext until that operation has taken place.
  **Losing the key = losing the database.**
  Both variables are read **from the environment OR from `PLUME_CONFIG`** (`/etc/plume/soc.conf`,
  0640, on a systemd host) — the environment wins. **P8.7-b, 2026-08-09**: before that date the path
  that OPENS the database only read the environment, whereas the cold tier also read the file; a
  key set in `soc.conf` alone therefore encrypted the Parquet day-files and left the hot database — the
  latest days, hence the recent incidents — **in plaintext on disk, without a word**. A single path
  now, and the switch is announced at startup on the hosts concerned.
- **Complementary**: putting `/var/lib/plume` on an encrypted volume (LUKS, gocryptfs) also protects the
  files *around* the database (spool, plaintext backups, logs). The two combine.

> **The compressed backup does NOT write plaintext to disk.** `plume-daemon backup --compress` and the
> native scheduler serialize a **typed dump** straight into `zstd` → `age` → `.age` file: the database
> is decrypted **in memory** by SQLCipher, row by row, and no intermediate file is created.
> The staging directory stays empty for the whole backup — this is a **measured** guard, not an
> intention (`backup_streaming_leaves_the_staging_dir_empty_under_watch` watches the directory continuously
> during a real backup, and the same test fails if the historical path is forced).
>
> ⚠️ **Two cases reopen the transient plaintext window**, and you need to know them: (1) a **schema outside
> the scope** of the typed dump (*contentless* FTS5 — hence `PLUME_FTS_FIELDS=1` — or any other virtual table
> that cannot be represented) triggers an **automatic fallback** to `sqlcipher_export`, which materializes the
> **entire database in plaintext** in the staging directory for the duration of the cycle; (2) the explicit escape hatch
> `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1`. In both cases the plaintext is erased by a RAII guard at the end of the
> cycle (with a sweep of orphans at the next backup), but the window exists: then point
> `PLUME_BACKUP_STAGING_DIR` to an **ephemeral** volume, outside durable storage.
>
> In all cases, the destination directory (`PLUME_BACKUP_DEST`) holds encrypted backups
> but must remain as protected as the database. The `plume-daemon backup <fichier>` mode (without `--compress`,
> the one used by the host timer) does a `VACUUM INTO` and stays encrypted end to end if the database is.

## Secrets
Notifier creds / tokens stored in the database or in `0640` config. Multi-host: revocable tokens + encrypted volume. The ledger signing key is `0600` (outside the database).

## Mail sensor — the local recipient of a virus or a banned attachment (`P10.33-f`)
The mail server log sensor (`collectors/mail.sh`) masks every local part of an address it emits
(`*@domaine`, `P10.32-l`). On an amavis INFECTED or BANNED verdict, the analyst therefore does not know which mailbox of
this server was targeted. A named setting makes it readable, **masked by default**:

| Setting | Effect | Default | Risk |
|---|---|---|---|
| `PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL` | `1`: the `rcpt` field of a `malware` (INFECTED) or `banned` (BANNED) event comes out **in plaintext** if its domain is local. Nothing else: the message, `user`, `sender`, external domains and all other events stay masked. `0` or empty: masked; any other value: masked, and admitted (`collect_status=fallback`, `reason=unreadable-config`) | empty (masked) | **real mailbox addresses of this server enter the SIEM**: every role that reads `source=mail` sees them, a stolen database carries them, and they last as long as retention lasts |
| `PLUME_MAIL_DOMAINES_LOCAUX` | what is "local": an **explicit** list of domains, separated by spaces or commas, compared case-insensitively and **exactly** (`sous.example.org` is not `example.org`). Nothing is guessed: the sensor only reads logs, neither `mydestination` nor `virtual_mailbox_domains`. Without a readable list, **nothing is unmasked**, and that is admitted; an unreadable entry is discarded and admitted | empty | a wrong list unmasks mailboxes that do not belong to this server: it is **declared**, nothing verifies it |

The state is shown in the sensor's config envelope (`destinataire_local`: `masque`, `demasque`,
`masque-sans-liste`; `domaines_locaux`: the list retained):
`filters` field of `search source=mail category=config`.

**Where the setting goes, in all three modes.** `mail.sh` runs **on the host**, under `plume-mail.service`, in
all three modes (the source is set by `PLUME_MAIL_SRC`, or detected if it is not: `deploy/MAIL.md`): it reads the log by file (native host, `PLUME_MAIL_SRC=file`), by `docker exec` (Docker)
or by `kubectl exec` in the mail server's pod (k3s). It runs in none of Plume's containers: neither the image
nor `docker-compose.yml` nor `deploy/k3s.yaml` carries it. The setting therefore always goes in the unit's
environment file, `/etc/plume/plume.conf` (`EnvironmentFile=` of `plume-mail.service`):
```sh
PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1
PLUME_MAIL_DOMAINES_LOCAUX="example.org example.net"
```
It takes effect at the timer's next run; removing it restores masking, without erasing what has already been emitted.
