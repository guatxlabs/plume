# DR — Restoring Plume backups (SQLCipher)

[Français](DR-plume-restore.md) | [English](DR-plume-restore.en.md)

This runbook covers restoring a Plume backup `plume-<TS>.db.age` (envelope
`age(zstd(…))`) from your object storage (`<votre-bucket>/plume/`), and the **two
backup encryption modes** the product offers.

## First: which backup do you have? The product writes TWO different formats

Do not follow this runbook before you have identified the format in your hands — they are not restored
the same way.

| Produced by | File name | Format | Restore |
|---|---|---|---|
| **Native in‑daemon scheduler** (`PLUME_BACKUP_INTERVAL` > 0 — enabled by the shipped `docker-compose.yml` and `deploy/k3s.yaml`) | `plume-<TS>.db.age` | `age(zstd(…))` envelope — for the PAYLOAD it carries, see "which payload in the `.age`?" below | **this runbook** (`plume-daemon restore`) |
| **Host timer** `plume-backup.timer` (installed by `bootstrap.sh`, daily at 04:00) | `plume-<TS>.db` | **compact SQLite copy** (`VACUUM INTO`), *SQLCipher-encrypted if and only if the database was* — **never** an age envelope | *see below*, not `restore` |

**Restoring a host-timer copy** (`.db`, no `.age`): it is an ordinary SQLite file, so restoring it is a
**file copy**, with the daemon stopped — do not use `plume-daemon restore`, which expects an age
envelope.

```sh
sudo systemctl stop plume-daemon
sudo install -o soc -g soc -m 0600 /var/lib/plume/backups/plume-<TS>.db /var/lib/plume/db/soc.db
sudo rm -f /var/lib/plume/db/soc.db-wal /var/lib/plume/db/soc.db-shm   # WAL of the old database
sudo systemctl start plume-daemon
```
The copy can only be read with the **same SQLCipher key** as the original database: if you had set
`PLUME_DB_KEY`/`PLUME_DB_KEY_FILE`, the same value is needed at restart. If the database was **in
plaintext**, this copy is **in plaintext** — treat it like the database itself.

**Local sink vs object storage.** By default the native scheduler writes to a **local directory**
(`PLUME_BACKUP_DEST`, default `<dir(PLUME_DB)>/backups`): the `mc cp` commands in this runbook only apply
to a deployment that then pushes to object storage. The native `s3://` sink **is not
implemented** — the daemon **explicitly refuses** it and disables itself rather than write a fake
local backup. **A backup that stays on the same volume as the database only protects against logical
corruption, not against losing the volume**: copy it off the machine.

## Next: which PAYLOAD in the `.age`? (recognized by its marker, never by the file name)

A distinction **independent** of the previous one: the one above says *which tool* produced the artifact,
this one says *what is inside it*. Two different payloads travel under the same envelope and under the
**same file name** `plume-<TS>.db.age` — there is **no suffix, no naming convention** that
tells them apart. The **marker at the head of the decompressed payload** decides, and
`plume-daemon restore` reads it on its own: **you need neither to know which one you hold, nor to pass
an option.**

| Marker at the head of the payload | What it is | Where it comes from |
|---|---|---|
| `PLUMEDUMP1\n` | **streaming typed dump** (DDL + rows) — the **default** | a backup that writes **no clear-text file to disk** |
| `SQLite format 3\0` | **full plaintext SQLite copy** | **legacy** path: backups older than streaming, schemas outside its scope (FTS5 *contentless*), or `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1` |

To read the marker by hand, if you want to know before restoring:

```sh
age -d -p < plume-<TS>.db.age | zstd -d | head -c 16 | xxd    # passphrase mode
# -> "PLUMEDUMP1."      = typed dump
# -> "SQLite format 3." = full SQLite copy
```

Practical consequences, to know **before** a timed DR:

- **Backups already in escrow remain restorable** — no migration, no conversion; switching the
  default makes nothing obsolete.
- The typed dump **carries neither the indexes nor the FTS5 shadow tables**: they are **rebuilt** on
  restore. The `.age` is therefore markedly smaller (measured: **×2.4** on a test database with the real
  schema; the gap grows with the mass of indexes — indexes + FTS weighed **43%** of the production file
  on 2026-08-08).
- **In return, the restore takes longer** — and by how much depends on the machine's load,
  because rebuilding indexes and FTS is **pure CPU**. Measured on the same database: **+12%** on an idle
  machine, **+138%** on a loaded machine. **Provision a factor that can approach 2.5× in the RTO**, and
  restore on a lightly loaded machine if time matters. The order, for its part, never flips.

## The cold tier: what a restore of the hot backup does NOT give back

Since Phase 2 aging (`daemon/src/cold_store/aging.rs`), a day sealed into Parquet has its
`event` rows **deleted from the hot database**. The hot database therefore only carries the
`PLUME_COLD_HOT_WINDOW_DAYS` window (**7 days** by default); the rest of the retention
(`PLUME_COLD_RETENTION_DAYS=365`) lives **only** under `PLUME_COLD_DIR=/data/cold`.

**There is no data loss.** The cold day-files are put in safekeeping by the daemon itself
(`P7.20-f`): after each cycle of the native scheduler (`PLUME_BACKUP_INTERVAL` — container and cluster) and
by `plume-backup.timer` in host mode (`plume-daemon cold-escrow <destination>`), as an incremental verbatim
copy under `<destination de sauvegarde>/cold/<tenant>/<env>/<AAAA-MM-JJ>-<NNNN>.parquet` — whatever
ships the destination also ships the cold days. `cold-backup-plan` remains the read-only form for
an external executor. They are already zstd+age-encrypted and immutable: no re-wrap, no clear text. With an
OBJECT destination (`s3://`, `s3_backup` feature), each copy is then uploaded under its key and
confirmed by reading it back; a copy without a confirmed upload is removed from the staging area and retried
on the next cycle (`P7.20-m`).

**What to take away for a DR:**

1. Restoring `plume-<TS>.db.age` alone gives back a SOC that is **functional but truncated**: search will answer,
   and will only see the last 7 days. An incident dated three weeks ago will be **absent without the
   slightest error message**.
2. A complete restore has **two components**: the hot `.db.age` **and** the `cold/` tree of
   the same backup destination, put back under `PLUME_COLD_DIR` before the daemon starts.
3. **Order matters**: drop the cold day-files *before* the first boot. The daemon reads
   `cold_seal` in the restored database; a sealed day whose Parquet file is missing is a silent
   hole, not a boot error.
4. **The binary must carry the feature.** A `plume-daemon` built without `--features cold_tier` ignores
   `/data/cold` and still declares the `PLUME_COLD_*` variables — that is the `P4.5-a` defect, which stayed three
   days in production. **The check, and it is the binary itself that answers** — to run BEFORE dropping
   the day-files, otherwise they would be silently ignored:
   ```sh
   plume-daemon --help | grep cold-backup-plan     # host; in a container: docker run --rm <image> --help | grep …
   # normal help line           -> the feature is there
   # line carrying INDISPONIBLE -> built without --features cold_tier
   ```
   The shipped image is built `ldap,cold_tier` (`ARG PLUME_FEATURES`, `Dockerfile`); **the host recipe, on the
   other hand, compiles bare** — a central installed by `bootstrap.sh` therefore does not have the cold tier by default, and
   `bootstrap.sh` **measures** it at the end of the install (verdict `>> Capacités optionnelles`), refusing to
   conclude rather than announcing an unproven capability. *This repository ships **no** guard on the
   deployment side that would compare the binary's features with what the manifest declares: the check
   above is an **operation**, and the binary/manifest mismatch of `P4.5-a` remains possible.*
5. **What the daily restore-test proves, and what it does not.** It structurally checks the
   **latest hot backup** and refuses to conclude if it is older than 3× the observed cadence. It
   **counts** the cold day-files in escrow and names them, but **does not check them**: when there
   are some, its verdict is `SUCCES PARTIEL — PORTEE : base CHAUDE seule`. Checking both tiers
   remains an **out-of-cluster DR drill** with the escrow age identity.
   Since 2026-09-09 (`P8.10-l`), `restore`, `backup-verify` and `restore-drill status` **say so in
   context**: « cette sauvegarde ne peut pas être restaurée ici … détenteur : … » — the holder is
   the text of `PLUME_BACKUP_ESCROW_HOLDER` (team, vault, procedure); when empty, it is reported as « non déclaré »,
   never invented. Measured in production on 2026-09-09: `restore-drill status` returns « jamais » (code 3) —
   no restore exercise has been recorded yet, so no escrow archive has been
   proven restorable; that is an operation for the operator, with the identity they hold.

**State measured on 2026-08-08 on the reference installation**: all the day-files present on the
disk were **escrowed** (positive witness: the objects under the `plume/` prefix cover them all;
negative witness: 0 under a nonexistent prefix), covering more than a month of history.

## Two backup encryption modes

| Mode | age header | Decrypted with | Where the read key lives | Automated in-cluster check |
|---|---|---|---|---|
| **Passphrase mode** (default) | `scrypt` stanza | passphrase = **SQLCipher key** (`PLUME_DB_KEY`) | wherever `PLUME_DB_KEY` already lives | **full** (decrypts + opens) |
| **age recipient mode** (`PLUME_BACKUP_AGE_RECIPIENT`) | `X25519` stanza | **PRIVATE age identity** (`AGE-SECRET-KEY-1…`) | **out-of-cluster escrow only** (never a k8s Secret) | **structural only** |

**Recipient mode** decouples reading the backups from the database key: the key that decrypts the
history is no longer present where the daemon runs. It is the recommended mode as soon as you can
keep an offline escrow.

- `plume-daemon backup-verify <obj>` prints `kind=Symmetric|Asymmetric`: it is the reliable way to
  know which mode a given object was produced with (the mode can change over the life of a
  deployment).
- `plume-daemon restore` **auto-detects**: it presents **both** identities to age (passphrase +
  private identity if provided) and age matches according to the header's stanza. No option to choose
  by hand.

### The scrypt work factor of passphrase mode (read this BEFORE a DR on an old archive)

Since **2026-08-09** (P8.6-b) plume writes a **FIXED** factor, `log_n = 12` → **4 194 304 bytes**
of buffer, and accepts on read up to **`log_n = 20` → 1 073 741 824 bytes**.

**Before that date, `age` picked this factor through a stopwatch calibration on every
backup.** Measured on 2026-08-09 on a 12-core machine, three calls in a row: `13, 14, 14` in a
*debug* binary but **`19, 19, 20` in *release*** — that is **512 MiB to 1 GiB** of RAM claimed by the
KDF alone, under a budget of 2 GiB, and drawn at random from one backup to the next.

What this changes for a DR:

- **Your symmetric archives from before 2026-08-09 remain restorable** — the ceiling of 20 is
  sized precisely for them — but the restore **will allocate a maximum of 1 GiB** for the duration of the
  KDF. Plan for the RAM on the restore machine.
- A `.age` requiring **more** than `log_n = 20` is **refused**, and the refusal says so: factor required,
  bytes required, ceiling, bytes of the ceiling, and the fact that **the passphrase is not at fault**.
  Recourse: decrypt offline with the `age` tool on a machine that has the RAM, then
  back up again with the current version.
- The symmetric refusal used to be **a function of the restore machine**: `age` capped
  at `target_scrypt_work_factor() + 4`, recomputed by stopwatch wherever decryption happens. Measured: an archive
  at `log_n = 19` was **REFUSED** (`Excessive work parameter for passphrase`) by a debug binary and
  **ACCEPTED** by the same code with the fixed ceiling. Restorability is now a property
  of the **file**, no longer of the machine.
- `PLUME_BACKUP_SCRYPT_LOG_N` (bounded to `[10, 20]`) lets you raise this factor. **It is only useful
  if you know that your `PLUME_DB_KEY` is a phrase typed by a human**: the same secret already protects
  the cold tier at `log_n = 12` (and its day-files go to escrow **as a verbatim copy**),
  so raising the backup alone does not lift any attack floor.
- **age recipient mode has no KDF term**: that is another reason it remains the recommended mode.

## Escrow prerequisites (OUT-of-cluster — operator's responsibility)

1. **SQLCipher key** (`PLUME_DB_KEY`) — to escrow. Required for **any** restore (the restore
   re-encrypts the target DB in SQLCipher with this key), and to decrypt backups produced in
   **passphrase mode**.
2. **Private age identity** — required only in **recipient mode**; generated by the operator,
   escrowed **offline** (never in the cluster):
   ```sh
   age-keygen -o plume-backup-identity.key      # AGE-SECRET-KEY-1... (PRIVATE, offline escrow)
   grep 'public key' plume-backup-identity.key   # age1...  (PUBLIC -> PLUME_BACKUP_AGE_RECIPIENT)
   ```
   The **public key** (`age1…`) goes into the deployment (`PLUME_BACKUP_AGE_RECIPIENT`, non-secret). The
   **private key** NEVER leaves the escrow; it is provided only at the time of a restore/drill.

## ⛔ Recipient mode activation GATE (MANDATORY ORDER)

**DO NOT** set `PLUME_BACKUP_AGE_RECIPIENT` **BEFORE** having generated the pair AND escrowed the
**private** key offline. Otherwise new backups become **undecryptable** (no identity to
read them). As long as `PLUME_BACKUP_AGE_RECIPIENT` is absent, backups stay in **passphrase
mode** (default behavior, byte-for-byte unchanged). Sequence:

1. `age-keygen` → escrow the **private** key offline (+ backup copy). Check that it is readable.
2. Set `PLUME_BACKUP_AGE_RECIPIENT: age1…` (**public** key) in the deployment (the container/sidecar
   that runs the backup) — or, on a **native-host systemd** install, in `/etc/plume/soc.conf`: since
   **2026-08-09** (P8.7-a) every `PLUME_BACKUP_*` setting follows the same precedence
   `env > PLUME_CONFIG > défaut`. *Before that date, this recipient written in `soc.conf` was silently
   ignored and archives went out in passphrase mode again*: if you run a host configured that way,
   your earlier archives are **symmetric** — check them with `backup-verify` before relying
   on them. The daemon names the keys concerned at startup.
3. Apply (your GitOps repository → pod restart). The next backup is encrypted to the recipient
   (check `backup-verify` → `Asymmetric`).
4. Run a **DR drill** (below) with the escrowed private key to PROVE that the new backup
   restores. **Write down the switchover date** in your own operations documentation: earlier
   objects remain in passphrase mode.

## Restoring a backup (real DR)

```sh
# 1) Fetch the object from object storage (here with the MinIO client `mc`)
mc cp <votre-bucket>/plume/plume-<TS>.db.age /restore/plume-<TS>.db.age

# 2a) Backup in PASSPHRASE MODE: the SQLCipher key alone is enough
export PLUME_DB_KEY_FILE=/etc/plume/db/db.key            # or PLUME_DB_KEY=<key> (escrow)
plume-daemon restore /restore/plume-<TS>.db.age /data/soc.db --force

# 2b) Backup in RECIPIENT MODE: SQLCipher key (target) + PRIVATE age identity (source)
export PLUME_DB_KEY_FILE=/etc/plume/db/db.key
export PLUME_BACKUP_AGE_IDENTITY_FILE=/escrow/plume-backup-identity.key   # from the escrow, NEVER in the cluster
plume-daemon restore /restore/plume-<TS>.db.age /data/soc.db --force
```

The destination is the database the daemon will open, its `PLUME_DB`: `/data/soc.db` in the shipped image
(`Dockerfile`), `/var/lib/plume/db/soc.db` on a host installed by `bootstrap.sh` (`/etc/plume/soc.conf`).
Any other destination leaves the daemon on its old database. Restore with the daemon stopped, as for the
host-timer copy. `restore` refuses to overwrite an existing DB without `--force`. The restored DB is byte-replayable
(round-trip proven by the tests).

> ⚠️ **Read the exit code of `plume-daemon restore` ITSELF, never that of a pipe** (`P8.10-k`,
> measured on 2026-09-09 on the binary: a decryption that fails — passphrase or identity missing —
> returns **1**, prints « déchiffrement age … No matching keys found », and **does not create** the destination;
> with `--force` on an existing database, the old database stays **intact**). The **zero** code and the **empty**
> file seen during an incident come from a shell construct, not from the command: through a pipe
> (`… | tee`, `… | zstd -d > fichier`), `$?` is that of the LAST program, and a redirection creates the
> file before anyone has decrypted anything. `set -o pipefail`, or read `${PIPESTATUS[0]}`,
> and never restart the daemon on a destination that `restore` has not announced on standard output.


## Automated check (restore-test) and its accepted degradation

The **in-cluster** restore-test can NOT hold the private identity (putting it in the cluster would ruin the
recipient mode's model). Behavior of `plume-daemon backup-verify <obj>`:

- **Passphrase mode**: `PLUME_DB_KEY` is available → **FULL check**: decrypts, replays into a
  throwaway database, **reopens it with its key and counts its content** (data tables and rows). An
  archive that decrypts and replays but returns **no row** is a **FAILURE** — it is
  precisely the case that a "no error" check let through.
- **Recipient mode**: private identity **absent** → **STRUCTURAL check**: validates the age v1
  header, the recipient stanza (`X25519`), and a plausible size — **without decrypting**. Exit 0 =
  structurally sound; the log clearly states that the full check requires the escrow identity.

In recipient mode, the **full check** therefore becomes a **periodic DR DRILL** (recommended:
monthly), run offline / in a throwaway pod with the escrowed private identity:

```sh
export PLUME_DB_KEY=<clé-escrow>
export PLUME_BACKUP_AGE_IDENTITY_FILE=/escrow/plume-backup-identity.key
plume-daemon backup-verify /restore/plume-<TS>.db.age   # -> full_decrypt_verified=true expected
```

**NEVER** store the private identity in a k8s Secret to automate this drill: that is
precisely the exposure recipient mode eliminates.

## The restore exercise: its trace, and what makes its absence visible

A backup of which **no row has ever been restored** is an untested guarantee. The drill
above takes place offline, on a machine that production does not see: without a trace, nothing
tells "exercise done last month" apart from "never done since the install".

**A successful full check emits an ATTESTATION** — a line on standard output, which
carries only facts produced by the exercise (archive, size, encryption mode, tables and rows
restored) and **no secret**:

```
PLUME-EXERCICE-RESTAURATION-1 {"ts":…,"archive":"plume-<TS>.db.age","archive_octets":…,
                               "chiffrement":"asymmetric","tables":…,"lignes":…}
```

This line is brought back to the node — copy-paste, USB key, `ssh` — **without any private identity
making the reverse trip**:

```sh
# on the exercise machine (isolated, with the escrow identity)
plume-daemon backup-verify /restore/plume-<TS>.db.age > /media/attestation.txt

# on the node (which has never seen the private identity) — native host form
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon restore-drill record < /media/attestation.txt
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon restore-drill status     # exit 0 = tested recently; 3 = an exercise is DUE
```

In Docker and in k3s, both run in the daemon's container, the attestation arriving on standard
input (`-T` for Docker, `-i` for k3s):

```sh
docker compose exec -T soc plume-daemon restore-drill record < /media/attestation.txt
kubectl -n soc exec -i deploy/soc -- plume-daemon restore-drill record < /media/attestation.txt
```

and likewise `restore-drill status`, without redirection. On a native host, `sudo` does not pass on the
unit's `PLUME_CONFIG`: without it, `record` writes the attestation into `/var/lib/plume/db/plume.db` and
`status` reads that same database, which is not the daemon's. `record` writes to the database: on a fresh
node, start the daemon once beforehand, otherwise it creates it in plaintext
([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).

`record` **refuses** an attestation dated in the future (beyond one hour of clock tolerance),
an attestation older than the one already recorded, and an attestation that attests nothing
(zero tables or zero rows).

**What the operator reads without running anything**, once the attestation is recorded:

| Where | What |
|---|---|
| `/api/system/health`, System panel | `restauration` component — `jamais` / `frais` / `perime` / `mode_non_eprouve`, with the age |
| `/metrics` | `plume_restore_drill_overdue` (1 = an exercise is due), `plume_restore_drill_age_seconds` and `plume_restore_drill_last_success_timestamp_seconds` — **absent as long as no exercise has taken place**, because an age of 0 would read as "restored just now" |
| SOC | **non-purgeable** `health` event emitted by every path that publishes an archive — the `backup` subcommand and the daemon's native cycle (daily dedup) — as long as an exercise is due |

Two rules carried by the mechanism, and not by a sentence:

1. **`PLUME_RESTORE_DRILL_MAX_AGE_DAYS`** (default **31**, `0` = tracking disabled and shown as such)
   sets when an exercise goes stale. The state **ages**: it moves on its own from `frais` to
   `perime`.
2. **An exercise carried out on the symmetric path does not close the obligation of an installation that
   escrows asymmetrically** (`PLUME_BACKUP_AGE_RECIPIENT` set): the state is then
   `mode_non_eprouve`, because the path that will serve in a disaster — the private identity outside the cluster —
   has not been taken.

**What this does not prove**, and it is stated here so that it can be held to: the attestation defends against
**forgetting**, not against deliberate falsification — a line can be copied by hand. The
escrow, for its part, stays intact: no private identity lives in the repository, in a test, or in
continuous integration.

## The off-site copy: what plume knows about it, and what it admits

The backup store can live on the same disk as the database: losing that disk then loses
the database AND its backups. The off-site copy is **pulled** by an outside desktop (production
has no access to it). After each verified copy, that desktop asks the node, through a forced
command, to write an attestation file of **one line**, dated by the node's clock:

```
<horodatage unix> plume-AAAAMMJJTHHMMSSZ.db.age <sha256 hexadécimal, 64 caractères>
```

plume reads this file on every health computation (bounded read, no database opened) and publishes
its age. The file's path is never served: the detail names the setting, not its value.

| Setting | Default | Effect |
|---|---|---|
| `PLUME_COPIE_HORS_SITE_ATTESTATION` | empty | path of the attestation file (mountable read-only); empty = copy **not declared** |
| `PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES` | `48` | age beyond which the copy is **stale**; `0` = tracking disabled and said so; a value that is not a non-negative integer is **refused** and named, never replaced by the default |

| State (`copy_state`) | Color | What it says |
|---|---|---|
| `non_declaree` | yellow | no file declared: plume does not know whether the backups leave the disk. Yellow and not `idle`, because `idle` counts as a green in `plume_component_up` and in the posture, whereas this is exactly the risk this component exists to state; not red, because no subsystem is down right now |
| `non_suivi` | `idle` | `PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES=0`, and the detail names it |
| `refusee` | yellow | an expected attestation could not be established; the cause is in `refusal` and the detail says this is **not** "never copied" |
| `fraiche` | green | latest copy within the maximum age (boundary included): age, archive name, fingerprint |
| `perimee` | yellow | latest copy older than the maximum age |

Causes of a refusal (`refusal`): `reglage_age_illisible`, `attestation_absente`,
`attestation_illisible` (errno), `attestation_pas_un_fichier`, `attestation_trop_grande` (size beyond
the read bound, file not read), `ligne_hors_forme` (not exactly one line of three fields separated
by a space, final `\n` allowed), `horodatage_hors_forme`, `nom_d_archive_hors_forme`,
`empreinte_hors_forme`, `datee_dans_le_futur` (more than one hour ahead).

`/metrics` derives `plume_offsite_copy_overdue` (1 = stale) and `plume_offsite_copy_age_seconds` from it,
**absent as long as nothing is established** (not declared, refused, not tracked): an alert is wired on
`plume_offsite_copy_overdue == 1` **and** on `plume_component_up{component="copie_hors_site"} < 1`.

**What this does not prove**: the attestation says that a copy took place, not that it restores
(that is the purpose of the exercise above), and it defends against **forgetting** (a job that no longer
runs), not against a line written by hand.

## Rotation

- **SQLCipher key**: rotation = re-encrypt the live DB; passphrase-mode backups remain
  readable with the **old** key (versioned escrow).
- **Backup age identity**: generate a new pair, set the new **public** key, escrow
  the new **private** one; keep the old private one as long as backups encrypted with the old
  key are within retention (`PLUME_BACKUP_KEEP` window). Decoupled from the SQLCipher key: the two
  rotations are independent.
