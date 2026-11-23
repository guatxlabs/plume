# Encryption and compression, as they are

[Français](CHIFFREMENT-COMPRESSION.md) | [English](CHIFFREMENT-COMPRESSION.en.md)

This document describes **the state of the code**, not an intention. Every claim comes from a reading of the
sources, and the command that reproduces it is written next to it. Where the code proves nothing, it says
"**not established**" rather than filling the gap with something plausible: a security property announced and
not held is worse than an absent property.

It replaces neither [`DR-plume-restore.md`](DR-plume-restore.en.md) — the restore runbook, which
remains the reference for *restoring* — nor [`../deploy/CONFIDENTIALITE.md`](../deploy/CONFIDENTIALITE.en.md),
which gives the posture. It answers: **what is encrypted, by what, in which order, and
what is not.**

---

## 1. The database at rest: new → encrypted; existing → never touched by a startup

**A new database is born encrypted. An existing database is never converted by a startup.** These are
the two halves of `P9.6-a`, and they are independent. SQLCipher is compiled into the binary —
unconditionally, it is not a compile *feature* (`daemon/Cargo.toml`, `rusqlite` with
`bundled-sqlcipher-vendored-openssl`).

```sh
grep -n 'bundled-sqlcipher' daemon/Cargo.toml
grep -n 'PRAGMA key' daemon/src/crypto/mod.rs daemon/src/db_open.rs
```

**"New → encrypted" assumes the daemon opens the database first.** The key is only generated at its
startup. A subcommand that writes to the database (`token`, `sigma-import` without `--dry-run`, `retention`,
`fts-compact`, `purge`, `restore-drill record`, `backup` after its backup) **creates** it if it is
missing, under whatever key is already set: with none, the database is born in plaintext, and the next startup
finds it existing and does not touch it. The safe order in all three modes is in
[`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database).

### The three levers, and the order between them

The precedence order is written **once**, in the code, as an array whose order IS the
rule (`daemon/src/crypto/mod.rs`):

| Lever | What it is | Behavior |
|---|---|---|
| `PLUME_DB_KEY_FILE` | path of a key file that **you** provide | **preferred**; if it is set but unreadable, empty or non-UTF8 → `[FATAL]` message and **process exit**, with no fallback to the other levers |
| `PLUME_DB_KEY` | the passphrase itself | fallback; readable through `/proc/<pid>/environ` if it comes from the environment |
| `PLUME_DB_KEY_AUTO_PATH` | path where the daemon **generates** and reads back its own key | last resort; empty → `<PLUME_DB>.key`. The key is generated **only** on an absent or empty database, and **never** elsewhere |
| `PLUME_DB_KEY_ESCROWED` | escrow acknowledgment (`1/true/yes/on`) | as long as it is absent, every opening of the database writes a **non-purgeable** posture event |

### The property that decides "new database", and why it cannot be wrong in the dangerous direction

Being wrong by calling a new database *existing* leaves it in plaintext: that is the previous default, made no
worse. Being wrong in the other direction would generate a key for a database that has none — and the
next startup would apply to it a `PRAGMA key` it does not understand. The
`etat_du_fichier_de_base` function is therefore written so that the second error does not exist:

* `Neuve` requires **two independent absences**: the main file absent or of zero length,
  **and** no SQLite companion (`-wal`, `-shm`, `-journal`) carrying bytes;
* **any** `metadata` error other than "absent" returns `Indecidable`, which does nothing — this is the
  `S32` fix applied here from the start, rather than the most reassuring verdict;
* and even if the verdict were wrong, the generated key **cannot reach** the path that rewrites
  a database: `ensure_encrypted` decides on `db_key_depuis` (explicit key), the generated key only enters
  through `db_key()` (opening key). The consequence of an error would be a refusal to start, not
  a conversion.

### A new way to lose everything, and what the product says about it

Before `P9.6-a`, losing a key file had no effect on a deployment shipped as is:
there was none. Now, **losing the key of an encrypted database means losing the entire SOC and
all its archives, permanently** — the compressed backup uses the same key as its passphrase.

The product says so **twice**, and never through a mere log line:

1. **at generation**: a message that names the file, says what the encryption protects against
   (disk theft, volume image, badly decommissioned storage) and what it does not protect against
   (compromised machine, where the key is readable next to the database);
2. **afterwards, as long as nothing attests the escrow**: a **non-purgeable posture event**
   (`source=plume-config`, `category=health`, `origin=daemon`, severity 4, at most one per hour),
   that an operator **cannot erase** — same mechanism as "symmetric backup" and
   "cycle without archive". It stops when `PLUME_DB_KEY_ESCROWED=1` is set.

**What this acknowledgment is worth, stated without complacency:** a *declaration*. The product cannot
verify that a copy of the key exists elsewhere, and it does not claim to — the signal's message says so
itself.

```sh
# read the generated key to put it in escrow (Docker)
docker compose exec soc cat /data/plume-at-rest.key
# … then set PLUME_DB_KEY_ESCROWED=1 in .env
```

Each one is read through `cfg()`, hence with the precedence common to the product — `environnement` > configuration
file > default — which means that **on a host, the key can live in
`/etc/plume/soc.conf`** with mode `0640`, outside the process environment. *This was not true before
the `P8.7-b` fix: the hot database only read the environment while the cold tier also read
the file — one half encrypted, the other in plaintext, with nothing saying so.*

The file's content is read **verbatim**: the trailing `\n` is not stripped, deliberately, so that
`fichier` and `environnement` carrying the same secret give the same bytes.

### What the code checks, and what it does not check

**The permissions of a key file that YOU provide are not checked.** Reading
`PLUME_DB_KEY_FILE` is a bare `read`; no mode check, no owner check. A
world-readable key file will be accepted without a word. It is up to the operator to set the permissions.

**The key that the daemon GENERATES, on the other hand, is set to `0600` and its permissions are READ BACK.** The file is
created with `create_new(true)` — it never overwrites an existing file, which also makes harmless
the race between two simultaneous startups — and the mode is requested **at creation**, not by an
after-the-fact `chmod` that would leave a window. If the filesystem does not honor POSIX
permissions (a `fat`, `9p`… mount), **the key is removed** and the daemon refuses to start rather than
leave it readable. The write is **fail-closed**: any write, sync or permission error
gives a `[FATAL]` and an `exit 78`, never a database silently created in plaintext.

```sh
grep -rn '0o600' daemon/src --include='*.rs' --exclude-dir=tests
grep -n 'create_new' daemon/src/crypto/mod.rs
```

### The encryption parameters are not chosen by this repository

**No SQLCipher setting is overridden**: neither `kdf_iter`, nor `cipher_page_size`, nor
`cipher_hmac_algorithm`, nor `page_size`. The values in force are therefore **the defaults of the
SQLCipher version vendored** by `libsqlite3-sys`, not choices made by plume.

```sh
grep -rn 'cipher_page_size\|kdf_iter\|cipher_hmac\|cipher_kdf' daemon/src   # nothing
```

A consequence not to gloss over: **SQLCipher's KDF is not *memory-hard***. The code
says so itself, at the top of the backup module. A weak passphrase therefore protects a stolen database poorly,
however strong the encryption itself.

The key is always passed **in passphrase form** (`PRAGMA key = '<chaîne>'`), never in raw-key form
`x'<64 hexa>'` — including for a tenant key, which is nonetheless 32 bytes of entropy
encoded in hexadecimal. SQLCipher therefore applies its KDF to it. *The exact consequences of this choice
depend on SQLCipher's behavior and **are not established** by reading this repository.*

### Converting an existing database: an explicit, irreversible operation, and what it requires before starting

**No startup converts an existing database.** Neither setting a key, nor changing it, nor upgrading
the image rewrites a database already in service. If a key is configured and the database is **in plaintext**,
the daemon **refuses to start** (`[FATAL]`, `exit 78`), touches nothing, and names the operation.

*This is a change of behavior compared with the previous state, and it is deliberate: the
conversion then happened at startup, without a backup, without proof of equivalence and without a space
check. Crossing a one-way door on a SOC's live data because an environment variable
changed is not a convenience, it is a risk.*

The operation is `plume-daemon chiffrer-au-repos` (engine: `convertir_la_base_au_repos`,
`daemon/src/crypto/mod.rs`). It **refuses to start** as long as the preconditions are not met:

| Precondition | What it establishes |
|---|---|
| an **explicit** key (`PLUME_DB_KEY_FILE` or `PLUME_DB_KEY`) | the key comes from you; the product never converts to a key it would have given itself |
| `PLUME_DB_KEY_ESCROWED=1` | you **declare** that the key is copied off the machine |
| the database is indeed **in plaintext** | `OpensWithKey` → nothing to do (the operation is idempotent); locked → refusal, stop the daemon first |
| **space**: `2,4 ×` the size of the database | the encrypted copy, the safety archive, and the throwaway database of its verification. An **unavailable** measurement counts as a refusal, not fail-open |

Then, in this order — and **the order is unusual for a measured reason**:

1. WAL checkpoint on the original (a WAL fold-back that is refused = refusal, touching nothing);
2. `sqlcipher_export` to `<db>.conversion-en-cours`, **a name the daemon never opens**;
3. **proven equivalence**, four reads all derived from the schema: `PRAGMA integrity_check` on
   the copy; the `sqlite_master` fingerprint object by object, in both directions; the count of **every**
   data table (not a total — two errors that offset each other would pass a total); and the
   **chain of the tamper-proof log**, re-verified on the copy;
4. **backup produced AND verified** — see below;
5. **switchover**: a hard link on the original, then **a single `rename`**, atomic;
6. the conversion **is recorded in the tamper-proof log** (`at_rest.converted`) with what was verified;
7. the plaintext copy is erased (overwrite + `unlink`).

**Why the backup is taken from the COPY and not from the original.** *The obvious sequence —
back up, then convert — is refuted by measurement*: `backup_compressed` opens its source **with
the key** (`PRAGMA key`), and a database in plaintext then becomes unreadable (`SQLITE_NOTADB`); without a key, it
refuses from its first statement. **The product cannot back up a database in plaintext** — this is
exactly the dead end named by `P9.4-b`. The workable sequence is therefore: export → prove
equivalence → back up and verify **from the copy** → switch over.

**What this precondition establishes**: an archive exists at `PLUME_BACKUP_DEST`; it decrypts;
it **replays** into a new database; and this restored database returns the **same number of rows** as
the copy that is about to become the live database. This count is checked against the one produced by the **other**
derivation in the product (`verify_backup` → `inventaire_restaure`): if the two readings of "which
tables carry the data" diverged, the conversion would refuse.

**What it does NOT establish**: that the archive is stored **off** the machine (without an `age`
recipient, it is encrypted by passphrase and the machine decrypts it); that a restore succeeds
elsewhere, on other hardware or another binary; that the rows are **semantically** right
— only their number is compared; nor that the archive survives the *keep-N* retention.

**Asymmetric mode without a private identity is refused**, and it is the most important point:
`verify_backup` then degrades to a **structural** check, which says "the header is well formed", not
"rows come back from it". Accepting that verdict as a precondition for a one-way door would be
exactly what `P8.3-a` named: a green check that bears the word "restore" without having restored
anything. Provide `PLUME_BACKUP_AGE_IDENTITY_FILE` for the duration of the conversion, or convert with
a symmetric archive that can be verified on the spot.

**No intermediate state can be started**, and this is structural: the copy lives under a name the
daemon never opens, the original keeps its own until the `rename`, and there is **no instant** when
`PLUME_DB` designates a half-written file. The hard link before the switchover is not a detail: two
successive `rename` calls would open a window where `PLUME_DB` does not exist — and a startup there would create a
database that is **empty, encrypted, healthy-looking**.

**What is reversible, and what is not.** Before the switchover: **everything**. Every failure leaves
the original intact, and removing the key from the configuration puts the deployment back in its exact state — the
database has not moved by a byte. After the switchover: **nothing**. There is **no decryption at
rest** in this product, and the only way back is the archive verified at step 4.

### Multi-tenant

One database **and one key per tenant**, 32 bytes of entropy from the operating system, with no fallback to
the clock if no entropy source is available. The key reference is resolved **before** any
creation (fail-closed), and forgetting the key is part of the operation that destroys a tenant
(`daemon/src/tenants.rs`).

---

## 2. What is NOT encrypted — the table

This is the most useful part of this document, and the easiest to forget.

| What touches the disk | Encrypted? | Established by |
|---|---|---|
| hot database | **yes, if and only if a key is set** | `daemon/src/crypto/mod.rs` |
| SQLite sort temporaries | **nothing is written by default** (`temp_store=MEMORY`); with `PLUME_SQLITE_DEVERSEMENT=1` → `temp_store=FILE`, and **the values go out in plaintext, outside the SQLCipher database** | `daemon/src/sqlite_plafond.rs` |
| WAL of the main database | **not established** — nothing in this repository sets or checks it; it is a property of SQLCipher | — |
| daemon ingestion spool | **no** — the HTTP body is written as is, then set to `0600` | `daemon/src/ingest/mod.rs` |
| agent spool | **no** — no file-encryption crate in `agent/Cargo.toml`, only transport TLS | `agent/Cargo.toml` |
| Parquet cold tier | **yes**, and **fail-closed**: without a key, no file is written | `daemon/src/cold_store/` |
| backup by the scheduler / `backup --compress` | **yes** (age) — see §3 | `daemon/src/backup/` |
| backup by `plume-daemon backup` without `--compress` | **inherits the state of the source**: the code applies no key to the destination, it runs `VACUUM INTO`. *That the copy is encrypted is a property of `VACUUM INTO` under SQLCipher — **not established** by this repository, no test checks it.* | `daemon/src/main.rs` |
| staging of a compressed backup | **nothing is written by default** (typed dump streamed); on the fallback path — triggered by `PLUME_FTS_FIELDS=1`, or forced by `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` — **the ENTIRE database is rewritten in plaintext** for the duration of the cycle, then erased by overwriting. See §3.2 | `daemon/src/backup/mod.rs` |
| audit log export | **no** — JSONL served in plaintext | `daemon/src/handlers/governance.rs` |
| API responses | in plaintext, except TLS (`PLUME_TLS_CERT`/`PLUME_TLS_KEY`) | — |

**Sort spilling** deserves one more sentence, because it is a trade-off and not a defect:
`temp_store=FILE` lets SQLite sort on disk instead of failing under the memory budget, but
SQLCipher **does not encrypt temporaries**. That is why the lever is **opt-in** and will
never be the default. The directory is set to `0700`; **it is bounded by no quota**.

---

## 3. The backup envelope

### 3.1 Two orchestrators, two outputs — and they do not produce the same thing

| | what triggers it | what comes out | compression | encryption |
|---|---|---|---|---|
| host timer | `plume-backup.timer` → `collectors/backup.sh` → `plume-daemon backup <dest>` | `plume-<horodatage>.db`, rotation at 7 | **none** | inherited from the source |
| internal scheduler | `PLUME_BACKUP_INTERVAL > 0` | `plume-<horodatage>.db.age`, *keep-N* retention | zstd | age |

The timer script calls the subcommand **without** `--compress`; it is the script, not the binary, that
forms the file name.

```sh
grep -n 'plume-daemon backup' collectors/backup.sh
grep -n 'db.age' daemon/src/server/sauvegarde_planifiee.rs
```

### 3.2 The order: compress first, encrypt next

The write chain, read from the outside in, is unambiguous in the code: the
file receives **age**, which wraps **zstd**, which receives the payload.

```
charge  →  zstd  →  age  →  fichier          soit :  age( zstd( charge ) )
```

This is the useful order: compressing after encrypting would gain nothing, ciphertext being
incompressible. Reading is symmetric — age decryption, then zstd decompression.

The **payload** itself has two forms, distinguished **by a marker at the head, never by the file
name**: a streamed typed dump (the default, which writes no transient plaintext) or a full SQLite
copy (historical path, reached by automatic fallback when a schema cannot be represented
as a typed dump).

**WHAT SWITCHES TO THE HISTORICAL PATH, AND WHAT THAT PATH WRITES.** *Established by reading the
sources on 2026-08-30.* The fallback is not theoretical: it is triggered by an **FTS virtual table
without a content table**. `collect_dump_plan` can only recreate an FTS vtable when it is backed
by an ordinary table — which is the case of `event_fts` (`content='event'`) — and returns
`PlanErr::Unsupported` for any other form. Now `PLUME_FTS_FIELDS=1` creates precisely a
`content=''` vtable (`event_fields_fts`). The fallback then runs `sqlcipher_export`, which **rewrites the
ENTIRE database IN PLAINTEXT** into the staging directory for the duration of the cycle, before compressing and
encrypting it. The file is erased by overwriting (`Drop` guard) and a sweep reaps the orphans of a
killed process, but **the window exists and it comes back on every cycle**. Three consequences:

- **enabling full-text indexing of FIELDS is a performance ↔ confidentiality trade-off**, not
  a memory trade-off — that is the real reason why `PLUME_FTS_FIELDS` is `0` by
  default, and the same kind of explicit trade-off as `PLUME_SQLITE_DEVERSEMENT` (§2);
- the log line of each cycle **says which path ran** (`clair-sur-disque=OUI/non`):
  it is the only way to know which of the two forms your installation produces;
- `PLUME_BACKUP_STAGING_DIR` moves this transient plaintext — onto an ephemeral volume, for example —
  and `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` forces the historical path without recompiling.

```sh
grep -n "content=''" daemon/src/maintenance.rs
sed -n '/fn collect_dump_plan/,/Unsupported/p' daemon/src/backup/dump_restauration.rs | tail -5
grep -n 'sqlcipher_export' daemon/src/backup/mod.rs
```

| Constant | Literal value | Where |
|---|---|---|
| backup zstd level | **7** | `daemon/src/backup/mod.rs` |
| stream buffer | **1 MiB** | `daemon/src/backup/mod.rs` |
| compression crate | `zstd` | `daemon/Cargo.toml` |
| encryption crate | `age` | `daemon/Cargo.toml` |
| scrypt factor written (passphrase mode) | **12**, bounded to `[10, 20]` on read | `daemon/src/backup/mod.rs` |

*The compression gain recorded in the code comments, on a test database, is of the order
of **x2.4** compared with the historical format, at the cost of an extra restore overhead.*

### 3.3 Symmetric or asymmetric: what changes is not "encrypted"

| Mode | Condition | Who can decrypt |
|---|---|---|
| **asymmetric** | `PLUME_BACKUP_AGE_RECIPIENT` set (**public** key `age1…`, not secret) | the holder of the private identity, **who does not have to be on the machine** — it is an escrow |
| **symmetric** | no recipient | **the machine itself**: the passphrase IS the SQLCipher key, present on the node |

The symmetric fallback is not silent. Three things happen, all carried by the code:

1. a loud warning on every archive — *« ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS
   d'escrow hors-cluster »*;
2. a **non-purgeable SOC posture event** (`category=health`, maximum severity, fields
   `backup_encryption=symmetric`, `node_decryptable=true`), deduplicated per hour, emitted **only
   when an archive has actually been published**;
3. `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1` **refuses** this fallback — and the refusal comes **before any
   write**, on both paths, so as not to produce a file that would then be rejected.
   Default: `0`.

### 3.4 The precondition of the compressed path: a database key, and where it comes from

**ESTABLISHED BY READING THE TRACKED TREE on 2026-08-30** — through the sources and their literals, no
cycle having been observed (§6). This is the most important point of this document for an operator,
because it decides whether an archive exists — and **the answer depends on the age of the database, not on the deployment
mode.**

The compressed path **requires a passphrase, and that passphrase is the SQLCipher key**. The very
first guard of `backup_compressed` refuses an absent or empty key, and its refusal names the
expected variable:

```rust
let pass = match key {
    Some(k) if !k.is_empty() => k.to_string(),
    _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
};
```

**What fills this argument is `db_key()`, in BOTH production paths**:
the native scheduler (`server::run_scheduled_backup`) and the subcommand
`plume-daemon backup --compress` (`main.rs`) both call it. Now `db_key()` has
**three** provenances, and the third is the **auto-generated** key of `P9.6-a` (§1) — the one the
daemon gives itself on a new database. The table of the three cases:

| State of the database at first startup | Key resolved by `db_key()` | Compressed cycle |
|---|---|---|
| **NEW** (blank volume, PVC or `/var/lib/plume/db`), no key provided | the key **auto-generated** at startup — `0600`, at `PLUME_DB_KEY_AUTO_PATH` otherwise `<PLUME_DB>.key` | **SUCCEEDS**: an archive is written on every cycle |
| **OLDER than `P9.6-a`** and left IN PLAINTEXT, no key provided | **none**: a startup NEVER generates a key for a database that already exists (§1, this is the invariant of the batch) | **REFUSES on every pass**, with the message above |
| any, with `PLUME_DB_KEY_FILE` or `PLUME_DB_KEY` set | the **explicit** key (it wins over the auto one) | SUCCEEDS |

**On an installation done today, in Docker as in k3s, the compressed backup therefore succeeds
without anything to set**: both manifests ship `PLUME_DB_KEY_AUTO_PATH`, the key
is born at first startup, and the cycles publish. It is the CI guard
`check_a_deployment_never_arms_a_task_it_cannot_run.py` that holds this conjunction — a manifest
that would arm the scheduler without shipping any of the three key provenances turns the CI red.

**The hole has not disappeared for everyone, and that is the middle row of the table.** A database
put into service BEFORE `P9.6-a` and left in plaintext has no key and will not receive one: its
scheduler starts every 6 h, fails, and the log is the only immediate witness of it
(`[backup-sched] backup B1 échoué : … (best-effort -> on continue)`). Since `P9.4-b`, a cycle without an
archive also emits a **non-purgeable posture signal**, so the absence is visible elsewhere than
in a log — but **nothing converts this database for you**: you must set an explicit
key, or run the conversion operation described in §1 ("Converting an existing database").

Two consequences to hold together:

- **host mode does not take this path at all**: `plume-backup.timer` calls `plume-daemon
  backup` without `--compress`, that is `VACUUM INTO`, which requires no key. The asymmetry between
  the modes concerns the FORMAT produced (`.db` copy versus `age(zstd(...))` archive), not
  the existence of a backup;
- **the auto key is set by the DAEMON, at its startup** (`server::mod.rs` calls
  `ensure_encrypted`, the subcommand does not). A `plume-daemon backup --compress` run by hand on
  a volume where the daemon has never run therefore finds nothing to read back, and refuses.

To **prove** that you are backed up rather than assume it, the command is
`plume-daemon backup-verify` (§3.5), and an empty destination directory is a failure, not a
silence. The three checks:

```sh
sed -n '/fn backup_compressed(/,/^}/p' daemon/src/backup/dump_restauration.rs | head -8
grep -n 'db_key().as_deref()' daemon/src/server/sauvegarde_planifiee.rs daemon/src/main.rs
grep -n 'PLUME_DB_KEY_AUTO_PATH\|PLUME_BACKUP_INTERVAL' docker-compose.yml deploy/k3s.yaml
```

*What this paragraph corrects: until 2026-08-30, this section described as impossible what
the product has been doing since `P9.6-a` (2026-08-25) — it was written before the auto-generated key
existed and did not follow. The decisions on default encryption remain carried by `P9.6-a`
in [`ROADMAP.md`](ROADMAP.md).*

### 3.5 Restoring, and verifying

- **`PLUME_DB_KEY` is always required at restore time**, even for an asymmetric archive:
  the target database is **re-encrypted with SQLCipher** using this key. An asymmetric archive also requires
  the private identity `AGE-SECRET-KEY-1…`.
- **No hash, no manifest, no checksum** accompanies the archive. Integrity is
  that of age's authenticated encryption: tampering breaks decryption. On top of that come a
  **format marker** at the head of the payload and an **end sentinel** that detects truncation.
- `backup-verify` reads the age header **without decrypting** to say whether the archive is symmetric or
  asymmetric, then, if the necessary identity is available, restores to a throwaway database and
  **inventories its content**: **an empty restore is a FAILURE**, not a silent success.

The complete procedure is in [`DR-plume-restore.md`](DR-plume-restore.en.md).

---

## 4. Compression, wherever it exists

| Where | Codec and level | Enabled by default? |
|---|---|---|
| compressed backup | `zstd`, level **7** (repository constant) | yes, as soon as that path is taken |
| Parquet cold tier | `ZSTD` at the **default level of the `parquet` crate** — this is **not** a choice written in plume | **no**: double lock, the `cold_tier` *feature* at compile time **and** `PLUME_COLD_TIER=1` at run time |
| HTTP responses | **gzip only** — `br`, `zstd` and `deflate` are not compiled | yes, the layer is unconditional |
| OTLP and Pub/Sub ingestion | gzip **de**compression, with an anti-bomb ceiling (`PLUME_OTLP_MAX_DECOMPRESS`) | yes, on compressed bodies |
| Prometheus *remote-write* ingestion | snappy **de**compression, also capped | yes |
| SQLite database | **no compression**: `page_size` is never set, no column is compressed | — |
| `VACUUM` | **never an automatic full `VACUUM`**; only **incremental** auto-vacuum exists, and it is inoperative if the database is not in `auto_vacuum=INCREMENTAL` | **no** (`PLUME_AUTOVACUUM_INTERVAL=0`) |

```sh
grep -n 'BACKUP_ZSTD_LEVEL' daemon/src/backup/mod.rs
grep -n 'set_compression' daemon/src/cold_store/schema.rs
grep -n 'tower-http' daemon/Cargo.toml            # the list of compiled HTTP codecs
```

**What really reduces volume is not a codec.** It is **retention**
(`PLUME_RETENTION_DAYS`), **moving to the cold tier**
(`PLUME_COLD_HOT_WINDOW_DAYS`, which removes the rows from the hot database after sealing) and
**aggregates** (`event_rollup`, with cardinality bounded by a top-N ceiling). No quantified gain is
established here for these three: see [`DESIGN-P10-echelle-2go.md`](DESIGN-P10-echelle-2go.en.md), which
carries the freshest state of this work.

---

## 5. Why it is this way

**One secret, two uses.** The passphrase of the symmetric backup **is** the SQLCipher key.
This choice avoids a second secret to distribute, rotate and lose — at the cost, said plainly,
that a compromised node can read its own archives. The asymmetric age recipient exists
precisely to break this link when an escrow is wanted, and the public key is not a secret:
it can live in plaintext in a versioned manifest.

**Database encryption is opt-in because enabling it is a one-way door.** An encrypted
database can no longer be read without its key; a default that would have converted existing installations
at the first restart would have been worse than the hole. That is the written reason — and it is also what
`P9.6-a` calls into question, with an argument that cuts the other way: the current default protects against nothing, not
even the theft of a disk. **The decision has not been made; this page describes the state, not the outcome.**

**Sort spilling is not a performance setting, it is a confidentiality trade-off.**
Hence the fact that it is opt-in and stays so: the right way is not to write the sorts to
disk, it is to have fewer bytes to sort.

**Refuse before writing, never after.** The fail-closed escrow, the probe before conversion,
the scrypt ceiling, the refusal to conclude on a partial inventory: the same principle everywhere, because
a file produced and then rejected has already touched the disk.

---

## 6. What has not been verified, and why

- **No backup was produced or restored in this batch.** The facts above are established
  by reading the sources and by the literal constants they contain, not by an observed
  cycle. The log line quoted in §3.4 is the one the code writes; it was not collected
  on an installation.
- **WAL encryption** remains **not established**: nothing in this repository sets or tests it.
- **The encrypted content of a `VACUUM INTO` copy** remains **not established** by this repository.
- The **effective SQLCipher parameters** (iterations, page size, HMAC) depend on the
  vendored version and are written nowhere in these sources.
