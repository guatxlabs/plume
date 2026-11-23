# The same operation in all three modes — native host · Docker · k3s

[Français](TROIS-MODES.md) | [English](TROIS-MODES.en.md)

Plume claims **three** first-class deployment modes. A document that describes an operation
without saying which mode it applies to only covers one — and leaves the reader of the other two believing
they have misunderstood. This document exists for that reason: **every operational task here carries its form
in all three modes, and where it does not exist in a mode, that is WRITTEN DOWN.**

It complements, without repeating them, installation ([`../README.md`](../README.en.md#installation)) and
uninstallation ([`../README.md`](../README.en.md#uninstallation--all-three-modes)).

> **What this document is not.** It is not a sizing guide, nor a disaster
> recovery procedure — that one is in [`DR-plume-restore.md`](DR-plume-restore.en.md) — nor a
> Kubernetes tutorial. It answers a single question: *"I have read about an operation; what does it look like
> on my setup?"*

---

## 1. The three modes, and where that figure comes from

The three modes are not a marketing promise: they are **enumerated by the code that
removes them**. `uninstall.sh` only accepts three values for `--mode`, and refuses everything else:

```sh
grep -nF 'case "${MODE}" in' uninstall.sh     # -F: the pattern contains ${…}, to be taken literally
```

The mode is also what decides the **form** of each operation below. There is no
hidden fourth mode: an installation assembled by hand is described by no installer in the
repository, and no tool in the repository claims to know it.

| Mode | What runs the daemon | What restarts it | Immutable? |
|---|---|---|---|
| `host` | a systemd unit (`systemd/plume-daemon.service`) | `systemctl` | no — the host's disk is writable |
| `docker` | a container of the `soc` service in `docker-compose.yml` | `docker compose` | **yes** — the image is rebuilt, never edited |
| `k3s` | a pod of the `Deployment` in `deploy/k3s.yaml` | `kubectl` | **yes** — and the pod is replaced on every deployment |

**Almost everything else follows from this "immutable" column.** An operation that writes to the
machine's disk makes sense on a host; on a container it is lost at the next deployment,
and on a cluster it is lost at the next pod restart.

---

## 2. Where things live

Read **from the tracked tree** on 2026-08-25, by reading the installers and the manifests — not an
installation.

| What lives there | `host` | `docker` | `k3s` |
|---|---|---|---|
| binary | `/usr/local/bin/plume-daemon` (placed by `bootstrap.sh`) | image `soc:latest` | image `soc:latest`, imported into `k3s ctr` |
| database | `/var/lib/plume/db/soc.db` | `/data/soc.db` on the `soc-data` volume | `/data/soc.db` on the `soc-data` PVC |
| spool | `/var/lib/plume/spool` | `/data/spool` | `/data/spool` |
| console files | `/usr/local/share/plume/web` | in the image | in the image |
| `config.d` overlays | `/usr/local/share/plume/config.d` | in the image, **read-only rootfs** | in the image, **read-only rootfs** |
| configuration file read by the daemon | `/etc/plume/soc.conf` | **none** | **none** |
| backups | `<dir(PLUME_DB)>/backups` | `/data/backups` | `/data/backups` |

The **compiled default** differs from what the installers set, and you need to know this to read the
code: the daemon looks for its database at `/var/lib/plume/db/plume.db` and its configuration file at
`/etc/plume/plume.conf` when nothing overrides them (`daemon/src/main.rs`). On a host, it is
the systemd unit that sets `PLUME_CONFIG=/etc/plume/soc.conf`, and `bootstrap.sh` that writes
`PLUME_DB=/var/lib/plume/db/soc.db` into that file. In a container, it is the `ENV` lines of the `Dockerfile`.

### The "configuration file" level is EMPTY in a container, and that is deliberate

The precedence is the same everywhere — **`environnement` > configuration file > compiled default**
(`cfg()`, `daemon/src/main.rs`) — but in `docker` mode **and** in `k3s` mode, the file path
is set to `/nonexistent` (`docker-compose.yml`, `deploy/k3s.yaml`, `Dockerfile`). The read fails,
the table is empty, and **the middle level does not exist**: everything arrives through the environment.

Corollary not to be missed: `.env` **is not** that configuration file. It is
`docker compose` that reads it, to interpolate values into the service's `environment:` block —
so **a `.env` variable that the `environment:` block does not list never reaches the
container**. The setting looks set and has no effect.

---

## 3. The same operation, in all three modes

### 3.1 Reaching the console

| | command | note |
|---|---|---|
| `host` | `http://soc.localhost:7000` | `bootstrap.sh` adds `127.0.0.1 soc.localhost` to `/etc/hosts`, and the listener is on `127.0.0.1` |
| `docker` | `http://soc.localhost:7000` | the port is only published on the host's `127.0.0.1` |
| `k3s` | the host of the `Ingress` | it **must** be identical to `PLUME_HOST`, otherwise the anti-DNS-rebinding guard returns `421` |

In all three cases, `PLUME_HOST` and the name actually requested must match. It is the same
guard, applied in the same place; only the way of writing the name changes.

### 3.2 Setting or changing a `PLUME_*` setting

**No mode has a reload operation.** The daemon's unit has no `ExecReload=`, and the daemon
installs no `SIGHUP` handler: nowhere is there a command that tells the daemon
"reread your configuration". The two checks:

```sh
grep -c ExecReload systemd/plume-daemon.service          # 0 — the daemon's unit has none
grep -rn 'SIGHUP' daemon/src --include='*.rs'            # nothing
```

*(Another shipped unit, `plume-portscan-nft.service`, does carry an `ExecReload=`: it reloads
an nftables table, not plume's configuration.)*

#### What really decides: the MEDIUM, not the operation

The reload operation is missing everywhere, but that is not what limits the matter. What limits it
is **the medium from which a new value could be read**. The precedence is
`environnement > fichier de configuration > défaut compilé` (`cfg()`, `daemon/src/main.rs`), and
the environment of a process **that is already running no longer changes**: only the "file" level can carry
a new value during the daemon's lifetime. And that level is cut off in a container (§2).

| | medium for a new value, daemon running | consequence |
|---|---|---|
| `host` | `/etc/plume/soc.conf`, reread on every read that goes through `load_config()` | a hot reload is **possible**, and part of it already exists (see §3.7) |
| `docker` | **none** — `PLUME_CONFIG=/nonexistent` (`docker-compose.yml`, `Dockerfile`) | nothing to reread: hot reload is **impossible by construction**, not merely unimplemented |
| `k3s` | **none** — `PLUME_CONFIG=/nonexistent` (`deploy/k3s.yaml`) | likewise; and the pod is **replaced** anyway to apply a modified `env:` |

In other words: **a hot reload could only serve the `host` mode.** In the other
two, changing a setting means replacing the container — the restart is not the price of
reconfiguration, it *is* the deployment mechanism. This is a known limitation carried by an open
key — see `P9.4-a` and `P9.6-b` in [`ROADMAP.md`](ROADMAP.md).

| | where to write | what applies it |
|---|---|---|
| `host` | `/etc/plume/soc.conf` (`0640`, `root:soc`) — or the unit's environment | `sudo systemctl restart plume-daemon` |
| `docker` | `.env` **and** the `environment:` block of the `soc` service (both, see §2) | `docker compose up -d` |
| `k3s` | the `env:` block of the `Deployment`, or the `Secret` `soc-auth` for a secret | `kubectl apply -f deploy/k3s.yaml` then `kubectl -n soc rollout restart deploy/soc` |

A **secret** is preferably set through a file rather than a variable: on a host, the
`0640` configuration file is not readable through `/proc/<pid>/environ`, unlike the environment;
on k3s, `PLUME_DB_KEY_FILE` points to a `Secret` mounted read-only (the lines ship
commented out in `deploy/k3s.yaml`).

### 3.3 Adding a collection source

This is where the modes diverge the most, and the document must say so instead of smoothing it over.

| | operation | reality |
|---|---|---|
| `host` | `PLUME_EXTRA_COLLECTORS="…"` then `bootstrap-agent.sh`, then `systemctl enable --now plume-<x>.timer` | the NATIVE operation; it is the procedure in the [`README`](../README.en.md#adding-your-sources-and-collectors) |
| `docker` | **this operation does not exist** | *(see below)* |
| `k3s` | **this operation does not exist** | *(see below)* |

**Measured on the tracked tree on 2026-08-25**: the `Dockerfile` copies **no** file from
`collectors/` into the image (`grep -n collectors Dockerfile` returns nothing), and
`PLUME_EXTRA_COLLECTORS` is only read by `bootstrap-agent.sh` — nowhere in the daemon:

```sh
grep -rn 'PLUME_EXTRA_COLLECTORS' daemon/src collectors bootstrap.sh bootstrap-agent.sh Dockerfile
```

In other words: **the containerised central is not its own agent.** The shell collectors are
a host artefact. What you do instead, in a container and in a cluster:

1. **An agent on a neighbouring machine** that pushes to the central (`POST /api/ingest`, *Bearer*
   token) — a Linux host with `bootstrap-agent.sh`, the endpoint agent from [`../agent/`](../agent/README.en.md),
   or the Windows collector from [`../collectors/windows/`](../collectors/windows/README.en.md);
2. **a PULL source** declared in the console (*Données* space → *Connecteurs de sources* tab, admin) — the daemon
   fetches, nothing is installed anywhere;
3. **a receiver** that the central already exposes: Splunk HEC, OTLP, syslog
   ([`../deploy/SYSLOG.md`](../deploy/SYSLOG.en.md)).

These three paths exist in all three modes. It is the **fourth** — installing a script on the
central's machine — that only exists in host mode.

### 3.4 Adding a parser, a rule, a playbook

| | through a file | through the console |
|---|---|---|
| `host` | drop it under `PLUME_CONFIG_DIR` (`/usr/local/share/plume/config.d`) then restart | yes, admin role; the row is marked "custom" |
| `docker` | **impossible without rebuilding the image or mounting a volume** — the container's root is read-only | yes, same operation |
| `k3s` | through a `ConfigMap` mounted on `PLUME_CONFIG_DIR`, otherwise impossible | yes, same operation |

The two paths do not produce the same thing, and that is deliberate: a file overlay is
marked `managed=1` (source = the versioned repository), a creation through the console is marked
`managed=2` (custom). **A custom item with the same name causes the file overlay to be IGNORED**, with a warning
at startup, rather than silently overwriting the operator's work
(`daemon/src/overlays.rs`). In a container and in a cluster, where the file is awkward, **the console
is the normal path** — and the file remains the durable source where it is practical.

### 3.5 Creating an agent token

The same subcommand, reached in three ways.

| | command |
|---|---|
| `host` | `sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token <nom> <hôte-lié>` (`sudo` does not pass on the unit's `PLUME_CONFIG`: without it, the token is written into `/var/lib/plume/db/plume.db`, a different database from the daemon's) |
| `docker` | `docker compose exec soc plume-daemon token <nom> <hôte-lié>` |
| `k3s` | `kubectl -n soc exec deploy/soc -- plume-daemon token <nom> <hôte-lié>` |

*Not run on a real installation in this batch* — the two-argument form and the
`--relais` flag are those described in the [`README`](../README.en.md#b-bare-host-systemd--a-first-class-mode-without-docker).
The token is displayed once; it cannot be read again.
On a new central, the daemon starts **before** the first subcommand: in `docker` and `k3s`,
`exec` enforces this (the daemon's container must be running); in `host`, a subcommand run before the
first start causes the database to be born in plaintext
([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).

> ⚠️ **The token NEVER goes through the command line on the agent side**, in any mode: `sudo`
> logs its full command line and the `journal` collector sends it back to the SOC, which stores it in plaintext.
> The safe form — writing through `tee` — is in the [`README`](../README.en.md#-never-pass-the-token-on-the-command-line).

### 3.6 Reading the daemon's logs

| | command |
|---|---|
| `host` | `journalctl -u plume-daemon -f` |
| `docker` | `docker compose logs -f soc` |
| `k3s` | `kubectl -n soc logs -f deploy/soc` |

This is where the SETUP mode **installation token** is read when no `PLUME_PASS_HASH` is
set. In host mode it is also written next to the database
(`/var/lib/plume/db/setup-token.txt`, see `bootstrap.sh`).

### 3.7 Backing up

**The two backup orchestrators do not have the same output**, and that is the trap of this
chapter. The details — envelope, order of operations, what is encrypted and what is not —
are in [`CHIFFREMENT-COMPRESSION.md`](CHIFFREMENT-COMPRESSION.en.md); restoration is in
[`DR-plume-restore.md`](DR-plume-restore.en.md).

| | what triggers it | what comes out |
|---|---|---|
| `host` | `plume-backup.timer` (daily) → `plume-daemon backup` | a compact copy, **uncompressed**, rotation of 7 |
| `docker` | the daemon's internal scheduler, if `PLUME_BACKUP_INTERVAL > 0` | the scheduler's envelope |
| `k3s` | likewise, `PLUME_BACKUP_INTERVAL` set in the shipped manifest | likewise |

To **align a host with the internal scheduler**: set `PLUME_BACKUP_INTERVAL` in
`/etc/plume/soc.conf` and turn off the timer (`systemctl disable --now plume-backup.timer`). Leaving both
running produces two families of backups in the same directory, with two independent
rotations.

#### Changing a backup setting: two groups, not one

The `PLUME_BACKUP_*` settings **are not all reloaded the same way**, and the difference is
invisible from their names. Read from the tracked tree on 2026-08-27:

| Group | Keys | When the value is read |
|---|---|---|
| encryption and escrow | `AGE_RECIPIENT` · `REQUIRE_ASYMMETRIC` · `FORCE_PLAINTEXT_EXPORT` · `SCRYPT_LOG_N` · `STAGING_DIR` · `AGE_IDENTITY[_FILE]` | **on every cycle** (`reglage_sauvegarde`, `daemon/src/backup/mod.rs`) |
| activation, cadence, target, retention | `INTERVAL` · `DEST` · `KEEP` · `ON_START` | **only once**, when the thread is started (`spawn_backup_scheduler`, `daemon/src/server/sauvegarde_planifiee.rs`) |

Consequence, **in `host` mode only** (it is the only mode where the "file" level exists, §3.2):
correcting an escrow recipient in `/etc/plume/soc.conf` takes effect **from the next cycle, without a
restart**. Correcting the interval, the destination or the retention **requires** a restart. In
`docker` and in `k3s`, both groups require replacing the container, for lack of a medium to reread.

#### What a restart costs, written down nowhere else

> **Until 2026-09-08, restarting the daemon reset the backup cadence to zero.** The
> scheduler kept no record of its last run: a 90 s wait (bind and *liveness*),
> then a **full** interval of sleep before its first cycle. With the shipped interval (`21600` s,
> i.e. 6 h), each restart pushed the backup back by 6 h 1 min 30 s, and a pod that restarts more
> often than its interval — deployment, `rollout restart`, eviction, `OOMKill` — **never produced
> a single archive**, while the console announced "24 × 6 h" next to an empty directory.
> The SOC signal for a barren cycle (`P9.4-b`) did not cover this case: it is only emitted by a cycle
> that runs.
>
> **Since `P9.4-a` (2026-09-08), the first wait is DERIVED from the most recent regular archive
> in the destination** (`premiere_attente_derivee`, `daemon/src/server/sauvegarde_planifiee.rs`): no
> archive, or an archive older than the interval → backup **immediately** after the 90 s;
> a fresh archive → the **remainder** of the interval. A restart therefore no longer pushes the cadence back, a
> looping process does not produce a storm either (as soon as an archive exists, it waits for the
> remainder), and the daemon **says so** at startup ("première sauvegarde dans N s"). The scheduler reads what
> it writes itself — no new state, no secret. `PLUME_BACKUP_ON_START=1` remains the operation that
> **forces** a backup even when a fresh archive exists. What remains true: **check the directory
> rather than the setting**, in all three modes:
> ```sh
> ls -la "$PLUME_BACKUP_DEST"     # host; docker/k3s: the same command through `exec` (§3.5)
> ```
> A `PLUME_BACKUP_DEST` without any `plume-<TS>.db.age` is a deployment **without backups**, whatever
> the retention announced next to it.

### 3.8 Encrypting the database at rest

In all three modes, **a NEW database is born encrypted**: without a provided key, the daemon generates its own
on first start (`0600`, at `PLUME_DB_KEY_AUTO_PATH`, otherwise `<PLUME_DB>.key`) — to be copied off the
machine, then `PLUME_DB_KEY_ESCROWED=1`. **An EXISTING database that is still in plaintext is never converted by
a start**: a key set on it makes the start refuse, naming the explicit operation
`plume-daemon chiffrer-au-repos` ([`CHIFFREMENT-COMPRESSION.md`](CHIFFREMENT-COMPRESSION.en.md)). Bringing
**your own** key is therefore done **before the first start**, and the medium differs by mode:

| | how |
|---|---|
| `host` | `PLUME_DB_KEY_FILE=/chemin/vers/la/cle` in `/etc/plume/soc.conf` |
| `docker` | `PLUME_DB_KEY` through `.env` (already listed in `environment:`), or a mounted file and `PLUME_DB_KEY_FILE` |
| `k3s` | the `Secret` `soc-auth`, mounted read-only; the lines ship **commented out** in `deploy/k3s.yaml` |

The file is preferable to the variable in all three modes: a process's environment is
readable through `/proc/<pid>/environ`. **Losing the key = losing the database.**

### 3.9 Updating

| | operation |
|---|---|
| `host` | recompile (`cargo build --release` — **bare build: two capabilities fewer**, see below the table), rerun `bootstrap.sh` (idempotent) |
| `docker` | `docker compose up -d --build` |
| `k3s` | rebuild the image, reimport it into `k3s ctr`, then `kubectl -n soc rollout restart deploy/soc` |

**These three rows do not rebuild the same binary, and the table alone does not show it.** The two
rows that go through the image inherit a feature set declared once and for
all — `ARG PLUME_FEATURES=ldap,cold_tier` in the [`Dockerfile`](../Dockerfile), since `971de7a`
(2026‑08‑08). The `host` row is **bare** and takes **none**. A host binary built this way has **neither the
columnar cold tier** — `PLUME_COLD_TIER` has no effect on it, and Parquet day files written by
another binary are invisible to it — **nor native LDAP/AD bind**: `POST /api/auth/ldap` answers **501**.
To get them: `cargo build --release --features cold_tier,ldap`. The bare default is **intended, not
accidental** (the build cost of `cold_tier` is not bounded by any measured figure; the header of
`bootstrap.sh` says so), but it must not be **suffered unknowingly**: this is why `bootstrap.sh` **measures**, at the end
of installation, what the installed binary carries — verdict `>> Capacités optionnelles`, obtained by querying
`plume-daemon --help` — and **refuses to conclude** rather than announce an unproven capability. This
automatic check only covers the cold tier; for the directory, the proof is the **501** answer from the
login route.

**No image and no binary are published to date**: all three paths compile from
source. It is an acknowledged gap, written in the [`README`](../README.en.md#installation).

An update that changes the database schema is a **one-way door**: it requires a
verified backup beforehand, and an explicit acknowledgement. See [`DR-plume-restore.md`](DR-plume-restore.en.md).

### 3.10 Uninstalling

A single tool, three modes, the mode is **named explicitly**:

```sh
bash uninstall.sh --dry-run                  # inventory of the three modes, no root, nothing modified
sudo bash uninstall.sh --mode host
sudo bash uninstall.sh --mode docker
bash uninstall.sh --mode k3s --apply
```

**The first line was run as-is on this tree**: it probes the three modes, modifies
nothing, and exits with `0`. On a machine with no reachable cluster, it does NOT conclude "there is
nothing" — it files k3s under *impossible probes* and says so. The other three, which write,
**were not run in this batch**.

The complete semantics — what `--purge` destroys, the exit codes, what resists and why —
are in the [`README`](../README.en.md#uninstallation--all-three-modes). The `k3s` mode **prints** its
plan and only executes with `--apply`, because it touches a shared cluster.

### 3.11 Setting the gesture secret

Creating an account, promoting an administrator, resetting the password of **another** account,
minting a token (agent, HEC, data source, client) or a delivery key (push source), setting
or reconfiguring an identity provider, opening an engagement (Engagement mode, all boxes: greybox
and whitebox mint an account, blackbox suspends auto-ban on its scope), and — in multi-tenant mode — setting a tenant permission or the
first administrator of a tenant require, **on top of the permission**, the gesture secret in the
`x-plume-secret-des-gestes` header. This holds for every administrator, whatever their
authentication mode (local session, header SSO, federation, Basic). **Without a secret set, these
operations are refused** (403, `cause: secret_des_gestes_non_configure`), and the refusal says how to set it.

The daemon only knows the **hash** of the secret (argon2id, PHC format), read from the file named by
`PLUME_GESTURE_SECRET_FILE`. Never the plaintext secret, neither in the database nor in the environment. The same
subcommand generates the hash in all three modes:

```sh
# the secret is displayed ONCE on standard error; only the hash goes into the file
plume-daemon secret-des-gestes --generer > secret-des-gestes.phc
# or, with a chosen secret (≥ 16 characters), read from standard input — never as an argument
plume-daemon secret-des-gestes < fichier-qui-porte-le-secret > secret-des-gestes.phc
```

| | where the file lives | what points to it |
|---|---|---|
| `host` | `/etc/plume/secret-des-gestes.phc`, `0640`, `root:soc` (`sudo /usr/local/bin/plume-daemon secret-des-gestes --generer \| sudo tee /etc/plume/secret-des-gestes.phc >/dev/null`) | `PLUME_GESTURE_SECRET_FILE=/etc/plume/secret-des-gestes.phc` in `/etc/plume/soc.conf`, then `sudo systemctl restart plume-daemon` |
| `docker` | a compose secret mounted as a file (`secrets:` → `/run/secrets/secret-des-gestes`); the hash is generated with `docker compose run --rm -T soc secret-des-gestes --generer > secret-des-gestes.phc` | `PLUME_GESTURE_SECRET_FILE=/run/secrets/secret-des-gestes` in the `environment:` block of the `soc` service (lines shipped commented out in `docker-compose.yml`), then `docker compose up -d` |
| `k3s` | a key of the `Secret` `soc-auth`, mounted read-only (volume `secret`, **without** `subPath`) | the variable in the `env:` block of the `Deployment` (lines shipped commented out in `deploy/k3s.yaml`), then `kubectl -n soc rollout restart deploy/soc` |

**The variable is read at startup; the file, at every operation.** Rotation is therefore a
replacement of the file, without a restart — a Kubernetes secret mounted without `subPath` is updated
under the pod; on Docker, a file rewritten in place (same inode) is seen, a file replaced by an
editor that changes the inode is only seen at the next `docker compose up -d`. A file that is removed, empty,
unreadable or that carries anything other than an `$argon2id$…` hash closes the operations at the next operation.

A **wrong** secret counts towards the same throttle as login failures (account, address pair;
backoff; `429` beyond the `PLUME_AUTH_LOCK_THRESHOLD` threshold) and is recorded in the register with the author
— never the secret. A missing header is not an attempt.

*Not run on a real installation in this batch*: the three rows of the table. The subcommand
and the judgement of the file (rotation, removal, plaintext refused) are exercised by the `sdg_` witnesses
(`daemon/src/tests/secret_des_gestes_demonstration_freinee_et_pose_de_l_administrateur.rs`).

---

## 4. The operations that do not exist, named

A table of equivalences is dishonest if it fills every cell. Here are the ones that remain
empty, and why.

| Operation | Absent in | Measured reason |
|---|---|---|
| installing a shell collector on the central's machine | `docker`, `k3s` | `collectors/` is not copied into the image (`Dockerfile`) |
| dropping a `config.d` overlay through the file system | `docker` | container root is read-only (`read_only: true`) |
| reading a setting from a configuration file | `docker`, `k3s` | `PLUME_CONFIG=/nonexistent` — deliberate, see §2 |
| editing `/etc/hosts` for local resolution | `k3s` | resolution goes through the `Ingress` and the cluster DNS |
| applying an egress `NetworkPolicy` | `host`, `docker` | it is a Kubernetes object; the host equivalent is the machine's firewall |
| reloading the backup activation, cadence, target or retention without a restart | **all three** | read only once when the thread is started (`spawn_backup_scheduler`) — see §3.7 |
| reloading **anything at all** without a restart | `docker`, `k3s` | no medium to reread: frozen environment + `PLUME_CONFIG=/nonexistent` — see §3.2. Only exception: the gesture secret **file**, reread at every gesture (§3.11) |
| requesting a reload through a signal or a command | **all three** | no `ExecReload=`, no `SIGHUP` — see §3.2 |

---

## 5. Why it is this way

**A single binary, three wrappers.** A single *program* — but not necessarily the same set of
**compiled** capabilities: the image build takes two that the host recipe leaves out (see §3.9). The daemon itself does not
know which mode it is running in, and that is intended: it reads variables and paths, nothing else.
Everything that distinguishes the *modes* lives **outside** the binary — in a systemd unit, in a
`docker-compose.yml`, in a manifest. The price of this choice is exactly this document: the operational
tasks, for their part, differ.

**The "file" level is cut off in a container for a reason.** Letting the daemon read
`/etc/plume/plume.conf` in an image where that file does not exist would make its behaviour depend
on a file that nobody versions, and that an unfortunate `docker cp` could create. `/nonexistent`
makes the level **explicitly** empty rather than accidentally empty.

**Install without enabling.** This is the golden rule of host mode: `bootstrap-agent.sh` installs the
requested sensors without arming their timers, and the operator decides. Three units are exceptions
and are armed automatically — `resources`, `integrity` and `ship` (`systemctl enable --now` at the end of the
script) — and `bootstrap.sh`, on the central, arms seven (the README counts them). In a container, the rule takes another
form — the receivers exist but only ingest what is sent to them, and the PULL
connectors are created one by one in the console.

**Cluster mode says what to do rather than doing it.** A cluster is shared; a tool that
applies a plan to it without showing it commits resources that do not belong to it. This is why
`uninstall.sh --mode k3s` prints and only executes on request — and it is the same principle that means
no operation in this document modifies a manifest on your behalf.

---

## 6. What was not run

Instrument honesty: the structural facts of this document (paths, variables, absence of
`collectors/` in the image, absence of `ExecReload=`, value of `PLUME_CONFIG`) are **read from
the tracked tree** and each carries the command that reproduces it. On the other hand, **none of the
deployment sequences was run on a machine in this batch**: the `docker compose`, `kubectl`
and `systemctl` commands are taken from the shipped manifests and installers, not from an observed
deployment. An operation that fails on your setup is a defect to report, not a misreading on
your part.
