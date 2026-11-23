# plume-agent — cross-OS endpoint agent (#16)

[Français](README.md) | [English](README.en.md)

A **standalone** binary installed **on the desktop** (endpoint), not in the SOC pod. It reads the OS's
**native** event sources, buffers them on disk (bounded spool, *at-least-once*), and POSTs them
to the Plume ingest endpoint — the same wire contract as the `.sh` collectors and the HEC emitter.

## Implementation status

| Component | State |
| --- | --- |
| CLI `run/install/uninstall/status/test-ship` | **complete** |
| TOML config + per-OS paths | **complete** |
| Envelope contract (`ts/host/kind/events[]`, event `ts/source/category/severity/message/fields/dedup`) | **complete** |
| **journald** source (Linux) | **FULLY implemented** (`journalctl -o json --after-cursor`, persisted cursor, `to_event`) |
| Bounded ring disk spool + backoff (503-aware) + post-ack cursors | **complete** |
| HTTP/1.1 shipping (TCP + rustls, Bearer/Basic, internal CA, mTLS, insecure) | **complete** |
| **systemd** service (Linux) install/enable/start + hardening | **complete** |
| **Windows Event Log** source (`EvtQuery/EvtNext/EvtRender` + `EvtCreateBookmark`) | **implemented** — *runtime validation DONE: Windows 11 24H2 (2026‑08‑02) **and** Windows Server 2022 build 20348, on **Server Core** as well as Desktop Experience, including promoted to domain controller* |
| **macOS unified log** source (`log show --style ndjson`) | **implemented** (`cfg(macos)` subprocess; pure CIM mapping tested on Linux) — *runtime validation: macOS host* |
| **launchd** service (macOS) install/enable/start (`launchctl bootstrap`) | **implemented** (plist tested) — *runtime validation: macOS host* |
| **Windows SCM** service (`create_service`/dispatcher) via `windows-service` | **implemented** — *runtime validation DONE: `install` creates and starts the service (Running, StartMode Auto) on Windows 11, on Server 2022 **Server Core** (no dependency on the graphical interface) and on a domain controller* |
| **Native FIM** source (#58: `type = "fim"`) | **implemented** — Linux `fanotify`→`inotify` (real); **scheduled scan** fallback on the other OSes; Windows `ReadDirectoryChangesW` **written, compiled in CI (`agent-cross`, `--features fim_windows_native`), not validated at runtime** — off by default until a Windows host has exercised it. Diff/baseline/CIM core **tested**; fanotify/inotify syscall path → *runtime validation: Linux root host* |
| **Generic DECLARATIVE** sources (#66/#67: `file` / `command` / `http`) + `regex`/`delimiter` parser | **implemented** — offset-cursor tail (rotation handled), timed command/URL polling, field extraction with named groups. Line→event mapping + tail + parser **tested**. See [`examples/sources.toml`](examples/sources.toml) |

### CIM mapping of the native sources

- **Windows Event Log** (`WinEventLog:<canal>`, categories `auth`/`exec`/`network`/`dns`/`endpoint`):
  `4625`→`auth` (failure, severity 3), `4624/4634/4672/…`→`auth`, `4688`→**`exec`**, `1102`/`7045`→`endpoint`;
  **Sysmon** ID `3`→`network`, `22`→`dns`, otherwise `endpoint`. Cursor = XML bookmark `<BookmarkList>` (multi-channel).
  *(`4688`→`process` used to be written here: that has been wrong since 2026‑07‑23. the agent's classification (`classer`) emits `exec`, the
  canonical CIM v1.3 name; `process` does not belong to `CIM_CATEGORIES`. Measured on 2026‑08‑02 on Windows 11
  Enterprise 24H2 (build 26100): the 4688 events forwarded by the agent arrive as `category=exec`.)*
  **Everything not listed above leaves with an EMPTY category** — this is not marginal:
  *measured on 2026‑08‑02, 1,572 of the 5,189 Windows events (30%) arrived without a category*, including
  834 from the `Security` channel and 604 from the `System` channel. The CIM field `action` (neutral vocabulary,
  `docs/CIM.md` §4c) is **never** set by this reader: **0 / 5,189** Windows events carry it.
  *Both gaps were **reconfirmed on 2026‑08‑02 on two Windows Server 2022 machines** (Server Core +
  Desktop Experience promoted to domain controller), so on another OS and another machine profile:
  **2,552 / 6,962 (36.7%)** without a category — `Application` **100%**, `Security` **43.6%**, `System`
  **41.8%**, Sysmon **0%** — and **0 / 6,962** with `action`. These are not desktop accidents: they
  are two product defects.* The PowerShell collector, for its part, always sets a category (0 / 1,505 empty)
  but **never** `action` either (0 / 1,505): the `action` gap is common to both emitters.
  **`dedup` key**: `win-<hôte>-<canal>-<EventRecordID>`. *The host name was added to it on 2026‑08‑02: without
  it, two machines overwrote each other (`event.dedup` is UNIQUE at the database level) — 45
  Sysmon records silently lost out of 311, measured, fixed, re-verified. Full detail and proof
  in `collectors/windows/README.md`, "the fleet trap".*
- **macOS unified log** (`source=subsystem`): `sshd/sudo/su/authd/…` or subsystem `*auth*`/`*ssh*`→`auth`;
  subsystem `*network*`→`network`; otherwise empty category (the server-side dparser decides). `messageType`
  `Error`/`Fault`→severity 3. Cursor = last `timestamp` (`log show --start`), dedup via `traceID`.
- **Native FIM** (`source=integrity`, `category=integrity`): emits EXACTLY the CIM contract of the endpoint
  ingest #57 (same `fim_*` fields) — the `search source=integrity` panel, the `integrity` health rollup
  and the #57 views light up identically, WITHOUT any daemon change. `fim_event` ∈ `added|modified|deleted`
  (severity `1|2|3`), `fim_mode` = `realtime` (fanotify/inotify) or `scheduled` (scan fallback), + `fim_sha256`
  (/`_before`), `fim_size`, `action` (`modify|delete`), `fim_change` (`created|content|attrs|deleted`) and a
  `path`/`sha256`/`change` mirror (`integrity.sh` style). Pure-Rust SHA-256 digest, bounded by
  `hash_max_bytes`. Path→hash baseline **persisted** (`<state_dir>/fim-<id>.baseline.json`) → no
  re-alert on reboot; 1st run = silent seed. **STRICTLY observational** (no write/remediation).

## Wire contract

- Envelope events → `POST {endpoint}/api/ingest`:
  `{"ts":<epoch>,"host":"<h>","kind":"events","events":[{ "ts","source","category","severity","message","fields"[,"dedup"] }]}`
- **raw** journald (ndjson, 1 object/line) → `POST {endpoint}/api/ingest/journal` (the **daemon** parses).
- ACK = **HTTP 202** (204 for an empty journal). Auth: `Authorization: Bearer <token>` or Basic.
- Optional mTLS: internal CA (`[tls].ca_cert`) + client cert (`[tls].client_cert/client_key`).

> ### Central's certificate refused — what works, measured (2026‑08‑02)
> `test-ship` said `io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))`: neither the word
> "certificate" in plain text, nor the setting that fixes it. The message **now names the remedy**, and
> that remedy was **executed** against an `openssl s_server` before being written down:
> | Central's configuration | Agent's `[tls]` | Measured result |
> | --- | --- | --- |
> | internal CA (CA:TRUE) signing a **leaf** (CA:FALSE) | `ca_cert = /chemin/ca.pem` | **accepted** |
> | **self‑signed** leaf (CA:FALSE) | `ca_cert = /chemin/de/cette/feuille.pem` | **accepted** |
> | self‑signed leaf, nothing declared | — | refused (`UnknownIssuer`) |
> | **CA** certificate served as the server certificate | `ca_cert` = that same file | **still refused** (`CaUsedAsEndEntity`) — it is the CENTRAL that must be fixed (serve a leaf signed by the CA) |
> | any of them | `insecure = true` | accepted — **dev only**, no verification |

## Configuration (TOML)

```toml
endpoint = "https://soc.example.com"
token = "…"                 # Bearer (recommended); or username/password (Basic)
# host = "web01"            # override (default = machine hostname)
# host_header = "soc.example.com"
batch_size = 500
flush_interval_secs = 10
spool_cap = 10000
# spool_dir / state_dir: per-OS default

[tls]
# ca_cert = "/etc/plume/ca.pem"        # internal CA to add to the public roots
# client_cert = "/etc/plume/agent.crt" # mTLS
# client_key  = "/etc/plume/agent.key"
# insecure = false                     # DANGER dev only: do not verify the server cert

[[source]]
type = "journald"
id = "journald-auth"
comm = ["sshd", "sshd-session", "sudo", "su"]
since = "15min"

[[source]]
type = "fim"                       # native FIM (#58) — file integrity monitoring
# id = "integrity"                 # default; -> source=integrity (panel `search source=integrity`)
paths = ["/etc", "/usr/local/bin"] # ALLOWLIST of roots. EMPTY = INERT source (mode 0, no disk access)
# recursive = true                 # descend into subdirectories
# exclude = ["*/.git/*", "*.swp"]  # excluded globs (* / ?), matched on the absolute path
# hash_max_bytes = 10485760        # 10 MiB: beyond that, size only (bounds CPU/RAM)
# max_watches = 8192               # cap on kernel watches / marks (anti-ENOSPC & anti-OOM)
# max_files = 200000               # cap on baseline entries (anti-OOM for deep trees)
# debounce_ms = 200                # per-path anti-burst coalescing
# min_rescan_interval_secs = 60    # MIN interval between forced full rescans (anti CPU/I/O amplification)
```

Without ANY `[[source]]`, a default journald auth source is injected (the `fim` block is NEVER
implicit). A `fim` source without `paths` is **inert** — mode 0 invariant.

**FIM privileges**: on Linux, the preferred `fanotify` backend requires **CAP_SYS_ADMIN**; failing that,
the agent **degrades cleanly** to `inotify` (no capability) — never a crash. The other OSes (macOS,
Windows without the native feature) fall back to a bounded **scheduled scan**. FIM is **strictly
observational**: it reads/hashes/reports, and NEVER modifies/quarantines/deletes a file (plume charter:
no live action on the host). It does not follow symlinks outside the roots (anti-escape): the probe
OPENS each path with `O_NOFOLLOW` and `fstat`s the descriptor (not the path) — no TOCTOU window,
a link substituted just before the open cannot get an arbitrary target hashed; only regular
files are hashed (fifos/devices/sockets ignored), reading is HARD-bounded to `hash_max_bytes`
(no unbounded read on a growing file / an endless stream). If a cap
(`max_watches`/`max_files`) is reached, the partial coverage is reported to the SOC via `fim_coverage=partial`
on the events (not just a host warning).

## DECLARATIVE sources (#66/#67) — ship logs WITHOUT writing a script

A technician who needs to ship logs to the SOC **declares** their sources in the TOML (`[[source]]`) —
they **do not need to write a `.ps1` / `.sh`**. The script collectors **remain fully
supported** (see below): they are the alternative for those who prefer scripting. The two **coexist**.

> **Format = TOML `[[source]]`**, not a separate YAML file. The TOML array of tables **is already a
> declarative format**, and the technician edits **the same file** as the rest of their config (`endpoint`,
> `[tls]`…) — minimal friction, zero new format to learn. We **do not add** a YAML dependency:
> `serde_yaml` is **unmaintained** (it would turn the `cargo audit --deny warnings` gate red) and the agent
> is deliberately **lightweight**. The only added dependency is `regex` (already used/audited by the
> daemon) for the named-group parser.

Five generic types, one uniform shape (`name` → `source=`, `category`, `severity` 0–4, optional
`parser`):

| `type` | What it does | Specific fields |
| --- | --- | --- |
| `file` | tails a log file (cursor = offset; rotation handled) | `path`, `from_start` |
| `command` | runs a command every `interval` s; 1 stdout line = 1 event | `cmd`, `args`, `interval`, `max_lines` |
| `http` | GETs a URL every `interval` s; 1 body line = 1 event (reuses the TLS of `[tls]`) | `url`, `interval`, `max_lines` |
| `journald` | native journald backend; follows `_COMM=` **and/or** systemd units | `comm`, `units`, `since` |
| `wineventlog` | native Windows Event Log backend (also loads on Linux, where it is a no-op) | `channels`, `query` |

**Field parser** (`[source.parser]`, optional — the `message` always stays the raw line, the
fields are **additive**):
- `regex` = a regex with **named groups** `(?P<champ>…)` → each captured group becomes a field;
- or `delimiter` + `fields` = splits the line and **names the columns** (**zero-dependency** mode,
  for CSV/space-/pipe-separated data).

**Resilience**: a **malformed** entry (unknown type, missing mandatory field, invalid regex) is
**ignored with a warning** — it never takes the other sources down with it nor crashes the agent. If
**no** `[[source]]` is declared, the default journald auth source is injected.

Minimal example (tail of an nginx access log with field extraction):

```toml
[[source]]
type = "file"
name = "nginx-access"
path = "/var/log/nginx/access.log"
category = "web"
[source.parser]
regex = '^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
```

👉 **Ready-to-copy examples** (all 5 types + regex parser and split parser):
[`examples/sources.toml`](examples/sources.toml).

### The script alternative remains supported

Nothing is removed. Those who prefer scripting keep:

- **Linux** — `collectors/*.sh` and above all the generic **`collectors/custom.sh`**, which reads
  `/etc/plume/inputs.d/*.input` (`KEY=value` files: `SOURCE=`, `CMD=`, `SEVERITY=`, `CATEGORY=`,
  `FILTER=`, `MAX=`, `MAXLEN=`) and ships each stdout line as an event.
- **Windows** — `collectors/windows/plume-collector.ps1`.

Same **wire contract** as the agent (`kind:events` envelope → `/api/ingest`): script and declarative
agent produce events that are **indistinguishable** on the SOC side.

## Usage

```bash
# 1. put the binary and the config OUTSIDE /home (see the warning below)
cargo build --release
sudo install -m0755 target/release/plume-agent /usr/local/bin/plume-agent
sudo install -d -m0750 /etc/plume
umask 077; printf 'endpoint = "https://soc.example.com"\ntoken = "%s"\n' '<token>' \
  | sudo tee /etc/plume/agent.toml >/dev/null      # token via STDIN, never in argv

# 2. test, install, verify
plume-agent test-ship --config /etc/plume/agent.toml   # connectivity/auth/TLS (1 health event)
sudo /usr/local/bin/plume-agent install --config /etc/plume/agent.toml
plume-agent status
sudo plume-agent uninstall
```

> ### `install` says what it set up — and refuses what could not work (fixed on 2026‑08‑02)
> **1. A binary left in `/home` (or `/root`, or `/tmp`) is now REFUSED, before any
> write.** `install` writes an `ExecStart=` pointing at the binary's **current path**, without
> copying it — and the same unit sets `ProtectHome=yes` / `PrivateTmp=yes`. *Measured on 2026‑08‑02 (systemd
> 261, single-variable differential probe): same executable, without `ProtectHome` the service
> runs (`ExecMainStatus=0`); with it, it dies with `status=203/EXEC` — the service cannot read its
> own binary — and `systemctl enable --now` still returns **0**, so that `install` displayed
> "service installed and started" and exited 0 on a machine that collected nothing and restarted
> in a loop every 5 s.* The command now refuses to write a unit that contradicts itself, and says
> what to do (copy the binary to `/usr/local/bin`, the config to `/etc/plume`).
> **1 bis. The refusal applies to all FOUR paths, and it is MEASURED on the host (2026‑08‑20).** The spool
> and the state were exempted, on the strength of a dated comment claiming that the unit's `ReadWritePaths=`
> re‑exposed them despite `ProtectHome=`. *Re‑measured on 2026‑08‑20 (systemd 261, transient
> units, a single variable): this does not reproduce — neither `ReadWritePaths=`, nor `BindPaths=`,
> nor `BindReadOnlyPaths=`, nor `ReadOnlyPaths=` bring back a path protected that way. Worse than 203:
> the unit STARTS (`ExecMainStatus=0`, no 203, no 226) and the service gets "Permission
> denied" on its first write to its spool.* A spool or a state under `/home`, `/root` or
> `/run/user` is therefore refused just like the binary. And because no table written in advance can
> describe the sandbox of every host, `install` **actually mounts** that sandbox before
> writing the unit (a transient unit carrying the same hardening) and tests each path in it in
> the mode the service needs. If that measurement cannot be made, it **says so** instead of
> passing for a green light.
> **2. What `install` claims is RE‑OBSERVED, and over a DURATION.** *Measured on 2026‑08‑02, 3 times out of
> 3: the sample taken right after starting a unit whose `ExecStart` is unreachable says
> `active/running/ExecMainStatus=0` — SUCCESS —, and the same unit is in `auto-restart/203` 1.2 s
> later.* An instantaneous probe would therefore validate exactly the defect it is supposed to catch:
> `install` requires `active/running` to hold for **2.5 s in a row** (budget 12 s), treats `auto-restart`
> and `NRestarts>0` as FAILURES, and separately checks `is-enabled` (the artifact says "at boot").
> Directories and unit are read back after being written. A service that does not hold makes the command exit
> **non-zero** — no more need for a verifying `systemctl is-active` afterwards.
> ```
>   posé     : /etc/systemd/system/plume-agent.service
>   ÉCHEC    : service plume-agent.service (actif au boot et maintenant) — le service NE TOURNE PAS
>              après `systemctl enable --now` (ActiveState=activating SubState=auto-restart
>              Result=exit-code ExecMainStatus=203) — 203/EXEC : l'ExecStart est INJOIGNABLE depuis
>              le bac à sable de l'unité…
> ```
> **3. `--token TOK` puts the secret in `sudo`'s argv**, which `sudo` logs and which the `journal`
> collector (or this agent's `journald` source) ships **in clear text** to the central. Write the TOML via
> STDIN as above, then `install --config`.

## Deployment (self-installed service)

`install` does NOT merely write the config: it **self-installs and starts the OS service** —
this is the default behaviour, designed for an endpoint agent (start at boot, automatic restart).

| OS | What `sudo plume-agent install` does | Removal |
|----|----------------------------------------|---------|
| **Linux (systemd)** | writes the hardened unit `/etc/systemd/system/plume-agent.service` (`NoNewPrivileges`, `SystemCallFilter`, dedicated directories), `daemon-reload`, then **`enable --now`** → starts **now AND at boot** | `sudo plume-agent uninstall` = `disable --now` + removal of the unit + reload |
| **macOS (launchd)** | installs the `LaunchDaemon` plist + `launchctl bootstrap` (starts + at boot) | `plume-agent uninstall` = `bootout` + removal of the plist |
| **Windows (SCM)** | `CreateService` (start=auto) + start | `plume-agent uninstall` = `stop` + `DeleteService` |

> ### `uninstall` says what it did — and what it did not do (fixed on 2026‑08‑02)
> *Measured that day on a machine where **nothing** was installed: `plume-agent uninstall` displayed
> "Failed to disable unit: …", then "Reload daemon failed: …", then **"service retiré :
> plume-agent.service"**, and exited **0**. Zero files deleted, two commands failed, one success
> announced.* Each step was a `let _ = …status();`: the failure was neither checked nor reported.
> Removal is now **OBSERVED** — each artifact is probed, acted upon, then **re‑probed** — and the
> report names the three outcomes without confusing them:
> ```
>   retiré   : service plume-agent.service (arrêté et désactivé)
>   absent   : /etc/systemd/system/plume-agent.service (rien à retirer)
>   ÉCHEC    : … — toujours ACTIF après `systemctl disable --now` (droits root ?)
> ```
> An artifact that **resists** makes the command exit **non-zero** (this is the case that was swallowed);
> "nothing was installed" exits 0 but **never** claims to have removed anything.
> *Verified at runtime on Linux only; the launchd/SCM backends have the same structure and are
> compiled by `agent-ci` on `macos-latest`/`windows-latest`, not executed.*

> **Auto-start = intended.** An endpoint must collect continuously, including after a reboot. If you want to
> **install without starting**, set up the unit yourself (or `install` then `sudo systemctl disable --now
> plume-agent`). For a deployment **without a service** (cron/timer/foreground), do not use `install`:
> run `plume-agent run --config agent.toml` (loop) or `--once` (one cycle, for cron/systemd-timer).

The sources (native AND [declarative `[[source]]`](#declarative-sources-6667--ship-logs-without-writing-a-script))
are read by this same service — no extra step on the OS side.

## Build

```bash
cargo build --release          # Linux (dev box) — native target
cargo test                     # unit tests (no network required)
```

## Cross-compilation (Win/Mac)

The native Win/macOS code is **implemented** and `cfg`-gated: a Linux build compiles the PURE parts
(CIM mapping, query/plist/binPath construction, epoch parsing — all **tested**) and skips the FFI.
A `Makefile` provides the build matrix; [`.cargo/config.toml`](.cargo/config.toml) carries the
PER-TARGET settings (today: the static CRT for Windows/MSVC, see below).

> ### The static CRT is now ENFORCED for Windows/MSVC (fixed on 2026‑08‑02)
> Without it, `cargo xwin build --release --target x86_64-pc-windows-msvc` produces an executable that
> imports `VCRUNTIME140.dll` — **absent from a freshly installed Windows 11 Enterprise 24H2** (the
> Visual C++ redistributable does not ship with the OS). *Measured: the exe terminates immediately with
> `0xC0000135` (STATUS_DLL_NOT_FOUND), including for `--help`.* **No diagnostic is possible
> from the program**: the loader fails before the first instruction of our code — the only
> fix is to REMOVE the dependency, not to detect it.
> The flag lives in [`.cargo/config.toml`](.cargo/config.toml) (so `make win-msvc`, `cargo xwin
> build`, `cargo check` and CI all apply it), and a test guards it against a silent
> removal. *Measured on 2026‑08‑02 by reading the PE import table of the two binaries produced here:
> without the flag **3,259,392 B with `VCRUNTIME140.dll`** + 5 `api-ms-win-crt-*` apisets; with it,
> **3,359,744 B, neither of the two** (and `wevtapi.dll` still imported — it is indeed the complete agent).*
> Do not set `RUSTFLAGS=` for this target: the environment variable **overrides** the file.

| Target | Triple | Build tool from Linux |
| --- | --- | --- |
| Windows x64 (MSVC) | `x86_64-pc-windows-msvc` | `cargo xwin build --target …` (`make win-msvc`) — MSVC headers/libs automatic, no VM; static CRT **already enforced** by `.cargo/config.toml` |
| Windows x64 (GNU) | `x86_64-pc-windows-gnu` | **MinGW-w64 REQUIRED** (`x86_64-w64-mingw32-gcc`, package `mingw-w64-gcc`) + `cargo build --target …` (`make win-gnu`, which checks the prerequisite and says so) — target **not verified here**, prefer MSVC |
| macOS x64 | `x86_64-apple-darwin` | `cargo zigbuild --target …` (`make mac-x64`) — Zig as linker + Apple SDK |
| macOS ARM | `aarch64-apple-darwin` | `cargo zigbuild --target …` (`make mac-arm`) |
| Static Linux | `x86_64-unknown-linux-musl` | `cargo build --target …` (`make linux-musl`) |

### Cross-CHECK (validates the cfg-gated code WITHOUT a linker)

`cargo check` **type-checks** the target without linking — so **neither MinGW nor the Apple SDK is required**, only the
target's std via `rustup`:

```bash
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
cargo check --target x86_64-pc-windows-msvc   # compiles source/windows.rs + service/windows_scm.rs
cargo check --target aarch64-apple-darwin     # compiles the cfg(macos) part
# or: make check-all   (Win+Mac cross-check, then native build+test)
```

> **Native dependencies** (in `Cargo.toml`, `[target.'cfg(windows)'.dependencies]`): `windows` 0.58
> (features `Win32_Foundation` + `Win32_System_EventLog`) and `windows-service` 0.8 — pulled in **only**
> by the Windows target. macOS has **no** native crate (`log` + `launchctl` subprocesses).
> `rustls` stays on the **ring** provider (like the daemon) — no cmake/nasm required.

> **Environment note (superseded — measured on 2026‑08‑02)**: this note said that the cross-check
> "could not be run here" for lack of `rustup`. That is no longer true: the MSVC target was
> **fully CROSS-COMPILED** from Linux with `cargo xwin` (51 s with the MSVC SDK already in the local
> cache; **the first build on a new machine must first download that SDK — ~1.2 GiB in
> `~/.cache/cargo-xwin` — duration NOT measured here, the cache already existed**), then the binary was
> **run on a real Windows 11 Enterprise 24H2**: Event Log FFI (`wevtapi.dll` present in the import
> table), SCM service, TLS ship — everything works. The **`x86_64-pc-windows-gnu`** target, on the other hand, **fails
> without MinGW-w64**: `error calling dlltool 'x86_64-w64-mingw32-dlltool': No such file or directory`
> (measured, in 16 s, on a machine where only `rustup target add` had been run). MSVC + `cargo xwin`
> is therefore indeed the path to recommend, but it is not "prerequisite-free".

## At-least-once semantics

A source's cursor is persisted to disk **only after** ship+ACK. A crash replays the last
un-acked batch; daemon-side deduplication (`dedup` / journald `__CURSOR`, `INSERT OR IGNORE`) absorbs
the duplicates. The spool is a **bounded ring**: if the central is unavailable, the oldest
entries are evicted beyond `spool_cap` (the desktop cannot fill up its disk).

### What "published" means, exactly

Two properties are often confused, and the promise above needs both:

- **Content atomicity** — after the rename, a reader sees the old file or the new one,
  never a half-written file. The rename alone provides it.
- **Durability** — after a power or kernel failure, the publication survives. The rename
  does **not** provide it: the temporary file's bytes must be on disk **before**, and the
  directory entry must be there **after**. Without the second point, the file can exist without its
  **name** existing: the bytes are there, nobody will find them, and nothing will count what is missing.

Every publication by this binary — spool entry, source cursor, FIM baseline — goes
through a **single path** (`src/durable.rs`) that performs both synchronizations, and a derived test
refuses any new site that reinvents the pattern by hand.

**What this guarantees, per target** — an unbounded promise is a false promise:

| Target | Content synchronized before | Directory synchronized after |
|---|---|---|
| Linux, macOS | yes | yes |
| Windows | yes | **no** — a directory descriptor cannot be opened there by the standard library; publication there is atomic and its content durable, with no guarantee on the directory entry |

**What the tests prove, and what they do not prove**: they prove that the synchronization
calls are **made**, at the right place on the publication path (per-thread
counter, plus a proof by mutation: removing a call makes a test that names the
surface fail). They do **not** prove survival of a power failure — that would require
cutting the power of a real machine at the exact instant. The defect actually closed is that no
call existed; hardware that lies about its own *flush* remains out of reach.
