# Agents and their protocol

[English](AGENTS-PROTOCOLE.md) | [Français](AGENTS-PROTOCOLE.fr.md)

What an agent does fits in one sentence: **it reads a source, buffers to disk, POSTs to the
central, and forgets what it has read only once the publication has been acknowledged.** The rest of
this page is the detail of that sentence, and above all **what it does not promise**.

Every claim is established by reading the sources and carries the command that reproduces it.
This document describes the **protocol**; the endpoint agent itself is documented in
[`../agent/README.md`](../agent/README.md), its validation in [`../agent/CI.md`](../agent/CI.md), and
the extension points in [`SDK.md`](SDK.md).

---

## 1. Three families, a single wire contract

The word "agent" covers three different things in this product. Confusing them is the first
source of misunderstanding.

| Family | What it is | Where it runs | Buffer |
|---|---|---|---|
| **shell collectors** | `collectors/*.sh` + systemd timers, set up by `bootstrap-agent.sh`; a separate shipper (`ship.sh`) drains the spool | Linux host | files in `PLUME_SPOOL` |
| **endpoint agent** | a cross-OS Rust binary (`agent/`) that reads, buffers and ships by itself | Linux, Windows, macOS | bounded ring on disk |
| **agentless** | Windows PowerShell collector, syslog receiver, HEC, OTLP, PULL connectors | the source, or the central | varies |

**They all end up on the same wire contract.** That is what makes it possible to add one without
touching the central — and it is why this document describes the contract before the families.

---

## 2. The wire contract

### 2.1 The envelope

`POST /api/ingest`, `Authorization: Bearer <jeton>`, JSON body:

```json
{
  "kind": "events",
  "ts": 1756000000,
  "host": "ws22-lab",
  "env_id": "prod",
  "events": [
    { "ts": 1756000000, "source": "sshd", "category": "auth", "severity": 2,
      "message": "Failed password for root", "host": "ws22-lab",
      "dedup": "sshd:1756000000:root", "fields": { "user": "root", "src_ip": "192.0.2.10" } }
  ]
}
```

Only **`kind`** is mandatory, and it is the only field checked at POST time. The values
`events`, `metrics` and the snapshots (`firewall`, `controls`, …) are dispatched at replay.

| Envelope field | If absent |
|---|---|
| `kind` | **`400` refusal** |
| `ts` | the time of the replay |
| `host` | **overwritten** by the token's host if it is bound (§3) |
| `env_id` | `prod` |
| `events` | empty list |

| Event field | If absent |
|---|---|
| `ts` | the envelope's |
| `source` | `agent` |
| `severity` | `0` |
| `category`, `message` | empty string |
| `dedup` | `NULL` → **no deduplication** for this row |
| `fields` | `NULL`; `src_ip`, `dst_ip` and `url` are promoted from it if they are present |

The canonical form is written three times, identically — in the shell library
(`collectors/lib.sh`), in the Rust agent (`agent/src/source/`) and in `agent/README.md`.

### 2.2 What the POST checks — and what it does not

**MEASURED ON THE TREE on 2026-08-25: there is no deserialized Rust struct for this
envelope.** The body is taken as a `String`, parsed as generic JSON, and **written verbatim to the
central's spool** after a single check: the presence of `kind`.

```sh
grep -rn 'derive(Deserialize' daemon/src/ingest    # nothing
```

A consequence to know before debugging an integration: **a malformed event returns `202`, not
an error.** What is refused synchronously is a short list:

| Code | When |
|---|---|
| `202 {"queued":true,"durable":true}` | the body is JSON and carries `kind` — on `durable`, see §2.5 |
| `400` | invalid JSON, or `kind` absent |
| `413` | too many events in a batch, or body too large — the message **names the ceiling that bit and the lever that changes it** |
| `503` + `Retry-After: 60` | free-space floor crossed (`PLUME_INGEST_MIN_FREE_MB`) |
| `429` + `Retry-After` | rate limiting (global, per IP, or on authentication) |
| `401` / `403` | unknown token, or insufficient role |
| `500` | spool write impossible |

There is **no `507`** in this product: disk pressure speaks as `503`.

### 2.3 The other entry points

| Route | Format | Success | Particularity |
|---|---|---|---|
| `/api/ingest` | envelope above | `202` | the reference entry point |
| `/api/ingest/journal` | raw journald NDJSON | `202`, `204` if empty | no enclosing envelope |
| `/api/ingest/minio` | native MinIO audit | `202`, `204` if the batch is entirely filtered | route ceiling **lower** than the configurable ceiling |
| `/services/collector[/event]` | Splunk HEC | **`200`** `{"text":"Success","code":0}` | wire-compatible: point your existing *forwarders* at it |
| `/services/collector/health` | — | `200` | **public route**, without authentication |
| `/v1/traces` | OTLP/HTTP JSON, gzip accepted | — | **`404` as long as `PLUME_OTLP_TRACES` is not set to `1`** |
| `/api/ingest/firehose`, `/api/ingest/pubsub` | AWS Firehose, GCP push | — | **the only ingestion routes that authenticate in their own handler**, outside the common check |

All of them inherit the body ceiling **by construction**: the bound is set on the sub-router, not
route by route, so that a route added tomorrow inherits it without anyone having to think about it.

**Syslog is not an HTTP route.** The receiver listens on UDP/TCP, writes to the local spool, and
it is the shipper that POSTs. It belongs to the shell family's transport.

### 2.4 The ceilings, and which one really bites

| Lever | Default |
|---|---|
| `PLUME_INGEST_MIN_FREE_MB` | `512` (MB); `0` disables the guard |
| `PLUME_INGEST_MAX_EVENTS` | `50000` |
| `PLUME_INGEST_MAX_BODY_MB` | `8` (MiB) |
| `PLUME_RL_GLOBAL_MAX` / `_IP_MAX` / `_AUTH_MAX` | `6000` / `1200` / `120` per 10 s window |

Two subtleties that the code carries and publishes itself, and that are worth reading before raising a
lever that will not bite:

- **when two ceilings guard the same route, the refusal DERIVES which one was binding** instead of
  naming a hard-coded lever. On the MinIO route, the **route** ceiling is the binding one: raising
  `PLUME_INGEST_MAX_EVENTS` changes nothing there. On HEC, OTLP and Firehose, the two are tied;
- **the byte ceiling bites well before the event ceiling** for any realistic profile. The
  event ceiling's error message was therefore dead code, and an integrator received the
  framework's generic message instead. This is written and dated in `daemon/src/limite_corps.rs`.

The disk guard **fails OPEN**: if the free-space measurement is impossible, ingestion goes through.
This is a choice — refusing on a missing measurement would bring ingestion down for a reason that is
not the right one.

### 2.5 What the acknowledgement attests — and what it does not

**MEASURED ON THE TREE on 2026-08-29: no receiving surface syncs what it has just
written.** A 2xx returned by the central attests that the body was **received and handed to the system**. It
does **not** attest that it would survive a power cut.

```sh
# the pattern looks for a CALL, not a mention — otherwise this page would contradict itself
grep -rn '\.sync_all()\|\.sync_data()' daemon/src/ingest                              # nothing
grep -rn '\.sync_all()\|\.sync_data()' daemon/src/cold_store daemon/src/crypto daemon/src/backup   # six calls
```

The second command is there because a command that returns nothing proves nothing until it has been
seen returning something. This is therefore **not** a capability the product lacks — the same operation is
called in the cold tier writer, when writing an encryption key and in the backup. It
is absent **where the promise is made**.

Two regimes, which are best not confused:

| Regime | Routes | What a power cut can take away |
|---|---|---|
| **spool** — a file written, **synced**, renamed, and then its **directory** synced | `/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/services/collector[/event]`, `/v1/traces`, `/api/ingest/firehose`, `/api/ingest/pubsub` | **nothing that was acknowledged**: both barriers are taken **before** the acknowledgement leaves |
| **database** — a committed transaction in `journal_mode=WAL` + `synchronous=NORMAL` | `/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push` | the last committed transactions: the `COMMIT` survives the death of the **process**, not that of the **machine** |

**What this changes for a shipper.**

*On the seven spool routes*, the acknowledgement allows you to forget, and it holds: when the `2xx` leaves, the
body is on disk, under its final name, both barriers taken. The write is **offloaded**
to a blocking thread, so waiting does not block the receiver; it is paid for in latency, not in lost
throughput — the cost of a barrier is that of the **barrier**, not of the batch size, and it is amortized
as soon as several shippers push in parallel. An operator whose storage makes this barrier
too expensive can disarm it with `PLUME_INGEST_FSYNC=0`; the `durable` field then falls back to `false` by
itself, and the next paragraph becomes true again for them.

*On the three database routes*, the acknowledgement still only covers the death of the **process**. If your
source is replayable — a retained log, a watermarked stream, a subscription that redelivers — keep
enough to replay a window: the central's deduplication (§4.4) absorbs the replay as soon as your
events carry a key. If it is not, that window is a loss that nothing recovers.

**Where it is written in the response, and where it is not.** The four routes whose body belongs to
plume carry the **`durable`** field, and it is not a constant: it is the value that the
publication **obtained**.

| Route | `durable` | Why |
|---|---|---|
| `/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio` | `true` | both barriers are taken before the acknowledgement (`false` if `PLUME_INGEST_FSYNC=0`, or if the kernel refuses the directory barrier after the rename — in which case the batch is published but not guaranteed) |
| `/api/metrics/prom` | `false` | **database** regime: nothing has changed for it |

The six other acknowledgements have a shape dictated by a **foreign** contract (Splunk HEC, OTLP, AWS
Firehose, GCP Pub/Sub, Loki push, Prometheus `remote_write`), when they have a body: adding a
field to them would modify a third party's protocol. For the four of them that are spool routes, the
witness is on the operator's side, in `/metrics`: `plume_spool_barriere_fichier_total`,
`plume_spool_barriere_repertoire_total`, `plume_spool_barriere_echec_total`. The first two rise
together; a gap, or the third one climbing, says that a `2xx` has stopped being backed by a barrier.

> **What is proven, and what is not.** What is demonstrated is that both barriers are
> **requested from the kernel and returned without error**, in that order, before the acknowledgement. Survival of a
> real power cut cannot be demonstrated from the process: beyond the call, it
> depends on the file system and the hardware.

> ⚠️ **The "database" regime remains open.** The loss there remains a **defect**; it is written down
> pending its removal. It is the remainder of key `S31` in [`ROADMAP.md`](ROADMAP.md).

---

## 3. Authentication, and what "bound to the host" means

### 3.1 The token

```sh
# native host: the unit's configuration, which `sudo` does not pass on
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token <nom> <hôte-lié>   # MACHINE token
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token <nom> --relais     # RELAY token (multi-host forwarder)
# Docker / k3s: in the container where the daemon runs
docker compose exec soc plume-daemon token <nom> <hôte-lié>
kubectl -n soc exec deploy/soc -- plume-daemon token <nom> <hôte-lié>
```

Without the unit's `PLUME_CONFIG`, the subcommand writes to a different database from the daemon's:
it displays a token, and the central refuses it. On a new central, start the daemon **first**:
a database that the subcommand creates is born unencrypted
([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).

The form without a host **and** without `--relais` is **refused**: a token's scope is declared, it is not
inferred from an omission. Setting both at once is refused too.

The secret is 32 bytes of system entropy, is displayed **only once**, and **only its SHA-256
is in the database** — it cannot be re-derived. Lost, it is recreated; it cannot be read back.

A token establishes an identity only on an **allowlist of paths** (ingestion, metrics,
traces, response channel). Outside that list, the holder of an agent token is nobody: the
default is closed.

### 3.2 Binding is not a refusal, it is a rewrite

**This is the most counter-intuitive point of the protocol, and it is measured in the repository.** An agent that
declares a `host` different from the one its token is bound to **receives `202`** — and the event is
recorded **under the token's host**, not under the one it declared.

In other words: binding protects the integrity of the inventory, **it does not warn the sender**. Do
not count on an error code to detect a misconfigured machine; compare what you
send with what the console displays.

A **relay** token, for its part, has no bound host: **the declared host passes unchanged and is not
attested**. The message displayed when it is created says so in plain words — whoever holds this token can
write under any host name. That is the price of a forwarder, and it is why a relay
token is **refused** on the response channel (§6).

### 3.3 Roles

| Minimum role | Routes |
|---|---|
| `Ingest` — satisfied by `editor` **or** `agent`, **never** `viewer` | ingestion, metrics, HEC, traces |
| `Agent` — satisfied by `agent` **alone** | response channel, active engagements |

A token of another kind (data source, client, Firehose, Pub/Sub) **cannot** authenticate
on the agent surface: the kinds are partitioned in the query itself.

---

## 4. The disk buffer, and what it guarantees

### 4.1 Publishing means two syncs, not a rename

The shell library publishes in four operations, in this order: set the permissions, **sync the
content**, rename, **sync the directory entry**. The rename alone gives atomicity of the
*content* and nothing else: after a power cut, the bytes can exist without their **name**
existing — and the shipper walks the spool **by name**. The two syncs are what close
this window; their cost is measured and written next to the code.

The Rust agent holds the same contract through a **single path** of publication, and a test refuses any
`rename(` written elsewhere in the crate. **Its limit is written down rather than asserted**: under Windows,
the directory is not synced, for lack of an equivalent operation in the standard library.

**The central, for its part, does not hold this contract on its own writes.** Its push receivers write
then rename without syncing — that is, exactly the form that this section describes as
insufficient, but on the side that *receives*. What the acknowledgement then covers, and what it does not, is
in §2.5.

### 4.2 The buffer's bound — and its absence

| Family | Bound | Policy when it is full |
|---|---|---|
| Rust agent | `spool_cap`, default **10 000** entries | eviction of the **oldest** |
| syslog receiver | `PLUME_SYSLOG_SPOOL_MAX_BYTES` (default 512 MiB), `PLUME_SYSLOG_SPOOL_MAX_FILES` (default 20 000); `0` = unlimited | the batch is **dropped** |
| **shell collectors** | **none** | — |

**MEASURED ON THE TREE on 2026-08-25: the shell family's spool has no size ceiling, no
file ceiling, no eviction, and no purge.**

```sh
grep -nE 'SPOOL_MAX|MAX_FILES|MAX_BYTES' collectors/lib.sh collectors/ship.sh bootstrap-agent.sh   # nothing
```

This is not a search failure: the two other families have one, which makes the absence
readable. The only ceiling on the shell side is **per collector pass** (number of lines read in one
go), not on the spool.

### 4.3 The consequence to know: only `202` acknowledges

The shell shipper deletes a file **if and only if** the response is `202`. Everything else is
"kept for retry" — including a `204` (empty body, or batch entirely filtered) and including
a **permanent error** such as `400` or `413`. This `202` attests only **receipt**: what it
leaves open is in §2.5.

```sh
sed -n '/^ship_glob/,/^}/p' collectors/ship.sh
```

Combined with the absence of a bound (§4.2), this means that **a permanent error makes the spool grow
without end**. Monitor `PLUME_SPOOL` on a shell agent, and read the error output of the shipping
unit: it names the file and the code.

The Rust agent does not behave this way, and it is deliberate: it acknowledges on any `2xx`, retries on
`429` and `5xx`, and **gives up while logging it** on a definitive `4xx`.

### 4.4 Deduplication is on the central's side, and it is partitioned

`event.dedup` is unique, and insertion ignores duplicates. The key is **partitioned by host** by
a length-prefixed encoding — two machines that would produce the same key do not erase one
another. **A row without `dedup` is never deduplicated**: SQLite treats two `NULL` values as
distinct.

This is what makes replay absorbable, and the exact cost of replay **per sensor** is written in
`collectors/lib.sh`: some carry a content-identity key (replay fully absorbed),
others a time bucket (absorbed within the bucket only).

---

## 5. Watermarks: what prevents losing or repeating

A watermark (`PLUME_STATE`, default `/var/lib/plume/state`) remembers where a sensor was. **It
is never shipped.**

**The rule holds by construction, not by discipline: a sensor does not have both operations at its
disposal.** It can *stage* a watermark, but the write only happens in the
functions that publish first. The order is therefore always: **publish, then acknowledge the watermark.**
Two CI guards hold it (`check_watermark_follows_publication.py`,
`check_publication_is_durable.py`).

Writing the watermark is **deliberately not durable**, and the code explicitly forbids
"fixing" the absence of sync there: a lost watermark costs a replay, which deduplication
absorbs; a watermark that survived the events would make them disappear **permanently**.

The same order is held by the three families. On the Windows side, the watermark is in addition **bounded to the
present** in both directions, after a measured case of a clock running ahead that had left three sources
blind irrecoverably.

---

## 6. The return channel: claiming an action

The central pushes nothing to an agent. It is the agent that **pulls**.

```
GET  /api/actions/pending    -> réclame ; réponse en TSV : id \t kind \t target \t dry_run
                                (sous « Accept: application/x-ndjson » : un objet JSON par ligne, voir plus bas)
POST /api/actions/result     -> rend compte : {"id":…, "status":"done|dryrun|failed", "result":"…"}
```

| Property | Detail |
|---|---|
| **role** | `agent` **and** a token bound to a host — a relay token is refused with `403` |
| **the host comes from the token** | never from a query parameter; the `?host=` parameter that the shell collector sends is **ignored** by the daemon — that is what closes the door to claiming someone else's action |
| **claimable vocabulary** | `ban_ip` and `unban_ip` **only**; `kill_pid` and `stop_service` are not claimed through this channel |
| **reissue** | an action claimed without a result is handed out again after a few minutes |
| **closing** | applies only to an action that is *approved* **and** assigned to the same host; idempotent |
| **format** | TSV by default, not JSON — so that the shell loop reads it without a dependency; JSON per line on request (below) |
| **ban duration** | carried by the JSON-per-line form only: `ban_ttl_s` (see below) |

**The ban duration of a response.** An agent that sends `Accept: application/x-ndjson` receives one JSON
object per line (content type `application/x-ndjson`), for example:

```
{"ban_ttl_s":5400,"dry_run":false,"id":12,"kind":"ban_ip","target":"203.0.113.82"}
{"dry_run":false,"id":14,"kind":"unban_ip","target":"203.0.113.84"}
```

- `ban_ttl_s` is an **integer, in seconds**: the **effective** ban duration of this response, the one that
  the central also applies (approval, HTTP blocking, CrowdSec command of the local responder) — the duration
  set by the playbook, or the default duration if the response does not carry one. It is present on **every**
  `ban_ip`, never zero, and **absent** from any other kind (`unban_ip`).
- The agent's contract: it falls back on `PLUME_BAN_DURATION` only if the duration **is not served** —
  a TSV response (an older daemon ignores the header), or an agent without a JSON reader that has not requested
  that form. Under the JSON-per-line form, a `ban_ip` whose `ban_ttl_s` is absent, zero, not an integer or
  outside 1 to 31 536 000 is **out of contract**: the action is reported `failed` with the cause, nothing is
  applied.
- **What `collectors/respond.sh` does**: it sends the header only if it can read JSON (`jq`,
  otherwise `python3 -I`), and takes the JSON path only if the served type is `application/x-ndjson` (a
  central that serves TSV despite the header goes back to the TSV path). Any status other than `200`, or a
  failed `curl`, is never read as a queue: named error log, exit code `3`, nothing
  executed. An unreadable JSON line is ignored and reported in the log, the others are served; an unknown
  field is ignored; no served value is evaluated by the shell, the target always goes through the
  same checks for address, reserved ranges and ban-exempt list. The duration goes to CrowdSec as
  `-d <n>s`; to nft as an element timeout in a dedicated set `inet plume blocklist_ttl` (`flags timeout`),
  the historical set `inet plume blocklist`, without a timeout, being neither migrated nor destroyed (its elements already
  set stay; an `unban_ip` removes the address from both sets); a zero or unreadable fallback duration
  (anything other than `<n>s`, `m`, `h` or `d` on a single line) is set neither by nft nor by cscli
  (`failed`, never a ban without end nor a value passed as is); fail2ban does not carry it (the ban lasts the jail's
  `bantime`), and the reported result says so. Every reported result, simulation included, carries the effective
  duration and its provenance (served, or `PLUME_BAN_DURATION` with the cause of the fallback).
- The header is read type by type (case ignored). A zero weight (`application/x-ndjson;q=0`) is an explicit
  refusal of that type: the response is then TSV.
- Without the header, the response remains the four-field TSV, byte for byte. A fifth field is not
  added to it: the loop of an already deployed agent (`read -r id kind target dry`) would read it into `dry`.
- A response whose duration cannot be read from the database is **neither handed out nor claimed**, in both forms:
  it stays approved, the daemon's log says so (`[actions] action <id> NON REMISE ce tour-ci : durée
  du ban de cette riposte NON lue …`), the other actions are handed out — the daemon reads the next page
  as long as a full page has not handed out a hundred actions, so that responses held back at the head of the queue do not
  hide the ones that follow —, and it leaves on the next round once the column is corrected. Nothing is applied with a guessed duration.
- A round hands out **at most a hundred** actions, whatever the form; the rest leaves on the following rounds. If
  reading a following page fails after actions have already been claimed, those are handed out (and
  the failure is in the daemon's log) rather than lost in a refusal.

Upstream, the chain is: creation → **approval by an administrator** → claim → result.
On the agent side, the engine is **off by default** (`PLUME_RESPONDER=0`) and, once switched on, it is in
**simulation** as long as `PLUME_RESPONDER_APPLY=1` is not set. Every result goes into the audit
log.

> ⚠️ The responder's allowlist file carries **two incompatible meanings** depending on
> the installer that seeded it. See the warning in the [`README`](../README.md#configuration-the-plume_-variables)
> and keys `P4.7-a`, `P4.7-b` and `P4.7-c` of [`ROADMAP.md`](ROADMAP.md).
> **The two readers do not have the same address criterion** (`P4.7-b`): what holds — and is measured
> on both — is that the daemon recognizes **strictly more** forms than the agent, so
> that no line is silently accepted by both. This is **not** equality, and the rejection of
> each reader is **not** derived from the predicate that decides what can be banned.
> **Since 2026-09-10 (`P4.7-c`), the ban-exempt list also applies on the central's side**: the daemon reads `PLUME_CENTRAL_BAN_EXEMPT_FILE` (default: the separate file seeded by the agent installer), its addresses join the protected set and a ban claimed by the central on one of them is refused, naming the exemption; an unreadable line is counted in the never-ban register without disarming the central. What follows describes the earlier state.
> **And the ban-exempt list applied only on the agent's side** (`P4.7-c`, until 2026-09-10): the central's responder did not
> consult it.

---

## 7. TLS and mTLS

| Family | How it is set | If it is absent |
|---|---|---|
| shell collectors | `PLUME_TLS_CACERT`, `PLUME_TLS_CERT`, `PLUME_TLS_KEY` — concatenated into options of the HTTP client | system trust store, **no client certificate, no warning** |
| Rust agent | **TOML** keys, not variables: `[tls] ca_cert / client_cert / client_key / insecure` | public roots only, no client certificate, no error |
| Windows collector | `PLUME_TLS_INSECURE=1` for a self-signed test central | normal verification |

**There is no "mandatory mTLS" mode on the agent side.** The requirement can only be set **on the
central's side**, by the entry point that exposes the ingestion route. An agent without a client certificate will not
complain about it.

**A name collision to know about**: `PLUME_TLS_CERT` and `PLUME_TLS_KEY` designate the **server**
certificate on the daemon side and the **client** certificate on the agent side. Same name, two opposite roles.

What happens when the chain does not verify is **measured and published** in
[`../agent/README.md`](../agent/README.md), case by case — including the counter-intuitive case of a
**CA** certificate served as a server certificate, which remains refused whatever the agent declares, and
whose remedy is to fix the **central**. The remedy displayed is derived from the **type** of the verification
error, not from its text.

---

## 8. Why it is this way

**The wire contract is thin so that an emitter can be written in thirty lines of shell.**
That is the product's reason for being: plugging in a source without a rebuild and without an SDK. The price is the one
described in §2.2 — validation is late, and a `202` does not prove that an event was well
formed.

**The buffer is on the emitter's side, not the central's.** A central that refuses (disk guard, rate
limiting) returns a code that invites a retry; it is the agent that keeps the bytes. This moves the risk
of saturation to the agent — hence the importance of §4.2. And it has a second, less visible price:
the moment the central acknowledges is the moment the **only other copy** disappears, while its
own is not yet durable (§2.5).

**The host is attested by the token, not by the emitter.** An inventory whose host names are
declared by the machine itself is not an inventory. Binding rewrites rather than refuses
because a refusal would lose the events of a misconfigured machine — but this is paid for by the
silence described in §3.2.

**We publish before acknowledging, always.** It is the only invariant that makes it possible to promise "at
least once" without ever promising "exactly once". Deduplication on the central's side
turns replay into a cost, not into a falsehood.

---

## 9. What has not been verified

- **No agent was enrolled, and no event was sent in this batch of work.** Everything above
  is established by reading the sources; the codes, defaults and behaviors cited are those
  that the code writes, not those of an observed session.
- The stored event row is built in a **crate external** to the repository (`guatx-core`,
  resolved by git tag): its fields are observable here only through the way they are
  filled.
- **What is actually exercised by the agent's continuous integration**, and what is only compiled,
  is written without embellishment in [`../agent/CI.md`](../agent/CI.md) — notably that **the installation of the
  service is not exercised on any operating system**. Read it before treating
  compilation as proof.
