# Purging events — what the purge does, and what it refuses to do

[English](PURGE.md) | [Français](PURGE.fr.md)

**Status: ✅ shipped (subcommand) · 🧪 opt-in (HTTP surface, closed by default)**

Plume's retention is *time-based*: it erases what is old, nothing else. What was missing was a way
to erase a **named** set of events — test rows after an onboarding, a miswired feed,
the traces of a pentest exercise, an erasure request. Without it, the only way out was direct SQL on
a SQLCipher database, from an image that contains only the daemon.

`plume-daemon purge` fills that gap. It is the most destructive function in the product: **a purge is
irreversible and destroys evidence**. This document says what it guarantees, and above all what it does not
guarantee.

---

## In two steps, always

```
# STEP 1 — SIMULATE. Writes nothing. Returns the exact count, a sample, and a TOKEN.
plume-daemon purge --source flux-de-test --since -2d --until -1h

# STEP 2 — EXECUTE, if the token is still the fingerprint of the re-simulated scope.
plume-daemon purge --source flux-de-test --since -2d --until -1h \
    --confirm <jeton> --reason "nettoyage des events de test d'onboarding"
```

Both steps open the database to write to it if needed, and **create** it if it is missing: never before the
daemon's first start ([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).

The token is not a session identifier: it is **the fingerprint of the simulation's result** (canonical
scope, cardinality, `id` and `ts` bounds, breakdown by source). Execution **re-simulates** and
recomputes this fingerprint. Therefore:

* confirming without having simulated is impossible (there is no token to return);
* replaying a confirmation fails (the content has changed — the rows are no longer there);
* if a row enters or leaves the scope between the two steps (concurrent ingest, late relay,
  legal-hold set), the fingerprint changes and **the confirmation becomes void**.

Exit codes: `0` simulation returned or purge executed · `2` invalid arguments / database cannot be opened ·
`3` **reasoned refusal** (a refusal has its own code, so that a runbook does not swallow it as a success).

---

## The scope is **named**, and it is **bounded**

| Argument | `event` column |
|---|---|
| `--source <nom>` | `source` |
| `--env <id>` | `env_id` |
| `--origin <val>` | `origin` |
| `--engagement <id>` | `engagement_id` |

* **At least one identifier is mandatory.** "everything in this window" is not an acceptable
  scope, nor is it a value the code knows how to represent.
* **Both bounds are mandatory** (`--since` / `--until`, epoch in seconds or offset `-7d` `-24h`
  `-30m` `-3600s`). There is no default window.
* **There is no free predicate.** No SQL, no GXQL, no wildcard: those are the forms that make a purge
  accidentally total, and they have no place in the type that describes a scope.
* Selectors **combine with AND**: adding one can only narrow the scope.
* Identifier values follow the product's **identifier charset** (alphanumeric + `.` `_` `-`,
  1 to 64 characters) — the same as `env_id` / index names. **Known limit**: a source whose name
  falls outside this charset (for example injected by a third-party forwarder with a space or a `/`) cannot be
  purged by name today; use `--env` or `--engagement` to pin it down.
* The **audit trail is refused as a scope**: `--source plume-config`,
  `plume-operator-access`, `plume-tenant-admin`, `plume-engagement` and `--origin daemon` are rejected
  explicitly. A purge cannot erase the trace of configuration changes or of operator
  access — including **the trace of a previous purge**.

---

## What the purge REFUSES to do (and says so)

| Refusal | Why |
|---|---|
| **Legal hold** | ≥ 1 active `legal_hold` covers the scope → **total** refusal, naming the holds. Never a partial purge "except the held rows": it would suggest everything is gone. Lifting a hold remains a traced governance act (`/api/legal-holds/{id}/release`); the purge does not bypass it. |
| **Hold state cannot be determined** | `legal_hold` table present but unreadable → fail-closed. Evidence is never deleted when it cannot be proven that it is not held. |
| **Cold tier** | Sealed Parquet files cover the window → refusal, naming the number of files and days. Emptying `event` would leave these columnar copies **queryable**: "purged" would be false. The purge cannot rewrite a sealed Parquet, and it does not claim otherwise. Workaround: wait for cold expiry, or narrow the window to days that are still hot. This count is **not** bounded by retention: a file for an already expired day whose removal was refused stays on disk; it is counted, and the refusal holds until it is removed. Cold expiry retries that removal on every pass, and the daemon log names the file at fault (line `[cold] expiration … fichier non retiré`): that is where what blocks can be read. |
| **Evidence chain** | An event in scope is cited by the timeline of a case/incident → refusal, naming the identifiers. Detach the item first. |
| **Full-text index out of sync** | `event_fts` exists without its delete trigger → a `DELETE` would leave the postings and the purged message would remain **searchable**. Refusal. |

---

## What the purge ACTUALLY covers

In **a single transaction**, after being written to the ledger:

* the `event` rows in scope;
* **`event_fts`** — the full-text index, through the delete trigger (whose absence is an upstream refusal);
* **`event_rollup`** and **`event_dim_rollup`** — the hourly buckets covering the window are deleted then
  **re-aggregated from the surviving rows**, with the same identifier bound as the published coverage
  (without this bound, recent rows would be counted twice). An aggregate that kept counting
  the destroyed rows would make the purged content still visible in the form of counts;
* **`panel_cache`** — cached panel payloads carry *rendered* results, hence possibly
  purged content: they are emptied (they are recomputed in the background).

---

## What the purge does NOT cover

Each point below is **counted and displayed** in the simulation's output. It is not a
footnote: a purge that let you believe it had erased everything would be worse than no purge at all.

* **Backups already taken.** A purge removes nothing from them. **A restore would reintroduce the purged
  rows.** For an erasure request (GDPR-type), handle the backups too — rotation, expiry,
  or a fresh backup after the purge. The product does not do it for you.
* **Alerts** (`alert`). An alert is not a row derived from `event`: it has its own retention and
  its own life cycle. But its `detail` field **may quote the text of a purged event**. The simulation
  counts the alerts in the window; the decision is yours.
* **Metrics and state captures** (`metric`, `snapshot`). These tables have neither `source` nor `origin`:
  the scope does not project onto them. They are counted, not touched.
* **Shareable dashboard snapshots** (`dashboard_snapshot`). They carry rendered results, hence
  possibly purged content. Destroying them would destroy user work: they are counted, not touched.
* **The fleet inventory** (`host_rollup`). Its per-host counters stay inflated by the purged rows. It is
  an inventory (host names, last activity), not event content; resetting it would make
  hosts disappear from the fleet view, which would be a lie of another kind.
* **Exported copies of the ledger** (WORM sinks). That is their reason to exist: they are *append-only* and
  verifiable outside the database. The purge **adds** its entry to them; it removes nothing.
* **A denial of service through repeated purges.** A malicious admin can purge a lot, often. Each purge
  is written to the chained ledger and emits a severity 4 SOC event, non-purgeable and alertable — it is
  a **detection**, not a prevention.

---

## Integrity: nothing is deleted without being recorded

Each purge writes, **in the same transaction as the deletion**:

1. an entry in the **hash-chained append-only ledger** (`kind = config.purge.events`): who, resolved
   scope, how many rows, when, the confirmed fingerprint, and the reason;
2. a severity 4 **SOC event** `source='plume-config'` `origin='daemon'` — hence non-purgeable and
   alertable, like a retention decrease.

If recording fails, **nothing is deleted**. And if the database deletes a number of rows different from
the one just recorded, **everything is rolled back** — ledger entry included: the ledger never asserts
anything other than what the database did.

The record carries the scope and the counters — **never the destroyed content**. No message, no IP,
no parsed field goes into it: the value passed to the recording does not carry them.

Checking afterwards:

```
plume-daemon verify                      # recomputes the whole chain + the checkpoint signatures
plume-daemon ledger-export --out purge.jsonl
plume-daemon ledger-verify-export purge.jsonl
```

`--out` opens the file **in append mode**: running the export again on the same file writes the chain into it a second
time. An export sink whose cursor the database refused to commit produces the same shape — the slice is
rewritten in full on the next send, including after a write interrupted at a line ending.
`ledger-verify-export` sets aside any line **byte-for-byte identical** to an already verified line, wherever it
sits in the copy, and counts it in its verdict (exit `0`): these are neither distinct events,
nor an alteration. A copy that **ends** in the middle of a repetition is accepted as well, and the
verdict says so: nothing that was verified is missing from it. Every other line must chain onto the last
verified line: a line with the same identifier and **different** content — a fork —, an altered,
missing or moved line remain a break (`EXPORT COMPROMIS`, exit `1`), as does a line cut in its
middle, which is no longer JSON. An unreadable file is not verified (exit `2`).

---

## Who has the permission

* The **subcommand** requires the SQLCipher key and access to the host — exactly the power that would be
  needed to erase the database by hand. It therefore adds no capability; it replaces an untraced manual `DELETE`
  with a bounded, simulated, confirmed and recorded path. The actor recorded in the ledger is the system account
  and the pid; `PLUME_PURGE_ACTOR` **adds** the name of the responsible human, without replacing what was measured.
* The **HTTP surface** (`POST /api/purge/plan`, `POST /api/purge/apply`) is **admin-only** and **closed by
  default**. It, on the other hand, adds a capability to destroy evidence *remotely*: it has to be armed
  explicitly at deployment with `PLUME_PURGE_API=1`. This separates two principals — the one who holds the
  admin password, and the one who controls the deployment.
* **"Admin" is not necessarily the right quantum of authority to destroy evidence.** The subtractive
  permission `purge_events` makes it possible to define a composable role `base=admin` **without** purge, without
  touching the code (`POST /api/roles`, `deny_perms: ["purge_events"]`).
* In multi-tenant mode, a cross-tenant purge by a super-admin already goes through the usual **break-glass**
  (mandatory reason, operator access marker that cannot be disabled in the customer's database).

---

## Variables

| Variable | Default | Effect |
|---|---|---|
| `PLUME_PURGE_API` | *(absent)* | `1` arms the HTTP purge routes (admin-only). Absent → they refuse. |
| `PLUME_PURGE_ACTOR` | *(absent)* | Name of the responsible human, **added** to the system actor recorded in the ledger. |
