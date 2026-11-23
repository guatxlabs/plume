# P10 — Staying under 2 GB at scale: hot / cold / bloom / compression

[Français](DESIGN-P10-echelle-2go.md) | [English](DESIGN-P10-echelle-2go.en.md)

> Design brainstorm, **anchored in measurement** (2026-08-06). This document is NOT a frozen
> decision: it is the map of the measured terrain and the order of levers that follows from it. Every
> figure-bearing claim carries its source. Nothing is built on the strength of an intuition.

## 0. What we are after, and why it is TWO problems, not one

The requirement, stated several times by the maintainer: "that the database take up very little space, almost as little as a zstd,
while ensuring reliability, confidentiality and security **natively** — without a plaintext dump then zstd
then age". And: run under **2 GB of RAM** on native host / Docker / k3s, everything configurable, the
**default = what is in prod**.

Two distinct problems hide under "P10", and confusing them leads to building the wrong
lever:

- **SIZE at rest** (the disk). This is the "x81". Lever: fewer bytes stored.
- **RAM of a query** (the OOM, P6.1-b). The SQLite sorter materializes **one record per row
  SCANNED** on a `stats … by` (see P10.0). Lever: fewer rows to scan **and** an aggregator
  with bounded state. **Compression at rest does NOT reduce sort RAM** — a compressed page is
  decrypted+decompressed in RAM before being sorted. Both levers are needed.

## 1. THE MEASUREMENT — where the bytes go

> ⚠ **THIS TABLE HAS ALREADY LIED ONCE, AND IT IS WORTH KNOWING WHY.** Its first version came from the
> BENCH (3.65 M events, unencrypted database) and stated that "the PROPORTIONS are independent of
> scale". Production contradicted it: **index 32.8% → 25.4%**, **FTS5 8.1% → 18.9%**. A
> bench proportion is not a law. **And one reading does not make a series**: between 08-08
> (FTS 18.9%) and 08-09 (FTS 10.7%) the gap could come from compaction `4ca6339`, from
> aging, or from a traffic dip — **two points do not say**. That is the gap that is
> now closed: the SAME measurement is written every hour into `metric` by `ventilation_serie`, and
> the table below is **re-derived without reading anything off by hand**:
>
> ```
> metric plume_db_poste_bytes by poste | timechart span=1d avg(value) by poste
> ```
>
> The shares are computed from this series ALONE (the sum of the buckets IS the file — that is what
> closed accounting guarantees). When the measurement cannot be taken, the series carries a GAP and
> `plume_db_ventilation_ok` drops to 0 with its cause — never a zero of bytes.

**Real database** (`plume-daemon db-stats --par-objet`, live pod, read-only, **2026-08-09**): a database
on the order of a GiB for a little under two million events ⇒ **on the order of a KiB per event**
on disk · freelist **7.3%** · auto_vacuum=none · accounting CLOSED ✓ · walk in **about twenty
seconds per GiB**.

| item | share | dominant objects |
|---|---:|---|
| **data (tables)** | **55.7%** | `event` **53.4%** |
| **b-tree indexes** | **26.3%** | `sqlite_autoindex_event_1` 4.6% · `idx_event_src_srcip` 3.1% · `idx_event_src_ts` 2.6% · `idx_event_host` 2.6% · `idx_event_sev_srcip` 2.1% · `idx_event_srcip` 2.0% · `idx_event_ts` 1.6% · `idx_event_category` 1.6% |
| **FTS5 (shadow)** | **10.7%** | `event_fts_data` 9.3% |
| UNCLASSIFIED | 0.0% | — |
| free pages | 7.3% | — |

**Three facts that drive the design:**

1. **The `event` table is HALF the database, and it is stored IN PLAIN PAGES** (SQLCipher
   encrypts the page, but does not COMPRESS it). The values are SIEM logs — `message`, `fields`
   JSON — which compress **x10 to x40** with zstd. It is the biggest single lever, and it is untouched.
2. **A QUARTER of the database is b-tree indexes** (26.3% in production; 32.8% on the bench — the gap
   is real, the bench share was too high). Compression can do almost nothing there (these are
   keys that are already compact). But a **columnar cold tier ELIMINATES them**: the cold tier carries no
   b-tree, it prunes through **bloom + zone-maps** (a few bits per value vs one index entry per
   row).
3. **FTS ≈ 11% in production** (against the 8% announced from the bench), entirely **droppable in the
   cold tier** (a cold query scans a bounded row-group or relies on the bloom; no need for the
   FTS shadow on data that is rarely searched in full text). It is the most VOLATILE item of the
   three — hence the series.

## 2. WHAT IS ALREADY BUILT (do not reinvent)

The **Parquet cold tier** (`daemon/src/cold_store/`, feature `cold_tier`, 14 modules) EXISTS:
columnar **Parquet + ZSTD** writer (row-groups ~256K, write RAM bounded to one row-group),
hot→cold **aging** branch per day, **masked hot∪cold reader**, **bloom filters**
(`crypto.rs`/`reader.rs`/`planner.rs`/`vectorized.rs`), crypto seal per day,
**vectorized** decoding (x2.7 measured, see OLAP horizon). **OPT-IN end to end**: compile gate
`#[cfg(feature="cold_tier")]` + runtime gate `PLUME_COLD_TIER`. ~~**OFF in production.**~~
**FALSE — corrected on 2026-08-10: it is ACTIVE on the reference installation** (`PLUME_COLD_TIER=1`,
dozens of Parquet day-files, hundreds of MiB, more than a month of depth). This sentence
contradicted §3 of the SAME file twenty lines further
down, and it survived the correction of lever A made that very morning: see `P10.10-a`. It is
struck through and not erased, because it is what kept lever A ranked first for
four days.

The **hot tier** has **NO compression at rest** today: the `event` table is in uncompressed b-tree
pages.

⇒ **The central question of the brainstorm is therefore NOT "how to build the cold tier" — it is
built. It is: (a) what PREVENTS enabling it by default, and (b) what is left for the
hot tier, which does not move.**

## 2 bis. RE-DERIVING THE ORDER FROM THE SHARES OF A REAL DATABASE (second reading of 2026-08-09)

The levers below were ordered on a **bench** breakdown (3.65 M events), published
with the claim "the proportions are independent of scale". **A real database
contradicted it.** Reading taken by `db-stats --par-objet` (verified read-only) on the live pod:
a database on the order of a GiB, a little under two million events, accounting CLOSED. *(The first call REFUSED to publish — "gap of 1 page" under concurrent writing. The
fail-closed behavior works, and it reveals that the CLI path does not have the `BEGIN DEFERRED` that
`ventilation_serie.rs` gave itself.)*

| item | share of the file | share of **live** bytes | what the text of §3-§5 still says |
|---|---:|---:|---|
| data (tables) | **57.3%** | 60.2% | "51%" — **stale** |
| — of which `event` | 55.0% | 57.7% | 5.8x the next object |
| **b-tree indexes** | **27.0%** | 28.3% | "33%" — **stale** |
| FTS5 (shadow) | 10.9% | 11.5% | lever E, delivered on 08-09 |
| free pages | 4.8% | — | — |

**THE READING TRAP, not to be fallen into again.** Between two readings on the same day six hours apart,
`page_count` is **identical** while tens of thousands of events came in: the
growth is paid for out of the **freelist**
(7.3% → 4.8%), not out of the file. Related to **live** bytes, the composition is **flat**
(60.1/28.4/11.5 → 60.2/28.3/11.5). Anyone comparing the **raw** percentages would "discover" that
data and indexes are growing: that would be an **artifact of freelist consumption**, not a
structural movement. Margin left at this rate: less than a day.

**MARGINAL composition**, derived from the two readings, accounting closed to within 0.1% (the increase
of the three items equals, to a tenth of a percent, the freelist consumed): **~509 B / ~220 B / ~74 B ≈
802 B per net event, split 63 / 27 / 9%**. **The marginal reproduces the stock.** Uncertainty: ±3% (data), ±7% (indexes),
**±22% (FTS)**.

**THE RE-DERIVED ORDER, and what changes:**

| lever | targeted item, **re-measured** | what changes |
|---|---|---|
| **A** — enable the cold tier | 60.2 + 28.3 + 11.5% of what it takes out of the hot tier | **stays #1**, but its arithmetic must be rewritten (51/33 → 57.3/27.0). Its task remains a **measurement** |
| **D** — b-tree indexes | **27.0%** | **THE REAL CHANGE.** Second deposit, 27% of the stock **and** 27% of the marginal |
| **B** — hot-tier compression | **57.3%**, not 51% | targets **more** than the map says |
| **C** — bounded aggregation | orthogonal to size | unchanged: its priority comes from the OOM, not the bytes |
| **E** — FTS compaction | 10.9% | delivered (`4ca6339`); keeps the item at its floor |

**WHAT THE MEASUREMENT IMPOSES, and it is the conclusion of this section.** §5.4 says "do NOT touch
the remaining indexes without a usage measurement" — and **nobody has measured it**. Yet this item weighs
**27% of the file, more than all of FTS (10.9%) + the freelist (4.8%) put together**. `sqlite_autoindex_event_1`
(a little under 5% of the file) carries the dedup's exactly-once: out of the question. **But the 7 others
weigh 16.0% of the file**, behind a "do not touch" sign with no measurement behind it.
For comparison: lever E, a real engineering effort, governs 10.9%.
⇒ **the index usage measurement must be promoted next to step 1**, not stay a footnote
in step 4. Both are measurements, both are cheap, and D's item is 2.5x
E's.
Three feasible routes, in increasing fidelity: (1) replaying `EXPLAIN QUERY PLAN` over the **closed**
corpus (panels of `seeds.rs`, table `rule`, `templates.json`, SQL of the detection engine) —
enumerable, but does not cover analyst ad hoc queries; (2) `1/N` sampling of plans at the choke
point (`run_query_ex`/`soql_glue`), counted in `metric` **by the
`ventilation_serie` machinery delivered on 08-09** — slow tick, bounded, survives restart, no new probe
in a vacuum; (3) *drop-and-watch*, which the repository already does (`drop_redundant_event_indexes_background`),
but of which **P6.8-c is the scar** from having done it without measurement.

**NOT ESTABLISHED, and the doc does not claim it**: the FTS drop 18.9% → 10.9% is **consistent** with
the compaction and nothing more. Three manual readings do not distinguish a gain from an ingestion
dip. It is the breakdown series (`c4c20f4`) that will settle it.

## 3. THE FOUR LEVERS, ordered by (measured impact ÷ new code)

### ~~Lever A — ENABLE cold aging (built, OFF)~~ → **CLOSED: IT WAS NEVER "OFF" BY DECISION, AND IT RUNS** *(re-measured 2026-08-10)*

> **⚠ THE PREMISE OF THIS LEVER WAS FALSE ON THE DAY IT WAS WRITTEN — and the date proves it.**
> This heading dates from `5de5ccd`, **2026-08-06 00:54**. The cold tier stopped writing only from
> **2026-08-05 to 2026-08-06** inclusive, because of a `Dockerfile` built `--features ldap` instead of
> `ldap,cold_tier`. Those two days are **the only moment in the whole history of the repository** when
> the observation "the cold tier produces nothing" was true. **A three-day build defect was
> promoted to a permanent design state, and the ORDER OF THE FOUR LEVERS was derived from it.**
> The cause was measured and written down **the next day** (`6dac62e`, 2026-08-07 11:30); neither this document
> nor the roadmap was corrected for four days.
>
> **NONE of the four hypotheses listed below ever had to be tested: none was
> the cause.** They are kept as they are, struck through, because erasing a false hypothesis
> would erase the lesson.
>
> **STATE MEASURED ON THE REFERENCE INSTALLATION ON 2026-08-10** (checked twice, independently):
> `PLUME_COLD_TIER=1` + 4 other variables in the Deployment's `env:` (no ConfigMap carries them) ·
> banner `[cold] tier froid ACTIF — <n> fichier(s)-jour, <taille>` · symbols in the binary THAT
> RUNS: `cold_store` **7**, `parquet` **32**, against a negative witness at **0** · dozens of
> Parquet day-files, hundreds of MiB, more than a month of depth.
> **The amputation window can be read in the write dates** — two files per day before the
> outage, **NOTHING during its two days**, then a catch-up on the day of the fix.
> It is a proof by mutation that history ran by itself: feature removed → 0 written;
> feature restored → catch-up the same day.
>
> **WHAT LEVER A BROUGHT IN, MEASURED AND NO LONGER HOPED FOR** (hourly breakdown series, N=1
> aging observed, 2026-08-10): an aged day returns **on the order of a hundred MiB** to the
> freelist — data, indexes and **FTS5** in unequal shares (about 64 / 22 / 14%) · file **unchanged**.
> Accounting closed at both ends. The day moved out weighs **a few MiB** in the cold tier. **One aged day =
> a ratio of about 30x between bytes returned to the hot tier and bytes written to the cold tier** — and it does take
> all three items, which **confirms `P10.2-a`** (aging takes the FTS share) on a real database.
>
> **AND HERE IS THE REAL PROBLEM, WHICH NOBODY WAS LOOKING AT**: the freelist is consumed again at
> a rate **10 to 25% higher** than what aging returns per day (two independent windows) →
> **a net deficit, on the order of a tenth of what aging returns**. At the rate of the last point, the
> free pages run out in **a few days**, after which the file starts growing again. **Aging slows
> growth, it does not cancel it.** What remains on the table is therefore what reduces bytes PER
> HOT EVENT — **lever B** — and not lever A.
>
> **WHAT REMAINS UNMEASURED, AND IT IS NAMED**: the RAM peak *attributable* to aging.
> The cgroup's `memory.peak` is close to three quarters of the limit and `VmHWM` about a third, but these
> are **cumulative, untimestamped** maxima over nearly a day — nothing says whether they fall during aging or
> during a query. Likewise for the duration, the CPU and the effect on hot latency: **aging
> is completely SILENT** (a hundred MiB freed without a single log line), which is
> exactly `P10.5-a`, still open. **THE measurement that unblocks all four axes at once**: a
> success line per `cold_age_run` carrying day, rows, bytes, duration and RSS peak. ~10 lines,
> and three of the four axes become observable without a bench or a copy of production.
>
> Design bounds, read in the code and checked against reality: writing capped at a single
> row-group (`ROW_GROUP_ROWS = 262 144`) — a huge day makes MORE files, not bigger ones;
> reading = `degré × un fichier déchiffré`, i.e. four day-files of a few MiB each in flight,
> negligible next to 2 GiB.

### ~~Lever A (original text, kept struck through)~~ · ENORMOUS impact, new code ~0
Moving old days to Parquet/ZSTD/bloom removes in one go **their `event` rows** (part
of the 51%) **AND their share of the 33% of indexes** (the cold tier carries none) **AND their FTS**. On a
30 d retention where ~90% of events are older than N days, the hot database melts away.
**What it ALSO does for the OOM (P6.1-b):** the `stats … by` over the hot window scans **far
fewer rows** → the sorter materializes far less. It is the only lever that attacks BOTH
problems with code **already written**.
**THE REAL TASK IS THEREFORE A MEASUREMENT, NOT A BUILD:** *why is it OFF in prod?* Hypotheses to
test, one by one — (i) decompression cost on cold queries never measured under real
load; (ii) does the hot∪cold reader have blind spots (P51 "silently truncated" was a
symptom, fixed); (iii) crash-safety of multi-file aging tested but never in prod;
(iv) does the per-day crypto seal add a key cost. **None can be settled without measurement.**

### Lever B — COMPRESSION AT REST of the HOT tier (to be built) · BIG impact on the 51%
What stays hot (the recent window, the only one indexed+FTS) keeps its large columns in plain
pages. **Compress the bulky columns NATIVELY** (`fields` JSON, `message`) — not the database,
the VALUES — with zstd, transparently to the engine. Two forms, to be decided between by measurement:
- **B1 — per value**: each `fields`/`message` stored zstd (dictionary shared per source for
  small blobs, otherwise plain zstd). Simple, local, reversible; the price is a
  decompress-on-read that the requirement **explicitly points out** ("decompression can be costly if
  done badly"). ⇒ measure the read cost BEFORE generalizing; keep the filtered/
  indexed columns (host, src_ip, severity, ts) IN THE CLEAR so that the index and the WHERE pay nothing.
- **B2 — per page** (compression VFS under SQLCipher, of the `sqlite_zstd`/`cvfs` kind): fully
  transparent, but touches the I/O layer and encryption — high **confidentiality risk** (the temporary file,
  see P10.1-a) and reliability risk. **Ruled out by default** unless proven to open no plaintext.
**Non-negotiable invariant (P10.1-a):** none of these forms may produce a plaintext dump on
disk. Compression happens IN RAM on the value, before the SQLCipher encrypted write. Never an
intermediate file.

### Lever C — NATIVE BOUNDED AGGREGATION (P10.3, to be built) · closes the OOM itself
Independent of size. The sorter materializes 1 row/scanned event for lack of an in-memory
spill mechanism (P10.0). **A native aggregator with bounded state** — for `count`, `dc`,
`count by` — maintains an accumulator of bounded size (HyperLogLog for `dc`, bounded top-N for
`count by`, see `AnswerShape`/`TruncatedAggregate` ALREADY in place) instead of delegating to the SQLite
sorter. Returns a result **declared partial** when cardinality exceeds the budget — consistent with
what exists, and **costs NO confidentiality** (nothing touches the disk). It is the real
closure of P6.1-b, the one that P10.1-a explicitly left open.

### Lever D — INDEX REDUCTION (already started) · small remainder
P10.2-d removed 9 useless indexes, P6.8 the auto-index. What remains, measured: `dedup UNIQUE` (6.2%) is
**necessary** (exactly-once), the host/src_ip composites serve active detection (P6.8-c proved it
painfully — do NOT touch again without measuring usage). Little fat left; **do not
over-optimize an item that has already been cleaned up**.

### Lever F — REDUCING THE DETAIL MODE OF THE FULL-TEXT INDEX · **WEIGHED ON 2026-08-28, AND THE DECISION IS "NO" FOR TWO OF THE THREE FORMS**

**THE INVENTORY FIRST, THE DECISION SECOND** — that is the order that `P10.2-g` imposes, and it is held
here. The open question was: "reducing the detail removes forms of search, but nobody
knows whether anyone emits them". **The answer is: THE PRODUCT ITSELF emits them, by construction,
and not by accident of usage.** `fts_plan` (`daemon/src/soql_glue.rs`) has three stages, and two of
them produce forms that reduced detail forbids:

* **stage 1, VERBATIM** — "everything that works today (`a OR b`, `err*`, `(x OR y)`, `NEAR(…)`)
  keeps working, byte for byte". `NEAR(…)` is therefore a PUBLISHED capability of the search bar.
* **stages 2 and 3, LITERALIZATION** — this is the remedy of `P10.7-a`: a term that the engine refuses
  on its own is put **in quotes**, which makes it a PHRASE. And the default tokenizer splits
  on punctuation, so that an input of a single "piece" becomes a phrase of several
  tokens: `10.0.0.1` -> 4 tokens, `/usr/bin/dash` -> 3.

**MEASUREMENT (2026-08-28, `sqlite3` 3.53.4, `fts5` table of the shipped form).** The FIVE inputs that
`P10.7-a` had measured as broken, rendered as the product renders them today:

| input, RENDERED by `fts_plan` | `detail=full` (shipped) | `detail=column` | `detail=none` |
|---|---|---|---|
| `"10.0.0.1"` · `"/usr/bin/dash"` · `"kube-audit"` · `"user:root"` · `"exec(1)"` | served | **`fts5: phrase queries are not supported (detail!=full)`** (5/5) | same (5/5) |
| `NEAR(failed password, 5)` | served | **`NEAR queries are not supported`** | same |
| `message:sshd` (column filter) | served | served | **`column queries are not supported`** |
| `sshd` · `fail*` · `sshd OR sudo` | served | served | served |

⇒ **`detail=column` WOULD REOPEN `P10.7-a`**, closed on 2026-08-09: searching for an IP address in one's
SOC would once again be an engine error. This is not a theoretical capability lost, it is the
delivered remedy that stops working.

**AND WHAT IT BRINGS IN, MEASURED ON THE SAME BENCH** (300 000 SIEM-like rows, `content='event'`,
after `optimize` + `VACUUM`, 4 KiB pages):

| form | `event_fts_data` | `event_fts_docsize` | FTS total | gain vs shipped | **carried over to the production shares of 2026-08-09** (FTS 10.7%, of which `event_fts_data` 9.3% — the reading that publishes BOTH) |
|---|---:|---:|---:|---:|---|
| `detail=full`, `columnsize=1` (**shipped**) | 17 412 096 B | 3 612 672 B | 21 045 248 B | — | — |
| `detail=column` | 15 994 880 B | 3 612 672 B | 19 628 032 B | **−8.1%** of `_data` | **≈ −0.8% of the file** |
| `detail=none` | 5 947 392 B | 3 612 672 B | 9 580 544 B | **−65.8%** of `_data` | **≈ −6.1% of the file** |
| `detail=full`, **`columnsize=0`** | 17 412 096 B (**identical to the byte**) | **absent** | 17 432 576 B | **−17.2%** of the FTS item | **≈ −1.4% of the file at most** |

**THE THREE DECISIONS, AND THEIR REASON:**

1. **`detail=column`: ELIMINATED BY DOMINANCE.** It costs exactly the same family of capabilities as
   `detail=none` (phrase + `NEAR`) and brings in **eight times less**. No trade-off chooses it.
2. **`detail=none`: the only real gain, and its price is `P10.7-a` + `NEAR` + column filters.**
   It is NOT committed: it trades against a search capability that the product publishes and whose
   loss has already been measured as a defect. To be reconsidered only if the search bar
   explicitly gives up phrases — which is a product decision, not a storage one.
3. **`columnsize=0`: the only reduction WITHOUT measured loss for THIS product** — and it is the new
   result of this weighing. All the forms above remain served, the deletion trigger
   `event_ad` works, `merge` works, and `bm25()` **does not error** (it returns a
   different weighting: −1.318 against −1.593 on the same row, because column sizes
   are no longer stored). **Nobody would notice here: the repository calls neither `bm25()`, nor
   `ORDER BY rank`, nor `snippet()`, nor `highlight()` on `event_fts`** — the only `rank` in the code is the
   *command* `INSERT INTO … (…, rank) VALUES('merge', …)` of `compactage_fts.rs`, which has nothing to do with it.
   Search orders by `e.ts DESC`. **It is NOT committed either**, for two written reasons:
   it is a change of on-disk FORMAT (the table has to be REBUILT, hence a migration and a
   window), and the gain is **bounded by 1.4% of the file** — less than what one aging pass returns.

**WHERE THE "AT MOST 15%", AND THEREFORE THE "1.4%", COMES FROM — THE DERIVATION, WRITTEN DOWN** *(it was missing; the
figure circulated without it, and it fell on the side that UNDERSTATES the gain, that is, on the side that supports
the conclusion "do not commit it")*. `columnsize=0` removes `event_fts_docsize`, and nothing else:
`event_fts_data` is **identical to the byte** (column 1 of the table). The gain is therefore bounded by everything
the FTS item contains OUTSIDE `_data`:

* production reading of 2026-08-09 — the only one that publishes both: **FTS 10.7%** of the file, of which
  **`event_fts_data` 9.3%** ⇒ everything-but-`_data` = **1.4% of the file**, and that is the UPPER BOUND
  of the gain;
* related to `_data`, this bound is `1,4 / 9,3` = **15.1%** — that is exactly the "at most 15%",
  and it is its only source. The bench, for its part, measures `3 612 672 / 17 412 096` = **20.7%**: the
  synthetic corpus carries proportionally more `docsize` than production;
* `15 % × 9,3 %` = **1.4% of the file**, the last column.

**WHAT THIS BOUND IS NOT.** It is an upper bound: `event_fts_idx` and `event_fts_config` ALSO live in
that 1.4%, and their share was **not** read separately — the real gain of `columnsize=0` is therefore
strictly below 1.4%, all the more so as these two objects weigh something. **MATCHED READING TRAP, and it
happened here:** the next production reading, six hours later on the same day, publishes
**FTS 10.9%** (freelist 7.3% → 4.8%) but **no `_data` breakdown**. Pairing that 10.9% with the 9.3%
of the other snapshot gives 1.6% / 17.2% — two different photos of the same day, whose gap is
freelist consumption, not structure. The column now cites the CONSISTENT pairing.

**WHAT THIS WEIGHING DOES NOT PROVE, AND IT MUST BE SAID.** It was done against `sqlite3` **3.53.4**,
while the product links **SQLCipher (vendored SQLite 3.39.4)**. The measured refusals are properties
of FTS5 documented since its origin, but **the sizes have not been re-taken on the linked engine**.
**That is why the last column is derived from the production shares and not copied from the bench** —
a bench gain presented as a product gain would be exactly the mistake that §1 of this document has
already made once.

### Lever E — COMPACTING THE FULL-TEXT INDEX (P10.7-b, built on 2026-08-09) · the only free one

**This lever was missing from the list above, and its absence was measurable.** The four levers A–D
all assume that the full-text index grows with the data. **That is false: it ALSO grows with
DELETIONS.** An external-content FTS5 table cannot remove a posting in place — the
`event_ad` trigger writes a DELETION one, which is ADDED — and the space is only returned at
SEGMENT MERGE, which plume **never** triggered. That is part of the gap between the 8.1%
of the bench above and the 17.9% read on a real database: **aging residue**, not growth.

> **WHAT THE NEXT READING SAYS — AND WHAT IT DOES NOT.** On 2026-08-09, the day after
> this lever was deployed, the real database measures **FTS5 = 10.7%** (`event_fts_data` 9.3% of the
> file). That is consistent with a compaction gain. **It is not proof**: three manual readings
> spaced days apart do not distinguish a compaction gain from an ingestion dip or
> less active aging. The proof will come from the series (`plume_db_poste_bytes{poste="fts"}`, one point per
> hour since this batch of work) — that is exactly the question it was built to settle.

Measured on 2026-08-09 on the product's exact SQLite (SQLCipher 4.5.3 / vendored SQLite 3.39.4,
PRAGMAs of `server::tune`), database with the profile of `bench/profile-prod.json`, 1 200 000 events then a
real `DELETE` of 58.4%:

| quantity | before purge | after purge | after compaction |
|---|---|---|---|
| `event_fts_docsize` | 14.11 MiB | **5.88 MiB** (−58.3%, it FOLLOWS) | 5.88 MiB |
| `event_fts_data` | 135.27 MiB | **185.69 MiB** (+37.3%, it GROWS) | **56.53 MiB** (−69.6%) |

**The how matters as much as the how much.** `optimize` and `merge` reach the same floor, but
`optimize` does it in **17.08 s in a single stretch under the write lock, with a 192.6 MiB
WAL burst**, and an interruption loses everything; `merge` with a **NEGATIVE** budget (`-500` pages/pass) does it in
25 passes of **1.04 s at worst**, with **13.4 MiB of WAL**, and each committed pass survives a
`SIGKILL` — the resumption converges byte for byte. The POSITIVE budget, for its part, returns **nothing at all** on
this index (no level reaches `usermerge`): that is the lever's trap. These two costs (lock,
WAL) are set by the pass budget and **do not grow with the index** — checked at twice the
volume. The RAM is that of `cache_size` and nothing else (66.3 MiB, identical for both arms).

Delivered: `daemon/src/compactage_fts.rs`, called at the end of `retention_run` (where the dead weight has just
been created) and by `plume-daemon fts-compact`. Settings `PLUME_FTS_COMPACT`(=1) /
`_PAGES`(=500) / `_PASSES`(=8) / `_REPOS_MS`(=200), all through `cfg()`. **What this lever does
not do**: shrink the file. The pages go to the freelist and are reused by ingestion;
`page_count` does not move.

## 4. THE TARGET, AND THE HOT/COLD BOUNDARY

Decoded from the figures: **the hot tier must be small and indexed; the cold tier, tiny and pruned.**
- **HOT** = recent window (to be measured: how many days remain "often queried"?), in
  SQLite/SQLCipher, indexed + FTS, **large columns compressed (lever B)**. This is what the
  sorter scans, hence **as small as possible without breaking interactivity**.
- **COLD** = the rest, in Parquet/ZSTD/bloom (lever A), **without b-trees, without FTS**. Rare queries,
  bounded row-group scan + bloom/zone-map pruning.
- **BLOOM**: the mechanism that makes the cold tier queryable without an index — one filter per column and per
  row-group (a few KiB) answers "value X is CERTAINLY not here" and discards the block without
  reading it. That is what replaces, at ~1% of the cost, the 33% of b-tree indexes for cold data.

## 5. RECOMMENDED ORDER OF ATTACK (each one validates on its own, none blocks the next)

1. ~~**MEASURE why the cold tier is OFF** (lever A)~~ → **DONE, AND THE LEVER IS CLOSED**
   *(2026-08-10)*. It was not OFF: the line above was written **during** a three-day build
   outage, the only window in which it was true. It runs, it returns **on the order of a
   hundred MiB per day** to the hot tier for a few MiB written to the cold tier, and **this gain is already IN the
   baseline read off** —
   it is not a gain to come. **What takes its place at the top is not one of the four levers**:
   it is **a success line on `cold_age_run`** (`P10.5-a`), ~10 lines, which makes measurable
   in one go the duration, the CPU, the attributable RAM peak and the effect on latency — today all
   four unknown because aging is SILENT. **Then lever B**, the only one to attack
   the net freelist deficit that the measurement brings to light.
2. **BUILD native bounded aggregation** (lever C / P10.3) — closes the OOM from the top, whatever
   the size of the hot window. Independent, confidentiality-neutral.
3. **BUILD hot-tier compression at rest** (lever B1 per value) — attacks the 51% that
   remain hot, keeping the filtered columns in the clear. Measure the read cost first.
4. Do NOT touch the remaining indexes (lever D) without a usage measurement (lesson P6.8-c).

## 6. INVARIANTS THAT DO NOT BEND (otherwise we regress what we have closed)

- **Confidentiality (P10.1-a)**: no event byte in plaintext on disk outside SQLCipher/sealed
  Parquet. Compression happens in RAM on the value. The cold Parquet is sealed per day.
- **The DEFAULT = prod, and everything is configurable** (host/Docker/k3s). A third party must get our
  figures. Each lever has its `PLUME_*`, default = what we decide after measurement.
- **Generic** (P6.2-a): gains are measured on SEVERAL profiles, not only ours — our
  bench events are 4.4x larger than our prod, hence an honest worst case.
- **No silent loss**: a partial cold or aggregated result is DECLARED (`AnswerShape`),
  never a truncated total presented as exact.
- **Byte-identical in mode 0**: each lever OFF leaves the current behavior intact.

---
*Next concrete step: the founding measurement of §5.1 (enable the cold tier on a bench copy, measure
the 3 figures). Then P10.3 (bounded aggregation). Anchored, not assumed.*
