# `bench/` — the measuring instrument

[Français](README.md) | [English](README.en.md)

This directory optimizes nothing. It makes optimizations **provable**. "Measure first,
optimize afterwards": without a published instrument, an announced improvement cannot be verified and an
announced figure cannot be challenged.

## The pieces

| File | Role |
|---|---|
| `prod-profile.sql` | **Read-only** extraction of a production's data profile. Extracts only aggregates: counts, cardinalities, lengths, key names. **Never** a row value. |
| `distill_profile.py` | Turns the output of the SQL above into `profile-prod.json`, marking each section `measured` or `derived`. |
| `profile-prod.json` | The versioned profile. It is the **only** input of the generator. |
| `make_fleet_profile.py` | **Derives** a FLEET profile (`profile-fleet-N.json`) from the measured profile: the number of hosts becomes an explicit parameter. Refuses to guess which sources are host-local — see below. |
| `fleet-per-host.txt` | The **operator declaration** that the script requires: which sources run on each machine. One line, one reason. |
| `make_axis_profile.py` | **DERIVES a profile that differs from the measured one along ONE axis only** — cardinality of extended keys, event size, severity distribution, source names. Each axis comes from a DECISION of the execution path (see below). Refuses to change two at once: a profile that differs on two parameters measures neither. |
| `campagne-generique.sh` | The **multi-profile** campaign: the same matrix on each profile, at equal volume, **witness measured twice** to give the noise band. |
| `probe_route_b.py` + `campagne-noms-sources.sh` | The probe for **ROUTE B** (`event_dim_rollup`), the only form that the matrix does not fire, and the only one whose route depends on the source's **NAME**. |
| `campagne-10m.sh` | Filling to **10 M through the real path**, with **proof that the dataset survived** (recount after the matrix). |
| `gen_events.py` | **Deterministic** generator (splitmix64, explicit seed, no call to the clock) with the profile above. Zero real data. |
| `measure.py` | The matrix: p50/p95 latency, **measured peak RSS** (/proc sampling every 15 ms), disk reads, machine pressure. The windows there are **derived**, not enumerated. |
| `probe.py` | The ingest sampler. Records, at each tick, what makes it possible to say WHY throughput drops: daemon CPU, CPU of the rest of the machine, bytes read/written at the block layer, cgroup memory stall. |
| `parity.py` | **Is the answer the SAME?** Queries TWO daemons (with and without cold tier) on the SAME matrix and compares **the values**, not the times. The set of checks is not written: it is `query_classes` × `windows` from `measure.py`. |
| `concurrency.py` | **N analysts at the same time.** The blind spot that `measure.py` declares itself (one query at a time → nobody waits their turn). Measures, in this order: CORRECTNESS under load (each concurrent answer compared by its VALUE with the answer obtained alone), RAM under an enforced budget (RSS + cgroup + `memory.events`), the latency/throughput curve, and the BREAKDOWN of waiting (`sem_wait_ms` = the permit; `db_lock_wait_ms` = the lock of the shared connection; `prepare_ms`/`exec_ms`). The query mix is **derived** from the solo pass that precedes it. |
| `report.py` | Renders `docs/BENCHMARK.md`. Hides no cell. |
| `run.sh` | **The single command.** Chains everything, 2 GiB budget *enforced* by cgroup. |
| `fts-compaction/` | **The `optimize` versus bounded `merge` trade-off** (P10.7-b) — the only bench that does not query the daemon. The question concerns what FTS5 does with its SEGMENTS when a purge leaves it deletion postings: it is a property of the storage engine, measured on the SQLCipher amalgamation that the daemon LINKS (same `-D` as the `build.rs` of `libsqlite3-sys`, but `-O2` — cargo's `dev` profile compiles this C at `-O0`, which would distort any duration). `mesurer.sh` **validates the instrument before using it** (SQLCipher version, FTS5, dbstat) and refuses to publish a figure if it is not the product's SQLite. |
| `results/` | The **raw data** of the measurement published in `docs/BENCHMARK.md`. Versioned on purpose — see below. |

## The windows are DERIVED, and a window that is not covered is not measured

`measure.py` does not carry a list of chosen windows. Each one comes from a parameter of the **product**
— or from the absence of bounds:

| Window | Where it comes from |
|---|---|
| `1h`, `24h` | interactive use (triage, dashboard). |
| `{N}d` | `PLUME_COLD_HOT_WINDOW_DAYS` (default **7**, `daemon/src/cold_store/aging.rs`) — **the product's hot/cold boundary**. Moving the hot window to 14 d moves the measured cell: nothing needs to be touched here. |
| `au-dela-{N}d` | the band entirely older than the hot window: the **pure-cold** regime when the cold tier is active. |
| `{R}d` | `PLUME_RETENTION_DAYS` — the whole retention. |
| `all` | unbounded: crosses the boundary. The most expensive case. |

**The guard**: a bounded window is fired only if the dataset **covers** it
(`portée <= span_days`). On a 28-day dataset, the "30 d" window is therefore NOT measured — it
would measure `all` under a label that lies. It is written in the JSONL as **not measured with
its reason**, and `docs/BENCHMARK.md` publishes it as such. The guard compares a range with an
extent: it has no list of forbidden windows, so it also holds for any window
added later. To check without measuring anything:

```sh
python3 bench/measure.py --list-windows --end-ts 0 --span-days 28 --hot-window-days 7 \
    --retention-days 30 --user x --password x --pid 1 --config-id x
```

## Concurrency — the guards are DERIVED, including the one on the sweep

`concurrency.py` has no list of queries and no list of "allowed" levels. Everything that
could be written by hand is derived there from a measurement or from a declaration by the daemon:

| What could be written by hand | What it is derived from |
|---|---|
| the size of the measured semaphore | **asked of the daemon** (`/api/system/diag` publishes `PLUME_QUERY_CONCURRENCY`). `--expect-sem` compares the pass's label with what the daemon REALLY applies, and refuses if the two diverge: a pass whose label lies measures nothing. |
| the query mix | the SOLO pass that precedes it: each **family** of the matrix (`C1`…`C6`) enters through its most expensive representative, if it costs at least 10 × the **measured floor** in the same pass. The floor's family fails its own test and excludes itself. The floor is added separately — it measures the dashboard click under load. |
| the window | the only **unbounded** window that `measure.windows` keeps (the most expensive case). Recognized by that property, not by its name. |
| "the two passes are comparable" | the mix is **DERIVED by the first pass then IMPOSED on the following ones** (`--mix`, set by `run.sh`). Two passes that each derive their own can differ — measured: `C5` 3.7 s against `C5b` 6.0 s, two classes of the same family that the machine can rank differently from one time to the next — and their throughput gap would then no longer be attributable to the semaphore. Each pass's own derivation is still computed and published next to the imposed mix. `report.py` additionally refuses to publish the comparison of two passes whose mix differs. |
| the levels of the sweep | free, but **guarded**: the sweep must contain a point strictly below the semaphore AND a point strictly above. Below, no query can wait; the queue only begins beyond. A sweep that does not cross that point measures a single regime and calls it "the capacity". |
| "the answer has changed" | the fingerprint from `parity.py` (order-insensitive) + the pagination total, against the SOLO reference of the SAME pass. A class whose answer **already varies on its own** is withdrawn from the verdict, and the withdrawal is published. |
| "the `sem_wait_ms` field is wrong" | the semantics of a semaphore: with *N* analysts for *S* ≥ *N* permits, **no** query can wait its turn. Any wait published at these levels is therefore something else. No threshold is involved — the guard compares a count of permits with a count of clients, so it holds for any semaphore size. It bit (10.2 s published under that name, 16.5 s solo); since the fix it **makes the harness fail** (`rc=5`) instead of publishing a figure that would send the operator off to enlarge the semaphore. |
| "where does the wait come from, if not the semaphore" | the daemon publishes the TOTAL breakdown (`prepare + sem_wait + exec == server`, `daemon/src/query_timing.rs`) and, separately, `db_lock_wait_ms` — the time spent OBTAINING the lock of the shared connection. The harness does not recompute it: it relays it. |
| "the daemon is ready" | three consecutive shots whose wait before the engine is **under a millisecond**. This wait is DERIVED (`server_ms - exec_ms`: everything the query goes through before executing), never `sem_wait_ms` alone — since that field now measures only the permit, it is zero by construction as soon as a permit is free, and a probe that looked only at it would declare "at rest" a daemon that still holds the write lock. The time it took is published — it is itself a measurement. |

```sh
BENCH_PHASES=concurrency BENCH_DIR=<copie d une base remplie> bench/run.sh
# variables: BENCH_SEM_SWEEP (default 3,8) · BENCH_CONC_LEVELS (default 1,2,3,4,6,8,10)
#             BENCH_CONC_ROUNDS (passes per analyst) · BENCH_CONC_PROBE_REPS
```

## The FLEET profile — what is measured, what is derived

The profiled production is **single-node**: its 32 sources all have `distinct_hosts: 1`. As
`host` is one of the six indexed columns, any figure published on a filter or a group-by by
host there bears on a **degenerate cardinality-1** case. `make_fleet_profile.py` therefore produces
profiles where the fleet size is an **explicit parameter**:

```sh
python3 bench/make_fleet_profile.py --hosts 50 --per-host @bench/fleet-per-host.txt \
    -o bench/profile-fleet-50.json
BENCH_PROFILE=$PWD/bench/profile-fleet-50.json BENCH_EVENTS=600000 bench/run.sh
```

| | |
|---|---|
| **Measured**, taken as is | per source: severity, categories, message and `fields` lengths, extended keys with types/lengths/cardinalities, `src_ip` rate; the hourly curve; the histograms. |
| **Derived**, marked `provenance: "derived"` | the weight `n` of host-local sources (multiplied by the number of hosts) and the cardinality of `host`. Each source keeps its `n_measured_mono_host`. |
| **Neither — declared** | *which* sources are host-local. The single-node profile contains nothing that allows it to be inferred: `--per-host` is **mandatory**, and the script stops rather than guess. The declaration is versioned in `fleet-per-host.txt`, one line per source with its reason. |
| **Not multiplied**, deliberately | the cardinality of `src_ip` (a larger fleet does not create more clients on the Internet), the message vocabulary, the per-host density. |

The distribution of events across hosts is **uniform**: it is the hardest case for a
group-by (all groups are populated) and the easiest for a filter on one host (selectivity
exactly 1/N). It is a bench assumption, not a measurement — a real fleet is unbalanced.

## Genericity — the axes are DERIVED from the execution path, and the ones set aside are TOO

A figure measured on our profile proves OUR case. To know whether it holds elsewhere, it has to be
re-measured on datasets that differ, and the gap published. The axes still must not be chosen at
random: each of the ones below corresponds to a **decision** that the daemon makes based on
the DATA, not on the query.

| Measured axis | The decision it moves | Anchor in the code |
|---|---|---|
| cardinality of `host` | selectivity of `idx_event_host` (filter) and number of groups (group-by) | `migrate.rs` (`idx_event_host`) |
| cardinality of extended keys | selectivity of the **expression index seek** on the 10 keys of `HOT_FIELDS`, and number of groups of a `by <clé>` | `soql_glue.rs` (`HOT_FIELDS`), `maintenance.rs` (`idx_ev_f_*`) |
| event size | **no index** covers `message` or `fields`; in GXQL a free term compiles to `LIKE '%…%'`. The cost is proportional to the BYTES read | `db/schema.sql`, GXQL compiler (`freetext_col`) |
| severity distribution | `event_rollup.src_ip` is a DIMENSION only if `severity >= PLUME_ROLLUP_SRCIP_MIN_SEV` (default 3) — otherwise the value is brought back to `''` | `rollups.rs` |
| source **name** | ROUTE B (`event_dim_rollup`) is taken only if the (source name, dimension) pair appears in `DIM_ROLLUP_SPECS`, a **hard-coded** table | `rollups.rs` (`DIM_ROLLUP_SPECS`), `rollup_route.rs` |

**And the axes SET ASIDE, with their reason** — an axis set aside without a reason is a disguised blind spot:

| Axis set aside | Why |
|---|---|
| source mix (uniform) | **MEASURED, not assumed**: making the mix uniform moves the share of `severity >= 3` from 0.064 to 0.219 and the average size from 252.8 to 237.4 bytes — because severity is a property OF each source. The gap would be attributable neither to the mix nor to severity. The profile `profile-axe-mix-uniforme.json` is kept: its `axis` section CARRIES this proof. |
| cardinality of `src_ip` | would move at the same time the indexed column (`idx_event_srcip`) AND the top-N ceiling of the rollups (`PLUME_ROLLUP_SRCIP_TOPN`). Same attribution problem. |
| cardinality of `category` | `category` is indexed, but **no class of the matrix filters or groups on it**: the axis would be exercised by no query. Set aside for lack of a probe, not for lack of importance. |
| `env_id`, `origin`, `engagement_id` | constant in mode 0 (multi-tenant off, outside an engagement). |
| `dst_ip`, `url`, `xff` | not indexed AND not queried by the matrix. |
| retention depth | it is not a property of the DATASET but a daemon setting; the windows are already derived from it, and the coverage guard already sets aside the ones the dataset does not carry. |

**What these profiles do not claim to be**: they are SYNTHETIC and DERIVED. They are nobody's
production. They answer "does the figure move when this parameter moves, and by
how much", which is the only question a bench can answer without the third party's data.
They do NOT answer "here is what such-and-such a client will measure" — that sentence would require THEIR dataset.

### Noise before the gap

A gap between two profiles means nothing as long as we do not know what the **same** measurement returns
twice in a row on the **same** dataset. The campaign therefore measures the witness **twice**,
bracketing the campaign (one pass at the start, one at the end, so machine drift included), and the
noise band that comes out of it becomes the criterion: a gap is declared attributable to the profile only
if it falls outside the **full range** of this band. No threshold is written — if the machine is
noisier, the band widens and the document **concludes less**. That is intended: a bench must lose
conclusions when it loses conditions, never gain confidence.

`measure.py` publishes for this the **per-shot samples** (`wall_samples_ms`, `sql_samples_ms`) and
no longer only their percentiles: a dispersion cannot be recomputed from a p50.

## The retention guard — the trap that bit, closed for good

A dataset frozen once and for all ends up leaving the daemon's retention: the clock moves forward, the
retention edge catches up with the tail of the dataset, and the purge DELETES events **during** the
campaign. This is not theoretical — measured on 2026-08-01: 1 440 007 -> 1 436 516 events in half
an hour, producing a FALSE correctness verdict blamed on concurrency when it came from
the clock. And the purge does not wait: `spawn_retention_loop` (`daemon/src/server/boucles_de_fond.rs`) runs a
first time **60 s after startup**, then every hour.

`run.sh` now REFUSES to start when the margin is negative, and announces it when it is
not. The guard is DERIVED — it compares two instants, `end_ts - span_days` against
`now - retention_days`, and so holds for any retention, any extent and any `end_ts`:

```
marge de rétention : 48 h avant que la purge n'entame le jeu (échéance …)
STOP: LE JEU EST DÉJÀ DANS LA ZONE DE PURGE — il a 42 h de retard.
```

A START guard proves nothing, however, about what happened DURING: `campagne-10m.sh`
therefore recounts the events **after** the matrix and publishes the before/after.

## Why the raw data are versioned

A table of measurements without its raw data can only be **believed or ignored**; it cannot
be *contradicted*. `results/` therefore carries the files from which `docs/BENCHMARK.md` is rendered:

| File | Content |
|---|---|
| `results/results.jsonl` | One line per cell: wall and SQL p50/p95, peak RSS, bytes read, memory pressure before/after, `swap_suspect`, the query and its compiled SQL. |
| `results/results-smoke-200k.jsonl` | The 200 k event shakedown pass. |
| `results/results-2026-07-31.jsonl` | The 07/31 pass: the product's hot window, cold tier ACTIVE (with the columnarization summary and the hot/cold **answer parity**), and the three fleet profiles. Also carries the windows SET ASIDE by the coverage guard — an absence there is a data point. |
| `results/ingest_rate.csv` | The ingest throughput curve of the 07/30 pass (loaded machine, without CPU columns). |
| `results/ingest_rate-quiet-2g.csv` | The 07/31 curve, machine at rest and complete probe: it is what makes it possible to ATTRIBUTE the collapse in throughput instead of assuming it. |
| `results/results-2026-07-31-corrige.jsonl` | The 07/31 pass RE-RUN after the cold truncation fix (hot witness `chaud-seul-v2@1.4M` + `froid-actif-v2@1.4M`, same machine, same database copies, post-fix binary). It is the one that describes the current code. |
| `results/parity-avant-2026-07-31.jsonl` | Hot/cold parity measured over the whole matrix **BEFORE** the fix: 53 checks out of 105 silently diverge. |
| `results/parity-apres-2026-07-31.jsonl` | The SAME measurement **AFTER**: no scalar aggregate silently diverges any more. |
| `results/parity-couverture-2026-07-31.jsonl` | The SAME measurement, RE-RUN with the post-fix binary for **rollup coverage**, on two FRESH copies of the same database and with a VERIFIED stabilization (both daemons have ticked, their coverage is published). It is the one that measures that the x6.6 undercount of the previous pass is fixed: the side without cold tier now returns EXACTLY the raw count. It describes the current repository; the caveats of earlier passes describe their binaries. |
| `results/fill-progress-quiet-2g.txt` | The generator's progress lines for this pass. `.txt` extension and not `.log`: `.gitignore` excludes `*.log`, and published data must not depend on an ignore exception. |
| `results/concurrency-2026-08-01.jsonl` | **CONCURRENCY**: one line per LEVEL (N simultaneous analysts), plus one header line per semaphore value (solo reference class by class, mix derivation, settling, cgroup state). It is the input of the document's "La concurrence" section. |
| `results/concurrency-requests-2026-08-01.jsonl` | The SAME pass, **one line per query** (analyst, round, class, relative instant, wall/server/wait, answer fingerprint, correctness verdict). Raw data: it is what makes it possible to recompute any published percentile, or to contradict a correctness verdict query by query. `report.py` accepts it without using it (it recognizes it by its shape). |
| `results/concurrency-reproduction-2026-08-01.jsonl` | **THE IMPOSSIBLE VALUE, REPRODUCED** before touching it. SHORT pass (levels 1 and 4, 1 round) on the BEFORE binary: `sem_wait_ms` reaches **16 456 ms in a SOLO pass** there and 3 348 ms with 1 analyst for 3 permits. It serves only one purpose, and it is the most important one: seeing the defect RED on this very machine before fixing it. Its mix is DERIVED (not imposed) — so it enters no throughput comparison, and `report.py` sets it aside by itself. |
| `results/concurrency-attribution-2026-08-01.jsonl` | **WHAT `sem_wait_ms` WAS MEASURING.** SHORT pass (2 levels, 1 round) fired on the binary that breaks down the wait but keeps the coverage read on the shared write lock. It is the one that ATTRIBUTES: with 1 analyst for 3 permits, the permit wait falls to **0.000 ms** and 2 876 ms reappear in `db_lock_wait_ms`. Without it, the fix would be a claim; with it, it is a measurement. |
| `results/concurrency-corrige-2026-08-01.jsonl` | The COMPLETE post-fix campaign (same levels, SAME imposed mix as the pass before, two semaphores). It is the one that describes the current repository. |
| `results/concurrency-requests-corrige-2026-08-01.jsonl` | The per-query detail of the pass above. |
| `results/generique-2026-08-03.jsonl` | **THE MULTI-PROFILE CAMPAIGN**: the same matrix on 5 profiles (witness, fleet of 1 and 50 hosts, cardinality x25, shifted severity, event size x3), at equal volume, **plus the witness measured TWICE** — it is this repetition that gives the noise band without which no inter-profile gap can be interpreted. Carries the **per-shot samples** (`wall_samples_ms`), so any dispersion can be recomputed from it. The fleet labels carry `-v2`: the 07/31 passes had the same names, and without this suffix two campaigns from different binaries would have merged silently. |
| `results/routeb-noms-sources-2026-08-03.jsonl` | **THE SOURCE NAME DECIDES THE ROUTE.** Two datasets identical but for one detail — the name of the sources. `served_from` goes from `rollup` to `raw`: DIRECT proof, not an inference from latencies. |
| `results/hotfields-2026-08-03.jsonl` | **INDEXED FIELD VERSUS NON-INDEXED FIELD**, a MATCHED pair derived from the profile (same type, same cardinality, same presence rate). Carries the EFFECTIVE setting read back from the daemon, not the one assumed from the code. **HISTORICAL PASS, and that is what gives it its value**: its three lines were taken on a binary that still carried ADAPTIVE indexing — mechanism at 0, then at 1, then at 1 after a complete tick. The non-indexed side stays at the same order of magnitude in all three cases: the mechanism promoted no index, and it was removed for that reason (P6.8-b). The setting they name no longer exists, and the probe no longer records it; these lines therefore cannot be re-run as they are. |

**Scanned before publication**: personal paths, e-mails, tokens (`ghp_`/`AKIA`/`xox*-`/
`AGE-SECRET`/`hvs.`/JWT), IPs outside documentation ranges, hexadecimal ≥ 32 — **zero
matches**. The only queries that appear there are those of the bench, synthetic.
A single string triggers the "e-mail" pattern and it is published knowingly:
`user@1000.service`, a systemd unit name in the path of the cgroup where the 2 GiB budget was
applied (`.../user-1000.slice/user@1000.service/app.slice/plume-bench-N.scope`). It is not an
address; it is the PROOF that the ceiling was applied to a real cgroup, and that is why it
stays.

**What is DELIBERATELY absent**: `matrix.log`, the execution log. It carries absolute build
paths of the machine that measured (3 occurrences of personal paths, checked) — publishing it
would be a leak for zero gain in verifiability, since it contains no figure that is not
already in the JSONL files. `report.py` accepts it as `--fill-log` when you run the bench yourself: it
is an output of YOUR run, not an input you need to receive from us.

**The rendering command is published BY the document itself** (`docs/BENCHMARK.md`, section
"Reproduire"): `report.py` rebuilds it from its own arguments and repoints it to
`bench/results/`. It is a FIXED POINT — running it again as is gives back the document byte for
byte, except for the timestamp line (checked). The previous version published an incomplete command that
amputated the document of its gap sections: a false reproduction command is worse
than an absent one, it makes people believe in a successful reproduction.

**Corollary for a contributor**: if you challenge a figure, re-run `bench/run.sh` and
compare your JSONL files with ours. The generator being deterministic (`--digest` prints the SHA-256 of the
stream), a disagreement is settled on identical data — which is the only case in which a performance
disagreement can be arbitrated.

## Running

```sh
CARGO_TARGET_DIR=../.bench-target cargo build --release --features cold_tier \
    --manifest-path daemon/Cargo.toml
bench/run.sh                          # 10 M events, complete matrix
BENCH_EVENTS=1000000 bench/run.sh     # 1 M — quick iteration
BENCH_PHASES=matrix bench/run.sh      # re-run the matrix on an already filled database
BENCH_PHASES=simple bench/run.sh      # ONE configuration (empty mask) — the mode for A/B tests where
                                      # only THE DATA changes (single host versus fleet)
BENCH_PHASES=cold BENCH_COLD=1 bench/run.sh   # cold tier: hot witness, real aging
                                      # (`plume-daemon retention`), summary, then cold matrix
BENCH_SKIP=1400000 BENCH_PHASES=ingest bench/run.sh   # EXTEND a database without changing the seed
# PARITY (values, not latencies): two daemons, one columnarized, the other intact, SAME binary.
python3 bench/parity.py --hot-base http://127.0.0.1:7421 --cold-base http://127.0.0.1:7422 \
    --user <u> --password <p> --end-ts <ts> --span-days 28 --hot-window-days 7 \
    --retention-days 30 -o parity.jsonl
# rendering: do NOT write it from memory. The EXACT command is published by the document
# itself (docs/BENCHMARK.md, section "Reproduire") and it is a fixed point of it.
```

`report.py` accepts SEVERAL result files: passing the JSONL files of two different volumes
enables the "how latency rises with volume" table, which is what really answers the
question "millions of events". To get a second volume without redoing the whole
fill, `gen_events.py --skip N` extends the SAME deterministic stream (same `dedup` keys, so
no duplicate) instead of changing the seed.

Outputs under `$BENCH_DIR` (by default `../.bench`, **outside the repository**): `results.jsonl` (one JSON
line per cell, it is the raw data), `manifest.json` (switches and rates), `daemon.log`,
`db/plume.db`. Count **about one KiB of database per event**, indexes and FTS included (order of
magnitude read on a real database): ten million events make about ten GiB.

## The rules that make the bench publishable

1. **Peak RAM is measured, never estimated.** `measure.py` samples `/proc/<pid>/statm`
   during the query and records `VmHWM`. The daemon runs under `MemoryMax=2G MemorySwapMax=0`:
   exceeding the budget is a kernel *kill*, not a silent slide into swap.
2. **A cell that exceeds the budget is a result**, not a failure. `report.py` lists them.
3. **A cell taken under swap is wrong.** It is marked `swap_suspect` and flagged as
   to be re-run.
4. **Data come in through the real path** (`POST /api/ingest`), not through an `INSERT` that
   would bypass normalization, column promotion, `cim_stamp`, the FTS triggers and
   the expression indexes.
5. **Determinism is verifiable**: `gen_events.py --digest` prints the SHA-256 of the stream.
6. **Zero real data**: IPv4 only in the documentation ranges of RFC 5737, IPv6
   in `2001:db8::/32` (RFC 3849), host names in `.plume.invalid`, users `bench-user-NNNN`.

## The axes of the matrix, and why

- **Query classes**: filtered scan + aggregate · full-text/regex on `message` · multi-dimension
  group-by with high cardinality · paginated RAW retrieval · **regex on an extended field
  (JSON)** · **the `host` column** (filter, group-by, retrieval of ONE machine). The second to last
  is the most expensive case, and it is precisely the one we claim to serve when we say "on
  all fields"; the last is the only one that tells a lab apart from a fleet.
- **Windows**: derived from the product's parameters (see above), not chosen.
- **Cold tier `PLUME_COLD_TIER` 0 and 1**: it is the read path for 358 of the 365 days of a
  one-year retention. Measured on the SAME database, before and after columnarization — and with a
  check of **answer parity**, because a path that truncates is faster without being
  better.
- **Number of hosts**: 1 (the profiled production), 50, 200. `host` is indexed; at cardinality 1
  any measurement that touches it is degenerate.
- **`PLUME_FTS_FIELDS` 0 and 1**: it is 0 by default. We measure its **cost** (RAM, disk, ingest)
  as much as its latency gain.
- **Empty vs non-empty masking**: decisive and counter-intuitive — a non-empty mask disarms the rollup
  route *and* the vectorized engine. Figures published without this axis only hold for a
  deployment without masking.

## Re-profiling another production

**PREREQUISITE ON THE HOST, AND IT IS INSTALLED BY NO SCRIPT IN THIS REPOSITORY** (`P7.20-l`): a
command-line `sqlcipher` client, compiled with `SQLITE_ENABLE_DBSTAT_VTAB` — without this option, the
occupancy passes of `prod-profile.sql` fail and the recipe stops halfway. The
Debian/Ubuntu `sqlcipher` package carries the option; elsewhere, check it before starting:

```sh
command -v sqlcipher || sudo apt-get install -y sqlcipher
sqlcipher :memory: "SELECT 1 FROM pragma_compile_options WHERE compile_options='ENABLE_DBSTAT_VTAB';"
# one line "1" = the option is present; NO output = this client cannot profile
```

This prerequisite is DECLARED here instead of being discovered at the moment it is needed: the tool lives on
the host, no manifest sets it up, and a package cleanup would remove it without anything turning red.
No guard holds it — a repository guard cannot judge a host it does not run on, and
turning CI red over an operator tool would make every contributor pay for it.

```sh
DB=/chemin/plume.db
KEY=<PLUME_DB_KEY>
{ printf "PRAGMA key = '%s';\n" "$KEY"; cat bench/prod-profile.sql; } > /tmp/p.sql && chmod 600 /tmp/p.sql
sqlcipher "file:$DB?mode=ro" < /tmp/p.sql > dump.txt ; rm -f /tmp/p.sql
python3 bench/distill_profile.py dump.txt --measured-at "$(date -Is)" \
    --host "<matériel>" --image "<version>" -o bench/profile-prod.json
```

`mode=ro` forbids any write. But a SQLite reader holds a snapshot: as long as a pass
is running, the WAL cannot be checkpointed and it grows. On a large database, run the sections
of the SQL **one at a time**.
