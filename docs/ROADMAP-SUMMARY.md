# Plume roadmap — English summary by phase

This page is the English entry point to [`docs/ROADMAP.md`](ROADMAP.md), the public index of
workstreams. That index stays in French and is not translated: it is large, it changes with almost
every commit, and several guards of this repository read it row by row. What follows summarizes it
phase by phase — what each phase aims at, where it stands, and its main workstreams — and sends the
reader to the French section for the detail of each key.

## How to read this summary

**Keys.** The index names every finding with a stable key, `P<phase>.<workstream>-<finding>`.
Commit messages cite these keys; a key never moves once assigned. Phase numbers come from an internal
audit and do not match the product phases of the specification. The phases appear below in the order
of the index, which is a reading order: P13 comes before P12 on purpose.

**States.** The index marks every key with one of five states: corrected and verified; measured and
decided but not built yet; open; blocked because the operation belongs to the operator; reserved
number with no finding behind it. A key that nothing can take right now carries a cause (operator
decision, measurement outside the workstation, one-way door, outside this repository, depends on
another key). The scope of version 1.0 is frozen: keys outside it carry the mark "after 1.0" and
are neither workable nor held back.

**Why there are no counts here.** The number of closed and open keys moves with almost every
commit. Written here, it would be stale after the next one, so each phase states its progress
qualitatively. The exact, derived count lives at the top of the French index, in a line that
`check_blocked_work_names_its_cause.py` recounts on every run.

**Security keys.** An open security key is summarized below by its theme only. Its mechanism is
described once it is corrected.

**What this summary does not hold.** It does not list keys one by one, it does not translate the
known limits section, and it carries no measurement taken on any installation. The guard
`check_the_roadmap_summary_covers_every_phase.py` holds one property only: the set of phases of the
index and the set of phase sections of this page are the same, in both directions. It does not
judge whether a sentence below is still accurate.

## P3 — Ingestion, deduplication, freshness probes

**Aim.** Every event that a sensor sends arrives once, is attributed to the right host, and the
freshness probes say when a part of the fleet goes silent.

**Where it stands.** Closed: every key of the phase is corrected and verified.

**Main workstreams.**
- Deduplication keys that carry the host, so that two machines doing the same work no longer
  overwrite each other.
- Freshness probes that look at each source rather than at the freshest machine of the fleet.
- The Loki-compatible ingestion route: its delivery guarantee is stated as at-least-once, and it now
  goes through the same ingestion processors (rejection, masking, routing) as every other route.
- Cost of the probes under the write lock, closed by a partial index.
- Integrity sensor coverage of systemd drop-ins, an alert for a rule abandoned again and again, and
  the ingestion of telemetry CSV files through the existing entry points.

**French section:** `## P3` in [the index](ROADMAP.md).

## P4 — Operations: CLI, service, collectors, ceilings

**Aim.** Running plume day to day: the command line, the systemd service, the collectors, the
ingestion ceilings, the deployment gate, what the image really contains, scripted inputs, and the
automatic response.

**Where it stands.** Almost entirely closed. The open keys are about the Windows sources and
entity-based detection, and wait for a measurement on a Windows fleet or for a one-way design
decision; keys of the deployment gate are deferred after 1.0. One number is reserved.

**Main workstreams.**
- CLI, HTTP observability, Windows build, sensor monitoring, uninstallation, integrity monitor and
  status command.
- Ingestion ceilings and the ingestion quarantine, which now has a depth, a drain and an operation.
- The deployment gate (sub-section P4.4): rollback, drift between repository and deployment,
  freshness of the reference, configuration placement. The tooling lives outside this repository;
  the findings stay here because commits cite them.
- What the image contains (P4.5): features compiled in, the image guard, the image identity.
- Scripted inputs (P4.6): the operator's command now has bounds on time and output, and an
  unreadable bound no longer makes a sensor report itself unavailable.
- Automatic response (P4.7): the allowlist that carried two incompatible policies, the address
  predicates shared by the agent and the central, the protection of public addresses on a fresh
  central, network prefixes, the anti-lockout valve, and the console writes that swallowed a
  refusal of the site storage.

**French section:** `## P4` in [the index](ROADMAP.md).

## P5 — Taxonomy, authority, token scope

**Aim.** Who may do what: event taxonomy, HTTP authority, the scope of tokens, secrets, and the
confidentiality of what is collected.

**Where it stands.** Closed, except one key blocked on the operator and deferred after 1.0: the
privileges of the operating account.

**Main workstreams.**
- Token scope and HTTP authority on every route.
- Event taxonomy and detection.
- Windows collection, secrets handling, confidentiality of collection, seeded rules, and
  self-monitoring.

**French section:** `## P5` in [the index](ROADMAP.md).

## P6 — Memory, performance, indexing

**Aim.** Diagnose and hold the memory budget, and make indexes earn their cost.

**Where it stands.** Closed, except one key deferred after 1.0: the query path of the full-text
index.

**Main workstreams.**
- Memory diagnosis and the memory budget.
- Adaptive indexing, and indexes used by detection.
- Generality of the measurements, and time bounds inside the test suite.

**French section:** `## P6` in [the index](ROADMAP.md).

## P7 — Hygiene, supply chain, authorization surface

**Aim.** Keep the tree clean and the dependencies under watch, and bound what the raw query surface
may reach.

**Where it stands.** Almost entirely closed. One key is decided and not built: making the
performance, confidentiality and integrity settings active by default, which waits for a
measurement outside the workstation. Other keys are deferred after 1.0 (splitting monolithic files,
the scale table of the bench, a large jump of the SQLite binding).

**Main workstreams.**
- Test hygiene, compiler warnings, supply chain.
- Raw SQL and its authorization, query observability, keyset pagination, displayed provenance.
- The cold tier in each deployment mode, including the bare host mode.
- Documentation that cited a control that does not exist, or a default justified by a memory cost
  nobody measured.
- Operational figures removed from code comments, and the guard that keeps them out.

**French section:** `## P7` in [the index](ROADMAP.md).

## P8 — Delivery chain: backup, restoration, repository guards

**Aim.** A backup that can be restored, a restoration that does not lie about its outcome, and
repository guards that run, are wired, and refuse what they claim to refuse.

**Where it stands.** Almost entirely closed. Some keys are deferred after 1.0 (configuration kept
outside the repository, an index key marked open after deployment, an exercise of a stripped-down
deployment). One number is reserved.

**Main workstreams.**
- Backup and restoration: key derivation, the object storage destination, a restoration that
  returned success when decryption failed, and disaster recovery.
- Repository guards: a guard written but not wired, a key cited in the code but missing from the
  index, a key filed under the wrong phase, a state that is not a state.
- Test counters and memory witnesses.
- Ownership and cleanup of temporary files, the canonical identity written once, and the public
  history.
- Dependency security advisories, pinned audit tools, and secrets flagged in the tree.
- The deployment driven by the repository, its lock, and the startup volume.

**French section:** `## P8` in [the index](ROADMAP.md).

## P9 — Backup, encryption at rest, documentation corpus

**Aim.** A backup that can be reconfigured and whose failure is heard, encryption at rest from the
first start, and a documentation corpus bound to the code.

**Where it stands.** Closed, except one key decided and not built: surfacing the state of the
secrets store outside an operator command.

**Main workstreams.**
- Backup configuration read without a restart, and an audible backup failure.
- Encryption at rest: a new database is born encrypted, an existing database is never converted.
- Rules that no source could trigger.
- The documentation of the full lifecycle, and a derived guard that binds the corpus to the code.

**French section:** `## P9` in [the index](ROADMAP.md).

## P10 — Staying under 2 GiB: storage, indexes, aggregation

**Aim.** The largest phase. Plume is designed to fit a memory budget of 2 GiB; every storage,
indexing and aggregation choice is decided against it. The phase also gathered the integrity,
security, sensor and console findings that this work brought up.

**Where it stands.** The great majority of its keys is closed. A minority stays open, and most of
the open keys are deferred after 1.0. The others wait for another key (mainly the mail sensor),
for a measurement outside the workstation, or for work outside this repository. Open security keys
concern the mail sensor, a dependency advisory tracked upstream, backup restoration and off-site
copies, secret scanning in CI, cancellation, encryption at rest, and identity provisioning across
tenants; the index names their theme, this summary goes no further.

**Main workstreams.**
- Storage: composition of the database, useless indexes, index usage, schema and startup, aging
  and its observability, latency under aging.
- Memory: confidentiality of sorts spilled to disk, the allocator setting behind the peak memory
  check, the write-ahead log footprint and its checkpoint.
- Integrity journals: hash chains, their verifiers, the export of the journal, checkpoints and the
  bound on the time without an anchor.
- Honest reads: a read that did not happen, a write that was swallowed, a transaction boundary that
  was ignored, a truncated list served as a complete one — each family held by a guard.
- Security of accounts and sessions: multi-factor authentication, password changes and resets,
  recent proof for sensitive operations, tokens of deleted accounts, header-based single sign-on.
- Sensors: the mail sensor, the CrowdSec sensor, data access, a live sensor that reads as mute.
- Console, dashboards, export, query parsing, notifications, health, and backups streamed and
  checked for freshness.
- The map and order of levers, the cold tier, and the bench campaign.

**French section:** `## P10` in [the index](ROADMAP.md). The design behind this phase is in
[`DESIGN-P10-echelle-2go.md`](DESIGN-P10-echelle-2go.md).

## P11 — Console: feedback from an analyst's use

**Aim.** Findings from real use of the console, not from reading the code. Each is measured before
it is corrected. The rule of the phase is the product's: what is shared is factored, what
redirects says where it lands, what is sensitive asks for confirmation.

**Where it stands.** The great majority of its keys is closed. Most of the open keys are deferred
after 1.0; a few are decided and not built (ban duration of a playbook response, dashboard views,
evidence carried by an alert).

**Main workstreams.**
- Navigation: where a newly created object lands, drill-down windows, heat map cells.
- Language: the console rendered in English announces the right language, lexicon guards.
- Lists: bounded lists that say whether there was more.
- Guards of the console tests: tree walks, fallbacks, witnesses that count rather than time.
- The decision bench of the deployment and its refusal channel.

**French section:** `## P11` in [the index](ROADMAP.md).

## P13 — Analytical use outside the SOC: file import and exploration

**Aim.** Plume used as an analytical tool without sensors, detection or agents: importing any file
through the interface and exploring it. The phase has a rank, not a date: it comes after every
phase above and before artificial intelligence. Its number is larger than the next phase's on
purpose, since a key never moves once assigned.

**Where it stands.** Not started, and deferred after 1.0. Some keys belong to the operator.

**Main workstreams.**
- File import with its settings.
- Query syntax for imported data (value alternation, quoting, field names with a hyphen).
- A viewer mode carried in parallel outside this repository.

**French section:** `## P13` in [the index](ROADMAP.md).

## P12 — Artificial intelligence and learning

**Aim.** Optional assistance and native assisted triage, gated on the operator and handled last.
They are optional, vendor-neutral and neutral for memory; native triage must never hide a true
positive.

**Where it stands.** Not started: its keys are blocked on the operator and deferred after 1.0.

**Main workstreams.**
- An optional assistance integration with no memory cost.
- Native assisted triage under an invariant that takes precedence over performance.

**French section:** `## P12` in [the index](ROADMAP.md). The direction is described in
[`AI-ML-DIRECTION.md`](AI-ML-DIRECTION.md).

## Other sections of the index

Besides the phases, the French index holds other sections that this page does not summarize: the
findings without a key (found and closed in the same operation, kept as a trace), the known limits
of the product, named plainly, and what is designed but not built.
