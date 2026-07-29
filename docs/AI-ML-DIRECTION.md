# Plume — AI / ML Direction

**Date:** 2026-07-18
**Status:** design reflection (roadmap, not shipped). The only piece landed is the `disposition` column prerequisite (v106). Everything else here is scoped, gated, and awaiting a go.

> This document consolidates two design reflections into a durable in-repo design doc:
> - **LLM assist** — an optional, vendor-neutral, RAM-neutral, advisory, human-in-the-loop AI provider on top of plume's existing closed surfaces.
> - **Native ML triage** — a native, in-process, explainable, hand-rolled classifier for alert triage / FP reduction, offline-trained on `disposition` labels.
>
> Both are **explorations, not committed work items**. They share a governance spine but are **separate engines** — do not route the native ML dot-product through the LLM HTTP abstraction; that would be wrong and would blur the sovereignty story.

---

## 0. Governing principle

**Native / sovereign intelligence first — LLM optional on top.**

The comfort and intelligence a SOC operator wants (completion, validation, triage scoring) is delivered **natively and in-cluster** by default; an LLM is an **optional layer bolted on**, never a dependency. Concretely:

- The default image needs **no LLM** and **no external inference** to be fully useful. A client without any AI endpoint runs plume unchanged.
- Nothing large ever runs inside the **2Go pod**. Native ML is a hand-rolled dot-product (µs, negligible RAM). LLM inference is 100% **remote** — the daemon makes a single guarded HTTP/JSON call, the memory profile of a notifier.
- **Human-in-the-loop, always.** Neither the LLM nor the ML engine ever executes an action or auto-closes/auto-mutes anything. Every action still flows through `/api/actions` (arm / approval / ledger / root-allowlist), unchanged.
- **Never masks a real finding.** This is a first-order invariant (below). AI/ML is an *annotation* layer in read, never in the path that decides what to keep or show.

The design leans entirely on surfaces plume already ships — it exposes closed surfaces to optional intelligence rather than "adding AI to plume":

| Existing surface | Role for AI/ML |
|---|---|
| `SecretProvider` SPI (`core/src/secret.rs`, v126) | template for an `AiProvider` SPI |
| connector presets (`handlers/connectors/presets.rs`) | template for secret-free AI presets |
| closed GXQL compiler (`core/src/soql.rs` `to_sql`) | the gate that renders LLM-generated text harmless |
| incident wizard (`handlers/incidents.rs`) | template for human-in-the-loop draft/approve |
| `ssrf_guard` + ledger (`ledger.rs`) | egress control + per-call audit |
| field-deny → authorizer (`field_filter.rs`) | prompt redaction / masking |
| UEBA z-score (`detection_advanced.rs baseline_anomaly`) + RBA (`rba.rs`) | the analytics ML complements, never duplicates |

---

## 1. Hard constraints (a proposal that violates one is wrong)

1. **2Go RAM non-negotiable** → no large local model in the pod; LLM inference 100% remote.
2. **Sovereignty** → AI strictly optional, feature-gated OFF, inert without config.
3. **Vendor-agnostic** → bring-your-own-endpoint (Ollama / vLLM / llama.cpp on another machine for air-gapped, Azure OpenAI, Anthropic, any OpenAI-compatible); zero hardcode.
4. **Human-in-the-loop** → AI never executes; everything routes through `/api/actions` unchanged.
5. **Injection-safe by construction** → all AI-generated GXQL passes the closed compiler which validates/rejects it (a hallucinated or malicious query is rejected the same as bad human GXQL).
6. **PII / secrets** → prompt redaction on the existing `field_filter` infra, never hash/token; egress via `ssrf_guard`; every AI call audited to the ledger.
7. **Cost** → no per-event LLM call (ruinous at ~289k/day); on-demand analyst or per-incident/aggregate only.

---

## 2. LLM assist — the `AiProvider` SPI

### Architecture

- `core/src/ai.rs` = trait `AiProvider { id(); complete(&AiRequest) -> Result<AiResponse, AiError> }` — pure, `AiError` neutral (mirrors `SecretError`).
- OpenAI-compatible impl in the daemon (`ai/mod.rs`), HTTP, outside the core (mirrors `VaultProvider`).
- Table `ai_provider` + presets JSON, secret-free (`docs/ai-presets/*.json`); credential in an encrypted column resolved through the `SecretRef` grammar.
- **Double gate**: Cargo feature `ai` (default OFF, `#[cfg(not(feature="ai"))]` stubs return 501, like `saml`/`ldap`) **and** runtime inert without an `ai_provider` row / `PLUME_AI_ENABLE`.
- **Cloud gate**: `PLUME_AI_ALLOW_CLOUD` (default OFF) — the AI equivalent of `PLUME_SSRF_BLOCK_PRIVATE`. Sovereignty puritans stay self-hosted-only; cloud endpoints are opt-in.
- **Ollama-native adapter**: Ollama exposes both `/v1/` (OpenAI-compatible) and its native `/api/chat`. Add an `api_shape=ollama-native` adapter to the provider SPI (`/api/chat` + `/api/tags` model-discovery + `/api/embeddings` future) so it matches exactly and prepares embeddings.

### Use-cases (value ÷ effort ÷ fit)

| # | Use-case | Phase | Notes |
|---|---|---|---|
| #1 | **NL→GXQL** | Ph1 (High/Low) | Analyst types English → LLM proposes GXQL → **closed compiler validates** → analyst runs it. The best AI shape in plume: untrusted LLM text cannot bypass `to_sql`, only field *names* surface, no data. Biggest "superset-of-Splunk" lever. |
| #2 | **Incident summary / narrative** | Ph1 (High/Low-Med) | Bounded, redacted digest → exec summary + timeline + dedup, as a **draft** the analyst edits. Aggregate, not per-event; prompt-injection-from-logs neutralized (output is prose that gets reviewed). |
| #3 | **Rule-writing assist** | Ph2 | Describe a behavior → propose GXQL/Sigma → same authoring gates → rule created **DISABLED**. Complements UEBA, doesn't duplicate. |
| #5 | **Threat-intel summary** | Ph2 (small, opportunistic) | — |
| #6 | **Parser suggestion for unknown source** | Ph2/3 (cautious) | The only case where raw log lines enter the prompt → minimal sampling + admin-review; output = validated PARSER-DSL config, not code. |
| #4 | **Copilot / RAG investigation** | Ph3 (explore only, NOT committed) | Retrieval **must** go through `to_sql` (RBAC/masking preserved). The friction is embeddings (remote endpoint + vector store = air-gapped friction, tension with the DuckDB/ClickHouse refusal). Start lexical/GXQL without embeddings; add vectors only if proven insufficient. |

### Honest SKIPs

Per-event LLM triage (ruinous + duplicates UEBA); AI auto-response/remediation (violates human-in-the-loop, **never**); auto-tuned alert thresholds (opaque, anti-reproducible); NL dashboard generation (marginal); embeddings-first "semantic search over all events" (cost/infra vs the DuckDB refusal).

### Phasing

- **Ph1** = SPI + OpenAI-compat provider + presets + `ssrf_guard` + ledger + redaction v1 (feature OFF) + #1 & #2. This is the MVP "AI in plume" — small, because the gates already exist.
- **Ph2** = #3/#5/#6 (admin-gated, disabled-by-default).
- **Ph3** = #4 exploration only. Do **not** commit embeddings/vector infra without proof it beats GXQL retrieval.

The reflection/build frontier: Ph1-2 are concrete gated builds; Ph3 is exploration.

### Open questions for the operator

1. First use-case? (reco: **NL→GXQL** — tracer bullet, proves the closed-compiler gate end-to-end before touching incident data).
2. Presets cloud+local or local-only in the default build?
3. Cloud endpoints allowed at all, or self-hosted-only → `PLUME_AI_ALLOW_CLOUD` default OFF?
4. Default redaction policy = maximally conservative + versioned to the ledger?
5. Feature compile-time + runtime (reco: both, like saml/ldap)?
6. Per-tenant AI call budget in the admin UI?

### External OSINT CLI — DECISION: NOT wired, salvage the logic

An external sovereign OSINT CLI pattern (live web-search → fetch → cited LLM synthesis with an offensive no-refusal model) was considered as a reference. Conclusion: **web / Tor / OSINT / offensive model = wrong fit for a defensive SOC** — do not call or mirror it.

Salvageable, adapted to plume's real need:

1. The **deterministic anti-hallucination guardrail** (`unverified_facts`: regex verbatim check of CVE/paths/versions/URLs against the source text + correction pass + ⚠ flag) — the best artefact.
2. The discipline **route → multi-angle → grounding/citation `[n]`** + fail-safe "insufficient information".

The "deep" reinterprets for a SOC as **deep search over plume's own evidence** (events/cases/TI/runbooks via the closed GXQL compiler), not the web — that is the future RAG/copilot phase (Ph3), grounded + cited + anti-hallucination. This is why the Ollama-native adapter (`/api/chat` + `/api/embeddings`) is worth carrying.

---

## 3. Native ML triage — hand-rolled, 0-crate, in-process

Distinct from the LLM SPI: the LLM is an activatable OpenAI-compatible option; **this is native classification** that runs in-cluster with nothing leaving the box.

### Resource verdict (the star) = hand-roll, no ML crate

A logistic-regression scorer = `sigmoid(Σ wᵢ·xᵢ + b)` = ~12 lines, **0 new dependency**, intrinsically explainable (each `wᵢ·xᵢ` is the per-feature contribution, displayable). Matches the codebase's existing hand-rolled TOTP precedent. Model = a KB `serde` blob in a table.

**Reject ML crates:** `linfa` pulls `ndarray-linalg` → BLAS/LAPACK = exactly the `cc1plus` landmine DuckDB was rejected for (the host build has only a C compiler for SQLCipher). `smartcore` (pure-Rust, no mandatory BLAS) = acceptable but feature-gated-OFF only, never in the default 2Go image. `candle`/`ort`/`xgboost` = C/heavy = sidecar placement only.

### Placements

- **(A) in-process pure-Rust inference-only** (dot-product µs, ~negligible RAM) = **DEFAULT**.
- **(C) offline batch** (train + score inside the existing `run_baselines`/`risk_rollup` cron loop; hot-path reads a score column) = paired with A.
- (B) sidecar / (D) external endpoint = fallback **only** for genuinely heavy models, justified against the budget.
- Preference **A ≈ C ≫ B > D**. A/C keep model + features + labels + inference **inside** the SQLCipher box = the sovereignty requirement.

### Complements (does NOT duplicate) the existing analytics

- z-score (`detection_advanced.rs baseline_anomaly`, univariate/unsupervised) → ML adds **multivariate supervised** (actionable-vs-benign, learned).
- RBA (`rba.rs`) is **already built** (weighted/decaying/velocity scoring) → ML **feeds** it, doesn't rebuild it (optionally the #1 score becomes a risk contribution).
- CIM (`core/src/cim.rs`) = the label space for event classification.
- suppression/silence (`alerting.rs`, TTL-bound, ledgered) = the hook for "suppress-candidate".
- Respects the declared non-goal (mature UEBA ML ceiling = stat baseline + RBA): Phase-1 is **supervised triage**, not deep unsupervised UEBA.
- Rollup discipline: train from `incident`/`alert`/rollup, **never a scan of `event`**.

### Use-cases

| # | Use-case | Phase | Notes |
|---|---|---|---|
| #1 | **Triage / FP-reduction scoring** | Ph1 (A+C, logistic hand-roll) | Score P(actionable) from source + rule + severity + hour + entity-history; **visible badge** + top-factors; re-ranks the queue as an opt-in column; analyst disposes. |
| #2 | **RBA** | already done | Don't rebuild; optionally the #1 score becomes a risk contribution. |
| #3 | **Event → CIM classification** | Ph2 (C offline, naive-Bayes tokens) | — |
| #4 | **Clustering / dedup** | deferred (B/C, opaque) | — |
| #5 | **Suppress-candidate** | Ph1.5 (reuses #1) | Via the audited silence machinery — **never** an auto-mute. Most sensitive vs the non-masking invariant → deferred or strictly per-item analyst-approved. |

SKIP: neural/embeddings anomaly (opaque + RAM + reopens the non-goal); auto-close/auto-action on score alone (violates human-in-the-loop, permanent SKIP).

### ⚠ Critical prerequisite (shipped v106): the `disposition` column

The `incident` table (`migrate.rs`) had `status/severity/priority/closed_ts/merged_into` but **no `disposition`/`verdict`/`false_positive`** column — so supervised labels were noisy proxies (escalated/actions = weak positive; closed-fast/merged = weak negative). The highest lever was an additive nullable **`disposition` column (TP/FP/benign/duplicate) captured at case close** (additive, mode-0 byte-identical migration).

**This shipped (schema v106).** The classifier now has a real label source; it waits only for enough accumulated labels before it is worth surfacing. Without it, the classifier would train on a weak proxy.

### ⚠ Non-masking / non-perturbation invariant (first-order, non-negotiable)

The ML must **never mask a real finding** nor **perturb correct operation by hiding elements**. Hard consequences:

- The ML score is **purely additive / annotative** — it never removes / hides / collapses / filters an alert or finding from any view; never suppresses a true positive; never re-orders in a way that buries a real finding.
- Prefer a **separate opt-in column/sort** over a default re-ranking. In the default view, **detection truth (severity / rule / RBA) always wins over the ML opinion** — a "benign" score never demotes a real/uncertain item out of visibility.
- The deterministic pipeline (rules / correlation / RBA / alerting / ingest) runs **unchanged**; ML is a read-layer annotation on top, never in the path that decides what to show or keep.
- Default = **show everything + annotate with ML**; the analyst opts in to ML sort/filter.
- Use-case #5 (suppress-candidate) is the most sensitive under this invariant → either deferred, or strictly a per-item analyst-approved suggestion via the reversible + audited silence machinery, **never** an auto/mass mute.

### Guard-rails (labels are analyst-provided = attackable)

- ML is never the sole gate (fail-closed like `run_due_rules`; a benign score re-ranks + annotates, never suppresses/closes without an analyst or audited machinery).
- **Poisoning** (a compromised editor teaching "real threat = benign") → history quorum + per-source influence cap + every training run **ledgered** (auditable/reversible) + advisory (degrades ranking, never drops the signal).
- **Drift** → cadenced retrain + precision/recall tracking + surface the drift.
- Reproducibility = pin the training snapshot.

### Governance spine (operator): native + explicit + tunable + in-cluster-secure

- **Transparency** = visible ML badge on each scored alert + top-factors (free with the linear model; a black box that can't justify a "benign" is a liability).
- **Tunable** via `cfg()` (like `rba.rs`) + UI: actionable-vs-benign threshold, features on/off, retrain cadence, enable/disable per source. Admin-only for train/config, threshold surfaced to the analyst.
- **Security** = **everything in-cluster** (features / labels / model / train / infer in SQLCipher — non-negotiable on an enterprise network; native = sovereign by default because nothing leaves). RBAC: admin = train/config, viewer = view/tune-threshold. Every train/swap/policy-change audited to the ledger (`audit_config_change`). Fail-closed.
- Feature `ml` OFF by default (mirrors duckdb/saml; default build byte-identical; hand-roll → "off" = zero extra linked code).

### Relation to the LLM SPI

**Share the governance spine** (`PLUME_AI_ALLOW_CLOUD` gate + ledger audit + external-endpoint transport for placement D bring-your-own-ML) **but keep a separate engine** (routing a µs dot-product through an HTTP abstraction would be wrong and would blur sovereignty). One line: **shared gate + shared audit + shared external-transport SPI; separate native inference engine.**

### Open questions for the operator

1. `disposition` additive column OK? — **[shipped v106]**
2. Batch-C score (zero hot-path, ≤1 cycle stale) vs inline-A (fresh, +µs)? (reco: batch first).
3. Confirm "never auto-act" (re-range + annotate + propose-suppress only) + default threshold + default per-source enable.
4. Minimum labels before displaying (cold-start)?
5. Poisoning tolerance: SMB single-analyst (operator alone) vs ESN multi — cap per-user influence now or defer?
6. Hand-roll the logistic (reco, 0 dep) vs `smartcore` feature-gated-OFF reserved for future trees/forest?
7. Confirm bring-your-own-ML (D) shares the `PLUME_AI_ALLOW_CLOUD` off-by-default gate on an enterprise network.

---

## 4. Phasing summary & where this stands

| Track | State |
|---|---|
| `disposition` column (ML prerequisite) | **Shipped (schema v106)** |
| Native ML triage scorer (#17) | Deferred — waits on accumulated `disposition` labels; hand-roll, feature `ml` OFF |
| Disposition triage metrics | Autonomous-native, buildable now |
| LLM `AiProvider` SPI + NL→GXQL (#1) | On branch `feat/ai-nl2soql`, **activation deferred until Ollama-at-the-pod wiring** ("Ollama last"); `ai_provider` migration to be renumbered v107→v108 at activation |
| LLM incident summary (#2), rule-assist (#3), TI/parser (#5/#6) | Ph1-2 gated builds, on go |
| RAG copilot (#4) + embeddings | Ph3 exploration only; not committed; salvage the OSINT-CLI anti-hallucination + grounding pattern for it |

**Bottom line:** native/sovereign comfort first (GXQL editor completion/validation shipped v129/v130, native ML triage on labels), LLM optional on top (feature-off, vendor-neutral, RAM-neutral, human-in-the-loop, never masks a finding).

---

*These are roadmap reflections (design direction), not shipped builds.*
