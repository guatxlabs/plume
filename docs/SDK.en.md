# Plume SDK — the *bring-your-own-vendor* model

[Français](SDK.md) | [English](SDK.en.md)

> **Status: umbrella document.** It does NOT define a new mechanism: it makes the extension *seams* that
> already exist **consistent and discoverable**. Each seam has its own detailed reference page
> (links below); here we give **the single mental model**, the decision rule, and one concrete example
> per seam. **No runtime behavior is changed by this document.**

Plume's SDK is **the seams**, not a library to link against. The product promise is that of the
*vendor-agnostic / superset* directive (project memory): **zero hard-coded vendor**, and **adding a
vendor must never require touching the core** (`guatx-core`) nor, in the nominal case, **recompiling**.

---

## 0. The pivot — the CIM contract (`core::cim`)

Everything starts from the **CIM** (Common Information Model, [`docs/CIM.md`](CIM.en.md), machine mirror
[`config.d/cim/cim.v1.json`](../config.d/cim/cim.v1.json)). It is the **neutral vocabulary** on which the whole
chain composes. Two fields carry the entire weight of vendor agnosticism:

| field | role | example |
|---|---|---|
| `source` | identity of the **PRODUCER / vendor** — **never** the semantics | `fortigate`, `defender`, `suricata` |
| `category` | **CROSS-vendor semantics** — the contract on which rules compose | `firewall`, `malware`, `ids`, `web`, `auth` |

> **Golden rule.** A detection filters on `category` (`search category=firewall action=blocked …`),
> **never** on a particular vendor `source`. Consequence: a rule written once works for
> **every** vendor that *maps* its `category` — that is what the superset means. The role of each seam below
> is **exactly** to translate a vendor dialect into this canonical row (`EventRow`), by
> **ENRICHING, never suppressing** (an out-of-taxonomy `category` is accepted as is + flagged,
> never rejected — see CIM §0).

---

## 1. The seams at a glance

Only three **idioms**, in order of preference:

1. **Declarative overlay** (config, *no rebuild*) — the nominal case. A JSON/YAML file placed in
   `config.d/`, or a connector `config`. It is the default path for 90 % of vendors.
2. **Out-of-process adapter** (config + third-party process) — to *act* on external systems
   (network enforcers, IdP) without coupling their code to the daemon.
3. **Compiled Rust trait** (*rebuild*) — reserved for formats the declarative layer cannot express
   (high-throughput binary/positional). Minimal contract, a single registration point.

| Seam | What you add | Idiom | Location / registration point | Rebuild? | Reference |
|---|---|---|---|:--:|---|
| **Parser** (vendor log → `EventRow`) | field extraction | declarative overlay (DSL) | `config.d/parsers/*.json` → tables `parser`/`dparser` | **no** | [PARSER-DSL.md](PARSER-DSL.en.md) |
| High-throughput **parser** | binary/positional dialect | compiled trait | `collector-syslog`: `impl VendorParser` + `parser::select()` | yes | code |
| **Pull source** (REST/JSON API) | an event source | connector descriptor | `POST /api/connectors` type `http_pull`, `config` field | **no** | [connector-presets](connector-presets/README.en.md) |
| **Push source** (SIEM/agent) | inbound stream | HTTP endpoint | `POST /services/collector` (HEC), `/api/ingest*` | **no** | code (`server/groupes_de_routes.rs`) |
| **Detection** | rule | declarative overlay | `config.d/rules/*.json` (GXQL) + `config.d/sigma/*.yml` | **no** | [SIGMA-IMPORTER.md](SIGMA-IMPORTER.en.md) |
| **Threat intel** | IOC feed | connector descriptor / import | `taxii2` connector, `POST /api/threat-intel/import` (STIX 2.1) | **no** | `core::ti` |
| **Response / enforcer** | action executor | out-of-process adapter | `PLUME_BAN_BACKEND` (nft/fail2ban/…), engagement `adapter` | **no** | code (`actions.rs`) |
| **Rollup dimensions** | queryable pre-aggregate | environment variable | `PLUME_ROLLUP_DIMS` | **no** | [config.d/README](../config.d/README.en.md) |

Common entry point for the `config.d/` overlays: `load_overlays` (at boot, after migrations/seeds) performs an
**UPSERT keyed by `name`**, set `managed=1`. Idempotent and durable (survives the re-seed of the builtins). The
path is `PLUME_CONFIG_DIR` (default baked into the image), so the overlay is **runtime-agnostic**
(k3s ConfigMap / docker bind mount / host directory).

---

## 2. Adding a vendor **parser** (without touching the core)

**Nominal case — declarative overlay (no rebuild).** You drop a file into `config.d/parsers/`. Either a
named regex parser, or a declarative DSL parser (see [PARSER-DSL.md](PARSER-DSL.en.md)) that **maps to the
CIM `category`**. Example (firewall extraction + mapping):

```json
{
  "name": "acme-fw — connexions bloquées",
  "source": "acme-fw",
  "pattern": "src=(?P<src_ip>\\S+) dst=(?P<dst_ip>\\S+) act=(?P<action>\\w+)",
  "enabled": true
}
```

> Registration: the file is loaded at boot by `load_overlays`, UPSERT on `name`, `managed=1`.
> **No-rebuild guarantee**: nothing to recompile and no image to redeploy — a `git commit` in `config.d/` (or
> a ConfigMap) is enough; a UI CRUD (`managed=2`) does the same thing live. An invalid file is
> **skipped with a warning**, never a boot crash.

**High-throughput case — compiled trait (rebuild).** For a binary/positional dialect where regex/DSL is not
enough (e.g. Fortinet structured syslog), the syslog collector exposes a trait:

```rust
// collector-syslog/src/parser.rs
pub trait VendorParser: Send + Sync {
    fn name(&self) -> &'static str;
    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value;
}
```

> Registration: `impl VendorParser for MonVendeur` then **one line** in `parser::select()` (selected
> by `PLUME_SYSLOG_PARSER`). That is all. Contract: `source`=vendor, `category`=CIM semantics, `src_ip`/
> `dst_ip` at top level, the rest in `fields`; **never panics** (malformed line → fallback event).

---

## 3. Adding a **source** (getting events in)

**Pull — `http_pull` descriptor (no rebuild).** Any REST/JSON API becomes a source **through
configuration alone**: URL, auth, pagination, watermark, and a `field_map` that projects the vendor response
onto the `EventRow`/`fields` fields. Example (skeleton):

```json
{
  "url": "https://api.acme.example/v1/alerts",
  "records_path": "data.items",
  "auth":  { "kind": "oauth2_client_credentials", "token_url": "https://api.acme.example/oauth/token", "client_id": "…" },
  "pagination": { "kind": "cursor", "cursor_path": "meta.next" },
  "watermark":  { "field_path": "created_at", "param": "since", "format": "iso8601" },
  "sourcetype_map": { "acme.alert": "malware" },
  "field_map": { "ts": "created_at", "src_ip": "network.src", "message": "title", "category": "=malware" }
}
```

> Registration: `POST /api/connectors` (type `http_pull`), paste the `config`, the **credential in the
> `secret` field** (never in `config`), **Test** (`/api/connectors/{id}/test` — 1 page, does not ingest,
> returns a mapped sample), then enable. The periodic poll (`run_due_connectors` →
> `poll_one_connector` → `poll_http_pull`) ingests and advances the watermark.
> **No-rebuild guarantee**: adding a vendor = writing a JSON like those in
> [`docs/connector-presets`](connector-presets/README.en.md) (Falcon, SentinelOne, generic REST are
> *pure docs*, not per-vendor code). Pulled events go through **the same enrichment
> pipeline** as native ones (parsers, generic extractor, **on-ingest TI match**).

**Compiled presets (defender / taxii2).** Two `ctype` values have a dedicated normalizer (`poll_defender`,
`poll_taxii`) because their schema (Graph Security, TAXII 2.1) is stable and deserves a first-class
adapter — but they are still dispatched by `ctype` in `poll_one_connector`, with nothing "hard-coded" on the
detection side (they converge on `EventRow`/`Ioc`).

**Push — HTTP endpoints (no rebuild).** An external SIEM/agent pushes directly:
`POST /services/collector` (**HEC** — Splunk-compatible), `/api/ingest`, `/api/ingest/journal`,
`/api/ingest/minio`. All converge on the same `EventRow` + the frozen `EVENT_INSERT_SQL`.

---

## 4. Adding a **detection** (rule)

Declarative overlay, no rebuild. Two formats, **one** `rule` table:

- **Native GXQL** — `config.d/rules/*.json`: `{"name","query":"search category=firewall action=blocked | stats count","op":">","threshold":0,"mitre":"T1190",…}`.
- **Sigma** (open standard) — `config.d/sigma/*.yml`: translated into a GXQL rule at boot (`load_overlay_sigma`),
  `logsource → category` mapping **via the CIM**. A construct that cannot be expressed in GXQL is **flagged + skipped**
  (never a silently wrong rule) — see the matrix in [SIGMA-IMPORTER.md](SIGMA-IMPORTER.en.md).

> Registration: `load_overlays`/`load_overlay_sigma`, UPSERT on `name`, `managed=1`; validation at boot
> (the `query` must **compile**). One-off import outside git: `POST /api/sigma/import` (admin), or
> `plume-daemon sigma-import <path> [--dry-run]` on the central — on a native host
> `sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon sigma-import <path>`, under Docker and
> k3s through `docker compose exec soc …` / `kubectl -n soc exec deploy/soc -- …`. Without `--dry-run`, it
> writes to the database: start the daemon once beforehand
> ([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)). **Write the rule by `category`**, and it will work for every vendor.

---

## 5. Adding a **threat-intel feed**

STIX parsing/normalization is **pure** in `core::ti` (`stix_bundle_to_iocs`, `normalize_ioc`) — vendor-agnostic,
shared. Three entry points, none touching the core:

- **TAXII 2.1** — a `ctype=taxii2` connector periodically PULLS the collection and translates the STIX objects into
  IOCs (`taxii_upsert_iocs`).
- **One-off STIX import** — `POST /api/threat-intel/import` (STIX 2.1 bundle); an unsupported pattern is
  *skipped with a reason*, never an IOC that silently under- or over-matches.
- **Manual / bulk addition** — `POST /api/threat-intel/iocs`.

The IOCs feed the **match-on-ingest** (`ti_match_event`): a `src_ip`/`dst_ip`/hash that matches receives
`fields.threat_intel` + `ti_match=1` and contributes to risk-based alerting. (The `IocIndex` membership
pre-filter — #30 — scales this match without changing the contract.)

---

## 6. Adding an **enforcer / a response** (acting outward)

**Out-of-process adapter** idiom: Plume does not reimplement enforcers, it **delegates** to those that
already exist at the customer's, selected by configuration.

- **Ban backend** — `PLUME_BAN_BACKEND` (`auto` by default) routes `ban_ip`/`unban_ip` to
  `fail2ban` / `nft` (fallback) / CrowdSec. Adding an enforcer = adding a **command** branch
  (the action stays `ban_ip`, backend-agnostic); the action vocabulary (`ban_ip | unban_ip |
  kill_pid | stop_service`) is the stable contract (`action_kind_valid`).
- **Engagement mode** — each engagement carries an **`adapter`** field (the out-of-process IdP/enforcer that
  applies the pentest scope): enforcement lives **outside the daemon**, the daemon only publishes the
  compiled scope (`ENGAGEMENT_SCOPE`, byte-identical when no engagement is active).

> **Guarantee**: the executor is a **process boundary** (a `Command` / an adapter), not a
> code coupling. A new backend never enters the hot ingest path.

---

## 7. Decision rule (which idiom?)

```
Le vendeur expose-t-il ses données via un log texte ou une API REST/JSON ?
  ├─ oui, et regex/DSL suffit à extraire+mapper  → OVERLAY DÉCLARATIF (config.d ou http_pull)   [no rebuild]
  └─ non, format binaire/positionnel haut débit  → TRAIT COMPILÉ (VendorParser + select())      [rebuild]

Faut-il AGIR sur un système externe (bloquer, révoquer, isoler) ?
  → ADAPTATEUR HORS-PROCESS (backend d'action / engagement adapter)                             [no rebuild]

Faut-il une sémantique nouvelle non couverte par la taxonomie CIM ?
  → proposer une évolution du CONTRAT CIM (docs/CIM.md, SemVer) — c'est le SEUL cas « cœur »
```

**The common thread**: the core (`guatx-core`) carries the *contract* (CIM, GXQL, pure TI); the seams carry the
*translation* of each vendor into that contract. As long as a vendor can be **described** (parser/connector/
rule by `category`) rather than **coded**, adding it is a config file, not a rebuild — and Plume remains
a **superset** of what the customer already has, never a loss of capability.
