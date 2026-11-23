# The console, space by space and tab by tab

[Français](CONSOLE.md) | [English](CONSOLE.en.md)

The plume console is a web application served by the daemon itself — JavaScript modules,
no build step, no dependency to install. It is navigated on **two levels**:
**spaces** in the sidebar, and **tabs** inside a space.

This document says **what each tab does, who can see it, and what it does not do**. It does not
replace the built-in help — the console's *Help* space, entirely static and offline —
but it is what you read **before** you have an instance at hand.

---

## 1. What a reader needs to know before the table

### 1.1 Reaching it, in all three modes

The address depends on the deployment mode: see [`TROIS-MODES.md`](TROIS-MODES.en.md#31-reaching-the-console).
In all three cases, the requested name must match `PLUME_HOST`, otherwise the DNS
rebinding guard returns `421`.

Without `PLUME_PASS_HASH`, the central starts in **SETUP mode**: a single-use installation token
appears in the logs, and the web wizard takes over.

### 1.2 Three roles, and a closed default

`viewer` · `editor` · `admin`. The check that counts is **server-side**: an unlisted route is
refused, not allowed. What the console hides is a convenience, not security — a hidden tab
whose address someone forced would run into a `403` from the API.

Three forms of restriction appear in the table below:

| Mark | Meaning |
|---|---|
| **admin space** | the whole space is reserved for administrators (that is the case of *Administration*) |
| **admin tab** | only the tab is reserved, the space stays visible |
| **multi-tenant** | the tab only appears in multi-tenant mode (`PLUME_MULTI_TENANT=1`), invisible otherwise |

Several tabs are **readable by everyone, writable by editor or administrator**: the
list is visible, the edit buttons are not.

### 1.3 A tab is an address

The URL fragment **is** the tab's identifier, unique across all spaces: `#explore`,
`#ledger`, `#datamodels`. Deep links therefore work, and can be shared. A few old
top-level fragments are still accepted as aliases, so as not to break existing links.

A space that has a single tab shows no tab bar.

### 1.4 Where this table comes from, and why it can no longer go stale silently

**The "Tab" column is derived from the navigation structure; the "Label" column from the
served document.** Read from the tracked tree on 2026-08-25: **8 spaces, 37 tabs** — count
unchanged on 2026-08-30. The command that gives the counts again:

```sh
python3 - <<'PY'
import re
src = open('web/navigation.js', encoding='utf-8').read()
bloc = src[src.index('const SPACES = ['):src.index('\n];', src.index('const SPACES = ['))]
esp = re.findall(r"\{\s*id:\s*'([a-z0-9-]+)'\s*,(?:\s*admin:\s*true\s*,)?\s*tabs:", bloc)
ong = re.findall(r"\{\s*id:\s*'([a-zA-Z0-9-]+)'\s*,\s*label:", bloc)
print(len(esp), "espaces,", len(ong), "onglets")
PY
```

**A label is not a written name: it is a DERIVED name.** Since 2026-08-25, the console
no longer writes a tab's name anywhere. It takes it where it is permanent, in this order:
the **title of the panel** the tab opens when it opens only one; failing that, the space's **sidebar
link**, when that space has only one tab; failing that, the label that a **group** tab
declares, for lack of a single panel to name (two cases only); failing that, an **admission**
that says the destination is not named, never a silence.

This column, though, was still copied by hand — and it stopped being kept up the very same day, without
anything saying so. **Measured on 2026-08-30: 24 of the 37 rows named a tab differently from
the screen.** They are now derived, and the property is **held by an instrument** rather
than by proofreading: `check_a_documented_tab_label_is_the_name_the_console_serves.py` re-runs the
derivation at each integration, compares, and **refuses to conclude** — instead of guessing — on
any destination it cannot decide. A modified panel title therefore turns this
document red.

**What this instrument does not see**, and it is written here rather than silenced by a green guard: a name quoted in **prose**
escapes it, and a label column moved out of the second position would escape it too.
On top of that comes a blind spot measured on 2026-08-30 while testing the guard itself: it consults four
sources to derive a name, and the ORDER in which it consults them — which IS the derivation, not a
detail — is exercised by none of its tests. Reversing that order leaves it GREEN. Neither its witness
corpus, nor its oracle, nor the real document can decide it, for a single reason: the only
tabs that fall back on a secondary source have an EMPTY panel title, so that both
orders yield the same string there. The deciding case can be named and does not exist: a space with a
SINGLE tab whose panel carries a title DIFFERENT from its sidebar link.

---

## 2. The eight spaces

### 2.1 `overview` — Overview

A single tab. It is the landing page: it answers "is everything all right?" before you
know what to ask.

| Tab | Label | Role | What you see there |
|---|---|---|---|
| `overview` | Vue d'ensemble | viewer+ | firewall, control catalog, integrations, and a compact pulse of source **freshness** |

It is **live**: it ignores the bar's time range selector, unlike the
dashboards. The full freshness detail has its own tab (`freshness-view`), so that
this page stays readable.

### 2.2 `search` — Search

A single tab, and it is the heart of the product.

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `explore` | Recherche | viewer+ | write a GXQL query, validate it while typing, read the results, the time histogram and the field facets, expand an event, export |

It is the **only** tab where the query bar is displayed, and it carries its own range
selector, distinct from the dashboards' one. The language itself is described in
[`GXQL.md`](GXQL.en.md); the shipped templates load there in one click.

### 2.3 `cases` — the alert → case flow

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `alerts` | Alertes | viewer+ | the queue of alerts raised by the rules, grouped, to triage |
| `cases` | Cases (gestion d'incident) | viewer+ | an incident case: timeline, linked events and alerts, deadlines |

The separation is deliberate: *Alerts* is what comes in, *Cases (incident management)* is what
you do about it.

### 2.4 `dashboards` — Dashboards

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `dashboards` | Dashboards | viewer+ | build and read dashboards; **each panel displays the query that produces it** |

It is the only space driven by the **bar's range selector**; it refreshes
automatically.

### 2.5 `detresp` — Detection and response

Seven tabs: from the rule that detects to the action that responds.

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `detection` | Détection | viewer+ read · editor+ write | the shipped rules and your own, and the coverage panel |
| `attack` | Matrice ATT&CK (couverture) | viewer+ | the MITRE ATT&CK coverage matrix — each miss becomes a visible blind spot |
| `playbooks` | Playbooks | viewer+ read · **runbook authoring reserved for administrators** | detection → automatic response, and the **Engagement Mode** switch |
| `actions` | Actions | viewer+ | the response queue: what is proposed, approved, applied, refused |
| `risk` | Risque par entité (RBA) | viewer+ | risk score per entity (risk-based alerting) |
| `detadv` | Détection avancée | viewer+ read · editor+ write | sequence correlations and behavioral baselines |
| `routing` | Politiques de notification | viewer+ read · editor+ write | who a notification goes to, and what gets muted |

An action is **never** applied without going through this chain: proposal, **approval by an
administrator**, claim by the agent, result in the audit log. The detail of the return channel is
in [`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md#6-le-canal-retour--réclamer-une-action).

### 2.6 `data` — Data and its plumbing

The largest space: thirteen tabs, from the raw source up to the semantic layer.

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `sources` | Inventaire des sources | viewer+ | the inventory of declared feeds: expected versus actual |
| `freshness-view` | Fraîcheur des sources | viewer+ | collection health, feed by feed, in detail |
| `system` | Système — opérabilité | viewer+ read · administration tools reserved | daemon self-metrics, per-component health, bulletin and diagnostics |
| `fleet` | Flotte — par hôte | viewer+ | the inventory of hosts and endpoints: last contact, status, enrollment |
| `connectors` | Connecteurs de sources | **admin** | external sources in **PULL** — the source-adding path that exists in all three modes |
| `destinations` | Destinations de sortie | **admin** | forwarding events to an external sink (syslog, HEC, webhook) — an exfiltration surface, hence the restriction |
| `processors` | Processeur d'ingest | **admin** | filter, mask, route, sample **at ingestion** |
| `indexes` | Indexes & rétention | **admin** | named logical indexes, with their own retention and caps |
| `parsers` | Parsers (extraction de champs) | viewer+ read · editor+ write | field extractors, shipped and personal |
| `lookups` | Lookups (tables d'enrichissement) | viewer+ read · editor+ write | the lookup tables used by the `lookup` command |
| `knowledge` | Objets de savoir | viewer+ read · editor+ write | knowledge objects resolved at search time: aliases, calculated fields, event types, tags |
| `datamodels` | Modèles de données & Pivot | viewer+ read and run · editor+ write | the semantic layer and the pivot report builder |
| `dataaccess` | Accès données | viewer+ | data access governance, read-only |

> **Note for the container and cluster modes.** Dropping a parser or a rule **as a file** there
> is difficult or impossible (read-only root). The `parsers`, `detection` and
> `lookups` tabs are therefore the normal path in these two modes — and what you create there carries a mark
> distinct from what comes from a versioned file. See
> [`TROIS-MODES.md`](TROIS-MODES.en.md#34-adding-a-parser-a-rule-a-playbook).

### 2.7 `admin` — Administration

**Space entirely reserved for administrators.** Eleven tabs.

| Tab | Label | Role | What you do there |
|---|---|---|---|
| `settings` | Réglages | your own account | password, preferences, and enrolling a TOTP second factor |
| `users` | Comptes & accès | admin | accounts and their roles |
| `tokens` | Jetons (agent & HEC) | **admin** | provision an agent or HEC token — the secret is displayed **only once** |
| `idp` | Identité fédérée (SSO) | **admin** | OIDC and LDAP providers — see [`NATIVE-IDP.md`](NATIVE-IDP.md) |
| `fieldfilters` | Field filters (masquage PII) | **admin** | per-field masking; it is a configuration that **constrains** the other roles |
| `tenants` | Tenants | **multi-tenant only** | tenants and entitlements; invisible in single-tenant |
| `notifiers` | Canaux de notification | admin | where notifications go |
| `threatintel` | Threat Intel (IOC) | admin | the IOC store: coverage, list, add, STIX import |
| `suppressions` | Suppressions & whitelists actives | admin | what you choose to no longer see, and why |
| `retention` | Rétention des données | admin | how long data is kept — see also [`PURGE.md`](PURGE.en.md) |
| `ledger` | Journal d'audit | admin | the hash-chained audit log, verifiable offline with `plume-daemon verify` |

Per-field masking deserves to be understood before it is set: it acts **at query
compile time**, and a query that touches a masked field is **refused** rather than returning an
empty value — see [`GXQL.md`](GXQL.en.md#53-masking-happens-at-compile-time).

### 2.8 `help` — Help

| Tab | Label | Role | What you find there |
|---|---|---|---|
| `help` | Aide | everyone | the built-in guide: summary of the spaces and glossary, **entirely static, no network call** |

The "?" buttons scattered across the console open a section of this same guide. A CI guard
(`check_every_help_trigger_has_a_section.py`) refuses a help button that opens a section that
does not exist — the defect had lived for weeks without anything saying so.

---

## 3. How the console is built, and why

**No build step.** JavaScript modules, served as is from disk. An
operator can read what runs at their site without tooling — consistent with a product that
promises a single binary and no external dependency. The price is real: no typing, no
transpilation, and a broken import shows up at runtime — hence a module harness in CI, which
loads the console outside a browser to catch those broken links.

**Navigation is data, not code.** Spaces and tabs are declared in a single
structure; the indexes (tab → space, fragment → tab) are **derived** from it. That is what lets
this document — and its guard — rely on a single source rather than on a hand-kept
list.

**What writes is kept apart from what reads.** A tab that exposes an exfiltration surface
(*Output destinations*), that handles secrets (*Tokens (agent & HEC)*, *Federated identity
(SSO)*) or that constrains the other roles (*Field filters (PII masking)*) is reserved for
the administrator — and the API refuses it too, independently of what
the console shows. Sensitive routes go through a shared confirmation, itself **derived from the
router** by a CI guard rather than enumerated.

**Content carries its origin.** A rule, a parser or a dashboard shows whether it comes from the
product, from a versioned file overlay, or from something created in the console. Without this
mark, an operator would not know what a restart can rewrite — and a personal homonym
causes the file overlay to be **ignored**, with a warning, rather than silently overwriting
the operator's work.

**Each panel shows its query.** A chart whose question cannot be read is a
black box; in a security tool, that is a defect, not an ergonomic choice.

---

## 4. What this document does not cover

- **Fine ergonomics** — keyboard shortcuts, preferences, light and dark theme, bilingualism and
  time zones — is not described here: it lives in the built-in guide, as close to the screen as possible.
- **No screenshot for this document was taken in this batch**, and **no instance was
  opened**: the tabs, their labels, their role restrictions and their grouping are
  **derived from the console's navigation structure**, not observed on screen. A discrepancy between this
  table and your instance is a defect to report.
- **Tabs backed by an optional feature** may behave differently depending on the
  build or the configuration — SAML absent from the shipped image, experimental analytics tier,
  multi-tenant disabled by default. The status of each topic is carried by
  [`README.md`](README.en.md), the index of this documentation.
