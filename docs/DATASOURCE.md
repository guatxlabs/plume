# plume AS A DATASOURCE (#52) — serve queries back to Grafana/Prometheus

Until now plume only **received** telemetry (`POST /api/ingest`, Prometheus `remote_write`, Loki push, Splunk
HEC). It exposed **no read API** a Grafana/Prometheus/Loki datasource could point a panel *at*. This is the
#1 Grafana adoption lever — "meet them where they are": an existing Grafana points a panel at plume instead of
re-platforming.

Three read surfaces (2 built, 1 designed):

| Lever | Endpoint(s) | Grafana datasource | Status |
|-------|-------------|--------------------|--------|
| 1. SOQL-over-HTTP-JSON | `GET/POST /api/ds/query` | Infinity / JSON | **built** |
| 2. Prometheus read | `/api/v1/query`, `/api/v1/query_range`, `/api/v1/label/__name__/values`, `/api/v1/labels`, `/api/v1/series` | Prometheus | **built (honest subset)** |
| 3. Loki read (LogQL) | `/loki/api/v1/query_range` | Loki | **stub (501) + design below** |

Everything here is **read-only** and **additive** — existing ingest/UI endpoints are byte-identical (mode 0).

---

## Security model (the #1 review criterion)

This is a **new external read surface**. It does **not** bypass #45 field-filter masking or RBAC:

- The caller is resolved by the normal `auth_guard` choke-point (token → role/tenant), exactly like every
  other route. **Anonymous is refused** (401) unless the operator opted into `PLUME_PUBLIC_DEMO` (viewer).
- **SOQL-HTTP** funnels every read through `soql_to_sql_masked_x(soql, from, to, env, effective_masks(role,…))`
  — the *same* masked compiler the UI's `/api/query` uses. The mask is emitted **inside the SQL** (before any
  aggregation/rename), and DENY rules on real columns also arm the SQLite read-pool authorizer. A viewer-scoped
  datasource token gets masked/denied fields masked; a query that *filters* on a masked field is rejected the
  same way the UI is.
- **Prometheus** respects role/tenant two ways: (a) a matcher on a **masked** label/host is **rejected** (an
  equality matcher is an oracle — mirror of `search_mask_guard`); (b) label/host **values** in the output are
  redacted via `mask_named_row`. Fail-closed: if a mask can't be applied, the request is refused, never served
  in clear. The metric SQL is built injection-safe (metric name + label keys strictly validated, values
  single-quote-escaped) and executed through the read-only pool (`run_query_ex` rejects any non-`SELECT`).
- **No raw SQL** is ever accepted from a datasource caller — only `soql` (compiled) or a metric selector.
- **Rate-limited** by the existing global + per-IP limiter (`PLUME_RL_IP_MAX`, default 1200 req/10 s) plus the
  per-query concurrency semaphore (`query_sem`) and the per-query time budget (`PLUME_QUERY_BUDGET_MS`, ~5 s).

### Auth / token model

A datasource authenticates with **any** valid credential the choke-point already understands (Basic account,
SSO trusted-header, session cookie) **or** a dedicated **read-scoped `datasource` token** (Bearer):

- Mint via `POST /api/tokens {name, kind:"datasource", role:"viewer"|"editor"}` (admin-only, mode 0). The clear
  secret is shown once. Role defaults to `viewer` (least privilege) and is **hard-bounded to viewer|editor** —
  never admin/agent, so a datasource token can never reach raw SQL or ingest.
- The token is accepted **only** on the datasource read paths (`datasource_bearer_path`, default-closed) and
  maps to `(role, tenant)` → `effective_masks(role,…)` → masking/RBAC inherited automatically.
- Grafana wiring: Prometheus datasource → *Authorization: Bearer <token>* (custom header); Infinity → Bearer
  token auth, URL `https://plume/api/ds/query`.

Schema: migration **v87** adds `token.role` (nullable). Agent/HEC tokens keep `role = NULL` (unchanged).
Datasource tokens are **mode-0 only** (like the UI token provisioning); in multi-tenant mode use Basic/SSO.

---

## Lever 1 — SOQL-over-HTTP-JSON (`/api/ds/query`)

The most general lever: run any SOQL read and get tabular JSON back.

```
GET  /api/ds/query?soql=<soql>&from=<epoch>&to=<epoch>&limit=<n>&format=records|table
POST /api/ds/query   {"soql":"search category=auth | stats count by host", "from":0, "to":0, "limit":500}
```

- `format=records` (default) → `[{col: val, …}, …]` (Grafana Infinity's natural shape).
- `format=table` → `{ "columns": [...], "rows": [[...], …] }`.
- `from`/`to` = epoch seconds (0 = unbounded). `limit` capped at 10 000.
- Compilation is byte-identical to `/api/query`'s SOQL path (masks applied). No `sql` (raw) field is accepted.

## Lever 2 — Prometheus-compatible read

Point a Grafana **Prometheus** datasource at `https://plume` (it will call `/api/v1/*`).

**Supported subset (honest):**

- Instant `GET/POST /api/v1/query?query=<selector>&time=<epoch>` → `resultType: vector` (last sample ≤ `time`
  per series, within a bounded lookback `PLUME_PROM_LOOKBACK_S`, default 3600 s).
- Range `GET/POST /api/v1/query_range?query=<selector>&start=&end=&step=` → `resultType: matrix` (**raw**
  samples in `[start,end]`; `step` is **not** re-sampled — Grafana downsamples client-side).
- `GET /api/v1/label/__name__/values` → distinct metric names. `GET /api/v1/label/<label>/values` → distinct
  values (rejected if the label is masked for the caller).
- `GET/POST /api/v1/labels` → known label keys (`__name__`, `host`, sampled JSON keys), minus masked keys.
- `GET/POST /api/v1/series?match[]=<selector>` → matching series label-sets (masked).

**Selector grammar (minimal):** `metric_name`, `metric_name{label="v",…}`, or `{__name__="metric_name",…}`.
**Only the `=` (equality) matcher is supported.** `!=`, `=~`, `!~` are **not** supported (clear 400).

**Explicit non-goals (documented follow-on):** no PromQL functions (`rate`, `sum`, `histogram_quantile`,
`irate`, …), no operators/aggregations, no `@`/offset modifiers, no regex matchers, no rollup-backed history
(only the raw `metric` table is served). This is a **compatibility shim** to graph a *stored* metric, not a
PromQL engine — consistent with the superset principle (don't overclaim).

## Lever 3 — Loki read (LogQL) — design + stub

`GET/POST /loki/api/v1/query_range` currently returns **501** (config seam `PLUME_LOKI_QUERY`, default off).

**Planned design (follow-on):** logs live in the `event` table (Loki push lands there with `category='log'`).
A LogQL stream selector `{source="…", host="…"} |= "needle"` maps cleanly onto SOQL:

```
{job="sshd"} |= "Failed password"   →   search source="plume-sshd" "Failed password" | table ts, host, message
```

The read path will reuse the **same masked compiler** (`soql_to_sql_masked_x` on `event`) so masking/RBAC are
inherited identically to lever 1 — including the `search_mask_guard` oracle rejection for filters on masked
fields. Line-format/label-format and metric queries (`count_over_time`, `rate`) are later stages. The stub +
seam exist so a Loki datasource can be *pointed* at plume today and light up when the flag ships.

---

## What is NOT changed

Existing ingest (`/api/ingest`, `/api/metrics/*`, `/loki/api/v1/push`, HEC), UI, detection, and all mutating
routes are untouched. The new endpoints are purely additive and read-only; with no field-filters configured
(mode 0) they behave like a thin read shim over the existing masked query path.
