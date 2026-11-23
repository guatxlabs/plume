# `http_pull` connector presets (config examples, NOT vendor code)

[Français](README.md) | [English](README.en.md)

These files are **documented configuration examples** — starting points to
**copy/adapt**, not integrations embedded in or maintained within the daemon.

Principle (*vendor-agnostic / superset* directive): Plume **hard-codes NO vendor**.
The generic `http_pull` connector (#20/#22) turns any REST/JSON API into an event
source *by configuration alone*. These presets only **demonstrate** the shape of an `http_pull`
`config` for real APIs (auth, pagination, `field_map`, watermark) — CrowdStrike Falcon,
SentinelOne, a generic REST. There is **not one line of per-vendor code** behind them; they
are documentation. Adding a new vendor = writing a JSON file like these, without a rebuild.

## Usage

1. Create a connector of type `http_pull` in the UI (Data → Source connectors) or via
   `POST /api/connectors` (admin).
2. **Copy the contents of a preset into the connector's `config` field**, then **adapt it**:
   URL/regional host, `client_id`, `field_map` paths (according to the real schema of YOUR tenant/API),
   pagination, watermark.
3. Put the **credential** (OAuth client_secret, API token…) in the connector's **`secret`**
   field — **NEVER in `config`**. The `secret` is never returned nor logged.
4. Use the **Tester** button (`POST /api/connectors/{id}/test`): it fetches 1 page, **ingests
   nothing**, and returns a SAMPLE of the mapped events so you can check that the `field_map` produces what
   you expect.
5. Enable the connector once the preview is correct (created **disabled** by default).

The `_comment` fields are ignored by the config parser (`HttpPullCfg::from_json`); they only
serve to document the preset.

## Enrichment at ingestion

Since #1, **pulled** events go through the **same enrichment pipeline** as a natively ingested
event: declarative parsers, generic extractor, and **threat-intel match-on-ingest**
(a `src_ip`/`dst_ip`/hash that matches a known IOC receives `fields.threat_intel` + `ti_match=1`, and
contributes to risk-based alerting). No extra config needed.

## Reference of the `config` fields (`HttpPullCfg`)

| Field | Role |
|---|---|
| `method` | `GET` (default) or `POST`. |
| `url` **or** `api_root`+`path` | Full URL, or root + path joined together. |
| `body` | Optional static body (POST). |
| `records_path` | JSONPath (safe subset) of the array of records in the response (`""` = the root is the array). |
| `source` | Default `source` label (otherwise `http:{id}`). |
| `sourcetype` / `sourcetype_map` | Constant `sourcetype` + inline `sourcetype -> catégorie CIM` table (bring-your-own CIM, without a rebuild). |
| `field_map` | Object `champ_event: <JSONPath \| "=const">`. `fields.<X>` keys -> `fields` object (searchable in GXQL). Recognized keys: `ts, severity, message, host, src_ip, dst_ip, url, category, sourcetype, source, id, dedup, entity`. |
| `auth.kind` | `none` \| `basic` \| `bearer` \| `token`/`header` (with `header_name`+`prefix`) \| `oauth2_client_credentials` (with `token_url`, `client_id`, `scope`). The credential is ALWAYS the connector's `secret` field. |
| `pagination.kind` | `none` \| `offset` \| `page` \| `cursor` (with `cursor_path`) \| `link_header` (with `next_path` fallback). Params: `param`, `size`, `size_param`, `start`. |
| `watermark` | Incremental: `field_path` (in each record), `param` (sent to the server), `format` (`epoch`\|`iso8601`), `template` (`{value}`), `lookback_days` (cold start). |

See also the code: `daemon/src/handlers/connectors/httppull.rs` (`HttpPullCfg`, `poll_http_pull`).
