# Cloud connector presets (`http_pull`)

[English](CONNECTOR-PRESETS.md) | [Français](CONNECTOR-PRESETS.fr.md)

> **Status: documentation + declarative descriptors.** A "preset" is **not** vendor
> code: it is a JSON file in [`docs/connector-presets/`](connector-presets/) to **copy
> into the `config` field** of an `http_pull` connector (no rebuild). The generic
> `http_pull` connector (#20/#22) turns any REST/JSON API into an event source *by
> configuration alone* — see [`docs/SDK.md`](SDK.md) and
> [`connector-presets/README.md`](connector-presets/README.md). This document describes, **per vendor**:
> the pulled API, the auth + scopes, the `field_map` → CIM, and the **secret-ref** to set.

## Principle (vendor-agnostic / superset)

- **Zero per-vendor code.** Each preset is an `http_pull` `config` (URL, auth, pagination,
  `field_map`, watermark). Adding a vendor = writing a JSON file like these — never a line of
  Rust. A user can always **bring-his-own** via a blank `http_pull`.
- **Inert by default (mode-0).** No preset is active until an **admin** creates a
  connector with credentials. Empty `connector` table ⇒ **byte-identical** behaviour.
- **CIM as the pivot.** Each `field_map` maps the vendor's fields to the
  [CIM](CIM.md) (`ts, src_ip, dst_ip, url, host, severity, message` + `category` derived from the
  `sourcetype` via `sourcetype_map`, and `fields.*` for extended dimensions such as
  `user`/`action`).

## Security (invariants, valid for ALL presets)

| Invariant | Mechanism |
|---|---|
| **Secrets = secret-ref, never in git** | The credential (OAuth client_secret, API token…) goes **exclusively** into the connector's **`secret`** field (never returned, never logged). The descriptors contain only **non-secret** identifiers (`client_id`, `token_url`, `scope`) — a CI test (`cloud_presets_parse_load_and_are_secret_free`) fails if a descriptor contains `client_secret`/`api_key`/`password`/… |
| **SSRF guard at egress** | The outgoing URL goes through `ssrf_guard(u)` at the **real egress point** (production `fetch`, `connectors/mod.rs`) — for the poll **and** the `Tester` dry-run. Internal targets (loopback / link-local metadata `169.254.169.254` / unspecified / IPv6 `fe80::/10` and `fc00::/7`) are refused whatever `PLUME_SSRF_BLOCK_PRIVATE` says; only a target listed in `PLUME_SSRF_ALLOW` escapes this. RFC1918 private addresses (`10/8`, `172.16/12`, `192.168/16`) are refused **by default** for a target entered through the API — connector, destination, channel (including a slack channel's `webhook_url`), and every address called by an OIDC identity provider (discovery, JWKS, token endpoint) or an LDAP one (the directory) or an AI one (inference call), whether written by the administrator or returned by the discovery document (operator decision of 2026-11-03: an IdP or an inference side-box on a private network is listed in `PLUME_SSRF_ALLOW`); a configuration target keeps them: the channel seeded by `PLUME_NOTIFY_NTFY_URL` (its exact URL) and an object written as a `config.d` overlay (its own targets, as long as its row still carries them). `PLUME_SSRF_BLOCK_PRIVATE=0` (or `false`/`no`/`off`) admits them everywhere, `=1` (or `true`/`yes`/`on`) refuses them everywhere, configuration included; empty or unrecognized = the default. `PLUME_SSRF_ALLOW` = comma-separated list of **exact** hosts and/or IPs or CIDRs (e.g. `10.20.0.0/16,svc.interne.example`) for which the **whole** guard is lifted, not just the private part. An **LDAP** identity provider's connection to its directory is judged by the same guard, before any connection (`ldap_garde_de_sortie`, daemon/src/idp/ldap.rs: `ldap://` and `ldaps://` only, `ldapi://` and an empty host refused, the literal and every resolved address judged); its URL is refused as soon as it is entered for its private address alone, like an OIDC issuer. A preset bypasses **nothing**: it goes through the same choke point. |
| **Admin-gated CRUD** | Creating / modifying / testing / polling a connector requires `is_admin()` (`forbidden` otherwise). |
| **Created disabled** | A connector is `enabled:false` at creation: the admin **tests** it (1-page dry-run, ingests nothing) before enabling it. |
| **Injection-safe extraction** | The `field_map` relies on a **safe JSONPath subset** (key/index/`[*]`) — pure indexing, zero eval. |

## How to use a preset

1. **Data → Source connectors** (or `POST /api/connectors`, admin) → new
   `http_pull` connector.
2. **Copy the preset's JSON** into the `config` field, then adapt the `REPLACE_*` /
   `{placeholders}` (regional host, tenant, `client_id`, account_id…).
3. Put the **credential** in the **`secret`** field (never in `config`).
4. **Test** (`POST /api/connectors/{id}/test`): 1 page, **ingests nothing**, returns a sample
   of the **mapped** events — check that the `field_map` produces the expected CIM.
5. **Enable** it once the preview is correct.

The pulled events go through the **same enrichment pipeline** as native ingest (declarative
parsers, generic extractor, **threat-intel match-on-ingest**).

---

## Preset matrix

| Vendor | File | API | Auth | Pagination | CIM `category` | Status |
|---|---|---|---|---|---|---|
| Okta | `okta.json` | System Log `GET /api/v1/logs` | `SSWS` header (secret) | `Link` RFC5988 | `auth` | **direct fit** |
| Entra ID sign-ins | `m365-entra-signin.json` | Graph `GET /v1.0/auditLogs/signIns` | OAuth2 client-creds | asc. watermark | `auth` | **direct fit** |
| Entra ID / M365 audit | `m365-entra-audit.json` | Graph `GET /v1.0/auditLogs/directoryAudits` | OAuth2 client-creds | asc. watermark | `audit` | **direct fit** |
| Google Workspace | `google-workspace.json` | Admin SDK Reports `activities` | Bearer (short-lived token) | `nextPageToken` | `auth` | fit + **token sidecar** |
| Cloudflare (audit) | `cloudflare-audit.json` | `GET /client/v4/accounts/{id}/audit_logs` | Bearer API token | `page`/`per_page` | `audit` | **direct fit** |
| AWS CloudTrail | `aws-cloudtrail.json` | CloudTrail records (S3/Firehose) | via gateway/push | depends on delivery | `audit` | **field_map** + delivery |
| AWS GuardDuty | `aws-guardduty.json` | Findings (EventBridge/SigV4) | via gateway/push | depends on delivery | `ids` | **field_map** + delivery |
| GCP Cloud Audit | `gcp-audit.json` | Logging `LogEntry` (Pub/Sub/gateway) | Bearer (short-lived token) | `nextPageToken` | `audit` | **field_map** + delivery |
| CrowdStrike Falcon | `crowdstrike-falcon.json` | Alerts API v2 | OAuth2 client-creds | `offset`/`limit` | `malware` | direct fit (pre-existing) |
| SentinelOne | `sentinelone.json` | Threats API v2.1 | `ApiToken` header | `cursor` | `malware` | direct fit (pre-existing) |
| Generic | `generic-rest.json` | — | bearer | `page` | (your choice) | skeleton |

> **"field_map + delivery"** = the vendor's native API requires a signature/flow that the generic
> puller does not do (AWS **SigV4**, GCP **service-account JWT**). The **durable and
> reusable** piece is the `field_map` → CIM; the events arrive through a suitable delivery mode
> (S3-pull, Firehose/EventBridge → HEC, Pub/Sub → HEC, or a signing gateway). See each
> section.

---

## Okta — System Log API

- **API**: `GET https://{yourOktaDomain}/api/v1/logs?sortOrder=ASCENDING` — root = array
  of events (`records_path:""`).
- **Auth**: Okta **SSWS** API token → header `Authorization: SSWS <token>` (`auth.kind=header`,
  `prefix:"SSWS "`). **Secret-ref**: the token in the `secret` field.
- **Pagination**: Okta returns an RFC5988 `Link` header `rel="next"` → `pagination.kind=link_header`
  (native). `size`→`limit` (max 1000).
- **Increment**: `sortOrder=ASCENDING` + watermark on `published` (`param:"since"`, ISO8601) —
  each tick resumes **after** the last `published` seen, **without loss**.
- **field_map → CIM**: `uuid→id`, `published→ts`, `displayMessage→message`,
  `client.ipAddress→src_ip`, `actor.alternateId→fields.user`, `outcome.result→fields.action`,
  `eventType→fields.event_type`, geo → `fields.city/country`. `sourcetype=okta:system → category auth`.
- **Severity note**: Okta's `severity` is in **UPPERCASE** (`INFO/WARN/ERROR`), not recognized by
  `sev_num` (default **0**). Refine through a declarative parser if sorting by severity is required.

## Microsoft 365 / Entra ID — Microsoft Graph

Same **OAuth2 client-credentials** pattern as the **Defender** connector (reused, not reinvented).

- **Entra app**: register an application, **application permission** `AuditLog.Read.All`
  (+`Directory.Read.All` for audits), admin consent. `token_url` =
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `scope` =
  `https://graph.microsoft.com/.default`. **Secret-ref**: the app's *client secret* in the
  `secret` field; `client_id`/`token_url`/`scope` stay in `config` (non-secrets).
- **Sign-ins** (`m365-entra-signin.json`): `GET /v1.0/auditLogs/signIns`, `records_path:"value"`,
  `category auth`. `field_map`: `createdDateTime→ts`, `userPrincipalName→fields.user`,
  `ipAddress→src_ip`, `appDisplayName→message`, `status.errorCode→fields.action`,
  `riskLevelDuringSignIn→severity` (low/medium/high recognized), `location.*→fields.city/country`.
- **Directory audits** (`m365-entra-audit.json`): `GET /v1.0/auditLogs/directoryAudits`,
  `category audit`. `activityDisplayName→message`, `initiatedBy.user.userPrincipalName→fields.user`,
  `result→fields.action`, `targetResources[0].*→fields.target`.
- **Pagination**: Graph's next-page link is the `@odata.nextLink` key (a dot **inside** the
  key, not addressable by the safe JSONPath). We do **not** paginate by nextLink but by **ascending
  watermark**: `?$orderby=createdDateTime` + `watermark.template:"createdDateTime gt {value}"`
  (param `$filter`) + `size→$top`. Each tick resumes chronologically, **without loss**. For a
  faster backfill: increase `$top` or the poll frequency.

## Google Workspace — Admin SDK Reports

- **API**: `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}`
  (`app` = `login`|`admin`|`drive`|`token`|`saml`|`groups`…). `records_path:"items"`.
- **Scope**: `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
- **Auth**: the API requires an **OAuth2 access_token** obtained by a **service account** with
  **domain-wide delegation** (JWT-bearer RS256) — a flow **not** performed by the generic
  puller. **Secret-ref**: put a **short-lived access_token (~1 h)** in the `secret` field
  (`auth.kind=bearer`) and **refresh it through a sidecar** (workload-identity /
  impersonated `gcloud auth print-access-token`). → *status: documented, requires a token sidecar.*
- **Pagination**: `nextPageToken` (query) → `pagination.kind=cursor` (`param:"pageToken"`,
  `cursor_path:"nextPageToken"`). Watermark `startTime` (RFC3339).
- **field_map → CIM**: `id.time→ts`, `id.uniqueQualifier→id`, `actor.email→fields.user`,
  `ipAddress→src_ip`, `events[0].name→message`, `id.applicationName→fields.application`.
  `sourcetype=gsuite:login → category auth` (use `admin`→`audit`, `drive`→`data` depending on the app).

## Cloudflare — Audit Logs

- **API**: `GET https://api.cloudflare.com/client/v4/accounts/{account_id}/audit_logs?direction=asc`
  — `records_path:"result"`.
- **Auth**: Cloudflare **API token** with the *Account Audit Logs: Read* permission → Bearer
  (`auth.kind=bearer`). **Secret-ref**: the token in the `secret` field.
- **Pagination**: `pagination.kind=page` (`param:"page"`, `size→per_page`). Watermark `when`
  (`param:"since"`, RFC3339).
- **field_map → CIM**: `id→id`, `when→ts`, `action.type→message`, `actor.email→fields.user`,
  `actor.ip→src_ip`, `action.result→fields.action`, `resource.type→fields.resource_type`.
  `sourcetype=cloudflare:audit → category audit`.
- **HTTP requests (WAF/proxy)**: they are **not** exposed by a paginated pull API →
  use **Logpush → R2 / HTTP endpoint** to Plume's **HEC** ingest (source `cloudflare-http`,
  already present, `category web`).

## AWS CloudTrail

- **Delivery issue**: the native API (`LookupEvents`) signs with **SigV4**, which the puller does
  not do. Two routes (same `field_map`):
  1. **S3-pull** — CloudTrail drops `.json.gz` `{"Records":[...]}` files into an S3 bucket; a
     forwarder/gateway exposes them over HTTP (`records_path:"Records"`), or the object-store collector does.
  2. **Push** — EventBridge / Kinesis **Firehose** → HTTP endpoint → Plume's **HEC ingest**
     (Firehose injects an `X-Amz-Firehose-Access-Key` header, **secret-ref**).
- **field_map → CIM** (CloudTrail record): `eventID→id`, `eventTime→ts`, `eventName→message`,
  `sourceIPAddress→src_ip`, `userIdentity.arn→fields.user`, `eventSource→fields.event_source`,
  `awsRegion→fields.aws_region`, `errorCode→fields.action`, `userAgent→fields.user_agent`.
  `sourcetype=cloudtrail → category audit` (S3 data-events → `data` via `sourcetype_map`).
- **Status**: documented; the `field_map` can be verified offline, the **delivery** requires a
  gateway/push (no live creds required to validate the mapping).

## AWS GuardDuty

- **Delivery**: `ListFindings`/`GetFindings` sign with SigV4. Recommended route: **EventBridge**
  (*GuardDuty Finding* rule) → Firehose / HTTP endpoint → **HEC ingest**; the EventBridge `detail`
  **is** a GuardDuty finding (the `field_map` applies to it). Otherwise a SigV4-signing gateway.
- **field_map → CIM**: `Id→id`, `UpdatedAt→ts`, `Title→message`, `Type→fields.finding_type`,
  `Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4→src_ip` (varies with
  `ActionType`), `Region/AccountId→fields.*`. `sourcetype=guardduty → category ids`.
- **Severity note**: GuardDuty scores **1.0–8.9**; the puller bounds to **0..4** (High 7–8.9→4,
  Medium 4–6.9→4, Low 1–3.9→1–3). An acceptable approximation, refinable through a declarative parser.
- **Status**: documented; mapping verifiable offline, delivery via push.

## GCP Cloud Audit Logs

- **Delivery**: the Logging API `entries:list` is a **POST** with `pageToken` **in the body** and
  requires a **service-account (JWT-bearer RS256)** access_token — a poor fit for the GET/param puller.
  Routes:
  1. **Push** — log sink → **Pub/Sub** → push subscription → HTTP endpoint → **HEC ingest** (the Pub/Sub
     message wraps the `LogEntry`).
  2. **Best-effort pull** — a sidecar drops a **short-lived access_token** (scope `logging.read`) into the
     `secret` field (`auth.kind=bearer`), behind a paginated GET gateway
     (`records_path:"entries"`, cursor `nextPageToken`).
- **field_map → CIM** (`LogEntry`/`protoPayload` AuditLog): `insertId→id`, `timestamp→ts`,
  `protoPayload.methodName→message`, `protoPayload.authenticationInfo.principalEmail→fields.user`,
  `protoPayload.requestMetadata.callerIp→src_ip`, `protoPayload.serviceName→fields.service`,
  `resource.type→fields.resource_type`, `protoPayload.status.code→fields.action`.
  `sourcetype=gcp:audit → category audit` (Data Access logs → `data`).
- **Severity note**: GCP's `severity` is in **UPPERCASE** (`INFO/WARNING/ERROR`…) → not normalized
  (default 0). **Status**: documented, requires a token sidecar / push.

## CrowdStrike Falcon & SentinelOne (pre-existing)

See [`connector-presets/crowdstrike-falcon.json`](connector-presets/crowdstrike-falcon.json)
(OAuth2 client-creds, Alerts API v2, `category malware`) and
[`connector-presets/sentinelone.json`](connector-presets/sentinelone.json) (`ApiToken` header,
Threats API v2.1, cursor, `category malware`). Same secret-ref / SSRF / admin-gate invariants.

---

## Tests

- `cloud_presets_parse_load_and_are_secret_free` — all descriptors PARSE via
  `HttpPullCfg::from_json`, non-empty `field_map`, `sourcetype_map` → valid CIM categories, **no
  secret in clear text**.
- `okta_preset_normalizes_sample_payload_to_cim` — the **real** Okta preset normalizes a
  System-Log payload into a CIM event (`category auth`, `src_ip`/`user`/`action` mapped, idempotent dedup).

(Module `daemon/src/tests/connectors.rs`.)
