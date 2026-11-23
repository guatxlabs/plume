# OTLP Traces — OpenTelemetry receiver (#41)

[Français](OTLP-TRACES.md) | [English](OTLP-TRACES.en.md)

> **Status: additive, INERT by default.** Plume can ingest OpenTelemetry **distributed traces**
> through the **standard OTLP/HTTP** protocol. Each `span` becomes a CIM row
> (`category=trace`), queryable in GXQL and **correlatable with logs through `trace_id`**. The receiver
> is **OFF** as long as `PLUME_OTLP_TRACES=1` is not set (mode 0 byte-identical).

This is the **vendor-agnostic / sovereign** choice: any existing OpenTelemetry SDK or OTel
Collector exports to Plume **without a new agent** and **without vendor lock-in**.

---

## 1. Endpoint

```
POST /v1/traces
Content-Type: application/json          # OTLP/JSON (ExportTraceServiceRequest)
Content-Encoding: gzip                  # optional (bounded decompression, anti-bomb)
Authorization: Bearer <token-agent>     # MANDATORY (authenticated ingest)
```

- **Signal**: `traces` only. OTLP `metrics`/`logs` → deferred (see §7).
- **Encoding**: **JSON** (`application/json`). OTLP **binary protobuf** → deferred (415 returned);
  JSON covers the SDKs/collectors that can speak OTLP/JSON. Configure the exporter with
  `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json`.
- **Response**: `200` + `ExportTraceServiceResponse` (`{}` = zero rejections; `{"partialSuccess":…}`
  if spans exceeded the per-request ceiling). This `200` attests **reception**, not
  **durability** — §6.

### Activation

```bash
# daemon (env or PLUME_CONFIG)
PLUME_OTLP_TRACES=1
```

Without this flag, `/v1/traces` returns `404` (surface absent) — **no** change of
behavior at rest.

### Auth (authenticated ingest, never an open surface)

`/v1/traces` is a **machine INGEST** path (`agent_bearer_path` + `route_min_role = Ingest`),
exactly like `/api/ingest`, HEC or Loki push. An `Authorization: Bearer <token>` resolves a
**host-bound, ingest-only** `agent` identity (never UI/admin). To provision an agent token:

```
POST /api/tokens   { "name": "otel-collector", "kind": "agent" }   # admin-only
```

A `datasource`/`client` (read) token **cannot** authenticate here (disjoint seam).

### Pointing an OTel Collector at Plume

```yaml
# otel-collector-config.yaml
exporters:
  otlphttp/plume:
    traces_endpoint: https://plume.example.com/v1/traces
    encoding: json
    compression: gzip           # or "none"
    headers:
      Authorization: "Bearer ${PLUME_AGENT_TOKEN}"
service:
  pipelines:
    traces:
      exporters: [otlphttp/plume]
```

Direct SDK (standard env variables):

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://plume.example.com/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer ${PLUME_AGENT_TOKEN}"
```

---

## 2. Span → CIM mapping

An OTLP `span` (`resourceSpans[] → scopeSpans[] → spans[]`) is mapped onto the **canonical
`EventRow` row** and ingested through the **same** path as any other event (`ingest_events_batch`, via the
spool) → **masking (#45), rollups and detection apply uniformly** (a trace is only
an event).

| CIM field (column)  | OTLP source |
|---------------------|-------------|
| `category`          | **`trace`** (fixed) |
| `ts`                | `span.startTimeUnixNano` / 1e9 (epoch seconds) |
| `source`            | resource `service.name` (default `otlp`) — `plume-*` namespace reserved |
| `severity`          | `status.code == ERROR` → `3` (error); otherwise `0` |
| `message`           | `span.name` (the operation) |
| `host`              | resource `host.name` \| `k8s.node.name` \| `host.id` \| `container.name` |
| `dedup`             | `otel-<trace_id>-<span_id>` (idempotent: re-export = no duplicate) |

### First-class trace fields (in `fields`, searchable)

| `fields.*` | Meaning |
|------------|------|
| `trace_id`        | trace ID (lowercase hex) — **the correlation key** |
| `span_id`         | span ID (hex) |
| `parent_span_id`  | parent span (absent = root span) |
| `span_name`       | name of the operation |
| `span_kind`       | `server` \| `client` \| `producer` \| `consumer` \| `internal` \| `unspecified` |
| `trace_status`    | `ok` \| `error` \| `unset` |
| `status_message`  | status message (if error) |
| `service`         | `service.name` |
| `scope_name` / `scope_version` | instrumentation scope |
| `duration_ms`     | `(end - start)` in milliseconds (latency) |
| `otel.<attr>`     | span **and** resource attributes flattened, `otel.` prefix (e.g. `otel.http.method`) |

OTLP `AnyValue`s (`stringValue`/`intValue`/`doubleValue`/`boolValue`/`arrayValue`/`kvlistValue`)
are converted to scalar/structured JSON; `intValue` (proto3-JSON string) → number.

---

## 3. Logs ↔ traces correlation through `trace_id`

The SOC benefit: **joining an application trace to the security logs** that carry the same
`trace_id`. Any log source that emits `trace_id` (through a parser, a Loki attribute, an HEC
field…) lands in `fields.trace_id` — **the same field** as the spans. A query therefore correlates
both surfaces:

```sql
-- tous les events (spans + logs) d'une trace, ordre chronologique
search trace_id=5b8efff798038103d269b633813fc60c | sort ts

-- spans en erreur d'un service, puis pivot sur leur trace_id
search category=trace trace_status=error service=checkout
```

---

## 4. GXQL / example queries

Since traces are `category=trace` events, they are immediately queryable:

```sql
-- opérations les plus lentes (P… par tri sur la durée)
search category=trace | sort duration_ms desc | head 20

-- taux d'erreur par service
search category=trace | stats count, count(eval(trace_status="error")) by service

-- volume de spans par kind
search category=trace | stats count by span_kind
```

> Native panels (slowest-ops, error-rate-by-service, trace-explorer grouped by `trace_id`):
> **deferred** to a UI follow-up. The GXQL queries above cover the use case today and
> can be saved as ad-hoc searches/panels.

---

## 5. DoS safeguards (the decoder = new external attack surface)

The `/v1/traces` body is **attacker-controlled**. Hard bounds:

| Safeguard | Value | Effect beyond it |
|-----------|--------|---------------|
| HTTP body size | `8 Mio` (global DefaultBodyLimit) | rejected upstream |
| gzip decompression (OTLP) | `OTLP_MAX_DECOMPRESS = 16 Mio` (env `PLUME_OTLP_MAX_DECOMPRESS`) | `413` (anti-bomb, bounded **before** allocation) |
| OTLP shape (pre-parse) | root object `{` + `"resourceSpans"` key (O(n) scan) | `400` **before** the full parse (kills non-OTLP JSON that inflates up to the cap) |
| Ingest concurrency | `PLUME_OTLP_INGEST_CONCURRENCY = 4` permits (`ingest_sem` semaphore, separate from the interactive one) | `503` if saturated (the OTLP client retries) — bounds the memory peak to N `Value` trees |
| Spans / request | `min(OTLP_MAX_SPANS=50 000, PLUME_INGEST_MAX_EVENTS)` | `413` (never a silent truncation) |
| Attributes / span | `OTLP_MAX_ATTRS_PER_SPAN = 256` | excess attributes ignored (anti-cardinality) |
| Value depth | `OTLP_MAX_VALUE_DEPTH = 6` | nested value → `Null` (serde already bounds the parse at 128) |

The OTLP decompression cap (**16 MiB**) is deliberately SMALLER than the cap shared by metrics/loki
(`INGEST_MAX_DECOMPRESS = 64 Mio`): OTLP/JSON does not amortize the cost through a structured protobuf decode —
`serde_json::from_slice` materializes the **entire** `Value` tree (several times the text size) before the
span/attr caps apply. Defense in layers: (1) 16 MiB cap, (2) pre-parse shape check, (3)
concurrency bound. Accepted residue: at most `PLUME_OTLP_INGEST_CONCURRENCY` `Value` trees materialized simultaneously.
**THIS FIGURE WAS UNDERESTIMATED AND IT IS CORRECTED (2026-08-30).** This sentence named the size of the SOURCE
TEXT, which reads as a residue of the same order. Measured on the bench, with a counting allocator, on spans
dense in attributes: the LIVE footprint at the point of publication is about TWENTY-FOUR TIMES the text
received — the decoded trees carry nearly nine tenths of it, the written buffer less than a tenth. The concurrency
bound therefore holds a much heavier residue than its wording suggested. THE RATIO
DEPENDS ON THE SHAPE OF THE BODY and does not carry over: it is measured on the costly case, a body dominated
by a single giant string would give much less. What carries over is the PROPERTY — the trees are
ALIVE, and at their MAXIMUM, at the moment of publication — see finding `S31` in the roadmap.

Malformed JSON → `400` **without panic**. No SQL is built from span data:
attributes and names go through the **same** **masked** CIM→event→GXQL path as any ingested field.

---

## 6. Ingestion path (identical to the other receivers)

`POST /v1/traces` → decodes JSON (+gzip) → maps each span → writes a `{kind:"events"}` envelope
into the **spool** (atomic, `0600`) → the background loop calls `ingest_events_batch`. **No**
DB work on the tokio worker (a burst does not saturate the runtime). No host-marker: an
OTel collector legitimately relays several services/hosts (authoritative host = resource attribute).

**"Atomic" is not "durable" — and since `S31` (step 2), the `200` covers both.**
The envelope is written, **synced**, renamed, then its **directory** is synced, all of it
**before** the `200` goes out. The OTel exporter that empties its queue on this acknowledgment therefore no longer loses the
window that existed here: the bytes and their directory entry have both gone through a
barrier. The write is **offloaded** to a blocking thread — the barrier blocks no tokio worker,
which remains true of everything in this paragraph.

The response body still does not say so, and will not: a strict protobuf-JSON decoder
refuses unknown fields in an `ExportTraceServiceResponse`. The witness is therefore in `/metrics` —
`plume_spool_barriere_fichier_total` and `plume_spool_barriere_repertoire_total` go up together on
every accepted export, `plume_spool_barriere_echec_total` says that a barrier was refused. An
operator can disarm the barrier (`PLUME_INGEST_FSYNC=0`); the regime from before `S31` then comes back
as it was, and the counters stop going up.

**What is not proven:** survival of a real power cut. What is demonstrated is
that both barriers are requested from the kernel, returned without error, and in that order. The regime of
the **database** (`/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push`) remains **open** —
see [`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md) (§2.5) and key `S31` of
[`ROADMAP.md`](ROADMAP.md).

---

## 7. Deferred (non-goals of this iteration)

- **OTLP/gRPC** (`OTLP/gRPC`, port 4317) — only **OTLP/HTTP** (`/v1/traces`, 4318-style) is served.
  gRPC would require tonic/h2 on a separate port; the standard OTLP exporter can speak HTTP.
- OTLP **binary protobuf** — JSON only (`application/x-protobuf` → `415`).
- **OTLP `metrics` and `logs` signals** (`/v1/metrics`, `/v1/logs`) — Plume already has
  Prometheus remote_write and Loki push receivers (see `ingest/obs.rs`); unification under OTLP is a
  later project.
- **Native trace panels** (trace-explorer) — GXQL covers the use case; UI in a follow-up.
