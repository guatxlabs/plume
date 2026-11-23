# Plume — Declarative parser (CIM DSL) — Slice #7, part 2

[Français](PARSER-DSL.md) | [English](PARSER-DSL.en.md)

> **Status: operator contract.** This document describes the format of a **declarative parser**: a JSON
> file placed under `config.d/parsers/` that **maps a source to the CIM** (`docs/CIM.md`) **without recompiling
> Rust**. It answers the blocker "will my 40 sources parse?": adding a source = adding
> a file.

- **Code anchor**: `dparser_compile` / `dparsers_reload` / `dparsers_apply` (`daemon/src/parsers.rs`),
  table `dparser` (migration v78), loader `load_overlay_dparsers`.
- **Shipped example**: [`config.d/parsers/example-cim-firewall.json`](../config.d/parsers/example-cim-firewall.json).

---

## 0. Guiding principle — ENRICH / MAP, never DROP

A declarative parser **parses, maps, enriches**. It **cannot remove or filter** an event:
a missing capture = **no enrichment** (never a removal). Any reduction of collection is a
**filter**, which belongs to the *whitelists* panel (#10), **not to a parser**.

**Mode 0 / byte-identical**: as long as no declarative parser targets a source, the event is stored
**byte for byte** as it is today. The mechanism is **purely additive**.

---

## 1. Where and how

- File `config.d/parsers/<nom>.json`. What **discriminates** a declarative parser is the presence of a
  **`map`** object (the *legacy regex* parsers with `pattern` live in the same folder and are loaded
  separately — a file goes to exactly one loader).
- Loaded at boot by `load_overlay_dparsers` (`managed=1`, git source), **validated-or-skipped**: an invalid
  spec (broken regex/`match`/`map`) is **WARN + skip**, never a boot crash.
- Compiled into the registry by `dparsers_reload`, then **executed at ingest** (`kind=events` path), **after**
  `parsers_apply`/`extract_generic` and **before** `src_ip`/`dst_ip`/`url` are promoted to columns.

---

## 2. Format

```jsonc
{
  "name": "…",              // required, UPSERT key
  "source": "firewall",      // targeted event source ('*' = all). Default '*'
  "enabled": true,           // default true

  "match": "action=",        // OPTIONAL: guard regex. The parser applies ONLY to
                              //   messages that match. Absent = applies to the whole source.

  "extract": [               // OPTIONAL: ORDERED extraction steps -> bag of captures.
    { "regex": "SRC=(?P<src>\\S+) DST=(?P<dst>\\S+)" },  // Rust NAMED groups (?P<name>…)
    { "kv": true },          // scans key=value / key="quoted" / logfmt   (alias: "logfmt": true)
    { "json": true },        // message = top-level JSON object, flattened 1 level (k, k.subkey)
    { "csv": { "delimiter": ",", "columns": ["ts", "src", "dst", "action"] } }
                             // message = ONE delimited line (CSV export); each cell is captured
                             //   under the name of the DECLARED column (quotes, inner "" and quoted
                             //   separator honored). The header line (cells == columns) is NOT a
                             //   record: no capture, counted (ingest.csv_header_lines_total).
  ],

  "map": {                   // REQUIRED: assigns values to CIM fields.
    "category": "firewall",   //   literal OR "$capture". Sets the `category` column.
    "severity": 2,            //   integer 0..4 (or numeric "$capture"). Out of range -> ignored.
    "src_ip":  "$src",        //   -> fields.src_ip  (PROMOTED to the src_ip column by the daemon)
    "dst_ip":  "$dst",        //   -> fields.dst_ip  (PROMOTED to the dst_ip column)
    "url":     "$url",        //   -> fields.url     (PROMOTED to the url column)
    "action":  "$act",        //   -> fields.action  (CIM outcome: see action_vocab)
    "fields":  { "proto": "$proto", "vendor": "acme" }  // arbitrary extended fields
  }
}
```

**`map` values**: a `"$nom"` string references a **capture** (from the `extract` steps); any
other string/number is a **literal**. A `$nom` reference that is **absent or empty** => the target is **left
as is** (never an empty field written, never a drop).

**Precedence** (ENRICH): `fields` **merges without overwriting** (a key already set by the collector wins);
`category`/`severity` are set by the **first** parser that produces them. `src_ip`/`dst_ip`/`url` are
written **into `fields`** then **promoted to columns** by the existing machinery (`fields_ip`/`fields_dst`/`fields_url`).

**Bounds** (RAM budget): ≤ 8 `extract` steps, ≤ 32 captures, value ≤ 256 chars, regex ≤ 1000 chars, message
truncated to 8192. `map.fields` keys: must pass `soql_ident_ok` (`[A-Za-z0-9_]`), otherwise ignored.
`csv` step: `delimiter` = a single ASCII character (neither a quote nor a line ending, default `,`), `columns` =
1 to 32 distinct, queryable names; a missing column writes nothing, an extra cell is
ignored. Out of reach, and stated rather than left unsaid: a line break inside a quoted cell (the
message IS one line — such an export must be rejoined upstream) and a UTF-16 export (to be converted to UTF-8).
Shipped example: `config.d/parsers/example-csv-firewall.json`.

---

## 3. Example — generic firewall (key=value) → CIM

Ingested message (`source=firewall`):

```
action=deny proto=tcp src=203.0.113.7 dst=198.51.100.2 dport=22
```

With the shipped example → CIM event: `category=firewall`, `severity=2`, column `src_ip=203.0.113.7`,
column `dst_ip=198.51.100.2`, `fields.action=deny`, `fields.proto=tcp`.

A **detection rule** then composes on top of it **without knowing the vendor** (see `docs/CIM.md`):
`search category=firewall action=deny | stats count by src_ip | where count > 20`.

---

## 4. Categories & vocabulary

`map.category` **should** target a category of the CIM taxonomy (`docs/CIM.md` §2). An
out-of-taxonomy value is **accepted but flagged** (`warn` at load time) — ENRICH, never SUPPRESS.
`map.action` **should** reuse the neutral outcome vocabulary (`success/failure/allowed/blocked/…`).
