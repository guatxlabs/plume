# GXQL — the search language

[English](GXQL.md) | [Français](GXQL.fr.md)

GXQL (*GuatX Query Language*, **formerly "SOQL"**: same language, same syntax, only the name
changed) is a pipe-based language, inspired by SPL, **compiled into read-only SQL**. You write a
filter, chain stages separated by `|`, and each stage wraps the previous one in a
subquery.

```
search source=sshd "Failed password" | stats count by src_ip | where count > 5 | sort -count
```

This document describes **the grammar actually accepted**, its bounds, and — just as important —
**what it does not accept**, because several constructs that a reader coming from SPL believes are
available are not.

---

## 1. Where the compiler lives, and how to re-derive this document

**The compiler does not live in this repository.** It is in the shared `guatx-core` crate, resolved
through a git tag pinned in `daemon/Cargo.toml`, and it is the **only** compilation path:
there is no longer any fallback implementation or toggle.

```sh
grep -n 'guatx-core' daemon/Cargo.toml        # the source, and the pinned tag
```

What **is** in this repository, and makes the vocabulary verifiable without cloning the crate: the
description tables in `daemon/src/handlers/soql_meta.rs`, one-to-one mirrors of the
compiler's lists, which a test refuses to let become incomplete.

```sh
# the vocabulary, counted ON THE TREE rather than copied here
for B in DOC_COMMANDS DOC_STATS_FUNCTIONS DOC_EVAL_FUNCTIONS DOC_OPERATORS DOC_FIELDS; do
  printf '%-22s ' "$B"
  sed -n "/const $B/,/^];/p" daemon/src/handlers/soql_meta.rs | grep -c '^    ("'
done
```

**Read from the tracked tree on 2026-08-25**: 20 pipe commands, 8 aggregation functions,
15 `eval` functions, 8 filter operators, 14 described fields.

On a running instance, `GET /api/soql/schema` returns **the whole** vocabulary — commands,
functions, operators, keywords, fields, enumeration values and descriptions — in a single call.
It is what the console's search bar uses for its completion; it is also the source
to query rather than trusting a page.

---

## 2. The filter, before the first pipe

### 2.1 What can be written

| Form | Effect |
|---|---|
| `champ=valeur` | equality; `:` is an exact alias of it |
| `champ!=valeur` | inequality |
| `champ>valeur` `champ<valeur` `champ>=` `champ<=` | comparisons; **numeric** if the value is a number |
| `champ=~motif` | regular expression |
| `champ=~motif` · `champ:~motif` | a `~` at the **start of the value**, on `=` or `:`, also switches to a regular expression |
| `champ=val*` | wildcard: translated into `LIKE`, `*` becoming `%` |
| `champ!=val*` | negated wildcard |
| `champ in (a, b, c)` · `champ not in (…)` | membership; a **positive text** list compares case-insensitively |
| `*` alone | everything; no filter is emitted |
| a lone word | **full-text search** in `message` |

### 2.2 What can NOT be written — and this is the main trap

**There is only AND, and it is implicit.** All the conditions of the base filter are joined by
`AND`. There is:

- **no `OR`** — an `OR` typed in the bar becomes a full-text term, that is, a
  search for the word "OR" in the messages;
- **no prefix `NOT`** — negation is written `!=` or `not in (…)`;
- **no grouping with parentheses.** Parentheses do not group: they fall back into **full-text
  terms**. Writing `search (foo in (1,2))` produces the membership condition **plus** two
  text searches, one for `(` and the other for `)`. This is not an inference: the
  compiler carries this case in a comment, with this exact example, at the place that puts the
  leading grouping back into the residual text.

**The only place in the language where `and`, `or`, `not` and real parentheses exist is an
`eval` expression.** Hence the idiomatic pattern for expressing a disjunction:

```
search category=auth | eval suspect = severity>=3 or src_ip="203.0.113.7" | where suspect = 1
```

**`eval` does not accept a regular expression**: the `~` is refused there by name
(`eval : caractère non autorisé : '~'`). The line published here until 2026-08-26 carried one —
it did not compile. Measured, and corrected, by compiling: see §10.

### 2.3 A misspelt field name is REFUSED, not ignored

An identifier that departs from the expected form — `x-forwarded-for=…`, `http.status=…` — does not become
a silent filter on its last segment: the query is **refused**, the offending name is quoted **in
full**, and the message suggests quotes. This is a choice: a filter that applies to something other
than what was written is worse than an error.

### 2.4 Known limitation: a vertical bar inside a regular expression

**No alternation is possible inside a regular expression today.** The compiler
splits the query into stages on every top-level `|` **before** reading quotes: it
only knows square brackets `[ … ]` as grouping (`soql_split_pipes`, in the core). Writing
`search message=~"(refused|denied)"` therefore cuts the query into two stages, and the second is not a
known command. Quotes do not protect the bar.

What can be written instead, and what each form means:

| Form | Effect |
|---|---|
| `message=~"a\x7cb"` | the sequence `\x7c` is a **literal** vertical bar for the regular expression engine: it searches for the text `a\|b`, it is **not** an alternation |
| `message=~"a[\|]b"` | likewise — a character class that contains the bar; the splitting ignores what is between square brackets |
| an alternation (`a` **or** `b`) | **no form**: a character class only chooses one character, never a word. Write two searches, or a disjunction in an `eval` (§2.2) over comparisons without a regular expression |

There is no `match()` function either: the list of `eval` functions (§4.2) is closed, and
`where` only accepts a comparison (§3.1).

**What a pattern is allowed to cost.** A single builder compiles all the patterns of a query
(`champ=~motif`, `champ:~motif`, `| rex`): the one on the hot path **and** the one on the cold tier, and the Sigma
import (`|re`) validates its patterns with the same one. It bounds three things:

- **pattern length: 512 bytes** (bytes, not characters: an `é` counts as two). Beyond that,
  the query is refused with `400`, and the `error` field of the response carries the message
  "motif regex trop long (max 512)";
- **size of the compiled program: 1 MiB** per automaton. A short pattern can exceed it — `\w` is
  Unicode, `\w{100}` is enough. Also refused with `400`, with the engine's message:
  `Compiled regex exceeds size limit of 1048576 bytes.`;
- **the lazy DFA cache: 1 MiB**. Exceeding it refuses nothing: the search continues on a slower
  engine, without a message.

Each read connection keeps four compiled patterns per function (`=~` on one side, `rex` on the
other): a query that combines a few of them does not recompile them for every row. On the cold tier, a
refused pattern is not evaluated: the query falls back to the hot path, which returns the same refusal. At
Sigma import, a rule whose generated pattern exceeds 512 bytes, or that the builder refuses, is
reported and **not imported**.

**The cost of a regular expression grows with the window.** It is evaluated row by row by a
SQL function (Rust's `regex` engine, linear time) and no index serves it: over a large
window, it reads every row that the rest of the filter lets through. Narrow the window, and
filter first on a real column (`source`, `host`, `category`) or a hot field (§5.2):
`search source=sshd category=auth message=~"Invalid user"` only runs the pattern on the rows of
that source. **What the bounds do not hold**: an accepted pattern remains expensive over a large window,
and interactive queries share a semaphore (`PLUME_QUERY_CONCURRENCY`, default 3). A few
heavy queries launched together can therefore make every other search in the
console wait, until they finish or are interrupted by their time budget.

---

## 3. The twenty pipe commands

| Command | What it does |
|---|---|
| `stats` | aggregates: one or more measures, optionally grouped with `by` |
| `timechart` | time series: one measure per interval (`span=`) |
| `where` | filters **after** a pipe — see the restriction below |
| `sort` | sorts — see the restriction below |
| `head` / `limit` | keeps only the first N rows; a negative N is **refused** (SQLite would read it as "unlimited") |
| `rex` | extracts fields from a text with a regular expression with named groups |
| `fields` | restricts the columns returned |
| `table` | presents the listed columns |
| `rename` | renames a field (`champ as alias`) |
| `dedup` | keeps the first event per field |
| `top` / `rare` | most / least frequent values |
| `eventstats` | like `stats`, but attaches the aggregate to each row without reducing them |
| `rate` | rate per unit of time |
| `eval` | creates a field from an expression |
| `append` | appends the results of a `[search …]` subsearch |
| `join` | joins the stream to a subsearch on a common field |
| `mvexpand` | expands a multivalued field into one row per value |
| `lookup` | enriches through a lookup table (`… OUTPUT …`) |

Two **bases** exist: `search` (the default, on events) and `metric` (on observability
series). Four structural words accompany them: `by`, `span=`, `as`, `OUTPUT`.

An unknown command is **refused by name**, never ignored.

### 3.1 Two restrictions — and the trap is not the refusal, it is the absence of refusal

**MEASURED ON 2026-08-27 BY COMPILING** each form below with `guatx_core::soql::to_sql`, at
the tag pinned by `daemon/Cargo.toml`. The previous version of this section was established by
READING the stage compilers, and it was wrong on the point that matters.

- **`where` accepts only ONE scalar comparison, or ONE whole `in`/`not in` clause.** There is neither
  `and` nor `or` in a `where`.
- **`sort` sorts on only ONE field** — the token that follows the command, prefixed with `-` for
  descending.

An earlier version of this page invited the reader to understand "why their
`where a=1 and b=2` **fails**". **That is false, and false on the wrong side: nothing fails.**

| What is written after a pipe | What the compiler emits | What the operator gets |
|---|---|---|
| `where count > 5 and count < 100` | `WHERE "count" > '5 and count < 100'` | **no refusal** — the end of the line becomes a text literal, the comparison applies to a string, the answer is empty and looks complete |
| `where a=1 and b=2` | `WHERE json_extract(fields,'$.a') = '1 and b=2'` | likewise |
| `sort host severity` | `ORDER BY "host" ASC` | **no refusal** — the second field is silently dropped |
| `sort host,severity` | *nothing* | refused: `sort : champ invalide : host,severity` |

A second term is therefore only reported if it carries a **comma**: it is the comma that breaks the
form of an identifier, not the conjunction. A space gets through.

Conjunction is written with a **pipe** — `… | where a=1 | where b=2` — and that one is rendered
exactly: each stage wraps the previous one. Disjunction is written in an `eval` (§2.2).

These discrepancies were in the description tables (`daemon/src/handlers/soql_meta.rs`, served by
`/api/soql/schema`) and in the console's built-in help (`web/help_registry.js`, French **and**
English), not in the compiler: it was the displayed text that promised more than what the language
does. **Four served labels** carried the promise, not two.

#### The bound is declared HERE, and every surface that describes the command must carry it

The table below is not prose: a build witness READS it, and requires every
surface that describes the command to carry the phrase in its column. A surface that went back to
"one or more fields" would no longer carry "one field" and would turn continuous integration red.
Adding a row here arms the witness on one more command, without touching it.

| Command | What the language holds (measured on 2026-08-27) | Required phrase (fr) | Required phrase (en) |
|---|---|---|---|
| `where` | ONE scalar comparison, or ONE whole `in`/`not in` clause | `ni and ni or` | `no and, no or` |
| `sort` | ONE field, the token that follows the command | `un champ` | `one field` |

What this witness does not hold: it compiles nothing — it holds a **consistency of wording** between the
corpus, the daemon's declaration and the rendered help. The measurement itself remains dated (§10).

---

## 4. The functions

### 4.1 Aggregation — usable by `stats`, `eventstats` and `timechart`

| Function | Form | Note |
|---|---|---|
| `count` | **bare**, without parentheses | counts rows; the output alias is `count` |
| `count(champ)` `sum` `avg` `min` `max` | `f(champ)` | the output alias is the function name |
| `dc(champ)` | | cardinality — counts distinct values |
| `values(champ)` | | **distinct** values, concatenated, **bounded in length** |
| `list(champ)` | | values with duplicates, **bounded in length** |

`values` and `list` are capped: beyond the cap, the list is truncated. This is a deliberate memory
bound, not a bug — an aggregation that concatenates without bound is a simple way to push
the daemon out of its budget.

An unknown function is **refused by name**.

### 4.2 `eval` — the only expressive surface

`if`, `coalesce`, `ifnull`, `nullif`, `lower`, `upper`, `length`, `len`, `abs`, `round`, `min`, `max`,
`substr`, `replace`, `trim`.

This list **is** the allowlist: the compiler references it directly, it does not keep a
copy of it. The console's completion therefore cannot diverge from what the compiler accepts.

**Two bounds of `eval`, measured on 2026-08-27 by compiling:**

- **No regular expression**: the `~` is refused by name
  (`eval : caractère non autorisé : '~'`). A disjunction on a pattern must therefore be written differently.
- **`eval` does NOT resolve the keys of the JSON bag**, and it is the only stage in this situation. A name there is
  copied **as is** into the SQL: `… | eval r = dport * 2` emits `(dport * 2)`, not
  `json_extract(fields,'$.dport')`. On a **real column** (`severity`, `src_ip`, …) the query
  works; on a bag key it **compiles** — so `/api/soql/validate` answers `valid:true` — and
  **fails at preparation** with `no such column: dport`. Both halves were verified: the
  SQL returned by the compiler, then its preparation by SQLite on the schema of `db/schema.sql`.
  It is the same root cause as the absence of a name guard in `eval` (§2.3 applies to the other stages):
  `eval` is the only arithmetic surface, and validating a name there would forbid arithmetic.

---

## 5. The fields

### 5.1 Real columns and the JSON bag

The event schema distinguishes two kinds of field, and this is essential to understand
performance as much as security:

| Kind | Examples | Translation |
|---|---|---|
| **real column** | `ts`, `host`, `source`, `category`, `severity`, `src_ip`, `dst_ip`, `url`, `xff`, `message` | quoted identifier; the columns are **allowlisted** |
| **JSON bag key** | everything else | `json_extract(fields, '$.<nom>')`, with numeric conversion in a numeric comparison |

**To say it plainly: JSON bag keys are NOT allowlisted.** Any
identifier of valid form is extracted. What prevents injection is not the list, it is the
**form** required of the identifier (letters, digits, underscore — nothing else), the quoting of
generated identifiers and the escaping of literals.

### 5.2 "Hot" fields

About a dozen JSON keys carry an **expression index** in the database — `action`, `user`, `owner`,
`kind`, `ns`, `role`, `scope`, `verb`, `resource`, `operation`, `dir`, `risk`. Filtering on these
is much cheaper than on an arbitrary bag key.

This list exists in two places — the core and the daemon — and **a divergence does not compile**:
a constant assertion compares the two arrays at compile time. A contract held by the
compiler cannot drift.

### 5.3 Masking happens at compile time

When a field filter masks a column for the current role, the compiler **refuses** the
query instead of returning a hollow value — including for full text, which applies to `message`.
A query that returned a different result depending on the role would be an oracle; a
readable refusal is better.

---

## 6. The bounds

### 6.1 At runtime

| Bound | Lever | Default |
|---|---|---|
| time budget of an "automatic" query (panels, rules, pagination) | `PLUME_QUERY_BUDGET_MS` | `5000` ms |
| budget of an **interactive** query | `PLUME_QUERY_BUDGET_INTERACTIVE_MS` | `60000` ms |
| ceiling on returned rows | `PLUME_QUERY_MAX` | `5000`; a value outside `1`–`100000` falls back to `5000` (§6.4) |
| default and ceiling of `/api/search` | `PLUME_SEARCH_LIMIT` / `PLUME_SEARCH_MAX` | `100` / `5000` |
| simultaneous queries | `PLUME_QUERY_CONCURRENCY` | `3`, **shared** between `/api/query` and `/api/search` |
| permits reserved for light queries | `PLUME_QUERY_RESERVE_LIGHT` | `1`: heavy ones (`interactive:true`, export, Pivot) hold at most N − 1 permits |

Exceeding the budget **interrupts** the running query; exceeding the row ceiling
**truncates** it and reports it in the response statistics rather than returning a partial result
that would look complete. A query can also be **cancelled** by the client, by identifier.

### 6.2 At compile time, before any execution

The compiler bounds the input text, the number of stages, the size of the SQL produced — recomputed
**after each stage**, not only at the end — the interval of a `timechart`, and the depth of
subsearches. These bounds carry names prefixed `GUATX_SOQL_MAX_*`. A value that is present but
unreadable is an **error returned to the caller**, never a silent fallback.

### 6.3 Read-only, in layers

This is the central security property of the product, and it does not rest on a single control:

1. the connection is **opened read-only**;
2. `PRAGMA query_only=ON`;
3. the prepared statement is **rejected if it is not read-only**;
4. a SQLite **authorizer** refuses the password and token columns **even to an
   administrator**;
5. field filters are applied **at compile time** (§5.3).

**Clarification that corrects a wording that was too short**: the GXQL path **does not use bound
parameters** — it **embeds escaped literals** and only accepts identifiers of restricted
form. It is escaping and the form constraint, not parameterisation, that close
injection on this path. Bound parameters exist, but on `/api/search`. Likewise, "a single
`SELECT`" is not an explicit control: it is a **structural property** — the compiler
only emits one `SELECT` made of nested subqueries, cannot produce a `;`, and
preparation only compiles the first statement anyway.

### 6.4 What the ceiling cuts, and how to read everything

**`5000` is not a limit on what plume queries nor on what it counts.** It is the number of
**rows returned** in a table — and, under the cold tier only, the number of cold rows
copied by one read path (below).

`PLUME_QUERY_MAX` is `5000` by default and only accepts an integer from `1` to `100000`. **Any other
value — above `100000`, `0`, negative, unreadable — silently falls back to `5000`**: no refusal,
no line at startup. Writing `PLUME_QUERY_MAX=200000` therefore raises nothing at all.

The ceiling applies once the SQL has run: beyond it, reading stops, `truncated` is set in
the response statistics, and the console says so. Without the cold tier, it does not affect the computation:

- **an aggregate counts everything.** `search source=sshd | stats count` returns a single row, and that count
  covers all the events in the window, however many there are;
- **but groups are rows.** `stats count by src_ip` over more than `PLUME_QUERY_MAX` addresses
  returns the first groups and reports the truncation; each count returned remains complete. A
  `| sort -count | head 100` after the `stats` chooses which ones;
- **the table of raw rows is what gets cut.** To go through it entirely, **cursor**
  pagination on `/api/query` reads page by page without a counting ceiling (example below). It only
  applies to a query that **keeps its rows** (filter, `table`, `fields`, sort by date); for any
  other form, the response falls back to offset pagination, which is capped;
- **narrowing the window** (`from`, `to`) remains the safest way to read less.

**With the cold tier active** (binary built with `cold_tier`, `PLUME_COLD_TIER=1`) and a window
that reaches into the cold tier, the first bullet no longer always holds. One of the read paths copies
the window's cold rows into a temporary table, **at most `PLUME_QUERY_MAX` rows** (for
the full export, `/api/export`: at most `PLUME_QUERY_MAX` or its bound plus one row, whichever is larger,
see the end of this section), then runs the query on that copy. When the copy has reached that ceiling:

- a query whose **every stage is per event** — `where`, `head`, `limit`, `eval`, `rex`,
  `rename`, `table`, `fields`, and nothing else — returns true rows, in incomplete number, with
  `truncated`;
- any other query — an aggregate (`stats`, `timechart`, `top`, `rare`), but also `eventstats`,
  `rate`, `dedup`, `sort`, `join`, `append`, `lookup`, `mvexpand` — **computes or chooses over
  the whole set**, and it is **refused**: the response is a `422` whose body carries
  `"reason": "cold_truncated_aggregate"`, `"truncated": true`, `cold_rows_hydrated` and `cold_row_cap`
  (the rows copied and the ceiling), and an `error` message that names the stage at fault and the paths
  that escape the ceiling. **Never a number computed on a
  sample.**

Some forms do not take this path: a pre-aggregate (response marked `stats.approx`, hence
approximate) or the columnar engine, which reads the whole cold tier without copying it, may serve them
first; the refusal message details them. To get an answer where the refusal falls:

- **narrow the window** until the copy fits under the ceiling — the set read becomes
  complete again;
- **raise `PLUME_QUERY_MAX`**, up to `100000` and no further (above): the copied rows
  are held in memory, so it is the daemon's memory that pays. An export copies at least as many
  rows, and more when its bound (`PLUME_EXPORT_MAX`, or the request's `limit`) plus one
  row exceeds `PLUME_QUERY_MAX`; the refusal message names the ceiling that applied.

**Going through all rows by cursor.** The first call carries `"keyset": true`; the response returns
`next_cursor` (and `has_more`); the next call sends that `next_cursor` back **as is** in the
`"cursor"` field of the body, including the `espace` field when it is present. A `next_cursor` of `null` marks the last
page; `limit` (at most `10000`, default `100`) sets the size of a page.

```sh
curl -sS -u admin -H 'Content-Type: application/json' https://soc.example.org/api/query \
  -d '{"soql":"search source=sshd","from":1767225600,"to":1767312000,"keyset":true,"limit":1000}'
# then, for the next page, the value of next_cursor copied as is:
curl -sS -u admin -H 'Content-Type: application/json' https://soc.example.org/api/query \
  -d '{"soql":"search source=sshd","from":1767225600,"to":1767312000,"keyset":true,"limit":1000,
       "cursor":{"ts":1767311999,"id":48213}}'
```

`curl -u admin` prompts for the password without writing it into the history; `from` and `to` are
seconds since the Unix epoch.

`PLUME_QUERY_MAX` is read from the daemon's **environment** only, not from the configuration file:
on a host, it is set through a drop-in for `plume-daemon.service`.

**The full export** (`/api/export`) does not obey `PLUME_QUERY_MAX`: it only obeys its own bound,
`PLUME_EXPORT_MAX` (also read from the environment; default `50000`, and a value outside `1` to `100000` yields that default), or the request's `limit`
if it is smaller, cold tier included. When the export stops at that bound, the response
says so: `x-plume-truncated: 1`, a file name that carries `-TRONQUE-`, and `x-plume-export-borne`, which
is the bound applied. Without `x-plume-export-borne`, a cut reported by `x-plume-truncated` comes
from elsewhere: the pre-aggregate's ceiling; a cold copy stopped at its ceiling when a filter or a `head`
applied after the copy leaves fewer rows than the bound; cold data not read, which
`x-plume-cold-coverage: cold_coverage_unread` also reports.

---

## 7. The HTTP surfaces

| Route | Method | What it takes | What it returns |
|---|---|---|---|
| `/api/query` | `POST` | `{"soql": "…"}` (+ `from`, `to`, `interactive`, `qid`, pagination) | `{"columns":[…], "rows":[[…]], "stats":{…}}` |
| `/api/search` | `GET` | `q=` and a few ad-hoc tokens | `{"results":[…]}` |
| `/api/soql/schema` | `GET` | — | the whole vocabulary |
| `/api/soql/validate` | `POST` | `{"soql": "…"}` | `{"valid":true}` or `{"valid":false,"error":"…"}` |
| `/api/soql/templates` | `GET` | — | the template library |
| `/api/export` | `POST` | like `/api/query` | export |
| `/api/cancel` | `POST` | `{"qid": "…"}` | cancels a running query |
| `/api/ds/query` | `GET`/`POST` | GXQL over HTTP-JSON | for Grafana — see [`DATASOURCE.md`](DATASOURCE.md) |

Two points not to confuse:

- **`/api/search` is not GXQL.** It is a search bar with an ad-hoc parser, backed by the
  full-text index, which accepts a few tokens (`limite`, regular expression, `champ:valeur`
  with wildcard). It **always returns `200`**, even on an engine error: the `error` field of the
  response then carries a fixed phrase, never the engine's text.
- **`/api/soql/validate` does not touch the database.** It compiles and returns its verdict — no handle,
  no execution. It is the call the console makes while typing.

**What `error` carries when a query is not served.** Two sources, not to be confused:

- **the GXQL compiler's refusal** (unknown command, function or field, masked field, bound
  exceeded): `400`, and `error` carries the compiler's message, as is. The compiler
  executes nothing and reads no event, but it expands macros **before** parsing the
  query: its message quotes the caller's query (the offending name they wrote), the
  closed vocabulary of the language and, when the query calls a macro, an excerpt of the **body of
  that macro** (a knowledge object, readable through `GET /api/knowledge`). This is intended: without it,
  a typo would be impossible to diagnose;
- **a failure at execution**: the class is decided by the engine's code, and `error` carries a
  fixed phrase per class — unreadable database storage or busy database as `503`, engine refusal
  (syntax of the compiled SQL, authorizer, pattern) as `400`, product phrase (cancellation, budget,
  read-only, memory, refused pattern) byte for byte as `400`. The engine's text never goes to the
  client; the operator finds the class and the code in the daemon's log (`[query] WARN`).
  `/api/rule-test` (testing a rule) serves the same phrases, but keeps its `200` `{error, sql}`.

**Raw SQL** (`{"sql": …}` on `/api/query`) is reserved for administrators, and it remains subject
to the authorizer: see the note in the [`README`](../README.md#security-built-in).

Technical identifiers remain `soql` — route `/api/soql/*`, JSON key `soql`, column
`is_soql`, module `guatx_core::soql`, folder `docs/soql-templates/`. It is a build identifier,
not a user-facing label.

---

## 8. The shipped templates

`docs/soql-templates/templates.json` contains **16 templates** (read from the tree on 2026-08-25),
each with `id`, `title`, `keywords` (French and English) and `soql`:

```sh
python3 -c "import json;d=json.load(open('docs/soql-templates/templates.json'));print(len(d['templates']));print([t['id'] for t in d['templates']])"
```

They are **embedded in the binary** through `include_str!` and served as is — no file read
at runtime. Two consequences: the folder must be present **before** compilation (the
`Dockerfile` copies it for that reason alone), and **each template is proven to compile by a test
in the suite**. A template that no longer compiled would turn continuous integration red, not
the user's screen.

---

## 9. Why the language is closed

**A closed language is an attack surface that can be enumerated.** The vocabulary fits in five
short lists; what is not in them is refused **by name**. This is what makes it possible to expose a
search to a *viewer* role without exposing the database, and it is also what makes the project of
translation from natural language possible: a text produced by a model is harmless if it must
pass through a closed compiler before reaching the engine.

**The price is written down**: several SPL constructs do not exist here — no disjunction in
the filter, no grouping, no multi-field sort, no `transaction`, no percentile. A
specification document in the repository promises some of them: these are wishes, not capabilities.
What the Sigma importer cannot translate faithfully is **reported, never guessed** —
[`SIGMA-IMPORTER.md`](SIGMA-IMPORTER.md) gives the exact matrix.

**The compiler lives in a shared crate** because two halves of the same suite must
speak the same language. The contribution rule that follows from this is written in
[`../CONTRIBUTING.md`](../CONTRIBUTING.md): it is fixed in place, never duplicated.

---

## 10. What was not verified

- **No query was run against an instance.** What this page says about the grammar
  rests, for the most part, on a **COMPILATION**: on 2026-08-27, every query then
  published here, and every form in the table of §3.1, was passed to `guatx_core::soql::to_sql`
  (tag pinned by `daemon/Cargo.toml`) and the SQL returned was recorded. It is this pass that
  showed that an example on this page did not compile (§2.2) and that its §3.1 announced a failure that
  does not happen. The runtime BOUNDS (§6.1, §6.4) and the response forms (§7) remain, for their part,
  established by reading the handlers.

  The queries this page publishes can be listed — **on the tracked tree: 6 lines**:

  ```sh
  grep -noE '(^|`)(search|metric) [^`]*' docs/GXQL.md
  ```

  **Only three were compiled** on 2026-08-27: the one in the header and the two in §2.2. The
  other three were added after that reading and **were not compiled** — the two in §2.4 and
  the one in §6.4. They were **reread** against the compiler source at the pinned tag: the
  splitting into stages, the base filter and the command dispatch. By that reading, the
  alternation query of §2.4 fails on its second stage ("commande GXQL inconnue"), as the
  section announces, and the other two produce SQL. Also **reread, not compiled** in the same
  way: the forms in the table of §2.4, the stages quoted alone in §6.4 and the query in the
  cursor call example.

  This command does **not** see a query split over two lines, nor a query that does not start
  with `search` or `metric` (a stage quoted alone, `| stats count by host`), nor a query written
  inside a JSON body. Nor does it say whether they compile: nothing in this repository compiles them,
  since the compiler lives in an external crate (§1). **This page is therefore held by a dated
  reread, not by a ratchet.**
- The **compiler's body** belongs to a crate external to the repository: the counts published in §1
  are derived from the **mirrors** present here, which a test in the suite keeps equal to the core's lists.
- The **acceptance rate** of the Sigma importer on the complete SigmaHQ repository **is not measured**,
  and no figure for it is published until the bench has been run.
