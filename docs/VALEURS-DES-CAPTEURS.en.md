# What a sensor emits — the values, and what they mean

[Français](VALEURS-DES-CAPTEURS.md) | [English](VALEURS-DES-CAPTEURS.en.md)

**State: 📐 design.** The contract described here is **partly present in the shipped
producers** and **wired nowhere**: none of these declarations reaches the wire or the screen. This
document says what exists, what is missing, and why the gap cannot be closed by hand. Roadmap
keys: `P11.19-a` (nothing DECLARES what a sensor emits) and `P11.19-b` (the Rust
declarations are only HELD outside the shipped artifact).

---

## The problem, as it measures

An operator reads abbreviated values in the console — `collection-reducing`, `subsystem-absent`,
`illisible`, `@status` — that no surface explains. The explanation cannot be written by
hand, and it is not a matter of effort: it would be **wrong from the start**.

**The key is not the field, it is the (source, field) pair.** Measured on the repository tree on
2026-08-26: eleven shipped files of the inventoried extraction surface write an extended field with the
same name — `fields.type` — with **five disjoint value spaces**: collection reduction,
sensor availability, rule coverage, host kind, file kind. Three more Rust
producers write it outside that surface. An explanation indexed by the field's **name** would
therefore be right for one producer and wrong for the ten others.

**The set derives from the producer's predicate, not from its tool's alphabet.** The data
ACL sensor classifies file system entries with `find -printf %y`, whose alphabet
has eight letters; its own selection predicate lets only **two** through. Publishing
the tool's alphabet instead of the sensor's set promises the analyst values that
will never arrive.

**The common model declares only one vocabulary, and it is broader than each sensor.**
`config.d/cim/cim.v1.json` declares a neutral `action_vocab` of eleven words; the agent's Windows
producer, for its part, writes `fields.action` for only four outcomes (the other cases are either resolved from
the record, or **declared without an outcome**). The common vocabulary is a **superset**: it
says what a field can be worth in the product, never what **this** sensor can write.

---

## What already exists in the shipped producers

The operation is not absent — it is **partial and not derivable**. Several shipped sensors already
declare the closed set of a field they emit, each in the form of its own language:

| Form | Where it lives | Is the check in the **shipped** artifact? |
|---|---|---|
| Word table + `debug_assert!` | Rust producers (endpoint agent, mail and syslog collectors) | **no** — see below: the check is erased by the release build |
| `@(…)` table + `-notcontains` + `throw` | Windows collector | **yes** — the script IS the artifact; an invented value throws, it does not slip into the database |
| Comment block "closed vocabulary of `<champ>`" | the sensors' shell library | **no** — it is prose: a POSIX script offers no cheap failure site |

**THIS DOCUMENT CLAIMED THE OPPOSITE FOR THE RUST ROW, AND IT WAS WRONG.** It said "a value
outside the table brings the site down". Measured on 2026-08-26: the six Rust declarations are held by
`debug_assert!`, and the three `[profile.release]` of the producing crates do not set
`debug-assertions` — `cargo build --release` therefore erases these checks, and it is with `--release` that
the binaries are built. **The shipped producer has no check on these values.** The code
already said so in its own way ("in production the check is erased"); it was the document and the guard that
presented the erasure as a guarantee. This is not a wording fix: what a
producer must DO with a foreign word in production — fail, replace it with a sentinel, or
admit it in a field — is a product decision, taken in the Rust crates. It carries its open
key: `P11.19-b`.

These declarations are **derived, not listed**: the guard
[`check_a_producer_declares_the_values_it_emits.py`](../.github/scripts/check_a_producer_declares_the_values_it_emits.py)
recognizes them by their form, requires them to be **attached to a key the producer actually writes** into
the `fields` bag, and **NAMES the scope of each check** — `livrée` (shipped), `développement` (development), or refused
when the failure site cannot be read. That scope is itself derived: the guard reads the crate's
`[profile.release]`, so that setting `debug-assertions = true` there tomorrow makes it
reclassify without anyone rewriting a number. Two disjoint ratchets that can only
go down: the shell prose cannot grow, and neither can the number of checks that do not reach the
shipped artifact. A producer added tomorrow falls into its scope out of the box.

**They do not agree with each other, and that is deliberate.** The same field `fields.reason` is
declared by five shipped files with **three different cardinalities**: the shell library and
the Windows collector carry the full vocabulary; the agent removes from it the word that denotes an
operator switch, which none of its sources carries; the mail and syslog collectors keep only
the two words their reading can produce. Each one is right **for itself**. It is the
shortest demonstration that the key must be the pair: a single explanation of `reason`
would be wrong for three producers out of five.

**And even the best of them is a superset.** The Windows collector's outcome table
contains two **sentinels** — "no outcome to carry" and "outcome to be read from the record" —
which are never written into the bag: the field is only set for the remaining words. Declaring a
closed set is therefore not enough; one must declare **the one that is emitted**.

---

## What is missing, and exactly where

1. **Nothing links a declaration to its source.** The declarations live in the producers'
   files; the source name under which their events arrive is decided elsewhere (at
   call time). The (source, field) pair is reconstructed nowhere.
2. **Nothing serves these sets.** The completion schema route already serves a `values` object —
   it is **exactly** the surface that coverage would read — but its keys are **field
   names** (`category`, `action`, `severity`, `source`), not pairs. Extended fields do not
   appear there at all, for lack of an upstream that declares them.
3. **The inventory of collected fields does not talk about values.** It associates an extended field with **one**
   shipped file that emits it — its question is "does plume collect this field?", not "what can it
   be worth?". Of the eleven producers of `fields.type`, it cites only one: that is correct for its
   purpose, and unusable for this one.
4. **The console cannot tell what a sensor saw from what ingestion stamped.**
   The daemon itself sets a contract version key in the bag of **every** event, and the
   reception paths set others (protocol envelope metadata). On screen, they
   are displayed at the same rank as a sensor observation. The neighboring mechanism that keeps certain
   keys out of a facet list is a **literal list**: adding the next marker to it by hand
   is precisely the operation not to perform.

---

## The target shape

* **The sensor declares**, in its own file, next to the emission site: for each field
  it writes, the **closed** set of values it can take **and the meaning of each**. That
  set derives from the sensor's predicate, never from the alphabet of the tool it uses.
* **The declaration is held IN THE SHIPPED ARTIFACT**: a value outside the set does not slip into
  the database, and the check that prevents it is the one the production binary runs — not
  the one that only a development build would have kept. This is the gap measured today,
  carried by `P11.19-b`.
* **The daemon serves it** next to the existing vocabulary, **indexed by the (source, field) pair**
  — the same surface as `values`, one notch more precise. It also declares there, separately, the keys
  it **stamps itself**, derived from the ingestion's write sites and not from a list.
* **The console carries the explanation in a single place**: the value box that the cell
  factory already places on every cell. Where the declaration is missing, the screen **says so** — a blank
  would read as an obvious value.

Until this path exists, **no value explanation is written** in the console: a
guessed explanation is worse than none, because it makes people stop looking.
