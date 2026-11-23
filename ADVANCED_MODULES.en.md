# Plume — Advanced modules (all open, separable, disabled by default)

[Français](ADVANCED_MODULES.md) | [English](ADVANCED_MODULES.en.md)

Plume is **entirely open source** under **[AGPL-3.0-or-later](LICENSE)** — the **whole product**,
without a paid edition, without a restricted feature and without any other license offered alongside. The complete SOC is open, and
every advanced capability described below is too: it lives in this repository, under the same license.

**Open does not mean without rules.** The AGPL is a strong copyleft:

- if you operate a **modified** Plume as a network service, you must offer the users of that
  service its **complete corresponding source** (AGPL §13);
- any distributed **derivative work** remains under **AGPL-3.0-or-later**;
- the **license text** and the **copyright and attribution notices** are preserved.

The freedom to read, run, modify and share comes **with** the obligations that maintain it; the
binding terms are those of [`LICENSE`](LICENSE). The shared library
[`guatx-core`](https://github.com/guatxlabs/core), which the daemon depends on, is under LGPL-3.0.

This document describes a **layering inside the open code**, not a commercial boundary. GuatX's
only commercial offer around Plume is **professional services** — deployment
assistance, support, managed hosting —, never a license on the code.

---

## The core — always present

Everything needed to operate a complete SOC, alone, as a team or in your own operations, with nothing
disabled:

| Domain | In the default build |
|---|---|
| **Ingestion** | agents (sh/systemd), HEC‑compatible endpoint, generic `http_pull` connector, syslog, declarative parser DSL |
| **Search and dashboards** | GXQL (read‑only, injection‑free), FTS5, saved panels and dashboards |
| **Detection** | rules · SOAR-lite playbooks · **Sigma import** (single and bulk) · **ATT&CK coverage matrix** · curated catalog ([`docs/DETECTION-CATALOG.md`](docs/DETECTION-CATALOG.md)) |
| **Threat-intel** | IOC store · STIX 2.1 import · matching at ingestion · TAXII 2.1 connector |
| **Risk (RBA)** | per‑entity score · alert on risk incident |
| **Cases and response** | incident cases · closed‑vocabulary response, per‑platform enforcers · **hash‑chained ledger** |
| **Governance** | legal-hold (locked retention, fail-closed), chain‑preserving ledger export, composable roles — see [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) |
| **Identity** | argon2id + RBAC, OIDC (Authorization-Code + PKCE), TOTP — see [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) |
| **Encryption** | SQLCipher active out of the box, host‑bound tokens, read‑only queries — see [`docs/CHIFFREMENT-COMPRESSION.md`](docs/CHIFFREMENT-COMPRESSION.md) |
| **Bring-your-own-vendor** | CIM contract · parser DSL · connector descriptors · extension SDK ([`docs/SDK.md`](docs/SDK.md)) |
| **Purple** | **Engagement Mode** (`PLUME_ENGAGEMENT_MODE` switch, off by default) and junction with [Forge](https://github.com/guatxlabs/forge), correlated by ATT&CK technique |
| **Interface** | bilingual FR/EN PWA, every IANA time zone |

If Plume fits on one node, the core is the whole product.

---

## The advanced modules — open, separable, disabled by default

These capabilities target **scale**, **work across several organizations** or particular
**identity and storage** requirements. They are built on top of the core, the core does not depend
on them, and each one is only engaged by an explicit gesture. For almost all of them, that gesture is a
**Cargo feature** (absent from the binary if it is not compiled), often paired with a **runtime
switch** that defaults to "off"; the default build compiles **none** of these features,
and the shipped container image compiles `ldap` and `cold_tier` (`ARG PLUME_FEATURES` of the
[`Dockerfile`](Dockerfile)), whose switches stay off as long as the operator does not set them.
**Multi-tenant is the exception**: it has no Cargo feature, its code is compiled into the default
build, and only the runtime switch `PLUME_MULTI_TENANT` (which defaults to `0`) engages it.

| Module | How to engage it | Documentation |
|---|---|---|
| **Columnar cold tier** (encrypted Parquet) | `cold_tier` feature + `PLUME_COLD_TIER=1` | [`docs/DESIGN-P10-echelle-2go.md`](docs/DESIGN-P10-echelle-2go.md) |
| **ClickHouse store** (one node; adapter compiled and tested, no runtime selection wired) | `clickhouse` feature; the daemon always serves SQLCipher, no switch moves to this store yet | [`docs/CLICKHOUSE-STORE.md`](docs/CLICKHOUSE-STORE.md) |
| **Distributed ClickHouse** (foundations, no execution path wired) | `clickhouse-ha` feature | [`docs/CLICKHOUSE-HA.md`](docs/CLICKHOUSE-HA.md) |
| **DuckDB store** (experimental; adapter compiled, no runtime selection wired) | `duckdb` feature; as with ClickHouse, the daemon always serves SQLCipher | [`docs/DUCKDB-STORE.md`](docs/DUCKDB-STORE.md) |
| **LDAP / AD directory** | `ldap` feature + directory configuration | [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) |
| **SAML 2.0** (service provider) | `saml` feature; without it, SAML login answers 501 | [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) §5 |
| **Backup repository on S3 object storage** | `s3_backup` feature + `s3://` destination | [`docs/DR-plume-restore.md`](docs/DR-plume-restore.md) |
| **AI advice** (remote inference, no network in CI) | `ai` feature + `PLUME_AI_*` | [`docs/AI-ML-DIRECTION.md`](docs/AI-ML-DIRECTION.md) |
| **Multi-tenant / MSSP** (one SQLCipher database and key per tenant, SCIM 2.0 provisioning) | compiled by default, no Cargo feature; `PLUME_MULTI_TENANT=1` | [`README.md`](README.en.md) |

The list of Cargo features is authoritative in `[features]` of [`daemon/Cargo.toml`](daemon/Cargo.toml).
What continuous integration actually checks for each one — compiled and tested, or only
type-checked — is stated in [`CONTRIBUTING.md`](CONTRIBUTING.md): an advanced module is not better
defended than what that table announces.

**Build invariant.** When not compiled, the Cargo features of these modules leave the default
build **byte‑for‑byte identical** to the core — proven by a constant test count (`EXPECTED_TESTS` in
`.github/workflows/ci.yml`). Multi-tenant, for its part, is in that build: what keeps it off is
`PLUME_MULTI_TENANT` left at `0`, not the absence of its code.

---

## Principle for contributors

Both layers are open under AGPL; the only question is where a capability belongs:

- it makes **detection, encryption, the ledger or response** stronger or more verifiable, or
  useful to a single operator → **it belongs in the core**;
- it is a matter of **scale, multi-tenant, a third‑party directory or distributed
  storage** → it is an **advanced module**, built separable, off by default, never a fork of the core
  nor a barrier that hides part of it.

Nothing is paid or held back: what is sold is services around the code, not the code.
