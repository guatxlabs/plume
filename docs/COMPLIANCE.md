# Compliance — POSTURE & COVERAGE (not certification) — #38

[English](COMPLIANCE.md) | [Français](COMPLIANCE.fr.md)

> **Honesty (hard invariant).** Plume exposes a **compliance posture / coverage**: which
> regulatory controls are **covered** (ingested SCA pass/fail) and which **detections** are
> mapped to a framework — all of it backed by the **integrity ledger** (Ed25519, tamper-evident). Plume **does
> not certify** compliance and does **not produce a certified audit**. Every label says "posture /
> coverage", never "compliant / certified".

## What this increment covers

1. **Compliance tags PER RULE.** A detection rule carries, next to its MITRE ATT&CK tag,
   regulatory framework tags (`rule.compliance`, schema **v88**, additive). Format: CSV of
   `cadre[:contrôle]` — e.g. `pci_dss:8.7,hipaa:164.312,nist_800_53:AU-2`.
   - **CONTROLLED framework vocabulary** (fail-closed): `guatx_core::cim::COMPLIANCE_FRAMEWORKS` =
     `pci_dss, hipaa, nist_800_53, gdpr, tsc, iso_27001, cis`. An out-of-vocabulary framework is **rejected**.
   - **FREE control** but with a bounded charset (`A-Za-z0-9 . _ - / ( ) espace`, ≤64) — stored as a value,
     never interpolated into SQL.
   - CRUD: API `POST /api/rules` + UI ("Compliance" field of the rule form). **Sigma** import:
     the doc's `tags` (namespaces `pci_dss.*`, `hipaa.*`, `nist.*`, `cis.*`, aliases included) are mapped.

2. **Posture dashboards PER FRAMEWORK** (seeded at boot, GXQL, "Conformité (posture)" view):
   **PCI DSS**, **HIPAA**, **NIST 800-53**. Each one filters the ingested SCA posture (#57,
   `category=posture`) down to the framework (`posture_framework=*<id>*`): overall pass/fail, failures per control,
   per host, detail. Read through the **masked GXQL path** (#45 field-filters + RBAC inherited).

3. **Posture rollup** — `GET /api/compliance/posture[?framework=<id>][&since=<epoch_s>]` (viewer+).
   Composes **(a)** SCA pass/fail **per control** (ingested posture, aggregated in Rust — no SQL concatenation)
   and **(b)** the **detections** that map this framework (`rule.compliance`). Without `framework`: a summary
   per framework. `GET /api/compliance/frameworks` lists the effective vocabulary.

4. **Posture report** — `GET /api/compliance/report?framework=<id>` (viewer+, read-only, exportable
   JSON). = rollup + **read-only evidence anchoring** on the ledger (chain head + latest signed
   checkpoint) + honesty disclaimer. **No write, no export of ledger entries.**

## Vendor-agnostic / extensible

The vocabulary is **DATA**, not a closed set hard-coded in. The base (`COMPLIANCE_FRAMEWORKS`, core CIM)
is **UNIONED** with an additional list from config:

```
PLUME_COMPLIANCE_FRAMEWORKS="soc2,dora"   # CSV, lowercase/_; added to the base, no rebuild
```

The IDs are **aligned with Wazuh** (`data.sca.check.compliance.{pci_dss,hipaa,nist_800_53,gdpr,tsc,cis}`,
see `ingest/endpoint.rs::flatten_compliance` -> `posture_framework`/`posture_compliance`): the ingested
posture and the rule tag **join on the same token**. Adding a framework on the ingestion side can also be done
through the declarative parser DSL (`config.d/parsers/`) by targeting `posture_framework`/`posture_compliance`.

## Mode 0 / byte-identical

- Migration v88 is **additive**: `rule.compliance` NULL for existing rows -> untagged rule -> scheduling
  selection (`run_due_rules`), coverage and `rules_list` **unchanged**.
- No compliance dashboard defined before this boot -> the seeds are idempotent (by name) and **EMPTY**
  as long as no SCA posture is ingested.

## Deferred (separate #38 subtasks — NOT built here)

- **WORM / legal-hold** retention.
- **Ledger export / streaming** (sensitive — separate security review).
- **SCIM** provisioning.
- **Composable / custom RBAC** roles.
