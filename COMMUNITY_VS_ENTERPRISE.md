# Plume — Community vs Enterprise

Plume follows a **copyleft open‑core** model. The whole SOC is open and auditable under
**[AGPL‑3.0](LICENSE)** — that openness is the credibility of a security product. The community edition
is strong copyleft: if you modify Plume *or* run it as a network service, you must offer users the
**complete corresponding source** of your version under the AGPL. On top of that open core the business
is a layer of **separable enterprise add‑ons**, a **managed/hosted** offering, and **support** — and, for
organizations that cannot meet the AGPL's obligations, a **separate commercial license**.

> **[Forge](https://github.com/guatxlabs/forge)** (the offensive engine) is likewise **AGPL‑3.0** —
> copyleft fits a security tool. Plume is the *blue* half: we want it self‑hosted and studied widely,
> under a license that keeps every deployed derivative open.

## Community edition — AGPL‑3.0 (open, self‑hostable, copyleft)

Everything you need to run a complete SOC, solo, in a team, or across your own operations:

| Area | Included in the open core |
|---|---|
| **Ingest** | Agents (sh/systemd), Splunk‑HEC endpoint, generic `http_pull` connector, syslog/Fortinet, declarative parser DSL |
| **Search & dashboards** | SOQL (read‑only, injection‑safe), FTS5, saved panels/dashboards |
| **Detection** | Rules · SOAR‑lite playbooks · **Sigma import** (single + bulk) · **ATT&CK coverage matrix** |
| **Threat‑intel** | IOC store · STIX 2.1 import · match‑on‑ingest · TAXII 2.1 connector · bloom‑backed membership |
| **Risk (RBA)** | Per‑entity scoring · risk‑incident alerting |
| **Cases & response** | Incident cases · closed‑vocab, injection‑safe response with per‑platform executors · **hash‑chain ledger** |
| **Bring‑your‑own‑vendor** | CIM contract · parser DSL · connector descriptors · the extension SDK — *no vendor hardcoded* |
| **Crypto & security** | argon2id + RBAC · host‑bound tokens · **per‑tenant SQLCipher** · read‑only queries · hardened container |
| **Multi‑tenant mode** | The multi‑tenant *engine* (per‑tenant crypto, routing, RBAC groups→tenant) — opt‑in, in the open core |
| **Purple** | **Engagement Mode** + the Forge junction (correlate by ATT&CK) |
| **UI** | Bilingual FR/EN PWA, every IANA time zone |

## Enterprise add‑ons — commercial license

Separable modules and services aimed at **scale, teams, and compliance** — for organizations that need
them and want a vendor behind them:

| Add‑on | What it adds on top of the open core |
|---|---|
| **Scale store / HA** | Distributed backend (ClickHouse) + high‑availability / clustering, stateless ingest tier |
| **MSSP operations** | Fleet‑of‑tenants management console, onboarding at scale, cross‑tenant analytics & billing hooks |
| **Identity** | SSO/SCIM provisioning, composable advanced RBAC, per‑engagement grants |
| **Compliance** | SOC2/ISO evidence packs, WORM / legal‑hold retention, KMS/HSM key custody |
| **Premium connectors** | Maintained, supported vendor integrations beyond the open bring‑your‑own‑vendor path |
| **Managed & support** | Hosted/managed Plume, SLAs, priority support, deployment services |

## Principle

The **entire SOC stays open and auditable** — detection logic, crypto, ledger, response, the purple
loop. A user, an auditor, or a contributor can read and verify all of it. The commercial layer is
**value added around the edges** (scale, compliance, operations, hosting, support), built as modules
that plug into — never gate — the open core.

*This boundary is a starting proposal and will evolve with real adoption.*
