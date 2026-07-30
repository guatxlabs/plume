# Security Policy

Plume is a **feather-light SOC/SIEM**: it ingests security telemetry, stores it encrypted,
and serves an API + UI + detection engine over a **closed GXQL read grammar** with
**field masking as a single choke-point**. Its value depends on that read path staying
sealed and on secrets never leaking into what it stores or serves. A flaw in those
controls is a serious bug, and we want to hear about it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through **GitHub Security Advisories** — the "Report a vulnerability" button on
the repository's **Security** tab. It keeps the report and the fix coordinated and private, and it
is the only reporting channel we monitor.

Please include: affected version/commit, a description, reproduction steps or a PoC, and the
impact. The advisory thread is private, so you can attach details there directly.

We aim to **acknowledge within 3 business days** and to agree on a remediation timeline with
you. We practise **coordinated disclosure** and will credit you (unless you prefer to remain
anonymous) once a fix is released.

## What is in scope

A security bug in Plume is anything that breaks the read-path seal, escapes an isolation
boundary, or leaks secrets. In particular:

- **Masking / `soql_field` bypass** — any query path that returns a masked column
  (password hashes, token hashes, secrets) unmasked, or that reaches raw rows before the
  `soql_field`/`soql_filter_field` choke-point applies masking.
- **Raw-SQL exposure** — an unprivileged (non-admin) caller reaching a raw-SQL surface, or
  a raw-SQL path escaping the SQLite authorizer's DENY on protected columns (e.g. reading
  `user.hash` / `token.token_hash` even as admin).
- **RBAC / authorizer bypass** — an `editor` (or lower) reaching an admin-only mutating
  route (password reset, mode/ban/kill, playbook arming), or a fail-open in the RBAC gate.
- **Tenant isolation break** — reading another tenant's events/findings/secrets under
  multi-tenant mode (`PLUME_MULTI_TENANT`), including via the GXQL surface or a shared key.
- **Secret leakage** — DB keys, session credentials, API/connector keys, or SSO secrets
  escaping into an event, a rollup, a report, a log line, or an API response.
- **AuthN/AuthZ** — authentication bypass, privilege escalation, cross-tenant IDOR.
- **Injection / RCE** in the daemon (SQL, path traversal, deserialization, decompression
  bombs on the ingest/OTLP paths, command execution).

## What is NOT a vulnerability

- **Running Plume against infrastructure you do not own or are not authorized to monitor.**
  That is the operator's responsibility, not a flaw in Plume.
- **Deployment-hardening trade-offs that Plume documents explicitly**, together with the opt-in
  mitigation that closes them (the docs state the trade-off where it applies). Report one only if
  you can **defeat the documented mitigation** or show a *new* impact beyond what is stated.

## Supported versions

Plume is pre-1.0 and has **no tagged release yet**. Security fixes land on `main`, which is the
only thing maintained, so please cite a `main` commit when you report.

| Version | Supported |
|---------|-----------|
| `main` | ✅ |
| tagged releases | none exist yet |

This section will name supported versions once tags exist — not before. Announcing per-version
support while no version exists would be a false promise, and would send a reporter looking for a
release number they cannot find.

## Hardening & audits

Plume ships a documented security model and a CI pipeline that runs `cargo audit` and secret
scanning. The core controls — the closed GXQL compiler, field masking as a single
choke-point, the fail-closed RBAC gate + SQLite DENY authorizer, per-tenant crypto isolation,
and mode-0 byte-identical feature gating — are covered by tests and have been adversarially
reviewed.
