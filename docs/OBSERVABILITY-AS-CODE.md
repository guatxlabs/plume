# Observability-as-code (#55)

Declare your whole SOC configuration — not just detection content — as versioned files under
`config.d/`, GitOps it alongside the ArgoCD deploy model, and let plume converge to it at boot.

This extends the **same** `config.d` overlay mechanism that already provisions detection content
(parsers / declarative parsers / rules / Sigma / playbooks — see `daemon/src/overlays.rs`) to the
**config objects** built more recently. The loader lives in `daemon/src/overlays_oac.rs` and mirrors
the rule/parser overlay pattern exactly: **idempotent, keyed by `name`, `managed=1`, validate-or-skip,
override-safe, prunable**.

> **Mode-0 guarantee.** Ship *no* new overlay files and behaviour is byte-identical: the loader is a
> strict no-op when the subdirectories are absent, and the only schema change (migration **v93**) adds a
> `managed` column that defaults to `2` ("ad-hoc UI") on every existing row. No object becomes managed
> until a file declares it.

---

## 1. File layout

Everything lives under `${PLUME_CONFIG_DIR}` (default `/usr/local/share/plume/config.d`, baked into the
image — the pod runs `readOnlyRootFilesystem`, so overlays are shipped *in the image*, not on a host
path). Each object type has its **own subdirectory**; each `*.json` file declares **one** object,
identified by its `name`:

```
config.d/
├── parsers/                 # (existing) regex + declarative CIM parsers
├── rules/                   # (existing) detection rules  — now also carry a `compliance` tag (#38)
├── sigma/                   # (existing) Sigma YAML → rules
├── playbooks/               # (existing) detection → response
│
├── dashboards/              # dashboards + their panels           → tables `dashboard` + `panel`
├── library-panels/          # reusable panels (#54)               → table `library_panel`
├── notifiers/               # alert channels                      → table `notifier`
├── notification-policies/   # alert routing                       → table `notification_policy`
├── destinations/            # event forward sinks (#50)           → table `destination`
├── connectors/              # external source connectors (#3a)    → table `connector`
├── index-policies/          # named indexes / retention (#49)     → table `index_policy`
└── field-filters/           # per-field masking (#45)             → table `field_filter`
```

> The `config.d/` shipped in this repo contains **only** benign detection examples. OAC example files
> are documented here (below) and deliberately **not** shipped, so the stock image forwards nothing and
> alerts nowhere out of the box.

### Example objects

`dashboards/soc-overview.json`
```json
{
  "name": "SOC Overview",
  "panels": [
    { "title": "High-sev events by host", "is_soql": true, "viz": "table",
      "query": "search severity>=3 | stats count by host" },
    { "title": "5xx by source IP (1h)", "is_soql": true, "viz": "timeseries", "window_s": 3600,
      "query": "search source=web status>=500 | stats count by src_ip" }
  ]
}
```

`notifiers/slack-soc.json` — **secret referenced, never inline** (see §3):
```json
{ "name": "Slack SOC", "kind": "slack", "config": { "webhook_url": "env:PLUME_SLACK_WEBHOOK" } }
```

`destinations/splunk-hec.json`
```json
{ "name": "Splunk HEC", "type": "hec", "enabled": true,
  "endpoint": "https://splunk.corp:8088/services/collector",
  "config": { "hec_token": "vault:secret/data/plume/splunk#hec_token" },
  "filter": { "min_severity": 2 } }
```

`connectors/defender.json` — the credential lives in the dedicated `secret` slot, via `secret_ref`:
```json
{ "name": "MS Defender", "type": "defender",
  "config": { "azure_tenant": "…", "client_id": "…" },
  "secret_ref": "env:PLUME_DEFENDER_CLIENT_SECRET" }
```

`index-policies/staging.json`, `field-filters/mask-username.json`, `rules/…json`:
```json
{ "name": "staging", "retention_days": 30 }
{ "name": "Mask username for viewers", "field": "user", "action": "mask", "role": "viewer" }
{ "name": "Brute force", "is_soql": true, "query": "search source=sshd fail | stats count",
  "op": ">", "threshold": 10, "mitre": "T1110", "compliance": "pci_dss:8.7" }
```

---

## 2. The managed-vs-user model

Every overlay-able table carries a `managed` flag with the **repo-wide** semantics already used by
`rule` / `parser` / `index_policy`:

| `managed` | meaning | UI editable? | pruned? |
|-----------|---------|--------------|---------|
| `0` | builtin / seed | disable-only | never |
| `1` | **overlay (config.d, source git)** | **no — locked** | yes, when its file is removed |
| `2` | ad-hoc UI (CRUD) | yes | never |

- **Loading** (boot, after all `seed_*`, inside `load_overlays_dir`): each object is UPSERTed **keyed by
  `name`** with `managed=1`. Re-running gives the same state (idempotent).
- **Override-safe.** An overlay **never clobbers a user object**: if a row of the same `name` already
  exists with `managed=2`, the loader **skips it and warns** (rename one of the two). Conversely, the UI
  refuses to delete/mutate a `managed=1` object (`delete_managed_row_tx` returns `409` — "managed by
  config.d, remove it in git"). A `managed=1` lock is surfaced in the UI exactly like a managed rule.
- **Lifecycle / prune (#26).** Removing an overlay file leaves its `managed=1` row behind (load only
  UPSERTs). `POST /api/config-overlays/prune` (admin-only, audited) deletes `managed=1` rows no longer
  backed by a file — and **only** those (never `managed=0`/`2`). Managed panels of a pruned dashboard are
  swept too. Idempotent.
- **Validation.** Overlay content is checked against the **same validators the API uses** before
  insertion — `compile_panel_sql` (dashboards/library panels), `dest_type_ok`/`dest_endpoint_ok`/
  `DestFilter::validate` (destinations), `safe_url`/kind allowlist (notifiers), per-type config shape +
  `env_slug_ok` (connectors), `env_id_ok` + retention clamp (index policies), `validate_field` + action/
  role allowlists (field filters), `parse_matchers` field-allowlist (notification policies),
  `norm_mitre` + `norm_compliance` (rules). A bad object is **warned and skipped — never inserted, never
  a boot crash** (validate-or-skip, mirroring the existing loaders).

---

## 3. Secrets — the honest, load-time indirection

**A committed overlay must never contain a plaintext secret.** Notifiers, destinations and connectors
carry auth. The overlay references the secret **indirectly**; the loader resolves it **at boot** and
writes only the resolved value into the (SQLCipher-encrypted, read-pool-denied) `secret`/`config`
column. If an overlay embeds an inline secret, the **whole object is rejected — fail-closed**.

### Reference schemes (resolved at load)

| scheme | resolves to | typical source |
|--------|-------------|----------------|
| `env:NAME` | environment variable `NAME` | k8s `Secret` → env, sidecar-injected |
| `file:/path` | file contents (trimmed) | k8s `Secret` mounted as a file, Vault-Agent template |
| `vault:PATH` | env var named by `PATH` uppercased, non-alnum→`_` | **Vault-Agent projection** (see boundary) |

A **missing** reference (env var absent, file unreadable) rejects the object — you never get a silent
object with an empty credential.

### What counts as "inline secret"

- **Connectors:** the credential must come via top-level **`secret_ref`**. A literal top-level `secret`
  key → rejected. `config` (non-secret identifiers only) is scanned defensively too.
- **Notifiers / destinations:** any secret-bearing key inside `config` (`token`, `pass`, `webhook_url`,
  `routing_key`, `auth_header`, `hec_token`, `client_secret`, `*_secret`, `*_token`, `*_key`, …) must be
  a reference; a plaintext value → rejected. URL/endpoint keys (`*_url`, `*_uri`, `*_endpoint`) are
  treated as **non-secret** so an OAuth `token_url` is not a false positive. For a token embedded in a
  webhook/endpoint URL itself, use `url_ref` / `endpoint_ref` (resolved the same way).

The detector is intentionally conservative (exact-key + suffix, endpoints excluded) to catch real leaks
without forcing indirection on plain usernames or endpoint URLs.

### RBAC & audit

Overlay loading is a **system action** (boot / reload) — no user context. Prune is admin-only and
ledgerised (`audit_config_change`, severity 3) exactly like the existing overlay prune.

---

## 4. Honest boundary (what this does *not* do)

- **Vault is not queried directly at load.** The loader has no Vault session at boot; `vault:` refs are
  resolved through the **standard Vault-Agent projection** (env/file) that the rest of plume already
  uses. Point `vault:` at a secret your Vault-Agent renders — the ref documents intent; the projection
  does the fetch. Prefer `env:`/`file:` when you can.
- **Secret scanning is top-level, key-name-based.** It resolves/rejects secret-*keys*; it does not
  entropy-scan arbitrary free-text values. A secret hidden in a non-secret-named field would not be
  caught — keep credentials in the documented slots.
- **UI edit-lock depth.** The destructive path (delete) is enforced for managed objects
  (`delete_managed_row_tx`, `409`) and `index_policy` has full CRUD-lifecycle wiring. Per-field *update*
  hardening across every legacy handler is surfaced via the `managed` flag (the UI renders the lock) but
  is not yet a hard server refusal on every mutate route — tracked as a follow-up.
- **Notification-policy identity** is the new `name` column (v93); policies created in the UI stay
  `name=''` and never collide with a named overlay.
- **Not env-scoped.** Config objects are tenant-wide by nature (like rules/dashboards), consistent with
  the existing overlay model.

---

## 5. Terraform provider — design (NOT built)

**Design intent only — no provider is shipped in this change.**

A `terraform-provider-plume` would let teams that already standardise on Terraform manage a plume SOC as
HCL resources instead of hand-authored JSON files, targeting the **same** validated, `managed`-flagged
objects this loader provisions. The natural shape:

- **Resources** mirror the overlay object types 1:1 — `plume_dashboard`, `plume_library_panel`,
  `plume_notifier`, `plume_notification_policy`, `plume_destination`, `plume_connector`,
  `plume_index_policy`, `plume_field_filter`, `plume_rule`. Each maps to the existing admin CRUD API
  (create/update/delete), which already validates identically to the overlay loader — so the provider
  reuses the server's validation rather than re-implementing it.
- **Secrets** stay first-class: secret attributes are `sensitive = true` and accept the **same
  `env:`/`file:`/`vault:` reference strings**, OR bind to a `vault_generic_secret` / `data.aws_*` data
  source and pass the *reference*, never the literal, so state never holds a plaintext credential. The
  provider should refuse to persist an inline secret, matching the loader's fail-closed rule.
- **`managed` reconciliation.** A provider-managed object would be written as `managed=1` (or a new
  `managed=3` "IaC" marker if we want to distinguish Terraform from git-file overlays), so Terraform
  `destroy` and the config.d prune share one lifecycle model and never fight the UI's `managed=2`.
- **Drift** is Terraform's native strength: `terraform plan` diffs desired HCL against the live object,
  surfacing out-of-band UI edits — the same governance angle as the prune endpoint, but continuous.

The **file-based `config.d` overlay is the primary, dependency-free path** (works with plain git +
ArgoCD, no extra tooling); the Terraform provider is an optional ergonomics layer for Terraform shops,
to be scoped as its own deliverable.
