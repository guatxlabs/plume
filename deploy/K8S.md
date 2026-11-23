# k8s/k3s coverage — producing cluster telemetry, not just ingesting it

[English](K8S.md) | [Français](K8S.fr.md)

Goal: cover the cluster blind spot **by direct production** (not just ingestion), so that one day a
dedicated metrics/logs stack can be removed. Rule: **additive first, parallel run + parity check, then
removal**. Never break a dependent (an IPS or an on-call tool may read from the stack you
intend to remove — check before).

## Sensors (on the host, OFF by default)
- **kube-state** (`plume-kube-state`, 60s): `kubectl --no-headers` → metrics `kube_pods_running/pending/total`,
  `kube_restarts_total`, `kube_nodes_ready/total`, `kube_deploy_unavailable`,
  `secretstore_notready`/`secretstore_total` (secret stores — "Key rotation" below)
  + **events** on problems (CrashLoopBackOff/OOMKilled/Error/Failed/Evicted, node NotReady,
  degraded deployment, secret store not ready). No jq.
- **pod-logs** (`plume-pod-logs`, 60s): `/var/log/pods` **filtered** (`PLUME_POD_LOG_FILTER`, default error|fail|denied|…)
  and **bounded** (`PLUME_POD_LOG_MAX`=200) → events `source=k8s-log`. It is NOT an exhaustive aggregator:
  it is a security slice.

## Key rotation: the secret store (ExternalSecrets/Vault) has its own signal

**WHAT IT COVERS.** `kube-state` reads the STORES themselves — `clustersecretstores` and `secretstores`
from `external-secrets.io` — and publishes `secretstore_notready` **with its denominator**
`secretstore_total`, plus a **sev. 4 event that NAMES each store** and the `Ready` condition it has
actually published (its absence included: a store that asserts nothing is NOT ready). These resources
are **optional**: if absent, nothing is asserted; if the cluster API is silent, the measurement is declared
**ABSENT** — never converted into health. The daemon derives **ONE alert for the whole provisioning**
from it (family `heartbeat.magasin-de-secrets`, sev. 4), **without any rule having to be created** — never
one alert per secret: a sealed vault stops *all* the secrets of the cluster at once, and one alert
per consumer would be a second defect. A reading only counts as "healthy" if it carries, at the same instant,
"no store not ready" **and** "at least one store declared": uninstalling the operator or emptying
the namespace during the incident therefore does not silence the alert.

**WHY AT THIS RANK.** A vault left sealed for several days prevents the refresh of everything
it provisions: the episode that got this signal built (2026-08-26) involved twenty-seven
external secrets across all namespaces — certificate issuer, identity provider, ingress
tunnel, application firewall — that is, key rotation switched off cluster-wide, discovered
by typing an inspection command. **The SOC, for its part, was serving normally**: it runs with the secrets
**already injected**, so its working properly is NOT proof that provisioning is alive.

**WHAT ARMS IT, AND WHAT ITS SILENCE MEANS.** The only producer of both series is `kube-state`,
hence **`plume-kube-state.timer`** — and `bootstrap.sh` **explicitly disables it** at installation,
like the other sensors on this page. As long as it is not armed, no series arrives and the daemon
**concludes NOTHING — neither healthy nor sick**; that silence **does not mean "all is well"**. And nothing
reports it: no "silent sensor" dead-man's-switch covers `kube-state` (it would cry out on every
deployment outside a cluster, where this sensor has no reason to run), so its absence is absorbed
as a clean tick. **On a cluster: arm the timer below, otherwise this paragraph describes a
signal you do not have.**

## Enabling (on the host, once a reachable central is in place)
```
# cluster access: KUBECONFIG=/etc/rancher/k3s/k3s.yaml (default in the unit).
# RBAC: read pods/nodes/deployments, AND read `secretstores`/`clustersecretstores`
#        of the `external-secrets.io` group — without it, the provisioning signal described
#        above can NOT be produced. Fixed on 2026-08-30: this line named an
#        RBAC NARROWER than what the page arms, so that an operator applying it to the
#        letter would have obtained an ABSENT measurement — honest, but silent where they believed
#        they had armed an alert. An absent measurement is not a reassuring measurement.
sudo systemctl enable --now plume-kube-state.timer plume-pod-logs.timer
```
Cluster-native alternative: a **CronJob** in `deploy/k3s.yaml` (read-only ServiceAccount) that POSTs to `/api/ingest`.

## Safety-net rules (to create in ⚙️ once the metrics are present)
- `SELECT value FROM metric WHERE name='kube_deploy_unavailable' ORDER BY ts DESC LIMIT 1` `>` `0` → high
- `… name='kube_nodes_ready'` vs `kube_nodes_total` (node down)
- `search source=k8s severity>=3 | stats count` `>` `0` → CrashLoop/OOMKilled/NotReady
- (Secret store: **nothing to create here** — the alert is native, see "Key rotation".)
- (PV%: requires the kubelet metrics `kubelet_volume_stats_used_bytes` — to be added via a kubelet scrape, next tier.)

## Cutover order (method)
1. Set up kube-state + pod-logs (**additive**, nothing changes for the existing stack).
2. Deploy the central in-cluster (`deploy/k3s.yaml`), always-on.
3. Create the safety-net rules above.
4. **Parallel run + parity check** (same values, same searchable rows) — it is the only go/no-go.
5. Re-point the **dependents** of the old stack (everything that queries it) before removing it.
6. Only remove afterwards, and **never** a component that **enforces** something (firewall, bans,
   IdP, admission, secret management, backups): Plume **observes**, it does not replace
   enforcement.
