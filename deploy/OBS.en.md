# Replacing Prometheus / Loki / Grafana with the SOC (OBS)

[Français](OBS.md) | [English](OBS.en.md)

Method: **parallel-run** (the SOC receives data IN ADDITION to the existing stack) -> validate **parity** ->
**decommission** Prom/Loki/Grafana (RAM savings). **Alloy** is kept as the collector, and
**CrowdSec** as the IPS (the SOC ingests, it does not replace).

## Why names like "loki" / "remote_write" when these servers are being REMOVED?
They are NOT references to branding: they are **PROTOCOL names** (wire formats).
The SOC exposes **COMPATIBILITY endpoints** so that your EXISTING collectors (Alloy, promtail,
Prometheus, any exporter) push to it **without reconfiguration** — changing the
URL is enough. That is exactly what makes it possible to remove the **servers** (Loki/Prometheus/Grafana) while
keeping the collection. The `remote_write` protocol / the Loki push API exist across the whole ecosystem,
independently of the Prometheus/Loki servers.

Two families of names, not to be confused:
- **Ingestion surface (compatibility)** = named after the PROTOCOL accepted: `/loki/api/v1/push`
  (Loki protocol, path imposed by the clients), `/api/metrics/write` (remote_write protocol, neutral
  name on the SOC side), `/api/metrics/prom` (Prometheus exposition format). -> enables drop-in.
- **The SOC's OWN surface** = 100% GuatX, zero "loki/prom": GXQL `metric`/`search`/`rate`/`timechart`,
  dashboards, `/api/query`. That is what YOU use day to day.

=> Yes: it is a **reusable utility** in any environment that already speaks Prometheus/Loki
(an adoption asset), and NO, it does not create a dependency on the servers being removed.

## Metrics (OBS-1/2) — the SOC SCRAPES the /metrics
On a host that has access to the `/metrics` endpoints:

`/etc/plume/prom-targets` (1 URL per line):
```
http://127.0.0.1:9100/metrics    # node_exporter
http://127.0.0.1:8080/metrics    # kube-state-metrics (kubectl -n <votre-ns> port-forward svc/<kube-state-metrics> 8080:8080)
```
`/etc/plume/prom.conf`:
```
PLUME_CENTRAL=https://soc.exemple:7000
PLUME_TOKEN=...        # minted on the central: plume-daemon token prom --relais  (multi-target scrape = RELAY)
```
Then: `sudo systemctl enable --now plume-prom-scrape.timer`

The tokens on this page are minted **on the central**, with the daemon already started once: on a missing
database, the subcommand creates it, and without a key, hence in plaintext
([`INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md#11-start-the-daemon-once-before-any-subcommand-that-writes-to-the-database)).
Form per mode (same for `token alloy --relais`):
```
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token prom --relais   # native host
docker compose exec soc plume-daemon token prom --relais                                     # Docker
kubectl -n soc exec deploy/soc -- plume-daemon token prom --relais                           # k3s
```
On a native host, `sudo` does not pass on the unit's `PLUME_CONFIG`: without it, the token is written into
`/var/lib/plume/db/plume.db`, a different database from the daemon's `soc.db`, and the central then refuses that
token.

Queries (PromQL -> GXQL):
```
metric node_load1 | timechart span=1m avg(value)
metric node_network_receive_bytes_total by device | rate | timechart span=1m avg(rate) by device
metric kube_pod_status_phase phase=Running by namespace | stats count by namespace
```
A metric label (`namespace`, `device`) is declared on the base, `metric <nom> by <label>`, before
it can be a key of `stats … by`: the compiler refuses a name that is neither a column nor a declared
label. For a "per hour" or "per day" series, it is `timechart span=1h` / `span=1d`, not `by hour`.

### Recommended variant for the CLUSTER: Alloy PUSHES (remote_write)
The scrape (pull) does not reach internal ClusterIPs. For ALL metrics (host + cluster),
add a 2nd `prometheus.remote_write` in Alloy towards the SOC (IN ADDITION to Prometheus):
```alloy
prometheus.remote_write "soc" {
  endpoint {
    url          = "https://soc.exemple:7000/api/metrics/write"
    bearer_token = "..."   // on the central: plume-daemon token alloy --relais (form per mode above; Alloy relays several hosts)
  }
}
```
then point the existing `prometheus.scrape.*` at `prometheus.remote_write.soc.receiver` as well.
The SOC accepts the **remote_write protocol** (protobuf+snappy; `__name__` = metric name) on
`/api/metrics/write` — a neutral name on the SOC side ("remote_write" is the protocol, not the Prometheus server).
No network concern: it is Alloy (in-cluster) that pushes.

## Logs (OBS-3) — Alloy PUSHES to the SOC (Loki-compatible)
In the Grafana Alloy config, add a `loki.write` towards the SOC (fan-out, IN ADDITION to Loki):
```alloy
loki.write "soc" {
  endpoint {
    url          = "https://soc.exemple:7000/loki/api/v1/push"
    bearer_token = "..."   // on the central: plume-daemon token alloy --relais (form per mode above; Alloy relays several hosts)
  }
}
```
then point the existing `loki.source.*` / `loki.process` at `loki.write.soc.receiver` as well.
The SOC accepts the **protobuf+snappy** push (Alloy default) **AND** Loki JSON.

Logs become searchable in the SOC:
```
search service_name=traefik level=error
search | timechart span=5m count by source
```

## Decommission (OBS-7)
Once parity is validated (same metric values + same searchable logs):
remove Prometheus + Loki + Grafana (via **ArgoCD/Git**), keep Alloy repointed to the SOC.
Net: less RAM (kube-prometheus-stack + Loki = the big consumers).
