# Remplacer Prometheus / Loki / Grafana par le SOC (OBS)

Methode : **parallel-run** (le SOC recoit EN PLUS de l'existant) -> valider la **parite** ->
**decommissionner** Prom/Loki/Grafana (gain RAM). On garde **Alloy** comme collecteur, et
**CrowdSec** comme IPS (le SOC ingere, ne remplace pas).

## Pourquoi des noms "loki" / "remote_write" alors qu'on SUPPRIME ces serveurs ?
Ce ne sont PAS des references au branding : ce sont des **noms de PROTOCOLES** (formats de fil).
Le SOC expose des **endpoints de COMPATIBILITE** pour que tes collecteurs EXISTANTS (Alloy, promtail,
Prometheus, n'importe quel exporter) poussent vers lui **sans reconfiguration** — il suffit de changer
l'URL. C'est exactement ce qui permet de retirer les **serveurs** (Loki/Prometheus/Grafana) tout en
gardant la collecte. Le protocole `remote_write` / l'API push Loki existent dans tout l'ecosysteme,
independamment des serveurs Prometheus/Loki.

Deux familles de noms, a ne pas confondre :
- **Surface d'ingestion (compatibilite)** = nommee d'apres le PROTOCOLE accepte : `/loki/api/v1/push`
  (protocole Loki, chemin impose par les clients), `/api/metrics/write` (protocole remote_write, nom
  neutre cote SOC), `/api/metrics/prom` (format d'exposition Prometheus). -> permet le drop-in.
- **Surface PROPRE au SOC** = 100% GuatX, zero "loki/prom" : soql `metric`/`search`/`rate`/`timechart`,
  dashboards, `/api/query`. C'est ce que TU utilises au quotidien.

=> Oui : c'est un **utilitaire reutilisable** dans tout environnement qui parle deja Prometheus/Loki
(atout d'adoption), et NON, ca ne cree pas de dependance aux serveurs qu'on supprime.

## Metriques (OBS-1/2) — le SOC SCRAPE les /metrics
Sur un hote ayant acces aux endpoints `/metrics` :

`/etc/plume/prom-targets` (1 URL par ligne) :
```
http://127.0.0.1:9100/metrics    # node_exporter
http://127.0.0.1:8080/metrics    # kube-state-metrics (kubectl -n <votre-ns> port-forward svc/<kube-state-metrics> 8080:8080)
```
`/etc/plume/prom.conf` :
```
PLUME_CENTRAL=https://soc.exemple:7000
PLUME_TOKEN=...        # genere par : plume-daemon token prom
```
Puis : `sudo systemctl enable --now plume-prom-scrape.timer`

Requetes (PromQL -> soql) :
```
metric node_load1 | timechart span=1m avg(value)
metric node_network_receive_bytes_total by device | rate | timechart span=1m avg(rate) by device
metric kube_pod_status_phase phase=Running | stats count by namespace
```

### Variante recommandee pour le CLUSTER : Alloy POUSSE (remote_write)
Le scrape (pull) ne joint pas les ClusterIP internes. Pour TOUTES les metriques (hote + cluster),
ajoute un 2e `prometheus.remote_write` dans Alloy vers le SOC (EN PLUS de Prometheus) :
```alloy
prometheus.remote_write "soc" {
  endpoint {
    url          = "https://soc.exemple:7000/api/metrics/write"
    bearer_token = "..."   // plume-daemon token alloy
  }
}
```
puis pointer les `prometheus.scrape.*` existants aussi vers `prometheus.remote_write.soc.receiver`.
Le SOC accepte le **protocole remote_write** (protobuf+snappy ; `__name__` = nom de la metrique) sur
`/api/metrics/write` — nom neutre cote SOC (le "remote_write" est le protocole, pas le serveur Prometheus).
Aucun souci de reseau : c'est Alloy (in-cluster) qui pousse.

## Logs (OBS-3) — Alloy POUSSE vers le SOC (compatible Loki)
Dans la config Grafana Alloy, ajouter un `loki.write` vers le SOC (fan-out, EN PLUS de Loki) :
```alloy
loki.write "soc" {
  endpoint {
    url          = "https://soc.exemple:7000/loki/api/v1/push"
    bearer_token = "..."   // plume-daemon token alloy
  }
}
```
puis pointer les `loki.source.*` / `loki.process` existants aussi vers `loki.write.soc.receiver`.
Le SOC accepte le push **protobuf+snappy** (defaut Alloy) **ET** le JSON Loki.

Les logs deviennent cherchables dans le SOC :
```
search service_name=traefik level=error
search | timechart span=5m count by source
```

## Decommission (OBS-7)
Quand la parite est validee (memes valeurs metriques + memes logs cherchables) :
retirer Prometheus + Loki + Grafana (via **ArgoCD/Git**), garder Alloy repointe SOC.
Net : moins de RAM (kube-prometheus-stack + Loki = les gros consommateurs).
