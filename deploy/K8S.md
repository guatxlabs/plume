# Couverture k8s/k3s — produire la télémétrie cluster, pas seulement l'ingérer

But : couvrir l'angle mort cluster **par production directe** (pas seulement ingérer), pour pouvoir un jour
retirer une pile métriques/logs dédiée. Règle : **additif d'abord, run en parallèle + vérif de parité, puis
suppression**. Ne jamais casser un dépendant (un IPS ou un outil d'astreinte peut lire dans la pile que
vous comptez retirer — vérifiez avant).

## Capteurs (sur l'hôte, OFF par défaut)
- **kube-state** (`plume-kube-state`, 60s) : `kubectl --no-headers` → metrics `kube_pods_running/pending/total`,
  `kube_restarts_total`, `kube_nodes_ready/total`, `kube_deploy_unavailable` + **events** sur problèmes
  (CrashLoopBackOff/OOMKilled/Error/Failed/Evicted, node NotReady, deployment dégradé). Sans jq.
- **pod-logs** (`plume-pod-logs`, 60s) : `/var/log/pods` **filtré** (`PLUME_POD_LOG_FILTER`, défaut error|fail|denied|…)
  et **borné** (`PLUME_POD_LOG_MAX`=200) → events `source=k8s-log`. Ce n'est PAS un agrégateur exhaustif :
  c'est une tranche sécurité.

## Activer (sur l'hôte, après avoir un central joignable)
```
# accès cluster : KUBECONFIG=/etc/rancher/k3s/k3s.yaml (par défaut dans l'unit). RBAC : lecture pods/nodes/deployments.
sudo systemctl enable --now plume-kube-state.timer plume-pod-logs.timer
```
Alternative cluster-native : un **CronJob** dans `deploy/k3s.yaml` (ServiceAccount lecture seule) qui POST vers `/api/ingest`.

## Règles filet-de-sécurité (à créer dans ⚙️ une fois les métriques présentes)
- `SELECT value FROM metric WHERE name='kube_deploy_unavailable' ORDER BY ts DESC LIMIT 1` `>` `0` → high
- `… name='kube_nodes_ready'` vs `kube_nodes_total` (node down)
- `search source=k8s severity>=3 | stats count` `>` `0` → CrashLoop/OOMKilled/NotReady
- (PV% : nécessite les métriques kubelet `kubelet_volume_stats_used_bytes` — à ajouter via un scrape kubelet, palier suivant.)

## Ordre de bascule (méthode)
1. Poser kube-state + pod-logs (**additif**, rien ne change pour l'existant).
2. Déployer le central in-cluster (`deploy/k3s.yaml`), always-on.
3. Créer les règles filet ci-dessus.
4. **Run parallèle + vérif de parité** (mêmes valeurs, mêmes lignes cherchables) — c'est le seul go/no-go.
5. Re-pointer les **dépendants** de l'ancienne pile (tout ce qui la requête) avant de la retirer.
6. Ne retirer qu'ensuite, et **jamais** un composant qui **applique** quelque chose (pare-feu, bans,
   IdP, admission, gestion de secrets, sauvegardes) : Plume **observe**, il ne remplace pas
   l'enforcement.
