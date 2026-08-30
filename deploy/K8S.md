# Couverture k8s/k3s — produire la télémétrie cluster, pas seulement l'ingérer

But : couvrir l'angle mort cluster **par production directe** (pas seulement ingérer), pour pouvoir un jour
retirer une pile métriques/logs dédiée. Règle : **additif d'abord, run en parallèle + vérif de parité, puis
suppression**. Ne jamais casser un dépendant (un IPS ou un outil d'astreinte peut lire dans la pile que
vous comptez retirer — vérifiez avant).

## Capteurs (sur l'hôte, OFF par défaut)
- **kube-state** (`plume-kube-state`, 60s) : `kubectl --no-headers` → metrics `kube_pods_running/pending/total`,
  `kube_restarts_total`, `kube_nodes_ready/total`, `kube_deploy_unavailable`,
  `secretstore_notready`/`secretstore_total` (magasins de secrets — « Rotation des clés » ci-dessous)
  + **events** sur problèmes (CrashLoopBackOff/OOMKilled/Error/Failed/Evicted, node NotReady,
  deployment dégradé, magasin de secrets pas prêt). Sans jq.
- **pod-logs** (`plume-pod-logs`, 60s) : `/var/log/pods` **filtré** (`PLUME_POD_LOG_FILTER`, défaut error|fail|denied|…)
  et **borné** (`PLUME_POD_LOG_MAX`=200) → events `source=k8s-log`. Ce n'est PAS un agrégateur exhaustif :
  c'est une tranche sécurité.

## Rotation des clés : le magasin de secrets (ExternalSecrets/Vault) a son propre signal

**CE QU'IL COUVRE.** `kube-state` lit les MAGASINS eux-mêmes — `clustersecretstores` et `secretstores`
de `external-secrets.io` — et publie `secretstore_notready` **avec son dénominateur**
`secretstore_total`, plus un **event sév. 4 qui NOMME chaque magasin** et la condition `Ready` qu'il a
réellement publiée (son absence comprise : un magasin qui n'affirme rien n'est PAS prêt). Ces ressources
sont **optionnelles** : absentes, rien n'est affirmé ; API du cluster muette, la mesure est déclarée
**ABSENTE** — jamais convertie en santé. Le daemon en tire **UNE alerte pour tout l'approvisionnement**
(famille `heartbeat.magasin-de-secrets`, sév. 4), **sans qu'aucune règle n'ait à être créée** — jamais
une alerte par secret : un coffre scellé arrête *tous* les secrets du cluster à la fois, et une alerte
par consommateur serait un second défaut. Un relevé ne vaut « sain » que s'il porte, au même instant,
« aucun magasin pas prêt » **et** « au moins un magasin déclaré » : désinstaller l'opérateur ou vider
le namespace pendant l'incident n'éteint donc pas l'alerte.

**POURQUOI À CE RANG.** Un coffre resté scellé plusieurs jours empêche le rafraîchissement de tout ce
qu'il approvisionne : l'épisode qui a fait construire ce signal (2026-08-26) portait sur vingt-sept
secrets externes de tous les namespaces — émetteur de certificats, fournisseur d'identité, tunnel
d'entrée, pare-feu applicatif — soit une rotation de clés éteinte à l'échelle du cluster, découverte
en tapant une commande d'inspection. **Le SOC, lui, servait normalement** : il tourne avec les secrets
**déjà injectés**, donc son bon fonctionnement n'est PAS une preuve que l'approvisionnement vit.

**CE QUI L'ARME, ET CE QUE SON SILENCE VEUT DIRE.** L'unique producteur des deux séries est `kube-state`,
donc **`plume-kube-state.timer`** — et `bootstrap.sh` le **désactive explicitement** à l'installation,
comme les autres capteurs de cette page. Tant qu'il n'est pas armé, aucune série n'arrive et le daemon
**ne conclut RIEN — ni sain, ni malade** ; ce silence **ne vaut pas « tout va bien »**. Et rien ne le
signale : aucun dead-man's-switch de « capteur muet » ne couvre `kube-state` (il crierait sur tout
déploiement hors cluster, où ce capteur n'a aucune raison de tourner), donc son absence est absorbée
comme un tick propre. **Sur un cluster : armez le minuteur ci-dessous, sinon ce paragraphe décrit un
signal que vous n'avez pas.**

## Activer (sur l'hôte, après avoir un central joignable)
```
# accès cluster : KUBECONFIG=/etc/rancher/k3s/k3s.yaml (par défaut dans l'unit).
# RBAC : lecture pods/nodes/deployments, ET lecture `secretstores`/`clustersecretstores`
#        du groupe `external-secrets.io` — sans elle, le signal d'approvisionnement décrit
#        plus haut ne peut PAS être produit. Corrigé le 2026-08-30 : cette ligne nommait un
#        RBAC plus ÉTROIT que ce que la page arme, si bien qu'un exploitant l'appliquant à la
#        lettre aurait obtenu une mesure ABSENTE — honnête, mais silencieuse là où il croyait
#        avoir armé une alerte. Une mesure absente n'est pas une mesure rassurante.
sudo systemctl enable --now plume-kube-state.timer plume-pod-logs.timer
```
Alternative cluster-native : un **CronJob** dans `deploy/k3s.yaml` (ServiceAccount lecture seule) qui POST vers `/api/ingest`.

## Règles filet-de-sécurité (à créer dans ⚙️ une fois les métriques présentes)
- `SELECT value FROM metric WHERE name='kube_deploy_unavailable' ORDER BY ts DESC LIMIT 1` `>` `0` → high
- `… name='kube_nodes_ready'` vs `kube_nodes_total` (node down)
- `search source=k8s severity>=3 | stats count` `>` `0` → CrashLoop/OOMKilled/NotReady
- (Magasin de secrets : **rien à créer ici** — l'alerte est native, cf. « Rotation des clés ».)
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
