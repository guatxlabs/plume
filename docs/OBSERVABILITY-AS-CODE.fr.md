# Observabilité en tant que code (#55)

[English](OBSERVABILITY-AS-CODE.md) | [Français](OBSERVABILITY-AS-CODE.fr.md)

Déclarez toute la configuration de votre SOC — pas seulement le contenu de détection — comme des fichiers
versionnés sous `config.d/`, gérez-la en GitOps à côté du modèle de déploiement ArgoCD, et laissez plume y
converger au démarrage.

Cela étend le **même** mécanisme de surcouche `config.d` qui provisionne déjà le contenu de détection
(parseurs / parseurs déclaratifs / règles / Sigma / playbooks — voir `daemon/src/overlays.rs`) aux **objets
de configuration** construits plus récemment. Le chargeur vit dans `daemon/src/overlays_oac.rs` et reflète
exactement le schéma des surcouches de règles/parseurs : **idempotent, indexé par `name`, `managed=1`,
valider-ou-ignorer, sans écrasement, élagable**.

> **Garantie du mode 0.** Ne livrez *aucun* nouveau fichier de surcouche et le comportement est
> byte-identique : le chargeur est strictement sans effet quand les sous-répertoires sont absents, et le seul
> changement de schéma (migration **v93**) ajoute une colonne `managed` qui vaut `2` par défaut
> (« interface ad hoc ») sur chaque rangée existante. Aucun objet ne devient géré tant qu'un fichier ne le
> déclare pas.

---

## 1. Disposition des fichiers

Tout vit sous `${PLUME_CONFIG_DIR}` (défaut `/usr/local/share/plume/config.d`, intégré à l'image — le pod
tourne en `readOnlyRootFilesystem`, donc les surcouches sont livrées *dans l'image*, pas sur un chemin de
l'hôte). Chaque type d'objet a son **propre sous-répertoire** ; chaque fichier `*.json` déclare **un** objet,
identifié par son `name` :

```
config.d/
├── parsers/                 # (existant) parseurs CIM regex + déclaratifs
├── rules/                   # (existant) règles de détection — portent aussi désormais une étiquette `compliance` (#38)
├── sigma/                   # (existant) YAML Sigma → règles
├── playbooks/               # (existant) détection → réponse
│
├── dashboards/              # tableaux de bord + leurs panneaux   → tables `dashboard` + `panel`
├── library-panels/          # panneaux réutilisables (#54)        → table `library_panel`
├── notifiers/               # canaux d'alerte                     → table `notifier`
├── notification-policies/   # routage des alertes                 → table `notification_policy`
├── destinations/            # sinks de transfert d'événements (#50) → table `destination`
├── connectors/              # connecteurs de sources externes (#3a) → table `connector`
├── index-policies/          # index nommés / rétention (#49)      → table `index_policy`
└── field-filters/           # masquage par champ (#45)            → table `field_filter`
```

> Le `config.d/` livré dans ce dépôt ne contient **que** des exemples de détection inoffensifs. Les fichiers
> d'exemple OAC sont documentés ici (ci-dessous) et délibérément **non** livrés, si bien que l'image d'origine
> ne transfère rien et n'alerte nulle part d'office.

### Exemples d'objets

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

`notifiers/slack-soc.json` — **secret référencé, jamais en ligne** (voir §3) :
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

`connectors/defender.json` — l'identifiant vit dans l'emplacement dédié `secret`, via `secret_ref` :
```json
{ "name": "MS Defender", "type": "defender",
  "config": { "azure_tenant": "…", "client_id": "…" },
  "secret_ref": "env:PLUME_DEFENDER_CLIENT_SECRET" }
```

`index-policies/staging.json`, `field-filters/mask-username.json`, `rules/…json` :
```json
{ "name": "staging", "retention_days": 30 }
{ "name": "Mask username for viewers", "field": "user", "action": "mask", "role": "viewer" }
{ "name": "Brute force", "is_soql": true, "query": "search source=sshd fail | stats count",
  "op": ">", "threshold": 10, "mitre": "T1110", "compliance": "pci_dss:8.7" }
```

---

## 2. Le modèle géré contre utilisateur

Chaque table qui admet des surcouches porte un drapeau `managed` avec la sémantique **commune à tout le
dépôt** déjà employée par `rule` / `parser` / `index_policy` :

| `managed` | signification | modifiable dans l'interface ? | élagué ? |
|-----------|---------|--------------|---------|
| `0` | intégré / semence | désactivation seulement | jamais |
| `1` | **surcouche (config.d, source git)** | **non — verrouillé** | oui, quand son fichier est retiré |
| `2` | interface ad hoc (CRUD) | oui | jamais |

- **Chargement** (au démarrage, après tous les `seed_*`, dans `load_overlays_dir`) : chaque objet est
  UPSERTé **indexé par `name`** avec `managed=1`. Une nouvelle exécution donne le même état (idempotent).
- **Sans écrasement — pour `managed=2` seulement, et la distinction compte.** Une surcouche n'écrase jamais un
  objet **utilisateur** : si une rangée du même `name` existe déjà avec `managed=2`, le chargeur **l'ignore et
  avertit** (renommez l'un des deux). Tous les autres cas prennent la branche `Update` — y compris
  `managed=0`. Un objet **semé/intégré** dont le `name` entre en collision avec un fichier de surcouche est
  donc **écrasé et basculé en `managed=1`**, ce qui le fait sortir de la ligne « jamais élagué » du tableau
  ci-dessus pour entrer dans la ligne élagable : retirer plus tard ce fichier de surcouche expose la rangée
  d'origine à `POST /api/config-overlays/prune`. Mesuré le 2026-08-06 (`overlays_oac.rs`, `plan_upsert` :
  `managed == 2 → SkipUser`, tout le reste → `Update(id)`).
  L'impact est borné — les semences sont idempotentes et réappliquées à chaque démarrage, donc la rangée
  revient — mais le tableau disait « jamais » et le code dit autre chose. Règle pratique : **ne donnez pas à
  un fichier de surcouche le `name` d'un objet semé**, à moins de vouloir en prendre possession. À l'inverse,
  l'interface refuse de supprimer/modifier un objet `managed=1` (`delete_managed_row_tx` rend `409` —
  « géré par config.d, retirez-le dans git »). Un verrou `managed=1` apparaît dans l'interface exactement
  comme une règle gérée.
- **Cycle de vie / élagage (#26).** Retirer un fichier de surcouche laisse derrière lui sa rangée `managed=1`
  (le chargement ne fait que des UPSERT). `POST /api/config-overlays/prune` (admin seulement, audité)
  supprime les rangées `managed=1` qu'aucun fichier n'adosse plus — et **seulement** celles-là (jamais
  `managed=0`/`2`). Les panneaux gérés d'un tableau de bord élagué sont balayés aussi. Idempotent.
- **Validation.** Le contenu des surcouches est contrôlé par les **mêmes validateurs que l'API** avant
  insertion — la compilation des panneaux (tableaux de bord/panneaux de bibliothèque),
  `dest_type_ok`/`dest_endpoint_ok`/`DestFilter::validate` (destinations), `safe_url`/liste d'autorisation
  des kinds (notifiers), forme de config par type + `env_slug_ok` (connecteurs), `env_id_ok` + bornage de la
  rétention (politiques d'index), `validate_field` + listes d'autorisation d'action/de rôle (filtres de
  champ), liste d'autorisation de champs de `parse_matchers` (politiques de notification), `norm_mitre` +
  `norm_compliance` (règles). Un objet invalide est **signalé et ignoré — jamais inséré, jamais un plantage au
  démarrage** (valider-ou-ignorer, à l'image des chargeurs existants).

---

## 3. Secrets — l'indirection honnête, au chargement

**Une surcouche commitée ne doit jamais contenir de secret en clair.** Notifiers, destinations et
connecteurs portent de l'authentification. La surcouche référence le secret **indirectement** ; le chargeur
le résout **au démarrage** et n'écrit que la valeur résolue dans la colonne `secret`/`config` (chiffrée par
SQLCipher, refusée au pool de lecture). Si une surcouche embarque un secret en ligne, **l'objet entier est
refusé — fail-closed**.

### Schémas de référence (résolus au chargement)

| schéma | se résout en | source typique |
|--------|-------------|----------------|
| `env:NAME` | variable d'environnement `NAME` | `Secret` k8s → env, injecté par un sidecar |
| `file:/path` | contenu du fichier (rogné) | `Secret` k8s monté comme fichier, gabarit Vault-Agent |
| `vault:PATH` | variable d'environnement nommée par `PATH` en majuscules, non-alphanumérique→`_` | **projection Vault-Agent** (voir la limite) |

Une référence **manquante** (variable d'environnement absente, fichier illisible) fait refuser l'objet — on
n'obtient jamais en silence un objet doté d'un identifiant vide.

### Ce qui compte comme « secret en ligne »

- **Connecteurs :** l'identifiant doit venir par **`secret_ref`** au premier niveau. Une clé `secret`
  littérale au premier niveau → refusée. `config` (identifiants non secrets seulement) est aussi analysé par
  précaution.
- **Notifiers / destinations :** toute clé porteuse de secret dans `config` (`token`, `pass`, `webhook_url`,
  `routing_key`, `auth_header`, `hec_token`, `client_secret`, `*_secret`, `*_token`, `*_key`, …) doit être une
  référence ; une valeur en clair → refusée. Les clés d'URL/de point d'entrée (`*_url`, `*_uri`,
  `*_endpoint`) sont traitées comme **non secrètes**, si bien qu'un `token_url` OAuth n'est pas un faux
  positif. Pour un jeton embarqué dans l'URL même d'un webhook/point d'entrée, utilisez `url_ref` /
  `endpoint_ref` (résolus de la même façon).

Le détecteur est volontairement prudent (clé exacte + suffixe, points d'entrée exclus) pour attraper les vraies
fuites sans imposer l'indirection sur de simples noms d'utilisateur ou des URL de point d'entrée.

### RBAC & audit

Le chargement des surcouches est une **action système** (démarrage / rechargement) — sans contexte
utilisateur. L'élagage est réservé à l'admin et inscrit au ledger (`audit_config_change`, sévérité 3),
exactement comme l'élagage de surcouches existant.

---

## 4. Limite honnête (ce que cela ne fait *pas*)

- **Vault n'est pas interrogé directement au chargement.** Le chargeur n'a pas de session Vault au
  démarrage ; les références `vault:` sont résolues par la **projection Vault-Agent standard** (env/fichier)
  que le reste de plume utilise déjà. Pointez `vault:` vers un secret que votre Vault-Agent rend — la
  référence documente l'intention ; la projection fait la récupération. Préférez `env:`/`file:` quand vous le
  pouvez.
- **L'analyse des secrets porte sur le premier niveau et sur les noms de clé.** Elle résout/refuse des
  *clés* secrètes ; elle ne mesure pas l'entropie de valeurs de texte libre arbitraires. Un secret caché dans
  un champ au nom non secret ne serait pas attrapé — gardez les identifiants dans les emplacements documentés.
- **Profondeur du verrou d'édition dans l'interface.** Le chemin destructif (suppression) est appliqué aux
  objets gérés (`delete_managed_row_tx`, `409`) et `index_policy` a un câblage complet du cycle de vie CRUD.
  Le durcissement de la *mise à jour* champ par champ sur chaque handler ancien est signalé par le drapeau
  `managed` (l'interface affiche le verrou) mais n'est pas encore un refus serveur dur sur chaque route de
  modification — suivi comme chantier ultérieur.
- **L'identité d'une politique de notification** est la nouvelle colonne `name` (v93) ; les politiques créées
  dans l'interface restent à `name=''` et n'entrent jamais en collision avec une surcouche nommée.
- **Pas de cloisonnement par environnement.** Les objets de configuration sont par nature à l'échelle du
  tenant (comme les règles/tableaux de bord), conformément au modèle de surcouche existant.

---

## 5. Fournisseur Terraform — conception (NON construit)

**Intention de conception seulement — aucun fournisseur n'est livré dans ce changement.**

Un `terraform-provider-plume` permettrait aux équipes déjà standardisées sur Terraform de gérer un SOC plume
comme ressources HCL plutôt que comme fichiers JSON écrits à la main, en visant les **mêmes** objets validés,
marqués `managed`, que provisionne ce chargeur. La forme naturelle :

- Les **ressources** reflètent les types d'objets de surcouche en 1:1 — `plume_dashboard`,
  `plume_library_panel`, `plume_notifier`, `plume_notification_policy`, `plume_destination`,
  `plume_connector`, `plume_index_policy`, `plume_field_filter`, `plume_rule`. Chacune correspond à l'API
  CRUD d'administration existante (create/update/delete), qui valide déjà à l'identique du chargeur de
  surcouches — si bien que le fournisseur réutilise la validation du serveur au lieu de la réimplémenter.
- Les **secrets** restent de première classe : les attributs secrets sont `sensitive = true` et acceptent les
  **mêmes chaînes de référence `env:`/`file:`/`vault:`**, OU se lient à une source de données
  `vault_generic_secret` / `data.aws_*` et transmettent la *référence*, jamais le littéral, si bien que l'état
  ne détient jamais d'identifiant en clair. Le fournisseur devrait refuser de persister un secret en ligne,
  conformément à la règle fail-closed du chargeur.
- **Réconciliation de `managed`.** Un objet géré par le fournisseur serait écrit en `managed=1` (ou avec un
  nouveau marqueur `managed=3` « IaC » si l'on veut distinguer Terraform des surcouches par fichier git), si
  bien que le `destroy` de Terraform et l'élagage de config.d partagent un seul modèle de cycle de vie et ne
  se battent jamais avec le `managed=2` de l'interface.
- La **dérive** est la force native de Terraform : `terraform plan` compare le HCL voulu à l'objet en service
  et fait ressortir les modifications faites hors bande dans l'interface — le même angle de gouvernance que le
  point d'entrée d'élagage, mais en continu.

La **surcouche `config.d` par fichiers est la voie principale, sans dépendance** (elle fonctionne avec git +
ArgoCD seuls, sans outillage supplémentaire) ; le fournisseur Terraform est une couche d'ergonomie optionnelle
pour les équipes Terraform, à cadrer comme un livrable à part.
