# config.d — overlays versionnés (Personnalisation Phase 1)

Source de vérité **git-versionnée** pour les **parsers**, **règles de détection** et **playbooks**
personnalisés du SOC Plume. Tout fichier `*.json` déposé ici est chargé au démarrage du daemon
(`load_overlays`, juste après les migrations et les seeds) et posé en base avec `managed = 1`.

> Cet overlay est l'un des *seams* d'extension de Plume. Vue d'ensemble (parser / connecteur / détection /
> threat-intel / enforcer) et modèle *bring-your-own-vendor* : **[`docs/SDK.md`](../docs/SDK.md)**.

## Pourquoi un overlay baked et pas `/etc/plume` ?

Le daemon tourne dans un pod Kubernetes avec `readOnlyRootFilesystem: true` : il n'a **aucun** chemin
hôte writable (pas de `/etc/plume`). Ce répertoire est donc **baked dans l'image** (comme les assets web
sous `/usr/local/share/plume/web`) et monté en lecture seule. Le daemon le lit via la variable
d'environnement `PLUME_CONFIG_DIR` (défaut `/usr/local/share/plume/config.d`).

## Disposition

```
config.d/
├── parsers/     *.json              → table `parser` (regex legacy) + `dparser` (DSL déclaratif, cf. docs/PARSER-DSL.md)
├── rules/       *.json              → table `rule`
├── playbooks/   *.json              → table `playbook`
├── sigma/       *.yml|*.yaml|*.json → table `rule` (règles Sigma traduites en GXQL, cf. docs/SIGMA-IMPORTER.md)
└── cim/         cim.v1.json         → SPEC (miroir machine du CIM, cf. docs/CIM.md ; IGNORÉ par le loader — zéro effet runtime)
```

Un fichier = une entité (SAUF `sigma/` : un fichier YAML peut porter **plusieurs** documents `---`). Les
fichiers sont chargés par ordre alphabétique. Les clés JSON inconnues (ex. `_comment`) sont ignorées —
pratique pour documenter chaque fichier (JSON n'a pas de commentaires).

> **`sigma/` (Slice #7, pièce 3).** Les règles [Sigma](https://github.com/SigmaHQ/sigma) (standard ouvert
> de détection, YAML) y sont **traduites en règles Plume** (GXQL `search … | stats count` + `title`/`level`/
> tags MITRE) au boot par `load_overlay_sigma`, `managed = 1`. Le mapping `logsource → category` passe par
> le **CIM** (`docs/CIM.md`). Un construit non exprimable en GXQL (OU inter-champs, `1 of them`, agrégation,
> `|base64`/`|cidr`…) est **signalé + ignoré** (jamais une règle silencieusement fausse). Voir la matrice de
> couverture dans **`docs/SIGMA-IMPORTER.md`**. Import ponctuel/hors-git : `plume-daemon sigma-import <path>
> [--dry-run]` ou `POST /api/sigma/import` (admin).

## Sémantique de `managed`

La colonne `managed` (migration schéma v60) distingue l'origine de chaque parser/règle/playbook :

| valeur | origine                                                              |
|:------:|---------------------------------------------------------------------|
| `0`    | **builtin / seed** (livré par le code, éditable/désactivable dans l'UI) |
| `1`    | **overlay-file** — CE répertoire `config.d` (source git, durable)   |
| `2`    | **ad-hoc UI** — créé via le CRUD de l'interface                      |

`load_overlays` fait un **UPSERT keyé par `name`** : un overlay **gagne** sur un builtin du même nom
(le builtin est écrasé, `managed` passe à `1`). C'est **idempotent** — re-déployer / redémarrer donne
le même état — et **durable** : l'override survit au re-seed des builtins.

## Validation (au boot)

Chaque fichier est validé **avant** insertion ; un fichier invalide est **ignoré** (warning dans les
logs du daemon), il **ne fait jamais crasher** le boot :

- **parser** : `pattern` non vide, ≤ 1000 caractères, regex (crate Rust `regex`) qui **compile**.
- **règle / playbook** : la `query` doit **compiler** (GXQL ou SQL brut, même chemin que l'éval/test).
- **règle** : `mitre` au format `Txxxx` ou `Txxxx.yyy` (vide = non mappée).

## Schémas JSON

### parser (`parsers/*.json`)

```json
{
  "name": "nginx — méthode + chemin + statut",   // requis, clé de l'UPSERT
  "source": "nginx",                              // défaut "*" (toutes sources)
  "pattern": "...regex avec (?P<champ>...)...",    // requis ; groupes nommés = champs extraits
  "enabled": true                                  // défaut true
}
```

### rule (`rules/*.json`)

```json
{
  "name": "...",            // requis, clé de l'UPSERT
  "enabled": true,          // défaut true
  "query": "search ... | stats count",  // requis ; doit compiler
  "is_soql": true,          // défaut true. false = SQL brut (cf. note sécurité ci-dessous)
  "op": ">",                // > >= < <= == !=
  "threshold": 0,           // seuil numérique
  "severity": 3,            // 0 info … 4 critique
  "interval_s": 300,        // période d'évaluation
  "window_s": 3600,         // fenêtre glissante
  "mitre": "T1190"          // optionnel, Txxxx[.yyy]
}
```

### playbook (`playbooks/*.json`)

```json
{
  "name": "...",            // requis, clé de l'UPSERT
  "enabled": false,         // défaut true
  "query": "search ... | table src_ip",  // requis ; 1re colonne = cible de l'action
  "is_soql": true,          // défaut true
  "action_kind": "ban_ip",  // ban_ip | unban_ip | stop_service | ...
  "interval_s": 300,
  "window_s": 3600
}
```

## Notes de sécurité

- **SQL brut (`is_soql: false`)** lit l'intégralité de la base. Dans le CRUD de l'UI, il est **réservé
  au rôle `admin`** (durcissement 3a) ; le GXQL (langage borné, lecture seule) reste permis à l'`editor`.
  Les overlays de ce répertoire sont considérés **trusted (git-reviewés)**, mais la frontière **n'est pas
  la même selon l'objet** — cette section affirmait un « le SQL brut y est accepté » uniforme que le code
  contredisait pour la moitié des objets. État réel, vérifié le 2026-08-03 :

  | Objet d'overlay | `is_soql: false` | Où |
  |---|---|---|
  | `rules/`, `playbooks/` | **REFUSÉ** au chargement (WARN + event `config.overlay.reject`) | `overlays.rs` |
  | `library-panels/`, `dashboards/` | **ACCEPTÉ**, et **tracé** au ledger (`config.overlay.raw_sql`) | `overlays_oac.rs` |

  La différence est assumée : une règle s'exécute **toute seule, en boucle**, alors qu'un panneau ne rend
  que ce que son lecteur a le droit de voir. Dans les deux cas la requête reste **validée** (doit compiler),
  et l'écriture de ce répertoire est un acte d'**opérateur** (image bakée en lecture seule / ConfigMap,
  process non-propriétaire) — jamais une action d'utilisateur authentifié.
- L'**évaluation** des règles et playbooks s'exécute sur une **connexion lecture seule**
  (`PRAGMA query_only=ON` + `SQLITE_OPEN_READ_ONLY` + garde `stmt.readonly()`) : une règle/playbook ne
  peut **que lire**, jamais muter la base (durcissement 3b).

## Déploiement (pour mémoire — hors de ce répertoire)

- **Dockerfile** : `COPY plume/config.d /usr/local/share/plume/config.d`
- **Deployment** : exposer `PLUME_CONFIG_DIR=/usr/local/share/plume/config.d` (ou laisser le défaut).

## Multi-déploiement — l'overlay est AGNOSTIQUE au runtime

L'overlay est lu depuis le **chemin** pointé par la variable `PLUME_CONFIG_DIR` : Plume (et Forge) peuvent
donc se déployer **standalone**, pas seulement sur k3s. Le baked `/usr/local/share/plume/config.d` reste
le **fallback par défaut** dans tous les modes (aucune variable -> ce chemin).

| Mode | Comment monter l'overlay |
|:--|:--|
| **k3s** | une **ConfigMap** montée sur `PLUME_CONFIG_DIR` (déclarez-la dans votre dépôt GitOps). |
| **docker-compose** | bind-mount `./config.d:/etc/plume/config.d` + `PLUME_CONFIG_DIR=/etc/plume/config.d`. |
| **host-native** | pointer `PLUME_CONFIG_DIR` vers un répertoire de l'hôte (ex. `/etc/plume/config.d`). |

> Le chemin baked dans l'image (`/usr/local/share/plume/config.d`) sert de défaut si `PLUME_CONFIG_DIR`
> n'est pas posé — pratique pour un déploiement sans overlay externe.

## Rollups par dimension config-driven (`PLUME_ROLLUP_DIMS`)

Indépendamment des fichiers de cet overlay, la variable d'environnement **`PLUME_ROLLUP_DIMS`** ajoute des
dimensions pré-agrégées (`event_dim_rollup`) **sans recompiler** : un `search source=X | stats count by <dim>`
est alors servi depuis la table de rollup (réponse en ms) au lieu de scanner la table chiffrée.

- **Format** : `"source1:dim1,dim2;source2:dim3"` (sources séparées par `;`, dims par `,`).
- **Sémantique** : ADDITIVE (union avec les défauts compilés) — n'enlève jamais une dim built-in ; crée les
  sources nouvelles. Plafond **6 dims/source**. Idents invalides ignorés silencieusement.
- ⚠️ **BASSE cardinalité UNIQUEMENT** (`level`, `status`, `verb`, `ns`…). **JAMAIS** `msg`/`time`/`trace_id` :
  le cap top-N/bucket tronquerait les chiffres ET ces clés explosent la RAM (elles sont dans la denylist d'auto-index).
- **Défaut** : `k8s-log` inclut déjà `ns,pod,level` -> `search source=k8s-log | stats count by level` instantané.
- Un changement de `PLUME_ROLLUP_DIMS` est pris en compte au **redémarrage** (valeur mise en cache au boot).
