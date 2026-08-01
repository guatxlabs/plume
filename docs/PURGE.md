# Purger des événements — ce que la purge fait, et ce qu'elle refuse de faire

**État : ✅ livré (sous-commande) · 🧪 opt-in (surface HTTP, fermée par défaut)**

La rétention de Plume est *temporelle* : elle efface ce qui est vieux, rien d'autre. Il manquait un moyen
d'effacer un ensemble d'événements **nommé** — des lignes de test après un onboarding, un flux mal branché,
les traces d'un exercice pentest, une demande d'effacement. Sans cela, la seule issue était du SQL direct sur
une base SQLCipher, depuis une image qui ne contient que le daemon.

`plume-daemon purge` comble ce trou. C'est la fonction la plus destructrice du produit : **une purge est
irréversible et détruit des preuves**. Ce document dit ce qu'elle garantit, et surtout ce qu'elle ne garantit
pas.

---

## En deux temps, toujours

```
# TEMPS 1 — SIMULE. N'écrit rien. Rend le compte exact, un échantillon, et un JETON.
plume-daemon purge --source flux-de-test --since -2d --until -1h

# TEMPS 2 — EXÉCUTE, si le jeton est encore l'empreinte du périmètre re-simulé.
plume-daemon purge --source flux-de-test --since -2d --until -1h \
    --confirm <jeton> --reason "nettoyage des events de test d'onboarding"
```

Le jeton n'est pas un identifiant de session : c'est **l'empreinte du résultat de la simulation** (périmètre
canonique, cardinalité, bornes d'`id` et de `ts`, ventilation par source). L'exécution **re-simule** et
recalcule cette empreinte. Donc :

* confirmer sans avoir simulé est impossible (il n'y a pas de jeton à rendre) ;
* rejouer une confirmation échoue (le contenu a changé — les lignes ne sont plus là) ;
* si une ligne entre ou sort du périmètre entre les deux temps (ingest concurrent, relais en retard,
  legal-hold posé), l'empreinte change et **la confirmation devient caduque**.

Codes de sortie : `0` simulation rendue ou purge exécutée · `2` arguments invalides / base inouvrable ·
`3` **refus motivé** (un refus a son propre code, pour qu'un runbook ne l'avale pas comme un succès).

---

## Le périmètre se **nomme**, et il est **borné**

| Argument | Colonne d'`event` |
|---|---|
| `--source <nom>` | `source` |
| `--env <id>` | `env_id` |
| `--origin <val>` | `origin` |
| `--engagement <id>` | `engagement_id` |

* **Au moins un identifiant est obligatoire.** « tout ce qui est dans cette fenêtre » n'est pas un périmètre
  acceptable, et n'est pas non plus une valeur que le code sait représenter.
* **Les deux bornes sont obligatoires** (`--since` / `--until`, epoch en secondes ou décalage `-7d` `-24h`
  `-30m` `-3600s`). Il n'y a pas de fenêtre par défaut.
* **Il n'existe aucun prédicat libre.** Ni SQL, ni GXQL, ni joker : ce sont les formes qui rendent une purge
  accidentellement totale, et elles n'ont pas de place dans le type qui décrit un périmètre.
* Les sélecteurs se **conjoignent** : en ajouter un ne peut que rétrécir le périmètre.
* Les valeurs d'identifiant suivent le **charset d'identifiant** du produit (alphanumérique + `.` `_` `-`,
  1 à 64 caractères) — le même que `env_id` / les noms d'index. **Limite connue** : une source dont le nom
  sortirait de ce charset (par exemple injectée par un forwarder tiers avec un espace ou un `/`) n'est pas
  purgeable par nom aujourd'hui ; utilisez `--env` ou `--engagement` pour la cerner.
* La **piste d'audit est refusée comme périmètre** : `--source plume-config`,
  `plume-operator-access`, `plume-tenant-admin`, `plume-engagement` et `--origin daemon` sont rejetés
  explicitement. Une purge ne peut pas effacer la trace des changements de configuration ni des accès
  opérateur — y compris **la trace d'une purge précédente**.

---

## Ce que la purge REFUSE de faire (et le dit)

| Refus | Pourquoi |
|---|---|
| **Rétention légale** | ≥ 1 `legal_hold` actif recouvre le périmètre → refus **total**, en nommant les holds. Jamais de purge partielle « sauf les lignes tenues » : elle laisserait croire que tout est parti. Lever un hold reste un acte de gouvernance tracé (`/api/legal-holds/:id/release`) ; la purge ne le contourne pas. |
| **État des holds indéterminable** | Table `legal_hold` présente mais illisible → fail-closed. On ne supprime jamais une preuve dont on ne peut pas prouver qu'elle n'est pas retenue. |
| **Tier froid** | Des fichiers Parquet scellés recouvrent la fenêtre → refus, en nommant le nombre de fichiers et de jours. Vider `event` laisserait ces copies columnarisées **interrogeables** : « purgé » serait faux. La purge ne sait pas réécrire un Parquet scellé, et elle ne prétend pas le contraire. Contournement : attendre l'expiration cold, ou restreindre la fenêtre aux jours encore chauds. |
| **Chaîne de preuve** | Un event du périmètre est cité par la timeline d'un case/incident → refus, en nommant les identifiants. Détacher l'item d'abord. |
| **Index plein-texte désynchronisé** | `event_fts` existe sans son trigger de suppression → un `DELETE` laisserait les postings et le message purgé resterait **cherchable**. Refus. |

---

## Ce que la purge couvre RÉELLEMENT

Dans **une seule transaction**, après inscription au registre :

* les lignes d'`event` du périmètre ;
* **`event_fts`** — l'index plein-texte, via le trigger de suppression (dont l'absence est un refus en amont) ;
* **`event_rollup`** et **`event_dim_rollup`** — les buckets horaires recouvrant la fenêtre sont supprimés puis
  **re-agrégés depuis les lignes survivantes**, avec la même borne d'identifiant que la couverture publiée
  (sans cette borne, les lignes récentes seraient comptées deux fois). Un agrégat qui continuerait de compter
  les lignes détruites rendrait le contenu purgé encore visible sous forme de comptes ;
* **`panel_cache`** — les payloads de panneaux mis en cache portent des résultats *rendus*, donc possiblement
  du contenu purgé : ils sont vidés (ils se recalculent en fond).

---

## Ce que la purge NE couvre PAS

Chaque point ci-dessous est **compté et affiché** dans la sortie de la simulation. Ce n'est pas une note de
bas de page : une purge qui laisserait croire qu'elle a tout effacé serait pire que pas de purge du tout.

* **Les sauvegardes déjà prises.** Une purge n'en retire rien. **Une restauration réintroduirait les lignes
  purgées.** Pour une demande d'effacement (type RGPD), traitez aussi les sauvegardes — rotation, expiration,
  ou re-prise après purge. Le produit ne le fait pas pour vous.
* **Les alertes** (`alert`). Une alerte n'est pas une ligne dérivée d'`event` : elle a sa propre rétention et
  son propre cycle de vie. Mais son champ `detail` **peut citer le texte d'un event purgé**. La simulation
  compte les alertes de la fenêtre ; à vous de décider.
* **Les métriques et les captures d'état** (`metric`, `snapshot`). Ces tables n'ont ni `source` ni `origin` :
  le périmètre ne s'y projette pas. Elles sont comptées, pas touchées.
* **Les instantanés de dashboard partageables** (`dashboard_snapshot`). Ils portent des résultats rendus, donc
  possiblement du contenu purgé. Les détruire détruirait du travail utilisateur : ils sont comptés, pas touchés.
* **L'inventaire de flotte** (`host_rollup`). Ses compteurs par hôte restent gonflés des lignes purgées. C'est
  un inventaire (noms d'hôtes, dernière activité), pas du contenu d'événement ; le remettre à zéro ferait
  disparaître des hôtes de la vue flotte, ce qui serait un mensonge d'un autre genre.
* **Les copies exportées du registre** (sinks WORM). C'est leur raison d'être : elles sont *append-only* et
  vérifiables hors base. La purge y **ajoute** son entrée ; elle n'en retire rien.
* **Un déni de service par purge répétée.** Un admin malveillant peut purger beaucoup, souvent. Chaque purge
  est inscrite au registre chaîné et émet un événement SOC de sévérité 4, non purgeable et alertable — c'est
  une **détection**, pas une prévention.

---

## Intégrité : rien ne se supprime sans être inscrit

Chaque purge écrit, **dans la même transaction que la suppression** :

1. une entrée au **registre append-only chaîné par hachage** (`kind = config.purge.events`) : qui, périmètre
   résolu, combien de lignes, quand, l'empreinte confirmée, et la raison ;
2. un **événement SOC** `source='plume-config'` `origin='daemon'` de sévérité 4 — donc non purgeable et
   alertable, comme une baisse de rétention.

Si l'inscription échoue, **rien n'est supprimé**. Et si la base supprime un nombre de lignes différent de
celui qui vient d'être inscrit, **tout est annulé** — l'entrée de registre comprise : le registre n'affirme
jamais autre chose que ce que la base a fait.

L'inscription porte le périmètre et les compteurs — **jamais le contenu détruit**. Aucun message, aucune IP,
aucun champ parsé n'y entre : la valeur passée à l'inscription ne les transporte pas.

Vérifier après coup :

```
plume-daemon verify                      # recompute toute la chaîne + les signatures de checkpoint
plume-daemon ledger-export --out purge.jsonl
plume-daemon ledger-verify-export purge.jsonl
```

---

## Qui a le droit

* La **sous-commande** exige la clé SQLCipher et l'accès à l'hôte — soit exactement le pouvoir qu'il faudrait
  pour effacer la base à la main. Elle n'ajoute donc aucune capacité ; elle remplace un `DELETE` manuel non
  tracé par un chemin borné, simulé, confirmé et inscrit. L'acteur inscrit au registre est le compte système
  et le pid ; `PLUME_PURGE_ACTOR` **ajoute** le nom de l'humain responsable, sans remplacer ce qui a été mesuré.
* La **surface HTTP** (`POST /api/purge/plan`, `POST /api/purge/apply`) est **admin-only** et **fermée par
  défaut**. Elle ajoute, elle, une capacité de destruction de preuves *à distance* : il faut l'armer
  explicitement au déploiement avec `PLUME_PURGE_API=1`. Cela sépare deux principals — celui qui détient le
  mot de passe admin, et celui qui contrôle le déploiement.
* **« Admin » n'est pas forcément le bon quantum d'autorité pour détruire des preuves.** La permission
  soustractive `purge_events` permet de définir un rôle composable `base=admin` **sans** la purge, sans
  toucher au code (`POST /api/roles`, `deny_perms: ["purge_events"]`).
* En mode multi-tenant, une purge cross-tenant par un super-admin passe déjà par le **break-glass** habituel
  (raison obligatoire, marqueur d'accès opérateur non désactivable dans la base du client).

---

## Variables

| Variable | Défaut | Effet |
|---|---|---|
| `PLUME_PURGE_API` | *(absent)* | `1` arme les routes HTTP de purge (admin-only). Absent → elles refusent. |
| `PLUME_PURGE_ACTOR` | *(absent)* | Nom de l'humain responsable, **ajouté** à l'acteur système inscrit au registre. |
