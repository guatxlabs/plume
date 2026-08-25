# GXQL — le langage de recherche

GXQL (*GuatX Query Language*, **anciennement « SOQL »** : même langage, même syntaxe, seul le nom a
changé) est un langage à tubes, d'inspiration SPL, **compilé en SQL de lecture seule**. On écrit un
filtre, on enchaîne des étapes séparées par `|`, et chaque étape enveloppe la précédente dans une
sous-requête.

```
search source=sshd "Failed password" | stats count by src_ip | where count > 5 | sort -count
```

Ce document décrit **la grammaire réellement acceptée**, ses bornes, et — ce qui compte autant —
**ce qu'elle n'accepte pas**, parce que plusieurs constructions qu'un lecteur venu de SPL croit
disponibles ne le sont pas.

---

## 1. Où vit le compilateur, et comment redériver ce document

**Le compilateur ne vit pas dans ce dépôt.** Il est dans la caisse partagée `guatx-core`, résolue
par une étiquette git épinglée dans `daemon/Cargo.toml`, et c'est le **seul** chemin de compilation :
il n'existe plus d'implémentation de repli ni de bascule.

```sh
grep -n 'guatx-core' daemon/Cargo.toml        # la source, et l'étiquette épinglée
```

Ce qui **est** dans ce dépôt, et qui rend le vocabulaire vérifiable sans cloner la caisse : les
tables de description de `daemon/src/handlers/soql_meta.rs`, miroirs un-pour-un des listes du
compilateur, qu'un test refuse de laisser incomplètes.

```sh
# le vocabulaire, compté SUR L'ARBRE plutôt que recopié ici
for B in DOC_COMMANDS DOC_STATS_FUNCTIONS DOC_EVAL_FUNCTIONS DOC_OPERATORS DOC_FIELDS; do
  printf '%-22s ' "$B"
  sed -n "/const $B/,/^];/p" daemon/src/handlers/soql_meta.rs | grep -c '^    ("'
done
```

**Relevé sur l'arbre suivi le 2026-08-25** : 20 commandes de tube, 8 fonctions d'agrégation,
15 fonctions d'`eval`, 8 opérateurs de filtre, 14 champs décrits.

Sur une instance qui tourne, `GET /api/soql/schema` rend **tout** le vocabulaire — commandes,
fonctions, opérateurs, mots-clés, champs, valeurs d'énumération et descriptions — en un seul appel.
C'est ce que la barre de recherche de la console utilise pour sa complétion ; c'est aussi la source
à interroger plutôt que de croire une page.

---

## 2. Le filtre, avant le premier tube

### 2.1 Ce qui s'écrit

| Forme | Effet |
|---|---|
| `champ=valeur` | égalité ; `:` en est un alias exact |
| `champ!=valeur` | différence |
| `champ>valeur` `champ<valeur` `champ>=` `champ<=` | comparaisons ; **numériques** si la valeur est un nombre |
| `champ=~motif` | expression régulière |
| `champ=~motif` · `champ:~motif` | un `~` en **tête de valeur**, sur `=` ou `:`, bascule aussi en expression régulière |
| `champ=val*` | joker : traduit en `LIKE`, `*` devenant `%` |
| `champ!=val*` | joker nié |
| `champ in (a, b, c)` · `champ not in (…)` | appartenance ; une liste **textuelle positive** compare sans tenir compte de la casse |
| `*` seul | tout ; aucun filtre n'est émis |
| un mot isolé | **recherche plein texte** dans `message` |

### 2.2 Ce qui NE s'écrit pas — et c'est le piège principal

**Il n'y a que du ET, et il est implicite.** Toutes les conditions du filtre de base sont jointes par
`AND`. Il n'existe :

- **aucun `OR`** — un `OR` tapé dans la barre devient un terme plein texte, c'est-à-dire une
  recherche du mot « OR » dans les messages ;
- **aucun `NOT` en préfixe** — la négation s'écrit `!=` ou `not in (…)` ;
- **aucun groupement par parenthèses.** Les parenthèses ne groupent pas : elles repartent en **termes
  plein texte**. Écrire `search (foo in (1,2))` produit la condition d'appartenance **plus** deux
  recherches de texte, l'une pour `(` et l'autre pour `)`. Ce n'est pas une déduction : le
  compilateur porte ce cas en commentaire, avec cet exemple précis, à l'endroit qui remet le
  groupement de tête dans le texte résiduel.

**Le seul endroit du langage où `and`, `or`, `not` et de vraies parenthèses existent est une
expression `eval`.** D'où le motif idiomatique pour exprimer une disjonction :

```
search category=auth | eval suspect = severity>=3 or src_ip=~"^203\.0\.113\." | where suspect = 1
```

### 2.3 Un nom de champ mal écrit est REFUSÉ, pas ignoré

Un identifiant qui sort de la forme attendue — `x-forwarded-for=…`, `http.status=…` — ne devient pas
un filtre muet sur son dernier segment : la requête est **refusée**, le nom fautif est cité **en
entier**, et le message suggère les guillemets. C'est un choix : un filtre qui porte sur autre chose
que ce qu'on a écrit est pire qu'une erreur.

---

## 3. Les vingt commandes de tube

| Commande | Ce qu'elle fait |
|---|---|
| `stats` | agrège : une ou plusieurs mesures, éventuellement groupées par `by` |
| `timechart` | série temporelle : une mesure par intervalle (`span=`) |
| `where` | filtre **après** un tube — voir la restriction ci-dessous |
| `sort` | trie — voir la restriction ci-dessous |
| `head` / `limit` | ne garde que les N premières lignes ; un N négatif est **refusé** (SQLite y verrait « illimité ») |
| `rex` | extrait des champs d'un texte par une expression régulière à groupes nommés |
| `fields` | restreint les colonnes rendues |
| `table` | présente les colonnes listées |
| `rename` | renomme un champ (`champ as alias`) |
| `dedup` | garde le premier événement par champ |
| `top` / `rare` | valeurs les plus / les moins fréquentes |
| `eventstats` | comme `stats`, mais rattache l'agrégat à chaque ligne sans les réduire |
| `rate` | taux par unité de temps |
| `eval` | crée un champ à partir d'une expression |
| `append` | ajoute les résultats d'une sous-recherche `[search …]` |
| `join` | joint le flux à une sous-recherche sur un champ commun |
| `mvexpand` | éclate un champ multivalué en une ligne par valeur |
| `lookup` | enrichit via une table de correspondance (`… OUTPUT …`) |

Deux **bases** existent : `search` (le défaut, sur les événements) et `metric` (sur les séries
d'observabilité). Quatre mots structurants les accompagnent : `by`, `span=`, `as`, `OUTPUT`.

Une commande inconnue est **refusée en la nommant**, jamais ignorée.

### 3.1 Deux restrictions que la description intégrée ne dit pas

**MESURÉ SUR L'ARBRE le 2026-08-25**, en lisant les compilateurs d'étape :

- **`where` n'accepte qu'UNE comparaison scalaire, ou UNE clause `in`/`not in` entière.** Il n'y a ni
  `and` ni `or` dans un `where`. *La description affichée par la console annonce pourtant
  « comparaisons, and/or ».*
- **`sort` ne trie que sur UN champ** — le jeton qui suit la commande, préfixé de `-` pour
  décroissant. *La description affichée annonce « un ou plusieurs champs ».*

Ces deux écarts sont dans les tables de description (`daemon/src/handlers/soql_meta.rs`), pas dans le
compilateur : c'est le texte affiché qui promet plus que ce que le langage fait. Écrit ici pour qu'un
lecteur ne perde pas une heure à chercher pourquoi son `where a=1 and b=2` échoue.

---

## 4. Les fonctions

### 4.1 Agrégation — utilisables par `stats`, `eventstats` et `timechart`

| Fonction | Forme | Note |
|---|---|---|
| `count` | **nue**, sans parenthèses | compte les lignes ; l'alias de sortie est `count` |
| `count(champ)` `sum` `avg` `min` `max` | `f(champ)` | l'alias de sortie est le nom de la fonction |
| `dc(champ)` | | cardinalité — compte les valeurs distinctes |
| `values(champ)` | | valeurs **distinctes**, concaténées, **bornées en longueur** |
| `list(champ)` | | valeurs avec doublons, **bornées en longueur** |

`values` et `list` sont plafonnées : au-delà, la liste est tronquée. C'est une borne mémoire
délibérée, pas un bogue — une agrégation qui concatène sans borne est un moyen simple de faire sortir
le démon de son budget.

Une fonction inconnue est **refusée en la nommant**.

### 4.2 `eval` — la seule surface expressive

`if`, `coalesce`, `ifnull`, `nullif`, `lower`, `upper`, `length`, `len`, `abs`, `round`, `min`, `max`,
`substr`, `replace`, `trim`.

Cette liste **est** l'allowlist : le compilateur la référence directement, il n'en tient pas une
copie. La complétion de la console ne peut donc pas diverger de ce que le compilateur accepte.

---

## 5. Les champs

### 5.1 Colonnes réelles et sac JSON

Le schéma des événements distingue deux natures de champ, et c'est essentiel pour comprendre les
performances autant que la sécurité :

| Nature | Exemples | Traduction |
|---|---|---|
| **colonne réelle** | `ts`, `host`, `source`, `category`, `severity`, `src_ip`, `dst_ip`, `url`, `xff`, `message` | identifiant quoté ; les colonnes sont en **liste blanche** |
| **clé du sac JSON** | tout le reste | `json_extract(fields, '$.<nom>')`, avec conversion numérique en comparaison chiffrée |

**À dire franchement : les clés du sac JSON ne sont PAS en liste blanche.** N'importe quel
identifiant de forme valide est extrait. Ce qui empêche l'injection n'est pas la liste, c'est la
**forme** exigée de l'identifiant (lettres, chiffres, tiret bas — rien d'autre), le quotage des
identifiants générés et l'échappement des littéraux.

### 5.2 Les champs « chauds »

Une douzaine de clés JSON portent un **index d'expression** en base — `action`, `user`, `owner`,
`kind`, `ns`, `role`, `scope`, `verb`, `resource`, `operation`, `dir`, `risk`. Filtrer sur celles-là
est bien moins coûteux que sur une clé quelconque du sac.

Cette liste existe en deux endroits — le cœur et le démon — et **une divergence ne compile pas** :
une assertion constante compare les deux tableaux à la compilation. Un contrat tenu par le
compilateur ne peut pas dériver.

### 5.3 Le masquage se fait à la compilation

Quand un filtre de champ masque une colonne pour le rôle courant, le compilateur **refuse** la
requête au lieu de rendre une valeur creuse — y compris pour le plein texte, qui porte sur `message`.
Une requête qui rendrait un résultat différent selon le rôle serait un oracle ; il vaut mieux un
refus lisible.

---

## 6. Les bornes

### 6.1 À l'exécution

| Borne | Levier | Défaut |
|---|---|---|
| budget de temps d'une requête « automatique » (panneaux, règles, pagination) | `PLUME_QUERY_BUDGET_MS` | `5000` ms |
| budget d'une requête **interactive** | `PLUME_QUERY_BUDGET_INTERACTIVE_MS` | `60000` ms |
| plafond de lignes rendues | `PLUME_QUERY_MAX` | `5000`, borné dur à `100000` |
| défaut et plafond de `/api/search` | `PLUME_SEARCH_LIMIT` / `PLUME_SEARCH_MAX` | `100` / `5000` |
| requêtes simultanées | `PLUME_QUERY_CONCURRENCY` | `3`, **partagé** entre `/api/query` et `/api/search` |

Le dépassement de budget **interrompt** la requête en cours ; le dépassement du plafond de lignes la
**tronque** et le signale dans les statistiques de réponse plutôt que de rendre un résultat partiel
qui aurait l'air complet. Une requête peut aussi être **annulée** par le client, par identifiant.

### 6.2 À la compilation, avant toute exécution

Le compilateur borne le texte d'entrée, le nombre d'étapes, la taille du SQL produit — recalculée
**après chaque étape**, pas seulement à la fin — l'intervalle d'un `timechart`, et la profondeur des
sous-recherches. Ces bornes portent des noms préfixés `GUATX_SOQL_MAX_*`. Une valeur présente mais
illisible est une **erreur rendue à l'appelant**, jamais un repli silencieux.

### 6.3 La lecture seule, en couches

C'est la propriété de sécurité centrale du produit, et elle ne repose pas sur un seul contrôle :

1. la connexion est **ouverte en lecture seule** ;
2. `PRAGMA query_only=ON` ;
3. l'instruction préparée est **rejetée si elle n'est pas en lecture** ;
4. un **autorisateur** SQLite refuse les colonnes de mot de passe et de jeton **même à un
   administrateur** ;
5. les filtres de champ sont appliqués **à la compilation** (§5.3).

**Précision qui corrige une formulation trop courte** : le chemin GXQL **n'utilise pas de paramètres
liés** — il **incorpore des littéraux échappés** et n'accepte que des identifiants de forme
restreinte. Ce sont l'échappement et la contrainte de forme, non le paramétrage, qui ferment
l'injection sur ce chemin. Les paramètres liés existent, mais sur `/api/search`. De même, « un seul
`SELECT` » n'est pas un contrôle explicite : c'est une **propriété structurelle** — le compilateur
n'émet qu'un `SELECT` fait de sous-requêtes imbriquées, ne peut pas produire de `;`, et la
préparation ne compile de toute façon que la première instruction.

---

## 7. Les surfaces HTTP

| Route | Méthode | Ce qu'elle prend | Ce qu'elle rend |
|---|---|---|---|
| `/api/query` | `POST` | `{"soql": "…"}` (+ `from`, `to`, `interactive`, `qid`, pagination) | `{"columns":[…], "rows":[[…]], "stats":{…}}` |
| `/api/search` | `GET` | `q=` et quelques jetons ad-hoc | `{"results":[…]}` |
| `/api/soql/schema` | `GET` | — | tout le vocabulaire |
| `/api/soql/validate` | `POST` | `{"soql": "…"}` | `{"valid":true}` ou `{"valid":false,"error":"…"}` |
| `/api/soql/templates` | `GET` | — | la bibliothèque de gabarits |
| `/api/export` | `POST` | comme `/api/query` | export |
| `/api/cancel` | `POST` | `{"qid": "…"}` | annule une requête en cours |
| `/api/ds/query` | `GET`/`POST` | GXQL sur HTTP-JSON | pour Grafana — voir [`DATASOURCE.md`](DATASOURCE.md) |

Deux points à ne pas confondre :

- **`/api/search` n'est pas du GXQL.** C'est une barre de recherche à analyseur ad-hoc, adossée à
  l'index plein texte, qui accepte quelques jetons (`limite`, expression régulière, `champ:valeur`
  avec joker). Elle rend **toujours `200`**, même sur une erreur de moteur, qu'elle place dans un
  champ `error` de la réponse.
- **`/api/soql/validate` ne touche pas la base.** Il compile et rend son verdict — pas de handle,
  pas d'exécution. C'est l'appel que fait la console pendant la frappe.

**Le SQL brut** (`{"sql": …}` sur `/api/query`) est réservé aux administrateurs, et il reste soumis
à l'autorisateur : voir la note du [`README`](../README.md#sécurité-intégrée).

Les identifiants techniques restent en `soql` — route `/api/soql/*`, clé JSON `soql`, colonne
`is_soql`, module `guatx_core::soql`, dossier `docs/soql-templates/`. C'est un identifiant de build,
pas un libellé utilisateur.

---

## 8. Les gabarits livrés

`docs/soql-templates/templates.json` contient **16 gabarits** (relevé sur l'arbre le 2026-08-25),
chacun avec `id`, `title`, `keywords` (français et anglais) et `soql` :

```sh
python3 -c "import json;d=json.load(open('docs/soql-templates/templates.json'));print(len(d['templates']));print([t['id'] for t in d['templates']])"
```

Ils sont **embarqués dans le binaire** par `include_str!` et servis tels quels — aucune lecture de
fichier à l'exécution. Deux conséquences : le dossier doit être présent **avant** la compilation (le
`Dockerfile` le copie pour cette seule raison), et **chaque gabarit est prouvé compilable par un test
de la suite**. Un gabarit qui ne compilerait plus ferait rougir l'intégration continue, pas
l'utilisateur.

---

## 9. Pourquoi le langage est fermé

**Un langage fermé est une surface d'attaque qu'on peut énumérer.** Le vocabulaire tient en cinq
listes courtes ; ce qui n'y est pas est refusé **en le nommant**. C'est ce qui permet d'exposer une
recherche à un rôle *viewer* sans exposer la base, et c'est aussi ce qui rend possible le projet de
traduction depuis le langage naturel : un texte produit par un modèle est inoffensif s'il doit
franchir un compilateur fermé avant d'atteindre le moteur.

**Le prix est écrit** : plusieurs constructions de SPL n'existent pas ici — pas de disjonction dans
le filtre, pas de groupement, pas de tri multi-champs, pas de `transaction`, pas de percentile. Un
document de spécification du dépôt en promet certaines : ce sont des souhaits, pas des capacités.
Ce que l'importeur Sigma ne sait pas traduire fidèlement est **signalé, jamais deviné** —
[`SIGMA-IMPORTER.md`](SIGMA-IMPORTER.md) en donne la matrice exacte.

**Le compilateur vit dans une caisse partagée** parce que deux moitiés d'une même suite doivent
parler le même langage. La règle de contribution qui en découle est écrite dans
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) : on le corrige sur place, on ne le duplique jamais.

---

## 10. Ce qui n'a pas été vérifié

- **Aucune requête n'a été exécutée contre une instance dans ce lot.** La grammaire, les bornes et
  les refus décrits ici sont établis par lecture des compilateurs d'étape et des tables de
  vocabulaire ; les formes de réponse le sont par lecture des gestionnaires.
- Le **corps du compilateur** appartient à une caisse externe au dépôt : les comptes publiés en §1
  sont dérivés des **miroirs** présents ici, qu'un test de la suite tient égaux aux listes du cœur.
- Le **taux d'acceptation** de l'importeur Sigma sur le dépôt SigmaHQ complet **n'est pas mesuré**,
  et aucun chiffre n'en est publié tant que le banc n'a pas été passé.
