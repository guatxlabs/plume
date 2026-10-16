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
search category=auth | eval suspect = severity>=3 or src_ip="203.0.113.7" | where suspect = 1
```

**`eval` n'accepte pas d'expression régulière** : le `~` y est refusé en le nommant
(`eval : caractère non autorisé : '~'`). La ligne publiée ici jusqu'au 2026-08-26 en portait une —
elle ne compilait pas. Mesuré, et corrigé, en compilant : voir §10.

### 2.3 Un nom de champ mal écrit est REFUSÉ, pas ignoré

Un identifiant qui sort de la forme attendue — `x-forwarded-for=…`, `http.status=…` — ne devient pas
un filtre muet sur son dernier segment : la requête est **refusée**, le nom fautif est cité **en
entier**, et le message suggère les guillemets. C'est un choix : un filtre qui porte sur autre chose
que ce qu'on a écrit est pire qu'une erreur.

### 2.4 Limite connue : une barre verticale dans une expression régulière

**Il n'y a pas d'alternance possible dans une expression régulière aujourd'hui.** Le compilateur
découpe la requête en étapes sur chaque `|` de premier niveau **avant** de lire les guillemets : il ne
connaît que les crochets `[ … ]` comme groupement (`soql_split_pipes`, dans le cœur). Écrire
`search message=~"(refused|denied)"` coupe donc la requête en deux étapes, et la seconde n'est pas une
commande connue. Les guillemets ne protègent pas la barre.

Ce qui s'écrit à la place, et ce que chaque forme veut dire :

| Forme | Effet |
|---|---|
| `message=~"a\x7cb"` | la séquence `\x7c` est une barre verticale **littérale** pour le moteur d'expressions régulières : elle cherche le texte `a\|b`, ce n'est **pas** une alternance |
| `message=~"a[\|]b"` | idem — une classe de caractères qui contient la barre ; le découpage ignore ce qui est entre crochets |
| une alternance (`a` **ou** `b`) | **aucune forme** : une classe de caractères ne choisit qu'un caractère, jamais un mot. Écrivez deux recherches, ou une disjonction dans un `eval` (§2.2) sur des comparaisons sans expression régulière |

Il n'existe pas non plus de fonction `match()` : la liste des fonctions d'`eval` (§4.2) est fermée, et
`where` n'accepte qu'une comparaison (§3.1).

**Ce qu'un motif a le droit de coûter.** Un seul constructeur compile tous les motifs d'une requête
(`champ=~motif`, `champ:~motif`, `| rex`) : celui du chemin chaud **et** celui du tier froid, et l'import
Sigma (`|re`) valide ses motifs par le même. Il borne trois choses :

- **la longueur du motif : 512 octets** (des octets, pas des caractères : un `é` en compte deux). Au-delà,
  la requête est refusée en `400`, et le champ `error` de la réponse porte le message
  « motif regex trop long (max 512) » ;
- **la taille du programme compilé : 1 Mio** par automate. Un motif court peut la dépasser — `\w` est
  Unicode, `\w{100}` suffit. Refus en `400` aussi, avec le message du moteur :
  `Compiled regex exceeds size limit of 1048576 bytes.` ;
- **le cache du DFA paresseux : 1 Mio**. Le dépasser ne refuse rien : la recherche continue sur un moteur
  plus lent, sans message.

Chaque connexion de lecture garde quatre motifs compilés par fonction (`=~` d'un côté, `rex` de
l'autre) : une requête qui en combine quelques-uns ne les recompile pas à chaque ligne. Au froid, un
motif refusé n'est pas évalué : la requête retombe sur le chemin chaud, qui rend le même refus. À
l'import Sigma, une règle dont le motif généré dépasse 512 octets, ou que le constructeur refuse, est
signalée et **non importée**.

**Le coût d'une expression régulière croît avec la fenêtre.** Elle est évaluée ligne par ligne par une
fonction SQL (moteur `regex` de Rust, temps linéaire) et aucun index ne la sert : sur une grande
fenêtre, elle lit toutes les lignes que le reste du filtre laisse passer. Resserrez la fenêtre, et
filtrez d'abord sur une colonne réelle (`source`, `host`, `category`) ou un champ chaud (§5.2) :
`search source=sshd category=auth message=~"Invalid user"` ne passe le motif que sur les lignes de
cette source. **Ce que les bornes ne tiennent pas** : un motif admis reste cher sur une grande fenêtre,
et les requêtes interactives se partagent un sémaphore (`PLUME_QUERY_CONCURRENCY`, défaut 3). Quelques
requêtes lourdes lancées ensemble peuvent donc faire attendre toutes les autres recherches de la
console, jusqu'à ce qu'elles finissent ou soient interrompues par leur budget de temps.

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

### 3.1 Deux restrictions — et le piège n'est pas le refus, c'est l'absence de refus

**MESURÉ LE 2026-08-27 EN COMPILANT** chaque forme ci-dessous par `guatx_core::soql::to_sql`, à
l'étiquette qu'épingle `daemon/Cargo.toml`. La version précédente de cette section était établie par
LECTURE des compilateurs d'étape, et elle se trompait sur le point qui compte.

- **`where` n'accepte qu'UNE comparaison scalaire, ou UNE clause `in`/`not in` entière.** Il n'y a ni
  `and` ni `or` dans un `where`.
- **`sort` ne trie que sur UN champ** — le jeton qui suit la commande, préfixé de `-` pour
  décroissant.

Une version antérieure de cette page invitait le lecteur à comprendre « pourquoi son
`where a=1 and b=2` **échoue** ». **C'est faux, et faux du mauvais côté : rien n'échoue.**

| Ce qu'on écrit après un tube | Ce que le compilateur émet | Ce que l'exploitant obtient |
|---|---|---|
| `where count > 5 and count < 100` | `WHERE "count" > '5 and count < 100'` | **aucun refus** — la fin de la ligne devient un littéral de texte, la comparaison porte sur une chaîne, la réponse est vide et a l'air complète |
| `where a=1 and b=2` | `WHERE json_extract(fields,'$.a') = '1 and b=2'` | idem |
| `sort host severity` | `ORDER BY "host" ASC` | **aucun refus** — le second champ est jeté en silence |
| `sort host,severity` | *rien* | refusé : `sort : champ invalide : host,severity` |

Un second terme n'est donc signalé que s'il porte une **virgule** : c'est la virgule qui casse la
forme d'un identifiant, pas la conjonction. Une espace passe.

La conjonction s'écrit par un **tube** — `… | where a=1 | where b=2` — et celle-là est rendue
exactement : chaque étape enveloppe la précédente. La disjonction s'écrit dans un `eval` (§2.2).

Ces écarts étaient dans les tables de description (`daemon/src/handlers/soql_meta.rs`, servies par
`/api/soql/schema`) et dans l'aide intégrée de la console (`web/help_registry.js`, française **et**
anglaise), pas dans le compilateur : c'est le texte affiché qui promettait plus que ce que le langage
fait. **Quatre libellés servis** portaient la promesse, pas deux.

#### La borne est déclarée ICI, et toute surface qui décrit la commande doit la porter

Le tableau ci-dessous n'est pas de la prose : un témoin de construction le LIT, et exige de chaque
surface qui décrit la commande qu'elle porte la phrase de sa colonne. Une surface qui reviendrait à
« un ou plusieurs champs » ne porterait plus « un champ » et ferait rougir l'intégration continue.
Ajouter une ligne ici arme le témoin sur une commande de plus, sans le toucher.

| Commande | Ce que le langage tient (mesuré le 2026-08-27) | Phrase exigée (fr) | Phrase exigée (en) |
|---|---|---|---|
| `where` | UNE comparaison scalaire, ou UNE clause `in`/`not in` entière | `ni and ni or` | `no and, no or` |
| `sort` | UN champ, le jeton qui suit la commande | `un champ` | `one field` |

Ce que ce témoin ne tient pas : il ne compile rien — il tient une **cohérence d'écriture** entre le
corpus, la déclaration du démon et l'aide rendue. La mesure, elle, reste datée (§10).

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

**Deux bornes d'`eval`, mesurées le 2026-08-27 en compilant :**

- **Pas d'expression régulière** : le `~` est refusé en le nommant
  (`eval : caractère non autorisé : '~'`). La disjonction sur un motif s'écrit donc autrement.
- **`eval` ne résout PAS les clés du sac JSON**, et c'est la seule étape dans ce cas. Un nom y est
  recopié **tel quel** dans le SQL : `… | eval r = dport * 2` émet `(dport * 2)`, pas
  `json_extract(fields,'$.dport')`. Sur une **colonne réelle** (`severity`, `src_ip`, …) la requête
  marche ; sur une clé du sac elle **compile** — donc `/api/soql/validate` répond `valid:true` — et
  **échoue à la préparation** avec `no such column: dport`. Les deux moitiés ont été vérifiées : le
  SQL rendu par le compilateur, puis sa préparation par SQLite sur le schéma de `db/schema.sql`.
  C'est la même racine que l'absence de garde de nom dans `eval` (§2.3 vaut pour les autres étapes) :
  `eval` est la seule surface arithmétique, et valider un nom y interdirait l'arithmétique.

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
| plafond de lignes rendues | `PLUME_QUERY_MAX` | `5000` ; une valeur hors de `1`–`100000` retombe sur `5000` (§6.4) |
| défaut et plafond de `/api/search` | `PLUME_SEARCH_LIMIT` / `PLUME_SEARCH_MAX` | `100` / `5000` |
| requêtes simultanées | `PLUME_QUERY_CONCURRENCY` | `3`, **partagé** entre `/api/query` et `/api/search` |
| jetons réservés aux requêtes légères | `PLUME_QUERY_RESERVE_LIGHT` | `1` : les lourdes (`interactive:true`, export, Pivot) tiennent au plus N − 1 jetons |

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

### 6.4 Ce que le plafond coupe, et comment tout lire

**`5000` n'est pas une limite de ce que plume interroge ni de ce qu'il compte.** C'est le nombre de
**lignes rendues** dans un tableau — et, sous tier froid seulement, le nombre de lignes froides
recopiées par un chemin de lecture (plus bas).

`PLUME_QUERY_MAX` vaut `5000` par défaut et n'accepte qu'un entier de `1` à `100000`. **Toute autre
valeur — au-delà de `100000`, `0`, négative, illisible — retombe en silence sur `5000`** : aucun refus,
aucune ligne au démarrage. Écrire `PLUME_QUERY_MAX=200000` ne relève donc rien du tout.

Le plafond s'applique une fois le SQL exécuté : au-delà, la lecture s'arrête, `truncated` est posé dans
les statistiques de la réponse, et la console le dit. Sans tier froid, il ne touche pas au calcul :

- **un agrégat compte tout.** `search source=sshd | stats count` rend une seule ligne, et ce compte
  porte sur tous les événements de la fenêtre, quel qu'en soit le nombre ;
- **mais les groupes sont des lignes.** `stats count by src_ip` sur plus de `PLUME_QUERY_MAX` adresses
  rend les premiers groupes et signale la troncature ; chaque compte rendu reste complet. Un
  `| sort -count | head 100` après le `stats` choisit lesquels ;
- **le tableau de lignes brutes est ce qui est coupé.** Pour le parcourir en entier, la pagination par
  **curseur** de `/api/query` lit page par page sans plafond de comptage (exemple ci-dessous). Elle ne
  vaut que pour une requête qui **garde ses lignes** (filtre, `table`, `fields`, tri par date) ; sur une
  autre forme, la réponse retombe sur la pagination par décalage, plafonnée ;
- **resserrer la fenêtre** (`from`, `to`) reste le moyen le plus sûr de lire moins.

**Avec le tier froid actif** (binaire construit avec `cold_tier`, `PLUME_COLD_TIER=1`) et une fenêtre
qui descend dans le froid, la première puce ne tient plus toujours. Un des chemins de lecture recopie
les lignes froides de la fenêtre dans une table temporaire, **au plus `PLUME_QUERY_MAX` lignes**, puis
exécute la requête sur cette copie. Quand la recopie a atteint ce plafond :

- une requête dont **chaque étage est par événement** — `where`, `head`, `limit`, `eval`, `rex`,
  `rename`, `table`, `fields`, et rien d'autre — rend des lignes vraies, en nombre incomplet, avec
  `truncated` ;
- toute autre requête — un agrégat (`stats`, `timechart`, `top`, `rare`), mais aussi `eventstats`,
  `rate`, `dedup`, `sort`, `join`, `append`, `lookup`, `mvexpand` — **calcule ou choisit sur
  l'ensemble**, et elle est **refusée** : la réponse est un `422` dont le corps porte
  `"reason": "cold_truncated_aggregate"`, `"truncated": true`, `cold_rows_hydrated` et `cold_row_cap`
  (les lignes recopiées et le plafond), et un message `error` qui nomme l'étape en cause et les voies
  qui échappent au plafond. **Jamais un nombre calculé sur un
  échantillon.**

Certaines formes n'empruntent pas ce chemin : un pré-agrégé (réponse marquée `stats.approx`, donc
approximative) ou le moteur colonnaire, qui lit tout le froid sans le recopier, peuvent les servir
d'abord ; le message du refus les détaille. Pour obtenir une réponse là où le refus tombe :

- **resserrer la fenêtre** jusqu'à ce que la recopie tienne sous le plafond — l'ensemble lu redevient
  complet ;
- **relever `PLUME_QUERY_MAX`**, jusqu'à `100000` et pas au-delà (ci-dessus) : les lignes recopiées
  sont tenues en mémoire, c'est donc la mémoire du démon qui paie.

**Parcourir toutes les lignes par curseur.** Le premier appel porte `"keyset": true` ; la réponse rend
`next_cursor` (et `has_more`) ; l'appel suivant renvoie ce `next_cursor` **tel quel** dans le champ
`"cursor"` du corps, champ `espace` compris quand il y figure. `next_cursor` à `null` marque la dernière
page ; `limit` (au plus `10000`, défaut `100`) fixe la taille d'une page.

```sh
curl -sS -u admin -H 'Content-Type: application/json' https://soc.example.org/api/query \
  -d '{"soql":"search source=sshd","from":1767225600,"to":1767312000,"keyset":true,"limit":1000}'
# puis, pour la page suivante, la valeur de next_cursor recopiée telle quelle :
curl -sS -u admin -H 'Content-Type: application/json' https://soc.example.org/api/query \
  -d '{"soql":"search source=sshd","from":1767225600,"to":1767312000,"keyset":true,"limit":1000,
       "cursor":{"ts":1767311999,"id":48213}}'
```

`curl -u admin` demande le mot de passe sans l'écrire dans l'historique ; `from` et `to` sont des
secondes depuis l'époque Unix.

`PLUME_QUERY_MAX` est lu dans l'**environnement** du démon seul, pas dans le fichier de configuration :
sur un hôte, il se pose par un drop-in de `plume-daemon.service`. L'export complet ne devrait obéir qu'à
sa propre borne ; qu'il subisse aussi celle-ci est ouvert sous `P10.32-r`.

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

- **Aucune requête n'a été exécutée contre une instance.** Ce que cette page dit de la grammaire
  repose, pour la plus grande part, sur une **COMPILATION** : le 2026-08-27, chaque requête alors
  publiée ici, et chaque forme du tableau de §3.1, a été passée à `guatx_core::soql::to_sql`
  (étiquette épinglée par `daemon/Cargo.toml`) et le SQL rendu a été relevé. C'est ce passage qui a
  montré qu'un exemple de cette page ne compilait pas (§2.2) et que sa §3.1 annonçait un échec qui
  n'arrive pas. Les BORNES d'exécution (§6.1, §6.4) et les formes de réponse (§7) restent, elles,
  établies par lecture des gestionnaires.

  Les requêtes que cette page publie se relèvent — **sur l'arbre suivi : 6 lignes** :

  ```sh
  grep -noE '(^|`)(search|metric) [^`]*' docs/GXQL.md
  ```

  **Trois seulement ont été compilées** le 2026-08-27 : celle de l'en-tête et les deux de §2.2. Les
  trois autres ont été ajoutées après ce relevé et **n'ont pas été compilées** — les deux de §2.4 et
  celle de §6.4. Elles ont été **relues** contre le source du compilateur à l'étiquette épinglée : le
  découpage en étapes, le filtre de base et l'aiguillage des commandes. Par cette lecture, la
  requête à alternance de §2.4 échoue sur sa seconde étape (« commande GXQL inconnue »), comme la
  section l'annonce, et les deux autres produisent un SQL. Sont **relues, non compilées** de la même
  façon : les formes du tableau de §2.4, les étapes citées seules de §6.4 et la requête de l'exemple
  d'appel par curseur.

  Cette commande ne voit **pas** une requête coupée sur deux lignes, ni une requête qui ne commence
  pas par `search` ou `metric` (une étape citée seule, `| stats count by host`), ni une requête écrite
  dans un corps JSON. Elle ne dit pas non plus si elles compilent : rien dans ce dépôt ne les compile,
  le compilateur vivant dans une caisse externe (§1). **Cette page est donc tenue par une relecture
  datée, pas par un cliquet.**
- Le **corps du compilateur** appartient à une caisse externe au dépôt : les comptes publiés en §1
  sont dérivés des **miroirs** présents ici, qu'un test de la suite tient égaux aux listes du cœur.
- Le **taux d'acceptation** de l'importeur Sigma sur le dépôt SigmaHQ complet **n'est pas mesuré**,
  et aucun chiffre n'en est publié tant que le banc n'a pas été passé.
