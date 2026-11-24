# Contribuer à Plume

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.fr.md)

Merci de votre intérêt pour Plume — le SOC/XDR poids plume. Plume est un binaire Rust unique
(`plume-daemon`) qui ingère de la télémétrie, la stocke chiffrée dans SQLite/SQLCipher, et sert
l'API + l'interface web + le moteur de détection. Les contributions sont bienvenues, sous quelques règles
qui existent parce que Plume est un outil **critique pour la sécurité et borné en ressources**.

En contribuant, vous acceptez que votre contribution soit placée sous **AGPL-3.0-or-later** (la licence
du projet), et vous certifiez le [Developer Certificate of Origin](https://developercertificate.org/)
par l'acte même de contribuer. **N'ajoutez pas de trailer `Signed-off-by:`.** Mesuré le 2026-08-26 :
le trailer porte une adresse hors du domaine du projet, les gardes la refusent, et la plateforme
la *reporte* dans un commit d'écrasement — un commit signé ainsi ne peut donc pas entrer ici. La
certification tient ; seul le trailer est abandonné. Voir *Comment un changement entre réellement ici*
plus bas.

Pour le *quoi* et le *pourquoi* de l'architecture, lisez d'abord ceux-ci — ce guide ne les répète
**pas** : [`ARCHITECTURE.md`](ARCHITECTURE.fr.md), [`docs/MODULE-MAP.md`](docs/MODULE-MAP.fr.md)
(carte des sous-systèmes + invariants de sécurité), [`docs/CIM.md`](docs/CIM.fr.md) (taxonomie des
événements).

## Non négociable : les invariants

Une demande de fusion qui affaiblit l'un d'eux sera **refusée**, si utile que soit la fonctionnalité :

- **Mode-0 byte-identique.** Tout ce qui est derrière une feature Cargo OFF par défaut (ou une porte
  d'exécution) **doit laisser le build par défaut byte-identique** — le module *n'existe pas*, il n'est
  pas simplement « sauté ». Vous le prouvez par un **compte de tests constant** : la suite par défaut
  passe le **même nombre** de tests avant et après votre changement cloisonné (`cd daemon && cargo test
  --locked`, features par défaut). **Ce nombre est écrit à UN seul endroit** :
  `EXPECTED_TESTS` dans `.github/workflows/ci.yml` — l'endroit que la CI applique réellement. Lisez-le
  là ; ne le recopiez pas dans de la prose. Ce document le nommait, et trois autres fichiers aussi ;
  les quatre ont pourri, devenus périmés, pendant que la CI restait juste, ce qui est la seule issue
  possible d'un compteur dupliqué. Une étape de CI ÉCHOUE désormais si la valeur vivante réapparaît
  sous la forme d'une affirmation nue « N tests » ailleurs dans l'arbre, si bien que la duplication ne
  peut pas revenir. Quand vous ajoutez légitimement des tests, mettez à jour `EXPECTED_TESTS` d'après
  votre propre mesure — et rien d'autre. (Les mesures historiques *citées avec leur date* sont
  acceptées et ne sont pas des compteurs : elles consignent ce qui était vrai alors, et ne doivent PAS
  être « corrigées » à la valeur du jour.)
  La CI ADDITIONNE les lignes `test result: ok. N passed` du run par défaut et FAIT ÉCHOUER
  le build sur tout écart, si bien qu'un changement cloisonné qui ajoute ou retire en silence un test
  dans le profil par défaut ne peut pas être fusionné (la crate agent est à part : `cd agent && cargo test
  --locked` → 96, non asserté par la CI). **La contrepartie de cet invariant est que la suite par
  défaut est AVEUGLE au code cloisonné par construction** — 752 sont restés verts avec une erreur de type
  délibérée dans `cold_store`. Un compte par défaut constant est donc nécessaire, pas suffisant : le
  travail cloisonné doit AUSSI être vert sous sa propre feature (job `cold-tier`). Une dépendance lourde
  nouvelle est `optional = true` derrière une feature, OFF par défaut, avec un commentaire de
  justification dans `daemon/Cargo.toml` (ce fichier est le journal canonique des justifications —
  suivez son style).
- **Le masquage s'applique au point de passage `soql_field` — jamais réimplémenté par appelant.**
  Les lectures exposées à l'utilisateur passent par le compilateur GXQL partagé ; les lignes passent par
  `soql_field`/`soql_filter_field` (dans guatx-core) **avant** l'agrégation ou le renommage. N'ajoutez
  pas de chemin de lecture qui hydrate des lignes brutes dans une requête utilisateur, et ne
  réimplémentez le masquage nulle part ailleurs. Les règles DENY arment aussi l'autorisateur SQLite, si
  bien que le refus tient même pour le SQL brut d'un admin. Comportement **fail-closed** : rôle inconnu → masqué ;
  règle illisible au rechargement → traitée comme DENY.
- **Un collecteur qui ne peut pas collecter doit le DIRE — un `exit 0` silencieux est un mensonge.** Un
  capteur dont un prérequis manque (binaire, fichier source, identifiant, sous-système) sortait **avec
  succès** et n'émettait rien, si bien que le SOC ne pouvait pas distinguer *« ce capteur est aveugle »*
  de *« rien ne s'est passé »*.
  *Mesuré le 2026-08-01 sur une VM Ubuntu 24.04 Server fraîche : `auditd.sh` faisait `[ -r "$LOG" ] || exit 0`,
  auditd n'est pas installé par défaut, et `category=exec` était vide sans que rien nulle part ne dise
  pourquoi — 29 des 37 capteurs livrés portaient la même forme — 50 sorties silencieuses.* Chaque sortie
  anticipée relève d'exactement un cas sur trois, et chacun a une primitive nommée dans
  `collectors/lib.sh` qui porte son propre `exit` : `plume_unavailable` (prérequis manquant → émet
  `category=config`, `collect_status=unavailable`, vocabulaire `reason` fermé), `plume_disabled`
  (interrupteur de l'exploitant coupé), `plume_exit_nodata` (rien de neuf — le seul silence légitime).
  **Un `exit 0` nu dans un collecteur fait échouer la CI**
  (`.github/scripts/check_collector_exit_is_classified.py`) : la porte n'énumère aucune liste de
  capteurs, si bien qu'un collecteur écrit demain est couvert par construction. Signaler ne suffit pas
  pour être *vu* : un événement `config` de plus fait paraître **frais** une source aveugle (mesuré :
  `/api/sources` rendait `status: "frais"` pour une source qui venait d'avouer être aveugle), donc la
  règle de catalogue `config.d/rules/catalog/de-collector-unavailable.json` lève une **alerte** sur
  l'aveu — **une fois qu'un exploitant l'active** : comme tout le catalogue, elle est livrée avec
  `"enabled": false`, et le chargeur lit `enabled` dans le fichier. Activée, elle lève **une seule**
  alerte **globale**, et le flux fautif la porte quand même (un badge d'alerte sur ce flux dans la vue
  des sources) : l'alerte consigne la `source` des **événements appariés** (`alert.sources`,
  `daemon/src/imputation.rs`), que `daemon/src/handlers/freshness.rs` lit pour compter les
  `active_alerts` par source ; l'ancien balayage du texte de la requête de la règle à la recherche de
  jetons `source=` ne reste qu'en repli pour les alertes levées avant que cette colonne n'existe. Laissé
  désactivé, un aveu est un événement et rien de plus.
- **Le budget de 2 Go de RAM n'est pas négociable — optimiser, ne pas grossir.** Le déploiement de
  référence mesure **~310 MiB de RSS** (9 844 503 événements, 2 vCPU, masquage des champs coupé) et est
  **plafonné à l'exécution** à **2 GiB** (`limits.memory: 2Gi` sous k3s, `MemoryMax=2G` sous systemd) —
  **aucun job de CI n'asserte ce plafond**, traitez-le donc comme un budget à re-mesurer, pas comme une
  garantie que la chaîne défend. Gardez l'ensemble de travail borné : paginer (keyset), streamer
  (tampons bornés ~1 MiB), ou agréger. Une requête qui balaie un événement par requête est un bug —
  précalculez des agrégats, utilisez la rollup-route/SWR. Si un changement échange de la RAM contre de la
  vitesse, il va derrière une feature OFF par défaut ou il n'entre pas.
- **Le DDL d'une migration de schéma ne doit dépendre ni des DONNÉES, ni de la configuration, ni du
  système de fichiers.** Le démarrage dérive la forme attendue d'une base en rejouant `db/schema.sql` +
  toute la chaîne de migrations dans une base **vide, en mémoire, non configurée**, puis refuse de servir
  une base à laquelle manque quoi que ce soit que cette référence déclare (objets *et* colonnes). Une
  étape qui crée, modifie ou supprime **sous condition du contenu** — « créer cette table seulement si
  `event` est vide », un `ALTER` conditionné par un `SELECT` — fait donc produire à une base de
  production parfaitement saine une forme *différente*, et le daemon refuse de démarrer dessus en disant
  à l'exploitant de restaurer une sauvegarde. C'est le pire mode de défaillance de ce code : une panne
  pour quelqu'un qui n'a rien cassé. Écrivez un DDL inconditionnel et idempotent (`IF NOT EXISTS`) ;
  mettez le travail sur les données dans des `INSERT`/`UPDATE` au sein de la même étape, là où il a sa
  place. Deux tests tiennent cela : `the_reference_holds_on_a_populated_database` (base peuplée, dans les
  deux sens de montée de version) et `every_migration_path_lands_on_the_same_shape`.
- **Pas de connexion en écriture à une base sans le contrat de schéma.** `db_open` est le seul module
  qui peut ouvrir une connexion SQLite sur un chemin. Prenez-la de `PreparedDb::open*` (garde
  anti-retour-arrière + `prepare_schema`), ou écrivez `open_db_without_schema_contract` en toutes
  lettres et attendez-vous à ce que le relecteur demande pourquoi. Un fichier de production qui ouvre
  lui-même une `rusqlite::Connection` fait échouer `the_door_is_the_only_way_in`.
- **Le compilateur GXQL vit dans `guatx-core` — le corriger en place, jamais le forker.** La grammaire
  fermée et son `SqliteDialect` sont partagés. Changez le compilateur *dans la crate core* ; ne le
  copiez pas dans le daemon et ne maintenez pas un parseur divergent. La dépendance est à sens unique :
  `plume-daemon` dépend de `guatx-core` ; le core ne dépend jamais du daemon et ne doit jamais acquérir
  de dépendance `rusqlite`/SQLCipher.

Dans le doute, ajoutez un test qui prouve que l'invariant tient toujours.

## Construire et tester

> **Note (build open source) :** le daemon dépend de `guatx-core` comme **dépendance git**
> (`github.com/guatxlabs/core`), épinglée sur une étiquette **dans `daemon/Cargo.toml` et nulle part
> ailleurs** — lisez-la avec `grep -n 'guatx-core' daemon/Cargo.toml`. Pour développer contre une copie
> locale du core, placez-la dans un répertoire voisin et ajoutez à la racine du dépôt un
> `.cargo/config.toml` ignoré par git, avec un `[patch]` qui redirige la dépendance git vers le chemin :
> ```toml
> # .cargo/config.toml (local seulement, jamais commité)
> [patch."https://github.com/guatxlabs/core"]
> guatx-core = { path = "../../core" }
> ```
>
> **Ce patch échoue EN SILENCE quand la version de votre core local diffère de celle du verrou —
> mesuré le 2026-07-30, et c'est un piège à faux vert, pas une gêne.** Le `Cargo.lock` commité épingle
> guatx-core sur une source git **et une révision**. Si la copie voisine porte un `version =`
> différent (disons que vous l'avez montée à 0.2.2 alors que le verrou épingle 0.2.1), cargo **refuse
> la substitution** et construit contre le core *publié* : votre build est vert et ne prouve rien sur
> votre changement local. Vous n'obtenez qu'une ligne, facile à perdre dans la sortie de cargo :
> ```
> warning: patch `guatx-core v0.2.2 (/path/to/core)` was not used in the crate graph
> ```
> Mesuré dans les deux sens : avec le verrou en place → résolu depuis
> la source `git+…?tag=…#<rev>` épinglée par le verrou ; avec le verrou autorisé à se re-résoudre →
> résolu depuis le chemin local. Donc **ne supposez pas — vérifiez quel core vous avez réellement
> compilé** :
> ```sh
> cargo metadata --format-version 1 | python3 -c "import json,sys; \
>   print([ (p['version'], p.get('source') or 'LOCAL PATH') \
>           for p in json.load(sys.stdin)['packages'] if p['name']=='guatx-core' ])"
> ```
> Il doit imprimer `LOCAL PATH`. S'il imprime une source `git+…`, laissez le verrou se re-résoudre
> (`cargo update -p guatx-core`) — et ne commitez jamais ce changement du verrou.

La crate vit dans `daemon/`, donc pointez cargo dessus. Le build par défaut est le profil PME
(`SqlcipherStore` seul) et doit rester **vert au compte qu'asserte `EXPECTED_TESTS`** (voir
plus haut — cette variable est la source unique de vérité) et **hors ligne** :

```sh
cargo test --manifest-path daemon/Cargo.toml        # features par défaut
```

La **suite `cold_tier` a son propre compte et son propre job de CI** (`cold-tier` dans
`.github/workflows/ci.yml`, `EXPECTED_COLD_TESTS`). Jouez-la aussi quand vous touchez
`daemon/src/cold_store/` — ou tout ce dont il dépend, notamment le compilateur GXQL :

```sh
TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml --features cold_tier
# le compte qu'asserte `EXPECTED_COLD_TESTS` (= la suite par défaut + ce que la feature ajoute)
```

> **Pourquoi cela compte plus qu'il n'y paraît.** Avec une fenêtre chaude de 7 jours et une rétention
> de 365 jours, `cold_store` est le chemin de lecture de ~358 des 365 jours retenus. C'est aussi le
> module dont le mode de défaillance est *silencieux* : élaguez trop un fichier Parquet et une requête
> qui couvre plus d'une semaine rend un compte faux **sans erreur**. Jusqu'à l'existence de ce job, rien
> dans la CI ne *compilait* même le module — et il était passé au rouge sans que personne ne le voie :
> monter guatx-core en v0.2.1 a resserré la validation des noms de champs GXQL et cassé les tests de
> parité d'extracteur du tier froid, pendant que la suite par défaut restait verte — **752 verts le
> 2026-07-28**, la taille de la suite à cette date. Ce nombre est une mesure datée, pas un compteur :
> ne l'alignez **pas** sur la valeur du jour, ou vous détruisez la preuve. Le compteur vivant est
> `EXPECTED_TESTS` et vit seulement dans `ci.yml`.

**Deux pièges de test** (appris à la dure) :

1. **Pointez `TMPDIR` sur un vrai chemin disque.** `/tmp` est souvent en RAM (tmpfs ZRAM) ; les tests
   qui y déversent des bases ou des Parquet temporaires mangent le budget RAM même que vous respectez,
   et peuvent provoquer un OOM.
2. **Ne jouez jamais la suite par défaut et une suite `--features cold_tier` en même temps.** Elles
   partagent des chemins de fixtures temporaires fixes → deux processus cargo se piétinent → faux
   échecs. Jouez les suites de features **séquentiellement, sur un runner séparé** :
   ```sh
   TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml
   TMPDIR=/path/on/disk cargo test --manifest-path daemon/Cargo.toml --features cold_tier
   ```

Tous les backends optionnels sont **OFF par défaut**. La liste complète des features, depuis
`[features]` dans `daemon/Cargo.toml` : `cold_tier`, `clickhouse`, `clickhouse-ha`, `ldap`, `saml`,
`duckdb`, `s3_backup`, `ai`. Le binaire par défaut n'en porte aucune.

**Ce que la CI vérifie réellement à leur sujet** — ne sur-interprétez pas une coche verte :

| feature | couverture CI |
|---|---|
| `cold_tier` | **compilée et testée** (job `cold-tier`, son propre compte asserté) |
| `ai` | **compilée et testée** (job `ai`, son propre compte asserté) — toute la suite tourne avec la feature active |
| `s3_backup` | **compilée et testée, filtrée** (job `features` : `cargo check`, puis seulement les tests `sink_s3_`, son propre compte asserté `EXPECTED_S3_TESTS`) — jamais contre un stockage objet réel |
| `duckdb`, `clickhouse`, `clickhouse-ha`, `ldap`, `saml` | **`cargo check` seulement** — vérifiées par le typage, jamais exécutées |

Une régression de comportement dans la validation des assertions SAML, le bind LDAP ou le backend
ClickHouse **passera la CI au vert**. Les rendre réelles exige des suites qui tournent sans IdP,
annuaire ou serveur ClickHouse réel ; ce travail n'est pas fait. Si vous touchez l'une d'elles, dites
dans la demande de fusion comment vous l'avez testée à la main — la CI ne le fera pas pour vous. Le
chemin consultatif de l'IA est exécuté par le job `ai` sans réseau — son câblage dans le daemon, jamais
un point de terminaison de modèle réel : le comportement réel d'un fournisseur sur le fil reste à
vérifier à la main.

Les **collecteurs shell** (43 scripts suivis) passent une porte d'analyse syntaxique `bash -n` (job
`shell`) et un shellcheck *consultatif*. `bash -n` prouve qu'ils s'analysent ; il ne prouve rien sur
leur comportement.

## Style de code

- **Noms auto-documentés, explicites sur le composant.** Aucun marqueur de déroulement dans les noms
  (tâche/commit/branche/fonctionnalité) ; l'état vit dans le statut, pas dans les noms.
- **Les préfixes de commit nomment le sous-système touché** (`storage:`, `soql:`, `ingest:`, `ui:`,
  `auth:`, `detection:`, `rollups:`, `cold:`, …). Délimitez les commits (`git add <file>`) ; n'ajoutez
  jamais en bloc.
- **Les commentaires portent la justification.** Chaque module ou invariant énonce son « pourquoi » en
  tête de fichier (voir les en-têtes de `cold_store/*.rs` et les blocs de dépendances de
  `daemon/Cargo.toml`). Le *pourquoi* porte ici une charge — gardez la discipline.
- **Les tests sont rangés par domaine** sous `daemon/src/tests/{rollup,detection,rbac,soql_completion,cases,
  governance,connectors,tokens,engagement,tenants,…}.rs`. Ajoutez les tests à côté du domaine qu'ils
  exercent ; ne faites pas grossir un monolithe de tests.

## Demandes de fusion

1. Ouvrez d'abord une issue pour tout ce qui n'est pas trivial, afin que nous convenions de l'approche.
2. Un changement logique par demande de fusion. Gardez le diff ciblé.
3. Incluez des tests. Préservez ou améliorez la couverture ; gardez le compte par défaut CONSTANT — la
   valeur vit dans `EXPECTED_TESTS` (`.github/workflows/ci.yml`) et nulle part ailleurs, lisez-la donc
   là. Si vous touchez `cold_store`, `EXPECTED_COLD_TESTS` est asserté de la même façon.
   `EXPECTED_AI_TESTS` est le compte de la suite **entière** sous `--features ai` — les tests par
   défaut plus ceux cloisonnés par ai —, il bouge donc avec **chaque** test que vous ajoutez au profil
   par défaut, pas seulement avec les tests ai. Re-mesurez-le avec
   `cargo test --manifest-path daemon/Cargo.toml --features ai -- --list` et mettez-le à jour dans
   `ci.yml`, à côté des autres.
   **Vérifiez-le en quelques secondes à quelques minutes au lieu de 47 minutes** avec
   `.github/scripts/compter-les-tests.sh` : il demande au harnais de *lister* ses tests
   (`cargo test -- --list`) au lieu de les jouer, et compare les **trois** comptes — par défaut
   (`EXPECTED_TESTS`), `--features cold_tier` (`EXPECTED_COLD_TESTS`) et `--features ai`
   (`EXPECTED_AI_TESTS`) — à `ci.yml` lui-même, sans seconde copie des nombres. Il rejoue aussi le
   contrôle d'ordre du job `ai` : `EXPECTED_AI_TESTS` doit rester **supérieur** à `EXPECTED_TESTS`,
   faute de quoi la feature n'ajoute plus de test et la CI la refuse. `--defaut` liste la suite par
   défaut seule (le contrôle d'ordre tourne quand même, il lit deux nombres et ne construit rien).
   Lister **compile** quand même le harnais, une fois par ensemble de features. Mesuré le 2026-10-25 sur
   une machine à 6 cœurs avec un `target/` chaud : quelques secondes quand rien n'a changé ; après avoir
   touché un fichier sous `daemon/src/`, environ 35 s pour `--defaut` et environ 100 s pour les trois
   suites (chaque ensemble de features recompile) ; sans artefacts `cold_tier` et `ai` encore, environ
   12 min ; sur un `target/` froid, un build complet par ensemble de features. Installez-le comme crochet
   de pre-commit avec `git config core.hooksPath .githooks` (il reste muet sauf si le commit touche
   `daemon/src/`, `daemon/Cargo.*` ou `ci.yml`, et liste alors les trois suites). Il ne vous dit **pas**
   que les tests passent — seule la CI, qui les joue réellement, le dit.
   *(Pourquoi un contrôle local et pas un déclencheur de CI de plus : `ci.yml` tourne déjà sur `push`
   vers chaque branche, et c'est le cas depuis la création du fichier. La dérive 937 → 945 du 2026-08-07
   a été attrapée par la CI à la poussée et simplement pas lue. Mesuré le 2026-08-09 : jouer les suites
   par défaut et `cold_tier` = 187 s + 2627 s ≈ 47 min.)*
   <!-- Ces deux lignes ont porté « 758 » et « 949 » jusqu'au 2026-08-02, quand les compteurs vivants
        valaient 866 et 1061 : 108 et 112 de retard, dans le fichier même qui INTERDIT de recopier la
        valeur. La garde `check_no_duplicated_test_count.py` restait verte — c'est son résidu
        documenté (jambe A ne cherche que la valeur COURANTE ; jambe B n'attrape que la forme
        « nombre PUIS mot », or ici le nombre suivait le mot et était en gras markdown). Élargir la
        jambe B a été MESURÉ le 2026-08-02 : 162 candidats pour 2 vrais — donc NON élargie, et le
        remède est de ne plus écrire de nombre ici du tout. -->

4. Jouez `cargo test` (par défaut) et, pour un travail cloisonné, la suite de la feature séparément ;
   jouez `cargo clippy`. Tout doit passer. « La suite par défaut est verte » n'est **pas** une preuve
   pour du code cloisonné — voir l'invariant mode-0 plus haut.
5. **Ne signez pas avec `-s`.** Le trailer porte une adresse hors projet que les deux gardes refusent —
   voir *Comment un changement entre réellement ici*. Le DCO se certifie en contribuant, pas par le
   trailer.
6. **Les problèmes de sécurité ne vont pas ici** — voir [`SECURITY.md`](SECURITY.fr.md).

### Comment un changement entre réellement ici

**Le bouton de fusion ne peut produire aucun commit que ce dépôt accepte.** Mesuré le 2026-08-26 sur
les réglages de ce dépôt et sur une fusion par écrasement réelle réglée à l'identique, le commit
d'écrasement porte trois choses que les gardes refusent, et aucun réglage du dépôt n'en retire une
seule : les **trailers de signature des commits écrasés sont reportés** (ce qui ramène une adresse hors
projet), une **ligne `Co-authored-by:` par auteur distinct** est ajoutée, et le commit d'écrasement est
**commité par le compte de la plateforme**, pas par l'identité canonique. Prouvé par mutation : le même
corps, privé de ces seules lignes, passe.

Une demande de fusion n'est donc **pas** un chemin d'entrée ici — pas même une écrite par le mainteneur.
Le seul chemin d'entrée est une **poussée directe** sur la branche de publication sous l'identité
canonique. Une contribution est réappliquée localement, rejouée sous cette identité, et poussée ; le
message de commit cite le numéro de la demande, pour que la discussion reste retrouvable. Il en va de
même des demandes de mise à jour de dépendances : le robot vaut d'être gardé pour l'**alerte** — il dit
quelle version bouge et pourquoi — et pas pour la fusion.

C'est pourquoi ces demandes de fusion restent au rouge, et ce rouge est **vrai**. Il ne se corrige pas
branche par branche : personne ne peut réécrire le message d'un commit qu'un robot vient d'écrire. Il ne
doit pas être éteint non plus — une garde qui cesserait de juger ces commits ne retirerait pas la cause,
seulement le fait de la voir, et la branche de publication perdrait sa seule redondance : chaque commit
y arriverait sans avoir jamais été lu.

## Un mot sur l'intention

Plume sert à surveiller **une infrastructure qui vous appartient ou que vous êtes autorisé à
surveiller**. Les contributions qui facilitent l'exfiltration de données, le contournement de ses
contrôles de masquage ou de RBAC, ou l'attaque de systèmes qui ne vous appartiennent pas sont hors du
périmètre de ce projet.

## Écrire pour le public

Ce dépôt est public. Tout ce qui y est écrit — messages de commit, documentation,
commentaires de code — s'adresse au **lecteur futur du code**, pas à une personne ni à une
conversation.

**Un message de commit dit CE QUI CHANGE et POURQUOI.** Il n'a pas à raconter le
déroulement du travail. À proscrire :

- nommer une personne, ou citer un échange privé ;
- le récit à la première personne (« j'ai essayé », « ma première version ») ;
- les repères de session (« hier », « ce matin », « la quatrième fois aujourd'hui ») ;
- un chemin machine (`/home/<compte>`), un pseudo personnel, une adresse tierce.

Ce qui a de la valeur et doit rester : la **mesure** (chiffres et date), ce qui a été
**réfuté**, et la **raison** d'un choix de conception. Le journal de travail, lui, a sa
place dans un dépôt interne — pas dans l'historique public.

**Identité.** Tous les commits sont signés `guatxlabs <noreply@guatx.com>`. À poser dans
chaque clone, car un clone frais hérite de la configuration globale de la machine :

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks   # arme les gardes ci-dessous
```

**Deux gardes versionnées** appliquent le mécanisable : `pre-commit` refuse un commit dont
l'auteur n'est pas le canonique ; `commit-msg` refuse un message portant un chemin machine,
un pseudo personnel ou une adresse tierce. Les hooks sont une **boucle de retour**, pas une
frontière — la CI juge tout commit poussé, sur toute branche, et c'est elle qui lie. Le STYLE, lui, n'est mécanisé que là
où un critère dérivable n'accuse pas à tort : depuis le 2026-09-09, la première personne dans les
commentaires et la documentation est tenue par `check_prose_addresses_the_reader_not_the_author.py`
(famille lue dans le vérificateur de message, citations et messages à l'exploitant retirés). Le reste
du style se tient à la relecture — une garde qui prétendrait en juger produirait du bruit et
finirait désarmée.

**Un chiffre porte son témoin.** Convention d'écriture, posée le 2026-09-09 et non mécanisée : quand
une phrase du dépôt publie une mesure — une durée, un volume, un compte, un ratio —, elle nomme, à
côté du nombre, **la date** et **l'instrument** qui l'a produit : « 256 s (mesuré le 2026-09-09 par
`cargo test --locked`, 12 cœurs) », « 19 sites (mesuré le 2026-09-09 par
`le_portillon_clos_avoue_sur_le_routeur_reel_et_se_tait_quand_il_ouvre`) ». Mesuré le 2026-09-02 :
sur mille trente-quatre lignes portant un nombre et une unité physique, six nommaient leur témoin ;
une garde qui l'exigerait aujourd'hui accuserait presque tout le corpus, donc elle n'existe pas —
c'est la convention qui doit d'abord faire sa population, ligne neuve après ligne neuve. Un chiffre
sans témoin n'est pas faux ; il est invérifiable, et il vieillit sans que rien ne le dise.

## Parité des traductions

**L'anglais d'abord.** Chaque document existe en deux langues : l'original `X.md`, en anglais, et
sa traduction française `X.fr.md`, à côté. Une modification d'un document touche ses deux langues
dans le même commit. `.github/scripts/check_every_document_is_paired_and_in_parity.py` y tient
l'arbre, dans l'intégration continue et dans la batterie de gardes : un document suivi sans sa
paire, ou tout écart de parité décrit ci-dessous, la fait échouer. Un document reste en une seule
langue, et il est nommé : `docs/ROADMAP.md` (le journal de travail, tenu en français).

Un document traduit garde les faits de son original : mêmes titres (nombre et niveaux), mêmes blocs
de code et mêmes commandes hors commentaires, mêmes tableaux, mêmes cibles de liens — un lien vers
`Y.md` vise `Y.fr.md` côté français quand ce fichier existe —, mêmes nombres et mêmes identifiants
entre accents graves (un segment de code replié sur deux lignes reste un seul segment, la fin de
ligne y valant une espace). Les deux fichiers portent le sélecteur de langue sur la première ligne
non vide sous leur titre de niveau 1, la même ligne des deux côtés, qui nomme l'original puis la
traduction : `[English](X.md) | [Français](X.fr.md)` ; absent, inversé ou visant un autre fichier,
c'est un écart. Dans la traduction, une ancre `#…` vers un document Markdown de l'arbre désigne un
titre qui existe dans le fichier visé, par son slug GitHub (minuscules, ponctuation retirée, espaces
en tirets, accents conservés, `-1`, `-2` pour un titre en double) : une ancre restée sur le titre de
l'original est nommée comme telle ; les ancres de l'original ne sont pas jugées.
`.github/scripts/parite_des_langues.py` compare le tout et nomme chaque écart par fichier et ligne :

```sh
python3 .github/scripts/parite_des_langues.py                      # toutes les paires suivies
python3 .github/scripts/parite_des_langues.py --paire X.md X.fr.md # une seule paire
python3 .github/scripts/parite_des_langues.py --inventaire         # documents sans leur paire
python3 .github/scripts/test_parite_des_langues.py                 # épreuves de l'outil
python3 .github/scripts/check_every_document_is_paired_and_in_parity.py # la garde
```

La convention de suffixe est un paramètre (`--suffixe-original`, `--suffixe-traduction`, par défaut
`X.md` / `X.fr.md`). Les documents tenus en une seule langue sont un ensemble nommé,
`UNE_SEULE_LANGUE`, chacun avec sa raison ; il porte `docs/ROADMAP.md`, le journal de travail tenu
en français. L'inventaire nomme tout autre document suivi sans sa paire, et toute entrée de l'ensemble
qui a retrouvé sa paire ou n'est plus suivie ; il rend vert tant que `--strict` n'est pas passé. En
comparaison, l'outil rend 1 dès qu'un écart est nommé, même si une autre paire n'a pas pu être lue
(elle est nommée) ; il rend 2 quand il n'y a aucun écart et que quelque chose n'a pas été lu (zéro
document suivi, zéro paire, fichier illisible, y compris un fichier visé par une ancre de la
traduction).
