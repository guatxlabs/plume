# Store DuckDB — tier analytique TIÈDE (#15) — **EXPÉRIMENTAL**

[English](DUCKDB-STORE.md) | [Français](DUCKDB-STORE.fr.md)

Statut : **OPT-IN, INERTE PAR DÉFAUT, EXPÉRIMENTAL.** Cloisonné par feature (`--features duckdb`),
sélectionné à l'exécution par `PLUME_STORE=duckdb`. Absent du build PME/prod et du déploiement de prod.
**Le défaut reste `SqlcipherStore` (SQLite/SQLCipher), byte-identique à aujourd'hui.**

DuckDB est un moteur analytique **embarqué, colonnaire, sans serveur externe**. Il occupe une niche
distincte dans le principe de sur-ensemble (analytique sur une seule machine « apportez-votre-absence-
d'infra », isolée du réseau). Mais ce n'est **pas la voie de montée en charge supportée** — **c'est
ClickHouse** (voir [`CLICKHOUSE-STORE.md`](./CLICKHOUSE-STORE.fr.md)). DuckDB reste un tier
expérimental/de montée en charge : garder la capacité, **ne pas** le livrer comme backend que le client
pourrait sélectionner sur le nœud de 2 Go.

> **À lire d'abord.** Le *coût de build* comme l'*empreinte à l'exécution* de DuckDB sont réels. Ce tier
> est destiné à un **hôte de build+exécution d'ESN/MSSP**, jamais au VPS mono-nœud de 2 Go.

---

## 1. Sémantique du sélecteur `PLUME_STORE`

> ⚠️ **CONÇU, PAS ENCORE CÂBLÉ.** `PLUME_STORE` n'est **lue nulle part dans le démon** — `grep -rn '"PLUME_STORE"' daemon/src`
> ne rend rien. La poser n'a **aucun effet** : le démon utilise toujours `SqlcipherStore`. La seule variable
> de store réellement lue aujourd'hui est `PLUME_STORE_DUCKDB_EXPERIMENTAL` (`daemon/src/ingest/duckdb_store.rs`).
> Le tableau ci-dessous est le contrat de sélecteur **prévu**, conservé comme conception de référence. Ne pas
> le traiter comme une documentation d'exploitant tant qu'aucun chemin d'exécution ne lit la variable.

`PLUME_STORE` est conçue pour choisir le store du plan de données à l'exécution. **Non posée ⇒ `SqlcipherStore` (défaut, intact).**

| `PLUME_STORE` | Store | Feature de build | Tier | Support |
|---|---|---|---|---|
| *(non posée)* | `SqlcipherStore` (SQLite/SQLCipher) | *(aucune — build par défaut)* | CHAUD, mono-nœud, chiffré au repos | **★ Défaut / PME / prod** |
| `duckdb` | `DuckDbStore` (colonnaire embarqué) | `--features duckdb` | TIÈDE, analytique mono-nœud | **Expérimental** |
| `clickhouse` | `ClickHouseStore` (cluster externe) | `--features clickhouse` | FROID/échelle, multi-nœud | Montée en charge supportée |

- Le build par défaut (sans `--features`) ne lie **ni** `duckdb` **ni** `clickhouse` — byte-identique en
  mode 0. Un `PLUME_STORE=duckdb` sur un binaire par défaut n'a aucun `DuckDbStore` compilé.
- L'aiguillage de sélection à l'exécution (remplacer `store()` sur les ~82 sites d'appel du démon) est un
  **chantier ultérieur différé** pour tous les stores hors défaut ; aujourd'hui les adaptateurs sont exercés
  par leur propre API + leurs tests, et non en basculant la variable d'environnement en prod (même étagement
  que pour ClickHouse — voir la note du §2.1 de `CLICKHOUSE-STORE.md`).

---

## 2. Coût de build — pourquoi `--features duckdb` est lourd, et comment on l'a désamorcé

### 2.1 L'ancien piège (bundled)

Auparavant, la dépendance était `duckdb = { … features = ["bundled"] }`. `bundled` force `libduckdb-sys` à
**compiler depuis les sources l'amalgamation C++ de DuckDB** via la crate `cc` — un bloc C++ de plusieurs Mo
en une seule unité de traduction. `cc1plus` sur cette seule unité demande **~4 Go de RAM de build** et **des
minutes de CPU sur un seul cœur**. Concrètement :

- Sur le **VPS de 2 Go** (pas de chaîne d'outils C++ — seul un compilateur C est présent, pour le SQLCipher
  embarqué dans les sources) : il meurt aussitôt avec `cc-rs: failed to find tool "c++"`.
- Sur une **machine de dev dotée d'une chaîne d'outils C++** : il sature la mémoire / bloque un cœur à ~90 %
  pendant des minutes.

C'était un **piège de build déclenché par un drapeau** (l'image de prod *par défaut* ne l'a jamais
déclenché — elle se construit sans `--features`), mais un piège sévère pour quiconque tapait
`--features duckdb`.

### 2.2 Le correctif (dégroupé → lier une libduckdb système)

`features = ["bundled"]` a été **retiré** (`daemon/Cargo.toml`). Sans `bundled`, `libduckdb-sys` utilise des
**liaisons pré-générées** (pas de `bindgen`/libclang) et cherche une **`libduckdb` système/précompilée** via
`pkg-config` / `DUCKDB_LIB_DIR` (ou un téléchargement précompilé avec `DUCKDB_DOWNLOAD_LIB`), puis se
contente de **lier** `-lduckdb`. **Pas de `cc1plus`, pas de compilation d'amalgamation, aucune exigence de
chaîne d'outils C++, pas de saturation mémoire.**

Compromis / exigence :

- `--features duckdb` **exige désormais une `libduckdb` présente sur l'hôte de build**. La fournir par l'un
  de ces moyens :
  - une installation système (`libduckdb-dev` / un `duckdb.pc` sur le chemin de `pkg-config`), ou
  - `export DUCKDB_LIB_DIR=/path/to/libduckdb` (et `DUCKDB_INCLUDE_DIR` si les en-têtes sont nécessaires), ou
  - `export DUCKDB_DOWNLOAD_LIB=1` pour laisser `libduckdb-sys` récupérer un binaire précompilé.
- Si **aucune** `libduckdb` n'est présente, le build échoue à l'étape d'**édition de liens** avec un
  `cannot find -lduckdb` **clair et rapide** — **et non** la lente agonie opaque de cc1plus (saturation
  mémoire / 90 % de CPU) d'avant. C'est le mode d'échec voulu, bien meilleur, sur un hôte qui ne devrait de
  toute façon pas construire DuckDB.
- La crate Rust `arrow` est **toujours compilée** (une dépendance tirée par `duckdb`), si bien que DuckDB
  double à peu près la surface de build Rust quoi qu'il arrive. **Construire DuckDB sur un véritable hôte
  d'ESN/MSSP, jamais sur le VPS.**

```bash
# Sur un hôte de build d'ESN/MSSP AVEC une libduckdb système/précompilée :
export DUCKDB_LIB_DIR=/opt/duckdb/lib        # ou installer libduckdb-dev / poser DUCKDB_DOWNLOAD_LIB=1
cargo build --release --features duckdb
```

---

## 3. Empreinte à l'exécution — plafonds (GAP-4)

DuckDB est **embarqué** : sa RAM vit **dans le pod plume**, en concurrence directe avec le budget de 2 Go.
Le `memory_limit` par défaut de DuckDB vaut ~**80 % de la RAM du système** et il prend
**tous les cœurs** — un seul gros parcours peut faire évincer le pod par manque de mémoire. `DuckDbStore`
impose donc des plafonds (`daemon/src/ingest/duckdb_store.rs::query_soql_masked`) :

| Enjeu | Application | Surcharge par l'environnement | Défaut |
|---|---|---|---|
| Mémoire | PRAGMA `SET memory_limit='…'` sur la connexion | `PLUME_DUCKDB_MEMORY_LIMIT` | `512MB` |
| CPU | PRAGMA `SET threads=N` | `PLUME_DUCKDB_THREADS` (borné à 1–8) | `2` |
| Durée de requête | fil chien de garde + `InterruptHandle` de DuckDB (reflet du chien de garde SQLite de `run_query_ex`) | `budget_ms` (fourni par l'appelant, comme pour le tier chaud) | 5 s auto / 60 s interactif |
| Plafond de rangées | `max_rows` à l'assemblage du résultat | `PLUME_QUERY_MAX` | 5000 |

- **`budget_ms` est respecté.** Un chien de garde interrompt une requête qui s'emballe au budget et rend une
  erreur claire « budget dépassé » (pas un 500 opaque) — le même schéma que le store SQLite par défaut.
- **La valeur d'environnement de `memory_limit` est validée contre l'injection** (`is_valid_memory_limit`) :
  seul `<number><unit>` (B/KB/MB/GB/TB, binaire ou décimal) est accepté avant d'être interpolé dans `SET` ;
  tout le reste retombe sur le défaut. Aucune évasion de la chaîne `SET` n'est possible.
- **`qid`** est propagé/tracé (il n'est plus ignoré). L'annulation externe par `/api/cancel` n'est **pas**
  encore câblée vers DuckDB — le registre des annulations en cours (`QUERY_CANCEL`) est typé sur
  `rusqlite::InterruptHandle` ; un registre neutre vis-à-vis du backend est un chantier ultérieur documenté.
  Le chien de garde `budget_ms` suffit à borner la consommation de ressources en attendant.

### 3.1 Barrière expérimentale

`DuckDbStore` n'est **pas sélectionnable en silence par le client**. La première requête journalise un
**avertissement bruyant**, sauf si l'exploitant acquitte avec `PLUME_STORE_DUCKDB_EXPERIMENTAL=1` :

```
[store] ⚠️  DuckDbStore (PLUME_STORE=duckdb) est un tier WARM EXPÉRIMENTAL, NON supporté en prod …
        Posez PLUME_STORE_DUCKDB_EXPERIMENTAL=1 pour acquitter …
```

La barrière ne bloque pas durement (les plafonds d'exécution sont déjà appliqués) ; son but est qu'un tier
non supporté ne soit jamais activé sans un acquittement délibéré et journalisé.

---

## 4. Notes de parité de sécurité

- **Masquage (#45)** — fail-closed. `soql_to_sql_masked` émet les masques par le point de passage unique
  `DuckDbDialect` ; une action non portable (`Hash` → une UDF absente de DuckDB) lève une **erreur
  d'exécution** (fail-closed) plutôt que de laisser fuir du texte en clair vers un rôle restreint.
- **Liste de refus des colonnes secrètes** — sans objet ici : les secrets du plan de contrôle (`user.hash`,
  `token.token_hash`) ne sont **jamais** dans le store du plan de données ; seuls `event`/`metric`/`snapshot`
  vivent dans DuckDB.
- **Le chiffrement au repos est DÉGRADÉ** par rapport au tier chaud SQLCipher (pas d'AES sur le fichier
  entier avec clé par tenant détenue par l'application). Comme pour ClickHouse, c'est une affaire
  d'exploitant/de chiffrement de disque, pas du niveau SQLCipher. Les clients PME qui ont choisi plume *pour*
  le chiffrement à clé détenue par l'application doivent rester sur le tier chaud.

---

## 5. Couverture de tests

Tests unitaires hors ligne (`cargo test --features duckdb`, aucune libduckdb n'est nécessaire pour ces
chemins purs — mais la crate elle-même doit se lier, donc à lancer sur un hôte doté de `libduckdb`) :

- `duckdb_store_masked_emission_threads_masks` — l'émission masquée propage les masques (fail-closed), des
  masques vides donnent un résultat byte-identique au chemin non masqué.
- `duckdb_memory_limit_is_injection_safe` — la validation de `memory_limit` accepte les formes de taille de
  DuckDB et refuse les tentatives d'injection dans `SET`.
- `duckdb_threads_bounded` — plafond de fils borné à [1..=8].

Le `cargo test` **par défaut** (SqlcipherStore seul) est inchangé et vert — le module DuckDB et ses tests ne
sont **pas compilés** sans `--features duckdb`.

---

## 6. En résumé

Garder DuckDB comme option **expérimentale d'analytique embarquée** (principe de sur-ensemble), construite sur
un véritable hôte d'ESN/MSSP doté d'une `libduckdb` système, derrière la barrière
`PLUME_STORE_DUCKDB_EXPERIMENTAL=1`, avec les plafonds d'exécution appliqués. **Ne jamais la construire sur le
VPS de 2 Go. Ne jamais en faire le défaut PME. Pour la montée en charge, utiliser
ClickHouse** — la voie supportée, légère, en pur Rust, qui externalise le calcul.
