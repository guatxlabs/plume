# Plume — Importeur Sigma (Slice #7, pièce 3)

> **Statut : contrat opérateur.** Absorbe la bibliothèque de détection **open-source** :
> [Sigma](https://github.com/SigmaHQ/sigma) est le standard YAML des règles de détection (logsource +
> `detection{selection/condition}` + tags MITRE). Cet importeur **traduit une règle Sigma en une règle
> de détection Plume** — une requête **SOQL** + les métadonnées (`title`, `level` → sévérité,
> `tags: attack.Txxxx` → MITRE). C'est **ADDITIF** : une règle Sigma = des lignes `rule` en plus, **zéro
> impact data-plane / mode 0**.

- **Ancre code** : `sigma_translate` / `sigma_field_tokens` / `sigma_parse_condition` /
  `sigma_yaml_to_docs` (`daemon/src/sigma.rs`), loader `load_overlay_sigma`, handler `sigma_import`,
  sous-commande CLI `sigma-import`.
- **Le pivot, c'est le CIM** (`docs/CIM.md`) : le mapping `logsource → category` et les champs cœur
  (`src_ip`/`dst_ip`/`url`/…) viennent de ce contrat. Une règle Sigma compose sur la `category` NEUTRE,
  donc elle est **vendor-agnostique** (le même « firewall deny » fire sur FortiGate, ufw, nft…).

---

## 0. Principes directeurs

1. **JAMAIS une règle silencieusement fausse.** Un construit non exprimable **fidèlement** en SOQL est
   **signalé + ignoré** avec une raison claire (`skipped: [{title, reason}]`), **jamais** émis comme une
   règle qui **sous-matche** (= angle mort) ou sur-matche en silence. Une règle Sigma mal traduite qui ne
   fire pas serait pire que pas de règle. La couverture ci-dessous est le **sous-ensemble commun** ;
   l'inexprimable est rejeté (voir §4).
2. **Injection impossible.** Aucune valeur Sigma n'est interpolée « à cru » dans du SQL. Chaque valeur
   string devient un **motif REGEXP** construit par un encodeur qui n'émet **que des caractères inertes**
   pour le tokenizer SOQL (les caractères STRUCTURELS — espace, `|`, `"`, `()`, `[]`, `,`, `'`, backtick —
   sont hex-échappés `\xNN` ; le moteur regex les décode, le découpage SOQL/pipe/`in` ne les voit pas). La
   requête finale est **recompilée par le compilo SOQL du cœur** (`soql_to_sql_x`) avant tout stockage : un
   SOQL qui ne compile pas est **rejeté** (garde-fou ultime).
3. **ENRICH / ADD, jamais réduire.** Importer une règle **ajoute** une détection ; ça n'en supprime ni
   n'en filtre aucune. Un `logsource` non mappé n'est **pas un drop** : la règle est importée (appliquée à
   toutes les sources) avec un **avertissement** de sur-match potentiel.

---

## 1. Comment importer — trois voies

| voie | usage | `managed` | commande |
|------|-------|:---------:|----------|
| **`config.d/sigma/`** | **GitOps** (durable, reviewé, baked dans l'image) | `1` | déposer `*.yml`/`*.yaml`/`*.json`, chargé au boot |
| **CLI** | import ponctuel / **pré-vol** (`--dry-run`) | `2` | `plume-daemon sigma-import <fichier\|dossier> [--dry-run]` |
| **API admin** | UI / automatisation | `2` | `POST /api/sigma/import` (**admin**) |

- **CLI** — `plume-daemon sigma-import ./rules/ --dry-run` affiche un **rapport JSON**
  (`imported[]` / `skipped[{title,reason}]` / `summary`) **sans écrire** ; sans `--dry-run`, UPSERT par
  nom dans `PLUME_DB` (`managed=2`).
- **API** — corps `{"content":"<yaml|json>","dry_run":false}` (texte Sigma, multi-docs `---` OK) **ou**
  `{"rules":[<sigma json>…]}`. Réponse `{imported:[…], skipped:[…]}`. Gate RBAC : la route `/api/sigma/*`
  tombe en **DEFAULT-DENY = admin** (l'import en masse de détections externes est privilégié).
- **UPSERT par `title`.** Ré-importer est idempotent. L'import **ne remplace jamais** une règle overlay
  git (`managed=1`) — elle est `skipped` (retirez-la côté git pour la remplacer).

Un fichier Sigma multi-documents (`---`) est supporté (un fichier peut porter N règles).

---

## 2. Le modèle de sortie — une règle Plume

Une règle Sigma « match » (fire dès qu'un event correspond) devient :

```
query      = search <category?> <champs…> | stats count
is_soql    = 1
op / seuil = ">" / 0        # fire s'il existe ≥ 1 event matchant dans la fenêtre
window_s   = 3600           # fenêtre glissante
interval_s = 300            # cadence d'évaluation
severity   = level → 0..4   # cf. §3
mitre      = 1re tag attack.Txxxx[.yyy] → Txxxx[.yyy] (norm_mitre)
name       = title
```

`| stats count` renvoie **un** nombre (le compte des events matchants) ; `run_due_rules` compare `count
> 0` → alerte, qui **hérite** de `severity` et `mitre` (mesure de couverture MITRE, purple-team).

### 3. `level` → sévérité (0..4, cf. `docs/CIM.md` §3)

| Sigma `level` | `informational` | `low` | `medium` (défaut) | `high` | `critical` |
|---------------|:---------------:|:-----:|:-----------------:|:------:|:----------:|
| Plume `severity` | 0 | 1 | 2 | 3 | 4 |

---

## 4. Matrice de couverture

### 4a. logsource → `category` (CIM)

Priorité `category` > `service` > `product`. Table `SIGMA_LOGSOURCE_CATEGORY` (extensible). Exemples :

| Sigma logsource | CIM `category` | | Sigma logsource | CIM `category` |
|-----------------|:--------------:|-|-----------------|:--------------:|
| `firewall`      | `firewall`     | | `process_creation`, `image_load`, `registry_event`, `file_event`… | `endpoint` |
| `proxy`, `webserver`, `apache`, `nginx` | `web` | | `network_connection`, `netflow` | `network` |
| `dns`           | `dns`          | | `kubernetes` | `k8s` |
| `antivirus`, `clamav` | `malware` | | `falco` | `ebpf` |
| `authentication`, `sshd`, `sudo` | `auth` | | `container` | `container` |
| `email`, `smtp` | `mail`         | | `vpn`, `dlp` | `vpn`, `dlp` |

**logsource non mappé** → règle importée **sans** filtre `category=` (s'applique à toutes les sources),
avec un **avertissement** (sur-match possible). Jamais un drop.

### 4b. Champs Sigma → champs Plume

**Deux questions distinctes, deux tables distinctes.** *Traduire* un nom (« ce champ Sigma s'écrit comment
chez Plume ? ») et *savoir s'il est peuplé* (« Plume collecte-t-il cette donnée ? ») sont des questions
différentes. Les confondre ferait qu'**ajouter un alias éteindrait l'avertissement d'inertie** sans qu'une
seule donnée nouvelle soit collectée — du silence pris pour de la couverture.

**Traduction** (`SIGMA_FIELD_ALIAS`, `daemon/src/sigma.rs`) :

- **Alias connus** → colonnes cœur : `SourceIp`/`src_ip`/`SourceAddress` → `src_ip` ;
  `DestinationIp`/`dst_ip` → `dst_ip` ; `DestinationPort`/`dst_port` → `dport` ; `Url`/`Uri` → `url` ;
  `User`/`TargetUserName`/`Account` → `user` ; `Hostname`/`ComputerName` → `host`.
- **Sinon** : le nom Sigma est utilisé **tel quel** comme champ étendu → `fields.<Nom>` (via `json_extract`,
  **casse préservée**).
- **Nom imbriqué / à points / tiret** (`winlog.event_data.X`) → **non mappable** (`json_extract` 1 niveau) →
  la règle est **flaggée** (skip).

**Inertie** (`COLLECTED_EXTENDED_FIELDS`, `daemon/src/collected.rs`) : une fois le champ traduit, l'importeur
**avertit** si *aucun collecteur, parseur ou agent livré n'écrit ce champ*. L'inventaire est une table
`(champ, fichier livré qui l'émet)` dont chaque entrée est **citée**. Une garde de test
(`collected_inventory_is_backed_by_shipped_collectors`) vérifie les deux sens **avec le même extracteur** :

- **(A) pas d'entrée que personne n'émet** — le champ doit être **extrait** du fichier cité, donc y figurer
  en **position de producteur** (objet `fields` littéral, insertion par clé littérale, `af(…)` awk, fragment
  JSON échappé, overlay de parseur). Une occurrence quelconque du nom **ne suffit pas** : `web.sh` *lit* la
  clé Traefik `RequestPath` sans jamais l'émettre, l'entrée `("RequestPath","web.sh")` est **rejetée** ;
- **(B) pas de champ émis qui manque à l'inventaire** — l'extraction couvre les formes réellement livrées :
  JSON échappé shell/awk, `jq` (clés non quotées), `serde_json::json!` de l'agent, dictionnaire Python,
  hashtable PowerShell, overlays `config.d/parsers/*.json` ;
- **(C) anti-rot par famille** — chaque famille de collecteurs a un **plancher d'extractions** : en perdre une
  entière (chemin déplacé, syntaxe d'émission changée) fait rougir la garde au lieu de passer inaperçu.

Conséquences :

- un **alias vers une cible non collectée** reste **signalé inerte** — l'alias traduit, il ne collecte pas ;
- l'avertissement **ne rejette jamais** la règle (la donnée peut arriver plus tard) ;
- **mise à jour** : un collecteur qui se met à émettre `fields.<X>` (ou qui cesse) fait **rougir la garde**
  tant que l'inventaire n'est pas ajusté.

**Ce que l'inventaire ne couvre pas** (surfaces **ouvertes**, définies au déploiement — donc non
inventoriables statiquement ; leurs champs restent **signalés inertes**, c'est-à-dire *sur*-avertis) : la
recopie verbatim des clés `EventData` du log Windows, les champs des sources déclaratives `[[source]]`, et
les overlays de parseurs ajoutés par l'exploitant après déploiement. `collected.rs` en donne la liste exacte,
ainsi que la **limite** du contrôle de citation : il exige une position de producteur, il n'est pas
infalsifiable.

### 4c. Modificateurs de champ

| Sigma | → SOQL | note |
|-------|--------|------|
| *(aucun)* | `field=~(?i)^…$` (ou `field=n` si entier) | **égalité** ; jokers Sigma `*`/`?` **actifs** (→ `.*`/`.`) |
| `\|contains` | `field=~(?i)…` | sous-chaîne (non ancré) |
| `\|startswith` | `field=~(?i)^…` | ancré début |
| `\|endswith` | `field=~(?i)…$` | ancré fin |
| `\|re` (`\|re\|i`) | `field=~…` (`(?i)…`) | regex brut, **si** embarquable (pas de `\|`/`()`/`[]`/espace → sinon flag) |
| `\|all` (+ liste) | plusieurs tokens en **ET** | ex. `contains\|all` |
| `\|lt \|lte \|gt \|gte` | `field< <= > >= n` | numérique |

> **Casse.** Les comparaisons string sont **casse-insensibles** (`(?i)`, conforme au défaut Sigma — et
> sûr : sur-match plutôt que sous-match). **Exception** : une liste OU en `in(...)` compare avec `=`
> (**sensible à la casse**) — signalé par un **avertissement** (membres à casse variable à vérifier).

### 4d. Valeurs

- **string** → motif regex hex/backslash-échappé (injection-safe, cf. §0.2).
- **jokers Sigma** `*` (→ `.*`), `?` (→ `.`), `\*`/`\?`/`\\` littéraux (égalité uniquement).
- **entier** en égalité → comparaison numérique exacte `field=n`.
- **liste** (OU d'égalités, sans joker) → `field in (a,b,c)` ; **liste + `\|all`** → **ET** de matchs.
- **`null`** (existence de champ) → **non exprimable** → flag.

### 4e. Condition

| supporté | ex. |
|----------|-----|
| sélection simple | `selection` |
| conjonction | `sel1 and sel2` |
| exclusion (négation d'une **égalité simple / liste d'égalités**) | `selection and not filter` → `field!=v` / `field not in (…)` |
| quantificateurs `all of` | `all of them`, `all of selection*` |
| parenthèses (autour d'une conjonction) | `(sel1 and sel2) and not filter` |

**Non supporté (flag) :** `or` / OU inter-champs ; `1 of them` / `any of` (OU) ; agrégations
`… | count() by X > N` ; négation d'une sélection **multi-champs** ou **avec modificateur** (pas de
`NOT REGEXP` en SOQL) ; liste OU de **sous-chaînes** (`contains` + liste sans `|all`) ; **modificateurs**
`base64`/`base64offset`/`utf16`/`wide`/`cidr`/`windash`.

> **Pourquoi rejeter l'OU ?** Le `search` SOQL conjugue ses filtres en **ET** ; le seul OU disponible est
> `field in (…)` (OU d'égalités sur **un** champ). Un OU inter-champs (`a or b`, `1 of them`) n'a pas de
> forme SOQL fidèle → le traduire approximativement **sous-matcherait** (angle mort). On préfère
> **flagger** honnêtement. (Le champ reste importable manuellement, ou via plusieurs règles.)

---

## 5. Exemples livrés (`config.d/sigma/`)

| fichier | démontre | SOQL produit |
|---------|----------|--------------|
| `firewall-denied-nonstandard-port.yml` | `logsource.category`→`firewall`, égalité, **négation de liste** | `search category=firewall action=~(?i)^deny$ dport not in (80,443) \| stats count` |
| `web-admin-path-blocked.yml` | `\|startswith` + égalité en **ET** | `search category=web action=~(?i)^blocked$ url=~(?i)^\/admin \| stats count` |
| `process-whoami-discovery.yml` | Sysmon `process_creation`→`endpoint`, champ étendu `\|contains` | `search category=endpoint CommandLine=~(?i)whoami \| stats count` |

Pré-vol : `plume-daemon sigma-import config.d/sigma --dry-run`.

---

## 6. Ce que l'importeur n'est PAS

- Pas un moteur Sigma complet : il cible le **sous-ensemble exprimable en SOQL** (§4). Le reste est
  **flaggé**, jamais deviné.
- Pas un chemin de **filtre/suppression** : une règle importée **ajoute** une détection (cf. principe #3).
- Pas un backend de **corrélation temporelle** (`timeframe`/agrégation Sigma) : hors périmètre → flag.
