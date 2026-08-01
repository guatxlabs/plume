# Plume — Importeur Sigma (Slice #7, pièce 3)

> **Statut : contrat opérateur.** Absorbe la bibliothèque de détection **open-source** :
> [Sigma](https://github.com/SigmaHQ/sigma) est le standard YAML des règles de détection (logsource +
> `detection{selection/condition}` + tags MITRE). Cet importeur **traduit une règle Sigma en une règle
> de détection Plume** — une requête **GXQL** + les métadonnées (`title`, `level` → sévérité,
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

1. **JAMAIS une règle silencieusement fausse.** Un construit non exprimable **fidèlement** en GXQL est
   **signalé + ignoré** avec une raison claire (`skipped: [{title, reason}]`), **jamais** émis comme une
   règle qui **sous-matche** (= angle mort) ou sur-matche en silence. Une règle Sigma mal traduite qui ne
   fire pas serait pire que pas de règle. La couverture ci-dessous est le **sous-ensemble commun** ;
   l'inexprimable est rejeté (voir §4).
2. **Injection impossible.** Aucune valeur Sigma n'est interpolée « à cru » dans du SQL. Chaque valeur
   string devient un **motif REGEXP** construit par un encodeur qui n'émet **que des caractères inertes**
   pour le tokenizer GXQL (les caractères STRUCTURELS — espace, `|`, `"`, `()`, `[]`, `,`, `'`, backtick —
   sont hex-échappés `\xNN` ; le moteur regex les décode, le découpage GXQL/pipe/`in` ne les voit pas). La
   requête finale est **recompilée par le compilo GXQL du cœur** (`soql_to_sql_x`) avant tout stockage : un
   GXQL qui ne compile pas est **rejeté** (garde-fou ultime).
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

Priorité `category` > `service` > `product`. Table `SIGMA_LOGSOURCE_CATEGORY` — **40 entrées, 16
catégories cibles distinctes** (compté dans `daemon/src/sigma.rs`).

| Sigma logsource | CIM `category` | | Sigma logsource | CIM `category` |
|-----------------|:--------------:|-|-----------------|:--------------:|
| `firewall`, `firewall_traffic` | `firewall` | | **`process_creation`** | **`exec`** |
| `proxy`, `webserver`, `apache`, `nginx`, `modsecurity`, `web` | `web` | | `process_access`, `image_load`, `driver_load`, `create_remote_thread`, `file_event`/`_change`/`_delete`, `registry_event`/`_set`/`_add`/`_delete` | `endpoint` |
| `dns`, `dns_query` | `dns`          | | `network_connection`, `netflow` | `network` |
| `antivirus`, `av`, `clamav` | `malware` | | `kubernetes` | `k8s` |
| `authentication`, `auth`, `sshd`, `sudo` | `auth` | | `falco` | `ebpf` |
| `email`, `smtp` | `mail`         | | `container` | `container` |
| `vpn`, `dlp` | `vpn`, `dlp` | | `syslog`, `system` | `syslog`, `system` |

**logsource non mappé** → règle importée **sans** filtre `category=` (s'applique à toutes les sources),
avec un **avertissement** (sur-match possible). Jamais un drop.

#### La règle qui gouverne cette table : *une cible sans émetteur est pire qu'une absence de mapping*

Un mapping vers une catégorie que **rien ne produit** fabrique une couverture **apparente** : la règle
s'importe, se catégorise, apparaît « couverte », et ne peut **jamais** fire. Non mappée, elle est
**visiblement** non catégorisée. Toute cible de la table est donc adossée à une **citation vérifiée
mécaniquement** — `(catégorie, fichier livré, fragment émetteur)` dans `SIGMA_TARGET_CATEGORY_EMITTERS`,
gardée dans les deux sens par `sigma_logsource_targets_are_emitted_by_a_shipped_collector` : pas de
citation fantôme (le fragment doit être présent dans le fichier cité), pas de cible sans citation
(mapper vers une catégorie non mesurée fait **rougir** la CI). Même contrat que
`collected::COLLECTED_EXTENDED_FIELDS` pour les champs, appliqué ici à l'axe `category`.

Deux entrées ont été corrigées sur ce critère :

- **`process_creation` → `exec`** (et non plus `endpoint`). La création de processus Windows
  (**EventID 4688**) est émise en `exec` — le nom canonique CIM v1.3 — par les **deux** collecteurs
  Windows livrés (`agent/src/source/windows.rs` : `4688 => ("exec"…)` ; `plume-collector.ps1` :
  `-Ids @(4688) … -Category 'exec'`) **et** par le flux Linux `collectors/auditd.sh` (`execve`). Tant
  que la table visait `endpoint`, **toute règle Sigma `process_creation` importée était aveugle à la
  télémétrie qu'elle vise** — la famille de règles la plus nombreuse de SigmaHQ.
- **`ps_script` : retiré** (donc non mappé). PowerShell Script Block Logging (EventID 4104, canal
  `Microsoft-Windows-PowerShell/Operational`) n'a **aucun** émetteur livré : le canal n'est ni dans les
  canaux par défaut de l'agent (`d_win_channels`) ni dans les `-LogName` du collecteur PowerShell, et
  `map_cim` rendrait de toute façon une catégorie **vide** pour lui. Pour brancher cette famille il faut
  d'abord **produire** la télémétrie (parseur/source déclarative), puis mapper.

#### Ce que chaque catégorie exige RÉELLEMENT de l'exploitant

Mesuré en lisant les émetteurs livrés (`collectors/`, `collectors/windows/`, `agent/src/`,
`collector-syslog/`, `collector-mail/`, `config.d/parsers/`, presets d'ingest du daemon).

> **Cadrage indispensable, mesuré dans `bootstrap.sh` : plume n'installe AUCUN paquet.** Il déploie les
> collecteurs + leurs timers systemd, et *arme* les règles auditd **si `augenrules` est déjà présent**
> (sinon il le dit : « auditd absent … sinon auditd.sh reste inerte »). Chaque ligne ci-dessous nomme donc
> ce que **l'exploitant** doit avoir sur l'hôte. Sans lui la catégorie reste **vide** et les règles Sigma
> qui la visent sont **inertes** — c'est signalé à l'import, jamais silencieux.

| CIM `category` | émetteur livré (exemple) | prérequis sur l'hôte |
|----------------|--------------------------|----------------------|
| `auth` | agent `source/linux.rs` (journald : sshd/sudo/su) | **journald** — présent sur toute distro systemd, donc le cas le plus courant |
| `firewall` | `collectors/ufw.sh`, `nft.sh`, `origin-drop.sh`, `portscan.sh`, `portprobe.sh` | **ufw** et/ou **nftables** (collecteurs en lecture, rien n'est installé) |
| `exec` | `collectors/auditd.sh` (`execve`) ; EventID 4688 côté Windows | **auditd installé** (les règles sont armées par `bootstrap.sh`) ; côté Windows, la politique d'audit « Audit Process Creation » |
| `network` | `collectors/conntrack.sh`, `crowdsec.sh` | **conntrack** (paquet `conntrack-tools`) |
| `web` | `collectors/web.sh`, `cloudflare.sh`, `cloudflare-http.sh` | un front web dont les logs d'accès sont lisibles (Traefik/nginx) ou le feed Cloudflare |
| `syslog` | `collector-syslog/src/parser.rs` (parser Generic) | le récepteur syslog `collector-syslog` déployé et des équipements qui y envoient |
| `malware` | `clamav.sh`, `yara.sh`, `plume-collector.ps1` (Defender) | un scanner : **ClamAV** / **YARA** / **Defender** |
| `k8s` | `kube-audit.sh`, `kube-state.sh`, `pod-logs.sh` | un **cluster Kubernetes** (+ audit log activé) |
| `container` | `collectors/containerd.sh` | **containerd** |
| `ebpf` | `collectors/falco.sh` | **Falco** |
| `mail` | `collector-mail/src/main.rs` | le service `collector-mail` branché sur une pile mail |
| `dns` | agent Sysmon ID 22, `suricata.sh`, FortiGate `utm/dns` | **Sysmon** ou **Suricata** ou **FortiGate** |
| `endpoint` | agent `map_cim` (Sysmon hors ID 1/3/22 ; Security 4697/1102 ; System 7045/7036/7040), FortiGate `event/endpoint`/`ems`/`connector` | **Sysmon** (+ agent plume sur l'hôte Windows) ou **FortiGate EMS** |
| `system` | `plume-collector.ps1`, FortiGate `event/system` | le **collecteur Windows** ou **FortiGate** |
| `vpn` | `collector-syslog/src/fortigate.rs` (`event/vpn`) | **FortiGate** |
| `dlp` | `collector-syslog/src/fortigate.rs` (`utm/dlp`) | **FortiGate** |

**Lecture pratique.** Sur un hôte Linux systemd sans composant tiers ajouté, les familles Sigma qui
peuvent réellement fire sont celles adossées à `auth` (`authentication`, `auth`, `sshd`, `sudo`) ; en
ajoutant les paquets `auditd`, `ufw`/`nftables` et `conntrack-tools` — que plume n'installe pas — s'y
joignent `process_creation` (via l'`execve` auditd), `firewall` / `firewall_traffic` et
`network_connection` / `netflow`, plus la famille web dès qu'un front est collecté. **Toutes les familles
Sysmon** (`process_access`, `image_load`, `driver_load`, `create_remote_thread`, `file_*`, `registry_*`)
exigent que **Sysmon** tourne sur les hôtes Windows *et* que l'agent plume y soit déployé : sans Sysmon,
elles s'importent et restent **inertes**.

#### Deux angles morts MESURÉS, écrits plutôt que masqués

1. **La création de processus est scindée entre deux catégories émises.** 4688 (agent + collecteur
   PowerShell) et l'`execve` auditd donnent `exec` ; **Sysmon ID 1** (création de processus) est rangé en
   `endpoint` par `map_cim` (branche par défaut « Sysmon hors 3/22 »). Une règle `process_creation`
   importée voit donc 4688 et auditd, **mais pas Sysmon ID 1**. Signalé par un **avertissement à
   l'import** et épinglé par un test. Refermer cela demande de changer la catégorie **émise** par
   l'agent (data-plane) et rouvre la même dette d'historique que `process` → `exec` (`docs/CIM.md` §5.2).
2. **`CommandLine` n'existe pas dans un 4688 par défaut.** Le champ n'apparaît que si la GPO *« Include
   command line in process creation events »* est activée. La règle vitrine livrée
   `config.d/sigma/process-whoami-discovery.yml` filtre `CommandLine` : elle **reste inerte sur un
   Windows par défaut, même après cette réconciliation** (l'importeur le signale — champ étendu inerte).
   Une règle qui filtre `NewProcessName` (toujours présent) fire, elle : c'est ce que prouve
   `sigma_process_creation_rule_fires_on_real_4688_event` sur une fixture 4688 réelle.

   **Sur Linux, la même règle est inerte pour une raison PLUS FORTE — structurelle, pas un réglage.**
   *Mesuré le 2026-08-01 (VM Ubuntu 24.04 Server amd64, 2 vCPU/2 Gio, règles auditd chargées, charge =
   build de 100 unités de compilation → 533 événements `category=exec` réels) :*

   | champ filtré   | événements `exec` correspondants | verdict |
   |----------------|----------------------------------|---------|
   | `CommandLine`  | **0 / 533**                      | ne peut pas matcher |
   | `exe`          | 407 / 533                        | matche |
   | `comm`         | 305 / 533                        | matche |

   Le chemin `execve` d'auditd émet exactement `action · auid · cim · comm · exe · key · success ·
   syscall · uid`. `CommandLine` n'en fait pas partie et **aucune option ne le fera apparaître** :
   sur Windows une GPO suffit, sur Linux il n'y a rien à activer. Les deux inerties ont donc des
   remèdes différents, et les confondre ferait croire qu'un réglage suffit.
   La **jumelle Linux qui fire** est livrée à côté :
   `config.d/sigma/process-whoami-discovery-linux.yml` (`exe|contains`). Le couple est délibéré — il
   enseigne la différence entre *champ traduit* (§4b, table de traduction) et *champ peuplé*.
   Une règle qui filtre un champ jamais peuplé n'est pas une couverture : c'est une couverture
   **apparente**, plus dangereuse que pas de règle du tout.

> **Quelle part d'un ruleset survit à la traduction ? NON MESURÉ ICI** — aucun corpus SigmaHQ n'est
> embarqué dans le dépôt, donc aucun taux n'est publié. Mesurez-le **sur votre propre ruleset** :
> `plume-daemon sigma-import <dossier> --dry-run` rend `imported[]` (avec leurs `warnings`) et
> `skipped[{title,reason}]`. C'est le seul chiffre qui vous concerne.

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

| Sigma | → GXQL | note |
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
`NOT REGEXP` en GXQL) ; liste OU de **sous-chaînes** (`contains` + liste sans `|all`) ; **modificateurs**
`base64`/`base64offset`/`utf16`/`wide`/`cidr`/`windash`.

> **Pourquoi rejeter l'OU ?** Le `search` GXQL conjugue ses filtres en **ET** ; le seul OU disponible est
> `field in (…)` (OU d'égalités sur **un** champ). Un OU inter-champs (`a or b`, `1 of them`) n'a pas de
> forme GXQL fidèle → le traduire approximativement **sous-matcherait** (angle mort). On préfère
> **flagger** honnêtement. (Le champ reste importable manuellement, ou via plusieurs règles.)

---

## 5. Exemples livrés (`config.d/sigma/`)

| fichier | démontre | GXQL produit |
|---------|----------|--------------|
| `firewall-denied-nonstandard-port.yml` | `logsource.category`→`firewall`, égalité, **négation de liste** | `search category=firewall action=~(?i)^deny$ dport not in (80,443) \| stats count` |
| `web-admin-path-blocked.yml` | `\|startswith` + égalité en **ET** | `search category=web action=~(?i)^blocked$ url=~(?i)^\/admin \| stats count` |
| `process-whoami-discovery.yml` | `process_creation`→`exec`, champ étendu `\|contains` | `search category=exec CommandLine=~(?i)whoami \| stats count` |

> ⚠️ **`process-whoami-discovery.yml` reste INERTE sur un Windows par défaut** : elle filtre
> `CommandLine`, champ **absent** d'un EventID 4688 tant que la GPO *« Include command line in process
> creation events »* n'est pas activée (cf. §4a, angle mort #2). Elle démontre la **traduction** d'un
> champ étendu, pas une détection active out-of-the-box. Traduire n'est pas détecter.

Pré-vol : `plume-daemon sigma-import config.d/sigma --dry-run`.

---

## 6. Ce que l'importeur n'est PAS

- Pas un moteur Sigma complet : il cible le **sous-ensemble exprimable en GXQL** (§4). Le reste est
  **flaggé**, jamais deviné.
- Pas un chemin de **filtre/suppression** : une règle importée **ajoute** une détection (cf. principe #3).
- Pas un backend de **corrélation temporelle** (`timeframe`/agrégation Sigma) : hors périmètre → flag.
