# Plume CIM — Common Information Model (v1.0)

> **Statut : contrat NORMATIF, versionné.** Ce document formalise le modèle d'information
> canonique de Plume — le vocabulaire NEUTRE de `category` et le jeu de champs cœur — sur
> lequel *toute* détection compose déjà, de façon **vendor-agnostique**. Il rend EXPLICITE
> un contrat jusqu'ici implicite dans le code ; **il ne change aucun comportement runtime**.

- **Version** : `1.3` (SemVer `majeur.mineur` ; majeur = rupture de taxonomie/champs). v1.1 (#57) ajoute
  les catégories `posture` (config-assessment / SCA-CIS) et `inventory` (inventaire endpoint) ; v1.2 (#41)
  ajoute la catégorie `trace` (télémétrie OpenTelemetry, corrélable par `trace_id`) ; v1.3 (Reorg Wave 2)
  ajoute des **homes canoniques rétroactifs** pour des catégories DÉJÀ émises par des collecteurs live —
  `exec` (auditd execve), `secrets` (vault-audit), `account` (auditd), `recon` et les sous-étapes du
  collecteur mail (`postscreen`/`reject`/`mailflow`/`mail-phishing`/`mail-url`) — **plus un tampon de version
  par event** (`fields.cim`, §4f). Tout additif (aucune ligne réécrite, zéro migration).
- **Miroir machine** : [`config.d/cim/cim.v1.json`](../config.d/cim/cim.v1.json).
- **Ancre code** : `CIM_VERSION` / `CIM_CATEGORIES` / `CIM_CORE_FIELDS` / `CIM_ACTION_VOCAB`
  + le validateur `cim_category_ok()` dans `guatx_core::cim` (crate `guatx-core`, `src/cim.rs`).
- **Garde anti-dérive** : deux tests exigent que **le const code == le JSON** — `cim_contract_is_self_consistent`
  (module `tests` de `guatx_core::cim`, cohérence interne du contrat) et
  `cim_const_mirror_matches_config_schema` (`daemon/src/tests/detection.rs`, miroir const ↔ schéma).
  Doc, code et schéma ne peuvent pas diverger sans casser `cargo test`.

---

## 0. Principe directeur — ENRICH, jamais SUPPRESS

Le CIM est un modèle de **PARSE / MAP / ENRICH**. Reconnaître, mapper ou enrichir une
`category` **ne supprime jamais** un événement. Une `category` hors-taxonomie est
**acceptée telle quelle** (l'ingest est inchangé) et seulement **signalée** (`warn`) — jamais
rejetée. Toute réduction de collecte (drop/suppress) est un **filtre**, qui appartient au
panneau *whitelists* (#10) et à l'audit `sev 3` (`/api/sources/settings`), **pas au CIM**.

C'est la garantie anti-angle-mort : le CIM enrichit la donnée, il ne la censure pas.

> **Vue d'ensemble des extensions.** Le CIM est le **pivot** du modèle *bring-your-own-vendor* : voir
> [`docs/SDK.md`](SDK.md) pour la carte des seams (parser, connecteur, détection, threat-intel, enforcer) et
> la règle « décrire, pas coder ».

---

## 1. La ligne canonique — `EventRow`

Tout chemin d'ingest (syslog, journal, collecteurs shell, MinIO natif, agents) **converge**
sur une seule ligne, `EventRow` (`guatx_core::store`, crate `guatx-core`, `src/store.rs`), insérée par un unique SQL figé
(`EVENT_INSERT_SQL`, `INSERT OR IGNORE` sur `dedup`). Les colonnes ci-dessous forment le
**jeu de champs CŒUR** (première classe : indexées / filtrables directement).

| champ           | type    | sémantique |
|-----------------|---------|------------|
| `ts`            | integer | Horodatage de l'événement — **epoch secondes, UTC**. |
| `source`        | string  | Identité du **PRODUCTEUR / vendeur** (`fortigate`, `suricata`, `web`…). **Jamais la sémantique.** |
| `category`      | string  | Classe **sémantique NEUTRE** (§2) — l'axe de composition des détections. |
| `severity`      | integer | **0..4** (§3). |
| `message`       | string  | Résumé lisible par un humain. |
| `host`          | string  | Hôte observateur/rapporteur. Lié au token de l'agent → **non usurpable** (M2). |
| `src_ip`        | string  | IP source — colonne **promue** depuis `fields.src_ip` \| `fields.rhost` (§4). |
| `dst_ip`        | string  | IP destination — colonne **promue** depuis `fields.dst_ip`. |
| `url`           | string  | URL / host+path — colonne **promue** depuis `fields.url`. |
| `dedup`         | string  | Clé anti-doublon (`INSERT OR IGNORE`). |
| `fields`        | object  | Sac JSON des champs **ÉTENDUS** (spécifiques vendeur/parser). |
| `engagement_id` | string  | Corrélation d'engagement purple-team. |
| `origin`        | string  | Marqueur d'origine d'ingestion. |
| `env_id`        | string  | Liaison d'environnement (défaut `prod`). |

> La struct `EventRow` + `EVENT_INSERT_SQL` restent la définition qui **fait foi** ;
> `CIM_CORE_FIELDS` en est le miroir-de-contrat testé.

---

## 2. Taxonomie `category` (v1.3 — 40 valeurs, closed-ish)

`source` = **QUI** produit (vendeur). `category` = **QUOI** sémantiquement (neutre,
inter-vendeur). Les règles composent **`category=…`, jamais par vendeur** — c'est ce qui rend
une détection portable de FortiGate à Suricata à un futur connecteur Defender sans réécriture.

Deux **namespaces**. La scission est une **GUIDANCE** (le runtime traite toutes les
catégories à l'identique) :

- **security** — signal d'attaque/sécurité ; l'axe où composent les règles de détection.
- **operational** — télémétrie collecteur, état de config, piste d'audit ; **pas** un signal
  d'attaque primaire — alimente santé / couverture / whitelists.

### 2a. Namespace `security` (27)

| category | signification | sources d'exemple |
|----------|---------------|-------------------|
| `firewall`    | Filtrage L3/L4, allow/deny, session/traffic.                              | `fortigate(traffic)`, `ufw`, `nft`, `origin-drop` |
| `ids`         | Détection/prévention d'intrusion, anomalie.                              | `suricata`, `fortigate(ips/anomaly)` |
| `alert`       | Alerte signature IDS.                                                     | `suricata` |
| `web`         | Filtrage web / proxy / WAF / accès HTTP applicatif.                       | `web`, `fortigate(webfilter/waf)`, `cloudflare-http` |
| `malware`     | Détection antivirus / EDR / YARA.                                        | `clamav`, `yara`, `fortigate(virus)` |
| `auth`        | Authentification / autorisation (login, sudo, session).                   | `journal(sshd/sudo)`, `fortigate(user)` |
| `dns`         | Requête / filtrage DNS.                                                   | `fortigate(dns)` |
| `mail`        | Sécurité / filtrage email.                                               | `mail`, `fortigate(emailfilter)` |
| `dlp`         | Prévention de fuite de données.                                          | `fortigate(dlp)` |
| `vpn`         | Événements de tunnel VPN.                                                | `fortigate(vpn)` |
| `application` | Contrôle applicatif (app-ctrl).                                          | `fortigate(app-ctrl)` |
| `endpoint`    | Endpoint / EMS / EDR.                                                     | `fortigate(endpoint/ems)` |
| `network`     | Flux / télémétrie réseau ; bucket neutre des types FortiGate non mappés. | `conntrack`, `crowdsec`, `fortigate(router/inconnu)` |
| `data`        | Accès aux données / stockage objet / RBAC-vers-données.                  | `minio`, `kube-rbac`, `dataaccess`, `dataacl` |
| `tamper`      | Altération d'un objet critique d'intégrité (tripwire).                   | `auditd(sudoers.d/shadow)` |
| `vuln`        | Constat de vulnérabilité.                                                | `vuln` |
| `utm`         | Fourre-tout UTM FortiGate (sous-type non mappé) — bucket neutre.          | `fortigate(utm)` |
| `posture`     | Évaluation de configuration / conformité (SCA-CIS) : hôte × benchmark × contrôle × pass\|fail × cadre. | `wazuh(sca)`, `openscap`, `osquery(pack)` |
| `exec`        | **Exécution de processus** (execve) — surveillance d'exécution hôte. v1.3 : home canonique du flux **dominant** auditd (~30 % des events), conforme **rétroactivement**. | `auditd(execve)`, `osquery(process_events)` |
| `secrets`     | Accès au **coffre de secrets** (lecture / écriture / suppression d'un secret). v1.3. | `vault-audit` |
| `account`     | **Gestion de compte** (création / modification / suppression d'utilisateur ou de groupe). v1.3. | `auditd(useradd/usermod/passwd)`, `journal` |
| `recon`       | Activité de **reconnaissance** / énumération / découverte. v1.3. | `nft(portscan corrélé)`, `moat-probe` |
| `postscreen`  | Postfix **postscreen** — pré-filtrage de connexion SMTP entrante (sous-étape mail). v1.3. | `mail(postscreen)` |
| `reject`      | **Rejet SMTP** (relais / politique / RBL) — sous-étape mail. v1.3. | `mail(reject)` |
| `mailflow`    | Étape de **flux mail** (livraison / file / transport) — sous-étape mail. v1.3. | `mail(mailflow)` |
| `mail-phishing`| Signal de **phishing** détecté dans le flux mail — sous-étape mail. v1.3. | `mail(phishing)` |
| `mail-url`    | **URL extraite** d'un message (analyse de lien) — sous-étape mail. v1.3. | `mail(url)` |

> **Note v1.3 — sous-étapes mail.** `mail` reste la catégorie de sécurité email primaire ; les cinq
> sous-étapes ci-dessus (`postscreen`/`reject`/`mailflow`/`mail-phishing`/`mail-url`) sont les **labels que
> le collecteur mail émet DÉJÀ** en `category`. On leur donne un home canonique SANS toucher le collecteur
> (ADDITIF, cf. §0) : le but est la parité contrat↔producteurs, pas la re-normalisation. Une évolution
> future POURRAIT replier ces labels en `category=mail` + `fields.mail_stage=…`, mais ce serait un
> changement de producteur (hors périmètre) et non rétro-conforme.

### 2b. Namespace `operational` (13)

| category | signification | sources d'exemple |
|----------|---------------|-------------------|
| `health`    | Battement de cœur / liveness du collecteur (0 attaque = normal ; distingue **silence** de **panne**). | tous les collecteurs (health beat) |
| `config`    | Auto-report de configuration du collecteur (transparence des filtres, **whitelists #10**). | `web`, `nft`, `portscan`, `auditd` |
| `audit`     | Transport de piste d'audit.                                              | `auditd(audit.sh)` |
| `system`    | Événements système / hôte.                                              | `fortigate(system/ha/config)` |
| `update`    | Dérive d'image / paquets & mises à jour.                                | `imgdrift` |
| `container` | Événements du runtime conteneur.                                        | `containerd` |
| `k8s`       | Audit Kubernetes.                                                        | `kube-audit` |
| `ebpf`      | Sécurité runtime eBPF.                                                   | `falco` |
| `ban`       | Registre des bannissements (fail2ban / CAPI).                            | `bans` |
| `integrity` | Surveillance d'intégrité de fichiers (FIM).                             | `integrity`, `wazuh(syscheck)` |
| `syslog`    | Repli syslog générique / non classé (bucket « pas encore mappé »).       | `collector-syslog` (parser `Generic`) |
| `inventory` | Télémétrie d'inventaire endpoint (syscollector) : paquets/ports/processus. | `wazuh(syscollector)`, `osquery` |
| `trace`     | Télémétrie OpenTelemetry : spans de traces distribuées (opération × service × durée × statut), **corrélables aux logs par `trace_id`** (#41). | `otlp(/v1/traces)`, `otel-collector`, `otel-sdk` |

> **Mapping guidance.** Un mapping vendeur DEVRAIT cibler une catégorie existante. En cas de
> doute : `network` (flux L3/L4 inconnu), `system` (état hôte), ou `syslog` (non classé) sont
> les buckets neutres de repli — **jamais** un drop. Ajouter une catégorie = **bump
> `CIM_VERSION`** + mettre à jour `docs/CIM.md` + `config.d/cim/cim.v1.json` (le test garde la
> parité). Une valeur hors-taxonomie est acceptée à l'ingest mais **signalée** (`warn`).

---

## 3. Échelle de sévérité (0..4)

| valeur | sens     | syslog RFC5424 (mappé par `syslog_sev_to_plume`) | FortiGate (`level_to_sev`) |
|:------:|----------|--------------------------------------------------|----------------------------|
| `0`    | info     | info, debug                                      | information, debug |
| `1`    | notice   | notice                                           | notice |
| `2`    | warning  | warning                                          | warning |
| `3`    | error    | err                                              | error |
| `4`    | critical | emerg, alert, crit                               | emergency, alert, critical |

---

## 4. Champs étendus (`fields`) — promotion, dimensions chaudes, outcome

Tout ce qui n'est pas une colonne cœur vit dans `fields` (objet JSON). Trois sous-contrats :

### 4a. Champs PROMUS en colonnes (par nom)

Le daemon promeut certains champs de `fields` vers les colonnes cœur (`fields_ip` /
`fields_dst` / `fields_url`). Un parser/mapping DOIT poser ces clés pour peupler les colonnes :

| colonne cible | clés `fields` sources |
|---------------|-----------------------|
| `src_ip`      | `fields.src_ip`, `fields.rhost` |
| `dst_ip`      | `fields.dst_ip` |
| `url`         | `fields.url` |

> `ip` (ambigu source/destination) **n'est pas** promu — pas de faux sens src/dst.

### 4b. Dimensions ÉTENDUES chaudes (`HOT_FIELDS`) — le « cœur étendu »

Clés de `fields` indexées / groupables (cardinalité bornée = énumérés/identités d'un parc
borné). C'est le cœur étendu du CIM sur lequel les détections filtrent/groupent en plus des
colonnes :

```
action  user  owner  kind  ns  role  scope  verb  resource  operation
```

### 4c. Vocabulaire NEUTRE de `action` (outcome normalisé — CIM v29)

`fields.action` porte l'**outcome normalisé** cross-source (produit par `journal_action`, les
parsers FortiGate/web, etc.). Guidance de mapping (réutiliser ces verbes neutres) :

```
success  failure  allowed  blocked  ban  read  modify  delete  sudo  session_open  session_close
```

### 4d. Denylist d'auto-index (cardinalité)

Champs **jamais** éligibles à l'auto-index (budget RAM 2 Go) — leur agrégation passe par les
rollups, pas par un index (`AUTOINDEX_DENY`) :

```
path  src_ip  uid  pid  url  message  dedup  remote_address
msg  time  logSource  request_id  trace_id  span_id  latency  duration  thread
```

### 4e. Familles de champs SÉCURITÉ ENDPOINT (#57 — BYO-agent)

Télémétrie endpoint-sécurité **ingérée** depuis l'agent que le client fait déjà tourner (Wazuh,
osquery, EDR) et normalisée en `fields.*` par le preset `endpoint_normalize` (schéma Wazuh) **ou** par
un parseur déclaratif (`docs/PARSER-DSL.md`) pour tout autre vendeur. Voir **`docs/ENDPOINT-SECURITY.md`**.
Plume **n'exécute AUCUN scan endpoint lui-même** (non-goal assumé) — il est le cerveau analytique/réponse.

| category    | familles de `fields` normalisés |
|-------------|---------------------------------|
| `posture`   | `posture_policy` `posture_policy_id` `posture_check_id` `posture_check_title` `posture_result`(pass\|fail\|na) `posture_remediation` `posture_framework` `posture_compliance` `posture_kind`(check\|summary) `posture_score` `posture_passed` `posture_failed` |
| `vuln`      | `cve` `vuln_severity`(critical..low) `vuln_package` `vuln_package_version` `vuln_status` `vuln_cvss` `vuln_title` |
| `integrity` | `fim_path` `fim_event`(added\|modified\|deleted) `fim_mode` `fim_sha256` `fim_md5` `fim_size` `fim_actor` (+ `action`=modify\|delete) |
| `inventory` | `inv_type`(package\|port\|process\|hotfix) `inv_name` `inv_version` `inv_vendor` `inv_port` `inv_protocol` `inv_process` `inv_pid` `inv_cmd` |

`agent_name` / `agent_id` / `agent_ip` (identité de l'endpoint rapporté) sont posés pour **toutes** les
familles : un forwarder central relaie plusieurs hôtes, donc la colonne `host` peut être le forwarder ;
`agent_name` est le **vrai** endpoint sur lequel les vues groupent.

### 4f. Tampon de version CIM par event (`fields.cim`) — dérive détectable AU REPOS

Chaque event est tamponné **à l'ingest** avec `fields.cim = CIM_VERSION` (helper `cim_stamp`, appliqué sur
les DEUX voies d'insertion : events génériques `ingest_events_batch_env` — qui absorbe /api/ingest, spool,
HEC, MinIO, OTLP, Loki, connecteurs — et journald `ingest_journal_lines`). But : rendre la **dérive de
contrat détectable sur des données figées**, sans quoi rien ne distingue une ligne d'ancienne convention
d'une ligne récente.

- **Lecture au repos** : une ligne **sans** clé `fields.cim` a été écrite **avant** le tampon (« pré-tampon »,
  convention inconnue) ; une valeur **ancienne** (`< CIM_VERSION`) signale un contrat périmé. Ex. GXQL :
  `search category=exec | where json_extract(fields,'$.cim')!="1.3"`.
- **Additif / idempotent / fail-safe** : `cim_stamp` n'écrase jamais une clé `cim` déjà posée ; un sac vide
  devient `{"cim":"1.3"}` ; un JSON non-objet imprévu est laissé INCHANGÉ (jamais de perte). Le tampon ne
  participe pas au `dedup` (explicite ou NULL, jamais dérivé de `fields`) → idempotence `INSERT OR IGNORE`
  préservée.
- **Blast-radius minimal** : un champ du sac `fields` déjà sérialisé — **pas** de colonne, donc **aucune
  migration de schéma**, aucun changement d'`EventRow`/`EVENT_INSERT_SQL` (pas de parité de store à
  re-prouver). Les lignes **pré-tampon** ne sont pas ré-écrites — elles restent lisibles comme telles.

---

## 5. Politique de version

- `CIM_VERSION = "1.3"`. **Additif** (nouvelle catégorie/nouveau champ étendu) → bump
  **mineur** (`1.1` a ajouté `posture`+`inventory`, #57 ; `1.2` a ajouté `trace`, #41 ; `1.3` a ajouté
  `exec`/`secrets`/`account`/`recon` + 5 sous-étapes mail + le tampon `fields.cim`, Reorg Wave 2).
  **Rupture** (retrait/renommage d'une catégorie ou d'un champ cœur) → bump **majeur** (`2.0`) + nouveau
  fichier `config.d/cim/cim.v2.json`.
- Le trio **doc (`docs/CIM.md`) ↔ code (`CIM_*` dans `guatx_core::cim`) ↔ schéma
  (`config.d/cim/cim.v1.json`)** est maintenu cohérent par le test de parité. Modifier l'un
  sans les autres **casse `cargo test`** — c'est voulu : une seule source de vérité. Un **garde-fou à la
  COMPILATION** (`daemon/build.rs`) va plus loin : il extrait la `version` du schéma embarqué et
  const-assert qu'elle égale `CIM_VERSION` du cœur LINKÉ — un build lié à un cœur STALE **échoue à compiler**.
- **RÉTRO-CONFORMITÉ** : ajouter un nom à l'allow-list `CIM_CATEGORIES` ne réécrit **aucune** ligne. Les
  events déjà stockés sous une catégorie nouvellement canonisée (ex. tout l'historique `exec`) deviennent
  in-contract **immédiatement, sans migration de données** — `cim_category_ok()` est une pure appartenance.

---

## 6. Ce que le CIM n'est PAS (encore)

Le CIM v1 est la **pièce 1** de la slice #7 (formalisation). Il **n'introduit aucun** nouveau
chemin d'ingest et ne modifie pas le data-plane. Les pièces qui s'appuient dessus (hors
périmètre de ce document) :

- **Pièce 2 — DSL de parser déclaratif** : mapper des champs vendeur → champs CIM en
  `config.d` sans rebuild Rust (PARSE/MAP/ENRICH, jamais DROP).
- **Pièce 3 — Importeur Sigma** : traduire les règles Sigma → règles Plume (GXQL) via le
  mapping logsource → `source`/`category` de ce contrat.

Ces deux pièces **référencent** cette taxonomie ; elles ne la redéfinissent pas.
