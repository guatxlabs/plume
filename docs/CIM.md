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
| `host`          | string  | Hôte observateur/rapporteur. **RÉSOLU À L'ÉCRITURE, EN UN SEUL ENDROIT** : `HoteIngere::resoudre` (`daemon/src/ingest/store.rs`) rend l'hôte **du jeton** quand celui-ci est lié à une machine, et l'hôte **déclaré** sinon. Un jeton de machine ne peut donc écrire que sous son propre hôte, **sur toutes les surfaces d'ingestion** (`/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push`, `/services/collector`, `/v1/traces`) — la résolution ne connaît pas les routes, elle ne peut donc pas en oublier une. Un jeton **relais** (`--relais`, forwarder multi-hôtes) écrit sous l'hôte qu'il déclare : cet hôte-là n'est **pas** attesté. *Avant : le liage n'était consulté que sur les voies `/api/ingest` et `/loki/api/v1/push`. Mesuré le 2026‑08‑02 avec un jeton lié à `WS22-LAB` — `/api/metrics/prom?host=HOTE-USURPE-PAR-METRICS` → HTTP 200 et métrique stockée sous l'hôte usurpé ; `/api/metrics/write` (label `instance`) → 204, idem ; `/services/collector` (HEC, `"host":"HEC-USURPE"`) → 200, idem. Quatre surfaces, dont une seule était documentée comme telle.* |
| `src_ip`        | string  | IP source — colonne **promue** depuis `fields.src_ip` \| `fields.rhost` (§4). |
| `dst_ip`        | string  | IP destination — colonne **promue** depuis `fields.dst_ip`. |
| `url`           | string  | URL / host+path — colonne **promue** depuis `fields.url`. |
| `dedup`         | string  | Clé anti-doublon (`INSERT OR IGNORE`). **CLOISONNÉE PAR HÔTE À L'ÉCRITURE** : la valeur STOCKÉE est `dedup_scoped_by_host(host, dedup)` (`daemon/src/ingest/store.rs`), donc la portée d'unicité est l'HÔTE de la ligne, pas la base. Un émetteur n'a **pas** à faire figurer l'hôte dans sa clé — et **ne peut pas** en produire une qui collisionne entre machines, quel que soit son langage. Il doit en revanche produire une clé **stable et déterministe** pour un même événement, c'est elle qui absorbe les réémissions du spool (at-least-once). *Avant ce cloisonnement, deux machines se volaient leurs événements en silence : mesuré 45 événements Sysmon disparus sur Windows (cf. `collectors/windows/README.md`) et 26 sur 78 côté Linux (cf. le bandeau de `ingest/store.rs`).* |
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
| `config`    | Auto-report du collecteur : transparence des filtres (**whitelists #10**) **et DISPONIBILITÉ** — `fields.collect_status` ∈ {`unavailable`, `disabled`} + `fields.reason` dit qu'un capteur ne PEUT PAS collecter (dépendance/source/réglage absent), au lieu de sortir silencieusement en succès. Voir `plume_unavailable` / `plume_disabled` (`collectors/lib.sh`). | `web`, `nft`, `portscan`, `auditd`, **tout capteur incapable** |
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
action  user  owner  kind  ns  role  scope  verb  resource  operation  dir  risk
```

> **`dir` et `risk` (2026‑08‑05) — entrés par ce que du contenu LIVRÉ interroge, pas par prédiction.**
> Ces deux clés étaient censées être servies par un mécanisme d'auto‑indexation piloté par la chaleur
> d'usage. Ce mécanisme **ne pouvait plus rien promouvoir** — ses crochets de comptage sont devenus du
> code mort quand le compilateur GXQL a migré dans `guatx-core` — et il a été retiré (P6.8‑b) ; sa
> purge de fond a droppé les index `idx_ev_auto_dir` / `idx_ev_auto_risk` / `idx_ev_auto_vtype` qui,
> eux, **existaient réellement en production** (relevés avec leur taille dans `bench/profile-prod.json`,
> `provenance: measured`, 2026‑07‑30 : 4,40 Mio pour `dir`, 12 Ko pour `risk`). Le critère d'entrée
> dans cette liste est donc devenu explicite
> et vérifiable : **une règle livrée filtre‑t‑elle sur ce champ ?** — `dir=outbound` : trois règles du
> catalogue (`ex-egress-fanout-external`, `lm-conntrack-internal-ssh`, `di-conntrack-internal-sweep`) ;
> `risk=public` : une (`cl-minio-public-bucket`). `vtype`, qu'aucun contenu livré n'interroge, n'a
> **pas** été restauré. La liste est **ordonnée** et dupliquée dans `guatx-core` ; une assertion de
> compilation refuse toute divergence entre les deux (`daemon/src/soql_glue.rs`).

### 4c. Vocabulaire NEUTRE de `action` (outcome normalisé — CIM v29)

`fields.action` porte l'**outcome normalisé** cross-source (produit par `journal_action`, les
parsers FortiGate/web, etc.). Guidance de mapping (réutiliser ces verbes neutres) :

```
success  failure  allowed  blocked  ban  read  modify  delete  sudo  session_open  session_close
```

**`action` EST UNE ISSUE — donc son absence n'est PAS uniforme, et ce document le disait mal.**
Ce paragraphe listait un vocabulaire sans jamais dire **où** `action` s'applique, ni ce que son
absence signifie. Deux relevés du 2026‑08‑02 montrent que la question n'est pas cosmétique :

- **Production réelle** (extraction lecture seule `bench/prod-profile.sql`, ~1,4 M d'événements) :
  `fields.action` est présent sur **68,7 %** des lignes, cardinalité 18.
- **Hôte Linux avec les collecteurs livrés** (base de labo peuplée par `collectors/*.sh` + journald
  réel) : absent sur **12,6 %** des lignes — et ces lignes-là sont **exactement** les catégories
  `health`, `config` et les flux `network`, c'est-à-dire celles qui **n'ont pas d'issue**.

La règle est donc : **une catégorie qui décrit un ACTE porte son issue ; une catégorie qui décrit un
ÉTAT n'en a pas.** Un battement de cœur ne réussit ni n'échoue ; un auto-report de disponibilité non
plus. Ce qui reste **exigible** :

| famille | `action` attendu |
|---|---|
| `auth` (ouverture/échec de session, Kerberos/NTLM, sudo, session) | **OUI** — `success` / `failure` / `session_open` / `session_close` / `sudo` |
| `firewall`, `web`, `dns`, `mail`, `dlp`, `application` (filtrage : il y a un verdict) | **OUI** — `allowed` / `blocked` |
| `ban` | **OUI** — `ban` |
| `data`, `secrets`, `integrity`, `account` (accès/mutation) | **OUI** — `read` / `modify` / `delete` |
| `exec` | **OUI** — `success` / `failure` (`auditd` rend `failure` sur un `execve` refusé ; Windows n'écrit 4688 que sur succès) |
| `health`, `config`, `inventory`, `posture`, `trace`, `network` (flux) | **NON** — pas d'issue à porter |

> Ce tableau est **NORMATIF** (ce qui est exigible d'un émetteur), pas un relevé de l'existant : la
> conformité n'est mesurée aujourd'hui que sur les chemins cités dans ce document. Un émetteur qui porte
> l'outcome sous un autre nom (`operation` pour `vault-audit`, par exemple) reste hors de portée des
> détections qui composent sur `action` — non mesuré ailleurs, donc non affirmé ailleurs.

> **Ce que l'absence coûtait, mesuré.** Les deux règles de brute-force livrées compilent
> `category=auth action=failure`, et **aucun** des deux émetteurs Windows livrés ne posait `action`.
> Trois échecs d'ouverture de session Windows (4625) réellement ingérés : `search category=auth |
> stats count by source` rendait `windows-security 2 · WinEventLog:Security 1 · sudo 366`, tandis que
> `search category=auth action=failure | stats count by source` rendait **`sudo 17` et RIEN pour
> Windows**. Une détection T1110 activée était aveugle sur l'OS où le brute-force est le plus courant.
> Fermé côté émetteur : l'agent (`agent/src/source/windows.rs`) décide catégorie, sévérité **et**
> issue en **une seule variante de type sans champ optionnel** — une branche qui oublierait l'issue ne
> compile pas ; le collecteur PowerShell (`collectors/windows/plume-collector.ps1`) dérive sa liste
> d'identifiants d'une **table `identifiant → issue`**, donc collecter sans déclarer l'issue n'est plus
> exprimable (garde de CI `check_windows_collector_is_honest.py`).

### 4d. Champs à FORTE cardinalité — ne comptez pas les indexer

Guidance de mapping, pas un réglage. Ces champs coûtent ~73 Mo d'index d'expression sur 2,6 M lignes,
hors budget RAM (2 Gio) : **leur agrégation passe par les rollups**, jamais par un index.

```
path  src_ip  uid  pid  url  message  dedup  remote_address
msg  time  logSource  request_id  trace_id  span_id  latency  duration  thread
```

> **Ce que cette section disait avant, et pourquoi c'était trompeur.** Elle s'intitulait « denylist
> d'auto-index » et citait une constante `AUTOINDEX_DENY`, ce qui laissait entendre qu'il existait un
> mécanisme d'auto-indexation *dont ces champs étaient exclus* — donc que les **autres** champs, eux,
> finiraient par être indexés à l'usage. C'était faux. Ce mécanisme adaptatif n'a **jamais promu un seul
> index** et il a été retiré (P6.8-b). La seule indexation de champs JSON qui existe est la liste FERMÉE
> `HOT_FIELDS` (§4b) ; **tout champ qui n'y figure pas est scanné**, qu'il soit dans le bloc ci-dessus ou
> non. Le bloc ci-dessus reste utile pour une raison plus modeste et exacte : ce sont les champs qu'il ne
> faut même pas *envisager* d'ajouter à `HOT_FIELDS`.

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

### 5.1 Catégorie hors taxonomie à l'ingestion — accepté, jamais rejeté

Une `category` déclarée par un collecteur et **absente** de `CIM_CATEGORIES` est **stockée telle quelle**.
Le CIM est un contrat de PARSE/MAP/ENRICH, **jamais un DROP** : refuser ferait perdre au SOC les
événements d'un collecteur tiers mal réglé, sans rejeu possible. La réduction de collecte a son chemin
explicite et audité (whitelists, audit sev 3) — le CIM n'en décide pas.

Ce qui a changé (2026-07-28) : la valeur n'était confrontée à la taxonomie **nulle part** sur le chemin
d'ingest — pas même un `warn` (les garde-fous existants étaient en amont : chargement d'un parseur
d'overlay, création d'un data-model, mapping HEC). Désormais la **première** occurrence de chaque couple
(`source`, `category`) hors taxonomie est journalisée en nommant le collecteur ; **une seule ligne par
couple et par vie du process** (un warn qui noie le journal n'avertit personne). La ligne stockée est
inchangée.

### 5.1bis Catégorie **ABSENTE** à l'ingestion — acceptée, mais plus jamais silencieuse

La §5.1 ne couvrait qu'un cas sur deux. Il y a **trois** états possibles, pas deux :

| état | ligne stockée | signalé | vu par une règle `category=…` |
|---|---|---|---|
| **canonique** (dans `CIM_CATEGORIES`) | telle quelle | non | oui |
| **hors taxonomie** (non vide, inconnue) | telle quelle | `warn`, une fois par couple (source, category) | non |
| **absente** (`category` vide) | telle quelle, **vide** | `warn`, une fois par source | **non, définitivement** |

Le troisième état sortait **avant tout contrôle**, sur ce motif écrit dans le code : « *Vide → rien
(le dparser tranchera côté serveur)* ». **C'était faux, et c'est mesuré** (2026‑08‑02) : quatre
événements à la forme exacte de l'agent livré (`WinEventLog:Security` 4768/4769,
`WinEventLog:Application` 1000, `macos-unified-log`) avec `category:""` → HTTP 202, **4 stockés tels
quels, zéro ligne de journal** ; et sur les **cinq** parseurs déclaratifs livrés, **aucun** ne cible
les sources de l'agent (ils ciblent `cloudflare`, `firewall`, `fim-agent`, `nginx`, `nft`). Rien ne
tranchait, ni à l'ingestion ni plus tard.

C'était l'état **le plus produit** par les émetteurs livrés : la classification Windows de l'agent
rend « non classé » pour tout identifiant hors de sa table, et le lecteur macOS rend une catégorie
vide pour toute ligne bénigne.

**On n'invente PAS de valeur.** Poser d'office un `unknown` serait pire que le vide : ce serait une
classification **fabriquée**, et `search category=unknown` ressemblerait à une classe alors que rien
n'a été reconnu. La ligne reste donc vide — ce qui est honnête. Ce qui est fermé, c'est le **silence** :

- la résolution est un **type à champ privé, constructeur unique** (`CategorieIngeree::resoudre`,
  `daemon/src/ingest/store.rs`), et sa somme est **exhaustive** : la valeur ne se fabrique pas hors de
  ce module, et un état ajouté demain ne compile pas tant qu'il n'est pas traité. *Limite exacte : le
  type n'OBLIGE pas un futur point d'écriture à l'emprunter — la colonne `category` d'`EventRow` reste
  une `String`. La garantie est « un seul endroit résout, et l'ingest y passe », pas « rien d'autre ne
  peut écrire ».*
- **mesurable au repos**, sur les données et non sur un compteur de processus (qui repart à zéro à
  chaque redémarrage) : `GET /api/system/diag` publie `counts.events_without_category` et la
  ventilation `unclassified_by_source`. En GXQL : `search category="" | stats count by source`.

### 5.2 Dette de migration — alias de lecture `exec` ⊃ `process` (péremption **2027-07-23**)

Les deux collecteurs Windows (`collectors/windows/plume-collector.ps1`, `agent/src/source/windows.rs`)
ont déclaré `category='process'` pour la **création de processus** (EventID 4688) jusqu'au **2026-07-23**.
`process` **n'appartient pas** à `CIM_CATEGORIES` ; le nom canonique v1.3 est **`exec`**. Les collecteurs
émettent `exec` depuis cette date.

L'historique **n'est pas migré** : rétention 365 jours, tier froid **scellé** (Parquet chiffré, jamais
réécrit) ⇒ immuable par construction. La réconciliation se fait à la **LECTURE** :

- une requête `category=exec` compile `category IN ('exec','process')` — posé au point de traversée à
  100 % de l'émission de lecture (`SqlcipherStore::soql_to_sql*`, cf. `soql_glue::cim_read_alias_exec`),
  plus la barre `/api/search` qui construit son SQL à la main ;
- **ce n'est pas un moteur de réécriture** : une seule équivalence écrite en dur, aucune table, aucune
  config, aucun ENV, inatteignable pour toute autre valeur. Elle ne s'applique qu'à l'**égalité** d'un
  filtre (`table_conds` / `where`) — `!=`, glob et regex ne sont **pas** aliasés ;
- **portée** : filtre de base, étage `where`, sous-recherches. **Hors portée** : corps de macro et filtre
  d'`eventtype` (détendus dans le cœur, après ce pré-pass).

Conséquences mesurées (lecture du cœur v0.2.1) : la liste `in (…)` est émise `COLLATE NOCASE` (sur-match
de casse, **jamais** un sous-match) ; `idx_event_category` (BINARY) ne sert plus ce filtre ; le tier froid
n'élague pas sur `category` pour une requête aliasée (`extract_cold_dim_preds` refuse la forme `IN`) et le
moteur colonnaire **décline** de vectoriser ces requêtes — l'oracle SQL les sert, donc une seule réponse
possible quelle que soit la route.

**Retrait.** Dernier événement `process` émis le 2026-07-23 ; rétention 365 jours ⇒ le dernier Parquet le
portant sort de rétention le **2027-07-23**. Après cette date (purge passée), supprimer le bloc
`cim_read_alias_exec` de `soql_glue.rs`, ses 4 sites d'appel (`ingest/store.rs` ×3, `handlers/search.rs`),
la garde `carries_cim_read_alias` du planner froid, et les tests `cim_read_alias_*` / `cim_aliased_*`.

### 5.3 Conséquence en aval — l'import Sigma réconcilié sur `exec`

Poser `exec` comme home canonique laissait une surface **non réconciliée** : l'importeur Sigma mappait le
logsource `process_creation` sur `endpoint`. Toute règle Sigma de création de processus importée filtrait
donc `category=endpoint` alors que **le 4688 des collecteurs livrés arrive en `exec`** — elle était
aveugle à la télémétrie qu'elle vise. Corrigé : `process_creation` → **`exec`**
(`SIGMA_LOGSOURCE_CATEGORY`, `daemon/src/sigma.rs`), avec une garde **dérivée** qui LIT les collecteurs
livrés et exige que la table s'accorde avec eux
(`sigma_process_creation_targets_the_category_the_shipped_4688_path_emits`).

**L'historique est couvert, et c'est prouvé.** L'importeur **recompile** la requête traduite par
`rule_sql` → `soql_to_sql_x` → `SqlcipherStore::soql_to_sql`, donc elle traverse
`cim_read_alias_exec` : une règle Sigma `process_creation` importée aujourd'hui voit la télémétrie `exec`
du jour **et** l'historique scellé `process`. Vérifié de bout en bout par
`sigma_process_creation_rule_fires_on_real_4688_event` (fixture 4688 réelle) — structure (`IN
('exec','process')` présent dans le SQL émis) **et** comptage ; neutraliser l'alias fait tomber le compte
de 2 à 1.

**Angle mort qui subsiste, mesuré.** `classer` (`agent/src/source/windows.rs`) range **Sysmon ID 1**
(création de processus) en `endpoint`, pas en `exec` — c'est la branche par défaut « Sysmon hors 3/22 ».
La création de processus est donc **scindée entre deux catégories émises** : `exec` (4688 + `execve`
auditd) et `endpoint` (Sysmon ID 1). Une règle `process_creation` ne peut pas voir les deux ; l'importeur
le **signale** (avertissement) et un test l'**épingle**. Le refermer signifie changer la catégorie
**émise** par l'agent : c'est un changement de data-plane qui rouvre exactement la dette du §5.2
(l'historique Sysmon rangé en `endpoint` deviendrait inatteignable par `category=exec`, et aucun alias ne
peut le désambiguïser puisque `endpoint` porte aussi image-load / registry / installation de service).
**Décision consciente** : non fait, écrit.

**Mesuré en conditions réelles le 2026‑08‑02** (Windows 11 Enterprise 24H2 build 26100, Sysmon 15.21
installé en 18 s avec une config minimale `ProcessCreate`, agent Rust cross-compilé et enregistré en
service SCM) : l'angle mort n'est plus déduit du code, il est **constaté**. Sysmon ID 1 arrive bien en
`category=endpoint` (36 événements), et sur le **même** poste, au **même** moment, la requête de la règle
Sigma `process_creation` importée telle quelle —
`search category=exec CommandLine=~(?i)whoami | stats count` — compte **50**, tandis que
`search category=endpoint CommandLine=~(?i)whoami | stats count` en compte **20** de plus qu'elle ne
voit pas. Ce sont les mêmes exécutions, vues deux fois, rangées dans deux catégories.

Deux conséquences pratiques que la lecture du code ne donnait pas :
- **Sysmon peuple `CommandLine` sans AUCUNE GPO** (c'est dans son schéma d'événement, pas dans l'audit
  Windows). Un parc équipé de Sysmon a donc la ligne de commande partout — y compris, mesuré, **les
  secrets passés en argv** (cf. l'avertissement de `collectors/windows/README.md`) — alors même que la
  règle `process_creation` reste aveugle à ces événements.
- La bascule d'`endpoint` vers `exec` serait donc *plus* payante qu'estimé (elle rendrait visible une
  télémétrie déjà riche en `CommandLine`), et *aussi* plus coûteuse (l'historique `endpoint` est mêlé).
  La décision reste inchangée ; seul son chiffrage est désormais mesuré.

**Corollaire pour la taxonomie.** L'axe `category` a désormais un oracle d'émission **mesuré**, ce que
`daemon/src/collected.rs` déclarait explicitement absent : `SIGMA_TARGET_CATEGORY_EMITTERS` cite, pour
chaque catégorie visée par l'import Sigma, **le fichier livré et le fragment qui l'émet** ; la garde
vérifie les deux sens. Le périmètre reste celui des cibles de l'import (16 catégories), pas la taxonomie
entière — **le reste n'est pas mesuré, donc pas affirmé**.

---

## 5.4 L'autre ligne canonique — l'INSTANTANÉ (`snapshot`), et sa portée d'unicité

Un émetteur ne produit pas que des événements : il peut publier un **instantané d'état**
(enveloppe spool `{"ts","host","kind","hash","data"}` — `collectors/firewall.sh`,
`collectors/controls.sh`, ou `POST /api/ingest` avec n'importe quel `kind`). Le daemon ne
réécrit `data` que si `hash` a **changé** ; sinon il avance le `ts` de la ligne existante
(*heartbeat* : un capteur stable ne doit pas être déclaré muet).

**LA SÉRIE EST `(kind, host)`, JAMAIS `kind` SEUL.** Un instantané capture ce que l'émetteur
peut OBSERVER, et un émetteur n'observe que sa machine. Toute la voie snapshot est donc
cloisonnée par l'hôte de la ligne (`SnapshotSeries`, `daemon/src/ingest/store.rs`) :
comparaison d'état, heartbeat, clés d'alerte d'état (`firewall.lockdown`, `control.catalog`),
sondes de fraîcheur et surfaces de lecture.

Conséquences pour qui écrit un émetteur :

- **`host` est ce qui vous identifie.** Deux machines qui publient le même `kind` avec le même
  `hash` sont **deux séries** ; aucune ne peut effacer l'autre. *Avant ce cloisonnement, un parc
  homogène de 3 machines rendait **1 seule ligne** — deux tiers du parc jetés en silence — et le
  battement d'une machine rajeunissait la ligne d'une autre (mesuré : +3540 s sur la ligne d'un
  hôte mort depuis 3600 s).*
- **Omettre `host` n'est pas un oubli toléré, c'est une DÉCLARATION** : l'instantané rejoint la
  série `(kind, NULL)`, celle de ce qui décrit **le déploiement** et non une machine. C'est ainsi —
  et seulement ainsi — qu'un instantané est légitimement global.
- **`hash` doit être stable et déterministe pour un même état**, et ne dépendre que de ce que
  l'émetteur observe (`firewall.sh` retire les compteurs volatils du ruleset avant de hasher).
- La **fraîcheur d'un parc** est celle de la machine la **plus en retard** (`MIN` sur les `MAX(ts)`
  par hôte) : une machine encore vivante ne peut plus faire passer tout le parc pour frais.

### 5.5 Deux émetteurs Windows, deux catégories pour le MÊME événement — mesuré, non corrigé

Les deux émetteurs Windows **livrés** rangent la gestion de comptes (4720/4722/4724/4726/4732/4756)
dans deux catégories différentes :

| émetteur | `category` émise |
|---|---|
| `collectors/windows/plume-collector.ps1` | **`account`** (le home canonique v1.3) |
| `agent/src/source/windows.rs` | **`auth`** |

Conséquence : une règle `category=account` ne voit que les postes équipés du collecteur PowerShell,
et une règle `category=auth` ramasse la gestion de comptes des postes équipés de l'agent. Aucune des
deux ne voit le parc entier — **c'est le même défaut de forme que le §5.3** (Sysmon ID 1 rangé en
`endpoint` alors que le 4688 va en `exec`).

**Décision consciente, comme au §5.3 : non fait, écrit.** Basculer l'agent vers `account` rouvrirait
exactement la dette du §5.2 — l'historique agent rangé en `auth` deviendrait inatteignable par
`category=account`, et **aucun alias de lecture ne peut le désambiguïser**, puisque `auth` porte
aussi les ouvertures de session, Kerberos et sudo. Le coût d'un alias `account ⊃ auth` serait de
faire remonter tout le trafic d'authentification sur une requête de gestion de comptes : le remède
serait pire.

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
