# Plume — Sécurité endpoint (BYO-agent) — #57

> **Statut : contrat opérateur + positionnement produit.** Ce document décrit comment Plume ingère et
> normalise la télémétrie **endpoint-sécurité** (SCA/conformité, vulnérabilités, FIM, inventaire) produite
> par l'agent que le client fait **déjà** tourner (Wazuh, osquery, EDR), et la surface en **vues natives**.

---

## 0. Positionnement — SUR-ENSEMBLE PAR INGESTION, pas un nouvel agent

**Décision stratégique (assumée).** Plume ne reconstruit **pas** un agent endpoint : pas de moteur natif
SCA, pas de scanner CVE, pas de rootcheck. Reconstruire ce moteur, ce serait re-bâtir OSSEC/Wazuh — à
contre-courant de la charte **souveraine / 2 Go RAM / vendor-agnostic**.

À la place, Plume adopte la stratégie **superset-par-ingestion** : il devient le **cerveau**
analytique / détection / réponse / registre (ledger) **au-dessus** du capteur endpoint que le client
possède déjà. Pendant une migration, **Wazuh / osquery / un EDR PEUT ÊTRE le capteur** ; Plume normalise
sa sortie en CIM et la rend requêtable/corrélable/actionnable comme n'importe quelle autre source.

- **Ce que Plume FAIT** : ingérer + normaliser (CIM) + indexer + détecter (GXQL/Sigma/corrélation/UEBA) +
  scorer le risque (RBA) + répondre (playbooks) + tracer (ledger) + surfacer (vues natives).
- **Ce que Plume NE FAIT PAS (non-goal honnête)** : scanner l'endpoint lui-même (pas d'inotify FIM natif,
  pas de feed CVE, pas d'évaluation CIS embarquée). Le **capteur** reste l'agent du client.

C'est la même couture que le reste du modèle *bring-your-own-vendor* (cf. `docs/SDK.md`, `docs/CIM.md`,
`docs/PARSER-DSL.md`, HEC `docs/…`) : Plume est un **sur-ensemble** de l'existant, pas un remplaçant qui
fait perdre une capacité.

---

## 1. Familles supportées & mapping CIM

Le preset built-in `endpoint_normalize` (`daemon/src/ingest/endpoint.rs`) reconnaît le **schéma d'alerte
JSON Wazuh** (le format BYO le plus répandu) et mappe ses familles vers le CIM (`docs/CIM.md`) :

| Famille (source Wazuh)                         | Clé JSON détectée        | → category CIM | Champs normalisés (`fields.*`) |
|------------------------------------------------|--------------------------|----------------|--------------------------------|
| **SCA** (Security Configuration Assessment/CIS)| `data.sca.*`             | `posture`      | `posture_policy`, `posture_check_id`, `posture_check_title`, `posture_result` (pass\|fail\|na), `posture_remediation`, `posture_framework`, `posture_compliance`, `posture_kind`, `posture_score`/`posture_passed`/`posture_failed` (résumé) |
| **Vulnerability-detector**                     | `data.vulnerability.*`   | `vuln`         | `cve`, `vuln_severity`, `vuln_package`, `vuln_package_version`, `vuln_status`, `vuln_cvss`, `vuln_title` |
| **FIM / syscheck**                             | `syscheck.*`             | `integrity`    | `fim_path`, `fim_event`, `fim_mode`, `fim_sha256`/`fim_md5`, `fim_size`, `fim_actor` (whodata), `action` |
| **syscollector** (inventaire)                  | `data.{program,port,process,hotfix}` / `location=syscollector` | `inventory` | `inv_type`, `inv_name`, `inv_version`, `inv_vendor`, `inv_port`, `inv_protocol`, `inv_process`, `inv_pid`, `inv_cmd` |

Toutes les familles posent aussi `agent_name` / `agent_id` / `agent_ip` (identité de l'**endpoint**). Un
forwarder central relaie plusieurs hôtes → la colonne `host` peut être le forwarder ; **`agent_name` est le
vrai endpoint** sur lequel les vues groupent.

**Sévérité** (échelle Plume 0..4, appliquée en **ENRICH-only** — le collecteur gagne s'il l'a déjà posée) :
SCA `failed`→2 / sinon 0 ; CVE `critical`→4 `high`→3 `medium`→2 `low`→1 ; FIM `deleted`→3 `modified`→2
`added`→1 ; inventaire→0.

**osquery** : reconnu comme `sourcetype osquery:results` côté HEC (`docs`), et ses packs FIM/SCA peuvent être
mappés par parseur déclaratif (ci-dessous) vers `integrity`/`posture`.

---

## 2. Formats d'entrée acceptés (comment envoyer la télémétrie)

Plume **n'a pas de nouvel agent** : on réutilise les chemins d'ingest existants. Le point clé est que la
**source** de l'event soit dans la liste opt-in `PLUME_ENDPOINT_NORMALIZE` (défaut `"wazuh"`) et que le
**message** soit l'alerte JSON complète.

- **HEC (Splunk-compatible, `POST /services/collector`)** — un forwarder Wazuh→Splunk-HEC, filebeat, ou
  tout client HEC : poster l'alerte comme `event` (objet) avec `"source":"wazuh"`. Le message devient le
  JSON de l'alerte → normalisé.
- **`POST /api/ingest`** (agent/connecteur natif) — event `{ "source":"wazuh", "message":"<alerte JSON>" }`.
- **Connecteur pull** (`connectors.rs`) — un connecteur qui tire les alertes Wazuh et les pousse par lot.

> **Étendre à un autre vendeur SANS rebuild** : ajouter la source à `PLUME_ENDPOINT_NORMALIZE` **si** son
> schéma est Wazuh-like ; sinon écrire un **parseur déclaratif** (`config.d/parsers/*.json`, cf.
> `config.d/parsers/example-endpoint-fim.json`) qui cible les **mêmes** champs/catégories CIM. Les vues
> natives fonctionnent alors à l'identique (elles composent sur `category`, jamais sur le vendeur).

---

## 3. Vues natives (GXQL-backed)

Deux dashboards semés (idempotents), vue **« Endpoint (BYO-agent) »**, **vides** tant qu'aucune télémétrie
n'arrive :

- **Posture de configuration (SCA/CIS)** — contrôles pass/fail, échecs par hôte, par benchmark, cadres de
  conformité impactés, détail des contrôles échoués. Composé sur `category=posture`.
- **Vulnérabilités (CVE endpoint)** — CVE par sévérité, hôtes les plus vulnérables, top CVE, paquets les
  plus touchés, critiques/hautes en détail. Composé sur `category=vuln`.

Les panneaux sont **GXQL** (chemin masqué : respecte les field-filters #45 + RBAC automatiquement). FIM
alimente déjà la catégorie `integrity` (vues d'intégrité existantes) ; l'inventaire (`category=inventory`)
est ingéré et requêtable — un dashboard dédié est un **follow-on**.

---

## 4. Garanties (invariants)

- **Mode 0 / byte-identique** : le normaliseur est **gate par source**. Tant qu'aucun event d'une source
  endpoint ne circule, l'ingest est **byte-identique** (aucun parse JSON, aucune allocation) — un simple
  test d'appartenance. Preuve : `endpoint_mode0_gate_ignores_non_endpoint_source`.
- **ENRICH / MAP, jamais DROP** : on n'ajoute que des `fields.*` absents (le collecteur gagne) ;
  `category`/`severity` ne sont posées qu'en ENRICH-only. Aucun event n'est supprimé ni filtré.
- **Injection-safe** : les valeurs normalisées transitent par le sac `fields` → chemin `EventRow`/INSERT à
  paramètres bindés (aucune construction SQL par chaîne). Les panneaux passent par GXQL.
- **Vendor-agnostic** : preset built-in **mince** pour Wazuh ; tout autre vendeur s'ajoute par parseur
  déclaratif `config.d` **sans recompiler**.

---

## 4bis. Coût de la règle `execve` (mesuré)

La règle `execve` **64 bits est active par défaut** dans `systemd/plume-audit.rules`. Sans elle,
`category=exec` est **vide** sur un hôte amd64 — angle mort total sur l'exécution de processus. Un
défaut aveugle est pire qu'un défaut volumineux. Mais elle coûte, et voici le coût **mesuré**, pas
estimé, pour que vous puissiez le projeter sur VOTRE parc.

> **Banc de mesure — 2026-08-01.** VM QEMU/KVM, image cloud officielle `noble-server-cloudimg-amd64`
> (Ubuntu 24.04 Server), **2 vCPU / 2 Gio**, `auditd` installé, gabarit livré chargé (**8/8 règles**,
> vérifié par `auditctl -l`), collecteur `auditd.sh` en réglages par défaut
> (`PLUME_AUDITD_EXEC_DROP` non posé), central Plume local. Refaites-la chez vous : les chiffres
> ci-dessous décrivent CETTE machine et CETTE charge, pas la vôtre.

### Grandeurs primitives (les seules réellement mesurées)

| grandeur | valeur mesurée | comment |
|---|---|---|
| **Taille sur DISQUE d'un événement `exec`** | **534 octets** | 10 000 événements `exec` ingérés, base passée au `wal_checkpoint(TRUNCATE)` : +5 349 376 octets. Inclut la ligne, l'overhead SQLite et **les 8 index**. |
| Taille *logique* (message + `fields`) | 270 octets en moyenne (198 min / 278 max) | `message` 75 o + blob `fields` 169 o. L'écart avec les 534 o disque = **×1,97 d'amplification** (overhead + index) — c'est le chiffre disque qui compte pour dimensionner. |
| **Au repos** (aucune session de login) | **≈ 0 / heure** | Fenêtre de **900 s**. 9 enregistrements `EXECVE` observés, tous imputables aux commandes du banc lui-même (9 ouvertures de session dans la même fenêtre). Surtout : **0** enregistrement avec `auid` non défini, alors que `plume-ship.timer` (30 s) et `plume-resources.timer` (60 s) ont tourné ~30 et ~15 fois pendant la fenêtre. |
| **Sous charge de build** | **533 événements** pour un build de 100 unités de compilation C + link (2 s) | soit **≈ 285 Kio** de base par build. |

### Pourquoi le repos est si calme — et ce que ça implique

Le filtre `-F auid!=-1` du gabarit ne journalise que les exec rattachables à une **session de login**.
Les timers systemd, les collecteurs Plume et les daemons tournent avec `auid` non défini : **ils ne
produisent aucun événement `exec`**. Le volume suit donc l'**activité humaine**, pas la churn machine.
C'est ce qui rend le défaut « actif » tenable sur un serveur, et c'est aussi pourquoi un **poste de
développeur ou un runner de CI** est le cas coûteux, pas le serveur de production.

### Projection à 30 jours (rétention par défaut du produit)

> ⚠️ **Ces lignes sont de l'ARITHMÉTIQUE sur les grandeurs mesurées ci-dessus, pas des mesures.** Le
> nombre de builds/jour est **votre** paramètre : remplacez-le.

| profil d'hôte | événements `exec`/jour | par jour | **à 30 jours** |
|---|---|---|---|
| Serveur, personne ne se connecte | ≈ 0 *(mesuré)* | ≈ 0 | **≈ 0** |
| Poste dev / runner CI, 20 builds/jour | 20 × 533 = 10 660 | 5,7 Mio | **~171 Mio** |
| **Build en continu (borne haute)** | 266 ev/s → **23 M/jour** | **12,3 Gio** | **~369 Gio** |

Le régime « serveur avec une session d'administration de temps en temps » n'est **pas** tabulé : il dépend
entièrement de ce que vos administrateurs tapent, et publier un nombre inventé pour cette ligne serait
exactement le genre de chiffre non mesuré que ce document refuse. Mesurez-le sur VOTRE parc, c'est une
requête :

```
search source=auditd category=exec | stats count by host
```

**La borne haute est le résultat qui compte** : un hôte qui compile en permanence sature n'importe quel
disque bien avant 30 jours. Sur un parc de build, `execve` large **doit** être réduit (voir plus bas) ;
ce n'est pas une opinion, c'est ce que dit le calcul.

**À l'échelle d'un parc.** Une mesure interne de la semaine du 2026-07-25 donne un facteur **×43** en
volume total en passant de **1 à 50 hôtes** (les hôtes ne sont pas identiques ; ce n'est pas ×50). Sur
ce facteur, 50 postes dev à 171 Mio/30 j donnent **≈ 7,3 Gio / 30 j** pour le seul flux `exec`. À
comparer à votre volume actuel avant de généraliser.

**Le budget 2 Gio de RAM n'est pas le facteur limitant ici, le DISQUE l'est.** Le flux `exec` grossit
la base, pas le working set : la lecture reste paginée (keyset) et passe par les rollups. Ce qu'il faut
surveiller est l'espace disque et la fenêtre de rétention, pas le RSS.

### Réduire sans redevenir aveugle — deux leviers, du plus doux au plus radical

1. **Filtrer au collecteur** (la forensique hôte reste **complète** : `ausearch` voit tout ; seule
   l'ingestion Plume est réduite). Dans `/etc/plume/plume.conf` :
   ```sh
   PLUME_AUDITD_EXEC_DROP=1                   # bruit build/système non équivoque (palier 1)
   PLUME_AUDITD_EXEC_DROP_INCLUDE_RECON=1     # + primitives de découverte (palier 2, plus agressif)
   ```
   Le palier 2 est **volontairement séparé** : il porte des primitives de découverte et de chasse aux
   secrets (T1083/T1057/T1552.001) qui restent **gardées par défaut**, même palier 1 actif. Mesurez la
   part réelle avant d'activer : `search source=auditd category=exec | stats count by exe | sort -count`.
2. **Retirer la couverture 64 bits** (commenter la ligne `arch=b64` du gabarit). Vous retombez alors
   dans l'angle mort mesuré : **`category=exec` redevient vide**. À ne faire qu'en le sachant.

Le collecteur **publie l'état de ces interrupteurs** en `category=config` à chaque passage — un
défenseur voit donc la surface d'angle mort exacte quelle que soit leur position, sans lire le code.

## 5. Réglages

| Variable                      | Défaut   | Effet |
|-------------------------------|----------|-------|
| `PLUME_ENDPOINT_NORMALIZE`    | `wazuh`  | CSV des `source` sur lesquelles le preset endpoint s'active (`*` interdit). |

Ancre code : `daemon/src/ingest/endpoint.rs` (`endpoint_normalize`, `endpoint_sources`) ; branchement dans
`daemon/src/ingest/mod.rs` (`ingest_events_batch_env`, juste après `dparsers_apply`). Catégories CIM :
`guatx_core::cim` (`posture`, `inventory`) + `config.d/cim/cim.v1.json` (v1.1). Dashboards : `seed_sca_dashboard`
/ `seed_vuln_dashboard` (`daemon/src/seeds.rs`).
