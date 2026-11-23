# Plume — Modules avancés (tous ouverts, séparables, désactivés par défaut)

[Français](ADVANCED_MODULES.md) | [English](ADVANCED_MODULES.en.md)

Plume est **entièrement open source** sous **[AGPL-3.0-or-later](LICENSE)** — le **produit entier**,
sans édition payante, sans fonction bridée et sans autre licence proposée à côté. Le SOC complet est ouvert, et
chaque capacité avancée décrite ci-dessous l'est aussi : elle vit dans ce dépôt, sous la même licence.

**Ouvert ne veut pas dire sans règles.** L'AGPL est un copyleft fort :

- si vous exploitez un Plume **modifié** comme service réseau, vous devez offrir aux utilisateurs de ce
  service sa **source correspondante complète** (AGPL §13) ;
- toute **œuvre dérivée** distribuée reste sous **AGPL-3.0-or-later** ;
- le **texte de la licence** et les **mentions de copyright et d'attribution** sont préservés.

La liberté de lire, exécuter, modifier et partager vient **avec** les obligations qui la maintiennent ; les
termes qui lient sont ceux de [`LICENSE`](LICENSE). La bibliothèque partagée
[`guatx-core`](https://github.com/guatxlabs/core), dont dépend le démon, est sous LGPL-3.0.

Ce document décrit une **stratification à l'intérieur du code ouvert**, pas une frontière commerciale. La
seule offre commerciale de GuatX autour de Plume est la **prestation de service** — accompagnement au
déploiement, support, hébergement managé —, jamais une licence sur le code.

---

## Le cœur — toujours présent

Tout ce qu'il faut pour exploiter un SOC complet, seul, en équipe ou dans vos propres opérations, sans rien
de désactivé :

| Domaine | Dans le build par défaut |
|---|---|
| **Ingestion** | agents (sh/systemd), point d'entrée compatible HEC, connecteur `http_pull` générique, syslog, DSL de parsers déclaratif |
| **Recherche et tableaux de bord** | GXQL (lecture seule, sans injection), FTS5, panneaux et tableaux de bord enregistrés |
| **Détection** | règles · playbooks SOAR-lite · **import Sigma** (unitaire et en masse) · **matrice de couverture ATT&CK** · catalogue curé ([`docs/DETECTION-CATALOG.md`](docs/DETECTION-CATALOG.md)) |
| **Threat-intel** | magasin d'IOC · import STIX 2.1 · correspondance à l'ingestion · connecteur TAXII 2.1 |
| **Risque (RBA)** | score par entité · alerte sur incident de risque |
| **Cases et réponse** | dossiers d'incident · réponse à vocabulaire fermé, exécuteurs par plateforme · **ledger en chaîne de hachage** |
| **Gouvernance** | legal-hold (rétention verrouillée, fail-closed), export du ledger à chaîne préservée, rôles composables — voir [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) |
| **Identité** | argon2id + RBAC, OIDC (Authorization-Code + PKCE), TOTP — voir [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) |
| **Chiffrement** | SQLCipher actif d'office, jetons liés à l'hôte, requêtes en lecture seule — voir [`docs/CHIFFREMENT-COMPRESSION.md`](docs/CHIFFREMENT-COMPRESSION.md) |
| **Bring-your-own-vendor** | contrat CIM · DSL de parsers · descripteurs de connecteurs · SDK d'extension ([`docs/SDK.md`](docs/SDK.md)) |
| **Purple** | **Mode Engagement** (interrupteur `PLUME_ENGAGEMENT_MODE`, éteint par défaut) et jonction avec [Forge](https://github.com/guatxlabs/forge), corrélée par technique ATT&CK |
| **Interface** | PWA bilingue FR/EN, tous les fuseaux IANA |

Si Plume tient sur un nœud, le cœur est le produit entier.

---

## Les modules avancés — ouverts, séparables, désactivés par défaut

Ces capacités visent l'**échelle**, le **travail à plusieurs organisations** ou des exigences
d'**identité et de stockage** particulières. Elles sont construites par-dessus le cœur, le cœur n'en dépend
pas, et chacune ne s'engage que par un geste explicite. Pour presque toutes, ce geste est une
**fonctionnalité Cargo** (absente du binaire si elle n'est pas compilée), souvent doublée d'un **interrupteur
d'exécution** qui vaut « éteint » par défaut ; le build par défaut ne compile **aucune** de ces fonctionnalités,
et l'image de conteneur livrée compile `ldap` et `cold_tier` (`ARG PLUME_FEATURES` du
[`Dockerfile`](Dockerfile)), dont les interrupteurs restent éteints tant que l'exploitant ne les pose pas.
**Le multi-tenant fait exception** : il n'a pas de fonctionnalité Cargo, son code est compilé dans le build
par défaut, et seul l'interrupteur d'exécution `PLUME_MULTI_TENANT` (qui vaut `0` par défaut) l'engage.

| Module | Comment l'engager | Documentation |
|---|---|---|
| **Tier froid colonnaire** (Parquet chiffré) | fonctionnalité `cold_tier` + `PLUME_COLD_TIER=1` | [`docs/DESIGN-P10-echelle-2go.md`](docs/DESIGN-P10-echelle-2go.md) |
| **Magasin ClickHouse** (un nœud ; adaptateur compilé et testé, aucune sélection à l'exécution câblée) | fonctionnalité `clickhouse` ; le démon sert toujours SQLCipher, aucun interrupteur ne bascule encore vers ce magasin | [`docs/CLICKHOUSE-STORE.md`](docs/CLICKHOUSE-STORE.md) |
| **ClickHouse distribué** (fondations, aucun chemin d'exécution câblé) | fonctionnalité `clickhouse-ha` | [`docs/CLICKHOUSE-HA.md`](docs/CLICKHOUSE-HA.md) |
| **Magasin DuckDB** (expérimental ; adaptateur compilé, aucune sélection à l'exécution câblée) | fonctionnalité `duckdb` ; comme pour ClickHouse, le démon sert toujours SQLCipher | [`docs/DUCKDB-STORE.md`](docs/DUCKDB-STORE.md) |
| **Annuaire LDAP / AD** | fonctionnalité `ldap` + configuration de l'annuaire | [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) |
| **SAML 2.0** (fournisseur de service) | fonctionnalité `saml` ; sans elle, le login SAML répond 501 | [`docs/NATIVE-IDP.md`](docs/NATIVE-IDP.md) §5 |
| **Dépôt de sauvegarde sur objet S3** | fonctionnalité `s3_backup` + destination `s3://` | [`docs/DR-plume-restore.md`](docs/DR-plume-restore.md) |
| **Avis IA** (inférence distante, sans réseau en CI) | fonctionnalité `ai` + `PLUME_AI_*` | [`docs/AI-ML-DIRECTION.md`](docs/AI-ML-DIRECTION.md) |
| **Multi-tenant / MSSP** (une base et une clé SQLCipher par tenant, provisioning SCIM 2.0) | compilé par défaut, sans fonctionnalité Cargo ; `PLUME_MULTI_TENANT=1` | [`README.md`](README.md) |

La liste des fonctionnalités Cargo fait foi dans `[features]` de [`daemon/Cargo.toml`](daemon/Cargo.toml).
Ce que l'intégration continue vérifie réellement pour chacune — compilée et testée, ou seulement
type-vérifiée — est dit dans [`CONTRIBUTING.md`](CONTRIBUTING.md) : un module avancé n'est pas mieux
défendu que ce que ce tableau annonce.

**Invariant de construction.** Non compilées, les fonctionnalités Cargo de ces modules laissent le build par
défaut **identique octet pour octet** au cœur — prouvé par un compte de tests constant (`EXPECTED_TESTS` dans
`.github/workflows/ci.yml`). Le multi-tenant, lui, est dans ce build : ce qui le tient éteint est
`PLUME_MULTI_TENANT` laissé à `0`, pas l'absence de son code.

---

## Principe pour les contributeurs

Les deux couches sont ouvertes sous AGPL ; la question est seulement de savoir où une capacité se range :

- elle rend la **détection, le chiffrement, le ledger ou la réponse** plus forts ou plus vérifiables, ou
  utiles à un exploitant seul → **elle appartient au cœur** ;
- elle relève de l'**échelle, du multi-tenant, d'un annuaire tiers ou d'un stockage
  distribué** → c'est un **module avancé**, construit séparable, éteint par défaut, jamais un fork du cœur
  ni une barrière qui en masque une partie.

Rien n'est payant ni retenu : ce qui se vend, ce sont des services autour du code, pas le code.
