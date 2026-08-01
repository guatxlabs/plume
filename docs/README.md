# Documentation Plume — index

Point d'entrée de `docs/`. Le *quoi* et le *pourquoi* de l'architecture sont dans
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) ; l'installation et les trois modes de déploiement dans
[`../README.md`](../README.md) ; les règles de contribution dans [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

**Statut** — chaque document porte l'un de ces états. Lisez-le avant de suivre une procédure : plusieurs
documents décrivent une **conception** dont le câblage runtime n'existe pas encore, et c'est dit
explicitement plutôt que laissé à la surprise de l'opérateur.

| État | Signification |
|---|---|
| ✅ **Livré** | implémenté dans le binaire livré, utilisable tel quel |
| 🧪 **Opt-in / expérimental** | implémenté derrière une feature de compilation ou un drapeau, non activé par défaut |
| 📐 **Conception** | design de référence ; **pas** (ou pas entièrement) câblé au runtime |

## Exploiter (opérateur)

| Document | État | Pour quoi |
|---|---|---|
| [DR-plume-restore.md](DR-plume-restore.md) | ✅ | **Reprise après sinistre** — les deux formats de backup produits par le produit, et comment restaurer chacun. À lire *avant* d'en avoir besoin. |
| [COMPLIANCE.md](COMPLIANCE.md) | ✅ | Posture et couverture de conformité (≠ certification). |
| [PURGE.md](PURGE.md) | ✅ CLI · 🧪 HTTP | **Purger des événements nommés** (au-delà de la rétention temporelle) : deux temps avec jeton, refus motivés (rétention légale, tier froid, chaîne de preuve), inscription au registre — et la liste explicite de ce qui **n'est pas** couvert, à commencer par les sauvegardes. |
| [DETECTION-CATALOG.md](DETECTION-CATALOG.md) | ✅ | Catalogue de détection curé livré comme point de départ. |
| [../deploy/CONFIDENTIALITE.md](../deploy/CONFIDENTIALITE.md) | ✅ | TLS, portée réelle des tokens d'agent, chiffrement at-rest, réserve sur l'export en clair du backup. |
| [../deploy/PROFILE.md](../deploy/PROFILE.md) | ✅ | Déployer sur n'importe quelle infra (variables `PLUME_*`, scripted inputs). |
| [../deploy/K8S.md](../deploy/K8S.md) | ✅ | Déploiement Kubernetes détaillé. |

## Ingérer et normaliser

| Document | État | Pour quoi |
|---|---|---|
| [SDK.md](SDK.md) | ✅ | Le modèle **bring-your-own-vendor** : par où brancher une source. |
| [CIM.md](CIM.md) | ✅ | Le modèle d'information commun — la taxonomie d'événements sur laquelle les règles se composent. |
| [PARSER-DSL.md](PARSER-DSL.md) | ✅ | Parseur déclaratif (DSL CIM) : ajouter un format de log **sans rebuild**. |
| [CONNECTOR-PRESETS.md](CONNECTOR-PRESETS.md) | ✅ | Presets `http_pull` prêts à l'emploi (AWS, M365/Entra, Okta, CrowdStrike, SentinelOne, GCP, Cloudflare, Google Workspace). Fichiers dans [`connector-presets/`](connector-presets/). |
| [SIGMA-IMPORTER.md](SIGMA-IMPORTER.md) | ✅ | Import de règles Sigma (unitaire et en masse) + delta de couverture ATT&CK. |
| [ENDPOINT-SECURITY.md](ENDPOINT-SECURITY.md) | ✅ | Sécurité endpoint en BYO-agent. |
| [OTLP-TRACES.md](OTLP-TRACES.md) | ✅ | Récepteur OpenTelemetry (traces). |

## Interopérer

| Document | État | Pour quoi |
|---|---|---|
| [DATASOURCE.md](DATASOURCE.md) | ✅ | Servir les requêtes **vers** Grafana/Prometheus (Plume comme source de données). |
| [OBSERVABILITY-AS-CODE.md](OBSERVABILITY-AS-CODE.md) | ✅ | Tableaux de bord et règles versionnés. |
| [NATIVE-IDP.md](NATIVE-IDP.md) | ✅ OIDC/LDAP/MFA · 🧪 SAML | IdP natif. **SAML exige `--features saml`** — absent de l'image livrée (→ 501). |

## Stockage — tiers analytiques

| Document | État | Pour quoi |
|---|---|---|
| [DUCKDB-STORE.md](DUCKDB-STORE.md) | 🧪 | Tier analytique WARM. Le sélecteur `PLUME_STORE` documenté est **une conception non câblée** — seul `PLUME_STORE_DUCKDB_EXPERIMENTAL` est lu. |
| [CLICKHOUSE-STORE.md](CLICKHOUSE-STORE.md) | 📐 | Adaptateur mono-nœud. `PLUME_STORE=clickhouse` **n'a aucun effet** aujourd'hui. |
| [CLICKHOUSE-HA.md](CLICKHOUSE-HA.md) | 📐 | Scaffold distribué multi-nœuds — inerte, non câblé (et le masquage n'est pas encore porté sur le SPI neutre : à lire avant d'y toucher). |

## Mesurer les performances

| Document | État | Pour quoi |
|---|---|---|
| [BENCHMARK.md](BENCHMARK.md) | ✅ | **La référence chiffrée, et l'instrument pour la contredire.** La matrice (classes de requêtes × fenêtres × masquage × FTS × tier froid × taille de flotte) sur une base synthétique au profil de production, daemon sous cgroup `MemoryMax=2G` **appliqué** — pas observé. Dit ce qui est **lent** avec la même franchise que ce qui est rapide, publie les leviers restants par gain mesuré, et NOMME les cellules qu'il n'a pas mesurées. Le harnais (`../bench/`) rejoue la matrice par une commande unique et publie ses données brutes, pour qu'un tiers puisse refaire — ou contredire — la mesure. **Lisez ses qualificatifs avant d'en citer un chiffre** : aucun compte n'est recopié ici (il pourrirait), le volume de référence n'est pas 10 M — le débit d'ingest réel et la CAUSE MESURÉE de sa dégradation sont publiés à la place — et la base tenait dans le cache de pages, donc les latences sont un **meilleur cas** borné par le CPU. |

## Direction et internes

| Document | État | Pour quoi |
|---|---|---|
| [MODULE-MAP.md](MODULE-MAP.md) | ✅ | **Carte des sous-systèmes + invariants de sécurité.** Le document à lire avant une première contribution. |
| [AI-ML-DIRECTION.md](AI-ML-DIRECTION.md) | 📐 | Direction IA/ML : optionnelle, neutre vis-à-vis du fournisseur, neutre en RAM, OFF par défaut. |

## Ressources non narratives

- [`img/`](img/) — captures d'écran et démo animée utilisées par le README.
- [`connector-presets/`](connector-presets/) · [`ai-presets/`](ai-presets/) — presets JSON livrés.
- [`soql-templates/`](soql-templates/) — bibliothèque de requêtes GXQL. **Nom de dossier historique
  conservé volontairement** : le fichier est embarqué par `include_str!` depuis le daemon et copié par le
  `Dockerfile` ; c'est un identifiant de build, pas un libellé utilisateur (cf. la frontière de nommage
  GXQL/`soql` décrite dans [`../README.md`](../README.md)).
