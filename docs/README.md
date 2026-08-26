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

## S'en servir (le cycle de vie, pour l'exploitant)

Ces cinq pages décrivent le produit **tel qu'il est**, pour quelqu'un qui l'exploite : installer,
configurer, s'en servir, désinstaller — dans les **trois** modes de déploiement. Chaque affirmation y
porte la commande qui la redonne, et ce qui n'a pas été exécuté y est dit à côté de l'exemple.
La garde [`check_operator_surface_is_documented.py`](../.github/scripts/check_operator_surface_is_documented.py)
dérive des sources ce qu'un exploitant doit pouvoir trouver — onglets, capteurs, modes, leviers — et
refuse qu'un ajout passe sans être écrit (`P9.7-b`).

| Document | État | Pour quoi |
|---|---|---|
| [TROIS-MODES.md](TROIS-MODES.md) | ✅ | **Le même geste dans les trois modes** — hôte natif, Docker, k3s. Où vivent les choses, comment on change un réglage, on ajoute une source, on crée un jeton, on sauvegarde, on met à jour — et **les gestes qui n'existent PAS** dans un mode, nommés au lieu d'être lissés. |
| [CONSOLE.md](CONSOLE.md) | ✅ | **La console, espace par espace et onglet par onglet** — ce que chacun fait, quel rôle le voit, ce qu'il ne fait pas. Dérivé de la structure de navigation, pas recopié. |
| [GXQL.md](GXQL.md) | ✅ | **Le langage de recherche** — les vingt commandes, les fonctions, les bornes, les couches de lecture seule, et surtout **ce que la grammaire n'accepte pas** (ni `OR`, ni groupement, ni tri multi-champs). |
| [AGENTS-PROTOCOLE.md](AGENTS-PROTOCOLE.md) | ✅ | **Les agents et leur protocole** — le contrat de fil, les jetons et ce que « lié à l'hôte » veut vraiment dire, le tampon disque et **son absence de borne côté shell**, les filigranes, le canal retour, TLS. |
| [CHIFFREMENT-COMPRESSION.md](CHIFFREMENT-COMPRESSION.md) | ✅ | **Chiffrement et compression, tels qu'ils sont** — ce qui est chiffré, ce qui ne l'est pas, l'ordre `age(zstd(…))`, et le défaut mesuré : **sans clé de base, le planificateur de sauvegarde ne produit rien**. |

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
| [VALEURS-DES-CAPTEURS.md](VALEURS-DES-CAPTEURS.md) | 📐 | **Ce qu'un capteur émet, et ce que ses valeurs veulent dire.** Le modèle commun ci-dessus déclare **un** vocabulaire par champ ; un capteur, lui, n'écrit qu'un sous-ensemble, et deux capteurs écrivent le même nom de champ avec des sens sans rapport — la clé est donc le couple **(source, champ)**. Dit ce que les producteurs livrés déclarent déjà, ce qui n'atteint ni le fil ni l'écran, et pourquoi l'écart ne se comble pas par une table écrite à la main (`P11.19-a`). |
| [PARSER-DSL.md](PARSER-DSL.md) | ✅ | Parseur déclaratif (DSL CIM) : ajouter un format de log **sans rebuild**. |
| [CONNECTOR-PRESETS.md](CONNECTOR-PRESETS.md) | ✅ | Presets `http_pull` prêts à l'emploi (AWS, M365/Entra, Okta, CrowdStrike, SentinelOne, GCP, Cloudflare, Google Workspace). Fichiers dans [`connector-presets/`](connector-presets/). |
| [SIGMA-IMPORTER.md](SIGMA-IMPORTER.md) | ✅ | Import de règles Sigma (unitaire et en masse) + delta de couverture ATT&CK. |
| [ENDPOINT-SECURITY.md](ENDPOINT-SECURITY.md) | ✅ | Sécurité endpoint en BYO-agent. |
| [OTLP-TRACES.md](OTLP-TRACES.md) | ✅ | Récepteur OpenTelemetry (traces). |

## Collecter aux extrémités (postes, équipements, boîtes aux lettres)

Là où les événements NAISSENT. Chacun de ces chemins finit sur le même contrat de fil que l'ingest —
c'est ce qui permet d'en ajouter un sans toucher au central.

| Document | État | Pour quoi |
|---|---|---|
| [../agent/README.md](../agent/README.md) | ✅ | **Agent d'endpoint cross-OS** : lit les sources natives de l'OS, tamponne sur disque (spool borné, *au moins une fois*), POST vers l'ingest. |
| [../agent/CI.md](../agent/CI.md) | ✅ | Comment cet agent est **validé** : ce que la CI exécute réellement par plateforme, et ce qu'elle ne fait que compiler. |
| [../collectors/windows/README.md](../collectors/windows/README.md) | ✅ | **Collecteur Windows** PowerShell, un seul fichier, sans agent ni spool : POST direct sur `/api/ingest`. |
| [../deploy/SYSLOG.md](../deploy/SYSLOG.md) | ✅ | **Récepteur syslog** (RFC 5424 + RFC 3164, UDP et TCP) et parseurs vendeur enfichables : un équipement réseau devient un collecteur de plus. |
| [../deploy/MAIL.md](../deploy/MAIL.md) | ✅ | **Détection mail** lue sur le maildir de l'hôte : motifs curés (IOC, hameçonnage, URL), événements minimaux. |
| [../deploy/EBPF-SIGMA.md](../deploy/EBPF-SIGMA.md) | ✅ | Brancher la détection runtime **eBPF** (sortie JSON Falco) et des règles **Sigma** sur l'ingest. |

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
| [../bench/README.md](../bench/README.md) | ✅ | **L'INSTRUMENT** qui produit le document ci-dessus : ce que chaque passe mesure, ce que chaque fichier de résultats contient, et les pièges de lecture nommés un par un. À lire avant de contredire un chiffre — ou d'en citer un. |

## Direction et internes

| Document | État | Pour quoi |
|---|---|---|
| [MODULE-MAP.md](MODULE-MAP.md) | ✅ | **Carte des sous-systèmes + invariants de sécurité.** Le document à lire avant une première contribution. |
| [AI-ML-DIRECTION.md](AI-ML-DIRECTION.md) | 📐 | Direction IA/ML : optionnelle, neutre vis-à-vis du fournisseur, neutre en RAM, OFF par défaut. |
| [DESIGN-P10-echelle-2go.md](DESIGN-P10-echelle-2go.md) | 📐 | **Tenir sous 2 Gio à l'échelle** — la carte du terrain MESURÉ (où partent les octets, où part la RAM de tri) et l'ordre des leviers qui en découle : chaud/froid, colonnaire, bloom, compression. C'est le document qui porte l'état le plus frais de ces travaux ; les clés `P10.*` de [ROADMAP.md](ROADMAP.md) y renvoient. Brainstorm ancré sur mesure, **pas** une décision figée. |

## Ressources non narratives

- [`img/`](img/) — captures d'écran et démo animée utilisées par le README.
- [`connector-presets/`](connector-presets/) · [`ai-presets/`](ai-presets/) — presets JSON livrés.
- [`soql-templates/`](soql-templates/) — bibliothèque de requêtes GXQL. **Nom de dossier historique
  conservé volontairement** : le fichier est embarqué par `include_str!` depuis le daemon et copié par le
  `Dockerfile` ; c'est un identifiant de build, pas un libellé utilisateur (cf. la frontière de nommage
  GXQL/`soql` décrite dans [`../README.md`](../README.md)).
