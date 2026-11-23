# Plume — orientation IA / ML

[English](AI-ML-DIRECTION.md) | [Français](AI-ML-DIRECTION.fr.md)

**Date :** 2026-07-18
**Statut :** réflexion de conception (roadmap, non livrée). La seule pièce livrée est le prérequis de la colonne `disposition` (v106). Tout le reste ici est cadré, cloisonné, et attend un feu vert.

> Ce document regroupe deux réflexions de conception en un document de conception durable, dans le dépôt :
> - **Assistance LLM** — un fournisseur d'IA optionnel, neutre vis-à-vis des fournisseurs, neutre en RAM, consultatif, avec l'humain dans la boucle, posé sur les surfaces fermées que plume a déjà.
> - **Triage ML natif** — un classifieur natif, dans le processus, explicable, écrit à la main pour le triage des alertes / la réduction des faux positifs, entraîné hors ligne sur les étiquettes `disposition`.
>
> Ce sont toutes deux des **explorations, pas des chantiers engagés**. Elles partagent une colonne vertébrale de gouvernance mais sont des **moteurs distincts** — ne faites pas passer le produit scalaire du ML natif par l'abstraction HTTP du LLM ; ce serait une erreur et cela brouillerait le récit de souveraineté.

---

## 0. Principe directeur

**L'intelligence native / souveraine d'abord — le LLM optionnel par-dessus.**

Le confort et l'intelligence que veut un exploitant de SOC (complétion, validation, score de triage) sont fournis **nativement et dans le cluster** par défaut ; un LLM est une **couche optionnelle ajoutée par-dessus**, jamais une dépendance. Concrètement :

- L'image par défaut n'a besoin d'**aucun LLM** ni d'**aucune inférence externe** pour être pleinement utile. Un client sans aucun point d'entrée d'IA fait tourner plume sans changement.
- Rien de gros ne tourne jamais dans le **pod de 2Go**. Le ML natif est un produit scalaire écrit à la main (µs, RAM négligeable). L'inférence LLM est 100% **distante** — le démon fait un seul appel HTTP/JSON gardé, le profil mémoire d'un notifier.
- **L'humain dans la boucle, toujours.** Ni le LLM ni le moteur de ML n'exécutent jamais une action ni ne ferment/ne rendent muet quoi que ce soit automatiquement. Chaque action passe toujours par `/api/actions` (armement / approbation / ledger / liste d'autorisation root), sans changement.
- **Ne masque jamais une vraie découverte.** C'est un invariant de premier ordre (ci-dessous). L'IA/le ML est une couche d'*annotation* en lecture, jamais sur le chemin qui décide de ce qu'on garde ou de ce qu'on montre.

La conception s'appuie entièrement sur des surfaces que plume livre déjà — elle expose des surfaces fermées à une intelligence optionnelle plutôt que d'« ajouter de l'IA à plume » :

| Surface existante | Rôle pour l'IA/le ML |
|---|---|
| SPI `SecretProvider` (`core/src/secret.rs`, v126) | modèle pour un SPI `AiProvider` |
| préréglages de connecteurs (`handlers/connectors/presets.rs`) | modèle pour des préréglages d'IA sans secret |
| compilateur GXQL fermé (`core/src/soql/mod.rs` `to_sql`) | la barrière qui rend inoffensif le texte généré par un LLM |
| assistant d'incident (`handlers/incidents.rs`) | modèle pour le brouillon/l'approbation avec l'humain dans la boucle |
| `ssrf_guard` + ledger (`ledger.rs`) | contrôle des sorties + audit de chaque appel |
| refus de champ → autorizer (`field_filter.rs`) | caviardage / masquage des prompts |
| z-score UEBA (`detection_advanced.rs baseline_anomaly`) + RBA (`rba.rs`) | l'analytique que le ML complète, sans jamais la dupliquer |

---

## 1. Contraintes dures (une proposition qui en viole une est fausse)

1. **2Go de RAM, non négociable** → pas de gros modèle local dans le pod ; inférence LLM 100% distante.
2. **Souveraineté** → IA strictement optionnelle, cloisonnée par feature, désactivée, inerte sans config.
3. **Indépendance vis-à-vis des fournisseurs** → apportez votre propre point d'entrée (Ollama / vLLM / llama.cpp sur une autre machine pour l'isolé du réseau, Azure OpenAI, Anthropic, tout compatible OpenAI) ; zéro valeur en dur.
4. **L'humain dans la boucle** → l'IA n'exécute jamais ; tout passe par `/api/actions` sans changement.
5. **Sûr face à l'injection par construction** → tout GXQL généré par l'IA passe par le compilateur fermé, qui le valide ou le refuse (une requête hallucinée ou malveillante est refusée comme le serait un mauvais GXQL humain).
6. **Données personnelles / secrets** → caviardage des prompts sur l'infrastructure `field_filter` existante, jamais de hash ni de jeton ; sorties via `ssrf_guard` ; chaque appel d'IA audité au ledger.
7. **Coût** → pas d'appel LLM par événement (ruineux à ~289k/jour) ; à la demande de l'analyste ou par incident/agrégat seulement.

---

## 2. Assistance LLM — le SPI `AiProvider`

### Architecture

- `core/src/ai.rs` = trait `AiProvider { id(); complete(&AiRequest) -> Result<AiResponse, AiError> }` — pur, `AiError` neutre (reflet de `SecretError`).
- Implémentation compatible OpenAI dans le démon (`ai/mod.rs`), HTTP, hors du core (reflet de `VaultProvider`).
- Table `ai_provider` + préréglages JSON, sans secret (`docs/ai-presets/*.json`) ; identifiant dans une colonne chiffrée, résolu par la grammaire `SecretRef`.
- **Double barrière** : feature Cargo `ai` (désactivée par défaut, des bouchons `#[cfg(not(feature="ai"))]` rendent 501, comme `saml`/`ldap`) **et** inerte à l'exécution sans rangée `ai_provider` / `PLUME_AI_ENABLE`.
- **Barrière cloud** : `PLUME_AI_ALLOW_CLOUD` (désactivée par défaut) — l'équivalent IA de `PLUME_SSRF_BLOCK_PRIVATE`. Les puristes de la souveraineté restent en auto-hébergé seulement ; les points d'entrée cloud sont opt-in.
- **Adaptateur natif Ollama** : Ollama expose à la fois `/v1/` (compatible OpenAI) et son `/api/chat` natif. Ajouter au SPI de fournisseur un adaptateur `api_shape=ollama-native` (`/api/chat` + découverte des modèles par `/api/tags` + `/api/embeddings` plus tard) pour qu'il corresponde exactement et prépare les embeddings.

### Cas d'usage (valeur ÷ effort ÷ adéquation)

| # | Cas d'usage | Phase | Notes |
|---|---|---|---|
| #1 | **Langage naturel→GXQL** | Ph1 (haute/faible) | L'analyste tape en anglais → le LLM propose du GXQL → **le compilateur fermé valide** → l'analyste l'exécute. La meilleure forme d'IA dans plume : le texte non fiable du LLM ne peut pas contourner `to_sql`, seuls des *noms* de champs remontent, aucune donnée. Le plus gros levier « sur-ensemble de Splunk ». |
| #2 | **Résumé / récit d'incident** | Ph1 (haute/faible-moyenne) | Condensé borné et caviardé → résumé pour la direction + chronologie + dédoublonnage, sous forme de **brouillon** que l'analyste retouche. Agrégé, pas par événement ; l'injection de prompt venue des journaux est neutralisée (la sortie est de la prose qui sera relue). |
| #3 | **Aide à l'écriture de règles** | Ph2 | Décrire un comportement → proposer du GXQL/Sigma → mêmes barrières de rédaction → règle créée **DÉSACTIVÉE**. Complète l'UEBA, ne la duplique pas. |
| #5 | **Résumé de renseignement sur les menaces** | Ph2 (petit, opportuniste) | — |
| #6 | **Suggestion de parseur pour une source inconnue** | Ph2/3 (prudent) | Le seul cas où des lignes de journal brutes entrent dans le prompt → échantillonnage minimal + revue par un admin ; sortie = config PARSER-DSL validée, pas du code. |
| #4 | **Copilote / investigation RAG** | Ph3 (exploration seulement, NON engagé) | La récupération **doit** passer par `to_sql` (RBAC/masquage préservés). Le point de friction, ce sont les embeddings (point d'entrée distant + base vectorielle = friction en isolé du réseau, tension avec le refus de DuckDB/ClickHouse). Commencer lexical/GXQL sans embeddings ; n'ajouter des vecteurs que s'ils se révèlent insuffisants. |

### ÉCARTS assumés

Triage LLM par événement (ruineux + duplique l'UEBA) ; réponse/remédiation automatique par l'IA (viole l'humain dans la boucle, **jamais**) ; seuils d'alerte auto-réglés (opaques, anti-reproductibles) ; génération de tableaux de bord en langage naturel (marginale) ; « recherche sémantique sur tous les événements » fondée d'abord sur les embeddings (coût/infra face au refus de DuckDB).

### Découpage en phases

- **Ph1** = SPI + fournisseur compatible OpenAI + préréglages + `ssrf_guard` + ledger + caviardage v1 (feature désactivée) + #1 & #2. C'est le MVP « l'IA dans plume » — petit, parce que les barrières existent déjà.
- **Ph2** = #3/#5/#6 (cloisonnés admin, désactivés par défaut).
- **Ph3** = #4 en exploration seulement. Ne **pas** engager d'infrastructure d'embeddings/vectorielle sans preuve qu'elle bat la récupération par GXQL.

La frontière réflexion/construction : Ph1-2 sont des constructions cloisonnées concrètes ; Ph3 est de l'exploration.

### Questions ouvertes pour l'exploitant

1. Premier cas d'usage ? (reco : **langage naturel→GXQL** — balle traçante, prouve la barrière du compilateur fermé de bout en bout avant de toucher aux données d'incident).
2. Préréglages cloud+local ou local seulement dans le build par défaut ?
3. Points d'entrée cloud permis tout court, ou auto-hébergé seulement → `PLUME_AI_ALLOW_CLOUD` désactivée par défaut ?
4. Politique de caviardage par défaut = la plus prudente possible + versionnée au ledger ?
5. Feature à la compilation + à l'exécution (reco : les deux, comme saml/ldap) ?
6. Budget d'appels d'IA par tenant dans l'interface d'administration ?

### CLI OSINT externe — DÉCISION : NON câblée, en récupérer la logique

Un modèle de CLI OSINT souveraine externe (recherche web en direct → récupération → synthèse LLM citée, avec un modèle offensif qui ne refuse rien) a été examiné comme référence. Conclusion : **web / Tor / OSINT / modèle offensif = mauvaise adéquation pour un SOC défensif** — ne pas l'appeler ni l'imiter.

Ce qui se récupère, adapté au vrai besoin de plume :

1. Le **garde-fou déterministe anti-hallucination** (`unverified_facts` : vérification verbatim par regex des CVE/chemins/versions/URL contre le texte source + passe de correction + drapeau ⚠) — le meilleur artefact.
2. La discipline **route → multi-angle → ancrage/citation `[n]`** + repli sûr « information insuffisante ».

Le « deep » se réinterprète pour un SOC comme une **recherche profonde dans les propres preuves de plume** (événements/dossiers/TI/runbooks via le compilateur GXQL fermé), pas sur le web — c'est la future phase RAG/copilote (Ph3), ancrée + citée + anti-hallucination. C'est pourquoi l'adaptateur natif Ollama (`/api/chat` + `/api/embeddings`) vaut d'être conservé.

---

## 3. Triage ML natif — écrit à la main, 0 crate, dans le processus

Distinct du SPI LLM : le LLM est une option compatible OpenAI qu'on peut activer ; **ceci est de la classification native** qui tourne dans le cluster, sans que rien ne quitte la machine.

### Verdict sur les ressources (la vedette) = écrit à la main, aucune crate de ML

Un scoreur par régression logistique = `sigmoid(Σ wᵢ·xᵢ + b)` = ~12 lignes, **0 nouvelle dépendance**, explicable par nature (chaque `wᵢ·xᵢ` est la contribution de la caractéristique, affichable). Conforme au précédent du TOTP écrit à la main dans le code existant. Modèle = un blob `serde` de quelques Ko dans une table.

**Refuser les crates de ML :** `linfa` tire `ndarray-linalg` → BLAS/LAPACK = exactement la mine `cc1plus` pour laquelle DuckDB a été refusé (le build de l'hôte n'a qu'un compilateur C, pour SQLCipher). `smartcore` (pur Rust, pas de BLAS obligatoire) = acceptable mais seulement cloisonné par feature et désactivé, jamais dans l'image par défaut de 2Go. `candle`/`ort`/`xgboost` = C/lourds = placement en sidecar seulement.

### Placements

- **(A) inférence seule dans le processus, en pur Rust** (produit scalaire en µs, RAM ~négligeable) = **DÉFAUT**.
- **(C) lot hors ligne** (entraînement + score dans la boucle cron existante `run_baselines`/`risk_rollup` ; le chemin chaud lit une colonne de score) = associé à A.
- (B) sidecar / (D) point d'entrée externe = repli **seulement** pour des modèles réellement lourds, justifiés au regard du budget.
- Préférence **A ≈ C ≫ B > D**. A/C gardent modèle + caractéristiques + étiquettes + inférence **dans** la boîte SQLCipher = l'exigence de souveraineté.

### Complète (sans la dupliquer) l'analytique existante

- z-score (`detection_advanced.rs baseline_anomaly`, univarié/non supervisé) → le ML ajoute le **supervisé multivarié** (à traiter contre bénin, appris).
- RBA (`rba.rs`) est **déjà construit** (score pondéré/décroissant/de vélocité) → le ML l'**alimente**, ne le reconstruit pas (en option, le score #1 devient une contribution de risque).
- CIM (`core/src/cim.rs`) = l'espace d'étiquettes pour la classification des événements.
- suppression/silence (`alerting.rs`, borné par TTL, inscrit au ledger) = le crochet pour le « candidat à la suppression ».
- Respecte le non-objectif déclaré (plafond de ML UEBA mature = ligne de base statistique + RBA) : la Phase 1 est du **triage supervisé**, pas de l'UEBA profonde non supervisée.
- Discipline des rollups : entraîner depuis `incident`/`alert`/rollup, **jamais un parcours de `event`**.

### Cas d'usage

| # | Cas d'usage | Phase | Notes |
|---|---|---|---|
| #1 | **Score de triage / réduction des faux positifs** | Ph1 (A+C, logistique écrite à la main) | Score P(à traiter) d'après source + règle + sévérité + heure + historique de l'entité ; **badge visible** + principaux facteurs ; reclasse la file comme colonne opt-in ; l'analyste tranche. |
| #2 | **RBA** | déjà fait | Ne pas reconstruire ; en option, le score #1 devient une contribution de risque. |
| #3 | **Classification événement → CIM** | Ph2 (C hors ligne, jetons naive-Bayes) | — |
| #4 | **Regroupement / dédoublonnage** | différé (B/C, opaque) | — |
| #5 | **Candidat à la suppression** | Ph1.5 (réutilise #1) | Via la machinerie de silence auditée — **jamais** une mise en sourdine automatique. Le plus sensible au regard de l'invariant de non-masquage → différé ou strictement approuvé élément par élément par l'analyste. |

ÉCARTÉ : anomalie par réseau de neurones/embeddings (opaque + RAM + rouvre le non-objectif) ; fermeture/action automatique sur le seul score (viole l'humain dans la boucle, ÉCART permanent).

### ⚠ Prérequis critique (livré v106) : la colonne `disposition`

La table `incident` (`migrate.rs`) avait `status/severity/priority/closed_ts/merged_into` mais **aucune colonne `disposition`/`verdict`/`false_positive`** — les étiquettes supervisées étaient donc des approximations bruitées (escaladé/actions = positif faible ; fermé vite/fusionné = négatif faible). Le levier le plus fort était une colonne additive nullable **`disposition` (TP/FP/benign/duplicate) saisie à la clôture du dossier** (migration additive, byte-identique en mode 0).

**C'est livré (schéma v106).** Le classifieur a désormais une vraie source d'étiquettes ; il n'attend plus que d'avoir accumulé assez d'étiquettes pour valoir d'être montré. Sans elle, le classifieur s'entraînerait sur une approximation faible.

### ⚠ Invariant de non-masquage / non-perturbation (de premier ordre, non négociable)

Le ML ne doit **jamais masquer une vraie découverte** ni **perturber le bon fonctionnement en cachant des éléments**. Conséquences dures :

- Le score ML est **purement additif / d'annotation** — il ne retire / ne cache / ne replie / ne filtre jamais une alerte ou une découverte d'aucune vue ; ne supprime jamais un vrai positif ; ne réordonne jamais d'une façon qui enfouirait une vraie découverte.
- Préférer une **colonne/un tri séparés en opt-in** à un reclassement par défaut. Dans la vue par défaut, **la vérité de la détection (sévérité / règle / RBA) l'emporte toujours sur l'avis du ML** — un score « bénin » ne fait jamais sortir de la visibilité un élément réel/incertain.
- Le pipeline déterministe (règles / corrélation / RBA / alerte / ingestion) tourne **sans changement** ; le ML est une annotation de la couche de lecture par-dessus, jamais sur le chemin qui décide de ce qu'on montre ou qu'on garde.
- Défaut = **tout montrer + annoter avec le ML** ; l'analyste choisit d'activer le tri/filtre ML.
- Le cas d'usage #5 (candidat à la suppression) est le plus sensible sous cet invariant → soit différé, soit strictement une suggestion approuvée élément par élément par l'analyste via la machinerie de silence réversible + auditée, **jamais** une mise en sourdine automatique/en masse.

### Garde-fous (les étiquettes viennent de l'analyste = attaquables)

- Le ML n'est jamais la seule barrière (fail-closed comme `run_due_rules` ; un score bénin reclasse + annote, ne supprime/ne ferme jamais sans un analyste ou une machinerie auditée).
- **Empoisonnement** (un editor compromis qui enseigne « vraie menace = bénin ») → quorum d'historique + plafond d'influence par source + chaque entraînement **inscrit au ledger** (auditable/réversible) + consultatif (dégrade le classement, ne fait jamais tomber le signal).
- **Dérive** → réentraînement cadencé + suivi de la précision/du rappel + faire ressortir la dérive.
- Reproductibilité = épingler l'instantané d'entraînement.

### Colonne vertébrale de gouvernance (exploitant) : natif + explicite + réglable + sûr dans le cluster

- **Transparence** = badge ML visible sur chaque alerte notée + principaux facteurs (gratuit avec le modèle linéaire ; une boîte noire qui ne sait pas justifier un « bénin » est un passif).
- **Réglable** via `cfg()` (comme `rba.rs`) + interface : seuil à traiter contre bénin, caractéristiques activées/désactivées, cadence de réentraînement, activation/désactivation par source. Admin seulement pour l'entraînement/la config, seuil exposé à l'analyste.
- **Sécurité** = **tout dans le cluster** (caractéristiques / étiquettes / modèle / entraînement / inférence dans SQLCipher — non négociable sur le réseau d'une organisation ; natif = souverain par défaut parce que rien ne sort). RBAC : admin = entraînement/config, viewer = consulter/régler le seuil. Chaque entraînement/remplacement/changement de politique audité au ledger (`audit_config_change`). Fail-closed.
- Feature `ml` désactivée par défaut (reflet de duckdb/saml ; build par défaut byte-identique ; écrit à la main → « désactivé » = zéro code lié en plus).

### Relation avec le SPI LLM

**Partager la colonne vertébrale de gouvernance** (barrière `PLUME_AI_ALLOW_CLOUD` + audit au ledger + transport vers point d'entrée externe pour le placement D, apportez-votre-propre-ML) **mais garder un moteur distinct** (faire passer un produit scalaire de quelques µs par une abstraction HTTP serait une erreur et brouillerait la souveraineté). En une ligne : **barrière partagée + audit partagé + SPI de transport externe partagé ; moteur d'inférence natif distinct.**

### Questions ouvertes pour l'exploitant

1. Colonne additive `disposition` OK ? — **[livrée v106]**
2. Score en lot C (zéro chemin chaud, ≤1 cycle de retard) contre A en ligne (frais, +µs) ? (reco : le lot d'abord).
3. Confirmer « jamais d'action automatique » (reclasser + annoter + proposer la suppression seulement) + seuil par défaut + activation par source par défaut.
4. Nombre minimal d'étiquettes avant affichage (démarrage à froid) ?
5. Tolérance à l'empoisonnement : PME à analyste unique (l'exploitant seul) contre ESN à plusieurs — plafonner l'influence par utilisateur maintenant ou différer ?
6. Écrire la logistique à la main (reco, 0 dépendance) contre `smartcore` cloisonné par feature et désactivé, réservé à de futurs arbres/forêts ?
7. Confirmer que l'apportez-votre-propre-ML (D) partage la barrière `PLUME_AI_ALLOW_CLOUD`, désactivée par défaut, sur le réseau d'une organisation.

---

## 4. Synthèse du découpage en phases & où en est le chantier

| Piste | État |
|---|---|
| Colonne `disposition` (prérequis du ML) | **Livrée (schéma v106)** |
| Scoreur de triage ML natif (#17) | Différé — attend l'accumulation d'étiquettes `disposition` ; écrit à la main, feature `ml` désactivée |
| Métriques de triage par disposition | Natif autonome, constructible maintenant |
| SPI LLM `AiProvider` + langage naturel→GXQL (#1) | Sur la branche `feat/ai-nl2soql`, **activation différée jusqu'au câblage d'Ollama au niveau du pod** (« Ollama en dernier ») ; migration `ai_provider` à renuméroter v107→v108 à l'activation |
| Résumé d'incident LLM (#2), aide aux règles (#3), TI/parseur (#5/#6) | Constructions cloisonnées Ph1-2, sur feu vert |
| Copilote RAG (#4) + embeddings | Exploration Ph3 seulement ; non engagé ; y reprendre le schéma anti-hallucination + ancrage de la CLI OSINT |

**En résumé :** le confort natif/souverain d'abord (complétion/validation de l'éditeur GXQL livrées en v129/v130, triage ML natif sur étiquettes), le LLM optionnel par-dessus (feature désactivée, neutre vis-à-vis des fournisseurs, neutre en RAM, l'humain dans la boucle, ne masque jamais une découverte).

---

*Ce sont des réflexions de roadmap (orientation de conception), pas des constructions livrées.*
