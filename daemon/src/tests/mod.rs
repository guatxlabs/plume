    //! Tests de la mesure de couverture de détection (purple-team, blue-team value) : migration MITRE
    //! idempotente, propagation rule -> alert, et l'agrégation EXACTE servie par /api/coverage/detections.
    use super::*;
    use rusqlite::Connection;

include!("common.rs");
include!("rollup.rs");
include!("detection.rs");
include!("misc.rs");
include!("heartbeat_maintenance.rs"); // P4.1-e : ce qu'une fenêtre de maintenance lève vraiment
include!("ingest.rs");
include!("governance.rs");
include!("engagement.rs");
include!("cases.rs");
include!("incidents.rs");
include!("connectors.rs");
include!("firehose.rs");
include!("pubsub.rs");
include!("tokens.rs");
include!("rbac.rs");
include!("tenants.rs");
include!("sec.rs");
include!("saml.rs");
include!("ai.rs"); // #16 IA conseil — tests TOUS gated `#[cfg(feature="ai")]` en interne (build DÉFAUT = no-op, miroir saml.rs)
include!("soql_completion.rs");
include!("keyset.rs");
include!("query_verify.rs"); // preuve chemin de requête sans perte silencieuse (bornes/regex/joker/combo)
include!("rollup_b2b_adverse.rs"); // B2b (merge rollup ∪ raw) — ajout tests-only
include!("rollup_parity_family.rs"); // parité route rapide == chemin brut, sur une FAMILLE dérivée (pas un cas nommé)
include!("rollup_dim_coverage.rs"); // le JUMEAU : couverture du rollup PAR DIMENSION (trou mesuré, fermeture, garde)
include!("topn_ampleur.rs"); // L'AMPLEUR du plafond top-N (ligne de reste, sonde, aveu) + la rétention qui ferme le résidu ROUTE A
include!("route_a_portes.rs"); // ROUTE A : par quelle porte le sur-compte s'atteindrait — la rétention la ferme, et on le prouve
include!("backup_retention_adverse.rs"); // scheduler backup natif + rétention KEEP-N — tests-only
include!("backup_streaming.rs"); // LE CLAIR SUR DISQUE : staging vide sous surveillance, RAM sous gros BLOB, taille/temps des deux formats
include!("netban.rs"); // chantier ② Phase 1 — ban natif HTTP (IP réelle, store net_ban, guard, API admin)
include!("purge.rs"); // PURGE EXPLICITE d'événements — refus (legal-hold/tier froid/case/FTS), caducité du jeton, registre, dérivés
include!("query_timing.rs"); // la métrique d'attente : garde SANS SEUIL (S permis >= N clients -> attente NULLE) + un seul écrivain
include!("dedup_flotte.rs"); // LA FLOTTE : `event.dedup` cloisonné par hôte (perte silencieuse entre machines)
include!("snapshot_flotte.rs"); // LA FLOTTE (2) : la voie SNAPSHOT — la série est (kind, host)
include!("sondes_cout.rs"); // P3.7-a : CE QUE COÛTE une sonde de fraîcheur — invariance sous mutation du volume, avec son contre-exemple
include!("transport_liaison.rs"); // TRANSPORT + LIAISON : autorité de la requête (h1/h2), hôte d'une ligne ingérée, portée d'un jeton
include!("panneau_bibliotheque.rs"); // P7.13-a : la porte « SQL brut = admin » du panneau et la définition de bibliothèque
include!("index_redondance.rs"); // P10.2-d : garde DÉRIVÉE des index subsumés — on DEMANDE à SQLite, on n'énumère pas
include!("autoindex_retire.rs"); // P6.8-b : le mécanisme d'auto-index adaptatif est RETIRÉ — garde dérivée anti-zombie + purge de la dette prouvée par mutation
include!("onboarding.rs"); // ONBOARDING /api/setup : d'où sort le token, comment il est comparé/compté, et ce que rend le serveur quand la pose de l'admin N'A PAS été écrite
include!("partition_config.rs"); // P8.7-a : UNE seule voie de lecture des réglages — garde DÉRIVÉE (scanner de sources) + l'annonce de bascule, pure
include!("cle_at_rest_voie_unique.rs"); // P8.7-b : la clé SQLCipher lue par UNE voie — preuve sur les octets (SQLite format 3\0 ou non) + précédence + annonce
include!("barre_fts_vide_silencieux.rs"); // P10.7-a : la barre /api/search rendait « aucun résultat » quand le moteur DISAIT « je refuse » — garde DÉRIVÉE du moteur (balayage ASCII), pas une liste
include!("compactage_fts.rs"); // P10.7-b : une purge fait GROSSIR l'index plein-texte — le défaut mesuré en octets, le correctif, et la mutation (désactivé => l'index reste gonflé au MÊME octet)
include!("index_usage_event.rs"); // P10.D : QUI SE SERT DES INDEX DE `event` — corpus FERMÉ (semeurs + config.d + gabarits) rejoué en EXPLAIN QUERY PLAN, sous deux régimes de statistiques
include!("vieillissement_serie.rs"); // P10.5-a : CE QUE COÛTE UN VIEILLISSEMENT FROID — un succès muet n'est pas une mesure ; « 0 jour traité » ne doit pas ressembler à « je n'ai pas tourné » ; et la crête RSS est ramenée à la FENÊTRE (VmHWM est cumulé depuis le démarrage : c'est le piège dans lequel la mesure du 2026-08-10 est tombée)
include!("cles_de_cause_gardees.rs"); // P10.14-a : TOUTE CLÉ QUI NOMME UN TROU a un test qui la nomme SEULE — garde de SOURCE dérivée (périmètre = qui construit une étiquette `cause` ; clés = le COMPLÉMENT des noms de série), parce que deux lots d'affilée ont livré un chemin `fail-*` gardé par une simple PHRASE
include!("cles_de_roadmap_uniques.rs");
include!("checkpoint_wal_voie_unique.rs"); // P10.17-a : `wal_checkpoint(TRUNCATE)` rend son verdict par une LIGNE (busy,log,checkpointed), pas par un code d erreur — les 5 sites de production appelaient `execute_batch`, aveugle aux lignes, et croyaient tronquer meme quand un lecteur avait REFUSE. Voie unique + garde qui exclut tests, modules #[cfg(test)] internes et commentaires // P8.9-b : une ligne qui se declare `*(cle neuve)*` doit etre la SEULE definition de sa cle — j'ai ouvert P4.4-j sur une cle DEJA PRISE et je l'ai pousse ; en cherchant la mienne j'ai trouve P8.5-a en double, dont une copie perimee. La regle « une cle = une ligne » a ete REFUTEE par la mesure (6 entrees legitimes accusees) : celle-ci est la regle que le document se donne a lui-meme
include!("enonces_du_vieillissement.rs"); // P10.13-a : LA DÉRIVATION EST-ELLE UNE DÉRIVATION ? — aucun énoncé SQL de lecture ne peut naître hors de `cold_store::enonces`, sinon la sonde `cold-aging-plan` mesurerait une passe qui n'est plus celle qui tourne (garde de SOURCE, catégorie refusée, jamais une liste)
include!("ventilation_serie.rs"); // LA SÉRIE DU BUDGET : la ventilation ÉCRITE DANS LE TEMPS — un refus de mesurer reste un TROU (jamais un zéro), le parcours ne prend pas le verrou d'écriture, et les deux bornes (CPU, disque) sont mesurées
include!("sink_s3.rs"); // SINK OBJET DE L'ORDONNANCEUR DE SAUVEGARDE — tests TOUS gated `#[cfg(feature="s3_backup")]` (build DÉFAUT = no-op, miroir saml.rs/ai.rs) : signature v4 opposée à un oracle TIERS, et les quatre portes par lesquelles un envoi raté pourrait ressortir en succès (refus du service, relecture muette, relecture qui annonce une AUTRE taille, service injoignable)
include!("exercice_de_restauration.rs"); // P8.3-a : L'EXERCICE DE RESTAURATION — une sauvegarde jamais restaurée est une garantie non éprouvée. Restauration menée de bout en bout sur le chemin SYMÉTRIQUE (aucune clé de séquestre n'existe ici, et c'est délibéré), contenu comparé table par table, et l'ABSENCE d'exercice rendue visible et vieillissante. Mutations : archive tronquée, archive parfaite d'une base SANS LIGNE (le cas que l'ancien contrôle rendait vert), horloge avancée
include!("semaphore_interactif.rs"); // P7.8-a : CE QUE COÛTE LA BORNE INTERACTIVE, PAR ROUTE — le décompte des routes qui la consomment est REFAIT à chaque exécution (le constat d'origine en annonçait dix-neuf sans les avoir recomptées), l'attente du permit et le travail permit en main sont mesurés SÉPARÉMENT (un total confond « lente » et « en file », dont les leviers sont opposés), et la cardinalité est bornée deux fois — étiquette = gabarit de route (jamais l'URL), registre plafonné (plafond prouvé en le faisant mordre)
