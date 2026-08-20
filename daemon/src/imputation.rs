//! L'IMPUTATION D'UNE ALERTE — À QUELLE(S) SOURCE(S) ELLE SE RAPPORTE, ET D'OÙ VIENT CE NOM.
//! Un seul auteur pour la question « quelles sources cette alerte concerne-t-elle ? », appelé par les
//! DEUX producteurs d'alertes (`run_due_rules`, `check_heartbeats`) et lu par la fraîcheur par-source.
use crate::*;

// ====================================================================================================
// CE QUI ÉTAIT CASSÉ (clé de roadmap S7).
//
// La pastille d'une source bascule sur `active_alerts > 0` (web/freshness.js). Le daemon calculait ce
// compteur en cherchant des jetons `source=<nom>` DANS LE TEXTE DE LA REQUÊTE de la règle, recopié dans
// `alert.detail` (cf. `extract_query_sources`). Conséquence : une alerte qui ne NOMME pas sa source dans
// sa prose n'imputait RIEN, et l'exploitant apprenait que « quelque chose » ne remonte plus sans savoir
// QUOI — c'est-à-dire qu'il devait refaire à la main le travail que l'alerte prétendait lui épargner.
//
// LA MESURE (dérivée du contenu LIVRÉ, comptée par `imputation_ampleur_du_contenu_livre`) :
//   - 47 règles livrées dans `config.d/rules/**` ; 36 portent un jeton `source=` dans leur texte, 11 n'en
//     portent AUCUN — dont 4 sont ACTIVES par défaut. Les 11 sont exactement les règles NORMALISÉES CIM
//     (`search category=firewall …`, `search category=config collect_status=unavailable …`) : celles que
//     le principe vendor-agnostic du projet demande d'écrire GÉNÉRIQUES. Le mécanisme textuel punit donc
//     précisément les règles que la conception réclame.
//   - Les alertes de CAPTEUR MUET (`heartbeat.*`, 23 capteurs) ne portent JAMAIS de jeton `source=` : leur
//     `detail` est une phrase (« aucune donnée depuis N min »). Les 23 étaient donc, elles aussi,
//     structurellement non imputables — alors que le descripteur de leur sonde NOMME la source.
//
// LA FORME DÉRIVÉE. Une règle est de la PROSE ; l'événement qui la fait tirer, lui, porte l'identité de sa
// source DANS UNE COLONNE (`event.source`), et une sonde de fraîcheur porte la sienne DANS SON TYPE
// (`Sonde::EventFlux { sources }`, `Sonde::Instantane { kind }`). L'imputation se lit donc là — jamais
// dans une chaîne de caractères. Le résultat est ÉCRIT SUR L'ALERTE (`alert.sources`, migration v115) au
// moment où elle est levée : le chemin de LECTURE (fraîcheur, watchdog 5 s) n'a plus rien à deviner.
//
// L'ORDRE DE PRÉFÉRENCE EST ÉCRIT UNE FOIS, ICI, et les deux producteurs l'héritent :
//   1. la DONNÉE (colonne `source` des événements appariés / descripteur typé de la sonde) ;
//   2. à défaut, le TEXTE de la règle — le mécanisme historique, CONSERVÉ : c'est la seule voie pour une
//      règle en SQL BRUT, opaque au compilateur GXQL (`source='cloudflare'` y est lisible, et 16 règles
//      semées sur 16 en dépendent) ;
//   3. à défaut, un INCONNU NOMMÉ (`SOURCE_INDETERMINABLE`) — jamais un silence. Une alerte qui retombe
//      sur rien redevient l'alerte globale du défaut d'origine ; une alerte qui DIT qu'elle ne sait pas
//      nommer sa source laisse l'exploitant décider. Un « inconnu » nommé vaut mieux qu'une imputation
//      fausse, et il vaut mieux qu'un zéro muet.
//
// CE QUE ÇA NE FERME PAS, ÉCRIT POUR ÊTRE OPPOSABLE. Dix endroits du daemon insèrent une alerte ;
// TROIS passent par ici — l'ordonnanceur de règles et le dead-man's-switch des capteurs, c'est-à-dire
// les deux qui portaient le défaut S7, plus la sonde de FLOTTE (P3.2-a). Les SEPT autres (alerting
// avancé, corrélations, scoring par risque, pression disque à l'ingest, alerte semée) laissent la
// colonne VIDE et retombent donc sur le chemin textuel : leur comportement est byte-identique à avant,
// ni meilleur ni pire. C'est un périmètre assumé et non un oubli — imputer depuis la donnée demande, à
// chaque producteur, de savoir QUELLES lignes ont fait tirer, et cela ne se devine pas depuis ici. Ce
// qui est garanti, c'est qu'un ONZIÈME producteur ne pourra pas rejoindre cette liste en silence :
// `imputation_tout_producteur_d_alerte_declare_son_choix` compte les sites en LISANT LA SOURCE et
// refuse un nombre qui bouge. C'est d'ailleurs cette garde qui a arrêté la sonde de flotte, écrite
// sans y penser : son alerte se rapporte à des HÔTES et à AUCUN feed, donc elle impute à l'INCONNU
// NOMMÉ. Un « inconnu » assumé vaut mieux qu'une pastille de source allumée à tort.
//
// CE QUE ÇA NE CHANGE PAS. Aucune alerte n'est créée, supprimée, re-titrée ni re-sévérisée : l'alerte
// GLOBALE d'une règle reste UNE alerte par règle, avec sa clé `rule-{id}`, son titre et son `detail`
// inchangés (garde : `imputation_ne_cree_ni_ne_retitre_aucune_alerte`). Elle gagne une colonne qui dit à
// QUOI elle se rapporte. Les alertes ANTÉRIEURES à la migration portent `sources=''` -> le lecteur
// retombe sur le chemin textuel : leur comportement est byte-identique.
// ====================================================================================================

/// LE NOM QU'ON DONNE À CE QU'ON NE SAIT PAS NOMMER. Écrit dans `alert.sources` plutôt que de laisser la
/// colonne vide : une colonne vide est indiscernable d'une alerte d'avant la migration, et retomberait
/// donc en silence sur le chemin textuel — c'est-à-dire sur le défaut. Ce jeton ne correspond au nom
/// d'AUCUN feed (il porte des espaces et des parenthèses, qu'un `event.source` ne porte pas) : il est
/// donc compté à part (`unattributed_alerts` de /api/freshness) au lieu d'accuser une source au hasard.
pub(crate) const SOURCE_INDETERMINABLE: &str = "(source indéterminée)";

/// SÉPARATEUR de la liste stockée. Le saut de ligne, et non la virgule : un nom de source est un
/// identifiant de flux (`k8s-log`, `minio-audit`, `sshd-session`) et n'en contient jamais, alors qu'une
/// virgule reste plausible dans un nom exotique. Un nom qui en contiendrait un est remplacé par
/// `SOURCE_INDETERMINABLE` plutôt que de couper la liste en deux noms faux (cf. `imputation_encoder`).
const SEPARATEUR: char = '\n';

/// PLAFOND de noms retenus pour UNE alerte. La cardinalité de `event.source` est petite par construction
/// (un flux par collecteur), donc ce plafond ne mord jamais en usage nominal ; il existe pour qu'une
/// règle balayant une base inattendue ne puisse pas faire enfler une ligne d'alerte sans borne (budget
/// 2 Gio). Quand il MORD, le reste n'est pas jeté en silence : `SOURCE_INDETERMINABLE` est ajouté — la
/// liste DIT qu'elle est tronquée.
const MAX_SOURCES: usize = 32;

/// Encode la liste telle qu'elle est STOCKÉE dans `alert.sources`. Dédoublonne en préservant l'ordre
/// d'arrivée, remplace tout nom vide ou porteur du séparateur par l'inconnu NOMMÉ, et borne à
/// `MAX_SOURCES`. Rend `SOURCE_INDETERMINABLE` (jamais la chaîne vide) sur une entrée vide : la colonne
/// vide est réservée aux alertes d'AVANT la migration.
pub(crate) fn imputation_encoder(sources: &[String]) -> String {
    let mut vus: Vec<String> = Vec::new();
    let mut tronquee = false;
    for s in sources {
        let n = s.trim();
        let nom = if n.is_empty() || n.contains(SEPARATEUR) { SOURCE_INDETERMINABLE.to_string() } else { n.to_string() };
        if vus.contains(&nom) {
            continue;
        }
        if vus.len() >= MAX_SOURCES {
            tronquee = true;
            break;
        }
        vus.push(nom);
    }
    if tronquee && !vus.iter().any(|v| v == SOURCE_INDETERMINABLE) {
        vus.pop();
        vus.push(SOURCE_INDETERMINABLE.to_string());
    }
    if vus.is_empty() {
        return SOURCE_INDETERMINABLE.to_string();
    }
    vus.join(&SEPARATEUR.to_string())
}

/// Décode `alert.sources`. La chaîne VIDE rend un vecteur vide — et c'est le signal, pour le lecteur,
/// qu'il s'agit d'une alerte d'avant la migration et qu'il doit retomber sur le chemin textuel.
pub(crate) fn imputation_decoder(csv: &str) -> Vec<String> {
    csv.split(SEPARATEUR).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string()).collect()
}

/// IMPUTATION D'UNE ALERTE DE CAPTEUR MUET — dérivée du DESCRIPTEUR de la sonde, jamais de son libellé.
///
/// Le `match` est EXHAUSTIF : une 5ᵉ variante de `Sonde` ne compilera pas tant qu'elle n'aura pas dit à
/// quel(s) feed(s) elle s'impute (E0004) — la même mécanique que `Sonde::requete`, et pour la même
/// raison : c'est le seul endroit où l'oubli serait silencieux.
///
/// LES NOMS RENDUS SONT CEUX DES FEEDS DE `compute_freshness`, pas des noms voisins : un feed d'events y
/// est nommé par sa `source` et un feed d'instantané par son `kind` (cf. `mk("snapshot", k, …)`). C'est
/// ce qui fait que l'imputation ARRIVE quelque part au lieu de compter dans le vide.
pub(crate) fn imputer_alerte_de_capteur(sonde: &Sonde) -> Vec<String> {
    match sonde {
        Sonde::Instantane { kind } => vec![(*kind).to_string()],
        Sonde::EventFlux { sources } => sources.iter().map(|s| (*s).to_string()).collect(),
        Sonde::EventBattementSante { source } => vec![(*source).to_string()],
        // LE CAS HONNÊTE. Le feed des métriques est nommé DYNAMIQUEMENT par la fraîcheur
        // (« métriques · N séries ») : il n'existe aucun nom stable à imputer ici, et en inventer un
        // ferait basculer un feed qui n'est pas celui-là. On le DIT.
        Sonde::MetriqueFlotteConfondue => vec![SOURCE_INDETERMINABLE.to_string()],
    }
}

/// IMPUTATION D'UNE ALERTE DE RÈGLE — dérivée des ÉVÉNEMENTS APPARIÉS (colonne `event.source`).
///
/// COMMENT LA REQUÊTE D'IMPUTATION EST FABRIQUÉE. On ne réécrit PAS la prose de la règle : on garde son
/// PREMIER ÉTAGE — découpé par le découpeur du compilateur lui-même (`soql_split_pipes`, qui respecte les
/// guillemets) — et on lui applique `| stats count by source`. Le premier étage EST le prédicat de
/// sélection (`search …`) : ce qu'on obtient, ce sont les sources des événements que la règle REGARDE,
/// c'est-à-dire les feeds que son alerte concerne. Les étages suivants (corrélation, seuil) ne changent
/// pas cet ensemble de feeds — ils décident seulement s'il faut alerter, ce qui a DÉJÀ été décidé quand
/// on arrive ici.
///
/// CE QU'ELLE NE COUVRE PAS, ET POURQUOI C'EST SANS CONSÉQUENCE : une règle en SQL BRUT (`is_soql=false`)
/// est opaque — il n'y a pas d'étage à isoler. On rend le vecteur vide, et l'appelant retombe sur le
/// chemin textuel, qui lit très bien `source='cloudflare'` (les 16 règles semées sont dans ce cas).
///
/// BUDGET. Une requête de plus, et une seule, PAR TIR (pas par évaluation) : elle est lancée depuis la
/// phase parallèle BORNÉE de `run_due_rules` (`detect_concurrency`), sur une connexion LECTURE SEULE,
/// JAMAIS sous le verrou d'écriture. Elle porte le budget AUTO (5 s) et non le budget interactif : une
/// imputation est un CONFORT, jamais une détection — si elle ne tient pas dans le budget, l'alerte part
/// quand même, imputée à l'inconnu NOMMÉ. Le contraire (allonger le balayage de détection pour un
/// affichage) serait payer une pastille avec un angle mort.
pub(crate) fn sources_des_evenements_apparies(db_path: &str, query: &str, is_soql: bool, window_s: i64) -> Vec<String> {
    if !is_soql {
        return Vec::new();
    }
    let etages = guatx_core::soql::soql_split_pipes(query);
    let Some(premier) = etages.first() else { return Vec::new() };
    let premier = premier.trim();
    if premier.is_empty() {
        return Vec::new();
    }
    let Ok(sql) = rule_sql(&format!("{premier} | stats count by source"), true, window_s) else {
        return Vec::new();
    };
    let Ok(v) = run_query_ex(db_path, &sql, query_budget_ms(), None) else {
        return Vec::new();
    };
    // Colonne `source` retrouvée PAR SON NOM (le compilateur nomme les colonnes de groupement) ; à
    // défaut, la première — jamais un index deviné en silence sur une forme inattendue.
    let idx = v
        .get("columns")
        .and_then(|c| c.as_array())
        .and_then(|c| c.iter().position(|n| n.as_str() == Some("source")))
        .unwrap_or(0);
    let Some(rows) = v.get("rows").and_then(|r| r.as_array()) else { return Vec::new() };
    rows.iter()
        .filter_map(|r| r.as_array())
        .filter_map(|r| r.get(idx))
        // Une ligne dont la source est NULL/vide est un événement réellement sans source : elle devient
        // l'inconnu NOMMÉ à l'encodage, pas un feed silencieusement oublié.
        .map(|c| c.as_str().unwrap_or("").to_string())
        .collect()
}

/// LA DÉCISION COMPLÈTE POUR UNE ALERTE DE RÈGLE, dans l'ordre de préférence du bandeau. Rend la chaîne
/// PRÊTE À ÉCRIRE dans `alert.sources` — jamais vide (cf. `imputation_encoder`).
pub(crate) fn imputer_alerte_de_regle(db_path: &str, query: &str, is_soql: bool, window_s: i64) -> String {
    let par_la_donnee = sources_des_evenements_apparies(db_path, query, is_soql, window_s);
    if !par_la_donnee.is_empty() {
        return imputation_encoder(&par_la_donnee);
    }
    // Repli TEXTUEL — le mécanisme historique, inchangé. `imputation_encoder` transforme un repli vide
    // en inconnu NOMMÉ : c'est là que « rien » cesse d'être silencieux.
    imputation_encoder(&extract_query_sources(query))
}
