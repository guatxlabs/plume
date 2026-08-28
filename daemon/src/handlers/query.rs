//! Requête analytique (P3) en lecture seule : handler `query` (SQL brut réservé admin / GXQL ouvert),
//! annulation `cancel`, et export (`export_max_rows`, `csv_cell`/`result_to_csv`/
//! `result_to_json_records`, `safe_export_name`, handler `export`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// COUNT de pagination BORNÉ (perf) — plafond de lignes comptées pour le `total` d'une page. AU-DESSOUS du
/// plafond : le total est EXACT (dernière page + numéros justes pour les petits résultats). AU plafond : on
/// renvoie `total = PAGINATION_COUNT_CAP` + `total_capped:true` (le SPA rend « … sur 10 000+ »). POURQUOI :
/// `SELECT COUNT(*) FROM (<compilé>)` non borné déchiffre+scanne TOUT le match-set (auditd-7d ~millions) juste
/// pour un total, alors que la page n'est que `LIMIT ~100`. On WRAP en `SELECT COUNT(*) FROM (SELECT 1 FROM
/// (<compilé>) LIMIT CAP+1)` : SQLite aplatit la sous-requête (le SELECT 1 n'a besoin d'aucune colonne grasse)
/// -> avec idx_event_src_ts le balayage est INDEX-ONLY et s'ARRÊTE à CAP+1 lignes (jamais le full-scan). Si le
/// compte atteint CAP+1 -> il y a > CAP lignes -> capé ; sinon exact. Best-effort inchangé : un COUNT qui dépasse
/// le watchdog reste `total=-1` (UI ◀ ▶ sans numéros).
pub(crate) const PAGINATION_COUNT_CAP: i64 = 10_000;

/// #18 — REFUS MOTIVÉ d'une valeur dérivée d'un ensemble froid TRONQUÉ (cf. `cold_store::exactness`).
/// 422 et non 400 : la requête est SYNTAXIQUEMENT valide et le serveur la comprend — il refuse de la
/// TRAITER parce que la seule réponse qu'il pourrait former serait un nombre faux. Un client peut donc
/// distinguer « ta requête est mal écrite » de « ta fenêtre est trop large pour une réponse exacte »,
/// ce qu'un 400 fourre-tout lui interdirait. `truncated:true` + `reason` sont posés dans le corps pour
/// que le SPA puisse proposer la voie exacte sans parser un message.
#[cfg(feature = "cold_tier")]
fn refuse_truncated_aggregate(t: crate::cold_store::TruncatedAggregate) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": t.message(),
            "reason": "cold_truncated_aggregate",
            "truncated": true,
            "cold_rows_hydrated": t.rows_hydrated,
            "cold_row_cap": t.cap,
        })),
    )
        .into_response()
}

/// L'ESPACE D'IDENTIFIANT DANS LEQUEL UN CURSEUR FROID A ÉTÉ NUMÉROTÉ.
///
/// LE FAIT QUI OBLIGE À L'ÉCRIRE. Une ligne froide n'a pas d'`id` : `id` n'est PAS stocké en Parquet
/// (`reader::PARQUET_COLS`). Les deux voies froides lui en FABRIQUENT donc un, et pas le même :
///   • l'oracle d'union hydrate dans `cold_event`, dont l'`id INTEGER PRIMARY KEY` est un rowid AUTO
///     assigné dans l'ordre canonique d'insertion (`reader::COLD_EVENT_DDL`) — un rang dans l'ensemble
///     HYDRATÉ, donc une numérotation qui dépend de la fenêtre ;
///   • le browse colonnaire fabrique `seq * COLD_FILE_MAX_ROWS + position` — une numérotation qui dépend
///     du FICHIER.
/// Les deux sont des entiers, dans des plages qui se recouvrent, et rien dans `{ts,id}` ne dit lequel.
/// Rejouer l'un dans l'autre ne produit ni erreur ni page vide : ça produit une page qui COMMENCE
/// AILLEURS — trou ou doublon, silencieux, au milieu d'une traversée.
///
/// CE QUE LA MARQUE FERME, ET DANS LES DEUX SENS. Elle est posée par la voie colonnaire sur le curseur
/// qu'elle ÉMET (et seulement quand la dernière ligne rendue est froide, cf. `keyset_marque_espace_id`),
/// et elle est LUE à l'entrée : un curseur froid qui ne la porte pas n'a pas été émis ici, donc il n'y
/// entre pas ; un curseur froid qui la porte n'est lisible QUE par elle, donc aucun repli ne l'emporte
/// vers l'oracle. Avant elle, le handler devinait l'espace d'un curseur à partir de son `ts` — « sous la
/// frontière donc synthétique » — ce qui est FAUX dès que la page précédente a été servie par l'oracle,
/// et c'est le cas ORDINAIRE d'une forme que le colonnaire ne route pas.
///
/// CE QU'ELLE NE TIENT PAS, ET CE QUI EN DÉCOULE : un client qui reconstruit `{ts,id}` à la main au
/// lieu de renvoyer le `next_cursor` reçu perd la marque. Ce cas était autrefois DÉDUIT — la routabilité
/// de la traversée servait à répondre « la page précédente est-elle passée par moi ? » — et cette
/// déduction a été SUPPRIMÉE le 2026-08-28 avec la fonction qui la portait : elle rendait deux verdicts
/// opposés sur le même curseur selon une prémisse qui cesse d'être vraie quand la frontière froide
/// avance entre deux pages. Un curseur froid SANS marque se refuse désormais, sans exception et sans
/// rien consulter (`verdict_du_curseur`, `refuse_curseur_froid_sans_espace`). La console livrée ne peut
/// pas le produire : une garde de source interdit qu'un module de `web/` reconstruise un curseur.
///
/// OÙ LA PROMESSE EST TENUE, ET POURQUOI PAS ICI (mesuré le 2026-08-28). « Aucun repli ne l'emporte
/// vers l'oracle » était FAUX D'UN CRAN AU-DESSUS de la fonction qui l'écrit : la règle d'entrée vivait
/// DANS `cold_keyset_vectorized_page`, et la décision de l'APPELER vivait au-dessus d'elle. Il suffisait
/// que la porte se ferme ENTRE deux pages pour que le curseur marqué parte à l'oracle sans qu'une seule
/// ligne ne consulte la marque. La règle d'entrée est désormais lue AVANT la porte et INDÉPENDAMMENT de
/// son état d'armement, sur la lecture `lire_espace_du_curseur` (cf. `refuse_curseur_sans_lecteur`).
#[cfg(feature = "cold_tier")]
pub(crate) const ESPACE_ID_COLD_VECTORISE: &str = "cold-vectorise";

/// L'ESPACE D'IDENTIFIANT DE L'ORACLE D'UNION — un PRÉFIXE, suivi de l'empreinte de la numérotation.
///
/// POURQUOI IL FALLAIT L'ÉCRIRE AUSSI (mesuré le 2026-08-28). Une seule des deux voies marquait ce
/// qu'elle émet, si bien que « ce curseur vient de l'oracle » n'était pas un FAIT mais une DEVINETTE :
/// la voie colonnaire y répondait par la ROUTABILITÉ de la traversée — « si je sais servir cette forme,
/// alors la page précédente est passée par moi ». La prémisse est fausse dès qu'une page précédente a
/// été servie par l'oracle SANS que la forme y soit pour rien, et c'est un geste ORDINAIRE de la
/// console : un SAUT DE PAGE (`offset > 0`) ferme la porte colonnaire, l'oracle sert et rend un curseur
/// froid, puis « Suivant » le renvoie sur une forme ROUTABLE -> échec de page « la marque a été perdue »,
/// alors que le client n'a rien perdu.
///
/// POURQUOI CE N'EST PAS UN MOT MAIS UN PRÉFIXE (mesuré le 2026-08-28, DEUXIÈME MESURE). Le mot seul
/// nommait le LECTEUR ; il ne nommait pas la NUMÉROTATION. Or l'oracle numérote « un rang dans
/// l'ensemble HYDRATÉ » — ce module l'écrit trente lignes plus haut — donc DEUX pages de l'oracle ne
/// partagent une numérotation que si elles ont hydraté le MÊME ensemble. La règle d'entrée qui lisait le
/// mot seul acceptait le curseur sur la condition `cold_boundary.is_some()`, c'est-à-dire « il existe
/// UNE fenêtre froide » — et en DÉDUISAIT « c'est la MÊME ». La console recalcule `now - fenêtre` à
/// chaque page : une seconde d'écart retire des lignes du DÉBUT de l'ordre canonique et décale TOUS les
/// rangs. La marque porte donc l'empreinte de l'hydratation qui l'a numérotée
/// (`reader::empreinte_de_numerotation`), et la page suivante COMPARE la sienne.
///
/// CONSÉQUENCE ASSUMÉE, ET ELLE EST ÉCRITE : un curseur marqué du mot NU `cold-union` — ce qu'émettait
/// la version précédente de ce fichier — n'a plus de lecteur et se REFUSE. Au premier déploiement, un
/// client en cours de pagination sur une fenêtre froide repart de la première page. Une fois. C'est ce
/// que ce dépôt choisit partout ailleurs plutôt qu'une page silencieusement décalée.
#[cfg(feature = "cold_tier")]
pub(crate) const ESPACE_ID_COLD_UNION_PREFIXE: &str = "cold-union/";

/// L'ESPACE D'IDENTIFIANT **LU** SUR UN CURSEUR — jamais déduit d'une prémisse.
///
/// CE QUE CHAQUE VARIANTE PORTE, ET POURQUOI PAS LA MÊME CHOSE. La numérotation colonnaire est
/// `seq * COLD_FILE_MAX_ROWS + position-dans-fichier` : une propriété du FICHIER, invariante par
/// translation de la fenêtre (`vectorized::cold_synth_id` calcule `position` sur l'indice BRUT du batch,
/// avant tout filtre) -> sa marque n'a rien d'autre à porter que son nom. La numérotation de l'oracle
/// est un RANG dans l'ensemble hydraté -> sa marque porte l'EMPREINTE de cet ensemble, sans quoi elle ne
/// dit rien de ce qu'elle numérote.
#[cfg(feature = "cold_tier")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EspaceCurseur {
    /// Le browse colonnaire (`cold_keyset_vectorized_page`) : `seq * COLD_FILE_MAX_ROWS + position`.
    Colonnaire,
    /// L'oracle d'union (`cold_union_query`) : le rowid AUTO de `cold_event`, RANG dans l'ensemble
    /// hydraté dont voici l'empreinte.
    Oracle { empreinte: u64 },
    /// Une marque dont AUCUNE voie de ce binaire n'est le lecteur — y compris l'`cold-union` NU des
    /// versions antérieures à la comparaison d'empreinte. Personne ne sait ce que ce nombre veut dire,
    /// donc personne n'a le droit de le rejouer.
    SansLecteur,
}

/// LA LECTURE DE L'ESPACE, ÉCRITE UNE SEULE FOIS — c'est elle que la règle d'entrée du handler
/// consulte, et c'est elle que consulte la voie colonnaire.
///
/// Un curseur SANS espace n'arrive pas ici : ce cas se juge sur la POSITION (au-dessus de la frontière
/// = `event.id` réel, que toutes les voies lisent pareil ; au-dessous = un `id` FABRIQUÉ par une voie
/// qui ne l'a pas dit, donc refusé — cf. `refuse_curseur_froid_sans_espace`).
///
/// LA FORME DE L'EMPREINTE EST STRICTE (16 chiffres hexadécimaux minuscules, tels que
/// `espace_oracle` les écrit) : `u64::from_str_radix` accepterait un `+` en tête et des longueurs
/// variables, et une marque presque-bien-formée n'est pas une marque.
#[cfg(feature = "cold_tier")]
pub(crate) fn lire_espace_du_curseur(espace: &str) -> EspaceCurseur {
    if espace == ESPACE_ID_COLD_VECTORISE {
        return EspaceCurseur::Colonnaire;
    }
    match espace.strip_prefix(ESPACE_ID_COLD_UNION_PREFIXE) {
        Some(h) if h.len() == 16 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {
            match u64::from_str_radix(h, 16) {
                Ok(empreinte) => EspaceCurseur::Oracle { empreinte },
                Err(_) => EspaceCurseur::SansLecteur,
            }
        }
        _ => EspaceCurseur::SansLecteur,
    }
}

/// LA MARQUE QUE L'ORACLE POSE SUR LE CURSEUR QU'IL ÉMET — l'unique écriture de cette forme, dont
/// `lire_espace_du_curseur` est l'unique lecture. Deux écritures de la même forme divergent.
#[cfg(feature = "cold_tier")]
pub(crate) fn espace_oracle(empreinte: u64) -> String {
    format!("{ESPACE_ID_COLD_UNION_PREFIXE}{empreinte:016x}")
}

/// CE QU'IL FAUT FAIRE D'UN CURSEUR REÇU, DÉCIDÉ **AVANT** TOUT DISPATCH.
#[cfg(feature = "cold_tier")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum VerdictCurseur {
    /// Rien à trancher : pas de curseur, curseur CHAUD non marqué (`event.id` réel, lu pareil partout),
    /// ou marque dont le lecteur sert bien cette page.
    Servir,
    /// Le curseur PORTE une marque, et la voie qui numérote dans cet espace n'est pas celle qui sert
    /// cette page (ou n'existe pas dans ce binaire).
    RefusMarqueSansLecteur,
    /// Le curseur pointe SOUS la frontière et ne porte AUCUNE marque : son `id` a été fabriqué par une
    /// voie qui ne l'a pas dit.
    RefusFroidSansEspace,
}

/// `P10.5-g` — LA RÈGLE D'ENTRÉE SUR LE CURSEUR, ÉCRITE UNE SEULE FOIS ET ÉPROUVABLE SANS ROUTEUR.
///
/// POURQUOI C'EST UNE FONCTION. Même raison que `voie_colonnaire_pour_cette_page`, et la même mesure
/// derrière : une règle écrite EN LIGNE dans un handler n'est éprouvable qu'à travers tout ce que le
/// handler exige avant elle (un routeur, une base, une frontière froide, un environnement de processus),
/// si bien qu'aucun de ses cas ne se joue vraiment — c'est ainsi que la jambe « oracle » de la règle
/// précédente n'a JAMAIS été jouée avec une frontière posée. Ici chaque cause rend un verdict nommé, et
/// chacune s'éprouve seule.
///
/// LES DEUX FAITS QU'ELLE LIT, ET AUCUN AUTRE :
///   • la MARQUE, telle qu'elle est écrite sur le curseur (`lire_espace_du_curseur`) — jamais déduite ;
///   • la POSITION du curseur par rapport à la frontière froide — un fait, pas une voie supposée.
/// L'égalité des NUMÉROTATIONS de l'oracle ne se juge pas ici : elle demande l'empreinte de
/// l'hydratation qui sert cette page, laquelle n'existe qu'APRÈS l'hydratation
/// (cf. `refuse_curseur_dune_autre_numerotation`). Ce qui se juge ici, c'est l'ACCESSIBILITÉ du lecteur.
#[cfg(feature = "cold_tier")]
pub(crate) fn verdict_du_curseur(
    cursor: Option<(i64, i64)>,
    cursor_espace: Option<&str>,
    voie_colonnaire_prise: bool,
    cold_boundary: Option<i64>,
) -> VerdictCurseur {
    let Some((cts, _)) = cursor else { return VerdictCurseur::Servir };
    match cursor_espace {
        Some(espace) => {
            let relisible = match lire_espace_du_curseur(espace) {
                // Le browse colonnaire : il faut qu'il serve CETTE page-ci. Sa numérotation est une
                // propriété du FICHIER — invariante par translation de fenêtre — donc la marque suffit.
                EspaceCurseur::Colonnaire => voie_colonnaire_prise,
                // L'oracle d'union : il faut que son chemin soit atteint (frontière froide posée).
                EspaceCurseur::Oracle { .. } => cold_boundary.is_some(),
                EspaceCurseur::SansLecteur => false,
            };
            if relisible {
                VerdictCurseur::Servir
            } else {
                VerdictCurseur::RefusMarqueSansLecteur
            }
        }
        // CURSEUR FROID SANS MARQUE. Sous la frontière, AUCUNE ligne ne porte d'identifiant stocké : les
        // deux voies froides en fabriquent un, et pas le même. Les deux MARQUENT désormais ce qu'elles
        // émettent -> un curseur nu vient d'un client qui l'a reconstruit, d'une version antérieure, ou
        // d'une page servie CHAUDE avant que la frontière n'avance. Aucun des trois ne se rejoue.
        None => {
            if cold_boundary.is_some_and(|b| cts < b) {
                VerdictCurseur::RefusFroidSansEspace
            } else {
                VerdictCurseur::Servir
            }
        }
    }
}

/// `P10.5-g` — LA PORTE DE LA VOIE COLONNAIRE : ÉCRITE UNE SEULE FOIS, ET LISIBLE PAR UN TÉMOIN.
///
/// POURQUOI ELLE EST UNE FONCTION. La règle d'entrée de la marque (`refuse_curseur_sans_lecteur`) et le
/// dispatch doivent lire LA MÊME décision : deux écritures de la même condition finissent par diverger,
/// et c'est précisément la forme du défaut fermé ici — la règle vivait DANS
/// `cold_keyset_vectorized_page`, la décision de l'appeler vivait au-dessus d'elle, et rien ne les
/// reliait. Ici il n'y a plus qu'une valeur, produite une fois, lue deux fois. En prime, chacune des
/// causes de FERMETURE devient éprouvable une par une, sans routeur ni environnement de processus.
///
/// CE QUI LA FERME, ET RIEN D'AUTRE :
///   • `cold_boundary` absente — la fenêtre n'atteint pas le froid, ou le tier froid est éteint ;
///   • (a) `PLUME_COLD_VECTORIZED=0` dans le fichier de l'exploitant — `load_config()` le RELIT à chaque
///     requête, donc l'effet est immédiat, sans redémarrage ;
///   • (b) `cold_vec_soql` absent — une règle de masque de champ est effective pour l'appelant, donc la
///     capture du GXQL pour le routeur n'a pas eu lieu ;
///   • (c) `offset > 0` — le saut-à-la-page reste sur le fallback capé.
#[cfg(feature = "cold_tier")]
pub(crate) fn voie_colonnaire_pour_cette_page(
    cold_boundary: Option<i64>,
    conf: Option<&std::collections::HashMap<String, String>>,
    offset: i64,
    cold_vec_soql: Option<&str>,
) -> Option<String> {
    let (Some(_), Some(c), Some(gxql)) = (cold_boundary, conf, cold_vec_soql) else {
        return None;
    };
    (offset == 0 && crate::cold_store::cold_vectorized_armed(c)).then(|| gxql.to_string())
}

/// `P10.5-g` — REFUS NOMMÉ D'UN CURSEUR QUE LA VOIE QUI VA SERVIR NE SAIT PAS RELIRE.
///
/// LE TROISIÈME SENS DE FUITE, MESURÉ LE 2026-08-28. Deux sens étaient fermés (curseur froid SANS
/// marque, dans les deux directions) ; celui-ci restait ouvert : un curseur froid QUI PORTE la marque
/// partait quand même à l'oracle dès que la porte de la voie vectorisée se fermait ENTRE deux pages —
/// `query.rs` retombait alors sur `page_sql(&sql, keyset_plan(cursor, offset), …)` puis
/// `cold_union_query`, qui rejoue le nombre comme un rowid de `cold_event`. LA VALEUR QUI TRANCHE : un
/// `id` colonnaire vaut `seq * COLD_FILE_MAX_ROWS + position`, donc >= 262 144 dès `seq >= 1`, tandis
/// que les rowids hydratés vont de 1 à `rows_hydrated` (<= 5 000 par défaut) -> `ts = cts AND id < cid`
/// admet TOUT le groupe d'égalité : la page REDÉMARRE en haut du groupe, doublons en silence, 200 OK.
///
/// TROIS CHOSES ORDINAIRES FERMENT CETTE PORTE, et aucune ne demande un redémarrage :
///   (a) l'exploitant écrit `PLUME_COLD_VECTORIZED=0` dans son fichier de configuration —
///       `load_config()` le RELIT à chaque requête, donc l'effet est immédiat ;
///   (b) une règle de masque de champ devient effective pour le rôle de l'appelant -> la capture
///       `cold_vec_soql` est `None` -> la voie n'est plus prise ;
///   (c) un client d'API renvoie le curseur AVEC `offset > 0` (`keyset_plan` fait PRIMER le curseur).
///
/// CE QUE CE REFUS ACHÈTE. Un échec de page que le client retente vaut infiniment mieux qu'une page qui
/// commence ailleurs — et il NOMME sa cause, au lieu d'être remis à un lecteur qui l'interprétera dans
/// un autre espace. 422 et non 400 : la requête est syntaxiquement valide et comprise ; ce qui est
/// refusé, c'est de la TRAITER avec un curseur qu'aucune voie de cette page ne sait relire.
#[cfg(feature = "cold_tier")]
fn refuse_curseur_sans_lecteur(espace: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": format!(
                "curseur refusé (cohérence espace-id) : ce curseur a été numéroté dans l'espace d'identifiant \
                 « {espace} », et aucune des voies qui servent CETTE page ne sait le relire — le rejouer rendrait \
                 une page qui COMMENCE AILLEURS (trou ou doublon, en silence). Reprenez le parcours SANS curseur. \
                 Causes ordinaires : le réglage `PLUME_COLD_VECTORIZED` ou une règle de masque de champ a changé \
                 entre deux pages, ou le curseur a été renvoyé avec un `offset` non nul."
            ),
            "reason": "cold_cursor_espace_sans_lecteur",
            "cursor_espace": espace,
            "restart_without_cursor": true,
        })),
    )
        .into_response()
}

/// `P10.5-g` — REFUS NOMMÉ D'UN CURSEUR FROID QUI NE DIT PAS DANS QUEL ESPACE IL A ÉTÉ NUMÉROTÉ.
///
/// LA FAMILLE, FERMÉE PLUTÔT QUE LE CAS (mesuré le 2026-08-28). Six reprises ont fermé, un par un, les
/// sens par lesquels un curseur pouvait être lu dans le mauvais espace. Les deux derniers avaient la
/// MÊME forme : le code INFÉRAIT l'espace d'un curseur NON MARQUÉ à partir d'une prémisse — « la page
/// précédente a forcément été servie par tel lecteur, donc ce curseur est de tel espace ». La prémisse
/// était vraie quand elle a été écrite et cesse de l'être dès que l'armement, la donnée ou un réglage
/// change entre deux pages. LA RÈGLE EST DONC DEVENUE : ON N'INFÈRE JAMAIS L'ESPACE D'UN CURSEUR.
///
/// CE QUI REND CE REFUS TENABLE : les DEUX voies froides marquent désormais ce qu'elles émettent (la
/// colonnaire par `ESPACE_ID_COLD_VECTORISE`, l'oracle par `espace_oracle`). Un curseur SOUS la
/// frontière et SANS marque ne peut donc venir que (i) d'un client qui a reconstruit `{ts,id}` au lieu
/// de renvoyer le `next_cursor` reçu — ce qu'une garde de source interdit dans la console livrée
/// (`aucun_module_web_ne_reconstruit_le_curseur_keyset`) — ou (ii) d'une version antérieure à ce
/// changement. Dans les deux cas son `id` a été FABRIQUÉ par une voie qui ne l'a pas dit, et personne
/// ne sait laquelle.
///
/// LE CAS QUE LA POSITION SEULE NE DISTINGUE PAS, ET C'EST VOULU : la frontière froide AVANCE d'un jour
/// entier au basculement du vieillissement (`reader::cold_query_boundary` la recalcule à chaque
/// requête). Un curseur émis CHAUD — donc portant un `event.id` RÉEL, légitimement non marqué — peut
/// donc se retrouver SOUS la frontière à la page suivante. Le servir serait FAUX : ses lignes sont
/// désormais dans `cold_event`, où les `id` sont des rangs d'hydratation bornés par le plafond, si bien
/// que `ts = cts AND id < cid` admettrait TOUT le groupe d'égalité et redémarrerait la page en haut du
/// groupe. Il se refuse donc lui aussi — c'est le COÛT ASSUMÉ : une fois, au basculement, un client
/// repart de la première page.
///
/// 422 et non 400 : la requête est syntaxiquement valide et comprise ; ce qui est refusé, c'est de la
/// TRAITER avec un curseur dont personne ne sait lire le nombre.
#[cfg(feature = "cold_tier")]
fn refuse_curseur_froid_sans_espace() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error":
                "curseur refusé (cohérence espace-id) : ce curseur pointe SOUS la frontière froide, où aucune \
                 ligne ne porte d'identifiant stocké — chaque voie froide lui en FABRIQUE un, et ce curseur ne \
                 dit pas laquelle. Le rejouer rendrait une page qui COMMENCE AILLEURS (trou ou doublon, en \
                 silence). Reprenez le parcours SANS curseur. Causes ordinaires : le curseur a été reconstruit \
                 à la main au lieu d'être renvoyé tel quel (le champ `espace` est perdu), il vient d'une \
                 version antérieure du démon, ou la frontière froide a avancé d'un jour entre deux pages.",
            "reason": "cold_cursor_sans_espace",
            "restart_without_cursor": true,
        })),
    )
        .into_response()
}

/// `P10.5-g` — REFUS NOMMÉ D'UN CURSEUR D'ORACLE QUI VIENT D'UNE **AUTRE NUMÉROTATION**.
///
/// LA MESURE QUI L'OBLIGE (2026-08-28). L'`id` que l'oracle rend est le RANG d'insertion dans
/// `cold_event`, donc une propriété de l'ENSEMBLE hydraté, pas de la ligne. Trois gestes ordinaires le
/// décalent entre deux pages sans qu'aucun réglage ne change : la borne basse de la fenêtre avance
/// (`web/viz.js` recalculait `now - fenêtre` à CHAQUE page), le hard-purge retire le plus vieux fichier,
/// le vieillissement en ajoute un. Un décalage de k rangs fait admettre par `ts = cts AND id < cid` k
/// lignes DÉJÀ servies : doublons, en silence, 200 OK.
///
/// LA COMPARAISON EST FAITE SUR DEUX VALEURS MESURÉES, jamais sur une prémisse : celle que la page
/// émettrice a publiée sur son curseur, et celle que l'hydratation de CETTE page vient de produire.
#[cfg(feature = "cold_tier")]
fn refuse_curseur_dune_autre_numerotation(recu: u64, servie: u64) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": format!(
                "curseur refusé (cohérence espace-id) : ce curseur a été numéroté par une hydratation froide \
                 ({recu:016x}) qui n'est PAS celle qui sert cette page ({servie:016x}) — l'oracle numérote un \
                 RANG dans l'ensemble hydraté, donc un rang d'un autre ensemble désigne une autre ligne. Le \
                 rejouer rendrait une page qui COMMENCE AILLEURS (trou ou doublon, en silence). Reprenez le \
                 parcours SANS curseur, et gardez la MÊME fenêtre d'un bout à l'autre d'un parcours. Causes \
                 ordinaires : la borne basse de la fenêtre a bougé entre deux pages, un jour a été purgé, ou \
                 un jour de plus a été columnarisé."
            ),
            "reason": "cold_cursor_autre_numerotation",
            "cursor_espace": espace_oracle(recu),
            "espace_servi": espace_oracle(servie),
            "restart_without_cursor": true,
        })),
    )
        .into_response()
}

/// `P10.5-c` — L'AVEU DE PROVENANCE DE LA PART FROIDE, ÉCRIT UNE SEULE FOIS.
///
/// IL L'ÉTAIT EN DEUX EXEMPLAIRES IDENTIQUES (chemin keyset et chemin page), et les deux DISAIENT LA
/// MÊME CHOSE FAUSSE : `served_from: "hot+cold"` en dur, quelle que soit la requête. Une requête de la
/// base `metric` — qui compile vers `metric ∪ metric_rollup`, deux tables de `main` — s'y voyait donc
/// attribuer une provenance froide qu'elle n'a pas, et un `truncated` qui n'est pas le sien. Les deux
/// grandeurs viennent désormais de `meta.bras_froid_lu`, DÉRIVÉE du SQL réellement exécuté, et un
/// troisième chemin ajouté demain hérite de l'aveu au lieu d'en fabriquer une troisième copie.
///
/// `rows_hydrated`/`files_read` restent ce qu'ils sont — ce que l'HYDRATATION a fait — et c'est
/// délibéré : ils mesurent un COÛT payé, que la réponse l'ait lu ou non.
#[cfg(feature = "cold_tier")]
fn stats_cold(boundary: i64, meta: &crate::cold_store::ColdUnionMeta) -> Value {
    json!({
        "served_from": meta.provenance(),
        "boundary_ts": boundary,
        "rows_hydrated": meta.rows_hydrated,
        "files_read": meta.files_read,
        "files_pruned": meta.files_pruned,
        "truncated": meta.troncature_de_la_reponse(),
    })
}

// =====================================================================================
// PAGINATION DU FLUX D'ÉVÉNEMENTS — un SEUL décideur (`keyset_applicable`) et un SEUL fabricant
// (`page_sql`). Avant, trois sites formataient leur propre `LIMIT/OFFSET` et l'applicabilité du
// keyset était une LISTE de deux commandes (`table`, `fields`) : la liste était à la fois trop
// stricte (elle refusait des pipelines que le curseur peut servir) et trop laxiste (elle acceptait
// `| sort <autre clé>`, dont le wrap keyset ÉCRASE silencieusement l'ordre demandé — mesuré :
// `search severity>=1 | sort severity` avec `keyset:true` rendait severity [2,2,2,2,3,2] au lieu de
// [1,1,1,1,1,1]). Les deux fonctions ci-dessous remplacent la liste par les PROPRIÉTÉS requises.
// =====================================================================================

/// Commandes de pipeline qui rendent UNE ligne de sortie PAR ÉVÉNEMENT d'entrée et n'imposent aucun
/// ordre : la clé `(ts,id)` reste unique et l'ordre reste celui du wrap. `table`/`fields` en font
/// partie UNIQUEMENT parce que le daemon RESTITUE `ts`/`id` dans leur liste (cf.
/// `keyset_projection_augment`) ; sans cette restitution, le wrap référencerait une colonne absente.
const KEYSET_ROW_PRESERVING: &[&str] =
    &["where", "head", "limit", "eval", "rex", "rename", "dedup", "eventstats", "rate", "table", "fields"];

/// Commandes qui CRÉENT des colonnes : si l'une nomme `ts` ou `id`, elle peut les redéfinir/les
/// dupliquer et le wrap ne peut plus garantir sa clé de tri -> non applicable (repli OFFSET).
const KEYSET_COL_CREATING: &[&str] = &["eval", "rex", "rename", "eventstats", "rate"];

/// `P10.5-f` — L'ORDRE QUE LE WRAP IMPOSE, ÉCRIT UNE SEULE FOIS, EN CLÉS GXQL.
///
/// Il l'était en DEUX endroits qui ne se parlaient pas : `page_sql` écrivait `ORDER BY ts DESC, id
/// DESC` en toutes lettres, et `keyset_applicable` décidait, à la main, quels `| sort` cet ordre peut
/// TENIR. Les deux ont divergé, et la divergence était laxiste VERS LE HAUT : le prédicat certifiait
/// `sort` dès que toutes les clés valaient `-ts` OU `-id`, donc `| sort -id` seul était déclaré
/// applicable alors que la page servie est ordonnée `(ts DESC, id DESC)` — un ordre qui n'est PAS
/// `id DESC`. Le commentaire du prédicat, lui, promettait déjà la bonne règle (« `-ts`, éventuellement
/// `-ts,-id` ») : c'est le CODE qui mentait, pas la prose.
///
/// Désormais `page_sql` DÉRIVE sa clause de cette liste (`keyset_order_by`) et `keyset_applicable`
/// en dérive les tris certifiables. Toucher la liste change les DEUX, et le témoin qui ancre la
/// clause en toutes lettres (`keyset.rs`) rougit.
pub(crate) const KEYSET_ORDRE: &[&str] = &["-ts", "-id"];

/// La clause `ORDER BY` du wrap, DÉRIVÉE de `KEYSET_ORDRE` : `-<col>` -> `<col> DESC`, sinon
/// `<col> ASC`. Rend exactement `ts DESC, id DESC` pour la liste livrée (ancré par témoin).
fn keyset_order_by() -> String {
    KEYSET_ORDRE
        .iter()
        .map(|k| match k.strip_prefix('-') {
            Some(col) => format!("{col} DESC"),
            None => format!("{k} ASC"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `P10.5-f` — LES TRIS QUE LE WRAP PEUT TENIR : exactement les PRÉFIXES NON VIDES de `KEYSET_ORDRE`.
///
/// La propriété est celle-ci, et elle se dit en une phrase : l'ordre du wrap RAFFINE l'ordre demandé
/// (il ajoute des départages, il n'en contredit aucun) si et seulement si les clés demandées sont un
/// préfixe des siennes. `-ts` est tenu (le wrap départage ensuite par `id`, ce que `sort -ts` ne
/// contredit pas) ; `-ts,-id` est le wrap lui-même ; `-id` ne l'est PAS (le wrap trie d'abord par
/// `ts`) ; `-id,-ts` non plus (il inverse la priorité) ; `-ts,-ts` non plus (la 2ᵉ clé n'est pas
/// celle du wrap). Aucune de ces quatre formes n'est ÉNUMÉRÉE : elles tombent du préfixe.
fn keyset_sort_tenable(keys: &[String]) -> bool {
    !keys.is_empty() && keys.len() <= KEYSET_ORDRE.len() && keys.iter().zip(KEYSET_ORDRE).all(|(k, w)| k == w)
}

/// KEYSET (#28) — APPLICABILITÉ, **DÉRIVÉE** des trois propriétés dont le wrap `page_sql` a besoin :
///   (P1) une ligne de sortie par ÉVÉNEMENT, donc `(ts,id)` UNIQUE — sinon le curseur strict `<`
///        sauterait les doublons de la ligne frontière (perte SILENCIEUSE) ;
///   (P2) l'ordre DEMANDÉ est bien `(ts DESC, id DESC)` — sinon le wrap écrase l'ordre du client ;
///   (P3) `ts` et `id` sont présents dans la projection finale — restitué par l'augmentation.
/// Le défaut est le REFUS : toute commande hors de `KEYSET_ROW_PRESERVING` (connue —
/// `stats`/`timechart`/`top`/`rare` agrègent, `mvexpand` duplique, `append`/`join`/`lookup`
/// introduisent des lignes étrangères — ou INCONNUE, p. ex. une commande GXQL ajoutée demain) rend
/// la requête non applicable, donc servie par la pagination OFFSET : correcte, bornée, et identique
/// au comportement pré-keyset. Un futur étage est ainsi couvert SANS être énuméré ici.
/// `sort` est admis pour les seuls PRÉFIXES de l'ordre du wrap (`keyset_sort_tenable`, dérivé de
/// `KEYSET_ORDRE`) : ce sont exactement les ordres que `page_sql` RAFFINE, donc qu'il ne peut pas
/// contredire. `| sort -id` n'en est PAS un et retombe sur l'OFFSET (`P10.5-f`).
/// Un `|` dans une valeur citée peut produire un FAUX NÉGATIF -> sûr (OFFSET).
pub(crate) fn keyset_applicable(soql: &str) -> bool {
    soql.split('|').skip(1).all(|stage| {
        let stage = stage.trim();
        let cmd = stage.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if cmd.is_empty() {
            return true; // pipe terminal / vide : aucun étage
        }
        if cmd == "sort" {
            // (P2) — les seuls tris que le wrap TIENT sont les préfixes de son propre ordre.
            let keys: Vec<String> = stage[4..]
                .split(',')
                .map(|k| k.trim().to_ascii_lowercase())
                .filter(|k| !k.is_empty())
                .collect();
            return keyset_sort_tenable(&keys);
        }
        if !KEYSET_ROW_PRESERVING.contains(&cmd.as_str()) {
            return false; // (P1) — et refus par DÉFAUT de l'inconnu
        }
        if KEYSET_COL_CREATING.contains(&cmd.as_str()) {
            // (P3) — un étage qui écrit des colonnes et NOMME la clé de tri n'est pas digne de confiance.
            let rest = stage[cmd.len()..].to_ascii_lowercase();
            let names_key = rest
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|w| w == "ts" || w == "id");
            return !names_key;
        }
        true
    })
}

/// KEYSET (#28) — AUGMENTATION DE PROJECTION. C'est ce qui rend (P3) vrai pour `| table`/`| fields`
/// au lieu de les REFUSER : chaque étage de projection explicite se voit ajouter les clés `ts`/`id`
/// qui lui manquent, de sorte que le wrap keyset trouve toujours sa clé de tri. Rend
/// `(soql augmenté, nombre de colonnes ajoutées au DERNIER étage de projection)` — ce nombre sert à
/// RETIRER ces colonnes de la réponse (`keyset_trim_helper_cols`), pour que le client reçoive
/// EXACTEMENT la projection qu'il a demandée, ni plus ni moins.
/// N'ajoute `id` que sous compilation keyset (`cursor_id=true`), où `id` est une colonne RÉELLE de la
/// base ; sans cursor_id le compilateur le résoudrait en `json_extract(fields,'$.id')` (mesuré) et le
/// curseur serait NULL — c'est pourquoi cette fonction n'est appelée que sur le chemin keyset.
/// `table *` / `table` nu sont des passe-plat (aucune liste) -> rien à augmenter.
pub(crate) fn keyset_projection_augment(soql: &str) -> (String, usize) {
    let mut out: Vec<String> = Vec::new();
    let mut added_last = 0usize;
    for (i, stage) in soql.split('|').enumerate() {
        if i == 0 {
            out.push(stage.to_string());
            continue;
        }
        let trimmed = stage.trim();
        let cmd = trimmed.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if cmd != "table" && cmd != "fields" {
            out.push(stage.to_string());
            continue;
        }
        let list = trimmed[cmd.len()..].trim();
        if list.is_empty() || list == "*" {
            out.push(stage.to_string()); // passe-plat : la clé de tri survit déjà
            continue;
        }
        // `table` sépare par virgules OU blancs, `fields` par virgules seules -> on lit les deux et on
        // ré-émet en VIRGULES, forme acceptée par les deux étages.
        let have: Vec<String> = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(|f| f.trim().to_ascii_lowercase())
            .filter(|f| !f.is_empty())
            .collect();
        let mut add: Vec<&str> = Vec::new();
        for key in ["ts", "id"] {
            if !have.iter().any(|f| f == key) {
                add.push(key);
            }
        }
        added_last = add.len();
        if add.is_empty() {
            out.push(stage.to_string());
        } else {
            // On ré-émet la commande TELLE QU'ÉCRITE (pas sa forme minuscule) : le compilateur GXQL
            // dispatche sur le token EXACT, donc normaliser la casse ici ferait COMPILER un `| TABLE a`
            // qui échoue aujourd'hui — un changement de résultat, gratuit et non demandé.
            let cmd_txt = &trimmed[..cmd.len()];
            out.push(format!(" {cmd_txt} {list},{}", add.join(",")));
        }
    }
    (out.join("|"), added_last)
}

/// KEYSET (#28) — retire les `n` DERNIÈRES colonnes de la réponse : celles que l'augmentation a
/// ajoutées pour que le wrap ait sa clé de tri. À appeler APRÈS `keyset_finalize` (qui a besoin de
/// `ts`/`id` pour fabriquer `next_cursor`). `n == 0` -> no-op strict.
/// `P10.5-g` — LA SORTIE UNIQUE D'UNE PAGE KEYSET.
///
/// LES TROIS RETOURS KEYSET FAISAIENT LA MÊME FIN DE TRAVAIL À LA MAIN, ET L'UN DES TROIS EN OUBLIAIT
/// UNE PART (mesuré le 2026-08-28). Le retour de la voie colonnaire ne retirait PAS les colonnes que
/// `keyset_projection_augment` avait ajoutées, alors que les deux autres le faisaient : `search
/// source=web | table ts,message` en keyset, sur une fenêtre qui franchit la frontière froide, rendait
/// `["ts","message","id"]` tant que la part CHAUDE remplissait la page (`cold_limit == 0` -> le bras
/// froid n'est jamais interrogé, donc aucun repli), puis `["ts","message"]` à la page où le chaud
/// s'épuise. La MÊME requête changeait de nombre de colonnes au milieu d'un parcours — contre le
/// contrat écrit sur `keyset_projection_augment` (« EXACTEMENT la projection qu'il a demandée, ni plus
/// ni moins »). Le défaut était PRÉEXISTANT : les deux sites d'origine portaient déjà le retrait, le
/// troisième chemin est né sans lui.
///
/// LE GESTE N'EST PLUS À REFAIRE : il est FAIT ICI, une fois. Un quatrième chemin keyset ajouté demain
/// hérite du retrait au lieu d'en fabriquer une copie — ou d'en oublier une. L'appelant pose ce qui lui
/// est PROPRE (`stats.cold`, `apply_rollup_stats`) AVANT d'appeler cette sortie ; ce qui est commun à
/// toute page keyset — retrait des colonnes d'aide, découpage des temps, SQL compilé — vit ici.
/// ORDRE : le retrait vient APRÈS `keyset_finalize`, qui a besoin de `ts`/`id` pour former le curseur.
#[allow(clippy::needless_pass_by_value)]
fn keyset_reponse(mut v: Value, trim: usize, timings: &QueryTimings, compiled: &str) -> Response {
    keyset_trim_helper_cols(&mut v, trim);
    timings.stamp(&mut v);
    v["compiled_sql"] = json!(compiled);
    Json(v).into_response()
}

pub(crate) fn keyset_trim_helper_cols(v: &mut Value, n: usize) {
    if n == 0 {
        return;
    }
    let keep = match v.get("columns").and_then(|c| c.as_array()).map(|a| a.len()) {
        Some(len) if len > n => len - n,
        _ => return, // moins de colonnes que d'ajouts : on ne touche à rien plutôt que de mutiler
    };
    if let Some(cols) = v.get_mut("columns").and_then(|c| c.as_array_mut()) {
        cols.truncate(keep);
    }
    if let Some(rows) = v.get_mut("rows").and_then(|r| r.as_array_mut()) {
        for r in rows.iter_mut() {
            if let Some(a) = r.as_array_mut() {
                a.truncate(keep);
            }
        }
    }
}

/// PLAN DE PAGINATION — la forme de page à fabriquer. Le type existe pour qu'il n'y ait qu'UN endroit
/// où la question « comment atteint-on cette page ? » se pose : ajouter une variante oblige à traiter
/// le cas dans `page_sql`, et un appelant ne peut pas composer sa propre clause d'offset.
pub(crate) enum PagePlan {
    /// CURSEUR `(ts,id)` (Suivant/Précédent séquentiel) : O(page) quelle que soit la profondeur.
    Cursor(i64, i64),
    /// SAUT à une page arbitraire DANS l'ordre keyset (clic sur un numéro / « Dernière ») : l'OFFSET
    /// est le seul moyen d'atteindre la page k sans parcourir les k-1 précédentes. C'est un choix
    /// ASSUMÉ, pas un oubli : la page atterrie rend son `next_cursor`, donc le Suivant repart en curseur.
    KeysetJump(i64),
    /// PREMIÈRE page keyset.
    KeysetFirst,
    /// Pagination OFFSET NUE — pipelines dont l'ordre demandé n'est PAS la clé keyset, et `sql` brut
    /// admin. AUCUN `ORDER BY` imposé : l'ordre reste celui du SQL compilé, byte-identique au pré-keyset.
    Offset(i64),
}

/// KEYSET (#28) — LE SEUL fabricant de page du flux d'événements. Wrappe le SQL compilé `sql` (qui
/// projette `id` en fin via cursor_id sur les variantes keyset). Tri STABLE `ts DESC, id DESC` (le plus
/// récent d'abord) sur les trois variantes keyset. Avec curseur `(cts,cid)` = page SUIVANTE strictement
/// APRÈS la dernière ligne rendue : `ts < cts OR (ts = cts AND id < cid)` -> le tiebreak `id` garantit
/// ZÉRO chevauchement / ZÉRO trou aux `ts` égaux (auditd firehose).
/// SÉCURITÉ : `cts`/`cid`/`offset` sont des `i64` (parsés stricts en amont) formatés directement ->
/// injection impossible. PAS de plafond de comptage sur les variantes curseur : le curseur pilote le
/// parcours INTÉGRAL du match-set (fin du cap qui cachait des événements).
pub(crate) fn page_sql(sql: &str, plan: PagePlan, lim: i64) -> String {
    // `P10.5-f` — la clause est DÉRIVÉE de `KEYSET_ORDRE`, la même liste dont `keyset_applicable`
    // dérive les tris qu'il certifie. Byte-identique à la clause écrite en dur qu'elle remplace
    // (`ts DESC, id DESC`), ancré par témoin.
    let ob = keyset_order_by();
    match plan {
        PagePlan::Cursor(cts, cid) => format!(
            "SELECT * FROM ({sql}) WHERE ts < {cts} OR (ts = {cts} AND id < {cid}) ORDER BY {ob} LIMIT {lim}"
        ),
        PagePlan::KeysetJump(offset) => {
            format!("SELECT * FROM ({sql}) ORDER BY {ob} LIMIT {lim} OFFSET {offset}")
        }
        PagePlan::KeysetFirst => format!("SELECT * FROM ({sql}) ORDER BY {ob} LIMIT {lim}"),
        PagePlan::Offset(offset) => format!("SELECT * FROM ({sql}) LIMIT {lim} OFFSET {offset}"),
    }
}

/// Traduit (curseur, offset) en plan keyset — la décision est ici, pas chez l'appelant.
pub(crate) fn keyset_plan(cursor: Option<(i64, i64)>, offset: i64) -> PagePlan {
    match cursor {
        Some((cts, cid)) => PagePlan::Cursor(cts, cid), // le curseur PRIME sur l'offset
        None if offset > 0 => PagePlan::KeysetJump(offset),
        None => PagePlan::KeysetFirst,
    }
}

/// KEYSET (#28) — finalise la réponse d'une page keyset : pose `has_more` + `next_cursor` (le `(ts,id)` de la
/// DERNIÈRE ligne) sur le résultat run_query_ex. `has_more` = la page a rendu EXACTEMENT `lim` lignes (il reste
/// probablement des lignes) OU a été tronquée au plafond run_query_ex (il en reste sûrement) -> dans les deux cas
/// on fournit le curseur de continuation. MOINS de `lim` lignes -> DERNIÈRE page (`next_cursor:null`,
/// `has_more:false`). Volontairement PAS de `total` : le curseur pilote le parcours complet, sans plafond de
/// comptage. DÉFENSIF : si les colonnes `ts`/`id` sont absentes (curseur inextractible — p.ex. une projection
/// `| table` qui a retiré `id`), on n'affirme PAS `has_more` (mieux vaut s'arrêter que boucler à l'infini).
/// `id` est une colonne SIMPLE (jamais masquée) -> `next_cursor` ne fuit aucune donnée sensible.
///
/// `espace_froid` — L'ESPACE D'IDENTIFIANT à poser sur le curseur, et la frontière SOUS laquelle il
/// s'applique. `None` = les `id` de cette page vivent dans l'espace d'`event.id`, que toutes les voies
/// lisent de la même façon (chemin hot, oracle d'union) : il n'y a rien à distinguer. `Some((espace, B))`
/// = les lignes `ts < B` de cette page ont été NUMÉROTÉES par une voie qui leur fabrique un `id` à elle
/// (le froid n'en stocke aucun), et le curseur qui en vient doit le DIRE — sans quoi la page suivante
/// serait servie par une voie qui lit ce même nombre autrement, et commencerait ailleurs en silence.
pub(crate) fn keyset_finalize(v: &mut Value, lim: i64, espace_froid: Option<(&str, i64)>) {
    let cols: Vec<&str> = v
        .get("columns")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("")).collect())
        .unwrap_or_default();
    let ts_i = cols.iter().position(|c| *c == "ts");
    let id_i = cols.iter().position(|c| *c == "id");
    let rows = v.get("rows").and_then(|r| r.as_array());
    let n = rows.map(|r| r.len()).unwrap_or(0) as i64;
    let truncated = v.get("stats").and_then(|s| s.get("truncated")).and_then(|t| t.as_bool()).unwrap_or(false);
    let more = truncated || n == lim;
    let next = if more {
        match (ts_i, id_i, rows.and_then(|r| r.last())) {
            (Some(ti), Some(ii), Some(last)) => {
                match (last.get(ti).and_then(|x| x.as_i64()), last.get(ii).and_then(|x| x.as_i64())) {
                    (Some(t), Some(id)) => json!({ "ts": t, "id": id }),
                    _ => Value::Null,
                }
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    // L'ESPACE D'IDENTIFIANT, POSÉ LÀ OÙ LE CURSEUR EST FABRIQUÉ — pas à côté. Il l'était, et un second
    // `keyset_finalize` (que ce contrat annonce idempotent) l'effaçait : une marque posée APRÈS le
    // fabricant n'est pas une propriété du curseur, c'est une décoration. Ici elle ne peut plus être
    // perdue sans que la fabrication elle-même change.
    // La CONDITION est DÉRIVÉE : seule une dernière ligne SOUS la frontière vient de la voie froide qui
    // numérote à sa façon ; une dernière ligne chaude porte l'`id` réel d'`event`, que toutes les voies
    // lisent pareil — la marquer inventerait une incompatibilité.
    let next = match (espace_froid, next.get("ts").and_then(|t| t.as_i64())) {
        (Some((espace, boundary)), Some(ts)) if ts < boundary => {
            let (t, id) = (next["ts"].clone(), next["id"].clone());
            json!({ "ts": t, "id": id, "espace": espace })
        }
        _ => next,
    };
    // `has_more` HONNÊTE : true seulement si on a AUSSI un curseur de continuation exploitable.
    v["has_more"] = json!(more && !next.is_null());
    v["next_cursor"] = next;
    v["limit"] = json!(lim);
}

/// ①a — UNE page keyset hot∪cold SANS CAP, servie par le moteur colonnaire (matérialisation keyset du brut froid).
/// SÉQUENCE HOT-PUIS-COLD (insight frontière : hot `ts>=boundary` puis cold `ts<boundary` ne s'interleavent PAS en
/// `ts DESC`) :
///   • curseur SOUS le hot (ou 1re page) -> remplit depuis le HOT (keyset SQLite EXISTANT, borné `ts>=boundary` pour
///     PARITÉ avec l'union oracle qui exclut les stragglers hot `ts<boundary`) ; si le hot rend < N (épuisé), COMPLÈTE
///     avec les `N - hot` premières lignes du COLD (`cold_keyset_page`, curseur=None = sommet du froid) ;
///   • curseur DANS le cold (`cts < boundary`) -> page ENTIÈREMENT depuis le COLD (`cold_keyset_page`, curseur porté).
/// `Ok(Some(v))` = page assemblée (COMPLÈTE, `has_more = rendu==N`, aucun `truncated` cap-artefact) ; `Ok(None)` =
/// forme non routable / divergence colonnes hot∪cold / curseur qui appartient à l'oracle -> l'appelant retombe sur
/// `cold_union_query` keyset VERBATIM ; `Err` = corruption froid, échec du bras chaud, OU un repli qui changerait
/// d'espace d'id (cf. `repli`) — fail-closed. Le masquage #45 est déjà garanti par la garde masques-vides de
/// l'appelant.
///
/// L'ESPACE D'IDENTIFIANT DÉCIDE QUI SERT LE CURSEUR, ET C'EST LA PREMIÈRE CHOSE QUE FAIT CETTE FONCTION. Une
/// ligne froide n'a pas d'`id` : chaque voie lui en fabrique un, et pas le même (cf. `ESPACE_ID_COLD_VECTORISE`).
/// Un curseur froid n'est donc servi ICI que s'il porte la MARQUE de cette voie ; portant celle de l'oracle
/// (`ESPACE_ID_COLD_UNION_PREFIXE` + empreinte) il repart à l'oracle, seul à savoir si cette numérotation
/// est encore la sienne ; portant une marque SANS lecteur il est
/// refusé ; n'en portant AUCUNE il est refusé, SANS EXCEPTION — la branche qui consultait la routabilité de la
/// traversée pour DÉDUIRE d'où venait un curseur nu a été supprimée le 2026-08-28, avec la fonction qui la
/// portait.
///
/// CE QUE CETTE RÈGLE NE PEUT PAS TENIR SEULE, ET OÙ ELLE EST TENUE : elle ne s'exécute que si l'appelant
/// DÉCIDE d'appeler cette fonction. La décision vit au-dessus d'elle, et trois réglages ordinaires la
/// renversent entre deux pages — c'est pourquoi la règle d'entrée est AUSSI posée avant la porte, dans le
/// handler (`refuse_curseur_sans_lecteur`), sur la même lecture `lire_espace_du_curseur`.
///
/// `pub(crate)` POUR QUE LE TÉMOIN JUGE CE CODE-CI (`P10.5-g`). Il était privé, et le témoin de traversée
/// (`cold_store/tests.rs`) en portait une RÉPLIQUE, présentée comme « réplique exacte de la logique du
/// handler » — une copie qui juge une copie ne dit rien du produit, et c'est précisément par la branche
/// pur-froide que la réplique et l'original ont divergé. Le témoin appelle désormais cette fonction.
#[cfg(feature = "cold_tier")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn cold_keyset_vectorized_page(
    db_path: &str,
    conf: &std::collections::HashMap<String, String>,
    env: Option<&str>,
    sql: &str,
    soql: &str,
    from: i64,
    to: i64,
    boundary: i64,
    cursor: Option<(i64, i64)>,
    cursor_espace: Option<&str>,
    n: i64,
    budget_ms: u64,
    qid: Option<&str>,
    preds: &[crate::cold_store::DimEq],
) -> Result<Option<Value>, String> {
    // Curseur DANS le cold -> page pur-froide (aucune ligne hot due : hot `ts>=boundary > cts`).
    let pure_cold = matches!(cursor, Some((cts, _)) if cts < boundary);
    // LA MARQUE, **LUE** — jamais devinée. La question que le lot précédent posait au `ts` — « sous la
    // frontière donc synthétique » — le `ts` ne peut pas y répondre : une page pur-froide servie par
    // l'ORACLE rend, elle aussi, un curseur sous la frontière, et son `id` est un rowid de `cold_event`.
    //   `None`             = le curseur ne porte aucune marque (ou il n'y a pas de curseur) ;
    //   `Some(Colonnaire|Oracle)` = une marque dont ce binaire connaît le lecteur ;
    //   `Some(SansLecteur)`       = une marque dont AUCUNE voie n'est le lecteur.
    let marque = cursor.and(cursor_espace).map(crate::lire_espace_du_curseur);
    let curseur_de_cette_voie = marque == Some(crate::EspaceCurseur::Colonnaire);
    match (marque, pure_cold) {
        // Le curseur porte NOTRE marque et il est sous la frontière : c'est le nôtre, on le sert.
        (Some(crate::EspaceCurseur::Colonnaire), true) => {}
        // NOTRE marque mais AU-DESSUS de la frontière : incohérent. La marque dit « id FABRIQUÉ par la
        // voie colonnaire », la position dit « ligne chaude », qui porte l'`id` RÉEL d'`event`. Aucune
        // des deux lectures n'est sûre -> échec de page, jamais une page qui commence ailleurs.
        (Some(crate::EspaceCurseur::Colonnaire), false) => {
            return Err(
                "cold keyset (fail-closed, cohérence espace-id) : curseur marqué par le browse colonnaire \
                 mais situé AU-DESSUS de la frontière froide — reprenez le parcours sans curseur"
                    .to_string(),
            )
        }
        // La marque d'une AUTRE voie connue (l'oracle d'union) : SON lecteur sait la relire — et lui seul
        // sait aussi si sa NUMÉROTATION est encore la sienne (la marque porte son empreinte, comparée dans
        // le handler). On rend la main, sans rien deviner de la routabilité : la marque le dit.
        (Some(crate::EspaceCurseur::Oracle { .. }), _) => return Ok(None),
        // Marque SANS lecteur : personne ici ne sait ce que ce nombre veut dire. Le handler refuse déjà
        // ce cas en amont ; ce bras tient la même règle pour tout appelant interne.
        (Some(crate::EspaceCurseur::SansLecteur), _) => {
            return Err(
                "cold keyset (fail-closed, cohérence espace-id) : espace d'identifiant inconnu sur le \
                 curseur — reprenez le parcours sans curseur"
                    .to_string(),
            )
        }
        // CURSEUR FROID SANS AUCUNE MARQUE -> ÉCHEC DE PAGE, SANS EXCEPTION.
        //
        // CE BRAS DÉDUISAIT, ET C'EST CE QUI EST SUPPRIMÉ (mesuré le 2026-08-28). Il interrogeait la
        // ROUTABILITÉ de la traversée pour en TIRER l'espace du curseur : « non routable ici, donc la page
        // précédente a forcément été servie par l'oracle, donc ce nombre est un rowid d'union ». La prémisse
        // est fausse dès que la frontière froide bouge entre deux pages — cas ORDINAIRE, elle avance d'un
        // JOUR ENTIER au basculement du vieillissement et `load_config()` la recalcule à chaque requête. Une
        // page servie ENTIÈREMENT par le bras CHAUD (`cold_limit == 0`) n'éprouve aucune routabilité et rend
        // un curseur portant un `event.id` RÉEL, non marqué ; à la page suivante ce même curseur passe SOUS
        // la nouvelle frontière, et la déduction le déclarait rowid d'union. Rejoué comme tel, `ts = cts AND
        // id < cid` admettait TOUT le groupe d'égalité (les rangs hydratés sont bornés par le plafond, un
        // `event.id` réel vaut des millions) -> la page REDÉMARRAIT en haut du groupe, en silence, 200 OK.
        //
        // ON N'INFÈRE JAMAIS L'ESPACE D'UN CURSEUR. Les DEUX voies marquent maintenant ce qu'elles émettent,
        // donc un curseur froid NU vient d'un client qui l'a reconstruit ou d'une version antérieure : dans
        // les deux cas son `id` a été fabriqué par une voie qui ne l'a pas dit. Le handler refuse déjà ce
        // cas en amont, en 422 (`refuse_curseur_froid_sans_espace`) ; ce bras tient la même règle pour tout
        // appelant interne, et il ne consulte plus rien pour la tenir.
        (None, true) => {
            return Err(
                "cold keyset (fail-closed, cohérence espace-id) : curseur froid SANS espace d'identifiant — \
                 sous la frontière aucune ligne ne porte d'identifiant stocké, et ce curseur ne dit pas quelle \
                 voie a fabriqué le sien. Reprenez le parcours sans curseur, et renvoyez désormais le \
                 `next_cursor` reçu tel quel (champ `espace` compris) au lieu de reconstruire {ts,id}"
                    .to_string(),
            );
        }
        // Page 1, ou curseur CHAUD : rien à trancher, `event.id` se lit pareil partout.
        (None, false) => {}
    }
    // LE REPLI VERS L'ORACLE N'EST PAS TOUJOURS DISPONIBLE. `Ok(None)` renvoie l'appelant sur
    // `cold_union_query`, qui rejoue le curseur DANS SON PROPRE espace d'id (des ROWID de `cold_event`).
    // Le repli est donc SÛR exactement quand le curseur n'a pas été numéroté ici — et à ce point de la
    // fonction, la question est déjà tranchée : un curseur froid SANS la marque a rendu la main plus
    // haut, un curseur froid AVEC la marque est, par construction, dans l'espace SYNTHÉTIQUE.
    //
    // CE QUE LA CONDITION N'EST PLUS. Elle était `pure_cold` — « ce curseur est sous la frontière, donc
    // il est synthétique ». La prémisse est FAUSSE : l'oracle rend lui aussi des curseurs sous la
    // frontière, et c'est le cas ORDINAIRE de toute forme que le colonnaire ne route pas. Elle est
    // désormais `curseur_de_cette_voie`, qui NE se devine pas : elle se LIT sur le curseur.
    let repli = |motif: &str| -> Result<Option<Value>, String> {
        if curseur_de_cette_voie {
            Err(format!("cold keyset (fail-closed, cohérence espace-id) : {motif}"))
        } else {
            Ok(None)
        }
    };
    // `P10.5-g` — LA FORME DE RÉFÉRENCE EST DÉRIVÉE MÊME QUAND LA PART CHAUDE NE DOIT RENDRE AUCUNE LIGNE.
    //
    // Ce bras était SAUTÉ sur une page pur-froide : `hot_cols` valait `None`, et la comparaison de colonnes
    // plus bas — dont c'est le SEUL rôle — ne s'armait pas. Le filet manquait donc exactement là où la
    // forme peut basculer : la page qui passe du chaud au froid, au milieu d'une traversée, servait les
    // colonnes du FROID sans que rien ne vérifie qu'elles sont celles des pages déjà rendues au client.
    //
    // Le geste manquant EXISTAIT, mal placé : c'est ce bras-ci. Il est désormais joué INCONDITIONNELLEMENT,
    // avec `LIMIT 0` quand la page est pur-froide. SQLite rend les noms de colonnes du SELECT
    // (`stmt.column_names()`) sans qu'une seule ligne soit lue : la référence est donc LITTÉRALEMENT ce que
    // la part chaude aurait rendu — dérivée de la requête, pas reconstruite à côté d'elle — et elle coûte
    // une préparation, pas un parcours.
    //
    // HOT part : le keyset SQLite existant, WRAPPÉ `WHERE ts >= boundary` -> PARITÉ EXACTE avec l'union oracle
    // (`event WHERE ts>=B` ∪ `cold WHERE ts<B`), qui EXCLUT les stragglers hot de `ts<B` (jamais un doublon/extra).
    let hot_n = if pure_cold { 0 } else { n };
    let (hot_cols, mut rows): (Vec<Value>, Vec<Value>) = {
        let hot_sql = format!("SELECT * FROM ({sql}) WHERE ts >= {boundary}");
        let hot_page = page_sql(&hot_sql, keyset_plan(cursor, 0), hot_n);
        match run_query_ex(db_path, &hot_page, budget_ms, qid) {
            Ok(hv) => {
                let cols = hv.get("columns").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                let rws = hv.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                (cols, rws)
            }
            // FAIL-CLOSED, PAS de fallback silencieux. Cette requête EST routable au
            // chemin keyset vectorisé (id synthétique) ; un fallback `cold_union_query` émettrait un curseur en
            // ROWID oracle (autre espace d'id). Une erreur hot TRANSITOIRE (budget/watchdog) est non-déterministe :
            // retomber sur l'oracle ici puis revenir au vectorisé à la page suivante MÉLANGERAIT les deux espaces
            // d'id -> gap/dup. On échoue la page (le client re-tente -> reste sur le vectorisé, séquence cohérente).
            // Le fallback légitime = formes JAMAIS routables (curseur oracle dès la page 1) via les `Ok(None)` plus bas.
            // La sonde `LIMIT 0` du cas pur-froid emprunte le MÊME refus : une référence qu'on n'a pas pu
            // dériver ne se remplace pas par « aucune comparaison ».
            Err(e) => return Err(format!("hot keyset (fail-closed, cohérence espace-id): {e}")),
        }
    };
    let hot_count = rows.len() as i64;
    // COLD complément : pur-froid -> N lignes sous le curseur ; sinon (hot épuisé) -> les N-hot premières du froid.
    let cold_limit = if pure_cold { n } else { (n - hot_count).max(0) };
    let cold_cursor = if pure_cold { cursor } else { None };
    let (cold_cols, cold_rows) = if cold_limit > 0 {
        match crate::cold_store::cold_keyset_page(db_path, conf, env, from, to, boundary, soql, true, cold_cursor, cold_limit as usize, preds)? {
            Some(x) => x,
            // Part froide non routable (garde de gate, masque, forme, multi-env non scopé) -> repli
            // COMPLET, jamais une page partielle — et jamais un repli qui changerait d'espace d'id.
            None => return repli("part froide non routable"),
        }
    } else {
        (Vec::new(), Vec::new())
    };
    // COLONNES — `P10.5-g`. La référence est la forme HOT, DÉRIVÉE de la requête et disponible sur TOUTE
    // page (y compris pur-froide, où elle vient de la sonde `LIMIT 0`). Deux refus, puis le service :
    //   • référence indérivable (aucun nom de colonne rendu) -> on ne PEUT pas comparer -> fallback, jamais
    //     « on sert quand même ». GARDE-FOU NON ÉPROUVÉ PAR TÉMOIN, et c'est dit : un SELECT préparé rend
    //     toujours ses noms de colonnes, donc aucun témoin ne sait atteindre cette branche depuis l'API.
    //     Elle tient le jour où `run_query_ex` changerait de forme de réponse, pas un cas d'aujourd'hui ;
    //   • le froid a annoncé une forme et elle DIVERGE -> fallback. La comparaison porte sur les colonnes
    //     ANNONCÉES, pas sur « le froid a rendu des lignes » : une page froide vide qui annonce une autre
    //     forme est le MÊME défaut de routage, et la page suivante, elle, portera des lignes ;
    //   • sinon la page est servie sous la forme de référence — celle des pages déjà rendues au client.
    if hot_cols.is_empty() {
        return repli("forme de référence indérivable");
    }
    if !cold_cols.is_empty() {
        let cc: Vec<Value> = cold_cols.iter().map(|s| json!(s)).collect();
        if cc != hot_cols {
            return repli("colonnes froid/chaud divergentes");
        }
    }
    let columns: Vec<Value> = hot_cols;
    for r in cold_rows {
        rows.push(Value::Array(r));
    }
    // has_more = rendu == N (pas de `truncated` cap-artefact : le parcours est COMPLET) ; next_cursor = dernière ligne.
    let mut v = json!({ "columns": columns, "rows": rows, "stats": { "truncated": false } });
    keyset_finalize(&mut v, n, Some((ESPACE_ID_COLD_VECTORISE, boundary)));
    // L'AVEU DE PROVENANCE DE CETTE VOIE, DÉRIVÉ DU MÊME FAIT QUE CELUI DE L'ORACLE (`parts_lues`) et posé
    // ICI, où le fait est connu — il était écrit EN DUR au site d'appel, donc « hot+cold » même sur une page
    // que la part CHAUDE a remplie seule (`cold_limit == 0` : le bras froid n'est alors jamais interrogé,
    // cf. plus haut). La ROUTE est le suffixe ; les PARTS viennent du point unique.
    v["stats"]["cold"] = json!({
        "served_from": format!("{}-vectorized-keyset", crate::cold_store::parts_lues(cold_limit > 0)),
        "boundary_ts": boundary,
    });
    Ok(Some(v))
}

// Requête analytique (P3) : SQL ou soql, en LECTURE SEULE (spawn_blocking).
// SQL BRUT = ADMIN : `au` sert à réserver le champ `sql` BRUT (is_soql=false) à l'admin ;
// le chemin GXQL/search reste OUVERT à TOUS les rôles (viewer inclus).
pub(crate) async fn query(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    let _mt = crate::search_timer(); // #51 DAY-2 OPS : latence recherche (p50/p95) enregistrée à la sortie (Drop)
    // MÉTRIQUE HONNÊTE (cf. `query_timing`) — l'horloge démarre à l'ENTRÉE et ne sait rendre QUE le
    // temps total ; le DÉCOUPAGE (préparation / attente du permit / verrou partagé / exécution)
    // n'existe qu'après `clock.permit(...)`, qui encadre l'acquisition elle-même. Avant ce module,
    // ce chrono d'entrée était lu APRÈS le permit et publié sous `sem_wait_ms` : il additionnait
    // l'attente du permit et une attente de VERROU qui a lieu avant toute borne de concurrence
    // (mesuré : jusqu'à 10,2 s, dont 3,8 s avec UN SEUL client). `elapsed_ms` conservé (compat).
    let clock = QueryClock::start();
    let from = body.i64_field("from", 0);
    let to = body.i64_field("to", 0);
    // CHANGEMENT 1 : budget PAR REQUÊTE. interactive:true -> budget INTERACTIF (60 s) ; sinon AUTO (5 s,
    // inchangé : panneaux/tuiles protégés). CHANGEMENT 2 : qid client optionnel -> annulable via /api/cancel.
    let interactive = body.bool_field("interactive", false);
    let budget_ms: u64 = if interactive { query_budget_interactive_ms() } else { query_budget_ms() };
    let qid_owned: Option<String> = body.get("qid").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    // KEYSET (#28) — le client OPTE dans la pagination par CURSEUR avec `keyset:true`. Le browse Explore raw
    // l'utilise pour parcourir l'INTÉGRALITÉ du match-set (millions de lignes auditd-7d) sans le cap 10 000 qui
    // CACHAIT des événements. N'a d'effet que sur le chemin GXQL (la compilation cursor_id est GXQL-only) : un
    // `sql` brut admin retombe sur la pagination offset habituelle. Off (défaut) -> chemins offset/count intacts.
    let keyset = body.bool_field("keyset", false);
    // KEYSET APPLICABILITÉ — DÉRIVÉE des propriétés du wrap (cf. `keyset_applicable`), plus l'AUGMENTATION
    // qui restitue `ts`/`id` aux pipelines projetés (`| table`/`| fields`), lesquels étaient auparavant
    // refusés en bloc et payaient donc un OFFSET croissant à chaque page. Non applicable -> on DÉGRADE vers
    // l'offset AVANT toute compilation, pour que la base compile en mode NON-keyset (soql_to_sql_masked_x ->
    // `| sort` interne préservé, byte-identique au pré-keyset) et que `do_keyset` reste faux. Point UNIQUE :
    // ce shadow gouverne la route rollup, le choix de compilation ET `do_keyset`.
    let keyset = keyset
        && body.get("soql").and_then(|v| v.as_str()).map(keyset_applicable).unwrap_or(true);
    // Colonnes AJOUTÉES par l'augmentation de projection, à retirer de la réponse (0 = rien ajouté).
    let mut keyset_trim = 0usize;
    // REPLI : la forme augmentée ne compile pas (p. ex. un `|` dans une valeur citée a fait mal découper les
    // étages) -> on sert EXACTEMENT comme avant (offset + COUNT borné) au lieu de rendre une erreur.
    let mut keyset_compile_failed = false;
    // rollup_meta = Some((approx, ampleur du plafond, note)) si la requête a été ROUTÉE vers un rollup
    // (sinon raw). Le deuxième membre n'est PAS un booléen : c'est une `CapMesure`, qui n'existe qu'après
    // dérivation depuis la base (cf. `topn_cap`) -> déclarer une troncature sans la chiffrer ne compile pas.
    let mut rollup_meta: Option<(bool, CapMesure, Option<String>)> = None;
    // #18 — le GXQL post-exclusion, capturé INCONDITIONNELLEMENT (masques compris) : c'est de LUI que la
    // FORME de la réponse est dérivée (`AnswerShape::of_gxql`) sur les chemins froids. `None` = champ `sql`
    // brut (admin) -> rien à dériver -> `AnswerShape::undecidable()` = refus. Distinct de `cold_vec_soql`,
    // qui est une capture CONDITIONNELLE (masques vides) au service du ROUTEUR, pas de la correction.
    #[cfg_attr(not(feature = "cold_tier"), allow(unused_mut, unused_variables))]
    let mut req_soql: Option<String> = None;
    // #18 P3 — UNION hot∪cold : `Some(B)` (frontière jour) si le tier cold est ON ET que la fenêtre atteint
    // SOUS `B` (territoire cold). None (feature off / cold off / fenêtre entièrement HOT / SQL brut) -> chemin
    // HOT byte-identique. Posé dans la branche GXQL ci-dessous (sous gate compile+runtime).
    #[allow(unused_mut)]
    let mut cold_boundary: Option<i64> = None;
    // #18 P4a — GXQL post-exclusion capturé pour le ROUTEUR VECTORISÉ (pur-froid + vectorisable). Posé UNIQUEMENT
    // quand masques VIDES et hors keyset (gate #3) ; None sinon -> le routeur n'est jamais tenté (fallback
    // = chemin actuel cold_union_query inchangé). Mode 0 / sans feature : variable absente.
    #[cfg(feature = "cold_tier")]
    #[allow(unused_mut)]
    let mut cold_vec_soql: Option<String> = None;
    // #28 PHASE B — les prédicats d'égalité sur les dims CIM universelles (pour l'ÉLAGAGE cold seal-résident,
    // min/max + bloom) sont extraits du SQL COMPILÉ juste avant l'appel `cold_union_query` (cf. le bloc UNION
    // ci-dessous) — pas ici : lire la SORTIE du compilateur garantit la PARITÉ (la valeur extraite ne peut
    // diverger de ce que la requête filtre) et RÉTABLIT l'élagage sur `host=web1 source in (a,b)`.
    let (sql, from_soql) = if let Some(soql) = body.get("soql").and_then(|v| v.as_str()) {
        // AFFICHAGE SEUL : substitue d'abord les placeholders d'exclusion self/opérateur (mirror
        // compile_panel_sql) -> /api/query débruite comme les panneaux ; no-op si absents. JAMAIS sur la
        // détection (rule_sql ne substitue pas ; cf invariant excl_v55_*).
        let soql = apply_excl_placeholders(soql.trim(), true);
        // #18 — capture pour la DÉRIVATION DE FORME. Inconditionnelle vis-à-vis des MASQUES (la correction
        // ne doit pas dépendre d'eux, contrairement au routage) ; gatée sur la feature parce qu'en mode 0
        // aucun chemin froid ne la lit — l'écrire y serait une affectation morte.
        #[cfg(feature = "cold_tier")]
        {
            req_soql = Some(soql.to_string());
        }
        // FILTRE ENVIRONNEMENT (#2d) : propagé au rollup-route ET au compilo (raw event). None en mode 0.
        let env = au.env_filter();
        // FIELD FILTERS (#45) : masques EFFECTIFS pour le rôle/tenant/env de l'appelant. VIDE (mode 0 / aucune
        // règle) -> compilation byte-identique + rollup-route intact. NON VIDE -> on DÉSACTIVE le rollup-route
        // (les tables event_rollup portent src_ip/host EN CLAIR -> les servir court-circuiterait le masque) et
        // on compile via le chemin masqué (masque émis DANS le SQL, avant agrégation).
        let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
        // #18 P4a — capture le GXQL post-exclusion pour le routeur vectorisé quand masques VIDES et hors keyset
        // (le routeur ne reproduit ni HASH/MASK ni le browse par curseur). Non vide -> le routeur sera tenté sur
        // le chemin cold non paginé ; échec de routage -> fallback cold_union_query (aucune régression).
        #[cfg(feature = "cold_tier")]
        {
            // ①a — capture AUSSI en keyset : le browse cold par curseur (chemin keyset) route vers la
            // matérialisation keyset colonnaire (`cold_keyset_page`). Le chemin vectorisé NON-keyset reste gaté
            // `limit.is_none()` ET n'est atteint QUE hors keyset (les requêtes keyset early-return avant lui) ->
            // élargir la capture à keyset est sûr (aucun chevauchement de route). Masque non vide -> capture None
            // -> le keyset retombe sur `cold_union_query` (fallback capé inchangé).
            if masks.is_empty() {
                cold_vec_soql = Some(soql.to_string());
            }
        }
        // #18 P3 — DÉCLENCHEUR UNION cold : gate COMPILE (`cold_tier`) + RUNTIME (`PLUME_COLD_TIER`). La fenêtre
        // atteint SOUS la frontière jour `B` (dérivée de la MÊME `cold_hot_cutoff` que l'aging) -> on DÉSACTIVE
        // le rollup-route (les rollups sont purgés à retention_days ; complétude rollup-gap P1.5 = brut hot∪cold)
        // et on exécutera le SQL compilé sur l'UNION masquée. `from<B` couvre AUSSI `from==0` (fenêtre non bornée
        // -> inclut le cold). Feature/flag OFF -> `cold_boundary` reste None -> chemin HOT byte-identique.
        #[cfg(feature = "cold_tier")]
        {
            let conf = load_config();
            if crate::cold_store::cold_tier_runtime_on(&conf) {
                let rc = req_db(&st, &au);
                let b = {
                    // VERROU PARTAGÉ CHRONOMÉTRÉ (cf. `query_timing::SharedDbWait`) : ce que ce
                    // `lock()` fait ATTENDRE part dans `stats.db_lock_wait_ms`, jamais fondu dans
                    // une attente de sémaphore.
                    let c = clock.db().lock(&rc);
                    let rd = retention_effective(&c, &conf, "retention_days");
                    crate::cold_store::cold_query_boundary(&c, &conf, now(), rd)
                };
                if from < b {
                    cold_boundary = Some(b);
                }
            }
        }
        // ROLLUP-ROUTE (masque VIDE requis — un masque/deny actif DÉSACTIVE toute route, hot comme cold, et
        // force le chemin masqué/authorizer). #28 Phase A : quand la fenêtre atteint SOUS `B` (cold_boundary
        // Some), on tente le rollup COLD+HOT (union event_rollup ∪ cold_rollup EN BASE, ZÉRO Parquet) ; succès
        // -> on EFFACE cold_boundary pour servir via le pool normal ; échec (motif non `count by` / dim non
        // rollée) -> cold_boundary CONSERVÉ -> chemin brut cold_union_query (correct, plus lent). Fenêtre
        // entièrement HOT (cold_boundary None) -> rollup HOT habituel, inchangé.
        // KEYSET (#28) : le browse par curseur porte sur des LIGNES BRUTES (ts,id) ; un rollup pré-agrégé n'a NI
        // `id` NI ligne individuelle -> on DÉSACTIVE toute route rollup (hot comme cold) quand `keyset` est demandé
        // et on compile la base brute AVEC `id` (via `soql_to_sql_masked_keyset_x`). Sans keyset : logique intacte.
        // COUVERTURE du rollup (cf. rollup_coverage) : ÉTABLIE depuis la base, jamais affirmée ici. Elle borne
        // le corps du MERGE multi-dim au réellement-agrégé ET fait rattraper les retardataires. Non établie ->
        // aucun corps -> chemin brut (exact). Lecture indexée (PK meta) ; sans effet sur ROUTE A/B (single-dim).
        // MÊME discipline pour le rollup PAR DIMENSION (ROUTE B) : la bande dont le job témoigne est LUE
        // depuis la base, jamais affirmée ici ; l'absence de bande vaut déclin (cf. `rollup_coverage`).
        // LA SÉRIALISATION RETIRÉE, ET POURQUOI C'EST SÛR. Cette lecture prenait le mutex de la
        // connexion PARTAGÉE — celui que la boucle de rollups tient pendant tout un tick
        // (`spawn_rollup_loop`, `server/boucles_de_fond.rs`, 120 s) et que l'`ANALYZE` de démarrage tient plusieurs
        // minutes. MESURÉ le 2026-08-01 sur la base de banc, en publiant l'attente à part
        // (`stats.db_lock_wait_ms`) : jusqu'à 3,4 s en SOLO et 4,1 s sous charge, sur le chemin de
        // CHAQUE requête GXQL — dont 3,4 s pour `C6-filter-host`, une requête qui s'exécute en
        // 14 ms. C'était un point de sérialisation situé AVANT la borne de concurrence, que rien
        // ne bornait et que personne ne voyait.
        //
        // ELLE PASSE DONC PAR LE POOL DE LECTURE, et la couverture ne change PAS de nature :
        //   * ce sont les MÊMES lignes `meta` COMMITÉES (WAL : un lecteur voit le dernier état
        //     validé, exactement comme la connexion d'écriture le verrait) ;
        //   * la lecture n'était DÉJÀ dans aucune transaction commune avec l'exécution — la
        //     requête, elle, s'exécute depuis toujours sur une connexion DIFFÉRENTE (le pool). On
        //     ne rapproche donc pas deux instantanés qui étaient liés : on aligne la couverture sur
        //     la famille de connexions qui servira la requête ;
        //   * l'invariant « rétracter d'abord, réparer ensuite » est une propriété de l'ORDRE des
        //     écritures (cf. `rollup_coverage`), pas de la connexion qui lit ;
        //   * FAIL-CLOSED IDENTIQUE : connexion indisponible -> `unproven` -> aucun corps rollup ->
        //     la route décline -> le chemin brut sert, exact. C'est EXACTEMENT ce que rendait déjà
        //     une lecture en échec.
        // Le chronomètre `clock.db()` RESTE armé sur le chemin (frontière froide ci-dessus) : si un
        // verrou partagé y revient un jour, il sera publié, pas absorbé.
        let (rollup_cov, dim_cov) = read_with(
            req_db_path(&st, &au).as_str(),
            (RollupCoverage::unproven(), DimRollupCoverage::unproven()),
            |c| (RollupCoverage::of(c), DimRollupCoverage::of(c)),
        );
        let rr = if masks.is_empty() && !keyset {
            #[cfg(feature = "cold_tier")]
            {
                match cold_boundary {
                    Some(b) => {
                        let c = try_cold_rollup_route(&soql, from, to, env, b, rollup_cov, dim_cov);
                        if c.is_some() {
                            cold_boundary = None;
                        }
                        c
                    }
                    None => try_rollup_route(&soql, from, to, env, rollup_cov, dim_cov),
                }
            }
            #[cfg(not(feature = "cold_tier"))]
            {
                try_rollup_route(&soql, from, to, env, rollup_cov, dim_cov)
            }
        } else {
            None
        };
        if let Some(rr) = rr {
            // L'AMPLEUR DU PLAFOND, MESURÉE — sur le POOL DE LECTURE, pour la même raison que la couverture
            // juste au-dessus (aucune sérialisation derrière le verrou d'un tick de rollups). La sonde lit la
            // MÊME table et le MÊME index que la route, sur les mêmes bandes, et le reste y tient une ligne
            // par heure : MESURÉ 2,4 ms (p50, base de banc, fenêtre de 22 j) contre ~25 ms pour la route.
            // Pool indisponible -> `sans_base()` = AVEU (« plafond posé, ampleur inconnue »), jamais un zéro.
            let cap = read_with(req_db_path(&st, &au).as_str(), rr.cap.sans_base(), |c| rr.cap.mesurer(c));
            rollup_meta = Some((rr.approx, cap, rr.note));
            (rr.sql, true)
        } else {
            // KEYSET : compile AVEC la clé de tri `id` en fin de projection (cursor_id=true) ; sinon compile masqué
            // habituel (cursor_id=false, byte-identique mode 0). Les DEUX passent par le MÊME choke-point store
            // (masques #45 + authorizer read-pool inchangés -> aucune fuite via le chemin keyset).
            // AUGMENTATION : sur le chemin keyset, un pipeline projeté (`| table`/`| fields`) se voit restituer
            // `ts`/`id` dans sa liste, faute de quoi le wrap n'aurait pas de clé de tri. Les colonnes ajoutées
            // sont retirées de la réponse (`keyset_trim`) -> le client reçoit EXACTEMENT sa projection.
            // REPLI : si la forme augmentée ne compile pas, on RETOMBE sur le compilé non-keyset et on
            // désarme le curseur -> la réponse est celle d'avant (offset + COUNT borné), jamais une erreur.
            let compiled = if keyset {
                let (aug, added) = keyset_projection_augment(&soql);
                match soql_to_sql_masked_keyset_x(&aug, from, to, env, &masks) {
                    Ok(s) => {
                        keyset_trim = added;
                        Ok(s)
                    }
                    Err(e) if added > 0 => {
                        keyset_compile_failed = true;
                        keyset_trim = 0;
                        let _ = e;
                        soql_to_sql_masked_x(&soql, from, to, env, &masks)
                    }
                    Err(e) => Err(e),
                }
            } else {
                soql_to_sql_masked_x(&soql, from, to, env, &masks)
            };
            match compiled {
                Ok(s) => (s, true),
                Err(e) => return bad_req(e),
            }
        }
    } else {
        // SQL BRUT = ADMIN — le champ `sql` BRUT (is_soql=false) lit l'INTÉGRALITÉ de la base
        // (tout `SELECT … FROM …`, y compris user.hash / token.token_hash) : RÉSERVÉ ADMIN, exactement comme
        // les règles (validate_detection_content) et les panneaux (panel_create/update). Le chemin GXQL/search
        // (branche `if` supra) reste OUVERT à TOUS les rôles — c'est le langage de lecture prévu du viewer.
        // Fail-closed via raw_sql_allowed : is_soql=false + rôle non-admin -> 403 (message clair, pas d'exécution).
        if !raw_sql_allowed(false, &au.role) {
            return forbidden("SQL brut réservé à l'administrateur (utilisez GXQL)");
        }
        let raw = apply_excl_placeholders(body.str_field("sql").trim(), false);
        (raw.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()), false)
    };
    if sql.is_empty() {
        return bad_req("requête vide");
    }
    // backpressure : l'acquisition ATTEND un permit (borne les déchiffrements concurrents à
    // N -> anti-OOM, les waiters ne déchiffrent pas) ; elle ne rejette jamais sous charge. UN seul acquire
    // par handler (pas de ré-acquisition imbriquée -> pas de deadlock) ; le permit couvre AUSSI le COUNT de
    // pagination ; relâché en fin de handler. Seule erreur possible = sémaphore fermé (shutdown).
    //
    // `P11.14-c` — ET ON LE DIT, comme `/api/search` le dit depuis `P10.7-a` : « le service s'arrête »
    // n'est pas « aucun résultat ». Cette branche rendait `{columns:[],rows:[]}` NU, c'est-à-dire une
    // réponse que tout consommateur lit comme une ABSENCE DE DONNÉES établie — le vide silencieux que
    // `P10.7-a` a fermé sur la barre de recherche et qui restait ouvert sur `/api/query`, la route qui
    // sert l'Explore, les tableaux de bord et les panneaux d'accès données. Le commentaire qui tenait
    // ici invoquait une PARITÉ qui n'existe plus : `/api/search` avoue (`handlers/search.rs`), et
    // `panel_data` ne prend JAMAIS ce permit (il est réservé à `/api/query` + `/api/search`, cf.
    // l'invariant 3c de `dashboards.rs`) — il n'avait donc pas de branche à imiter.
    // La FORME est conservée (`columns`/`rows` vides) pour tout lecteur qui les attend ; `error`
    // s'y ajoute, et c'est lui que les consommateurs testent. Toujours pas de 503 « saturation »
    // trompeur : l'acquisition n'a pas échoué sous la charge, le processus se ferme.
    //
    // `P10.7-c` — LA PHRASE N'EST PLUS ÉCRITE ICI. Elle l'était, et `/api/search` en écrivait une
    // quasi-jumelle chez elle : deux exemplaires d'un même aveu, et onze autres routes qui n'en
    // avaient aucun. L'aveu vient désormais du seul `handlers/portillon`, pour toutes les routes
    // qui franchissent le portillon — une route ajoutée demain ne peut plus en fabriquer un
    // treizième, ni l'oublier (garde dérivée : `daemon/src/tests/portillon_avoue.rs`).
    //
    // MÉTRIQUE : `clock.permit` CONSOMME l'horloge d'entrée et rend le DÉCOUPAGE (`QueryTimings`).
    // C'est la seule porte : l'attente publiée en `sem_wait_ms` ne peut venir que de l'acquisition
    // qui vient d'avoir lieu ici, jamais du temps écoulé depuis l'entrée du handler.
    let (_permit, timings) = match clock.permit(&st.query_sem).await {
        Ok(x) => x,
        Err(_) => {
            return Json(crate::handlers::portillon::corps_de_refus(json!({
                "columns": [],
                "rows": [],
            })))
            .into_response()
        }
    };
    let sql_for_resp = sql.clone();
    let db_path = req_db_path(&st, &au); // #2a-2b : requête interactive routée vers la base du tenant courant
    // PAGINATION SERVEUR : si `limit` fourni ET pas de LIMIT déjà dans le SQL (raw search), on renvoie
    // UNE page (LIMIT/OFFSET) + le total (COUNT) -> le navigateur ne tient jamais qu'une page (scale 1M+).
    let limit = body.get("limit").and_then(|v| v.as_i64()).filter(|&n| n > 0 && n <= 10000);
    let offset = body.i64_field("offset", 0).max(0);
    // KEYSET (#28) — COMPTAGE TOTAL asynchrone SANS PLAFOND : le SPA le demande EN PARALLÈLE de la 1re page keyset
    // pour afficher « N résultats · page X / N » + le pager numéroté. `COUNT(*) FROM (SELECT 1 FROM (sql))` -> compte
    // index-assisté quand le filtre est indexé (idx_event_src_ts), borné par le budget interactif + annulable (qid).
    // Masques/authorizer inchangés (un COUNT compte des LIGNES, ne lit aucun champ masqué). -1 si le watchdog
    // interrompt (le SPA rend « ? »). AUCUN plafond -> aucun événement caché (contraste avec le COUNT capé de l'offset).
    if body.bool_field("count_only", false) {
        let count_sql = format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}))");
        let dbp = db_path.clone();
        let qidc = qid_owned.clone();
        let total = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &count_sql, budget_ms, qidc.as_deref()))
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|v| v.get("rows").and_then(|r| r.get(0)).and_then(|r0| r0.get(0)).and_then(|x| x.as_i64()))
            .unwrap_or(-1);
        return Json(json!({ "count_only": true, "total": total })).into_response();
    }
    // KEYSET (#28) — chemin browse par CURSEUR (parcours intégral, ZÉRO plafond de comptage). N'est actif que
    // sur le chemin GXQL (`from_soql` : la clé de tri `id` n'existe que via la compilation cursor_id). `cursor`
    // OPTIONNEL continue une page précédente : `{ts:<i64>, id:<i64>}`. SÉCURITÉ : `ts`/`id` sont parsés en i64
    // STRICT (`as_i64()` -> None si non entier) puis formatés dans le SQL -> injection IMPOSSIBLE (jamais de
    // texte non fiable interpolé). Curseur mal formé / absent -> première page (pas d'erreur).
    // P7.14-a — LE DRAPEAU EST CONSULTÉ, SINON LE REPLI DOCUMENTÉ N'EXISTE PAS.
    // Le commentaire ~80 lignes plus haut promet : « on RETOMBE sur le compilé non-keyset et on
    // DÉSARME LE CURSEUR -> la réponse est celle d'avant (offset + COUNT borné), JAMAIS une erreur ».
    // Or `do_keyset` ne lisait pas `keyset_compile_failed` : le curseur restait ARMÉ sur un SQL de
    // repli dont la projection n'a ni `id` ni `ts`, et le wrap keyset (`ORDER BY ts DESC, id DESC`)
    // s'appliquait quand même -> erreur SQL sur colonne absente -> HTTP 400. Le filet annoncé
    // n'existait pas, et le drapeau était mort (déclaré, écrit une fois, JAMAIS lu) : c'est ce qui a
    // rendu la promesse invérifiable. Vérifié le 2026-08-05.
    let do_keyset = keyset && from_soql && !keyset_compile_failed;
    let cursor: Option<(i64, i64)> = if do_keyset {
        body.get("cursor").and_then(|c| Some((c.get("ts")?.as_i64()?, c.get("id")?.as_i64()?)))
    } else {
        None
    };
    // L'ESPACE D'IDENTIFIANT DU CURSEUR REÇU (cf. `ESPACE_ID_COLD_VECTORISE`) : le client renvoie le
    // `next_cursor` TEL QUEL, donc ce champ revient avec lui. Absent = « pas émis par le browse
    // colonnaire », ce qui est le défaut SÛR et le cas de tout curseur chaud ou d'oracle.
    #[cfg(feature = "cold_tier")]
    let cursor_espace: Option<String> = body
        .get("cursor")
        .and_then(|c| c.get("espace"))
        .and_then(|e| e.as_str())
        .map(|s| s.to_string());
    // KEYSET — taille de page par défaut si le client n'a pas fourni `limit` (il l'envoie normalement = pageSize).
    let keyset_lim = limit.unwrap_or(100);
    // `P10.5-g` — LA CONFIGURATION DU CHEMIN KEYSET FROID, RELUE **UNE SEULE FOIS**. `load_config()`
    // relit le fichier de l'exploitant à CHAQUE appel : avec deux lectures, la règle d'entrée
    // ci-dessous jugerait une porte qui n'est déjà plus celle qui sert. Un seul instantané, partagé.
    #[cfg(feature = "cold_tier")]
    let conf_keyset: Option<std::collections::HashMap<String, String>> = (do_keyset && cold_boundary.is_some()).then(load_config);
    // LA VOIE COLONNAIRE EST-ELLE PRISE POUR CETTE PAGE ? DÉCIDÉE ICI, UNE FOIS, et lue DEUX fois : par
    // la règle d'entrée de la marque juste en dessous, puis par le dispatch lui-même. La règle ne peut
    // donc pas DÉRIVER de la porte — ce n'est pas une copie de sa condition, c'est la MÊME valeur.
    // `Some(gxql)` = la voie sert cette page ; `None` = elle est fermée (désarmée, masque effectif, ou
    // saut OFFSET).
    #[cfg(feature = "cold_tier")]
    let voie_colonnaire: Option<String> =
        voie_colonnaire_pour_cette_page(cold_boundary, conf_keyset.as_ref(), offset, cold_vec_soql.as_deref());
    // LA RÈGLE D'ENTRÉE DE LA MARQUE — AVANT LA PORTE, ET INDÉPENDAMMENT DE SON ÉTAT D'ARMEMENT
    // (cf. `refuse_curseur_sans_lecteur`, qui porte la mesure et les trois déclencheurs). Un curseur qui
    // PORTE un espace d'identifiant n'est relisible que par la voie qui numérote dans cet espace ; si
    // cette voie n'est pas celle qui va servir la page, on REFUSE en nommant la cause plutôt que de le
    // remettre à un lecteur qui l'interprétera autrement. La condition « la voie sert cette page » est
    // LUE sur les valeurs du dispatch, jamais réécrite.
    // LA RÈGLE D'ENTRÉE, **LUE** — elle est décidée une fois, ailleurs, et chacune de ses causes y est
    // éprouvable seule (`verdict_du_curseur`). La branche qui DÉDUISAIT l'espace d'un curseur nu à partir
    // de la routabilité de la traversée a été SUPPRIMÉE, pas amendée : la prémisse « la page précédente a
    // forcément été servie par tel lecteur » cesse d'être vraie dès que la frontière bouge entre deux
    // pages, et elle le fait d'un JOUR ENTIER au basculement du vieillissement.
    #[cfg(feature = "cold_tier")]
    match verdict_du_curseur(cursor, cursor_espace.as_deref(), voie_colonnaire.is_some(), cold_boundary) {
        VerdictCurseur::Servir => {}
        VerdictCurseur::RefusMarqueSansLecteur => {
            // La marque est NÉCESSAIREMENT présente sous ce verdict — c'est elle qui le produit. Le
            // repli vide n'est donc pas un cas : il est là pour que la forme du code ne demande pas un
            // `unwrap` qui pourrait paniquer, jamais pour rendre un refus sans cause nommée.
            return refuse_curseur_sans_lecteur(cursor_espace.as_deref().unwrap_or(""));
        }
        VerdictCurseur::RefusFroidSansEspace => return refuse_curseur_froid_sans_espace(),
    }
    // KEYSET (#28) — CHEMIN COLD hot∪cold par curseur.
    // ⚠ CE COMMENTAIRE DISAIT « cold_tier OFF en prod : le HOT ci-dessous est prioritaire » — FAUX,
    // corrigé le 2026-08-10. Le tier froid est ACTIF sur une installation réelle (`PLUME_COLD_TIER=1`,
    // des dizaines de fichiers-jour Parquet, des centaines de Mio) : ce chemin est VIVANT et non un repli
    // théorique. Cf. `P10.10-a` —
    // la phrase venait d'une panne de build de trois jours prise pour un état permanent.
    // On applique le MÊME wrap keyset (`page_sql`) sur l'union hydratée + le MÊME masquage/authorizer que
    // le hot (via `cold_union_query`). Pas de COUNT (le curseur pilote le parcours). CAVEAT documenté : si
    // l'hydratation cold PLAFONNE (meta.truncated), on le surface et on garde `has_more` -> jamais présenté complet.
    #[cfg(feature = "cold_tier")]
    if let (true, Some(boundary), Some(conf)) = (do_keyset, cold_boundary, conf_keyset) {
        {
            let env_s = au.env_filter().map(|s| s.to_string());
            let preds = crate::cold_store::extract_cold_dim_preds(&sql);
            // ①a — CHEMIN KEYSET VECTORISÉ (hot-puis-cold SÉQUENTIEL, SANS cap). La PORTE n'est plus écrite
            // ici : elle a été décidée une fois, plus haut, dans `voie_colonnaire` (gate `PLUME_COLD_VECTORIZED`,
            // masques vides via `cold_vec_soql`, `offset == 0` — le saut-à-la-page OFFSET reste sur le fallback
            // capé). C'est la MÊME valeur que la règle d'entrée de la marque a lue, et c'est ce qui rend cette
            // règle-là indéréglable : il n'existe plus deux écritures de la condition qui puissent diverger.
            // Insight frontière : hot `ts>=boundary` puis cold `ts<boundary` NE S'INTERLEAVENT PAS en `ts DESC`
            // -> on remplit la page depuis le HOT (keyset SQLite existant, borné `ts>=boundary`), et si le hot
            // s'épuise avant N on COMPLÈTE avec le COLD keyset colonnaire.
            // `None` (forme non vectorisable / hydrat. impossible) -> FALLBACK `cold_union_query` ci-dessous.
            if let Some(rsoql) = voie_colonnaire {
                {
                    let dbp = db_path.clone();
                    let confc = conf.clone();
                    let envc = env_s.clone();
                    let sqlc = sql.clone();
                    let predsc = preds.clone();
                    let qidc = qid_owned.clone();
                    let cur = cursor;
                    let cur_espace = cursor_espace.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        cold_keyset_vectorized_page(
                            &dbp, &confc, envc.as_deref(), &sqlc, &rsoql, from, to, boundary, cur, cur_espace.as_deref(), keyset_lim, budget_ms,
                            qidc.as_deref(), &predsc,
                        )
                    })
                    .await;
                    match res {
                        Ok(Ok(Some(v))) => {
                            // TRANSPARENCE : `stats.cold` est posé par la fonction elle-même, où le fait
                            // « le bras froid a-t-il été interrogé ? » est connu (cf. `parts_lues`). Le reste
                            // — retrait des colonnes d'aide compris — passe par la SORTIE UNIQUE : c'est
                            // exactement ce retrait que ce chemin-ci oubliait (cf. `keyset_reponse`).
                            return keyset_reponse(v, keyset_trim, &timings, &sql_for_resp);
                        }
                        Ok(Ok(None)) => { /* non routable -> FALLBACK cold_union_query ci-dessous */ }
                        // Err = corruption froid OU erreur hot transitoire : côté SERVEUR, fail-closed
                        // et RETRIABLE (5xx, pas 4xx) -> le client re-tente et reste sur le chemin vectorisé.
                        Ok(Err(e)) => return server_err(e),
                        Err(_) => return server_err("exécution échouée"),
                    }
                }
            }
            let ks_page = page_sql(&sql, keyset_plan(cursor, offset), keyset_lim);
            let dbp = db_path.clone();
            let qid = qid_owned.clone();
            let res = tokio::task::spawn_blocking(move || {
                crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &ks_page, None, budget_ms, qid.as_deref(), &preds)
            })
            .await;
            // #18 — la FORME de la réponse est DÉRIVÉE du GXQL, jamais affirmée ici : `render` refuse
            // toute valeur dérivée d'un ensemble tronqué (un `| eventstats`/`| dedup` keyset-applicable
            // rendrait des colonnes calculées sur l'échantillon). Voie par-événement -> page partielle.
            let shape = match req_soql.as_deref() {
                Some(s) => crate::cold_store::AnswerShape::of_gxql(s),
                None => crate::cold_store::AnswerShape::undecidable(),
            };
            return match res {
                Ok(Ok((answer, meta))) => {
                    // LA NUMÉROTATION SE COMPARE, ELLE NE SE SUPPOSE PAS (`P10.5-g`). Les deux valeurs sont
                    // MESURÉES : celle que la page émettrice a publiée sur le curseur, et celle que
                    // l'hydratation de CETTE page vient de produire. Le refus précède le rendu — une page
                    // formée sur un curseur d'une autre numérotation ne doit jamais atteindre le client.
                    if let Some(EspaceCurseur::Oracle { empreinte }) = cursor_espace.as_deref().map(lire_espace_du_curseur) {
                        if empreinte != meta.empreinte_de_numerotation {
                            return refuse_curseur_dune_autre_numerotation(empreinte, meta.empreinte_de_numerotation);
                        }
                    }
                    let mut v = match answer.render(shape) {
                        Ok(r) => {
                            // truncated cold OR-é AVANT keyset_finalize -> `has_more` en tient compte (jamais un union
                            // tronqué présenté comme dernière page).
                            let mut v = r.value;
                            if r.truncated { v["stats"]["truncated"] = json!(true); }
                            v
                        }
                        Err(t) => return refuse_truncated_aggregate(t),
                    };
                    // L'ORACLE MARQUE CE QU'IL ÉMET, LUI AUSSI — et sa marque porte SA NUMÉROTATION, pas
                    // seulement son nom. Ses `id` sous la frontière sont des rangs dans l'ensemble hydraté :
                    // une numérotation qui dépend de l'HYDRATATION, illisible pour le browse colonnaire ET
                    // pour une AUTRE hydratation de l'oracle. L'empreinte vient de `meta`, donc de ce que
                    // l'hydratation a RÉELLEMENT parcouru — elle n'est pas reconstruite ici.
                    let espace = espace_oracle(meta.empreinte_de_numerotation);
                    keyset_finalize(&mut v, keyset_lim, Some((&espace, boundary)));
                    v["stats"]["cold"] = stats_cold(boundary, &meta);
                    // `P10.5-c` — L'AVEU D'EXACTITUDE, SUR LE CHEMIN QUI ÉMET LE REFUS. Le message de
                    // `TruncatedAggregate` envoie le lecteur à `stats.served_from` ; ce chemin-ci ne le
                    // publiait pas, alors que c'est LUI qui sert quand le lecteur a suivi le conseil (a)
                    // « restreindre la fenêtre ». `rollup_meta` est nécessairement `None` sous ce bras (une
                    // route pré-agrégée ANNULE `cold_boundary`, cf. le site qui l'écrit) -> `served_from`
                    // vaut `raw`, ce qui est exactement l'aveu attendu : brut, donc exact.
                    apply_rollup_stats(&mut v, &rollup_meta);
                    keyset_reponse(v, keyset_trim, &timings, &sql_for_resp)
                }
                Ok(Err(e)) => bad_req(e),
                Err(_) => server_err("exécution échouée"),
            };
        }
    }
    // KEYSET (#28) — CHEMIN HOT (prod). Wrap `SELECT * FROM ({sql}) [WHERE (ts,id) < curseur] ORDER BY ts DESC,
    // id DESC LIMIT lim`. `{sql}` est le SQL DÉJÀ compilé/masqué/autorisé (avec `id` projeté) -> le wrap PRÉSERVE
    // masques (#45), authorizer DENY (user.hash/token_hash au prepare) et scope tenant/env : `SELECT *` d'une
    // sous-requête masquée reste masqué (`id` n'est pas un champ masqué). MÊME budget/qid/permit que le hot offset.
    if do_keyset {
        let ks_page = page_sql(&sql, keyset_plan(cursor, offset), keyset_lim);
        let dbp = db_path.clone();
        let qid = qid_owned.clone();
        let res = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &ks_page, budget_ms, qid.as_deref())).await;
        return match res {
            Ok(inner) => {
                match inner {
                    Ok(mut v) => {
                        keyset_finalize(&mut v, keyset_lim, None);
                        apply_rollup_stats(&mut v, &rollup_meta); // rollup_meta = None ici (keyset désactive la route) -> served_from=raw
                        keyset_reponse(v, keyset_trim, &timings, &sql_for_resp)
                    }
                    Err(e) => bad_req(e),
                }
            }
            Err(_) => server_err("exécution échouée"),
        };
    }
    // #18 P3 — CHEMIN UNION hot∪cold. Early-return DÉDIÉ (le chemin HOT ci-dessous reste byte-identique). On
    // construit la connexion d'union UNE FOIS (une seule hydratation) et on exécute page + COUNT dans UN SEUL
    // spawn_blocking (la Connection ne traverse jamais un .await). Masquage (#45) + authorizer DENY appliqués aux
    // lignes cold via le MÊME SQL compilé + le MÊME authorizer (cf. cold_store::open_cold_union). `truncated`
    // (plafond cold atteint) est SURFACÉ (jamais un cold∪hot incomplet présenté comme complet).
    #[cfg(feature = "cold_tier")]
    if let Some(boundary) = cold_boundary {
        // #18 P4a — ROUTEUR VECTORISÉ (premier câblage runtime). Tenté UNIQUEMENT sur le chemin NON paginé
        // (limit None : dashboards/agrégats), pour une requête pur-froid ET vectorisable (masques vides). Succès
        // -> servi par les kernels (vitesse) ; None -> FALLBACK au chemin actuel cold_union_query CI-DESSOUS
        // (INCHANGÉ). Invariant : résultat routé == résultat cold_union_query (prouvé par le harnais de parité).
        // #28 P3.5 — égalités de dims extraites du SQL COMPILÉ (post-masquage #45), le MÊME que celui exécuté par
        // l'oracle `cold_union_query` ci-dessous -> les DEUX chemins élaguent le MÊME ensemble de fichiers (cohérence
        // du gate cap). Calculé UNE FOIS ici et partagé (vectorisé + union).
        let cold_dim_preds = crate::cold_store::extract_cold_dim_preds(&sql);
        if limit.is_none() {
            if let Some(rsoql) = cold_vec_soql.clone() {
                let conf = load_config();
                let env_s = au.env_filter().map(|s| s.to_string());
                let dbp = db_path.clone();
                let preds = cold_dim_preds.clone();
                let qidv = qid_owned.clone();
                // #18 P4a vs P4b — ROUTAGE selon la FENÊTRE : PUR-FROID (`0 < to < boundary`) -> kernels seuls
                // (`cold_vectorized_try`) ; CHEVAUCHANTE (`from < boundary <= to`, ou `to<=0` non borné haut =
                // atteint le hot) -> MERGE hot∪cold (`cold_vectorized_merge_try` : froid vectorisé + hot SQLite
                // fusionnés). Une SEULE des deux est appelée (compteur de route propre). None (l'une ou l'autre)
                // -> FALLBACK au chemin actuel cold_union_query CI-DESSOUS (INCHANGÉ). Invariant des deux :
                // résultat routé == cold_union_query (harnais de parité p4a_* / p4b_*).
                let pure_cold = to > 0 && to < boundary;
                let res = tokio::task::spawn_blocking(move || {
                    if pure_cold {
                        crate::cold_store::cold_vectorized_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, &preds)
                    } else {
                        crate::cold_store::cold_vectorized_merge_try(&dbp, &conf, env_s.as_deref(), from, to, boundary, &rsoql, true, budget_ms, qidv.as_deref(), &preds)
                    }
                })
                .await;
                match res {
                    Ok(Ok(Some(mut v))) => {
                        let mode = if pure_cold { "cold-vectorized" } else { "cold-vectorized-merge" };
                        timings.stamp(&mut v);
                        v["compiled_sql"] = json!(sql_for_resp);
                        v["stats"]["served_from"] = json!(mode);
                        // TRANSPARENCE : servi par le moteur colonnaire (pur-froid) ou le merge hot∪cold vectorisé.
                        v["stats"]["cold"] = json!({ "served_from": mode, "boundary_ts": boundary });
                        return Json(v).into_response();
                    }
                    Ok(Ok(None)) => { /* non vectorisable / non routable -> fallback cold_union_query ci-dessous */ }
                    Ok(Err(e)) => return bad_req(e), // corruption cold -> fail-closed (comme l'oracle)
                    Err(_) => return server_err("exécution échouée"),
                }
            }
        }
        let conf = load_config();
        let env_s = au.env_filter().map(|s| s.to_string());
        let (cold_page, count_sql) = match limit {
            Some(lim) => (
                page_sql(&sql, PagePlan::Offset(offset), lim),
                // COUNT BORNÉ (perf) : MÊME plafond que le chemin hot (cf. PAGINATION_COUNT_CAP) -> le COUNT sur
                // l'union hydratée hot∪cold s'arrête à CAP+1 lignes au lieu de compter tout le match-set.
                Some(format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}) LIMIT {})", PAGINATION_COUNT_CAP + 1)),
            ),
            None => (sql.clone(), None),
        };
        let dbp = db_path.clone();
        let qid = qid_owned.clone();
        // #28 PHASE B/P3.5 — RÉUTILISE les égalités de dims déjà extraites du SQL COMPILÉ (`sql`, post-masquage
        // #45), le MÊME jeu que le chemin vectorisé ci-dessus -> parité par construction + gate cap cohérent.
        let preds = cold_dim_preds;
        let res = tokio::task::spawn_blocking(move || {
            crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &cold_page, count_sql.as_deref(), budget_ms, qid.as_deref(), &preds)
        })
        .await;
        // #18 — FORME DÉRIVÉE du GXQL. C'est ICI que le défaut mordait : `search source=auditd severity>=2 |
        // stats count` rendait 289 au lieu de 58 747 (×203 mesuré), avec un drapeau à côté. `render` refuse
        // désormais de former ce nombre ; la voie exacte est le routeur vectorisé essayé juste au-dessus.
        let shape = match req_soql.as_deref() {
            Some(s) => crate::cold_store::AnswerShape::of_gxql(s),
            None => crate::cold_store::AnswerShape::undecidable(), // `sql` brut admin : rien de dérivable
        };
        return match res {
            Ok(Ok((answer, meta))) => {
                let crate::cold_store::Rendered { mut value, total, truncated } = match answer.render(shape) {
                    Ok(r) => r,
                    Err(t) => return refuse_truncated_aggregate(t),
                };
                let v = &mut value;
                timings.stamp(v);
                v["compiled_sql"] = json!(sql_for_resp);
                // TRANSPARENCE + INCOMPLÉTUDE : couverture cold + drapeau. Truncated cold -> on OR-e aussi le
                // `stats.truncated` global (même posture que le row-cap hot) : aucun consommateur ne peut prendre
                // un cold∪hot tronqué pour complet.
                v["stats"]["cold"] = stats_cold(boundary, &meta);
                // `P10.5-c` — L'AVEU D'EXACTITUDE, SUR LE CHEMIN QUI ÉMET LE REFUS. Le message de
                // `TruncatedAggregate` (cf. `cold_store::exactness`) renvoie le lecteur à
                // `stats.served_from` pour trancher exact/approximatif — et ce chemin-ci, le SEUL qui
                // émette ce refus (`refuse_truncated_aggregate` juste au-dessus), ne publiait PAS ce
                // champ : le lecteur qui suivait le conseil (a) « restreindre la fenêtre » recevait sa
                // réponse EXACTE par ce même chemin, sans rien pour la distinguer d'un pré-agrégé
                // approximatif. `rollup_meta` est nécessairement `None` sous ce bras — une route
                // pré-agrégée ANNULE `cold_boundary` là où elle est retenue — donc `served_from` vaut
                // `raw` : brut, donc exact, ce qui est exactement l'aveu promis.
                apply_rollup_stats(v, &rollup_meta);
                if truncated {
                    v["stats"]["truncated"] = json!(true);
                }
                if let Some(lim) = limit {
                    // COUNT BORNÉ : raw = min(vrai_total, CAP+1). > CAP -> capé (CAP + total_capped) ; sinon exact.
                    // `total` est None sur un ensemble tronqué (un COUNT de pagination est lui aussi une valeur
                    // dérivée) -> -1, et le pager rend ◀ ▶ sans numéros au lieu d'un total faux.
                    let raw_total = total.unwrap_or(-1);
                    let total_capped = raw_total > PAGINATION_COUNT_CAP;
                    v["total"] = json!(if total_capped { PAGINATION_COUNT_CAP } else { raw_total });
                    if total_capped { v["total_capped"] = json!(true); }
                    v["offset"] = json!(offset);
                    v["limit"] = json!(lim);
                }
                Json(value).into_response()
            }
            Ok(Err(e)) => bad_req(e),
            Err(_) => server_err("exécution échouée"),
        };
    }
    if let Some(lim) = limit {
        // pagination par WRAP en sous-requête : marche AUSSI quand {sql} a déjà un LIMIT (`| head`) ->
        // l'inner cape, l'outer pagine dedans. AVANT : `if !contains(" limit ")` SAUTAIT la pagination
        // pour ces requêtes -> offset ignoré (chaque page = mêmes lignes) + pas de `total` -> pager cassé.
        let off_page = page_sql(&sql, PagePlan::Offset(offset), lim);
        // COUNT BORNÉ (perf) : plafonné à PAGINATION_COUNT_CAP+1 lignes -> exact sous le plafond, capé au-dessus
        // (cf. PAGINATION_COUNT_CAP). Le SELECT 1 s'aplatit -> index-only via idx_event_src_ts, s'arrête au cap.
        let count_sql = format!("SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({sql}) LIMIT {})", PAGINATION_COUNT_CAP + 1);
        let dbp = db_path.clone();
        // FIX perf : COUNT total et page lancés CONCURREMMENT (tokio::join!) -> latence ≈ max(count, page)
        // au lieu de count + page (avant : await séquentiels). Sémantique inchangée ; le permit du
        // sémaphore couvre toujours les deux (relâché en fin de handler).
        // budget par requête (CHANGEMENT 1) + qid pour l'annulation (CHANGEMENT 2) : page ET count sont
        // enregistrés sous le qid -> /api/cancel interrompt les deux (sinon le join! attendrait le count).
        let qid1 = qid_owned.clone();
        let qid2 = qid_owned.clone();
        let count_fut = tokio::task::spawn_blocking(move || run_query_ex(&dbp, &count_sql, budget_ms, qid1.as_deref()));
        let page_fut = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &off_page, budget_ms, qid2.as_deref()));
        let (count_res, page) = tokio::join!(count_fut, page_fut);
        // total best-effort : si le COUNT dépasse le watchdog (requête énorme), -1 -> UI ◀ ▶ sans numéros.
        let raw_total = count_res
            .ok().and_then(|r| r.ok())
            .and_then(|v| v.get("rows").and_then(|r| r.get(0)).and_then(|r0| r0.get(0)).and_then(|x| x.as_i64()))
            .unwrap_or(-1);
        // COUNT BORNÉ : raw_total = min(vrai_total, CAP+1). > CAP -> capé (on renvoie CAP + total_capped) ; sinon
        // EXACT (petits résultats : dernière page + numéros justes). -1 (watchdog) N'est jamais > CAP -> intact.
        let total_capped = raw_total > PAGINATION_COUNT_CAP;
        let total = if total_capped { PAGINATION_COUNT_CAP } else { raw_total };
        return match page {
            Ok(inner) => {
                match inner {
                    Ok(mut v) => {
                        v["total"] = json!(total);
                        if total_capped { v["total_capped"] = json!(true); }  // le SPA rend « … sur 10 000+ »
                        v["offset"] = json!(offset);
                        v["limit"] = json!(lim);
                        timings.stamp(&mut v);
                        if from_soql {
                            v["compiled_sql"] = json!(sql_for_resp);
                            apply_rollup_stats(&mut v, &rollup_meta); // served_from/approx/truncated (transparence)
                        }
                        Json(v).into_response()
                    }
                    Err(e) => bad_req(e),
                }
            }
            Err(_) => server_err("exécution échouée"),
        };
    }
    let qid_c = qid_owned.clone();
    let res = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &sql, budget_ms, qid_c.as_deref())).await;
    match res {
        Ok(inner) => {
            match inner {
                Ok(mut v) => {
                    timings.stamp(&mut v);
                    if from_soql {
                        v["compiled_sql"] = json!(sql_for_resp);
                        apply_rollup_stats(&mut v, &rollup_meta); // served_from/approx/truncated (transparence)
                    }
                    Json(v).into_response()
                }
                Err(e) => bad_req(e),
            }
        }
        Err(_) => server_err("exécution échouée"),
    }
}

/// CHANGEMENT 2 — annulation serveur (bouton STOP). Body `{"qid":"..."}` : pose le drapeau `cancelled`
/// puis appelle `.interrupt()` sur TOUTES les requêtes en vol de ce qid (page + count de pagination) ->
/// la requête en cours s'arrête et renvoie « annulé par l'utilisateur » (pas un 500). Idempotent (qid
/// inconnu/déjà fini -> cancelled:0). Même garde d'auth que /api/query (viewer) via readonly_post.
pub(crate) async fn cancel(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let qid = b.trimmed("qid");
    if qid.is_empty() {
        return bad_req("qid requis");
    }
    // MT-KEY : n'annule QUE les requêtes en vol de CE db_path portant ce qid (jamais celles d'une autre base).
    let key = (req_db_path(&st, &au), qid.clone());
    let mut n = 0u32;
    if let Some(reg) = QUERY_CANCEL.get() {
        { let map = reg.lock();
            if let Some(vec) = map.get(&key) {
                for e in vec {
                    e.cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                    e.interrupt.interrupt();
                    n += 1;
                }
            }
        }
    }
    Json(json!({ "cancelled": n, "qid": qid })).into_response()
}

// ================================================================================================
// EXPORT (CSV / JSON) — P0 UI. INVARIANT DE SÉCURITÉ : ne fait RIEN d'autre que /api/query, en changeant
// UNIQUEMENT le format de sortie. Même compilation (GXQL ouvert à tous ; champ `sql` BRUT réservé admin via
// raw_sql_allowed), même exécuteur run_query_ex -> donc MÊME authorizer read-pool qui DENY user.hash /
// token.token_hash / connector.secret au prepare() (non contournable, même en SQL brut admin), MÊME budget/
// watchdog, MÊME plafond de lignes. Un export ne peut donc PAS voir une colonne que /api/query ne verrait
// pas, ni contourner le gate admin, ni produire un dump brut non caviardé. Aucun accès à st.db (sans
// authorizer) : tout passe par req_db_path + run_query_ex (read pool). Mode 0 / data-plane inchangés.
// ================================================================================================

/// Plafond de lignes d'un export (borne la taille du fichier). Réglable via PLUME_EXPORT_MAX, borné dur à
/// 100k (= plafond dur de run_query_ex). run_query_ex applique DE TOUTE FAÇON son propre max_rows
/// (PLUME_QUERY_MAX) -> l'export ne dépasse jamais le plafond de lecture existant (pas d'exfiltration massive).
pub(crate) fn export_max_rows() -> i64 {
    std::env::var("PLUME_EXPORT_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0 && n <= 100_000)
        .unwrap_or(50_000)
}

/// Seuil de lignes au-delà duquel un EXPORT est audité (exfiltration potentielle).
/// Réglable via PLUME_AUDIT_BULK_ROWS (défaut 10 000). L'/api/query interactif est paginé (≤ 10k/page) -> le
/// vecteur d'exfil de masse est l'export ; c'est lui qu'on audite.
pub(crate) fn bulk_read_threshold() -> usize {
    std::env::var("PLUME_AUDIT_BULK_ROWS").ok().and_then(|s| s.parse().ok()).filter(|&n| n > 0).unwrap_or(10_000)
}
/// Émet un event source=plume-audit action=bulk_read SI (et seulement si) `rows >= seuil` -> mode-0-INERTE
/// (une lecture normale ne l'atteint jamais). Best-effort ; ne porte JAMAIS de donnée de résultat (juste le
/// compte + le principal). La règle SEC4 « lecture/export de masse » alerte dessus.
pub(crate) fn audit_bulk_read(st: &AppState, au: &AuthUser, kind: &str, rows: usize) {
    if rows < bulk_read_threshold() { return; }
    let ts = now();
    let msg = format!("{kind} de masse : {rows} lignes par '{}' (rôle {})", au.name, au.role);
    let fields = json!({ "action": "bulk_read", "kind": kind, "principal": au.name, "role": au.role, "rows": rows }).to_string();
    let conn = st.db.lock();
    let _ = conn.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,'plume-audit','audit',3,?2,'plume-daemon',?3,'daemon')",
        params![ts, msg, fields],
    );
}

/// Échappe une cellule CSV (RFC 4180) + neutralisation d'injection de formule (OWASP CSV injection) : une
/// cellule TEXTE débutant par `= + @` ou un caractère de contrôle (\t \r) est préfixée d'une apostrophe ->
/// le tableur ne l'interprète PAS comme une formule. Les nombres/booléens ne sont jamais neutralisés.
pub(crate) fn csv_cell(v: &Value) -> String {
    let raw = match v {
        Value::Null => return String::new(),
        Value::Bool(b) => return b.to_string(),
        Value::Number(n) => return n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let needs_guard = raw
        .as_bytes()
        .first()
        .is_some_and(|&c| matches!(c, b'=' | b'+' | b'@' | b'\t' | b'\r'));
    let guarded = if needs_guard { format!("'{raw}") } else { raw };
    if guarded.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// Sérialise un résultat run_query_ex ({columns, rows}) en CSV (en-tête = colonnes ; CRLF ; RFC 4180).
pub(crate) fn result_to_csv(v: &Value) -> String {
    let empty: Vec<Value> = Vec::new();
    let cols = v.get("columns").and_then(|c| c.as_array()).unwrap_or(&empty);
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);
    let mut out = String::new();
    let header: Vec<String> = cols.iter().map(csv_cell).collect();
    out.push_str(&header.join(","));
    out.push_str("\r\n");
    for row in rows {
        if let Some(arr) = row.as_array() {
            let line: Vec<String> = arr.iter().map(csv_cell).collect();
            out.push_str(&line.join(","));
            out.push_str("\r\n");
        }
    }
    out
}

/// Sérialise un résultat en JSON « records » ([{col: val, ...}, ...]) — le format le plus consommable par
/// un tiers. Colonnes homonymes : la dernière l'emporte (rare en GXQL/table). Valeurs déjà caviardées par
/// run_query_ex (l'authorizer a refusé les colonnes secrètes au prepare()).
pub(crate) fn result_to_json_records(v: &Value) -> Value {
    let cols: Vec<String> = v
        .get("columns")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let empty: Vec<Value> = Vec::new();
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);
    let recs: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            if let Some(arr) = row.as_array() {
                for (i, c) in cols.iter().enumerate() {
                    obj.insert(c.clone(), arr.get(i).cloned().unwrap_or(Value::Null));
                }
            }
            Value::Object(obj)
        })
        .collect();
    Value::Array(recs)
}

/// Nom de fichier SÛR (anti-injection d'en-tête Content-Disposition) : ne conserve que [A-Za-z0-9._-],
/// borné à 48 caractères, défaut « export ». Empêche toute CRLF/guillemet dans l'en-tête.
pub(crate) fn safe_export_name(raw: Option<&str>) -> String {
    let s: String = raw
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(48)
        .collect();
    if s.is_empty() { "export".to_string() } else { s }
}

/// EXPORT CSV/JSON — même gating et même exécuteur que /api/query (cf. bloc EXPORT supra). Body :
/// `{ format:"csv"|"json", soql?|sql?, from?, to?, limit?, name? }`. Enregistré en `readonly_post`
/// (POST de LECTURE) -> viewer autorisé pour GXQL ; `sql` brut refusé au non-admin (raw_sql_allowed).
/// Réponse = fichier en pièce jointe (Content-Disposition: attachment) + X-Plume-Truncated si le plafond
/// de lignes a été atteint.
/// P7.3-b/c — CE QUE LE NOM DU FICHIER DOIT AVOUER. Fonction PURE : c'est la règle elle-même qui est
/// testable, pas seulement le chemin HTTP qui l'emprunte (le handler `export` n'avait AUCUN test).
///
/// Trois états, et trois seulement — « non tronqué », « tronqué de N lignes », « tronqué d'une ampleur
/// que la sonde n'a pas établie ». Le troisième n'est PAS replié sur zéro : un `truncated` sans
/// ampleur est précisément la faiblesse déjà corrigée sur le top-N, où la perte atteignait ×16,42.
pub(crate) fn marque_troncature(truncated: bool, ecartes: Option<i64>) -> String {
    if !truncated {
        return String::new();
    }
    match ecartes {
        Some(n) if n > 0 => format!("-TRONQUE-{n}-lignes-manquantes"),
        _ => "-TRONQUE-ampleur-inconnue".to_string(),
    }
}

pub(crate) async fn export(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    let from = body.i64_field("from", 0);
    let to = body.i64_field("to", 0);
    let format = body.get("format").and_then(|v| v.as_str()).unwrap_or("csv").to_ascii_lowercase();
    if format != "csv" && format != "json" {
        return bad_req("format invalide (csv|json)");
    }
    // #18 P3 — comme /api/query : union hot∪cold quand la fenêtre atteint sous la frontière jour (sinon None).
    #[allow(unused_mut)]
    let mut cold_boundary: Option<i64> = None;
    // P7.3 — AMPLEUR du plafond top-N de la route rollup (même triplet qu'en /api/query). Portée
    // FONCTION : la sonde est prise à la compilation, mais elle n'est rendue qu'après l'exécution.
    let mut rollup_meta: Option<(bool, CapMesure, Option<String>)> = None;
    // #28 PHASE B — MÊME élagage dimensionnel cold que /api/query : les prédicats sont extraits du SQL COMPILÉ
    // juste avant `cold_union_query` (parité par construction), pas ici.
    // --- COMPILATION STRICTEMENT IDENTIQUE À /api/query (choke-point unique de redaction/RBAC) ---
    // #18 — GXQL post-exclusion pour la DÉRIVATION DE FORME (cf. /api/query). `None` = `sql` brut admin.
    #[cfg_attr(not(feature = "cold_tier"), allow(unused_mut, unused_variables))]
    let mut req_soql: Option<String> = None;
    let (sql, _from_soql) = if let Some(soql) = body.get("soql").and_then(|v| v.as_str()) {
        let soql = apply_excl_placeholders(soql.trim(), true);
        #[cfg(feature = "cold_tier")]
        {
            req_soql = Some(soql.to_string());
        }
        let env = au.env_filter();
        // FIELD FILTERS (#45) : export = MÊME compilation masquée que /api/query (choke-point unique). Masques
        // VIDES -> byte-identique + rollup-route intact ; sinon rollup désactivé (src_ip/host en clair) + compile
        // masqué -> l'export CSV/JSON hérite AUTOMATIQUEMENT du masque (jamais de dump brut non caviardé).
        let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
        // #18 P3 — MÊME déclencheur union que /api/query : une fenêtre atteignant sous `B` DÉSACTIVE le rollup-route
        // (complétude rollup-gap) et exporte l'union hot∪cold masquée -> un export sur longue histoire n'omet JAMAIS
        // en SILENCE les lignes cold. Feature/flag OFF -> None -> chemin HOT byte-identique.
        #[cfg(feature = "cold_tier")]
        {
            let conf = load_config();
            if crate::cold_store::cold_tier_runtime_on(&conf) {
                let rc = req_db(&st, &au);
                let b = {
                    let c = rc.lock();
                    let rd = retention_effective(&c, &conf, "retention_days");
                    crate::cold_store::cold_query_boundary(&c, &conf, now(), rd)
                };
                if from < b {
                    cold_boundary = Some(b);
                }
            }
        }
        // #28 Phase A — MÊME logique que /api/query : rollup COLD+HOT (ZÉRO Parquet) quand la fenêtre atteint
        // sous `B` et qu'aucun masque n'est actif ; succès -> cold_boundary effacé (pool normal) ; sinon chemin
        // brut cold_union_query. Un masque/deny actif -> aucune route -> compile masqué + authorizer (parité).
        // COUVERTURE du rollup : voir /api/query — ÉTABLIE depuis la base, jamais affirmée ici.
        // MÊME discipline pour le rollup PAR DIMENSION (ROUTE B) : la bande dont le job témoigne est LUE
        // depuis la base, jamais affirmée ici ; l'absence de bande vaut déclin (cf. `rollup_coverage`).
        // POOL DE LECTURE, pour la MÊME raison qu'en /api/query (voir le raisonnement là-bas) : un export
        // est déclenché par un humain qui attend, il n'a pas à faire la queue derrière un tick de rollups.
        let (rollup_cov, dim_cov) = read_with(
            req_db_path(&st, &au).as_str(),
            (RollupCoverage::unproven(), DimRollupCoverage::unproven()),
            |c| (RollupCoverage::of(c), DimRollupCoverage::of(c)),
        );
        let rr = if masks.is_empty() {
            #[cfg(feature = "cold_tier")]
            {
                match cold_boundary {
                    Some(b) => {
                        let c = try_cold_rollup_route(&soql, from, to, env, b, rollup_cov, dim_cov);
                        if c.is_some() {
                            cold_boundary = None;
                        }
                        c
                    }
                    None => try_rollup_route(&soql, from, to, env, rollup_cov, dim_cov),
                }
            }
            #[cfg(not(feature = "cold_tier"))]
            {
                try_rollup_route(&soql, from, to, env, rollup_cov, dim_cov)
            }
        } else {
            None
        };
        if let Some(rr) = rr {
            // P7.3 — L'EXPORT SERVI DEPUIS LE ROLLUP DOIT AVOUER SON PLAFOND. Il jetait `rr.cap`
            // (la sonde top-N), `rr.approx` et `rr.note` pour ne garder que le SQL : un export
            // agrégé sortait donc avec `x-plume-truncated: 0` alors que le plafond par dimension
            // avait mordu. `/api/query` mesure la sonde depuis toujours ; l'export ne le faisait
            // pas — même moteur, même plafond, aveu manquant d'un seul côté.
            let cap = read_with(req_db_path(&st, &au).as_str(), rr.cap.sans_base(), |c| rr.cap.mesurer(c));
            rollup_meta = Some((rr.approx, cap, rr.note));
            (rr.sql, true)
        } else {
            match soql_to_sql_masked_x(&soql, from, to, env, &masks) {
                Ok(s) => (s, true),
                Err(e) => return bad_req(e),
            }
        }
    } else {
        // FAILLE A (miroir /api/query) : le champ `sql` BRUT lit toute la base -> RÉSERVÉ ADMIN. L'authorizer
        // read-pool DENY quand même les colonnes secrètes, même pour un admin (défense en profondeur).
        if !raw_sql_allowed(false, &au.role) {
            return forbidden("SQL brut réservé à l'administrateur (utilisez GXQL)");
        }
        let raw = apply_excl_placeholders(body.str_field("sql").trim(), false);
        (raw.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()), false)
    };
    if sql.is_empty() {
        return bad_req("requête vide");
    }
    // borne d'export : wrap LIMIT (marche même si {sql} a déjà un LIMIT — l'inner cape). run_query_ex applique
    // EN PLUS son propre plafond (max_rows) -> jamais au-delà du plafond de lecture existant.
    let limit = body
        .get("limit")
        .and_then(|v| v.as_i64())
        .filter(|&n| n > 0)
        .unwrap_or_else(export_max_rows)
        .min(export_max_rows());
    // backpressure : MÊME sémaphore que /api/query (borne les déchiffrements concurrents ; anti-OOM).
    let _permit = match acquire_query_permit(&st.query_sem).await {
        Ok((p, _wait)) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    let db_path = req_db_path(&st, &au); // #2a : base du tenant courant (jamais st.db, jamais une autre base)
    let export_sql = format!("SELECT * FROM ({sql}) LIMIT {limit}");
    let budget = query_budget_interactive_ms(); // export = action délibérée -> budget interactif (comme /api/query interactive)
    // #18 P3 — INCOMPLÉTUDE : un export cold-tronqué DOIT le signaler (X-Plume-Truncated) -> jamais un CSV/JSON
    // partiel présenté comme complet. `cold_extra_truncated` OR-e la troncature cold au flag `stats.truncated`.
    #[allow(unused_mut)]
    let mut cold_extra_truncated = false;
    #[cfg(feature = "cold_tier")]
    let v = if let Some(boundary) = cold_boundary {
        let conf = load_config();
        let env_s = au.env_filter().map(|s| s.to_string());
        let dbp = db_path.clone();
        let ps = export_sql.clone();
        // #28 PHASE B — extrait du SQL COMPILÉ (`sql`, post-masquage #45), le MÊME qui s'exécute sur l'union.
        let preds = crate::cold_store::extract_cold_dim_preds(&sql);
        let res = tokio::task::spawn_blocking(move || {
            crate::cold_store::cold_union_query(&dbp, &conf, env_s.as_deref(), from, to, boundary, &ps, None, budget, None, &preds)
        })
        .await;
        // #18 — un export est un fichier qu'on archive et qu'on cite : y écrire un agrégat calculé sur un
        // échantillon est pire qu'ailleurs (le drapeau X-Plume-Truncated ne survit pas au fichier). FORME
        // DÉRIVÉE, refus si dérivée-sur-tronqué.
        let shape = match req_soql.as_deref() {
            Some(s) => crate::cold_store::AnswerShape::of_gxql(s),
            None => crate::cold_store::AnswerShape::undecidable(),
        };
        match res {
            Ok(Ok((answer, _meta))) => match answer.render(shape) {
                Ok(r) => {
                    cold_extra_truncated = r.truncated;
                    r.value
                }
                Err(t) => return refuse_truncated_aggregate(t),
            },
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    } else {
        let dbp = db_path.clone();
        let ps = export_sql.clone();
        match tokio::task::spawn_blocking(move || run_query_ex(&dbp, &ps, budget, None)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    };
    #[cfg(not(feature = "cold_tier"))]
    let v = {
        let res = tokio::task::spawn_blocking(move || run_query_ex(&db_path, &export_sql, budget, None)).await;
        match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return bad_req(e),
            Err(_) => return server_err("exécution échouée"),
        }
    };
    // P7.3 — l'ampleur top-N entre dans `stats` AVANT toute lecture de `truncated` (miroir exact de
    // /api/query : `stats.truncated` devient `prev || cap.tronque()`, et `topn_ecartes/servis/total`
    // n'apparaissent QUE si la sonde a pu mesurer — case absente = non mesuré, jamais un zéro).
    let mut v = v;
    apply_rollup_stats(&mut v, &rollup_meta);
    // AUDIT : audite l'export SI le volume dépasse le seuil (exfiltration potentielle).
    let nrows = v.get("rows").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0);
    audit_bulk_read(&st, &au, "export", nrows);
    let truncated = v.get("stats").and_then(|s| s.get("truncated")).and_then(|t| t.as_bool()).unwrap_or(false) || cold_extra_truncated;
    let ecartes = v.get("stats").and_then(|s| s.get("topn_ecartes")).and_then(|x| x.as_i64());
    let (ct, ext, body_str): (&'static str, &str, String) = if format == "csv" {
        ("text/csv; charset=utf-8", "csv", result_to_csv(&v))
    } else {
        ("application/json; charset=utf-8", "json", serde_json::to_string(&result_to_json_records(&v)).unwrap_or_else(|_| "[]".into()))
    };
    // P7.3-b — LE FICHIER PORTE L'AVEU. Un export existe pour SURVIVRE à la réponse : enregistré, un
    // résultat tronqué devenait un fichier d'apparence complète, rouvert des semaines plus tard sans
    // le moindre indice. L'en-tête HTTP, elle, meurt avec la réponse.
    //
    // POURQUOI LE NOM DE FICHIER, et pas le corps. MESURÉ le 2026-08-03 : le CSV est un en-tête de
    // colonnes + N lignes CRLF, le JSON un TABLEAU NU d'objets — et `result_to_json_records` sert
    // AUSSI `/api/ds/query` (datasource Grafana Infinity). Une ligne de commentaire en tête du CSV
    // ou une enveloppe autour du JSON changeraient le contrat de format et casseraient ces tuyaux.
    // Le nom, lui, voyage avec le fichier et ne traverse aucun parseur.
    //
    // P7.3-c — et il porte l'AMPLEUR, pas un simple drapeau : `truncated` nu était la faiblesse déjà
    // corrigée sur le top-N, où une perte allant jusqu'à ×16,42 tenait dans un booléen. Quand la
    // sonde a chiffré l'écart, le nom le dit ; quand elle ne l'a pas établi, le nom dit « ampleur
    // inconnue » — on n'invente pas un nombre qu'on n'a pas.
    let fname = format!(
        "plume-{}-{}{}.{}",
        safe_export_name(body.get("name").and_then(|v| v.as_str())),
        now(),
        marque_troncature(truncated, ecartes),
        ext
    );
    let disp = format!("attachment; filename=\"{fname}\"");
    let mut resp = (StatusCode::OK, body_str).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static(ct));
    if let Ok(hv) = axum::http::HeaderValue::from_str(&disp) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    h.insert(
        axum::http::HeaderName::from_static("x-plume-truncated"),
        axum::http::HeaderValue::from_static(if truncated { "1" } else { "0" }),
    );
    // L'ampleur en en-tête est ADDITIVE : le seul consommateur connu (`web/app.js`) teste
    // `x-plume-truncated === '1'` et n'est pas touché. `x-plume-rows` est toujours posée (le nombre
    // de lignes RENDUES est toujours connu) ; `x-plume-truncated-ecartes` seulement si mesurée.
    if let Ok(hv) = axum::http::HeaderValue::from_str(&nrows.to_string()) {
        h.insert(axum::http::HeaderName::from_static("x-plume-rows"), hv);
    }
    if let Some(n) = ecartes {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&n.to_string()) {
            h.insert(axum::http::HeaderName::from_static("x-plume-truncated-ecartes"), hv);
        }
    }
    resp
}
