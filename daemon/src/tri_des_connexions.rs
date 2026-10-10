//! CE QU'UNE CONNEXION FAIT DE SES TRIS (`S26`) : le verdict `Tri` et ses fonctions PURES ou de LECTURE.
//!
//! Module FEUILLE extrait de `sqlite_plafond` par déplacement pur (`P7.18-a`) : la table de
//! `sqlite3TempInMemory` (`tri_en_memoire`), la dérivation (`tri_pour`), la lecture sur une connexion
//! (`lire_tri`, `tri_dune_connexion_nue`, `tri_de_la_connexion_qui_sert`), le désaccord avec le mode, le
//! constat et le refus de démarrer. Il ne dépend pas de `sqlite_plafond` ; `sqlite_plafond` le consomme
//! (`banniere`, `garde_du_tri_en_memoire`, `armer_avec`) et RÉ-EXPORTE ses symboles, de sorte que tous
//! les chemins `crate::sqlite_plafond::…` restent valides. Le commentaire de section `S26` (pourquoi
//! `PRAGMA temp_store` ne répond pas à la question, et ce que pose le lot) reste dans `sqlite_plafond`,
//! au-dessus de la garde et de l'armement qu'il décrit ; « l'en-tête de ce module » y renvoie.
use crate::*;

/// CE QU'UNE CONNEXION FAIT DE SES TRIS. Trois cas EXCLUSIFS, d'où un type et des `match` EXHAUSTIFS :
/// « je ne sais pas » ne doit jamais pouvoir se déguiser en « tout va bien ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tri {
    /// Le trieur n'a AUCUN chemin de déversement : rien d'un événement ne peut toucher le disque.
    EnMemoire { compile: i64, local: i64 },
    /// Le trieur PEUT déverser : des valeurs d'événement partiraient en clair hors de SQLCipher.
    SurDisque { compile: i64, local: i64 },
    /// Le réglage ne se LIT pas. On ne prétend rien — et l'appelant refuse.
    Illisible(String),
}

/// MIROIR EXACT de `sqlite3TempInMemory` (`sqlite3.c` 3.39.4, l. 178609-178624) : la TABLE que SQLite
/// documente lui-même, pas une intuition. PURE, donc exerçable sur toutes les combinaisons — y compris
/// celles qu'aucune construction ne produit aujourd'hui, qui sont précisément le sujet.
pub(crate) fn tri_en_memoire(compile: i64, local: i64) -> bool {
    match compile {
        1 => local == 2,  // défaut de SQLite : seul un `temp_store=MEMORY` EXPLICITE sauve le silence
        2 => local != 1,  // ce que porte la construction SQLCipher livrée
        3 => true,        // « jamais de fichier temporaire », compilé en dur
        _ => false,       // 0 ou hors bornes : SQLite rend 0 — FICHIER, quel que soit le réglage local
    }
}

/// LA DÉRIVATION, séparée de la LECTURE pour être exerçable sans moteur sous la main.
pub(crate) fn tri_pour(compile: Option<i64>, local: Option<i64>) -> Tri {
    match (compile, local) {
        (Some(c), Some(l)) if tri_en_memoire(c, l) => Tri::EnMemoire { compile: c, local: l },
        (Some(c), Some(l)) => Tri::SurDisque { compile: c, local: l },
        (None, _) => Tri::Illisible("`PRAGMA compile_options` ne nomme aucun TEMP_STORE".into()),
        (Some(_), None) => Tri::Illisible("`PRAGMA temp_store` ne se relit pas".into()),
    }
}

/// LA VALEUR COMPILÉE, LUE DANS LE MOTEUR. C'est la seule chose qui réponde à « que fait une connexion
/// qui ne dit rien » : `PRAGMA temp_store` rendrait 0, qui ne distingue pas les deux mondes.
fn temp_store_compile(conn: &Connection) -> Option<i64> {
    let mut st = conn.prepare("PRAGMA compile_options").ok()?;
    let mut lignes = st.query([]).ok()?;
    while let Ok(Some(r)) = lignes.next() {
        if let Ok(o) = r.get::<_, String>(0) {
            if let Some(v) = o.trim().strip_prefix("TEMP_STORE=") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

/// CE QUE CETTE CONNEXION-CI fera de ses tris, LU sur elle.
pub(crate) fn lire_tri(conn: &Connection) -> Tri {
    tri_pour(
        temp_store_compile(conn),
        conn.query_row("PRAGMA temp_store", [], |r| r.get::<_, i64>(0)).ok(),
    )
}

/// CE QUE FAIT UNE CONNEXION QUI NE DIT RIEN — la mesure dont dépend toute la garantie.
///
/// `open_in_memory` est DÉLIBÉRÉ et ne restreint pas la portée : `sqlite3TempInMemory` ne regarde que
/// la valeur compilée (une constante du PROCESSUS) et le réglage local de la connexion. Le fichier
/// n'entre pas dans la décision, et sonder un fichier créerait une base pour poser une question de
/// configuration.
///
/// INSTRUMENT VALIDÉ : une sonde dont le réglage local n'est pas 0 n'est PAS nue — elle ne mesure alors
/// pas le silence, et un instrument qui ne peut pas voir son sujet doit le DIRE, pas rendre vert.
pub(crate) fn tri_dune_connexion_nue() -> Tri {
    match Connection::open_in_memory() {
        Ok(c) => match lire_tri(&c) {
            Tri::EnMemoire { local, .. } | Tri::SurDisque { local, .. } if local != 0 => {
                Tri::Illisible(format!("la sonde n'est pas NUE (temp_store local={local})"))
            }
            verdict => verdict,
        },
        Err(e) => Tri::Illisible(format!("connexion de sonde impossible : {e}")),
    }
}

/// CE QUE LA CONNEXION QUI SERT FERA DE SES TRIS — la mesure que la bannière publie (`S38`).
///
/// Lue sur la connexion que la porte a ARMÉE, donc celle dont `PRAGMA temp_store` vaut ce que `armer`
/// a posé : 1 sous déversement, 2 au défaut — et 0 si l'armement n'a PAS eu lieu, auquel cas c'est la
/// contradiction qui se dit (sous déversement : « demandé mais le tri reste en mémoire »), pas un
/// « tout va bien ». Une sonde nue (`tri_dune_connexion_nue`) ne peut PAS répondre à cette question :
/// personne n'y pose `temp_store=FILE`, donc sous déversement elle contredisait le mode à chaque
/// démarrage, et une garde qui alerte toujours ne prouve rien.
///
/// Rendue sous la forme de `S32` parce que la bannière doit pouvoir dire « NON MESURÉ » : un appelant
/// qui n'a pas encore de connexion armée sous la main passe `Mesure::Illisible` avec sa cause, jamais
/// la lecture d'une autre connexion.
pub(crate) fn tri_de_la_connexion_qui_sert(conn: &Connection) -> crate::mesure_environnement::Mesure<Tri> {
    crate::mesure_environnement::Mesure::Lue(lire_tri(conn))
}

/// CE QUE LA LECTURE CONTREDIT. PURE, donc exerçable dans les DEUX sens sans toucher à l'environnement.
/// `None` = la lecture CONFIRME ce que le mode promet ; une garde qui alerterait toujours ne prouverait
/// rien.
pub(crate) fn desaccord_pour(tri: &Tri, deversement: bool) -> Option<String> {
    match (tri, deversement) {
        (Tri::EnMemoire { .. }, false) | (Tri::SurDisque { .. }, true) => None,
        (Tri::SurDisque { compile, local }, false) => Some(format!(
            "LE TRI DÉVERSE ALORS QUE RIEN NE L'A DEMANDÉ (LU : temp_store local={local}, \
             TEMP_STORE={compile} dans compile_options) : des VALEURS D'ÉVÉNEMENT partent EN CLAIR hors \
             de la base SQLCipher, qui ne chiffre PAS les fichiers temporaires de SQLite. \
             PLUME_SQLITE_DEVERSEMENT vaut 0 : cet échange n'a pas été pris."
        )),
        (Tri::EnMemoire { compile, local }, true) => Some(format!(
            "LE DÉVERSEMENT A ÉTÉ DEMANDÉ MAIS LE TRI RESTE EN MÉMOIRE (LU : temp_store local={local}, \
             TEMP_STORE={compile} dans compile_options) : la borne mémoire attendue du trieur n'existe \
             pas, un tri trop large ÉCHOUERA au plafond au lieu de déverser."
        )),
        (Tri::Illisible(e), _) => Some(format!(
            "CE QUE LE MOTEUR FAIT DE SES TRIS N'EST PAS LISIBLE ({e}) : impossible de dire si des \
             valeurs d'événement peuvent partir en clair hors de la base chiffrée."
        )),
    }
}

/// LE CONSTAT, EN CHIFFRES LUS — ce que la bannière publie quand la mesure confirme le mode.
pub(crate) fn constat_de_tri(tri: &Tri) -> String {
    match tri {
        Tri::EnMemoire { compile, local } => format!(
            "un tri reste en MÉMOIRE (temp_store local={local}, TEMP_STORE={compile} dans compile_options)"
        ),
        Tri::SurDisque { compile, local } => format!(
            "un tri DÉVERSE sur le disque (temp_store local={local}, TEMP_STORE={compile} dans compile_options)"
        ),
        Tri::Illisible(e) => format!("réglage NON LISIBLE ({e})"),
    }
}

/// LE REFUS DE DÉMARRER. UNE SEULE des deux directions arrête le processus, et la dissymétrie se dit :
/// un déversement demandé et non obtenu coûte une requête qui échoue, un déversement obtenu sans avoir
/// été demandé coûte la confidentialité — et une fuite ne se rattrape pas.
/// PUR (prend le verdict déjà lu) → les deux sens se testent sans toucher à l'environnement.
pub(crate) fn refus_de_demarrage_pour(tri: &Tri, deversement: bool) -> Option<String> {
    if deversement {
        return None;
    }
    desaccord_pour(tri, deversement).map(|quoi| {
        format!(
            "REFUS DE DÉMARRER — {quoi} Reconstruire la liaison SQLite avec SQLITE_TEMP_STORE=2 (le \
             moteur trie alors en mémoire même pour une connexion muette), ou poser \
             PLUME_SQLITE_DEVERSEMENT=1 pour prendre cet échange EXPLICITEMENT — et placer alors \
             SQLITE_TMPDIR sur un support chiffré."
        )
    })
}
