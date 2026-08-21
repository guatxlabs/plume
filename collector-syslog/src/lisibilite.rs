//! `S36` — À L'ENTRÉE AUSSI, UNE LECTURE QUI ÉCHOUE NE REND PAS LA VALEUR LA PLUS RASSURANTE.
//!
//! LA FORME EST CELLE DU DÉMON (`daemon/src/mesure_environnement.rs`, clés `S28`/`S32`/`S33`), REPRISE
//! AUX MÊMES MOTS. Ce récepteur ne partage aucune bibliothèque avec le démon ni avec l'agent — les
//! trois binaires sont autonomes par construction. Le vocabulaire, lui, est COMMUN : un exploitant qui
//! lit deux surfaces doit reconnaître les mêmes mots, et un test de ce crate lit le module du démon
//! pour refuser toute dérive silencieuse de l'un des deux côtés.
//!
//! CE QUE CE MODULE FERME ICI, ET DANS QUEL ORDRE :
//!   * la LISTE D'ADRESSES AUTORISÉES, qui n'est pas une mesure mais une PORTE : son analyse jetait
//!     les entrées invalides une par une, et une liste entièrement fautive devenait une liste VIDE,
//!     c'est-à-dire « tout le monde entre ». Ce n'est pas une détection rendue impossible, c'est un
//!     port d'ingestion non authentifié ouvert au monde ;
//!   * l'IDENTITÉ DE L'HÔTE, qui rendait un nom plausible (`unknown`) quand sa source n'était pas
//!     lisible — indiscernable d'une lecture réussie, et commune à toutes les machines en échec ;
//!   * les RÉGLAGES NUMÉRIQUES, dont une valeur POSÉE mais non comprise retombait en silence sur le
//!     défaut : un plafond qu'un exploitant croit avoir changé et qui n'a pas bougé.

use serde_json::json;

// =================================================================================================
// LE VOCABULAIRE — LES MOTS DU DÉMON, À LA LETTRE
// =================================================================================================

/// La cause quand il n'y en a pas.
pub const CAUSE_AUCUNE: &str = "aucune";
/// La source n'existe pas (fichier, répertoire, variable non posée).
pub const CAUSE_SOURCE_ABSENTE: &str = "source_absente";
/// La source existe mais son accès est refusé.
pub const CAUSE_SOURCE_REFUSEE: &str = "source_refusee";
/// La source existe, l'accès est permis, la lecture échoue quand même.
pub const CAUSE_SOURCE_ILLISIBLE: &str = "source_illisible";
/// La source a été LUE mais sa forme n'est pas comprise. C'est le cas de la liste d'adresses posée
/// et fautive, et celui d'un réglage numérique qui n'est pas un nombre.
pub const CAUSE_FORME_INCONNUE: &str = "forme_inconnue";

/// L'ensemble FERMÉ des causes — le même que celui du démon, dans le même ordre.
pub const CAUSES: [&str; 5] =
    [CAUSE_AUCUNE, CAUSE_SOURCE_ABSENTE, CAUSE_SOURCE_REFUSEE, CAUSE_SOURCE_ILLISIBLE, CAUSE_FORME_INCONNUE];

/// Le mot de verdict quand la lecture a eu lieu.
#[allow(dead_code)] // moitié LUE du couple : exercée par la suite, et le pendant de `VERDICT_ILLISIBLE`
pub const VERDICT_LU: &str = "lu";
/// Le mot de verdict quand la source n'est pas lisible.
pub const VERDICT_ILLISIBLE: &str = "illisible";

/// Vocabulaire GROSSIER du contrat d'indisponibilité déjà livré (`collectors/lib.sh`).
pub const RAISON_SOURCE_ABSENTE: &str = "missing-source";
/// Un RÉGLAGE obligatoire manque ou n'est pas exploitable.
pub const RAISON_CONFIG_ABSENTE: &str = "missing-config";
/// L'ensemble fermé employé par cette surface (les autres mots du contrat n'y ont pas d'emploi).
pub const RAISONS: [&str; 2] = [RAISON_SOURCE_ABSENTE, RAISON_CONFIG_ABSENTE];

// =================================================================================================
// LE TYPE — DEUX CAS, AUCUNE VALEUR PAR DÉFAUT
// =================================================================================================

/// CE QU'UNE LECTURE PEUT VALOIR. Aucun constructeur ne rend une valeur faute de savoir.
#[derive(Debug, Clone, PartialEq)]
pub enum Lecture<T> {
    /// La source a été lue et comprise. La valeur peut être vide — c'est alors un VRAI vide.
    Lue(T),
    /// La source n'a pas pu être lue, ou pas comprise.
    Illisible { cause: &'static str, detail: String },
}

/// LES ACCESSEURS DU CONTRAT — une seule traduction verdict/cause pour toute la surface. Tous n'ont
/// pas encore d'appelant hors de la suite ; les retirer obligerait le prochain site à en réinventer.
#[allow(dead_code)]
impl<T> Lecture<T> {
    pub fn verdict(&self) -> &'static str {
        match self {
            Lecture::Lue(_) => VERDICT_LU,
            Lecture::Illisible { .. } => VERDICT_ILLISIBLE,
        }
    }
    pub fn cause(&self) -> &'static str {
        match self {
            Lecture::Lue(_) => CAUSE_AUCUNE,
            Lecture::Illisible { cause, .. } => cause,
        }
    }
    pub fn valeur(&self) -> Option<&T> {
        match self {
            Lecture::Lue(v) => Some(v),
            Lecture::Illisible { .. } => None,
        }
    }
    pub fn detail(&self) -> Option<&str> {
        match self {
            Lecture::Lue(_) => None,
            Lecture::Illisible { detail, .. } => Some(detail),
        }
    }
}

/// LA CAUSE, DÉRIVÉE DE L'ERREUR SYSTÈME — un seul auteur pour cette traduction.
pub fn cause_io(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => CAUSE_SOURCE_ABSENTE,
        std::io::ErrorKind::PermissionDenied => CAUSE_SOURCE_REFUSEE,
        _ => CAUSE_SOURCE_ILLISIBLE,
    }
}

// =================================================================================================
// L'IDENTITÉ DE L'HÔTE
// =================================================================================================

/// LE NOM PUBLIÉ QUAND L'IDENTITÉ N'A PAS PU ÊTRE LUE. Ce n'est pas un repli, c'est le VERDICT mis à
/// la place de la valeur : `unknown` était un nom d'hôte PLAUSIBLE, indiscernable d'une lecture
/// réussie, sur lequel toutes les machines en échec se confondaient — et qu'une machine réellement
/// nommée ainsi se voyait attribuer.
pub const HOTE_NON_LU: &str = "hote-illisible";

/// L'IDENTITÉ DE CET HÔTE, LUE OU AVOUÉE — paramétrée sur ses sources, donc exerçable hors machine.
/// La précédence est celle d'avant : le fichier d'abord, la variable ensuite. Un fichier présent mais
/// VIDE est lu et compris, et ce qu'il porte n'est pas un nom : `forme_inconnue`, pas `source_absente`.
pub fn identite_hote_depuis(chemin: &std::path::Path, variable: Option<&str>) -> Lecture<String> {
    let (contenu, echec) = match std::fs::read_to_string(chemin) {
        Ok(t) => (t.trim().to_string(), None),
        Err(e) => (String::new(), Some((cause_io(&e), format!("{} : {e}", chemin.display())))),
    };
    if !contenu.is_empty() {
        return Lecture::Lue(contenu);
    }
    if let Some(v) = variable.map(str::trim).filter(|v| !v.is_empty()) {
        return Lecture::Lue(v.to_string());
    }
    match echec {
        Some((cause, detail)) => Lecture::Illisible {
            cause,
            detail: format!("{detail} ; et aucune variable de repli renseignée"),
        },
        None => Lecture::Illisible {
            cause: CAUSE_FORME_INCONNUE,
            detail: format!(
                "{} : lu, mais ne porte aucun nom d'hôte (vide ou blancs) ; et aucune variable de \
                 repli renseignée",
                chemin.display()
            ),
        },
    }
}

// =================================================================================================
// L'AVEU — LE CANAL D'INDISPONIBILITÉ DÉJÀ LIVRÉ, À L'IDENTIQUE
// =================================================================================================

fn empreinte(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// L'AVEU, AU CONTRAT DE `collectors/lib.sh` : `category=config`, `fields.collect_status=unavailable`,
/// `fields.reason` dans le vocabulaire shell, plus `fields.cause`/`fields.verdict` aux mots du démon.
/// La règle livrée `de-collector-unavailable.json` ALERTE déjà sur cette forme — aucune règle, aucune
/// catégorie et aucune métrique nouvelle n'est créée. Clé à seau HORAIRE, comme `plume_unavailable`.
pub fn event_indisponibilite(
    source: &str,
    raison: &'static str,
    cause: &'static str,
    detail: &str,
    ts: i64,
) -> serde_json::Value {
    debug_assert!(RAISONS.contains(&raison), "raison hors de l'ensemble ferme : {raison:?}");
    debug_assert!(CAUSES.contains(&cause), "cause hors de l'ensemble ferme : {cause:?}");
    debug_assert!(cause != CAUSE_AUCUNE, "un aveu sans cause n'avoue rien");
    let fields = json!({
        "type": "collector-availability",
        "collector": source,
        "collect_status": "unavailable",
        "reason": raison,
        "cause": cause,
        "verdict": VERDICT_ILLISIBLE,
        "detail": detail,
    });
    let dd = format!("avail-{source}-{:x}-{}", empreinte(&fields.to_string()), ts / 3600);
    json!({
        "ts": ts,
        "source": source,
        "category": "config",
        // Sévérité 2 (avertissement), comme `plume_unavailable` : un trou de couverture doit se voir.
        "severity": 2,
        "message": format!("collector-syslog {source} : {cause} ({raison}) — {detail}"),
        "dedup": dd,
        "fields": fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un repertoire temporaire POSSEDE : rien de la machine qui execute la suite n'entre dans un
    /// verdict — c'est ce qui rend ces temoins valables sur un hote sans `/proc` comme sur un autre.
    struct TmpPossede(std::path::PathBuf);
    impl TmpPossede {
        fn neuf(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!("plume-s36-syslog-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
        fn join(&self, p: &str) -> std::path::PathBuf {
            self.0.join(p)
        }
    }
    impl Drop for TmpPossede {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// LA PAIRE SUR L'IDENTITE. ② une source presente et renseignee est LUE et sa valeur publiee ;
    /// ① une source absente rend un VERDICT et AUCUN nom. Sans le second temoin, une version qui ne
    /// saurait jamais rien passerait le premier sans rien prouver.
    #[test]
    fn une_identite_illisible_ne_rend_aucun_nom() {
        let tmp = TmpPossede::neuf("identite");
        let f = tmp.join("hostname");

        // ② le cas nominal.
        std::fs::write(&f, "recepteur-01\n").unwrap();
        let v = identite_hote_depuis(&f, None);
        assert_eq!(v.verdict(), VERDICT_LU);
        assert_eq!(v.valeur().map(String::as_str), Some("recepteur-01"));

        // ① la source n'est pas la, et aucune variable ne la remplace.
        let absent = tmp.join("jamais-ecrit");
        let v = identite_hote_depuis(&absent, None);
        assert_eq!(v.verdict(), VERDICT_ILLISIBLE);
        assert_eq!(v.cause(), CAUSE_SOURCE_ABSENTE);
        assert!(v.valeur().is_none(), "aucun nom ne sort d'une source absente");

        // ① bis — present mais vide : LU, et ce qu'il porte n'est pas un nom.
        std::fs::write(&f, "  \n").unwrap();
        assert_eq!(identite_hote_depuis(&f, None).cause(), CAUSE_FORME_INCONNUE);
        // ② bis — la variable prend alors le relais, comme avant.
        assert_eq!(
            identite_hote_depuis(&f, Some("depuis-variable")).valeur().map(String::as_str),
            Some("depuis-variable")
        );
    }

    /// Le verdict d'identite n'est pas un nom de machine plausible : c'est la propriete qui le
    /// distingue de l'ancien repli `unknown`, sur lequel toutes les machines en echec se confondaient.
    #[test]
    fn le_verdict_d_identite_n_est_pas_un_nom_plausible() {
        assert_ne!(HOTE_NON_LU, "unknown");
        assert_ne!(HOTE_NON_LU, "localhost");
        assert!(HOTE_NON_LU.contains(VERDICT_ILLISIBLE));
    }

    /// L'aveu emprunte le canal deja livre, MOT POUR MOT : c'est la condition pour que la regle
    /// `de-collector-unavailable.json` (`search category=config collect_status=unavailable`) le voie
    /// sans etre touchee, et pour que l'imputation bascule la pastille de CETTE source.
    #[test]
    fn l_aveu_respecte_le_contrat_d_indisponibilite_deja_livre() {
        let ev = event_indisponibilite("hote-illisible", RAISON_CONFIG_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 3600);
        assert_eq!(ev["category"], "config");
        assert_eq!(ev["severity"], 2);
        assert_eq!(ev["fields"]["collect_status"], "unavailable");
        assert_eq!(ev["fields"]["type"], "collector-availability");
        assert_eq!(ev["fields"]["reason"], RAISON_CONFIG_ABSENTE);
        assert_eq!(ev["fields"]["cause"], CAUSE_SOURCE_ABSENTE);
        // Cle a seau HORAIRE : stable dans l'heure, ré-affirmee a la suivante.
        let meme = event_indisponibilite("hote-illisible", RAISON_CONFIG_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 3659);
        let apres = event_indisponibilite("hote-illisible", RAISON_CONFIG_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 7200);
        assert_eq!(ev["dedup"], meme["dedup"]);
        assert_ne!(ev["dedup"], apres["dedup"]);
    }

    /// LE VOCABULAIRE EST CELUI DU DEMON, ET IL NE PEUT PAS DERIVER EN SILENCE.
    ///
    /// Ces trois binaires ne partagent aucune bibliotheque — c'est voulu, ils s'installent seuls.
    /// Le vocabulaire de causes, lui, DOIT rester commun : un exploitant qui lit une mesure du demon
    /// et un aveu de ce recepteur doit reconnaitre les memes mots. Cette garde lit donc le module du
    /// demon et exige que chacun de ses mots y figure. Elle porte son propre plancher : si elle ne
    /// peut pas lire la reference, elle ECHOUE au lieu de rendre vert en etant aveugle.
    #[test]
    fn les_mots_de_cause_sont_ceux_du_demon() {
        let reference = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("daemon")
            .join("src")
            .join("mesure_environnement.rs");
        let texte = std::fs::read_to_string(&reference).unwrap_or_else(|e| {
            panic!(
                "reference de vocabulaire illisible ({e}) — cette garde ne peut pas conclure, et ne \
                 doit pas rendre vert en etant aveugle"
            )
        });
        assert!(
            texte.len() > 2000,
            "reference de vocabulaire suspecte ({} octets) : parcours casse", texte.len()
        );
        for mot in CAUSES.iter().chain([&VERDICT_LU, &VERDICT_ILLISIBLE]) {
            assert!(
                texte.contains(&format!("\"{mot}\"")),
                "le mot {mot:?} n'existe plus dans le module du demon : les deux surfaces ont derive"
            );
        }
        // Aucun doublon : une table qui se repete ne borne rien.
        for (i, a) in CAUSES.iter().enumerate() {
            assert!(!CAUSES[i + 1..].contains(a), "cause en double : {a}");
        }
    }
}
