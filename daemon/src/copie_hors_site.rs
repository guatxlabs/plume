//! LA COPIE HORS SITE : CE QUE PLUME SAIT, ET AVOUE, DE LA DERNIÈRE COPIE DE SES SAUVEGARDES HORS DU DISQUE.
//! ===============================================================================================
//! LE DÉFAUT QUE CE MODULE FERME. Le magasin des sauvegardes peut vivre sur le MÊME disque que la
//! base : perdre ce disque perd alors la base ET toutes ses sauvegardes. La parade retenue par
//! l'exploitant est une copie TIRÉE par un poste extérieur — la production n'a aucun accès vers lui,
//! elle ne peut donc ni lancer ni vérifier la copie elle-même. Ce qu'elle peut faire, c'est LIRE ce
//! que le poste dépose après chaque copie réussie, et dire depuis combien de temps rien n'est venu.
//! Sans ce module, rien dans le produit ne disait si une copie hors site existait, ni son âge.
//!
//! LE FICHIER D'ATTESTATION. Une seule ligne `<horodatage unix> <nom d'archive> <sha256 hex64>`.
//! Après une copie vérifiée (taille et empreinte), le poste n'envoie que le nom et l'empreinte, par
//! sa commande forcée ; c'est le script de cette commande, CÔTÉ PRODUCTION, qui écrit la ligne et
//! l'horodatage, pris à l'horloge du nœud. Le format est celui-là seul : ce dépôt ne porte pas ce
//! script, il n'en prouve donc pas la sortie — la concordance se relit sur la ligne servie en
//! production (`last_copy_ts`, `archive`, `sha256` du composant). Son chemin est le
//! réglage `PLUME_COPIE_HORS_SITE_ATTESTATION` ; il peut être monté en lecture seule. Le fichier est
//! lu à chaque calcul de santé, borné en taille, jugé par `stat` AVANT toute ouverture (un fichier
//! trop grand ou qui n'est pas un fichier ordinaire est refusé sur sa métadonnée), puis ouvert avec
//! `O_NONBLOCK` : défense pour la fenêtre entre le `stat` et l'ouverture (un tube nommé substitué
//! là ne doit pas suspendre la lecture) — une course, sans témoin déterministe.
//!
//! CE QUE L'ATTESTATION N'EST PAS. Elle ne prouve pas que la copie est restaurable (c'est l'objet de
//! l'exercice de restauration, `exercice_de_restauration.rs`), ni qu'un exploitant n'a pas écrit la
//! ligne à la main : la menace visée est l'OUBLI — une tâche qui ne tourne plus, une session fermée
//! depuis des jours — et un oubli se voit à l'âge.
//!
//! CE QUI EST SERVI, ET CE QUI NE L'EST JAMAIS. Le composant de santé porte l'état, l'âge, le nom
//! d'archive (une forme fixe, jamais un chemin) et l'empreinte. Le CHEMIN du fichier d'attestation
//! n'est servi nulle part : le détail nomme le RÉGLAGE, jamais sa valeur.
use crate::*;

/// Nom du composant de santé — le même dans `/api/system/health`, dans `plume_component_up` et dans
/// le bundle de diagnostic.
pub(crate) const COMPOSANT: &str = "copie_hors_site";

/// Chemin du fichier d'attestation. Vide ou absent -> copie hors site NON DÉCLARÉE.
pub(crate) const REGLAGE_ATTESTATION: &str = "PLUME_COPIE_HORS_SITE_ATTESTATION";

/// Âge maximal de la dernière copie avant qu'elle ne soit dite PÉRIMÉE, en HEURES. `0` -> suivi
/// DÉSACTIVÉ, et la désactivation se VOIT (composant `idle` qui nomme le réglage). Une valeur qui
/// n'est pas un entier positif ou nul est REFUSÉE et nommée, jamais remplacée par le défaut.
pub(crate) const REGLAGE_AGE_MAX_HEURES: &str = "PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES";
pub(crate) const AGE_MAX_HEURES_DEFAUT: i64 = 48;

/// Borne de lecture du fichier d'attestation, en octets. Une ligne d'attestation en fait moins de
/// cent cinquante ; au-delà, le fichier n'est pas lu et le refus dit sa taille.
pub(crate) const TAILLE_MAX_OCTETS: u64 = 1024;

/// Avance d'horloge tolérée sur l'horodatage attesté (même tolérance que l'exercice de restauration).
pub(crate) const TOLERANCE_HORLOGE_S: i64 = 3600;

/// Forme du nom d'archive attesté : `plume-<AAAAMMJJTHHMMSSZ>.db.age`, l'horodatage relu par
/// `backup::parse_backup_ts` (le même lecteur que la rétention).
const PREFIXE_ARCHIVE: &str = "plume-";
const SUFFIXE_ARCHIVE: &str = ".db.age";

/// UNE ATTESTATION LUE ET JUGÉE BIEN FORMÉE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attestation {
    /// Instant de la dernière copie attestée (unix s), écrit côté production par le script de la
    /// commande forcée à la réception de l'attestation, horloge du nœud — pas celle du poste.
    pub(crate) ts: i64,
    /// Nom d'archive copiée, de forme fixe (jamais un chemin).
    pub(crate) archive: String,
    /// Empreinte SHA-256 attestée, telle qu'écrite (64 caractères hexadécimaux).
    pub(crate) sha256: String,
}

/// LES REFUS NOMMÉS. Chacun dit ce qui n'a pas pu être établi ; aucun ne se lit « jamais copiée ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refus {
    /// `PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES` n'est pas un entier positif ou nul.
    ReglageAgeIllisible,
    /// Le fichier d'attestation n'existe pas au chemin déclaré.
    AttestationAbsente,
    /// Le fichier existe peut-être, mais sa lecture a échoué (droits, E/S) ; l'errno quand il est connu.
    AttestationIllisible { errno: Option<i32> },
    /// Le chemin déclaré n'est pas un fichier ordinaire (répertoire, tube, périphérique).
    AttestationPasUnFichier,
    /// Le fichier dépasse la borne de lecture : un FAIT borné, pas une lecture ratée.
    AttestationTropGrande { octets: u64 },
    /// Pas exactement une ligne de trois champs séparés par une espace (ou octets non UTF-8).
    LigneHorsForme,
    /// L'horodatage n'est pas un entier décimal positif.
    HorodatageHorsForme,
    /// Le nom d'archive n'a pas la forme `plume-AAAAMMJJTHHMMSSZ.db.age`.
    NomDArchiveHorsForme,
    /// L'empreinte n'est pas un SHA-256 hexadécimal de 64 caractères.
    EmpreinteHorsForme,
    /// L'horodatage est dans le futur au-delà de la tolérance d'horloge.
    DateeDansLeFutur { avance_s: i64 },
}

impl Refus {
    /// Le mot publié en JSON (stable, indépendant de la phrase).
    pub(crate) fn mot(&self) -> &'static str {
        match self {
            Refus::ReglageAgeIllisible => "reglage_age_illisible",
            Refus::AttestationAbsente => "attestation_absente",
            Refus::AttestationIllisible { .. } => "attestation_illisible",
            Refus::AttestationPasUnFichier => "attestation_pas_un_fichier",
            Refus::AttestationTropGrande { .. } => "attestation_trop_grande",
            Refus::LigneHorsForme => "ligne_hors_forme",
            Refus::HorodatageHorsForme => "horodatage_hors_forme",
            Refus::NomDArchiveHorsForme => "nom_d_archive_hors_forme",
            Refus::EmpreinteHorsForme => "empreinte_hors_forme",
            Refus::DateeDansLeFutur { .. } => "datee_dans_le_futur",
        }
    }

    /// La phrase de la cause. Elle nomme le RÉGLAGE, jamais sa valeur (le chemin n'est pas servi).
    pub(crate) fn phrase(&self) -> String {
        match self {
            Refus::ReglageAgeIllisible => format!("{REGLAGE_AGE_MAX_HEURES} n'est pas un entier positif ou nul"),
            Refus::AttestationAbsente => format!("fichier d'attestation absent au chemin de {REGLAGE_ATTESTATION}"),
            Refus::AttestationIllisible { errno: Some(n) } => format!("fichier d'attestation illisible (errno {n})"),
            // HORS D'ATTEINTE PAR UN TÉMOIN : `stat`, `open` et `read` rendent toujours un errno du
            // système ; ce bras couvre une erreur d'E/S synthétique de la bibliothèque standard.
            Refus::AttestationIllisible { errno: None } => "fichier d'attestation illisible (cause non numérotée)".into(),
            Refus::AttestationPasUnFichier => format!("le chemin de {REGLAGE_ATTESTATION} n'est pas un fichier ordinaire"),
            Refus::AttestationTropGrande { octets } => format!(
                "fichier d'attestation de {octets} octets, au-delà de la borne de {TAILLE_MAX_OCTETS} octets : non lu"),
            Refus::LigneHorsForme => "attendu une seule ligne `<horodatage unix> <archive> <sha256>`".into(),
            Refus::HorodatageHorsForme => "horodatage qui n'est pas un entier décimal positif".into(),
            Refus::NomDArchiveHorsForme => "nom d'archive hors de la forme `plume-AAAAMMJJTHHMMSSZ.db.age`".into(),
            Refus::EmpreinteHorsForme => "empreinte qui n'est pas un SHA-256 hexadécimal de 64 caractères".into(),
            Refus::DateeDansLeFutur { avance_s } => format!(
                "attestation datée dans le futur ({avance_s} s d'avance, tolérance {TOLERANCE_HORLOGE_S} s) : \
                 horloge de qui écrit l'attestation ou de ce nœud à vérifier"),
        }
    }
}

/// L'ÉTAT DU SUIVI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Etat {
    /// Suivi désactivé (`PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES=0`).
    NonSuivi,
    /// Aucun fichier d'attestation déclaré : plume ne sait pas si une copie hors site existe.
    NonDeclaree,
    /// Une attestation était attendue et n'a pas pu être établie.
    Refusee(Refus),
    /// Dernière copie plus récente que l'âge maximal (bord compris).
    Fraiche { attestation: Attestation, age_s: i64 },
    /// Dernière copie plus vieille que l'âge maximal.
    Perimee { attestation: Attestation, age_s: i64 },
}

impl Etat {
    /// LA COULEUR. `non_declaree` est JAUNE, pas `idle` : `idle` compte comme un vert dans
    /// `plume_component_up` (1) et dans la posture, alors qu'une installation qui ne déclare aucune
    /// copie hors site porte exactement le risque que ce composant existe pour dire (le disque des
    /// sauvegardes est peut-être celui de la base). Et pas ROUGE : aucun sous-système n'est en panne
    /// MAINTENANT, c'est un défaut de posture, comme un exercice de restauration jamais fait (jaune
    /// lui aussi). Seul le suivi DÉSACTIVÉ explicitement est `idle`, et il nomme le réglage.
    pub(crate) fn sante(&self) -> &'static str {
        match self {
            Etat::NonSuivi => "idle",
            Etat::Fraiche { .. } => "green",
            Etat::NonDeclaree | Etat::Refusee(_) | Etat::Perimee { .. } => "yellow",
        }
    }

    pub(crate) fn mot(&self) -> &'static str {
        match self {
            Etat::NonSuivi => "non_suivi",
            Etat::NonDeclaree => "non_declaree",
            Etat::Refusee(_) => "refusee",
            Etat::Fraiche { .. } => "fraiche",
            Etat::Perimee { .. } => "perimee",
        }
    }

    /// `Some(true)` = la copie est en retard ; `None` tant que rien n'est ÉTABLI (non déclarée,
    /// refusée, non suivie) : publier 0 dirait « à jour » sur une copie dont on ne sait rien.
    pub(crate) fn en_retard(&self) -> Option<bool> {
        match self {
            Etat::Fraiche { .. } => Some(false),
            Etat::Perimee { .. } => Some(true),
            Etat::NonSuivi | Etat::NonDeclaree | Etat::Refusee(_) => None,
        }
    }

    pub(crate) fn attestation(&self) -> Option<&Attestation> {
        match self {
            Etat::Fraiche { attestation, .. } | Etat::Perimee { attestation, .. } => Some(attestation),
            _ => None,
        }
    }

    pub(crate) fn age_s(&self) -> Option<i64> {
        match self {
            Etat::Fraiche { age_s, .. } | Etat::Perimee { age_s, .. } => Some(*age_s),
            _ => None,
        }
    }

    pub(crate) fn detail(&self) -> String {
        use crate::exercice_de_restauration::duree_lisible;
        match self {
            Etat::NonSuivi => format!(
                "copie hors site NON SUIVIE ({REGLAGE_AGE_MAX_HEURES}=0) : l'âge de la dernière copie hors site \
                 n'est pas surveillé"),
            Etat::NonDeclaree => format!(
                "copie hors site NON DÉCLARÉE ({REGLAGE_ATTESTATION} vide) : plume ne sait pas si les sauvegardes \
                 quittent ce disque ; si elles y restent, perdre le disque perd la base ET ses sauvegardes"),
            Etat::Refusee(r) => format!(
                "attestation de copie hors site REFUSÉE : {} — ce n'est PAS « jamais copiée », l'âge de la \
                 dernière copie n'est pas établi", r.phrase()),
            Etat::Fraiche { attestation, age_s } => format!(
                "dernière copie hors site il y a {} ({})", duree_lisible(*age_s), attestation.archive),
            Etat::Perimee { attestation, age_s } => format!(
                "dernière copie hors site il y a {} ({}) — au-delà de l'âge maximal ({REGLAGE_AGE_MAX_HEURES})",
                duree_lisible(*age_s), attestation.archive),
        }
    }
}

/// LECTURE DE LA LIGNE, EN FONCTION PURE : le texte déjà lu -> une attestation bien formée ou un
/// refus nommé. Une seule ligne, un `\n` final admis, trois champs séparés par UNE espace.
pub(crate) fn lire_la_ligne(texte: &str) -> Result<Attestation, Refus> {
    let ligne = texte.strip_suffix('\n').unwrap_or(texte);
    if ligne.contains('\n') || ligne.contains('\r') {
        return Err(Refus::LigneHorsForme);
    }
    let champs: Vec<&str> = ligne.split(' ').collect();
    if champs.len() != 3 {
        return Err(Refus::LigneHorsForme);
    }
    let (ts_brut, archive, sha) = (champs[0], champs[1], champs[2]);
    if !ts_brut.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refus::HorodatageHorsForme);
    }
    let ts = ts_brut.parse::<i64>().map_err(|_| Refus::HorodatageHorsForme)?;
    let nom_bien_forme = archive
        .strip_prefix(PREFIXE_ARCHIVE)
        .and_then(|r| r.strip_suffix(SUFFIXE_ARCHIVE))
        .and_then(crate::backup::parse_backup_ts)
        .is_some();
    if !nom_bien_forme {
        return Err(Refus::NomDArchiveHorsForme);
    }
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Refus::EmpreinteHorsForme);
    }
    Ok(Attestation { ts, archive: archive.to_string(), sha256: sha.to_string() })
}

/// LECTURE DU FICHIER, BORNÉE. `stat` d'abord (sans descripteur) : absent, pas un fichier ordinaire,
/// trop grand -> refus SANS ouvrir. Puis ouverture sans attente et lecture d'au plus la borne + 1.
pub(crate) fn lire_le_fichier(chemin: &std::path::Path) -> Result<String, Refus> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let illisible = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::NotFound => Refus::AttestationAbsente,
        _ => Refus::AttestationIllisible { errno: e.raw_os_error() },
    };
    let md = std::fs::metadata(chemin).map_err(illisible)?;
    if !md.is_file() {
        return Err(Refus::AttestationPasUnFichier);
    }
    if md.len() > TAILLE_MAX_OCTETS {
        return Err(Refus::AttestationTropGrande { octets: md.len() });
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(chemin)
        .map_err(illisible)?;
    let mut octets = Vec::new();
    f.take(TAILLE_MAX_OCTETS + 1).read_to_end(&mut octets).map_err(illisible)?;
    // HORS D'ATTEINTE PAR UN TÉMOIN DÉTERMINISTE : le fichier a grandi entre le `stat` ci-dessus et
    // la lecture (tout fichier déjà trop grand est refusé par le `stat`, quelques lignes plus haut).
    // La borne reste un fait borné : `octets` dit « au moins la borne + 1 ».
    if octets.len() as u64 > TAILLE_MAX_OCTETS {
        return Err(Refus::AttestationTropGrande { octets: octets.len() as u64 });
    }
    String::from_utf8(octets).map_err(|_| Refus::LigneHorsForme)
}

/// L'ÉTAT, EN FONCTION PURE des réglages déjà lus, de la lecture faite et de l'horloge injectée.
/// Ordre : réglage d'âge illisible, suivi désactivé, non déclarée, refus de lecture, futur, âge.
pub(crate) fn etat_selon(
    age_max_s: Result<i64, Refus>,
    lecture: Option<Result<String, Refus>>,
    now_ts: i64,
) -> Etat {
    let age_max_s = match age_max_s {
        Ok(a) => a,
        Err(r) => return Etat::Refusee(r),
    };
    if age_max_s == 0 {
        return Etat::NonSuivi;
    }
    let Some(lecture) = lecture else { return Etat::NonDeclaree };
    let attestation = match lecture.and_then(|t| lire_la_ligne(&t)) {
        Ok(a) => a,
        Err(r) => return Etat::Refusee(r),
    };
    if attestation.ts > now_ts + TOLERANCE_HORLOGE_S {
        return Etat::Refusee(Refus::DateeDansLeFutur { avance_s: attestation.ts - now_ts });
    }
    // Dans la tolérance d'horloge, une avance donne un âge borné à 0, jamais négatif.
    let age_s = (now_ts - attestation.ts).max(0);
    if age_s > age_max_s {
        Etat::Perimee { attestation, age_s }
    } else {
        Etat::Fraiche { attestation, age_s }
    }
}

/// Âge maximal configuré, en SECONDES : vide -> défaut ; entier >= 0 -> lui ; sinon refus nommé.
fn age_max_s_selon(conf: &HashMap<String, String>) -> Result<i64, Refus> {
    let brut = cfg(conf, REGLAGE_AGE_MAX_HEURES, "");
    let brut = brut.trim();
    if brut.is_empty() {
        return Ok(AGE_MAX_HEURES_DEFAUT * 3600);
    }
    match brut.parse::<i64>() {
        Ok(h) if h >= 0 => h.checked_mul(3600).ok_or(Refus::ReglageAgeIllisible),
        _ => Err(Refus::ReglageAgeIllisible),
    }
}

/// L'ÉTAT, lu par la voie unique `env > fichier PLUME_CONFIG > défaut` (la même que les autres
/// réglages). Le fichier d'attestation est lu dès qu'un chemin est déclaré.
pub(crate) fn etat(conf: &HashMap<String, String>, now_ts: i64) -> Etat {
    let chemin = cfg(conf, REGLAGE_ATTESTATION, "");
    let chemin = chemin.trim();
    let lecture = if chemin.is_empty() { None } else { Some(lire_le_fichier(std::path::Path::new(chemin))) };
    etat_selon(age_max_s_selon(conf), lecture, now_ts)
}

/// LE COMPOSANT DE SANTÉ, tel qu'il apparaît dans `/api/system/health`, `plume_component_up` et le
/// bundle de diagnostic. Les jauges `plume_offsite_copy_*` en sont DÉRIVÉES dans `metrics.rs`.
pub(crate) fn composant(now_ts: i64) -> Value {
    let conf = load_config();
    let e = etat(&conf, now_ts);
    let a = e.attestation();
    json!({
        "component": COMPOSANT,
        "state": e.sante(),
        "detail": e.detail(),
        "copy_state": e.mot(),
        "refusal": match &e { Etat::Refusee(r) => Some(r.mot()), _ => None },
        // `null` (et non false) tant que rien n'est établi.
        "overdue": e.en_retard(),
        "age_s": e.age_s(),
        "last_copy_ts": a.map(|x| x.ts),
        "archive": a.map(|x| x.archive.clone()),
        "sha256": a.map(|x| x.sha256.clone()),
        "max_age_s": age_max_s_selon(&conf).ok(),
    })
}
