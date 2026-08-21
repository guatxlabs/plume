// `S36` — LA FORME ELLE-MÊME, EXERCÉE DANS LES DEUX SENS.
//
// CE QUE CES TESTS PROUVENT, ET POURQUOI IL EN FAUT DEUX POUR CHAQUE PROPRIÉTÉ.
//   ① SENS « ILLISIBLE » — une source retirée doit produire le verdict `illisible`, une cause NOMMÉE,
//      et AUCUNE valeur. C'est le défaut d'origine : un nom d'hôte plausible et un lot vide.
//   ② SENS « LU, VALEUR VIDE » — une source PRÉSENTE dont la valeur est réellement vide doit produire
//      le verdict `lu` et la valeur vide. Sans ce second témoin, une version qui rendrait TOUJOURS
//      « illisible » passerait le premier sans rien prouver — et elle serait le défaut symétrique,
//      exactement aussi grave : elle ferait disparaître le cas nominal (un hôte calme, une source
//      réellement sans nouveauté).
//
// CE QUI REND CES TESTS INDÉPENDANTS DE LA MACHINE QUI LES EXÉCUTE : aucune fonction exercée ici ne
// nomme un chemin système ni ne lit une variable réelle — le fichier et les variables arrivent en
// paramètre, et les arborescences sont fabriquées dans un temporaire POSSÉDÉ. Le même verdict tombe
// donc sur un hôte Linux, sur un hôte sans `/proc`, et dans un conteneur.

use super::*;

/// Un répertoire temporaire POSSÉDÉ (créé, puis retiré à la destruction) : aucune lecture de la
/// machine de test n'entre dans un verdict.
pub struct TmpPossede(std::path::PathBuf);

impl TmpPossede {
    pub fn neuf(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("plume-s36-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temporaire possédé");
        Self(d)
    }
    pub fn join(&self, p: &str) -> std::path::PathBuf {
        self.0.join(p)
    }
}

impl Drop for TmpPossede {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// =================================================================================================
// L'IDENTITÉ DE L'HÔTE — LA PAIRE
// =================================================================================================

/// ② LE CAS NOMINAL D'ABORD : un fichier présent et renseigné est LU, et sa valeur est publiée.
#[test]
fn une_identite_lisible_est_lue_et_sa_valeur_publiee() {
    let tmp = TmpPossede::neuf("identite-lue");
    let f = tmp.join("hostname");
    std::fs::write(&f, "poste-de-mesure\n").unwrap();
    let v = identite_hote_depuis(Some(&f), &[]);
    assert_eq!(v.verdict(), VERDICT_LU);
    assert_eq!(v.cause(), CAUSE_AUCUNE);
    assert_eq!(v.valeur().map(String::as_str), Some("poste-de-mesure"), "les blancs sont retirés");
    assert!(v.detail().is_none());
}

/// ① La source n'est pas là et aucune variable ne la remplace : verdict d'échec, cause NOMMÉE, et
/// AUCUN nom. L'ancienne forme rendait `unknown` — un nom plausible, indiscernable d'une lecture
/// réussie, sur lequel TOUTES les machines en échec se confondaient.
#[test]
fn une_identite_illisible_ne_rend_aucun_nom() {
    let tmp = TmpPossede::neuf("identite-absente");
    let jamais = tmp.join("pas-de-fichier-ici");
    let v = identite_hote_depuis(Some(&jamais), &[None, Some("   ")]);
    assert_eq!(v.verdict(), VERDICT_ILLISIBLE);
    assert_eq!(v.cause(), CAUSE_SOURCE_ABSENTE);
    assert!(v.valeur().is_none(), "aucun nom ne doit sortir d'une source absente : {v:?}");
    assert!(v.detail().unwrap().contains("pas-de-fichier-ici"), "l'aveu porte le chemin tenté");
}

/// ① bis — UN FICHIER PRÉSENT MAIS VIDE N'EST PAS UNE IDENTITÉ, et ce n'est pas non plus une absence.
/// La distinction n'est pas cosmétique : l'un se répare en écrivant le fichier, l'autre en le créant.
#[test]
fn une_identite_vide_est_de_forme_inconnue_pas_absente() {
    let tmp = TmpPossede::neuf("identite-vide");
    let f = tmp.join("hostname");
    std::fs::write(&f, "  \n").unwrap();
    let v = identite_hote_depuis(Some(&f), &[]);
    assert_eq!(v.cause(), CAUSE_FORME_INCONNUE);
    assert!(v.valeur().is_none());
}

/// La PRÉCÉDENCE est celle d'avant, à la lettre : fichier d'abord, variables ensuite, dans l'ordre.
#[test]
fn la_variable_prend_le_relais_du_fichier_mais_jamais_l_inverse() {
    let tmp = TmpPossede::neuf("identite-precedence");
    let f = tmp.join("hostname");
    // fichier vide -> la variable prend le relais
    std::fs::write(&f, "").unwrap();
    let v = identite_hote_depuis(Some(&f), &[Some("depuis-variable")]);
    assert_eq!(v.valeur().map(String::as_str), Some("depuis-variable"));
    // fichier renseigné -> il gagne
    std::fs::write(&f, "depuis-fichier").unwrap();
    let v = identite_hote_depuis(Some(&f), &[Some("depuis-variable")]);
    assert_eq!(v.valeur().map(String::as_str), Some("depuis-fichier"));
    // ordre des variables respecté
    let v = identite_hote_depuis(None, &[None, Some("deuxieme")]);
    assert_eq!(v.valeur().map(String::as_str), Some("deuxieme"));
}

/// AUCUNE SOURCE D'IDENTITÉ DU TOUT (plateforme sans fichier de nom d'hôte, aucune variable) : c'est
/// une absence de source, pas une forme inconnue — et surtout pas un nom.
#[test]
fn aucune_source_d_identite_est_une_absence_nommee() {
    let v = identite_hote_depuis(None, &[None, None]);
    assert_eq!(v.cause(), CAUSE_SOURCE_ABSENTE);
    assert!(v.valeur().is_none());
}

// =================================================================================================
// LE RELEVÉ — CE QUI SÉPARE « CALME » DE « AVEUGLE »
// =================================================================================================

fn rec(x: &str) -> crate::source::NativeRecord {
    crate::source::NativeRecord { raw: x.to_string(), cursor: None }
}

/// ② UNE SOURCE RÉELLEMENT SANS NOUVEAUTÉ EST `lu`, AVEC ZÉRO ENREGISTREMENT. C'est le cas nominal
/// d'un hôte calme : sans ce témoin, un lecteur qui crierait « illisible » en permanence passerait le
/// témoin ① sans rien prouver, et noierait le SOC sous des aveux faux.
#[test]
fn un_lot_vide_mais_lu_reste_lu() {
    let r = Releve::lu(Vec::new());
    assert_eq!(r.lisibilite.verdict(), VERDICT_LU);
    assert_eq!(r.lisibilite.cause(), CAUSE_AUCUNE);
    assert!(r.records.is_empty());
    // et la cadence non échue n'est pas davantage un échec : la source n'a pas été interrogée.
    assert_eq!(Releve::rien_a_faire().lisibilite.verdict(), VERDICT_LU);
}

/// ① UNE SOURCE ILLISIBLE NE REND AUCUN ENREGISTREMENT, ET LE DIT.
#[test]
fn un_lot_illisible_porte_sa_cause_et_aucun_enregistrement() {
    let r = Releve::illisible(RAISON_DEPENDANCE_ABSENTE, CAUSE_SOURCE_ABSENTE, "journalctl introuvable");
    assert_eq!(r.lisibilite.verdict(), VERDICT_ILLISIBLE);
    assert_eq!(r.lisibilite.cause(), CAUSE_SOURCE_ABSENTE);
    assert_eq!(r.raison, RAISON_DEPENDANCE_ABSENTE, "un binaire absent est une DÉPENDANCE, pas une source");
    assert!(r.records.is_empty());
    assert!(r.lisibilite.detail().unwrap().contains("journalctl"));
}

/// UN LOT INTERROMPU EN COURS N'EST PAS UN LOT COMPLET. Ce qui a été lu part quand même — le perdre
/// serait une seconde faute — mais l'incomplétude est avouée : un lot tronqué en silence est plus
/// petit que la réalité, et pour qui compte, c'est aussi dangereux qu'un lot vide.
#[test]
fn un_lot_partiel_garde_ce_qui_a_ete_lu_et_avoue_l_interruption() {
    let r = Releve::partiel(vec![rec("a"), rec("b")], RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ILLISIBLE, "flux coupé");
    assert_eq!(r.records.len(), 2, "ce qui a été lu n'est jamais jeté");
    assert_eq!(r.lisibilite.verdict(), VERDICT_ILLISIBLE);
}

// =================================================================================================
// L'AVEU — LE CONTRAT DÉJÀ LIVRÉ, À L'IDENTIQUE
// =================================================================================================

/// L'aveu emprunte le canal de `collectors/lib.sh` MOT POUR MOT : c'est la condition pour que la règle
/// livrée (`search category=config collect_status=unavailable`) le voie sans être touchée.
#[test]
fn l_aveu_respecte_le_contrat_d_indisponibilite_deja_livre() {
    let ev = event_indisponibilite(
        "auth",
        "poste-1",
        RAISON_DEPENDANCE_ABSENTE,
        CAUSE_SOURCE_ABSENTE,
        "journalctl introuvable",
        1_700_000_000,
    );
    assert_eq!(ev.category, "config", "la règle livrée cherche category=config");
    assert_eq!(ev.severity, 2, "trou de couverture = avertissement, comme plume_unavailable");
    assert_eq!(ev.source, "auth", "imputé à LA source aveugle (c'est ce qui bascule sa pastille)");
    assert_eq!(ev.fields["collect_status"], "unavailable", "le jeton que la règle livrée cherche");
    assert_eq!(ev.fields["type"], "collector-availability");
    assert_eq!(ev.fields["reason"], RAISON_DEPENDANCE_ABSENTE, "mot GROSSIER du contrat shell");
    assert_eq!(ev.fields["cause"], CAUSE_SOURCE_ABSENTE, "mot FIN du démon, le MÊME vocabulaire");
    assert_eq!(ev.fields["verdict"], VERDICT_ILLISIBLE);
    assert!(ev.message.contains("journalctl introuvable"), "le détail reste lisible par un humain");
}

/// LA CLÉ DE DÉDOUBLONNAGE : stable dans l'heure (sinon l'aveu écrit 1440 lignes/jour), différente
/// d'une heure à l'autre (sinon l'aveu vieillit jusqu'à devenir invisible), et différente d'une cause
/// à l'autre (sinon deux trous distincts s'effacent l'un l'autre).
#[test]
fn la_cle_de_l_aveu_est_horaire_et_discrimine_les_causes() {
    let a = event_indisponibilite("s", "h", RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 3600);
    let b = event_indisponibilite("s", "h", RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 3600 + 59);
    let c = event_indisponibilite("s", "h", RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_ABSENTE, "d", 7200);
    let d = event_indisponibilite("s", "h", RAISON_SOURCE_ABSENTE, CAUSE_SOURCE_REFUSEE, "d", 3600);
    assert_eq!(a.dedup, b.dedup, "même heure, même trou -> une seule ligne");
    assert_ne!(a.dedup, c.dedup, "heure suivante -> l'aveu est RÉ-AFFIRMÉ");
    assert_ne!(a.dedup, d.dedup, "cause différente -> trou différent");
}

// =================================================================================================
// LES ENSEMBLES FERMÉS
// =================================================================================================

/// La traduction de l'erreur système a UN SEUL auteur : la garder, c'est garder tous ses appelants.
/// Les causes qui demandent une erreur qu'un test ne peut pas fabriquer de façon portable (un accès
/// refusé dépend de qui exécute la suite) sont donc exercées sur la TRADUCTION elle-même.
#[test]
fn la_traduction_de_l_erreur_systeme_couvre_les_trois_familles() {
    use std::io::{Error, ErrorKind};
    assert_eq!(cause_io(&Error::from(ErrorKind::NotFound)), CAUSE_SOURCE_ABSENTE);
    assert_eq!(cause_io(&Error::from(ErrorKind::PermissionDenied)), CAUSE_SOURCE_REFUSEE);
    assert_eq!(cause_io(&Error::from(ErrorKind::Other)), CAUSE_SOURCE_ILLISIBLE);
    assert_eq!(cause_io(&Error::from(ErrorKind::UnexpectedEof)), CAUSE_SOURCE_ILLISIBLE);
}

/// LES DEUX ENSEMBLES SONT FERMÉS ET DISJOINTS DE FORME. Le vocabulaire fin est celui du démon, mot
/// pour mot : un exploitant qui lit les deux surfaces doit reconnaître les mêmes mots. Ce test est
/// ce qui empêche un renommage discret de l'un des deux côtés.
#[test]
fn les_vocabulaires_sont_fermes_et_sont_ceux_des_surfaces_existantes() {
    // Les mots du démon (daemon/src/mesure_environnement.rs), à la lettre.
    assert_eq!(
        CAUSES,
        ["aucune", "source_absente", "source_refusee", "source_illisible", "forme_inconnue"]
    );
    assert_eq!(VERDICT_LU, "lu");
    assert_eq!(VERDICT_ILLISIBLE, "illisible");
    // Les mots du contrat shell (collectors/lib.sh), à la lettre.
    assert_eq!(
        RAISONS,
        ["missing-dependency", "missing-source", "missing-config", "subsystem-absent", "unreachable"]
    );
    // Aucun doublon : une table qui se répète ne borne rien.
    for (i, a) in CAUSES.iter().enumerate() {
        assert!(!CAUSES[i + 1..].contains(a), "cause en double : {a}");
    }
    for (i, a) in RAISONS.iter().enumerate() {
        assert!(!RAISONS[i + 1..].contains(a), "raison en double : {a}");
    }
}

/// LE NOM PUBLIÉ QUAND L'IDENTITÉ N'EST PAS LUE N'EST PAS UN NOM D'HÔTE PLAUSIBLE. C'est la propriété
/// qui distingue ce verdict de l'ancien repli : aucune machine ne peut légitimement le porter, donc
/// deux agents aveugles ne se confondent pas avec une machine réelle.
#[test]
fn le_verdict_d_identite_n_est_pas_un_nom_de_machine_plausible() {
    assert_ne!(HOTE_NON_LU, "unknown");
    assert_ne!(HOTE_NON_LU, "localhost");
    assert!(HOTE_NON_LU.contains(VERDICT_ILLISIBLE), "il porte le mot de verdict, il se cherche tel quel");
}

/// LE VOCABULAIRE EST CELUI DU DÉMON, ET IL NE PEUT PAS DÉRIVER EN SILENCE.
///
/// Ces binaires ne partagent aucune bibliothèque avec le démon — c'est voulu, l'agent s'installe seul
/// sur un poste. Le vocabulaire de causes, lui, DOIT rester commun : un exploitant qui lit une mesure
/// du démon et un aveu de cet agent doit reconnaître les mêmes mots. Cette garde lit donc le module
/// du démon et exige que chacun de ses mots y figure. Elle porte son propre plancher : si elle ne
/// peut pas lire la référence, elle ÉCHOUE au lieu de rendre vert en étant aveugle.
#[test]
fn les_mots_de_cause_sont_ceux_du_demon() {
    let reference = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("daemon")
        .join("src")
        .join("mesure_environnement.rs");
    let texte = std::fs::read_to_string(&reference).unwrap_or_else(|e| {
        panic!(
            "référence de vocabulaire illisible ({e}) — cette garde ne peut pas conclure, et ne doit \
             pas rendre vert en étant aveugle"
        )
    });
    assert!(
        texte.len() > 2000,
        "référence de vocabulaire suspecte ({} octets) : parcours cassé",
        texte.len()
    );
    for mot in CAUSES.iter().chain([&VERDICT_LU, &VERDICT_ILLISIBLE]) {
        assert!(
            texte.contains(&format!("\"{mot}\"")),
            "le mot {mot:?} n'existe plus dans le module du démon : les deux surfaces ont dérivé"
        );
    }
}
