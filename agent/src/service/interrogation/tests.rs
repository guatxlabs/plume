//! LES DEUX SENS, ET LE SECOND EST LE CŒUR.
//!
//! ① L'interrogation ÉCHOUE -> verdict d'échec NOMMÉ, et AUCUNE conclusion sur l'état du service.
//! ② Elle RÉUSSIT et rapporte un service réellement sain -> le verdict normal, sans réserve.
//!
//! Sans ②, une fonction qui rendrait toujours « je ne sais pas » passerait ① sans rien prouver, et
//! ferait disparaître le cas nominal — un service réellement actif, une unité réellement absente.
//!
//! INDÉPENDANTS DE LA MACHINE : rien ici ne lance de commande ni ne parle à un gestionnaire de
//! services. Les trois valeurs qu'une commande rend (code de retour, sortie standard, erreur
//! standard) sont FABRIQUÉES, d'après ce qui a été mesuré le 2026-08-21 sur systemd 261. Les tests
//! tournent donc à l'identique sur les trois OS d'intégration continue, dont deux n'ont pas de
//! systemd, et sur un hôte où l'agent est installé comme sur un hôte où il ne l'est pas.

use super::*;
use crate::lisibilite::{
    CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ABSENTE, CAUSE_SOURCE_ILLISIBLE, CAUSE_SOURCE_REFUSEE,
    VERDICT_ILLISIBLE, VERDICT_LU,
};

/// Le vocabulaire d'exercice — deux mots vrais, deux faux : une table dégénérée (tout faux) rendrait
/// vert un classificateur qui ne lirait rien.
const MOTS: [(&str, bool); 4] =
    [("active", true), ("reloading", true), ("inactive", false), ("failed", false)];

// =================================================================================================
// ② LE TÉMOIN POSITIF — CE QUE LA LECTURE DOIT CONTINUER DE RENDRE
// =================================================================================================

/// UN SERVICE RÉELLEMENT SAIN REND LE VERDICT NORMAL. C'est la moitié sans laquelle tout le reste ne
/// prouverait rien.
#[test]
fn un_service_sain_rend_le_verdict_normal() {
    let l = verdict_de_mot("systemctl is-active", Some(0), b"active\n", b"", &MOTS);
    assert_eq!(l.verdict(), VERDICT_LU);
    assert_eq!(l.valeur(), Some(&("active", true)));
    assert!(l.detail().is_none(), "une lecture qui a abouti n'a rien à avouer");
}

/// UN CODE DE RETOUR NON NUL N'EST PAS UN ÉCHEC DE LECTURE. Mesuré le 2026-08-21 (systemd 261) : sur
/// une unité ABSENTE, `is-active` sort 4 en disant `inactive`. C'est une MESURE — et le retrait doit
/// pouvoir conclure « rien à retirer » dessus, sinon la correction troquerait un mensonge rassurant
/// contre un « je ne sais jamais rien » qui rendrait la commande inutilisable.
#[test]
fn un_code_non_nul_avec_un_mot_reste_une_mesure() {
    for (code, mot, attendu) in
        [(Some(4), "inactive", false), (Some(3), "inactive", false), (Some(0), "active", true)]
    {
        let l = verdict_de_mot("systemctl is-active", code, mot.as_bytes(), b"", &MOTS);
        assert_eq!(l.verdict(), VERDICT_LU, "code {code:?} + mot {mot:?} = une réponse");
        assert_eq!(oui_non(l).valeur(), Some(&attendu));
    }
}

/// LES PROPRIÉTÉS D'UNE UNITÉ RÉELLEMENT SAINE SONT LUES, avec la forme exacte que rend l'outil
/// (`KEY=VALUE` par ligne, ordre non supposé, valeur éventuellement vide).
#[test]
fn des_proprietes_completes_sont_lues() {
    let sortie = b"NRestarts=3\nActiveState=active\nSubState=running\nExecMainStatus=0\nResult=success\n";
    let l = proprietes(
        "systemctl show",
        Some(0),
        sortie,
        b"",
        &["ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts"],
    );
    let t = l.valeur().expect("une sortie complète se lit");
    assert_eq!(t.get("ActiveState").map(String::as_str), Some("active"));
    assert_eq!(t.get("NRestarts").map(String::as_str), Some("3"));
}

/// UNE VALEUR VIDE N'EST PAS UNE PROPRIÉTÉ ABSENTE. Mesuré le 2026-08-21 (systemd 261) : sur une
/// unité absente, `show` sort **0** et imprime `UnitFileState=` — la clé est là, sa valeur est vide,
/// et c'est une mesure. La confondre avec une clé manquante ferait échouer la lecture sur le cas le
/// plus banal qui soit : l'agent n'est pas installé.
#[test]
fn une_valeur_vide_reste_une_mesure() {
    let sortie = b"LoadState=not-found\nActiveState=inactive\nUnitFileState=\n";
    let l = proprietes("systemctl show", Some(0), sortie, b"", &["UnitFileState", "ActiveState"]);
    assert_eq!(l.verdict(), VERDICT_LU);
    assert_eq!(l.valeur().unwrap().get("UnitFileState").map(String::as_str), Some(""));
}

// =================================================================================================
// ① LA MUTATION — L'INTERROGATION ÉCHOUE, ET RIEN N'EST CONCLU
// =================================================================================================

/// LE DÉFAUT MESURÉ, FIGÉ. Mesuré le 2026-08-21 (systemd 261) : gestionnaire injoignable ->
/// code 1, SORTIE STANDARD VIDE, motif sur l'erreur standard. L'ancienne forme en faisait `false`,
/// c'est-à-dire « le service n'est pas actif » — le mot qu'aurait rendu une mesure réussie sur un
/// service arrêté. Le verdict doit désormais être NOMMÉ, et la valeur ABSENTE.
#[test]
fn une_interrogation_sans_reponse_ne_conclut_rien() {
    let l = verdict_de_mot(
        "systemctl is-active",
        Some(1),
        b"",
        b"Failed to connect to system scope bus via local transport: No such file or directory\n",
        &MOTS,
    );
    assert_eq!(l.verdict(), VERDICT_ILLISIBLE);
    assert_eq!(l.cause(), CAUSE_SOURCE_ILLISIBLE);
    assert_eq!(l.valeur(), None, "aucune valeur : c'est ce qui empêche l'appelant de conclure");
    let dit = l.detail().unwrap();
    assert!(dit.contains("Failed to connect"), "l'aveu porte le motif rendu par l'outil : {dit}");
    assert!(dit.contains("systemctl is-active"), "l'aveu nomme l'interrogation : {dit}");
}

/// UN MOT HORS VOCABULAIRE NE VAUT PAS « AU REPOS ». Sans cette branche, un état ajouté demain par un
/// gestionnaire se lirait « ce n'est pas `active`, donc c'est arrêté » — le défaut reconstruit un cran
/// plus bas, et cette fois sans même une erreur pour le trahir.
#[test]
fn un_mot_hors_vocabulaire_est_avoue() {
    let l = verdict_de_mot("systemctl is-active", Some(0), b"quiescing\n", b"", &MOTS);
    assert_eq!(l.cause(), CAUSE_FORME_INCONNUE);
    assert_eq!(l.valeur(), None);
    assert!(l.detail().unwrap().contains("quiescing"), "l'aveu cite le mot non compris");
}

/// LA COMMANDE QUI NE SE LANCE PAS PORTE LE MOT DU DÉMON, et il DISTINGUE l'absence du refus : la
/// première se répare en installant l'outil, la seconde en corrigeant des droits ou un confinement.
#[test]
fn une_commande_non_lancee_distingue_absence_et_refus() {
    use std::io::{Error, ErrorKind};
    let absente: Lecture<(&str, bool)> =
        pas_lance("systemctl is-active", &Error::new(ErrorKind::NotFound, "no such file"));
    assert_eq!(absente.cause(), CAUSE_SOURCE_ABSENTE);
    let refusee: Lecture<(&str, bool)> =
        pas_lance("systemctl is-active", &Error::new(ErrorKind::PermissionDenied, "denied"));
    assert_eq!(refusee.cause(), CAUSE_SOURCE_REFUSEE);
    for l in [absente, refusee] {
        assert_eq!(l.verdict(), VERDICT_ILLISIBLE);
        assert_eq!(l.valeur(), None);
    }
}

/// LE SITE CITÉ PAR LA CAMPAGNE : l'interrogation de propriétés en échec ne doit plus valoir « pas en
/// échec ». L'ancienne forme rendait une TABLE VIDE ; l'appelant en tirait `ActiveState=""`, et son
/// prédicat — qui cherche `failed` ou `auto-restart` — ne pouvait plus tirer. Un service en boucle de
/// redémarrage passait donc pour sain.
#[test]
fn des_proprietes_sans_reponse_ne_valent_pas_pas_en_echec() {
    let l = proprietes(
        "systemctl show",
        Some(1),
        b"",
        b"Failed to connect to system scope bus via local transport: No such file or directory\n",
        &["ActiveState"],
    );
    assert_eq!(l.cause(), CAUSE_SOURCE_ILLISIBLE);
    assert_eq!(l.valeur(), None, "une table vide se lisait « rien à signaler » : il n'y en a plus");
    assert!(l.detail().unwrap().contains("Failed to connect"));
}

/// UNE CLÉ DEMANDÉE ET ABSENTE EST AVOUÉE, et l'aveu la NOMME — c'est ce qui empêche de reconstruire
/// le défaut sous la forme d'un `unwrap_or("")` chez l'appelant.
#[test]
fn une_propriete_demandee_et_absente_est_avouee() {
    let l = proprietes(
        "systemctl show",
        Some(0),
        b"ActiveState=active\nSubState=running\n",
        b"",
        &["ActiveState", "SubState", "NRestarts"],
    );
    assert_eq!(l.cause(), CAUSE_FORME_INCONNUE);
    assert_eq!(l.valeur(), None);
    assert!(l.detail().unwrap().contains("NRestarts"), "l'aveu nomme la propriété manquante");
}

/// LA PROPRIÉTÉ D'ENSEMBLE, DANS LES DEUX SENS D'UN COUP : le verdict d'une interrogation qui n'a pas
/// abouti n'est JAMAIS celui d'une interrogation qui a abouti. C'est cette inégalité — et non le
/// détail des messages — qui rend le défaut non-écrivable.
#[test]
fn le_verdict_de_l_echec_n_est_jamais_celui_du_succes() {
    let sains = [
        verdict_de_mot("i", Some(0), b"active", b"", &MOTS),
        verdict_de_mot("i", Some(3), b"inactive", b"", &MOTS),
    ];
    let rates = [
        verdict_de_mot("i", Some(1), b"", b"bus injoignable", &MOTS),
        verdict_de_mot("i", Some(0), b"mot-inconnu", b"", &MOTS),
        pas_lance("i", &std::io::Error::new(std::io::ErrorKind::NotFound, "x")),
    ];
    for s in &sains {
        assert!(s.est_lue());
        for r in &rates {
            assert_ne!(s.verdict(), r.verdict(), "un échec de lecture ne peut pas porter le verdict d'une lecture");
        }
    }
    for r in &rates {
        assert!(!r.est_lue());
        assert!(r.detail().is_some(), "un aveu sans détail n'avoue rien d'exploitable");
    }
}
