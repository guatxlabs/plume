//! P10.32-l — UNE ECOUTE RESEAU SANS LISTE D'AUTORISATION NE DEMARRE PAS.
//!
//! Le recepteur ecoute par defaut `0.0.0.0:514`, et une `PLUME_SYSLOG_ALLOW` vide valait « accepte
//! tout », avec un simple avertissement : tout hote du reseau injectait des evenements que l'agent
//! expedie sous sa propre identite. Ces temoins executent le BINAIRE livre (pas une copie de sa
//! logique) : refus hors de la boucle locale, code non nul et message qui dit quoi poser ; demarrage
//! en boucle locale ; demarrage quand une liste — meme ouverte a tous, mais ECRITE — est posee.
//!
//! Le demarrage se constate par une propriete d'ORDRE, pas par une duree : la ligne de configuration
//! (`collector-syslog: parser=…`) n'est ecrite qu'APRES la porte. Le delai d'attente borne seulement
//! un binaire qui ne repondrait plus ; il ne juge rien.
//!
//! Une ecoute posee VIDE coupe son transport (`env_ecoute`) : c'est ce qui permet de jouer la porte sur
//! UN transport seul. Lue comme non posee, elle retombait sur `0.0.0.0:514`, et l'autre transport, resté
//! ouvert, suffisait a faire refuser — la porte n'etait alors jamais jugee sur le transport voulu.

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-syslog");
const ATTENTE_MAX: Duration = Duration::from_secs(60);

fn lancer(spool: &std::path::Path, udp: &str, tcp: &str, allow: Option<&str>) -> Child {
    let mut c = Command::new(BINAIRE);
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.env("PLUME_SPOOL", spool)
        .env("PLUME_HOST", "hote-de-temoin")
        .env("PLUME_SYSLOG_UDP", udp)
        .env("PLUME_SYSLOG_TCP", tcp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(a) = allow {
        c.env("PLUME_SYSLOG_ALLOW", a);
    }
    c.spawn().expect("le binaire du recepteur se lance")
}

/// Les lignes de la sortie d'erreur, lues par un fil a part (le binaire qui demarre ne rend pas la main).
fn lignes(enfant: &mut Child) -> mpsc::Receiver<String> {
    let err = enfant.stderr.take().expect("stderr capture");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for l in BufReader::new(err).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    rx
}

/// Le statut d'un processus dont la sortie d'erreur est close. Le noyau ferme les descripteurs AVANT de
/// rendre le processus attendable : un `try_wait` immediat peut encore rendre `None`. On attend donc,
/// borne ; ne pas l'obtenir dans la borne, c'est un processus qui vit encore.
fn statut_borne(enfant: &mut Child) -> Option<std::process::ExitStatus> {
    let fin = Instant::now() + ATTENTE_MAX;
    loop {
        if let Some(s) = enfant.try_wait().expect("statut lisible") {
            return Some(s);
        }
        if Instant::now() >= fin {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Le refus : le processus sort d'office, code 2, et le message nomme les variables a poser ET les
/// ecoutes qui l'ont cause (`hors_boucle`, tel que le refus les ecrit : `udp=0.0.0.0:0`).
fn juger_le_refus(udp: &str, tcp: &str, hors_boucle: &str) {
    let tmp = tmp_possede::TmpPossede::neuf("syslog-sans-liste");
    let mut enfant = lancer(&tmp, udp, tcp, None);
    let rx = lignes(&mut enfant);
    let mut texte = String::new();
    let mut demarre = false;
    while let Ok(l) = rx.recv_timeout(ATTENTE_MAX) {
        texte.push_str(&l);
        texte.push('\n');
        // La ligne de configuration n'est ecrite qu'APRES la porte : la voir, c'est avoir demarre (et
        // c'est la seule preuve d'ordre que ce temoin tient : une configuration ecrite AVANT un refus
        // ferait aussi rougir ici, puisque la lecture s'arrete a elle).
        if l.starts_with("collector-syslog: parser=") {
            demarre = true;
            break;
        }
    }
    let statut = if demarre { None } else { statut_borne(&mut enfant) };
    let statut = match statut {
        Some(s) => s,
        None => {
            let _ = enfant.kill();
            let _ = enfant.wait();
            panic!("udp={udp:?} tcp={tcp:?}, liste vide : le recepteur a DEMARRE (configuration ecrite, ou processus \
                vivant) au lieu de refuser\n{texte}");
        }
    };
    assert_eq!(statut.code(), Some(2), "udp={udp:?} tcp={tcp:?} : code {statut:?} au lieu de 2\n{texte}");
    assert!(texte.contains("ARRET. PLUME_SYSLOG_ALLOW est vide"), "le refus ne dit pas sa cause :\n{texte}");
    assert!(
        texte.contains(&format!("boucle locale ({hors_boucle})")),
        "udp={udp:?} tcp={tcp:?} : le refus ne nomme pas exactement `{hors_boucle}` :\n{texte}"
    );
    assert!(
        texte.contains("PLUME_SYSLOG_ALLOW=<CIDR") && texte.contains("PLUME_SYSLOG_ALLOW=0.0.0.0/0,::/0"),
        "le refus ne dit pas quoi poser :\n{texte}"
    );
}

/// Le demarrage : la ligne de configuration, ecrite apres la porte, arrive ; le processus vit encore.
fn juger_le_demarrage(udp: &str, tcp: &str, allow: Option<&str>) -> String {
    let tmp = tmp_possede::TmpPossede::neuf("syslog-demarre");
    let mut enfant = lancer(&tmp, udp, tcp, allow);
    let rx = lignes(&mut enfant);
    let mut texte = String::new();
    let mut vue = None;
    while let Ok(l) = rx.recv_timeout(ATTENTE_MAX) {
        texte.push_str(&l);
        texte.push('\n');
        if l.starts_with("collector-syslog: parser=") {
            vue = Some(l);
            break;
        }
    }
    let encore_vivant = enfant.try_wait().expect("statut lisible").is_none();
    let _ = enfant.kill();
    let _ = enfant.wait();
    let ligne = vue.unwrap_or_else(|| {
        panic!("udp={udp:?} tcp={tcp:?} allow={allow:?} : le recepteur n'a pas passe la porte\n{texte}")
    });
    // La ligne de configuration precede les liaisons : un processus deja sorti ici serait sorti par la
    // porte (code 2), jamais par un bind.
    if !encore_vivant {
        panic!("udp={udp:?} tcp={tcp:?} allow={allow:?} : le processus est sorti juste apres la porte\n{texte}");
    }
    ligne
}

#[test]
fn une_ecoute_reseau_sans_liste_d_autorisation_refuse_de_demarrer() {
    // Toutes les interfaces IPv4, en UDP seul, en TCP seul (l'autre transport COUPE), et IPv6.
    juger_le_refus("0.0.0.0:0", "", "udp=0.0.0.0:0");
    juger_le_refus("", "0.0.0.0:0", "tcp=0.0.0.0:0");
    juger_le_refus("[::]:0", "", "udp=[::]:0");
    // Une seule ecoute hors de la boucle locale suffit : l'autre, locale, ne la couvre pas, dans les deux
    // sens.
    juger_le_refus("127.0.0.1:0", "0.0.0.0:0", "tcp=0.0.0.0:0");
    juger_le_refus("0.0.0.0:0", "127.0.0.1:0", "udp=0.0.0.0:0");
    // Une adresse que le resolveur ne rend pas n'est pas prouvee locale : le doute ferme la porte
    // (`.invalid` est reserve, RFC 2606 : il ne se resout nulle part).
    juger_le_refus("nom-inexistant.invalid:0", "", "udp=nom-inexistant.invalid:0");
}

#[test]
fn une_ecoute_videe_coupe_son_transport() {
    // TCP vide : coupe, pas `0.0.0.0:514`. La boucle locale seule demarre sans liste.
    let l = juger_le_demarrage("127.0.0.1:0", "", None);
    assert!(l.contains(" tcp=off "), "TCP vide n'est pas coupe : {l}");
    let l = juger_le_demarrage("", "127.0.0.1:0", None);
    assert!(l.contains(" udp=off "), "UDP vide n'est pas coupe : {l}");
}

#[test]
fn une_ecoute_en_boucle_locale_sans_liste_d_autorisation_demarre() {
    let l = juger_le_demarrage("127.0.0.1:0", "127.0.0.1:0", None);
    assert!(l.contains("allow=ANY"), "la configuration ne dit pas que toute source locale est acceptee : {l}");
}

#[test]
fn une_liste_d_autorisation_ecrite_ouvre_le_reseau() {
    let l = juger_le_demarrage("0.0.0.0:0", "", Some("192.0.2.10/32"));
    assert!(l.contains("allow=1 cidr"), "{l}");
    // Ouvrir a tous reste possible, mais ECRIT.
    let l = juger_le_demarrage("0.0.0.0:0", "0.0.0.0:0", Some("0.0.0.0/0,::/0"));
    assert!(l.contains("allow=2 cidr"), "{l}");
}
