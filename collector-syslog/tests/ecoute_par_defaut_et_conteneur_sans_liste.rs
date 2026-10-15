//! P10.32-l — LE CAS PAR DEFAUT, ET LE CONTENEUR : AUCUNE ECOUTE POSEE, AUCUNE LISTE, PAS DE DEMARRAGE.
//!
//! Les autres temoins de la porte posent toujours `PLUME_SYSLOG_UDP` et `PLUME_SYSLOG_TCP` : aucun ne
//! jouait le cas que l'exploitant rencontre le premier, le binaire lance sans rien (`0.0.0.0:514` sur les
//! deux transports, liste vide) — c'est aussi le cas de l'image `runtime` du Dockerfile, ou l'ecoute est
//! forcement hors de la boucle locale du conteneur. Ces temoins executent le BINAIRE livre : refus,
//! code 2, les deux ecoutes par defaut nommees, et le message dit au conteneur quoi poser.
//!
//! Aucun port n'est lie : la porte refuse AVANT toute liaison. Un binaire qui passerait la porte serait
//! vu par la ligne de configuration (ecrite apres elle) ou par un code autre que 2 (`:514` refuse a un
//! utilisateur non privilegie, « aucun listener actif », code 1).

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-syslog");
const ATTENTE_MAX: Duration = Duration::from_secs(60);

/// Le binaire lance SANS aucune variable `PLUME_` hors du spool et de l'identite : (code, sortie d'erreur).
fn lancer_sans_ecoute_posee() -> (Option<i32>, String) {
    let tmp = tmp_possede::TmpPossede::neuf("syslog-defaut");
    let mut c = Command::new(BINAIRE);
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.env("PLUME_SPOOL", &*tmp)
        .env("PLUME_HOST", "hote-de-temoin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut enfant = c.spawn().expect("le binaire du recepteur se lance");
    let err = enfant.stderr.take().expect("stderr capture");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for l in BufReader::new(err).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    let mut texte = String::new();
    while let Ok(l) = rx.recv_timeout(ATTENTE_MAX) {
        texte.push_str(&l);
        texte.push('\n');
        if l.starts_with("collector-syslog: parser=") {
            let _ = enfant.kill();
            let _ = enfant.wait();
            panic!("sans ecoute posee ni liste, le recepteur a passe la porte :\n{texte}");
        }
    }
    let fin = Instant::now() + ATTENTE_MAX;
    loop {
        if let Some(s) = enfant.try_wait().expect("statut lisible") {
            return (s.code(), texte);
        }
        if Instant::now() >= fin {
            let _ = enfant.kill();
            let _ = enfant.wait();
            panic!("sans ecoute posee ni liste, le recepteur vit encore :\n{texte}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sans_ecoute_posee_ni_liste_le_recepteur_refuse_sur_les_deux_ecoutes_par_defaut() {
    let (code, texte) = lancer_sans_ecoute_posee();
    assert_eq!(code, Some(2), "code {code:?} au lieu de 2 :\n{texte}");
    assert!(texte.contains("ARRET. PLUME_SYSLOG_ALLOW est vide"), "le refus ne dit pas sa cause :\n{texte}");
    assert!(
        texte.contains("boucle locale (udp=0.0.0.0:514, tcp=0.0.0.0:514)"),
        "le refus ne nomme pas les deux ecoutes par defaut :\n{texte}"
    );
}

#[test]
fn le_refus_dit_au_conteneur_quoi_poser() {
    let (code, texte) = lancer_sans_ecoute_posee();
    assert_eq!(code, Some(2), "{texte}");
    assert!(
        texte.contains("en conteneur (Docker, k3s)")
            && texte.contains("PLUME_SYSLOG_ALLOW avec les IP des emetteurs TELLES QUE LE CONTENEUR LES VOIT")
            && texte.contains("restreins la publication du port cote hote")
            && texte.contains("deploy/SYSLOG.md, section \"Conteneur\""),
        "le refus ne dit pas au conteneur quoi poser :\n{texte}"
    );
}
