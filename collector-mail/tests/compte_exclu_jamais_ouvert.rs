//! P10.33-m — UN COMPTE RETIRE PAR `PLUME_MAIL_EXCLURE_COMPTES` N'EST JAMAIS OUVERT.
//!
//! Ces temoins executent le BINAIRE livre contre un maildir fabrique. Chaque compte exclu porte un
//! message qui DECLENCHERAIT une alerte (URL a IP brute), sous un nom de fichier marque `EXCLU…`, et son
//! repertoire est en droits 000 : toute sonde du collecteur — `stat` de `cur/`, `read_dir`, lecture de
//! message — y echoue, et un echec d'enumeration fait echouer le passage entier. L'instrument est
//! VALIDE avant d'etre cru : le temoin verifie que la privation MORD (une execution privilegiee lit un
//! repertoire 000) et refuse sinon de conclure, plutot que de declarer « jamais ouvert » sans l'avoir vu.
//! Les voisins dont le nom est un PREFIXE ou un SUFFIXE du compte exclu (et l'inverse) restent lus.

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-mail");
const VARIABLE: &str = "PLUME_MAIL_EXCLURE_COMPTES";

/// Un message que le jeu de motifs par defaut FLAGGE (`raw-ip-url`, adresse RFC 5737).
fn message(marque: &str) -> String {
    format!(
        "From: expediteur@sender.example\r\nTo: boite@example.test\r\nSubject: note\r\n\
         Message-ID: <{marque}@sender.example>\r\nDate: Wed, 14 Oct 2026 10:00:00 +0000\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nVoir http://192.0.2.10/connexion\r\n"
    )
}

/// Pose une boite `dossier` avec un message dont le nom de fichier porte `marque`.
fn boite(dossier: &Path, marque: &str) {
    std::fs::create_dir_all(dossier.join("cur")).unwrap();
    std::fs::create_dir_all(dossier.join("new")).unwrap();
    std::fs::write(dossier.join("new").join(format!("1700000100.{marque}:2,")), message(marque)).unwrap();
}

/// Rend les droits aux repertoires prives AVANT que le temporaire possede ne s'efface — y compris sur
/// panique (declare APRES le `TmpPossede`, il est detruit AVANT lui).
struct Restaurer(Vec<PathBuf>);
impl Drop for Restaurer {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        }
    }
}

/// Prive `dossiers` de tout acces et dit si la privation MORD pour ce processus.
fn priver(dossiers: &[PathBuf]) -> (Restaurer, bool) {
    for d in dossiers {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let mord = dossiers.iter().all(|d| std::fs::read_dir(d).is_err());
    (Restaurer(dossiers.to_vec()), mord)
}

struct Passage {
    code: Option<i32>,
    stderr: String,
    /// Tout le texte depose dans le spool.
    spool: String,
    /// Les evenements `source=mail` qui ne sont pas des aveux.
    alertes: Vec<serde_json::Value>,
    aveux: Vec<serde_json::Value>,
    etat: String,
}

fn passer(tmp: &Path, racine: &Path, exclure: Option<&str>) -> Passage {
    let spool = tmp.join("spool");
    let etat = tmp.join("etat");
    let mut c = Command::new(BINAIRE);
    c.arg("scan");
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.env("PLUME_MAIL_ROOT", racine)
        .env("PLUME_MAIL_DOMAIN", "example.test")
        .env("PLUME_SPOOL", &spool)
        .env("PLUME_MAIL_STATE", &etat)
        .env("PLUME_HOST", "hote-de-temoin");
    if let Some(v) = exclure {
        c.env(VARIABLE, v);
    }
    let sortie = c.output().expect("le binaire du collecteur se lance");
    let mut p = Passage {
        code: sortie.status.code(),
        stderr: String::from_utf8_lossy(&sortie.stderr).into_owned(),
        spool: String::new(),
        alertes: Vec::new(),
        aveux: Vec::new(),
        etat: std::fs::read_to_string(&etat).unwrap_or_default(),
    };
    let mut noms: Vec<PathBuf> = match std::fs::read_dir(&spool) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    };
    noms.sort();
    for f in noms {
        let nom = f.file_name().unwrap().to_string_lossy().to_string();
        if nom.starts_with('.') || !nom.ends_with(".json") {
            continue;
        }
        let texte = std::fs::read_to_string(&f).unwrap();
        p.spool.push_str(&texte);
        let doc: serde_json::Value = serde_json::from_str(&texte).unwrap();
        for ev in doc["events"].as_array().cloned().unwrap_or_default() {
            if ev["fields"]["collect_status"] == "unavailable" {
                p.aveux.push(ev);
            } else {
                p.alertes.push(ev);
            }
        }
    }
    p
}

/// La ligne de battement du passage (`collector-mail: N compte(s) dont …`).
fn battement(p: &Passage) -> String {
    p.stderr
        .lines()
        .find(|l| l.starts_with("collector-mail: ") && l.contains(" compte(s) dont "))
        .unwrap_or_else(|| panic!("aucun battement : {}", p.stderr))
        .to_string()
}

fn comptes_alertes(p: &Passage) -> Vec<String> {
    let mut v: Vec<String> =
        p.alertes.iter().map(|e| e["fields"]["account"].as_str().unwrap_or("?").to_string()).collect();
    v.sort();
    v
}

#[test]
fn un_compte_exclu_n_est_jamais_ouvert_et_ses_voisins_de_prefixe_ou_de_suffixe_sont_lus() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-plat");
    let racine = tmp.join("maildir");
    // `alice` exclu par sa partie locale ecrite en MAJUSCULES ; `Bob` (repertoire en majuscule) exclu
    // par son adresse complete ecrite dans une autre casse.
    boite(&racine.join("alice"), "EXCLUALICE");
    boite(&racine.join("Bob"), "EXCLUBOB");
    for voisin in ["alic", "lice", "alicex", "xalice", "bo"] {
        boite(&racine.join(voisin), &format!("VOISIN{voisin}"));
    }
    let (_rendre, mord) = priver(&[racine.join("alice"), racine.join("Bob")]);
    assert!(
        mord,
        "execution privilegiee : un repertoire 000 reste lisible pour ce processus, ce temoin ne peut \
         pas prouver « jamais ouvert » — rejoue-le sans privilege"
    );

    let p = passer(&tmp, &racine, Some("ALICE, bob@EXAMPLE.test"));
    // Une seule sonde du collecteur dans un compte prive fait echouer le passage (enumeration refusee).
    assert_eq!(p.code, Some(0), "le passage a touche un compte exclu : {}", p.stderr);
    assert!(p.aveux.is_empty(), "aucun aveu attendu : {:#?}\n{}", p.aveux, p.stderr);
    assert_eq!(
        comptes_alertes(&p),
        ["alic@example.test", "alicex@example.test", "bo@example.test", "lice@example.test", "xalice@example.test"],
        "chaque voisin est lu, aucun exclu ne l'est : {:#?}",
        p.alertes
    );
    for marque in ["EXCLUALICE", "EXCLUBOB"] {
        for (ou, texte) in [("spool", &p.spool), ("etat incremental", &p.etat), ("sortie d'erreur", &p.stderr)] {
            assert!(!texte.contains(marque), "`{marque}` figure dans {ou} :\n{texte}");
        }
    }
    for voisin in ["alic", "lice", "alicex", "xalice", "bo"] {
        assert!(p.etat.contains(&format!("{voisin}@example.test|INBOX|")), "{voisin} non marque vu : {}", p.etat);
    }
    let b = battement(&p);
    assert!(
        b.contains("7 compte(s) dont 5 ouvert(s), 2 exclu(s) par PLUME_MAIL_EXCLURE_COMPTES"),
        "le battement dit le COMPTE des exclus : {b}"
    );
    for nom in ["alice", "ALICE", "Bob", "bob"] {
        assert!(!b.contains(nom), "le battement nomme un compte (`{nom}`) : {b}");
    }
}

#[test]
fn en_layout_imbrique_une_partie_locale_exclut_dans_chaque_domaine_et_une_adresse_dans_le_sien() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-imbrique");
    let racine = tmp.join("maildir");
    let d1 = racine.join("example.test");
    let d2 = racine.join("autre.example.test");
    boite(&d1.join("alice"), "EXCLUALICE1");
    boite(&d2.join("alice"), "EXCLUALICE2");
    boite(&d1.join("bob"), "EXCLUBOB1");
    boite(&d2.join("bob"), "VOISINBOB2");
    boite(&d1.join("alicex"), "VOISINALICEX");
    let (_rendre, mord) = priver(&[d1.join("alice"), d2.join("alice"), d1.join("bob")]);
    assert!(mord, "execution privilegiee : la privation ne mord pas, ce temoin ne peut pas conclure");

    let p = passer(&tmp, &racine, Some("alice bob@example.test"));
    assert_eq!(p.code, Some(0), "le passage a touche un compte exclu : {}", p.stderr);
    assert!(p.aveux.is_empty(), "aucun aveu attendu : {:#?}", p.aveux);
    assert_eq!(comptes_alertes(&p), ["alicex@example.test", "bob@autre.example.test"]);
    for marque in ["EXCLUALICE1", "EXCLUALICE2", "EXCLUBOB1"] {
        assert!(!p.spool.contains(marque) && !p.etat.contains(marque), "`{marque}` a ete lu");
    }
    let b = battement(&p);
    assert!(b.contains("5 compte(s) dont 2 ouvert(s), 3 exclu(s) par"), "{b}");
}

#[test]
fn une_liste_vide_garde_le_passage_d_avant_et_une_liste_sans_cible_dit_zero() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-vide");
    let racine = tmp.join("maildir");
    boite(&racine.join("alice"), "LUEALICE");
    boite(&racine.join("bob"), "LUEBOB");
    for exclure in [None, Some(""), Some("  \t  ")] {
        let p = passer(&tmp, &racine, exclure);
        assert_eq!(p.code, Some(0), "{exclure:?} : {}", p.stderr);
        let b = battement(&p);
        assert!(!b.contains("exclu"), "liste vide : le battement d'avant, a l'identique : {b}");
        assert!(b.contains("2 compte(s) dont 2 ouvert(s), 2 message(s) examine(s)"), "{b}");
        let _ = std::fs::remove_file(tmp.join("etat"));
        let _ = std::fs::remove_dir_all(tmp.join("spool"));
    }
    let p = passer(&tmp, &racine, Some("carol"));
    assert_eq!(comptes_alertes(&p), ["alice@example.test", "bob@example.test"]);
    assert!(battement(&p).contains("2 compte(s) dont 2 ouvert(s), 0 exclu(s) par"), "{}", p.stderr);
}

#[test]
fn une_entree_invalide_arrete_le_passage_avant_toute_lecture_et_l_avoue_par_son_rang() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-invalide");
    let racine = tmp.join("maildir");
    boite(&racine.join("alice"), "JAMAISLUE");
    for (valeur, rang, cause) in [
        ("alice,,bob", 2, "entree vide"),
        ("ali*", 1, "motif glob"),
        ("bob al/ice", 2, "caractere hors classe"),
        ("bob@@example.test", 1, "adresse mal formee"),
    ] {
        let p = passer(&tmp, &racine, Some(valeur));
        assert_eq!(p.code, Some(1), "{valeur:?} doit arreter le passage : {}", p.stderr);
        assert!(
            p.stderr.contains(&format!("{VARIABLE} : entree n°{rang} refusee ({cause}")),
            "{valeur:?} : aveu nomme attendu : {}",
            p.stderr
        );
        assert!(p.alertes.is_empty() && p.etat.is_empty(), "{valeur:?} : rien ne devait etre lu");
        assert!(!p.spool.contains("JAMAISLUE") && !p.stderr.contains("JAMAISLUE"));
        assert_eq!(p.aveux.len(), 1, "{valeur:?} : un aveu dans le spool : {}", p.spool);
        let detail = p.aveux[0]["fields"]["detail"].as_str().unwrap();
        assert!(detail.contains(&format!("n°{rang} ")) && !detail.contains("alice") && !detail.contains("bob"), "{detail}");
        let _ = std::fs::remove_dir_all(tmp.join("spool"));
    }
}

#[test]
fn la_lecture_a_la_demande_refuse_un_compte_exclu_sans_rien_ouvrir() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-body");
    let racine = tmp.join("maildir");
    boite(&racine.join("alice"), "BODYALICE");
    boite(&racine.join("alicex"), "BODYALICEX");
    let lire = |compte: &str, id: &str| {
        let mut c = Command::new(BINAIRE);
        for (k, _) in std::env::vars() {
            if k.starts_with("PLUME_") {
                c.env_remove(k);
            }
        }
        c.args(["body", compte, id])
            .env("PLUME_MAIL_ROOT", &racine)
            .env("PLUME_SPOOL", tmp.join("spool"))
            .env("PLUME_HOST", "hote-de-temoin")
            .env(VARIABLE, "Alice")
            .output()
            .unwrap()
    };
    let refus = lire("alice@example.test", "1700000100.BODYALICE");
    assert_eq!(refus.status.code(), Some(1));
    assert!(refus.stdout.is_empty(), "aucun contenu rendu");
    assert!(String::from_utf8_lossy(&refus.stderr).contains("retire par PLUME_MAIL_EXCLURE_COMPTES"));
    let voisin = lire("alicex@example.test", "1700000100.BODYALICEX");
    assert_eq!(voisin.status.code(), Some(0), "{}", String::from_utf8_lossy(&voisin.stderr));
    assert!(String::from_utf8_lossy(&voisin.stdout).contains("192.0.2.10"));
}
