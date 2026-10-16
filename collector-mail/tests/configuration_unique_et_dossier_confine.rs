//! P10.33-m — LE BALAYAGE ET `body` APPLIQUENT LA MEME CONFIGURATION, ET UN DOSSIER NE SORT PAS DU COMPTE.
//!
//! Deux regles distinctes calculaient le domaine du layout plat : le balayage lisait son environnement
//! (celui que `EnvironmentFile=` lui charge), `body` lisait `mail.conf` puis l'environnement du DEMON.
//! Une meme boite s'appelait alors `alice@localhost` pour l'un et `alice@example.test` pour l'autre : le
//! balayage la retirait, `body` la rendait. Ces temoins posent la configuration aux DEUX chemins et
//! exigent la meme decision.
//!
//! Le nom de dossier passe a `body` etait joint au chemin du compte sans examen : `Sent/../../bob`
//! lisait la boite `bob`. Ces temoins exigent le refus, et celui d'un dossier ou d'un `cur/` en lien
//! qui sort du compte.

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-mail");
const VARIABLE: &str = "PLUME_MAIL_EXCLURE_COMPTES";

/// Un message que le jeu de motifs par defaut FLAGGE (`raw-ip-url`, adresse RFC 5737).
fn boite(dossier: &Path, marque: &str) {
    std::fs::create_dir_all(dossier.join("cur")).unwrap();
    std::fs::create_dir_all(dossier.join("new")).unwrap();
    let corps = format!(
        "From: expediteur@sender.example\r\nTo: boite@example.test\r\nSubject: note\r\n\
         Message-ID: <{marque}@sender.example>\r\nDate: Wed, 14 Oct 2026 10:00:00 +0000\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\nVoir http://192.0.2.10/{marque}\r\n"
    );
    std::fs::write(dossier.join("new").join(format!("1700000100.{marque}:2,")), corps).unwrap();
}

/// Rend les droits AVANT que le temporaire possede ne s'efface (declare apres lui).
struct Restaurer(Vec<PathBuf>);
impl Drop for Restaurer {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        }
    }
}

fn commande(conf: &Path, env: &[(&str, &str)]) -> Command {
    let mut c = Command::new(BINAIRE);
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.env("PLUME_HOST", "hote-de-temoin").env("PLUME_MAIL_CONF", conf);
    for (k, v) in env {
        c.env(k, v);
    }
    c
}

struct Sortie {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// Tout le texte depose dans le spool, et l'etat incremental.
    spool: String,
    etat: String,
}

fn executer(mut c: Command, spool: &Path, etat: &Path) -> Sortie {
    let _ = std::fs::remove_dir_all(spool);
    let _ = std::fs::remove_file(etat);
    let o = c.env("PLUME_SPOOL", spool).env("PLUME_MAIL_STATE", etat).output().unwrap();
    let mut texte = String::new();
    if let Ok(rd) = std::fs::read_dir(spool) {
        for e in rd {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                texte.push_str(&std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    Sortie {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        spool: texte,
        etat: std::fs::read_to_string(etat).unwrap_or_default(),
    }
}

fn balayer(tmp: &Path, racine: &Path, conf: &Path, env: &[(&str, &str)]) -> Sortie {
    let mut c = commande(conf, env);
    c.arg("scan").env("PLUME_MAIL_ROOT", racine);
    executer(c, &tmp.join("spool-scan"), &tmp.join("etat"))
}

fn lire(tmp: &Path, racine: &Path, conf: &Path, env: &[(&str, &str)], args: &[&str]) -> Sortie {
    let mut c = commande(conf, env);
    c.arg("body").args(args).env("PLUME_MAIL_ROOT", racine);
    executer(c, &tmp.join("spool-body"), &tmp.join("etat-body"))
}

fn refusee(l: &Sortie, pourquoi: &str, cas: &str) {
    assert_eq!(l.code, Some(1), "{cas} : refus attendu : {}", l.stderr);
    assert!(l.stdout.is_empty(), "{cas} : aucun contenu rendu : {}", l.stdout);
    assert!(l.spool.is_empty(), "{cas} : aucune lecture auditee, donc aucune lecture : {}", l.spool);
    assert!(l.stderr.contains(pourquoi), "{cas} : `{pourquoi}` attendu : {}", l.stderr);
}

fn rendue(l: &Sortie, marque: &str, cas: &str) {
    assert_eq!(l.code, Some(0), "{cas} : {}", l.stderr);
    assert!(l.stdout.contains(marque), "{cas} : contenu `{marque}` attendu : {}", l.stdout);
}

/// La ligne de battement du balayage.
fn battement(s: &Sortie) -> &str {
    s.stderr
        .lines()
        .find(|l| l.contains(" compte(s) dont "))
        .unwrap_or_else(|| panic!("aucun battement : {}", s.stderr))
}

#[test]
fn le_domaine_de_mail_conf_l_emporte_sur_l_environnement_pour_les_deux_chemins() {
    // Sonde `sonde_precedence` du verificateur : `mail.conf` nomme le domaine et retire alice ; le demon
    // (environnement de `body`) porte un AUTRE domaine.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-precedence");
    let racine = tmp.join("maildir");
    let conf = tmp.join("mail.conf");
    boite(&racine.join("alice"), "PRECALICE");
    boite(&racine.join("bob"), "PRECBOB");
    std::fs::write(&conf, "PLUME_MAIL_DOMAIN=example.test\nPLUME_MAIL_EXCLURE_COMPTES=alice@example.test\n").unwrap();
    let env = [("PLUME_MAIL_DOMAIN", "autre.test")];

    for compte in ["alice@example.test", "alice@autre.test"] {
        refusee(&lire(&tmp, &racine, &conf, &env, &[compte, "1700000100.PRECALICE"]), "retire par", compte);
    }
    rendue(&lire(&tmp, &racine, &conf, &env, &["bob@autre.test", "1700000100.PRECBOB"]), "PRECBOB", "bob");

    let s = balayer(&tmp, &racine, &conf, &env);
    assert_eq!(s.code, Some(0), "{}", s.stderr);
    assert!(!s.etat.contains("PRECALICE") && !s.spool.contains("PRECALICE"), "alice balayee : {}", s.etat);
    assert!(s.etat.contains("bob@example.test|INBOX|"), "le balayage nomme bob dans le domaine du fichier : {}", s.etat);
    assert!(battement(&s).contains("2 compte(s) dont 1 ouvert(s), 1 exclu(s)"), "{}", s.stderr);
}

#[test]
fn une_valeur_vide_vaut_le_defaut_pour_les_deux_chemins() {
    // Sonde `sonde_domaine_vide` : `mail.conf` porte la cle VIDE (sous systemd elle ecrase
    // l'environnement, et le balayage retombe sur `localhost`). `body` retombait, lui, sur le domaine
    // de l'environnement du demon et lisait la boite que le balayage retirait.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-domaine-vide");
    let racine = tmp.join("maildir");
    let conf = tmp.join("mail.conf");
    boite(&racine.join("alice"), "VIDEALICE");
    boite(&racine.join("bob"), "VIDEBOB");
    for (contenu, env, cas) in [
        ("PLUME_MAIL_DOMAIN=\nPLUME_MAIL_EXCLURE_COMPTES=alice@localhost\n", ("PLUME_MAIL_DOMAIN", "example.test"), "cle vide dans le fichier"),
        ("PLUME_MAIL_DOMAIN=''\nPLUME_MAIL_EXCLURE_COMPTES=alice@localhost\n", ("PLUME_MAIL_DOMAIN", "example.test"), "cle vide entre guillemets"),
        ("PLUME_MAIL_EXCLURE_COMPTES=alice@localhost\n", ("PLUME_MAIL_DOMAIN", ""), "cle absente, environnement vide"),
    ] {
        std::fs::write(&conf, contenu).unwrap();
        let env = [env];
        let s = balayer(&tmp, &racine, &conf, &env);
        assert!(battement(&s).contains("2 compte(s) dont 1 ouvert(s), 1 exclu(s)"), "{cas} : {}", s.stderr);
        assert!(!s.etat.contains("VIDEALICE"), "{cas} : alice balayee : {}", s.etat);
        refusee(&lire(&tmp, &racine, &conf, &env, &["alice@example.test", "1700000100.VIDEALICE"]), "retire par", cas);
        rendue(&lire(&tmp, &racine, &conf, &env, &["bob@example.test", "1700000100.VIDEBOB"]), "VIDEBOB", cas);
    }
}

#[test]
fn un_mail_conf_illisible_refuse_meme_quand_l_environnement_porte_une_liste() {
    // La liste du FICHIER peut nommer un compte que celle de l'environnement ne nomme pas : lire faute
    // d'avoir pu la lire rendrait la boite retiree. Refus aux deux chemins, sans rien ouvrir.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-conf-illisible");
    let racine = tmp.join("maildir");
    let conf = tmp.join("mail.conf");
    boite(&racine.join("alice"), "ILLALICE");
    std::fs::write(&conf, "PLUME_MAIL_EXCLURE_COMPTES=alice\n").unwrap();
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _rendre = Restaurer(vec![conf.clone()]);
    assert!(std::fs::read(&conf).is_err(), "execution privilegiee : un fichier 000 reste lisible, ce temoin ne peut pas conclure");

    for env in [&[(VARIABLE, "bob")][..], &[][..]] {
        let l = lire(&tmp, &racine, &conf, env, &["alice@example.test", "1700000100.ILLALICE"]);
        refusee(&l, "illisible", &format!("body, environnement {env:?}"));
        let s = balayer(&tmp, &racine, &conf, env);
        assert_eq!(s.code, Some(1), "balayage {env:?} : refus attendu : {}", s.stderr);
        assert!(s.stderr.contains("illisible"), "{}", s.stderr);
        assert!(s.etat.is_empty() && !s.spool.contains("ILLALICE"), "balayage {env:?} : rien ne devait etre lu");
        assert!(s.spool.contains("\"collect_status\":\"unavailable\""), "balayage {env:?} : aveu attendu : {}", s.spool);
    }
}

#[test]
fn un_dossier_qui_remonte_n_ouvre_pas_une_autre_boite() {
    // Revue de securite, attaque 2 : `Sent/../../bob` resolvait `<racine>/bob`. Le controle d'exclusion
    // porte sur le compte NOMME (alice) : la boite bob, retiree, etait rendue.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-dossier");
    let racine = tmp.join("maildir");
    let sans_conf = tmp.join("pas-de-mail.conf");
    boite(&racine.join("alice"), "DOSALICE");
    boite(&racine.join("alice").join(".Sent"), "DOSALICESENT");
    boite(&racine.join("bob"), "DOSBOB");
    let retire = [(VARIABLE, "bob@example.test"), ("PLUME_MAIL_DOMAIN", "example.test")];
    for env in [&retire[..], &[][..]] {
        for dossier in ["Sent/../../bob", "../bob", "..", "Sent\\..\\..\\bob", "Se\u{1}nt", ""] {
            let l = lire(&tmp, &racine, &sans_conf, env, &["alice@example.test", "1700000100.DOSBOB", dossier]);
            refusee(&l, "nom de dossier refuse", &format!("{dossier:?} {env:?}"));
            assert!(!l.stderr.contains("bob"), "l'erreur ne recopie pas le dossier : {}", l.stderr);
        }
    }
    // Les dossiers ordinaires restent lus.
    rendue(&lire(&tmp, &racine, &sans_conf, &retire, &["alice@example.test", "1700000100.DOSALICESENT", "Sent"]), "DOSALICESENT", "Sent");
    rendue(&lire(&tmp, &racine, &sans_conf, &retire, &["alice@example.test", "1700000100.DOSALICE", "INBOX"]), "DOSALICE", "INBOX");
}

#[test]
fn un_dossier_ou_un_cur_en_lien_hors_du_compte_est_refuse_sans_y_entrer() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-lien-dossier");
    let racine = tmp.join("maildir");
    let sans_conf = tmp.join("pas-de-mail.conf");
    boite(&racine.join("alice"), "LIENALICE");
    boite(&racine.join("bob"), "LIENBOB");
    boite(&racine.join("carol"), "LIENCAROL");
    // `.Sent` d'alice pointe la boite bob, que l'on PRIVE : y entrer (meme un `stat` de `cur/`) rendrait
    // « message introuvable » ; le refus doit tomber AVANT, sur le lien.
    std::os::unix::fs::symlink("../bob", racine.join("alice").join(".Sent")).unwrap();
    std::fs::set_permissions(racine.join("bob"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let _rendre = Restaurer(vec![racine.join("bob")]);
    assert!(std::fs::read_dir(racine.join("bob")).is_err(), "execution privilegiee : la privation ne mord pas");
    // `.Junk` est un vrai dossier d'alice, mais son `cur/` pointe celui de carol (lisible).
    std::fs::create_dir_all(racine.join("alice").join(".Junk")).unwrap();
    std::os::unix::fs::symlink("../../carol/new", racine.join("alice").join(".Junk").join("new")).unwrap();
    let retire = [(VARIABLE, "bob carol"), ("PLUME_MAIL_DOMAIN", "example.test")];
    for env in [&retire[..], &[][..]] {
        let l = lire(&tmp, &racine, &sans_conf, env, &["alice@example.test", "1700000100.LIENBOB", "Sent"]);
        refusee(&l, "hors du compte", &format!(".Sent -> bob {env:?}"));
        let l = lire(&tmp, &racine, &sans_conf, env, &["alice@example.test", "1700000100.LIENCAROL", "Junk"]);
        refusee(&l, "hors du compte", &format!(".Junk/new -> carol {env:?}"));
    }
    rendue(&lire(&tmp, &racine, &sans_conf, &retire, &["alice@example.test", "1700000100.LIENALICE", "INBOX"]), "LIENALICE", "INBOX");
}
