//! P10.33-m — UN COMPTE RETIRE PAR `PLUME_MAIL_EXCLURE_COMPTES` N'EST JAMAIS OUVERT.
//!
//! Ces temoins executent le BINAIRE livre contre un maildir fabrique. Chaque compte exclu porte un
//! message qui DECLENCHERAIT une alerte (URL a IP brute), sous un nom de fichier marque `EXCLU…`, et son
//! repertoire est en droits 000 : un `read_dir` ou une lecture de message y echoue, et ce qui se voit
//! alors (passage en echec, aveu, compte qui change dans le battement, « introuvable » au lieu du refus)
//! fait rougir le temoin. CE QUE CES TEMOINS NE VOIENT PAS : un simple `stat` de `cur/` dans un compte
//! exclu. `is_maildir` avale l'EACCES et rend « pas un maildir », sans trace observable de l'exterieur ;
//! le « ni stat » de `deploy/MAIL.md` repose sur l'ORDRE du code (la decision sur le nom tombe avant la
//! sonde, `maildir.rs`), pas sur un temoin. L'instrument est VALIDE avant d'etre cru : le temoin
//! verifie que la privation MORD (une execution privilegiee lit un repertoire 000) et refuse sinon de
//! conclure, plutot que de declarer « jamais ouvert » sans l'avoir vu.
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
    // Un domaine dont le SEUL compte est exclu et prive : il reste un domaine (un exclu), pas un compte
    // plat fantome `seul.test@example.test` « ouvert ».
    let d3 = racine.join("seul.test");
    boite(&d3.join("alice"), "EXCLUALICE3");
    // Un domaine ecrit en majuscules sur le disque : `bob@example.test` l'exclut (casse ASCII pliee).
    let d4 = racine.join("Example.TEST");
    boite(&d4.join("bob"), "EXCLUBOB4");
    boite(&d4.join("carol"), "VOISINCAROL4");
    let (_rendre, mord) =
        priver(&[d1.join("alice"), d2.join("alice"), d1.join("bob"), d3.join("alice"), d4.join("bob")]);
    assert!(mord, "execution privilegiee : la privation ne mord pas, ce temoin ne peut pas conclure");

    let p = passer(&tmp, &racine, Some("alice bob@example.test"));
    assert_eq!(p.code, Some(0), "le passage a touche un compte exclu : {}", p.stderr);
    assert!(p.aveux.is_empty(), "aucun aveu attendu : {:#?}", p.aveux);
    assert_eq!(comptes_alertes(&p), ["alicex@example.test", "bob@autre.example.test", "carol@Example.TEST"]);
    for marque in ["EXCLUALICE1", "EXCLUALICE2", "EXCLUBOB1", "EXCLUALICE3", "EXCLUBOB4"] {
        assert!(!p.spool.contains(marque) && !p.etat.contains(marque), "`{marque}` a ete lu");
    }
    assert!(!p.etat.contains("seul.test@"), "un domaine lu comme compte plat : {}", p.etat);
    let b = battement(&p);
    assert!(b.contains("8 compte(s) dont 3 ouvert(s), 5 exclu(s) par"), "{b}");
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
fn le_battement_sans_alerte_compte_aussi_les_exclus() {
    // Le regime NORMAL d'un passage : aucune alerte. Sa ligne doit dire le total (exclus compris) et
    // le nombre d'exclus, comme celle d'un passage qui alerte.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-zero");
    let racine = tmp.join("maildir");
    for compte in ["alice", "bob"] {
        std::fs::create_dir_all(racine.join(compte).join("cur")).unwrap();
        std::fs::create_dir_all(racine.join(compte).join("new")).unwrap();
    }
    let p = passer(&tmp, &racine, Some("alice"));
    assert_eq!(p.code, Some(0), "{}", p.stderr);
    assert!(p.alertes.is_empty() && p.aveux.is_empty(), "{}", p.spool);
    let b = battement(&p);
    assert!(
        b.contains("2 compte(s) dont 1 ouvert(s), 1 exclu(s) par PLUME_MAIL_EXCLURE_COMPTES, 0 message(s) examine(s), 0 alerte"),
        "{b}"
    );
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

struct Lecture {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// Fichiers deposes dans le spool (l'audit d'une lecture en est un).
    spool: usize,
}

/// `body <compte> <id>` avec un environnement NETTOYE ; `conf` = chemin de `PLUME_MAIL_CONF` (toujours
/// pose : le `/etc/plume/mail.conf` de la machine de test ne doit pas entrer dans le temoin).
fn lire(tmp: &Path, racine: &Path, conf: &Path, env: &[(&str, &str)], compte: &str, id: &str) -> Lecture {
    let spool = tmp.join("spool-body");
    let _ = std::fs::remove_dir_all(&spool);
    let mut c = Command::new(BINAIRE);
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.args(["body", compte, id])
        .env("PLUME_MAIL_ROOT", racine)
        .env("PLUME_SPOOL", &spool)
        .env("PLUME_HOST", "hote-de-temoin")
        .env("PLUME_MAIL_CONF", conf);
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    Lecture {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        spool: std::fs::read_dir(&spool).map(|rd| rd.count()).unwrap_or(0),
    }
}

fn refusee(l: &Lecture, pourquoi: &str, cas: &str) {
    assert_eq!(l.code, Some(1), "{cas} : refus attendu : {}", l.stderr);
    assert!(l.stdout.is_empty(), "{cas} : aucun contenu rendu : {}", l.stdout);
    assert_eq!(l.spool, 0, "{cas} : aucune lecture auditee, donc aucune lecture");
    assert!(l.stderr.contains(pourquoi), "{cas} : `{pourquoi}` attendu : {}", l.stderr);
}

fn rendue(l: &Lecture, cas: &str) {
    assert_eq!(l.code, Some(0), "{cas} : {}", l.stderr);
    assert!(l.stdout.contains("192.0.2.10"), "{cas} : contenu attendu : {}", l.stdout);
}

#[test]
fn la_lecture_a_la_demande_refuse_un_compte_exclu_sans_rien_ouvrir() {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-body");
    let racine = tmp.join("maildir");
    let sans_conf = tmp.join("pas-de-mail.conf");
    boite(&racine.join("alice"), "BODYALICE");
    boite(&racine.join("alicex"), "BODYALICEX");
    let env = [(VARIABLE, "Alice")];
    refusee(&lire(&tmp, &racine, &sans_conf, &env, "alice@example.test", "1700000100.BODYALICE"), "retire par", "alice");
    rendue(&lire(&tmp, &racine, &sans_conf, &env, "alicex@example.test", "1700000100.BODYALICEX"), "voisin");

    // Liste INVALIDE : la lecture est refusee, meme pour un compte qu'aucune entree valide ne viserait.
    let invalide = [(VARIABLE, "ali*")];
    let l = lire(&tmp, &racine, &sans_conf, &invalide, "alicex@example.test", "1700000100.BODYALICEX");
    refusee(&l, "entree n°1 refusee (motif glob", "liste invalide");

    // Boite exclue PRIVEE (000) : le refus tombe AVANT toute recherche du message. Lire d'abord rendrait
    // « message introuvable » (l'enumeration y echoue), pas le refus.
    let (_rendre, mord) = priver(&[racine.join("alice")]);
    assert!(mord, "execution privilegiee : la privation ne mord pas, ce temoin ne peut pas conclure");
    refusee(&lire(&tmp, &racine, &sans_conf, &env, "alice@example.test", "1700000100.BODYALICE"), "retire par", "alice 000");
}

#[test]
fn en_layout_plat_la_boite_resolue_decide_pas_l_adresse_ecrite() {
    // Layout plat : `alice@<n'importe quoi>` resout la meme boite `<racine>/alice`. L'entree
    // `alice@example.test` (le domaine du layout plat) doit la proteger sous TOUTES ses ecritures.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-body-plat");
    let racine = tmp.join("maildir");
    let sans_conf = tmp.join("pas-de-mail.conf");
    boite(&racine.join("alice"), "PLATALICE");
    boite(&racine.join("alice").join(".Sent"), "PLATALICESENT");
    boite(&racine.join("alicex"), "PLATALICEX");
    let env = [(VARIABLE, "alice@example.test"), ("PLUME_MAIL_DOMAIN", "example.test")];
    for compte in ["alice@example.test", "alice@autre.test", "alice@example.test.", ".Sent@alice", "alice@."] {
        let id = if compte.starts_with(".Sent") { "1700000100.PLATALICESENT" } else { "1700000100.PLATALICE" };
        refusee(&lire(&tmp, &racine, &sans_conf, &env, compte, id), "lecture refusee", compte);
    }
    // La racine elle-meme (`.` en layout plat) ne designe aucun compte : refusee, pas lue.
    refusee(&lire(&tmp, &racine, &sans_conf, &env, ".@nulle.part", "1700000100.PLATALICE"), "lecture refusee", "racine");
    // Un lien qui sort de la racine : le balayage ne le suit pas, `body` ne le lit pas.
    boite(&tmp.join("dehors"), "DEHORS");
    std::os::unix::fs::symlink(tmp.join("dehors"), racine.join("lien")).unwrap();
    refusee(&lire(&tmp, &racine, &sans_conf, &env, "lien@example.test", "1700000100.DEHORS"), "hors de la racine", "lien");
    rendue(&lire(&tmp, &racine, &sans_conf, &env, "alicex@autre.test", "1700000100.PLATALICEX"), "voisin plat");
    // L'adresse vise le domaine du layout PLAT : sous un autre domaine plat, `alice` n'est pas visee.
    let ailleurs = [(VARIABLE, "alice@example.test"), ("PLUME_MAIL_DOMAIN", "autre.test")];
    rendue(&lire(&tmp, &racine, &sans_conf, &ailleurs, "alice@example.test", "1700000100.PLATALICE"), "autre domaine");
}

#[test]
fn la_lecture_a_la_demande_applique_la_liste_du_fichier_de_configuration() {
    // `body` est lance par le DEMON (`PLUME_MAIL_BODY_CMD`) : il n'herite pas de `mail.conf`. Il doit
    // relire le fichier lui-meme, joindre sa liste a celle de l'environnement, et refuser s'il ne peut
    // pas le lire.
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-33-m-body-conf");
    let racine = tmp.join("maildir");
    let conf = tmp.join("mail.conf");
    for compte in ["alice", "bob", "carol"] {
        boite(&racine.join(compte), &format!("CONF{compte}"));
    }
    std::fs::write(
        &conf,
        "# comme /etc/plume/mail.conf\nPLUME_MAIL_DOMAIN=example.test\nPLUME_MAIL_EXCLURE_COMPTES=\"alice@example.test\"\n",
    )
    .unwrap();
    let env = [(VARIABLE, "bob")];
    refusee(&lire(&tmp, &racine, &conf, &[], "alice@example.test", "1700000100.CONFalice"), "retire par", "fichier seul");
    refusee(&lire(&tmp, &racine, &conf, &env, "alice@example.test", "1700000100.CONFalice"), "retire par", "fichier + env");
    refusee(&lire(&tmp, &racine, &conf, &env, "bob@example.test", "1700000100.CONFbob"), "retire par", "env + fichier");
    rendue(&lire(&tmp, &racine, &conf, &env, "carol@example.test", "1700000100.CONFcarol"), "carol");

    std::fs::write(&conf, "PLUME_MAIL_EXCLURE_COMPTES=alice,,bob\n").unwrap();
    refusee(&lire(&tmp, &racine, &conf, &[], "carol@example.test", "1700000100.CONFcarol"), "entree n°2 refusee", "fichier invalide");

    std::fs::write(&conf, "PLUME_MAIL_EXCLURE_COMPTES=alice\n").unwrap();
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o000)).unwrap();
    let illisible = std::fs::read(&conf).is_err();
    let l = lire(&tmp, &racine, &conf, &[], "carol@example.test", "1700000100.CONFcarol");
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(illisible, "execution privilegiee : un fichier 000 reste lisible, ce temoin ne peut pas conclure");
    refusee(&l, "illisible", "fichier illisible");
}
