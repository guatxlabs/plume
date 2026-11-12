//! P10.32-l — UN JETON PLACE DANS LE CHEMIN D'UNE URL NE SORT PAS.
//!
//! `url_coupee` (collector-mail/src/confidentialite.rs) garde le chemin d'une URL ; un lien de
//! reinitialisation ou de confirmation y place souvent son jeton (`/reset/<jeton>`), que l'evenement
//! deposait alors dans le SIEM. Un SEGMENT de chemin qui a la forme d'un jeton est desormais remplace
//! par la marque `[jeton coupe]`, le reste du chemin est garde.
//!
//! Deux etages de temoins :
//!   * la regle de forme, appelee directement (le module est compile ici tel quel) : une table
//!     entree -> sortie EXACTE pour chaque forme coupee et chaque forme gardee, chaque bord de seuil,
//!     le segment encode en pourcentage (une et deux fois), plusieurs jetons, le chemin vide, l'URL
//!     sans chemin, le repli d'une URL que la bibliotheque refuse, la borne de longueur de
//!     l'echantillon ;
//!   * le BINAIRE livre (`plume-collector-mail scan`) contre une boite fabriquee : ce que le spool
//!     recoit pour un motif `url` et pour un motif de corps qui couvre l'URL.
//!
//! Deux voisins du meme module, temoignes aux memes deux etages :
//!   * dans un TEXTE (`texte_assaini`), le schema d'une URL se reconnait sans egard a la casse
//!     (`HTTPS://`, `Https://`, `hTTp://`) : jeton du chemin, requete, fragment et identifiants coupes ;
//!   * l'objet DEMANDE (`objet_emis`, et la valeur d'objet d'un echantillon `headers`) est assaini sur
//!     sa longueur entiere AVANT d'etre borne : un jeton ou une partie locale qui chevauche la borne ne
//!     sort pas par ses premiers caracteres.
//! Les marques sont ecrites ICI en litteraux : une sortie fausse de la production ne se compare pas
//! a elle-meme.
#![allow(dead_code)]

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;
#[path = "../src/url_extract.rs"]
mod url_extract;
#[path = "../src/confidentialite.rs"]
mod confidentialite;

use confidentialite::{echantillon_d_en_tetes, objet_emis, texte_assaini, url_coupee};
use std::process::Command;

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-mail");
const MARQUE: &str = "[jeton coupe]";
const BORNE_DE_L_ECHANTILLON: usize = 200;

fn jouer_la_table(cas: &[(&str, String)]) -> Vec<String> {
    let mut fautes = Vec::new();
    for (entree, attendu) in cas {
        let vu = url_coupee(entree);
        if &vu != attendu {
            fautes.push(format!("\n  {entree}\n    attendu {attendu}\n    vu      {vu}"));
        }
    }
    fautes
}

fn chemin(p: &str) -> String {
    format!("https://a.example.org{p}")
}

/// Un JWT ordinaire fabrique (en-tete `{"alg":"HS256"}`, charge `{"sub":"alice"}`, signature inventee),
/// ASSEMBLE A L'EXECUTION : ecrit d'un seul tenant, il porterait dans le source la forme qu'un detecteur
/// de secrets (regle `jwt` de gitleaks) signale, et l'historique la garderait. Aucun morceau n'a seul
/// cette forme : une partie `ey…` sans `.ey…` qui la suive.
fn jwt_assemble() -> String {
    let en_tete = ["eyJhbGci", "OiJIUzI1NiJ9"].concat();
    let charge = ["eyJzdWIi", "OiJhbGljZSJ9"].concat();
    let signature = ["SflKxwRJSMeKKF2QT4fw", "pMeJf36POk6yJV_adQssw5c"].concat();
    format!("https://a.example.org/s/{en_tete}.{charge}.{signature}")
}

#[test]
fn chaque_forme_de_jeton_est_coupee_dans_le_chemin() {
    let m = MARQUE;
    let jwt_ordinaire = jwt_assemble();
    let cas: Vec<(&str, String)> = vec![
        // hexadecimal long (empreinte, jeton de reinitialisation)
        ("https://a.example.org/reset/3f9a8b7c6d5e4f30a1b2c3d4e5f60718", chemin(&format!("/reset/{m}"))),
        // hexadecimal en capitales
        ("https://a.example.org/reset/3F9A8B7C6D5E4F30A1B2", chemin(&format!("/reset/{m}"))),
        // chiffres seuls, seize : un hexadecimal
        ("https://a.example.org/o/1234567890123456", chemin(&format!("/o/{m}"))),
        // hexadecimal fait de lettres seules (aucun chiffre, une seule casse)
        ("https://a.example.org/k/deadbeefcafebabe", chemin(&format!("/k/{m}"))),
        // base64url long, `-` et `_` compris
        ("https://a.example.org/confirm/a8Fk-29_xQpLmZ7r0Tb3Yw", chemin(&format!("/confirm/{m}"))),
        // base64 sans le chiffre qui suffirait : la casse melee le trahit
        ("https://a.example.org/c/QWxhZGRpbjpvcGVuIHNlc2FtZQ", chemin(&format!("/c/{m}"))),
        // base64 rembourre (`=`) : le `=` n'est pas une limite qui protege le jeton
        ("https://a.example.org/c/QWxhZGRpbjpvcGVuIHNlc2FtZQ==", chemin(&format!("/c/{m}"))),
        // minuscules et chiffres melees (base36), pas un hexadecimal
        ("https://a.example.org/v/k3j9x0m2p8q7w1z5", chemin(&format!("/v/{m}"))),
        // JWT ordinaire (assemble a l'execution, `jwt_assemble`)
        (jwt_ordinaire.as_str(), chemin(&format!("/s/{m}"))),
        // JWT court (`{"alg":"x"}` puis `{}`) : aucune de ses parties n'atteint seize caracteres,
        // seule la forme JWT le coupe
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.c2ln", chemin(&format!("/s/{m}"))),
        // JWT sans signature (`alg: none`) : troisieme partie vide
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.", chemin(&format!("/s/{m}"))),
        // JWT court rembourre (`=`) : le rembourrage n'est pas une limite qui protege le jeton
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.c2ln=", chemin(&format!("/s/{m}"))),
        ("https://a.example.org/s/eyJhbGciOiJ4In0=.e30=.c2ln", chemin(&format!("/s/{m}"))),
        // JWT court suivi d'une quatrieme partie : au moins trois parties, pas exactement trois
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.c2ln.x", chemin(&format!("/s/{m}"))),
        // JWE compact (cinq parties) : coupe comme un JWT
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.e30.e30.c2ln", chemin(&format!("/s/{m}"))),
        // un caractere hors base64url dans une partie ne protege pas le jeton
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.c2ln~x", chemin(&format!("/s/{m}"))),
        // UUID fait de chiffres seuls : seule la forme UUID le coupe
        ("https://a.example.org/u/12345678-1234-1234-1234-123456789012/view", chemin(&format!("/u/{m}/view"))),
        // UUID ordinaire
        ("https://a.example.org/u/550e8400-e29b-41d4-a716-446655440000", chemin(&format!("/u/{m}"))),
        // jeton nomme comme un fichier : la tige est jugee, le segment entier part
        ("https://a.example.org/f/3f9a8b7c6d5e4f30a1b2.pdf", chemin(&format!("/f/{m}"))),
        // parametre de chemin (`;jsessionid=`) : la valeur est un jeton, le segment entier part
        ("https://a.example.org/app;jsessionid=0A1B2C3D4E5F60718293A4B5C6D7E8F9", chemin(&format!("/{m}"))),
        // `nom=valeur` dans le segment : la valeur est un morceau a part, jugee seule
        ("https://a.example.org/k/id=deadbeefcafebabe", chemin(&format!("/k/{m}"))),
        // encode en pourcentage : le segment est juge DECODE (`3f9a8b7c6d5e4f30`)
        (
            "https://a.example.org/r/%33%66%39%61%38%62%37%63%36%64%35%65%34%66%33%30",
            chemin(&format!("/r/{m}")),
        ),
        // encode DEUX fois (`%25` puis `%33`…) : le decodage est repris
        (
            "https://a.example.org/r/%2533%2566%2539%2561%2538%2562%2537%2563%2536%2564%2535%2565%2534%2566%2533%2530",
            chemin(&format!("/r/{m}")),
        ),
        // encode TROIS fois : la derniere passe admise
        (
            "https://a.example.org/r/%252533%252566%252539%252561%252538%252562%252537%252563%252536%252564%252535%252565%252534%252566%252533%252530",
            chemin(&format!("/r/{m}")),
        ),
        // plusieurs jetons : CHAQUE segment est juge, le premier comme les suivants
        (
            "https://a.example.org/a/3f9a8b7c6d5e4f30a1b2/b/550e8400-e29b-41d4-a716-446655440000/c",
            chemin(&format!("/a/{m}/b/{m}/c")),
        ),
        // un jeton en DERNIER segment, apres des segments gardes
        ("https://a.example.org/a/b/c/d/3f9a8b7c6d5e4f30a1b2", chemin(&format!("/a/b/c/d/{m}"))),
        // la requete et le fragment restent coupes et dits, apres la marque du chemin
        (
            "https://a.example.org/reset/3f9a8b7c6d5e4f30a1b2?t=x#y",
            chemin(&format!("/reset/{m} [requete coupee] [fragment coupe]")),
        ),
        // le port est garde
        ("https://a.example.org:8443/reset/3f9a8b7c6d5e4f30a1b2", format!("https://a.example.org:8443/reset/{m}")),
    ];
    assert!(cas.len() >= 20, "table amputee : {} cas", cas.len());
    let fautes = jouer_la_table(&cas);
    assert!(fautes.is_empty(), "jeton(s) non coupe(s) dans le chemin :{}", fautes.concat());
}

#[test]
fn ce_qui_n_a_pas_la_forme_d_un_jeton_sort_tel_quel() {
    let cas: Vec<(&str, String)> = vec![
        // mot courant long
        ("https://a.example.org/unsubscribe-confirmation", chemin("/unsubscribe-confirmation")),
        // mots et annee : aucun melange a l'interieur d'un mot
        ("https://a.example.org/news/annual-report-2026-final", chemin("/news/annual-report-2026-final")),
        // mot puis annee colles : une seule alternance lettres/chiffres
        ("https://a.example.org/newsletter2026-archives", chemin("/newsletter2026-archives")),
        // noms de fichier
        ("https://a.example.org/docs/rapport-annuel-2026.pdf", chemin("/docs/rapport-annuel-2026.pdf")),
        ("https://a.example.org/img/logo.png", chemin("/img/logo.png")),
        ("https://a.example.org/js/jquery.min.js", chemin("/js/jquery.min.js")),
        // identifiant numerique court
        ("https://a.example.org/order/123456", chemin("/order/123456")),
        // nom en casse chameau : aucune paire de capitales
        ("https://a.example.org/MyAccountSettingsPage", chemin("/MyAccountSettingsPage")),
        // trois parties a points qui ne commencent pas par `eyJ` : pas un JWT
        ("https://a.example.org/eyeglasses.v2.pdf", chemin("/eyeglasses.v2.pdf")),
        // trois parties a points, la premiere assez longue, sans `eyJ` : pas un JWT
        ("https://a.example.org/application.settings.json", chemin("/application.settings.json")),
        // forme d'UUID a une position pres (tiret deplace) et sans assez de melange : gardee
        ("https://a.example.org/u/1234567-81234-1234-1234-123456789012", chemin("/u/1234567-81234-1234-1234-123456789012")),
        // encode en pourcentage, pas un jeton une fois decode (`ete-2026`)
        ("https://a.example.org/%C3%A9t%C3%A9-2026", chemin("/%C3%A9t%C3%A9-2026")),
        // chemin vide, URL sans chemin : rien n'est change
        ("https://a.example.org/", chemin("/")),
        ("https://a.example.org", chemin("/")),
        // l'HOTE n'est pas un segment de chemin : il sort tel quel
        ("https://3f9a8b7c6d5e4f30a1b2.example.org/x", "https://3f9a8b7c6d5e4f30a1b2.example.org/x".to_string()),
    ];
    assert!(cas.len() >= 10, "table amputee : {} cas", cas.len());
    let fautes = jouer_la_table(&cas);
    assert!(fautes.is_empty(), "segment(s) garde(s) a tort coupe(s) :{}", fautes.concat());
}

#[test]
fn chaque_seuil_de_la_regle_a_ses_deux_bords() {
    let m = MARQUE;
    let cas: Vec<(&str, String)> = vec![
        // longueur : quinze caracteres gardes, seize et dix-sept coupes
        ("https://a.example.org/h/0123456789abcde", chemin("/h/0123456789abcde")),
        ("https://a.example.org/h/0123456789abcdef", chemin(&format!("/h/{m}"))),
        ("https://a.example.org/h/0123456789abcdef0", chemin(&format!("/h/{m}"))),
        // longueur, chiffres seuls : quinze gardes, seize coupes
        ("https://a.example.org/o/123456789012345", chemin("/o/123456789012345")),
        // alternances lettres/chiffres (hors hexadecimal) : deux gardees, trois coupees
        ("https://a.example.org/w/ghijklmnopqrs12t", chemin("/w/ghijklmnopqrs12t")),
        ("https://a.example.org/w/ghijklmnopqrs1t2", chemin(&format!("/w/{m}"))),
        // changements de casse (lettres seules, avec des capitales adjacentes) : quatre sur quinze
        // paires gardes, cinq sur quinze coupes (seuil : un tiers)
        ("https://a.example.org/w/ABCDEFGHIJKLaBcD", chemin("/w/ABCDEFGHIJKLaBcD")),
        ("https://a.example.org/w/ABCDEFGHIJKaBcDe", chemin(&format!("/w/{m}"))),
        // casse chameau : sans capitales adjacentes gardee, avec une paire coupee
        ("https://a.example.org/w/MyAccountSettingsPage", chemin("/w/MyAccountSettingsPage")),
        ("https://a.example.org/w/MyACcountSettingsPage", chemin(&format!("/w/{m}"))),
        // JWT : en-tete de onze caracteres admis, de dix refuse
        ("https://a.example.org/s/eyJhbGciOiJ.e30.", chemin(&format!("/s/{m}"))),
        ("https://a.example.org/s/eyJhbGciOi.e30.", chemin("/s/eyJhbGciOi.e30.")),
        // JWT : deuxieme partie vide refusee
        ("https://a.example.org/s/eyJhbGciOiJ4In0..c2ln", chemin("/s/eyJhbGciOiJ4In0..c2ln")),
        // JWT : deux parties gardees, trois coupees (plus haut), quatre coupees
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30", chemin("/s/eyJhbGciOiJ4In0.e30")),
        ("https://a.example.org/s/eyJhbGciOiJ4In0.e30.c2ln.e30", chemin(&format!("/s/{m}"))),
    ];
    assert!(cas.len() >= 10, "table amputee : {} cas", cas.len());
    let fautes = jouer_la_table(&cas);
    assert!(fautes.is_empty(), "bord(s) faux :{}", fautes.concat());
}

/// Les limites que l'en-tete du module DIT : chacune sort encore, telle quelle. Si l'une se met a etre
/// coupee, l'en-tete ment et se corrige avec ce temoin.
#[test]
fn les_limites_dites_par_l_en_tete_sortent_encore() {
    let cas: Vec<(&str, String)> = vec![
        // moins de seize caracteres
        ("https://a.example.org/t/a8Fk29xQpLmZ7r0", chemin("/t/a8Fk29xQpLmZ7r0")),
        // lettres d'une seule casse, hors hexadecimal
        ("https://a.example.org/t/qwkzjxvbnmrtplsd", chemin("/t/qwkzjxvbnmrtplsd")),
        // lettres puis chiffres, une seule alternance
        ("https://a.example.org/t/ABCDEFGHIJKL12345678", chemin("/t/ABCDEFGHIJKL12345678")),
        // un jeton long coupe en morceaux de moins de seize caracteres par `.`, `~` ou un `/` encode
        ("https://a.example.org/t/3f9a8b7c.6d5e4f30.a1b2c3d4.e5f60718", chemin("/t/3f9a8b7c.6d5e4f30.a1b2c3d4.e5f60718")),
        ("https://a.example.org/t/3f9a8b7c6d5e4f3~0a1b2c3d4e5f607", chemin("/t/3f9a8b7c6d5e4f3~0a1b2c3d4e5f607")),
        ("https://a.example.org/t/3f9a8b7c6d5e4f3%2F0a1b2c3d4e5f607", chemin("/t/3f9a8b7c6d5e4f3%2F0a1b2c3d4e5f607")),
        // un jeton dans l'HOTE, URL acceptee par la bibliotheque et sans chemin
        ("https://3f9a8b7c6d5e4f30a1b2.example.org", "https://3f9a8b7c6d5e4f30a1b2.example.org/".to_string()),
        // un jeton dans l'HOTE, URL refusee par la bibliotheque (repli) et sans aucun `/` apres l'autorite
        ("https://3f9a8b7c6d5e4f30a1b2^.example", "https://3f9a8b7c6d5e4f30a1b2^.example".to_string()),
        // encode QUATRE fois : au-dela des trois passes de decodage
        (
            "https://a.example.org/r/%25252533%25252566%25252539%25252561%25252538%25252562%25252537%25252563%25252536%25252564%25252535%25252565%25252534%25252566%25252533%25252530",
            chemin("/r/%25252533%25252566%25252539%25252561%25252538%25252562%25252537%25252563%25252536%25252564%25252535%25252565%25252534%25252566%25252533%25252530"),
        ),
    ];
    assert!(cas.len() >= 9, "table amputee : {} cas", cas.len());
    let fautes = jouer_la_table(&cas);
    assert!(fautes.is_empty(), "une limite dite ne tient plus :{}", fautes.concat());
}

#[test]
fn le_repli_coupe_aussi_le_jeton_du_chemin() {
    let m = MARQUE;
    let cas: Vec<(&str, String)> = vec![
        // `^` est interdit dans un hote : la bibliotheque refuse l'URL, le repli la coupe
        ("https://exa^mple.org/reset/3f9a8b7c6d5e4f30a1b2", format!("https://exa^mple.org/reset/{m}")),
        (
            "https://u:p@exa^mple.org/reset/3f9a8b7c6d5e4f30a1b2?t=1#f",
            format!("https://exa^mple.org/reset/{m} [identifiants coupes] [requete coupee] [fragment coupe]"),
        ),
        // l'hote du repli n'est pas un segment de chemin
        ("https://3f9a8b7c6d5e4f30a1b2^.example/x", "https://3f9a8b7c6d5e4f30a1b2^.example/x".to_string()),
        // sans `://` (un `href` qui commence par `http` sans en etre une) : tout est chemin
        ("httpx/reset/3f9a8b7c6d5e4f30a1b2", format!("httpx/reset/{m}")),
        ("httpx/reset/abc", "httpx/reset/abc".to_string()),
    ];
    assert!(cas.len() >= 5, "table amputee : {} cas", cas.len());
    let fautes = jouer_la_table(&cas);
    assert!(fautes.is_empty(), "repli faux :{}", fautes.concat());
}

#[test]
fn la_borne_de_l_echantillon_tient_apres_le_remplacement() {
    let m = MARQUE;
    // `https://a.example.org/reset/[jeton coupe]/` fait 42 caracteres ; le remplissage porte le total
    // a la borne - 1, a la borne, a la borne + 1. Le remplacement a lieu AVANT la borne : la sortie
    // garde le remplissage que le jeton brut (32 caracteres) aurait pousse dehors.
    let jeton = "3f9a8b7c6d5e4f30a1b2c3d4e5f60718";
    let tete = chemin(&format!("/reset/{m}/"));
    assert_eq!(tete.chars().count(), 42);
    for (k, attendu_len) in [(157usize, 199usize), (158, 200), (159, 200)] {
        let entree = format!("https://a.example.org/reset/{jeton}/{}", "x".repeat(k));
        let vu = url_coupee(&entree);
        let attendu: String = format!("{tete}{}", "x".repeat(k)).chars().take(BORNE_DE_L_ECHANTILLON).collect();
        assert_eq!(attendu.chars().count(), attendu_len);
        assert_eq!(vu, attendu, "remplissage {k}");
    }
    // Multioctet, par le repli (le chemin n'y est pas encode) : la coupe tombe sur un caractere
    // entier, jamais au milieu d'un `é`.
    let tete_repli = format!("https://exa^mple.org/reset/{m}/");
    let n = BORNE_DE_L_ECHANTILLON + 1 - tete_repli.chars().count();
    let entree = format!("https://exa^mple.org/reset/{jeton}/{}", "é".repeat(n));
    let vu = url_coupee(&entree);
    let attendu: String = format!("{tete_repli}{}", "é".repeat(n)).chars().take(BORNE_DE_L_ECHANTILLON).collect();
    assert_eq!(vu, attendu);
    assert!(vu.len() > BORNE_DE_L_ECHANTILLON, "la matiere n'est pas multioctet : {} octets", vu.len());
}

/// (code, stderr, echantillons `source=mail`, texte integral depose)
fn passage(corps: &str, motifs: &str) -> (Option<i32>, String, Vec<String>, String) {
    let (code, err, echantillons, _, tout) = passage_avec_objet("Avis", false, corps, motifs);
    (code, err, echantillons, tout)
}

/// Comme `passage`, avec l'objet du message et `PLUME_MAIL_EMIT_SUBJECT` (`1` si `emettre_l_objet`,
/// absent sinon) : (code, stderr, echantillons, messages, texte integral depose).
fn passage_avec_objet(
    objet: &str,
    emettre_l_objet: bool,
    corps: &str,
    motifs: &str,
) -> (Option<i32>, String, Vec<String>, Vec<String>, String) {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-32-l-jeton-chemin");
    let boite = tmp.join("maildir");
    let spool = tmp.join("spool");
    let new = boite.join("alice").join("new");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::create_dir_all(boite.join("alice").join("cur")).unwrap();
    let brut = format!(
        "From: a@sender.example\r\nTo: alice@example.test\r\nSubject: {objet}\r\nMessage-ID: <j0@sender.example>\r\n\
         Date: Wed, 14 Oct 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{corps}"
    );
    std::fs::write(new.join("1.j0:2,"), brut).unwrap();
    let f = tmp.join("motifs.json");
    std::fs::write(&f, motifs).unwrap();
    let mut c = Command::new(BINAIRE);
    c.arg("scan");
    for (k, _) in std::env::vars() {
        if k.starts_with("PLUME_") {
            c.env_remove(k);
        }
    }
    c.env("PLUME_MAIL_ROOT", &boite)
        .env("PLUME_MAIL_DOMAIN", "example.test")
        .env("PLUME_SPOOL", &spool)
        .env("PLUME_HOST", "hote-de-temoin")
        .env("PLUME_MAIL_CONF", tmp.join("pas-de-mail.conf"))
        .env("PLUME_MAIL_PATTERNS", &f);
    if emettre_l_objet {
        c.env("PLUME_MAIL_EMIT_SUBJECT", "1");
    }
    let sortie = c.output().expect("le binaire du collecteur se lance");
    let (mut echantillons, mut messages, mut tout) = (Vec::new(), Vec::new(), String::new());
    if let Ok(rd) = std::fs::read_dir(&spool) {
        let mut noms: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        noms.sort();
        for p in noms {
            let nom = p.file_name().unwrap().to_string_lossy().to_string();
            if nom.starts_with('.') || !nom.ends_with(".json") {
                continue;
            }
            let texte = std::fs::read_to_string(&p).unwrap();
            tout.push_str(&texte);
            let doc: serde_json::Value = serde_json::from_str(&texte).unwrap();
            for ev in doc["events"].as_array().cloned().unwrap_or_default() {
                if ev["source"] == "mail" {
                    echantillons.push(ev["fields"]["sample"].as_str().unwrap_or("").to_string());
                    messages.push(ev["message"].as_str().unwrap_or("").to_string());
                }
            }
        }
    }
    (sortie.status.code(), String::from_utf8_lossy(&sortie.stderr).into_owned(), echantillons, messages, tout)
}

const JETON_DU_COURRIEL: &str = "3f9a8b7c6d5e4f30a1b2c3d4e5f60718";

#[test]
fn le_binaire_ne_depose_pas_le_jeton_d_un_motif_url() {
    let motifs = r#"[{"id":"t-url","category":"mail","severity":1,"target":"url","regex":"reset"}]"#;
    let corps = format!("Reinitialiser : https://login.example.org/reset/{JETON_DU_COURRIEL}\r\n");
    let (code, err, echantillons, tout) = passage(&corps, motifs);
    assert_eq!(code, Some(0), "{err}");
    assert!(!tout.contains(JETON_DU_COURRIEL), "le jeton du chemin est sorti :\n{tout}");
    assert_eq!(echantillons, vec![format!("https://login.example.org/reset/{MARQUE}")]);
}

#[test]
fn le_binaire_ne_depose_pas_le_jeton_d_une_url_trouvee_dans_le_corps() {
    let motifs = r#"[{"id":"t-texte","category":"mail","severity":1,"target":"text_body","regex":"Reinitialiser : \\S+"}]"#;
    let corps = format!("Reinitialiser : https://login.example.org/reset/{JETON_DU_COURRIEL}\r\n");
    let (code, err, echantillons, tout) = passage(&corps, motifs);
    assert_eq!(code, Some(0), "{err}");
    assert!(!tout.contains(JETON_DU_COURRIEL), "le jeton du chemin est sorti :\n{tout}");
    assert_eq!(echantillons, vec![format!("Reinitialiser : https://login.example.org/reset/{MARQUE}")]);
}

/// Dans un TEXTE, le schema d'une URL se reconnait sans egard a la casse : chaque partie qui sort coupee
/// d'une URL en minuscules sort coupee de la meme URL en capitales ou en casse melee (le schema sort en
/// minuscules, tel que la bibliotheque le normalise).
#[test]
fn le_schema_d_une_url_dans_un_texte_se_reconnait_sans_egard_a_la_casse() {
    let m = MARQUE;
    let mut cas: Vec<(String, String)> = Vec::new();
    for (schema, normalise) in [("HTTPS", "https"), ("Https", "https"), ("hTTp", "http")] {
        // jeton dans le chemin
        cas.push((
            format!("Lien {schema}://a.example.org/reset/3f9a8b7c6d5e4f30a1b2 fin"),
            format!("Lien {normalise}://a.example.org/reset/{m} fin"),
        ));
        // requete
        cas.push((
            format!("Lien {schema}://a.example.org/p?t=TOKCASSE fin"),
            format!("Lien {normalise}://a.example.org/p [requete coupee] fin"),
        ));
        // fragment
        cas.push((
            format!("Lien {schema}://a.example.org/p#FRAGCASSE fin"),
            format!("Lien {normalise}://a.example.org/p [fragment coupe] fin"),
        ));
        // identifiants
        cas.push((
            format!("Lien {schema}://u:p@a.example.org/p fin"),
            format!("Lien {normalise}://a.example.org/p [identifiants coupes] fin"),
        ));
    }
    assert!(cas.len() >= 12, "table amputee : {} cas", cas.len());
    let mut fautes = Vec::new();
    for (entree, attendu) in &cas {
        let vu = texte_assaini(entree);
        if &vu != attendu {
            fautes.push(format!("\n  {entree}\n    attendu {attendu}\n    vu      {vu}"));
        }
    }
    assert!(fautes.is_empty(), "URL a schema en capitales non coupee(s) :{}", fautes.concat());
}

#[test]
fn le_binaire_coupe_une_url_a_schema_en_capitales_trouvee_dans_le_corps() {
    let motifs = r#"[{"id":"t-texte","category":"mail","severity":1,"target":"text_body","regex":"Reinitialiser : \\S+"}]"#;
    let corps = format!("Reinitialiser : HTTPS://login.example.org/reset/{JETON_DU_COURRIEL}?t=TOKCASSE\r\n");
    let (code, err, echantillons, tout) = passage(&corps, motifs);
    assert_eq!(code, Some(0), "{err}");
    for secret in [JETON_DU_COURRIEL, "TOKCASSE"] {
        assert!(!tout.contains(secret), "`{secret}` est sorti :\n{tout}");
    }
    assert_eq!(
        echantillons,
        vec![format!("Reinitialiser : https://login.example.org/reset/{MARQUE} [requete coupee]")]
    );
}

/// Les limites du TEXTE que l'en-tete du module dit : elles sortent encore, telles quelles.
#[test]
fn les_limites_du_texte_dites_par_l_en_tete_sortent_encore() {
    let cas: Vec<&str> = vec![
        // un autre schema
        "voir ftp://a.example.org/r/3f9a8b7c6d5e4f30a1b2?t=x",
        // sans schema
        "voir www.example.org/r/3f9a8b7c6d5e4f30a1b2?t=x",
    ];
    assert!(cas.len() >= 2, "table amputee : {} cas", cas.len());
    for entree in &cas {
        assert_eq!(texte_assaini(entree), *entree, "une limite dite ne tient plus");
    }
    // L'extraction offerte aux motifs `url` reste sensible a la casse (temoin positif d'abord).
    assert_eq!(url_extract::extract_urls(None, Some("voir https://a.example.org/x")).len(), 1);
    assert!(url_extract::extract_urls(None, Some("voir HTTPS://a.example.org/x")).is_empty());
}

/// La borne de l'objet, ecrite ICI : `OBJET_MAX` de la production ne se compare pas a elle-meme.
const BORNE_DE_L_OBJET: usize = 80;

/// L'objet demande est assaini sur sa longueur ENTIERE, puis borne. Un jeton de seize caracteres
/// (`JETON_MIN` tout juste) termine l'objet a la borne - 1, a la borne, a la borne + 1 : tronque d'abord,
/// le dernier cas laissait sortir quinze caracteres du jeton, trop peu pour etre juges.
#[test]
fn l_objet_demande_est_juge_avant_d_etre_borne() {
    let m = MARQUE;
    let jeton = "0123456789abcdef";
    for longueur in [BORNE_DE_L_OBJET - 1, BORNE_DE_L_OBJET, BORNE_DE_L_OBJET + 1] {
        let tete = format!("{} ", "x".repeat(longueur - 41));
        let objet = format!("{tete}https://a.example.org/r/{jeton}");
        assert_eq!(objet.chars().count(), longueur);
        let attendu = format!("{tete}https://a.example.org/r/{m}");
        assert_eq!(objet_emis(&objet, true), attendu, "objet de {longueur} caracteres");
        // la meme valeur d'objet dans un echantillon d'en-tetes
        let h = format!("X-Sonde: a\r\nSubject: {objet}");
        assert_eq!(
            echantillon_d_en_tetes(&h, 0, h.len(), true),
            format!("X-Sonde: a\r\nSubject: {attendu}"),
            "valeur d'objet de {longueur} caracteres"
        );
    }
    // La borne tombe dix caracteres DANS un jeton long : rien du jeton ne sort, la borne coupe la marque.
    let jeton_long = "3f9a8b7c6d5e4f30a1b2c3d4e5f60718";
    let tete = format!("{} ", "x".repeat(45));
    let objet = format!("{tete}https://a.example.org/r/{jeton_long}");
    let attendu = format!("{tete}https://a.example.org/r/[jeton cou");
    assert_eq!(attendu.chars().count(), BORNE_DE_L_OBJET);
    assert_eq!(objet_emis(&objet, true), attendu);
    let h = format!("Subject: {objet}");
    assert_eq!(echantillon_d_en_tetes(&h, 0, h.len(), true), format!("Subject: {attendu}"));
    // Une partie locale qui chevauche la borne : masquee avant la coupe (tronquee d'abord, elle perdait
    // son `@` et sortait par ses premiers caracteres).
    let tete = "x".repeat(70);
    let objet = format!("{tete} alice.martin@example.org");
    assert_eq!(objet_emis(&objet, true), format!("{tete} *@example"));
    let h = format!("Subject: {objet}");
    assert_eq!(echantillon_d_en_tetes(&h, 0, h.len(), true), format!("Subject: {tete} *@example"));
}

/// L'echantillon d'en-tetes est assaini morceau par morceau : avant la valeur d'objet, apres elle, la
/// valeur elle-meme ; la borne de l'objet compte depuis le debut de la VALEUR ; la borne de l'echantillon
/// tient sur l'ensemble.
#[test]
fn l_echantillon_d_en_tetes_assainit_chaque_morceau_et_tient_ses_deux_bornes() {
    // Avant la valeur : partie locale masquee, requete coupee, l'objet demande ou non.
    let h = "X-Sonde: <jean@example.org> https://a.example.org/p?t=TOKAVANT\r\nSubject: Avis";
    let avant = "X-Sonde: <*@example.org> https://a.example.org/p [requete coupee]\r\nSubject: ";
    assert_eq!(echantillon_d_en_tetes(h, 0, h.len(), true), format!("{avant}Avis"));
    assert_eq!(echantillon_d_en_tetes(h, 0, h.len(), false), format!("{avant}[objet non emis]"));
    // Apres la valeur.
    let h = "Subject: Avis\r\nX-Apres: <jean@example.org>";
    assert_eq!(echantillon_d_en_tetes(h, 0, h.len(), true), "Subject: Avis\r\nX-Apres: <*@example.org>");
    // Le nom de l'en-tete n'est pas masque avec une partie locale collee a lui.
    let h = "Subject:alice@example.org";
    assert_eq!(echantillon_d_en_tetes(h, 0, h.len(), true), "Subject:*@example.org");
    // La correspondance commence au milieu de la valeur : la borne compte depuis le debut de la valeur
    // (soixante caracteres deja passes, vingt de place).
    let h = format!("Subject: {}Z{}", "y".repeat(60), "w".repeat(40));
    let debut = h.find('Z').unwrap();
    assert_eq!(echantillon_d_en_tetes(&h, debut, h.len(), true), format!("Z{}", "w".repeat(19)));
    // La borne de l'echantillon (deux cents caracteres) sur l'ensemble des morceaux.
    let h = format!("X-Sonde: {}\r\nSubject: {}", "a".repeat(150), "b".repeat(100));
    let vu = echantillon_d_en_tetes(&h, 0, h.len(), true);
    assert_eq!(vu, format!("X-Sonde: {}\r\nSubject: {}", "a".repeat(150), "b".repeat(30)));
    assert_eq!(vu.chars().count(), BORNE_DE_L_ECHANTILLON);
}

#[test]
fn le_binaire_juge_l_objet_demande_avant_de_le_borner() {
    let jeton = "0123456789abcdef";
    let tete = format!("Reinit {} ", "x".repeat(BORNE_DE_L_OBJET + 1 - 41 - 7));
    let objet = format!("{tete}https://a.example.org/r/{jeton}");
    assert_eq!(objet.chars().count(), BORNE_DE_L_OBJET + 1);
    let attendu = format!("{tete}https://a.example.org/r/{MARQUE}");
    // Motif `subject` : l'echantillon ET l'objet du message.
    let motifs = r#"[{"id":"t-objet","category":"mail","severity":1,"target":"subject","regex":"Reinit.*"}]"#;
    let (code, err, echantillons, messages, tout) = passage_avec_objet(&objet, true, "Rien.\r\n", motifs);
    assert_eq!(code, Some(0), "{err}");
    assert!(!tout.contains("0123456789abcde"), "le debut du jeton de l'objet est sorti :\n{tout}");
    assert_eq!(echantillons, vec![attendu.clone()]);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains(&format!("| subj: {attendu} |")), "objet du message : {}", messages[0]);
    // Motif `headers` qui couvre l'en-tete `Subject:`.
    let motifs = r#"[{"id":"t-h","category":"mail","severity":1,"target":"headers","regex":"Subject:[^\\r\\n]*"}]"#;
    let (code, err, echantillons, _, tout) = passage_avec_objet(&objet, true, "Rien.\r\n", motifs);
    assert_eq!(code, Some(0), "{err}");
    assert!(!tout.contains("0123456789abcde"), "le debut du jeton de l'objet est sorti :\n{tout}");
    assert_eq!(echantillons, vec![format!("Subject: {attendu}")]);
}
