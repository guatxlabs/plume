//! P10.32-l — UN COURRIEL LEGITIME A JETON NE DEPOSE PAS SON JETON DANS LE SIEM.
//!
//! Ces temoins executent le BINAIRE livre (`plume-collector-mail scan`) contre une boite fabriquee,
//! et lisent ce qu'il a depose dans le spool — exactement ce que le central recevrait. Avant ce lot,
//! l'evenement portait l'URL complete qui avait declenche un motif (requete et fragment compris), la
//! VALEUR base64 decodee d'un parametre, l'objet (160 caracteres) et l'adresse complete de
//! l'expediteur. Chaque secret pose dans la boite est un marqueur unique, cherche dans TOUT le texte
//! depose (message, champs, cles) : il ne doit y figurer nulle part.

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;

use std::path::Path;
use std::process::Command;

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-mail");

/// Les messages de la boite : (nom de fichier, objet, corps texte).
const EXPEDITEUR: &str = "jean.expediteur@sender.example";
const JETON: &str = "JETONSECRET0123456789";
const FRAGMENT: &str = "FRAGMENTSECRET42";
const MOT_DE_PASSE: &str = "pa55wordZZ9";
// base64 (alphabet URL) d'une URL de connexion sur evil.example dont la requete porte VALEUR_DECODEE
const PARAMETRE_B64: &str = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUvbG9naW4_amV0b249VkFMU09OREVERUNPREVFOQ";
const VALEUR_DECODEE: &str = "VALSONDEDECODEE9";
const OBJET_LONG: &str =
    "Urgent : verify your account now, votre acces sera suspendu sous peu sans action de votre part QUEUEDOBJETSECRETE";

fn messages() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "1.m1:2,",
            "Bienvenue".to_string(),
            format!("Confirmez ici : https://login.example.org/account/confirm?token={JETON}&uid=42#{FRAGMENT}\n"),
        ),
        (
            "2.m2:2,",
            "Lettre".to_string(),
            format!("Lire : https://track.example.net/r?d={PARAMETRE_B64}\n"),
        ),
        (
            "3.m3:2,",
            "Fichiers".to_string(),
            format!("Partage : https://jean:{MOT_DE_PASSE}@files.example.org/update\n"),
        ),
        ("4.m4:2,", OBJET_LONG.to_string(), "Rien d'autre.\n".to_string()),
    ]
}

fn poser_la_boite(racine: &Path) {
    let new = racine.join("alice").join("new");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::create_dir_all(racine.join("alice").join("cur")).unwrap();
    for (i, (nom, objet, corps)) in messages().into_iter().enumerate() {
        let brut = format!(
            "From: \"Jean Expediteur\" <{EXPEDITEUR}>\r\nTo: alice@example.test\r\nSubject: {objet}\r\n\
             Message-ID: <m{i}@sender.example>\r\nDate: Wed, 14 Oct 2026 10:00:0{i} +0000\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n{corps}"
        );
        std::fs::write(new.join(nom), brut).unwrap();
    }
}

type Passage = (Option<i32>, String, Vec<serde_json::Value>, String);

/// Un passage du binaire : (code, texte d'erreur, evenements deposes `source=mail`).
fn passage(objet: Option<&str>) -> Passage {
    passage_de(poser_la_boite, objet, None)
}

/// Un passage sur une boite posee par `poser`, avec un fichier de motifs d'exploitant s'il est donne
/// (`PLUME_MAIL_PATTERNS` remplace alors les motifs par defaut).
fn passage_de(poser: fn(&Path), objet: Option<&str>, motifs: Option<&str>) -> Passage {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-32-l");
    let boite = tmp.join("maildir");
    let spool = tmp.join("spool");
    poser(&boite);
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
        // le balayage relit `mail.conf` (P10.33-m) : celui de la machine de test reste dehors
        .env("PLUME_MAIL_CONF", tmp.join("pas-de-mail.conf"));
    if let Some(v) = objet {
        c.env("PLUME_MAIL_EMIT_SUBJECT", v);
    }
    if let Some(m) = motifs {
        let f = tmp.join("motifs.json");
        std::fs::write(&f, m).unwrap();
        c.env("PLUME_MAIL_PATTERNS", &f);
    }
    let sortie = c.output().expect("le binaire du collecteur se lance");
    let mut evenements = Vec::new();
    let mut tout = String::new();
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
                    evenements.push(ev);
                }
            }
        }
    }
    (sortie.status.code(), String::from_utf8_lossy(&sortie.stderr).into_owned(), evenements, tout)
}

fn par_objet<'a>(evenements: &'a [serde_json::Value], msgid: &str) -> &'a serde_json::Value {
    evenements
        .iter()
        .find(|e| e["fields"]["msgid"] == msgid)
        .unwrap_or_else(|| panic!("aucun evenement pour {msgid} : {evenements:#?}"))
}

#[test]
fn aucun_jeton_ni_valeur_decodee_ni_adresse_complete_ne_sort_d_un_courriel() {
    let (code, err, evenements, tout) = passage(None);
    assert_eq!(code, Some(0), "le passage a echoue : {err}");
    assert_eq!(evenements.len(), 4, "quatre messages flagges attendus : {evenements:#?}\n{err}");
    // Les secrets poses dans la boite ne figurent NULLE PART dans ce qui est depose.
    for secret in [JETON, FRAGMENT, "uid=42", MOT_DE_PASSE, VALEUR_DECODEE, PARAMETRE_B64, "evil.example",
                   "jean.expediteur", "Jean Expediteur", "QUEUEDOBJETSECRETE", "verify your account"] {
        assert!(!tout.contains(secret), "`{secret}` est sorti dans le spool :\n{tout}");
    }
    // L'URL sort coupee, et la coupure est DITE.
    let m1 = par_objet(&evenements, "m0@sender.example");
    let s1 = m1["fields"]["sample"].as_str().unwrap();
    assert_eq!(s1, "https://login.example.org/account/confirm [requete coupee] [fragment coupe]", "{m1:#}");
    // Un parametre decode sort par son NOM.
    let m2 = par_objet(&evenements, "m1@sender.example");
    assert_eq!(
        m2["fields"]["sample"].as_str().unwrap(),
        "https://track.example.net/r [requete coupee] [parametre d decode, valeur coupee]",
        "{m2:#}"
    );
    assert!(m2["fields"]["patterns"].as_str().unwrap().contains("decoded-credential"), "{m2:#}");
    // Les identifiants d'une URL sont coupes.
    let m3 = par_objet(&evenements, "m2@sender.example");
    assert_eq!(m3["fields"]["sample"].as_str().unwrap(), "https://files.example.org/update [identifiants coupes]", "{m3:#}");
    // L'objet n'est pas emis par defaut, l'expediteur sort par son domaine.
    for ev in &evenements {
        let m = ev["message"].as_str().unwrap();
        assert!(m.contains("| subj: [objet non emis] |"), "{m}");
        assert!(m.contains("mail ") && m.contains(": *@sender.example -> alice@example.test/"), "{m}");
    }
    let m4 = par_objet(&evenements, "m3@sender.example");
    assert_eq!(m4["fields"]["sample"].as_str().unwrap(), "[objet non emis]", "{m4:#}");
}

#[test]
fn l_objet_ne_sort_que_sur_demande_ecrite_et_tronque() {
    let (code, err, evenements, tout) = passage(Some("1"));
    assert_eq!(code, Some(0), "le passage a echoue : {err}");
    let m4 = par_objet(&evenements, "m3@sender.example");
    let m = m4["message"].as_str().unwrap();
    let tronque: String = OBJET_LONG.chars().take(80).collect();
    assert!(m.contains(&format!("| subj: {tronque} |")), "l'objet demande n'est pas emis tronque a 80 : {m}");
    assert!(!tout.contains("QUEUEDOBJETSECRETE"), "la fin de l'objet, au-dela de 80 caracteres, est sortie");
    // L'URL reste coupee, l'expediteur masque, meme objet demande.
    assert!(!tout.contains(JETON) && !tout.contains("jean.expediteur"), "{tout}");

    // Une valeur posee et non comprise ARRETE le passage, et le dit.
    let (code, err, evenements, _) = passage(Some("oui"));
    assert_eq!(code, Some(1), "PLUME_MAIL_EMIT_SUBJECT=oui : code {code:?} au lieu de 1 ({err})");
    assert!(err.contains("PLUME_MAIL_EMIT_SUBJECT=\"oui\" non compris"), "{err}");
    assert!(evenements.is_empty(), "un passage refuse a quand meme depose des evenements");
    // `0` vaut « non », sans un mot.
    let (code, err, evenements, _) = passage(Some("0"));
    assert_eq!(code, Some(0), "{err}");
    assert!(evenements.iter().all(|e| e["message"].as_str().unwrap().contains("[objet non emis]")));
}

/// Une boite de messages BRUTS (en-tetes compris), un par fichier.
fn poser_des_bruts(racine: &Path, bruts: &[String]) {
    let new = racine.join("alice").join("new");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::create_dir_all(racine.join("alice").join("cur")).unwrap();
    for (i, brut) in bruts.iter().enumerate() {
        std::fs::write(new.join(format!("{}.b{i}:2,", i + 1)), brut).unwrap();
    }
}

fn brut(i: usize, from: &str, entetes: &str, objet: &str, type_: &str, corps: &str) -> String {
    format!(
        "From: {from}\r\nTo: alice@example.test\r\n{entetes}Subject: {objet}\r\nMessage-ID: <b{i}@sender.example>\r\n\
         Date: Wed, 14 Oct 2026 11:00:0{i} +0000\r\nContent-Type: {type_}; charset=utf-8\r\n\r\n{corps}"
    )
}

// Des URL que la bibliotheque `url` REFUSE (`^` est interdit dans un hote) : elles passent par le repli
// de `url_coupee`, et le motif par defaut `credential-url` les retient.
fn boite_d_url_refusees(racine: &Path) {
    poser_des_bruts(
        racine,
        &[
            brut(0, "a@sender.example", "", "Avis", "text/plain", "Lien : https://exa^mple.org/login?token=TOKSONDE4#FRAGSONDE6\r\n"),
            brut(1, "a@sender.example", "", "Avis", "text/plain", "Lien : https://user5:PWSONDE5@exa^mple.org/login\r\n"),
            // Un fragment SANS requete : la coupe au `?` ne l'emporte pas avec elle.
            brut(2, "a@sender.example", "", "Avis", "text/plain", "Lien : https://exa^mple.org/login#FRAGSONDE8\r\n"),
        ],
    );
}

#[test]
fn une_url_que_la_bibliotheque_refuse_est_coupee_par_la_meme_regle() {
    let (code, err, evenements, tout) = passage_de(boite_d_url_refusees, None, None);
    assert_eq!(code, Some(0), "le passage a echoue : {err}");
    for secret in ["TOKSONDE4", "FRAGSONDE6", "PWSONDE5", "user5", "FRAGSONDE8"] {
        assert!(!tout.contains(secret), "`{secret}` est sorti dans le spool :\n{tout}");
    }
    let s0 = par_objet(&evenements, "b0@sender.example")["fields"]["sample"].as_str().unwrap().to_string();
    assert_eq!(s0, "https://exa^mple.org/login [requete coupee] [fragment coupe]");
    let s1 = par_objet(&evenements, "b1@sender.example")["fields"]["sample"].as_str().unwrap().to_string();
    assert_eq!(s1, "https://exa^mple.org/login [identifiants coupes]");
    let s2 = par_objet(&evenements, "b2@sender.example")["fields"]["sample"].as_str().unwrap().to_string();
    assert_eq!(s2, "https://exa^mple.org/login [fragment coupe]");
}

const OBJET_SONDE: &str = "OBJLONG ce texte de l'objet depasse quatre-vingts caracteres, et sa fin ne sort jamais QUEUEOBJSONDE";
// L'objet du message dont l'en-tete est couvert par un motif `headers` : long, lui aussi.
const OBJET_EN_TETE: &str = "OBJSONDE2 confidentiel, un objet d'en-tete qui depasse lui aussi la borne de quatre-vingts QUEUEOBJSONDE2";

// Une cible par message (texte, HTML, en-tetes, expediteur, objet) : chaque message ne declenche QUE son
// motif, l'echantillon de l'evenement est donc le sien.
fn boite_des_cibles(racine: &Path) {
    poser_des_bruts(
        racine,
        &[
            brut(0, "a@sender.example", "", "Avis", "text/plain",
                 "Contact : jean.sonde1@example.org et \"marie curie\"@example.org, lien \
                  https://a.example.org/p?t=TOKSONDE1#FRAGSONDE1 FINTEXTE\r\n"),
            brut(1, "a@sender.example", "", "Avis", "text/html",
                 "<p>HTMLDEBUT ecrire a lea.sonde7@example.org ou https://b.example.org/q?k=TOKSONDE7 HTMLFIN</p>\r\n"),
            brut(2, "a@sender.example", "X-Sonde: <paul.sonde2@example.org>\r\n",
                 OBJET_EN_TETE, "text/plain", "Rien.\r\n"),
            brut(3, "\"S\" <sondefrom3@example.org>", "", "Avis", "text/plain", "Rien.\r\n"),
            brut(4, "a@sender.example", "", OBJET_SONDE, "text/plain", "Rien.\r\n"),
        ],
    );
}

const MOTIFS_DES_CIBLES: &str = r#"[
  {"id":"t-texte","category":"mail","severity":1,"target":"text_body","regex":"(?s)Contact :.*FINTEXTE"},
  {"id":"t-html","category":"mail","severity":1,"target":"html_body","regex":"HTMLDEBUT[^<]*HTMLFIN"},
  {"id":"t-entetes","category":"mail","severity":1,"target":"headers","regex":"X-Sonde:[^\\r\\n]*\\r\\nSubject:[^\\r\\n]*"},
  {"id":"t-exp","category":"mail","severity":1,"target":"from","regex":"sondefrom3"},
  {"id":"t-objet","category":"mail","severity":1,"target":"subject","regex":"OBJLONG.*"}
]"#;

fn echantillon(evenements: &[serde_json::Value], msgid: &str, motif: &str) -> String {
    let e = par_objet(evenements, msgid);
    assert_eq!(e["fields"]["patterns"], motif, "{msgid} : un autre motif que `{motif}` a juge : {e:#}");
    e["fields"]["sample"].as_str().unwrap().to_string()
}

#[test]
fn un_texte_trouve_sort_avec_ses_url_coupees_et_ses_parties_locales_masquees() {
    let (code, err, evenements, tout) = passage_de(boite_des_cibles, None, Some(MOTIFS_DES_CIBLES));
    assert_eq!(code, Some(0), "le passage a echoue : {err}");
    assert_eq!(evenements.len(), 5, "cinq messages flagges attendus : {evenements:#?}\n{err}");
    for secret in ["jean.sonde1", "marie", "curie", "TOKSONDE1", "FRAGSONDE1", "lea.sonde7", "TOKSONDE7",
                   "paul.sonde2", "OBJSONDE2", "sondefrom3", "OBJLONG", "QUEUEOBJSONDE"] {
        assert!(!tout.contains(secret), "`{secret}` est sorti dans le spool :\n{tout}");
    }
    assert_eq!(
        echantillon(&evenements, "b0@sender.example", "t-texte"),
        "Contact : *@example.org et *@example.org, lien https://a.example.org/p [requete coupee] [fragment coupe] FINTEXTE"
    );
    assert_eq!(
        echantillon(&evenements, "b1@sender.example", "t-html"),
        "HTMLDEBUT ecrire a *@example.org ou https://b.example.org/q [requete coupee] HTMLFIN"
    );
    // Un motif d'en-tetes qui couvre `Subject:` ne fait pas sortir l'objet non demande.
    assert_eq!(
        echantillon(&evenements, "b2@sender.example", "t-entetes"),
        "X-Sonde: <*@example.org>\r\nSubject: [objet non emis]"
    );
    assert_eq!(echantillon(&evenements, "b3@sender.example", "t-exp"), "*@example.org");
    assert_eq!(echantillon(&evenements, "b4@sender.example", "t-objet"), "[objet non emis]");
}

#[test]
fn l_objet_demande_reste_borne_dans_tout_echantillon() {
    let (code, err, evenements, tout) = passage_de(boite_des_cibles, Some("1"), Some(MOTIFS_DES_CIBLES));
    assert_eq!(code, Some(0), "le passage a echoue : {err}");
    assert!(!tout.contains("QUEUEOBJSONDE"), "la fin de l'objet, au-dela de 80 caracteres, est sortie :\n{tout}");
    let borne: String = OBJET_SONDE.chars().take(80).collect();
    assert_eq!(echantillon(&evenements, "b4@sender.example", "t-objet"), borne);
    // Demande, l'objet sort dans l'echantillon d'en-tetes, borne lui aussi.
    let borne: String = OBJET_EN_TETE.chars().take(80).collect();
    assert_eq!(
        echantillon(&evenements, "b2@sender.example", "t-entetes"),
        format!("X-Sonde: <*@example.org>\r\nSubject: {borne}")
    );
}

// Huit parametres dont la valeur decodee declenche le motif : la table de hachage qui les porte change
// d'ordre a chaque processus. Le parametre nomme est le premier par ordre lexical, a chaque passage.
fn boite_a_parametres_multiples(racine: &Path) {
    // base64 (alphabet URL) d'une URL de connexion sur evil.example dont la requete porte VALEUR_DECODEE
    let v = PARAMETRE_B64;
    let url = format!("https://track.example.net/r?ph={v}&pc={v}&pf={v}&pa={v}&pg={v}&pd={v}&pb={v}&pe={v}");
    poser_des_bruts(racine, &[brut(0, "a@sender.example", "", "Lettre", "text/plain", &format!("Lire : {url}\r\n"))]);
}

#[test]
fn le_parametre_nomme_est_le_meme_a_chaque_passage() {
    for n in 0..4 {
        let (code, err, evenements, tout) = passage_de(boite_a_parametres_multiples, None, None);
        assert_eq!(code, Some(0), "passage {n} : {err}");
        assert!(!tout.contains(VALEUR_DECODEE), "passage {n} : la valeur decodee est sortie");
        assert_eq!(
            echantillon(&evenements, "b0@sender.example", "decoded-credential"),
            "https://track.example.net/r [requete coupee] [parametre pa decode, valeur coupee]",
            "passage {n}"
        );
    }
}
