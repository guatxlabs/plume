//! P10.32-l — CE QUE LES PREMIERS TEMOINS DE L'ECHANTILLON NE JOUAIENT PAS.
//!
//! Le BINAIRE livre (`plume-collector-mail scan`) contre une boite fabriquee ; on lit ce qu'il depose
//! dans le spool. Chaque cas est une regle de `confidentialite.rs` qu'aucun temoin ne faisait rougir :
//!   * un objet PLIE sur plusieurs lignes (continuation RFC 5322) et un en-tete `SUBJECT:` en capitales,
//!     couverts par un motif `headers` : la valeur ne sort pas, suite pliee comprise ;
//!   * l'objet DEMANDE (`PLUME_MAIL_EMIT_SUBJECT=1`) sort ASSAINI : partie locale masquee, requete coupee ;
//!   * la borne de 200 caracteres d'un texte trouve, et les marques de coupure qui y SURVIVENT ;
//!   * le repli de `url_coupee` (URL que la bibliotheque refuse) coupe les identifiants jusqu'au DERNIER
//!     `@` de l'autorite — un mot de passe qui contient `@` ne sort pas a moitie ;
//!   * le port d'une URL est garde.

#[path = "../src/tmp_possede.rs"]
mod tmp_possede;


use std::process::Command;

const BINAIRE: &str = env!("CARGO_BIN_EXE_plume-collector-mail");

/// (code, stderr, evenements `source=mail`, texte integral depose).
type Passage = (Option<i32>, String, Vec<serde_json::Value>, String);

/// Une boite d'UN message brut, jouee avec les motifs donnes (`None` = motifs par defaut).
fn passage(brut: &str, objet: Option<&str>, motifs: Option<&str>) -> Passage {
    let tmp = tmp_possede::TmpPossede::neuf("mail-p10-32-l-bornes");
    let boite = tmp.join("maildir");
    let spool = tmp.join("spool");
    let new = boite.join("alice").join("new");
    std::fs::create_dir_all(&new).unwrap();
    std::fs::create_dir_all(boite.join("alice").join("cur")).unwrap();
    std::fs::write(new.join("1.s0:2,"), brut).unwrap();
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
        .env("PLUME_HOST", "hote-de-temoin");
    if let Some(v) = objet {
        c.env("PLUME_MAIL_EMIT_SUBJECT", v);
    }
    if let Some(m) = motifs {
        let f = tmp.join("motifs.json");
        std::fs::write(&f, m).unwrap();
        c.env("PLUME_MAIL_PATTERNS", &f);
    }
    let sortie = c.output().expect("le binaire du collecteur se lance");
    let (mut evenements, mut tout) = (Vec::new(), String::new());
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

/// L'evenement unique du passage, juge par le motif attendu.
fn unique<'a>(p: &'a Passage, motif: &str) -> &'a serde_json::Value {
    let (code, err, evenements, _) = p;
    assert_eq!(*code, Some(0), "le passage a echoue : {err}");
    assert_eq!(evenements.len(), 1, "un evenement attendu : {evenements:#?}\n{err}");
    let e = &evenements[0];
    assert_eq!(e["fields"]["patterns"], motif, "un autre motif que `{motif}` a juge : {e:#}");
    e
}

fn echantillon(e: &serde_json::Value) -> String {
    e["fields"]["sample"].as_str().unwrap().to_string()
}

/// Un message : en-tetes donnes tels quels (`Subject` compris), corps texte.
fn brut(entetes: &str, corps: &str) -> String {
    format!(
        "From: a@sender.example\r\nTo: alice@example.test\r\n{entetes}Message-ID: <s0@sender.example>\r\n\
         Date: Wed, 14 Oct 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{corps}"
    )
}

const MOTIF_ENTETES_PLIES: &str = r#"[
  {"id":"t-h","category":"mail","severity":1,"target":"headers","regex":"X-Sonde:[^\\r\\n]*\\r\\nSubject:[^\\r\\n]*\\r\\n [^\\r\\n]*"}
]"#;

#[test]
fn un_objet_plie_ne_sort_pas_par_sa_ligne_de_continuation() {
    let p = passage(&brut("X-Sonde: a\r\nSubject: debut OBJPLIEA\r\n suite OBJPLIEB\r\n", "Rien.\r\n"), None,
                    Some(MOTIF_ENTETES_PLIES));
    let e = unique(&p, "t-h");
    for secret in ["OBJPLIEA", "OBJPLIEB", "suite"] {
        assert!(!p.3.contains(secret), "`{secret}` (objet plie) est sorti :\n{}", p.3);
    }
    assert_eq!(echantillon(e), "X-Sonde: a\r\nSubject: [objet non emis]");
}

#[test]
fn un_en_tete_subject_en_capitales_est_un_objet() {
    let motifs = r#"[
  {"id":"t-h","category":"mail","severity":1,"target":"headers","regex":"X-Sonde:[^\\r\\n]*\\r\\nSUBJECT:[^\\r\\n]*"}
]"#;
    let p = passage(&brut("X-Sonde: a\r\nSUBJECT: OBJCAPITALES\r\n", "Rien.\r\n"), None, Some(motifs));
    let e = unique(&p, "t-h");
    assert!(!p.3.contains("OBJCAPITALES"), "l'objet d'un en-tete `SUBJECT:` est sorti :\n{}", p.3);
    assert_eq!(echantillon(e), "X-Sonde: a\r\nSUBJECT: [objet non emis]");
}

#[test]
fn l_objet_demande_sort_assaini() {
    // Le motif juge l'expediteur : l'objet ne passe que par `objet_emis`, dans le message.
    let motifs = r#"[{"id":"t-exp","category":"mail","severity":1,"target":"from","regex":"sender"}]"#;
    let objet = "Avis jean.objsonde@example.org https://a.example.org/p?t=TOKOBJSONDE";
    let p = passage(&brut(&format!("Subject: {objet}\r\n"), "Rien.\r\n"), Some("1"), Some(motifs));
    let e = unique(&p, "t-exp");
    for secret in ["jean.objsonde", "TOKOBJSONDE"] {
        assert!(!p.3.contains(secret), "`{secret}` (objet demande) est sorti :\n{}", p.3);
    }
    let m = e["message"].as_str().unwrap();
    assert!(
        m.contains("| subj: Avis *@example.org https://a.example.org/p [requete coupee] |"),
        "l'objet demande ne sort pas assaini : {m}"
    );
}

#[test]
fn un_texte_trouve_est_borne_a_deux_cents_caracteres() {
    let motifs = r#"[{"id":"t-texte","category":"mail","severity":1,"target":"text_body","regex":"(?s)DEBUTLONG.*QUEUELONGUE"}]"#;
    let corps = format!("DEBUTLONG {} QUEUELONGUE\r\n", "x".repeat(300));
    let p = passage(&brut("Subject: Avis\r\n", &corps), None, Some(motifs));
    let s = echantillon(unique(&p, "t-texte"));
    assert_eq!(s.chars().count(), 200, "echantillon de {} caracteres : {s}", s.chars().count());
    assert!(s.starts_with("DEBUTLONG ") && !p.3.contains("QUEUELONGUE"), "{s}");
}

#[test]
fn les_marques_de_coupure_survivent_a_la_borne() {
    let motifs = r#"[{"id":"t-url","category":"mail","severity":1,"target":"url","regex":"cheminlong"}]"#;
    let url = format!("https://a.example.org/cheminlong{}?t=TOKLONGSONDE#FRAGLONGSONDE", "a".repeat(300));
    let p = passage(&brut("Subject: Avis\r\n", &format!("Lien : {url}\r\n")), None, Some(motifs));
    let s = echantillon(unique(&p, "t-url"));
    assert!(!p.3.contains("TOKLONGSONDE") && !p.3.contains("FRAGLONGSONDE"), "{}", p.3);
    assert!(s.ends_with("a [requete coupee] [fragment coupe]"), "les marques de coupure n'ont pas survecu : {s}");
    assert_eq!(s.chars().count(), 200, "echantillon de {} caracteres : {s}", s.chars().count());
}

#[test]
fn le_repli_coupe_les_identifiants_jusqu_au_dernier_arobase() {
    // `^` est interdit dans un hote : la bibliotheque refuse l'URL, le repli la coupe (motif par defaut
    // `credential-url`, chemin `/login`).
    let corps = "Lien : https://user9:PWDEBUT9@PWSUITE9@exa^mple.org/login\r\n";
    let p = passage(&brut("Subject: Avis\r\n", corps), None, None);
    let (code, err, evenements, tout) = &p;
    assert_eq!(*code, Some(0), "{err}");
    for secret in ["user9", "PWDEBUT9", "PWSUITE9"] {
        assert!(!tout.contains(secret), "`{secret}` (identifiants) est sorti :\n{tout}");
    }
    assert_eq!(evenements.len(), 1, "{evenements:#?}");
    assert_eq!(echantillon(&evenements[0]), "https://exa^mple.org/login [identifiants coupes]");
}

#[test]
fn le_port_d_une_url_est_garde() {
    let corps = "Confirmez : https://login.example.org:8443/account/confirm?token=TOKPORTSONDE\r\n";
    let p = passage(&brut("Subject: Avis\r\n", corps), None, None);
    let (code, err, evenements, tout) = &p;
    assert_eq!(*code, Some(0), "{err}");
    assert!(!tout.contains("TOKPORTSONDE"), "{tout}");
    assert_eq!(evenements.len(), 1, "{evenements:#?}");
    assert_eq!(echantillon(&evenements[0]), "https://login.example.org:8443/account/confirm [requete coupee]");
}

