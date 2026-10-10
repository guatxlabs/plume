// =================================================================================================
// `P10.23-a` — LA SECTION « TOTP MFA » DE `docs/NATIVE-IDP.md` DIT LE COMPORTEMENT LIVRÉ, ET LE NOMME.
//
// LE DÉFAUT : la section décrivait le flux (connexion -> ticket -> `/api/login/mfa` -> session) sans aucun des
// contrôles posés depuis — ni le frein par compte, ni l'essai compté avant examen, ni le refus nommé d'un pas non
// consommé, ni le 409 de réactivation, ni le mot de passe exigé à l'enrôlement, ni le refus des comptes sans mot
// de passe local, ni la révocation des tickets par l'époque. Un contrôle de sécurité non documenté est un contrôle
// que l'exploitant ne sait ni relire ni opposer.
//
// CE QUE CE TÉMOIN TIENT, ET COMMENT. La documentation n'est pas compilée : rien ne la lie au code, et un symbole
// renommé y laisse une phrase qui ne désigne plus rien. Deux règles, lues sur le fichier à l'exécution :
//   (1) chaque contrôle EXIGÉ est cité dans la section par le symbole qui le porte, et ce symbole est DÉFINI (`const`
//       ou `fn`) dans le fichier de `daemon/src` que la table nomme — la phrase et le code se désignent l'un l'autre ;
//   (2) tout identifiant cité entre accents graves dans la section (un mot qui contient un souligné) existe dans une
//       ligne de CODE de `daemon/src` hors `src/tests/` — une ligne qui commence par `//` ne compte pas : un nom qui
//       ne survit plus que dans un commentaire ne désigne plus rien. Un mot sans souligné (`setting`, `global`) n'est
//       pas jugé ;
//   (3) CORRECTION (vérificateur indépendant) — les phrases que la clé exige ont chacune LEUR puce, dans LEUR
//       sous-section, avec les fragments qui les font (`PHRASES_EXIGEES`) : la phrase du 409 était aussi citée en 4.1
//       et `mfa_verify` en 4.3, si bien que retirer toute la 4.2, ou la puce « Arbitrage », laissait le témoin vert ;
//       et le 409 de réactivation est servi DANS le corps de `mfa_verify`, AVANT `reserver_un_essai` (la phrase était
//       cherchée n'importe où dans `idp.rs`, où `mfa_enroll` la sert deux fois) ;
//   (4) la remise à zéro par le retrait d'un enrôlement EN ATTENTE, que la doc disait impossible (« seul un code juste
//       accepté »), est JOUÉE : trois codes faux à `mfa_verify` comptent trois échecs, `mfa_disable` sans code les
//       efface. Le témoin tient la phrase corrigée au comportement livré.
// Contrôle positif : la section est trouvée et la règle (2) juge au moins autant d'identifiants que la table (1) en
// exige — une section introuvable ou vide ne passe pas pour une section juste.
//
// CE QU'IL NE TIENT PAS : il ne lit pas le SENS des phrases (un statut HTTP faux à côté d'un symbole juste passe) ;
// c'est la relecture qui le tient. Un nom cité dans un commentaire de FIN de ligne de code compte encore.
#[cfg(test)]
mod documentation_du_second_facteur_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Les contrôles que la section DOIT citer : (symbole, fichier sous `daemon/src`, forme de définition).
    const SYMBOLES_EXIGES: &[(&str, &str, &str)] = &[
        // frein par compte, essai compté avant examen, oubli, remise à zéro, durable, vu du SIEM
        ("reserver_un_essai", "handlers/frein_du_second_facteur.rs", "fn"),
        ("CAUSE_SECOND_FACTEUR_FREINE", "handlers/idp.rs", "const"),
        ("CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE", "handlers/frein_du_second_facteur.rs", "const"),
        ("MEMOIRE_DES_ECHECS_S", "handlers/frein_du_second_facteur.rs", "const"),
        ("remettre_a_zero", "handlers/frein_du_second_facteur.rs", "fn"),
        ("rendre_l_essai", "handlers/frein_du_second_facteur.rs", "fn"),
        ("PORTEE_DU_FREIN_DU_SECOND_FACTEUR", "handlers/frein_du_second_facteur.rs", "const"),
        ("tracer_l_echec", "handlers/frein_du_second_facteur.rs", "fn"),
        // pas non consommé : refus nommé, rejeu
        ("consommer_le_pas_totp", "handlers/idp.rs", "fn"),
        ("CAUSE_PAS_TOTP_NON_CONSOMME", "handlers/idp.rs", "const"),
        // 409 de réactivation (porté par `mfa_verify`)
        ("mfa_verify", "handlers/idp.rs", "fn"),
        // mot de passe exigé à l'enrôlement, comptes sans mot de passe local
        ("prouver_le_premier_facteur", "session.rs", "fn"),
        ("CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER", "handlers/idp.rs", "const"),
        ("CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL", "handlers/idp.rs", "const"),
        ("le_compte_a_un_mot_de_passe_local", "session.rs", "fn"),
        // tickets révoqués par l'époque
        ("CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE", "handlers/idp.rs", "const"),
        ("epoque_du_compte", "session.rs", "fn"),
        ("avancer_l_epoque_du_compte", "session.rs", "fn"),
    ];

    /// Le 409 de réactivation est servi sous cette phrase littérale : la section la cite, le code la sert.
    const PHRASE_DU_409_DE_REACTIVATION: &str = "MFA déjà active (désactivez-la d'abord)";

    /// Les phrases exigées : (sous-section, ce qu'elle dit, fragments qu'UNE MÊME puce de cette sous-section porte).
    const PHRASES_EXIGEES: &[(&str, &str, &[&str])] = &[
        ("### 4.2", "le 409 de réactivation", &["**409**", PHRASE_DU_409_DE_REACTIVATION, "`mfa_verify`", "**avant**"]),
        ("### 4.3", "l'arbitrage du frein", &["**Arbitrage**", "`lock_max_s`", "ticket"]),
        ("### 4.3", "la remise à zéro et son exception", &["**Remise à zéro**", "`remettre_a_zero`", "`mfa_disable`", "**en attente**"]),
        (
            "### 4.3",
            "le seuil et les délais, avec leurs variables",
            &["**Seuil et délai**", "`PLUME_AUTH_LOCK_THRESHOLD`", "`PLUME_AUTH_LOCK_BASE_S`", "`PLUME_AUTH_LOCK_MAX_S`"],
        ),
    ];

    /// Ce témoin se nomme dans la section (il vit sous `src/tests/`, que la règle (2) ne lit pas).
    const NOM_DU_TEMOIN: &str = "documentation_du_second_facteur";

    fn racine_du_crate() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// La section `## 4.` jusqu'à la section `## ` suivante (les `### ` en font partie).
    fn section_du_second_facteur() -> String {
        let doc = std::fs::read_to_string(racine_du_crate().join("../docs/NATIVE-IDP.md")).expect("docs/NATIVE-IDP.md lisible");
        let mut dedans = false;
        let mut sortie = String::new();
        for ligne in doc.lines() {
            if ligne.starts_with("## ") {
                if dedans {
                    break;
                }
                dedans = ligne.starts_with("## 4. TOTP MFA");
            }
            if dedans {
                sortie.push_str(ligne);
                sortie.push('\n');
            }
        }
        sortie
    }

    /// Les identifiants cités entre accents graves (mot fait de lettres ASCII, chiffres et soulignés, avec au moins
    /// un souligné) ; les citations composées (`a.b`, `x=0`, `{…}`) ne sont pas des identifiants.
    fn identifiants_cites(section: &str) -> Vec<String> {
        let mut sortie: Vec<String> = section
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|c| c.contains('_') && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
            .map(str::to_owned)
            .collect();
        sortie.sort();
        sortie.dedup();
        sortie
    }

    /// Les puces (`- ` en colonne zéro, avec leurs lignes de suite) de la sous-section dont le titre commence par
    /// `titre`, jusqu'au titre suivant.
    fn puces_de_la_sous_section(section: &str, titre: &str) -> Vec<String> {
        let mut dedans = false;
        let mut puces: Vec<String> = Vec::new();
        for ligne in section.lines() {
            if ligne.starts_with("### ") || ligne.starts_with("## ") {
                dedans = ligne.starts_with(titre);
                continue;
            }
            if !dedans {
                continue;
            }
            if ligne.starts_with("- ") {
                puces.push(ligne.to_owned());
            } else if ligne.starts_with(' ') {
                if let Some(derniere) = puces.last_mut() {
                    derniere.push(' ');
                    derniere.push_str(ligne.trim());
                }
            }
        }
        puces
    }

    /// Le corps de `fn {nom}(` jusqu'à la première accolade fermante en colonne zéro.
    fn corps_de_la_fonction<'a>(code: &'a str, nom: &str) -> &'a str {
        let debut = code.find(&format!("fn {nom}(")).unwrap_or(code.len());
        let reste = &code[debut..];
        &reste[..reste.find("\n}\n").unwrap_or(reste.len())]
    }

    fn sources_hors_tests(rep: &Path, sortie: &mut String) {
        for entree in std::fs::read_dir(rep).expect("daemon/src lisible") {
            let chemin = entree.expect("entrée lisible").path();
            if chemin.is_dir() {
                if chemin.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                sources_hors_tests(&chemin, sortie);
            } else if chemin.extension().is_some_and(|e| e == "rs") {
                let source = std::fs::read_to_string(&chemin).expect("source lisible");
                for ligne in source.lines().filter(|l| !l.trim_start().starts_with("//")) {
                    sortie.push_str(ligne);
                    sortie.push('\n');
                }
            }
        }
    }

    /// `mot` figure dans `texte` comme mot entier (ni précédé ni suivi d'une lettre, d'un chiffre ou d'un souligné).
    fn contient_le_mot(texte: &str, mot: &str) -> bool {
        let est_mot = |c: char| c.is_ascii_alphanumeric() || c == '_';
        texte.match_indices(mot).any(|(i, _)| {
            let avant = texte[..i].chars().next_back().map_or(true, |c| !est_mot(c));
            let apres = texte[i + mot.len()..].chars().next().map_or(true, |c| !est_mot(c));
            avant && apres
        })
    }

    #[test]
    fn dsf_chaque_controle_exige_est_cite_par_le_symbole_qui_le_porte() {
        let section = section_du_second_facteur();
        assert!(!section.is_empty(), "section `## 4. TOTP MFA` introuvable dans docs/NATIVE-IDP.md");
        let cites = identifiants_cites(&section);
        let src = racine_du_crate().join("src");
        let mut manquants = Vec::new();
        for (symbole, fichier, forme) in SYMBOLES_EXIGES {
            if !cites.iter().any(|c| c == symbole) {
                manquants.push(format!("`{symbole}` non cité dans la section"));
            }
            let code = std::fs::read_to_string(src.join(fichier)).unwrap_or_default();
            let definition = match *forme {
                "const" => format!("const {symbole}:"),
                _ => format!("fn {symbole}("),
            };
            if !code.contains(&definition) {
                manquants.push(format!("`{definition}` absent de daemon/src/{fichier}"));
            }
        }
        if !section.contains(PHRASE_DU_409_DE_REACTIVATION) {
            manquants.push(format!("le 409 de réactivation « {PHRASE_DU_409_DE_REACTIVATION} » non cité"));
        }
        let idp = std::fs::read_to_string(src.join("handlers/idp.rs")).expect("handlers/idp.rs lisible");
        let verify = corps_de_la_fonction(&idp, "mfa_verify");
        let refus = verify.find(&format!("StatusCode::CONFLICT, \"{PHRASE_DU_409_DE_REACTIVATION}\""));
        let essai = verify.find("reserver_un_essai(");
        match (refus, essai) {
            (Some(r), Some(e)) if r < e => {}
            (None, _) => manquants.push("le 409 de réactivation n'est plus servi par `mfa_verify` sous la phrase citée".to_owned()),
            _ => manquants.push("`mfa_verify` ne sert plus le 409 de réactivation AVANT `reserver_un_essai`".to_owned()),
        }
        assert!(manquants.is_empty(), "docs/NATIVE-IDP.md §4 ne dit pas le comportement livré :\n  {}", manquants.join("\n  "));
    }

    #[test]
    fn dsf_chaque_phrase_exigee_a_sa_puce_dans_sa_sous_section() {
        let section = section_du_second_facteur();
        let mut manquantes = Vec::new();
        for (titre, objet, fragments) in PHRASES_EXIGEES {
            let puces = puces_de_la_sous_section(&section, titre);
            if !puces.iter().any(|p| fragments.iter().all(|f| p.contains(f))) {
                manquantes.push(format!("{titre} : aucune puce ne dit {objet} (fragments exigés ensemble : {fragments:?})"));
            }
        }
        assert!(manquantes.is_empty(), "docs/NATIVE-IDP.md §4 :\n  {}", manquantes.join("\n  "));
    }

    /// LA PHRASE CORRIGÉE, JOUÉE. Trois codes faux à l'activation d'un enrôlement EN ATTENTE comptent trois échecs au
    /// frein ; `mfa_disable` sans code retire l'enrôlement (200) et remet le compte à zéro.
    #[tokio::test]
    async fn dsf_retirer_un_enrolement_en_attente_remet_le_frein_a_zero() {
        let (st, _p) = sp_state("dsf-attente");
        let graine = base32_encode(b"12345678901234567890");
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,0,'[]',-1,0,0)",
                params![graine],
            )
            .expect("fixture : enrôlement en attente");
        assert!(st.lock_threshold > 3, "fixture : trois échecs restent sous le seuil ({})", st.lock_threshold);
        let pair: std::net::SocketAddr = "10.77.0.1:45454".parse().expect("adresse");
        let pas = now() / 30;
        let justes: Vec<String> = (-3..=3).map(|d| hotp(&base32_decode(&graine).expect("graine"), (pas + d) as u64, 6)).collect();
        let faux: Vec<String> = (0..1000u32).map(|k| format!("{:06}", k * 997 + 3)).filter(|c| !justes.contains(c)).take(3).collect();
        for code in &faux {
            let r = mfa_verify(State(st.clone()), ConnectInfo(pair), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await;
            assert_eq!(r.status().as_u16(), 401, "un code faux à l'activation est refusé");
        }
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "adm"), 3, "trois échecs comptés");
        let r = mfa_disable(State(st.clone()), ConnectInfo(pair), Extension(sp_au("adm", "admin")), Json(json!({ "code": "" }))).await;
        assert_eq!(r.status().as_u16(), 200, "un enrôlement en attente se retire sans code");
        assert_eq!(
            crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "adm"),
            0,
            "le retrait d'un enrôlement en attente remet le compte à zéro, comme le dit docs/NATIVE-IDP.md §4.3"
        );
    }

    #[test]
    fn dsf_chaque_identifiant_cite_existe_dans_le_code() {
        let section = section_du_second_facteur();
        let cites = identifiants_cites(&section);
        assert!(
            cites.len() >= SYMBOLES_EXIGES.len(),
            "contrôle positif : {} identifiant(s) cité(s), au moins {} attendus — section introuvable ou vide",
            cites.len(),
            SYMBOLES_EXIGES.len()
        );
        let mut code = String::new();
        sources_hors_tests(&racine_du_crate().join("src"), &mut code);
        let orphelins: Vec<&String> = cites.iter().filter(|c| c.as_str() != NOM_DU_TEMOIN && !contient_le_mot(&code, c)).collect();
        assert!(orphelins.is_empty(), "docs/NATIVE-IDP.md §4 cite des noms absents du code (hors tests) : {orphelins:?}");
    }
}
