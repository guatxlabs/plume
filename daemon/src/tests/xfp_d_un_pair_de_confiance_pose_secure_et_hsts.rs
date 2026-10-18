// `P10.32-t` (décision de l'exploitant, et les deux restes de la ligne) — X-FORWARDED-PROTO D'UN PAIR DE CONFIANCE.
//
// DÉCISION : `PLUME_TLS_TERMINATED_UPSTREAM=1` reste prioritaire. En REPLI, `X-Forwarded-Proto: https` vaut TLS amont
// UNIQUEMENT si le pair TCP figure dans une liste `PLUME_TRUSTED_PROXIES` EXPLICITE et NON VIDE — jamais par le repli
// « pairs privés » de `proxy_is_trusted`. Le secret d'edge n'entre pas en jeu.
//
// TENU : `auth::https_annonce_par_un_pair_de_confiance` (PURE, variante stricte) lue par `auth::https_vu_par_la_requete`
// sur LA requête ; `security_headers` calcule ce booléen une fois par requête et en rend HSTS (`hsts_pour`) ET l'attribut
// `Secure` de chaque cookie de la réponse (`session::poser_l_attribut_secure`, rendu par `cookie_secure_suffix_pour`).
// Aucun gestionnaire n'écrit plus `Secure` lui-même : un seul site, un seul prédicat, pour les deux.
//
// RESTES DE LA LIGNE : la condition « sans TLS natif » de la ligne de démarrage `[tls]` (sous-processus : réglage à 1
// AVEC TLS natif -> aucune ligne) et l'entrée `PLUME_TLS_TERMINATED_UPSTREAM` du paquet de diagnostic (valeur servie).
//
// MUTANTS JOUÉS (sous cfg!(test), par variable de mutation, retirés avant le commit) : `t_repli_prive` (liste vide -> politique privée),
// `t_liste_ignoree` (pair non comparé à la liste), `t_entete_ignore` (valeur de l'en-tête non lue), `t_premiere_valeur`
// (première valeur seule), `t_hsts_sans_annonce` et `t_cookie_sans_annonce` (un des deux rendus laisse tomber l'annonce),
// `t_secure_double` (un cookie déjà `Secure` le reçoit deux fois), `t_ligne_sans_condition_native` (ligne `[tls]` même
// avec TLS natif), `t_diag_sans_cle` (l'entrée retirée du paquet de diagnostic), `t_premiere_ligne_seule` (seule la
// première ligne `X-Forwarded-Proto` est lue).
mod xfp_d_un_pair_de_confiance_pose_secure_et_hsts {
    use super::*;

    /// Adresses de documentation (RFC 5737) : un mandataire déclaré, et un pair hors liste.
    const MANDATAIRE: &str = "192.0.2.10";
    const HORS_LISTE: &str = "192.0.2.11";
    /// Clé de signature des sessions fournie aux enfants (fixture de test, pas un secret).
    const SIGNATURE_DE_TEST: &str = "temoin-p1032t-xfp-signature-de-test";
    const HSTS_ATTENDU: &str = "max-age=31536000; includeSubDomains";

    fn liste(adresses: &[&str]) -> Vec<String> {
        adresses.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn p1032t_xfp_vaut_https_seulement_pour_un_pair_de_la_liste_explicite() {
        let declaree = liste(&[MANDATAIRE]);
        let f = crate::auth::https_annonce_par_un_pair_de_confiance;
        // Pair de la liste, en-tête https (casse, espaces, liste toute https) -> vrai ; pair replié (v4 dans v6) -> vrai.
        for v in ["https", "HTTPS", " https ", "https, https"] {
            assert!(f(MANDATAIRE, Some(v), &declaree), "pair déclaré + X-Forwarded-Proto {v:?} -> https attendu");
        }
        assert!(f(&format!("::ffff:{MANDATAIRE}"), Some("https"), &declaree), "pair déclaré replié -> https attendu");
        // Pair hors liste -> faux.
        assert!(!f(HORS_LISTE, Some("https"), &declaree), "pair hors liste : l'en-tête ne vaut rien");
        // Liste VIDE : jamais, même pour un pair que la politique par défaut de `proxy_is_trusted` croit (privé, loopback).
        for pair in ["127.0.0.1", "10.42.0.7", "::1"] {
            assert!(crate::auth::proxy_is_trusted(pair, &[]), "contrôle : {pair} est de confiance pour l'IP réelle sous la liste vide");
            assert!(!f(pair, Some("https"), &[]), "liste vide + pair {pair} : le repli « pairs privés » ne vaut pas TLS amont");
        }
        // Valeur autre que https, absente, ou une valeur http dans la liste -> faux.
        for v in ["http", "", "httpsx", "https, http", "http, https", "wss"] {
            assert!(!f(MANDATAIRE, Some(v), &declaree), "X-Forwarded-Proto {v:?} -> rien attendu");
        }
        assert!(!f(MANDATAIRE, None, &declaree), "en-tête absent -> rien");
        assert!(!f("", Some("https"), &declaree), "pair inconnu (aucune information de connexion) -> rien");
    }

    /// `X-Forwarded-Proto` sur PLUSIEURS lignes : une seule liste (RFC 9110 §5.3). `https` puis `http` (un mandataire qui
    /// ajoute sa ligne) -> rien ; `https` puis `https` -> https ; une ligne seule se juge comme avant.
    #[test]
    fn p1032t_xfp_sur_plusieurs_lignes_chaque_ligne_doit_valoir_https() {
        use axum::http::{HeaderMap, HeaderValue};
        let declaree = liste(&[MANDATAIRE]);
        let lignes = |valeurs: &[&'static str]| {
            let mut h = HeaderMap::new();
            for v in valeurs {
                h.append("x-forwarded-proto", HeaderValue::from_static(v));
            }
            h
        };
        let f = crate::auth::https_annonce_par_les_entetes;
        assert!(!f(MANDATAIRE, &lignes(&["https", "http"]), &declaree), "lignes https puis http -> rien attendu");
        assert!(!f(MANDATAIRE, &lignes(&["https", "https, http"]), &declaree), "seconde ligne avec une valeur http -> rien");
        assert!(f(MANDATAIRE, &lignes(&["https", "https"]), &declaree), "deux lignes https -> https attendu");
        assert!(f(MANDATAIRE, &lignes(&["https"]), &declaree), "une ligne https -> https attendu");
        assert!(!f(MANDATAIRE, &lignes(&[]), &declaree), "aucune ligne -> rien");
        assert!(!f(HORS_LISTE, &lignes(&["https", "https"]), &declaree), "pair hors liste -> rien");
    }

    #[test]
    fn p1032t_l_attribut_secure_est_pose_une_fois_sur_chaque_cookie() {
        use axum::http::{header, HeaderMap, HeaderValue};
        let entetes = || {
            let mut h = HeaderMap::new();
            h.append(header::SET_COOKIE, HeaderValue::from_static("plume_session=a; HttpOnly; SameSite=Strict; Path=/"));
            h.append(header::SET_COOKIE, HeaderValue::from_static("plume_oidc=b; HttpOnly; Path=/api/auth/oidc; secure"));
            h.append(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            h
        };
        let lus = |h: &HeaderMap| -> Vec<String> {
            h.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect()
        };
        let mut h = entetes();
        crate::session::poser_l_attribut_secure(&mut h, "; Secure");
        assert_eq!(
            lus(&h),
            vec![
                "plume_session=a; HttpOnly; SameSite=Strict; Path=/; Secure".to_string(),
                "plume_oidc=b; HttpOnly; Path=/api/auth/oidc; secure".to_string(),
            ],
            "Secure ajouté au cookie qui ne l'a pas, jamais doublé sur celui qui l'a"
        );
        assert_eq!(h.get(header::CONTENT_TYPE).unwrap(), "application/json", "les autres en-têtes ne bougent pas");
        let mut h = entetes();
        crate::session::poser_l_attribut_secure(&mut h, "");
        assert_eq!(lus(&h), lus(&entetes()), "suffixe vide : les cookies sont inchangés");
    }

    /// Plus aucun gestionnaire n'écrit `Secure` : le seul site est `security_headers` (lu par
    /// `p1032t_les_deux_sites_lisent_le_meme_etat_et_le_meme_predicat`). Un `{secure}` ou un `; Secure` réintroduit dans
    /// une construction de cookie ferait un second site de décision, qui ignorerait l'annonce du mandataire.
    #[test]
    fn p1032t_aucun_gestionnaire_ne_decide_secure_lui_meme() {
        for (fichier, source) in [("session.rs", include_str!("../session.rs")), ("handlers/idp.rs", include_str!("../handlers/idp.rs"))] {
            for (n, ligne) in source.lines().enumerate().filter(|(_, l)| l.contains("SameSite=")) {
                if ligne.trim_start().starts_with("//") {
                    continue;
                }
                assert!(
                    !ligne.contains("Secure") && !ligne.contains("{secure}"),
                    "{fichier}:{} construit un cookie qui décide Secure lui-même : {ligne}",
                    n + 1
                );
            }
        }
        assert_eq!(include_str!("../handlers/idp.rs").matches("cookie_secure_suffix_pour(").count(), 0, "idp.rs rend Secure lui-même");
        assert_eq!(
            include_str!("../session.rs").matches("cookie_secure_suffix_pour(").count(),
            1,
            "session.rs : cookie_secure_suffix_pour n'est que DÉFINI ici, appelé par security_headers"
        );
    }

    /// AU SITE, de bout en bout : un sous-processus par cas (la liste `PLUME_TRUSTED_PROXIES` est lue une fois par
    /// processus). Le routeur réel sert `/api/login` puis `/api/logout` à un pair loopback (`127.0.0.1`), avec ou sans
    /// `X-Forwarded-Proto` ; on juge HSTS et l'attribut `Secure` des deux cookies de chaque réponse.
    #[test]
    fn p1032t_xfp_d_un_pair_de_confiance_pose_secure_et_hsts_au_site() {
        const ENFANT: &str = "P1032T_XFP_ENFANT";
        const VALEUR_XFP: &str = "P1032T_XFP_VALEUR";
        const FIN: &str = "P1032T-XFP-ENFANT-A-JOUE";
        if std::env::var(ENFANT).is_ok() {
            crate::server::rejouer_le_demarrage_pour_un_temoin();
            let xfp = std::env::var(VALEUR_XFP).unwrap_or_default();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
            rt.block_on(async {
                let (st, _db) = router_test_state("p1032t-xfp");
                let addr = router_serve(st).await;
                let mut entetes: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
                if !xfp.is_empty() {
                    entetes.push(("X-Forwarded-Proto", xfp.as_str()));
                }
                for (geste, chemin, corps) in [
                    ("login", "/api/login", r#"{"user":"vwr","pass":"viewerpw12345"}"#),
                    ("logout", "/api/logout", ""),
                ] {
                    let (code, reponse) = router_probe_envoi(addr, "POST", chemin, None, &entetes, corps).await;
                    println!("XFP-CODE:{geste}:{code}");
                    let tete = reponse.split("\r\n\r\n").next().unwrap_or("");
                    for (nom, valeur) in tete.lines().skip(1).filter_map(|l| l.split_once(':')) {
                        let nom = nom.trim().to_ascii_lowercase();
                        if nom == "strict-transport-security" || nom == "set-cookie" {
                            println!("XFP-ENTETE:{geste}:{nom}:{}", valeur.trim());
                        }
                    }
                }
            });
            println!("{FIN}");
            return;
        }
        let configuration_absente = crate::tmp_possede::racine_systeme().join("plume-p1032t-xfp-configuration-inexistante");
        let jouer = |liste_de_confiance: Option<&str>, xfp: &str| -> String {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::xfp_d_un_pair_de_confiance_pose_secure_et_hsts::p1032t_xfp_d_un_pair_de_confiance_pose_secure_et_hsts_au_site",
            ]);
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande
                .env(ENFANT, "1")
                .env(VALEUR_XFP, xfp)
                .env("PLUME_CONFIG", &configuration_absente)
                .env("PLUME_SESSION_SECRET", SIGNATURE_DE_TEST);
            if let Some(l) = liste_de_confiance {
                commande.env("PLUME_TRUSTED_PROXIES", l);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            let cas = format!("liste={liste_de_confiance:?} xfp={xfp:?}");
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({cas}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ({cas}) : {stdout}\n{stderr}");
            for geste in ["login", "logout"] {
                assert!(stdout.contains(&format!("XFP-CODE:{geste}:200")), "contrôle : {geste} rend 200 ({cas}) : {stdout}");
            }
            stdout
        };
        let entetes = |stdout: &str, geste: &str, nom: &str| -> Vec<String> {
            let prefixe = format!("XFP-ENTETE:{geste}:{nom}:");
            stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).map(str::to_string).collect()
        };
        // Juge un cas : HSTS et `Secure` sur les deux cookies de login ET de logout, tous présents ou tous absents.
        let juger = |stdout: &str, attendu: bool, cas: &str| {
            for geste in ["login", "logout"] {
                let hsts = entetes(stdout, geste, "strict-transport-security");
                if attendu {
                    assert_eq!(hsts, vec![HSTS_ATTENDU.to_string()], "{cas} : {geste} sans HSTS : {stdout}");
                } else {
                    assert!(hsts.is_empty(), "{cas} : {geste} sert HSTS : {stdout}");
                }
                let cookies = entetes(stdout, geste, "set-cookie");
                for nom in ["plume_session", "plume_csrf"] {
                    let c: Vec<&String> = cookies.iter().filter(|c| c.starts_with(&format!("{nom}="))).collect();
                    assert_eq!(c.len(), 1, "contrôle : un cookie {nom} posé par {geste} ({cas}) : {stdout}");
                    if attendu {
                        assert!(c[0].ends_with("; Secure"), "{cas} : {geste} pose {nom} sans Secure : {}", c[0]);
                        assert_eq!(c[0].matches("Secure").count(), 1, "{cas} : Secure doublé sur {nom} : {}", c[0]);
                    } else {
                        assert!(!c[0].contains("Secure"), "{cas} : {geste} pose {nom} avec Secure : {}", c[0]);
                    }
                }
            }
        };
        juger(&jouer(Some("127.0.0.1"), "https"), true, "pair de confiance + X-Forwarded-Proto https");
        juger(&jouer(Some(MANDATAIRE), "https"), false, "pair hors liste + X-Forwarded-Proto https");
        juger(&jouer(None, "https"), false, "liste vide + pair loopback + X-Forwarded-Proto https");
        juger(&jouer(Some("127.0.0.1"), "http"), false, "pair de confiance + X-Forwarded-Proto http");
        juger(&jouer(Some("127.0.0.1"), ""), false, "pair de confiance sans X-Forwarded-Proto");
    }

    /// RESTE (i) : la ligne `[tls]` du démarrage ne parle que SANS TLS natif. Réglage à 1 avec PLUME_TLS_CERT et
    /// PLUME_TLS_KEY posés (chemins jamais lus par `boot_config`) -> aucune ligne ; sans eux -> une ligne.
    #[test]
    fn p1032t_la_ligne_de_demarrage_se_tait_avec_le_tls_natif() {
        const ENFANT: &str = "P1032T_LIGNE_ENFANT";
        const FIN: &str = "P1032T-LIGNE-ENFANT-A-JOUE";
        const LIGNE_DE_JOURNAL: &str = "[tls] PLUME_TLS_TERMINATED_UPSTREAM=1 sans TLS natif";
        const CERTIFICAT: &str = "/nonexistent/p1032t/certificat.pem";
        const CLE_PRIVEE_CHEMIN: &str = "/nonexistent/p1032t/cle.pem";
        if std::env::var(ENFANT).is_ok() {
            crate::server::rejouer_le_demarrage_pour_un_temoin();
            println!("P1032T-LIGNE-ETAT:{:?}", etat_tls_au_demarrage());
            println!("{FIN}");
            return;
        }
        let configuration_absente = crate::tmp_possede::racine_systeme().join("plume-p1032t-ligne-configuration-inexistante");
        let jouer = |tls_natif: bool| -> (String, String) {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::xfp_d_un_pair_de_confiance_pose_secure_et_hsts::p1032t_la_ligne_de_demarrage_se_tait_avec_le_tls_natif",
            ]);
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande
                .env(ENFANT, "1")
                .env("PLUME_CONFIG", &configuration_absente)
                .env("PLUME_SESSION_SECRET", SIGNATURE_DE_TEST)
                .env("PLUME_TLS_TERMINATED_UPSTREAM", "1");
            if tls_natif {
                commande.env("PLUME_TLS_CERT", CERTIFICAT).env("PLUME_TLS_KEY", CLE_PRIVEE_CHEMIN);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué (tls_natif={tls_natif}) : {stdout}\n{stderr}");
            (stdout, stderr)
        };
        let lignes = |stderr: &str| stderr.lines().filter(|l| l.starts_with(LIGNE_DE_JOURNAL)).count();
        let (stdout, stderr) = jouer(true);
        assert!(stdout.contains("P1032T-LIGNE-ETAT:(true, true)"), "contrôle : TLS natif ET réglage lus au démarrage : {stdout}");
        assert_eq!(lignes(&stderr), 0, "réglage à 1 AVEC TLS natif : la ligne [tls] parle quand même : {stderr}");
        let (stdout, stderr) = jouer(false);
        assert!(stdout.contains("P1032T-LIGNE-ETAT:(false, true)"), "contrôle : réglage seul lu au démarrage : {stdout}");
        assert_eq!(lignes(&stderr), 1, "réglage à 1 sans TLS natif : une ligne [tls] attendue : {stderr}");
    }

    /// RESTE (ii) : le paquet de diagnostic sert la valeur du réglage, en clair (ce n'est pas un secret).
    #[test]
    fn p1032t_le_paquet_de_diagnostic_sert_le_reglage() {
        use crate::handlers::system::{diag_bundle_json, key_is_secretish};
        const REGLAGE: &str = "PLUME_TLS_TERMINATED_UPSTREAM";
        assert!(!key_is_secretish(REGLAGE), "le réglage serait réduit à « set » : sa valeur ne serait pas lue");
        let _env = VERROU_ENV_PROCESSUS.write();
        let c = day2_conn();
        {
            let _pose = ReglageBackupPose::neuf(REGLAGE, "1");
            let b = diag_bundle_json(&c, "/spool", "", 80);
            assert_eq!(b["config"][REGLAGE], json!("1"), "réglage à 1 : le paquet de diagnostic ne le sert pas : {}", b["config"]);
        }
        let _retire = ReglageBackupPose::retire(REGLAGE);
        let b = diag_bundle_json(&c, "/spool", "", 80);
        assert_eq!(b["config"][REGLAGE], json!(""), "réglage absent : valeur vide attendue : {}", b["config"]);
    }
}
