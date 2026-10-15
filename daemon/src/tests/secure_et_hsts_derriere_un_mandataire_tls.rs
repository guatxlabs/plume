// `P10.32-t` — `Secure` ET HSTS DERRIÈRE UN MANDATAIRE TLS.
//
// VU (re-mesuré) : `cookie_secure_suffix` (session.rs) et `security_headers` (server/mod.rs) ne posaient l'attribut
// `Secure` et l'en-tête HSTS que si `TLS_ON`, vrai seulement avec PLUME_TLS_CERT ET PLUME_TLS_KEY. Derrière un Ingress,
// Traefik, un mandataire Docker ou un nginx hôte, le cookie `plume_session` partait sans `Secure` et sans HSTS, et aucun
// réglage ne permettait de les demander.
//
// TENU : le réglage `PLUME_TLS_TERMINATED_UPSTREAM` (« 1 » seul) et un prédicat PUR unique
// `https_percu_par_le_navigateur(tls_natif, termine_en_amont)` lu par les DEUX sites. Témoins sur le prédicat, sur les
// chaînes rendues (`cookie_secure_suffix_pour`, `hsts_pour`) et sur la lecture du réglage — jamais en mutant les
// statiques `TLS_ON` / `TLS_TERMINATED_UPSTREAM` dans le processus des tests (ils tournent en parallèle). La chaîne
// réglage -> `boot_config` -> statique -> sites se juge de bout en bout dans un SOUS-PROCESSUS par cas (test 5) : en-tête
// HSTS et attribut `Secure` servis par le routeur réel, ligne `[tls]` du journal.
//
// MUTANTS JOUÉS (sous cfg!(test), par variable de mutation, retirés avant le commit) : HSTS_NATIF_SEUL (HSTS câblé sur le seul TLS natif),
// COOKIE_NATIF_SEUL (Secure câblé sur le seul TLS natif), VALEUR_NON_VIDE (toute valeur non vide active le réglage),
// DEFAUT_VRAI (réglage absent = actif). Test 5, un site chacun : M_BOOT_NON_STOCKE et M_BOOT_STOCKE_TLS_ON (`boot_config`
// stocke faux, ou le seul TLS natif), M_ETAT_SANS_AMONT (`etat_tls_au_demarrage` ignore la statique),
// M_SITE_HSTS_SANS_AMONT et M_SITE_COOKIE_SANS_AMONT (un site laisse tomber le réglage), M_SITE_HSTS_TOUJOURS
// (`security_headers` pose HSTS sans condition : rouge sur le cas « réglage absent »).
mod secure_et_hsts_derriere_un_mandataire_tls {
    use super::*;

    const REGLAGE: &str = "PLUME_TLS_TERMINATED_UPSTREAM";
    /// Clé de signature des sessions fournie à l'enfant (fixture de test, pas un secret) : sans elle, le démarrage
    /// en écrirait une sur disque.
    const SIGNATURE_DE_TEST: &str = "temoin-p1032t-signature-de-test";

    fn conf_avec(valeur: Option<&str>) -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        if let Some(v) = valeur {
            m.insert(REGLAGE.to_string(), v.to_string());
        }
        m
    }

    /// Corps d'une fonction lu dans son source (de sa signature à la première accolade fermante en colonne 0).
    fn corps<'a>(source: &'a str, signature: &str) -> &'a str {
        let debut = source.find(signature).unwrap_or_else(|| panic!("`{signature}` introuvable dans le source"));
        let reste = &source[debut..];
        let fin = reste.find("\n}\n").unwrap_or_else(|| panic!("fin de `{signature}` introuvable"));
        &reste[..fin]
    }

    #[test]
    fn p1032t_le_predicat_est_vrai_ssi_tls_natif_ou_mandataire_en_amont() {
        for natif in [false, true] {
            for amont in [false, true] {
                assert_eq!(
                    https_percu_par_le_navigateur(natif, amont),
                    natif || amont,
                    "(tls_natif={natif}, termine_en_amont={amont})"
                );
            }
        }
    }

    #[test]
    fn p1032t_secure_et_hsts_poses_ensemble_ssi_l_un_des_deux() {
        for natif in [false, true] {
            for amont in [false, true] {
                let attendu = natif || amont;
                let secure = crate::session::cookie_secure_suffix_pour(natif, amont);
                let hsts = hsts_pour(natif, amont);
                assert_eq!(
                    secure,
                    if attendu { "; Secure" } else { "" },
                    "attribut Secure faux pour (tls_natif={natif}, termine_en_amont={amont})"
                );
                assert_eq!(
                    hsts,
                    if attendu { Some("max-age=31536000; includeSubDomains") } else { None },
                    "HSTS faux pour (tls_natif={natif}, termine_en_amont={amont})"
                );
            }
        }
    }

    #[test]
    fn p1032t_le_reglage_ne_s_active_que_sur_un() {
        assert!(
            std::env::var(REGLAGE).is_err(),
            "{REGLAGE} est posé dans l'environnement du test : la lecture par la configuration ne serait pas jugée"
        );
        assert!(!tls_termine_en_amont_demande(&conf_avec(None)), "réglage absent -> off (défaut inchangé)");
        assert!(tls_termine_en_amont_demande(&conf_avec(Some("1"))), "« 1 » -> actif");
        for v in ["", "0", "true", "TRUE", "yes", "on", "2", "01"] {
            assert!(!tls_termine_en_amont_demande(&conf_avec(Some(v))), "valeur {v:?} -> off attendu");
        }
    }

    #[test]
    fn p1032t_les_deux_sites_lisent_le_meme_etat_et_le_meme_predicat() {
        // Défaut : aucun test ne pose les statiques (seul `boot_config` les écrit) -> origine en clair, sans Secure ni HSTS.
        let (natif, amont) = etat_tls_au_demarrage();
        assert_eq!((natif, amont), (false, false), "statiques TLS posées hors boot_config : le défaut n'est pas jugé");
        assert_eq!(crate::session::cookie_secure_suffix(), "", "défaut : aucun attribut Secure");
        // Le défaut « aucun HSTS » se juge AU SITE, sur l'en-tête servi par le routeur réel après le démarrage réel :
        // `p1032t_le_routeur_reel_sert_secure_et_hsts_selon_le_reglage_lu_au_demarrage`, cas « réglage absent ».

        // Câblage des deux sites (jugé sur le source, pas sur les statiques) : l'un et l'autre lisent l'état du boot
        // par `etat_tls_au_demarrage` et rendent par la fonction pure qui porte le prédicat ; aucun ne relit `TLS_ON`.
        let serveur = include_str!("../server/mod.rs");
        let session = include_str!("../session.rs");
        let entetes = corps(serveur, "pub(crate) async fn security_headers(");
        assert!(entetes.contains("etat_tls_au_demarrage()") && entetes.contains("hsts_pour("), "security_headers doit rendre HSTS par hsts_pour");
        assert!(!entetes.contains("TLS_ON"), "security_headers relit TLS_ON : second site de décision");
        let suffixe = corps(session, "pub(crate) fn cookie_secure_suffix() ");
        assert!(
            suffixe.contains("etat_tls_au_demarrage()") && suffixe.contains("cookie_secure_suffix_pour("),
            "cookie_secure_suffix doit rendre par cookie_secure_suffix_pour"
        );
        assert!(!suffixe.contains("TLS_ON"), "cookie_secure_suffix relit TLS_ON : second site de décision");
        for (nom, signature, source) in [
            ("hsts_pour", "pub(crate) fn hsts_pour(", serveur),
            ("cookie_secure_suffix_pour", "pub(crate) fn cookie_secure_suffix_pour(", session),
        ] {
            assert!(
                corps(source, signature).contains("https_percu_par_le_navigateur("),
                "{nom} ne lit pas le prédicat unique https_percu_par_le_navigateur"
            );
        }
    }

    /// (5) BOUT EN BOUT, AU SITE — le réglage lu par le démarrage RÉEL (`boot_config`), posé dans les statiques, appliqué
    /// par les DEUX sites du routeur RÉEL. Un sous-processus par cas (les statiques sont globales au processus) :
    /// réglage à « 1 » puis réglage absent, rien d'autre de `PLUME_*` hérité. On juge ce que le navigateur reçoit sur une
    /// connexion réussie : l'en-tête HSTS et l'attribut `Secure` des deux cookies, plus la ligne `[tls]` du journal.
    #[test]
    fn p1032t_le_routeur_reel_sert_secure_et_hsts_selon_le_reglage_lu_au_demarrage() {
        const ENFANT: &str = "P1032T_ENFANT_BOUT_EN_BOUT";
        const FIN: &str = "P1032T-ENFANT-A-JOUE";
        const LIGNE_DE_JOURNAL: &str = "[tls] PLUME_TLS_TERMINATED_UPSTREAM=1 sans TLS natif";
        const HSTS: &str = "strict-transport-security";
        if std::env::var(ENFANT).is_ok() {
            crate::server::rejouer_le_demarrage_pour_un_temoin();
            println!("P1032T-ETAT:{:?}", etat_tls_au_demarrage());
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
            let (code, reponse) = rt.block_on(async {
                let (st, _db) = router_test_state("p1032t-bout-en-bout");
                let addr = router_serve(st).await;
                let json = [("Content-Type", "application/json")];
                router_probe_envoi(addr, "POST", "/api/login", None, &json, r#"{"user":"vwr","pass":"viewerpw12345"}"#).await
            });
            println!("P1032T-CODE:{code}");
            let entete = reponse.split("\r\n\r\n").next().unwrap_or("");
            for (nom, valeur) in entete.lines().skip(1).filter_map(|l| l.split_once(':')) {
                let nom = nom.trim().to_ascii_lowercase();
                if nom == HSTS || nom == "set-cookie" {
                    println!("P1032T-ENTETE:{nom}:{}", valeur.trim());
                }
            }
            println!("{FIN}");
            return;
        }
        let configuration_absente = crate::tmp_possede::racine_systeme().join("plume-p1032t-configuration-inexistante");
        // Mode natif : l'unité systemd pose `PLUME_CONFIG` et le réglage vit dans ce fichier, pas dans l'environnement.
        let dossier_de_configuration = crate::tmp_possede::TmpPossede::neuf("p1032t-configuration-native");
        let configuration_native = dossier_de_configuration.join("plume.conf");
        std::fs::write(&configuration_native, format!("{REGLAGE}=1\n")).expect("fichier de configuration du témoin");
        let jouer = |reglage: Option<&str>, configuration: &std::path::Path| -> (String, String) {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::secure_et_hsts_derriere_un_mandataire_tls::p1032t_le_routeur_reel_sert_secure_et_hsts_selon_le_reglage_lu_au_demarrage",
            ]);
            // Environnement maîtrisé : aucun `PLUME_*` hérité (ni TLS natif, ni fichier de configuration lu), et une
            // clé de signature fournie pour que le démarrage n'écrive rien sur disque.
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande
                .env(ENFANT, "1")
                .env("PLUME_CONFIG", configuration)
                .env("PLUME_SESSION_SECRET", SIGNATURE_DE_TEST);
            if let Some(v) = reglage {
                commande.env(REGLAGE, v);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({reglage:?}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 ({reglage:?}) : {stdout}\n{stderr}");
            assert!(stdout.contains("P1032T-CODE:200"), "contrôle : la connexion réussit ({reglage:?}) : {stdout}\n{stderr}");
            (stdout, stderr)
        };
        let entetes = |stdout: &str, nom: &str| -> Vec<String> {
            let prefixe = format!("P1032T-ENTETE:{nom}:");
            stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).map(str::to_string).collect()
        };
        let cookie = |stdout: &str, nom: &str| -> String {
            let trouves: Vec<String> =
                entetes(stdout, "set-cookie").into_iter().filter(|c| c.starts_with(&format!("{nom}="))).collect();
            assert_eq!(trouves.len(), 1, "contrôle : un seul cookie {nom} posé par la connexion : {stdout}");
            trouves[0].clone()
        };
        let lignes_tls = |stderr: &str| stderr.lines().filter(|l| l.starts_with(LIGNE_DE_JOURNAL)).count();

        // Mandataire TLS déclaré : HSTS servi, `Secure` sur les deux cookies, une ligne au démarrage.
        let (stdout, stderr) = jouer(Some("1"), &configuration_absente);
        assert_eq!(
            entetes(&stdout, HSTS),
            vec!["max-age=31536000; includeSubDomains".to_string()],
            "réglage à 1 : le routeur réel ne sert pas HSTS : {stdout}"
        );
        for nom in ["plume_session", "plume_csrf"] {
            let c = cookie(&stdout, nom);
            assert!(c.ends_with("; Secure"), "réglage à 1 : le cookie {nom} part sans Secure : {c}\n{stdout}");
        }
        assert_eq!(lignes_tls(&stderr), 1, "réglage à 1 sans TLS natif : une ligne [tls] au démarrage : {stderr}");

        // Réglage absent (défaut) : ni HSTS, ni `Secure`, aucune ligne.
        let (stdout, stderr) = jouer(None, &configuration_absente);
        assert_eq!(entetes(&stdout, HSTS), Vec::<String>::new(), "réglage absent : le routeur réel sert HSTS : {stdout}");
        for nom in ["plume_session", "plume_csrf"] {
            let c = cookie(&stdout, nom);
            assert!(!c.contains("Secure"), "réglage absent : le cookie {nom} porte Secure : {c}\n{stdout}");
        }
        assert_eq!(lignes_tls(&stderr), 0, "réglage absent : aucune ligne [tls] : {stderr}");

        // Mode natif : réglage à 1 dans le seul fichier `PLUME_CONFIG`, aucune variable d'environnement. Le même
        // résultat qu'en conteneur — sinon le réglage écrit dans plume.conf ne ferait rien, sans un mot.
        let (stdout, stderr) = jouer(None, &configuration_native);
        assert_eq!(
            entetes(&stdout, HSTS),
            vec!["max-age=31536000; includeSubDomains".to_string()],
            "réglage dans le fichier de configuration seul : le routeur réel ne sert pas HSTS : {stdout}"
        );
        for nom in ["plume_session", "plume_csrf"] {
            let c = cookie(&stdout, nom);
            assert!(c.ends_with("; Secure"), "réglage dans le fichier seul : le cookie {nom} part sans Secure : {c}\n{stdout}");
        }
        assert_eq!(lignes_tls(&stderr), 1, "réglage dans le fichier seul : une ligne [tls] au démarrage : {stderr}");
    }
}
