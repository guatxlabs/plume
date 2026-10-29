// =====================================================================================
// `P10.32-r` (vague AY) — L'EXPORT COMPLET N'OBÉIT QU'À SA BORNE, ET LE DIT QUAND IL LA TOUCHE.
//
// LE DÉFAUT, MESURÉ SUR 3e67d249 AVANT LE CORRECTIF : `/api/export` enveloppait la requête dans
// `SELECT * FROM (…) LIMIT {borne}` (borne = `PLUME_EXPORT_MAX`, défaut 50 000), puis l'exécutait par `run_query_ex`,
// dont le cœur (`query_exec::run_on_conn`) coupe à `PLUME_QUERY_MAX` (défaut 5 000), le plafond des lectures
// interactives. Deux fautes : (a) au réglage par défaut, un export rendait au plus 5 000 lignes, pas 50 000 ; (b)
// quand la borne de l'export était la plus petite, le LIMIT coupait EN SILENCE (`stats.truncated` faux, fichier sans
// `-TRONQUE-`, `x-plume-truncated: 0`) : le cœur ne voyait jamais la ligne suivante.
//
// LE REMÈDE : `query_exec::sous_le_plafond_de_l_export` pose la borne de l'export comme plafond du cœur, sur le fil de
// l'exécution, à la place de `PLUME_QUERY_MAX` (borné par `PLAFOND_DUR_DES_LIGNES_RENDUES`, remis à la sortie) ; le
// LIMIT enveloppant laisse passer UNE ligne sonde, que le cœur ne rend pas mais qui pose `stats.truncated` ; la route
// pose alors `x-plume-export-borne: <borne>` en plus de `x-plume-truncated: 1` et du nom `-TRONQUE-`.
//
// LES PROTECTIONS CONTRE L'EXFILTRATION, TENUES ET JOUÉES ICI : plafond dur (PLUME_EXPORT_MAX hors ]0, 100 000] -> défaut,
// plafond du cœur borné même si on lui passe plus), gate de rôle (SQL brut réservé admin), authorizer du pool de
// lecture (une colonne secrète refusée même à l'admin), audit `bulk_read` (qui compte les lignes de la borne de
// l'export).
//
// MUTANTS (variable de mutation, retirés avant le commit) : AY3_QUERY_MAX (le cœur ignore la borne posée), AY3_SANS_SONDE
// (LIMIT borne, sans ligne sonde), AY3_ENTETE_TOUJOURS, AY3_ENTETE_JAMAIS, AY3_SANS_MIN_CORPS (la `limit` du corps
// n'est plus bornée par PLUME_EXPORT_MAX), AY3_SANS_PLAFOND_DUR, AY3_SANS_REMISE (la borne survit sur le fil),
// AY3_SANS_AUDIT, AY3_SQL_BRUT_OUVERT, AY3_SANS_AUTORISATEUR.
// =====================================================================================
mod ay3_export_n_obeit_qu_a_sa_borne {
    use super::*;
    use crate::handlers::query::{export_max_rows, ENTETE_BORNE_DE_L_EXPORT_TOUCHEE, REQUETE_REJETEE_PAR_LE_MOTEUR};
    use crate::query_exec::{query_budget_interactive_ms, run_query_ex, sous_le_plafond_de_l_export, PLAFOND_DUR_DES_LIGNES_RENDUES};

    const AY3_SOQL: &str = "search source=ay3";
    const AY3_LEVIERS: [&str; 3] = ["PLUME_QUERY_MAX", "PLUME_EXPORT_MAX", "PLUME_AUDIT_BULK_ROWS"];
    const AY3_REFUS_SQL_BRUT: &str = "SQL brut réservé à l'administrateur (utilisez GXQL)";
    const AY3_ENTETE_BORNE: &str = "x-plume-export-borne";
    /// Mot de passe de l'administrateur posé par `router_test_state` (nom de constante : jamais un littéral passé tel quel).
    const AY3_MOT_DE_PASSE_ADMIN: &str = "rootpw1234567";

    /// Pose les leviers du test et remet l'état d'avant à la sortie (l'appelant tient `VERROU_ENV_PROCESSUS.write()`).
    struct Ay3Env(Vec<(&'static str, Option<String>)>);
    impl Ay3Env {
        fn poser(valeurs: &[(&'static str, Option<&str>)]) -> Self {
            let avant = AY3_LEVIERS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in AY3_LEVIERS {
                std::env::remove_var(k);
            }
            for (k, v) in valeurs {
                if let Some(v) = v {
                    std::env::set_var(k, v);
                }
            }
            Ay3Env(avant)
        }
    }
    impl Drop for Ay3Env {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn ay3_semer(st: &AppState, n: usize) {
        let c = st.db.lock();
        let ts = now() - 60;
        for i in 0..n {
            c.execute("INSERT INTO event(ts,source,dedup) VALUES(?1,'ay3',?2)", params![ts, format!("ay3-{i}")]).expect("fixture : événement");
        }
    }

    fn ay3_admin_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("root:{AY3_MOT_DE_PASSE_ADMIN}")))
    }

    struct Ay3Servi {
        code: u16,
        corps: Value,
        brut: String,
    }
    impl Ay3Servi {
        fn entete(&self, nom: &str) -> Option<String> {
            let tete = self.brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(&self.brut);
            tete.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(nom).then(|| v.trim().to_string())
            })
        }
        fn lignes(&self) -> usize {
            self.corps.as_array().unwrap_or_else(|| panic!("export JSON : tableau d'objets attendu : {}", self.corps)).len()
        }
    }

    /// POST par le routeur réel ; corps JSON décodé (chunked compris), réponse brute gardée pour les en-têtes.
    async fn ay3_envoi(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> Ay3Servi {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, "POST", route, Some(authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {route} : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {route}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        Ay3Servi { code, corps: serde_json::from_str(&c).unwrap_or(Value::Null), brut }
    }

    fn ay3_corps_d_export(limite: Option<i64>) -> Value {
        let maintenant = now();
        let mut b = json!({ "soql": AY3_SOQL, "from": maintenant - 3600, "to": maintenant + 3600, "format": "json" });
        if let Some(l) = limite {
            b["limit"] = json!(l);
        }
        b
    }

    fn ay3_juger_borne_touchee(s: &Ay3Servi, borne: usize, quoi: &str) {
        assert_eq!(s.code, 200, "{quoi} : servi : {}", s.corps);
        assert_eq!(s.lignes(), borne, "{quoi} : l'export rend SA borne ({borne} lignes), pas PLUME_QUERY_MAX");
        assert_eq!(s.entete("x-plume-rows").as_deref(), Some(borne.to_string().as_str()), "{quoi} : x-plume-rows");
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "{quoi} : l'export coupé à sa borne se dit incomplet");
        assert_eq!(s.entete(AY3_ENTETE_BORNE).as_deref(), Some(borne.to_string().as_str()), "{quoi} : en-tête de la borne touchée, ligne exacte");
        let disposition = s.entete("content-disposition").unwrap_or_default();
        assert!(disposition.ends_with("-TRONQUE-ampleur-inconnue.json\""), "{quoi} : le nom du fichier porte l'aveu : {disposition}");
    }

    /// (1) PLUME_QUERY_MAX=3, PLUME_EXPORT_MAX=7, dix événements : l'export rend 7 lignes et le DIT (x-plume-truncated: 1,
    /// x-plume-export-borne: 7, nom `-TRONQUE-`) ; l'audit `bulk_read` compte ces 7 lignes ; `/api/query`, lecture
    /// interactive, reste à 3. MUTANTS : AY3_QUERY_MAX, AY3_SANS_SONDE, AY3_ENTETE_JAMAIS, AY3_SANS_AUDIT.
    #[tokio::test]
    async fn ay3_l_export_rend_sa_borne_et_le_dit() {
        assert_eq!(ENTETE_BORNE_DE_L_EXPORT_TOUCHEE, AY3_ENTETE_BORNE, "nom de l'en-tête servi");
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3Env::poser(&[("PLUME_QUERY_MAX", Some("3")), ("PLUME_EXPORT_MAX", Some("7")), ("PLUME_AUDIT_BULK_ROWS", Some("5"))]);
        let (st, _base) = router_test_state("ay3-borne");
        ay3_semer(&st, 10);
        let addr = router_serve(st.clone()).await;
        let s = ay3_envoi(addr, "/api/export", &viewer_authz(), &ay3_corps_d_export(None)).await;
        ay3_juger_borne_touchee(&s, 7, "export sans limite");
        let audits: Vec<(String, i64)> = {
            let c = st.db.lock();
            let mut q = c
                .prepare("SELECT json_extract(fields,'$.kind'), json_extract(fields,'$.rows') FROM event WHERE source='plume-audit' AND json_extract(fields,'$.action')='bulk_read'")
                .expect("lecture de l'audit");
            let lignes = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).expect("audit lisible");
            lignes.map(|l| l.expect("ligne d'audit")).collect()
        };
        assert_eq!(audits, vec![("export".to_string(), 7)], "l'audit bulk_read compte les lignes de la borne de l'export");
        let q = ay3_envoi(addr, "/api/query", &viewer_authz(), &json!({ "soql": AY3_SOQL, "from": now() - 3600, "to": now() + 3600 })).await;
        assert_eq!(q.code, 200, "contrôle /api/query : {}", q.corps);
        assert_eq!(q.corps["rows"].as_array().map(|a| a.len()), Some(3), "/api/query reste sous PLUME_QUERY_MAX : {}", q.corps);
        assert_eq!(q.corps["stats"]["truncated"], json!(true), "/api/query dit sa coupure");
    }

    /// (2) Exactement la borne (7 événements, PLUME_EXPORT_MAX=7, PLUME_QUERY_MAX=3) : 7 lignes, rien n'est dit
    /// incomplet, aucun en-tête de borne, nom sans `-TRONQUE-`. MUTANTS : AY3_ENTETE_TOUJOURS, AY3_QUERY_MAX.
    #[tokio::test]
    async fn ay3_export_exactement_a_sa_borne_ne_se_dit_pas_coupe() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3Env::poser(&[("PLUME_QUERY_MAX", Some("3")), ("PLUME_EXPORT_MAX", Some("7"))]);
        let (st, _base) = router_test_state("ay3-exact");
        ay3_semer(&st, 7);
        let addr = router_serve(st.clone()).await;
        let s = ay3_envoi(addr, "/api/export", &viewer_authz(), &ay3_corps_d_export(None)).await;
        assert_eq!(s.code, 200, "servi : {}", s.corps);
        assert_eq!(s.lignes(), 7, "toutes les lignes");
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("0"), "export complet");
        assert_eq!(s.entete(AY3_ENTETE_BORNE), None, "aucune borne touchée");
        let disposition = s.entete("content-disposition").unwrap_or_default();
        assert!(disposition.starts_with("attachment; filename=\"plume-") && !disposition.contains("TRONQUE"), "nom sans aveu : {disposition}");
    }

    /// (3) La `limit` du corps est bornée par PLUME_EXPORT_MAX (1000 demandées -> 7), et une `limit` plus petite est la
    /// borne touchée (5 -> 5, dite). MUTANT : AY3_SANS_MIN_CORPS.
    #[tokio::test]
    async fn ay3_limite_du_corps_bornee_par_celle_de_l_export() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3Env::poser(&[("PLUME_QUERY_MAX", Some("3")), ("PLUME_EXPORT_MAX", Some("7"))]);
        let (st, _base) = router_test_state("ay3-corps");
        ay3_semer(&st, 10);
        let addr = router_serve(st.clone()).await;
        let s = ay3_envoi(addr, "/api/export", &viewer_authz(), &ay3_corps_d_export(Some(1000))).await;
        ay3_juger_borne_touchee(&s, 7, "limite 1000 sous PLUME_EXPORT_MAX=7");
        let s = ay3_envoi(addr, "/api/export", &viewer_authz(), &ay3_corps_d_export(Some(5))).await;
        ay3_juger_borne_touchee(&s, 5, "limite 5");
    }

    /// (4) PLAFOND DUR : PLUME_EXPORT_MAX hors ]0, 100 000] -> défaut 50 000 ; le cœur ne rend jamais plus de 100 000
    /// lignes même si on lui passe 200 000 (100 005 lignes produites) ; la borne de l'export ne survit pas sur le fil
    /// (la lecture suivante revient à PLUME_QUERY_MAX). MUTANTS : AY3_SANS_PLAFOND_DUR, AY3_SANS_REMISE, AY3_QUERY_MAX.
    #[test]
    fn ay3_plafond_dur_et_borne_remise_sur_le_fil() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        for (valeur, attendu) in [("100000", 100_000), ("7", 7), ("100001", 50_000), ("200000", 50_000), ("0", 50_000), ("-3", 50_000), ("abc", 50_000)] {
            let _leviers = Ay3Env::poser(&[("PLUME_EXPORT_MAX", Some(valeur))]);
            assert_eq!(export_max_rows(), attendu, "PLUME_EXPORT_MAX={valeur}");
        }
        let _leviers = Ay3Env::poser(&[("PLUME_QUERY_MAX", Some("3"))]);
        assert_eq!(PLAFOND_DUR_DES_LIGNES_RENDUES, 100_000, "plafond dur");
        let (_st, base) = router_test_state("ay3-dur");
        let budget = query_budget_interactive_ms();
        let cent_mille_cinq = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 100005) SELECT x FROM c";
        let v = sous_le_plafond_de_l_export(200_000, || run_query_ex(base.as_str(), cent_mille_cinq, budget, None)).expect("lecture servie");
        assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(100_000), "plafond dur tenu au cœur");
        assert_eq!(v["stats"]["truncated"], json!(true), "coupure dite");
        let dix = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 10) SELECT x FROM c";
        let v = sous_le_plafond_de_l_export(7, || run_query_ex(base.as_str(), dix, budget, None)).expect("lecture servie");
        assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(7), "sous la borne de l'export : 7, pas PLUME_QUERY_MAX=3");
        let v = run_query_ex(base.as_str(), dix, budget, None).expect("lecture servie");
        assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(3), "après l'export, le même fil revient à PLUME_QUERY_MAX");
        let paniquee = std::panic::catch_unwind(|| sous_le_plafond_de_l_export(7, || panic!("ay3 : panique sous la borne")));
        assert!(paniquee.is_err(), "contrôle : la panique a eu lieu");
        let v = run_query_ex(base.as_str(), dix, budget, None).expect("lecture servie");
        assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(3), "après une panique sous la borne, le fil revient à PLUME_QUERY_MAX");
    }

    /// (5) GATE DE RÔLE ET AUTHORIZER, par la route : un lecteur qui exporte du SQL brut reçoit le 403 entier ; un admin
    /// qui exporte une colonne secrète (`user.hash`) reçoit le refus du moteur entier, sans la valeur. MUTANTS :
    /// AY3_SQL_BRUT_OUVERT, AY3_SANS_AUTORISATEUR.
    #[tokio::test]
    async fn ay3_gate_de_role_et_authorizer_tenus_sur_l_export() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3Env::poser(&[("PLUME_EXPORT_MAX", Some("7"))]);
        let (st, _base) = router_test_state("ay3-protections");
        ay3_semer(&st, 2);
        let hachage: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='vwr'", [], |r| r.get(0)).expect("fixture : hachage du lecteur");
        assert!(hachage.len() > 20, "contrôle : la valeur secrète existe");
        let addr = router_serve(st.clone()).await;
        let corps = json!({ "sql": "SELECT name FROM user", "from": 0, "to": now() + 3600, "format": "json" });
        let s = ay3_envoi(addr, "/api/export", &viewer_authz(), &corps).await;
        assert_eq!((s.code, s.corps.clone()), (403, json!({ "error": AY3_REFUS_SQL_BRUT })), "lecteur : SQL brut refusé");
        let corps = json!({ "sql": "SELECT hash FROM user", "from": 0, "to": now() + 3600, "format": "json" });
        let s = ay3_envoi(addr, "/api/export", &ay3_admin_authz(), &corps).await;
        assert_eq!((s.code, s.corps.clone()), (400, json!({ "error": REQUETE_REJETEE_PAR_LE_MOTEUR })), "admin : colonne secrète refusée par l'authorizer");
        assert!(!s.brut.contains(&hachage), "la valeur secrète ne part pas");
        let corps = json!({ "sql": "SELECT name FROM user", "from": 0, "to": now() + 3600, "format": "json" });
        let s = ay3_envoi(addr, "/api/export", &ay3_admin_authz(), &corps).await;
        assert_eq!(s.code, 200, "contrôle : l'admin exporte une colonne permise : {}", s.corps);
        assert!(s.lignes() >= 1, "contrôle : au moins le lecteur");
    }
}
