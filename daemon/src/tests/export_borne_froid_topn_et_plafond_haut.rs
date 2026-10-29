// =====================================================================================
// `P10.32-r` (vague AY, correction après vérification) — LA BORNE DE L'EXPORT TENUE AUSSI SUR LE TIER FROID, ET
// L'EN-TÊTE `x-plume-export-borne` POSÉ SEULEMENT QUAND CETTE BORNE A MORDU.
//
// TROIS TROUS RELEVÉS PAR LE VÉRIFICATEUR, MESURÉS AVANT CE CORRECTIF :
//   (a) profil de production (`ldap,cold_tier`) : quand la fenêtre atteint le froid, l'hydratation froide restait
//       plafonnée par `cold_store::reader::cold_hydrate_row_cap`, qui relisait `PLUME_QUERY_MAX` : 120 lignes froides
//       + 21 chaudes, QUERY_MAX=50, EXPORT_MAX=200 -> 71 lignes au lieu de 141, `x-plume-truncated: 1`. Le remède :
//       `cold_hydrate_row_cap` lit le plafond du fil (`query_exec::plafond_de_lignes_de_ce_fil`), donc la borne de
//       l'export sous `sous_le_plafond_de_l_export`. L'enveloppe de la branche froide n'avait aucun témoin.
//   (b) l'en-tête de borne lu AVANT `apply_rollup_stats` et sans la coupure froide n'était tenu par aucun témoin :
//       un export pré-agrégé coupé par le plafond top-N, ou un export coupé par l'hydratation froide sous sa borne,
//       aurait pu annoncer « borne touchée ».
//   (c) la borne haute du plafond interactif (PLUME_QUERY_MAX > 100 000 -> défaut 5 000) n'avait pas de témoin.
//
// MUTANTS (variable VERIF_MUT, retirés avant le commit) : AY3C_FROID_CAP (l'hydratation froide relit PLUME_QUERY_MAX),
// AY3C_H5 (la branche froide sans `sous_le_plafond_de_l_export`), AY3C_H8 (en-tête lu après `apply_rollup_stats`),
// AY3C_H8B (en-tête = troncature finale, coupure froide et top-N comprises), AY3C_Q5 (plus de borne haute sur
// PLUME_QUERY_MAX).
// =====================================================================================
mod ay3c_export_borne_froid_topn_et_plafond_haut {
    use super::*;
    use crate::query_exec::{plafond_de_lignes_de_ce_fil, query_budget_interactive_ms, run_query_ex};

    const AY3C_LEVIERS: [&str; 3] = ["PLUME_QUERY_MAX", "PLUME_EXPORT_MAX", "PLUME_ROLLUP_DIM_TOPN"];
    const AY3C_ENTETE_BORNE: &str = "x-plume-export-borne";

    /// Pose les leviers et remet l'état d'avant à la sortie (l'appelant tient `VERROU_ENV_PROCESSUS.write()`).
    struct Ay3cEnv(Vec<(&'static str, Option<String>)>);
    impl Ay3cEnv {
        fn poser(valeurs: &[(&'static str, &str)]) -> Self {
            let avant = AY3C_LEVIERS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in AY3C_LEVIERS {
                std::env::remove_var(k);
            }
            for (k, v) in valeurs {
                std::env::set_var(k, v);
            }
            Ay3cEnv(avant)
        }
    }
    impl Drop for Ay3cEnv {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    struct Ay3cServi {
        code: u16,
        corps: Value,
        brut: String,
    }
    impl Ay3cServi {
        fn entete(&self, nom: &str) -> Option<String> {
            let tete = self.brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(&self.brut);
            tete.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(nom).then(|| v.trim().to_string())
            })
        }
        fn lignes(&self) -> usize {
            self.corps.as_array().unwrap_or_else(|| panic!("export JSON : tableau attendu, code {} : {}", self.code, self.brut)).len()
        }
        fn resume(&self) -> String {
            format!(
                "code={} lignes={:?} tronque={:?} borne={:?} nom={:?}",
                self.code,
                self.corps.as_array().map(|a| a.len()),
                self.entete("x-plume-truncated"),
                self.entete(AY3C_ENTETE_BORNE),
                self.entete("content-disposition")
            )
        }
    }

    /// POST /api/export par le routeur réel ; corps JSON décodé (chunked compris), réponse brute gardée.
    async fn ay3c_exporter(addr: std::net::SocketAddr, authz: &str, corps: &Value) -> Ay3cServi {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, "POST", "/api/export", Some(authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked : {brut}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        Ay3cServi { code, corps: serde_json::from_str(&c).unwrap_or(Value::Null), brut }
    }

    /// (1) PLAFOND HAUT DU PLAFOND INTERACTIF : PLUME_QUERY_MAX au-delà de 100 000 retombe au défaut 5 000, sur la
    /// fonction ET sur le chemin chaud (100 005 lignes produites -> 5 000 rendues, coupure dite). MUTANT : AY3C_Q5.
    #[test]
    fn ay3c_query_max_au_dela_du_plafond_dur_retombe_au_defaut() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        for (valeur, attendu) in [("100000", 100_000), ("100001", 5_000), ("200000", 5_000), ("50", 50), ("0", 5_000), ("abc", 5_000)] {
            let _leviers = Ay3cEnv::poser(&[("PLUME_QUERY_MAX", valeur)]);
            assert_eq!(plafond_de_lignes_de_ce_fil(), attendu, "PLUME_QUERY_MAX={valeur}");
        }
        let _leviers = Ay3cEnv::poser(&[("PLUME_QUERY_MAX", "200000")]);
        let (_st, base) = router_test_state("ay3c-plafond-haut");
        let cent_mille_cinq = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 100005) SELECT x FROM c";
        let v = run_query_ex(base.as_str(), cent_mille_cinq, query_budget_interactive_ms(), None).expect("lecture servie");
        assert_eq!(v["rows"].as_array().map(|a| a.len()), Some(5_000), "PLUME_QUERY_MAX=200000 hors bornes -> défaut 5 000 sur le chemin chaud");
        assert_eq!(v["stats"]["truncated"], json!(true), "coupure dite");
    }

    /// (2) TOP-N DU PRÉ-AGRÉGÉ : 37 statuts distincts, PLUME_ROLLUP_DIM_TOPN=5. L'export pré-agrégé rend 5 lignes,
    /// se dit tronqué (le plafond top-N a mordu, 32 lignes manquantes) mais N'ANNONCE PAS sa borne (50 000, jamais
    /// atteinte). Contre-épreuve : `limit` 3 -> la borne mord, en-tête 3. MUTANTS : AY3C_H8, AY3C_H8B.
    #[tokio::test]
    async fn ay3c_coupure_top_n_n_est_pas_la_borne_de_l_export() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3cEnv::poser(&[("PLUME_ROLLUP_DIM_TOPN", "5")]);
        let (st, _base) = router_test_state("ay3c-topn");
        {
            let c = st.db.lock();
            let bucket = (now() / 3600) * 3600;
            amp_seed_distinct(&c, bucket + 61, "web", "status", 37, "ay3c");
            rollup_events(&c);
        }
        std::env::remove_var("PLUME_ROLLUP_DIM_TOPN");
        let addr = router_serve(st.clone()).await;
        let corps = json!({ "soql": "search source=web | stats count by status", "from": 0, "to": 0, "format": "json" });
        let s = ay3c_exporter(addr, &viewer_authz(), &corps).await;
        assert_eq!(s.code, 200, "servi : {}", s.resume());
        assert_eq!(s.lignes(), 5, "le pré-agrégé rend les 5 statuts gardés : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "le plafond top-N a mordu : {}", s.resume());
        let disposition = s.entete("content-disposition").unwrap_or_default();
        assert!(disposition.contains("-TRONQUE-32-lignes-manquantes"), "contrôle : servi par le pré-agrégé, ampleur chiffrée : {}", s.resume());
        assert_eq!(s.entete(AY3C_ENTETE_BORNE), None, "coupure top-N, pas la borne de l'export : {}", s.resume());
        let mut corps3 = corps.clone();
        corps3["limit"] = json!(3);
        let s = ay3c_exporter(addr, &viewer_authz(), &corps3).await;
        assert_eq!(s.code, 200, "servi : {}", s.resume());
        assert_eq!(s.lignes(), 3, "limit 3 : {}", s.resume());
        assert_eq!(s.entete(AY3C_ENTETE_BORNE).as_deref(), Some("3"), "la borne a mordu : {}", s.resume());
    }

    /// (3) TIER FROID (profil de production) : 120 lignes vieillies + 1 chaude + 20 chaudes semées ici, PLUME_QUERY_MAX=50.
    /// (a) EXPORT_MAX=200 -> 141 lignes, rien n'est dit coupé, aucun en-tête de borne. (b) EXPORT_MAX=100 -> 100 lignes,
    /// borne 100 dite. (c) EXPORT_MAX=100 et `| head 10` : l'hydratation froide coupe à 100 (120 froides), la réponse
    /// rend 10 lignes et se dit tronquée, mais la borne de l'export n'a PAS mordu : aucun en-tête de borne.
    /// MUTANTS : AY3C_FROID_CAP et AY3C_H5 (a), AY3C_H8B (c).
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn ay3c_export_froid_n_obeit_qu_a_sa_borne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Ay3cEnv::poser(&[("PLUME_QUERY_MAX", "50"), ("PLUME_EXPORT_MAX", "200")]);
        let banc = BancFroidSurLaRoute::monter("ay3c-froid", false).await;
        {
            let c = banc.st.db.lock();
            for i in 0..20 {
                c.execute(
                    "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                     VALUES(?1,1,'froid','test','h-froid','','','','',?2,'','','prod','ligne chaude','{}')",
                    params![banc.maintenant - 120 - i, format!("ay3c-chaud-{i}")],
                )
                .expect("fixture : ligne chaude");
            }
        }
        banc.vieillir();
        let corps = |soql: &str| json!({ "soql": soql, "from": banc.base_froide - 60, "to": banc.maintenant + 60, "format": "json" });
        let s = ay3c_exporter(banc.addr, &banc.authz, &corps("search source=froid")).await;
        assert_eq!(s.code, 200, "(a) servi : {}", s.resume());
        assert_eq!(s.lignes(), (LIGNES_FROIDES + 21) as usize, "(a) toutes les lignes, froides comprises, sous la borne 200 : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("0"), "(a) export complet : {}", s.resume());
        assert_eq!(s.entete(AY3C_ENTETE_BORNE), None, "(a) borne non touchée : {}", s.resume());

        std::env::set_var("PLUME_EXPORT_MAX", "100");
        let s = ay3c_exporter(banc.addr, &banc.authz, &corps("search source=froid")).await;
        assert_eq!(s.code, 200, "(b) servi : {}", s.resume());
        assert_eq!(s.lignes(), 100, "(b) la borne 100, pas PLUME_QUERY_MAX=50 : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "(b) coupé à sa borne : {}", s.resume());
        assert_eq!(s.entete(AY3C_ENTETE_BORNE).as_deref(), Some("100"), "(b) borne dite : {}", s.resume());

        let s = ay3c_exporter(banc.addr, &banc.authz, &corps("search source=froid | head 10")).await;
        assert_eq!(s.code, 200, "(c) servi : {}", s.resume());
        assert_eq!(s.lignes(), 10, "(c) head 10 : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "(c) l'hydratation froide a coupé (120 froides > 100) : {}", s.resume());
        assert_eq!(s.entete(AY3C_ENTETE_BORNE), None, "(c) coupure froide sous la borne, pas la borne de l'export : {}", s.resume());
    }
}
