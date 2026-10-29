// =====================================================================================
// `P10.32-r` (vague AZ, correction après vérification) — SOUS UN EXPORT, L'HYDRATATION FROIDE NE DESCEND JAMAIS SOUS
// `PLUME_QUERY_MAX` : LA BORNE DE L'EXPORT LIMITE LES LIGNES RENDUES, PAS LES LIGNES LUES.
//
// LE DÉFAUT, MESURÉ PAR LE VÉRIFICATEUR SUR a6c32c53 (profil `cold_tier`, 120 lignes froides) : sous un export,
// `query_exec::plafond_d_hydratation_froide_de_ce_fil` valait la borne plus une ligne À LA PLACE de `PLUME_QUERY_MAX`
// (avant 3903eb8e : `PLUME_QUERY_MAX`). Dès que la borne était plus petite :
//  * `limit` 10, `search source=froid | stats count` : `/api/query` 200 (120), `/api/export` 422, `cold_row_cap` 11 ;
//  * `PLUME_EXPORT_MAX=50` : 422, `cold_row_cap` 51 ;
//  * `limit` 5, `| where ts >= base+110*60` : `/api/query` 10 lignes, l'export 0 (les 6 plus anciennes recopiées,
//    filtrées ensuite), marqué tronqué sans borne.
// Remède : sous un export, le plus grand de `PLUME_QUERY_MAX` et de la borne plus une ligne, borné par le plafond dur
// plus une ligne. Le refus d'un agrégat froid nomme alors `PLUME_QUERY_MAX` quand c'est lui qui a arrêté la lecture
// (`cold_store/exactness.rs`, `plafond_applique`).
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
//  AZ3C_HYDRATE_A_LA_BORNE (sous un export, la borne plus une ligne seule, état de a6c32c53) : (1), (2), (3), (5) ;
//  AZ3C_SANS_LIGNE_SONDE (le plus grand de `PLUME_QUERY_MAX` et de la borne, sans la ligne de plus) : (5), et les
//  témoins (1) et (2) de `export_froid_coupe_a_sa_borne_et_union_occupee.rs` ;
//  AZ3C_MESSAGE_TOUJOURS_BORNE (sous un export, le message nomme la borne même quand `PLUME_QUERY_MAX` a arrêté la
//  lecture) : (4).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le `.min(PLAFOND_DUR_DES_LIGNES_RENDUES + 1)` est inerte par construction
// (`PLUME_QUERY_MAX` et la borne sont déjà bornés au plafond dur) : aucun mutant ne peut le faire rougir.
// =====================================================================================

/// (5) LE PLAFOND D'HYDRATATION, lu sur le fil, sans route ni tier froid (vaut dans les deux profils).
#[test]
fn az3c_hydratation_froide_sous_export_jamais_sous_plume_query_max() {
    use crate::query_exec::{plafond_d_hydratation_froide_de_ce_fil, sous_le_plafond_de_l_export, PLAFOND_DUR_DES_LIGNES_RENDUES};
    let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
    let avant = std::env::var("PLUME_QUERY_MAX").ok();
    struct Remise(Option<String>);
    impl Drop for Remise {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("PLUME_QUERY_MAX", v),
                None => std::env::remove_var("PLUME_QUERY_MAX"),
            }
        }
    }
    let _remise = Remise(avant);

    std::env::set_var("PLUME_QUERY_MAX", "50");
    assert_eq!(plafond_d_hydratation_froide_de_ce_fil(), 50, "hors export : PLUME_QUERY_MAX");
    assert_eq!(sous_le_plafond_de_l_export(20, plafond_d_hydratation_froide_de_ce_fil), 50, "borne 20 < PLUME_QUERY_MAX=50 : la lecture reste à 50");
    assert_eq!(sous_le_plafond_de_l_export(49, plafond_d_hydratation_froide_de_ce_fil), 50, "borne 49 : 49 + 1 = 50");
    assert_eq!(sous_le_plafond_de_l_export(50, plafond_d_hydratation_froide_de_ce_fil), 51, "borne 50 : la ligne sonde passe au-dessus");
    assert_eq!(sous_le_plafond_de_l_export(100, plafond_d_hydratation_froide_de_ce_fil), 101, "borne 100 : la borne et la ligne sonde");
    assert_eq!(plafond_d_hydratation_froide_de_ce_fil(), 50, "après l'export : PLUME_QUERY_MAX de nouveau");

    std::env::remove_var("PLUME_QUERY_MAX");
    assert_eq!(sous_le_plafond_de_l_export(10, plafond_d_hydratation_froide_de_ce_fil), 5000, "défaut : borne 10, la lecture reste au défaut 5000");
    assert_eq!(
        sous_le_plafond_de_l_export(usize::MAX, plafond_d_hydratation_froide_de_ce_fil),
        PLAFOND_DUR_DES_LIGNES_RENDUES + 1,
        "borne démesurée : le plafond dur et la ligne sonde"
    );
}

#[cfg(feature = "cold_tier")]
mod az3c_export_froid_lit_au_moins_plume_query_max {
    use super::*;

    const AZ3C_LEVIERS: [&str; 2] = ["PLUME_QUERY_MAX", "PLUME_EXPORT_MAX"];

    /// Pose les leviers et remet l'état d'avant à la sortie (l'appelant tient `VERROU_ENV_PROCESSUS.write()`).
    struct Az3cEnv(Vec<(&'static str, Option<String>)>);
    impl Az3cEnv {
        fn poser(valeurs: &[(&'static str, &str)]) -> Self {
            let avant = AZ3C_LEVIERS.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in AZ3C_LEVIERS {
                std::env::remove_var(k);
            }
            for (k, v) in valeurs {
                std::env::set_var(k, v);
            }
            Az3cEnv(avant)
        }
    }
    impl Drop for Az3cEnv {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    struct Az3cServi {
        code: u16,
        corps: Value,
        brut: String,
    }
    impl Az3cServi {
        fn entete(&self, nom: &str) -> Option<String> {
            let tete = self.brut.split_once("\r\n\r\n").map(|(t, _)| t).unwrap_or(&self.brut);
            tete.lines().skip(1).find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(nom).then(|| v.trim().to_string())
            })
        }
        fn resume(&self) -> String {
            format!(
                "code={} tronque={:?} borne={:?} corps={}",
                self.code,
                self.entete("x-plume-truncated"),
                self.entete("x-plume-export-borne"),
                self.corps
            )
        }
        /// Le compte d'un `stats count` exporté en JSON : un tableau d'UN objet à UNE valeur entière.
        fn compte(&self) -> i64 {
            let lignes = self.corps.as_array().unwrap_or_else(|| panic!("tableau attendu : {}", self.resume()));
            assert_eq!(lignes.len(), 1, "une ligne de compte : {}", self.resume());
            let valeurs: Vec<&Value> = lignes[0].as_object().unwrap_or_else(|| panic!("objet attendu : {}", self.resume())).values().collect();
            assert_eq!(valeurs.len(), 1, "une colonne : {}", self.resume());
            valeurs[0].as_i64().unwrap_or_else(|| panic!("entier attendu : {}", self.resume()))
        }
    }

    async fn az3c_exporter(banc: &BancFroidSurLaRoute, corps: &Value) -> Az3cServi {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(banc.addr, "POST", "/api/export", Some(&banc.authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked : {brut}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        Az3cServi { code, corps: serde_json::from_str(&c).unwrap_or(Value::Null), brut }
    }

    fn az3c_fenetre(banc: &BancFroidSurLaRoute) -> (i64, i64) {
        (banc.base_froide - 60, banc.base_froide + LIGNES_FROIDES * 60)
    }

    /// (1) RÉGLAGES PAR DÉFAUT, `limit` 10, `search source=froid | stats count` sur une fenêtre entièrement froide :
    /// `/api/query` sert 120 ; l'export sert le même compte, 200, non tronqué. (2) même requête, `PLUME_EXPORT_MAX=50`,
    /// sans `limit` : 200, 120. MUTANT : AZ3C_HYDRATE_A_LA_BORNE (422, `cold_row_cap` 11 puis 51).
    #[tokio::test]
    async fn az3c_agregat_froid_servi_par_query_l_est_par_un_export_etroit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3cEnv::poser(&[]);
        let banc = BancFroidSurLaRoute::monter("az3c-agregat-etroit", false).await;
        banc.vieillir();
        let (de, a) = az3c_fenetre(&banc);
        let soql = "search source=froid | stats count";

        let (code, v) = banc.interroger(soql, de, a).await;
        assert_eq!(code, 200, "/api/query : servi : {v}");
        assert_eq!(v["rows"], json!([[LIGNES_FROIDES]]), "/api/query : le compte entier : {v}");

        let s = az3c_exporter(&banc, &json!({ "soql": soql, "from": de, "to": a, "limit": 10, "format": "json" })).await;
        assert_eq!(s.code, 200, "(1) `limit` 10 : l'agrégat que /api/query sert n'est pas refusé : {}", s.resume());
        assert_eq!(s.compte(), LIGNES_FROIDES, "(1) `limit` 10 : le compte entier : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("0"), "(1) non tronqué : {}", s.resume());

        std::env::set_var("PLUME_EXPORT_MAX", "50");
        let s = az3c_exporter(&banc, &json!({ "soql": soql, "from": de, "to": a, "format": "json" })).await;
        assert_eq!(s.code, 200, "(2) PLUME_EXPORT_MAX=50 : servi : {}", s.resume());
        assert_eq!(s.compte(), LIGNES_FROIDES, "(2) PLUME_EXPORT_MAX=50 : le compte entier : {}", s.resume());
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("0"), "(2) non tronqué : {}", s.resume());
    }

    /// (3) `limit` 5, `| where ts >= base+110*60` (10 lignes vraies, les plus récentes) : l'export rend 5 lignes vraies,
    /// coupé à SA borne et le disant (`x-plume-export-borne: 5`). MUTANT : AZ3C_HYDRATE_A_LA_BORNE (0 ligne : les 6
    /// plus anciennes recopiées, toutes filtrées).
    #[tokio::test]
    async fn az3c_export_filtre_etroit_rend_ses_lignes_vraies() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3cEnv::poser(&[]);
        let banc = BancFroidSurLaRoute::monter("az3c-filtre-etroit", false).await;
        banc.vieillir();
        let (de, a) = az3c_fenetre(&banc);
        let seuil = banc.base_froide + 110 * 60;
        let soql = format!("search source=froid | where ts >= {seuil}");

        let (code, v) = banc.interroger(&soql, de, a).await;
        assert_eq!(code, 200, "/api/query : servi : {v}");
        assert_eq!(v["rows"].as_array().map(|r| r.len()), Some(10), "/api/query : les 10 lignes vraies : {}", v["stats"]);

        let s = az3c_exporter(&banc, &json!({ "soql": soql, "from": de, "to": a, "limit": 5, "format": "json" })).await;
        assert_eq!(s.code, 200, "servi : {}", s.resume());
        let lignes = s.corps.as_array().unwrap_or_else(|| panic!("tableau attendu : {}", s.resume()));
        assert_eq!(lignes.len(), 5, "la borne de lignes vraies, pas moins : {}", s.resume());
        assert!(
            lignes.iter().all(|l| l["ts"].as_i64().is_some_and(|ts| ts >= seuil)),
            "chaque ligne rendue passe le filtre : {}",
            s.resume()
        );
        assert_eq!(s.entete("x-plume-truncated").as_deref(), Some("1"), "coupé : {}", s.resume());
        assert_eq!(s.entete("x-plume-export-borne").as_deref(), Some("5"), "coupé à SA borne, et dit : {}", s.resume());
    }

    /// (4) `PLUME_QUERY_MAX=50`, `PLUME_EXPORT_MAX=20` (borne plus une ligne, 21, sous 50), agrégat froid sur 120 lignes :
    /// 422, `cold_row_cap` 50, le message nomme `PLUME_QUERY_MAX=50`, seul plafond qui a arrêté la lecture, et pas la
    /// borne de l'export. MUTANTS : AZ3C_MESSAGE_TOUJOURS_BORNE (message), AZ3C_HYDRATE_A_LA_BORNE (`cold_row_cap` 21).
    #[tokio::test]
    async fn az3c_refus_sous_export_etroit_nomme_plume_query_max() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _leviers = Az3cEnv::poser(&[("PLUME_QUERY_MAX", "50"), ("PLUME_EXPORT_MAX", "20")]);
        let banc = BancFroidSurLaRoute::monter("az3c-refus-etroit", false).await;
        banc.vieillir();
        let (de, a) = az3c_fenetre(&banc);
        let s = az3c_exporter(&banc, &json!({ "soql": "search source=froid | stats count", "from": de, "to": a, "format": "json" })).await;
        assert_eq!(s.code, 422, "agrégat sur une recopie tronquée à 50 : refusé : {}", s.resume());
        assert_eq!(s.corps["reason"], json!("cold_truncated_aggregate"), "{}", s.resume());
        assert_eq!(s.corps["cold_row_cap"], json!(50), "la lecture froide s'arrête à PLUME_QUERY_MAX, pas à la borne : {}", s.resume());
        let message = s.corps["error"].as_str().unwrap_or_default();
        assert!(message.contains("plafond RAM PLUME_QUERY_MAX=50"), "le message nomme le plafond appliqué : {message}");
        assert!(!message.contains("plafond de l'export"), "la borne de l'export n'a pas arrêté la lecture : {message}");
    }
}
