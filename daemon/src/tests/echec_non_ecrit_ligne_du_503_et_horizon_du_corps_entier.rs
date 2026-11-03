// =====================================================================================
// `P10.32-o` (vague BI) — LE 503 D'UNE ÉCRITURE DU CACHE REFUSÉE, JUGÉ ENTIER (HORIZON COMPRIS), ET SA LIGNE DE JOURNAL
// DANS LA VARIANTE DE L'ÉCHEC.
//
// MESURÉ PAR LE VÉRIFICATEUR SUR 2cbef5c8 :
//  * l'horizon du 503 `cache_non_ecrit` / `calcul_echoue` (`coverage_synthetique(raison, from, now_s,
//    horizon_courant(pc))`, dashboards.rs `serve_swr`) n'était relu par personne : un horizon jeté (`None`) restait vert.
//    Les témoins d'avant jouent des panneaux qui ne nomment aucune table à rétention : leur horizon n'a pas d'`horizon_ts`,
//    et le jeter ne change rien à leur corps. Le panneau d'ici lit `event`, sous une rétention ÉCRITE ;
//  * la ligne de journal de ce 503 dans sa variante échec (« échec du dernier calcul NON ÉCRIT au cache ») n'était relue
//    par aucun test : une ligne qui disait « résultat du dernier calcul » pour un échec restait verte.
//
// CE QUE CES TÉMOINS JUGENT, par le HANDLER RÉEL `panel_data` (coût inconnu -> `serve_swr`) :
//  (1) panneau qui lit `event`, rétention écrite, refus d'écrire un RÉSULTAT puis refus d'écrire un ÉCHEC, chacun récent :
//      le 503 ENTIER à l'octet près (clés, cause et notice écrites ici, identifiant servi, `searched_from`, `calcule_a`
//      dans l'échange, `horizon_ts` = l'instant moins la rétention écrite, `older_outside_window`), rien d'armé ;
//  (2) en sous-processus, MODE 1, DEUX tenants réels : la ligne `[panel]` du 503 de l'échec, ENTIÈRE (identifiant servi,
//      instant du refus, panneau, tenant échappé, geste), aucune autre ligne « NON ÉCRIT au cache ».
// MUTANTS JOUÉS (variable de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : l'horizon jeté du
// 503 (D18), la ligne qui dit « résultat du dernier calcul » pour un échec (D11).
// CE QUE CES TÉMOINS NE TIENNENT PAS : `older_outside_window` vaut `false` ici (fenêtre de 24 h sous une rétention plus
// longue) ; sa valeur vraie est jugée par les témoins de l'horizon des panneaux, pas par ceux-ci.
// =====================================================================================
mod echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const BI2_SQL_EVENT: &str = "SELECT COUNT(*) AS n FROM event";
    const BI2_RETENTION_JOURS: i64 = 30;
    const BI2_PHRASE: &str = "bi2 phrase servie de la classe";
    // Écrites ici : un témoin qui lirait la constante de production ne verrait pas qu'elle change.
    const BI2_CAUSE_RESULTAT: &str = "RÉSULTAT DU PANNEAU NON ÉCRIT : la base a refusé d'écrire dans le cache le résultat du dernier calcul de ce panneau — ce n'est PAS une mesure en cours. RIEN n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Si le refus persiste, la base est pleine ou en lecture seule.";
    const BI2_NOTICE_RESULTAT: &str = "la base a refusé d'écrire dans le cache le résultat du dernier calcul de ce panneau : aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS une absence ; un nouveau calcul est armé au plus une fois par durée du cache, le détail est au journal de l'exploitant.";
    const BI2_CAUSE_ECHEC: &str = "CALCUL DU PANNEAU EN ÉCHEC, ÉCHEC NON ÉCRIT : le dernier calcul de ce panneau a échoué et la base a refusé d'écrire cet échec dans le cache — ce n'est PAS une mesure en cours. RIEN n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Cause du calcul : ";
    const BI2_NOTICE_ECHEC: &str = "le calcul de ce panneau a échoué (cause dans `error`) : aucune ligne n'a été calculée. Ce corps vide n'établit PAS une absence ; une nouvelle tentative suit l'expiration du cache.";
    const BI2_ENFANT: &str = "BI2_ENFANT_LIGNE_DU_503_DE_L_ECHEC";
    const BI2_ATTENDU: &str = "BI2-ATTENDU:";
    const BI2_ALPHA: &str = "bi2-alpha";
    const BI2_BETA: &str = "bi2-beta";

    /// Refuse les INSERT de `panel_cache` et de `panel_cost` (le panneau reste au coût inconnu, donc en SWR).
    fn bi2_refuser(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } | AuthAction::Insert { table_name: "panel_cost" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Un panneau qui lit `event` (horizon dérivable) sur un tableau de `proprietaire`, et la rétention ÉCRITE.
    fn bi2_semer(conn: &Connection, proprietaire: &str, visibilite: &str) -> i64 {
        conn.execute(
            "INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','retention_days',?1)",
            params![BI2_RETENTION_JOURS.to_string()],
        )
        .expect("fixture : rétention écrite");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('bi2',?1,?2)", params![proprietaire, visibilite])
            .expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'bi2',?2,0,'table')", params![did, BI2_SQL_EVENT])
            .expect("fixture : panneau");
        conn.last_insert_rowid()
    }

    /// Le 503 servi, comparé ENTIER : seules les valeurs qu'aucune constante ne fixe (identifiant, instants) sont prises
    /// au corps, chacune bornée par l'échange avant d'être remise dans l'attendu.
    async fn bi2_le_503_entier(st: &AppState, id: i64, from: i64, error: &str, raison: &str, notice: &str, quoi: &str) {
        let avant = now();
        let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(t3c_admin()), Path(id), t3c_q(from)).await).await;
        let apres = now();
        assert_eq!(code, 503, "{quoi} : refus nommé : {v}");
        assert!(t3c_rien_en_vol(st), "{quoi} : refus récent, rien d'armé");
        let cid = v["id"].as_str().filter(|s| !s.is_empty()).unwrap_or_else(|| panic!("{quoi} : identifiant servi : {v}")).to_string();
        let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{quoi} : calcule_a : {v}"));
        assert!((avant..=apres).contains(&calcule_a), "{quoi} : calcule_a dans l'échange : {v}");
        let horizon_ts = v["stats"]["coverage"]["horizon_ts"]
            .as_i64()
            .unwrap_or_else(|| panic!("{quoi} : un panneau qui lit `event` sous une rétention écrite a un horizon mesuré : {v}"));
        let retenue = BI2_RETENTION_JOURS * 86_400;
        assert!((avant - retenue..=apres - retenue).contains(&horizon_ts), "{quoi} : horizon = l'instant moins la rétention écrite : {v}");
        let attendu = json!({
            "columns": [],
            "rows": [],
            "error": error,
            "id": cid,
            "stats": { "coverage": {
                "searched_from": from,
                "calcule_a": calcule_a,
                "horizon_ts": horizon_ts,
                "older_outside_window": false,
                "reason": raison,
                "notice": notice,
            } }
        });
        assert_eq!(v, attendu, "{quoi} : le 503 ENTIER, horizon compris");
    }

    // ---------------------------------------------------------------------------------
    // (1) LE 503 ENTIER, HORIZON COMPRIS, POUR LE RÉSULTAT ET POUR L'ÉCHEC NON ÉCRITS.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bi2_le_503_d_une_ecriture_refusee_est_servi_entier_horizon_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, dbp, _g, _panne, _sain) = t3c_state("bi2-horizon");
        let id = bi2_semer(&st.db.lock(), "adm", "private");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, id, from);
        assert!(ttl > 0, "précondition : le cache des panneaux est actif");
        bi2_refuser(&st.db.lock());

        let refus = panneau_avoue::cache_ecrire_dit(&st.db.lock(), id, &rk, &fp, now(), "{}");
        assert!(refus.is_err(), "fixture : l'écriture d'un résultat est refusée, le refus noté");
        bi2_le_503_entier(&st, id, from, BI2_CAUSE_RESULTAT, "cache_non_ecrit", BI2_NOTICE_RESULTAT, "résultat non écrit").await;

        let n = now();
        let refus = panneau_avoue::cache_ecrire_l_echec_dit(&st.db.lock(), id, &rk, &fp, n, n, "{}", BI2_PHRASE);
        assert!(refus.is_err(), "fixture : l'écriture d'un échec est refusée, le refus noté");
        let cause = format!("{BI2_CAUSE_ECHEC}{BI2_PHRASE}");
        bi2_le_503_entier(&st, id, from, &cause, "calcul_echoue", BI2_NOTICE_ECHEC, "échec non écrit").await;
        ff_rm(&dbp);
    }

    // ---------------------------------------------------------------------------------
    // (2) LA LIGNE DU 503 DE L'ÉCHEC, MODE 1, DEUX TENANTS.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bi2_ligne_du_503_de_l_echec_non_ecrit_entiere_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        if std::env::var(BI2_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            for t in [BI2_ALPHA, BI2_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bi2")), Json(json!({ "id": t, "name": t })))
                    .await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
            }
            let from = now() - 86_400;
            let rk = env_range_key(None, &cache_range_key(from, 0, now()));
            let fp = query_fingerprint(BI2_SQL_EVENT, false);
            let mut attendus: Vec<String> = Vec::new();
            for t in [BI2_ALPHA, BI2_BETA] {
                let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
                let id = bi2_semer(&handle.lock(), "root", "shared");
                bi2_refuser(&handle.lock());
                // Le refus est noté ANTIDATÉ (dans la durée du cache) : l'instant écrit à la ligne est celui du refus.
                let refusee_a = now() - 3;
                let refus = panneau_avoue::cache_ecrire_l_echec_dit(&handle.lock(), id, &rk, &fp, refusee_a, refusee_a, "{}", BI2_PHRASE);
                assert!(refus.is_err(), "contrôle {t} : l'écriture de l'échec est refusée");
                let au = au_tadmin("adm", t);
                let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au), Path(id), t3c_q(from)).await).await;
                assert_eq!(code, 503, "contrôle {t} : 503 : {v}");
                assert_eq!(v["stats"]["coverage"]["reason"], json!("calcul_echoue"), "contrôle {t} : variante de l'échec : {v}");
                let cid = v["id"].as_str().unwrap_or_default();
                attendus.push(format!(
                    "[{cid}] [panel] WARN échec du dernier calcul NON ÉCRIT au cache (refus à {refusee_a}), panneau #{id}, tenant \"{t}\" — aucune charge servable en cache : refus nommé servi en 503 (sans `warming`), aucun calcul armé avant l'expiration du cache"
                ));
            }
            for l in &attendus {
                println!("{BI2_ATTENDU}{l}");
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::echec_non_ecrit_ligne_du_503_et_horizon_du_corps_entier::bi2_ligne_du_503_de_l_echec_non_ecrit_entiere_deux_tenants",
            ])
            .env(BI2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // La marque peut suivre, sur la même ligne, ce que le banc de test écrit sans retour à la ligne : on lit après elle.
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BI2_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> = stderr.lines().filter(|l| l.contains("NON ÉCRIT au cache")).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert_eq!(attendus.len(), 2, "contrôle : une ligne attendue par tenant : {stdout}");
        assert_eq!(vus, attendus, "chaque ligne ENTIÈRE, tenant échappé, aucune autre :\n{stderr}");
    }
}
