// =====================================================================================
// `P10.32-o` — UNE LIGNE DE CACHE NON LUE OU ILLISIBLE N'EST JAMAIS SERVIE COMME UNE CHAUFFE.
// `P10.29-l` — LES LIGNES `[panel]` DE `serve_swr` NOMMENT LE TENANT DE L'APPELANT.
//
// MESURÉ SUR b29051c4 (lecture de `handlers/dashboards.rs::serve_swr`) : une ligne `LectureDeCache::NonLue` (lecture
// refusée par la base) partait en MISS — corps `{warming: true}` dont la notice disait « ce n'est pas une mesure en
// cours » ; la console, qui lit `warming` d'abord (web/dashboards.js, `j.warming === true`), affichait « chargement
// (mesure en cours) ». Une ligne `Illisible` (lue, non décodable) partait aussi en `warming`, raison `mesure_en_cours`.
// Et les deux lignes `[panel] WARN ligne de cache …` ne nommaient pas le tenant.
//
// LE CORRECTIF (handlers/dashboards.rs, `serve_swr`, enum `LigneDeCacheRatee`) :
//  * NON LUE -> 503 `{columns: [], rows: [], error: CAUSE_LIGNE_DE_CACHE_DU_PANNEAU_NON_LUE, id, stats.coverage}` (raison
//    `cache_non_lu` et sa notice, horizon mesuré), rafraîchissement armé si le panneau compile ; la console le peint en
//    lecture refusée avec sa cause (`if (!r.ok) nonServie()`, web/dashboards.js ; `causeNommeeParLeDemon`, web/core.js) ;
//  * ILLISIBLE -> 200 `{columns: [], rows: [], stats.coverage}` de raison `paye_utile_illisible` (le corps d'une charge
//    qui n'est pas du JSON), sans `warming`, rafraîchissement armé si le panneau compile ;
//  * les deux sont jugées AVANT le refus du compilateur, rendu seulement sur une vraie absence ;
//  * chaque ligne nomme le tenant de l'appelant, échappé (`{:?}`) ; la NON LUE porte l'identifiant de corrélation servi.
//
// CE QUE CE TÉMOIN JUGE, dans UN sous-processus (journal capturé, compte de production par processus), en MODE 1 avec
// DEUX tenants réels créés par `tenant_create`, chacun avec son panneau sain (`event`, horizon dérivable) et son panneau
// refusé par le compilateur, appelés par `panel_data` au rôle lecteur :
//  (1) ILLISIBLE, panneau sain : 200, clés exactes, raison `paye_utile_illisible`, `horizon_ts` présent, aucun `warming` ;
//      le rafraîchissement armé REMPLACE la ligne par une charge utile sans `error` ;
//  (2) ILLISIBLE, panneau refusé par le compilateur : 200 (pas le 400 du compilateur), même forme, sans horizon, rien armé,
//      la ligne reste illisible ;
//  (3) NON LUE (autorisateur qui refuse `panel_cache.payload` sur la base du tenant), panneau sain, ligne absente : 503,
//      clés exactes, `error` = phrase du témoin, raison `cache_non_lu`, notice du témoin, `horizon_ts` présent, `id` servi ;
//      le rafraîchissement armé ÉCRIT la ligne ;
//  (4) NON LUE, panneau refusé par le compilateur : 503 (pas le 400), sans horizon, rien armé ;
//  journal : les huit lignes `[panel] WARN ligne de cache …` ENTIÈRES, dans l'ordre, tenant de l'appelant par ligne.
// MUTANTS JOUÉS (variable `VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : BF6_NONLUE_EN_CHAUFFE,
// BF6_ILLISIBLE_EN_CHAUFFE, BF6_NONLUE_200, BF6_NONLUE_SANS_RAFRAICHIR, BF6_ILLISIBLE_SANS_RAFRAICHIR,
// BF6_COMPILATION_D_ABORD, BF6_TENANT_ILLISIBLE_FIGE, BF6_TENANT_NONLUE_FIGE, BF6_TENANT_NON_ECHAPPE,
// BF6_NONLUE_SANS_HORIZON, BF6_ILLISIBLE_SANS_HORIZON, BF6_NONLUE_SANS_NOTICE, BF6_NONLUE_ID_DIVERGENT.
// CE QUE CE TÉMOIN NE TIENT PAS : les lignes `[cache]` du pré-chauffage (rollups.rs, `cache_refresh_all_panels`) ne
// nomment toujours pas le tenant : la boucle qui l'appelle (server/boucles_de_fond.rs, `_tid`) ne le lui passe pas ;
// la console ne lit pas `stats.rafraichissement_en_echec`.
// =====================================================================================
mod ligne_de_cache_non_lue_jamais_servie_en_chauffe {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const BF6_ENFANT: &str = "BF6_ENFANT_LIGNE_DE_CACHE_NON_LUE";
    const BF6_ATTENDU: &str = "BF6-ATTENDU:";
    const BF6_FIN: &str = "BF6-FIN:";
    const BF6_ALPHA: &str = "bf6-alpha";
    const BF6_BETA: &str = "bf6-beta";
    const BF6_SQL_SAIN: &str = "SELECT COUNT(*) AS n FROM event";
    const BF6_GXQL_REFUSE: &str = "search source=bf6 | inputlookup secret";
    const BF6_ILLISIBLE: &str = "Invalid column type Blob at index: 0, name: payload";
    const BF6_REFUS: &str = "access to panel_cache.payload is prohibited [code étendu 23]";
    /// La phrase servie, écrite ici (et non empruntée à la production) : un témoin qui lirait la constante ne verrait
    /// pas qu'elle change.
    const BF6_CAUSE: &str = "LIGNE DE CACHE NON LUE : la base n'a pas rendu la ligne de cache de ce panneau — ce n'est PAS \
         une mesure en cours ni une absence, c'est une lecture qui n'a pas eu lieu. RIEN n'est servi ; un rafraîchissement \
         est armé si le panneau compile. Réessayez ; si le refus persiste, la table du cache des panneaux est illisible.";
    const BF6_NOTICE_NON_LUE: &str = "la ligne de cache de ce panneau n'a pas pu être lue (lecture refusée par la base) : \
         aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS une absence ; le détail \
         est au journal de l'exploitant.";

    fn bf6_lecteur(t: &str) -> AuthUser {
        AuthUser { name: "lecteur-bf6".into(), role: "viewer".into(), tenant: t.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    fn bf6_q(from: i64) -> Query<HashMap<String, String>> {
        Query(HashMap::from([("from".to_string(), from.to_string()), ("to".to_string(), "0".to_string())]))
    }

    fn bf6_issue(conn: &Connection, id: i64, rk: &str, fp: &str) -> String {
        match panneau_avoue::cache_lire_dit(conn, id, rk, fp) {
            panneau_avoue::LectureDeCache::Lue(p, _) => format!("Lue:{p}"),
            panneau_avoue::LectureDeCache::Absente => "Absente".into(),
            panneau_avoue::LectureDeCache::Illisible(_) => "Illisible".into(),
            panneau_avoue::LectureDeCache::NonLue(_) => "NonLue".into(),
        }
    }

    fn bf6_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    fn bf6_ligne_illisible(id: i64, t: &str, rang: u64) -> String {
        format!(
            "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant \"{t}\" : {BF6_ILLISIBLE} \
             (lecture de cache ratée n° {rang} depuis le démarrage) — servie comme une charge utile illisible (corps \
             synthétique `paye_utile_illisible`, sans `warming`), rafraîchissement armé si le panneau compile, qui la \
             remplacera"
        )
    }

    fn bf6_ligne_non_lue(cid: &str, id: i64, t: &str, rang: u64) -> String {
        format!(
            "[{cid}] [panel] WARN ligne de cache NON LUE, panneau #{id}, tenant \"{t}\" : {BF6_REFUS} (lecture de cache \
             ratée n° {rang} depuis le démarrage) — refus de lecture nommé servi en 503 (sans `warming`), rafraîchissement \
             armé si le panneau compile"
        )
    }

    fn bf6_refuser(handle: &Arc<Mutex<Connection>>) {
        handle.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bf6_permettre(handle: &Arc<Mutex<Connection>>) {
        handle.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Joue les quatre cas sur le tenant `t` et rend les lignes de journal attendues, dans l'ordre.
    async fn bf6_jouer_un_tenant(st: &AppState, t: &str) -> Vec<String> {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bf6")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let (sain, refuse) = {
            let conn = handle.lock();
            conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('bf6','root','shared')", []).expect("fixture : tableau");
            let did = conn.last_insert_rowid();
            let mut ids = Vec::new();
            for (q, soql) in [(BF6_SQL_SAIN, 0), (BF6_GXQL_REFUSE, 1)] {
                conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'bf6',?2,?3,'table')", params![did, q, soql])
                    .expect("fixture : panneau");
                ids.push(conn.last_insert_rowid());
            }
            (ids[0], ids[1])
        };
        assert!(panneau_avoue::compile_panneau_avoue(BF6_GXQL_REFUSE, true, now() - 86_400, 0, None).is_err(), "précondition : le GXQL est refusé");
        let au = bf6_lecteur(t);
        let from = now() - 86_400;
        let rk = env_range_key(None, &cache_range_key(from, 0, now()));
        let fp_sain = query_fingerprint(BF6_SQL_SAIN, false);
        let fp_refuse = query_fingerprint(BF6_GXQL_REFUSE, true);
        let poser_un_blob = |id: i64, fp: &str| {
            handle
                .lock()
                .execute(
                    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                    params![id, rk, fp, now() - 5],
                )
                .expect("fixture : ligne BLOB");
        };
        let mut attendus = Vec::new();

        // (1) ILLISIBLE, panneau sain.
        poser_un_blob(sain, &fp_sain);
        assert_eq!(bf6_issue(&handle.lock(), sain, &rk, &fp_sain), "Illisible", "fixture (1) : {t}");
        let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), bf6_q(from)).await).await;
        assert_eq!(code, 200, "(1) {t} : {corps}");
        assert_eq!(bf6_cles(&corps), vec!["columns", "rows", "stats"], "(1) {t} : forme exacte, sans `warming` : {corps}");
        assert_eq!((corps["columns"].clone(), corps["rows"].clone()), (json!([]), json!([])), "(1) {t} : aucune ligne : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("paye_utile_illisible"), "(1) {t} : {corps}");
        assert!(corps["stats"]["coverage"]["horizon_ts"].is_i64(), "(1) {t} : horizon mesuré : {corps}");
        attendus.push(bf6_ligne_illisible(sain, t, rang));
        t3c_attendre_la_tache(st).await;
        let apres = bf6_issue(&handle.lock(), sain, &rk, &fp_sain);
        let charge: Value = serde_json::from_str(apres.strip_prefix("Lue:").unwrap_or_else(|| panic!("(1) {t} : ligne remplacée : {apres}")))
            .unwrap_or_else(|_| panic!("(1) {t} : charge JSON : {apres}"));
        assert!(charge.get("error").is_none() && charge["rows"].is_array(), "(1) {t} : le rafraîchissement a écrit un résultat : {charge}");

        // (2) ILLISIBLE, panneau refusé par le compilateur : la ligne ratée l'emporte, rien n'est armé.
        poser_un_blob(refuse, &fp_refuse);
        let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(refuse), bf6_q(from)).await).await;
        assert!(t3c_rien_en_vol(st), "(2) {t} : rien n'est armé");
        assert_eq!(code, 200, "(2) {t} : pas le refus du compilateur : {corps}");
        assert_eq!(bf6_cles(&corps), vec!["columns", "rows", "stats"], "(2) {t} : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("paye_utile_illisible"), "(2) {t} : {corps}");
        assert!(corps["stats"]["coverage"].get("horizon_ts").is_none(), "(2) {t} : aucun horizon sans compilation : {corps}");
        attendus.push(bf6_ligne_illisible(refuse, t, rang));

        // (3) NON LUE, panneau sain, ligne absente : 503 nommé, le rafraîchissement armé écrit la ligne.
        // Le coût mesuré par le rafraîchissement de (1) classerait le panneau en LIVE (coût bas confirmé) : il est retiré,
        // le panneau redevient INCONNU, donc servi en SWR (`serve_swr`), le chemin jugé ici.
        handle.lock().execute("DELETE FROM panel_cache WHERE panel_id=?1", params![sain]).expect("fixture : ligne retirée");
        handle.lock().execute("DELETE FROM panel_cost WHERE panel_id=?1", params![sain]).expect("fixture : coût retiré");
        bf6_refuser(&handle);
        let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), bf6_q(from)).await).await;
        t3c_attendre_la_tache(st).await;
        bf6_permettre(&handle);
        assert_eq!(code, 503, "(3) {t} : {corps}");
        assert_eq!(bf6_cles(&corps), vec!["columns", "error", "id", "rows", "stats"], "(3) {t} : forme exacte, sans `warming` : {corps}");
        assert_eq!(corps["error"], json!(BF6_CAUSE), "(3) {t} : la phrase servie : {corps}");
        assert_eq!((corps["columns"].clone(), corps["rows"].clone()), (json!([]), json!([])), "(3) {t} : aucune ligne : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("cache_non_lu"), "(3) {t} : {corps}");
        assert_eq!(corps["stats"]["coverage"]["notice"], json!(BF6_NOTICE_NON_LUE), "(3) {t} : {corps}");
        assert!(corps["stats"]["coverage"]["horizon_ts"].is_i64(), "(3) {t} : horizon mesuré : {corps}");
        let cid = corps["id"].as_str().unwrap_or_else(|| panic!("(3) {t} : identifiant servi : {corps}")).to_string();
        attendus.push(bf6_ligne_non_lue(&cid, sain, t, rang));
        let apres = bf6_issue(&handle.lock(), sain, &rk, &fp_sain);
        assert!(apres.starts_with("Lue:") && !apres.contains("\"error\""), "(3) {t} : le rafraîchissement armé a écrit la ligne : {apres}");

        // (4) NON LUE, panneau refusé par le compilateur : 503, rien n'est armé.
        bf6_refuser(&handle);
        let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
        let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(refuse), bf6_q(from)).await).await;
        let rien = t3c_rien_en_vol(st);
        bf6_permettre(&handle);
        assert!(rien, "(4) {t} : rien n'est armé");
        assert_eq!(code, 503, "(4) {t} : pas le refus du compilateur : {corps}");
        assert_eq!(corps["error"], json!(BF6_CAUSE), "(4) {t} : {corps}");
        assert_eq!(corps["stats"]["coverage"]["reason"], json!("cache_non_lu"), "(4) {t} : {corps}");
        assert!(corps["stats"]["coverage"].get("horizon_ts").is_none(), "(4) {t} : aucun horizon sans compilation : {corps}");
        let cid = corps["id"].as_str().unwrap_or_else(|| panic!("(4) {t} : identifiant servi : {corps}")).to_string();
        attendus.push(bf6_ligne_non_lue(&cid, refuse, t, rang));
        attendus
    }

    #[tokio::test]
    async fn bf6_ligne_non_lue_ou_illisible_jamais_en_chauffe_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        if std::env::var(BF6_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let mut attendus = Vec::new();
            for t in [BF6_ALPHA, BF6_BETA] {
                attendus.extend(bf6_jouer_un_tenant(&st, t).await);
            }
            for l in &attendus {
                println!("{BF6_ATTENDU}{l}");
            }
            println!("{BF6_FIN} {}", attendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .env(BF6_ENFANT, "1")
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ligne_de_cache_non_lue_jamais_servie_en_chauffe::bf6_ligne_non_lue_ou_illisible_jamais_en_chauffe_deux_tenants",
            ])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant juge chaque corps et sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BF6_FIN} 8")), "contrôle : huit lignes attendues (quatre cas, deux tenants) : {stdout}");
        let attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BF6_ATTENDU).map(|(_, r)| r.to_string())).collect();
        assert!(attendus.len() >= 8, "plancher : huit lignes attendues ({})", attendus.len());
        assert!(
            attendus.iter().any(|l| l.contains(&format!("tenant \"{BF6_ALPHA}\""))) && attendus.iter().any(|l| l.contains(&format!("tenant \"{BF6_BETA}\""))),
            "contrôle : les deux tenants sont nommés"
        );
        let journal: Vec<String> = stderr.lines().filter(|l| l.contains("[panel] WARN ligne de cache")).map(str::to_string).collect();
        assert_eq!(journal, attendus, "chaque ligne, entière, nomme le tenant de l'appelant :\n{stderr}");
        for l in &journal {
            assert!(!l.contains(BF6_SQL_SAIN) && !l.contains(BF6_GXQL_REFUSE), "jamais la requête au journal : {l}");
        }
    }
}
