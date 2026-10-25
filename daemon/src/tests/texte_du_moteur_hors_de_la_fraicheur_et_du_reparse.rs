// =====================================================================================
// `P10.29-l` (restes AO : « `FinDeParcours::cause()` encore servi par `freshness.rs` et `detection.rs` ») — LE TEXTE DU
// MOTEUR NE PART PLUS DANS LES AVEUX DE PARCOURS DE `/api/freshness` NI DANS `cause_scan` DU REPARSE.
//
// LE DÉFAUT, LU SUR ac1f43b8 AVANT LE CORRECTIF : `ParcoursDeFraicheur::noter` gardait `cause.to_string()` (le
// `e.to_string()` de rusqlite que rend `FinDeParcours::cause()`), servi ensuite dans `error` (« … (cause) ») et dans
// `imputation_des_alertes.error` d'un corps 200 que le rôle lecteur reçoit ; les entrées de famille (`feeds[].cause`) et
// `series_non_lues` recevaient le même texte. Un refus de l'autorisateur sur une fonction y citait l'énoncé interne
// entier (« not authorized to use function: COALESCE in SELECT … at offset 11 »). `parser_reparse` servait de même
// `cause_scan` = `CAUSE_REPARSE_INCOMPLET` suivi du texte du moteur.
//
// LE REMÈDE : chaque aveu garde sa constante et la fait suivre de la phrase fixe de la classe (`phrase_de_la_fin`
// d'`alerts.rs` : `FIN_DE_PARCOURS_INTERROMPUE` ou `FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE`) ; le moteur part à une ligne
// `[freshness] WARN` (parcours nommé par un libellé fixe, fin, tenant dont la base est lue ; jamais le chemin de cette
// base) ou `[reparse] WARN` (fin, tenant, lignes lues ; jamais la source demandée).
//
// TROIS PROPRIÉTÉS QU'UN JEU DE TÉMOINS PLUS ÉTROIT LAISSAIT PASSER : (a) seul le REFUS atteignait les deux familles et les séries, si bien qu'une
// phrase constante du refus à la place de `phrase_de_la_fin` y restait verte ; une préparation INTERROMPUE s'y atteint
// de façon déterministe : un énoncé tenu ACTIF sur la connexion empêche SQLite de remettre le drapeau d'interruption à
// zéro, et l'autorisateur le pose à la lecture qui PRÉCÈDE l'énoncé visé (un drapeau posé pendant la préparation de
// l'énoncé visé lui-même ne la fait pas échouer : elle se termine sans le relire) ;
// (b) la ligne `[reparse] WARN` n'était jouée qu'en mode 0 (tenant toujours `default`) et sans champ `source` ;
// (c) la ligne `[freshness] WARN` écrivait « tenant non connu ici » alors que le gestionnaire connaît `au.tenant` et la
// boucle de rollup le tenant parcouru : `compute_freshness_du_tenant` le reçoit désormais.
//
// LES TÉMOINS :
// (1) `ap1_fraicheur_par_la_route` (routeur réel, mode 0, jeton lecteur) : nominal, refus de COALESCE (partage des
//     alertes et famille des événements), refus de SUM (familles des événements et des instantanés, séries de métriques),
//     interruption du seul partage des alertes, préparation INTERROMPUE des deux familles puis des séries (classe
//     « interrompu » servie aux trois sites), puis nominal de nouveau ; corps comparés à l'octet, l'horloge seule
//     neutralisée (`ts` et `age_s`), sauf aux deux issues interrompues où les champs visés sont relus un à un ;
// (2) `ap1_reparse_par_la_route` (jeton administrateur, `dry_run`) : nominal, scan coupé en vol, ligne illisible au
//     mappeur ; corps entiers ;
// (3) `ap1_journal` : les deux parties en sous-processus, lignes `[freshness] WARN` et `[reparse] WARN` EN ENTIER, dans
//     l'ordre, une par fin ratée, aucune sur un chemin nominal ;
// (4) `ap1_deux_tenants` (mode 1, deux tenants réels, en sous-processus) : la fraîcheur refusée chez l'un (calcul à
//     froid, puis rafraîchissement d'une valeur périmée chez l'autre) et le reparse d'une ligne illisible avec un champ
//     `source` dans la demande ; chaque ligne de journal nomme le tenant de l'appelant, jamais la source ; l'autre
//     tenant est servi par SA base, sans ligne.
// Pannes : une connexion de lecture DÉPOSÉE dans le pool de la base (fraîcheur), ou la connexion d'écriture (reparse),
// armée d'un autorisateur qui refuse UNE fonction tant que le témoin la tient armée, ou d'un rappel de progression qui
// coupe le parcours visé une fois commencé (l'autorisateur, appelé à la préparation, dit quel énoncé est en vol).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les lectures d'une seule ligne de `compute_freshness` (`{e}` des lignes non lues,
// du flux des métriques et de ses comptes, épinglées par l'instrument 97 du harnais console), la dernière collecte non
// établie (texte composé par `sondes.rs`), les `non_lus` de `compute_integrations`, le 503 `prepare: {e}` du reparse,
// `collectors_cause` = `FinDeParcours::cause()` d'`admin_ui.rs` (vers :1078, épinglé par l'instrument 100 du harnais
// console) ; le tenant passé par la boucle de rollup (`boucles_de_fond.rs`, pré-chauffage de chaque tenant) n'est pas
// joué (boucle en fil dédié) ; le pré-chauffage de démarrage lit la seule base par défaut (tenant `default`).
// Restes nommés au rapport.
// =====================================================================================
mod ap1_fraicheur_et_reparse_sans_texte_du_moteur {
    use super::*;
    use crate::handlers::alerts::{FIN_DE_PARCOURS_INTERROMPUE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE};
    use crate::handlers::detection::CAUSE_REPARSE_INCOMPLET;
    use crate::handlers::freshness::{
        freshness_map, CAUSE_FAMILLE_DE_FLUX_NON_LUE, CAUSE_FRAICHEUR_INCOMPLETE, CAUSE_IMPUTATION_NON_ETABLIE,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const AP1_ENFANT: &str = "AP1_ENFANT_JOURNAL";
    const AP1_RENDU: &str = "AP1-RENDU:";
    const AP1_FIN: &str = "AP1-FIN:";
    /// Au plus autant de requêtes pour que la connexion armée serve la route (le pool global peut l'évincer).
    const AP1_ESSAIS: usize = 40;
    /// Au plus autant de lectures de `/api/freshness` en attendant que le calcul en fond remplace « warming ».
    const AP1_ATTENTES: usize = 800;
    const AP1_SERIE: &str = "ap1_serie";
    const AP1_SOURCE_REPARSE: &str = "ap1-src";
    /// Lignes lisibles semées pour le reparse.
    const AP1_EVENTS: i64 = 40;
    const AP1_TENANT_MODE_0: &str = "default";
    const AP1_ADMIN: &str = "root:rootpw1234567";

    // Les énoncés que les pannes refusent, tels que `compute_freshness` les prépare (prédicat d'environnement vide en
    // mode 0) : le journal les cite, et le témoin compare la ligne ENTIÈRE au texte que le moteur rend pour eux.
    const SQL_PARTAGE_SANS_COLONNE: &str = "SELECT '', COALESCE(detail,'') FROM alert WHERE status='new'";
    const SQL_FLUX_D_EVENEMENTS: &str = "SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) FROM event_rollup WHERE bucket>=?2 AND source<>'' GROUP BY source HAVING SUM(n)>=3";
    const SQL_FLUX_D_INSTANTANES: &str = "SELECT kind, MIN(l), SUM(nn), COUNT(*) FROM (SELECT kind, host, MAX(ts) AS l, SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) AS nn FROM snapshot WHERE ts>?2 GROUP BY kind, host) GROUP BY kind";
    const SQL_SERIES: &str = "SELECT name, MAX(ts), SUM(CASE WHEN ts>?1 THEN 1 ELSE 0 END) FROM metric WHERE ts>?2 GROUP BY name ORDER BY name";

    /// Les issues de la fraîcheur, dans l'ordre.
    const AP1_ORDRE_FRAICHEUR: [&str; 7] =
        ["nominal", "refus_coalesce", "refus_sum", "coupe_partage", "familles_interrompues", "series_interrompues", "nominal_apres"];
    /// La lecture qui précède les deux familles (marquages des sources, échec muet) et celle qui précède les séries
    /// (l'énoncé des comptes, seul à lire `metric.name` avant elles).
    const AP1_AVANT_LES_FAMILLES: Ap1Panne = Ap1Panne::InterromptApres("source_settings", "source");
    const AP1_AVANT_LES_SERIES: Ap1Panne = Ap1Panne::InterromptApres("metric", "name");

    #[derive(Clone, Copy)]
    enum Ap1Panne {
        /// Refuse la fonction nommée tant que la panne est armée.
        Fonction(&'static str),
        /// Coupe le premier pas du partage des alertes (la lecture de `alert.detail` à la préparation le désigne).
        CoupePartage,
        /// Tient un énoncé ACTIF sur la connexion, puis pose le drapeau d'interruption à la première lecture de
        /// `table.colonne`. Tant qu'un énoncé est actif, SQLite ne remet pas ce drapeau à zéro (ni au début d'une
        /// préparation, ni au premier pas) : l'énoncé qui lit la colonne échoue à son premier pas, et chaque énoncé
        /// préparé ENSUITE échoue à la préparation (« interrupted ») — la fin `NonCommence` d'une interruption. Le
        /// drapeau posé pendant la préparation de l'énoncé visé lui-même n'y suffirait pas : la préparation se
        /// termine sans le relire.
        InterromptApres(&'static str, &'static str),
    }

    struct Armement {
        joue: Arc<AtomicBool>,
        arme: Arc<AtomicBool>,
        /// L'énoncé tenu actif (`InterromptApres`), finalisé par `lever`.
        enonce_actif: Option<usize>,
    }
    impl Armement {
        /// Désarme la panne et finalise l'énoncé tenu actif : la connexion, rendue au pool, redevient ordinaire.
        fn lever(&self) {
            self.arme.store(false, Ordering::SeqCst);
            if let Some(stmt) = self.enonce_actif {
                // SAFETY : énoncé préparé sur une connexion du pool de lecture qui n'est plus en service (le calcul
                // qui l'a prise est rendu) ; finalisé une seule fois.
                unsafe { rusqlite::ffi::sqlite3_finalize(stmt as *mut rusqlite::ffi::sqlite3_stmt) };
            }
        }
    }

    /// Prépare et avance d'un pas un énoncé sans table, jamais réinitialisé : il reste ACTIF jusqu'à `lever`.
    fn ap1_tenir_un_enonce_actif(conn: &Connection) -> usize {
        let sql = std::ffi::CString::new("SELECT 1 UNION ALL SELECT 2").expect("énoncé sans NUL");
        let mut stmt: *mut rusqlite::ffi::sqlite3_stmt = std::ptr::null_mut();
        // SAFETY : pointeur de connexion valide le temps de l'appel ; l'énoncé est finalisé par `Armement::lever`.
        unsafe {
            let rc = rusqlite::ffi::sqlite3_prepare_v2(conn.handle(), sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut());
            assert_eq!(rc, rusqlite::ffi::SQLITE_OK, "instrument : énoncé actif préparé");
            assert_eq!(rusqlite::ffi::sqlite3_step(stmt), rusqlite::ffi::SQLITE_ROW, "instrument : énoncé actif avancé d'un pas");
        }
        stmt as usize
    }

    fn ap1_poser(conn: &Connection, panne: Ap1Panne) -> Armement {
        let joue = Arc::new(AtomicBool::new(false));
        let arme = Arc::new(AtomicBool::new(true));
        let mut enonce_actif = None;
        match panne {
            Ap1Panne::Fonction(nom) => {
                let (j, a) = (joue.clone(), arme.clone());
                conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Function { function_name } if a.load(Ordering::SeqCst) && function_name.eq_ignore_ascii_case(nom) => {
                        j.store(true, Ordering::SeqCst);
                        Authorization::Deny
                    }
                    _ => Authorization::Allow,
                }));
            }
            Ap1Panne::CoupePartage => {
                let commence = Arc::new(AtomicBool::new(false));
                let (c, a) = (commence.clone(), arme.clone());
                conn.authorizer(Some(move |ctx: AuthContext<'_>| {
                    if let AuthAction::Read { table_name: "alert", column_name: "detail" } = ctx.action {
                        if a.load(Ordering::SeqCst) {
                            c.store(true, Ordering::SeqCst);
                        }
                    }
                    Authorization::Allow
                }));
                let (j, a) = (joue.clone(), arme.clone());
                conn.progress_handler(1, Some(move || a.load(Ordering::SeqCst) && commence.load(Ordering::SeqCst) && !j.swap(true, Ordering::SeqCst)));
            }
            Ap1Panne::InterromptApres(table, colonne) => {
                enonce_actif = Some(ap1_tenir_un_enonce_actif(conn));
                let poignee = conn.get_interrupt_handle();
                let (j, a) = (joue.clone(), arme.clone());
                conn.authorizer(Some(move |ctx: AuthContext<'_>| {
                    if let AuthAction::Read { table_name, column_name } = ctx.action {
                        if a.load(Ordering::SeqCst) && table_name == table && column_name == colonne && !j.swap(true, Ordering::SeqCst) {
                            poignee.interrupt();
                        }
                    }
                    Authorization::Allow
                }));
            }
        }
        Armement { joue, arme, enonce_actif }
    }

    /// Dépose dans le pool de `chemin` une connexion de lecture armée de `panne`, après avoir vidé les connexions au
    /// repos de cette base (la connexion armée est la seule à prendre).
    fn ap1_armer_le_pool(chemin: &str, panne: Ap1Panne) -> Armement {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let armement = ap1_poser(&conn, panne);
        crate::query_exec::read_conn_put(chemin, conn);
        armement
    }

    async fn ap1_envoi(addr: std::net::SocketAddr, methode: &str, route: &str, authz: &str, corps: &str) -> (u16, String) {
        let (code, brut) = router_probe_envoi(addr, methode, route, Some(authz), &[("Content-Type", "application/json")], corps).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {route} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {route}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    /// `/api/freshness` sert « warming » puis calcule en fond (cache SWR) : le témoin vide l'entrée de CETTE base, puis
    /// relit jusqu'à ce que le calcul soit servi.
    async fn ap1_fraicheur_calculee(addr: std::net::SocketAddr, chemin: &str) -> (u16, String) {
        freshness_map().lock().retain(|cle, _| !cle.ends_with(chemin));
        for _ in 0..AP1_ATTENTES {
            let (code, corps) = ap1_envoi(addr, "GET", "/api/freshness", &viewer_authz(), "").await;
            let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
            if code != 200 || v.get("warming").is_none() {
                return (code, corps);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("instrument : `/api/freshness` est resté « warming » {AP1_ATTENTES} fois — le témoin ne conclut pas");
    }

    async fn ap1_fraicheur_en_panne(addr: std::net::SocketAddr, chemin: &str, panne: Ap1Panne) -> (u16, String) {
        for _ in 0..AP1_ESSAIS {
            let armement = ap1_armer_le_pool(chemin, panne);
            let rendu = ap1_fraicheur_calculee(addr, chemin).await;
            armement.lever();
            if armement.joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi `/api/freshness` en aucun des {AP1_ESSAIS} essais — le témoin ne conclut pas");
    }

    /// Les issues de la fraîcheur, dans l'ordre, sur une base à deux alertes actives et une série de métriques.
    async fn ap1_jouer_fraicheur() -> Vec<(&'static str, u16, String)> {
        let (st, base) = router_test_state("ap1-fraicheur");
        let chemin = base.as_str().to_string();
        st.db
            .lock()
            .execute_batch(&format!(
                "DELETE FROM alert; DELETE FROM event_rollup; DELETE FROM snapshot; DELETE FROM metric;
                 INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(1000,'rule.ap1a',2,'Alerte AP1 A','','new','T1046','');
                 INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(1001,'rule.ap1b',2,'Alerte AP1 B','','new','T1046','');
                 INSERT INTO metric(ts,name,labels,value) VALUES({},'{AP1_SERIE}','{{}}',1.0);",
                now() - 60
            ))
            .expect("fixture : deux alertes actives et une série");
        let addr = router_serve(st.clone()).await;
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();
        let (s, c) = ap1_fraicheur_calculee(addr, &chemin).await;
        rendus.push(("nominal", s, c));
        let (s, c) = ap1_fraicheur_en_panne(addr, &chemin, Ap1Panne::Fonction("COALESCE")).await;
        rendus.push(("refus_coalesce", s, c));
        let (s, c) = ap1_fraicheur_en_panne(addr, &chemin, Ap1Panne::Fonction("SUM")).await;
        rendus.push(("refus_sum", s, c));
        let (s, c) = ap1_fraicheur_en_panne(addr, &chemin, Ap1Panne::CoupePartage).await;
        rendus.push(("coupe_partage", s, c));
        let (s, c) = ap1_fraicheur_en_panne(addr, &chemin, AP1_AVANT_LES_FAMILLES).await;
        rendus.push(("familles_interrompues", s, c));
        let (s, c) = ap1_fraicheur_en_panne(addr, &chemin, AP1_AVANT_LES_SERIES).await;
        rendus.push(("series_interrompues", s, c));
        let (s, c) = ap1_fraicheur_calculee(addr, &chemin).await;
        rendus.push(("nominal_apres", s, c));
        rendus
    }

    /// Le reparse : nominal, chaque essai de coupe (le tir est CHERCHÉ jusqu'à un préfixe strict), puis une ligne
    /// illisible au mappeur. Chaque essai est rendu : le journal en porte une ligne par fin ratée, essais compris.
    async fn ap1_jouer_reparse() -> Vec<(String, u16, String)> {
        let (st, _base) = router_test_state("ap1-reparse");
        {
            let c = st.db.lock();
            c.execute_batch("DELETE FROM event;").expect("fixture : table event vide");
            for i in 0..AP1_EVENTS {
                c.execute(
                    "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'auth',1,?3)",
                    params![now() - 100, AP1_SOURCE_REPARSE, format!("m{i}")],
                )
                .expect("fixture : event");
            }
        }
        let addr = router_serve(st.clone()).await;
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(AP1_ADMIN));
        let corps = json!({ "dry_run": true, "days": 1 }).to_string();
        let mut rendus: Vec<(String, u16, String)> = Vec::new();
        let (s, c) = ap1_envoi(addr, "POST", "/api/parsers/reparse", &admin, &corps).await;
        rendus.push(("nominal".to_string(), s, c));
        for tir in 0..400usize {
            let arme = Arc::new(AtomicBool::new(true));
            {
                let c = st.db.lock();
                let commence = Arc::new(AtomicBool::new(false));
                let (cm, a) = (commence.clone(), arme.clone());
                c.authorizer(Some(move |ctx: AuthContext<'_>| {
                    if let AuthAction::Read { table_name: "event", column_name: "message" } = ctx.action {
                        if a.load(Ordering::SeqCst) {
                            cm.store(true, Ordering::SeqCst);
                        }
                    }
                    Authorization::Allow
                }));
                let vus = Arc::new(AtomicUsize::new(0));
                let a = arme.clone();
                c.progress_handler(8, Some(move || a.load(Ordering::SeqCst) && commence.load(Ordering::SeqCst) && vus.fetch_add(1, Ordering::SeqCst) == tir));
            }
            let (s, c) = ap1_envoi(addr, "POST", "/api/parsers/reparse", &admin, &corps).await;
            arme.store(false, Ordering::SeqCst);
            let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
            let lues = v["scanned"].as_i64().unwrap_or(-1);
            rendus.push((format!("coupe:{tir}"), s, c));
            if v.get("cause_scan").is_some() && lues > 0 && lues < AP1_EVENTS {
                break;
            }
        }
        {
            let c = st.db.lock();
            c.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            c.progress_handler(8, None::<fn() -> bool>);
            c.execute(
                "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'auth',1,x'00ff')",
                params![now() - 100, AP1_SOURCE_REPARSE],
            )
            .expect("fixture : ligne dont le message n'est pas un texte");
        }
        let (s, c) = ap1_envoi(addr, "POST", "/api/parsers/reparse", &admin, &corps).await;
        rendus.push(("illisible".to_string(), s, c));
        rendus
    }

    /// L'horloge seule est neutralisée : `ts` et chaque `age_s` numérique (flux et séries).
    fn ap1_sans_horloge(mut v: Value) -> Value {
        if v.get("ts").is_some() {
            v["ts"] = json!(0);
        }
        if let Some(flux) = v.get_mut("feeds").and_then(|f| f.as_array_mut()) {
            for f in flux.iter_mut() {
                if f["age_s"].is_number() {
                    f["age_s"] = json!(0);
                }
                if let Some(series) = f.get_mut("series").and_then(|s| s.as_array_mut()) {
                    for s in series.iter_mut() {
                        if s["age_s"].is_number() {
                            s["age_s"] = json!(0);
                        }
                    }
                }
            }
        }
        v
    }

    fn ap1_famille(kind: &str, nom: &str, phrase: &str) -> Value {
        json!({
            "kind": kind, "name": nom, "last_seen": Value::Null, "age_s": Value::Null, "n_24h": Value::Null,
            "status": "non_lu", "active_alerts": Value::Null, "non_lu": true, "famille_non_lue": true,
            "cause": format!("{CAUSE_FAMILLE_DE_FLUX_NON_LUE}{phrase}"),
        })
    }

    fn ap1_partage(actives: i64, aveu: Option<&str>) -> Value {
        let mut v = json!({
            "actives": actives, "avec_cloche": 0, "sans_source_nommee": 0, "sans_imputation": actives,
            "jeton_sans_source": crate::imputation::SOURCE_INDETERMINABLE,
        });
        if let Some(phrase) = aveu {
            v["error"] = json!(format!("{CAUSE_IMPUTATION_NON_ETABLIE}{phrase}"));
        }
        v
    }

    fn ap1_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort_unstable();
        c
    }

    /// (1) LA FRAÎCHEUR SERVIE PAR LA ROUTE, au rôle lecteur : chaque issue comparée à l'octet (horloge neutralisée).
    #[tokio::test]
    async fn ap1_fraicheur_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let rendus = ap1_jouer_fraicheur().await;
        let issues: Vec<&str> = rendus.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(issues, AP1_ORDRE_FRAICHEUR.to_vec(), "chaque issue est jouée une fois, dans l'ordre");
        let lu = |issue: &str| -> Value {
            let (_, s, c) = rendus.iter().find(|(i, _, _)| *i == issue).unwrap_or_else(|| panic!("issue {issue} jouée"));
            assert_eq!(*s, 200, "{issue} : statut : {c}");
            ap1_sans_horloge(serde_json::from_str(c).unwrap_or_else(|e| panic!("{issue} : corps JSON ({e}) : {c}")))
        };

        // LE CHEMIN NOMINAL : aucune clé d'aveu, le partage compté, le flux des métriques listé avec sa série.
        let nominal = lu("nominal");
        assert_eq!(ap1_cles(&nominal), ["feeds", "imputation_des_alertes", "pipeline_fresh", "ts"], "nominal : ensemble exact des clés : {nominal}");
        assert_eq!(nominal["imputation_des_alertes"], ap1_partage(2, None), "nominal : partage compté, sans aveu : {nominal}");
        assert_eq!(nominal["pipeline_fresh"], json!(true), "nominal : pipeline lu frais : {nominal}");
        let flux = nominal["feeds"].as_array().cloned().unwrap_or_default();
        assert_eq!(flux.len(), 1, "nominal : le seul flux des métriques : {nominal}");
        let metrique = flux[0].clone();
        assert_eq!((metrique["kind"].clone(), metrique["name"].clone(), metrique["n_24h"].clone()), (json!("metric"), json!("métriques · 1 séries"), json!(1)), "nominal : {metrique}");
        assert_eq!(metrique["series"].as_array().map(|s| s.iter().map(|x| x["name"].clone()).collect::<Vec<_>>()), Some(vec![json!(AP1_SERIE)]), "nominal : la série : {metrique}");
        for cle in ["cause", "non_lu", "famille_non_lue", "series_non_lues", "n_24h_non_lu", "nb_series_non_lu"] {
            assert!(metrique.get(cle).is_none(), "nominal : le flux ne porte pas « {cle} » : {metrique}");
        }
        assert_eq!(lu("nominal_apres").to_string(), nominal.to_string(), "les pannes levées, le corps nominal revient à l'octet");

        let r = FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE;
        let mut refus_coalesce = nominal.clone();
        refus_coalesce["feeds"] = json!([ap1_famille("event", "flux d'événements", r), metrique.clone()]);
        refus_coalesce["imputation_des_alertes"] = ap1_partage(0, Some(r));
        refus_coalesce["error"] = json!(format!("{CAUSE_FRAICHEUR_INCOMPLETE}le partage des alertes actives ({r}) ; les flux d'événements ({r})"));

        let mut metrique_sans_series = metrique.clone();
        metrique_sans_series["series"] = Value::Null;
        metrique_sans_series["series_non_lues"] = json!(format!("{CAUSE_FAMILLE_DE_FLUX_NON_LUE}{r}"));
        let mut refus_sum = nominal.clone();
        refus_sum["feeds"] = json!([ap1_famille("event", "flux d'événements", r), ap1_famille("snapshot", "flux d'instantanés", r), metrique_sans_series]);
        refus_sum["error"] = json!(format!("{CAUSE_FRAICHEUR_INCOMPLETE}les flux d'événements ({r}) ; les flux d'instantanés ({r}) ; les séries de métriques ({r})"));

        let i = FIN_DE_PARCOURS_INTERROMPUE;
        let mut coupe = nominal.clone();
        coupe["imputation_des_alertes"] = ap1_partage(0, Some(i));
        coupe["error"] = json!(format!("{CAUSE_FRAICHEUR_INCOMPLETE}le partage des alertes actives ({i})"));

        let lus: Vec<(&str, String)> = ["refus_coalesce", "refus_sum", "coupe_partage"].iter().map(|issue| (*issue, lu(issue).to_string())).collect();
        let attendus: Vec<(&str, String)> = vec![
            ("refus_coalesce", refus_coalesce.to_string()),
            ("refus_sum", refus_sum.to_string()),
            ("coupe_partage", coupe.to_string()),
        ];
        assert_eq!(lus, attendus, "chaque corps à l'octet : la constante, puis la phrase fixe de la classe, jamais le moteur");

        // LA CLASSE DE LA FIN AUX TROIS SITES : une préparation INTERROMPUE sert la phrase de l'interruption dans
        // `feeds[].cause` des deux familles et dans `series_non_lues`, jamais celle du refus. Les lectures d'une seule
        // ligne interrompues avec elles (flux des métriques, comptes) portent encore `{e}` : reste nommé en tête
        // (instrument 97), d'où des champs relus un à un et non le corps entier.
        // La part `releve` de `error`, avant la part des lectures d'une seule ligne (jointe par « — »).
        let separateur = format!(" — {}", crate::handlers::freshness::CAUSE_LIGNES_DE_FRAICHEUR_NON_LUES);
        let releve_de = |v: &Value| -> String {
            let e = v["error"].as_str().unwrap_or_default();
            assert!(e.contains(&separateur), "instrument : la part des lectures d'une seule ligne est jointe : {e}");
            e.split(separateur.as_str()).next().unwrap_or_default().to_string()
        };
        let familles = lu("familles_interrompues");
        let lues: Vec<Value> = familles["feeds"].as_array().cloned().unwrap_or_default().into_iter().filter(|f| f.get("famille_non_lue").is_some()).collect();
        let series = lu("series_interrompues");
        let flux_metrique = series["feeds"].as_array().and_then(|f| f.iter().find(|x| x["kind"] == json!("metric")).cloned()).unwrap_or(Value::Null);
        assert_eq!(
            (lues, releve_de(&familles), flux_metrique["series"].clone(), flux_metrique["series_non_lues"].clone(), releve_de(&series)),
            (
                vec![ap1_famille("event", "flux d'événements", i), ap1_famille("snapshot", "flux d'instantanés", i)],
                format!("{CAUSE_FRAICHEUR_INCOMPLETE}les flux d'événements ({i}) ; les flux d'instantanés ({i})"),
                Value::Null,
                json!(format!("{CAUSE_FAMILLE_DE_FLUX_NON_LUE}{i}")),
                format!("{CAUSE_FRAICHEUR_INCOMPLETE}les séries de métriques ({i})"),
            ),
            "préparations interrompues : la phrase de l'interruption aux deux familles et aux séries :\n{familles}\n{series}"
        );
        assert!(rendus.len() >= AP1_ORDRE_FRAICHEUR.len(), "plancher : toutes les issues sont relues");
        for (issue, _, brut) in &rendus {
            for trace in ["not authorized", "COALESCE", "SUM(", "SELECT", "interrupted", "offset"] {
                // `interrupted` des lectures d'une seule ligne : reste nommé (instrument 97), hors de cette clé.
                if trace == "interrupted" && (*issue == "familles_interrompues" || *issue == "series_interrompues") {
                    continue;
                }
                assert!(!brut.contains(trace), "{issue} : le corps porte « {trace} » : {brut}");
            }
        }
    }

    fn ap1_reparse_attendu(lues: i64, phrase: Option<&str>) -> String {
        let mut v = json!({ "scanned": lues, "matched": 0, "updated": 0, "truncated": false, "dry_run": true, "cap": 50000 });
        if let Some(p) = phrase {
            v["interrompu"] = json!(true);
            v["cause_scan"] = json!(format!("{CAUSE_REPARSE_INCOMPLET}{p}"));
        }
        v.to_string()
    }

    /// (2) LE REPARSE PAR LA ROUTE, jeton administrateur, `dry_run` : nominal, coupe en vol, ligne illisible.
    #[tokio::test]
    async fn ap1_reparse_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let rendus = ap1_jouer_reparse().await;
        assert!(rendus.len() >= 3, "plancher : nominal, au moins un essai de coupe, ligne illisible : {rendus:?}");
        let rendu = |issue: &str| -> (u16, String) {
            rendus.iter().find(|(i, _, _)| i == issue).map(|(_, s, c)| (*s, c.clone())).unwrap_or_else(|| panic!("issue {issue} jouée"))
        };
        assert_eq!(rendu("nominal"), (200, ap1_reparse_attendu(AP1_EVENTS, None)), "nominal : tout lu, aucun aveu");
        let (issue, s, c) = rendus.iter().rev().find(|(i, _, _)| i.starts_with("coupe:")).cloned().expect("au moins un essai de coupe");
        let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
        let lues = v["scanned"].as_i64().unwrap_or(-1);
        assert!(lues > 0 && lues < AP1_EVENTS, "instrument : aucun tir n'a coupé le scan en vol (dernier essai {issue}) : {c}");
        assert_eq!((s, c), (200, ap1_reparse_attendu(lues, Some(FIN_DE_PARCOURS_INTERROMPUE))), "coupe : le préfixe avoué, la phrase fixe de l'interruption");
        assert_eq!(rendu("illisible"), (200, ap1_reparse_attendu(AP1_EVENTS, Some(FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE))), "ligne illisible : la phrase fixe du refus");
        for (issue, _, brut) in &rendus {
            for trace in ["interrupted", "Invalid column", "message", AP1_SOURCE_REPARSE] {
                assert!(!brut.contains(trace), "{issue} : le corps porte « {trace} » : {brut}");
            }
        }
    }

    /// Le texte que le moteur rend pour `sql` quand l'autorisateur refuse la fonction `nom` (préparé sur une base au
    /// même schéma) : le journal le cite tel quel.
    fn ap1_moteur_du_refus(c: &Connection, sql: &str, nom: &'static str) -> String {
        let _armement = ap1_poser(c, Ap1Panne::Fonction(nom));
        let texte = match c.prepare(sql) {
            Ok(_) => panic!("instrument : l'énoncé n'a pas été refusé : {sql}"),
            Err(e) => e.to_string(),
        };
        assert!(texte.contains(sql), "instrument : le refus cite l'énoncé : {texte}");
        texte
    }

    /// (3) LE JOURNAL : une ligne `[freshness] WARN` / `[reparse] WARN` par fin ratée, EN ENTIER, dans l'ordre.
    #[tokio::test]
    async fn ap1_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AP1_ENFANT).is_ok() {
            let fraicheur = ap1_jouer_fraicheur().await;
            let reparse = ap1_jouer_reparse().await;
            for (issue, statut, corps) in fraicheur.iter().map(|(i, s, c)| (i.to_string(), *s, c.clone())).chain(reparse) {
                println!("{AP1_RENDU}{}", json!([issue, statut, corps]));
            }
            println!("{AP1_FIN}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::ap1_fraicheur_et_reparse_sans_texte_du_moteur::ap1_journal"])
            .env(AP1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(AP1_FIN), "contrôle : l'enfant a joué toutes ses issues : {stdout}\n{stderr}");
        let rendus: Vec<(String, u16, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AP1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert!(rendus.len() >= AP1_ORDRE_FRAICHEUR.len() + 3, "plancher : fraîcheur et reparse rendus : {stdout}");

        let (st, _base) = router_test_state("ap1-moteur");
        let (partage, evenements_coalesce, evenements_sum, instantanes, series) = {
            let c = st.db.lock();
            (
                ap1_moteur_du_refus(&c, SQL_PARTAGE_SANS_COLONNE, "COALESCE"),
                ap1_moteur_du_refus(&c, SQL_FLUX_D_EVENEMENTS, "COALESCE"),
                ap1_moteur_du_refus(&c, SQL_FLUX_D_EVENEMENTS, "SUM"),
                ap1_moteur_du_refus(&c, SQL_FLUX_D_INSTANTANES, "SUM"),
                ap1_moteur_du_refus(&c, SQL_SERIES, "SUM"),
            )
        };
        let t = AP1_TENANT_MODE_0;
        let attendu_fraicheur = vec![
            format!("[freshness] WARN parcours le partage des alertes actives non commencé (tenant '{t}') : {partage}"),
            format!("[freshness] WARN parcours les flux d'événements non commencé (tenant '{t}') : {evenements_coalesce}"),
            format!("[freshness] WARN parcours les flux d'événements non commencé (tenant '{t}') : {evenements_sum}"),
            format!("[freshness] WARN parcours les flux d'instantanés non commencé (tenant '{t}') : {instantanes}"),
            format!("[freshness] WARN parcours les séries de métriques non commencé (tenant '{t}') : {series}"),
            format!("[freshness] WARN parcours le partage des alertes actives interrompu (tenant '{t}') : interrupted"),
            format!("[freshness] WARN parcours les flux d'événements non commencé (tenant '{t}') : interrupted"),
            format!("[freshness] WARN parcours les flux d'instantanés non commencé (tenant '{t}') : interrupted"),
            format!("[freshness] WARN parcours les séries de métriques non commencé (tenant '{t}') : interrupted"),
        ];
        let journal_fraicheur: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[freshness] WARN")).collect();
        assert_eq!(journal_fraicheur, attendu_fraicheur, "une ligne EXACTE par parcours raté, le moteur au journal seul, aucune pour un nominal :\n{stderr}");

        // Chaque essai de coupe qui a avoué a écrit sa ligne, avec les lignes que SON corps dit lues ; la ligne
        // illisible au mappeur vient en dernier.
        let mut attendu_reparse: Vec<String> = Vec::new();
        for (issue, _, corps) in rendus.iter().filter(|(i, _, _)| i.starts_with("coupe:")) {
            let v: Value = serde_json::from_str(corps).unwrap_or_else(|e| panic!("{issue} : corps JSON ({e}) : {corps}"));
            if v.get("cause_scan").is_some() {
                let lues = v["scanned"].as_i64().unwrap_or(-1);
                attendu_reparse.push(format!("[reparse] WARN parcours des events interrompu (tenant '{t}') après {lues} ligne(s) lue(s) : interrupted"));
            }
        }
        assert!(!attendu_reparse.is_empty(), "contrôle : au moins une coupe avouée : {stdout}");
        attendu_reparse.push(format!(
            "[reparse] WARN parcours des events interrompu (tenant '{t}') après {AP1_EVENTS} ligne(s) lue(s) : Invalid column type Blob at index: 2, name: message"
        ));
        let journal_reparse: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[reparse] WARN")).collect();
        assert_eq!(journal_reparse, attendu_reparse, "une ligne EXACTE par scan raté, avec le tenant et les lignes lues, jamais la source :\n{stderr}");
    }

    const AP1_ENFANT_DEUX: &str = "AP1_ENFANT_DEUX_TENANTS";
    const AP1_ALPHA: &str = "ap1-alpha";
    const AP1_BETA: &str = "ap1-beta";
    /// La source DEMANDÉE au reparse : un texte de l'appelant, que la ligne `[reparse] WARN` n'écrit jamais.
    const AP1_SOURCE_DEMANDEE: &str = "ap1-source-demandee";
    /// Lignes lisibles de la source demandée semées chez alpha et chez beta (comptes distincts : chaque tenant est
    /// servi par SA base), plus deux lignes d'une autre source chez alpha, que le filtre `source` écarte.
    const AP1_LIGNES_ALPHA: i64 = 3;
    const AP1_LIGNES_BETA: i64 = 5;
    const AP1_MOTEUR_ILLISIBLE: &str = "Invalid column type Blob at index: 2, name: message";

    fn ap1_au(tenant: &str, role: &str) -> AuthUser {
        AuthUser { name: format!("{role}-ap1"), role: role.into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    /// Crée le tenant `t` (vraie route de création), sème `alertes` alertes actives et `lignes` events lisibles de la
    /// source demandée dans SA base, et rend le chemin de cette base.
    async fn ap1_creer_le_tenant(st: &AppState, t: &str, alertes: i64, lignes: i64, autres: i64) -> String {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-ap1")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        {
            let c = h.lock();
            for i in 0..alertes {
                c.execute(
                    "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(?1,?2,2,'Alerte AP1','','new','T1046','')",
                    params![1000 + i, format!("rule.{t}.{i}")],
                )
                .expect("fixture : alerte");
            }
            for (source, n) in [(AP1_SOURCE_DEMANDEE, lignes), ("ap1-autre-source", autres)] {
                for i in 0..n {
                    c.execute(
                        "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'auth',1,?3)",
                        params![now() - 100, source, format!("m{i}")],
                    )
                    .expect("fixture : event");
                }
            }
        }
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    fn ap1_actives(st: &AppState, t: &str) -> i64 {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let c = h.lock();
        c.query_row("SELECT COUNT(*) FROM alert WHERE status='new'", [], |r| r.get(0)).expect("contrôle : alertes actives comptées")
    }

    /// `/api/freshness` du tenant `t` par son gestionnaire, au rôle lecteur. `perime` : une valeur PÉRIMÉE est posée
    /// au cache de SA base (chemin du rafraîchissement en fond) ; sinon l'entrée est retirée (calcul à froid). Relit
    /// jusqu'à ce que le calcul soit servi.
    async fn ap1_fraicheur_du_tenant(st: &AppState, t: &str, perime: bool) -> Value {
        let au = ap1_au(t, "viewer");
        let cle = crate::handlers::dashboards::env_range_key(None, req_db_path(st, &au).as_str());
        if perime {
            let vieux = std::time::Instant::now()
                .checked_sub(crate::handlers::freshness::FRESHNESS_TTL * 4)
                .expect("instrument : horloge monotone assez avancée pour une valeur périmée");
            freshness_map().lock().insert(cle.clone(), (vieux, json!({ "ap1_perime": true, "feeds": [] })));
        } else {
            freshness_map().lock().remove(&cle);
        }
        for _ in 0..AP1_ATTENTES {
            let v = crate::handlers::freshness::freshness(State(st.clone()), Extension(au.clone())).await.0;
            if v.get("warming").is_none() && v.get("ap1_perime").is_none() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("instrument : la fraîcheur de {t} n'a pas été calculée en {AP1_ATTENTES} lectures — le témoin ne conclut pas");
    }

    async fn ap1_fraicheur_refusee_du_tenant(st: &AppState, t: &str, chemin: &str, perime: bool) -> Value {
        for _ in 0..AP1_ESSAIS {
            let armement = ap1_armer_le_pool(chemin, Ap1Panne::Fonction("COALESCE"));
            let rendu = ap1_fraicheur_du_tenant(st, t, perime).await;
            armement.lever();
            if armement.joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi la fraîcheur de {t} en aucun des {AP1_ESSAIS} essais");
    }

    /// Le reparse du tenant `t` par son gestionnaire, rôle administrateur du tenant, `dry_run`, AVEC un champ `source`.
    async fn ap1_reparse_du_tenant(st: &AppState, t: &str) -> (u16, String) {
        let corps = json!({ "dry_run": true, "days": 1, "source": AP1_SOURCE_DEMANDEE });
        let r = crate::handlers::detection::parser_reparse(State(st.clone()), Extension(ap1_au(t, "admin")), Json(corps)).await;
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    /// Pose (ou retire) chez `t` une ligne de la source demandée dont le message n'est pas un texte.
    fn ap1_ligne_illisible(st: &AppState, t: &str, poser: bool) {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let c = h.lock();
        if poser {
            c.execute(
                "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,?2,'auth',1,x'00ff')",
                params![now() - 100, AP1_SOURCE_DEMANDEE],
            )
            .expect("fixture : ligne illisible");
        } else {
            c.execute("DELETE FROM event WHERE typeof(message)='blob'", []).expect("fixture : ligne illisible retirée");
        }
    }

    /// Les rendus du mode 1, dans l'ordre : la fraîcheur (alpha refusée à froid, beta nominale à froid, beta refusée au
    /// rafraîchissement d'une valeur périmée, alpha nominale au même chemin), puis le reparse (alpha illisible, beta
    /// nominal, beta illisible, alpha nominal), puis les comptes d'alertes actives lus sur chaque base.
    async fn ap1_jouer_deux_tenants() -> Vec<(String, u16, String)> {
        let (st, _dir) = mk_mode1_state();
        let alpha = ap1_creer_le_tenant(&st, AP1_ALPHA, 1, AP1_LIGNES_ALPHA, 2).await;
        let beta = ap1_creer_le_tenant(&st, AP1_BETA, 2, AP1_LIGNES_BETA, 0).await;
        assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
        let mut rendus: Vec<(String, u16, String)> = Vec::new();
        let f = |issue: &str, v: Value| (issue.to_string(), 200u16, v.to_string());
        rendus.push(f("fraicheur:alpha_refusee:alpha", ap1_fraicheur_refusee_du_tenant(&st, AP1_ALPHA, &alpha, false).await));
        rendus.push(f("fraicheur:alpha_refusee:beta", ap1_fraicheur_du_tenant(&st, AP1_BETA, false).await));
        rendus.push(f("fraicheur:beta_refusee:beta", ap1_fraicheur_refusee_du_tenant(&st, AP1_BETA, &beta, true).await));
        rendus.push(f("fraicheur:beta_refusee:alpha", ap1_fraicheur_du_tenant(&st, AP1_ALPHA, true).await));
        ap1_ligne_illisible(&st, AP1_ALPHA, true);
        let (s, c) = ap1_reparse_du_tenant(&st, AP1_ALPHA).await;
        rendus.push(("reparse:alpha_illisible:alpha".to_string(), s, c));
        let (s, c) = ap1_reparse_du_tenant(&st, AP1_BETA).await;
        rendus.push(("reparse:alpha_illisible:beta".to_string(), s, c));
        ap1_ligne_illisible(&st, AP1_ALPHA, false);
        ap1_ligne_illisible(&st, AP1_BETA, true);
        let (s, c) = ap1_reparse_du_tenant(&st, AP1_BETA).await;
        rendus.push(("reparse:beta_illisible:beta".to_string(), s, c));
        let (s, c) = ap1_reparse_du_tenant(&st, AP1_ALPHA).await;
        rendus.push(("reparse:beta_illisible:alpha".to_string(), s, c));
        for t in [AP1_ALPHA, AP1_BETA] {
            rendus.push((format!("actives:{t}"), 200, ap1_actives(&st, t).to_string()));
        }
        rendus
    }

    /// (4) DEUX TENANTS RÉELS (mode 1) : la ligne `[freshness] WARN` et la ligne `[reparse] WARN` nomment le tenant de
    /// l'appelant (jamais `default`, jamais la source demandée) ; l'autre tenant est servi par SA base, sans ligne.
    #[tokio::test]
    async fn ap1_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AP1_ENFANT_DEUX).is_ok() {
            for (issue, statut, corps) in ap1_jouer_deux_tenants().await {
                println!("{AP1_RENDU}{}", json!([issue, statut, corps]));
            }
            println!("{AP1_FIN}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::ap1_fraicheur_et_reparse_sans_texte_du_moteur::ap1_deux_tenants"])
            .env(AP1_ENFANT_DEUX, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(AP1_FIN), "contrôle : l'enfant a joué toutes ses issues : {stdout}\n{stderr}");
        let rendus: Vec<(String, u16, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AP1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        let rendu = |issue: &str| -> (u16, String) {
            rendus.iter().find(|(i, _, _)| i == issue).map(|(_, s, c)| (*s, c.clone())).unwrap_or_else(|| panic!("contrôle : {issue} rendu par l'enfant : {stdout}"))
        };
        let actives = |t: &str| -> i64 { rendu(&format!("actives:{t}")).1.parse().unwrap_or(-1) };
        let (actives_alpha, actives_beta) = (actives(AP1_ALPHA), actives(AP1_BETA));
        assert!(actives_alpha >= 1 && actives_beta >= 1 && actives_alpha != actives_beta, "contrôle : deux bases aux comptes distincts ({actives_alpha}, {actives_beta})");

        // LA FRAÎCHEUR : le tenant refusé sert la phrase fixe, l'autre est compté sur SA base et n'avoue rien.
        let r = FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE;
        let erreur_refusee = format!("{CAUSE_FRAICHEUR_INCOMPLETE}le partage des alertes actives ({r}) ; les flux d'événements ({r})");
        let lu = |issue: &str| -> Value {
            let (s, c) = rendu(issue);
            assert_eq!(s, 200, "{issue} : statut");
            serde_json::from_str(&c).unwrap_or_else(|e| panic!("{issue} : corps JSON ({e}) : {c}"))
        };
        let servis: Vec<(String, Value, Value)> = [
            "fraicheur:alpha_refusee:alpha", "fraicheur:alpha_refusee:beta", "fraicheur:beta_refusee:beta", "fraicheur:beta_refusee:alpha",
        ]
        .iter()
        .map(|issue| {
            let v = lu(issue);
            (issue.to_string(), v.get("error").cloned().unwrap_or(Value::Null), v["imputation_des_alertes"]["actives"].clone())
        })
        .collect();
        let attendus: Vec<(String, Value, Value)> = vec![
            ("fraicheur:alpha_refusee:alpha".to_string(), json!(erreur_refusee), json!(0)),
            ("fraicheur:alpha_refusee:beta".to_string(), Value::Null, json!(actives_beta)),
            ("fraicheur:beta_refusee:beta".to_string(), json!(erreur_refusee), json!(0)),
            ("fraicheur:beta_refusee:alpha".to_string(), Value::Null, json!(actives_alpha)),
        ];
        assert_eq!(servis, attendus, "chaque tenant servi par SA base, la phrase fixe chez le seul tenant refusé");

        // LE REPARSE : la ligne illisible chez l'un, l'autre servi par SA base ; la source filtre (alpha a deux lignes
        // d'une autre source, jamais lues).
        let lus: Vec<(String, (u16, String))> = [
            "reparse:alpha_illisible:alpha", "reparse:alpha_illisible:beta", "reparse:beta_illisible:beta", "reparse:beta_illisible:alpha",
        ]
        .iter()
        .map(|issue| (issue.to_string(), rendu(issue)))
        .collect();
        let attendus: Vec<(String, (u16, String))> = vec![
            ("reparse:alpha_illisible:alpha".to_string(), (200, ap1_reparse_attendu(AP1_LIGNES_ALPHA, Some(r)))),
            ("reparse:alpha_illisible:beta".to_string(), (200, ap1_reparse_attendu(AP1_LIGNES_BETA, None))),
            ("reparse:beta_illisible:beta".to_string(), (200, ap1_reparse_attendu(AP1_LIGNES_BETA, Some(r)))),
            ("reparse:beta_illisible:alpha".to_string(), (200, ap1_reparse_attendu(AP1_LIGNES_ALPHA, None))),
        ];
        assert_eq!(lus, attendus, "chaque reparse lit SA base et la seule source demandée ; la phrase fixe chez le seul tenant illisible");

        // LE JOURNAL : une ligne par fin ratée, EN ENTIER, qui nomme le tenant de l'appelant.
        let (st, _base) = router_test_state("ap1-moteur-deux");
        let (partage, evenements) = {
            let c = st.db.lock();
            (ap1_moteur_du_refus(&c, SQL_PARTAGE_SANS_COLONNE, "COALESCE"), ap1_moteur_du_refus(&c, SQL_FLUX_D_EVENEMENTS, "COALESCE"))
        };
        let journal_fraicheur: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[freshness] WARN")).collect();
        assert_eq!(
            journal_fraicheur,
            vec![
                format!("[freshness] WARN parcours le partage des alertes actives non commencé (tenant '{AP1_ALPHA}') : {partage}"),
                format!("[freshness] WARN parcours les flux d'événements non commencé (tenant '{AP1_ALPHA}') : {evenements}"),
                format!("[freshness] WARN parcours le partage des alertes actives non commencé (tenant '{AP1_BETA}') : {partage}"),
                format!("[freshness] WARN parcours les flux d'événements non commencé (tenant '{AP1_BETA}') : {evenements}"),
            ],
            "une ligne EXACTE par parcours refusé, qui nomme le tenant refusé, à froid comme au rafraîchissement :\n{stderr}"
        );
        let journal_reparse: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[reparse] WARN")).collect();
        assert_eq!(
            journal_reparse,
            vec![
                format!("[reparse] WARN parcours des events interrompu (tenant '{AP1_ALPHA}') après {AP1_LIGNES_ALPHA} ligne(s) lue(s) : {AP1_MOTEUR_ILLISIBLE}"),
                format!("[reparse] WARN parcours des events interrompu (tenant '{AP1_BETA}') après {AP1_LIGNES_BETA} ligne(s) lue(s) : {AP1_MOTEUR_ILLISIBLE}"),
            ],
            "une ligne EXACTE par scan raté, qui nomme le tenant de l'appelant et jamais la source demandée :\n{stderr}"
        );
        for ligne in journal_fraicheur.iter().chain(journal_reparse.iter()) {
            assert!(!ligne.contains(AP1_SOURCE_DEMANDEE) && !ligne.contains("'default'"), "ni la source demandée ni le tenant par défaut : {ligne}");
        }
    }
}
