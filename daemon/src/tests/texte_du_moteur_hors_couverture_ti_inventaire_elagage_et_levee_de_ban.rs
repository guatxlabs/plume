// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi au client », suite) — COUVERTURE THREAT-INTEL, INVENTAIRE DES SOURCES,
// ÉLAGAGE SUR ADOSSEMENT ILLISIBLE, LEVÉE DE BAN : LA CAUSE SERVIE EST FIXE OU TIRÉE D'UNE LISTE FERMÉE ; LE TEXTE DU
// MOTEUR, LE SQL ET LE CHEMIN DU FICHIER VONT AU JOURNAL SEUL.
//
// LE DÉFAUT, MESURÉ SUR 8639270b :
// - `ti_coverage_json` (threat_intel.rs, route ouverte à tous les rôles) servait dans un deux cents `total_detail` /
//   `active_detail` = `format!("{sql} : {e}")` (le SQL ET le texte du moteur), `by_type_error` et `by_source_error`
//   = `… NON LUE : {e}` ; et la route `/api/threat-intel/coverage` y ajoutait `cache_actifs_detail` = le détail du
//   dernier rechargement raté du cache IOC (`ioc_cache_reload`), qui portait le CHEMIN de la base et le texte du moteur
//   (le même détail part au voyant de santé et à `/api/metrics`) ;
// - `corps_inventaire_non_lu` (sources.rs, route ouverte à tous les rôles) servait `inventaire NON LU : {cause}` avec
//   `cause` = `pipeline : {e}`, `sources observées : {e}`, `déclarations : {e}` ;
// - `config_overlays_prune` (overlays.rs) servait en 500 le `Display` de `RefusDePrune::Adossement`, qui porte le
//   CHEMIN du fichier et le texte d'E/S ou d'analyse ;
// - `netban_delete` (actions.rs) servait en 503 le texte du store de ban : `levée de ban IMPOSSIBLE (store
//   indisponible) : {e}` et `… ÉCHEC sur la forme canonique : {e}`.
//
// DÉCISION PAR DÉFAUT (vague AJ) : statuts et clés inchangés (200 pour la couverture et l'inventaire, 500 pour
// l'élagage, 503 pour la levée) ; seul le TEXTE change. Couverture et inventaire : phrase fixe par lecture (la lecture
// nommée reste dite), pas d'identifiant (deux cents). Élagage : la phrase du refus d'adossement et sa cause de la
// liste fermée `S32` restent, le chemin et le texte d'analyse vont au journal avec l'identifiant servi. Levée : les
// ouvertures, « RÉESSAYER » et la mention de trace manquante restent ; le texte du store va au journal avec
// l'identifiant servi, jamais l'adresse.
//
// LES TÉMOINS.
// (1) La couverture threat-intel sur une table `ioc` hors d'atteinte : le corps ENTIER égal à l'attendu (toutes les
//     clés), contrôle positif avant la coupe.
// (2) L'inventaire, sur ses trois lectures coupées chacune à son tour (snapshot, event_rollup, source_settings) :
//     clés exactes, phrase égale à la cause attendue, aucun texte du moteur ; contrôle positif avant chaque coupe.
// (3) L'élagage sur un `rules/*.json` invalide : 500, clés exactes `error`/`id`, phrase égale à l'attendue, ni le
//     chemin ni le texte d'analyse ; rien n'est élagué.
// (4) La levée refusée puis la levée PARTIELLE : 503, clés exactes, phrase égale à l'attendue, le ban reste actif.
// (5) Le journal : le binaire de test se rejoue en sous-processus, l'enfant joue les refus, le parent compare les
//     lignes ENTIÈRES (identifiant servi en tête pour l'élagage et les deux levées, chemin de la base pour le cache
//     IOC), et vérifie qu'aucune ligne `HTTP 5xx` ne porte le chemin ni le texte du store.
// (6) La couverture PAR LA ROUTE (`ti_coverage`, identité viewer) après un rechargement raté du cache IOC : le corps
//     ENTIER égal à l'attendu, `cache_actifs_detail` égal à une phrase écrite en toutes lettres dans le témoin, ni le
//     chemin de la base ni le texte du moteur ; contrôle positif avant la coupe.
//
// LA GARDE `check_a_bare_chain_match_is_never_served_as_a_fact.py` : le bras `Err` des deux comptes rend
// `compte_du_magasin_non_lu`, constructeur `/// AVEU` (vocabulaire typé que la garde reconnaît) — sans ce mot de
// documentation, la garde accuse `ti_coverage_json` en FORME NEUVE `Err => valeur` (mesuré, puis remis).
//
// TESTS ANTÉRIEURS INVERSÉS : `levee_de_ban_par_api_trace_avouee.rs` (`phrase_d_avant` des deux refus, qui portait
// `: levee refusee par le temoin`). `couverture_ti_non_lue_avoue.rs`, `un_seul_fabricant_de_liste_bornee.rs` et
// `inventaire_de_sources_non_lu_avoue.rs` n'affirment que l'ouverture (« NON LUE », « inventaire NON LU : pipeline »),
// gardée : ils restent tels quels.
//
// MUTANTS JOUÉS (variable de mutation sous `cfg!(test)`, retirés du source avant le commit) : `AJ3_TI_COMPTE`, `AJ3_TI_TYPE`, `AJ3_TI_SOURCE`
// (le texte du moteur rendu au corps) font rougir (1) ; `AJ3_INV` (idem), `AJ3_INV_PIPE`, `AJ3_INV_OBS`,
// `AJ3_INV_DECL` (un site sert la cause d'une autre lecture) font rougir (2) ; `AJ3_ELAG` rougit (3) ; `AJ3_LEVEE`,
// `AJ3_CANON` rougissent (4) ; `AJ3_TI_COMPTE_J`, `AJ3_TI_TYPE_J`, `AJ3_TI_SOURCE_J`, `AJ3_INV_J`, `AJ3_ELAG_J`,
// `AJ3_LEVEE_J`, `AJ3_CANON_J` (la ligne de journal tue) rougissent (5) ; `AJ3_CACHE` (chemin et texte du moteur
// rendus à `cache_actifs_detail`) rougit (6), `AJ3_CACHE_J` (la ligne `[ti] WARN` tue) rougit (5).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les quatre 503 `CAUSE_* ({e})` d'`actions.rs` (résultat d'agent, riposte non
// lue, approbation et annulation non enregistrées), laissés tels quels — leur forme `<cause> (<détail>)` est relue
// mot pour mot par les instruments 101 et 103 du harnais console et par `check_enforcer_lists_fail_closed.py` ; le
// détail des maillons `netban.remove.echec` (texte du store et nom de l'acteur, au registre) ; la cause d'un maillon
// manquant servie dans la mention de trace ; `derniere_collecte_non_etablie` de l'inventaire (texte du moteur par
// source, `sondes.rs`) ; le voyant de santé et `/api/metrics`, qui reprennent le même détail du cache IOC, ne sont pas
// rejoués ici ; la console n'est pas exercée.
// =====================================================================================
mod texte_du_moteur_hors_couverture_ti_inventaire_elagage_et_levee_de_ban {
    use super::*;

    /// Variable qui fait de ce binaire l'enfant du témoin (5).
    const AJ3_ENFANT: &str = "AJ3_ENFANT_JOURNAL";
    /// Ce que l'enfant écrit sur stdout pour prouver qu'il a joué.
    const AJ3_MARQUE_ENFANT: &str = "AJ3-ENFANT-A-JOUE";
    /// Ligne où l'enfant donne l'identifiant servi, un par refus 5xx, dans l'ordre (`absent` sinon).
    const AJ3_ID_ENFANT: &str = "AJ3-ID-SERVI";
    /// Ligne où l'enfant donne le chemin de la base du témoin du cache IOC.
    const AJ3_CHEMIN_ENFANT: &str = "AJ3-CHEMIN-CACHE";
    /// Les refus 5xx joués par l'enfant (élagage, levée, levée partielle).
    const AJ3_REFUS_5XX: usize = 3;
    /// Le `detail` servi pour le compte `total` illisible.
    const AJ3_DETAIL_TOTAL: &str = "total NON LU : la base n'a pas rendu ce compte du magasin d'indicateurs — ce n'est \
         PAS un zéro, c'est une lecture qui n'a pas eu lieu";
    /// Le `detail` servi pour le compte `active` illisible.
    const AJ3_DETAIL_ACTIVE: &str = "active NON LU : la base n'a pas rendu ce compte du magasin d'indicateurs — ce \
         n'est PAS un zéro, c'est une lecture qui n'a pas eu lieu";
    /// Le refus de levée servi quand le store refuse la saisie (le registre a pris l'échec : aucune mention).
    const AJ3_LEVEE_IMPOSSIBLE: &str = "levée de ban IMPOSSIBLE (store indisponible) — RÉESSAYER ; le ban est TOUJOURS actif";
    /// Le refus de levée servi quand la forme canonique est refusée après une première passe.
    const AJ3_LEVEE_PARTIELLE: &str = "levée de ban PARTIELLE (1 retiré(s)) puis ÉCHEC sur la forme canonique — RÉESSAYER";
    /// Le texte que le store de la fixture rend : il ne doit jamais atteindre le corps.
    const AJ3_TEXTE_DU_STORE: &str = "levee refusee par le temoin";

    fn aj3_inventaire_attendu(cause: &str) -> String {
        format!("inventaire NON LU : {cause} — aucune source n'est établie, et l'ingestion n'est pas dite en panne")
    }

    fn aj3_elagage_attendu() -> String {
        format!(
            "échec transaction prune (aucune modification): adossement illisible ({}) — élagage REFUSÉ, rien n'a été \
             supprimé (un fichier qu'on ne sait pas lire n'est pas un fichier retiré) ; le fichier en cause est nommé au \
             journal du démon, sous l'identifiant de ce refus",
            crate::mesure_environnement::CAUSE_FORME_INCONNUE
        )
    }

    async fn aj3_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn aj3_cles(v: &Value) -> Option<std::collections::BTreeSet<String>> {
        v.as_object().map(|o| o.keys().cloned().collect())
    }

    fn aj3_ensemble(cles: &[&str]) -> Option<std::collections::BTreeSet<String>> {
        Some(cles.iter().map(|c| c.to_string()).collect())
    }

    // ---------------------------------------------------------------- (1) couverture threat-intel

    /// La couverture sur une table `ioc` renommée : le corps rendu par la fonction pure de la route.
    fn aj3_couverture_coupee() -> Value {
        let conn = test_db();
        let avant = crate::handlers::threat_intel::ti_coverage_json(&conn, now());
        assert!(avant["total"].is_i64(), "contrôle positif : le total se lit avant la coupe : {avant}");
        assert!(avant.get("by_type_error").is_none() && avant.get("total_detail").is_none(), "contrôle positif : rien à avouer : {avant}");
        conn.execute_batch("ALTER TABLE ioc RENAME TO ioc_hors_d_atteinte;").expect("fixture : la table se renomme");
        crate::handlers::threat_intel::ti_coverage_json(&conn, now())
    }

    /// (1) LE CORPS ENTIER DE LA COUVERTURE NON LUE. MUTANTS : `AJ3_TI_COMPTE`, `AJ3_TI_TYPE`, `AJ3_TI_SOURCE`.
    #[test]
    fn aj3_couverture_ti_non_lue_sert_des_phrases_fixes_sans_sql_ni_texte_du_moteur() {
        let v = aj3_couverture_coupee();
        let attendu = json!({
            "by_type": null,
            "by_source": null,
            "by_source_window": null,
            "by_source_capped": null,
            "hits_query": "search ti_match=1 | timechart count",
            "by_type_error": crate::handlers::threat_intel::TI_VENTILATION_PAR_TYPE_NON_LUE,
            "by_source_error": crate::handlers::threat_intel::TI_VENTILATION_PAR_SOURCE_NON_LUE,
            "lecture_non_faite": true,
            "total_verdict": "illisible",
            "total_cause": "source_illisible",
            "total_detail": AJ3_DETAIL_TOTAL,
            "active_verdict": "illisible",
            "active_cause": "source_illisible",
            "active_detail": AJ3_DETAIL_ACTIVE,
        });
        assert_eq!(v, attendu, "le corps de la couverture non lue, clé pour clé");
        assert!(crate::handlers::threat_intel::TI_VENTILATION_PAR_TYPE_NON_LUE.starts_with("ventilation par type NON LUE : la base"));
        assert!(crate::handlers::threat_intel::TI_VENTILATION_PAR_SOURCE_NON_LUE.starts_with("ventilation par source NON LUE : la base"));
        let texte = v.to_string();
        assert!(!texte.contains("no such table") && !texte.contains("SELECT"), "ni texte du moteur ni SQL : {v}");
    }

    /// Le `cache_actifs_detail` attendu pour un indicateur conservé, écrit en toutes lettres.
    const AJ3_DETAIL_CACHE_UN: &str = "rechargement du cache IOC : la table `ioc` n'a pas pu être lue entièrement — 1 \
         indicateur(s) de la dernière lecture réussie CONSERVÉ(S), la correspondance continue sur ce jeu et la mise à jour \
         est perdue ; installer un ensemble vide aurait ÉTEINT la correspondance sans qu'aucun corps servi ne le dise ; la \
         cause est au journal du démon";

    /// La couverture PAR LA ROUTE, identité viewer, après un rechargement raté du cache IOC (un indicateur conservé) :
    /// (corps, chemin de la base).
    async fn aj3_couverture_route_cache_coupe(tag: &str) -> (Value, String) {
        let (st, _p) = sp_state(tag);
        let dbp = st.db_path.as_ref().clone();
        {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,env_id) \
                 VALUES('ip','203.0.113.91','feed-aj3',80,3,?1,?1,NULL,'prod')",
                params![now()],
            )
            .expect("fixture : l'indicateur s'insère");
            crate::handlers::threat_intel::ioc_cache_reload(&conn, &dbp);
        }
        let avant = crate::handlers::threat_intel::ti_coverage(State(st.clone()), Extension(sp_au("lecteur", "viewer"))).await.0;
        assert_eq!(avant["cache_actifs"], json!(1), "contrôle positif : le cache se lit avant la coupe : {avant}");
        assert!(avant.get("cache_actifs_detail").is_none(), "contrôle positif : rien à avouer : {avant}");
        {
            let conn = st.db.lock();
            conn.execute_batch("ALTER TABLE ioc RENAME TO ioc_hors_d_atteinte;").expect("fixture : la table se renomme");
            crate::handlers::threat_intel::ioc_cache_reload(&conn, &dbp);
        }
        let v = crate::handlers::threat_intel::ti_coverage(State(st.clone()), Extension(sp_au("lecteur", "viewer"))).await.0;
        (v, dbp)
    }

    /// (6) LA ROUTE NE SERT NI LE CHEMIN NI LE TEXTE DU MOTEUR DANS `cache_actifs_detail`. MUTANT : `AJ3_CACHE`.
    #[tokio::test]
    async fn aj3_couverture_par_la_route_sert_le_cache_non_relu_sans_chemin_ni_texte_du_moteur() {
        let (v, dbp) = aj3_couverture_route_cache_coupe("aj3-cache-route").await;
        assert_eq!(
            crate::handlers::threat_intel::detail_du_cache_ioc_non_relu(1),
            AJ3_DETAIL_CACHE_UN,
            "la phrase servie, en toutes lettres"
        );
        let attendu = json!({
            "by_type": null,
            "by_source": null,
            "by_source_window": null,
            "by_source_capped": null,
            "hits_query": "search ti_match=1 | timechart count",
            "by_type_error": crate::handlers::threat_intel::TI_VENTILATION_PAR_TYPE_NON_LUE,
            "by_source_error": crate::handlers::threat_intel::TI_VENTILATION_PAR_SOURCE_NON_LUE,
            "lecture_non_faite": true,
            "total_verdict": "illisible",
            "total_cause": "source_illisible",
            "total_detail": AJ3_DETAIL_TOTAL,
            "active_verdict": "illisible",
            "active_cause": "source_illisible",
            "active_detail": AJ3_DETAIL_ACTIVE,
            "cache_actifs_verdict": "illisible",
            "cache_actifs_cause": crate::mesure_environnement::CAUSE_FORME_INCONNUE,
            "cache_actifs_detail": AJ3_DETAIL_CACHE_UN,
        });
        assert_eq!(v, attendu, "le corps de la route, clé pour clé");
        let texte = serde_json::to_string(&v).expect("corps sérialisable");
        assert_eq!(texte, serde_json::to_string(&attendu).expect("attendu sérialisable"), "le corps servi, à l'octet");
        assert!(!texte.contains(&dbp) && !texte.contains("no such table"), "ni chemin de la base ni texte du moteur : {texte}");
    }

    // ---------------------------------------------------------------- (2) inventaire des sources

    /// Les trois lectures de l'inventaire, chacune coupée par le renommage de sa table : (table, cause attendue).
    const AJ3_COUPES_DE_L_INVENTAIRE: [(&str, &str); 3] = [
        ("snapshot", "pipeline : la base n'a pas rendu la fraîcheur du pipeline"),
        ("event_rollup", "sources observées : la base n'a pas rendu les cumuls des sources"),
        ("source_settings", "déclarations : la base n'a pas rendu les marquages des sources"),
    ];

    async fn aj3_inventaire(st: &AppState) -> Value {
        use axum::response::IntoResponse;
        let au = sp_au("adm", "admin");
        aj3_corps(crate::handlers::sources::sources_inventory(State(st.clone()), Extension(au)).await.into_response()).await.1
    }

    /// Joue une coupe : contrôle positif puis l'inventaire, la table renommée.
    async fn aj3_inventaire_coupe(table: &str) -> Value {
        let (st, _p) = sp_state(&format!("aj3-inv-{table}"));
        let au = sp_au("adm", "admin");
        let avant = aj3_inventaire(&st).await;
        assert_eq!(avant["ok"], json!(true), "contrôle positif : l'inventaire se lit avant la coupe de `{table}` : {avant}");
        with_write(&st, &au, |conn| {
            conn.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;")).expect("fixture : la table se renomme")
        });
        aj3_inventaire(&st).await
    }

    /// (2) L'INVENTAIRE NON LU SUR CHACUNE DE SES TROIS LECTURES. MUTANTS : `AJ3_INV`, `AJ3_INV_PIPE`, `AJ3_INV_OBS`,
    /// `AJ3_INV_DECL`.
    #[tokio::test]
    async fn aj3_inventaire_non_lu_sert_la_cause_de_sa_lecture_sans_texte_du_moteur() {
        let mut manquent: Vec<String> = Vec::new();
        let mut servies = std::collections::BTreeSet::new();
        for (table, cause) in AJ3_COUPES_DE_L_INVENTAIRE {
            let v = aj3_inventaire_coupe(table).await;
            servies.insert(v["error"].to_string());
            for (propriete, tenue) in [
                ("clés exactes", aj3_cles(&v) == aj3_ensemble(&["ok", "generated", "pipeline_fresh", "sources", "error"])),
                ("`ok` faux", v["ok"] == json!(false)),
                ("`pipeline_fresh` nul", v["pipeline_fresh"] == Value::Null),
                ("`sources` vide", v["sources"] == json!([])),
                ("`generated` est un nombre", v["generated"].is_i64()),
                ("`error` égal à la cause attendue", v["error"] == json!(aj3_inventaire_attendu(cause))),
                ("aucun texte du moteur", !v.to_string().contains("no such table")),
            ] {
                if !tenue {
                    manquent.push(format!("coupe de `{table}` : {propriete} — corps {v}"));
                }
            }
        }
        assert!(manquent.is_empty(), "inventaires non lus mal servis :\n{}", manquent.join("\n"));
        assert_eq!(servies.len(), AJ3_COUPES_DE_L_INVENTAIRE.len(), "chaque lecture coupée sert SA cause, distincte des autres : {servies:?}");
    }

    // ---------------------------------------------------------------- (3) élagage sur adossement illisible

    /// Pose `rules/aj3.json` invalide dans `dossier` et rend son chemin.
    fn aj3_adossement_illisible(dossier: &std::path::Path) -> std::path::PathBuf {
        std::fs::create_dir_all(dossier.join("rules")).expect("fixture : dossier des règles");
        let fichier = dossier.join("rules").join("aj3.json");
        std::fs::write(&fichier, "{ pas du json").expect("fixture : fichier illisible");
        fichier
    }

    /// Une orpheline `managed=1` que l'élagage supprimerait, puis l'élagage : (statut, corps, orphelines restantes).
    async fn aj3_elaguer(tag: &str) -> (u16, Value, i64) {
        let (st, _p) = sp_state(tag);
        st.db
            .lock()
            .execute_batch(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                 VALUES('aj3-orpheline',1,'search source=auth | stats count',1,'>',0,2,300,3600,1)",
            )
            .expect("fixture : orpheline");
        let (statut, corps) = aj3_corps(config_overlays_prune(State(st.clone()), Extension(sp_au("adm", "admin"))).await).await;
        let restantes: i64 = st
            .db
            .lock()
            .query_row("SELECT COUNT(*) FROM rule WHERE name='aj3-orpheline' AND managed=1", [], |r| r.get(0))
            .expect("fixture : le compte se lit");
        (statut, corps, restantes)
    }

    /// (3) L'ADOSSEMENT ILLISIBLE NE SERT NI LE CHEMIN NI LE TEXTE D'ANALYSE. MUTANT : `AJ3_ELAG`.
    #[tokio::test]
    async fn aj3_elagage_sur_adossement_illisible_ne_sert_pas_le_chemin_du_fichier() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // `PLUME_CONFIG_DIR` est posée pour la portée
        let dossier = crate::tmp_possede::TmpPossede::neuf("aj3-config-d");
        let fichier = aj3_adossement_illisible(&dossier);
        let _pose = ReglageBackupPose::neuf("PLUME_CONFIG_DIR", dossier.to_str().expect("chemin UTF-8"));
        let (statut, corps, restantes) = aj3_elaguer("aj3-elagage").await;
        assert_eq!(statut, 500, "adossement illisible : 500 : {corps}");
        assert_eq!(aj3_cles(&corps), aj3_ensemble(&["error", "id"]), "clés exactes `error` et `id` : {corps}");
        assert_eq!(corps["error"], json!(aj3_elagage_attendu()), "la phrase du refus d'adossement, sans le fichier : {corps}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "identifiant de corrélation : {corps}");
        let texte = corps.to_string();
        assert!(!texte.contains("aj3.json") && !texte.contains("JSON invalide"), "ni chemin ni texte d'analyse : {corps}");
        assert!(!texte.contains(&*fichier.to_string_lossy()), "le chemin du fichier ne part pas : {corps}");
        assert_eq!(restantes, 1, "rien n'est élagué sur un adossement illisible");
    }

    // ---------------------------------------------------------------- (4) levée de ban refusée

    fn aj3_ban_actif(st: &AppState, ip: &str) {
        let conn = st.db.lock();
        conn.execute("DELETE FROM net_ban", []).expect("fixture : store vidé");
        conn.execute(
            "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(?1,'temoin',1000,NULL,'analyste','prod')",
            params![ip],
        )
        .expect("fixture : le ban s'insère");
        netban_reload(&conn);
        assert!(net_ban_is_blocked(ip, now()), "fixture : le ban est actif dans le cache");
    }

    /// La levée refusée sur la saisie : (statut, corps, ban encore actif).
    async fn aj3_levee_refusee() -> (u16, Value, bool) {
        let (st, _p) = sp_state("aj3-levee");
        let ip = "203.0.113.81";
        aj3_ban_actif(&st, ip);
        st.db
            .lock()
            .execute_batch(&format!("CREATE TRIGGER aj3_levee_refusee BEFORE DELETE ON net_ban BEGIN SELECT RAISE(ABORT, '{AJ3_TEXTE_DU_STORE}'); END;"))
            .expect("fixture : trigger");
        let (statut, corps) = aj3_corps(netban_delete(State(st.clone()), Extension(sp_au("adm", "admin")), Path(ip.to_string())).await).await;
        (statut, corps, net_ban_is_blocked(ip, now()))
    }

    /// La levée PARTIELLE : la saisie retirée puis reposée, la forme canonique refusée : (statut, corps, lignes).
    async fn aj3_levee_partielle() -> (u16, Value, i64) {
        let (st, _p) = sp_state("aj3-partielle");
        aj3_ban_actif(&st, "203.0.113.82");
        st.db
            .lock()
            .execute_batch(&format!(
                "CREATE TABLE aj3_compteur(n INTEGER); INSERT INTO aj3_compteur VALUES(0);
                 CREATE TRIGGER aj3_refus_canon BEFORE DELETE ON net_ban WHEN (SELECT n FROM aj3_compteur) >= 1
                   BEGIN SELECT RAISE(ABORT, '{AJ3_TEXTE_DU_STORE}'); END;
                 CREATE TRIGGER aj3_reposer AFTER DELETE ON net_ban WHEN (SELECT n FROM aj3_compteur) = 0
                   BEGIN UPDATE aj3_compteur SET n = 1;
                     INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(OLD.ip,'temoin',1000,NULL,'analyste','prod'); END;"
            ))
            .expect("fixture : triggers");
        let (statut, corps) =
            aj3_corps(netban_delete(State(st.clone()), Extension(sp_au("adm", "admin")), Path("::ffff:203.0.113.82".to_string())).await).await;
        let lignes: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).expect("fixture : le compte se lit");
        (statut, corps, lignes)
    }

    /// (4) LES DEUX REFUS DE LEVÉE NE SERVENT PAS LE TEXTE DU STORE. MUTANTS : `AJ3_LEVEE`, `AJ3_CANON`.
    #[tokio::test]
    async fn aj3_levee_de_ban_refusee_ne_sert_pas_le_texte_du_store() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (statut, corps, actif) = aj3_levee_refusee().await;
        assert_eq!(statut, 503, "{corps}");
        assert_eq!(aj3_cles(&corps), aj3_ensemble(&["error", "id"]), "clés exactes : {corps}");
        assert_eq!(corps["error"], json!(AJ3_LEVEE_IMPOSSIBLE), "la phrase du refus, sans le texte du store : {corps}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "identifiant de corrélation : {corps}");
        assert!(actif, "le ban est TOUJOURS actif");

        let (statut, corps, lignes) = aj3_levee_partielle().await;
        assert_eq!(statut, 503, "{corps}");
        assert_eq!(aj3_cles(&corps), aj3_ensemble(&["error", "id"]), "clés exactes : {corps}");
        assert_eq!(corps["error"], json!(AJ3_LEVEE_PARTIELLE), "la phrase de la levée partielle, sans le texte du store : {corps}");
        assert!(corps["id"].as_str().unwrap_or("").starts_with("plume-e"), "identifiant de corrélation : {corps}");
        assert!(!corps.to_string().contains("203.0.113"), "sans adresse : {corps}");
        assert_eq!(lignes, 1, "la ligne reposée est toujours là");
        netban_cache().write().clear();
    }

    // ---------------------------------------------------------------- (5) le journal

    /// (5) LES SEPT REFUS JOURNALISENT LA CAUSE DU MOTEUR, LIGNE ENTIÈRE. L'enfant (variable `AJ3_ENFANT` posée) joue
    /// les sept refus ; le parent lit son stderr. MUTANTS : les sept `_J`.
    #[tokio::test]
    async fn aj3_les_sept_refus_journalisent_la_cause_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'élagage lit sa conf (`cfg`)
        if std::env::var(AJ3_ENFANT).is_ok() {
            let _g = NETBAN_TEST_LOCK.lock();
            netban_cache().write().clear();
            let _ = aj3_couverture_coupee();
            let (_, dbp) = aj3_couverture_route_cache_coupe("aj3-journal-cache").await;
            println!("{AJ3_CHEMIN_ENFANT} {dbp}");
            for (table, _) in AJ3_COUPES_DE_L_INVENTAIRE {
                let _ = aj3_inventaire_coupe(table).await;
            }
            let (_, elagage, _) = aj3_elaguer("aj3-journal-elagage").await;
            let (_, levee, _) = aj3_levee_refusee().await;
            let (_, partielle, _) = aj3_levee_partielle().await;
            for corps in [&elagage, &levee, &partielle] {
                println!("{AJ3_ID_ENFANT} {}", corps["id"].as_str().unwrap_or("absent"));
            }
            netban_cache().write().clear();
            println!("{AJ3_MARQUE_ENFANT}");
            return;
        }
        let dossier = crate::tmp_possede::TmpPossede::neuf("aj3-config-d-enfant");
        let fichier = aj3_adossement_illisible(&dossier);
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::texte_du_moteur_hors_couverture_ti_inventaire_elagage_et_levee_de_ban::aj3_les_sept_refus_journalisent_la_cause_du_moteur",
            ])
            .env(AJ3_ENFANT, "1")
            .env("PLUME_CONFIG_DIR", &*dossier)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(AJ3_MARQUE_ENFANT), "contrôle : l'enfant a joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(AJ3_ID_ENFANT)).map(|(_, id)| id.trim()).collect();
        assert_eq!(ids.len(), AJ3_REFUS_5XX, "contrôle : un identifiant par refus 5xx : {stdout}");
        assert!(ids.iter().all(|id| id.starts_with("plume-e")), "contrôle : identifiants servis : {ids:?}");
        let chemins: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(AJ3_CHEMIN_ENFANT)).map(|(_, c)| c.trim()).collect();
        assert_eq!(chemins.len(), 1, "contrôle : l'enfant donne le chemin de la base du cache : {stdout}");
        let (cause, pourquoi) = crate::overlays::overlay_read_json_ou_cause(&fichier).expect_err("fixture : le fichier est illisible");
        let couverture = [
            "[threat-intel] WARN couverture : compte `total` NON lu, aucune valeur servie (no such table: ioc)",
            "[threat-intel] WARN couverture : compte `active` NON lu, aucune valeur servie (no such table: ioc)",
            "[threat-intel] WARN couverture : ventilation par type NON lue, aucune liste servie (no such table: ioc)",
            "[threat-intel] WARN couverture : ventilation par source NON lue, aucune liste servie (no such table: ioc)",
        ];
        let mut attendues: Vec<String> = couverture.iter().map(|l| l.to_string()).collect();
        attendues.push(format!(
            "[ti] WARN rechargement du cache IOC de `{}` : table `ioc` non relue (no such table: ioc) — 1 indicateur(s) \
             CONSERVÉ(S), la correspondance continue sur ce jeu",
            chemins[0]
        ));
        attendues.extend(couverture.iter().map(|l| l.to_string()));
        attendues.extend([
            "[sources] WARN inventaire NON LU (pipeline), aucune source servie (no such table: snapshot)".to_string(),
            "[sources] WARN inventaire NON LU (sources observées), aucune source servie (no such table: event_rollup)".to_string(),
            "[sources] WARN inventaire NON LU (déclarations), aucune source servie (no such table: source_settings)".to_string(),
            format!(
                "[{}] [overlays] WARN élagage des overlays orphelins refusé : adossement illisible ({cause}) : {} : {pourquoi}",
                ids[0],
                fichier.display()
            ),
            format!("[{}] [netban] WARN levée de ban NON faite, store indisponible, le ban reste actif ({AJ3_TEXTE_DU_STORE})", ids[1]),
            format!("[{}] [netban] WARN levée de ban PARTIELLE (1 retiré(s)), forme canonique NON levée ({AJ3_TEXTE_DU_STORE})", ids[2]),
        ]);
        let lignes: Vec<&str> = stderr
            .lines()
            .filter(|l| {
                l.starts_with("[threat-intel] WARN couverture")
                    || l.starts_with("[ti] WARN rechargement du cache IOC")
                    || l.starts_with("[sources] WARN inventaire NON LU")
                    || l.contains("[overlays] WARN élagage des overlays orphelins refusé")
                    || l.contains("[netban] WARN levée de ban")
            })
            .collect();
        // Le texte du moteur ATTEINT le journal : huit lectures de couverture, le cache, trois d'inventaire.
        let portent_le_moteur = lignes.iter().filter(|l| l.contains("(no such table: ")).count();
        assert_eq!(portent_le_moteur, 12, "la cause du moteur va au journal, une fois par lecture coupée :\n{stderr}");
        assert_eq!(lignes, attendues, "une ligne EXACTE par refus :\n{stderr}");
        // La ligne `HTTP 5xx` d'`err_json` ne porte ni le chemin ni le texte du store : la phrase servie les a quittés.
        let http_fuite: Vec<&str> = stderr
            .lines()
            .filter(|l| (l.contains("HTTP 500") || l.contains("HTTP 503")) && (l.contains("aj3.json") || l.contains(AJ3_TEXTE_DU_STORE)))
            .collect();
        assert!(http_fuite.is_empty(), "une ligne `HTTP 5xx` porte encore le chemin ou le texte du store : {http_fuite:?}");
    }
}
