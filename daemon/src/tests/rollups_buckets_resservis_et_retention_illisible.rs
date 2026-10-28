// =====================================================================================
// `P10.32-a`, `P10.20-b` (hors `handlers/` : `rollups.rs`) — UNE RECONSTRUCTION NE PURGE QUE LES BUCKETS QU'`event`
// PEUT RESSERVIR ; UNE COUVERTURE DONT LA RÉTRACTATION EST REFUSÉE N'EST PAS REPUBLIÉE ; UN RÉGLAGE DE RÉTENTION ÉCRIT
// MAIS ILLISIBLE NE PURGE PAS SA FAMILLE ; LES MÉTRIQUES BRUTES NE SONT PURGÉES QU'APRÈS LEUR PLI PRIS.
//
// LES DÉFAUTS, LUS SUR a759d83d :
//  * `rollup_events` : la reconstruction purgeait TOUTE la bande `[agg_from, recent)` (`DELETE FROM event_rollup WHERE
//    bucket >= ?1 AND bucket < ?2`), et `agg_from` descend jusqu'au plancher `MIN(event.ts)` : UNE vieille ligne restée
//    dans `event` (événements de contrôle gardés par la rétention ou le vieillissement) abaissait ce plancher sous des
//    buckets dont `event` ne porte plus rien — l'histoire que seul le rollup garde, effacée (mesuré n = 42 -> 0 par la
//    vérification des vagues AN/AP, dernier reste d'intégrité nommé de `P10.32-a`). Même purge par tranche dans le rollup
//    par dimension, et son plancher lu par `.ok().flatten().unwrap_or(recent)`, sans rien dire ;
//  * la rétractation de la couverture (`let _ = DELETE FROM meta …`) était avalée : la bande était reconstruite sous la
//    couverture ancienne restée publiée, le watermark avançait, et la couverture était republiée ;
//  * `retention_run_tenant` : les cinq fenêtres passaient par `retention_effective`, qui jette le troisième champ de
//    `setting_days_lu` ; une valeur ÉCRITE illisible retombait sur env/conf/défaut (365 j écrits, 30 j appliqués) ;
//  * le pli horaire des métriques (`INSERT INTO metric_rollup …`) et la purge des brutes étaient deux `let _` : un
//    INSERT refusé était suivi de la purge, les brutes partaient sans agrégat.
//
// DÉSORMAIS (décisions de l'orchestrateur, vague AQ) : la purge d'une reconstruction est bornée aux GROUPES (bucket,
// source, env_id) resservis par `event` sous la borne (`purge_des_buckets_resservis_sql`, même découpe horaire et mêmes
// `COALESCE` que l'INSERT) — une purge par bucket seul effaçait encore l'histoire d'une autre source ou d'un autre
// environnement du même bucket (vérification de la vague AQ : 42 -> 0, trois fois) ; la purge refusée d'`event_rollup`
// ne publie pas de couverture ; la rétractation refusée est comptée et dite, et rien ne bouge (bande, watermark,
// couverture) ; un réglage illisible — BLOB, ou texte présent mais non entier — saute sa famille ce tour (tick aveugle
// sous le nom du réglage), jamais le repli, gel juridique actif compris ; le pli refusé saute la purge, compté et dit.
//
// LES VOIES D'ÉCHEC FABRIQUÉES : autorisateur SQLite (premier `DELETE` sur `meta` ; premier `DELETE` sur `event_rollup` ;
// deuxième fonction `min` ; `INSERT` sur `metric_rollup`) ; valeur `setting` posée en BLOB (affinité TEXT : la ligne
// EXISTE et `get::<String>` échoue) ou en texte non entier ; une ligne d'`event` insérée par une SECONDE connexion pendant
// la préparation d'une purge (identifiant au-dessus de la borne), sur `event_rollup` et sur `event_dim_rollup` ; un gel
// juridique actif sur une AUTRE source (branche `HoldEnforce::Guard`, qui ne retient pas les lignes de la fixture). Journal
// lu sur le stderr d'un sous-processus, lignes ENTIÈRES, causes du moteur sondées dans l'enfant.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un groupe partiellement purgé côté `event` (frontière de rétention) reste
// reconstruit sur ce qui reste (limite écrite dans `rollups.rs`) ; le tier froid n'est joué que sous `--features
// cold_tier` (témoin (p) : vieillissement et horizon étendu sautés sur `retention_days` illisible), pas son expiration
// des fichiers Parquet, qui ne tourne que dans la passe de vieillissement. Les lectures de la rétention HORS de la
// passe (`cold_store/aging.rs`, sonde, bannière, routes) ne gardent plus le repli depuis la vague AR (témoins
// `retention_lue_hors_de_la_passe.rs`), ni `query.rs` et `datamodels.rs` depuis la vague AS (`frontiere_froide_non_lue_et_ecritures_avouees.rs`).
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable d'environnement de mutation sous `cfg!(test)`, puis retirées du source) :
//  * « AQ4_ER_TOUTE_LA_BANDE » (purge d'`event_rollup` sans le prédicat, la forme d'avant le lot) : (a), (d), (j) ;
//  * « AQ4_DIM_TOUTE_LA_TRANCHE » (purge d'une tranche par dimension sans le prédicat) : (c), (k) ;
//  * « AQ4_PURGE_BUCKET_SEUL » (prédicat par bucket seul) : (a), (c), (j) ; « AQ4_PURGE_SANS_SOURCE » : (a), (c), (j) ;
//    « AQ4_PURGE_SANS_ENV » : (a), (c), (j) ;
//  * « AQ4_PURGE_SANS_BORNE » (prédicat sans `id <= ?3`) : (d), (k) ; « AQ4_DIM_BORNE » (borne de la tranche à
//    `i64::MAX`, site seul) : (k) ;
//  * « AQ4_PURGE_SANS_DECOUPE » (sous-requête sans `(ts/3600)*3600`) : (a), (c) ; « AQ4_BORD_TS_SUB » (`ts > ?1` dans
//    la sous-requête) : (a) ;
//  * « AQ4_ER_PURGE_AVALEE » (résultat de la purge d'`event_rollup` jeté) : (o), (i) ;
//  * « AQ4_RETRACTION_IGNOREE », « AQ4_WM_SANS_RETRACTION », « AQ4_PUBLIE_SANS_RETRACTION », « AQ4_RETRACTION_NON_COMPTEE » : (e) ;
//  * « AQ4_RETOUR_RETENTION_EFFECTIVE », « AQ4_RET_NON_COMPTEE » : (f) ; « AQ4_RET_COMPTE_LISIBLE » : (f) ;
//    « AQ4_CLE_INCONNUE_ZERO » : (g) ;
//  * « AQ4_EV_GUARD », « AQ4_SNAP_GUARD », « AQ4_ALERT_GUARD » (repli 30/30/90 j sous gel actif) : (m) ;
//  * « AQ4_NON_ENTIER_DEFAUT » (texte non entier rendu absent, la forme d'avant) : (n) ;
//  * « AQ4_DIM_PLANCHER_BAS » (plancher non lu rendu très bas au lieu de `recent`) : (l) ;
//  * « AQ4_COLD_AGE_REPLI », « AQ4_COLD_CUTOFF_REPLI » (vieillissement ou horizon étendu nourris d'un repli) : (p) ;
//  * « AQ4_METRIC_PURGE_APRES_REFUS », « AQ4_METRIC_NON_COMPTE » : (h) ;
//  * « AQ4_RETRACTION_SANS_JOURNAL », « AQ4_DIM_PLANCHER_MUET », « AQ4_METRIC_SANS_JOURNAL », « AQ4_RET_NON_COMPTEE » : (i).
// =====================================================================================
mod rollups_buckets_resservis_et_retention_illisible {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::metrics::ticks_aveugles_de_ce_fil;
    use crate::rollup_coverage::{META_DIM_ROLLUP_COV, META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const RBR_COMPTE_RETRACTATION: &str = "geste de fond non validé rollup : couverture d'event_rollup : rétractation refusée";
    const RBR_COMPTE_PLI: &str = "geste de fond non validé retention : pli horaire des métriques : INSERT refusé";
    const JOUR: i64 = 86400;

    fn rbr_recent() -> i64 {
        heure_ronde_precedente_hors_de_la_fin_d_heure()
    }

    fn rbr_meta(conn: &rusqlite::Connection, cle: &str) -> Option<String> {
        conn.query_row("SELECT CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| r.get(0)).ok()
    }

    fn rbr_n(conn: &rusqlite::Connection, bucket: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![bucket], |r| r.get(0)).unwrap()
    }

    fn rbr_rollup(conn: &rusqlite::Connection, bucket: i64, source: &str, n: i64) {
        conn.execute(
            "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,?2,0,'','','',?3,0,'prod')",
            params![bucket, source, n],
        )
        .unwrap();
    }

    /// Une ligne de rollup d'un groupe (source, env_id) précis, `host` libre (une ligne PÉRIMÉE d'un groupe resservi porte
    /// `host = 'rbr-perime'` : une reconstruction juste la remplace par les lignes d'`event`, `host = 'rbr'`).
    fn rbr_rollup_g(conn: &rusqlite::Connection, bucket: i64, source: &str, host: &str, env: &str, n: i64) {
        conn.execute(
            "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,?2,0,'','',?3,?4,0,?5)",
            params![bucket, source, host, n, env],
        )
        .unwrap();
    }

    /// Le compte d'un groupe (bucket, source, env_id) d'`event_rollup`.
    fn rbr_n_groupe(conn: &rusqlite::Connection, bucket: i64, source: &str, env: &str) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1 AND source=?2 AND env_id=?3",
            params![bucket, source, env],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Le compte des lignes PÉRIMÉES (`host = 'rbr-perime'`) d'un bucket d'`event_rollup`.
    fn rbr_n_perime(conn: &rusqlite::Connection, bucket: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1 AND host='rbr-perime'", params![bucket], |r| r.get(0)).unwrap()
    }

    fn rbr_event(conn: &rusqlite::Connection, ts: i64) -> i64 {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbr','sshd',1,'m')", params![ts]).unwrap();
        conn.last_insert_rowid()
    }

    fn rbr_max_id(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap()
    }

    /// Les instants de la fixture d'`event_rollup`. `vieux` : UNE ligne isolée, quarante jours en arrière (le plancher),
    /// posée PILE au début de son heure (`ts == lo`, le bord bas de la bande : une sous-requête en `ts > ?1` ne la
    /// retrouverait pas) ; `hist` : un bucket à trente jours, n = 42, SANS aucune ligne d'`event` ; `vivant` : deux lignes
    /// à `recent - 7200`, `ts` NON alignés sur l'heure (une sous-requête sans découpe horaire ne les retrouverait pas).
    struct Rbr {
        b_vieux: i64,
        b_hist: i64,
        b_vivant: i64,
    }

    fn rbr_instants(recent: i64) -> Rbr {
        Rbr { b_vieux: recent - 40 * JOUR, b_hist: recent - 30 * JOUR, b_vivant: recent - 7200 }
    }

    /// Les buckets du rollup d'avant le passage : l'histoire (42, bucket sans ligne d'`event`) ; dans les buckets
    /// resservis, une ligne PÉRIMÉE du groupe (sshd, prod) qu'`event` porte (une reconstruction juste la remplace) ; et,
    /// dans le bucket de la vieille ligne, l'histoire de DEUX AUTRES groupes du même bucket — une autre source
    /// (`rbr-autre`, prod) et un autre environnement (sshd, staging), 42 chacun — qu'`event` ne porte plus.
    fn rbr_rollup_d_avant(conn: &rusqlite::Connection, i: &Rbr) {
        rbr_rollup(conn, i.b_hist, "rbr-histoire", 42);
        rbr_rollup_g(conn, i.b_vivant, "sshd", "rbr-perime", "prod", 7);
        rbr_rollup_g(conn, i.b_vieux, "sshd", "rbr-perime", "prod", 99);
        rbr_rollup_g(conn, i.b_vieux, "rbr-autre", "", "prod", 42);
        rbr_rollup_g(conn, i.b_vieux, "sshd", "", "staging", 42);
    }

    /// Les trois déclencheurs de la reconstruction : watermark et couverture absents ; watermark présent et couverture
    /// absente ; bande sale (la vieille ligne arrivée APRÈS la couverture, sous le watermark).
    fn rbr_fixture(conn: &rusqlite::Connection, cas: &str, recent: i64) -> Rbr {
        let i = rbr_instants(recent);
        conn.execute("DELETE FROM meta WHERE key IN (?1, ?2)", params![META_ROLLUP_WM, META_ROLLUP_COV_ID]).unwrap();
        rbr_rollup_d_avant(conn, &i);
        match cas {
            "absents" => {
                rbr_event(conn, i.b_vieux);
                rbr_event(conn, i.b_vivant + 60);
                rbr_event(conn, i.b_vivant + 61);
            }
            "couverture-absente" => {
                rbr_event(conn, i.b_vieux);
                rbr_event(conn, i.b_vivant + 60);
                rbr_event(conn, i.b_vivant + 61);
                conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
            }
            "bande-sale" => {
                rbr_event(conn, i.b_vivant + 60);
                let couverte = rbr_event(conn, i.b_vivant + 61);
                conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
                conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, couverte.to_string()]).unwrap();
                rbr_event(conn, i.b_vieux); // tardive : id > couverture, ts < watermark
            }
            autre => panic!("cas inconnu {autre}"),
        }
        rbr_event(conn, now() - 10); // fenêtre chaude
        i
    }

    /// (a) Les trois déclencheurs : le bucket SANS ligne d'`event` reste à 42 (avant le lot, et sous
    /// `AQ4_ER_TOUTE_LA_BANDE` : 0) ; dans le bucket de la vieille ligne, l'histoire de l'autre source et de l'autre
    /// environnement reste à 42 (sous `AQ4_PURGE_BUCKET_SEUL` : 0) ; les groupes resservis par `event` sont RECOMPOSÉS
    /// (contrôle positif : la ligne périmée disparaît, le compte vaut les lignes d'`event` — sous
    /// `AQ4_PURGE_SANS_DECOUPE` elle reste à `recent - 7200`, sous `AQ4_BORD_TS_SUB` au bord bas) ; couverture et
    /// watermark publiés.
    #[test]
    fn rbr_la_reconstruction_garde_le_bucket_sans_ligne_d_event_et_recompose_les_autres() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let mut joues = 0;
        for cas in ["absents", "couverture-absente", "bande-sale"] {
            let (st, _p) = sp_state(&format!("rbr-a-{cas}"));
            let conn = st.db.lock();
            let i = rbr_fixture(&conn, cas, recent);
            rollup_events(&conn);
            assert_eq!(rbr_n(&conn, i.b_hist), 42, "({cas}) le bucket sans ligne d'event est l'histoire que seul le rollup garde : intact");
            assert_eq!(rbr_n_perime(&conn, i.b_vivant), 0, "({cas}) groupe resservi : la ligne périmée est purgée");
            assert_eq!(rbr_n(&conn, i.b_vivant), 2, "({cas}) bucket resservi : recomposé depuis event (deux lignes)");
            assert_eq!(rbr_n_perime(&conn, i.b_vieux), 0, "({cas}) le groupe de la vieille ligne (au bord bas) est recomposé, pas conservé périmé");
            assert_eq!(rbr_n_groupe(&conn, i.b_vieux, "sshd", "prod"), 1, "({cas}) le groupe de la vieille ligne vaut sa ligne");
            assert_eq!(rbr_n_groupe(&conn, i.b_vieux, "rbr-autre", "prod"), 42, "({cas}) bucket mixte : l'histoire d'une autre source reste");
            assert_eq!(rbr_n_groupe(&conn, i.b_vieux, "sshd", "staging"), 42, "({cas}) bucket mixte : l'histoire d'un autre environnement reste");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "({cas}) watermark à recent");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), Some(rbr_max_id(&conn).to_string()), "({cas}) couverture publiée à la borne");
            joues += 1;
        }
        assert_eq!(joues, 3, "les trois déclencheurs ont été joués");
    }

    /// (b) Le plan de la purge par groupe : la liste des groupes suit `idx_event_ts` sur la bande (recherche d'intervalle,
    /// pas de balayage d'`event`), et elle n'est lue qu'UNE fois ; chaque groupe est cherché dans la table de rollup par
    /// sa clé primaire (`r`, aucun balayage de la table), la suppression se fait par `rowid`. Le plan est écrit sur le
    /// stderr du témoin (lisible par `--nocapture`).
    #[test]
    fn rbr_la_purge_des_buckets_resservis_suit_l_index_de_event_ts() {
        let (st, _p) = sp_state("rbr-plan");
        let conn = st.db.lock();
        let mut tables = 0;
        for table in ["event_rollup", "event_dim_rollup"] {
            let sql = format!("EXPLAIN QUERY PLAN {}", purge_des_buckets_resservis_sql(table));
            let mut stmt = conn.prepare(&sql).unwrap();
            let plan: Vec<String> = stmt.query_map(params![0i64, 3600i64, 1i64], |r| r.get::<_, String>(3)).unwrap().map(Result::unwrap).collect();
            eprintln!("[rbr] plan de la purge de {table} : {plan:?}");
            let lectures_de_la_bande = plan.iter().filter(|l| l.contains("event USING") && l.contains("idx_event_ts")).count();
            assert_eq!(lectures_de_la_bande, 1, "{table} : la liste des groupes suit idx_event_ts, une seule fois : {plan:?}");
            assert!(
                !plan.iter().any(|l| l.starts_with("SCAN event") || l.starts_with(&format!("SCAN {table}")) || l.starts_with("SCAN r")),
                "{table} : aucun balayage d'event ni de la table de rollup : {plan:?}"
            );
            assert!(
                plan.iter().any(|l| l.starts_with("SEARCH r USING ") && l.contains(&format!("sqlite_autoindex_{table}_1 (bucket=? AND source=?"))),
                "{table} : chaque groupe est cherché par la clé primaire de la table de rollup : {plan:?}"
            );
            tables += 1;
        }
        assert_eq!(tables, 2, "les deux tables ont été jugées");
    }

    fn rbr_n_dim(conn: &rusqlite::Connection, bucket: i64, val: &str) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE bucket=?1 AND source='web' AND dim='status' AND val=?2",
            params![bucket, val],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// (c) Rollup par dimension : la tranche basse `[from - 5 h, from)` porte un bucket d'histoire de `web` (n = 42) où
    /// `event` ne porte AUCUNE ligne de `web` en prod — seulement une ligne `sshd` et une ligne `web` de `staging` (bucket
    /// mixte) —, et le bucket de la vieille ligne (le plancher), où une valeur périmée traîne. L'histoire reste à 42 (sous
    /// `AQ4_DIM_TOUTE_LA_TRANCHE`, `AQ4_PURGE_BUCKET_SEUL`, `AQ4_PURGE_SANS_SOURCE`, `AQ4_PURGE_SANS_ENV` : 0), la ligne
    /// de `staging` y est agrégée, le bucket du plancher est recomposé (sous `AQ4_PURGE_SANS_DECOUPE`, la valeur périmée
    /// reste) ; la bande est publiée.
    #[test]
    fn rbr_la_tranche_par_dimension_garde_le_bucket_sans_ligne_d_event() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let from = recent - 10 * 3600;
        let b_vieux = from - 5 * 3600;
        let b_hist = from - 3 * 3600;
        let (st, _p) = sp_state("rbr-c-dim");
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'m','{\"status\":\"200\"}')", params![b_vieux + 77])
            .unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'m','{\"status\":\"500\"}')", params![now() - 10])
            .unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbr','sshd',1,'m')", params![b_hist + 9]).unwrap();
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,fields,env_id) VALUES(?1,'rbr','web',1,'m','{\"status\":\"201\"}','staging')",
            params![b_hist + 11],
        )
        .unwrap();
        for (bucket, val, n) in [(b_hist, "418", 42), (b_vieux, "999", 7)] {
            conn.execute("INSERT INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status',?2,?3,'prod')", params![bucket, val, n])
                .unwrap();
        }
        let id = rbr_max_id(&conn);
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)",
            params![META_DIM_ROLLUP_COV, format!("{from}|{recent}|{recent}|{id}")],
        )
        .unwrap();
        rollup_events(&conn);
        assert_eq!(rbr_n_dim(&conn, b_hist, "418"), 42, "bucket mixte : l'histoire de web en prod reste intacte");
        assert_eq!(rbr_n_dim(&conn, b_hist, "201"), 1, "contrôle : le groupe resservi (web, staging) du même bucket est agrégé");
        assert_eq!(rbr_n_dim(&conn, b_vieux, "999"), 0, "bucket resservi : la valeur périmée est purgée");
        assert_eq!(rbr_n_dim(&conn, b_vieux, "200"), 1, "bucket resservi : recomposé depuis event");
        assert_eq!(rbr_meta(&conn, META_DIM_ROLLUP_COV), Some(format!("{b_vieux}|{recent}|{recent}|{id}")), "la bande est publiée jusqu'au plancher");
    }

    /// (d) Une ligne d'`event` insérée par une SECONDE connexion pendant la préparation de la purge (donc au-dessus de la
    /// borne `new_cov`, lue avant) dans le bucket d'histoire, du MÊME groupe que cette histoire (`rbr-histoire`, prod) :
    /// l'INSERT borné ne l'agrège pas, la purge ne doit donc pas effacer ce groupe. Sous `AQ4_PURGE_SANS_BORNE`, il passe
    /// de 42 à 0.
    #[test]
    fn rbr_une_ligne_au_dessus_de_la_borne_ne_fait_pas_purger_son_bucket() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let (st, chemin) = sp_state("rbr-d-borne");
        let conn = st.db.lock();
        let i = rbr_fixture(&conn, "absents", recent);
        let seconde = std::sync::Mutex::new(open_db(&chemin).unwrap());
        let ts_course = i.b_hist + 5;
        let inseree = Arc::new(AtomicUsize::new(0));
        let compteur = inseree.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Delete { table_name: "event_rollup" } = ctx.action {
                if compteur.load(Ordering::Relaxed) == 0 {
                    seconde
                        .lock()
                        .unwrap()
                        .execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbr','rbr-histoire',1,'course')", params![ts_course])
                        .unwrap();
                    compteur.fetch_add(1, Ordering::Relaxed);
                }
            }
            Authorization::Allow
        }));
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(inseree.load(Ordering::Relaxed), 1, "prémisse : la ligne de course est insérée une fois");
        let id_course: i64 = conn.query_row("SELECT id FROM event WHERE ts=?1", params![ts_course], |r| r.get(0)).unwrap();
        let cov: i64 = rbr_meta(&conn, META_ROLLUP_COV_ID).expect("prémisse : couverture publiée").parse().unwrap();
        assert!(id_course > cov, "prémisse : la ligne de course est au-dessus de la borne ({id_course} > {cov})");
        assert_eq!(rbr_n(&conn, i.b_hist), 42, "une ligne au-dessus de la borne ne fait pas purger un bucket que l'INSERT ne récrira pas");
        assert_eq!(rbr_n(&conn, i.b_vivant), 2, "contrôle : la bande est reconstruite");
    }

    /// Autorisateur qui refuse le PREMIER `DELETE` sur `meta` (la rétractation de la couverture : aucun autre effacement
    /// de `meta` ne la précède dans `rollup_events`). Rend le nombre de refus.
    fn rbr_refuser_la_retractation(conn: &rusqlite::Connection) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = 0usize;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "meta" } => {
                vus += 1;
                if vus == 1 {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// Fixture de (e) : un passage nominal établit watermark et couverture, puis le watermark est ramené à `recent - 7200`
    /// (rattrapage `[recent - 7200, recent)` demandé) et une ligne périmée est posée dans ce bucket ; `avec_couverture` =
    /// false retire la couverture. Rend (couverture d'avant, bucket du rattrapage).
    fn rbr_rattrapage(conn: &rusqlite::Connection, recent: i64, avec_couverture: bool) -> (Option<String>, i64) {
        let b = recent - 7200;
        rbr_event(conn, b + 60);
        rollup_events(conn);
        rbr_event(conn, now() - 10);
        conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![b.to_string(), META_ROLLUP_WM]).unwrap();
        rbr_rollup_g(conn, b, "sshd", "rbr-perime", "prod", 7);
        if !avec_couverture {
            conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        }
        (rbr_meta(conn, META_ROLLUP_COV_ID), b)
    }

    /// (e) Rétractation REFUSÉE : ni la bande (ligne périmée intacte), ni le watermark (`recent - 7200`), ni la couverture
    /// ne bougent — présente, elle reste celle d'avant ; absente, elle n'est pas publiée —, la fenêtre chaude est servie,
    /// le refus est compté une fois. Contrôle : sans refus, la bande est recomposée, watermark et couverture publiés, rien
    /// n'est compté.
    #[test]
    fn rbr_une_retractation_refusee_ne_touche_ni_la_bande_ni_le_watermark_ni_la_couverture() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let bucket_chaud = (now() - 10) / 3600 * 3600;
        {
            let (st, _p) = sp_state("rbr-e-controle");
            let conn = st.db.lock();
            let (_, b) = rbr_rattrapage(&conn, recent, true);
            rollup_events(&conn);
            assert_eq!(rbr_n_perime(&conn, b), 0, "contrôle : la bande est recomposée");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "contrôle : watermark à recent");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), Some(rbr_max_id(&conn).to_string()), "contrôle : couverture à la borne");
            assert_eq!(compte_des_temoins(&conn, RBR_COMPTE_RETRACTATION), 0, "contrôle : rien n'est compté");
        }
        let mut joues = 0;
        for avec_couverture in [true, false] {
            let (st, _p) = sp_state(&format!("rbr-e-refus-{avec_couverture}"));
            let conn = st.db.lock();
            let (cov_avant, b) = rbr_rattrapage(&conn, recent, avec_couverture);
            assert_eq!(cov_avant.is_some(), avec_couverture, "prémisse : couverture présente ou absente");
            let refus = rbr_refuser_la_retractation(&conn);
            rollup_events(&conn);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse ({avec_couverture}) : la rétractation est refusée une fois");
            assert_eq!(rbr_n_perime(&conn, b), 7, "({avec_couverture}) rétractation refusée : la bande n'est ni purgée ni ré-agrégée");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_WM), Some(b.to_string()), "({avec_couverture}) rétractation refusée : le watermark n'avance pas");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), cov_avant, "({avec_couverture}) rétractation refusée : la couverture n'est pas republiée");
            assert!(rbr_n(&conn, bucket_chaud) >= 1, "({avec_couverture}) la fenêtre chaude reste servie");
            assert_eq!(compte_des_temoins(&conn, RBR_COMPTE_RETRACTATION), 1, "({avec_couverture}) le refus est compté une fois");
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux départs ont été joués");
    }

    /// Les deux âges d'une famille : `moyen` (plus vieux que le défaut, plus jeune que 365 unités) et `ancien` (plus vieux
    /// que 365 unités). Unité : le jour, l'heure pour `metric_raw_hours`.
    fn rbr_ages(cle: &str, n: i64) -> (i64, i64) {
        if cle == "metric_raw_hours" {
            (n - 100 * 3600, n - 400 * 3600)
        } else {
            (n - 200 * JOUR, n - 400 * JOUR)
        }
    }

    const RBR_FAMILLES: [&str; 5] = ["retention_days", "snapshot_days", "alert_days", "metric_days", "metric_raw_hours"];

    /// Pose, pour chaque famille, une ligne `moyen` et une ligne `ancien` dans chacune de ses tables.
    fn rbr_retention_fixture(conn: &rusqlite::Connection, n: i64) {
        for cle in RBR_FAMILLES {
            let (moyen, ancien) = rbr_ages(cle, n);
            for (ts, age) in [(moyen, "moyen"), (ancien, "ancien")] {
                match cle {
                    "retention_days" => {
                        conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent',?2,'')", params![ts, age]).unwrap();
                        let b = ts / 3600 * 3600;
                        rbr_rollup(conn, b, age, 5);
                        conn.execute("INSERT INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status',?2,5,'prod')", params![b, age])
                            .unwrap();
                    }
                    "snapshot_days" => {
                        conn.execute("INSERT INTO snapshot(ts,kind,data) VALUES(?1,'firewall',?2)", params![ts, age]).unwrap();
                    }
                    "alert_days" => {
                        conn.execute("INSERT INTO alert(ts,rule,severity,status,title) VALUES(?1,'r',2,'closed',?2)", params![ts, age]).unwrap();
                    }
                    "metric_days" => {
                        conn.execute("INSERT INTO metric_rollup(ts,name,host,labels,avg,min,max,n) VALUES(?1,'rbr-agrege','h',?2,1,1,1,1)", params![ts, age])
                            .unwrap();
                    }
                    "metric_raw_hours" => {
                        conn.execute("INSERT INTO metric(ts,name,host,labels,value) VALUES(?1,'rbr-brut','h',?2,1.0)", params![ts, age]).unwrap();
                    }
                    autre => panic!("famille inconnue {autre}"),
                }
            }
        }
    }

    /// Les lignes restantes d'une famille d'âge `age`, dans CHACUNE de ses tables (une famille à trois tables rend trois
    /// comptes : tous doivent valoir la même chose).
    fn rbr_restantes(conn: &rusqlite::Connection, cle: &str, age: &str) -> Vec<i64> {
        let q = |sql: &str| -> i64 { conn.query_row(sql, params![age], |r| r.get(0)).unwrap() };
        match cle {
            "retention_days" => vec![
                q("SELECT COUNT(*) FROM event WHERE message=?1"),
                q("SELECT COUNT(*) FROM event_rollup WHERE source=?1"),
                q("SELECT COUNT(*) FROM event_dim_rollup WHERE val=?1"),
            ],
            "snapshot_days" => vec![q("SELECT COUNT(*) FROM snapshot WHERE data=?1")],
            "alert_days" => vec![q("SELECT COUNT(*) FROM alert WHERE title=?1")],
            "metric_days" => vec![q("SELECT COUNT(*) FROM metric_rollup WHERE name='rbr-agrege' AND labels=?1")],
            "metric_raw_hours" => vec![q("SELECT COUNT(*) FROM metric WHERE name='rbr-brut' AND labels=?1")],
            autre => panic!("famille inconnue {autre}"),
        }
    }

    fn rbr_pose_le_reglage(conn: &rusqlite::Connection, cle: &str, valeur: rusqlite::types::Value) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global',?1,?2)", params![cle, valeur]).unwrap();
    }

    fn rbr_cause_du_moteur(conn: &rusqlite::Connection, cle: &str) -> String {
        conn.query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![cle], |r| r.get::<_, String>(0))
            .expect_err("prémisse : la valeur écrite est illisible")
            .to_string()
    }

    /// (f) Pour CHACUNE des cinq familles : son réglage écrit en BLOB (illisible SEUL) -> aucune ligne de la famille n'est
    /// supprimée, les quatre voisines (défauts) sont purgées, un tick aveugle est compté sous le nom du réglage et sous la
    /// cause du moteur, aucun sous les voisines ; le pli des métriques brutes n'a pas lieu quand `metric_raw_hours` est
    /// illisible. Contrôle : le même réglage lisible à 365 -> `moyen` gardé, `ancien` purgé (purge inchangée), RIEN compté
    /// sous aucune des cinq familles (sous `AQ4_RET_COMPTE_LISIBLE`, un tick est compté pour un réglage lu). Sous
    /// `AQ4_RETOUR_RETENTION_EFFECTIVE` (le repli), la famille illisible est purgée au défaut.
    #[test]
    fn rbr_un_reglage_de_retention_illisible_ne_purge_pas_sa_famille() {
        let _env = VERROU_ENV_PROCESSUS.read(); // retention_run lit cfg()
        let mut jugees = 0;
        for cle in RBR_FAMILLES {
            for lisible in [false, true] {
                let (st, _p) = sp_state(&format!("rbr-f-{cle}-{lisible}"));
                let n = now();
                let cause = {
                    let conn = st.db.lock();
                    rbr_retention_fixture(&conn, n);
                    // La cause du moteur pour une valeur BLOB, sondée sur une clé hors de `RETENTION_FIELDS` : la même
                    // dans les deux régimes, pour que le contrôle lisible juge le même compte que le régime illisible.
                    rbr_pose_le_reglage(&conn, "rbr_sonde", rusqlite::types::Value::Blob(vec![0]));
                    let cause = crate::rollups::cause_du_reglage_de_retention_illisible(&rbr_cause_du_moteur(&conn, "rbr_sonde"));
                    let valeur = if lisible { rusqlite::types::Value::Text("365".into()) } else { rusqlite::types::Value::Blob(vec![0]) };
                    rbr_pose_le_reglage(&conn, cle, valeur);
                    cause
                };
                let avant: Vec<u64> = RBR_FAMILLES.iter().map(|k| ticks_aveugles_de_ce_fil::compte(*k, &cause)).collect();
                retention_run(&st.db);
                let apres: Vec<u64> = RBR_FAMILLES.iter().map(|k| ticks_aveugles_de_ce_fil::compte(*k, &cause)).collect();
                let conn = st.db.lock();
                for voisine in RBR_FAMILLES {
                    let (moyen, ancien) = (rbr_restantes(&conn, voisine, "moyen"), rbr_restantes(&conn, voisine, "ancien"));
                    let tables = moyen.len();
                    let (attendu_moyen, attendu_ancien) = match (voisine == cle, lisible) {
                        (true, false) => (1, 1), // illisible : rien supprimé
                        (true, true) => (1, 0),  // 365 lisible : moyen gardé, ancien purgé
                        (false, _) => (0, 0),    // voisine au défaut : tout purgé
                    };
                    assert_eq!(moyen, vec![attendu_moyen; tables], "({cle}, lisible={lisible}) famille {voisine}, âge moyen");
                    assert_eq!(ancien, vec![attendu_ancien; tables], "({cle}, lisible={lisible}) famille {voisine}, âge ancien");
                }
                let plis: i64 = conn.query_row("SELECT COUNT(*) FROM metric_rollup WHERE name='rbr-brut'", [], |r| r.get(0)).unwrap();
                let plis_attendus = match (cle, lisible) {
                    ("metric_raw_hours", false) => 0, // ni pli ni purge
                    ("metric_raw_hours", true) => 1,  // l'ancienne seule
                    _ => 2,                           // les deux, au défaut de 48 h
                };
                assert_eq!(plis, plis_attendus, "({cle}, lisible={lisible}) pli des métriques brutes");
                let deltas: Vec<u64> = apres.iter().zip(&avant).map(|(a, b)| a - b).collect();
                let attendus: Vec<u64> = RBR_FAMILLES.iter().map(|k| u64::from(*k == cle && !lisible)).collect();
                assert_eq!(deltas, attendus, "({cle}, lisible={lisible}) un tick aveugle sous le réglage illisible et lui seul, rien sous un réglage lu");
                jugees += 1;
            }
        }
        assert_eq!(jugees, 2 * RBR_FAMILLES.len(), "chaque famille jugée illisible puis lisible");
        assert!(jugees >= 10, "plancher : cinq familles, deux régimes");
    }

    /// (g) Une clé absente de `RETENTION_FIELDS` ne vaut pas zéro (le repli de `retention_effective`, qui purgerait tout) :
    /// `None`, compté. Sous `AQ4_CLE_INCONNUE_ZERO` : `Some(0)`.
    #[test]
    fn rbr_une_cle_de_retention_inconnue_ne_vaut_pas_zero() {
        let _env = VERROU_ENV_PROCESSUS.read(); // cfg_lu lit l'environnement
        let conn = test_db();
        let conf: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let avant = ticks_aveugles_de_ce_fil::compte("rbr_cle_inconnue", crate::rollups::CAUSE_CLE_DE_RETENTION_INCONNUE);
        assert_eq!(crate::rollups::fenetre_de_retention_lue(&conn, &conf, "rbr_cle_inconnue"), None, "clé inconnue : aucune fenêtre");
        let apres = ticks_aveugles_de_ce_fil::compte("rbr_cle_inconnue", crate::rollups::CAUSE_CLE_DE_RETENTION_INCONNUE);
        assert_eq!(apres - avant, 1, "clé inconnue : comptée");
        assert_eq!(crate::rollups::fenetre_de_retention_lue(&conn, &conf, "alert_days"), Some(90), "contrôle : clé connue, défaut lu");
    }

    fn rbr_refuser_le_pli(st: &AppState) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "metric_rollup" } => {
                compteur.fetch_add(1, Ordering::Relaxed);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// (h) L'INSERT du pli horaire des métriques REFUSÉ : les métriques brutes ne sont PAS purgées (sous
    /// `AQ4_METRIC_PURGE_APRES_REFUS`, la forme d'avant, elles partent sans agrégat), le refus est compté une fois.
    /// Contrôle : sans refus, la brute est pliée puis purgée, rien n'est compté.
    #[test]
    fn rbr_un_pli_des_metriques_refuse_ne_purge_pas_les_brutes() {
        let _env = VERROU_ENV_PROCESSUS.read(); // retention_run lit cfg()
        let brute = |st: &AppState| -> (i64, i64) {
            let conn = st.db.lock();
            (
                conn.query_row("SELECT COUNT(*) FROM metric WHERE name='rbr-brut'", [], |r| r.get(0)).unwrap(),
                conn.query_row("SELECT COALESCE(SUM(n),0) FROM metric_rollup WHERE name='rbr-brut'", [], |r| r.get(0)).unwrap(),
            )
        };
        for refuse in [false, true] {
            let (st, _p) = sp_state(&format!("rbr-h-{refuse}"));
            st.db.lock().execute("INSERT INTO metric(ts,name,host,value) VALUES(?1,'rbr-brut','h',1.0)", params![now() - 100 * 3600]).unwrap();
            let refus = if refuse { Some(rbr_refuser_le_pli(&st)) } else { None };
            retention_run(&st.db);
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let compte = compte_des_temoins(&st.db.lock(), RBR_COMPTE_PLI);
            if let Some(refus) = refus {
                assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'INSERT du pli est refusé une fois");
                assert_eq!(brute(&st), (1, 0), "pli refusé : la brute est gardée, aucun agrégat");
                assert_eq!(compte, 1, "pli refusé : compté une fois");
            } else {
                assert_eq!(brute(&st), (0, 1), "contrôle : la brute est pliée puis purgée");
                assert_eq!(compte, 0, "contrôle : rien n'est compté");
            }
        }
    }

    /// (i) LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus, ENTIÈRES : rétractation refusée, plancher du
    /// rollup par dimension non lu (deuxième `min` refusé, le plancher d'`event_rollup` lu), purge de reconstruction
    /// d'`event_rollup` refusée (sous `AQ4_ER_PURGE_AVALEE`, aucune ligne), pli des métriques refusé,
    /// réglage de rétention illisible (la ligne du tick aveugle). Le passage nominal n'en écrit aucune. Les causes du
    /// moteur sont sondées dans l'enfant et rendues sur sa sortie standard.
    #[test]
    fn rbr_lignes_de_journal_des_refus() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        const ENFANT: &str = "RBR_ENFANT_JOURNAL";
        const PHASE: &str = "RBR-PHASE:";
        const MOTEUR: &str = "RBR-MOTEUR-";
        const TETE_RETRACTATION: &str = "[rollup] WARN couverture d'event_rollup NON rétractée (";
        const TETE_DIM: &str = "[rollup] WARN plancher d'event du rollup par dimension NON lu (";
        const TETE_PLI: &str = "[retention] WARN pli horaire des métriques NON écrit (";
        const TETE_PURGE: &str = "[rollup] WARN purge de reconstruction d'event_rollup NON faite (";
        const TETE_REGLAGE: &str = "[plume] balayage de fond AVEUGLE (snapshot_days) : ";
        if std::env::var(ENFANT).is_ok() {
            let recent = rbr_recent();
            // Sondes des causes du moteur, sur une base jetable.
            {
                let sonde = test_db();
                sonde.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Delete { table_name: "meta" } | AuthAction::Insert { table_name: "metric_rollup" } => Authorization::Deny,
                    AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("min") => Authorization::Deny,
                    _ => Authorization::Allow,
                }));
                let m = |r: rusqlite::Result<usize>| r.expect_err("sonde refusée").to_string();
                println!("{MOTEUR}DELETE:{}", m(sonde.execute("DELETE FROM meta WHERE key='rbr'", [])));
                println!("{MOTEUR}INSERT:{}", m(sonde.execute("INSERT INTO metric_rollup(ts,name) VALUES(0,'rbr')", [])));
                println!(
                    "{MOTEUR}MIN:{}",
                    sonde.query_row("SELECT MIN(ts) FROM event", [], |r| r.get::<_, Option<i64>>(0)).expect_err("sonde refusée")
                );
                sonde.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                rbr_pose_le_reglage(&sonde, "snapshot_days", rusqlite::types::Value::Blob(vec![0]));
                println!("{MOTEUR}BLOB:{}", rbr_cause_du_moteur(&sonde, "snapshot_days"));
            }
            eprintln!("{PHASE}retractation");
            {
                let (st, _p) = sp_state("rbr-i-retractation");
                let conn = st.db.lock();
                rbr_rattrapage(&conn, recent, true);
                let refus = rbr_refuser_la_retractation(&conn);
                rollup_events(&conn);
                conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("RBR-REFUS-RETRACTATION:{}", refus.load(Ordering::Relaxed));
            }
            eprintln!("{PHASE}dim");
            {
                let (st, _p) = sp_state("rbr-i-dim");
                let conn = st.db.lock();
                let i = rbr_fixture(&conn, "absents", recent);
                let refus = Arc::new(AtomicUsize::new(0));
                let compteur = refus.clone();
                let mut mins = 0usize;
                conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("min") => {
                        mins += 1;
                        if mins == 2 {
                            compteur.fetch_add(1, Ordering::Relaxed);
                            Authorization::Deny
                        } else {
                            Authorization::Allow
                        }
                    }
                    _ => Authorization::Allow,
                }));
                rollup_events(&conn);
                conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("RBR-REFUS-DIM:{}", refus.load(Ordering::Relaxed));
                println!("RBR-PLANCHER-LU:{}", rbr_n_groupe(&conn, i.b_vieux, "sshd", "prod"));
            }
            eprintln!("{PHASE}purge");
            {
                let (st, _p) = sp_state("rbr-i-purge");
                let conn = st.db.lock();
                rbr_fixture(&conn, "absents", recent);
                let refus = rbr_refuser_la_purge_d_event_rollup(&conn);
                rollup_events(&conn);
                conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("RBR-REFUS-PURGE:{}", refus.load(Ordering::Relaxed));
            }
            eprintln!("{PHASE}pli");
            {
                let (st, _p) = sp_state("rbr-i-pli");
                st.db.lock().execute("INSERT INTO metric(ts,name,host,value) VALUES(?1,'rbr-brut','h',1.0)", params![now() - 100 * 3600]).unwrap();
                let refus = rbr_refuser_le_pli(&st);
                retention_run(&st.db);
                st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("RBR-REFUS-PLI:{}", refus.load(Ordering::Relaxed));
            }
            eprintln!("{PHASE}reglage");
            {
                let (st, _p) = sp_state("rbr-i-reglage");
                rbr_pose_le_reglage(&st.db.lock(), "snapshot_days", rusqlite::types::Value::Blob(vec![0]));
                retention_run(&st.db);
            }
            eprintln!("{PHASE}calme");
            {
                let (st, _p) = sp_state("rbr-i-calme");
                {
                    let conn = st.db.lock();
                    rbr_rattrapage(&conn, recent, true);
                    rollup_events(&conn);
                    conn.execute("INSERT INTO metric(ts,name,host,value) VALUES(?1,'rbr-brut','h',1.0)", params![now() - 100 * 3600]).unwrap();
                    rbr_pose_le_reglage(&conn, "snapshot_days", rusqlite::types::Value::Text("365".into()));
                }
                retention_run(&st.db);
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::rollups_buckets_resservis_et_retention_illisible::rbr_lignes_de_journal_des_refus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut premisses = 0;
        for m in ["RBR-REFUS-RETRACTATION:1", "RBR-REFUS-DIM:1", "RBR-PLANCHER-LU:1", "RBR-REFUS-PURGE:1", "RBR-REFUS-PLI:1"] {
            assert!(stdout.lines().any(|l| l == m), "prémisse : {m} : {stdout}");
            premisses += 1;
        }
        assert_eq!(premisses, 5, "les cinq prémisses jugées");
        let moteur = |nom: &str| -> String {
            let tete = format!("{MOTEUR}{nom}:");
            // La première sonde peut partager sa ligne avec l'en-tête du test (« test … ... ») : la tête est cherchée DANS la ligne.
            stdout.lines().find_map(|l| l.split_once(tete.as_str()).map(|(_, v)| v)).unwrap_or_else(|| panic!("sonde {nom} : {stdout}")).to_string()
        };
        let phase = |nom: &str, tete: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with(tete)).map(str::to_string).collect()
        };
        assert_eq!(
            phase("retractation", TETE_RETRACTATION),
            vec![format!(
                "{TETE_RETRACTATION}{}) — bande, watermark et couverture laissés tels quels ce passage, reprise au prochain passage",
                moteur("DELETE")
            )],
            "rétractation refusée : une ligne, entière"
        );
        assert_eq!(
            phase("dim", TETE_DIM),
            vec![format!("{TETE_DIM}{}) — le front bas ne descend pas ce passage, reprise au prochain passage", moteur("MIN"))],
            "plancher du rollup par dimension non lu : une ligne, entière"
        );
        assert_eq!(
            phase("purge", TETE_PURGE),
            vec![format!(
                "{TETE_PURGE}{}) — bande non ré-agrégée, couverture non publiée (la route sert le brut), reprise au prochain passage",
                moteur("DELETE")
            )],
            "purge de reconstruction refusée : une ligne, entière"
        );
        assert_eq!(
            phase("pli", TETE_PLI),
            vec![format!("{TETE_PLI}{}) — métriques brutes NON purgées ce tour, reprise au prochain passage", moteur("INSERT"))],
            "pli refusé : une ligne, entière"
        );
        assert_eq!(
            phase("reglage", TETE_REGLAGE),
            vec![format!(
                "{TETE_REGLAGE}aucun geste de ce balayage ce tour-ci : {}",
                crate::rollups::cause_du_reglage_de_retention_illisible(&moteur("BLOB"))
            )],
            "réglage illisible : la ligne du tick aveugle, entière"
        );
        let mut calmes = 0;
        for tete in [TETE_RETRACTATION, TETE_DIM, TETE_PURGE, TETE_PLI, TETE_REGLAGE] {
            assert!(phase("calme", tete).is_empty(), "le nominal n'écrit pas « {tete} »");
            calmes += 1;
        }
        assert_eq!(calmes, 5, "les cinq têtes jugées au nominal");
    }

    /// Autorisateur qui refuse le PREMIER `DELETE` sur `event_rollup` (la purge de reconstruction : elle précède la purge
    /// de la fenêtre chaude dans `rollup_events`). Rend le nombre de refus.
    fn rbr_refuser_la_purge_d_event_rollup(conn: &rusqlite::Connection) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = 0usize;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "event_rollup" } => {
                vus += 1;
                if vus == 1 {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// (j) LE BUCKET MIXTE, les deux sondes de la vérification de la vague AQ : un bucket d'histoire (web, prod, n = 42,
    /// aucune ligne d'`event` de ce groupe) partage son heure avec UNE ligne d'`event` d'un AUTRE groupe — un événement de
    /// contrôle `plume-config`/`daemon` (jamais purgé), ou une ligne de `web` d'un autre environnement (`staging`, l'index
    /// de prod étant plafonné). L'histoire reste à 42 (sous `AQ4_PURGE_BUCKET_SEUL` et `AQ4_ER_TOUTE_LA_BANDE` : 0 ; sous
    /// `AQ4_PURGE_SANS_SOURCE`, le premier cas ; sous `AQ4_PURGE_SANS_ENV`, le second) ; le groupe de la ligne est agrégé,
    /// couverture publiée.
    #[test]
    fn rbr_un_bucket_mixte_garde_l_histoire_des_autres_groupes() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let b_h = recent - 30 * JOUR;
        let mut joues = 0;
        for (cas, source, env) in [("autre-source", "plume-config", "prod"), ("autre-env", "web", "staging")] {
            let (st, _p) = sp_state(&format!("rbr-j-{cas}"));
            let conn = st.db.lock();
            rbr_rollup_g(&conn, b_h, "web", "", "prod", 42);
            conn.execute(
                "INSERT INTO event(ts,host,source,severity,message,origin,env_id) VALUES(?1,'rbr',?2,1,'m','daemon',?3)",
                params![b_h + 5, source, env],
            )
            .unwrap();
            rbr_event(&conn, now() - 10);
            rollup_events(&conn);
            assert_eq!(rbr_n_groupe(&conn, b_h, "web", "prod"), 42, "({cas}) l'histoire d'un autre groupe du bucket reste intacte");
            assert_eq!(rbr_n_groupe(&conn, b_h, source, env), 1, "({cas}) contrôle : le groupe resservi est agrégé");
            assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), Some(rbr_max_id(&conn).to_string()), "({cas}) couverture publiée");
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux sondes jouées");
    }

    /// (k) La borne de la tranche par dimension : une ligne de `web` (prod) insérée par une SECONDE connexion pendant la
    /// préparation de la purge de la tranche basse (donc au-dessus de `dim_at_id`, lue avant) dans le bucket d'histoire de
    /// la dimension : l'INSERT borné ne l'agrège pas, la purge ne doit donc pas effacer ce groupe. Sous `AQ4_DIM_BORNE`
    /// (borne de ce site seul) et `AQ4_PURGE_SANS_BORNE`, il passe de 42 à 0.
    #[test]
    fn rbr_une_ligne_au_dessus_de_la_borne_ne_fait_pas_purger_une_tranche_par_dimension() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let from = recent - 10 * 3600;
        let b_vieux = from - 5 * 3600;
        let b_hist = from - 3 * 3600;
        let (st, chemin) = sp_state("rbr-k-dim-borne");
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'m','{\"status\":\"200\"}')", params![b_vieux + 77])
            .unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'m','{\"status\":\"500\"}')", params![now() - 10])
            .unwrap();
        conn.execute("INSERT INTO event_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,'web','status','418',42,'prod')", params![b_hist]).unwrap();
        let id = rbr_max_id(&conn);
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_DIM_ROLLUP_COV, format!("{from}|{recent}|{recent}|{id}")])
            .unwrap();
        let seconde = std::sync::Mutex::new(open_db(&chemin).unwrap());
        let ts_course = b_hist + 5;
        let inseree = Arc::new(AtomicUsize::new(0));
        let compteur = inseree.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Delete { table_name: "event_dim_rollup" } = ctx.action {
                if compteur.load(Ordering::Relaxed) == 0 {
                    seconde
                        .lock()
                        .unwrap()
                        .execute(
                            "INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'course','{\"status\":\"200\"}')",
                            params![ts_course],
                        )
                        .unwrap();
                    compteur.fetch_add(1, Ordering::Relaxed);
                }
            }
            Authorization::Allow
        }));
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(inseree.load(Ordering::Relaxed), 1, "prémisse : la ligne de course est insérée une fois");
        let id_course: i64 = conn.query_row("SELECT id FROM event WHERE ts=?1", params![ts_course], |r| r.get(0)).unwrap();
        let cov = rbr_meta(&conn, META_DIM_ROLLUP_COV).expect("prémisse : bande publiée");
        let at_id: i64 = cov.rsplit('|').next().unwrap().parse().unwrap();
        assert!(id_course > at_id, "prémisse : la ligne de course est au-dessus de la borne ({id_course} > {at_id})");
        assert_eq!(cov, format!("{b_vieux}|{recent}|{recent}|{at_id}"), "prémisse : la tranche basse a été reconstruite et publiée");
        assert_eq!(rbr_n_dim(&conn, b_hist, "418"), 42, "une ligne au-dessus de la borne ne fait pas purger un groupe que l'INSERT ne récrira pas");
        assert_eq!(rbr_n_dim(&conn, b_vieux, "200"), 1, "contrôle : la tranche est reconstruite");
    }

    /// (l) LA VALEUR du plancher non lu du rollup par dimension : `recent`, donc le front bas ne descend pas — la bande
    /// publiée part de `recent` et la ligne de `recent - 5 h` n'est pas agrégée (sous `AQ4_DIM_PLANCHER_BAS`, un plancher
    /// très bas : la bande descend de 24 h et la ligne est agrégée). Contrôle sans refus : le plancher lu, la bande
    /// descend jusqu'à la ligne. La ligne de journal est jugée en (i).
    #[test]
    fn rbr_un_plancher_par_dimension_non_lu_ne_fait_pas_descendre_la_bande() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let b = recent - 5 * 3600;
        for refuse in [false, true] {
            let (st, _p) = sp_state(&format!("rbr-l-{refuse}"));
            let conn = st.db.lock();
            conn.execute("INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rbr','web',1,'m','{\"status\":\"200\"}')", params![b + 77])
                .unwrap();
            rbr_event(&conn, now() - 10);
            let id = rbr_max_id(&conn);
            let refus = Arc::new(AtomicUsize::new(0));
            if refuse {
                // Watermark et couverture d'`event_rollup` absents, aucune bande par dimension : le premier `min` est le
                // plancher d'`event_rollup`, le deuxième celui du rollup par dimension (même ordre qu'en (i)).
                let compteur = refus.clone();
                let mut mins = 0usize;
                conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("min") => {
                        mins += 1;
                        if mins == 2 {
                            compteur.fetch_add(1, Ordering::Relaxed);
                            Authorization::Deny
                        } else {
                            Authorization::Allow
                        }
                    }
                    _ => Authorization::Allow,
                }));
            }
            rollup_events(&conn);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            if refuse {
                assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : le plancher par dimension est refusé une fois");
                assert_eq!(rbr_meta(&conn, META_DIM_ROLLUP_COV), Some(format!("{recent}|{recent}|{recent}|{id}")), "plancher non lu : la bande ne descend pas");
                assert_eq!(rbr_n_dim(&conn, b, "200"), 0, "plancher non lu : rien n'est agrégé sous la bande");
            } else {
                assert_eq!(rbr_meta(&conn, META_DIM_ROLLUP_COV), Some(format!("{b}|{recent}|{recent}|{id}")), "contrôle : la bande descend au plancher lu");
                assert_eq!(rbr_n_dim(&conn, b, "200"), 1, "contrôle : la ligne est agrégée");
            }
        }
    }

    /// (m) GEL JURIDIQUE ACTIF (`HoldEnforce::Guard`, un gel sur une AUTRE source : il ne retient aucune ligne de la
    /// fixture) : pour `event`, `snapshot` et `alert`, le réglage écrit en BLOB -> aucune ligne de la famille n'est
    /// supprimée (sous `AQ4_EV_GUARD`, `AQ4_SNAP_GUARD`, `AQ4_ALERT_GUARD` : purgée au repli de 30/30/90 j). Contrôle : le
    /// réglage lisible à 365 -> `moyen` gardé, `ancien` purgé (la branche purge bien sous ce gel).
    #[test]
    fn rbr_un_reglage_illisible_sous_gel_juridique_ne_purge_pas_sa_famille() {
        let _env = VERROU_ENV_PROCESSUS.read(); // retention_run lit cfg()
        let mut jugees = 0;
        for cle in ["retention_days", "snapshot_days", "alert_days"] {
            for lisible in [false, true] {
                let (st, _p) = sp_state(&format!("rbr-m-{cle}-{lisible}"));
                {
                    let conn = st.db.lock();
                    rbr_retention_fixture(&conn, now());
                    conn.execute("INSERT INTO legal_hold(name,scope_source,active) VALUES('rbr-gel','rbr-ailleurs',1)", []).unwrap();
                    assert!(
                        matches!(crate::governance::legal_hold_enforcement(&conn), crate::governance::HoldEnforce::Guard(_)),
                        "prémisse : gel actif, branche Guard"
                    );
                    let valeur = if lisible { rusqlite::types::Value::Text("365".into()) } else { rusqlite::types::Value::Blob(vec![0]) };
                    rbr_pose_le_reglage(&conn, cle, valeur);
                }
                retention_run(&st.db);
                let conn = st.db.lock();
                let (moyen, ancien) = (rbr_restantes(&conn, cle, "moyen"), rbr_restantes(&conn, cle, "ancien"));
                let (attendu_moyen, attendu_ancien) = if lisible { (1, 0) } else { (1, 1) };
                assert_eq!(moyen, vec![attendu_moyen; moyen.len()], "({cle}, lisible={lisible}) sous gel, âge moyen");
                assert_eq!(ancien, vec![attendu_ancien; ancien.len()], "({cle}, lisible={lisible}) sous gel, âge ancien");
                jugees += 1;
            }
        }
        assert_eq!(jugees, 6, "trois familles, deux régimes");
    }

    /// (n) UNE VALEUR PRÉSENTE MAIS NON ENTIÈRE est illisible, pas absente (la sonde de la vérification de la vague AQ :
    /// « 365.0 » écrit, une ligne de 200 j purgée au défaut de 30 j) : la ligne de 200 j reste, un tick aveugle est compté
    /// sous la cause d'analyse, la fenêtre lue est `None` (sous `AQ4_NON_ENTIER_DEFAUT`, la forme d'avant : purgée, rien
    /// compté, `Some(30)`). Contrôles : un texte vide est illisible aussi ; une ligne absente rend le défaut ; « 365 »
    /// rend 365.
    #[test]
    fn rbr_un_reglage_texte_non_entier_est_illisible() {
        let _env = VERROU_ENV_PROCESSUS.read(); // retention_run et cfg_lu lisent l'environnement
        let cause = |brut: &str| {
            crate::rollups::cause_du_reglage_de_retention_illisible(&format!("valeur écrite non entière : {}", brut.parse::<i64>().unwrap_err()))
        };
        let (st, _p) = sp_state("rbr-n-non-entier");
        let n = now();
        {
            let conn = st.db.lock();
            conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent','rbr-200j','')", params![n - 200 * JOUR]).unwrap();
            rbr_pose_le_reglage(&conn, "retention_days", rusqlite::types::Value::Text("365.0".into()));
        }
        let avant = ticks_aveugles_de_ce_fil::compte("retention_days", &cause("365.0"));
        retention_run(&st.db);
        let apres = ticks_aveugles_de_ce_fil::compte("retention_days", &cause("365.0"));
        let conn = st.db.lock();
        let restantes: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE message='rbr-200j'", [], |r| r.get(0)).unwrap();
        assert_eq!(restantes, 1, "« 365.0 » écrit : la ligne de 200 j n'est pas purgée au défaut");
        assert_eq!(apres - avant, 1, "« 365.0 » écrit : un tick aveugle sous la cause d'analyse");
        let conf: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        assert_eq!(crate::rollups::fenetre_de_retention_lue(&conn, &conf, "retention_days"), None, "« 365.0 » : aucune fenêtre");
        let mut controles = 0;
        for (valeur, attendu) in [(Some(""), None), (None, Some(30)), (Some("365"), Some(365))] {
            match valeur {
                Some(v) => rbr_pose_le_reglage(&conn, "retention_days", rusqlite::types::Value::Text(v.into())),
                None => {
                    conn.execute("DELETE FROM setting WHERE scope='global' AND key='retention_days'", []).unwrap();
                }
            }
            assert_eq!(crate::rollups::fenetre_de_retention_lue(&conn, &conf, "retention_days"), attendu, "contrôle {valeur:?}");
            controles += 1;
        }
        assert_eq!(controles, 3, "les trois contrôles joués");
    }

    /// (o) La purge de reconstruction d'`event_rollup` REFUSÉE : la bande n'est pas ré-agrégée (la ligne périmée reste),
    /// la couverture n'est PAS publiée (sous `AQ4_ER_PURGE_AVALEE`, la forme d'avant : publiée sur des orphelins), la
    /// fenêtre chaude est servie. Contrôle : sans refus, couverture publiée.
    #[test]
    fn rbr_une_purge_de_reconstruction_refusee_ne_publie_pas_la_couverture() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rbr_recent();
        let bucket_chaud = (now() - 10) / 3600 * 3600;
        for refuse in [false, true] {
            let (st, _p) = sp_state(&format!("rbr-o-{refuse}"));
            let conn = st.db.lock();
            let i = rbr_fixture(&conn, "absents", recent);
            let refus = refuse.then(|| rbr_refuser_la_purge_d_event_rollup(&conn));
            rollup_events(&conn);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert!(rbr_n(&conn, bucket_chaud) >= 1, "({refuse}) la fenêtre chaude reste servie");
            if let Some(refus) = refus {
                assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la purge de reconstruction est refusée une fois");
                assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), None, "purge refusée : aucune couverture publiée");
                assert_eq!(rbr_n_perime(&conn, i.b_vivant), 7, "purge refusée : la bande n'est pas ré-agrégée par-dessus");
            } else {
                assert_eq!(rbr_meta(&conn, META_ROLLUP_COV_ID), Some(rbr_max_id(&conn).to_string()), "contrôle : couverture publiée");
                assert_eq!(rbr_n_perime(&conn, i.b_vivant), 0, "contrôle : la bande est recomposée");
            }
        }
    }

    /// Pose `PLUME_COLD_TIER=1` et une racine froide possédée, et les retire à la destruction (même sur panique).
    #[cfg(feature = "cold_tier")]
    struct RbrFroid {
        _racine: crate::tmp_possede::TmpPossede,
    }

    #[cfg(feature = "cold_tier")]
    impl RbrFroid {
        fn poser() -> Self {
            let d = crate::tmp_possede::TmpPossede::neuf("rbr-froid");
            std::env::set_var("PLUME_COLD_TIER", "1");
            std::env::set_var("PLUME_COLD_DIR", d.to_string_lossy().to_string());
            std::env::remove_var("PLUME_COLD_RETENTION_DAYS");
            RbrFroid { _racine: d }
        }
    }

    #[cfg(feature = "cold_tier")]
    impl Drop for RbrFroid {
        fn drop(&mut self) {
            std::env::remove_var("PLUME_COLD_TIER");
            std::env::remove_var("PLUME_COLD_DIR");
        }
    }

    /// (p) TIER FROID ACTIF (`--features cold_tier`, `PLUME_COLD_TIER=1`), `retention_days` écrit en BLOB : la passe de
    /// vieillissement ne tourne pas (aucun point `plume_cold_aging_ok` publié ; sous `AQ4_COLD_AGE_REPLI`, elle tourne sur
    /// un repli de 30 j) et l'horizon étendu de la purge d'`event` n'est pas calculé (la ligne de 400 j reste ; sous
    /// `AQ4_COLD_CUTOFF_REPLI`, purgée à `cold_retention_days(30)`). Contrôle : `retention_days` lisible à 30 -> la passe
    /// publie son point, la ligne de 400 j est purgée.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn rbr_tier_froid_un_reglage_illisible_ne_vieillit_ni_ne_purge() {
        let _env = VERROU_ENV_PROCESSUS.write(); // l'environnement du processus est modifié
        let _froid = RbrFroid::poser();
        for lisible in [false, true] {
            let (st, _p) = sp_state(&format!("rbr-p-{lisible}"));
            {
                let conn = st.db.lock();
                conn.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'agent','rbr-400j','')", params![now() - 400 * JOUR]).unwrap();
                let valeur = if lisible { rusqlite::types::Value::Text("30".into()) } else { rusqlite::types::Value::Blob(vec![0]) };
                rbr_pose_le_reglage(&conn, "retention_days", valeur);
            }
            retention_run(&st.db);
            let conn = st.db.lock();
            let points: i64 = conn
                .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", params![crate::vieillissement_serie::NOM_OK], |r| r.get(0))
                .unwrap();
            let restantes: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE message='rbr-400j'", [], |r| r.get(0)).unwrap();
            if lisible {
                assert!(points >= 1, "contrôle : réglage lisible, la passe de vieillissement publie son point ({points})");
                assert_eq!(restantes, 0, "contrôle : réglage lisible, la ligne de 400 j est purgée à l'horizon froid");
            } else {
                assert_eq!(points, 0, "réglage illisible : la passe de vieillissement ne tourne pas sur un repli");
                assert_eq!(restantes, 1, "réglage illisible : l'horizon étendu n'est pas calculé sur un repli, la ligne reste");
            }
        }
    }
}
