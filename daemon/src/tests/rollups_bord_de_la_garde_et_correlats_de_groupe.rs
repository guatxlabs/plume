// =====================================================================================
// `P10.32-a` (hors `handlers/` : `rollups.rs`) — LE BORD DE LA GARDE D'UN GROUPE PARTIELLEMENT PURGÉ ET LES CORRÉLATS QUI
// DÉCIDENT (`bucket` de l'exclusion d'`event_rollup`, `source` de la garde et de l'exclusion d'`event_dim_rollup`).
//
// CE QUE LES TÉMOINS DE `rollups_groupe_partiellement_purge_et_bans_expires.rs` LAISSAIENT OUVERT (vérification de la
// vague BB) : tous les groupes gardés d'`event_rollup` y avaient un déficit d'au moins deux lignes — une garde décalée d'une
// ligne (`SUM(n) > c + 1`) restait verte ; aucun jeu ne portait deux sources qui partagent un nom de dimension dans le même
// bucket — retirer `source` de la garde ou de l'exclusion d'`event_dim_rollup` restait vert, alors que `path`, `user`,
// `action`, `vhost` et `ns` sont partagés par les sources par défaut ; aucun jeu ne portait une même source dans deux
// buckets de la bande, l'un gardé, l'autre recomposé — retirer `bucket` de l'exclusion d'`event_rollup` restait vert.
//
// DONNÉES RÉELLES : la purge partielle est faite par le VRAI plafond d'index (`index_policy` de `prod`, `max_rows`), joué
// par `retention_run` ; la reconstruction est déclenchée en retirant la couverture publiée (celle d'`event_rollup` ou celle
// par dimension) ; les dimensions sont celles des sources par défaut (`web` : status, vhost, path ; `dataaccess` : user,
// action, path).
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable d'environnement de mutation sous `cfg!(test)`, retirées du source avant le
// commit) :
//  * « BC4_ER_BORD » (garde d'`event_rollup` en `HAVING SUM(u.n) > g.c + 1`) : (a) ;
//  * « BC4_ER_EXCLUSION_SANS_BUCKET » (exclusion de l'INSERT d'`event_rollup` sans `u.bucket = …`) : (b) ;
//  * « BC4_DIM_EXCLUSION_SANS_SOURCE » (exclusion de l'INSERT par dimension sans `u.source = '{source}'`) : (c) ;
//  * « BC4_DIM_GARDE_SANS_SOURCE » (garde d'`event_dim_rollup` sans `u.source = g.s`) : (d).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les limites écrites dans `rollups.rs` (ligne tardive dans un groupe gardé,
// compensation par des tardives) ; horloge reculée sous le watermark (limite écrite) ; lecture d'`event` non couvrante
// sur la bande (performance, aucun index ne porte `source`/`env_id` avec `ts`).
// =====================================================================================
mod rollups_bord_de_la_garde_et_correlats_de_groupe {
    use super::*;
    use crate::rollup_coverage::{META_DIM_ROLLUP_COV, META_ROLLUP_COV_ID};

    const JOUR: i64 = 86400;
    const BC4_PERIME: &str = "bc4-perime";

    fn bc4_event(conn: &rusqlite::Connection, ts: i64, source: &str) {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'bc4',?2,1,'m')", params![ts, source]).unwrap();
    }

    fn bc4_web(conn: &rusqlite::Connection, ts: i64) {
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'bc4','web',1,'m',?2)",
            params![ts, "{\"status\":\"200\",\"vhost\":\"a\",\"path\":\"/p\"}"],
        )
        .unwrap();
    }

    fn bc4_dataaccess(conn: &rusqlite::Connection, ts: i64) {
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'bc4','dataaccess',1,'m',?2)",
            params![ts, "{\"user\":\"u1\",\"action\":\"read\",\"path\":\"/d\"}"],
        )
        .unwrap();
    }

    /// (somme, part périmée) d'un groupe (bucket, source, prod) d'`event_rollup`.
    fn bc4_groupe(conn: &rusqlite::Connection, bucket: i64, source: &str) -> (i64, i64) {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0), COALESCE(SUM(CASE WHEN host=?3 THEN n ELSE 0 END),0) \
             FROM event_rollup WHERE bucket=?1 AND source=?2 AND env_id='prod'",
            params![bucket, source, BC4_PERIME],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    fn bc4_lignes_d_event(conn: &rusqlite::Connection, bucket: i64, source: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM event WHERE ts>=?1 AND ts<?1+3600 AND source=?2 AND env_id='prod'",
            params![bucket, source],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn bc4_plafond_de_prod(conn: &rusqlite::Connection, max_rows: i64) {
        conn.execute(
            "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES('prod',0,?1,0,1) \
             ON CONFLICT(name) DO UPDATE SET retention_days=0, max_rows=excluded.max_rows, max_bytes=0, enabled=1",
            params![max_rows],
        )
        .unwrap();
    }

    /// Image ordonnée (dim, val, n) d'un groupe (bucket, source, prod) d'`event_dim_rollup`, restes vides (`n = 0`) omis.
    fn bc4_image_dim(conn: &rusqlite::Connection, bucket: i64, source: &str) -> Vec<(String, String, i64)> {
        let mut st = conn
            .prepare("SELECT dim, val, n FROM event_dim_rollup WHERE bucket=?1 AND source=?2 AND env_id='prod' AND n>0 ORDER BY dim, val")
            .unwrap();
        st.query_map(params![bucket, source], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    }

    fn bc4_l(dim: &str, val: &str, n: i64) -> (String, String, i64) {
        (dim.to_string(), val.to_string(), n)
    }

    fn bc4_image_web() -> Vec<(String, String, i64)> {
        vec![bc4_l("path", "/p", 2), bc4_l("status", "200", 2), bc4_l("vhost", "a", 2)]
    }

    fn bc4_image_dataaccess() -> Vec<(String, String, i64)> {
        vec![bc4_l("action", "read", 2), bc4_l("path", "/d", 2), bc4_l("user", "u1", 2)]
    }

    /// (a) LE BORD : UN GROUPE AUQUEL IL MANQUE UNE SEULE LIGNE EST GARDÉ, UN GROUPE À COMPTE ÉGAL EST RECOMPOSÉ. Le bucket B
    /// (deux jours) porte `sshd` (cinq lignes, les plus vieilles) et `bc4-egal` (deux, marquées périmées après le passage
    /// nominal), plus une ligne chaude. Le plafond `prod` à sept lignes retire la plus vieille de `sshd` (prémisse : il en
    /// reste 4). Couverture retirée, reconstruction : `sshd` reste à 5, sa ligne intacte (sous « BC4_ER_BORD » : 5 n'est pas
    /// > 4 + 1, le groupe est récrit à 4) ; `bc4-egal` est recomposé, sans ligne périmée.
    #[test]
    fn bc4_un_groupe_auquel_il_manque_une_seule_ligne_est_garde() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        let recent = heure_ronde_precedente_hors_de_la_fin_d_heure();
        let b = recent - 2 * JOUR;
        let (st, _p) = sp_state("bc4-a-bord");
        {
            let conn = st.db.lock();
            for k in 0..5 {
                bc4_event(&conn, b + 100 + k, "sshd");
            }
            bc4_event(&conn, b + 200, "bc4-egal");
            bc4_event(&conn, b + 201, "bc4-egal");
            bc4_event(&conn, now() - 10, "bc4-chaud");
            rollup_events(&conn);
            assert_eq!((bc4_groupe(&conn, b, "sshd"), bc4_groupe(&conn, b, "bc4-egal")), ((5, 0), (2, 0)), "prémisse : passage nominal");
            conn.execute("UPDATE event_rollup SET host=?1 WHERE source='bc4-egal'", params![BC4_PERIME]).unwrap();
            bc4_plafond_de_prod(&conn, 7);
        }
        retention_run(&st.db);
        let conn = st.db.lock();
        assert_eq!(bc4_lignes_d_event(&conn, b, "sshd"), 4, "prémisse : le plafond d'index a retiré UNE ligne de sshd");
        assert_eq!(bc4_lignes_d_event(&conn, b, "bc4-egal"), 2, "prémisse : bc4-egal intact dans event");
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        rollup_events(&conn);
        let ligne: (i64, String) = conn
            .query_row("SELECT n, host FROM event_rollup WHERE bucket=?1 AND source='sshd'", params![b], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(ligne, (5, "bc4".to_string()), "déficit d'une seule ligne (4 contre 5) : le groupe est gardé, sa ligne intacte");
        assert_eq!(bc4_groupe(&conn, b, "bc4-egal"), (2, 0), "compte égal : recomposé, la ligne périmée est partie");
    }

    /// (b) LE CORRÉLAT `bucket` DE L'EXCLUSION D'`event_rollup`. `sshd` porte cinq lignes dans B1 (deux jours, les plus
    /// vieilles) et deux dans B2 = B1 + 1 h (marquées périmées après le passage nominal). Le plafond `prod` à six lignes
    /// retire les deux plus vieilles de B1 (prémisse : il en reste 3, B2 intact). Couverture retirée, reconstruction : B1
    /// gardé à 5 ; B2 (compte égal) purgé puis RÉCRIT à 2, sans ligne périmée. Sous « BC4_ER_EXCLUSION_SANS_BUCKET »
    /// (l'INSERT épargne toute ligne dont la source a une ligne de rollup dans N'IMPORTE QUEL bucket), B2 est purgé et
    /// jamais récrit : 0 — perte de données.
    #[test]
    fn bc4_l_exclusion_d_event_rollup_est_par_bucket() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        let recent = heure_ronde_precedente_hors_de_la_fin_d_heure();
        let b1 = recent - 2 * JOUR;
        let b2 = b1 + 3600;
        let (st, _p) = sp_state("bc4-b-bucket");
        {
            let conn = st.db.lock();
            for k in 0..5 {
                bc4_event(&conn, b1 + 100 + k, "sshd");
            }
            bc4_event(&conn, b2 + 100, "sshd");
            bc4_event(&conn, b2 + 101, "sshd");
            bc4_event(&conn, now() - 10, "bc4-chaud");
            rollup_events(&conn);
            assert_eq!((bc4_groupe(&conn, b1, "sshd"), bc4_groupe(&conn, b2, "sshd")), ((5, 0), (2, 0)), "prémisse : passage nominal");
            conn.execute("UPDATE event_rollup SET host=?1 WHERE source='sshd' AND bucket=?2", params![BC4_PERIME, b2]).unwrap();
            bc4_plafond_de_prod(&conn, 6);
        }
        retention_run(&st.db);
        let conn = st.db.lock();
        assert_eq!(bc4_lignes_d_event(&conn, b1, "sshd"), 3, "prémisse : le plafond d'index a retiré deux lignes de B1");
        assert_eq!(bc4_lignes_d_event(&conn, b2, "sshd"), 2, "prémisse : B2 intact dans event");
        assert_eq!(bc4_groupe(&conn, b2, "sshd"), (2, 2), "prémisse : la ligne de B2 est marquée périmée");
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        rollup_events(&conn);
        assert_eq!(bc4_groupe(&conn, b1, "sshd"), (5, 0), "B1 partiellement purgé : gardé à 5");
        assert_eq!(bc4_groupe(&conn, b2, "sshd"), (2, 0), "B2 à compte égal : récrit, malgré B1 gardé pour la même source");
    }

    /// (c) LE CORRÉLAT `source` DE L'EXCLUSION PAR DIMENSION. `web` et `dataaccess` portent chacune deux lignes dans le même
    /// bucket (cinq heures) ; elles partagent la dimension `path`, et `web` est agrégée avant `dataaccess`. Premier passage :
    /// chaque source a toutes ses dimensions, `path` compris. Sous « BC4_DIM_EXCLUSION_SANS_SOURCE », la ligne `path` de
    /// `web` fait épargner celle de `dataaccess` : `dataaccess` perd `path`.
    #[test]
    fn bc4_une_dimension_partagee_est_ecrite_pour_chaque_source() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = heure_ronde_precedente_hors_de_la_fin_d_heure();
        let b = recent - 5 * 3600;
        let (st, _p) = sp_state("bc4-c-dim-partagee");
        let conn = st.db.lock();
        bc4_web(&conn, b + 100);
        bc4_web(&conn, b + 101);
        bc4_dataaccess(&conn, b + 200);
        bc4_dataaccess(&conn, b + 201);
        rollup_events(&conn);
        assert_eq!(bc4_image_dim(&conn, b, "web"), bc4_image_web(), "web : ses trois dimensions");
        assert_eq!(bc4_image_dim(&conn, b, "dataaccess"), bc4_image_dataaccess(), "dataaccess : ses trois dimensions, path compris malgré celui de web");
    }

    /// (d) LE CORRÉLAT `source` DE LA GARDE PAR DIMENSION. Même jeu ; après le premier passage, la ligne `user` de
    /// `dataaccess` est marquée périmée (même compte). Couverture par dimension retirée, reconstruction : le groupe
    /// (B, `dataaccess`) est à compte égal sur chaque dimension (2 contre 2) : recomposé, la valeur périmée est partie. Sous
    /// « BC4_DIM_GARDE_SANS_SOURCE », la somme de `path` additionne `web` et `dataaccess` (4 > 2) : le groupe est gardé à
    /// tort et la valeur périmée reste.
    #[test]
    fn bc4_la_garde_par_dimension_ne_somme_pas_les_sources() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = heure_ronde_precedente_hors_de_la_fin_d_heure();
        let b = recent - 5 * 3600;
        let (st, _p) = sp_state("bc4-d-garde-source");
        let conn = st.db.lock();
        bc4_web(&conn, b + 100);
        bc4_web(&conn, b + 101);
        bc4_dataaccess(&conn, b + 200);
        bc4_dataaccess(&conn, b + 201);
        rollup_events(&conn);
        assert_eq!(bc4_image_dim(&conn, b, "dataaccess"), bc4_image_dataaccess(), "prémisse : dataaccess agrégée");
        conn.execute("UPDATE event_dim_rollup SET val=?1 WHERE source='dataaccess' AND dim='user'", params![BC4_PERIME]).unwrap();
        assert_eq!(
            bc4_image_dim(&conn, b, "dataaccess"),
            vec![bc4_l("action", "read", 2), bc4_l("path", "/d", 2), bc4_l("user", BC4_PERIME, 2)],
            "prémisse : la valeur user de dataaccess est marquée périmée"
        );
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_DIM_ROLLUP_COV]).unwrap();
        rollup_events(&conn);
        assert_eq!(bc4_image_dim(&conn, b, "dataaccess"), bc4_image_dataaccess(), "compte égal par dimension : recomposé, la valeur périmée est partie");
        assert_eq!(bc4_image_dim(&conn, b, "web"), bc4_image_web(), "web : recomposé à l'identique");
    }
}
