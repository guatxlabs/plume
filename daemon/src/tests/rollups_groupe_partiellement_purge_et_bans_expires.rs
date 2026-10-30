// =====================================================================================
// `P10.32-a` (hors `handlers/` : `rollups.rs`) — UN GROUPE PARTIELLEMENT PURGÉ CÔTÉ `event` N'EST PLUS RÉÉCRIT PLUS PETIT
// PAR LA RECONSTRUCTION DES ROLLUPS ; LA PURGE OPTIONNELLE DES BANS EXPIRÉS N'IGNORE PLUS SON ISSUE.
//
// LES DÉFAUTS, LUS SUR 50aab3e6 :
//  * `purge_des_buckets_resservis_sql` purgeait tout groupe (bucket, source, env_id) dont `event` portait AU MOINS UNE
//    ligne sous la borne, et l'INSERT de reconstruction le récrivait sur ce qui restait. Un plafond d'index
//    (`index_policy.max_rows`, `retention_apply_caps`) ne purge que `event` : le bucket à la frontière du plafond perd une
//    partie de ses lignes, le rollup les garde ; à la reconstruction suivante (couverture absente, watermark absent, ou
//    ligne tardive sous le watermark), le groupe passait de 5 à 2 — l'histoire que seul le rollup gardait, effacée. Même
//    défaut dans les tranches d'`event_dim_rollup` ;
//  * `materialize_banned_ip` : `let _ = DELETE FROM banned_ip WHERE last_seen < ?` (`PLUME_BANNED_IP_RETENTION` > 0) —
//    un refus laissait les bans expirés en place, sans compte ni journal.
//
// DÉSORMAIS : un groupe dont `event` porte MOINS de lignes que le rollup n'en compte (par dimension pour
// `event_dim_rollup`, `<dim>` et son reste `!<dim>` ensemble) est GARDÉ — ni purgé, ni récrit (l'INSERT l'épargne) ; à
// compte égal ou supérieur, il est recomposé comme avant. Une purge des bans expirés refusée est comptée sous « rollup :
// purge des bans expirés de banned_ip : purge refusée » (lue par `poser_les_gestes_de_fond_non_valides`, la fonction que
// `/api/system/metrics` appelle) et dite au journal avec la cause du moteur.
//
// DONNÉES RÉELLES : la purge partielle est faite par le VRAI plafond d'index (`index_policy` de `prod`, `max_rows`), joué
// par `retention_run` ; les trois déclencheurs de reconstruction sont joués ; le refus de la purge des bans est fabriqué
// par autorisateur SQLite (`DELETE` sur `banned_ip`). Journal lu sur le stderr d'un sous-processus, ligne ENTIÈRE.
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable d'environnement de mutation sous `cfg!(test)`, retirées du source avant le commit) :
//  * « BB4_ER_SANS_EXCES » (purge d'`event_rollup` sans la garde du groupe : la forme d'avant) : (a) ;
//  * « BB4_ER_INSERT_SANS_EXCLUSION » (INSERT d'`event_rollup` qui récrit les groupes gardés) : (a) ;
//  * « BB4_EXCES_LARGE » (`SUM(n) >= c` : un groupe à compte égal est gardé au lieu d'être recomposé) : (a), (b) ;
//  * « BB4_DIM_SANS_EXCES », « BB4_DIM_SANS_LTRIM » (compte par dimension brute, reste séparé),
//    « BB4_DIM_INSERT_SANS_EXCLUSION » : (b) ; « BB4_DIM_EXCLUSION_TOUTES_DIMS » (une dimension écrite fait épargner
//    les suivantes du même groupe) : (b), dès la première tranche ;
//  * « BB4_BANS_NON_COMPTE » : (c) ; « BB4_BANS_JOURNAL_MUET » : (d) ;
//  * « BB4_ER_GARDE_PAR_LIGNE » (garde d'`event_rollup` jugée ligne à ligne, sans somme) : (e) ;
//  * « BB4_ER_GARDE_SANS_ENV » (garde sans `env_id`) et « BB4_ER_EXCLUSION_SANS_ENV » (exclusion de l'INSERT sans
//    `env_id` : un groupe staging purgé n'est jamais récrit) : (f).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une ligne tardive arrivée dans un groupe GARDÉ n'y est pas ajoutée et la couverture
// la tient pour agrégée (limite écrite dans `rollups.rs`) ; COMPENSATION : un groupe partiellement purgé puis complété par
// des lignes tardives jusqu'à `c >= SUM(n)` n'est plus gardé et se recompose sur ce qui reste — le rollup ne descend
// jamais sous sa valeur, mais l'histoire purgée est perdue (groupe à 5, plafond qui en laisse 2, trois tardives : 5, et
// non 8 ; limite écrite dans `rollups.rs`, non témoignée) ; la purge explicite (`purge.rs`, `purge_rebuild_rollups`)
// efface et recompose ses buckets entiers, hors de ce lot ; horloge reculée (limite écrite) ; lecture d'`event` non
// couvrante (performance).
// =====================================================================================
mod rollups_groupe_partiellement_purge_et_bans_expires {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::rollup_coverage::{META_DIM_ROLLUP_COV, META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const JOUR: i64 = 86400;
    const BB4_CLE_BANS: &str = "rollup : purge des bans expirés de banned_ip";
    const BB4_COMPTE_BANS: &str = "geste de fond non validé rollup : purge des bans expirés de banned_ip : purge refusée";
    const BB4_CAUSE_BANS: &str = "purge refusée : not authorized";
    const BB4_LIGNE_BANS: &str =
        "[rollup] WARN purge des bans expirés de banned_ip NON faite (not authorized) — bans expirés gardés, purge reprise au prochain passage";
    const BB4_RETENTION_DES_BANS: &str = "PLUME_BANNED_IP_RETENTION";
    const BB4_IP_EXPIREE: &str = "192.0.2.44";

    fn bb4_recent() -> i64 {
        heure_ronde_precedente_hors_de_la_fin_d_heure()
    }

    fn bb4_meta(conn: &rusqlite::Connection, cle: &str) -> Option<String> {
        conn.query_row("SELECT CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| r.get(0)).ok()
    }

    fn bb4_max_id(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap()
    }

    fn bb4_event(conn: &rusqlite::Connection, ts: i64, source: &str) -> i64 {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'bb4',?2,1,'m')", params![ts, source]).unwrap();
        conn.last_insert_rowid()
    }

    fn bb4_web(conn: &rusqlite::Connection, ts: i64, status: &str, vhost: &str, path: &str, env: &str) {
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,fields,env_id) VALUES(?1,'bb4','web',1,'m',?2,?3)",
            params![ts, format!("{{\"status\":\"{status}\",\"vhost\":\"{vhost}\",\"path\":\"{path}\"}}"), env],
        )
        .unwrap();
    }

    /// Le compte d'un groupe (bucket, source, env_id) d'`event_rollup`, et celui de ses lignes PÉRIMÉES (`host`).
    fn bb4_groupe(conn: &rusqlite::Connection, bucket: i64, source: &str) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1 AND source=?2 AND env_id='prod'",
            params![bucket, source],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn bb4_perime(conn: &rusqlite::Connection, bucket: i64, source: &str) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1 AND source=?2 AND host='bb4-perime'",
            params![bucket, source],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn bb4_lignes_d_event(conn: &rusqlite::Connection, bucket: i64, source: &str, env: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM event WHERE ts>=?1 AND ts<?1+3600 AND source=?2 AND env_id=?3",
            params![bucket, source, env],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Le plafond `max_rows` de l'index `prod`, posé dans `index_policy` (la ligne gérée existe peut-être déjà).
    fn bb4_plafond_de_prod(conn: &rusqlite::Connection, max_rows: i64) {
        conn.execute(
            "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,enabled) VALUES('prod',0,?1,0,1) \
             ON CONFLICT(name) DO UPDATE SET retention_days=0, max_rows=excluded.max_rows, max_bytes=0, enabled=1",
            params![max_rows],
        )
        .unwrap();
    }

    /// (a) `event_rollup`, les trois déclencheurs. Le bucket `B` (deux jours) porte trois groupes de `prod` : `sshd`
    /// (cinq lignes, les plus vieilles), `bb4-egal` (deux), `bb4-plus` (une) ; plus une ligne chaude. Un passage nominal
    /// les agrège (5, 2, 1) ; les lignes de `bb4-egal` sont marquées PÉRIMÉES (même compte). Le plafond d'index `prod`
    /// à six lignes, joué par `retention_run`, retire les trois plus vieilles de `sshd` (prémisse : il en reste 2). Une
    /// ligne tardive de `bb4-plus` arrive (au-dessus de la couverture). Après la reconstruction :
    ///  * `sshd` reste à 5, sa ligne intacte (sous « BB4_ER_SANS_EXCES » et « BB4_ER_INSERT_SANS_EXCLUSION » : 2) ;
    ///  * `bb4-egal` (compte égal) est RECOMPOSÉ : plus de ligne périmée (sous « BB4_EXCES_LARGE » : gardée) ;
    ///  * `bb4-plus` (compte supérieur) est recomposé à 2 ; watermark et couverture publiés.
    #[test]
    fn bb4_un_groupe_partiellement_purge_par_le_plafond_d_index_est_garde() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        let recent = bb4_recent();
        let b = recent - 2 * JOUR;
        for cas in ["couverture-absente", "watermark-absent", "bande-sale"] {
            let (st, _p) = sp_state(&format!("bb4-a-{cas}"));
            {
                let conn = st.db.lock();
                for k in 0..5 {
                    bb4_event(&conn, b + 100 + k, "sshd");
                }
                bb4_event(&conn, b + 200, "bb4-egal");
                bb4_event(&conn, b + 201, "bb4-egal");
                bb4_event(&conn, b + 250, "bb4-plus");
                bb4_event(&conn, now() - 10, "bb4-chaud");
                rollup_events(&conn);
                assert_eq!(
                    (bb4_groupe(&conn, b, "sshd"), bb4_groupe(&conn, b, "bb4-egal"), bb4_groupe(&conn, b, "bb4-plus")),
                    (5, 2, 1),
                    "({cas}) prémisse : le passage nominal agrège les trois groupes"
                );
                conn.execute("UPDATE event_rollup SET host='bb4-perime' WHERE source='bb4-egal'", []).unwrap();
                bb4_plafond_de_prod(&conn, 6);
            }
            retention_run(&st.db);
            let conn = st.db.lock();
            assert_eq!(bb4_lignes_d_event(&conn, b, "sshd", "prod"), 2, "({cas}) prémisse : le plafond d'index a retiré trois lignes de sshd");
            assert_eq!(bb4_lignes_d_event(&conn, b, "bb4-egal", "prod"), 2, "({cas}) prémisse : bb4-egal intact dans event");
            assert_eq!(bb4_groupe(&conn, b, "sshd"), 5, "({cas}) prémisse : le plafond ne touche pas le rollup");
            let cov_avant: i64 = bb4_meta(&conn, META_ROLLUP_COV_ID).expect("prémisse : couverture publiée").parse().unwrap();
            let tardive = bb4_event(&conn, b + 300, "bb4-plus");
            assert!(tardive > cov_avant, "({cas}) prémisse : la ligne tardive est au-dessus de la couverture");
            match cas {
                "couverture-absente" => {
                    conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
                }
                "watermark-absent" => {
                    conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_WM]).unwrap();
                }
                _ => {} // la ligne tardive, sous le watermark, ouvre la bande sale
            }
            rollup_events(&conn);
            assert_eq!(bb4_groupe(&conn, b, "sshd"), 5, "({cas}) groupe partiellement purgé côté event : le rollup garde ses 5 lignes");
            let ligne: (i64, String) = conn
                .query_row("SELECT n, host FROM event_rollup WHERE bucket=?1 AND source='sshd'", params![b], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            assert_eq!(ligne, (5, "bb4".to_string()), "({cas}) la ligne du groupe gardé est intacte");
            assert_eq!(bb4_perime(&conn, b, "bb4-egal"), 0, "({cas}) groupe à compte égal : recomposé, la ligne périmée est partie");
            assert_eq!(bb4_groupe(&conn, b, "bb4-egal"), 2, "({cas}) groupe à compte égal : recomposé depuis event");
            assert_eq!(bb4_groupe(&conn, b, "bb4-plus"), 2, "({cas}) groupe à compte supérieur : recomposé avec la ligne tardive");
            assert_eq!(bb4_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "({cas}) watermark à recent");
            assert_eq!(bb4_meta(&conn, META_ROLLUP_COV_ID), Some(bb4_max_id(&conn).to_string()), "({cas}) couverture publiée à la borne");
        }
    }

    fn bb4_event_de(conn: &rusqlite::Connection, ts: i64, source: &str, host: &str, env: &str) {
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,env_id) VALUES(?1,?2,?3,1,'m',?4)",
            params![ts, host, source, env],
        )
        .unwrap();
    }

    /// Le compte d'un groupe (bucket, source, env) d'`event_rollup`, et celui de ses lignes marquées périmées.
    fn bb4_groupe_de(conn: &rusqlite::Connection, bucket: i64, source: &str, env: &str) -> (i64, i64) {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0), COALESCE(SUM(CASE WHEN host='bb4-perime' THEN n ELSE 0 END),0) \
             FROM event_rollup WHERE bucket=?1 AND source=?2 AND env_id=?3",
            params![bucket, source, env],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    /// (e) LE GROUPE EST JUGÉ SUR LA SOMME DE SES LIGNES. Le groupe (B, `sshd`, prod) porte TROIS lignes de rollup (hôtes
    /// `h1` : 2, `h2` : 2, `h3` : 1) ; le plafond `prod` à quatre lignes retire les deux de `h1` (prémisse : il en reste 3).
    /// Aucune ligne seule ne dépasse 3, leur somme (5) oui : après reconstruction (couverture retirée), le groupe garde ses
    /// trois lignes à l'identique (sous « BB4_ER_GARDE_PAR_LIGNE », garde jugée ligne à ligne : récrit à 3).
    #[test]
    fn bb4_un_groupe_de_plusieurs_lignes_est_juge_sur_leur_somme() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        let recent = bb4_recent();
        let b = recent - 2 * JOUR;
        let (st, _p) = sp_state("bb4-e-somme");
        let image = |conn: &rusqlite::Connection| -> Vec<(String, i64)> {
            let mut q = conn.prepare("SELECT host, n FROM event_rollup WHERE bucket=?1 AND source='sshd' ORDER BY host").unwrap();
            q.query_map(params![b], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
        };
        let attendu = vec![("h1".to_string(), 2), ("h2".to_string(), 2), ("h3".to_string(), 1)];
        {
            let conn = st.db.lock();
            for (k, h) in ["h1", "h1", "h2", "h2", "h3"].iter().enumerate() {
                bb4_event_de(&conn, b + 100 + k as i64, "sshd", h, "prod");
            }
            bb4_event(&conn, now() - 10, "bb4-chaud");
            rollup_events(&conn);
            assert_eq!(image(&conn), attendu, "prémisse : trois lignes de rollup dans le groupe");
            bb4_plafond_de_prod(&conn, 4);
        }
        retention_run(&st.db);
        let conn = st.db.lock();
        assert_eq!(bb4_lignes_d_event(&conn, b, "sshd", "prod"), 3, "prémisse : le plafond d'index a retiré les deux lignes de h1");
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        rollup_events(&conn);
        assert_eq!(image(&conn), attendu, "groupe jugé sur sa somme (5 > 3) : ses trois lignes gardées à l'identique");
        assert_eq!(bb4_meta(&conn, META_ROLLUP_COV_ID), Some(bb4_max_id(&conn).to_string()), "couverture publiée à la borne");
    }

    /// (f) LA GARDE ET L'EXCLUSION SONT PAR ENVIRONNEMENT. Le bucket B porte, pour `sshd`, cinq lignes de prod et deux de
    /// staging ; pour `bb4-egal`, deux de prod et deux de staging. Le plafond `prod` à cinq lignes retire trois lignes de
    /// `sshd` en prod (prémisse : il en reste 2, staging intact). Les lignes de rollup de `bb4-egal` prod et de `sshd`
    /// staging sont marquées périmées (même compte). Après reconstruction (couverture retirée) :
    ///  * `sshd` prod GARDÉ à 5 ;
    ///  * `bb4-egal` prod (compte égal) RECOMPOSÉ : sous « BB4_ER_GARDE_SANS_ENV » (le staging du même groupe entre dans
    ///    la somme), il est gardé et sa ligne périmée reste ;
    ///  * `sshd` staging (compte égal) purgé puis RÉCRIT à 2 : sous « BB4_ER_EXCLUSION_SANS_ENV » (l'INSERT épargne tout
    ///    environnement dont prod est gardé), il est purgé et jamais récrit (0) — perte de données.
    #[test]
    fn bb4_la_garde_et_l_exclusion_d_event_rollup_sont_par_environnement() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et retention_run lisent cfg()
        let recent = bb4_recent();
        let b = recent - 2 * JOUR;
        let (st, _p) = sp_state("bb4-f-env");
        {
            let conn = st.db.lock();
            for k in 0..5 {
                bb4_event_de(&conn, b + 100 + k, "sshd", "bb4", "prod");
            }
            bb4_event_de(&conn, b + 150, "sshd", "bb4", "staging");
            bb4_event_de(&conn, b + 151, "sshd", "bb4", "staging");
            bb4_event_de(&conn, b + 200, "bb4-egal", "bb4", "prod");
            bb4_event_de(&conn, b + 201, "bb4-egal", "bb4", "prod");
            bb4_event_de(&conn, b + 250, "bb4-egal", "bb4", "staging");
            bb4_event_de(&conn, b + 251, "bb4-egal", "bb4", "staging");
            bb4_event(&conn, now() - 10, "bb4-chaud");
            rollup_events(&conn);
            assert_eq!(
                (
                    bb4_groupe_de(&conn, b, "sshd", "prod"),
                    bb4_groupe_de(&conn, b, "sshd", "staging"),
                    bb4_groupe_de(&conn, b, "bb4-egal", "prod"),
                    bb4_groupe_de(&conn, b, "bb4-egal", "staging")
                ),
                ((5, 0), (2, 0), (2, 0), (2, 0)),
                "prémisse : le passage nominal agrège les quatre groupes"
            );
            conn.execute(
                "UPDATE event_rollup SET host='bb4-perime' WHERE (source='bb4-egal' AND env_id='prod') OR (source='sshd' AND env_id='staging')",
                [],
            )
            .unwrap();
            bb4_plafond_de_prod(&conn, 5);
        }
        retention_run(&st.db);
        let conn = st.db.lock();
        assert_eq!(bb4_lignes_d_event(&conn, b, "sshd", "prod"), 2, "prémisse : le plafond d'index a retiré trois lignes de sshd en prod");
        assert_eq!(bb4_lignes_d_event(&conn, b, "sshd", "staging"), 2, "prémisse : staging intact dans event");
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
        rollup_events(&conn);
        assert_eq!(bb4_groupe_de(&conn, b, "sshd", "prod"), (5, 0), "sshd prod partiellement purgé : gardé à 5");
        assert_eq!(bb4_groupe_de(&conn, b, "bb4-egal", "prod"), (2, 0), "bb4-egal prod à compte égal : recomposé, malgré le staging du même groupe");
        assert_eq!(bb4_groupe_de(&conn, b, "sshd", "staging"), (2, 0), "sshd staging à compte égal : récrit, malgré le prod gardé du même groupe");
        assert_eq!(bb4_groupe_de(&conn, b, "bb4-egal", "staging"), (2, 0), "bb4-egal staging : recomposé");
    }

    /// Image ordonnée des lignes d'un groupe (bucket, `web`, env) d'`event_dim_rollup`.
    fn bb4_image_dim(conn: &rusqlite::Connection, bucket: i64, env: &str) -> Vec<(String, String, i64)> {
        let mut st = conn
            .prepare("SELECT dim, val, n FROM event_dim_rollup WHERE bucket=?1 AND source='web' AND env_id=?2 ORDER BY dim, val")
            .unwrap();
        st.query_map(params![bucket, env], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
    }

    fn bb4_l(dim: &str, val: &str, n: i64) -> (String, String, i64) {
        (dim.to_string(), val.to_string(), n)
    }

    /// (b) `event_dim_rollup`, plafond top-N à 1 (`PLUME_ROLLUP_DIM_TOPN`) : le groupe (B, web, prod) porte cinq lignes
    /// (trois `200/a//p`, deux `404/b//q`) ; chaque dimension garde sa valeur de tête (3) et met le reste (2) sous `!<dim>`
    /// — AUCUNE dimension brute ne dépasse 4. Le groupe (B, web, staging) porte une ligne (`201/c//s`), sa valeur `status`
    /// marquée périmée (même compte). Le plafond `prod` à cinq lignes retire la plus vieille (prémisse : il en reste 4).
    /// Couverture par dimension retirée, reconstruction : le groupe de prod est GARDÉ à l'identique (sous
    /// « BB4_DIM_SANS_EXCES », « BB4_DIM_SANS_LTRIM », « BB4_DIM_INSERT_SANS_EXCLUSION » : récrit sur quatre lignes) ; le
    /// groupe de staging est recomposé, ses TROIS dimensions présentes (sous « BB4_EXCES_LARGE » : la valeur périmée
    /// reste) ; la bande est publiée. Sous « BB4_DIM_EXCLUSION_TOUTES_DIMS », la première tranche (prémisse) n'écrit déjà
    /// que `status` : `vhost` et `path` manquent.
    #[test]
    fn bb4_un_groupe_partiellement_purge_garde_ses_dimensions_et_les_autres_sont_recomposees() {
        let _env = VERROU_ENV_PROCESSUS.write(); // pose PLUME_ROLLUP_DIM_TOPN
        let _topn = ReglageBackupPose::neuf("PLUME_ROLLUP_DIM_TOPN", "1");
        let recent = bb4_recent();
        let b = recent - 5 * 3600;
        let (st, _p) = sp_state("bb4-b-dim");
        let image_prod;
        {
            let conn = st.db.lock();
            bb4_web(&conn, b + 100, "200", "a", "/p", "prod");
            bb4_web(&conn, b + 101, "200", "a", "/p", "prod");
            bb4_web(&conn, b + 102, "200", "a", "/p", "prod");
            bb4_web(&conn, b + 103, "404", "b", "/q", "prod");
            bb4_web(&conn, b + 104, "404", "b", "/q", "prod");
            bb4_web(&conn, b + 150, "201", "c", "/s", "staging");
            bb4_web(&conn, now() - 10, "500", "z", "/z", "prod");
            rollup_events(&conn);
            image_prod = bb4_image_dim(&conn, b, "prod");
            let attendu_prod = vec![
                bb4_l("!path", "", 2),
                bb4_l("!status", "", 2),
                bb4_l("!vhost", "", 2),
                bb4_l("path", "/p", 3),
                bb4_l("status", "200", 3),
                bb4_l("vhost", "a", 3),
            ];
            assert_eq!(image_prod, attendu_prod, "prémisse : top-1 par dimension, reste sous !<dim>");
            conn.execute("UPDATE event_dim_rollup SET val='bb4-perime' WHERE env_id='staging' AND dim='status'", []).unwrap();
            bb4_plafond_de_prod(&conn, 5);
        }
        retention_run(&st.db);
        let conn = st.db.lock();
        assert_eq!(bb4_lignes_d_event(&conn, b, "web", "prod"), 4, "prémisse : le plafond d'index a retiré une ligne de web en prod");
        conn.execute("DELETE FROM meta WHERE key=?1", params![META_DIM_ROLLUP_COV]).unwrap();
        rollup_events(&conn);
        assert_eq!(bb4_image_dim(&conn, b, "prod"), image_prod, "groupe partiellement purgé côté event : toutes ses dimensions gardées à l'identique");
        let attendu_staging = vec![
            bb4_l("!path", "", 0),
            bb4_l("!status", "", 0),
            bb4_l("!vhost", "", 0),
            bb4_l("path", "/s", 1),
            bb4_l("status", "201", 1),
            bb4_l("vhost", "c", 1),
        ];
        assert_eq!(bb4_image_dim(&conn, b, "staging"), attendu_staging, "groupe à compte égal : recomposé, chaque dimension écrite");
        let id = bb4_max_id(&conn);
        assert_eq!(bb4_meta(&conn, META_DIM_ROLLUP_COV), Some(format!("{b}|{recent}|{recent}|{id}")), "la bande est publiée jusqu'au plancher");
    }

    fn bb4_ban_expire(conn: &rusqlite::Connection) {
        let vieux = now() - 10 * JOUR;
        conn.execute(
            "INSERT INTO banned_ip(src_ip,source,label,first_seen,last_seen) VALUES(?1,'fail2ban','sshd',?2,?2)",
            params![BB4_IP_EXPIREE, vieux],
        )
        .unwrap();
    }

    fn bb4_ban_present(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM banned_ip WHERE src_ip=?1", params![BB4_IP_EXPIREE], |r| r.get(0)).unwrap()
    }

    /// Autorisateur qui refuse tout `DELETE` sur `banned_ip` (la purge des bans expirés est le seul de `materialize_banned_ip`).
    fn bb4_refuser_la_purge_des_bans(conn: &rusqlite::Connection) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "banned_ip" } => {
                compteur.fetch_add(1, Ordering::Relaxed);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// La valeur de PRODUCTION du compte, telle que `/api/system/metrics` la pose (`scheduler.gestes_de_fond_non_valides`).
    fn bb4_compte_de_production() -> (u64, Option<String>) {
        let mut scheduler = serde_json::Map::new();
        crate::comptes_de_transaction::poser_les_gestes_de_fond_non_valides(&mut scheduler);
        let geste = &scheduler["gestes_de_fond_non_valides"][BB4_CLE_BANS];
        (geste["n"].as_u64().unwrap_or(0), geste["derniere_cause"].as_str().map(str::to_string))
    }

    /// (c) Purge des bans expirés REFUSÉE (`PLUME_BANNED_IP_RETENTION` à un jour, ban vieux de dix ; que le ban reste est
    /// la prémisse de l'autorisateur, pas un constat) : le refus est compté UNE fois en production (n + 1, dernière cause « purge refusée : not authorized ») et sur la base
    /// visée (sous « BB4_BANS_NON_COMPTE » : 0). Contrôle : sans refus, le ban expiré part et rien n'est compté.
    #[test]
    fn bb4_une_purge_des_bans_expires_refusee_est_comptee() {
        let _env = VERROU_ENV_PROCESSUS.write(); // pose PLUME_BANNED_IP_RETENTION
        let _ret = ReglageBackupPose::neuf(BB4_RETENTION_DES_BANS, "86400");
        {
            let (st, _p) = sp_state("bb4-c-controle");
            let conn = st.db.lock();
            bb4_ban_expire(&conn);
            let (avant, _) = bb4_compte_de_production();
            materialize_banned_ip(&conn);
            assert_eq!(bb4_ban_present(&conn), 0, "contrôle : la purge passe, le ban expiré part");
            assert_eq!(bb4_compte_de_production().0, avant, "contrôle : rien n'est compté en production");
            assert_eq!(compte_des_temoins(&conn, BB4_COMPTE_BANS), 0, "contrôle : rien n'est compté sur la base");
        }
        let (st, _p) = sp_state("bb4-c-refus");
        let conn = st.db.lock();
        bb4_ban_expire(&conn);
        let (avant, _) = bb4_compte_de_production();
        let refus = bb4_refuser_la_purge_des_bans(&conn);
        materialize_banned_ip(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la purge des bans expirés est refusée une fois");
        assert_eq!(bb4_compte_de_production(), (avant + 1, Some(BB4_CAUSE_BANS.to_string())), "purge refusée : comptée une fois en production, avec sa cause");
        assert_eq!(compte_des_temoins(&conn, BB4_COMPTE_BANS), 1, "purge refusée : comptée une fois sur la base visée");
    }

    /// (d) LA LIGNE DE JOURNAL, lue sur le stderr d'un sous-processus : un refus écrit EXACTEMENT `BB4_LIGNE_BANS` (une
    /// fois) ; le passage nominal n'écrit aucune ligne de purge des bans. Sous « BB4_BANS_JOURNAL_MUET » : aucune ligne.
    #[test]
    fn bb4_ligne_de_journal_de_la_purge_des_bans_expires() {
        let _env = VERROU_ENV_PROCESSUS.read(); // materialize_banned_ip lit cfg()
        const ENFANT: &str = "BB4_ENFANT_JOURNAL";
        const PHASE: &str = "BB4-PHASE:";
        const TETE: &str = "[rollup] WARN purge des bans expirés";
        if std::env::var(ENFANT).is_ok() {
            eprintln!("{PHASE}refus");
            {
                let (st, _p) = sp_state("bb4-d-refus");
                let conn = st.db.lock();
                bb4_ban_expire(&conn);
                let refus = bb4_refuser_la_purge_des_bans(&conn);
                materialize_banned_ip(&conn);
                conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("BB4-REFUS:{}", refus.load(Ordering::Relaxed));
            }
            eprintln!("{PHASE}calme");
            {
                let (st, _p) = sp_state("bb4-d-calme");
                let conn = st.db.lock();
                bb4_ban_expire(&conn);
                materialize_banned_ip(&conn);
                println!("BB4-CALME-PURGE:{}", bb4_ban_present(&conn));
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::rollups_groupe_partiellement_purge_et_bans_expires::bb4_ligne_de_journal_de_la_purge_des_bans_expires",
            ])
            .env(ENFANT, "1")
            .env(BB4_RETENTION_DES_BANS, "86400")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for m in ["BB4-REFUS:1", "BB4-CALME-PURGE:0"] {
            assert!(stdout.contains(m), "prémisse : {m} : {stdout}"); // libtest écrit « test … … » sur la même ligne
        }
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with(TETE)).map(str::to_string).collect()
        };
        assert_eq!(phase("refus"), vec![BB4_LIGNE_BANS.to_string()], "refus : la ligne entière, une fois");
        assert!(phase("calme").is_empty(), "le nominal n'écrit aucune ligne de purge des bans");
    }
}
