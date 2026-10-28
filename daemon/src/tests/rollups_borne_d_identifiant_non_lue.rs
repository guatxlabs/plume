// =====================================================================================
// `P10.32-a` (hors `handlers/` : `rollups.rs`) — UNE BORNE D'IDENTIFIANT NON LUE NE RÉTRACTE NI N'AGRÈGE NI NE PUBLIE.
//
// LE DÉFAUT, LU SUR 9f67050b : `rollup_events` prend la borne `new_cov = MAX(event.id)` AVANT d'agréger et la pousse dans
// la condition d'agrégation (`id <= new_cov`). Elle était lue par `.unwrap_or(0)` : une lecture ratée valait 0, la bande
// `[agg_from, recent)` était RÉTRACTÉE (`DELETE FROM event_rollup`), ré-agrégée sous `id <= 0` (rien), le watermark
// avançait à `recent` et la couverture `0` était PUBLIÉE — fausse, le rollup portant des lignes d'identifiant positif.
// Sans un mot au journal. Le passage suivant, borne relue, reconstruit la bande (couverture `0` = tout est tardif) : la
// perte des buckets d'`event` est transitoire, celle de l'exactitude de la couverture servie ne l'est pas, et une lecture
// durablement ratée la rend permanente.
//
// DÉSORMAIS (décision par défaut, vague Y) : borne non lue -> ni rétraction, ni agrégation, watermark ET couverture
// laissés tels quels (la paire du passage précédent reste vraie : seuls les buckets `>= recent` bougent), dit au journal ;
// la fenêtre chaude reste servie.
//
// LA VOIE D'ÉCHEC FABRIQUÉE : un AUTORISATEUR qui refuse toute instruction lisant `event.id` AVANT `event.ts` (SQLite
// résout la liste de résultats avant `WHERE`) : seules les lectures `SELECT COALESCE(MAX(id),0) FROM event` sont dans ce
// cas — la bande sale, le plancher et les agrégations lisent `ts` d'abord. Deux lectures ont ce SQL : la borne
// d'`event_rollup` et `dim_at_id` plus bas. La prémisse ne compte donc QUE les refus survenus AVANT le premier `DELETE`
// sur `event_rollup` (la purge de la fenêtre chaude, toujours jouée après la borne et avant `dim_at_id`) : exactement un,
// celui de la borne. Un refus de `dim_at_id` seul ne la satisfait pas.
//
// DEUX ÉTATS DE DÉPART : couverture PRÉSENTE (elle doit rester telle quelle) et couverture ABSENTE, watermark présent
// (elle doit rester absente : la publication est gardée par la borne lue, une couverture `0` ne s'écrit pas — la clé
// `meta.key` étant PRIMARY KEY, seul ce départ-ci rend visible une publication non gardée).
//
// CE QUE CE TÉMOIN NE TIENT PAS : une lecture ratée par interruption réelle (même branche `Err`) ; la borne jumelle
// `dim_at_id` du rollup dimensionnel (refusée aussi par cet autorisateur, traitée et témoignée à part :
// `rollups_dim_et_banned_ip_non_ecrits.rs`) ; l'horloge reculée (`wm > recent`) : borne non lue, `[recent, wm)` est ré-agrégé sans borne d'identifiant
// sous un watermark laissé en place, double compte des lignes tardives `id > cov` (limite écrite dans `rollups.rs`) ;
// le plancher `MIN(event.ts)` abaissé par une vieille ligne restée dans `event` (traité et témoigné à part :
// `rollups_buckets_resservis_et_retention_illisible.rs`).
//
// LES MUTATIONS QUI LE FONT ROUGIR (jouées par variable d'environnement de mutation sous `cfg!(test)`, puis retirées du source) :
//  * « Y3_BORNE_ZERO » (`.unwrap_or(0)` rétabli, la forme d'avant) : bucket rétracté, watermark avancé, couverture `0` ;
//  * « Y3_RETRACTION_MALGRE » (la rétraction — couverture et bande effacées — faite malgré le non-lu) : bucket, couverture ;
//  * « Y3_WM_AVANCE » (le watermark réécrit malgré le non-lu) : watermark ;
//  * « Y3_COV_EFFACEE » (la couverture effacée à la publication malgré le non-lu) : couverture ;
//  * « Y3_PUBLIE_MALGRE » (la garde `borne_lue` retirée de la PUBLICATION) : couverture `0` publiée au départ sans couverture ;
//  * « Y3_PREMISSE » (la borne lue par un chemin que l'autorisateur laisse passer, `dim_at_id` seul refusé) : prémisse.
// =====================================================================================
mod rollups_borne_d_identifiant_non_lue {
    use super::*;
    use crate::rollup_coverage::{META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn rbil_recent() -> i64 {
        heure_ronde_precedente_hors_de_la_fin_d_heure()
    }

    fn rbil_meta(conn: &rusqlite::Connection, cle: &str) -> Option<String> {
        conn.query_row("SELECT CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| r.get(0)).ok()
    }

    fn rbil_n_du_bucket(conn: &rusqlite::Connection, bucket: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![bucket], |r| r.get(0)).unwrap()
    }

    /// Fixture : un event à `recent - 7200` agrégé par un passage nominal, puis le watermark ramené à `recent - 7200`
    /// (dernier passage il y a deux heures) : le passage suivant rattrape la bande `[recent - 7200, recent)`, qui porte un
    /// bucket n=1. Un event chaud (`now - 10`) pour la fenêtre chaude. Rend l'identifiant couvert.
    fn rbil_bande_a_rattraper(conn: &rusqlite::Connection, recent: i64) -> i64 {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbil','sshd',1,'m')", params![recent - 7200]).unwrap();
        let id = conn.last_insert_rowid();
        rollup_events(conn);
        assert_eq!(rbil_n_du_bucket(conn, recent - 7200), 1, "prémisse : bucket agrégé par le passage nominal");
        assert_eq!(rbil_meta(conn, META_ROLLUP_COV_ID), Some(id.to_string()), "prémisse : couverture publiée");
        conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![(recent - 7200).to_string(), META_ROLLUP_WM]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbil','sshd',1,'chaud')", params![now() - 10]).unwrap();
        id
    }

    /// Pose l'autorisateur qui refuse les lectures d'`event.id` faites avant `event.ts`. Rend le nombre de refus survenus
    /// AVANT le premier `DELETE` sur `event_rollup` — ceux de la borne d'`event_rollup`, et d'elle seule.
    fn rbil_refuser_la_borne(conn: &rusqlite::Connection) -> Arc<AtomicUsize> {
        let refus_borne = Arc::new(AtomicUsize::new(0));
        let compteur = refus_borne.clone();
        let mut ts_lu = false;
        let mut rollup_purge = false;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => {
                ts_lu = false;
                Authorization::Allow
            }
            AuthAction::Delete { table_name: "event_rollup" } => {
                rollup_purge = true;
                Authorization::Allow
            }
            AuthAction::Read { table_name: "event", column_name: "ts" } => {
                ts_lu = true;
                Authorization::Allow
            }
            AuthAction::Read { table_name: "event", column_name: "id" } if !ts_lu => {
                if !rollup_purge {
                    compteur.fetch_add(1, Ordering::Relaxed);
                }
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus_borne
    }

    /// Borne `MAX(event.id)` NON LUE : le bucket de la bande est intact (avant : rétracté puis ré-agrégé à vide), le
    /// watermark et la couverture inchangés (avant : `recent` et `0`), la fenêtre chaude servie. Contrôle : borne lue, la
    /// bande est rattrapée, le watermark avance, la couverture vaut la borne.
    #[test]
    fn rbil_une_borne_d_identifiant_non_lue_ne_retracte_ni_ne_publie() {
        let recent = rbil_recent();
        let bucket_chaud = (now() - 10) / 3600 * 3600;
        // Contrôle : borne lue.
        {
            let (st, _p) = sp_state("rbil-lue");
            let conn = st.db.lock();
            rbil_bande_a_rattraper(&conn, recent);
            rollup_events(&conn);
            let borne: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(rbil_n_du_bucket(&conn, recent - 7200), 1, "contrôle : la bande est ré-agrégée");
            assert_eq!(rbil_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "contrôle : watermark à recent");
            assert_eq!(rbil_meta(&conn, META_ROLLUP_COV_ID), Some(borne.to_string()), "contrôle : couverture = borne");
        }
        let (st, _p) = sp_state("rbil-non-lue");
        let conn = st.db.lock();
        let id = rbil_bande_a_rattraper(&conn, recent);
        let refus = rbil_refuser_la_borne(&conn);
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la lecture de la borne d'event_rollup (et non dim_at_id) a été refusée");
        assert_eq!(rbil_n_du_bucket(&conn, recent - 7200), 1, "borne non lue : le bucket de la bande n'est PAS rétracté");
        assert_eq!(rbil_meta(&conn, META_ROLLUP_WM), Some((recent - 7200).to_string()), "borne non lue : le watermark n'avance PAS");
        assert_eq!(rbil_meta(&conn, META_ROLLUP_COV_ID), Some(id.to_string()), "borne non lue : la couverture est laissée telle quelle (ni effacée, ni `0`)");
        assert!(rbil_n_du_bucket(&conn, bucket_chaud) >= 1, "borne non lue : la fenêtre chaude reste servie");
    }

    /// Départ SANS couverture, watermark présent (publication interrompue, base d'avant la couverture) : borne NON LUE ->
    /// la couverture reste ABSENTE (avant, et sous `Y3_PUBLIE_MALGRE` : `0` publiée), le watermark inchangé, le bucket
    /// de la bande intact. Contrôle : borne lue, la couverture est publiée à la borne.
    #[test]
    fn rbil_sans_couverture_une_borne_non_lue_ne_publie_pas_zero() {
        let recent = rbil_recent();
        let depart = |conn: &rusqlite::Connection| {
            conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbil','sshd',1,'m')", params![recent - 7200]).unwrap();
            rollup_events(conn);
            assert_eq!(rbil_meta(conn, META_ROLLUP_WM), Some(recent.to_string()), "prémisse : watermark présent");
            conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
            assert_eq!(rbil_meta(conn, META_ROLLUP_COV_ID), None, "prémisse : couverture absente");
            conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rbil','sshd',1,'chaud')", params![now() - 10]).unwrap();
        };
        {
            let (st, _p) = sp_state("rbil-sans-cov-lue");
            let conn = st.db.lock();
            depart(&conn);
            rollup_events(&conn);
            let borne: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(rbil_meta(&conn, META_ROLLUP_COV_ID), Some(borne.to_string()), "contrôle : couverture republiée à la borne");
        }
        let (st, _p) = sp_state("rbil-sans-cov-non-lue");
        let conn = st.db.lock();
        depart(&conn);
        let refus = rbil_refuser_la_borne(&conn);
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la lecture de la borne d'event_rollup (et non dim_at_id) a été refusée");
        assert_eq!(rbil_meta(&conn, META_ROLLUP_COV_ID), None, "borne non lue : aucune couverture publiée (jamais `0`)");
        assert_eq!(rbil_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "borne non lue : watermark inchangé");
        assert_eq!(rbil_n_du_bucket(&conn, recent - 7200), 1, "borne non lue : le bucket de la bande n'est PAS rétracté");
    }
}
