// =====================================================================================
// `P10.32-a` (hors `handlers/` : `rollups.rs`) — UN PLANCHER NON LU NE PUBLIE PAS UNE COUVERTURE DONT LA RECONSTRUCTION
// A ÉTÉ SAUTÉE, MÊME QUAND UNE COUVERTURE ÉTAIT PRÉSENTE ; UN PLANCHER DE RATTRAPAGE DE FLOTTE NON LU EST DIT ET COMPTÉ.
//
// CE QUI MANQUAIT (relevé par le vérificateur indépendant sur la reprise de `rollups_watermarks_non_lus.rs`) : la garde de
// publication de `rollup_events` — `plancher_lu || dirty_lo.is_none()` — n'était témoignée, côté refus, que pour une
// couverture ABSENTE (témoin (f)). Deux cas affirmés par son commentaire n'étaient tenus par rien :
//  (h) bande sale TROUVÉE (une tardive sous le watermark, au-dessus de la couverture) puis plancher NON LU ;
//  (i) watermark d'`event_rollup` NON LU ou ABSENT, couverture PRÉSENTE, plancher NON LU.
// Dans les deux, une reconstruction était demandée et a été sautée (`agg_from = recent`). Le mutant qui confond « rien de
// sale » et « couverture présente » (`dirty_lo.is_none()` -> `cov.is_some()`) publiait alors la couverture sur la tardive
// jamais réparée, et le trou devenait DÉFINITIF : la bande sale suivante part de `id > cov`. Il restait vert sur les
// sept témoins de l'autre fichier.
//
//  (j) le plancher de rattrapage de flotte (`host_rollup_backfill_floor`) lu par `.ok().and_then(parse).unwrap_or(new_wm)` :
//      non lu (blob, texte non entier, lecture ratée), il valait « rien à rattraper », SANS RIEN DIRE. Désormais trois
//      issues : absent = NO-OP ; lu = rattrapage ; non lu = rattrapage sauté, plancher inchangé, dit et compté sous
//      « rattrapage de l'inventaire de flotte : plancher de rattrapage non lu ».
//
// LES VOIES D'ÉCHEC FABRIQUÉES : (h) un autorisateur qui laisse passer la bande sale (seule instruction qui lit `event.id`
// ET `event.ts`) puis refuse le `min` de l'instruction suivante, le plancher, une seule fois (prémisse assertée) ; (i) un
// autorisateur qui refuse toute fonction `min` (prémisse : au moins un refus) ; (j) `meta.value` du plancher posé en BLOB
// (affinité TEXT : `get::<String>` échoue sur une ligne qui EXISTE) ou en texte non entier.
//
// GRAVITÉ, DITE ET NON GONFLÉE : aucun déclenchement observé en production. (h)(i) exigent une lecture ratée du plancher
// (verrou, interruption) ; (j) une base altérée ou une lecture ratée. La garde de (h)(i) était déjà juste ; ces témoins
// la TIENNENT. (j) ne change que la parole : avant comme après, le rattrapage est sauté et le plancher laissé en place.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une lecture ratée du plancher par interruption réelle (budget, `progress_handler`) —
// même branche `Err`, fabriquée par l'autorisateur ; un plancher de rattrapage DURABLEMENT corrompu (blob, texte non
// entier) : rien ne le réécrit, et l'upsert de `note_host_backfill_floor` (`CAST(meta.value AS INTEGER) > ...`, qui vaut
// 0 sur un blob ou un texte non entier) ne le rabaisse jamais pour un `ts` positif — le rattrapage reste sauté à CHAQUE
// passage, compté chaque fois, les arrivées tardives non foldées jusqu'à réparation manuelle de `meta` (dit au journal,
// pas réparé : le réécrire exigerait de savoir quelle arrivée tardive il notait, et le remplacer par `MIN(event.ts)`
// rejouerait le scan non borné que ce plancher évite).
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par `VERIF_MUT` sous `cfg!(test)`, puis retirées du source) :
//  * « P_GARDE_PAR_COV » (`rollup_events` : `dirty_lo.is_none()` remplacé par `cov.is_some()`) : (h), (i) ;
//  * « P_PUB_SANS_PLANCHER » (`rollup_events` : la garde perd le plancher, la forme d'avant le lot) : (h), (i) ;
//  * « J_PLANCHER_NONLU_MUET » (`rollup_hosts` : plancher non lu = `new_wm` sans compte, la forme d'avant) : (j).
// =====================================================================================
mod rollups_plancher_non_lu_reconstruction_demandee {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::rollup_coverage::{META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const RPNL_COMPTE_DU_RATTRAPAGE: &str =
        "geste de fond non validé rollup : rattrapage de l'inventaire de flotte : plancher de rattrapage non lu";

    fn rpnl_recent() -> i64 {
        ((now() / 3600) * 3600 - 3600).max(0)
    }

    fn rpnl_meta(conn: &rusqlite::Connection, cle: &str) -> Option<(String, String)> {
        conn.query_row("SELECT typeof(value), CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok()
    }

    fn rpnl_n_du_bucket(conn: &rusqlite::Connection, bucket: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![bucket], |r| r.get(0)).unwrap()
    }

    /// (h) Bande sale TROUVÉE puis plancher NON LU : la réparation est sautée, la couverture (présente avant) n'est PAS
    /// republiée. Sous `P_GARDE_PAR_COV`, elle le serait sur l'identifiant de la tardive jamais réparée.
    #[test]
    fn rpnl_bande_sale_trouvee_et_plancher_non_lu_ne_publie_pas_la_couverture() {
        let recent = rpnl_recent();
        let (st, _p) = sp_state("rpnl-sale-trouvee");
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rpnl','sshd',1,'ancienne')", params![recent - 7200]).unwrap();
        let couverte = conn.last_insert_rowid();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, couverte.to_string()]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rpnl','sshd',1,'tardive')", params![recent - 3600]).unwrap();
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = (false, false);
        let mut sale_vue = false;
        let mut instruction_apres_la_sale = false;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            match ctx.action {
                AuthAction::Select => {
                    if sale_vue {
                        instruction_apres_la_sale = true;
                    }
                    vus = (false, false);
                }
                AuthAction::Read { table_name: "event", column_name: "id" } => vus.0 = true,
                AuthAction::Read { table_name: "event", column_name: "ts" } => vus.1 = true,
                AuthAction::Function { function_name }
                    if function_name.eq_ignore_ascii_case("min") && instruction_apres_la_sale && compteur.load(Ordering::Relaxed) == 0 =>
                {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    return Authorization::Deny;
                }
                _ => {}
            }
            if vus.0 && vus.1 {
                sale_vue = true;
            }
            Authorization::Allow
        }));
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la bande sale lue, le plancher refusé une fois");
        assert_eq!(rpnl_n_du_bucket(&conn, recent - 3600), 0, "prémisse : la tardive n'a pas été réparée");
        assert_eq!(rpnl_meta(&conn, META_ROLLUP_WM).map(|(_, v)| v), Some(recent.to_string()), "watermark à recent");
        assert_eq!(
            rpnl_meta(&conn, META_ROLLUP_COV_ID),
            None,
            "bande sale trouvée + plancher non lu : la couverture n'est PAS publiée (sinon la tardive jamais réparée serait couverte, trou définitif)"
        );
    }

    /// (i) Watermark d'`event_rollup` NON LU (blob) ou ABSENT, couverture PRÉSENTE, plancher NON LU : la reconstruction
    /// demandée est sautée, rien n'est effacé, la couverture n'est PAS republiée.
    #[test]
    fn rpnl_watermark_non_lu_couverture_presente_et_plancher_non_lu_ne_publie_pas() {
        let recent = rpnl_recent();
        for (tag, pose_du_watermark) in [
            ("blob", "UPDATE meta SET value=X'00' WHERE key='event_rollup_wm'"),
            ("absent", "DELETE FROM meta WHERE key='event_rollup_wm'"),
        ] {
            let (st, _p) = sp_state(&format!("rpnl-wm-{tag}"));
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'rpnl-ancien',0,'','','',42,0,'prod')",
                params![recent - 30 * 86400],
            )
            .unwrap();
            conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rpnl','sshd',1,'m')", params![recent - 7200]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, id.to_string()]).unwrap();
            conn.execute(pose_du_watermark, []).unwrap();
            assert_eq!(rpnl_meta(&conn, META_ROLLUP_COV_ID).map(|(_, v)| v), Some(id.to_string()), "prémisse ({tag}) : couverture présente");
            let refus = Arc::new(AtomicUsize::new(0));
            let compteur = refus.clone();
            conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("min") => {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            rollup_events(&conn);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert!(refus.load(Ordering::Relaxed) >= 1, "prémisse ({tag}) : le plancher a bien été refusé");
            assert_eq!(rpnl_n_du_bucket(&conn, recent - 30 * 86400), 42, "({tag}) l'histoire que seul le rollup garde n'est pas effacée");
            assert_eq!(rpnl_n_du_bucket(&conn, recent - 7200), 0, "prémisse ({tag}) : la reconstruction a été sautée");
            assert_eq!(
                rpnl_meta(&conn, META_ROLLUP_COV_ID),
                None,
                "({tag}) watermark non lu + couverture présente + plancher non lu : la couverture n'est PAS republiée"
            );
        }
    }

    /// Un hôte plié une fois (watermark de flotte ABSENT -> premier pli depuis 0) : watermark lu à `recent`.
    fn rpnl_flotte_pliee_une_fois(conn: &rusqlite::Connection) -> i64 {
        let recent = rpnl_recent();
        conn.execute("DELETE FROM meta WHERE key IN ('host_rollup_wm','host_rollup_backfill_floor')", []).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'rpnl-hote','sshd','m')", params![recent - 1800]).unwrap();
        rollup_hosts(conn);
        recent
    }

    /// (j) Plancher de rattrapage de flotte NON LU (blob, puis texte non entier) : le rattrapage est sauté, le plancher
    /// laissé tel quel (type ET valeur), et le saut est COMPTÉ (avant : rien). Contrôle dans le même témoin : un plancher
    /// LU sous le watermark rattrape l'hôte tardif et remonte au watermark, sans compte.
    #[test]
    fn rpnl_un_plancher_de_rattrapage_non_lu_est_compte_et_laisse_en_place() {
        {
            let (st, _p) = sp_state("rpnl-rattrapage-lu");
            let conn = st.db.lock();
            let recent = rpnl_flotte_pliee_une_fois(&conn);
            assert_eq!(rpnl_meta(&conn, "host_rollup_wm").map(|(_, v)| v), Some(recent.to_string()), "prémisse : watermark lu à recent");
            conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'rpnl-tardif','sshd','m')", params![recent - 7200]).unwrap();
            note_host_backfill_floor(&conn, recent - 7200);
            rollup_hosts(&conn);
            let tardif: Option<i64> =
                conn.query_row("SELECT sig_total FROM host_rollup WHERE host='rpnl-tardif'", [], |r| r.get(0)).ok();
            assert_eq!(tardif, Some(1), "contrôle : plancher lu, l'hôte tardif est rattrapé");
            assert_eq!(rpnl_meta(&conn, "host_rollup_backfill_floor").map(|(_, v)| v), Some(recent.to_string()), "contrôle : plancher remonté au watermark");
            assert_eq!(compte_des_temoins(&conn, RPNL_COMPTE_DU_RATTRAPAGE), 0, "contrôle : aucun rattrapage sauté compté");
        }
        for (tag, valeur, attendu) in [("blob", "X'00'", ("blob", "\u{0}")), ("texte", "'pas-un-entier'", ("text", "pas-un-entier"))] {
            let (st, _p) = sp_state(&format!("rpnl-rattrapage-{tag}"));
            let conn = st.db.lock();
            let recent = rpnl_flotte_pliee_une_fois(&conn);
            conn.execute(&format!("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_backfill_floor', {valeur})"), []).unwrap();
            rollup_hosts(&conn);
            assert_eq!(rpnl_meta(&conn, "host_rollup_wm").map(|(_, v)| v), Some(recent.to_string()), "({tag}) le watermark lu n'est pas touché");
            assert_eq!(
                rpnl_meta(&conn, "host_rollup_backfill_floor"),
                Some((attendu.0.to_string(), attendu.1.to_string())),
                "({tag}) plancher non lu : laissé en place (type ET valeur), un échec passager sera repris"
            );
            assert_eq!(compte_des_temoins(&conn, RPNL_COMPTE_DU_RATTRAPAGE), 1, "({tag}) plancher non lu : le rattrapage sauté est COMPTÉ sous son étape");
        }
    }
}
