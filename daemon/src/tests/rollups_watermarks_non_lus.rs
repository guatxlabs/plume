// =====================================================================================
// `P10.20-b` (hors `handlers/` : watermarks de `rollups.rs`) — UN WATERMARK NON LU N'EST NI UN ZÉRO NI UN « RIEN À
// RÉPARER ».
//
// LE DÉFAUT, LU SUR 80ad700a (ces témoins joués sur la forme d'avant par les mutations ci-dessous, qui la restituent) :
//  (1) `rollup_hosts` lisait `host_rollup_wm` par `.ok().and_then(parse).unwrap_or(0)` : une lecture ratée ou une
//      valeur non entière valait 0, le pli DÉFINITIF [0, recent) était rejoué, et son conflit ADDITIONNE
//      (`sig_total = host_rollup.sig_total + excluded.sig_total`) : `sig_total` de chaque hôte DOUBLÉ, sans retour,
//      puis le watermark réécrit à `recent` par-dessus la preuve ;
//  (2) `note_host_backfill_floor` : même lecture à 0, `min_ts < 0` faux, plancher PERDU, l'arrivée tardive jamais
//      foldée ;
//  (3) `rollup_events` : la bande sale (`MIN(ts)` des lignes arrivées sous le watermark depuis la couverture) lue par
//      `.ok().flatten()` : une lecture ratée valait « rien de sale », et la couverture était PUBLIÉE sur des lignes
//      tardives jamais réparées — la route servait ce rollup comme EXACT.
//
// LES VOIES D'ÉCHEC FABRIQUÉES : (1)(2) `meta.value` de `host_rollup_wm` posé en BLOB (affinité TEXT : le blob reste
// un blob, `get::<String>` échoue sur une ligne qui EXISTE) ou en texte non entier ; (3) un AUTORISATEUR qui refuse
// la seule requête de `rollup_events` qui lit à la fois `event.id` et `event.ts` sans réparation en cours — la
// lecture de la bande sale (prémisse assertée : au moins un refus prononcé).
//
// GRAVITÉ, DITE ET NON GONFLÉE : aucun déclenchement observé en production. Le watermark est écrit par le démon seul
// (`recent.to_string()`), donc (1)(2) exigent une base altérée ou une lecture ratée du moteur ; (3) une lecture ratée
// (verrou, interruption) sur une base vivante. Ce sont des correctifs de cause : les comptes de flotte étaient
// irréversibles et la couverture « exacte » non prouvée.
//
//  (4) `rollup_events` lisait `event_rollup_wm` par `meta_i64(..).unwrap_or(0)` : absent (migrations v33/v64 qui
//      l'effacent) ou non lu, il valait 0 ; la couverture étant présente, la bande sale `ts < 0` était vide, le
//      rattrapage partait de 0 SANS le plancher `MIN(event.ts)`, et `DELETE FROM event_rollup WHERE bucket >= 0 AND
//      bucket < recent` effaçait l'histoire que SEUL le rollup garde (mesuré : bucket ancien n=42 lu, n=0 non lu) —
//      défaut antérieur au lot, relevé par le vérificateur ; désormais absent/non lu = reconstruction bornée au plancher ;
//  (5) le plancher `MIN(event.ts)` lu par `.ok().flatten()` : non lu, il valait « `event` vide », le rattrapage était
//      sauté et la couverture PUBLIÉE sur des heures définitives jamais agrégées.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une lecture ratée de la bande sale par interruption réelle (budget,
// `progress_handler`) — même branche `Err`, fabriquée ici par l'autorisateur ; la couverture `event_rollup_cov_id`
// elle-même, lue par `meta_i64` (non lue = « absente », ce qui RECONSTRUIT, bornée au plancher : sens sûr, non
// traité) ; le COÛT d'un `event_rollup_wm` non lu : une reconstruction complète `[MIN(event.ts), recent)` au passage
// suivant, assumée (rare, et le watermark est réécrit) ; un `host_rollup_wm` DURABLEMENT corrompu (blob, texte non
// entier) : rien ne le réécrit, le pli définitif reste sauté à chaque passage, compté chaque fois, `sig_total`
// sous-compté jusqu'à réparation manuelle de `meta` (dit au journal, pas réparé : le réécrire exigerait de savoir où le
// pli s'est arrêté) ; le watermark de `banned_ip` (`materialize_banned_ip`, même idiome, upsert idempotent MIN/MAX :
// bénin, non traité).
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par variable d'environnement de mutation sous `cfg!(test)`, puis retirées
// du source) :
//  * « M5_WM_HOTES_ZERO » (`rollup_hosts` : watermark non lu = 0, la forme d'avant) : (a), et (b) dans sa seconde moitié (le rattrapage n'est plus sauté) ;
//  * « M5_PLANCHER_ZERO » (`note_host_backfill_floor` : watermark non lu = 0) : (b) ;
//  * « M5_SALE_NONLUE_VAUT_RIEN » (`rollup_events` : bande sale non lue = rien de sale) : (d) ;
//  * « M5_CHAUDE_NONLU_SAUTEE » (`rollup_hosts` : la fenêtre chaude non servie sous watermark non lu) : (a) ;
//  * « M5_WM_EVENTS_NONLU_ZERO » (`rollup_events` : watermark absent/non lu = 0, la forme d'avant) : (e) ;
//  * « M5_PLANCHER_ERR_VAUT_VIDE » (`rollup_events` : plancher non lu = `event` vide, couverture publiée) : (f).
//  * « P_PUB_SANS_NONE » (`rollup_events` : la garde de publication perd `|| dirty_lo.is_none()`, un plancher non lu
//    dépublie la couverture même sans rien de sale) : (g).
// =====================================================================================
mod rollups_watermarks_non_lus {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::rollup_coverage::{META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const RWNL_COMPTE_DU_PLI: &str =
        "geste de fond non validé rollup : pli définitif de l'inventaire de flotte : watermark non lu";

    fn rwnl_recent() -> i64 {
        ((now() / 3600) * 3600 - 3600).max(0)
    }

    fn rwnl_sig_total(conn: &rusqlite::Connection, host: &str) -> i64 {
        conn.query_row("SELECT sig_total FROM host_rollup WHERE host=?1", params![host], |r| r.get(0)).expect("hôte au rollup")
    }

    fn rwnl_meta(conn: &rusqlite::Connection, cle: &str) -> Option<(String, String)> {
        conn.query_row("SELECT typeof(value), CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok()
    }

    /// Un hôte plié une fois par le premier pli (watermark ABSENT -> depuis 0) : `sig_total = 1`, watermark à `recent`.
    fn rwnl_flotte_pliee_une_fois(conn: &rusqlite::Connection) -> i64 {
        let recent = rwnl_recent();
        conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'rwnl-hote','sshd','m')", params![recent - 1800]).unwrap();
        rollup_hosts(conn);
        recent
    }

    /// (a) Watermark de flotte NON LU (blob, puis texte non entier) : le pli définitif est SAUTÉ — `sig_total`
    /// inchangé (avant : doublé), watermark NON réécrit (avant : réécrit à `recent`) — et le saut est compté.
    #[test]
    fn rwnl_un_watermark_de_flotte_non_lu_ne_double_pas_les_comptes() {
        for (tag, valeur, attendu) in [("blob", "X'00'", ("blob", "\u{0}")), ("texte", "'pas-un-entier'", ("text", "pas-un-entier"))] {
            let (st, _p) = sp_state(&format!("rwnl-wm-{tag}"));
            let conn = st.db.lock();
            let recent = rwnl_flotte_pliee_une_fois(&conn);
            assert_eq!(rwnl_sig_total(&conn, "rwnl-hote"), 1, "prémisse ({tag}) : premier pli, l'hôte compté une fois");
            assert_eq!(rwnl_meta(&conn, "host_rollup_wm"), Some(("text".into(), recent.to_string())), "prémisse ({tag}) : watermark à recent");

            conn.execute(&format!("UPDATE meta SET value={valeur} WHERE key='host_rollup_wm'"), []).unwrap();
            // La fenêtre chaude reste servie : un sig_hot périmé est remis à zéro, un hôte vu dans l'heure apparaît.
            conn.execute("UPDATE host_rollup SET sig_hot = 7 WHERE host='rwnl-hote'", []).unwrap();
            conn.execute("INSERT INTO event(ts,host,source,message) VALUES(?1,'rwnl-chaud','sshd','m')", params![now() - 10]).unwrap();
            rollup_hosts(&conn);

            assert_eq!(rwnl_sig_total(&conn, "rwnl-hote"), 1, "({tag}) watermark non lu : le pli additif [0, recent) n'est PAS rejoué, sig_total non doublé");
            assert_eq!(
                rwnl_meta(&conn, "host_rollup_wm"),
                Some((attendu.0.to_string(), attendu.1.to_string())),
                "({tag}) watermark non lu : il n'est PAS réécrit par-dessus (type ET valeur)"
            );
            let sig_hot = |h: &str| -> Option<i64> {
                conn.query_row("SELECT sig_hot FROM host_rollup WHERE host=?1", params![h], |r| r.get(0)).ok()
            };
            assert_eq!(sig_hot("rwnl-hote"), Some(0), "({tag}) watermark non lu : la fenêtre chaude remet sig_hot à zéro");
            assert_eq!(sig_hot("rwnl-chaud"), Some(1), "({tag}) watermark non lu : un hôte vu dans l'heure apparaît (fenêtre chaude servie)");
            assert_eq!(compte_des_temoins(&conn, RWNL_COMPTE_DU_PLI), 1, "({tag}) le pli sauté est compté sous son étape");
        }
    }

    /// (b) Watermark NON LU : le plancher de rattrapage est noté quand même (avant : perdu).
    #[test]
    fn rwnl_un_watermark_non_lu_ne_perd_pas_le_plancher_de_rattrapage() {
        let (st, _p) = sp_state("rwnl-plancher");
        let conn = st.db.lock();
        let recent = rwnl_recent();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_wm', X'00')", []).unwrap();
        note_host_backfill_floor(&conn, recent - 7200);
        assert_eq!(
            rwnl_meta(&conn, "host_rollup_backfill_floor").map(|(_, v)| v),
            Some((recent - 7200).to_string()),
            "watermark non lu : le plancher est noté, l'arrivée tardive sera rattrapée"
        );
        // Et le rattrapage n'a lieu qu'une fois le watermark RELU : sous watermark non lu, il est sauté, le plancher reste.
        rollup_hosts(&conn);
        assert_eq!(
            rwnl_meta(&conn, "host_rollup_backfill_floor").map(|(_, v)| v),
            Some((recent - 7200).to_string()),
            "watermark non lu : le rattrapage est sauté, le plancher n'est pas remonté"
        );
    }

    /// (c) CONTRÔLE NÉGATIF : le chemin nominal est inchangé. Absent = premier pli depuis 0 (déjà joué par la fixture),
    /// re-tick sans double ; watermark lu : une donnée courante ne note aucun plancher, une donnée tardive le note ;
    /// absent : aucun plancher (`min_ts < 0` faux, comme avant).
    #[test]
    fn rwnl_le_chemin_nominal_des_watermarks_de_flotte_est_inchange() {
        let (st, _p) = sp_state("rwnl-nominal");
        let conn = st.db.lock();
        let recent = rwnl_flotte_pliee_une_fois(&conn);
        assert_eq!(rwnl_sig_total(&conn, "rwnl-hote"), 1, "absent : premier pli, compté une fois");
        rollup_hosts(&conn);
        assert_eq!(rwnl_sig_total(&conn, "rwnl-hote"), 1, "watermark lu : re-tick sans double");
        assert_eq!(compte_des_temoins(&conn, RWNL_COMPTE_DU_PLI), 0, "aucun pli sauté sur le chemin nominal");
        note_host_backfill_floor(&conn, recent + 10);
        assert_eq!(rwnl_meta(&conn, "host_rollup_backfill_floor"), None, "donnée courante : aucun plancher");
        note_host_backfill_floor(&conn, recent - 7200);
        assert_eq!(rwnl_meta(&conn, "host_rollup_backfill_floor").map(|(_, v)| v), Some((recent - 7200).to_string()), "donnée tardive : plancher noté");
        conn.execute("DELETE FROM meta WHERE key IN ('host_rollup_wm','host_rollup_backfill_floor')", []).unwrap();
        note_host_backfill_floor(&conn, recent - 7200);
        assert_eq!(rwnl_meta(&conn, "host_rollup_backfill_floor"), None, "watermark absent : aucun plancher, le premier pli couvrira tout");
    }

    /// Fixture de (d) : une couverture à la première ligne, le watermark à `recent`, puis une ligne TARDIVE (sous le
    /// watermark, identifiant au-dessus de la couverture). Rend l'identifiant de la tardive.
    fn rwnl_ligne_tardive_sous_la_couverture(conn: &rusqlite::Connection, recent: i64) -> i64 {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rwnl','sshd',1,'ancienne')", params![recent - 7200]).unwrap();
        let couverte = conn.last_insert_rowid();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, couverte.to_string()]).unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rwnl','sshd',1,'tardive')", params![recent - 3600]).unwrap();
        conn.last_insert_rowid()
    }

    /// (d) Bande sale NON LUE : la couverture n'est PAS publiée (avant : publiée sur une ligne tardive jamais
    /// réparée). Contrôle positif dans le même témoin : lue, la bande est réparée et la couverture publiée.
    #[test]
    fn rwnl_une_bande_sale_non_lue_ne_publie_pas_la_couverture() {
        let recent = rwnl_recent();
        // Contrôle : lecture réussie -> la tardive est réparée, la couverture vaut son identifiant.
        {
            let (st, _p) = sp_state("rwnl-sale-lue");
            let conn = st.db.lock();
            let tardive = rwnl_ligne_tardive_sous_la_couverture(&conn, recent);
            rollup_events(&conn);
            let reparee: i64 = conn
                .query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![recent - 3600], |r| r.get(0))
                .unwrap();
            assert_eq!(reparee, 1, "contrôle : bande sale lue, la ligne tardive est agrégée");
            assert_eq!(rwnl_meta(&conn, META_ROLLUP_COV_ID).map(|(_, v)| v), Some(tardive.to_string()), "contrôle : couverture publiée");
        }
        let (st, _p) = sp_state("rwnl-sale-non-lue");
        let conn = st.db.lock();
        rwnl_ligne_tardive_sous_la_couverture(&conn, recent);
        // L'autorisateur refuse toute instruction qui lit À LA FOIS `event.id` et `event.ts` : sans réparation en cours,
        // c'est la lecture de la bande sale (les agrégations dimensionnelles refusées n'affectent que leur propre bande).
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = (false, false);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            match ctx.action {
                AuthAction::Select => vus = (false, false),
                AuthAction::Read { table_name: "event", column_name: "id" } => vus.0 = true,
                AuthAction::Read { table_name: "event", column_name: "ts" } => vus.1 = true,
                _ => {}
            }
            if vus.0 && vus.1 {
                compteur.fetch_add(1, Ordering::Relaxed);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
        rollup_events(&conn);
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(refus.load(Ordering::Relaxed) >= 1, "prémisse : la lecture de la bande sale a bien été refusée");
        let reparee: i64 = conn
            .query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![recent - 3600], |r| r.get(0))
            .unwrap();
        assert_eq!(reparee, 0, "prémisse : la ligne tardive n'a pas été réparée");
        assert_eq!(rwnl_meta(&conn, META_ROLLUP_COV_ID), None, "bande sale non lue : la couverture n'est PAS publiée, la route décline et sert le brut");
    }
    /// Fixture de (e) : l'histoire que SEUL le rollup garde (un bucket à 30 jours, n=42, sans aucun event dessous), un
    /// event à `recent - 7200`, la couverture à son identifiant, le watermark à `recent`. Rend l'identifiant de l'event.
    fn rwnl_histoire_du_rollup(conn: &rusqlite::Connection, recent: i64) -> i64 {
        conn.execute(
            "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'rwnl-ancien',0,'','','',42,0,'prod')",
            params![recent - 30 * 86400],
        )
        .unwrap();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rwnl','sshd',1,'m')", params![recent - 7200]).unwrap();
        let id = conn.last_insert_rowid();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, id.to_string()]).unwrap();
        id
    }

    fn rwnl_n_du_bucket(conn: &rusqlite::Connection, bucket: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket=?1", params![bucket], |r| r.get(0)).unwrap()
    }

    /// (e) `event_rollup_wm` ABSENT ou NON LU, couverture présente : l'histoire sous `MIN(event.ts)` n'est PAS effacée
    /// (avant : `DELETE ... bucket >= 0`, n=0), la reconstruction couvre ce qu'`event` porte, le watermark est réécrit
    /// et la couverture publiée. Contrôle : watermark lu, l'histoire est intacte.
    #[test]
    fn rwnl_un_watermark_d_event_rollup_non_lu_n_efface_pas_l_histoire() {
        let recent = rwnl_recent();
        for (tag, pose) in [
            ("lu", None),
            ("blob", Some("UPDATE meta SET value=X'00' WHERE key='event_rollup_wm'")),
            ("texte", Some("UPDATE meta SET value='pas-un-entier' WHERE key='event_rollup_wm'")),
            ("absent", Some("DELETE FROM meta WHERE key='event_rollup_wm'")),
        ] {
            let (st, _p) = sp_state(&format!("rwnl-hist-{tag}"));
            let conn = st.db.lock();
            let id = rwnl_histoire_du_rollup(&conn, recent);
            if let Some(sql) = pose {
                conn.execute(sql, []).unwrap();
            }
            rollup_events(&conn);
            assert_eq!(rwnl_n_du_bucket(&conn, recent - 30 * 86400), 42, "({tag}) l'histoire que seul le rollup garde n'est PAS effacée");
            assert_eq!(rwnl_meta(&conn, META_ROLLUP_WM), Some(("text".into(), recent.to_string())), "({tag}) watermark à recent");
            assert_eq!(rwnl_meta(&conn, META_ROLLUP_COV_ID).map(|(_, v)| v), Some(id.to_string()), "({tag}) couverture publiée");
            if pose.is_some() {
                assert_eq!(rwnl_n_du_bucket(&conn, recent - 7200), 1, "({tag}) reconstruction : ce qu'`event` porte est agrégé");
            }
        }
    }

    /// (f) Plancher `MIN(event.ts)` NON LU (autorisateur qui refuse la fonction `min`), couverture absente donc
    /// reconstruction demandée : rien n'est effacé ET la couverture n'est PAS publiée (avant : publiée sur l'heure
    /// définitive jamais agrégée). Contrôle : plancher lu, l'heure est agrégée et la couverture publiée.
    #[test]
    fn rwnl_un_plancher_non_lu_ne_publie_pas_la_couverture() {
        let recent = rwnl_recent();
        for refuser in [false, true] {
            let (st, _p) = sp_state(&format!("rwnl-plancher-ev-{refuser}"));
            let conn = st.db.lock();
            let id = rwnl_histoire_du_rollup(&conn, recent);
            conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap();
            let refus = Arc::new(AtomicUsize::new(0));
            if refuser {
                let compteur = refus.clone();
                conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("min") => {
                        compteur.fetch_add(1, Ordering::Relaxed);
                        Authorization::Deny
                    }
                    _ => Authorization::Allow,
                }));
            }
            rollup_events(&conn);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert_eq!(rwnl_n_du_bucket(&conn, recent - 30 * 86400), 42, "(refus={refuser}) l'histoire n'est pas effacée");
            if refuser {
                assert!(refus.load(Ordering::Relaxed) >= 1, "prémisse : la lecture du plancher a bien été refusée");
                assert_eq!(rwnl_n_du_bucket(&conn, recent - 7200), 0, "prémisse : l'heure définitive n'a pas été agrégée");
                assert_eq!(rwnl_meta(&conn, META_ROLLUP_COV_ID), None, "plancher non lu : la couverture n'est PAS publiée, la route sert le brut");
            } else {
                assert_eq!(rwnl_n_du_bucket(&conn, recent - 7200), 1, "contrôle : plancher lu, l'heure est agrégée");
                assert_eq!(rwnl_meta(&conn, META_ROLLUP_COV_ID).map(|(_, v)| v), Some(id.to_string()), "contrôle : couverture publiée");
            }
        }
    }

    /// (g) Plancher NON LU mais RIEN DE SALE (watermark lu, couverture présente, aucune ligne tardive) : le rattrapage
    /// `[wm, recent)` ne dépend pas du plancher, la couverture reste PUBLIÉE. Sans la disjonction `|| dirty_lo.is_none()`
    /// de la garde, elle serait dépubliée : la route servirait le brut et le passage suivant, couverture absente,
    /// relancerait une reconstruction complète `[MIN(event.ts), recent)`. L'autorisateur laisse passer la bande sale
    /// (seule instruction qui lit `event.id` ET `event.ts`) puis refuse le `min` de l'instruction SUIVANTE — le
    /// plancher —, une seule fois (prémisse assertée).
    #[test]
    fn rwnl_un_plancher_non_lu_sans_rien_de_sale_publie_la_couverture() {
        let recent = rwnl_recent();
        let (st, _p) = sp_state("rwnl-plancher-propre");
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'rwnl','sshd',1,'m')", params![recent - 7200]).unwrap();
        let id = conn.last_insert_rowid();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]).unwrap();
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, id.to_string()]).unwrap();
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
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : le plancher a été refusé une fois, la bande sale lue");
        assert_eq!(rwnl_meta(&conn, META_ROLLUP_WM).map(|(_, v)| v), Some(recent.to_string()), "watermark à recent");
        assert_eq!(
            rwnl_meta(&conn, META_ROLLUP_COV_ID).map(|(_, v)| v),
            Some(id.to_string()),
            "plancher non lu, rien de sale : la couverture reste publiée (pas de dépublication ni de reconstruction complète au passage suivant)"
        );
    }
}
