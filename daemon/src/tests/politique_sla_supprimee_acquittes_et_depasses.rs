// =====================================================================================
// `P10.31-v` (volet démon, avancée) — LA SUPPRESSION D'UNE POLITIQUE DÉGOUVERNE AUSSI SES DOSSIERS ACQUITTÉS ET DÉJÀ EN
// DÉPASSEMENT D'ACQUITTEMENT.
//
// CE QUI MANQUAIT : tous les dossiers des témoins précédents étaient non acquittés et sans dépassement au moment de la
// suppression. Un `UPDATE` restreint par `AND ack_due IS NOT NULL`, `AND ack_breached=0` ou `AND first_response_ts IS NULL`
// laissait le `resolve_due` d'un dossier acquitté (le cas courant d'un dossier vivant) ou déjà en dépassement
// d'acquittement, et le tour notifiait « SLA résolution (MTTR) P1 dépassé » sur une politique disparue, sans qu'aucun
// témoin ne rougisse.
// CE QU'IL NE TIENT PAS : la console (`web/`) ; `sla_policy_upsert` ; les marqueurs `ack_breached` passés, conservés à
// dessein (le témoin le vérifie, il ne le change pas).
// =====================================================================================
mod politique_sla_supprimee_acquittes_et_depasses {
    use super::*;

    /// CE QU'IL TIENT : sous P1 (supprimée), Q1 acquitté avec `ack_due` NULL, Q2 acquitté avec `ack_due` figé, R déjà en
    /// dépassement d'acquittement (`ack_breached=1`) ; tous trois ont un `resolve_due` échu. Sous P2 (active), B échu.
    /// Après suppression de P1 : Q1, Q2 et R valent (None,None,None), le registre dit « 3 dossier(s) », le tour ne notifie
    /// ni Q1, ni Q2, ni R, et notifie B (contrôle : le tour tourne et notifie bien un dossier échu). Le marqueur
    /// `ack_breached=1` de R est conservé.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=K1U` (`AND ack_due IS NOT NULL` au WHERE), `VERIF_MUT=K1V`
    /// (`AND ack_breached=0`), `VERIF_MUT=K1W` (`AND first_response_ts IS NULL`).
    #[tokio::test]
    async fn pad_acquittes_et_deja_en_depassement_sont_degouvernes_et_non_notifies() {
        let chemin = crate::tmp_possede::TmpDb::neuf("pad-acq");
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        let t = now();
        let (p1, q1, q2, r, b) = {
            let conn = st.db.lock();
            let politique = |nom: &str, pr: i64| -> i64 {
                conn.execute(
                    "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
                    params![nom, pr],
                )
                .unwrap();
                conn.last_insert_rowid()
            };
            let p1 = politique("P1", 1);
            let p2 = politique("P2", 2);
            let dossier = |titre: &str, pr: i64, pid: i64, ack_due: Option<i64>, ack_breached: i64, premiere_reponse: Option<i64>| -> i64 {
                let id = dossier_seme(&conn, "alice", titre, 4, "", None, pr);
                conn.execute(
                    "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?3, ack_breached=?4, first_response_ts=?5 WHERE id=?6",
                    params![pid, ack_due, t - 100, ack_breached, premiere_reponse, id],
                )
                .unwrap();
                id
            };
            let q1 = dossier("Q1", 1, p1, None, 0, Some(t - 50));
            let q2 = dossier("Q2", 1, p1, Some(t + 100_000), 0, Some(t - 50));
            let r = dossier("R", 1, p1, Some(t - 200), 1, None);
            let b = dossier("B", 2, p2, Some(t + 100_000), 0, Some(t - 50));
            conn.execute_batch("INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pad','webhook',1,'https://example.invalid/h',0,'{}')")
                .unwrap();
            (p1, q1, q2, r, b)
        };
        let chrono = |id: i64| -> (Option<i64>, Option<i64>, Option<i64>) {
            st.db
                .lock()
                .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |x| {
                    Ok((x.get(0)?, x.get(1)?, x.get(2)?))
                })
                .unwrap()
        };
        let au = AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let rep = sla_policy_delete(State(st.clone()), Extension(au), Path(p1)).await.into_response();
        let statut = rep.status().as_u16();
        let corps = axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap().to_vec();
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "suppression réussie : 204, corps vide");
        assert_eq!(chrono(q1), (None, None, None), "Q1, acquitté avec ack_due NULL, est dégouverné");
        assert_eq!(chrono(q2), (None, None, None), "Q2, acquitté avec ack_due figé, est dégouverné");
        assert_eq!(chrono(r), (None, None, None), "R, déjà en dépassement d'acquittement, est dégouverné");
        let details: Vec<String> = {
            let conn = st.db.lock();
            let mut s = conn.prepare("SELECT detail FROM ledger WHERE kind='sla_policy.delete'").unwrap();
            s.query_map([], |x| x.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        assert_eq!(
            details,
            vec![format!("#{p1} by analyste ; 3 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)")],
            "les trois dossiers comptés"
        );

        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        for (nom, id) in [("Q1", q1), ("Q2", q2), ("R", r)] {
            assert!(
                !envois.iter().any(|d| d.starts_with(&format!("Case #{id} "))),
                "{nom}, gouverné par une politique supprimée, n'est pas notifié : {envois:?}"
            );
        }
        assert!(
            envois.iter().any(|d| d.starts_with(&format!("Case #{b} ")) && d.contains("résolution (MTTR)")),
            "contrôle : B, échu sous P2 active, est notifié en MTTR : {envois:?}"
        );
        let marqueur_r = st
            .db
            .lock()
            .query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![r], |x| {
                Ok((x.get::<_, i64>(0)?, x.get::<_, i64>(1)?))
            })
            .unwrap();
        assert_eq!(marqueur_r, (1, 0), "R garde son marqueur d'acquittement passé, aucun dépassement MTTR marqué");
    }
}
