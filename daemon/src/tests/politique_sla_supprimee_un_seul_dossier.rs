// =====================================================================================
// `P10.31-v` (volet démon, avancée) — LE REGISTRE DIT LE NOMBRE DE DOSSIERS DÉGOUVERNÉS DÈS LE PREMIER.
//
// CE QUI MANQUAIT : les témoins de `sla_policy_delete` relisaient le registre à 0 dossier (détail d'avant), à 2 et à 3,
// jamais à UN seul (`psd_maillon_refuse_est_avoue` a un dossier, mais le registre y est refusé, donc rien n'est relu).
// Une borne `degouvernes > 1` au lieu de `> 0` écrivait « #id by analyste » pour un dossier dégouverné, exactement
// comme pour aucun, sans qu'aucun témoin ne rougisse.
// CE QU'IL NE TIENT PAS : la console (`web/`) ; `sla_policy_upsert` (politique modifiée ou désactivée).
// =====================================================================================
mod politique_sla_supprimee_un_seul_dossier {
    use super::*;

    /// CE QU'IL TIENT : une politique qui gouverne UN SEUL dossier ; la supprimer rend 204, corps vide, le dossier perd
    /// ses trois colonnes, et le registre porte mot pour mot « #id by analyste ; 1 dossier(s) dégouverné(s) : … ».
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=K14` (`degouvernes > 0` devenu `> 1`), `VERIF_MUT=K15` (détail muet).
    #[tokio::test]
    async fn pud_un_seul_dossier_degouverne_le_registre_dit_1() {
        let chemin = crate::tmp_possede::TmpDb::neuf("pud-un");
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        let (pid, id) = {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)",
                [],
            )
            .unwrap();
            let pid = conn.last_insert_rowid();
            let id = dossier_seme(&conn, "alice", "Seul", 4, "", None, 1);
            conn.execute(
                "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?2 WHERE id=?3",
                params![pid, now() - 100, id],
            )
            .unwrap();
            (pid, id)
        };
        let au = AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let r = sla_policy_delete(State(st.clone()), Extension(au), Path(pid)).await.into_response();
        let statut = r.status().as_u16();
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec();
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "suppression réussie, maillon inscrit : 204, corps vide");
        let chrono: (Option<i64>, Option<i64>, Option<i64>) = st
            .db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(chrono, (None, None, None), "le seul dossier de la politique est dégouverné");
        let details: Vec<String> = {
            let conn = st.db.lock();
            let mut s = conn.prepare("SELECT detail FROM ledger WHERE kind='sla_policy.delete'").unwrap();
            s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        assert_eq!(
            details,
            vec![format!("#{pid} by analyste ; 1 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)")],
            "UN dossier dégouverné : le registre le dit, il ne se confond pas avec zéro"
        );
    }
}
