// =====================================================================================
// `P10.31-v` (volet démon, suite) — LA SUPPRESSION D'UNE POLITIQUE DÉGOUVERNE AUSSI LES DOSSIERS QUE LE TOUR SAUTE.
//
// CE QUI MANQUAIT, MESURÉ PAR LE VÉRIFICATEUR SUR fa0c3b5 : les témoins `psd_` ne gouvernaient que des dossiers ouverts,
// sans pause, non fusionnés — exactement ceux que `sla_multilevel_tick_par` lit. Un `UPDATE` borné à
// `status NOT IN ('resolved','closed','contained')`, à `sla_paused_since IS NULL` ou à `merged_into IS NULL` restait vert,
// alors qu'un dossier rouvert (le changement de statut ne rejoue pas `sla_apply_policy`), repris de pause ou défusionné
// (`case_unmerge` ne le rejoue pas non plus) garde alors les échéances d'une politique disparue et le tour le NOTIFIE.
// Le code du lot était juste ; ce sont ses témoins qui ne le tenaient pas.
//
// CE QU'ILS TIENNENT : un dossier terminal, un en pause, un fusionné sous P1 -> (None, None, None) chacun et
// « 3 dossier(s) » au registre ; la pause en cours conservée (`sla_paused_since`) et reprise à la sortie de `waiting`
// (cumul crédité) ; rouverts / repris / défusionnés, le tour ne les notifie pas, alors qu'il notifie toujours un dossier
// échu de P2 (contrôle : le tour a bien tourné) ; un dossier NON gouverné portant des échéances orphelines n'est pas
// touché (seul état où un `WHERE` élargi aux non-gouvernés se verrait sur le dossier lui-même, et pas seulement au compte).
// CE QU'ILS NE TIENNENT PAS : la route de changement de statut elle-même (le témoin rouvre par `UPDATE` direct et
// `sla_on_status_change`, la forme que `cases.rs` enchaîne) ; la route HTTP de défusion (le témoin appelle
// `case_unmerge`) ; un dossier non gouverné à échéances orphelines est un état fabriqué, aucun chemin connu ne le produit.
// Mutants (VERIF_MUT, retirés avant le commit) nommés sur le témoin.
// =====================================================================================
mod politique_sla_supprimee_terminaux_pause_fusion {
    use super::*;

    fn pst_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pst-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn pst_admin() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn pst_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pst_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn pst_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé, puis `UPDATE incident SET <reglage> WHERE id=<id>` (le réglage porte politique, échéances, statut…).
    fn pst_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            pst_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    fn pst_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }

    fn pst_tick(st: &AppState) -> Vec<String> {
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    /// CE QU'IL TIENT : sous P1, T terminal (`resolved`), W en pause (`waiting`, `sla_paused_since` posé), F fusionné
    /// (`merged_into`, `closed`), tous échus ; N non gouverné avec échéances orphelines ; P2 active (B échu). Supprimer
    /// P1 : 204, T/W/F à (None, None, None), pause de W conservée, N et B intacts, registre « 3 dossier(s) ». Puis T
    /// rouvert, W repris (`sla_on_status_change` = `Ecrit`, cumul >= 100 s), F défusionné (`case_unmerge` = `Ecrite`) :
    /// le tour ne notifie ni T, ni W, ni F, ne marque aucun dépassement sur eux, et notifie toujours B.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=J7_EXCLUT_TERMINAUX` (`AND status NOT IN (...)`),
    /// `VERIF_MUT=J7_EXCLUT_PAUSE` (`AND sla_paused_since IS NULL`), `VERIF_MUT=J7_EXCLUT_FUSIONNES`
    /// (`AND merged_into IS NULL`), `VERIF_MUT=J7_EFFACE_PAUSE` (`sla_paused_since=NULL` ajouté à l'effacement),
    /// `VERIF_MUT=J7_ENGLOBE_NON_GOUVERNES` (`OR sla_policy_id IS NULL`).
    #[tokio::test]
    async fn pst_terminal_pause_et_fusionne_degouvernes_puis_rouverts_ne_sont_pas_notifies() {
        let (st, _t) = pst_etat("tpf");
        let p1 = pst_politique(&st, "P1", 1);
        let p2 = pst_politique(&st, "P2", 2);
        let n0 = now();
        let echu = n0 - 100;
        let pause_depuis = n0 - 100;
        let t = pst_dossier(&st, "T", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}, status='resolved'"));
        let w = pst_dossier(
            &st,
            "W",
            1,
            &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}, status='waiting', sla_paused_since={pause_depuis}", n0 - 10_000, n0 - 10_000),
        );
        let x = pst_dossier(&st, "X", 3, "");
        let f = pst_dossier(&st, "F", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}, merged_into={x}, status='closed'"));
        let n = pst_dossier(&st, "N", 3, &format!("sla_policy_id=NULL, ack_due={}, resolve_due={}", n0 + 100_000, n0 + 100_000));
        let b = pst_dossier(&st, "B", 2, &format!("sla_policy_id={p2}, ack_due={echu}, resolve_due={echu}"));
        pst_sql(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pst','webhook',1,'https://example.invalid/h',0,'{}')");
        let chrono_n = pst_chrono(&st, n);
        assert!(chrono_n.1.is_some(), "fixture : N porte des échéances orphelines");
        let chrono_b = pst_chrono(&st, b);

        let r = sla_policy_delete(State(st.clone()), Extension(pst_admin()), Path(p1)).await.into_response();
        assert_eq!(r.status().as_u16(), 204, "suppression réussie, maillon inscrit");
        assert_eq!(pst_chrono(&st, t), (None, None, None), "T, TERMINAL, est dégouverné aussi");
        assert_eq!(pst_chrono(&st, w), (None, None, None), "W, EN PAUSE, est dégouverné aussi");
        assert_eq!(pst_chrono(&st, f), (None, None, None), "F, FUSIONNÉ, est dégouverné aussi");
        assert_eq!(
            pst_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={w}")),
            Some(pause_depuis),
            "la pause en cours de W est conservée"
        );
        assert_eq!(pst_chrono(&st, n), chrono_n, "N, non gouverné, n'est pas touché (échéances orphelines intactes)");
        assert_eq!(pst_chrono(&st, b), chrono_b, "B, gouverné par P2, intact");
        assert_eq!(
            pst_entier(&st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"),
            Some(1),
            "un seul registre de suppression"
        );
        let detail: String = st
            .db
            .lock()
            .query_row("SELECT detail FROM ledger WHERE kind='sla_policy.delete'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            detail,
            format!("#{p1} by analyste ; 3 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)"),
            "le compte exact : les trois dossiers sautés par le tour, pas N, pas B"
        );

        // Réouverture, reprise, défusion : aucune ne rejoue `sla_apply_policy`.
        pst_sql(&st, &format!("UPDATE incident SET status='triage', closed_ts=NULL WHERE id={t}"));
        {
            let conn = st.db.lock();
            assert_eq!(crate::handlers::caseops::sla_on_status_change(&conn, w, "triage", now()), crate::handlers::caseops::IssueDuChronoSla::Ecrit, "W repris sans politique portée");
        }
        pst_sql(&st, &format!("UPDATE incident SET status='triage' WHERE id={w}"));
        assert_eq!(pst_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={w}")), None, "pause levée");
        assert!(
            pst_entier(&st, &format!("SELECT sla_pause_accum FROM incident WHERE id={w}")).unwrap_or(0) >= 100,
            "le temps de pause est crédité au cumul"
        );
        {
            let conn = st.db.lock();
            assert_eq!(crate::handlers::caseops::case_unmerge(&conn, f, "alice"), crate::handlers::caseops::IssueDeLaFusion::Ecrite, "F défusionné");
        }

        let envois = pst_tick(&st);
        assert!(!envois.iter().any(|d| d.starts_with(&format!("Case #{t} "))), "T rouvert notifié sur une politique disparue : {envois:?}");
        assert!(!envois.iter().any(|d| d.starts_with(&format!("Case #{w} "))), "W repris notifié sur une politique disparue : {envois:?}");
        assert!(!envois.iter().any(|d| d.starts_with(&format!("Case #{f} "))), "F défusionné notifié sur une politique disparue : {envois:?}");
        assert!(envois.iter().any(|d| d.starts_with(&format!("Case #{b} "))), "contrôle : B, échu sous P2 active, est notifié : {envois:?}");
        for (nom, id) in [("T", t), ("W", w), ("F", f)] {
            assert_eq!(
                pst_entier(&st, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={id}")),
                Some(0),
                "aucun dépassement marqué sur {nom}"
            );
        }
    }
}
