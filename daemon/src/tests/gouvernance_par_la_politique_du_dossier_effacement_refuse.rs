// =====================================================================================
// `P10.31-v` — LA GOUVERNANCE DU TOUR SLA EST CELLE DE LA POLITIQUE DU DOSSIER, MÊME QUAND L'EFFACEMENT EST REFUSÉ.
//
// LE MANQUE, LU SUR ae63513b : `tpd_identifiant_pendant_sous_une_politique_active_de_meme_priorite_n_est_pas_juge`
// (tick_sla_jamais_au_nom_d_une_politique_desactivee.rs) ne rougit plus quand la gouvernance juge « une politique active
// de la même priorité » au lieu de la politique du dossier : depuis la vague BA, le tour EFFACE d'abord les échéances
// du dossier à identifiant pendant (`effacer_les_echeances_d_une_politique_inactive`, avant les sélections), et le
// dossier n'a plus rien à juger. La propriété n'avait plus de témoin capable de rougir quand une seule couche cède.
//
// CE QU'IL TIENT : P2 ACTIVE ; vingt dossiers D (P2) à identifiant PENDANT (999, politique disparue) échus de 1000 s ;
// E (P2, gouverné par la P2 active) échu de 10 s, plus récent qu'eux ; l'effacement est REFUSÉ par un déclencheur (le
// même que `epi_effacement_refuse_le_filtre_des_selections_…`). Le tour notifie et marque E seul, en acquittement ET en
// résolution ; les vingt gardent leurs échéances (rien n'est effacé) et ne sont ni notifiés ni marqués.
// MUTANTS (variable de mutation, posés sous `cfg!(test)` puis retirés avant le commit) :
// `BB5C_GOUVERNANCE_PAR_PRIORITE` (la gouvernance des deux sélections ET du marqueur devient
// `EXISTS(... p.priority=incident.priority AND p.enabled=1)` : les vingt D sont notifiés et marqués au nom de P2) et
// `BB5C_SELECTIONS_PAR_PRIORITE` (la même, dans les deux sélections seules : les vingt D occupent les vingt places de
// la fenêtre, le marqueur les refuse, E n'est pas notifié). Les deux sont VERTS sur le témoin `tpd_…` (effacement).
// CE QU'IL NE TIENT PAS : la gouvernance par priorité posée dans le SEUL marqueur (les sélections excluent déjà les D ;
// seule une course entre sélection et marqueur qui rendrait un dossier pendant sans effacer ses échéances la
// montrerait, et aucune route ne le fait : la suppression d'une politique efface les échéances dans sa transaction).
// =====================================================================================
mod gouvernance_par_la_politique_du_dossier_effacement_refuse {
    use super::*;

    const GPD_PENDANTE: i64 = 999;
    const GPD_REFUS: &str = "CREATE TRIGGER gpd_refus BEFORE UPDATE OF ack_due ON incident WHEN NEW.ack_due IS NULL \
                             BEGIN SELECT RAISE(ABORT,'effacement refuse par le temoin gpd'); END;";

    #[test]
    fn gpd_identifiant_pendant_sous_une_politique_active_de_meme_priorite_effacement_refuse_n_est_pas_juge() {
        let chemin = crate::tmp_possede::TmpDb::neuf("gpd-pendante-refus");
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('gpd','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        let n0 = now();
        let (p2, e) = {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P2',2,60,600,1,0,'root',0)",
                [],
            )
            .unwrap();
            let p2 = conn.last_insert_rowid();
            assert_ne!(p2, GPD_PENDANTE, "fixture : l'identifiant pendant n'est pas celui de P2");
            for i in 0..20 {
                let d = dossier_seme(&conn, "alice", &format!("D{i}"), 4, "", None, 2);
                conn.execute(
                    "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?2 WHERE id=?3",
                    params![GPD_PENDANTE, n0 - 1000, d],
                )
                .unwrap();
            }
            let e = dossier_seme(&conn, "alice", "E", 4, "", None, 2);
            conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![n0 - 10, e]).unwrap();
            conn.execute_batch(GPD_REFUS).unwrap();
            (p2, e)
        };
        let nombre = |sql: &str| -> i64 { st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(
            nombre(&format!("SELECT COUNT(*) FROM incident WHERE sla_policy_id={GPD_PENDANTE} AND ack_due<{} AND resolve_due<{}", n0 - 10, n0 - 10)),
            20,
            "fixture : vingt dossiers pendants, plus anciens que E"
        );
        assert_eq!(nombre(&format!("SELECT sla_policy_id FROM incident WHERE id={e}")), p2, "fixture : E gouverné par P2 active");

        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        assert_eq!(
            envois,
            vec![
                format!("Case #{e} « E » : SLA acquittement (MTTA) P2 dépassé."),
                format!("Case #{e} « E » : SLA résolution (MTTR) P2 dépassé."),
            ],
            "seul E est notifié ; les vingt pendants (politique disparue) ne le sont pas"
        );
        assert_eq!(
            nombre(&format!("SELECT COUNT(*) FROM incident WHERE sla_policy_id={GPD_PENDANTE} AND ack_due IS NOT NULL AND resolve_due IS NOT NULL")),
            20,
            "l'effacement refusé n'a rien effacé : les vingt gardent leurs échéances"
        );
        assert_eq!(
            nombre("SELECT COUNT(*) FROM incident WHERE ack_breached=1 OR resolve_breached=1"),
            1,
            "seul E est marqué, aucun pendant au nom de P2"
        );
        assert_eq!(nombre(&format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={e}")), 2, "E marqué deux fois");
    }
}
