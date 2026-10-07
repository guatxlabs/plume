// =====================================================================================
// `P10.20-w` (rang trois) — LA FUSION, LA DÉFUSION ET L'ESCALADE SLA COMPTENT LEUR ÉCRITURE AVANT LE FAIT.
//
// CE QUE CES TÉMOINS TIENNENT. `case_merge` et `case_unmerge` (caseops.rs) avalaient leur `UPDATE incident`
// puis posaient deux (ou une) lignes de chronologie, une ligne `case.merge`/`case.unmerge` au registre non
// purgeable, et la route rendait 204 : une fusion que la base n'avait pas prise était ATTESTÉE. Et
// `escalate_overdue_cases` (cases.rs) envoyait la notification, AVALAIT `UPDATE incident SET escalated=1`,
// puis attestait l'escalade : `escalated` restant à 0, le dossier restait sélectionné et CHAQUE tick
// renvoyait la même notification, avec une ligne `case.sla_escalate` de plus au registre (désormais : la
// notification est renvoyée à chaque tour, AVOUANT l'escalade non enregistrée, mais le registre se tait). Les témoins
// jouent la table `incident` rendue NON MODIFIABLE (vue temporaire de même nom, comme les témoins `ecf_` :
// la lecture passe, seule l'écriture échoue), comptent registre, chronologie et ENVOIS, puis rejouent
// la base saine pour prouver que la sortie d'avant est intacte (contrôle positif, texte des traces relu).
//
// CE QU'ILS NE TIENNENT PAS : aucune base réellement en lecture seule (le chemin refusé est le même) ;
// le bras `Ok(0)` (dossier disparu entre le jugement et l'écriture) n'est pas fabriqué ; rien de ce que
// la console PEINT de ces deux 503 neufs ; aucun envoi réseau réel (l'envoyeur est injecté) ; les sites
// restants du rang trois (`sla_multilevel_tick`, `case_apply_update`, `case_set_archived`, `step_advance`).
// =====================================================================================
mod fusion_et_escalade_comptees {
    use super::*;

    fn fec_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("fec-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-w` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn fec_editeur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn fec_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn fec_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn fec_texte(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn fec_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    fn fec_table_incident_non_modifiable(st: &AppState) {
        fec_ecrire(st, "ALTER TABLE incident RENAME TO incident_source; CREATE TEMP VIEW incident AS SELECT * FROM incident_source;");
    }

    fn fec_table_incident_modifiable(st: &AppState) {
        fec_ecrire(st, "DROP VIEW incident; ALTER TABLE incident_source RENAME TO incident;");
    }

    fn fec_deux_dossiers(st: &AppState) -> (i64, i64) {
        let conn = st.db.lock();
        (dossier_seme(&conn, "alice", "A", 3, "", None, 2), dossier_seme(&conn, "alice", "B", 3, "", None, 2))
    }

    async fn fec_fusionner(st: &AppState, de: i64, vers: i64) -> (u16, Value) {
        pb_json(case_merge_handler(State(st.clone()), Extension(fec_editeur()), Path(de), Json(json!({ "into": vers }))).await).await
    }

    async fn fec_defusionner(st: &AppState, de: i64) -> (u16, Value) {
        pb_json(case_unmerge_handler(State(st.clone()), Extension(fec_editeur()), Path(de)).await).await
    }

    /// CE QU'IL TIENT (`case_merge`) : la fusion que la base refuse d'écrire sort en 503 NOMMÉ, sans ligne
    /// `case.merge` au registre ni élément de chronologie, et la source n'est PAS fusionnée ; la fonction rend
    /// `NonEcrite`. Contrôle positif dans le même corps : la base saine rend 204, la source porte `merged_into`,
    /// et les traces sont EXACTEMENT celles d'avant (textes relus).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : avaler l'`UPDATE` de `case_merge` (`let _ =`, ou le bras `Err` qui
    /// continue) — la route redevient 204 et le registre gagne `case.merge` sur une fusion non faite.
    #[tokio::test]
    async fn fec_une_fusion_non_ecrite_n_est_ni_un_deux_cent_quatre_ni_une_ligne_de_registre() {
        let (st, _tmp) = fec_etat("fusion");
        let (a, b) = fec_deux_dossiers(&st);

        fec_table_incident_non_modifiable(&st);
        let registre_avant = fec_compte(&st, "SELECT COUNT(*) FROM ledger");
        let chronologie_avant = fec_compte(&st, "SELECT COUNT(*) FROM incident_item");
        let (statut, avoue) = fec_fusionner(&st, a, b).await;
        assert_eq!(statut, 503, "fusion non écrite : 503 nommé, jamais un 204 : {avoue}");
        assert!(fec_phrase(&avoue).starts_with(CAUSE_FUSION_NON_ECRITE), "le refus NOMME sa cause : {avoue}");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM ledger"), registre_avant, "aucune ligne `case.merge` n'atteste une fusion non faite");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM incident_item"), chronologie_avant, "et aucune chronologie ne la raconte");
        {
            let conn = st.db.lock();
            assert!(matches!(case_merge(&conn, a, b, "analyste"), IssueDeLaFusion::NonEcrite(_)), "la fonction NOMME l'écriture refusée");
        }
        fec_table_incident_modifiable(&st);
        assert_eq!(fec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into IS NULL")), 1, "la source n'est PAS fusionnée");

        // CONTRÔLE POSITIF — la sortie d'avant, octet pour octet.
        let (statut, corps) = fec_fusionner(&st, a, b).await;
        assert_eq!(statut, 204, "base saine : 204, comme avant : {corps}");
        assert_eq!(fec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into={b} AND status='closed'")), 1);
        assert_eq!(fec_texte(&st, "SELECT detail FROM ledger WHERE kind='case.merge'"), vec![format!("#{a} -> #{b} by analyste")]);
        assert_eq!(
            fec_texte(&st, "SELECT body FROM incident_item WHERE kind='merge' ORDER BY id"),
            vec![format!("fusionné dans #{b}"), format!("#{a} fusionné ici (timeline combinée)")]
        );
    }

    /// CE QU'IL TIENT (`case_unmerge`) : la défusion que la base refuse d'écrire sort en 503 NOMMÉ, sans ligne
    /// `case.unmerge` ni élément de chronologie, et le dossier reste fusionné. Contrôle positif : 204, dossier
    /// rouvert en `triage`, traces d'avant relues mot pour mot.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : avaler l'`UPDATE` de `case_unmerge` — 204 et `case.unmerge` au registre
    /// sur un dossier toujours fusionné.
    #[tokio::test]
    async fn fec_une_defusion_non_ecrite_laisse_le_dossier_fusionne_et_le_registre_muet() {
        let (st, _tmp) = fec_etat("defusion");
        let (a, b) = fec_deux_dossiers(&st);
        assert_eq!(fec_fusionner(&st, a, b).await.0, 204, "fixture : la fusion est posée");

        fec_table_incident_non_modifiable(&st);
        let registre_avant = fec_compte(&st, "SELECT COUNT(*) FROM ledger");
        let chronologie_avant = fec_compte(&st, "SELECT COUNT(*) FROM incident_item");
        let (statut, avoue) = fec_defusionner(&st, a).await;
        assert_eq!(statut, 503, "défusion non écrite : 503 nommé, jamais un 204 : {avoue}");
        assert!(fec_phrase(&avoue).starts_with(CAUSE_DEFUSION_NON_ECRITE), "le refus NOMME sa cause : {avoue}");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM ledger"), registre_avant, "aucune ligne `case.unmerge`");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM incident_item"), chronologie_avant, "aucune chronologie");
        fec_table_incident_modifiable(&st);
        assert_eq!(fec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into={b}")), 1, "le dossier est TOUJOURS fusionné");

        // CONTRÔLE POSITIF — la sortie d'avant, octet pour octet.
        assert_eq!(fec_defusionner(&st, a).await.0, 204, "base saine : 204, comme avant");
        assert_eq!(fec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into IS NULL AND status='triage'")), 1);
        assert_eq!(fec_texte(&st, "SELECT detail FROM ledger WHERE kind='case.unmerge'"), vec![format!("#{a} <- #{b} by analyste")]);
        assert_eq!(
            fec_texte(&st, &format!("SELECT body FROM incident_item WHERE incident_id={a} AND kind='merge' ORDER BY id DESC LIMIT 1")),
            vec![format!("dé-fusionné de #{b} (ré-ouvert)")]
        );
    }

    /// CE QU'IL TIENT (`escalate_overdue_cases`) : un marqueur `escalated` que la base refuse d'écrire ne fait PAS taire
    /// un SLA réellement dépassé — DEUX dossiers en retard sur DEUX ticks : quatre envois (un par dossier et par tick,
    /// renvoyés comme avant le lot), chacun AVOUANT `ESCALADE_NON_ENREGISTREE` — mais ni `case.sla_escalate` ni
    /// chronologie, et le refus compté UNE fois par TOUR (+2 pour deux ticks, pas +4). Contrôle positif : la base saine,
    /// deux ticks -> UN envoi par dossier, sans aveu, une ligne de registre et une chronologie chacun, aux textes d'avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, une par site : (a) bras `Err` sans envoi (la forme du lot avant correction) ->
    /// zéro envoi ; (b) bras `Err` qui trace comme un marqueur écrit (la forme d'avant le lot) -> registre et chronologie
    /// non vides ; (c) compter par dossier dans le bras `Err` -> +4 ; (d) envoyer le `detail` nu -> aveu absent.
    #[test]
    fn fec_un_marqueur_d_escalade_non_ecrit_notifie_quand_meme_en_l_avouant_sans_s_inscrire_au_registre() {
        let (st, _tmp) = fec_etat("escalade");
        let ids: Vec<i64> = {
            let conn = st.db.lock();
            let base = now() - 200;
            let ids: Vec<i64> = ["En retard un", "En retard deux"]
                .iter()
                .enumerate()
                .map(|(i, titre)| {
                    let id = dossier_seme(&conn, "alice", titre, 4, "", None, 1);
                    conn.execute("UPDATE incident SET sla_due=?1 WHERE id=?2", params![base + i as i64, id]).unwrap();
                    id
                })
                .collect();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('fec_canal','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
            ids
        };
        let dossiers: Vec<(i64, String, i64, i64)> = ids
            .iter()
            .map(|id| {
                st.db
                    .lock()
                    .query_row("SELECT id,COALESCE(title,''),priority,sla_due FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                    .unwrap()
            })
            .collect();
        let mut envois: Vec<(String, String)> = Vec::new();
        let aveugles = || crate::metrics::tick_aveugle_de("escalate_overdue_marqueur").map(|(n, _)| n).unwrap_or(0);
        let aveu = crate::handlers::cases::ESCALADE_NON_ENREGISTREE;

        fec_table_incident_non_modifiable(&st);
        let aveugles_avant = aveugles();
        for _ in 0..2 {
            escalate_overdue_cases_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, titre: &str, detail: &str, _h: &str, _t: i64| {
                envois.push((titre.to_string(), detail.to_string()));
                true
            });
        }
        assert_eq!(envois.len(), 4, "un SLA dépassé ne se TAIT pas : un envoi par dossier et par tick, malgré le marqueur refusé : {envois:?}");
        assert!(envois.iter().all(|(_, d)| d.ends_with(aveu)), "chaque envoi AVOUE l'escalade non enregistrée : {envois:?}");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.sla_escalate'"), 0, "aucune escalade attestée au registre");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'"), 0, "aucune chronologie");
        assert_eq!(aveugles(), aveugles_avant + 2, "le refus est COMPTÉ une fois par TOUR, pas une fois par dossier (/metrics)");
        fec_table_incident_modifiable(&st);
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM incident WHERE escalated=1"), 0, "aucun marqueur n'est posé");

        // CONTRÔLE POSITIF — deux ticks sur la base saine : un envoi par dossier, sans aveu, une trace chacun, aux textes d'avant.
        envois.clear();
        for _ in 0..2 {
            escalate_overdue_cases_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, titre: &str, detail: &str, _h: &str, _t: i64| {
                envois.push((titre.to_string(), detail.to_string()));
                true
            });
        }
        let attendu = |(id, titre, priorite, echeance): &(i64, String, i64, i64)| format!("Case #{id} « {titre} » : SLA P{priorite} dépassé (échéance {echeance}).");
        assert_eq!(
            envois,
            dossiers.iter().map(|d| (format!("SLA dépassé : {}", d.1), attendu(d))).collect::<Vec<_>>(),
            "UN envoi par dossier sur deux ticks, sans aveu"
        );
        assert_eq!(aveugles(), aveugles_avant + 2, "base saine : plus aucun refus compté");
        assert_eq!(fec_compte(&st, "SELECT COUNT(*) FROM incident WHERE escalated=1"), 2);
        assert_eq!(
            fec_texte(&st, "SELECT detail FROM ledger WHERE kind='case.sla_escalate' ORDER BY id"),
            dossiers.iter().map(|(id, _, p, e)| format!("#{id} P{p} sla_due={e}")).collect::<Vec<_>>()
        );
        assert_eq!(fec_texte(&st, "SELECT body FROM incident_item WHERE kind='sla' ORDER BY id"), dossiers.iter().map(attendu).collect::<Vec<_>>());
    }
}
