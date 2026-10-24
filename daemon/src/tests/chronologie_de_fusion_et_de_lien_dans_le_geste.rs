// =====================================================================================
// `P10.33-k` (reste « `case_add_item` chez ses autres appelants ») et `P10.31-u` (maillons nus de la fusion, de la
// défusion, du lien et du tick SLA) — LA CHRONOLOGIE FAIT PARTIE DU GESTE, LE MAILLON MANQUANT EST AVOUÉ.
//
// LE DÉFAUT, MESURÉ SUR aa5556fd. `case_merge`, `case_unmerge` et `case_link_add` (caseops.rs) posaient leurs éléments de
// chronologie par `case_add_item`, qui AVALE (`let _ = ajouter_l_element_au_dossier(..)`), APRÈS l'écriture comptée,
// puis appelaient `ledger_append` sans lire son issue : une chronologie refusée rendait quand même `Ecrite`/`Pose` et
// 204 (fusion sans trace dans les deux dossiers, MTTA non figé), un maillon refusé un 204 muet. `with_write` ne prend que
// le verrou de l'écrivain (`query_exec.rs`), AUCUNE transaction : rien n'englobait le geste. Le tick SLA multi-niveau
// avait le même défaut, après l'envoi : marqueur posé, notification sans aveu, chronologie absente, jamais renvoyée.
//
// DÉCISION PAR DÉFAUT (vague AB) : jugement, écriture, chronologies (`ajouter_l_element_au_dossier`, comptées) et maillon
// dans UNE transaction (`jouer_le_geste_garde`, patron de `sla_policy_upsert`) ; chronologie, `BEGIN` ou `COMMIT`
// refusés -> geste annulé, 503 nommé existant (`CAUSE_FUSION_NON_ECRITE`, `CAUSE_DEFUSION_NON_ECRITE`,
// `CAUSE_LIEN_NON_POSE`) ; maillon manquant -> 200 `{ok, registre_sans_maillon}`, geste NON annulé. Tick SLA : marqueur,
// chronologie et maillon validés ensemble AVANT l'envoi ; chronologie, `BEGIN` ou `COMMIT` refusés suivent le chemin du
// marqueur refusé (envoi avec l'aveu, rien d'inscrit, compté au balayage `sla_multilevel_marqueur`, renvoyé au tour
// suivant) ; un maillon manquant n'annule RIEN (marqué, chronologie écrite, envoi nominal, jamais renvoyé).
//
// LES REFUS SONT FABRIQUÉS par des triggers temporaires `RAISE(ABORT)` (chronologie, registre), une transaction laissée
// ouverte sur l'écrivain (`BEGIN` refusé) et une clé étrangère DIFFÉRÉE violée (`COMMIT` refusé). Après un `BEGIN`
// refusé, l'état est lu AVANT le `ROLLBACK` du témoin, sur la même connexion : une écriture faite par erreur dans la
// transaction étrangère s'y voit encore (le `ROLLBACK` l'effacerait). Les témoins du tick qui lisent le balayage
// `sla_multilevel_marqueur` (compteur global du processus) en différence exacte se sérialisent avec le témoin `dec_` par
// `VERROU_DU_BALAYAGE_SLA_MULTILEVEL_MARQUEUR`.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console fait du 200 `registre_sans_maillon` sur ces trois routes (web/ hors
// périmètre) ; un `ROLLBACK` refusé ; aucun témoin de course sur le verrou du balayage (sous nextest, un processus par
// témoin, la course n'existe pas). RESTES de `P10.33-k`, non touchés : les autres appelants de `case_add_item`, qui
// avalent toujours — cases.rs création (`created`), assignation (`assign`), priorité (`priority`), statut (`status`),
// verdict effacé et posé (`disposition`), escalade (`sla`), archivage et désarchivage — et le maillon `case.unlink` de
// `case_link_remove` (caseops.rs), toujours jeté.
//
// MUTANTS JOUÉS (VERIF_MUT sous cfg!(test), retirés avant le commit), chacun vu ROUGE : `ab3_fusion_chrono_avalee`,
// `ab3_fusion_chrono_cible_avalee`, `ab3_fusion_hors_transaction`, `ab3_fusion_maillon_jete`, `ab3_fusion_maillon_annule`,
// `ab3_fusion_refus_de_transaction_ecrit`, `ab3_route_fusion_204`, `ab3_defusion_chrono_avalee`, `ab3_route_defusion_204`,
// `ab3_lien_chrono_avalee`, `ab3_lien_chrono_second_avalee`, `ab3_lien_hors_transaction`, `ab3_lien_maillon_jete`,
// `ab3_lien_refus_de_transaction_pose`, `ab3_route_lien_204`, `ab3_sla_chrono_avalee`, `ab3_sla_hors_transaction`,
// `ab3_sla_refus_tait`, `ab3_sla_refus_de_transaction_tait` ; puis, à la relecture : `M_SLA_NONVALIDE_TAIT` (`COMMIT`
// refusé lu comme validé), `M_SLA_MAILLON_REFUS` (maillon manquant lu comme refus), `M_FUSION_BEGIN_ECRIT`,
// `M_LIEN_BEGIN_POSE`, `M_SLA_BEGIN_MARQUE` (écriture dans la transaction étrangère après un `BEGIN` refusé, que le
// `ROLLBACK` du témoin effaçait avant la lecture), `M_REPONSE_PARTAGEE_SANS_CAUSE` (corps partagé sans la cause).
// =====================================================================================
mod chronologie_de_fusion_et_de_lien_dans_le_geste {
    use super::*;

    fn ab3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ab3-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ab3_editeur() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ab3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ab3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ab3_textes(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn ab3_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// L'état d'un dossier que le geste écrit : `merged_into`, statut, `closed_ts`, `updated`, `first_response_ts`.
    fn ab3_dossier(st: &AppState, id: i64) -> (Option<i64>, String, Option<i64>, i64, Option<i64>) {
        st.db
            .lock()
            .query_row(
                "SELECT merged_into, status, closed_ts, updated, first_response_ts FROM incident WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("fixture : le dossier se lit")
    }

    /// Deux dossiers dont `updated` est ramené dans le passé : une écriture annulée se voit à `updated` inchangé.
    fn ab3_deux_dossiers(st: &AppState) -> (i64, i64) {
        let conn = st.db.lock();
        let a = dossier_seme(&conn, "alice", "A", 3, "", None, 2);
        let b = dossier_seme(&conn, "alice", "B", 3, "", None, 2);
        conn.execute("UPDATE incident SET updated=1000 WHERE id IN (?1,?2)", params![a, b]).unwrap();
        (a, b)
    }

    async fn ab3_fusionner(st: &AppState, de: i64, vers: i64) -> (u16, Value) {
        pb_json(case_merge_handler(State(st.clone()), Extension(ab3_editeur()), Path(de), Json(json!({ "into": vers }))).await).await
    }

    async fn ab3_defusionner(st: &AppState, de: i64) -> (u16, Value) {
        pb_json(case_unmerge_handler(State(st.clone()), Extension(ab3_editeur()), Path(de)).await).await
    }

    async fn ab3_lier(st: &AppState, a: i64, b: i64) -> (u16, Value) {
        pb_json(case_link_handler(State(st.clone()), Extension(ab3_editeur()), Path(a), Json(json!({ "to": b, "kind": "duplicate" }))).await).await
    }

    fn ab3_refuser_l_element(st: &AppState, condition: &str) {
        ab3_sql(
            st,
            &format!("CREATE TEMP TRIGGER ab3_element BEFORE INSERT ON incident_item WHEN {condition} BEGIN SELECT RAISE(ABORT, 'ab3 chronologie refusée'); END;"),
        );
    }

    fn ab3_refuser_le_maillon(st: &AppState, genre: &str) {
        ab3_sql(
            st,
            &format!("CREATE TEMP TRIGGER ab3_maillon BEFORE INSERT ON ledger WHEN NEW.kind='{genre}' BEGIN SELECT RAISE(ABORT, 'ab3 maillon refusé'); END;"),
        );
    }

    /// `COMMIT` refusé : clé étrangère DIFFÉRÉE violée par un trigger sur l'élément de chronologie (patron `pde_`).
    fn ab3_refuser_le_commit(st: &AppState) {
        ab3_sql(
            st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE ab3_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE ab3_enfant(p INTEGER REFERENCES ab3_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER ab3_fk AFTER INSERT ON incident_item BEGIN INSERT INTO ab3_enfant VALUES(999); END;",
        );
    }

    fn ab3_lever_le_commit(st: &AppState) {
        ab3_sql(st, "DROP TRIGGER ab3_fk; DROP TABLE ab3_enfant; DROP TABLE ab3_parent; PRAGMA foreign_keys=OFF;");
    }

    // INVERSÉ NOMMÉMENT par `P10.29-l` (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, plus le texte du moteur.
    fn ab3_maillon_avoue(corps: &Value) -> bool {
        corps.get("ok") == Some(&json!(true))
            && corps.get(CLE_REGISTRE_SANS_MAILLON).and_then(|v| v.as_str()).is_some_and(|p| p == format!("{CAUSE_GESTE_SANS_TRACE} ({CAUSE_MAILLON_NON_ECRIT})"))
    }

    /// CE QU'IL TIENT (`case_merge`, par la route) : la chronologie de la SOURCE, puis celle de la CIBLE, refusée -> 503
    /// `{error: CAUSE_FUSION_NON_ECRITE, id}` seul (la chronologie nommée au journal, `P10.29-l`), et RIEN n'est écrit : source non fusionnée ni close, `updated`
    /// et `first_response_ts` des deux dossiers inchangés, aucun élément `merge` (celui de la source, posé avant le refus
    /// de la cible, est annulé avec le reste), aucun `case.merge`, aucune transaction laissée ouverte. Contrôle positif :
    /// le trigger levé, 204 et les traces d'avant mot pour mot, MTTA figé sur les deux dossiers.
    /// MUTANTS : `ab3_fusion_chrono_avalee`, `ab3_fusion_chrono_cible_avalee`, `ab3_fusion_hors_transaction`.
    #[tokio::test]
    async fn ab3_une_chronologie_de_fusion_refusee_annule_la_fusion() {
        for (cote, de_quel_dossier) in [("source", 0usize), ("cible", 1usize)] {
            let (st, _tmp) = ab3_etat(&format!("fusion-{cote}"));
            let (a, b) = ab3_deux_dossiers(&st);
            let refuse = [a, b][de_quel_dossier];
            let avant = (ab3_dossier(&st, a), ab3_dossier(&st, b));
            ab3_refuser_l_element(&st, &format!("NEW.kind='merge' AND NEW.incident_id={refuse}"));
            let (statut, corps) = ab3_fusionner(&st, a, b).await;
            assert_eq!(statut, 503, "{cote} : chronologie refusée -> 503, jamais un 204 : {corps}");
            // `P10.29-l` (vague AL) — INVERSÉ : il lisait « chronologie de la <côté> » et le motif du trigger dans le corps ;
            // le corps ENTIER est la phrase seule `{error, id}`, la cause (côté nommé, motif du moteur) part au journal, lue
            // ligne entière par `al1_journal_de_la_fusion_non_ecrite_nomme_chronologie_begin_et_commit` (sous-processus).
            super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule(cote, statut, &corps, CAUSE_FUSION_NON_ECRITE);
            assert!(!corps.to_string().contains("ab3 chronologie refusée"), "{cote} : le motif du moteur ne sort pas : {corps}");
            assert!(st.db.lock().is_autocommit(), "{cote} : aucune transaction laissée ouverte");
            assert_eq!((ab3_dossier(&st, a), ab3_dossier(&st, b)), avant, "{cote} : la fusion est ANNULÉE (merged_into, statut, updated, MTTA)");
            assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='merge'"), 0, "{cote} : aucun élément de fusion ne survit");
            assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.merge'"), 0, "{cote} : rien au registre");

            ab3_sql(&st, "DROP TRIGGER ab3_element;");
            let (statut, corps) = ab3_fusionner(&st, a, b).await;
            assert_eq!(statut, 204, "{cote} : contrôle positif, 204 comme avant : {corps}");
            let (merged, status, _, _, mtta_a) = ab3_dossier(&st, a);
            assert_eq!((merged, status.as_str()), (Some(b), "closed"));
            assert!(mtta_a.is_some() && ab3_dossier(&st, b).4.is_some(), "{cote} : la chronologie fige le MTTA des deux dossiers");
            assert_eq!(
                ab3_textes(&st, "SELECT body FROM incident_item WHERE kind='merge' ORDER BY id"),
                vec![format!("fusionné dans #{b}"), format!("#{a} fusionné ici (timeline combinée)")]
            );
            assert_eq!(ab3_textes(&st, "SELECT detail FROM ledger WHERE kind='case.merge'"), vec![format!("#{a} -> #{b} by analyste")]);
        }
    }

    /// CE QU'IL TIENT (`case_merge`) : le maillon `case.merge` refusé -> 200 `{ok, registre_sans_maillon}` (phrase
    /// `CAUSE_GESTE_SANS_TRACE` + cause), et la fusion EST faite : source fusionnée, deux chronologies, rien au registre.
    /// MUTANTS : `ab3_fusion_maillon_jete` (204 muet), `ab3_fusion_maillon_annule` (fusion annulée), `ab3_route_fusion_204`.
    #[tokio::test]
    async fn ab3_un_maillon_de_fusion_refuse_est_avoue_sans_annuler_la_fusion() {
        let (st, _tmp) = ab3_etat("fusion-maillon");
        let (a, b) = ab3_deux_dossiers(&st);
        ab3_refuser_le_maillon(&st, "case.merge");
        let (statut, corps) = ab3_fusionner(&st, a, b).await;
        assert_eq!(statut, 200, "maillon manquant : 200 qui l'avoue, jamais un 204 muet ni un 503 : {corps}");
        assert!(ab3_maillon_avoue(&corps), "le corps avoue la trace manquante : {corps}");
        assert_eq!(ab3_dossier(&st, a).0, Some(b), "la fusion a eu lieu, elle n'est pas annulée");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='merge'"), 2, "les deux chronologies sont écrites");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.merge'"), 0);
    }

    /// CE QU'IL TIENT (`case_merge`) : `BEGIN` refusé (transaction laissée ouverte sur l'écrivain) puis `COMMIT` refusé
    /// -> 503 `{error: CAUSE_FUSION_NON_ECRITE, id}` seul (le refus nommé au journal, `P10.29-l`), rien d'écrit — après le `BEGIN` refusé, lu AVANT le
    /// `ROLLBACK` du témoin, dans la transaction étrangère elle-même. Contrôle : leviers retirés, 204.
    /// MUTANTS : `ab3_fusion_refus_de_transaction_ecrit`, `M_FUSION_BEGIN_ECRIT`.
    #[tokio::test]
    async fn ab3_une_fusion_dont_la_transaction_est_refusee_n_ecrit_rien() {
        let (st, _tmp) = ab3_etat("fusion-transaction");
        let (a, b) = ab3_deux_dossiers(&st);
        let avant = (ab3_dossier(&st, a), ab3_dossier(&st, b));

        ab3_sql(&st, "BEGIN;");
        let (statut, corps) = ab3_fusionner(&st, a, b).await;
        // LU AVANT le ROLLBACK, sur la même connexion : une écriture faite dans la transaction étrangère s'y voit encore.
        let pendant = (ab3_dossier(&st, a), ab3_dossier(&st, b));
        let traces = ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='merge'") + ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.merge'");
        ab3_sql(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : 503 : {corps}");
        // `P10.29-l` (vague AL) — INVERSÉ : il lisait « transaction non ouverte » dans le corps ; la phrase seule `{error, id}`.
        // Ce qui distinguait le `BEGIN` refusé du `COMMIT` refusé (libellés « transaction non ouverte » / « validation
        // refusée ») est lu au journal, ligne entière, par `al1_journal_de_la_fusion_non_ecrite_nomme_chronologie_begin_et_commit`.
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("BEGIN refusé", statut, &corps, CAUSE_FUSION_NON_ECRITE);
        assert_eq!(pendant, avant, "BEGIN refusé : rien n'est écrit, pas même dans la transaction étrangère");
        assert_eq!(traces, 0, "BEGIN refusé : aucune chronologie ni maillon, pas même dans la transaction étrangère");

        ab3_refuser_le_commit(&st);
        let (statut, corps) = ab3_fusionner(&st, a, b).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte après le COMMIT refusé");
        ab3_lever_le_commit(&st);
        assert_eq!(statut, 503, "COMMIT refusé : 503 : {corps}");
        // `P10.29-l` (vague AL) — INVERSÉ : il lisait « validation refusée » dans le corps ; la phrase seule `{error, id}`.
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("COMMIT refusé", statut, &corps, CAUSE_FUSION_NON_ECRITE);
        assert_eq!((ab3_dossier(&st, a), ab3_dossier(&st, b)), avant);
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='merge'") + ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.merge'"), 0);

        assert_eq!(ab3_fusionner(&st, a, b).await.0, 204, "contrôle : leviers retirés, la fusion aboutit");
    }

    /// CE QU'IL TIENT (`case_unmerge`) : la chronologie de la défusion refusée -> 503 `CAUSE_DEFUSION_NON_ECRITE`, le
    /// dossier reste fusionné et clos, aucun élément « dé-fusionné », aucun `case.unmerge` ; puis le maillon refusé ->
    /// 200 `{ok, registre_sans_maillon}`, dossier défusionné en `triage`, élément écrit.
    /// MUTANTS : `ab3_defusion_chrono_avalee`, `ab3_route_defusion_204`, `ab3_fusion_maillon_jete` (issue partagée).
    #[tokio::test]
    async fn ab3_une_defusion_annulee_par_sa_chronologie_ou_avouee_sans_maillon() {
        let (st, _tmp) = ab3_etat("defusion");
        let (a, b) = ab3_deux_dossiers(&st);
        assert_eq!(ab3_fusionner(&st, a, b).await.0, 204, "fixture : la fusion est posée");
        let avant = ab3_dossier(&st, a);

        ab3_refuser_l_element(&st, "NEW.body LIKE 'dé-fusionné%'");
        let (statut, corps) = ab3_defusionner(&st, a).await;
        assert_eq!(statut, 503, "chronologie refusée : 503 : {corps}");
        // `P10.29-l` (vague AL) — INVERSÉ : il lisait le motif du trigger dans le corps ; la phrase seule `{error, id}`.
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("chronologie de la défusion refusée", statut, &corps, CAUSE_DEFUSION_NON_ECRITE);
        assert_eq!(ab3_dossier(&st, a), avant, "le dossier reste fusionné, rien n'a bougé");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE body LIKE 'dé-fusionné%'"), 0);
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.unmerge'"), 0);
        ab3_sql(&st, "DROP TRIGGER ab3_element;");

        ab3_refuser_le_maillon(&st, "case.unmerge");
        let (statut, corps) = ab3_defusionner(&st, a).await;
        assert_eq!(statut, 200, "maillon manquant : 200 qui l'avoue : {corps}");
        assert!(ab3_maillon_avoue(&corps), "{corps}");
        let (merged, status, ..) = ab3_dossier(&st, a);
        assert_eq!((merged, status.as_str()), (None, "triage"), "la défusion a eu lieu");
        assert_eq!(ab3_textes(&st, "SELECT body FROM incident_item WHERE body LIKE 'dé-fusionné%'"), vec![format!("dé-fusionné de #{b} (ré-ouvert)")]);
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.unmerge'"), 0);
    }

    /// CE QU'IL TIENT (`case_link_add`, par la route) : la chronologie du premier, puis du second dossier, refusée -> 503
    /// `CAUSE_LIEN_NON_POSE` qui nomme la chronologie ; aucune ligne `case_link`, aucun élément `link`, aucun `case.link`,
    /// `updated`/MTTA inchangés. Contrôle : 204, traces d'avant.
    /// MUTANTS : `ab3_lien_chrono_avalee`, `ab3_lien_chrono_second_avalee`, `ab3_lien_hors_transaction`.
    #[tokio::test]
    async fn ab3_une_chronologie_de_lien_refusee_annule_le_lien() {
        for (rang, quel) in [("premier", 0usize), ("second", 1usize)] {
            let (st, _tmp) = ab3_etat(&format!("lien-{rang}"));
            let (a, b) = ab3_deux_dossiers(&st);
            let refuse = [a, b][quel];
            let avant = (ab3_dossier(&st, a), ab3_dossier(&st, b));
            ab3_refuser_l_element(&st, &format!("NEW.kind='link' AND NEW.incident_id={refuse}"));
            let (statut, corps) = ab3_lier(&st, a, b).await;
            assert_eq!(statut, 503, "{rang} : chronologie refusée -> 503 : {corps}");
            let phrase = ab3_phrase(&corps);
            assert!(phrase.starts_with(CAUSE_LIEN_NON_POSE), "{rang} : le 503 existant du lien non posé : {corps}");
            assert!(phrase.contains(&format!("chronologie du {rang} dossier")) && phrase.contains("ab3 chronologie refusée"), "{rang} : {corps}");
            assert!(st.db.lock().is_autocommit(), "{rang} : aucune transaction laissée ouverte");
            assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM case_link"), 0, "{rang} : la ligne du lien est annulée");
            assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='link'"), 0, "{rang} : aucun élément de lien");
            assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.link'"), 0, "{rang} : rien au registre");
            assert_eq!((ab3_dossier(&st, a), ab3_dossier(&st, b)), avant, "{rang} : updated et MTTA inchangés");

            ab3_sql(&st, "DROP TRIGGER ab3_element;");
            assert_eq!(ab3_lier(&st, a, b).await.0, 204, "{rang} : contrôle positif");
            assert_eq!(
                ab3_textes(&st, "SELECT body FROM incident_item WHERE kind='link' ORDER BY id"),
                vec![format!("lié à #{b} (duplicate)"), format!("lié à #{a} (duplicate)")]
            );
            assert_eq!(ab3_textes(&st, "SELECT detail FROM ledger WHERE kind='case.link'"), vec![format!("#{a} <-duplicate-> #{b} by analyste")]);
        }
    }

    /// CE QU'IL TIENT (`case_link_add`) : le maillon `case.link` refusé -> 200 `{ok, registre_sans_maillon}`, le lien et
    /// ses deux chronologies écrits ; le même lien redemandé reste 204 (déjà lié, rien de doublé).
    /// MUTANTS : `ab3_lien_maillon_jete`, `ab3_route_lien_204`.
    #[tokio::test]
    async fn ab3_un_maillon_de_lien_refuse_est_avoue_sans_annuler_le_lien() {
        let (st, _tmp) = ab3_etat("lien-maillon");
        let (a, b) = ab3_deux_dossiers(&st);
        ab3_refuser_le_maillon(&st, "case.link");
        let (statut, corps) = ab3_lier(&st, a, b).await;
        assert_eq!(statut, 200, "maillon manquant : 200 qui l'avoue : {corps}");
        assert!(ab3_maillon_avoue(&corps), "{corps}");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM case_link"), 1, "le lien est posé");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='link'"), 2);
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.link'"), 0);
        assert_eq!(ab3_lier(&st, a, b).await.0, 204, "déjà lié : 204 inchangé");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='link'"), 2, "rien de doublé");
    }

    /// CE QU'IL TIENT (`case_link_add`) : `BEGIN` puis `COMMIT` refusés -> 503 `CAUSE_LIEN_NON_POSE` qui nomme le refus,
    /// aucune ligne ni trace — après le `BEGIN` refusé, lu AVANT le `ROLLBACK` du témoin. Contrôle : 204.
    /// MUTANTS : `ab3_lien_refus_de_transaction_pose`, `M_LIEN_BEGIN_POSE`.
    #[tokio::test]
    async fn ab3_un_lien_dont_la_transaction_est_refusee_n_est_pas_pose() {
        let (st, _tmp) = ab3_etat("lien-transaction");
        let (a, b) = ab3_deux_dossiers(&st);
        let avant = (ab3_dossier(&st, a), ab3_dossier(&st, b));
        ab3_sql(&st, "BEGIN;");
        let (statut, corps) = ab3_lier(&st, a, b).await;
        // LU AVANT le ROLLBACK, sur la même connexion : une écriture faite dans la transaction étrangère s'y voit encore.
        let pendant = (ab3_dossier(&st, a), ab3_dossier(&st, b));
        let lignes = ab3_compte(&st, "SELECT COUNT(*) FROM case_link");
        let traces = ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='link'") + ab3_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.link'");
        ab3_sql(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : {corps}");
        assert!(ab3_phrase(&corps).starts_with(CAUSE_LIEN_NON_POSE) && ab3_phrase(&corps).contains("transaction non ouverte"), "{corps}");
        assert_eq!(lignes, 0, "BEGIN refusé : aucune ligne de lien, pas même dans la transaction étrangère");
        assert_eq!(traces, 0, "BEGIN refusé : aucune chronologie ni maillon, pas même dans la transaction étrangère");
        assert_eq!(pendant, avant, "BEGIN refusé : updated et MTTA inchangés");

        ab3_refuser_le_commit(&st);
        let (statut, corps) = ab3_lier(&st, a, b).await;
        assert!(st.db.lock().is_autocommit());
        ab3_lever_le_commit(&st);
        assert_eq!(statut, 503, "COMMIT refusé : {corps}");
        assert!(ab3_phrase(&corps).starts_with(CAUSE_LIEN_NON_POSE) && ab3_phrase(&corps).contains("validation refusée"), "{corps}");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM case_link") + ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='link'"), 0);

        assert_eq!(ab3_lier(&st, a, b).await.0, 204, "contrôle : leviers retirés, le lien est posé");
    }

    /// Un dossier P1 dont les deux échéances sont dépassées, une politique active et un canal : chaque tour notifie
    /// l'acquittement ET la résolution tant que rien n'est marqué.
    fn ab3_sla_fixture(st: &AppState) -> i64 {
        let conn = st.db.lock();
        conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)", [])
            .unwrap();
        let id = dossier_seme(&conn, "alice", "Échu", 4, "", None, 1);
        conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![now() - 10, id]).unwrap();
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('ab3_canal','webhook',1,'https://example.invalid/h',0,'{}')",
            [],
        )
        .unwrap();
        id
    }

    fn ab3_tour(st: &AppState) -> Vec<String> {
        let mut envois = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _ts: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    /// Le balayage `sla_multilevel_marqueur` : (compte, dernière cause). Lu SOUS `ab3_verrou_du_balayage()`.
    fn ab3_balayage() -> (u64, String) {
        crate::metrics::tick_aveugle_de("sla_multilevel_marqueur").unwrap_or((0, String::new()))
    }

    fn ab3_verrou_du_balayage() -> parking_lot::MutexGuard<'static, ()> {
        super::dossier_et_echeances_comptes::VERROU_DU_BALAYAGE_SLA_MULTILEVEL_MARQUEUR.lock()
    }

    fn ab3_marques(st: &AppState, id: i64) -> (i64, i64) {
        st.db
            .lock()
            .query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture : les marqueurs se lisent")
    }

    const AB3_TRACES_SLA: &str = "SELECT COUNT(*) FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach')";

    /// CE QU'IL TIENT (`sla_multilevel_tick_par`) : la chronologie `sla` refusée annule le marqueur ; l'envoi part QUAND
    /// MÊME, son détail finit par `DEPASSEMENT_SLA_NON_ENREGISTRE`, rien en chronologie ni au registre, aucun marqueur,
    /// le refus compté au balayage `sla_multilevel_marqueur`, et le tour suivant RENVOIE (rien n'a été marqué). Contrôle :
    /// trigger levé, un envoi par échéance sans aveu, marqueurs, deux chronologies, deux maillons.
    /// MUTANTS : `ab3_sla_chrono_avalee`, `ab3_sla_hors_transaction`, `ab3_sla_refus_tait`.
    #[test]
    fn ab3_une_chronologie_sla_refusee_annule_le_marqueur_et_s_avoue_dans_l_envoi() {
        let _verrou = ab3_verrou_du_balayage();
        let (st, _tmp) = ab3_etat("sla-chrono");
        let id = ab3_sla_fixture(&st);
        let aveu = crate::handlers::caseops::DEPASSEMENT_SLA_NON_ENREGISTRE;
        ab3_refuser_l_element(&st, "NEW.kind='sla'");
        let balayage_avant = ab3_balayage().0;
        for tour in 0..2u64 {
            let envois = ab3_tour(&st);
            assert_eq!(envois.len(), 2, "tour {tour} : un SLA dépassé ne se tait pas, deux échéances notifiées : {envois:?}");
            assert!(envois.iter().all(|d| d.ends_with(aveu)), "tour {tour} : chaque envoi avoue le dépassement non enregistré : {envois:?}");
            let (compte, cause) = ab3_balayage();
            assert_eq!(compte, balayage_avant + tour + 1, "tour {tour} : le refus est compté UNE fois par tour au balayage `sla_multilevel_marqueur`");
            assert!(cause.contains("chronologie du dépassement") && cause.contains("ab3 chronologie refusée"), "tour {tour} : la cause comptée nomme la chronologie : {cause}");
        }
        assert_eq!(ab3_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND (ack_breached=1 OR resolve_breached=1)")), 0, "le marqueur est annulé avec la chronologie");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'"), 0);
        assert_eq!(ab3_compte(&st, AB3_TRACES_SLA), 0);

        ab3_sql(&st, "DROP TRIGGER ab3_element;");
        let envois = ab3_tour(&st);
        assert_eq!(envois.len(), 2, "contrôle positif : {envois:?}");
        assert!(envois.iter().all(|d| !d.ends_with(aveu)), "sans aveu : {envois:?}");
        assert_eq!(ab3_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND ack_breached=1 AND resolve_breached=1")), 1);
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'"), 2);
        assert_eq!(ab3_compte(&st, AB3_TRACES_SLA), 2);
        assert!(ab3_tour(&st).is_empty(), "marqué : plus rien n'est renvoyé");
    }

    /// CE QU'IL TIENT : `BEGIN` refusé pendant le tour (transaction laissée ouverte sur l'écrivain) -> envois avec l'aveu,
    /// rien de marqué ni d'inscrit — lu AVANT le `ROLLBACK` du témoin, dans la transaction étrangère elle-même —, le
    /// refus compté une fois au balayage, sa cause nommée.
    /// MUTANTS : `ab3_sla_refus_de_transaction_tait`, `M_SLA_BEGIN_MARQUE`.
    #[test]
    fn ab3_un_tour_sla_dont_la_transaction_est_refusee_s_avoue_dans_l_envoi() {
        let _verrou = ab3_verrou_du_balayage();
        let (st, _tmp) = ab3_etat("sla-begin");
        let id = ab3_sla_fixture(&st);
        let aveu = crate::handlers::caseops::DEPASSEMENT_SLA_NON_ENREGISTRE;
        let balayage_avant = ab3_balayage().0;
        ab3_sql(&st, "BEGIN;");
        let envois = ab3_tour(&st);
        // LU AVANT le ROLLBACK, sur la même connexion : une écriture faite dans la transaction étrangère s'y voit encore.
        let marques = ab3_marques(&st, id);
        let traces = ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'") + ab3_compte(&st, AB3_TRACES_SLA);
        ab3_sql(&st, "ROLLBACK;");
        assert_eq!(envois.len(), 2, "{envois:?}");
        assert!(envois.iter().all(|d| d.ends_with(aveu)), "BEGIN refusé : chaque envoi l'avoue : {envois:?}");
        assert_eq!(marques, (0, 0), "BEGIN refusé : aucun marqueur, pas même dans la transaction étrangère");
        assert_eq!(traces, 0, "BEGIN refusé : ni chronologie ni registre, pas même dans la transaction étrangère");
        let (compte, cause) = ab3_balayage();
        assert_eq!(compte, balayage_avant + 1, "le refus est compté UNE fois pour le tour");
        assert!(cause.contains("transaction non ouverte"), "la cause comptée nomme le BEGIN refusé : {cause}");
    }

    /// CE QU'IL TIENT (`sla_multilevel_tick_par`) : `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par la chronologie)
    /// -> sur DEUX tours : deux envois par tour, chacun AVOUANT `DEPASSEMENT_SLA_NON_ENREGISTRE`, aucune transaction
    /// laissée ouverte, le refus compté UNE fois par tour et nommé (« validation refusée ») ; aucun marqueur, aucune
    /// chronologie, rien au registre, donc renvoyé. Contrôle : levier retiré, envois sans aveu, deux marqueurs, puis
    /// plus rien.
    /// MUTANT : `M_SLA_NONVALIDE_TAIT` (`COMMIT` refusé lu comme validé : envoi sans aveu, refus non compté).
    #[test]
    fn ab3_un_tour_sla_dont_le_commit_est_refuse_s_avoue_dans_l_envoi_et_se_compte() {
        let _verrou = ab3_verrou_du_balayage();
        let (st, _tmp) = ab3_etat("sla-commit");
        let id = ab3_sla_fixture(&st);
        let aveu = crate::handlers::caseops::DEPASSEMENT_SLA_NON_ENREGISTRE;
        ab3_refuser_le_commit(&st);
        let balayage_avant = ab3_balayage().0;
        for tour in 0..2u64 {
            let envois = ab3_tour(&st);
            assert!(st.db.lock().is_autocommit(), "tour {tour} : aucune transaction laissée ouverte après le COMMIT refusé");
            assert_eq!(envois.len(), 2, "tour {tour} : un SLA dépassé ne se tait pas : {envois:?}");
            assert!(envois.iter().all(|d| d.ends_with(aveu)), "tour {tour} : COMMIT refusé : chaque envoi l'avoue : {envois:?}");
            let (compte, cause) = ab3_balayage();
            assert_eq!(compte, balayage_avant + tour + 1, "tour {tour} : le refus est compté UNE fois par tour");
            assert!(cause.contains("validation refusée"), "tour {tour} : la cause comptée nomme le COMMIT refusé : {cause}");
        }
        assert_eq!(ab3_marques(&st, id), (0, 0), "COMMIT refusé : les marqueurs sont annulés");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'") + ab3_compte(&st, AB3_TRACES_SLA), 0);

        ab3_lever_le_commit(&st);
        let envois = ab3_tour(&st);
        assert_eq!(envois.len(), 2, "contrôle positif : {envois:?}");
        assert!(envois.iter().all(|d| !d.ends_with(aveu)), "contrôle : sans aveu : {envois:?}");
        assert_eq!(ab3_marques(&st, id), (1, 1));
        assert!(ab3_tour(&st).is_empty(), "contrôle : marqué, plus rien n'est renvoyé");
    }

    /// CE QU'IL TIENT (`P10.31-u`, tick SLA) : le maillon `case.sla_*_breach` refusé n'ANNULE PAS le dépassement — les
    /// deux marqueurs posés, les deux chronologies écrites, deux envois SANS l'aveu `DEPASSEMENT_SLA_NON_ENREGISTRE`
    /// (le dépassement est enregistré ; seul le registre manque, la primitive l'a dit au journal), rien de compté au
    /// balayage `sla_multilevel_marqueur`, et le tour suivant ne RENVOIE rien (pas de renotification à chaque tour).
    /// MUTANT : `M_SLA_MAILLON_REFUS` (maillon manquant lu comme refus : marqueur et chronologie annulés, renvoi).
    #[test]
    fn ab3_un_maillon_sla_refuse_n_annule_pas_le_depassement_et_ne_renotifie_pas() {
        let _verrou = ab3_verrou_du_balayage();
        let (st, _tmp) = ab3_etat("sla-maillon");
        let id = ab3_sla_fixture(&st);
        let aveu = crate::handlers::caseops::DEPASSEMENT_SLA_NON_ENREGISTRE;
        ab3_sql(
            &st,
            "CREATE TEMP TRIGGER ab3_maillon BEFORE INSERT ON ledger WHEN NEW.kind IN ('case.sla_ack_breach','case.sla_resolve_breach') \
             BEGIN SELECT RAISE(ABORT, 'ab3 maillon refusé'); END;",
        );
        let balayage_avant = ab3_balayage().0;
        let envois = ab3_tour(&st);
        assert_eq!(envois.len(), 2, "deux échéances notifiées : {envois:?}");
        assert!(envois.iter().all(|d| !d.ends_with(aveu)), "maillon manquant : le dépassement EST enregistré, aucun aveu de non-enregistrement : {envois:?}");
        assert_eq!(ab3_balayage().0, balayage_avant, "maillon manquant : rien de compté au balayage du marqueur");
        assert_eq!(ab3_marques(&st, id), (1, 1), "maillon manquant : les marqueurs NE sont PAS annulés");
        assert_eq!(ab3_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'"), 2, "les deux chronologies sont écrites");
        assert_eq!(ab3_compte(&st, AB3_TRACES_SLA), 0, "le registre ne porte rien (le trigger l'a refusé)");
        assert!(ab3_tour(&st).is_empty(), "marqué : le tour suivant ne renotifie pas");
    }
}
