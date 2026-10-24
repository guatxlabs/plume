// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi au client », suite, vague AL) — CASEOPS.RS : LA FICHE CLIENT, LA FUSION,
// LA DÉFUSION ET LES DEUX GESTES DE POLITIQUE SLA SERVENT UNE PHRASE FIXE ; LA CAUSE DU MOTEUR VA AU JOURNAL.
//
// LE DÉFAUT, MESURÉ SUR 831785a9 (handlers/caseops.rs) :
//   * `client_case_get` (vers :1731-1736) : `dossier NON LU : la lecture a échoué (<moteur>) — …` en 500 sur
//     `/api/client/cases/{id}`, lisible par le rôle `client` (jeton externe d'un client MSSP) : le nom de la table
//     (`no such table: incident_item`) sortait de l'équipe ;
//   * `case_merge_handler` / `case_unmerge_handler` (vers :1185, :1212) : `IssueDeLaFusion::NonEcrite(cause)` servi
//     `<CAUSE_FUSION_NON_ECRITE|CAUSE_DEFUSION_NON_ECRITE> (<cause>)` en 503 (motif du trigger, refus de transaction) ;
//   * `sla_policy_delete` (vers :1651, :1660, :1682) : `<CAUSE_POLITIQUE_NON_SUPPRIMEE|CAUSE_DOSSIERS_NON_DEGOUVERNES>
//     (<moteur>)` en 503, trois bras (suppression refusée, effacement refusé, transaction non ouverte ou non validée) ;
//   * `reponse_de_l_upsert_sla` (vers :1462-1466) : `reason` = `politique NON enregistrée (<moteur>) — …` en 500.
//
// LE CORRECTIF : les 503 passent par `refus_nomme_cause_au_journal` (handlers/cases.rs, vague AK) — corps `{error:
// <cause>, id}`, ligne `[cases] WARN <geste> (<id>) : <moteur>` ; la fiche client passe par `refus_de_la_fiche_non_lue`
// (même patron que la fiche interne : `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id, lecture_non_faite: true}`, préfixe
// « dossier NON LU » gardé) ; l'upsert sert `{recomputed: 0, reason: CAUSE_POLITIQUE_SLA_NON_ENREGISTREE, id}` et écrit
// `[caseops] WARN politique SLA NON enregistrée (<id>) : <moteur>`. Statuts inchangés ; bras de succès inchangés.
//
// LES TÉMOINS (par le gestionnaire de la route, identité du rôle le plus faible admis : `client` pour la fiche client,
// `editor` pour la fusion, la défusion et l'upsert, `admin` pour la suppression, réservée) :
// (1) `al1_corps_*` : chaque refus rend son statut et le corps ENTIER (ensemble exact des clés, phrase égale, identifiant
//     `plume-e…`), le texte du moteur absent du corps ; contrôles : succès et absences d'avant à l'octet, bras précédents
//     (403 de la suppression, 400 de l'upsert) à l'octet, rien d'écrit sous le refus.
// (2) `al1_journal_des_refus_de_caseops` : le binaire se rejoue en sous-processus, l'enfant joue chaque refus entre deux
//     marques de phase, le parent compare la ligne `[cases]` (ou `[caseops]` pour l'upsert) ENTIÈRE — identifiant servi,
//     cause du moteur lue à part sous le même refus — et la ligne `HTTP 5xx` ENTIÈRE (la phrase seule).
// (3) `al1_journal_de_la_fusion_non_ecrite_nomme_chronologie_begin_et_commit` : la fusion non écrite dans ses quatre cas
//     (chronologie de la source, de la cible, `BEGIN` refusé, `COMMIT` refusé), corps ENTIER et ligne `[cases]` ENTIÈRE,
//     libellés de caseops posés en littéral, moteur lu à part : ce que le corps d'avant distinguait, le journal le dit.
//
// MUTANTS (variable VERIF_MUT sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE : la forme d'avant au
// site — `AL1_FICHE_CLIENT`, `AL1_FUSION`, `AL1_DEFUSION`, `AL1_SLA_SUPPR`, `AL1_SLA_DEGOUV`, `AL1_SLA_TX`, `AL1_UPSERT`
// rougissent (1) et (2) ; `AL1_FICHE_CLIENT_MUET` (phrase fixe sans passer par l'assistant, aucune ligne) et
// `AL1_UPSERT_J` (ligne de l'upsert tue) rougissent (2) ; `AL1_UPSERT_ID` (corps sans identifiant) rougit (1) et (2).
// À la relecture : `AL1C_LABEL` (libellés « transaction non ouverte » / « validation refusée » échangés dans
// `issue_du_geste_de_fusion`) et `AL1C_COTE` (« chronologie de la source » dit « de la cible ») rougissent (3) seul ;
// `AL1C_FUSION_AVANT` (le 503 d'avant au site de la fusion) rougit (1), (2), (3) et les deux tests ab3 inversés.
//
// TESTS ANTÉRIEURS INVERSÉS NOMMÉMENT (ils lisaient la cause du moteur dans le corps servi) :
// `ab3_une_chronologie_de_fusion_refusee_annule_la_fusion`, `ab3_une_fusion_dont_la_transaction_est_refusee_n_ecrit_rien` et `ab3_une_defusion_annulee_par_sa_chronologie_ou_avouee_sans_maillon`
// (chronologie_de_fusion_et_de_lien_dans_le_geste.rs), `psd_effacement_refuse_rend_503_et_conserve_la_politique`
// (politique_sla_supprimee_degouverne_ses_dossiers.rs), `pde_refus_de_transaction_ne_pose_rien`
// (politique_sla_desactivee_et_trace_de_l_upsert.rs) jugent désormais la phrase seule ; les deux fiches non lues de
// dossiers_non_lus_avouent.rs et dossiers_client_non_lus_avouent.rs sont ancrées sur `CAUSE_FICHE_DU_DOSSIER_NON_LUE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le bras `NonValide` (`COMMIT` refusé) de la suppression partage le site du bras
// `NonOuvert` joué ici, sans témoin propre ; le chemin par jeton client réel (garde d'authentification) n'est pas rejoué,
// seul le gestionnaire l'est avec l'identité résolue ; restes de `P10.29-l` non pris : `LienDeDossier::NonPose` et
// `LienRetire::NonRetire` (caseops.rs, exigés mot pour mot par le harnais console), la liste ILLISIBLE `({e})` du `manque`
// de `sla_recalcule_la_priorite` (200 `reason`) et les `NonLu(format!(…{e}))` du chrono SLA ; le corps
// `registre_sans_maillon` (cause du maillon).
// =====================================================================================
mod texte_du_moteur_hors_de_la_fiche_client_de_la_fusion_et_des_politiques_sla {
    use super::*;
    use crate::handlers::caseops::{
        case_merge, case_merge_handler, case_unmerge, case_unmerge_handler, client_case_get, client_case_get_lu, sla_policy_delete, sla_policy_upsert, CAUSE_DEFUSION_NON_ECRITE, CAUSE_DOSSIERS_NON_DEGOUVERNES, CAUSE_DOSSIER_CLIENT_INTROUVABLE,
        CAUSE_FUSION_NON_ECRITE, CAUSE_POLITIQUE_NON_SUPPRIMEE, CAUSE_POLITIQUE_SLA_INTROUVABLE, CAUSE_POLITIQUE_SLA_NON_ENREGISTREE,
        CAUSE_POLITIQUE_SLA_PRIORITE_HORS_BORNES, CAUSE_SUPPRESSION_DE_POLITIQUE_SLA_RESERVEE, IssueDeLaFusion,
    };
    use crate::handlers::cases::CAUSE_FICHE_DU_DOSSIER_NON_LUE;
    use super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule;

    const AL1_TITRE: &str = "al1-titre-du-dossier";

    fn al1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("al1-{tag}"));
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

    fn al1_identite(nom: &str, role: &str) -> AuthUser {
        AuthUser {
            name: nom.into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn al1_client() -> AuthUser {
        al1_identite("cli", "client")
    }

    fn al1_ed() -> AuthUser {
        al1_identite("alice", "editor")
    }

    fn al1_adm() -> AuthUser {
        al1_identite("adm", "admin")
    }

    fn al1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn al1_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn al1_dossier(st: &AppState) -> i64 {
        dossier_seme(&st.db.lock(), "alice", AL1_TITRE, 3, "", None, 2)
    }

    fn al1_politique(st: &AppState, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('al1',?1,60,600,1,0,'root',0)",
            params![priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn al1_dossier_gouverne(st: &AppState, pid: i64) -> i64 {
        let id = al1_dossier(st);
        st.db.lock().execute("UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?2 WHERE id=?3", params![pid, now() + 1000, id]).unwrap();
        id
    }

    async fn al1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// Ensemble exact des clés d'un corps objet, triées.
    fn al1_cles(quoi: &str, corps: &Value) -> Vec<String> {
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<String> = o.keys().cloned().collect();
        cles.sort_unstable();
        cles
    }

    fn al1_identifiant(quoi: &str, corps: &Value) -> String {
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    /// LE CINQ CENTS DE LA FICHE CLIENT : statut 500, corps ENTIER `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id: plume-e…,
    /// lecture_non_faite: true}` ; rend l'identifiant servi.
    fn al1_fiche_client_phrase_seule(statut: u16, corps: &Value) -> String {
        assert_eq!(statut, 500, "fiche client non lue : statut : {corps}");
        assert_eq!(al1_cles("fiche client", corps), ["error", "id", "lecture_non_faite"], "fiche client : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FICHE_DU_DOSSIER_NON_LUE), "fiche client : la phrase seule : {corps}");
        assert_eq!(corps["lecture_non_faite"], json!(true), "fiche client : le drapeau d'avant : {corps}");
        al1_identifiant("fiche client", corps)
    }

    /// LE CINQ CENTS DE L'UPSERT : statut 500, corps ENTIER `{recomputed: 0, reason: CAUSE_POLITIQUE_SLA_NON_ENREGISTREE,
    /// id: plume-e…}` ; rend l'identifiant servi.
    fn al1_upsert_phrase_seule(statut: u16, corps: &Value) -> String {
        assert_eq!(statut, 500, "upsert non enregistré : statut : {corps}");
        assert_eq!(al1_cles("upsert", corps), ["id", "reason", "recomputed"], "upsert : ensemble exact des clés : {corps}");
        assert_eq!(corps["recomputed"], json!(0), "upsert : rien recalculé : {corps}");
        assert_eq!(corps["reason"], json!(CAUSE_POLITIQUE_SLA_NON_ENREGISTREE), "upsert : la phrase seule : {corps}");
        al1_identifiant("upsert", corps)
    }

    /// Un refus joué : la réponse, le préfixe de journal et le geste attendus, la cause du moteur lue à part sous le même
    /// refus, la phrase servie et le statut.
    struct Al1Refus {
        reponse: (u16, Value),
        ligne: String,
        moteur: String,
        phrase: &'static str,
        statut: u16,
    }

    /// (a) `client_case_get` lu par le rôle `client`, `incident_item` hors d'atteinte (le moteur nomme la table).
    async fn al1_jouer_fiche_client(st: &AppState) -> (Al1Refus, i64) {
        let id = al1_dossier(st);
        al1_sql(st, "ALTER TABLE incident_item RENAME TO al1_items_caches;");
        let chemin = crate::req_db_path(st, &al1_client());
        let moteur = match client_case_get_lu(&st.db.lock(), &chemin, &guatx_core::soql::FieldMaskSet::new(), id, now()) {
            Err(e) => e.to_string(),
            Ok(v) => panic!("fixture : lecture de la fiche client ratée attendue, pas {v:?}"),
        };
        let reponse = al1_reponse(client_case_get(State(st.clone()), Extension(al1_client()), Path(id)).await).await;
        al1_sql(st, "ALTER TABLE al1_items_caches RENAME TO incident_item;");
        assert!(moteur.contains("incident_item"), "fixture : le texte du moteur nomme la table : {moteur}");
        let refus = Al1Refus { reponse, ligne: format!("[cases] WARN fiche du dossier #{id} NON lue"), moteur, phrase: CAUSE_FICHE_DU_DOSSIER_NON_LUE, statut: 500 };
        (refus, id)
    }

    /// (b) `case_merge_handler` : la chronologie de la fusion refusée par la base (cause lue sur la même paire, refus
    /// annulé, rien n'est écrit entre les deux).
    async fn al1_jouer_fusion(st: &AppState) -> (Al1Refus, i64, i64) {
        let (a, b) = (al1_dossier(st), al1_dossier(st));
        al1_sql(st, "CREATE TEMP TRIGGER al1_chrono BEFORE INSERT ON incident_item WHEN NEW.kind='merge' BEGIN SELECT RAISE(ABORT, 'al1 chronologie refusee : incident_item.body'); END;");
        let moteur = match case_merge(&st.db.lock(), a, b, "alice") {
            IssueDeLaFusion::NonEcrite(cause) => cause,
            _ => panic!("fixture : fusion non écrite attendue"),
        };
        let reponse = al1_reponse(case_merge_handler(State(st.clone()), Extension(al1_ed()), Path(a), Json(json!({ "into": b }))).await).await;
        al1_sql(st, "DROP TRIGGER al1_chrono;");
        assert!(moteur.contains("al1 chronologie refusee"), "fixture : la cause porte le motif du moteur : {moteur}");
        assert_eq!(al1_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into IS NULL")), 1, "fusion refusée : rien d'écrit");
        let refus = Al1Refus { reponse, ligne: format!("[cases] WARN dossier #{a} : fusion dans #{b} NON écrite"), moteur, phrase: CAUSE_FUSION_NON_ECRITE, statut: 503 };
        (refus, a, b)
    }

    /// (c) `case_unmerge_handler` : la chronologie de la défusion refusée (dossier fusionné d'abord, cause lue sur lui).
    async fn al1_jouer_defusion(st: &AppState) -> (Al1Refus, i64) {
        let (a, b) = (al1_dossier(st), al1_dossier(st));
        assert!(matches!(case_merge(&st.db.lock(), a, b, "alice"), IssueDeLaFusion::Ecrite), "fixture : fusion posée");
        al1_sql(st, "CREATE TEMP TRIGGER al1_chrono_defusion BEFORE INSERT ON incident_item WHEN NEW.body LIKE 'dé-fusionné%' BEGIN SELECT RAISE(ABORT, 'al1 defusion refusee : incident_item.body'); END;");
        let moteur = match case_unmerge(&st.db.lock(), a, "alice") {
            IssueDeLaFusion::NonEcrite(cause) => cause,
            _ => panic!("fixture : défusion non écrite attendue"),
        };
        let reponse = al1_reponse(case_unmerge_handler(State(st.clone()), Extension(al1_ed()), Path(a)).await).await;
        al1_sql(st, "DROP TRIGGER al1_chrono_defusion;");
        assert!(moteur.contains("al1 defusion refusee"), "fixture : la cause porte le motif du moteur : {moteur}");
        assert_eq!(al1_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into={b}")), 1, "défusion refusée : toujours fusionné");
        let refus = Al1Refus { reponse, ligne: format!("[cases] WARN dossier #{a} : défusion NON écrite"), moteur, phrase: CAUSE_DEFUSION_NON_ECRITE, statut: 503 };
        (refus, a)
    }

    async fn al1_supprimer(st: &AppState, qui: AuthUser, pid: i64) -> (u16, Value) {
        al1_reponse(sla_policy_delete(State(st.clone()), Extension(qui), Path(pid)).await).await
    }

    /// (d) `sla_policy_delete` : le `DELETE` de la politique refusé par la base.
    async fn al1_jouer_suppression(st: &AppState) -> (Al1Refus, i64) {
        let pid = al1_politique(st, 1);
        al1_sql(st, "CREATE TEMP TRIGGER al1_suppr BEFORE DELETE ON sla_policy BEGIN SELECT RAISE(ABORT, 'al1 suppression refusee : sla_policy'); END;");
        let moteur = st.db.lock().execute("DELETE FROM sla_policy WHERE id=?1", params![pid]).expect_err("fixture : suppression refusée").to_string();
        let reponse = al1_supprimer(st, al1_adm(), pid).await;
        al1_sql(st, "DROP TRIGGER al1_suppr;");
        assert_eq!(al1_entier(st, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={pid}")), 1, "suppression refusée : politique conservée");
        let refus = Al1Refus { reponse, ligne: format!("[cases] WARN politique SLA #{pid} NON supprimée"), moteur, phrase: CAUSE_POLITIQUE_NON_SUPPRIMEE, statut: 503 };
        (refus, pid)
    }

    /// (e) `sla_policy_delete` : l'effacement des échéances d'un dossier gouverné refusé, suppression annulée.
    async fn al1_jouer_degouvernement(st: &AppState) -> (Al1Refus, i64) {
        let pid = al1_politique(st, 2);
        let a = al1_dossier_gouverne(st, pid);
        al1_sql(st, "CREATE TEMP TRIGGER al1_degouv BEFORE UPDATE OF ack_due ON incident BEGIN SELECT RAISE(ABORT, 'al1 effacement refuse : incident.ack_due'); END;");
        let moteur = st
            .db
            .lock()
            .execute("UPDATE incident SET sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL WHERE sla_policy_id=?1", params![pid])
            .expect_err("fixture : effacement refusé")
            .to_string();
        let reponse = al1_supprimer(st, al1_adm(), pid).await;
        al1_sql(st, "DROP TRIGGER al1_degouv;");
        assert_eq!(al1_entier(st, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={pid}")), 1, "effacement refusé : politique conservée");
        assert_eq!(al1_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND sla_policy_id={pid}")), 1, "effacement refusé : dossier gouverné");
        let refus = Al1Refus {
            reponse,
            ligne: format!("[cases] WARN politique SLA #{pid} : dossiers NON dégouvernés, suppression annulée"),
            moteur,
            phrase: CAUSE_DOSSIERS_NON_DEGOUVERNES,
            statut: 503,
        };
        (refus, pid)
    }

    /// (f) `sla_policy_delete` : le `BEGIN` du geste refusé (transaction étrangère ouverte sur l'écrivain) ; la cause est
    /// lue par le même geste gardé sous la même transaction étrangère.
    async fn al1_jouer_transaction(st: &AppState) -> (Al1Refus, i64) {
        let pid = al1_politique(st, 3);
        al1_sql(st, "BEGIN;");
        let moteur = match crate::handlers::transaction_validee::jouer_le_geste_garde(&st.db.lock(), "al1", "sonde", |_| Ok::<(), ()>(())) {
            crate::handlers::transaction_validee::IssueDuGesteGarde::NonOuvert(e) => e.to_string(),
            _ => panic!("fixture : transaction non ouverte attendue"),
        };
        let reponse = al1_supprimer(st, al1_adm(), pid).await;
        let pendant = al1_entier(st, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={pid}"));
        al1_sql(st, "ROLLBACK;");
        assert_eq!(pendant, 1, "BEGIN refusé : politique conservée, même dans la transaction étrangère");
        let refus = Al1Refus { reponse, ligne: format!("[cases] WARN politique SLA #{pid} NON supprimée"), moteur, phrase: CAUSE_POLITIQUE_NON_SUPPRIMEE, statut: 503 };
        (refus, pid)
    }

    fn al1_demande_d_upsert() -> Value {
        json!({ "name": "al1", "priority": 4, "ack_target_s": 60, "resolve_target_s": 600 })
    }

    async fn al1_upsert(st: &AppState, demande: Value) -> (u16, Value) {
        al1_reponse(sla_policy_upsert(State(st.clone()), Extension(al1_ed()), Json(demande)).await).await
    }

    /// (g) `sla_policy_upsert` : l'écriture de la politique refusée par la base (cause lue par le même `INSERT`).
    async fn al1_jouer_upsert(st: &AppState) -> Al1Refus {
        al1_sql(st, "CREATE TEMP TRIGGER al1_upsert BEFORE INSERT ON sla_policy BEGIN SELECT RAISE(ABORT, 'al1 politique refusee : sla_policy.priority'); END;");
        let moteur = st
            .db
            .lock()
            .execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('al1',4,60,600,1,0,'alice',0)",
                [],
            )
            .expect_err("fixture : écriture refusée")
            .to_string();
        let reponse = al1_upsert(st, al1_demande_d_upsert()).await;
        al1_sql(st, "DROP TRIGGER al1_upsert;");
        assert_eq!(al1_entier(st, "SELECT COUNT(*) FROM sla_policy WHERE priority=4"), 0, "upsert refusé : rien d'écrit");
        Al1Refus { reponse, ligne: "[caseops] WARN politique SLA NON enregistrée".into(), moteur, phrase: CAUSE_POLITIQUE_SLA_NON_ENREGISTREE, statut: 500 }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (1) LES CORPS, EN ENTIER, PAR LE GESTIONNAIRE DE LA ROUTE
    // ---------------------------------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la fiche client lue par le rôle `client`, `incident_item` hors d'atteinte, rend 500 et le corps
    /// entier `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id, lecture_non_faite: true}` — ni le nom de la table ni la cause
    /// n'en sortent ; contrôles : la même fiche servie (200, identifiant) avant, l'absence établie 404 `{error}` d'avant.
    /// MUTANT : `AL1_FICHE_CLIENT`.
    #[tokio::test]
    async fn al1_corps_fiche_client_non_lue_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = al1_etat("corps-fiche-client");
        let id = al1_dossier(&st);
        let (statut, corps) = al1_reponse(client_case_get(State(st.clone()), Extension(al1_client()), Path(id)).await).await;
        assert_eq!((statut, corps["id"].clone()), (200, json!(id)), "contrôle : fiche client servie : {corps}");
        assert!(corps.get("error").is_none(), "contrôle : une fiche lue ne porte aucun aveu : {corps}");
        let absent = al1_reponse(client_case_get(State(st.clone()), Extension(al1_client()), Path(id + 999)).await).await;
        assert_eq!(absent, (404, json!({ "error": CAUSE_DOSSIER_CLIENT_INTROUVABLE })), "absence établie : corps d'avant");
        let (r, _) = al1_jouer_fiche_client(&st).await;
        al1_fiche_client_phrase_seule(r.reponse.0, &r.reponse.1);
        let servi = r.reponse.1.to_string();
        assert!(!servi.contains(&r.moteur) && !servi.contains("incident_item"), "fiche client : le moteur ne sort pas : {servi}");
        let (statut, _) = al1_reponse(client_case_get(State(st.clone()), Extension(al1_client()), Path(id)).await).await;
        assert_eq!(statut, 200, "contrôle : table rétablie, fiche servie");
    }

    /// CE QU'IL TIENT : fusion et défusion dont la chronologie est refusée rendent 503 et `{error: <cause>, id}` seuls, rien
    /// d'écrit ; contrôles : leviers retirés, la même fusion puis la même défusion rendent 204 sans corps.
    /// MUTANTS : `AL1_FUSION`, `AL1_DEFUSION`.
    #[tokio::test]
    async fn al1_corps_fusion_et_defusion_non_ecrites_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = al1_etat("corps-fusion");
        let (r, a, b) = al1_jouer_fusion(&st).await;
        ak3_phrase_seule("fusion non écrite", r.reponse.0, &r.reponse.1, r.phrase);
        assert!(!r.reponse.1.to_string().contains("al1 chronologie"), "fusion : le moteur ne sort pas : {}", r.reponse.1);
        let fait = al1_reponse(case_merge_handler(State(st.clone()), Extension(al1_ed()), Path(a), Json(json!({ "into": b }))).await).await;
        assert_eq!(fait, (204, Value::Null), "contrôle : levée, la fusion rend le 204 d'avant");
        let (r, c) = al1_jouer_defusion(&st).await;
        ak3_phrase_seule("défusion non écrite", r.reponse.0, &r.reponse.1, r.phrase);
        assert!(!r.reponse.1.to_string().contains("al1 defusion"), "défusion : le moteur ne sort pas : {}", r.reponse.1);
        let fait = al1_reponse(case_unmerge_handler(State(st.clone()), Extension(al1_ed()), Path(c)).await).await;
        assert_eq!(fait, (204, Value::Null), "contrôle : levée, la défusion rend le 204 d'avant");
    }

    /// CE QU'IL TIENT : la suppression d'une politique — `DELETE` refusé, effacement refusé, `BEGIN` refusé — rend 503 et
    /// `{error: <cause>, id}` seuls ; contrôles : le 403 d'un éditeur (avant le bloc) et le 404 d'absence à l'octet, puis
    /// leviers retirés, 204 sans corps. MUTANTS : `AL1_SLA_SUPPR`, `AL1_SLA_DEGOUV`, `AL1_SLA_TX`.
    #[tokio::test]
    async fn al1_corps_suppression_de_politique_refusee_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = al1_etat("corps-suppression");
        let (r, p1) = al1_jouer_suppression(&st).await;
        ak3_phrase_seule("suppression refusée", r.reponse.0, &r.reponse.1, r.phrase);
        assert!(!r.reponse.1.to_string().contains("al1 suppression"), "suppression : le moteur ne sort pas : {}", r.reponse.1);
        let (r, p2) = al1_jouer_degouvernement(&st).await;
        ak3_phrase_seule("effacement refusé", r.reponse.0, &r.reponse.1, r.phrase);
        assert!(!r.reponse.1.to_string().contains("al1 effacement"), "effacement : le moteur ne sort pas : {}", r.reponse.1);
        let (r, p3) = al1_jouer_transaction(&st).await;
        ak3_phrase_seule("transaction non ouverte", r.reponse.0, &r.reponse.1, r.phrase);
        assert!(!r.reponse.1.to_string().contains(&r.moteur), "transaction : le moteur ne sort pas : {}", r.reponse.1);
        let refuse = al1_supprimer(&st, al1_ed(), p1).await;
        assert_eq!(refuse, (403, json!({ "error": CAUSE_SUPPRESSION_DE_POLITIQUE_SLA_RESERVEE })), "403 d'un éditeur : corps d'avant");
        let absent = al1_supprimer(&st, al1_adm(), 9_999_999).await;
        assert_eq!(absent, (404, json!({ "error": CAUSE_POLITIQUE_SLA_INTROUVABLE })), "404 d'absence : corps d'avant");
        assert_eq!(al1_supprimer(&st, al1_adm(), p1).await, (204, Value::Null), "contrôle : levée, suppression de la première en 204");
        assert_eq!(al1_supprimer(&st, al1_adm(), p2).await, (204, Value::Null), "contrôle : levée, suppression de la deuxième en 204");
        assert_eq!(al1_supprimer(&st, al1_adm(), p3).await, (204, Value::Null), "contrôle : levée, suppression de la troisième en 204");
    }

    /// CE QU'IL TIENT : l'écriture de la politique refusée rend 500 et `{recomputed: 0, reason:
    /// CAUSE_POLITIQUE_SLA_NON_ENREGISTREE, id}` seuls, rien d'écrit ; contrôles : le 400 d'une priorité hors bornes
    /// (avant le bloc) à l'octet, puis levier retiré, 204 sans corps. MUTANTS : `AL1_UPSERT`, `AL1_UPSERT_ID`.
    #[tokio::test]
    async fn al1_corps_upsert_non_enregistre_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = al1_etat("corps-upsert");
        let r = al1_jouer_upsert(&st).await;
        al1_upsert_phrase_seule(r.reponse.0, &r.reponse.1);
        assert!(!r.reponse.1.to_string().contains("al1 politique"), "upsert : le moteur ne sort pas : {}", r.reponse.1);
        let hors = al1_upsert(&st, json!({ "priority": 9, "ack_target_s": 60, "resolve_target_s": 600 })).await;
        assert_eq!(hors, (400, json!({ "error": CAUSE_POLITIQUE_SLA_PRIORITE_HORS_BORNES })), "400 hors bornes : corps d'avant");
        assert_eq!(al1_upsert(&st, al1_demande_d_upsert()).await, (204, Value::Null), "contrôle : levée, 204 d'avant");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (2) LE JOURNAL, LIGNE ENTIÈRE, EN SOUS-PROCESSUS
    // ---------------------------------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : chaque refus écrit UNE ligne `<préfixe> (<identifiant servi>) : <cause du moteur>`, égale à
    /// l'attendue, et la ligne `[<identifiant>] HTTP <statut> : <phrase>` ne porte que la phrase ; ni le titre du dossier ni
    /// le nom de l'acteur au journal. MUTANTS : chacun des sept sites (forme d'avant), `AL1_FICHE_CLIENT_MUET`,
    /// `AL1_UPSERT_J`, `AL1_UPSERT_ID`.
    #[tokio::test]
    async fn al1_journal_des_refus_de_caseops() {
        const ENFANT: &str = "AL1_ENFANT_JOURNAL";
        const PHASE: &str = "AL1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = al1_etat("journal");
            let mut sortie = serde_json::Map::new();
            for phase in ["fiche_client", "fusion", "defusion", "suppression", "degouvernement", "transaction", "upsert"] {
                eprintln!("{PHASE}{phase}");
                let r = match phase {
                    "fiche_client" => al1_jouer_fiche_client(&st).await.0,
                    "fusion" => al1_jouer_fusion(&st).await.0,
                    "defusion" => al1_jouer_defusion(&st).await.0,
                    "suppression" => al1_jouer_suppression(&st).await.0,
                    "degouvernement" => al1_jouer_degouvernement(&st).await.0,
                    "transaction" => al1_jouer_transaction(&st).await.0,
                    _ => al1_jouer_upsert(&st).await,
                };
                sortie.insert(
                    phase.into(),
                    json!({ "reponse": [r.reponse.0, r.reponse.1], "ligne": r.ligne, "moteur": r.moteur, "phrase": r.phrase, "statut": r.statut }),
                );
            }
            eprintln!("{PHASE}fin");
            println!("AL1-SORTIE:{}", Value::Object(sortie));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::texte_du_moteur_hors_de_la_fiche_client_de_la_fusion_et_des_politiques_sla::al1_journal_des_refus_de_caseops",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("AL1-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie de l'enfant : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : sortie JSON ({e}) : {stdout}"));
        let lignes_de_phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().map(str::to_string).collect()
        };
        let jugees = s.as_object().map(|o| o.len()).unwrap_or(0);
        assert_eq!(jugees, 7, "contrôle : les sept refus sont joués par l'enfant : {s}");
        for (phase, r) in s.as_object().into_iter().flatten() {
            let statut = r["reponse"][0].as_u64().unwrap_or(0) as u16;
            let corps = &r["reponse"][1];
            let phrase = r["phrase"].as_str().unwrap_or_else(|| panic!("contrôle : phrase de {phase} : {r}"));
            let attendu = r["statut"].as_u64().unwrap_or(0) as u16;
            let cid = match phase.as_str() {
                "fiche_client" => al1_fiche_client_phrase_seule(statut, corps),
                "upsert" => al1_upsert_phrase_seule(statut, corps),
                _ => ak3_phrase_seule(phase, statut, corps, phrase),
            };
            let (ligne, moteur) = (r["ligne"].as_str().unwrap_or(""), r["moteur"].as_str().unwrap_or(""));
            assert!(!moteur.is_empty() && !ligne.is_empty(), "contrôle : {phase} : ligne et cause lues : {r}");
            let prefixe = if phase == "upsert" { "[caseops] WARN politique SLA" } else { "[cases] WARN" };
            let lignes = lignes_de_phase(phase);
            let du_geste: Vec<&String> = lignes.iter().filter(|l| l.contains(prefixe)).collect();
            assert_eq!(du_geste, [&format!("{ligne} ({cid}) : {moteur}")], "{phase} : la ligne de journal, ENTIÈRE");
            let marque = format!(" HTTP {attendu} : ");
            let http: Vec<&String> = lignes.iter().filter(|l| l.contains(&marque)).collect();
            assert_eq!(http, [&format!("[{cid}] HTTP {attendu} : {phrase}")], "{phase} : la ligne HTTP porte la phrase seule");
            assert!(lignes.iter().all(|l| !l.contains(AL1_TITRE) && !l.contains("alice")), "{phase} : ni titre ni acteur au journal : {lignes:?}");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (3) LA FUSION NON ÉCRITE : CE QUE LE CORPS NE DIT PLUS, LE JOURNAL LE DIT — CÔTÉ DE LA CHRONOLOGIE, BEGIN, COMMIT
    // ---------------------------------------------------------------------------------------------------------------

    /// Le motif du refus de chronologie, celui de la fixture `ab3_refuser_l_element` (chronologie_de_fusion_et_de_lien_dans_le_geste.rs).
    const AL1_MOTIF_CHRONOLOGIE: &str = "ab3 chronologie refusée";

    /// Les lignes de stderr de l'enfant entre la marque `<marque><phase>` et la marque suivante.
    fn al1_lignes_de_phase(stderr: &str, marque: &str, phase: &str) -> Vec<String> {
        let debut = stderr.split_once(&format!("{marque}{phase}\n")).unwrap_or_else(|| panic!("contrôle : phase {phase} : {stderr}")).1;
        let corps = debut.split_once(marque).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().map(str::to_string).collect()
    }

    /// Une fusion refusée par la route, selon `phase` : `chrono_source` / `chrono_cible` (élément `merge` du dossier visé
    /// refusé par trigger), `begin` (transaction étrangère ouverte sur l'écrivain), `commit` (clé étrangère DIFFÉRÉE violée
    /// par l'élément de chronologie). Le texte du moteur est lu À PART, sous le même levier, par le même appel bas
    /// (`ajouter_l_element_au_dossier` pour la chronologie, `jouer_le_geste_garde` pour `BEGIN` et `COMMIT`) : il ne porte
    /// AUCUN libellé de caseops, que le parent pose en littéral. Rien n'est écrit (relu, et sous `BEGIN` avant le `ROLLBACK`).
    async fn al1_jouer_fusion_refusee(st: &AppState, phase: &str) -> Value {
        use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde};
        let (a, b) = (al1_dossier(st), al1_dossier(st));
        let moteur = match phase {
            "chrono_source" | "chrono_cible" => {
                let refuse = if phase == "chrono_source" { a } else { b };
                al1_sql(
                    st,
                    &format!("CREATE TEMP TRIGGER al1_chrono_fusion BEFORE INSERT ON incident_item WHEN NEW.kind='merge' AND NEW.incident_id={refuse} BEGIN SELECT RAISE(ABORT, '{AL1_MOTIF_CHRONOLOGIE}'); END;"),
                );
                crate::handlers::cases::ajouter_l_element_au_dossier(&st.db.lock(), refuse, now(), "merge", "sonde", "sonde", None).expect_err("fixture : élément de fusion refusé")
            }
            "begin" => {
                al1_sql(st, "BEGIN;");
                match jouer_le_geste_garde(&st.db.lock(), "al1", "sonde", |_| Ok::<(), ()>(())) {
                    IssueDuGesteGarde::NonOuvert(e) => e.to_string(),
                    _ => panic!("fixture : transaction non ouverte attendue"),
                }
            }
            _ => {
                al1_sql(
                    st,
                    "PRAGMA foreign_keys=ON;
                     CREATE TEMP TABLE al1_parent(id INTEGER PRIMARY KEY);
                     CREATE TEMP TABLE al1_enfant(p INTEGER REFERENCES al1_parent(id) DEFERRABLE INITIALLY DEFERRED);
                     CREATE TEMP TRIGGER al1_fk AFTER INSERT ON incident_item BEGIN INSERT INTO al1_enfant VALUES(999); END;",
                );
                match jouer_le_geste_garde(&st.db.lock(), "al1", "sonde", |c| {
                    c.execute("INSERT INTO al1_enfant VALUES(999)", []).expect("fixture : insertion différée");
                    Ok::<(), ()>(())
                }) {
                    IssueDuGesteGarde::NonValide(e) => e.to_string(),
                    _ => panic!("fixture : validation refusée attendue"),
                }
            }
        };
        let reponse = al1_reponse(case_merge_handler(State(st.clone()), Extension(al1_ed()), Path(a), Json(json!({ "into": b }))).await).await;
        let ecrit = al1_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={a} AND merged_into IS NOT NULL"))
            + al1_entier(st, &format!("SELECT COUNT(*) FROM incident_item WHERE kind='merge' AND incident_id IN ({a},{b})"));
        match phase {
            "chrono_source" | "chrono_cible" => al1_sql(st, "DROP TRIGGER al1_chrono_fusion;"),
            "begin" => al1_sql(st, "ROLLBACK;"),
            _ => al1_sql(st, "DROP TRIGGER al1_fk; DROP TABLE al1_enfant; DROP TABLE al1_parent; PRAGMA foreign_keys=OFF;"),
        }
        assert_eq!(ecrit, 0, "fixture : {phase} : la fusion refusée n'écrit rien");
        assert!(st.db.lock().is_autocommit(), "fixture : {phase} : aucune transaction laissée ouverte");
        json!({ "reponse": [reponse.0, reponse.1], "ligne": format!("[cases] WARN dossier #{a} : fusion dans #{b} NON écrite"), "moteur": moteur })
    }

    /// CE QU'IL TIENT (`case_merge_handler`, par la route, rôle `editor`) : la fusion non écrite sert la phrase seule
    /// `{error: CAUSE_FUSION_NON_ECRITE, id}` (corps ENTIER) dans les quatre cas, et ce qui les DISTINGUAIT dans le corps
    /// d'avant part au journal, UNE ligne `[cases] WARN dossier #<a> : fusion dans #<b> NON écrite (<id servi>) : <cause>`,
    /// comparée ENTIÈRE, où `<cause>` est `chronologie de la source : <moteur>`, `chronologie de la cible : <moteur>`,
    /// `transaction non ouverte : <moteur>` ou `validation refusée : <moteur>` — libellés posés ici en littéral, moteur lu à
    /// part ; la chronologie porte le motif `ab3 chronologie refusée`. La ligne `HTTP 503` ne porte que la phrase ; ni
    /// titre ni acteur au journal. Rétablit le témoin du `BEGIN` contre le `COMMIT` que l'inversion de
    /// `ab3_une_fusion_dont_la_transaction_est_refusee_n_ecrit_rien` avait retiré du corps.
    /// MUTANTS : `AL1C_LABEL` (libellés `BEGIN`/`COMMIT` échangés, `issue_du_geste_de_fusion`), `AL1C_COTE` (libellés
    /// source/cible échangés, `case_merge`), `AL1C_FUSION_AVANT` (le 503 d'avant, cause dans le corps, aucune ligne).
    #[tokio::test]
    async fn al1_journal_de_la_fusion_non_ecrite_nomme_chronologie_begin_et_commit() {
        const ENFANT: &str = "AL1_ENFANT_JOURNAL_FUSION";
        const PHASE: &str = "AL1C-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = al1_etat("journal-fusion");
            let mut sortie = serde_json::Map::new();
            for phase in ["chrono_source", "chrono_cible", "begin", "commit"] {
                eprintln!("{PHASE}{phase}");
                sortie.insert(phase.into(), al1_jouer_fusion_refusee(&st, phase).await);
            }
            eprintln!("{PHASE}fin");
            println!("AL1C-SORTIE:{}", Value::Object(sortie));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::texte_du_moteur_hors_de_la_fiche_client_de_la_fusion_et_des_politiques_sla::al1_journal_de_la_fusion_non_ecrite_nomme_chronologie_begin_et_commit",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("AL1C-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie de l'enfant : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : sortie JSON ({e}) : {stdout}"));
        let jugees = s.as_object().map(|o| o.len()).unwrap_or(0);
        assert_eq!(jugees, 4, "contrôle : les quatre refus sont joués par l'enfant : {s}");
        for (phase, r) in s.as_object().into_iter().flatten() {
            let statut = r["reponse"][0].as_u64().unwrap_or(0) as u16;
            let cid = ak3_phrase_seule(phase, statut, &r["reponse"][1], CAUSE_FUSION_NON_ECRITE);
            let (ligne, moteur) = (r["ligne"].as_str().unwrap_or(""), r["moteur"].as_str().unwrap_or(""));
            assert!(!moteur.is_empty() && !ligne.is_empty(), "contrôle : {phase} : ligne et moteur lus : {r}");
            let cause = match phase.as_str() {
                "chrono_source" => format!("chronologie de la source : {moteur}"),
                "chrono_cible" => format!("chronologie de la cible : {moteur}"),
                "begin" => format!("transaction non ouverte : {moteur}"),
                "commit" => format!("validation refusée : {moteur}"),
                autre => panic!("contrôle : phase inconnue {autre}"),
            };
            if phase.starts_with("chrono_") {
                assert!(moteur.contains(AL1_MOTIF_CHRONOLOGIE), "contrôle : {phase} : le moteur porte le motif du trigger : {moteur}");
            }
            assert!(!r["reponse"][1].to_string().contains(moteur), "{phase} : le moteur ne sort pas dans le corps : {r}");
            let lignes = al1_lignes_de_phase(&stderr, PHASE, phase);
            let du_geste: Vec<&String> = lignes.iter().filter(|l| l.contains("[cases] WARN")).collect();
            assert_eq!(du_geste, [&format!("{ligne} ({cid}) : {cause}")], "{phase} : la ligne de journal, ENTIÈRE");
            let http: Vec<&String> = lignes.iter().filter(|l| l.contains(" HTTP 503 : ")).collect();
            assert_eq!(http, [&format!("[{cid}] HTTP 503 : {CAUSE_FUSION_NON_ECRITE}")], "{phase} : la ligne HTTP porte la phrase seule");
            assert!(lignes.iter().all(|l| !l.contains(AL1_TITRE) && !l.contains("alice")), "{phase} : ni titre ni acteur au journal : {lignes:?}");
        }
    }
}
