// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi au client », suite, vague AK) — LES 503 DES GESTES DE DOSSIER
// (handlers/cases.rs) SERVENT LA PHRASE SEULE ; LA CAUSE DU MOTEUR VA AU JOURNAL AVEC L'IDENTIFIANT SERVI.
//
// LE DÉFAUT, MESURÉ SUR 307d4dc3 : dix sites servaient `<phrase> (<moteur>)` dans un 503 lisible par tout rôle qui
// écrit sur un dossier — chemins, noms de colonnes (`no such column: sla_pause_accum`), motifs de contrainte :
//   * `refus_du_dossier_non_lu` (`format!("{CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT} ({e})")`), appelé par
//     `etablir_le_dossier` (toutes les routes de dossier), `juger_la_defusion`, `RefusDeFusion::NonLu`, la pose de lien
//     (caseops.rs) et les runbooks (incidents.rs) ;
//   * `case_create` (`CAUSE_DOSSIER_NON_OUVERT ({cause})`), `case_update` (`CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE
//     ({cause})`, `CAUSE_CHRONO_SLA_NON_LU ({cause})`), `case_archive` / `case_unarchive` (`CAUSE_ARCHIVAGE_NON_ECRIT`,
//     `CAUSE_DESARCHIVAGE_NON_ECRIT`, `CAUSE_CHRONO_SLA_NON_LU`, chacun `({cause})`), `case_item_delete`
//     (`CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT ({e})`, et le détachement refusé `{cause} ({moteur})`).
//
// LE CORRECTIF : un assistant partagé, `refus_nomme_cause_au_journal(cause, geste, moteur)` — corps `{error: <cause>,
// id}` (statut 503 et ouverture de cause inchangés : la console les lit déjà), ligne `[cases] WARN <geste> (<id>) :
// <moteur>` au journal ; quand le geste nomme le dossier, c'est par son numéro, jamais par son titre, son assigné ni la
// demande (`refus_du_dossier_non_lu` n'en nomme aucun : l'identifiant de corrélation seul relie sa ligne). Les deux
// phrases qui renvoyaient « entre parenthèses » (`CAUSE_CHRONO_SLA_NON_LU`, `CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE`)
// renvoient au journal. Les deux `match` jumeaux d'archivage deviennent `reponse_du_geste_d_archivage` : leur bras
// « chrono non lu », que `case_set_archived` ne rend jamais, est ainsi joué par appel (le point d'entrée des routes).
// Le cinq cents de la fiche (`case_get`, lisible par tout lecteur, rôle viewer) servait `dossier NON LU : la lecture a
// échoué (<moteur>) — …` : `refus_de_la_fiche_non_lue` sert `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id,
// lecture_non_faite: true}` (même statut, même ouverture, même drapeau), le moteur au journal.
//
// LES TÉMOINS (par la route, identité éditeur — administrateur pour l'archivage, réservé) :
// (1) `ak3_corps_*` : chaque refus rend 503 et le corps ENTIER `{error: <phrase>, id: plume-e…}` (ensemble exact des
//     clés, phrase égale) ; rien n'est écrit (ligne relue) ; contrôles : 404 d'absence et succès d'avant à l'octet.
// (2) `ak3_journal_des_refus_de_dossier` : le binaire se rejoue en sous-processus, l'enfant joue chaque refus entre
//     deux marques de phase, le parent compare les lignes `[cases]` ENTIÈRES (une par refus, identifiant servi, cause
//     du moteur lue à part sous le même refus) et la ligne `HTTP 503` ENTIÈRE (la phrase seule) ; la fiche non lue, à
//     part (cinq cents), ligne `[cases]` et ligne `HTTP 500` ENTIÈRES.
// (3) `ak3_corps_fiche_non_lue_phrase_seule` : la fiche lue par un viewer, `incident_item` hors d'atteinte, rend 500 et le
//     corps ENTIER `{error, id, lecture_non_faite}` ; contrôles : fiche servie avant, 404 d'absence d'avant.
//
// MUTANTS (variable de mutation sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE : la forme
// d'avant au site — `AK3_LECTURE` (assistant `refus_du_dossier_non_lu`), `AK3_OUVERTURE`, `AK3_MAJ`, `AK3_CHRONO`,
// `AK3_ELEMENT`, `AK3_DETACHE`, `AK3_ARCHIVE_NON_ECRIT`, `AK3_DESARCHIVE_NON_ECRIT`, `AK3_ARCHIVE_CHRONO`,
// `AK3_DESARCHIVE_CHRONO` rougissent (1) et (2) ; la ligne de journal tue (`AK3_J`) ou sans identifiant (`AK3_J_CID`)
// rougissent (2). Correction : `AK3_FICHE` (forme d'avant du cinq cents de la fiche) rougit (2) et (3) ;
// `AK3_FICHE_J` (ligne de journal de la fiche tue) rougit (2).
//
// TESTS ANTÉRIEURS INVERSÉS NOMMÉMENT (ils lisaient la cause dans le corps servi) : `csl_cause`, `cse_cause`,
// `drc_cause`, `dmr_cause` lisent la cause à `case_apply_update` ; `dossier_champs_libres_ecrits_comptes.rs`,
// `dossier_cree_echeance_relue_priorite_comptee.rs`, `dossier_et_echeances_comptes.rs`,
// `dossier_priorite_ecrite_echeance_rattrapee.rs`, `chronologie_et_maillon_des_gestes_de_dossier.rs` et
// `detachement_d_element_ecrit_ou_refuse.rs` jugent la phrase seule par `ak3_phrase_seule` et la cause à la fonction.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les corps 200 de `case_create` (`sla_due_non_lu`, `echeances_multi_niveau_*`)
// servent encore `({e})` / `({cause})` (relus mot pour mot par l'instrument 137 du harnais console) ; le bras
// `DossierAbsent` des archivages et les appelants de caseops.rs / incidents.rs passent par l'assistant (corps changé
// par lui seul) sans témoin de route propre ; les causes portées par `registre_sans_maillon` (hors vague) ; la fiche
// d'un dossier vue par le CLIENT (`client_case_get`, caseops.rs) sert encore `dossier NON LU : la lecture a échoué
// ({e})` (hors lot, comme `LienDeDossier::NonPose` et `LienRetire::NonRetire`).
// =====================================================================================
mod dossier_refus_sans_texte_du_moteur {
    use super::*;
    use crate::handlers::cases::{
        reponse_du_geste_d_archivage, CAUSE_ARCHIVAGE_NON_ECRIT, CAUSE_DESARCHIVAGE_NON_ECRIT, CAUSE_DOSSIER_INTROUVABLE,
        CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT, CAUSE_DOSSIER_NON_OUVERT, CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER, CAUSE_ELEMENT_NON_DETACHE,
        CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT, CAUSE_FICHE_DU_DOSSIER_NON_LUE, IssueDuDetachement,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// UN 503 NOMMÉ SANS TEXTE DU MOTEUR : statut 503, corps ENTIER `{error: <cause>, id: plume-e…}` ; rend l'identifiant
    /// servi. Partagé par les tests antérieurs inversés par ce lot (ils lisaient la cause dans le corps).
    pub(super) fn ak3_phrase_seule(quoi: &str, statut: u16, corps: &Value, cause: &str) -> String {
        assert_eq!(statut, 503, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule, sans texte du moteur : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    const AK3_TITRE: &str = "ak3-titre-du-dossier";
    const AK3_ASSIGNE: &str = "ak3-assigne";

    fn ak3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ak3-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            // Politiques en P1 et P3 (le chrono SLA d'un dossier P3 se lit à la mise à jour) ; aucune en P2.
            conn.execute_batch(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
                 INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P3',3,3000,30000,1,0,'root',0);",
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ak3_ed() -> AuthUser {
        AuthUser {
            name: "alice".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ak3_adm() -> AuthUser {
        AuthUser {
            name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ak3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn ak3_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ak3_dossier(st: &AppState, priorite: i64) -> i64 {
        dossier_seme(&st.db.lock(), "alice", AK3_TITRE, 3, "", None, priorite)
    }

    fn ak3_element(st: &AppState, id: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute("INSERT INTO incident_item(incident_id,ts,kind,author,body) VALUES(?1,1,'note','alice','ak3')", params![id])
            .expect("fixture : élément écrit");
        conn.last_insert_rowid()
    }

    async fn ak3_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// Refuse toute lecture de `table` sur l'écrivain (autorisateur SQLite).
    fn ak3_refuser_la_lecture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ak3_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Un refus joué par la route : la réponse, le geste attendu au journal, la cause du moteur lue à part sous le même
    /// refus (pour comparer la ligne ENTIÈRE), et la phrase attendue au corps.
    struct Ak3Refus {
        reponse: (u16, Value),
        geste: String,
        moteur: String,
        phrase: &'static str,
    }

    /// (a) `etablir_le_dossier` -> `refus_du_dossier_non_lu` : la lecture du dossier refusée, mise à jour du titre.
    async fn ak3_jouer_lecture(st: &AppState) -> Ak3Refus {
        let id = ak3_dossier(st, 2);
        ak3_refuser_la_lecture(st, "incident");
        let moteur = st.db.lock().query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).expect_err("fixture : lecture refusée").to_string();
        let r = case_update(State(st.clone()), Extension(ak3_ed()), Path(id), Json(json!({ "title": "ak3-titre-neuf", "assignee": AK3_ASSIGNE }))).await;
        let reponse = ak3_reponse(r).await;
        ak3_lever(st);
        assert_eq!(ak3_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND title='{AK3_TITRE}' AND assignee IS NULL")), 1, "lecture refusée : rien d'écrit");
        Ak3Refus { reponse, geste: "dossier NON lu, geste non fait".into(), moteur, phrase: CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT }
    }

    /// (b) `case_create` : l'`INSERT` du dossier refusé par la base.
    async fn ak3_jouer_ouverture(st: &AppState) -> Ak3Refus {
        let avant = ak3_entier(st, "SELECT COUNT(*) FROM incident");
        ak3_sql(st, "CREATE TEMP TRIGGER ak3_ouverture BEFORE INSERT ON incident BEGIN SELECT RAISE(ABORT, 'ak3 ouverture refusee : incident.title'); END;");
        let moteur = match case_create_row_echeances_et_maillon(&st.db.lock(), "alice", AK3_TITRE, 2, "", None, 2).0 {
            DossierOuvert::NonOuvert(cause) => cause,
            DossierOuvert::Ouvert(id) => panic!("fixture : ouverture refusée attendue, dossier #{id} ouvert"),
        };
        let r = case_create(State(st.clone()), Extension(ak3_ed()), Json(json!({ "title": AK3_TITRE, "assignee": AK3_ASSIGNE, "priority": 2 }))).await;
        let reponse = ak3_reponse(r).await;
        ak3_sql(st, "DROP TRIGGER ak3_ouverture;");
        assert_eq!(ak3_entier(st, "SELECT COUNT(*) FROM incident"), avant, "ouverture refusée : aucun dossier");
        Ak3Refus { reponse, geste: "dossier NON ouvert".into(), moteur, phrase: CAUSE_DOSSIER_NON_OUVERT }
    }

    /// (c) `case_update`, `NonEcrite` : l'assignation refusée par la base (cause lue sur un dossier jumeau).
    async fn ak3_jouer_mise_a_jour(st: &AppState) -> Ak3Refus {
        let (id, jumeau) = (ak3_dossier(st, 2), ak3_dossier(st, 2));
        ak3_sql(st, "CREATE TEMP TRIGGER ak3_assignation BEFORE UPDATE OF assignee ON incident BEGIN SELECT RAISE(ABORT, 'ak3 assignation refusee : incident.assignee'); END;");
        let demande = json!({ "assignee": AK3_ASSIGNE });
        let moteur = match case_apply_update(&st.db.lock(), jumeau, "alice", &demande) {
            IssueDuDossierModifie::NonEcrite(cause) => cause,
            autre => panic!("fixture : `NonEcrite` attendu, pas {autre:?}"),
        };
        let r = case_update(State(st.clone()), Extension(ak3_ed()), Path(id), Json(demande)).await;
        let reponse = ak3_reponse(r).await;
        ak3_sql(st, "DROP TRIGGER ak3_assignation;");
        assert_eq!(ak3_entier(st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND assignee IS NULL")), 1, "assignation refusée : non écrite");
        Ak3Refus { reponse, geste: format!("dossier #{id} : mise à jour NON écrite"), moteur, phrase: CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE }
    }

    /// (d) `case_update`, `ChronoSlaNonLu` : la colonne `sla_pause_accum` hors d'atteinte (le texte du moteur la nomme).
    async fn ak3_jouer_chrono(st: &AppState) -> Ak3Refus {
        let (id, jumeau) = (ak3_dossier(st, 3), ak3_dossier(st, 3));
        let echeance = ak3_entier(st, &format!("SELECT resolve_due FROM incident WHERE id={id}"));
        ak3_sql(st, "ALTER TABLE incident RENAME COLUMN sla_pause_accum TO ak3_pause_cachee;");
        let moteur = match case_apply_update(&st.db.lock(), jumeau, "alice", &json!({ "priority": 1 })) {
            IssueDuDossierModifie::ChronoSlaNonLu(cause) => cause,
            autre => panic!("fixture : `ChronoSlaNonLu` attendu, pas {autre:?}"),
        };
        let r = case_update(State(st.clone()), Extension(ak3_ed()), Path(id), Json(json!({ "priority": 1 }))).await;
        let reponse = ak3_reponse(r).await;
        ak3_sql(st, "ALTER TABLE incident RENAME COLUMN ak3_pause_cachee TO sla_pause_accum;");
        assert_eq!(ak3_entier(st, &format!("SELECT resolve_due FROM incident WHERE id={id}")), echeance, "chrono non lu : échéance inchangée");
        assert!(moteur.contains("sla_pause_accum"), "fixture : le texte du moteur nomme la colonne : {moteur}");
        Ak3Refus { reponse, geste: format!("dossier #{id} : chrono SLA NON lu, mise à jour non écrite"), moteur, phrase: CAUSE_CHRONO_SLA_NON_LU }
    }

    /// (e) `case_item_delete` : la lecture de l'élément refusée.
    async fn ak3_jouer_element(st: &AppState) -> Ak3Refus {
        let id = ak3_dossier(st, 2);
        let item = ak3_element(st, id);
        ak3_refuser_la_lecture(st, "incident_item");
        let moteur = st
            .db
            .lock()
            .query_row("SELECT 1 FROM incident_item WHERE id=?1 AND incident_id=?2", params![item, id], |_| Ok(()))
            .expect_err("fixture : lecture refusée")
            .to_string();
        let r = case_item_delete(State(st.clone()), Extension(ak3_ed()), Path((id, item))).await;
        let reponse = ak3_reponse(r).await;
        ak3_lever(st);
        assert_eq!(ak3_entier(st, &format!("SELECT COUNT(*) FROM incident_item WHERE id={item}")), 1, "élément non lu : toujours là");
        Ak3Refus { reponse, geste: format!("élément #{item} du dossier #{id} NON lu, rien n'est détaché"), moteur, phrase: CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT }
    }

    /// (f) `case_item_delete` : l'effacement refusé par la base (cause du moteur lue sur un élément jumeau).
    async fn ak3_jouer_detachement(st: &AppState) -> Ak3Refus {
        let id = ak3_dossier(st, 2);
        let (item, jumeau) = (ak3_element(st, id), ak3_element(st, id));
        ak3_sql(st, "CREATE TEMP TRIGGER ak3_effacement BEFORE DELETE ON incident_item BEGIN SELECT RAISE(ABORT, 'ak3 effacement refuse : incident_item'); END;");
        let moteur = match case_detach_item(&st.db.lock(), id, jumeau, "alice") {
            IssueDuDetachement::NonEcrit { cause, moteur: Some(moteur) } if cause == CAUSE_ELEMENT_NON_DETACHE => moteur,
            autre => panic!("fixture : effacement refusé attendu, pas {autre:?}"),
        };
        let r = case_item_delete(State(st.clone()), Extension(ak3_ed()), Path((id, item))).await;
        let reponse = ak3_reponse(r).await;
        ak3_sql(st, "DROP TRIGGER ak3_effacement;");
        assert_eq!(ak3_entier(st, &format!("SELECT COUNT(*) FROM incident_item WHERE id={item}")), 1, "effacement refusé : toujours là");
        Ak3Refus { reponse, geste: format!("élément #{item} du dossier #{id} NON détaché"), moteur, phrase: CAUSE_ELEMENT_NON_DETACHE }
    }

    /// (g) `case_archive` (`archive`) ou `case_unarchive` : l'`UPDATE` d'archivage refusé par la base.
    async fn ak3_jouer_archivage(st: &AppState, archive: bool) -> Ak3Refus {
        let (id, jumeau) = (ak3_dossier(st, 2), ak3_dossier(st, 2));
        if !archive {
            ak3_sql(st, &format!("UPDATE incident SET archived=1 WHERE id IN ({id},{jumeau})"));
        }
        ak3_sql(st, "CREATE TEMP TRIGGER ak3_archivage BEFORE UPDATE OF archived ON incident BEGIN SELECT RAISE(ABORT, 'ak3 archivage refuse : incident.archived'); END;");
        let moteur = match case_set_archived(&st.db.lock(), jumeau, "adm", archive) {
            IssueDuDossierModifie::NonEcrite(cause) => cause,
            autre => panic!("fixture : `NonEcrite` attendu, pas {autre:?}"),
        };
        let r = if archive {
            case_archive(State(st.clone()), Extension(ak3_adm()), Path(id)).await
        } else {
            case_unarchive(State(st.clone()), Extension(ak3_adm()), Path(id)).await
        };
        let reponse = ak3_reponse(r).await;
        ak3_sql(st, "DROP TRIGGER ak3_archivage;");
        let attendu = if archive { 0 } else { 1 };
        assert_eq!(ak3_entier(st, &format!("SELECT archived FROM incident WHERE id={id}")), attendu, "archivage refusé : état d'avant");
        let (geste, phrase) = if archive { ("archivage", CAUSE_ARCHIVAGE_NON_ECRIT) } else { ("désarchivage", CAUSE_DESARCHIVAGE_NON_ECRIT) };
        Ak3Refus { reponse, geste: format!("dossier #{id} : {geste} NON écrit"), moteur, phrase }
    }

    /// (h) le bras « chrono non lu » de la réponse d'archivage — `case_set_archived` ne le rend jamais : joué par appel du
    /// point d'entrée que les deux routes appellent (`reponse_du_geste_d_archivage`).
    async fn ak3_jouer_archivage_chrono(archive: bool) -> Ak3Refus {
        let id = 4242;
        let moteur = "no such column: sla_pause_accum".to_string();
        let r = reponse_du_geste_d_archivage(IssueDuDossierModifie::ChronoSlaNonLu(moteur.clone()), id, archive);
        let geste = if archive { "archivage" } else { "désarchivage" };
        Ak3Refus { reponse: ak3_reponse(r).await, geste: format!("dossier #{id} : chrono SLA NON lu, {geste} non écrit"), moteur, phrase: CAUSE_CHRONO_SLA_NON_LU }
    }

    fn ak3_viewer() -> AuthUser {
        AuthUser {
            name: "vic".into(), role: "viewer".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// (i) `case_get` : la fiche d'un dossier lue par un viewer, `incident_item` hors d'atteinte (le texte du moteur nomme
    /// la table) ; rend (réponse, numéro du dossier, cause du moteur lue à part sous le même refus).
    async fn ak3_jouer_fiche(st: &AppState) -> ((u16, Value), i64, String) {
        let id = ak3_dossier(st, 2);
        ak3_sql(st, "ALTER TABLE incident_item RENAME TO ak3_items_caches;");
        let moteur = match case_get_lu(&st.db.lock(), id, now()) {
            Err(e) => e.to_string(),
            Ok(v) => panic!("fixture : lecture de la fiche ratée attendue, pas {v:?}"),
        };
        let reponse = ak3_reponse(case_get(State(st.clone()), Extension(ak3_viewer()), Path(id)).await).await;
        ak3_sql(st, "ALTER TABLE ak3_items_caches RENAME TO incident_item;");
        assert!(moteur.contains("incident_item"), "fixture : le texte du moteur nomme la table : {moteur}");
        (reponse, id, moteur)
    }

    /// LE CINQ CENTS DE LA FICHE : statut 500, corps ENTIER `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id: plume-e…,
    /// lecture_non_faite: true}` ; rend l'identifiant servi.
    fn ak3_fiche_phrase_seule(statut: u16, corps: &Value) -> String {
        assert_eq!(statut, 500, "fiche non lue : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("fiche non lue : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id", "lecture_non_faite"], "fiche non lue : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FICHE_DU_DOSSIER_NON_LUE), "fiche non lue : la phrase seule, sans texte du moteur : {corps}");
        assert_eq!(corps["lecture_non_faite"], json!(true), "fiche non lue : le drapeau d'avant : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("fiche non lue : identifiant : {corps}")).to_string()
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (1) LES CORPS, EN ENTIER, PAR LA ROUTE
    // ---------------------------------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture du dossier refusée (`etablir_le_dossier` -> `refus_du_dossier_non_lu`) rend le corps
    /// entier `{error: CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT, id}` ; contrôles : absence établie 404 `{error}` d'avant, et
    /// la même mise à jour levée rend 204. MUTANT : `AK3_LECTURE`.
    #[tokio::test]
    async fn ak3_corps_lecture_du_dossier_refusee_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-lecture");
        let r = ak3_jouer_lecture(&st).await;
        ak3_phrase_seule("lecture refusée", r.reponse.0, &r.reponse.1, r.phrase);
        let id = ak3_dossier(&st, 2);
        let absent = ak3_reponse(case_update(State(st.clone()), Extension(ak3_ed()), Path(id + 999), Json(json!({ "title": "x" }))).await).await;
        assert_eq!(absent, (404, json!({ "error": CAUSE_DOSSIER_INTROUVABLE })), "absence établie : corps d'avant");
        let leve = ak3_reponse(case_update(State(st.clone()), Extension(ak3_ed()), Path(id), Json(json!({ "title": "ak3-leve" }))).await).await;
        assert_eq!(leve, (204, Value::Null), "levée : 204 d'avant");
    }

    /// CE QU'IL TIENT : l'ouverture refusée rend `{error: CAUSE_DOSSIER_NON_OUVERT, id}`, aucun dossier ; contrôle : levée,
    /// 200 avec l'identifiant. MUTANT : `AK3_OUVERTURE`.
    #[tokio::test]
    async fn ak3_corps_ouverture_refusee_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-ouverture");
        let r = ak3_jouer_ouverture(&st).await;
        ak3_phrase_seule("ouverture refusée", r.reponse.0, &r.reponse.1, r.phrase);
        let (statut, corps) = ak3_reponse(case_create(State(st.clone()), Extension(ak3_ed()), Json(json!({ "title": AK3_TITRE, "priority": 2 }))).await).await;
        assert_eq!(statut, 200, "levée : dossier ouvert : {corps}");
        assert!(corps["id"].as_i64().is_some(), "levée : identifiant servi : {corps}");
    }

    /// CE QU'IL TIENT : l'écriture refusée (`NonEcrite`) et le chrono non lu (`ChronoSlaNonLu`) d'une mise à jour rendent
    /// la phrase seule ; contrôle : la priorité levée rend 204. MUTANTS : `AK3_MAJ`, `AK3_CHRONO`.
    #[tokio::test]
    async fn ak3_corps_mise_a_jour_non_ecrite_et_chrono_non_lu_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-maj");
        let r = ak3_jouer_mise_a_jour(&st).await;
        ak3_phrase_seule("mise à jour non écrite", r.reponse.0, &r.reponse.1, r.phrase);
        let r = ak3_jouer_chrono(&st).await;
        ak3_phrase_seule("chrono non lu", r.reponse.0, &r.reponse.1, r.phrase);
        let id = ak3_dossier(&st, 3);
        let leve = ak3_reponse(case_update(State(st.clone()), Extension(ak3_ed()), Path(id), Json(json!({ "priority": 1, "assignee": AK3_ASSIGNE }))).await).await;
        assert_eq!(leve, (204, Value::Null), "levée : 204 d'avant");
    }

    /// CE QU'IL TIENT : élément non lu et effacement refusé rendent la phrase seule ; contrôles : élément absent 404
    /// `{error}` d'avant, note refusée (cause du moteur jamais servie, bras inchangé) `{error, id}` d'avant, levée 204.
    /// MUTANTS : `AK3_ELEMENT`, `AK3_DETACHE`.
    #[tokio::test]
    async fn ak3_corps_element_non_lu_et_detachement_refuse_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-element");
        let r = ak3_jouer_element(&st).await;
        ak3_phrase_seule("élément non lu", r.reponse.0, &r.reponse.1, r.phrase);
        let r = ak3_jouer_detachement(&st).await;
        ak3_phrase_seule("effacement refusé", r.reponse.0, &r.reponse.1, r.phrase);
        let id = ak3_dossier(&st, 2);
        let absent = ak3_reponse(case_item_delete(State(st.clone()), Extension(ak3_ed()), Path((id, 9_999_999))).await).await;
        assert_eq!(absent, (404, json!({ "error": CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER })), "élément absent : corps d'avant");
        let item = ak3_element(&st, id);
        ak3_sql(&st, "CREATE TEMP TRIGGER ak3_note BEFORE INSERT ON incident_item BEGIN SELECT RAISE(ABORT, 'ak3 note refusee'); END;");
        let note = ak3_reponse(case_item_delete(State(st.clone()), Extension(ak3_ed()), Path((id, item))).await).await;
        ak3_sql(&st, "DROP TRIGGER ak3_note;");
        ak3_phrase_seule("note refusée (bras inchangé)", note.0, &note.1, CAUSE_ELEMENT_NON_DETACHE);
        let leve = ak3_reponse(case_item_delete(State(st.clone()), Extension(ak3_ed()), Path((id, item))).await).await;
        assert_eq!(leve, (204, Value::Null), "levée : 204 d'avant");
    }

    /// CE QU'IL TIENT : archivage et désarchivage refusés, et le bras « chrono non lu » de leur réponse, rendent la phrase
    /// seule ; contrôle : archivage puis désarchivage levés, 204. MUTANTS : `AK3_ARCHIVE_NON_ECRIT`,
    /// `AK3_DESARCHIVE_NON_ECRIT`, `AK3_ARCHIVE_CHRONO`, `AK3_DESARCHIVE_CHRONO`.
    #[tokio::test]
    async fn ak3_corps_archivage_et_desarchivage_refuses_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-archive");
        let r = ak3_jouer_archivage(&st, true).await;
        ak3_phrase_seule("archivage refusé", r.reponse.0, &r.reponse.1, r.phrase);
        let r = ak3_jouer_archivage(&st, false).await;
        ak3_phrase_seule("désarchivage refusé", r.reponse.0, &r.reponse.1, r.phrase);
        let r = ak3_jouer_archivage_chrono(true).await;
        ak3_phrase_seule("archivage, chrono non lu", r.reponse.0, &r.reponse.1, r.phrase);
        let r = ak3_jouer_archivage_chrono(false).await;
        ak3_phrase_seule("désarchivage, chrono non lu", r.reponse.0, &r.reponse.1, r.phrase);
        let id = ak3_dossier(&st, 2);
        assert_eq!(ak3_reponse(case_archive(State(st.clone()), Extension(ak3_adm()), Path(id)).await).await, (204, Value::Null), "archivage levé");
        assert_eq!(ak3_reponse(case_unarchive(State(st.clone()), Extension(ak3_adm()), Path(id)).await).await, (204, Value::Null), "désarchivage levé");
    }

    /// CE QU'IL TIENT : la fiche d'un dossier lue par un viewer, `incident_item` hors d'atteinte, rend 500 et le corps
    /// entier `{error: CAUSE_FICHE_DU_DOSSIER_NON_LUE, id, lecture_non_faite: true}` — le nom de la table n'en sort pas ;
    /// contrôles : la même fiche servie (200, titre) avant, et l'absence établie 404 `{error}` d'avant. MUTANT : `AK3_FICHE`.
    #[tokio::test]
    async fn ak3_corps_fiche_non_lue_phrase_seule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _t) = ak3_etat("corps-fiche");
        let id = ak3_dossier(&st, 2);
        let (statut, corps) = ak3_reponse(case_get(State(st.clone()), Extension(ak3_viewer()), Path(id)).await).await;
        assert_eq!((statut, corps["title"].clone()), (200, json!(AK3_TITRE)), "contrôle : fiche servie : {corps}");
        let absent = ak3_reponse(case_get(State(st.clone()), Extension(ak3_viewer()), Path(id + 999)).await).await;
        assert_eq!(absent, (404, json!({ "error": CAUSE_DOSSIER_INTROUVABLE })), "absence établie : corps d'avant");
        let ((statut, corps), _, moteur) = ak3_jouer_fiche(&st).await;
        ak3_fiche_phrase_seule(statut, &corps);
        assert!(!corps.to_string().contains(&moteur) && !corps.to_string().contains("incident_item"), "fiche non lue : le moteur ne sort pas : {corps}");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // (2) LE JOURNAL, LIGNE ENTIÈRE, EN SOUS-PROCESSUS
    // ---------------------------------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : chaque refus écrit UNE ligne `[cases] WARN <geste> (<identifiant servi>) : <cause du moteur>`,
    /// égale à l'attendue, et la ligne `[<identifiant>] HTTP 503 : <phrase>` d'`err_json_et_identifiant` ne porte que la
    /// phrase. MUTANTS : chacun des dix sites (forme d'avant), `AK3_J` (ligne tue), `AK3_J_CID` (ligne sans identifiant).
    #[tokio::test]
    async fn ak3_journal_des_refus_de_dossier() {
        const ENFANT: &str = "AK3_ENFANT_JOURNAL";
        const PHASE: &str = "AK3-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _t) = ak3_etat("journal");
            let mut sortie = serde_json::Map::new();
            let phases = [
                "lecture", "ouverture", "maj", "chrono", "element", "detachement", "archive", "desarchive", "archive_chrono", "desarchive_chrono",
            ];
            for phase in phases {
                eprintln!("{PHASE}{phase}");
                let r = match phase {
                    "lecture" => ak3_jouer_lecture(&st).await,
                    "ouverture" => ak3_jouer_ouverture(&st).await,
                    "maj" => ak3_jouer_mise_a_jour(&st).await,
                    "chrono" => ak3_jouer_chrono(&st).await,
                    "element" => ak3_jouer_element(&st).await,
                    "detachement" => ak3_jouer_detachement(&st).await,
                    "archive" => ak3_jouer_archivage(&st, true).await,
                    "desarchive" => ak3_jouer_archivage(&st, false).await,
                    "archive_chrono" => ak3_jouer_archivage_chrono(true).await,
                    _ => ak3_jouer_archivage_chrono(false).await,
                };
                sortie.insert(phase.into(), json!({ "reponse": [r.reponse.0, r.reponse.1], "geste": r.geste, "moteur": r.moteur, "phrase": r.phrase }));
            }
            eprintln!("{PHASE}fiche");
            let ((statut, corps), id, moteur) = ak3_jouer_fiche(&st).await;
            println!("AK3-FICHE:{}", json!({ "reponse": [statut, corps], "id": id, "moteur": moteur }));
            eprintln!("{PHASE}fin");
            println!("AK3-SORTIE:{}", Value::Object(sortie));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::dossier_refus_sans_texte_du_moteur::ak3_journal_des_refus_de_dossier"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("AK3-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie de l'enfant : {stdout}")).1;
        let s: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : sortie JSON ({e}) : {stdout}"));
        let lignes_de_phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().map(str::to_string).collect()
        };
        let jugees = s.as_object().map(|o| o.len()).unwrap_or(0);
        assert_eq!(jugees, 10, "contrôle : les dix refus sont joués par l'enfant : {s}");
        for (phase, r) in s.as_object().into_iter().flatten() {
            let statut = r["reponse"][0].as_u64().unwrap_or(0) as u16;
            let phrase = r["phrase"].as_str().unwrap_or_else(|| panic!("contrôle : phrase de {phase} : {r}"));
            let cid = ak3_phrase_seule(phase, statut, &r["reponse"][1], phrase);
            let (geste, moteur) = (r["geste"].as_str().unwrap_or(""), r["moteur"].as_str().unwrap_or(""));
            assert!(!moteur.is_empty() && !geste.is_empty(), "contrôle : {phase} : geste et cause lus : {r}");
            let lignes = lignes_de_phase(phase);
            let du_dossier: Vec<&String> = lignes.iter().filter(|l| l.contains("[cases]")).collect();
            assert_eq!(du_dossier, [&format!("[cases] WARN {geste} ({cid}) : {moteur}")], "{phase} : la ligne de journal, ENTIÈRE");
            let http: Vec<&String> = lignes.iter().filter(|l| l.contains(" HTTP 503 : ")).collect();
            assert_eq!(http, [&format!("[{cid}] HTTP 503 : {phrase}")], "{phase} : la ligne HTTP porte la phrase seule");
            assert!(lignes.iter().all(|l| !l.contains(AK3_TITRE) && !l.contains(AK3_ASSIGNE)), "{phase} : ni titre ni assigné au journal : {lignes:?}");
        }
        // LA FICHE NON LUE (cinq cents) : ligne `[cases]` et ligne `HTTP 500` ENTIÈRES.
        let fiche = stdout.split_once("AK3-FICHE:").unwrap_or_else(|| panic!("contrôle : fiche jouée par l'enfant : {stdout}")).1;
        let f: Value = serde_json::from_str(fiche.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : fiche JSON ({e}) : {stdout}"));
        let cid = ak3_fiche_phrase_seule(f["reponse"][0].as_u64().unwrap_or(0) as u16, &f["reponse"][1]);
        let (id, moteur) = (f["id"].as_i64().unwrap_or(0), f["moteur"].as_str().unwrap_or(""));
        assert!(id > 0 && moteur.contains("incident_item"), "contrôle : fiche : numéro et cause lus : {f}");
        let lignes = lignes_de_phase("fiche");
        let du_dossier: Vec<&String> = lignes.iter().filter(|l| l.contains("[cases]")).collect();
        assert_eq!(du_dossier, [&format!("[cases] WARN fiche du dossier #{id} NON lue ({cid}) : {moteur}")], "fiche : la ligne de journal, ENTIÈRE");
        let http: Vec<&String> = lignes.iter().filter(|l| l.contains(" HTTP 500 : ")).collect();
        assert_eq!(http, [&format!("[{cid}] HTTP 500 : {CAUSE_FICHE_DU_DOSSIER_NON_LUE}")], "fiche : la ligne HTTP porte la phrase seule");
    }
}
