// =====================================================================================
// `P10.20-l` (sites de handlers/datamodels.rs, handlers/scheduled_reports.rs et handlers/engagement.rs), `P10.29-l`
// (famille « texte du moteur servi », mêmes fichiers) et `P10.27-j` (`last_error` d'un lot de connecteur non écrit)
// — UNE LECTURE RATÉE N'EST PAS UNE ABSENCE, LE TEXTE DU MOTEUR NE PART PAS AU CLIENT, ET UN LOT NON PRIS N'EST PAS
// UN LOT ANNULÉ.
//
// LE DÉFAUT, MESURÉ SUR 1011ec9f AVANT LE CORRECTIF.
//   · datamodels.rs : `model_delete`, `object_delete`, `field_delete`, `dataset_delete` et `dataset_run` lisaient leur
//     ligne par `Err(_) => not_found(…)`, `object_create` et `field_create` leur rattachement par `.is_err()`, le parent
//     d'un objet par `Err(_) => bad_req("objet parent introuvable")` : une ligne qui ne se lit pas, une table hors
//     d'atteinte, se servaient « introuvable ». `dm_commit` servait `échec transaction audit (aucune modification):
//     <moteur>`, la sonde d'enfants `CAUSE_ENFANTS_DE_L_OBJET_NON_LUS (<moteur>)`.
//   · scheduled_reports.rs : `report_delete` (`Err(_)`) et `report_run_now` (`.is_err()`) rendaient 404 « rapport
//     introuvable » sur une lecture ratée — l'administrateur lisait absent un rapport qui PART TOUJOURS vers son canal ;
//     `report_create` rendait 400 « dataset/notifier introuvable » ; deux 500 servaient le texte du moteur.
//   · engagement.rs : `engagement_get` rendait 404 sur toute lecture ratée de la fiche (colonne illisible comprise,
//     `engagement_row_json`) ; trois 500 (création, clôture, bascule du mode) servaient `échec transaction audit
//     (…): <moteur>`.
//   · connectors/mod.rs : les deux bras `Err(_)` d'`ingest_events_batch_env` (http_pull et defender) écrivaient
//     « échec d'ingestion (batch annulé, rejouable) » aussi pour un lot NON PRIS (`LotNonEcrit::NonPris`).
//
// LE CORRECTIF (décision par défaut de la vague AG). Trois issues : lue, le geste suit ; absente (ou désactivée pour
// `dataset_run`, dans la même lecture), le refus d'avant au corps près (404, ou 400 pour le parent d'un objet et les
// références d'un rapport) ; lecture ratée, 503 nommé (`CAUSE_MODELE_DE_DONNEES_NON_SUPPRIME_NON_LU`,
// `CAUSE_MODELE_DE_DONNEES_NON_CREE_RATTACHEMENT_NON_LU`, `CAUSE_JEU_DE_DONNEES_NON_EXECUTE_NON_LU`,
// `CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE`, `CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU`,
// `CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU`, `CAUSE_ENGAGEMENT_NON_LU`), RIEN n'est écrit, supprimé, exécuté ni
// envoyé ; la cause du moteur au journal seul avec l'identifiant de corrélation servi. Les 500 gardent leur statut et
// servent `PHRASE_ECHEC_TRANSACTION_AUDIT` par `servir_l_echec_de_la_transaction_d_audit`. Un parent d'un autre modèle
// reste un 400, un doublon reste un 400. `P10.27-j` : deux phrases distinctes, `last_run` posé, `last_ok`,
// `last_count` et le watermark inchangés.
//
// LES PANNES ÉPROUVÉES : une colonne lue stockée en BLOB (la ligne existe, sa lecture échoue), la table retirée, un
// autorisateur qui refuse une colonne (sonde d'enfants), un déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger`
// (la trace d'audit refusée) ; pour les connecteurs, une transaction étrangère pendante sur l'écrivain (lot non pris)
// et un déclencheur qui refuse le second événement du lot (lot annulé après un événement). Les lignes de journal sont
// lues sur le stderr d'un sous-processus et comparées EN ENTIER.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : lecteur des modèles `AG4_DM_ABSENT_EN_503`,
// `AG4_DM_CAUSE_EXPOSEE`, `AG4_DM_SANS_JOURNAL` ; par suppression `AG4_<L>_DELETE_LECTURE_EN_404` et
// `AG4_<L>_DELETE_LECTURE_FAIT_LE_GESTE` (L = MODEL, OBJECT, FIELD, DATASET) ; `AG4_OBJECT_CREATE_MODELE_EN_404`,
// `AG4_OBJECT_CREATE_PARENT_EN_400`, `AG4_OBJECT_CREATE_AUTRE_MODELE_ADMIS`, `AG4_OBJECT_CREATE_LECTURE_FAIT_LE_GESTE`,
// `AG4_FIELD_CREATE_OBJET_EN_404`, `AG4_FIELD_CREATE_LECTURE_FAIT_LE_GESTE`, `AG4_DSRUN_LECTURE_EN_404`,
// `AG4_DSRUN_ENABLED_RETIRE`, `AG4_ENFANTS_CAUSE_EXPOSEE`, `AG4_ENFANTS_SANS_JOURNAL`, `AG4_DM_MOTEUR_SERVI`,
// `AG4_DM_UNIQUE_RETIRE`, `AG4_DM_GESTE_IGNORE` ; rapports `AG4_SR_ABSENT_EN_503`, `AG4_SR_CAUSE_EXPOSEE`,
// `AG4_SR_SANS_JOURNAL`, `AG4_SR_CREATE_DATASET_EN_400`, `AG4_SR_CREATE_NOTIFIER_EN_400`,
// `AG4_SR_CREATE_LECTURE_FAIT_LE_GESTE`, `AG4_SR_DELETE_LECTURE_EN_404`, `AG4_SR_DELETE_LECTURE_FAIT_LE_GESTE`,
// `AG4_SR_RUN_LECTURE_EN_404`, `AG4_SR_RUN_LECTURE_FAIT_LE_GESTE`, `AG4_SR_CREATE_MOTEUR_SERVI`,
// `AG4_SR_DELETE_MOTEUR_SERVI`, `AG4_SR_CREATE_UNIQUE_RETIRE` ; engagement `AG4_ENG_GET_LECTURE_EN_404`,
// `AG4_ENG_GET_ABSENT_EN_503`, `AG4_ENG_GET_CAUSE_EXPOSEE`, `AG4_ENG_GET_SANS_JOURNAL`, `AG4_ENG_CREATE_MOTEUR_SERVI`,
// `AG4_ENG_END_MOTEUR_SERVI`, `AG4_ENG_MODE_MOTEUR_SERVI` ; connecteurs `AG4_CONN_NONPRIS_DIT_ANNULE`,
// `AG4_CONN_ANNULE_SANS_COMPTE`, `AG4_CONN_HTTP_MESSAGE_UNIQUE`, `AG4_CONN_DEF_MESSAGE_UNIQUE`,
// `AG4_CONN_HTTP_LAST_OK_AVANCE`, `AG4_CONN_DEF_WATERMARK_AVANCE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les écrans ne sont pas exercés — web/datamodels.js peint le refus d'une
// suppression par son toast (le 503 nommé y est un refus nommé, aucune ouverture « rien n'a changé » ne reconnaissant
// une lecture manquée) ; aucun écran n'appelle `/api/scheduled-reports` ; la fiche d'engagement et la colonne
// `last_error` des connecteurs ne sont pas lues côté console ici. Restent hors de ce lot, et donc non témoignés :
// `object_constraint_chain` (une lecture ratée y rendait 400 « objet introuvable ou désactivé » ; 503 nommé depuis la
// vague AP, témoins `chaine_du_pivot_et_etape_de_recherche_en_trois_issues.rs`), les trois lectures de définition de
// `deliver_report` (400 via `report_run_now`), les écritures `let _ = conn.execute(UPDATE connector …)` voisines. Une lecture ratée par verrou
// et le mode multi-tenant ne sont pas joués.
//
// CORRECTION (après vérification). `mode_get` (engagement.rs) servait encore, dans un corps 200, `mode NON LU : … (<moteur>)` :
// phrase fixe désormais, cause au journal seul (`ag4_mode_non_lu_phrase_fixe_sans_texte_du_moteur`, phase `mode` du
// journal ; mutants `AG4C_MODE_MOTEUR_SERVI`, `AG4C_MODE_AVEU_RETIRE`, `AG4C_MODE_SANS_JOURNAL`). Le témoin des
// connecteurs posait le watermark « W0 », lexicalement plus grand que toute date : un bras d'échec qui avançait le
// watermark jusqu'à celui du passage restait vert. Il pose maintenant une date ISO antérieure, configure le watermark
// de http_pull et contrôle, sur les deux sites, qu'un lot écrit l'avance (mutants `AG4C_CONN_*_WATERMARK_DU_PASSAGE`).
// Reste : quand le lot n'est pas pris parce qu'une AUTRE connexion tient le verrou (`BEGIN IMMEDIATE` refusé), l'`UPDATE`
// best-effort de `last_run`/`last_error` est refusé de même — ni `last_run` ni la phrase ne sont écrits ; seul le cas
// d'une transaction pendante sur l'écrivain est joué ici.
// =====================================================================================
mod modeles_rapports_et_engagements_lecture_ratee_et_lot_non_pris {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AG4_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit (sans « UNIQUE »).
    const AG4_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AG4)";
    const AG4_ABSENT: i64 = 987_654;
    /// Le nom de l'acteur : il ne doit paraître dans aucune ligne de journal de ce lot.
    const AG4_ACTEUR: &str = "ag4_operatrice";
    const AG4_GXQL: &str = "search | table message";
    const AG4_CANAL: &str = "https://198.51.100.40/hook";

    fn ag4_adm() -> AuthUser {
        sp_au(AG4_ACTEUR, "admin")
    }

    fn ag4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ag4_insere(st: &AppState, sql: &str) -> i64 {
        let c = st.db.lock();
        c.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
        c.last_insert_rowid()
    }

    fn ag4_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ag4_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn ag4_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(AG4_MOTEUR_LECTURE) && !corps.contains("Blob") && !corps.contains("no such table")
            && !corps.contains("prohibited") && !corps.contains("hors d atteinte"), "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    fn ag4_registre_refuse(st: &AppState) {
        ag4_sql(st, &format!("CREATE TRIGGER ag4_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AG4_MOTEUR_ECRITURE}'); END;"));
    }

    fn ag4_registre_rendu(st: &AppState) {
        ag4_sql(st, "DROP TRIGGER ag4_ledger_refuse;");
    }

    fn ag4_refuser_la_colonne(st: &AppState, table: &'static str, colonne: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ag4_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    // ---- les quatre lignes que les suppressions de modèles visent, par leur point d'entrée ----

    #[derive(Clone, Copy, Debug)]
    enum Ag4Ligne { Modele, Objet, Champ, JeuDeDonnees }

    const AG4_LIGNES: [Ag4Ligne; 4] = [Ag4Ligne::Modele, Ag4Ligne::Objet, Ag4Ligne::Champ, Ag4Ligne::JeuDeDonnees];

    impl Ag4Ligne {
        /// (table, 404 d'avant, sorte de la trace de suppression, geste nommé au journal sans l'identifiant)
        fn fiche(self) -> (&'static str, &'static str, &'static str, &'static str) {
            match self {
                Ag4Ligne::Modele => ("data_model", "data model introuvable", "config.datamodel.delete", "suppression du modèle de données"),
                Ag4Ligne::Objet => ("data_model_object", "objet introuvable", "config.datamodel.object.delete", "suppression de l'objet de modèle"),
                Ag4Ligne::Champ => ("data_model_field", "champ introuvable", "config.datamodel.field.delete", "suppression du champ de modèle"),
                Ag4Ligne::JeuDeDonnees => ("dataset", "dataset introuvable", "config.dataset.delete", "suppression du jeu de données"),
            }
        }

        fn creer(self, st: &AppState, nom: &str) -> i64 {
            match self {
                Ag4Ligne::Modele => ag4_insere(st, &format!("INSERT INTO data_model(name) VALUES('{nom}')")),
                Ag4Ligne::Objet => {
                    let m = ag4_insere(st, &format!("INSERT INTO data_model(name) VALUES('{nom}_hote')"));
                    ag4_insere(st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m},'{nom}')"))
                }
                Ag4Ligne::Champ => {
                    let m = ag4_insere(st, &format!("INSERT INTO data_model(name) VALUES('{nom}_hote')"));
                    let o = ag4_insere(st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m},'{nom}_hote')"));
                    ag4_insere(st, &format!("INSERT INTO data_model_field(object_id,name) VALUES({o},'{nom}')"))
                }
                Ag4Ligne::JeuDeDonnees => ag4_insere(st, &format!("INSERT INTO dataset(name,soql) VALUES('{nom}','{AG4_GXQL}')")),
            }
        }

        async fn supprimer(self, st: &AppState, id: i64) -> (u16, String, Value) {
            let (s, a, p) = (State(st.clone()), Extension(ag4_adm()), Path(id));
            ag4_reponse(match self {
                Ag4Ligne::Modele => model_delete(s, a, p).await,
                Ag4Ligne::Objet => object_delete(s, a, p).await,
                Ag4Ligne::Champ => field_delete(s, a, p).await,
                Ag4Ligne::JeuDeDonnees => dataset_delete(s, a, p).await,
            }).await
        }
    }

    async fn ag4_creer_un_objet(st: &AppState, model_id: i64, corps: Value) -> (u16, String, Value) {
        ag4_reponse(object_create(State(st.clone()), Extension(ag4_adm()), Path(model_id), Json(corps)).await).await
    }

    async fn ag4_creer_un_champ(st: &AppState, object_id: i64, nom: &str) -> (u16, String, Value) {
        ag4_reponse(field_create(State(st.clone()), Extension(ag4_adm()), Path(object_id), Json(json!({ "name": nom, "type": "string" }))).await).await
    }

    async fn ag4_lancer_le_jeu(st: &AppState, id: i64) -> (u16, String, Value) {
        // l'exécution d'un jeu de données est ouverte au lecteur (viewer+) : jouée sous ce rôle.
        ag4_reponse(dataset_run(State(st.clone()), Extension(sp_au(AG4_ACTEUR, "viewer")), Path(id), Json(json!({}))).await).await
    }

    fn ag4_id(quoi: &str, (statut, corps, v): &(u16, String, Value)) -> i64 {
        assert_eq!(*statut, 200, "fixture : {quoi} : {corps}");
        v["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant de {quoi} : {corps}"))
    }

    /// CE QU'IL TIENT (suppression d'un modèle, d'un objet, d'un champ, d'un jeu de données) : absent, le 404 d'avant
    /// exactement ; nom illisible puis table retirée, `503` nommé `CAUSE_MODELE_DE_DONNEES_NON_SUPPRIME_NON_LU` en entier,
    /// sans la cause du moteur — jamais `404` ; la ligne reste, aucune suppression attestée, transaction fermée.
    /// Contrôle : une ligne lisible se supprime (`200 {"ok": true}`), attestée.
    /// MUTATIONS : `AG4_<L>_DELETE_LECTURE_EN_404`, `AG4_<L>_DELETE_LECTURE_FAIT_LE_GESTE`, `AG4_DM_ABSENT_EN_503`,
    /// `AG4_DM_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ag4_suppressions_des_modeles_de_donnees_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-dm-retraits");
        assert!(AG4_LIGNES.len() >= 4, "plancher : les quatre suppressions");
        for l in AG4_LIGNES {
            let (table, introuvable, sorte, _) = l.fiche();
            let trace = format!("SELECT COUNT(*) FROM ledger WHERE kind='{sorte}'");

            let (statut, corps, v) = l.supprimer(&st, AG4_ABSENT).await;
            assert_eq!((statut, &v), (404, &json!({ "error": introuvable })), "{l:?} : l'absence établie reste le 404 d'avant, rien d'autre : {corps}");

            let id = l.creer(&st, &format!("ag4_illisible_{table}"));
            ag4_sql(&st, &format!("UPDATE {table} SET name=X'00' WHERE id={id}"));
            let r = l.supprimer(&st, id).await;
            ag4_juger_5xx(&format!("{l:?} illisible"), &r, 503, CAUSE_MODELE_DE_DONNEES_NON_SUPPRIME_NON_LU);
            assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={id}")), 1, "{l:?} : la ligne illisible reste");
            assert_eq!(ag4_compte(&st, &trace), 0, "{l:?} : aucune suppression attestée");
            assert!(st.db.lock().is_autocommit(), "{l:?} : la transaction est fermée");

            let lisible = l.creer(&st, &format!("ag4_lisible_{table}"));
            let (statut, corps, v) = l.supprimer(&st, lisible).await;
            assert_eq!((statut, v), (200, json!({ "ok": true })), "{l:?} : contrôle : une ligne lisible se supprime : {corps}");
            assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={lisible}")), 0, "{l:?} : contrôle : elle est partie");
            assert_eq!(ag4_compte(&st, &trace), 1, "{l:?} : contrôle : la suppression est attestée");

            ag4_sql(&st, &format!("ALTER TABLE {table} RENAME TO {table}_ag4_retiree;"));
            let r = l.supprimer(&st, id).await;
            ag4_sql(&st, &format!("ALTER TABLE {table}_ag4_retiree RENAME TO {table};"));
            ag4_juger_5xx(&format!("{l:?} table retirée"), &r, 503, CAUSE_MODELE_DE_DONNEES_NON_SUPPRIME_NON_LU);
            assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={id}")), 1, "{l:?} : la ligne reste");
            assert_eq!(ag4_compte(&st, &trace), 1, "{l:?} : aucune autre suppression attestée");
            assert!(st.db.lock().is_autocommit(), "{l:?} : la transaction est fermée");
        }
    }

    /// CE QU'IL TIENT (créations rattachées) : `object_create` — modèle absent `404 {"error": "data model introuvable"}`,
    /// parent absent `400 {"error": "objet parent introuvable"}`, parent d'un autre modèle `400 {"error": "objet parent
    /// d'un autre modèle"}`, corps entiers ; parent illisible puis modèle hors d'atteinte : `503`
    /// `CAUSE_MODELE_DE_DONNEES_NON_CREE_RATTACHEMENT_NON_LU` en entier, aucun objet créé. `field_create` — objet absent
    /// `404 {"error": "objet introuvable"}`, objet hors d'atteinte `503` (même cause), aucun champ créé. Contrôles : un
    /// objet et un champ se créent (`200 {"id": n}`).
    /// MUTATIONS : `AG4_OBJECT_CREATE_MODELE_EN_404`, `AG4_OBJECT_CREATE_PARENT_EN_400`,
    /// `AG4_OBJECT_CREATE_AUTRE_MODELE_ADMIS`, `AG4_OBJECT_CREATE_LECTURE_FAIT_LE_GESTE`, `AG4_FIELD_CREATE_OBJET_EN_404`,
    /// `AG4_FIELD_CREATE_LECTURE_FAIT_LE_GESTE`.
    #[tokio::test]
    async fn ag4_creations_rattachees_lecture_ratee_jamais_404_ni_400_et_rien_n_est_cree() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-dm-creations");
        let objets = "SELECT COUNT(*) FROM data_model_object";
        let champs = "SELECT COUNT(*) FROM data_model_field";
        let m = ag4_insere(&st, "INSERT INTO data_model(name) VALUES('ag4_modele')");
        let autre = ag4_insere(&st, "INSERT INTO data_model(name) VALUES('ag4_autre_modele')");
        let parent = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m},'ag4_parent')"));
        let etranger = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({autre},'ag4_etranger')"));
        let avant = ag4_compte(&st, objets);

        let (statut, corps, v) = ag4_creer_un_objet(&st, AG4_ABSENT, json!({ "name": "ag4_orphelin" })).await;
        assert_eq!((statut, &v), (404, &json!({ "error": "data model introuvable" })), "modèle absent : le 404 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_creer_un_objet(&st, m, json!({ "name": "ag4_enfant", "parent_id": AG4_ABSENT })).await;
        assert_eq!((statut, &v), (400, &json!({ "error": "objet parent introuvable" })), "parent absent : le 400 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_creer_un_objet(&st, m, json!({ "name": "ag4_enfant", "parent_id": etranger })).await;
        assert_eq!((statut, &v), (400, &json!({ "error": "objet parent d'un autre modèle" })), "parent d'un autre modèle : 400 inchangé : {corps}");
        assert_eq!(ag4_compte(&st, objets), avant, "aucun objet créé par un refus");

        ag4_sql(&st, &format!("UPDATE data_model_object SET model_id=X'00' WHERE id={parent}"));
        let r = ag4_creer_un_objet(&st, m, json!({ "name": "ag4_enfant", "parent_id": parent })).await;
        ag4_sql(&st, &format!("UPDATE data_model_object SET model_id={m} WHERE id={parent}"));
        ag4_juger_5xx("parent illisible", &r, 503, CAUSE_MODELE_DE_DONNEES_NON_CREE_RATTACHEMENT_NON_LU);
        assert_eq!(ag4_compte(&st, objets), avant, "parent illisible : aucun objet créé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        ag4_sql(&st, "ALTER TABLE data_model RENAME TO data_model_ag4_retiree;");
        let r = ag4_creer_un_objet(&st, m, json!({ "name": "ag4_sans_modele" })).await;
        ag4_sql(&st, "ALTER TABLE data_model_ag4_retiree RENAME TO data_model;");
        ag4_juger_5xx("modèle hors d'atteinte", &r, 503, CAUSE_MODELE_DE_DONNEES_NON_CREE_RATTACHEMENT_NON_LU);
        assert_eq!(ag4_compte(&st, objets), avant, "modèle hors d'atteinte : aucun objet créé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let enfant = ag4_id("objet sous un parent lisible", &ag4_creer_un_objet(&st, m, json!({ "name": "ag4_enfant", "parent_id": parent })).await);
        assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM data_model_object WHERE id={enfant} AND parent_id={parent}")), 1, "contrôle : l'objet est créé sous son parent");

        let avant = ag4_compte(&st, champs);
        let (statut, corps, v) = ag4_creer_un_champ(&st, AG4_ABSENT, "ag4_champ").await;
        assert_eq!((statut, &v), (404, &json!({ "error": "objet introuvable" })), "objet absent : le 404 d'avant, rien d'autre : {corps}");
        ag4_sql(&st, "ALTER TABLE data_model_object RENAME TO data_model_object_ag4_retiree;");
        let r = ag4_creer_un_champ(&st, enfant, "ag4_champ").await;
        ag4_sql(&st, "ALTER TABLE data_model_object_ag4_retiree RENAME TO data_model_object;");
        ag4_juger_5xx("objet hors d'atteinte", &r, 503, CAUSE_MODELE_DE_DONNEES_NON_CREE_RATTACHEMENT_NON_LU);
        assert_eq!(ag4_compte(&st, champs), avant, "objet hors d'atteinte : aucun champ créé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        let (statut, corps, v) = ag4_creer_un_champ(&st, enfant, "ag4_champ").await;
        assert_eq!(statut, 200, "contrôle : un champ se crée sous un objet lisible : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["id"], "contrôle : corps entier `{{\"id\": n}}` : {corps}");
        assert_eq!(ag4_compte(&st, champs), avant + 1, "contrôle : le champ est créé");
    }

    /// CE QU'IL TIENT (exécution d'un jeu de données) : absent ET désactivé, `404 {"error": "dataset introuvable ou
    /// désactivé"}` exactement (même lecture : `enabled` dans le `WHERE` qui rend la requête) ; requête illisible puis
    /// table retirée, `503` nommé `CAUSE_JEU_DE_DONNEES_NON_EXECUTE_NON_LU` en entier, rien n'est exécuté (aucune
    /// colonne servie). Contrôle : un jeu actif s'exécute et sert la requête stockée.
    /// MUTATIONS : `AG4_DSRUN_LECTURE_EN_404`, `AG4_DSRUN_ENABLED_RETIRE`.
    #[tokio::test]
    async fn ag4_execution_d_un_jeu_de_donnees_trois_issues_et_activation_lue_dans_la_meme_lecture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'exécution lit l'environnement (budget, tier froid)
        let (st, _p) = sp_state("ag4-dm-execution");
        let absent = json!({ "error": "dataset introuvable ou désactivé" });
        let actif = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_ds_actif','{AG4_GXQL}')"));
        let eteint = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql,enabled) VALUES('ag4_ds_eteint','{AG4_GXQL}',0)"));
        let illisible = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_ds_illisible','{AG4_GXQL}')"));

        let (statut, corps, v) = ag4_lancer_le_jeu(&st, AG4_ABSENT).await;
        assert_eq!((statut, &v), (404, &absent), "absent : le 404 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_lancer_le_jeu(&st, eteint).await;
        assert_eq!((statut, &v), (404, &absent), "désactivé : le 404 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_lancer_le_jeu(&st, actif).await;
        assert_eq!(statut, 200, "contrôle : un jeu actif s'exécute : {corps}");
        assert_eq!(v["soql"], json!(AG4_GXQL), "contrôle : la requête stockée est celle exécutée : {corps}");

        ag4_sql(&st, &format!("UPDATE dataset SET soql=X'00' WHERE id={illisible}"));
        let r = ag4_lancer_le_jeu(&st, illisible).await;
        ag4_juger_5xx("requête illisible", &r, 503, CAUSE_JEU_DE_DONNEES_NON_EXECUTE_NON_LU);

        ag4_sql(&st, "ALTER TABLE dataset RENAME TO dataset_ag4_retiree;");
        let r = ag4_lancer_le_jeu(&st, actif).await;
        ag4_sql(&st, "ALTER TABLE dataset_ag4_retiree RENAME TO dataset;");
        ag4_juger_5xx("table des jeux retirée", &r, 503, CAUSE_JEU_DE_DONNEES_NON_EXECUTE_NON_LU);
    }

    /// CE QU'IL TIENT (sonde d'enfants d'un objet, `P10.29-l`) : sous un autorisateur qui refuse `parent_id`, `503`
    /// EXACTEMENT `{error: CAUSE_ENFANTS_DE_L_OBJET_NON_LUS, id}` — le texte du moteur (« access to … is prohibited ») ne part plus
    /// en parenthèse ; le parent reste.
    /// MUTATIONS : `AG4_ENFANTS_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ag4_sonde_d_enfants_non_lue_sans_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-dm-sonde");
        let m = ag4_insere(&st, "INSERT INTO data_model(name) VALUES('ag4_modele_sonde')");
        let parent = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m},'ag4_parent_sonde')"));
        ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name,parent_id) VALUES({m},'ag4_enfant_sonde',{parent})"));
        ag4_refuser_la_colonne(&st, "data_model_object", "parent_id");
        let r = ag4_reponse(object_delete(State(st.clone()), Extension(ag4_adm()), Path(parent)).await).await;
        ag4_lever(&st);
        ag4_juger_5xx("sonde d'enfants non lue", &r, 503, CAUSE_ENFANTS_DE_L_OBJET_NON_LUS);
        assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM data_model_object WHERE id={parent}")), 1, "le parent reste");
    }

    /// CE QU'IL TIENT (les huit 500 de `dm_commit`) : sous une trace d'audit refusée, `500` EXACTEMENT
    /// `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}`, sans la phrase du moteur, pour les quatre créations et les quatre
    /// suppressions ; rien n'est créé ni supprimé, transaction fermée. Puis la branche `UNIQUE`, INCHANGÉE : un doublon
    /// est un `400 {"error": "un objet porte déjà ce nom"}`, corps entier.
    /// MUTATIONS : `AG4_DM_MOTEUR_SERVI`, `AG4_DM_UNIQUE_RETIRE`.
    #[tokio::test]
    async fn ag4_ecritures_refusees_des_modeles_phrase_fixe_et_doublon_reste_un_400() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-dm-ecritures");
        let adm = || Extension(ag4_adm());
        let m = ag4_id("modèle", &ag4_reponse(model_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_garde" }))).await).await);
        let o = ag4_id("objet", &ag4_creer_un_objet(&st, m, json!({ "name": "ag4_garde_objet" })).await);
        let f = ag4_id("champ", &ag4_creer_un_champ(&st, o, "ag4_garde_champ").await);
        let d = ag4_id("jeu", &ag4_reponse(dataset_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_garde_jeu", "kind": "search", "soql": AG4_GXQL }))).await).await);
        let comptes = "SELECT (SELECT COUNT(*) FROM data_model) * 1000000 + (SELECT COUNT(*) FROM data_model_object) * 10000 \
                       + (SELECT COUNT(*) FROM data_model_field) * 100 + (SELECT COUNT(*) FROM dataset)";
        let avant = ag4_compte(&st, comptes);
        ag4_registre_refuse(&st);
        let mut refus = Vec::new();
        refus.push(("création d'un modèle", ag4_reponse(model_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_refuse" }))).await).await));
        refus.push(("création d'un objet", ag4_creer_un_objet(&st, m, json!({ "name": "ag4_refuse_objet" })).await));
        refus.push(("création d'un champ", ag4_creer_un_champ(&st, o, "ag4_refuse_champ").await));
        refus.push(("création d'un jeu", ag4_reponse(dataset_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_refuse_jeu", "kind": "search", "soql": AG4_GXQL }))).await).await));
        refus.push(("suppression du champ", ag4_reponse(field_delete(State(st.clone()), adm(), Path(f)).await).await));
        refus.push(("suppression de l'objet", ag4_reponse(object_delete(State(st.clone()), adm(), Path(o)).await).await));
        refus.push(("suppression du modèle", ag4_reponse(model_delete(State(st.clone()), adm(), Path(m)).await).await));
        refus.push(("suppression du jeu", ag4_reponse(dataset_delete(State(st.clone()), adm(), Path(d)).await).await));
        ag4_registre_rendu(&st);
        assert!(refus.len() >= 8, "plancher : les huit gestes de `dm_commit`");
        for (quoi, r) in &refus {
            ag4_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        }
        assert_eq!(ag4_compte(&st, comptes), avant, "rien n'est créé ni supprimé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ag4_reponse(model_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_garde" }))).await).await;
        assert_eq!((statut, v), (400, json!({ "error": "un objet porte déjà ce nom" })), "doublon, corps entier : {corps}");
    }

    // ---- rapports planifiés ----

    fn ag4_canal(st: &AppState) -> i64 {
        ag4_insere(st, &format!("INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('ag4-canal','temoin-ag4',1,'{AG4_CANAL}',0,'{{}}')"))
    }

    async fn ag4_creer_un_rapport(st: &AppState, nom: &str, dataset_id: i64, notifier_id: i64) -> (u16, String, Value) {
        let corps = json!({ "name": nom, "dataset_id": dataset_id, "notifier_id": notifier_id });
        ag4_reponse(report_create(State(st.clone()), Extension(ag4_adm()), Json(corps)).await).await
    }

    async fn ag4_supprimer_le_rapport(st: &AppState, id: i64) -> (u16, String, Value) {
        ag4_reponse(report_delete(State(st.clone()), Extension(ag4_adm()), Path(id)).await).await
    }

    async fn ag4_declencher_le_rapport(st: &AppState, id: i64) -> (u16, String, Value) {
        ag4_reponse(report_run_now(State(st.clone()), Extension(ag4_adm()), Path(id)).await).await
    }

    /// CE QU'IL TIENT (rapports planifiés) : création — jeu ou canal absent, `400 {"error": "dataset introuvable"}` /
    /// `{"error": "notifier introuvable"}` exactement ; table des jeux puis des canaux hors d'atteinte, `503`
    /// `CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE` en entier, aucun rapport écrit (pas d'orphelin). Suppression —
    /// absent `404 {"error": "rapport introuvable"}` ; nom illisible puis table retirée, `503`
    /// `CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU`, le rapport reste, rien d'attesté. Déclenchement — absent, le 404
    /// d'avant ; table retirée, `503` `CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU`, marque d'échéance inchangée (rien
    /// n'est exécuté). Contrôles : création, déclenchement et suppression d'un rapport lisible ; doublon `400`.
    /// MUTATIONS : `AG4_SR_CREATE_DATASET_EN_400`, `AG4_SR_CREATE_NOTIFIER_EN_400`, `AG4_SR_CREATE_LECTURE_FAIT_LE_GESTE`,
    /// `AG4_SR_DELETE_LECTURE_EN_404`, `AG4_SR_DELETE_LECTURE_FAIT_LE_GESTE`, `AG4_SR_RUN_LECTURE_EN_404`,
    /// `AG4_SR_RUN_LECTURE_FAIT_LE_GESTE`, `AG4_SR_ABSENT_EN_503`, `AG4_SR_CAUSE_EXPOSEE`, `AG4_SR_CREATE_UNIQUE_RETIRE`.
    #[tokio::test]
    async fn ag4_rapports_planifies_lecture_ratee_jamais_404_ni_400_et_rien_n_est_ecrit_ni_envoye() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-rapports");
        let ds = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_rapport_jeu','{AG4_GXQL}')"));
        let nf = ag4_canal(&st);
        let rapports = "SELECT COUNT(*) FROM scheduled_report";
        let trace = "SELECT COUNT(*) FROM ledger WHERE kind='config.scheduled_report.delete'";

        let (statut, corps, v) = ag4_creer_un_rapport(&st, "ag4_rapport", AG4_ABSENT, nf).await;
        assert_eq!((statut, &v), (400, &json!({ "error": "dataset introuvable" })), "jeu absent : le 400 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_creer_un_rapport(&st, "ag4_rapport", ds, AG4_ABSENT).await;
        assert_eq!((statut, &v), (400, &json!({ "error": "notifier introuvable" })), "canal absent : le 400 d'avant, rien d'autre : {corps}");
        assert_eq!(ag4_compte(&st, rapports), 0, "aucun rapport écrit par un refus");

        for table in ["dataset", "notifier"] {
            ag4_sql(&st, &format!("ALTER TABLE {table} RENAME TO {table}_ag4_retiree;"));
            let r = ag4_creer_un_rapport(&st, "ag4_rapport", ds, nf).await;
            ag4_sql(&st, &format!("ALTER TABLE {table}_ag4_retiree RENAME TO {table};"));
            ag4_juger_5xx(&format!("{table} hors d'atteinte"), &r, 503, CAUSE_RAPPORT_PLANIFIE_NON_CREE_REFERENCE_NON_LUE);
            assert_eq!(ag4_compte(&st, rapports), 0, "{table} hors d'atteinte : aucun rapport orphelin");
            assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        }

        let (statut, corps, v) = ag4_creer_un_rapport(&st, "ag4_rapport", ds, nf).await;
        assert_eq!(statut, 200, "contrôle : un rapport se crée : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["id"], "contrôle : corps entier : {corps}");
        let id = v["id"].as_i64().expect("identifiant du rapport");
        let (statut, corps, v) = ag4_creer_un_rapport(&st, "ag4_rapport", ds, nf).await;
        assert_eq!((statut, v), (400, json!({ "error": "un rapport porte déjà ce nom" })), "doublon, corps entier : {corps}");

        let (statut, corps, v) = ag4_supprimer_le_rapport(&st, AG4_ABSENT).await;
        assert_eq!((statut, &v), (404, &json!({ "error": "rapport introuvable" })), "suppression d'un absent : le 404 d'avant : {corps}");
        ag4_sql(&st, &format!("UPDATE scheduled_report SET name=X'00' WHERE id={id}"));
        let r = ag4_supprimer_le_rapport(&st, id).await;
        ag4_sql(&st, &format!("UPDATE scheduled_report SET name='ag4_rapport' WHERE id={id}"));
        ag4_juger_5xx("rapport illisible", &r, 503, CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU);
        assert_eq!(ag4_compte(&st, rapports), 1, "le rapport illisible reste (et part toujours)");
        assert_eq!(ag4_compte(&st, trace), 0, "aucune suppression attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ag4_declencher_le_rapport(&st, AG4_ABSENT).await;
        assert_eq!((statut, &v), (404, &json!({ "error": "rapport introuvable" })), "déclenchement d'un absent : le 404 d'avant : {corps}");
        ag4_sql(&st, "ALTER TABLE scheduled_report RENAME TO scheduled_report_ag4_retiree;");
        let r = ag4_declencher_le_rapport(&st, id).await;
        let r_retrait = ag4_supprimer_le_rapport(&st, id).await;
        ag4_sql(&st, "ALTER TABLE scheduled_report_ag4_retiree RENAME TO scheduled_report;");
        ag4_juger_5xx("déclenchement, table retirée", &r, 503, CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU);
        ag4_juger_5xx("suppression, table retirée", &r_retrait, 503, CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_NON_LU);
        assert_eq!(ag4_compte(&st, &format!("SELECT last_run FROM scheduled_report WHERE id={id}")), 0, "rien n'est exécuté : marque inchangée");
        assert_eq!(ag4_compte(&st, rapports), 1, "le rapport reste");

        let (statut, corps, v) = ag4_declencher_le_rapport(&st, id).await;
        assert_eq!((statut, &v["ok"]), (200, &json!(true)), "contrôle : un rapport lisible se déclenche : {corps}");
        assert!(ag4_compte(&st, &format!("SELECT last_run FROM scheduled_report WHERE id={id}")) > 0, "contrôle : marque posée");
        let (statut, corps, v) = ag4_supprimer_le_rapport(&st, id).await;
        assert_eq!((statut, v), (200, json!({ "ok": true })), "contrôle : un rapport lisible se supprime : {corps}");
        assert_eq!((ag4_compte(&st, rapports), ag4_compte(&st, trace)), (0, 1), "contrôle : parti, et attesté");
    }

    /// CE QU'IL TIENT (les deux 500 des rapports) : sous une trace d'audit refusée, création et suppression rendent `500`
    /// EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}`, sans la phrase du moteur ; rien n'est créé ni supprimé.
    /// MUTATIONS : `AG4_SR_CREATE_MOTEUR_SERVI`, `AG4_SR_DELETE_MOTEUR_SERVI`.
    #[tokio::test]
    async fn ag4_ecritures_refusees_des_rapports_phrase_fixe() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        let (st, _p) = sp_state("ag4-rapports-ecritures");
        let ds = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_rapport_jeu','{AG4_GXQL}')"));
        let nf = ag4_canal(&st);
        let id = ag4_id("rapport", &ag4_creer_un_rapport(&st, "ag4_rapport_garde", ds, nf).await);
        ag4_registre_refuse(&st);
        let creation = ag4_creer_un_rapport(&st, "ag4_rapport_refuse", ds, nf).await;
        let retrait = ag4_supprimer_le_rapport(&st, id).await;
        ag4_registre_rendu(&st);
        ag4_juger_5xx("création refusée", &creation, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        ag4_juger_5xx("suppression refusée", &retrait, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        assert_eq!(ag4_compte(&st, "SELECT COUNT(*) FROM scheduled_report"), 1, "rien n'est créé ni supprimé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
    }

    // ---- engagements ----

    const AG4_SCOPE: &str = "198.51.100.0/24";

    fn ag4_engagement(st: &AppState, id: &str) {
        ag4_sql(st, &format!(
            "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status) \
             VALUES('{id}','ag4 fiche','blackbox','[\"{AG4_SCOPE}\"]',{},{},'active')",
            now() - 60,
            now() + 3600
        ));
    }

    async fn ag4_lire_l_engagement(st: &AppState, id: &str) -> (u16, String, Value) {
        ag4_reponse(engagement_get(State(st.clone()), Extension(ag4_adm()), Path(id.to_string())).await).await
    }

    /// CE QU'IL TIENT (fiche d'un engagement) : absent, `404 {"error": "engagement introuvable"}` exactement ; nom
    /// illisible (`engagement_row_json`) puis table retirée, `503` nommé `CAUSE_ENGAGEMENT_NON_LU` en entier, sans la
    /// cause du moteur — jamais `404`. Contrôle : une fiche lisible est servie avec ses permis.
    /// MUTATIONS : `AG4_ENG_GET_LECTURE_EN_404`, `AG4_ENG_GET_ABSENT_EN_503`, `AG4_ENG_GET_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ag4_fiche_d_engagement_lecture_ratee_jamais_404() {
        let (st, _p) = sp_state("ag4-engagement-fiche");
        ag4_engagement(&st, "eng-ag4-lu");
        ag4_engagement(&st, "eng-ag4-illisible");
        ag4_sql(&st, "UPDATE engagement SET name=X'00' WHERE id='eng-ag4-illisible'");

        let (statut, corps, v) = ag4_lire_l_engagement(&st, "eng-ag4-absent").await;
        assert_eq!((statut, &v), (404, &json!({ "error": "engagement introuvable" })), "absent : le 404 d'avant, rien d'autre : {corps}");
        let (statut, corps, v) = ag4_lire_l_engagement(&st, "eng-ag4-lu").await;
        assert_eq!(statut, 200, "contrôle : une fiche lisible est servie : {corps}");
        assert_eq!((&v["id"], &v["name"], &v["scope"], &v["grants"]), (&json!("eng-ag4-lu"), &json!("ag4 fiche"), &json!([AG4_SCOPE]), &json!([])),
            "contrôle : la fiche et ses permis : {corps}");

        let r = ag4_lire_l_engagement(&st, "eng-ag4-illisible").await;
        ag4_juger_5xx("fiche illisible", &r, 503, CAUSE_ENGAGEMENT_NON_LU);
        ag4_sql(&st, "ALTER TABLE engagement RENAME TO engagement_ag4_retiree;");
        let r = ag4_lire_l_engagement(&st, "eng-ag4-lu").await;
        ag4_sql(&st, "ALTER TABLE engagement_ag4_retiree RENAME TO engagement;");
        ag4_juger_5xx("table des engagements retirée", &r, 503, CAUSE_ENGAGEMENT_NON_LU);
    }

    /// CE QU'IL TIENT (les trois 500 d'engagement.rs) : sous une trace d'audit refusée, création, clôture et bascule du
    /// mode rendent `500` EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}`, sans la phrase du moteur ; aucun
    /// engagement créé, l'engagement ouvert reste `active`, le mode n'est pas armé.
    /// MUTATIONS : `AG4_ENG_CREATE_MOTEUR_SERVI`, `AG4_ENG_END_MOTEUR_SERVI`, `AG4_ENG_MODE_MOTEUR_SERVI`.
    #[tokio::test]
    async fn ag4_ecritures_refusees_d_engagement_phrase_fixe() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (configuration)
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("ag4-engagement-ecritures");
        let corps = json!({ "box": "blackbox", "scope": [AG4_SCOPE], "reason": "ag4", "window_end": now() + 3600 });
        let (statut, cree, v) = ag4_reponse(engagement_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(ag4_adm()), Json(corps.clone())).await).await;
        assert_eq!(statut, 200, "fixture : engagement créé : {cree}");
        let eid = v["id"].as_str().expect("identifiant").to_string();
        let engagements = "SELECT COUNT(*) FROM engagement";
        let arme = "SELECT COUNT(*) FROM meta WHERE key='plume_mode' AND value='active'";
        assert_eq!((ag4_compte(&st, engagements), ag4_compte(&st, arme)), (1, 0), "fixture : un engagement, mode non armé");

        ag4_registre_refuse(&st);
        let creation = ag4_reponse(engagement_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(ag4_adm()), Json(corps)).await).await;
        let cloture = ag4_reponse(engagement_end(State(st.clone()), Extension(ag4_adm()), Path(eid.clone())).await).await;
        let bascule = ag4_reponse(mode_set(State(st.clone()), Extension(ag4_adm()), Json(json!({ "mode": "active" }))).await).await;
        ag4_registre_rendu(&st);
        eng_test_reset();
        ag4_juger_5xx("création refusée", &creation, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        ag4_juger_5xx("clôture refusée", &cloture, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        ag4_juger_5xx("bascule refusée", &bascule, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        assert_eq!(ag4_compte(&st, engagements), 1, "aucun engagement créé");
        assert_eq!(ag4_compte(&st, &format!("SELECT COUNT(*) FROM engagement WHERE id='{eid}' AND status='active'")), 1, "l'engagement reste ouvert");
        assert_eq!(ag4_compte(&st, arme), 0, "le mode n'est pas armé");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
    }

    /// La phrase servie par `mode_get` sur une lecture ratée du mode (phrase fixe, sans cause du moteur).
    const AG4_MODE_NON_LU: &str = "mode NON LU : la lecture de plume_mode a échoué — « observe » est un repli, pas la valeur enregistrée";

    /// CE QU'IL TIENT (`P10.29-l`, `mode_get` d'engagement.rs) : sur une lecture ratée du mode (table `meta` retirée), le
    /// corps 200 est EXACTEMENT `{mode: "observe", error: AG4_MODE_NON_LU}` — le repli et son aveu restent, la cause du
    /// moteur (« no such table ») n'y paraît pas. Contrôle : un mode posé se lit sans aveu.
    /// MUTATIONS : `AG4C_MODE_MOTEUR_SERVI`, `AG4C_MODE_AVEU_RETIRE`.
    #[tokio::test]
    async fn ag4_mode_non_lu_phrase_fixe_sans_texte_du_moteur() {
        let (st, _p) = sp_state("ag4-mode-non-lu");
        ag4_sql(&st, "INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')");
        let lu = mode_get(State(st.clone()), Extension(ag4_adm())).await.0;
        assert_eq!(lu, json!({ "mode": "active" }), "contrôle : un mode posé se lit sans aveu");
        ag4_sql(&st, "ALTER TABLE meta RENAME TO meta_ag4_retiree;");
        let cause = st.db.lock().query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get::<_, String>(0))
            .expect_err("fixture : la lecture rate").to_string();
        let non_lu = mode_get(State(st.clone()), Extension(ag4_adm())).await.0;
        ag4_sql(&st, "ALTER TABLE meta_ag4_retiree RENAME TO meta;");
        assert!(cause.contains("no such table"), "contrôle : la cause du moteur est celle d'une table absente : {cause}");
        assert_eq!(non_lu, json!({ "mode": "observe", "error": AG4_MODE_NON_LU }), "repli, aveu en phrase fixe, sans « {cause} »");
    }

    // ---- `P10.27-j` : connecteurs ----

    fn ag4_cfg_http() -> String {
        json!({
            "url": "https://203.0.113.10/api/alertes", "records_path": "items", "field_map": { "id": "id", "message": "msg" },
            "watermark": { "field_path": "ts", "param": "since", "format": "iso8601" },
        }).to_string()
    }

    fn ag4_fetch_http() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let corps = json!({ "items": [
                { "id": "ag4-a1", "msg": "un", "ts": "2026-07-01T10:00:00Z" },
                { "id": "ag4-a2", "msg": "deux", "ts": AG4_WM_DU_PASSAGE_HTTP },
            ] });
            Ok(HttpResp { status: 200, headers: vec![], body: corps.to_string().into_bytes() })
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Ag4Issue { NonPris, Annule, Ecrit }

    /// Le watermark déjà enregistré : une date ISO ANTÉRIEURE à tout ce que le passage lit, pour qu'un watermark avancé
    /// par erreur sur un lot non écrit se VOIE (une valeur non ISO comme « W0 » est lexicalement plus grande que toute
    /// date : l'avance monotone la garderait, et la régression passerait inaperçue).
    const AG4_WM_ENREGISTRE: &str = "2020-01-01T00:00:00Z";
    /// Le plus grand watermark lu par un passage http_pull (champ `ts` des enregistrements).
    const AG4_WM_DU_PASSAGE_HTTP: &str = "2026-07-01T11:00:00Z";
    /// Le plus grand watermark lu par un passage defender (`lastUpdateDateTime` de `mock_ok_fetch`).
    const AG4_WM_DU_PASSAGE_DEFENDER: &str = "2026-06-30T13:30:00Z";

    /// Joue un passage du connecteur `ctype` sous l'issue demandée et rend (last_run, last_ok, last_count, watermark,
    /// last_error, événements du connecteur), lus sur l'écrivain.
    fn ag4_passage(ctype: &str, issue: Ag4Issue, now_ts: i64) -> (i64, i64, i64, Option<String>, Option<String>, i64) {
        let db = connector_test_db();
        let (cfg, secret, source) = if ctype == "http_pull" { (ag4_cfg_http(), "", "http:1") } else { (defender_cfg_json(), "supersecret", "defender") };
        {
            let c = db.lock();
            c.execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id,last_run,last_ok,last_count,watermark) \
                 VALUES(1,?1,'ag4',1,?2,?3,300,'prod',5,111,7,?4)",
                params![ctype, cfg, secret, AG4_WM_ENREGISTRE],
            ).expect("fixture : connecteur");
            match issue {
                // le `BEGIN` du lot refusé par un autorisateur, écrivain LIBRE (`NonPris`). `P10.34-f` : la forme d'avant
                // (une transaction étrangère pendante, `BEGIN` à la main) affirmait que l'état du passage s'écrivait DANS
                // cette transaction, ce que `P10.34-f` corrige (rien n'y est plus essayé, tenu par
                // `ecritures_d_etat_des_migrations_et_des_connecteurs_consommees.rs`, phases `etrangere-*`).
                Ag4Issue::NonPris => c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                // le second événement du lot refusé : `Annule(1)`.
                Ag4Issue::Annule => c.execute_batch(
                    "CREATE TRIGGER ag4_lot_refuse BEFORE INSERT ON event WHEN (SELECT COUNT(*) FROM event WHERE source=NEW.source) >= 1 \
                     BEGIN SELECT RAISE(ABORT, 'lot refuse par le temoin AG4'); END;",
                ).expect("fixture : déclencheur"),
                Ag4Issue::Ecrit => {}
            }
        }
        if ctype == "http_pull" {
            poll_one_connector(&db, ":memory:", 1, ctype, &cfg, secret, "prod", Some(AG4_WM_ENREGISTRE), now_ts, ag4_fetch_http());
        } else {
            poll_one_connector(&db, ":memory:", 1, ctype, &cfg, secret, "prod", Some(AG4_WM_ENREGISTRE), now_ts, mock_ok_fetch());
        }
        let c = db.lock();
        let etat = c.query_row(
            "SELECT last_run,last_ok,last_count,watermark,last_error FROM connector WHERE id=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).expect("état du connecteur lisible");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0)).expect("compte d'événements");
        assert!(c.is_autocommit(), "{ctype} {issue:?} : contrôle, aucune transaction pendante sur l'écrivain");
        (etat.0, etat.1, etat.2, etat.3, etat.4, n)
    }

    /// CE QU'IL TIENT (`P10.27-j`, deux sites : http_pull et defender) : un lot NON PRIS écrit `last_error` =
    /// `ECHEC_D_INGESTION_LOT_NON_PRIS` exactement, un lot annulé après un événement « échec d'ingestion (lot annulé après
    /// 1 événement(s), rien d'écrit, rejouable) » exactement ; dans les deux cas `last_run` posé, `last_ok`, `last_count`
    /// et le watermark inchangés, aucun événement écrit. Le watermark enregistré est une date ISO antérieure à celles du
    /// passage, et http_pull a un watermark configuré : un bras d'échec qui reprendrait le watermark du passage se voit.
    /// Contrôle, sur les deux sites : un lot écrit avance le watermark jusqu'à celui du passage et efface l'erreur.
    /// MUTATIONS : `AG4_CONN_NONPRIS_DIT_ANNULE`, `AG4_CONN_ANNULE_SANS_COMPTE`, `AG4_CONN_HTTP_MESSAGE_UNIQUE`,
    /// `AG4_CONN_DEF_MESSAGE_UNIQUE`, `AG4_CONN_HTTP_LAST_OK_AVANCE`, `AG4_CONN_DEF_WATERMARK_AVANCE`,
    /// `AG4C_CONN_HTTP_WATERMARK_DU_PASSAGE`, `AG4C_CONN_DEF_WATERMARK_DU_PASSAGE` (le bras d'échec écrit
    /// `watermark=COALESCE(o.watermark, watermark)`, la régression réaliste).
    #[test]
    fn ag4_lot_de_connecteur_non_pris_ou_annule_dit_lequel_et_n_avance_rien() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le poll lit l'environnement (pages, configuration)
        let now_ts = now();
        let annule = "échec d'ingestion (lot annulé après 1 événement(s), rien d'écrit, rejouable)";
        let cas = [
            ("http_pull", Ag4Issue::NonPris, ECHEC_D_INGESTION_LOT_NON_PRIS),
            ("http_pull", Ag4Issue::Annule, annule),
            ("defender", Ag4Issue::NonPris, ECHEC_D_INGESTION_LOT_NON_PRIS),
            ("defender", Ag4Issue::Annule, annule),
        ];
        assert!(cas.len() >= 4, "plancher : deux issues sur deux sites");
        assert_ne!(ECHEC_D_INGESTION_LOT_NON_PRIS, annule, "contrôle : deux phrases distinctes");
        for (ctype, issue, attendue) in cas {
            let etat = ag4_passage(ctype, issue, now_ts);
            assert_eq!(etat, (now_ts, 111, 7, Some(AG4_WM_ENREGISTRE.to_string()), Some(attendue.to_string()), 0),
                "{ctype} {issue:?} : last_run posé, last_ok/last_count/watermark inchangés, phrase exacte, rien d'écrit");
        }
        for (ctype, wm_du_passage) in [("http_pull", AG4_WM_DU_PASSAGE_HTTP), ("defender", AG4_WM_DU_PASSAGE_DEFENDER)] {
            assert!(AG4_WM_ENREGISTRE < wm_du_passage, "contrôle : le watermark enregistré précède celui du passage");
            let etat = ag4_passage(ctype, Ag4Issue::Ecrit, now_ts);
            assert_eq!(etat, (now_ts, now_ts, 2, Some(wm_du_passage.to_string()), None, 2),
                "contrôle {ctype} : un lot écrit avance last_ok, last_count et le watermark, et efface l'erreur");
        }
    }

    /// CE QU'IL TIENT (journal) : chaque lecture ratée écrit UNE ligne, comparée EN ENTIER (module, geste, identifiant de
    /// corrélation servi, cause du moteur rejouée sur la même base) ; chaque 500 écrit `[<id servi>] <module> WARN <geste>
    /// refusé : transaction d'audit annulée, aucune modification (<cause du moteur>)`, ligne entière ; aucune ligne ne
    /// porte le nom d'un objet, d'un rapport, d'un engagement, l'acteur ni l'adresse du canal ; le nominal et les
    /// absences n'écrivent rien.
    /// MUTATIONS : `AG4_DM_SANS_JOURNAL`, `AG4_ENFANTS_SANS_JOURNAL`, `AG4_SR_SANS_JOURNAL`, `AG4_ENG_GET_SANS_JOURNAL`,
    /// `AG4_DM_GESTE_IGNORE`.
    #[tokio::test]
    async fn ag4_lignes_de_journal_des_refus() {
        const ENFANT: &str = "PLUME_TEMOIN_AG4_ENFANT";
        const PHASE: &str = "AG4-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            set_engagement_mode(true);
            let (st, _p) = sp_state("ag4-journal");
            let adm = || Extension(ag4_adm());
            // La cause du moteur, rejouée sur la même base par la même lecture : la ligne attendue se compare en entier.
            let cause_texte = |sql: String| -> String {
                st.db.lock().query_row(&sql, [], |r| r.get::<_, String>(0)).expect_err("fixture : la lecture rate").to_string()
            };
            let cause_existence = |sql: String| -> String {
                st.db.lock().query_row(&sql, [], |_| Ok(())).expect_err("fixture : la lecture rate").to_string()
            };
            let cid = |r: &(u16, String, Value)| r.2["id"].as_str().unwrap_or("").to_string();
            let dm = |geste: String, cid: String, e: String| format!("[datamodels] WARN {geste} refusé : la ligne visée n'a pas pu être lue, rien n'est écrit ({cid}) : {e}");
            let sr = |geste: String, cid: String, e: String| format!("[rapports] WARN {geste} refusé : la ligne visée n'a pas pu être lue, rien n'est écrit ni envoyé ({cid}) : {e}");

            // préparation des lignes illisibles
            let mut illisibles = Vec::new();
            for l in AG4_LIGNES {
                let (table, _, _, _) = l.fiche();
                let id = l.creer(&st, &format!("ag4_journal_illisible_{table}"));
                ag4_sql(&st, &format!("UPDATE {table} SET name=X'00' WHERE id={id}"));
                illisibles.push((l, id));
            }
            let m_ok = ag4_insere(&st, "INSERT INTO data_model(name) VALUES('ag4_journal_modele')");
            let parent_illisible = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m_ok},'ag4_journal_parent')"));
            ag4_sql(&st, &format!("UPDATE data_model_object SET model_id=X'00' WHERE id={parent_illisible}"));
            let o_ok = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m_ok},'ag4_journal_objet')"));
            let parent_sonde = ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name) VALUES({m_ok},'ag4_journal_parent_sonde')"));
            ag4_insere(&st, &format!("INSERT INTO data_model_object(model_id,name,parent_id) VALUES({m_ok},'ag4_journal_enfant_sonde',{parent_sonde})"));
            let ds_illisible = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_journal_jeu_illisible','{AG4_GXQL}')"));
            ag4_sql(&st, &format!("UPDATE dataset SET soql=X'00' WHERE id={ds_illisible}"));
            let ds = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_journal_jeu','{AG4_GXQL}')"));
            let nf = ag4_canal(&st);
            let r_illisible = ag4_id("rapport", &ag4_creer_un_rapport(&st, "ag4_journal_rapport_illisible", ds, nf).await);
            ag4_sql(&st, &format!("UPDATE scheduled_report SET name=X'00' WHERE id={r_illisible}"));
            let r_ok = ag4_id("rapport", &ag4_creer_un_rapport(&st, "ag4_journal_rapport", ds, nf).await);
            ag4_engagement(&st, "eng-ag4-journal-illisible");
            ag4_sql(&st, "UPDATE engagement SET name=X'00' WHERE id='eng-ag4-journal-illisible'");

            eprintln!("{PHASE}lectures");
            let mut attendues = Vec::new();
            let mut statuts = Vec::new();
            for (l, id) in &illisibles {
                let (table, _, _, geste) = l.fiche();
                let e = cause_texte(format!("SELECT name FROM {table} WHERE id={id}"));
                let r = l.supprimer(&st, *id).await;
                attendues.push(dm(format!("{geste} #{id}"), cid(&r), e));
                statuts.push(r.0);
            }
            // parent illisible d'un objet à créer
            let e = st.db.lock().query_row(&format!("SELECT model_id FROM data_model_object WHERE id={parent_illisible}"), [], |r| r.get::<_, i64>(0))
                .expect_err("fixture : la lecture rate").to_string();
            let r = ag4_creer_un_objet(&st, m_ok, json!({ "name": "ag4_journal_enfant", "parent_id": parent_illisible })).await;
            attendues.push(dm(format!("création d'un objet sous le modèle de données #{m_ok}"), cid(&r), e));
            statuts.push(r.0);
            // modèle hors d'atteinte
            ag4_sql(&st, "ALTER TABLE data_model RENAME TO data_model_ag4_retiree;");
            let e = cause_existence(format!("SELECT 1 FROM data_model WHERE id={m_ok}"));
            let r = ag4_creer_un_objet(&st, m_ok, json!({ "name": "ag4_journal_sans_modele" })).await;
            ag4_sql(&st, "ALTER TABLE data_model_ag4_retiree RENAME TO data_model;");
            attendues.push(dm(format!("création d'un objet sous le modèle de données #{m_ok}"), cid(&r), e));
            statuts.push(r.0);
            // objet hors d'atteinte
            ag4_sql(&st, "ALTER TABLE data_model_object RENAME TO data_model_object_ag4_retiree;");
            let e = cause_existence(format!("SELECT 1 FROM data_model_object WHERE id={o_ok}"));
            let r = ag4_creer_un_champ(&st, o_ok, "ag4_journal_champ").await;
            ag4_sql(&st, "ALTER TABLE data_model_object_ag4_retiree RENAME TO data_model_object;");
            attendues.push(dm(format!("création d'un champ sous l'objet de modèle #{o_ok}"), cid(&r), e));
            statuts.push(r.0);
            // jeu de données illisible
            let e = cause_texte(format!("SELECT soql FROM dataset WHERE id={ds_illisible} AND enabled=1"));
            let r = ag4_lancer_le_jeu(&st, ds_illisible).await;
            attendues.push(dm(format!("exécution du jeu de données #{ds_illisible}"), cid(&r), e));
            statuts.push(r.0);
            // sonde d'enfants non lue
            ag4_refuser_la_colonne(&st, "data_model_object", "parent_id");
            let e = st.db.lock().query_row(&format!("SELECT EXISTS(SELECT 1 FROM data_model_object WHERE parent_id={parent_sonde})"), [], |r| r.get::<_, i64>(0))
                .expect_err("fixture : la sonde rate").to_string();
            let r = ag4_reponse(object_delete(State(st.clone()), adm(), Path(parent_sonde)).await).await;
            ag4_lever(&st);
            attendues.push(format!("[datamodels] WARN suppression de l'objet de modèle #{parent_sonde} refusé : la sonde d'enfants n'a pas pu être lue, rien n'est supprimé ({}) : {e}", cid(&r)));
            statuts.push(r.0);
            // rapports : références hors d'atteinte, rapport illisible, table retirée au déclenchement
            for table in ["dataset", "notifier"] {
                ag4_sql(&st, &format!("ALTER TABLE {table} RENAME TO {table}_ag4_retiree;"));
                let ref_id = if table == "dataset" { ds } else { nf };
                let e = cause_existence(format!("SELECT 1 FROM {table} WHERE id={ref_id}"));
                let r = ag4_creer_un_rapport(&st, "ag4_journal_rapport_refuse", ds, nf).await;
                ag4_sql(&st, &format!("ALTER TABLE {table}_ag4_retiree RENAME TO {table};"));
                attendues.push(sr(format!("création d'un rapport planifié (jeu de données #{ds}, canal #{nf})"), cid(&r), e));
                statuts.push(r.0);
            }
            let e = cause_texte(format!("SELECT name FROM scheduled_report WHERE id={r_illisible}"));
            let r = ag4_supprimer_le_rapport(&st, r_illisible).await;
            attendues.push(sr(format!("suppression du rapport planifié #{r_illisible}"), cid(&r), e));
            statuts.push(r.0);
            ag4_sql(&st, "ALTER TABLE scheduled_report RENAME TO scheduled_report_ag4_retiree;");
            let e = cause_existence(format!("SELECT 1 FROM scheduled_report WHERE id={r_ok}"));
            let r = ag4_declencher_le_rapport(&st, r_ok).await;
            ag4_sql(&st, "ALTER TABLE scheduled_report_ag4_retiree RENAME TO scheduled_report;");
            attendues.push(sr(format!("déclenchement du rapport planifié #{r_ok}"), cid(&r), e));
            statuts.push(r.0);
            // fiche d'engagement illisible
            let e = st.db.lock().query_row(
                "SELECT id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created,created_by,ended_ts \
                 FROM engagement WHERE id='eng-ag4-journal-illisible'", [], engagement_row_json,
            ).expect_err("fixture : la lecture rate").to_string();
            let r = ag4_lire_l_engagement(&st, "eng-ag4-journal-illisible").await;
            attendues.push(format!("[engagement] WARN lecture de l'engagement 'eng-ag4-journal-illisible' refusée : sa fiche n'a pas pu être lue ({}) : {e}", cid(&r)));
            statuts.push(r.0);
            println!("AG4-STATUT-LECTURES:{}", statuts.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            for a in &attendues {
                println!("AG4-ATTENDUE-LECTURE:{a}");
            }

            eprintln!("{PHASE}preparation");
            let m = ag4_id("modèle", &ag4_reponse(model_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_journal_garde" }))).await).await);
            let o = ag4_id("objet", &ag4_creer_un_objet(&st, m, json!({ "name": "ag4_journal_garde_objet" })).await);
            let f = ag4_id("champ", &ag4_creer_un_champ(&st, o, "ag4_journal_garde_champ").await);
            let d = ag4_id("jeu", &ag4_reponse(dataset_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_journal_garde_jeu", "kind": "search", "soql": AG4_GXQL }))).await).await);
            let corps_eng = json!({ "box": "blackbox", "name": "ag4_journal_engagement", "scope": [AG4_SCOPE], "reason": "ag4_journal_raison", "window_end": now() + 3600 });
            let (s, c, v) = ag4_reponse(engagement_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), adm(), Json(corps_eng.clone())).await).await;
            assert_eq!(s, 200, "fixture : engagement créé : {c}");
            let eid = v["id"].as_str().expect("identifiant").to_string();
            ag4_registre_refuse(&st);

            eprintln!("{PHASE}ecritures");
            let mut rs = Vec::new();
            let mut gestes = Vec::new();
            rs.push(ag4_reponse(model_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_journal_refuse" }))).await).await);
            gestes.push("[datamodels] WARN création d'un modèle de données".to_string());
            rs.push(ag4_creer_un_objet(&st, m, json!({ "name": "ag4_journal_refuse_objet" })).await);
            gestes.push(format!("[datamodels] WARN création d'un objet sous le modèle de données #{m}"));
            rs.push(ag4_creer_un_champ(&st, o, "ag4_journal_refuse_champ").await);
            gestes.push(format!("[datamodels] WARN création d'un champ sous l'objet de modèle #{o}"));
            rs.push(ag4_reponse(dataset_create(State(st.clone()), adm(), Json(json!({ "name": "ag4_journal_refuse_jeu", "kind": "search", "soql": AG4_GXQL }))).await).await);
            gestes.push("[datamodels] WARN création d'un jeu de données".to_string());
            rs.push(ag4_reponse(field_delete(State(st.clone()), adm(), Path(f)).await).await);
            gestes.push(format!("[datamodels] WARN suppression du champ de modèle #{f}"));
            rs.push(ag4_reponse(object_delete(State(st.clone()), adm(), Path(o)).await).await);
            gestes.push(format!("[datamodels] WARN suppression de l'objet de modèle #{o}"));
            rs.push(ag4_reponse(model_delete(State(st.clone()), adm(), Path(m)).await).await);
            gestes.push(format!("[datamodels] WARN suppression du modèle de données #{m}"));
            rs.push(ag4_reponse(dataset_delete(State(st.clone()), adm(), Path(d)).await).await);
            gestes.push(format!("[datamodels] WARN suppression du jeu de données #{d}"));
            rs.push(ag4_creer_un_rapport(&st, "ag4_journal_rapport_refuse", ds, nf).await);
            gestes.push(format!("[rapports] WARN création d'un rapport planifié (jeu de données #{ds}, canal #{nf})"));
            rs.push(ag4_supprimer_le_rapport(&st, r_ok).await);
            gestes.push(format!("[rapports] WARN suppression du rapport planifié #{r_ok}"));
            rs.push(ag4_reponse(engagement_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), adm(), Json(corps_eng)).await).await);
            gestes.push("[engagement] WARN création d'un engagement".to_string());
            rs.push(ag4_reponse(engagement_end(State(st.clone()), adm(), Path(eid.clone())).await).await);
            gestes.push(format!("[engagement] WARN clôture de l'engagement '{eid}'"));
            rs.push(ag4_reponse(mode_set(State(st.clone()), adm(), Json(json!({ "mode": "active" }))).await).await);
            gestes.push("[engagement] WARN bascule du mode vers 'active'".to_string());
            println!("AG4-STATUT-ECRITURES:{}", rs.iter().map(|r| r.0.to_string()).collect::<Vec<_>>().join(":"));
            for (r, g) in rs.iter().zip(gestes.iter()) {
                println!("AG4-ATTENDUE-ECRITURE:[{}] {g} refusé : transaction d'audit annulée, aucune modification ({AG4_MOTEUR_ECRITURE})", cid(r));
            }
            ag4_registre_rendu(&st);

            eprintln!("{PHASE}mode");
            ag4_sql(&st, "ALTER TABLE meta RENAME TO meta_ag4_retiree;");
            let e = st.db.lock().query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get::<_, String>(0))
                .expect_err("fixture : la lecture rate").to_string();
            let corps_mode = mode_get(State(st.clone()), adm()).await.0;
            ag4_sql(&st, "ALTER TABLE meta_ag4_retiree RENAME TO meta;");
            println!("AG4-STATUT-MODE:{}", if corps_mode.get("error").is_some() { "aveu" } else { "sans-aveu" });
            println!("AG4-ATTENDUE-MODE:[engagement] WARN lecture du mode global ratée : « observe » servi en repli ({e})");

            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("ag4-journal-calme");
            let mut calme = Vec::new();
            for l in AG4_LIGNES {
                let (table, _, _, _) = l.fiche();
                let id = l.creer(&st, &format!("ag4_calme_{table}"));
                calme.push(l.supprimer(&st, id).await.0);
                calme.push(l.supprimer(&st, AG4_ABSENT).await.0);
            }
            let ds = ag4_insere(&st, &format!("INSERT INTO dataset(name,soql) VALUES('ag4_calme_jeu','{AG4_GXQL}')"));
            calme.push(ag4_lancer_le_jeu(&st, ds).await.0);
            calme.push(ag4_lancer_le_jeu(&st, AG4_ABSENT).await.0);
            let nf = ag4_canal(&st);
            let r = ag4_id("rapport", &ag4_creer_un_rapport(&st, "ag4_calme_rapport", ds, nf).await);
            calme.push(ag4_supprimer_le_rapport(&st, r).await.0);
            calme.push(ag4_supprimer_le_rapport(&st, AG4_ABSENT).await.0);
            calme.push(ag4_declencher_le_rapport(&st, AG4_ABSENT).await.0);
            calme.push(ag4_lire_l_engagement(&st, "eng-ag4-absent").await.0);
            let _ = mode_get(State(st.clone()), adm()).await; // mode jamais posé : « observe » établi, aucune ligne
            println!("AG4-STATUT-CALME:{}", calme.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::modeles_rapports_et_engagements_lecture_ratee_et_lot_non_pris::ag4_lignes_de_journal_des_refus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let lignes_marquees = |m: &str| -> Vec<String> {
            stdout.lines().filter_map(|l| l.split_once(m).map(|(_, r)| r.to_string())).collect()
        };
        let lectures = marque("AG4-STATUT-LECTURES:");
        assert!(lectures.len() >= 14, "plancher : les quatorze lectures");
        assert!(lectures.iter().all(|s| s == "503"), "contrôle : quatorze lectures ratées : {lectures:?}");
        let ecritures = marque("AG4-STATUT-ECRITURES:");
        assert!(ecritures.len() >= 13, "plancher : les treize écritures");
        assert!(ecritures.iter().all(|s| s == "500"), "contrôle : treize écritures refusées : {ecritures:?}");
        assert_eq!(marque("AG4-STATUT-CALME:"),
            ["200", "404", "200", "404", "200", "404", "200", "404", "200", "404", "200", "404", "404", "404"],
            "contrôle : nominal et absences");
        let est_de_ce_lot = |l: &str| ["[datamodels] WARN", "[rapports] WARN", "[engagement] WARN"].iter().any(|t| l.starts_with(t) || l.contains(&format!("] {t}")));
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect()
        };
        let attendues = lignes_marquees("AG4-ATTENDUE-LECTURE:");
        assert!(attendues.len() >= 14, "plancher : une ligne attendue par lecture");
        assert!(attendues.iter().all(|l| l.contains("(plume-e")), "contrôle : identifiants servis : {attendues:?}");
        assert_eq!(phase("lectures"), attendues, "phase lectures : une ligne par lecture ratée, en entier");
        assert!(attendues.iter().any(|l| l.contains(AG4_MOTEUR_LECTURE)) && attendues.iter().any(|l| l.contains("no such table"))
            && attendues.iter().any(|l| l.contains("is prohibited")), "contrôle : les causes rejouées sont celles du moteur : {attendues:?}");
        let attendues = lignes_marquees("AG4-ATTENDUE-ECRITURE:");
        assert!(attendues.len() >= 13, "plancher : une ligne attendue par écriture");
        assert!(attendues.iter().all(|l| l.starts_with("[plume-e")), "contrôle : identifiants servis : {attendues:?}");
        assert_eq!(phase("ecritures"), attendues, "phase ecritures : identifiant servi, geste et cause du moteur, en entier");
        assert_eq!(marque("AG4-STATUT-MODE:"), ["aveu"], "contrôle : le mode non lu est avoué dans le corps");
        let attendues = lignes_marquees("AG4-ATTENDUE-MODE:");
        assert!(attendues.len() == 1 && attendues[0].contains("no such table"), "contrôle : une ligne attendue, cause rejouée : {attendues:?}");
        assert_eq!(phase("mode"), attendues, "phase mode : une ligne, cause du moteur au journal, en entier");
        let toutes: Vec<String> = stderr.lines().filter(|l| est_de_ce_lot(l)).map(str::to_string).collect();
        assert!(toutes.iter().all(|l| !l.contains("ag4_journal") && !l.contains(AG4_ACTEUR) && !l.contains(AG4_CANAL) && !l.contains("ag4 fiche")),
            "aucune ligne ne porte un nom d'objet, de rapport, d'engagement, l'acteur ni l'adresse du canal : {toutes:?}");
        assert!(phase("calme").is_empty(), "le nominal et les absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
