// =====================================================================================
// `P10.20-l` (tranche de la vague AI) — LES LECTURES D'EXISTENCE ET DE DOUBLON PAR `.is_ok()` / `.is_err()` / `.ok()`
// confondaient « aucune ligne » et « lecture qui n'a pas eu lieu ». Hors de la population de `garde_82` (qui ne lit que
// le `match` direct), tenues par la garde des lectures d'une ligne (`P10.20-b`) comme exemptions.
//
// LE DÉFAUT, MESURÉ SUR 88afe566 AVANT LE CORRECTIF.
//   * Créations (`legal_hold_create`, `ledger_sink_create`, `index_policy_create`) : le doublon lu par `.is_ok()` ; une
//     lecture ratée valait « nom libre », et la création passait à l'écriture (200, ligne écrite, maillon au registre)
//     sans qu'aucune lecture ait établi l'absence de doublon.
//   * `lookup_delete` (`.is_err()`) et `playbook_test` (`.ok()`) : lecture ratée servie 404 « introuvable ».
//   * `case_apply_update` (`.ok()`), `case_set_archived` (`.is_err()`) : lecture ratée rendue `DossierAbsent` ; la route
//     de mise à jour la servait « MISE À JOUR INTERROMPUE, des champs ont pu être écrits » alors que rien ne l'était.
//     Les routes d'archivage servaient déjà un 503 « dossier non lu » (elles traduisaient `DossierAbsent` ainsi).
//   * `case_unmerge` (`.ok()`) : lecture ratée rendue `Refusee` (la route la traduisait déjà en 503 « dossier non lu »).
//   * `case_merge` (`juger_la_fusion(..).is_err()`) : le second jugement non lu rendu `Refusee` (même 503 à la route).
//
// LE CORRECTIF (décisions par défaut de la vague AI). Trois issues par `.optional()` : présent, la suite ; absent, la
// sortie d'avant à l'octet (409, 404, `DossierAbsent`, `Refusee`) ; lecture ratée, 503 nommé, rien n'est écrit, la cause
// du moteur au journal seul avec l'identifiant de corrélation servi. Créations : refus AVANT toute transaction.
// `IssueDuDossierModifie::DossierNonLu` et `IssueDeLaFusion::DossierNonLu` (neuves : `NonEcrite` se sert « la base a
// refusé / n'a pas pris l'écriture », et aucune écriture n'a été tentée) ; fusion et défusion : transaction annulée,
// la route sert le corps d'avant à l'octet et journalise la cause avec l'identifiant servi. La phrase « mise à jour
// interrompue » ne cite plus la lecture de l'état courant (une lecture ratée n'y arrive plus).
//
// LES PANNES ÉPROUVÉES : autorisateur SQLite qui refuse la lecture d'une table (`legal_hold`, `ledger_sink`,
// `index_policy`, `lookup_meta`, `playbook`, `incident`), d'une colonne (`incident.status`, que la lecture d'existence de
// la route ne touche pas), ou d'une table à partir du N-ième `SELECT` préparé (la route établit le dossier, la fonction
// le relit : seule la relecture est refusée). Lignes de journal lues sur le stderr d'un sous-processus, ENTIÈRES, par
// égalité ; corps de refus comparés EN ENTIER ; ligne relue après chaque appel.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE : la forme d'avant au site
// (`AI4_GEL`, `AI4_PUITS`, `AI4_INDEX`, `AI4_LOOKUP`, `AI4_ESSAI`, `AI4_MAJ`, `AI4_ARCHIVE`, `AI4_DEFUSION`) ; le doublon
// établi qui laisse passer (`AI4_GEL_PRIS`, `AI4_PUITS_PRIS`, `AI4_INDEX_PRIS`) ; l'absence servie en lecture ratée
// (`AI4_LOOKUP_ABSENT`, `AI4_ESSAI_ABSENT`) ; la route de mise à jour qui garde « interrompue » (`AI4_MAJ_ROUTE`) ; la
// ligne de journal retirée (`*_SANS_JOURNAL`, un par site, `AI4_DESARCHIVE_SANS_JOURNAL` compris). Correction : la
// défusion rendue `NonEcrite` (`AI4C_DEFUSION_NON_ECRITE`) ou servie « défusion non écrite » (`AI4C_DEFUSION_ROUTE`) ;
// le second jugement de la fusion rendu `Refusee` (`AI4C_FUSION`), un refus jugé rendu `DossierNonLu`
// (`AI4C_FUSION_TOUT_NON_LU`) ; la ligne sans identifiant ou retirée (`AI4C_{FUSION,DEFUSION}_SANS_{CID,JOURNAL}`) ;
// la phrase « interrompue » d'avant (`AI4C_INTERROMPUE`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le bras `Ok(0)` des écritures d'archivage et de défusion (inchangé).
// =====================================================================================
mod lectures_d_existence_en_trois_issues {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AI4_GEL: &str = "ai4-gel";
    const AI4_PUITS: &str = "ai4-puits";
    const AI4_INDEX: &str = "ai4index";
    const AI4_LOOKUP: &str = "ai4lookup";
    const AI4_LOOKUP_ABSENT: &str = "ai4absent";

    fn ai4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn ai4_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ai4_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// Refuse la lecture de `table` (de sa colonne `colonne` seule si `Some`) à partir du `a_partir`-ième `SELECT`
    /// préparé sur l'écrivain (1 = toujours).
    fn ai4_refuser(st: &AppState, table: &'static str, colonne: Option<&'static str>, a_partir: usize) {
        let mut selects = 0usize;
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => {
                selects += 1;
                Authorization::Allow
            }
            AuthAction::Read { table_name, column_name } if table_name == table && colonne.map_or(true, |c| c == column_name) && selects >= a_partir => {
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
    }

    fn ai4_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La cause du moteur que rend `sql` sous le refus posé (lue à part, pour comparer la ligne de journal).
    fn ai4_cause(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |_| Ok(())).expect_err("fixture : lecture refusée").to_string()
    }

    /// Un 503 nommé : le corps ENTIER est `{error: <cause>, id: <identifiant>}` ; rend l'identifiant servi.
    fn ai4_cinq_cents(quoi: &str, (statut, corps): &(u16, Value), cause: &str) -> String {
        assert_eq!(*statut, 503, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule, sans texte du moteur : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    /// LES SITES DE LA TRANCHE, joués dans un sous-processus dont le stderr est lu : chaque lecture ratée rend son 503
    /// nommé (corps ENTIER), écrit sa ligne ENTIÈRE au journal avec l'identifiant servi, et n'écrit rien (ligne relue) ;
    /// absences, doublons et nominaux gardent statut et corps d'avant, sans ligne. MUTATIONS : `AI4_*` (voir l'en-tête).
    #[tokio::test]
    async fn ai4_lectures_d_existence() {
        const ENFANT: &str = "AI4_ENFANT_JOURNAL";
        const PHASE: &str = "AI4-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("ai4-existence");
            let adm = sp_au("adm", "admin");
            let ed = sp_au("alice", "editor");
            let mut sortie = serde_json::Map::new();
            let mut causes = serde_json::Map::new();
            let registre = |st: &AppState| ai4_entier(st, "SELECT COUNT(*) FROM ledger");

            // ---- governance.rs : pose d'un gel ----
            eprintln!("{PHASE}gel");
            let avant = registre(&st);
            ai4_refuser(&st, "legal_hold", None, 1);
            causes.insert("gel".into(), json!(ai4_cause(&st, &format!("SELECT 1 FROM legal_hold WHERE name='{AI4_GEL}'"))));
            let r = crate::handlers::governance::legal_hold_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": AI4_GEL }))).await;
            sortie.insert("gel".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("gel_ecrit".into(), json!([ai4_entier(&st, "SELECT COUNT(*) FROM legal_hold"), registre(&st) - avant]));
            eprintln!("{PHASE}gel_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::governance::legal_hold_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": AI4_GEL }))).await).await);
            c.push(ai4_reponse(crate::handlers::governance::legal_hold_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": AI4_GEL }))).await).await);
            sortie.insert("gel_controles".into(), json!(c));
            sortie.insert("gel_id".into(), json!(ai4_entier(&st, &format!("SELECT id FROM legal_hold WHERE name='{AI4_GEL}'"))));

            // ---- governance.rs : création d'un puits ----
            eprintln!("{PHASE}puits");
            let avant = registre(&st);
            ai4_refuser(&st, "ledger_sink", None, 1);
            causes.insert("puits".into(), json!(ai4_cause(&st, &format!("SELECT 1 FROM ledger_sink WHERE name='{AI4_PUITS}'"))));
            let corps_puits = json!({ "name": AI4_PUITS, "kind": "stdout" });
            let r = crate::handlers::governance::ledger_sink_create(State(st.clone()), Extension(adm.clone()), Json(corps_puits.clone())).await;
            sortie.insert("puits".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("puits_ecrit".into(), json!([ai4_entier(&st, "SELECT COUNT(*) FROM ledger_sink"), registre(&st) - avant]));
            eprintln!("{PHASE}puits_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::governance::ledger_sink_create(State(st.clone()), Extension(adm.clone()), Json(corps_puits.clone())).await).await);
            c.push(ai4_reponse(crate::handlers::governance::ledger_sink_create(State(st.clone()), Extension(adm.clone()), Json(corps_puits.clone())).await).await);
            sortie.insert("puits_controles".into(), json!(c));
            sortie.insert("puits_id".into(), json!(ai4_entier(&st, &format!("SELECT id FROM ledger_sink WHERE name='{AI4_PUITS}'"))));

            // ---- index_policies.rs : création d'une politique ----
            eprintln!("{PHASE}index");
            let avant = registre(&st);
            let deja = ai4_entier(&st, "SELECT COUNT(*) FROM index_policy");
            ai4_refuser(&st, "index_policy", None, 1);
            causes.insert("index".into(), json!(ai4_cause(&st, &format!("SELECT 1 FROM index_policy WHERE name='{AI4_INDEX}'"))));
            let corps_index = json!({ "name": AI4_INDEX, "retention_days": 30 });
            let r = crate::handlers::index_policies::index_policy_create(State(st.clone()), Extension(adm.clone()), Json(corps_index.clone())).await;
            sortie.insert("index".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("index_ecrit".into(), json!([ai4_entier(&st, "SELECT COUNT(*) FROM index_policy") - deja, registre(&st) - avant]));
            eprintln!("{PHASE}index_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::index_policies::index_policy_create(State(st.clone()), Extension(adm.clone()), Json(corps_index.clone())).await).await);
            c.push(ai4_reponse(crate::handlers::index_policies::index_policy_create(State(st.clone()), Extension(adm.clone()), Json(corps_index.clone())).await).await);
            sortie.insert("index_controles".into(), json!(c));
            sortie.insert("index_id".into(), json!(ai4_entier(&st, &format!("SELECT id FROM index_policy WHERE name='{AI4_INDEX}'"))));

            // ---- users_lookups.rs : suppression d'une table d'enrichissement ----
            ai4_sql(&st, &format!(
                "INSERT INTO lookup_meta(name,key_field,cols,updated) VALUES('{AI4_LOOKUP}','k','[\"v\"]',0); \
                 INSERT INTO lookup_kv(name,key,val) VALUES('{AI4_LOOKUP}','k1','{{\"v\":\"1\"}}');"
            ));
            eprintln!("{PHASE}lookup");
            let avant = registre(&st);
            ai4_refuser(&st, "lookup_meta", None, 1);
            causes.insert("lookup".into(), json!(ai4_cause(&st, &format!("SELECT 1 FROM lookup_meta WHERE name='{AI4_LOOKUP}'"))));
            let r = crate::handlers::users_lookups::lookup_delete(State(st.clone()), Extension(adm.clone()), Path(AI4_LOOKUP.to_string())).await;
            sortie.insert("lookup".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("lookup_ecrit".into(), json!([
                ai4_entier(&st, &format!("SELECT COUNT(*) FROM lookup_meta WHERE name='{AI4_LOOKUP}'")),
                ai4_entier(&st, &format!("SELECT COUNT(*) FROM lookup_kv WHERE name='{AI4_LOOKUP}'")),
                registre(&st) - avant
            ]));
            eprintln!("{PHASE}lookup_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::users_lookups::lookup_delete(State(st.clone()), Extension(adm.clone()), Path(AI4_LOOKUP_ABSENT.to_string())).await).await);
            c.push(ai4_reponse(crate::handlers::users_lookups::lookup_delete(State(st.clone()), Extension(adm.clone()), Path(AI4_LOOKUP.to_string())).await).await);
            sortie.insert("lookup_controles".into(), json!(c));
            sortie.insert("lookup_restants".into(), json!(ai4_entier(&st, &format!("SELECT COUNT(*) FROM lookup_meta WHERE name='{AI4_LOOKUP}'"))));

            // ---- playbooks.rs : essai (dry-run) ----
            ai4_sql(&st, "INSERT INTO playbook(name,query,is_soql,action_kind,window_s,interval_s,enabled,created_by_role) \
                          VALUES('ai4-essai','search | table src_ip',1,'ban_ip',86400,3600,0,'admin');");
            let pb = ai4_entier(&st, "SELECT id FROM playbook WHERE name='ai4-essai'");
            eprintln!("{PHASE}essai");
            ai4_refuser(&st, "playbook", None, 1);
            causes.insert("essai".into(), json!(ai4_cause(&st, &format!("SELECT query,is_soql,action_kind,window_s FROM playbook WHERE id={pb}"))));
            let r = crate::handlers::playbooks::playbook_test(State(st.clone()), Extension(adm.clone()), Path(pb)).await;
            sortie.insert("essai".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            eprintln!("{PHASE}essai_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::playbooks::playbook_test(State(st.clone()), Extension(adm.clone()), Path(pb + 9_999)).await).await);
            c.push(ai4_reponse(crate::handlers::playbooks::playbook_test(State(st.clone()), Extension(adm.clone()), Path(pb)).await).await);
            sortie.insert("essai_controles".into(), json!(c));

            // ---- cases.rs : mise à jour (route), l'état courant non lu ----
            let d = dossier_seme(&st.db.lock(), "alice", "ai4-titre", 3, "", None, 2);
            eprintln!("{PHASE}maj");
            ai4_refuser(&st, "incident", Some("status"), 1);
            causes.insert("maj".into(), json!(ai4_cause(&st, &format!("SELECT priority, status FROM incident WHERE id={d}"))));
            let r = crate::handlers::cases::case_update(State(st.clone()), Extension(ed.clone()), Path(d), Json(json!({ "title": "ai4-change" }))).await;
            sortie.insert("maj".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("maj_titre".into(), json!(ai4_entier(&st, &format!("SELECT title='ai4-titre' FROM incident WHERE id={d}"))));
            // Fonction : lecture ratée et absence, chacune son issue.
            ai4_refuser(&st, "incident", None, 1);
            let issue = crate::handlers::cases::case_apply_update(&st.db.lock(), d, "alice", &json!({ "title": "ai4-change" }));
            sortie.insert("maj_fonction".into(), json!(format!("{issue:?}")));
            causes.insert("dossier".into(), json!(ai4_cause(&st, &format!("SELECT 1 FROM incident WHERE id={d}"))));
            causes.insert("etat".into(), json!(ai4_cause(&st, &format!("SELECT priority, status FROM incident WHERE id={d}"))));
            ai4_lever(&st);
            let issue = crate::handlers::cases::case_apply_update(&st.db.lock(), d + 9_999, "alice", &json!({ "title": "ai4-change" }));
            sortie.insert("maj_absent".into(), json!(format!("{issue:?}")));
            eprintln!("{PHASE}maj_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::cases::case_update(State(st.clone()), Extension(ed.clone()), Path(d + 9_999), Json(json!({ "title": "x" }))).await).await);
            c.push(ai4_reponse(crate::handlers::cases::case_update(State(st.clone()), Extension(ed.clone()), Path(d), Json(json!({ "title": "ai4-change" }))).await).await);
            sortie.insert("maj_controles".into(), json!(c));
            sortie.insert("maj_titre_nominal".into(), json!(ai4_entier(&st, &format!("SELECT title='ai4-change' FROM incident WHERE id={d}"))));

            // ---- cases.rs : archivage et désarchivage (routes), la relecture refusée après l'établissement ----
            eprintln!("{PHASE}archive");
            let avant = registre(&st);
            ai4_refuser(&st, "incident", None, 2);
            let r = crate::handlers::cases::case_archive(State(st.clone()), Extension(adm.clone()), Path(d)).await;
            sortie.insert("archive".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("archive_ecrit".into(), json!([ai4_entier(&st, &format!("SELECT archived FROM incident WHERE id={d}")), registre(&st) - avant]));
            ai4_refuser(&st, "incident", None, 1);
            let issue = crate::handlers::cases::case_set_archived(&st.db.lock(), d, "adm", true);
            sortie.insert("archive_fonction".into(), json!(format!("{issue:?}")));
            ai4_lever(&st);
            let issue = crate::handlers::cases::case_set_archived(&st.db.lock(), d + 9_999, "adm", true);
            sortie.insert("archive_absent".into(), json!(format!("{issue:?}")));
            eprintln!("{PHASE}archive_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ai4_reponse(crate::handlers::cases::case_archive(State(st.clone()), Extension(adm.clone()), Path(d + 9_999)).await).await);
            c.push(ai4_reponse(crate::handlers::cases::case_archive(State(st.clone()), Extension(adm.clone()), Path(d)).await).await);
            sortie.insert("archive_controles".into(), json!(c));
            eprintln!("{PHASE}desarchive");
            let avant = registre(&st);
            ai4_refuser(&st, "incident", None, 2);
            let r = crate::handlers::cases::case_unarchive(State(st.clone()), Extension(adm.clone()), Path(d)).await;
            sortie.insert("desarchive".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("desarchive_ecrit".into(), json!([ai4_entier(&st, &format!("SELECT archived FROM incident WHERE id={d}")), registre(&st) - avant]));
            eprintln!("{PHASE}desarchive_controles");
            let r = crate::handlers::cases::case_unarchive(State(st.clone()), Extension(adm.clone()), Path(d)).await;
            sortie.insert("desarchive_controles".into(), json!(ai4_reponse(r).await));
            sortie.insert("desarchive_etat".into(), json!(ai4_entier(&st, &format!("SELECT archived FROM incident WHERE id={d}"))));

            // ---- caseops.rs : défusion (route et fonction) ----
            let src = dossier_seme(&st.db.lock(), "alice", "ai4-source", 3, "", None, 2);
            let dst = dossier_seme(&st.db.lock(), "alice", "ai4-cible", 3, "", None, 2);
            let fusion = crate::handlers::caseops::case_merge(&st.db.lock(), src, dst, "alice");
            assert_eq!(fusion, crate::handlers::caseops::IssueDeLaFusion::Ecrite, "fixture : fusion posée");
            eprintln!("{PHASE}defusion");
            let avant = registre(&st);
            ai4_refuser(&st, "incident", None, 2);
            let r = crate::handlers::caseops::case_unmerge_handler(State(st.clone()), Extension(ed.clone()), Path(src)).await;
            sortie.insert("defusion".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("defusion_ecrit".into(), json!([ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={src}")), registre(&st) - avant]));
            eprintln!("{PHASE}defusion_fonction");
            ai4_refuser(&st, "incident", None, 1);
            let issue = crate::handlers::caseops::case_unmerge(&st.db.lock(), src, "alice");
            sortie.insert("defusion_fonction".into(), json!(format!("{issue:?}")));
            causes.insert("defusion".into(), json!(ai4_cause(&st, &format!("SELECT merged_into FROM incident WHERE id={src}"))));
            ai4_lever(&st);
            sortie.insert("defusion_fonction_ecrit".into(), json!(ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={src}"))));
            // NULL (non fusionné) et absence : `Refusee` d'avant.
            let non_fusionne = crate::handlers::caseops::case_unmerge(&st.db.lock(), dst, "alice");
            let absent = crate::handlers::caseops::case_unmerge(&st.db.lock(), src + dst + 9_999, "alice");
            sortie.insert("defusion_refusees".into(), json!([format!("{non_fusionne:?}"), format!("{absent:?}")]));
            eprintln!("{PHASE}defusion_controles");
            let r = crate::handlers::caseops::case_unmerge_handler(State(st.clone()), Extension(ed.clone()), Path(src)).await;
            sortie.insert("defusion_controles".into(), json!(ai4_reponse(r).await));
            sortie.insert("defusion_etat".into(), json!(ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={src}"))));

            // ---- caseops.rs : fusion, second jugement non lu (route et fonction) ----
            let fa = dossier_seme(&st.db.lock(), "alice", "ai4-fa", 3, "", None, 2);
            let fb = dossier_seme(&st.db.lock(), "alice", "ai4-fb", 3, "", None, 2);
            eprintln!("{PHASE}fusion");
            let avant = registre(&st);
            // La route juge (source, cible, chaîne : trois `SELECT`) ; le quatrième ouvre le second jugement de `case_merge`.
            ai4_refuser(&st, "incident", None, 4);
            let r = crate::handlers::caseops::case_merge_handler(State(st.clone()), Extension(ed.clone()), Path(fa), Json(json!({ "into": fb }))).await;
            sortie.insert("fusion".into(), json!(ai4_reponse(r).await));
            ai4_lever(&st);
            sortie.insert("fusion_ecrit".into(), json!([ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={fa}")), registre(&st) - avant]));
            eprintln!("{PHASE}fusion_fonction");
            ai4_refuser(&st, "incident", None, 1);
            let issue = crate::handlers::caseops::case_merge(&st.db.lock(), fa, fb, "alice");
            sortie.insert("fusion_fonction".into(), json!(format!("{issue:?}")));
            causes.insert("fusion".into(), json!(ai4_cause(&st, &format!("SELECT merged_into FROM incident WHERE id={fa}"))));
            ai4_lever(&st);
            sortie.insert("fusion_fonction_ecrit".into(), json!(ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={fa}"))));
            // Un refus jugé (même dossier) : `Refusee` d'avant.
            let meme = crate::handlers::caseops::case_merge(&st.db.lock(), fa, fa, "alice");
            sortie.insert("fusion_refusee".into(), json!(format!("{meme:?}")));
            eprintln!("{PHASE}fusion_controles");
            let r = crate::handlers::caseops::case_merge_handler(State(st.clone()), Extension(ed.clone()), Path(fa), Json(json!({ "into": fb }))).await;
            sortie.insert("fusion_controles".into(), json!(ai4_reponse(r).await));
            sortie.insert("fusion_etat".into(), json!(ai4_entier(&st, &format!("SELECT COALESCE(merged_into,-1) FROM incident WHERE id={fa}"))));

            // ---- cases.rs : mise à jour interrompue (une écriture à zéro ligne), la phrase servie ----
            eprintln!("{PHASE}interrompue");
            ai4_sql(&st, "CREATE TEMP TRIGGER ai4_ignore BEFORE UPDATE OF title ON incident BEGIN SELECT RAISE(IGNORE); END;");
            let r = crate::handlers::cases::case_update(State(st.clone()), Extension(ed.clone()), Path(d), Json(json!({ "title": "ai4-ignore" }))).await;
            sortie.insert("interrompue".into(), json!(ai4_reponse(r).await));
            ai4_sql(&st, "DROP TRIGGER ai4_ignore;");
            eprintln!("{PHASE}fin");

            let ids = json!({ "pb": pb, "d": d, "src": src, "dst": dst, "fa": fa, "fb": fb });
            println!("AI4-SORTIE:{}", Value::Object(sortie));
            println!("AI4-CAUSES:{}", Value::Object(causes));
            println!("AI4-IDS:{ids}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::lectures_d_existence_en_trois_issues::ai4_lectures_d_existence"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Value {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : {m} JSON ({e}) : {stdout}"))
        };
        let (s, causes, ids) = (marque("AI4-SORTIE:"), marque("AI4-CAUSES:"), marque("AI4-IDS:"));
        let cause = |k: &str| -> String { causes[k].as_str().unwrap_or_else(|| panic!("contrôle : cause {k} : {causes}")).to_string() };
        let id = |k: &str| -> i64 { ids[k].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant {k} : {ids}")) };
        let reponse = |k: &str| -> (u16, Value) {
            let v = &s[k];
            (v[0].as_u64().unwrap_or_else(|| panic!("contrôle : statut de {k} : {v}")) as u16, v[1].clone())
        };
        let reponses = |k: &str| -> Vec<(u16, Value)> { serde_json::from_value(s[k].clone()).unwrap_or_else(|e| panic!("contrôle : {k} ({e}) : {s}")) };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps
                .lines()
                .filter(|l| ["[gouvernance]", "[index-policies]", "[lookup]", "[playbooks]", "[cases]", "[caseops]"].iter().any(|t| l.contains(t)))
                .map(str::to_string)
                .collect()
        };

        // ---- Les lectures ratées : 503 nommé, ligne ENTIÈRE, rien d'écrit ----
        let cid = ai4_cinq_cents("gel, doublon non lu", &reponse("gel"), crate::handlers::governance::CAUSE_GEL_JURIDIQUE_NON_POSE_DOUBLON_NON_LU);
        assert_eq!(phase("gel"), [format!("[gouvernance] WARN doublon du gel juridique à poser NON lu, rien n'est posé ({cid}) : {}", cause("gel"))]);
        assert_eq!(s["gel_ecrit"], json!([0, 0]), "gel : aucune ligne, aucun maillon");
        let cid = ai4_cinq_cents("puits, doublon non lu", &reponse("puits"), crate::handlers::governance::CAUSE_PUITS_DU_REGISTRE_NON_CREE_DOUBLON_NON_LU);
        assert_eq!(phase("puits"), [format!("[gouvernance] WARN doublon du puits du registre à créer NON lu, rien n'est créé ({cid}) : {}", cause("puits"))]);
        assert_eq!(s["puits_ecrit"], json!([0, 0]), "puits : aucune ligne, aucun maillon");
        let cid = ai4_cinq_cents("index, doublon non lu", &reponse("index"), crate::handlers::index_policies::CAUSE_POLITIQUE_D_INDEX_NON_CREEE_DOUBLON_NON_LU);
        assert_eq!(phase("index"), [format!("[index-policies] WARN doublon de la politique d'index à créer NON lu, rien n'est créé ({cid}) : {}", cause("index"))]);
        assert_eq!(s["index_ecrit"], json!([0, 0]), "index : aucune ligne, aucun maillon");
        let cid = ai4_cinq_cents("lookup non lu", &reponse("lookup"), crate::handlers::users_lookups::CAUSE_TABLE_D_ENRICHISSEMENT_NON_SUPPRIMEE_NON_LUE);
        assert_eq!(phase("lookup"), [format!("[lookup] WARN table d'enrichissement à supprimer NON lue, rien n'est supprimé ({cid}) : {}", cause("lookup"))]);
        assert_eq!(s["lookup_ecrit"], json!([1, 1, 0]), "lookup non lu : métadonnée et lignes intactes, aucun maillon");
        let cid = ai4_cinq_cents("essai non lu", &reponse("essai"), crate::handlers::playbooks::CAUSE_PLAYBOOK_NON_ESSAYE_NON_LU);
        assert_eq!(phase("essai"), [format!("[playbooks] WARN playbook #{} NON lu pour l'essai, aucune requête exécutée ({cid}) : {}", id("pb"), cause("essai"))]);
        let d = id("d");
        let cid = ai4_cinq_cents("mise à jour, état non lu", &reponse("maj"), crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT);
        assert_eq!(phase("maj"), [format!("[cases] WARN dossier #{d} NON lu pour la mise à jour, rien n'est écrit ({cid}) : {}", cause("maj"))]);
        assert_eq!(s["maj_titre"], json!(1), "mise à jour, état non lu : titre inchangé");
        assert_eq!(s["maj_fonction"], json!(format!("{:?}", crate::handlers::cases::IssueDuDossierModifie::DossierNonLu(cause("etat")))));
        assert_eq!(s["maj_absent"], json!(format!("{:?}", crate::handlers::cases::IssueDuDossierModifie::DossierAbsent)));
        let relecture = format!("{} (relecture du dossier)", crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT);
        let cid = ai4_cinq_cents("archivage, relecture refusée", &reponse("archive"), &relecture);
        assert_eq!(phase("archive"), [format!("[cases] WARN dossier #{d} NON relu pour l'archivage, rien n'est écrit ({cid}) : {}", cause("dossier"))]);
        assert_eq!(s["archive_ecrit"], json!([0, 0]), "archivage refusé : non archivé, aucun maillon");
        assert_eq!(s["archive_fonction"], json!(format!("{:?}", crate::handlers::cases::IssueDuDossierModifie::DossierNonLu(cause("dossier")))));
        assert_eq!(s["archive_absent"], json!(format!("{:?}", crate::handlers::cases::IssueDuDossierModifie::DossierAbsent)));
        let cid = ai4_cinq_cents("désarchivage, relecture refusée", &reponse("desarchive"), &relecture);
        assert_eq!(phase("desarchive"), [format!("[cases] WARN dossier #{d} NON relu pour le désarchivage, rien n'est écrit ({cid}) : {}", cause("dossier"))]);
        assert_eq!(s["desarchive_ecrit"], json!([1, 0]), "désarchivage refusé : toujours archivé, aucun maillon");
        let src = id("src");
        // Le corps d'AVANT le lot, à l'octet (jamais « défusion non écrite » : aucune écriture n'a été tentée).
        let defusion = format!("{} (relecture du dossier fusionné)", crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT);
        let cid = ai4_cinq_cents("défusion, relecture refusée", &reponse("defusion"), &defusion);
        assert_eq!(phase("defusion"), [format!("[caseops] WARN dossier #{src} NON relu pour la défusion, rien n'est écrit ({cid}) : {}", cause("defusion"))]);
        assert_eq!(s["defusion_ecrit"], json!([id("dst"), 0]), "défusion refusée : toujours fusionné, aucun maillon");
        let non_lu = crate::handlers::caseops::IssueDeLaFusion::DossierNonLu(cause("defusion"));
        assert_eq!(s["defusion_fonction"], json!(format!("{non_lu:?}")));
        assert!(phase("defusion_fonction").is_empty(), "défusion (fonction) : la ligne est écrite par la route, avec l'identifiant : {stderr}");
        assert_eq!(s["defusion_fonction_ecrit"], json!(id("dst")), "défusion (fonction) refusée : transaction annulée");
        let refusee = format!("{:?}", crate::handlers::caseops::IssueDeLaFusion::Refusee);
        assert_eq!(s["defusion_refusees"], json!([refusee, refusee]), "non fusionné (NULL) et absent : `Refusee` d'avant");
        let (fa, fb) = (id("fa"), id("fb"));
        let fusion = format!("{} (second jugement de la fusion)", crate::handlers::cases::CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT);
        let cid = ai4_cinq_cents("fusion, second jugement non lu", &reponse("fusion"), &fusion);
        assert_eq!(phase("fusion"), [format!("[caseops] WARN dossier #{fa} NON relu pour la fusion dans #{fb}, rien n'est écrit ({cid}) : {}", cause("fusion"))]);
        assert_eq!(s["fusion_ecrit"], json!([-1, 0]), "fusion refusée : non fusionné, aucun maillon");
        let non_lu = crate::handlers::caseops::IssueDeLaFusion::DossierNonLu(cause("fusion"));
        assert_eq!(s["fusion_fonction"], json!(format!("{non_lu:?}")));
        assert!(phase("fusion_fonction").is_empty(), "fusion (fonction) : la ligne est écrite par la route : {stderr}");
        assert_eq!(s["fusion_fonction_ecrit"], json!(-1), "fusion (fonction) refusée : transaction annulée");
        assert_eq!(s["fusion_refusee"], json!(refusee), "refus jugé (même dossier) : `Refusee` d'avant");
        // La phrase servie, écrite ici en toutes lettres : elle ne cite plus la lecture de l'état courant.
        ai4_cinq_cents(
            "mise à jour interrompue",
            &reponse("interrompue"),
            "MISE À JOUR DU DOSSIER INTERROMPUE : le dossier n'était plus en base à la lecture de son état courant, ou une \
             écriture n'a touché aucune ligne. Les champs qui précèdent dans la demande ont pu être écrits, avec leur \
             chronologie et leur ligne de registre : relisez le dossier avant de réessayer.",
        );
        assert!(phase("interrompue").is_empty(), "mise à jour interrompue : aucune ligne neuve au journal : {stderr}");

        // ---- Contrôles : doublon, absence, nominal — statut et corps d'avant, aucune ligne ----
        assert_eq!(
            reponses("gel_controles"),
            vec![
                (200, json!({ "ok": true, "id": s["gel_id"], "name": AI4_GEL, "active": true })),
                (409, json!({ "error": format!("un hold nommé '{AI4_GEL}' existe déjà") })),
            ],
            "gel : nominal puis doublon établi"
        );
        assert_eq!(
            reponses("puits_controles"),
            vec![
                (200, json!({ "ok": true, "id": s["puits_id"], "name": AI4_PUITS })),
                (409, json!({ "error": format!("un sink nommé '{AI4_PUITS}' existe déjà") })),
            ],
            "puits : nominal puis doublon établi"
        );
        assert_eq!(
            reponses("index_controles"),
            vec![
                (200, json!({ "id": s["index_id"], "name": AI4_INDEX, "retention_days": 30, "managed": 2 })),
                (409, json!({ "error": format!("un index nommé '{AI4_INDEX}' existe déjà") })),
            ],
            "index : nominal puis doublon établi"
        );
        assert_eq!(
            reponses("lookup_controles"),
            vec![(404, json!({ "error": "lookup introuvable" })), (200, json!({ "ok": true, "deleted": true }))],
            "lookup : absent puis nominal"
        );
        assert_eq!(s["lookup_restants"], json!(0), "lookup nominal : supprimé");
        assert_eq!(
            reponses("essai_controles"),
            vec![(404, json!({ "error": "playbook introuvable" })), (200, json!({ "action_kind": "ban_ip", "targets": [], "valides": 0 }))],
            "essai : absent puis nominal"
        );
        assert_eq!(
            reponses("maj_controles"),
            vec![(404, json!({ "error": crate::handlers::cases::CAUSE_DOSSIER_INTROUVABLE })), (204, Value::Null)],
            "mise à jour : absent puis nominal"
        );
        assert_eq!(s["maj_titre_nominal"], json!(1), "mise à jour nominale : titre écrit");
        assert_eq!(
            reponses("archive_controles"),
            vec![(404, json!({ "error": crate::handlers::cases::CAUSE_DOSSIER_INTROUVABLE })), (204, Value::Null)],
            "archivage : absent puis nominal"
        );
        assert_eq!(reponse("desarchive_controles"), (204, Value::Null), "désarchivage nominal");
        assert_eq!(s["desarchive_etat"], json!(0), "désarchivage nominal : désarchivé");
        assert_eq!(reponse("defusion_controles"), (204, Value::Null), "défusion nominale");
        assert_eq!(s["defusion_etat"], json!(-1), "défusion nominale : merged_into NULL");
        assert_eq!(reponse("fusion_controles"), (204, Value::Null), "fusion nominale");
        assert_eq!(s["fusion_etat"], json!(id("fb")), "fusion nominale : fusionné dans la cible");
        let controles = [
            "gel_controles",
            "puits_controles",
            "index_controles",
            "lookup_controles",
            "essai_controles",
            "maj_controles",
            "archive_controles",
            "desarchive_controles",
            "defusion_controles",
            "fusion_controles",
        ];
        assert!(controles.len() >= 10, "plancher : dix phases de contrôle");
        for nom in controles {
            assert!(phase(nom).is_empty(), "{nom} : les sorties d'avant n'écrivent rien au journal : {stderr}");
        }
    }
}
