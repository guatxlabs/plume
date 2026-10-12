// =====================================================================================
// `P10.22-q` (restes de `P10.21-t`) et `P10.29-j` — L'ATTACHE D'UN RUNBOOK : LES DEUX DERNIÈRES LECTURES, ET CE QUI
// ÉTAIT DÉJÀ TENU.
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ, RE-MESURÉ SUR cc71144 :
//   * « `attach_runbook` lit "déjà attaché" par `unwrap_or(0)` » : la lecture est un `match` (`P10.20-b`, rang deux),
//     une lecture ratée rend `NonLu(CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE)`, 503 côté route ;
//   * « le contrôle d'existence rend 404 sur une lecture ratée » : `QueryReturnedNoRows` est distingué, toute autre
//     erreur rend `NonLu(CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE)` ;
//   * `step_advance` a été retiré de la garde des écritures avalées par `P10.20-w`
//     (`check_a_swallowed_write_is_never_affirmed_as_a_fact.py`).
// Le témoin (2) ÉPINGLE cet état tenu.
//
// `P10.29-j` — LE VU ÉTAIT VRAI À SON ÉCRITURE (ece536fe, 2026-09-25) ; SA MOITIÉ « JOURNAL » A ÉTÉ CORRIGÉE AILLEURS
// ENSUITE, ET SA MOITIÉ « PHRASE » RESTAIT VRAIE :
//   * journal et compte du `BEGIN` refusé : `scim_group_patch` sous `jouer_le_geste_garde` (c2d9f127, `P10.21-r`,
//     2026-09-25 après-midi), `attach_runbook` par `dire_la_transaction_non_ouverte` (5705e45f, `P10.27-h`, 2026-10-01).
//     Le VU est PÉRIMÉ pour cette moitié ; les témoins (3) et (4) en tiennent le compte ;
//   * la phrase : la route d'attache servait `CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES` + l'erreur du moteur (« Cause :
//     transaction refusée (cannot start a transaction within a transaction) ») ; `scim_group_patch` fondait `NonOuvert`
//     et `NonValide` sous `CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE` (« n'a pas pris l'ajout ou le retrait d'un
//     membre », faux quand c'est le `BEGIN` qui est refusé). CORRIGÉ ICI : chacun a sa cause `*_TRANSACTION_NON_OUVERTE`
//     (`CAUSE_RUNBOOK_NON_ATTACHE_TRANSACTION_NON_OUVERTE`, `CAUSE_SCIM_OPERATION_DE_GROUPE_TRANSACTION_NON_OUVERTE`),
//     sans l'erreur du moteur dans le corps.
//
// CE QUI ÉTAIT VRAI ET EST CORRIGÉ (`P10.22-q`) : la ligne du runbook se lisait `.map_err(|_| "runbook introuvable")`
// (une lecture refusée rendait 400 « introuvable » pour une procédure qui existe) ; les étapes non lues rendaient un 400
// de client avec l'erreur du moteur dans le corps. Désormais trois issues sur la ligne du runbook (absence établie =
// refus d'avant ; lecture non faite = `NonLu(CAUSE_RUNBOOK_NON_LU_POUR_L_ATTACHE)`) et les étapes non lues =
// `NonLu(CAUSE_ETAPES_DU_RUNBOOK_NON_LUES_POUR_L_ATTACHE)` : 503, l'erreur du moteur au journal seulement.
//
// LA VOIE DE L'ÉCHEC : la table `runbook` (puis `runbook_step`) RENOMMÉE — jamais un déclencheur sur `SELECT` — et une
// ligne de runbook illisible (nom stocké en blob : le mappeur refuse, la requête est saine).
//
// CE QUE CE LOT NE TIENT PAS :
//   * `attach_runbook` AVALE TOUJOURS l'écriture de sa chronologie (`case_add_item`, qui rend `()` pour ses vingt
//     appelants ; `P10.21-n` n'a fermé que la route `case_item_add`) : un `INSERT` refusé sur `incident_item` laisse
//     `Ok(n)`, étapes et registre écrits, chronologie absente et MTTA (`first_response_ts`) non figée ;
//   * le journal du démon (`eprintln!` des lectures non faites) n'est jugé par aucun instrument ;
//   * l'attache garde un refus typé (`Txn::begin`, site toléré par `garde_74`) plutôt que `ouvrir_le_garde_du_geste` ;
//   * la console n'est pas jugée.
// =====================================================================================

/// Un dossier neuf (sans progression) et un runbook actif d'une étape, posé à la main. Rend `(dossier, runbook)`.
fn arl_dossier_et_runbook(conn: &Connection, cle: &str) -> (i64, i64) {
    let id = dossier_seme(conn, "adm", "intrusion-arl", 4, "", None, 2);
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,'Procédure arl','*','','',0,1,1000)",
        params![cle],
    )
    .expect("fixture : le runbook");
    let rb = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind) VALUES(?1,0,'triage','Vérifier','','manual')",
        params![rb],
    )
    .expect("fixture : une étape");
    (id, rb)
}

/// (étapes du dossier, items de chronologie « runbook » du dossier, lignes de registre d'attache, toutes).
fn arl_traces(conn: &Connection, id: i64) -> (i64, i64, i64) {
    let n = |sql: &str| -> i64 { conn.query_row(sql, params![id], |r| r.get(0)).expect("compte de témoin") };
    (
        n("SELECT COUNT(*) FROM case_step WHERE incident_id=?1"),
        n("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='runbook'"),
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach'", [], |r| r.get(0)).expect("compte du registre"),
    )
}

fn arl_adm() -> AuthUser {
    AuthUser { name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
}

async fn arl_attacher(st: &AppState, id: i64, rb: i64) -> (StatusCode, Value) {
    tok_resp_json(case_runbook_attach(State(st.clone()), Extension(arl_adm()), Path(id), Json(json!({ "runbook_id": rb }))).await).await
}

// -------------------------------------------------------------------------------------
// (1) LA LIGNE DU RUNBOOK ET SES ÉTAPES — LUES OU AVOUÉES, JAMAIS « INTROUVABLE » NI 400
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : contrôles positifs d'abord — un runbook absent rend « runbook introuvable », un runbook inactif
/// « runbook inactif », un runbook sans étape « runbook sans étape » (refus d'avant, octet pour octet, `Refuse`). Puis
/// la table `runbook` renommée : `NonLu(CAUSE_RUNBOOK_NON_LU_POUR_L_ATTACHE)`, rien d'écrit ; la ligne illisible (blob)
/// : même refus ; la table `runbook_step` renommée : `NonLu(CAUSE_ETAPES_DU_RUNBOOK_NON_LUES_POUR_L_ATTACHE)`, rien
/// d'écrit (l'absence de l'erreur du moteur dans le corps est jugée à la route, témoin suivant). Les tables revenues, l'attache passe, entière.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `arl_runbook_introuvable` (la lecture ratée rendue « runbook introuvable », la
/// forme d'avant) ; `arl_etapes_400` (les étapes non lues rendues en `Refuse` avec l'erreur du moteur).
#[test]
fn arl_une_lecture_du_runbook_non_faite_est_avouee_et_rien_n_est_ecrit() {
    let conn = test_db();
    let (id, rb) = arl_dossier_et_runbook(&conn, "arl-un");
    let avant = arl_traces(&conn, id);
    assert_eq!(avant.0, 0, "fixture : aucune progression");

    // CONTRÔLES POSITIFS — l'absence et les faits LUS gardent leur refus d'avant.
    match attach_runbook(&conn, id, 987_654, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::Refuse(r)) => assert_eq!(r, "runbook introuvable"),
        autre => panic!("un runbook absent reste « runbook introuvable » : {autre:?}"),
    }
    conn.execute("INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('arl-inactif','I','*','','',0,0,1000)", []).unwrap();
    let inactif = conn.last_insert_rowid();
    match attach_runbook(&conn, id, inactif, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::Refuse(r)) => assert_eq!(r, "runbook inactif"),
        autre => panic!("un runbook inactif reste refusé comme avant : {autre:?}"),
    }
    conn.execute("INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('arl-vide','V','*','','',0,1,1000)", []).unwrap();
    let vide = conn.last_insert_rowid();
    match attach_runbook(&conn, id, vide, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::Refuse(r)) => assert_eq!(r, "runbook sans étape"),
        autre => panic!("un runbook sans étape reste refusé comme avant : {autre:?}"),
    }
    assert_eq!(arl_traces(&conn, id), avant, "rien d'écrit sur les refus d'avant");

    // LA TABLE DU RUNBOOK HORS D'ATTEINTE.
    conn.execute_batch("ALTER TABLE runbook RENAME TO runbook_hors_d_atteinte;").expect("fixture : renommage");
    let r = attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default());
    conn.execute_batch("ALTER TABLE runbook_hors_d_atteinte RENAME TO runbook;").expect("fixture : retour");
    match &r {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(*c, CAUSE_RUNBOOK_NON_LU_POUR_L_ATTACHE),
        autre => panic!("un runbook NON LU n'est pas « runbook introuvable » : {autre:?}"),
    }
    assert_eq!(arl_traces(&conn, id), avant, "rien d'écrit sur le runbook non lu");

    // LA LIGNE DU RUNBOOK ILLISIBLE (nom en blob : le mappeur refuse).
    conn.execute("UPDATE runbook SET name=x'00ff' WHERE id=?1", params![rb]).unwrap();
    match attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(c, CAUSE_RUNBOOK_NON_LU_POUR_L_ATTACHE),
        autre => panic!("une ligne de runbook illisible n'est pas « introuvable » : {autre:?}"),
    }
    conn.execute("UPDATE runbook SET name='Procédure arl' WHERE id=?1", params![rb]).unwrap();
    assert_eq!(arl_traces(&conn, id), avant, "rien d'écrit sur la ligne illisible");

    // LES ÉTAPES HORS D'ATTEINTE.
    conn.execute_batch("ALTER TABLE runbook_step RENAME TO runbook_step_hors_d_atteinte;").expect("fixture : renommage");
    let r = attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default());
    conn.execute_batch("ALTER TABLE runbook_step_hors_d_atteinte RENAME TO runbook_step;").expect("fixture : retour");
    match &r {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(*c, CAUSE_ETAPES_DU_RUNBOOK_NON_LUES_POUR_L_ATTACHE),
        autre => panic!("des étapes NON LUES sont une cause serveur nommée, pas un refus de client : {autre:?}"),
    }
    assert_eq!(arl_traces(&conn, id), avant, "rien d'écrit sur les étapes non lues");

    // LES TABLES REVENUES — l'attache passe, entière.
    assert_eq!(attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default()).expect("l'attache reste possible"), 1);
    assert_eq!(arl_traces(&conn, id), (1, 1, avant.2 + 1), "attache entière : étape, chronologie, registre");
}

/// CE QU'IL TIENT : la ROUTE sert 503 avec la cause constante (ni 400, ni l'erreur du moteur dans le corps) pour le
/// runbook non lu et pour les étapes non lues ; un runbook absent garde son 400 « runbook introuvable » ; rien n'est
/// écrit ; les tables revenues, la route attache (200, `attached: 1`).
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `arl_runbook_introuvable` (400 « introuvable ») ; `arl_etapes_400` (400 avec
/// « no such table » dans le corps).
#[tokio::test]
async fn arl_la_route_d_attache_sert_503_sur_une_lecture_du_runbook_non_faite() {
    let (st, _p) = sp_state("arl-route");
    let (id, rb) = arl_dossier_et_runbook(&st.db.lock(), "arl-route");
    let avant = arl_traces(&st.db.lock(), id);

    let (statut, corps) = arl_attacher(&st, id, 987_654).await;
    assert_eq!(statut, StatusCode::BAD_REQUEST, "absence établie : 400 d'avant : {corps}");
    assert!(corps.to_string().contains("runbook introuvable"), "{corps}");

    st.db.lock().execute_batch("ALTER TABLE runbook RENAME TO runbook_hors_d_atteinte;").unwrap();
    let (statut, corps) = arl_attacher(&st, id, rb).await;
    st.db.lock().execute_batch("ALTER TABLE runbook_hors_d_atteinte RENAME TO runbook;").unwrap();
    assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "runbook non lu : 503 nommé : {corps}");
    assert!(corps.to_string().contains(CAUSE_RUNBOOK_NON_LU_POUR_L_ATTACHE), "la cause est servie : {corps}");

    st.db.lock().execute_batch("ALTER TABLE runbook_step RENAME TO runbook_step_hors_d_atteinte;").unwrap();
    let (statut, corps) = arl_attacher(&st, id, rb).await;
    st.db.lock().execute_batch("ALTER TABLE runbook_step_hors_d_atteinte RENAME TO runbook_step;").unwrap();
    assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "étapes non lues : 503, pas 400 : {corps}");
    assert!(corps.to_string().contains(CAUSE_ETAPES_DU_RUNBOOK_NON_LUES_POUR_L_ATTACHE), "la cause est servie : {corps}");
    assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
    assert_eq!(arl_traces(&st.db.lock(), id), avant, "rien d'écrit");

    let (statut, corps) = arl_attacher(&st, id, rb).await;
    assert_eq!(statut, StatusCode::OK, "tables revenues : l'attache passe : {corps}");
    assert_eq!(corps["attached"], json!(1), "{corps}");
}

// -------------------------------------------------------------------------------------
// (2) RÉFUTATION ÉPINGLÉE — `P10.22-q` : progression et existence non lues sont déjà des 503 nommés
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT (état déjà tenu, que l'énoncé disait faux) : la progression non lue (lecture de `case_step` refusée
/// par autorisateur, écriture permise) rend 503 à la route avec `CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE`, sans
/// doubler l'étape ; l'existence du dossier non lue (vue temporaire qui coiffe `incident`) rend
/// `NonLu(CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE)`, jamais « incident introuvable ».
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `arl_progression_zero` (le zéro fabriqué `unwrap_or(0)` : 200 et étape doublée) ;
/// `arl_existence_introuvable` (la lecture ratée rendue « incident introuvable »).
#[tokio::test]
async fn arl_refutation_progression_et_existence_non_lues_sont_deja_des_refus_nommes() {
    let (st, _p) = sp_state("arl-refut");
    let (id, rb) = arl_dossier_et_runbook(&st.db.lock(), "arl-refut");
    attach_runbook(&st.db.lock(), id, rb, "adm", &PrefillTargets::default()).expect("fixture : attache réelle");
    let avant = arl_traces(&st.db.lock(), id);
    assert_eq!(avant.0, 1);

    lqr_lecture_des_etapes_refusee(&st.db.lock());
    let (statut, corps) = arl_attacher(&st, id, rb).await;
    lqr_autorisateur_leve(&st.db.lock());
    assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "progression non lue : 503 : {corps}");
    assert!(corps.to_string().contains(CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE), "{corps}");
    assert_eq!(arl_traces(&st.db.lock(), id), avant, "la progression n'est pas doublée");

    let conn = st.db.lock();
    // Vue temporaire qui coiffe `incident` (colonne `id` absente : la préparation échoue) — la voie de `lqr_`.
    conn.execute_batch("CREATE TEMP VIEW incident AS SELECT 1 AS autre;").unwrap();
    let r = attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default());
    conn.execute_batch("DROP VIEW temp.incident;").unwrap();
    match r {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(c, CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE),
        autre => panic!("une existence NON LUE n'est pas « incident introuvable » : {autre:?}"),
    }
    assert_eq!(arl_traces(&conn, id), avant, "rien d'écrit");
}

// -------------------------------------------------------------------------------------
// (3) `P10.29-j` — LE `BEGIN` REFUSÉ : DIT ET COMPTÉ (corrigé ailleurs), ET SA PROPRE CAUSE (corrigée ici)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : l'écrivain porte la transaction d'un autre geste ; `attach_runbook` rend `TransactionNonOuverte` ;
/// la route rend 503 avec `CAUSE_RUNBOOK_NON_ATTACHE_TRANSACTION_NON_OUVERTE`, ni la cause des étapes non écrites ni le
/// texte du moteur ; rien d'écrit ; le `BEGIN` refusé est COMPTÉ sous le journal `runbooks` (`P10.27-h`) ; la transaction
/// étrangère fermée, l'attache passe et rien de plus n'est compté.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `arl_begin_muet` (le refus typé rendu sans `dire_la_transaction_non_ouverte`) ;
/// `arl_begin_cause_fusionnee` (le `BEGIN` refusé rendu en `EtapesNonEcrites` avec l'erreur du moteur, la forme d'avant).
#[tokio::test]
async fn arl_l_attache_dit_compte_et_nomme_un_begin_refuse() {
    let (st, _p) = sp_state("arl-begin");
    let (id, rb) = arl_dossier_et_runbook(&st.db.lock(), "arl-begin");
    let quoi = "begin refusé runbooks transaction_etrangere";
    assert_eq!(crate::comptes_de_transaction::compte_des_temoins(&st.db.lock(), quoi), 0);
    st.db.lock().execute_batch("BEGIN IMMEDIATE; INSERT INTO meta(key,value) VALUES('arl-etrangere','1');").unwrap();
    let direct = attach_runbook(&st.db.lock(), id, rb, "adm", &PrefillTargets::default());
    let (statut, corps) = arl_attacher(&st, id, rb).await;
    st.db.lock().execute_batch("ROLLBACK").unwrap();
    assert!(matches!(direct, Err(RefusDAttache::TransactionNonOuverte)), "BEGIN refusé : sa propre variante : {direct:?}");
    assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "BEGIN refusé : 503 : {corps}");
    assert_eq!(corps["error"], json!(crate::handlers::incidents::CAUSE_RUNBOOK_NON_ATTACHE_TRANSACTION_NON_OUVERTE), "la cause du BEGIN refusé, seule : {corps}");
    assert!(!corps.to_string().contains(CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES), "pas la cause des étapes non écrites : {corps}");
    assert!(!corps.to_string().contains("transaction within a transaction"), "l'erreur du moteur reste au journal : {corps}");
    assert_eq!(crate::comptes_de_transaction::compte_des_temoins(&st.db.lock(), quoi), 2, "chaque BEGIN refusé est dit et compté");
    assert_eq!(arl_traces(&st.db.lock(), id).0, 0, "aucune étape posée");
    let (statut, corps) = arl_attacher(&st, id, rb).await;
    assert_eq!(statut, StatusCode::OK, "{corps}");
    assert_eq!(crate::comptes_de_transaction::compte_des_temoins(&st.db.lock(), quoi), 2, "un BEGIN pris n'est pas compté");
}

/// CE QU'IL TIENT : le plan de contrôle porte la transaction d'un autre geste ; `scim_group_patch` rend 503 avec
/// `CAUSE_SCIM_OPERATION_DE_GROUPE_TRANSACTION_NON_OUVERTE` (pas la cause d'une opération non écrite, pas le texte du
/// moteur), aucun droit n'est posé, et le `BEGIN` refusé est COMPTÉ sous le journal `scim` (`jouer_le_geste_garde`,
/// `P10.21-r`) ; la transaction étrangère fermée, le même PATCH passe (200), le droit est posé, rien de plus n'est compté.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `arl_scim_begin_muet` (le refus rendu sans passer par la forme commune) ;
/// `arl_scim_cause_fusionnee` (`NonOuvert` refondu sous `CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE`, la forme d'avant).
#[tokio::test]
async fn arl_scim_group_patch_dit_compte_et_nomme_un_begin_refuse() {
    const T: &str = "arl-t1";
    let (cp, tmp) = mk_test_control();
    cp.conn
        .lock()
        .execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'ARL','','sans-base',?2,0)", params![T, now()])
        .expect("fixture : tenant");
    let membre = ensure_platform_user(&cp, "arl-membre").expect("fixture : utilisateur");
    let st = tenant_test_state("admins", "editors", "supers", Some(cp));
    let plan = || st.tenants.control.as_ref().expect("mode 1");
    let droits = || -> i64 { plan().conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", params![T], |r| r.get(0)).unwrap() };
    let quoi = "begin refusé scim transaction_etrangere";
    let compte = || crate::comptes_de_transaction::compte_des_temoins(&plan().conn.lock(), quoi);
    let patch = json!({ "Operations": [{ "op": "add", "value": [{ "value": membre }] }] });
    let jouer = || scim_group_patch(State(st.clone()), Extension(ScimCtx { tenant: T.into() }), Path("editor".to_string()), Json(patch.clone()));

    assert_eq!((compte(), droits()), (0, 0));
    plan().conn.lock().execute_batch("BEGIN IMMEDIATE; CREATE TABLE arl_etrangere(x);").unwrap();
    let (statut, v) = tok_resp_json(jouer().await).await;
    plan().conn.lock().execute_batch("ROLLBACK").unwrap();
    assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "BEGIN refusé : 503 : {v}");
    assert_eq!(compte(), 1, "le BEGIN refusé est dit et compté sous `scim`");
    let texte = v.to_string();
    assert!(texte.contains(crate::scim::CAUSE_SCIM_OPERATION_DE_GROUPE_TRANSACTION_NON_OUVERTE), "la cause du BEGIN refusé : {v}");
    assert!(!texte.contains(crate::scim::CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE), "pas la cause d'une opération non écrite : {v}");
    assert!(!texte.contains("transaction within a transaction"), "l'erreur du moteur reste au journal : {v}");
    assert_eq!(droits(), 0, "aucun droit posé");

    let (statut, v) = tok_resp_json(jouer().await).await;
    assert_eq!(statut, StatusCode::OK, "transaction étrangère fermée : le PATCH passe : {v}");
    assert_eq!((compte(), droits()), (1, 1), "droit posé, rien de plus compté");
    drop(tmp);
}
