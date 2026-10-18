// =====================================================================================
// `P10.20-b` (rang trois : `panneau_resolu::ElementMoinsVisible::premier`) — LES ÉLÉMENTS QUI
// RETIENDRAIENT UN PARTAGE, S'ILS N'ONT PAS PU ÊTRE LUS, NE VALENT PAS « RIEN NE RETIENT ».
//
// LE DÉFAUT RE-MESURÉ SUR `318bf0e`. `premier` lisait le COMPTE des éléments moins visibles par
// `query_row(..).unwrap_or(0)` (zéro -> `None`) et la LIGNE du premier par `query_row(..).ok()`. Les
// trois gestes de partage de `dashboards.rs` (`dash_update`, `panel_update`, `view_update`) faisaient
// `if let Some(element)` : une lecture ratée était lue « aucun élément ne retient », et l'écriture qui
// publie (`visibility='shared'`) suivait. La porte de `P11.20-m` s'ouvrait sur « non lu ».
//
// LES DEUX VOIES, UNE PAR LECTURE ABSORBÉE. La TABLE RENOMMÉE fait échouer la préparation du COMPTE
// (le `unwrap_or(0)`) ; un BLOB posé dans la colonne du NOM de l'élément (`title`, `name`) laisse le
// compte sain et fait échouer le MAPPEUR de la LIGNE (le `.ok()`). Aucun déclencheur sur SELECT.
// Chaque témoin porte, dans le même corps, le 409 qui nomme l'élément (la porte juge quand elle a lu)
// et le 204 une fois l'élément partagé (le refus n'est pas inconditionnel).
//
// LES MUTATIONS QUI LES FONT ROUGIR (`VERIF_MUT`, retirées avant le commit) : `K3_COMPTE` rétablit
// `unwrap_or(0)` sur le compte -> les blocs « table renommée » publient (204) ; `K3_LIGNE` rétablit
// `.ok()` sur la ligne -> les blocs « nom illisible » publient (204).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint de ce 503 (aucun module de `web/` ne
// le distingue) ; `panneau_resolu::courante` (`.ok()`, rang quatre) est hors de ce lot.
// =====================================================================================

fn ern_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

fn ern_texte(st: &AppState, sql: &str, id: i64) -> String {
    st.db.lock().query_row(sql, params![id], |r| r.get(0)).expect("fixture : la valeur se lit")
}

/// La phrase servie : `error` (refus JSON) ou corps texte brut (409 de `P11.20-m`).
fn ern_phrase(v: &Value) -> String {
    v.get("error").and_then(|e| e.as_str()).or_else(|| v.get("_texte").and_then(|t| t.as_str())).unwrap_or("").to_string()
}

async fn ern_dashboard(st: &AppState, au: &AuthUser, corps: Value) -> i64 {
    let (_, v) = pb_json(dash_create(State(st.clone()), Extension(au.clone()), Json(corps)).await.into_response()).await;
    v.get("id").and_then(|x| x.as_i64()).expect("dash_create rend un id")
}

async fn ern_dash_update(st: &AppState, au: &AuthUser, id: i64, corps: Value) -> (u16, Value) {
    pb_json(dash_update(State(st.clone()), Extension(au.clone()), Path(id), Json(corps)).await).await
}

async fn ern_panel_update(st: &AppState, au: &AuthUser, id: i64, corps: Value) -> (u16, Value) {
    pb_json(panel_update(State(st.clone()), Extension(au.clone()), Path(id), Json(corps)).await).await
}

async fn ern_view_update(st: &AppState, au: &AuthUser, id: i64, corps: Value) -> (u16, Value) {
    pb_json(view_update(State(st.clone()), Extension(au.clone()), Path(id), Json(corps)).await).await
}

fn ern_refus_avoue(statut: u16, v: &Value, quoi: &str) {
    assert_eq!(statut, 503, "{quoi} : lecture non faite, la route REFUSE au lieu de conclure « rien ne retient » : {v}");
    assert_eq!(v["error"], json!(panneau_resolu::CAUSE_ELEMENTS_RETENANT_NON_LUS), "{quoi} : le refus nomme SA cause : {v}");
}

// -------------------------------------------------------------------------------------
// (1) LE TABLEAU DE BORD — panneaux, puis définitions de bibliothèque qu'ils exécutent.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn p10_20b_un_tableau_de_bord_dont_les_elements_retenant_ne_sont_pas_lus_n_est_pas_publie() {
    let (st, _tmp) = sp_state("ern-tableau");
    let alice = sp_au("alice", "editor");
    let did = ern_dashboard(&st, &alice, json!({ "name": "brouillon", "visibility": "private" })).await;
    let (c, pid) = sp_panneau(&st, &alice, did, "chiffres internes", "private").await;
    assert_eq!(c, 200, "fixture : panneau privé créé");

    // LUE : la porte juge et nomme le panneau.
    let (statut, refus) = ern_dash_update(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 409, "{refus}");
    assert!(ern_phrase(&refus).contains("le panneau « chiffres internes »"), "{refus}");

    // NOM ILLISIBLE (la LIGNE du premier élément) : le compte dit 1, le mappeur échoue.
    ern_ecrire(&st, &format!("UPDATE panel SET title=x'FF' WHERE id={pid};"));
    let (statut, v) = ern_dash_update(&st, &alice, did, json!({ "name": "renommé au passage", "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "ligne du panneau illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM dashboard WHERE id=?1", did), "private", "RIEN n'est publié");
    assert_eq!(ern_texte(&st, "SELECT name FROM dashboard WHERE id=?1", did), "brouillon", "pas même le renommage");
    ern_ecrire(&st, &format!("UPDATE panel SET title='chiffres internes' WHERE id={pid};"));

    // Le panneau partagé : seule la branche « définitions de bibliothèque » reste à juger.
    let (statut, v) = ern_panel_update(&st, &alice, pid, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "fixture : le panneau sans définition se partage : {v}");

    // TABLE `library_panel` RENOMMÉE : le compte de panneaux est LU et nul, celui des définitions rate.
    ern_ecrire(&st, "ALTER TABLE library_panel RENAME TO library_panel_hors_d_atteinte;");
    let (statut, v) = ern_dash_update(&st, &alice, did, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "compte des définitions illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM dashboard WHERE id=?1", did), "private", "RIEN n'est publié");
    ern_ecrire(&st, "ALTER TABLE library_panel_hors_d_atteinte RENAME TO library_panel;");

    // TABLE `panel` RENOMMÉE : le premier compte rate, la seconde branche n'est pas consultée.
    ern_ecrire(&st, "ALTER TABLE panel RENAME TO panel_hors_d_atteinte;");
    let (statut, v) = ern_dash_update(&st, &alice, did, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "compte des panneaux illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM dashboard WHERE id=?1", did), "private", "RIEN n'est publié");
    ern_ecrire(&st, "ALTER TABLE panel_hors_d_atteinte RENAME TO panel;");

    // LUE ET NULLE : le geste passe (le refus n'est pas inconditionnel).
    let (statut, v) = ern_dash_update(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "{v}");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM dashboard WHERE id=?1", did), "shared");
}

// -------------------------------------------------------------------------------------
// (2) LE PANNEAU — la définition de bibliothèque qu'il exécute.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn p10_20b_un_panneau_dont_la_definition_retenant_n_est_pas_lue_n_est_pas_publie() {
    let (st, _tmp) = sp_state("ern-panneau");
    let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
    let (c, lib) = pb_lib(
        &st,
        &bob,
        json!({ "name": "revue de bob", "title": "revue", "query": "search source=web | table message", "is_soql": true, "viz": "table", "visibility": "shared" }),
    )
    .await;
    assert_eq!(c, 200, "fixture : bob publie sa définition");
    let did = ern_dashboard(&st, &alice, json!({ "name": "veille", "visibility": "private" })).await;
    let (_, pid) = sp_panneau(&st, &alice, did, "exécute la revue", "private").await;
    let (_, nu) = sp_panneau(&st, &alice, did, "sans définition", "private").await;
    let (statut, v) = ern_panel_update(&st, &alice, pid, json!({ "library_panel_id": lib })).await;
    assert_eq!(statut, 204, "fixture : rattachement licite tant que la définition est commune : {v}");
    assert_eq!(library_panel_update(State(st.clone()), Extension(bob.clone()), Path(lib), Json(json!({ "visibility": "private" }))).await.status().as_u16(), 204);

    // LUE : la porte juge et nomme la définition AVEC son propriétaire.
    let (statut, refus) = ern_panel_update(&st, &alice, pid, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 409, "{refus}");
    let phrase = ern_phrase(&refus);
    assert!(phrase.contains("« revue de bob »") && phrase.contains("à bob"), "{phrase}");

    // NOM ILLISIBLE : le compte dit 1, le mappeur échoue ; la suite de `panel_update` (résolution de
    // la définition exécutée) ne lit pas `name` et laisserait passer l'écriture.
    ern_ecrire(&st, &format!("UPDATE library_panel SET name=x'FF' WHERE id={lib};"));
    let (statut, v) = ern_panel_update(&st, &alice, pid, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "ligne de la définition illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM panel WHERE id=?1", pid), "private", "RIEN n'est publié");
    ern_ecrire(&st, &format!("UPDATE library_panel SET name='revue de bob' WHERE id={lib};"));

    // TABLE `library_panel` RENOMMÉE : le compte rate. Sur le panneau SANS définition, rien d'autre ne
    // lit cette table : sans le refus, la lecture ratée publiait.
    ern_ecrire(&st, "ALTER TABLE library_panel RENAME TO library_panel_hors_d_atteinte;");
    let (statut, v) = ern_panel_update(&st, &alice, nu, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "compte de la définition illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM panel WHERE id=?1", nu), "private", "RIEN n'est publié");
    let (statut, v) = ern_panel_update(&st, &alice, pid, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "compte de la définition illisible (panneau rattaché)");
    ern_ecrire(&st, "ALTER TABLE library_panel_hors_d_atteinte RENAME TO library_panel;");

    // LUE ET NULLE : les deux gestes passent.
    let (statut, v) = ern_panel_update(&st, &alice, nu, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "{v}");
    assert_eq!(library_panel_update(State(st.clone()), Extension(bob.clone()), Path(lib), Json(json!({ "visibility": "shared" }))).await.status().as_u16(), 204);
    let (statut, v) = ern_panel_update(&st, &alice, pid, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "{v}");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM panel WHERE id=?1", pid), "shared");
}

// -------------------------------------------------------------------------------------
// (3) LA VUE — les tableaux de bord qui y sont rangés.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn p10_20b_une_vue_dont_les_tableaux_retenant_ne_sont_pas_lus_n_est_pas_publiee() {
    let (st, _tmp) = sp_state("ern-vue");
    let alice = sp_au("alice", "editor");
    let (c, v) = pb_json(
        view_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "ma vue", "visibility": "private" }))).await.into_response(),
    )
    .await;
    assert_eq!(c, 200, "{v}");
    let vid = v["id"].as_i64().expect("view_create rend un id");
    let did = ern_dashboard(&st, &alice, json!({ "name": "tableau privé", "visibility": "private", "view_id": vid })).await;

    // LUE : la porte juge et nomme le tableau de bord.
    let (statut, refus) = ern_view_update(&st, &alice, vid, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 409, "{refus}");
    assert!(ern_phrase(&refus).contains("le tableau de bord « tableau privé »"), "{refus}");

    // NOM ILLISIBLE : le compte dit 1, le mappeur échoue.
    ern_ecrire(&st, &format!("UPDATE dashboard SET name=x'FF' WHERE id={did};"));
    let (statut, v) = ern_view_update(&st, &alice, vid, json!({ "name": "renommée au passage", "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "ligne du tableau de bord illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM view WHERE id=?1", vid), "private", "RIEN n'est publié");
    assert_eq!(ern_texte(&st, "SELECT name FROM view WHERE id=?1", vid), "ma vue", "pas même le renommage");
    ern_ecrire(&st, &format!("UPDATE dashboard SET name='tableau privé' WHERE id={did};"));

    // TABLE `dashboard` RENOMMÉE : la vue se lit, le compte des tableaux rate.
    ern_ecrire(&st, "ALTER TABLE dashboard RENAME TO dashboard_hors_d_atteinte;");
    let (statut, v) = ern_view_update(&st, &alice, vid, json!({ "visibility": "shared" })).await;
    ern_refus_avoue(statut, &v, "compte des tableaux de bord illisible");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM view WHERE id=?1", vid), "private", "RIEN n'est publié");
    ern_ecrire(&st, "ALTER TABLE dashboard_hors_d_atteinte RENAME TO dashboard;");

    // LUE ET NULLE : le tableau partagé, le geste passe.
    let (statut, v) = ern_dash_update(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "{v}");
    let (statut, v) = ern_view_update(&st, &alice, vid, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "{v}");
    assert_eq!(ern_texte(&st, "SELECT visibility FROM view WHERE id=?1", vid), "shared");
}
