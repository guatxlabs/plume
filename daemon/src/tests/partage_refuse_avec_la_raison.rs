// =====================================================================================
// `P11.20-m` — LE PARTAGE D'UN OBJET COMPOSÉ EST REFUSÉ, AVEC LA RAISON, TANT QU'UN ÉLÉMENT EST
// MOINS VISIBLE. Décision de l'exploitant du 2026-09-10 : ni retrait silencieux, ni avertissement de
// console — le démon refuse et NOMME l'élément (et son propriétaire quand ce n'est pas l'auteur).
// Trois arêtes (vue → tableau de bord, tableau de bord → panneau, panneau → définition de
// bibliothèque), un témoin par arête avec son CONTRÔLE POSITIF (le même geste passe une fois
// l'élément partagé), et un quatrième pour la valeur hors vocabulaire, retenue fail-closed.
// =====================================================================================

async fn pr_texte(r: Response) -> (u16, String) {
    let (code, v) = pb_json(r).await;
    (code, v.get("_texte").and_then(|t| t.as_str()).unwrap_or("").to_string())
}

fn pr_visibilite(st: &AppState, table: &str, id: i64) -> String {
    st.db
        .lock()
        .query_row(&format!("SELECT COALESCE(visibility,'') FROM {table} WHERE id=?1"), params![id], |r| r.get(0))
        .unwrap()
}

async fn pr_dashboard(st: &AppState, au: &AuthUser, corps: Value) -> i64 {
    let (_, v) = pb_json(dash_create(State(st.clone()), Extension(au.clone()), Json(corps)).await.into_response()).await;
    v.get("id").and_then(|x| x.as_i64()).expect("dash_create rend un id")
}

async fn pr_partager_le_tableau(st: &AppState, au: &AuthUser, did: i64) -> Response {
    dash_update(State(st.clone()), Extension(au.clone()), Path(did), Json(json!({ "visibility": "shared" }))).await
}

async fn pr_panneau(st: &AppState, au: &AuthUser, pid: i64, corps: Value) -> u16 {
    panel_update(State(st.clone()), Extension(au.clone()), Path(pid), Json(corps)).await.status().as_u16()
}

async fn pr_definition(st: &AppState, au: &AuthUser, lib: i64, visibilite: &str) -> u16 {
    library_panel_update(State(st.clone()), Extension(au.clone()), Path(lib), Json(json!({ "visibility": visibilite }))).await.as_u16()
}

#[tokio::test]
async fn le_partage_d_un_tableau_de_bord_est_refuse_tant_qu_un_panneau_est_prive_et_le_refus_nomme_le_panneau() {
    let (st, _tmp) = sp_state("partage-tableau");
    let alice = sp_au("alice", "editor");
    let did = pr_dashboard(&st, &alice, json!({ "name": "brouillon", "visibility": "private" })).await;
    let (c, secret) = sp_panneau(&st, &alice, did, "chiffres internes", "private").await;
    assert_eq!(c, 200);
    let (c, second) = sp_panneau(&st, &alice, did, "second secret", "private").await;
    assert_eq!(c, 200);
    let (c, _commun) = sp_panneau(&st, &alice, did, "pour tous", "shared").await;
    assert_eq!(c, 200);

    let (code, texte) = pr_texte(
        dash_update(State(st.clone()), Extension(alice.clone()), Path(did), Json(json!({ "name": "renommé au passage", "visibility": "shared" }))).await,
    )
    .await;
    assert_eq!(code, 409, "le geste est refusé : {texte}");
    assert!(
        texte.contains("le panneau « chiffres internes »") && texte.contains(&format!("n° {secret}")),
        "le refus nomme l'élément : {texte}"
    );
    assert!(texte.contains("1 autre(s)"), "et compte les autres éléments qui retiennent : {texte}");
    assert_eq!(pr_visibilite(&st, "dashboard", did), "private", "rien n'a bougé");
    let nom: String = st.db.lock().query_row("SELECT name FROM dashboard WHERE id=?1", params![did], |r| r.get(0)).unwrap();
    assert_eq!(nom, "brouillon", "un refus n'applique RIEN du corps, pas même le renommage");

    // CONTRÔLE POSITIF : les deux panneaux partagés, le même geste passe.
    for pid in [secret, second] {
        assert_eq!(pr_panneau(&st, &alice, pid, json!({ "visibility": "shared" })).await, 204);
    }
    assert_eq!(pr_partager_le_tableau(&st, &alice, did).await.status().as_u16(), 204);
    assert_eq!(pr_visibilite(&st, "dashboard", did), "shared");

    // UN RENVOI IDEMPOTENT N'EST PAS UN GESTE : rendre un panneau privé APRÈS le partage reste permis
    // (réduction de visibilité, servi au seul propriétaire depuis `P11.20-n`), et la fiche qui renvoie
    // `shared` sur un tableau déjà commun n'est pas jugée.
    assert_eq!(pr_panneau(&st, &alice, secret, json!({ "visibility": "private" })).await, 204);
    assert_eq!(
        dash_update(State(st.clone()), Extension(alice.clone()), Path(did), Json(json!({ "name": "édité", "visibility": "shared" }))).await.status().as_u16(),
        204
    );
    assert_eq!(pr_visibilite(&st, "panel", secret), "private");
}

#[tokio::test]
async fn le_partage_d_une_vue_est_refuse_tant_qu_un_tableau_de_bord_prive_y_est_range_et_le_refus_le_nomme() {
    let (st, _tmp) = sp_state("partage-vue");
    let alice = sp_au("alice", "editor");
    let (_, v) = pb_json(
        view_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "ma vue", "visibility": "private" }))).await.into_response(),
    )
    .await;
    let vid = v["id"].as_i64().expect("view_create rend un id");
    let did = pr_dashboard(&st, &alice, json!({ "name": "en cours", "visibility": "private", "view_id": vid })).await;
    let range: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM dashboard WHERE view_id=?1", params![vid], |r| r.get(0)).unwrap();
    assert_eq!(range, 1, "fixture : le tableau est bien rangé dans la vue");

    let (code, texte) = pr_texte(
        view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "visibility": "shared" }))).await,
    )
    .await;
    assert_eq!(code, 409, "{texte}");
    assert!(texte.contains("le tableau de bord « en cours »") && texte.contains(", à alice)"), "{texte}");
    assert_eq!(pr_visibilite(&st, "view", vid), "private");

    // CONTRÔLE POSITIF
    assert_eq!(pr_partager_le_tableau(&st, &alice, did).await.status().as_u16(), 204);
    assert_eq!(
        view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "visibility": "shared" }))).await.status().as_u16(),
        204
    );
    assert_eq!(pr_visibilite(&st, "view", vid), "shared");
}

#[tokio::test]
async fn le_partage_est_refuse_quand_un_panneau_execute_la_definition_privee_d_autrui_et_le_refus_nomme_son_proprietaire() {
    let (st, _tmp) = sp_state("partage-definition");
    let alice = sp_au("alice", "editor");
    let bob = sp_au("bob", "editor");
    // bob publie une définition, alice l'exécute (rattachement licite : elle est commune, `P7.13-a`),
    // puis bob la reprend en privé — c'est le cas de la famille : un élément qui n'est pas à l'auteur.
    let (c, lib) = pb_lib(
        &st,
        &bob,
        json!({ "name": "revue de bob", "title": "revue", "query": "search source=web | table message", "is_soql": true, "viz": "table", "visibility": "shared" }),
    )
    .await;
    assert_eq!(c, 200);
    let did = pr_dashboard(&st, &alice, json!({ "name": "veille", "visibility": "private" })).await;
    let (_, pid) = sp_panneau(&st, &alice, did, "exécute la revue", "private").await;
    assert_eq!(pr_panneau(&st, &alice, pid, json!({ "library_panel_id": lib })).await, 204);
    assert_eq!(pr_definition(&st, &bob, lib, "private").await, 204);

    // (a) partager le PANNEAU : refusé, la définition est nommée avec son propriétaire.
    let (code, texte) = pr_texte(panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "visibility": "shared" }))).await).await;
    assert_eq!(code, 409, "{texte}");
    assert!(texte.contains("la définition de bibliothèque « revue de bob »") && texte.contains(", à bob)"), "{texte}");
    assert_eq!(pr_visibilite(&st, "panel", pid), "private");

    // (b) partager le TABLEAU : sur un second tableau dont le panneau est commun, c'est la définition
    //     qui retient (le rattachement se fait pendant qu'elle est commune, bob la reprend ensuite).
    let did2 = pr_dashboard(&st, &alice, json!({ "name": "veille 2", "visibility": "private" })).await;
    let (_, pid2) = sp_panneau(&st, &alice, did2, "commun, exécute la revue", "shared").await;
    assert_eq!(pr_definition(&st, &bob, lib, "shared").await, 204);
    assert_eq!(pr_panneau(&st, &alice, pid2, json!({ "library_panel_id": lib })).await, 204);
    assert_eq!(pr_definition(&st, &bob, lib, "private").await, 204);
    let (code, texte) = pr_texte(pr_partager_le_tableau(&st, &alice, did2).await).await;
    assert_eq!(code, 409, "{texte}");
    assert!(texte.contains("la définition de bibliothèque « revue de bob »") && texte.contains(", à bob)"), "{texte}");

    // CONTRÔLE POSITIF : bob partage sa définition, le tableau et le panneau d'alice se partagent.
    assert_eq!(pr_definition(&st, &bob, lib, "shared").await, 204);
    assert_eq!(pr_partager_le_tableau(&st, &alice, did2).await.status().as_u16(), 204);
    assert_eq!(pr_panneau(&st, &alice, pid, json!({ "visibility": "shared" })).await, 204);
}

#[tokio::test]
async fn une_visibilite_hors_vocabulaire_retient_comme_la_moins_visible() {
    // FAIL-CLOSED : la colonne est sans contrainte au schéma ; une valeur ni `shared` ni `private`
    // retient le partage au lieu de passer pour commune.
    let (st, _tmp) = sp_state("partage-hors-vocabulaire");
    let alice = sp_au("alice", "editor");
    let did = pr_dashboard(&st, &alice, json!({ "name": "x", "visibility": "private" })).await;
    let (_, pid) = sp_panneau(&st, &alice, did, "étrange", "shared").await;
    st.db.lock().execute("UPDATE panel SET visibility='pending' WHERE id=?1", params![pid]).unwrap();
    let (code, texte) = pr_texte(pr_partager_le_tableau(&st, &alice, did).await).await;
    assert_eq!(code, 409, "{texte}");
    assert!(texte.contains("le panneau « étrange »"), "{texte}");
}
