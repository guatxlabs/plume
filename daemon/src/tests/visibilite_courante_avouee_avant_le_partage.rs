// =====================================================================================
// `P10.20-k` — LA VISIBILITÉ COURANTE QU'ON N'A PAS PU LIRE NE SE DEVINE PAS, ET LE REFUS PORTE SA
// PHRASE.
//
// LE DÉFAUT MESURÉ LE 2026-09-16, par la garde de forme de `P10.20-b` (rang un, invisible au geste
// `ok`). `dash_update` et `panel_update` lisaient la visibilité COURANTE de l'objet par
// `.unwrap_or_else(|_| "shared".into())`. `panneau_resolu::est_un_geste_de_partage` ne rend `true` que
// si cette visibilité courante N'EST PAS déjà `shared` : une lecture ratée déclarait donc l'objet DÉJÀ
// PARTAGÉ, le geste cessait d'être un partage, la porte de `P11.20-m` — celle qui REFUSE de publier un
// contenant portant un élément moins visible, décision de produit de l'exploitant du 2026-09-10 —
// n'était jamais interrogée, et l'écriture qui publie suivait. Le repli n'était pas prudent : il était
// exactement du côté ouvert.
//
// CE QUI ÉTAIT DÉJÀ BON, ET CE QUI NE L'ÉTAIT PAS. `view_update`, dans le même fichier, retombait sur
// `"private"` : la porte JOUAIT, et c'est ce site qui a servi de contrôle positif à la mesure. Il est
// pourtant rallié ici à la même forme, parce que son refus était alors un 409 NOMMANT un élément moins
// visible — une cause FAUSSE pour une lecture qui n'a pas eu lieu, qui envoie l'appelant partager un
// élément quand il doit réessayer. Une cause fausse n'est pas un fait.
//
// LA FORME DU CORRECTIF EST CELLE DU DÉPÔT. La visibilité se lit avec l'EXISTENCE de la ligne, en un
// seul énoncé, rendu en `Result<Option<_>>` (`rusqlite::OptionalExtension::optional`) : `Ok(None)` est
// une absence ÉTABLIE (404), `Err(..)` est une lecture NON FAITE et refuse par un 503 nommé
// (`panneau_resolu::CAUSE_VISIBILITE_NON_LUE`) AVANT tout jugement de partage et avant toute écriture.
// 503 et non 403 ni 404 : ce n'est ni un droit ni une absence, et un refus réessayable ne s'apprend pas
// comme une interdiction permanente.
//
// LES DEUX VOIES JOUÉES, ET POURQUOI DEUX. La TABLE RETIRÉE (renommée sous les pieds du gestionnaire)
// fait échouer la PRÉPARATION ; la LIGNE ILLISIBLE (un `BLOB` posé dans la colonne `visibility`, que
// SQLite conserve tel quel quelle que soit l'affinité) fait échouer le MAPPEUR, la requête restant
// saine — c'est la voie la plus proche des causes de terrain (cache de schéma de pool périmé, colonne
// migrée, valeur corrompue) et celle qu'aucune garde de forme ne verrait. Chaque témoin porte son
// CONTRÔLE POSITIF dans le même corps : sans lui, un refus INCONDITIONNEL passerait pour un refus fondé.
//
// LE QUATRIÈME TÉMOIN NE JUGE PAS UNE LECTURE mais un ÉCART DE FORME nommé sous `P10.20-b` :
// `panel_update` rendait le CODE SEUL là où `panel_create` rend la phrase du refus — et le message de
// `DefinitionExecutee::projetee` (dont le 503 « définition de bibliothèque NON LUE » de `P10.20-b`
// lui-même) était jeté par un `Err((code, _))`. La console peignait « 403 » nu.
//
// CE QUE CE LOT NE TIENT PAS : aucun de ces témoins ne juge ce que la CONSOLE peint du 503
// (`web/dashboards.js` et `web/views.js` affichent le message d'`apiSend`, qui porte désormais un corps
// mais n'a pas de nœud dédié) ; et `dash_editable`, appelé juste après, garde un `Err(_) => false` qui
// rend 403 sur une lecture ratée du tableau de bord — hors de cette clé, famille `P10.20-l`.
// =====================================================================================

/// Statut + corps (JSON, ou `{_texte}` quand le corps est du texte brut comme le 409 de `P11.20-m`).
async fn vca_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
}

/// La phrase servie, d'où qu'elle vienne : `error` (refus JSON du démon) ou corps texte brut.
fn vca_phrase(v: &Value) -> String {
    v.get("error")
        .and_then(|e| e.as_str())
        .or_else(|| v.get("_texte").and_then(|t| t.as_str()))
        .unwrap_or("")
        .to_string()
}

fn vca_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// Retire une table sous les pieds du gestionnaire sans toucher au code servi : renommée, elle n'est
/// plus sous le nom que le SQL servi attend (un renommage ne viole aucune clé étrangère).
fn vca_retirer_la_table(st: &AppState, table: &str) {
    vca_ecrire(st, &format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"));
}

/// Le TYPE SQLite de la colonne de visibilité — lisible même quand elle porte un blob, donc utilisable
/// APRÈS le geste refusé pour prouver que RIEN n'a été écrit (un `UPDATE ... SET visibility='shared'`
/// la ferait repasser en `text`).
fn vca_type_de_visibilite(st: &AppState, table: &str, id: i64) -> String {
    st.db
        .lock()
        .query_row(&format!("SELECT typeof(visibility) FROM {table} WHERE id=?1"), params![id], |r| r.get(0))
        .expect("fixture : la ligne existe et son type se lit")
}

fn vca_texte(st: &AppState, sql: &str, id: i64) -> String {
    st.db.lock().query_row(sql, params![id], |r| r.get(0)).expect("fixture : la valeur se lit")
}

async fn vca_dashboard(st: &AppState, au: &AuthUser, corps: Value) -> i64 {
    let (_, v) = vca_corps(dash_create(State(st.clone()), Extension(au.clone()), Json(corps)).await.into_response()).await;
    v.get("id").and_then(|x| x.as_i64()).expect("dash_create rend un id")
}

async fn vca_partager(st: &AppState, au: &AuthUser, did: i64, corps: Value) -> (u16, Value) {
    vca_corps(dash_update(State(st.clone()), Extension(au.clone()), Path(did), Json(corps)).await).await
}

// -------------------------------------------------------------------------------------
// (1) LE TABLEAU DE BORD — le site où le repli ouvrait la porte.
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur un tableau de bord dont la visibilité courante a été LUE, la porte de
/// `P11.20-m` joue (409 qui nomme le panneau privé) et le geste passe une fois le panneau partagé
/// (contrôle positif compté deux fois dans le corps) ; sur une ligne illisible et sur une table
/// retirée, `dash_update` REFUSE par un 503 nommé — et rien du corps n'est appliqué, pas même le
/// renommage envoyé dans la même requête.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint de ce 503, et il ne dit rien de
/// `dash_editable`, dont le `Err(_) => false` rend un 403 sur la même panne (famille `P10.20-l`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.unwrap_or_else(|_| "shared".into())` — la route
/// redevient 204, le tableau de bord PORTANT UN PANNEAU PRIVÉ est publié, et les deux derniers blocs
/// tombent (le premier sur le statut, le second sur le type de la colonne repassé en `text`).
#[tokio::test]
async fn p10_20k_un_tableau_de_bord_dont_la_visibilite_n_est_pas_lue_n_est_pas_publie() {
    let (st, _tmp) = sp_state("vca-tableau");
    let alice = sp_au("alice", "editor");
    let did = vca_dashboard(&st, &alice, json!({ "name": "brouillon", "visibility": "private" })).await;
    let (c, secret) = sp_panneau(&st, &alice, did, "chiffres internes", "private").await;
    assert_eq!(c, 200, "fixture : le panneau privé est créé");

    // CONTRÔLE POSITIF (1/2) — la visibilité courante est LUE, la porte de `P11.20-m` joue.
    let (statut, refus) = vca_partager(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 409, "la porte de `P11.20-m` juge : {refus}");
    assert!(vca_phrase(&refus).contains("le panneau « chiffres internes »"), "et elle nomme l'élément : {refus}");

    // CONTRÔLE POSITIF (2/2) — le panneau partagé, le même geste PASSE : le refus n'est pas inconditionnel.
    assert_eq!(
        panel_update(State(st.clone()), Extension(alice.clone()), Path(secret), Json(json!({ "visibility": "shared" }))).await.status().as_u16(),
        204
    );
    let (statut, _) = vca_partager(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 204, "le geste passe une fois l'élément partagé");

    // LA LIGNE ILLISIBLE — un second tableau, privé, portant un panneau privé : `visibility` porte un
    // BLOB que `get::<String>` refuse. La requête reste saine, seul le MAPPEUR échoue.
    let did2 = vca_dashboard(&st, &alice, json!({ "name": "brouillon 2", "visibility": "private" })).await;
    let (c, _) = sp_panneau(&st, &alice, did2, "second secret", "private").await;
    assert_eq!(c, 200);
    vca_ecrire(&st, &format!("UPDATE dashboard SET visibility=x'FF' WHERE id={did2};"));
    let (statut, avoue) =
        vca_partager(&st, &alice, did2, json!({ "name": "renommé au passage", "visibility": "shared" })).await;
    assert_eq!(statut, 503, "lecture non faite : la route REFUSE au lieu de conclure « déjà partagé » : {avoue}");
    assert_eq!(avoue["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "le refus NOMME sa cause : {avoue}");
    assert_eq!(
        vca_type_de_visibilite(&st, "dashboard", did2),
        "blob",
        "RIEN n'a été écrit : la colonne porte toujours le blob, elle n'est pas repassée à `shared`"
    );
    assert_eq!(
        vca_texte(&st, "SELECT name FROM dashboard WHERE id=?1", did2),
        "brouillon 2",
        "et pas même le renommage envoyé dans la même requête"
    );

    // LA TABLE RETIRÉE — la PRÉPARATION échoue, même refus nommé.
    vca_retirer_la_table(&st, "dashboard");
    let (statut, sans_table) = vca_partager(&st, &alice, did, json!({ "visibility": "shared" })).await;
    assert_eq!(statut, 503, "table hors d'atteinte : même refus : {sans_table}");
    assert_eq!(sans_table["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "{sans_table}");
}

// -------------------------------------------------------------------------------------
// (2) LE PANNEAU — même forme, même porte, sur la définition de bibliothèque qu'il exécute.
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : la définition de bibliothèque PRIVÉE d'autrui retient le partage du panneau (409
/// qui la nomme AVEC son propriétaire, contrôle positif compté : bob la partage, le geste passe) ; sur
/// une ligne illisible et sur une table retirée, `panel_update` refuse par le 503 nommé, et le panneau
/// reste privé.
///
/// CE QU'IL NE TIENT PAS : la voie de la table retirée y fait tomber la lecture de l'ÉTAT COURANT du
/// panneau (dashboard, requête, référence), pas seulement celle de la visibilité — c'est le même
/// énoncé depuis ce lot, et c'est DIT ici plutôt que caché.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.unwrap_or_else(|_| "shared".into())` pour la
/// visibilité du panneau — la route redevient 204 et publie un panneau qui exécute la définition
/// privée de bob.
#[tokio::test]
async fn p10_20k_un_panneau_dont_la_visibilite_n_est_pas_lue_n_est_pas_publie() {
    let (st, _tmp) = sp_state("vca-panneau");
    let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
    let (c, lib) = pb_lib(
        &st,
        &bob,
        json!({ "name": "revue de bob", "title": "revue", "query": "search source=web | table message", "is_soql": true, "viz": "table", "visibility": "shared" }),
    )
    .await;
    assert_eq!(c, 200, "fixture : bob publie sa définition");
    let did = vca_dashboard(&st, &alice, json!({ "name": "veille", "visibility": "private" })).await;
    let (_, pid) = sp_panneau(&st, &alice, did, "exécute la revue", "private").await;
    assert_eq!(
        panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await.status().as_u16(),
        204,
        "fixture : le rattachement est licite tant que la définition est commune"
    );
    assert_eq!(library_panel_update(State(st.clone()), Extension(bob.clone()), Path(lib), Json(json!({ "visibility": "private" }))).await.as_u16(), 204);

    // CONTRÔLE POSITIF (1/2) — la visibilité courante est LUE, la porte juge et nomme le propriétaire.
    let (statut, refus) =
        vca_corps(panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "visibility": "shared" }))).await).await;
    assert_eq!(statut, 409, "{refus}");
    let phrase = vca_phrase(&refus);
    assert!(phrase.contains("la définition de bibliothèque « revue de bob »") && phrase.contains(", à bob)"), "{refus}");

    // LA LIGNE ILLISIBLE — la visibilité du panneau porte un blob.
    vca_ecrire(&st, &format!("UPDATE panel SET visibility=x'FF' WHERE id={pid};"));
    let (statut, avoue) = vca_corps(
        panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "title": "renommé au passage", "visibility": "shared" }))).await,
    )
    .await;
    assert_eq!(statut, 503, "lecture non faite : la route REFUSE au lieu de conclure « déjà partagé » : {avoue}");
    assert_eq!(avoue["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "{avoue}");
    assert_eq!(vca_type_de_visibilite(&st, "panel", pid), "blob", "RIEN n'a été écrit");
    assert_eq!(
        vca_texte(&st, "SELECT title FROM panel WHERE id=?1", pid),
        "exécute la revue",
        "et pas même le renommage envoyé dans la même requête"
    );

    // CONTRÔLE POSITIF (2/2) — la visibilité redevient lisible et bob partage sa définition : le geste passe.
    vca_ecrire(&st, &format!("UPDATE panel SET visibility='private' WHERE id={pid};"));
    assert_eq!(library_panel_update(State(st.clone()), Extension(bob.clone()), Path(lib), Json(json!({ "visibility": "shared" }))).await.as_u16(), 204);
    assert_eq!(
        panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "visibility": "shared" }))).await.status().as_u16(),
        204
    );

    // LA TABLE RETIRÉE — la PRÉPARATION échoue, même refus nommé.
    vca_retirer_la_table(&st, "panel");
    let (statut, sans_table) =
        vca_corps(panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "visibility": "shared" }))).await).await;
    assert_eq!(statut, 503, "table hors d'atteinte : même refus, jamais le 404 d'une absence : {sans_table}");
    assert_eq!(sans_table["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "{sans_table}");
}

// -------------------------------------------------------------------------------------
// (3) LA VUE — le contrôle positif de la mesure, rallié à la même forme.
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : le repli `"private"` de `view_update` ne publiait rien, et le témoin le CONSTATE
/// (contrôle positif : 409 qui nomme le tableau de bord privé rangé dans la vue, puis 204 une fois le
/// tableau partagé) ; mais sur une lecture non faite la route ne rend plus ce 409 — qui accuserait un
/// élément à tort — et rend le 503 nommé, comme ses deux voisins.
///
/// CE QU'IL NE TIENT PAS : il ne prouve aucune fuite, parce qu'il n'y en avait pas ici ; il juge la
/// CAUSE SERVIE, pas une porte enjambée.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.unwrap_or_else(|_| "private".into())` — le statut
/// redevient 409 et le bloc de la ligne illisible tombe sur le statut comme sur la cause.
#[tokio::test]
async fn p10_20k_une_vue_dont_la_visibilite_n_est_pas_lue_refuse_sans_accuser_un_element() {
    let (st, _tmp) = sp_state("vca-vue");
    let alice = sp_au("alice", "editor");
    let (_, v) = vca_corps(
        view_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "ma vue", "visibility": "private" }))).await.into_response(),
    )
    .await;
    let vid = v["id"].as_i64().expect("view_create rend un id");
    let did = vca_dashboard(&st, &alice, json!({ "name": "en cours", "visibility": "private", "view_id": vid })).await;

    // CONTRÔLE POSITIF (1/2) — la porte joue et nomme le tableau de bord.
    let (statut, refus) =
        vca_corps(view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "visibility": "shared" }))).await).await;
    assert_eq!(statut, 409, "{refus}");
    assert!(vca_phrase(&refus).contains("le tableau de bord « en cours »"), "{refus}");

    // LA LIGNE ILLISIBLE — la cause servie change de NATURE : ce n'est plus « un élément te retient »
    // (409), c'est « je n'ai pas lu » (503). Le geste demandé à l'appelant n'est pas le même.
    vca_ecrire(&st, &format!("UPDATE view SET visibility=x'FF' WHERE id={vid};"));
    let (statut, avoue) = vca_corps(
        view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "name": "renommée au passage", "visibility": "shared" }))).await,
    )
    .await;
    assert_eq!(statut, 503, "une lecture non faite n'accuse plus un élément : {avoue}");
    assert_eq!(avoue["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "{avoue}");
    assert!(!vca_phrase(&avoue).contains("le tableau de bord"), "et la phrase n'accuse aucun élément : {avoue}");
    assert_eq!(vca_type_de_visibilite(&st, "view", vid), "blob", "RIEN n'a été écrit");
    assert_eq!(vca_texte(&st, "SELECT name FROM view WHERE id=?1", vid), "ma vue", "pas même le renommage");

    // CONTRÔLE POSITIF (2/2) — la visibilité redevient lisible, le tableau est partagé, le geste passe.
    vca_ecrire(&st, &format!("UPDATE view SET visibility='private' WHERE id={vid};"));
    assert_eq!(
        dash_update(State(st.clone()), Extension(alice.clone()), Path(did), Json(json!({ "visibility": "shared" }))).await.status().as_u16(),
        204
    );
    assert_eq!(
        view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "visibility": "shared" }))).await.status().as_u16(),
        204
    );

    // LA TABLE RETIRÉE — la PRÉPARATION échoue, même refus nommé.
    vca_retirer_la_table(&st, "view");
    let (statut, sans_table) =
        vca_corps(view_update(State(st.clone()), Extension(alice.clone()), Path(vid), Json(json!({ "visibility": "shared" }))).await).await;
    assert_eq!(statut, 503, "{sans_table}");
    assert_eq!(sans_table["error"], json!(panneau_resolu::CAUSE_VISIBILITE_NON_LUE), "{sans_table}");
}

// -------------------------------------------------------------------------------------
// (4) L'ÉCART DE FORME — `panel_update` rendait le CODE SEUL.
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : les QUATRE refus de `panel_update` portent désormais une phrase dans leur corps,
/// comme ceux de `panel_create` — le 404 d'un panneau absent, les deux 403 (tableau non modifiable, SQL
/// brut réservé à l'administrateur) et, le plus coûteux, le 503 de `DefinitionExecutee::projetee`, dont
/// le message était JETÉ par un `Err((code, _))` : c'est la cause de `P10.20-b` qui n'atteignait pas
/// l'appelant. Contrôle positif compté dans le même corps : un update légitime rend 204.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas le rendu console (`web/dashboards.js` affiche le message
/// d'`apiSend`, qui montrera ces phrases sans nœud dédié), et il ne dit rien du CODE de ces refus —
/// seulement qu'ils ne sont plus muets.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `Err((code, _)) => return code.into_response()` — le
/// corps du 503 redevient vide et le dernier bloc tombe.
#[tokio::test]
async fn p10_20k_les_refus_de_panel_update_portent_leur_phrase() {
    let (st, _tmp) = sp_state("vca-forme");
    let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
    let did = vca_dashboard(&st, &alice, json!({ "name": "à alice", "visibility": "private" })).await;
    let (_, pid) = sp_panneau(&st, &alice, did, "le panneau", "private").await;

    // CONTRÔLE POSITIF — un update légitime passe, et ne porte aucune phrase.
    let (statut, _) = vca_corps(panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "title": "renommé" }))).await).await;
    assert_eq!(statut, 204, "le chemin nominal est intact");

    // (a) LE PANNEAU ABSENT — 404, et il DIT ce qui est introuvable.
    let (statut, absent) = vca_corps(panel_update(State(st.clone()), Extension(adm.clone()), Path(999_999), Json(json!({ "title": "x" }))).await).await;
    assert_eq!(statut, 404);
    assert!(vca_phrase(&absent).contains("panneau introuvable"), "le 404 n'est plus muet : {absent}");

    // (b) LE TABLEAU NON MODIFIABLE — 403 avec le motif, la MÊME phrase que `panel_create`.
    let (statut, interdit) = vca_corps(panel_update(State(st.clone()), Extension(bob.clone()), Path(pid), Json(json!({ "title": "x" }))).await).await;
    assert_eq!(statut, 403);
    assert!(vca_phrase(&interdit).contains("dashboard non modifiable"), "le 403 n'est plus muet : {interdit}");

    // (c) LE SQL BRUT RÉSERVÉ À L'ADMINISTRATEUR — 403 avec le geste de rechange (« utilisez GXQL »).
    let (statut, brut) = vca_corps(
        panel_update(State(st.clone()), Extension(alice.clone()), Path(pid), Json(json!({ "is_soql": false, "query": "SELECT name,role FROM user" }))).await,
    )
    .await;
    assert_eq!(statut, 403);
    assert!(vca_phrase(&brut).contains("SQL brut réservé à l'administrateur"), "le 403 dit quoi faire : {brut}");

    // (d) LA DÉFINITION DE BIBLIOTHÈQUE NON LUE — 503 dont la phrase est celle de `P10.20-b`, et qui
    //     n'atteignait PAS l'appelant : elle était jetée avec le second membre du couple d'erreur.
    let (c, lib) = pb_lib(
        &st,
        &adm,
        json!({ "name": "revue admin", "title": "revue", "query": "search source=web | table message", "is_soql": true, "viz": "table", "visibility": "shared" }),
    )
    .await;
    assert_eq!(c, 200);
    vca_retirer_la_table(&st, "library_panel");
    let (statut, illisible) =
        vca_corps(panel_update(State(st.clone()), Extension(adm.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await).await;
    assert_eq!(statut, 503, "{illisible}");
    assert!(
        vca_phrase(&illisible).contains(panneau_resolu::CAUSE_DEFINITION_DE_BIBLIOTHEQUE_NON_LUE),
        "la cause de `P10.20-b` atteint enfin l'appelant : {illisible}"
    );
}
