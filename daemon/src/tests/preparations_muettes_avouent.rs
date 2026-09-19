// =====================================================================================
// `P10.20-p` — UNE PRÉPARATION QUI N'A PAS ABOUTI NE SE SERT PAS COMME UN PARCOURS COMPLET.
//
// LA FORME. `if let Ok(mut s) = conn.prepare(..)` SANS branche d'échec est muette PAR CONSTRUCTION :
// il n'y a pas de branche où écrire quoi que ce soit. `P10.20-g` a fermé les trois sites de
// `compute_freshness` ; le relevé qui l'accompagnait en laissait DEUX sous `handlers/`, et ce lot les
// prend — plus les variantes voisines mesurées dans les mêmes fonctions et dans `resolve_case_ref`.
//
// CE QUE CHAQUE SITE SERVAIT.
//   * `suppressions_get` (admin_ui.rs) — le panneau « Suppressions & whitelists actives » sert la liste
//     des auto-reports collecteurs ET un aveu de parcours (`collectors_incomplets`/`collectors_cause`,
//     posé par `P10.7-f`). La préparation muette ENJAMBAIT cet aveu : `coll_fin` restait `Complet`,
//     donc le corps affirmait « le relevé est entier » à côté d'une liste vide, et le panneau se lisait
//     « aucun collecteur n'a auto-reporté sa configuration » — sur la surface dont l'objet est
//     précisément de montrer ce qui de-bruite la collecte.
//   * `object_field_allow` (datamodels.rs) — l'allowlist des champs déclarés d'un objet de modèle. Le
//     fail-closed était RÉEL et il le reste (une allowlist vide fait refuser le Pivot), mais la cause
//     servie disait « champ split-by non déclaré dans l'objet : <champ> » : une accusation portée
//     contre la DÉCLARATION de l'exploitant, qui l'envoie déclarer un champ déjà déclaré. Et un Pivot
//     qui ne cite AUCUN champ (un `count` seul) passait sans que personne n'apprenne que l'allowlist
//     n'avait pas été lue.
//   * `resolve_case_ref` (cases.rs) — variante mesurée et TRAITÉE parce qu'elle SERT UN FAIT : ses deux
//     `if let Ok(..) = query_row(..)` rendaient `(None, None)` sur une lecture ratée, c'est-à-dire
//     EXACTEMENT ce que rend une cible supprimée, et `web/cases.js:457` peint alors, en toutes lettres,
//     « cible introuvable — supprimée ou expirée » sur une alerte qui existe.
//
// LA FORME DES CORRECTIFS EST CELLE DU DÉPÔT : `FinDeParcours::NonCommence` (le mot que `P10.7-f` avait
// déjà, qu'il manquait d'écrire pour la préparation) pour le parcours ; un `Result` dont l'appelant
// tire la cause, servie en 503 et non en 400 (l'allowlist non lue n'est le défaut de personne, et un
// 400 apprendrait à l'appelant que sa demande est malformée) ; un aveu nommé POSÉ SUR L'OBJET
// (`ref_non_lu`) et absent du chemin nominal, donc un aveu inconditionnel — qui ne vaudrait rien — est
// structurellement impossible.
//
// LES VOIES JOUÉES. La TABLE RETIRÉE (renommée sous les pieds du gestionnaire) fait échouer la
// PRÉPARATION : c'est la voie que ces sites ne savaient pas dire. La LIGNE ILLISIBLE (un `BLOB` dans une
// colonne lue en `TEXT` ou en `INTEGER`) fait échouer le MAPPEUR, la requête restant saine — et elle
// sépare deux verdicts qu'il ne faut pas confondre : sur un parcours elle rend `Interrompu` (un PRÉFIXE
// a été servi), pas `NonCommence` (rien n'a été lu).
//
// CE QUE CE LOT NE TIENT PAS, ET IL FAUT LE LIRE ICI : `rows.flatten()` de `object_field_allow` RESTE —
// c'est l'arbitrage assumé nommé dans `SITES_ASSUMES` de la garde de famille (une ligne illisible ampute
// l'allowlist, le champ correspondant est REFUSÉ, jamais inventé), et le témoin l'ASSERTE au lieu de le
// taire. `object_constraint_chain`, deux lignes plus haut, confond toujours « objet introuvable ou
// désactivé » et « pas lu » (famille `P10.20-b`, non traitée ici). Et aucun module de `web/` ne lit les
// aveux neufs.
// =====================================================================================

/// Statut + corps JSON d'une réponse (ou `{_texte}` si le corps n'est pas du JSON).
async fn pma_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
}

fn pma_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

fn pma_retirer_la_table(st: &AppState, table: &str) {
    pma_ecrire(st, &format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"));
}

// -------------------------------------------------------------------------------------
// (1) LE PANNEAU DES AUTO-REPORTS COLLECTEURS — un parcours qui n'a pas démarré le DIT.
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur une base lisible, `suppressions_get` sert l'auto-report du collecteur ET déclare
/// son relevé COMPLET (`collectors_incomplets: false`, cause nulle — contrôle positif) ; la table des
/// événements retirée, la préparation échoue et le corps DIT que le relevé n'a pas eu lieu, au lieu
/// d'affirmer « entier » à côté d'une liste vide.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la console (`web/suppressions.js` ne lit ni
/// `collectors_incomplets` ni `collectors_cause`), et il ne dit rien des autres lectures du même corps
/// (registre daemon, instantanés pare-feu), qui ont leurs propres aveux.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `if let Ok(mut s) = conn.prepare(..)` — le dernier bloc
/// retrouve `collectors_incomplets: false` et une cause nulle, c'est-à-dire l'affirmation exactement
/// fausse, pendant que le premier bloc reste vert.
#[tokio::test]
async fn p10_20p_un_releve_d_auto_reports_qui_n_a_pas_demarre_ne_se_sert_pas_complet() {
    let (st, _tmp) = sp_state("pma-suppressions");
    let adm = sp_au("adm", "admin");
    pma_ecrire(
        &st,
        "INSERT INTO event(ts,source,category,severity,host,message,fields,origin) \
         VALUES(1000,'mail','config',0,'mx1','config du collecteur mail','{\"type\":\"collection-reducing\"}','');",
    );

    // CONTRÔLE POSITIF — l'auto-report est lu, servi, et le relevé se déclare COMPLET.
    let (statut, lu) = pma_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(lu["collectors"].as_array().map(|a| a.len()), Some(1), "l'auto-report est servi : {lu}");
    assert_eq!(lu["collectors_incomplets"], json!(false), "et le relevé se déclare entier : {lu}");
    assert_eq!(lu["collectors_cause"], Value::Null, "un corps qui avoue toujours n'avoue rien : {lu}");

    // LA TABLE RETIRÉE — la PRÉPARATION échoue. Avant ce lot : `collectors: []` + `collectors_incomplets:
    // false`, soit « aucun collecteur n'a auto-reporté », affirmé sur une lecture qui n'a pas eu lieu.
    pma_retirer_la_table(&st, "event");
    let (statut, avoue) = pma_corps(suppressions_get(State(st.clone()), Extension(adm.clone())).await).await;
    assert_eq!(statut, 200, "le corps reste servi (les autres familles sont lues) : {avoue}");
    assert_eq!(avoue["collectors"].as_array().map(|a| a.len()), Some(0), "aucune ligne n'a pu être lue : {avoue}");
    assert_eq!(
        avoue["collectors_incomplets"],
        json!(true),
        "et le corps ne l'affirme PLUS entier — c'est tout le défaut : {avoue}"
    );
    assert!(
        avoue["collectors_cause"].as_str().is_some_and(|c| !c.is_empty()),
        "la cause du moteur est conservée telle qu'il l'a dite : {avoue}"
    );
}

// -------------------------------------------------------------------------------------
// (2) L'ALLOWLIST DU PIVOT — « pas lu » cesse de se dire « aucun champ déclaré ».
// -------------------------------------------------------------------------------------

fn pma_modele(st: &AppState) -> i64 {
    pma_ecrire(
        st,
        "INSERT INTO data_model(id,name,title) VALUES(1,'auth','Authentification'); \
         INSERT INTO data_model_object(id,model_id,name,constraint_soql) VALUES(1,1,'echecs','category=auth'); \
         INSERT INTO data_model_field(id,object_id,name,ftype,expr) VALUES(1,1,'host','string',''); \
         INSERT INTO data_model_field(id,object_id,name,ftype,expr) VALUES(2,1,'user','string','');",
    );
    1
}

async fn pma_pivot(st: &AppState, au: &AuthUser, corps: Value) -> (u16, Value) {
    pma_corps(pivot_compile(State(st.clone()), Extension(au.clone()), Json(corps)).await).await
}

/// CE QU'IL TIENT : sur des champs LUS, le Pivot compile son GXQL (contrôle positif) et refuse en 400 un
/// champ RÉELLEMENT non déclaré ; la table des champs retirée, il refuse en 503 avec une cause qui dit
/// « pas lu » — y compris pour un Pivot qui ne cite AUCUN champ (un `count` seul), lequel passait
/// auparavant sans que l'allowlist ait été lue. L'ARBITRAGE ASSUMÉ est asserté dans le même corps : une
/// LIGNE illisible ampute l'allowlist et le champ perdu est REFUSÉ, jamais inventé.
///
/// CE QU'IL NE TIENT PAS : il ne referme pas cet arbitrage (`rows.flatten()`, entrée `object_field_allow`
/// de `SITES_ASSUMES`), et il ne juge pas `object_constraint_chain`, qui confond toujours une lecture
/// ratée avec « objet introuvable ou désactivé ».
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `if let Ok(mut s) = conn.prepare(..)` et le type
/// `HashSet` — le bloc de la table retirée retrouve un 400 « champ split-by non déclaré dans l'objet »,
/// et le `count` seul retrouve un 200.
#[tokio::test]
async fn p10_20p_une_allowlist_de_pivot_non_lue_ne_se_dit_pas_aucun_champ_declare() {
    let (st, _tmp) = sp_state("pma-pivot");
    let alice = sp_au("alice", "editor");
    let oid = pma_modele(&st);

    // CONTRÔLE POSITIF (1/2) — les champs sont lus, le GXQL se compile.
    let (statut, compile) =
        pma_pivot(&st, &alice, json!({ "object_id": oid, "splitby": ["host"], "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 200, "{compile}");
    assert!(compile["soql"].as_str().unwrap_or("").contains("by host"), "{compile}");

    // CONTRÔLE POSITIF (2/2) — un champ RÉELLEMENT non déclaré est refusé, et la phrase le nomme.
    let (statut, refus) =
        pma_pivot(&st, &alice, json!({ "object_id": oid, "splitby": ["secret"], "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 400, "un champ non déclaré est un défaut du CORPS reçu : {refus}");
    assert!(refus["error"].as_str().unwrap_or("").contains("non déclaré dans l'objet"), "{refus}");

    // L'ARBITRAGE ASSUMÉ, ASSERTÉ — une LIGNE illisible ampute l'allowlist ; le champ perdu est REFUSÉ
    // (jamais inventé), et l'AUTRE champ reste servi. C'est l'entrée `object_field_allow` de
    // `SITES_ASSUMES` dans la garde de famille, et ce lot ne la change pas.
    pma_ecrire(&st, "UPDATE data_model_field SET name=x'FF' WHERE id=1;");
    let (statut, ampute) =
        pma_pivot(&st, &alice, json!({ "object_id": oid, "splitby": ["host"], "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 400, "la ligne avalée fait REFUSER le champ, elle n'en invente aucun : {ampute}");
    let (statut, _) = pma_pivot(&st, &alice, json!({ "object_id": oid, "splitby": ["user"], "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 200, "et le champ dont la ligne est saine reste servi");

    // LA TABLE RETIRÉE — la PRÉPARATION échoue : 503, et la cause dit « pas lu ».
    pma_retirer_la_table(&st, "data_model_field");
    let (statut, non_lu) =
        pma_pivot(&st, &alice, json!({ "object_id": oid, "splitby": ["host"], "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 503, "ce n'est pas un défaut du corps reçu, c'est une lecture : {non_lu}");
    let cause = non_lu["error"].as_str().unwrap_or("").to_string();
    assert!(cause.contains("NON LUS"), "la cause dit « pas lu » : {non_lu}");
    assert!(!cause.contains("non déclaré dans l'objet"), "et n'accuse plus la DÉCLARATION de l'exploitant : {non_lu}");

    // ET LE PIVOT QUI NE CITE AUCUN CHAMP — un `count` seul — n'échappe plus au refus : il passait
    // auparavant sans que l'allowlist ait été lue, parce que rien n'allait la consulter.
    let (statut, compte_seul) = pma_pivot(&st, &alice, json!({ "object_id": oid, "stats": [{ "func": "count" }] })).await;
    assert_eq!(statut, 503, "l'allowlist non lue refuse même quand personne ne l'interroge : {compte_seul}");
}

// -------------------------------------------------------------------------------------
// (3) LA RÉFÉRENCE D'UN ITEM DE TIMELINE — « introuvable » cesse d'absorber « pas lu ».
// -------------------------------------------------------------------------------------

fn pma_dossier_avec_ref(st: &AppState, rf: &str) -> i64 {
    let conn = st.db.lock();
    let id = dossier_seme(&conn, "alice", "intrusion", 3, "", None, 2);
    case_add_item(&conn, id, now(), "link", "alice", "pièce jointe", Some(rf));
    id
}

fn pma_item_avec_ref(st: &AppState, id: i64) -> Value {
    let conn = st.db.lock();
    let fiche = case_get_lu(&conn, id, now()).expect("la fiche se lit").expect("la fiche existe");
    fiche["items"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i.get("ref").and_then(|r| r.as_str()).unwrap_or("").starts_with("alert:")).cloned())
        .expect("l'item porteur de la ref est servi")
}

/// CE QU'IL TIENT : une cible LUE donne son titre et sa sévérité et ne pose aucun aveu (contrôle
/// positif) ; une cible ABSENTE donne `null` SANS aveu — c'est un FAIT, la rétention l'a effacée ; une
/// cible NON LUE (ligne illisible, puis table retirée) donne `null` PLUS `ref_non_lu`, ce qui empêche la
/// console d'écrire « cible introuvable — supprimée ou expirée » sur une alerte qui existe.
///
/// CE QU'IL NE TIENT PAS : `web/cases.js` ne lit pas encore `ref_non_lu` — il peindra sa phrase tant
/// que la console n'aura pas été faite ; le témoin tient le DÉMON, pas le rendu.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `if let Ok(r) = conn.query_row(..)` et le couple à deux
/// membres — les deux derniers blocs perdent `ref_non_lu` et redeviennent indiscernables du bloc de la
/// cible absente, qui, lui, reste vert.
#[tokio::test]
async fn p10_20p_une_reference_de_timeline_non_lue_ne_se_sert_pas_introuvable() {
    let (st, _tmp) = sp_state("pma-refcase");
    pma_ecrire(
        &st,
        "INSERT INTO alert(id,ts,rule,severity,title) VALUES(7,1000,'T1110',3,'bruteforce sur mx1');",
    );

    // CONTRÔLE POSITIF (1/2) — la cible est lue : titre, sévérité, et AUCUN aveu.
    let cas = pma_dossier_avec_ref(&st, "alert:7");
    let item = pma_item_avec_ref(&st, cas);
    assert_eq!(item["ref_title"], json!("bruteforce sur mx1"), "{item}");
    assert_eq!(item["ref_severity"], json!(3), "{item}");
    assert_eq!(item.get("ref_non_lu"), None, "aucun aveu sur le chemin nominal : {item}");

    // CONTRÔLE POSITIF (2/2) — la cible ABSENTE est un FAIT : `null`, et toujours aucun aveu.
    let efface = pma_dossier_avec_ref(&st, "alert:999999");
    let item = pma_item_avec_ref(&st, efface);
    assert_eq!(item["ref_title"], Value::Null, "{item}");
    assert_eq!(item.get("ref_non_lu"), None, "une cible effacée par la rétention n'est pas une lecture ratée : {item}");

    // LA LIGNE ILLISIBLE — `severity` porte un BLOB que `get::<i64>` refuse. La requête reste saine.
    pma_ecrire(&st, "UPDATE alert SET severity=x'FF' WHERE id=7;");
    let item = pma_item_avec_ref(&st, cas);
    assert_eq!(item["ref_title"], Value::Null, "{item}");
    assert_eq!(item["ref_non_lu"], json!(true), "la lecture non faite est AVOUÉE, pas peinte « introuvable » : {item}");

    // LA TABLE RETIRÉE — la PRÉPARATION échoue, même aveu.
    pma_retirer_la_table(&st, "alert");
    let item = pma_item_avec_ref(&st, cas);
    assert_eq!(item["ref_non_lu"], json!(true), "table hors d'atteinte : même aveu : {item}");
}
