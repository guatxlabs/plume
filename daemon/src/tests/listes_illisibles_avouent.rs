// =====================================================================================
// `P10.7-z` — UNE LISTE QUI N'A PAS PU ÊTRE LUE NE SE SERT PLUS COMME UNE LISTE VIDE.
//
// LE DÉFAUT MESURÉ (2026-09-10, garde `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py`,
// jambe B) : sept routes de liste — panneaux de bibliothèque, listes de lecture, instantanés, tableaux
// de bord, rétentions légales, puits du journal, politiques SLA — rendaient `[]` quand la préparation
// ou l'exécution de leur lecture échouait, deux d'entre elles avec `ok: true`. Un registre ILLISIBLE se
// lisait « registre vide », et rien ne pouvait le trahir : la forme servie est exactement celle du fait.
//
// CE QUE CES TÉMOINS JOUENT : la table est RETIRÉE sous les pieds du gestionnaire (renommée — un renommage
// ne viole aucune clé étrangère, et le SQL servi, lui, n'est pas réécrit), et la même route est appelée
// AVANT et APRÈS. Avant : aucun `error` (rien à avouer). Après : la clé de liste existe et est vide, et
// `error` porte `CAUSE_LISTE_ILLISIBLE` ; les deux routes qui servaient `ok: true` servent `ok: false`.
// Le témoin positif est dans chaque test, pas à côté : sans lui, un aveu INCONDITIONNEL passerait.
//
// CE QUE LA PREMIÈRE EXÉCUTION A TROUVÉ, ET QUI A CHANGÉ LE CORRECTIF : cinq témoins sur sept étaient
// ROUGES avec un corps `{ "<cle>": [] }` SANS `error` — la lecture n'avait pas échoué à la préparation.
// Cause lue dans le moteur : la connexion de lecture du pool avait servi la page « avant », son cache de
// schéma portait encore la table ; `prepare` réussit sur ce cache, et c'est au premier PAS que SQLite
// relit le schéma et rend « no such table » — comme une ERREUR DE LIGNE, que `.flatten()` avalait. Une
// table disparue se servait donc « registre vide », par la voie même que `P10.7-f` décrit. Les sept
// routes collectent désormais `Result<Vec<_>, _>` : une ligne en erreur rend la LISTE non établie.
// Ce témoin joue cette voie-là exactement (même connexion du pool, aucune sonde entre les deux pages).
//
// CE QUE CE LOT NE TIENT PAS : les autres routes de liste gardent leur `.flatten()` (famille `P10.7-f`),
// et la console ne LIT pas encore cet aveu sur les deux routes qu'elle consulte (`dashboards.js` :
// `|| []`), reste nommé sous `P11.21-h`.
// =====================================================================================

/// Le corps JSON d'une réponse `Response`.
async fn li_corps_json(r: Response) -> Value {
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    serde_json::from_slice(&b).expect("corps JSON")
}

/// Rend une table ILLISIBLE pour le gestionnaire sans toucher au code servi : renommée, elle n'est plus
/// sous le nom que le SQL servi attend. Passe par la voie d'écriture du démon, aucune ouverture de plus.
fn li_retirer_la_table(st: &AppState, au: &AuthUser, table: &str) {
    with_write(st, au, |conn| {
        conn.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"))
            .expect("la fixture peut renommer la table")
    });
}

/// Le jugement, écrit une fois : AVANT rien à avouer, APRÈS la forme est conservée et la cause est posée.
fn li_juger(avant: &Value, apres: &Value, cle: &str) {
    assert!(avant.get("error").is_none(), "table présente : rien à avouer, or : {avant}");
    assert!(avant[cle].is_array(), "table présente : la liste est un tableau : {avant}");
    assert_eq!(apres[cle], json!([]), "table hors d'atteinte : la FORME est conservée (clé présente, vide) : {apres}");
    assert_eq!(
        apres["error"],
        json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
        "table hors d'atteinte : le corps doit DIRE que ce vide n'a pas été établi : {apres}"
    );
}

#[tokio::test]
async fn p10_7z_la_liste_des_panneaux_de_bibliotheque_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-library");
    let au = sp_au("adm", "admin");
    let avant = library_panels_list(State(st.clone()), Extension(au.clone())).await.0;
    li_retirer_la_table(&st, &au, "library_panel");
    let apres = library_panels_list(State(st.clone()), Extension(au.clone())).await.0;
    li_juger(&avant, &apres, "library_panels");
}

#[tokio::test]
async fn p10_7z_la_liste_des_listes_de_lecture_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-playlists");
    let au = sp_au("adm", "admin");
    let avant = playlists_list(State(st.clone()), Extension(au.clone())).await.0;
    li_retirer_la_table(&st, &au, "playlist");
    let apres = playlists_list(State(st.clone()), Extension(au.clone())).await.0;
    li_juger(&avant, &apres, "playlists");
}

#[tokio::test]
async fn p10_7z_la_liste_des_instantanes_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-snapshots");
    let au = sp_au("adm", "admin");
    let avant = snapshots_list(State(st.clone()), Extension(au.clone())).await.0;
    li_retirer_la_table(&st, &au, "dashboard_snapshot");
    let apres = snapshots_list(State(st.clone()), Extension(au.clone())).await.0;
    li_juger(&avant, &apres, "snapshots");
}

#[tokio::test]
async fn p10_7z_la_liste_des_tableaux_de_bord_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-dashboards");
    let au = sp_au("adm", "admin");
    let q = || Query(std::collections::HashMap::<String, String>::new());
    let avant = dash_list(State(st.clone()), Extension(au.clone()), q()).await.0;
    li_retirer_la_table(&st, &au, "dashboard");
    let apres = dash_list(State(st.clone()), Extension(au.clone()), q()).await.0;
    li_juger(&avant, &apres, "dashboards");
}

#[tokio::test]
async fn p10_7z_la_liste_des_politiques_sla_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-sla");
    let au = sp_au("adm", "admin");
    let avant = sla_policies_list(State(st.clone()), Extension(au.clone())).await.0;
    li_retirer_la_table(&st, &au, "sla_policy");
    let apres = sla_policies_list(State(st.clone()), Extension(au.clone())).await.0;
    li_juger(&avant, &apres, "policies");
}

#[tokio::test]
async fn p10_7z_la_liste_des_retentions_legales_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-holds");
    let au = sp_au("adm", "admin");
    let avant = li_corps_json(legal_holds_list(State(st.clone()), Extension(au.clone())).await).await;
    li_retirer_la_table(&st, &au, "legal_hold");
    let apres = li_corps_json(legal_holds_list(State(st.clone()), Extension(au.clone())).await).await;
    li_juger(&avant, &apres, "holds");
    assert_eq!(avant["ok"], json!(true));
    assert_eq!(apres["ok"], json!(false), "une liste non lue ne se sert pas sous `ok: true` : {apres}");
}

#[tokio::test]
async fn p10_7z_la_liste_des_puits_du_journal_avoue_quand_elle_nest_pas_lue() {
    let (st, _p) = sp_state("li-sinks");
    let au = sp_au("adm", "admin");
    let avant = li_corps_json(ledger_sinks_list(State(st.clone()), Extension(au.clone())).await).await;
    li_retirer_la_table(&st, &au, "ledger_sink");
    let apres = li_corps_json(ledger_sinks_list(State(st.clone()), Extension(au.clone())).await).await;
    li_juger(&avant, &apres, "sinks");
    assert_eq!(avant["ok"], json!(true));
    assert_eq!(apres["ok"], json!(false), "une liste non lue ne se sert pas sous `ok: true` : {apres}");
}
