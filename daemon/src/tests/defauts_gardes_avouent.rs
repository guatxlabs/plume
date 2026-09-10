// =====================================================================================
// `P10.7-g` (lot 92) — LES DÉFAUTS GARDÉS AVOUENT.
//
// `read_with` et `read_with_watchdog` servent leur valeur PAR DÉFAUT quand aucune connexion de lecture n'est
// disponible ; la jointure de la tâche bloquante sert la sienne quand la tâche ne rend rien. Treize routes
// servaient là un corps VIDE sans un mot — une liste d'alertes vide, une file de dossiers vide, une posture de
// conformité sans règle, un inventaire de sources vide — c'est-à-dire un fait rassurant à la place d'une
// lecture qui n'a pas eu lieu. La jambe A de la garde des lectures non faites les nommait toutes.
//
// CE QUE CES TÉMOINS JOUENT : un état dont le chemin de base n'existe pas (aucune connexion de lecture ne
// peut s'ouvrir), la route appelée avec une identité réelle, et le corps servi lu tel quel. Les routes de
// liste portent `error` ; les deux routes fail-closed (journal d'audit, dossier client) rendent un 5xx nommé
// au lieu, pour la seconde, d'un 404 « introuvable » qui inventait une absence.
// =====================================================================================

/// L'état d'une base qui n'existe pas : aucune connexion de lecture ne s'ouvre, le défaut gardé est servi.
fn dg_etat_sans_base(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (mut st, p) = sp_state(tag);
    let chemin = Arc::new(format!("{}-inexistante/plume.db", p.as_ref() as &str));
    st.db_path = chemin.clone();
    st.tenants.default_db_path = chemin;
    (st, sp_au("adm", "admin"), p)
}

async fn dg_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn dg_q() -> Query<std::collections::HashMap<String, String>> {
    Query(std::collections::HashMap::new())
}

#[tokio::test]
async fn p10_7g_onze_defauts_gardes_portent_leur_cause() {
    use axum::response::IntoResponse;
    let (st, au, _p) = dg_etat_sans_base("dg-listes");
    let corps: Vec<(&str, (u16, Value))> = vec![
        ("alerts", dg_corps(alerts(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("alert_groups", dg_corps(alert_groups(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("coverage_detections", dg_corps(coverage_detections(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("coverage_attack", dg_corps(coverage_attack(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("case_queues", dg_corps(case_queues(State(st.clone()), Extension(au.clone())).await.into_response()).await),
        ("case_metrics", dg_corps(case_metrics(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("case_links_get", dg_corps(case_links_get(State(st.clone()), Extension(au.clone()), Path(1)).await.into_response()).await),
        ("client_cases_list", dg_corps(client_cases_list(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("cases_list", dg_corps(cases_list(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
        ("sources_inventory", dg_corps(sources_inventory(State(st.clone()), Extension(au.clone())).await.into_response()).await),
        ("compliance_posture", dg_corps(compliance_posture(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await),
    ];
    for (nom, (statut, v)) in &corps {
        let cause = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert!(
            cause.contains("NON FAITE") || cause.contains("NON LUE") || cause.contains("NON ÉTABLIE"),
            "{nom} : sans connexion de lecture, le corps doit DIRE que rien n'a été lu (statut {statut}) : {v}"
        );
    }
    assert_eq!(corps.len(), 11, "onze routes de liste sont jouées ici — les deux fail-closed ont leur témoin");
}

#[tokio::test]
async fn p10_7g_les_deux_defauts_fail_closed_rendent_un_5xx_nomme_jamais_une_absence() {
    use axum::response::IntoResponse;
    let (st, au, _p) = dg_etat_sans_base("dg-fail-closed");
    let (statut, corps) = dg_corps(client_case_get(State(st.clone()), Extension(au.clone()), Path(1)).await.into_response()).await;
    assert_eq!(statut, 500, "un dossier client non LU n'est pas un dossier INTROUVABLE (404) : {corps}");
    assert!(corps["error"].as_str().unwrap_or("").contains("NON FAITE"), "le 5xx nomme sa cause : {corps}");
    let (statut, _) = dg_corps(ledger_get(State(st.clone()), Extension(au.clone()), dg_q()).await.into_response()).await;
    assert_eq!(statut, 500, "le journal d'audit non lu ne rend aucune page (5xx nommé)");
}
