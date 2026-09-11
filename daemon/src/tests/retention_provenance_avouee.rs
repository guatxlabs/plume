// =====================================================================================
// `P10.7-g` (lot 101) — CHAQUE VALEUR DE RÉTENTION DIT SA PROVENANCE, ET UNE VALEUR ÉCRITE NON LUE EST NOMMÉE.
//
// Le résolveur servait une valeur effective juste (celle que la purge applique) sans dire d'où elle venait, et
// une table `setting` illisible se lisait exactement comme « rien d'écrit ». La provenance est servie par clé
// (`setting`, `environment`, `configuration`, `default`), et la lecture ratée est nommée (`reglage_illisible`,
// `error`), la valeur restant celle de la chaîne de repli.
// =====================================================================================

async fn rp_corps(r: Response) -> Value {
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    serde_json::from_slice(&b).unwrap_or(Value::Null)
}

#[tokio::test]
async fn p10_7g_la_provenance_de_chaque_valeur_de_retention_est_dite_et_une_valeur_ecrite_non_lue_est_nommee() {
    use axum::response::IntoResponse;
    let (st, _p) = sp_state("rp-retention");
    let au = sp_au("adm", "admin");
    let vocabulaire = ["setting", "environment", "configuration", "default"];
    let avant = rp_corps(retention_settings_get(State(st.clone()), Extension(au.clone())).await.into_response()).await;
    assert!(avant.get("error").is_none(), "table présente : rien à avouer : {avant}");
    for (skey, _, _, _, _) in RETENTION_FIELDS {
        let p = avant["provenance"][skey].as_str().unwrap_or("");
        assert!(vocabulaire.contains(&p), "la provenance de `{skey}` est un mot du vocabulaire : {avant}");
        assert_ne!(p, "setting", "instrument : rien n'est écrit avant l'écriture : {avant}");
    }
    // Une valeur ÉCRITE par la route de réglage : sa provenance devient `setting`.
    let plancher = avant["bounds"]["retention_days"]["min"].as_i64().expect("plancher publié");
    let ecrit = rp_corps(retention_settings_put(State(st.clone()), Extension(au.clone()), Json(json!({ "retention_days": plancher }))).await.into_response()).await;
    let apres_ecriture = rp_corps(retention_settings_get(State(st.clone()), Extension(au.clone())).await.into_response()).await;
    assert_eq!(apres_ecriture["provenance"]["retention_days"], json!("setting"), "une valeur écrite est dite écrite : {apres_ecriture} (écriture : {ecrit})");
    assert_eq!(apres_ecriture["retention_days"], json!(plancher));
    // La table des réglages devient illisible : la valeur servie est celle du repli, et la lecture ratée est NOMMÉE.
    with_write(&st, &au, |conn| conn.execute_batch("ALTER TABLE setting RENAME TO setting_hors_d_atteinte;").expect("la fixture peut renommer la table"));
    let non_lu = rp_corps(retention_settings_get(State(st.clone()), Extension(au.clone())).await.into_response()).await;
    assert!(non_lu["reglage_illisible"]["retention_days"].is_string(), "la lecture ratée est nommée par clé : {non_lu}");
    assert!(non_lu["error"].as_str().unwrap_or("").starts_with("réglage NON LU"), "le corps porte la cause : {non_lu}");
    let p = non_lu["provenance"]["retention_days"].as_str().unwrap_or("");
    assert!(["environment", "configuration", "default"].contains(&p), "la valeur servie vient du repli, jamais dite « écrite » : {non_lu}");
}
