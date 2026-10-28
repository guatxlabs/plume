// =====================================================================================
// `P10.33-i` — L'ACQUITTEMENT DE `/api/ingest` EST UN CONTRAT LU PAR LE COLLECTEUR WINDOWS.
//
// `collectors/windows/plume-collector.ps1` (`Flush-Events`) ne tient un lot pour livré que si la réponse
// porte `"queued": true`, un BOOLÉEN. Raison : Windows PowerShell 5.1, que lance la tâche planifiée, ne
// lève pas sur une réponse 303, 307 ou 308 refusée par `-MaximumRedirection 0` — elle revient comme une
// réponse normale au corps vide, et « aucune exception » valait acquittement (lot perdu, tâche verte).
// Le jugement au CORPS ferme ce cas, à condition que le central rende bien ce corps-là : ce témoin
// l'épingle sur la route réelle (`ingest_post`), lot non vide, deux régimes de barrière.
//
// MUTATION : `"queued": true` -> `"queued": 1` (ou retirer la clé) au site de l'accusé de `ingest_post`
// ⇒ ROUGE. Ce que le côté PowerShell exige est joué par `check_windows_collector_is_honest.py`
// (`jouer_la_redirection`).
//
// CE QU'IL NE PROUVE PAS : qu'un frontal entre le poste et le central laisse passer ce corps intact.
// =====================================================================================
mod acquittement_d_ingestion_lu_par_le_collecteur_windows {
    use super::*;

    #[tokio::test]
    async fn l_accuse_de_l_ingestion_porte_queued_en_booleen_vrai() {
        let corps = json!({ "ts": 1_700_000_000, "host": "WS-TEMOIN", "kind": "events",
                            "events": [{ "ts": 1_700_000_000, "source": "windows-security",
                                         "category": "auth", "severity": 1, "message": "temoin" }] }).to_string();
        for arme in [true, false] {
            let (mut st, _spool) = ing_state_with_spool();
            st.ingest_fsync = arme;
            let au = AuthUser { name: "agent".into(), role: "agent".into(), tenant: "default".into(),
                                is_superadmin: false, method: "bearer".into(), csrf: String::new(), env: None };
            let r = crate::ingest::ingest_post(State(st), Extension(au), corps.clone()).await;
            assert_eq!(r.status(), StatusCode::ACCEPTED, "barrière armée={arme} : l'accusé est un 202");
            let j: Value = serde_json::from_slice(
                &axum::body::to_bytes(r.into_body(), 64 * 1024).await.unwrap()).unwrap();
            assert_eq!(j.get("queued"), Some(&Value::Bool(true)),
                "barrière armée={arme} : le collecteur Windows ne tient le lot pour livré que sur \
                 `\"queued\": true` (booléen) — sans lui, chaque envoi y est un échec. Corps rendu : {j}");
        }
    }
}
