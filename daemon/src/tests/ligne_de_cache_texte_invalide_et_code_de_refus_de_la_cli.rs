// =====================================================================================
// `P10.32-o` — UNE LIGNE DE CACHE DONT LE TEXTE N'EST PAS DE L'UTF-8 EST ILLISIBLE, PAS NON LUE.
// `P10.29-l` — LA CLI DE PURGE SERT LE MÊME CODE DE REFUS QUE LA ROUTE APRÈS UNE DÉCISION DONT L'ANNULATION EST REFUSÉE.
//
// LES DÉFAUTS, RELEVÉS PAR LE VÉRIFICATEUR SUR 7d9bf2e4 :
//  (1) le bras `FromSqlConversionFailure` de `panneau_avoue::cache_lire_dit` n'avait aucun témoin : seule la charge BLOB
//      (`InvalidColumnType`) était jugée. Une charge TEXT à l'UTF-8 invalide y passe ; classée `NonLue`, la ligne n'est
//      jamais remplacée et la route sert `warming`/`cache_non_lu` sans fin (la chauffe éternelle de `P10.32-o`). Le
//      mutant « FromSqlConversionFailure -> NonLue » restait vert sur les tests ciblés.
//  (2) le JSON de la CLI (`plume purge … --json`) gardait `refusal: "transaction_left_open"` après une décision dont
//      l'annulation est refusée, alors que la route sert le code de la décision.
//
// LE CORRECTIF : (2) `purge::code_de_refus_servi`, lu par la route ET par `purge::purge_refusal_cli_json` (le corps CLI
// porte aussi `id` et `annulation_refusee`, comme la route).
//
// MUTANTS JOUÉS (variable `VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// `BA2C_O3` (FromSqlConversionFailure classé NonLue) et `BA2C_CLI` (la CLI rend `purge_refusal_code`).
// CE QUE CE TÉMOIN NE TIENT PAS : il juge l'issue de `cache_lire_dit` (dont dépend le remplacement, jugé pour le BLOB par
// `ligne_de_cache_illisible_remplacee_et_non_lue_dite.rs`), pas la route sur une charge UTF-8 invalide ; il juge
// l'assistant `purge_refusal_cli_json` (le site de la CLI, `purge::purge_cli_sur`, et sa sortie 3 sont jugés par
// `purge_classement_de_l_annulation_et_site_de_la_cli.rs`). `IntegralValueOutOfRange` reste sans témoin : `computed_at` est lu en
// `i64`, ce bras n'est pas atteignable par cette lecture.
// =====================================================================================
mod ligne_de_cache_texte_invalide_et_code_de_refus_de_la_cli {
    use super::*;

    #[test]
    fn ltc_charge_texte_utf8_invalide_classee_illisible() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE panel_cache(panel_id INTEGER NOT NULL, range_key TEXT NOT NULL, query_fp TEXT NOT NULL, \
             computed_at INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(panel_id, range_key));
             INSERT INTO panel_cache VALUES(7, 'rk', 'fp', 1000, CAST(X'FF' AS TEXT));",
        )
        .unwrap();
        let typ: String = conn.query_row("SELECT typeof(payload) FROM panel_cache", [], |r| r.get(0)).unwrap();
        assert_eq!(typ, "text", "la charge posée doit être du TEXT (et non un BLOB, déjà jugé ailleurs)");
        match panneau_avoue::cache_lire_dit(&conn, 7, "rk", "fp") {
            panneau_avoue::LectureDeCache::Illisible(cause) => {
                assert!(cause.contains("invalid utf-8"), "la cause nomme la conversion ratée : {cause}");
                assert!(cause.contains("lecture de cache ratée n°"), "la cause porte le rang du compte : {cause}");
            }
            autre => panic!("une charge TEXT à l'UTF-8 invalide est une ligne lue non décodable (Illisible), pas {autre:?}"),
        }
    }

    #[tokio::test]
    async fn ltc_cli_sert_le_code_de_la_decision_comme_la_route() {
        let decision = PurgeRefusal::TransactionLeftOpen { id: "corr-1".into(), etape: "count_mismatch", decision: true };
        let corps = purge_refusal_cli_json(&decision);
        assert_eq!(corps["ok"], json!(false));
        assert_eq!(corps["refusal"], json!("count_mismatch"), "CLI : le code de la décision, pas transaction_left_open : {corps}");
        assert_eq!(corps["annulation_refusee"], json!(true), "{corps}");
        assert_eq!(corps["id"], json!("corr-1"), "{corps}");
        // La route sert le même code.
        let rep = purge_refusal_response(PurgeRefusal::TransactionLeftOpen { id: "corr-1".into(), etape: "count_mismatch", decision: true });
        let octets = axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap();
        let route: Value = serde_json::from_slice(&octets).unwrap();
        assert_eq!(route["refusal"], corps["refusal"], "route et CLI divergent : route {route} / CLI {corps}");

        // Hors décision : transaction restée ouverte sans décision, et un refus ordinaire, inchangés.
        let ouverte = PurgeRefusal::TransactionLeftOpen { id: "corr-2".into(), etape: "db", decision: false };
        let corps = purge_refusal_cli_json(&ouverte);
        assert_eq!(corps["refusal"], json!("transaction_left_open"), "{corps}");
        assert_eq!(corps["id"], json!("corr-2"), "{corps}");
        assert!(corps.get("annulation_refusee").is_none(), "{corps}");
        let corps = purge_refusal_cli_json(&PurgeRefusal::ReasonRequired);
        assert_eq!(corps["refusal"], json!("reason_required"), "{corps}");
        assert!(corps.get("id").is_none(), "{corps}");
    }
}
