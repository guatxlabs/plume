// =====================================================================================
// `P10.20-b` (rang quatre) — MODIFIER OU SUPPRIMER UN FOURNISSEUR D'IA DIT « NON LU » AU LIEU D'UNE FAUSSE ABSENCE :
// `ai_provider_update` (désactivation d'urgence comprise) et `ai_provider_delete`.
//
// VU sur `c78be971` : les deux gestionnaires lisaient la ligne visée par `.ok()` puis rendaient 404 « provider
// introuvable » sur `None` — une lecture ratée servait la même sortie qu'une absence. Fail-closed (rien n'est retiré),
// mais l'administrateur qui coupait en urgence la sortie de données vers un fournisseur d'IA tiers lisait que ce
// fournisseur n'existait pas alors qu'il restait actif et recevait toujours les questions posées à l'assistant : il
// n'avait aucune raison de réessayer. Le même geste a été fermé pour `idp_provider_update`/`idp_provider_delete`
// (témoins : `gestes_de_retrait_d_acces_lectures_avouees.rs`).
//
// ATTENDU, tenu ici : l'absence ÉTABLIE garde le 404 JSON d'avant OCTET POUR OCTET ; la lecture NON FAITE rend un 503
// nommé (cause du moteur au journal seulement), rien n'est écrit ni attesté, aucune transaction laissée ouverte, le
// fournisseur actif l'est toujours ; table rendue, le geste a lieu comme avant (200 `{"ok":true}`, 204).
//
// LA LECTURE EST RENDUE ILLISIBLE sans toucher au code servi, de DEUX façons. (1) La table `ai_provider` est RENOMMÉE le
// temps de l'appel, puis rendue. Aucun déclencheur, aucune vue ni aucune clé étrangère ne la référence (vérifié dans
// `migrate.rs`, `migrate_v109`). Cette fabrication ne peut PAS juger « rien d'écrit » : sans table, aucune écriture
// n'aboutirait. (2) D'où une seconde fabrication, une CELLULE illisible : un second fournisseur actif dont la colonne lue
// est un BLOB `X'00'` (affinité TEXT : le BLOB reste BLOB), `endpoint` pour la modification, `name` pour la suppression.
// La lecture échoue (`InvalidColumnType`) alors que la table est là : un UPDATE ou un DELETE tenté avant le 503
// ABOUTIRAIT, et l'assertion « reste actif / est toujours là » le verrait. Les gestionnaires sont appelés directement.
// Les fournisseurs sont posés à même la table, endpoint en RFC 5737 ; la désactivation seule ne passe pas par la garde
// cloud (ni réactivation ni endpoint neuf).
//
// MUTATIONS (vues ROUGES puis retirées) : `R3_UPD_OK`, `R3_DEL_OK` rétablissent le `.ok()` (404 sur la lecture ratée)
// de leur site ; `R3_UPD_INV`, `R3_DEL_INV` confondent l'absence avec la lecture ratée (503 sur l'absence) ;
// `R3_CAUSE_CROISEE` sert la cause de la modification sur la suppression ; `R3_TX_AVANT` ouvre la transaction AVANT la
// lecture (le 404 d'absence et le 503 la laissent pendante : le témoin rougit à la remise de la table, que le
// ROLLBACK de la transaction pendante a déjà défaite). Chacune ne fait rougir que le témoin de son site.
// `U_ECRIT503`, `D_ECRIT503` (mutants du vérificateur : l'UPDATE `enabled` ou le DELETE tenté sur la lecture ratée, puis le
// 503 nommé) restaient VERTS sous la seule fabrication (1) ; la fabrication (2) les rend ROUGES, chacun sur son site.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la phrase que la console peint de ces 503 (aucun témoin de harnais) ; une lecture
// qui échoue AUTREMENT que par une table absente ou une cellule d'un mauvais type (verrou, corruption, interruption) — le
// partage est le même `Err`, les fabrications n'en jouent que deux ; une écriture tentée sur une AUTRE colonne que
// `enabled` (modification) quand la lecture rate — seule la désactivation est jouée ; l'UPDATE d'un fournisseur supprimé entre la lecture et la transaction (inchangé) ; la
// garde cloud jugée sur la ligne lue avant la transaction et non relue dedans ; `ai_provider_create` et le test de
// fournisseur, hors lot. Compilés et joués seulement sous `--features ai` (sans elle, les gestionnaires rendent 501).
// =====================================================================================
#[cfg(feature = "ai")]
mod fournisseurs_d_ia_lectures_avouees {
    use super::*;

    async fn fial_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn fial_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn fial_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn fial_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn fial_attestations(st: &AppState, kind: &str) -> i64 {
        fial_entier(st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{kind}'"))
    }

    /// Un fournisseur d'IA ACTIF, posé à même la table : son identifiant.
    fn fial_fournisseur_actif(st: &AppState) -> i64 {
        fial_ecrire(
            st,
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
             VALUES('ia-fial','local','openai','http://192.0.2.10:11434','s',1,'{}',1,1);",
        );
        fial_entier(st, "SELECT id FROM ai_provider WHERE name='ia-fial'")
    }

    /// Un second fournisseur ACTIF dont la colonne `illisible` vaut le BLOB `X'00'` : la table est là, l'écriture
    /// aboutirait, seule la lecture typée (`String`) de cette colonne échoue. Son identifiant.
    fn fial_fournisseur_actif_a_cellule_illisible(st: &AppState, illisible: &str) -> i64 {
        let (name, endpoint) = match illisible {
            "endpoint" => ("'ia-fial-cellule'", "X'00'"),
            "name" => ("X'00'", "'http://192.0.2.11:11434'"),
            autre => panic!("fixture : colonne `{autre}` non prévue"),
        };
        fial_ecrire(
            st,
            &format!(
                "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
                 VALUES({name},'local','openai',{endpoint},'s',1,'{{}}',1,1);"
            ),
        );
        let id = fial_entier(st, "SELECT MAX(id) FROM ai_provider");
        assert_eq!(fial_entier(st, &format!("SELECT typeof({illisible})='blob' FROM ai_provider WHERE id={id}")), 1, "fixture : cellule BLOB");
        id
    }

    fn fial_rendre_illisible(st: &AppState) {
        fial_ecrire(st, "ALTER TABLE ai_provider RENAME TO ai_provider_hors_d_atteinte;");
    }

    fn fial_rendre(st: &AppState) {
        fial_ecrire(st, "ALTER TABLE ai_provider_hors_d_atteinte RENAME TO ai_provider;");
    }

    /// `ai_provider_update`, DÉSACTIVATION D'URGENCE : absence ÉTABLIE -> le 404 d'avant ; table hors d'atteinte ->
    /// 503 nommé, le fournisseur reste ACTIF, rien d'attesté, transaction fermée ; table rendue -> il est désactivé.
    /// Cellule `endpoint` illisible, table présente -> 503 nommé, le fournisseur reste ACTIF.
    /// Rouge sous `R3_UPD_OK`, `R3_UPD_INV`, `R3_TX_AVANT`, `U_ECRIT503`.
    #[tokio::test]
    async fn fial_desactivation_fournisseur_d_ia_non_lu_est_un_503_nomme() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("fial-ia-upd");
        let id = fial_fournisseur_actif(&st);
        let desactiver = |id: i64| {
            let st = st.clone();
            async move {
                fial_corps(ai_provider_update(State(st), Extension(fial_adm()), axum::extract::Path(id), Json(json!({ "enabled": false }))).await)
                    .await
            }
        };

        let (statut, corps) = desactiver(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "provider introuvable" })), "absence ÉTABLIE : sortie d'avant");

        fial_rendre_illisible(&st);
        let (statut, corps) = desactiver(id).await;
        let fermee = st.db.lock().is_autocommit();
        if !fermee {
            let _ = st.db.lock().execute_batch("ROLLBACK");
        }
        fial_rendre(&st);
        assert_eq!(statut, 503, "lecture non faite : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_NON_MODIFIE_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert!(fermee, "aucune transaction laissée ouverte");
        assert_eq!(fial_entier(&st, &format!("SELECT enabled FROM ai_provider WHERE id={id}")), 1, "le fournisseur reste actif");
        assert_eq!(fial_attestations(&st, "config.ai.provider.update"), 0, "aucune modification attestée");

        // (2) CELLULE illisible, table présente : une écriture tentée avant le 503 aboutirait ; elle ne doit pas avoir lieu.
        let id_cellule = fial_fournisseur_actif_a_cellule_illisible(&st, "endpoint");
        let (statut, corps) = desactiver(id_cellule).await;
        let fermee = st.db.lock().is_autocommit();
        if !fermee {
            let _ = st.db.lock().execute_batch("ROLLBACK");
        }
        assert_eq!(statut, 503, "cellule illisible : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_NON_MODIFIE_NON_LU), "cellule illisible : la cause NOMMÉE : {corps}");
        assert!(fermee, "cellule illisible : aucune transaction laissée ouverte");
        assert_eq!(
            fial_entier(&st, &format!("SELECT enabled FROM ai_provider WHERE id={id_cellule}")),
            1,
            "cellule illisible, table présente : le fournisseur reste ACTIF (aucune désactivation tentée sur une lecture ratée)"
        );
        assert_eq!(fial_attestations(&st, "config.ai.provider.update"), 0, "cellule illisible : aucune modification attestée");

        let (statut, corps) = desactiver(id).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true })), "table rendue : la désactivation a lieu, sortie d'avant");
        assert_eq!(fial_entier(&st, &format!("SELECT enabled FROM ai_provider WHERE id={id}")), 0, "le fournisseur est désactivé");
        assert_eq!(fial_attestations(&st, "config.ai.provider.update"), 1, "désactivation attestée une fois");
    }

    /// `ai_provider_delete` : absence ÉTABLIE -> le 404 d'avant ; table hors d'atteinte -> 503 nommé, le fournisseur
    /// est là et ACTIF, rien d'attesté, transaction fermée ; table rendue -> la suppression a lieu.
    /// Cellule `name` illisible, table présente -> 503 nommé, le fournisseur est toujours là et ACTIF.
    /// Rouge sous `R3_DEL_OK`, `R3_DEL_INV`, `R3_CAUSE_CROISEE`, `R3_TX_AVANT`, `D_ECRIT503`.
    #[tokio::test]
    async fn fial_suppression_fournisseur_d_ia_non_lu_est_un_503_nomme() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, _p) = sp_state("fial-ia-del");
        let id = fial_fournisseur_actif(&st);
        let supprimer = |id: i64| {
            let st = st.clone();
            async move { fial_corps(ai_provider_delete(State(st), Extension(fial_adm()), axum::extract::Path(id)).await).await }
        };

        let (statut, corps) = supprimer(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "provider introuvable" })), "absence ÉTABLIE : sortie d'avant");

        fial_rendre_illisible(&st);
        let (statut, corps) = supprimer(id).await;
        let fermee = st.db.lock().is_autocommit();
        if !fermee {
            let _ = st.db.lock().execute_batch("ROLLBACK");
        }
        fial_rendre(&st);
        assert_eq!(statut, 503, "lecture non faite : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_NON_SUPPRIME_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert!(fermee, "aucune transaction laissée ouverte");
        assert_eq!(fial_entier(&st, &format!("SELECT enabled FROM ai_provider WHERE id={id}")), 1, "le fournisseur est là et actif");
        assert_eq!(fial_attestations(&st, "config.ai.provider.delete"), 0, "aucune suppression attestée");

        // (2) CELLULE illisible, table présente : un DELETE tenté avant le 503 aboutirait ; il ne doit pas avoir lieu.
        let id_cellule = fial_fournisseur_actif_a_cellule_illisible(&st, "name");
        let (statut, corps) = supprimer(id_cellule).await;
        let fermee = st.db.lock().is_autocommit();
        if !fermee {
            let _ = st.db.lock().execute_batch("ROLLBACK");
        }
        assert_eq!(statut, 503, "cellule illisible : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_NON_SUPPRIME_NON_LU), "cellule illisible : la cause NOMMÉE : {corps}");
        assert!(fermee, "cellule illisible : aucune transaction laissée ouverte");
        assert_eq!(
            fial_entier(&st, &format!("SELECT COUNT(*) FROM ai_provider WHERE id={id_cellule} AND enabled=1")),
            1,
            "cellule illisible, table présente : le fournisseur est toujours là et actif (aucun DELETE tenté sur une lecture ratée)"
        );
        assert_eq!(fial_attestations(&st, "config.ai.provider.delete"), 0, "cellule illisible : aucune suppression attestée");

        let (statut, corps) = supprimer(id).await;
        assert_eq!(statut, 204, "table rendue : la suppression a lieu : {corps}");
        assert_eq!(fial_entier(&st, &format!("SELECT COUNT(*) FROM ai_provider WHERE id={id}")), 0, "le fournisseur est supprimé");
        assert_eq!(fial_attestations(&st, "config.ai.provider.delete"), 1, "suppression attestée une fois");
    }
}
