// =====================================================================================
// `P10.20-b` (rang quatre) — LES GESTES DE RETRAIT D'ACCÈS DISENT « NON LU » AU LIEU D'UNE FAUSSE ABSENCE :
// révocation d'un jeton (`token_delete`), désactivation ou modification d'un fournisseur d'identité
// (`idp_provider_update`), suppression d'un fournisseur (`idp_provider_delete`).
//
// VU sur `80ad700a` : `token_delete` comptait les jetons du nom par `COUNT(*) … .unwrap_or(0)` — un `COUNT(*)` rend
// toujours une ligne, donc ce zéro ne pouvait venir QUE d'une lecture ratée, et il partait en 404 « jeton
// introuvable » ; `idp_provider_update` (`.is_err()`) et `idp_provider_delete` (`.ok()`) rendaient 404 « provider
// introuvable » sur une lecture ratée — la modification est AUSSI la voie de désactivation d'urgence, ouverte sans le
// secret des gestes. Fail-closed (rien n'est retiré), mais l'administrateur lisait que le jeton ou le fournisseur
// n'existait pas alors qu'il authentifiait encore : il n'avait aucune raison de réessayer.
//
// ATTENDU, tenu ici : l'absence ÉTABLIE garde le 404 JSON d'avant OCTET POUR OCTET ; la lecture NON FAITE rend un 503
// nommé (cause du moteur au journal seulement), rien n'est écrit ni attesté, aucune transaction laissée ouverte, le
// jeton authentifie toujours, le fournisseur actif l'est toujours ; table rendue, le geste a lieu comme avant.
//
// LA LECTURE EST RENDUE ILLISIBLE sans toucher au code servi : la table (`token`, `idp_provider`) est RENOMMÉE le
// temps de l'appel, puis rendue. Aucun déclencheur ni aucune vue ne la référence (vérifié dans `migrate.rs` et
// `db/schema.sql`). Les gestionnaires sont appelés directement. La désactivation est jouée SANS le secret des gestes :
// c'est la voie d'urgence que `P10.24-m` laisse ouverte, et celle que la forme d'avant trompait.
//
// MUTATIONS (vues ROUGES puis retirées) : `M6_TOK_404`, `M6_IDPU_404`, `M6_IDPD_404` rétablissent le 404 sur la
// lecture ratée de leur site ; `M6_TOK_INV`, `M6_IDPU_INV`, `M6_IDPD_INV` inversent les deux issues (absence -> 503,
// lecture ratée -> 404). Chacune ne fait rougir que le témoin de son site.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la phrase que la console peint de ces 503 (aucun témoin de harnais) ; une
// lecture qui échoue AUTREMENT que par une table absente (verrou, corruption, interruption) — le partage est le même
// `Err`, la fabrication n'en joue qu'une ; `load_provider` et `ldap_login_post` (chemin de connexion publique, hors
// lot) ; l'UPDATE de `idp_provider_update` sur un fournisseur supprimé entre la lecture et la transaction (inchangé).
// =====================================================================================
mod gestes_de_retrait_d_acces_lectures_avouees {
    use super::*;

    async fn grad_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn grad_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn grad_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn grad_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn grad_sans_secret() -> crate::secret_des_gestes::SecretDesGestesPresente {
        crate::secret_des_gestes::SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() }
    }

    fn grad_attestations(st: &AppState, kind: &str) -> i64 {
        grad_entier(st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{kind}'"))
    }

    /// Un fournisseur OIDC ACTIF, posé à même la table : son identifiant.
    fn grad_fournisseur_actif(st: &AppState) -> i64 {
        grad_ecrire(
            st,
            "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES('idp-grad','oidc',1,'{}','s',1,1);",
        );
        grad_entier(st, "SELECT id FROM idp_provider WHERE name='idp-grad'")
    }

    /// `token_delete` : absence ÉTABLIE (compte lu à zéro) -> le 404 d'avant ; table hors d'atteinte -> 503 nommé, le
    /// jeton authentifie toujours, rien d'attesté ; table rendue -> la révocation a lieu.
    /// Rouge sous `M6_TOK_404` (404 sur la lecture ratée) et `M6_TOK_INV` (503 sur l'absence).
    #[tokio::test]
    async fn grad_revocation_jetons_non_comptes_est_un_503_nomme() {
        let (st, _p) = sp_state("grad-jeton");
        let (statut, corps) = grad_corps(
            token_create(
                State(st.clone()),
                crate::secret_des_gestes::presente_de_test(),
                Extension(grad_adm()),
                Json(json!({ "name": "ag-grad", "kind": "agent", "host": "h-grad" })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : jeton frappé : {corps}");
        let secret = corps["token"].as_str().expect("secret montré une fois").to_string();
        let revoquer = |nom: &'static str| {
            let st = st.clone();
            async move { grad_corps(token_delete(State(st), Extension(grad_adm()), axum::extract::Path(nom.to_string())).await).await }
        };

        let (statut, corps) = revoquer("ag-inconnu").await;
        assert_eq!((statut, corps), (404, json!({ "error": "jeton introuvable" })), "absence ÉTABLIE : sortie d'avant");

        grad_ecrire(&st, "ALTER TABLE token RENAME TO token_hors_d_atteinte;");
        let (statut, corps) = revoquer("ag-grad").await;
        let fermee = st.db.lock().is_autocommit();
        grad_ecrire(&st, "ALTER TABLE token_hors_d_atteinte RENAME TO token;");
        assert_eq!(statut, 503, "lecture non faite : pas « jeton introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_JETON_NON_REVOQUE_JETONS_NON_COMPTES), "le refus NOMME sa cause : {corps}");
        assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert!(fermee, "aucune transaction laissée ouverte");
        assert!(token_lookup(&st, &secret).is_some(), "le jeton authentifie toujours, comme la cause le dit");
        assert_eq!(grad_entier(&st, "SELECT COUNT(*) FROM token WHERE name='ag-grad'"), 1, "la ligne est là");
        assert_eq!(grad_attestations(&st, "config.token.revoke"), 0, "aucune révocation attestée");

        let (statut, corps) = revoquer("ag-grad").await;
        assert_eq!(statut, 204, "table rendue : la révocation a lieu : {corps}");
        assert!(token_lookup(&st, &secret).is_none(), "et le jeton n'authentifie plus");
        assert_eq!(grad_attestations(&st, "config.token.revoke"), 1, "révocation attestée une fois");
    }

    /// `idp_provider_update`, DÉSACTIVATION D'URGENCE sans le secret des gestes : absence ÉTABLIE -> le 404 d'avant ;
    /// table hors d'atteinte -> 503 nommé, le fournisseur reste ACTIF, rien d'attesté ; table rendue -> il est désactivé.
    /// Rouge sous `M6_IDPU_404` (404 sur la lecture ratée) et `M6_IDPU_INV` (503 sur l'absence).
    #[tokio::test]
    async fn grad_desactivation_fournisseur_non_lu_est_un_503_nomme() {
        let (st, _p) = sp_state("grad-idp-upd");
        let id = grad_fournisseur_actif(&st);
        let desactiver = |id: i64| {
            let st = st.clone();
            async move {
                grad_corps(
                    idp_provider_update(State(st), grad_sans_secret(), Extension(grad_adm()), axum::extract::Path(id), Json(json!({ "enabled": false })))
                        .await,
                )
                .await
            }
        };

        let (statut, corps) = desactiver(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "provider introuvable" })), "absence ÉTABLIE : sortie d'avant");

        grad_ecrire(&st, "ALTER TABLE idp_provider RENAME TO idp_provider_hors_d_atteinte;");
        let (statut, corps) = desactiver(id).await;
        let fermee = st.db.lock().is_autocommit();
        grad_ecrire(&st, "ALTER TABLE idp_provider_hors_d_atteinte RENAME TO idp_provider;");
        assert_eq!(statut, 503, "lecture non faite : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IDENTITE_NON_MODIFIE_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert!(fermee, "aucune transaction laissée ouverte");
        assert_eq!(grad_entier(&st, &format!("SELECT enabled FROM idp_provider WHERE id={id}")), 1, "le fournisseur reste actif");
        assert_eq!(grad_attestations(&st, "config.idp.update"), 0, "aucune modification attestée");

        let (statut, corps) = desactiver(id).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true })), "table rendue : la désactivation a lieu, sortie d'avant");
        assert_eq!(grad_entier(&st, &format!("SELECT enabled FROM idp_provider WHERE id={id}")), 0, "le fournisseur est désactivé");
        assert_eq!(grad_attestations(&st, "config.idp.update"), 1, "désactivation attestée une fois");
    }

    /// `idp_provider_delete` : absence ÉTABLIE -> le 404 d'avant ; table hors d'atteinte -> 503 nommé, le fournisseur
    /// est là et ACTIF, rien d'attesté ; table rendue -> la suppression a lieu.
    /// Rouge sous `M6_IDPD_404` (404 sur la lecture ratée) et `M6_IDPD_INV` (503 sur l'absence).
    #[tokio::test]
    async fn grad_suppression_fournisseur_non_lu_est_un_503_nomme() {
        let (st, _p) = sp_state("grad-idp-del");
        let id = grad_fournisseur_actif(&st);
        let supprimer = |id: i64| {
            let st = st.clone();
            async move { grad_corps(idp_provider_delete(State(st), Extension(grad_adm()), axum::extract::Path(id)).await).await }
        };

        let (statut, corps) = supprimer(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "provider introuvable" })), "absence ÉTABLIE : sortie d'avant");

        grad_ecrire(&st, "ALTER TABLE idp_provider RENAME TO idp_provider_hors_d_atteinte;");
        let (statut, corps) = supprimer(id).await;
        let fermee = st.db.lock().is_autocommit();
        grad_ecrire(&st, "ALTER TABLE idp_provider_hors_d_atteinte RENAME TO idp_provider;");
        assert_eq!(statut, 503, "lecture non faite : pas « provider introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IDENTITE_NON_SUPPRIME_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(!corps.to_string().contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert!(fermee, "aucune transaction laissée ouverte");
        assert_eq!(grad_entier(&st, &format!("SELECT enabled FROM idp_provider WHERE id={id}")), 1, "le fournisseur est là et actif");
        assert_eq!(grad_attestations(&st, "config.idp.delete"), 0, "aucune suppression attestée");

        let (statut, corps) = supprimer(id).await;
        assert_eq!(statut, 204, "table rendue : la suppression a lieu : {corps}");
        assert_eq!(grad_entier(&st, "SELECT COUNT(*) FROM idp_provider"), 0, "le fournisseur est supprimé");
        assert_eq!(grad_attestations(&st, "config.idp.delete"), 1, "suppression attestée une fois");
    }
}
