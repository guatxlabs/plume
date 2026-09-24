// =====================================================================================
// `P10.26-a` — SÉCURITÉ : LE `COMMIT` DES CONNECTEURS EST JUGÉ. La suppression d'un connecteur est la révocation de ses
//              clés de livraison (le geste que `DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME` prescrit pour une clé
//              conservée) ; la création et la modification (rotation du secret, désactivation) suivent la même règle.
// `P10.26-b` — CONFIDENTIALITÉ : LE `COMMIT` DE LA POLITIQUE DE CAVIARDAGE ET DES FOURNISSEURS D'IA EST JUGÉ.
// `P10.26-c` — INTÉGRITÉ : LE `COMMIT` DES GELS JURIDIQUES ET DES PUITS D'EXPORT DU REGISTRE EST JUGÉ.
//
// Un refus rend un 503 dont la cause dit ce qui est TOUJOURS en place, ferme la transaction (`valider_la_transaction`
// annule), et rien n'est rendu, révoqué ni servi avant.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré ;
// `COMMIT` refusé par un autorisateur SQLite, « à froid » = une connexion neuve sur le même fichier, ce qu'un
// redémarrage relit). Les onze gestes ignoraient leur `COMMIT` et laissaient la transaction PENDANTE sur l'écrivain
// partagé : tout ce qui lit par cet écrivain agissait sur un état que la base n'avait pas pris, et un geste suivant qui
// ouvre sa propre transaction échouait en 500 « verrou base indisponible ».
//  * connecteurs : la suppression d'une source push rendait 204, sa clé de livraison était refusée tant que la
//    transaction pendait, le connecteur et la clé étaient là à froid, et la clé AUTHENTIFIAIT de nouveau dès la
//    transaction annulée ; la création rendait 200 et un identifiant, le connecteur actif était sélectionné comme DÛ par
//    la collecte (aucune ligne à froid) ; la désactivation avec rotation du secret rendait 200, désactivé et nouveau
//    secret pour ce processus, ACTIF avec l'ANCIEN secret à froid ;
//  * IA : la politique v2 rendait 200, était SERVIE par `GET /api/ai/redaction-policy` et APPLIQUÉE au schéma envoyé au
//    modèle, sans ligne à froid ; un fournisseur créé était actif pour `ai_status` sans ligne à froid ; désactivé (200)
//    ou supprimé (204), il était actif à froid ;
//  * gouvernance : un gel posé rendait 200 `active: true`, respecté par la rétention de ce processus, absent à froid ;
//    un gel levé rendait 200 `active: false`, la rétention de ce processus PURGEAIT la preuve gelée, et le `COMMIT` de
//    `rollup_hosts` — qui ignore l'échec de son propre `BEGIN` — rendait DURABLES la levée ET la purge ; un puits créé
//    rendait 200 et un envoi exportait vers lui des maillons du registre jamais validés (dont la trace de sa création),
//    aucun puits à froid ; un puits supprimé rendait 200, toujours déclaré à froid.
//
// CE QUE L'ÉNONCÉ DE `P10.26-b` DISAIT MAL : la politique de caviardage gouverne les NOMS DE CHAMP du schéma envoyé au
// modèle, pas des données ; une politique perdue laisse sortir des noms de champ, jamais une valeur d'événement.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les témoins de `P10.26-b` ne sont compilés que sous `--features ai`, qu'aucun job
// de la CI ne compile en mode test (`cargo check --features ai` sans `--tests`) — ils ne comptent ni dans
// `EXPECTED_TESTS` ni dans `EXPECTED_COLD_TESTS` et ont été joués à la main ; les sept chemins qui ignorent l'échec de
// leur `BEGIN` puis valident (ou annulent) une transaction ÉTRANGÈRE restent tels quels ; le mode multi-tenant (écrivain
// du tenant) et un `COMMIT` que SQLite annule de lui-même (disque plein, E/S) ne sont pas joués (`P10.26-h`) ; le
// curseur d'un envoi de puits (`ledger_sink_flush`) avance toujours par une écriture avalée ; aucun module de `web/`
// n'est exercé ici.
// =====================================================================================
mod commit_juge_connecteurs_ia_et_gouvernance {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// `COMMIT` (et `END`) refusés sur l'écrivain partagé ; `BEGIN` et `ROLLBACK` restent permis.
    fn cjcg_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cjcg_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn cjcg_transaction_fermee(st: &AppState) -> bool {
        st.db.lock().is_autocommit()
    }

    async fn cjcg_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn cjcg_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    /// Ce que le processus lit, sur l'écrivain partagé.
    fn cjcg_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn cjcg_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    /// Un secret de connecteur fabriqué (aucun littéral dans la fixture).
    fn cjcg_secret(lettre: char) -> String {
        format!("cjcg-{}", lettre.to_string().repeat(24))
    }

    const CJCG_TAXII: &str = r#"{"api_root":"https://taxii.cjcg.example/api","collection_id":"cjcg"}"#;

    // -------------------------------------------------------------------------------------
    // (1) `P10.26-a` — UN COMMIT REFUSÉ NE SUPPRIME AUCUN CONNECTEUR ET NE RÉVOQUE AUCUNE CLÉ DE LIVRAISON EN MÉMOIRE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une source push Firehose et sa clé de livraison, qui authentifie sur son récepteur. `COMMIT`
    /// refusé, la suppression rend 503 nommé (`CAUSE_CONNECTEUR_NON_SUPPRIME`), la transaction est fermée, la clé
    /// AUTHENTIFIE toujours (comme la cause le dit), le connecteur et la clé sont là à froid, et aucune suppression n'est
    /// attestée. Levé, 204 : la clé est refusée, ni connecteur ni clé, ici comme à froid.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : ignorer le `COMMIT` de `connector_delete` (la forme d'avant) — 204.
    #[tokio::test]
    async fn cjcg_un_commit_refuse_ne_supprime_aucun_connecteur_ni_ne_revoque_sa_cle_de_livraison() {
        let (st, p) = sp_state("cjcg-suppression");
        let (statut, corps) =
            cjcg_corps(connector_push_source(State(st.clone()), Extension(cjcg_adm()), Json(json!({ "preset_id": "aws-cloudtrail" }))).await).await;
        assert_eq!(statut, 200, "fixture : source push : {corps}");
        let cle = corps["delivery_key"].as_str().expect("clé montrée une fois").to_string();
        let id = corps["connector_id"].as_i64().expect("connecteur");
        assert_eq!(firehose_token_lookup(&st, &cle).map(|i| i.connector_id), Some(id), "fixture : la clé authentifie");
        let supprimer = |st: AppState| async move {
            cjcg_corps(connector_delete(State(st), Extension(cjcg_adm()), axum::extract::Path(id)).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = supprimer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne supprime aucun connecteur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_CONNECTEUR_NON_SUPPRIME), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(firehose_token_lookup(&st, &cle).map(|i| i.connector_id), Some(id), "la clé authentifie toujours, comme la cause le dit");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM connector"), 1, "le connecteur est là au redémarrage");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM token WHERE kind='firehose'"), 1, "et sa clé aussi");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.delete'"), 0, "aucune suppression attestée");

        let (statut, corps) = supprimer(st.clone()).await;
        assert_eq!(statut, 204, "levé, la suppression a lieu : {corps}");
        assert!(firehose_token_lookup(&st, &cle).is_none(), "la clé est révoquée");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM connector"), 0, "ni connecteur");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM token"), 0, "ni clé, au redémarrage");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.26-a` — UN COMMIT REFUSÉ NE CRÉE AUCUN CONNECTEUR, NE LE DÉSACTIVE PAS ET NE REMPLACE PAS SON SECRET
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `COMMIT` refusé, la création d'un connecteur TAXII actif rend 503 nommé sans identifiant,
    /// transaction fermée, aucun connecteur (ni « dû » pour la collecte), aucune trace. Levé, 200. Sur ce connecteur,
    /// la désactivation avec rotation du secret rend 503 nommé, transaction fermée, et le connecteur est ACTIF avec
    /// l'ANCIEN secret, ici et à froid, sans trace. Levé, 200 : désactivé, nouveau secret.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `connector_create` — 200 et un identifiant ; celui de
    /// `connector_update` — 200.
    #[tokio::test]
    async fn cjcg_un_commit_refuse_ne_cree_ni_ne_modifie_aucun_connecteur() {
        let (st, p) = sp_state("cjcg-connecteurs");
        let config: Value = serde_json::from_str(CJCG_TAXII).expect("config TAXII");
        let (ancien, nouveau) = (cjcg_secret('a'), cjcg_secret('b'));
        let creer = |st: AppState| {
            let corps = json!({ "type": "taxii2", "name": "cjcg", "enabled": true, "secret": ancien.clone(), "config": config.clone() });
            async move { cjcg_corps(connector_create(State(st), Extension(cjcg_adm()), Json(corps)).await).await }
        };
        let dus = "SELECT COUNT(*) FROM connector WHERE enabled=1 AND type NOT IN ('aws_firehose','gcp_pubsub')";

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun connecteur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_CONNECTEUR_NON_CREE), "{corps}");
        assert!(corps["id"].as_i64().is_none(), "aucun identifiant de ligne rendu (seul celui de l'erreur) : {corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(cjcg_compte(&st, dus), 0, "aucun connecteur dû pour la collecte de ce processus");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.create'"), 0, "aucune création attestée");

        let (statut, corps) = creer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la création a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        let modifier = |st: AppState| {
            let corps = json!({ "enabled": false, "secret": nouveau.clone() });
            async move { cjcg_corps(connector_update(State(st), Extension(cjcg_adm()), axum::extract::Path(id), Json(corps)).await).await }
        };
        let etat = |secret: &str| format!("SELECT enabled * 10 + (secret = '{secret}') FROM connector WHERE id={id}");

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = modifier(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne modifie aucun connecteur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_CONNECTEUR_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la modification est fermée");
        assert_eq!(cjcg_compte(&st, &etat(&ancien)), 11, "actif, ancien secret, pour ce processus");
        assert_eq!(cjcg_a_froid(&p, &etat(&ancien)), 11, "et au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.update'"), 0, "aucune modification attestée");

        let (statut, corps) = modifier(st.clone()).await;
        assert_eq!(statut, 200, "levé, la modification a lieu : {corps}");
        assert_eq!(cjcg_a_froid(&p, &etat(&nouveau)), 1, "désactivé, nouveau secret");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.26-b` — UN COMMIT REFUSÉ NE POSE AUCUNE POLITIQUE DE CAVIARDAGE, NI SERVIE NI APPLIQUÉE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT (`--features ai`) : la politique v1 par défaut laisse `src_user` dans le schéma envoyé au modèle.
    /// `COMMIT` refusé, la pose d'une v2 qui ÉLARGIT le caviardage à `user` rend 503 nommé, transaction fermée ; la
    /// politique SERVIE est v1, la politique APPLIQUÉE laisse `src_user` (comme la cause le dit), aucune ligne à froid,
    /// aucune trace. Levé, 200 : v2 servie, `src_user` retiré.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : ignorer le `COMMIT` de `ai_redaction_policy_put` — 200 `version: 2`.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn cjcg_un_commit_refuse_ne_pose_aucune_politique_de_caviardage() {
        let (st, p) = sp_state("cjcg-caviardage");
        let champs = vec!["src_user".to_string(), "src_ip".to_string()];
        let applique = |st: &AppState| guatx_core::ai::redact_fields(&champs, &active_redaction_policy(&st.db.lock()).0);
        let servie = |st: AppState| async move { cjcg_corps(ai_redaction_policy_get(State(st), Extension(cjcg_adm())).await).await.1["version"].clone() };
        assert_eq!(applique(&st), champs, "fixture : v1 laisse les deux noms");
        let mut deny = guatx_core::ai::default_redaction_policy().deny_substr;
        deny.push("user".to_string());
        let poser = |st: AppState| {
            let corps = json!({ "version": 2, "deny_substr": deny.clone() });
            async move { cjcg_corps(ai_redaction_policy_put(State(st), Extension(cjcg_adm()), Json(corps)).await).await }
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = poser(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne pose aucune politique : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_POLITIQUE_DE_CAVIARDAGE_INCHANGEE), "{corps}");
        assert!(fermee, "la transaction de la pose est fermée");
        assert_eq!(servie(st.clone()).await, json!(1), "la politique servie est celle d'avant");
        assert_eq!(applique(&st), champs, "et la politique appliquée laisse toujours `src_user`, comme la cause le dit");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM meta WHERE key='ai_redaction_policy'"), 0, "rien au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ai.redaction_policy'"), 0, "aucune pose attestée");

        let (statut, corps) = poser(st.clone()).await;
        assert_eq!(statut, 200, "levé, la pose a lieu : {corps}");
        assert_eq!(servie(st.clone()).await, json!(2), "v2 servie");
        assert_eq!(applique(&st), vec!["src_ip".to_string()], "et `src_user` retiré du schéma");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.26-b` — UN COMMIT REFUSÉ LAISSE LES FOURNISSEURS D'IA INTACTS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT (`--features ai`) : `COMMIT` refusé, la création d'un fournisseur actif rend 503 nommé sans
    /// identifiant, aucun fournisseur pour `ai_status`. Levé, 200. Sur ce fournisseur actif, la désactivation puis la
    /// suppression rendent 503 nommé, transaction fermée, il est actif pour `ai_status` et à froid, sans trace. Levé,
    /// la désactivation et la suppression ont lieu.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `ai_provider_create` — 200 ; de `ai_provider_update`
    /// — 200 ; de `ai_provider_delete` — 204.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn cjcg_un_commit_refuse_laisse_les_fournisseurs_d_ia_intacts() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("cjcg-fournisseurs-ia");
        let creer = |st: AppState| async move {
            let corps = json!({ "name": "cjcg-local", "endpoint": "http://127.0.0.1:11434", "enabled": true, "config": { "model": "cjcg" } });
            cjcg_corps(ai_provider_create(State(st), Extension(cjcg_adm()), Json(corps)).await).await
        };
        let actif = |st: AppState| async move { cjcg_corps(ai_status(State(st), Extension(cjcg_adm())).await).await.1["has_provider"].clone() };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun fournisseur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_INCHANGE), "{corps}");
        assert!(corps["id"].as_i64().is_none(), "aucun identifiant de ligne rendu (seul celui de l'erreur) : {corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(actif(st.clone()).await, json!(false), "aucun fournisseur actif pour ce processus");

        let (statut, corps) = creer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la création a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        let desactiver = |st: AppState| async move {
            cjcg_corps(ai_provider_update(State(st), Extension(cjcg_adm()), axum::extract::Path(id), Json(json!({ "enabled": false }))).await).await
        };
        let supprimer = |st: AppState| async move {
            cjcg_corps(ai_provider_delete(State(st), Extension(cjcg_adm()), axum::extract::Path(id)).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = desactiver(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne désactive aucun fournisseur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la désactivation est fermée");
        assert_eq!(actif(st.clone()).await, json!(true), "toujours actif pour ce processus, comme la cause le dit");
        assert_eq!(cjcg_a_froid(&p, "SELECT enabled FROM ai_provider"), 1, "et au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ai.provider.update'"), 0, "aucune trace");

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = supprimer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne supprime aucun fournisseur : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_FOURNISSEUR_D_IA_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(actif(st.clone()).await, json!(true), "toujours actif pour ce processus");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM ai_provider WHERE enabled=1"), 1, "et au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ai.provider.delete'"), 0, "aucune trace");

        let (statut, corps) = desactiver(st.clone()).await;
        assert_eq!(statut, 200, "levé, la désactivation a lieu : {corps}");
        assert_eq!(actif(st.clone()).await, json!(false), "plus aucun fournisseur actif");
        let (statut, corps) = supprimer(st.clone()).await;
        assert_eq!(statut, 204, "levé, la suppression a lieu : {corps}");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM ai_provider"), 0, "supprimé");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.26-c` — UN COMMIT REFUSÉ NE POSE NI NE LÈVE AUCUN GEL JURIDIQUE, ET LA RÉTENTION LE SAIT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une preuve `sshd` de quarante jours, rétention à sept. `COMMIT` refusé, la pose d'un gel sur
    /// `sshd` rend 503 nommé, transaction fermée, aucun gel ici ni à froid, la preuve n'est pas gelée, aucune trace.
    /// Levé, 200 et la preuve est gelée. `COMMIT` refusé, la levée rend 503 nommé, transaction fermée, le gel est actif
    /// ici et à froid, sans trace, et une passe de rétention NE PURGE PAS la preuve (comme la cause le dit). Levé, 200,
    /// et la rétention suivante la purge.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `legal_hold_create` — 200 `active: true` ; celui de
    /// `legal_hold_release` — 200 `active: false`, et la rétention purge la preuve gelée.
    #[tokio::test]
    async fn cjcg_un_commit_refuse_ne_pose_ni_ne_leve_aucun_gel_juridique() {
        // `retention_run` relit l'environnement du processus (`PLUME_COLD_TIER`) : même verrou que ses autres témoins.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("cjcg-gels");
        let vieux = now() - 40 * 86400;
        {
            let c = st.db.lock();
            c.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).expect("fixture : rétention");
            c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','preuve cjcg','')", params![vieux]).expect("fixture : preuve");
        }
        let preuves = "SELECT COUNT(*) FROM event WHERE source='sshd'";
        let poser = |st: AppState| async move {
            cjcg_corps(legal_hold_create(State(st), Extension(cjcg_adm()), Json(json!({ "name": "litige-cjcg", "scope_source": "sshd" }))).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = poser(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne pose aucun gel : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_GEL_JURIDIQUE_NON_POSE), "{corps}");
        assert!(fermee, "la transaction de la pose est fermée");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM legal_hold"), 0, "aucun gel pour ce processus");
        assert!(!event_is_held(&st.db.lock(), "sshd", vieux), "la preuve n'est pas gelée, comme la cause le dit");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM legal_hold"), 0, "ni au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.legal_hold.create'"), 0, "aucune pose attestée");

        let (statut, corps) = poser(st.clone()).await;
        assert_eq!(statut, 200, "levé, la pose a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        assert!(event_is_held(&st.db.lock(), "sshd", vieux), "fixture : la preuve est gelée");
        let lever = |st: AppState| async move {
            cjcg_corps(legal_hold_release(State(st), Extension(cjcg_adm()), axum::extract::Path(id)).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = lever(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne lève aucun gel : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_GEL_JURIDIQUE_NON_LEVE), "{corps}");
        assert!(fermee, "la transaction de la levée est fermée");
        assert!(event_is_held(&st.db.lock(), "sshd", vieux), "le gel tient pour ce processus");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM legal_hold WHERE active=1"), 1, "et au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.legal_hold.release'"), 0, "aucune levée attestée");
        retention_run(&st.db);
        assert_eq!(cjcg_compte(&st, preuves), 1, "la rétention ne purge pas la preuve gelée");
        assert_eq!(cjcg_a_froid(&p, preuves), 1, "ni à froid");

        let (statut, corps) = lever(st.clone()).await;
        assert_eq!(statut, 200, "levé, la levée a lieu : {corps}");
        retention_run(&st.db);
        assert_eq!(cjcg_a_froid(&p, preuves), 0, "et la rétention suivante purge la portée");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.26-c` — UN COMMIT REFUSÉ NE CRÉE NI NE RETIRE AUCUN PUITS D'EXPORT, ET NE LAISSE AUCUN MAILLON LISIBLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `COMMIT` refusé, la création d'un puits rend 503 nommé sans identifiant, transaction fermée,
    /// aucun puits, aucune trace — et le registre que lit un envoi (`ledger_sink_flush`, sur l'écrivain) n'a AUCUN
    /// maillon de plus que le registre à froid. Levé, 200. `COMMIT` refusé, la suppression rend 503 nommé, transaction
    /// fermée, le puits est là ici et à froid, sans trace. Levé, la suppression a lieu.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : ignorer le `COMMIT` de `ledger_sink_create` — 200 et un identifiant ; celui de
    /// `ledger_sink_delete` — 200.
    #[tokio::test]
    async fn cjcg_un_commit_refuse_ne_cree_ni_ne_retire_aucun_puits_du_registre() {
        let (st, p) = sp_state("cjcg-puits");
        let dernier_maillon = "SELECT COALESCE(MAX(id), 0) FROM ledger";
        let creer = |st: AppState| async move {
            cjcg_corps(ledger_sink_create(State(st), Extension(cjcg_adm()), Json(json!({ "name": "puits-cjcg", "kind": "stdout" }))).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = creer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne crée aucun puits : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_PUITS_DU_REGISTRE_INCHANGE), "{corps}");
        assert!(corps["id"].as_i64().is_none(), "aucun identifiant de ligne rendu (seul celui de l'erreur) : {corps}");
        assert!(fermee, "la transaction de la création est fermée");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger_sink"), 0, "aucun puits pour ce processus");
        assert_eq!(cjcg_compte(&st, dernier_maillon), cjcg_a_froid(&p, dernier_maillon), "aucun maillon non validé n'est lisible par un envoi");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ledger_sink.create'"), 0, "aucune création attestée");

        let (statut, corps) = creer(st.clone()).await;
        assert_eq!(statut, 200, "levé, la création a lieu : {corps}");
        let id = corps["id"].as_i64().expect("identifiant");
        let supprimer = |st: AppState| async move {
            cjcg_corps(ledger_sink_delete(State(st), Extension(cjcg_adm()), axum::extract::Path(id)).await).await
        };

        cjcg_refuser_le_commit(&st);
        let (statut, corps) = supprimer(st.clone()).await;
        let fermee = cjcg_transaction_fermee(&st);
        cjcg_lever_l_autorisateur(&st);
        assert_eq!(statut, 503, "un COMMIT refusé ne retire aucun puits : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_PUITS_DU_REGISTRE_INCHANGE), "{corps}");
        assert!(fermee, "la transaction de la suppression est fermée");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger_sink"), 1, "le puits est déclaré pour ce processus");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM ledger_sink"), 1, "et au redémarrage");
        assert_eq!(cjcg_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ledger_sink.delete'"), 0, "aucun retrait attesté");

        let (statut, corps) = supprimer(st.clone()).await;
        assert_eq!(statut, 200, "levé, le retrait a lieu : {corps}");
        assert_eq!(cjcg_a_froid(&p, "SELECT COUNT(*) FROM ledger_sink"), 0, "retiré");
    }
}
