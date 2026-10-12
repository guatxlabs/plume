// =====================================================================================
// `P10.20-b` (rang quatre) — LA CLÔTURE D'UN ENGAGEMENT, LA SUPPRESSION ET LA MODIFICATION D'UN COMPTE DISENT
// « NON LU » AU LIEU D'UNE FAUSSE ABSENCE OU D'UN FAUX « DERNIER ADMINISTRATEUR ».
//
// VU sur `824949d` : `engagement_end` lisait l'engagement par `query_row(..).is_ok()` — une lecture NON FAITE rendait
// 404 « engagement introuvable ou déjà clos » alors que la fenêtre de permis restait ouverte ; `user_delete` et
// `user_update` lisaient la cible par `.ok()` (404 « compte introuvable ») et le compte d'administrateurs par
// `.unwrap_or(0)` (zéro ≤ 1 : « dernier administrateur » affirmé sans lecture). Fail-closed, cause FAUSSE.
//
// ATTENDU, tenu ici : l'absence ÉTABLIE garde la sortie d'avant OCTET POUR OCTET (404 JSON pour l'engagement, 404
// texte pour le compte, 400 texte « dernier administrateur » quand le compte est LU et vaut ≤ 1) ; la lecture NON
// FAITE rend un 503 nommé, rien n'est écrit ni attesté, l'engagement n'est PAS dit clos (son exemption reste posée,
// sa crédence authentifie).
//
// LA LECTURE EST RENDUE ILLISIBLE sans toucher au code servi : la table est RENOMMÉE (engagement, user), ou `user`
// est remplacée par une VUE dont la colonne `role` ÉCHOUE (`json()` sur un texte malformé) pour la seule ligne de
// `bob` — la lecture de la cible par identifiant passe, le `COUNT(*) … WHERE role='admin'` échoue. Jamais un trigger
// sur SELECT. Les gestionnaires sont appelés directement : renommer `user` casserait l'authentification d'une route.
//
// MUTATIONS (vues ROUGES puis retirées) : les mutants `J4_ENG`, `J4_DEL_CIBLE`, `J4_DEL_ADM`, `J4_UPD_CIBLE`,
// `J4_UPD_ADM` rétablissent le repli d'avant (`.ok()`, `.unwrap_or(0)`) sur leur site.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la phrase que la console peint de ces 503 (aucun témoin de harnais) ;
// `engagement_cred_within_window` (authentification d'une crédence de pentest sur lecture ratée : refus sans cause
// nommée) ; l'anti-verrouillage relu DANS la transaction de `user_update`, qui propageait déjà par `?`.
// =====================================================================================
mod cloture_et_comptes_lectures_avouees {
    use super::*;

    async fn lcca_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn lcca_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn lcca_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn lcca_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn lcca_id(st: &AppState, nom: &str) -> i64 {
        lcca_entier(st, &format!("SELECT id FROM user WHERE name='{nom}'"))
    }

    /// Un second administrateur, `adm2` : la suppression ou la rétrogradation de l'un des deux est permise.
    fn lcca_second_admin(st: &AppState) -> i64 {
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('adm2',?1,'admin')", params![hash_pw("motdepasse12345").unwrap()])
            .expect("fixture : adm2 posé");
        lcca_id(st, "adm2")
    }

    /// `user` remplacée par une vue dont `role` échoue pour la seule ligne de `bob` : la cible lue par identifiant
    /// passe, le compte des administrateurs échoue.
    fn lcca_administrateurs_illisibles(st: &AppState) {
        lcca_ecrire(
            st,
            "ALTER TABLE user RENAME TO user_reel;
             CREATE VIEW user AS SELECT id, name, hash, CASE WHEN name='bob' THEN json(name || '{') ELSE role END AS role, created FROM user_reel;",
        );
    }

    fn lcca_administrateurs_lisibles(st: &AppState) {
        lcca_ecrire(st, "DROP VIEW user; ALTER TABLE user_reel RENAME TO user;");
    }

    async fn lcca_supprimer(st: &AppState, auteur: &str, id: i64) -> (u16, Value) {
        lcca_corps(user_delete(State(st.clone()), Extension(sp_au(auteur, "admin")), axum::extract::Path(id)).await).await
    }

    async fn lcca_retrograder(st: &AppState, auteur: &str, id: i64) -> (u16, Value) {
        let pair: std::net::SocketAddr = "10.78.0.1:45454".parse().expect("adresse de test");
        lcca_corps(
            user_update(
                State(st.clone()),
                crate::secret_des_gestes::presente_de_test(),
                ConnectInfo(pair),
                Extension(sp_au(auteur, "admin")),
                axum::extract::Path(id),
                Json(json!({ "role": "viewer" })),
            )
            .await,
        )
        .await
    }

    fn lcca_attestations(st: &AppState, kind: &str) -> i64 {
        lcca_entier(st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{kind}'"))
    }

    /// `engagement_end` : absence ÉTABLIE -> le 404 d'avant ; table hors d'atteinte -> 503 nommé, l'engagement court
    /// toujours (statut, crédence, exemption), rien d'attesté ; table rendue -> la clôture a lieu.
    /// Rouge sous `J4_ENG` (404 « déjà clos »).
    #[tokio::test]
    async fn lcca_cloture_lecture_ratee_ne_dit_pas_l_engagement_clos() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("lcca-engagement");
        let chemin = st.db_path.as_str().to_string();
        let corps = json!({ "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "lcca", "window_end": now() + 3600 });
        let (statut, cree) = lcca_corps(
            engagement_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sp_au("adm", "admin")), Json(corps)).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : engagement créé : {cree}");
        let id = cree["id"].as_str().expect("identifiant").to_string();
        let credence = &cree["credentials"][0];
        let nom = credence["username"].as_str().expect("compte frappé").to_string();
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{}", credence["secret"].as_str().expect("secret montré")))
        );
        assert!(ip_in_active_engagement("198.51.100.9", &chemin), "fixture : exemption posée");
        let clore = |id: String| {
            let st = st.clone();
            async move { lcca_corps(engagement_end(State(st), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await).await }
        };

        let (statut, corps) = clore("pas-un-engagement".into()).await;
        assert_eq!((statut, corps), (404, json!({ "error": "engagement introuvable ou déjà clos" })), "absence ÉTABLIE : sortie d'avant");

        lcca_ecrire(&st, "ALTER TABLE engagement RENAME TO engagement_hors_d_atteinte;");
        let (statut, corps) = clore(id.clone()).await;
        lcca_ecrire(&st, "ALTER TABLE engagement_hors_d_atteinte RENAME TO engagement;");
        assert_eq!(statut, 503, "lecture non faite : pas « déjà clos » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_ENGAGEMENT_NON_CLOS_ETAT_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(!corps["error"].as_str().unwrap_or("").contains("no such table"), "l'erreur du moteur reste au journal : {corps}");
        assert_eq!(lcca_texte(&st, &format!("SELECT status FROM engagement WHERE id='{id}'")), "active", "l'engagement court");
        assert_eq!(authenticate(&st, &basic), Some((nom.clone(), "viewer".to_string())), "sa crédence authentifie");
        assert!(ip_in_active_engagement("198.51.100.9", &chemin), "son exemption reste posée");
        assert_eq!(lcca_attestations(&st, "config.engagement.end"), 0, "aucune clôture attestée");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");

        let (statut, corps) = clore(id.clone()).await;
        assert_eq!(statut, 200, "table rendue : la clôture a lieu : {corps}");
        assert_eq!(authenticate(&st, &basic), None, "la crédence est révoquée");
        assert!(!ip_in_active_engagement("198.51.100.9", &chemin), "l'exemption est levée");
        eng_test_reset();
    }

    /// `user_delete`, la cible : absence ÉTABLIE -> le 404 texte d'avant ; table hors d'atteinte -> 503 nommé, rien de
    /// supprimé ni d'attesté. Rouge sous `J4_DEL_CIBLE` (404 « compte introuvable »).
    #[tokio::test]
    async fn lcca_suppression_cible_non_lue_est_un_503_nomme() {
        let (st, _p) = sp_state("lcca-del-cible");
        let bob = lcca_id(&st, "bob");
        let (statut, corps) = lcca_supprimer(&st, "adm", 999_999).await;
        assert_eq!((statut, corps), (404, json!("compte introuvable")), "absence ÉTABLIE : sortie d'avant");

        lcca_ecrire(&st, "ALTER TABLE user RENAME TO user_hors_d_atteinte;");
        let (statut, corps) = lcca_supprimer(&st, "adm", bob).await;
        lcca_ecrire(&st, "ALTER TABLE user_hors_d_atteinte RENAME TO user;");
        assert_eq!(statut, 503, "lecture non faite : pas « compte introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_SUPPRIME_CIBLE_NON_LUE), "{corps}");
        assert_eq!(lcca_entier(&st, "SELECT COUNT(*) FROM user WHERE name='bob'"), 1, "bob est là");
        assert_eq!(lcca_attestations(&st, "config.user.delete"), 0, "aucune suppression attestée");

        let (statut, corps) = lcca_supprimer(&st, "adm", bob).await;
        assert_eq!(statut, 200, "table rendue : la suppression a lieu : {corps}");
    }

    /// `user_delete`, le compte d'administrateurs : non compté -> 503 nommé (pas « dernier administrateur »), rien de
    /// supprimé ; compté et ≤ 1 -> le 400 texte d'avant ; compté à deux -> la suppression a lieu.
    /// Rouge sous `J4_DEL_ADM` (400 « dernier administrateur »).
    #[tokio::test]
    async fn lcca_suppression_administrateurs_non_comptes_est_un_503_nomme() {
        let (st, _p) = sp_state("lcca-del-adm");
        let adm2 = lcca_second_admin(&st);
        lcca_administrateurs_illisibles(&st);
        let (statut, corps) = lcca_supprimer(&st, "adm", adm2).await;
        lcca_administrateurs_lisibles(&st);
        assert_eq!(statut, 503, "compte non lu : pas « dernier administrateur » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_SUPPRIME_ADMINISTRATEURS_NON_COMPTES), "{corps}");
        assert_eq!(lcca_entier(&st, "SELECT COUNT(*) FROM user WHERE role='admin'"), 2, "rien de supprimé");
        assert_eq!(lcca_attestations(&st, "config.user.delete"), 0, "aucune suppression attestée");

        let (statut, corps) = lcca_supprimer(&st, "adm", adm2).await;
        assert_eq!(statut, 200, "compté à deux : la suppression a lieu : {corps}");
        let adm = lcca_id(&st, "adm");
        let (statut, corps) = lcca_supprimer(&st, "autre-admin", adm).await;
        assert_eq!((statut, corps), (400, json!("dernier administrateur — suppression refusée")), "compté à un : sortie d'avant");
    }

    /// `user_update`, la cible : absence ÉTABLIE -> le 404 texte d'avant ; table hors d'atteinte -> 503 nommé, rien de
    /// changé ni d'attesté. Rouge sous `J4_UPD_CIBLE` (404 « compte introuvable »).
    #[tokio::test]
    async fn lcca_modification_cible_non_lue_est_un_503_nomme() {
        let (st, _p) = sp_state("lcca-upd-cible");
        let bob = lcca_id(&st, "bob");
        let (statut, corps) = lcca_retrograder(&st, "adm", 999_999).await;
        assert_eq!((statut, corps), (404, json!("compte introuvable")), "absence ÉTABLIE : sortie d'avant");

        lcca_ecrire(&st, "ALTER TABLE user RENAME TO user_hors_d_atteinte;");
        let (statut, corps) = lcca_retrograder(&st, "adm", bob).await;
        lcca_ecrire(&st, "ALTER TABLE user_hors_d_atteinte RENAME TO user;");
        assert_eq!(statut, 503, "lecture non faite : pas « compte introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_MODIFIE_CIBLE_NON_LUE), "{corps}");
        assert_eq!(lcca_texte(&st, "SELECT role FROM user WHERE name='bob'"), "editor", "rôle inchangé");
        assert_eq!(lcca_attestations(&st, "config.user.role_change"), 0, "aucun changement attesté");

        let (statut, corps) = lcca_retrograder(&st, "adm", bob).await;
        assert_eq!(statut, 204, "table rendue : la modification a lieu : {corps}");
    }

    /// `user_update`, la lecture anticipée du compte d'administrateurs : non compté -> 503 nommé, rôle inchangé ;
    /// compté à deux -> la rétrogradation a lieu ; compté à un -> le 400 texte d'avant.
    /// Rouge sous `J4_UPD_ADM` (400 « dernier administrateur »).
    #[tokio::test]
    async fn lcca_retrogradation_administrateurs_non_comptes_est_un_503_nomme() {
        let (st, _p) = sp_state("lcca-upd-adm");
        let adm2 = lcca_second_admin(&st);
        lcca_administrateurs_illisibles(&st);
        let (statut, corps) = lcca_retrograder(&st, "adm", adm2).await;
        lcca_administrateurs_lisibles(&st);
        assert_eq!(statut, 503, "compte non lu : pas « dernier administrateur » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_MODIFIE_ADMINISTRATEURS_NON_COMPTES), "{corps}");
        assert_eq!(lcca_texte(&st, "SELECT role FROM user WHERE name='adm2'"), "admin", "rôle inchangé");
        assert_eq!(lcca_attestations(&st, "config.user.role_change"), 0, "aucun changement attesté");

        let (statut, corps) = lcca_retrograder(&st, "adm", adm2).await;
        assert_eq!(statut, 204, "compté à deux : la rétrogradation a lieu : {corps}");
        let adm = lcca_id(&st, "adm");
        let (statut, corps) = lcca_retrograder(&st, "autre-admin", adm).await;
        assert_eq!((statut, corps), (400, json!("dernier administrateur — rétrogradation refusée")), "compté à un : sortie d'avant");
    }
}
