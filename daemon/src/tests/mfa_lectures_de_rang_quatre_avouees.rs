// =====================================================================================
// `P10.20-b` (rang quatre, volet MFA de `P10.30-d`) — LES TROIS DERNIÈRES LECTURES DE `user_mfa` DISENT
// « NON LU » AU LIEU D'UNE FAUSSE ABSENCE.
//
// VU sur `b52f097` : `mfa_verify`, `mfa_disable` et `login_mfa_post` lisaient la ligne `user_mfa` par
// `query_row(..).ok()`. Une lecture NON FAITE (table hors d'atteinte, valeur d'un type inattendu) devenait
// `None`, donc « aucun enrôlement en cours » (400), « aucune MFA enrôlée » (404), « aucune MFA active pour ce
// compte » (401) : fail-closed, aucun fait inventé, mais une cause FAUSSE — un 401/404 se lit révocation ou
// absence, un 503 se rejoue.
//
// ATTENDU, tenu ici : l'absence ÉTABLIE garde la sortie d'avant OCTET POUR OCTET ; la lecture NON FAITE rend un
// 503 nommé, rien n'est écrit, aucun échec n'est laissé au frein du compte, et la MFA ACTIVE reste ACTIVE après
// le 503 de la désactivation (transaction annulée, essai rendu).
//
// LA LECTURE EST RENDUE ILLISIBLE sans toucher au code servi : `secret` porte un BLOB (`get::<String>` le refuse,
// la requête reste saine et `enabled` reste lisible — c'est ce qui laisse passer les lectures qui précèdent le
// site jugé), ou la table est RENOMMÉE après l'émission du ticket. Jamais par un trigger sur SELECT.
//
// MUTATIONS (vues ROUGES, puis retirées) : les mutants `H3_VERIFY`, `H3_DISABLE`, `H3_LOGIN` rétablissent le repli
// de `.ok()` (l'erreur devient `None`) sur leur site ; `H3_DISABLE_RENDRE` omet le retour de l'essai réservé.
//
// « AUCUN ÉCHEC COMPTÉ » porte sur LES DEUX freins : celui du compte (`user_mfa_fail`) ET le compteur du couple
// compte+adresse (`auth_fails`, celui qui émet l'événement « failure »). Mutant `H3_L5` : un `auth_record_failure` sur
// la branche du 503 de la connexion — rouge.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la phrase que la console peint du 503 (le harnais ESM, témoin 108, la tient) ;
// une panne de lecture APRÈS la réservation à la connexion (le site est AVANT le frein, il n'y a rien à rendre) ; le
// `ROLLBACK` refusé de la désactivation, NON JOUÉ et TU : `let _ = conn.execute_batch("ROLLBACK")` avale son erreur,
// comme les autres branches de `mfa_disable` (motif antérieur, aucune forme commune d'annulation n'existe) — quand
// aucun essai n'est réservé (enrôlement en attente), rien n'en passe au journal. Seule la ligne « NON relu » y passe.
// =====================================================================================
mod mfa_lectures_de_rang_quatre_avouees {
    use super::*;
    use rusqlite::OptionalExtension;

    const MLRQ_MOT_DE_PASSE: &str = "motdepasse12345";

    async fn mlrq_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn mlrq_pair() -> std::net::SocketAddr {
        "10.77.0.1:45454".parse().expect("adresse de test")
    }

    fn mlrq_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// `adm` porteur d'une ligne `user_mfa` (graine valide), ACTIVE si `active`.
    fn mlrq_etat(tag: &str, active: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("mlrq-{tag}"));
        assert!(st.lock_threshold > 0, "fixture : le frein du compte est armé, sinon « aucun échec compté » ne prouve rien");
        let graine = base32_encode(b"12345678901234567890");
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,?2,'[]',-1,0,0)",
                params![graine, active as i64],
            )
            .expect("fixture : MFA posée");
        (st, p)
    }

    /// La ligne illisible : `secret` devient un BLOB, `enabled` reste lisible.
    fn mlrq_secret_illisible(st: &AppState) {
        mlrq_ecrire(st, "UPDATE user_mfa SET secret=x'FF' WHERE user='adm';");
    }

    fn mlrq_enabled(st: &AppState) -> Option<i64> {
        st.db
            .lock()
            .query_row("SELECT enabled FROM user_mfa WHERE user='adm'", [], |r| r.get(0))
            .optional()
            .expect("fixture : `enabled` lisible")
    }

    fn mlrq_echecs(st: &AppState) -> u32 {
        crate::handlers::idp::echecs_consecutifs_du_second_facteur(st, "adm")
    }

    /// Le compteur du couple compte+adresse (`auth_fails`), distinct du frein du compte.
    fn mlrq_echecs_du_couple(st: &AppState) -> u32 {
        st.auth_fails.lock().get(&("adm".to_string(), mlrq_pair().ip().to_string())).map_or(0, |f| f.count)
    }

    async fn mlrq_ticket(st: &AppState) -> String {
        let r = login_post(State(st.clone()), ConnectInfo(mlrq_pair()), Json(json!({ "user": "adm", "pass": MLRQ_MOT_DE_PASSE }))).await;
        let (statut, c) = mlrq_corps(r).await;
        assert_eq!(statut, 200, "fixture : le mot de passe rend un ticket : {c}");
        c["ticket"].as_str().expect("ticket").to_string()
    }

    async fn mlrq_activer(st: &AppState) -> (u16, Value) {
        mlrq_corps(mfa_verify(State(st.clone()), ConnectInfo(mlrq_pair()), Extension(sp_au("adm", "admin")), Json(json!({ "code": "123456" }))).await).await
    }

    async fn mlrq_desactiver(st: &AppState) -> (u16, Value) {
        mlrq_corps(mfa_disable(State(st.clone()), ConnectInfo(mlrq_pair()), Extension(sp_au("adm", "admin")), Json(json!({ "code": "123456" }))).await).await
    }

    /// Le second facteur à la connexion : `(statut, session posée, corps)`.
    async fn mlrq_connexion(st: &AppState, ticket: &str) -> (u16, bool, Value) {
        let r = login_mfa_post(State(st.clone()), ConnectInfo(mlrq_pair()), Json(json!({ "ticket": ticket, "code": "123456" }))).await;
        let session = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let (statut, corps) = mlrq_corps(r).await;
        (statut, session, corps)
    }

    /// `mfa_verify` : absence ÉTABLIE -> le 400 d'avant ; ligne illisible ou table hors d'atteinte -> 503 nommé,
    /// l'enrôlement reste EN ATTENTE, aucun échec compté. Rouge sous `H3_VERIFY` (400 « aucun enrôlement »).
    #[tokio::test]
    async fn mlrq_activation_lecture_ratee_est_un_503_nomme() {
        let (vierge, _pv) = sp_state("mlrq-verify-vierge");
        let (statut, corps) = mlrq_activer(&vierge).await;
        assert_eq!((statut, corps), (400, json!({ "error": "aucun enrôlement en cours (appelez /api/mfa/enroll d'abord)" })), "absence ÉTABLIE : sortie d'avant");

        let (st, _p) = mlrq_etat("verify", false);
        mlrq_secret_illisible(&st);
        let (statut, corps) = mlrq_activer(&st).await;
        assert_eq!(statut, 503, "lecture non faite : pas « aucun enrôlement » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MFA_NON_LUE), "le refus NOMME sa cause : {corps}");
        assert_eq!(mlrq_enabled(&st), Some(0), "rien n'est activé");
        assert_eq!(mlrq_echecs(&st), 0, "aucun échec laissé au frein");

        mlrq_ecrire(&st, "ALTER TABLE user_mfa RENAME TO user_mfa_hors_d_atteinte;");
        let (statut, corps) = mlrq_activer(&st).await;
        assert_eq!(statut, 503, "table hors d'atteinte : même refus : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MFA_NON_LUE));
    }

    /// `mfa_disable` : absence ÉTABLIE -> le 404 d'avant ; ligne non relue DANS la transaction -> 503 sous la cause
    /// dédiée, la MFA ACTIVE reste ACTIVE, l'essai réservé est RENDU, aucune transaction ne reste ouverte.
    /// Rouge sous `H3_DISABLE` (404 « aucune MFA enrôlée ») et sous `H3_DISABLE_RENDRE` (un échec de trop).
    #[tokio::test]
    async fn mlrq_desactivation_lecture_ratee_laisse_la_mfa_active() {
        let (vierge, _pv) = sp_state("mlrq-disable-vierge");
        let (statut, corps) = mlrq_desactiver(&vierge).await;
        assert_eq!((statut, corps), (404, json!({ "error": "aucune MFA enrôlée" })), "absence ÉTABLIE : sortie d'avant");

        let (st, _p) = mlrq_etat("disable", true);
        mlrq_secret_illisible(&st);
        let (statut, corps) = mlrq_desactiver(&st).await;
        assert_eq!(statut, 503, "lecture non faite : pas « aucune MFA enrôlée » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MFA_NON_DESACTIVEE_LECTURE_NON_FAITE), "le refus NOMME sa cause : {corps}");
        assert_eq!(mlrq_enabled(&st), Some(1), "la MFA ACTIVE reste ACTIVE après le 503");
        assert_eq!(mlrq_echecs(&st), 0, "l'essai réservé est RENDU : aucun code n'a été examiné");
        assert!(st.db.lock().is_autocommit(), "la transaction de la désactivation est ANNULÉE, pas laissée ouverte");
    }

    /// `login_mfa_post` : absence ÉTABLIE -> le 401 d'avant ; ligne illisible ou table hors d'atteinte -> 503 nommé,
    /// AUCUNE session, AUCUN échec compté au frein (le site est avant la réservation). Rouge sous `H3_LOGIN`.
    #[tokio::test]
    async fn mlrq_connexion_lecture_ratee_ne_consomme_pas_le_frein() {
        let (st, _p) = mlrq_etat("login", true);
        let ticket = mlrq_ticket(&st).await;

        mlrq_secret_illisible(&st);
        let (statut, session, corps) = mlrq_connexion(&st, &ticket).await;
        assert_eq!(statut, 503, "lecture non faite : pas « aucune MFA active » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MFA_NON_LUE), "le refus NOMME sa cause : {corps}");
        assert!(!session, "aucune session posée");
        assert_eq!(mlrq_echecs(&st), 0, "le frein du compte n'est PAS consommé");
        assert_eq!(mlrq_echecs_du_couple(&st), 0, "le couple compte+adresse n'est PAS compté (ni « failure » émis)");

        mlrq_ecrire(&st, "ALTER TABLE user_mfa RENAME TO user_mfa_hors_d_atteinte;");
        let (statut, session, corps) = mlrq_connexion(&st, &ticket).await;
        assert_eq!(statut, 503, "table hors d'atteinte : même refus : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MFA_NON_LUE));
        assert!(!session);
        assert_eq!(mlrq_echecs(&st), 0);
        assert_eq!(mlrq_echecs_du_couple(&st), 0);

        // L'absence ÉTABLIE (la ligne retirée après l'émission du ticket) : le 401 d'avant, octet pour octet.
        mlrq_ecrire(&st, "ALTER TABLE user_mfa_hors_d_atteinte RENAME TO user_mfa; DELETE FROM user_mfa WHERE user='adm';");
        let (statut, session, corps) = mlrq_connexion(&st, &ticket).await;
        assert_eq!((statut, corps), (401, json!({ "error": "aucune MFA active pour ce compte" })), "absence ÉTABLIE : sortie d'avant");
        assert!(!session);
    }
}
