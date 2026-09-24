// =====================================================================================
// `P10.23-m` — LE MOT DE PASSE ADMINISTRATEUR NE CHANGE PAS SUR LA SEULE SESSION : L'ACTUEL EST RE-PROUVÉ.
// `P10.23-l` — LA RÉINITIALISATION D'UN MOT DE PASSE RÉVOQUE LES SESSIONS ET LES TICKETS MFA DU SEUL COMPTE.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (banc joué sur la forme d'avant ; chaque témoin
// ci-dessous a été vu ROUGE sous la mutation qu'il nomme) :
//  * `P10.23-m` : `password_post` avec `{new}` SEUL, sous la session de `adm` -> 200, mot de passe changé ;
//  * `P10.23-l` : `user_update` réinitialise le mot de passe de `bob` (204) ; la session de `bob` frappée AVANT
//    résout encore son identité, et un ticket MFA de `bob` émis AVANT ouvre une session (200, cookie) ; l'époque
//    globale n'a pas bougé (0 -> 0) ;
//  * `P10.23-l`, l'effet inverse : `password_post` avançait l'époque GLOBALE (0 -> 1) — la session d'`alice`,
//    étrangère au changement, était refusée ; tout le monde était déconnecté.
//
// CE QUE L'ÉNONCÉ DE `P10.23-m` NE DISAIT PAS, MESURÉ LE MÊME JOUR : `user_update` réinitialise AUSSI le mot de
// passe du compte APPELANT, sans l'ancien (204 sous la session seule de `adm` sur son propre identifiant) — la
// prise de compte par une session administrateur volée reste ouverte par `/api/users/{id}`, hors de ce lot.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la voie d'écrivain de la résolution d'identité (comptes `eng-cred-*`, read
// pool indisponible), dont l'époque est relue à part ; le mode multi-tenant, où l'époque du compte n'est ni frappée
// ni jugée ; le budget par adresse du `rate_limit` (non traversé par un appel direct).
// =====================================================================================
mod mot_de_passe_actuel_exige_et_revocation_par_compte {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::Ordering;

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const MDPA_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const MDPA_GRAINE: &[u8] = b"12345678901234567890";

    /// Un mot de passe neuf recevable (au moins `PASSWORD_MIN_CHARS`), construit — jamais un littéral de clé.
    fn mdpa_neuf(marque: &str) -> String {
        format!("mdpa-{marque}-{}", "n".repeat(PASSWORD_MIN_CHARS))
    }

    async fn mdpa_corps(r: Response) -> (u16, Option<String>, Option<String>, Value) {
        let statut = r.status().as_u16();
        let session = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("plume_session=").map(|reste| reste.split(';').next().unwrap_or("").to_string()));
        let attente = r.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).map(str::to_string);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, session, attente, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn mdpa_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    fn mdpa_code(graine_b32: &str) -> String {
        hotp(&base32_decode(graine_b32).expect("graine base32"), (now() / 30) as u64, 6)
    }

    fn mdpa_epoque_globale(st: &AppState) -> i64 {
        st.session_epoch.load(Ordering::SeqCst)
    }

    fn mdpa_epoque_du_compte(st: &AppState, user: &str) -> i64 {
        epoque_du_compte(&st.db.lock(), user).expect("fixture : l'époque du compte se lit")
    }

    fn mdpa_registre(st: &AppState, motif: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE substr(detail, 1, length(?1)) = ?1", params![motif], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : le registre se lit ({e})"))
    }

    fn mdpa_echecs_du_couple(st: &AppState, user: &str, ip: &str) -> u32 {
        st.auth_fails.lock().get(&(user.to_string(), ip.to_string())).map_or(0, |f| f.count)
    }

    fn mdpa_evenements_d_acces(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-auth'", [], |r| r.get(0)).expect("fixture : event se lit")
    }

    fn mdpa_id(st: &AppState, nom: &str) -> i64 {
        st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : id du compte")
    }

    /// L'identité que la résolution servie donne à un cookie `plume_session`.
    fn mdpa_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    /// Une session frappée par le chemin servi (époque globale et époque du compte COURANTES).
    fn mdpa_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session de {user} frappée"))
    }

    /// `adm` administrateur de l'assistant (son compte est aussi dans `user`, comme `set_admin` le pose).
    fn mdpa_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("mdpa-{tag}"));
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("adm".into(), h));
        (st, p)
    }

    /// Le changement tel que la console le joue sous la session de `adm` : `actuel` = `None` pour un corps sans
    /// champ `current` (la session seule).
    async fn mdpa_changer(st: &AppState, ip: &str, actuel: Option<&str>, neuf: &str) -> (u16, Option<String>, Value) {
        let corps = match actuel {
            Some(a) => json!({ "current": a, "new": neuf }),
            None => json!({ "new": neuf }),
        };
        let (s, _, attente, c) =
            mdpa_corps(password_post(State(st.clone()), ConnectInfo(mdpa_pair(ip)), Extension(sp_au("adm", "admin")), Json(corps)).await).await;
        (s, attente, c)
    }

    /// Le premier facteur tel qu'un navigateur le joue : `(statut, cookie de session, ticket)`.
    async fn mdpa_connexion(st: &AppState, user: &str, mot_de_passe: &str, ip: &str) -> (u16, Option<String>, String) {
        let (s, session, _, c) =
            mdpa_corps(login_post(State(st.clone()), ConnectInfo(mdpa_pair(ip)), Json(json!({ "user": user, "pass": mot_de_passe }))).await).await;
        (s, session, c["ticket"].as_str().unwrap_or("").to_string())
    }

    async fn mdpa_second_facteur(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, Option<String>, Value) {
        let (s, session, _, c) =
            mdpa_corps(login_mfa_post(State(st.clone()), ConnectInfo(mdpa_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await).await;
        (s, session, c)
    }

    /// `P10.24-a` : `user_update` lit l'adresse du pair ; la cible étant ici un AUTRE compte que l'appelant (`adm`),
    /// le mot de passe actuel n'est pas jugé et l'adresse est sans effet.
    async fn mdpa_reinitialiser(st: &AppState, cible: &str, neuf: &str) -> u16 {
        user_update(State(st.clone()), ConnectInfo(mdpa_pair("10.60.0.1")), Extension(sp_au("adm", "admin")), axum::extract::Path(mdpa_id(st, cible)), Json(json!({ "password": neuf })))
            .await
            .status()
            .as_u16()
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.23-m` — LA SESSION SEULE NE CHANGE PAS LE MOT DE PASSE ADMINISTRATEUR
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la session de `adm` et SANS son mot de passe actuel, le changement est refusé en `403`
    /// nommé — corps sans `current` : rien de compté ; `current` faux : un échec compté au verrou (compte, adresse)
    /// de la connexion, un événement d'accès au SIEM, une ligne au registre — et le mot de passe n'a PAS changé (le
    /// neuf ne connecte pas, l'ancien connecte), l'époque du compte n'a pas bougé. CONTRÔLE POSITIF : le VRAI mot de
    /// passe actuel change le mot de passe (200, registre, compteur du couple remis à zéro, époque du compte avancée).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : dans `password_post`, traiter toute issue de `prouver_le_premier_facteur`
    /// comme `Prouvee` (la forme d'avant) — `200` sur la session seule (mesuré tel quel avant le lot) ; retirer la
    /// ligne de registre du refus — le refus n'est plus tracé.
    #[tokio::test]
    async fn mdpa_le_mot_de_passe_administrateur_ne_change_pas_sur_la_seule_session() {
        let (st, _p) = mdpa_etat("session-seule");
        let ip = "10.61.0.1";
        let neuf = mdpa_neuf("session-seule");

        let (statut, _, corps) = mdpa_changer(&st, ip, None, &neuf).await;
        assert_eq!(statut, 403, "une session seule ne change pas le mot de passe : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_EXIGE), "{corps}");
        assert_eq!(mdpa_echecs_du_couple(&st, "adm", ip), 0, "un corps sans mot de passe actuel ne compte rien");

        let (statut, _, corps) = mdpa_changer(&st, ip, Some("pas-le-mot-de-passe-actuel"), &neuf).await;
        assert_eq!(statut, 403, "un mot de passe actuel faux ne change rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE), "{corps}");
        assert_eq!(mdpa_echecs_du_couple(&st, "adm", ip), 1, "l'échec est compté au verrou de la connexion");
        assert_eq!(mdpa_evenements_d_acces(&st), 1, "et vu du SIEM");
        assert_eq!(mdpa_registre(&st, "changement du mot de passe admin de 'adm' refusé"), 1, "et inscrit au registre");

        assert_eq!(mdpa_registre(&st, "mot de passe admin changé"), 0, "aucun changement attesté");
        assert_eq!(mdpa_epoque_du_compte(&st, "adm"), 0, "aucune session du compte révoquée");
        let (statut, _, _) = mdpa_connexion(&st, "adm", &neuf, "10.61.0.2").await;
        assert_eq!(statut, 401, "le mot de passe n'a PAS changé : le neuf ne connecte pas");
        let (statut, session, _) = mdpa_connexion(&st, "adm", MDPA_MOT_DE_PASSE_DE_FIXTURE, "10.61.0.3").await;
        assert_eq!((statut, session.is_some()), (200, true), "l'ancien connecte toujours");

        // CONTRÔLE POSITIF — le vrai mot de passe actuel.
        let (statut, _, corps) = mdpa_changer(&st, ip, Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        assert_eq!(statut, 200, "le mot de passe actuel prouvé change le mot de passe : {corps}");
        assert_eq!(mdpa_registre(&st, "mot de passe admin changé"), 1, "changement attesté");
        assert_eq!(mdpa_echecs_du_couple(&st, "adm", ip), 0, "une preuve réussie remet le couple à zéro, comme la connexion");
        assert_eq!(mdpa_epoque_du_compte(&st, "adm"), 1, "les sessions et tickets du compte sont révoqués");
        let (statut, _, _) = mdpa_connexion(&st, "adm", MDPA_MOT_DE_PASSE_DE_FIXTURE, "10.61.0.4").await;
        assert_eq!(statut, 401, "l'ancien ne connecte plus");
        let (statut, session, _) = mdpa_connexion(&st, "adm", &neuf, "10.61.0.5").await;
        assert_eq!((statut, session.is_some()), (200, true), "le neuf connecte");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.23-m` — LE MOT DE PASSE ACTUEL PARTAGE LE VERROU DE LA CONNEXION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` mots de passe actuels faux depuis une adresse posent le verrou (compte, adresse) :
    /// le mot de passe actuel JUSTE y est ensuite refusé en `429` nommé (Retry-After), rien n'est écrit — et la
    /// CONNEXION du même compte depuis la même adresse est verrouillée aussi (un seul compteur). Depuis une autre
    /// adresse, le changement passe.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans `password_post`, rendre le `429` comme une preuve faite
    /// (`Verrouillee(_) => {}`) — le mot de passe change depuis l'adresse verrouillée (`200`) ; celle de `P10.23-b`
    /// (retirer `auth_lock_check` de `prouver_le_premier_facteur`) aussi, la preuve étant partagée.
    #[tokio::test]
    async fn mdpa_le_mot_de_passe_actuel_partage_le_verrou_de_la_connexion() {
        let (st, _p) = mdpa_etat("verrou");
        let seuil = st.lock_threshold;
        assert!(seuil >= 2, "fixture : seuil {seuil}");
        let ip = "10.62.0.1";
        let neuf = mdpa_neuf("verrou");
        for i in 0..seuil {
            let (statut, _, corps) = mdpa_changer(&st, ip, Some(&format!("faux-{i}")), &neuf).await;
            assert_eq!(statut, 403, "l'essai {i} est un refus ordinaire : {corps}");
        }
        let (statut, attente, corps) = mdpa_changer(&st, ip, Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        assert_eq!(statut, 429, "verrouillé : le mot de passe actuel JUSTE n'est même pas examiné : {corps}");
        assert!(attente.is_some(), "le refus dit combien attendre (Retry-After)");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_VERROUILLE), "{corps}");
        assert_eq!(mdpa_registre(&st, "mot de passe admin changé"), 0, "rien n'est écrit");
        let (statut, session, _) = mdpa_connexion(&st, "adm", MDPA_MOT_DE_PASSE_DE_FIXTURE, ip).await;
        assert_eq!((statut, session.is_some()), (429, false), "la connexion du même couple est verrouillée : UN compteur");

        let (statut, _, corps) = mdpa_changer(&st, "10.62.0.2", Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        assert_eq!(statut, 200, "depuis une autre adresse, le titulaire change son mot de passe : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.23-m` — UNE LECTURE RATÉE N'ACCUSE PERSONNE ; UN ADMINISTRATEUR SANS MOT DE PASSE LOCAL EST NOMMÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture du hachage refusée (autorisateur SQLite), le mot de passe actuel JUSTE rend un
    /// `503` NOMMÉ — ni « refusé » (une accusation), ni un changement : aucun échec compté, rien d'écrit ; la lecture
    /// revenue, le même geste change le mot de passe. Et un administrateur visé SANS mot de passe local (aucun
    /// administrateur d'assistant, aucun `PLUME_PASS_HASH`) rend le `403` nommé qui renvoie à l'installation, au
    /// lieu de POSER un mot de passe administrateur sur la foi d'une session.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans `password_post`, rendre `CompteNonLu` comme `Refusee` — la lecture ratée
    /// devient une accusation comptée ; ou `SansMotDePasseLocal => {}` — un administrateur est posé sans preuve.
    #[tokio::test]
    async fn mdpa_une_lecture_ratee_ne_change_ni_n_accuse_et_l_administrateur_sans_mot_de_passe_est_nomme() {
        let (st, _p) = mdpa_etat("compte-non-lu");
        let ip = "10.63.0.1";
        let neuf = mdpa_neuf("compte-non-lu");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, _, corps) = mdpa_changer(&st, ip, Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "compte non lu : ni changé ni refusé : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_LU_AU_CHANGEMENT), "{corps}");
        assert_eq!(mdpa_echecs_du_couple(&st, "adm", ip), 0, "aucun échec compté");
        assert_eq!(mdpa_registre(&st, "mot de passe admin changé"), 0, "rien n'est écrit");
        let (statut, _, corps) = mdpa_changer(&st, ip, Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        assert_eq!(statut, 200, "la lecture revenue, le même geste change le mot de passe : {corps}");

        // L'ADMINISTRATEUR VISÉ SANS MOT DE PASSE LOCAL — rien à prouver, donc rien à changer.
        let (st, _p) = sp_state("mdpa-sans-mot-de-passe-local");
        let mut st = st;
        st.user = Arc::new("racine-sans-ligne".to_string());
        st.pass_hash = Arc::new(String::new());
        *st.admin.lock() = None;
        let (statut, _, corps) = mdpa_changer(&st, ip, Some("un-mot-de-passe-quelconque"), &neuf).await;
        assert_eq!(statut, 403, "aucun mot de passe actuel à prouver : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_ADMINISTRATEUR_SANS_MOT_DE_PASSE_LOCAL), "{corps}");
        let lignes: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM user WHERE name='racine-sans-ligne'", [], |r| r.get(0)).expect("lu");
        assert_eq!(lignes, 0, "aucun administrateur posé sur la foi d'une session");
        assert!(st.admin.lock().is_none(), "aucun administrateur d'assistant posé");
        assert_eq!(mdpa_echecs_du_couple(&st, "racine-sans-ligne", ip), 0, "personne n'est accusé");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.23-l` — LA RÉINITIALISATION PAR UN ADMINISTRATEUR RÉVOQUE LES JETONS DU SEUL COMPTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` (MFA active) a une session et un ticket émis ; `alice` a une session. Un administrateur
    /// réinitialise le mot de passe de `bob` (`user_update`, 204) : la session de `bob` ne résout plus AUCUNE
    /// identité ; son ticket, avec un code JUSTE, rend le `401` nommé du ticket — aucune session, le pas n'est pas
    /// consommé, aucun échec compté ; la session d'`alice` vaut toujours, et l'époque GLOBALE n'a pas bougé.
    /// CONTRÔLES POSITIFS : un changement de RÔLE seul ne révoque rien (le rôle est relu à chaque requête) ; `bob`
    /// se reconnecte par son nouveau mot de passe et son code, et cette session-là résout son identité.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer `avancer_l_epoque_du_compte` de
    /// `user_update` — la session d'avant résout encore `bob` et le ticket d'avant ouvre une session (200).
    #[tokio::test]
    async fn mdpa_la_reinitialisation_par_un_administrateur_revoque_les_jetons_du_seul_compte() {
        let (st, _p) = mdpa_etat("reinitialisation");
        let graine = base32_encode(MDPA_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('bob',?1,1,'[]',-1,0,0)",
                params![graine],
            )
            .expect("fixture : MFA de bob");
        let ip = "10.64.0.1";
        let session_de_bob = mdpa_session(&st, "bob", "editor");
        let session_d_alice = mdpa_session(&st, "alice", "editor");
        let (statut, _, ticket_de_bob) = mdpa_connexion(&st, "bob", MDPA_MOT_DE_PASSE_DE_FIXTURE, ip).await;
        assert_eq!((statut, ticket_de_bob.is_empty()), (200, false), "fixture : le mot de passe de bob rend un ticket");
        assert!(mdpa_identite(&st, &session_de_bob).is_some(), "fixture : la session de bob vaut");

        // CONTRÔLE POSITIF — un changement de rôle seul ne révoque rien.
        let r = user_update(State(st.clone()), ConnectInfo(mdpa_pair(ip)), Extension(sp_au("adm", "admin")), axum::extract::Path(mdpa_id(&st, "bob")), Json(json!({ "role": "viewer" }))).await;
        assert_eq!(r.status().as_u16(), 204, "fixture : rôle changé");
        assert_eq!(mdpa_identite(&st, &session_de_bob), Some(("bob".into(), "viewer".into())), "le rôle suit, la session vaut");

        let epoque = mdpa_epoque_globale(&st);
        let neuf = mdpa_neuf("reinitialisation");
        assert_eq!(mdpa_reinitialiser(&st, "bob", &neuf).await, 204, "fixture : mot de passe de bob réinitialisé");
        assert_eq!(mdpa_identite(&st, &session_de_bob), None, "la session de bob d'avant la réinitialisation ne vaut plus");
        let (statut, session, corps) = mdpa_second_facteur(&st, &ticket_de_bob, &mdpa_code(&graine), ip).await;
        assert_eq!((statut, session.is_some()), (401, false), "le ticket d'avant la réinitialisation ne sert plus : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE), "{corps}");
        let pas: i64 = st.db.lock().query_row("SELECT last_step FROM user_mfa WHERE user='bob'", [], |r| r.get(0)).expect("lu");
        assert_eq!(pas, -1, "le pas n'est pas consommé");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 0, "rien au frein du compte");
        assert_eq!(mdpa_echecs_du_couple(&st, "bob", ip), 0, "rien au verrou du couple");
        assert_eq!(mdpa_identite(&st, &session_d_alice), Some(("alice".into(), "editor".into())), "la session d'alice vaut toujours");
        assert_eq!(mdpa_epoque_globale(&st), epoque, "l'époque globale n'a pas bougé");

        // CONTRÔLE POSITIF — bob se reconnecte par son nouveau mot de passe et son code.
        let (_, _, ticket) = mdpa_connexion(&st, "bob", &neuf, ip).await;
        let (statut, session, corps) = mdpa_second_facteur(&st, &ticket, &mdpa_code(&graine), ip).await;
        assert_eq!(statut, 200, "le ticket d'après la réinitialisation sert : {corps}");
        let session = session.expect("session posée");
        assert_eq!(mdpa_identite(&st, &session), Some(("bob".into(), "viewer".into())), "et sa session résout son identité");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.23-l` — CHANGER LE MOT DE PASSE ADMINISTRATEUR NE DÉCONNECTE QUE SON COMPTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `adm` et `alice` ont chacun une session ; `adm` change son mot de passe (`password_post`,
    /// mot de passe actuel prouvé) : la session de `adm` ne résout plus aucune identité, celle d'`alice` vaut
    /// toujours, l'époque globale n'a pas bougé. CONTRÔLE POSITIF : la session que `adm` ouvre ensuite vaut.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : remettre l'avancée de l'époque GLOBALE dans `password_post` (la forme
    /// d'avant, `bump_session_epoch`) à la place de celle du compte — la session d'`alice` tombe ; retirer
    /// l'avancée de l'époque du compte (`poser_l_administrateur(.., false)`) — la session d'avant de `adm` vaut encore.
    #[tokio::test]
    async fn mdpa_changer_le_mot_de_passe_administrateur_ne_deconnecte_que_son_compte() {
        let (st, _p) = mdpa_etat("changement");
        let session_d_adm = mdpa_session(&st, "adm", "admin");
        let session_d_alice = mdpa_session(&st, "alice", "editor");
        let epoque = mdpa_epoque_globale(&st);
        let neuf = mdpa_neuf("changement");
        let (statut, _, corps) = mdpa_changer(&st, "10.65.0.1", Some(MDPA_MOT_DE_PASSE_DE_FIXTURE), &neuf).await;
        assert_eq!(statut, 200, "fixture : mot de passe changé : {corps}");

        assert_eq!(mdpa_identite(&st, &session_d_adm), None, "la session d'adm d'avant le changement ne vaut plus");
        assert_eq!(mdpa_identite(&st, &session_d_alice), Some(("alice".into(), "editor".into())), "la session d'alice vaut toujours");
        assert_eq!(mdpa_epoque_globale(&st), epoque, "l'époque globale n'a pas bougé");

        let (statut, session, _) = mdpa_connexion(&st, "adm", &neuf, "10.65.0.2").await;
        assert_eq!(statut, 200, "fixture : reconnexion");
        assert_eq!(mdpa_identite(&st, &session.expect("session posée")), Some(("adm".into(), "admin".into())), "la session d'après vaut");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.23-l` — LE JETON PORTE L'ÉPOQUE DE SON COMPTE, SIGNÉE, ET RIEN NE CHANGE POUR L'ÉPOQUE ZÉRO
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : (a) le jeton d'un compte jamais révoqué est OCTET POUR OCTET celui d'avant `P10.23-l` (même
    /// matière signée, deux segments) — le déploiement ne déconnecte personne ; (b) au-delà de zéro, l'époque est
    /// portée (`.<k>`) ET signée : la réécrire pour l'aligner sur l'époque courante du compte, la retirer, ou
    /// l'écrire sous une forme non canonique (`+k`, `0k`) casse le jeton ; (c) à l'identité, seul le jeton de
    /// l'époque COURANTE du compte vaut.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `suffixe_signe_de_l_epoque_du_compte` du message signé (session) en
    /// gardant l'époque portée — le jeton d'une époque révolue, réécrit à l'époque courante, résout l'identité.
    #[tokio::test]
    async fn mdpa_le_jeton_porte_l_epoque_de_son_compte_signee_et_rien_ne_change_a_zero() {
        let (st, _p) = mdpa_etat("jeton");
        let secret = st.session_secret.as_slice();
        let epoch = mdpa_epoque_globale(&st);

        // (a) époque zéro : la forme d'avant, recalculée ici à la main.
        let jeton0 = mint_session_du_compte(secret, "bob", "editor", 3600, epoch, 0);
        let (p_b64, sig_hex) = jeton0.split_once('.').expect("deux segments");
        assert!(!sig_hex.contains('.'), "époque zéro : aucun troisième segment : {jeton0}");
        assert_eq!(sig_hex, hex_encode(&hmac_sha256(secret, format!("{p_b64}|{epoch}").as_bytes())), "matière signée d'avant");

        // (b) au-delà de zéro.
        assert_eq!(mdpa_reinitialiser(&st, "bob", &mdpa_neuf("jeton-1")).await, 204, "fixture");
        let ancien = mdpa_session(&st, "bob", "editor");
        assert_eq!(mdpa_reinitialiser(&st, "bob", &mdpa_neuf("jeton-2")).await, 204, "fixture");
        assert_eq!(mdpa_epoque_du_compte(&st, "bob"), 2, "fixture : deux réinitialisations");
        assert!(ancien.ends_with(".1"), "le jeton porte l'époque de son compte : {ancien}");
        let reecrit = format!("{}.2", ancien.trim_end_matches(".1"));
        assert_eq!(mdpa_identite(&st, &reecrit), None, "époque réécrite à la courante : signature cassée");
        assert_eq!(mdpa_identite(&st, ancien.trim_end_matches(".1")), None, "époque retirée : signature cassée");
        let courant = mdpa_session(&st, "bob", "editor");
        assert!(courant.ends_with(".2"), "fixture : {courant}");
        let base = courant.trim_end_matches(".2");
        for forme in ["+2", "02", "2.", "-2", "0"] {
            assert_eq!(mdpa_identite(&st, &format!("{base}.{forme}")), None, "forme non canonique `{forme}` refusée");
        }

        // (c) seul le jeton de l'époque courante vaut.
        assert_eq!(mdpa_identite(&st, &ancien), None, "époque révolue");
        assert_eq!(mdpa_identite(&st, &jeton0), None, "époque zéro révolue");
        assert_eq!(mdpa_identite(&st, &courant), Some(("bob".into(), "editor".into())), "époque courante");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.23-l` — UNE ÉPOQUE DE COMPTE ILLISIBLE N'OUVRE RIEN ET NE SE LIT PAS COMME ZÉRO
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'époque de `alice` corrompue dans `meta` (`abc`) — sa session d'époque zéro ne résout
    /// AUCUNE identité (une révocation illisible n'est pas une absence de révocation) ; sa connexion rend le `503`
    /// NOMMÉ sans cookie ; son cookie présenté à la déconnexion ne révoque pas tout le monde ; son RÔLE reste servi à
    /// qui ne juge aucune session (`live_role_for`). La valeur réparée, la même session vaut.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : lire une valeur illisible comme zéro (`interpreter_l_epoque_du_compte` rendant
    /// `Ok(0)`) — la session vaut, la connexion rend 200.
    #[tokio::test]
    async fn mdpa_une_epoque_de_compte_illisible_n_ouvre_rien() {
        let (st, _p) = mdpa_etat("illisible");
        let session = mdpa_session(&st, "alice", "editor");
        st.db
            .lock()
            .execute("INSERT INTO meta(key,value) VALUES(?1,'abc')", params![cle_de_l_epoque_du_compte("alice")])
            .expect("fixture : époque corrompue");

        assert_eq!(mdpa_identite(&st, &session), None, "époque illisible : aucune identité");
        let (statut, cookie, _, corps) = mdpa_corps(
            login_post(State(st.clone()), ConnectInfo(mdpa_pair("10.66.0.1")), Json(json!({ "user": "alice", "pass": MDPA_MOT_DE_PASSE_DE_FIXTURE }))).await,
        )
        .await;
        assert_eq!((statut, cookie.is_some()), (503, false), "aucune session frappée sans l'époque du compte : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_EPOQUE_DU_COMPTE_NON_LUE), "{corps}");
        let epoque = mdpa_epoque_globale(&st);
        let mut en_tetes = axum::http::HeaderMap::new();
        en_tetes.insert(header::COOKIE, format!("plume_session={session}").parse().expect("en-tête"));
        let _ = logout_post(State(st.clone()), en_tetes).await;
        assert_eq!(mdpa_epoque_globale(&st), epoque, "un cookie non jugeable ne révoque pas tout le monde");
        assert_eq!(live_role_for(&st, "alice").as_deref(), Some("editor"), "le rôle reste servi hors jugement de session");

        st.db
            .lock()
            .execute("UPDATE meta SET value='0' WHERE key=?1", params![cle_de_l_epoque_du_compte("alice")])
            .expect("fixture : réparée");
        assert_eq!(mdpa_identite(&st, &session), Some(("alice".into(), "editor".into())), "réparée, la même session vaut");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.23-l` — UN COOKIE RÉVOQUÉ POUR SON COMPTE NE DÉCONNECTE PAS TOUT LE MONDE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la garde anti-DoS de `/api/logout` (seule une session VALIDE avance l'époque globale) juge
    /// aussi l'époque du compte : après la réinitialisation de `bob`, son cookie d'avant présenté à la déconnexion
    /// n'avance PAS l'époque globale, et la session d'`alice` vaut toujours. CONTRÔLE POSITIF : le cookie COURANT de
    /// `bob` l'avance (la déconnexion révoque toujours tout, `P10.23-o` reste ouverte).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans `session_ouverte_par`, ne plus comparer l'époque du compte (la garde
    /// d'avant, signature seule) — le cookie révoqué de `bob` déconnecte tout le monde.
    #[tokio::test]
    async fn mdpa_un_cookie_revoque_pour_son_compte_ne_deconnecte_pas_tout_le_monde() {
        let (st, _p) = mdpa_etat("deconnexion");
        let ancien = mdpa_session(&st, "bob", "editor");
        let session_d_alice = mdpa_session(&st, "alice", "editor");
        assert_eq!(mdpa_reinitialiser(&st, "bob", &mdpa_neuf("deconnexion")).await, 204, "fixture");
        let epoque = mdpa_epoque_globale(&st);
        let deconnexion = |jeton: String| {
            let mut en_tetes = axum::http::HeaderMap::new();
            en_tetes.insert(header::COOKIE, format!("plume_session={jeton}").parse().expect("en-tête"));
            logout_post(State(st.clone()), en_tetes)
        };
        let _ = deconnexion(ancien).await;
        assert_eq!(mdpa_epoque_globale(&st), epoque, "le cookie révoqué de bob n'avance pas l'époque globale");
        assert!(mdpa_identite(&st, &session_d_alice).is_some(), "la session d'alice vaut toujours");

        let _ = deconnexion(mdpa_session(&st, "bob", "editor")).await;
        assert_eq!(mdpa_epoque_globale(&st), epoque + 1, "le cookie courant de bob déconnecte, comme avant");
    }
}
