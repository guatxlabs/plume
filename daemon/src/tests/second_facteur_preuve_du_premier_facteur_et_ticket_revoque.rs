// =====================================================================================
// `P10.23-b` — UNE SESSION SEULE N'ENRÔLE PAS DE GRAINE : LE MOT DE PASSE DU COMPTE EST RE-PROUVÉ.
// `P10.22-x` — LE TICKET MFA SUIT LA RÉVOCATION DES SESSIONS (ÉPOQUE DE SESSION DANS SA SIGNATURE).
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-23 (banc joué sur la forme d'avant ; chaque témoin
// ci-dessous a été vu ROUGE sous la mutation qu'il nomme) :
//  * `P10.23-b` : une session SEULE de `adm` (mot de passe inconnu) -> `mfa_enroll` 200 et une graine ;
//    `mfa_verify` avec un code de cette graine -> 200 et DIX codes de secours ; la connexion du titulaire avec
//    son VRAI mot de passe rend alors `{mfa_required, ticket}` sans session — enfermé hors de son compte ;
//  * `P10.23-b`, l'enrôlement EN ATTENTE : un second `mfa_enroll` (session seule) remplace la graine du
//    titulaire en attente ; le code de SA graine rend 401, et un échec est compté à son frein ;
//  * `P10.23-b`, un compte fédéré (hachage `!external-idp`) enrôlait (200) une graine que sa connexion (OIDC,
//    SAML, LDAP) ne demande jamais ;
//  * `P10.22-x` : un ticket émis avant un changement du mot de passe administrateur (`password_post`, époque
//    0 -> 1) ouvrait encore une session (200, cookie) ; de même avant une déconnexion (`logout_post`, 0 -> 1) ;
//    et le MÊME ticket, rejoué avec le pas suivant, ouvrait une seconde session.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la réinitialisation d'un mot de passe par un administrateur
// (`user_update`) ne fait pas avancer l'époque — MESURÉ le même jour : le ticket d'avant ouvre encore une session
// (200) ET la session d'avant reste valide ; c'est un défaut de révocation des SESSIONS, hors de ce lot (clé
// neuve) ; le rejeu d'un ticket pendant ses cinq minutes, à époque inchangée, reste possible À DESSEIN (voir
// `mfa_ticket_sign`) ; ce que la console peint des refus neufs (`web/idp.js` n'envoie pas encore de mot de
// passe à l'enrôlement) ; le budget par adresse du `rate_limit` (non traversé par un appel direct).
// =====================================================================================
mod second_facteur_preuve_du_premier_facteur_et_ticket_revoque {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SFPR_MOT_DE_PASSE: &str = "motdepasse12345";
    const SFPR_GRAINE: &[u8] = b"12345678901234567890";

    async fn sfpr_corps(r: Response) -> (u16, bool, Option<String>, Value) {
        let statut = r.status().as_u16();
        let cookie = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let attente = r.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).map(str::to_string);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, cookie, attente, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn sfpr_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    fn sfpr_code(graine_b32: &str, pas: i64) -> String {
        hotp(&base32_decode(graine_b32).expect("graine base32"), pas as u64, 6)
    }

    fn sfpr_compter(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn sfpr_lignes_mfa(st: &AppState, user: &str) -> i64 {
        sfpr_compter(st, &format!("SELECT COUNT(*) FROM user_mfa WHERE user='{user}'"))
    }

    fn sfpr_registre(st: &AppState, motif: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE substr(detail, 1, length(?1)) = ?1", params![motif], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : le registre se lit ({e})"))
    }

    fn sfpr_echecs_du_couple(st: &AppState, user: &str, ip: &str) -> u32 {
        st.auth_fails.lock().get(&(user.to_string(), ip.to_string())).map_or(0, |f| f.count)
    }

    /// L'enrôlement tel que la console le joue, sous l'identité de session `user` : `mot_de_passe` = `None` pour
    /// un corps sans champ `password` (la session seule).
    async fn sfpr_enroler(st: &AppState, user: &str, ip: &str, mot_de_passe: Option<&str>) -> (u16, Option<String>, Value) {
        let corps = match mot_de_passe {
            Some(m) => json!({ "password": m }),
            None => json!({}),
        };
        let (s, _, attente, c) =
            sfpr_corps(mfa_enroll(State(st.clone()), ConnectInfo(sfpr_pair(ip)), Extension(sp_au(user, "editor")), Json(corps)).await).await;
        (s, attente, c)
    }

    async fn sfpr_activer(st: &AppState, user: &str, code: &str) -> (u16, Value) {
        let (s, _, _, c) = sfpr_corps(mfa_verify(State(st.clone()), Extension(sp_au(user, "editor")), Json(json!({ "code": code }))).await).await;
        (s, c)
    }

    /// Le premier facteur tel qu'un navigateur le joue : rend `(statut, session posée, ticket)`.
    async fn sfpr_connexion(st: &AppState, user: &str, mot_de_passe: &str, ip: &str) -> (u16, bool, String) {
        let (s, cookie, _, c) =
            sfpr_corps(login_post(State(st.clone()), ConnectInfo(sfpr_pair(ip)), Json(json!({ "user": user, "pass": mot_de_passe }))).await).await;
        (s, cookie, c["ticket"].as_str().unwrap_or("").to_string())
    }

    async fn sfpr_second_facteur(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, bool, Value) {
        let (s, cookie, _, c) =
            sfpr_corps(login_mfa_post(State(st.clone()), ConnectInfo(sfpr_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await).await;
        (s, cookie, c)
    }

    fn sfpr_epoque(st: &AppState) -> i64 {
        st.session_epoch.load(Ordering::SeqCst)
    }

    /// L'état mode 0 file-backed, `user` porteur d'une MFA ACTIVE à la graine connue (`last_step = -1`).
    fn sfpr_etat_mfa_active(tag: &str, user: &str) -> (AppState, crate::tmp_possede::TmpDb, String) {
        let (st, p) = sp_state(&format!("sfpr-{tag}"));
        let graine = base32_encode(SFPR_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,'[]',-1,0,0)",
                params![user, graine],
            )
            .expect("fixture : MFA posée");
        (st, p, graine)
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.23-b` — UNE SESSION SEULE N'ENRÔLE RIEN, LE TITULAIRE N'EST PAS ENFERMÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la session de `adm` et SANS son mot de passe, l'enrôlement est refusé en `403` nommé
    /// (corps sans `password` : rien de compté ; mot de passe faux : un échec compté au verrou (compte, adresse) de
    /// la connexion, un événement d'accès au SIEM, une ligne au registre), AUCUNE graine n'est posée, l'activation
    /// n'a rien à activer, et le titulaire se connecte toujours par son seul mot de passe. CONTRÔLE POSITIF : le
    /// VRAI mot de passe enrôle (graine en attente, le compteur du couple remis à zéro), l'activation sert ses
    /// codes, et la connexion demande alors le code — le geste légitime est intact.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : dans `mfa_enroll`, traiter toute issue de `prouver_le_premier_facteur`
    /// comme `Prouvee` (la forme d'avant) — `200` et une graine sur la session seule (mesuré tel quel avant le lot) ;
    /// retirer `auth_record_failure` du refus — l'échec n'est plus compté ; retirer la ligne de registre du refus —
    /// le refus n'est plus tracé.
    #[tokio::test]
    async fn sfpr_une_session_seule_n_enrole_ni_n_active_de_graine() {
        let (st, _p) = sp_state("sfpr-session-seule");
        let ip = "10.40.0.1";

        let (statut, _, corps) = sfpr_enroler(&st, "adm", ip, None).await;
        assert_eq!(statut, 403, "une session seule n'enrôle pas : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER), "{corps}");
        assert!(corps.get("secret").is_none(), "AUCUNE graine servie : {corps}");
        assert_eq!(sfpr_echecs_du_couple(&st, "adm", ip), 0, "un corps sans mot de passe ne compte rien");

        let (statut, _, corps) = sfpr_enroler(&st, "adm", ip, Some("pas-le-bon-mot-de-passe")).await;
        assert_eq!(statut, 403, "un mot de passe faux n'enrôle pas : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT), "{corps}");
        assert!(corps.get("secret").is_none(), "AUCUNE graine servie : {corps}");
        assert_eq!(sfpr_echecs_du_couple(&st, "adm", ip), 1, "l'échec est compté au verrou de la connexion");
        assert_eq!(sfpr_compter(&st, "SELECT COUNT(*) FROM event WHERE source='plume-auth'"), 1, "et vu du SIEM");
        assert_eq!(sfpr_registre(&st, "enrôlement MFA refusé pour 'adm'"), 1, "et inscrit au registre");
        assert_eq!(sfpr_lignes_mfa(&st, "adm"), 0, "aucune graine n'est posée");

        let (statut, corps) = sfpr_activer(&st, "adm", "123456").await;
        assert_eq!(statut, 400, "rien à activer : {corps}");
        let (statut, session, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, "10.40.0.2").await;
        assert_eq!((statut, session, ticket.is_empty()), (200, true, true), "le titulaire se connecte par son seul mot de passe");

        // CONTRÔLE POSITIF — le vrai mot de passe enrôle ; l'activation et la connexion suivent.
        let (statut, _, corps) = sfpr_enroler(&st, "adm", ip, Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 200, "le mot de passe re-prouvé enrôle : {corps}");
        let graine = corps["secret"].as_str().expect("graine servie").to_string();
        assert_eq!(sfpr_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=0"), 1, "en attente");
        assert_eq!(sfpr_echecs_du_couple(&st, "adm", ip), 0, "une preuve réussie remet le couple à zéro, comme la connexion");
        let (statut, corps) = sfpr_activer(&st, "adm", &sfpr_code(&graine, now() / 30)).await;
        assert_eq!((statut, corps["recovery_codes"].as_array().map(|a| a.len())), (200, Some(10)), "{corps}");
        let (statut, session, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, "10.40.0.3").await;
        assert_eq!((statut, session, ticket.is_empty()), (200, false, false), "la connexion demande le code");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.23-b` — L'ENRÔLEMENT EN ATTENTE DU TITULAIRE N'EST PAS ÉCRASÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` a enrôlé (avec son mot de passe) et n'a pas encore activé ; une session seule, puis un
    /// mot de passe faux, tentent un second enrôlement : `403` les deux fois, la graine en base est TOUJOURS celle
    /// de `bob`, et le code de SA graine l'active (`200`) sans qu'aucun échec du second facteur ne soit compté.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : celle du témoin (1) — la graine en attente est remplacée et le code du
    /// titulaire rend `401`, compté à son frein (mesuré tel quel avant le lot).
    #[tokio::test]
    async fn sfpr_un_enrolement_en_attente_du_titulaire_n_est_pas_ecrase_sans_le_mot_de_passe() {
        let (st, _p) = sp_state("sfpr-attente");
        let (statut, _, corps) = sfpr_enroler(&st, "bob", "10.41.0.1", Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 200, "fixture : le titulaire enrôle : {corps}");
        let graine = corps["secret"].as_str().expect("graine").to_string();

        for mot_de_passe in [None, Some("pas-le-bon-mot-de-passe")] {
            let (statut, _, corps) = sfpr_enroler(&st, "bob", "10.41.0.2", mot_de_passe).await;
            assert_eq!(statut, 403, "sans le mot de passe, pas de second enrôlement ({mot_de_passe:?}) : {corps}");
        }
        let en_base: String = st.db.lock().query_row("SELECT secret FROM user_mfa WHERE user='bob'", [], |r| r.get(0)).expect("ligne");
        assert_eq!(en_base, graine, "la graine en attente est TOUJOURS celle du titulaire");

        let (statut, corps) = sfpr_activer(&st, "bob", &sfpr_code(&graine, now() / 30)).await;
        assert_eq!(statut, 200, "le titulaire active SA graine : {corps}");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 0, "aucun échec compté à son frein");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.23-b` — LE MOT DE PASSE RE-SAISI PARTAGE LE VERROU DE LA CONNEXION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` mots de passe faux à l'enrôlement depuis une adresse posent le verrou (compte,
    /// adresse) : le mot de passe JUSTE y est ensuite refusé en `429` nommé (Retry-After), sans graine — et la
    /// CONNEXION du même compte depuis la même adresse est verrouillée aussi (un seul compteur). Depuis une autre
    /// adresse, le titulaire enrôle (le verrou est par couple, comme celui de la connexion).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `auth_lock_check` de `prouver_le_premier_facteur` — le mot de passe
    /// juste enrôle depuis l'adresse verrouillée (`200`) ; retirer `auth_record_failure` du refus — aucun verrou,
    /// même rouge. Sans elles, cette route offrirait des essais que `/api/login` refuse.
    #[tokio::test]
    async fn sfpr_le_mot_de_passe_de_l_enrolement_partage_le_verrou_de_la_connexion() {
        let (st, _p) = sp_state("sfpr-verrou");
        let seuil = st.lock_threshold;
        assert!(seuil >= 2, "fixture : seuil {seuil}");
        let ip = "10.42.0.1";
        for i in 0..seuil {
            let (statut, _, corps) = sfpr_enroler(&st, "alice", ip, Some(&format!("faux-{i}"))).await;
            assert_eq!(statut, 403, "l'essai {i} est un refus ordinaire : {corps}");
        }
        let (statut, attente, corps) = sfpr_enroler(&st, "alice", ip, Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 429, "verrouillé : le mot de passe JUSTE n'est même pas examiné : {corps}");
        assert!(attente.is_some(), "le refus dit combien attendre (Retry-After)");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT), "{corps}");
        assert_eq!(sfpr_lignes_mfa(&st, "alice"), 0, "aucune graine");
        let (statut, session, _) = sfpr_connexion(&st, "alice", SFPR_MOT_DE_PASSE, ip).await;
        assert_eq!((statut, session), (429, false), "la connexion du même couple est verrouillée : UN compteur");

        let (statut, _, corps) = sfpr_enroler(&st, "alice", "10.42.0.2", Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 200, "depuis une autre adresse, le titulaire enrôle : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.23-b` — UN COMPTE SANS MOT DE PASSE LOCAL N'ENRÔLE PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un compte fédéré (`IDP_HASH_SENTINEL`, posé par `idp_provision_user`), un compte au hachage
    /// vide et une identité SSO par en-têtes sans ligne locale reçoivent le `403` NOMMÉ « sans mot de passe local »,
    /// quel que soit le mot de passe présenté : aucune graine, aucun échec compté, rien au registre. CONTRÔLE
    /// POSITIF : l'administrateur de CONFIGURATION (hors table `user`, `PLUME_PASS_HASH`) prouve son mot de passe et
    /// enrôle — la préséance est celle d'`authenticate`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans `le_compte_a_un_mot_de_passe_local`, ne plus écarter la sentinelle
    /// (`Some(h) => !h.is_empty()`) — le compte fédéré reçoit « mot de passe refusé » et un échec lui est compté :
    /// une fausse accusation, sur un compte qui n'a pas de mot de passe à donner.
    #[tokio::test]
    async fn sfpr_un_compte_sans_mot_de_passe_local_n_enrole_pas_et_rien_n_est_compte() {
        let (st, _p) = sp_state("sfpr-sans-mot-de-passe");
        st.db
            .lock()
            .execute_batch(&format!(
                "INSERT INTO user(name,hash,role) VALUES('fed','{}','editor'); INSERT INTO user(name,hash,role) VALUES('vide','','editor');",
                IDP_HASH_SENTINEL
            ))
            .expect("fixture : comptes sans mot de passe local");
        let ip = "10.43.0.1";
        for user in ["fed", "vide", "hdr"] {
            let (statut, _, corps) = sfpr_enroler(&st, user, ip, Some("un-mot-de-passe-quelconque")).await;
            assert_eq!(statut, 403, "{user} : pas de mot de passe local, pas d'enrôlement : {corps}");
            assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL), "{user} : {corps}");
            assert_eq!(sfpr_lignes_mfa(&st, user), 0, "{user} : aucune graine");
            assert_eq!(sfpr_echecs_du_couple(&st, user, ip), 0, "{user} : aucun échec compté — personne n'est accusé");
        }
        assert_eq!(sfpr_registre(&st, "enrôlement MFA refusé"), 0, "rien au registre");

        // CONTRÔLE POSITIF — l'administrateur de configuration, hors table, prouve son mot de passe.
        let mut st = st;
        st.user = Arc::new("cfgadmin".to_string());
        st.pass_hash = Arc::new(hash_pw(SFPR_MOT_DE_PASSE).expect("fixture : hachage"));
        let (statut, _, corps) = sfpr_enroler(&st, "cfgadmin", ip, Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 200, "l'administrateur de configuration enrôle : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.23-b` — UNE LECTURE RATÉE DU COMPTE N'ACCUSE PERSONNE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture du hachage refusée (autorisateur SQLite), le mot de passe JUSTE rend un `503`
    /// NOMMÉ — ni « sans mot de passe local » (un fait inventé), ni « refusé » (une accusation) : aucune graine,
    /// aucun échec compté ; la lecture revenue, le même geste enrôle.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : lire le hachage par `.ok().flatten()` au lieu de `.optional()?` — la lecture
    /// ratée devient « aucune ligne », et le compte reçoit le `403` « sans mot de passe local ».
    #[tokio::test]
    async fn sfpr_une_lecture_ratee_du_compte_refuse_l_enrolement_sans_accuser() {
        let (st, _p) = sp_state("sfpr-compte-non-lu");
        let ip = "10.44.0.1";
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, _, corps) = sfpr_enroler(&st, "adm", ip, Some(SFPR_MOT_DE_PASSE)).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "compte non lu : ni accepté ni refusé : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT), "{corps}");
        assert_eq!(sfpr_lignes_mfa(&st, "adm"), 0, "aucune graine");
        assert_eq!(sfpr_echecs_du_couple(&st, "adm", ip), 0, "aucun échec compté");

        let (statut, _, corps) = sfpr_enroler(&st, "adm", ip, Some(SFPR_MOT_DE_PASSE)).await;
        assert_eq!(statut, 200, "la lecture revenue, le même geste enrôle : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.23-b` — UN ENRÔLEMENT NE DÉSARME PAS UNE MFA ACTIVÉE PENDANT SA PREUVE
    //
    // Le banc : une TROISIÈME connexion tient le verrou d'écriture (WAL) ; l'enrôlement lit `enabled=0`, prouve le
    // mot de passe, puis se bloque sur son écriture ; son gestionnaire d'occupation le signale. L'activation du
    // titulaire est alors validée par la troisième connexion, et seulement ensuite le verrou est relâché.
    // -------------------------------------------------------------------------------------

    static SFPR_BLOQUES_ENROLEMENT: AtomicUsize = AtomicUsize::new(0);
    fn sfpr_signaler_enrolement(essai: i32) -> bool {
        if essai == 0 {
            SFPR_BLOQUES_ENROLEMENT.fetch_add(1, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(2));
        essai < 5_000
    }

    /// CE QU'IL TIENT : l'enrôlement qui a lu la MFA « en attente » et dont l'écriture arrive APRÈS l'activation
    /// rend `409` et n'écrit rien : la graine activée reste en place, `enabled=1`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer `WHERE user_mfa.enabled=0` de l'écriture
    /// d'enrôlement — `200`, une graine neuve posée par-dessus la graine ACTIVÉE, `enabled=0` : le second facteur du
    /// compte désarmé par un enrôlement.
    #[test]
    fn sfpr_un_enrolement_ne_desarme_pas_une_mfa_activee_pendant_sa_preuve() {
        let (st, p) = sp_state("sfpr-course-enrolement");
        let graine = base32_encode(SFPR_GRAINE);
        st.db
            .lock()
            .execute("INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,0,'[]',-1,0,0)", params![graine])
            .expect("fixture : enrôlement en attente");
        let mode: String = st.db.lock().query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("fixture : WAL");
        assert_eq!(mode, "wal", "fixture : WAL (les lectures ne sont pas bloquées par l'écrivain)");
        let st1 = ds_file_state(&p);
        st1.db.lock().busy_handler(Some(sfpr_signaler_enrolement)).expect("fixture");
        let tient_le_verrou = open_db(&p).expect("fixture : troisième connexion");
        tient_le_verrou.execute_batch("BEGIN IMMEDIATE").expect("fixture : verrou d'écriture pris");

        let enrolement = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de fil");
            rt.block_on(async move { sfpr_enroler(&st1, "adm", "10.45.0.1", Some(SFPR_MOT_DE_PASSE)).await })
        });
        // Ce qui est établi est un COMPTE (l'enrôlement bloqué une fois sur son écriture) ; le filet qui empêche la
        // fixture d'attendre sans fin est un nombre d'essais, pas une échéance d'horloge.
        let mut essais = 0u32;
        while SFPR_BLOQUES_ENROLEMENT.load(Ordering::SeqCst) < 1 && essais < 6_000 {
            std::thread::sleep(Duration::from_millis(5));
            essais += 1;
        }
        assert_eq!(SFPR_BLOQUES_ENROLEMENT.load(Ordering::SeqCst), 1, "fixture : l'enrôlement s'est bloqué UNE fois sur son écriture");
        tient_le_verrou
            .execute("UPDATE user_mfa SET enabled=1, last_step=?1 WHERE user='adm' AND enabled=0", params![now() / 30])
            .expect("fixture : l'activation du titulaire");
        tient_le_verrou.execute_batch("COMMIT").expect("fixture : activation validée");
        let (statut, _, corps) = enrolement.join().expect("fil d'enrôlement");

        // L'ÉTAT D'ABORD : c'est lui l'enjeu (un second facteur désarmé), le statut n'en est que le compte rendu.
        let (secret, enabled): (String, i64) =
            st.db.lock().query_row("SELECT secret,enabled FROM user_mfa WHERE user='adm'", [], |r| Ok((r.get(0)?, r.get(1)?))).expect("ligne");
        assert_eq!((secret == graine, enabled), (true, 1), "la graine ACTIVÉE est en place, le second facteur armé (statut {statut}) : {corps}");
        assert_eq!(statut, 409, "la MFA est devenue active : l'enrôlement n'écrit rien : {corps}");
        assert!(corps.get("secret").is_none(), "aucune graine servie : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.22-x` — UN TICKET ÉMIS AVANT UN CHANGEMENT DE MOT DE PASSE NE SERT PLUS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `adm` (administrateur de l'assistant, MFA active) reçoit un ticket ; son mot de passe est
    /// changé (`password_post`, l'époque avance) ; le ticket d'avant, avec un code JUSTE, est refusé en `401` nommé :
    /// aucune session, le pas n'est pas consommé, aucune connexion attestée, aucun échec compté (ni au frein du
    /// compte, ni au couple). CONTRÔLE POSITIF : le NOUVEAU mot de passe rend un ticket qui ouvre la session.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `{epoch}` du message signé par `mfa_ticket_sign` et vérifié par
    /// `mfa_ticket_verify` (la forme d'avant) — le ticket d'avant ouvre une session valide APRÈS le changement.
    #[tokio::test]
    async fn sfpr_un_ticket_emis_avant_un_changement_de_mot_de_passe_ne_sert_plus() {
        let (st, _p, graine) = sfpr_etat_mfa_active("ticket-mot-de-passe", "adm");
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("adm".into(), h));
        let ip = "10.46.0.1";
        let (statut, _, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, ip).await;
        assert_eq!((statut, ticket.is_empty()), (200, false), "fixture : le mot de passe rend un ticket");

        let epoque = sfpr_epoque(&st);
        let r = password_post(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "new": "un-autre-mot-de-passe-long" }))).await;
        assert_eq!(r.status().as_u16(), 200, "fixture : le mot de passe est changé");
        assert_eq!(sfpr_epoque(&st), epoque + 1, "fixture : le changement fait avancer l'époque de session");

        let (statut, session, corps) = sfpr_second_facteur(&st, &ticket, &sfpr_code(&graine, now() / 30), ip).await;
        assert_eq!((statut, session), (401, false), "le ticket d'avant le changement ne sert plus : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE), "{corps}");
        assert_eq!(sfpr_compter(&st, "SELECT last_step FROM user_mfa WHERE user='adm'"), -1, "le pas n'est pas consommé");
        assert_eq!(sfpr_registre(&st, "login local MFA validé"), 0, "aucune connexion attestée");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "adm"), 0, "rien au frein du compte");
        assert_eq!(sfpr_echecs_du_couple(&st, "adm", ip), 0, "rien au verrou du couple");

        // CONTRÔLE POSITIF — le nouveau mot de passe, un ticket neuf, la session.
        let (_, _, ticket) = sfpr_connexion(&st, "adm", "un-autre-mot-de-passe-long", ip).await;
        let (statut, session, corps) = sfpr_second_facteur(&st, &ticket, &sfpr_code(&graine, now() / 30), ip).await;
        assert_eq!((statut, session), (200, true), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.22-x` — UN TICKET ÉMIS AVANT UNE DÉCONNEXION (RÉVOCATION DES SESSIONS) NE SERT PLUS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un ticket de `adm` est émis ; une déconnexion portant une session valide révoque les
    /// sessions (`logout_post`, l'époque avance) ; le ticket d'avant, code juste, rend `401` nommé sans session.
    /// CONTRÔLE POSITIF : un ticket émis APRÈS la révocation ouvre la session.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : celle du témoin (7).
    #[tokio::test]
    async fn sfpr_un_ticket_emis_avant_une_revocation_des_sessions_ne_sert_plus() {
        let (st, _p, graine) = sfpr_etat_mfa_active("ticket-revocation", "adm");
        let ip = "10.47.0.1";
        let (_, _, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, ip).await;
        assert!(!ticket.is_empty(), "fixture : ticket");
        let epoque = sfpr_epoque(&st);
        let jeton = mint_session(st.session_secret.as_slice(), "alice", "editor", st.session_ttl_s, epoque);
        let mut en_tetes = axum::http::HeaderMap::new();
        en_tetes.insert(header::COOKIE, format!("plume_session={jeton}").parse().expect("en-tête"));
        let _ = logout_post(State(st.clone()), en_tetes).await;
        assert_eq!(sfpr_epoque(&st), epoque + 1, "fixture : la déconnexion révoque les sessions");

        let (statut, session, corps) = sfpr_second_facteur(&st, &ticket, &sfpr_code(&graine, now() / 30), ip).await;
        assert_eq!((statut, session), (401, false), "le ticket d'avant la révocation ne sert plus : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE), "{corps}");

        let (_, _, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, ip).await;
        let (statut, session, corps) = sfpr_second_facteur(&st, &ticket, &sfpr_code(&graine, now() / 30), ip).await;
        assert_eq!((statut, session), (200, true), "un ticket émis après la révocation sert : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (9) `P10.22-x` — UN TICKET NE PASSE PAS POUR UN COOKIE DE SESSION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : lier le ticket à l'époque ne le rapproche pas d'une session. Le ticket servi par
    /// `login_post`, présenté comme cookie `plume_session` à la résolution d'identité, n'authentifie PERSONNE.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : signer le ticket comme une session (`{p_b64}|{epoch}`, sans le préfixe
    /// `mfa-ticket|`) — `verify_session` l'accepte, pour l'utilisateur `mfa|adm`.
    #[tokio::test]
    async fn sfpr_un_ticket_ne_passe_pas_pour_une_session() {
        let (st, _p, _) = sfpr_etat_mfa_active("ticket-session", "adm");
        let (_, _, ticket) = sfpr_connexion(&st, "adm", SFPR_MOT_DE_PASSE, "10.48.0.1").await;
        assert!(!ticket.is_empty(), "fixture : ticket");
        assert!(verify_session(st.session_secret.as_slice(), &ticket, sfpr_epoque(&st)).is_none(), "le ticket n'est pas une session");
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={ticket}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        let (ident, methode, ..) = resolve_identity(&st, &req);
        assert!(ident.is_none(), "aucune identité par un ticket présenté en cookie ({methode})");
    }
}
