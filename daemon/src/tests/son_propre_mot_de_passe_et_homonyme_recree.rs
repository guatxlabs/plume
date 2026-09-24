// =====================================================================================
// `P10.24-a` — `/api/users/{id}` NE CHANGE PLUS LE MOT DE PASSE DE L'APPELANT SUR LA SEULE SESSION.
// `P10.24-c` — SUPPRIMER UN COMPTE RÉVOQUE SES JETONS ET RETIRE SON SECOND FACTEUR : UN HOMONYME RECRÉÉ N'HÉRITE
//              NI D'UNE SESSION, NI D'UN TICKET, NI D'UNE GRAINE.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (ces témoins joués sur la forme d'avant) :
//  * `P10.24-a` : sous la seule session de `adm`, `user_update` sur son propre identifiant avec `{password}` -> 204,
//    et avec `{password, current: <faux>}` -> 204 aussi (`current` n'était pas lu) : une session volée remplaçait
//    le mot de passe du titulaire, qui était enfermé dehors, et ses sessions à lui étaient révoquées ;
//  * `P10.24-c` : après `user_delete` puis `user_create` d'un homonyme, la session frappée AVANT la suppression
//    résolvait l'identité du NOUVEAU compte, le ticket MFA d'avant ouvrait une session avec un code de l'ANCIENNE
//    graine, et la connexion du nouveau titulaire, par son propre mot de passe, était arrêtée au second facteur de
//    l'ancien (`mfa_required`) — la ligne `user_mfa` et la ligne `user_pref` survivaient à la suppression.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (la preuve y est jugée par la résolution du mode 0).
// Les trois restes que cet en-tête nommait ici — le frein du second facteur et le compteur d'échecs tenus en mémoire
// par nom, les objets d'un compte supprimé restés à son nom, le compte de l'administrateur de l'assistant — sont
// tenus depuis par `suppression_de_compte_complete.rs` (`P10.24-o`, `P10.24-p`, `P10.24-n`).
// =====================================================================================
mod son_propre_mot_de_passe_et_homonyme_recree {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::Ordering;

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const RPCH_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const RPCH_GRAINE: &[u8] = b"12345678901234567890";

    /// Un mot de passe neuf recevable (au moins `PASSWORD_MIN_CHARS`), construit — jamais un littéral de clé.
    fn rpch_neuf(marque: &str) -> String {
        format!("rpch-{marque}-{}", "n".repeat(PASSWORD_MIN_CHARS))
    }

    async fn rpch_corps(r: Response) -> (u16, Option<String>, Option<String>, Value) {
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

    fn rpch_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    fn rpch_code(graine_b32: &str) -> String {
        hotp(&base32_decode(graine_b32).expect("graine base32"), (now() / 30) as u64, 6)
    }

    fn rpch_epoque_globale(st: &AppState) -> i64 {
        st.session_epoch.load(Ordering::SeqCst)
    }

    fn rpch_epoque_du_compte(st: &AppState, user: &str) -> i64 {
        epoque_du_compte(&st.db.lock(), user).expect("fixture : l'époque du compte se lit")
    }

    fn rpch_compte(st: &AppState, sql: &str, nom: &str) -> i64 {
        st.db.lock().query_row(sql, params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn rpch_registre(st: &AppState, motif: &str) -> i64 {
        rpch_compte(st, "SELECT COUNT(*) FROM ledger WHERE substr(detail, 1, length(?1)) = ?1", motif)
    }

    fn rpch_registre_de_type(st: &AppState, genre: &str) -> i64 {
        rpch_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind = ?1", genre)
    }

    fn rpch_echecs_du_couple(st: &AppState, user: &str, ip: &str) -> u32 {
        st.auth_fails.lock().get(&(user.to_string(), ip.to_string())).map_or(0, |f| f.count)
    }

    fn rpch_evenements_d_acces(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-auth'", [], |r| r.get(0)).expect("fixture : event se lit")
    }

    fn rpch_id(st: &AppState, nom: &str) -> i64 {
        rpch_compte(st, "SELECT id FROM user WHERE name=?1", nom)
    }

    fn rpch_hachage(st: &AppState, nom: &str) -> String {
        st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : hachage du compte")
    }

    /// L'identité que la résolution servie donne à un cookie `plume_session`.
    fn rpch_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    /// Une session frappée par le chemin servi (époque globale et époque du compte COURANTES).
    fn rpch_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session de {user} frappée"))
    }

    /// `POST /api/users/{id}` tel que la console le joue sous la session de `appelant` (administrateur).
    async fn rpch_modifier(st: &AppState, appelant: &str, cible: &str, corps: Value, ip: &str) -> (u16, Option<String>, Value) {
        let id = rpch_id(st, cible);
        let (s, _, attente, c) = rpch_corps(
            user_update(State(st.clone()), ConnectInfo(rpch_pair(ip)), Extension(sp_au(appelant, "admin")), axum::extract::Path(id), Json(corps)).await,
        )
        .await;
        (s, attente, c)
    }

    /// Le corps d'un changement de mot de passe : `actuel` = `None` pour un corps sans champ `current`.
    fn rpch_corps_du_changement(actuel: Option<&str>, neuf: &str) -> Value {
        match actuel {
            Some(a) => json!({ "password": neuf, "current": a }),
            None => json!({ "password": neuf }),
        }
    }

    /// Le premier facteur tel qu'un navigateur le joue : `(statut, cookie de session, corps)`.
    async fn rpch_connexion(st: &AppState, user: &str, mot_de_passe: &str, ip: &str) -> (u16, Option<String>, Value) {
        let (s, session, _, c) =
            rpch_corps(login_post(State(st.clone()), ConnectInfo(rpch_pair(ip)), Json(json!({ "user": user, "pass": mot_de_passe }))).await).await;
        (s, session, c)
    }

    async fn rpch_second_facteur(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, Option<String>, Value) {
        let (s, session, _, c) =
            rpch_corps(login_mfa_post(State(st.clone()), ConnectInfo(rpch_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await).await;
        (s, session, c)
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-a` — LA SESSION SEULE NE CHANGE PAS LE MOT DE PASSE DE L'APPELANT PAR `/api/users/{id}`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la session de `adm`, sur SON identifiant, un corps qui change le mot de passe est refusé
    /// en `403` nommé — sans `current` : rien de compté ; `current` faux : un échec compté au verrou (compte, adresse)
    /// de la connexion, un événement d'accès au SIEM, une ligne au registre — et rien n'a changé : le neuf ne connecte
    /// pas, l'ancien connecte, l'époque du compte n'a pas bougé, aucune réinitialisation n'est attestée, et le rôle
    /// demandé dans le même corps n'est pas appliqué. CONTRÔLE POSITIF : le VRAI mot de passe actuel change le mot de
    /// passe (204, réinitialisation attestée, compteur du couple remis à zéro, sessions du compte révoquées).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer l'exigence de `user_update` (ne plus
    /// juger `current` quand la cible est l'appelant) — `204` sur la session seule.
    #[tokio::test]
    async fn rpch_son_propre_mot_de_passe_ne_change_pas_sur_la_seule_session() {
        let (st, _p) = sp_state("rpch-session-seule");
        let ip = "10.71.0.1";
        let neuf = rpch_neuf("session-seule");
        // Un second administrateur : la rétrogradation de `adm` demandée plus bas est RECEVABLE (anti-verrouillage).
        let hachage_d_alice = rpch_hachage(&st, "alice");
        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES('adm2',?1,'admin')", params![hachage_d_alice]).expect("fixture : adm2");

        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(None, &neuf), ip).await;
        assert_eq!(statut, 403, "une session seule ne change pas le mot de passe de l'appelant : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_EXIGE), "{corps}");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "un corps sans mot de passe actuel ne compte rien");

        let mut faux = rpch_corps_du_changement(Some("pas-le-mot-de-passe-actuel"), &neuf);
        faux["role"] = json!("editor");
        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", faux, ip).await;
        assert_eq!(statut, 403, "un mot de passe actuel faux ne change rien : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE), "{corps}");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 1, "l'échec est compté au verrou de la connexion");
        assert_eq!(rpch_evenements_d_acces(&st), 1, "et vu du SIEM");
        assert_eq!(rpch_registre(&st, "réinitialisation du mot de passe de son propre compte 'adm' refusée"), 1, "et inscrit au registre");

        assert_eq!(rpch_registre_de_type(&st, "config.user.password_reset"), 0, "aucune réinitialisation attestée");
        assert_eq!(rpch_registre_de_type(&st, "config.user.role_change"), 0, "le rôle du même corps n'est pas appliqué");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1 AND role='admin'", "adm"), 1, "adm reste administrateur");
        assert_eq!(rpch_epoque_du_compte(&st, "adm"), 0, "aucune session du compte révoquée");
        let (statut, _, _) = rpch_connexion(&st, "adm", &neuf, "10.71.0.2").await;
        assert_eq!(statut, 401, "le mot de passe n'a PAS changé : le neuf ne connecte pas");
        let (statut, session, _) = rpch_connexion(&st, "adm", RPCH_MOT_DE_PASSE_DE_FIXTURE, "10.71.0.3").await;
        assert_eq!((statut, session.is_some()), (200, true), "l'ancien connecte toujours");

        // CONTRÔLE POSITIF — le vrai mot de passe actuel.
        let session_d_avant = rpch_session(&st, "adm", "admin");
        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(RPCH_MOT_DE_PASSE_DE_FIXTURE), &neuf), ip).await;
        assert_eq!(statut, 204, "le mot de passe actuel prouvé change le mot de passe : {corps}");
        assert_eq!(rpch_registre_de_type(&st, "config.user.password_reset"), 1, "réinitialisation attestée");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "une preuve réussie remet le couple à zéro, comme la connexion");
        assert_eq!(rpch_epoque_du_compte(&st, "adm"), 1, "les sessions et tickets du compte sont révoqués");
        assert_eq!(rpch_identite(&st, &session_d_avant), None, "la session d'avant ne vaut plus");
        let (statut, _, _) = rpch_connexion(&st, "adm", RPCH_MOT_DE_PASSE_DE_FIXTURE, "10.71.0.4").await;
        assert_eq!(statut, 401, "l'ancien ne connecte plus");
        let (statut, session, _) = rpch_connexion(&st, "adm", &neuf, "10.71.0.5").await;
        assert_eq!((statut, session.is_some()), (200, true), "le neuf connecte");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-a` — LE MOT DE PASSE ACTUEL PARTAGE LE VERROU DE LA CONNEXION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` mots de passe actuels faux depuis une adresse posent le verrou (compte, adresse) : le
    /// mot de passe actuel JUSTE y est ensuite refusé en `429` nommé (Retry-After), rien n'est écrit — et la CONNEXION
    /// du même compte depuis la même adresse est verrouillée aussi (un seul compteur, partagé avec `/api/login` et
    /// `/api/password`). Depuis une autre adresse, le changement passe.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans le jugement partagé du mot de passe actuel, rendre le verrou comme une
    /// preuve faite (`Verrouillee(_) => {}`) — le mot de passe change depuis l'adresse verrouillée (`204`).
    #[tokio::test]
    async fn rpch_son_propre_mot_de_passe_partage_le_verrou_de_la_connexion() {
        let (st, _p) = sp_state("rpch-verrou");
        let seuil = st.lock_threshold;
        assert!(seuil >= 2, "fixture : seuil {seuil}");
        let ip = "10.72.0.1";
        let neuf = rpch_neuf("verrou");
        for i in 0..seuil {
            let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(&format!("faux-{i}")), &neuf), ip).await;
            assert_eq!(statut, 403, "l'essai {i} est un refus ordinaire : {corps}");
        }
        let (statut, attente, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(RPCH_MOT_DE_PASSE_DE_FIXTURE), &neuf), ip).await;
        assert_eq!(statut, 429, "verrouillé : le mot de passe actuel JUSTE n'est même pas examiné : {corps}");
        assert!(attente.is_some(), "le refus dit combien attendre (Retry-After)");
        assert_eq!(corps["error"], json!(CAUSE_MOT_DE_PASSE_ACTUEL_VERROUILLE), "{corps}");
        assert_eq!(rpch_registre_de_type(&st, "config.user.password_reset"), 0, "rien n'est écrit");
        let (statut, session, _) = rpch_connexion(&st, "adm", RPCH_MOT_DE_PASSE_DE_FIXTURE, ip).await;
        assert_eq!((statut, session.is_some()), (429, false), "la connexion du même couple est verrouillée : UN compteur");

        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(RPCH_MOT_DE_PASSE_DE_FIXTURE), &neuf), "10.72.0.2").await;
        assert_eq!(statut, 204, "depuis une autre adresse, le titulaire change son mot de passe : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-a` — UNE LECTURE RATÉE N'ACCUSE PERSONNE ; UN COMPTE SANS MOT DE PASSE LOCAL NE S'EN POSE PAS UN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture du hachage refusée (autorisateur SQLite), le mot de passe actuel JUSTE rend un `503`
    /// NOMMÉ — ni « refusé », ni un changement : aucun échec compté, rien d'écrit ; la lecture revenue, le même geste
    /// change le mot de passe. Et un administrateur FÉDÉRÉ (hachage sentinelle des comptes OIDC, SAML, LDAP) ne se
    /// pose PAS un mot de passe local sur la foi de sa session : `403` nommé qui renvoie à un AUTRE administrateur,
    /// le hachage reste la sentinelle, personne n'est accusé. Ce geste-là était le pire de la forme d'avant : une
    /// session fédérée volée devenait un mot de passe local, hors de portée de l'annuaire qui la révoque.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : dans le jugement partagé, rendre `CompteNonLu` comme `Refusee` — la lecture
    /// ratée devient une accusation comptée ; ou `SansMotDePasseLocal => {}` — un mot de passe est posé sans preuve.
    #[tokio::test]
    async fn rpch_une_lecture_ratee_n_accuse_personne_et_un_compte_federe_ne_se_pose_pas_de_mot_de_passe() {
        let (st, _p) = sp_state("rpch-compte-non-lu");
        let ip = "10.73.0.1";
        let neuf = rpch_neuf("compte-non-lu");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(RPCH_MOT_DE_PASSE_DE_FIXTURE), &neuf), ip).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "compte non lu : ni changé ni refusé : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_NON_LU_AU_CHANGEMENT), "{corps}");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "aucun échec compté");
        assert_eq!(rpch_registre_de_type(&st, "config.user.password_reset"), 0, "rien n'est écrit");
        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some(RPCH_MOT_DE_PASSE_DE_FIXTURE), &neuf), ip).await;
        assert_eq!(statut, 204, "la lecture revenue, le même geste change le mot de passe : {corps}");

        // L'ADMINISTRATEUR FÉDÉRÉ — rien à prouver, donc rien à poser sur la foi de sa session.
        let (st, _p) = sp_state("rpch-compte-federe");
        st.db.lock().execute("UPDATE user SET hash=?1 WHERE name='adm'", params![IDP_HASH_SENTINEL]).expect("fixture : adm fédéré");
        let (statut, _, corps) = rpch_modifier(&st, "adm", "adm", rpch_corps_du_changement(Some("un-mot-de-passe-quelconque"), &neuf), ip).await;
        assert_eq!(statut, 403, "aucun mot de passe actuel à prouver : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_SON_PROPRE_COMPTE_SANS_MOT_DE_PASSE_LOCAL), "{corps}");
        assert_eq!(rpch_hachage(&st, "adm"), IDP_HASH_SENTINEL, "aucun mot de passe local posé sur la foi d'une session");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "personne n'est accusé");
        assert_eq!(rpch_registre_de_type(&st, "config.user.password_reset"), 0, "rien n'est écrit");
        // CONTRÔLE POSITIF — le remède que la cause nomme : un AUTRE administrateur le pose, et c'est tracé.
        let hachage_d_alice = rpch_hachage(&st, "alice");
        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES('adm2',?1,'admin')", params![hachage_d_alice]).expect("fixture : adm2");
        let (statut, _, corps) = rpch_modifier(&st, "adm2", "adm", rpch_corps_du_changement(None, &neuf), ip).await;
        assert_eq!(statut, 204, "un autre administrateur pose le mot de passe : {corps}");
        assert_eq!(rpch_registre(&st, "mot de passe du compte 'adm' réinitialisé par adm2"), 1, "tracé au registre");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.24-a`, LA DÉCISION — UN ADMINISTRATEUR RÉINITIALISE UN AUTRE COMPTE SANS SON MOT DE PASSE ; C'EST TRACÉ
    //     ET LE COMPTE VISÉ EST RÉVOQUÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `adm` réinitialise le mot de passe de `bob` sans `current` (c'est le geste d'administration :
    /// le titulaire l'a oublié, ou il faut lui retirer l'accès) — `204` ; la réinitialisation est au registre ET au
    /// SIEM (source `plume-config`, sévérité 4, alertable) sous le nom de celui qui l'a faite ; la session de `bob`
    /// ne vaut plus, celle de `adm` vaut toujours, l'époque globale n'a pas bougé, et rien n'est compté au verrou de
    /// `adm`. Un `current` joint au corps n'est ni exigé ni jugé.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : exiger la preuve pour TOUTE cible (la condition « la cible est l'appelant »
    /// retirée) — le geste d'administration serait refusé (`403`) ; et celle de `P10.23-l` (retirer l'avancée de
    /// l'époque du compte) — la session de `bob` vaut encore.
    #[tokio::test]
    async fn rpch_un_administrateur_reinitialise_un_autre_compte_trace_et_revoque() {
        let (st, _p) = sp_state("rpch-autre-compte");
        let ip = "10.74.0.1";
        let session_de_bob = rpch_session(&st, "bob", "editor");
        let session_d_adm = rpch_session(&st, "adm", "admin");
        let epoque = rpch_epoque_globale(&st);
        let neuf = rpch_neuf("autre-compte");

        let (statut, _, corps) = rpch_modifier(&st, "adm", "bob", rpch_corps_du_changement(None, &neuf), ip).await;
        assert_eq!(statut, 204, "le geste d'administration reste : {corps}");
        assert_eq!(rpch_registre(&st, "mot de passe du compte 'bob' réinitialisé par adm"), 1, "tracé au registre, au nom de l'auteur");
        let au_siem: i64 = st
            .db
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM event WHERE source='plume-config' AND severity=4 \
                 AND json_extract(fields,'$.action')='config.user.password_reset' AND json_extract(fields,'$.target')='bob' \
                 AND json_extract(fields,'$.actor')='adm'",
                [],
                |r| r.get(0),
            )
            .expect("fixture : event se lit");
        assert_eq!(au_siem, 1, "et au SIEM, sévérité 4 (alertable)");
        assert_eq!(rpch_identite(&st, &session_de_bob), None, "la session de bob ne vaut plus");
        assert_eq!(rpch_identite(&st, &session_d_adm), Some(("adm".into(), "admin".into())), "celle de l'auteur vaut toujours");
        assert_eq!(rpch_epoque_du_compte(&st, "adm"), 0, "les sessions de l'auteur ne sont pas révoquées");
        assert_eq!(rpch_epoque_globale(&st), epoque, "l'époque globale n'a pas bougé");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "rien n'est compté au verrou de l'auteur");

        // Un `current` FAUX joint au corps n'est pas jugé : ce n'est pas le compte de l'appelant.
        let (statut, _, corps) = rpch_modifier(&st, "adm", "bob", rpch_corps_du_changement(Some("sans-objet"), &rpch_neuf("autre-2")), ip).await;
        assert_eq!(statut, 204, "`current` n'est pas jugé pour un autre compte : {corps}");
        assert_eq!(rpch_echecs_du_couple(&st, "adm", ip), 0, "et rien n'est compté");
        let (statut, session, _) = rpch_connexion(&st, "bob", &rpch_neuf("autre-2"), "10.74.0.2").await;
        assert_eq!((statut, session.is_some()), (200, true), "bob se connecte par le mot de passe posé");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.24-c` — UN HOMONYME RECRÉÉ N'HÉRITE NI D'UNE SESSION, NI D'UN TICKET, NI D'UNE GRAINE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` (MFA active, préférences posées) a une session et un ticket ; `alice` a une session. Un
    /// administrateur supprime `bob` (204) puis crée un compte du même nom (200) avec un autre mot de passe. La session
    /// de l'ancien `bob` ne résout AUCUNE identité ; son ticket, avec un code juste de l'ANCIENNE graine, rend le `401`
    /// nommé du ticket, sans session ; la ligne `user_mfa` et la ligne `user_pref` de l'ancien compte n'existent plus ;
    /// le nouveau titulaire se connecte par SON mot de passe sans second facteur (200, cookie), et cette session
    /// résout son identité. La session d'`alice` vaut toujours, l'époque globale n'a pas bougé.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer de `user_delete` l'avancée de l'époque du compte — la session de
    /// l'ancien `bob` résout l'identité du nouveau ; retirer la purge de `user_mfa` — la graine de l'ancien compte est
    /// encore là (et la connexion du nouveau titulaire serait arrêtée à son second facteur, `mfa_required`) ; retirer
    /// celle de `user_pref` — ses préférences passent au nouveau.
    #[tokio::test]
    async fn rpch_un_homonyme_recree_n_herite_ni_session_ni_ticket_ni_graine() {
        let (st, _p) = sp_state("rpch-homonyme");
        let graine = base32_encode(RPCH_GRAINE);
        {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('bob',?1,1,'[]',-1,0,0)",
                params![graine],
            )
            .expect("fixture : MFA de bob");
            c.execute("INSERT INTO user_pref(user,prefs,updated) VALUES('bob','{\"favoris\":[1]}',0)", []).expect("fixture : préférences de bob");
        }
        let ip = "10.75.0.1";
        let session_de_bob = rpch_session(&st, "bob", "editor");
        let session_d_alice = rpch_session(&st, "alice", "editor");
        let (statut, _, corps) = rpch_connexion(&st, "bob", RPCH_MOT_DE_PASSE_DE_FIXTURE, ip).await;
        let ticket_de_bob = corps["ticket"].as_str().unwrap_or("").to_string();
        assert_eq!((statut, ticket_de_bob.is_empty()), (200, false), "fixture : le mot de passe de bob rend un ticket : {corps}");
        let epoque = rpch_epoque_globale(&st);

        let r = user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(rpch_id(&st, "bob"))).await;
        assert_eq!(r.status().as_u16(), 204, "fixture : bob supprimé");
        let neuf = rpch_neuf("homonyme");
        let (statut, _, _, corps) = rpch_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": "bob", "password": neuf, "role": "viewer" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : un homonyme est créé : {corps}");

        assert_eq!(rpch_identite(&st, &session_de_bob), None, "la session de l'ancien bob ne vaut rien pour le nouveau");
        let (statut, session, corps) = rpch_second_facteur(&st, &ticket_de_bob, &rpch_code(&graine), ip).await;
        assert_eq!((statut, session.is_some()), (401, false), "le ticket de l'ancien bob n'ouvre rien : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_TICKET_MFA_INVALIDE_EXPIRE_OU_REVOQUE), "{corps}");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "bob"), 0, "la graine de l'ancien bob est retirée");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user_pref WHERE user=?1", "bob"), 0, "ses préférences aussi");
        let (statut, session, corps) = rpch_connexion(&st, "bob", &neuf, ip).await;
        assert_eq!((statut, corps["mfa_required"].as_bool()), (200, None), "le nouveau titulaire n'est pas arrêté au second facteur de l'ancien : {corps}");
        let session = session.expect("session posée");
        assert_eq!(rpch_identite(&st, &session), Some(("bob".into(), "viewer".into())), "et sa session résout son identité");
        assert_eq!(rpch_identite(&st, &session_d_alice), Some(("alice".into(), "editor".into())), "la session d'alice vaut toujours");
        assert_eq!(rpch_epoque_globale(&st), epoque, "l'époque globale n'a pas bougé");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.24-c` — LA RÉVOCATION ET LA PURGE SONT DANS LA TRANSACTION DE LA SUPPRESSION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la purge de `user_mfa` refusée (autorisateur SQLite), la suppression n'a PAS lieu — `500`
    /// nommé, le compte existe toujours, son époque n'a pas bougé, sa graine est là, aucune suppression n'est
    /// attestée. La purge revenue, le même geste supprime (204), avance l'époque et retire la graine.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : avaler l'échec de la purge (`let _ = conn.execute(...)`) — le compte est
    /// supprimé, `204`, et sa graine survit pour le prochain homonyme.
    #[tokio::test]
    async fn rpch_la_revocation_et_la_purge_sont_dans_la_transaction_de_la_suppression() {
        let (st, _p) = sp_state("rpch-atomique");
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('bob',?1,1,'[]',-1,0,0)",
                params![base32_encode(RPCH_GRAINE)],
            )
            .expect("fixture : MFA de bob");
        let id = rpch_id(&st, "bob");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name } if table_name == "user_mfa" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(r.status().as_u16(), 500, "la purge refusée, la suppression n'a pas lieu");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "bob"), 1, "le compte existe toujours");
        assert_eq!(rpch_epoque_du_compte(&st, "bob"), 0, "son époque n'a pas bougé");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "bob"), 1, "sa graine est là");
        assert_eq!(rpch_registre_de_type(&st, "config.user.delete"), 0, "aucune suppression attestée");

        let r = user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await;
        assert_eq!(r.status().as_u16(), 204, "la purge revenue, le même geste supprime");
        assert_eq!(rpch_epoque_du_compte(&st, "bob"), 1, "l'époque du compte avance à la suppression");
        assert_eq!(rpch_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "bob"), 0, "la graine est retirée");
        assert_eq!(rpch_registre_de_type(&st, "config.user.delete"), 1, "la suppression est attestée");
    }
}
