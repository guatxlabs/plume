// =====================================================================================
// `P10.24-n` — LE COMPTE DE L'ADMINISTRATEUR DE L'ASSISTANT NE SE SUPPRIME PAS : SA CRÉDENCE NE SE RESSUSCITE PLUS.
// `P10.24-o` — SUPPRIMER UN COMPTE OUBLIE SES ÉCHECS DE CONNEXION ET SON FREIN DU SECOND FACTEUR (PAS LA CRÉATION).
// `P10.24-p` — LES OBJETS D'UN COMPTE SUPPRIMÉ NE REVIENNENT PAS À UN HOMONYME : PURGÉS OU RÉATTRIBUÉS, ATTESTÉS.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré) :
//  * `P10.24-n` : l'administrateur `wiz` posé par `set_admin` (l'écriture de `/api/setup`), puis réinitialisé ET
//    rétrogradé `viewer` par `adm` (son mot de passe d'installation : 401 ; le neuf : 200 `viewer`) ; supprimé : 204.
//    ENSUITE, le mot de passe d'INSTALLATION se reconnectait — 200, rôle `admin`, session résolue `("wiz","admin")`,
//    Basic aussi — et le neuf rendait 401. L'énoncé (« `authenticate` y retombe ») sous-comptait : c'est la crédence
//    d'installation qui revient, avec le rôle administrateur, par-dessus une réinitialisation et une rétrogradation.
//    Et l'énoncé de démarrage (`server/mod.rs`, LU et recopié par la mesure) ne recharge plus d'administrateur de
//    l'assistant : sans mot de passe de configuration, le démon repart en mode installation ;
//  * `P10.24-o` : dix mots de passe faux de l'ancien `bob` depuis une adresse, dix codes faux au second facteur ; `bob`
//    supprimé : compteur (10) et frein (engagé, 29 s) intacts ; `bob` recréé : son BON mot de passe depuis cette
//    adresse -> 429, et un code JUSTE de SA graine -> 429 du frein ;
//  * `P10.24-p` : `bob` supprimé puis recréé `viewer` listait la requête enregistrée, le tableau de bord, la vue, le
//    panneau de bibliothèque et la playlist PRIVÉS de l'ancien (`editable: true`), et son INSTANTANÉ avec le jeton,
//    capturé au rôle `admin`. L'énoncé ne nommait ni les panneaux de bibliothèque, ni les playlists, ni les
//    instantanés.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (le refus de `P10.24-n` y est borné au tenant `default`,
// lu, non joué) ; le redémarrage (aucun banc ne rejoue `server/mod.rs`) ; les lignes laissées au nom de comptes
// supprimés AVANT ce lot, qu'un homonyme créé aujourd'hui recevrait encore ; la rétrogradation de l'administrateur
// de l'assistant, qui n'est pas refusée ; l'homonymie avec une identité sans ligne dans `user` (administrateur de
// configuration, SSO d'en-têtes).
// =====================================================================================
mod suppression_de_compte_complete {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const CSUP_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const CSUP_GRAINE_ANCIENNE: &[u8] = b"12345678901234567890";
    const CSUP_GRAINE_NEUVE: &[u8] = b"09876543210987654321";

    /// Un mot de passe recevable (au moins `PASSWORD_MIN_CHARS`), construit — jamais un littéral de clé.
    fn csup_mot(marque: &str) -> String {
        format!("csup-{marque}-{}", "m".repeat(PASSWORD_MIN_CHARS))
    }

    async fn csup_corps(r: Response) -> (u16, Option<String>, Value) {
        let statut = r.status().as_u16();
        let session = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("plume_session=").map(|reste| reste.split(';').next().unwrap_or("").to_string()));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, session, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn csup_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    fn csup_code(graine: &[u8]) -> String {
        hotp(graine, (now() / 30) as u64, 6)
    }

    fn csup_compte(st: &AppState, sql: &str, nom: &str) -> i64 {
        st.db.lock().query_row(sql, params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn csup_id(st: &AppState, nom: &str) -> i64 {
        csup_compte(st, "SELECT id FROM user WHERE name=?1", nom)
    }

    fn csup_epoque_du_compte(st: &AppState, nom: &str) -> i64 {
        epoque_du_compte(&st.db.lock(), nom).expect("fixture : l'époque du compte se lit")
    }

    fn csup_echecs(st: &AppState, nom: &str, ip: &str) -> Option<u32> {
        st.auth_fails.lock().get(&(nom.to_string(), ip.to_string())).map(|f| f.count)
    }

    fn csup_suppressions_attestees(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.user.delete'", [], |r| r.get(0)).expect("fixture : ledger se lit")
    }

    fn csup_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    async fn csup_connexion(st: &AppState, nom: &str, mot: &str, ip: &str) -> (u16, Option<String>, Value) {
        csup_corps(login_post(State(st.clone()), ConnectInfo(csup_pair(ip)), Json(json!({ "user": nom, "pass": mot }))).await).await
    }

    async fn csup_second_facteur(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, Option<String>, Value) {
        csup_corps(login_mfa_post(State(st.clone()), ConnectInfo(csup_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await).await
    }

    async fn csup_supprimer(st: &AppState, auteur: &str, cible: &str) -> (u16, Value) {
        let (s, _, c) =
            csup_corps(user_delete(State(st.clone()), Extension(sp_au(auteur, "admin")), axum::extract::Path(csup_id(st, cible))).await).await;
        (s, c)
    }

    async fn csup_creer(st: &AppState, nom: &str, mot: &str, role: &str) {
        let (s, _, c) = csup_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": nom, "password": mot, "role": role }))).await,
        )
        .await;
        assert_eq!(s, 200, "fixture : le compte {nom} est créé : {c}");
    }

    fn csup_enroler(st: &AppState, nom: &str, graine: &[u8]) {
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,'[]',-1,0,0)",
                params![nom, base32_encode(graine)],
            )
            .expect("fixture : second facteur actif");
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-n` — LE COMPTE DE L'ASSISTANT NE SE SUPPRIME PAS, ET SA CRÉDENCE D'INSTALLATION NE REVIENT PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `wiz` est posé par `set_admin` (l'écriture de `/api/setup`), puis `adm` le réinitialise et le
    /// rétrograde `viewer`. Sa suppression par `adm` est refusée, `400` et la cause nommée — par son NOM : la
    /// rétrogradation préalable ne la contourne pas. Rien n'est écrit : le compte est là, `viewer`, son second facteur
    /// aussi, son époque n'a pas bougé depuis la réinitialisation, aucune suppression n'est attestée. Le mot de passe
    /// d'INSTALLATION ne connecte pas (ni par `/api/login`, ni en Basic) ; le mot de passe posé par `adm` connecte,
    /// `viewer`. CONTRÔLE POSITIF : un autre administrateur (`adm2`) se supprime (200), et son mot de passe ne connecte
    /// plus — aucune crédence ne survit pour un compte qui n'est pas celui de l'assistant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer le refus de `user_delete` — `200`, puis le
    /// mot de passe d'installation reconnecte `wiz` en administrateur.
    #[tokio::test]
    async fn csup_le_compte_de_l_assistant_ne_se_supprime_pas_et_sa_credence_ne_revient_pas() {
        let (st, _p) = sp_state("csup-assistant");
        let installation = csup_mot("installation");
        let posee_par_adm = csup_mot("posee-par-adm");
        set_admin(&st, "wiz", &hash_pw(&installation).expect("hachage")).expect("fixture : administrateur de l'assistant posé");
        // Une graine EN ATTENTE (non active) : elle doit survivre au refus, sans arrêter la connexion au second facteur.
        csup_enroler(&st, "wiz", CSUP_GRAINE_ANCIENNE);
        st.db.lock().execute("UPDATE user_mfa SET enabled=0 WHERE user='wiz'", []).expect("fixture : graine en attente");
        let (s, _, c) = csup_corps(
            user_update(
                State(st.clone()),
                ConnectInfo(csup_pair("10.81.0.1")),
                Extension(sp_au("adm", "admin")),
                axum::extract::Path(csup_id(&st, "wiz")),
                Json(json!({ "password": posee_par_adm, "role": "viewer" })),
            )
            .await,
        )
        .await;
        assert_eq!(s, 204, "fixture : adm réinitialise et rétrograde wiz : {c}");
        let (s, _, _) = csup_connexion(&st, "wiz", &installation, "10.81.0.2").await;
        assert_eq!(s, 401, "fixture : avant la suppression, le mot de passe d'installation est déjà refusé");

        let (statut, corps) = csup_supprimer(&st, "adm", "wiz").await;
        assert_eq!(statut, 400, "le compte de l'assistant ne se supprime pas : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE), "{corps}");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1 AND role='viewer'", "wiz"), 1, "le compte est là, viewer");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "wiz"), 1, "rien n'est purgé");
        assert_eq!(csup_epoque_du_compte(&st, "wiz"), 1, "l'époque n'a avancé que par la réinitialisation");
        assert_eq!(csup_suppressions_attestees(&st), 0, "aucune suppression attestée");

        let (s, session, c) = csup_connexion(&st, "wiz", &installation, "10.81.0.3").await;
        assert_eq!((s, session.is_some()), (401, false), "le mot de passe d'installation ne connecte pas : {c}");
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("wiz:{installation}")));
        assert_eq!(authenticate(&st, &basic), None, "ni en Basic");
        let (s, session, c) = csup_connexion(&st, "wiz", &posee_par_adm, "10.81.0.4").await;
        assert_eq!((s, c["role"].as_str()), (200, Some("viewer")), "le mot de passe posé par adm connecte, viewer : {c}");
        assert_eq!(csup_identite(&st, &session.expect("session posée")), Some(("wiz".into(), "viewer".into())), "et la session est viewer");

        // CONTRÔLE POSITIF — un administrateur qui n'est pas celui de l'assistant se supprime, sans crédence qui survive.
        let de_adm2 = csup_mot("adm2");
        csup_creer(&st, "adm2", &de_adm2, "admin").await;
        let (statut, corps) = csup_supprimer(&st, "adm", "adm2").await;
        assert_eq!(statut, 200, "un autre administrateur se supprime : {corps}");
        let (s, _, _) = csup_connexion(&st, "adm2", &de_adm2, "10.81.0.5").await;
        assert_eq!(s, 401, "et son mot de passe ne connecte plus");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-o` — L'HOMONYME RECRÉÉ N'HÉRITE NI DES ÉCHECS DE CONNEXION NI DU FREIN DU SECOND FACTEUR
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'ancien `bob` (second facteur actif) a dix mots de passe faux depuis `X` (verrouillé) et dix
    /// codes faux, chacun depuis sa propre adresse, avec un ticket juste (frein engagé) ; `alice` a trois échecs depuis
    /// `X`. `bob` supprimé (200) : plus aucun échec compté pour `bob`, quelle que soit l'adresse, et plus de frein ;
    /// les trois échecs d'`alice` sont intacts. `bob` recréé, avec sa propre graine : son BON mot de passe depuis `X`
    /// rend un ticket (200), et un code JUSTE de SA graine ouvre une session qui résout son identité.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer de `user_delete` l'oubli des échecs (`429` au mot de passe depuis
    /// `X`) ; retirer l'oubli du frein (`429` du frein au code juste).
    #[tokio::test]
    async fn csup_l_homonyme_n_herite_ni_des_echecs_ni_du_frein() {
        let (st, _p) = sp_state("csup-frein");
        let x = "10.82.0.1";
        csup_enroler(&st, "bob", CSUP_GRAINE_ANCIENNE);
        for _ in 0..10 {
            let _ = csup_connexion(&st, "bob", "pas-le-mot-de-passe", x).await;
        }
        for _ in 0..3 {
            let _ = csup_connexion(&st, "alice", "pas-le-mot-de-passe", x).await;
        }
        let (s, _, c) = csup_connexion(&st, "bob", CSUP_MOT_DE_PASSE_DE_FIXTURE, x).await;
        assert_eq!(s, 429, "fixture : l'ancien bob est verrouillé depuis X : {c}");
        let (s, _, c) = csup_connexion(&st, "bob", CSUP_MOT_DE_PASSE_DE_FIXTURE, "10.82.0.2").await;
        let ticket = c["ticket"].as_str().unwrap_or("").to_string();
        assert_eq!((s, ticket.is_empty()), (200, false), "fixture : ticket de l'ancien bob : {c}");
        for i in 0..10 {
            let _ = csup_second_facteur(&st, &ticket, "000000", &format!("10.82.1.{i}")).await;
        }
        assert!(crate::handlers::idp::second_facteur_freine(&st, "bob").is_some(), "fixture : le frein de l'ancien bob est engagé");

        let (statut, corps) = csup_supprimer(&st, "adm", "bob").await;
        assert_eq!(statut, 200, "fixture : bob supprimé : {corps}");
        assert_eq!(st.auth_fails.lock().keys().filter(|(nom, _)| nom == "bob").count(), 0, "aucun échec ne reste compté pour bob");
        assert_eq!(crate::handlers::idp::second_facteur_freine(&st, "bob"), None, "plus de frein");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 0, "plus aucun code faux compté");
        assert_eq!(csup_echecs(&st, "alice", x), Some(3), "les échecs d'alice ne sont pas touchés");

        let neuf = csup_mot("nouveau-bob");
        csup_creer(&st, "bob", &neuf, "viewer").await;
        csup_enroler(&st, "bob", CSUP_GRAINE_NEUVE);
        let (s, _, c) = csup_connexion(&st, "bob", &neuf, x).await;
        let ticket = c["ticket"].as_str().unwrap_or("").to_string();
        assert_eq!((s, ticket.is_empty()), (200, false), "le nouveau bob, depuis X, passe le premier facteur : {c}");
        let (s, session, c) = csup_second_facteur(&st, &ticket, &csup_code(CSUP_GRAINE_NEUVE), x).await;
        assert_eq!((s, session.is_some()), (200, true), "un code juste de sa graine ouvre sa session : {c}");
        assert_eq!(csup_identite(&st, &session.expect("session")), Some(("bob".into(), "viewer".into())), "qui résout son identité");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-o`, LA DÉCISION — LA CRÉATION D'UN COMPTE NE LIBÈRE PAS UN NOM MARTELÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : dix mots de passe faux contre `carol`, qui n'existe pas, depuis `Y` : verrouillé. `carol` est
    /// créée (200) : depuis `Y`, même son BON mot de passe reste refusé (`429`) — ces essais ont été faits sans aucun
    /// mot de passe à connaître, et la création ne rend pas des essais neufs à qui martèle ce nom ; depuis une autre
    /// adresse, `carol` se connecte (200). Témoin d'une DÉCISION (vert avant comme après le lot).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : oublier les échecs du nom à la création (`oublier_les_echecs_du_compte_supprime`
    /// appelée dans `user_create` après le commit) — `200` depuis `Y`.
    #[tokio::test]
    async fn csup_la_creation_ne_libere_pas_un_nom_martele() {
        let (st, _p) = sp_state("csup-creation");
        let y = "10.83.0.1";
        for _ in 0..10 {
            let _ = csup_connexion(&st, "carol", "pas-le-mot-de-passe", y).await;
        }
        assert_eq!(csup_echecs(&st, "carol", y), Some(10), "fixture : dix échecs contre un nom sans compte");
        let de_carol = csup_mot("carol");
        csup_creer(&st, "carol", &de_carol, "editor").await;
        let (s, _, c) = csup_connexion(&st, "carol", &de_carol, y).await;
        assert_eq!(s, 429, "la création ne libère pas celui qui martelait ce nom : {c}");
        let (s, session, c) = csup_connexion(&st, "carol", &de_carol, "10.83.0.2").await;
        assert_eq!((s, session.is_some()), (200, true), "carol se connecte depuis une autre adresse : {c}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.24-p` — LES OBJETS DE L'ANCIEN COMPTE NE REVIENNENT PAS À L'HOMONYME ; LA SUPPRESSION LES ATTESTE
    // -------------------------------------------------------------------------------------

    /// Les objets posés par la fixture de (4) et (5), écrits comme les créateurs de production les écrivent (le nom de
    /// l'auteur dans `owner` ou `created_by`, la visibilité déclarée).
    struct CsupObjets {
        requetes: Vec<i64>,
        tdb_prive: i64,
        tdb_commun: i64,
        vue: i64,
        panneau: i64,
        playlist: i64,
        instantane: i64,
    }

    fn csup_poser_les_objets(st: &AppState, nom: &str, jeton: &str) -> CsupObjets {
        let c = st.db.lock();
        let ins = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> i64 {
            c.execute(sql, p).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"));
            c.last_insert_rowid()
        };
        let requetes = vec![
            ins("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES(?1,'chasse','search src_ip=10.0.0.1',1,1)", &[&nom]),
            ins("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES(?1,'pivot','search host=x',1,1)", &[&nom]),
        ];
        let tdb_prive = ins("INSERT INTO dashboard(name,created,owner,visibility) VALUES('tdb prive',1,?1,'private')", &[&nom]);
        let tdb_commun = ins("INSERT INTO dashboard(name,created,owner,visibility) VALUES('tdb commun',1,?1,'shared')", &[&nom]);
        let vue = ins("INSERT INTO view(name,owner,visibility) VALUES('vue privee',?1,'private')", &[&nom]);
        let panneau = ins(
            "INSERT INTO library_panel(name,title,query,owner,visibility,created,updated) VALUES('lp prive','t','search',?1,'private',1,1)",
            &[&nom],
        );
        let playlist = ins("INSERT INTO playlist(name,items,owner,visibility,created,updated) VALUES('pl privee','[]',?1,'private',1,1)", &[&nom]);
        let instantane = ins(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,'capture',?2,'{}',1,?3,'admin')",
            &[&tdb_prive, &jeton, &nom],
        );
        CsupObjets { requetes, tdb_prive, tdb_commun, vue, panneau, playlist, instantane }
    }

    fn csup_proprietaire(st: &AppState, table: &str, id: i64) -> (String, String) {
        st.db
            .lock()
            .query_row(&format!("SELECT COALESCE(owner,''),COALESCE(visibility,'') FROM {table} WHERE id=?1"), params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or_else(|e| panic!("fixture : {table} #{id} se lit ({e})"))
    }

    /// CE QU'IL TIENT : `bob` possède deux requêtes enregistrées, un tableau de bord privé et un commun, une vue, un
    /// panneau de bibliothèque et une playlist privés, et un instantané capturé au rôle `admin` ; `alice` possède une
    /// requête, un tableau de bord privé et un instantané. `adm` supprime `bob` (200) :
    ///  * ses requêtes et son instantané n'existent plus ; ses tableaux de bord, sa vue, son panneau et sa playlist
    ///    appartiennent à `adm`, leur visibilité INCHANGÉE (le privé reste privé, le commun commun) ;
    ///  * rien de ce qui est à `alice` n'a bougé ;
    ///  * l'événement d'audit de la suppression porte les identifiants de chaque objet réattribué et purgé, et la ligne
    ///    du registre leurs comptes et l'héritier.
    /// `bob` recréé `viewer` : ses six listes (requêtes, tableaux de bord, vues, panneaux, playlists, instantanés) ne
    /// portent plus rien de l'ancien, et le jeton de l'instantané ne sert plus rien (404). `adm` voit le tableau de
    /// bord privé réattribué, à son nom.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer l'appel à `ObjetsDuCompteSupprime::traiter` (la forme d'avant : tout
    /// revient au nouveau `bob`) ; retirer `dashboard_snapshot` des objets purgés (l'instantané et son jeton reviennent) ;
    /// retirer `library_panel` des objets réattribués (le panneau privé revient).
    #[tokio::test]
    async fn csup_les_objets_du_compte_ne_reviennent_pas_a_l_homonyme() {
        let (st, _p) = sp_state("csup-objets");
        let jeton_de_bob = "ab".repeat(32);
        let a_bob = csup_poser_les_objets(&st, "bob", &jeton_de_bob);
        let a_alice = csup_poser_les_objets(&st, "alice", &"cd".repeat(32));

        let (statut, corps) = csup_supprimer(&st, "adm", "bob").await;
        assert_eq!(statut, 200, "bob supprimé : {corps}");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner=?1", "bob"), 0, "ses requêtes enregistrées sont purgées");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot WHERE created_by=?1", "bob"), 0, "son instantané aussi");
        assert_eq!(csup_proprietaire(&st, "dashboard", a_bob.tdb_prive), ("adm".into(), "private".into()), "tableau de bord privé : à adm, privé");
        assert_eq!(csup_proprietaire(&st, "dashboard", a_bob.tdb_commun), ("adm".into(), "shared".into()), "tableau de bord commun : à adm, commun");
        assert_eq!(csup_proprietaire(&st, "view", a_bob.vue), ("adm".into(), "private".into()), "vue : à adm");
        assert_eq!(csup_proprietaire(&st, "library_panel", a_bob.panneau), ("adm".into(), "private".into()), "panneau : à adm");
        assert_eq!(csup_proprietaire(&st, "playlist", a_bob.playlist), ("adm".into(), "private".into()), "playlist : à adm");
        for (table, id) in [("dashboard", a_alice.tdb_prive), ("view", a_alice.vue), ("library_panel", a_alice.panneau), ("playlist", a_alice.playlist)] {
            assert_eq!(csup_proprietaire(&st, table, id).0, "alice", "{table} d'alice intact");
        }
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner=?1", "alice"), 2, "les requêtes d'alice sont là");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot WHERE created_by=?1", "alice"), 1, "son instantané aussi");

        let champs: String = st
            .db
            .lock()
            .query_row(
                "SELECT fields FROM event WHERE source='plume-config' AND json_extract(fields,'$.action')='config.user.delete'",
                [],
                |r| r.get(0),
            )
            .expect("l'événement d'audit de la suppression existe");
        let champs: Value = serde_json::from_str(&champs).expect("champs JSON");
        assert_eq!(champs["objets_reattribues_a"], json!("adm"), "{champs}");
        assert_eq!(
            champs["objets_reattribues"],
            json!({ "dashboard": [a_bob.tdb_prive, a_bob.tdb_commun], "view": [a_bob.vue], "library_panel": [a_bob.panneau], "playlist": [a_bob.playlist] }),
            "chaque objet réattribué est nommé à l'audit : {champs}"
        );
        assert_eq!(
            champs["objets_purges"],
            json!({ "saved_query": a_bob.requetes, "dashboard_snapshot": [a_bob.instantane] }),
            "chaque objet purgé aussi : {champs}"
        );
        assert!(!champs.to_string().contains(&jeton_de_bob), "le jeton de l'instantané n'entre pas dans l'audit");
        assert_eq!(
            csup_compte(
                &st,
                "SELECT COUNT(*) FROM ledger WHERE kind='config.user.delete' AND detail=?1",
                "compte 'bob' (rôle editor) supprimé par adm ; objets réattribués à adm : dashboard 2, view 1, library_panel 1, \
                 playlist 1 ; purgés : saved_query 2, dashboard_snapshot 1 ; \
                 jetons révoqués 0 [], conservés au secret connu 0 [], d'auteur non établi 0" // `P10.24-w` : la phrase des jetons
            ),
            1,
            "et au registre, chaîné"
        );

        csup_creer(&st, "bob", &csup_mot("homonyme"), "viewer").await;
        let nouveau = sp_au("bob", "viewer");
        let (_, _, requetes) = csup_corps(saved_queries_list(State(st.clone()), Extension(nouveau.clone())).await).await;
        assert_eq!(requetes["queries"], json!([]), "aucune requête de l'ancien bob : {requetes}");
        let tableaux = dash_list(State(st.clone()), Extension(nouveau.clone()), Query(HashMap::new())).await.0;
        let noms_des_tableaux: Vec<&str> = tableaux["dashboards"].as_array().expect("liste").iter().filter_map(|d| d["name"].as_str()).collect();
        assert!(!noms_des_tableaux.contains(&"tdb prive"), "le tableau de bord privé de l'ancien bob n'est pas servi : {noms_des_tableaux:?}");
        assert!(
            tableaux["dashboards"].as_array().expect("liste").iter().all(|d| d["owner"] != json!("bob")),
            "aucun tableau de bord au nom de bob : {tableaux}"
        );
        let vues = views_list(State(st.clone()), Extension(nouveau.clone())).await.0;
        assert!(vues["views"].as_array().expect("liste").iter().all(|v| v["owner"] != json!("bob") && v["name"] != json!("vue privee")), "{vues}");
        let panneaux = library_panels_list(State(st.clone()), Extension(nouveau.clone())).await.0;
        assert_eq!(panneaux["library_panels"], json!([]), "aucun panneau privé servi : {panneaux}");
        let playlists = playlists_list(State(st.clone()), Extension(nouveau.clone())).await.0;
        assert_eq!(playlists["playlists"], json!([]), "aucune playlist privée servie : {playlists}");
        let instantanes = snapshots_list(State(st.clone()), Extension(nouveau.clone())).await.0;
        assert_eq!(instantanes["snapshots"], json!([]), "aucun instantané de l'ancien bob : {instantanes}");
        let par_jeton = snapshot_get(State(st.clone()), Extension(nouveau.clone()), axum::extract::Path(jeton_de_bob.clone())).await;
        assert_eq!(par_jeton.status().as_u16(), 404, "le jeton de l'instantané ne sert plus rien");

        let de_adm = dash_list(State(st.clone()), Extension(sp_au("adm", "admin")), Query(HashMap::new())).await.0;
        let repris = de_adm["dashboards"].as_array().expect("liste").iter().find(|d| d["id"] == json!(a_bob.tdb_prive)).cloned();
        assert_eq!(
            repris.map(|d| (d["owner"].clone(), d["visibility"].clone(), d["editable"].clone())),
            Some((json!("adm"), json!("private"), json!(true))),
            "adm tient le tableau de bord privé réattribué"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.24-p` et `P10.24-o` — OBJETS ET MÉMOIRE SUIVENT LA TRANSACTION DE LA SUPPRESSION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la réattribution des playlists refusée (autorisateur SQLite — la DERNIÈRE écriture d'objets),
    /// la suppression n'a PAS lieu — `500` nommé : le compte existe, ses requêtes et son instantané sont là (leur purge,
    /// faite AVANT, est défaite), ses tableaux de bord sont à lui, son époque n'a pas bougé, aucune suppression n'est
    /// attestée, et la mémoire n'a rien oublié (trois échecs de connexion, trois codes faux comptés). L'autorisateur
    /// retiré, le même geste supprime (200), purge, réattribue, et la mémoire oublie.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : avaler l'échec des objets (le `?` de `ObjetsDuCompteSupprime::traiter` remplacé
    /// par un résultat vide) — `200`, le compte supprimé avec ses playlists à son nom ; oublier la mémoire AVANT la
    /// transaction — les échecs de `bob` perdus alors que rien n'est supprimé.
    #[tokio::test]
    async fn csup_objets_et_memoire_suivent_la_transaction_de_la_suppression() {
        let (st, _p) = sp_state("csup-atomique");
        let a_bob = csup_poser_les_objets(&st, "bob", &"ef".repeat(32));
        csup_enroler(&st, "bob", CSUP_GRAINE_ANCIENNE);
        for _ in 0..3 {
            let _ = csup_connexion(&st, "bob", "pas-le-mot-de-passe", "10.85.0.1").await;
        }
        let (_, _, c) = csup_connexion(&st, "bob", CSUP_MOT_DE_PASSE_DE_FIXTURE, "10.85.0.2").await;
        let ticket = c["ticket"].as_str().unwrap_or("").to_string();
        for _ in 0..3 {
            let _ = csup_second_facteur(&st, &ticket, "000000", "10.85.0.3").await;
        }
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 3, "fixture : trois codes faux comptés");

        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "playlist" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = csup_supprimer(&st, "adm", "bob").await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 500, "la réattribution refusée, la suppression n'a pas lieu : {corps}");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "bob"), 1, "le compte existe");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner=?1", "bob"), 2, "ses requêtes sont là");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot WHERE created_by=?1", "bob"), 1, "son instantané aussi");
        assert_eq!(csup_proprietaire(&st, "dashboard", a_bob.tdb_prive).0, "bob", "son tableau de bord est à lui");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM user_mfa WHERE user=?1", "bob"), 1, "sa graine est là");
        assert_eq!(csup_epoque_du_compte(&st, "bob"), 0, "son époque n'a pas bougé");
        assert_eq!(csup_suppressions_attestees(&st), 0, "aucune suppression attestée");
        assert_eq!(csup_echecs(&st, "bob", "10.85.0.1"), Some(3), "la mémoire n'a pas oublié ses échecs");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 3, "ni ses codes faux");

        let (statut, corps) = csup_supprimer(&st, "adm", "bob").await;
        assert_eq!(statut, 200, "l'autorisateur retiré, le même geste supprime : {corps}");
        assert_eq!(csup_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner=?1", "bob"), 0, "requêtes purgées");
        assert_eq!(csup_proprietaire(&st, "playlist", a_bob.playlist).0, "adm", "playlist réattribuée");
        assert_eq!(csup_epoque_du_compte(&st, "bob"), 1, "époque avancée");
        assert_eq!(csup_suppressions_attestees(&st), 1, "suppression attestée");
        assert_eq!(csup_echecs(&st, "bob", "10.85.0.1"), None, "échecs oubliés");
        assert_eq!(crate::handlers::idp::echecs_consecutifs_du_second_facteur(&st, "bob"), 0, "codes faux oubliés");
    }
}
