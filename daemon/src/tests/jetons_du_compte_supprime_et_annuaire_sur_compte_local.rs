// =====================================================================================
// `P10.24-w` — LES JETONS QU'UN COMPTE A FRAPPÉS SUIVENT UNE DÉCISION ÉCRITE À SA SUPPRESSION : révoqués (lecture des
//              données, ou ingestion jamais servie), ou conservés comme biens de l'installation (ingestion déjà
//              servie) et NOMMÉS au secret connu d'un compte supprimé — dans la réponse et à l'audit. Migration v123 :
//              `token.created_by`, `token.created_by_deleted_at`, rétro-remplis depuis le registre.
// `P10.25-d` — LE CHEMIN SSO D'EN-TÊTES NE PREND PAS UN NOM QUI PORTE UN MOT DE PASSE LOCAL, ni celui de
//              l'administrateur de configuration : refus nommé, tracé, relu à chaque requête.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré) :
//  * `P10.24-w` : `eve`, administratrice, frappe un jeton d'agent lié à `h-jcsa`, un relais HEC, un jeton de source
//    de données `editor`, un jeton client et une clé de livraison ; `adm` la supprime — 204, sans corps. Les CINQ
//    authentifient encore : `/api/ingest` et `/api/actions/pending` en `agent` de `h-jcsa`, `/services/collector` en
//    `agent`, `/api/ds/query` en `editor`, `/api/client/cases` en `client`, la clé de livraison sur son connecteur.
//    `token` n'a que `id, name, token_hash, created, last_used, host, kind, role, connector_id` ; le registre dit
//    « jeton agent 'ag-jcsa' (hôte h-jcsa) créé par eve », et pour la clé de livraison « source push … créée par eve
//    + clé de livraison mintée » — le CONNECTEUR, pas la clé. L'homonyme recréé `viewer` n'hérite de rien (liste des
//    jetons : 403) : rien ne lie un jeton à un compte, c'est ce qui laissait la suppression sans prise sur eux ;
//  * `P10.25-d` : l'annuaire (secret d'en-tête juste) présente `bob` (`editor`, mot de passe local) dans le groupe
//    administrateur : `bob`, rôle `admin`, et sa requête privée lui est servie ; le nom de l'administrateur de
//    configuration : résolu `viewer` ; `adm` (administrateur local) : résolu `viewer`. Un nom, deux
//    authentifications.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (jetons du plan de contrôle, `platform_user`) ; les clés
// de livraison des sources push conservées au secret connu (`P10.25-q` : elles portent leur auteur depuis, tenu par
// `cjgi_` (7) ; ici la clé d'`eve`, jamais servie, part avec elle) ; la face console du compte rendu neuf de la suppression et des refus de l'annuaire (`web/`) ; les jetons déjà
// laissés en production par des comptes supprimés avant v123 (rendus lisibles, pas révoqués) ; un annuaire qui
// présente le nom d'une identité de jeton ou de la démonstration (`P10.25-h`).
// =====================================================================================
mod jetons_du_compte_supprime_et_annuaire_sur_compte_local {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const JCSA_MOT_DE_PASSE_DE_FIXTURE: &str = "motdepasse12345";
    const JCSA_SECRET_SSO: &str = "secret-de-bord-jcsa";
    const JCSA_ADMIN_DE_CONFIGURATION: &str = "root-jcsa";
    const JCSA_CHEMIN: &str = "/api/cases"; // GET = lecture (viewer)

    /// Un mot de passe recevable, construit — jamais un littéral de clé.
    fn jcsa_mot(marque: &str) -> String {
        format!("jcsa-{marque}-{}", "m".repeat(PASSWORD_MIN_CHARS))
    }

    async fn jcsa_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn jcsa_requete(chemin: &str, entetes: &[(&str, &str)]) -> Request<axum::body::Body> {
        let mut b = Request::builder().uri(chemin);
        for (k, v) in entetes {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).expect("requête")
    }

    fn jcsa_compte(st: &AppState, sql: &str, p: &str) -> i64 {
        st.db.lock().query_row(sql, params![p], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// L'identité qu'un jeton établit, par la résolution servie (`None` : le jeton n'authentifie plus).
    fn jcsa_par_le_jeton(st: &AppState, chemin: &str, autorisation: String) -> Option<(String, String)> {
        resolve_identity(st, &jcsa_requete(chemin, &[("authorization", autorisation.as_str())])).0
    }

    /// Un état où l'administrateur de configuration existe (hors mode d'installation).
    fn jcsa_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(tag);
        st.sso_secret = Arc::new(JCSA_SECRET_SSO.into());
        st.user = Arc::new(JCSA_ADMIN_DE_CONFIGURATION.into());
        st.pass_hash = Arc::new(hash_pw(&jcsa_mot("configuration")).expect("hachage"));
        (st, p)
    }

    async fn jcsa_creer(st: &AppState, nom: &str, role: &str) {
        let (s, c) = jcsa_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": nom, "password": jcsa_mot(nom), "role": role }))).await,
        )
        .await;
        assert_eq!(s, 200, "fixture : compte `{nom}` créé : {c}");
    }

    async fn jcsa_supprimer(st: &AppState, nom: &str) -> (u16, Value) {
        let id = jcsa_compte(st, "SELECT id FROM user WHERE name=?1", nom);
        jcsa_corps(user_delete(State(st.clone()), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await).await
    }

    async fn jcsa_frapper(st: &AppState, auteur: &str, corps: Value) -> String {
        let (s, c) = jcsa_corps(token_create(State(st.clone()), Extension(sp_au(auteur, "admin")), Json(corps)).await).await;
        assert_eq!(s, 200, "fixture : jeton frappé : {c}");
        c["token"].as_str().expect("fixture : secret montré une fois").to_string()
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-w` — LA SUPPRESSION D'UN COMPTE RÉVOQUE OU NOMME CHACUN DES JETONS QU'IL A FRAPPÉS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `eve` frappe un jeton d'agent lié (servi une fois), un relais HEC (jamais servi), un jeton de
    /// source de données `editor`, un jeton client, et une clé de livraison par une source push (jamais servie ;
    /// `P10.25-q` : son auteur est écrit) ; la ligne de commande frappe un jeton (auteur non établi). La frappe de la
    /// console écrit `created_by`. Une suppression dont le COMMIT est refusé ne révoque rien (503). Puis la
    /// suppression : 200 et le compte rendu — RÉVOQUÉS le relais et la clé de livraison jamais servis, la source de
    /// données et le client (raison nommée), CONSERVÉ au secret connu le jeton d'agent servi (marqué
    /// `created_by_deleted_at`, `created_by` intact), AUTEUR NON ÉTABLI le jeton de la ligne de commande, la décision
    /// écrite. L'événement d'audit porte le MÊME compte rendu, la ligne du registre les noms. Après : l'agent
    /// conservé et le jeton de la ligne de commande authentifient ; les quatre révoqués, non.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `JetonsDuCompteSupprime::traiter` qui ne lit aucun jeton (la forme d'avant,
    /// quant aux jetons) — les révoqués authentifient, le compte rendu est vide ; la frappe sans auteur (`inserer_jeton`
    /// au lieu de `inserer_jeton_frappe_par`) ; `GENRES_DE_JETON_DE_LECTURE` qui ne désigne plus rien — la source de
    /// données part pour « jamais servi », le client servi reste ; l'ingestion servie révoquée aussi — l'agent
    /// n'authentifie plus.
    #[tokio::test]
    async fn jcsa_la_suppression_d_un_compte_revoque_ou_nomme_chacun_de_ses_jetons() {
        let (st, _p) = jcsa_etat("jcsa-suppression");
        jcsa_creer(&st, "eve", "admin").await;
        let agent = jcsa_frapper(&st, "eve", json!({ "name": "ag-jcsa", "kind": "agent", "host": "h-jcsa" })).await;
        let relais = jcsa_frapper(&st, "eve", json!({ "name": "hec-jcsa", "kind": "hec", "relay": true })).await;
        let lecture = jcsa_frapper(&st, "eve", json!({ "name": "ds-jcsa", "kind": "datasource", "role": "editor" })).await;
        let client = jcsa_frapper(&st, "eve", json!({ "name": "cl-jcsa", "kind": "client" })).await;
        assert_eq!(jcsa_compte(&st, "SELECT COUNT(*) FROM token WHERE created_by=?1", "eve"), 4, "la frappe écrit son auteur");
        let cli = "c".repeat(64);
        inserer_jeton(&st.db.lock(), "cli-jcsa", &sha256_hex(cli.as_bytes()), None, None, &PorteeJeton::Machine("h-cli".into()))
            .expect("fixture : jeton de la ligne de commande");
        let (s, c) = jcsa_corps(connector_push_source(State(st.clone()), Extension(sp_au("eve", "admin")), Json(json!({ "preset_id": "aws-cloudtrail" }))).await).await;
        assert_eq!(s, 200, "fixture : clé de livraison : {c}");
        let cle = c["delivery_key"].as_str().expect("fixture : clé montrée").to_string();
        let cle_nom = format!("firehose-{}", c["connector_id"].as_i64().expect("fixture : connecteur"));
        // Servis une fois : le jeton d'agent (capteur en place) et le jeton client ; le relais et la source de données, jamais.
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ingest", format!("Bearer {agent}")), Some(("h-jcsa".into(), "agent".into())), "fixture");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/client/cases", format!("Bearer {client}")), Some(("cl-jcsa".into(), "client".into())), "fixture");

        // Une suppression refusée ne révoque rien.
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = jcsa_supprimer(&st, "eve").await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_COMPTE_NON_SUPPRIME_COMMIT_REFUSE)), "{corps}");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ds/query", format!("Bearer {lecture}")), Some(("ds-jcsa".into(), "editor".into())), "rien n'est révoqué");

        let (statut, corps) = jcsa_supprimer(&st, "eve").await;
        assert_eq!(statut, 200, "la suppression rend son compte rendu : {corps}");
        let jetons = &corps["jetons"];
        assert_eq!(
            jetons["revoques"],
            json!([
                { "name": "hec-jcsa", "kind": "hec", "host": null, "raison": "jamais_servi" },
                { "name": "ds-jcsa", "kind": "datasource", "host": null, "raison": "lecture_des_donnees" },
                { "name": "cl-jcsa", "kind": "client", "host": null, "raison": "lecture_des_donnees" },
                { "name": cle_nom, "kind": "firehose", "host": null, "raison": "jamais_servi" },
            ]),
            "{corps}"
        );
        let conserves = jetons["conserves_secret_connu"].as_array().expect("liste des conservés");
        assert_eq!(conserves.len(), 1, "{corps}");
        assert_eq!((&conserves[0]["name"], &conserves[0]["kind"], &conserves[0]["host"]), (&json!("ag-jcsa"), &json!("agent"), &json!("h-jcsa")), "{corps}");
        assert!(conserves[0]["last_used"].as_i64().is_some(), "le conservé a servi : {corps}");
        assert_eq!(jetons["auteur_non_etabli"], json!({ "agent": 1 }), "{corps}");
        assert_eq!(jetons["decision"], json!(DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME), "{corps}");

        // L'audit : le même compte rendu dans l'événement, les noms dans le registre.
        let champs: String = st
            .db
            .lock()
            .query_row("SELECT fields FROM event WHERE source='plume-config' AND json_extract(fields,'$.action')='config.user.delete'", [], |r| r.get(0))
            .expect("événement d'audit de la suppression");
        let champs: Value = serde_json::from_str(&champs).expect("champs JSON");
        assert_eq!(champs, corps, "la réponse est ce que l'audit atteste");
        let detail: String =
            st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='config.user.delete'", [], |r| r.get(0)).expect("maillon");
        assert!(
            detail.ends_with(&format!(
                "jetons révoqués 4 [hec-jcsa, ds-jcsa, cl-jcsa, {cle_nom}], conservés au secret connu 1 [ag-jcsa], d'auteur non établi 1"
            )),
            "{detail}"
        );

        // Ce qui authentifie encore.
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ingest", format!("Bearer {agent}")), Some(("h-jcsa".into(), "agent".into())), "conservé");
        assert_eq!(jcsa_par_le_jeton(&st, "/services/collector", format!("Splunk {relais}")), None, "relais jamais servi : révoqué");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ds/query", format!("Bearer {lecture}")), None, "lecture : révoquée");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/client/cases", format!("Bearer {client}")), None, "client : révoqué");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ingest", format!("Bearer {cli}")), Some(("h-cli".into(), "agent".into())), "auteur non établi : intact");
        assert!(firehose_token_lookup(&st, &cle).is_none(), "clé de livraison jamais servie : révoquée avec son autrice (`P10.25-q`)");
        let (auteur, marque): (Option<String>, Option<i64>) = st
            .db
            .lock()
            .query_row("SELECT created_by, created_by_deleted_at FROM token WHERE name='ag-jcsa'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("jeton conservé");
        assert_eq!(auteur.as_deref(), Some("eve"), "l'attestation n'est pas réécrite");
        assert!(marque.is_some(), "le conservé est marqué : son auteur est supprimé");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-w` — UN HOMONYME RECRÉÉ N'EST PAS L'AUTEUR DES JETONS DE L'ANCIEN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'ancienne `eve` frappe un jeton d'agent servi, conservé à sa suppression. `eve` est recréée,
    /// frappe un jeton de source de données, puis est supprimée à son tour : le compte rendu nomme SON jeton (révoqué)
    /// et ne nomme pas celui de l'ancienne — qui authentifie toujours, `created_by` toujours `eve`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : lire les jetons de l'auteur sans `created_by_deleted_at IS NULL` — le jeton de
    /// l'ancienne est relu comme celui de la nouvelle et la suppression échoue (sa marque n'est pas reposable).
    #[tokio::test]
    async fn jcsa_un_homonyme_recree_n_est_pas_l_auteur_des_jetons_de_l_ancien() {
        let (st, _p) = jcsa_etat("jcsa-homonyme");
        jcsa_creer(&st, "eve", "admin").await;
        let ancien = jcsa_frapper(&st, "eve", json!({ "name": "ag-ancienne", "kind": "agent", "host": "h-ancienne" })).await;
        assert!(jcsa_par_le_jeton(&st, "/api/ingest", format!("Bearer {ancien}")).is_some(), "fixture : servi");
        let (statut, corps) = jcsa_supprimer(&st, "eve").await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps["jetons"]["conserves_secret_connu"].as_array().map(Vec::len), Some(1), "{corps}");

        jcsa_creer(&st, "eve", "admin").await;
        let neuf = jcsa_frapper(&st, "eve", json!({ "name": "ds-nouvelle", "kind": "datasource" })).await;
        let (statut, corps) = jcsa_supprimer(&st, "eve").await;
        assert_eq!(statut, 200, "la suppression de l'homonyme a lieu : {corps}");
        assert_eq!(
            corps["jetons"]["revoques"],
            json!([{ "name": "ds-nouvelle", "kind": "datasource", "host": null, "raison": "lecture_des_donnees" }]),
            "{corps}"
        );
        assert_eq!(corps["jetons"]["conserves_secret_connu"], json!([]), "le jeton de l'ancienne n'est pas le sien : {corps}");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ds/query", format!("Bearer {neuf}")), None, "le sien est révoqué");
        assert_eq!(jcsa_par_le_jeton(&st, "/api/ingest", format!("Bearer {ancien}")), Some(("h-ancienne".into(), "agent".into())), "celui de l'ancienne reste");
        assert_eq!(jcsa_compte(&st, "SELECT COUNT(*) FROM token WHERE created_by=?1 AND name='ag-ancienne'", "eve"), 1, "attestation intacte");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-w` — LA MIGRATION v123 RETROUVE L'AUTEUR DANS LE REGISTRE QUAND L'APPARIEMENT EST UNIQUE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une base v122 (colonnes de v123 retirées) porte des jetons et les maillons que la console
    /// d'avant écrivait. Après la migration : l'agent `ag-a` (hôte, même seconde) est à `eve` ; la source de données
    /// `ds-b` (maillon une seconde après) est à `bob`, marquée supprimée à l'instant du PREMIER `config.user.delete`
    /// de `bob` postérieur à sa création (celui d'avant sa création ne compte pas) ; deux relais `dup` frappés à une
    /// seconde d'écart, deux maillons, deux auteurs : AMBIGU, aucun auteur ; le jeton de la ligne de commande : aucun ;
    /// un maillon hors fenêtre : aucun ; `ag_x` n'est pas apparié au maillon de `agXx` (le `_` n'est pas un joker).
    /// Aucun jeton n'est révoqué, la version est à la tête.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer l'unicité côté maillon — un `dup` reçoit un auteur ; comparer
    /// par `LIKE` — `ag_x` reçoit `mallory` ; retirer `s.ts >= t.created` — `ag-a` est marqué supprimé par une
    /// suppression antérieure à sa frappe.
    #[test]
    fn jcsa_la_migration_v123_retrouve_l_auteur_dans_le_registre_sans_rien_revoquer() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("jcsa-migration");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "fixture : tête");
        conn.execute_batch(
            "ALTER TABLE token DROP COLUMN created_by; ALTER TABLE token DROP COLUMN created_by_deleted_at; \
             UPDATE meta SET value='122' WHERE key='schema_version'; DELETE FROM token; DELETE FROM ledger;",
        )
        .expect("une base v122 se fabrique en retirant les colonnes de v123");
        let t = 1_700_000_000_i64;
        let jeton = |nom: &str, genre: Option<&str>, hote: Option<&str>, cree: i64| {
            conn.execute(
                "INSERT INTO token(name,token_hash,created,host,kind) VALUES(?1,?2,?3,?4,?5)",
                params![nom, sha256_hex(format!("{nom}-{cree}").as_bytes()), cree, hote, genre],
            )
            .expect("fixture : jeton");
        };
        let maillon = |genre: &str, detail: &str, ts: i64| {
            conn.execute("INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,'',?4)", params![ts, genre, detail, format!("{genre}{ts}{detail}")])
                .expect("fixture : maillon");
        };
        maillon("config.user.delete", "compte 'eve' (rôle admin) supprimé par adm", t - 100);
        jeton("ag-a", Some("agent"), Some("h1"), t);
        maillon("config.token.create", "jeton agent 'ag-a' (hôte h1) créé par eve", t);
        jeton("ds-b", Some("datasource"), None, t + 10);
        maillon("config.token.create", "jeton datasource 'ds-b' créé par bob", t + 11);
        maillon("config.user.delete", "compte 'bob' (rôle editor) supprimé par adm ; objets réattribués à adm : dashboard 0", t + 50);
        maillon("config.user.delete", "compte 'bob' (rôle viewer) supprimé par adm", t + 90);
        jeton("dup", Some("hec"), None, t + 20);
        jeton("dup", Some("hec"), None, t + 21);
        maillon("config.token.create", "jeton hec 'dup' créé par alice", t + 20);
        maillon("config.token.create", "jeton hec 'dup' créé par carol", t + 21);
        jeton("cli", None, Some("h2"), t + 30);
        jeton("ag-c", Some("agent"), None, t + 40);
        maillon("config.token.create", "jeton agent 'ag-c' créé par carol", t + 45);
        jeton("ag_x", Some("agent"), None, t + 60);
        maillon("config.token.create", "jeton agent 'agXx' créé par mallory", t + 60);

        assert!(migrate(&conn), "la migration 122 -> 123 passe");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("version");
        assert_eq!(v, crate::migrate::CODE_SCHEMA_MAX.to_string());
        let lus: Vec<(String, Option<String>, Option<i64>)> = conn
            .prepare("SELECT name, created_by, created_by_deleted_at FROM token ORDER BY id")
            .and_then(|mut q| q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>())
            .expect("jetons relus");
        assert_eq!(
            lus,
            vec![
                ("ag-a".to_string(), Some("eve".to_string()), None),
                ("ds-b".to_string(), Some("bob".to_string()), Some(t + 50)),
                ("dup".to_string(), None, None),
                ("dup".to_string(), None, None),
                ("cli".to_string(), None, None),
                ("ag-c".to_string(), None, None),
                ("ag_x".to_string(), None, None),
            ],
            "l'auteur n'est retenu que sur un appariement unique ; rien n'est deviné"
        );
    }

    // -------------------------------------------------------------------------------------
    // Le banc du chemin servi : le garde d'authentification RÉEL devant une sonde qui compte ses exécutions.
    // -------------------------------------------------------------------------------------

    struct JcsaBanc {
        st: AppState,
        adresse: std::net::SocketAddr,
        servies: Arc<AtomicUsize>,
        arret: Option<tokio::sync::oneshot::Sender<()>>,
        fil: Option<tokio::task::JoinHandle<()>>,
        _base: crate::tmp_possede::TmpDb,
    }

    async fn jcsa_banc(tag: &str) -> JcsaBanc {
        let (st, base) = jcsa_etat(tag);
        let servies = Arc::new(AtomicUsize::new(0));
        let compteur = servies.clone();
        let app = axum::Router::new()
            .route(
                JCSA_CHEMIN,
                axum::routing::get(move |Extension(au): Extension<AuthUser>| {
                    let compteur = compteur.clone();
                    async move {
                        compteur.fetch_add(1, Ordering::SeqCst);
                        Json(json!({ "name": au.name, "role": au.role, "method": au.method }))
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(st.clone(), auth_guard))
            .with_state(st.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("fixture : port local");
        let adresse = l.local_addr().expect("fixture : adresse liée");
        let (arret, recu) = tokio::sync::oneshot::channel::<()>();
        let fil = tokio::spawn(async move {
            let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = recu.await;
                })
                .await;
        });
        JcsaBanc { st, adresse, servies, arret: Some(arret), fil: Some(fil), _base: base }
    }

    /// Un rouge avant `arreter` : le fil du serveur est interrompu (le test tourne sur un exécuteur à un fil, qui ne
    /// le reprend plus avant de le détruire).
    impl Drop for JcsaBanc {
        fn drop(&mut self) {
            if let Some(f) = self.fil.take() {
                f.abort();
            }
        }
    }

    impl JcsaBanc {
        /// L'annuaire présente `nom` dans `groupes` : (statut, corps JSON).
        async fn par_l_annuaire(&self, nom: &str, groupes: &str) -> (u16, Value) {
            let entetes = [("x-plume-sso-secret", JCSA_SECRET_SSO), ("x-authentik-username", nom), ("x-authentik-groups", groupes)];
            self.sonder(None, &entetes).await
        }
        async fn par_le_mot_de_passe(&self, nom: &str, mot: &str) -> (u16, Value) {
            let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mot}")));
            self.sonder(Some(&basic), &[]).await
        }
        async fn sonder(&self, autorisation: Option<&str>, entetes: &[(&str, &str)]) -> (u16, Value) {
            let (code, brut) = router_probe_corps(self.adresse, "GET", JCSA_CHEMIN, autorisation, entetes).await;
            let corps = brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
            (code, serde_json::from_str(&corps).unwrap_or(Value::String(corps)))
        }
        fn traces(&self, nom: &str) -> (i64, i64) {
            let c = self.st.db.lock();
            let registre: i64 = c
                .query_row("SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse' AND detail LIKE '%''' || ?1 || '''%'", params![nom], |r| r.get(0))
                .expect("registre");
            let evenements: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM event WHERE source='plume-auth' AND json_extract(fields,'$.action')='annuaire_refuse' AND json_extract(fields,'$.username')=?1",
                    params![nom],
                    |r| r.get(0),
                )
                .expect("événements");
            (registre, evenements)
        }
        /// Le serveur est arrêté et son fil attendu AVANT que la base temporaire ne soit détruite.
        async fn arreter(mut self) {
            if let Some(a) = self.arret.take() {
                let _ = a.send(());
            }
            if let Some(f) = self.fil.take() {
                let _ = tokio::time::timeout(Duration::from_secs(20), f).await;
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.25-d` — L'ANNUAIRE NE PREND PAS UN NOM QUI PORTE UN MOT DE PASSE LOCAL
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par le garde d'authentification réel : l'annuaire présente `bob` (`editor`, mot de passe) dans
    /// le groupe administrateur — 403, la cause nommée, la sonde ne tourne pas, une trace au registre et un événement
    /// `plume-auth`, rien à l'inventaire des accès ; une seconde requête refusée n'écrit pas une seconde trace. Le nom
    /// de l'administrateur de configuration — 403, sa cause. `adm` (administrateur local) et un compte d'engagement à
    /// mot de passe — 403. CONTRÔLES POSITIFS : `carol-jcsa`, sans ligne, servie `admin` ; `fed-jcsa`, ligne SANS mot de
    /// passe posée par la fédération, servie `editor` ; `bob` par SON mot de passe, servi `editor`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `juger_le_nom_presente_par_l_annuaire` de la résolution (la forme
    /// d'avant) — `bob` servi `admin` ; retirer la réservation de l'administrateur de configuration — refusé, mais
    /// sous la cause d'un compte à mot de passe ; ne plus armer la fenêtre de trace — deux traces.
    #[tokio::test]
    async fn jcsa_l_annuaire_ne_prend_pas_un_nom_qui_porte_un_mot_de_passe_local() {
        let banc = jcsa_banc("jcsa-annuaire").await;
        let st = banc.st.clone();
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('eng-cred-jcsa',?1,'admin')", params![hash_pw(&jcsa_mot("engagement")).expect("hachage")])
            .expect("fixture : compte d'engagement");
        idp_provision_user(&st.db.lock(), "fed-jcsa", "editor", crate::handlers::idp::reserved_static_admin(&st)).expect("fixture : compte fédéré");

        let (statut, corps) = banc.par_l_annuaire("bob", "plume-admin").await;
        assert_eq!((statut, &corps["error"]), (403, &json!(CAUSE_ANNUAIRE_NOM_D_UN_COMPTE_A_MOT_DE_PASSE)), "{corps}");
        assert_eq!(banc.servies.load(Ordering::SeqCst), 0, "rien n'est servi");
        assert_eq!(banc.traces("bob"), (1, 1), "une trace au registre, un événement");
        assert_eq!(jcsa_compte(&st, "SELECT COUNT(*) FROM acces_observe WHERE nom=?1 AND methode='sso'", "bob"), 0, "rien à l'inventaire");
        let (statut, _) = banc.par_l_annuaire("bob", "plume-admin").await;
        assert_eq!(statut, 403, "toujours refusé");
        assert_eq!(banc.traces("bob"), (1, 1), "une trace par fenêtre");

        let (statut, corps) = banc.par_l_annuaire(JCSA_ADMIN_DE_CONFIGURATION, "plume-viewer").await;
        assert_eq!((statut, &corps["error"]), (403, &json!(CAUSE_ANNUAIRE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION)), "{corps}");
        for nom in ["adm", "eng-cred-jcsa"] {
            let (statut, corps) = banc.par_l_annuaire(nom, "plume-viewer").await;
            assert_eq!((statut, &corps["error"]), (403, &json!(CAUSE_ANNUAIRE_NOM_D_UN_COMPTE_A_MOT_DE_PASSE)), "{nom} : {corps}");
        }
        assert_eq!(banc.servies.load(Ordering::SeqCst), 0, "rien n'est servi");

        let (statut, corps) = banc.par_l_annuaire("carol-jcsa", "plume-admin").await;
        assert_eq!((statut, &corps["name"], &corps["role"], &corps["method"]), (200, &json!("carol-jcsa"), &json!("admin"), &json!("sso")), "{corps}");
        let (statut, corps) = banc.par_l_annuaire("fed-jcsa", "plume-editor").await;
        assert_eq!((statut, &corps["name"], &corps["role"]), (200, &json!("fed-jcsa"), &json!("editor")), "{corps}");
        let (statut, corps) = banc.par_le_mot_de_passe("bob", JCSA_MOT_DE_PASSE_DE_FIXTURE).await;
        assert_eq!((statut, &corps["name"], &corps["role"], &corps["method"]), (200, &json!("bob"), &json!("editor"), &json!("basic")), "{corps}");
        assert_eq!(banc.servies.load(Ordering::SeqCst), 3, "les trois contrôles positifs sont servis");
        banc.arreter().await;
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.25-d` — LA DÉCISION EST RELUE À CHAQUE REQUÊTE : AUCUN CACHE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `fed-jcsa`, compte fédéré sans mot de passe, servi par l'annuaire ; un administrateur lui pose
    /// un mot de passe (`user_update`) — la requête SUIVANTE de l'annuaire est refusée. `bob` connecté par son mot de
    /// passe (le cache d'authentification le garde), refusé à l'annuaire ; `bob` supprimé — son mot de passe ne
    /// connecte plus, et la requête SUIVANTE de l'annuaire sur `bob` est servie, sans objet hérité.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : garder la décision en mémoire par nom — la pose du mot de passe n'est pas vue.
    #[tokio::test]
    async fn jcsa_la_decision_de_l_annuaire_est_relue_a_chaque_requete() {
        let banc = jcsa_banc("jcsa-sans-cache").await;
        let st = banc.st.clone();
        idp_provision_user(&st.db.lock(), "fed-jcsa", "editor", crate::handlers::idp::reserved_static_admin(&st)).expect("fixture : compte fédéré");
        st.db.lock().execute("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('bob','privee de bob','search x',1,1)", []).expect("fixture");
        assert_eq!(banc.par_l_annuaire("fed-jcsa", "plume-editor").await.0, 200, "fixture : servi");

        let id = jcsa_compte(&st, "SELECT id FROM user WHERE name=?1", "fed-jcsa");
        let r = user_update(
            State(st.clone()),
            ConnectInfo("10.94.0.1:45454".parse().expect("adresse")),
            Extension(sp_au("adm", "admin")),
            axum::extract::Path(id),
            Json(json!({ "password": jcsa_mot("pose") })),
        )
        .await;
        assert_eq!(r.status().as_u16(), 204, "fixture : mot de passe posé par un administrateur");
        let (statut, corps) = banc.par_l_annuaire("fed-jcsa", "plume-editor").await;
        assert_eq!((statut, &corps["error"]), (403, &json!(CAUSE_ANNUAIRE_NOM_D_UN_COMPTE_A_MOT_DE_PASSE)), "la pose est vue sur-le-champ : {corps}");

        assert_eq!(banc.par_le_mot_de_passe("bob", JCSA_MOT_DE_PASSE_DE_FIXTURE).await.0, 200, "fixture : bob connecté, en cache");
        assert_eq!(banc.par_l_annuaire("bob", "plume-admin").await.0, 403, "fixture : refusé à l'annuaire");
        let (statut, corps) = jcsa_supprimer(&st, "bob").await;
        assert_eq!(statut, 200, "fixture : bob supprimé : {corps}");
        assert_eq!(banc.par_le_mot_de_passe("bob", JCSA_MOT_DE_PASSE_DE_FIXTURE).await.0, 401, "son mot de passe ne connecte plus");
        let (statut, corps) = banc.par_l_annuaire("bob", "plume-admin").await;
        assert_eq!((statut, &corps["name"], &corps["role"]), (200, &json!("bob"), &json!("admin")), "la suppression est vue sur-le-champ : {corps}");
        let au = AuthUser { method: "sso".into(), ..sp_au("bob", "admin") };
        let (_, requetes) = jcsa_corps(saved_queries_list(State(st.clone()), Extension(au)).await).await;
        assert_eq!(requetes["queries"], json!([]), "aucun objet hérité de l'ancien compte local : {requetes}");
        banc.arreter().await;
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.25-d` — UN NOM QU'ON N'A PAS PU VÉRIFIER N'EST PAS SERVI PAR L'ANNUAIRE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la lecture du hachage de `bob` refusée sur l'écrivain (autorisateur SQLite), l'annuaire qui
    /// présente `bob` reçoit 503 et sa cause, rien n'est servi. L'autorisateur levé : 403 (compte à mot de passe).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : traiter l'échec de lecture comme « aucun mot de passe » — `bob` servi.
    #[tokio::test]
    async fn jcsa_un_nom_non_verifie_n_est_pas_servi_par_l_annuaire() {
        let banc = jcsa_banc("jcsa-non-verifie").await;
        banc.st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = banc.par_l_annuaire("bob", "plume-admin").await;
        banc.st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_ANNUAIRE_NOM_NON_VERIFIE)), "{corps}");
        assert_eq!(banc.servies.load(Ordering::SeqCst), 0, "rien n'est servi");
        let (statut, _) = banc.par_l_annuaire("bob", "plume-admin").await;
        assert_eq!(statut, 403, "l'autorisateur levé, le nom est jugé");
        banc.arreter().await;
    }
}
