// =====================================================================================
// `P10.24-b` — `/api/password` CHANGE LE MOT DE PASSE DE L'APPELANT, ET RIEN D'AUTRE.
// `P10.24-s` — LE COMPTE DE L'ADMINISTRATEUR DE L'ASSISTANT NE SE RÉTROGRADE PAS.
// `P10.24-t` — LA FÉDÉRATION LIT CE QUE LE NOM TIENT SANS COMPTE, COMME LA CRÉATION.
// `P10.21-r` — L'ANTI-VERROUILLAGE DU DERNIER ADMINISTRATEUR LIT ET ÉCRIT DANS LA MÊME TRANSACTION.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-25 (banc de mesure joué sur la forme d'avant, puis retiré ;
// chaque témoin ci-dessous a été vu ROUGE sous la mutation qu'il nomme) :
//  * `P10.24-b` : `adm` (administrateur à mot de passe) présente SON mot de passe actuel -> 403 « refusé », et l'échec
//    est compté au verrou de l'administrateur de l'assistant `wiz` depuis l'adresse d'`adm` ; avec le mot de passe de
//    `wiz` -> 200 : c'est `wiz` qui change (`wiz`/neuf 200, `wiz`/ancien 401), `adm` garde le sien. Sans administrateur
//    de l'assistant, l'administrateur de CONFIGURATION change le sien -> 200 : la route lui pose une ligne `user`
//    administrateur ET la crédence d'assistant (`meta.admin_user`, rechargée au démarrage) — son mot de passe de
//    configuration rend 401 ensuite. Une identité SSO d'en-têtes (sans ligne) change de même celui de
//    l'administrateur de configuration (200), et son essai faux est compté au verrou de CELUI-CI. Un éditeur ou un
//    lecteur : 403 à la porte, aucun moyen de changer le sien ;
//  * `P10.24-s` : `adm` rétrograde `viewer` le compte `wiz3` de l'assistant -> 204 ; l'énoncé de rechargement du
//    démarrage ne rend plus AUCUN administrateur de l'assistant ; l'état redémarré (sans mot de passe de configuration)
//    répond `configured: false` — le mode installation ;
//  * `P10.24-t` : `zed-mpra` tient, sans ligne `user` ni vue par l'annuaire, une requête privée, un tableau de bord
//    privé et un instantané `admin` ; la création locale rend 409 (`P10.24-u`), la FÉDÉRATION rendait `Ok` et le
//    compte fédéré listait la requête privée (1) ;
//  * `P10.21-r` : deux retraits concurrents des deux derniers administrateurs — SCIM `DELETE` (204, 204), SCIM `PUT
//    active=false` (200, 200), `grant_delete` (204, 204), `grant_set` vers `viewer` (200, 200), `user_update` en mode 0
//    (204, 204) — laissaient ZÉRO administrateur, le verrou NON tenu au point de course. ET CE QUE L'ÉNONCÉ NE DISAIT
//    PAS, SANS AUCUNE COURSE : `POST /Users` du seul administrateur avec le groupe `viewer` (201) et `PATCH /Groups/viewer`
//    `add` du seul administrateur (200) le RÉTROGRADAIENT — aucune garde sur l'ajout qui écrase un rôle.
//
// LE TÉMOIN DE COURSE (`point_de_course`, inerte hors `cfg(test)`). Posé dans chaque geste ENTRE la lecture de sa garde
// et l'écriture. Le crochet y fait jouer le geste concurrent sur un autre fil : si le geste TIENT le verrou de sa base à
// cet instant, le concurrent l'attend (il ne peut passer qu'après la validation) ; sinon il passe en entier, là, avant
// l'écriture — le pire ordonnancement que les verrous du geste permettent. Aucune horloge : l'issue ne dépend que de ce
// que le geste tient. Chaque fil est attendu avant la destruction des temporaires.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un second PROCESSUS écrivant la même base (le verrou d'écriture de SQLite, pris
// au `BEGIN IMMEDIATE`, le tient ; non joué) ; le redémarrage réel (`server/mod.rs` n'est pas exécuté : son énoncé de
// rechargement est REJOUÉ et épinglé sur sa source) ; le chemin d'en-têtes SSO, qui sert toujours à une identité sans
// ligne les lignes qu'un compte supprimé a laissées à son nom (décision écrite, clé proposée) ; les lignes orphelines
// déjà en base (aucun nettoyage : porte à sens unique, décrite et non exécutée).
// =====================================================================================
mod mot_de_passe_de_l_appelant_retrogradation_annuaire_et_dernier_administrateur {
    use super::*;
    use crate::handlers::transaction_validee::poser_un_crochet_de_course;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Le mot de passe que `sp_state` pose sur `alice`, `bob` et `adm`.
    const MPRA_FIXTURE: &str = "motdepasse12345";
    const MPRA_SECRET_SSO: &str = "secret-de-bord-mpra";
    const MPRA_TENANT: &str = "mpra-t";
    /// L'énoncé de rechargement de l'administrateur de l'assistant au démarrage, tel que `server/mod.rs` l'écrit
    /// (épinglé par `mpra_epingler_le_rechargement`).
    const MPRA_RECHARGEMENT_NOM: &str = "SELECT value FROM meta WHERE key='admin_user'";
    const MPRA_RECHARGEMENT_HACHE: &str = "SELECT hash FROM user WHERE name=?1 AND role='admin'";

    /// Un mot de passe recevable (au moins `PASSWORD_MIN_CHARS`), construit — jamais un littéral de clé.
    fn mpra_mot(marque: &str) -> String {
        format!("mpra-{marque}-{}", "q".repeat(PASSWORD_MIN_CHARS))
    }

    fn mpra_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    async fn mpra_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    /// `/api/login`, le cache d'authentification vidé (chaque essai juge le haché EN BASE).
    async fn mpra_connexion(st: &AppState, nom: &str, mot: &str, ip: &str) -> u16 {
        st.auth_cache.lock().clear();
        login_post(State(st.clone()), ConnectInfo(mpra_pair(ip)), Json(json!({ "user": nom, "pass": mot }))).await.status().as_u16()
    }

    async fn mpra_changer(st: &AppState, au: AuthUser, actuel: &str, neuf: &str, ip: &str) -> (u16, Value) {
        mpra_corps(password_post(State(st.clone()), ConnectInfo(mpra_pair(ip)), Extension(au), Json(json!({ "current": actuel, "new": neuf }))).await)
            .await
    }

    fn mpra_echecs(st: &AppState, nom: &str, ip: &str) -> u32 {
        st.auth_fails.lock().get(&(nom.to_string(), ip.to_string())).map_or(0, |f| f.count)
    }

    fn mpra_compte(st: &AppState, sql: &str, nom: &str) -> i64 {
        st.db.lock().query_row(sql, params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn mpra_id(st: &AppState, nom: &str) -> i64 {
        mpra_compte(st, "SELECT id FROM user WHERE name=?1", nom)
    }

    fn mpra_registre(st: &AppState, tete: &str) -> i64 {
        mpra_compte(st, "SELECT COUNT(*) FROM ledger WHERE substr(detail, 1, length(?1)) = ?1", tete)
    }

    fn mpra_sso(nom: &str) -> AuthUser {
        AuthUser { method: "sso".into(), ..sp_au(nom, "admin") }
    }

    /// L'énoncé de `server/mod.rs` est celui que ce témoin rejoue : sinon le rejeu mesurerait autre chose.
    fn mpra_epingler_le_rechargement() {
        let source = include_str!("../server/mod.rs");
        assert!(source.contains(MPRA_RECHARGEMENT_NOM), "fixture : le démarrage lit toujours `meta.admin_user` par cet énoncé");
        assert!(source.contains(MPRA_RECHARGEMENT_HACHE), "fixture : le démarrage recharge toujours par cet énoncé");
    }

    /// LE REDÉMARRAGE, REJOUÉ : l'administrateur de l'assistant que `server/mod.rs` rechargerait de cette base.
    fn mpra_rechargement(st: &AppState) -> Option<(String, String)> {
        use rusqlite::OptionalExtension as _;
        let c = st.db.lock();
        let nom: Option<String> = c.query_row(MPRA_RECHARGEMENT_NOM, [], |r| r.get(0)).optional().expect("fixture : meta se lit");
        nom.and_then(|n| c.query_row(MPRA_RECHARGEMENT_HACHE, params![n], |r| r.get::<_, String>(0)).optional().expect("fixture : user se lit").map(|h| (n, h)))
    }

    /// L'état d'un démon redémarré sur cette base (même configuration, crédence d'assistant rechargée).
    async fn mpra_configure_apres_redemarrage(st: &AppState) -> bool {
        let mut redemarre = st.clone();
        redemarre.admin = Arc::new(Mutex::new(mpra_rechargement(st)));
        let Json(v) = setup_status(State(redemarre)).await;
        v["configured"].as_bool().expect("fixture : setup-status répond")
    }

    // ---------- le témoin de course ----------

    fn mpra_bloquer<F: std::future::Future<Output = (u16, Value)>>(f: F) -> (u16, Value) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de fil").block_on(f)
    }

    /// Ce que le crochet a vu (le verrou tenu au point de course ?) et ce que le geste concurrent a rendu.
    struct Course {
        verrou_tenu: Arc<Mutex<Option<bool>>>,
        issue: Arc<Mutex<Option<(u16, Value)>>>,
        fil: Arc<Mutex<Option<std::thread::JoinHandle<(u16, Value)>>>>,
    }

    fn mpra_course(cle: &str, verrou: Arc<Mutex<Connection>>, concurrent: impl FnOnce() -> (u16, Value) + Send + 'static) -> Course {
        let course = Course { verrou_tenu: Arc::new(Mutex::new(None)), issue: Arc::new(Mutex::new(None)), fil: Arc::new(Mutex::new(None)) };
        let (verrou_tenu, issue, fil) = (course.verrou_tenu.clone(), course.issue.clone(), course.fil.clone());
        poser_un_crochet_de_course(cle, move || {
            let tenu = verrou.is_locked();
            *verrou_tenu.lock() = Some(tenu);
            let concurrent = std::thread::spawn(concurrent);
            if tenu {
                // Le geste tient le verrou : le concurrent l'attend, il sera joint après le geste.
                *fil.lock() = Some(concurrent);
            } else {
                // Le verrou est libre : le concurrent passe EN ENTIER ici, avant l'écriture du geste.
                *issue.lock() = Some(concurrent.join().expect("fil concurrent"));
            }
        });
        course
    }

    /// Joint le fil concurrent (s'il attend encore) : à appeler AVANT toute assertion.
    fn mpra_attendre(course: &Course) -> (Option<bool>, Option<(u16, Value)>) {
        let fil = course.fil.lock().take();
        if let Some(fil) = fil {
            *course.issue.lock() = Some(fil.join().expect("fil concurrent"));
        }
        (*course.verrou_tenu.lock(), course.issue.lock().clone())
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-b` — CHAQUE COMPTE CHANGE SON MOT DE PASSE, ET SEULEMENT LE SIEN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `wiz` est l'administrateur de l'assistant (`set_admin`) ; `adm`, administrateur à mot de passe,
    /// change le SIEN avec son mot de passe actuel (200, `user: adm`) : `adm` se connecte par le neuf, plus par
    /// l'ancien ; `wiz` garde le sien ; aucun échec au verrou de `wiz` ; seule l'époque d'`adm` avance ; le registre
    /// l'atteste. Le mot de passe de `wiz` présenté par `adm` est REFUSÉ (403), compté au verrou d'`adm` et non de
    /// `wiz`. `bob`, éditeur, passe la porte et change le sien. `wiz` change le sien : sa ligne, et sa crédence en
    /// mémoire suit ; le démarrage le rechargerait toujours.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : viser l'administrateur au lieu de l'appelant
    /// (`let user = st.admin…unwrap_or(st.user)` dans `password_post`) — `adm` et son propre mot de passe : 403.
    #[tokio::test]
    async fn mpra_chaque_compte_change_son_mot_de_passe_et_seulement_le_sien() {
        assert_eq!(route_min_role("/api/password", true), MinRole::Read, "la route est celle de chaque compte authentifié");
        let (st, _p) = sp_state("mpra-chacun");
        let de_wiz = mpra_mot("wiz");
        set_admin(&st, "wiz", &hash_pw(&de_wiz).expect("hachage")).expect("fixture : administrateur de l'assistant");

        let neuf_adm = mpra_mot("adm");
        let (statut, corps) = mpra_changer(&st, sp_au("adm", "admin"), MPRA_FIXTURE, &neuf_adm, "10.71.0.1").await;
        assert_eq!((statut, &corps), (200, &json!({ "ok": true, "user": "adm" })), "adm change SON mot de passe");
        assert_eq!(mpra_connexion(&st, "adm", &neuf_adm, "10.71.1.1").await, 200, "adm : le neuf connecte");
        assert_eq!(mpra_connexion(&st, "adm", MPRA_FIXTURE, "10.71.1.2").await, 401, "adm : l'ancien ne connecte plus");
        assert_eq!(mpra_connexion(&st, "wiz", &de_wiz, "10.71.1.3").await, 200, "wiz garde le sien");
        assert_eq!(mpra_echecs(&st, "wiz", "10.71.0.1"), 0, "rien au verrou de wiz");
        assert_eq!(epoque_du_compte(&st.db.lock(), "adm").expect("époque"), 1, "les sessions d'adm tombent");
        assert_eq!(epoque_du_compte(&st.db.lock(), "wiz").expect("époque"), 0, "celles de wiz non");
        assert_eq!(mpra_registre(&st, "mot de passe du compte 'adm' changé par son titulaire"), 1, "attesté au registre");

        let (statut, corps) = mpra_changer(&st, sp_au("adm", "admin"), &de_wiz, &mpra_mot("usurpe"), "10.71.0.2").await;
        assert_eq!((statut, corps["error"].clone()), (403, json!(CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE)), "le mot de passe de wiz n'est pas celui d'adm");
        assert_eq!((mpra_echecs(&st, "adm", "10.71.0.2"), mpra_echecs(&st, "wiz", "10.71.0.2")), (1, 0), "l'échec est à adm, pas à wiz");
        assert_eq!(mpra_connexion(&st, "wiz", &de_wiz, "10.71.1.4").await, 200, "wiz inchangé");

        assert!(rbac_gate("editor", "/api/password", true).is_ok(), "un éditeur passe la porte");
        let neuf_bob = mpra_mot("bob");
        let (statut, corps) = mpra_changer(&st, sp_au("bob", "editor"), MPRA_FIXTURE, &neuf_bob, "10.71.0.3").await;
        assert_eq!(statut, 200, "bob change le sien : {corps}");
        assert_eq!(mpra_connexion(&st, "bob", &neuf_bob, "10.71.1.5").await, 200, "bob : le neuf connecte");

        let neuf_wiz = mpra_mot("wiz-neuf");
        let (statut, corps) = mpra_changer(&st, sp_au("wiz", "admin"), &de_wiz, &neuf_wiz, "10.71.0.4").await;
        assert_eq!(statut, 200, "wiz change le sien : {corps}");
        assert_eq!(mpra_connexion(&st, "wiz", &neuf_wiz, "10.71.1.6").await, 200, "wiz : le neuf connecte");
        assert_eq!(mpra_connexion(&st, "wiz", &de_wiz, "10.71.1.7").await, 401, "wiz : l'ancien ne connecte plus");
        let credence = st.admin.lock().clone().expect("crédence d'assistant");
        assert!(verify_pw(&neuf_wiz, &credence.1), "la crédence en mémoire suit la ligne");
        assert_eq!(mpra_rechargement(&st).map(|(n, _)| n).as_deref(), Some("wiz"), "le démarrage le rechargerait toujours");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-b` — CE QUI NE SE CHANGE PAS ICI EST REFUSÉ NOMMÉMENT, SANS RIEN ÉCRIRE NI COMPTER
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'administrateur de CONFIGURATION (`cfg-mpra`, aucune ligne) présente son mot de passe juste :
    /// 409 nommé — aucune ligne posée, aucune crédence d'assistant, rien au redémarrage, son mot de passe de
    /// configuration connecte toujours, rien compté. Une identité SSO d'en-têtes (sans ligne) : 403 nommé — elle ne
    /// change plus le mot de passe de l'administrateur de configuration, et son essai n'est compté à personne. Un compte
    /// fédéré (ligne sans mot de passe local) : 403 nommé. Mode multi-tenant, un compte de la plateforme : 409 nommé.
    /// CONTRÔLE POSITIF : dans le même état, `alice` change le sien.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : rendre `DeConfiguration` comme la voie de l'assistant (la forme d'avant) —
    /// 200 ; viser l'administrateur au lieu de l'appelant (la mutation du témoin 1) — l'identité SSO reçoit 409 (elle
    /// vise l'administrateur de configuration) au lieu de son propre refus. CE QUI NE ROUGIT PAS SEUL, ET C'EST DIT :
    /// rendre `Aucun` comme une ligne — la preuve (`prouver_le_premier_facteur`) refuse alors elle-même un compte sans
    /// mot de passe local, sous la MÊME cause : deux couches tiennent ce refus.
    #[tokio::test]
    async fn mpra_la_configuration_et_l_annuaire_ne_se_changent_pas_par_cette_route() {
        let (st, _p) = sp_state("mpra-configuration");
        let mut st = st;
        let de_configuration = mpra_mot("configuration");
        st.user = Arc::new("cfg-mpra".into());
        st.pass_hash = Arc::new(hash_pw(&de_configuration).expect("hachage"));
        assert_eq!(mpra_connexion(&st, "cfg-mpra", &de_configuration, "10.72.1.0").await, 200, "fixture : il se connecte");

        let (statut, corps) = mpra_changer(&st, sp_au("cfg-mpra", "admin"), &de_configuration, &mpra_mot("n1"), "10.72.0.1").await;
        assert_eq!((statut, corps["error"].clone()), (409, json!(CAUSE_MOT_DE_PASSE_DE_CONFIGURATION)), "{corps}");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "cfg-mpra"), 0, "aucune ligne posée");
        assert!(st.admin.lock().is_none(), "aucune crédence d'assistant posée");
        assert!(mpra_rechargement(&st).is_none(), "rien que le démarrage rechargerait");
        assert_eq!(mpra_echecs(&st, "cfg-mpra", "10.72.0.1"), 0, "rien compté");
        assert_eq!(mpra_connexion(&st, "cfg-mpra", &de_configuration, "10.72.1.1").await, 200, "son mot de passe de configuration vaut");

        let (statut, corps) = mpra_changer(&st, mpra_sso("guat-mpra"), &de_configuration, &mpra_mot("n2"), "10.72.0.2").await;
        assert_eq!((statut, corps["error"].clone()), (403, json!(CAUSE_APPELANT_SANS_MOT_DE_PASSE_LOCAL)), "{corps}");
        assert_eq!((mpra_echecs(&st, "cfg-mpra", "10.72.0.2"), mpra_echecs(&st, "guat-mpra", "10.72.0.2")), (0, 0), "compté à personne");
        assert_eq!(mpra_connexion(&st, "cfg-mpra", &de_configuration, "10.72.1.2").await, 200, "l'administrateur de configuration inchangé");

        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES('fed-mpra',?1,'editor')", params![IDP_HASH_SENTINEL]).expect("fixture : compte fédéré");
        let (statut, corps) = mpra_changer(&st, sp_au("fed-mpra", "editor"), &de_configuration, &mpra_mot("n3"), "10.72.0.3").await;
        assert_eq!((statut, corps["error"].clone()), (403, json!(CAUSE_APPELANT_SANS_MOT_DE_PASSE_LOCAL)), "{corps}");
        let hache: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='fed-mpra'", [], |r| r.get(0)).expect("lu");
        assert_eq!(hache, IDP_HASH_SENTINEL, "aucun mot de passe local posé");

        let (statut, corps) = mpra_changer(&st, sp_au("alice", "editor"), MPRA_FIXTURE, &mpra_mot("alice"), "10.72.0.4").await;
        assert_eq!(statut, 200, "CONTRÔLE POSITIF : alice change le sien : {corps}");

        let (st1, _dir) = mk_mode1_state();
        let (statut, corps) = mpra_changer(&st1, sp_au("plat-mpra", "admin"), MPRA_FIXTURE, &mpra_mot("n4"), "10.72.0.5").await;
        assert_eq!((statut, corps["error"].clone()), (409, json!(CAUSE_MOT_DE_PASSE_DE_PLATEFORME)), "mode multi-tenant : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-b` — UN MOT DE PASSE RÉINITIALISÉ PENDANT LA DEMANDE N'EST PAS ÉCRASÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `bob` change le sien ; ENTRE la preuve de son mot de passe actuel et l'écriture (point de course),
    /// `adm` réinitialise le mot de passe de `bob` pour lui retirer l'accès (204). L'écriture de `bob` est refusée (409
    /// nommé) : le mot de passe posé par `adm` connecte, celui de `bob` et l'ancien non ; aucun changement n'est attesté.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `AND hash=?3` de l'écriture de `changer_le_mot_de_passe_de_sa_ligne` —
    /// 200, et le mot de passe choisi par `bob` écrase la réinitialisation qui devait l'exclure.
    #[tokio::test]
    async fn mpra_un_mot_de_passe_reinitialise_pendant_la_demande_n_est_pas_ecrase() {
        let (st, _p) = sp_state("mpra-entre-temps");
        let de_l_administrateur = mpra_mot("pose-par-adm");
        let (st2, id_bob, pose) = (st.clone(), mpra_id(&st, "bob"), de_l_administrateur.clone());
        let course = mpra_course(st.db_path.as_str(), st.db.clone(), move || {
            mpra_bloquer(async move {
                mpra_corps(
                    user_update(State(st2), ConnectInfo(mpra_pair("10.73.0.9")), Extension(sp_au("adm", "admin")), axum::extract::Path(id_bob), Json(json!({ "password": pose })))
                        .await,
                )
                .await
            })
        });
        let choisi_par_bob = mpra_mot("choisi-par-bob");
        let (statut, corps) = mpra_changer(&st, sp_au("bob", "editor"), MPRA_FIXTURE, &choisi_par_bob, "10.73.0.1").await;
        let (tenu, concurrent) = mpra_attendre(&course);
        assert_eq!(concurrent.map(|c| c.0), Some(204), "fixture : adm a réinitialisé bob au point de course");
        assert_eq!(tenu, Some(false), "fixture : le verrou est relâché entre la preuve et l'écriture");
        assert_eq!((statut, corps["error"].clone()), (409, json!(CAUSE_MOT_DE_PASSE_CHANGE_ENTRE_TEMPS)), "{corps}");
        assert_eq!(mpra_connexion(&st, "bob", &de_l_administrateur, "10.73.1.1").await, 200, "la réinitialisation d'adm tient");
        assert_eq!(mpra_connexion(&st, "bob", &choisi_par_bob, "10.73.1.2").await, 401, "le mot de passe de bob n'est pas écrit");
        assert_eq!(mpra_connexion(&st, "bob", MPRA_FIXTURE, "10.73.1.3").await, 401, "l'ancien ne connecte plus");
        assert_eq!(mpra_registre(&st, "mot de passe du compte 'bob' changé par son titulaire"), 0, "aucun changement attesté");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.24-s` — LE COMPTE DE L'ASSISTANT NE SE RÉTROGRADE PAS, ET LE REDÉMARRAGE LE RECHARGE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `wiz` posé par `set_admin`. Sa rétrogradation vers `viewer` puis vers `editor` est refusée (400
    /// nommé), et un corps qui mêle mot de passe et rôle n'écrit rien (le mot de passe de `wiz` vaut toujours, son
    /// époque n'a pas bougé, aucun changement de rôle attesté). Le redémarrage (énoncé de `server/mod.rs`, épinglé et
    /// rejoué) le recharge : `configured: true`. L'ÉTAT HÉRITÉ, mesuré : rétrogradé AVANT ce refus, le rejeu ne rend
    /// rien et l'état redémarré est celui de l'installation (`configured: false`) — la promotion vers `admin` reste
    /// permise et le répare. CONTRÔLE POSITIF : un autre administrateur se rétrograde (204).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer le refus de `user_update` — 204, puis
    /// l'état redémarré est le mode installation.
    #[tokio::test]
    async fn mpra_le_compte_de_l_assistant_ne_se_retrograde_pas_et_le_redemarrage_le_recharge() {
        mpra_epingler_le_rechargement();
        let (st, _p) = sp_state("mpra-retrogradation");
        let de_wiz = mpra_mot("wiz");
        set_admin(&st, "wiz", &hash_pw(&de_wiz).expect("hachage")).expect("fixture : administrateur de l'assistant");
        let id_wiz = mpra_id(&st, "wiz");
        let modifier = |corps: Value| {
            let st = st.clone();
            async move {
                mpra_corps(user_update(State(st), ConnectInfo(mpra_pair("10.74.0.1")), Extension(sp_au("adm", "admin")), axum::extract::Path(id_wiz), Json(corps)).await).await
            }
        };
        for role in ["viewer", "editor"] {
            let (statut, corps) = modifier(json!({ "role": role })).await;
            assert_eq!((statut, corps["error"].clone()), (400, json!(CAUSE_COMPTE_DE_L_ASSISTANT_NON_RETROGRADABLE)), "vers {role} : {corps}");
        }
        let (statut, _) = modifier(json!({ "role": "viewer", "password": mpra_mot("melange") })).await;
        assert_eq!(statut, 400, "un corps qui mêle rôle et mot de passe est refusé entier");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1 AND role='admin'", "wiz"), 1, "wiz reste administrateur");
        assert_eq!(mpra_connexion(&st, "wiz", &de_wiz, "10.74.1.1").await, 200, "son mot de passe n'a pas changé");
        assert_eq!(epoque_du_compte(&st.db.lock(), "wiz").expect("époque"), 0, "ses sessions n'ont pas été révoquées");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.role_change"), 0, "aucun changement de rôle attesté");
        assert_eq!(mpra_rechargement(&st).map(|(n, _)| n).as_deref(), Some("wiz"), "le démarrage le recharge");
        assert!(mpra_configure_apres_redemarrage(&st).await, "l'état redémarré est installé");

        // L'ÉTAT HÉRITÉ : rétrogradé avant ce refus.
        st.db.lock().execute("UPDATE user SET role='viewer' WHERE name='wiz'", []).expect("fixture : état hérité");
        assert!(mpra_rechargement(&st).is_none(), "MESURÉ : rétrogradé, le démarrage ne le recharge pas");
        assert!(!mpra_configure_apres_redemarrage(&st).await, "MESURÉ : l'état redémarré serait le mode installation");
        let (statut, corps) = modifier(json!({ "role": "admin" })).await;
        assert_eq!(statut, 204, "la promotion répare : {corps}");
        assert!(mpra_configure_apres_redemarrage(&st).await, "et l'état redémarré est de nouveau installé");

        // CONTRÔLE POSITIF — un administrateur qui n'est pas celui de l'assistant se rétrograde.
        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES('adm2',?1,'admin')", params![hash_pw(MPRA_FIXTURE).expect("hachage")]).expect("fixture");
        let id_adm2 = mpra_id(&st, "adm2");
        let r = user_update(State(st.clone()), ConnectInfo(mpra_pair("10.74.0.2")), Extension(sp_au("adm", "admin")), axum::extract::Path(id_adm2), Json(json!({ "role": "viewer" }))).await;
        assert_eq!(r.status().as_u16(), 204, "un autre administrateur se rétrograde");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.24-t` — LA FÉDÉRATION LIT CE QUE LE NOM TIENT, COMME LA CRÉATION
    // -------------------------------------------------------------------------------------

    /// Une requête privée, un tableau de bord privé, un instantané capturé au rôle `admin`, au nom `nom`.
    fn mpra_objets(st: &AppState, nom: &str, jeton: &str) {
        let c = st.db.lock();
        c.execute("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES(?1,'chasse privee mpra','search x',1,1)", params![nom]).expect("fixture");
        c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES('tdb prive mpra',1,?1,'private')", params![nom]).expect("fixture");
        let tableau = c.last_insert_rowid();
        c.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,'capture',?2,'{}',1,?3,'admin')",
            params![tableau, jeton, nom],
        )
        .expect("fixture");
    }

    fn mpra_requete_sso(nom: &str) -> Request<axum::body::Body> {
        Request::builder()
            .uri("/api/me")
            .header("x-plume-sso-secret", MPRA_SECRET_SSO)
            .header("x-authentik-username", nom)
            .header("x-authentik-groups", "plume-editor")
            .body(axum::body::Body::empty())
            .expect("requête")
    }

    async fn mpra_requetes_servies(st: &AppState, nom: &str) -> usize {
        let au = AuthUser { method: "cookie".into(), ..sp_au(nom, "viewer") };
        let (_, corps) = mpra_corps(saved_queries_list(State(st.clone()), Extension(au)).await).await;
        corps["queries"].as_array().map_or(0, Vec::len)
    }

    /// CE QU'IL TIENT : `zed-mpra` (lignes sans compte, jamais vu par l'annuaire) — la fédération est refusée,
    /// `NomTenuSansCompte` : 409, la cause, le MÊME détail que la création (qui rend 409 aussi) ; aucune ligne posée ;
    /// le refus est tracé (registre, événement `nom_tenu_sans_compte`, porte OIDC). `carol-mpra`, vue par l'annuaire
    /// (en-têtes) et propriétaire des mêmes objets, est fédérée (la voie légitime) et sert sa requête. Un nom sans rien
    /// est fédéré. La lecture refusée (inventaire des accès illisible) refuse en 503 nommé. DÉCISION ÉCRITE, TENUE ICI :
    /// le chemin d'en-têtes ne joue pas ce refus (`zed-mpra` y reste prenable).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `juger_ce_que_le_nom_tient_a_la_federation` de `federer_le_nom` (la
    /// forme d'avant) — `Ok`, et le compte fédéré sert la requête de l'ancien titulaire ; refuser aussi un nom vu par
    /// l'annuaire (bras `vu_par_l_annuaire` retiré) — `carol-mpra` refusée.
    #[tokio::test]
    async fn mpra_la_federation_lit_ce_que_le_nom_tient_comme_la_creation() {
        let (st, _p) = sp_state("mpra-federation");
        let mut st = st;
        st.sso_secret = Arc::new(MPRA_SECRET_SSO.into());
        let orphelin = "zed-mpra";
        mpra_objets(&st, orphelin, &"a1".repeat(32));
        let detail = json!({ "vu_par_l_annuaire": false, "lignes": { "saved_query": 1, "dashboard_snapshot": 1, "dashboard": 1 } });

        let refus = federer_le_nom(&st, &st.db.lock(), orphelin, "viewer");
        assert_eq!(refus, Err(RefusDeLaFederation::NomTenuSansCompte(orphelin.into(), detail.clone())), "la fédération ne prend pas les restes");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", orphelin), 0, "aucune ligne posée");
        let (statut, corps) = mpra_corps(refus.expect_err("refus").servir(&st, PorteDeLAnnuaire::Oidc, "203.0.113.7")).await;
        assert_eq!((statut, &corps), (409, &json!({ "error": CAUSE_FEDERATION_NOM_TENU_SANS_COMPTE, "ce_que_le_nom_tient": detail })), "{corps}");
        let trace: Option<(String, String)> = st
            .db
            .lock()
            .query_row(
                "SELECT json_extract(fields,'$.cause'), json_extract(fields,'$.porte') FROM event WHERE json_extract(fields,'$.username')=?1",
                params![orphelin],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        assert_eq!(trace, Some(("nom_tenu_sans_compte".into(), "federation_oidc".into())), "le refus est tracé");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind=?1", "auth.annuaire.refuse"), 1, "et inscrit au registre");
        let (statut, corps) = mpra_corps(
            user_create(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "name": orphelin, "password": mpra_mot("zed"), "role": "viewer" }))).await,
        )
        .await;
        assert_eq!((statut, corps["ce_que_le_nom_tient"].clone()), (409, detail), "la création lit la même chose");

        // LA VOIE LÉGITIME : un nom que l'annuaire a présenté.
        let carol = "carol-mpra";
        let (identite, methode, _, _, _) = resolve_identity(&st, &mpra_requete_sso(carol));
        let (resolu, role) = identite.expect("fixture : l'annuaire authentifie");
        crate::acces_observe::consigner_l_acces(&st, "default", &resolu, &role, methode);
        mpra_objets(&st, carol, &"b2".repeat(32));
        assert_eq!(federer_le_nom(&st, &st.db.lock(), carol, "editor"), Ok(()), "un nom vu par l'annuaire est fédéré");
        assert_eq!(mpra_requetes_servies(&st, carol).await, 1, "et sa requête est la sienne");
        assert_eq!(federer_le_nom(&st, &st.db.lock(), "neuf-mpra", "viewer"), Ok(()), "un nom qui ne tient rien est fédéré");

        // LA DÉCISION ÉCRITE : le chemin d'en-têtes n'est pas touché.
        assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, orphelin), Ok(()), "les en-têtes prennent toujours ce nom (clé proposée)");

        // UN NOM NON VÉRIFIÉ.
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "acces_observe", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let refus = federer_le_nom(&st, &st.db.lock(), "autre-mpra", "viewer");
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(matches!(refus, Err(RefusDeLaFederation::TenueNonVerifiee(..))), "{refus:?}");
        let (statut, corps) = mpra_corps(refus.expect_err("refus").reponse()).await;
        assert_eq!((statut, corps["error"].clone()), (503, json!(CAUSE_FEDERATION_CE_QUE_LE_NOM_TIENT_NON_VERIFIE)), "{corps}");
        assert_eq!(mpra_compte(&st, "SELECT COUNT(*) FROM user WHERE name=?1", "autre-mpra"), 0, "aucune ligne posée");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.21-r` — DEUX RETRAITS CONCURRENTS DES DEUX DERNIERS ADMINISTRATEURS D'UN TENANT : AU PLUS UN PASSE
    // -------------------------------------------------------------------------------------

    /// Un tenant `mpra-t` (base créée) dont `mpra-a` et `mpra-b` sont les deux seuls administrateurs.
    async fn mpra_tenant_a_deux_administrateurs() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (st, dir) = mk_mode1_state();
        let sa = au_super("sa-mpra");
        let r = tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": MPRA_TENANT, "name": "MpraT" }))).await;
        assert_eq!(r.status(), StatusCode::CREATED, "fixture : tenant");
        for nom in ["mpra-a", "mpra-b"] {
            let r = grant_set(State(st.clone()), Extension(sa.clone()), Path(MPRA_TENANT.into()), Json(json!({ "user": nom, "role": "admin" }))).await;
            assert_eq!(r.status().as_u16(), 200, "fixture : {nom} administrateur");
        }
        (st, dir)
    }

    fn mpra_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn mpra_administrateurs_du_tenant(st: &AppState) -> i64 {
        effective_admin_grant_count_conn(&mpra_plan(st).conn.lock(), MPRA_TENANT).expect("fixture : droits lisibles")
    }

    fn mpra_maillons(st: &AppState, genre: &str) -> i64 {
        mpra_plan(st).conn.lock().query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0)).expect("fixture")
    }

    /// `acteur` retire (ou rétrograde) `cible` par le geste nommé.
    async fn mpra_geste_du_plan(st: AppState, geste: &'static str, acteur: &'static str, cible: &'static str) -> (u16, Value) {
        let id_de = |nom: &str| -> String {
            mpra_plan(&st).conn.lock().query_row("SELECT id FROM platform_user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : id")
        };
        let ctx = ScimCtx { tenant: MPRA_TENANT.into() };
        let r = match geste {
            "SCIM DELETE" => scim_user_delete(State(st.clone()), Extension(ctx), Path(id_de(cible))).await,
            "SCIM PUT active=false" => scim_user_replace(State(st.clone()), Extension(ctx), Path(id_de(cible)), Json(json!({ "active": false }))).await,
            "grant_delete" => grant_delete(State(st.clone()), Extension(au_tadmin(acteur, MPRA_TENANT)), Path((MPRA_TENANT.into(), cible.into()))).await,
            _ => grant_set(State(st.clone()), Extension(au_tadmin(acteur, MPRA_TENANT)), Path(MPRA_TENANT.into()), Json(json!({ "user": cible, "role": "viewer" }))).await,
        };
        mpra_corps(r).await
    }

    /// CE QU'IL TIENT, pour CHACUN des quatre gestes (SCIM `DELETE`, SCIM `PUT active=false`, `grant_delete`,
    /// `grant_set` vers `viewer`) : `mpra-a` retire `mpra-b` pendant que `mpra-b` retire `mpra-a`, le second joué au
    /// point de course du premier. Exactement UN passe, l'autre reçoit le refus « dernier administrateur » (409 SCIM,
    /// 400 console) ; il reste UN administrateur ; un seul maillon au journal de contrôle. Et le fait de structure :
    /// au point de course, le geste TIENT le verrou du plan de contrôle (garde et écriture sous un seul verrou).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : la garde lue sous ses propres verrous puis
    /// l'écriture sous un autre (`scim_would_orphan_last_admin(cp, …)` / `tenant_admin_grant_count(cp, …)` rétablis, le
    /// point de course posé entre la lecture et l'écriture) — les deux gestes passent, zéro administrateur.
    #[tokio::test]
    async fn mpra_deux_retraits_concurrents_des_derniers_administrateurs_d_un_tenant_au_plus_un_passe() {
        for (geste, genre) in [
            ("SCIM DELETE", "scim.user.deprovision"),
            ("SCIM PUT active=false", "scim.user.deprovision"),
            ("grant_delete", "grant.remove"),
            ("grant_set viewer", "grant.set"),
        ] {
            let (st, _dir) = mpra_tenant_a_deux_administrateurs().await;
            let maillons_avant = mpra_maillons(&st, genre);
            let st2 = st.clone();
            let course = mpra_course(&mpra_plan(&st).db_path, mpra_plan(&st).conn.clone(), move || {
                mpra_bloquer(mpra_geste_du_plan(st2, geste, "mpra-b", "mpra-a"))
            });
            let premier = mpra_geste_du_plan(st.clone(), geste, "mpra-a", "mpra-b").await;
            let (tenu, second) = mpra_attendre(&course);
            let second = second.unwrap_or_else(|| panic!("{geste} : le point de course n'a pas été atteint"));
            let passes = [premier.0, second.0].iter().filter(|s| matches!(s, 200 | 204)).count();
            assert_eq!(passes, 1, "{geste} : au plus UN passe, et un seul (premier {premier:?}, second {second:?})");
            assert_eq!(mpra_administrateurs_du_tenant(&st), 1, "{geste} : il reste un administrateur");
            let refus = if matches!(premier.0, 200 | 204) { &second } else { &premier };
            assert!(matches!(refus.0, 400 | 409), "{geste} : l'autre reçoit le refus du dernier administrateur : {refus:?}");
            assert_eq!(mpra_maillons(&st, genre) - maillons_avant, 1, "{geste} : un seul geste attesté");
            assert_eq!(tenu, Some(true), "{geste} : au point de course, le geste tient le verrou du plan de contrôle");
        }
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.21-r` — LA MÊME COURSE SUR LES COMPTES DU MODE 0 (`user_update`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `adm` et `adm2`, seuls administrateurs ; `adm` rétrograde `adm2` pendant que `adm2` rétrograde
    /// `adm`, le second joué au point de course du premier (la fenêtre où le verrou est relâché pour la preuve du mot de
    /// passe). Exactement UN passe (204), l'autre reçoit 400 « dernier administrateur » ; il reste un administrateur.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer la relecture de l'anti-verrouillage dans la
    /// transaction de `user_update` — deux 204, zéro administrateur.
    #[tokio::test]
    async fn mpra_deux_retrogradations_concurrentes_des_derniers_administrateurs_au_plus_une_passe() {
        let (st, _p) = sp_state("mpra-course-comptes");
        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES('adm2',?1,'admin')", params![hash_pw(MPRA_FIXTURE).expect("hachage")]).expect("fixture");
        let (id_adm, id_adm2) = (mpra_id(&st, "adm"), mpra_id(&st, "adm2"));
        let st2 = st.clone();
        let course = mpra_course(st.db_path.as_str(), st.db.clone(), move || {
            mpra_bloquer(async move {
                mpra_corps(user_update(State(st2), ConnectInfo(mpra_pair("10.75.0.2")), Extension(sp_au("adm2", "admin")), axum::extract::Path(id_adm), Json(json!({ "role": "viewer" }))).await)
                    .await
            })
        });
        let premier = mpra_corps(
            user_update(State(st.clone()), ConnectInfo(mpra_pair("10.75.0.1")), Extension(sp_au("adm", "admin")), axum::extract::Path(id_adm2), Json(json!({ "role": "viewer" }))).await,
        )
        .await;
        let (tenu, second) = mpra_attendre(&course);
        let second = second.expect("le point de course a été atteint");
        let admins: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).expect("lu");
        assert_eq!([premier.0, second.0].iter().filter(|s| **s == 204).count(), 1, "au plus UNE passe (premier {premier:?}, second {second:?})");
        assert_eq!(admins, 1, "il reste un administrateur");
        assert_eq!(premier, (400, json!("dernier administrateur — rétrogradation refusée")), "le geste dont la fenêtre a été franchie est refusé");
        assert_eq!(tenu, Some(false), "fixture : la fenêtre est celle où le verrou est relâché");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.21-r` — UN DROIT SCIM QUI ÉCRASERAIT LE RÔLE DU DERNIER ADMINISTRATEUR EST REFUSÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sans aucune course : `mpra-a` seul administrateur. `POST /Users` de `mpra-a` avec le groupe
    /// `viewer` : 409, il reste administrateur, aucun `scim.user.provision`. `PATCH /Groups/viewer` `add` de `mpra-a` : 409,
    /// la demande atomique (l'ajout de `mpra-c` dans la même demande n'est pas appliqué), aucun `scim.group.patch`.
    /// CONTRÔLE POSITIF : un second administrateur présent, la même demande passe (200) et rétrograde `mpra-a`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la garde de l'ajout du `PATCH` (la forme d'avant) — 200, zéro
    /// administrateur ; retirer celle du `POST /Users` — 201, zéro administrateur.
    #[tokio::test]
    async fn mpra_un_droit_scim_qui_retrograderait_le_dernier_administrateur_est_refuse() {
        let (st, _dir) = mpra_tenant_a_deux_administrateurs().await;
        let sa = au_super("sa-mpra");
        let r = grant_delete(State(st.clone()), Extension(sa.clone()), Path((MPRA_TENANT.into(), "mpra-b".into()))).await;
        assert_eq!(r.status().as_u16(), 204, "fixture : mpra-a seul administrateur");
        let ctx = || ScimCtx { tenant: MPRA_TENANT.into() };
        let id_c = ensure_platform_user(mpra_plan(&st), "mpra-c").expect("fixture");
        let id_a: String = mpra_plan(&st).conn.lock().query_row("SELECT id FROM platform_user WHERE name='mpra-a'", [], |r| r.get(0)).expect("fixture");

        let (statut, v) = mpra_corps(scim_user_create(State(st.clone()), Extension(ctx()), Json(json!({ "userName": "mpra-a", "groups": [{ "value": "viewer" }] }))).await).await;
        assert_eq!(statut, 409, "POST /Users : {v}");
        assert_eq!(mpra_administrateurs_du_tenant(&st), 1, "POST /Users : il reste administrateur");
        assert_eq!(mpra_maillons(&st, "scim.user.provision"), 0, "POST /Users : rien d'attesté");

        let patch = json!({ "Operations": [{ "op": "add", "value": [{ "value": id_c }, { "value": id_a }] }] });
        let (statut, v) = mpra_corps(scim_group_patch(State(st.clone()), Extension(ctx()), Path("viewer".into()), Json(patch.clone())).await).await;
        assert_eq!(statut, 409, "PATCH add : {v}");
        assert_eq!(mpra_administrateurs_du_tenant(&st), 1, "PATCH add : il reste administrateur");
        assert_eq!(count_grant(&st, MPRA_TENANT, "mpra-c"), 0, "PATCH add : la demande est atomique");
        assert_eq!(mpra_maillons(&st, "scim.group.patch"), 0, "PATCH add : rien d'attesté");

        // CONTRÔLE POSITIF — un second administrateur présent.
        let r = grant_set(State(st.clone()), Extension(sa), Path(MPRA_TENANT.into()), Json(json!({ "user": "mpra-b", "role": "admin" }))).await;
        assert_eq!(r.status().as_u16(), 200, "fixture : second administrateur");
        let (statut, v) = mpra_corps(scim_group_patch(State(st.clone()), Extension(ctx()), Path("viewer".into()), Json(patch)).await).await;
        assert_eq!(statut, 200, "avec un second administrateur, la demande passe : {v}");
        assert_eq!(mpra_administrateurs_du_tenant(&st), 1, "mpra-b reste administrateur, mpra-a est rétrogradé");
        assert_eq!(count_grant(&st, MPRA_TENANT, "mpra-c"), 1, "et mpra-c est ajouté");
    }
}
