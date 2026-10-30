// =====================================================================================
// `P10.24-e` et `P10.30-d` — LE RÔLE D'UNE LIGNE DU TENANT `default` SOUS UN PLAN DE CONTRÔLE ; L'AVEU DE LA BASE NON
// SERVIE À LA CRÉATION D'UN TENANT.
//
// LES DÉFAUTS, RELUS SUR LA BASE AVANT CE FICHIER.
//  * `handlers::users_lookups::user_update` : sous un plan de contrôle, le changement de rôle d'une ligne de `default`
//    était admis pour TOUTE ligne (`204`, rôle écrit, inscrit au registre), alors que le droit effectif vient du
//    `grant` et que le démarrage (`server::lire_l_etat_d_administration`) n'y lit que deux faits : la ligne de
//    l'administrateur de l'assistant est-elle `admin`, et reste-t-il une ligne `admin`. Le témoin de la vague BD
//    l'affirmait comme un reste nommé (`bd1_le_role_d_une_ligne_du_tenant_default_reste_change_sous_plan`, inversé
//    dans son fichier).
//  * `tenants.rs::tenant_create` : une base du tenant NON SERVIE à l'événement de création (`SansBaseServie`) n'était
//    avouée par aucun corps (limite écrite au code), alors que les quatre autres gestes l'avouaient.
//
// CE QUI EST TENU ICI. Sous un plan de contrôle, dans `default`, un changement de rôle est admis seulement s'il fait
// passer la ligne de `admin` à un autre rôle ou l'inverse ET que la ligne est celle de l'administrateur de l'assistant
// (`st.admin` ou `meta.admin_user`) ou qu'aucune ligne n'est `admin` ; tout autre changement rend `409`
// `CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET`, après la lecture de la cible, la validation, l'anti-verrouillage,
// et avant le secret des gestes ; les deux faits non lus rendent `503`
// `CAUSE_COMPTE_NON_MODIFIE_EFFET_DU_ROLE_NON_ETABLI`, ligne de journal entière. Sans plan de contrôle : admis comme
// avant. La création d'un tenant suspendu dès son inscription rend son `201` avec
// `evenement_du_tenant_non_ecrit: CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE`.
//
// LES VOIES : le routeur réel (Basic d'un administrateur de `default` par son droit) pour les issues servies ;
// l'appel direct de `user_update` pour les lectures rendues illisibles (`meta` renommée, `user` remplacée par une vue
// dont le `role` d'une AUTRE ligne échoue) ; un déclencheur `AFTER INSERT` sur `tenant` du plan de contrôle, qui
// suspend le tenant à son inscription, pour la base non servie à la création.
//
// MUTANTS JOUÉS (posés sous une variable de mutation lue en `cfg!(test)`, retirés avant le commit), chacun nommé au
// témoin qu'il fait rougir.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint de ces corps (aucun témoin de harnais ; les refus de
// `/api/users/{id}` y passent par la face générique, qui colle la phrase).
// =====================================================================================
mod role_de_default_sous_plan_et_aveu_de_la_creation_sans_base {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{
        rgsc_basic, rgsc_compter, rgsc_envoyer, rgsc_ligne, rgsc_plateforme, RgscReponse, RGSC_JSON, RGSC_MOT_DE_PASSE, RGSC_MOT_DE_PASSE_DE_LA_LIGNE, RGSC_SECRET,
    };
    use super::*;
    use std::sync::atomic::Ordering;

    const RDSP_SECRET_SSO: &str = "secret-de-bord-rdsp";
    const RDSP_TENANT_DEFAULT: (&str, &str) = ("x-plume-tenant", "default");
    /// L'ouverture de la phrase du refus de `default`, écrite ICI (pas lue dans la constante) : la phrase servie est
    /// celle de `default`, distincte de celle des autres tenants.
    const RDSP_OUVERTURE_DU_REFUS_DE_DEFAULT: &str =
        "RÔLE NON CHANGÉ, LES DROITS SONT CEUX DE LA PLATEFORME : en mode multi-tenant, le rôle d'un compte dans le tenant `default` est celui de son droit";
    const RDSP_OUVERTURE_DE_L_EFFET_NON_ETABLI: &str = "COMPTE NON MODIFIÉ, EFFET DU RÔLE NON ÉTABLI : la base du tenant `default` n'a pas pu lire";

    async fn rdsp_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    /// Le refus de `default`, corps EXACT, et son ouverture contre le littéral du témoin.
    fn rdsp_refus_de_default(quoi: &str, r: &RgscReponse) {
        assert_eq!((r.statut, &r.corps), (409, &json!({ "error": CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET })), "{quoi} : {}", r.texte);
        assert!(CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET.starts_with(RDSP_OUVERTURE_DU_REFUS_DE_DEFAULT), "{quoi} : la phrase de `default`");
    }

    /// Un `503` d'`err_json` : EXACTEMENT `{error, id}`, l'erreur égale à la phrase de l'effet non établi.
    fn rdsp_effet_non_etabli(quoi: &str, statut: u16, corps: &Value) {
        assert_eq!(statut, 503, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : un objet JSON : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble EXACT des clés : {corps}");
        assert_eq!(o["error"], json!(CAUSE_COMPTE_NON_MODIFIE_EFFET_DU_ROLE_NON_ETABLI), "{quoi} : la phrase entière : {corps}");
        assert!(CAUSE_COMPTE_NON_MODIFIE_EFFET_DU_ROLE_NON_ETABLI.starts_with(RDSP_OUVERTURE_DE_L_EFFET_NON_ETABLI), "{quoi} : l'ouverture");
        assert!(o["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
    }

    fn rdsp_role(st: &AppState, nom: &str) -> String {
        st.db.lock().query_row("SELECT role FROM user WHERE name=?1", params![nom], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : rôle de {nom} lu ({e})"))
    }

    fn rdsp_inscrits(st: &AppState) -> i64 {
        rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.role_change")
    }

    fn rdsp_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"));
    }

    /// `POST /api/users/{id}` sous `default` par `rgsc-dan` (administrateur de `default` par son droit, Basic).
    async fn rdsp_poster(addr: std::net::SocketAddr, id: i64, role: &str, avec_secret: bool) -> RgscReponse {
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let mut entetes = vec![RGSC_JSON, RDSP_TENANT_DEFAULT];
        if avec_secret {
            entetes.push(RGSC_SECRET);
        }
        rgsc_envoyer(addr, "POST", &format!("/api/users/{id}"), Some(&dan), &entetes, &json!({ "role": role }).to_string()).await
    }

    /// Les deux faits du démarrage, sur la fixture : aucune ligne `admin`, aucun administrateur de l'assistant.
    fn rdsp_base_de_default_vierge(st: &AppState) {
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM user WHERE role=?1", "admin"), 0, "fixture : aucune ligne `admin` dans `default`");
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM meta WHERE key=?1", "admin_user"), 0, "fixture : aucun `meta.admin_user`");
        assert!(st.admin.lock().is_none(), "fixture : aucun administrateur de l'assistant chargé");
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.24-e` — SOUS UN PLAN DE CONTRÔLE, UN CHANGEMENT SANS EFFET AU DÉMARRAGE EST REFUSÉ DANS `default`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle (deux tenants réels), par le routeur, tenant `default`,
    /// auteur `rgsc-dan`. Base de `default` sans ligne `admin` ni administrateur de l'assistant :
    ///  (a) `rdsp-ed` (`editor`) -> `viewer` : `409` corps exact `{error: CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET}`
    ///      — aucune ligne n'est `admin`, mais ce changement ne la fait pas passer de `admin` à un autre rôle ;
    ///  (b) rôle invalide sur `rdsp-ed` : le `400` d'avant ; identifiant absent : le `404` d'avant (jugé APRÈS la
    ///      lecture et la validation, contrairement aux autres tenants) ;
    /// une ligne `rdsp-adm1` (`admin`) posée :
    ///  (c) `rdsp-vw` (`viewer`) -> `admin`, SANS le secret des gestes : `409` (une ligne `admin` existe déjà ; aucun
    ///      secret examiné : pas le `403` du secret absent) ;
    ///  (d) `rdsp-adm1` -> `viewer` : le `400` d'avant « dernier administrateur » (l'anti-verrouillage d'abord) ;
    /// une ligne `rdsp-adm2` (`admin`) posée :
    ///  (e) `rdsp-adm2` -> `viewer`, avec le secret : `409` (il en reste une).
    /// Après eux : aucun rôle n'a changé, aucune ligne `config.user.role_change` au registre de `default`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_SANS_REFUS » (la forme d'avant : `204` partout) ; « BE3_FRANCHIT_IGNORE »
    /// (le passage `admin` <-> autre rôle non exigé : (a) admis, aucune ligne n'étant `admin`) ; « BE3_PHRASE_DE_TENANT »
    /// (la phrase des autres tenants servie) ; « BE3_ZERO_LE_UN » (« au plus une ligne `admin` » au lieu d'« aucune » :
    /// (c) admis) ; « BE3_APRES_SECRET » (le refus jugé après le secret des gestes : (c) rend `403`) ;
    /// « BE3_AVANT_GARDES » (le refus jugé avant l'anti-verrouillage : (d) rend `409`).
    #[tokio::test]
    async fn rdsp_sous_plan_un_role_sans_effet_au_demarrage_est_refuse_dans_default() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        rdsp_base_de_default_vierge(&st);
        let ed = rgsc_ligne(&st, "default", "rdsp-ed", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let vw = rgsc_ligne(&st, "default", "rdsp-vw", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);

        rdsp_refus_de_default("(a) editor -> viewer, aucune ligne admin", &rdsp_poster(addr, ed, "viewer", true).await);
        let r = rdsp_poster(addr, ed, "superviseur", true).await;
        assert_eq!((r.statut, &r.corps), (400, &json!("rôle invalide (admin|editor|viewer)")), "(b) rôle invalide : {}", r.texte);
        let r = rdsp_poster(addr, ed + 999_999, "viewer", true).await;
        assert_eq!((r.statut, &r.corps), (404, &json!("compte introuvable")), "(b) identifiant absent : {}", r.texte);

        rgsc_ligne(&st, "default", "rdsp-adm1", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let adm1: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name='rdsp-adm1'", [], |r| r.get(0)).expect("fixture");
        rdsp_refus_de_default("(c) viewer -> admin sans secret, une ligne admin", &rdsp_poster(addr, vw, "admin", false).await);
        let r = rdsp_poster(addr, adm1, "viewer", true).await;
        assert_eq!((r.statut, &r.corps), (400, &json!("dernier administrateur — rétrogradation refusée")), "(d) dernier administrateur : {}", r.texte);

        let adm2 = rgsc_ligne(&st, "default", "rdsp-adm2", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        rdsp_refus_de_default("(e) admin -> viewer, deux lignes admin", &rdsp_poster(addr, adm2, "viewer", true).await);

        let roles: Vec<String> = ["rdsp-ed", "rdsp-vw", "rdsp-adm1", "rdsp-adm2"].iter().map(|n| rdsp_role(&st, n)).collect();
        assert_eq!(roles, ["editor", "viewer", "admin", "admin"], "aucun rôle écrit");
        assert_eq!(rdsp_inscrits(&st), 0, "rien d'inscrit au registre de `default`");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-e` — UN CHANGEMENT QUI DÉCIDE DU DÉMARRAGE RESTE ADMIS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : même plateforme, tenant `default`, auteur `rgsc-dan`, chaque fois `204`, rôle écrit, inscrit :
    ///  (f) aucune ligne `admin` : `rdsp-vw0` (`viewer`) -> `admin` (la promotion ferme l'installation) ; SANS le secret
    ///      d'abord : le `403` du secret (le geste admis passe par lui), rôle inchangé ;
    ///  (g) `meta.admin_user` = `rdsp-wiz` (`viewer`), `st.admin` vide, une ligne `admin` ailleurs : `rdsp-wiz` -> `admin`
    ///      (il sera rechargé au démarrage) ;
    ///  (h) le même `rdsp-wiz` -> `viewer`, deux lignes `admin` : admis (il ne sera plus rechargé) ;
    ///  (i) `st.admin` nomme `rdsp-assist` (`viewer`), `meta.admin_user` nomme un autre, une ligne `admin` ailleurs :
    ///      `rdsp-assist` -> `admin` : admis ; puis le même `admin` -> `admin` : `409` (rien ne passe de `admin` à un
    ///      autre rôle, même sur la ligne de l'assistant ; non inscrit).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_ZERO_IGNORE » (aucune ligne `admin` ne compte plus : (f) `409`) ;
    /// « BE3_META_IGNORE » (`meta.admin_user` non lu : (g) et (h) `409`) ; « BE3_FRANCHIT_PROMO_SEULE » (seule une
    /// promotion peut avoir un effet : (h) `409`) ; « BE3_ST_ADMIN_IGNORE » (`st.admin` non lu : (i) `409`).
    #[tokio::test]
    async fn rdsp_sous_plan_un_role_qui_decide_le_demarrage_reste_admis_dans_default() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        rdsp_base_de_default_vierge(&st);
        let vw0 = rgsc_ligne(&st, "default", "rdsp-vw0", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let r = rdsp_poster(addr, vw0, "admin", false).await;
        assert_eq!(r.statut, 403, "(f) sans secret : le geste admis passe par le secret des gestes : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-vw0"), "viewer", "(f) sans secret : rien d'écrit");
        let r = rdsp_poster(addr, vw0, "admin", true).await;
        assert_eq!(r.statut, 204, "(f) aucune ligne admin, promotion : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-vw0"), "admin", "(f) écrit");

        let wiz = rgsc_ligne(&st, "default", "rdsp-wiz", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        rdsp_sql(&st, "INSERT INTO meta(key,value) VALUES('admin_user','rdsp-wiz')");
        let r = rdsp_poster(addr, wiz, "admin", true).await;
        assert_eq!(r.statut, 204, "(g) administrateur de l'assistant par `meta`, promotion : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-wiz"), "admin", "(g) écrit");
        let r = rdsp_poster(addr, wiz, "viewer", true).await;
        assert_eq!(r.statut, 204, "(h) administrateur de l'assistant par `meta`, rétrogradation : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-wiz"), "viewer", "(h) écrit");

        let assist = rgsc_ligne(&st, "default", "rdsp-assist", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        *st.admin.lock() = Some(("rdsp-assist".into(), hash_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE).expect("hachage")));
        let r = rdsp_poster(addr, assist, "admin", true).await;
        assert_eq!(r.statut, 204, "(i) administrateur de l'assistant par `st.admin`, promotion : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-assist"), "admin", "(i) écrit");
        rdsp_refus_de_default("(i) administrateur de l'assistant par `st.admin`, admin -> admin", &rdsp_poster(addr, assist, "admin", true).await);
        assert_eq!(rdsp_inscrits(&st), 4, "les quatre changements admis sont inscrits, le refus ne l'est pas");
    }

    // -------------------------------------------------------------------------------------
    // (2 bis) `P10.24-e` — L'ADMINISTRATEUR DE L'ASSISTANT DÉSIGNE UNE AUTRE LIGNE : LE PASSAGE RESTE REFUSÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le cas courant d'une installation, où l'administrateur de l'assistant EXISTE et désigne une
    /// AUTRE ligne que la cible. Plan de contrôle, tenant `default`, auteur `rgsc-dan`, secret présenté ; lignes
    /// `rdsp-assist` (`viewer`, la ligne nommée), `rdsp-vw` (`viewer`), `rdsp-adm1` et `rdsp-adm2` (`admin`). Chaque
    /// phase envoie `rdsp-vw` -> `admin` (promotion, des lignes `admin` existent déjà) et `rdsp-adm2` -> `viewer`
    /// (rétrogradation, l'autre `admin` reste) ; chaque fois `409` corps exact
    /// `{error: CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET}` :
    ///  (j) `st.admin` nomme `rdsp-assist`, aucun `meta.admin_user` ;
    ///  (k) `st.admin` vide, `meta.admin_user` = `rdsp-assist` ;
    ///  (l) les deux nomment `rdsp-assist` (l'état d'une installation rechargée au démarrage).
    /// CONTRÔLE, même fixture que (l) : `rdsp-assist` -> `admin` rend `204` — le refus tient au NOM désigné, pas à la
    /// présence d'un administrateur de l'assistant. Après eux : seuls `rdsp-assist` a changé, une seule ligne
    /// `config.user.role_change` inscrite.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_STADMIN_PRESENT » (`st.admin` compté dès qu'il est chargé, quel que soit
    /// le nom : (j) et (l) `204`) ; « BE3_META_PRESENT » (`meta.admin_user` compté dès qu'il est posé, quel que soit le
    /// nom : (k) `204`).
    #[tokio::test]
    async fn rdsp_sous_plan_l_administrateur_de_l_assistant_qui_nomme_une_autre_ligne_n_admet_pas_le_passage() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        rdsp_base_de_default_vierge(&st);
        let assist = rgsc_ligne(&st, "default", "rdsp-assist", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let vw = rgsc_ligne(&st, "default", "rdsp-vw", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        rgsc_ligne(&st, "default", "rdsp-adm1", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let adm2 = rgsc_ligne(&st, "default", "rdsp-adm2", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let assistant_en_memoire = || Some(("rdsp-assist".to_string(), hash_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE).expect("hachage")));

        *st.admin.lock() = assistant_en_memoire();
        rdsp_refus_de_default("(j) `st.admin` nomme une autre ligne, viewer -> admin", &rdsp_poster(addr, vw, "admin", true).await);
        rdsp_refus_de_default("(j) `st.admin` nomme une autre ligne, admin -> viewer", &rdsp_poster(addr, adm2, "viewer", true).await);

        *st.admin.lock() = None;
        rdsp_sql(&st, "INSERT INTO meta(key,value) VALUES('admin_user','rdsp-assist')");
        rdsp_refus_de_default("(k) `meta.admin_user` nomme une autre ligne, viewer -> admin", &rdsp_poster(addr, vw, "admin", true).await);
        rdsp_refus_de_default("(k) `meta.admin_user` nomme une autre ligne, admin -> viewer", &rdsp_poster(addr, adm2, "viewer", true).await);

        *st.admin.lock() = assistant_en_memoire();
        rdsp_refus_de_default("(l) les deux nomment une autre ligne, viewer -> admin", &rdsp_poster(addr, vw, "admin", true).await);
        rdsp_refus_de_default("(l) les deux nomment une autre ligne, admin -> viewer", &rdsp_poster(addr, adm2, "viewer", true).await);

        let roles: Vec<String> = ["rdsp-vw", "rdsp-adm1", "rdsp-adm2", "rdsp-assist"].iter().map(|n| rdsp_role(&st, n)).collect();
        assert_eq!(roles, ["viewer", "admin", "admin", "viewer"], "aucun rôle écrit par les refus");
        assert_eq!(rdsp_inscrits(&st), 0, "rien d'inscrit par les refus");

        let r = rdsp_poster(addr, assist, "admin", true).await;
        assert_eq!(r.statut, 204, "contrôle : la ligne nommée elle-même passe à `admin` : {}", r.texte);
        assert_eq!(rdsp_role(&st, "rdsp-assist"), "admin", "contrôle : écrit");
        assert_eq!(rdsp_inscrits(&st), 1, "contrôle : seul le changement admis est inscrit");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-e` — LES DEUX FAITS NON LUS : 503 NOMMÉ
    // -------------------------------------------------------------------------------------

    /// `user_update` appelé directement par l'administrateur de `default` (son droit) : renommer `meta` ou `user`
    /// casserait l'authentification d'une route.
    async fn rdsp_promouvoir_direct(st: &AppState, id: i64) -> (u16, Value) {
        let dan = AuthUser { name: "rgsc-dan".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        rdsp_corps(
            user_update(
                State(st.clone()),
                crate::secret_des_gestes::presente_de_test(),
                axum::extract::ConnectInfo("192.0.2.31:45454".parse().expect("adresse de test")),
                Extension(dan),
                axum::extract::Path(id),
                Json(json!({ "role": "admin" })),
            )
            .await,
        )
        .await
    }

    /// CE QU'IL TIENT : plan de contrôle, tenant `default`, `rdsp-vw` (`viewer`) -> `admin`, une ligne `admin` ailleurs,
    /// aucun administrateur de l'assistant en mémoire. `meta` hors d'atteinte (renommée) : `503` corps exact `{error:
    /// CAUSE_COMPTE_NON_MODIFIE_EFFET_DU_ROLE_NON_ETABLI, id}`. Le `role` d'une AUTRE ligne (`rdsp-casse`) illisible
    /// (vue) — la cible se lit, le compte des administrateurs échoue : le même `503`. Chaque fois : rôle inchangé,
    /// rien d'inscrit. CONTRÔLE : les deux rendues lisibles, la même demande rend le `409` de `default`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_LECTURE_RATEE_409 » (la lecture ratée servie comme « sans effet ») ;
    /// « BE3_LECTURE_RATEE_ADMISE » (la lecture ratée servie comme un effet : `204`, rôle écrit).
    #[tokio::test]
    async fn rdsp_sous_plan_l_effet_non_lu_est_un_503_nomme_et_rien_ne_change() {
        let (st, _dir) = rgsc_plateforme().await;
        rdsp_base_de_default_vierge(&st);
        let vw = rgsc_ligne(&st, "default", "rdsp-vw", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        rgsc_ligne(&st, "default", "rdsp-adm", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        rgsc_ligne(&st, "default", "rdsp-casse", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);

        rdsp_sql(&st, "ALTER TABLE meta RENAME TO rdsp_meta_hors_d_atteinte;");
        let (statut, corps) = rdsp_promouvoir_direct(&st, vw).await;
        rdsp_sql(&st, "ALTER TABLE rdsp_meta_hors_d_atteinte RENAME TO meta;");
        rdsp_effet_non_etabli("`meta` hors d'atteinte", statut, &corps);
        assert_eq!(rdsp_role(&st, "rdsp-vw"), "viewer", "`meta` hors d'atteinte : rien d'écrit");

        rdsp_sql(
            &st,
            "ALTER TABLE user RENAME TO rdsp_user_reel;
             CREATE VIEW user AS SELECT id, name, hash, CASE WHEN name='rdsp-casse' THEN json(name || '{') ELSE role END AS role, created FROM rdsp_user_reel;",
        );
        let (statut, corps) = rdsp_promouvoir_direct(&st, vw).await;
        rdsp_sql(&st, "DROP VIEW user; ALTER TABLE rdsp_user_reel RENAME TO user;");
        rdsp_effet_non_etabli("administrateurs non comptés", statut, &corps);
        assert_eq!(rdsp_role(&st, "rdsp-vw"), "viewer", "administrateurs non comptés : rien d'écrit");
        assert_eq!(rdsp_inscrits(&st), 0, "rien d'inscrit");

        let (statut, corps) = rdsp_promouvoir_direct(&st, vw).await;
        assert_eq!((statut, corps), (409, json!({ "error": CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET })), "contrôle : les faits lus décident");
    }

    /// CE QU'IL TIENT : la ligne `[comptes] WARN` de l'effet non établi, lue ENTIÈRE sur le stderr d'un sous-processus :
    /// `meta` hors d'atteinte, la promotion de `rdsp-vw` écrit EXACTEMENT `[comptes] WARN modification du compte <id>
    /// refusée : l'effet de son rôle n'a pas pu être établi (<constat>)`, une fois, où `<constat>` est l'erreur que rend
    /// `ENONCE_DES_FAITS_DU_DEMARRAGE` sur la même base ; la ligne ne nomme pas le compte (`rdsp-vw`).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_JOURNAL_MUET » (la ligne retirée) ; « BE3_JOURNAL_NOMME » (la ligne nomme
    /// le compte).
    #[tokio::test]
    async fn rdsp_journal_de_l_effet_non_lu_ligne_entiere_sans_nom() {
        const ENFANT: &str = "RDSP_ENFANT_JOURNAL_DE_L_EFFET";
        const MARQUE: &str = "RDSP-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les mutants lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _dir) = rgsc_plateforme().await;
            let vw = rgsc_ligne(&st, "default", "rdsp-vw", "viewer", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
            rgsc_ligne(&st, "default", "rdsp-adm", "admin", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
            rdsp_sql(&st, "ALTER TABLE meta RENAME TO rdsp_meta_hors_d_atteinte;");
            let constat = st.db.lock().query_row(ENONCE_DES_FAITS_DU_DEMARRAGE, [], |r| r.get::<_, Option<String>>(0)).expect_err("fixture : `meta` hors d'atteinte").to_string();
            eprintln!("{MARQUE}debut");
            let (statut, _) = rdsp_promouvoir_direct(&st, vw).await;
            eprintln!("{MARQUE}fin");
            println!("RDSP-STATUT:{statut}");
            println!("RDSP-ID:{vw}");
            println!("RDSP-CONSTAT:{}", json!(constat));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::role_de_default_sous_plan_et_aveu_de_la_creation_sans_base::rdsp_journal_de_l_effet_non_lu_ligne_entiere_sans_nom",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> String {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").to_string()
        };
        assert_eq!(marque("RDSP-STATUT:"), "503", "contrôle : le 503 de l'effet non établi");
        let id = marque("RDSP-ID:");
        let constat: String = serde_json::from_str(&marque("RDSP-CONSTAT:")).expect("contrôle : constat");
        let debut = stderr.split_once(&format!("{MARQUE}debut\n")).unwrap_or_else(|| panic!("contrôle : phase : {stderr}")).1;
        let corps = debut.split_once(MARQUE).map(|(c, _)| c).unwrap_or(debut);
        let lues: Vec<&str> = corps.lines().filter(|l| l.contains("[comptes]")).collect();
        assert_eq!(lues, [format!("[comptes] WARN modification du compte {id} refusée : l'effet de son rôle n'a pas pu être établi ({constat})")], "la ligne entière, une fois");
        assert!(lues.iter().all(|l| !l.contains("rdsp-vw")), "la ligne ne nomme pas le compte : {lues:?}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.24-e` — SANS PLAN DE CONTRÔLE, ADMIS COMME AVANT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : mode 0 (aucun plan de contrôle : la ligne EST le compte qui se connecte), par le routeur,
    /// `rdsp-carol` administratrice du SSO d'en-têtes. `rdsp-alice` (`editor`) -> `viewer` : `204`, écrit ; `rdsp-adm2`
    /// (`admin`, deux lignes `admin`, ni l'une ni l'autre l'administrateur de l'assistant) -> `viewer` : `204`, écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BE3_SANS_PLAN » (le jugement de `default` appliqué sans plan de contrôle :
    /// `409` sur les deux).
    #[tokio::test]
    async fn rdsp_sans_plan_de_controle_le_role_d_une_ligne_de_default_se_change() {
        let (mut st, _p) = router_test_state("rdsp-mode-0");
        st.sso_secret = Arc::new(RDSP_SECRET_SSO.into());
        st.installation_ouverte.store(false, Ordering::SeqCst);
        assert!(st.tenants.control.is_none() && st.admin.lock().is_none(), "fixture : mode 0, aucun administrateur de l'assistant");
        let ids: Vec<i64> = {
            let c = st.db.lock();
            [("rdsp-alice", "editor"), ("rdsp-adm1", "admin"), ("rdsp-adm2", "admin")]
                .iter()
                .map(|(nom, role)| {
                    c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, hash_pw(RGSC_MOT_DE_PASSE).expect("hachage"), role]).expect("fixture : compte");
                    c.last_insert_rowid()
                })
                .collect()
        };
        let addr = router_serve(st.clone()).await;
        let sso = [RGSC_JSON, ("x-plume-sso-secret", RDSP_SECRET_SSO), ("x-authentik-username", "rdsp-carol"), ("x-authentik-groups", "plume-admin"), ("Origin", "http://127.0.0.1")];
        let r_alice = rgsc_envoyer(addr, "POST", &format!("/api/users/{}", ids[0]), None, &sso, &json!({ "role": "viewer" }).to_string()).await;
        let r_adm2 = rgsc_envoyer(addr, "POST", &format!("/api/users/{}", ids[2]), None, &sso, &json!({ "role": "viewer" }).to_string()).await;
        assert_eq!([r_alice.statut, r_adm2.statut], [204, 204], "mode 0 : {} | {}", r_alice.texte, r_adm2.texte);
        assert_eq!([rdsp_role(&st, "rdsp-alice"), rdsp_role(&st, "rdsp-adm2")], ["viewer", "viewer"], "mode 0 : écrits");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.30-d` — LA CRÉATION D'UN TENANT DONT LA BASE N'EST PAS SERVIE L'AVOUE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : plan de contrôle, `tenant_create` par le super-administrateur, sans premier administrateur. Un
    /// déclencheur `AFTER INSERT` sur `tenant` suspend le tenant à son inscription : la base est provisionnée, mais
    /// l'événement de création n'a pas de destinataire. `201`, corps EXACT `{ok, id, name, first_admin: null,
    /// evenement_du_tenant_non_ecrit: CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE}` ; le tenant est inscrit, suspendu.
    /// CONTRÔLE POSITIF : déclencheur retiré, un autre tenant rend le `201` d'avant, à l'octet, sans la clé.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BE3_SANS_BASE_MUET » (rbac.rs : `SansBaseServie` non avoué, la forme
    /// d'avant) ; « BE3_SANS_BASE_PHRASE_PERTE » (la phrase de la perte d'écriture servie à la place) ;
    /// « BE3_CREATION_SANS_APPEL » (tenants.rs : la création n'appelle plus l'aveu).
    #[tokio::test]
    async fn rdsp_la_creation_d_un_tenant_dont_la_base_n_est_pas_servie_l_avoue() {
        let (st, _dir) = mk_mode1_state();
        let sa = au_super("op-rdsp");
        let plan = st.tenants.control.as_ref().expect("plan");
        plan.conn
            .lock()
            .execute_batch("CREATE TRIGGER rdsp_suspendu_a_l_inscription AFTER INSERT ON tenant BEGIN UPDATE tenant SET suspended=1 WHERE id=NEW.id; END;")
            .expect("fixture : déclencheur");
        let (statut, v) = rdsp_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "rdsp-susp", "name": "RdspSusp" }))).await).await;
        assert_eq!(
            (statut, &v),
            (
                201,
                &json!({ "ok": true, "id": "rdsp-susp", "name": "RdspSusp", "first_admin": null, "evenement_du_tenant_non_ecrit": crate::tenants::CAUSE_EVENEMENT_DU_TENANT_SANS_BASE_SERVIE })
            ),
            "base non servie à la création : l'événement non écrit est AVOUÉ"
        );
        let suspendu: i64 = plan.conn.lock().query_row("SELECT suspended FROM tenant WHERE id='rdsp-susp'", [], |r| r.get(0)).expect("fixture : tenant inscrit");
        assert_eq!(suspendu, 1, "fixture : le tenant est inscrit, suspendu");

        plan.conn.lock().execute_batch("DROP TRIGGER rdsp_suspendu_a_l_inscription;").expect("fixture");
        let (statut, v) = rdsp_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "rdsp-servi", "name": "RdspServi" }))).await).await;
        assert_eq!((statut, &v), (201, &json!({ "ok": true, "id": "rdsp-servi", "name": "RdspServi", "first_admin": null })), "nominal : le 201 d'avant, à l'octet");
    }
}
