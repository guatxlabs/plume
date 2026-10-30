// =====================================================================================
// `P10.31-i` et `P10.24-e` (reprise de la vague BC) — LA RELECTURE DU SUPER-ADMINISTRATEUR SUIT LA MÉTHODE ; L'ORDRE DES
// REFUS DE LA CRÉATION ; LE RÔLE D'UNE LIGNE DE TENANT SOUS UN PLAN DE CONTRÔLE.
//
// Relevés par la vérification de la vague BC, mesurés sur l'arbre repris avant ce fichier :
//  * `session::revocation_globale_post` relit `platform_user` pour Basic et cookie seulement (le SSO d'en-têtes juge
//    par les groupes) : retirer ce filtre de méthode ne faisait rougir aucun témoin, et un administrateur de tenant
//    servi par le SSO recevait alors le `503` AUTORITÉ NON LUE au lieu du `403` de la réserve. La relecture Basic
//    n'avait pas de témoin non plus (le témoin d'avant joue le cookie).
//  * `handlers::users_lookups::user_create` : le refus `409` « identité de plateforme » est dit jugé après la validation
//    du corps ; le placer avant ne faisait rougir aucun témoin — un nom invalide, un nom réservé, un mot de passe court
//    prenaient la cause « identité de plateforme ».
//  * `handlers::users_lookups::user_update` : sous un plan de contrôle, le rôle d'une ligne de tenant n'est lu par
//    aucune résolution (`rbac::resolve_tenant_access` -> `grant_role_for`) ; le changer était servi `204`. Refus neuf
//    `409` `CAUSE_ROLE_NON_CHANGE_IDENTITE_DE_PLATEFORME`, hors tenant `default` (sa base est lue au démarrage :
//    `server::lire_l_etat_d_administration`). Le tenant `default` est jugé ligne par ligne depuis la vague BE
//    (`409` `CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET` pour un changement sans effet au démarrage ; témoins dans
//    `role_de_default_sous_plan_et_aveu_de_la_creation_sans_base.rs`).
//
// MUTANTS JOUÉS (posés sous `VERIF_MUT`, retirés avant le commit), chacun nommé au témoin qu'il fait rougir.
// =====================================================================================
mod relecture_par_methode_ordre_de_la_creation_et_role_d_une_ligne_de_tenant {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{
        rgsc_base, rgsc_basic, rgsc_cinq_cent_trois, rgsc_compter, rgsc_envoyer, rgsc_epoques, rgsc_ligne, rgsc_plateforme, rgsc_traces_globales, RGSC_JSON,
        RGSC_MOT_DE_PASSE, RGSC_MOT_DE_PASSE_DE_LA_LIGNE, RGSC_MOT_DE_PASSE_NEUF, RGSC_SECRET, RGSC_TENANT_A, RGSC_TENANT_B,
    };
    use super::*;
    use std::sync::atomic::Ordering;

    const BD1_ROUTE_REVOCATION: &str = "/api/sessions/revocation-globale";
    const BD1_SECRET_SSO: &str = "secret-de-bord-bd1";
    const BD1_MOT_DE_PASSE_DE_CONFIGURATION: &str = "configuration-bd1-123456";

    /// Les en-têtes du SSO d'en-têtes pour `nom` et `groupes`, sous le secret de bord de ce fichier.
    fn bd1_sso(nom: &'static str, groupes: &'static str) -> Vec<(&'static str, &'static str)> {
        vec![("x-plume-sso-secret", BD1_SECRET_SSO), ("x-authentik-username", nom), ("x-authentik-groups", groupes), ("Origin", "http://127.0.0.1")]
    }

    /// La plateforme de `rgsc_plateforme` (deux tenants réels, plan de contrôle) sous le secret de bord de ce fichier.
    async fn bd1_plateforme() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (mut st, dir) = rgsc_plateforme().await;
        st.sso_secret = Arc::new(BD1_SECRET_SSO.into());
        (st, dir)
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.31-i` — LA RELECTURE DU SUPER-ADMINISTRATEUR SUIT LA MÉTHODE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle, par le routeur. `bd1-sso-ta`, administrateur du tenant A
    /// par ses groupes (`plume-rgsca-admin`), PAS super-administrateur par ses groupes, `platform_user` rendue illisible
    /// (table renommée) le temps de la requête : `POST /api/sessions/revocation-globale` sous A rend `403`, corps exact
    /// `{error: CAUSE_REVOCATION_GLOBALE_RESERVEE}` — le SSO juge l'autorité par les groupes, il n'y a rien à relire ;
    /// aucun cookie effacé, époque globale `(0, 0)`, aucune ligne `auth.deconnexion.globale`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « S_RG_RELU_SSO » (le filtre de méthode retiré : la relecture échoue sur la table
    /// illisible et sert le `503` AUTORITÉ NON LUE à un appelant que les groupes ont déjà jugé).
    #[tokio::test]
    async fn bd1_sso_administrateur_de_tenant_platform_user_illisible_garde_le_403() {
        let (st, _dir) = bd1_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let plan = st.tenants.control.as_ref().expect("plan");
        let mut sso = bd1_sso("bd1-sso-ta", "plume-rgsca-admin");
        sso.push(("x-plume-tenant", RGSC_TENANT_A));
        plan.conn.lock().execute_batch("ALTER TABLE platform_user RENAME TO bd1_platform_user_cache;").expect("fixture : illisible");
        let r = rgsc_envoyer(addr, "POST", BD1_ROUTE_REVOCATION, None, &sso, "").await;
        plan.conn.lock().execute_batch("ALTER TABLE bd1_platform_user_cache RENAME TO platform_user;").expect("fixture : remise");
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })), "{}", r.texte);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");
    }

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle, par le routeur. `rgsc-ana`, administratrice du tenant A,
    /// PAS super-administratrice, s'authentifie par Basic (`GET /api/me` sous A : `200`, l'identité entre au cache
    /// d'authentification) ; puis sa SEULE valeur `is_superadmin` est rendue illisible (BLOB). `POST
    /// /api/sessions/revocation-globale` par Basic sous A rend le `503` nommé, corps exact `{error:
    /// CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE, id}` — un `false` tiré d'une lecture ratée n'est pas un refus de
    /// droit ; époque globale `(0, 0)`, rien d'inscrit. CONTRÔLE : la valeur rendue à l'entier `0`, la même requête rend
    /// le `403` de la réserve.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « S_RG_RELU_BASIC » (Basic exclu de la relecture : le `403` de la réserve servi
    /// sur une valeur illisible).
    #[tokio::test]
    async fn bd1_basic_administrateur_de_tenant_is_superadmin_illisible_nomme_l_autorite_non_lue() {
        let (st, _dir) = bd1_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let plan = st.tenants.control.as_ref().expect("plan");
        let ana = rgsc_basic("rgsc-ana", RGSC_MOT_DE_PASSE);
        let tenant_a = ("x-plume-tenant", RGSC_TENANT_A);
        let me = rgsc_envoyer(addr, "GET", "/api/me", Some(&ana), &[tenant_a], "").await;
        assert_eq!(me.statut, 200, "fixture : ana s'authentifie par Basic : {}", me.texte);
        assert_eq!(plan.conn.lock().execute("UPDATE platform_user SET is_superadmin=X'01' WHERE name='rgsc-ana'", []).expect("fixture"), 1, "fixture : illisible");
        let r = rgsc_envoyer(addr, "POST", BD1_ROUTE_REVOCATION, Some(&ana), &[tenant_a], "").await;
        rgsc_cinq_cent_trois(&r, CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE);
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");

        assert_eq!(plan.conn.lock().execute("UPDATE platform_user SET is_superadmin=0 WHERE name='rgsc-ana'", []).expect("fixture"), 1, "fixture : lisible");
        let r = rgsc_envoyer(addr, "POST", BD1_ROUTE_REVOCATION, Some(&ana), &[tenant_a], "").await;
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_REVOCATION_GLOBALE_RESERVEE })), "contrôle, valeur lisible : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (0, 0), "contrôle : rien n'est révoqué");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.24-e` — L'ORDRE DES REFUS DE LA CRÉATION SOUS UN PLAN DE CONTRÔLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle (l'administrateur de configuration `root` posé), par le
    /// routeur. `rgsc-dan`, administrateur de `default`, par Basic, AVEC le secret des gestes, `POST /api/users` :
    /// chaque corps irrecevable garde SA cause, statut et corps exacts — nom invalide `400`, préfixe `eng-cred-` `400`,
    /// nom de l'administrateur de configuration `409`, nom de la démonstration `409`, mot de passe court `400` ; seul le
    /// corps recevable reçoit le `409` « identité de plateforme ». Aucune ligne posée dans `default`, aucune ligne
    /// `config.user.create` au registre.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « U_UC_AVANT_VALIDATION » (le refus de la plateforme jugé avant la validation :
    /// les cinq corps irrecevables reçoivent `409` « identité de plateforme »).
    #[tokio::test]
    async fn bd1_creation_sous_plan_un_corps_irrecevable_garde_sa_cause() {
        let (mut st, _dir) = bd1_plateforme().await;
        st.user = Arc::new("root".into());
        st.pass_hash = Arc::new(hash_pw(BD1_MOT_DE_PASSE_DE_CONFIGURATION).expect("hachage"));
        let addr = router_serve(st.clone()).await;
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let entetes = [RGSC_JSON, ("x-plume-tenant", "default"), RGSC_SECRET];
        let corps = [
            ("nom invalide!", RGSC_MOT_DE_PASSE_NEUF),
            ("eng-cred-bd1", RGSC_MOT_DE_PASSE_NEUF),
            ("root", RGSC_MOT_DE_PASSE_NEUF),
            ("demo", RGSC_MOT_DE_PASSE_NEUF),
            ("bd1-court", "court"),
            ("bd1-neuf", RGSC_MOT_DE_PASSE_NEUF),
        ];
        let mut servis = Vec::new();
        for (nom, mot) in corps {
            let r = rgsc_envoyer(addr, "POST", "/api/users", Some(&dan), &entetes, &json!({ "name": nom, "password": mot, "role": "viewer" }).to_string()).await;
            servis.push((nom, r.statut, r.corps));
        }
        let attendus = vec![
            ("nom invalide!", 400, json!("nom invalide (alphanumérique, . _ - uniquement)")),
            ("eng-cred-bd1", 400, json!("préfixe 'eng-cred-' réservé aux credentials d'engagement")),
            ("root", 409, json!({ "error": CAUSE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION })),
            ("demo", 409, json!({ "error": CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION })),
            ("bd1-court", 400, json!("mot de passe trop court (≥ 12 caractères)")),
            ("bd1-neuf", 409, json!({ "error": CAUSE_COMPTE_NON_CREE_IDENTITE_DE_PLATEFORME })),
        ];
        assert_eq!(servis, attendus, "chaque corps irrecevable garde sa cause, avant le refus de la plateforme");
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.create"), 0, "rien d'inscrit");
        for nom in ["root", "demo", "bd1-court", "bd1-neuf"] {
            assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM user WHERE name=?1", nom), 0, "aucune ligne {nom}");
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.24-e` — LE RÔLE D'UNE LIGNE DE TENANT SOUS UN PLAN DE CONTRÔLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle, par le routeur, tenant B. Sur la ligne `bd1-cible`
    /// (`editor`) de B, `rgsc-ben` (administrateur de B, Basic) : rétrograder avec le secret des gestes, promouvoir SANS
    /// secret, un rôle invalide ; puis rétrograder un identifiant ABSENT ; puis `bd1-sso-tb`, administrateur de B par ses
    /// groupes (SSO d'en-têtes) : rétrograder. Les cinq gestes rendent `409`, corps exact `{error:
    /// CAUSE_ROLE_NON_CHANGE_IDENTITE_DE_PLATEFORME}` — ni `204`, ni le `403` du secret absent, ni le `400` du rôle
    /// invalide, ni le `404` de la cible absente (aucune lecture : la réponse ne dit pas si l'identifiant existe). Après
    /// eux : le rôle de la ligne est `editor`, aucune ligne `config.user.role_change` ni `secret_des_gestes` au registre de
    /// B ; le droit de la CIBLE sur B (`bd1-cible`, compte de plateforme à droit `editor` posé par la fixture), seul rôle
    /// effectif, est inchangé.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BD1_UU_ROLE_SANS_REFUS » (la forme d'avant : `204`, le rôle de la ligne
    /// écrit) ; « BD1_UU_ROLE_APRES_LECTURE » (le refus jugé après la lecture et la validation : `400` puis `404`) ;
    /// « BE3_GRANT_ECRIT » (vague BE : le refus porté sur le droit de la cible, `grant` réécrit au rôle demandé — l'assertion
    /// d'avant relisait le droit de l'AUTEUR, `rgsc-ben`, qu'aucune implémentation ne touche).
    #[tokio::test]
    async fn bd1_le_role_d_une_ligne_de_tenant_hors_default_est_refuse_avant_toute_lecture() {
        let (st, _dir) = bd1_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne = rgsc_ligne(&st, RGSC_TENANT_B, "bd1-cible", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        {
            let plan = st.tenants.control.as_ref().expect("plan");
            ensure_platform_user(plan, "bd1-cible").expect("fixture : compte de plateforme de la cible");
            plan.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) SELECT id,?1,'editor' FROM platform_user WHERE name='bd1-cible'", params![RGSC_TENANT_B])
                .expect("fixture : droit de la cible");
        }
        assert_eq!(crate::rbac::grant_role_for(&st, "bd1-cible", RGSC_TENANT_B, None).as_deref(), Some("editor"), "fixture : droit de la cible sur B");
        let absente = ligne + 999_999;
        let ben = rgsc_basic("rgsc-ben", RGSC_MOT_DE_PASSE);
        let tenant_b = ("x-plume-tenant", RGSC_TENANT_B);
        let refus = json!({ "error": CAUSE_ROLE_NON_CHANGE_IDENTITE_DE_PLATEFORME });
        let r_retro = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ben), &[RGSC_JSON, tenant_b, RGSC_SECRET], &json!({ "role": "viewer" }).to_string()).await;
        let r_promo = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ben), &[RGSC_JSON, tenant_b], &json!({ "role": "admin" }).to_string()).await;
        let r_invalide = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ben), &[RGSC_JSON, tenant_b], &json!({ "role": "superviseur" }).to_string()).await;
        let r_absente = rgsc_envoyer(addr, "POST", &format!("/api/users/{absente}"), Some(&ben), &[RGSC_JSON, tenant_b], &json!({ "role": "viewer" }).to_string()).await;
        let mut sso = bd1_sso("bd1-sso-tb", "plume-rgscb-admin");
        sso.extend([RGSC_JSON, tenant_b]);
        let r_sso = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), None, &sso, &json!({ "role": "viewer" }).to_string()).await;
        assert_eq!(
            [(r_retro.statut, &r_retro.corps), (r_promo.statut, &r_promo.corps), (r_invalide.statut, &r_invalide.corps), (r_absente.statut, &r_absente.corps), (r_sso.statut, &r_sso.corps)],
            [(409, &refus), (409, &refus), (409, &refus), (409, &refus), (409, &refus)],
            "rétrogradation | promotion sans secret | rôle invalide | cible absente | SSO : {} | {} | {} | {} | {}",
            r_retro.texte,
            r_promo.texte,
            r_invalide.texte,
            r_absente.texte,
            r_sso.texte
        );
        let base_b = rgsc_base(&st, RGSC_TENANT_B);
        let role: String = base_b.lock().query_row("SELECT role FROM user WHERE id=?1", params![ligne], |r| r.get(0)).expect("ligne lue");
        assert_eq!(role, "editor", "le rôle de la ligne n'est pas écrit");
        for kind in ["config.user.role_change", "secret_des_gestes"] {
            assert_eq!(rgsc_compter(&base_b.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", kind), 0, "aucune ligne `{kind}` au registre de B");
        }
        assert_eq!(crate::rbac::grant_role_for(&st, "bd1-cible", RGSC_TENANT_B, None).as_deref(), Some("editor"), "le droit de la CIBLE sur B est inchangé");
    }

    /// CE QU'IL TIENT : mode multi-tenant avec plan de contrôle, par le routeur, tenant `default`. `rgsc-dan`
    /// (administrateur de `default`, Basic) rétrograde la ligne `bd1-defaut` (`editor`) de `default` : `409`, corps exact
    /// `{error: CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET}`, le rôle de la ligne reste `editor`, aucune ligne
    /// `config.user.role_change` au registre de `default`. INVERSÉ par la vague BE (`P10.24-e`) : ce témoin affirmait le
    /// `204` (rôle écrit, inscrit) comme un reste nommé. `bd1-defaut` n'est ni l'administrateur de l'assistant ni une
    /// ligne `admin` : ce changement ne touche aucun des deux faits que le démarrage lit dans la base de `default`, et le
    /// droit effectif est celui du `grant`. Les changements qui ont un effet restent admis (témoins dans
    /// `role_de_default_sous_plan_et_aveu_de_la_creation_sans_base.rs`).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BE3_SANS_REFUS » (la forme d'avant : `204`, rôle écrit).
    #[tokio::test]
    async fn bd1_le_role_d_une_ligne_du_tenant_default_sans_effet_est_refuse_sous_plan() {
        let (st, _dir) = bd1_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne = rgsc_ligne(&st, "default", "bd1-defaut", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&dan), &[RGSC_JSON, ("x-plume-tenant", "default")], &json!({ "role": "viewer" }).to_string()).await;
        assert_eq!((r.statut, &r.corps), (409, &json!({ "error": CAUSE_ROLE_NON_CHANGE_LIGNE_DE_DEFAULT_SANS_EFFET })), "default : {}", r.texte);
        let role: String = st.db.lock().query_row("SELECT role FROM user WHERE id=?1", params![ligne], |r| r.get(0)).expect("ligne lue");
        assert_eq!(role, "editor", "default : le rôle de la ligne n'est pas écrit");
        assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.role_change"), 0, "default : rien n'est inscrit");
    }

    /// CE QU'IL TIENT : mode multi-tenant DÉGRADÉ (`multi_tenant` vrai, AUCUN plan de contrôle : toute base de tenant est
    /// `st.db`, `TenantDbManager::handle_for`), par le routeur. `bd1-carol`, administratrice du tenant `bd1x` par ses
    /// groupes (`plume-bd1x-admin`), rétrograde la ligne `bd1-alice` (`editor`) sous `bd1x` : `204`, le rôle de la ligne
    /// est `viewer` — sans plan de contrôle, l'identité est la base unique et le rôle de la ligne est celui que la session
    /// lit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BD1_UU_ROLE_SANS_PLAN » (le refus pris sans le plan de contrôle : `409`).
    #[tokio::test]
    async fn bd1_sans_plan_de_controle_le_role_d_une_ligne_se_change_hors_default() {
        let (mut st, _p) = router_test_state("bd1-degrade-role");
        st.sso_secret = Arc::new(BD1_SECRET_SSO.into());
        st.installation_ouverte.store(false, Ordering::SeqCst);
        st.multi_tenant = true;
        assert!(st.tenants.control.is_none(), "fixture : aucun plan de contrôle");
        let ligne = {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('bd1-alice',?1,'editor')", params![hash_pw(RGSC_MOT_DE_PASSE).expect("hachage")]).expect("fixture : compte");
            c.last_insert_rowid()
        };
        let addr = router_serve(st.clone()).await;
        let mut sso = bd1_sso("bd1-carol", "plume-bd1x-admin");
        sso.extend([RGSC_JSON, ("x-plume-tenant", "bd1x")]);
        let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), None, &sso, &json!({ "role": "viewer" }).to_string()).await;
        assert_eq!(r.statut, 204, "sans plan de contrôle : {}", r.texte);
        let role: String = st.db.lock().query_row("SELECT role FROM user WHERE id=?1", params![ligne], |r| r.get(0)).expect("ligne lue");
        assert_eq!(role, "viewer", "sans plan de contrôle : le rôle de la ligne est écrit");
    }

    /// CE QU'IL TIENT (`P10.24-e`, la clause « un rôle est demandé » du refus neuf) : mode multi-tenant avec plan de
    /// contrôle, par le routeur, tenant B. `rgsc-ben` (administrateur de B, Basic) envoie sur la ligne `bd1-vide`
    /// (`editor`) de B un corps qui ne demande NI rôle NI mot de passe — `{}`, puis `{"role": null, "password": "  "}`
    /// (rôle non textuel, mot de passe blanc : ni l'un ni l'autre n'est demandé) : `204` chacun, le rôle de la ligne reste
    /// `editor`, aucune ligne `config.user.role_change` au registre de B. Le même corps `{}` sur un identifiant ABSENT rend
    /// le `404` de la lecture (`compte introuvable`) : sans rôle demandé, le refus ne s'applique pas et la cible est lue.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BD1_UU_ROLE_SANS_CORPS » (la clause `new_role.is_some()` retirée : les trois
    /// corps reçoivent le `409` « RÔLE NON CHANGÉ » d'un rôle que personne n'a demandé).
    #[tokio::test]
    async fn bd1_un_corps_sans_role_hors_default_garde_la_lecture_et_son_204_sans_effet() {
        let (st, _dir) = bd1_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne = rgsc_ligne(&st, RGSC_TENANT_B, "bd1-vide", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let absente = ligne + 999_999;
        let ben = rgsc_basic("rgsc-ben", RGSC_MOT_DE_PASSE);
        let entetes = [RGSC_JSON, ("x-plume-tenant", RGSC_TENANT_B)];
        let r_vide = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ben), &entetes, "{}").await;
        let r_blanc = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&ben), &entetes, &json!({ "role": null, "password": "  " }).to_string()).await;
        let r_absente = rgsc_envoyer(addr, "POST", &format!("/api/users/{absente}"), Some(&ben), &entetes, "{}").await;
        assert_eq!(
            [r_vide.statut, r_blanc.statut, r_absente.statut],
            [204, 204, 404],
            "corps vide | rôle nul et mot de passe blanc | cible absente : {} | {} | {}",
            r_vide.texte,
            r_blanc.texte,
            r_absente.texte
        );
        assert_eq!(r_absente.corps, json!("compte introuvable"), "cible absente : le 404 de la lecture, corps exact : {}", r_absente.texte);
        let base_b = rgsc_base(&st, RGSC_TENANT_B);
        let role: String = base_b.lock().query_row("SELECT role FROM user WHERE id=?1", params![ligne], |r| r.get(0)).expect("ligne lue");
        assert_eq!(role, "editor", "aucun rôle demandé, aucun écrit");
        assert_eq!(rgsc_compter(&base_b.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "config.user.role_change"), 0, "rien d'inscrit au registre de B");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.31-i` — LES LIGNES DE JOURNAL DE L'AUTORITÉ NON LUE, AUX DEUX PORTES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : les deux lignes `[session] WARN` servies quand le super-administrateur n'a pas pu être relu dans le
    /// plan de contrôle, lues sur le stderr d'un sous-processus, chacune ENTIÈRE. Mode multi-tenant avec plan de contrôle,
    /// par le routeur : `rgsc-sa` se connecte, puis sa SEULE valeur `is_superadmin` est rendue illisible (BLOB). Phase
    /// `logout` : `POST /api/logout` sous la portée `globale` par son cookie rend `503` et écrit EXACTEMENT
    /// `[session] WARN déconnexion globale refusée : le super-administrateur n'a pas pu être relu dans le plan de contrôle
    /// (<constat>)`. Phase `revocation` : `POST /api/sessions/revocation-globale` sous A (cookie et jeton CSRF) rend `503`
    /// et écrit EXACTEMENT `[session] WARN révocation globale refusée : … (<constat>)`. `<constat>` est la cause rendue par
    /// `rbac::platform_user_superadmin_lu` sur la même valeur. Aucune ligne `[session]` de la phase ne nomme le compte
    /// (`rgsc-sa`) : la ligne dit l'échec et sa cause, jamais qui appelait (`P10.31-u`).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « BD1_LOG_LOGOUT_MUET » (la ligne de `logout_post` retirée) ;
    /// « BD1_LOG_REVOCATION_MUET » (celle de `revocation_globale_post` retirée) ; « BD1_LOG_REVOCATION_NOMME » (celle de
    /// `revocation_globale_post` nomme l'appelant).
    #[tokio::test]
    async fn bd1_journal_de_l_autorite_non_lue_aux_deux_portes_entier_et_sans_nom() {
        const ENFANT: &str = "BD1_ENFANT_JOURNAL_AUTORITE";
        const PHASE: &str = "BD1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les mutants lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _dir) = bd1_plateforme().await;
            let addr = router_serve(st.clone()).await;
            let sa = super::revocation_globale_sans_cookie_et_comptes_du_mode_un::rgsc_connexion(addr, "rgsc-sa").await;
            let plan = st.tenants.control.as_ref().expect("plan");
            assert_eq!(plan.conn.lock().execute("UPDATE platform_user SET is_superadmin=X'01' WHERE name='rgsc-sa'", []).expect("fixture"), 1, "fixture : illisible");
            let constat = crate::rbac::platform_user_superadmin_lu(&st, "rgsc-sa").expect_err("fixture : valeur illisible");
            let (cookie, csrf) = (format!("plume_session={sa}"), csrf_for(st.session_secret.as_slice(), &sa));
            let entetes = [("Cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str()), ("x-plume-tenant", RGSC_TENANT_A)];
            eprintln!("{PHASE}logout");
            let porte_1 = super::revocation_globale_sans_cookie_et_comptes_du_mode_un::rgsc_deconnexion_globale(addr, &sa).await;
            eprintln!("{PHASE}revocation");
            let porte_2 = rgsc_envoyer(addr, "POST", BD1_ROUTE_REVOCATION, None, &entetes, "").await;
            eprintln!("{PHASE}fin");
            println!("BD1-STATUTS:{}:{}", porte_1.statut, porte_2.statut);
            println!("BD1-CONSTAT:{}", json!(constat));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::relecture_par_methode_ordre_de_la_creation_et_role_d_une_ligne_de_tenant::bd1_journal_de_l_autorite_non_lue_aux_deux_portes_entier_et_sans_nom",
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
        assert_eq!(marque("BD1-STATUTS:"), "503:503", "contrôle : les deux portes servent le 503 de l'autorité non lue");
        let constat: String = serde_json::from_str(&marque("BD1-CONSTAT:")).expect("contrôle : constat");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[session]")).map(str::to_string).collect()
        };
        let attendues = [
            ("logout", vec![format!("[session] WARN déconnexion globale refusée : le super-administrateur n'a pas pu être relu dans le plan de contrôle ({constat})")]),
            ("revocation", vec![format!("[session] WARN révocation globale refusée : le super-administrateur n'a pas pu être relu dans le plan de contrôle ({constat})")]),
        ];
        for (nom, lignes) in &attendues {
            let lues = phase(nom);
            assert_eq!(&lues, lignes, "phase {nom} : la ligne entière, une fois");
            assert!(lues.iter().all(|l| !l.contains("rgsc-sa")), "phase {nom} : la ligne ne nomme pas le compte : {lues:?}");
        }
    }
}
