// =====================================================================================
// `P10.31-i` (témoins après vérification) — LE SUPER-ADMINISTRATEUR RELU DANS `platform_user` : COMPTE ABSENT = REFUS DE
// DROIT, LECTURE RATÉE = AUCUN SUPER-ADMINISTRATEUR.
//
// `rbac::platform_user_superadmin_lu` rend `Ok(false)` pour un compte ABSENT de `platform_user` (l'administrateur de
// l'assistant, qui ouvre une session par le repli de `state::lookup_basic_ident_lu` sans ligne de plateforme) et
// `Err(constat)` pour une lecture ratée. L'enveloppe `rbac::platform_user_is_superadmin` (`unwrap_or(false)`) sert deux
// appelants : `rbac::resolve_tenant_access` (accès inter-tenants, et `au.is_superadmin` que juge
// `session::revocation_globale_post`) et `auth::resolve_tenant_and_role` pour les routes de gestion des tenants.
//
// Deux cas n'avaient aucun témoin (mutants verts relevés par le vérificateur de la vague précédente) :
//  * le compte absent rendu `Err` : la portée `globale` de `POST /api/logout` servirait à l'administrateur de l'assistant
//    le `503` AUTORITÉ NON LUE au lieu du `403` du refus de droit ;
//  * le repli permissif de l'enveloppe (`unwrap_or(true)`) : `platform_user` illisible, tout porteur de cookie deviendrait
//    super-administrateur — accès inter-tenants, révocation globale par l'administratrice d'UN tenant, liste des tenants.
//
// L'illisibilité est posée de deux façons : la table renommée (toutes les lectures de `platform_user` ratent), et la
// SEULE valeur `is_superadmin` du compte rendue illisible (un BLOB : `r.get::<_, i64>` échoue, les droits du compte
// restent lisibles — le compte reste membre de ses tenants).
//
// MUTANTS JOUÉS (posés sous cfg!(test), retirés avant le commit), chacun vu ROUGE : `R1_ABSENT_ERR` (ligne absente -> `Err`) ;
// `R3_ENVELOPPE_PERMISSIVE` (`unwrap_or(true)` dans l'enveloppe) ; `R3_SITE_RBAC148` (le repli permissif au seul appel
// de `resolve_tenant_access`) ; `R3_SITE_AUTH1794` (le repli permissif au seul appel des routes de gestion).
// =====================================================================================
mod super_administrateur_absent_ou_illisible_sans_repli_permissif {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{
        rgsc_connexion, rgsc_deconnexion_globale, rgsc_envoyer, rgsc_epoques, rgsc_me, rgsc_plateforme, rgsc_traces_globales, RGSC_MOT_DE_PASSE,
        RGSC_TENANT_A,
    };
    use super::*;

    const SAR_ROUTE_REVOCATION: &str = "/api/sessions/revocation-globale";
    /// Le refus de `resolve_tenant_access` pour un non-membre qui n'est pas super-administrateur (texte brut).
    const SAR_AUCUN_ACCES: &str = "aucun accès à ce tenant (grant requis)";
    /// Le refus de `tenant_mgmt_gate` pour un non-super-administrateur sur `GET /api/tenants` (texte brut).
    const SAR_GESTION_RESERVEE: &str = "gestion des tenants réservée au super-admin plateforme";

    /// `GET` sous le cookie `jeton` (et un tenant), au routeur : statut et corps.
    async fn sar_get(addr: std::net::SocketAddr, chemin: &str, jeton: &str, tenant: Option<&str>) -> (u16, Value, String) {
        let cookie = format!("plume_session={jeton}");
        let mut entetes = vec![("Cookie", cookie.as_str())];
        if let Some(t) = tenant {
            entetes.push(("x-plume-tenant", t));
        }
        let r = rgsc_envoyer(addr, "GET", chemin, None, &entetes, "").await;
        (r.statut, r.corps, r.texte)
    }

    /// La SEULE valeur `is_superadmin` de `nom` rendue illisible (BLOB), ou rendue à l'entier `valeur`.
    fn sar_poser_is_superadmin(st: &AppState, nom: &str, valeur: Option<i64>) {
        let plan = st.tenants.control.as_ref().expect("fixture : plan de contrôle");
        let c = plan.conn.lock();
        let n = match valeur {
            None => c.execute("UPDATE platform_user SET is_superadmin=X'01' WHERE name=?1", params![nom]),
            Some(v) => c.execute("UPDATE platform_user SET is_superadmin=?1 WHERE name=?2", params![v, nom]),
        }
        .expect("fixture : is_superadmin posé");
        assert_eq!(n, 1, "fixture : une ligne {nom}");
        if valeur.is_none() {
            let genre: String = c.query_row("SELECT typeof(is_superadmin) FROM platform_user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : genre lu");
            assert_eq!(genre, "blob", "fixture : la valeur est illisible comme entier");
        }
    }

    /// CE QU'IL TIENT (`R1`) : mode multi-tenant avec plan de contrôle, `POST /api/logout` sous la portée `globale`, au
    /// routeur. `rgsc-wiz`, administrateur de l'assistant (`st.admin`), n'a AUCUNE ligne dans `platform_user` : sa session
    /// ouvre par le repli ; la portée globale rend `403`, corps exact `{error: CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN}`
    /// — un refus de droit, pas le `503` AUTORITÉ NON LUE —, aucun cookie effacé, rien de révoqué ni d'inscrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « R1_ABSENT_ERR » (la ligne absente rendue `Err` : `503`).
    #[tokio::test]
    async fn sar_compte_absent_de_la_plateforme_refus_de_droit() {
        let (st, _dir) = rgsc_plateforme().await;
        *st.admin.lock() = Some(("rgsc-wiz".into(), hash_pw(RGSC_MOT_DE_PASSE).expect("hachage")));
        let lignes: i64 = st.tenants.control.as_ref().expect("plan").conn.lock().query_row("SELECT COUNT(*) FROM platform_user WHERE name='rgsc-wiz'", [], |r| r.get(0)).expect("fixture : compte");
        assert_eq!(lignes, 0, "fixture : rgsc-wiz est absent de platform_user");
        let addr = router_serve(st.clone()).await;
        let wiz = rgsc_connexion(addr, "rgsc-wiz").await;
        let r = rgsc_deconnexion_globale(addr, &wiz).await;
        assert_eq!((r.statut, &r.corps), (403, &json!({ "error": CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN })), "{}", r.texte);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");
    }

    /// CE QU'IL TIENT (`R3`, `resolve_tenant_access`, table entière) : `rgsc-ana` (administratrice de A, éditrice de B,
    /// pas super-administratrice) par son cookie. Avant : `200` dans A, `403` dans `default` dont elle n'est pas membre.
    /// `platform_user` renommée : `GET /api/me` sous `default` rend `403`, corps exact SAR_AUCUN_ACCES — pas l'accès
    /// inter-tenants (lecteur) du super-administrateur.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « R3_ENVELOPPE_PERMISSIVE » et « R3_SITE_RBAC148 » (`200` dans `default`).
    #[tokio::test]
    async fn sar_platform_user_illisible_pas_d_acces_inter_tenants() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        assert_eq!(rgsc_me(addr, &ana, Some(RGSC_TENANT_A)).await, 200, "fixture");
        assert_eq!(rgsc_me(addr, &ana, Some("default")).await, 403, "fixture : non membre de default");
        let plan = st.tenants.control.as_ref().expect("plan");
        plan.conn.lock().execute_batch("ALTER TABLE platform_user RENAME TO platform_user_ecartee_sar").expect("fixture : illisible");
        let (statut, corps, texte) = sar_get(addr, "/api/me", &ana, Some("default")).await;
        plan.conn.lock().execute_batch("ALTER TABLE platform_user_ecartee_sar RENAME TO platform_user").expect("fixture : rendue");
        assert_eq!((statut, &corps), (403, &json!(SAR_AUCUN_ACCES)), "platform_user illisible : ana n'entre pas dans default : {texte}");
    }

    /// CE QU'IL TIENT (`R3`, `resolve_tenant_access`, la SEULE valeur `is_superadmin` illisible) : `rgsc-ana` reste membre
    /// de A (`/api/me` `200` sous A). Sous `default` : `403`, corps exact SAR_AUCUN_ACCES. `POST
    /// /api/sessions/revocation-globale` sous A, par son cookie et son jeton CSRF : `503`, cause
    /// `CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE` — l'autorité n'est pas jugée, comme par l'autre porte (`logout_post`),
    /// et l'administratrice d'UN tenant ne révoque pas les sessions des autres —, rien de révoqué ni d'inscrit. CONTRÔLE POSITIF, la même valeur rendue à l'entier `1` : `/api/me` sous `default` rend
    /// `200` (la requête distingue bien le super-administrateur).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « R3_ENVELOPPE_PERMISSIVE » et « R3_SITE_RBAC148 » (`200` sous `default`, et la
    /// révocation globale `200` de toutes les sessions, époque avancée et inscrite).
    #[tokio::test]
    async fn sar_is_superadmin_illisible_ni_inter_tenants_ni_revocation_globale() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        assert_eq!(rgsc_me(addr, &ana, Some("default")).await, 403, "fixture : non membre de default");
        sar_poser_is_superadmin(&st, "rgsc-ana", None);
        assert_eq!(rgsc_me(addr, &ana, Some(RGSC_TENANT_A)).await, 200, "fixture : ses droits restent lisibles, membre de A");

        // Les deux gestes sont joués AVANT tout jugement, puis jugés ensemble : sous un mutant, le message montre l'un ET
        // l'autre (l'accès inter-tenants servi ET la révocation globale faite).
        let (statut_me, corps_me, texte_me) = sar_get(addr, "/api/me", &ana, Some("default")).await;
        let (cookie, csrf) = (format!("plume_session={ana}"), csrf_for(st.session_secret.as_slice(), &ana));
        let r = rgsc_envoyer(addr, "POST", SAR_ROUTE_REVOCATION, None, &[("Cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str()), ("x-plume-tenant", RGSC_TENANT_A)], "").await;
        assert_eq!(
            ((statut_me, &corps_me), (r.statut, &r.corps["error"]), rgsc_epoques(&st), rgsc_traces_globales(&st).len()),
            ((403, &json!(SAR_AUCUN_ACCES)), (503, &json!(CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE)), (0, 0), 0),
            "is_superadmin illisible : ni accès inter-tenants, ni révocation globale (rien de révoqué ni d'inscrit) : {texte_me} | {}",
            r.texte
        );

        sar_poser_is_superadmin(&st, "rgsc-ana", Some(1));
        let (statut, _, texte) = sar_get(addr, "/api/me", &ana, Some("default")).await;
        assert_eq!(statut, 200, "contrôle positif : super-administratrice lisible, accès inter-tenants : {texte}");
    }

    /// CE QU'IL TIENT (`R3`, `auth::resolve_tenant_and_role`, routes de gestion des tenants) : `rgsc-ana` par son cookie,
    /// `GET /api/tenants`. Avant : `403`. La SEULE valeur `is_superadmin` illisible : `403`, corps exact
    /// SAR_GESTION_RESERVEE ; `platform_user` renommée : `403`, même corps. CONTRÔLE POSITIF, la valeur rendue à l'entier
    /// `1` : `200`, la liste nomme le tenant A.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : « R3_ENVELOPPE_PERMISSIVE » et « R3_SITE_AUTH1794 » (`200`, la liste de tous
    /// les tenants servie, dans les deux illisibilités).
    #[tokio::test]
    async fn sar_platform_user_illisible_pas_de_gestion_des_tenants() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        let refus = json!(SAR_GESTION_RESERVEE);
        let (statut, corps, texte) = sar_get(addr, "/api/tenants", &ana, None).await;
        assert_eq!((statut, &corps), (403, &refus), "fixture : ana n'est pas super-administratrice : {texte}");

        // Les deux illisibilités sont jouées AVANT tout jugement, puis jugées ensemble : sous un mutant, le message montre
        // l'une ET l'autre.
        sar_poser_is_superadmin(&st, "rgsc-ana", None);
        let (statut_blob, corps_blob, texte_blob) = sar_get(addr, "/api/tenants", &ana, None).await;
        sar_poser_is_superadmin(&st, "rgsc-ana", Some(0));
        let plan = st.tenants.control.as_ref().expect("plan");
        plan.conn.lock().execute_batch("ALTER TABLE platform_user RENAME TO platform_user_ecartee_sar").expect("fixture : illisible");
        let (statut_table, corps_table, texte_table) = sar_get(addr, "/api/tenants", &ana, None).await;
        plan.conn.lock().execute_batch("ALTER TABLE platform_user_ecartee_sar RENAME TO platform_user").expect("fixture : rendue");
        assert_eq!(
            ((statut_blob, &corps_blob), (statut_table, &corps_table)),
            ((403, &refus), (403, &refus)),
            "is_superadmin illisible : {texte_blob} | platform_user illisible : {texte_table}"
        );

        sar_poser_is_superadmin(&st, "rgsc-ana", Some(1));
        let (statut, corps, texte) = sar_get(addr, "/api/tenants", &ana, None).await;
        assert_eq!(statut, 200, "contrôle positif : {texte}");
        let ids: Vec<&str> = corps["tenants"].as_array().map(|v| v.iter().filter_map(|t| t["id"].as_str()).collect()).unwrap_or_default();
        assert!(ids.contains(&RGSC_TENANT_A), "contrôle positif : la liste nomme A : {texte}");
    }
}
