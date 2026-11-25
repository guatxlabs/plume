// =====================================================================================
// `P10.20-b` — UNE LECTURE D'UNE LIGNE QUI N'A PAS EU LIEU NE DÉCIDE NI D'UN ACCÈS, NI D'UN TENANT, NI D'UNE
// ÉCRITURE, NI D'UN REJEU DE LA CHAÎNE DE MIGRATIONS.
//
// LE DÉFAUT, LU SUR LA BASE AVANT LE CORRECTIF. Hors de `handlers/`, sept lectures d'une ligne qui DÉCIDENT
// confondaient « aucune ligne » et « lecture ratée » par `.ok()` ou `.is_ok()` :
//   * `state::resolve_user_tenant` (trois lectures : le compte de plateforme, le droit sur le tenant demandé,
//     le premier droit) : une lecture ratée valait « aucun droit », servie en 403 « aucun accès à ce tenant »
//     par `rbac::resolve_tenant_access` et en rôle « viewer » (ou « admin » pour un super-administrateur) par
//     `rbac::mgmt_grants_role` sur les routes de gestion des droits ;
//   * `state::TenantDbManager::catalog_route` : une ligne de catalogue non lue valait « tenant absent »,
//     servie en 403 « tenant inconnu ou indisponible » (accès inter-tenants) et « tenant indisponible (base
//     non résoluble) » (porte d'entrée d'`auth_guard`) ;
//   * `tenants::tenant_delete` : un nom non lu valait « tenant inconnu » (404) ;
//   * `tenants::tenant_provision` : une existence non lue valait « identifiant libre », et la transaction
//     poursuivait jusqu'à l'effacement de ce qui restait sous l'identifiant ;
//   * `migrate::migrate_chain` : une estampille illisible (BLOB, valeur non entière) valait « un », et la
//     chaîne ENTIÈRE se rejouait sur une base à jour ; et `migrate::prepare_schema`, appelé hors de la porte
//     sur une base dont `meta` a disparu, laissait `db/schema.sql` recréer une table `meta` portant « 1 » —
//     une estampille parfaitement LUE et fausse — avant de rejouer la même chaîne.
//
// LA FORME DES CORRECTIFS est celle du dépôt : `.optional()` pour que l'absence reste un fait, un 503 NOMMÉ
// pour la lecture ratée (jamais un 403 ni un 404 : ce n'est ni un droit ni une absence), sans le texte du
// moteur, dans le corps `{error, id}` que la console lit ; pour la chaîne, la lecture de la porte
// (`lire_l_estampille_de_schema`) et aucune étape jouée.
//
// LES VOIES D'ÉCHEC : la TABLE RETIRÉE (renommée le temps du geste), la LIGNE ILLISIBLE (un BLOB dans une
// colonne lue en TEXT : la requête est saine, seul le mappeur échoue), une VUE TEMPORAIRE qui échoue à
// l'exécution (`json_each` d'un texte qui n'est pas du JSON) ; pour l'estampille, un BLOB et un texte non entier.
// Chaque témoin porte son contrôle positif (absence établie et lecture réussie servent la sortie d'avant).
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` et `VERIF_MUT`, retirés avant le commit), chacun vu rouge seul :
// `CJ1_UID`, `CJ1_DEMANDE`, `CJ1_DEFAUT` (chaque lecture de `resolve_user_tenant` rendue à l'absence) ;
// `CJ1_ROLE_RBAC`, `CJ1_DEFAUT_RBAC` (le bras `Err` de `resolve_tenant_access` lu comme « aucun droit ») ;
// `CJ1_GESTION` (le repli non-membre de `mgmt_grants_role` repris sur une lecture ratée) ; `CJ1_CATALOGUE`
// (la ligne du catalogue rendue à l'absence) ; `CJ1_CATALOGUE_RBAC`, `CJ1_CATALOGUE_AUTH` (le bras `Err` de
// chaque porte servi en 403) ; `CJ1_DESTRUCTION`, `CJ1_PROVISION` (les deux gestes de `tenants.rs`) ;
// `CJ1_CHAINE` (la version de la chaîne retombant sur « un ») ; `CJ1_CONTRAT` (le contrôle d'entrée de
// `prepare_schema` retiré) ; `CJ1_TEXTE_NU` (le 503 de `resolve_tenant_access` rendu en texte nu par
// `auth::resolve_tenant_and_role`, que la console prendrait pour une panne de passerelle — tenu par le témoin
// inversé `sar_platform_user_illisible_pas_d_acces_inter_tenants`, par la route).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : `TenantDbManager::ready` garde `None` pour une ligne de catalogue non
// lue comme pour un tenant absent (fail-closed, rien n'est routé, aucune ligne de journal) — la cause est
// servie en amont par les deux portes témoignées ici, et un job de fond qui passerait par `ready` saute le
// tenant sans le dire ; `migrate_step` relit encore la version d'avant l'étape par `read_schema_version` (une
// lecture ratée ENTRE deux étapes ferait réécrire « 1 » par `restore_schema_version` si l'étape échouait
// ensuite : double panne non fabriquée ici, la fonction est privée au module) ; le message de
// `prepare_schema` sur une chaîne interrompue cite `read_schema_version`, qui DÉCRIT et peut dire « 1 ».
// =====================================================================================
mod lectures_d_une_ligne_du_plan_de_controle_et_de_l_estampille {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{rgsc_connexion, rgsc_envoyer, rgsc_plateforme, RGSC_TENANT_A};
    use super::*;

    const CJ1_A: &str = "cj1-a";
    const CJ1_C: &str = "cj1-c";
    const CJ1_AUCUN_ACCES: &str = "aucun accès à ce tenant (grant requis)";
    const CJ1_AUCUN_TENANT: &str = "aucun tenant accessible (grant requis)";
    const CJ1_TENANT_INDISPONIBLE: &str = "tenant inconnu ou indisponible";
    /// Les deux phrases fixes des refus neufs, écrites ici en toutes lettres : le témoin ne compare jamais une
    /// sortie de la production à elle-même.
    const CJ1_DROITS_NON_LUS: &str = "DROITS DU COMPTE NON LUS : le plan de contrôle n'a pas pu lire le compte de \
         plateforme ou ses droits sur les tenants — ce n'est PAS « aucun droit » : l'accès n'est ni accordé ni refusé \
         sur cette lecture. Réessayez une fois le plan de contrôle de nouveau lisible.";
    const CJ1_CATALOGUE_NON_LU: &str = "CATALOGUE DES TENANTS NON LU : le plan de contrôle n'a pas pu lire la ligne \
         du tenant demandé — ce n'est PAS « tenant inconnu ou indisponible » : son existence n'est ni affirmée ni \
         niée, et aucune base n'est servie. Réessayez une fois le plan de contrôle de nouveau lisible.";
    const CJ1_DESTRUCTION_NON_LUE: &str = "TENANT NON DÉTRUIT : le plan de contrôle n'a pas pu lire le tenant visé \
         avant la destruction — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. RIEN n'est \
         détruit ni tracé : le tenant et sa base sont intacts. Réessayez une fois le plan de contrôle de nouveau lisible.";
    const CJ1_EXISTENCE_NON_LUE: &str = "TENANT NON CRÉÉ : le plan de contrôle n'a pas pu lire si un tenant porte \
         déjà cet identifiant — RIEN n'est créé ni effacé : ni ligne au catalogue, ni base chiffrée. Ce n'est PAS \
         « tenant existant » ni « identifiant libre ». Réessayez une fois le plan de contrôle de nouveau lisible.";

    type Cj1Acces = Result<(String, String, bool, bool), (u16, String)>;

    /// Un plan de contrôle avec deux tenants catalogués (`cj1-a`, `cj1-c`, sans base), `cj1-ana` éditrice de A,
    /// `cj1-op` super-administrateur sans aucun droit, `cj1-stranger` sans compte de plateforme.
    fn cj1_etat() -> (AppState, crate::tmp_possede::TmpDb) {
        let (cp, tmp) = mk_test_control();
        let ana = ensure_platform_user(&cp, "cj1-ana").expect("fixture : compte de plateforme");
        ensure_platform_user(&cp, "cj1-op").expect("fixture : compte de plateforme");
        {
            let c = cp.conn.lock();
            for t in [CJ1_A, CJ1_C] {
                c.execute(
                    "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?1,'','sans-base',?2,0)",
                    params![t, now()],
                )
                .expect("fixture : tenant catalogué");
            }
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![ana, CJ1_A])
                .expect("fixture : droit posé");
            c.execute("UPDATE platform_user SET is_superadmin=1 WHERE name='cj1-op'", []).expect("fixture : super-administrateur");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp)
    }

    fn cj1_plan(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cj1_compte(st: &AppState, sql: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// L'ACCÈS TEL QUE LE RÉSOUT `auth_guard` à chaque requête Basic ou cookie en mode 1.
    fn cj1_acces(st: &AppState, nom: &str, demande: Option<&str>) -> Cj1Acces {
        resolve_tenant_access(st, nom, None, false, demande, false, None)
            .map(|a| (a.tenant, a.role, a.is_superadmin, a.cross_tenant))
            .map_err(|(code, msg)| (code.as_u16(), msg))
    }

    fn cj1_acces_attendu(tenant: &str, role: &str, sa: bool, inter: bool) -> Cj1Acces {
        Ok((tenant.to_string(), role.to_string(), sa, inter))
    }

    fn cj1_refus(code: u16, msg: &str) -> Cj1Acces {
        Err((code, msg.to_string()))
    }

    /// Le corps d'un 5xx `err_json` : EXACTEMENT `error` et `id`, la cause égale à la phrase attendue.
    fn cj1_cinq_cent_trois(quoi: &str, statut: u16, v: &Value, cause: &str) {
        assert_eq!(statut, 503, "{quoi} : une lecture NON FAITE est un 503 nommé : {v}");
        let cles: std::collections::BTreeSet<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"].into_iter().collect(), "{quoi} : corps entier : {v}");
        assert_eq!(v["error"], json!(cause), "{quoi} : SA cause, sans le texte du moteur : {v}");
    }

    // -------------------------------------------------------------------------------------
    // (1) `resolve_user_tenant` — le compte de plateforme.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le compte de plateforme de `cj1-ana` non lu — table retirée, puis `id` illisible par une VUE
    /// temporaire qui le projette en BLOB —, l'accès au tenant DEMANDÉ et l'accès par DÉFAUT rendent tous deux `503`
    /// CJ1_DROITS_NON_LUS, jamais le 403 « aucun accès ». Contrôle positif : la table remise, ana entre dans A en
    /// éditrice (demandé et défaut) ; un compte ABSENT garde ses deux 403 d'avant, mot pour mot.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_UID` (403 « aucun accès » / « aucun tenant accessible »), et les deux
    /// bras de `resolve_tenant_access` que le compte non lu traverse (`CJ1_ROLE_RBAC`, `CJ1_DEFAUT_RBAC`).
    #[test]
    fn cj1_compte_de_plateforme_non_lu_est_un_503_nomme_sur_les_deux_chemins() {
        let (st, _tmp) = cj1_etat();
        assert_eq!(cj1_acces(&st, "cj1-ana", Some(CJ1_A)), cj1_acces_attendu(CJ1_A, "editor", false, false), "contrôle : demandé");
        assert_eq!(cj1_acces(&st, "cj1-ana", None), cj1_acces_attendu(CJ1_A, "editor", false, false), "contrôle : défaut");
        assert_eq!(cj1_acces(&st, "cj1-stranger", Some(CJ1_A)), cj1_refus(403, CJ1_AUCUN_ACCES), "absence établie : demandé");
        assert_eq!(cj1_acces(&st, "cj1-stranger", None), cj1_refus(403, CJ1_AUCUN_TENANT), "absence établie : défaut");

        for (voie, pose, remise) in [
            ("table retirée", "ALTER TABLE platform_user RENAME TO cj1_platform_user;", "ALTER TABLE cj1_platform_user RENAME TO platform_user;"),
            (
                "ligne illisible",
                "ALTER TABLE platform_user RENAME TO cj1_platform_user; CREATE TEMP VIEW platform_user AS \
                 SELECT CAST(id AS BLOB) AS id, name, hash, is_superadmin, created FROM cj1_platform_user;",
                "DROP VIEW temp.platform_user; ALTER TABLE cj1_platform_user RENAME TO platform_user;",
            ),
        ] {
            cj1_plan(&st, pose);
            let demande = cj1_acces(&st, "cj1-ana", Some(CJ1_A));
            let defaut = cj1_acces(&st, "cj1-ana", None);
            cj1_plan(&st, remise);
            assert_eq!(demande, cj1_refus(503, CJ1_DROITS_NON_LUS), "{voie} : demandé");
            assert_eq!(defaut, cj1_refus(503, CJ1_DROITS_NON_LUS), "{voie} : défaut");
        }
        assert_eq!(cj1_acces(&st, "cj1-ana", Some(CJ1_A)), cj1_acces_attendu(CJ1_A, "editor", false, false), "remis : l'accès revient");
    }

    // -------------------------------------------------------------------------------------
    // (2) `resolve_user_tenant` — le droit sur le tenant DEMANDÉ, puis le PREMIER droit.
    // -------------------------------------------------------------------------------------

    /// Les deux voies des lectures de `grant` : (nom, pose, remise).
    fn cj1_voies_du_droit() -> [(&'static str, String, String); 2] {
        [
            ("table retirée", "ALTER TABLE \"grant\" RENAME TO cj1_grant;".into(), "ALTER TABLE cj1_grant RENAME TO \"grant\";".into()),
            (
                "ligne illisible",
                format!("UPDATE \"grant\" SET role=X'00' WHERE tenant_id='{CJ1_A}';"),
                format!("UPDATE \"grant\" SET role='editor' WHERE tenant_id='{CJ1_A}';"),
            ),
        ]
    }

    /// CE QU'IL TIENT : le droit de `cj1-ana` sur A non lu (table retirée, `role` en BLOB), l'accès DEMANDÉ à A rend
    /// `503` CJ1_DROITS_NON_LUS ; le compte de plateforme, lui, reste lisible. Contrôle positif : remis, éditrice.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_DEMANDE` (la lecture rendue à l'absence) et `CJ1_ROLE_RBAC` (le bras
    /// `Err` de `resolve_tenant_access` lu comme « aucun droit ») — 403 « aucun accès à ce tenant ».
    #[test]
    fn cj1_droit_demande_non_lu_est_un_503_nomme() {
        let (st, _tmp) = cj1_etat();
        for (voie, pose, remise) in cj1_voies_du_droit() {
            cj1_plan(&st, &pose);
            let r = cj1_acces(&st, "cj1-ana", Some(CJ1_A));
            cj1_plan(&st, &remise);
            assert_eq!(r, cj1_refus(503, CJ1_DROITS_NON_LUS), "{voie}");
        }
        assert_eq!(cj1_acces(&st, "cj1-ana", Some(CJ1_A)), cj1_acces_attendu(CJ1_A, "editor", false, false), "remis");
    }

    /// CE QU'IL TIENT : le premier droit de `cj1-ana` non lu (mêmes voies), l'accès SANS sélection rend `503`
    /// CJ1_DROITS_NON_LUS — ni « aucun tenant accessible », ni la `409` « sélection requise » d'un super-administrateur.
    /// Contrôle positif : remis, éditrice de A par défaut.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_DEFAUT` et `CJ1_DEFAUT_RBAC` — 403 « aucun tenant accessible ».
    #[test]
    fn cj1_premier_droit_non_lu_est_un_503_nomme() {
        let (st, _tmp) = cj1_etat();
        for (voie, pose, remise) in cj1_voies_du_droit() {
            cj1_plan(&st, &pose);
            let r = cj1_acces(&st, "cj1-ana", None);
            cj1_plan(&st, &remise);
            assert_eq!(r, cj1_refus(503, CJ1_DROITS_NON_LUS), "{voie}");
        }
        assert_eq!(cj1_acces(&st, "cj1-ana", None), cj1_acces_attendu(CJ1_A, "editor", false, false), "remis");
    }

    // -------------------------------------------------------------------------------------
    // (3) `auth::resolve_tenant_and_role` — les routes de gestion des droits (`mgmt_grants_role`).
    // -------------------------------------------------------------------------------------

    /// `Err((statut, corps))` : le corps est relu en JSON quand il en est un (le 503 `{error, id}`), en texte sinon.
    async fn cj1_gestion(st: &AppState, nom: &str, sa: bool) -> Result<(String, String, bool, bool), (u16, Value)> {
        let chemin = format!("/api/tenants/{CJ1_A}/grants");
        let req = axum::http::Request::builder().uri(chemin.as_str()).body(axum::body::Body::empty()).expect("requête");
        match crate::auth::resolve_tenant_and_role(st, &req, &chemin, nom, "admin".into(), "basic", None, None, sa, false, None) {
            Ok(v) => Ok(v),
            Err(r) => {
                let code = r.status().as_u16();
                let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
                Err((code, serde_json::from_slice(&corps).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&corps).into_owned()))))
            }
        }
    }

    /// CE QU'IL TIENT : sur `/api/tenants/cj1-a/grants`, les droits non lus (deux voies) rendent `503`, corps entier
    /// `{error: CJ1_DROITS_NON_LUS, id}`, pour l'éditrice ET pour le super-administrateur — ni le rôle « viewer » du non-membre, ni le rôle « admin » du
    /// super-administrateur décidés sans lecture. Contrôle positif : ana « editor », le super-administrateur non membre
    /// « admin », comme avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_GESTION` (le repli non-membre repris sur la lecture ratée : `Ok`), et
    /// `CJ1_DEMANDE` (la lecture du droit demandé, que ce chemin emprunte, rendue à l'absence).
    #[tokio::test]
    async fn cj1_droits_non_lus_sur_les_routes_de_gestion_sont_un_503_nomme() {
        let (st, _tmp) = cj1_etat();
        assert_eq!(cj1_gestion(&st, "cj1-ana", false).await, Ok((CJ1_A.to_string(), "editor".to_string(), false, false)), "contrôle : membre");
        assert_eq!(cj1_gestion(&st, "cj1-op", true).await, Ok((CJ1_A.to_string(), "admin".to_string(), true, false)), "contrôle : super-administrateur");
        for (voie, pose, remise) in cj1_voies_du_droit() {
            cj1_plan(&st, &pose);
            let ana = cj1_gestion(&st, "cj1-ana", false).await;
            let op = cj1_gestion(&st, "cj1-op", true).await;
            cj1_plan(&st, &remise);
            let (statut, corps) = ana.expect_err("membre : refusé");
            cj1_cinq_cent_trois(&format!("{voie} : membre"), statut, &corps, CJ1_DROITS_NON_LUS);
            if voie == "table retirée" {
                let (statut, corps) = op.expect_err("super-administrateur : refusé");
                cj1_cinq_cent_trois(&format!("{voie} : super-administrateur"), statut, &corps, CJ1_DROITS_NON_LUS);
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // (4) `catalog_route` — l'accès inter-tenants d'un super-administrateur (`resolve_tenant_access`).
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `cj1-op`, super-administrateur sans droit sur C, demande C. La ligne de C illisible (`key_ref`
    /// puis `db_path` en BLOB ; les lectures de droits, qui ne lisent que `id` et `suspended`, restent saines) : `503`
    /// CJ1_CATALOGUE_NON_LU. Contrôle positif : remise, l'accès inter-tenants (lecteur) est servi ; un tenant ABSENT
    /// garde le 403 CJ1_TENANT_INDISPONIBLE d'avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_CATALOGUE` et `CJ1_CATALOGUE_RBAC` — 403 CJ1_TENANT_INDISPONIBLE.
    #[test]
    fn cj1_catalogue_non_lu_a_l_acces_inter_tenants_est_un_503_nomme() {
        let (st, _tmp) = cj1_etat();
        assert_eq!(cj1_acces(&st, "cj1-op", Some(CJ1_C)), cj1_acces_attendu(CJ1_C, "viewer", true, true), "contrôle : inter-tenants");
        assert_eq!(cj1_acces(&st, "cj1-op", Some("cj1-fantome")), cj1_refus(403, CJ1_TENANT_INDISPONIBLE), "absence établie");
        for colonne in ["key_ref", "db_path"] {
            let avant: String = st.tenants.control.as_ref().expect("plan").conn.lock()
                .query_row(&format!("SELECT {colonne} FROM tenant WHERE id=?1"), params![CJ1_C], |r| r.get(0))
                .expect("fixture : valeur d'avant");
            cj1_plan(&st, &format!("UPDATE tenant SET {colonne}=X'00' WHERE id='{CJ1_C}';"));
            let r = cj1_acces(&st, "cj1-op", Some(CJ1_C));
            st.tenants.control.as_ref().expect("plan").conn.lock()
                .execute(&format!("UPDATE tenant SET {colonne}=?1 WHERE id=?2"), params![avant, CJ1_C])
                .expect("fixture : remise");
            assert_eq!(r, cj1_refus(503, CJ1_CATALOGUE_NON_LU), "{colonne} illisible");
        }
        assert_eq!(cj1_acces(&st, "cj1-op", Some(CJ1_C)), cj1_acces_attendu(CJ1_C, "viewer", true, true), "remise");
    }

    // -------------------------------------------------------------------------------------
    // (5) `catalog_route` — la porte d'entrée d'`auth_guard`, par le routeur.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : par la route (`GET /api/me`, cookie de `rgsc-ana`, administratrice du tenant A), la ligne de A
    /// au catalogue illisible (`key_ref` en BLOB ; ses droits restent lisibles) : `503`, corps entier `{error:
    /// CJ1_CATALOGUE_NON_LU, id}`, jamais « tenant indisponible (base non résoluble) ». Contrôle positif avant et après : 200.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ1_CATALOGUE` et `CJ1_CATALOGUE_AUTH` — 403.
    #[tokio::test]
    async fn cj1_catalogue_non_lu_a_la_porte_d_entree_est_un_503_nomme_par_la_route() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ana = rgsc_connexion(addr, "rgsc-ana").await;
        let cookie = format!("plume_session={ana}");
        let entetes = [("Cookie", cookie.as_str()), ("x-plume-tenant", RGSC_TENANT_A)];
        let r = rgsc_envoyer(addr, "GET", "/api/me", None, &entetes, "").await;
        assert_eq!(r.statut, 200, "contrôle : {}", r.texte);

        let plan = st.tenants.control.as_ref().expect("plan");
        let avant: String = plan.conn.lock().query_row("SELECT key_ref FROM tenant WHERE id=?1", params![RGSC_TENANT_A], |r| r.get(0)).expect("fixture");
        plan.conn.lock().execute("UPDATE tenant SET key_ref=X'00' WHERE id=?1", params![RGSC_TENANT_A]).expect("fixture : illisible");
        let r = rgsc_envoyer(addr, "GET", "/api/me", None, &entetes, "").await;
        plan.conn.lock().execute("UPDATE tenant SET key_ref=?1 WHERE id=?2", params![avant, RGSC_TENANT_A]).expect("fixture : remise");
        cj1_cinq_cent_trois("catalogue illisible", r.statut, &r.corps, CJ1_CATALOGUE_NON_LU);

        let r = rgsc_envoyer(addr, "GET", "/api/me", None, &entetes, "").await;
        assert_eq!(r.statut, 200, "remise : {}", r.texte);
    }

    // -------------------------------------------------------------------------------------
    // (6) `tenant_delete` — le nom du tenant visé.
    // -------------------------------------------------------------------------------------

    fn cj1_super_admin() -> AuthUser {
        AuthUser {
            name: "op-cj1".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    async fn cj1_creer(st: &AppState, id: &str) -> (u16, Value) {
        pb_json(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(cj1_super_admin()), Json(json!({ "id": id, "name": id }))).await).await
    }

    async fn cj1_detruire(st: &AppState, id: &str, confirm: &str) -> (u16, Value) {
        pb_json(tenant_delete(State(st.clone()), Extension(cj1_super_admin()), Path(id.into()), Json(json!({ "confirm": confirm }))).await).await
    }

    /// CE QU'IL TIENT : le nom de `cj1-d` non lu (table retirée, puis `name` en BLOB), `DELETE /api/tenants/cj1-d` rend
    /// `503`, corps entier `{error: CJ1_DESTRUCTION_NON_LUE, id}` — jamais 404 « tenant inconnu » ; aucun maillon
    /// `tenant.destroy` ; le tenant reste au catalogue et sa base sur le disque. Contrôle positif : un tenant ABSENT
    /// garde le 404 texte d'avant ; une confirmation fausse rend 400 (le nom a été LU) ; la bonne détruit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ1_DESTRUCTION` (la lecture ratée servie comme l'absence : 404).
    #[tokio::test]
    async fn cj1_destruction_dont_le_tenant_n_est_pas_lu_est_un_503_nomme() {
        let (st, _dir) = mk_mode1_state();
        assert_eq!(cj1_creer(&st, "cj1-d").await.0, 201, "fixture");
        let base = tenant_db_path(&st, "cj1-d");
        assert!(std::path::Path::new(&base).exists(), "fixture : la base du tenant existe");
        for (voie, pose, remise) in [
            ("table retirée", "ALTER TABLE tenant RENAME TO cj1_tenant;", "ALTER TABLE cj1_tenant RENAME TO tenant;"),
            ("ligne illisible", "UPDATE tenant SET name=X'00' WHERE id='cj1-d';", "UPDATE tenant SET name='cj1-d' WHERE id='cj1-d';"),
        ] {
            cj1_plan(&st, pose);
            let (statut, v) = cj1_detruire(&st, "cj1-d", "cj1-d").await;
            cj1_plan(&st, remise);
            cj1_cinq_cent_trois(voie, statut, &v, CJ1_DESTRUCTION_NON_LUE);
            assert_eq!(cj1_compte(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind='tenant.destroy'"), 0, "{voie} : rien n'est tracé");
            assert_eq!(cj1_compte(&st, "SELECT COUNT(*) FROM tenant WHERE id='cj1-d'"), 1, "{voie} : le tenant reste au catalogue");
            assert!(std::path::Path::new(&base).exists(), "{voie} : la base du tenant est intacte");
        }
        let (statut, v) = cj1_detruire(&st, "cj1-absent", "cj1-absent").await;
        assert_eq!((statut, v.get("_texte").and_then(|x| x.as_str())), (404, Some("tenant inconnu")), "absence établie : {v}");
        let (statut, v) = cj1_detruire(&st, "cj1-d", "autre-nom").await;
        assert_eq!(statut, 400, "le nom LU juge la confirmation : {v}");
        let (statut, v) = cj1_detruire(&st, "cj1-d", "cj1-d").await;
        assert_eq!((statut, v.get("destroyed").and_then(|x| x.as_bool())), (200, Some(true)), "lecture réussie : détruit : {v}");
    }

    // -------------------------------------------------------------------------------------
    // (7) `tenant_provision` — l'existence d'un tenant sous l'identifiant demandé.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'existence non lue — table retirée, puis VUE temporaire `tenant` qui échoue à l'exécution
    /// (`json_each` d'un texte qui n'est pas du JSON, placé en boucle externe par `CROSS JOIN` : l'erreur survient
    /// même quand aucune ligne ne porte l'identifiant) —, `POST /api/tenants` `cj1-n` rend `503`, corps entier
    /// `{error: CJ1_EXISTENCE_NON_LUE, id}` : ni la cause de l'inscription refusée qu'atteignait la forme d'avant, ni un
    /// succès ; rien n'est créé (aucune ligne, aucune base). Contrôle positif : remis, `cj1-n` se crée (201) ; recréé,
    /// il rend la 409 texte « existe déjà » d'avant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ1_PROVISION` (l'existence non lue lue « identifiant libre » : la transaction
    /// poursuit et sert `CAUSE_TENANT_NON_CREE_LIGNE_NON_INSCRITE`).
    #[tokio::test]
    async fn cj1_creation_dont_l_existence_n_est_pas_lue_est_un_503_nomme() {
        let (st, _dir) = mk_mode1_state();
        let base = tenant_db_path(&st, "cj1-n");
        for (voie, pose, remise) in [
            ("table retirée", "ALTER TABLE tenant RENAME TO cj1_tenant;", "ALTER TABLE cj1_tenant RENAME TO tenant;"),
            (
                "vue qui échoue",
                "ALTER TABLE tenant RENAME TO cj1_tenant; CREATE TEMP VIEW tenant AS \
                 SELECT t.* FROM json_each('pas du json') CROSS JOIN cj1_tenant AS t;",
                "DROP VIEW temp.tenant; ALTER TABLE cj1_tenant RENAME TO tenant;",
            ),
        ] {
            cj1_plan(&st, pose);
            let (statut, v) = cj1_creer(&st, "cj1-n").await;
            cj1_plan(&st, remise);
            cj1_cinq_cent_trois(voie, statut, &v, CJ1_EXISTENCE_NON_LUE);
            assert_eq!(cj1_compte(&st, "SELECT COUNT(*) FROM tenant WHERE id='cj1-n'"), 0, "{voie} : aucune ligne");
            assert!(!std::path::Path::new(&base).exists(), "{voie} : aucune base");
        }
        assert_eq!(cj1_creer(&st, "cj1-n").await.0, 201, "remis : la création passe");
        let (statut, v) = cj1_creer(&st, "cj1-n").await;
        assert_eq!((statut, v.get("_texte").and_then(|x| x.as_str())), (409, Some("tenant 'cj1-n' existe déjà")), "présence établie : {v}");
    }

    // -------------------------------------------------------------------------------------
    // (8) LA CHAÎNE DE MIGRATIONS ET LE CONTRAT — une base existante n'est jamais prise pour une base neuve.
    // -------------------------------------------------------------------------------------

    fn cj1_estampille(p: &str) -> (String, Option<String>) {
        let c = crate::db_open::open_db(p).unwrap();
        c.query_row("SELECT typeof(value), CAST(value AS TEXT) FROM meta WHERE key='schema_version'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture : l'estampille se relit")
    }

    fn cj1_poser_l_estampille(p: &str, sql: &str) {
        crate::db_open::open_db(p).unwrap().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"));
    }

    /// CE QU'IL TIENT (ce que fait le code, dit par la mesure) : sur une base MIGRÉE et peuplée dont l'estampille ne se
    /// lit pas comme un entier (un BLOB, puis un texte non entier), la chaîne de migrations appelée directement
    /// (`migrate()`) rend `false` et ne joue AUCUNE étape — l'inventaire des lignes que les étapes destructrices visent
    /// est intact et l'estampille n'est pas réécrite. Contrôle positif : l'estampille remise à la tête, la chaîne rend
    /// `true` sans rien toucher.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ1_CHAINE` (la version retombe sur « un », la forme d'avant) — la chaîne se
    /// rejoue et l'inventaire change.
    #[test]
    fn cj1_la_chaine_ne_rejoue_rien_sur_une_estampille_illisible() {
        let (_t, p) = eso_base_migree("cj1-chaine");
        eso_semer(&p);
        let avant = eso_inventaire(&p);
        for (voie, pose, attendue) in [
            ("blob", "UPDATE meta SET value=X'313236' WHERE key='schema_version';", ("blob", Some("126"))),
            ("texte non entier", "UPDATE meta SET value='v-cent' WHERE key='schema_version';", ("text", Some("v-cent"))),
        ] {
            cj1_poser_l_estampille(&p, pose);
            {
                let c = crate::db_open::open_db(&p).unwrap();
                assert!(!crate::migrate::migrate(&c), "{voie} : la chaîne n'est pas menée sur une version non lue");
            }
            assert_eq!(eso_inventaire(&p), avant, "{voie} : aucune étape n'a été rejouée");
            let (genre, valeur) = cj1_estampille(&p);
            assert_eq!((genre.as_str(), valeur.as_deref()), attendue, "{voie} : l'estampille n'est pas réécrite");
        }
        cj1_poser_l_estampille(&p, &format!("UPDATE meta SET value='{CODE_SCHEMA_MAX}' WHERE key='schema_version';"));
        {
            let c = crate::db_open::open_db(&p).unwrap();
            assert!(crate::migrate::migrate(&c), "contrôle : estampille lue à la tête, la chaîne est au bout");
        }
        assert_eq!(eso_inventaire(&p), avant, "contrôle : rien n'est rejoué sur une base à jour");
    }

    /// CE QU'IL TIENT : le contrat de schéma (`prepare_schema`) appelé hors de la porte sur une base MIGRÉE dont `meta`
    /// a disparu (table renommée) REFUSE, phrase qui commence par `CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE` : `db/schema.sql`
    /// n'est pas joué (une seule table `meta%` au catalogue, l'ancienne) et l'inventaire est intact. Même refus sur
    /// l'estampille en BLOB, réécrite nulle part. Contrôle positif : la table remise, le contrat passe sans rien rejouer.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ1_CONTRAT` (le contrôle d'entrée retiré) — `db/schema.sql` recrée `meta` avec
    /// « 1 », la chaîne lit cette estampille et se rejoue : deux tables `meta%`, inventaire changé.
    #[test]
    fn cj1_le_contrat_ne_prend_jamais_une_base_existante_pour_une_base_neuve() {
        let (_t, p) = eso_base_migree("cj1-contrat");
        eso_semer(&p);
        let avant = eso_inventaire(&p);

        cj1_poser_l_estampille(&p, "ALTER TABLE meta RENAME TO meta_cj1;");
        let refus = {
            let c = crate::db_open::open_db(&p).unwrap();
            crate::migrate::prepare_schema(&c)
        };
        let tables_meta = eso_tables_meta(&p);
        let apres = eso_inventaire(&p);
        cj1_poser_l_estampille(&p, "ALTER TABLE meta_cj1 RENAME TO meta;");
        let refus = refus.expect_err("table retirée : le contrat refuse");
        assert!(refus.starts_with(CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE), "table retirée : cause nommée : {refus}");
        assert_eq!(tables_meta, 1, "table retirée : `db/schema.sql` n'a pas recréé de table `meta`");
        assert_eq!(apres, avant, "table retirée : aucune étape rejouée");

        cj1_poser_l_estampille(&p, "UPDATE meta SET value=X'313236' WHERE key='schema_version';");
        let refus = {
            let c = crate::db_open::open_db(&p).unwrap();
            crate::migrate::prepare_schema(&c)
        };
        assert!(refus.expect_err("blob : le contrat refuse").starts_with(CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE), "blob : cause nommée");
        assert_eq!(cj1_estampille(&p).0, "blob", "blob : l'estampille n'est pas réécrite");
        assert_eq!(eso_inventaire(&p), avant, "blob : aucune étape rejouée");

        cj1_poser_l_estampille(&p, &format!("UPDATE meta SET value='{CODE_SCHEMA_MAX}' WHERE key='schema_version';"));
        {
            let c = crate::db_open::open_db(&p).unwrap();
            assert!(crate::migrate::prepare_schema(&c).is_ok(), "contrôle : base saine, contrat satisfait");
        }
        assert_eq!(eso_inventaire(&p), avant, "contrôle : rien n'est rejoué");
    }
}
