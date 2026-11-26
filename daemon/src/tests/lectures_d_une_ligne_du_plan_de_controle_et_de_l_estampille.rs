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
// inversé `sar_platform_user_illisible_pas_d_acces_inter_tenants`, par la route) ; `CJ1_DESTRUCTION_OUVERTURE` (la
// destruction non lue servie sous l'ouverture `TENANT NON DÉTRUIT`, que la console peint avec une transaction annulée et
// une ligne de journal déjà écrite) ; `CJ1_PROVISION` rejoué sur la voie où l'inscription réussirait (le jeton laissé
// sous l'identifiant effacé, vu rouge AVANT la cause). Et, par édition de source, chaque `eprintln!` de la cause du
// moteur retiré d'un bras neuf (témoin (9)).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les appelants de `TenantDbManager::ready_lu` qui ne passent pas par les deux
// portes témoignées ici — l'ingestion du spool, le parcours des tenants des tâches de fond, `req_db`, `req_db_path`
// et la projection `handle_for` — sont tenus par `catalogue_non_lu_a_l_ingestion_et_aux_taches_de_fond.rs`.
//
// LES SECTIONS (10) À (13) (préfixe `cj10_`) tiennent les derniers défauts connus de la même famille hors de
// `handlers/`, mesurés ROUGES sur la base avant leur correctif :
//   * l'alerte `control.catalog` écrivait en base « aucun état DIFFÉRENT n'a jamais été relevé » pour une machine dont
//     l'état précédent n'avait pas été lu (instant REAL) ; elle dit désormais l'ancienneté NON ÉTABLIE (deux phrases
//     fixes : état précédent non lu, jour non calculé), la cause du moteur au journal, et reste toujours écrite ;
//   * `migrate_step` réécrivait « 1 » dans `meta` après une version d'avant l'étape non lue suivie d'un échec de
//     l'étape (mesuré : estampille « 1 », une réécriture restée en base) ; l'étape n'est plus jouée, rien n'est
//     réécrit, et les messages (échec d'étape, contrat de schéma) disent `NON LUE` au lieu de « 1 » ;
//   * la fiche de runbooks d'un dossier (`case_runbooks_json`) : déjà un 503 nommé sur sa lecture ratée, VERT sur la
//     base ; le témoin par la route prouve le reclassement de son `.ok()?` parmi les arbitrages assumés de la garde.
// MUTANTS JOUÉS (posés sous `cfg!(test)` le temps de la mesure, retirés avant le commit), chacun vu rouge seul :
// `CJ10_ETAT`, `CJ10_JOUR`, `CJ10_JOUR_NUL` (le repli « jamais relevé » remis à chaque site et à chaque bras),
// `CJ10_PHRASE` (l'état non lu dit avec la phrase du jour), `CJ10_ETAT_JOURNAL`, `CJ10_JOUR_JOURNAL` (la ligne de
// journal retirée),
// `CJ10_AVANT` (la version non lue rendue à « 1 » et l'étape jouée), `CJ10_DECRIT` (un message qui dit « 1 » pour
// « non lue »), `CJ10_ESTAMPILLE`, `CJ10_COMMIT`, `CJ10_RESTAURE`, `CJ10_ANOMALIE`, `CJ10_FICHE`,
// `CJ10_CONTRAT_MANQUES` (le refus des manques du contrat dit « 1 » pour « non lue »), `CJ10_RELUE_ENTIER`
// (la valeur non entière relue « 1 »), `CJ10_AVANT_ABSENTE`, `CJ10_DECRIT_ABSENTE` (la ligne absente prise pour une
// lecture ratée, au moteur puis au message).
// CE QU'ILS NE TIENNENT PAS : les messages d'échec des deux bases de référence (`build_reference_shape`,
// `ddl_de_reference`) prennent la même description, mais leur connexion est ouverte en mémoire DANS la fonction et
// aucun témoin ne peut y rendre `meta` illisible (hors d'atteinte) ; le dossier supprimé entre les deux lectures de
// la fiche de runbooks (dit « non lu ») n'est pas fabriqué.
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
    /// Ouverture `TENANT NON LU, …` et non `TENANT NON DÉTRUIT` : la console peint cette dernière avec une transaction
    /// annulée et une ligne du journal de contrôle déjà écrite, deux faits faux pour un refus posé avant l'une et l'autre.
    const CJ1_DESTRUCTION_NON_LUE: &str = "TENANT NON LU, DESTRUCTION NON FAITE : le plan de contrôle n'a pas pu lire le \
         tenant visé avant la destruction — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. RIEN \
         n'est détruit ni tracé : le tenant et sa base sont intacts. Réessayez une fois le plan de contrôle de nouveau lisible.";
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

    /// CE QU'IL TIENT : l'existence non lue, par trois voies — une VUE temporaire `tenant` qui échoue à la LECTURE
    /// (`json_each` d'un texte qui n'est pas du JSON, placé en boucle externe par `CROSS JOIN` : l'erreur survient même
    /// quand aucune ligne ne porte l'identifiant) mais accepte l'INSCRIPTION par un déclencheur `INSTEAD OF INSERT` vers
    /// la table d'origine ; la table retirée ; la même vue sans déclencheur —, `POST /api/tenants` `cj1-n` rend `503`,
    /// corps entier `{error: CJ1_EXISTENCE_NON_LUE, id}`. Sur la PREMIÈRE voie, effacement et inscription
    /// RÉUSSIRAIENT si la transaction poursuivait : « aucune ligne », « aucune base » et « le jeton laissé sous
    /// l'identifiant est toujours là » y sont donc des faits qui rougissent, jugés AVANT la cause. Sur les deux autres,
    /// l'inscription est impossible et la transaction annulée : seule la cause y discrimine. Contrôle positif : remis,
    /// `cj1-n` se crée (201) et le jeton laissé sous l'identifiant est effacé — l'observable du reste est vivant ; recréé,
    /// il rend la 409 texte « existe déjà » d'avant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ1_PROVISION` (l'existence non lue lue « identifiant libre » : la transaction
    /// poursuit — première voie : le jeton est effacé et la ligne inscrite ; les autres : la cause de l'inscription
    /// refusée, `CAUSE_TENANT_NON_CREE_LIGNE_NON_INSCRITE`).
    #[tokio::test]
    async fn cj1_creation_dont_l_existence_n_est_pas_lue_est_un_503_nomme() {
        let (st, _dir) = mk_mode1_state();
        let base = tenant_db_path(&st, "cj1-n");
        cj1_plan(&st, "INSERT INTO token(hash,tenant_id) VALUES('cj1-reste','cj1-n');");
        let reste = "SELECT COUNT(*) FROM token WHERE hash='cj1-reste'";
        for (voie, pose, remise) in [
            (
                "vue qui échoue à la lecture, inscription possible",
                "ALTER TABLE tenant RENAME TO cj1_tenant; CREATE TEMP VIEW tenant AS \
                 SELECT t.* FROM json_each('pas du json') CROSS JOIN cj1_tenant AS t; \
                 CREATE TEMP TRIGGER cj1_inscrire INSTEAD OF INSERT ON tenant BEGIN \
                 INSERT INTO cj1_tenant(id,name,key_ref,db_path,created,suspended) \
                 VALUES(NEW.id,NEW.name,NEW.key_ref,NEW.db_path,NEW.created,NEW.suspended); END;",
                "DROP VIEW temp.tenant; ALTER TABLE cj1_tenant RENAME TO tenant;",
            ),
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
            assert_eq!(cj1_compte(&st, reste), 1, "{voie} : rien n'est effacé sous l'identifiant ({statut} {v})");
            assert_eq!(cj1_compte(&st, "SELECT COUNT(*) FROM tenant WHERE id='cj1-n'"), 0, "{voie} : aucune ligne ({statut} {v})");
            assert!(!std::path::Path::new(&base).exists(), "{voie} : aucune base ({statut} {v})");
            cj1_cinq_cent_trois(voie, statut, &v, CJ1_EXISTENCE_NON_LUE);
        }
        assert_eq!(cj1_creer(&st, "cj1-n").await.0, 201, "remis : la création passe");
        assert_eq!(cj1_compte(&st, reste), 0, "remis : la création efface le jeton laissé sous l'identifiant (l'observable vit)");
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

    // -------------------------------------------------------------------------------------
    // (9) LA CAUSE DU MOTEUR D'UNE LECTURE NON FAITE EST DITE AU JOURNAL — jamais servie, jamais jetée.
    // -------------------------------------------------------------------------------------

    /// Le bras qui sert `servi` dans `source` : les lignes depuis son `Err(` jusqu'à la ligne servie, la ligne servie
    /// comprise. Une seule occurrence du motif servi est admise : deux rendraient le témoin ambigu.
    fn cj1_bras_qui_sert<'a>(source: &'a str, fichier: &str, servi: &str) -> Vec<&'a str> {
        let lignes: Vec<&str> = source.lines().collect();
        let sites: Vec<usize> = lignes.iter().enumerate().filter(|(_, l)| l.contains(servi)).map(|(i, _)| i).collect();
        assert_eq!(sites.len(), 1, "{fichier} : `{servi}` doit être servi en UN site, trouvé {sites:?} (le témoin ne conclut pas)");
        let i = sites[0];
        let debut = (i.saturating_sub(4)..=i).rev().find(|&j| lignes[j].trim_start().starts_with("Err("))
            .unwrap_or_else(|| panic!("{fichier} : le site de `{servi}` n'est plus le bras `Err(` d'un `match` (le témoin ne conclut pas)"));
        lignes[debut..=i].to_vec()
    }

    /// CE QU'IL TIENT : chaque bras neuf qui sert une lecture d'une ligne NON FAITE en 503 nommé garde la cause du moteur
    /// — liée (`Err(e)`, jamais `Err(_)`) et écrite au journal par `eprintln!` —, comme les étapes voisines de la même
    /// fonction. La phrase servie reste fixe (jugée par les témoins de route ci-dessus) : le texte du moteur n'a que le
    /// journal pour se dire, et sans lui l'exploitant ne sait pas POURQUOI le plan de contrôle n'a pas été lu. Sites :
    /// `tenant_provision` (l'existence), `tenant_delete` (le tenant visé), `rbac::refus_des_droits_non_lus` et
    /// `rbac::refus_du_catalogue_non_lu` (qui prennent la cause : le compilateur interdit de la jeter à leurs appelants de
    /// `resolve_tenant_access`), et les deux portes d'`auth.rs`, qui passent par ces mêmes fonctions.
    ///
    /// LECTURE DE SOURCE, PAS DE ROUTE : la sortie d'erreur d'un test n'est pas capturable sans dépendance neuve. Ce que
    /// ce témoin NE TIENT PAS : le texte exact écrit au journal, ni qu'il y parvient à l'exécution.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : chaque `eprintln!` retiré d'un de ces quatre sites, ou une porte d'`auth.rs`
    /// rendue à la constante servie directement.
    #[test]
    fn cj1_la_cause_du_moteur_d_une_lecture_non_faite_est_dite_au_journal() {
        let tenants = include_str!("../tenants.rs");
        for servi in [
            "return Err(ProvisionNonFaite::NonPrise(EtapeDeLaCreationNonPrise::ExistenceNonLue));",
            "return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TENANT_NON_LU_DESTRUCTION_NON_FAITE);",
        ] {
            let bras = cj1_bras_qui_sert(tenants, "tenants.rs", servi);
            assert!(bras[0].trim_start().starts_with("Err(e) =>"), "tenants.rs : le bras de `{servi}` lie la cause : {bras:?}");
            assert!(bras.iter().any(|l| l.contains("eprintln!(") && l.contains(": {e}\")")),
                "tenants.rs : le bras de `{servi}` dit la cause du moteur au journal : {bras:?}");
        }
        let rbac = include_str!("../rbac.rs");
        for refus in ["pub(crate) fn refus_des_droits_non_lus(cause_du_moteur: &rusqlite::Error)", "pub(crate) fn refus_du_catalogue_non_lu(cause_du_moteur: &rusqlite::Error)"] {
            let corps: Vec<&str> = rbac.split(refus).nth(1).unwrap_or_else(|| panic!("rbac.rs : `{refus}` n'existe plus (le témoin ne conclut pas)"))
                .lines().take_while(|l| *l != "}").collect();
            assert!(corps.iter().any(|l| l.contains("eprintln!(") && l.contains("{cause_du_moteur}")), "rbac.rs : `{refus}` dit la cause au journal : {corps:?}");
        }
        let auth = include_str!("../auth.rs");
        for refus in ["crate::rbac::refus_des_droits_non_lus(&e)", "crate::rbac::refus_du_catalogue_non_lu(&e)"] {
            let bras = cj1_bras_qui_sert(auth, "auth.rs", refus);
            assert!(bras[0].trim_start().starts_with("Err(e) =>"), "auth.rs : le bras de `{refus}` lie la cause : {bras:?}");
        }
        for constante in ["crate::rbac::CAUSE_DROITS_DU_COMPTE_NON_LUS", "crate::rbac::CAUSE_CATALOGUE_DES_TENANTS_NON_LU"] {
            assert!(!auth.contains(constante), "auth.rs sert `{constante}` sans passer par le refus qui dit la cause au journal");
        }
    }

    // -------------------------------------------------------------------------------------
    // (10) L'ANCIENNETÉ D'UN ÉTAT DE CONTRÔLES — « jamais relevé » seulement quand c'est LU.
    // -------------------------------------------------------------------------------------

    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CJ10_HOTE: &str = "srv01";
    const CJ10_TS: i64 = 1_785_600_000;
    const CJ10_TETE_DU_TITRE: &str = "1 contrôle(s) de défense MANQUANT(S) sur srv01 : auditd_active";
    const CJ10_JAMAIS: &str = " — aucun état DIFFÉRENT n'a jamais été relevé pour cette machine";
    const CJ10_DEPUIS_LE_31: &str = " — même état depuis au moins le 2026-07-31";
    const CJ10_ETAT_NON_LU: &str =
        " — ancienneté de cet état NON ÉTABLIE : l'état précédent de cette machine n'a pas pu être lu";
    const CJ10_JOUR_NON_CALCULE: &str =
        " — ancienneté de cet état NON ÉTABLIE : le jour de l'état précédent n'a pas pu être calculé";
    /// L'état précédent de la série, lisible, un jour avant le rapport.
    const CJ10_ETAT_LU: &str = "INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(1785513600,'controls','srv01','etat_ancien','{}');";
    /// Le même, instant en REAL : `MAX(ts)` rend un REAL que le mappeur entier refuse (la ligne existe, elle ne se lit pas).
    const CJ10_ETAT_ILLISIBLE: &str =
        "INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(1785513600.5,'controls','srv01','etat_ancien','{}');";
    /// Le même, instant au-delà de l'an 9999 : `date(…,'unixepoch')` rend NULL (aucune erreur du moteur).
    const CJ10_ETAT_HORS_CALENDRIER: &str =
        "INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(300000000000,'controls','srv01','etat_ancien','{}');";
    const CJ10_LIGNE_ETAT_NON_LU: &str = "[controles] WARN état précédent d'une série de contrôles de défense NON lu, \
         ancienneté NON ÉTABLIE dans le titre de l'alerte : ";
    const CJ10_LIGNE_JOUR_NON_CALCULE: &str = "[controles] WARN jour de l'état précédent d'une série de contrôles de défense \
         NON calculé, ancienneté NON ÉTABLIE dans le titre de l'alerte : ";

    /// Ingère par le spool UN rapport `controls` de `srv01` (un contrôle manquant) après avoir posé `prealable` sur la
    /// base du démon ; `refuser_le_jour` installe sur la connexion d'ingestion un autorisateur qui refuse la fonction
    /// `date` (la lecture de l'état précédent passe, le calcul du jour échoue). Rend le titre de L'UNIQUE alerte
    /// `control.catalog` (`ctl_titre` échoue s'il n'y en a pas exactement une : l'alerte est toujours écrite).
    fn cj10_titre_apres(prealable: &str, refuser_le_jour: bool) -> String {
        let (st, spool) = ing_state_with_spool();
        if !prealable.is_empty() {
            st.db.lock().execute_batch(prealable).unwrap_or_else(|e| panic!("fixture : `{prealable}` ({e})"));
        }
        if refuser_le_jour {
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("date") => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        }
        let data = json!({ "failed": 1, "controls": [ctl_item("auditd_active", Some(false))] });
        depose_spool(&spool, CJ10_HOTE, 0, &ctl_enveloppe(CJ10_HOTE, CJ10_TS, "etat_courant", data));
        ingest_once(&st.tenants, &st.spool);
        let c = st.db.lock();
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let titre = ctl_titre(&c, "control.catalog");
        drop(c);
        let _ = std::fs::remove_dir_all(&spool);
        titre
    }

    /// CE QU'IL TIENT (par l'ingestion réelle, titre ENTIER écrit en base) : l'alerte `control.catalog` est écrite dans
    /// les cinq cas ; « aucun état DIFFÉRENT n'a jamais été relevé » n'est écrit que si la série ne porte réellement
    /// aucun autre état (à l'octet d'avant) ; un état précédent LU donne son jour ; un état précédent présent mais
    /// illisible, un jour hors du calendrier de SQLite et un jour que le moteur refuse de calculer disent l'ancienneté
    /// NON ÉTABLIE, par une phrase fixe, sans le texte du moteur.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ10_ETAT` (l'état précédent non lu rendu à « jamais relevé »), `CJ10_JOUR`
    /// et `CJ10_JOUR_NUL` (le jour refusé par le moteur, puis le jour NULL, rendus à « jamais relevé »), `CJ10_PHRASE`
    /// (l'état précédent non lu dit avec la phrase du jour non calculé).
    #[test]
    fn cj10_l_anciennete_d_un_etat_n_est_dite_jamais_relevee_que_si_c_est_lu() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        for (voie, prealable, refuser, attendu) in [
            ("aucun autre état (absence établie)", "", false, CJ10_JAMAIS),
            ("état précédent lu", CJ10_ETAT_LU, false, CJ10_DEPUIS_LE_31),
            ("état précédent illisible (instant REAL)", CJ10_ETAT_ILLISIBLE, false, CJ10_ETAT_NON_LU),
            ("jour hors du calendrier (date NULL)", CJ10_ETAT_HORS_CALENDRIER, false, CJ10_JOUR_NON_CALCULE),
            ("jour refusé par le moteur", CJ10_ETAT_LU, true, CJ10_JOUR_NON_CALCULE),
        ] {
            assert_eq!(cj10_titre_apres(prealable, refuser), format!("{CJ10_TETE_DU_TITRE}{attendu}"), "{voie} : titre entier");
        }
    }

    /// La cause que le moteur rend pour l'état précédent en REAL (même énoncé, même mappeur que la production).
    fn cj10_moteur_de_l_instant_reel() -> String {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE snapshot(ts INTEGER NOT NULL, kind TEXT, host TEXT, hash TEXT, data TEXT);").unwrap();
        c.execute_batch(CJ10_ETAT_ILLISIBLE).unwrap();
        c.query_row(
            "SELECT MAX(ts) FROM snapshot WHERE kind='controls' AND host IS ?1 AND COALESCE(hash,'')<>?2",
            params![CJ10_HOTE, "etat_courant"],
            |r| r.get::<_, Option<i64>>(0),
        )
        .expect_err("fixture : l'instant REAL ne se lit pas en entier")
        .to_string()
    }

    /// La cause que le moteur rend quand l'autorisateur refuse la fonction `date`.
    fn cj10_moteur_du_jour_refuse() -> String {
        let c = Connection::open_in_memory().unwrap();
        c.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("date") => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        c.query_row("SELECT date(?1,'unixepoch')", params![1_785_513_600i64], |r| r.get::<_, Option<String>>(0))
            .expect_err("fixture : la fonction date est refusée")
            .to_string()
    }

    // -------------------------------------------------------------------------------------
    // (11) `migrate_step` NE RESTAURE JAMAIS UNE VERSION QU'IL N'A PAS LUE, ET NE DIT JAMAIS « 1 » POUR « NON LUE ».
    // -------------------------------------------------------------------------------------

    const CJ10_CAUSE_AVANT: &str = "version d'avant l'étape NON LUE, l'étape n'est pas jouée et rien n'est réécrit dans `meta`";
    const CJ10_CAUSE_ESTAMPILLE: &str = "estampille de l'étape NON RELUE après son corps, l'étape n'est pas commitée";

    /// Une base MIGRÉE, estampillée à la version d'avant la dernière étape (la chaîne ne joue donc que v126, étape
    /// idempotente), avec un déclencheur qui COMPTE chaque `UPDATE` de `meta` qui reste en base (`cj10_reecritures`) :
    /// une réécriture annulée par un ROLLBACK n'y laisse rien, une restauration jouée hors transaction y laisse une ligne.
    fn cj10_base_a_la_veille(nom: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let (t, p) = eso_base_migree(nom);
        cj1_poser_l_estampille(
            &p,
            &format!(
                "UPDATE meta SET value='{}' WHERE key='schema_version'; CREATE TABLE cj10_reecritures(n INTEGER); \
                 CREATE TRIGGER cj10_trace AFTER UPDATE ON meta BEGIN INSERT INTO cj10_reecritures(n) VALUES(1); END;",
                CODE_SCHEMA_MAX - 1
            ),
        );
        (t, p)
    }

    /// Installe un autorisateur qui COMPTE les lectures de `meta.value` (rang à partir de un, dans l'ordre où la
    /// connexion les prépare) et REFUSE celles dont le rang est dans `refusees` ; rend le compteur.
    fn cj10_compter_et_refuser(c: &Connection, refusees: Vec<usize>) -> Arc<std::sync::atomic::AtomicUsize> {
        let vues = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compteur = vues.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "meta", column_name: "value" } => {
                let rang = compteur.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if refusees.contains(&rang) { Authorization::Deny } else { Authorization::Allow }
            }
            _ => Authorization::Allow,
        }));
        vues
    }

    /// La chaîne de migrations (`migrate()`) jouée sous l'autorisateur ; rend son verdict et le nombre de lectures de
    /// `meta.value` qu'elle a préparées.
    fn cj10_migrer(p: &str, refusees: Vec<usize>) -> (bool, usize) {
        let c = crate::db_open::open_db(p).unwrap();
        let vues = cj10_compter_et_refuser(&c, refusees);
        let ok = crate::migrate::migrate(&c);
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        (ok, vues.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// L'estampille telle que la base la porte APRÈS le geste, et le nombre de réécritures de `meta` restées en base.
    fn cj10_apres(p: &str) -> (String, i64) {
        let c = crate::db_open::open_db(p).unwrap();
        let v: String = c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("fixture : estampille relue");
        let n: i64 = c.query_row("SELECT COUNT(*) FROM cj10_reecritures", [], |r| r.get(0)).expect("fixture : réécritures comptées");
        (v, n)
    }

    /// La cause que le moteur rend quand l'autorisateur refuse la lecture de `meta.value` (sqlite3.c : « access to
    /// %z is prohibited » sur un SQLITE_READ refusé).
    fn cj10_moteur_de_l_estampille_refusee() -> String {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO meta VALUES('schema_version','1');").unwrap();
        cj10_compter_et_refuser(&c, vec![1]);
        c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
            .expect_err("fixture : la lecture est refusée")
            .to_string()
    }

    /// La ligne d'échec d'étape d'`abort_step`, entière, pour v126.
    fn cj10_ligne_d_echec(cause: &str, version_relue: &str) -> String {
        cj10_ligne_d_echec_de(CODE_SCHEMA_MAX, cause, version_relue)
    }

    /// La ligne d'échec d'étape d'`abort_step`, entière, pour l'étape `cible`.
    fn cj10_ligne_d_echec_de(cible: i64, cause: &str, version_relue: &str) -> String {
        format!(
            "[migration] v{cible} ÉCHEC ({cause}) — le message « schéma -> v{cible} » éventuellement affiché \
             ci-dessus est ANNULÉ ; version RELUE en base : {version_relue}, étape RE-TENTÉE au prochain démarrage (migrate interrompu)"
        )
    }

    /// CE QU'IL TIENT : le contrat de schéma (`prepare_schema`) sur une base à la veille de la dernière étape, dont la
    /// version d'avant l'étape ne se lit plus (toutes les lectures de `meta.value` refusées à partir de celle-là) : il
    /// REFUSE, sa phrase dit `schema_version=NON LUE` — jamais « 1 » —, l'estampille reste celle d'avant et aucune
    /// réécriture de `meta` n'est restée en base. Le rang de la lecture refusée est DÉRIVÉ d'un passage nominal sur une
    /// base jumelle (la version d'avant l'étape est l'avant-dernière lecture d'un contrat qui réussit) ; ce passage
    /// nominal est le contrôle positif.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ10_AVANT` (la version non lue rendue à « 1 » et l'étape jouée), `CJ10_DECRIT`
    /// (la version non lue décrite « 1 » dans un message).
    #[test]
    fn cj10_le_contrat_dit_la_version_non_lue_sans_chiffre_et_ne_reecrit_rien() {
        let (_t1, jumelle) = cj10_base_a_la_veille("cj10-contrat-nominal");
        let n = {
            let c = crate::db_open::open_db(&jumelle).unwrap();
            let vues = cj10_compter_et_refuser(&c, vec![]);
            let r = crate::migrate::prepare_schema(&c);
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert_eq!(r, Ok(()), "contrôle : le contrat nominal passe");
            vues.load(std::sync::atomic::Ordering::SeqCst)
        };
        assert!(n >= 4, "contrôle : entrée du contrat, chaîne, version d'avant et estampille lues ({n})");
        assert_eq!(cj10_apres(&jumelle), (CODE_SCHEMA_MAX.to_string(), 1), "contrôle : l'étape est commitée, une réécriture");

        let (_t2, p) = cj10_base_a_la_veille("cj10-contrat-non-lu");
        let refus = {
            let c = crate::db_open::open_db(&p).unwrap();
            cj10_compter_et_refuser(&c, (n - 1..n + 32).collect());
            let r = crate::migrate::prepare_schema(&c);
            c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            r
        };
        assert_eq!(
            refus,
            Err(format!(
                "migration INTERROMPUE (cause détaillée ci-dessus) — base en schema_version=NON LUE alors que ce binaire \
                 attend v{CODE_SCHEMA_MAX} : le schéma est INCOMPLET. La migration sera RE-TENTÉE au prochain démarrage"
            )),
            "le refus dit la version NON LUE, jamais un chiffre"
        );
        assert_eq!(cj10_apres(&p), ((CODE_SCHEMA_MAX - 1).to_string(), 0), "rien n'est réécrit dans `meta`");
    }

    /// Une base MIGRÉE et estampillée `CODE_SCHEMA_MAX` (aucune étape ne se rejoue) dont la table `net_ban` — que seule
    /// l'étape v111 crée, `db/schema.sql` ne la déclare pas — est supprimée : le contrat de schéma y voit un manque.
    fn cj10_base_a_jour_sans_net_ban(nom: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let (t, p) = eso_base_migree(nom);
        cj1_poser_l_estampille(&p, "DROP TABLE net_ban;");
        (t, p)
    }

    /// Le contrat de schéma joué sous l'autorisateur ; rend son verdict et le nombre de lectures de `meta.value`.
    fn cj10_contrat(p: &str, refusees: Vec<usize>) -> (Result<(), String>, usize) {
        let c = crate::db_open::open_db(p).unwrap();
        let vues = cj10_compter_et_refuser(&c, refusees);
        let r = crate::migrate::prepare_schema(&c);
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        (r, vues.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// CE QU'IL TIENT : le SECOND refus du contrat de schéma — celui des manques, après une chaîne menée au bout — dit
    /// `schema_version=NON LUE` quand la relecture faite pour son message n'a pas lieu, jamais « 1 ». Le rang refusé est
    /// DÉRIVÉ d'un passage sur une base jumelle : la relecture du message est la DERNIÈRE lecture de `meta.value` du
    /// contrat (ses arguments s'évaluent après `schema_gaps`). Ce passage, qui refuse en disant la version LUE et nomme
    /// la table, est le contrôle positif ; le refus non lu lui est comparé ENTIER, la version seule diffère. L'estampille
    /// n'est pas réécrite et la table n'est pas recréée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ10_CONTRAT_MANQUES` (ce seul site rend « 1 » pour une version non lue).
    #[test]
    fn cj10_le_refus_des_manques_dit_la_version_non_lue_sans_chiffre() {
        let (_t1, jumelle) = cj10_base_a_jour_sans_net_ban("cj10-manques-lu");
        let (lu, n) = cj10_contrat(&jumelle, vec![]);
        let lu = lu.expect_err("contrôle : la table supprimée est un manque");
        let tete_lue = format!("base estampillée schema_version={CODE_SCHEMA_MAX} mais ");
        assert!(lu.starts_with(&tete_lue) && lu.contains("table net_ban"), "contrôle : refus des manques, version lue : {lu}");
        assert!(n >= 3, "contrôle : entrée du contrat, chaîne et message lus ({n})");

        let (_t2, p) = cj10_base_a_jour_sans_net_ban("cj10-manques-non-lu");
        let (refus, vues) = cj10_contrat(&p, vec![n]);
        assert_eq!(vues, n, "même parcours que la jumelle, sa dernière lecture refusée");
        assert_eq!(
            refus,
            Err(lu.replacen(&tete_lue, "base estampillée schema_version=NON LUE mais ", 1)),
            "le refus des manques dit la version NON LUE, jamais un chiffre"
        );
        let c = crate::db_open::open_db(&p).unwrap();
        let v: String = c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("fixture : estampille relue");
        assert_eq!(v, CODE_SCHEMA_MAX.to_string(), "l'estampille n'est pas réécrite");
        let recreee: i64 = c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='net_ban'", [], |r| r.get(0)).unwrap();
        assert_eq!(recreee, 0, "le contrat constate, il ne recrée rien");
    }

    /// CE QU'IL TIENT : la relecture du moteur de migration (`relire_la_version_de_schema`) rend ses trois issues, la
    /// valeur non entière comprise — bras qu'aucun appelant de production n'atteint aujourd'hui (la porte, l'entrée du
    /// contrat et la chaîne refusent avant `migrate_step` une estampille non entière, et chaque étape estampille un
    /// entier), tenu ici pour ce qu'il rend : une version NON LUE avec la valeur brute, jamais un nombre.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ10_RELUE_ENTIER` (la valeur non entière rendue lue à « 1 »).
    #[test]
    fn cj10_la_version_relue_par_le_moteur_a_trois_issues() {
        use crate::migrate::{relire_la_version_de_schema, VersionDeSchemaRelue};
        let issue = |c: &Connection| match relire_la_version_de_schema(c) {
            VersionDeSchemaRelue::Lue(v) => format!("lue {v}"),
            VersionDeSchemaRelue::Absente => "absente".to_string(),
            VersionDeSchemaRelue::NonLue(cause) => format!("non lue : {cause}"),
        };
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);").unwrap();
        assert_eq!(issue(&c), "absente", "aucune ligne : absence établie");
        c.execute("INSERT INTO meta VALUES('schema_version','42')", []).unwrap();
        assert_eq!(issue(&c), "lue 42", "contrôle : un entier se lit");
        c.execute("UPDATE meta SET value='abc' WHERE key='schema_version'", []).unwrap();
        assert_eq!(issue(&c), "non lue : la ligne `meta.schema_version` ne porte pas un entier : \"abc\"", "valeur non entière");
        c.execute_batch("DROP TABLE meta;").unwrap();
        assert_eq!(issue(&c), "non lue : no such table: meta", "lecture qui n'a pas lieu");
    }

    /// Un fichier qui ne porte que `meta`, sans ligne `schema_version` : la forme legacy que la chaîne reprend à la
    /// version un (`JamaisEstampillee`).
    fn cj10_base_meta_seule(nom: &str) -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(nom);
        let chemin = tmp.sous("plume.db").chemin().to_path_buf();
        let _ = std::fs::remove_file(&chemin);
        let p = chemin.to_str().unwrap().to_string();
        cj1_poser_l_estampille(&p, "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);");
        (tmp, p)
    }

    // -------------------------------------------------------------------------------------
    // (12) LA FICHE DE RUNBOOKS D'UN DOSSIER — sa lecture ratée est déjà un 503 nommé, jamais une absence.
    // -------------------------------------------------------------------------------------

    const CJ10_VIEWER: &str = "vwr:viewerpw12345";
    const CJ10_DOSSIER_INTROUVABLE: &str = "DOSSIER INTROUVABLE : aucun dossier ne porte cet identifiant (la lecture a abouti \
         et n'a trouvé aucune ligne). Rien n'a été fait.";
    const CJ10_DOSSIER_NON_LU: &str = "DOSSIER NON LU, GESTE NON FAIT : la base n'a pas pu dire si ce dossier existe \
         (lecture refusée ou table illisible) — ce n'est PAS « dossier introuvable ». Rien n'est écrit, ni dans le dossier \
         ni au registre. Réessayez.";

    /// GET par le routeur réel avec le rôle le plus faible admis (viewer) : statut et corps JSON.
    async fn cj10_get(addr: std::net::SocketAddr, chemin: &str) -> (u16, Value) {
        let authz = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(CJ10_VIEWER));
        let (code, brut) = router_probe_envoi(addr, "GET", chemin, Some(&authz), &[], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, if corps.is_empty() { Value::Null } else { serde_json::from_str(&corps).unwrap_or(Value::String(corps)) })
    }

    /// CE QU'IL TIENT (par la route, rôle viewer) : `GET /api/cases/{id}/runbooks` sur un dossier dont l'existence se
    /// lit mais dont la ligne lue par `case_runbooks_json` ne se lit pas (`incident_type` en BLOB) sert le 503 nommé
    /// `{error, id}` de la lecture de dossier non faite — ni un 404, ni une fiche vide en 200. Contrôles : le dossier
    /// lisible sert sa fiche (200), un dossier absent garde son 404 d'avant, et la ligne remise rend la fiche d'avant.
    /// C'est ce qui reclasse le `.ok()?` de `case_runbooks_json` parmi les arbitrages assumés de la garde des lectures
    /// d'une ligne : son unique appelant de production ne sert jamais son `None` comme une absence.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ10_FICHE` (le `None` servi en 404 « dossier introuvable »).
    #[tokio::test]
    async fn cj10_la_fiche_de_runbooks_d_un_dossier_non_lu_est_un_503_jamais_une_absence() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _base) = router_test_state("cj10-fiche");
        let dossier = dossier_seme(&st.db.lock(), "adm", "intrusion", 4, "", None, 2);
        let origine: String = st
            .db
            .lock()
            .query_row("SELECT quote(incident_type) FROM incident WHERE id=?1", params![dossier], |r| r.get(0))
            .expect("fixture : type d'incident lu");
        let addr = router_serve(st.clone()).await;
        let chemin = format!("/api/cases/{dossier}/runbooks");

        let nominal = cj10_get(addr, &chemin).await;
        assert_eq!(nominal.0, 200, "contrôle : la fiche se lit : {:?}", nominal.1);
        assert!(nominal.1.get("available").is_some(), "contrôle : c'est la fiche de runbooks : {:?}", nominal.1);
        assert_eq!(
            cj10_get(addr, &format!("/api/cases/{}/runbooks", dossier + 99_999)).await,
            (404, json!({ "error": CJ10_DOSSIER_INTROUVABLE })),
            "absence établie : le 404 d'avant, à l'octet"
        );

        st.db.lock().execute("UPDATE incident SET incident_type=x'00' WHERE id=?1", params![dossier]).expect("fixture : ligne illisible");
        let (statut, corps) = cj10_get(addr, &chemin).await;
        cj1_cinq_cent_trois("fiche de runbooks, ligne du dossier illisible", statut, &corps, CJ10_DOSSIER_NON_LU);

        st.db
            .lock()
            .execute_batch(&format!("UPDATE incident SET incident_type={origine} WHERE id={dossier};"))
            .expect("fixture : ligne remise");
        assert_eq!(cj10_get(addr, &chemin).await, nominal, "rétabli : la fiche d'avant");
    }

    // -------------------------------------------------------------------------------------
    // (13) LES LIGNES DE JOURNAL — capturées dans un processus enfant, comparées ENTIÈRES.
    // -------------------------------------------------------------------------------------

    const CJ10_ENFANT: &str = "CJ10_ENFANT_JOURNAL";
    const CJ10_PHASE: &str = "CJ10-PHASE:";
    const CJ10_PREFIXE_CONTROLES: &str = "[controles]";

    /// CE QU'IL TIENT : (a) l'ingestion d'un rapport de contrôles écrit au journal UNE ligne entière, avec la cause du
    /// moteur, quand l'état précédent n'est pas lu ou que son jour n'est pas calculé par le moteur ; aucune ligne quand
    /// la série n'a pas d'autre état, quand l'état précédent est lu, ni quand le jour est hors du calendrier (NULL, aucune
    /// erreur). (b) La chaîne de migrations, sur une base à la veille de la dernière étape, sous un autorisateur qui
    /// refuse des lectures de `meta.value` par leur rang (ordre de préparation : 1 la chaîne, 2 la version d'avant
    /// l'étape, 3 l'estampille après le corps, 4 et 5 les deux lectures de la restauration, 6 celle du message d'échec) :
    ///   * nominal : trois lectures, l'étape commitée, aucune ligne d'échec ;
    ///   * 2 et 3 refusées : l'étape n'est PAS jouée, la ligne d'échec nomme la version d'avant non lue et dit la version
    ///     relue « NON LUE », l'estampille reste celle d'avant et rien n'est réécrit (avant ce lot : « 1 » réécrit) ;
    ///   * 3 refusée : l'étape n'est pas commitée, la ligne d'échec nomme l'estampille non relue, version relue lue ;
    ///   * 3 et 4 refusées : la restauration RÉÉCRIT la version d'avant (lue) — une réécriture restée en base ;
    ///   * 3 et 5 refusées : la ligne d'anomalie dit l'estampille NON RELUE après sa remise, avec la cause du moteur.
    /// (c) La chaîne sur un fichier qui ne porte que `meta`, sans ligne (forme legacy, reprise à la version un) : la
    /// ligne ABSENTE n'est pas une lecture ratée — l'étape v2 est jouée, échoue faute d'estampille posée, et sa ligne
    /// d'échec dit la version relue « 1 » ; six lectures, rien d'écrit dans `meta`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ10_ETAT_JOURNAL`, `CJ10_JOUR_JOURNAL` (la ligne retirée), `CJ10_AVANT`,
    /// `CJ10_DECRIT`, `CJ10_ESTAMPILLE` (l'estampille non relue décrite « non estampillée »), `CJ10_COMMIT` (l'estampille
    /// non relue prise pour posée), `CJ10_RESTAURE` (la version d'avant non réécrite sur une relecture ratée),
    /// `CJ10_ANOMALIE` (la relecture ratée tue), `CJ10_AVANT_ABSENTE` (une version d'avant ABSENTE traitée comme non
    /// lue : l'étape n'est pas jouée), `CJ10_DECRIT_ABSENTE` (une ligne absente décrite « NON LUE »).
    #[test]
    fn cj10_la_cause_d_une_lecture_non_faite_va_au_journal_ligne_entiere() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CJ10_ENFANT).is_ok() {
            let mut attendus = serde_json::Map::new();
            let (moteur_reel, moteur_jour) = (cj10_moteur_de_l_instant_reel(), cj10_moteur_du_jour_refuse());
            for (phase, prealable, refuser, lignes) in [
                ("c_jamais", "", false, vec![]),
                ("c_lu", CJ10_ETAT_LU, false, vec![]),
                ("c_illisible", CJ10_ETAT_ILLISIBLE, false, vec![format!("{CJ10_LIGNE_ETAT_NON_LU}{moteur_reel}")]),
                ("c_hors_calendrier", CJ10_ETAT_HORS_CALENDRIER, false, vec![]),
                ("c_jour_refuse", CJ10_ETAT_LU, true, vec![format!("{CJ10_LIGNE_JOUR_NON_CALCULE}{moteur_jour}")]),
            ] {
                eprintln!("{CJ10_PHASE}{phase}");
                let _ = cj10_titre_apres(prealable, refuser);
                attendus.insert(phase.into(), json!({ "prefixe": CJ10_PREFIXE_CONTROLES, "lignes": lignes }));
            }

            let moteur = cj10_moteur_de_l_estampille_refusee();
            let veille = (CODE_SCHEMA_MAX - 1).to_string();
            let prefixe = format!("[migration] v{CODE_SCHEMA_MAX} ");
            let echec_estampille = cj10_ligne_d_echec(&format!("{CJ10_CAUSE_ESTAMPILLE} ({moteur})"), &veille);
            for (phase, refusees, verdict, lectures, apres, lignes) in [
                ("m_nominal", vec![], true, 3, (CODE_SCHEMA_MAX.to_string(), 1), vec![]),
                (
                    "m_avant",
                    vec![2, 3],
                    false,
                    3,
                    (veille.clone(), 0),
                    vec![cj10_ligne_d_echec(&format!("{CJ10_CAUSE_AVANT} ({moteur})"), "NON LUE")],
                ),
                ("m_estampille", vec![3], false, 6, (veille.clone(), 0), vec![echec_estampille.clone()]),
                ("m_restauration", vec![3, 4], false, 6, (veille.clone(), 1), vec![echec_estampille.clone()]),
                (
                    "m_relue",
                    vec![3, 5],
                    false,
                    6,
                    (veille.clone(), 0),
                    vec![
                        echec_estampille.clone(),
                        format!(
                            "[migration] v{CODE_SCHEMA_MAX} ANOMALIE GRAVE : schema_version n'a PAS pu être RELUE après sa remise \
                             à {veille} ({moteur}) — la base est peut-être estampillée pour un schéma qu'elle n'a pas. Restaurer \
                             la sauvegarde antérieure."
                        ),
                    ],
                ),
            ] {
                let (_t, p) = cj10_base_a_la_veille(&format!("cj10-{phase}"));
                eprintln!("{CJ10_PHASE}{phase}");
                let (ok, vues) = cj10_migrer(&p, refusees);
                assert_eq!((ok, cj10_apres(&p)), (verdict, apres), "{phase} : verdict de la chaîne, estampille et réécritures");
                assert_eq!(vues, lectures, "{phase} : lectures de `meta.value` préparées (le rang des refus en dépend)");
                attendus.insert(phase.into(), json!({ "prefixe": prefixe, "lignes": lignes }));
            }
            {
                let (_t, p) = cj10_base_meta_seule("cj10-m_absente");
                eprintln!("{CJ10_PHASE}m_absente");
                let (ok, vues) = cj10_migrer(&p, vec![]);
                let lignes_meta: i64 = crate::db_open::open_db(&p)
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM meta", [], |r| r.get(0))
                    .expect("fixture : lignes de `meta` comptées");
                assert_eq!((ok, vues, lignes_meta), (false, 6, 0), "m_absente : verdict, lectures de `meta.value`, rien d'écrit");
                attendus.insert(
                    "m_absente".into(),
                    json!({
                        "prefixe": "[migration] v2 ",
                        "lignes": [cj10_ligne_d_echec_de(2, "schema_version non estampillée à 2", "1")],
                    }),
                );
            }
            eprintln!("{CJ10_PHASE}fin");
            println!("CJ10-ATTENDUS:{}", Value::Object(attendus));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lectures_d_une_ligne_du_plan_de_controle_et_de_l_estampille::cj10_la_cause_d_une_lecture_non_faite_va_au_journal_ligne_entiere",
            ])
            .env(CJ10_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (ses assertions tiennent) : {stdout}\n{stderr}");
        let reste = stdout.split_once("CJ10-ATTENDUS:").unwrap_or_else(|| panic!("contrôle : attendus : {stdout}")).1;
        let attendus: serde_json::Map<String, Value> =
            serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : attendus JSON ({e}) : {stdout}"));
        assert!(attendus.len() >= 11, "plancher : onze phases jouées, {} rendues", attendus.len());
        for (nom, attendu) in &attendus {
            let debut = stderr.split_once(&format!("{CJ10_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let fenetre = debut.split_once(CJ10_PHASE).map(|(c, _)| c).unwrap_or(debut);
            let prefixe = attendu["prefixe"].as_str().unwrap_or_else(|| panic!("contrôle : préfixe de {nom}"));
            let vues: Vec<Value> = fenetre.lines().filter(|l| l.starts_with(prefixe)).map(|l| json!(l)).collect();
            assert_eq!(&Value::Array(vues), &attendu["lignes"], "phase {nom} : chaque ligne de journal entière");
        }
    }
}
