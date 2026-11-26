// =====================================================================================
// `P10.20-b` — LES DERNIERS APPELANTS DE LA PROJECTION À DEUX ISSUES DU CATALOGUE DES TENANTS (`handle_for`) DÉCIDENT DE
// LA LIGNE NON LUE, ET LA LISTE DES TENANTS ACTIFS DES TÂCHES DE FOND EST LUE EN BLOC.
//
// CE QUI A ÉTÉ MESURÉ AVANT LE CORRECTIF, SITE PAR SITE :
//   * récepteurs Pub/Sub et Firehose (`handle_for(tenant).unwrap_or_else(|| st.db.clone())`) : le repli sur la base du
//     processus n'est PAS atteignable par la route — `push_token_connector_lu` (state.rs) rend `Absent` dès qu'un plan
//     de contrôle existe, la livraison est refusée à la clé (Pub/Sub 401, Firehose 403) avant toute lecture du
//     connecteur, et le tenant porteur vaut toujours `default`. Témoin (1), par les deux routes. Le repli restait écrit :
//     la base est désormais choisie par `base_de_la_livraison_push_lu`, en trois issues, sans base du processus à la
//     place de celle du tenant ; ses deux bras de refus sont HORS D'ATTEINTE par la route et témoignés par appel direct (2) ;
//   * `for_each_active_tenant` : une liste non lue rendait une liste VIDE, une ligne indécodable était avalée par
//     `.flatten()` — le tour de tous les tenants, ou de ceux qui suivaient, était sauté sans un mot (3), (8). Et une
//     liste refusée en bloc n'appelait aucun corps : les boucles qui publient un bilan (règles, connecteurs,
//     destinations, rapports, rétention, risque) publiaient `Lue(0)`, la santé restait verte. Le parcours rend désormais
//     l'aveu de la liste non lue, que chacune absorbe avant de publier (3), (9), (10), (W4) ;
//   * inventaire des accès (`acces_observe::consigner_l_acces`) : rien n'était écrit (conduite juste), la ligne non lue
//     passait pour « tenant non résoluble » (4), (8) ; tenant non servable (suspendu, absent) : rien n'est écrit (11) ;
//   * événement d'accès opérateur (`rbac::poser_l_evenement_du_tenant`) : la trace perdue était comptée sous « base du
//     tenant non résoluble » (5) ;
//   * événement d'audit du tenant (`rbac::audit_tenant_event`) : la ligne non lue rendait `SansBaseServie`, servi sous
//     une phrase qui AFFIRME que la base de ce tenant n'est pas servie (6), (8) ;
//   * poignée prise avant la suspension (`tenants::tenant_set_suspended`) : la ligne non lue valait « base qui ne se
//     résolvait déjà pas », la bascule passait et l'événement, cherché après elle, était perdu (7), (8).
//
// LA VOIE D'ÉCHEC : la ligne du tenant illisible (`key_ref` en BLOB : les lectures d'existence et la bascule passent,
// seule la lecture du catalogue qui sert une base échoue) ; pour la liste, la table retirée (préparation), une vue
// temporaire qui échoue au premier pas (`json_each` d'un texte qui n'est pas du JSON) et une ligne dont l'identifiant
// est un BLOB, placée entre deux tenants lisibles.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` et `VERIF_MUT`, retirés avant le commit), chacun vu rouge seul :
// `CJ7_CLE_PUSH_MODE_UN` (state.rs : la clé push lue aussi en mode multi-tenant) : (1) ; `CJ7_PUSH_REPLI_ABSENT`,
// `CJ7_PUSH_REPLI_NON_LU` (le tenant non servable, la ligne non lue servis par la base du processus),
// `CJ7_PUSH_NON_LU_ABSENT` (la ligne non lue rendue comme un tenant non servable), `CJ7_PUSH_TOUJOURS_PROCESSUS` (la
// base du processus servie au tenant servable) : (2) ; `CJ7_LISTE_FLATTEN` (la ligne indécodable avalée) : (3) ;
// `CJ7_LISTE_LIGNE_TUE`, `CJ7_LISTE_CHAQUE_FOIS`, `CJ7_LISTE_JAMAIS_OUBLIE`, `CJ7_LISTE_NON_COMPTEE`,
// `CJ7_LISTE_TOTAL_NON_COMPTE` : (8) ; `CJ7_ACCES_REPLI` (l'accès inscrit dans la base du processus) : (4) ;
// `CJ7_ACCES_LIGNE_TUE` : (8) ; `CJ7_TRACE_CAUSE` (la cause d'avant), `CJ7_TRACE_REPLI` (l'événement posé dans la base du
// processus) : (5) ; `CJ7_AUDIT_SANS_BASE` (la ligne non lue rendue `SansBaseServie`), `CJ7_AVOUER_MUET` (la troisième
// issue non avouée), `CJ7_RETRAIT_204` (le retrait garde son deux cent quatre nu) : (6) ; `CJ7_AUDIT_LIGNE_TUE` : (8) ;
// `CJ7_SUSPENSION_POURSUIT` (la bascule passe sur la poignée non lue) : (7) ; `CJ7_SUSPENSION_LIGNE_TUE` : (8) ;
// `CJ7_LISTE_PAS_VIDE` (le pas du moteur en échec rendu comme une liste vide) : (3) ; `CJ7_PARCOURS_MUET` (la liste non
// lue rend `Lue(0)`) : (3), (9) ; `CJ7_TOUR_SANS_PARCOURS` (le tour commun n'absorbe pas l'aveu du parcours) : (9) ;
// `CJ7_RISQUE_SANS_PARCOURS`, `CJ7_RETENTION_SANS_PARCOURS`, et dans la source `V_RISQUE_ORDRE` (deux formes) et
// `V_RET_ORDRE` (l'absorption après la mesure publiée) : (10) ; `V_RET_ORDRE` posé à l'exécution (la mesure de la
// rétention prise avant l'absorption) : (W4) ; `V_ACCES_NONSERV_REPLI` (le tenant non servable inscrit dans la base du
// processus) : (11).
//
// CE QUI EST TENU PAR COMPORTEMENT : (1) à (9), (11), et la passe de rétention en mode multi-tenant, mesure rendue ET
// mesure publiée sur une liste non lue, avec son contrôle (W4, dans le module de témoins de
// `server/boucles_de_fond.rs`, où vit le verrou de la clé `retention` que ses voisins relisent). CE QUI EST TENU PAR
// GARDE DE SOURCE SEULEMENT (10) : le câblage des boucles au parcours, et l'ordre dans le bloc de la boucle du risque
// (fil sans fin, aucun point d'appel sans refonte) ; l'ordre du tour commun et de la rétention y est jugé aussi.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les deux bras de refus des récepteurs push (403 d'un tenant non servable, 503
// nommé d'une ligne non lue), hors d'atteinte par la route tant que les clés push n'existent pas en mode multi-tenant,
// ni leurs lignes de journal ; une ligne non lue à l'inventaire des accès consomme la fenêtre de débounce de cet accès,
// comme un tenant non servable (il n'est pas retenté avant elle) ; la clé de tenant non résolue pour une cause passagère
// (coffre injoignable) rend toujours « non servable ». Les mutants qui remettent le repli sur la base du processus dans
// ces deux bras des gestionnaires push restent verts : ils sont ÉQUIVALENTS tant que la route refuse à la clé.
// Les boucles de fond elles-mêmes (fils sans fin) ne sont jouées par aucun témoin : leur câblage et l'ordre du bloc du
// risque sont tenus sur la source (10), leur tour commun et l'aveu par comportement (9), la passe de rétention par (W4) ; une liste illisible d'une seule ligne arrête le tour de
// tous les tenants (refus en bloc), et c'est ce que la santé dit désormais, en rouge.
// =====================================================================================
mod catalogue_non_lu_aux_derniers_appelants_de_la_projection {
    use super::*;

    const CJ7_A: &str = "cj7-a";
    const CJ7_B: &str = "cj7-b";
    const CJ7_FANTOME: &str = "cj7-fantome";
    const CJ7_ENFANT: &str = "CJ7_ENFANT_LIGNES_DES_DERNIERS_APPELANTS";
    const CJ7_PHASE: &str = "CJ7-PHASE:";
    /// Les causes du moteur : `key_ref` en BLOB lu en TEXT, la table retirée, un identifiant en BLOB.
    const CJ7_CAUSE_BLOB: &str = "Invalid column type Blob at index: 1, name: key_ref";
    const CJ7_CAUSE_TABLE: &str = "no such table: tenant";
    const CJ7_CAUSE_ID_BLOB: &str = "Invalid column type Blob at index: 0, name: id";
    /// Le pas du moteur en échec : `json_each` d'un texte qui n'est pas du JSON.
    const CJ7_CAUSE_PAS: &str = "malformed JSON";
    const CJ7_BALAYAGE: &str = "tenants_actifs";
    /// LES PHRASES, écrites ici en toutes lettres : le témoin ne compare jamais une sortie de la production à elle-même.
    const CJ7_BASCULE_NON_FAITE: &str = "TENANT NON LU, BASCULE NON FAITE : le plan de contrôle n'a pas pu lire le tenant \
         visé — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. Le tenant garde l'état qu'il avait \
         (suspendu ou actif), rien n'est tracé. Réessayez une fois le plan de contrôle de nouveau lisible.";
    const CJ7_EVENEMENT_CATALOGUE_NON_LU: &str = "ÉVÉNEMENT DU TENANT NON ÉCRIT : le geste d'administration a bien eu \
         lieu, mais le plan de contrôle n'a pas pu relire la ligne de ce tenant pour lui servir sa base — l'événement \
         d'audit qui le lui montre n'y a pas été écrit, et ce tenant ne verra pas ce changement parmi ses propres \
         événements. Refaire le geste ne le comble pas : signalez-le.";

    fn cj7_ligne_liste(cause: &str) -> String {
        format!(
            "[multi-tenant][jobs] liste des tenants actifs NON LUE ({cause}) -> AUCUN tenant n'est exécuté à ce tour, ni \
             sur sa base ni sur la base default, et aucun n'est exécuté sur une liste partielle. Dit une fois jusqu'à la \
             prochaine lecture entière de la liste ; chaque tour sauté est compté parmi les balayages de fond aveugles \
             (tenants_actifs)."
        )
    }
    fn cj7_ligne_acces(tenant: &str, methode: &str, cause: &str) -> String {
        format!(
            "[acces_observe] tenant '{tenant}' : ligne du catalogue des tenants NON LUE ({cause}) -> accès par « {methode} » \
             NON inscrit à l'inventaire, ni dans sa base ni dans celle d'un autre"
        )
    }
    fn cj7_ligne_audit(action: &str, tenant: &str, cause: &str) -> String {
        format!(
            "[tenants] WARN événement d'audit '{action}' NON écrit : ligne du catalogue des tenants NON LUE pour '{tenant}' \
             ({cause}) -> aucune base servie à cet événement, ni la sienne ni celle d'un autre"
        )
    }
    fn cj7_ligne_suspension(tenant: &str, cause: &str) -> String {
        format!("[tenants] WARN tenant '{tenant}' : ligne du catalogue des tenants NON LUE avant la bascule de suspension (poignée de sa base) : {cause}")
    }

    /// Un plan de contrôle, le tenant `default`, deux tenants réels provisionnés avec leur base (`cj7-a`, `cj7-b`).
    fn cj7_etat() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (st, dir) = mk_mode1_state();
        for t in [CJ7_A, CJ7_B] {
            let chemin = String::from(&*dir.sous(&format!("{t}.db")));
            assert!(tenant_provision(&st.tenants, t, t, &chemin, "").is_ok(), "fixture : {t} provisionné");
        }
        (st, dir)
    }

    fn cj7_plan(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cj7_compte_plan(st: &AppState, sql: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn cj7_illisible(st: &AppState, t: &str) {
        cj7_plan(st, &format!("UPDATE tenant SET key_ref=X'00' WHERE id='{t}';"));
    }
    fn cj7_lisible(st: &AppState, t: &str) {
        cj7_plan(st, &format!("UPDATE tenant SET key_ref='' WHERE id='{t}';"));
    }

    fn cj7_compte(h: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        h.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("contrôle : `{sql}` se lit ({e})"))
    }
    fn cj7_base(st: &AppState, t: &str) -> Arc<Mutex<Connection>> {
        st.tenants.handle_for(t).unwrap_or_else(|| panic!("contrôle : base de {t} servie"))
    }

    // -------------------------------------------------------------------------------------
    // (1) LES RÉCEPTEURS PUSH, PAR LA ROUTE — le repli sur la base du processus n'est pas atteignable.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par les deux routes : une source push (clé ET connecteur) vit dans la base du processus. Mode 0 :
    /// la livraison est servie et spoolée sous l'environnement de CE connecteur (contrôle positif : l'observable vit).
    /// Le même état passé en mode multi-tenant (plan de contrôle posé, rien d'autre ne change) : Pub/Sub rend son 401
    /// d'avant, Firehose son 403 d'avant, corps entiers, et rien de plus n'est spoolé — aucun réglage du connecteur de
    /// la base du processus n'est appliqué, puisque la livraison est refusée à la clé, avant toute lecture du connecteur.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ7_CLE_PUSH_MODE_UN` (la clé lue aussi en mode multi-tenant : le tenant porteur
    /// `default` n'est pas servable ici, 403 au lieu de 401 pour Pub/Sub, `errorMessage` d'un binding cassé pour Firehose).
    #[tokio::test]
    async fn cj7_en_mode_multi_tenant_la_livraison_push_est_refusee_a_la_cle_sans_rien_lire_de_la_base_du_processus() {
        // Pub/Sub.
        let (mut st, spool) = ps_state_with_spool();
        let (_cid, cle) = ps_mk_push_source(&st, "cj7-proc").await;
        let corps = || ps_envelope(&ps_b64(&gcp_logentry("cj7-ps", "v1.compute.instances.insert", "203.0.113.7").to_string()));
        let (code, v) = pb_json(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&cle), corps()).await).await;
        assert_eq!(code, 200, "mode 0 : la livraison est servie ({v})");
        assert_eq!(ps_spool_count(&spool), 1, "mode 0 : une livraison spoolée");
        let lot: Value = std::fs::read_dir(&spool)
            .expect("spool lisible")
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("ps-"))
            .map(|e| serde_json::from_str(&std::fs::read_to_string(e.path()).expect("lot lisible")).expect("lot JSON"))
            .expect("lot spoolé");
        assert_eq!(lot["env_id"], json!("cj7-proc"), "mode 0 : le réglage du connecteur du processus est appliqué");
        let (cp, _plan) = mk_test_control();
        st.tenants.control = Some(cp);
        st.multi_tenant = true;
        let (code, v) = pb_json(pubsub_ingest_post(State(st.clone()), axum::http::HeaderMap::new(), ps_query(&cle), corps()).await).await;
        assert_eq!((code, &v), (401, &json!({ "error": "invalid or missing ?token= delivery token" })), "mode multi-tenant : refusée à la clé");
        assert_eq!(ps_spool_count(&spool), 1, "mode multi-tenant : rien de plus au spool");

        // Firehose.
        let (mut st, spool) = fh_state_with_spool();
        let (_cid, cle) = fh_mk_push_source(&st, "aws-guardduty", "cj7-proc").await;
        let finding = json!({ "Id": "cj7-fh", "UpdatedAt": "2026-07-01T10:00:00Z", "Severity": 5.0, "Title": "x" });
        let corps = || fh_body("cj7-req", &[fh_b64(&finding.to_string())]);
        let spoole = || std::fs::read_dir(&spool).expect("spool lisible").filter(|e| e.as_ref().expect("entrée").file_name().to_string_lossy().starts_with("fh-")).count();
        let (code, v) = pb_json(firehose_ingest_post(State(st.clone()), fh_headers(&cle), corps()).await).await;
        assert_eq!(code, 200, "mode 0 : la livraison est servie ({v})");
        assert_eq!(spoole(), 1, "mode 0 : une livraison spoolée");
        let (cp, _plan_fh) = mk_test_control();
        st.tenants.control = Some(cp);
        st.multi_tenant = true;
        let (code, v) = pb_json(firehose_ingest_post(State(st.clone()), fh_headers(&cle), corps()).await).await;
        assert_eq!(code, 403, "mode multi-tenant : refusée à la clé ({v})");
        let cles: std::collections::BTreeSet<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["errorMessage", "requestId", "timestamp"].into_iter().collect(), "corps Firehose entier : {v}");
        assert_eq!(v["errorMessage"], json!("invalid or missing X-Amz-Firehose-Access-Key"), "le refus d'une clé inconnue : {v}");
        assert_eq!(v["requestId"], json!(""), "le refus d'avant, sans écho : {v}");
        assert_eq!(spoole(), 1, "mode multi-tenant : rien de plus au spool");
    }

    // -------------------------------------------------------------------------------------
    // (2) LA BASE D'UNE LIVRAISON PUSH, PAR APPEL DIRECT — jamais celle du processus à la place de celle du tenant.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un connecteur push posé DANS LA BASE DU PROCESSUS sous un identifiant donné (contrôle : il s'y
    /// lit). Tenant A servable : sa base, pas celle du processus, et ce connecteur n'y est pas lu. B suspendu, tenant
    /// absent : `NonServable`. Ligne de A illisible : `CatalogueNonLu`, la cause du moteur portée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_PUSH_REPLI_ABSENT`, `CJ7_PUSH_REPLI_NON_LU`, `CJ7_PUSH_NON_LU_ABSENT`,
    /// `CJ7_PUSH_TOUJOURS_PROCESSUS`.
    #[test]
    fn cj7_la_base_d_une_livraison_push_n_est_jamais_celle_du_processus() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj7_etat();
        let cid = {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,created) \
                 VALUES('gcp_pubsub','cj7-processus',1,'{}','',0,'cj7-proc',?1)",
                params![now()],
            )
            .expect("fixture : connecteur dans la base du processus");
            c.last_insert_rowid()
        };
        assert!(
            matches!(connecteur_push_lie_lu(&st.db.lock(), cid), Ok(Some((ref t, _, ref env))) if t == "gcp_pubsub" && env == "cj7-proc"),
            "contrôle : le connecteur se lit dans la base du processus"
        );
        let base_a = cj7_base(&st, CJ7_A);
        match base_de_la_livraison_push_lu(&st, CJ7_A) {
            BaseDeLaLivraisonPush::Servie(h) => {
                assert!(Arc::ptr_eq(&h, &base_a), "A servable : SA base");
                assert!(!Arc::ptr_eq(&h, &st.db), "jamais la base du processus");
                assert!(matches!(connecteur_push_lie_lu(&h.lock(), cid), Ok(None)), "le connecteur du processus n'y est pas lu");
            }
            autre => panic!("A servable : sa base attendue ({autre:?})"),
        }
        cj7_plan(&st, &format!("UPDATE tenant SET suspended=1 WHERE id='{CJ7_B}';"));
        assert!(matches!(base_de_la_livraison_push_lu(&st, CJ7_B), BaseDeLaLivraisonPush::NonServable), "B suspendu : non servable");
        assert!(matches!(base_de_la_livraison_push_lu(&st, CJ7_FANTOME), BaseDeLaLivraisonPush::NonServable), "tenant absent : non servable");
        cj7_illisible(&st, CJ7_A);
        let issue = base_de_la_livraison_push_lu(&st, CJ7_A);
        cj7_lisible(&st, CJ7_A);
        match issue {
            BaseDeLaLivraisonPush::CatalogueNonLu(e) => assert_eq!(e.to_string(), CJ7_CAUSE_BLOB, "la cause du moteur est portée"),
            autre => panic!("ligne non lue : CatalogueNonLu attendu ({autre:?})"),
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) LA LISTE DES TENANTS ACTIFS — lue en bloc ou refusée en bloc.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : trois voies, aucun corps de tâche n'est appelé ET le parcours rend l'aveu de la liste non lue,
    /// sous la cause du moteur et sa catégorie — table retirée (la préparation échoue), vue qui échoue au premier pas, et
    /// une ligne dont l'identifiant est un BLOB placée ENTRE A et B (le tenant `default` et A la précèdent, B la suit).
    /// Après chaque voie, la liste remise : les trois tenants, chacun une fois, et un vrai zéro (`Lue(0)`). Mode 0 : le
    /// tenant `default`, `Lue(0)`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_LISTE_FLATTEN` (la ligne indécodable avalée : `default`, A et B exécutés),
    /// `CJ7_LISTE_PAS_VIDE` (le pas du moteur en échec rendu comme une liste vide : aucun corps appelé, mais `Lue(0)`),
    /// `CJ7_PARCOURS_MUET` (la liste non lue rend `Lue(0)`).
    #[test]
    fn cj7_une_liste_des_tenants_non_lue_ou_partielle_n_execute_aucun_tenant() {
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE};
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dir) = mk_mode1_state();
        let chemin = |t: &str| String::from(&*dir.sous(&format!("{t}.db")));
        assert!(tenant_provision(&st.tenants, CJ7_A, CJ7_A, &chemin(CJ7_A), "").is_ok(), "fixture : A provisionné");
        let ligne_x = "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(X'00','x','','sans-base',0,0);";
        cj7_plan(&st, ligne_x);
        assert!(tenant_provision(&st.tenants, CJ7_B, CJ7_B, &chemin(CJ7_B), "").is_ok(), "fixture : B provisionné");
        let parcours = |st: &AppState| {
            let mut vus: Vec<String> = Vec::new();
            let bilan = for_each_active_tenant(&st.tenants, |tid, _h, _p| vus.push(tid.to_string()));
            vus.sort();
            (vus, bilan)
        };
        let non_lue = |cause: &'static str, moteur: &str| Mesure::Illisible {
            cause,
            detail: format!(
                "liste des tenants actifs NON LUE ({moteur}) : aucun tenant n'a été parcouru ce tour (tenants_actifs)"
            ),
        };
        let tous = (vec!["cj7-a".to_string(), "cj7-b".to_string(), "default".to_string()], Mesure::Lue(0));
        assert_eq!(
            parcours(&st),
            (Vec::<String>::new(), non_lue(CAUSE_FORME_INCONNUE, CJ7_CAUSE_ID_BLOB)),
            "ligne au milieu : aucun tenant exécuté sur une liste partielle, et l'aveu rendu"
        );
        cj7_plan(&st, "DELETE FROM tenant WHERE typeof(id)='blob';");
        assert_eq!(parcours(&st), tous, "ligne retirée : les trois, vrai zéro");
        for (voie, pose, remise, attendu) in [
            (
                "table retirée",
                "ALTER TABLE tenant RENAME TO cj7_tenant;",
                "ALTER TABLE cj7_tenant RENAME TO tenant;",
                non_lue(CAUSE_FORME_INCONNUE, CJ7_CAUSE_TABLE),
            ),
            (
                "vue qui échoue au premier pas",
                "ALTER TABLE tenant RENAME TO cj7_tenant; CREATE TEMP VIEW tenant AS \
                 SELECT t.* FROM json_each('pas du json') CROSS JOIN cj7_tenant AS t;",
                "DROP VIEW temp.tenant; ALTER TABLE cj7_tenant RENAME TO tenant;",
                non_lue(CAUSE_SOURCE_ILLISIBLE, CJ7_CAUSE_PAS),
            ),
        ] {
            cj7_plan(&st, pose);
            let vu = parcours(&st);
            cj7_plan(&st, remise);
            assert_eq!(vu, (Vec::<String>::new(), attendu), "{voie} : aucun tenant exécuté, et l'aveu rendu");
            assert_eq!(parcours(&st), tous, "{voie}, remise : les trois, vrai zéro");
        }
        // Mode 0 : un seul tour, sur `default`, et un vrai zéro.
        let st0 = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let mut vus0: Vec<String> = Vec::new();
        let bilan0 = for_each_active_tenant(&st0.tenants, |tid, _h, _p| vus0.push(tid.to_string()));
        assert_eq!((vus0, bilan0), (vec!["default".to_string()], Mesure::Lue(0)), "mode 0 : `default`, vrai zéro");
    }

    // -------------------------------------------------------------------------------------
    // (9) LE TOUR D'UNE BOUCLE DE FOND, SON BILAN PUBLIÉ, LA SANTÉ — la liste non lue n'est plus un zéro.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `tour_des_tenants_sous_bilan` (le tour des boucles règles, connecteurs, destinations, rapports)
    /// sur une table des tenants retirée n'appelle aucun corps, rend ET publie l'aveu de la liste non lue, que la surface
    /// d'état lit ROUGE (`etat_de_surface`, la règle des composants `detection` et `forwarder`). Contrôle positif, table
    /// remise : les trois corps appelés, chacun rend un abandon, `Lue(3)` publié, jaune. Clé de publication propre au
    /// témoin, remise à `Lue(0)` à la fin (la forme de `toute_passe_qui_publie_est_servie`).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_PARCOURS_MUET`, `CJ7_TOUR_SANS_PARCOURS` (le bilan du parcours non absorbé).
    #[test]
    fn cj7_le_tour_d_une_boucle_de_fond_sur_une_liste_non_lue_publie_un_aveu_rouge() {
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE};
        const CJ7_TOUR: &str = "cj7-tour-sous-bilan";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj7_etat();
        let mut appels = 0u32;
        cj7_plan(&st, "ALTER TABLE tenant RENAME TO cj7_tenant;");
        let mesure = crate::server::boucles_de_fond::tour_des_tenants_sous_bilan(&st.tenants, CJ7_TOUR, |_, _, _| {
            appels += 1;
            Mesure::Lue(1)
        });
        cj7_plan(&st, "ALTER TABLE cj7_tenant RENAME TO tenant;");
        assert_eq!(appels, 0, "aucun corps appelé sur la liste non lue");
        let attendu = Mesure::Illisible {
            cause: CAUSE_FORME_INCONNUE,
            detail: format!(
                "1 famille(s) aveugle(s) ce tick — liste des tenants actifs NON LUE ({CJ7_CAUSE_TABLE}) : aucun tenant \
                 n'a été parcouru ce tour (tenants_actifs) ; abandons comptés par ailleurs : 0"
            ),
        };
        assert_eq!(mesure, attendu, "le tour rend l'aveu de la liste, jamais `Lue(0)`");
        assert_eq!(crate::bilan_de_tick::dernier(CJ7_TOUR), Some(attendu.clone()), "et le publie");
        let (etat, _) = crate::bilan_de_tick::etat_de_surface("green", "tick à l'heure".to_string(), Some(&attendu));
        assert_eq!(etat, "red", "la surface lit ROUGE un tour qui n'a rien parcouru");

        let mesure = crate::server::boucles_de_fond::tour_des_tenants_sous_bilan(&st.tenants, CJ7_TOUR, |_, _, _| {
            appels += 1;
            Mesure::Lue(1)
        });
        assert_eq!((appels, mesure.clone()), (3, Mesure::Lue(3)), "contrôle positif : trois corps, trois abandons");
        assert_eq!(crate::bilan_de_tick::dernier(CJ7_TOUR), Some(Mesure::Lue(3)), "publié");
        let (etat, _) = crate::bilan_de_tick::etat_de_surface("green", "tick à l'heure".to_string(), Some(&mesure));
        assert_eq!(etat, "yellow", "contrôle positif : des abandons, jaune");
        crate::bilan_de_tick::publier(CJ7_TOUR, Mesure::Lue(0));
    }

    // -------------------------------------------------------------------------------------
    // (10) CHAQUE BOUCLE DE FOND QUI PUBLIE UN BILAN Y PORTE L'AVEU DU PARCOURS — garde de câblage, sur la source.
    // -------------------------------------------------------------------------------------

    /// Les sites d'appel du parcours dans `server/boucles_de_fond.rs`, lignes de code seulement (commentaires retirés).
    fn cj7_sites_du_parcours(source: &str) -> Result<(), String> {
        let code: Vec<&str> = source
            .lines()
            .map(|l| l.split("//").next().unwrap_or_default().trim())
            .filter(|l| !l.is_empty())
            .collect();
        let mut liees = 0usize;
        for l in code.iter().filter(|l| l.contains("for_each_active_tenant(")) {
            if l.starts_with("let parcours = for_each_active_tenant(") {
                liees += 1;
            } else if !l.starts_with("let _liste_non_lue_comptee_par_le_parcours = for_each_active_tenant(") {
                return Err(format!("site du parcours dont l'aveu n'est pas lié à `parcours` : `{l}`"));
            }
        }
        let absorbees = code.iter().filter(|l| l.contains(".absorber(parcours);")).count();
        if liees == 0 || absorbees != liees {
            return Err(format!("{liees} parcours liés, {absorbees} absorbés : chaque aveu du parcours entre au bilan"));
        }
        let tours = code.iter().filter(|l| l.contains("tour_des_tenants_sous_bilan(&tenants, crate::bilan_de_tick::BOUCLE_")).count();
        if tours != 4 {
            return Err(format!("{tours} boucles par `tour_des_tenants_sous_bilan` : règles, connecteurs, destinations, rapports"));
        }
        Ok(())
    }

    /// L'ORDRE DE CHAQUE BLOC DU PARCOURS, jugé bloc entier : de chaque `let parcours = for_each_active_tenant(` jusqu'au
    /// premier `bilan_de_tick::publier(` qui le suit (lignes de code seulement). Dans ce bloc : UNE absorption
    /// `X.absorber(parcours);` ; aucune prise de mesure (`.mesure()`, `.bilan_de_tick()`) avant elle ; et ce que
    /// `publier` reçoit est `X.mesure()` prise sur la ligne même, ou une liaison dont la DERNIÈRE pose avant `publier` est
    /// `let v = X.mesure();`, après l'absorption (`.clone()` admis). Rend les cibles publiées, préfixe de module retiré.
    /// Un `publier` coupé sur plusieurs lignes est refusé (la garde ne lit pas un argument qu'elle ne voit pas entier).
    fn cj7_ordre_des_blocs_du_parcours(source: &str) -> Result<Vec<String>, String> {
        let code: Vec<&str> = source
            .lines()
            .map(|l| l.split("//").next().unwrap_or_default().trim())
            .filter(|l| !l.is_empty())
            .collect();
        let mut cibles = Vec::new();
        for (debut, _) in code.iter().enumerate().filter(|(_, l)| l.starts_with("let parcours = for_each_active_tenant(")) {
            let Some(fin) = (debut + 1..code.len()).find(|&i| code[i].contains("bilan_de_tick::publier(")) else {
                return Err(format!("bloc du parcours ligne de code {debut} : aucun `publier` ne le suit"));
            };
            let bloc = &code[debut + 1..fin];
            let absorptions: Vec<(usize, &str)> = bloc
                .iter()
                .enumerate()
                .filter_map(|(i, l)| l.strip_suffix(".absorber(parcours);").map(|x| (i, x)))
                .collect();
            let [(a, bilan)] = absorptions[..] else {
                return Err(format!("bloc du parcours avant `{}` : {} absorption(s) de `parcours`, une attendue", code[fin], absorptions.len()));
            };
            if let Some(l) = bloc[..a].iter().find(|l| l.contains(".mesure()") || l.contains(".bilan_de_tick()")) {
                return Err(format!("mesure prise AVANT l'absorption du parcours : `{l}`"));
            }
            let appel = code[fin].split("bilan_de_tick::publier(").nth(1).unwrap_or_default();
            let Some(args) = appel.strip_suffix(");") else {
                return Err(format!("`publier` qui ne tient pas sur sa ligne : `{}`", code[fin]));
            };
            let Some((cible, recu)) = args.split_once(", ") else {
                return Err(format!("`publier` sans ses deux arguments : `{}`", code[fin]));
            };
            let recu = recu.strip_suffix(".clone()").unwrap_or(recu);
            let mesure_apres = format!("{bilan}.mesure()");
            if recu != mesure_apres {
                // Une pose `let v = X.mesure();` placée avant l'absorption est déjà refusée plus haut (mesure avant
                // l'absorption) : la dernière pose admise suit donc l'absorption. `let mut v` n'est pas une pose admise.
                let pose = format!("let {recu} =");
                let reaffectation = format!("{recu} =");
                let derniere = bloc.iter().rev().find(|l| l.starts_with(&pose) || l.starts_with(&reaffectation));
                match derniere {
                    Some(l) if *l == format!("let {recu} = {mesure_apres};") => {}
                    Some(l) => return Err(format!("`publier` reçoit `{recu}`, posée par `{l}` : pas la mesure du bilan prise après l'absorption")),
                    None => return Err(format!("`publier` reçoit `{recu}`, jamais posée dans le bloc")),
                }
            }
            cibles.push(cible.trim_start_matches("crate::bilan_de_tick::").to_string());
        }
        Ok(cibles)
    }

    /// CE QU'IL TIENT : sur la source réelle, chaque appel du parcours lie son aveu à `parcours` et l'absorbe (rétention,
    /// risque, le tour commun), sauf le pré-chauffage, qui ne publie aucun bilan et le dit par le nom de sa liaison ; les
    /// quatre boucles règles, connecteurs, destinations, rapports passent par le tour commun. Instrument validé sur
    /// trois corpus FABRIQUÉS : l'état d'avant (parcours en instruction nue), un aveu lié jamais absorbé, une boucle
    /// rendue à la main. Et L'ORDRE, bloc entier (`cj7_ordre_des_blocs_du_parcours`) : dans le tour commun, la rétention
    /// et le risque, l'absorption du parcours précède toute prise de mesure, et `publier` reçoit la mesure du bilan prise
    /// après elle ; instrument validé sur deux corpus sains et un corpus FABRIQUÉ par faute (absorption absente, après
    /// `publier`, doublée ; mesure ou bilan de tick pris avant elle ; `publier` qui reçoit une mesure antérieure, une
    /// liaison posée avant, reposée, réaffectée, mutable ou jamais posée, la mesure d'un autre bilan ; `publier` coupé ou
    /// absent).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (dans la source) : `CJ7_RISQUE_SANS_PARCOURS`, `CJ7_RETENTION_SANS_PARCOURS`
    /// (l'absorption retirée de la boucle de rollup, de la passe de rétention) ; `V_RISQUE_ORDRE`, ses deux formes (la
    /// mesure du risque prise avant l'absorption et passée à `publier` ; l'absorption déplacée après `publier`) ;
    /// `V_RET_ORDRE` (la mesure de la rétention prise avant l'absorption).
    #[test]
    fn cj7_chaque_boucle_qui_publie_un_bilan_y_porte_l_aveu_du_parcours() {
        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server/boucles_de_fond.rs"))
            .expect("source des boucles de fond");
        assert_eq!(cj7_sites_du_parcours(&source), Ok(()), "la source réelle");
        let tour = "tour_des_tenants_sous_bilan(&tenants, crate::bilan_de_tick::BOUCLE_X, |a, h, p| x(h, p));\n";
        let quatre = tour.repeat(4);
        let avant = format!("{quatre}let mut b = B::default();\nfor_each_active_tenant(&t, |a, h, p| b.absorber(y(h, p)));\n");
        assert!(cj7_sites_du_parcours(&avant).is_err(), "corpus d'avant : parcours en instruction nue, refusé");
        let jamais = format!("{quatre}let parcours = for_each_active_tenant(&t, |a, h, p| y(h, p));\nlet _ = parcours;\n");
        assert!(cj7_sites_du_parcours(&jamais).is_err(), "aveu lié jamais absorbé, refusé");
        let ok = format!("{quatre}let parcours = for_each_active_tenant(&t, |a, h, p| y(h, p));\nb.absorber(parcours);\n");
        assert_eq!(cj7_sites_du_parcours(&ok), Ok(()), "contrôle positif : lié et absorbé");
        let a_la_main = format!("{}let parcours = for_each_active_tenant(&t, |a, h, p| y(h, p));\nb.absorber(parcours);\n", tour.repeat(3));
        assert!(cj7_sites_du_parcours(&a_la_main).is_err(), "une boucle rendue à la main, refusé");

        // L'ORDRE, BLOC ENTIER : les trois blocs réels (le tour commun, la rétention, le risque).
        assert_eq!(
            cj7_ordre_des_blocs_du_parcours(&source),
            Ok(vec!["boucle".to_string(), "BOUCLE_RETENTION".to_string(), "BOUCLE_RISQUE".to_string()]),
            "la source réelle : chaque bloc absorbe le parcours avant toute mesure et publie la mesure d'après"
        );
        let bloc = |corps: &str| format!("let parcours = for_each_active_tenant(&t, |a, h, p| {{\nb.absorber(y(h, p));\n}});\n{corps}");
        let ordre = |corps: &str| cj7_ordre_des_blocs_du_parcours(&bloc(corps));
        assert_eq!(
            ordre("b.absorber(parcours); // aveu\ncrate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_X, b.mesure());\n"),
            Ok(vec!["BOUCLE_X".to_string()]),
            "sain, forme du risque : la mesure prise sur la ligne de `publier`"
        );
        assert_eq!(
            ordre("b.absorber(parcours);\nlet m = b.mesure();\ncrate::bilan_de_tick::publier(BOUCLE_Y, m.clone());\nm\n"),
            Ok(vec!["BOUCLE_Y".to_string()]),
            "sain, forme de la rétention : une liaison posée après l'absorption"
        );
        for (faute, corps) in [
            ("absorption absente", "crate::bilan_de_tick::publier(BOUCLE_X, b.mesure());\n"),
            ("absorption après `publier`", "crate::bilan_de_tick::publier(BOUCLE_X, b.mesure());\nb.absorber(parcours);\n"),
            ("absorption doublée", "b.absorber(parcours);\nb.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, b.mesure());\n"),
            ("mesure avant l'absorption", "let vu = b.mesure();\nb.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, b.mesure());\n"),
            ("bilan de tick avant l'absorption", "let vu = b.bilan_de_tick();\nb.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, b.mesure());\n"),
            ("`publier` reçoit une mesure antérieure", "let m = b.mesure();\nb.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, m);\n"),
            ("`publier` reçoit une liaison posée avant", "let m = Mesure::Lue(0);\nb.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, m);\n"),
            ("liaison reposée après la mesure", "b.absorber(parcours);\nlet m = b.mesure();\nlet m = Mesure::Lue(0);\ncrate::bilan_de_tick::publier(BOUCLE_X, m.clone());\n"),
            ("liaison réaffectée après la mesure", "b.absorber(parcours);\nlet m = b.mesure();\nm = Mesure::Lue(0);\ncrate::bilan_de_tick::publier(BOUCLE_X, m);\n"),
            ("pose mutable, non admise", "b.absorber(parcours);\nlet mut m = b.mesure();\ncrate::bilan_de_tick::publier(BOUCLE_X, m);\n"),
            ("liaison jamais posée", "b.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, m);\n"),
            ("mesure d'un autre bilan", "b.absorber(parcours);\ncrate::bilan_de_tick::publier(BOUCLE_X, autre.mesure());\n"),
            ("`publier` coupé sur deux lignes", "b.absorber(parcours);\ncrate::bilan_de_tick::publier(\nBOUCLE_X, b.mesure());\n"),
            ("aucun `publier`", "b.absorber(parcours);\nlet m = b.mesure();\n"),
        ] {
            assert!(ordre(corps).is_err(), "corpus fabriqué « {faute} » : refusé ({:?})", ordre(corps));
        }
    }

    // -------------------------------------------------------------------------------------
    // (4) L'INVENTAIRE DES ACCÈS — rien n'est écrit, ni chez le tenant ni dans la base du processus.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : ligne de A illisible, l'accès de `cj7-ana` à A n'est inscrit ni dans la base de A, ni dans celle
    /// du processus, ni dans celle de B. Contrôle positif, ligne relue : l'accès de `cj7-bea` est inscrit dans la base de
    /// A, une fois, et pas dans celle du processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ7_ACCES_REPLI` (la base du processus prise sur la ligne non lue).
    #[test]
    fn cj7_l_inventaire_des_acces_n_inscrit_rien_sur_une_ligne_non_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj7_etat();
        let (base_a, base_b) = (cj7_base(&st, CJ7_A), cj7_base(&st, CJ7_B));
        let compte = |h: &Arc<Mutex<Connection>>, nom: &str| cj7_compte(h, &format!("SELECT COUNT(*) FROM acces_observe WHERE nom='{nom}'"));
        cj7_illisible(&st, CJ7_A);
        crate::acces_observe::consigner_l_acces(&st, CJ7_A, "cj7-ana", "admin", "basic");
        cj7_lisible(&st, CJ7_A);
        assert_eq!((compte(&base_a, "cj7-ana"), compte(&st.db, "cj7-ana"), compte(&base_b, "cj7-ana")), (0, 0, 0), "rien n'est inscrit, nulle part");
        crate::acces_observe::consigner_l_acces(&st, CJ7_A, "cj7-bea", "admin", "basic");
        assert_eq!((compte(&base_a, "cj7-bea"), compte(&st.db, "cj7-bea")), (1, 0), "ligne relue : inscrit chez A seulement");
    }

    // -------------------------------------------------------------------------------------
    // (11) L'INVENTAIRE DES ACCÈS, TENANT NON SERVABLE — rien n'est écrit, ni chez lui ni dans la base du processus.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par appel direct du site (`consigner_l_acces`, le point de passage qu'appelle `auth_guard`) : B
    /// suspendu, l'accès de `cj7-cyd` à B n'est inscrit ni dans la base de B, ni dans celle du processus, ni dans celle
    /// de A ; tenant absent du catalogue, l'accès de `cj7-dan` n'est inscrit ni dans la base du processus ni dans celles
    /// de A et B. Contrôle positif, B remis actif : l'accès de `cj7-eve` est inscrit dans la base de B, une fois, et pas
    /// dans celle du processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `V_ACCES_NONSERV_REPLI` (`Ok(None) => st.db.clone()` : la base du processus prise
    /// pour un tenant non servable).
    #[test]
    fn cj7_l_inventaire_des_acces_n_inscrit_rien_pour_un_tenant_non_servable() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj7_etat();
        let (base_a, base_b) = (cj7_base(&st, CJ7_A), cj7_base(&st, CJ7_B));
        let compte = |h: &Arc<Mutex<Connection>>, nom: &str| cj7_compte(h, &format!("SELECT COUNT(*) FROM acces_observe WHERE nom='{nom}'"));
        cj7_plan(&st, &format!("UPDATE tenant SET suspended=1 WHERE id='{CJ7_B}';"));
        assert!(matches!(st.tenants.handle_for_lu(CJ7_B), Ok(None)), "fixture : B suspendu, non servable");
        crate::acces_observe::consigner_l_acces(&st, CJ7_B, "cj7-cyd", "admin", "basic");
        assert_eq!(
            (compte(&base_b, "cj7-cyd"), compte(&st.db, "cj7-cyd"), compte(&base_a, "cj7-cyd")),
            (0, 0, 0),
            "tenant suspendu : rien n'est inscrit, nulle part"
        );
        assert!(matches!(st.tenants.handle_for_lu(CJ7_FANTOME), Ok(None)), "fixture : tenant absent, non servable");
        crate::acces_observe::consigner_l_acces(&st, CJ7_FANTOME, "cj7-dan", "admin", "basic");
        assert_eq!(
            (compte(&st.db, "cj7-dan"), compte(&base_a, "cj7-dan"), compte(&base_b, "cj7-dan")),
            (0, 0, 0),
            "tenant absent : rien n'est inscrit, nulle part"
        );
        cj7_plan(&st, &format!("UPDATE tenant SET suspended=0 WHERE id='{CJ7_B}';"));
        crate::acces_observe::consigner_l_acces(&st, CJ7_B, "cj7-eve", "admin", "basic");
        assert_eq!((compte(&base_b, "cj7-eve"), compte(&st.db, "cj7-eve")), (1, 0), "B remis actif : inscrit chez B seulement");
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ÉVÉNEMENT D'ACCÈS OPÉRATEUR — la trace perdue l'est sous SA cause.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : ligne de A illisible, un accès opérateur en lecture à A garde sa trace du plan de contrôle
    /// (l'accès passerait), la trace du tenant est perdue, comptée UNE fois, sous la cause « ligne du catalogue des
    /// tenants NON LUE au moment de l'écriture (cause du moteur) » ; aucun événement n'est écrit, ni chez A ni dans la base
    /// du processus. Ligne relue, le même opérateur : l'événement est écrit chez A (la réservation a été oubliée).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_TRACE_CAUSE` (« base du tenant non résoluble »), `CJ7_TRACE_REPLI`
    /// (l'événement posé dans la base du processus).
    #[test]
    fn cj7_la_trace_d_acces_operateur_sur_une_ligne_non_lue_est_perdue_sous_sa_cause() {
        let _verrou = super::acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj7_etat();
        let base_a = cj7_base(&st, CJ7_A);
        let evenements = |h: &Arc<Mutex<Connection>>| cj7_compte(h, "SELECT COUNT(*) FROM event WHERE source='plume-operator-access'");
        let perdus = || crate::metrics::acces_operateur_non_trace_de(crate::rbac::TRACE_OPERATEUR_TENANT_LECTURE);
        let avant = perdus().map(|(n, _)| n).unwrap_or(0);
        cj7_illisible(&st, CJ7_A);
        let issue = crate::rbac::emit_operator_access(&st, "op-cj7", CJ7_A, false, None);
        cj7_lisible(&st, CJ7_A);
        assert!(matches!(issue, crate::rbac::TraceDAccesOperateur::AuMoinsUneTrace), "le maillon du plan de contrôle est inscrit ({issue:?})");
        let (n, cause) = perdus().expect("la trace perdue est comptée");
        assert_eq!(n - avant, 1, "comptée une fois");
        assert_eq!(cause, format!("ligne du catalogue des tenants NON LUE au moment de l'écriture ({CJ7_CAUSE_BLOB})"), "sous SA cause");
        assert_eq!((evenements(&base_a), evenements(&st.db)), (0, 0), "aucun événement, nulle part");
        let issue = crate::rbac::emit_operator_access(&st, "op-cj7", CJ7_A, false, None);
        assert!(matches!(issue, crate::rbac::TraceDAccesOperateur::AuMoinsUneTrace), "ligne relue : l'accès est tracé ({issue:?})");
        assert_eq!((evenements(&base_a), evenements(&st.db)), (1, 0), "ligne relue : l'événement est écrit chez A");
    }

    // -------------------------------------------------------------------------------------
    // (6) L'ÉVÉNEMENT D'AUDIT DU TENANT — avoué sous sa phrase à chaque geste qui l'écrit après une bascule faite.
    // -------------------------------------------------------------------------------------

    fn cj7_evenements_d_audit(h: &Arc<Mutex<Connection>>, action: &str) -> i64 {
        cj7_compte(h, &format!("SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin' AND json_extract(fields,'$.action')='{action}'"))
    }

    /// CE QU'IL TIENT, par les gestionnaires, corps ENTIERS : ligne de A illisible pendant le geste seulement —
    /// la pose d'un droit (200), son retrait (200 et non le 204 nu), la réactivation (200), puis une création dont la ligne
    /// devient illisible à l'inscription (201) — chacun porte `evenement_du_tenant_non_ecrit` sous la phrase de la ligne
    /// non relue ; aucun événement de ces gestes n'est écrit, ni chez le tenant ni dans la base du processus ; le geste,
    /// lui, est fait (droit posé puis retiré, tenant réactivé, tenant inscrit).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_AUDIT_SANS_BASE` (la phrase de la base non servie), `CJ7_AVOUER_MUET` (aucun
    /// aveu), `CJ7_RETRAIT_204` (le retrait rend 204).
    #[tokio::test]
    async fn cj7_l_evenement_d_audit_sur_une_ligne_non_lue_est_avoue_sous_sa_phrase_a_chaque_geste() {
        let (st, _dir) = cj7_etat();
        let sa = au_super("op-cj7");
        let base_a = cj7_base(&st, CJ7_A);
        let aveu = json!(CJ7_EVENEMENT_CATALOGUE_NON_LU);

        cj7_illisible(&st, CJ7_A);
        let pose = pb_json(
            grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path(CJ7_A.into()), Json(json!({ "user": "cj7-carl", "role": "viewer" })))
                .await,
        )
        .await;
        cj7_lisible(&st, CJ7_A);
        assert_eq!(
            pose,
            (200, json!({ "ok": true, "tenant": CJ7_A, "user": "cj7-carl", "role": "viewer", "evenement_du_tenant_non_ecrit": aveu })),
            "pose d'un droit : avouée sous la phrase de la ligne non relue"
        );
        assert_eq!(cj7_compte_plan(&st, "SELECT COUNT(*) FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE p.name='cj7-carl'"), 1, "le droit est posé");

        cj7_illisible(&st, CJ7_A);
        let retrait = pb_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path((CJ7_A.into(), "cj7-carl".into()))).await).await;
        cj7_lisible(&st, CJ7_A);
        assert_eq!(
            retrait,
            (200, json!({ "ok": true, "tenant": CJ7_A, "user": "cj7-carl", "removed": true, "evenement_du_tenant_non_ecrit": aveu })),
            "retrait : deux cents avec l'aveu, jamais le deux cent quatre nu"
        );
        assert_eq!(cj7_compte_plan(&st, "SELECT COUNT(*) FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE p.name='cj7-carl'"), 0, "le droit est retiré");

        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path(CJ7_A.into())).await).await;
        assert_eq!(statut, 200, "fixture : A suspendu ({v})");
        cj7_illisible(&st, CJ7_A);
        let reactivation = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path(CJ7_A.into())).await).await;
        cj7_lisible(&st, CJ7_A);
        assert_eq!(
            reactivation,
            (200, json!({ "ok": true, "id": CJ7_A, "suspended": false, "evenement_du_tenant_non_ecrit": aveu })),
            "réactivation : avouée sous la phrase de la ligne non relue"
        );
        assert_eq!(cj7_compte_plan(&st, &format!("SELECT suspended FROM tenant WHERE id='{CJ7_A}'")), 0, "A est réactivé");

        for action in ["grant.set", "grant.remove", "tenant.unsuspend"] {
            assert_eq!((cj7_evenements_d_audit(&base_a, action), cj7_evenements_d_audit(&st.db, action)), (0, 0), "{action} : aucun événement, nulle part");
        }
        assert_eq!(cj7_evenements_d_audit(&base_a, "tenant.suspend"), 1, "contrôle : l'événement de la suspension, ligne lisible, est écrit chez A");

        // La référence de clé inscrite par la création est gardée à côté, pour rendre la ligne lisible ensuite.
        cj7_plan(
            &st,
            "CREATE TABLE cj7_cle_inscrite(id TEXT, key_ref TEXT); \
             CREATE TRIGGER cj7_illisible_a_l_inscription AFTER INSERT ON tenant BEGIN \
             INSERT INTO cj7_cle_inscrite VALUES(NEW.id, NEW.key_ref); UPDATE tenant SET key_ref=X'00' WHERE id=NEW.id; END;",
        );
        let creation = pb_json(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "cj7-n", "name": "Cj7N" }))).await).await;
        cj7_plan(
            &st,
            "DROP TRIGGER cj7_illisible_a_l_inscription; \
             UPDATE tenant SET key_ref=(SELECT key_ref FROM cj7_cle_inscrite WHERE id='cj7-n') WHERE id='cj7-n';",
        );
        assert_eq!(
            creation,
            (201, json!({ "ok": true, "id": "cj7-n", "name": "Cj7N", "first_admin": null, "evenement_du_tenant_non_ecrit": aveu })),
            "création : avouée sous la phrase de la ligne non relue"
        );
        assert_eq!(cj7_evenements_d_audit(&cj7_base(&st, "cj7-n"), "tenant.create"), 0, "création : aucun événement chez le tenant créé");
        assert_eq!(cj7_evenements_d_audit(&st.db, "tenant.create"), 0, "création : aucun dans la base du processus");
    }

    // -------------------------------------------------------------------------------------
    // (7) LA SUSPENSION — refusée avant toute bascule quand la poignée de la base ne se lit pas.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : ligne de A illisible, `POST /api/tenants/cj7-a/suspend` rend 503, corps entier `{error, id}`,
    /// `error` = la cause d'un tenant non lu à la bascule ; A reste actif, aucun maillon `tenant.suspend`, aucun événement.
    /// Contrôle positif, ligne relue : 200, A suspendu, son événement écrit chez lui (vu après réactivation).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ7_SUSPENSION_POURSUIT` (la poignée non lue prise pour une base absente : 200).
    #[tokio::test]
    async fn cj7_la_suspension_dont_la_ligne_n_est_pas_lue_est_refusee_avant_toute_bascule() {
        let (st, _dir) = cj7_etat();
        let sa = au_super("op-cj7");
        let base_a = cj7_base(&st, CJ7_A);
        cj7_illisible(&st, CJ7_A);
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path(CJ7_A.into())).await).await;
        cj7_lisible(&st, CJ7_A);
        assert_eq!(statut, 503, "refusée : {v}");
        let cles: std::collections::BTreeSet<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"].into_iter().collect(), "corps entier : {v}");
        assert_eq!(v["error"], json!(CJ7_BASCULE_NON_FAITE), "la cause d'un tenant non lu à la bascule : {v}");
        assert_eq!(cj7_compte_plan(&st, &format!("SELECT suspended FROM tenant WHERE id='{CJ7_A}'")), 0, "A reste actif");
        assert_eq!(cj7_compte_plan(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind='tenant.suspend'"), 0, "rien n'est tracé");
        assert_eq!(cj7_evenements_d_audit(&base_a, "tenant.suspend"), 0, "aucun événement");

        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path(CJ7_A.into())).await).await;
        assert_eq!(statut, 200, "ligne relue : suspendu ({v})");
        assert_eq!(cj7_compte_plan(&st, &format!("SELECT suspended FROM tenant WHERE id='{CJ7_A}'")), 1, "ligne relue : A suspendu");
        let (statut, v) = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path(CJ7_A.into())).await).await;
        assert_eq!(statut, 200, "contrôle : réactivé ({v})");
        assert_eq!(cj7_evenements_d_audit(&base_a, "tenant.suspend"), 1, "ligne relue : l'événement de la suspension est écrit chez A");
    }

    // -------------------------------------------------------------------------------------
    // (8) LE JOURNAL ET LE COMPTE, PAR CAPTURE — sous-processus, phases séparées par un marqueur.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, ligne ENTIÈRE par ligne entière, phase par phase :
    ///   1. table des tenants retirée, deux parcours : UNE ligne de la liste non lue ;
    ///   2. table remise, un parcours : aucune ligne ;
    ///   3. une ligne à identifiant BLOB, un parcours : la ligne est dite de nouveau (une lecture entière l'a oubliée),
    ///      sous la cause de l'identifiant ; puis la ligne retirée ;
    ///   4. ligne de A illisible, un accès : la ligne de l'inventaire des accès ;
    ///   5. même panne, un événement d'audit : sa ligne ;
    ///   6. même panne, une suspension : sa ligne.
    /// Et le compte des tours sautés : trois sous `tenants_actifs` (dernière cause : l'identifiant BLOB), trois de plus au
    /// total des balayages aveugles.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ7_LISTE_LIGNE_TUE`, `CJ7_LISTE_CHAQUE_FOIS`, `CJ7_LISTE_JAMAIS_OUBLIE`,
    /// `CJ7_LISTE_NON_COMPTEE`, `CJ7_LISTE_TOTAL_NON_COMPTE`, `CJ7_ACCES_LIGNE_TUE`, `CJ7_AUDIT_LIGNE_TUE`,
    /// `CJ7_SUSPENSION_LIGNE_TUE`.
    #[test]
    fn cj7_les_lignes_des_derniers_appelants_sont_dites_et_les_tours_saute_comptes() {
        if std::env::var(CJ7_ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            cj7_enfant();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::catalogue_non_lu_aux_derniers_appelants_de_la_projection::cj7_les_lignes_des_derniers_appelants_sont_dites_et_les_tours_saute_comptes",
            ])
            .env(CJ7_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut phases: Vec<Vec<String>> = Vec::new();
        for l in stderr.lines() {
            if l.starts_with(CJ7_PHASE) {
                phases.push(Vec::new());
            } else if let Some(courante) = phases.last_mut() {
                if l.starts_with("[multi-tenant]") || l.starts_with("[acces_observe]") || l.starts_with("[tenants]") {
                    courante.push(l.to_string());
                }
            }
        }
        let attendu: Vec<Vec<String>> = vec![
            vec![cj7_ligne_liste(CJ7_CAUSE_TABLE)],
            vec![],
            vec![cj7_ligne_liste(CJ7_CAUSE_ID_BLOB)],
            vec![cj7_ligne_acces(CJ7_A, "basic", CJ7_CAUSE_BLOB)],
            vec![cj7_ligne_audit("cj7.essai", CJ7_A, CJ7_CAUSE_BLOB)],
            vec![cj7_ligne_suspension(CJ7_A, CJ7_CAUSE_BLOB)],
        ];
        assert!(phases.len() >= 6, "plancher : six phases marquées :\n{stderr}");
        assert_eq!(phases.len(), attendu.len(), "une entrée par phase marquée :\n{stderr}");
        for (i, (vu, att)) in phases.iter().zip(attendu.iter()).enumerate() {
            assert_eq!(vu, att, "phase {} : lignes ENTIÈRES, aucune autre :\n{stderr}", i + 1);
        }
    }

    /// Le corps joué par l'enfant ; chaque phase ouvre par son marqueur sur la sortie d'erreur.
    fn cj7_enfant() {
        use std::sync::atomic::Ordering::Relaxed;
        let (st, _dir) = cj7_etat();
        let phase = |n: u32| eprintln!("{CJ7_PHASE}{n}");
        let total = crate::metrics::TICKS_AVEUGLES_TOTAL.load(Relaxed);
        let par_nom = crate::metrics::tick_aveugle_de(CJ7_BALAYAGE).map(|(n, _)| n).unwrap_or(0);
        let mut appels = 0;

        phase(1);
        cj7_plan(&st, "ALTER TABLE tenant RENAME TO cj7_tenant;");
        let _ = for_each_active_tenant(&st.tenants, |_, _, _| appels += 1);
        let _ = for_each_active_tenant(&st.tenants, |_, _, _| appels += 1);
        cj7_plan(&st, "ALTER TABLE cj7_tenant RENAME TO tenant;");
        assert_eq!(appels, 0, "enfant : aucun tenant exécuté");
        phase(2);
        let _ = for_each_active_tenant(&st.tenants, |_, _, _| appels += 1);
        assert_eq!(appels, 3, "enfant : liste lue, les trois");
        phase(3);
        cj7_plan(&st, "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(X'00','x','','sans-base',0,0);");
        let _ = for_each_active_tenant(&st.tenants, |_, _, _| appels += 1);
        cj7_plan(&st, "DELETE FROM tenant WHERE typeof(id)='blob';");
        assert_eq!(appels, 3, "enfant : aucun tenant exécuté sur la liste partielle");
        assert_eq!(crate::metrics::TICKS_AVEUGLES_TOTAL.load(Relaxed) - total, 3, "enfant : trois tours sautés au total des balayages aveugles");
        let (n, cause) = crate::metrics::tick_aveugle_de(CJ7_BALAYAGE).expect("enfant : le balayage est consigné");
        assert_eq!((n - par_nom, cause.as_str()), (3, CJ7_CAUSE_ID_BLOB), "enfant : trois tours sous `tenants_actifs`, dernière cause");

        phase(4);
        cj7_illisible(&st, CJ7_A);
        crate::acces_observe::consigner_l_acces(&st, CJ7_A, "cj7-dan", "admin", "basic");
        phase(5);
        let evenement = crate::rbac::audit_tenant_event(&st, CJ7_A, "cj7.essai", 1, "m", json!({}));
        assert!(matches!(evenement, crate::rbac::EvenementDAuditDuTenant::CatalogueNonLu), "enfant : ligne non lue ({evenement:?})");
        phase(6);
        let au = au_super("op-cj7");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("enfant : exécuteur");
        let refus = rt.block_on(tenant_set_suspended(&st, &au, CJ7_A, true));
        assert_eq!(refus.status(), StatusCode::SERVICE_UNAVAILABLE, "enfant : suspension refusée");
        cj7_lisible(&st, CJ7_A);
    }
}
