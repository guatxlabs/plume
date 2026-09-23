// =====================================================================================
// `P10.20-z` — LE JOURNAL DE CONTRÔLE ET LES ÉVÉNEMENTS D'ACCÈS AVOUENT LEUR ÉCRITURE : UN MAILLON
// NON INSCRIT N'EST PAS UNE TRACE, UN ÉCHEC D'AUTHENTIFICATION NON ÉCRIT N'EST PAS UN SILENCE.
//
// LE DÉFAUT, MESURÉ AVANT TOUT CORRECTIF. Trois écritures se faisaient sous `let _ =`, la forme SANS
// branche d'échec :
//   * `rbac::control_ledger_append` avouait le refus AMONT (hachage précédent illisible, `P10.7-o`) mais
//     avalait l'`INSERT` final — le défaut exact de `ledger_append` avant `P10.20-v`, sur le journal des
//     accès superadmin, des gestes de tenant, de grant, de rôle et de SCIM ;
//   * `auth::ingest_auth_event` et `auth::ingest_authz_denied` avalaient l'`INSERT` dans `event` — la
//     matière première de la détection de force brute et de reconnaissance pouvait manquer sans qu'aucun
//     compteur ne bouge.
//
// CE QUE L'ÉNONCÉ DE LA CLÉ COMPTAIT, ET CE QUE LA MESURE DONNE. « Vingt-sept appelants » : c'est le
// nombre d'occurrences de `control_ledger_append(` dans l'arbre, la DÉFINITION et les TESTS compris. Les
// appelants de PRODUCTION sont douze (sept gestes d'administration servis à la console, quatre gestes
// SCIM, un point de passage d'accès cross-tenant) ; quatorze sont des fixtures de test. Comme pour
// `ledger_append` avant `P10.20-v`, aucun appelant ne pouvait scruter quoi que ce soit : la primitive
// rendait `()`. Le défaut était dans le TYPE.
//
// LES DEUX VOIES D'ÉCHEC, ET POURQUOI DEUX — la paire de `P10.20-t`/`P10.20-v`. La VUE TEMPORAIRE (la
// table renommée, une vue de même nom posée par-dessus) laisse la LECTURE de la tête de chaîne passer et
// fait échouer la seule ÉCRITURE : c'est la voie que cette clé ouvre. La TABLE RETIRÉE fait tomber la
// lecture amont : la voie que `P10.7-o` avait fermée, qui porte maintenant la même issue nommée.
//
// LA QUESTION DE LA CLÉ, ET SA RÉPONSE EST DANS LE DERNIER TÉMOIN. « La vérification hors ligne du
// control-plane est-elle aveugle de la même façon ? » OUI, et sur ses DEUX instruments : quatre appels,
// trois lignes, `control_ledger_verify_conn` (celui que `verify-control` appelle) rend « trois maillons
// intègres, aucune rupture » et la copie exportée se vérifie hors ligne en trois entrées. Le maillon
// suivant s'accroche au dernier PRÉSENT, et l'identifiant ne saute pas (`INTEGER PRIMARY KEY` sans
// `AUTOINCREMENT`). L'aveu À L'ÉCRITURE est le seul endroit où la perte se voit.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils éprouvent un objet non modifiable, pas une base réellement en
// lecture seule (le chemin de code refusé est le même) ; ils appellent les fonctions, pas le binaire
// `verify-control` ; aucun module de `web/` ne lit l'aveu neuf des réponses de tenant, de grant et de
// rôle ; et les quatre gestes SCIM et le point de passage d'accès cross-tenant laissent la perte à la
// sortie d'erreur, sans compteur.
// =====================================================================================
mod journaux_avouent_leur_ecriture {
    use super::*;

    /// La table du journal de contrôle renommée, une vue TEMPORAIRE de même nom par-dessus : la tête de
    /// chaîne se LIT, l'`INSERT` ne passe pas.
    const JAE_VUE_SUR_LE_JOURNAL: &str = "ALTER TABLE control_ledger RENAME TO control_ledger_source;\
         CREATE TEMP VIEW control_ledger AS SELECT * FROM control_ledger_source;";
    const JAE_VUE_RETIREE: &str = "DROP VIEW control_ledger; ALTER TABLE control_ledger_source RENAME TO control_ledger;";

    fn jae_plan_de_controle(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn jae_compte_de_controle(st: &AppState, sql: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .expect("fixture : le compte se lit")
    }

    fn jae_genres_de_controle(st: &AppState, genre: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le compte par genre se lit")
    }

    fn jae_super_admin() -> AuthUser {
        AuthUser {
            name: "op-jae".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// L'aveu de trace manquante posé À CÔTÉ d'un succès, s'il y en a un.
    fn jae_aveu(v: &Value) -> Option<String> {
        v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).map(str::to_string)
    }

    fn jae_aveu_de_controle(quoi: &str, v: &Value) {
        let aveu = jae_aveu(v).unwrap_or_else(|| panic!("{quoi} : la trace manque et la réponse DOIT le dire : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE_DE_CONTROLE), "{quoi} : l'aveu nomme le journal de CONTRÔLE : {aveu}");
    }

    // -------------------------------------------------------------------------------------
    // (1) LA PRIMITIVE — les deux voies de non-inscription, et le mode 0, rendus à l'appelant.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `control_ledger_append` rend `NonInscrit` avec sa cause sous la VUE TEMPORAIRE
    /// (la tête de chaîne se lit, seule l'écriture tombe) et sous la TABLE RETIRÉE (la lecture amont
    /// tombe, la cause le dit) ; le compte des maillons ne bouge dans aucun des deux cas ; en mode 0 la
    /// primitive dit qu'il n'y a pas de journal au lieu de se taire. Contrôle positif avant et après.
    ///
    /// CE QU'IL NE TIENT PAS : aucun appelant — c'est l'objet des témoins suivants.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO control_ledger…")`
    /// suivi de `Inscrit`. La voie de la vue repasse pour inscrite sur un maillon qui n'existe pas.
    #[test]
    fn jae_un_maillon_de_controle_non_inscrit_est_rendu_a_l_appelant() {
        let (st, _cptmp) = un_control_plane_au_journal_vierge();

        // CONTRÔLE POSITIF — un journal sain inscrit, et le compte monte d'exactement un.
        assert!(
            control_ledger_append(&st, "role.upsert", "op-jae", "", "maillon du contrôle positif").cause_de_non_inscription().is_none(),
            "un journal sain INSCRIT son maillon"
        );
        assert_eq!(compter_les_maillons_de_controle(&st), 1);

        // LA VUE TEMPORAIRE — la tête se LIT, l'écriture ne passe pas.
        jae_plan_de_controle(&st, JAE_VUE_SUR_LE_JOURNAL);
        {
            let cp = st.tenants.control.as_ref().expect("mode 1");
            assert!(
                control_ledger_prev_hash(&cp.conn.lock()).is_ok(),
                "CONTRÔLE D'INSTRUMENT : sous la vue, la LECTURE de la tête réussit — sans quoi ce témoin \
                 éprouverait la voie amont et non l'écriture"
            );
        }
        let cause = control_ledger_append(&st, "grant.set", "op-jae", "acme", "maillon que la base refuse")
            .cause_de_non_inscription()
            .map(str::to_string)
            .unwrap_or_else(|| panic!("l'écriture refusée doit être RENDUE, jamais avalée"));
        assert!(!cause.is_empty() && !cause.contains("ILLISIBLE"), "c'est l'ÉCRITURE qui est tombée : {cause}");
        assert_eq!(jae_compte_de_controle(&st, "SELECT COUNT(*) FROM control_ledger_source"), 1, "AUCUN maillon n'est entré");

        // LA TABLE RETIRÉE — la lecture amont tombe, et la même issue le dit.
        jae_plan_de_controle(&st, "DROP VIEW control_ledger; ALTER TABLE control_ledger_source RENAME TO control_ledger_hors_d_atteinte;");
        let cause = control_ledger_append(&st, "grant.set", "op-jae", "acme", "maillon sans tête lisible")
            .cause_de_non_inscription()
            .map(str::to_string)
            .unwrap_or_else(|| panic!("la lecture amont ratée doit être RENDUE, elle aussi"));
        assert!(cause.contains("ILLISIBLE"), "la cause dit LAQUELLE des deux voies a tenu la plume : {cause}");

        // CONTRÔLE POSITIF, SECONDE FOIS — la table remise, le maillon suivant entre.
        jae_plan_de_controle(&st, "ALTER TABLE control_ledger_hors_d_atteinte RENAME TO control_ledger;");
        assert!(
            control_ledger_append(&st, "grant.set", "op-jae", "acme", "maillon d'après").cause_de_non_inscription().is_none(),
            "le refus n'est pas inconditionnel"
        );
        assert_eq!(compter_les_maillons_de_controle(&st), 2, "deux inscrits, deux refusés : le compte le dit");

        // MODE 0 — pas de plan de contrôle : l'issue le NOMME, elle ne prétend pas avoir inscrit.
        let st0 = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        match control_ledger_append(&st0, "role.upsert", "op-jae", "", "sans journal") {
            MaillonDeRegistre::NonInscrit(cause) => assert_eq!(cause, CAUSE_SANS_PLAN_DE_CONTROLE),
            MaillonDeRegistre::Inscrit => panic!("mode 0 : aucun journal de contrôle n'existe, rien ne peut y être inscrit"),
        }
    }

    // -------------------------------------------------------------------------------------
    // (2) LES GESTES D'ADMINISTRATION — faits, et leur trace manquante DITE à côté du succès.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur le journal de contrôle, les gestes qui ONT EU LIEU —
    /// grant posé, grant retiré, tenant suspendu, rôle créé — sont servis comme faits (refuser serait
    /// faux : le rejeu ne comblerait pas le trou) ET portent l'aveu `registre_sans_maillon` ; le retrait
    /// de grant, qui rend un 204 sans corps sur le chemin nominal, devient un 200 qui porte l'aveu ; et
    /// aucun maillon n'entre. Contrôle positif dans le même corps : la vue retirée, les gestes inverses
    /// n'avouent RIEN, le retrait redevient un 204, et chacun inscrit son maillon.
    ///
    /// CE QU'IL NE TIENT PAS : `tenant_create` n'est éprouvé que sur son chemin nominal (sa forme est
    /// celle de `tenant_suspend`) ; et il ne juge pas ce que la console peint de l'aveu.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur l'`INSERT` de la primitive — l'issue
    /// redevient `Inscrit`, aucun aveu ne sort, et le retrait de grant redevient un 204 muet.
    #[tokio::test]
    async fn jae_un_geste_d_administration_dont_la_trace_manque_est_servi_avec_son_aveu() {
        let _roles = CUSTOM_ROLES_TEST_LOCK.lock();
        let (st, _dir) = mk_mode1_state();
        let sa = jae_super_admin();
        let (statut, cree) =
            pb_json(tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "jae-acme", "name": "JaeAcme" }))).await).await;
        assert_eq!(statut, 201, "{cree}");
        assert_eq!(jae_aveu(&cree), None, "CONTRÔLE POSITIF : le chemin nominal n'avoue RIEN : {cree}");

        jae_plan_de_controle(&st, JAE_VUE_SUR_LE_JOURNAL);
        let maillons_avant = jae_compte_de_controle(&st, "SELECT COUNT(*) FROM control_ledger_source");

        let (statut, v) = pb_json(
            grant_set(State(st.clone()), Extension(sa.clone()), Path("jae-acme".into()), Json(json!({ "user": "carol", "role": "editor" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "le grant EST posé : {v}");
        jae_aveu_de_controle("grant.set", &v);
        assert_eq!(count_grant(&st, "jae-acme", "carol"), 1, "et il existe");

        let (statut, v) =
            pb_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path(("jae-acme".into(), "carol".into()))).await).await;
        assert_eq!(statut, 200, "un 204 ne peut rien avouer : le retrait sans trace porte un corps : {v}");
        assert_eq!(v.get("removed").and_then(|x| x.as_bool()), Some(true), "{v}");
        jae_aveu_de_controle("grant.remove", &v);
        assert_eq!(count_grant(&st, "jae-acme", "carol"), 0, "et le grant est retiré");

        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("jae-acme".into())).await).await;
        assert_eq!(statut, 200, "{v}");
        jae_aveu_de_controle("tenant.suspend", &v);

        let (statut, v) = pb_json(
            role_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "name": "jae-role", "base_role": "viewer" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "{v}");
        jae_aveu_de_controle("role.upsert", &v);

        assert_eq!(
            jae_compte_de_controle(&st, "SELECT COUNT(*) FROM control_ledger_source"), maillons_avant,
            "AUCUN des quatre maillons n'est entré — c'est ce que les quatre aveux disent"
        );

        // CONTRÔLE POSITIF — la vue retirée, les gestes inverses n'avouent rien et inscrivent leur maillon.
        jae_plan_de_controle(&st, JAE_VUE_RETIREE);
        let (statut, v) = pb_json(
            grant_set(State(st.clone()), Extension(sa.clone()), Path("jae-acme".into()), Json(json!({ "user": "dave", "role": "viewer" }))).await,
        )
        .await;
        assert_eq!((statut, jae_aveu(&v)), (200, None), "{v}");
        let r = grant_delete(State(st.clone()), Extension(sa.clone()), Path(("jae-acme".into(), "dave".into()))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "le chemin nominal du retrait reste un 204 SANS corps");
        let (statut, v) = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("jae-acme".into())).await).await;
        assert_eq!((statut, jae_aveu(&v)), (200, None), "{v}");
        let (statut, v) = pb_json(role_delete(State(st.clone()), Extension(sa.clone()), Path("jae-role".into())).await).await;
        assert_eq!((statut, jae_aveu(&v)), (200, None), "{v}");
        assert_eq!(
            jae_compte_de_controle(&st, "SELECT COUNT(*) FROM control_ledger"), maillons_avant + 4,
            "les quatre gestes du contrôle positif ont chacun leur maillon"
        );
    }

    // -------------------------------------------------------------------------------------
    // (3) LA DESTRUCTION — la trace précède l'irréversible, ou l'irréversible n'a pas lieu.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire, `DELETE /api/tenants/{id}` REFUSE par un 503 nommé et ne
    /// détruit RIEN — le fichier du tenant existe, le catalogue le résout encore, aucun `tenant.destroy`
    /// n'est au journal. Contrôle positif : la vue retirée, la MÊME demande détruit et le journal
    /// l'atteste — le geste est rejouable.
    ///
    /// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint de ce 503.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre l'appel nu à `control_ledger_append` avant la
    /// destruction — le tenant est détruit alors que la seule preuve de sa destruction manque.
    #[tokio::test]
    async fn jae_une_destruction_de_tenant_sans_trace_est_refusee_et_ne_detruit_rien() {
        let (st, _dir) = mk_mode1_state();
        let sa = jae_super_admin();
        assert_eq!(
            tenant_create(State(st.clone()), Extension(sa.clone()), Json(json!({ "id": "jae-beta", "name": "JaeBeta" }))).await.status(),
            StatusCode::CREATED
        );
        let chemin: String = {
            let cp = st.tenants.control.as_ref().expect("mode 1");
            let c = cp.conn.lock();
            c.query_row("SELECT db_path FROM tenant WHERE id='jae-beta'", [], |r| r.get(0)).expect("fixture : le tenant est catalogué")
        };
        assert!(std::path::Path::new(&chemin).exists(), "fixture : la base du tenant existe");

        jae_plan_de_controle(&st, JAE_VUE_SUR_LE_JOURNAL);
        let (statut, v) =
            pb_json(tenant_delete(State(st.clone()), Extension(sa.clone()), Path("jae-beta".into()), Json(json!({ "confirm": "JaeBeta" }))).await)
                .await;
        assert_eq!(statut, 503, "journal muet : la destruction est REFUSÉE : {v}");
        let phrase = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
        assert!(phrase.starts_with(CAUSE_DESTRUCTION_SANS_TRACE), "le refus NOMME sa cause : {v}");
        assert!(std::path::Path::new(&chemin).exists(), "RIEN n'est détruit : la base du tenant est intacte");
        assert!(st.tenants.resolve("jae-beta").is_some(), "et le catalogue le résout encore");

        // CONTRÔLE POSITIF — la vue retirée, la MÊME demande détruit, et le journal l'atteste.
        jae_plan_de_controle(&st, JAE_VUE_RETIREE);
        assert_eq!(jae_genres_de_controle(&st, "tenant.destroy"), 0, "aucune destruction n'a été attestée pendant le refus");
        let r = tenant_delete(State(st.clone()), Extension(sa.clone()), Path("jae-beta".into()), Json(json!({ "confirm": "JaeBeta" }))).await;
        assert_eq!(r.status(), StatusCode::OK, "le refus n'est pas inconditionnel");
        assert!(!std::path::Path::new(&chemin).exists(), "la destruction a lieu");
        assert_eq!(jae_genres_de_controle(&st, "tenant.destroy"), 1, "et sa trace la précède");
    }

    // -------------------------------------------------------------------------------------
    // (4) LES ÉVÉNEMENTS D'ACCÈS — une perte COMPTÉE, par genre, sans identité.
    // -------------------------------------------------------------------------------------

    fn jae_perdus(genre: &str) -> u64 {
        crate::metrics::evenement_d_acces_non_ecrit_de(genre).map(|(n, _)| n).unwrap_or(0)
    }

    /// CE QU'IL TIENT : un échec d'authentification, un verrouillage et un refus d'autorisation que la
    /// base ne prend pas — vue temporaire sur `event`, puis table retirée — montent chacun le compteur de
    /// LEUR genre, et la dernière cause publiée ne porte ni le compte visé ni l'adresse ; aucune ligne
    /// n'entre. Contrôle positif en tête : sur une base saine, les lignes entrent et aucun compteur ne
    /// bouge. L'exposition est lue dans `/api/metrics` (`gather_json`) et dans l'inscription Prometheus.
    ///
    /// CE QU'IL NE TIENT PAS : le compteur est global au processus ; les égalités strictes supposent
    /// qu'aucun autre témoin ne perd un événement d'accès en même temps (aucun ne le fait).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute(..)` dans l'une des deux
    /// ingestions — son genre ne monte plus, la perte redevient muette.
    #[test]
    fn jae_un_evenement_d_acces_que_la_base_refuse_est_compte_et_avoue_sans_identite() {
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
        let lignes = |source: &str, table: &str| -> i64 {
            st.db
                .lock()
                .query_row(&format!("SELECT COUNT(*) FROM {table} WHERE source=?1"), params![source], |r| r.get(0))
                .expect("fixture : le compte se lit")
        };
        let (echecs, verrous, refus) = (jae_perdus("plume-auth.failure"), jae_perdus("plume-auth.lockout"), jae_perdus("plume-authz.denied"));

        // CONTRÔLE POSITIF — base saine : les lignes entrent, aucun compteur ne bouge.
        ingest_auth_event(&st, "failure", "jae-compte", "198.51.100.7", 1, 3);
        ingest_authz_denied(&st, "jae-compte", "viewer", "/api/mode", "POST");
        assert_eq!((lignes("plume-auth", "event"), lignes("plume-authz", "event")), (1, 1), "les deux lignes sont écrites");
        assert_eq!(
            (jae_perdus("plume-auth.failure"), jae_perdus("plume-authz.denied")), (echecs, refus),
            "une écriture réussie n'est pas comptée comme perdue"
        );

        // LA VUE TEMPORAIRE SUR `event` — la base se lit, l'écriture ne passe pas.
        st.db
            .lock()
            .execute_batch("ALTER TABLE event RENAME TO event_source; CREATE TEMP VIEW event AS SELECT * FROM event_source;")
            .expect("fixture : vue posée");
        ingest_auth_event(&st, "failure", "jae-compte", "198.51.100.7", 2, 3);
        ingest_auth_event(&st, "lockout", "jae-compte", "198.51.100.7", 5, 4);
        ingest_authz_denied(&st, "jae-compte", "viewer", "/api/mode", "POST");
        assert_eq!(jae_perdus("plume-auth.failure"), echecs + 1, "l'échec d'authentification non écrit est COMPTÉ");
        assert_eq!(jae_perdus("plume-auth.lockout"), verrous + 1, "le verrouillage non écrit est COMPTÉ, sous son propre genre");
        assert_eq!(jae_perdus("plume-authz.denied"), refus + 1, "le refus d'autorisation non écrit est COMPTÉ");
        for genre in ["plume-auth.failure", "plume-auth.lockout", "plume-authz.denied"] {
            let (_, cause) = crate::metrics::evenement_d_acces_non_ecrit_de(genre).expect("le genre est publié");
            assert!(!cause.is_empty(), "{genre} : la cause du moteur est portée");
            assert!(
                !cause.contains("jae-compte") && !cause.contains("198.51.100.7") && !cause.contains("/api/mode"),
                "{genre} : l'aveu ne porte NI le compte, NI l'adresse, NI la route : {cause}"
            );
        }
        assert_eq!((lignes("plume-auth", "event_source"), lignes("plume-authz", "event_source")), (1, 1), "AUCUNE ligne n'est entrée");

        // LA TABLE RETIRÉE — la préparation elle-même tombe, la perte est comptée pareil.
        st.db
            .lock()
            .execute_batch("DROP VIEW event; ALTER TABLE event_source RENAME TO event_hors_d_atteinte;")
            .expect("fixture : table retirée");
        ingest_authz_denied(&st, "jae-compte", "viewer", "/api/mode", "POST");
        assert_eq!(jae_perdus("plume-authz.denied"), refus + 2, "la table retirée est une perte COMPTÉE, elle aussi");
        st.db.lock().execute_batch("ALTER TABLE event_hors_d_atteinte RENAME TO event;").expect("fixture : table remise");

        // L'EXPOSITION — le total et la ventilation sont servis par `/api/metrics`, la série Prometheus est inscrite.
        let m = crate::gather_json(&st.db.lock(), "/spool", "jae-acces", &crate::handlers::system::VersionDeSchema::Lue(0), 80);
        assert!(m["ingest"]["evenements_d_acces_non_ecrits_total"].as_u64().unwrap_or(0) >= 4, "le total est publié : {}", m["ingest"]);
        assert!(
            m["ingest"]["evenements_d_acces_non_ecrits"]["plume-auth.lockout"]["n"].as_u64().unwrap_or(0) >= 1,
            "la ventilation par genre est publiée : {}", m["ingest"]
        );
        assert!(
            include_str!("../metrics.rs").contains("\"plume_ingest_evenements_d_acces_non_ecrits_total\""),
            "la série Prometheus est inscrite"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) LA QUESTION DE LA CLÉ — ce que la vérification HORS LIGNE du control-plane dit d'une ligne manquante.
    // -------------------------------------------------------------------------------------

    /// LA RÉPONSE À LA QUESTION DE `P10.20-z`, PRISE PAR LES DEUX VÉRIFICATEURS DU JOURNAL DE CONTRÔLE :
    /// `control_ledger_verify_conn` (celui que `verify-control` appelle) et `control_ledger_verify_export`
    /// (la vérification d'une copie exportée, sans la base — `P10.7-r`).
    ///
    /// CE QU'IL TIENT : quatre appels, le troisième refusé par la base, trois lignes : les DEUX
    /// vérificateurs rendent « intègre » — trois maillons, aucune rupture —, le verdict exact d'un journal
    /// complet ; et l'identifiant ne saute pas (`INTEGER PRIMARY KEY` sans `AUTOINCREMENT`). LE
    /// VÉRIFICATEUR HORS LIGNE DU CONTROL-PLANE EST AVEUGLE DE LA MÊME FAÇON QUE `verify_ledger`.
    ///
    /// LE CONTRÔLE POSITIF EST DANS LE CORPS, et il porte sur les INSTRUMENTS : un `detail` réécrit après
    /// coup fait NOMMER la rupture par les deux. Leur silence sur le journal amputé est donc une propriété
    /// de la chaîne, pas un instrument aveugle.
    ///
    /// CE QU'IL NE TIENT PAS : il n'exécute pas le binaire `verify-control`, seulement la fonction qu'il
    /// appelle ; et l'ancrage externe qui rendrait une ligne manquante visible (`P10.7-r`) n'existe pas.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ =` sur l'`INSERT` de la primitive — le troisième
    /// appel n'avoue plus rien, et le journal amputé devient indiscernable d'un journal complet à
    /// l'écriture COMME à la lecture.
    #[test]
    fn jae_une_ligne_de_controle_manquante_ne_rompt_pas_la_chaine_a_la_verification_hors_ligne() {
        // ---- ① LE JOURNAL AMPUTÉ : deux maillons, un TROISIÈME que la base refuse, puis un quatrième. ----
        let (st, _cptmp) = un_control_plane_au_journal_vierge();
        for i in 0..2 {
            assert!(
                control_ledger_append(&st, "grant.set", "op-jae", "acme", &format!("maillon {i}")).cause_de_non_inscription().is_none(),
                "fixture : les deux premiers maillons sont écrits"
            );
        }
        jae_plan_de_controle(&st, JAE_VUE_SUR_LE_JOURNAL);
        assert!(
            control_ledger_append(&st, "grant.remove", "op-jae", "acme", "maillon PERDU").cause_de_non_inscription().is_some(),
            "le maillon perdu est AVOUÉ à l'écriture — c'est le seul endroit où il se voit"
        );
        jae_plan_de_controle(&st, JAE_VUE_RETIREE);
        assert!(
            control_ledger_append(&st, "grant.set", "op-jae", "acme", "maillon d'après la perte").cause_de_non_inscription().is_none(),
            "fixture : le maillon suivant, lui, est écrit"
        );
        let (dernier_id, lignes): (i64, i64) = {
            let cp = st.tenants.control.as_ref().expect("mode 1");
            let c = cp.conn.lock();
            c.query_row("SELECT MAX(id), COUNT(*) FROM control_ledger", [], |r| Ok((r.get(0)?, r.get(1)?))).expect("fixture : le journal se lit")
        };
        assert_eq!(lignes, 3, "fixture : QUATRE appels, TROIS lignes en base");
        assert_eq!(dernier_id, 3, "et l'identifiant ne saute PAS : même le compteur ne trahit pas la perte");

        // ---- ② LES DEUX VERDICTS SUR LE JOURNAL AMPUTÉ : « intègre ». ----
        {
            let cp = st.tenants.control.as_ref().expect("mode 1");
            let c = cp.conn.lock();
            assert_eq!(
                control_ledger_verify_conn(&c),
                Ok((3, None)),
                "LA RÉPONSE À LA QUESTION : `verify-control` rend « trois maillons intègres, aucune rupture » \
                 sur un journal AMPUTÉ — le verdict qu'il rendrait si rien n'avait été perdu"
            );
            let (copie, _, _) = crate::governance::control_ledger_export_lines(&c, 0, 0).expect("le journal s'exporte");
            assert_eq!(
                crate::governance::control_ledger_verify_export(&copie, ""),
                Ok(3),
                "et la copie exportée se vérifie hors ligne comme une chaîne complète"
            );
        }

        // ---- ③ CONTRÔLE POSITIF D'INSTRUMENT : une VRAIE rupture, elle, est NOMMÉE par les deux. ----
        let (st_rompu, _cptmp_rompu) = un_control_plane_au_journal_vierge();
        for i in 0..3 {
            assert!(
                control_ledger_append(&st_rompu, "grant.set", "op-jae", "acme", &format!("maillon {i}")).cause_de_non_inscription().is_none(),
                "fixture : les trois maillons sont écrits"
            );
        }
        let cp = st_rompu.tenants.control.as_ref().expect("mode 1");
        let c = cp.conn.lock();
        let vise: i64 = c.query_row("SELECT MIN(id) + 1 FROM control_ledger", [], |r| r.get(0)).expect("fixture");
        c.execute("UPDATE control_ledger SET detail='détail réécrit après coup' WHERE id=?1", params![vise]).expect("fixture");
        assert_eq!(control_ledger_verify_conn(&c), Ok((1, Some(vise))), "CONTRÔLE POSITIF : `verify-control` NOMME une rupture réelle");
        let (copie, _, _) = crate::governance::control_ledger_export_lines(&c, 0, 0).expect("le journal s'exporte");
        assert!(
            crate::governance::control_ledger_verify_export(&copie, "").is_err(),
            "CONTRÔLE POSITIF : la vérification de la copie NOMME la même rupture"
        );
    }
}
