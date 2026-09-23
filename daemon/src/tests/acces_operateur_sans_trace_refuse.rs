// =====================================================================================
// `P10.21-p` — UN ACCÈS OPÉRATEUR CROSS-TENANT QUI NE PEUT ÊTRE TRACÉ NULLE PART EST REFUSÉ AVANT D'ÊTRE
// SERVI ; UNE SEULE TRACE PERDUE LAISSE PASSER, ET SA PERTE RESTE COMPTÉE.
//
// LA DÉCISION D'EXPLOITATION APPLIQUÉE. Un accès aux données d'un autre tenant laisse deux traces : un
// maillon du journal du plan de contrôle et un événement `plume-operator-access` dans la base du tenant
// visité. Jusqu'ici leur perte était comptée (`acces_operateur_non_traces`, `P10.21-g`) et l'accès
// passait quand même — même quand AUCUNE des deux n'était écrite, ce qui rendait l'accès indétectable
// après coup. Désormais le garde d'authentification refuse en 503, avec la cause
// `CAUSE_ACCES_OPERATEUR_SANS_TRACE`, AVANT le gestionnaire, en lecture comme en écriture d'urgence.
//
// L'ORDRE, MESURÉ DANS LA SOURCE AVANT LE CORRECTIF : les deux écritures avaient DÉJÀ lieu avant
// `next.run` (garde d'authentification, après la disponibilité du tenant et avant l'inventaire des
// accès) ; il manquait seulement que leur issue remonte. Le DEBOUNCE des lectures : la première lecture
// d'une fenêtre écrit l'événement ; les suivantes de la même fenêtre ne le réécrivent pas et s'appuient
// sur lui — la fenêtre n'est armée que par un événement ÉCRIT (`P10.21-g` l'oublie sur une perte), donc
// une lecture débouncée a toujours une trace de tenant derrière elle.
//
// LA VOIE D'ÉCHEC : la VUE TEMPORAIRE de même nom posée par-dessus la table renommée (`control_ledger`
// sur le plan de contrôle, `event` sur la base du tenant) — la lecture de la tête de chaîne passe, seule
// l'écriture tombe. Les requêtes traversent le VRAI garde d'authentification (identité d'annuaire par
// en-têtes, groupe super-administrateur), monté devant une sonde qui compte ses exécutions : « aucune
// donnée servie » se lit comme « la sonde n'a pas tourné ».
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils montent le garde devant une sonde, pas le routeur complet
// (les couches autour du garde ne décident rien ici) ; ils éprouvent un objet non modifiable, pas une
// base réellement en lecture seule ; le compteur est global au processus — les témoins qui perdent une
// trace d'accès opérateur (ceux-ci et `ecc_un_acces_operateur_dont_la_trace_manque_est_compte_sans_identite`)
// se sérialisent par `VERROU_DES_TRACES_D_ACCES_OPERATEUR` ; la course où une lecture concurrente est
// débouncée PENDANT que l'écriture qui a armé la fenêtre échoue n'a pas de témoin ; et ils ne jugent pas
// ce que la console peint du refus neuf.
// =====================================================================================
mod acces_operateur_sans_trace_refuse {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Les témoins qui PERDENT une trace d'accès opérateur mesurent le compteur global par différence :
    /// ils se sérialisent ici. `parking_lot` n'empoisonne pas : un rouge ne gèle pas les voisins.
    pub(crate) static VERROU_DES_TRACES_D_ACCES_OPERATEUR: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// Exécutions de la sonde — la « donnée du tenant ». Lue sous le verrou ci-dessus.
    static AOST_SONDE_EXECUTEE: AtomicUsize = AtomicUsize::new(0);
    const AOST_DONNEE: &str = "DONNEE-DU-TENANT-VISITE";
    const AOST_SECRET_SSO: &str = "aost-secret-sso";
    const AOST_CHEMIN: &str = "/api/cases"; // GET = lecture (viewer), POST = écriture (break-glass) ; jamais un POST de lecture

    async fn aost_sonde() -> &'static str {
        AOST_SONDE_EXECUTEE.fetch_add(1, Ordering::SeqCst);
        AOST_DONNEE
    }

    struct AostBanc {
        st: AppState,
        adresse: std::net::SocketAddr,
        tenant: &'static str,
        _plan: crate::tmp_possede::TmpDb,
        _base: crate::tmp_possede::TmpDb,
    }

    /// Un plan de contrôle, un tenant visité catalogué et migré, et le garde d'authentification RÉEL monté
    /// devant la sonde. L'opérateur est un super-administrateur d'annuaire, non membre du tenant visité.
    async fn aost_banc(tenant: &'static str) -> AostBanc {
        let (cp, plan) = mk_test_control();
        let base = mk_tmp_path(&format!("{tenant}.db"));
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'V','',?2,?3,0)",
                params![tenant, base.as_str(), now()],
            )
            .expect("fixture : tenant visité catalogué");
        let mut st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        st.sso_secret = Arc::new(AOST_SECRET_SSO.to_string());
        st.pass_hash = Arc::new("fixture : hors du mode d'installation".to_string());
        {
            let h = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
            let _ = migrate(&c);
        }
        let app = axum::Router::new()
            .route(AOST_CHEMIN, axum::routing::get(aost_sonde).post(aost_sonde))
            .layer(axum::middleware::from_fn_with_state(st.clone(), auth_guard))
            .with_state(st.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("fixture : port local");
        let adresse = l.local_addr().expect("fixture : adresse liée");
        tokio::spawn(async move {
            let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
        });
        AostBanc { st, adresse, tenant, _plan: plan, _base: base }
    }

    impl AostBanc {
        /// Une requête de l'opérateur `operateur` vers le tenant visité ; `urgence` = break-glass (POST).
        async fn acceder(&self, operateur: &str, urgence: Option<&str>) -> (u16, String) {
            let mut entetes = vec![
                ("x-plume-sso-secret", AOST_SECRET_SSO),
                ("x-authentik-username", operateur),
                ("x-authentik-groups", "admins"),
                ("x-plume-tenant", self.tenant),
            ];
            let methode = match urgence {
                Some(raison) => {
                    entetes.push(("x-plume-breakglass", raison));
                    // Une mutation sous identité d'annuaire exige la même origine (garde CSRF, en amont).
                    entetes.push(("origin", "http://127.0.0.1"));
                    "POST"
                }
                None => "GET",
            };
            let (code, brut) = router_probe_corps(self.adresse, methode, AOST_CHEMIN, None, &entetes).await;
            let corps = brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
            (code, corps)
        }

        fn plan(&self, sql: &str) {
            self.st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock().execute_batch(sql)
                .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
        }
        fn base(&self, sql: &str) {
            self.st.tenants.handle_for(self.tenant).expect("fixture : base du tenant").lock().execute_batch(sql)
                .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
        }
        fn maillons(&self, genre: &str) -> i64 {
            self.st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock()
                .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1 AND tenant=?2", params![genre, self.tenant], |r| r.get(0))
                .expect("fixture : le journal de contrôle se lit")
        }
        fn evenements(&self) -> i64 {
            self.st.tenants.handle_for(self.tenant).expect("fixture : base du tenant").lock()
                .query_row("SELECT COUNT(*) FROM event WHERE source='plume-operator-access'", [], |r| r.get(0))
                .expect("fixture : les événements se lisent")
        }
    }

    fn aost_vue_sur(table: &str) -> String {
        format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT * FROM \"{table}_source\";")
    }
    fn aost_vue_retiree(table: &str) -> String {
        format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";")
    }

    fn aost_perdus(trace: &str) -> u64 {
        crate::metrics::acces_operateur_non_trace_de(trace).map(|(n, _)| n).unwrap_or(0)
    }
    fn aost_executions() -> usize {
        AOST_SONDE_EXECUTEE.load(Ordering::SeqCst)
    }

    fn aost_servi(quoi: &str, (code, corps): &(u16, String)) {
        assert_eq!(*code, 200, "{quoi} : l'accès passe : {corps}");
        assert!(corps.contains(AOST_DONNEE), "{quoi} : la donnée est servie : {corps}");
    }

    fn aost_refuse(quoi: &str, (code, corps): &(u16, String), operateur: &str, tenant: &str) {
        assert_eq!(*code, 503, "{quoi} : un accès sans aucune trace est REFUSÉ en 503 : {corps}");
        let v: Value = serde_json::from_str(corps).unwrap_or_else(|e| panic!("{quoi} : refus JSON ({e}) : {corps}"));
        assert_eq!(v["error"].as_str(), Some(CAUSE_ACCES_OPERATEUR_SANS_TRACE), "{quoi} : le refus NOMME sa cause : {corps}");
        assert!(!corps.contains(AOST_DONNEE), "{quoi} : aucune donnée servie : {corps}");
        assert!(
            !corps.contains(operateur) && !corps.contains(tenant) && !corps.contains(AOST_SECRET_SSO),
            "{quoi} : le refus ne nomme ni le compte, ni le tenant, ni le secret : {corps}"
        );
    }

    /// (a) CE QU'IL TIENT : sous les DEUX vues temporaires, une lecture cross-tenant — la PREMIÈRE de sa
    /// fenêtre de debounce — rend un 503 nommé, la sonde ne tourne pas, aucune ligne n'entre, et les deux
    /// traces de lecture sont comptées ; un break-glass en écriture, pareil (traces d'écriture comptées).
    /// Les vues retirées, la même lecture passe et ÉCRIT l'événement : le refus n'a pas consommé la fenêtre.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : retirer le refus du garde d'authentification — la sonde tourne,
    /// deux cents.
    #[tokio::test]
    async fn aost_un_acces_sans_aucune_trace_est_refuse_avant_le_gestionnaire() {
        let _verrou = VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = aost_banc("aost-a-visite").await;
        let avant: Vec<u64> = [
            TRACE_OPERATEUR_CONTROLE_LECTURE,
            TRACE_OPERATEUR_TENANT_LECTURE,
            TRACE_OPERATEUR_CONTROLE_ECRITURE,
            TRACE_OPERATEUR_TENANT_ECRITURE,
        ]
        .iter()
        .map(|t| aost_perdus(t))
        .collect();
        let executions = aost_executions();

        banc.plan(&aost_vue_sur("control_ledger"));
        banc.base(&aost_vue_sur("event"));
        let lecture = banc.acceder("op-aost-a", None).await;
        aost_refuse("lecture", &lecture, "op-aost-a", banc.tenant);
        let urgence = banc.acceder("op-aost-a", Some("incident-aost")).await;
        aost_refuse("break-glass", &urgence, "op-aost-a", banc.tenant);
        assert!(!urgence.1.contains("incident-aost"), "le refus ne porte pas la raison du break-glass : {}", urgence.1);
        assert_eq!(aost_executions(), executions, "la sonde n'a PAS tourné : rien n'a été lu ni écrit");
        assert_eq!(aost_perdus(TRACE_OPERATEUR_CONTROLE_LECTURE) - avant[0], 1, "le maillon de lecture perdu est compté");
        assert_eq!(aost_perdus(TRACE_OPERATEUR_TENANT_LECTURE) - avant[1], 1, "l'événement de lecture perdu est compté");
        assert_eq!(aost_perdus(TRACE_OPERATEUR_CONTROLE_ECRITURE) - avant[2], 1, "le maillon d'écriture perdu est compté");
        assert_eq!(aost_perdus(TRACE_OPERATEUR_TENANT_ECRITURE) - avant[3], 1, "l'événement d'écriture perdu est compté");
        banc.plan(&aost_vue_retiree("control_ledger"));
        banc.base(&aost_vue_retiree("event"));
        assert_eq!((banc.maillons("superadmin.read"), banc.maillons("superadmin.write"), banc.evenements()), (0, 0, 0), "aucune ligne n'est entrée");

        let reprise = banc.acceder("op-aost-a", None).await;
        aost_servi("lecture reprise", &reprise);
        assert_eq!(banc.evenements(), 1, "la lecture reprise écrit l'événement : le refus n'a pas armé la fenêtre");
        assert_eq!(banc.maillons("superadmin.read"), 1, "et son maillon");
    }

    /// (b) CE QU'IL TIENT : une seule des deux traces refusée, l'accès PASSE et la perte est comptée —
    /// maillon refusé (vue sur `control_ledger`) : servi, `control_ledger.superadmin.read` +1, l'événement
    /// écrit ; événement refusé (vue sur `event`, autre opérateur, fenêtre neuve) : servi,
    /// `tenant.plume-operator-access.read` +1, le maillon écrit.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : refuser dès qu'UNE trace manque — cinq cent trois.
    #[tokio::test]
    async fn aost_une_seule_trace_perdue_laisse_passer_et_reste_comptee() {
        let _verrou = VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = aost_banc("aost-b-visite").await;
        let controle = aost_perdus(TRACE_OPERATEUR_CONTROLE_LECTURE);
        let tenant = aost_perdus(TRACE_OPERATEUR_TENANT_LECTURE);
        let executions = aost_executions();

        banc.plan(&aost_vue_sur("control_ledger"));
        aost_servi("maillon refusé", &banc.acceder("op-aost-b1", None).await);
        banc.plan(&aost_vue_retiree("control_ledger"));
        assert_eq!(aost_perdus(TRACE_OPERATEUR_CONTROLE_LECTURE) - controle, 1, "le maillon perdu est compté");
        assert_eq!((banc.maillons("superadmin.read"), banc.evenements()), (0, 1), "l'événement, lui, est écrit");

        banc.base(&aost_vue_sur("event"));
        aost_servi("événement refusé", &banc.acceder("op-aost-b2", None).await);
        banc.base(&aost_vue_retiree("event"));
        assert_eq!(aost_perdus(TRACE_OPERATEUR_TENANT_LECTURE) - tenant, 1, "l'événement perdu est compté");
        assert_eq!((banc.maillons("superadmin.read"), banc.evenements()), (1, 1), "le maillon, lui, est écrit");
        assert_eq!(aost_executions() - executions, 2, "les deux accès ont été servis");
    }

    /// (c) CONTRÔLE POSITIF : bases saines, une lecture et un break-glass passent, un maillon et un
    /// événement chacun, aucun compteur ne bouge.
    #[tokio::test]
    async fn aost_deux_traces_ecrites_l_acces_passe_sans_rien_compter() {
        let _verrou = VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = aost_banc("aost-c-visite").await;
        let traces = [
            TRACE_OPERATEUR_CONTROLE_LECTURE,
            TRACE_OPERATEUR_CONTROLE_ECRITURE,
            TRACE_OPERATEUR_TENANT_LECTURE,
            TRACE_OPERATEUR_TENANT_ECRITURE,
        ];
        let avant: u64 = traces.iter().map(|t| aost_perdus(t)).sum();
        aost_servi("lecture", &banc.acceder("op-aost-c", None).await);
        aost_servi("break-glass", &banc.acceder("op-aost-c", Some("incident-aost")).await);
        assert_eq!((banc.maillons("superadmin.read"), banc.maillons("superadmin.write"), banc.evenements()), (1, 1, 2));
        assert_eq!(traces.iter().map(|t| aost_perdus(t)).sum::<u64>(), avant, "aucune trace n'est comptée perdue");
    }

    /// (d) LE DEBOUNCE : une première lecture TRACÉE (maillon et événement) arme la fenêtre ; dans la même
    /// fenêtre, une seconde lecture dont le maillon est refusé PASSE — elle s'appuie sur l'événement déjà
    /// posé, qu'elle ne réécrit pas — et la perte du maillon est comptée.
    ///
    /// CE QU'IL NE TIENT PAS : l'expiration de la fenêtre (horloge réelle, dix minutes).
    #[tokio::test]
    async fn aost_une_lecture_debouncee_s_appuie_sur_la_trace_de_sa_fenetre() {
        let _verrou = VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = aost_banc("aost-d-visite").await;
        let controle = aost_perdus(TRACE_OPERATEUR_CONTROLE_LECTURE);
        let tenant = aost_perdus(TRACE_OPERATEUR_TENANT_LECTURE);

        aost_servi("première lecture", &banc.acceder("op-aost-d", None).await);
        assert_eq!((banc.maillons("superadmin.read"), banc.evenements()), (1, 1), "la première lecture pose ses deux traces");

        banc.plan(&aost_vue_sur("control_ledger"));
        aost_servi("seconde lecture, maillon refusé", &banc.acceder("op-aost-d", None).await);
        banc.plan(&aost_vue_retiree("control_ledger"));
        assert_eq!(aost_perdus(TRACE_OPERATEUR_CONTROLE_LECTURE) - controle, 1, "le maillon perdu est compté");
        assert_eq!(aost_perdus(TRACE_OPERATEUR_TENANT_LECTURE) - tenant, 0, "l'événement n'est pas perdu : il est débouncé");
        assert_eq!((banc.maillons("superadmin.read"), banc.evenements()), (1, 1), "rien n'est réécrit dans la fenêtre");
    }
}
