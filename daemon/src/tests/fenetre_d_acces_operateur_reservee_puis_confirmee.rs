// =====================================================================================
// `P10.21-q` (volet démon) — LA FENÊTRE DE DEBOUNCE D'UN ACCÈS OPÉRATEUR EST RÉSERVÉE PUIS CONFIRMÉE :
// UNE LECTURE CONCURRENTE NE S'APPUIE JAMAIS SUR UNE TRACE QUI N'EST PAS ENCORE ÉCRITE.
//
// LE DÉFAUT. `operator_access_should_emit` armait la fenêtre (horodatage dans `OPERATOR_ACCESS_LAST`)
// AVANT l'INSERT de l'événement dans la base du tenant visité. Une lecture B arrivée pendant l'écriture
// de A prenait la branche débouncée (`CouvertParLaFenetre`) et comptait comme tracée ; si l'INSERT de A
// échouait ensuite et que le maillon de contrôle de B échouait aussi, B était servie sans aucune trace.
//
// LE CORRECTIF (décision par défaut de la vague) : A RÉSERVE la fenêtre (jeton), écrit, et ne la
// CONFIRME qu'après l'INSERT réussi ; seule une fenêtre confirmée couvre. B, qui voit une réservation non
// confirmée, écrit elle-même sa trace. Un échec oublie la réservation de son jeton seulement.
//
// LA COURSE, RENDUE DÉTERMINISTE : le témoin tient le verrou de la connexion du tenant visité. A, lancée
// sur un fil, réserve puis bloque sur ce verrou, AVANT son INSERT ; B est lancée pendant ce temps par le
// VRAI point d'entrée (`emit_operator_access`, celui qu'appelle le garde d'authentification). Le témoin
// attend que B ait décidé (réservation de B visible, ou B terminée), puis relâche le verrou.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le garde d'authentification et la réponse HTTP (tenus par
// `acces_operateur_sans_trace_refuse.rs`, ici l'issue `TraceDAccesOperateur` et son refus) ; l'expiration
// réelle de la fenêtre ; la garde de `confirmer_la_fenetre` qui garde une fenêtre confirmée plus récente
// (horodatage à la seconde : inobservable sans attente chronométrée, limite écrite sur la fonction) ; la
// console (volet `web/` de la clé).
// =====================================================================================
mod fenetre_d_acces_operateur_reservee_puis_confirmee {
    use super::*;

    struct FapcBanc {
        st: AppState,
        tenant: &'static str,
        base: Arc<Mutex<rusqlite::Connection>>,
        _plan: crate::tmp_possede::TmpDb,
        _chemin: crate::tmp_possede::TmpDb,
    }

    fn fapc_banc(tenant: &'static str) -> FapcBanc {
        let (cp, plan) = mk_test_control();
        let chemin = mk_tmp_path(&format!("{tenant}.db"));
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'V','',?2,?3,0)",
                params![tenant, chemin.as_str(), now()],
            )
            .expect("fixture : tenant visité catalogué");
        let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        let base = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
        {
            let c = base.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
            let _ = migrate(&c);
        }
        FapcBanc { st, tenant, base, _plan: plan, _chemin: chemin }
    }

    impl FapcBanc {
        fn plan(&self, sql: &str) {
            self.st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock().execute_batch(sql)
                .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
        }
        fn evenements(&self, table: &str) -> i64 {
            self.base
                .lock()
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\" WHERE source='plume-operator-access'"), [], |r| r.get(0))
                .expect("fixture : les événements se lisent")
        }
    }

    fn fapc_vue_sur(table: &str) -> String {
        format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_source\"; CREATE TEMP VIEW \"{table}\" AS SELECT * FROM \"{table}_source\";")
    }
    fn fapc_vue_retiree(table: &str) -> String {
        format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_source\" RENAME TO \"{table}\";")
    }

    fn fapc_fenetre(operateur: &str, tenant: &str) -> Option<FenetreDAccesOperateur> {
        OPERATOR_ACCESS_LAST.get().and_then(|c| c.lock().get(&(operateur.to_string(), tenant.to_string())).copied())
    }

    /// Attente d'un fait posé par un autre fil ; la borne n'est qu'un garde-fou contre un fil bloqué, elle
    /// ne mesure rien.
    fn fapc_attendre(quoi: &str, fait: impl Fn() -> bool) {
        for _ in 0..20_000 {
            if fait() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("fixture : {quoi} n'est jamais arrivé");
    }

    /// Lance A (lecture) pendant que le témoin tient la base du tenant, attend sa réservation, lance B,
    /// attend la décision de B, relâche la base, et rend les deux issues (A, B).
    fn fapc_course(banc: &FapcBanc, operateur: &'static str) -> (TraceDAccesOperateur, TraceDAccesOperateur) {
        let tenant = banc.tenant;
        let garde = banc.base.lock();
        let st_a = banc.st.clone();
        let a = std::thread::spawn(move || emit_operator_access(&st_a, operateur, tenant, false, None));
        fapc_attendre("la réservation de A", || fapc_fenetre(operateur, tenant).is_some());
        let jeton_a = fapc_fenetre(operateur, tenant).expect("fixture : A a réservé").jeton;
        let st_b = banc.st.clone();
        let b = std::thread::spawn(move || emit_operator_access(&st_b, operateur, tenant, false, None));
        fapc_attendre("la décision de B", || b.is_finished() || fapc_fenetre(operateur, tenant).is_some_and(|f| f.jeton != jeton_a));
        drop(garde);
        (a.join().expect("fil A"), b.join().expect("fil B"))
    }

    /// (a) A ÉCHOUE, B CONCURRENTE, son maillon échoue aussi : B est REFUSÉE (`AucuneTrace`, 503), jamais
    /// servie sur la fenêtre de A ; et aucune réservation ne survit aux deux échecs.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `q_confirmer_avant_l_ecriture` (la réservation couvre dès sa pose :
    /// B passe en `AuMoinsUneTrace`) ; `q_garder_la_reservation_sur_echec` (la réservation de B reste dans
    /// la table).
    #[test]
    fn fapc_une_lecture_concurrente_d_une_ecriture_qui_echoue_n_est_jamais_servie_sans_trace() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = fapc_banc("fapc-a-visite");
        banc.plan(&fapc_vue_sur("control_ledger"));
        banc.base.lock().execute_batch(&fapc_vue_sur("event")).expect("fixture : vue posée");

        let (a, b) = fapc_course(&banc, "op-fapc-a");

        assert!(
            matches!(b, TraceDAccesOperateur::AucuneTrace { .. }),
            "B ne s'appuie pas sur la fenêtre réservée par une écriture qui a échoué : {b:?}"
        );
        let refus = b.refus_si_aucune_trace().expect("B est refusée avant d'être servie");
        assert_eq!(refus.status(), StatusCode::SERVICE_UNAVAILABLE, "refus en cinq cent trois");
        assert!(matches!(a, TraceDAccesOperateur::AucuneTrace { .. }), "A n'a aucune trace non plus : {a:?}");
        assert_eq!(
            fapc_fenetre("op-fapc-a", banc.tenant),
            None,
            "les deux échecs oublient leur réservation : rien ne reste dans la table"
        );

        banc.plan(&fapc_vue_retiree("control_ledger"));
        banc.base.lock().execute_batch(&fapc_vue_retiree("event")).expect("fixture : vue retirée");
        assert_eq!(banc.evenements("event"), 0, "aucune ligne n'est entrée");
        let reprise = emit_operator_access(&banc.st, "op-fapc-a", banc.tenant, false, None);
        assert!(matches!(reprise, TraceDAccesOperateur::AuMoinsUneTrace), "la reprise est tracée : {reprise:?}");
        assert_eq!(banc.evenements("event"), 1, "la reprise écrit l'événement");
        assert!(
            fapc_fenetre("op-fapc-a", banc.tenant).is_some_and(|f| f.confirmee),
            "la fenêtre n'est confirmée qu'après l'écriture réussie"
        );
    }

    /// (b) B CONCURRENTE D'UNE ÉCRITURE EN COURS, base saine, maillon refusé : B écrit SA propre trace —
    /// deux événements entrent — et la fenêtre finit confirmée.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `q_confirmer_avant_l_ecriture` (B est débouncée sur la réservation de
    /// A : un seul événement).
    #[test]
    fn fapc_une_lecture_concurrente_d_une_ecriture_en_cours_ecrit_sa_propre_trace() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = fapc_banc("fapc-b-visite");
        banc.plan(&fapc_vue_sur("control_ledger"));

        let (a, b) = fapc_course(&banc, "op-fapc-b");
        banc.plan(&fapc_vue_retiree("control_ledger"));

        assert!(matches!(a, TraceDAccesOperateur::AuMoinsUneTrace), "A est tracée par son événement : {a:?}");
        assert!(matches!(b, TraceDAccesOperateur::AuMoinsUneTrace), "B est tracée par son événement : {b:?}");
        assert_eq!(banc.evenements("event"), 2, "B a écrit sa propre trace au lieu de s'appuyer sur la réservation de A");
        assert!(fapc_fenetre("op-fapc-b", banc.tenant).is_some_and(|f| f.confirmee), "la fenêtre finit confirmée");
    }

    /// (c) DEUX LECTURES CONCURRENTES, la SECONDE insertion (quel que soit l'ordre d'arrivée sur la base)
    /// refusée par un déclencheur : l'échec de l'une n'efface pas la fenêtre que l'autre a confirmée ; une
    /// troisième lecture est couverte. Structurel : les deux lectures décident pendant que le témoin tient
    /// la base, la décision vient de l'état de la table et non d'une horloge.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `q_oublier_sans_jeton` (l'échec retire la fenêtre quel que soit son
    /// jeton : plus de fenêtre, la troisième lecture écrit).
    #[test]
    fn fapc_l_echec_d_une_lecture_n_efface_pas_la_fenetre_confirmee_par_l_autre() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = fapc_banc("fapc-c-visite");
        banc.base
            .lock()
            .execute_batch(
                "CREATE TEMP TRIGGER fapc_seconde_refusee BEFORE INSERT ON event \
                 WHEN (SELECT COUNT(*) FROM main.event WHERE source='plume-operator-access') >= 1 \
                 BEGIN SELECT RAISE(ABORT, 'fapc : seconde insertion refusée'); END;",
            )
            .expect("fixture : déclencheur posé");

        let (a, b) = fapc_course(&banc, "op-fapc-c");
        banc.base.lock().execute_batch("DROP TRIGGER fapc_seconde_refusee;").expect("fixture : déclencheur retiré");

        assert!(matches!(a, TraceDAccesOperateur::AuMoinsUneTrace), "A est tracée (maillon inscrit) : {a:?}");
        assert!(matches!(b, TraceDAccesOperateur::AuMoinsUneTrace), "B est tracée (maillon inscrit) : {b:?}");
        assert_eq!(banc.evenements("event"), 1, "une seule des deux lectures a écrit son événement");
        assert!(
            fapc_fenetre("op-fapc-c", banc.tenant).is_some_and(|f| f.confirmee),
            "la fenêtre confirmée par la lecture qui a écrit survit à l'échec de l'autre"
        );
        let c = emit_operator_access(&banc.st, "op-fapc-c", banc.tenant, false, None);
        assert!(matches!(c, TraceDAccesOperateur::AuMoinsUneTrace), "la troisième lecture passe : {c:?}");
        assert_eq!(banc.evenements("event"), 1, "la troisième lecture est couverte par la fenêtre confirmée");
    }

    /// (d) CHAQUE RÉSERVATION A SON JETON : deux réservations successives du même couple, sans
    /// confirmation entre elles, rendent deux jetons distincts — c'est ce qui permet à un échec de ne
    /// retirer que la sienne.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `q_jeton_constant` (tous les accès partagent un jeton).
    #[test]
    fn fapc_deux_reservations_du_meme_couple_ont_deux_jetons_distincts() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let (op, tenant, t) = ("op-fapc-d", "fapc-d-visite", now());
        let premiere = operator_access_should_emit(op, tenant, t, false);
        let seconde = operator_access_should_emit(op, tenant, t, false);
        OPERATOR_ACCESS_LAST.get().expect("table initialisée").lock().remove(&(op.to_string(), tenant.to_string()));
        let (DecisionDeFenetre::Reservee(j1), DecisionDeFenetre::Reservee(j2)) = (premiere, seconde) else {
            panic!("une réservation non confirmée ne couvre rien : deux réservations attendues ({premiere:?}, {seconde:?})");
        };
        assert_ne!(j1, j2, "deux réservations du même couple portent deux jetons distincts");
    }

    /// (e) UN ACCÈS FORCÉ (break-glass) DONT L'ÉVÉNEMENT EST REFUSÉ n'efface pas la fenêtre confirmée par
    /// une lecture : elle reste telle quelle, et la lecture suivante reste couverte par l'événement écrit.
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `q_force_remplace_la_fenetre_confirmee` (le forcé pose sa réservation
    /// par-dessus la fenêtre confirmée, son échec la retire : la lecture suivante écrit un second
    /// événement) ; aussi `q_oublier_sans_jeton` et `q_jeton_constant` (l'échec du forcé retire la fenêtre
    /// de la lecture).
    #[test]
    fn fapc_un_acces_force_qui_echoue_n_efface_pas_la_fenetre_confirmee_d_une_lecture() {
        let _verrou = acces_operateur_sans_trace_refuse::VERROU_DES_TRACES_D_ACCES_OPERATEUR.lock();
        let banc = fapc_banc("fapc-e-visite");
        let op = "op-fapc-e";
        let lecture = emit_operator_access(&banc.st, op, banc.tenant, false, None);
        assert!(matches!(lecture, TraceDAccesOperateur::AuMoinsUneTrace), "fixture : la lecture est tracée : {lecture:?}");
        assert_eq!(banc.evenements("event"), 1, "fixture : la lecture a écrit son événement");
        let avant = fapc_fenetre(op, banc.tenant);
        assert!(avant.is_some_and(|f| f.confirmee), "fixture : la fenêtre de la lecture est confirmée");

        banc.base
            .lock()
            .execute_batch(
                "CREATE TEMP TRIGGER fapc_force_refuse BEFORE INSERT ON event WHEN NEW.severity = 4 \
                 BEGIN SELECT RAISE(ABORT, 'fapc : événement forcé refusé'); END;",
            )
            .expect("fixture : déclencheur posé");
        let force = emit_operator_access(&banc.st, op, banc.tenant, true, Some("incident-fapc-e"));
        banc.base.lock().execute_batch("DROP TRIGGER fapc_force_refuse;").expect("fixture : déclencheur retiré");
        assert!(matches!(force, TraceDAccesOperateur::AuMoinsUneTrace), "le forcé reste tracé par son maillon : {force:?}");
        assert_eq!(banc.evenements("event"), 1, "fixture : l'événement du forcé a bien été refusé");

        assert_eq!(fapc_fenetre(op, banc.tenant), avant, "l'échec du forcé laisse la fenêtre confirmée telle quelle");
        let suivante = emit_operator_access(&banc.st, op, banc.tenant, false, None);
        assert!(matches!(suivante, TraceDAccesOperateur::AuMoinsUneTrace), "la lecture suivante passe : {suivante:?}");
        assert_eq!(banc.evenements("event"), 1, "la lecture suivante reste couverte par l'événement de la première");
    }
}
