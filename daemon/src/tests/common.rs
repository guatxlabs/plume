// Shared test helpers and cross-area *_TEST_LOCK statics.
// Extracted verbatim from the former single-file main_tests.rs (pure move).

    static RBA_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // Sérialise les tests qui mutent PLUME_OTLP_* (gate + caps handler) — env process-global.
    static OTLP_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // FIX #18 — sérialise les tests qui mutent PLUME_COLD_TIER/PLUME_COLD_DIR (gate cold des plafonds #49) — env
    // process-global. Uniquement compilé sous la feature cold_tier (les seuls tests qui touchent ces vars).
    #[cfg(feature = "cold_tier")]
    static COLD_CAPS_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static ENGAGEMENT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static CUSTOM_ROLES_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // Sérialise les tests qui mutent PLUME_ROLLUP_DIM_TOPN (plafond du rollup par dimension) — env
    // process-global, lu à CHAQUE tick par `rollup_events`.
    static ROLLUP_DIMS_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // Sérialise les tests qui mutent PLUME_RETENTION_DAYS (fenêtre de rétention) — env process-global.
    static RETENTION_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// LES RÉGLAGES DE SAUVEGARDE PORTÉS PAR L'ENVIRONNEMENT — `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT`
    /// (chemin historique) et `PLUME_BACKUP_REQUIRE_ASYMMETRIC` (refus fail-closed). `backup_compressed`
    /// les RELIT à chaque sauvegarde, et l'environnement est PROCESS-global alors que les tests partagent
    /// le processus : poser l'un d'eux, c'est le poser pour TOUS les tests qui tournent au même instant.
    ///
    /// Verrou LECTEURS/ÉCRIVAIN, pas mutex : ÉCRITURE pour un test qui POSE un réglage, LECTURE pour tout
    /// test qui déclenche une sauvegarde. Les lecteurs restent donc parallèles entre eux (la trentaine de
    /// tests qui sauvegardent ne sont pas sérialisés), et seule la fenêtre de mutation les exclut.
    ///
    /// LE DÉFAUT QUE CE VERROU FERME, MESURÉ (2026-08-19, binaire de test, filtre `backup`, 12 fils) :
    /// `backup_b1_parity_roundtrip` rougissait 2 fois sur 5 en lisant le chemin HISTORIQUE posé par un
    /// voisin là où il attendait le format B1 ; `backup_streaming_survives_an_unusable_staging_dir`
    /// rougissait en voyant sa sauvegarde REFUSÉE par une exigence d'asymétrique posée ailleurs. Les deux
    /// passaient SEULS. La garde dérivée `aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou`
    /// interdit la récidive : elle DÉDUIT des sources qui déclenche une sauvegarde, sans liste à tenir.
    static BACKUP_ENV_LOCK: parking_lot::RwLock<()> = parking_lot::RwLock::new(());

    /// Pose un réglage de sauvegarde LE TEMPS D'UNE PORTÉE et restaure la valeur antérieure au `Drop` —
    /// y compris quand la portée se termine par un panic d'assertion. Un `remove_var` écrit en ligne
    /// droite après la mesure, lui, est SAUTÉ par le déroulement de la pile : la variable resterait posée
    /// pour tout le reste du binaire de test, et le verrou ne protégerait plus rien (parking_lot
    /// n'empoisonne pas). À construire sous `BACKUP_ENV_LOCK.write()`.
    struct ReglageBackupPose {
        cle: &'static str,
        avant: Option<String>,
    }

    impl ReglageBackupPose {
        fn neuf(cle: &'static str, valeur: &str) -> Self {
            let avant = std::env::var(cle).ok();
            std::env::set_var(cle, valeur);
            Self { cle, avant }
        }

        /// Le cas SYMÉTRIQUE : RETIRE le réglage pour la portée. Nécessaire pour éprouver un défaut
        /// « absent -> OFF » sans dépendre de l'environnement de celui qui lance la suite, et sans le
        /// retirer DÉFINITIVEMENT à un opérateur qui l'aurait posé dans son shell.
        fn retire(cle: &'static str) -> Self {
            let avant = std::env::var(cle).ok();
            std::env::remove_var(cle);
            Self { cle, avant }
        }
    }

    impl Drop for ReglageBackupPose {
        fn drop(&mut self) {
            match self.avant.take() {
                Some(v) => std::env::set_var(self.cle, v),
                None => std::env::remove_var(self.cle),
            }
        }
    }

    /// Fixture PARTAGÉE : base complète (schema.sql + TOUTE la chaîne de migrations), celle que la
    /// production construit. Le booléen est ASSERTÉ ici — pas ignoré : cette fixture est utilisée par
    /// des centaines de tests, donc toute régression qui ferait échouer une étape de migration sur une
    /// base saine casse la suite entière au lieu de passer inaperçue. (Les fixtures PARTIELLES, elles,
    /// ignorent volontairement le booléen : elles n'ont jamais eu vocation à satisfaire le contrat.)
    fn test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture de test : la chaîne de migrations doit aller au bout");
        conn
    }

    /// La clé `event.dedup` telle qu'elle est STOCKÉE : le store la CLOISONNE par l'hôte de la ligne
    /// (cf. `ingest::store::dedup_scoped_by_host` — deux machines ne peuvent plus se voler leurs
    /// événements). Un test qui INGÈRE avec une clé d'émetteur puis relit `WHERE dedup=…` doit donc
    /// passer par ici, avec le MÊME hôte que la ligne écrite (`None` = event sans hôte).
    fn ddk(host: Option<&str>, cle: &str) -> String {
        dedup_scoped_by_host(host, Some(cle)).unwrap()
    }

    /// Helper : insère un event env-scopé au ts donné. env_id + origin par défaut ('' = purgeable).
    fn ins_ev(c: &Connection, ts: i64, env: &str, msg: &str) {
        c.execute("INSERT INTO event(ts,source,message,env_id,origin) VALUES(?1,'agent',?2,?3,'')", params![ts, msg, env]).unwrap();
    }

    fn ergo_au(role: &str) -> AuthUser {
        AuthUser { name: format!("{role}-u"), role: role.into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }
