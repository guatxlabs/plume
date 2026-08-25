// Shared test helpers and cross-area *_TEST_LOCK statics.
// Extracted verbatim from the former single-file main_tests.rs (pure move).

    /// L'ENVIRONNEMENT DU PROCESSUS EST **UNE** RESSOURCE, ET ELLE N'A QU'UN VERROU.
    ///
    /// `cfg()` résout TOUTE clé dans l'ordre `env > conf > défaut`. Poser ou retirer une variable, c'est
    /// donc changer ce que LIT n'importe quel test qui tourne au même instant — y compris un test qui
    /// croyait contrôler cette clé par sa propre `conf`, puisque l'environnement passe devant. La
    /// ressource n'est pas « PLUME_COLD_TIER » ni « PLUME_ROLLUP_MULTIDIM » prise une à une : c'est
    /// l'environnement, un seul objet global au processus.
    ///
    /// CE QU'IL REMPLACE, ET POURQUOI. Neuf verrous distincts gardaient cette ressource unique
    /// (`RBA_ENV_LOCK`, `OTLP_ENV_LOCK`, `COLD_CAPS_ENV_LOCK`, `ROLLUP_DIMS_ENV_LOCK`,
    /// `RETENTION_ENV_LOCK`, `BACKUP_ENV_LOCK`, `B2_ENV_LOCK`, `AI_ENV_LOCK`, `par_env_lock`), et douze
    /// tests n'en prenaient aucun (relevé du 2026-08-25 sur cet arbre : 72 tests mutent l'environnement).
    /// DEUX VERROUS POUR UNE RESSOURCE, C'EST ZÉRO VERROU : chaque famille obtenait la sérialisation
    /// qu'elle croyait avoir vis-à-vis d'elle-même, et aucune vis-à-vis des autres — et le compilateur ne
    /// pouvait pas le voir, les types étant différents. Le prix mesuré le 2026-08-25 : le test froid
    /// `search_declares_what_it_did_not_search_only_when_cold_history_exists` a échoué une fois sur deux
    /// exécutions complètes de la suite froide, sur une assertion qui DIT « tier froid OFF » (sa `conf`
    /// portait `PLUME_COLD_TIER=0`) pendant qu'un test de plafonds posait `PLUME_COLD_TIER=1` dans
    /// l'environnement — donc un message qui accuse le tier d'être éteint alors qu'il était allumé.
    ///
    /// LES DEUX SENS, ET RIEN D'AUTRE :
    ///   · `.write()` — le test **MUTE** l'environnement (`set_var` / `remove_var`, directement ou par un
    ///     utilitaire de test). Il exclut alors tout le monde, le temps de sa portée.
    ///   · `.read()`  — le test **LIT** l'environnement (son résultat en dépend) sans le muter. Les
    ///     lecteurs restent parallèles entre eux : seule la fenêtre de mutation les exclut.
    ///
    /// LA GARDE QUI TIENT LA RÈGLE : `.github/scripts/check_no_test_mutates_the_process_env_unlocked.py`
    /// dérive des sources les tests qui mutent l'environnement (y compris à travers un utilitaire de test,
    /// fonctions associées comprises) et refuse celui qui ne prend pas CE verrou-ci EN ÉCRITURE — muter
    /// sous `.read()` n'exclut personne, les lecteurs étant parallèles entre eux. Sans elle, un dixième
    /// verrou réapparaît.
    ///
    /// Verrou `parking_lot` : il n'empoisonne PAS, donc un panic d'assertion sous garde relâche un verrou
    /// sain au lieu de geler toute la famille — et aucun site d'appel n'a de type de garde à nommer.
    pub(crate) static VERROU_ENV_PROCESSUS: parking_lot::RwLock<()> = parking_lot::RwLock::new(());
    static ENGAGEMENT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static CUSTOM_ROLES_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    // LES RÉGLAGES DE SAUVEGARDE PORTÉS PAR L'ENVIRONNEMENT — `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT`
    // (chemin historique) et `PLUME_BACKUP_REQUIRE_ASYMMETRIC` (refus fail-closed) — sont, eux aussi, des
    // variables de CET environnement : ils n'ont donc pas de verrou à eux. Le défaut qu'ils avaient
    // fermé (mesuré le 2026-08-19, binaire de test, filtre `backup` : `backup_b1_parity_roundtrip`
    // rougissait 2 fois sur 5 en lisant le chemin HISTORIQUE posé par un voisin, et
    // `backup_streaming_survives_an_unusable_staging_dir` en voyant sa sauvegarde REFUSÉE par une
    // exigence d'asymétrique posée ailleurs ; les deux passaient SEULS) reste fermé par
    // `VERROU_ENV_PROCESSUS` avec la MÊME répartition : `.write()` pour qui POSE un réglage, `.read()`
    // pour qui déclenche une sauvegarde. La garde dérivée
    // `aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou` continue de l'exiger, en DÉDUISANT
    // des sources qui déclenche une sauvegarde.

    /// Pose un réglage de sauvegarde LE TEMPS D'UNE PORTÉE et restaure la valeur antérieure au `Drop` —
    /// y compris quand la portée se termine par un panic d'assertion. Un `remove_var` écrit en ligne
    /// droite après la mesure, lui, est SAUTÉ par le déroulement de la pile : la variable resterait posée
    /// pour tout le reste du binaire de test, et le verrou ne protégerait plus rien (parking_lot
    /// n'empoisonne pas). À construire sous `VERROU_ENV_PROCESSUS.write()`.
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
