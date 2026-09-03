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

    // `P7.19-j` — LA POPULATION DES LECTEURS A ÉTÉ DÉRIVÉE, ET UNE GARDE A ÉTÉ REFUSÉE. LE CHIFFRE.
    //
    // CE QUI EST GARDÉ AUJOURD'HUI, EXACTEMENT. Deux gardes, et l'une des deux juge bien des LECTEURS :
    //   · les ÉCRIVAINS, toutes clés confondues — `check_no_test_mutates_the_process_env_unlocked.py`
    //     exige `.write()` de tout test qui MUTE l'environnement ;
    //   · les LECTEURS D'UNE SEULE FAMILLE — `aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou`
    //     exige `.read()` de tout test qui déclenche une SAUVEGARDE (clés `PLUME_BACKUP_*`).
    // L'angle mort n'est donc pas « les lecteurs ne sont pas gardés » : c'est que la garde des lecteurs
    // est adossée à UNE famille de clés, et que le défaut est entré par une AUTRE (`PLUME_COLD_TIER`).
    //
    // LA POPULATION, DÉRIVÉE ET NON ÉNUMÉRÉE (mesurée le 2026-09-03 sur cet arbre, par la mécanique de
    // la garde de sauvegarde généralisée aux 22 clés que la caisse POSE). « Nu » = un `#[test]` qui
    // atteint un lecteur de production d'une de ces clés sans prendre ce verrou. Selon la profondeur de
    // dérivation — 0 = le test appelle la fonction qui NOMME la clé ; n = plus n crans d'appelants
    // publics, ce que fait la garde de sauvegarde existante :
    //     profondeur 0 : 111 gardés,  54 nus        profondeur 2 : 155 gardés, 228 nus
    //     profondeur 1 : 151 gardés, 183 nus        profondeur 4 : 155 gardés, 326 nus
    //
    // LA GARDE EST REFUSÉE, ET C'EST LE RAPPORT QUI TRANCHE. Un seul lecteur nu a JAMAIS été mesuré
    // exposé (`idx49_row_and_size_caps` : jeu réduit joué huit fois, six rouges). La garde la plus
    // ÉTROITE concevable en accuserait 54, la plus large 326 — pour un fautif connu. Un rouge
    // d'intégration sur 54 à 326 témoins légitimes, qu'aucun geste utile ne referme, est une RANÇON :
    // il serait payé en `.read()` posés au hasard, ce qui n'ajoute aucune propriété et retire le sens
    // du verrou. Le compte est écrit ici pour que le refus soit RELISIBLE, et non refait à l'aveugle.
    //
    // CE QUI A ÉTÉ FAIT À LA PLACE, ET SA BORNE. Le verrou est posé sur la FAMILLE ENTIÈRE de
    // `retention_run` — les douze lecteurs nus restants, en plus du seul exposé — parce qu'un lecteur
    // « inoffensif aujourd'hui » ne l'est que tant que le drapeau ne change pas ce qu'il éprouve. Cela
    // ferme la famille NOMMÉE ; cela ne ferme pas la classe. La voie qui la fermerait — une lecture qui
    // ne passe plus par l'environnement du processus — bute sur `main::cfg`, dont la précédence
    // `env > conf > défaut` est un CONTRAT D'EXPLOITATION (systemd / k3s posent des `PLUME_*`) : la
    // changer pour arranger la caisse serait corriger le produit au bénéfice du banc.

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
