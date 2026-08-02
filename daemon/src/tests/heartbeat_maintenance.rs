
    // ============================================================================================
    // P4.1-e — CE QU'UNE FENÊTRE DE MAINTENANCE PRODUIT VRAIMENT COMME ALERTES.
    // Mesuré le 2026-08-02 sur l'arbre courant (APRÈS 7d3bf95, qui a changé la sonde d'instantané).
    // ============================================================================================

    /// Silence TOTAL de l'hôte pendant `age` secondes, puis `check_heartbeats`. Rend (nb d'alertes,
    /// règles levées). Mono-hôte = le déploiement PAR DÉFAUT (PME) : c'est le pire cas pour les
    /// sondes « flotte confondue », puisqu'il n'existe aucune autre machine pour masquer le silence.
    fn hb_apres_silence(age: i64, sources_deja_vues: &[(&str, &str)]) -> (i64, Vec<String>) {
        let conn = test_db();
        let now_ts = now();
        // Tout ce qui a DÉJÀ été collecté l'a été il y a `age` secondes (dernier run avant l'arrêt).
        for (source, category) in sources_deja_vues {
            conn.execute(
                "INSERT INTO event(ts,host,source,category,severity,message) VALUES(?1,'srv01',?2,?3,1,'m')",
                params![now_ts - age, source, category],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO metric(ts,host,name,value) VALUES(?1,'srv01','cpu',1.0)",
            params![now_ts - age],
        )
        .unwrap();
        for kind in ["firewall", "controls"] {
            conn.execute(
                "INSERT INTO snapshot(ts,host,kind,data) VALUES(?1,'srv01',?2,'{}')",
                params![now_ts - age, kind],
            )
            .unwrap();
        }
        let db = Arc::new(Mutex::new(conn));
        check_heartbeats(&db);
        let conn = db.lock();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert WHERE rule LIKE 'heartbeat.%'", [], |r| r.get(0))
            .unwrap();
        let mut regles = Vec::new();
        let mut s = conn.prepare("SELECT rule FROM alert WHERE rule LIKE 'heartbeat.%' ORDER BY rule").unwrap();
        for r in s.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            regles.push(r.unwrap());
        }
        (n, regles)
    }

    /// TOUTES les sources d'events que les capteurs de `COLLECTORS` savent voir — c'est-à-dire un
    /// hôte où TOUT est branché. Sert de contre-épreuve : sur une telle machine, plus aucune alerte
    /// ne peut porter sur un capteur « jamais vu ».
    const SOURCES_TOUT_BRANCHE: [(&str, &str); 12] = [
        ("sshd", "auth"),
        ("auditd", "exec"),
        ("yara", "endpoint"),
        ("dataaccess", "data"),
        ("integrity", "integrity"),
        ("k8s-log", "k8s"),
        ("k8s-log", "health"),
        ("crowdsec", "network"),
        ("crowdsec", "health"),
        ("fail2ban", "ban"),
        ("ufw", "firewall"),
        ("portscan", "network"),
    ];

    /// LE CHIFFRE, SUR UNE MACHINE OÙ TOUT EST BRANCHÉ. Une maintenance de 5 min ne lève QU'UNE
    /// alerte (le capteur de métriques, seul à avoir un seuil de 300 s) ; à 11 min le pipeline global
    /// est déclaré en panne et la volée part. C'est la conséquence VOULUE du dead-man's-switch : un
    /// hôte muet 11 min EST un angle mort. On fige les chiffres pour que personne ne « corrige » les
    /// seuils sans voir ce qu'il rouvre.
    #[test]
    fn maintenance_courte_ne_leve_quune_alerte_maintenance_longue_leve_la_volee() {
        let (n5, r5) = hb_apres_silence(301, &SOURCES_TOUT_BRANCHE);
        assert_eq!(r5, vec!["heartbeat.resources"], "5 min : seul le capteur 60 s déborde");
        assert_eq!(n5, 1);
        let (n11, _) = hb_apres_silence(661, &SOURCES_TOUT_BRANCHE);
        assert_eq!(
            n11, 12,
            "11 min : le pipeline global est déclaré muet -> volée d'alertes. Le chiffre est FIGÉ \
             (mesuré le 2026-08-02, 12 avant comme après le correctif) : s'il BAISSE, une détection \
             réelle a été perdue ; s'il MONTE, du bruit est réapparu."
        );
    }

    /// LE DÉFAUT DE FAMILLE, ISOLÉ. Un capteur qui n'a JAMAIS RIEN ÉMIS (jamais installé : YARA,
    /// CrowdSec, k8s… sur une PME Linux nue) n'a pas de silence à constater. Le panneau
    /// d'intégrations le dit correctement — `compute_integrations` rend « inconnu » — mais
    /// `check_heartbeats` levait pour lui « Capteur muet », avec le détail « pipeline d'ingestion
    /// muet ». Deux surfaces, la même entrée, deux verdicts : l'une AFFIRME une panne d'un capteur
    /// dont elle sait qu'elle n'a jamais rien vu.
    ///
    /// MESURÉ le 2026-08-02, PME Linux nue (seul `sshd` a déjà émis), silence de 11 min :
    /// AVANT **11** alertes, dont **8** nommant des capteurs jamais installés (yara, dataaccess,
    /// integrity, k8s-log, crowdsec, fail2ban, ufw, portscan) ; APRÈS **3** (journal, resources,
    /// firewall — les seuls qui aient déjà parlé). CONTRE-ÉPREUVE, machine où TOUT est branché :
    /// **12 avant, 12 après** — aucune détection réelle n'est perdue, seul le bruit part.
    #[test]
    fn un_capteur_jamais_vu_nest_jamais_declare_muet() {
        // PME Linux nue : journald + métriques + firewall/controls. NI yara, NI crowdsec, NI k8s…
        let (npme, regles) = hb_apres_silence(661, &[("sshd", "auth")]);
        assert_eq!(
            npme, 3,
            "PME nue, silence de 11 min : SEULS les capteurs qui ont DÉJÀ parlé alertent (journal, \
             resources, firewall). Mesuré le 2026-08-02 : 11 alertes AVANT le correctif, 3 après. \
             Ce chiffre est le cœur du constat — il est figé, pas approché. Alertes levées : {regles:?}"
        );
        let jamais_vus: Vec<&String> = regles
            .iter()
            .filter(|r| {
                matches!(
                    r.as_str(),
                    "heartbeat.yara"
                        | "heartbeat.dataaccess"
                        | "heartbeat.integrity"
                        | "heartbeat.k8s-log"
                        | "heartbeat.crowdsec"
                        | "heartbeat.fail2ban"
                        | "heartbeat.ufw"
                        | "heartbeat.portscan"
                )
            })
            .collect();
        assert!(
            jamais_vus.is_empty(),
            "{} alerte(s) « capteur muet » sur des capteurs JAMAIS installés : {:?}",
            jamais_vus.len(),
            jamais_vus
        );
    }

    /// LES DEUX SURFACES NE PEUVENT PLUS DIVERGER — et c'est la SOURCE qui l'atteste, pas une
    /// tautologie. Le fichier des deux surfaces (`handlers/freshness.rs`) ne doit contenir QUE des
    /// appels à `statut_capteur` : si quelqu'un ré-implémente la règle d'un côté (le motif
    /// historique était un `if *event_based { … } else { … }` recopié), il réintroduit `event_based`
    /// hors des sites autorisés et ce test tombe. C'est la seule forme qui attrape la RÉ-ÉCRITURE,
    /// que ni la grille ci-dessous ni un appel direct ne verraient.
    #[test]
    fn aucune_surface_ne_reimplemente_le_verdict() {
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/freshness.rs"),
        )
        .expect("freshness.rs lisible");
        let appels = src.matches("statut_capteur(").count();
        assert_eq!(appels, 3, "1 définition + 2 sites d'appel (panneau + alerte) — {appels} trouvés");
        // `event_based` ne se lit QUE dans la signature/le corps du verdict et aux 2 sites d'appel.
        // (comptés hors commentaires : c'est le nombre d'occurrences EXÉCUTABLES qu'on fige)
        let usages: usize = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| l.matches("event_based").count())
            .sum();
        assert_eq!(
            usages, 8,
            "le drapeau `event_based` a fui hors du verdict partagé : une surface s'est remise à \
             décider toute seule (c'est exactement le défaut mesuré le 2026-08-02)"
        );
    }

    /// La grille complète du verdict : (jamais vu / frais / en retard) × (pipeline frais / en panne)
    /// × (événementiel / continu). Fige le seul verdict qui alerte, et l'invariant central : un
    /// capteur jamais vu ne peut pas être déclaré muet.
    #[test]
    fn statut_affiche_et_alerte_sont_le_meme_verdict() {
        for event_based in [true, false] {
            for pipe_fresh in [true, false] {
                for ls in [None, Some(0_i64), Some(10_000_i64)] {
                    let s = statut_capteur(ls.map(|age| now() - age), 60, event_based, pipe_fresh, CYCLES_TOLERES_ALERTE, now());
                    // Le seul verdict qui ALERTE est « muet », et il exige d'avoir DÉJÀ vu le capteur.
                    assert_eq!(s.alerte(), s == StatutCapteur::Muet);
                    if ls.is_none() {
                        assert_eq!(s, StatutCapteur::Inconnu, "jamais vu -> inconnu, jamais muet");
                        assert!(!s.alerte());
                    }
                }
            }
        }
    }
