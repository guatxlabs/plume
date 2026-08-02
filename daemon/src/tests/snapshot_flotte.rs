    // ================================================================================================
    // LA FLOTTE (2) — LA VOIE SNAPSHOT : LA SÉRIE EST `(kind, host)`.
    // Jumeau de `dedup_flotte.rs` (`event.dedup`). Ce que ces tests mesurent, et dans quel ordre :
    //   1. la PERTE et la CORRUPTION, par le VRAI chemin (`ingest_once` sur un vrai spool + marqueur
    //      `#H#`), enveloppes VERBATIM de `collectors/firewall.sh` / `collectors/controls.sh` ;
    //   2. LA FRAÎCHEUR — le point le plus dangereux : « frais » alors que le parc s'est tu ;
    //   3. ce que le cloisonnement NE DOIT PAS casser : le mono-hôte (parité EXACTE), la série sans
    //      hôte (déploiement), le heartbeat d'un capteur stable ;
    //   4. les GARDES : une sonde d'instantané ne peut pas être écrite sans hôte (typage), et aucune
    //      lecture « dernier instantané du kind » ne peut oublier l'hôte (source).
    // Chiffres AVANT correction cités en commentaire : mesurés le 2026-08-02 sur ce même protocole.
    // ================================================================================================

    /// Enveloppe spool `kind=firewall` — FORME VERBATIM de `collectors/firewall.sh` (ligne 33).
    fn snap_env_fw(host: &str, ts: i64, rs_hash: &str, lockdown_ok: Option<bool>) -> String {
        let mut data = json!({ "ruleset_sha256": rs_hash });
        if let Some(ok) = lockdown_ok {
            data.as_object_mut().unwrap().insert("control_docker_lockdown".into(), json!({
                "iface": "wlan0", "docker_user_v4": ok, "input_v4": ok, "input_v6": ok, "ok": ok
            }));
        }
        json!({ "ts": ts, "host": host, "kind": "firewall", "hash": rs_hash, "data": data }).to_string()
    }

    /// Enveloppe spool `kind=controls` — FORME VERBATIM de `collectors/controls.sh` (ligne 54).
    fn snap_env_ctl(host: &str, ts: i64, hash: &str, failed: i64) -> String {
        json!({ "ts": ts, "host": host, "kind": "controls", "hash": hash,
                "data": { "failed": failed, "controls": [{"id":"auditd_active","ok":failed==0,"detail":"auditd actif"}] } })
            .to_string()
    }

    fn snap_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    // ---------------------------------------------------------------------------------------------
    // (1) LA PERTE ET LA CORRUPTION
    // ---------------------------------------------------------------------------------------------

    /// PARC HOMOGÈNE — le cas le PLUS courant (même image dorée -> même hash de ruleset) et le plus grave :
    /// AVANT, 9 instantanés envoyés par 3 machines rendaient **1 SEULE ligne**, `web02` et `web03` n'étant
    /// JAMAIS enregistrées (2 machines sur 3 invisibles, sans un mot). La série étant (kind, host), chaque
    /// machine a désormais sa ligne — et un rapport stable reste dédupliqué EN PLUS (1 ligne par machine,
    /// pas 3).
    #[test]
    fn snapshot_parc_homogene_chaque_machine_a_sa_ligne() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = now() - 100;
        let hosts = ["web01", "web02", "web03"];
        let mut n = 0u32;
        for tour in 0..3i64 {
            for h in hosts {
                depose_spool(&spool, h, n, &snap_env_fw(h, ts0 + tour * 10, "aaaa_meme_ruleset", None));
                n += 1;
            }
            ingest_once(&st.tenants, &st.spool);
        }
        let conn = st.db.lock();
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(DISTINCT host) FROM snapshot WHERE kind='firewall'"), 3,
            "3 machines rapportent -> 3 machines REPRÉSENTÉES. 1 = deux tiers du parc jetés en silence."
        );
        for h in hosts {
            assert_eq!(
                snap_compte(&conn, &format!("SELECT COUNT(*) FROM snapshot WHERE kind='firewall' AND host='{h}'")), 1,
                "{h} : UNE ligne — présente (la machine existe) et UNE seule (état stable -> heartbeat, pas d'insert)"
            );
        }
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// PARC HÉTÉROGÈNE — deux rôles aux rulesets DIFFÉRENTS mais tous deux STABLES. AVANT : 10 rapports
    /// -> 10 lignes dont **8 changements fantômes**, chaque machine « changeant » par rapport à celle d'à
    /// côté ; la détection de changement était purement inopérante. La comparaison se faisant dans la
    /// série de la machine, un état stable ne produit plus AUCUN faux changement.
    #[test]
    fn snapshot_parc_heterogene_zero_changement_fantome() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = now() - 100;
        let mut n = 0u32;
        for tour in 0..5i64 {
            depose_spool(&spool, "web01", n, &snap_env_fw("web01", ts0 + tour * 10, "hash_role_web", None));
            n += 1;
            ingest_once(&st.tenants, &st.spool);
            depose_spool(&spool, "db01", n, &snap_env_fw("db01", ts0 + tour * 10 + 5, "hash_role_db", None));
            n += 1;
            ingest_once(&st.tenants, &st.spool);
        }
        let conn = st.db.lock();
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(*) FROM snapshot WHERE kind='firewall'"), 2,
            "2 états réels, 10 rapports -> 2 lignes. 10 = 8 changements FANTÔMES (la détection de \
             changement comparait la machine à sa voisine)."
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// LE HEARTBEAT TOUCHE **SA** LIGNE, PAS CELLE D'À CÔTÉ.
    ///
    /// L'`UPDATE … WHERE kind=?2 AND ts=(SELECT MAX(ts) …)` visait le dernier instantané TOUS HÔTES
    /// CONFONDUS : le battement d'une machine atterrissait sur la ligne de CELLE QUI AVAIT PARLÉ EN
    /// DERNIER. Chronologie choisie pour ISOLER ce seul défaut (la comparaison d'état, elle, est déjà
    /// cloisonnée) : `web01` rapporte, PUIS `web02` rapporte (sa ligne devient le max global), PUIS
    /// `web01` re-rapporte un état INCHANGÉ. Sans le filtre d'hôte, ce battement de `web01` avance la
    /// ligne de **`web02`** — donc `web01`, qui vient pourtant de parler, paraît en retard, et `web02`,
    /// muet, paraît frais. C'est la donnée STOCKÉE qui devient fausse, pas seulement la requête.
    #[test]
    fn snapshot_heartbeat_ne_rajeunit_pas_la_machine_daccote() {
        let (st, spool) = ing_state_with_spool();
        let t = now() - 100;
        depose_spool(&spool, "web01", 0, &snap_env_fw("web01", t - 300, "ruleset_web01", None));
        ingest_once(&st.tenants, &st.spool);
        depose_spool(&spool, "web02", 1, &snap_env_fw("web02", t - 200, "ruleset_web02", None));
        ingest_once(&st.tenants, &st.spool);
        // web01 re-rapporte le MÊME état -> branche heartbeat. Le max global est la ligne de web02.
        depose_spool(&spool, "web01", 2, &snap_env_fw("web01", t - 100, "ruleset_web01", None));
        ingest_once(&st.tenants, &st.spool);

        let conn = st.db.lock();
        let ts01: i64 = conn.query_row("SELECT ts FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap();
        let ts02: i64 = conn.query_row("SELECT ts FROM snapshot WHERE host='web02'", [], |r| r.get(0)).unwrap();
        assert_eq!(ts01, t - 100, "le battement avance la ligne de LA MACHINE QUI A PARLÉ (web01)");
        assert_eq!(ts02, t - 200, "et laisse INTACTE celle de la machine muette (web02)");
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// UNE MACHINE MORTE N'EST PAS RAJEUNIE PAR SA VOISINE. Parc HOMOGÈNE (même image, même hash) :
    /// `web01` meurt à T-3600 s, `web02` continue. AVANT : `web02` n'obtenait AUCUNE ligne (son état
    /// « existait déjà »), et ses battements avançaient la ligne de `web01` de **+3540 s** — le SOC
    /// voyait une machine morte comme fraîche, et la machine vivante nulle part.
    #[test]
    fn snapshot_machine_morte_nest_pas_rajeunie_par_sa_voisine() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = now() - 100;
        depose_spool(&spool, "web01", 0, &snap_env_fw("web01", ts0 - 3600, "aaaa_meme_ruleset", None));
        ingest_once(&st.tenants, &st.spool);
        let avant: i64 = st.db.lock().query_row("SELECT ts FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap();
        for k in 1..4u32 {
            depose_spool(&spool, "web02", k, &snap_env_fw("web02", ts0 - 60, "aaaa_meme_ruleset", None));
            ingest_once(&st.tenants, &st.spool);
        }
        let conn = st.db.lock();
        let apres: i64 = conn.query_row("SELECT ts FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap();
        assert_eq!(apres, avant, "la ligne d'une machine MORTE ne bouge pas (avant : +3540 s offerts par sa voisine)");
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(*) FROM snapshot WHERE host='web02'"), 1,
            "et web02 EXISTE (avant : 0 ligne — la machine vivante était l'invisible)"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// ALERTES D'ÉTAT — UNE PAR MACHINE. AVANT : 5 machines sans le contrôle docker-lockdown -> **1 seule
    /// alerte** (la première du jour), 4 machines en défaut invisibles ; idem pour `control.catalog`, où
    /// 5 machines au MÊME hash (même rôle, mêmes contrôles manquants) rendaient 1 ligne et 1 alerte.
    #[test]
    fn snapshot_alertes_detat_une_par_machine() {
        // (a) firewall.lockdown — 5 machines, rulesets DIFFÉRENTS, toutes sans le lockdown.
        {
            let (st, spool) = ing_state_with_spool();
            let ts0 = now() - 100;
            for i in 0..5u32 {
                let h = format!("lap{i}");
                depose_spool(&spool, &h, i, &snap_env_fw(&h, ts0, &format!("rs_{i}"), Some(false)));
            }
            ingest_once(&st.tenants, &st.spool);
            let conn = st.db.lock();
            assert_eq!(
                snap_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='firewall.lockdown'"), 5,
                "5 machines en défaut -> 5 alertes (avant : 1, et les 4 autres machines restaient muettes)"
            );
            assert_eq!(snap_compte(&conn, "SELECT COUNT(DISTINCT host) FROM alert WHERE rule='firewall.lockdown'"), 5);
            drop(conn);
            let _ = std::fs::remove_dir_all(&spool);
        }
        // (b) control.catalog — 5 machines du MÊME rôle : même hash, mêmes 2 contrôles manquants.
        {
            let (st, spool) = ing_state_with_spool();
            let ts0 = now() - 100;
            for i in 0..5u32 {
                let h = format!("srv{i}");
                depose_spool(&spool, &h, i, &snap_env_ctl(&h, ts0, "hash_controls_identique", 2));
            }
            ingest_once(&st.tenants, &st.spool);
            let conn = st.db.lock();
            assert_eq!(snap_compte(&conn, "SELECT COUNT(*) FROM snapshot WHERE kind='controls'"), 5, "5 machines -> 5 états (avant : 1)");
            assert_eq!(
                snap_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='control.catalog'"), 5,
                "5 machines à 2 contrôles manquants -> 5 alertes (avant : 1 — un parc entier en défaut \
                 signalé par une seule machine)"
            );
            drop(conn);
            let _ = std::fs::remove_dir_all(&spool);
        }
    }

    /// LA DÉDUPLICATION FAIT TOUJOURS SON TRAVAIL — même machine, même état, même jour : 1 alerte, pas 3.
    /// (Le cloisonnement est une fonction PURE de l'hôte : il ne peut pas transformer une répétition en
    /// bruit, sinon on remplacerait une perte silencieuse par une inondation.)
    #[test]
    fn snapshot_alerte_reste_dedupliquee_pour_une_meme_machine() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = now() - 100;
        for i in 0..3u32 {
            depose_spool(&spool, "lap0", i, &snap_env_fw("lap0", ts0 + i as i64, &format!("rs_{i}"), Some(false)));
            ingest_once(&st.tenants, &st.spool);
        }
        let conn = st.db.lock();
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='firewall.lockdown'"), 1,
            "3 rapports du MÊME hôte le MÊME jour -> 1 alerte (dédup préservé)"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    // ---------------------------------------------------------------------------------------------
    // (2) LA FRAÎCHEUR — LE POINT LE PLUS DANGEREUX
    // ---------------------------------------------------------------------------------------------

    /// Peuple `snapshot` avec `n` hôtes ayant rapporté `kind` à `vieux_ts`, sauf le premier à `frais_ts`.
    fn snap_parc(conn: &Connection, kind: &str, n: usize, vieux_ts: i64, frais_ts: i64) {
        for i in 0..n {
            let ts = if i == 0 { frais_ts } else { vieux_ts };
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}',?4)",
                params![ts, kind, format!("h{i}"), format!("srv{i:02}")],
            )
            .unwrap();
        }
    }

    /// LA SONDE DÉCLARE LA MACHINE LA PLUS EN RETARD, PAS LA PLUS FRAÎCHE.
    /// Parc de 50, 49 muettes depuis 2 h, une seule encore vivante. AVANT : la sonde livrée
    /// (`SELECT MAX(ts) FROM snapshot WHERE kind='firewall'`) déclarait un âge de **101 s** et le statut
    /// **actif** — un SOC qui affiche « frais » pendant que 49 machines sur 50 se sont tues donne une
    /// confiance FAUSSE. Après : l'âge déclaré est celui du parc réel.
    #[test]
    fn snapshot_sonde_declare_la_machine_la_plus_en_retard() {
        let conn = test_db();
        let now_ts = now();
        snap_parc(&conn, "firewall", 50, now_ts - 7200, now_ts - 5);

        let sonde = Sonde::Instantane { kind: "firewall" };
        let ls = sonde.derniere_collecte(&conn).expect("le parc a rapporté");
        assert!(
            now_ts - ls >= 7200,
            "âge déclaré {} s : la sonde doit rendre la machine la PLUS EN RETARD (7200 s), pas la plus \
             fraîche (5 s -> statut « actif » alors que 49/50 sont muettes)",
            now_ts - ls
        );
        // Statut tel que compute_integrations le calcule (capteur CONTINU, intervalle 120 s).
        assert!(now_ts - ls > 120 * 3, "statut = muet (avant : actif)");

        // Contre-épreuve : l'ANCIENNE requête, sur les MÊMES données, dit toujours « frais ». C'est la
        // preuve que le test mord sur la portée et non sur le jeu de données.
        let ancienne: i64 = conn
            .query_row("SELECT MAX(ts) FROM snapshot WHERE kind='firewall'", [], |r| r.get(0))
            .unwrap();
        assert!(now_ts - ancienne <= 120 * 3, "l'ancienne sonde aurait déclaré « actif » sur ces mêmes données");
    }

    /// L'ALERTE « CAPTEUR MUET » SE LÈVE **ET NOMME LES MACHINES**. AVANT : `check_heartbeats` levait
    /// ZÉRO alerte sur ce parc. Sans les noms, « Capteur muet : firewall » n'est pas actionnable — on ne
    /// sait pas s'il s'agit d'une machine ou de quarante-neuf.
    #[test]
    fn snapshot_alerte_capteur_muet_se_leve_et_nomme_les_machines() {
        let conn = test_db();
        let now_ts = now();
        snap_parc(&conn, "firewall", 50, now_ts - 7200, now_ts - 5);
        // pipeline VIVANT (un event récent) -> on prouve bien le muet du CAPTEUR, pas une panne globale.
        conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,'m')", params![now_ts - 5]).unwrap();
        let db = Arc::new(Mutex::new(conn));

        check_heartbeats(&db);

        let conn = db.lock();
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(*) FROM alert WHERE rule='heartbeat.firewall'"), 1,
            "49 machines muettes -> l'alerte se lève (avant : 0 — le silence du parc était invisible)"
        );
        let detail: String = conn
            .query_row("SELECT detail FROM alert WHERE rule='heartbeat.firewall'", [], |r| r.get(0))
            .unwrap();
        assert!(detail.contains("machines en retard"), "le détail nomme les machines : {detail}");
        assert!(detail.contains("srv01"), "au moins une machine muette est NOMMÉE : {detail}");
        assert!(!detail.contains("srv00"), "la machine encore vivante n'est PAS accusée : {detail}");
    }

    /// LE FEED `/api/freshness` (`kind`) porte lui aussi la fraîcheur du PARC + son dénominateur.
    #[test]
    fn snapshot_feed_freshness_porte_le_parc_et_son_denominateur() {
        let mut path = std::env::temp_dir();
        path.push(format!("plume-snapfresh-{}-{}.db", std::process::id(), now()));
        let p = path.to_string_lossy().to_string();
        let now_ts = now();
        {
            let w = open_db(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            snap_parc(&w, "firewall", 50, now_ts - 7200, now_ts - 5);
        }
        let v = compute_freshness(&p, None);
        let f = v["feeds"].as_array().unwrap().iter()
            .find(|f| f["kind"] == "snapshot" && f["name"] == "firewall")
            .expect("feed firewall présent");
        assert_eq!(f["n_hosts"], 50, "le dénominateur est explicite (avant : 1 feed pour 50 séries, sans le dire)");
        assert!(f["age_s"].as_i64().unwrap() >= 7200, "l'âge du feed est celui de la machine la plus en retard");
        let _ = std::fs::remove_file(&p);
    }

    // ---------------------------------------------------------------------------------------------
    // (3) CE QUE ÇA NE CASSE PAS
    // ---------------------------------------------------------------------------------------------

    /// PARITÉ MONO-HÔTE — le déploiement par DÉFAUT (PME). Sur un seul hôte, la sonde par-hôte rend la
    /// valeur EXACTE de l'ancienne requête globale : `MIN` sur un seul groupe == `MAX`. Aucune bascule de
    /// statut, aucune alerte nouvelle, à la seconde près.
    #[test]
    fn snapshot_mono_hote_valeur_strictement_identique() {
        let conn = test_db();
        let base = now() - 500;
        for (i, k) in ["firewall", "controls", "firewall"].iter().enumerate() {
            conn.execute(
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}','vps-unique')",
                params![base + i as i64 * 60, k, format!("h{i}")],
            )
            .unwrap();
        }
        for kind in ["firewall", "controls"] {
            let ancienne: Option<i64> = conn
                .query_row(&format!("SELECT MAX(ts) FROM snapshot WHERE kind='{kind}'"), [], |r| r.get::<_, Option<i64>>(0))
                .ok()
                .flatten();
            let nouvelle = Sonde::Instantane { kind }.derniere_collecte(&conn);
            assert_eq!(nouvelle, ancienne, "mono-hôte : la sonde par-hôte == l'ancienne sonde globale ({kind})");
        }
        // Table VIDE pour un kind inconnu : `None` des deux côtés (statut « inconnu », jamais « muet »).
        assert_eq!(Sonde::Instantane { kind: "jamais-vu" }.derniere_collecte(&conn), None);
    }

    /// LA SÉRIE SANS HÔTE EXISTE ET RESTE À ELLE-MÊME. Un instantané qui décrit LE DÉPLOIEMENT (et non une
    /// machine) n'a pas d'hôte à déclarer : il forme sa PROPRE série `(kind, NULL)` — c'est ainsi que
    /// « légitimement global » se dit, SANS liste de `kind` autorisés (laquelle serait fausse dès qu'un
    /// client poste son propre `kind` via `/api/ingest`). Deux propriétés : (a) la série sans hôte se
    /// déduplique elle-même (`host IS NULL`, pas `= NULL`) ; (b) elle ne touche PAS la ligne d'un hôte nommé.
    #[test]
    fn snapshot_serie_sans_hote_reste_une_serie_a_part_entiere() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = now() - 100;
        // une machine NOMMÉE, état stable.
        let nomme = json!({ "ts": ts0 - 3600, "host": "web01", "kind": "posture", "hash": "H", "data": {} }).to_string();
        std::fs::write(spool.join(format!("ingest-{}-1.json", now())), &nomme).unwrap();
        ingest_once(&st.tenants, &st.spool);
        let ts_nomme_avant: i64 = st.db.lock().query_row("SELECT ts FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap();

        // même `kind`, même `hash`, AUCUN hôte (ni déclaré ni marqueur) -> série (posture, NULL), 2 fois.
        let anonyme = json!({ "ts": ts0, "kind": "posture", "hash": "H", "data": {} }).to_string();
        for i in 2..4u32 {
            std::fs::write(spool.join(format!("ingest-{}-{i}.json", now())), &anonyme).unwrap();
            ingest_once(&st.tenants, &st.spool);
        }
        let conn = st.db.lock();
        assert_eq!(
            snap_compte(&conn, "SELECT COUNT(*) FROM snapshot WHERE kind='posture' AND host IS NULL"), 1,
            "(a) la série sans hôte se DÉDUPLIQUE elle-même : 2 rapports au même hash -> 1 ligne + heartbeat \
             (si `host IS ?` avait été écrit `host = ?`, un NULL ne s'égalant pas lui-même, on aurait \
             réinséré à CHAQUE rapport)"
        );
        assert_eq!(
            conn.query_row::<i64, _, _>("SELECT ts FROM snapshot WHERE host='web01'", [], |r| r.get(0)).unwrap(),
            ts_nomme_avant,
            "(b) la série sans hôte ne rajeunit PAS la ligne d'une machine nommée"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// LE PANNEAU VENTILE PAR MACHINE. `dernier_instantane_par_hote` rend le DERNIER état de CHAQUE
    /// machine (et un seul par machine), la plus fraîche d'abord — c'est ce qui donne au panneau son
    /// dénominateur (`n_hosts`) au lieu d'afficher `srv00` comme « l'état du parc ».
    #[test]
    fn snapshot_lecture_ventile_par_machine() {
        let conn = test_db();
        let now_ts = now();
        snap_parc(&conn, "firewall", 4, now_ts - 7200, now_ts - 5);
        // srv01 a un HISTORIQUE (2 lignes) : la lecture n'en garde que la plus récente.
        conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,'firewall','vieux','{}','srv01')", params![now_ts - 99999]).unwrap();

        let v = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
        assert_eq!(v.len(), 4, "une entrée par MACHINE (pas par ligne d'historique)");
        assert_eq!(v[0].0.as_deref(), Some("srv00"), "la plus fraîche d'abord");
        let srv01 = v.iter().find(|(h, ..)| h.as_deref() == Some("srv01")).unwrap();
        assert_eq!(srv01.1, now_ts - 7200, "pour chaque machine, son DERNIER état (pas le plus vieux)");
        assert!(crate::ingest::store::dernier_instantane_par_hote(&conn, "jamais-vu", 500).is_empty());
    }

    /// LE PANNEAU LUI-MÊME (route `GET /api/panel/:kind`) PORTE SON DÉNOMINATEUR. AVANT : la route rendait
    /// `{kind, ts, hash, data}` — l'état de la DERNIÈRE machine à avoir parlé (mesuré : `srv00` pour un
    /// parc de 50), sans `host` ni compte. Les champs de tête restent ceux de la machine la plus fraîche
    /// (mono-hôte : réponse inchangée) mais sont désormais ATTRIBUÉS et accompagnés du parc.
    #[tokio::test]
    async fn snapshot_panneau_expose_lhote_et_le_denominateur() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        let now_ts = now();
        {
            let conn = st.db.lock();
            snap_parc(&conn, "firewall", 50, now_ts - 7200, now_ts - 5);
        }
        let Json(v) = panel(State(st.clone()), Extension(mk_admin()), Path("firewall".to_string())).await;
        assert_eq!(v["n_hosts"], 50, "le panneau DIT combien de machines il agrège (avant : rien du tout)");
        assert_eq!(v["host"], "srv00", "et QUELLE machine il montre en tête");
        assert_eq!(v["hosts"].as_array().unwrap().len(), 50, "la ventilation complète est disponible");
        // kind inconnu -> forme vide EXPLICITE (pas d'absence de champ qui se lirait « une machine »).
        let Json(vide) = panel(State(st), Extension(mk_admin()), Path("jamais-vu".to_string())).await;
        assert_eq!(vide["n_hosts"], 0);
    }

    // ---------------------------------------------------------------------------------------------
    // (4) LES GARDES
    // ---------------------------------------------------------------------------------------------

    /// GARDE (TYPAGE) — l'ANCRAGE de la classification des sondes. Le champ « requête » d'un capteur n'est
    /// plus une chaîne SQL libre mais un `Sonde` : il n'existe AUCUNE façon d'ÉCRIRE une sonde
    /// d'instantané qui confonde les hôtes (`Sonde::Instantane` ne prend qu'un `kind`, le `GROUP BY host`
    /// est posé par `derniere_collecte`). Ce test fige DEUX choses que le compilateur ne peut pas figer :
    /// (a) l'ensemble des `kind` sondés par hôte, (b) le COMPTE de la dette DÉCLARÉE « flotte confondue ».
    /// Un 24ᵉ capteur oblige à trancher, ici comme à la compilation.
    #[test]
    fn snapshot_sonde_instantanee_ancrage_de_portee() {
        let mut instantanes: Vec<&str> = Vec::new();
        let (mut ev, mut me) = (0usize, 0usize);
        for (_, _, _, sonde, _) in COLLECTORS.iter() {
            match sonde {
                Sonde::Instantane { kind } => instantanes.push(kind),
                Sonde::EventFlotteConfondue { .. } => ev += 1,
                Sonde::MetriqueFlotteConfondue => me += 1,
            }
        }
        instantanes.sort_unstable();
        assert_eq!(
            instantanes, vec!["controls", "firewall"],
            "ANCRAGE : les `kind` d'instantané sondés PAR HÔTE. Un `kind` ajouté/retiré doit passer par ici."
        );
        assert_eq!(
            (ev, me), (20, 1),
            "ANCRAGE DE LA DETTE DÉCLARÉE : 20 sondes d'events + 1 de métriques gardent la portée « flotte \
             confondue » — MÊME défaut de famille, coût DIFFÉRENT (`event` ~9,8 M lignes, sondé sous le \
             verrou d'écriture, contre une ligne vivante par (kind,hôte) pour `snapshot`). Ce compte doit \
             BAISSER, jamais monter en silence."
        );
        assert_eq!(instantanes.len() + ev + me, COLLECTORS.len(), "toute sonde est classée");
    }

    /// GARDE (SOURCE) — AUCUNE lecture « le dernier instantané de ce kind » ne peut oublier l'hôte.
    /// Le typage ferme le descripteur de sonde ; il ne ferme pas un `conn.query_row("… FROM snapshot
    /// WHERE kind=…")` écrit à la main dans un handler. Cette garde lit les sources et exige que TOUTE
    /// requête de production qui interroge `snapshot` PAR `kind` porte aussi l'hôte (`host IS`, `AND
    /// host`, ou `GROUP BY host`). Les requêtes qui n'interrogent PAS par `kind` (santé GLOBALE du
    /// pipeline : `MAX(ts)` sur l'UNION event∪metric∪snapshot ; rétention ; rollup d'hôtes) ne sont pas
    /// concernées — leur portée globale est leur RAISON D'ÊTRE et elle est nommée.
    #[test]
    fn snapshot_lecture_par_kind_toujours_avec_lhote() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        dedup_rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner voit les sources ({})", fichiers.len());
        let marques = dedup_fichiers_de_test(&fichiers);

        // Les DEUX formes qui désignent « l'instantané courant d'un kind » : la LECTURE
        // (`… FROM snapshot WHERE kind …`) et l'ÉCRITURE CIBLÉE (`UPDATE snapshot SET …`, le heartbeat —
        // c'est elle qui rajeunissait la ligne de la machine d'à côté). La purge de rétention
        // (`chunked_purge("snapshot", "ts < ?1")`) n'est ni l'une ni l'autre : sa portée est le TEMPS,
        // et elle est nommée.
        const MOTIFS: [&str; 2] = ["FROM snapshot WHERE kind", "UPDATE snapshot SET"];
        let (mut vues, mut violations) = (Vec::<String>::new(), Vec::<String>::new());
        for f in &fichiers {
            if marques.iter().any(|m| f == m || f.starts_with(m)) {
                continue; // fixtures : pas un chemin de lecture de production
            }
            let src = std::fs::read_to_string(f).unwrap();
            // Les lignes de COMMENTAIRE sont retirées : un bandeau qui CITE l'ancienne requête fautive
            // pour expliquer le défaut est de la documentation, pas un chemin de lecture — la compter
            // ferait mentir l'ancrage. (Une ligne de littéral SQL continué par `\` ne commence jamais
            // par `//`, donc aucune requête réelle n'est perdue par ce filtre.)
            let txt: String = dedup_texte_prod(f, &src)
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(|l| format!("{l}\n"))
                .collect();
            let nom = f.file_name().unwrap().to_string_lossy().to_string();
            for motif in MOTIFS {
                let mut d = 0usize;
                while let Some(p) = txt[d..].find(motif) {
                    let abs = d + p;
                    // le littéral ENGLOBANT : du `"` ouvrant (précédent) au `"` fermant suivant.
                    let deb = txt[..abs].rfind('"').map(|i| i + 1).unwrap_or(0);
                    let fin = txt[abs..].find('"').map(|i| abs + i).unwrap_or(txt.len());
                    let litteral = &txt[deb..fin];
                    vues.push(nom.clone());
                    if !(litteral.contains("host IS") || litteral.contains("AND host") || litteral.contains("GROUP BY host")) {
                        violations.push(format!("{nom} : {}", litteral.split_whitespace().collect::<Vec<_>>().join(" ")));
                    }
                    d = abs + motif.len();
                }
            }
        }
        assert!(
            violations.is_empty(),
            "ces requêtes de production demandent « le dernier instantané du kind » SANS nommer l'hôte : \
             elles présentent l'état d'UNE machine comme celui du parc (mesuré : 1 hôte rendu pour 50). \
             Passez par `SnapshotSeries` (écriture) ou `dernier_instantane_par_hote` (lecture) : \
             {violations:?}"
        );
        // ANTI-ROT — la garde serait VACUE si l'extracteur ne voyait plus rien. On fige ce qu'il DOIT voir,
        // mesuré le 2026-08-02 : store.rs x4 (`dernier_hash`, le `UPDATE` du heartbeat COMPTÉ DEUX FOIS —
        // une par motif —, et la lecture par hôte) · main.rs x2 (les deux méthodes de `Sonde`).
        vues.sort();
        assert_eq!(
            vues,
            vec!["main.rs", "main.rs", "store.rs", "store.rs", "store.rs", "store.rs"],
            "ANTI-ROT : l'ensemble des interrogations de `snapshot` PAR `kind` vues par l'extracteur a \
             changé. (a) requête reformatée -> réparez l'EXTRACTEUR, sinon la garde passe au vert en ne \
             regardant rien ; (b) site ajouté/retiré LÉGITIMEMENT -> vérifiez qu'il porte l'hôte et mettez \
             cette liste à jour."
        );
    }
