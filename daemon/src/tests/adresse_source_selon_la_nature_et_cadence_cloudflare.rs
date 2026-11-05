    // ============================================================================================
    // CE QUE LA PAGE DES SOURCES DIT D'UN ÉVÉNEMENT SANS ADRESSE, ET LA CADENCE DES DEUX CAPTEURS
    // CLOUDFLARE (constats de l'exploitant du 2026-11-04).
    //
    // (1) Le compte « écrit sans adresse source » (`without_src_ip_since_start` de `/api/sources`,
    //     `ingest.events_without_src_ip_total` de `/api/metrics`) comptait TOUT événement à `src_ip`
    //     vide, battements de santé et aveux de configuration compris : la console invitait à poser un
    //     processeur rename là où aucune adresse n'existe. Seul compte désormais ce dont la nature admet
    //     une adresse : la liste `metrics::EVENEMENTS_SANS_ADRESSE_PAR_NATURE` (paires source, catégorie)
    //     et la liste `metrics::ADRESSE_ABSENTE_SELON_LE_CONTENU` (auditd `addr=?`, lignes de session de
    //     sshd et sshd-session, gestion de comptes de l'agent Rust rangée en `auth`), jugées au même endroit pour la voie générique et la voie journald.
    // (2) `cloudflare` et `cloudflare-http` n'avaient aucune sonde : « cadence non déclarée ». Leurs deux
    //     capteurs tournent sur un minuteur de 2 min mais n'écrivent que sur événement : la cadence servie
    //     est `evenementielle`, déclarée par leur sonde, et un site calme n'est jamais « en retard ».
    //
    // AUCUN TÉMOIN NE LIT UN DELTA DU COMPTE DE PROCESSUS SOUS UN NOM QU'UN AUTRE TÉMOIN ÉCRIT : sous
    // `cargo test` (fils parallèles, le mode de la CI), un delta nul sur `sudo` ou `auditd` était une course.
    // Les règles nommées se jugent sur le prédicat pur (`evenement_peut_porter_une_adresse`) ; ce qui passe
    // par l'ingestion lit soit le compte de processus sous un nom PROPRE au témoin, soit le compte du FIL
    // qui ingère (`metrics::sans_adresse_de_ce_fil`).
    // MUTANTS JOUÉS (posés sous cfg!(test), retirés avant le commit), chacun vu ROUGE : BS2_SANS_SOURCE et BS2_SANS_CAT
    // (une règle de contenu sans sa condition de source ou de catégorie), BS2_SANS_VALEUR (le champ présent
    // suffit), BS2_SANS_SESSION (règles de session sshd retirées), BS2_SANS_WIN (paire `WinEventLog:Security`
    // retirée), BS2_CAT_IGNOREE (une paire exclut toute sa source), BS2_PREFIXE (`minio-audit` pris pour
    // `minio`), BS2_SANS_JOKER_CONFIG (joker `config` retiré), BS2_GEN_SANS_SAC et BS2_JOURNALD_SANS_SAC (une
    // voie d'ingestion ne passe pas le sac), BS2_JOURNALD_BRUT (la voie journald compte sans le prédicat),
    // BS2_TOTAL_AVANT (le total monte avant le prédicat) ; puis C_CHAMP_IGNORE (l'aveu cherché dans tout
    // champ du sac), C_NOMBRE (`event_id` numérique non lu), C_SANS_WIN_COMPTES (règles de gestion de comptes
    // de l'agent Rust retirées), C_SANS_SESSION (règles de session sshd retirées, vu sur p4_12b).
    // ============================================================================================

    /// L'entrée de `/api/sources` (lue par un lecteur, le rôle le plus faible admis) pour `src`.
    async fn asn_entree(p: &str, src: &str) -> Value {
        let st = ds_file_state(p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        v["sources"].as_array().unwrap().iter().find(|s| s["source"] == src).cloned().unwrap_or_else(|| panic!("source {src} absente de {v}"))
    }

    fn asn_ev(source: &str, category: &str, i: i64, src_ip: Option<&str>) -> Value {
        let mut e = json!({"ts": now() - 60 - i, "source": source, "category": category, "severity": 1,
            "message": format!("{source} {category} {i}"), "dedup": format!("{source}-{category}-{i}")});
        if let Some(ip) = src_ip {
            e["src_ip"] = json!(ip);
        }
        e
    }

    /// PAR LA ROUTE : un battement de santé sans adresse ne compte plus, un événement réseau sans adresse
    /// compte encore — et chaque membre « toute source » de la liste a sa ligne dans la fixture mixte.
    /// Une source TIERCE (ni auditd ni windows-security) qui écrit `exec`, `account` ou `tamper` sans
    /// adresse reste comptée : ces catégories ne sont exclues que chez les capteurs lus.
    #[tokio::test]
    async fn asn_la_route_ne_compte_que_les_evenements_qui_peuvent_porter_une_adresse() {
        let (_tmp, p) = imp_base_disque("asn-route");
        let (battement, mixte, tierce) = ("asn-battement-seul", "asn-mixte", "asn-idp-tiers");
        {
            let w = open_db(&p).unwrap();
            // Une source qui n'émet QUE des battements de santé, sans adresse (forme de collectors/lib.sh:476-481).
            let beats: Vec<Value> = (0..3).map(|i| asn_ev(battement, "health", i, None)).collect();
            ingest_events_batch(&w, &p, &beats, 1, None, None).unwrap();
            // Une source MIXTE : une ligne par catégorie exclue partout, puis deux lignes réseau sans
            // adresse et une avec. Le compte attendu est 2 : retirer un membre de la liste le fait monter.
            let mut evs: Vec<Value> = ["health", "config"].iter().enumerate().map(|(i, c)| asn_ev(mixte, c, i as i64, None)).collect();
            evs.push(asn_ev(mixte, "network", 10, None));
            evs.push(asn_ev(mixte, "network", 11, None));
            evs.push(asn_ev(mixte, "network", 12, Some("192.0.2.10")));
            // La source tierce : les trois catégories exclues SEULEMENT chez auditd / windows-security.
            evs.extend(["exec", "account", "tamper"].iter().enumerate().map(|(i, c)| asn_ev(tierce, c, 20 + i as i64, None)));
            ingest_events_batch(&w, &p, &evs, 1, None, None).unwrap();
            rollup_events(&w);
        }
        let b = asn_entree(&p, battement).await;
        assert_eq!(b["without_src_ip_since_start"], Value::Null,
            "trois battements de santé sans adresse : rien n'est compté, la console ne dit rien : {b}");
        let m = asn_entree(&p, mixte).await;
        assert_eq!(m["without_src_ip_since_start"], json!(2),
            "seules les deux lignes réseau sans adresse comptent (santé, configuration exclues) : {m}");
        let t = asn_entree(&p, tierce).await;
        assert_eq!(t["without_src_ip_since_start"], json!(3),
            "exec, account et tamper d'une source tierce restent comptés (le doute compte, P4.12-b) : {t}");
    }

    /// Ce que CE fil a compté sans adresse sous chaque source pendant `f` (compte par fil : aucun autre
    /// témoin parallèle ne peut le faire bouger).
    fn asn_delta_du_fil<F: FnOnce()>(sources: &[&str], f: F) -> Vec<u64> {
        use crate::metrics::sans_adresse_de_ce_fil::compte;
        let avant: Vec<u64> = sources.iter().map(|s| compte(s)).collect();
        f();
        sources.iter().zip(avant).map(|(s, a)| compte(s) - a).collect()
    }

    /// Le prédicat pur, sur un sac `fields` écrit en JSON.
    fn asn_peut(source: &str, category: &str, fields: Option<Value>) -> bool {
        let f = fields.map(|v| v.to_string());
        crate::metrics::evenement_peut_porter_une_adresse(source, category, f.as_deref())
    }

    /// Les paires (source, catégorie) exclues, recopiées ICI à la main : retirer une paire de la liste de
    /// production, ou en ajouter une, rompt l'égalité ci-dessous.
    const ASN_PAIRES_ATTENDUES: &[(&str, &str)] = &[
        ("auditd", "exec"),
        ("windows-security", "exec"),
        ("WinEventLog:Security", "exec"),
        ("auditd", "tamper"),
        ("auditd", "account"),
        ("windows-security", "account"),
        ("integrity", "integrity"),
        ("sudo", "auth"),
        ("su", "auth"),
        ("dataaccess", "data"),
        ("dataacl", "data"),
        ("kube-rbac", "data"),
        ("minio", "data"),
    ];

    /// LE PRÉDICAT : chaque paire n'exclut QUE sa catégorie, pour sa source exacte. La même source en
    /// `network` sans adresse reste comptée ; une source dont le nom PROLONGE celui d'une paire aussi.
    #[test]
    fn asn_une_paire_exclut_sa_categorie_pas_toute_la_source() {
        let mut prod: Vec<(&str, &str)> = crate::metrics::EVENEMENTS_SANS_ADRESSE_PAR_NATURE.iter().filter(|(s, _)| *s != "*").copied().collect();
        let mut attendu: Vec<(&str, &str)> = ASN_PAIRES_ATTENDUES.to_vec();
        prod.sort();
        attendu.sort();
        assert_eq!(prod, attendu, "les paires de production sont celles que ce témoin juge, ni plus ni moins");
        for (s, c) in ASN_PAIRES_ATTENDUES {
            assert!(!asn_peut(s, c, None), "`{s}` category={c} ne peut pas porter d'adresse");
            assert!(asn_peut(s, "network", None), "`{s}` category=network reste compté : seule sa catégorie listée est exclue");
        }
        // Deux cas nommés hors boucle : le capteur Rust de plume (4688) et le préfixe d'une source distante.
        assert!(!asn_peut("WinEventLog:Security", "exec", None), "4688 de l'agent Rust : exécution locale");
        assert!(asn_peut("WinEventLog:Security", "auth", None), "une ouverture de session Windows reste comptée");
        assert!(asn_peut("minio-audit", "data", None), "`minio-audit` n'est pas `minio` : accès S3 distant, compté");
        // Les deux jokers, sur une source quelconque.
        assert!(!asn_peut("asn-quelconque", "health", None) && !asn_peut("asn-quelconque", "config", None), "santé et configuration : jamais d'adresse");
        assert!(asn_peut("asn-quelconque", "network", None), "la même source en réseau est comptée");
    }

    /// LA RÈGLE DE CONTENU : la source, la catégorie, le champ ET la valeur décident ensemble.
    #[test]
    fn asn_la_regle_de_contenu_juge_source_categorie_et_valeur() {
        let addr = |a: &str| Some(json!({"acct": "alice", "exe": "/usr/bin/sudo", "res": "failed", "addr": a}));
        // auditd `USER_AUTH res=failed` (collectors/auditd.sh:258-263) : `addr=?` = aucun pair.
        assert!(!asn_peut("auditd", "auth", addr("?")), "auditd auth addr=? : non compté");
        assert!(asn_peut("asn-idp-tiers", "auth", addr("?")), "une AUTRE source en auth avec addr=? reste comptée (condition de source)");
        assert!(asn_peut("auditd", "network", addr("?")), "auditd d'une AUTRE catégorie avec addr=? reste compté (condition de catégorie)");
        assert!(asn_peut("auditd", "auth", addr("bastion.example")), "un addr en nom d'hôte (non promu) reste compté (valeur)");
        assert!(asn_peut("auditd", "auth", Some(json!({"acct": "alice", "res": "failed"}))), "un addr absent reste compté");
        assert!(asn_peut("auditd", "auth", None), "sans sac : compté (le doute compte)");
        // sshd et sshd-session : les lignes pam de session n'ont aucune adresse.
        let action = |a: &str| Some(json!({"user": "root", "action": a}));
        for src in ["sshd", "sshd-session"] {
            for a in ["session_open", "session_close"] {
                assert!(!asn_peut(src, "auth", action(a)), "{src} action={a} : ligne de session sans pair, non comptée");
            }
            assert!(asn_peut(src, "auth", action("failure")), "{src} échec sans adresse lue : compté");
            assert!(asn_peut(src, "auth", Some(json!({"user": "root"}))), "{src} sans action : compté");
            assert!(asn_peut(src, "network", action("session_open")), "{src} hors auth : la règle ne s'applique pas");
            assert!(asn_peut(src, "auth", addr("?")), "{src} : `addr=?` n'est un aveu que chez auditd");
        }
        assert!(asn_peut("asn-idp-tiers", "auth", action("session_open")), "une autre source en session reste comptée");
        assert!(asn_peut("auditd", "auth", action("session_open")), "auditd : `action=session_open` n'est pas sa règle");
        // LE NOM DU CHAMP décide : la valeur d'aveu dans un AUTRE champ ne suffit pas. auditd écrit `acct="?"`
        // pour un utilisateur inconnu ; une ligne au `addr` en nom d'hôte reste comptée.
        assert!(asn_peut("auditd", "auth", Some(json!({"acct": "?", "addr": "bastion.example", "res": "failed"}))),
            "auditd acct=? mais addr en nom d'hôte : compté (seul `addr` porte l'aveu)");
        for src in ["sshd", "sshd-session"] {
            assert!(asn_peut(src, "auth", Some(json!({"user": "session_open"}))), "{src} user=session_open : compté (seul `action` décide)");
        }
    }

    /// LA VOIE GÉNÉRIQUE passe le sac écrit au prédicat : auditd `addr=?` ingéré n'est pas compté, un nom
    /// d'hôte ou un addr absent l'est (compte du fil).
    #[test]
    fn asn_auditd_auth_addr_point_d_interrogation_n_est_pas_compte() {
        let conn = test_db();
        let dbp = "asn-auditd-auth";
        let ev = |i: i64, addr: Option<&str>| {
            let mut e = asn_ev("auditd", "auth", 200 + i, None);
            let mut f = json!({"acct": "alice", "exe": "/usr/bin/sudo", "res": "failed", "action": "failure"});
            if let Some(a) = addr {
                f["addr"] = json!(a);
            }
            e["fields"] = f;
            e
        };
        let locales = asn_delta_du_fil(&["auditd"], || {
            ingest_events_batch(&conn, dbp, &[ev(0, Some("?")), ev(1, Some("?"))], 1, None, None).unwrap();
        });
        assert_eq!(locales, vec![0], "deux échecs sudo locaux (addr=?) : rien de compté");
        let distantes = asn_delta_du_fil(&["auditd"], || {
            ingest_events_batch(&conn, dbp, &[ev(2, Some("bastion.example")), ev(3, None)], 1, None, None).unwrap();
        });
        assert_eq!(distantes, vec![2], "un addr en nom d'hôte (non promu) ou absent reste compté");
    }

    /// L'AGENT RUST (`WinEventLog:Security`, 4688 -> `exec`, agent/src/source/windows.rs:426) suit la même
    /// règle que windows-security/exec par la voie générique ; son `auth` reste compté.
    #[test]
    fn asn_l_exec_de_l_agent_windows_n_est_pas_compte() {
        let conn = test_db();
        let src = "WinEventLog:Security";
        let d = asn_delta_du_fil(&[src], || {
            let evs = vec![asn_ev(src, "exec", 500, None), asn_ev(src, "exec", 501, None), asn_ev(src, "auth", 502, None)];
            ingest_events_batch(&conn, "asn-winevt", &evs, 1, None, None).unwrap();
        });
        assert_eq!(d, vec![1], "deux 4688 sans adresse : rien ; une ouverture de session sans adresse : comptée");
    }

    /// LA GESTION DE COMPTES DE L'AGENT RUST, rangée en `auth` sous `WinEventLog:Security`
    /// (agent/src/source/windows.rs:408-417), n'est pas comptée : l'agent écrit `event_id` en NOMBRE
    /// (agent/src/source/windows.rs:571). Les ouvertures de session de la même paire restent comptées, et le
    /// même identifiant chez une autre source ou en chaîne hors de la liste ne décide rien.
    #[test]
    fn asn_la_gestion_de_comptes_de_l_agent_windows_n_est_pas_comptee() {
        let eid = |n: i64| Some(json!({"event_id": n, "channel": "Security"}));
        for n in [4720, 4722, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740] {
            assert!(!asn_peut("WinEventLog:Security", "auth", eid(n)), "agent Rust auth event_id={n} (nombre) : gestion de compte, non comptée");
        }
        assert!(!asn_peut("WinEventLog:Security", "auth", Some(json!({"event_id": "4720"}))), "la forme chaîne vaut la forme nombre");
        for n in [4624, 4625, 4648, 4768, 4776] {
            assert!(asn_peut("WinEventLog:Security", "auth", eid(n)), "event_id={n} : authentification, comptée");
        }
        assert!(asn_peut("WinEventLog:System", "auth", eid(4720)), "une autre source avec 4720 : comptée");
        assert!(asn_peut("WinEventLog:Security", "network", eid(4720)), "hors auth : comptée");
        assert!(asn_peut("WinEventLog:Security", "auth", Some(json!({"record_id": 4720}))), "4720 dans un autre champ : comptée");
        // Par l'ingestion, compte du fil : une gestion de compte et une ouverture de session sans adresse.
        let conn = test_db();
        let p = "asn-win-comptes";
        let evs = vec![
            json!({"ts": now() - 60, "source": "WinEventLog:Security", "category": "auth", "severity": 1, "message": "4720", "fields": {"event_id": 4720}, "dedup": "asn-w1"}),
            json!({"ts": now() - 61, "source": "WinEventLog:Security", "category": "auth", "severity": 1, "message": "4624", "fields": {"event_id": 4624}, "dedup": "asn-w2"}),
        ];
        let d = asn_delta_du_fil(&["WinEventLog:Security"], || {
            ingest_events_batch(&conn, p, &evs, 1, None, None).unwrap();
        });
        assert_eq!(d, vec![1], "seule l'ouverture de session sans adresse est comptée");
    }

    /// LA VOIE JOURNALD pose `auth` en dur et passe son sac : `sudo` et `su` (élévation locale) ne sont pas
    /// comptés, ni les lignes de session de sshd et sshd-session ; une ligne sshd sans adresse qui n'est pas
    /// une session l'est, une ligne avec adresse ne l'est pas. Une source propre au témoin lit le compte de
    /// PROCESSUS servi à la route.
    #[test]
    fn asn_journald_sudo_et_su_ne_sont_pas_comptes_sshd_l_est() {
        let conn = test_db();
        let dbp = "asn-journald";
        let propre = "asn-journald-propre";
        let l = |c: &str, i: u32, m: &str| format!(r#"{{"__REALTIME_TIMESTAMP":"17000000{i:02}000000","_COMM":"{c}","MESSAGE":"{m}","PRIORITY":"5","__CURSOR":"asn{i}","_HOSTNAME":"h1"}}"#);
        let lignes = [
            l("sudo", 1, "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"),
            l("sudo", 2, "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"),
            l("su", 3, "pam_unix(su:session): session opened for user root by alice(uid=1000)"),
            l("sshd", 4, "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)"),
            l("sshd", 5, "pam_unix(sshd:session): session closed for user root"),
            l("sshd-session", 6, "pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)"),
            l("sshd-session", 7, "pam_unix(sshd:session): session closed for user root"),
            l("sshd", 8, "error: kex_exchange_identification: Connection closed by remote host"),
            l("sshd", 9, "Failed password for root from 192.0.2.7 port 2222 ssh2"),
            l(propre, 10, "error: kex_exchange_identification: Connection closed by remote host"),
        ].join("\n");
        let d = asn_delta_du_fil(&["sudo", "su", "sshd", "sshd-session", propre], || {
            assert_eq!(crate::ingest::ingest_journal_lines(&conn, dbp, &lignes, None).ok(), Some(10), "prémisse : dix lignes journald ingérées");
        });
        assert_eq!(d, vec![0, 0, 1, 0, 1], "sudo, su et les sessions : rien ; sshd hors session sans adresse : une ; l'adresse lue : rien");
        assert_eq!(crate::metrics::sans_adresse_source_de(propre), Some(1), "le compte de processus (servi à la route) voit la ligne de la source propre");
    }

    /// `integrity` (empreintes de fichiers surveillés, collectors/integrity.sh:295) n'a aucun pair.
    #[test]
    fn asn_les_empreintes_integrity_ne_sont_pas_comptees() {
        let conn = test_db();
        let d = asn_delta_du_fil(&["integrity"], || {
            let evs: Vec<Value> = (0..2).map(|i| {
                let mut e = asn_ev("integrity", "integrity", 300 + i, None);
                e["fields"] = json!({"path": "/etc/passwd", "change": "modified"});
                e
            }).collect();
            ingest_events_batch(&conn, "asn-integrity", &evs, 1, None, None).unwrap();
        });
        assert_eq!(d, vec![0], "deux empreintes modifiées sans adresse : rien de compté");
    }

    /// C'est la catégorie ÉCRITE (après le parseur déclaratif) qui décide, pas celle que le producteur a
    /// déclarée : un événement sans catégorie qu'un dparser range en `health` n'est pas compté.
    #[test]
    fn asn_la_categorie_ecrite_par_un_dparser_decide() {
        let conn = test_db();
        let dbp = ":memory:asn-dparser";
        let src = "asn-dparser-battement";
        let spec = r#"{"name":"asn-batt","source":"asn-dparser-battement","map":{"category":"health"}}"#;
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('asn-batt','asn-dparser-battement',?1,1,0,1,0)", params![spec]).unwrap();
        crate::parsers::dparsers_reload(&conn, dbp);
        let evs: Vec<Value> = (0..3).map(|i| json!({"ts": now() - 60 - i, "source": src, "severity": 1, "message": format!("battement {i}"), "dedup": format!("asn-dp-{i}")})).collect();
        ingest_events_batch(&conn, dbp, &evs, 1, None, None).unwrap();
        let cats: Vec<String> = conn.prepare("SELECT category FROM event WHERE source=?1").unwrap()
            .query_map([src], |r| r.get(0)).unwrap().flatten().collect();
        assert_eq!(cats, vec!["health"; 3], "instrument : le dparser a écrit la catégorie");
        assert_eq!(crate::metrics::sans_adresse_source_de(src), None, "catégorie écrite `health` : rien de compté");
    }

    /// `data` n'est exclu QUE pour les sources dont la donnée est locale : une autre source `data` reste
    /// comptée (le prédicat de source décide), et `minio-audit` (accès S3 d'un client distant) aussi.
    #[tokio::test]
    async fn asn_la_categorie_data_n_est_exclue_que_pour_les_sources_locales() {
        let (_tmp, p) = imp_base_disque("asn-data");
        let locales = ["dataaccess", "dataacl", "kube-rbac", "minio"];
        let distante = "asn-donnees-distantes";
        let d = asn_delta_du_fil(&["dataaccess", "dataacl", "kube-rbac", "minio", "minio-audit"], || {
            let w = open_db(&p).unwrap();
            let mut evs: Vec<Value> = Vec::new();
            for s in locales {
                evs.extend((0..3).map(|i| asn_ev(s, "data", i, None)));
            }
            evs.extend((0..3).map(|i| asn_ev(distante, "data", i, None)));
            evs.extend((0..3).map(|i| asn_ev("minio-audit", "data", 400 + i, None)));
            ingest_events_batch(&w, &p, &evs, 1, None, None).unwrap();
            rollup_events(&w);
        });
        assert_eq!(d, vec![0, 0, 0, 0, 3], "données locales : rien ; minio-audit (daemon/src/ingest/minio.rs:165), accès S3 distant : trois");
        let e = asn_entree(&p, distante).await;
        assert_eq!(e["without_src_ip_since_start"], json!(3), "une autre source `data` sans adresse reste comptée, servie par la route : {e}");
    }

    /// Le TOTAL publié suit la même règle que la ventilation : des battements de santé sans adresse ne
    /// le font pas monter. Le total est un compte de PROCESSUS que les témoins parallèles de `cargo test`
    /// font monter aussi : la borne est large (moins que les battements ingérés), et le constat se rejoue
    /// jusqu'à trois fois avant de conclure — une course ne coïncide pas trois fois avec deux mille lignes,
    /// le mutant qui compte avant le prédicat monte de deux mille à CHAQUE essai.
    #[test]
    fn asn_le_total_publie_ne_compte_pas_les_battements() {
        let conn = test_db();
        let dbp = "asn-total";
        let total = |c: &Connection| crate::gather_json(c, "/spool", dbp, &crate::handlers::system::VersionDeSchema::Lue(0), 80)["ingest"]["events_without_src_ip_total"]
            .as_u64()
            .expect("total publié");
        const N: i64 = 2_000;
        let mut essais = Vec::new();
        for essai in 0..3 {
            let avant = total(&conn);
            let beats: Vec<Value> = (0..N).map(|i| asn_ev("asn-total-battements", "health", essai * N + i, None)).collect();
            ingest_events_batch(&conn, dbp, &beats, 1, None, None).unwrap();
            let apres = total(&conn);
            essais.push((avant, apres));
            if apres - avant < N as u64 {
                break;
            }
        }
        let (avant, apres) = *essais.last().unwrap();
        assert!(apres - avant < N as u64, "deux mille battements sans adresse ne montent pas le total publié ({essais:?})");
        assert_eq!(crate::metrics::sans_adresse_source_de("asn-total-battements"), None, "ni la ventilation par source");
    }

    /// PAR LA ROUTE : les deux sources Cloudflare servent une cadence ÉVÉNEMENTIELLE déclarée par leur
    /// sonde, et deux heures de silence (site calme) ne les rendent pas « en retard ».
    #[tokio::test]
    async fn asn_les_deux_sources_cloudflare_servent_une_cadence_evenementielle_declaree() {
        let (_tmp, p) = imp_base_disque("asn-cf");
        {
            let w = open_db(&p).unwrap();
            imp_flux(&w, "web", "web", 10, 4); // pipeline frais
            imp_flux(&w, "cloudflare", "web", 2 * 3600, 4);
            imp_flux(&w, "cloudflare-http", "web", 2 * 3600, 4);
            rollup_events(&w);
        }
        for src in ["cloudflare", "cloudflare-http"] {
            let e = asn_entree(&p, src).await;
            assert_eq!(e["cadence_declaree"], "evenementielle", "{src} : cadence servie : {e}");
            assert_eq!(e["cadence_capteur"], src, "{src} : déclarée par sa propre sonde : {e}");
            assert_eq!(e["cadence_declarable"], false, "{src} : une sonde parle, l'exploitant n'a plus à la déclarer : {e}");
            assert_eq!(e["status"], "calme", "{src} : deux heures sans événement sur un site calme, jamais « en retard » : {e}");
        }
    }

    /// L'INTERVALLE servi pour les deux sondes Cloudflare est celui de leur minuteur (2 min,
    /// systemd/plume-cloudflare*.timer:6), lu par le panneau des intégrations (`interval_s`) — la cadence
    /// `Evenementielle` de `/api/sources` n'en porte aucun, c'est donc ici qu'il est tenu.
    #[test]
    fn asn_les_deux_sondes_cloudflare_servent_l_intervalle_du_minuteur() {
        let (_tmp, p) = imp_base_disque("asn-cf-intervalle");
        let iv = compute_integrations(&p);
        for src in ["cloudflare", "cloudflare-http"] {
            let c = iv["collectors"].as_array().unwrap().iter().find(|c| c["id"] == src).cloned().unwrap_or_else(|| panic!("{src} absent : {iv}"));
            assert_eq!(c["interval_s"], json!(120), "{src} : l'intervalle servi est le minuteur de 2 min : {c}");
            assert_eq!(c["event_based"], json!(true), "{src} : capteur événementiel : {c}");
        }
    }

    /// Le témoin direct de la déclaration (inversion de `cadence_declaree_derive_des_sondes`, qui
    /// tenait `cloudflare` pour non déclarée).
    #[test]
    fn les_deux_capteurs_cloudflare_declarent_une_cadence_evenementielle() {
        use crate::sondes::DeclarantDeCadence as Decl;
        assert_eq!(cadence_declaree("event", "cloudflare"), CadenceDeclaree::Evenementielle { par: Decl::Sonde("cloudflare") });
        assert_eq!(cadence_declaree("event", "cloudflare-http"), CadenceDeclaree::Evenementielle { par: Decl::Sonde("cloudflare-http") });
    }
