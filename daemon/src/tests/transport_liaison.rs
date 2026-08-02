    // ================================================================================================
    // LE BLOC TRANSPORT + LIAISON D'HÔTE — P5.3-a (autorité de la requête) et P5.2-a/b (hôte d'une
    // ligne ingérée, portée d'un jeton).
    //
    // Ce que ces tests figent, et pourquoi ils sont ici plutôt qu'ailleurs :
    //   1. l'AUTORITÉ d'une requête se lit dans les DEUX emplacements du protocole. Les deux formes
    //      reproduites ci-dessous ne sont pas devinées : elles sont la SORTIE d'une sonde posée dans le
    //      middleware réel le 2026-08-02, contre un daemon en TLS natif, en HTTP/1.1 puis en HTTP/2 —
    //        HTTP/1.1 -> uri.authority = None,               header Host = Some("plume.test:7443")
    //        HTTP/2.0 -> uri.authority = Some(plume.test:7443), header Host = None
    //      La garde ne peut donc pas être vérifiée « sur le papier » : ce sont ces deux formes-là qui
    //      arrivent, et c'est sur elles qu'on teste.
    //   2. l'HÔTE d'une ligne ingérée vient d'UNE résolution, la même pour toutes les surfaces.
    //   3. la PORTÉE d'un jeton est une DÉCLARATION : l'omission est refusée, pas défaultée.
    //
    // GARANTIE À LA COMPILATION (elle ne peut pas s'écrire en test, c'est le point) : `AutoriteDemandee`,
    // `HoteIngere` et `PorteeJeton` ont tous un champ/constructeur PRIVÉ. On ne peut pas fabriquer une
    // autorité depuis le seul en-tête `Host`, ni un hôte de ligne depuis une query string, ni un jeton
    // sans trancher sa portée : la mutation correspondante ne compile pas.
    // ================================================================================================

    /// Requête telle que hyper la livre en HTTP/1.1 : cible en forme ORIGINE (chemin seul) + en-tête `Host`.
    fn req_h1(host: &str, path: &str) -> Request {
        axum::http::Request::builder()
            .version(axum::http::Version::HTTP_11)
            .method("GET")
            .uri(path)
            .header("host", host)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// Requête telle que hyper la livre en HTTP/2 : `:authority` rangé DANS l'URI, AUCUN en-tête `Host`.
    fn req_h2(authority: &str, path: &str) -> Request {
        axum::http::Request::builder()
            .version(axum::http::Version::HTTP_2)
            .method("GET")
            .uri(format!("https://{authority}{path}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    // ---------------------------------------------------------------------------------------------
    // (1) P5.3-a — L'AUTORITÉ DEMANDÉE
    // ---------------------------------------------------------------------------------------------

    /// LE DÉFAUT LUI-MÊME. En HTTP/2 il n'y a PAS d'en-tête `Host` : une lecture qui ne regardait que là
    /// rendait `None`, que `host_guard` traduisait en 421 « bad host ». MESURÉ le 2026-08-02 sur le
    /// daemon en TLS natif (ALPN annonce `h2` EN PREMIER, donc un navigateur négocie h2) : `/api/me`,
    /// `/api/search`, `/login` et `/` répondaient 421 en HTTP/2 et 401/404 en `--http1.1`, MÊME autorité.
    /// 242 des 245 routes déclarées étaient injoignables depuis un navigateur ; seules `/healthz`,
    /// `/readyz` et `/metrics` répondaient, parce qu'elles sont exemptées de la garde.
    #[test]
    fn autorite_lue_dans_les_deux_formes_du_protocole() {
        // HTTP/1.1 : l'autorité est dans l'en-tête.
        assert_eq!(AutoriteDemandee::de_la_requete(&req_h1("plume.test:7443", "/api/me")).hote(), Some("plume.test"));
        // HTTP/2 : l'autorité est dans l'URI, et il n'y a AUCUN en-tête Host. C'est le cas qui rendait 421.
        let h2 = req_h2("plume.test:7443", "/api/me");
        assert!(h2.headers().get(axum::http::header::HOST).is_none(), "forme h2 : pas d'en-tête Host (c'est tout le défaut)");
        assert_eq!(AutoriteDemandee::de_la_requete(&h2).hote(), Some("plume.test"));
    }

    /// LA GARDE RESTE UNE GARDE. Le remède n'est pas de laisser passer quand l'autorité manque : une
    /// requête qui ne nomme AUCUNE autorité rend `None`, et `None` est un refus chez l'appelant.
    #[test]
    fn autorite_absente_reste_absente_jamais_un_laissez_passer() {
        let nue = axum::http::Request::builder()
            .version(axum::http::Version::HTTP_11)
            .method("GET").uri("/api/me")
            .body(axum::body::Body::empty()).unwrap();
        assert_eq!(AutoriteDemandee::de_la_requete(&nue).hote(), None,
            "aucune autorité nommée -> None (host_guard le traduit en 421, comme avant)");
    }

    /// LE DÉCOUPAGE : port retiré s'il en EST un, crochets IPv6 retirés, et une forme MALFORMÉE n'est PAS
    /// tronquée en quelque chose qui pourrait matcher l'allowlist (la garde ne s'élargit pas).
    #[test]
    fn autorite_decoupe_port_et_ipv6_sans_elargir() {
        let cas = [
            ("plume.test", "plume.test"),
            ("plume.test:7443", "plume.test"),
            ("[::1]:7443", "::1"),
            ("127.0.0.1:7000", "127.0.0.1"),
            ("plume.test:", "plume.test:"), // port vide = forme malformée -> NON tronquée -> ne matche rien
        ];
        for (brut, attendu) in cas {
            assert_eq!(AutoriteDemandee::de_la_requete(&req_h1(brut, "/x")).hote(), Some(attendu), "autorité « {brut} »");
        }
    }

    /// LA MÊME SOURCE SERT LES DEUX GARDES. `sso_same_origin_ok` lisait elle aussi l'en-tête `Host` seul :
    /// en HTTP/2 son repli same-origin refusait TOUTE mutation SSO. Elle lit désormais la même autorité.
    /// (Défaut de DISPONIBILITÉ, pas de sécurité — le refus était fail-closed — mais même trou.)
    #[test]
    fn csrf_sso_same_origin_fonctionne_aussi_en_http2() {
        // Origin qui CORRESPOND à l'autorité :h2 -> accepté.
        let ok = axum::http::Request::builder()
            .version(axum::http::Version::HTTP_2).method("POST")
            .uri("https://plume.test/api/notifiers")
            .header("origin", "https://plume.test")
            .body(axum::body::Body::empty()).unwrap();
        assert!(sso_same_origin_ok(&ok), "h2 + Origin same-origin -> accepté (avant : refusé, faute d'en-tête Host)");
        // Origin ÉTRANGER -> refusé, en h2 comme en h1.
        let ko = axum::http::Request::builder()
            .version(axum::http::Version::HTTP_2).method("POST")
            .uri("https://plume.test/api/notifiers")
            .header("origin", "https://attaquant.example")
            .body(axum::body::Body::empty()).unwrap();
        assert!(!sso_same_origin_ok(&ko), "la défense CSRF MORD toujours en h2");
        // Ni Origin ni Referer -> refus fail-closed (inchangé).
        let nu = axum::http::Request::builder()
            .version(axum::http::Version::HTTP_2).method("POST")
            .uri("https://plume.test/api/notifiers")
            .body(axum::body::Body::empty()).unwrap();
        assert!(!sso_same_origin_ok(&nu), "fail-closed conservé");
    }

    // ---------------------------------------------------------------------------------------------
    // (2) P5.2-a — L'HÔTE D'UNE LIGNE INGÉRÉE
    // ---------------------------------------------------------------------------------------------

    fn au_agent_lie(host: &str) -> AuthUser {
        AuthUser { name: host.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false, method: "bearer".into(), csrf: String::new(), env: None }
    }

    /// LE THÉORÈME. Quelle que soit la surface et quel que soit l'hôte DÉCLARÉ, un jeton lié écrit sous
    /// SON hôte. MESURÉ avant correction, jeton lié à `WS22-LAB` : `/api/metrics/prom?host=…` -> 200 et
    /// métrique stockée sous l'hôte usurpé ; `/api/metrics/write` (label `instance`) -> 204 idem ;
    /// `/services/collector` (HEC) -> 200 idem. La résolution ne connaît pas les routes : elle ne peut
    /// donc pas en oublier une.
    #[test]
    fn hote_ingere_un_jeton_lie_ecrit_sous_son_hote_quoi_qu_il_declare() {
        let au = au_agent_lie("WS22-LAB");
        for declare in [None, Some("HOTE-USURPE-PAR-METRICS"), Some("CONTROLEUR-DE-DOMAINE-USURPE"), Some(""), Some("WS22-LAB")] {
            assert_eq!(HoteIngere::resoudre(&au, declare).as_deref(), Some("WS22-LAB"),
                "déclaré {declare:?} -> l'hôte du jeton gagne, toujours");
        }
    }

    /// CE QUE LA GARDE NE DOIT PAS CASSER : un RELAIS. Jeton non lié, collecteur Basic (editor/admin),
    /// utilisateur — l'hôte déclaré passe INCHANGÉ, sinon on casserait tout forwarder multi-hôtes.
    #[test]
    fn hote_ingere_un_relais_garde_l_hote_qu_il_declare() {
        let non_lie = AuthUser { name: String::new(), ..au_agent_lie("x") };
        let editor = AuthUser { name: "collecteur-central".into(), role: "editor".into(), ..au_agent_lie("x") };
        for au in [&non_lie, &editor] {
            assert_eq!(HoteIngere::resoudre(au, Some("RELAIS-DECLARE")).as_deref(), Some("RELAIS-DECLARE"));
            assert_eq!(HoteIngere::resoudre(au, None).as_deref(), None);
        }
        // Un `name` non conforme à un hostname ne lie RIEN (fail vers le déclaré, jamais un crash).
        let bancal = au_agent_lie("bad host/../#");
        assert_eq!(HoteIngere::resoudre(&bancal, Some("DECLARE")).as_deref(), Some("DECLARE"));
    }

    /// UN SEUL PRÉDICAT. Le marqueur spool `#H#…#H#` (voie `/api/ingest`, `/api/ingest/journal`, HEC,
    /// OTLP, MinIO) et la résolution en direct (`/api/metrics/*`, `/loki/api/v1/push`) répondent à la
    /// MÊME question. Ils ne peuvent plus diverger : le marqueur est ÉCRIT en termes de la résolution.
    #[test]
    fn marqueur_spool_et_resolution_sont_le_meme_predicat() {
        for au in [
            au_agent_lie("web01.internal"),
            AuthUser { name: String::new(), ..au_agent_lie("x") },
            AuthUser { name: "collecteur".into(), role: "editor".into(), ..au_agent_lie("x") },
            au_agent_lie("bad host/../#"),
        ] {
            let attendu = match HoteIngere::resoudre(&au, None).as_deref() {
                Some(h) => format!("#H#{h}#H#"),
                None => String::new(),
            };
            assert_eq!(spool_host_marker(&au), attendu, "marqueur et résolution doivent coïncider pour {}", au.name);
        }
    }

    /// LE DTO D'ÉCRITURE PORTE L'HÔTE RÉSOLU — c'est ce qui empêche une route d'écrire `?host=` tel quel
    /// (le point d'écriture n'accepte pas de chaîne d'hôte). On vérifie ici que la valeur transportée est
    /// bien celle de la résolution, pour les deux issues.
    #[test]
    fn metric_ingeree_porte_l_hote_resolu() {
        let lie = metric_ingeree(42, "m", "{}", 1.5, &HoteIngere::resoudre(&au_agent_lie("WS22-LAB"), Some("USURPE")));
        assert_eq!(lie.host.as_deref(), Some("WS22-LAB"));
        assert_eq!((lie.ts, lie.name.as_str(), lie.labels.as_deref(), lie.value), (42, "m", Some("{}"), 1.5));
        let relais = AuthUser { name: String::new(), ..au_agent_lie("x") };
        let libre = metric_ingeree(42, "m", "{}", 1.5, &HoteIngere::resoudre(&relais, Some("RELAIS-DECLARE")));
        assert_eq!(libre.host.as_deref(), Some("RELAIS-DECLARE"));
    }

    // ---------------------------------------------------------------------------------------------
    // (3) P5.2-b — LA PORTÉE D'UN JETON
    // ---------------------------------------------------------------------------------------------

    /// L'OMISSION EST REFUSÉE. `plume-daemon token <nom>` (deux arguments) produisait un jeton non lié —
    /// MESURÉ le 2026-08-02 : avec lui, `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` est accepté (202) et
    /// STOCKÉ sous ce nom. La portée doit désormais être ÉCRITE, dans un sens ou dans l'autre.
    #[test]
    fn portee_jeton_ni_hote_ni_relais_est_refuse() {
        let err = PorteeJeton::declarer(None, false).unwrap_err();
        assert!(err.contains("usurper"), "le refus DIT ce qui est en jeu, il ne renvoie pas juste « usage » : {err}");
        // La chaîne vide est une OMISSION, pas une déclaration de relais.
        assert!(PorteeJeton::declarer(Some("   "), false).is_err());
    }

    /// LES DEUX DÉCLARATIONS VALIDES, ET LEUR CONSÉQUENCE SUR LA COLONNE `host`.
    #[test]
    fn portee_jeton_machine_ou_relais() {
        assert_eq!(PorteeJeton::declarer(Some("web01.internal"), false).unwrap().hote_lie(), Some("web01.internal"));
        assert_eq!(PorteeJeton::declarer(None, true).unwrap().hote_lie(), None);
        // Espaces autour de l'hôte : tolérés (comme `b.trimmed`), la portée reste « machine ».
        assert_eq!(PorteeJeton::declarer(Some(" srv.local "), false).unwrap().hote_lie(), Some("srv.local"));
    }

    /// UNE DÉCLARATION CONTRADICTOIRE EST REFUSÉE, pas arbitrée en silence — sinon « je crois avoir
    /// provisionné une machine » et « le daemon a créé un relais » cohabiteraient sans que rien ne le dise.
    #[test]
    fn portee_jeton_hote_et_relais_ensemble_est_refuse() {
        assert!(PorteeJeton::declarer(Some("web01"), true).is_err());
    }

    /// L'HÔTE RESTE VALIDÉ (pas d'injection dans le marqueur ni dans un nom de fichier spool).
    #[test]
    fn portee_jeton_hote_invalide_refuse() {
        assert!(PorteeJeton::declarer(Some("bad host/../#"), false).is_err());
        assert!(PorteeJeton::declarer(Some(&"a".repeat(254)), false).is_err());
    }

    /// LE CHEMIN D'ÉCRITURE EST UNIQUE : la ligne `token` d'un jeton de MACHINE porte l'hôte, celle d'un
    /// RELAIS porte NULL — et il n'existe pas de troisième cas, puisqu'il n'existe pas de troisième portée.
    #[test]
    fn inserer_jeton_derive_la_colonne_host_de_la_portee() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE token(id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, \
             created INTEGER, last_used INTEGER, host TEXT, kind TEXT, role TEXT)",
        )
        .unwrap();
        inserer_jeton(&conn, "machine", "h1", None, None, &PorteeJeton::declarer(Some("web01"), false).unwrap()).unwrap();
        inserer_jeton(&conn, "relais", "h2", Some("hec"), None, &PorteeJeton::declarer(None, true).unwrap()).unwrap();
        let lu = |n: &str| -> Option<String> {
            conn.query_row("SELECT host FROM token WHERE name=?1", params![n], |r| r.get(0)).unwrap()
        };
        assert_eq!(lu("machine").as_deref(), Some("web01"));
        assert_eq!(lu("relais"), None, "un relais n'est lié à AUCUN hôte — NULL, pas la chaîne vide");
    }
