// =====================================================================================
// `P10.20-b` (rang quatre : `load_provider`, `ldap_login_post`), `P10.31-u` (traces de connexion de `idp.rs`) et
// `P10.29-l` (texte du moteur servi par la modification et la suppression d'un fournisseur d'identité).
//
// LE DÉFAUT, MESURÉ SUR 2bbee64c AVANT LE CORRECTIF.
//   * `load_provider` lisait le fournisseur par `query_row(..).ok()`, et `ldap_login_post` le premier fournisseur LDAP
//     de la même façon : une lecture ratée devenait `None`, que les six appelants publics (`oidc_start`,
//     `oidc_callback`, `saml_start`, `saml_acs`, `saml_metadata`, `ldap_login_post`) servaient en 404 « provider …
//     inconnu ou désactivé » / « aucun provider LDAP activé » — une panne de la base lue comme une absence de
//     configuration ;
//   * les quatre traces de connexion (`ledger_append(&conn, "login", ..)` nus : OIDC, SAML, LDAP, second facteur local)
//     jetaient leur maillon : une connexion réussie pouvait ne laisser aucune trace non purgeable sans aveu ;
//   * `idp_provider_update` et `idp_provider_delete` servaient `échec transaction audit …: {e}` — la phrase du moteur
//     SQLite au client.
//
// LE CORRECTIF (décision par défaut de la vague AD). Fournisseur lu en trois issues : présent = la suite d'avant,
// absent = le 404 d'avant octet pour octet, lecture ratée = 503 `CAUSE_FOURNISSEUR_DE_CONNEXION_NON_LU` (cause du moteur
// au journal seul, sans le nom demandé ni l'identifiant présenté, aucun échec compté au frein LDAP). Les quatre traces
// passent par `tracer_la_connexion` : un maillon manquant n'annule pas la connexion et se dit au journal (porte,
// identifiant INTERNE du fournisseur, cause du moteur ; jamais l'identifiant connecté ni l'adresse). Les deux 500
// gardent leur phrase fixe sans `{e}`, la cause du moteur au journal.
//
// LES PANNES ÉPROUVÉES : la table `idp_provider` RENOMMÉE le temps de l'appel (aucun déclencheur ni vue ne la
// référence) ; des fournisseurs DÉSACTIVÉS (`enabled=0`) qui doivent rester une absence ; déclencheurs `RAISE(ABORT)`
// sur `BEFORE INSERT ON ledger`, genre `login` seul (la trace de connexion) ou genres `config.idp.*` seuls (la trace
// d'audit de la modification et de la suppression, refusée APRÈS l'écriture du fournisseur dans la transaction) ; les
// lignes de journal et toute la sortie lues sur un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AD1_LP_404`, `AD1_LDAP1_404` (lecture ratée rendue
// en absence), `AD1_LP_JOURNAL` (503 sans ligne de journal), `AD1_TRACE_MFA` (maillon du second facteur jeté),
// `AD1_TRACE_JOURNAL` (maillon lu, rien au journal), `AD1_TEXTE_UPD`, `AD1_TEXTE_DEL` (texte du moteur rendu au client),
// `AD1_TEXTE_UPD_JOURNAL`, `AD1_TEXTE_DEL_JOURNAL` (cause du moteur perdue) ; `AD1_TRACE_OIDC`, `AD1_TRACE_SAML`,
// `AD1_TRACE_LDAP` rendent, dans le SOURCE JUGÉ par le témoin textuel, le site de leur porte à sa forme d'avant.
// Second passage : `AD1_LP_SANS_ENABLED`, `AD1_LDAP1_SANS_ENABLED` (filtre `enabled=1` retiré), `AD1_UPD_COMMIT`,
// `AD1_DEL_COMMIT` (`COMMIT` au lieu du `ROLLBACK`), `AD1_MFA_FUITE` (l'identifiant connecté écrit sur une ligne hors
// `[idp] WARN`) ; `AD1_OIDC_FUITE`, `AD1_SAML_FUITE`, `AD1_LDAP_FUITE` (l'identifiant connecté ajouté au sujet, dans
// le source jugé).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les traces OIDC, SAML et LDAP ne sont tenues que par une LECTURE DU SOURCE (même
// limite que `bdrn_les_trois_portes_de_federation_tracent_leur_refus` : aucun IdP n'est jouable dans un témoin, SAML et
// LDAP sont derrière des features éteintes) — seule la trace du second facteur local est jouée de bout en bout ; une
// lecture qui échoue autrement que par une table absente (verrou, corruption) — le partage est le même `Err` ; l'écran
// de connexion de la console (aucun module de `web/` n'appelle ces routes par `fetch`) ; les 5xx d'`oidc_callback` et de
// `saml_start` qui servent un texte d'erreur réseau ou de construction (ce n'est pas le moteur SQLite).
// =====================================================================================
mod connexions_fournisseur_lu_et_trace_avouee {
    use super::*;

    const AD1_RENOMMER: &str = "ALTER TABLE idp_provider RENAME TO idp_provider_hors_d_atteinte;";
    const AD1_RENDRE: &str = "ALTER TABLE idp_provider_hors_d_atteinte RENAME TO idp_provider;";
    const AD1_MOTEUR_REGISTRE: &str = "ad1 registre refuse";
    const AD1_MOTEUR_ECRITURE: &str = "ad1 ecriture du fournisseur refusee";
    const AD1_GRAINE: &[u8] = b"12345678901234567890";
    /// L'identifiant du compte qui se connecte par le second facteur : un nom qu'aucune autre sortie du témoin ne porte,
    /// cherché dans TOUTE la sortie de l'enfant de `ad1_lignes_de_journal`.
    const AD1_PORTEUR_MFA: &str = "ad1porteurmfa";

    fn ad1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ad1_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ad1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn ad1_pair() -> std::net::SocketAddr {
        "10.77.0.2:45454".parse().expect("adresse de test")
    }

    /// Le peuplement de `idp_provider` d'un témoin : aucune ligne, un fournisseur DÉSACTIVÉ de chaque genre (une
    /// désactivation d'urgence : la ligne existe, `enabled=0`), ou un fournisseur ACTIF de chaque genre.
    #[derive(Clone, Copy)]
    enum Ad1Fournisseurs {
        Aucun,
        Desactives,
        Actifs,
    }

    /// L'état d'un témoin ; les fournisseurs posés portent les noms `<genre>-ad1` et une configuration vide.
    fn ad1_etat(tag: &str, fournisseurs: Ad1Fournisseurs) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("ad1-{tag}"));
        let actif = match fournisseurs {
            Ad1Fournisseurs::Aucun => return (st, p),
            Ad1Fournisseurs::Desactives => 0,
            Ad1Fournisseurs::Actifs => 1,
        };
        ad1_sql(
            &st,
            &format!(
                "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES \
                 ('oidc-ad1','oidc',{actif},'{{}}','s',1,1), ('saml-ad1','saml',{actif},'{{}}','s',1,1), ('ldap-ad1','ldap',{actif},'{{}}','s',1,1);"
            ),
        );
        (st, p)
    }

    /// Les sept points d'entrée publics qui lisent un fournisseur (le LDAP deux fois : nommé et premier activé).
    const AD1_ROUTES: [&str; 7] = ["oidc_start", "oidc_callback", "saml_start", "saml_acs", "saml_metadata", "ldap_nomme", "ldap_premier"];

    async fn ad1_jouer(st: &AppState, route: &str) -> (u16, Value) {
        let secret = st.session_secret.as_slice();
        let r = match route {
            "oidc_start" => oidc_start(State(st.clone()), axum::extract::Path("oidc-ad1".to_string())).await,
            "oidc_callback" => {
                let blob = oidc_state_sign(secret, "oidc-ad1", "etat-ad1", "nonce-ad1", "verif-ad1", 600);
                let mut entetes = axum::http::HeaderMap::new();
                entetes.insert(header::COOKIE, format!("plume_oidc={blob}").parse().expect("en-tête"));
                let q: HashMap<String, String> = [("state", "etat-ad1"), ("code", "code-ad1")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                oidc_callback(State(st.clone()), axum::http::Extensions::new(), entetes, Query(q)).await
            }
            "saml_start" => saml_start(State(st.clone()), axum::extract::Path("saml-ad1".to_string())).await,
            "saml_acs" => {
                let relais = saml_relaystate_sign(secret, "saml-ad1", "_ad1requete", 600);
                let f: HashMap<String, String> = [("SAMLResponse", "PHNhbWw+"), ("RelayState", relais.as_str())].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                saml_acs(State(st.clone()), axum::http::Extensions::new(), axum::http::HeaderMap::new(), axum::extract::Form(f)).await
            }
            "saml_metadata" => saml_metadata(State(st.clone()), axum::extract::Path("saml-ad1".to_string())).await,
            "ldap_nomme" => ldap_login_post(State(st.clone()), ConnectInfo(ad1_pair()), Json(json!({ "provider": "ldap-ad1", "user": "alice", "pass": "x" }))).await,
            "ldap_premier" => ldap_login_post(State(st.clone()), ConnectInfo(ad1_pair()), Json(json!({ "user": "alice", "pass": "x" }))).await,
            autre => panic!("route inconnue du témoin : {autre}"),
        };
        ad1_reponse(r).await
    }

    fn ad1_absence_attendue(route: &str) -> Value {
        match route {
            "oidc_start" | "oidc_callback" => json!({ "error": "provider OIDC inconnu ou désactivé" }),
            "saml_start" | "saml_acs" | "saml_metadata" => json!({ "error": "provider SAML inconnu ou désactivé" }),
            _ => json!({ "error": "aucun provider LDAP activé" }),
        }
    }

    /// Un 5xx nommé : EXACTEMENT les clés `error` et `id`, la cause attendue, l'identifiant de corrélation.
    fn ad1_juger_5xx(quoi: &str, corps: &Value, cause: &str) {
        let cles: Vec<&str> = corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la cause servie : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
    }

    fn ad1_echecs_ldap(st: &AppState) -> u32 {
        st.auth_fails.lock().get(&("alice".to_string(), ad1_pair().ip().to_string())).map_or(0, |f| f.count)
    }

    /// LES SEPT POINTS D'ENTRÉE, TROIS ISSUES CHACUN : absent = le 404 d'avant octet pour octet, que la table soit vide
    /// ou que le fournisseur soit DÉSACTIVÉ (`enabled=0`, la désactivation d'urgence) ; table hors d'atteinte = 503 nommé
    /// (clés exactes, pas de texte du moteur), aucun échec compté au frein LDAP ; présent = la suite d'avant (ni 404 ni
    /// 503). Rouge sous `AD1_LP_404` (six routes) et `AD1_LDAP1_404` (le LDAP sans fournisseur nommé) ; sous
    /// `AD1_LP_SANS_ENABLED` et `AD1_LDAP1_SANS_ENABLED` (le filtre `enabled=1` retiré : un fournisseur désactivé
    /// ouvrirait encore la connexion).
    #[tokio::test]
    async fn ad1_fournisseur_de_connexion_lu_en_trois_issues() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        assert!(AD1_ROUTES.len() >= 7, "plancher : les sept points d'entrée");
        let (vide, _pv) = ad1_etat("absent", Ad1Fournisseurs::Aucun);
        let (desactive, _pd) = ad1_etat("desactive", Ad1Fournisseurs::Desactives);
        assert_eq!(ad1_compte(&desactive, "SELECT COUNT(*) FROM idp_provider WHERE enabled=0"), 3, "contrôle : trois fournisseurs désactivés posés");
        let (st, _p) = ad1_etat("present", Ad1Fournisseurs::Actifs);
        let mut statuts_lus = Vec::new();
        for route in AD1_ROUTES {
            for (etat, quoi) in [(&vide, "table vide"), (&desactive, "fournisseur désactivé")] {
                let (statut, corps) = ad1_jouer(etat, route).await;
                assert_eq!((statut, corps), (404, ad1_absence_attendue(route)), "{route} ({quoi}) : absence ÉTABLIE, sortie d'avant");
            }

            let echecs_avant = ad1_echecs_ldap(&st);
            ad1_sql(&st, AD1_RENOMMER);
            let (statut, corps) = ad1_jouer(&st, route).await;
            ad1_sql(&st, AD1_RENDRE);
            assert_eq!(statut, 503, "{route} : lecture non faite, pas une absence : {corps}");
            ad1_juger_5xx(route, &corps, CAUSE_FOURNISSEUR_DE_CONNEXION_NON_LU);
            assert!(!corps.to_string().contains("no such table"), "{route} : l'erreur du moteur reste au journal : {corps}");
            assert_eq!(ad1_echecs_ldap(&st), echecs_avant, "{route} : aucun échec compté sur une lecture non faite");

            let (statut, corps) = ad1_jouer(&st, route).await;
            assert!(statut != 404 && statut != 503, "{route} : fournisseur lu, la suite d'avant : {statut} {corps}");
            statuts_lus.push((route, statut));
        }
        // Les statuts EXACTS du fournisseur lu (configuration vide) ne valent que sans les features `saml` et `ldap` :
        // avec elles, la vérification SAML et le bind LDAP sont réellement tentés et leurs statuts dépendent du moteur.
        if !cfg!(feature = "saml") && !cfg!(feature = "ldap") {
            let attendus: Vec<(&str, u16)> = AD1_ROUTES
                .iter()
                .map(|&route| (route, match route {
                    "oidc_start" | "saml_start" => 500,
                    "oidc_callback" => 502,
                    _ => 501,
                }))
                .collect();
            assert_eq!(statuts_lus, attendus, "fournisseur lu (configuration vide) : la suite d'avant, route par route");
        } else {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "ad1_fournisseur_de_connexion_lu_en_trois_issues",
                "feature `saml` ou `ldap` allumée : les statuts EXACTS du fournisseur lu (500/502/501, configuration vide) \
                 n'ont PAS été jugés, seulement « ni 404 ni 503 ». Rejouer sans ces features.",
            );
        }
    }

    /// La MODIFICATION et la SUPPRESSION d'un fournisseur dont la TRACE D'AUDIT est refusée (après que la désactivation
    /// et la suppression ont été écrites dans la transaction) : même statut (500), la phrase FIXE d'avant sans le texte
    /// du moteur (clés exactes), rien de changé — la transaction est annulée, le fournisseur reste présent et actif.
    /// Rouge sous `AD1_TEXTE_UPD`, `AD1_TEXTE_DEL` (texte du moteur servi) et `AD1_UPD_COMMIT`, `AD1_DEL_COMMIT`
    /// (`COMMIT` au lieu du `ROLLBACK` : la désactivation ou la suppression passe sans trace d'audit).
    #[tokio::test]
    async fn ad1_ecriture_du_fournisseur_refusee_sans_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ad1_etat("textes", Ad1Fournisseurs::Actifs);
        let id = ad1_compte(&st, "SELECT id FROM idp_provider WHERE name='oidc-ad1'");
        let (statut, corps) = ad1_modifier_et_supprimer(&st, id).await;
        assert_eq!(statut.0, 500, "modification refusée : statut d'avant : {}", corps.0);
        ad1_juger_5xx("modification", &corps.0, "échec transaction audit (aucune modification)");
        assert_eq!(statut.1, 500, "suppression refusée : statut d'avant : {}", corps.1);
        ad1_juger_5xx("suppression", &corps.1, "échec transaction audit");
        for c in [&corps.0, &corps.1] {
            assert!(!c.to_string().contains(AD1_MOTEUR_ECRITURE), "le texte du moteur reste au journal : {c}");
        }
        assert_eq!(ad1_compte(&st, &format!("SELECT COUNT(*) FROM idp_provider WHERE id={id} AND enabled=1")), 1, "transaction annulée : le fournisseur est intact et actif");
        assert_eq!(ad1_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.idp.%'"), 0, "aucune trace d'audit d'un geste annulé");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// Joue la désactivation puis la suppression sous un refus de la trace d'audit des fournisseurs (`config.idp.*` au
    /// registre) : l'écriture du fournisseur est faite dans la transaction, c'est l'audit qui échoue (le refus est retiré
    /// après).
    async fn ad1_modifier_et_supprimer(st: &AppState, id: i64) -> ((u16, u16), (Value, Value)) {
        let adm = sp_au("adm", "admin");
        ad1_sql(st, &format!("CREATE TRIGGER ad1_refus_audit BEFORE INSERT ON ledger WHEN NEW.kind LIKE 'config.idp.%' BEGIN SELECT RAISE(ABORT,'{AD1_MOTEUR_ECRITURE}'); END;"));
        let sans_secret = crate::secret_des_gestes::SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
        let (s1, c1) = ad1_reponse(
            idp_provider_update(State(st.clone()), sans_secret, Extension(adm.clone()), axum::extract::Path(id), Json(json!({ "enabled": false }))).await,
        )
        .await;
        let (s2, c2) = ad1_reponse(idp_provider_delete(State(st.clone()), Extension(adm), axum::extract::Path(id)).await).await;
        ad1_sql(st, "DROP TRIGGER ad1_refus_audit;");
        ((s1, s2), (c1, c2))
    }

    /// `AD1_PORTEUR_MFA` (compte admin) porteur d'une MFA ACTIVE à graine connue ; rend `(statut, session posée, corps)`
    /// du second facteur juste.
    async fn ad1_connexion_mfa(st: &AppState) -> (u16, bool, Value) {
        let graine = base32_encode(AD1_GRAINE);
        if ad1_compte(st, &format!("SELECT COUNT(*) FROM user_mfa WHERE user='{AD1_PORTEUR_MFA}'")) == 0 {
            let conn = st.db.lock();
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin')", params![AD1_PORTEUR_MFA, hash_pw("motdepasse12345").unwrap()])
                .expect("fixture : compte posé");
            conn.execute("INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,'[]',-1,0,0)", params![AD1_PORTEUR_MFA, graine])
                .expect("fixture : MFA active posée");
        }
        // Le pas déjà consommé par une connexion précédente du même témoin est rendu (anti-rejeu).
        ad1_sql(st, &format!("UPDATE user_mfa SET last_step=-1 WHERE user='{AD1_PORTEUR_MFA}';"));
        let (_, defi) = ad1_reponse(mfa_challenge_response(st, AD1_PORTEUR_MFA, "admin")).await;
        let ticket = defi["ticket"].as_str().expect("fixture : ticket de défi").to_string();
        let code = hotp(&base32_decode(&graine).expect("graine base32"), (now() / 30) as u64, 6);
        let r = login_mfa_post(State(st.clone()), ConnectInfo(ad1_pair()), Json(json!({ "ticket": ticket, "code": code }))).await;
        let session = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let (statut, corps) = ad1_reponse(r).await;
        (statut, session, corps)
    }

    fn ad1_refuser_le_registre_des_connexions(st: &AppState) {
        ad1_sql(st, &format!("CREATE TRIGGER ad1_registre BEFORE INSERT ON ledger WHEN NEW.kind='login' BEGIN SELECT RAISE(ABORT,'{AD1_MOTEUR_REGISTRE}'); END;"));
    }

    fn ad1_connexions_attestees(st: &AppState) -> i64 {
        ad1_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='login'")
    }

    /// LE SECOND FACTEUR LOCAL, maillon refusé : la connexion n'est PAS annulée (200, session posée, corps d'avant sans
    /// clé ajoutée), rien au registre ; registre sain : une trace. La ligne de journal est jugée par
    /// `ad1_lignes_de_journal`.
    #[tokio::test]
    async fn ad1_maillon_de_connexion_refuse_n_annule_pas_la_connexion() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ad1_etat("mfa", Ad1Fournisseurs::Aucun);
        ad1_refuser_le_registre_des_connexions(&st);
        let (statut, session, corps) = ad1_connexion_mfa(&st).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true, "user": AD1_PORTEUR_MFA, "role": "admin" })), "connexion faite, corps d'avant");
        assert!(session, "la session est posée malgré le maillon manquant");
        assert_eq!(ad1_connexions_attestees(&st), 0, "le registre n'a rien pris");
        ad1_sql(&st, "DROP TRIGGER ad1_registre;");
        let (statut, session, _) = ad1_connexion_mfa(&st).await;
        assert!(statut == 200 && session, "registre sain : connexion faite");
        assert_eq!(ad1_connexions_attestees(&st), 1, "registre sain : une trace");
    }

    /// Le source de production de `handlers/idp.rs` (le module de témoins coupé).
    fn ad1_source_jugee() -> &'static str {
        let source = include_str!("../handlers/idp.rs");
        source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source)
    }

    /// CE QU'IL TIENT (lecture du source, faute d'IdP jouable) : aucune trace de connexion nue ne reste dans
    /// `handlers/idp.rs` ; les trois portes de fédération posent la leur par `tracer_la_connexion`, chacune dans le bras
    /// qui suit `federer_le_nom`, avec un SUJET (ce qui va au journal) ÉGAL à l'expression attendue — la porte et
    /// l'identifiant interne du fournisseur, rien d'autre : un sujet qui ajouterait l'identifiant connecté rougit ; le
    /// second facteur local aussi. Rouge sous `AD1_TRACE_OIDC`, `AD1_TRACE_SAML`, `AD1_TRACE_LDAP` (le site rendu au
    /// maillon nu d'avant) et `AD1_OIDC_FUITE`, `AD1_SAML_FUITE`, `AD1_LDAP_FUITE` (` pour {username}` / ` pour {user}`
    /// ajouté au sujet), tous posés dans le source jugé.
    #[test]
    fn ad1_les_quatre_traces_de_connexion_sont_lues() {
        let prod = ad1_source_jugee();
        assert!(!prod.contains("ledger_append(&conn, \"login\""), "une trace de connexion nue jette son maillon");
        assert_eq!(prod.matches("tracer_la_connexion(&conn, ").count(), 4, "quatre traces de connexion lues");
        let segments: Vec<&str> = prod.split("federer_le_nom(&st, &conn,").skip(1).collect();
        let portes = [
            ("OIDC", "&format!(\"connexion OIDC par le fournisseur #{}\", fournisseur.id)"),
            ("SAML", "&format!(\"connexion SAML par le fournisseur #{}\", fournisseur.id)"),
            ("LDAP", "&format!(\"connexion LDAP par le fournisseur #{fournisseur_id}\")"),
        ];
        assert_eq!(segments.len(), portes.len(), "instrument : trois appels à `federer_le_nom`");
        for (segment, (porte, sujet_attendu)) in segments.iter().zip(portes) {
            let bras = segment.split("Err(refus) => Some(refus)").next().unwrap_or("");
            let appel = bras.split_once("tracer_la_connexion(&conn, ").map(|(_, a)| a);
            let appel = appel.unwrap_or_else(|| panic!("la porte {porte} trace sa connexion par `tracer_la_connexion`"));
            let fin_du_sujet = format!(", &format!(\"login {porte} : ");
            let sujet = appel.split_once(&fin_du_sujet).map(|(s, _)| s);
            let sujet = sujet.unwrap_or_else(|| panic!("instrument : le détail `login {porte} : …` suit le sujet de la porte {porte}"));
            assert_eq!(sujet, sujet_attendu, "la porte {porte} : le sujet (journal) dit la porte et l'identifiant interne, rien d'autre");
            assert!(!bras.contains("ledger_append("), "la porte {porte} ne pose aucun maillon nu");
        }
        assert!(
            prod.contains("tracer_la_connexion(&conn, \"connexion locale à double authentification\", &detail)"),
            "le second facteur local trace sa connexion par `tracer_la_connexion`"
        );
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus. Fournisseur non lu : UNE ligne
    /// `[idp] WARN connexion <PORTE> refusée : … (<moteur>)` par appel, sans le nom demandé ; maillon de connexion refusé :
    /// UNE ligne `[idp] WARN connexion locale à double authentification ouverte : le registre n'a PAS pris le maillon
    /// `login` (<moteur>) …`, sans l'identifiant ni l'adresse ; écritures refusées du fournisseur : UNE ligne chacune avec
    /// l'identifiant interne et la cause du moteur ; le nominal, l'absence et le fournisseur lu n'en écrivent aucune.
    /// MUTATIONS : `AD1_LP_JOURNAL`, `AD1_TRACE_MFA`, `AD1_TRACE_JOURNAL`, `AD1_TEXTE_UPD_JOURNAL`, `AD1_TEXTE_DEL_JOURNAL`.
    #[tokio::test]
    async fn ad1_lignes_de_journal() {
        const ENFANT: &str = "AD1_ENFANT_JOURNAL";
        const PHASE: &str = "AD1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = ad1_etat("journal", Ad1Fournisseurs::Actifs);
            eprintln!("{PHASE}fournisseur");
            ad1_sql(&st, AD1_RENOMMER);
            let a = ad1_jouer(&st, "oidc_start").await.0;
            let b = ad1_jouer(&st, "ldap_premier").await.0;
            ad1_sql(&st, AD1_RENDRE);
            println!("AD1-STATUT-FOURNISSEUR:{a}:{b}");
            eprintln!("{PHASE}trace");
            ad1_refuser_le_registre_des_connexions(&st);
            println!("AD1-STATUT-TRACE:{}", ad1_connexion_mfa(&st).await.0);
            ad1_sql(&st, "DROP TRIGGER ad1_registre;");
            eprintln!("{PHASE}textes");
            let id = ad1_compte(&st, "SELECT id FROM idp_provider WHERE name='saml-ad1'");
            let (s, _) = ad1_modifier_et_supprimer(&st, id).await;
            println!("AD1-STATUT-TEXTES:{}:{}:{id}", s.0, s.1);
            eprintln!("{PHASE}calme");
            let (vide, _tv) = ad1_etat("journal-calme", Ad1Fournisseurs::Desactives);
            let c = ad1_jouer(&vide, "oidc_start").await.0;
            let d = ad1_jouer(&st, "oidc_start").await.0;
            let e = ad1_connexion_mfa(&st).await.0;
            println!("AD1-STATUT-CALME:{c}:{d}:{e}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::connexions_fournisseur_lu_et_trace_avouee::ad1_lignes_de_journal"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        assert_eq!(marque("AD1-STATUT-FOURNISSEUR:"), ["503", "503"], "contrôle : fournisseur non lu");
        assert_eq!(marque("AD1-STATUT-TRACE:"), ["200"], "contrôle : connexion faite malgré le maillon refusé");
        let textes = marque("AD1-STATUT-TEXTES:");
        assert_eq!(textes[..2], ["500", "500"], "contrôle : écritures refusées : {textes:?}");
        assert_eq!(marque("AD1-STATUT-CALME:"), ["404", "500", "200"], "contrôle : absent, lu, connexion tracée");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[idp] WARN")).map(str::to_string).collect()
        };
        let lignes = phase("fournisseur");
        assert_eq!(lignes.len(), 2, "phase fournisseur : une ligne par refus : {lignes:?}");
        for (ligne, porte) in lignes.iter().zip(["OIDC", "LDAP"]) {
            let tete = format!("[idp] WARN connexion {porte} refusée : le fournisseur de connexion n'a pas pu être lu (");
            assert!(ligne.starts_with(&tete) && ligne.contains("no such table"), "phase fournisseur : porte et cause du moteur : {ligne}");
            assert!(!ligne.contains("-ad1") && !ligne.contains("alice"), "phase fournisseur : ni le nom demandé ni l'identifiant : {ligne}");
        }
        let lignes = phase("trace");
        assert_eq!(
            lignes,
            [format!("[idp] WARN connexion locale à double authentification ouverte : le registre n'a PAS pris le maillon `login` ({AD1_MOTEUR_REGISTRE}) — la connexion n'est pas annulée")],
            "phase trace : sujet et cause du moteur, ni l'identifiant ni l'adresse"
        );
        let lignes = phase("textes");
        let id = &textes[2];
        assert_eq!(
            lignes,
            [
                format!("[idp] WARN modification du fournisseur d'identité #{id} non écrite, transaction annulée : {AD1_MOTEUR_ECRITURE}"),
                format!("[idp] WARN suppression du fournisseur d'identité #{id} non écrite, transaction annulée : {AD1_MOTEUR_ECRITURE}"),
            ],
            "phase textes : identifiant interne et cause du moteur"
        );
        assert!(phase("calme").is_empty(), "l'absence, le fournisseur lu et la connexion tracée n'écrivent aucune ligne : {:?}", phase("calme"));
        // Le second facteur local s'est joué deux fois (maillon refusé, puis tracé) : l'identifiant connecté n'apparaît
        // NULLE PART dans la sortie de l'enfant, quel que soit le canal ou le préfixe de la ligne.
        for (canal, texte) in [("stdout", &stdout), ("stderr", &stderr)] {
            assert!(!texte.contains(AD1_PORTEUR_MFA), "{canal} de l'enfant : l'identifiant connecté n'est jamais écrit : {texte}");
        }
    }
}
