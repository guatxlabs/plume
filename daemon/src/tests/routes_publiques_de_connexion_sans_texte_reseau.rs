// =====================================================================================
// `P10.29-l` (reste AD : 5xx d'`oidc_callback`, `oidc_start`, `saml_start` et `saml_metadata`) et `P10.31-u` (reste :
// lignes `[mfa] WARN` qui nommaient le compte).
//
// LE DÉFAUT, MESURÉ SUR 536bda8a AVANT LE CORRECTIF.
//   * Routes PUBLIQUES (pré-authentification) de `handlers/idp.rs` : huit corps servaient un texte variable —
//     `découverte OIDC échouée: {e}` (deux fois, 502), `échange de code échoué: {e}` (502), `JWKS indisponible: {e}` (502),
//     `id_token invalide: {e}` (401), `échec de l'AuthnRequest SAML: {e}` (500), `génération métadonnée SP échouée: {e}`
//     (500), où `{e}` est le texte de `ssrf_guard`/`http_call`/`fetch_json` (hôte et port de l'IdP, motif du refus SSRF,
//     délai dépassé), de la validation du jeton ou de la construction SAML : un appelant non authentifié lisait la
//     joignabilité et la politique de sortie du serveur. `l'IdP a refusé l'authentification: {e}` (401) reflétait le
//     paramètre `error` de la requête, texte libre.
//   * Huit lignes `[mfa] WARN` (statut, enrôlement, activation lue et écrite, désactivation lue, relue et validée,
//     connexion) nommaient le compte.
//
// LE CORRECTIF (décision par défaut de la vague AF). Une phrase FIXE par étape (`PHRASE_*`, préfixes d'avant gardés),
// statuts 502/401/500 inchangés ; la cause va au journal seul par `servir_l_echec_de_l_etape` : geste, identifiant
// INTERNE du fournisseur, étape, et la NATURE de l'échec (`nature_de_l_echec` : le libellé fixe avant le premier `:`,
// une phrase propre pour `connexion <hôte>:<port>`), sous l'identifiant de corrélation servi pour un 5xx. Le paramètre
// `error` n'est ni servi ni journalisé. Les huit lignes `[mfa] WARN` disent `compte #<user.id>` (`compte_au_journal`,
// lecture pour le journal seul : « sans ligne `user` » ou « identifiant non lu » quand elle ne rend pas d'identifiant).
//
// LES PANNES ÉPROUVÉES : cibles OIDC refusées par la garde SSRF sans aucun levier (`[fd00::7]`, ULA, toujours hors
// sortie) ou endpoints non https (aucun appel réseau n'est tenté) ; table `user_mfa` renommée ; colonne lue en BLOB ;
// déclencheurs `RAISE(ABORT)` sur `user_mfa` ; `COMMIT` et lecture de `user.id` refusés par un autorisateur SQLite.
// Lignes de journal et toute la sortie lues sur un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit). Textes : `AF1_T708`, `AF1_T770`,
// `AF1_T781`, `AF1_T740` (texte d'avant servi), `AF1_S798`, `AF1_S803`, `AF1_S869`, `AF1_S983` (site rendu à sa forme
// d'avant dans le source jugé). Journaux : `AF1_J708`, `AF1_J770`, `AF1_J781` (phrase fixe sans ligne de journal),
// `AF1_SJ798`, `AF1_SJ803`, `AF1_SJ869`, `AF1_SJ983` (idem, dans le source jugé), `AF1_740_JOURNAL` (paramètre
// journalisé), `AF1_CORRELATION_ABSENTE`, `AF1_NATURE_ENTIERE`, `AF1_NATURE_SANS_TRIM`, `AF1_NATURE_CONNEXION` ;
// `AF1_M1167`, `AF1_M1266`, `AF1_M1298`, `AF1_M1366`, `AF1_M1411`, `AF1_M1455`, `AF1_M1464`, `AF1_M1719` (la ligne
// d'avant, qui nomme le compte, écrite au site) ; `AF1_COMPTE_SANS_LIGNE_NOM`, `AF1_COMPTE_NON_LU_NOM`. Bras ajoutés
// avant l'appel aux quatre sites lus dans le source (relevés par la vérification indépendante) : `V847A`, `V847B`
// (cause resservie avant le JWKS), `V852A` (cause resservie), `V852B` (401 changé en 502), `V918A`, `V918B`, `V1032A`,
// `V1032B` (idem pour l'AuthnRequest et la métadonnée SP, 500 changé en 502) — rouges sous les deux témoins de bloc.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : `JWKS indisponible` et `id_token invalide` exigent un point de jeton https qui
// réponde, et les deux sites SAML ne sont atteignables qu'avec la feature `saml` (éteinte : la construction rend
// toujours « non compilé », servi en 501) — ces quatre sites sont tenus par LECTURE DU SOURCE (appel exact dans la
// bonne fonction, forme d'avant absente, `match` comparé EN ENTIER, aucune cause passée à un constructeur de réponse
// dans les quatre routes hors bras « non compilé »), et le constructeur commun est joué directement. Les jouer
// réellement est hors de portée du témoin : le JWKS et l'`id_token` ne viennent qu'après un échange de code réussi
// (2xx portant un `id_token`), or les endpoints sont exigés en https et la garde SSRF refuse toute adresse locale ou
// privée sans `PLUME_SSRF_ALLOW`, levier que ce témoin n'écrit pas — aucun point de jeton joignable ne peut être servi ; la nature d'une erreur
// `connexion <hôte>:<port>` n'est jouée que par le constructeur (aucune connexion TCP n'est tentée) ; le délai de
// réponse, qui distingue encore un port fermé d'un hôte muet, n'est pas changé (hors décision) ; l'écran de la console
// (aucun module de `web/` n'appelle ces routes par `fetch`).
// =====================================================================================
mod routes_publiques_de_connexion_sans_texte_reseau {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Le compte porteur du second facteur : un nom qu'aucune autre sortie du témoin ne porte.
    const AF1_PORTEUR: &str = "af1porteur";
    /// Un compte servi sans ligne `user`.
    const AF1_SANS_LIGNE: &str = "af1sansligne";
    const AF1_PASSE: &str = "motdepasse12345";
    const AF1_GRAINE: &[u8] = b"12345678901234567890";
    /// Le paramètre `error` soumis au callback : ni servi ni journalisé.
    const AF1_PARAM_SOUMIS: &str = "access_denied af1-param-soumis [fd00::7] <b>x</b>";
    const AF1_MOTEUR_GRAINE: &str = "af1 graine refusee";
    const AF1_MOTEUR_ACTIVATION: &str = "af1 activation refusee";
    const AF1_REDIRECT: &str = "https://plume.af1.example/cb";

    /// Fournisseurs OIDC : découverte vers une cible refusée par la garde SSRF ; endpoints explicites dont l'un n'est
    /// pas https ; endpoints explicites https dont le point de jeton est refusé par la garde SSRF.
    fn af1_fournisseurs() -> [(&'static str, String); 3] {
        [
            ("af1-decouverte", format!(r#"{{"issuer":"http://[fd00::7]:9","client_id":"af1","redirect_uri":"{AF1_REDIRECT}"}}"#)),
            (
                "af1-https",
                format!(
                    r#"{{"issuer":"https://idp.af1.example","client_id":"af1","redirect_uri":"{AF1_REDIRECT}","authorization_endpoint":"http://198.51.100.7/auth","token_endpoint":"https://198.51.100.7/token","jwks_uri":"https://198.51.100.7/jwks"}}"#
                ),
            ),
            (
                "af1-jeton",
                format!(
                    r#"{{"issuer":"https://idp.af1.example","client_id":"af1","redirect_uri":"{AF1_REDIRECT}","authorization_endpoint":"https://198.51.100.7/auth","token_endpoint":"https://[fd00::7]/token","jwks_uri":"https://198.51.100.7/jwks"}}"#
                ),
            ),
        ]
    }

    fn af1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn af1_id(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn af1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn af1_pair() -> std::net::SocketAddr {
        "192.0.2.10:45454".parse().expect("adresse de test")
    }

    /// L'état d'un témoin : les trois fournisseurs OIDC actifs, et le compte porteur (admin, mot de passe local).
    fn af1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("af1-{tag}"));
        {
            let conn = st.db.lock();
            for (nom, cfg) in af1_fournisseurs() {
                conn.execute(
                    "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,'oidc',1,?2,'s',1,1)",
                    params![nom, cfg],
                )
                .expect("fixture : fournisseur posé");
            }
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin')", params![AF1_PORTEUR, hash_pw(AF1_PASSE).unwrap()])
                .expect("fixture : compte posé");
        }
        (st, p)
    }

    async fn af1_start(st: &AppState, fournisseur: &str) -> (u16, Value) {
        af1_reponse(oidc_start(State(st.clone()), axum::extract::Path(fournisseur.to_string())).await).await
    }

    async fn af1_callback(st: &AppState, fournisseur: &str, erreur: Option<&str>) -> (u16, Value) {
        let blob = oidc_state_sign(st.session_secret.as_slice(), fournisseur, "etat-af1", "nonce-af1", "verif-af1", 600);
        let mut entetes = axum::http::HeaderMap::new();
        entetes.insert(header::COOKIE, format!("plume_oidc={blob}").parse().expect("en-tête"));
        let mut q: HashMap<String, String> = [("state", "etat-af1"), ("code", "code-af1")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        if let Some(e) = erreur {
            q.insert("error".to_string(), e.to_string());
        }
        af1_reponse(oidc_callback(State(st.clone()), axum::http::Extensions::new(), entetes, Query(q)).await).await
    }

    /// Un 5xx d'étape : EXACTEMENT les clés `error` et `id`, la phrase fixe, l'identifiant de corrélation.
    fn af1_juger_5xx(quoi: &str, corps: &Value, phrase: &str) {
        let cles: Vec<&str> = corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(phrase), "{quoi} : la phrase fixe : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
    }

    /// Ni l'hôte, ni la plage, ni le motif SSRF, ni un schéma d'URL, ni le paramètre soumis dans une sortie.
    fn af1_sans_destination(quoi: &str, texte: &str) {
        for interdit in ["fd00", "198.51.100", "SSRF", "http", "idp.af1.example", "af1-param-soumis"] {
            assert!(!texte.contains(interdit), "{quoi} : `{interdit}` ne sort pas : {texte}");
        }
    }

    /// LES TROIS SITES OIDC JOUABLES SANS RÉSEAU, corps ENTIER : découverte de `oidc_start` et d'`oidc_callback` (cible
    /// refusée par la garde SSRF, puis endpoint non https : la MÊME phrase pour deux causes), échange de code du callback
    /// (point de jeton refusé par la garde SSRF) ; statut 502 inchangé. Contrôle : le fournisseur aux endpoints https
    /// redirige (302). Rouge sous `AF1_T708`, `AF1_T770`, `AF1_T781`.
    #[tokio::test]
    async fn af1_etapes_oidc_servent_une_phrase_fixe() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _p) = af1_etat("etapes");
        let cas: [(&str, &str, &str); 5] = [
            ("oidc_start", "af1-decouverte", PHRASE_DECOUVERTE_OIDC_ECHOUEE),
            ("oidc_start", "af1-https", PHRASE_DECOUVERTE_OIDC_ECHOUEE),
            ("oidc_callback", "af1-decouverte", PHRASE_DECOUVERTE_OIDC_ECHOUEE),
            ("oidc_callback", "af1-https", PHRASE_DECOUVERTE_OIDC_ECHOUEE),
            ("oidc_callback", "af1-jeton", PHRASE_ECHANGE_DE_CODE_ECHOUE),
        ];
        assert!(cas.len() >= 5, "plancher : cinq cas");
        for (route, fournisseur, phrase) in cas {
            let (statut, corps) = if route == "oidc_start" { af1_start(&st, fournisseur).await } else { af1_callback(&st, fournisseur, None).await };
            let quoi = format!("{route} {fournisseur}");
            assert_eq!(statut, 502, "{quoi} : statut d'avant : {corps}");
            af1_juger_5xx(&quoi, &corps, phrase);
            af1_sans_destination(&quoi, &corps.to_string());
        }
        let (statut, corps) = af1_start(&st, "af1-jeton").await;
        assert_eq!(statut, 302, "contrôle : endpoints https sans découverte, la redirection d'avant : {corps}");
    }

    /// LE PARAMÈTRE `error` DE L'IdP n'est pas reflété : 401 d'avant, corps EXACT, phrase fixe. Rouge sous `AF1_T740`.
    #[tokio::test]
    async fn af1_parametre_error_de_l_idp_non_reflete() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = af1_etat("erreur");
        let (statut, corps) = af1_callback(&st, "af1-jeton", Some(AF1_PARAM_SOUMIS)).await;
        assert_eq!((statut, corps), (401, json!({ "error": PHRASE_IDP_A_REFUSE_L_AUTHENTIFICATION })), "phrase fixe, rien de la requête");
    }

    /// LE CONSTRUCTEUR COMMUN, corps ENTIER : un 4xx sert `{error}` seul (pas d'identifiant), un 5xx `{error, id}` ; le
    /// statut passé est celui servi.
    #[tokio::test]
    async fn af1_constructeur_de_l_etape_sert_le_statut_et_la_phrase() {
        let (statut, corps) = af1_reponse(servir_l_echec_de_l_etape(
            StatusCode::UNAUTHORIZED,
            PHRASE_ID_TOKEN_INVALIDE,
            "connexion OIDC",
            41,
            "id_token",
            "validation JWT échouée: InvalidIssuer af1-revendication",
        ))
        .await;
        assert_eq!((statut, corps), (401, json!({ "error": PHRASE_ID_TOKEN_INVALIDE })), "4xx : la phrase seule");
        let cas: [(StatusCode, &str); 4] = [
            (StatusCode::BAD_GATEWAY, PHRASE_JWKS_INDISPONIBLE),
            (StatusCode::INTERNAL_SERVER_ERROR, PHRASE_AUTHNREQUEST_SAML_ECHOUEE),
            (StatusCode::INTERNAL_SERVER_ERROR, PHRASE_METADONNEE_SP_ECHOUEE),
            (StatusCode::BAD_GATEWAY, PHRASE_DECOUVERTE_OIDC_ECHOUEE),
        ];
        assert!(cas.len() >= 4, "plancher : quatre cas");
        for (code, phrase) in cas {
            let (statut, corps) = af1_reponse(servir_l_echec_de_l_etape(code, phrase, "connexion SAML", 42, "AuthnRequest", "acs_url: https://198.51.100.7/acs")).await;
            assert_eq!(statut, code.as_u16(), "statut passé, statut servi : {corps}");
            af1_juger_5xx(phrase, &corps, phrase);
            af1_sans_destination(phrase, &corps.to_string());
        }
    }

    /// LA NATURE D'UN ÉCHEC, sans sa partie variable, comparée en entier. Rouge sous `AF1_NATURE_ENTIERE`,
    /// `AF1_NATURE_SANS_TRIM`, `AF1_NATURE_CONNEXION`.
    #[test]
    fn af1_nature_de_l_echec_sans_destination() {
        let connexion = "connexion TCP impossible (refusée, injoignable ou délai dépassé)";
        let cas: [(&str, &str); 9] = [
            ("SSRF: cible interne interdite (fd00::7)", "SSRF"),
            ("SSRF: résolution de 'idp.af1.example' impossible (deny): failed to lookup", "SSRF"),
            ("connexion 198.51.100.7:443 : Connection refused (os error 111)", connexion),
            ("connexion [fd00::7]:443 : Connection timed out (os error 110)", connexion),
            ("HTTP 404 (discovery/jwks)", "HTTP 404 (discovery/jwks)"),
            ("nom TLS invalide : idp.af1.example", "nom TLS invalide"),
            ("endpoint OIDC non-https refusé", "endpoint OIDC non-https refusé"),
            ("validation JWT échouée: InvalidIssuer af1-revendication", "validation JWT échouée"),
            ("acs_url: https://198.51.100.7/acs", "acs_url"),
        ];
        assert!(cas.len() >= 9, "plancher : neuf cas");
        for (detail, attendu) in cas {
            assert_eq!(nature_de_l_echec(detail), attendu, "nature de « {detail} »");
        }
    }

    /// Les quatre sites que le témoin ne peut pas jouer : (site, appel attendu, forme d'avant — celle des mutants
    /// `AF1_S*` —, forme sans ligne de journal — celle des mutants `AF1_SJ*` —, fonction qui le porte).
    const AF1_SITES_DU_SOURCE: [(&str, &str, &str, &str, &str); 4] = [
        (
            "798",
            "Ok(Err(e)) => return servir_l_echec_de_l_etape(StatusCode::BAD_GATEWAY, PHRASE_JWKS_INDISPONIBLE, \"connexion OIDC\", fournisseur.id, \"JWKS\", &e),",
            "Ok(Err(e)) => return err_json(StatusCode::BAD_GATEWAY, format!(\"JWKS indisponible: {e}\")),",
            "Ok(Err(_)) => return err_json(StatusCode::BAD_GATEWAY, PHRASE_JWKS_INDISPONIBLE),",
            "pub(crate) async fn oidc_callback(",
        ),
        (
            "803",
            "Err(e) => return servir_l_echec_de_l_etape(StatusCode::UNAUTHORIZED, PHRASE_ID_TOKEN_INVALIDE, \"connexion OIDC\", fournisseur.id, \"id_token\", &e),",
            "Err(e) => return err_json(StatusCode::UNAUTHORIZED, format!(\"id_token invalide: {e}\")),",
            "Err(_) => return err_json(StatusCode::UNAUTHORIZED, PHRASE_ID_TOKEN_INVALIDE),",
            "pub(crate) async fn oidc_callback(",
        ),
        (
            "869",
            "Err(e) => return servir_l_echec_de_l_etape(StatusCode::INTERNAL_SERVER_ERROR, PHRASE_AUTHNREQUEST_SAML_ECHOUEE, \"connexion SAML\", fournisseur.id, \"AuthnRequest\", &e),",
            "Err(e) => return server_err(format!(\"échec de l'AuthnRequest SAML: {e}\")),",
            "Err(_) => return server_err(PHRASE_AUTHNREQUEST_SAML_ECHOUEE),",
            "pub(crate) async fn saml_start(",
        ),
        (
            "983",
            "Err(e) => servir_l_echec_de_l_etape(StatusCode::INTERNAL_SERVER_ERROR, PHRASE_METADONNEE_SP_ECHOUEE, \"métadonnée SP SAML\", fournisseur.id, \"génération\", &e),",
            "Err(e) => server_err(format!(\"génération métadonnée SP échouée: {e}\")),",
            "Err(_) => server_err(PHRASE_METADONNEE_SP_ECHOUEE),",
            "pub(crate) async fn saml_metadata(",
        ),
    ];

    /// Le source de production de `handlers/idp.rs` (le module de témoins coupé).
    fn af1_source_jugee() -> String {
        let source = include_str!("../handlers/idp.rs");
        source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source).to_string()
    }

    /// Le corps d'une fonction du source jugé : de son en-tête à la première accolade fermante en colonne zéro.
    fn af1_corps_de<'a>(prod: &'a str, entete: &str) -> &'a str {
        let debut = prod.find(entete).unwrap_or_else(|| panic!("instrument : `{entete}` dans le source"));
        let reste = &prod[debut..];
        &reste[..reste.find("\n}\n").unwrap_or(reste.len())]
    }

    /// CE QU'IL TIENT (lecture du source, faute de point de jeton https joignable et de la feature `saml`) : chacun des
    /// quatre sites appelle `servir_l_echec_de_l_etape` avec sa phrase, son statut d'avant, son geste et son étape,
    /// UNE fois, dans la fonction qui le porte ; la forme d'avant n'existe plus nulle part. Rouge sous `AF1_S798`,
    /// `AF1_S803`, `AF1_S869`, `AF1_S983` (forme d'avant) et `AF1_SJ798`, `AF1_SJ803`, `AF1_SJ869`, `AF1_SJ983` (phrase
    /// fixe sans ligne de journal), posés dans le source jugé.
    #[test]
    fn af1_sites_hors_d_atteinte_tenus_par_le_source() {
        let prod = af1_source_jugee();
        assert!(AF1_SITES_DU_SOURCE.len() >= 4, "plancher : quatre sites");
        for (site, attendu, ancien, _, fonction) in AF1_SITES_DU_SOURCE {
            assert_eq!(af1_corps_de(&prod, fonction).matches(attendu).count(), 1, "site {site} : l'appel attendu dans `{fonction}`");
            assert_eq!(prod.matches(attendu).count(), 1, "site {site} : un seul appel de cette forme");
            assert!(!prod.contains(ancien), "site {site} : la forme d'avant (texte variable servi) a disparu");
        }
    }

    /// Les mêmes quatre sites, `match` ENTIER (de la ligne qui porte `match` à l'accolade fermante en indentation de
    /// fonction), espaces normalisés : (site, fonction qui le porte, bloc attendu). Un bras ajouté, retiré ou réordonné,
    /// un statut changé ou une cause resservie le fait différer.
    const AF1_BLOCS_DU_SOURCE: [(&str, &str, &str); 4] = [
        (
            "798",
            "pub(crate) async fn oidc_callback(",
            "let jwks = match tokio::task::spawn_blocking(move || jwks_du_fournisseur(&cfg_jwks, &jwks_url)).await {
                Ok(Ok(j)) => j,
                Ok(Err(e)) => return servir_l_echec_de_l_etape(StatusCode::BAD_GATEWAY, PHRASE_JWKS_INDISPONIBLE, \"connexion OIDC\", fournisseur.id, \"JWKS\", &e),
                Err(_) => return server_err(\"échec interne (jwks)\"),
            };",
        ),
        (
            "803",
            "pub(crate) async fn oidc_callback(",
            "let claims = match oidc_validate_id_token(id_token, &jwks, &cfg.issuer, &cfg.client_id, &nonce) {
                Ok(c) => c,
                Err(e) => return servir_l_echec_de_l_etape(StatusCode::UNAUTHORIZED, PHRASE_ID_TOKEN_INVALIDE, \"connexion OIDC\", fournisseur.id, \"id_token\", &e),
            };",
        ),
        (
            "869",
            "pub(crate) async fn saml_start(",
            "let (url, blob) = match saml_build_authn_redirect(&cfg, &name, &fournisseur.secret, st.session_secret.as_slice()) {
                Ok(v) => v,
                Err(e) if e.contains(\"non compilé\") => return err_json(StatusCode::NOT_IMPLEMENTED, e),
                Err(e) => return servir_l_echec_de_l_etape(StatusCode::INTERNAL_SERVER_ERROR, PHRASE_AUTHNREQUEST_SAML_ECHOUEE, \"connexion SAML\", fournisseur.id, \"AuthnRequest\", &e),
            };",
        ),
        (
            "983",
            "pub(crate) async fn saml_metadata(",
            "match saml_sp_metadata_xml(&cfg) {
                Ok(xml) => ([(header::CONTENT_TYPE, \"application/samlmetadata+xml\")], xml).into_response(),
                Err(e) if e.contains(\"non compilé\") => err_json(StatusCode::NOT_IMPLEMENTED, e),
                Err(e) => servir_l_echec_de_l_etape(StatusCode::INTERNAL_SERVER_ERROR, PHRASE_METADONNEE_SP_ECHOUEE, \"métadonnée SP SAML\", fournisseur.id, \"génération\", &e),
            }",
        ),
    ];

    fn af1_espaces_normalises(texte: &str) -> String {
        texte.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Le `match` dont la première ligne commence par `ancre` dans `corps` : de cette ligne à la première ligne `    };`
    /// ou `    }` (indentation de fonction) qui la suit, inclusivement.
    fn af1_bloc_du_match(corps: &str, ancre: &str) -> String {
        assert_eq!(corps.matches(ancre).count(), 1, "instrument : ancre `{ancre}` une fois dans le corps");
        let pos = corps.find(ancre).unwrap_or_else(|| panic!("instrument : ancre `{ancre}` absente du corps"));
        let debut = corps[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let mut fin = corps.len();
        let mut curseur = pos;
        for ligne in corps[pos..].split_inclusive('\n') {
            let nette = ligne.trim_end();
            curseur += ligne.len();
            if nette == "    };" || nette == "    }" {
                fin = curseur;
                break;
            }
        }
        af1_espaces_normalises(&corps[debut..fin])
    }

    /// CE QU'IL TIENT : le `match` de chacun des quatre sites hors d'atteinte est, en entier, celui attendu — aucun bras
    /// ajouté avant l'appel (qui resservirait la cause ou changerait 401/500 en 502), aucun bras retiré.
    #[test]
    fn af1_blocs_des_sites_hors_d_atteinte_compares_en_entier() {
        let prod = af1_source_jugee();
        assert!(AF1_BLOCS_DU_SOURCE.len() >= 4, "plancher : quatre blocs");
        for (site, fonction, attendu) in AF1_BLOCS_DU_SOURCE {
            let attendu = af1_espaces_normalises(attendu);
            let ancre = attendu.lines().next().unwrap_or("");
            let ancre = &ancre[..ancre.find(" {").map(|i| i + 2).unwrap_or(ancre.len())];
            let corps = af1_corps_de(&prod, fonction);
            assert_eq!(af1_bloc_du_match(corps, ancre), attendu, "site {site} : le `match` entier dans `{fonction}`");
        }
    }

    /// CE QU'IL TIENT : dans les quatre routes publiques qui portent ces sites, aucune cause n'est interpolée ni passée
    /// à un constructeur de réponse — seuls les bras « non compilé » (texte fixe de la build, servi en 501) passent `e`.
    #[test]
    fn af1_routes_publiques_sans_cause_interpolee() {
        let prod = af1_source_jugee();
        let fonctions = [
            "pub(crate) async fn oidc_start(",
            "pub(crate) async fn oidc_callback(",
            "pub(crate) async fn saml_start(",
            "pub(crate) async fn saml_metadata(",
        ];
        let constructeurs = ["err_json(", "server_err(", "bad_req(", "not_found(", "forbidden(", "format!("];
        let causes = ["{e}", "{e:", "{e.", ", e)", ", &e)", "e.to_string()", "&e.", "+ &e"];
        let mut bras_non_compile = 0;
        for fonction in fonctions {
            let corps = af1_corps_de(&prod, fonction);
            assert!(!corps.contains("{e}") && !corps.contains("{e:"), "`{fonction}` : une cause interpolée");
            for ligne in corps.lines() {
                let nette = ligne.trim();
                if nette.starts_with("Err(e) if e.contains(\"non compilé\") =>") && nette.ends_with("err_json(StatusCode::NOT_IMPLEMENTED, e),") {
                    bras_non_compile += 1;
                    continue;
                }
                if constructeurs.iter().any(|c| nette.contains(c)) {
                    for cause in causes {
                        assert!(!nette.contains(cause), "`{fonction}` : cause `{cause}` passée à un constructeur de réponse : {nette}");
                    }
                }
            }
        }
        assert_eq!(bras_non_compile, 2, "les deux bras « non compilé » (saml_start, saml_metadata), seuls à passer `e`");
    }

    /// `COMMIT` (et `END`) refusés sur l'écrivain partagé ; `BEGIN` et `ROLLBACK` restent permis.
    fn af1_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// La lecture de `user.id` refusée : l'identifiant du compte n'est pas lu.
    fn af1_refuser_l_identifiant(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "user", column_name: "id" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn af1_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La cause que le moteur rend à une lecture, rejouée telle quelle (pour comparer la ligne de journal ENTIÈRE).
    fn af1_cause_de_lecture(st: &AppState, sql: &str, colonnes: usize) -> String {
        let conn = st.db.lock();
        let r = conn.query_row(sql, params![AF1_PORTEUR], |r| {
            for i in 0..colonnes {
                r.get::<_, String>(i)?;
            }
            Ok(())
        });
        r.expect_err("fixture : la lecture rejouée échoue").to_string()
    }

    fn af1_code(st: &AppState) -> String {
        let graine = base32_encode(AF1_GRAINE);
        af1_sql(st, &format!("DELETE FROM user_mfa WHERE user='{AF1_PORTEUR}';"));
        st.db
            .lock()
            .execute("INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,1,'[]',-1,0,0)", params![AF1_PORTEUR, graine])
            .expect("fixture : MFA posée");
        hotp(&base32_decode(&graine).expect("graine base32"), (now() / 30) as u64, 6)
    }

    async fn af1_activer(st: &AppState, qui: &str, code: &str) -> u16 {
        af1_reponse(mfa_verify(State(st.clone()), ConnectInfo(af1_pair()), Extension(sp_au(qui, "admin")), Json(json!({ "code": code }))).await).await.0
    }

    async fn af1_desactiver(st: &AppState, code: &str) -> u16 {
        af1_reponse(mfa_disable(State(st.clone()), ConnectInfo(af1_pair()), Extension(sp_au(AF1_PORTEUR, "admin")), Json(json!({ "code": code }))).await).await.0
    }

    const AF1_RENOMMER_MFA: &str = "ALTER TABLE user_mfa RENAME TO user_mfa_hors_d_atteinte;";
    const AF1_RENDRE_MFA: &str = "ALTER TABLE user_mfa_hors_d_atteinte RENAME TO user_mfa;";

    /// Joue les huit sites `[mfa] WARN` et les deux issues de `compte_au_journal` sans identifiant ; rend les statuts
    /// servis (contrôles) et les causes du moteur rejouées, dans l'ordre des lignes attendues.
    async fn af1_jouer_les_sites_mfa(st: &AppState) -> (Vec<u16>, Vec<String>) {
        let au = sp_au(AF1_PORTEUR, "admin");
        let mut statuts = Vec::new();
        let mut causes = Vec::new();
        // 1167 — statut : `user.hash` illisible (BLOB), `user.id` lisible.
        af1_sql(st, &format!("UPDATE user SET hash=x'00' WHERE name='{AF1_PORTEUR}';"));
        statuts.push(af1_reponse(mfa_status(State(st.clone()), Extension(au.clone())).await).await.0);
        causes.push(af1_cause_de_lecture(st, "SELECT hash FROM user WHERE name=?1", 1));
        st.db.lock().execute("UPDATE user SET hash=?1 WHERE name=?2", params![hash_pw(AF1_PASSE).unwrap(), AF1_PORTEUR]).expect("fixture : hash rendu");
        // 1266 — enrôlement : l'INSERT de la graine refusé.
        af1_sql(st, &format!("CREATE TRIGGER af1_graine BEFORE INSERT ON user_mfa BEGIN SELECT RAISE(ABORT,'{AF1_MOTEUR_GRAINE}'); END;"));
        let r = mfa_enroll(State(st.clone()), ConnectInfo(af1_pair()), Extension(au.clone()), Json(json!({ "password": AF1_PASSE }))).await;
        statuts.push(af1_reponse(r).await.0);
        causes.push(AF1_MOTEUR_GRAINE.to_string());
        af1_sql(st, "DROP TRIGGER af1_graine;");
        // 1298 — activation : `user_mfa` hors d'atteinte ; le porteur, puis un compte sans ligne `user`, puis le porteur
        // dont l'identifiant n'est pas lu.
        af1_sql(st, AF1_RENOMMER_MFA);
        let cause_1298 = af1_cause_de_lecture(st, "SELECT secret,enabled,last_step FROM user_mfa WHERE user=?1", 1);
        statuts.push(af1_activer(st, AF1_PORTEUR, "123456").await);
        statuts.push(af1_activer(st, AF1_SANS_LIGNE, "123456").await);
        af1_refuser_l_identifiant(st);
        statuts.push(af1_activer(st, AF1_PORTEUR, "123456").await);
        af1_lever_l_autorisateur(st);
        causes.extend([cause_1298.clone(), cause_1298.clone(), cause_1298]);
        // 1411 — désactivation : `user_mfa` hors d'atteinte.
        causes.push(af1_cause_de_lecture(st, "SELECT enabled FROM user_mfa WHERE user=?1", 1));
        statuts.push(af1_desactiver(st, "123456").await);
        // 1719 — connexion : ticket émis, puis `user_mfa` hors d'atteinte.
        af1_sql(st, AF1_RENDRE_MFA);
        af1_code(st);
        let (_, defi) = af1_reponse(mfa_challenge_response(st, AF1_PORTEUR, "admin")).await;
        let ticket = defi["ticket"].as_str().expect("fixture : ticket de défi").to_string();
        af1_sql(st, AF1_RENOMMER_MFA);
        causes.push(af1_cause_de_lecture(st, "SELECT secret,last_step FROM user_mfa WHERE user=?1 AND enabled=1", 1));
        let r = login_mfa_post(State(st.clone()), ConnectInfo(af1_pair()), Json(json!({ "ticket": ticket, "code": "123456" }))).await;
        statuts.push(af1_reponse(r).await.0);
        af1_sql(st, AF1_RENDRE_MFA);
        // 1366 — activation : enrôlement en attente, code juste, l'UPDATE refusé.
        let code = af1_code(st);
        af1_sql(st, &format!("UPDATE user_mfa SET enabled=0 WHERE user='{AF1_PORTEUR}';"));
        af1_sql(st, &format!("CREATE TRIGGER af1_activation BEFORE UPDATE ON user_mfa BEGIN SELECT RAISE(ABORT,'{AF1_MOTEUR_ACTIVATION}'); END;"));
        statuts.push(af1_activer(st, AF1_PORTEUR, &code).await);
        causes.push(AF1_MOTEUR_ACTIVATION.to_string());
        af1_sql(st, "DROP TRIGGER af1_activation;");
        // 1455 — désactivation : MFA active, `secret` illisible (BLOB) à la relecture dans la transaction.
        af1_code(st);
        af1_sql(st, &format!("UPDATE user_mfa SET secret=x'FF' WHERE user='{AF1_PORTEUR}';"));
        statuts.push(af1_desactiver(st, "123456").await);
        causes.push(af1_cause_de_lecture(st, "SELECT secret,enabled,recovery FROM user_mfa WHERE user=?1", 1));
        // 1464 — désactivation : code juste, `COMMIT` refusé. Le frein du compte est éteint pour ce geste (sa réservation
        // passe par une transaction validée, que l'autorisateur refuserait avant le site jugé).
        let code = af1_code(st);
        let mut sans_frein = st.clone();
        sans_frein.lock_threshold = 0;
        af1_refuser_le_commit(st);
        statuts.push(af1_desactiver(&sans_frein, &code).await);
        let cause_commit = {
            let conn = st.db.lock();
            conn.execute_batch("BEGIN").expect("fixture : BEGIN permis");
            let e = conn.execute_batch("COMMIT").expect_err("fixture : COMMIT refusé").to_string();
            conn.execute_batch("ROLLBACK").expect("fixture : ROLLBACK permis");
            e
        };
        af1_lever_l_autorisateur(st);
        causes.push(cause_commit);
        (statuts, causes)
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus, chacune ENTIÈRE. OIDC : une ligne par étape échouée
    /// (identifiant de corrélation du corps servi, identifiant interne du fournisseur, étape, nature), sans hôte ni motif ;
    /// constructeur : 4xx sans identifiant, nature d'une connexion TCP sans hôte ; paramètre `error` : aucune ligne ;
    /// second facteur : les huit sites disent `compte #<id>`, un compte sans ligne `user` et un identifiant non lu sont
    /// dits tels quels ; le nominal n'écrit rien ; le nom du compte, les hôtes et le paramètre soumis n'apparaissent
    /// NULLE PART dans la sortie. MUTATIONS : `AF1_J708`, `AF1_J770`, `AF1_J781`, `AF1_740_JOURNAL`,
    /// `AF1_CORRELATION_ABSENTE`, `AF1_NATURE_ENTIERE`, `AF1_NATURE_CONNEXION`, `AF1_M*`, `AF1_COMPTE_SANS_LIGNE_NOM`,
    /// `AF1_COMPTE_NON_LU_NOM`.
    #[tokio::test]
    async fn af1_lignes_de_journal() {
        const ENFANT: &str = "AF1_ENFANT_JOURNAL";
        const PHASE: &str = "AF1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = af1_etat("journal");
            let fid = |nom: &str| af1_id(&st, &format!("SELECT id FROM idp_provider WHERE name='{nom}'"));
            eprintln!("{PHASE}oidc");
            let (a, ca) = af1_start(&st, "af1-decouverte").await;
            let (b, cb) = af1_callback(&st, "af1-https", None).await;
            let (c, cc) = af1_callback(&st, "af1-jeton", None).await;
            let (d, _) = af1_callback(&st, "af1-jeton", Some(AF1_PARAM_SOUMIS)).await;
            println!("AF1-STATUT-OIDC:{a}:{b}:{c}:{d}");
            println!("AF1-ID-OIDC:{}:{}:{}", ca["id"].as_str().unwrap_or("-"), cb["id"].as_str().unwrap_or("-"), cc["id"].as_str().unwrap_or("-"));
            println!("AF1-FOURNISSEURS:{}:{}:{}", fid("af1-decouverte"), fid("af1-https"), fid("af1-jeton"));
            eprintln!("{PHASE}etapes");
            let (e, ce) = af1_reponse(servir_l_echec_de_l_etape(StatusCode::UNAUTHORIZED, PHRASE_ID_TOKEN_INVALIDE, "connexion OIDC", 41, "id_token", "validation JWT échouée: InvalidIssuer af1-revendication")).await;
            let (f, cf) = af1_reponse(servir_l_echec_de_l_etape(StatusCode::INTERNAL_SERVER_ERROR, PHRASE_AUTHNREQUEST_SAML_ECHOUEE, "connexion SAML", 42, "AuthnRequest", "acs_url: https://198.51.100.7/acs")).await;
            let (g, cg) = af1_reponse(servir_l_echec_de_l_etape(StatusCode::BAD_GATEWAY, PHRASE_JWKS_INDISPONIBLE, "connexion OIDC", 43, "JWKS", "connexion 198.51.100.7:443 : Connection refused (os error 111)")).await;
            println!("AF1-STATUT-ETAPES:{e}:{f}:{g}:{}", ce.get("id").is_none());
            println!("AF1-ID-ETAPES:{}:{}", cf["id"].as_str().unwrap_or("-"), cg["id"].as_str().unwrap_or("-"));
            eprintln!("{PHASE}mfa");
            let (statuts, causes) = af1_jouer_les_sites_mfa(&st).await;
            println!("AF1-STATUT-MFA:{}", statuts.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            println!("AF1-CAUSES-MFA:{}", json!(causes));
            println!("AF1-COMPTE:{}", af1_id(&st, &format!("SELECT id FROM user WHERE name='{AF1_PORTEUR}'")));
            eprintln!("{PHASE}calme");
            af1_sql(&st, &format!("DELETE FROM user_mfa WHERE user='{AF1_PORTEUR}';"));
            let h = af1_start(&st, "af1-jeton").await.0;
            let i = af1_reponse(mfa_status(State(st.clone()), Extension(sp_au(AF1_PORTEUR, "admin"))).await).await.0;
            println!("AF1-STATUT-CALME:{h}:{i}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::routes_publiques_de_connexion_sans_texte_reseau::af1_lignes_de_journal"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> String {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").to_string()
        };
        let champs = |m: &str| -> Vec<String> { marque(m).split(':').map(str::to_string).collect() };
        assert_eq!(champs("AF1-STATUT-OIDC:"), ["502", "502", "502", "401"], "contrôle : trois étapes échouées, un refus de l'IdP");
        assert_eq!(champs("AF1-STATUT-ETAPES:"), ["401", "500", "502", "true"], "contrôle : statuts du constructeur, 4xx sans identifiant");
        assert_eq!(champs("AF1-STATUT-MFA:"), ["200", "503", "503", "503", "503", "503", "503", "503", "503", "503"], "contrôle : chaque site atteint");
        assert_eq!(champs("AF1-STATUT-CALME:"), ["302", "200"], "contrôle : nominal");
        let ids = champs("AF1-ID-OIDC:");
        let fournisseurs = champs("AF1-FOURNISSEURS:");
        let ids_etapes = champs("AF1-ID-ETAPES:");
        let compte = marque("AF1-COMPTE:");
        let causes: Vec<String> = serde_json::from_str(&marque("AF1-CAUSES-MFA:")).expect("contrôle : causes rejouées");
        assert_eq!(causes.len(), 10, "contrôle : dix causes rejouées : {causes:?}");
        let phase = |nom: &str, prefixe: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains(prefixe)).map(str::to_string).collect()
        };
        assert_eq!(
            phase("oidc", "[idp] WARN"),
            [
                format!("[{}] [idp] WARN connexion OIDC (fournisseur #{}) échouée à l'étape « découverte » : SSRF", ids[0], fournisseurs[0]),
                format!("[{}] [idp] WARN connexion OIDC (fournisseur #{}) échouée à l'étape « découverte » : endpoint OIDC non-https refusé", ids[1], fournisseurs[1]),
                format!("[{}] [idp] WARN connexion OIDC (fournisseur #{}) échouée à l'étape « échange de code » : SSRF", ids[2], fournisseurs[2]),
            ],
            "phase oidc : une ligne par étape, aucune pour le paramètre `error`"
        );
        assert_eq!(
            phase("etapes", "[idp] WARN"),
            [
                "[idp] WARN connexion OIDC (fournisseur #41) échouée à l'étape « id_token » : validation JWT échouée".to_string(),
                format!("[{}] [idp] WARN connexion SAML (fournisseur #42) échouée à l'étape « AuthnRequest » : acs_url", ids_etapes[0]),
                format!(
                    "[{}] [idp] WARN connexion OIDC (fournisseur #43) échouée à l'étape « JWKS » : connexion TCP impossible (refusée, injoignable ou délai dépassé)",
                    ids_etapes[1]
                ),
            ],
            "phase etapes : 4xx sans identifiant, nature sans hôte"
        );
        let porteur = format!("compte #{compte}");
        let attendues = [
            format!("[mfa] WARN {porteur} NON lu au statut : {}", causes[0]),
            format!("[mfa] WARN enrôlement du {porteur} NON écrit : {}", causes[1]),
            format!("[mfa] WARN second facteur du {porteur} NON lu à l'activation : {}", causes[2]),
            format!("[mfa] WARN second facteur du compte sans ligne `user` NON lu à l'activation : {}", causes[3]),
            format!("[mfa] WARN second facteur du compte (identifiant non lu) NON lu à l'activation : {}", causes[4]),
            format!("[mfa] WARN second facteur du {porteur} NON lu à la désactivation : {}", causes[5]),
            format!("[mfa] WARN second facteur du {porteur} NON lu à la connexion : {}", causes[6]),
            format!("[mfa] WARN activation du {porteur} NON écrite : {}", causes[7]),
            format!("[mfa] WARN second facteur du {porteur} NON relu dans la transaction de désactivation : {}", causes[8]),
            format!("[mfa] WARN désactivation du {porteur} NON validée : {}", causes[9]),
        ];
        assert!(attendues.len() >= 10, "plancher : dix lignes");
        assert_eq!(phase("mfa", "[mfa]"), attendues, "phase mfa : chaque ligne entière, l'identifiant interne seul");
        assert!(phase("calme", "WARN").is_empty(), "le nominal n'écrit aucune ligne : {:?}", phase("calme", "WARN"));
        for (canal, texte) in [("stdout", &stdout), ("stderr", &stderr)] {
            for interdit in [AF1_PORTEUR, AF1_SANS_LIGNE, "fd00", "198.51.100", "af1-param-soumis", "af1-revendication", "idp.af1.example"] {
                assert!(!texte.contains(interdit), "{canal} de l'enfant : `{interdit}` n'est jamais écrit : {texte}");
            }
        }
    }
}
