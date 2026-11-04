// =====================================================================================
// `P7.20-a` — LES TROIS RESTES DE LA DÉCISION DE L'EXPLOITANT DU 2026-11-03 (fournisseurs d'identité et d'IA créés par
// l'API jugés comme les objets de l'API) : la connexion LDAP gardée, la saisie refusée, le refus de l'IA qui nomme ses
// réglages.
//
// LE DÉFAUT, MESURÉ SUR 4a041a6b :
// (1) `ldap_authenticate` (daemon/src/idp/ldap.rs:129) ouvrait `LdapConn::with_settings(settings, &cfg.url)` sans
//     aucune garde : un fournisseur LDAP créé par l'API joignait une adresse privée, la boucle locale ou la cible des
//     métadonnées du nuage, et `ldapi://` ouvrait un socket local ; un hôte vide vaut `localhost` pour `ldap3` 0.12.1,
//     ou le fait paniquer (`ldap:///dc=…` : `unexpected None from url.host_str()`, src/conn.rs).
// (2) `idp_provider_create` / `idp_provider_update` (daemon/src/handlers/idp.rs) et `ai_provider_create` /
//     `ai_provider_update` (daemon/src/handlers/ai.rs) acceptaient (200) un issuer, un point de jeton, des JWKS, une URL
//     d'annuaire ou un endpoint d'IA sur adresse privée, refusés seulement à l'appel — quand un connecteur, une
//     destination ou un canal saisi par l'API l'est dès la saisie.
// (3) `ai_worker_err` servait, sur un refus de la garde pour adresse privée, la phrase générique de l'échec et la nature
//     `NATURE_GARDE_SSRF`, qui ne nommaient ni `PLUME_SSRF_ALLOW` ni `PLUME_SSRF_BLOCK_PRIVATE=0`.
//
// LE CORRECTIF : (1) `ldap_garde_de_sortie` (lecture de l'URL par `ldap_hote_et_port`, puis `ssrf_check_host` avec
// `ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA`) jouée par `ldap_authenticate` AVANT `LdapConn::with_settings` ; un refus
// sert en 502 `PHRASE_ANNUAIRE_LDAP_REFUSE_PAR_LA_GARDE` sur `POST /api/auth/ldap`, la nature au journal `[idp]`, aucun
// échec compté au frein. (2) refus 400 à la saisie quand une cible tient à sa SEULE adresse privée
// (`refusee_pour_sa_seule_adresse_privee`, comme un connecteur) : OIDC = découverte si exigée, point de jeton et JWKS
// écrits ; LDAP = URL de l'annuaire ; IA = endpoint ; création ET modification, `from-preset` compris (il délègue à la
// création). (3) une phrase et une nature propres au refus d'adresse privée, qui nomment les deux réglages, sans
// l'adresse.
//
// LES TÉMOINS, en sous-processus (la politique et `PLUME_SSRF_ALLOW` sont figées au premier usage), trois réglages
// chacun — défaut, `PLUME_SSRF_ALLOW`, `PLUME_SSRF_BLOCK_PRIVATE=0` —, les noms résolus par la résolution injectée
// (`resolution_injectee`, daemon/src/ledger.rs), le réseau HTTP remplacé par le témoin de l'égress :
// (A) suite par défaut — saisies d'un fournisseur d'identité PAR LA ROUTE (`POST /api/idp/providers`,
//     `POST /api/idp/providers/{id}`), OIDC et LDAP, corps entiers, base relue après un refus (dont la découverte
//     exigée par UN SEUL endpoint absent, et l'URL d'annuaire sur boucle locale, métadonnées, `ldapi://` ou nom non
//     résolu, admise à la saisie) ; la `config` d'une modification jugée HORS du verrou de la base (point de course
//     `idp-saisie-jugee:<genre>`, `is_locked()` lu) ; `POST /api/auth/ldap` par le routeur, la garde jouée par la route
//     avant le bind dans tout profil : 502 corps entier, ligne `[idp]` entière et frein inchangé pour CHAQUE cause de
//     refus (boucle, métadonnées, `ldapi://`, hôte vide, nom non résolu, nom privé, nom privé suivi de `?@` ou `#@` et
//     d'une adresse publique) ; un fournisseur NON CONFIGURÉ (URL vide, blanche, absente) garde la réponse d'avant (501
//     sans `ldap`, 401 avec), jamais le 502 de la garde ; la garde sur `ldap://10.0.0.5?@192.0.2.10` et sa variante en
//     `#` ; et la lecture de l'URL d'annuaire (`ldap_hote_et_port`), pure, compilée dans tout profil.
// (B) `--features ldap` — `ldap_authenticate` (l'appel du gestionnaire) sur un littéral privé, un nom qui résout vers le
//     privé, un nom à deux adresses dont une listée, la boucle locale où écoute un témoin TCP (aucune connexion reçue
//     quand la garde refuse, une quand l'adresse est listée), `ldapi://` et l'hôte vide ; et `POST /api/auth/ldap` par le
//     routeur : 502 corps entier, ligne de journal entière, frein inchangé.
//     Compilation : `cargo test --manifest-path daemon/Cargo.toml --features ldap -- fournisseurs_refuses_a_la_saisie`.
// (C) `--features ai` — saisies d'un fournisseur d'IA par la route (création, `from-preset`, modification, l'endpoint
//     d'une modification jugé HORS du verrou de la base, point de course `ia-saisie-jugee`) et l'appel
//     `POST /api/ai/nl2soql` (lecteur) d'un fournisseur stocké avant ce correctif sur adresse privée, sur un nom qui
//     résout vers le privé et sur la cible des métadonnées : phrase et ligne de journal entières par classe.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` par la variable de mutation, retirés avant le commit), chacun vu ROUGE :
// (A) `M_SAISIE_IDP_CREATION`, `M_SAISIE_IDP_MAJ`, `M_SAISIE_OIDC_SANS_JETON`, `M_SAISIE_OIDC_SANS_JWKS`,
//     `M_SAISIE_OIDC_DECOUVERTE_TOUJOURS`, `M_SAISIE_OIDC_AVEC_AUTORISATION`, `M_SAISIE_LDAP`,
//     `M_SAISIE_IDP_AVANT_VALIDATION`, `M_SAISIE_IDP_APRES_SECRET`, `M_SAISIE_IDP_MAJ_AVANT_LECTURE`,
//     `M_SAISIE_IDP_MAJ_GENRE_OIDC`, `M_LDAP_SCHEMA_LIBRE`, `M_LDAP_HOTE_VIDE_ADMIS` ;
// (B) `M_LDAP_SANS_GARDE`, `M_LDAP_GARDE_APRES_CONNEXION`, `M_LDAP_ORIGINE_CONFIG`, `M_LDAP_LITTERAL_SEUL`,
//     `M_LDAP_SCHEMA_LIBRE`, `M_LDAP_HOTE_VIDE_ADMIS`, `M_LOGIN_LDAP_401`, `M_LOGIN_LDAP_COMPTE_ECHEC` ;
// (C) `M_SAISIE_IA_CREATION`, `M_SAISIE_IA_MAJ`, `M_IA_SAISIE_AVANT_CLOUD`, `M_IA_MAJ_AVANT_FORME`,
//     `M_IA_PHRASE_SANS_LEVIERS`, `M_IA_NATURE_SANS_LEVIERS`.
//
// CORRECTION APRÈS VÉRIFICATION (même lot) — mutants vus VERTS par le vérificateur, ROUGES ici :
// `M_V_OIDC_DECOUVERTE_SANS_AUTORISATION`, `M_V_DECOUVERTE_ET` (découverte partielle, A1),
// `M_V_LOGIN_PRIVE_SEUL` (502 pour la seule adresse privée, A1 à A3), `M_V_LDAP_SAISIE_CAUSE_FUSIONNEE` (A1 à A3),
// `M_V_ROUTE_SANS_GARDE` (la route ne joue plus la garde : rouge dans le profil par défaut) ; l'enfant de l'IA ne mute
// plus l'environnement (l'ordre cloud est joué par un second enfant lancé sans `PLUME_AI_ALLOW_CLOUD`).
//
// SECONDE CORRECTION — (1) la route jouait la garde sur une URL VIDE et servait 502 au lieu de la réponse d'avant
// (`ad1_fournisseur_de_connexion_lu_en_trois_issues` rouge) : la garde n'est plus jouée sur une URL vide, par la même
// condition que `ldap_authenticate` ; mutant `Q_GARDE_SUR_VIDE`. (2) le découpage de l'autorité sur `?` et `#` n'avait
// aucun témoin : mutants `L9` (`/` seul), `L9_SANS_DIESE`, `L9_SANS_QUESTION`. (3) la résolution du jugement de saisie
// se faisait sous le verrou de la base : mutants `Q_IDP_JUGE_SOUS_VERROU`, `Q_IA_JUGE_SOUS_VERROU`, et le choix du
// verdict par le genre lu, `Q_POUR_LDAP_PREND_OIDC`, `Q_POUR_OIDC_PREND_LDAP`.
//
// CE QU'IL NE TIENT PAS : `ldap3` résout le nom une seconde fois pour se connecter (fenêtre de re-résolution, la même
// que celle des URL jugées par `ssrf_guard`) ; à la saisie, seul le refus qui tient à l'adresse privée est jugé — la
// boucle locale, la cible des métadonnées ou un nom non résolu restent refusés à l'appel (témoin C-ISSUER-METADONNEES) ;
// un fournisseur déjà stocké sur adresse privée n'est pas refusé quand on le réactive sans toucher sa cible : il l'est
// à l'appel. La garde rejouée par `ldap_authenticate` au point de connexion (aucune connexion reçue par l'écouteur) et
// l'admission d'une adresse listée jusqu'au bind ne sont témoignées que sous `--features ldap` (B), que la CI ne fait
// que compiler.
// =====================================================================================
mod fournisseurs_refuses_a_la_saisie_et_annuaire_ldap_garde {
    use super::*;

    const MODULE: &str = "tests::fournisseurs_refuses_a_la_saisie_et_annuaire_ldap_garde::";
    const ADMIN_IDENT: &str = "root:rootpw1234567";
    /// Les phrases attendues, écrites ici en littéral (jamais lues de la production).
    const PHRASE_SAISIE_IDP: &str = "fournisseur d'identité refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour \
un fournisseur saisi par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée";
    const PHRASE_VALIDATION_OIDC: &str = "config OIDC : issuer, client_id et redirect_uri requis";
    const REDIRECT: &str = "https://soc.exemple.test/api/auth/oidc/callback";
    const FIN: &str = "BP1-ENFANT-A-JOUE";

    fn basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    /// Le corps d'une réponse brute du routeur (dé-chunké).
    fn corps_de(brut: &str) -> String {
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or((brut, ""));
        if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_default()).unwrap_or_default()
        } else {
            corps.to_string()
        }
    }

    async fn envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: Option<&str>, extra: &[(&str, &str)], corps: &str) -> String {
        let mut entetes: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        entetes.extend_from_slice(extra);
        let (code, brut) = router_probe_envoi(addr, methode, chemin, authz, &entetes, corps).await;
        format!("{code} {}", corps_de(&brut))
    }

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> String {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
        trouves[0].to_string()
    }

    /// `<statut> <corps JSON>` -> (statut, corps lu).
    fn statut_et_corps(rendu: &str) -> (u16, Value) {
        let (s, c) = rendu.split_once(' ').unwrap_or((rendu, ""));
        (s.parse().unwrap_or(0), serde_json::from_str(c).unwrap_or(Value::Null))
    }

    fn statut(rendu: &str) -> u16 {
        statut_et_corps(rendu).0
    }

    fn refus_400(phrase: &str) -> (u16, Value) {
        (400, json!({ "error": phrase }))
    }

    fn vider_l_environnement_plume(commande: &mut std::process::Command) {
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
    }

    /// Ce que l'enfant a rendu : (stdout, stderr), après les contrôles de fin.
    fn sortie_de(sortie: std::process::Output) -> (String, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    // ------------------------------------------------------------------ (A) saisie d'un fournisseur d'identité

    const ENFANT_SAISIE_IDP: &str = "BP1_ENFANT_SAISIE_IDP";
    const TABLE_IDP: [(&str, &[&str]); 2] = [("idp.bp1.test", &["10.0.0.8"]), ("annuaire.bp1.test", &["10.0.0.7"])];

    /// L'enfant des saisies : routes réelles, secret des gestes armé, chaque réponse sur sa ligne.
    async fn jouer_la_saisie_idp_dans_l_enfant() {
        println!(); // la première ligne de l'enfant suit l'en-tête de libtest
        let _injectee = crate::ledger::resolution_injectee::injecter(&TABLE_IDP);
        let (mut st, _base) = router_test_state("bp1-saisie-idp");
        st.secret_des_gestes = Arc::new(crate::secret_des_gestes::SourceDuSecretDesGestes::Empreinte(crate::secret_des_gestes::empreinte_de_test()));
        let addr = router_serve(st.clone()).await;
        let admin = basic(ADMIN_IDENT);
        let secret = [(crate::secret_des_gestes::ENTETE_DU_SECRET_DES_GESTES, crate::secret_des_gestes::SECRET_DES_GESTES_DE_TEST)];
        let oidc = |nom: &str, config: Value| json!({ "name": nom, "kind": "oidc", "enabled": true, "config": config }).to_string();
        let ldap = |nom: &str, url: &str| json!({ "name": nom, "kind": "ldap", "enabled": true, "config": { "url": url } }).to_string();
        let issuer = |i: &str| json!({ "issuer": i, "client_id": "bp1", "redirect_uri": REDIRECT });
        let avec = |i: &str, cle: &str, valeur: &str| {
            let mut c = issuer(i);
            c[cle] = json!(valeur);
            c
        };
        let creer = |corps: String| async move { envoi(addr, "POST", "/api/idp/providers", Some(&basic(ADMIN_IDENT)), &secret, &corps).await };

        println!("C-ISSUER-PRIVE:{}", creer(oidc("bp1-issuer-prive", issuer("https://10.0.0.5"))).await);
        println!("C-ISSUER-NOM-PRIVE:{}", creer(oidc("bp1-issuer-nom", issuer("https://idp.bp1.test"))).await);
        println!("C-JETON-PRIVE:{}", creer(oidc("bp1-jeton", avec("https://192.0.2.10", "token_endpoint", "https://10.0.0.6/token"))).await);
        println!("C-JWKS-PRIVE:{}", creer(oidc("bp1-jwks", avec("https://192.0.2.10", "jwks_uri", "https://10.0.0.6/jwks"))).await);
        let ecrits = json!({
            "issuer": "https://10.0.0.6", "client_id": "bp1", "redirect_uri": REDIRECT,
            "authorization_endpoint": "https://192.0.2.10/auth", "token_endpoint": "https://192.0.2.10/token", "jwks_uri": "https://192.0.2.10/jwks",
        });
        println!("C-ENDPOINTS-ECRITS:{}", creer(oidc("bp1-ecrits", ecrits)).await);
        println!("C-AUTORISATION-PRIVEE:{}", creer(oidc("bp1-autorisation", avec("https://192.0.2.10", "authorization_endpoint", "https://10.0.0.6/auth"))).await);
        // Découverte exigée parce qu'UN SEUL des trois endpoints manque (les deux autres écrits publics) : l'issuer privé
        // est jugé, quel que soit l'endpoint absent.
        for (absent, cas) in [("authorization_endpoint", "C-DECOUVERTE-SANS-AUTORISATION"), ("token_endpoint", "C-DECOUVERTE-SANS-JETON"), ("jwks_uri", "C-DECOUVERTE-SANS-JWKS")] {
            let mut c = json!({
                "issuer": "https://10.0.0.5", "client_id": "bp1", "redirect_uri": REDIRECT,
                "authorization_endpoint": "https://192.0.2.10/auth", "token_endpoint": "https://192.0.2.10/token", "jwks_uri": "https://192.0.2.10/jwks",
            });
            c[absent] = json!("");
            println!("{cas}:{}", creer(oidc(&format!("bp1-{}", cas.to_ascii_lowercase()), c)).await);
        }
        println!("C-ISSUER-PUBLIC:{}", creer(oidc("bp1-oidc-public", issuer("https://192.0.2.10"))).await);
        println!("C-ISSUER-METADONNEES:{}", creer(oidc("bp1-metadonnees", issuer("https://169.254.169.254"))).await);
        println!("L-URL-PRIVEE:{}", creer(ldap("bp1-ldap-prive", "ldap://10.0.0.5")).await);
        println!("L-URL-NOM-PRIVE:{}", creer(ldap("bp1-ldap-nom", "ldaps://annuaire.bp1.test")).await);
        println!("L-URL-PUBLIQUE:{}", creer(ldap("bp1-ldap-public", "ldap://192.0.2.10")).await);
        // Ce qui ne tient pas à la seule adresse privée n'est pas refusé à la saisie : jugé à la connexion (route ci-dessous).
        println!("L-URL-BOUCLE:{}", creer(ldap("bp1-ldap-boucle", "ldap://127.0.0.1")).await);
        println!("L-URL-METADONNEES:{}", creer(ldap("bp1-ldap-metadonnees", "ldap://169.254.169.254")).await);
        println!("L-URL-NOM-ABSENT:{}", creer(ldap("bp1-ldap-absent", "ldap://absent.bp1.test")).await);
        println!("L-URL-LDAPI:{}", creer(ldap("bp1-ldap-ldapi", "ldapi://%2Ftmp%2Fbp1.sock")).await);
        // Ordre : la validation par type d'abord (client_id manquant), puis l'adresse privée, puis le secret des gestes.
        println!("C-ORDRE-VALIDATION:{}", creer(oidc("bp1-ordre", json!({ "issuer": "https://10.0.0.5", "redirect_uri": REDIRECT }))).await);
        println!("C-ORDRE-SECRET:{}", envoi(addr, "POST", "/api/idp/providers", Some(&admin), &[], &oidc("bp1-sans-secret", issuer("https://10.0.0.5"))).await);

        let id_de = |nom: &str| -> i64 {
            st.db.lock().query_row("SELECT id FROM idp_provider WHERE name=?1", params![nom], |r| r.get(0)).expect("fournisseur créé")
        };
        let config_de = |id: i64| -> String {
            st.db.lock().query_row("SELECT config_json FROM idp_provider WHERE id=?1", params![id], |r| r.get(0)).expect("config lue")
        };
        let (oidc_public, ldap_public) = (id_de("bp1-oidc-public"), id_de("bp1-ldap-public"));
        let maj = |id: i64, config: Value| async move {
            envoi(addr, "POST", &format!("/api/idp/providers/{id}"), Some(&basic(ADMIN_IDENT)), &secret, &json!({ "config": config }).to_string()).await
        };
        // Le verrou de la base au point de course du jugement (résolution comprise), par genre jugé.
        let verrou_vu: Vec<Arc<Mutex<Option<bool>>>> = ["oidc", "ldap"]
            .iter()
            .map(|genre| {
                let vu = Arc::new(Mutex::new(None));
                let (vu_c, base) = (vu.clone(), st.db.clone());
                crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("idp-saisie-jugee:{genre}"), move || {
                    *vu_c.lock() = Some(base.is_locked());
                });
                vu
            })
            .collect();
        println!("M-OIDC-VOISIN:{}", maj(oidc_public, issuer("https://10.0.0.6")).await);
        println!("M-VERROU-AU-JUGEMENT:{:?}", verrou_vu.iter().map(|vu| *vu.lock()).collect::<Vec<_>>());
        println!("M-OIDC-APRES:{}", OidcCfg::from_json(&serde_json::from_str(&config_de(oidc_public)).unwrap_or(Value::Null)).issuer);
        println!("M-LDAP-PRIVEE:{}", maj(ldap_public, json!({ "url": "ldap://10.0.0.6" })).await);
        println!("M-LDAP-APRES:{}", LdapCfg::from_json(&serde_json::from_str(&config_de(ldap_public)).unwrap_or(Value::Null)).url);
        println!("M-INCONNU:{}", maj(999_999, issuer("https://10.0.0.6")).await);

        // La route `POST /api/auth/ldap`, fournisseurs stockés (tels qu'une version antérieure les aurait laissés) : la
        // garde est jouée par la route avant le bind, dans tout profil ; chaque cause de refus sert le 502, sans échec.
        for (cas, url) in ROUTES_ANNUAIRE {
            st.db
                .lock()
                .execute(
                    "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,'ldap',1,?2,'',1,1)",
                    params![format!("bp1-route-{cas}"), json!({ "url": url, "user_dn_template": "uid={user},dc=bp1,dc=test" }).to_string()],
                )
                .expect("fournisseur LDAP stocké");
            let id = id_de(&format!("bp1-route-{cas}"));
            let corps = json!({ "provider": format!("bp1-route-{cas}"), "user": format!("u-{cas}"), "pass": "x" }).to_string();
            println!("R-{cas}:{} {}", id, envoi(addr, "POST", "/api/auth/ldap", None, &[], &corps).await);
            let echecs = st.auth_fails.lock().get(&(format!("u-{cas}"), "127.0.0.1".to_string())).map_or(0, |f| f.count);
            println!("R-{cas}-ECHECS:{echecs}");
        }
        // Un fournisseur LDAP NON CONFIGURÉ (URL vide, blanche ou absente) n'est pas une cible refusée : la garde n'est pas
        // jouée, la réponse est celle d'avant (le bind du profil), un échec compté.
        for (cas, config) in [("URL-VIDE", json!({ "url": "" })), ("URL-BLANCHE", json!({ "url": "   " })), ("SANS-URL", json!({}))] {
            st.db
                .lock()
                .execute(
                    "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(?1,'ldap',1,?2,'',1,1)",
                    params![format!("bq1-{cas}"), config.to_string()],
                )
                .expect("fournisseur LDAP non configuré stocké");
            let corps = json!({ "provider": format!("bq1-{cas}"), "user": format!("n-{cas}"), "pass": "x" }).to_string();
            println!("N-{cas}:{}", envoi(addr, "POST", "/api/auth/ldap", None, &[], &corps).await);
            let echecs = st.auth_fails.lock().get(&(format!("n-{cas}"), "127.0.0.1".to_string())).map_or(0, |f| f.count);
            println!("N-{cas}-ECHECS:{echecs}");
        }
        // La garde elle-même sur une autorité que `?` ou `#` arrête avant un `@` (l'hôte que `ldap3` joint est 10.0.0.5).
        println!("G-QUESTION:{:?}", crate::idp::ldap_garde_de_sortie("ldap://10.0.0.5?@192.0.2.10"));
        println!("G-DIESE:{:?}", crate::idp::ldap_garde_de_sortie("ldap://10.0.0.5#@192.0.2.10"));
        println!("{FIN}");
    }

    /// Les fournisseurs LDAP stockés que la route éprouve : (cas, URL de l'annuaire). Les noms privés en DERNIER : admis
    /// par la garde sous `PLUME_SSRF_BLOCK_PRIVATE=0`, ils vont jusqu'au bind (501 sans `ldap`, 401 avec : `.test` ne
    /// résout pas). `NOM-PRIVE-QUESTION` et `NOM-PRIVE-DIESE` : l'autorité s'arrête à `?` ou `#`, l'hôte jugé est le nom
    /// privé que `ldap3` joint, jamais l'adresse publique qui suit le `@`.
    const ROUTES_ANNUAIRE: [(&str, &str); 8] = [
        ("BOUCLE", "ldap://127.0.0.1:389"),
        ("METADONNEES", "ldap://169.254.169.254"),
        ("LDAPI", "ldapi://%2Ftmp%2Fbp1.sock"),
        ("HOTE-VIDE", "ldap:///dc=bp1"),
        ("NOM-ABSENT", "ldap://absent.bp1.test"),
        ("NOM-PRIVE", "ldaps://annuaire.bp1.test"),
        ("NOM-PRIVE-QUESTION", "ldaps://annuaire.bp1.test?@192.0.2.10"),
        ("NOM-PRIVE-DIESE", "ldap://annuaire.bp1.test#@192.0.2.10"),
    ];
    /// La route, par cause de refus : 502 corps entier, ligne `[idp]` entière (nature « SSRF » sauf l'adresse privée, qui
    /// nomme ses réglages), aucun échec compté. `prive_refuse` : la garde refuse-t-elle le nom privé sous ce réglage ?
    fn juger_les_routes(a: &str, a_err: &str, prive_refuse: bool) {
        let mut attendues = Vec::new();
        for (cas, _) in ROUTES_ANNUAIRE {
            let rendu = lu(a, &format!("R-{cas}"));
            let (fournisseur, reponse) = rendu.split_once(' ').unwrap_or(("", ""));
            let echecs = lu(a, &format!("R-{cas}-ECHECS"));
            let nom_prive = cas.starts_with("NOM-PRIVE");
            if nom_prive && !prive_refuse {
                let attendu = if cfg!(feature = "ldap") { 401 } else { 501 };
                assert_eq!(statut(reponse), attendu, "garde passée : le bind d'avant ({cas}) : {reponse}");
                assert_eq!(echecs, "1", "un bind tenté est un échec compté ({cas})");
                continue;
            }
            let (s, v) = statut_et_corps(reponse);
            assert_eq!(s, 502, "route, cause {cas} : 502 nommé : {reponse}");
            let id = v["id"].as_str().unwrap_or("").to_string();
            assert!(id.starts_with("plume-e"), "identifiant servi ({cas}) : {v}");
            assert_eq!(v, json!({ "error": PHRASE_ANNUAIRE_REFUSE, "id": id }), "corps entier, sans l'adresse ({cas})");
            assert_eq!(echecs, "0", "aucun identifiant éprouvé, aucun échec compté ({cas})");
            let nature = if nom_prive { NATURE_PRIVEE } else { "SSRF" };
            attendues.push(format!("[{id}] [idp] WARN connexion LDAP (fournisseur #{fournisseur}) échouée à l'étape « garde de sortie » : {nature}"));
        }
        let lignes: Vec<String> = a_err.lines().filter(|l| l.contains("[idp] WARN connexion LDAP")).map(str::to_string).collect();
        assert_eq!(lignes, attendues, "journal [idp], lignes entières : {a_err}");
    }

    /// Ce qui ne dépend pas du réglage : l'adresse publique part, l'ordre des refus, la cible des métadonnées admise à la
    /// saisie (jugée à l'appel), le point d'autorisation (navigateur) non jugé, la découverte non exigée non jugée.
    fn juger_les_saisies_communes(a: &str) {
        assert_eq!(statut(&lu(a, "C-ISSUER-PUBLIC")), 200, "issuer public admis");
        assert_eq!(statut(&lu(a, "L-URL-PUBLIQUE")), 200, "annuaire public admis");
        assert_eq!(statut(&lu(a, "C-ISSUER-METADONNEES")), 200, "la cible des métadonnées n'est pas refusée à la saisie : à l'appel");
        assert_eq!(statut(&lu(a, "C-AUTORISATION-PRIVEE")), 200, "le point d'autorisation (navigateur) n'est pas une cible du démon");
        assert_eq!(statut(&lu(a, "C-ENDPOINTS-ECRITS")), 200, "les trois endpoints écrits : la découverte n'est pas appelée, l'issuer n'est pas jugé");
        for cas in ["L-URL-BOUCLE", "L-URL-METADONNEES", "L-URL-NOM-ABSENT", "L-URL-LDAPI"] {
            assert_eq!(statut(&lu(a, cas)), 200, "{cas} : seule l'adresse privée est refusée à la saisie, le reste à la connexion");
        }
        assert_eq!(statut_et_corps(&lu(a, "C-ORDRE-VALIDATION")), refus_400(PHRASE_VALIDATION_OIDC), "la validation par type garde sa cause");
        assert_eq!(statut_et_corps(&lu(a, "M-INCONNU")), (404, json!({ "error": "provider introuvable" })), "fournisseur absent : le 404 d'avant");
        assert_eq!(lu(a, "M-VERROU-AU-JUGEMENT"), "[Some(false), Some(false)]", "modification : la config est jugée (OIDC puis LDAP) hors du verrou de la base");
        juger_les_fournisseurs_non_configures(a);
    }

    /// Un fournisseur LDAP non configuré : la réponse d'avant le lot, corps entier, un échec compté (le bind du profil a
    /// été tenté) — 501 du stub sans `ldap`, 401 générique avec (`ldap_authenticate` : « URL LDAP manquante »).
    fn juger_les_fournisseurs_non_configures(a: &str) {
        for cas in ["URL-VIDE", "URL-BLANCHE", "SANS-URL"] {
            let (s, v) = statut_et_corps(&lu(a, &format!("N-{cas}")));
            if cfg!(feature = "ldap") {
                assert_eq!((s, v), (401, json!({ "error": "identifiants LDAP invalides" })), "{cas} : non configuré, la réponse d'avant");
            } else {
                let id = v["id"].as_str().unwrap_or("").to_string();
                assert!(id.starts_with("plume-e"), "identifiant servi ({cas}) : {v}");
                assert_eq!(
                    (s, v),
                    (501, json!({ "error": "support LDAP non compilé (recompiler avec --features ldap)", "id": id })),
                    "{cas} : non configuré, le 501 d'avant (jamais le 502 de la garde)"
                );
            }
            assert_eq!(lu(a, &format!("N-{cas}-ECHECS")), "1", "{cas} : le bind d'avant est tenté, l'échec compté");
        }
    }

    /// (A1) DÉFAUT : chaque cible privée refusée à la saisie, corps entier ; rien n'est écrit par une modification refusée.
    #[tokio::test]
    async fn bp1_saisie_idp_prive_refusee_par_defaut() {
        if std::env::var(ENFANT_SAISIE_IDP).is_ok() {
            jouer_la_saisie_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_saisie_idp_prive_refusee_par_defaut"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_SAISIE_IDP, "1").env("PLUME_CONFIG", "/nonexistent");
        let (a, a_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_communes(&a);
        juger_les_routes(&a, &a_err, true);
        let refus = refus_400(PHRASE_SAISIE_IDP);
        assert_eq!(statut_et_corps(&lu(&a, "C-ISSUER-PRIVE")), refus, "issuer littéral privé");
        for cas in ["C-DECOUVERTE-SANS-AUTORISATION", "C-DECOUVERTE-SANS-JETON", "C-DECOUVERTE-SANS-JWKS"] {
            assert_eq!(statut_et_corps(&lu(&a, cas)), refus, "{cas} : un endpoint manque, la découverte (issuer privé) est jugée");
        }
        assert_eq!(statut_et_corps(&lu(&a, "C-ISSUER-NOM-PRIVE")), refus, "issuer dont le nom résout vers le privé");
        assert_eq!(statut_et_corps(&lu(&a, "C-JETON-PRIVE")), refus, "point de jeton écrit privé");
        assert_eq!(statut_et_corps(&lu(&a, "C-JWKS-PRIVE")), refus, "JWKS écrits privés");
        assert_eq!(statut_et_corps(&lu(&a, "L-URL-PRIVEE")), refus, "URL d'annuaire littérale privée");
        assert_eq!(statut_et_corps(&lu(&a, "L-URL-NOM-PRIVE")), refus, "URL d'annuaire dont le nom résout vers le privé");
        assert_eq!(statut_et_corps(&lu(&a, "C-ORDRE-SECRET")), refus, "l'adresse privée est jugée avant le secret des gestes");
        assert_eq!(statut_et_corps(&lu(&a, "M-OIDC-VOISIN")), refus, "modification OIDC vers le privé");
        assert_eq!(lu(&a, "M-OIDC-APRES"), "https://192.0.2.10", "rien n'est écrit");
        assert_eq!(statut_et_corps(&lu(&a, "M-LDAP-PRIVEE")), refus, "modification LDAP vers le privé (genre lu)");
        assert_eq!(lu(&a, "M-LDAP-APRES"), "ldap://192.0.2.10", "rien n'est écrit");
        assert_eq!(lu(&a, "G-QUESTION"), format!("Err({:?})", refus_prive("10.0.0.5")), "`?` arrête l'autorité : 10.0.0.5 est jugée");
        assert_eq!(lu(&a, "G-DIESE"), format!("Err({:?})", refus_prive("10.0.0.5")), "`#` arrête l'autorité : 10.0.0.5 est jugée");
    }

    /// (A2) `PLUME_SSRF_ALLOW=10.0.0.5` : l'adresse listée passe, ses voisines et les noms vers une autre adresse non.
    #[tokio::test]
    async fn bp1_saisie_idp_prive_admise_quand_l_adresse_est_listee() {
        if std::env::var(ENFANT_SAISIE_IDP).is_ok() {
            jouer_la_saisie_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_saisie_idp_prive_admise_quand_l_adresse_est_listee"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_SAISIE_IDP, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_ALLOW", "10.0.0.5");
        let (b, b_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_communes(&b);
        juger_les_routes(&b, &b_err, true);
        let refus = refus_400(PHRASE_SAISIE_IDP);
        assert_eq!(statut(&lu(&b, "C-ISSUER-PRIVE")), 200, "issuer listé admis");
        for cas in ["C-DECOUVERTE-SANS-AUTORISATION", "C-DECOUVERTE-SANS-JETON", "C-DECOUVERTE-SANS-JWKS"] {
            assert_eq!(statut(&lu(&b, cas)), 200, "{cas} : issuer listé admis");
        }
        assert_eq!(statut_et_corps(&lu(&b, "C-ISSUER-NOM-PRIVE")), refus, "nom vers 10.0.0.8, non listée");
        assert_eq!(statut_et_corps(&lu(&b, "C-JETON-PRIVE")), refus, "voisine 10.0.0.6");
        assert_eq!(statut_et_corps(&lu(&b, "C-JWKS-PRIVE")), refus, "voisine 10.0.0.6");
        assert_eq!(statut(&lu(&b, "L-URL-PRIVEE")), 200, "annuaire listé admis");
        assert_eq!(statut_et_corps(&lu(&b, "L-URL-NOM-PRIVE")), refus, "nom vers 10.0.0.7, non listée");
        assert_eq!(statut(&lu(&b, "C-ORDRE-SECRET")), 403, "adresse listée : la saisie passe, le secret des gestes refuse");
        assert_eq!(statut_et_corps(&lu(&b, "M-OIDC-VOISIN")), refus);
        assert_eq!(lu(&b, "M-OIDC-APRES"), "https://192.0.2.10");
        assert_eq!(statut_et_corps(&lu(&b, "M-LDAP-PRIVEE")), refus);
        assert_eq!(lu(&b, "M-LDAP-APRES"), "ldap://192.0.2.10");
        assert_eq!((lu(&b, "G-QUESTION"), lu(&b, "G-DIESE")), ("Ok(())".to_string(), "Ok(())".to_string()), "10.0.0.5 listée : admise");
    }

    /// (A3) `PLUME_SSRF_BLOCK_PRIVATE=0` : toute adresse privée admise à la saisie, et écrite.
    #[tokio::test]
    async fn bp1_saisie_idp_prive_admise_sous_la_politique_admises_partout() {
        if std::env::var(ENFANT_SAISIE_IDP).is_ok() {
            jouer_la_saisie_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_saisie_idp_prive_admise_sous_la_politique_admises_partout"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_SAISIE_IDP, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_BLOCK_PRIVATE", "0");
        let (c, c_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_communes(&c);
        juger_les_routes(&c, &c_err, false);
        assert_eq!(statut(&lu(&c, "C-ISSUER-PRIVE")), 200);
        for cas in ["C-DECOUVERTE-SANS-AUTORISATION", "C-DECOUVERTE-SANS-JETON", "C-DECOUVERTE-SANS-JWKS"] {
            assert_eq!(statut(&lu(&c, cas)), 200, "{cas}");
        }
        assert_eq!(statut(&lu(&c, "C-ISSUER-NOM-PRIVE")), 200);
        assert_eq!(statut(&lu(&c, "C-JETON-PRIVE")), 200);
        assert_eq!(statut(&lu(&c, "C-JWKS-PRIVE")), 200);
        assert_eq!(statut(&lu(&c, "L-URL-PRIVEE")), 200);
        assert_eq!(statut(&lu(&c, "L-URL-NOM-PRIVE")), 200);
        assert_eq!(statut(&lu(&c, "C-ORDRE-SECRET")), 403);
        assert_eq!(statut_et_corps(&lu(&c, "M-OIDC-VOISIN")), (200, json!({ "ok": true })));
        assert_eq!(lu(&c, "M-OIDC-APRES"), "https://10.0.0.6", "la modification admise est écrite");
        assert_eq!(statut_et_corps(&lu(&c, "M-LDAP-PRIVEE")), (200, json!({ "ok": true })));
        assert_eq!(lu(&c, "M-LDAP-APRES"), "ldap://10.0.0.6");
        assert_eq!((lu(&c, "G-QUESTION"), lu(&c, "G-DIESE")), ("Ok(())".to_string(), "Ok(())".to_string()), "politique 0 : admise");
    }

    /// (A4) La lecture de l'URL d'annuaire, celle que `ldap3` ouvrira : ports par défaut, port explicite, informations
    /// d'utilisateur, littéral IPv6, casse ; `ldapi://`, un autre schéma et l'hôte vide refusés, chacun par sa phrase.
    #[test]
    fn bp1_lecture_de_l_url_d_annuaire() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let lire = |u: &str| crate::idp::ldap_hote_et_port(u);
        assert_eq!(lire("ldap://annuaire.exemple.test"), Ok(("annuaire.exemple.test".to_string(), 389)));
        assert_eq!(lire("ldaps://annuaire.exemple.test"), Ok(("annuaire.exemple.test".to_string(), 636)));
        assert_eq!(lire("  LDAP://Annuaire.Exemple.Test:3890/dc=exemple?uid#x"), Ok(("annuaire.exemple.test".to_string(), 3890)));
        assert_eq!(lire("ldaps://svc:motdepasse@10.0.0.5:6360"), Ok(("10.0.0.5".to_string(), 6360)));
        assert_eq!(lire("ldap://[fd00::5]:3389"), Ok(("fd00::5".to_string(), 3389)));
        let schema = "SSRF: schéma d'URL LDAP non autorisé (ldap:// ou ldaps:// attendu)";
        assert_eq!(lire("ldapi://%2Fvar%2Frun%2Fslapd.sock"), Err(schema.to_string()));
        assert_eq!(lire("https://10.0.0.5"), Err(schema.to_string()));
        assert_eq!(lire("10.0.0.5:389"), Err(schema.to_string()));
        let vide = "SSRF: hôte d'URL LDAP vide";
        assert_eq!(lire("ldap:///dc=exemple"), Err(vide.to_string()));
        assert_eq!(lire("ldaps://"), Err(vide.to_string()));
        assert_eq!(lire("ldap://svc@:389"), Err(vide.to_string()));
    }

    /// (A5) L'autorité s'arrête au premier `?` ou `#`, même avant un `@` : la bibliothèque `url` que lit `ldap3` arrête les
    /// informations d'utilisateur à ces deux caractères (url 2.5.8, `parse_userinfo`), l'hôte joint est donc celui qui
    /// précède. Jugée sur ce qui suit le `@`, l'adresse publique masquerait l'adresse privée réellement jointe.
    #[test]
    fn bq1_autorite_d_annuaire_arretee_a_la_question_et_au_diese() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let lire = |u: &str| crate::idp::ldap_hote_et_port(u);
        assert_eq!(lire("ldap://10.0.0.5?@192.0.2.10"), Ok(("10.0.0.5".to_string(), 389)), "`?` avant le `@`");
        assert_eq!(lire("ldap://10.0.0.5#@192.0.2.10"), Ok(("10.0.0.5".to_string(), 389)), "`#` avant le `@`");
        assert_eq!(lire("ldaps://10.0.0.5:6360?x@192.0.2.10:636"), Ok(("10.0.0.5".to_string(), 6360)), "port de l'hôte joint");
        assert_eq!(lire("ldap://svc@10.0.0.5?@192.0.2.10"), Ok(("10.0.0.5".to_string(), 389)), "informations d'utilisateur avant, `?` ensuite");
    }

    // ------------------------------------------------------------------ (B) la connexion LDAP (feature `ldap`)

    #[cfg(feature = "ldap")]
    const ENFANT_ANNUAIRE: &str = "BP1_ENFANT_ANNUAIRE";
    #[cfg(feature = "ldap")]
    const TABLE_ANNUAIRE: [(&str, &[&str]); 2] =
        [("annuaire.bp1.test", &["10.0.0.7"]), ("annuaire-double.bp1.test", &["10.0.0.7", "10.0.0.8"])];
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    const PHRASE_ANNUAIRE_REFUSE: &str = "connexion LDAP refusée : l'adresse de l'annuaire du fournisseur d'identité a été \
refusée par la garde de sortie, avant toute connexion ; aucune session n'est posée, la cause est au journal du serveur sous \
l'identifiant de cette réponse.";
    const NATURE_PRIVEE: &str = "SSRF: adresse privée refusée — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, \
PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";

    /// L'issue d'une tentative : le refus de la garde en entier ; sinon la classe de l'échec qui SUIT la garde
    /// (« connexion » : `ldap3` n'a pas joint l'hôte ; « bind » : la connexion a eu lieu, le bind a échoué).
    #[cfg(feature = "ldap")]
    fn issue_ldap(r: Result<String, String>) -> String {
        match r {
            Ok(role) => format!("rôle {role}"),
            Err(e) if e.starts_with("SSRF:") => e,
            Err(e) if e.starts_with("connexion LDAP:") => "connexion".to_string(),
            Err(e) if e.starts_with("bind user:") => "bind".to_string(),
            Err(e) => format!("autre : {e}"),
        }
    }

    /// L'enfant de l'annuaire : `ldap_authenticate` (hors de l'exécuteur, comme le gestionnaire), puis la route.
    #[cfg(feature = "ldap")]
    async fn jouer_l_annuaire_dans_l_enfant() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        println!();
        let _injectee = crate::ledger::resolution_injectee::injecter(&TABLE_ANNUAIRE);
        // Un écouteur TCP sur la boucle locale : chaque connexion reçue est comptée, puis fermée.
        let ecouteur = std::net::TcpListener::bind("127.0.0.1:0").expect("écouteur de boucle locale");
        let port = ecouteur.local_addr().expect("port").port();
        let recues = Arc::new(AtomicUsize::new(0));
        {
            let recues = recues.clone();
            std::thread::spawn(move || {
                for flux in ecouteur.incoming() {
                    if flux.is_ok() {
                        recues.fetch_add(1, Ordering::SeqCst);
                    }
                    drop(flux);
                }
            });
        }
        let tenter = |url: String| async move {
            let cfg = LdapCfg::from_json(&json!({ "url": url, "user_dn_template": "uid={user},dc=bp1,dc=test" }));
            tokio::task::spawn_blocking(move || issue_ldap(ldap_authenticate(&cfg, "", "alice", "x"))).await.expect("tentative jouée")
        };
        println!("L-NOM-PRIVE:{}", tenter("ldaps://annuaire.bp1.test".into()).await);
        println!("L-NOM-DOUBLE:{}", tenter("ldap://annuaire-double.bp1.test".into()).await);
        println!("L-BOUCLE:{}", tenter(format!("ldap://127.0.0.1:{port}")).await);
        println!("L-BOUCLE-RECUES:{}", recues.load(Ordering::SeqCst));
        println!("L-SCHEMA:{}", tenter("ldapi://%2Ftmp%2Fbp1.sock".into()).await);
        println!("L-HOTE-VIDE:{}", tenter("ldap:///dc=bp1".into()).await);

        // La route publique, fournisseur stocké (tel qu'une version antérieure l'aurait laissé) sur un nom privé.
        let (st, _base) = router_test_state("bp1-annuaire");
        st.db
            .lock()
            .execute(
                "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES('bp1-annuaire','ldap',1,?1,'',1,1)",
                params![json!({ "url": "ldaps://annuaire.bp1.test", "user_dn_template": "uid={user},dc=bp1,dc=test" }).to_string()],
            )
            .expect("fournisseur LDAP stocké");
        let addr = router_serve(st.clone()).await;
        println!("L-ROUTE:{}", envoi(addr, "POST", "/api/auth/ldap", None, &[], r#"{"user":"alice","pass":"x"}"#).await);
        let echecs = st.auth_fails.lock().get(&("alice".to_string(), "127.0.0.1".to_string())).map_or(0, |f| f.count);
        println!("L-ROUTE-ECHECS:{echecs}");
        // En dernier : sans la garde, `ldap3` tenterait de joindre ce littéral privé.
        if std::env::var("PLUME_SSRF_BLOCK_PRIVATE").as_deref() != Ok("0") {
            println!("L-LITTERAL-PRIVE:{}", tenter("ldap://10.0.0.5".into()).await);
        }
        println!("{FIN}");
    }

    fn refus_prive(hote: &str) -> String {
        format!("SSRF: adresse privée refusée ({hote}) — {LEVIERS}")
    }

    #[cfg(feature = "ldap")]
    fn refus_prive_resolu(nom: &str, ip: &str) -> String {
        format!("SSRF: adresse privée refusée : '{nom}' résout vers {ip} — {LEVIERS}")
    }

    /// Ce qui ne dépend pas du réglage : `ldapi://` et l'hôte vide refusés, chacun par sa phrase.
    #[cfg(feature = "ldap")]
    fn juger_l_annuaire_commun(a: &str) {
        assert_eq!(lu(a, "L-SCHEMA"), "SSRF: schéma d'URL LDAP non autorisé (ldap:// ou ldaps:// attendu)", "ldapi:// refusé");
        assert_eq!(lu(a, "L-HOTE-VIDE"), "SSRF: hôte d'URL LDAP vide", "hôte vide (localhost pour ldap3) refusé");
    }

    /// La route quand la garde admet : `ldap3` ne joint pas le nom de test, 401 d'avant et un échec compté.
    #[cfg(feature = "ldap")]
    fn juger_la_route_admise(a: &str, a_err: &str) {
        assert_eq!(statut_et_corps(&lu(a, "L-ROUTE")), (401, json!({ "error": "identifiants LDAP invalides" })), "garde passée : la suite d'avant");
        assert_eq!(lu(a, "L-ROUTE-ECHECS"), "1", "un bind tenté est un échec compté");
        assert!(!a_err.contains("[idp] WARN connexion LDAP"), "aucun refus de la garde au journal : {a_err}");
    }

    /// (B1) DÉFAUT : la garde refuse avant toute connexion — littéral et nom privés, boucle locale (aucune connexion
    /// reçue) ; la route sert le 502 nommé, corps entier, la ligne de journal entière nomme les réglages, aucun échec.
    #[cfg(feature = "ldap")]
    #[tokio::test]
    async fn bp1_annuaire_prive_refuse_avant_toute_connexion_par_defaut() {
        if std::env::var(ENFANT_ANNUAIRE).is_ok() {
            jouer_l_annuaire_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_annuaire_prive_refuse_avant_toute_connexion_par_defaut"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_ANNUAIRE, "1").env("PLUME_CONFIG", "/nonexistent");
        let (a, a_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_annuaire_commun(&a);
        assert_eq!(lu(&a, "L-NOM-PRIVE"), refus_prive_resolu("annuaire.bp1.test", "10.0.0.7"), "l'adresse RÉSOLUE est jugée");
        assert_eq!(lu(&a, "L-NOM-DOUBLE"), refus_prive_resolu("annuaire-double.bp1.test", "10.0.0.7"));
        assert_eq!(lu(&a, "L-BOUCLE"), "SSRF: cible interne interdite (127.0.0.1)", "boucle locale refusée");
        assert_eq!(lu(&a, "L-BOUCLE-RECUES"), "0", "refus AVANT toute connexion : l'écouteur n'a rien reçu");
        assert_eq!(lu(&a, "L-LITTERAL-PRIVE"), refus_prive("10.0.0.5"), "littéral privé refusé");
        let (s, v) = statut_et_corps(&lu(&a, "L-ROUTE"));
        assert_eq!(s, 502, "route : 502 nommé");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "identifiant servi : {v}");
        assert_eq!(v, json!({ "error": PHRASE_ANNUAIRE_REFUSE, "id": id }), "corps entier, sans l'adresse");
        let lignes: Vec<&str> = a_err.lines().filter(|l| l.contains("[idp] WARN")).collect();
        assert_eq!(
            lignes,
            vec![format!("[{id}] [idp] WARN connexion LDAP (fournisseur #1) échouée à l'étape « garde de sortie » : {NATURE_PRIVEE}")],
            "journal [idp], ligne entière : {a_err}"
        );
        assert_eq!(lu(&a, "L-ROUTE-ECHECS"), "0", "aucun identifiant éprouvé : aucun échec compté au frein");
    }

    /// (B2) `PLUME_SSRF_ALLOW=127.0.0.1,10.0.0.7` : l'adresse listée passe la garde (la boucle locale reçoit la
    /// connexion) ; l'autre adresse d'un nom, et le littéral non listé, restent refusés.
    #[cfg(feature = "ldap")]
    #[tokio::test]
    async fn bp1_annuaire_admis_quand_l_adresse_est_listee() {
        if std::env::var(ENFANT_ANNUAIRE).is_ok() {
            jouer_l_annuaire_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_annuaire_admis_quand_l_adresse_est_listee"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_ANNUAIRE, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_ALLOW", "127.0.0.1,10.0.0.7");
        let (b, b_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_annuaire_commun(&b);
        assert_eq!(lu(&b, "L-NOM-PRIVE"), "connexion", "nom vers l'adresse listée : la garde admet, ldap3 tente");
        assert_eq!(lu(&b, "L-NOM-DOUBLE"), refus_prive_resolu("annuaire-double.bp1.test", "10.0.0.8"), "l'autre adresse du nom reste jugée");
        assert_eq!(lu(&b, "L-BOUCLE"), "bind", "boucle locale listée : connexion faite, bind échoué");
        assert_eq!(lu(&b, "L-BOUCLE-RECUES"), "1", "l'écouteur a reçu la connexion admise");
        assert_eq!(lu(&b, "L-LITTERAL-PRIVE"), refus_prive("10.0.0.5"), "littéral non listé refusé");
        juger_la_route_admise(&b, &b_err);
    }

    /// (B3) `PLUME_SSRF_BLOCK_PRIVATE=0` : le privé passe la garde, la boucle locale reste refusée.
    #[cfg(feature = "ldap")]
    #[tokio::test]
    async fn bp1_annuaire_admis_sous_la_politique_admises_partout() {
        if std::env::var(ENFANT_ANNUAIRE).is_ok() {
            jouer_l_annuaire_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_annuaire_admis_sous_la_politique_admises_partout"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_ANNUAIRE, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_BLOCK_PRIVATE", "0");
        let (c, c_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_annuaire_commun(&c);
        assert_eq!(lu(&c, "L-NOM-PRIVE"), "connexion");
        assert_eq!(lu(&c, "L-NOM-DOUBLE"), "connexion");
        assert_eq!(lu(&c, "L-BOUCLE"), "SSRF: cible interne interdite (127.0.0.1)", "la boucle locale reste refusée");
        assert_eq!(lu(&c, "L-BOUCLE-RECUES"), "0");
        juger_la_route_admise(&c, &c_err);
    }

    // ------------------------------------------------------------------ (C) le fournisseur d'IA (feature `ai`)

    #[cfg(feature = "ai")]
    const ENFANT_IA: &str = "BP1_ENFANT_IA";
    #[cfg(feature = "ai")]
    const TABLE_IA: [(&str, &[&str]); 1] = [("ia.bp1.test", &["10.0.0.9"])];
    #[cfg(feature = "ai")]
    const LECTEUR_IDENT: &str = "vwr:viewerpw12345";
    #[cfg(feature = "ai")]
    const PHRASE_SAISIE_IA: &str = "fournisseur d'IA refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour un \
fournisseur saisi par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée";
    #[cfg(feature = "ai")]
    const PHRASE_FORME: &str = "api_shape non supporté (openai | ollama-native | anthropic)";
    #[cfg(feature = "ai")]
    const PHRASE_CLOUD: &str = "provider IA CLOUD refusé (endpoint public ou requires_cloud) — poser PLUME_AI_ALLOW_CLOUD=1 \
pour autoriser l'inférence hors du réseau local";
    #[cfg(feature = "ai")]
    const PHRASE_APPEL_PRIVE: &str = "appel au fournisseur d'IA refusé : son adresse est privée (10/8, 172.16/12, \
192.168/16) et la garde de sortie la refuse avant toute connexion — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, \
PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée ; aucune proposition servie (la nature de l'échec est au journal du \
démon, sous l'identifiant servi)";
    #[cfg(feature = "ai")]
    const PHRASE_APPEL: &str = "appel au fournisseur d'IA échoué : aucune proposition servie (la nature de l'échec est au \
journal du démon, sous l'identifiant servi)";
    #[cfg(feature = "ai")]
    const NATURE_IA_PRIVEE: &str = "adresse privée du fournisseur (10/8, 172.16/12, 192.168/16) refusée par la garde SSRF, \
avant toute connexion — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    #[cfg(feature = "ai")]
    const NATURE_IA_SSRF: &str = "adresse du fournisseur refusée par la garde SSRF (cible interne, résolution impossible ou \
schéma refusé), avant toute connexion";
    #[cfg(feature = "ai")]
    const NATURE_IA_ADMIS: &str = "réponse du fournisseur non JSON ou complétion vide";

    /// L'enfant de l'IA : saisies par la route, puis trois appels d'un fournisseur stocké, inférence interceptée (`{}`).
    /// Il ne MUTE jamais l'environnement : lancé sans `PLUME_AI_ALLOW_CLOUD`, il ne joue que l'ordre des refus (la garde
    /// cloud d'abord) ; lancé avec, tout le reste.
    #[cfg(feature = "ai")]
    async fn jouer_l_ia_bp1_dans_l_enfant() {
        println!();
        let _injectee = crate::ledger::resolution_injectee::injecter(&TABLE_IA);
        let _arme = crate::ledger::temoin_de_l_egress::armer(|_m, _u| Ok(crate::ledger::temoin_de_l_egress::reponse(200, &[], "{}")));
        let (st, _base) = router_test_state("bp1-ia");
        let addr = router_serve(st.clone()).await;
        let admin = basic(ADMIN_IDENT);
        let creer = |nom: &str, endpoint: &str, config: Value| {
            json!({ "name": nom, "api_shape": "openai", "endpoint": endpoint, "enabled": false, "config": config }).to_string()
        };
        if std::env::var("PLUME_AI_ALLOW_CLOUD").is_err() {
            // Ordre : la garde cloud garde sa cause (403) sur un fournisseur `requires_cloud` à adresse privée.
            let cloud = creer("bp1-ia-cloud", "http://10.0.0.5:8000", json!({ "model": "bp1", "requires_cloud": true }));
            println!("A-ORDRE-CLOUD:{}", envoi(addr, "POST", "/api/ai/providers", Some(&admin), &[], &cloud).await);
            println!("{FIN}");
            return;
        }
        println!("A-CREATION-PRIVEE:{}", envoi(addr, "POST", "/api/ai/providers", Some(&admin), &[], &creer("bp1-ia-prive", "http://10.0.0.5:8000", json!({ "model": "bp1" }))).await);
        let preset = json!({ "preset_id": "openai-compatible-generic", "name": "bp1-ia-preset", "values": { "endpoint": "http://ia.bp1.test:8000", "model": "bp1" } });
        println!("A-PRESET-NOM-PRIVE:{}", envoi(addr, "POST", "/api/ai/from-preset", Some(&admin), &[], &preset.to_string()).await);
        println!("A-CREATION-PUBLIQUE:{}", envoi(addr, "POST", "/api/ai/providers", Some(&admin), &[], &creer("bp1-ia-public", "http://192.0.2.10:8000", json!({ "model": "bp1" }))).await);
        let public: i64 = st.db.lock().query_row("SELECT id FROM ai_provider WHERE name='bp1-ia-public'", [], |r| r.get(0)).expect("fournisseur public créé");
        let endpoint_de = |id: i64| -> String { st.db.lock().query_row("SELECT endpoint FROM ai_provider WHERE id=?1", params![id], |r| r.get(0)).expect("endpoint lu") };
        let maj = |id: i64, corps: Value| async move { envoi(addr, "POST", &format!("/api/ai/providers/{id}"), Some(&basic(ADMIN_IDENT)), &[], &corps.to_string()).await };
        println!("A-MAJ-ORDRE-FORME:{}", maj(public, json!({ "endpoint": "http://10.0.0.6:8000", "api_shape": "bogus" })).await);
        println!("A-MAJ-INCONNU:{}", maj(999_999, json!({ "endpoint": "http://10.0.0.6:8000" })).await);
        // Le verrou de la base au point de course du jugement de l'endpoint (résolution comprise).
        let verrou_vu = Arc::new(Mutex::new(None));
        {
            let (vu, base) = (verrou_vu.clone(), st.db.clone());
            crate::handlers::transaction_validee::poser_un_crochet_de_course("ia-saisie-jugee", move || *vu.lock() = Some(base.is_locked()));
        }
        println!("A-MAJ-PRIVEE:{}", maj(public, json!({ "endpoint": "http://10.0.0.6:8000" })).await);
        println!("A-MAJ-VERROU-AU-JUGEMENT:{:?}", *verrou_vu.lock());
        println!("A-MAJ-APRES:{}", endpoint_de(public));

        // Les appels d'un fournisseur stocké (tel qu'une version antérieure l'aurait laissé), seul actif.
        st.db
            .lock()
            .execute_batch(
                "UPDATE ai_provider SET enabled=0; \
                 INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
                 VALUES('bp1-ia-appel','local','openai','http://10.0.0.5:8000','',1,'{\"model\":\"bp1\"}',1,1);",
            )
            .expect("fournisseur stocké");
        let appel: i64 = st.db.lock().query_row("SELECT id FROM ai_provider WHERE name='bp1-ia-appel'", [], |r| r.get(0)).expect("id lu");
        println!("A-APPEL-ID:{appel}");
        let lecteur = basic(LECTEUR_IDENT);
        let question = r#"{"nl":"erreurs auth"}"#;
        println!("A-APPEL-PRIVE:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        st.db.lock().execute("UPDATE ai_provider SET endpoint='http://ia.bp1.test:8000' WHERE id=?1", params![appel]).expect("endpoint posé");
        println!("A-APPEL-NOM-PRIVE:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        st.db.lock().execute("UPDATE ai_provider SET endpoint='http://169.254.169.254:8000' WHERE id=?1", params![appel]).expect("endpoint posé");
        println!("A-APPEL-METADONNEES:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        let vus: Vec<String> = crate::ledger::temoin_de_l_egress::vus().into_iter().map(|(m, u)| format!("{m} {u}")).collect();
        println!("A-VUS:{}", vus.join(" | "));
        println!("{FIN}");
    }

    /// Un 500 de l'appel, corps ENTIER (phrase attendue) ; rend l'identifiant servi.
    #[cfg(feature = "ai")]
    fn echec_de_l_appel(rendu: &str, phrase: &str) -> String {
        let (s, v) = statut_et_corps(rendu);
        assert_eq!(s, 500, "500 de l'appel : {rendu}");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "identifiant servi : {rendu}");
        assert_eq!(v, json!({ "error": phrase, "id": id }), "corps entier, sans l'adresse : {rendu}");
        id
    }

    /// Les trois appels : (phrase servie, nature au journal) chacun, lignes de journal entières.
    #[cfg(feature = "ai")]
    fn juger_les_appels(a: &str, a_err: &str, prive: (&str, &str), nom_prive: (&str, &str), metadonnees: (&str, &str)) {
        let fournisseur = lu(a, "A-APPEL-ID");
        let ligne = |id: &str, nature: &str| format!("[{id}] [ia] WARN appel du fournisseur d'IA #{fournisseur} échoué, aucune proposition servie : {nature}");
        let id_prive = echec_de_l_appel(&lu(a, "A-APPEL-PRIVE"), prive.0);
        let id_nom = echec_de_l_appel(&lu(a, "A-APPEL-NOM-PRIVE"), nom_prive.0);
        let id_metadonnees = echec_de_l_appel(&lu(a, "A-APPEL-METADONNEES"), metadonnees.0);
        let lignes: Vec<String> = a_err.lines().filter(|l| l.contains("[ia] WARN appel du fournisseur")).map(str::to_string).collect();
        assert_eq!(
            lignes,
            vec![ligne(&id_prive, prive.1), ligne(&id_nom, nom_prive.1), ligne(&id_metadonnees, metadonnees.1)],
            "journal [ia], lignes entières : {a_err}"
        );
    }

    /// Ce qui ne dépend pas du réglage : l'adresse publique part, l'ordre des refus (forme d'API, absence).
    #[cfg(feature = "ai")]
    fn juger_les_saisies_ia_communes(a: &str) {
        assert_eq!(statut(&lu(a, "A-CREATION-PUBLIQUE")), 200, "endpoint public admis");
        assert_eq!(statut_et_corps(&lu(a, "A-MAJ-ORDRE-FORME")), refus_400(PHRASE_FORME), "la forme d'API garde sa cause");
        assert_eq!(statut_et_corps(&lu(a, "A-MAJ-INCONNU")), (404, json!({ "error": "provider introuvable" })), "absence : le 404 d'avant");
        assert_eq!(lu(a, "A-MAJ-VERROU-AU-JUGEMENT"), "Some(false)", "modification : l'endpoint est jugé hors du verrou de la base");
    }

    /// (C1) DÉFAUT : saisie privée refusée (création, preset, modification, rien d'écrit) ; l'appel d'un fournisseur
    /// stocké sur adresse privée sert la phrase qui nomme les réglages, la nature aussi ; la cible des métadonnées garde
    /// la phrase et la nature générales.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bp1_ia_prive_refuse_a_la_saisie_et_le_refus_de_l_appel_nomme_ses_reglages() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_bp1_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_ia_prive_refuse_a_la_saisie_et_le_refus_de_l_appel_nomme_ses_reglages"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_IA, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_AI_ENABLE", "1").env("PLUME_AI_ALLOW_CLOUD", "1");
        let (a, a_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_ia_communes(&a);
        // L'ordre des refus, dans un second enfant lancé SANS `PLUME_AI_ALLOW_CLOUD` (aucun test ne mute l'environnement).
        let mut sans_cloud = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        sans_cloud.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_ia_prive_refuse_a_la_saisie_et_le_refus_de_l_appel_nomme_ses_reglages"));
        vider_l_environnement_plume(&mut sans_cloud);
        sans_cloud.env_remove("PLUME_AI_ALLOW_CLOUD").env(ENFANT_IA, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_AI_ENABLE", "1");
        let (ordre, _) = sortie_de(sans_cloud.output().expect("ré-exécution du binaire de test"));
        assert_eq!(statut_et_corps(&lu(&ordre, "A-ORDRE-CLOUD")), (403, json!({ "error": PHRASE_CLOUD })), "la garde cloud garde sa cause");
        let refus = refus_400(PHRASE_SAISIE_IA);
        assert_eq!(statut_et_corps(&lu(&a, "A-CREATION-PRIVEE")), refus, "création privée refusée");
        assert_eq!(statut_et_corps(&lu(&a, "A-PRESET-NOM-PRIVE")), refus, "from-preset : nom vers le privé refusé");
        assert_eq!(statut_et_corps(&lu(&a, "A-MAJ-PRIVEE")), refus, "modification vers le privé refusée");
        assert_eq!(lu(&a, "A-MAJ-APRES"), "http://192.0.2.10:8000", "rien n'est écrit");
        juger_les_appels(&a, &a_err, (PHRASE_APPEL_PRIVE, NATURE_IA_PRIVEE), (PHRASE_APPEL_PRIVE, NATURE_IA_PRIVEE), (PHRASE_APPEL, NATURE_IA_SSRF));
        assert_eq!(lu(&a, "A-VUS"), "", "aucun appel n'atteint le réseau");
    }

    /// (C2) `PLUME_SSRF_ALLOW=10.0.0.5` : l'adresse listée passe, à la saisie et à l'appel ; le nom vers 10.0.0.9 non.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bp1_ia_prive_admis_quand_l_adresse_est_listee() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_bp1_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_ia_prive_admis_quand_l_adresse_est_listee"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT_IA, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_AI_ENABLE", "1")
            .env("PLUME_AI_ALLOW_CLOUD", "1")
            .env("PLUME_SSRF_ALLOW", "10.0.0.5");
        let (b, b_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_ia_communes(&b);
        let refus = refus_400(PHRASE_SAISIE_IA);
        assert_eq!(statut(&lu(&b, "A-CREATION-PRIVEE")), 200, "adresse listée admise à la saisie");
        assert_eq!(statut_et_corps(&lu(&b, "A-PRESET-NOM-PRIVE")), refus, "nom vers 10.0.0.9 non listée");
        assert_eq!(statut_et_corps(&lu(&b, "A-MAJ-PRIVEE")), refus, "voisine 10.0.0.6 refusée");
        assert_eq!(lu(&b, "A-MAJ-APRES"), "http://192.0.2.10:8000");
        juger_les_appels(&b, &b_err, (PHRASE_APPEL, NATURE_IA_ADMIS), (PHRASE_APPEL_PRIVE, NATURE_IA_PRIVEE), (PHRASE_APPEL, NATURE_IA_SSRF));
        assert_eq!(lu(&b, "A-VUS"), "POST http://10.0.0.5:8000/v1/chat/completions", "seule l'adresse listée part");
    }

    /// (C3) `PLUME_SSRF_BLOCK_PRIVATE=0` : le privé passe partout ; la cible des métadonnées reste refusée à l'appel.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bp1_ia_prive_admis_sous_la_politique_admises_partout() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_bp1_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bp1_ia_prive_admis_sous_la_politique_admises_partout"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT_IA, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_AI_ENABLE", "1")
            .env("PLUME_AI_ALLOW_CLOUD", "1")
            .env("PLUME_SSRF_BLOCK_PRIVATE", "0");
        let (c, c_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_ia_communes(&c);
        assert_eq!(statut(&lu(&c, "A-CREATION-PRIVEE")), 200);
        assert_eq!(statut(&lu(&c, "A-PRESET-NOM-PRIVE")), 200);
        assert_eq!(statut_et_corps(&lu(&c, "A-MAJ-PRIVEE")), (200, json!({ "ok": true })));
        assert_eq!(lu(&c, "A-MAJ-APRES"), "http://10.0.0.6:8000", "la modification admise est écrite");
        juger_les_appels(&c, &c_err, (PHRASE_APPEL, NATURE_IA_ADMIS), (PHRASE_APPEL, NATURE_IA_ADMIS), (PHRASE_APPEL, NATURE_IA_SSRF));
        assert_eq!(
            lu(&c, "A-VUS"),
            "POST http://10.0.0.5:8000/v1/chat/completions | POST http://ia.bp1.test:8000/v1/chat/completions",
            "les appels admis, dans l'ordre"
        );
    }
}
