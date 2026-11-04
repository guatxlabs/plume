// =====================================================================================
// `P7.20-a` — LES FOURNISSEURS D'IDENTITÉ ET D'IA SONT JUGÉS DE L'API (décision de l'exploitant du 2026-11-03).
//
// LE DÉFAUT, MESURÉ SUR 0afef585 : `ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA` valait `Configuration`
// (daemon/src/ledger.rs:1474) : sans `PLUME_SSRF_BLOCK_PRIVATE`, un fournisseur d'identité OIDC ou d'IA créé par l'API
// sur une adresse privée (10/8, 172.16/12, 192.168/16) était APPELÉ — découverte, JWKS, point de jeton, inférence —,
// quand un connecteur, une destination ou un canal saisi par l'API était refusé. Le site unique vaut désormais `Api`, la
// règle « endpoint de découverte qui partage l'hôte et le port = configuration » est retirée (ses deux bras rendaient
// `Api`), et la nature journalisée d'une adresse privée refusée nomme les réglages qui lèvent le refus
// (`NATURE_DU_REFUS_D_ADRESSE_PRIVEE`, daemon/src/handlers/idp.rs).
//
// LES TÉMOINS, PAR LA VRAIE CHAÎNE (sous-processus : la politique et la liste sont figées au premier usage), le réseau
// remplacé par le témoin de l'égress (`appel_reseau_apres_la_garde`, aucune connexion) :
// (1) IdP, suite par défaut : création PAR LA ROUTE (`POST /api/idp/providers`, administrateur et secret des gestes),
//     puis `GET /api/auth/oidc/{nom}/start` — la découverte réelle ; modification par la route (`POST
//     /api/idp/providers/{id}`, issuer voisin) puis démarrage ; un IdP à issuer PUBLIC créé et démarré ; et les fonctions
//     qu'appelle `oidc_callback` pour les JWKS et le point de jeton (`jwks_du_fournisseur`, `echange_au_point_de_jeton`,
//     appel tenu à l'octet par `routes_publiques_de_connexion_sans_texte_reseau.rs` et
//     `compte_au_journal_du_second_facteur_et_refus_de_l_echange_de_code.rs`), plus `oidc_endpoints_for` dont l'erreur
//     est le refus de la garde. Trois réglages : (a) défaut — le privé refusé, le refus de la garde nomme
//     `PLUME_SSRF_ALLOW` et `PLUME_SSRF_BLOCK_PRIVATE=0`, la route sert le 502 de la découverte (corps entier) et le
//     journal `[idp]` nomme les mêmes réglages (ligne entière), rien ne part vers le privé ; (b) `PLUME_SSRF_ALLOW=10.0.0.5`
//     — l'hôte listé part, l'issuer voisin de la modification reste refusé ; (c) `PLUME_SSRF_BLOCK_PRIVATE=0` — tout part.
//     (e) l'issuer public part sous chacun des trois.
// (2) IA, sous `--features ai` : création par la route (`POST /api/ai/providers`), `POST /api/ai/nl2soql` (lecteur),
//     modification de l'endpoint vers le voisin puis vers une adresse PUBLIQUE, chaque fois suivie de l'appel ; et
//     `crate::ai::run_nl2soql`, l'appel que fait le gestionnaire, dont l'erreur porte le refus de la garde. Mêmes trois
//     réglages ; `PLUME_AI_ENABLE=1` et `PLUME_AI_ALLOW_CLOUD=1` (l'adresse publique est « cloud »). Un appel admis
//     atteint le témoin de l'égress, qui rend `{}` : la route sert alors son 500 (complétion vide), et seule la NATURE du
//     journal `[ia]` (et la liste des appels vus) distingue l'appel admis du refus de la garde.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` par `VERIF_MUT`, retirés avant le commit), chacun vu ROUGE : `M_CONST_CONFIG`
// (le site unique remis à `Configuration`) rougit (1a) et (2a) ; `M_IDP_DECOUVERTE_SANS_GARDE`, `M_IDP_JWKS_SANS_GARDE`,
// `M_IDP_JETON_SANS_GARDE` (une garde du fournisseur d'identité sautée) et `M_NATURE_SANS_LEVIERS` (la nature d'avant,
// « SSRF ») rougissent (1a) ; `M_IA_SANS_GARDE` (la garde de l'inférence sautée) rougit (2a).
//
// CORRECTION APRÈS VÉRIFICATION (défauts relevés par un vérificateur indépendant) :
// - un endpoint RENDU par le document de découverte n'était plus témoin d'être jugé sur sa PROPRE adresse : les mutants
//   `V_JWKS_JUGE_DECOUVERTE` et `V_JETON_JUGE_DECOUVERTE` (la garde de l'étape juge l'URL de découverte au lieu de son
//   endpoint) restaient verts. L'enfant (1) joue désormais un issuer sur 10.0.0.5 dont le document désigne des JWKS sur
//   169.254.169.254 et un point de jeton sur 10.0.0.6, et les mêmes hôtes croisés sous l'issuer 10.0.0.5 : refusés sous
//   `PLUME_SSRF_ALLOW=10.0.0.5` (1b), chacun sur sa propre adresse (1a), la cible des métadonnées sous toute politique
//   (1c). Les deux mutants rougissent (1a) et (1b).
// - (3) la ligne `[ssrf]` du démarrage disait « fournisseur d'identité » sans « OIDC », alors que la connexion d'un
//   fournisseur LDAP à son annuaire n'est pas jugée (daemon/src/idp/ldap.rs) : chaque ligne dit « OIDC » et nomme ce
//   reste. Et elle suit de nouveau le site unique (`ligne_de_la_politique_selon_l_origine_des_fournisseurs`) au lieu
//   d'être écrite en dur. `M_LIGNE_EN_DUR` (l'origine ignorée), `M_LIGNE_SANS_OIDC` (l'ancien texte) et
//   `M_LIGNE_SANS_LDAP` (le reste tu) rougissent (3a).
//
// INVERSÉ PAR LA VAGUE SUIVANTE (fournisseurs_refuses_a_la_saisie_et_annuaire_ldap_garde.rs) : la saisie d'un fournisseur
// sur adresse privée est désormais refusée (400) dès la saisie. Les enfants (1) et (2) gardent leur objet — l'APPEL d'un
// fournisseur déjà stocké sur adresse privée — : quand la route refuse la création ou la modification, l'enfant pose la
// même ligne à même la table (`poser_si_refusee`), comme l'aurait laissée une version antérieure, et
// `juger_les_saisies_idp` / `juger_l_ia` attendent le refus sous le réglage qui le prononce. La ligne `[ssrf]` du
// démarrage ne dit plus la connexion LDAP hors de la garde (3a inversé) : elle est jugée (`ldap_garde_de_sortie`).
//
// CE QU'IL NE TIENT PAS : `oidc_callback` n'est pas joué de bout en bout (état signé, code, jeton d'identité) — ses
// appels sont tenus par les instruments de source cités ; l'inventaire du démarrage ne liste pas les fournisseurs
// stockés sur adresse privée.
// =====================================================================================
mod fournisseurs_d_identite_et_d_ia_juges_de_l_api {
    use super::*;
    use crate::ledger::temoin_de_l_egress;
    use crate::ledger::OrigineDeLaCible;

    const MODULE: &str = "tests::fournisseurs_d_identite_et_d_ia_juges_de_l_api::";
    const ADMIN_IDENT: &str = "root:rootpw1234567";
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    /// La nature `[idp]` d'une adresse privée refusée, écrite ici en littéral (jamais lue de la production).
    const NATURE_PRIVEE_ATTENDUE: &str = "SSRF: adresse privée refusée — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, \
PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    const PHRASE_SAISIE_IDP: &str = "fournisseur d'identité refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour \
un fournisseur saisi par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée";
    const PHRASE_DECOUVERTE_ATTENDUE: &str = "découverte OIDC échouée: le fournisseur d'identité n'a pas pu être joint, sa \
cible a été refusée par la garde de sortie, ou sa réponse n'est pas exploitable ; aucune session n'est posée, la cause est \
au journal du serveur sous l'identifiant de cette réponse.";
    const ISSUER_PRIVE: &str = "https://10.0.0.5";
    const ISSUER_VOISIN: &str = "https://10.0.0.6";
    const ISSUER_PUBLIC: &str = "https://192.0.2.10";
    /// Un issuer sur l'hôte privé 10.0.0.5 dont le document de découverte DÉSIGNE d'autres hôtes : JWKS sur la cible des
    /// métadonnées du nuage, point de jeton sur l'hôte voisin 10.0.0.6 (correction du lot, défaut relevé : sans ce cas,
    /// une garde qui jugerait l'URL de découverte au lieu de l'endpoint restait verte).
    const ISSUER_DETOURNE: &str = "https://10.0.0.5/detourne";
    const JWKS_METADONNEES: &str = "https://169.254.169.254/jwks";
    const JETON_VOISIN: &str = "https://10.0.0.6/token";
    const REFUS_METADONNEES: &str = "SSRF: cible interne interdite (169.254.169.254)";
    const FIN_IDP: &str = "BL1-IDP-A-JOUE";
    const ENFANT_IDP: &str = "BL1_ENFANT_IDP";

    fn basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    fn refus_prive(hote: &str) -> String {
        format!("SSRF: adresse privée refusée ({hote}) — {LEVIERS}")
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

    async fn demarrer(addr: std::net::SocketAddr, nom: &str) -> String {
        let (code, brut) = router_probe_corps(addr, "GET", &format!("/api/auth/oidc/{nom}/start"), None, &[]).await;
        format!("{code} {}", corps_de(&brut))
    }

    fn issue<T>(r: Result<T, String>) -> String {
        match r {
            Ok(_) => "admis".to_string(),
            Err(e) => e,
        }
    }

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> String {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
        trouves[0].to_string()
    }

    /// La ligne `CLE:` est-elle absente de la sortie de l'enfant ?
    fn absent(stdout: &str, cle: &str) -> bool {
        let prefixe = format!("{cle}:");
        !stdout.lines().any(|l| l.starts_with(prefixe.as_str()))
    }

    /// `<statut> <corps JSON>` -> (statut, corps lu).
    fn statut_et_corps(rendu: &str) -> (u16, Value) {
        let (s, c) = rendu.split_once(' ').unwrap_or((rendu, ""));
        (s.parse().unwrap_or(0), serde_json::from_str(c).unwrap_or(Value::Null))
    }

    /// Un 502 de la découverte, corps ENTIER : la phrase et l'identifiant servi, rien d'autre ; rend l'identifiant.
    fn refus_de_la_decouverte(rendu: &str) -> String {
        let (s, v) = statut_et_corps(rendu);
        assert_eq!(s, 502, "502 de la découverte : {rendu}");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(!id.is_empty(), "identifiant servi : {rendu}");
        assert_eq!(v, json!({ "error": PHRASE_DECOUVERTE_ATTENDUE, "id": id }), "corps entier : {rendu}");
        id
    }

    fn ligne_idp(id: &str, fournisseur: i64) -> String {
        format!("[{id}] [idp] WARN connexion OIDC (fournisseur #{fournisseur}) échouée à l'étape « découverte » : {NATURE_PRIVEE_ATTENDUE}")
    }

    fn lignes_idp(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.contains("[idp] WARN")).map(str::to_string).collect()
    }

    fn vider_l_environnement_plume(commande: &mut std::process::Command) {
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
    }

    /// L'enfant du fournisseur d'identité : routes réelles, découverte interceptée.
    async fn jouer_l_idp_dans_l_enfant() {
        println!(); // la première ligne de l'enfant suit l'en-tête de libtest
        let _arme = temoin_de_l_egress::armer(|_m, url| {
            let corps = match url.strip_suffix("/.well-known/openid-configuration") {
                Some(base) if base == ISSUER_DETOURNE => json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/auth"),
                    "token_endpoint": JETON_VOISIN,
                    "jwks_uri": JWKS_METADONNEES,
                })
                .to_string(),
                Some(base) => json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/auth"),
                    "token_endpoint": format!("{base}/token"),
                    "jwks_uri": format!("{base}/jwks"),
                })
                .to_string(),
                None => r#"{"keys":[]}"#.to_string(),
            };
            Ok(temoin_de_l_egress::reponse(200, &[], &corps))
        });
        let (mut st, _base) = router_test_state("bl1-idp");
        st.secret_des_gestes = Arc::new(crate::secret_des_gestes::SourceDuSecretDesGestes::Empreinte(crate::secret_des_gestes::empreinte_de_test()));
        let addr = router_serve(st.clone()).await;
        let admin = basic(ADMIN_IDENT);
        let secret = [(crate::secret_des_gestes::ENTETE_DU_SECRET_DES_GESTES, crate::secret_des_gestes::SECRET_DES_GESTES_DE_TEST)];
        let config = |issuer: &str| format!(r#"{{"issuer":"{issuer}","client_id":"bl1","redirect_uri":"https://soc.exemple.test/api/auth/oidc/callback"}}"#);
        let creer = |nom: &str, issuer: &str| format!(r#"{{"name":"{nom}","kind":"oidc","enabled":true,"config":{}}}"#, config(issuer));

        let creation = envoi(addr, "POST", "/api/idp/providers", Some(&admin), &secret, &creer("bl1-prive", ISSUER_PRIVE)).await;
        println!("BL1-CREATION-PRIVE:{creation}");
        poser_si_refusee(&st, &creation, "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES('bl1-prive','oidc',1,?1,'',1,1)", &config(ISSUER_PRIVE));
        println!("BL1-DEMARRAGE-PRIVE:{}", demarrer(addr, "bl1-prive").await);
        let maj = format!(r#"{{"config":{}}}"#, config(ISSUER_VOISIN));
        let modification = envoi(addr, "POST", "/api/idp/providers/1", Some(&admin), &secret, &maj).await;
        println!("BL1-MAJ-VOISIN:{modification}");
        poser_si_refusee(&st, &modification, "UPDATE idp_provider SET config_json=?1 WHERE id=1", &config(ISSUER_VOISIN));
        println!("BL1-DEMARRAGE-VOISIN:{}", demarrer(addr, "bl1-prive").await);
        println!("BL1-CREATION-PUBLIC:{}", envoi(addr, "POST", "/api/idp/providers", Some(&admin), &secret, &creer("bl1-public", ISSUER_PUBLIC)).await);
        println!("BL1-DEMARRAGE-PUBLIC:{}", demarrer(addr, "bl1-public").await);

        let cfg = OidcCfg::from_json(&json!({ "issuer": ISSUER_PRIVE, "client_id": "bl1", "redirect_uri": "https://soc.exemple.test/cb" }));
        println!("BL1-DECOUVERTE:{}", issue(oidc_endpoints_for(&cfg)));
        println!("BL1-JWKS:{}", issue(jwks_du_fournisseur(&cfg, "https://10.0.0.5/jwks")));
        println!("BL1-JETON:{}", issue(echange_au_point_de_jeton(&cfg, "https://10.0.0.5/token", "corps")));
        // Les endpoints RENDUS par un document de découverte, chacun jugé sur sa propre adresse (le chemin
        // d'`oidc_callback` : `oidc_endpoints_for`, puis l'endpoint rendu passé à la fonction de l'étape).
        let detourne = OidcCfg::from_json(&json!({ "issuer": ISSUER_DETOURNE, "client_id": "bl1", "redirect_uri": "https://soc.exemple.test/cb" }));
        match oidc_endpoints_for(&detourne) {
            Ok(ep) => {
                println!("BL1-DETOURNE-DECOUVERTE:admis {} {}", ep.jwks_uri, ep.token_endpoint);
                println!("BL1-JWKS-RENDU-METADONNEES:{}", issue(jwks_du_fournisseur(&detourne, &ep.jwks_uri)));
                println!("BL1-JETON-RENDU-VOISIN:{}", issue(echange_au_point_de_jeton(&detourne, &ep.token_endpoint, "corps")));
            }
            Err(e) => println!("BL1-DETOURNE-DECOUVERTE:{e}"),
        }
        // Les mêmes hôtes croisés, sous la configuration de l'issuer 10.0.0.5 (listé en (1b)).
        println!("BL1-JWKS-VOISIN:{}", issue(jwks_du_fournisseur(&cfg, "https://10.0.0.6/jwks")));
        println!("BL1-JETON-METADONNEES:{}", issue(echange_au_point_de_jeton(&cfg, "https://169.254.169.254/token", "corps")));
        let vus: Vec<String> = temoin_de_l_egress::vus().into_iter().map(|(m, u)| format!("{m} {u}")).collect();
        println!("BL1-VUS:{}", vus.join(" | "));
        println!("{FIN_IDP}");
    }

    /// Ce que l'enfant a rendu : (stdout, stderr), après les contrôles de fin.
    fn sortie_de(sortie: std::process::Output) -> (String, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN_IDP) || stdout.contains(FIN_IA), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    /// INVERSÉ : la création et la modification vers le privé sont refusées à la saisie (400) sous le réglage qui
    /// refuse leur adresse (`PHRASE_SAISIE_IDP`), admises sinon ; l'issuer public passe toujours.
    fn juger_les_saisies_idp(a: &str, creation_refusee: bool, modification_refusee: bool) {
        let refus = (400, json!({ "error": PHRASE_SAISIE_IDP }));
        let creation = if creation_refusee { refus.clone() } else { (200, json!({ "id": 1, "enabled": true })) };
        let modification = if modification_refusee { refus } else { (200, json!({ "ok": true })) };
        assert_eq!(statut_et_corps(&lu(a, "BL1-CREATION-PRIVE")), creation, "création par la route");
        assert_eq!(statut_et_corps(&lu(a, "BL1-MAJ-VOISIN")), modification, "modification par la route");
        assert_eq!(statut_et_corps(&lu(a, "BL1-CREATION-PUBLIC")), (200, json!({ "id": 2, "enabled": true })));
    }

    /// La saisie refusée par la route : la même ligne posée à même la table, comme une version antérieure l'aurait
    /// laissée, pour juger l'APPEL d'un fournisseur stocké sur adresse privée.
    fn poser_si_refusee(st: &AppState, rendu: &str, sql: &str, valeur: &str) {
        if !rendu.starts_with("200 ") {
            st.db.lock().execute(sql, params![valeur]).expect("ligne d'avant posée");
        }
    }

    /// (1a) DÉFAUT : l'issuer privé refusé à la découverte réelle, le refus nomme ses réglages, rien ne part vers le
    /// privé ; l'issuer public part.
    #[tokio::test]
    async fn bl1_idp_prive_refuse_par_defaut_et_le_refus_nomme_ses_reglages() {
        if std::env::var(ENFANT_IDP).is_ok() {
            jouer_l_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_idp_prive_refuse_par_defaut_et_le_refus_nomme_ses_reglages"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_IDP, "1").env("PLUME_CONFIG", "/nonexistent");
        let (a, a_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_idp(&a, true, true);
        let id_prive = refus_de_la_decouverte(&lu(&a, "BL1-DEMARRAGE-PRIVE"));
        let id_voisin = refus_de_la_decouverte(&lu(&a, "BL1-DEMARRAGE-VOISIN"));
        assert_eq!(lignes_idp(&a_err), vec![ligne_idp(&id_prive, 1), ligne_idp(&id_voisin, 1)], "journal [idp], lignes entières : {a_err}");
        assert_eq!(lu(&a, "BL1-DEMARRAGE-PUBLIC"), "302 ", "issuer public : la découverte part, redirection vers l'IdP");
        assert_eq!(lu(&a, "BL1-DECOUVERTE"), refus_prive("10.0.0.5"), "le refus de la garde nomme ses réglages");
        assert_eq!(lu(&a, "BL1-JWKS"), refus_prive("10.0.0.5"), "JWKS privés refusés");
        assert_eq!(lu(&a, "BL1-JETON"), refus_prive("10.0.0.5"), "point de jeton privé refusé");
        assert_eq!(lu(&a, "BL1-DETOURNE-DECOUVERTE"), refus_prive("10.0.0.5"), "découverte de l'issuer détourné refusée");
        assert!(absent(&a, "BL1-JWKS-RENDU-METADONNEES") && absent(&a, "BL1-JETON-RENDU-VOISIN"), "aucun endpoint rendu : {a}");
        assert_eq!(lu(&a, "BL1-JWKS-VOISIN"), refus_prive("10.0.0.6"), "JWKS jugés sur leur propre hôte (10.0.0.6), pas sur l'issuer");
        assert_eq!(lu(&a, "BL1-JETON-METADONNEES"), REFUS_METADONNEES, "point de jeton jugé sur sa propre adresse");
        assert_eq!(lu(&a, "BL1-VUS"), "GET https://192.0.2.10/.well-known/openid-configuration", "seul le public atteint le réseau");
    }

    /// (1b) `PLUME_SSRF_ALLOW=10.0.0.5` : l'hôte listé part sur chaque appel ; l'issuer voisin de la modification reste
    /// refusé (la modification est relue au démarrage suivant).
    #[tokio::test]
    async fn bl1_idp_prive_admis_quand_l_hote_est_liste() {
        if std::env::var(ENFANT_IDP).is_ok() {
            jouer_l_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_idp_prive_admis_quand_l_hote_est_liste"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_IDP, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_ALLOW", "10.0.0.5");
        let (b, b_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_idp(&b, false, true);
        assert_eq!(lu(&b, "BL1-DEMARRAGE-PRIVE"), "302 ", "hôte listé : la découverte part");
        let id_voisin = refus_de_la_decouverte(&lu(&b, "BL1-DEMARRAGE-VOISIN"));
        assert_eq!(lignes_idp(&b_err), vec![ligne_idp(&id_voisin, 1)], "seul le voisin est refusé : {b_err}");
        assert_eq!(lu(&b, "BL1-DEMARRAGE-PUBLIC"), "302 ");
        assert_eq!(lu(&b, "BL1-DECOUVERTE"), "admis");
        assert_eq!(lu(&b, "BL1-JWKS"), "admis");
        assert_eq!(lu(&b, "BL1-JETON"), "admis");
        // Le document de l'hôte listé est admis ; les endpoints qu'il désigne ailleurs restent refusés, chacun sur sa
        // propre adresse — la cible des métadonnées du nuage comme l'hôte voisin non listé.
        assert_eq!(lu(&b, "BL1-DETOURNE-DECOUVERTE"), format!("admis {JWKS_METADONNEES} {JETON_VOISIN}"), "document de l'hôte listé admis");
        assert_eq!(lu(&b, "BL1-JWKS-RENDU-METADONNEES"), REFUS_METADONNEES, "JWKS rendus vers 169.254.169.254 : refusés");
        assert_eq!(lu(&b, "BL1-JETON-RENDU-VOISIN"), refus_prive("10.0.0.6"), "point de jeton rendu vers l'hôte voisin : refusé");
        assert_eq!(lu(&b, "BL1-JWKS-VOISIN"), refus_prive("10.0.0.6"), "JWKS sur l'hôte voisin : refusés");
        assert_eq!(lu(&b, "BL1-JETON-METADONNEES"), REFUS_METADONNEES, "point de jeton sur 169.254.169.254 : refusé");
        assert_eq!(
            lu(&b, "BL1-VUS"),
            "GET https://10.0.0.5/.well-known/openid-configuration | GET https://192.0.2.10/.well-known/openid-configuration | \
GET https://10.0.0.5/.well-known/openid-configuration | GET https://10.0.0.5/jwks | POST https://10.0.0.5/token | \
GET https://10.0.0.5/detourne/.well-known/openid-configuration",
            "les appels admis, dans l'ordre"
        );
    }

    /// (1c) `PLUME_SSRF_BLOCK_PRIVATE=0` : adresses privées admises partout, voisin compris.
    #[tokio::test]
    async fn bl1_idp_prive_admis_sous_la_politique_admises_partout() {
        if std::env::var(ENFANT_IDP).is_ok() {
            jouer_l_idp_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_idp_prive_admis_sous_la_politique_admises_partout"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_IDP, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_SSRF_BLOCK_PRIVATE", "0");
        let (c, c_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_les_saisies_idp(&c, false, false);
        assert_eq!(lu(&c, "BL1-DEMARRAGE-PRIVE"), "302 ");
        assert_eq!(lu(&c, "BL1-DEMARRAGE-VOISIN"), "302 ");
        assert_eq!(lu(&c, "BL1-DEMARRAGE-PUBLIC"), "302 ");
        assert!(lignes_idp(&c_err).is_empty(), "aucun refus : {c_err}");
        assert_eq!(lu(&c, "BL1-DECOUVERTE"), "admis");
        assert_eq!(lu(&c, "BL1-JWKS"), "admis");
        assert_eq!(lu(&c, "BL1-JETON"), "admis");
        // Privé admis partout, la cible des métadonnées du nuage reste refusée.
        assert_eq!(lu(&c, "BL1-DETOURNE-DECOUVERTE"), format!("admis {JWKS_METADONNEES} {JETON_VOISIN}"));
        assert_eq!(lu(&c, "BL1-JWKS-RENDU-METADONNEES"), REFUS_METADONNEES, "169.254.169.254 refusé sous toute politique");
        assert_eq!(lu(&c, "BL1-JETON-RENDU-VOISIN"), "admis");
        assert_eq!(lu(&c, "BL1-JWKS-VOISIN"), "admis");
        assert_eq!(lu(&c, "BL1-JETON-METADONNEES"), REFUS_METADONNEES);
        assert_eq!(
            lu(&c, "BL1-VUS"),
            "GET https://10.0.0.5/.well-known/openid-configuration | GET https://10.0.0.6/.well-known/openid-configuration | \
GET https://192.0.2.10/.well-known/openid-configuration | GET https://10.0.0.5/.well-known/openid-configuration | \
GET https://10.0.0.5/jwks | POST https://10.0.0.5/token | GET https://10.0.0.5/detourne/.well-known/openid-configuration | \
POST https://10.0.0.6/token | GET https://10.0.0.6/jwks",
            "les appels admis, dans l'ordre"
        );
    }

    // ------------------------------------------------------------------ (3) la ligne `[ssrf]` du démarrage

    /// Les six lignes attendues, écrites ici en littéral : (politique, origine des fournisseurs) -> ligne. INVERSÉES : la
    /// connexion d'un fournisseur LDAP à son annuaire est jugée (`ldap_garde_de_sortie`, daemon/src/idp/ldap.rs) ; la
    /// ligne la range avec l'OIDC (« (OIDC ou LDAP) ») et ne dit plus de reste hors de la garde.
    fn lignes_attendues() -> Vec<(crate::ledger::PolitiqueDesAdressesPrivees, OrigineDeLaCible, String)> {
        use crate::ledger::PolitiqueDesAdressesPrivees::{AdmisesPartout, BloqueesPartout, ParDefaut};
        let api = "un canal, une destination, un connecteur ou un fournisseur d'identité (OIDC ou LDAP) ou d'IA saisi par l'API";
        let api_sans_fournisseurs = "un canal, une destination ou un connecteur saisi par l'API";
        let leviers = "PLUME_SSRF_BLOCK_PRIVATE=0 les admet partout, =1 les refuse partout, PLUME_SSRF_ALLOW exempte un hôte ou un CIDR";
        let plages = "adresses privées (10/8, 172.16/12, 192.168/16)";
        vec![
            (ParDefaut, OrigineDeLaCible::Api, format!("[ssrf] {plages} : REFUSÉES pour {api} ; ADMISES pour le canal semé par \
PLUME_NOTIFY_NTFY_URL (son URL exacte) et les objets écrits en surcouche config.d (leurs propres cibles) — {leviers}")),
            (ParDefaut, OrigineDeLaCible::Configuration, format!("[ssrf] {plages} : REFUSÉES pour {api_sans_fournisseurs} ; ADMISES \
pour le canal semé par PLUME_NOTIFY_NTFY_URL (son URL exacte), les objets écrits en surcouche config.d (leurs propres cibles) et \
les fournisseurs d'identité (OIDC et LDAP) et d'IA — {leviers}")),
            (BloqueesPartout, OrigineDeLaCible::Api, format!("[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 1 : {plages} REFUSÉES pour \
toute cible, canal semé par PLUME_NOTIFY_NTFY_URL et surcouches config.d compris — PLUME_SSRF_ALLOW exempte un hôte ou un CIDR")),
            (BloqueesPartout, OrigineDeLaCible::Configuration, format!("[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 1 : {plages} REFUSÉES \
pour toute cible, canal semé par PLUME_NOTIFY_NTFY_URL, surcouches config.d et fournisseurs d'identité (OIDC et LDAP) et d'IA \
compris — PLUME_SSRF_ALLOW exempte un hôte ou un CIDR")),
            (AdmisesPartout, OrigineDeLaCible::Api, format!("[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 0 : {plages} ADMISES pour toute \
cible, y compris {api}")),
            (AdmisesPartout, OrigineDeLaCible::Configuration, format!("[ssrf] PLUME_SSRF_BLOCK_PRIVATE posé à 0 : {plages} ADMISES \
pour toute cible, y compris {api_sans_fournisseurs}")),
        ]
    }

    /// (3a) INVERSÉ : la ligne range LDAP avec l'OIDC (sa connexion est jugée) et ne nomme plus de reste, sous chaque
    /// politique ; elle place les fournisseurs selon leur origine — et la ligne écrite au démarrage est celle de
    /// l'origine que fixe le site unique : remettre la constante à `Configuration` changerait la ligne avec elle.
    #[test]
    fn bl1_la_ligne_du_demarrage_suit_l_origine_des_fournisseurs_et_range_ldap_avec_l_oidc() {
        use crate::ledger::{
            ligne_de_la_politique_des_adresses_privees, ligne_de_la_politique_selon_l_origine_des_fournisseurs,
            ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA,
        };
        for (politique, origine, attendue) in lignes_attendues() {
            assert_eq!(ligne_de_la_politique_selon_l_origine_des_fournisseurs(politique, origine), attendue, "{politique:?} / {origine:?}");
            if origine == ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA {
                assert_eq!(ligne_de_la_politique_des_adresses_privees(politique), attendue, "ligne du démarrage, {politique:?}");
            }
        }
        assert_eq!(ORIGINE_DES_FOURNISSEURS_D_IDENTITE_ET_D_IA, OrigineDeLaCible::Api, "contrôle : la ligne écrite est celle de l'API");
    }

    // ------------------------------------------------------------------ (2) le fournisseur d'IA (feature `ai`)

    const FIN_IA: &str = "BL1-IA-A-JOUE";
    #[cfg(feature = "ai")]
    const ENFANT_IA: &str = "BL1_ENFANT_IA";
    #[cfg(feature = "ai")]
    const LECTEUR_IDENT: &str = "vwr:viewerpw12345";
    #[cfg(feature = "ai")]
    const ENDPOINT_PRIVE: &str = "http://10.0.0.5:8000";
    #[cfg(feature = "ai")]
    const ENDPOINT_VOISIN: &str = "http://10.0.0.6:8000";
    #[cfg(feature = "ai")]
    const ENDPOINT_PUBLIC: &str = "http://192.0.2.10:8000";
    #[cfg(feature = "ai")]
    const PHRASE_APPEL_ATTENDUE: &str = "appel au fournisseur d'IA échoué : aucune proposition servie (la nature de l'échec \
est au journal du démon, sous l'identifiant servi)";
    #[cfg(feature = "ai")]
    const PHRASE_SAISIE_IA: &str = "fournisseur d'IA refusé : adresse privée (10/8, 172.16/12, 192.168/16) pour un \
fournisseur saisi par l'API — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse \
privée";
    #[cfg(feature = "ai")]
    const PHRASE_APPEL_PRIVE_ATTENDUE: &str = "appel au fournisseur d'IA refusé : son adresse est privée (10/8, 172.16/12, \
192.168/16) et la garde de sortie la refuse avant toute connexion — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, \
PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée ; aucune proposition servie (la nature de l'échec est au journal du \
démon, sous l'identifiant servi)";
    #[cfg(feature = "ai")]
    const NATURE_IA_REFUS: &str = "adresse privée du fournisseur (10/8, 172.16/12, 192.168/16) refusée par la garde SSRF, \
avant toute connexion — PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";
    #[cfg(feature = "ai")]
    const NATURE_IA_ADMIS: &str = "réponse du fournisseur non JSON ou complétion vide";

    /// L'enfant du fournisseur d'IA : routes réelles, inférence interceptée (réponse `{}`, complétion vide).
    #[cfg(feature = "ai")]
    async fn jouer_l_ia_dans_l_enfant() {
        println!();
        let _arme = temoin_de_l_egress::armer(|_m, _u| Ok(temoin_de_l_egress::reponse(200, &[], "{}")));
        let (st, _base) = router_test_state("bl1-ia");
        let addr = router_serve(st.clone()).await;
        let admin = basic(ADMIN_IDENT);
        let lecteur = basic(LECTEUR_IDENT);
        let creation = format!(r#"{{"name":"bl1-ia","api_shape":"openai","endpoint":"{ENDPOINT_PRIVE}","enabled":true,"config":{{"model":"bl1"}}}}"#);
        let question = r#"{"nl":"erreurs auth"}"#;
        let creation = envoi(addr, "POST", "/api/ai/providers", Some(&admin), &[], &creation).await;
        println!("BL1-IA-CREATION:{creation}");
        poser_si_refusee(
            &st,
            &creation,
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
             VALUES('bl1-ia','','openai',?1,'',1,'{\"model\":\"bl1\"}',1,1)",
            ENDPOINT_PRIVE,
        );
        println!("BL1-IA-APPEL-PRIVE:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        let maj = |e: &str| format!(r#"{{"endpoint":"{e}"}}"#);
        let modification = envoi(addr, "POST", "/api/ai/providers/1", Some(&admin), &[], &maj(ENDPOINT_VOISIN)).await;
        println!("BL1-IA-MAJ-VOISIN:{modification}");
        poser_si_refusee(&st, &modification, "UPDATE ai_provider SET endpoint=?1 WHERE id=1", ENDPOINT_VOISIN);
        println!("BL1-IA-APPEL-VOISIN:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        println!("BL1-IA-MAJ-PUBLIC:{}", envoi(addr, "POST", "/api/ai/providers/1", Some(&admin), &[], &maj(ENDPOINT_PUBLIC)).await);
        println!("BL1-IA-APPEL-PUBLIC:{}", envoi(addr, "POST", "/api/ai/nl2soql", Some(&lecteur), &[], question).await);
        let politique = guatx_core::ai::default_redaction_policy();
        let direct = crate::ai::run_nl2soql(
            ENDPOINT_PRIVE, "openai", "bl1", "", 0.0, 4096, "erreurs auth", &[], &[], &politique, 64, &|_| Err("non compilé".to_string()),
        );
        println!("BL1-IA-DIRECT:{}", issue(direct));
        let vus: Vec<String> = temoin_de_l_egress::vus().into_iter().map(|(m, u)| format!("{m} {u}")).collect();
        println!("BL1-IA-VUS:{}", vus.join(" | "));
        println!("{FIN_IA}");
    }

    /// Le 500 de l'appel, corps ENTIER ; rend l'identifiant servi. INVERSÉ : un refus d'adresse privée sert la phrase
    /// qui nomme ses réglages (`PHRASE_APPEL_PRIVE_ATTENDUE`), un appel admis la phrase générale.
    #[cfg(feature = "ai")]
    fn echec_de_l_appel(rendu: &str, nature: &str) -> String {
        let phrase = if nature == NATURE_IA_REFUS { PHRASE_APPEL_PRIVE_ATTENDUE } else { PHRASE_APPEL_ATTENDUE };
        let (s, v) = statut_et_corps(rendu);
        assert_eq!(s, 500, "500 de l'appel : {rendu}");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(!id.is_empty(), "identifiant servi : {rendu}");
        assert_eq!(v, json!({ "error": phrase, "id": id }), "corps entier : {rendu}");
        id
    }

    #[cfg(feature = "ai")]
    fn ligne_ia(id: &str, nature: &str) -> String {
        format!("[{id}] [ia] WARN appel du fournisseur d'IA #1 échoué, aucune proposition servie : {nature}")
    }

    #[cfg(feature = "ai")]
    fn lignes_ia(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.contains("[ia] WARN")).map(str::to_string).collect()
    }

    /// Les saisies par la route (INVERSÉ : refusées à la saisie sous le réglage qui refuse leur adresse), et les trois
    /// appels : (identifiant servi, nature attendue) chacun.
    #[cfg(feature = "ai")]
    fn juger_l_ia(a: &str, a_err: &str, natures: [&str; 3], creation_refusee: bool, modification_refusee: bool) {
        let refus = (400, json!({ "error": PHRASE_SAISIE_IA }));
        let creation = if creation_refusee { refus.clone() } else { (200, json!({ "id": 1, "enabled": true })) };
        let modification = if modification_refusee { refus } else { (200, json!({ "ok": true })) };
        assert_eq!(statut_et_corps(&lu(a, "BL1-IA-CREATION")), creation, "création par la route");
        assert_eq!(statut_et_corps(&lu(a, "BL1-IA-MAJ-VOISIN")), modification, "modification par la route");
        assert_eq!(statut_et_corps(&lu(a, "BL1-IA-MAJ-PUBLIC")), (200, json!({ "ok": true })));
        let ids = [
            echec_de_l_appel(&lu(a, "BL1-IA-APPEL-PRIVE"), natures[0]),
            echec_de_l_appel(&lu(a, "BL1-IA-APPEL-VOISIN"), natures[1]),
            echec_de_l_appel(&lu(a, "BL1-IA-APPEL-PUBLIC"), natures[2]),
        ];
        let attendues: Vec<String> = ids.iter().zip(natures).map(|(id, n)| ligne_ia(id, n)).collect();
        assert_eq!(lignes_ia(a_err), attendues, "journal [ia], lignes entières : {a_err}");
    }

    /// (2a) DÉFAUT : l'endpoint privé refusé par la garde à l'appel réel (route et appel du gestionnaire), le refus nomme
    /// ses réglages ; l'endpoint public part.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bl1_ia_prive_refuse_par_defaut_et_le_refus_nomme_ses_reglages() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_ia_prive_refuse_par_defaut_et_le_refus_nomme_ses_reglages"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT_IA, "1").env("PLUME_CONFIG", "/nonexistent").env("PLUME_AI_ENABLE", "1").env("PLUME_AI_ALLOW_CLOUD", "1");
        let (a, a_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_ia(&a, &a_err, [NATURE_IA_REFUS, NATURE_IA_REFUS, NATURE_IA_ADMIS], true, true);
        assert_eq!(lu(&a, "BL1-IA-DIRECT"), format!("backend IA : {}", refus_prive("10.0.0.5")), "le refus de la garde nomme ses réglages");
        assert_eq!(lu(&a, "BL1-IA-VUS"), "POST http://192.0.2.10:8000/v1/chat/completions", "seul le public atteint le réseau");
    }

    /// (2b) `PLUME_SSRF_ALLOW=10.0.0.5` : l'endpoint listé part, le voisin reste refusé.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bl1_ia_prive_admis_quand_l_hote_est_liste() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_ia_prive_admis_quand_l_hote_est_liste"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT_IA, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_AI_ENABLE", "1")
            .env("PLUME_AI_ALLOW_CLOUD", "1")
            .env("PLUME_SSRF_ALLOW", "10.0.0.5");
        let (b, b_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_ia(&b, &b_err, [NATURE_IA_ADMIS, NATURE_IA_REFUS, NATURE_IA_ADMIS], false, true);
        assert_eq!(lu(&b, "BL1-IA-DIRECT"), "réponse IA invalide : complétion vide", "l'appel admis atteint le témoin");
        assert_eq!(
            lu(&b, "BL1-IA-VUS"),
            "POST http://10.0.0.5:8000/v1/chat/completions | POST http://192.0.2.10:8000/v1/chat/completions | \
POST http://10.0.0.5:8000/v1/chat/completions",
            "les appels admis, dans l'ordre"
        );
    }

    /// (2c) `PLUME_SSRF_BLOCK_PRIVATE=0` : tout part.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn bl1_ia_prive_admis_sous_la_politique_admises_partout() {
        if std::env::var(ENFANT_IA).is_ok() {
            jouer_l_ia_dans_l_enfant().await;
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}bl1_ia_prive_admis_sous_la_politique_admises_partout"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT_IA, "1")
            .env("PLUME_CONFIG", "/nonexistent")
            .env("PLUME_AI_ENABLE", "1")
            .env("PLUME_AI_ALLOW_CLOUD", "1")
            .env("PLUME_SSRF_BLOCK_PRIVATE", "0");
        let (c, c_err) = sortie_de(commande.output().expect("ré-exécution du binaire de test"));
        juger_l_ia(&c, &c_err, [NATURE_IA_ADMIS, NATURE_IA_ADMIS, NATURE_IA_ADMIS], false, false);
        assert_eq!(lu(&c, "BL1-IA-DIRECT"), "réponse IA invalide : complétion vide");
        assert_eq!(
            lu(&c, "BL1-IA-VUS"),
            "POST http://10.0.0.5:8000/v1/chat/completions | POST http://10.0.0.6:8000/v1/chat/completions | \
POST http://192.0.2.10:8000/v1/chat/completions | POST http://10.0.0.5:8000/v1/chat/completions",
            "les appels admis, dans l'ordre"
        );
    }
}
