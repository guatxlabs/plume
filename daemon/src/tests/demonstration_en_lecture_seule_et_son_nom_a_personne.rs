// =====================================================================================
// `P10.28-i` — LA DÉMONSTRATION PUBLIQUE EST EN LECTURE SEULE, PAR SA MÉTHODE (`auth::refuser_l_ecriture_de_la_demonstration`,
//              jugée dans `apply_gates` après `rbac_gate`).
// `P10.28-j` — LE NOM DE LA DÉMONSTRATION N'EST À PERSONNE : refusé aux deux portes de l'annuaire (règle unique) quand
//              la démonstration est SERVIE, à l'assistant d'installation, et la démonstration ne s'active pas quand il
//              appartient déjà à quelqu'un (`server::activation_de_la_demonstration`) — ce qui tient aussi l'identité
//              de l'annuaire prise hors démonstration.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-29 (témoin de mesure joué sur la forme d'avant, au routeur réel,
// puis retiré) :
//  * `P10.28-i`, démonstration active, aucun identifiant : `POST /api/saved-queries` -> 200 (`{"id":1,"ok":true}`), une
//    ligne `saved_query` sous `demo` et un maillon `saved_query.create` ; `PUT /api/prefs` -> 200, une ligne `user_pref`
//    sous `demo`. `POST /api/dashboards` -> 403 « lecture seule (rôle viewer) » et un déni `plume-authz` : le rôle ne
//    tenait la lecture seule que HORS des quatre surfaces que `viewer` écrit pour lui-même. L'énoncé sous-comptait l'effet :
//    tous les visiteurs anonymes sont le même propriétaire ;
//  * `P10.28-j` : l'assistant d'installation avec `user = demo` -> 200, `user(demo, admin)` posé ; la règle des annuaires
//    rendait `Ok(())` sur `demo` (en-têtes et fédération, démonstration active ou non) et, démonstration active, l'annuaire
//    qui présente `demo` était servi `demo`/`editor` (200) ; un compte `demo` présent quand la démonstration s'active :
//    l'anonyme listait sa requête privée AVEC son texte (200) ; `PLUME_USER=demo` : l'anonyme servi sous le nom de
//    l'administrateur de configuration (200, `user: demo`). L'énoncé sous-comptait les portes (assistant, `PLUME_USER`).
//
// CORRECTIONS DE VÉRIFICATION (tour 1), chacune avec son témoin ci-dessous et sa mutation rouge :
//  * le verdict d'activation pouvait être JETÉ dans `run()` sans qu'aucun témoin ne rougisse (l'épingle ne lisait que la
//    présence de l'appel) : la valeur demandée a désormais son propre type (`DemonstrationDemandee`), que l'état servi
//    refuse à la compilation — (6) épingle ce qui garde ce type en place ;
//  * la lecture du rôle dans le jugement d'activation pouvait être avalée : (5) refuse la seule colonne `user.role` ;
//  * l'ordre « jugé AVANT la lecture du hachage » n'avait aucun témoin : (3) le joue, lecture refusée ou mot de passe ;
//  * la règle refusait `demo` à l'annuaire même hors démonstration, sans protection de plus (l'activation le tient) et
//    au prix d'une identité réelle éventuelle : (3) le prend hors démonstration, et montre l'activation refusée ensuite ;
//  * le refus d'activation ne se lisait qu'au journal : (5) le lit au registre, (7) au paquet de diagnostic ;
//  * deux causes servies disaient faux ou conseillaient un geste que la console n'offre pas : (8).
// CORRECTIONS DE VÉRIFICATION (tour 2) :
//  * la SECONDE lecture du jugement d'activation (ce que le nom tient sans compte) pouvait être avalée, tout restant
//    vert : (5) la rend illisible sans compte `demo` (`acces_observe`, puis `saved_query`) ;
//  * « le SEUL chemin vers le `bool` servi » disait trop — le type ferme la reprise de la valeur demandée, pas la
//    fabrication d'une autre : (6) lit la liaison servie entière et le champ de l'état en forme courte.
// CORRECTIONS DE VÉRIFICATION (tour 3) :
//  * que la porte de lecture seule se décide sur la MÉTHODE `demo` et non sur le NOM `demo` n'était tenu que par la
//    fonction isolée (2) : forcer la méthode à `demo` sur ce nom dans `apply_gates` laissait tout vert, et hors
//    démonstration `demo` ne jouait qu'une lecture (3). (3) l'y fait ÉCRIRE, par les en-têtes SSO et par un compte à
//    mot de passe : 200, ses lignes posées sous son nom.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le démarrage lui-même (`run()` ne se joue pas en test : le type de la valeur
// demandée y tient le flux, son câblage restant est épinglé sur le source, la décision est jouée sur la fonction qu'il
// appelle) ; le mode multi-tenant (le chemin d'en-têtes du mode 1 ne joue pas la règle des annuaires) ; la réponse HTTP
// des trois fédérations (non jouable sans fournisseur : la règle est jouée par `federer_le_nom` et `reponse`) ; les POST
// de lecture (`/api/cancel` compris) restent servis à l'anonyme, par décision. La population réelle d'identités SSO
// nommées `demo` en production n'est plus une condition : la démonstration y est inactive, et la règle ne refuse ce
// nom que démonstration servie.
// =====================================================================================
mod demonstration_en_lecture_seule_et_son_nom_a_personne {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const DLSP_SECRET_SSO: &str = "secret-de-bord-dlsp";
    const DLSP_MOT_DE_PASSE_DU_LECTEUR: &str = "motdepasse-du-lecteur-dlsp";

    /// Un état servi : un administrateur de configuration (pas de mode installation), le secret SSO posé.
    fn dlsp_etat(tag: &str, demonstration: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(tag);
        st.sso_secret = Arc::new(DLSP_SECRET_SSO.into());
        st.user = Arc::new("root-dlsp".into());
        st.pass_hash = Arc::new(hash_pw("motdepasse-de-configuration-dlsp").expect("hachage"));
        st.public_demo = demonstration;
        (st, p)
    }

    fn dlsp_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Le corps JSON d'une réponse brute du routeur (après l'en-tête ; un corps découpé en morceaux est recollé).
    fn dlsp_corps(brut: &str) -> Value {
        let apres = brut.split_once("\r\n\r\n").map(|(_, c)| c).unwrap_or("");
        let chunked = brut.split_once("\r\n\r\n").map(|(t, _)| t.to_ascii_lowercase().contains("transfer-encoding: chunked")).unwrap_or(false);
        let texte = if chunked {
            let mut out = String::new();
            let mut reste = apres;
            while let Some((taille, suite)) = reste.split_once("\r\n") {
                let n = usize::from_str_radix(taille.trim(), 16).unwrap_or(0);
                if n == 0 || suite.len() < n {
                    break;
                }
                out.push_str(&suite[..n]);
                reste = suite[n..].trim_start_matches("\r\n");
            }
            out
        } else {
            apres.to_string()
        };
        serde_json::from_str(&texte).unwrap_or(Value::String(texte))
    }

    async fn dlsp_envoyer(addr: std::net::SocketAddr, methode: &str, chemin: &str, autorisation: Option<&str>, corps: &str) -> (u16, Value) {
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &[("content-type", "application/json")] };
        let (code, brut) = router_probe_envoi(addr, methode, chemin, autorisation, entetes, corps).await;
        (code, dlsp_corps(&brut))
    }

    fn dlsp_basic(nom: &str, mot: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mot}")))
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.28-i` — L'ANONYME DE LA DÉMONSTRATION N'ÉCRIT RIEN, ET LIT TOUJOURS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, au routeur réel, démonstration active, aucun identifiant : les SIX mutations des quatre surfaces que
    /// `viewer` écrit pour lui-même (créer, modifier, supprimer une requête enregistrée ; écrire ses préférences ;
    /// enrôler un second facteur ; changer son mot de passe) rendent 403 et LA cause nommée ; la requête que `demo` tenait
    /// déjà (reste d'avant) est intacte, aucune préférence n'est posée, aucun maillon `saved_query.*` n'est inscrit, et
    /// chaque refus est tracé par un déni `plume-authz` (six). Une mutation que le rôle refuse déjà (`POST
    /// /api/dashboards`) garde son refus et son message d'avant, et sa trace. LES LECTURES RESTENT : la liste des requêtes
    /// (200, le reste d'avant listé), les préférences (200), un POST de lecture (`/api/soql/validate`, 200).
    /// CONTRÔLE POSITIF, même instance : un VRAI lecteur (`viewer`, mot de passe) crée sa requête et écrit ses préférences
    /// (200 et 200) — son libre-service est intact.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer l'appel de `refuser_l_ecriture_de_la_demonstration` de `apply_gates` (la
    /// forme d'avant : 200 sur la création) ; juger sur le RÔLE `viewer` au lieu de la méthode (le vrai lecteur reçoit
    /// 403).
    #[tokio::test]
    async fn dlsp_l_anonyme_de_la_demonstration_n_ecrit_rien_et_lit_toujours() {
        let (st, _p) = dlsp_etat("dlsp-lecture-seule", true);
        let reste: i64 = {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO user(name,hash,role) VALUES('vwr-dlsp',?1,'viewer')",
                params![hash_pw(DLSP_MOT_DE_PASSE_DU_LECTEUR).expect("hachage")],
            )
            .expect("fixture : un vrai lecteur");
            c.execute("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('demo','reste d avant','search reste',1,1)", [])
                .expect("fixture : une requête laissée sous `demo` avant ce lot");
            c.last_insert_rowid()
        };
        let addr = router_serve(st.clone()).await;
        let (s, moi) = dlsp_envoyer(addr, "GET", "/api/me", None, "").await;
        assert_eq!((s, moi["auth_method"].as_str()), (200, Some("demo")), "fixture : l'anonyme est servi par la démonstration : {moi}");

        let refusees: [(&str, String, &str); 6] = [
            ("POST", "/api/saved-queries".into(), r#"{"name":"anonyme","soql":"search x"}"#),
            ("PUT", format!("/api/saved-queries/{reste}"), r#"{"name":"ecrase","soql":"search y"}"#),
            ("DELETE", format!("/api/saved-queries/{reste}"), ""),
            ("PUT", "/api/prefs".into(), r#"{"prefs":{"colw":{"t":{"c":90}}}}"#),
            ("POST", "/api/mfa/enroll".into(), r#"{"password":"n-importe-quoi-dlsp"}"#),
            ("POST", "/api/password".into(), r#"{"current":"n-importe-quoi-dlsp","new":"un-mot-de-passe-assez-long-dlsp"}"#),
        ];
        for (methode, chemin, corps) in &refusees {
            let (s, c) = dlsp_envoyer(addr, methode, chemin, None, corps).await;
            assert_eq!(
                (s, c["error"].as_str()),
                (403, Some(CAUSE_DEMONSTRATION_EN_LECTURE_SEULE)),
                "`{methode} {chemin}` sous la démonstration : refusé, la cause nommée : {c}"
            );
        }
        let (nom, texte): (String, String) =
            st.db.lock().query_row("SELECT name, soql FROM saved_query WHERE id=?1", params![reste], |r| Ok((r.get(0)?, r.get(1)?))).expect("le reste d'avant est toujours là");
        assert_eq!((nom.as_str(), texte.as_str()), ("reste d avant", "search reste"), "ni modifié ni supprimé");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner='demo'"), 1, "aucune requête posée sous `demo`");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user_pref WHERE user='demo'"), 0, "aucune préférence posée sous `demo`");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'saved_query.%'"), 0, "aucun maillon d'une écriture qui n'a pas eu lieu");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM event WHERE source='plume-authz'"), 6, "chaque refus est tracé comme un déni");

        let (s, c) = dlsp_envoyer(addr, "POST", "/api/dashboards", None, r#"{"name":"x"}"#).await;
        assert_eq!((s, c.as_str()), (403, Some("lecture seule (rôle viewer)")), "une mutation que le rôle refuse garde son refus d'avant : {c}");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM event WHERE source='plume-authz'"), 7, "et sa trace");

        let (s, c) = dlsp_envoyer(addr, "GET", "/api/saved-queries", None, "").await;
        assert_eq!(s, 200, "la lecture reste servie : {c}");
        assert!(c["queries"].as_array().is_some_and(|q| q.iter().any(|x| x["id"] == json!(reste))), "le reste d'avant est listé : {c}");
        let (s, c) = dlsp_envoyer(addr, "GET", "/api/prefs", None, "").await;
        assert_eq!(s, 200, "les préférences se lisent : {c}");
        let (s, c) = dlsp_envoyer(addr, "POST", "/api/soql/validate", None, r#"{"soql":"search source=sshd"}"#).await;
        assert_eq!(s, 200, "un POST de lecture reste servi : {c}");

        let lecteur = dlsp_basic("vwr-dlsp", DLSP_MOT_DE_PASSE_DU_LECTEUR);
        let (s, c) = dlsp_envoyer(addr, "POST", "/api/saved-queries", Some(&lecteur), r#"{"name":"la mienne","soql":"search z"}"#).await;
        assert_eq!(s, 200, "CONTRÔLE POSITIF : un vrai lecteur crée sa requête : {c}");
        let (s, c) = dlsp_envoyer(addr, "PUT", "/api/prefs", Some(&lecteur), r#"{"prefs":{"k":"v"}}"#).await;
        assert_eq!(s, 200, "CONTRÔLE POSITIF : et écrit ses préférences : {c}");
        assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner='vwr-dlsp'"), 1, "sous son nom");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.28-i` — LA PORTE NE JUGE QUE LA MÉTHODE ET LA MUTATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la méthode `demo` en mutation est refusée, la cause nommée ; en lecture, servie ; toute autre
    /// méthode (cookie, Basic, SSO, jeton d'agent, de source de données, client, aucune) passe, mutation ou non.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `if auth_method == "demo"` sans `mutating` (les lectures de la démonstration
    /// refusées) ; `if mutating` sans la méthode (toute écriture refusée à tous).
    #[test]
    fn dlsp_la_porte_ne_juge_que_la_methode_et_la_mutation() {
        assert_eq!(refuser_l_ecriture_de_la_demonstration("demo", true), Err(CAUSE_DEMONSTRATION_EN_LECTURE_SEULE));
        assert_eq!(refuser_l_ecriture_de_la_demonstration("demo", false), Ok(()), "la démonstration lit");
        for methode in ["cookie", "basic", "sso", "bearer", "datasource", "client", "hec", ""] {
            for mutation in [true, false] {
                assert_eq!(refuser_l_ecriture_de_la_demonstration(methode, mutation), Ok(()), "`{methode}`, mutation {mutation} : passe");
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.28-j` — UN ANNUAIRE QUI PRÉSENTE `demo` EST REFUSÉ SOUS LA DÉMONSTRATION, PRIS HORS D'ELLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT :
    ///  * DÉMONSTRATION SERVIE : la règle unique refuse `demo` (`IdentiteDeLaDemonstration`) au chemin d'en-têtes comme à
    ///    la fédération servie (`federer_le_nom`), qui ne pose aucune ligne et répond 409 et la cause ; au routeur, les
    ///    en-têtes SSO qui présentent `demo` reçoivent 403 et la cause (JSON), un maillon `auth.annuaire.refuse` et un
    ///    événement dont le champ `cause` est `identite_de_la_demonstration`. CONTRÔLE POSITIF : `demo-dlsp` est pris
    ///    aux deux portes et servi par les en-têtes (200, méthode `sso`) ;
    ///  * DÉMONSTRATION NON SERVIE (correction de vérification) : `demo` est pris comme un autre nom — servi par les
    ///    en-têtes (200, méthode `sso`, aucun refus tracé), fédéré (une ligne sans mot de passe) ;
    ///    ET IL ÉCRIT (tour 3) — servi par les en-têtes, `PUT /api/prefs` et `POST /api/saved-queries` rendent 200 et
    ///    posent sous `demo`, sans déni ; un compte `demo` à mot de passe (Basic) de même. ET LA PROTECTION QUE
    ///    L'ANCIEN REFUS PRÉTENDAIT DONNER EST TENUE AILLEURS : la démonstration demandée ensuite sur cette base est
    ///    refusée à l'activation (`CompteExistant`) ;
    ///  * L'ORDRE (correction de vérification) : démonstration servie, `demo` est refusé SANS lire le hachage — une porte
    ///    dont la lecture échouerait ne change pas la cause en `NonVerifie`, une ligne à mot de passe ne la change pas en
    ///    `CompteAMotDePasse`, et la lecture n'est pas appelée ;
    ///  * un `PLUME_USER=demo` garde la cause d'avant (`AdministrateurDeConfiguration`), démonstration servie ou non.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la branche `IDENTITE_DE_LA_DEMONSTRATION` de
    /// `juger_le_nom_pris_par_un_annuaire` (la forme d'avant : la fédération pose `user(demo)`, les en-têtes servent
    /// `demo`, démonstration servie) ; la juger sans `noms.demonstration_servie` (la première forme du lot : hors
    /// démonstration, 403) ; `demonstration_servie: false` dans `NomsTenusHorsDeLaTable::de` (servie, pris) ; déplacer
    /// la branche APRÈS la lecture du hachage (`NonVerifie`, `CompteAMotDePasse`, lecture appelée) ; dans `apply_gates`,
    /// juger la lecture seule sur le NOM `demo` (forcer la méthode à `demo` quand `name == IDENTITE_DE_LA_DEMONSTRATION`
    /// — hors démonstration, l'écriture de `demo` reçoit 403, SSO comme Basic).
    #[tokio::test]
    async fn dlsp_un_annuaire_qui_presente_demo_est_refuse_sous_la_demonstration_et_pris_hors_d_elle() {
        use crate::server::activation_de_la_demonstration::{juger_l_activation_de_la_demonstration, RefusDeLaDemonstration};
        let nom = crate::auth::IDENTITE_DE_LA_DEMONSTRATION;
        let sso = |qui: &'static str| [("x-plume-sso-secret", DLSP_SECRET_SSO), ("x-authentik-username", qui), ("x-authentik-groups", "plume-editor")];

        // ── DÉMONSTRATION SERVIE : refusé aux deux portes ──
        {
            let (st, _p) = dlsp_etat("dlsp-annuaire-servie", true);
            let refus = RefusDeLAnnuaire::IdentiteDeLaDemonstration(nom.into());
            assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, nom), Err(RefusDeLAnnuaire::IdentiteDeLaDemonstration(nom.into())), "en-têtes, démonstration servie");
            let federation = federer_le_nom(&st, &st.db.lock(), nom, "viewer");
            assert_eq!(federation, Err(RefusDeLaFederation::Nom(refus)), "fédération, démonstration servie");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user WHERE name='demo'"), 0, "aucune ligne posée");
            let r = federation.expect_err("refus").reponse();
            let statut = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
            let corps: Value = serde_json::from_slice(&b).expect("JSON");
            assert_eq!((statut, corps["error"].as_str()), (409, Some(CAUSE_ANNUAIRE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION)), "réponse de la fédération");

            let addr = router_serve(st.clone()).await;
            let (s, brut) = router_probe_corps(addr, "GET", "/api/me", None, &sso("demo")).await;
            let c = dlsp_corps(&brut);
            assert_eq!((s, c["error"].as_str()), (403, Some(CAUSE_ANNUAIRE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION)), "au routeur : {c}");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse'"), 1, "un maillon");
            assert_eq!(
                dlsp_compte(&st, "SELECT COUNT(*) FROM event WHERE source='plume-auth' AND json_extract(fields,'$.cause')='identite_de_la_demonstration'"),
                1,
                "un événement sous son code"
            );

            assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, "demo-dlsp"), Ok(()), "CONTRÔLE POSITIF : en-têtes");
            let (s, brut) = router_probe_corps(addr, "GET", "/api/me", None, &sso("demo-dlsp")).await;
            let c = dlsp_corps(&brut);
            assert_eq!((s, c["user"].as_str(), c["auth_method"].as_str()), (200, Some("demo-dlsp"), Some("sso")), "CONTRÔLE POSITIF : servi : {c}");
            assert_eq!(federer_le_nom(&st, &st.db.lock(), "demo-dlsp", "viewer"), Ok(()), "CONTRÔLE POSITIF : fédération");
        }

        // ── DÉMONSTRATION NON SERVIE : pris comme un autre nom, et l'activation le tient ensuite ──
        {
            let (st, _p) = dlsp_etat("dlsp-annuaire-non-servie", false);
            assert_eq!(juger_le_nom_presente_par_l_annuaire(&st, nom), Ok(()), "en-têtes, démonstration non servie : pris");
            let addr = router_serve(st.clone()).await;
            let (s, brut) = router_probe_corps(addr, "GET", "/api/me", None, &sso("demo")).await;
            let c = dlsp_corps(&brut);
            assert_eq!((s, c["user"].as_str(), c["auth_method"].as_str()), (200, Some("demo"), Some("sso")), "servi par les en-têtes : {c}");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse'"), 0, "aucun refus tracé");
            // IL ÉCRIT, PAS SEULEMENT IL LIT (tour 3) : la lecture seule se décide sur la méthode, pas sur le nom.
            let ecriture_sso: Vec<(&str, &str)> = sso("demo").into_iter().chain([("origin", "http://127.0.0.1"), ("content-type", "application/json")]).collect();
            for (methode, chemin, corps) in [("PUT", "/api/prefs", r#"{"prefs":{"k":"sso"}}"#), ("POST", "/api/saved-queries", r#"{"name":"sso","soql":"search s"}"#)] {
                let (s, brut) = router_probe_envoi(addr, methode, chemin, None, &ecriture_sso, corps).await;
                assert_eq!(s, 200, "`{methode} {chemin}` par les en-têtes sous `demo`, démonstration non servie : {}", dlsp_corps(&brut));
            }
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user_pref WHERE user='demo'"), 1, "ses préférences posées sous son nom");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner='demo'"), 1, "sa requête posée sous son nom");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM event WHERE source='plume-authz'"), 0, "aucun déni");
            assert_eq!(federer_le_nom(&st, &st.db.lock(), nom, "viewer"), Ok(()), "fédération, démonstration non servie : prise");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user WHERE name='demo'"), 1, "une ligne fédérée");
            assert_eq!(
                juger_l_activation_de_la_demonstration(&st.db.lock(), crate::handlers::idp::reserved_static_admin(&st)),
                Err(RefusDeLaDemonstration::CompteExistant("viewer".into())),
                "la démonstration demandée ensuite sur cette base n'est pas activée : le nom appartient à l'identité de l'annuaire"
            );
        }

        // ── DÉMONSTRATION NON SERVIE : un compte `demo` à mot de passe (reste d'avant la réservation) écrit aussi ──
        {
            let (st, _p) = dlsp_etat("dlsp-annuaire-non-servie-basic", false);
            st.db
                .lock()
                .execute("INSERT INTO user(name,hash,role) VALUES('demo',?1,'viewer')", params![hash_pw(DLSP_MOT_DE_PASSE_DU_LECTEUR).expect("hachage")])
                .expect("fixture : un compte `demo` à mot de passe");
            let addr = router_serve(st.clone()).await;
            let demo = dlsp_basic(nom, DLSP_MOT_DE_PASSE_DU_LECTEUR);
            let (s, moi) = dlsp_envoyer(addr, "GET", "/api/me", Some(&demo), "").await;
            assert_eq!((s, moi["user"].as_str(), moi["auth_method"].as_str()), (200, Some("demo"), Some("basic")), "fixture : servi par son mot de passe : {moi}");
            let (s, c) = dlsp_envoyer(addr, "PUT", "/api/prefs", Some(&demo), r#"{"prefs":{"k":"basic"}}"#).await;
            assert_eq!(s, 200, "`PUT /api/prefs` d'un compte `demo` à mot de passe, démonstration non servie : {c}");
            let (s, c) = dlsp_envoyer(addr, "POST", "/api/saved-queries", Some(&demo), r#"{"name":"basic","soql":"search b"}"#).await;
            assert_eq!(s, 200, "`POST /api/saved-queries` du même : {c}");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user_pref WHERE user='demo'"), 1, "ses préférences posées");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM saved_query WHERE owner='demo'"), 1, "sa requête posée");
        }

        // ── L'ORDRE : démonstration servie, jugé AVANT la lecture du hachage ──
        {
            let noms = NomsTenusHorsDeLaTable { administrateur_de_configuration: None, administrateur_de_l_assistant: None, demonstration_servie: true };
            let lue = std::cell::Cell::new(0u32);
            let ratee = juger_le_nom_pris_par_un_annuaire(nom, &noms, || {
                lue.set(lue.get() + 1);
                Err(rusqlite::Error::InvalidQuery)
            });
            assert_eq!(ratee, Err(RefusDeLAnnuaire::IdentiteDeLaDemonstration(nom.into())), "une lecture qui échouerait ne change pas la cause");
            let a_mot_de_passe = juger_le_nom_pris_par_un_annuaire(nom, &noms, || {
                lue.set(lue.get() + 1);
                Ok(Some("$argon2id$v=19$fixture-dlsp".into()))
            });
            assert_eq!(a_mot_de_passe, Err(RefusDeLAnnuaire::IdentiteDeLaDemonstration(nom.into())), "une ligne à mot de passe ne change pas la cause");
            assert_eq!(lue.get(), 0, "aucune lecture n'entre dans ce jugement");
        }

        for servie in [false, true] {
            let (mut st, _p) = dlsp_etat("dlsp-annuaire-configuration", servie);
            st.user = Arc::new(nom.into());
            assert_eq!(
                juger_le_nom_presente_par_l_annuaire(&st, nom),
                Err(RefusDeLAnnuaire::AdministrateurDeConfiguration(nom.into())),
                "`PLUME_USER=demo` garde la cause d'avant, démonstration servie={servie}"
            );
        }
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.28-j` — L'ASSISTANT NE POSE PAS UN ADMINISTRATEUR NOMMÉ `demo`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, au routeur réel en mode installation, jeton juste : `user = demo` (et `" demo "`, rogné) -> 409 et
    /// la cause de la création d'un compte ; aucune ligne `user`, pas de `meta.admin_user`, aucun administrateur en
    /// mémoire, aucun maillon `setup`. Le jeton reste valable : l'installation sous un autre nom passe ensuite (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR, ET QUI EST LA FORME D'AVANT : retirer la réservation de `setup_post` — 200 et
    /// `user(demo, admin)` posé.
    #[tokio::test]
    async fn dlsp_l_assistant_ne_pose_pas_un_administrateur_nomme_demo() {
        let (st, _p) = onb_state("dlsp-assistant");
        let (admin, db) = (st.admin.clone(), st.db.clone());
        let addr = router_serve(st).await;
        for presente in ["demo", " demo "] {
            let corps = json!({ "token": ONB_TOKEN, "user": presente, "password": "motdepasse-tres-long-dlsp" }).to_string();
            let (s, c) = dlsp_envoyer(addr, "POST", "/api/setup", None, &corps).await;
            assert_eq!((s, c["error"].as_str()), (409, Some(CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION)), "`{presente}` : {c}");
        }
        {
            let c = db.lock();
            let n = |sql: &str| c.query_row(sql, [], |r| r.get::<_, i64>(0)).expect("compte");
            assert_eq!(n("SELECT COUNT(*) FROM user WHERE name='demo'"), 0, "aucune ligne");
            assert_eq!(n("SELECT COUNT(*) FROM meta WHERE key='admin_user'"), 0, "aucun nom d'administrateur");
            assert_eq!(n("SELECT COUNT(*) FROM ledger WHERE kind='setup'"), 0, "aucune installation attestée");
        }
        assert!(admin.lock().is_none(), "aucun administrateur en mémoire");
        let corps = json!({ "token": ONB_TOKEN, "user": "root-dlsp", "password": "motdepasse-tres-long-dlsp" }).to_string();
        let (s, c) = dlsp_envoyer(addr, "POST", "/api/setup", None, &corps).await;
        assert_eq!(s, 200, "CONTRÔLE POSITIF : le jeton reste valable, un autre nom s'installe : {c}");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.28-j` — LA DÉMONSTRATION NE S'ACTIVE PAS SUR UN NOM DÉJÀ À QUELQU'UN
    // -------------------------------------------------------------------------------------

    fn dlsp_refuser_la_lecture_des_comptes(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "user", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// CE QU'IL TIENT, sur `juger_l_activation_de_la_demonstration` et `activer_la_demonstration_si_permise` :
    ///  * PERMISE : une base où `demo` n'est à personne — y compris quand l'inventaire des accès consigne la démonstration
    ///    elle-même (méthode `demo`) et que des dossiers semés par `PLUME_DEMO=1` portent `owner = demo` (contrôles
    ///    négatifs : ces traces n'octroient rien) ; un administrateur de configuration d'un autre nom ;
    ///  * REFUSÉE : `PLUME_USER=demo` ; un compte `demo` à mot de passe (`editor`), ou fédéré (`viewer`) ; sans compte, une
    ///    requête enregistrée, des préférences, ou une vue par l'annuaire (`sso`) sous ce nom ; la lecture des comptes
    ///    refusée (`NonVerifie`) ; et (correction de vérification) la SEULE colonne `user.role` illisible, un compte
    ///    `demo` présent : `NonVerifie` — la lecture de repli (`ce_que_le_nom_tient_sans_compte`) voit le compte et ne
    ///    conclurait rien, c'est donc la lecture du rôle qui doit refuser ; et (correction de vérification, tour 2)
    ///    AUCUN compte `demo`, la SECONDE lecture illisible — `acces_observe` seule refusée, puis `saved_query` seule :
    ///    `NonVerifie`, non activée — la lecture du rôle rend « aucune ligne », c'est donc la seconde qui doit refuser ;
    ///  * non demandée : jamais activée, même sur une base permise ; demandée et refusée : non activée ;
    ///  * (correction de vérification) LE REFUS EST INSCRIT AU REGISTRE : un maillon `demo.activation.refusee` portant la
    ///    phrase du refus ; aucun maillon quand la démonstration est permise ou non demandée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la lecture de la ligne `user` (le compte `demo` passe) ; avaler son erreur
    /// (`Err(_) => {}` : la colonne `role` illisible passe) ; retirer la lecture de ce que le nom tient (la requête laissée
    /// sous `demo` passe) ; avaler l'erreur de cette seconde lecture (`Err(_) => Ok(())` : la démonstration s'active sur
    /// une base qu'elle n'a pas pu lire) ; `activer_la_demonstration_si_permise` qui rend `demandee` sans juger (la forme d'avant) ; retirer
    /// l'inscription du refus au registre.
    #[test]
    fn dlsp_la_demonstration_ne_s_active_pas_sur_un_nom_deja_a_quelqu_un() {
        use crate::server::activation_de_la_demonstration::{
            activer_la_demonstration_si_permise, juger_l_activation_de_la_demonstration, DemonstrationDemandee, RefusDeLaDemonstration as R,
            MAILLON_DE_LA_DEMONSTRATION_REFUSEE,
        };
        let demandee = DemonstrationDemandee::depuis_la_configuration;
        let juger = |preparer: &dyn Fn(&Connection), configuration: Option<&str>| {
            let (st, _p) = sp_state("dlsp-activation");
            let c = st.db.lock();
            preparer(&c);
            juger_l_activation_de_la_demonstration(&c, configuration)
        };
        let rien = |_: &Connection| {};
        assert_eq!(juger(&rien, None), Ok(()), "une base où `demo` n'est à personne");
        assert_eq!(juger(&rien, Some("root-dlsp")), Ok(()), "un administrateur de configuration d'un autre nom");
        let traces_de_la_demonstration = |c: &Connection| {
            c.execute(
                "INSERT INTO acces_observe(nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue) VALUES('demo','demonstration','viewer','demonstration','demo',1,1)",
                [],
            )
            .expect("fixture : l'inventaire consigne la démonstration elle-même");
            c.execute("INSERT INTO incident(ts,updated,title,status,severity,owner) VALUES(1,1,'semé','open',2,'demo')", []).expect("fixture : un dossier semé");
        };
        assert_eq!(juger(&traces_de_la_demonstration, None), Ok(()), "CONTRÔLE NÉGATIF : les traces de la démonstration n'octroient rien");

        assert_eq!(juger(&rien, Some("demo")), Err(R::AdministrateurDeConfiguration), "`PLUME_USER=demo`");
        let compte = |hachage: &'static str, role: &'static str| {
            move |c: &Connection| {
                c.execute("INSERT INTO user(name,hash,role) VALUES('demo',?1,?2)", params![hachage, role]).expect("fixture : un compte `demo`");
            }
        };
        assert_eq!(juger(&compte("$argon2id$v=19$fixture-dlsp", "editor"), None), Err(R::CompteExistant("editor".into())), "un compte à mot de passe");
        assert_eq!(juger(&compte(IDP_HASH_SENTINEL, "viewer"), None), Err(R::CompteExistant("viewer".into())), "un compte fédéré");
        let tenu = |sql: &'static str| {
            move |c: &Connection| {
                c.execute(sql, []).expect("fixture : une ligne sous `demo`");
            }
        };
        for (quoi, sql, cle) in [
            ("une requête enregistrée", "INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('demo','x','search x',1,1)", "saved_query"),
            ("des préférences", "INSERT INTO user_pref(user,prefs,updated) VALUES('demo','{}',1)", "user_pref"),
        ] {
            match juger(&tenu(sql), None) {
                Err(R::NomTenuSansCompte(tenue)) => assert_eq!(tenue["lignes"][cle], json!(1), "{quoi} : {tenue}"),
                autre => panic!("{quoi} sous `demo` sans compte refuse l'activation : {autre:?}"),
            }
        }
        let vu_par_l_annuaire = |c: &Connection| {
            c.execute(
                "INSERT INTO acces_observe(nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue) VALUES('demo','annuaire','editor','groupes','sso',1,1)",
                [],
            )
            .expect("fixture : `demo` vu par l'annuaire");
        };
        match juger(&vu_par_l_annuaire, None) {
            Err(R::NomTenuSansCompte(tenue)) => assert_eq!(tenue["vu_par_l_annuaire"], json!(true), "{tenue}"),
            autre => panic!("un nom vu par l'annuaire refuse l'activation : {autre:?}"),
        }
        let (st, _p) = sp_state("dlsp-activation-non-lue");
        dlsp_refuser_la_lecture_des_comptes(&st);
        let non_lue = juger_l_activation_de_la_demonstration(&st.db.lock(), None);
        assert!(matches!(non_lue, Err(R::NonVerifie(_))), "une lecture qui n'a pas eu lieu refuse : {non_lue:?}");
        assert!(!activer_la_demonstration_si_permise(&st.db.lock(), demandee(true), None), "demandée, non vérifiée : non activée");
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);

        // La SEULE colonne `user.role` illisible, un compte `demo` présent : la lecture de repli verrait le compte et ne
        // conclurait rien — c'est la lecture du rôle qui refuse.
        let (st, _p) = sp_state("dlsp-activation-role-illisible");
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('demo','$argon2id$v=19$fixture-dlsp','editor')", [])
            .expect("fixture : un compte `demo`");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "user", column_name: "role" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        assert_eq!(
            crate::handlers::users_lookups::ce_que_le_nom_tient_sans_compte(&st.db.lock(), "demo").map_err(|e| e.to_string()),
            Ok(None),
            "fixture : la lecture de repli voit le compte et ne conclut rien (sinon ce témoin ne départage pas les deux lectures)"
        );
        let role_illisible = juger_l_activation_de_la_demonstration(&st.db.lock(), None);
        assert!(matches!(role_illisible, Err(R::NonVerifie(_))), "la colonne `role` illisible refuse : {role_illisible:?}");
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);

        // (correction de vérification, tour 2) LA SECONDE LECTURE illisible, AUCUN compte `demo` : la lecture du rôle
        // rend « aucune ligne » et ne conclut rien, c'est donc la lecture de ce que le nom tient sans compte qui doit
        // refuser. Deux tables de cette lecture, chacune seule refusée : l'inventaire des accès (`acces_observe`) et une
        // colonne d'autorité (`saved_query`).
        for table_refusee in ["acces_observe", "saved_query"] {
            let (st, _p) = sp_state("dlsp-activation-seconde-lecture");
            assert_eq!(dlsp_compte(&st, "SELECT COUNT(*) FROM user WHERE name='demo'"), 0, "fixture : aucun compte `demo`, la première lecture ne conclut rien");
            st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, .. } if table_name == table_refusee => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            assert!(
                crate::handlers::users_lookups::ce_que_le_nom_tient_sans_compte(&st.db.lock(), "demo").is_err(),
                "fixture : `{table_refusee}` refusée, la seconde lecture échoue bien (sinon ce témoin ne juge rien)"
            );
            let seconde = juger_l_activation_de_la_demonstration(&st.db.lock(), None);
            assert!(matches!(seconde, Err(R::NonVerifie(_))), "`{table_refusee}` illisible, aucun compte : la seconde lecture qui n'a pas eu lieu refuse : {seconde:?}");
            assert!(!activer_la_demonstration_si_permise(&st.db.lock(), demandee(true), None), "`{table_refusee}` illisible : demandée, non vérifiée, non activée");
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        }

        let (st, _p) = sp_state("dlsp-activation-issue");
        let maillons = || dlsp_compte(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{MAILLON_DE_LA_DEMONSTRATION_REFUSEE}'"));
        assert!(!activer_la_demonstration_si_permise(&st.db.lock(), demandee(false), None), "non demandée : jamais activée");
        assert!(activer_la_demonstration_si_permise(&st.db.lock(), demandee(true), None), "demandée, permise : activée");
        assert_eq!(maillons(), 0, "rien n'est inscrit quand la démonstration est permise ou non demandée");
        assert!(!activer_la_demonstration_si_permise(&st.db.lock(), demandee(true), Some("demo")), "demandée, refusée : non activée");
        assert_eq!(maillons(), 1, "le refus est inscrit au registre");
        let detail: String = st
            .db
            .lock()
            .query_row("SELECT detail FROM ledger WHERE kind=?1", params![MAILLON_DE_LA_DEMONSTRATION_REFUSEE], |r| r.get(0))
            .expect("le maillon se lit");
        assert_eq!(detail, R::AdministrateurDeConfiguration.phrase(), "le maillon porte la phrase entière du refus");
        for refus in [R::AdministrateurDeConfiguration, R::CompteExistant("editor".into()), R::NomTenuSansCompte(json!({})), R::NonVerifie("x".into())] {
            let phrase = refus.phrase();
            assert!(phrase.contains("NON ACTIVÉE") && phrase.contains(refus.code()) && phrase.contains("Remède"), "la phrase nomme le refus, son code et son remède : {phrase}");
        }
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.28-j` — LA DÉMONSTRATION REFUSÉE NE SERT PAS L'ANONYME, ET LE DÉMARRAGE LA JUGE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un compte `demo` (mot de passe) tient une requête privée ; la démonstration demandée est jugée par
    /// la fonction que le démarrage appelle — non activée — et, au routeur réel, l'anonyme reçoit 401 (plus la requête
    /// privée) tandis que le compte lit toujours la sienne par son mot de passe.
    ///
    /// LE FLUX DU VERDICT JUSQU'À L'ÉTAT SERVI EST TENU PAR LE COMPILATEUR (correction de vérification, MESURÉ : la
    /// première épingle, qui ne lisait que la présence de l'appel, restait verte quand `run()` JETAIT le verdict —
    /// `let _public_demo_jugee = …` — et servait la valeur demandée). La valeur demandée est une
    /// `DemonstrationDemandee`, que `AppState { public_demo, … }` (un `bool`) refuse : jeter le verdict ou l'enfermer
    /// dans un bloc NE COMPILE PLUS (E0308). Ce témoin épingle donc ce qui garde ce type en place, sur le source de
    /// `server/mod.rs` : `BootConfig` porte la valeur demandée sous ce type ; `boot_config` est le seul à la fabriquer, de
    /// la seule lecture de `PLUME_PUBLIC_DEMO` du module ; `run()` n'en refabrique aucune ; il appelle
    /// `activer_la_demonstration_si_permise` AVANT de construire l'état servi, avec l'administrateur de configuration
    /// défini comme `reserved_static_admin` ; `boot_config` ne publie plus la bannière de la démonstration.
    /// (correction de vérification, tour 2) LE TYPE NE FERME QUE LA REPRISE DE LA VALEUR DEMANDÉE — un littéral `true`,
    /// ou un bloc qui appelle la fonction puis rend autre chose, compile dans l'état servi : la liaison servie est donc
    /// lue ENTIÈRE (le verdict lié tel quel), et l'état la prend en forme courte (`public_demo,`).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer l'appel de `run()` (la forme d'avant) ; rendre à `BootConfig` un `bool`
    /// que `run()` enveloppe lui-même (le verdict redeviendrait jetable) ; relire `PLUME_PUBLIC_DEMO` dans `run()` ; lier
    /// `let public_demo = { let _ = activer_la_demonstration_si_permise(…); true };` ; `public_demo: true,` dans l'état.
    /// Et, au compilateur : jeter le verdict (`let _public_demo_jugee = …`) sans rien lier d'autre. CE QUE L'ÉPINGLE NE
    /// TIENT PAS : une liaison qui passerait ces deux lectures en rendant autre chose que le verdict (elle n'existe pas au
    /// source ; la relecture la verrait).
    #[tokio::test]
    async fn dlsp_la_demonstration_refusee_ne_sert_pas_l_anonyme_et_le_demarrage_la_juge() {
        let (mut st, _p) = dlsp_etat("dlsp-refusee", false);
        let mot = "motdepasse-du-compte-demo-dlsp";
        {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('demo',?1,'editor')", params![hash_pw(mot).expect("hachage")]).expect("fixture : compte `demo`");
            c.execute("INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('demo','privee','search secret-dlsp',1,1)", []).expect("fixture : requête privée");
        }
        st.public_demo = crate::server::activation_de_la_demonstration::activer_la_demonstration_si_permise(
            &st.db.lock(),
            crate::server::activation_de_la_demonstration::DemonstrationDemandee::depuis_la_configuration(true),
            crate::handlers::idp::reserved_static_admin(&st),
        );
        assert!(!st.public_demo, "la démonstration demandée n'est pas activée");
        let addr = router_serve(st.clone()).await;
        let (s, brut) = router_probe_corps(addr, "GET", "/api/saved-queries", None, &[]).await;
        assert_eq!(s, 401, "l'anonyme n'est pas servi : {brut}");
        assert!(!brut.contains("secret-dlsp"), "la requête privée ne sort pas : {brut}");
        let (s, c) = dlsp_envoyer(addr, "GET", "/api/saved-queries", Some(&dlsp_basic("demo", mot)), "").await;
        assert!(s == 200 && c.to_string().contains("secret-dlsp"), "le compte lit toujours la sienne : {s} {c}");

        let source = include_str!("../server/mod.rs");
        let run = &source[source.find("pub(crate) async fn run()").expect("`run` repérable")..];
        let appel = run.find("activation_de_la_demonstration::activer_la_demonstration_si_permise(").expect("`run` juge la démonstration demandée");
        let etat = run.find("let state = AppState {").expect("l'état servi est construit dans `run`");
        assert!(appel < etat, "le jugement précède la construction de l'état servi");
        assert!(run[appel..etat].contains("(!pass.is_empty()).then_some(user.as_str())"), "l'administrateur de configuration, défini comme `reserved_static_admin`");
        // (correction de vérification, tour 2) LE TYPE NE FERME QUE LA REPRISE DE LA VALEUR DEMANDÉE : tout autre `bool`
        // compile dans l'état servi. La liaison servie est donc lue ENTIÈRE, blancs réduits : le verdict lié tel quel,
        // sans bloc ni opérateur autour, et l'état le prend en forme courte.
        let liaison = run[..etat].rfind("let public_demo").expect("`run` lie la démonstration servie avant l'état");
        let liaison = run[liaison..etat].split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            liaison,
            "let public_demo = activation_de_la_demonstration::activer_la_demonstration_si_permise( &db.lock(), public_demo, (!pass.is_empty()).then_some(user.as_str()), );",
            "la démonstration servie EST le verdict, lié tel quel — pas un bloc qui l'appelle et rend autre chose"
        );
        let champ = run[etat..].find("public_demo").expect("l'état servi porte la démonstration");
        assert!(run[etat + champ..].starts_with("public_demo,"), "l'état servi prend la liaison du verdict (forme courte), pas une autre valeur");
        let boot = &source[source.find("fn boot_config() -> BootConfig").expect("`boot_config` repérable")..source.find("pub(crate) async fn run()").expect("run")];
        assert!(!boot.contains("accès ANONYME en LECTURE SEULE"), "`boot_config` ne publie plus la bannière avant le jugement");

        let structure = &source[source.find("struct BootConfig {").expect("`BootConfig` repérable")..source.find("fn boot_config() -> BootConfig").expect("boot_config")];
        assert!(
            structure.contains("public_demo: activation_de_la_demonstration::DemonstrationDemandee,"),
            "`BootConfig` porte la valeur DEMANDÉE sous son type, pas un `bool` que l'état prendrait sans jugement"
        );
        const FABRIQUE: &str = "DemonstrationDemandee::depuis_la_configuration(";
        const LECTURE: &str = "\"PLUME_PUBLIC_DEMO\"";
        assert_eq!(source.matches(LECTURE).count(), 1, "une seule lecture de `PLUME_PUBLIC_DEMO` dans le module du démarrage");
        let fabrique = boot.find(FABRIQUE).expect("`boot_config` fabrique la valeur demandée");
        let lecture = boot.find(LECTURE).expect("`boot_config` lit `PLUME_PUBLIC_DEMO`");
        assert!(fabrique < lecture && lecture - fabrique < 120, "la lecture de `PLUME_PUBLIC_DEMO` est l'argument de la fabrique");
        assert!(!run.contains(FABRIQUE), "`run()` ne refabrique pas une valeur demandée (qui rendrait le verdict jetable)");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.28-j` — LE PAQUET DE DIAGNOSTIC REND LA DÉMONSTRATION SERVIE (correction de vérification)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, au routeur réel, par l'administrateur de configuration : `GET /api/system/diag` rend
    /// `public_demo_served` égal au drapeau SERVI (`st.public_demo`), faux puis vrai — à côté de `config.PLUME_PUBLIC_DEMO`,
    /// qui rend la configuration. Avant, le paquet remis au support ne portait que la configuration : `"1"` sur un démon
    /// qui avait refusé la démonstration et répondait 401 à l'anonyme.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer l'insertion de `public_demo_served` dans `system_diag`.
    #[tokio::test]
    async fn dlsp_le_paquet_de_diagnostic_rend_la_demonstration_servie() {
        use crate::handlers::system::CLE_DE_LA_DEMONSTRATION_SERVIE;
        let administrateur = dlsp_basic("root-dlsp", "motdepasse-de-configuration-dlsp");
        for servie in [false, true] {
            let (st, _p) = dlsp_etat(if servie { "dlsp-diag-servie" } else { "dlsp-diag-non-servie" }, servie);
            let addr = router_serve(st).await;
            let (s, c) = dlsp_envoyer(addr, "GET", "/api/system/diag", Some(&administrateur), "").await;
            assert_eq!(s, 200, "fixture : le paquet est servi à l'administrateur : {c}");
            assert_eq!(c["kind"], json!("plume-diagnostic-bundle"), "fixture : c'est le paquet de diagnostic");
            assert_eq!(c[CLE_DE_LA_DEMONSTRATION_SERVIE], json!(servie), "le paquet rend la démonstration SERVIE ({servie})");
        }
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.28-i` / `P10.28-j` — LES CAUSES SERVIES DISENT CE QUI EST VRAI (correction de vérification)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur les phrases servies (DÉCRITES ici, jamais recopiées) :
    ///  * `CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION` (création d'un compte, assistant d'installation) ne dit plus que
    ///    l'anonyme MODIFIERAIT ou SUPPRIMERAIT ce qu'un compte `demo` tient — il n'écrit plus rien (`P10.28-i`) — et dit
    ///    que la démonstration refuserait de s'activer au-dessus d'un tel compte (`P10.28-j`) ; son préfixe, lu par la
    ///    console (`web/admin_users.js`), est intact ;
    ///  * `CAUSE_DEMONSTRATION_EN_LECTURE_SEULE` ne conseille plus « connectez-vous » — la console n'offre aucune connexion
    ///    sous une démonstration active (`/api/me` rend 200 `demo`, l'écran de connexion ne vient que d'un 401) — et dit ce
    ///    qu'une écriture demande : une identité à soi ;
    ///  * `CAUSE_ANNUAIRE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION` ne dit plus « active ou non » (la règle ne refuse plus que
    ///    sous la démonstration servie) ; son préfixe, lu par la console (`web/login.js`), est intact.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : rendre à chacune des trois sa phrase d'avant.
    #[test]
    fn dlsp_les_causes_de_la_demonstration_disent_ce_qui_est_vrai() {
        let reserve = CAUSE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION;
        for faux in ["modifierait", "supprimerait"] {
            assert!(!reserve.contains(faux), "la cause du nom réservé ne dit plus que l'anonyme « {faux} » : {reserve}");
        }
        assert!(reserve.contains("refuserait alors de s'activer"), "elle dit que la démonstration ne s'activerait pas : {reserve}");
        assert!(reserve.starts_with("NOM RÉSERVÉ, C'EST L'IDENTITÉ DE LA DÉMONSTRATION PUBLIQUE :"), "préfixe lu par la console : {reserve}");

        let lecture_seule = CAUSE_DEMONSTRATION_EN_LECTURE_SEULE;
        assert!(!lecture_seule.to_lowercase().contains("connectez"), "la lecture seule ne conseille pas une connexion que la console n'offre pas : {lecture_seule}");
        assert!(lecture_seule.contains("une identité à soi"), "elle dit ce qu'une écriture demande : {lecture_seule}");

        let annuaire = CAUSE_ANNUAIRE_NOM_DE_L_IDENTITE_DE_LA_DEMONSTRATION;
        assert!(!annuaire.contains("active ou non"), "le refus de l'annuaire ne vaut plus hors démonstration : {annuaire}");
        assert!(annuaire.contains("Tant que la démonstration est active"), "il dit quand il vaut : {annuaire}");
        assert!(annuaire.starts_with("IDENTITÉ DE L'ANNUAIRE REFUSÉE"), "préfixe lu par la console : {annuaire}");
    }
}
