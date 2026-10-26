// =====================================================================================
// `P10.20-b` et `P10.29-l` (vague AT) — LA PAGE KEYSET PORTE L'AVEU D'HORIZON, ET UNE VOIE FROIDE QUI N'A PAS PU LIRE
// LE TIER FROID EST UNE BASE ILLISIBLE, PAS UNE REQUÊTE REJETÉE.
//
// LES DÉFAUTS, LUS SUR 53488460 AVANT LE CORRECTIF :
//  * `handlers/query.rs` : les trois sorties keyset (voie colonnaire vers :1573, oracle d'union vers :1637, chemin
//    chaud vers :1659, toutes par `keyset_reponse`) rendaient la page SANS `stats.coverage`, alors que `couverture`
//    était déjà calculée (vers :1435) et posée sur toutes les autres voies par `avec_couverture` : une page keyset
//    lue sous l'horizon de rétention, ou sous la frontière froide, se lisait comme complète ;
//  * `query_exec::en_classant` range tout échec sans note sous `Moteur` : aux cinq sites froids (vers :988, :1589,
//    :1697, :1739, :2176), un fichier froid écrasé ou retiré, un horizon de lecture non lu ou une ouverture ratée
//    étaient servis en 400 `REQUETE_REJETEE_PAR_LE_MOTEUR` — une faute de la requête — et le texte de la lecture
//    froide, qui cite le chemin d'un fichier, partait au journal sous la nature « hors du cœur ».
//
// DÉSORMAIS : `keyset_reponse` reçoit la couverture (paramètre obligatoire) et la pose ; les cinq sites froids
// classent par `query_exec::en_classant_la_voie_froide` : la note du fil garde sa classe (le SQL de l'appelant refusé
// par le moteur sur l'union reste un 400 à l'octet), deux refus du produit gardent la leur (400), tout autre échec
// est du support : 503 `CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE`, ouverture que la console lit déjà (`web/viz.js:946`
// lit le corps quel que soit le statut, `web/viz.js:3058` et `:3264` le passent à `showQError`), et la ligne
// `[query]` porte la nature fixe ET le texte échappé de la cause (aucune ligne `[sqlite]` ni `[cold]` ne la relaie) :
// l'exploitant y lit le fichier froid fautif ou le réglage d'horizon non lu ; la réponse n'en porte rien.
//
// LES TÉMOINS :
// (1) `at1_keyset_chaud_porte_la_couverture_par_la_route` : routeur réel, jeton lecteur, keyset chaud, fenêtre SOUS
//     l'horizon de rétention puis DANS l'horizon ; `stats.coverage` comparé EN ENTIER à un objet littéral ;
// (2) `at1_keyset_chaud_deux_tenants` : mode 1, deux tenants réels aux rétentions différentes, même fenêtre : l'aveu
//     suit la base de l'appelant (dans l'horizon pour l'un, dessous pour l'autre) ;
// (3) `cold_tier` — `at1_keyset_froid_porte_la_couverture_par_la_route` : la voie colonnaire (armée) et l'oracle
//     d'union (voie désarmée), fenêtre sous la frontière froide puis fenêtre non bornée ;
// (4) `cold_tier` — `at1_voie_froide_illisible_sert_le_503_par_la_route` : sous-processus, routeur réel, jeton lecteur,
//     les six voies froides (union paginée, keyset par l'oracle, export, keyset colonnaire, fusion vectorisée,
//     vectorisée pur-froide), chacune nominale (voie contrôlée) puis fichiers froids ÉCRASÉS puis RETIRÉS : 503
//     `{error, id}` exactement, aucune trace de la lecture froide dans la réponse brute, journal `[query]` : préfixe
//     ENTIER (route, tenant, identifiant servi, nature) puis le texte de la cause, qui nomme la racine froide ;
// (5) `cold_tier` — `at1_plafond_de_groupes_reste_un_refus_du_produit` : sous-processus, agrégat froid au-delà du
//     plafond de groupes : 400 à phrase fixe comme avant, ligne `[query]` entière jugée sur le texte relevé au
//     producteur par l'appel même que la route fait ;
// (6) `cold_tier` — `at1_horizon_froid_non_lu_est_du_support` : `cold_union_query` sur une base au réglage de rétention
//     écrit illisible (« 365.0 »), par le classeur que la route appelle : support, nature fixe, texte du producteur ;
// (7) `cold_tier` — `at1_troncature_inattendue_reste_un_refus_du_produit` : le texte réel d'`expect_exact` ;
// (8) `at1_classeur_froid_garde_la_note_et_range_le_reste_au_support` : succès, note du moteur et note du support
//     gardées, note périmée effacée, texte étranger après une note, les deux ouvertures du produit, le reste ;
// (9) `cold_tier` — `at1_journal_nomme_la_cause_de_la_panne_froide` : sous-processus, union paginée : horizon de
//     lecture non lu (par le classeur et `refus_de_requete`, la route lisant le réglage avant d'aiguiller) puis
//     (réglage rendu, page nominale par la route) fichiers froids écrasés par le routeur réel : deux 503 identiques
//     pour l'appelant, deux lignes `[query]` DISTINCTES : la première porte le texte exact `HORIZON_FROID_NON_LU`,
//     la seconde le texte de la lecture du fichier, qui nomme la racine froide.
//
// LES MUTATIONS QUI LES FONT ROUGIR (posées sous `cfg!(test)` par une variable de mutation, retirées du source avant le commit) :
// sortie keyset sans couverture (1)(2)(3) ; une par sortie keyset (1)(3) ; couverture calculée sur la base par défaut
// (2) ; un par site froid rendu à `en_classant` (4) ; « support pour tout » (8) et les témoins `ar2_` du froid ;
// « moteur pour tout » (4)(6)(8) ; chaque ouverture du produit retirée (5)(7)(8) ; note du fil non effacée (8) ;
// ligne du support froid sans la cause (4)(9) et le témoin `ar2_` de la part froide illisible ; cause journalisée
// pour TOUT support, base vive comprise (témoins `ar2_` du support). Le mot du module froid hors de `cold_store`
// (garde `p2b_hydrate_is_internal_no_query_or_handler_reference`) : un fichier `.rs` hors module qui le porte.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la couverture des voies froides n'est jouée qu'au tenant par défaut (elle est
// calculée une fois, avant l'aiguillage, et (2) la joue avec deux tenants) ; une base froide OCCUPÉE à l'ouverture
// rend un texte sans code (`cold_store` rend `String`) et sert donc la phrase de la base illisible, pas celle de la
// base occupée ; trois causes (horizon non lu, fichier corrompu, fichier absent) partagent la NATURE et ne se
// distinguent qu'au texte de la ligne (seuls l'horizon et le fichier écrasé sont jugés distincts par (9)) ; le refus du compilateur
// dans `hot_partial` est hors d'atteinte (commentaire au classeur) ; la console n'affiche pas `stats.coverage` dans
// l'Explore (`renderQBadge`, `web/viz.js:792`, ne lit que la provenance, la troncature et la part froide).
// =====================================================================================
mod at1_couverture_keyset_et_voie_froide {
    use super::*;
    use crate::query_exec::{en_classant, en_classant_la_voie_froide, EchecDeRequete};

    const AT1_JOUR: i64 = 86_400;
    const AT1_SOQL: &str = "search source=at1";
    const AT1_ALPHA: &str = "at1-alpha";
    const AT1_BETA: &str = "at1-beta";
    const AT1_RAISON_RETENTION: &str = "retention_floor";
    /// Les phrases d'horizon (`notice_d_horizon`, `handlers/panneau_avoue.rs`), recopiées.
    const AT1_NOTICE_RETENTION_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
    const AT1_NOTICE_RETENTION_DEDANS: &str = "la fenêtre demandée tient AU-DESSUS de l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce panneau n'est assuré d'en voir aucune : rien n'est resté dehors de ce fait.";
    /// `query_exec::NATURE_DE_LA_LECTURE_FROIDE` et `NATURE_HORS_DU_COEUR`, recopiées.
    const AT1_NATURE_DE_LA_LECTURE_FROIDE: &str =
        "lecture du tier froid non faite (ouverture, horizon de lecture, hydratation ou décodage d'un fichier), hors du cœur d'exécution";
    const AT1_NATURE_HORS_DU_COEUR: &str = "erreur hors du cœur d'exécution";
    /// Les deux ouvertures des refus du produit rendus en texte par les voies froides, recopiées.
    const AT1_OUVERTURE_PLAFOND_DE_GROUPES: &str = "refus de rendre un agrégat INCOMPLET : ce group-by dépasse ";
    const AT1_OUVERTURE_TRONCATURE_INATTENDUE: &str = "P4b hot_partial: troncature INATTENDUE sur un chemin sans hydratation froide (";
    #[cfg(feature = "cold_tier")]
    const AT1_RAISON_COLD: &str = "cold_boundary";
    #[cfg(feature = "cold_tier")]
    const AT1_RAISON_NON_BORNEE: &str = "fenetre_non_bornee";
    #[cfg(feature = "cold_tier")]
    const AT1_NOTICE_FROID_DEHORS: &str = "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS la frontière du vieillissement froid : sous elle, les lignes ont quitté la base vive et ce panneau n'a aucun chemin pour les lire. La part antérieure à cet horizon est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que cet horizon, il se peut que rien n'ait jamais été supprimé.";
    #[cfg(feature = "cold_tier")]
    const AT1_NOTICE_FROID_NON_BORNEE: &str = "fenêtre non bornée : tout ce que la base porte encore a été cherché. la frontière du vieillissement froid : sous elle, les lignes ont quitté la base vive et ce panneau n'a aucun chemin pour les lire — ce panneau ne voit rien au-delà, quelle que soit la fenêtre demandée.";
    /// `CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE` et `REQUETE_REJETEE_PAR_LE_MOTEUR` (`handlers/query.rs`), recopiées.
    #[cfg(feature = "cold_tier")]
    const AT1_CAUSE_BASE_ILLISIBLE: &str = "REQUÊTE NON SERVIE : la base n'a pas pu être lue (erreur du support : entrée-sortie, disque, fichier illisible ou corrompu) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez ; si le refus persiste, la base est illisible : l'exploitant en trouve le code au journal.";
    #[cfg(feature = "cold_tier")]
    const AT1_REQUETE_REJETEE: &str = "requête REFUSÉE par le moteur (ce n'est pas un résultat vide) : syntaxe, champ, motif ou accès rejeté — rien n'est rendu ; le détail est au journal de l'exploitant.";
    /// `HORIZON_FROID_NON_LU` (`cold_store/reader.rs`), recopiée.
    #[cfg(feature = "cold_tier")]
    const AT1_HORIZON_FROID_NON_LU: &str =
        "lecture froide refusée : réglage retention_days écrit mais non lu — l'horizon de rétention froide est inconnu, aucun jour froid n'est servi";
    #[cfg(feature = "cold_tier")]
    const AT1_SOQL_FROID: &str = "search source=froid";
    #[cfg(feature = "cold_tier")]
    const AT1_SOQL_FROID_COMPTE: &str = "search source=froid | stats count";
    #[cfg(feature = "cold_tier")]
    const AT1_SOQL_FROID_GROUPES: &str = "search source=froid | stats count by message";
    #[cfg(feature = "cold_tier")]
    const AT1_ENFANT_ILLISIBLE: &str = "AT1_ENFANT_VOIE_FROIDE_ILLISIBLE";
    #[cfg(feature = "cold_tier")]
    const AT1_ENFANT_GROUPES: &str = "AT1_ENFANT_PLAFOND_DE_GROUPES";
    #[cfg(feature = "cold_tier")]
    const AT1_ENFANT_CAUSE: &str = "AT1_ENFANT_CAUSE_DE_LA_PANNE_FROIDE";
    #[cfg(feature = "cold_tier")]
    const AT1_LEVIER_PLAFOND_DE_GROUPES: &str = "PLUME_COLD_GROUP_MAX";
    #[cfg(feature = "cold_tier")]
    const AT1_RENDU: &str = "AT1-RENDU:";
    #[cfg(feature = "cold_tier")]
    const AT1_FIN: &str = "AT1-FIN:";
    #[cfg(feature = "cold_tier")]
    const AT1_RELEVE: &str = "AT1-RELEVE:";

    /// L'aveu d'horizon attendu, objet ENTIER (mêmes clés que `horizon_et_frontiere_du_sql`).
    fn at1_couverture_attendue(depuis: i64, calcule_a: i64, horizon_ts: i64, dehors: bool, raison: &str, notice: &str) -> Value {
        json!({
            "searched_from": depuis,
            "calcule_a": calcule_a,
            "horizon_ts": horizon_ts,
            "older_outside_window": dehors,
            "reason": raison,
            "notice": notice,
        })
    }

    fn at1_poser_la_retention(conn: &Connection, jours: &str) {
        conn.execute("INSERT OR REPLACE INTO setting(scope,key,value) VALUES('global','retention_days',?1)", params![jours]).expect("fixture : rétention posée");
    }

    fn at1_semer(conn: &Connection, ts: i64) {
        conn.execute("INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'at1',1,'at1-sonde','at1-h',NULL)", params![ts])
            .expect("fixture : événement");
    }

    /// POST par le routeur réel : (statut, corps décodé, réponse brute en-têtes compris).
    async fn at1_envoi(addr: std::net::SocketAddr, route: &str, authz: &str, corps: &Value) -> (u16, String, String) {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, "POST", route, Some(authz), &entetes, &corps.to_string()).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {route} : {brut}"));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {route}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        (code, c, brut)
    }

    /// La page est bien une page KEYSET (curseur rendu, aucun total ni décalage du repli par décalage).
    fn at1_controle_keyset(contexte: &str, v: &Value) {
        assert!(v.get("next_cursor").is_some() && v.get("has_more").is_some(), "contrôle : {contexte} servi par une sortie keyset : {v}");
        assert!(v.get("total").is_none() && v.get("offset").is_none(), "contrôle : {contexte} n'est pas le repli par décalage : {v}");
    }

    /// (1) LE KEYSET CHAUD, PAR LA ROUTE, AU RÔLE LECTEUR : sous l'horizon puis dans l'horizon.
    #[tokio::test]
    async fn at1_keyset_chaud_porte_la_couverture_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _base) = router_test_state("at1-keyset-chaud");
        let maintenant = now();
        {
            let c = st.db.lock();
            at1_poser_la_retention(&c, "30");
            at1_semer(&c, maintenant - 60);
        }
        let addr = router_serve(st.clone()).await;
        let lecteur = viewer_authz();
        let mut joues = 0;
        for (fenetre, depuis, dehors, notice) in [
            ("sous l'horizon", maintenant - 40 * AT1_JOUR, true, AT1_NOTICE_RETENTION_DEHORS),
            ("dans l'horizon", maintenant - 3600, false, AT1_NOTICE_RETENTION_DEDANS),
        ] {
            let corps = json!({ "soql": AT1_SOQL, "from": depuis, "to": maintenant + 3600, "limit": 10, "keyset": true });
            let (code, b, _) = at1_envoi(addr, "/api/query", &lecteur, &corps).await;
            assert_eq!(code, 200, "contrôle : keyset chaud {fenetre} servi : {b}");
            let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
            at1_controle_keyset(fenetre, &v);
            assert_eq!(v["rows"].as_array().map(Vec::len), Some(1), "contrôle : la ligne semée est servie ({fenetre}) : {b}");
            let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("keyset chaud {fenetre} : pas de `stats.coverage` : {b}"));
            assert!(calcule_a >= maintenant, "contrôle : l'instant du verdict est celui de la requête ({calcule_a} < {maintenant})");
            assert_eq!(
                v["stats"]["coverage"],
                at1_couverture_attendue(depuis, calcule_a, calcule_a - 30 * AT1_JOUR, dehors, AT1_RAISON_RETENTION, notice),
                "keyset chaud {fenetre} : l'aveu d'horizon entier"
            );
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux fenêtres jouées");
    }

    fn at1_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-at1".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    /// (2) DEUX TENANTS RÉELS, RÉTENTIONS DIFFÉRENTES, MÊME FENÊTRE : l'aveu suit la base de l'appelant.
    #[tokio::test]
    async fn at1_keyset_chaud_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        let maintenant = now();
        for (t, jours) in [(AT1_ALPHA, "30"), (AT1_BETA, "10")] {
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-at1")), Json(json!({ "id": t, "name": t }))).await;
            assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
            let base = st.tenants.handle_for(t).expect("contrôle : base du tenant");
            let c = base.lock();
            at1_poser_la_retention(&c, jours);
            at1_semer(&c, maintenant - 60);
        }
        let depuis = maintenant - 20 * AT1_JOUR;
        let corps = json!({ "soql": AT1_SOQL, "from": depuis, "to": maintenant + 3600, "limit": 10, "keyset": true });
        let mut joues = 0;
        for (t, jours, dehors, notice) in [(AT1_ALPHA, 30, false, AT1_NOTICE_RETENTION_DEDANS), (AT1_BETA, 10, true, AT1_NOTICE_RETENTION_DEHORS)] {
            let r = crate::handlers::query::query(State(st.clone()), Extension(at1_lecteur(t)), Json(corps.clone())).await;
            let code = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            let v: Value = serde_json::from_slice(&b).expect("contrôle : réponse JSON");
            assert_eq!(code, 200, "contrôle : {t} servi : {v}");
            at1_controle_keyset(t, &v);
            let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{t} : pas de `stats.coverage` : {v}"));
            assert_eq!(
                v["stats"]["coverage"],
                at1_couverture_attendue(depuis, calcule_a, calcule_a - jours * AT1_JOUR, dehors, AT1_RAISON_RETENTION, notice),
                "{t} : l'aveu est calculé sur la base de l'appelant ({jours} j)"
            );
            joues += 1;
        }
        assert_eq!(joues, 2, "contrôle : deux tenants joués");
    }

    /// (3) LES DEUX SORTIES KEYSET FROIDES : voie colonnaire (armée) et oracle d'union (désarmée).
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn at1_keyset_froid_porte_la_couverture_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // le banc froid pose l'environnement
        let mut joues = 0;
        for (vectorise, voie) in [(true, "hot+cold-vectorized-keyset"), (false, "hot+cold")] {
            let banc = BancFroidSurLaRoute::monter(if vectorise { "at1-cov-colonnaire" } else { "at1-cov-oracle" }, vectorise).await;
            banc.vieillir();
            for depuis in [banc.base_froide - 60, 0] {
                let corps = json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": banc.maintenant + 60, "limit": 10, "keyset": true });
                let (code, b, _) = at1_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
                assert_eq!(code, 200, "contrôle : {voie} depuis {depuis} servi : {b}");
                let v: Value = serde_json::from_str(&b).expect("contrôle : réponse JSON");
                at1_controle_keyset(voie, &v);
                assert_eq!(v["stats"]["cold"]["served_from"], json!(voie), "contrôle : la page est servie par la voie visée : {b}");
                let frontiere = v["stats"]["cold"]["boundary_ts"].as_i64().unwrap_or_else(|| panic!("contrôle : frontière publiée : {b}"));
                let calcule_a = v["stats"]["coverage"]["calcule_a"].as_i64().unwrap_or_else(|| panic!("{voie} depuis {depuis} : pas de `stats.coverage` : {b}"));
                let attendu = if depuis > 0 {
                    at1_couverture_attendue(depuis, calcule_a, frontiere, true, AT1_RAISON_COLD, AT1_NOTICE_FROID_DEHORS)
                } else {
                    at1_couverture_attendue(0, calcule_a, frontiere, false, AT1_RAISON_NON_BORNEE, AT1_NOTICE_FROID_NON_BORNEE)
                };
                assert_eq!(v["stats"]["coverage"], attendu, "{voie} depuis {depuis} : l'aveu d'horizon entier");
                joues += 1;
            }
        }
        assert_eq!(joues, 4, "contrôle : deux voies, deux fenêtres");
    }

    #[cfg(feature = "cold_tier")]
    type At1Rendus = Vec<(String, String, u16, String, String)>;

    /// Tous les fichiers sous la racine froide dérivée de la base (fichiers de la fixture, jamais la base vivante).
    #[cfg(feature = "cold_tier")]
    fn at1_fichiers_froids(chemin_base: &str) -> Vec<std::path::PathBuf> {
        let mut a_voir = vec![std::path::PathBuf::from(format!("{chemin_base}.cold"))];
        let mut fichiers = Vec::new();
        while let Some(d) = a_voir.pop() {
            for entree in std::fs::read_dir(&d).expect("fixture : racine froide lisible") {
                let chemin = entree.expect("fixture : entrée de la racine froide lisible").path();
                if chemin.is_dir() {
                    a_voir.push(chemin);
                } else {
                    fichiers.push(chemin);
                }
            }
        }
        fichiers
    }

    #[cfg(feature = "cold_tier")]
    fn at1_lancer_l_enfant(mut enfant: std::process::Command, test: &str) -> (String, String) {
        let sortie = enfant.args(["--exact", "--nocapture", "--test-threads=1", test]).output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    #[cfg(feature = "cold_tier")]
    fn at1_lire_les_rendus(stdout: &str) -> At1Rendus {
        stdout
            .lines()
            .filter_map(|l| l.split_once(AT1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect()
    }

    #[cfg(feature = "cold_tier")]
    fn at1_journal(stderr: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with("[query] ")).map(str::to_string).collect()
    }

    /// Le 503 de la base illisible : `{error, id}` exactement, la phrase fixe, et l'identifiant rendu.
    #[cfg(feature = "cold_tier")]
    fn at1_refus_illisible(contexte: &str, code: u16, corps: &str) -> String {
        let v: Value = serde_json::from_str(corps).unwrap_or(Value::Null);
        assert_eq!(code, 503, "{contexte} : statut de la base illisible : {corps}");
        let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, vec!["error", "id"], "{contexte} : exactement `error` et `id` : {v}");
        assert_eq!(v["error"], json!(AT1_CAUSE_BASE_ILLISIBLE), "{contexte} : la phrase fixe de la base illisible");
        let id = v["id"].as_str().unwrap_or_default().to_string();
        assert!(id.starts_with("plume-e"), "{contexte} : identifiant de corrélation : {v}");
        id
    }

    /// Ce que la réponse brute (en-têtes compris) ne porte jamais : les mots des textes de la lecture froide.
    #[cfg(feature = "cold_tier")]
    const AT1_TRACES_FROIDES: [&str; 6] = ["hydrate", "vectoris", "materialize", ".cold", "Parquet", "requête ÉCHOUÉE"];

    /// (4) LES SIX VOIES FROIDES, FICHIERS ÉCRASÉS PUIS RETIRÉS, PAR LA ROUTE.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn at1_voie_froide_illisible_sert_le_503_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // le banc froid pose l'environnement
        if std::env::var(AT1_ENFANT_ILLISIBLE).is_ok() {
            let mut rendus: At1Rendus = Vec::new();
            for vectorise in [false, true] {
                let banc = BancFroidSurLaRoute::monter(if vectorise { "at1-illisible-colonnaire" } else { "at1-illisible-oracle" }, vectorise).await;
                banc.vieillir();
                let (depuis, jusqua) = (banc.base_froide - 60, banc.maintenant + 60);
                let keyset = json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": jusqua, "limit": 10, "keyset": true });
                let (_, b, _) = at1_envoi(banc.addr, "/api/query", &banc.authz, &keyset).await;
                let frontiere = serde_json::from_str::<Value>(&b).ok().and_then(|v| v["stats"]["cold"]["boundary_ts"].as_i64()).unwrap_or(0);
                let sites: Vec<(&str, &str, Value)> = if vectorise {
                    vec![
                        ("keyset_colonnaire", "/api/query", keyset.clone()),
                        ("fusion_vectorisee", "/api/query", json!({ "soql": AT1_SOQL_FROID_COMPTE, "from": depuis, "to": jusqua })),
                        ("pur_froid_vectorise", "/api/query", json!({ "soql": AT1_SOQL_FROID_COMPTE, "from": depuis, "to": frontiere - 1 })),
                    ]
                } else {
                    vec![
                        ("union_paginee", "/api/query", json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": jusqua, "limit": 10 })),
                        ("keyset_oracle", "/api/query", keyset.clone()),
                        ("export", "/api/export", json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": jusqua, "format": "json" })),
                    ]
                };
                for (site, route, corps) in &sites {
                    let (c, b, brut) = at1_envoi(banc.addr, route, &banc.authz, corps).await;
                    rendus.push((site.to_string(), "nominal".into(), c, b, brut));
                }
                let fichiers = at1_fichiers_froids(&banc.chemin_base);
                println!("{AT1_RELEVE}{}", json!({ "vectorise": vectorise, "fichiers": fichiers.len(), "frontiere": frontiere, "racine": format!("{}.cold", banc.chemin_base) }));
                for f in &fichiers {
                    let taille = std::fs::metadata(f).expect("fixture : taille du fichier froid").len() as usize;
                    std::fs::write(f, vec![0x5a_u8; taille.max(64)]).expect("fixture : fichier froid écrasé");
                }
                for (site, route, corps) in &sites {
                    let (c, b, brut) = at1_envoi(banc.addr, route, &banc.authz, corps).await;
                    rendus.push((site.to_string(), "ecrase".into(), c, b, brut));
                }
                for f in &fichiers {
                    std::fs::remove_file(f).expect("fixture : fichier froid retiré");
                }
                for (site, route, corps) in &sites {
                    let (c, b, brut) = at1_envoi(banc.addr, route, &banc.authz, corps).await;
                    rendus.push((site.to_string(), "retire".into(), c, b, brut));
                }
            }
            for r in &rendus {
                println!("{AT1_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AT1_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = at1_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AT1_ENFANT_ILLISIBLE, "1");
                enfant
            },
            "tests::at1_couverture_keyset_et_voie_froide::at1_voie_froide_illisible_sert_le_503_par_la_route",
        );
        let rendus = at1_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AT1_FIN} 18")), "contrôle : six voies, trois issues chacune : {stdout}\n{stderr}");
        assert!(rendus.len() >= 18, "plancher : dix-huit issues rendues ({})", rendus.len());
        let releves: Vec<Value> = stdout.lines().filter_map(|l| l.split_once(AT1_RELEVE)).map(|(_, v)| serde_json::from_str(v).expect("contrôle : relevé lisible")).collect();
        assert_eq!(releves.len(), 2, "contrôle : deux bancs relevés : {stdout}");
        for r in &releves {
            assert!(r["fichiers"].as_i64().unwrap_or(0) >= 1, "contrôle : au moins un fichier froid écrasé puis retiré : {r}");
            assert!(r["frontiere"].as_i64().unwrap_or(0) > 0, "contrôle : la frontière lue sur la page nominale : {r}");
        }
        let racine_de = |vectorise: bool| -> String {
            releves.iter().find(|r| r["vectorise"] == json!(vectorise)).and_then(|r| r["racine"].as_str()).unwrap_or_else(|| panic!("contrôle : racine froide relevée : {releves:?}")).to_string()
        };
        let mut attendu_journal: Vec<(String, String)> = Vec::new();
        let mut juges = 0;
        for (site, issue, code, corps, brut) in &rendus {
            let route = if site == "export" { "/api/export" } else { "/api/query" };
            if issue == "nominal" {
                assert_eq!(*code, 200, "contrôle : {site} nominal servi : {corps}");
                if route == "/api/query" {
                    let v: Value = serde_json::from_str(corps).expect("contrôle : réponse JSON");
                    let (ou, voie) = match site.as_str() {
                        "keyset_colonnaire" => (v["stats"]["cold"]["served_from"].clone(), "hot+cold-vectorized-keyset"),
                        "fusion_vectorisee" => (v["stats"]["served_from"].clone(), "cold-vectorized-merge"),
                        "pur_froid_vectorise" => (v["stats"]["served_from"].clone(), "cold-vectorized"),
                        _ => (v["stats"]["cold"]["served_from"].clone(), "hot+cold"),
                    };
                    assert_eq!(ou, json!(voie), "contrôle : {site} est servi par la voie visée : {corps}");
                }
                continue;
            }
            let id = at1_refus_illisible(&format!("{site}/{issue}"), *code, corps);
            for trace in AT1_TRACES_FROIDES {
                assert!(!brut.contains(trace), "{site}/{issue} : la réponse porte « {trace} » : {brut}");
            }
            let vectorise = matches!(site.as_str(), "keyset_colonnaire" | "fusion_vectorisee" | "pur_froid_vectorise");
            attendu_journal.push((
                format!("[query] WARN requête non servie, erreur du support de la base ({route}, tenant 'default', {id}) : {AT1_NATURE_DE_LA_LECTURE_FROIDE} : \""),
                racine_de(vectorise),
            ));
            juges += 1;
        }
        assert_eq!(juges, 12, "contrôle : six voies, deux pannes chacune");
        let journal = at1_journal(&stderr);
        assert_eq!(journal.len(), attendu_journal.len(), "une ligne `[query]` par voie froide illisible :\n{stderr}");
        for (ligne, (prefixe, racine)) in journal.iter().zip(&attendu_journal) {
            let cause = ligne.strip_prefix(prefixe.as_str()).unwrap_or_else(|| panic!("la ligne porte route, tenant, identifiant et nature, puis la cause : attendu « {prefixe}… », lu « {ligne} »"));
            assert!(cause.ends_with('"') && cause.len() > 1, "la cause est le texte échappé sur la ligne : {ligne}");
            assert!(cause.contains(racine.as_str()), "la cause nomme le fichier froid fautif (racine {racine}) : {ligne}");
        }
    }

    /// Retire à la chute le levier posé par le témoin (5), panic compris.
    #[cfg(feature = "cold_tier")]
    struct At1LevierPose(&'static str);
    #[cfg(feature = "cold_tier")]
    impl Drop for At1LevierPose {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    /// (5) LE PLAFOND DE GROUPES D'UN AGRÉGAT FROID RESTE UN REFUS DU PRODUIT (400), PAS UNE BASE ILLISIBLE.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn at1_plafond_de_groupes_reste_un_refus_du_produit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        if std::env::var(AT1_ENFANT_GROUPES).is_ok() {
            std::env::set_var(AT1_LEVIER_PLAFOND_DE_GROUPES, "1");
            let _levier = At1LevierPose(AT1_LEVIER_PLAFOND_DE_GROUPES);
            let banc = BancFroidSurLaRoute::monter("at1-plafond-de-groupes", true).await;
            // Une seconde valeur de `message` dans la journée froide : deux groupes pour un plafond d'un. Une ligne
            // chaude est posée APRÈS elle : sans quoi la journée froide détiendrait le dernier rowid de la table, et le
            // vieillissement la diffère (garde anti-réutilisation, `cold_store/aging.rs`).
            {
                let c = banc.st.db.lock();
                for (ts, dedup, message) in [(banc.base_froide + 30, "at1-autre", "at1 autre message"), (banc.maintenant - 30, "at1-chaude-apres", "ligne chaude")] {
                    c.execute(
                        "INSERT INTO event(ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields) \
                         VALUES(?1,1,'froid','test','h-froid','','','','',?2,'','','prod',?3,'{}')",
                        params![ts, dedup, message],
                    )
                    .expect("fixture : ligne posée");
                }
            }
            banc.vieillir();
            let depuis = banc.base_froide - 60;
            let keyset = json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": banc.maintenant + 60, "limit": 10, "keyset": true });
            let (_, b, _) = at1_envoi(banc.addr, "/api/query", &banc.authz, &keyset).await;
            let frontiere = serde_json::from_str::<Value>(&b).ok().and_then(|v| v["stats"]["cold"]["boundary_ts"].as_i64()).unwrap_or(0);
            let corps = json!({ "soql": AT1_SOQL_FROID_GROUPES, "from": depuis, "to": frontiere - 1 });
            let (c, b, brut) = at1_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
            println!("{AT1_RENDU}{}", json!(["groupes", "plafond", c, b, brut]));
            // Le texte que la voie pur-froide rend, relevé au producteur par l'appel même que la route fait.
            let texte = crate::cold_store::cold_vectorized_try(
                &banc.chemin_base, &banc.conf, None, depuis, frontiere - 1, frontiere, AT1_SOQL_FROID_GROUPES, true, crate::query_exec::query_budget_ms(), &[],
            )
            .err();
            println!("{AT1_RELEVE}{}", json!({ "texte": texte, "frontiere": frontiere }));
            println!("{AT1_FIN} 1");
            return;
        }
        let (stdout, stderr) = at1_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AT1_ENFANT_GROUPES, "1");
                enfant
            },
            "tests::at1_couverture_keyset_et_voie_froide::at1_plafond_de_groupes_reste_un_refus_du_produit",
        );
        let rendus = at1_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AT1_FIN} 1")) && rendus.len() == 1, "contrôle : une issue rendue : {stdout}\n{stderr}");
        let releve: Value = stdout
            .lines()
            .find_map(|l| l.split_once(AT1_RELEVE))
            .map(|(_, v)| serde_json::from_str(v).expect("contrôle : relevé lisible"))
            .unwrap_or_else(|| panic!("contrôle : relevé du producteur : {stdout}"));
        assert!(releve["frontiere"].as_i64().unwrap_or(0) > 0, "contrôle : frontière lue : {releve}");
        let texte = releve["texte"].as_str().unwrap_or_else(|| panic!("contrôle : la voie pur-froide refuse au producteur : {releve}")).to_string();
        assert!(texte.starts_with(AT1_OUVERTURE_PLAFOND_DE_GROUPES), "contrôle : le producteur rend le refus du plafond de groupes : {texte}");
        let (_, _, code, corps, brut) = &rendus[0];
        assert_eq!(
            (*code, serde_json::from_str::<Value>(corps).unwrap_or(Value::Null)),
            (400, json!({ "error": AT1_REQUETE_REJETEE })),
            "le refus du produit reste le 400 d'avant, à l'octet, jamais le 503 de la base illisible"
        );
        assert!(!brut.contains(AT1_OUVERTURE_PLAFOND_DE_GROUPES), "la réponse ne porte pas le texte du refus : {brut}");
        assert_eq!(
            at1_journal(&stderr),
            vec![format!("[query] WARN requête rejetée par le moteur (/api/query, tenant 'default') : {AT1_NATURE_HORS_DU_COEUR} : {texte:?}")],
            "la ligne `[query]` d'avant, entière :\n{stderr}"
        );
    }

    /// (6) LE RÉGLAGE DE RÉTENTION ÉCRIT ILLISIBLE, AU PRODUCTEUR, PAR LE CLASSEUR QUE LA ROUTE APPELLE.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn at1_horizon_froid_non_lu_est_du_support() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let banc = BancFroidSurLaRoute::monter("at1-horizon-non-lu", false).await;
        banc.vieillir();
        let depuis = banc.base_froide - 60;
        let keyset = json!({ "soql": AT1_SOQL_FROID, "from": depuis, "to": banc.maintenant + 60, "limit": 10, "keyset": true });
        let (_, b, _) = at1_envoi(banc.addr, "/api/query", &banc.authz, &keyset).await;
        let frontiere = serde_json::from_str::<Value>(&b).ok().and_then(|v| v["stats"]["cold"]["boundary_ts"].as_i64()).unwrap_or_else(|| panic!("contrôle : frontière lue : {b}"));
        let sql = "SELECT ts, message FROM event";
        let lue = en_classant_la_voie_froide(|| {
            crate::cold_store::cold_union_query(&banc.chemin_base, &banc.conf, None, depuis, banc.maintenant + 60, frontiere, sql, None, 5_000, None, &[])
        });
        assert!(lue.is_ok(), "contrôle : la lecture froide aboutit sur un réglage lisible");
        at1_poser_la_retention(&banc.st.db.lock(), "365.0");
        let refusee = en_classant_la_voie_froide(|| {
            crate::cold_store::cold_union_query(&banc.chemin_base, &banc.conf, None, depuis, banc.maintenant + 60, frontiere, sql, None, 5_000, None, &[])
        })
        .map(|_| ());
        assert_eq!(
            refusee,
            Err(EchecDeRequete::Support { nature: AT1_NATURE_DE_LA_LECTURE_FROIDE.into(), texte: AT1_HORIZON_FROID_NON_LU.into() }),
            "un horizon de lecture non lu est une base illisible, jamais un refus du moteur"
        );
    }

    /// (9) LE JOURNAL NOMME LA CAUSE D'UNE PANNE FROIDE : horizon non lu et fichier écrasé, même 503, deux lignes distinctes.
    #[cfg(feature = "cold_tier")]
    #[tokio::test]
    async fn at1_journal_nomme_la_cause_de_la_panne_froide() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        if std::env::var(AT1_ENFANT_CAUSE).is_ok() {
            let banc = BancFroidSurLaRoute::monter("at1-cause-au-journal", false).await;
            banc.vieillir();
            let corps = json!({ "soql": AT1_SOQL_FROID, "from": banc.base_froide - 60, "to": banc.maintenant + 60, "limit": 10 });
            let mut rendus: At1Rendus = Vec::new();
            let mut envoyer = |issue: &str, r: (u16, String, String)| rendus.push(("union_paginee".into(), issue.into(), r.0, r.1, r.2));
            let nominal = at1_envoi(banc.addr, "/api/query", &banc.authz, &corps).await;
            let frontiere = serde_json::from_str::<Value>(&nominal.1).ok().and_then(|v| v["stats"]["cold"]["boundary_ts"].as_i64()).unwrap_or(0);
            envoyer("nominal", nominal);
            // L'HORIZON NON LU : la route lit le même réglage AVANT d'aiguiller (`retention_effective_lue`, vers
            // `handlers/query.rs:1274`) et sert alors la part chaude avec l'aveu de frontière non lue ; le refus du
            // lecteur froid n'arrive qu'à un réglage changé entre les deux lectures. Il est donc joué par le chemin
            // exact de la route après l'aiguillage : le classeur de la voie froide, puis `refus_de_requete`.
            at1_poser_la_retention(&banc.st.db.lock(), "365.0");
            let sql = "SELECT ts, message FROM event";
            let echec = en_classant_la_voie_froide(|| {
                crate::cold_store::cold_union_query(&banc.chemin_base, &banc.conf, None, banc.base_froide - 60, banc.maintenant + 60, frontiere, sql, None, 5_000, None, &[])
            })
            .map(|_| ())
            .expect_err("contrôle : la lecture froide refuse un réglage illisible");
            let reponse = crate::handlers::query::refus_de_requete(echec, "/api/query", "default");
            let code = reponse.status().as_u16();
            let brut = format!("{:?}", reponse.headers());
            let octets = axum::body::to_bytes(reponse.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
            let corps_h = String::from_utf8_lossy(&octets).into_owned();
            envoyer("horizon", (code, corps_h.clone(), format!("{brut}\n{corps_h}")));
            banc.st.db.lock().execute("DELETE FROM setting WHERE scope='global' AND key='retention_days'", []).expect("fixture : réglage rendu");
            envoyer("rendu", at1_envoi(banc.addr, "/api/query", &banc.authz, &corps).await);
            let fichiers = at1_fichiers_froids(&banc.chemin_base);
            for f in &fichiers {
                let taille = std::fs::metadata(f).expect("fixture : taille du fichier froid").len() as usize;
                std::fs::write(f, vec![0x5a_u8; taille.max(64)]).expect("fixture : fichier froid écrasé");
            }
            envoyer("ecrase", at1_envoi(banc.addr, "/api/query", &banc.authz, &corps).await);
            println!("{AT1_RELEVE}{}", json!({ "fichiers": fichiers.len(), "frontiere": frontiere, "racine": format!("{}.cold", banc.chemin_base) }));
            for r in &rendus {
                println!("{AT1_RENDU}{}", json!([r.0, r.1, r.2, r.3, r.4]));
            }
            println!("{AT1_FIN} {}", rendus.len());
            return;
        }
        let (stdout, stderr) = at1_lancer_l_enfant(
            {
                let mut enfant = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
                enfant.env(AT1_ENFANT_CAUSE, "1");
                enfant
            },
            "tests::at1_couverture_keyset_et_voie_froide::at1_journal_nomme_la_cause_de_la_panne_froide",
        );
        let rendus = at1_lire_les_rendus(&stdout);
        assert!(stdout.contains(&format!("{AT1_FIN} 4")) && rendus.len() == 4, "contrôle : quatre issues rendues : {stdout}\n{stderr}");
        let releve: Value = stdout
            .lines()
            .find_map(|l| l.split_once(AT1_RELEVE))
            .map(|(_, v)| serde_json::from_str(v).expect("contrôle : relevé lisible"))
            .unwrap_or_else(|| panic!("contrôle : relevé : {stdout}"));
        assert!(releve["fichiers"].as_i64().unwrap_or(0) >= 1, "contrôle : au moins un fichier froid écrasé : {releve}");
        assert!(releve["frontiere"].as_i64().unwrap_or(0) > 0, "contrôle : frontière lue sur la page nominale : {releve}");
        let racine = releve["racine"].as_str().expect("contrôle : racine froide relevée").to_string();
        let issue = |nom: &str| rendus.iter().find(|r| r.1 == nom).cloned().unwrap_or_else(|| panic!("contrôle : issue {nom} rendue"));
        for nom in ["nominal", "rendu"] {
            let (_, _, code, corps, _) = issue(nom);
            assert_eq!(code, 200, "contrôle : {nom} servi (la panne vient du seul réglage, puis des seuls fichiers) : {corps}");
            let v: Value = serde_json::from_str(&corps).expect("contrôle : réponse JSON");
            assert_eq!(v["stats"]["cold"]["served_from"], json!("hot+cold"), "contrôle : {nom} lit le tier froid : {corps}");
        }
        let (_, _, code_h, corps_h, brut_h) = issue("horizon");
        let id_h = at1_refus_illisible("horizon", code_h, &corps_h);
        let (_, _, code_e, corps_e, brut_e) = issue("ecrase");
        let id_e = at1_refus_illisible("ecrase", code_e, &corps_e);
        for (nom, brut) in [("horizon", &brut_h), ("ecrase", &brut_e)] {
            assert!(!brut.contains("retention_days") && !brut.contains(racine.as_str()), "{nom} : la réponse ne porte pas la cause : {brut}");
        }
        let journal = at1_journal(&stderr);
        assert_eq!(journal.len(), 2, "une ligne `[query]` par panne :\n{stderr}");
        assert_eq!(
            journal[0],
            format!("[query] WARN requête non servie, erreur du support de la base (/api/query, tenant 'default', {id_h}) : {AT1_NATURE_DE_LA_LECTURE_FROIDE} : {AT1_HORIZON_FROID_NON_LU:?}"),
            "l'horizon non lu se lit au journal, texte exact :\n{stderr}"
        );
        let prefixe_e = format!("[query] WARN requête non servie, erreur du support de la base (/api/query, tenant 'default', {id_e}) : {AT1_NATURE_DE_LA_LECTURE_FROIDE} : \"");
        let cause_e = journal[1].strip_prefix(prefixe_e.as_str()).unwrap_or_else(|| panic!("la ligne du fichier écrasé : attendu « {prefixe_e}… », lu « {} »", journal[1]));
        assert!(cause_e.contains(racine.as_str()), "le fichier écrasé se lit au journal, sous la racine froide {racine} : {}", journal[1]);
        assert!(!cause_e.contains("retention_days"), "les deux causes restent distinctes au journal :\n{stderr}");
    }

    /// (7) LA TRONCATURE IMPOSSIBLE D'UNE PART CHAUDE : le texte réel d'`expect_exact`, rangé comme avant.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn at1_troncature_inattendue_reste_un_refus_du_produit() {
        let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cold_store/planner.rs")).expect("planner.rs lisible");
        assert_eq!(src.matches("answer.expect_exact(\"P4b hot_partial\")?").count(), 1, "contrôle : la seule voie qui appelle `expect_exact` le nomme ainsi");
        let reponse = crate::cold_store::ColdAnswer::Truncated { value: json!({}), rows_hydrated: 3, cap: 2 };
        let texte = reponse.expect_exact("P4b hot_partial").err().expect("contrôle : une réponse tronquée est refusée");
        assert!(texte.starts_with(AT1_OUVERTURE_TRONCATURE_INATTENDUE), "contrôle : le texte du producteur ouvre comme attendu : {texte}");
        assert_eq!(
            en_classant_la_voie_froide(|| Err::<(), String>(texte.clone())),
            Err(EchecDeRequete::Moteur { nature: AT1_NATURE_HORS_DU_COEUR.into(), texte }),
            "la troncature inattendue reste un refus du produit (400), pas une base illisible"
        );
    }

    /// Une fonction scalaire qui rend, au pas, le code passé en argument.
    fn at1_fonction_d_erreur(c: &Connection) {
        c.create_scalar_function("at1_erreur", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, |ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(ctx.get::<i32>(0)?), None))
        })
        .expect("instrument : fonction d'erreur");
    }

    /// (8) LE CLASSEUR DE LA VOIE FROIDE, BRAS PAR BRAS.
    #[test]
    fn at1_classeur_froid_garde_la_note_et_range_le_reste_au_support() {
        let c = Connection::open_in_memory().expect("instrument : connexion en mémoire");
        at1_fonction_d_erreur(&c);
        // Succès : rendu tel quel.
        assert_eq!(en_classant_la_voie_froide(|| Ok::<i64, String>(7)), Ok(7), "succès rendu tel quel");
        // Note du moteur (le SQL de l'appelant refusé) : gardée, comme `en_classant` la rend.
        let moteur = "SELECT at1 FROM at1_absente";
        let froid = en_classant_la_voie_froide(|| crate::query_exec::run_on_conn(&c, ":memory:at1-note", moteur, 600_000, None)).map(|_| ());
        let coeur = en_classant(|| crate::query_exec::run_on_conn(&c, ":memory:at1-note", moteur, 600_000, None)).map(|_| ());
        assert!(
            matches!(&froid, Err(EchecDeRequete::Moteur { nature, .. }) if nature.starts_with("code SQLite ")),
            "le refus du moteur noté reste un refus du moteur, avec son code : {froid:?}"
        );
        assert_eq!(froid, coeur, "la note garde la classe que `en_classant` lui donne");
        // Note du support (E/S au pas) : gardée, avec son code — pas la nature fixe de la lecture froide.
        let support = format!("SELECT at1_erreur({})", rusqlite::ffi::SQLITE_IOERR_READ);
        let froid = en_classant_la_voie_froide(|| crate::query_exec::run_on_conn(&c, ":memory:at1-note", &support, 600_000, None)).map(|_| ());
        assert!(
            matches!(&froid, Err(EchecDeRequete::Support { nature, .. }) if nature.starts_with("code SQLite ")),
            "le support noté garde sa nature : {froid:?}"
        );
        // Une note PÉRIMÉE (laissée par un appel précédent) est effacée avant l'appel : le même texte rendu sans
        // nouvelle note est un échec de la lecture froide.
        let texte_periime = crate::query_exec::run_on_conn(&c, ":memory:at1-note", &support, 600_000, None).expect_err("contrôle : l'appel échoue et note");
        assert_eq!(
            en_classant_la_voie_froide(|| Err::<(), String>(texte_periime.clone())),
            Err(EchecDeRequete::Support { nature: AT1_NATURE_DE_LA_LECTURE_FROIDE.into(), texte: texte_periime }),
            "une note d'un appel précédent ne classe pas l'échec de celui-ci"
        );
        // Un texte étranger APRÈS une note de cet appel : la note ne classe que son texte.
        let froid = en_classant_la_voie_froide(|| {
            let note = crate::query_exec::run_on_conn(&c, ":memory:at1-note", moteur, 600_000, None).expect_err("contrôle : l'appel échoue et note");
            assert_ne!(note, "at1-autre-producteur", "contrôle : deux textes distincts");
            Err::<(), String>("at1-autre-producteur".into())
        });
        assert_eq!(
            froid,
            Err(EchecDeRequete::Support { nature: AT1_NATURE_DE_LA_LECTURE_FROIDE.into(), texte: "at1-autre-producteur".into() }),
            "un texte étranger après une note est un échec de la lecture froide"
        );
        // Les deux ouvertures des refus du produit : rangées comme avant.
        let plafond = format!("{AT1_OUVERTURE_PLAFOND_DE_GROUPES}2 groupes");
        assert_eq!(
            en_classant_la_voie_froide(|| Err::<(), String>(plafond.clone())),
            Err(EchecDeRequete::Moteur { nature: AT1_NATURE_HORS_DU_COEUR.into(), texte: plafond }),
            "le plafond de groupes reste un refus du produit"
        );
        let troncature = format!("{AT1_OUVERTURE_TRONCATURE_INATTENDUE}3 lignes)");
        assert_eq!(
            en_classant_la_voie_froide(|| Err::<(), String>(troncature.clone())),
            Err(EchecDeRequete::Moteur { nature: AT1_NATURE_HORS_DU_COEUR.into(), texte: troncature }),
            "la troncature inattendue reste un refus du produit"
        );
        // Le reste : la lecture froide n'a pas été faite.
        assert_eq!(
            en_classant_la_voie_froide(|| Err::<(), String>("at1 hydratation froide : fichier cold sélectionné invalide".into())),
            Err(EchecDeRequete::Support { nature: AT1_NATURE_DE_LA_LECTURE_FROIDE.into(), texte: "at1 hydratation froide : fichier cold sélectionné invalide".into() }),
            "un échec du tier froid sans note est du support"
        );
    }
}
