    // ============================================================================================
    // FONDATION MULTI-TENANT #2a-1 — TEST D'ISOLATION : deux db_path distincts NE PARTAGENT PAS l'état
    // process-global re-clé (R1 READ_POOL, R4 PARSERS). Preuve directe que la re-clé
    // par db_path borne l'état au-dessus du handle DB. En mono-tenant (un seul db_path) tout ce code
    // n'a qu'UNE clé -> comportement STRICTEMENT identique ; ici on exerce 2 clés pour prouver la garde.
    // ============================================================================================
    #[test]
    fn mt_isolation_read_pool_and_caches_keyed_by_db_path() {
        let a = mk_tmp_path("mt-a.db");
        let b = mk_tmp_path("mt-b.db");
        // deux bases RÉELLES avec un marqueur distinct -> prouve QUELLE base a servi la connexion.
        for (p, tag) in [(&a, "AAA"), (&b, "BBB")] {
            let c = Connection::open(p).unwrap();
            c.execute_batch(&format!("CREATE TABLE marker(v TEXT); INSERT INTO marker VALUES('{tag}');")).unwrap();
        }

        // ---- R1 READ_POOL ---- : une connexion rendue sous A ne doit JAMAIS être servie pour B
        // (bug LATENT avant re-clé : l'ancien Vec global rendait n'importe quelle connexion pour n'importe
        // quelle base). On remplit le pool de A puis un get(B) DOIT servir une connexion ouverte sur B.
        let ca = read_conn_get(&a).expect("open A");
        read_conn_put(&a, ca); // READ_POOL.by_path[A] = [conn ouverte sur A]
        let cb = read_conn_get(&b).expect("open B");
        let vb: String = cb.query_row("SELECT v FROM marker", [], |r| r.get(0)).unwrap();
        assert_eq!(vb, "BBB", "R1 : get(B) ne doit JAMAIS servir une connexion ouverte sur A");
        read_conn_put(&b, cb);
        let ca2 = read_conn_get(&a).expect("reopen A");
        let va: String = ca2.query_row("SELECT v FROM marker", [], |r| r.get(0)).unwrap();
        assert_eq!(va, "AAA", "R1 : le pool de A ne sert que des connexions ouvertes sur A");
        read_conn_put(&a, ca2);

        // ---- R4 PARSERS ---- : un registre chargé sous A ne s'applique pas à une ingestion sous B.
        {
            { let mut w = parsers_cell().write();
                let re = regex::Regex::new(r"tok=(?P<iso>\w+)").unwrap();
                w.insert(a.as_str().to_string(), vec![("*".to_string(), re)]);
            }
            let fa = parsers_apply(&a, "src", "tok=HELLO", None);
            let fb = parsers_apply(&b, "src", "tok=HELLO", None);
            assert!(fa.as_deref().map_or(false, |s| s.contains("HELLO")),
                    "R4 : les parseurs de A enrichissent une ingestion sous A");
            assert!(fb.is_none(),
                    "R4 : les parseurs de A ne s'appliquent JAMAIS à une ingestion sous B");
            { let mut w = parsers_cell().write(); w.remove(a.as_str()); }
        }

        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    // ============================================================================================
    // DEUX FAIL-OPEN MODE 1, MESURÉS AVANT D'ÊTRE FERMÉS (audit) :
    //   (1) les registres PAR db_path (dont le MASQUAGE/DLP #45) n'étaient peuplés qu'au boot, pour
    //       PLUME_DB. Après un redémarrage, tout tenant AUTRE que celui de PLUME_DB tournait donc avec
    //       un ensemble de masquage VIDE -> les champs marqués DENY/masqué par l'exploitant redevenaient
    //       lisibles, y compris en SQL brut (l'authorizer consulte le MÊME registre).
    //   (2) `req_db_path` retombait sur la base DU PROCESSUS quand le tenant n'était pas servable, alors
    //       que son homologue en écriture rendait une base CUL-DE-SAC -> une LECTURE d'un tenant
    //       indisponible servait les lignes d'un AUTRE tenant.
    // Les deux mesures passent par les MÊMES fonctions qu'une requête (`req_db_path`/`req_db`, puis le
    // pool read-only) : jamais par une relecture du code.
    // ============================================================================================

    /// Ce qu'un NOUVEAU PROCESSUS a en mémoire pour un db_path : RIEN. On oublie l'état par-db_path
    /// (registre de masquage/DENY/sel) et le writer mémoïsé, sans lancer un second processus. NB : les
    /// connexions du pool read-only ne sont PAS évincées — inutile, leur authorizer consulte le registre
    /// DYNAMIQUEMENT ; les garder est la mesure la plus CONSERVATRICE (elle ne peut pas fabriquer un déni).
    fn forget_tenant_process_state(st: &AppState, tenant: &str, db_path: &str) {
        st.tenants.writers.lock().remove(tenant);
        field_filters_forget(db_path);
    }

    /// (1) LE MASQUAGE/DLP D'UN TENANT SURVIT À UN REDÉMARRAGE — mesuré sur le comportement.
    ///
    /// Mesure AVANT correctif (base tenant réelle, 2 règles posées par l'exploitant, redémarrage simulé) :
    /// `effective_masks` rendait un jeu VIDE et `SELECT src_ip FROM event` rendait la valeur EN CLAIR
    /// (`203.0.113.7`) alors que la règle DENY existait dans la base du tenant. Cause : `field_filters_reload`
    /// n'était appelé qu'au bind pour PLUME_DB (server.rs) et après un CRUD — jamais à l'obtention d'une
    /// connexion tenant.
    #[test]
    fn mode1_field_masking_survives_a_process_restart_for_every_tenant() {
        use guatx_core::soql::MaskAction;
        let (st, dir) = mk_mode1_state();
        let key = tenant_generate_key();
        let tpath = format!("{dir}/tenant-mask.db");
        tenant_provision(&st.tenants, "t", "T", &tpath, &format!("literal:{key}")).expect("provision t");

        // L'EXPLOITANT pose ses règles DANS LA BASE DU TENANT : DENY sur une colonne RÉELLE (src_ip ->
        // authorizer, tous rôles admin compris) et MASK sur une clé du sac JSON (pan, seuil admin).
        {
            let h = st.tenants.handle_for("t").expect("writer du tenant");
            let c = h.lock();
            c.execute("INSERT INTO field_filter(name,field,action,role) VALUES('deny-srcip','src_ip','deny','')", []).unwrap();
            c.execute("INSERT INTO field_filter(name,field,action,role) VALUES('mask-pan','pan','mask','admin')", []).unwrap();
            c.execute(
                "INSERT INTO event(ts,source,message,src_ip) VALUES(?1,'s','ligne du tenant','203.0.113.7')",
                params![now()],
            )
            .unwrap();
        }

        // REDÉMARRAGE : plus rien en mémoire pour cette base (état d'un processus neuf).
        forget_tenant_process_state(&st, "t", &tpath);
        assert!(
            effective_masks(&tpath, "admin", "t", None).is_empty(),
            "précondition : après redémarrage le registre de CE db_path est vide"
        );

        // CE QUE FAIT UNE REQUÊTE : router (req_db_path) puis lire par le pool read-only.
        let au = au_tadmin("alice", "t");
        let p = req_db_path(&st, &au);
        assert_eq!(p, tpath, "la requête est routée vers la base DU tenant");

        // (a) LA DONNÉE, D'ABORD : la colonne DENY n'est plus lisible, même admin, même en SQL brut
        // (l'authorizer est alimenté par le MÊME registre par-db_path).
        let brut = run_query(&p, "SELECT src_ip FROM event");
        assert!(
            brut.is_err(),
            "DENY src_ip : lecture REFUSÉE attendue, obtenu {:?}",
            brut.as_ref().map(|v| v["rows"].clone())
        );

        // (b) et le jeu de masques EFFECTIF de l'appelant porte les 2 règles — sans aucun CRUD préalable.
        let masks = effective_masks(&p, "admin", "t", None);
        assert_eq!(
            masks.get("src_ip"),
            Some(MaskAction::Deny),
            "DENY src_ip du tenant PERDU après redémarrage (jeu de masques rendu : {} champ(s))",
            masks.field_names().count()
        );
        assert_eq!(masks.get("pan"), Some(MaskAction::Mask), "MASK pan du tenant PERDU après redémarrage");
        // contrôle négatif : la garde ne rend pas la base illisible (une colonne non déniée reste servie).
        let ok = run_query(&p, "SELECT message FROM event WHERE source='s'").expect("colonne non déniée : lisible");
        assert_eq!(ok["rows"][0][0].as_str(), Some("ligne du tenant"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (2) UN TENANT INDISPONIBLE N'EST JAMAIS SERVI DEPUIS LA BASE D'UN AUTRE — lecture ET écriture.
    ///
    /// Mesure AVANT correctif : tenant `s` provisionné, writer CHAUD (cas d'exploitation), puis suspendu.
    /// `req_db_path` rendait le chemin de la base OPÉRATEUR et la lecture servait SES lignes (1 ligne
    /// `SECRET-OPERATEUR`) ; `req_db` rendait le writer CHAUD du tenant suspendu (cache-hit sans re-contrôle)
    /// et l'INSERT réussissait. Le guard d'auth (auth.rs) refuse déjà un tenant suspendu à l'entrée de la
    /// requête : ce test mesure la fonction de ROUTAGE elle-même (suspension en cours de requête, appelant
    /// futur, job hors requête) — la garde ne doit pas dépendre d'un appelant qui pense à vérifier.
    #[test]
    fn mode1_a_suspended_tenant_is_never_served_from_another_tenants_database() {
        let (st, dir) = mk_mode1_state();
        // Base OPÉRATEUR RÉELLE (celle du processus = tenant `default`), avec un marqueur qui n'appartient
        // qu'à elle -> une fuite se MESURE en lignes servies, pas en relecture de code.
        {
            let c = PreparedDb::open_keyed(st.db_path.as_str(), None).expect("base opérateur");
            c.execute("INSERT INTO event(ts,source,message) VALUES(?1,'op','SECRET-OPERATEUR')", params![now()]).unwrap();
        }
        register_db_key(st.db_path.as_str(), None); // ce que catalog_route fait pour le tenant `default`

        let key = tenant_generate_key();
        let tpath = format!("{dir}/tenant-susp.db");
        tenant_provision(&st.tenants, "s", "S", &tpath, &format!("literal:{key}")).expect("provision s");
        let au = au_tadmin("bob", "s");
        assert_eq!(req_db_path(&st, &au), tpath, "précondition : tenant ACTIF -> routé vers SA base");
        {
            let h = st.tenants.handle_for("s").expect("writer du tenant");
            h.lock()
                .execute("INSERT INTO event(ts,source,message) VALUES(?1,'s','SECRET-DU-TENANT')", params![now()])
                .unwrap();
        }

        // SUSPENSION, writer CHAUD (l'exploitant suspend un tenant qui vient de servir).
        {
            let c = st.tenants.control.as_ref().unwrap().conn.lock();
            c.execute("UPDATE tenant SET suspended=1 WHERE id='s'", []).unwrap();
        }

        // LECTURE : le chemin rendu ne doit désigner NI la base opérateur, NI aucune base servable.
        let p = req_db_path(&st, &au);
        let fuite = run_query(&p, "SELECT COUNT(*) FROM event WHERE message='SECRET-OPERATEUR'")
            .map(|v| v["rows"][0][0].as_i64().unwrap_or(-2))
            .unwrap_or(-1);
        assert_eq!(
            fuite, -1,
            "lecture d'un tenant SUSPENDU : {fuite} ligne(s) de la base OPÉRATEUR servie(s) (chemin rendu : {p})"
        );
        assert_ne!(p, *st.db_path, "le repli d'un tenant indisponible n'est JAMAIS la base d'un autre tenant");

        // ÉCRITURE : même invariant, dérivé du même refus (et non d'un appelant vigilant).
        let avant_tenant: i64 = {
            let c = open_db_keyed(&tpath, Some(&key)).unwrap();
            c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap()
        };
        let h = req_db(&st, &au);
        let ecrit = h.lock().execute("INSERT INTO event(ts,source,message) VALUES(2,'x','APRES-SUSPENSION')", []);
        assert!(ecrit.is_err(), "écriture sur un tenant SUSPENDU : REFUS attendu, obtenu {ecrit:?}");
        let apres_tenant: i64 = {
            let c = open_db_keyed(&tpath, Some(&key)).unwrap();
            c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(avant_tenant, apres_tenant, "aucune ligne écrite dans la base d'un tenant suspendu");
        let chez_operateur: i64 = {
            let c = open_db_keyed(st.db_path.as_str(), None).unwrap();
            c.query_row("SELECT COUNT(*) FROM event WHERE message='APRES-SUSPENSION'", [], |r| r.get(0)).unwrap()
        };
        assert_eq!(chez_operateur, 0, "aucune ligne n'a atterri dans la base d'un AUTRE tenant");

        // RÉACTIVATION : la garde n'est pas un aller simple (le tenant redevient servable, mêmes chemins).
        {
            let c = st.tenants.control.as_ref().unwrap().conn.lock();
            c.execute("UPDATE tenant SET suspended=0 WHERE id='s'", []).unwrap();
        }
        assert_eq!(req_db_path(&st, &au), tpath, "réactivé -> routé de nouveau vers SA base");
        assert!(
            req_db(&st, &au).lock().execute("INSERT INTO event(ts,source,message) VALUES(3,'s','REACTIVE')", []).is_ok(),
            "réactivé -> écriture de nouveau acceptée"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// LE CUL-DE-SAC DE LECTURE NE PEUT DÉSIGNER AUCUNE BASE — la propriété est vérifiée, pas supposée :
    /// `/dev/null` existe mais n'est pas un répertoire, donc toute ouverture SOUS lui échoue (ENOTDIR) en
    /// lecture ET en écriture, et le répertoire manquant n'est pas créable. C'est ce qui autorise
    /// `req_db_path` à rendre une `String` sans jamais désigner la base d'un autre tenant.
    #[test]
    fn the_dead_end_path_can_never_designate_a_real_database() {
        let p = UNAVAILABLE_TENANT_DB_PATH;
        assert!(!std::path::Path::new(p).exists(), "le cul-de-sac n'existe pas");
        assert!(std::fs::create_dir_all(std::path::Path::new(p).parent().unwrap()).is_err(),
                "son répertoire parent n'est PAS créable (sinon le chemin pourrait devenir une vraie base)");
        assert!(read_conn_get(p).is_err(), "lecture par le pool : impossible");
        assert!(Connection::open(p).is_err(), "écriture : impossible (aucun fichier ne peut y naître)");
        assert!(std::fs::File::create(p).is_err(), "et rien ne peut créer ce fichier hors SQLite non plus");
    }

    /// MODE 0 INCHANGÉ : le routage ne touche NI le catalogue, NI un writer tenant, NI aucun registre —
    /// il rend la base du processus, quel que soit le tenant porté par l'appelant (il n'y en a qu'un).
    #[test]
    fn mode0_tenant_routing_and_registries_are_unchanged() {
        let st = tenant_test_state("a", "e", "s", None); // control=None -> mode 0
        assert!(!st.multi_tenant, "précondition : mode 0");
        for tenant in ["default", "peu-importe"] {
            let au = au_tadmin("u", tenant);
            assert_eq!(req_db_path(&st, &au), *st.db_path, "mode 0 : req_db_path = la base du processus");
            assert!(Arc::ptr_eq(&req_db(&st, &au), &st.db), "mode 0 : req_db = le writer du processus");
        }
        assert!(st.tenants.writers.lock().is_empty(), "mode 0 : AUCUN writer tenant n'est ouvert");
    }

    /// LE CLIQUET : tout registre PAR db_path que le bind charge pour PLUME_DB doit être chargé pour une
    /// base TENANT. La liste n'est pas écrite ici — elle est DÉRIVÉE du texte de `server.rs` (tout appel
    /// `X_reload(&conn, &db_path)` EST un registre par db_path) et confrontée au corps de l'unique point
    /// d'hydratation. Un registre ajouté demain au bind fait rougir ce test tant qu'il n'est pas hydraté
    /// pour les tenants — sans que personne n'ait à le déclarer quelque part.
    #[test]
    fn every_per_db_registry_loaded_at_boot_is_loaded_for_a_tenant_base() {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let boot = std::fs::read_to_string(src.join("server.rs")).expect("lecture de server.rs");
        let mut noms: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for l in boot.lines() {
            let compact: String = l.chars().filter(|c| !c.is_whitespace()).collect();
            let Some(i) = compact.find("_reload(&conn,&db_path)") else { continue };
            let debut = compact[..i]
                .rfind(|c: char| !c.is_alphanumeric() && c != '_')
                .map_or(0, |j| j + 1);
            noms.insert(format!("{}_reload", &compact[debut..i]));
        }
        assert!(
            noms.len() >= 5,
            "ANTI-FAUX-VERT : {} registre(s) par db_path trouvé(s) dans server.rs — le motif cherché ne \
             correspond plus au code, ce test ne prouve donc plus rien ({noms:?})",
            noms.len()
        );
        let etat = std::fs::read_to_string(src.join("state.rs")).expect("lecture de state.rs");
        let i = etat.find("fn per_db_registries_reload").expect("le point d'hydratation existe");
        let corps = &etat[i..];
        let fin = corps.find("\n}\n").expect("corps de per_db_registries_reload délimité");
        let corps = &corps[..fin];
        for n in &noms {
            assert!(
                corps.contains(&format!("{n}(")),
                "`{n}` est chargé au bind pour PLUME_DB mais PAS par `per_db_registries_reload` -> une base \
                 TENANT tournerait avec ce registre VIDE (c'est exactement le défaut #45 mesuré). \
                 Registres vus au bind : {noms:?}"
            );
        }
        println!("[cliquet] {} registres par db_path dérivés de server.rs : {noms:?}", noms.len());
    }

