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
    /// n'était appelé qu'au bind pour PLUME_DB (server/mod.rs) et après un CRUD — jamais à l'obtention d'une
    /// connexion tenant.
    #[test]
    fn mode1_field_masking_survives_a_process_restart_for_every_tenant() {
        use guatx_core::soql::MaskAction;
        let (st, dir) = mk_mode1_state();
        let key = tenant_generate_key().expect("l'hôte de test fournit de l'entropie");
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

        let key = tenant_generate_key().expect("l'hôte de test fournit de l'entropie");
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
    /// base TENANT. La liste n'est pas écrite ici — elle est DÉRIVÉE du texte du module `server` (tout appel
    /// `X_reload(&conn, &db_path)` EST un registre par db_path) et confrontée au corps de l'unique point
    /// d'hydratation. Un registre ajouté demain au bind fait rougir ce test tant qu'il n'est pas hydraté
    /// pour les tenants — sans que personne n'ait à le déclarer quelque part.
    #[test]
    fn every_per_db_registry_loaded_at_boot_is_loaded_for_a_tenant_base() {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        // Façade ET sous-modules : DÉRIVÉ DU PRÉFIXE DE RÉPERTOIRE depuis `P7.18-a`, jamais d'un nom de
        // fichier — un registre déplacé dans `server/<x>.rs` reste vu.
        let boot = texte_du_module_serveur();
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
            "ANTI-FAUX-VERT : {} registre(s) par db_path trouvé(s) dans le module `server` — le motif cherché ne \
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
        println!("[cliquet] {} registres par db_path dérivés du module `server` : {noms:?}", noms.len());
    }


    // ============================================================================================
    // S4 — LA CLÉ D'UN TENANT NE SE FABRIQUE PAS À PARTIR D'UNE HORLOGE
    //
    // Le défaut : `tenant_generate_key` hachait `now() | pid | adresse de pile | SystemTime::now()`
    // quand `/dev/urandom` ne s'ouvrait pas, avertissait au journal, et rendait la clé. Cette clé
    // chiffre la base ENTIÈRE d'un tenant : qui connaît approximativement la minute de création
    // énumère l'espace restant, et il l'énumère pour toute la durée de rétention de la donnée. Un
    // avertissement se lit une fois ; une clé faible reste faible.
    //
    // Le correctif suit celui déjà fermé sur le chemin d'installation (`os_entropy`, cf. onboarding) :
    // deux sources RÉELLES de l'OS (`/dev/urandom` puis `getrandom(2)`), et RIEN d'autre. Ce que le
    // repli prétendait couvrir — `/dev` non monté — est précisément ce que la seconde source sert.
    // ============================================================================================

    /// (S4-1) MUTATION : source d'entropie INDISPONIBLE -> AUCUNE clé. Et le témoin inverse, sans
    /// lequel on ne mesurerait qu'un chemin mort : sur cet hôte la source réelle rend bien de la
    /// matière, et la clé produite EST cette matière, rien d'autre.
    #[test]
    fn s4_cle_de_tenant_sans_entropie_ne_produit_aucune_cle() {
        assert!(
            tenant_key_from_entropy(None).is_none(),
            "AUCUNE entropie -> AUCUNE clé (fail-closed). Une clé dérivée d'une horloge ou d'un pid est \
             ÉNUMÉRABLE : elle donne l'apparence du chiffrement à une base entière de tenant."
        );
        let plate = tenant_key_from_entropy(Some([0xab; TENANT_KEY_BYTES])).expect("matière fournie -> clé");
        assert_eq!(plate, "ab".repeat(TENANT_KEY_BYTES), "la clé EST la matière fournie, rien d'autre");

        let vraie = tenant_generate_key().expect("l'hôte fournit de l'entropie -> le chemin nominal est vivant");
        assert_eq!(vraie.len(), TENANT_KEY_BYTES * 2, "clé = 256 bits en hex (64 chars)");
        assert!(vraie.chars().all(|c| c.is_ascii_hexdigit()), "clé hex pure : {vraie}");

        // Et l'identifiant de control-plane, qui TIRE de la même fonction, en hérite le fail-closed.
        let pu = gen_control_id("pu_").expect("entropie disponible -> identifiant control-plane");
        assert!(pu.starts_with("pu_") && pu.len() == 3 + 24, "identifiant control-plane : {pu}");
    }

    /// (S4-2) DEUX CLÉS NE PARTAGENT AUCUNE STRUCTURE PRÉVISIBLE — et l'instrument est éprouvé DANS LES
    /// DEUX SENS : le même contrôle, appliqué à un générateur à COMPTEUR (la famille exacte que le repli
    /// retiré représentait : une valeur qui avance d'un cran), DOIT dénoncer. Un contrôle qui ne rend
    /// jamais rien ne prouve rien.
    #[test]
    fn s4_deux_cles_de_tenant_ne_partagent_pas_de_structure_previsible() {
        /// Rend la faute de structure trouvée dans un lot de clés, ou `None`. PUR.
        fn structure_previsible(cles: &[String]) -> Option<String> {
            let distinctes: std::collections::BTreeSet<&String> = cles.iter().collect();
            if distinctes.len() != cles.len() {
                return Some(format!("{} clés pour {} valeurs distinctes (répétition)", cles.len(), distinctes.len()));
            }
            // Préfixe commun : un générateur qui avance (compteur, horodatage) garde une tête figée.
            for i in 0..cles.len() {
                for j in (i + 1)..cles.len() {
                    let commun = cles[i].bytes().zip(cles[j].bytes()).take_while(|(a, b)| a == b).count();
                    if commun >= 8 {
                        return Some(format!("deux clés partagent {commun} caractères de tête"));
                    }
                }
            }
            // Diversité des octets : 2048 octets tirés uniformément couvrent ~256 valeurs distinctes ;
            // un lot structuré (compteur, horodatage) en couvre une poignée.
            let mut vus = [false; 256];
            for c in cles {
                for o in c.as_bytes() {
                    vus[*o as usize] = true;
                }
            }
            let n = vus.iter().filter(|v| **v).count();
            if n < 16 {
                return Some(format!("seulement {n} valeurs d'octet distinctes sur tout le lot"));
            }
            None
        }

        let lot: Vec<String> = (0..64)
            .map(|_| tenant_generate_key().expect("l'hôte fournit de l'entropie"))
            .collect();
        assert_eq!(structure_previsible(&lot), None, "64 clés tirées du CSPRNG de l'OS : aucune structure");

        // TÉMOIN POSITIF DE L'INSTRUMENT : un générateur à compteur, formaté EXACTEMENT comme une vraie
        // clé (64 hex). Le contrôle doit le refuser — sinon il ne mesure rien.
        let compteur: Vec<String> = (0..64u64).map(|n| format!("{n:064x}")).collect();
        assert!(
            structure_previsible(&compteur).is_some(),
            "le contrôle de structure DOIT dénoncer un générateur à compteur, sinon il est aveugle"
        );
    }

    /// Les fonctions de PRODUCTION qui puisent à une source d'entropie de l'OS **et** rendent de la
    /// MATIÈRE (String / [u8; N] / Vec<u8> / clé de signature). Partition FERMÉE PAR CONSTRUCTION : un
    /// producteur écrit demain y entre sans être inscrit nulle part. Le corps va de la signature à
    /// l'accolade fermante de MÊME indentation (les fonctions de méthode sont donc couvertes aussi).
    fn s4_producteurs_de_matiere() -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for (chemin, txt) in onb_sources_production() {
            for (n, ligne) in txt.lines().enumerate() {
                let nu = ligne.trim_start();
                if !(nu.starts_with("fn ")
                    || nu.starts_with("pub fn ")
                    || nu.starts_with("async fn ")
                    || nu.starts_with("pub async fn ")
                    || nu.starts_with("pub(crate) fn ")
                    || nu.starts_with("pub(crate) async fn "))
                {
                    continue;
                }
                let nom = nu.split("fn ").nth(1).unwrap_or("").split(['(', '<']).next().unwrap_or("").to_string();
                let indent = ligne.len() - nu.len();
                let deb = txt.lines().take(n).map(|l| l.len() + 1).sum::<usize>();
                let reste = &txt[deb..];
                let fermeture = format!("\n{}}}", " ".repeat(indent));
                let fin = reste.find(&fermeture).map(|i| i + fermeture.len()).unwrap_or(reste.len());
                let corps = &reste[..fin];
                // Type de retour : `main`/`run` n'en ont pas -> hors partition, comme il se doit.
                let entete = &corps[..corps.find('{').unwrap_or(corps.len())];
                let Some((_, retour)) = entete.split_once("->") else { continue };
                if !(retour.contains("String") || retour.contains("[u8") || retour.contains("Vec<u8>") || retour.contains("SigningKey")) {
                    continue;
                }
                // Le CODE seul : un commentaire ne puise ni ne dérive rien, et on veut pouvoir décrire
                // le défaut retiré à l'endroit où il vivait sans que la garde y voie une rechute.
                let code: String = corps.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
                if !(code.contains("/dev/urandom") || code.contains("os_entropy") || code.contains("OsRng")) {
                    continue;
                }
                out.push((chemin.clone(), nom, code));
            }
        }
        out
    }

    /// Ce qu'un corps dérive d'une horloge, d'un pid ou d'un compteur d'exécution. PUR.
    fn s4_derivations_d_horloge(code: &str) -> Vec<&'static str> {
        ["process::id()", "SystemTime", "now()", "elapsed()"].into_iter().filter(|m| code.contains(m)).collect()
    }

    /// (S4-3) GARDE DÉRIVÉE — AUCUN PRODUCTEUR DE MATIÈRE NE RETOMBE SUR L'HORLOGE. Trois correctifs
    /// ponctuels se re-cassent un par un : ce qu'on interdit ici est la FIGURE, sur une partition
    /// dérivée d'une PROPRIÉTÉ (puiser à l'entropie de l'OS et rendre de la matière), jamais d'une liste
    /// de noms. MESURÉ sur 91c9a39 : la partition comptait 11 fonctions, dont DEUX dérivaient d'une
    /// horloge — `tenant_generate_key` (clé SQLCipher d'un tenant) et `engagement_new_id` (identifiant
    /// d'engagement, `eng_{horodatage}`, qui pouvait de surcroît collisionner sur sa clé primaire).
    #[test]
    fn s4_aucun_producteur_de_matiere_ne_derive_d_une_horloge() {
        let partition = s4_producteurs_de_matiere();
        assert!(
            partition.len() >= 8,
            "partition des producteurs de matière : {} fonction(s) — un balayage qui ne trouve presque \
             rien ne prouve rien ({:?})",
            partition.len(),
            partition.iter().map(|(_, n, _)| n.as_str()).collect::<Vec<_>>()
        );
        // Le balayage VOIT bien les producteurs connus (sinon il mesurerait un périmètre vide).
        let noms: Vec<&str> = partition.iter().map(|(_, n, _)| n.as_str()).collect();
        for attendu in ["os_entropy", "tenant_generate_key", "token_rand_hex", "gen_snapshot_token", "engagement_new_id"] {
            assert!(noms.contains(&attendu), "`{attendu}` doit être DANS la partition balayée ; vus : {noms:?}");
        }

        let fautes: Vec<String> = partition
            .iter()
            .filter_map(|(chemin, nom, code)| {
                let d = s4_derivations_d_horloge(code);
                (!d.is_empty()).then(|| format!("{chemin}::{nom} dérive de {d:?}"))
            })
            .collect();
        assert!(
            fautes.is_empty(),
            "MATIÈRE FABRIQUÉE DEPUIS UNE HORLOGE OU UN PID : {fautes:#?}. La bonne réponse à une source \
             d'entropie indisponible est de REFUSER : `os_entropy` offre déjà les DEUX sources réelles de \
             l'OS (/dev/urandom, puis getrandom(2) sans descripteur — le cas `/dev` non monté), et il n'y \
             a pas de troisième voie."
        );

        // LE CÂBLAGE, sans quoi (S4-1) ne mesurerait qu'un cœur pur DÉBRANCHÉ : la fonction réelle
        // compose le producteur unique et le cœur pur, et n'a aucune autre voie vers une clé.
        let (_, _, corps_cle) = partition
            .iter()
            .find(|(_, n, _)| n == "tenant_generate_key")
            .expect("`tenant_generate_key` est dans la partition");
        for attendu in ["os_entropy", "tenant_key_from_entropy"] {
            assert!(
                corps_cle.contains(attendu),
                "`tenant_generate_key` doit composer `{attendu}` — sinon la clé peut naître ailleurs que \
                 du CSPRNG de l'OS ; corps mesuré : {corps_cle}"
            );
        }

        // TÉMOIN POSITIF DE L'INSTRUMENT : le corps exact qui vivait dans `tenant_generate_key` DOIT être
        // dénoncé par le même prédicat. Un détecteur qui ne se déclenche jamais est indiscernable d'un
        // détecteur cassé.
        let retire = "let seed = format!(\"{}|{}\", now(), std::process::id()); Sha256::digest(seed)";
        assert!(
            !s4_derivations_d_horloge(retire).is_empty(),
            "le prédicat DOIT dénoncer la graine horloge+pid retirée, sinon la garde est aveugle"
        );
        assert!(
            s4_derivations_d_horloge("tenant_key_from_entropy(os_entropy::<32>())").is_empty(),
            "et il ne doit PAS dénoncer le chemin nominal, sinon il est du bruit"
        );
    }
