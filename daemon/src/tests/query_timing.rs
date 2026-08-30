// LA MÉTRIQUE D'ATTENTE — gardes DÉRIVÉES de la sémantique d'un sémaphore, sans aucun seuil.
//
// LE DÉFAUT QU'ELLES FERMENT. `stats.sem_wait_ms` publiait le temps écoulé entre l'ENTRÉE du
// handler et l'obtention du permit. Mesuré sur la campagne de concurrence (2026-08-01, base de banc
// d'environ 1,44 M d'événements) : jusqu'à 10,2 s à des niveaux où AUCUNE file n'était possible, et
// 16,5 s en passe SOLO — un seul client, des permis libres. Structurellement impossible pour une
// attente de sémaphore ; le champ mesurait donc autre chose, et son nom envoyait l'exploitant
// AUGMENTER le sémaphore, c'est-à-dire vers la seule action que la même campagne mesure comme
// nuisible (débit ×0,46, p95 27 s -> 50 s, RSS +725 Mio, daemon TUÉ à 10 analystes).
//
// LA PROPRIÉTÉ, ET POURQUOI ELLE N'A PAS DE SEUIL : tant qu'il y a au moins autant de permis que de
// clients simultanés, aucune requête ne PEUT attendre son tour. L'attente doit donc être NULLE —
// pas « petite », pas « sous un seuil » : nulle. C'est vrai pour toujours, pour toute taille de
// sémaphore, et ça suffit à réfuter n'importe quelle valeur contaminée.

    use tokio::sync::Semaphore;

    /// (a) LA GARDE DÉRIVÉE — S permis, N <= S clients simultanés, attente EXACTEMENT nulle.
    ///
    /// Aucun seuil, aucune tolérance : la boucle balaie tous les (S, N) avec N <= S et exige `0.0`.
    /// Chaque client fait du TRAVAIL avant de demander son permit (c'est ce que fait le vrai
    /// handler : masques, couverture des rollups, compilation) — c'est ce travail que l'ancienne
    /// implémentation comptait comme de l'attente de sémaphore. Ce test l'aurait donc attrapé au
    /// premier passage : il aurait publié ~la durée du travail au lieu de zéro.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_permit_wait_while_permits_outnumber_clients() {
        for permits in 1..=4usize {
            for clients in 1..=permits {
                let sem = Arc::new(Semaphore::new(permits));
                let mut hs = Vec::new();
                for _ in 0..clients {
                    let s = sem.clone();
                    hs.push(tokio::spawn(async move {
                        let clock = QueryClock::start();
                        // TRAVAIL AVANT LE PERMIT — la contamination que le défaut mesurait.
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        let (_p, t) = clock.permit(&s).await.unwrap();
                        // On garde le permit un instant : sans ça, les clients ne se recouvrent pas
                        // et le test ne mettrait pas le sémaphore en situation.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        t.sem_wait_ms()
                    }));
                }
                for h in hs {
                    let w = h.await.unwrap();
                    assert_eq!(
                        w, 0.0,
                        "{permits} permis pour {clients} client(s) simultané(s) : aucune requête ne PEUT \
                         attendre son tour, et pourtant sem_wait_ms = {w} ms. Une attente non nulle ici \
                         n'est pas de l'attente de sémaphore — c'est du travail fait AVANT le permit et \
                         compté comme de la file (le défaut du 2026-08-01 : 16,5 s publiées en solo)."
                    );
                }
            }
        }
    }

    /// (b) LA GARDE MORD DANS L'AUTRE SENS — quand la file EXISTE, l'attente est VUE.
    ///
    /// Sans ce test, (a) serait satisfait par un champ constamment nul, c'est-à-dire par une
    /// métrique morte : le pire remède au mensonge précédent. N+1 clients pour N permis, chacun
    /// tenant son permit un moment -> au moins un client DOIT avoir attendu.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_real_queue_is_measured() {
        let sem = Arc::new(Semaphore::new(2));
        let mut hs = Vec::new();
        for _ in 0..3 {
            let s = sem.clone();
            hs.push(tokio::spawn(async move {
                let clock = QueryClock::start();
                let (p, t) = clock.permit(&s).await.unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
                drop(p);
                t.sem_wait_ms()
            }));
        }
        let mut waits = Vec::new();
        for h in hs {
            waits.push(h.await.unwrap());
        }
        assert!(
            waits.iter().any(|&w| w > 0.0),
            "3 clients pour 2 permis : le troisième a forcément fait la queue, et aucune attente \
             n'a été publiée ({waits:?}). Une métrique toujours nulle ne ment pas moins qu'une \
             métrique toujours pleine — elle est juste plus difficile à réfuter."
        );
    }

    /// (c) LE DÉCOUPAGE EST TOTAL — `prepare + sem_wait + exec == server`, par construction.
    ///
    /// Si l'identité ne tenait pas, un temps serait passé quelque part sans qu'aucun champ ne le
    /// porte : exactement la condition qui a permis à l'attente de verrou de se cacher dans
    /// `sem_wait_ms`. Le test lit les champs PUBLIÉS (pas les accesseurs), donc il vaut pour le
    /// JSON que reçoit l'exploitant.
    #[tokio::test]
    async fn the_split_accounts_for_every_millisecond() {
        let sem = Arc::new(Semaphore::new(1));
        let clock = QueryClock::start();
        tokio::time::sleep(Duration::from_millis(25)).await;
        let (_p, t) = clock.permit(&sem).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
        let mut v = json!({});
        t.stamp(&mut v);
        let f = |k: &str| v["stats"][k].as_f64().unwrap_or_else(|| panic!("{k} absent de stats"));
        let (server, prepare, sem_wait, exec) = (f("server_ms"), f("prepare_ms"), f("sem_wait_ms"), f("exec_ms"));
        assert!(
            (prepare + sem_wait + exec - server).abs() <= 0.01,
            "le découpage ne rend pas compte du temps total : prepare={prepare} + sem_wait={sem_wait} \
             + exec={exec} != server={server}. Un temps non attribué est un temps qui finira attribué \
             au mauvais champ."
        );
        assert!(prepare >= 25.0, "la préparation (25 ms de travail avant le permit) est tombée à {prepare} ms");
        assert_eq!(sem_wait, 0.0, "un permit libre ne fait pas attendre (sem_wait={sem_wait})");
        assert!(v["stats"]["db_lock_wait_ms"].is_number(), "db_lock_wait_ms doit être publié même à zéro : une absence se lit « champ inconnu », pas « aucune attente »");
    }

    /// (d) LE VERROU PARTAGÉ EST VU, ET IL N'EST PAS CONFONDU AVEC LE SÉMAPHORE.
    ///
    /// C'est LA distinction que l'exploitant doit pouvoir faire : « ça attend le permit » (augmenter
    /// le sémaphore peut aider) contre « ça attend le verrou de la connexion partagée » (augmenter
    /// le sémaphore n'y changera rien, et mettra plus de monde sur le verrou). Un tiers tient le
    /// verrou 40 ms ; le chemin de requête doit publier cette attente en `db_lock_wait_ms` ET
    /// laisser `sem_wait_ms` à zéro.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_lock_wait_is_published_apart_from_the_semaphore() {
        let sem = Arc::new(Semaphore::new(8));
        let m: Arc<Mutex<Connection>> = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let held = m.clone();
        // Le TIERS : la boucle de rollups du vrai daemon (`server/boucles_de_fond.rs`) tient ce même
        // verrou pendant tout un tick, toutes les 120 s.
        // LA REMISE DU VERROU EST DÉTERMINISTE, PLUS UNE COURSE — corrigé le 2026-08-31 après un
        // ÉCHEC DU PORTILLON DE DÉPLOIEMENT que ce poste ne reproduisait pas. La forme d'origine
        // faisait dormir le fil principal 5 ms « pour laisser le tiers prendre le verrou » : sur une
        // machine chargée, le tiers n'est pas ordonnancé dans cette fenêtre, le fil principal prend
        // le verrou EN PREMIER, n'attend rien, et l'assertion tombe. Le témoin mesurait donc
        // l'ORDONNANCEUR autant que le code. Le tiers SIGNALE désormais qu'il détient le verrou, et
        // le fil principal ne tente sa prise qu'après ce signal : la propriété tenue est la même,
        // mais sa violation vient du code et non de la charge de la machine.
        let (prevenu, attendre_le_tiers) = std::sync::mpsc::channel::<()>();
        let squatter = std::thread::spawn(move || {
            let _g = held.lock();
            prevenu.send(()).expect("le fil principal attend ce signal");
            std::thread::sleep(Duration::from_millis(40));
        });
        attendre_le_tiers
            .recv_timeout(Duration::from_secs(10))
            .expect("INSTRUMENT : le tiers n'a jamais annoncé tenir le verrou — le témoin ne mesurerait rien");
        let clock = QueryClock::start();
        {
            let _c = clock.db().lock(&m); // attend le tiers
        }
        let (_p, t) = clock.permit(&sem).await.unwrap();
        squatter.join().unwrap();
        assert!(
            t.db_lock_wait_ms() >= 20.0,
            "l'attente du verrou PARTAGÉ (un tiers le tenait 40 ms) n'est pas publiée : \
             db_lock_wait_ms={}. C'est le point de sérialisation qui, avant ce module, se \
             retrouvait dans sem_wait_ms et faisait accuser le sémaphore.",
            t.db_lock_wait_ms()
        );
        assert_eq!(
            t.sem_wait_ms(),
            0.0,
            "le sémaphore avait 8 permis libres : l'attente du VERROU ne doit JAMAIS être publiée \
             comme une attente de PERMIT — c'est précisément la confusion qui envoie l'exploitant \
             augmenter le sémaphore, la seule action mesurée comme nuisible."
        );
    }

    /// (d bis) LA COUVERTURE NE DÉPEND PAS DE LA CONNEXION QUI LA LIT.
    ///
    /// C'est la condition — et la SEULE — qui autorise à sortir cette lecture du verrou d'écriture
    /// partagé. Le gain mesuré était énorme (jusqu'à 3,4 s en solo sur le chemin de CHAQUE requête
    /// GXQL — atteints par une requête qui s'EXÉCUTE en 14 ms), mais la couverture des rollups
    /// vient d'être corrigée précisément parce qu'une couverture SUPPOSÉE servait des nombres faux :
    /// on ne l'échange contre aucune milliseconde. Le test l'établit au lieu de l'affirmer — il lit
    /// la MÊME base par les DEUX chemins et exige la MÊME couverture, y compris par le pool de
    /// lecture RÉEL (`read_with`), donc à travers l'authorizer qu'il installe. Si celui-ci refusait
    /// `meta`, la couverture retomberait silencieusement sur `unproven` : la route déclinerait pour
    /// toujours, la réponse resterait JUSTE mais le rollup serait mort sans que rien ne le dise.
    #[test]
    fn rollup_coverage_is_the_same_read_from_the_pool_as_from_the_writer() {
        // Le pool applique la clé SQLCipher de l'environnement (`apply_key`) : sur une base EN CLAIR
        // comme celle-ci, un `PLUME_DB_KEY` posé dans l'env ferait échouer l'ouverture et le test
        // accuserait l'authorizer d'un défaut qui n'est pas le sien. Même garde que `sec.rs`.
        if !std::env::var("PLUME_DB_KEY").map(|v| v.is_empty()).unwrap_or(true) {
            return;
        }
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("cov-pool");
        let path = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let p = path.to_string_lossy().to_string();
        let (below, at_id) = (1_785_000_000i64, 4242i64);
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&w);
            // La couverture telle que le JOB la publie (les deux faits, ensemble).
            for (k, v) in [(META_ROLLUP_WM, below.to_string()), (META_ROLLUP_COV_ID, at_id.to_string())] {
                w.execute("INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![k, v]).unwrap();
            }
            DimRollupCoverage::publish(&w, 1_784_000_000, below, below, at_id);
        }
        let ecrivain = {
            let w = Connection::open(&p).unwrap();
            (RollupCoverage::of(&w), DimRollupCoverage::of(&w))
        };
        let pool = read_with(
            p.as_str(),
            (RollupCoverage::unproven(), DimRollupCoverage::unproven()),
            |c| (RollupCoverage::of(c), DimRollupCoverage::of(c)),
        );
        assert_eq!(
            ecrivain.0, pool.0,
            "la couverture du rollup lue par le POOL diffère de celle lue par l'écrivain : sortir \
             cette lecture du verrou partagé changerait ce qui est SERVI, pas seulement quand"
        );
        assert_eq!(ecrivain.1, pool.1, "même exigence pour la couverture PAR DIMENSION");
        assert_eq!(
            pool.0.covered_below(),
            below,
            "le pool doit rendre la borne ÉTABLIE, pas `unproven` : un `unproven` silencieux ferait \
             décliner la route pour toujours — réponse juste, rollup mort, et personne ne le voit"
        );
        assert!(pool.1.band().is_some(), "même exigence pour la bande par dimension");
        let _ = std::fs::remove_file(&p);
    }

    /// (e) UN SEUL ÉCRIVAIN. Le défaut n'était pas une ligne fausse : c'était SEPT sites qui
    /// écrivaient `sem_wait_ms` à la main depuis une variable calculée ailleurs. Tant que n'importe
    /// quel handler peut poser ce nom sur n'importe quel nombre, le prochain le reposera. La garde
    /// est DÉRIVÉE (elle cherche le NOM des champs, pas une liste de fichiers) : tout nouveau site
    /// qui publierait une de ces mesures sans passer par `QueryTimings::stamp` la fait rougir.
    #[test]
    fn only_query_timings_publishes_the_time_split() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Les noms des champs de temps publiés dans `stats`. `server_ms` en fait partie : c'est en
        // le posant à côté de `sem_wait_ms` que l'ancien code rendait les deux indissociables.
        const CHAMPS: [&str; 5] = ["sem_wait_ms", "server_ms", "prepare_ms", "db_lock_wait_ms", "exec_ms"];
        let mut hors: Vec<(String, String)> = Vec::new();
        let mut dans = 0usize;
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                        continue; // le code de test a le droit de LIRE les champs qu'il vérifie
                    }
                    stack.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                let rel = p.strip_prefix(&root).unwrap().to_string_lossy().to_string();
                for line in std::fs::read_to_string(&p).unwrap().lines() {
                    let l = line.trim();
                    if l.starts_with("//") || l.starts_with("//!") {
                        continue; // la documentation NOMME ces champs, c'est son travail
                    }
                    if !CHAMPS.iter().any(|c| l.contains(c)) {
                        continue;
                    }
                    if rel == "query_timing.rs" {
                        dans += 1;
                    } else {
                        hors.push((rel.clone(), l.to_string()));
                    }
                }
            }
        }
        assert!(dans > 0, "invariant vide = invariant mort : query_timing.rs ne publie plus rien, la sonde est cassée");
        assert!(
            hors.is_empty(),
            "ces sites nomment un champ de temps hors de `query_timing` — c'est la FORME qui a produit le \
             défaut (un nombre calculé ici, publié là, sous un nom qui décrit autre chose). Passer par \
             `QueryTimings::stamp` : {hors:?}"
        );
    }

    /// (f) UNE SEULE PORTE VERS LE SÉMAPHORE INTERACTIF. Une route qui prend un permit sans passer
    /// par l'acquisition chronométrée redevient invisible à toute mesure de concurrence — c'est
    /// exactement ce qu'était `/api/search`, qui consommait les mêmes permis sans publier un seul
    /// chiffre. La garde est dérivée du NOM du sémaphore : une route ajoutée demain hérite de la
    /// contrainte sans qu'on ait à l'énumérer ici.
    ///
    /// P7.8-a A ÉLARGI L'ENJEU. Cette même porte publie maintenant, PAR ROUTE, l'attente du permit
    /// et le temps passé à occuper la borne (`semaphore_interactif`). Une acquisition qui la
    /// contourne ne perd donc plus seulement son champ `stats` : elle disparaît aussi de
    /// l'exposition d'exploitation, c'est-à-dire de la seule vue qui dit QUI sature la ressource la
    /// plus contrainte du projet.
    #[test]
    fn the_interactive_semaphore_is_only_acquired_through_the_timed_gate() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sites: Vec<(String, String)> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                        continue;
                    }
                    stack.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                let rel = p.strip_prefix(&root).unwrap().to_string_lossy().to_string();
                // DÉCLARATION et CÂBLAGE du sémaphore : `state.rs` porte le champ, la FAÇADE du module
                // `server` le construit et le transporte. Ces deux fichiers-là NOMMENT donc légitimement
                // le sémaphore sans l'acquérir — et le test le vérifie plus bas, au lieu de leur faire
                // confiance. L'exemption reste NOMINATIVE et ne couvre PAS les sous-modules de `server`
                // (`P7.18-a`) : un sous-module qui prendrait un permit hors de la porte serait accusé.
                let porteur = rel == "state.rs" || rel == "server/mod.rs";
                for (n, line) in std::fs::read_to_string(&p).unwrap().lines().enumerate() {
                    let l = line.trim();
                    if l.starts_with("//") || l.starts_with("//!") {
                        continue;
                    }
                    // LE CRITÈRE EST « NOMMER LE SÉMAPHORE », PAS « NOMMER `acquire` SUR LA MÊME
                    // LIGNE ». L'ancien critère exigeait les deux mots ENSEMBLE : il suffisait donc
                    // de couper en deux lignes (`let s = st.query_sem.clone();` puis
                    // `s.acquire_owned().await`) pour prendre un permit sous le radar — la seconde
                    // ligne ne nomme plus le sémaphore. On refuse maintenant l'ACCÈS lui-même : sans
                    // pouvoir nommer `query_sem`, aucune ligne ne peut en obtenir un permit.
                    // La part CODE seulement : `handlers/dashboards.rs` porte un
                    // `let refresh_sem = …; // … (jamais query_sem)`, et un commentaire ne prend pas
                    // de permit. Lire la ligne entière ferait accuser la route qui dit justement ne
                    // pas toucher à la borne interactive.
                    let code = l.split("//").next().unwrap_or("");
                    if code.contains("query_sem") {
                        if porteur {
                            assert!(
                                !code.contains("acquire"),
                                "{rel}:{} acquiert un permit dans le câblage du sémaphore, où aucune \
                                 route ne le verra passer : {l}",
                                n + 1
                            );
                            continue;
                        }
                        sites.push((format!("{rel}:{}", n + 1), code.trim().to_string()));
                    }
                }
            }
        }
        assert!(!sites.is_empty(), "invariant vide = invariant mort : plus aucune acquisition trouvée");
        for (site, line) in &sites {
            assert!(
                line.contains("acquire_query_permit(&st.query_sem)") || line.contains(".permit(&st.query_sem)"),
                "{site} touche au sémaphore interactif hors de l'acquisition chronométrée : son attente ne \
                 sera mesurée nulle part, la route pèsera sur la concurrence sans apparaître dans aucune \
                 courbe (P7.8-a), et rien ne publiera le temps pendant lequel elle occupe la borne. \
                 Passer par `acquire_query_permit(&st.query_sem)` ou `clock.permit(&st.query_sem)`. {line}"
            );
        }
    }
