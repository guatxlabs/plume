    // ================================================================================================
    // P10.7-c — LE PORTILLON AVOUE, UNE FOIS, POUR TOUTES LES ROUTES QUI LE FRANCHISSENT.
    //
    // CE QUI ÉTAIT CASSÉ, ET CE QUE LA MESURE A RÉFUTÉ. Quand le portillon interactif refuse
    // (`AppState::query_sem` CLOS — l'arrêt du processus), chaque route décidait chez elle quoi
    // rendre. Le défaut « corps vide NU » avait été fermé DEUX FOIS au cas par cas — `/api/search`
    // sous `P10.7-a`, `/api/query` sous `P11.14-c` — et l'index annonçait une TROISIÈME occurrence,
    // sur le Pivot. Le compte est FAUX : le balayage dérivé de ce module, joué le 2026-08-28 sur
    // l'arbre, trouve DIX-NEUF sites d'acquisition, dont ONZE rendaient un corps 200 dont toutes les
    // clés sont vides et qui ne porte AUCUNE cause — `{"alerts":[]}`, `{"hosts":[]}`,
    // `{"cases":[],"total":0}`, `{"columns":[],"rows":[]}`… La troisième occurrence était la
    // onzième, et c'est le vrai résultat : un remède qui se rejoue route par route ne converge pas,
    // il ferme les occurrences qu'on a regardées et laisse la FORME intacte pour la suivante.
    //
    // CE QUI EST TENU ICI, EN DEUX JAMBES QUI NE PROUVENT PAS LA MÊME CHOSE.
    //
    //   (a) STATIQUE, DÉRIVÉE. La population n'est pas une liste de routes : c'est l'ensemble des
    //       sites qui NOMMENT le sémaphore interactif, découverts par parcours de `daemon/src/`.
    //       Une route écrite demain y entre sans que personne ne l'inscrive. La règle porte sur la
    //       branche `Err` de chaque site : elle doit soit passer par `handlers::portillon`, seul
    //       point qui écrit la cause, soit rendre une réponse d'ÉCHEC HTTP (`err_json`,
    //       `server_err`, `bad_req`) — un statut d'échec n'est déjà, pour aucun consommateur, une
    //       absence établie. Ce qui reste interdit est exactement le troisième cas : un corps 200
    //       fabriqué sur place.
    //
    //       CETTE JAMBE EST COMPLÈTE PAR COMPOSITION, ET C'EST DIT PLUTÔT QUE SUPPOSÉ. Elle ne
    //       reconnaît qu'une seule écriture de l'acquisition (`(&st.query_sem)`) ; ce qui interdit
    //       d'en écrire une autre n'est pas elle, c'est la garde voisine
    //       `the_interactive_semaphore_is_only_acquired_through_the_timed_gate` (`P7.8-a`), qui
    //       refuse qu'une ligne nomme le sémaphore hors de la porte chronométrée. Retirer CETTE
    //       garde-là rendrait celle-ci contournable ; les deux tiennent ensemble.
    //
    //   (b) EXÉCUTÉE, ET ELLE-MÊME EXHAUSTIVE. La jambe statique prouve une FORME : elle ne dit pas
    //       que l'aveu ARRIVE au client. Le routeur RÉEL est donc servi avec le portillon CLOS, et
    //       chaque route qui le franchit est interrogée. Les routes ne sont pas énumérées non plus :
    //       elles sont dérivées de la table de routage (`server/groupes_de_routes.rs`) par
    //       intersection avec les fonctions trouvées en (a). Et le test VÉRIFIE SA PROPRE
    //       COUVERTURE : toute fonction qui rend un corps de refus et qu'aucune sonde n'atteint fait
    //       ÉCHOUER le test au lieu d'être silencieusement non couverte — c'est ce qui empêche une
    //       quatorzième route d'entrer sans preuve exécutée.
    //
    //       LE TÉMOIN INVERSE EST INDISPENSABLE : le MÊME balayage est rejoué portillon OUVERT, et
    //       aucune de ces routes ne doit alors porter la cause. Sans lui, un correctif dégénéré —
    //       « avoue toujours » — passerait le premier balayage brillamment tout en accusant le
    //       portillon sur des réponses parfaitement normales. La valeur qui change entre les deux
    //       balayages est nommée : la présence de la cause du portillon dans le corps servi, à
    //       requête, identité et base IDENTIQUES.
    //
    // CE QUE CE MODULE NE PROUVE PAS, ET QUI EST ÉCRIT PARCE QUE C'EST LA MOITIÉ QUI MANQUE :
    //   * il ne prouve rien sur ce que l'ANALYSTE voit. Le démon avoue ; un module de console qui ne
    //     lit jamais `error` affichera toujours une table vide. Mesuré le 2026-08-28 : sur les six
    //     modules de `web/` qui consomment ces routes, QUATRE ne lisent `error` nulle part
    //     (`alerts.js`, `fleet.js`, `datamodels.js`, `attack.js`). Le versant console est un constat
    //     à part entière, et il reste OUVERT ;
    //   * il ne tient QUE le portillon. Une lecture qui échoue plus loin — pool de lecture
    //     indisponible, watchdog, tâche bloquante paniquée, compilation refusée — a ses propres
    //     branches, dont plusieurs rendent encore un corps vide nu. Même famille, autre mécanisme,
    //     hors de cette garde ;
    //   * les six sites qui rendent une réponse d'échec HTTP sont ACCEPTÉS sur leur statut, pas sur
    //     la qualité de leur phrase : « service indisponible » est vague, et cette garde ne le dira
    //     pas.
    // ================================================================================================

    /// Sous ce nombre de sites d'acquisition RÉELLEMENT lus, ce n'est pas l'arbre qui est propre,
    /// c'est la lecture qui est cassée — et un balayage aveugle rend vert. MESURÉ le 2026-08-28 :
    /// 19 sites (13 corps 200 passant par le portillon, 6 réponses d'échec HTTP).
    const PORTILLON_PLANCHER_SITES: usize = 15;

    /// Idem pour la jambe exécutée : sous ce nombre de routes GET dérivées, la sonde ne prouve plus
    /// rien. MESURÉ le 2026-08-28 : 11 routes GET sans paramètre.
    const PORTILLON_PLANCHER_ROUTES: usize = 8;

    /// LES SONDES ÉCRITES À LA MAIN, et pourquoi chacune l'est.
    ///
    /// La table de routage donne le CHEMIN d'une route, jamais ce qu'il faut lui envoyer pour
    /// atteindre le portillon. Deux familles échappent donc à la dérivation : un `POST`, dont le
    /// corps ne se devine pas ; et un `GET` qui REFUSE avant le portillon quand un paramètre
    /// manque — `/api/search` sans `q` rend `{"results":[]}` sans jamais demander de permit.
    ///
    /// LEUR OUBLI N'EST PAS POSSIBLE : le test rapproche l'ensemble des fonctions couvertes
    /// (dérivées + écrites) de l'ensemble des fonctions qui rendent un corps de refus, et refuse
    /// tout écart. Une fonction que la dérivation n'atteint pas fait ROUGIR le test tant qu'aucune
    /// sonde ne l'atteint.
    const PORTILLON_SONDES_ECRITES: &[(&str, &str, &str, &str)] = &[
        // (méthode, chemin, corps de requête, fonction du démon que la sonde atteint)
        ("GET", "/api/search?q=plume", "", "search"),
        ("POST", "/api/query", r#"{"soql":"search"}"#, "query"),
        ("POST", "/api/pivot/run", r#"{"object_id":1,"stats":[{"func":"count"}]}"#, "run_generated_soql"),
    ];

    /// Un site d'acquisition du portillon : où il est, dans quelle fonction, et ce que rend sa
    /// branche `Err`.
    #[derive(Debug, Clone)]
    struct SitePortillon {
        fichier: String,
        ligne: usize,
        fonction: String,
        branche_err: String,
    }

    /// Le texte à JUGER : commentaires de ligne retirés, hauteur CONSERVÉE (les numéros de ligne
    /// rendus doivent désigner le vrai fichier). Un `//` dans un littéral de chaîne couperait à tort
    /// — aucun site d'acquisition n'en porte, et le plancher de non-dégénérescence est là pour le
    /// cas où cette hypothèse cesserait d'être vraie.
    fn portillon_depouiller(src: &str) -> String {
        src.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
    }

    /// Le bloc délimité par la PREMIÈRE accolade ouvrante à partir de `depuis`, accolades appariées.
    /// Rend `None` si l'appariement ne se ferme pas : mieux vaut ne rien conclure que juger un
    /// fragment.
    fn portillon_bloc(texte: &str, depuis: usize) -> Option<&str> {
        let o = texte[depuis..].find('{')? + depuis;
        let (mut prof, o_ct) = (0usize, texte.as_bytes());
        for i in o..texte.len() {
            match o_ct[i] {
                b'{' => prof += 1,
                b'}' => {
                    prof -= 1;
                    if prof == 0 {
                        return Some(&texte[o..=i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// La branche `Err` d'un site d'acquisition, à partir de la position du marqueur.
    ///
    /// DEUX FORMES EXISTENT DANS L'ARBRE, et les deux sont lues : le `match … { Ok(..) => …,
    /// Err(..) => … }`, et l'enchaînement `…await.map_err(|_| …)?`. Une troisième forme qui
    /// n'exposerait aucune des deux rend `None` — le site est alors ACCUSÉ, jamais blanchi.
    fn portillon_branche_err(texte: &str, marqueur: usize) -> Option<String> {
        let fin_instruction = texte[marqueur..].find(';').map(|i| marqueur + i).unwrap_or(texte.len());
        let ouvrante = texte[marqueur..].find('{').map(|i| marqueur + i);
        // `map_err` avant toute accolade -> forme sans `match` : l'instruction entière fait foi.
        if ouvrante.map(|o| o > fin_instruction).unwrap_or(true) {
            let s = &texte[marqueur..fin_instruction];
            return s.contains("map_err").then(|| portillon_une_ligne(s));
        }
        let bloc = portillon_bloc(texte, marqueur)?;
        let i = bloc.find("Err")?;
        Some(portillon_une_ligne(&bloc[i..]))
    }

    /// Réduction des blancs : le texte rendu dans un message d'échec tient sur une ligne.
    fn portillon_une_ligne(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Les sites d'acquisition d'un texte de fichier : `(ligne, fonction, branche Err)`.
    ///
    /// LE MARQUEUR EST L'ACCÈS AU SÉMAPHORE, pas le nom d'une fonction d'acquisition : c'est ce qui
    /// rend la lecture insensible au choix entre `acquire_query_permit(&st.query_sem)` et
    /// `clock.permit(&st.query_sem)`, les deux seules écritures que `P7.8-a` autorise.
    fn portillon_sites_du_texte(brut: &str) -> Vec<(usize, String, String)> {
        let texte = portillon_depouiller(brut);
        let mut out = Vec::new();
        let mut depuis = 0usize;
        while let Some(rel) = texte[depuis..].find("(&st.query_sem)") {
            let m = depuis + rel;
            depuis = m + 1;
            let ligne = texte[..m].matches('\n').count() + 1;
            // La fonction ENGLOBANTE : la dernière déclaration `fn` en tête de ligne avant le site.
            let fonction = texte[..m]
                .lines()
                .rev()
                .find_map(|l| {
                    let t = l.trim_start();
                    let reste = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
                    let reste = reste.strip_prefix("async ").unwrap_or(reste);
                    reste.strip_prefix("fn ").map(|q| {
                        q.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("").to_string()
                    })
                })
                .unwrap_or_default();
            let branche = portillon_branche_err(&texte, m).unwrap_or_default();
            out.push((ligne, fonction, branche));
        }
        out
    }

    /// LA POPULATION : tous les sites d'acquisition de `daemon/src/`, `tests` exclu (un test qui
    /// acquiert un permit ne sert aucune réponse).
    fn portillon_sites() -> Vec<SitePortillon> {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        crate::db_open::door_tests::rs_files(&racine, &mut fichiers);
        fichiers.sort();
        let mut out = Vec::new();
        for p in fichiers {
            let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().to_string();
            if rel.starts_with("tests/") || rel.starts_with("tests\\") {
                continue;
            }
            let src = std::fs::read_to_string(&p).expect("source du démon lisible");
            for (ligne, fonction, branche_err) in portillon_sites_du_texte(&src) {
                out.push(SitePortillon { fichier: rel.clone(), ligne, fonction, branche_err });
            }
        }
        out
    }

    /// UNE BRANCHE QUI REND UN CORPS, par opposition à une réponse d'ÉCHEC HTTP.
    ///
    /// C'EST CE PRÉDICAT-LÀ, ET NON L'AVEU, QUI DÉFINIT LA POPULATION DE LA JAMBE EXÉCUTÉE — la
    /// distinction a été MESURÉE par mutation le 2026-08-28. Une population définie par « passe par
    /// le point unique » RÉTRÉCIT au moment exact où une route régresse : la route sort de
    /// l'ensemble, plus aucune sonde ne l'interroge, et la jambe exécutée reste VERTE sur un défaut
    /// qu'elle existe pour voir. Définie par « rend un corps », elle ne bouge pas : la route
    /// régressée reste sondée, et la sonde la trouve sans cause.
    fn portillon_branche_rend_un_corps(branche: &str) -> bool {
        !(branche.contains("err_json(") || branche.contains("server_err(") || branche.contains("bad_req("))
    }

    /// L'AVEU, tel que la garde le reconnaît : le point unique, ou un statut d'échec HTTP.
    fn portillon_branche_avoue(branche: &str) -> bool {
        branche.contains("portillon::corps_de_refus(") || !portillon_branche_rend_un_corps(branche)
    }

    /// (a) LA JAMBE STATIQUE — aucune branche `Err` du portillon ne rend un corps 200 fabriqué sur place.
    #[test]
    fn aucune_branche_du_portillon_ne_rend_un_corps_sans_cause() {
        // L'INSTRUMENT SE VALIDE AVANT DE JUGER, DANS LES DEUX SENS. Sans le témoin inverse, une
        // lecture qui accuserait TOUT passerait le positif brillamment.
        let doit_accuser = [
            r#"async fn r(){ let _p = match acquire_query_permit(&st.query_sem).await { Ok((p,_w)) => p, Err(_) => return Json(json!({ "alerts": [] })), }; }"#,
            r#"async fn r(){ let (_p,_t) = match clock.permit(&st.query_sem).await { Ok(x) => x, Err(_) => return Json(json!({})).into_response(), }; }"#,
            // une forme sans `match` NI `map_err` : rien n'est lisible -> accusée, jamais blanchie
            r#"async fn r(){ let _p = acquire_query_permit(&st.query_sem).await.unwrap(); }"#,
        ];
        let doit_ignorer = [
            r#"async fn r(){ let _p = match acquire_query_permit(&st.query_sem).await { Ok((p,_w)) => p, Err(_) => return Json(crate::handlers::portillon::corps_de_refus(json!({ "alerts": [] }))), }; }"#,
            r#"async fn r(){ let _p = match acquire_query_permit(&st.query_sem).await { Ok((p,_w)) => p, Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "service indisponible"), }; }"#,
            r#"async fn r(){ let _p = acquire_query_permit(&st.query_sem).await.map(|(p,_w)| p).map_err(|_| err_json(StatusCode::SERVICE_UNAVAILABLE, "x"))?; }"#,
        ];
        // La forme fautive écrite dans un COMMENTAIRE ne décide de rien : elle ne doit produire AUCUN
        // site. Sans ce témoin-là, la lecture accuserait le commentaire qui EXPLIQUE le défaut.
        let commentaire = "async fn r(){ // Err(_) => return Json(json!({})) sur (&st.query_sem)\n let x = 1; }";
        for src in doit_accuser {
            let s = portillon_sites_du_texte(src);
            assert_eq!(s.len(), 1, "témoin : un site attendu dans `{src}` — lu {s:?}");
            assert_eq!(s[0].1, "r", "témoin : la fonction englobante est retrouvée — lu `{}`", s[0].1);
            assert!(!portillon_branche_avoue(&s[0].2), "témoin : la forme NUE n'est pas accusée — {src}");
        }
        for src in doit_ignorer {
            let s = portillon_sites_du_texte(src);
            assert_eq!(s.len(), 1, "témoin INVERSE : un site attendu dans `{src}` — lu {s:?}");
            assert!(portillon_branche_avoue(&s[0].2), "témoin INVERSE : une forme saine est accusée — {}", s[0].2);
        }
        assert!(
            portillon_sites_du_texte(commentaire).is_empty(),
            "témoin de dépouillement : un site est lu dans un COMMENTAIRE — la lecture accuserait la \
             prose qui explique le défaut."
        );

        let sites = portillon_sites();
        assert!(
            sites.len() >= PORTILLON_PLANCHER_SITES,
            "INSTRUMENT MUET : {} site(s) d'acquisition lus, plancher {PORTILLON_PLANCHER_SITES}. La \
             découverte est cassée — cette garde refuse de conclure plutôt que de rendre vert en étant \
             aveugle.",
            sites.len()
        );
        let nus: Vec<String> = sites
            .iter()
            .filter(|s| !portillon_branche_avoue(&s.branche_err))
            .map(|s| format!("{}:{} ({}) -> {}", s.fichier, s.ligne, s.fonction, s.branche_err))
            .collect();
        assert!(
            nus.is_empty(),
            "ces branches rendent, quand le portillon REFUSE, un corps que tout consommateur lit comme \
             une ABSENCE ÉTABLIE — c'est-à-dire comme un fait. Le remède ne s'écrit pas ici : passer par \
             `crate::handlers::portillon::corps_de_refus(<la forme attendue>)`, qui écrit la cause UNE \
             fois pour toutes les routes. {nus:#?}"
        );
        // Le point unique est réellement emprunté : sans cela, la règle serait tenue par les seules
        // réponses d'échec HTTP et le module `portillon` serait mort sans que rien ne rougisse.
        let par_le_point = sites.iter().filter(|s| s.branche_err.contains("portillon::corps_de_refus(")).count();
        assert!(
            par_le_point >= 10,
            "INSTRUMENT MUET : {par_le_point} branche(s) passent par `handlers::portillon`. Le point \
             unique de l'aveu n'est plus emprunté — la règle serait tenue à vide."
        );
    }

    /// La cause, réduite à son plus long fragment PUREMENT ASCII : c'est ce fragment qu'on cherche
    /// dans le corps servi. DÉRIVÉ de la constante, jamais recopié — reformuler la phrase change la
    /// sonde du même geste, et aucun encodage JSON de caractère non-ASCII ne peut faire manquer la
    /// recherche.
    fn portillon_marqueur_ascii() -> String {
        crate::handlers::portillon::CAUSE_PORTILLON_CLOS
            .split(|c: char| !c.is_ascii() || c == '"' || c == '\\')
            .max_by_key(|s| s.len())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    /// Les routes GET SANS PARAMÈTRE servies par une fonction donnée, lues à l'unique site de
    /// déclaration de la table de routage.
    fn portillon_routes_get(fonctions: &std::collections::BTreeSet<String>) -> Vec<(String, String)> {
        let src = texte_du_module_serveur();
        let mut out = Vec::new();
        for line in src.lines() {
            let code = line.split("//").next().unwrap_or("");
            let Some((_, rest)) = code.split_once(".route(\"") else { continue };
            let Some((path, tail)) = rest.split_once('"') else { continue };
            if path.contains('{') {
                continue; // un gabarit demande une valeur : hors de ce balayage, et dit
            }
            let Some((_, apres)) = tail.split_once("get(") else { continue };
            let nom: String = apres.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if fonctions.contains(&nom) {
                out.push((path.to_string(), nom));
            }
        }
        out
    }

    /// (b) LA JAMBE EXÉCUTÉE — portillon CLOS, chaque route qui le franchit AVOUE ; portillon
    /// OUVERT, aucune ne porte la cause. Le routeur est le VRAI, avec ses six couches.
    #[tokio::test]
    async fn le_portillon_clos_avoue_sur_le_routeur_reel_et_se_tait_quand_il_ouvre() {
        let sites = portillon_sites();
        // LA POPULATION EST « REND UN CORPS », JAMAIS « AVOUE » : cf. `portillon_branche_rend_un_corps`.
        let rendent_un_corps: std::collections::BTreeSet<String> = sites
            .iter()
            .filter(|s| portillon_branche_rend_un_corps(&s.branche_err))
            .map(|s| s.fonction.clone())
            .collect();
        assert!(
            rendent_un_corps.len() >= 10,
            "INSTRUMENT MUET : {} fonction(s) rendent un corps sur le refus du portillon — la \
             dérivation est cassée.",
            rendent_un_corps.len()
        );
        // Une fonction déjà atteinte par une sonde ÉCRITE sort du balayage dérivé : la dérivation ne
        // sait pas qu'il lui faut un paramètre, et la sonderait sur un chemin qui refuse avant le
        // portillon.
        let ecrites: std::collections::BTreeSet<String> =
            PORTILLON_SONDES_ECRITES.iter().map(|(_, _, _, f)| (*f).to_string()).collect();
        let routes: Vec<(String, String)> = portillon_routes_get(&rendent_un_corps)
            .into_iter()
            .filter(|(_, f)| !ecrites.contains(f))
            .collect();
        assert!(
            routes.len() >= PORTILLON_PLANCHER_ROUTES,
            "INSTRUMENT MUET : {} route(s) GET dérivées, plancher {PORTILLON_PLANCHER_ROUTES} : la \
             table de routage n'est plus lue, le balayage sonderait le vide.",
            routes.len()
        );

        // LA COUVERTURE EST VÉRIFIÉE, PAS ESPÉRÉE : toute fonction qui rend un corps de refus et
        // qu'aucune sonde n'atteint fait échouer le test. C'est ce qui interdit à une route neuve
        // d'entrer sans preuve exécutée.
        let mut couvertes: std::collections::BTreeSet<String> = routes.iter().map(|(_, f)| f.clone()).collect();
        couvertes.extend(ecrites.iter().cloned());
        let orphelines: Vec<&String> = rendent_un_corps.difference(&couvertes).collect();
        assert!(
            orphelines.is_empty(),
            "ces fonctions rendent un CORPS quand le portillon refuse, et AUCUNE sonde ne les atteint : la \
             jambe exécutée les déclarerait couvertes sans les avoir vues. Ajouter la sonde (une route \
             GET sans paramètre est dérivée toute seule ; sinon, une entrée dans \
             `PORTILLON_SONDES_ECRITES`). {orphelines:?}"
        );
        // … et la réciproque : une sonde écrite qui viserait une fonction que plus aucune branche ne
        // sert deviendrait une sonde sur du vide, verte en ne mesurant rien.
        let sondes_mortes: Vec<&String> = ecrites.difference(&rendent_un_corps).collect();
        assert!(
            sondes_mortes.is_empty(),
            "sondes écrites qui ne visent plus aucune branche rendant un corps — elles seraient \
             vertes sans rien mesurer : {sondes_mortes:?}"
        );

        let marqueur = portillon_marqueur_ascii();
        assert!(
            marqueur.len() > 20,
            "INSTRUMENT MUET : le fragment ASCII dérivé de la cause est trop court (`{marqueur}`) pour \
             discriminer quoi que ce soit dans un corps de réponse."
        );

        // Un objet de modèle de données MINIMAL : c'est ce qui fait qu'un `POST /api/pivot/run`
        // atteint le portillon au lieu d'être refusé avant lui.
        let (mut st, dbp) = router_test_state("portillon-clos");
        {
            let c = open_db(&dbp).unwrap();
            c.execute("INSERT INTO data_model(id,name,enabled) VALUES(1,'m',1)", []).ok();
            c.execute(
                "INSERT INTO data_model_object(id,model_id,name,parent_id,constraint_soql,enabled) \
                 VALUES(1,1,'o',NULL,'',1)",
                [],
            )
            .unwrap();
        }
        let authz = viewer_authz();
        let json_ct = [("Content-Type", "application/json")];

        // ---- PORTILLON CLOS : la cause est SERVIE, sur chaque route. ----
        let mut ferme = st.clone();
        ferme.query_sem = Arc::new(tokio::sync::Semaphore::new(2));
        ferme.query_sem.close();
        let addr = router_serve(ferme).await;
        for (chemin, f) in &routes {
            let (code, corps) = router_probe_corps(addr, "GET", chemin, Some(&authz), &[]).await;
            assert_eq!(code, 200, "portillon clos, {chemin} ({f}) : la réponse devrait être un corps, pas un statut — {corps}");
            assert!(
                corps.contains(&marqueur),
                "portillon CLOS : `{chemin}` ({f}) rend un corps SANS la cause. Tout consommateur le lit \
                 comme une absence établie. Corps : {corps}"
            );
        }
        for (methode, chemin, corps_req, f) in PORTILLON_SONDES_ECRITES {
            let (code, corps) = router_probe_envoi(addr, methode, chemin, Some(&authz), &json_ct, corps_req).await;
            assert_eq!(code, 200, "portillon clos, {methode} {chemin} ({f}) : {corps}");
            assert!(corps.contains(&marqueur), "portillon CLOS : `{chemin}` ({f}) rend un corps SANS la cause : {corps}");
        }

        // ---- TÉMOIN INVERSE, MÊME BASE, MÊMES REQUÊTES : portillon OUVERT -> aucune cause. ----
        // Sans ce balayage-là, « avoue toujours » passerait le premier : la valeur qui change est
        // la PRÉSENCE de la cause, et rien d'autre ne bouge entre les deux.
        st.query_sem = Arc::new(tokio::sync::Semaphore::new(2));
        let addr = router_serve(st).await;
        for (chemin, f) in &routes {
            let (_, corps) = router_probe_corps(addr, "GET", chemin, Some(&authz), &[]).await;
            assert!(
                !corps.contains(&marqueur),
                "portillon OUVERT : `{chemin}` ({f}) accuse pourtant le portillon. Un aveu permanent ne \
                 vaut pas mieux qu'un silence : il rend la cause illisible quand elle est vraie. {corps}"
            );
        }
        for (methode, chemin, corps_req, f) in PORTILLON_SONDES_ECRITES {
            let (_, corps) = router_probe_envoi(addr, methode, chemin, Some(&authz), &json_ct, corps_req).await;
            assert!(!corps.contains(&marqueur), "portillon OUVERT : `{chemin}` ({f}) accuse pourtant le portillon : {corps}");
        }
    }

    /// LE POINT UNIQUE LUI-MÊME : il ajoute la cause SANS retirer la forme, et il ne peut pas être
    /// réduit au silence par la forme qu'on lui passe.
    #[test]
    fn le_point_unique_ajoute_la_cause_sans_perdre_la_forme() {
        use crate::handlers::portillon::{corps_de_refus, CAUSE_PORTILLON_CLOS};
        let v = corps_de_refus(json!({ "cases": [], "total": 0 }));
        assert_eq!(v["cases"], json!([]), "la forme attendue par le consommateur est CONSERVÉE");
        assert_eq!(v["total"], json!(0), "la forme attendue par le consommateur est CONSERVÉE");
        assert_eq!(v["error"], json!(CAUSE_PORTILLON_CLOS), "la cause est portée par `error`");
        // Une forme qui portait déjà `error` ne peut pas masquer l'aveu du portillon.
        let v = corps_de_refus(json!({ "error": "autre chose" }));
        assert_eq!(v["error"], json!(CAUSE_PORTILLON_CLOS), "c'est le portillon qui a refusé, pas la route");
        // Une forme qui n'est pas un objet est REMPLACÉE plutôt que rendue nue.
        let v = corps_de_refus(json!([1, 2, 3]));
        assert_eq!(v["error"], json!(CAUSE_PORTILLON_CLOS), "aucune valeur ne sort d'ici sans sa cause");
        // La phrase dit les trois choses sans lesquelles un lecteur relit un vide : ce qui n'a pas eu
        // lieu, pourquoi, et ce que le corps n'établit PAS.
        assert!(CAUSE_PORTILLON_CLOS.contains("portillon"), "la cause nomme le mécanisme qui a refusé");
        assert!(
            CAUSE_PORTILLON_CLOS.contains("aucune ligne") && CAUSE_PORTILLON_CLOS.contains("absence"),
            "la cause dit que le corps vide n'établit PAS une absence : sans cette phrase, le corps se \
             relit exactement comme avant. Cause : {CAUSE_PORTILLON_CLOS}"
        );
    }
