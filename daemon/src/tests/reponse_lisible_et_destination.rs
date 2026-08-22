    // =============================================================================================
    // `P11.2-b` + `P11.1-e` — UN INTERRUPTEUR QUI ARME UN BAN SE LIT, ET CE QUI CRÉE UN PRODUCTEUR
    // D'ALERTES DIT OÙ SON PRODUIT ARRIVE.
    //
    // CE QUI S'EST PASSÉ. Sur la console, l'analyste a coché une case « actif » à côté d'un playbook
    // livré (« SSH CVE-2024-6387 … -> ban IP ») sans lire qu'elle armait un ban d'IP : l'effet a eu lieu
    // (IP bannie), l'intention n'était pas lisible. Dans la même session, une règle créée ne disait pas
    // où ses alertes arriveraient.
    //
    // CE QUE CETTE SUITE TIENT, ET COMMENT.
    //   ① La PHRASE de conséquence d'un `ban_ip` nomme la durée que les EXÉCUTEURS posent réellement :
    //      elle est confrontée à l'argument `--duration` que `action_command` passe à CrowdSec et au TTL
    //      du blocage HTTP natif. Une phrase qui dirait « 4 h » quand l'exécuteur pose « 2h » tombe ici.
    //   ② Le vocabulaire offert PAR LES SURFACES (le `<select>` du formulaire playbook, la liste des
    //      actions d'une étape de runbook) est DÉRIVÉ des sources web : chaque action offerte est dans le
    //      vocabulaire fermé ET a une phrase qui n'est pas le repli « hors vocabulaire » ; une action
    //      inventée obtient le repli ET le refus de `action_kind_valid` (témoin inverse).
    //   ③ La liste servie à la surface porte la phrase et le MODE global : en Observation la ligne dit
    //      « proposé », en Actif « exécuté » — la même ligne, l'autre mot (mutation du mode).
    //   ④ GARDE DÉRIVÉE `P11.1-e` : les tables de producteurs sont LUES dans les boucles du
    //      planificateur (`FROM <table> … enabled=1`), les routes qui en créent sont LUES dans
    //      `server.rs` + le corps des handlers (`INSERT INTO <table>(`), et les modules web qui POSTent
    //      sur ces routes sont LUS sous `web/`. Chacun doit nommer la destination par l'aide partagée
    //      (`announceCreated` / `destinationNote` / `destinationSentence` de `producer_ui.js`). Aucune
    //      des trois listes n'est écrite à la main ; un module qui apparaîtrait demain est attrapé le
    //      jour où il apparaît. Les ÉCARTS CONNUS sont nommés avec leur raison, et l'ensemble mesuré
    //      doit être EXACTEMENT celui-là : corriger un écart oblige à le retirer de la liste.
    // =============================================================================================
    mod reponse_lisible_et_destination {
        use super::*;
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::PathBuf;

        fn racine_src() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src") }
        fn racine_web() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../web") }

        // ------------------------------------------------------------------------------------------
        // ① La phrase dit la durée que les exécuteurs posent.
        // ------------------------------------------------------------------------------------------
        #[test]
        fn la_phrase_de_consequence_du_ban_dit_la_duree_que_les_executeurs_posent() {
            let phrase = action_consequence("ban_ip");
            // CrowdSec : `--duration <n>h`, lu dans l'argv que l'exécuteur construit, pas dans une constante.
            let (_prog, args) = action_command("ban_ip", "203.0.113.9", "crowdsec", "");
            let pos = args.iter().position(|a| a == "--duration").expect("action_command crowdsec : --duration absent");
            let duree = args.get(pos + 1).expect("--duration sans valeur");
            let heures = duree.strip_suffix('h').and_then(|h| h.parse::<i64>().ok()).expect("durée CrowdSec attendue en heures entières");
            assert_eq!(heures, ban_duration_hours(), "la durée CrowdSec ({duree}) et le TTL du blocage natif ({} s) divergent : la phrase ne peut pas être vraie pour les deux", NETBAN_ACTION_TTL_S);
            assert!(phrase.contains(&format!("pendant {heures} h")), "la phrase ne nomme pas la durée posée ({heures} h) : « {phrase} »");
            assert!(phrase.contains("bannit l'IP source"), "la phrase ne nomme pas l'effet : « {phrase} »");
            assert!(phrase.contains("fail2ban") && phrase.contains("nft"), "les backends dont la durée n'est pas celle-là doivent être nommés : « {phrase} »");
            // Témoin inverse : une action hors vocabulaire obtient le repli, jamais une phrase rassurante.
            let repli = action_consequence("format_disk");
            assert!(repli.contains("hors vocabulaire") && !repli.contains("bannit"), "repli attendu : « {repli} »");
            assert!(action_kind_valid("format_disk").is_err());
        }

        // ------------------------------------------------------------------------------------------
        // ② Le vocabulaire offert par les surfaces est dérivé des sources web.
        // ------------------------------------------------------------------------------------------
        /// Les actions que la surface OFFRE : options du `<select id="pb-kind">` (formulaire playbook) et
        /// tableau `RB_ACTIONS` (étape `response` d'un runbook). Lues, pas recopiées.
        fn actions_offertes_par_la_surface() -> BTreeSet<String> {
            let mut out = BTreeSet::new();
            let html = std::fs::read_to_string(racine_web().join("index.html")).unwrap();
            let select = html.split("id=\"pb-kind\"").nth(1).expect("index.html : <select id=\"pb-kind\"> absent");
            let select = select.split("</select>").next().unwrap();
            for morceau in select.split("<option value=\"").skip(1) {
                out.insert(morceau.split('"').next().unwrap().to_string());
            }
            let js = std::fs::read_to_string(racine_web().join("runbooks.js")).unwrap();
            let ligne = js.lines().find(|l| l.trim_start().starts_with("const RB_ACTIONS")).expect("runbooks.js : RB_ACTIONS absent");
            for morceau in ligne.split('\'').skip(1).step_by(2) {
                out.insert(morceau.to_string());
            }
            out
        }

        #[test]
        fn chaque_action_offerte_par_la_surface_a_une_phrase_de_consequence() {
            let offertes = actions_offertes_par_la_surface();
            assert!(offertes.len() >= 3, "instrument : {} action(s) lue(s) dans les surfaces, la lecture est cassée", offertes.len());
            for kind in &offertes {
                assert!(action_kind_valid(kind).is_ok(), "la surface offre « {kind} », hors du vocabulaire fermé");
                let phrase = action_consequence(kind);
                assert!(!phrase.contains("hors vocabulaire"), "« {kind} » est offert sans phrase de conséquence");
                assert!(phrase.len() > 20, "phrase trop courte pour « {kind} » : « {phrase} »");
            }
        }

        // ------------------------------------------------------------------------------------------
        // ③ La liste servie porte la phrase et le mode ; le mode change le mot.
        // ------------------------------------------------------------------------------------------
        #[tokio::test]
        async fn la_liste_des_playbooks_porte_la_consequence_et_le_mode_courant() {
            let st = tenant_test_state("plume-admin", "plume-editor", "admins", None);
            { let c = st.db.lock(); seed_ssh_cve_playbook(&c); }
            let v = playbooks_list(State(st.clone()), Extension(tok_au("admin"))).await.0;
            let rows = v["playbooks"].as_array().expect("playbooks : tableau");
            assert!(!rows.is_empty(), "le seed regreSSHion doit être listé");
            for r in rows {
                let phrase = r["consequence"].as_str().unwrap_or("");
                assert!(phrase.contains("bannit l'IP source pendant"), "ligne sans phrase de conséquence : {r}");
                assert_eq!(r["enabled"], false, "le seed est livré OFF");
            }
            assert_eq!(v["mode"], "observe", "sans réglage, le mode est Observation");
            assert_eq!(v["ban_duration_s"], NETBAN_ACTION_TTL_S);
            // Mutation : le mode passe en actif, la liste le dit — la surface n'a pas à le deviner.
            { let c = st.db.lock(); c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap(); }
            let v2 = playbooks_list(State(st.clone()), Extension(tok_au("admin"))).await.0;
            assert_eq!(v2["mode"], "active");
        }

        // ------------------------------------------------------------------------------------------
        // ④ Garde dérivée : qui crée un producteur d'alertes doit dire où il arrive.
        // ------------------------------------------------------------------------------------------
        fn sources_rust() -> Vec<(PathBuf, String)> {
            let mut fichiers = Vec::new();
            crate::db_open::door_tests::rs_files(&racine_src(), &mut fichiers);
            fichiers.into_iter()
                .filter(|p| !p.components().any(|c| c.as_os_str() == "tests"))
                .map(|p| { let s = std::fs::read_to_string(&p).unwrap(); (p, s) })
                .collect()
        }

        /// INDEX des fonctions du crate : nom -> corps, construit UNE fois. Le corps va du `fn nom(` jusqu'à
        /// la prochaine déclaration `fn` d'indentation inférieure ou égale — suffisant pour y lire des
        /// littéraux SQL. Un nom défini PLUSIEURS fois (méthodes homonymes de `impl` différents : `new`,
        /// `execute`…) est rangé sous `ambigus` et n'est jamais suivi : suivre le mauvais corps fabriquerait
        /// un créateur qui n'existe pas.
        struct IndexDesFonctions { corps: BTreeMap<String, String>, ambigus: BTreeSet<String> }
        fn indexer(sources: &[(PathBuf, String)]) -> IndexDesFonctions {
            let mut corps: BTreeMap<String, String> = BTreeMap::new();
            let mut ambigus = BTreeSet::new();
            let est_decl = |t: &str| t.starts_with("fn ") || t.starts_with("pub(crate) fn ") || t.starts_with("pub(crate) async fn ") || t.starts_with("pub fn ") || t.starts_with("async fn ");
            for (_p, src) in sources {
                let lignes: Vec<&str> = src.lines().collect();
                for (i, l) in lignes.iter().enumerate() {
                    let t = l.trim_start();
                    if !est_decl(t) { continue; }
                    let apres = t.split("fn ").nth(1).unwrap_or("");
                    let nom: String = apres.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                    if nom.is_empty() || !apres[nom.len()..].starts_with(|c| c == '(' || c == '<') { continue; }
                    let indent = l.len() - t.len();
                    let mut body = String::new();
                    for suite in &lignes[i..] {
                        let ts = suite.trim_start();
                        let ind = suite.len() - ts.len();
                        if !body.is_empty() && est_decl(ts) && ind <= indent { break; }
                        body.push_str(suite); body.push('\n');
                    }
                    let plat = body.replace("\\\n", " ").replace('\n', " ");
                    if corps.insert(nom.clone(), plat).is_some() { ambigus.insert(nom); }
                }
            }
            for a in &ambigus { corps.remove(a); }
            IndexDesFonctions { corps, ambigus }
        }
        fn corps_de_fonction<'a>(index: &'a IndexDesFonctions, nom: &str) -> Option<&'a String> { index.corps.get(nom) }

        /// LE TICK QUI DISPATCHE LES ALERTES : la fermeture `catch_unwind` de `server.rs` qui contient
        /// `dispatch_notifications(`. Ce qui y tourne produit ce que l'onglet Alertes/Actions reçoit ; les
        /// autres boucles (connecteurs, destinations, rapports) lisent aussi des tables `enabled=1` mais
        /// produisent des ÉVÉNEMENTS ou des ENVOIS, pas des alertes — elles ne sont pas des producteurs.
        fn tick_des_alertes(sources: &[(PathBuf, String)]) -> String {
            let (_p, server) = sources.iter().find(|(p, _)| p.ends_with("server.rs")).expect("server.rs");
            let fin = server.find("dispatch_notifications(").expect("server.rs : dispatch_notifications( absent du tick");
            let debut = server[..fin].rfind("catch_unwind(").expect("server.rs : aucun catch_unwind avant dispatch_notifications");
            let apres = server[fin..].find("}));").map(|i| fin + i).unwrap_or(server.len());
            server[debut..apres].to_string()
        }

        /// Les boucles du tick des alertes : tout `absorber(<fn>(` du bloc.
        fn boucles_du_planificateur(sources: &[(PathBuf, String)]) -> BTreeSet<String> {
            let bloc = tick_des_alertes(sources);
            let mut out = BTreeSet::new();
            for morceau in bloc.split("absorber(").skip(1) {
                let nom: String = morceau.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                if morceau[nom.len()..].starts_with('(') && !nom.is_empty() { out.insert(nom); }
            }
            out
        }

        /// Les tables de producteurs : `FROM <table>` dont le littéral SQL porte `enabled=1`, lu dans le
        /// corps de chaque boucle.
        fn tables_de_producteurs(index: &IndexDesFonctions, boucles: &BTreeSet<String>) -> BTreeMap<String, BTreeSet<String>> {
            let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for b in boucles {
                let Some(plat) = corps_de_fonction(index, b) else { continue };
                for litteral in plat.split('"').skip(1).step_by(2) {
                    if !litteral.contains("enabled=1") { continue; }
                    for morceau in litteral.split("FROM ").skip(1) {
                        let table: String = morceau.trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                        if !table.is_empty() { out.entry(table).or_default().insert(b.clone()); }
                    }
                }
            }
            out
        }

        /// Les routes POST de `server.rs` : (chemin, handler).
        fn routes_post(sources: &[(PathBuf, String)]) -> Vec<(String, String)> {
            let (_p, server) = sources.iter().find(|(p, _)| p.ends_with("server.rs")).unwrap();
            let mut out = Vec::new();
            for l in server.lines() {
                let Some(reste) = l.split(".route(\"").nth(1) else { continue };
                let chemin = reste.split('"').next().unwrap().to_string();
                for morceau in reste.split("post(").skip(1) {
                    let h: String = morceau.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                    if !h.is_empty() { out.push((chemin.clone(), h)); }
                }
            }
            out
        }

        /// Un handler (ou ce qu'il appelle, jusqu'à `profondeur` niveaux) insère-t-il dans l'une des tables ?
        fn insere_dans(index: &IndexDesFonctions, nom: &str, tables: &BTreeSet<String>, profondeur: u8, vus: &mut BTreeSet<String>) -> Option<String> {
            if profondeur == 0 || !vus.insert(nom.to_string()) { return None; }
            let plat = corps_de_fonction(index, nom)?;
            for t in tables {
                if plat.contains(&format!("INSERT INTO {t}(")) { return Some(t.clone()); }
            }
            // Appels : `ident(` ; on ne descend que dans ce que l'index connaît sans ambiguïté.
            let mut appels = BTreeSet::new();
            let octets = plat.as_bytes();
            let mut i = 0;
            while i < octets.len() {
                if octets[i].is_ascii_alphabetic() || octets[i] == b'_' {
                    let d = i;
                    while i < octets.len() && (octets[i].is_ascii_alphanumeric() || octets[i] == b'_') { i += 1; }
                    if i < octets.len() && octets[i] == b'(' { appels.insert(plat[d..i].to_string()); }
                } else { i += 1; }
            }
            for a in appels {
                if index.ambigus.contains(&a) { continue; }
                if let Some(t) = insere_dans(index, &a, tables, profondeur - 1, vus) { return Some(t); }
            }
            None
        }

        /// Les modules web qui POSTent sur un chemin d'API (chemin sans `/api`, cité tel quel).
        fn modules_web_qui_postent(chemin_api: &str) -> Vec<(String, String)> {
            let chemin = chemin_api.strip_prefix("/api").unwrap_or(chemin_api);
            let cible = format!("'{chemin}'");
            let mut out = Vec::new();
            let mut entrees: Vec<_> = std::fs::read_dir(racine_web()).unwrap().filter_map(Result::ok).map(|e| e.path()).collect();
            entrees.sort();
            for p in entrees {
                if p.extension().and_then(|e| e.to_str()) != Some("js") { continue; }
                let src = std::fs::read_to_string(&p).unwrap();
                let poste = src.lines().any(|l| l.contains(&cible) && (l.contains("'POST'") || l.contains("contentSubmit(")));
                if poste { out.push((p.file_name().unwrap().to_string_lossy().to_string(), src)); }
            }
            out
        }

        /// Écarts CONNUS, avec leur raison. L'ensemble mesuré doit être EXACTEMENT celui-ci.
        // Aucun écart connu : les trois surfaces nomment leur destination (l'import Sigma depuis le commit qui ferme P11.1-e).
        const ECARTS_CONNUS: &[(&str, &str)] = &[];

        #[test]
        fn toute_surface_qui_cree_un_producteur_d_alertes_nomme_sa_destination() {
            let sources = sources_rust();
            let index = indexer(&sources);
            let boucles = boucles_du_planificateur(&sources);
            assert!(boucles.len() >= 4, "instrument : {} boucle(s) lue(s) dans le tick des alertes ({boucles:?}), la lecture est cassée", boucles.len());
            let tables = tables_de_producteurs(&index, &boucles);
            let noms_tables: BTreeSet<String> = tables.keys().cloned().collect();
            assert!(noms_tables.len() >= 3, "instrument : {} table(s) de producteurs dérivée(s) ({tables:?}), la lecture est cassée", noms_tables.len());
            assert!(noms_tables.contains("rule") && noms_tables.contains("playbook"), "les tables `rule` et `playbook` doivent être dérivées, pas supposées : {noms_tables:?}");
            assert!(!noms_tables.contains("connector"), "la table `connector` (boucle de collecte, hors du tick des alertes) ne doit pas être prise pour un producteur d'alertes : {noms_tables:?}");

            // Routes POST dont le handler (ou ce qu'il appelle) INSÈRE dans une table de producteurs.
            let mut routes_creatrices: BTreeMap<String, String> = BTreeMap::new();
            for (chemin, handler) in routes_post(&sources) {
                let mut vus = BTreeSet::new();
                if let Some(t) = insere_dans(&index, &handler, &noms_tables, 3, &mut vus) {
                    routes_creatrices.insert(chemin, t);
                }
            }
            assert!(routes_creatrices.len() >= 4, "instrument : {} route(s) créatrice(s) dérivée(s) ({routes_creatrices:?})", routes_creatrices.len());
            for attendu in ["/api/rules", "/api/playbooks", "/api/correlations", "/api/baselines"] {
                assert!(routes_creatrices.contains_key(attendu), "{attendu} doit être dérivée comme créatrice : {routes_creatrices:?}");
            }

            // Modules web qui POSTent sur ces routes : chacun nomme la destination par l'aide partagée.
            let mut sans_destination: BTreeSet<String> = BTreeSet::new();
            let mut surfaces: BTreeSet<String> = BTreeSet::new();
            for (chemin, _table) in &routes_creatrices {
                for (module, src) in modules_web_qui_postent(chemin) {
                    surfaces.insert(module.clone());
                    let importe = src.contains("from './producer_ui.js'");
                    let nomme = src.contains("announceCreated(") || src.contains("destinationNote(") || src.contains("destinationSentence(");
                    if !(importe && nomme) { sans_destination.insert(module); }
                }
            }
            assert!(surfaces.len() >= 3, "instrument : {} surface(s) web dérivée(s) ({surfaces:?}), la lecture est cassée", surfaces.len());
            let connus: BTreeSet<String> = ECARTS_CONNUS.iter().map(|(m, _)| m.to_string()).collect();
            let nouveaux: Vec<_> = sans_destination.difference(&connus).collect();
            assert!(nouveaux.is_empty(), "surface(s) qui créent un producteur d'alertes SANS nommer la destination : {nouveaux:?} (surfaces dérivées : {surfaces:?})");
            let corriges: Vec<_> = connus.difference(&sans_destination).collect();
            assert!(corriges.is_empty(), "écart(s) connu(s) désormais corrigé(s), à retirer de ECARTS_CONNUS : {corriges:?}");
        }

        // Validation de l'instrument : la recherche de corps et d'insertion voit bien une insertion directe
        // (playbook_create) et une insertion déléguée (sigma_import_bulk -> sigma_bulk_apply -> table rule).
        #[test]
        fn l_instrument_voit_une_insertion_directe_et_une_insertion_deleguee() {
            let sources = sources_rust();
            let index = indexer(&sources);
            let tables: BTreeSet<String> = ["rule", "playbook"].iter().map(|s| s.to_string()).collect();
            assert_eq!(insere_dans(&index, "playbook_create", &tables, 1, &mut BTreeSet::new()).as_deref(), Some("playbook"));
            // Déléguée : `sigma_import_bulk` n'insère pas lui-même, `sigma_bulk_apply` le fait pour lui.
            assert_eq!(insere_dans(&index, "sigma_import_bulk", &tables, 1, &mut BTreeSet::new()), None, "au niveau 1 l'insertion déléguée est invisible : c'est pourquoi l'instrument descend");
            assert_eq!(insere_dans(&index, "sigma_import_bulk", &tables, 3, &mut BTreeSet::new()).as_deref(), Some("rule"));
            assert_eq!(insere_dans(&index, "rule_test_adhoc", &tables, 3, &mut BTreeSet::new()), None, "un test à blanc n'insère rien : l'instrument ne doit pas le voir comme créateur");
            assert!(corps_de_fonction(&index, "fonction_qui_n_existe_pas").is_none());
            assert!(!index.ambigus.is_empty() && !index.corps.contains_key("new"), "les homonymes (`new`…) doivent être rangés hors de l'index suivi");
            // Le tick des alertes est bien celui qui dispatche, et il ne contient pas la boucle des connecteurs.
            let tick = tick_des_alertes(&sources);
            assert!(tick.contains("run_due_rules(") && tick.contains("run_playbooks(") && !tick.contains("run_due_connectors("), "bloc du tick mal borné : {tick}");
        }
    }
