// =====================================================================================
// `P10.32-v`, `P10.32-h` — CE QUE LE COMPILATEUR 0.2.6 NE LIT PAS EST REFUSÉ, ET CE QU'IL LIT EST SERVI, PAR LA ROUTE.
//
// Le compilateur (`guatx-core` 0.2.6) découpe en respectant les guillemets doubles, refuse un guillemet non fermé,
// un `OR`/`AND`/`NOT` nu et une parenthèse de groupement dans `search`, et refuse tout jeton qu'une étape ne lit pas.
// Ces témoins le tiennent CÔTÉ PLUME, par `POST /api/query` (routeur réel `router_serve`, lecteur `vwr`), sur des
// événements semés (`source=k4`, `source=k4p`) :
//   1. une barre dans une valeur entre guillemets rend les lignes de la VALEUR, même quand elle ressemble à une étape ;
//   2. `OR`, `AND`, `NOT` nus et un groupement sont refusés, statut et corps entiers ; `"OR"`, `or`, `in (…)` et une
//      valeur de champ à parenthèses restent servis ;
//   3. un second agrégat, un alias, un `BY` majuscule et un argument de tri en trop sont refusés en nommant le jeton ;
//      les formes lues rendent leurs lignes ;
//   4. `rex` lit un guillemet échappé et une barre dans son motif ;
//   5. PAGINATION AU CURSEUR : un `where` qui porte une barre entre guillemets, paginé au curseur, rend exactement les
//      lignes servies sans curseur, colonnes comprises, et le SQL compare la valeur tapée (`keyset_projection_augment`
//      découpe par le découpeur du compilateur) ; un guillemet non fermé est refusé avant toute page ;
//   6. une RÈGLE dont la requête porte une forme refusée est refusée à la création et à la modification (400) ; un
//      PANNEAU est ACCEPTÉ (création 200, modification 204) puis refusé à l'exécution (`/api/panels/{id}/data`, 400) :
//      acceptation silencieuse au temps auteur, épinglée telle quelle (aucun contrôle de compilation dans
//      `panel_create`/`panel_update`).
// Chaque témoin collecte ses écarts cas par cas et les nomme ensemble.
// =====================================================================================
mod k4_formes_non_lues_refusees_par_la_route {
    use super::*;

    /// Mot de passe de l'éditeur semé pour les routes de règle et de panneau (constante nommée).
    const K4_MOT_DE_PASSE_EDITEUR: &str = "editeurpw12345";

    const K4_REFUS_OR: &str = "search : opérateur non lu : « OR » (les termes de `search` sont toujours reliés par ET ; pour une alternative : `champ in (a, b)` ou `champ=~\"a|b\"` ; pour chercher le mot lui-même, mettez-le entre guillemets : \"OR\")";
    const K4_REFUS_AND: &str = "search : opérateur non lu : « AND » (les termes de `search` sont toujours reliés par ET ; la conjonction est implicite (`a b` = a ET b) : retirez `AND` ; pour chercher le mot lui-même, mettez-le entre guillemets : \"AND\")";
    const K4_REFUS_NOT: &str = "search : opérateur non lu : « NOT » (les termes de `search` sont toujours reliés par ET ; pour une négation : `champ!=valeur` ou `champ not in (a, b)` ; pour chercher le mot lui-même, mettez-le entre guillemets : \"NOT\")";
    const K4_REFUS_GROUPE: &str = "search : parenthèse de groupement non lue : « (host=h1) » (les termes de `search` sont toujours reliés par ET, sans groupement : retirez les parenthèses ; pour une alternative : `champ in (a, b)` ou `champ=~\"a|b\"` ; pour chercher ce texte tel quel, mettez-le entre guillemets : \"(host=h1)\")";
    const K4_REFUS_GROUPE_VALEUR: &str = "search : parenthèse de groupement non lue : « h2) » (les termes de `search` sont toujours reliés par ET, sans groupement : retirez les parenthèses ; pour une alternative : `champ in (a, b)` ou `champ=~\"a|b\"` ; pour chercher ce texte tel quel, mettez-le entre guillemets : \"h2)\")";
    const K4_REFUS_SECOND_AGREGAT: &str = "stats : jeton non lu : « dc(x) » (un seul agrégat est lu, « count » ; forme : `stats <agrégat> [by champ1,champ2]` — un second agrégat demande une seconde requête)";
    const K4_REFUS_ALIAS: &str = "stats : jeton non lu : « as n » (un alias n'est pas lu : la colonne de « count » s'appelle « count » ; pour la renommer : `| rename count AS <nom>`)";
    const K4_REFUS_BY_MAJUSCULE: &str = "stats : jeton non lu : « BY host » (le regroupement s'écrit `by` en minuscules, « BY » n'est pas lu ; forme : `stats <agrégat> [by champ1,champ2]`)";
    const K4_REFUS_SORT_DESC: &str = "sort : jeton non lu : « desc » (un seul champ de tri est lu ; forme : `sort champ` (ascendant) ou `sort -champ` (descendant))";
    const K4_REFUS_GUILLEMET: &str = "guillemet non fermé : le « \" » à l'octet 25 ouvre un texte qui ne se referme pas avant la fin de la requête ; fermez-le (`champ=\"valeur\"`), ou retirez-le";

    /// Messages semés sous `source=k4` (hôte, message, url, sac) : une barre dans une valeur, une valeur qui ressemble
    /// à une étape, le mot `OR`, un guillemet, une parenthèse.
    const K4_EVENEMENTS: &[(&str, &str, &str, &str)] = &[
        ("h1", "alpha | stats count", "/a", "{\"action\":\"deny\"}"),
        ("h2", "beta|gamma", "/b", "{\"action\":\"allow\"}"),
        ("h1", "x | stats count", "/a", "{}"),
        ("h2", "OR", "/b", "{}"),
        ("h1", "user=\"bob\" logged", "/a", "{}"),
        ("h2", "(paren) here", "/b", "{}"),
    ];
    /// Valeur comparée par la pagination au curseur (`source=k4p`) : elle ressemble à une projection.
    const K4_VALEUR_PAGINEE: &str = "p|table b";

    struct K4Banc {
        addr: std::net::SocketAddr,
        base: crate::tmp_possede::TmpDb,
        _st: AppState,
    }

    fn k4_editeur_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt:{K4_MOT_DE_PASSE_EDITEUR}")))
    }

    async fn k4_banc(tag: &str) -> K4Banc {
        let (st, base) = router_test_state(tag);
        {
            let w = open_db(base.as_str()).unwrap();
            w.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(K4_MOT_DE_PASSE_EDITEUR).unwrap()]).unwrap();
            let ts = now() - 60;
            for (i, (hote, message, url, sac)) in K4_EVENEMENTS.iter().enumerate() {
                w.execute(
                    "INSERT INTO event(ts,source,host,message,url,fields,dedup) VALUES(?1,'k4',?2,?3,?4,?5,?6)",
                    params![ts - i as i64, hote, message, url, sac, format!("k4-{i}")],
                )
                .unwrap();
            }
            for i in 0..5 {
                w.execute(
                    "INSERT INTO event(ts,source,host,message,dedup) VALUES(?1,'k4p','h1',?2,?3)",
                    params![ts - 100 - i, K4_VALEUR_PAGINEE, format!("k4p-{i}")],
                )
                .unwrap();
            }
            for i in 0..3 {
                w.execute(
                    "INSERT INTO event(ts,source,host,message,dedup) VALUES(?1,'k4p','h1','p',?2)",
                    params![ts - 200 - i, format!("k4p-autre-{i}")],
                )
                .unwrap();
            }
        }
        let addr = router_serve(st.clone()).await;
        K4Banc { addr, base, _st: st }
    }

    struct K4Servi {
        code: u16,
        texte: String,
        corps: Value,
    }
    impl K4Servi {
        fn colonnes(&self) -> Vec<String> {
            self.corps["columns"].as_array().map(|c| c.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default()
        }
        fn lignes(&self) -> Vec<Vec<Value>> {
            self.corps["rows"].as_array().map(|r| r.iter().map(|l| l.as_array().cloned().unwrap_or_default()).collect()).unwrap_or_default()
        }
        /// Les valeurs de la colonne `nom`, en texte (`null` pour une absence).
        fn valeurs(&self, nom: &str) -> Vec<String> {
            let Some(i) = self.colonnes().iter().position(|c| c == nom) else { return vec![format!("<colonne {nom} absente>")] };
            self.lignes().iter().map(|l| l.get(i).map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).unwrap_or_default()).collect()
        }
    }

    async fn k4_envoi(banc: &K4Banc, authz: &str, methode: &str, chemin: &str, corps: &str) -> K4Servi {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(banc.addr, methode, chemin, Some(authz), &entetes, corps).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let texte = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        let corps = serde_json::from_str(&texte).unwrap_or(Value::Null);
        K4Servi { code, texte, corps }
    }

    /// `POST /api/query` par le lecteur ; `curseur` : `None` sans curseur, `Some(c)` au curseur (page 2 = `c` reçu).
    async fn k4_requete(banc: &K4Banc, soql: &str, curseur: Option<&Value>) -> K4Servi {
        let maintenant = now();
        let mut corps = json!({ "soql": soql, "from": maintenant - 3600, "to": maintenant + 3600 });
        if let Some(c) = curseur {
            corps["keyset"] = json!(true);
            corps["limit"] = json!(2);
            if !c.is_null() {
                corps["cursor"] = c.clone();
            }
        }
        k4_envoi(banc, &viewer_authz(), "POST", "/api/query", &corps.to_string()).await
    }

    /// Refus attendu : 400, corps entier `{"error": phrase}` ; un écart est nommé dans `ecarts`.
    fn k4_refus(ecarts: &mut Vec<String>, quoi: &str, s: &K4Servi, phrase: &str) {
        if s.code != 400 || s.corps != json!({ "error": phrase }) {
            ecarts.push(format!("{quoi} : 400 {{error: phrase}} attendu, rendu {} {}", s.code, s.texte));
        }
    }

    fn k4_servi(ecarts: &mut Vec<String>, quoi: &str, s: &K4Servi, colonne: &str, attendu: &[&str]) {
        let mut rendu = s.valeurs(colonne);
        rendu.sort();
        let mut voulu: Vec<String> = attendu.iter().map(|v| v.to_string()).collect();
        voulu.sort();
        if s.code != 200 || rendu != voulu {
            ecarts.push(format!("{quoi} : 200 et {colonne} = {voulu:?} attendus, rendu {} {rendu:?} {}", s.code, s.texte));
        }
    }

    fn k4_conclure(ecarts: &[String]) {
        assert!(ecarts.is_empty(), "écarts : {ecarts:#?}");
    }

    #[tokio::test]
    async fn k4_c1_barre_dans_une_valeur_citee_rend_les_lignes_de_la_valeur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c1").await;
        let mut ecarts = Vec::new();
        let cas: &[(&str, &[&str])] = &[
            ("search source=k4 message=\"alpha | stats count\"", &["alpha | stats count"]),
            ("search source=k4 message=\"beta|gamma\"", &["beta|gamma"]),
            ("search source=k4 message=\"x | stats count\"", &["x | stats count"]),
        ];
        for (soql, attendu) in cas {
            let s = k4_requete(&banc, soql, None).await;
            k4_servi(&mut ecarts, soql, &s, "message", attendu);
        }
        let tous: Vec<&str> = K4_EVENEMENTS.iter().map(|e| e.1).collect();
        let s = k4_requete(&banc, "search source=k4 | where url=~\"/a|/b\"", None).await;
        k4_servi(&mut ecarts, "where url=~\"/a|/b\"", &s, "message", &tous);
        k4_conclure(&ecarts);
    }

    #[tokio::test]
    async fn k4_c2_operateurs_et_groupement_refuses_formes_lues_servies() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c2").await;
        let mut ecarts = Vec::new();
        let refus: &[(&str, &str)] = &[
            ("search source=k4 OR host=h1", K4_REFUS_OR),
            ("search source=k4 AND host=h1", K4_REFUS_AND),
            ("search source=k4 NOT host=h1", K4_REFUS_NOT),
            ("search source=k4 (host=h1)", K4_REFUS_GROUPE),
            ("search source=k4 host=(h1 h2)", K4_REFUS_GROUPE_VALEUR),
        ];
        for (soql, phrase) in refus {
            let s = k4_requete(&banc, soql, None).await;
            k4_refus(&mut ecarts, soql, &s, phrase);
        }
        let tous: Vec<&str> = K4_EVENEMENTS.iter().map(|e| e.1).collect();
        let servis: &[(&str, Vec<&str>)] = &[
            ("search source=k4 \"OR\"", vec!["OR"]),
            ("search source=k4 or", vec!["OR"]),
            ("search source=k4 host in (h1, h2)", tous.clone()),
            ("search source=k4 action=~(?i)^deny$", vec!["alpha | stats count"]),
        ];
        for (soql, attendu) in servis {
            let s = k4_requete(&banc, soql, None).await;
            k4_servi(&mut ecarts, soql, &s, "message", attendu);
        }
        k4_conclure(&ecarts);
    }

    #[tokio::test]
    async fn k4_c3_jetons_non_lus_refuses_formes_lues_servies() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c3").await;
        let mut ecarts = Vec::new();
        let refus: &[(&str, &str)] = &[
            ("search source=k4 | stats count dc(x) by host", K4_REFUS_SECOND_AGREGAT),
            ("search source=k4 | stats count as n", K4_REFUS_ALIAS),
            ("search source=k4 | stats count BY host", K4_REFUS_BY_MAJUSCULE),
            ("search source=k4 | sort ts desc", K4_REFUS_SORT_DESC),
        ];
        for (soql, phrase) in refus {
            let s = k4_requete(&banc, soql, None).await;
            k4_refus(&mut ecarts, soql, &s, phrase);
        }
        let s = k4_requete(&banc, "search source=k4 | stats count by host | rename count AS n", None).await;
        if s.code != 200 || s.colonnes() != ["host", "count", "n"] || s.lignes() != vec![vec![json!("h1"), json!(3), json!(3)], vec![json!("h2"), json!(3), json!(3)]] {
            ecarts.push(format!("stats count by host | rename count AS n : {} {}", s.code, s.texte));
        }
        let s = k4_requete(&banc, "search source=k4 | sort -ts", None).await;
        let attendu: Vec<String> = K4_EVENEMENTS.iter().map(|e| e.1.to_string()).collect();
        if s.code != 200 || s.valeurs("message") != attendu {
            ecarts.push(format!("sort -ts : ordre décroissant des instants attendu : {} {}", s.code, s.texte));
        }
        k4_conclure(&ecarts);
    }

    #[tokio::test]
    async fn k4_c4_rex_guillemet_echappe_et_barre_dans_le_motif() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c4").await;
        let mut ecarts = Vec::new();
        let s = k4_requete(&banc, "search source=k4 | rex message \"user=\\\"(?<u>[a-z]+)\" | where u=\"bob\" | table u", None).await;
        if s.code != 200 || s.colonnes() != ["u"] || s.valeurs("u") != ["bob"] {
            ecarts.push(format!("rex à guillemet échappé : {} {}", s.code, s.texte));
        }
        let s = k4_requete(&banc, "search source=k4 | rex message \"(?<w>alpha|beta)\" | table w", None).await;
        let mut extraits: Vec<String> = s.valeurs("w").into_iter().filter(|v| v != "null").collect();
        extraits.sort();
        if s.code != 200 || s.colonnes() != ["w"] || extraits != ["alpha", "beta"] || s.lignes().len() != K4_EVENEMENTS.len() {
            ecarts.push(format!("rex à barre dans le motif : {} {}", s.code, s.texte));
        }
        k4_conclure(&ecarts);
    }

    /// Parcourt toutes les pages au curseur ; rend (lignes, colonnes de chaque page, SQL compilé de la première page).
    async fn k4_parcours(banc: &K4Banc, soql: &str, ecarts: &mut Vec<String>) -> (Vec<Vec<Value>>, Vec<Vec<String>>, String) {
        let (mut lignes, mut colonnes, mut sql) = (Vec::new(), Vec::new(), String::new());
        let mut curseur = Value::Null;
        for page in 0..10 {
            let s = k4_requete(banc, soql, Some(&curseur)).await;
            if s.code != 200 {
                ecarts.push(format!("`{soql}` page {page} : {} {}", s.code, s.texte));
                break;
            }
            if page == 0 {
                sql = s.corps["compiled_sql"].as_str().unwrap_or("").to_string();
            }
            lignes.extend(s.lignes());
            colonnes.push(s.colonnes());
            curseur = s.corps["next_cursor"].clone();
            if curseur.is_null() {
                break;
            }
        }
        (lignes, colonnes, sql)
    }

    #[tokio::test]
    async fn k4_c5_curseur_sur_un_where_a_barre_citee_rend_les_lignes_sans_curseur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c5").await;
        let mut ecarts = Vec::new();
        // (requête, la page au curseur ajoute-t-elle la clé `id` aux colonnes servies sans curseur ?)
        for (soql, ajoute_id) in [
            ("search source=k4p | where message=\"p|table b\" | table ts,message", false),
            ("search source=k4p | where message=\"p|table b\"", true),
        ] {
            let sans = k4_requete(&banc, soql, None).await;
            let mut instants_sans: Vec<String> = sans.valeurs("ts");
            instants_sans.sort();
            if sans.code != 200 || instants_sans.len() != 5 || sans.valeurs("message").iter().any(|m| m != K4_VALEUR_PAGINEE) {
                ecarts.push(format!("`{soql}` sans curseur : 5 lignes de la valeur attendues : {} {}", sans.code, sans.texte));
            }
            let (lignes, colonnes, sql) = k4_parcours(&banc, soql, &mut ecarts).await;
            let ts_i = colonnes.first().and_then(|c| c.iter().position(|x| x == "ts")).unwrap_or(0);
            let mut instants: Vec<String> = lignes.iter().map(|l| l.get(ts_i).map(|v| v.to_string()).unwrap_or_default()).collect();
            instants.sort();
            if instants != instants_sans {
                ecarts.push(format!("`{soql}` au curseur : instants {instants:?}, sans curseur {instants_sans:?}"));
            }
            if colonnes.len() != 3 {
                ecarts.push(format!("`{soql}` : trois pages (2, 2, 1) attendues, rendu {}", colonnes.len()));
            }
            // La PLACE de `id` n'est pas jugée : le savoir du processus (champs calculés, lookups automatiques posés par
            // un autre test quand la suite tourne en un seul processus) ajoute ses colonnes après celles de l'événement,
            // donc après `id` au curseur. Ce qui est jugé : `id` présent une fois ou absent, et les autres colonnes
            // celles de la réponse sans curseur, dans le même ordre.
            let attendues = sans.colonnes();
            for (p, c) in colonnes.iter().enumerate() {
                let cles = c.iter().filter(|x| *x == "id").count();
                let hors_cle: Vec<String> = c.iter().filter(|x| *x != "id").cloned().collect();
                if cles != usize::from(ajoute_id) || hors_cle != attendues {
                    ecarts.push(format!("`{soql}` page {p} : colonnes {c:?}, attendues {attendues:?} et `id` {} fois", usize::from(ajoute_id)));
                }
            }
            if !sql.contains("= 'p|table b'") || sql.contains("ts,id'") {
                ecarts.push(format!("`{soql}` : le SQL au curseur doit comparer la valeur tapée : {sql}"));
            }
        }
        // Guillemet non fermé : refusé avant toute page, aucun curseur.
        let s = k4_requete(&banc, "search source=k4 message=\"unclosed", Some(&Value::Null)).await;
        k4_refus(&mut ecarts, "guillemet non fermé au curseur", &s, K4_REFUS_GUILLEMET);
        k4_conclure(&ecarts);
    }

    #[tokio::test]
    async fn k4_c6_regle_refusee_au_temps_auteur_panneau_accepte_puis_refuse_a_l_execution() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k4_banc("k4-c6").await;
        let editeur = k4_editeur_authz();
        let mut ecarts = Vec::new();
        // RÈGLE : création et modification refusées, la requête stockée ne bouge pas.
        let s = k4_envoi(&banc, &editeur, "POST", "/api/rules", &json!({ "name": "k4-or", "query": "search source=k4 OR host=h1", "is_soql": true }).to_string()).await;
        k4_refus(&mut ecarts, "règle créée avec OR", &s, &format!("requête invalide : {K4_REFUS_OR}"));
        let s = k4_envoi(&banc, &editeur, "POST", "/api/rules", &json!({ "name": "k4-lue", "query": "search source=k4", "is_soql": true }).to_string()).await;
        let regle = s.corps["id"].as_i64().unwrap_or_else(|| panic!("règle lue créée : {} {}", s.code, s.texte));
        let s = k4_envoi(&banc, &editeur, "POST", &format!("/api/rules/{regle}"), &json!({ "query": "search source=k4 | stats count as n" }).to_string()).await;
        k4_refus(&mut ecarts, "règle modifiée avec un alias", &s, &format!("requête invalide : {K4_REFUS_ALIAS}"));
        let conn = open_db(banc.base.as_str()).unwrap();
        let stockee: String = conn.query_row("SELECT query FROM rule WHERE id=?1", params![regle], |r| r.get(0)).unwrap();
        if stockee != "search source=k4" {
            ecarts.push(format!("règle refusée mais requête réécrite : {stockee}"));
        }
        let refusees: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='k4-or'", [], |r| r.get(0)).unwrap();
        if refusees != 0 {
            ecarts.push(format!("règle refusée mais écrite : {refusees}"));
        }
        // PANNEAU : accepté à la création puis refusé à l'exécution ; même chose à la modification.
        let s = k4_envoi(&banc, &editeur, "POST", "/api/dashboards", &json!({ "name": "k4" }).to_string()).await;
        let tableau = s.corps["id"].as_i64().unwrap_or_else(|| panic!("tableau : {} {}", s.code, s.texte));
        let m = now();
        let donnees = |id: i64| format!("/api/panels/{id}/data?from={}&to={}", m - 3600, m + 3600);
        let s = k4_envoi(&banc, &editeur, "POST", "/api/panels", &json!({ "dashboard_id": tableau, "query": "search source=k4 | stats count as n", "is_soql": true }).to_string()).await;
        let panneau = s.corps["id"].as_i64();
        if s.code != 200 || panneau.is_none() || s.corps.as_object().map(|o| o.len()) != Some(1) {
            ecarts.push(format!("panneau à alias : création acceptée (200 {{id}}) attendue, rendu {} {}", s.code, s.texte));
        }
        if let Some(id) = panneau {
            let s = k4_envoi(&banc, &editeur, "GET", &donnees(id), "").await;
            k4_refus(&mut ecarts, "données du panneau à alias", &s, K4_REFUS_ALIAS);
        }
        let s = k4_envoi(&banc, &editeur, "POST", "/api/panels", &json!({ "dashboard_id": tableau, "query": "search source=k4", "is_soql": true }).to_string()).await;
        let lu = s.corps["id"].as_i64().unwrap_or_else(|| panic!("panneau lu : {} {}", s.code, s.texte));
        let s = k4_envoi(&banc, &editeur, "POST", &format!("/api/panels/{lu}"), &json!({ "query": "search source=k4 OR host=h1" }).to_string()).await;
        if s.code != 204 || !s.texte.is_empty() {
            ecarts.push(format!("panneau modifié avec OR : 204 vide attendu, rendu {} {}", s.code, s.texte));
        }
        let stockee: String = conn.query_row("SELECT query FROM panel WHERE id=?1", params![lu], |r| r.get(0)).unwrap();
        if stockee != "search source=k4 OR host=h1" {
            ecarts.push(format!("panneau modifié : requête stockée {stockee}"));
        }
        let s = k4_envoi(&banc, &editeur, "GET", &donnees(lu), "").await;
        k4_refus(&mut ecarts, "données du panneau à OR", &s, K4_REFUS_OR);
        k4_conclure(&ecarts);
    }
}
