// P11.1-a — LE LIEN DE RECHERCHE D'UNE ALERTE REPRODUIT SON COMPTE.
//
// LE DÉFAUT MESURÉ. Le lien d'une alerte était construit par le navigateur : la tête `search …` de la
// requête (tout ce qui précède le premier `|`), sur la fenêtre de la règle ÉLARGIE d'une marge de 5 %
// à chaque bord. Deux conséquences, sur TOUTES les règles livrées et par construction :
//   • la marge rendait le lien PLUS LARGE que le compte, pour toute règle ;
//   • pour une règle de corrélation (`… | stats dc(x) by k | where … | stats count`), la tête seule
//     rend les ÉVÉNEMENTS, là où la règle a compté des GROUPES ;
//   • pour une règle en SQL brut, le lien était `search <titre avant ':'>` — un autre ensemble ;
//   • pour une règle `metric … | stats max(value)`, la tête `metric …` nue est prise pour du SQL brut
//     par la barre Explore (`isSoql` ne reconnaît que `search` ou un `|`).
//
// LE CRITÈRE. Le lien est DÉRIVÉ par le démon (`lien_de_recherche_de_regle`), une fois, depuis la
// requête telle qu'elle a compté et la fenêtre de la règle. Pour chaque règle livrée, sur une base de
// fixture où plusieurs règles TIRENT :
//   • si le dernier étage est `… | stats count` : le lien rend EXACTEMENT `valeur` lignes ;
//   • si le dernier étage est un autre `stats` scalaire : le lien, rejoué AVEC cet étage, rend `valeur` ;
//   • sinon (requête entière, ou SQL brut) : le lien rend `valeur` en dernière colonne de première ligne.
// Le témoin exige un plancher de règles qui tirent (un critère vérifié sur des zéros ne prouve rien),
// plante pour chaque règle `stats count` qui tire un événement apparié JUSTE HORS FENÊTRE de chaque côté
// (une marge rétablie, même de 30 s, le ferait reprendre par le lien et rougit en nommant la règle),
// et porte un témoin NÉGATIF : l'ancienne construction, rejouée sur la même base, ne satisfait PAS le critère.
mod lien_de_recherche_des_alertes {
    use super::*;
    use std::collections::BTreeMap;

    /// Les formes de lien que la dérivation produit, par forme de requête — pour publier la liste.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FormeDeLien {
        /// `search … | stats count` : le lien rend les événements comptés.
        Evenements,
        /// `… | stats f by k | where … | stats count` : le lien rend les GROUPES comptés.
        Groupes,
        /// `metric … | stats max(value)` et consorts : le lien rend les lignes agrégées.
        LignesAgregees,
        /// Aucun `stats` scalaire terminal : le lien est la requête entière (résultat tel quel).
        ResultatEntier,
        /// SQL brut : le lien est le SQL, fenêtre substituée (porte « SQL brut = admin » inchangée).
        SqlBrut,
    }

    fn forme_du_lien(query: &str, is_soql: bool) -> FormeDeLien {
        if !is_soql {
            return FormeDeLien::SqlBrut;
        }
        let etages = guatx_core::soql::soql_split_pipes(query);
        let Some(dernier) = etages.last() else { return FormeDeLien::ResultatEntier };
        let scalaire = lien_de_recherche_de_regle(query, true, 60, 60).query != query.trim();
        if !scalaire {
            return FormeDeLien::ResultatEntier;
        }
        let compte = dernier.split_whitespace().last().map(|t| t.eq_ignore_ascii_case("count") || t.eq_ignore_ascii_case("count()")).unwrap_or(false);
        if !compte {
            return FormeDeLien::LignesAgregees;
        }
        if etages.len() > 2 { FormeDeLien::Groupes } else { FormeDeLien::Evenements }
    }

    struct RegleLivree {
        name: String,
        query: String,
        is_soql: bool,
        window_s: i64,
    }

    fn regles_livrees(conn: &Connection) -> Vec<RegleLivree> {
        let mut st = conn.prepare("SELECT name,query,is_soql,window_s FROM rule ORDER BY id").expect("table rule lisible");
        st.query_map([], |r| Ok(RegleLivree { name: r.get(0)?, query: r.get(1)?, is_soql: r.get::<_, i64>(2)? != 0, window_s: r.get(3)? }))
            .expect("règles lisibles")
            .map(|r| r.expect("ligne de règle"))
            .collect()
    }

    /// Dernière colonne de la première ligne, comme `eval_value_budget` — mais sur un résultat déjà lu.
    fn scalaire(v: &Value) -> Option<f64> {
        let cell = v.get("rows")?.as_array()?.first()?.as_array()?.last()?.clone();
        cell.as_f64().or_else(|| cell.as_i64().map(|n| n as f64))
    }

    fn nb_lignes(v: &Value) -> usize {
        v.get("rows").and_then(|r| r.as_array()).map(|r| r.len()).unwrap_or(0)
    }

    /// Une base au schéma réel, peuplée pour que des règles de CHAQUE forme tirent. Les instants sont
    /// relatifs à `t0` et tenus loin des bords de fenêtre (la plus courte fenêtre livrée est de 300 s).
    fn fixture_ou_des_regles_tirent(t0: i64) -> (crate::tmp_possede::TmpDb, Arc<Mutex<Connection>>) {
        let (chemin, db) = base_au_schema_reel("lien-de-recherche");
        {
            let conn = db.lock();
            seed_tenant_content(&conn);
            load_overlays_dir(&conn, &config_d_du_depot());
            let ev = |ts: i64, source: &str, category: &str, sev: i64, src_ip: Option<&str>, fields: &str, msg: &str| {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,src_ip,message,fields) VALUES(?1,?2,?3,?4,'h1',?5,?6,?7)",
                    params![ts, source, category, sev, src_ip, msg, fields],
                )
                .expect("événement de fixture");
            };
            // k8s : 7 événements de sévérité >= 3 dans la fenêtre (le compte de l'alerte rapportée), 3 en
            // dessous du seuil, 2 HORS fenêtre de 900 s — ceux que l'ancien lien élargi ne doit pas reprendre.
            for i in 0..7 { ev(t0 - 60 - i, "k8s", "k8s", 3, None, "{}", "pod CrashLoopBackOff"); }
            for i in 0..3 { ev(t0 - 70 - i, "k8s", "k8s", 1, None, "{}", "pod scheduled"); }
            for i in 0..2 { ev(t0 - 2000 - i, "k8s", "k8s", 4, None, "{}", "pod OOMKilled"); }
            // ufw : deux sources qui balayent 20 ports, une qui en touche 3 -> la corrélation compte 2 GROUPES
            // sur 43 événements.
            for p in 0..20 { ev(t0 - 100 - p, "ufw", "network", 2, Some("203.0.113.1"), &format!("{{\"dport\":{}}}", 1000 + p), "BLOCK"); }
            for p in 0..20 { ev(t0 - 130 - p, "ufw", "network", 2, Some("203.0.113.2"), &format!("{{\"dport\":{}}}", 2000 + p), "BLOCK"); }
            for p in 0..3 { ev(t0 - 160 - p, "ufw", "network", 2, Some("203.0.113.3"), &format!("{{\"dport\":{}}}", 3000 + p), "BLOCK"); }
            // mail : deux détections antivirus.
            for i in 0..2 { ev(t0 - 80 - i, "mail", "malware", 4, None, "{}", "virus detected"); }
            // auth : 120 échecs depuis une même adresse -> pic global (seuil 100) ET brute-force par IP.
            for i in 0..120 { ev(t0 - 200 - (i % 50), "sshd", "auth", 3, Some("198.51.100.7"), "{\"action\":\"failure\",\"user\":\"root\"}", "Failed password"); }
            // web : une adresse qui touche 35 chemins distincts en 404.
            for i in 0..35 { ev(t0 - 90 - (i % 20), "web", "web", 1, Some("198.51.100.9"), &format!("{{\"status\":404,\"path\":\"/p{i}\"}}"), "GET 404"); }
            // métriques : une valeur qui franchit le seuil dans la fenêtre, une plus ancienne sous le seuil.
            let m = |ts: i64, name: &str, v: f64| {
                conn.execute("INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'',?3)", params![ts, name, v]).expect("métrique de fixture");
            };
            m(t0 - 60, "velero_failed", 1.0);
            m(t0 - 120, "velero_failed", 0.0);
            m(t0 - 60, "kube_deploy_unavailable", 2.0);
            m(t0 - 60, "cpu_pct", 95.0);
            m(t0 - 60, "disk_root_pct", 95.0);
            m(t0 - 60, "mem_slab_mb", 3000.0);
        }
        (chemin, db)
    }

    /// PLANTE, juste hors fenêtre, une COPIE d'un événement que le lien a apparié : même source, catégorie,
    /// sévérité, hôte, adresse, message et champs — seul `ts` change. C'est l'événement qui satisfait le
    /// prédicat de la règle par construction (il en vient), donc le seul que la fenêtre seule doit écarter.
    /// Rend l'id inséré, pour pouvoir le retirer ensuite.
    fn planter_une_copie_au_bord(conn: &Connection, resultat: &Value, ts: i64) -> Option<i64> {
        let cols: Vec<String> = resultat.get("columns")?.as_array()?.iter().map(|c| c.as_str().unwrap_or("").to_string()).collect();
        let ligne = resultat.get("rows")?.as_array()?.first()?.as_array()?.clone();
        let cell = |nom: &str| cols.iter().position(|c| c == nom).and_then(|i| ligne.get(i)).cloned().unwrap_or(Value::Null);
        let texte = |v: Value| v.as_str().map(|x| x.to_string());
        let source = texte(cell("source"))?;
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,host,src_ip,message,fields) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                ts, source, texte(cell("category")), cell("severity").as_i64().unwrap_or(0), texte(cell("host")),
                texte(cell("src_ip")), texte(cell("message")), texte(cell("fields")),
            ],
        )
        .ok()?;
        Some(conn.last_insert_rowid())
    }

    /// Rejoue un lien GXQL sur sa fenêtre, par la porte GXQL nue (celle de `/api/query`, sans masque ni env).
    fn executer_lien(db_path: &str, lien: &LienDeRecherche) -> Result<Value, String> {
        let sql = if lien.is_soql { soql_to_sql_x(&lien.query, lien.from, lien.to, None)? } else { lien.query.clone() };
        run_query_ex(db_path, &sql, query_budget_interactive_ms(), None)
    }

    #[test]
    fn le_lien_de_chaque_regle_livree_reproduit_la_valeur_de_la_regle() {
        let t0 = now();
        let (chemin, db) = fixture_ou_des_regles_tirent(t0);
        let regles = regles_livrees(&db.lock());
        assert!(regles.len() >= 40, "corpus de règles livrées trop petit ({}) : le semis ou les overlays n'ont pas chargé", regles.len());
        let mut qui_tirent = 0usize;
        let mut groupes_qui_tirent = 0usize;
        let mut non_evaluables: Vec<String> = Vec::new();
        let mut ecarts: Vec<String> = Vec::new();
        let mut par_forme: BTreeMap<String, usize> = BTreeMap::new();
        let mut plantees_au_bord = 0usize;
        for r in &regles {
            let forme = forme_du_lien(&r.query, r.is_soql);
            *par_forme.entry(format!("{forme:?}")).or_insert(0) += 1;
            // `ts` = l'instant de l'évaluation : le même `now()` que `rule_sql` va lire, à la seconde près ;
            // la fixture tient ses événements loin des bords de fenêtre pour qu'une seconde ne change rien.
            let ts = now();
            let sql = match rule_sql(&r.query, r.is_soql, r.window_s) {
                Ok(s) => s,
                Err(e) => { non_evaluables.push(format!("{} : compilation refusée ({e})", r.name)); continue; }
            };
            let Some(valeur) = eval_value_budget(chemin.as_str(), &sql, query_budget_interactive_ms()) else {
                non_evaluables.push(format!("{} : évaluation en échec", r.name));
                continue;
            };
            if valeur > 0.0 { qui_tirent += 1; if forme == FormeDeLien::Groupes { groupes_qui_tirent += 1; } }
            let lien = lien_de_recherche_de_regle(&r.query, r.is_soql, r.window_s, ts);
            let res = match executer_lien(chemin.as_str(), &lien) {
                Ok(v) => v,
                Err(e) => { ecarts.push(format!("{} : le lien « {} » ne s'exécute pas ({e})", r.name, lien.query)); continue; }
            };
            let reproduit = match forme {
                FormeDeLien::Evenements | FormeDeLien::Groupes => nb_lignes(&res) as f64,
                FormeDeLien::LignesAgregees => {
                    let etage = guatx_core::soql::soql_split_pipes(&r.query).last().cloned().unwrap_or_default();
                    let relu = soql_to_sql_x(&format!("{} | {etage}", lien.query), lien.from, lien.to, None)
                        .and_then(|s| run_query_ex(chemin.as_str(), &s, query_budget_interactive_ms(), None));
                    match relu { Ok(v) => scalaire(&v).unwrap_or(f64::NAN), Err(e) => { ecarts.push(format!("{} : lien + étage ne s'exécute pas ({e})", r.name)); continue; } }
                }
                FormeDeLien::ResultatEntier | FormeDeLien::SqlBrut => scalaire(&res).unwrap_or(f64::NAN),
            };
            if (reproduit - valeur).abs() > 1e-9 {
                ecarts.push(format!("{} [{forme:?}] : la règle vaut {valeur}, le lien « {} » rend {reproduit}", r.name, lien.query));
                continue;
            }
            // LE BORD DE LA FENÊTRE — là où le défaut de départ vivait. Pour chaque règle `stats count` qui
            // tire, une copie d'un événement apparié est plantée à `ts - window_s - 1` et une à `ts + 1` :
            // juste hors fenêtre, des deux côtés. La règle ne les voit pas (la copie de gauche est avant
            // `from` ; celle de droite est insérée APRÈS son évaluation, comme un événement arrivé après le
            // tir), et le lien ne doit pas les voir non plus. Une marge rétablie — ne serait-ce que de 30 s,
            // d'un côté ou de l'autre — fait reprendre une copie au lien, et l'écart nomme la règle. Les
            // copies sont retirées ensuite : la règle suivante est mesurée sur la fixture d'origine.
            if forme == FormeDeLien::Evenements && valeur > 0.0 && r.window_s > 0 {
                let conn = db.lock();
                let gauche = planter_une_copie_au_bord(&conn, &res, ts - r.window_s - 1);
                let droite = planter_une_copie_au_bord(&conn, &res, ts + 1);
                drop(conn);
                let (Some(g), Some(d)) = (gauche, droite) else {
                    ecarts.push(format!("{} : impossible de planter une copie d'événement au bord (colonnes du lien : {:?})", r.name, res.get("columns")));
                    continue;
                };
                plantees_au_bord += 1;
                let relu = executer_lien(chemin.as_str(), &lien).map(|v| nb_lignes(&v) as f64);
                let revalue = rule_sql(&r.query, r.is_soql, r.window_s).ok().and_then(|sql| eval_value_budget(chemin.as_str(), &sql, query_budget_interactive_ms()));
                db.lock().execute("DELETE FROM event WHERE id IN (?1, ?2)", params![g, d]).expect("retrait des copies au bord");
                match relu {
                    Ok(n) if (n - valeur).abs() < 1e-9 => {}
                    Ok(n) => ecarts.push(format!("{} : avec une copie d'événement juste hors fenêtre de chaque côté, la règle vaut {valeur} et le lien « {} » sur [{}, {}] rend {n} — le lien déborde de la fenêtre", r.name, lien.query, lien.from, lien.to)),
                    Err(e) => ecarts.push(format!("{} : le lien ne se rejoue pas avec les copies au bord ({e})", r.name)),
                }
                // La copie de gauche est hors fenêtre pour la règle aussi : sa valeur ne bouge pas. La copie
                // de droite, elle, est vue par la règle si on la ré-évalue (sa fenêtre n'a pas de borne haute :
                // en production un tel événement n'existe pas encore au moment du tir) -> +1 toléré, pas plus.
                if let Some(v2) = revalue {
                    if (v2 - valeur).abs() > 1e-9 && (v2 - valeur - 1.0).abs() > 1e-9 {
                        ecarts.push(format!("{} : la règle vaut {valeur} puis {v2} avec les copies au bord — la copie de gauche n'est pas hors fenêtre, la fixture est fausse", r.name));
                    }
                }
            }
        }
        eprintln!("[P11.1-a] {} règles livrées ; formes : {par_forme:?} ; {qui_tirent} tirent sur la fixture (dont {groupes_qui_tirent} de corrélation) ; {plantees_au_bord} règles éprouvées au bord de la fenêtre ; non évaluables ici : {}", regles.len(), non_evaluables.len());
        for n in &non_evaluables { eprintln!("[P11.1-a]   non évaluable : {n}"); }
        assert!(qui_tirent >= 8, "seulement {qui_tirent} règle(s) tirent sur la fixture : le critère serait vérifié sur des zéros");
        assert!(groupes_qui_tirent >= 2, "seulement {groupes_qui_tirent} règle(s) de corrélation tirent : la forme « groupes » n'est pas éprouvée");
        assert!(plantees_au_bord >= 3, "seulement {plantees_au_bord} règle(s) éprouvée(s) avec un événement juste hors fenêtre : une marge rétablie passerait inaperçue");
        assert!(non_evaluables.len() * 4 <= regles.len(), "trop de règles non évaluables sur la fixture ({}/{}) : {non_evaluables:?}", non_evaluables.len(), regles.len());
        assert!(ecarts.is_empty(), "{} lien(s) qui ne reproduisent pas la valeur de leur règle :\n  {}", ecarts.len(), ecarts.join("\n  "));
    }

    /// TÉMOIN NÉGATIF — l'ancienne construction (tête `search …` seule, fenêtre élargie de 5 % à chaque bord,
    /// minimum 30 s), rejouée sur la même fixture, NE reproduit PAS le compte : sur les corrélations elle rend
    /// des événements là où la règle a compté des groupes ; et sur la règle de l'alerte rapportée, la marge
    /// reprend des événements hors fenêtre dès qu'il en existe au bord.
    #[test]
    fn l_ancienne_construction_tete_seule_et_marge_ne_reproduisait_pas_le_compte() {
        let t0 = now();
        let (chemin, db) = fixture_ou_des_regles_tirent(t0);
        // Deux événements k8s posés DANS la marge de 5 % (45 s pour 900 s) que l'ancien lien ajoutait au bord
        // gauche : hors fenêtre pour la règle, dedans pour l'ancien lien.
        {
            let conn = db.lock();
            for i in 0..2 {
                conn.execute("INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'k8s','k8s',3,'h1','pod au bord','{}')", params![t0 - 900 - 10 - i]).unwrap();
            }
        }
        let regles = regles_livrees(&db.lock());
        let mut correlations_trahies = 0usize;
        let mut marge_trahit_k8s = false;
        for r in regles.iter().filter(|r| r.is_soql) {
            let ts = now();
            let Ok(sql) = rule_sql(&r.query, true, r.window_s) else { continue };
            let Some(valeur) = eval_value_budget(chemin.as_str(), &sql, query_budget_interactive_ms()) else { continue };
            if valeur <= 0.0 { continue; }
            let tete = guatx_core::soql::soql_split_pipes(&r.query).first().cloned().unwrap_or_default();
            let marge = ((r.window_s as f64) * 0.05).round().clamp(30.0, 600.0) as i64;
            let Ok(sql_ancien) = soql_to_sql_x(&tete, ts - r.window_s - marge, ts + marge, None) else { continue };
            let Ok(res) = run_query_ex(chemin.as_str(), &sql_ancien, query_budget_interactive_ms(), None) else { continue };
            let ancien = nb_lignes(&res) as f64;
            if forme_du_lien(&r.query, true) == FormeDeLien::Groupes && ancien != valeur { correlations_trahies += 1; }
            if r.name.starts_with("k8s: problème pod") && ancien > valeur { marge_trahit_k8s = true; }
        }
        assert!(correlations_trahies >= 2, "l'ancienne tête seule reproduit le compte des corrélations ({correlations_trahies} trahie(s)) : le témoin négatif ne discrimine pas");
        assert!(marge_trahit_k8s, "la marge de 5 % n'a repris aucun événement hors fenêtre sur la règle k8s : le témoin négatif ne discrimine pas");
    }

    /// LA DÉRIVATION ELLE-MÊME, sur ses formes : ce qu'elle retire, ce qu'elle garde, ce qu'elle substitue.
    #[test]
    fn la_derivation_du_lien_retire_le_seul_etage_scalaire_terminal() {
        let l = lien_de_recherche_de_regle("search source=k8s severity>=3 | stats count", true, 900, 10_000);
        assert_eq!((l.query.as_str(), l.is_soql, l.from, l.to), ("search source=k8s severity>=3", true, 9_100, 10_000));
        // corrélation : les groupes retenus, pas la tête.
        let l = lien_de_recherche_de_regle("search source=ufw | stats dc(dport) by src_ip | where dc > 15 | stats count", true, 600, 10_000);
        assert_eq!(l.query, "search source=ufw | stats dc(dport) by src_ip | where dc > 15");
        // agrégat scalaire autre que count : retiré aussi (les lignes agrégées).
        assert_eq!(lien_de_recherche_de_regle("metric velero_failed | stats max(value)", true, 3600, 10_000).query, "metric velero_failed");
        // `stats … by …` terminal n'est pas scalaire : la requête entière est le lien.
        assert_eq!(lien_de_recherche_de_regle("search source=web | stats count by src_ip", true, 600, 10_000).query, "search source=web | stats count by src_ip");
        // une requête sans pipe est son propre lien.
        assert_eq!(lien_de_recherche_de_regle("search source=web", true, 600, 10_000).query, "search source=web");
        // SQL brut : fenêtre substituée, porte admin inchangée (is_soql=false).
        let l = lien_de_recherche_de_regle("SELECT value FROM metric WHERE name='cpu_pct' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1", false, 600, 10_000);
        assert_eq!(l.query, "SELECT value FROM metric WHERE name='cpu_pct' AND ts>=9400 ORDER BY ts DESC LIMIT 1");
        assert!(!l.is_soql);
        // fenêtre nulle = pas de borne basse.
        assert_eq!(lien_de_recherche_de_regle("search x | stats count", true, 0, 10_000).from, 0);
    }
}
