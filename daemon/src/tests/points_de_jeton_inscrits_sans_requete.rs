// =====================================================================================
// `P7.20-a` (correction après vérification) — LE POINT DE JETON D'UN CONNECTEUR DE SURCOUCHE EST INSCRIT TEL QUEL.
//
// Un connecteur écrit en surcouche `config.d` inscrit ses cibles de configuration
// (`cibles_d_egress_d_un_connecteur`, daemon/src/overlays_oac.rs). La base des pages (`url` d'un http_pull, base Graph
// `graph_host` d'un defender) est inscrite SUIVIE DE SES PARAMÈTRES : une page suivante `base?…` en relève. Le point
// de jeton OAuth2 (`auth.token_url` d'un http_pull, `login_host` d'un defender) est appelé tel quel et inscrit TEL
// QUEL : une URL tirée d'une réponse (`next`, `@odata.nextLink`) qui vise `<point de jeton>?…` n'en relève pas, elle
// est jugée de l'API, et une adresse privée y est refusée avant le réseau.
//
// Sonde du vérificateur : le point de jeton inscrit « suivi d'une requête » laissait tous les témoins verts, alors
// qu'une page suivante vers `<point de jeton privé>?x` aurait été admise comme configuration.
//
// Chaque témoin joue la vraie chaîne (chargement de la surcouche, passage de fond `run_due_connectors`, garde au point
// d'égress) dans un sous-processus où la garde tourne au défaut (aucun `PLUME_*`, fichier de configuration absent),
// le témoin d'égress armé. La page suivante vers la base (`base?p=2`) part : c'est le contrôle qui montre que la
// pagination suit, et que seul le point de jeton est refusé.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : BA1C_JETON_HTTP
// (`auth.token_url` d'un http_pull inscrit suivi d'une requête) ; BA1C_JETON_DEFENDER (`login_host` d'un defender
// inscrit suivi d'une requête).
// =====================================================================================
mod points_de_jeton_inscrits_sans_requete {
    use super::*;

    const MODULE: &str = "tests::points_de_jeton_inscrits_sans_requete::";
    const ENFANT: &str = "P720A_ENFANT_POINT_DE_JETON";
    const FIN: &str = "P720A-POINT-DE-JETON-A-JOUE";
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";

    // http_pull : la base des pages et le point de jeton sur le MÊME hôte privé (seul le chemin les distingue).
    const HTTP_BASE: &str = "http://10.0.0.91/api";
    const HTTP_PAGE_2: &str = "http://10.0.0.91/api?p=2";
    const HTTP_JETON: &str = "http://10.0.0.91/jeton";
    const HTTP_JETON_SUIVI: &str = "http://10.0.0.91/jeton?q=1";

    // defender : `login_host` et `graph_host` sur le MÊME hôte privé.
    const DEF_HOTE: &str = "10.0.0.93";
    const DEF_JETON: &str = "https://10.0.0.93/t-1/oauth2/v2.0/token";
    const DEF_JETON_SUIVI: &str = "https://10.0.0.93/t-1/oauth2/v2.0/token?x=1";
    const DEF_GRAPH: &str = "https://10.0.0.93/v1.0/security/alerts_v2";
    const DEF_GRAPH_PAGE_2: &str = "https://10.0.0.93/v1.0/security/alerts_v2?$skiptoken=2";

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> String {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        assert_eq!(trouves.len(), 1, "une seule ligne {cle} : {stdout}");
        trouves[0].to_string()
    }

    /// Prépare la ré-exécution de `test` : arguments, environnement `PLUME_*` vidé, `PLUME_CONFIG` vers un fichier
    /// absent. L'appelant pose ensuite `ENFANT`.
    fn preparer_l_enfant(commande: &mut std::process::Command, test: &str) {
        commande.args(["--exact", "--nocapture", "--test-threads=1"]).arg(format!("{MODULE}{test}"));
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
        commande.env("PLUME_CONFIG", "/nonexistent");
    }

    /// Lance l'enfant ; rend sa sortie standard, après avoir vérifié qu'il a joué jusqu'au bout.
    fn sortie_de_l_enfant(mut commande: std::process::Command) -> String {
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        stdout
    }

    /// Les appels vus par le témoin d'égress ; la première page Graph (filtre daté) est nommée `GRAPH-PAGE-1`.
    fn vus_texte() -> String {
        crate::ledger::temoin_de_l_egress::vus()
            .into_iter()
            .map(|(m, u)| if u.starts_with(&format!("{DEF_GRAPH}?$filter=")) { format!("{m} GRAPH-PAGE-1") } else { format!("{m} {u}") })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Le témoin répond : chaque page renvoie vers la suivante, la dernière vers le point de jeton suivi d'une requête.
    fn repondre(methode: &str, url: &str) -> Result<HttpResp, String> {
        let corps = if url == HTTP_BASE {
            format!(r#"{{"items":[],"next":"{HTTP_PAGE_2}"}}"#)
        } else if url == HTTP_PAGE_2 {
            format!(r#"{{"items":[],"next":"{HTTP_JETON_SUIVI}"}}"#)
        } else if methode == "POST" && url == DEF_JETON {
            r#"{"access_token":"p720a-jeton"}"#.to_string()
        } else if url == DEF_GRAPH_PAGE_2 {
            format!(r#"{{"value":[],"@odata.nextLink":"{DEF_JETON_SUIVI}"}}"#)
        } else if url.starts_with(&format!("{DEF_GRAPH}?$filter=")) {
            format!(r#"{{"value":[],"@odata.nextLink":"{DEF_GRAPH_PAGE_2}"}}"#)
        } else {
            r#"{"items":[],"value":[]}"#.to_string()
        };
        Ok(crate::ledger::temoin_de_l_egress::reponse(200, &[], &corps))
    }

    /// Dans l'enfant : pose la surcouche `connecteur` (objet JSON entier), la rend due, joue un passage de fond le
    /// témoin armé, imprime les appels vus et l'état du connecteur.
    fn jouer_le_passage(etiquette: &str, connecteur: Value) {
        let (st, base) = router_test_state(&format!("p720a-pj-{etiquette}"));
        let dossier = crate::tmp_possede::TmpPossede::neuf(&format!("p720a-pj-{etiquette}"));
        let d = dossier.join("connectors");
        std::fs::create_dir_all(&d).expect("dossier de surcouche");
        std::fs::write(d.join("k.json"), connecteur.to_string()).expect("surcouche");
        let id: i64 = {
            let c = open_db(&base).expect("base");
            println!("P720A-PJ-POSES:{}", crate::overlays_oac::load_overlay_connectors(&c, &d).charges);
            c.query_row("SELECT id FROM connector WHERE name='p720a-pj'", [], |r| r.get(0)).expect("id lisible")
        };
        st.db.lock().execute("UPDATE connector SET last_run=0 WHERE id=?1", params![id]).expect("connecteur dû");
        let arme = crate::ledger::temoin_de_l_egress::armer(repondre);
        let _ = run_due_connectors(&st.db, &base.to_string());
        println!("P720A-PJ-VUS:{}", vus_texte());
        drop(arme);
        let etat: String = st.db.lock()
            .query_row("SELECT COALESCE(last_error,'') FROM connector WHERE id=?1", params![id], |r| r.get(0))
            .expect("état lisible");
        println!("P720A-PJ-ETAT:{etat}");
        println!("{FIN}");
    }

    /// Les cibles d'un connecteur, (champ, URL, requête admise).
    fn cibles_texte(ctype: &str, config: &Value) -> Vec<(String, String, bool)> {
        crate::overlays_oac::cibles_d_egress_d_un_connecteur(ctype, config)
            .into_iter()
            .map(|(champ, c)| (champ.to_string(), c.url, c.requete_admise))
            .collect()
    }

    fn config_http() -> Value {
        json!({ "url": HTTP_BASE, "records_path": "items", "field_map": { "message": "msg" },
                "pagination": { "kind": "link_header", "next_path": "next" },
                "auth": { "kind": "none", "token_url": HTTP_JETON } })
    }

    fn config_defender() -> Value {
        json!({ "azure_tenant": "t-1", "client_id": "c-1", "login_host": DEF_HOTE, "graph_host": DEF_HOTE })
    }

    /// http_pull de surcouche : la base, puis sa page suivante, partent ; la page suivante tirée de la réponse vers
    /// `auth.token_url?q=1` est refusée avant le réseau, comme une cible de l'API.
    #[test]
    fn p720a_une_page_suivante_vers_le_point_de_jeton_d_un_http_pull_est_refusee() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            jouer_le_passage("http", json!({ "name": "p720a-pj", "type": "http_pull", "enabled": true, "config": config_http() }));
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_une_page_suivante_vers_le_point_de_jeton_d_un_http_pull_est_refusee");
        commande.env(ENFANT, "1");
        let s = sortie_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-PJ-POSES"), "1", "contrôle : la surcouche est posée");
        assert_eq!(lu(&s, "P720A-PJ-VUS"), format!("GET {HTTP_BASE} | GET {HTTP_PAGE_2}"),
            "la base et sa page suivante partent ; la page vers le point de jeton suivi d'une requête est refusée avant le réseau");
        assert_eq!(lu(&s, "P720A-PJ-ETAT"), format!("SSRF: adresse privée refusée (10.0.0.91) — {LEVIERS}"),
            "le refus est celui d'une adresse privée de l'API");
        assert_eq!(
            cibles_texte("http_pull", &config_http()),
            vec![("url".to_string(), HTTP_BASE.to_string(), true), ("auth.token_url".to_string(), HTTP_JETON.to_string(), false)],
            "base des pages suivie de ses paramètres, point de jeton tel quel"
        );
    }

    /// defender de surcouche : le jeton, la première page Graph et sa suivante partent ; un `@odata.nextLink` vers
    /// `<point de jeton>?x=1` est refusé avant le réseau, comme une cible de l'API.
    #[test]
    fn p720a_un_lien_suivant_vers_le_point_de_jeton_d_un_defender_est_refuse() {
        if std::env::var(ENFANT).is_ok() {
            println!();
            jouer_le_passage("defender", json!({ "name": "p720a-pj", "type": "defender", "enabled": true, "config": config_defender() }));
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        preparer_l_enfant(&mut commande, "p720a_un_lien_suivant_vers_le_point_de_jeton_d_un_defender_est_refuse");
        commande.env(ENFANT, "1");
        let s = sortie_de_l_enfant(commande);
        assert_eq!(lu(&s, "P720A-PJ-POSES"), "1", "contrôle : la surcouche est posée");
        assert_eq!(lu(&s, "P720A-PJ-VUS"), format!("POST {DEF_JETON} | GET GRAPH-PAGE-1 | GET {DEF_GRAPH_PAGE_2}"),
            "le jeton et les pages Graph partent ; le lien suivant vers le point de jeton suivi d'une requête est refusé avant le réseau");
        assert_eq!(lu(&s, "P720A-PJ-ETAT"), format!("SSRF: adresse privée refusée ({DEF_HOTE}) — {LEVIERS}"),
            "le refus est celui d'une adresse privée de l'API");
        assert_eq!(
            cibles_texte("defender", &config_defender()),
            vec![("login_host".to_string(), DEF_JETON.to_string(), false), ("graph_host".to_string(), DEF_GRAPH.to_string(), true)],
            "point de jeton tel quel, base Graph suivie de ses paramètres"
        );
    }
}
