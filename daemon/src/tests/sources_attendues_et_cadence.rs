    // ================================================================================================
    // P11.3-a / P11.3-b — L'INVENTAIRE DES SOURCES ET LA FRAÎCHEUR.
    //
    // CE QUI A ÉTÉ MESURÉ AVANT DE CORRIGER.
    //   (a) Le verdict « inattendu » venait d'une liste ÉNUMÉRÉE (`KNOWN_EXTRA_SOURCES`, 17 noms) accolée
    //       aux identifiants de capteurs. Six des sept sources signalées « inattendu » par l'analyste sont
    //       ÉMISES par un collecteur livré sous `collectors/` avec son timer sous `systemd/` : un défaut de
    //       DÉRIVATION, pas un manque de bouton. La septième (`derive-deploiement`) n'est émise par aucun
    //       fichier de ce dépôt : c'est un signal LÉGITIME, et le marquage est la bonne issue.
    //   (b) Le bouton « attendu » existait, mais gaté `S.isAdmin` côté web et admin-only côté RBAC : un
    //       éditeur n'avait aucune issue. Et poser un LIBELLÉ sur une source inattendue créait une ligne
    //       `source_settings` dont `expected` valait le DÉFAUT DE COLONNE (1) : acquittement silencieux,
    //       sans l'audit de sévérité 3.
    //   (c) « dégradé / en retard » était fabriqué côté web à partir d'alertes actives OU d'un âge > 4× un
    //       intervalle `expected_s` = 86400 / n_24h — une MOYENNE OBSERVÉE, pas une cadence attendue. Le
    //       démon, lui, ne rendait que frais / calme / muet et n'avait aucune notion de cadence déclarée.
    //
    // CE QUI EST TENU ICI.
    //   1. `SOURCES_LIVREES` est le MIROIR des fichiers livrés (extracteur validé dans les deux sens).
    //   2. Les six sources du constat sont attendues par construction ; `derive-deploiement` ne l'est pas.
    //   3. Le marquage est editor+, persistant, réversible, et rendu avec son auteur ; un libellé
    //      n'acquitte plus rien en silence.
    //   4. La cadence déclarée dérive de `COLLECTORS` ; le statut en dérive ; une source périodique sans
    //      cadence déclarée n'est JAMAIS « en retard » ; une continue l'est au même seuil que le capteur
    //      est « muet » dans Intégrations ; l'inventaire et la fraîcheur rendent le MÊME mot.
    // ================================================================================================

    /// Racine du dépôt (la surface balayée dépasse `daemon/`).
    fn sac_racine() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// Retire les lignes dont le premier caractère non blanc ouvre un commentaire (`#` ou `//`), et — pour
    /// le Rust — tout ITEM annoté `#[cfg(test)]` en colonne 0 (on saute jusqu'à l'accolade fermante
    /// appariée de l'item qui suit : `fn`, `mod`, `impl`…). Une fixture de test n'est pas de la collecte.
    fn sac_depouiller(txt: &str, rust: bool) -> String {
        let mut out = String::with_capacity(txt.len());
        let mut lignes = txt.lines().peekable();
        while let Some(l) = lignes.next() {
            let s = l.trim_start();
            if rust && l.starts_with("#[cfg(test)]") {
                // sauter l'item : trouver la première `{` puis son `}` apparié.
                let mut prof: i32 = 0;
                let mut ouvert = false;
                let mut corps = String::new();
                for l2 in lignes.by_ref() {
                    corps.push_str(l2);
                    corps.push('\n');
                    for c in l2.chars() {
                        if c == '{' { prof += 1; ouvert = true; }
                        if c == '}' { prof -= 1; }
                    }
                    if ouvert && prof <= 0 { break; }
                    // item sans corps (`#[cfg(test)] use …;`) : une ligne terminée par `;` avant toute `{`.
                    if !ouvert && l2.trim_end().ends_with(';') { break; }
                }
                continue;
            }
            if s.starts_with('#') || (rust && s.starts_with("//")) { continue; }
            out.push_str(l);
            out.push('\n');
        }
        out
    }

    const SAC_NOM: &str = r"[A-Za-z][A-Za-z0-9_.-]*";

    /// Les POSITIONS DE PRODUCTEUR reconnues, par famille de fichier. Chaque motif capture le nom de source.
    fn sac_motifs_shell() -> Vec<regex::Regex> {
        vec![
            // S1 : objet JSON `"source":"X"` (guillemets éventuellement échappés : awk / printf).
            regex::Regex::new(&format!(r#"\\?"source\\?"\s*:\s*\\?"({SAC_NOM})\\?""#)).unwrap(),
            // S1b : clé nue de `jq` (`source: "X"`), non précédée d'un guillemet ni d'un `$`.
            regex::Regex::new(&format!(r#"(?:^|[^\w"$\\])source:\s*"({SAC_NOM})""#)).unwrap(),
            // S2 : premier argument LITTÉRAL d'une aide de lib.sh qui émet sous un nom de source.
            regex::Regex::new(&format!(r"(?m)(?:^|[;&|(]|\$\()\s*(?:heartbeat|plume_unavailable|plume_disabled|plume_lecture_echouee|plume_lecture_partielle|plume_report_availability)\s+({SAC_NOM})\b")).unwrap(),
        ]
    }
    fn sac_motifs_rust(struct_source: bool) -> Vec<regex::Regex> {
        let mut v = vec![
            // R1 : `INSERT [OR IGNORE] INTO event(...) VALUES(?1,'X'` — la source est la 2e colonne.
            regex::Regex::new(&format!(r"INSERT(?: OR IGNORE)? INTO event\s*\([^)]*\)\s*\\?\s*VALUES\s*\(\s*\?1\s*,\s*'({SAC_NOM})'")).unwrap(),
            // R3 : `audit_source_change(conn, "X"`.
            regex::Regex::new(&format!(r#"audit_source_change\(\s*&?\w+\s*,\s*"({SAC_NOM})""#)).unwrap(),
            // R4 : `"source": "X"` (json!).
            regex::Regex::new(&format!(r#""source"\s*:\s*"({SAC_NOM})""#)).unwrap(),
        ];
        if struct_source {
            // R2 : champ de structure `source: "X".into()` / `.to_string()` — réservé au démon et à l'agent,
            // où ce champ est celui d'une LIGNE d'événement (ailleurs, un champ `source` peut nommer autre chose).
            v.push(regex::Regex::new(&format!(r#"(?:^|[^\w"])source\s*:\s*"({SAC_NOM})"\s*(?:\.into\(\)|\.to_string\(\))"#)).unwrap());
        }
        v
    }
    /// Descripteurs de sondes : `sources: &["a", "b"]` et `SOURCES_JOURNAL: &[&str] = &[...]` (sondes.rs).
    fn sac_noms_de_liste(txt: &str, tete: &regex::Regex) -> Vec<String> {
        let nom = regex::Regex::new(&format!(r#""({SAC_NOM})""#)).unwrap();
        tete.captures_iter(txt)
            .flat_map(|c| nom.captures_iter(c.get(1).unwrap().as_str()).map(|m| m[1].to_string()).collect::<Vec<_>>())
            .collect()
    }

    /// Fichiers d'une famille (glob simple sur extension, récursif pour le Rust), chemins RELATIFS à la racine.
    fn sac_fichiers(racine: &std::path::Path, sous: &str, ext: &str, recursif: bool) -> Vec<String> {
        fn marcher(d: &std::path::Path, ext: &str, recursif: bool, out: &mut Vec<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(d) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if recursif && p.file_name().map(|n| n != "target").unwrap_or(true) { marcher(&p, ext, recursif, out); }
                } else if p.extension().map(|x| x == ext).unwrap_or(false) {
                    out.push(p);
                }
            }
        }
        let mut v = Vec::new();
        marcher(&racine.join(sous), ext, recursif, &mut v);
        let mut rel: Vec<String> = v.iter().map(|p| p.strip_prefix(racine).unwrap().to_string_lossy().replace('\\', "/")).collect();
        rel.sort();
        rel
    }

    /// LA SURFACE : (répertoire, extension, récursif, rust, champ `source:` de structure reconnu, plancher).
    const SAC_SURFACE: &[(&str, &str, bool, bool, bool, usize)] = &[
        ("collectors", "sh", false, false, false, 30),
        ("collectors", "py", false, false, false, 1),
        ("daemon/src", "rs", true, true, true, 8),
        ("agent/src", "rs", true, true, true, 1),
        ("collector-mail/src", "rs", true, true, false, 2),
        ("collector-syslog/src", "rs", true, true, false, 0),
    ];

    /// L'EXTRACTION : source -> ensemble des fichiers (relatifs) qui la PRODUISENT, + le compte par famille.
    fn sac_extraire(racine: &std::path::Path) -> (std::collections::BTreeMap<String, std::collections::BTreeSet<String>>, Vec<(&'static str, usize)>) {
        let shell = sac_motifs_shell();
        let liste_sources = regex::Regex::new(r"sources:\s*&\[([^\]]*)\]").unwrap();
        let liste_journal = regex::Regex::new(r"SOURCES_JOURNAL:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]").unwrap();
        let mut out: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = Default::default();
        let mut comptes = Vec::new();
        for (sous, ext, recursif, rust, struct_source, _) in SAC_SURFACE {
            let mut n = 0usize;
            let rs = sac_motifs_rust(*struct_source);
            for rel in sac_fichiers(racine, sous, ext, *recursif) {
                // les répertoires de tests du démon ne sont pas de la collecte.
                if rel.contains("/tests/") || rel.ends_with("/tests.rs") { continue; }
                let Ok(txt) = std::fs::read_to_string(racine.join(&rel)) else { continue };
                let corps = sac_depouiller(&txt, *rust);
                let mut noms: Vec<String> = Vec::new();
                if *rust {
                    for re in &rs { noms.extend(re.captures_iter(&corps).map(|c| c[1].to_string())); }
                    noms.extend(sac_noms_de_liste(&corps, &liste_sources));
                    noms.extend(sac_noms_de_liste(&corps, &liste_journal));
                } else {
                    for re in &shell { noms.extend(re.captures_iter(&corps).map(|c| c[1].to_string())); }
                }
                for nom in noms {
                    n += 1;
                    out.entry(nom).or_default().insert(rel.clone());
                }
            }
            comptes.push((*sous, n));
        }
        (out, comptes)
    }

    /// L'INSTRUMENT SE VALIDE AVANT DE JUGER : formes qu'il DOIT reconnaître, formes qu'il NE DOIT PAS compter.
    #[test]
    fn sac_extracteur_reconnait_les_producteurs_et_ignore_le_reste() {
        let shell = sac_motifs_shell();
        let cap = |res: &[regex::Regex], txt: &str| -> Vec<String> {
            let corps = sac_depouiller(txt, false);
            res.iter().flat_map(|re| re.captures_iter(&corps).map(|c| c[1].to_string()).collect::<Vec<_>>()).collect()
        };
        // POSITIFS shell : JSON échappé (awk/printf), JSON nu (python), clé nue jq, aide de lib.sh.
        assert_eq!(cap(&shell, r#"ev="{\"ts\":$ts,\"source\":\"origin-drop\",\"category\":\"firewall\"}""#), vec!["origin-drop"]);
        assert_eq!(cap(&shell, r#"events.append({"ts": ts, "source": "minio-audit", "category": "data"})"#), vec!["minio-audit"]);
        assert_eq!(cap(&shell, "jq -c '{ ts:$ts, source:\"cloudflare-http\", category:\"web\" }'"), vec!["cloudflare-http"]);
        assert_eq!(cap(&shell, "command -v nft >/dev/null 2>&1 || plume_unavailable firewall missing-dependency \"nft absent\""), vec!["firewall"]);
        assert_eq!(cap(&shell, "spool_write \"x.json\" \"$(emit_event \"$(heartbeat journal 'journal santé' '{\"alive\":1}')\")\" nl"), vec!["journal"]);
        // NÉGATIFS shell : un commentaire, une variable (`$1`), une clé LUE (`.source` de jq), un `source=` de prose.
        assert!(cap(&shell, "# -> events source=cloudflare-http, category=web").is_empty(), "un commentaire n'émet rien");
        assert!(cap(&shell, r#"events="{\"ts\":$ts,\"source\":\"$1\",\"category\":\"ban\"}""#).is_empty(), "une variable n'est pas un littéral");
        assert!(cap(&shell, "(.action // \"\") as $a | (.source // \"\") as $s |").is_empty(), "une clé lue n'est pas un producteur");
        assert!(cap(&shell, "  # PAS de heartbeat sous source=portprobe : un battement sans src_ip").is_empty());
        assert!(cap(&shell, "cf_source: $s,").is_empty(), "`cf_source:` n'est pas `source:`");
        // POSITIFS rust : INSERT multi-ligne, champ de structure, audit_source_change, json!, descripteur de sonde.
        let rs = sac_motifs_rust(true);
        let capr = |txt: &str| -> Vec<String> {
            let corps = sac_depouiller(txt, true);
            let mut v: Vec<String> = rs.iter().flat_map(|re| re.captures_iter(&corps).map(|c| c[1].to_string()).collect::<Vec<_>>()).collect();
            v.extend(sac_noms_de_liste(&corps, &regex::Regex::new(r"sources:\s*&\[([^\]]*)\]").unwrap()));
            v
        };
        assert_eq!(capr("\"INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \\\n         VALUES(?1,'plume-authz','authz',3,?2,'plume-daemon',?3,'daemon')\","), vec!["plume-authz"]);
        assert_eq!(capr("    let ev = Event { ts, host, source: \"agent\".to_string(), category: \"health\".to_string() };"), vec!["agent"]);
        assert_eq!(capr("audit_source_change(conn, \"plume-config\", ledger_kind, detail, sev, msg, fields)"), vec!["plume-config"]);
        assert_eq!(capr("let evs = json!({ \"source\": \"defender\", \"ts\": ev.ts });"), vec!["defender"]);
        assert_eq!(capr("(\"audit\", \"auditd (exec/privesc)\", 120, Sonde::EventFlux { sources: &[\"auditd\"] }, false),"), vec!["auditd"]);
        // NÉGATIFS rust : un item `#[cfg(test)]` en colonne 0 (fn puis mod), un commentaire, un `cf_source:`.
        let fixture = "#[cfg(test)]\nfn aide() -> i64 {\n    let e = Event { source: \"fixture-fn\".into() };\n    0\n}\nfn prod() { let e = Event { source: \"vrai\".into() }; }\n#[cfg(test)]\nmod tests {\n    fn t() { let e = Event { source: \"fixture-mod\".into() }; }\n}\n";
        assert_eq!(capr(fixture), vec!["vrai"], "les items #[cfg(test)] (fn ET mod) sont retirés, la production reste");
        assert!(capr("// source: \"commentaire\".into()").is_empty());
        assert!(capr("cf_source: \"x\".into(),").is_empty());
        // sans reconnaissance du champ de structure (collecteurs Rust), `source: \"X\".into()` ne compte pas.
        let sans = sac_motifs_rust(false);
        assert!(sans.iter().all(|re| !re.is_match("source: \"html-anchor\".into()")), "hors démon/agent, un champ `source` de structure n'est pas un producteur");
    }

    /// LA GARDE : `SOURCES_LIVREES` est le miroir des fichiers livrés, dans les DEUX sens, et chaque famille
    /// de la surface mord encore (plancher).
    #[test]
    fn sources_livrees_est_le_miroir_des_fichiers_livres() {
        let racine = sac_racine();
        let (derivees, comptes) = sac_extraire(&racine);
        // (C) anti-dégénérescence : chaque famille ramène au moins son plancher (relevé sur l'arbre).
        for (sous, _, _, _, _, plancher) in SAC_SURFACE {
            let n = comptes.iter().find(|(s, _)| s == sous).map(|(_, n)| *n).unwrap_or(0);
            assert!(n >= *plancher, "famille `{sous}` : {n} extraction(s), plancher {plancher} — cette famille a cessé d'être vue ; corriger l'extracteur avant de conclure.");
        }
        // (A) aucune entrée fantôme : le fichier cité est unique dans la surface, et il PRODUIT la source.
        for (source, cite) in crate::handlers::sources::SOURCES_LIVREES {
            let producteurs = derivees.get(*source).cloned().unwrap_or_default();
            let cites: Vec<&String> = producteurs.iter().filter(|rel| rel.as_str() == *cite || rel.ends_with(&format!("/{cite}"))).collect();
            assert!(!cites.is_empty(),
                "source livrée `{source}` : le fichier cité `{cite}` ne la PRODUIT pas (producteurs dérivés : {producteurs:?}). Si le collecteur a été retiré, retirer l'entrée — sinon le flag « inattendu » s'éteindrait sur une source que plus rien n'émet.");
            assert_eq!(cites.len(), 1, "source livrée `{source}` : la citation `{cite}` désigne plusieurs fichiers {cites:?} — l'allonger.");
        }
        // (B) aucune dérive silencieuse : tout ce que l'extracteur ramène est dans la table.
        let manquantes: Vec<String> = derivees.iter()
            .filter(|(s, _)| !crate::handlers::sources::SOURCES_LIVREES.iter().any(|(t, _)| t == s))
            .map(|(s, f)| format!("{s} (émise par {f:?})"))
            .collect();
        assert!(manquantes.is_empty(),
            "source(s) émise(s) par un fichier LIVRÉ mais absente(s) de `SOURCES_LIVREES` : {manquantes:?}. Les y ajouter avec le fichier qui les émet — sinon l'inventaire les signalera « inattendu » à tort, le défaut même que P11.3-a ferme.");
        // une source listée UNE fois.
        let mut noms: Vec<&str> = crate::handlers::sources::SOURCES_LIVREES.iter().map(|(s, _)| *s).collect();
        noms.sort();
        let avant = noms.len();
        noms.dedup();
        assert_eq!(avant, noms.len(), "une source apparaît deux fois dans SOURCES_LIVREES");
    }

    /// LE CONSTAT, MESURÉ : six des sept sources « inattendu » sont livrées par ce dépôt (défaut de
    /// dérivation) ; la septième ne l'est pas (signal légitime). Et les dix feeds qu'une liste manuelle
    /// avait dû rattraper restent attendus — par dérivation, plus par énumération.
    #[test]
    fn les_six_sources_livrees_du_constat_sont_attendues_et_la_septieme_reste_un_signal() {
        let conn = test_db();
        for s in ["cloudflare-http", "engagement-adapter", "nft", "origin-drop", "portprobe", "kube-rbac"] {
            let r = raison_attendue_par_construction(&conn, s);
            assert!(matches!(r, Some(RaisonAttendue::Livree { .. })), "`{s}` est émise par un collecteur livré : {r:?}");
        }
        assert_eq!(raison_attendue_par_construction(&conn, "derive-deploiement"), None,
            "`derive-deploiement` n'est émise par aucun fichier de ce dépôt : le signal est légitime, l'issue est le marquage");
        for s in ["minio-audit", "vault-audit", "cloudflare", "conntrack", "mail", "containerd", "minio", "k8s", "dataacl", "agent", "sshd", "auditd", "plume-config", "plume-auth"] {
            assert!(source_attendue_par_construction(&conn, s), "`{s}` doit rester attendue par construction");
        }
        // `vault-audit` n'est livrée par aucun collecteur : elle est attendue parce que le PRODUIT l'agrège.
        assert_eq!(raison_attendue_par_construction(&conn, "vault-audit"), Some(RaisonAttendue::Agregee));
        // un identifiant de capteur sans source homonyme (`k8s-log-health`) reste attendu via la sonde.
        assert!(matches!(raison_attendue_par_construction(&conn, "k8s-log-health"), Some(RaisonAttendue::Sonde { .. })));
        for s in ["totally-new-thing", "attacker-c2", "unknown-src"] {
            assert!(!source_attendue_par_construction(&conn, s), "`{s}` (vraiment inconnue) DOIT rester un signal");
        }
        // DÉRIVATION 4 — un connecteur configuré déclare sa source ; un TAXII (indicateurs) n'en déclare aucune.
        conn.execute("INSERT INTO connector(id,type,name,enabled,config_json) VALUES(7,'http_pull','x',1,'{\"source\":\"okta\"}')", []).unwrap();
        conn.execute("INSERT INTO connector(id,type,name,enabled,config_json) VALUES(8,'http_pull','y',1,'{}')", []).unwrap();
        conn.execute("INSERT INTO connector(id,type,name,enabled,config_json) VALUES(9,'taxii2','z',1,'{\"source\":\"ioc-feed\"}')", []).unwrap();
        assert_eq!(raison_attendue_par_construction(&conn, "okta"), Some(RaisonAttendue::Connecteur { id: 7 }));
        assert_eq!(raison_attendue_par_construction(&conn, "http:8"), Some(RaisonAttendue::Connecteur { id: 8 }), "sans `source` déclarée, le repli de l'ingestion `http:<id>`");
        assert_eq!(raison_attendue_par_construction(&conn, "ioc-feed"), None, "un connecteur TAXII n'émet pas d'événement");
        // le registre d'exclusions rend la même dérivation (sans la partie base).
        let sans_base = sources_attendues_sans_base();
        assert!(sans_base.iter().any(|s| s == "portprobe") && sans_base.iter().any(|s| s == "vault-audit") && !sans_base.iter().any(|s| s == "okta"));
    }

    fn sac_au(role: &str, nom: &str) -> AuthUser {
        AuthUser { name: nom.into(), role: role.into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
    }
    async fn sac_put(st: &AppState, au: AuthUser, body: Value) -> StatusCode {
        source_settings_put(State(st.clone()), Extension(au), Json(body)).await.into_response().status()
    }
    fn sac_ligne(st: &AppState, source: &str) -> Option<(bool, String, Option<String>)> {
        let c = st.db.lock();
        c.query_row("SELECT expected, COALESCE(updated_by,''), label FROM source_settings WHERE scope='global' AND source=?1", params![source],
            |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?))).ok()
    }

    /// LE MARQUAGE : editor+ (le viewer est refusé par le path-guard ET par le handler), persistant,
    /// réversible dans les deux sens, audité (sévérité 3 quand il acquitte un signal), et la ligne créée
    /// par un libellé naît avec le verdict de construction — plus d'acquittement silencieux.
    #[tokio::test]
    async fn marquage_attendue_editor_persistant_reversible_et_sans_acquittement_silencieux() {
        // path-guard : mutation editor+ ; lecture viewer+ ; viewer refusé en écriture.
        assert!(rbac_gate("editor", "/api/sources/settings", true).is_ok(), "un éditeur marque une source");
        assert!(rbac_gate("admin", "/api/sources/settings", true).is_ok());
        assert!(rbac_gate("viewer", "/api/sources/settings", true).is_err(), "un viewer ne marque rien");
        assert!(rbac_gate("viewer", "/api/sources/settings", false).is_ok(), "la liste brute se lit (rien de secret)");
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // handler : le viewer est refusé même si le path-guard était contourné.
        assert_eq!(sac_put(&st, sac_au("viewer", "vic"), json!({"source":"derive-deploiement","action":"set_expected","value":true})).await, StatusCode::FORBIDDEN);
        assert!(sac_ligne(&st, "derive-deploiement").is_none(), "rien n'est persisté sur un refus");
        // (b) un LIBELLÉ posé par un éditeur sur une source inattendue n'acquitte PAS le signal.
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"derive-deploiement","action":"set_label","value":"dérive de déploiement"})).await, StatusCode::OK);
        let l = sac_ligne(&st, "derive-deploiement").expect("ligne créée par le libellé");
        assert!(!l.0, "la ligne naît avec le verdict de construction (inattendue), pas avec le défaut de colonne");
        assert_eq!(l.2.as_deref(), Some("dérive de déploiement"));
        // ... alors que sur une source LIVRÉE, la ligne naît attendue.
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"portprobe","action":"set_note","value":"sondes de ports"})).await, StatusCode::OK);
        assert!(sac_ligne(&st, "portprobe").unwrap().0, "source livrée : la ligne naît attendue");
        // (a) l'acquittement : persistant, avec son auteur, audité en sévérité 3 (un signal est étouffé).
        let avant: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND severity=3", [], |r| r.get(0)).unwrap();
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"derive-deploiement","action":"set_expected","value":true})).await, StatusCode::OK);
        let l = sac_ligne(&st, "derive-deploiement").unwrap();
        assert!(l.0 && l.1 == "eve", "marquée attendue par eve : {l:?}");
        let apres: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND severity=3", [], |r| r.get(0)).unwrap();
        assert_eq!(apres, avant + 1, "acquitter un signal est audité en sévérité 3");
        // réversible : rétablir le signal (sévérité 2, pas 3), puis `clear` = retour au verdict de construction.
        assert_eq!(sac_put(&st, sac_au("admin", "root"), json!({"source":"derive-deploiement","action":"set_expected","value":false})).await, StatusCode::OK);
        let l = sac_ligne(&st, "derive-deploiement").unwrap();
        assert!(!l.0 && l.1 == "root", "marquée inattendue par root : {l:?}");
        let apres2: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-config' AND severity=3", [], |r| r.get(0)).unwrap();
        assert_eq!(apres2, apres, "rétablir un signal n'est pas un étouffement");
        // l'autre sens : marquer INATTENDUE une source livrée (l'éditeur veut voir le signal) — persistant aussi.
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"portprobe","action":"set_expected","value":false})).await, StatusCode::OK);
        assert!(!sac_ligne(&st, "portprobe").unwrap().0);
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"portprobe","action":"clear"})).await, StatusCode::OK);
        assert!(sac_ligne(&st, "portprobe").is_none(), "clear : la source reprend le verdict de construction");
        // enum fermé.
        assert_eq!(sac_put(&st, sac_au("editor", "eve"), json!({"source":"x","action":"drop_table"})).await, StatusCode::BAD_REQUEST);
    }

    /// L'INVENTAIRE rend le verdict AVEC sa raison (construction) ou son marquage (qui / quand), et le MÊME
    /// statut que la fraîcheur — sur le vrai chemin (`/api/sources`, base sur disque, rollup matérialisé).
    #[tokio::test]
    async fn inventaire_rend_la_raison_le_marquage_et_le_statut_partage() {
        let (_tmp, p) = imp_base_disque("inv-p11");
        {
            let w = open_db(&p).unwrap();
            imp_flux(&w, "web", "web", 10, 4); // pipeline frais ; web = continu déclaré (1800 s)
            imp_flux(&w, "portprobe", "firewall", 2 * 3600, 5); // livrée, aucune cadence déclarée, calme depuis 2 h
            imp_flux(&w, "derive-deploiement", "config", 3000, 3); // inconnue
            imp_flux(&w, "auditd", "exec", 1200, 4); // continu déclaré 120 s : 20 min de silence = en retard
            rollup_events(&w);
            w.execute("INSERT INTO source_settings(scope,source,expected,updated,updated_by) VALUES('global','derive-deploiement',1,1700000000,'eve')", []).unwrap();
        }
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        let src = |n: &str| v["sources"].as_array().unwrap().iter().find(|s| s["source"] == n).cloned().unwrap_or_else(|| panic!("source {n} absente de {v}"));
        let pp = src("portprobe");
        assert_eq!(pp["expected"], true);
        assert_eq!(pp["unexpected"], false);
        assert!(pp["raison_attendue"].as_str().unwrap().contains("collectors/portprobe.sh"), "la raison nomme le fichier livré : {pp}");
        assert_eq!(pp["cadence_declaree"], "non_declaree");
        assert_eq!(pp["status"], "calme", "sans cadence déclarée, deux heures de silence = calme, jamais en retard");
        let dd = src("derive-deploiement");
        assert_eq!(dd["expected"], true, "marquage persistant lu");
        assert!(dd["raison_attendue"].as_str().unwrap().starts_with("marquée attendue par eve"), "qui : {dd}");
        assert_eq!(dd["marquage"]["updated_by"], "eve");
        assert_eq!(dd["marquage"]["updated"], 1700000000, "quand");
        let au = src("auditd");
        assert_eq!(au["cadence_declaree"], "continue");
        assert_eq!(au["cadence_interval_s"], 120);
        assert_eq!(au["status"], "en_retard");
        let wb = src("web");
        assert_eq!(wb["status"], "frais");
        // même mot que la fraîcheur, sur la même base.
        let f = compute_freshness(&p, None);
        let feed = |n: &str| f["feeds"].as_array().unwrap().iter().find(|x| x["name"] == n).cloned().unwrap();
        for n in ["portprobe", "auditd", "web", "derive-deploiement"] {
            assert_eq!(feed(n)["status"], src(n)["status"], "inventaire et fraîcheur rendent le même mot pour {n}");
        }
    }

    /// LA CADENCE DÉCLARÉE dérive de `COLLECTORS` — par famille de sonde, avec la préséance du battement.
    #[test]
    fn cadence_declaree_derive_des_sondes() {
        // flux continu.
        assert_eq!(cadence_declaree("event", "auditd"), CadenceDeclaree::Continue { interval_s: 120, capteur: "audit" });
        assert_eq!(cadence_declaree("event", "web"), CadenceDeclaree::Continue { interval_s: 1800, capteur: "web" });
        // flux événementiel SANS battement : jamais en retard.
        assert_eq!(cadence_declaree("event", "sshd"), CadenceDeclaree::Evenementielle { capteur: "journal" });
        assert_eq!(cadence_declaree("event", "yara"), CadenceDeclaree::Evenementielle { capteur: "yara" });
        // flux événementiel AVEC battement de santé : le battement (dead-man's-switch) donne la cadence.
        assert_eq!(cadence_declaree("event", "crowdsec"), CadenceDeclaree::Continue { interval_s: 300, capteur: "crowdsec-health" });
        assert_eq!(cadence_declaree("event", "portscan"), CadenceDeclaree::Continue { interval_s: 300, capteur: "portscan-health" });
        // instantanés et métriques.
        assert_eq!(cadence_declaree("snapshot", "firewall"), CadenceDeclaree::Continue { interval_s: 120, capteur: "firewall" });
        assert_eq!(cadence_declaree("metric", "métriques · 3 séries"), CadenceDeclaree::Continue { interval_s: 60, capteur: "resources" });
        // les quatre sources du constat : aucune sonde ne déclare de cadence pour mail / portprobe /
        // cloudflare ; `derive-deploiement` non plus. Elles ne peuvent donc pas être « en retard ».
        for n in ["mail", "portprobe", "cloudflare", "derive-deploiement", "nft"] {
            assert_eq!(cadence_declaree("event", n), CadenceDeclaree::NonDeclaree, "{n}");
        }
        // un kind d'instantané n'est pas une source d'event (et inversement).
        assert_eq!(cadence_declaree("event", "firewall"), CadenceDeclaree::NonDeclaree);
        assert_eq!(cadence_declaree("snapshot", "auditd"), CadenceDeclaree::NonDeclaree);
        // TOUTE entrée de COLLECTORS est couverte par une famille (une 5e variante de `Sonde` devrait l'être aussi).
        for (id, _, _, sonde, _) in COLLECTORS.iter() {
            let couverte = match sonde {
                Sonde::Instantane { kind } => cadence_declaree("snapshot", kind) != CadenceDeclaree::NonDeclaree,
                Sonde::EventFlux { sources } => sources.iter().all(|s| cadence_declaree("event", s) != CadenceDeclaree::NonDeclaree),
                Sonde::EventBattementSante { source } => cadence_declaree("event", source) != CadenceDeclaree::NonDeclaree,
                Sonde::MetriqueFlotteConfondue => cadence_declaree("metric", "x") != CadenceDeclaree::NonDeclaree,
            };
            assert!(couverte, "la sonde `{id}` ne déclare de cadence pour aucun feed");
        }
    }

    /// LE STATUT : quatre mots, un sens chacun, et le seuil « en retard » = celui du capteur « muet ».
    #[test]
    fn statut_de_source_quatre_mots_un_sens_chacun() {
        let cont = CadenceDeclaree::Continue { interval_s: 300, capteur: "x" };
        let evt = CadenceDeclaree::Evenementielle { capteur: "x" };
        // pipeline en panne : muet, quelle que soit la cadence.
        assert_eq!(statut_de_source(5, false, Some(&cont)), "muet");
        assert_eq!(statut_de_source(5, false, None), "muet");
        // frais / calme sans cadence déclarée ou événementielle : JAMAIS en retard, même après des heures.
        assert_eq!(statut_de_source(60, true, None), "frais");
        assert_eq!(statut_de_source(FRAIS_S, true, None), "frais");
        assert_eq!(statut_de_source(FRAIS_S + 1, true, None), "calme");
        assert_eq!(statut_de_source(66 * 60, true, None), "calme", "le courrier à 66 min : calme, pas en retard");
        assert_eq!(statut_de_source(48 * 3600, true, Some(&evt)), "calme", "événementiel : deux jours sans événement = calme");
        // continu : en retard AU-DELÀ de interval × CYCLES_TOLERES_AFFICHAGE — le seuil du capteur « muet ».
        assert_eq!(statut_de_source(300 * CYCLES_TOLERES_AFFICHAGE, true, Some(&cont)), "frais", "à la limite : pas encore en retard");
        assert_eq!(statut_de_source(300 * CYCLES_TOLERES_AFFICHAGE + 1, true, Some(&cont)), "en_retard", "la cadence déclarée prime sur frais/calme");
        let lent = CadenceDeclaree::Continue { interval_s: 1800, capteur: "web" };
        assert_eq!(statut_de_source(3600, true, Some(&lent)), "calme", "web à 1 h : sous 3 cycles de 30 min, calme");
        assert_eq!(statut_de_source(5401, true, Some(&lent)), "en_retard", "web à 90 min et 1 s : en retard");
        // cohérence avec le verdict du capteur : même observation, même seuil.
        let now_ts = 1_000_000;
        for age in [1, 899, 900, 901, 5000] {
            let capteur = statut_capteur(Some(now_ts - age), 300, false, true, CYCLES_TOLERES_AFFICHAGE, now_ts);
            let source = statut_de_source(age, true, Some(&cont));
            assert_eq!(capteur == StatutCapteur::Muet, source == "en_retard", "âge {age} : capteur {capteur:?} vs source {source}");
        }
    }

    /// LE CHEMIN RÉEL : `compute_freshness` rend le statut dérivé, le rythme observé sous son vrai nom, et
    /// les alertes actives comme un COMPTE à part. Mutation dans les deux sens : la même base, la même
    /// source, un silence sous puis au-delà de la cadence déclarée.
    #[test]
    fn freshness_rend_le_statut_derive_et_les_alertes_a_part() {
        let (_tmp, p) = imp_base_disque("fresh-p11");
        {
            let w = open_db(&p).unwrap();
            imp_flux(&w, "web", "web", 10, 4); // pipeline frais
            imp_flux(&w, "mail", "mail", 66 * 60, 87); // 87 événements/24 h : l'ancienne moyenne donnait 4×993 s = 66 min -> « en retard » à tort
            imp_flux(&w, "portprobe", "firewall", 3700, 1200); // 1200/24 h : l'ancien « continu » (≤ 90 s) puis « en retard » après 1 h
            imp_flux(&w, "auditd", "exec", 359, 4); // continu 120 s : 359 s < 360 -> pas en retard
            imp_flux(&w, "kube-audit", "k8s", 361, 4); // continu 120 s : 361 s > 360 -> en retard
            imp_flux(&w, "cloudflare", "web", 30, 4); // frais, avec une alerte active imputée
            rollup_events(&w);
            w.execute("INSERT INTO alert(ts,rule,severity,title,detail,status,sources) VALUES(?1,'cf-recon',2,'Recon web edge','search source=cloudflare','new',?2)",
                params![now(), imputation_encoder(&["cloudflare".to_string()])]).unwrap();
        }
        let v = compute_freshness(&p, None);
        let feed = |n: &str| v["feeds"].as_array().unwrap().iter().find(|x| x["name"] == n).cloned().unwrap_or_else(|| panic!("feed {n} absent : {v}"));
        let mail = feed("mail");
        assert_eq!(mail["status"], "calme", "le courrier à 66 min sans cadence déclarée : calme");
        assert_eq!(mail["cadence_declaree"], "non_declaree");
        assert!(mail["observed_interval_s"].as_i64().unwrap() > 900, "le rythme observé est rendu sous son vrai nom");
        assert!(mail.get("expected_s").is_none(), "plus de champ qui fait passer une moyenne pour une attente");
        assert_eq!(feed("portprobe")["status"], "calme", "les sondes de ports, 1 h de calme sans cadence déclarée : calme");
        assert_eq!(feed("auditd")["status"], "frais");
        assert_eq!(feed("kube-audit")["status"], "en_retard");
        assert_eq!(feed("kube-audit")["cadence_capteur"], "kube-audit");
        let cf = feed("cloudflare");
        assert_eq!(cf["status"], "frais", "une alerte active ne dégrade pas la collecte");
        assert_eq!(cf["active_alerts"], 1, "... elle est comptée à part");
        // le pipeline en panne : tout muet, y compris ce qui était en retard.
        let (_tmp2, p2) = imp_base_disque("fresh-p11-muet");
        {
            let w = open_db(&p2).unwrap();
            imp_flux(&w, "web", "web", 1200, 4);
            rollup_events(&w);
        }
        let v2 = compute_freshness(&p2, None);
        assert_eq!(v2["pipeline_fresh"], false);
        assert!(v2["feeds"].as_array().unwrap().iter().all(|f| f["status"] == "muet"));
    }
