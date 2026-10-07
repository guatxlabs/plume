    // ================================================================================================
    // `P11.19-a` (reste 2, moitié démon) — `GET /api/sources` sert, sur chaque entrée, les CHAMPS ÉTENDUS
    // émis par la source, DÉRIVÉS de `COLLECTED_EXTENDED_FIELDS ⨝ SOURCES_LIVREES`, en TROIS états : liste,
    // liste vide établie, `null` (source non couverte par la jointure). Les témoins ci-dessous tiennent :
    //   1. la surface de la jointure est le MIROIR de celle de l'extracteur (sinon « vide » ne prouve rien) ;
    //   2. l'autorité est COMPLÈTE AU GRAIN DU COUPLE (champ, fichier) — elle ne portait qu'une citation
    //      par champ, 133 couples émis manquaient, et la jointure aurait servi des listes tronquées ;
    //   3. sur la VRAIE route, dans les DEUX sens : tout couple de l'autorité est servi sous une source ou
    //      nommé « sans source livrée » ; aucun champ servi ne sort de l'autorité ; chaque liste servie est
    //      ÉGALE à ce que l'extracteur trouve dans les fichiers qui écrivent sous la source (son fichier, le
    //      canal d'aveu de `lib.sh` qu'elle nomme littéralement, ses overlays) ; `null` et `[]` ne se confondent pas ;
    //   4. le canal d'aveu et les overlays sont des MIROIRS du texte livré, relus ici sans passer par la route ;
    //   5. l'enveloppe de spool (`\"kind\":\"events\"`) n'est pas prise pour un champ, et ce qui suit son
    //      ouverture sur la même ligne reste dérivé ;
    //   6. les champs NUMÉRIQUES du 3e argument de `heartbeat` sont servis sous la source du 1er argument —
    //      oracle qui relit les appels SANS l'extracteur (les témoins 2 et 3 partagent l'extracteur qui tient
    //      l'autorité : ils ne voient pas ce qu'il ne voit pas).
    // Mutations jouées sur ces témoins (posées sous cfg!(test), retirées avant le commit) : `retire_champ`, `champ_fantome`, `vide_pour_inconnu`,
    // `autorite_une_citation` (l'état d'avant : une citation par champ) ; puis, à la correction,
    // `enveloppe_comptee`, `kind_enveloppe_remis`, `aveu_non_impute`, `overlay_non_impute`, `surface_sans_extension` ;
    // puis, au second tour : `hb_ignore`, `hb_couples_retires`, `sans_dedup`, `tests_rs_admis`, `enveloppe_ligne`.
    // Vague D (correction après revue adverse), mutants par VERIF_MUT, retirés avant le commit : `M_P5_PREMIERE`
    // (la 1re clé d'un fragment redevient invisible), `M_P3_ACTION` (`map.action` des overlays ignoré), `M_NOSORT`
    // (tri retiré), `M_P6_PROF` (clés imbriquées du battement admises), `M_PARSEURS_IGNORES`, `M_DYN_FAUX`, `M_PA_CORE` (le filtre « hors colonnes cœur » des parseurs regex actifs retiré : crowdsec servirait `src_ip`), `M_P3_SCALAIRE` (P3 bis ne retient plus qu'une valeur chaîne), et `M_TABLE_AVANT` (les six couples neufs retirés de la porte `couples_etendus` : les deux oracles sans extracteur et l'inventaire rougissent).
    // Second tour : `M8_PA_DEDUP` / `M9_PA_TRI` (dédoublonnage / tri des parseurs regex actifs retirés), `M15_NVP_TRONQUE` (la racine ne sert
    // que trois aveux), `M14_SSL_TRI` (tri des listes « sans source livrée » retiré), `M18B_ENV_DEBUT` (la ligne d'enveloppe prise depuis le début du fichier).
    // ================================================================================================

    /// Fichier livré qui émet une source de `SOURCES_LIVREES`.
    fn cesp_fichier_de(source: &str) -> Option<&'static str> {
        crate::handlers::sources::SOURCES_LIVREES.iter().find(|(s, _)| *s == source).map(|(_, f)| *f)
    }

    /// Surface balayée, relue sur `COLLECTED_SCAN_SURFACE` (l'extracteur), PAS sur la porte de la route.
    fn cesp_dans_la_surface(fichier: &str) -> bool {
        let Some((dir, base)) = fichier.rsplit_once('/') else { return false };
        let Some((_, ext)) = base.rsplit_once('.') else { return false };
        base != "tests.rs" && COLLECTED_SCAN_SURFACE.iter().any(|(d, e, _, _)| *d == dir && *e == ext)
    }

    /// Lignes de code d'un fichier livré (les lignes de commentaire n'émettent rien).
    fn cesp_lignes_de_code(root: &std::path::Path, rel: &str) -> Vec<String> {
        std::fs::read_to_string(root.join(rel))
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    /// LE CANAL D'AVEU, relu sur le texte : les fonctions de `lib.sh` qui mènent (transitivement) à
    /// `plume_report_availability`, puis les sources qu'un capteur livré leur passe LITTÉRALEMENT en premier argument.
    fn cesp_sources_du_canal_d_aveu(root: &std::path::Path) -> std::collections::BTreeSet<String> {
        let def = regex::Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{").unwrap();
        let mut corps: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        let mut courante: Option<String> = None;
        for l in cesp_lignes_de_code(root, "collectors/lib.sh") {
            if let Some(c) = def.captures(&l) {
                courante = Some(c[1].to_string());
                corps.entry(c[1].to_string()).or_default();
            } else if l.starts_with('}') {
                courante = None;
            } else if let Some(f) = &courante {
                corps.get_mut(f).unwrap().push(l);
            }
        }
        let mut atteintes: std::collections::BTreeSet<String> = ["plume_report_availability".to_string()].into();
        loop {
            let avant = atteintes.len();
            let mot = regex::Regex::new(&format!(r"\b({})\b", atteintes.iter().cloned().collect::<Vec<_>>().join("|"))).unwrap();
            for (f, b) in &corps {
                if b.iter().any(|l| mot.is_match(l)) {
                    atteintes.insert(f.clone());
                }
            }
            if atteintes.len() == avant { break; }
        }
        assert!(atteintes.len() >= 5, "canal d'aveu : {atteintes:?} — lib.sh a changé de forme, la relecture ne mord plus");
        let appel = regex::Regex::new(&format!(
            r#"\b(?:{})\s+"?([A-Za-z0-9_.-]+)"?(?:\s|$|;|\))"#,
            atteintes.iter().cloned().collect::<Vec<_>>().join("|")
        ))
        .unwrap();
        let mut sources = std::collections::BTreeSet::new();
        let mut fichiers: Vec<_> = std::fs::read_dir(root.join("collectors")).unwrap().flatten().map(|e| e.path()).collect();
        fichiers.sort();
        for p in fichiers {
            let base = p.file_name().unwrap().to_string_lossy().to_string();
            if !base.ends_with(".sh") || base == "lib.sh" { continue; }
            for l in cesp_lignes_de_code(root, &format!("collectors/{base}")) {
                for c in appel.captures_iter(&l) { sources.insert(c[1].to_string()); }
            }
        }
        sources
    }

    /// LES OVERLAYS DE PARSEUR CHARGEABLES et la source qu'ils visent, relus sur `config.d/parsers/`.
    fn cesp_overlays(root: &std::path::Path) -> std::collections::BTreeSet<(String, String)> {
        let mut out = std::collections::BTreeSet::new();
        for e in std::fs::read_dir(root.join("config.d/parsers")).unwrap().flatten() {
            let base = e.file_name().to_string_lossy().to_string();
            if !base.ends_with(".json") { continue; }
            let v: Value = serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap();
            let chargeable = v.get("enabled").map_or(true, |x| x.as_bool() != Some(false))
                && v.get("name").and_then(|n| n.as_str()).is_some_and(|n| !n.trim().is_empty());
            if let (true, Some(src)) = (chargeable, v.get("source").and_then(|x| x.as_str())) {
                if src != "*" { out.insert((format!("config.d/parsers/{base}"), src.to_string())); }
            }
        }
        out
    }

    /// Les fichiers dont les champs arrivent sous une source, recalculés par le témoin (miroirs relus ci-dessus).
    fn cesp_fichiers_de(source: &str, aveu: &std::collections::BTreeSet<String>, overlays: &std::collections::BTreeSet<(String, String)>) -> Option<Vec<String>> {
        let f = cesp_fichier_de(source)?;
        if !cesp_dans_la_surface(f) { return None; }
        let mut v = vec![f.to_string()];
        if aveu.contains(source) { v.push("collectors/lib.sh".to_string()); }
        v.extend(overlays.iter().filter(|(_, s)| s == source).map(|(o, _)| o.clone()));
        Some(v)
    }

    /// Ce que l'extracteur (celui qui tient l'autorité) trouve dans un fichier, hors colonnes cœur.
    fn cesp_derive_du_fichier(derive: &[(String, String, &'static str)], fichier: &str) -> std::collections::BTreeSet<String> {
        derive
            .iter()
            .filter(|(f, rel, _)| rel == fichier && !CIM_CORE_FIELDS.contains(&f.as_str()))
            .map(|(f, _, _)| f.clone())
            .collect()
    }

    #[test]
    fn la_surface_de_la_jointure_est_le_miroir_de_celle_de_l_extracteur() {
        let a: std::collections::BTreeSet<(&str, &str)> = crate::collected::COLLECTED_SCAN_DIRS.iter().copied().collect();
        let b: std::collections::BTreeSet<(&str, &str)> = COLLECTED_SCAN_SURFACE.iter().map(|(d, e, _, _)| (*d, *e)).collect();
        assert_eq!(a, b, "COLLECTED_SCAN_DIRS (jointure servie) doit être le miroir exact de COLLECTED_SCAN_SURFACE (extracteur)");
        // La règle de citation : suffixe AU SÉPARATEUR près, jamais une sous-chaîne.
        assert!(crate::collected::citation_designe("collectors/cloudflare.sh", "cloudflare.sh"));
        assert!(!crate::collected::citation_designe("collectors/cloudflare-http.sh", "http.sh"));
        assert!(!crate::collected::fichier_dans_la_surface("agent/src/main.rs"));
        assert!(crate::collected::fichier_dans_la_surface("collectors/minio-audit-relay.py"));
        // Une extension étrangère dans un répertoire balayé n'est PAS dans la surface : l'extracteur ne la lit pas.
        assert!(!crate::collected::fichier_dans_la_surface("collectors/README.md"));
        assert!(!crate::collected::fichier_dans_la_surface("config.d/parsers/nft-scan-detect.yaml"));
        assert!(!crate::collected::fichier_dans_la_surface("collectors/windows/plume-collector.sh"));
        // Le `tests.rs` d'un répertoire balayé n'est pas lu par l'extracteur : ni la porte ni le témoin ne l'y mettent.
        assert!(!crate::collected::fichier_dans_la_surface("agent/src/source/fim/tests.rs"));
        assert!(!cesp_dans_la_surface("agent/src/source/fim/tests.rs"));
        assert!(crate::collected::fichier_dans_la_surface("agent/src/source/fim/mod.rs"));
        // La porte de la route et la relecture du témoin disent la même chose sur chaque fichier livré cité.
        for (s, f) in crate::handlers::sources::SOURCES_LIVREES.iter() {
            assert_eq!(crate::collected::fichier_dans_la_surface(f), cesp_dans_la_surface(f), "{s} ({f})");
        }
    }

    /// LE CANAL D'AVEU ET LES OVERLAYS SONT DES MIROIRS DU TEXTE LIVRÉ, dans les deux sens. Et les couples cités
    /// `lib.sh` sont EXACTEMENT les clés de l'objet `fields` du canal d'aveu : si une autre aide de lib.sh se mettait
    /// à écrire un champ, l'imputer aux sources d'aveu serait faux — ce témoin rougit avant.
    #[test]
    fn le_canal_d_aveu_et_les_overlays_sont_des_miroirs_du_texte_livre() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let aveu_lu = cesp_sources_du_canal_d_aveu(&root);
        let aveu_table: std::collections::BTreeSet<String> = crate::collected::SOURCES_DU_CANAL_D_AVEU.iter().map(|s| s.to_string()).collect();
        assert_eq!(aveu_table, aveu_lu, "SOURCES_DU_CANAL_D_AVEU doit être le miroir des premiers arguments littéraux");
        assert!(aveu_lu.contains("clamav") && aveu_lu.contains("fail2ban") && !aveu_lu.contains("dataacl"), "{aveu_lu:?}");
        let ov_table: std::collections::BTreeSet<(String, String)> =
            crate::collected::SOURCE_DES_OVERLAYS.iter().map(|(f, s)| (f.to_string(), s.to_string())).collect();
        assert_eq!(ov_table, cesp_overlays(&root), "SOURCE_DES_OVERLAYS doit être le miroir des overlays chargeables");
        assert_eq!(crate::collected::FICHIER_DU_CANAL_D_AVEU, "collectors/lib.sh");

        let ligne = cesp_lignes_de_code(&root, "collectors/lib.sh").into_iter().find(|l| l.contains("_av_fields=$(printf"))
            .expect("lib.sh : l'objet `fields` du canal d'aveu est introuvable");
        let cle = regex::Regex::new(r#""([A-Za-z_][A-Za-z0-9_]*)":"#).unwrap();
        let cles: std::collections::BTreeSet<String> = cle.captures_iter(&ligne).map(|c| c[1].to_string()).collect();
        let lib: std::collections::BTreeSet<String> = crate::collected::couples_etendus().into_iter()
            .filter(|(_, c)| *c == "lib.sh").map(|(f, _)| f.to_string()).collect();
        assert_eq!(lib, cles, "les couples cités lib.sh doivent être exactement les clés du canal d'aveu");
    }

    /// L'ENVELOPPE DE SPOOL N'EST PAS UN CHAMP. `{\"ts\":…,\"host\":…,\"kind\":\"events\",\"events\":[…]}` porte
    /// `kind`, que `ingest` lit pour aiguiller et ne recopie jamais dans `fields`. Oracle INDÉPENDANT de l'extracteur :
    /// une clé d'enveloppe dérivée d'un fichier doit y figurer aussi sur une ligne de code qui n'est PAS l'enveloppe.
    #[test]
    fn l_enveloppe_de_spool_n_est_pas_prise_pour_un_champ() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let derive = collected_extract_shipped(&root);
        let enveloppe = regex::Regex::new(r#"\\?"(?:events|metrics)\\?"\s*:\s*\["#).unwrap();
        let cle = regex::Regex::new(r#"\\"([A-Za-z_][A-Za-z0-9_]*)\\"\s*:"#).unwrap();
        let mut n_enveloppes = 0;
        let mut faux: Vec<String> = Vec::new();
        let mut fichiers: Vec<_> = std::fs::read_dir(root.join("collectors")).unwrap().flatten().map(|e| e.path()).collect();
        fichiers.sort();
        for p in fichiers {
            let base = p.file_name().unwrap().to_string_lossy().to_string();
            if !base.ends_with(".sh") { continue; }
            let rel = format!("collectors/{base}");
            let lignes = cesp_lignes_de_code(&root, &rel);
            for l in lignes.iter().filter(|l| enveloppe.is_match(l)) {
                n_enveloppes += 1;
                for c in cle.captures_iter(l) {
                    let k = &c[1];
                    if CIM_CORE_FIELDS.contains(&k) || k == "events" || k == "metrics" { continue; }
                    let derive_ici = derive.iter().any(|(f, r, _)| f == k && *r == rel);
                    let ailleurs = lignes.iter().any(|m| {
                        !enveloppe.is_match(m) && (m.contains(&format!("\\\"{k}\\\":")) || m.contains(&format!("\"{k}\":")) || m.contains(&format!("{k}:")))
                    });
                    if derive_ici && !ailleurs { faux.push(format!("{k} ({rel})")); }
                }
            }
        }
        assert!(n_enveloppes >= 5, "seulement {n_enveloppes} lignes d'enveloppe trouvées : la relecture ne mord plus");
        assert!(faux.is_empty(), "clé(s) d'ENVELOPPE dérivée(s) comme champ : {faux:?}");
        for f in ["web.sh", "mail.sh", "dataaccess.sh", "dataacl.sh"] {
            let rel = format!("collectors/{f}");
            assert!(!derive.iter().any(|(k, r, _)| k == "kind" && *r == rel), "`kind` n'est que l'enveloppe de {f}");
            assert!(!crate::collected::couples_etendus().contains(&("kind", f)), "couple (kind, {f}) dans l'autorité");
        }
        // Contrôle inverse : là où `kind` est un vrai `fields.kind`, il reste dérivé (sinon ce test passerait à vide).
        for f in ["kube-rbac.sh", "minio.sh", "integrity.sh"] {
            let rel = format!("collectors/{f}");
            assert!(derive.iter().any(|(k, r, _)| k == "kind" && *r == rel), "`kind` est un vrai champ de {f}");
        }
    }

    /// COMPLÉTUDE AU GRAIN DU COUPLE — la garde de `detection.rs` ne la tient qu'au grain du CHAMP (« un
    /// fichier au moins l'émet »), ce qui laissait `web.sh` à 3 champs sur 18 dans toute lecture par fichier.
    #[test]
    fn l_autorite_porte_chaque_couple_champ_fichier_emis() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let derive = collected_extract_shipped(&root);
        let couples = crate::collected::couples_etendus();
        let mut manquants: Vec<String> = derive
            .iter()
            .filter(|(f, _, _)| !CIM_CORE_FIELDS.contains(&f.as_str()))
            .filter(|(f, rel, _)| !couples.iter().any(|(g, c)| g == f && crate::collected::citation_designe(rel, c)))
            .map(|(f, rel, _)| format!("{f} (émis par {rel})"))
            .collect();
        manquants.sort();
        manquants.dedup();
        assert!(manquants.is_empty(), "couple(s) émis absents de COLLECTED_EXTENDED_FIELDS ({}) : {manquants:?}", manquants.len());
    }

    #[tokio::test]
    async fn l_inventaire_sert_les_champs_de_chaque_source_dans_les_deux_sens() {
        let livrees = crate::handlers::sources::SOURCES_LIVREES;
        let (_tmp, p) = imp_base_disque("cesp-p1119a");
        {
            let w = open_db(&p).unwrap();
            // Le registre regex de CETTE base, chargé comme au démarrage : ce que les migrations y sèment est servi à part.
            crate::parsers::parsers_reload(&w, &p);
            // Chaque source livrée est listée (déclaration de l'exploitant : entrée dormante) ; plus une
            // source que SEUL l'exploitant déclare, et une que SEUL un connecteur déclare (observée).
            for (s, _) in livrees.iter() {
                w.execute(
                    "INSERT INTO source_settings(scope,source,expected,updated,updated_by,expected_par,expected_le) VALUES('global',?1,1,1700000000,'eve','eve',1700000000)",
                    params![s],
                )
                .unwrap();
            }
            w.execute(
                "INSERT INTO source_settings(scope,source,expected,updated,updated_by,expected_par,expected_le) VALUES('global','cesp-exploitant',1,1700000000,'eve','eve',1700000000)",
                [],
            )
            .unwrap();
            w.execute("INSERT INTO connector(type,name,enabled,config_json) VALUES('http_pull','cesp',1,'{\"source\":\"cesp-connecteur\"}')", []).unwrap();
            imp_flux(&w, "cesp-connecteur", "config", 10, 4);
            rollup_events(&w);
        }
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        assert_eq!(v["ok"], true, "{v}");
        let servies: std::collections::BTreeMap<String, Value> = v["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["source"].as_str().unwrap().to_string(), e.clone()))
            .collect();
        let racine = v["champs_etendus_sans_source_livree"].as_object().expect("racine : champs sans source livrée");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let derive = collected_extract_shipped(&root);
        let aveu = cesp_sources_du_canal_d_aveu(&root);
        let overlays = cesp_overlays(&root);

        // (0) LA CLÉ EST PRÉSENTE SUR CHAQUE ENTRÉE, liste ou `null` — jamais absente, jamais autre chose.
        for (s, e) in &servies {
            let c = e.get("champs_etendus").unwrap_or_else(|| panic!("{s} : clé `champs_etendus` absente"));
            assert!(c.is_array() || c.is_null(), "{s} : `champs_etendus` doit être une liste ou null, pas {c}");
        }
        for (s, _) in livrees.iter() {
            assert!(servies.contains_key(*s), "source livrée {s} non servie par l'inventaire");
        }

        // (1) TROIS ÉTATS, jamais confondus.
        let (mut n_pleines, mut n_vides, mut n_null) = (0, 0, 0);
        for (s, e) in &servies {
            let c = &e["champs_etendus"];
            let couverte = cesp_fichier_de(s).is_some_and(cesp_dans_la_surface);
            if couverte {
                let liste = c.as_array().unwrap_or_else(|| panic!("{s} : couverte par la jointure, servie {c} au lieu d'une liste"));
                if liste.is_empty() { n_vides += 1 } else { n_pleines += 1 }
            } else {
                assert!(c.is_null(), "{s} : NON couverte par la jointure (exploitant, connecteur, agent, démon, hors surface) — servie {c} ; une liste vide y dirait « aucun champ » sans le savoir");
                n_null += 1;
            }
        }
        for s in ["cesp-exploitant", "cesp-connecteur", "agent", "plume-auth", "sshd", "defender", "mail-audit"] {
            assert!(servies[s]["champs_etendus"].is_null(), "{s} doit être servi null : {}", servies[s]);
        }
        // Mesuré à la correction : AUCUNE source livrée n'est plus servie `[]` — les « vides » d'avant (clamav,
        // falco, journal…) portaient les champs du canal d'aveu. L'état vide reste possible ; s'il réapparaît,
        // (2) exige qu'il soit ÉGAL à ce que les fichiers de la source écrivent, donc établi.
        assert!(n_pleines > 0 && n_null > 0, "listes et null doivent être exercés : {n_pleines} pleines, {n_vides} vides, {n_null} null");

        // (2) CHAQUE LISTE SERVIE == CE QUE L'EXTRACTEUR TROUVE DANS LES FICHIERS QUI ÉCRIVENT SOUS LA SOURCE
        // (son fichier, `lib.sh` si elle passe par le canal d'aveu, ses overlays — relus par le témoin). Cela
        // rend la liste COMPLÈTE AU REGARD DE L'EXTRACTEUR, sans passer par la constante d'autorité — mais PAS
        // indépendamment de l'extracteur, qui tient aussi l'autorité : ce qu'aucune de ses positions ne voit
        // manquerait des deux côtés. Le témoin `les_champs_du_battement_sont_servis_sous_leur_source` relit
        // le cas mesuré (valeurs numériques de `heartbeat`) sans lui. La liste servie est aussi SANS DOUBLON
        // et TRIÉE : un repli en ensemble ne le verrait pas.
        for (s, e) in &servies {
            let Some(liste) = e["champs_etendus"].as_array() else { continue };
            let brute: Vec<String> = liste.iter().map(|x| x.as_str().unwrap().to_string()).collect();
            let mut triee = brute.clone();
            triee.sort();
            triee.dedup();
            assert_eq!(brute, triee, "{s} : la liste servie doit être triée et sans doublon");
            let servi: std::collections::BTreeSet<String> = brute.into_iter().collect();
            let fichiers = cesp_fichiers_de(s, &aveu, &overlays).unwrap();
            let attendu: std::collections::BTreeSet<String> = fichiers.iter().flat_map(|f| cesp_derive_du_fichier(&derive, f)).collect();
            assert_eq!(servi, attendu, "{s} ({fichiers:?}) : la liste servie diffère de ce que ces fichiers émettent");
        }
        // Les cas qui ont motivé la correction, nommés.
        let liste_de = |s: &str| -> Vec<String> {
            servies[s]["champs_etendus"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
        };
        assert!(!liste_de("web").contains(&"kind".to_string()), "web : `kind` n'est que l'enveloppe de spool");
        assert!(liste_de("kube-rbac").contains(&"kind".to_string()), "kube-rbac écrit un vrai fields.kind");
        for c in ["type", "collector", "collect_status", "reason", "detail"] {
            assert!(liste_de("clamav").contains(&c.to_string()), "clamav : ses aveux portent `{c}`");
        }
        for c in ["dst_port", "proto", "signal", "action"] {
            assert!(liste_de("nft").contains(&c.to_string()), "nft : l'overlay nft-scan-detect.json écrit `{c}`");
        }
        assert!(liste_de("firewall").contains(&"action".to_string()), "firewall : example-cim-firewall.json écrit `map.action`");
        assert!(liste_de("k8s-log").contains(&"ns".to_string()), "k8s-log : pod-logs.sh écrit `ns` (1re clé de son sac)");
        // Ce que l'ingestion ajoute hors fichiers livrés est dit À CÔTÉ de la liste, sur chaque entrée.
        let actifs_de = |s: &str| -> Vec<String> {
            servies[s]["champs_etendus_parseurs_actifs"].as_array().unwrap_or_else(|| panic!("{s} : registre chargé, servi {}", servies[s])).iter().map(|x| x.as_str().unwrap().to_string()).collect()
        };
        assert!(actifs_de("fail2ban").contains(&"jail".to_string()), "fail2ban : parseur regex semé `jail` : {:?}", actifs_de("fail2ban"));
        assert!(actifs_de("crowdsec").contains(&"scenario".to_string()), "crowdsec : parseur regex semé `scenario` : {:?}", actifs_de("crowdsec"));
        assert!(!actifs_de("crowdsec").contains(&"src_ip".to_string()), "crowdsec : `src_ip` (colonne cœur) servi comme champ étendu : {:?}", actifs_de("crowdsec"));
        for s in ["web", "k8s-log", "cesp-exploitant"] {
            assert!(actifs_de(s).contains(&"user".to_string()) && actifs_de(s).contains(&"uid".to_string()), "{s} : les parseurs semés sur `*` ajoutent user/uid");
            assert!(!actifs_de(s).contains(&"jail".to_string()), "{s} : `jail` ne vise que fail2ban");
        }
        for (s, e) in &servies {
            assert_eq!(e["champs_etendus_cles_dynamiques"], json!(crate::parsers::generic_sources().iter().any(|g| g == s)), "{s}");
        }
        let limites = v["champs_etendus_ne_voit_pas"].as_array().expect("racine : ce que les listes ne voient pas");
        assert!(limites.len() >= 3 && limites.iter().all(|l| l.as_str().is_some_and(|t| !t.is_empty())), "{limites:?}");
        // La route sert TOUS les aveux, pas un préfixe : chaque angle mort mesuré est nommé (relu par mot-clé,
        // sans passer par la constante), et le servi est la constante entière.
        let servies_limites: Vec<&str> = limites.iter().map(|l| l.as_str().unwrap()).collect();
        assert_eq!(servies_limites, crate::handlers::sources::CHAMPS_ETENDUS_NE_VOIT_PAS, "la racine doit servir tous les aveux");
        for mot in ["parseurs regex actifs", "extraction générique", "overlay", "_COMM", "non littérale-string", "variable au canal d'aveu", "bans.sh"] {
            assert!(servies_limites.iter().any(|l| l.contains(mot)), "aveu manquant à la racine (`{mot}`) : {servies_limites:?}");
        }

        // (3) AUCUN CHAMP SERVI NE SORT DE L'AUTORITÉ (lue ici sur la constante, pas par la porte de la route).
        let autorite = crate::collected::COLLECTED_EXTENDED_FIELDS;
        let mut fantomes: Vec<String> = Vec::new();
        for (s, e) in &servies {
            let Some(liste) = e["champs_etendus"].as_array() else { continue };
            let fichiers = cesp_fichiers_de(s, &aveu, &overlays).unwrap();
            for f in liste {
                let f = f.as_str().unwrap();
                if !autorite.iter().any(|(g, c)| *g == f && fichiers.iter().any(|fi| crate::collected::citation_designe(fi, c))) {
                    fantomes.push(format!("{s}:{f}"));
                }
            }
        }
        for (c, champs) in racine {
            for f in champs.as_array().unwrap() {
                let f = f.as_str().unwrap();
                if !autorite.iter().any(|(g, d)| *g == f && d == c) {
                    fantomes.push(format!("<sans source livrée {c}>:{f}"));
                }
            }
        }
        assert!(fantomes.is_empty(), "champ(s) servi(s) hors de l'autorité : {fantomes:?}");

        // (4) TOUT COUPLE DE L'AUTORITÉ EST SERVI sous une source livrée, OU nommé « sans source livrée ».
        let mut perdus: Vec<String> = Vec::new();
        for (f, c) in autorite.iter() {
            let sous_une_source = servies.iter().any(|(s, e)| {
                cesp_fichiers_de(s, &aveu, &overlays).is_some_and(|fs| fs.iter().any(|fi| crate::collected::citation_designe(fi, c)))
                    && e["champs_etendus"].as_array().is_some_and(|l| l.iter().any(|x| x == f))
            });
            let nomme = racine.get(*c).and_then(|l| l.as_array()).is_some_and(|l| l.iter().any(|x| x == f));
            if !(sous_une_source || nomme) {
                perdus.push(format!("{f} ({c})"));
            }
            assert!(!(sous_une_source && nomme), "{f} ({c}) servi sous une source ET nommé sans source livrée");
        }
        assert!(perdus.is_empty(), "couple(s) de l'autorité ni servi(s) ni nommé(s) : {perdus:?}");
        // Le canal d'aveu et l'overlay d'une source servie sont imputés à leurs sources, plus rangés « sans source ».
        assert!(!racine.contains_key("lib.sh") && !racine.contains_key("nft-scan-detect.json"), "{racine:?}");
        assert!(racine.contains_key("plume-collector.ps1"), "un émetteur sans source livrée reste nommé : {racine:?}");
        // LIMITE DITE (population fixée au déploiement) : `pid`/`uid` de la source journald de l'agent restent
        // nommés à la racine — ils ne sont imputés à aucune source livrée, même si un `_COMM` suivi en porte le nom.
        let linux: Vec<&str> = racine["source/linux.rs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert!(linux.contains(&"pid") && linux.contains(&"uid"), "{linux:?}");
    }

    /// LE BATTEMENT DE CŒUR ÉCRIT DES CHAMPS NUMÉRIQUES SOUS SA SOURCE. `lib.sh::heartbeat` recopie son 3e argument
    /// tel quel après `"fields":` ; `bans.sh` y met `{\"active_bans\":$nb}`. ORACLE SANS L'EXTRACTEUR : on relit
    /// chaque appel `$(heartbeat <source> … {…})` des capteurs livrés, on prend les clés entre la DERNIÈRE `{` et la
    /// DERNIÈRE `}` de la ligne, et chacune doit être servie sous la source NOMMÉE en 1er argument — pas sous le
    /// fichier qui appelle. Mesuré au second tour de `P11.19-a` : 8 couples manquaient (fail2ban sans `active_bans`,
    /// ufw sans `blocks_seen` ni `rules_allow`, dataaccess/integrity/journal sans `alive`…).
    #[test]
    fn les_champs_du_battement_sont_servis_sous_leur_source() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let appel = regex::Regex::new(r#"\$\(heartbeat\s+"?([A-Za-z0-9_.-]+)"?\s"#).unwrap();
        let cle = regex::Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\\?"\s*:"#).unwrap();
        let mut vus: Vec<(String, String)> = Vec::new();
        let mut manquants: Vec<String> = Vec::new();
        let mut fichiers: Vec<_> = std::fs::read_dir(root.join("collectors")).unwrap().flatten().map(|e| e.path()).collect();
        fichiers.sort();
        for p in fichiers {
            let base = p.file_name().unwrap().to_string_lossy().to_string();
            if !base.ends_with(".sh") || base == "lib.sh" { continue; }
            for l in cesp_lignes_de_code(&root, &format!("collectors/{base}")) {
                let Some(c) = appel.captures(&l) else { continue };
                let source = c[1].to_string();
                let (Some(a), Some(b)) = (l.rfind('{'), l.rfind('}')) else { continue };
                if a > b { continue; }
                for k in cle.captures_iter(&l[a..b]) {
                    let k = k[1].to_string();
                    let servie = crate::handlers::sources::champs_etendus_de_source(&source);
                    if !servie.as_ref().is_some_and(|v| v.contains(&k.as_str())) {
                        manquants.push(format!("{source}:{k} ({base}) servi {servie:?}"));
                    }
                    vus.push((source.clone(), k));
                }
            }
        }
        // La relecture mord : les huit couples mesurés sont vus (sinon ce témoin passerait à vide).
        for (s, k) in [("fail2ban", "active_bans"), ("dataaccess", "alive"), ("integrity", "alive"), ("journal", "alive"),
                       ("origin-drop", "hits_seen"), ("portscan", "scans_seen"), ("ufw", "blocks_seen"), ("ufw", "rules_allow")] {
            assert!(vus.iter().any(|(a, b)| a == s && b == k), "relecture : ({s}, {k}) non vu dans les appels heartbeat — {vus:?}");
        }
        assert!(manquants.is_empty(), "champ(s) du battement non servi(s) sous leur source : {manquants:?}");
    }

    /// LA CLÉ D'ENVELOPPE EST CELLE QUI PRÉCÈDE `\"events\":[` SUR SA LIGNE, PAS TOUTE LA LIGNE. Un capteur qui écrit
    /// un événement sur la même ligne que l'enveloppe garde ses champs dérivés. Racine SYNTHÉTIQUE (les six
    /// répertoires de la surface, un seul capteur) : aucun capteur livré n'a aujourd'hui cette forme.
    #[test]
    fn un_champ_ecrit_sur_la_ligne_d_enveloppe_reste_derive() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cesp-enveloppe");
        for (d, _, _, _) in COLLECTED_SCAN_SURFACE {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(
            tmp.join("collectors/synth.sh"),
            concat!(
                "#!/bin/sh\n",
                "fields=\"{\\\"cesp_p1\\\":\\\"x\\\"}\"\n",
                "printf \"{\\\"ts\\\":%s,\\\"host\\\":\\\"%s\\\",\\\"kind\\\":\\\"events\\\",\\\"events\\\":[{\\\"ts\\\":%s,\\\"source\\\":\\\"synth\\\",\\\"cesp_apres\\\":\\\"%s\\\"}]}\" 1 h 1 v\n",
            ),
        )
        .unwrap();
        let derive = collected_extract_shipped(&tmp);
        let ici: std::collections::BTreeSet<&str> =
            derive.iter().filter(|(_, r, _)| r == "collectors/synth.sh").map(|(f, _, _)| f.as_str()).collect();
        assert!(ici.contains("cesp_p1"), "prémisse : le capteur synthétique est lu ({ici:?})");
        assert!(!ici.contains("kind"), "`kind` précède l'ouverture de l'enveloppe : clé d'enveloppe ({ici:?})");
        assert!(ici.contains("cesp_apres"), "`cesp_apres` suit `\\\"events\\\":[` : champ d'événement, doit rester dérivé ({ici:?})");
    }

    /// UN SAC ASSIGNÉ À UNE VARIABLE PUIS RECOPIÉ SOUS `\"fields\":$VAR` EST SERVI EN ENTIER. Vague D, mesuré par une
    /// revue adverse : `pod-logs.sh` écrit `fj="{\"ns\":…,\"pod\":…,\"container\":…}"` puis `\"fields\":$fj`, et
    /// `k8s-log` était servi sans `ns` — P5 exigeait la virgule devant la clé, donc perdait la PREMIÈRE. ORACLE SANS
    /// L'EXTRACTEUR : on relit chaque affectation shell d'un objet JSON échappé dont la variable est recopiée sous
    /// `\"fields\":`, on prend ses clés de profondeur 1 QUELLE QUE SOIT leur valeur, et chacune doit être servie sous
    /// la source du capteur.
    #[test]
    fn un_sac_assigne_a_une_variable_est_servi_en_entier() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let affectation = regex::Regex::new(r#"^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)="(\{\\".*\})"\s*$"#).unwrap();
        let cle = regex::Regex::new(r#"\\"([A-Za-z_][A-Za-z0-9_]*)\\"\s*:"#).unwrap();
        let mut vus: Vec<(String, String)> = Vec::new();
        let mut manquants: Vec<String> = Vec::new();
        for (source, fichier) in crate::handlers::sources::SOURCES_LIVREES.iter() {
            if !fichier.starts_with("collectors/") || !fichier.ends_with(".sh") { continue; }
            let lignes = cesp_lignes_de_code(&root, fichier);
            let corps = lignes.join("\n");
            for l in &lignes {
                let Some(c) = affectation.captures(l) else { continue };
                let recopie = regex::Regex::new(&format!(r#"\\"fields\\":\$\{{?{}\b"#, &c[1])).unwrap();
                if !recopie.is_match(&corps) { continue; }
                let (mut prof, mut plat) = (0usize, String::new());
                for ch in c[2].chars() {
                    match ch { '{' => prof += 1, '}' => prof -= 1, _ if prof == 1 => plat.push(ch), _ => {} }
                }
                let servie = crate::handlers::sources::champs_etendus_de_source(source);
                for k in cle.captures_iter(&plat) {
                    let k = k[1].to_string();
                    if CIM_CORE_FIELDS.contains(&k.as_str()) { continue; }
                    if !servie.as_ref().is_some_and(|v| v.contains(&k.as_str())) {
                        manquants.push(format!("{source}:{k} ({fichier}) servi {servie:?}"));
                    }
                    vus.push((source.to_string(), k));
                }
            }
        }
        // La relecture mord : le cas mesuré et des sacs d'autres capteurs sont vus (sinon ce témoin passerait à vide).
        for (s, k) in [("k8s-log", "ns"), ("k8s-log", "pod"), ("kube-audit", "verb"), ("yara", "rule"), ("ufw", "dport")] {
            assert!(vus.iter().any(|(a, b)| a == s && b == k), "relecture : ({s}, {k}) non vu — {vus:?}");
        }
        assert!(manquants.is_empty(), "clé(s) d'un sac recopié sous fields non servie(s) sous leur source : {manquants:?}");
    }

    /// LES CLÉS DE TÊTE DE `map` QUE L'INGESTION ÉCRIT DANS LE SAC SONT SERVIES SOUS LA SOURCE DE L'OVERLAY. Vague D,
    /// mesuré par une revue adverse : `dparsers_apply` pose `map.action` dans `fields` (`dfield_put(…, "action", …)`),
    /// mais l'extracteur ne lisait que `map.fields` et `pattern` — `nft` (`"action":"deny"`) et `firewall`
    /// (`"action":"$action"`) étaient servis sans `action`. ORACLE SANS L'EXTRACTEUR : les clés écrites sont relues
    /// sur le TEXTE de parsers.rs (littéraux de `dfield_put(&mut obj, &mut added, "<clé>"`), puis chaque overlay
    /// chargeable qui en porte une (hors colonnes cœur) doit la voir servie sous sa source, ou nommée à la racine.
    #[test]
    fn les_cles_de_tete_de_map_d_un_overlay_sont_servies_sous_sa_source() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let parsers = std::fs::read_to_string(root.join("daemon/src/parsers.rs")).unwrap();
        let ecrit = regex::Regex::new(r#"dfield_put\(&mut obj, &mut added, "([A-Za-z_][A-Za-z0-9_]*)""#).unwrap();
        let lues: std::collections::BTreeSet<String> = ecrit.captures_iter(&parsers).map(|c| c[1].to_string()).collect();
        let extraites: std::collections::BTreeSet<String> = DPARSER_MAP_KEYS_WRITTEN_TO_FIELDS.iter().map(|s| s.to_string()).collect();
        assert_eq!(lues, extraites, "l'extracteur doit lire exactement les clés de `map` que dparsers_apply écrit dans le sac");
        let mut vus = 0;
        let mut manquants: Vec<String> = Vec::new();
        for (overlay, source) in cesp_overlays(&root) {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(root.join(&overlay)).unwrap()).unwrap();
            // Ce que le COMPILATEUR réel admet pour cette clé (pas une recopie de la condition de l'extracteur) :
            // `Some(Lit("…"))` non vide ou `Some(Cap(…))`. `Some(Lit(""))` ne résout jamais.
            // Un overlay sans `map` (parseur regex, `example-nginx.json`) n'est pas déclaratif : aucune clé de tête.
            let compile = crate::parsers::dparser_compile(&source, &v).map(|c| format!("{c:?}")).unwrap_or_default();
            for k in &lues {
                let admise = compile.contains(&format!("{k}: Some(")) && !compile.contains(&format!("{k}: Some(Lit(\"\"))"));
                if CIM_CORE_FIELDS.contains(&k.as_str()) || !admise { continue; }
                vus += 1;
                let base = overlay.rsplit('/').next().unwrap();
                let servie = crate::handlers::sources::champs_etendus_de_source(&source);
                let ok = match &servie {
                    Some(l) => l.contains(&k.as_str()),
                    None => crate::handlers::sources::champs_etendus_sans_source_livree().get(base).is_some_and(|l| l.contains(&k.as_str())),
                };
                if !ok { manquants.push(format!("{source}:{k} ({overlay}) servi {servie:?}")); }
            }
        }
        assert!(vus >= 5, "seulement {vus} clés de tête relues sur les overlays livrés : la relecture ne mord plus");
        assert!(manquants.is_empty(), "clé(s) de `map` écrite(s) dans le sac non servie(s) : {manquants:?}");
        assert!(crate::handlers::sources::champs_etendus_de_source("nft").unwrap().contains(&"action"), "cas mesuré : nft");
        assert!(crate::handlers::sources::champs_etendus_de_source("firewall").unwrap().contains(&"action"), "cas mesuré : firewall");
    }

    /// LE TRI DE LA LISTE SERVIE NE REPOSE PAS SUR L'ORDRE DE LA TABLE. Vague D : retirer le tri restait VERT sur la
    /// table réelle, déjà triée par champ. Des couples dans le désordre, deux fichiers qui répètent un champ.
    #[test]
    fn la_liste_servie_est_triee_meme_si_la_table_ne_l_est_pas() {
        let couples: &[(&'static str, &'static str)] =
            &[("zeta", "x.sh"), ("alpha", "lib.sh"), ("mu", "x.sh"), ("alpha", "x.sh"), ("hors", "y.sh")];
        let v = crate::handlers::sources::champs_des_fichiers(couples, &["collectors/x.sh", "collectors/lib.sh"]);
        assert_eq!(v, vec!["alpha", "mu", "zeta"]);
    }

    /// P6 NE RETIENT QUE LA PROFONDEUR 1 DU 3e ARGUMENT DE `heartbeat`. Vague D : la règle était sans effet sur le
    /// corpus livré (tous les objets passés au battement sont plats), donc admettre toute profondeur restait vert.
    /// Racine SYNTHÉTIQUE : un battement à objet imbriqué.
    #[test]
    fn le_battement_ne_rend_que_ses_cles_de_profondeur_un() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cesp-battement");
        for (d, _, _, _) in COLLECTED_SCAN_SURFACE {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(
            tmp.join("collectors/synth.sh"),
            "#!/bin/sh\nevents=\"$(heartbeat synth \"ok\" '{\"cesp_haut\":1,\"cesp_sac\":{\"cesp_dedans\":2}}')\"\n",
        )
        .unwrap();
        let derive = collected_extract_shipped(&tmp);
        let ici: std::collections::BTreeSet<&str> =
            derive.iter().filter(|(_, r, _)| r == "collectors/synth.sh").map(|(f, _, _)| f.as_str()).collect();
        assert!(ici.contains("cesp_haut") && ici.contains("cesp_sac"), "prémisse : le battement synthétique est lu ({ici:?})");
        assert!(!ici.contains("cesp_dedans"), "`cesp_dedans` est imbriqué : ce n'est pas un `fields.<X>` ({ici:?})");
    }

    /// UNE CLÉ DE TÊTE DE `map` À VALEUR NOMBRE OU BOOLÉEN EST ÉCRITE DANS LE SAC, DONC DÉRIVÉE. Vague D : P3 bis ne
    /// retenait qu'une valeur chaîne, alors que `DMapVal::parse` admet nombre et booléen et que `dparsers_apply` les
    /// écrit (`"action": 1` -> `fields.action = "1"`). ORACLE : l'ingestion réelle (`dparser_compile` + `dparsers_apply`
    /// sur un registre de test), pas la condition de l'extracteur. Racine SYNTHÉTIQUE, un overlay par cas.
    #[test]
    fn une_cle_de_map_a_valeur_scalaire_non_chaine_est_derivee() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cesp-map-scalaire");
        for (d, _, _, _) in COLLECTED_SCAN_SURFACE {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        let cas: &[(&str, Value)] = &[("nombre", json!(1)), ("booleen", json!(true)), ("chaine", json!("deny")), ("vide", json!(""))];
        for (nom, val) in cas {
            let spec = json!({"name": format!("cesp {nom}"), "source": format!("cesp-{nom}"), "enabled": true, "map": {"category": "firewall", "action": val}});
            std::fs::write(tmp.join(format!("config.d/parsers/cesp-{nom}.json")), spec.to_string()).unwrap();
        }
        let derive = collected_extract_shipped(&tmp);
        let registre = format!("{}#cesp-map-scalaire", tmp.join("x").display());
        for (nom, val) in cas {
            let src = format!("cesp-{nom}");
            let spec = json!({"source": src, "map": {"category": "firewall", "action": val}});
            crate::parsers::dparsers_cell().write().insert(registre.clone(), vec![crate::parsers::dparser_compile(&src, &spec).unwrap()]);
            let (fields, _, _) = crate::parsers::dparsers_apply(&registre, &src, "ligne", None);
            let ecrite = fields.and_then(|f| serde_json::from_str::<Value>(&f).ok()).is_some_and(|f| f.get("action").is_some());
            let rel = format!("config.d/parsers/cesp-{nom}.json");
            let derivee = derive.iter().any(|(f, r, _)| f == "action" && *r == rel);
            assert_eq!(derivee, ecrite, "{nom} ({val}) : l'ingestion écrit `action`={ecrite}, l'extracteur la dérive={derivee}");
        }
        crate::parsers::dparsers_cell().write().remove(&registre);
        assert!(derive.iter().any(|(f, r, _)| f == "action" && r == "config.d/parsers/cesp-nombre.json"), "cas mesuré : `\"action\": 1`");
    }

    /// LES CHAMPS DES PARSEURS REGEX ACTIFS SONT LUS SUR LE REGISTRE DE LA BASE — `null` si aucun registre n'est chargé.
    #[test]
    fn les_parseurs_regex_actifs_sont_dits_par_source() {
        let (_tmp, p) = imp_base_disque("cesp-parseurs");
        assert_eq!(crate::handlers::sources::champs_des_parseurs_regex_actifs(&p, "fail2ban"), None, "registre non chargé : inconnu, pas « aucun »");
        let w = open_db(&p).unwrap();
        crate::parsers::parsers_reload(&w, &p);
        let f2b = crate::handlers::sources::champs_des_parseurs_regex_actifs(&p, "fail2ban").unwrap();
        assert!(f2b.contains(&"jail".to_string()) && f2b.contains(&"user".to_string()), "{f2b:?}");
        let web = crate::handlers::sources::champs_des_parseurs_regex_actifs(&p, "web").unwrap();
        assert!(web.contains(&"uid".to_string()) && !web.contains(&"jail".to_string()), "{web:?}");
        assert!(!web.iter().any(|n| CIM_CORE_FIELDS.contains(&n.as_str())), "colonnes cœur exclues : {web:?}");
        // Le filtre « hors colonnes cœur » MORD : le parseur semé crowdsec (migrate.rs, v23) capture `scenario` ET
        // `src_ip` ; `src_ip` est une colonne cœur, elle n'est pas un champ étendu. (Sur `web`, l'assertion
        // ci-dessus est vacante : user/uid seulement.)
        let cs = crate::handlers::sources::champs_des_parseurs_regex_actifs(&p, "crowdsec").unwrap();
        assert!(cs.contains(&"scenario".to_string()), "prémisse : le parseur crowdsec semé est chargé ({cs:?})");
        assert!(!cs.contains(&"src_ip".to_string()), "crowdsec : `src_ip` est une colonne cœur, pas un champ étendu ({cs:?})");
        assert!(crate::handlers::sources::source_a_des_cles_dynamiques("k8s-log") == crate::parsers::generic_sources().iter().any(|s| s == "k8s-log"));
        if std::env::var("PLUME_GENERIC_EXTRACT").is_err() {
            assert!(crate::handlers::sources::source_a_des_cles_dynamiques("k8s-log"), "k8s-log : extraction générique par défaut");
        } else {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "les_parseurs_regex_actifs_sont_dits_par_source",
                "PLUME_GENERIC_EXTRACT est posée dans l'environnement : la valeur PAR DÉFAUT (k8s-log) n'est pas observable ici",
            )
        }
    }

    /// LES PARSEURS REGEX ACTIFS SONT SERVIS TRIÉS ET SANS DOUBLON. Second tour : les témoins ne lisaient que
    /// `contains`, et retirer le tri ou le dédoublonnage restait vert alors que les parseurs SEMÉS répètent des
    /// groupes (sshd : `user`, `rhost`, `user` sur `*`, `uid`, `rhost`). Deux preuves : un registre synthétique
    /// dans le désordre avec doublons (la fonction réelle, sans prémisse sur les graines), puis le registre semé
    /// réel sur `sshd`, dont on relit d'abord qu'il RÉPÈTE bien un groupe (sinon l'assertion serait vacante).
    #[test]
    fn les_parseurs_regex_actifs_sont_servis_tries_et_sans_doublon() {
        let cle = "cesp-parseurs-synthetiques#tri";
        let re = |m: &str| regex::Regex::new(m).unwrap();
        crate::parsers::parsers_cell().write().insert(
            cle.to_string(),
            vec![
                ("cesp".to_string(), re(r"(?P<zeta>z) (?P<alpha>a)")),
                ("*".to_string(), re(r"(?P<mu>m) (?P<alpha>a)")),
                ("autre".to_string(), re(r"(?P<hors>h)")),
                ("cesp".to_string(), re(r"(?P<zeta>z) (?P<src_ip>i)")),
            ],
        );
        let v = crate::handlers::sources::champs_des_parseurs_regex_actifs(cle, "cesp");
        crate::parsers::parsers_cell().write().remove(cle);
        assert_eq!(v, Some(vec!["alpha".to_string(), "mu".to_string(), "zeta".to_string()]));

        let (_tmp, p) = imp_base_disque("cesp-parseurs-sshd");
        let w = open_db(&p).unwrap();
        crate::parsers::parsers_reload(&w, &p);
        let bruts: Vec<String> = crate::parsers::parsers_cell().read()[&p]
            .iter()
            .filter(|(s, _)| s == "*" || s == "sshd")
            .flat_map(|(_, r)| r.capture_names().flatten().map(str::to_string).collect::<Vec<_>>())
            .filter(|n| !CIM_CORE_FIELDS.contains(&n.as_str()))
            .collect();
        let uniques: std::collections::BTreeSet<&String> = bruts.iter().collect();
        assert!(uniques.len() < bruts.len(), "prémisse : les parseurs semés sur sshd répètent un groupe ({bruts:?})");
        let servi = crate::handlers::sources::champs_des_parseurs_regex_actifs(&p, "sshd").unwrap();
        let attendu: Vec<String> = uniques.into_iter().cloned().collect();
        assert_eq!(servi, attendu, "sshd : servi trié et sans doublon");
        crate::parsers::parsers_cell().write().remove(&p);
    }

    /// LES LISTES « SANS SOURCE LIVRÉE » SONT TRIÉES MÊME SI LA TABLE NE L'EST PAS. Second tour : la table réelle,
    /// triée par champ, laissait un tri retiré (ou inversé) au vert. Couples dans le désordre, un doublon.
    #[test]
    fn les_listes_sans_source_livree_sont_triees_meme_si_la_table_ne_l_est_pas() {
        let couples: &[(&'static str, &'static str)] =
            &[("zeta", "orphelin.ps1"), ("alpha", "orphelin.ps1"), ("mu", "orphelin.ps1"), ("alpha", "orphelin.ps1"), ("porte", "x.sh")];
        let m = crate::handlers::sources::couples_sans_porte(couples, &["collectors/x.sh"]);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m["orphelin.ps1"], vec!["alpha", "mu", "zeta"]);
    }

    /// LA LIGNE D'ENVELOPPE EST CELLE DU FRAGMENT, PAS LA PREMIÈRE DU FICHIER. Second tour : un seul fichier livré par
    /// capteur porte une ligne `\"events\":[`, donc borner la recherche au début du FICHIER restait vert. Racine
    /// SYNTHÉTIQUE : un capteur à DEUX enveloppes ; la clé qui précède la seconde est une clé d'enveloppe.
    #[test]
    fn la_clef_qui_precede_une_seconde_enveloppe_n_est_pas_derivee() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cesp-deux-enveloppes");
        for (d, _, _, _) in COLLECTED_SCAN_SURFACE {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(
            tmp.join("collectors/synth.sh"),
            concat!(
                "#!/bin/sh\n",
                "fields=\"{\\\"cesp_p1\\\":\\\"x\\\"}\"\n",
                "printf \"{\\\"cesp_env_a\\\":\\\"e\\\",\\\"events\\\":[{\\\"cesp_apres_a\\\":\\\"%s\\\"}]}\" v\n",
                "printf \"{\\\"cesp_env_b\\\":\\\"e\\\",\\\"events\\\":[{\\\"cesp_apres_b\\\":\\\"%s\\\"}]}\" v\n",
            ),
        )
        .unwrap();
        let derive = collected_extract_shipped(&tmp);
        let ici: std::collections::BTreeSet<&str> =
            derive.iter().filter(|(_, r, _)| r == "collectors/synth.sh").map(|(f, _, _)| f.as_str()).collect();
        assert!(ici.contains("cesp_p1") && ici.contains("cesp_apres_a") && ici.contains("cesp_apres_b"), "prémisse : le capteur est lu ({ici:?})");
        assert!(!ici.contains("cesp_env_a"), "1re enveloppe : clé d'enveloppe ({ici:?})");
        assert!(!ici.contains("cesp_env_b"), "2e enveloppe : clé d'enveloppe, la ligne est celle du fragment ({ici:?})");
    }
