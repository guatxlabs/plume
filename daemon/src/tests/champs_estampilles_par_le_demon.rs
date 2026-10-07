    // ================================================================================================
    // `P11.19-a` (vague E) — CE QUE LE DÉMON ÉCRIT LUI-MÊME DANS `fields`, ET LES CAPTEURS QUI EMPRUNTENT
    // UNE SOURCE. Mesuré à la revue de la vague D : un événement `yara` ingéré porte en base `cim`, que ni sa
    // liste `champs_etendus`, ni ses parseurs actifs, ni aucun aveu de la racine ne nommaient ; de même
    // `threat_intel`/`ti_*` sur correspondance d'IOC et `reclasse`/`severite_origine` sous `integrity`.
    // Témoins :
    //   1. PAR L'INGESTION RÉELLE (`ingest_events_batch` puis `sources_inventory`) : toute clé portée en base
    //      sous une source livrée est servie par sa liste, ses parseurs actifs, ou la famille estampillée qui
    //      vise cette source ; et, dans l'autre sens, chaque clé estampillée servie est OBSERVÉE en base ;
    //   2. les aveux de la racine nomment la liste à part, RENAME et le normaliseur endpoint ;
    //   3. le FIM de l'agent émet sous une source LIVRÉE par défaut (relue dans `agent/src/config.rs`) et
    //      l'aveu la nomme ; les clés que `collector-mail` écrit sous `mail` hors de la liste `mail` sont
    //      EXACTEMENT celles de l'aveu (relues dans `collector-mail/src/main.rs`).
    // Mutants joués par VERIF_MUT (rouges, retirés avant le commit) : `E1_SANS_CORRECTIF` (liste à part vide, aveux
    // ramenés aux sept d'avant), `E1_SANS_CIM`, `E1_TI_FANTOME`, `E1_TI_MANQUE`, `E1_RECLASSE_AILLEURS` (famille
    // integrity servie sous ufw), `E1_SANS_AVEU_FIM`, `E1_SANS_AVEU_RENAME`, `E1_AVEU_MAIL_MANQUE` (msgid retiré).
    // Reprise (vague E, correction) : les voies HEC, OTLP et journald sont jouées pour de vrai, la threat-intel sous
    // trois sources, un dépôt d'unité hors integrity en témoin négatif, et le champ `sources` est tenu (servie sous
    // une source : observée sous elle seule ; sous `*` : sous deux sources au moins). Mutants : `E1_M_SANS_CORRECTIF`,
    // `E1_M_HEC_ABSENT`, `E1_M_OTLP_TRACE_ID`, `E1_M_OTLP_FANTOME`, `E1_M_JOURNAL_UNIT`, `E1_M_TI_UFW`,
    // `E1_M_RECLASSE_ETOILE`, `E1_M_AVEU_JOURNAL` (l'aveu journald d'avant, qui citait source/linux.rs).
    // ================================================================================================

    /// Les clés de premier niveau d'un sac JSON relu en base.
    fn cepd_cles(sac: &str) -> Vec<String> {
        serde_json::from_str::<serde_json::Map<String, Value>>(sac).map(|m| m.keys().cloned().collect()).unwrap_or_default()
    }

    #[tokio::test]
    async fn chaque_cle_portee_en_base_est_listee_ou_estampillee_par_le_demon() {
        let livrees = crate::handlers::sources::SOURCES_LIVREES;
        let (_tmp, p) = imp_base_disque("cepd-p1119a");
        let racine_depot = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        {
            let w = open_db(&p).unwrap();
            crate::parsers::parsers_reload(&w, &p);
            for (s, _) in livrees.iter() {
                w.execute(
                    "INSERT INTO source_settings(scope,source,expected,updated,updated_by,expected_par,expected_le) VALUES('global',?1,1,1700000000,'eve','eve',1700000000)",
                    params![s],
                )
                .unwrap();
            }
            // Un déploiement daté (la base porte la signature d'un build antérieur) : ouvre la fenêtre du reclassement.
            w.execute(
                "INSERT INTO meta(key,value) VALUES(?1,'signature-du-build-anterieur') ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![CLE_META_SIGNATURE],
            )
            .unwrap();
            noter_le_build_en_cours(&w, &p);
            let fait = fait_de_deploiement(&p);
            assert!(fait > 0, "prémisse : le déploiement est daté");
            // Un indicateur au magasin : une correspondance enrichit l'événement.
            w.execute(
                "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,env_id) VALUES('ip','203.0.113.9','cepd-feed',80,3,?1,?1,NULL,'prod')",
                params![now()],
            )
            .unwrap();
            ioc_cache_reload(&w, &p);

            let t = now();
            let mut evts: Vec<Value> = Vec::new();
            // Chaque source livrée à liste non vide, avec EXACTEMENT les clés de sa liste.
            for (s, _) in livrees.iter() {
                let Some(liste) = crate::handlers::sources::champs_etendus_de_source(s) else { continue };
                if liste.is_empty() || *s == crate::SOURCE_INTEGRITE {
                    continue;
                }
                let sac: serde_json::Map<String, Value> = liste.iter().map(|k| (k.to_string(), json!("x"))).collect();
                evts.push(json!({ "ts": t, "source": s, "category": "cepd", "severity": 1, "message": "cepd", "fields": sac, "dedup": format!("cepd-{s}") }));
            }
            // Une correspondance d'IOC sous DEUX sources livrées (la famille threat-intel vise toute source ; la
            // voie journald en ajoute une troisième plus bas).
            evts.push(json!({ "ts": t, "source": "ufw", "category": "cepd", "severity": 1, "message": "cepd ti", "src_ip": "203.0.113.9", "dedup": "cepd-ti" }));
            evts.push(json!({ "ts": t, "source": "yara", "category": "cepd", "severity": 1, "message": "cepd ti yara", "src_ip": "203.0.113.9", "dedup": "cepd-ti-yara" }));
            // TÉMOIN NÉGATIF : le MÊME dépôt d'unité livrée, dans la fenêtre, mais hors integrity : jamais reclassé.
            evts.push(json!({
                "ts": fait + 60, "source": "ufw", "category": "cepd-neg", "severity": 3,
                "message": format!("unit systemd ajout (persistance) : /etc/systemd/system/{}", "plume-integrity.service"),
                "fields": { "kind": "unit", "path": "/etc/systemd/system/plume-integrity.service",
                            "sha256": sha256_hex(&std::fs::read(racine_depot.join("systemd").join("plume-integrity.service")).expect("unité livrée lisible")),
                            "scope": "host", "change": "ajout" },
                "dedup": "cepd-neg-unit",
            }));
            // VOIE HEC RÉELLE (`hec_record_to_event`, comme `hec_post`) sous deux sources livrées : le démon copie
            // sourcetype et index dans le sac.
            let sans_surcharge: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            for s in ["web", "ufw"] {
                let rec = json!({ "time": t, "source": s, "sourcetype": "access_combined", "index": "main", "event": format!("cepd hec {s}") });
                evts.push(hec_record_to_event(&rec, &sans_surcharge).expect("enregistrement HEC exploitable"));
            }
            // VOIE OTLP RÉELLE (`otlp_request_to_events`, comme `otlp_traces_post`) : deux services nommés comme des
            // sources livrées, chaque champ de trace optionnel présent.
            let span = |n: u8| json!({
                "traceId": format!("{:032x}", 0xa0 + n as u32), "spanId": format!("{:016x}", 0xb0 + n as u32),
                "parentSpanId": format!("{:016x}", 0xc0 + n as u32), "name": format!("cepd-span-{n}"), "kind": 2,
                "startTimeUnixNano": format!("{}", (t as i128) * 1_000_000_000), "endTimeUnixNano": format!("{}", (t as i128) * 1_000_000_000 + 5_000_000),
                "status": { "code": 2, "message": "cepd" },
            });
            let requete = json!({ "resourceSpans": [
                { "resource": { "attributes": [ { "key": "service.name", "value": { "stringValue": "web" } } ] },
                  "scopeSpans": [ { "scope": { "name": "cepd-scope", "version": "1" }, "spans": [ span(1) ] } ] },
                { "resource": { "attributes": [ { "key": "service.name", "value": { "stringValue": "yara" } } ] },
                  "scopeSpans": [ { "scope": { "name": "cepd-scope", "version": "1" }, "spans": [ span(2) ] } ] },
            ] });
            let spans = otlp_request_to_events(&requete, 100).expect("requête OTLP sous le plafond");
            assert_eq!(spans.len(), 2, "prémisse : deux spans convertis");
            evts.extend(spans);
            // Le dépôt d'une unité LIVRÉE, dans la fenêtre : la forme exacte qu'écrit integrity.sh.
            let nom = "plume-integrity.service";
            let empreinte = sha256_hex(&std::fs::read(racine_depot.join("systemd").join(nom)).expect("unité livrée lisible"));
            let chemin = format!("/etc/systemd/system/{nom}");
            evts.push(json!({
                "ts": fait + 60, "source": "integrity", "category": "integrity", "severity": 3,
                "message": format!("unit systemd ajout (persistance) : {chemin}"),
                "fields": { "kind": "unit", "path": chemin, "sha256": empreinte, "scope": "host", "change": "ajout" },
            }));
            ingest_events_batch(&w, &p, &evts, t, None, None).expect("lot ingéré");
            // VOIE JOURNALD RÉELLE (`ingest_journal_lines`, ce que sert /api/ingest/journal) : _COMM nomme deux
            // sources livrées ; la ligne crowdsec porte l'adresse de l'IOC (troisième source enrichie).
            let journal = [("crowdsec", "cepd journal from 203.0.113.9", "c1"), ("ufw", "cepd journal ufw", "c2")]
                .iter()
                .map(|(comm, msg, cur)| json!({ "__REALTIME_TIMESTAMP": format!("{}", t * 1_000_000), "_COMM": comm, "MESSAGE": msg, "PRIORITY": "6", "_PID": "42", "_UID": "0", "_SYSTEMD_UNIT": format!("{comm}.service"), "__CURSOR": format!("cepd-{cur}") }).to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(ingest_journal_lines(&w, &p, &journal, None).ok(), Some(2), "prémisse : deux lignes journald ingérées");
            let reclasse: i64 = w
                .query_row("SELECT COUNT(*) FROM event WHERE source='integrity' AND severity=?1", params![SEVERITE_RECLASSEE], |r| r.get(0))
                .unwrap();
            assert_eq!(reclasse, 1, "prémisse : le dépôt corroboré est reclassé");
            let ti: i64 = w.query_row("SELECT COUNT(*) FROM event WHERE json_extract(fields,'$.ti_match')=1", [], |r| r.get(0)).unwrap();
            assert_eq!(ti, 3, "prémisse : la correspondance d'IOC a enrichi un événement sous ufw, yara et crowdsec");
            let neg: (i64, i64) = w
                .query_row("SELECT severity, json_extract(fields,'$.reclasse') IS NOT NULL FROM event WHERE category='cepd-neg'", [], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            assert_eq!(neg, (3, 0), "témoin négatif : un dépôt d'unité hors integrity n'est jamais reclassé");
            rollup_events(&w);
        }
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        assert_eq!(v["ok"], true, "{v}");
        let servies: std::collections::BTreeMap<String, Value> =
            v["sources"].as_array().unwrap().iter().map(|e| (e["source"].as_str().unwrap().to_string(), e.clone())).collect();
        let familles = v["champs_etendus_estampilles_par_le_demon"].as_array().expect("racine : clés estampillées par le démon").clone();
        for f in &familles {
            let champs: Vec<&str> = f["champs"].as_array().expect("champs").iter().map(|x| x.as_str().unwrap()).collect();
            let mut tries = champs.clone();
            tries.sort_unstable();
            tries.dedup();
            assert_eq!(champs, tries, "famille servie triée et sans doublon : {f}");
            assert!(f["sources"].is_string() && f["quand"].is_string() && f["code"].is_string(), "{f}");
        }
        let estampillees_sous = |source: &str| -> std::collections::BTreeSet<String> {
            familles
                .iter()
                .filter(|f| f["sources"] == "*" || f["sources"] == source)
                .flat_map(|f| f["champs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()))
                .collect()
        };

        // (1) SENS « BASE -> SERVI » : toute clé portée en base sous une source livrée est nommée quelque part.
        let (lignes, negatives): (Vec<(String, String)>, Vec<(String, String)>) = {
            let c = open_db(&p).unwrap();
            // Les seules lignes du lot : le démon écrit aussi ses propres événements (`plume-config`…) dans cette
            // base. Les voies HEC, OTLP et journald posent leur propre catégorie : reconnues au message.
            let mut s = c
                .prepare("SELECT source, COALESCE(fields,'{}'), category='cepd-neg' FROM event WHERE category IN ('cepd','cepd-neg') OR message LIKE 'cepd%' OR (source='integrity' AND message LIKE 'unit systemd%')")
                .unwrap();
            let toutes: Vec<(String, String, bool)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<Result<_, _>>().unwrap();
            let (n, l): (Vec<_>, Vec<_>) = toutes.into_iter().partition(|(_, _, neg)| *neg);
            (l.into_iter().map(|(a, b, _)| (a, b)).collect(), n.into_iter().map(|(a, b, _)| (a, b)).collect())
        };
        assert_eq!(negatives.len(), 1, "prémisse : le témoin négatif est en base");
        // Prémisse par voie, sur SES lignes (reconnues au message) et une clé que la famille porte : ni `champs[0]`
        // partagé avec des listes, ni repli quand la famille manque (second tour, vague E).
        {
            let c = open_db(&p).unwrap();
            for (code, prefixe, cle, n) in [("hec.rs", "cepd hec", "index", 2), ("otlp.rs", "cepd-span", "trace_id", 2), ("ingest_journal_lines", "cepd journal", "pid", 2)] {
                let f = familles.iter().find(|f| f["code"].as_str().unwrap().contains(code)).unwrap_or_else(|| panic!("famille {code} servie"));
                assert!(f["champs"].as_array().unwrap().iter().any(|x| x.as_str() == Some(cle)), "la famille {code} porte {cle}");
                let vues: i64 = c
                    .query_row("SELECT COUNT(*) FROM event WHERE message LIKE ?1 || '%' AND json_extract(fields, '$.' || ?2) IS NOT NULL", params![prefixe, cle], |r| r.get(0))
                    .unwrap();
                assert!(vues >= n, "prémisse : la voie {code} a écrit {vues} ligne(s) portant {cle}");
            }
        }
        assert!(lignes.len() > 10, "prémisse : le lot couvre les sources livrées ({} lignes)", lignes.len());
        let mut tues: Vec<String> = Vec::new();
        let mut observees: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
        for (source, sac) in &lignes {
            let e = servies.get(source).unwrap_or_else(|| panic!("{source} : ingérée, absente de l'inventaire"));
            let liste: std::collections::BTreeSet<String> = e["champs_etendus"]
                .as_array()
                .unwrap_or_else(|| panic!("{source} : liste null, le témoin n'ingère que des sources couvertes"))
                .iter()
                .chain(e["champs_etendus_parseurs_actifs"].as_array().into_iter().flatten())
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let estampillees = estampillees_sous(source);
            for k in cepd_cles(sac) {
                observees.insert((source.clone(), k.clone()));
                if !liste.contains(&k) && !estampillees.contains(&k) {
                    tues.push(format!("{source}.{k}"));
                }
            }
        }
        tues.sort();
        tues.dedup();
        assert!(tues.is_empty(), "clé(s) portée(s) en base, ni listée(s) ni servie(s) comme estampillée(s) par le démon : {tues:?}");

        // (2) SENS « SERVI -> BASE » : chaque clé estampillée servie est observée sous une source qu'elle vise.
        for f in &familles {
            for k in f["champs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()) {
                let vue = observees.iter().any(|(s, c)| c == k && (f["sources"] == "*" || f["sources"] == s.as_str()));
                assert!(vue, "clé estampillée servie ({k}, sources {}) jamais écrite par l'ingestion réelle", f["sources"]);
            }
        }
        assert!(!familles.is_empty(), "la liste à part est servie");
        // (3) LE CHAMP `sources` DE CHAQUE FAMILLE EST EXACT. Servie sous une source précise : ses clés, hors de la
        // liste et des parseurs actifs, ne sont observées QUE sous elle (le témoin négatif y contribue). Servie
        // sous `*` : chacune est observée sous au moins deux sources distinctes.
        let mut expliquee_hors_liste: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
        for (source, sac) in lignes.iter().chain(negatives.iter()) {
            let e = &servies[source];
            let liste: std::collections::BTreeSet<String> = e["champs_etendus"].as_array().into_iter().flatten()
                .chain(e["champs_etendus_parseurs_actifs"].as_array().into_iter().flatten())
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            for k in cepd_cles(sac) {
                if !liste.contains(&k) {
                    expliquee_hors_liste.insert((source.clone(), k));
                }
            }
        }
        for f in &familles {
            for k in f["champs"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()) {
                if f["sources"] == "*" {
                    let sous: std::collections::BTreeSet<&String> = observees.iter().filter(|(_, c)| c == k).map(|(s, _)| s).collect();
                    assert!(sous.len() >= 2, "famille servie sous `*` ({}) : {k} observée sous {sous:?} seulement", f["code"]);
                } else {
                    let sous: std::collections::BTreeSet<&str> =
                        expliquee_hors_liste.iter().filter(|(_, c)| c == k).map(|(s, _)| s.as_str()).collect();
                    let attendu: std::collections::BTreeSet<&str> = [f["sources"].as_str().unwrap()].into_iter().collect();
                    assert_eq!(sous, attendu, "famille servie sous {} ({}) : {k} écrite par le démon sous d'autres sources", f["sources"], f["code"]);
                }
            }
        }

        // La version CIM est sur CHAQUE ligne (ce que la revue a mesuré manquant sous `yara`).
        assert!(lignes.iter().all(|(_, sac)| cepd_cles(sac).iter().any(|k| k == "cim")), "prémisse : cim estampillé partout");
    }

    /// LES AVEUX DE LA RACINE NOMMENT LA LISTE À PART ET LES DEUX VOIES D'EXPLOITANT QUI AJOUTENT UNE CLÉ.
    #[tokio::test]
    async fn les_aveux_nomment_les_cles_estampillees_rename_et_le_normaliseur_endpoint() {
        let (_tmp, p) = imp_base_disque("cepd-aveux");
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        let aveux: Vec<&str> = v["champs_etendus_ne_voit_pas"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        for mot in ["champs_etendus_estampilles_par_le_demon", "RENAME", "PLUME_ENDPOINT_NORMALIZE"] {
            assert!(aveux.iter().any(|a| a.contains(mot)), "aucun aveu ne nomme {mot} : {aveux:?}");
        }
        assert!(v["champs_etendus_estampilles_par_le_demon"].is_array(), "{v}");
        // L'aveu journald nomme l'ÉCRIVAIN RÉEL (le démon, `ingest_journal_lines`) et CHAQUE clé qu'il écrit, pas
        // `source/linux.rs` (qui ne sert qu'aux tests et à test-ship).
        let journal = aveux.iter().find(|a| a.contains("_COMM")).expect("aveu journald");
        assert!(journal.contains("ingest_journal_lines") && !journal.contains("linux.rs"), "aveu journald inexact : {journal}");
        let famille = crate::handlers::sources::champs_estampilles_par_le_demon()
            .into_iter()
            .find(|f| f.code.contains("ingest_journal_lines"))
            .expect("famille journald");
        let entre = journal.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("aveu journald : liste entre crochets");
        let nommees: Vec<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(nommees, famille.champs, "l'aveu journald doit nommer EXACTEMENT les clés que le démon écrit : {journal}");
    }

    /// LE FIM DE L'AGENT ET COLLECTOR-MAIL ÉMETTENT SOUS UNE SOURCE LIVRÉE QUI N'EST PAS LA LEUR : l'aveu est exact.
    #[test]
    fn les_capteurs_qui_empruntent_une_source_livree_sont_avoues_exactement() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let aveux = crate::handlers::sources::champs_etendus_ne_voit_pas();

        // FIM : l'id par défaut, relu dans le texte de l'agent.
        let config = std::fs::read_to_string(racine.join("agent/src/config.rs")).expect("agent/src/config.rs");
        let ligne = config.lines().find(|l| l.contains("fn d_fim_id()")).expect("d_fim_id présent");
        let id = ligne.split('"').nth(1).expect("id littéral");
        assert!(
            crate::handlers::sources::SOURCES_LIVREES.iter().any(|(s, _)| *s == id),
            "prémisse : l'id FIM par défaut ({id}) est une source livrée"
        );
        assert!(
            crate::handlers::sources::champs_etendus_sans_source_livree().contains_key("fim/mod.rs"),
            "prémisse : les champs du FIM sont rangés sans source livrée"
        );
        assert!(
            aveux.iter().any(|a| a.contains("fim/mod.rs") && a.contains(&format!("« {id} »"))),
            "aucun aveu ne dit que le FIM de l'agent émet sous « {id} » : {aveux:?}"
        );

        // collector-mail : les clés des sacs `fields` des événements émis sous `"source": "mail"`.
        let texte = std::fs::read_to_string(racine.join("collector-mail/src/main.rs")).expect("collector-mail/src/main.rs");
        let lignes: Vec<&str> = texte.lines().collect();
        let mut emises: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut sous_mail = false;
        let mut dans_sac = false;
        for l in &lignes {
            let t = l.trim();
            if t.starts_with("\"source\":") {
                sous_mail = t.contains("\"mail\"");
            }
            if sous_mail && t.starts_with("\"fields\": {") {
                dans_sac = true;
            }
            if dans_sac {
                let corps = t.trim_start_matches("\"fields\": {");
                for morceau in corps.split(',') {
                    let m = morceau.trim();
                    if let Some(rest) = m.strip_prefix('"') {
                        if let Some((k, apres)) = rest.split_once('"') {
                            if apres.trim_start().starts_with(':') {
                                emises.insert(k.to_string());
                            }
                        }
                    }
                }
                if t.contains('}') {
                    dans_sac = false;
                    sous_mail = false;
                }
            }
        }
        assert!(emises.len() >= 6 && emises.contains("msgid"), "prémisse : sacs de collector-mail relus ({emises:?})");
        let liste_mail: std::collections::BTreeSet<String> =
            crate::handlers::sources::champs_etendus_de_source("mail").expect("mail couverte").iter().map(|s| s.to_string()).collect();
        let hors_liste: std::collections::BTreeSet<String> = emises.difference(&liste_mail).cloned().collect();
        let aveu = aveux.iter().find(|a| a.contains("collector-mail")).expect("aveu collector-mail");
        let entre = aveu.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("liste entre crochets");
        let avouees: std::collections::BTreeSet<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(avouees, hors_liste, "l'aveu collector-mail doit nommer EXACTEMENT les clés émises sous mail hors de sa liste");
        assert!(aveu.contains(" mail "), "l'aveu nomme la source empruntée : {aveu}");
    }
