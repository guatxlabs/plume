    // ================================================================================================
    // `P11.19-a` (vague E, second tour) — CHAQUE AVEU DE LA RACINE EST TENU PAR UN MOT QUI LUI EST PROPRE, ET LES
    // PRESETS DE CONNECTEUR LIVRÉS SONT AVOUÉS EXACTEMENT. Mesuré à la vérification du premier tour : l'aveu des
    // voies ouvertes et l'aveu « liste à part » ne partageaient qu'un mot (`champs_etendus_estampilles_par_le_demon`)
    // avec l'aveu journald ; les retirer laissait tout vert. Et le preset livré `cloudflare-audit` écrit sous la
    // source livrée `cloudflare` quatre clés qu'aucune liste, famille ni aveu ne nommait.
    // Mutants joués par VERIF_MUT (rouges, retirés avant le commit) : `E1C2_SANS_OUVERTES` (aveu des voies ouvertes
    // retiré), `E1C2_OUVERTES_SANS_HEC` (ramené à /api/ingest seul), `E1C2_SANS_LISTE` (aveu « liste à part »
    // retiré), `E1C2_SANS_PRESET` (aveu connecteur retiré), `E1C2_PRESET_INCOMPLET` (metadata retiré de l'aveu),
    // `E1C2_HEC_SANS_HTTPPULL` (famille HEC qui ne cite plus httppull.rs), `E1C2_FIM_SANS_VERDICT`.
    // ================================================================================================

    /// Les mots propres de chaque aveu : le PREMIER n'apparaît dans aucun autre aveu, tous apparaissent dans le
    /// même. Un aveu par entrée, dans les deux sens : un aveu retiré, ou ajouté sans entrée ici, rougit.
    const AMP_MOTS_PROPRES: &[&[&str]] = &[
        &["champs_etendus_parseurs_actifs", "/api/parsers"],
        &["champs_etendus_cles_dynamiques", "logfmt"],
        &["déposé par l'exploitant après déploiement", "overlay"],
        &["_COMM", "ingest_journal_lines"],
        &["voies d'ingestion ouvertes", "/api/ingest", "HEC", "OTLP", "Loki", "ingest/obs.rs"],
        &["commentaire de fin de ligne"],
        &["\"$SOURCE\"", "custom.sh"],
        &["bans.sh", "crowdsec"],
        &["fim/mod.rs", "d_fim_id", "event_indisponibilite"],
        &["collector-mail"],
        &["version CIM", "threat-intel", "reclassement", "champs_etendus_estampilles_par_le_demon"],
        &["RENAME", "MASK"],
        &["cloudflare-audit", "field_map", "httppull_map_record"],
        &["PLUME_ENDPOINT_NORMALIZE", "ingest/endpoint.rs"],
    ];

    #[tokio::test]
    async fn chaque_aveu_de_la_racine_est_tenu_par_un_mot_qui_lui_est_propre() {
        let (_tmp, p) = imp_base_disque("amp-aveux");
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        let servis: Vec<&str> = v["champs_etendus_ne_voit_pas"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(servis, crate::handlers::sources::champs_etendus_ne_voit_pas(), "la route sert la porte de lecture des aveux");
        assert_eq!(servis.len(), AMP_MOTS_PROPRES.len(), "un aveu par entrée de mots propres : {servis:#?}");
        let mut tenus: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for mots in AMP_MOTS_PROPRES {
            let porteurs: Vec<usize> = (0..servis.len()).filter(|i| servis[*i].contains(mots[0])).collect();
            assert_eq!(porteurs.len(), 1, "le mot propre « {} » doit être porté par UN aveu exactement : {porteurs:?}", mots[0]);
            let aveu = servis[porteurs[0]];
            for m in mots.iter() {
                assert!(aveu.contains(m), "l'aveu de « {} » doit nommer « {m} » : {aveu}", mots[0]);
            }
            tenus.insert(porteurs[0]);
        }
        assert_eq!(tenus.len(), servis.len(), "chaque aveu servi est tenu par sa propre entrée");
    }

    /// Construit un enregistrement vendeur où chaque chemin pointé du field_map vaut une chaîne (les constantes `=`
    /// et les chemins non pointés simples sont ignorés ou posés tels quels).
    fn amp_enregistrement_pour(field_map: &serde_json::Map<String, Value>) -> Value {
        let mut rec = serde_json::Map::new();
        for spec in field_map.values().filter_map(|s| s.as_str()) {
            if spec.starts_with('=') || spec.contains('[') || spec.contains('$') {
                continue;
            }
            let parties: Vec<&str> = spec.split('.').collect();
            let mut cur = &mut rec;
            for (i, part) in parties.iter().enumerate() {
                if i + 1 == parties.len() {
                    let valeur = if *part == "when" { json!("2026-10-07T00:00:00Z") } else { json!(format!("amp-{part}")) };
                    cur.entry(part.to_string()).or_insert(valeur);
                } else {
                    let e = cur.entry(part.to_string()).or_insert_with(|| json!({}));
                    if !e.is_object() {
                        *e = json!({});
                    }
                    cur = e.as_object_mut().unwrap();
                }
            }
        }
        Value::Object(rec)
    }

    /// LES PRESETS LIVRÉS QUI ÉCRIVENT SOUS UNE SOURCE LIVRÉE : chaque clé qu'ils posent est servie (liste, parseurs
    /// actifs, famille estampillée qui cite httppull.rs) ou avouée ; l'aveu connecteur nomme EXACTEMENT les clés
    /// restantes, et chaque preset concerné. Joué par le mappage réel (`httppull_map_record`) puis l'ingestion réelle.
    #[tokio::test]
    async fn les_presets_livres_sous_une_source_livree_sont_servis_ou_avoues_exactement() {
        let livrees = crate::handlers::sources::SOURCES_LIVREES;
        let (_tmp, p) = imp_base_disque("amp-presets");
        let mut concernes: Vec<(&str, String)> = Vec::new();
        {
            let w = open_db(&p).unwrap();
            crate::parsers::parsers_reload(&w, &p);
            let mut evts: Vec<Value> = Vec::new();
            for preset in PRESETS.iter() {
                let brut: Value = serde_json::from_str(preset.raw).expect("preset livré : JSON");
                let cfg = HttpPullCfg::from_json(&brut);
                let Some(fm) = brut["field_map"].as_object() else { continue };
                let rec = amp_enregistrement_pour(fm);
                let ev = httppull_map_record(&rec, &cfg, 7).expect("record mappé");
                let source = ev["source"].as_str().unwrap().to_string();
                if !livrees.iter().any(|(s, _)| *s == source) {
                    continue;
                }
                w.execute(
                    "INSERT INTO source_settings(scope,source,expected,updated,updated_by,expected_par,expected_le) VALUES('global',?1,1,1700000000,'eve','eve',1700000000) ON CONFLICT DO NOTHING",
                    params![source],
                )
                .unwrap();
                concernes.push((preset.id, source));
                evts.push(ev);
            }
            assert!(concernes.iter().any(|(id, s)| *id == "cloudflare-audit" && s == "cloudflare"), "prémisse : cloudflare-audit écrit sous cloudflare ({concernes:?})");
            ingest_events_batch(&w, &p, &evts, now(), None, None).expect("lot ingéré");
            rollup_events(&w);
        }
        let st = ds_file_state(&p);
        let v = sources_inventory(State(st), Extension(sac_au("viewer", "v"))).await.0;
        let familles = v["champs_etendus_estampilles_par_le_demon"].as_array().unwrap().clone();
        let aveux: Vec<String> = v["champs_etendus_ne_voit_pas"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let aveu = aveux.iter().find(|a| a.contains("cloudflare-audit")).expect("aveu des presets de connecteur");
        let entre = aveu.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("aveu connecteur : liste entre crochets");
        let avouees: std::collections::BTreeSet<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

        let c = open_db(&p).unwrap();
        let mut hors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (id, source) in &concernes {
            assert!(aveu.contains(id) && aveu.contains(&format!(" {source} ")), "l'aveu connecteur nomme le preset {id} et sa source {source} : {aveu}");
            let e = v["sources"].as_array().unwrap().iter().find(|e| e["source"] == source.as_str()).expect("source servie").clone();
            let liste: std::collections::BTreeSet<String> = e["champs_etendus"]
                .as_array()
                .expect("source livrée à liste close")
                .iter()
                .chain(e["champs_etendus_parseurs_actifs"].as_array().into_iter().flatten())
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let sac: String = c.query_row("SELECT fields FROM event WHERE source=?1 AND message LIKE 'amp-%'", params![source], |r| r.get(0)).unwrap();
            let cles: Vec<String> = serde_json::from_str::<serde_json::Map<String, Value>>(&sac).unwrap().keys().cloned().collect();
            assert!(cles.len() >= 4, "prémisse : le preset {id} a écrit son sac ({cles:?})");
            for k in cles {
                if liste.contains(&k) {
                    continue;
                }
                let famille = familles.iter().find(|f| {
                    (f["sources"] == "*" || f["sources"] == source.as_str()) && f["champs"].as_array().unwrap().iter().any(|x| x.as_str() == Some(k.as_str()))
                });
                match famille {
                    // cim est posé par l'ingestion sur tout événement ; toute autre clé estampillée l'est ici par le mappage.
                    Some(f) if k == "cim" => assert!(f["code"].as_str().unwrap().contains("cim_stamp"), "{f}"),
                    Some(f) => assert!(
                        f["code"].as_str().unwrap().contains("httppull.rs"),
                        "{k} écrite sous {source} par le preset {id} : la famille qui la sert doit citer httppull.rs ({f})"
                    ),
                    None => {
                        hors.insert(k);
                    }
                }
            }
        }
        assert_eq!(avouees, hors, "l'aveu connecteur doit nommer EXACTEMENT les clés des presets livrés hors liste et hors familles");
    }

    /// L'AVEU D'INDISPONIBILITÉ DE L'AGENT, sous la source FIM : les clés de `event_indisponibilite` hors de la liste
    /// `integrity` sont exactement celles que l'aveu FIM nomme (relues dans `agent/src/lisibilite.rs`).
    #[test]
    fn l_aveu_fim_nomme_les_cles_d_indisponibilite_de_l_agent_hors_liste() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let texte = std::fs::read_to_string(racine.join("agent/src/lisibilite.rs")).expect("agent/src/lisibilite.rs");
        let debut = texte.find("pub fn event_indisponibilite(").expect("event_indisponibilite présent");
        let corps = &texte[debut..];
        let sac = &corps[corps.find("json!({").expect("sac json!") + 7..];
        let sac = &sac[..sac.find("});").expect("fin du sac")];
        let mut emises: std::collections::BTreeSet<String> = sac
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"').and_then(|r| r.split_once('"')).filter(|(_, a)| a.trim_start().starts_with(':')).map(|(k, _)| k.to_string()))
            .collect();
        let ajout = corps.split("fields[\"").nth(1).and_then(|r| r.split_once('"')).map(|(k, _)| k.to_string()).expect("clé ajoutée au sac");
        emises.insert(ajout);
        assert!(emises.contains("verdict") && emises.contains("collector") && emises.len() >= 7, "prémisse : sac relu ({emises:?})");
        let liste: std::collections::BTreeSet<String> = crate::handlers::sources::champs_etendus_de_source(crate::SOURCE_INTEGRITE)
            .expect("integrity couverte")
            .iter()
            .map(|s| s.to_string())
            .collect();
        let hors: std::collections::BTreeSet<String> = emises.difference(&liste).cloned().collect();
        let aveux = crate::handlers::sources::champs_etendus_ne_voit_pas();
        let aveu = aveux.iter().find(|a| a.contains("fim/mod.rs")).expect("aveu FIM");
        let entre = aveu.split_once('[').and_then(|(_, r)| r.split_once(']')).map(|(x, _)| x).expect("aveu FIM : liste entre crochets");
        let avouees: std::collections::BTreeSet<String> = entre.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        assert_eq!(avouees, hors, "l'aveu FIM doit nommer EXACTEMENT les clés d'indisponibilité de l'agent hors de la liste integrity");
    }
