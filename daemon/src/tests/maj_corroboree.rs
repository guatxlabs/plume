    // ================================================================================================
    // P5.7-b — LE SOC S'ALERTE SUR SA PROPRE MISE À JOUR : CORROBORER, JAMAIS EXEMPTER.
    //
    // Le capteur d'intégrité a RAISON de surveiller `/etc/systemd/system` : y déposer une unité est un
    // vecteur de persistance, et le produit l'annonce. Mais le produit écrit lui-même dans ce répertoire
    // à chaque déploiement, et une alerte par déploiement apprend à l'exploitant à ne plus lire ce
    // capteur. L'exemption par NOM est écartée : elle offrirait à un attaquant l'angle mort qu'il vise.
    //
    // Ce que ces tests prouvent, DANS LES DEUX SENS :
    //   ① une mise à jour légitime simulée est reclassée, la règle T1543 ne tire plus, et l'événement
    //     est TOUJOURS LÀ — avec son motif et la sévérité que le capteur avait posée ;
    //   ② un dépôt HOSTILE qui imite une mise à jour reste détecté, sous SIX formes : nom du produit
    //     avec contenu étranger, nom inventé qui ressemble au produit, contenu authentique sous un
    //     autre nom, dépôt authentique hors fenêtre, dépôt antérieur au déploiement, dépôt authentique
    //     sans aucun déploiement. Si ce second test ne pouvait pas s'écrire, la solution serait une
    //     exemption déguisée.
    // ================================================================================================

    /// Racine du dépôt (le test tourne depuis `daemon/`).
    fn mc_racine() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    /// Les unités que le dépôt livre RÉELLEMENT, relues sur disque : `(nom, sha256 du contenu)`.
    /// DÉRIVÉ du répertoire, jamais recopié — un fichier ajouté demain est vu le jour même.
    fn mc_unites_sur_disque() -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        for e in std::fs::read_dir(mc_racine().join("systemd")).expect("systemd/ lisible").flatten() {
            let p = e.path();
            let nom = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(".service") || n.ends_with(".timer") => n.to_string(),
                _ => continue,
            };
            out.insert(nom, sha256_hex(&std::fs::read(&p).expect("unité lisible")));
        }
        out
    }

    /// L'empreinte LIVRÉE d'une unité nommée, relue sur le fichier : une fixture ne recopie pas un hash.
    fn mc_empreinte(nom: &str) -> String {
        mc_unites_sur_disque()
            .remove(nom)
            .unwrap_or_else(|| panic!("{nom} n'est plus livrée dans systemd/ — la fixture doit nommer une unité qui existe"))
    }

    /// Base FICHIER (l'évaluateur de règles rouvre `db_path` : une base en mémoire ne verrait rien).
    fn mc_base(etiquette: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let p = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = Connection::open(p.as_str()).expect("ouverture de la base de test");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        (p, conn)
    }

    /// Simule un DÉPLOIEMENT : la base porte la signature d'un build ANTÉRIEUR, puis ce build démarre.
    /// Rend la date du fait de déploiement.
    fn mc_deploiement(conn: &Connection, db_path: &str) -> i64 {
        conn.execute(
            "INSERT INTO meta(key,value) VALUES(?1,'signature-du-build-anterieur') \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![CLE_META_SIGNATURE],
        )
        .unwrap();
        noter_le_build_en_cours(conn, db_path);
        let fait = fait_de_deploiement(db_path);
        assert!(fait > 0, "précondition : un changement de jeu d'unités doit DATER le déploiement");
        fait
    }

    /// L'événement que `collectors/integrity.sh` écrit pour un dépôt d'unité, dans sa forme exacte
    /// (`kind`/`path`/`sha256`/`scope`/`change`, severity 3).
    fn mc_depot(ts: i64, nom: &str, empreinte: &str, change: &str) -> Value {
        let chemin = format!("/etc/systemd/system/{nom}");
        json!({
            "ts": ts,
            "source": "integrity",
            "category": "integrity",
            "severity": 3,
            "message": format!("unit systemd {change} (persistance) : {chemin}"),
            "fields": { "kind": "unit", "path": chemin, "sha256": empreinte, "scope": "host", "change": change },
        })
    }

    /// La valeur que rend la règle SEMÉE T1543 (« vecteur de persistance ajouté »), telle qu'elle est
    /// livrée — on ne réécrit pas sa requête ici, on la LIT.
    fn mc_valeur_t1543(db_path: &str) -> f64 {
        let (_, q, _, _, _, _, _, w, _) =
            DETECTION_RULES_V50.iter().find(|r| r.8 == "T1543").expect("règle T1543 livrée");
        let sql = rule_sql(q, true, *w).expect("la règle T1543 doit compiler");
        eval_value(db_path, &sql).expect("la règle T1543 doit s'évaluer")
    }

    /// La ligne stockée pour un chemin d'unité : `(severity, fields)`.
    fn mc_ligne(conn: &Connection, nom: &str) -> (i64, Value) {
        let chemin = format!("/etc/systemd/system/{nom}");
        conn.query_row(
            "SELECT severity, fields FROM event WHERE source='integrity' AND fields LIKE ?1",
            params![format!("%{chemin}%")],
            |r| Ok((r.get::<_, i64>(0)?, serde_json::from_str(&r.get::<_, String>(1)?).unwrap())),
        )
        .unwrap_or_else(|e| panic!("la ligne de {nom} doit EXISTER (reclasser n'efface pas) : {e}"))
    }

    /// L'AMPLEUR, DÉRIVÉE DES FICHIERS ET NON ESTIMÉE (arbre du 2026-08-20). Le produit livre 88 unités
    /// systemd. C'est le nombre de contenus qu'un déploiement peut légitimement déposer dans le
    /// répertoire que le capteur surveille — et donc le nombre d'empreintes que la corroboration doit
    /// connaître. Si ce compte bouge, la table d'empreintes doit bouger avec lui : la garde qui suit
    /// l'exige, et celle de `detection.rs` épingle séparément les 27 que `bootstrap.sh` dépose.
    const UNITES_SYSTEMD_LIVREES: usize = 88;

    /// LA TABLE D'EMPREINTES EST CELLE DES FICHIERS — re-hachée, jamais crue sur parole.
    ///
    /// C'est la garde qui empêche la corroboration de devenir une liste morte. Une unité modifiée sans
    /// re-hachage ne crée AUCUN angle mort (son dépôt cesserait d'être reconnu, donc il alerterait), mais
    /// elle rendrait le mécanisme silencieusement inopérant : le SOC se remettrait à hurler à chaque
    /// déploiement sans que personne comprenne pourquoi. Ici, la dérive rougit.
    #[test]
    fn les_empreintes_livrees_sont_celles_des_fichiers() {
        let disque = mc_unites_sur_disque();
        assert_eq!(
            disque.len(),
            UNITES_SYSTEMD_LIVREES,
            "le dépôt livre {} unité(s) systemd, la mesure en déclare {UNITES_SYSTEMD_LIVREES}. Chaque \
             unité livrée est un contenu qu'un déploiement peut déposer dans le répertoire surveillé : \
             re-mesurez, puis mettez à jour la constante ET la table d'empreintes.",
            disque.len()
        );
        let table: std::collections::BTreeMap<String, String> =
            UNITES_LIVREES.iter().map(|(n, h)| (n.to_string(), h.to_string())).collect();
        assert_eq!(
            table.len(),
            UNITES_LIVREES.len(),
            "la table `UNITES_LIVREES` porte un nom EN DOUBLE : une entrée en masquerait une autre."
        );
        let manquantes: Vec<&String> = disque.keys().filter(|n| !table.contains_key(*n)).collect();
        let fantomes: Vec<&String> = table.keys().filter(|n| !disque.contains_key(*n)).collect();
        let perimees: Vec<&String> =
            disque.iter().filter(|(n, h)| table.get(*n).is_some_and(|t| t != *h)).map(|(n, _)| n).collect();
        assert!(
            manquantes.is_empty() && fantomes.is_empty() && perimees.is_empty(),
            "la table d'empreintes de `maj_corroboree.rs` a DÉRIVÉ des fichiers de systemd/ — \
             absentes de la table : {manquantes:?} ; dans la table mais plus livrées : {fantomes:?} ; \
             empreinte périmée : {perimees:?}. Régénérez la table depuis les fichiers (sha256 du \
             contenu, trié par nom) : sans elle, un déploiement légitime réveille l'alerte T1543."
        );
    }

    /// CE QUE LA CORROBORATION DOIT POUVOIR RECONNAÎTRE : tout ce que les installeurs déposent.
    /// DÉRIVÉ des scripts d'installation — une unité déposée par un installeur mais absente de
    /// `systemd/` ne serait jamais corroborable, et son déploiement alerterait pour toujours.
    #[test]
    fn tout_ce_que_les_installeurs_deposent_est_une_unite_livree() {
        let table: std::collections::BTreeSet<String> =
            UNITES_LIVREES.iter().map(|(n, _)| n.to_string()).collect();
        let mut deposees: std::collections::BTreeSet<String> = Default::default();
        for script in ["bootstrap.sh", "bootstrap-agent.sh"] {
            let src = std::fs::read_to_string(mc_racine().join(script)).expect("installeur lisible");
            for l in src.lines() {
                let l = l.trim();
                if l.starts_with('#') || !l.contains("/etc/systemd/system") {
                    continue;
                }
                if let Some(p) = l.find("systemd/plume-") {
                    let nom: String = l[p + "systemd/".len()..]
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != '"')
                        .collect();
                    if nom.ends_with(".service") || nom.ends_with(".timer") {
                        deposees.insert(nom);
                    }
                }
            }
        }
        assert!(!deposees.is_empty(), "l'extracteur ne voit plus AUCUN dépôt d'unité : il a cessé de mesurer");
        let inconnues: Vec<&String> = deposees.iter().filter(|n| !table.contains(*n)).collect();
        assert!(
            inconnues.is_empty(),
            "un installeur dépose {inconnues:?} dans /etc/systemd/system, mais ces unités ne figurent \
             pas parmi celles que ce build livre : leur dépôt ne pourra JAMAIS être corroboré et \
             alertera à chaque déploiement."
        );
    }

    /// ① MUTATION — UNE MISE À JOUR LÉGITIME EST RECLASSÉE, ET L'ÉVÉNEMENT RESTE.
    ///
    /// Le déploiement est daté (le build livre un autre jeu d'unités qu'auparavant), puis le capteur
    /// signale le dépôt de l'unité de son propre timer, au contenu LIVRÉ. Attendu : la règle T1543
    /// rend 0 — et la ligne est toujours là, en `severite_origine=3`, avec son motif, son `kind`, son
    /// `path`, son `sha256` et son `change` intacts. Le TÉMOIN NÉGATIF est dans la même fonction :
    /// SANS le déploiement, la même ligne rend 1.
    #[test]
    fn une_mise_a_jour_legitime_est_reclassee_et_lalerte_ne_part_pas() {
        let nom = "plume-integrity.service";
        let empreinte = mc_empreinte(nom);

        // TÉMOIN NÉGATIF d'abord : le MÊME dépôt, sans aucun déploiement noté -> la règle TIRE.
        {
            let (p, conn) = mc_base("maj-temoin");
            assert_eq!(fait_de_deploiement(p.as_str()), 0, "aucun déploiement noté sur cette base");
            ingest_events_batch(&conn, p.as_str(), &[mc_depot(now(), nom, &empreinte, "ajout")], now(), None, None)
                .expect("batch ingéré");
            assert_eq!(
                mc_valeur_t1543(p.as_str()),
                1.0,
                "SANS déploiement, un dépôt d'unité DOIT rester détecté : si ce témoin rend 0, le \
                 reclassement s'applique sans corroboration et c'est une exemption."
            );
            assert_eq!(mc_ligne(&conn, nom).0, 3, "sans corroboration, la sévérité du capteur est intacte");
        }

        // MUTATION : le même dépôt, corroboré par un déploiement daté.
        let (p, conn) = mc_base("maj-legitime");
        let fait = mc_deploiement(&conn, p.as_str());
        ingest_events_batch(&conn, p.as_str(), &[mc_depot(fait + 60, nom, &empreinte, "ajout")], now(), None, None)
            .expect("batch ingéré");
        assert_eq!(
            mc_valeur_t1543(p.as_str()),
            0.0,
            "une mise à jour corroborée ne doit plus lever « vecteur de persistance ajouté » : c'est \
             cette alerte-là qui partait à chaque déploiement et qui apprenait à ignorer le capteur."
        );
        let (sev, f) = mc_ligne(&conn, nom);
        assert_eq!(sev, SEVERITE_RECLASSEE, "reclassé en informationnel, pas effacé");
        assert_eq!(f[CHAMP_MOTIF], json!(MOTIF_MAJ_PRODUIT), "le motif du reclassement est ÉCRIT sur la ligne");
        assert_eq!(f[CHAMP_SEVERITE_ORIGINE], json!(3), "la sévérité que le CAPTEUR avait posée est conservée");
        assert_eq!(f["kind"], json!("unit"), "kind intact");
        assert_eq!(f["change"], json!("ajout"), "change intact");
        assert_eq!(f["sha256"], json!(empreinte), "sha256 intact");
        assert_eq!(f["path"], json!(format!("/etc/systemd/system/{nom}")), "path intact");
        // Ce qui a été atténué se retrouve, et ne se confond avec rien d'autre.
        let attenues: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM event WHERE source='integrity' AND json_extract(fields,'$.reclasse')=?1",
                params![MOTIF_MAJ_PRODUIT],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(attenues, 1, "`reclasse=maj-produit` rend EXACTEMENT ce qui a été atténué");
    }

    /// ② MUTATION — UN DÉPÔT HOSTILE QUI IMITE UNE MISE À JOUR RESTE DÉTECTÉ.
    ///
    /// C'EST LE TEST QUI SÉPARE UNE CORROBORATION D'UNE EXEMPTION DÉGUISÉE. Les six dépôts ci-dessous
    /// sont tous posés PENDANT la fenêtre d'un déploiement réel (sauf ceux dont c'est justement la
    /// variable), et tous doivent rester à la sévérité du capteur, donc visibles de la règle T1543.
    #[test]
    fn un_depot_hostile_qui_imite_une_mise_a_jour_reste_detecte() {
        let nom_livre = "plume-integrity.service";
        let livree = mc_empreinte(nom_livre);
        let hostile = sha256_hex(b"[Service]\nExecStart=/tmp/.x/porte-derobee\n");

        // (a) LE NOM DU PRODUIT, CONTENU ÉTRANGER — l'attaque exacte qu'une exemption par nom ouvrirait.
        // (b) UN NOM INVENTÉ QUI RESSEMBLE AU PRODUIT — jamais livré, donc jamais reconnu.
        // (c) UN CONTENU AUTHENTIQUE SOUS UN AUTRE NOM — le contenu ne suffit pas non plus.
        for (cas, nom, empreinte) in [
            ("nom du produit + contenu étranger", nom_livre, hostile.clone()),
            ("nom inventé façon produit", "plume-persistance.service", hostile.clone()),
            ("contenu livré sous un autre nom", "systemd-udevd-helper.service", livree.clone()),
        ] {
            let (p, conn) = mc_base("maj-hostile");
            let fait = mc_deploiement(&conn, p.as_str());
            ingest_events_batch(&conn, p.as_str(), &[mc_depot(fait + 60, nom, &empreinte, "ajout")], now(), None, None)
                .expect("batch ingéré");
            assert_eq!(
                mc_valeur_t1543(p.as_str()),
                1.0,
                "[{cas}] un dépôt hostile posé PENDANT une mise à jour doit rester détecté — sinon la \
                 corroboration est une exemption déguisée et l'angle mort est taillé sur mesure."
            );
            assert_eq!(mc_ligne(&conn, nom).0, 3, "[{cas}] la sévérité du capteur est intacte");
        }

        // (d) DÉPÔT AUTHENTIQUE HORS FENÊTRE, (e) ANTÉRIEUR AU DÉPLOIEMENT : un dépôt isolé n'a pas le
        // même statut qu'une mise à jour, même si son contenu est authentique.
        for (cas, decalage) in [
            ("hors fenêtre", FENETRE_DE_CORROBORATION_S + 1),
            ("antérieur au déploiement", -60),
        ] {
            let (p, conn) = mc_base("maj-fenetre");
            let fait = mc_deploiement(&conn, p.as_str());
            ingest_events_batch(&conn, p.as_str(), &[mc_depot(fait + decalage, nom_livre, &livree, "ajout")], now(), None, None)
                .expect("batch ingéré");
            assert_eq!(
                mc_valeur_t1543(p.as_str()),
                1.0,
                "[{cas}] la fenêtre est bornée des DEUX côtés : hors d'elle, le contenu authentique ne \
                 corrobore rien."
            );
            assert_eq!(mc_ligne(&conn, nom_livre).0, 3, "[{cas}] la sévérité du capteur est intacte");
        }

        // (f) MÊME BUILD, AUCUN DÉPLOIEMENT : un redémarrage ne doit rien ouvrir.
        let (p, conn) = mc_base("maj-sans-deploiement");
        noter_le_build_en_cours(&conn, p.as_str()); // base neuve -> pose silencieuse
        noter_le_build_en_cours(&conn, p.as_str()); // redémarrage du MÊME build
        assert_eq!(fait_de_deploiement(p.as_str()), 0, "un redémarrage sans déploiement n'ouvre AUCUNE fenêtre");
        ingest_events_batch(&conn, p.as_str(), &[mc_depot(now(), nom_livre, &livree, "ajout")], now(), None, None)
            .expect("batch ingéré");
        assert_eq!(
            mc_valeur_t1543(p.as_str()),
            1.0,
            "sans changement du jeu d'unités livré, un dépôt d'unité reste une alerte — y compris au \
             contenu authentique."
        );
    }

    /// LE FAIT DE DÉPLOIEMENT EST DATÉ ET AUDITÉ, ET IL NE S'INVENTE PAS.
    ///
    /// Trois démarrages : base neuve (pose SILENCIEUSE, aucune fenêtre, aucun audit), même build
    /// (rien), build différent (fenêtre + EXACTEMENT une ligne de ledger et un event `plume-config`).
    /// L'atténuation ne peut donc pas exister sans sa trace, et l'exploitant retrouve QUAND elle a été
    /// ouverte et par quel changement.
    #[test]
    fn le_fait_de_deploiement_est_date_audite_et_ne_sinvente_pas() {
        let (p, conn) = mc_base("maj-audit");
        let compte_audit = |c: &Connection| -> i64 {
            c.query_row(
                "SELECT COUNT(*) FROM event WHERE source='plume-config' AND json_extract(fields,'$.kind')='unites_livrees'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        let compte_ledger = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![KIND_AUDIT], |r| r.get(0)).unwrap()
        };

        noter_le_build_en_cours(&conn, p.as_str());
        assert_eq!(fait_de_deploiement(p.as_str()), 0, "base neuve : aucune fenêtre — il n'y a pas de build antérieur");
        assert_eq!(compte_audit(&conn), 0, "base neuve : on n'audite pas un déploiement qui n'a pas eu lieu");
        let signature: String = conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![CLE_META_SIGNATURE], |r| r.get(0))
            .expect("la signature du build est notée");
        assert_eq!(signature, signature_des_unites_livrees(), "la signature notée est celle de CE build");

        noter_le_build_en_cours(&conn, p.as_str());
        assert_eq!(fait_de_deploiement(p.as_str()), 0, "même build : toujours aucune fenêtre");
        assert_eq!(compte_audit(&conn), 0, "même build : rien à auditer");

        let fait = mc_deploiement(&conn, p.as_str());
        assert_eq!(compte_audit(&conn), 1, "un déploiement = UNE ligne d'audit `plume-config`, pas une par unité");
        assert_eq!(compte_ledger(&conn), 1, "…et UNE entrée de ledger tamper-evident");
        let persiste: i64 = conn
            .query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key=?1", params![CLE_META_FAIT], |r| r.get(0))
            .expect("le fait de déploiement est PERSISTÉ");
        assert_eq!(persiste, fait, "la fenêtre est ancrée au déploiement, pas au démarrage qui suit");
    }
