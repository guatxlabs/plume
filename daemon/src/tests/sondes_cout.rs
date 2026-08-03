// ================================================================================================
// P3.7-a — CE QUE COÛTE UNE SONDE DE FRAÎCHEUR, ET POURQUOI ÇA NE PEUT PLUS DÉRAPER EN SILENCE.
//
// LE DÉFAUT MESURÉ. `Sonde::EventFlotteConfondue { predicat: &'static str }` prenait une chaîne SQL
// libre. Le type figeait la TABLE et la COLONNE, jamais le COÛT. 8 des 20 sondes d'events portaient
// `AND category='health'` — colonne absente de idx_event_src_ts(source, ts) — donc SQLite remontait la
// plage de la source ligne par ligne. Loi mesurée le 2026-08-03 :
//     VM steps = 5 x (lignes de la source postérieures au dernier battement) + 13
// et une sonde dead-man's-switch n'a JAMAIS de battement récent quand le collecteur qu'elle surveille
// est mort : elle devient la plus chère exactement quand elle sert. Sous le verrou d'écriture, toutes
// les 20 s.
//
// CE QUE CES TESTS PROUVENT, dans cet ordre :
//   1. `sonde_cout_independant_du_volume` — LE THÉORÈME. Le coût d'une sonde ne change pas quand le
//      volume est MULTIPLIÉ PAR 4. Pas de plan à relire, pas de constante magique : une MUTATION du
//      volume et une égalité. C'est la définition de « pas O(N) », et rien d'autre ne la satisfait.
//   2. `sonde_cout_la_garde_mord` — LA GARDE DISCRIMINE. Le même théorème, l'index PARTIEL retiré :
//      le coût EXPLOSE. Un test qui ne peut pas échouer ne prouve rien ; celui-ci porte son propre
//      contre-exemple, donc il ne peut pas devenir vrai par accident (ex. table vidée).
//      Et il prouve dans le même geste l'INTÉGRITÉ : les VALEURS rendues sont IDENTIQUES avec et sans
//      l'index. L'index change le CHEMIN, jamais la RÉPONSE — mode 0 byte-identique.
//   3. `sonde_plan_nomme_son_index` — L'EXPLICATION. Ce que chaque sonde DÉCLARE (`Cout`) — l'index
//      qui la sert, ou la table dont la cardinalité la borne — est confronté au plan RÉEL. Attrape le
//      jour où quelqu'un droppe un index « qui paraissait redondant ».
//   4. `sonde_index_battement_declare_partout` — ZÉRO DÉRIVE entre les trois endroits où la DDL de
//      l'index existe (le type, la création en fond, `db/schema.sql`).
//
// CE QUE LE COMPILATEUR TIENT DÉJÀ, et que ces tests n'ont donc PAS à tenir : une sonde ne peut plus
// porter de SQL (aucune variante de `Sonde` n'a de champ chaîne), et toute variante doit répondre
// `Cout` — dont aucune variante ne veut dire « on ne sait pas ». Une 5ᵉ sonde ne compile pas tant
// qu'elle n'a pas dit ce qui borne son coût (`Sonde::requete`, match exhaustif -> E0004).
// ================================================================================================

    /// Le coût d'une sonde, compté par SQLite lui-même (`SQLITE_STMTSTATUS_VM_STEP`). DÉTERMINISTE :
    /// il ne dépend ni de la charge machine, ni du cache, ni de l'horloge — deux exécutions identiques
    /// rendent le même nombre. C'est ce qui rend le théorème (1) opposable au lieu d'être un chrono.
    fn cout_vm(conn: &Connection, sonde: &Sonde) -> i64 {
        let r = sonde.requete();
        let mut s = conn.prepare(r.sql()).expect("la sonde émet un SQL valide");
        let _: Option<i64> = s
            .query_row(rusqlite::params_from_iter(r.binds().iter()), |row| row.get(0))
            .unwrap_or(None);
        s.get_status(rusqlite::StatementStatus::VmStep) as i64
    }

    /// La VALEUR rendue par une sonde (ce que l'opérateur voit), séparée de son coût.
    fn valeurs(conn: &Connection) -> Vec<(&'static str, Option<i64>)> {
        COLLECTORS.iter().map(|(id, _, _, sonde, _)| (*id, sonde.derniere_collecte(conn))).collect()
    }

    /// BASE AU CAS PATHOLOGIQUE, à l'échelle `n`. Forme choisie pour que le défaut, s'il revient, se
    /// VOIE : les sources `ufw`/`dataaccess`/`integrity`/`portscan`/`fail2ban`/`journal` ont du VOLUME
    /// mais n'ont JAMAIS émis de battement `health` (collecteur host pas encore à jour, ou mort) —
    /// c'est exactement le cas où l'ancienne sonde remontait TOUTE la plage de la source.
    /// `crowdsec`/`k8s-log` battent normalement (cas nominal, doit rester nominal).
    /// La FLOTTE (`snapshot`) NE SUIT PAS `n` : c'est précisément ce que `Cout::BorneParLaTable`
    /// affirme, et le peuplement le respecte au lieu de le contourner.
    fn peuple_pathologique(conn: &Connection, n: i64) {
        // FLOTTE : 3 machines x 2 kinds, INDÉPENDANTE de n (borne déclarée des sondes d'instantané).
        for h in 0..3 {
            for k in ["firewall", "controls"] {
                conn.execute(
                    "INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(?1,?2,?3,'h','{}')",
                    params![1_750_000_000i64 + h, k, format!("machine{h}")],
                )
                .unwrap();
            }
        }
        // MÉTRIQUES : le volume SUIT n (si l'index ts-leading manquait, le MAX(ts) grossirait avec n).
        for i in 0..(n / 10) {
            conn.execute(
                "INSERT INTO metric(ts,name,labels,value) VALUES(?1,'cpu','{}',1.0)",
                params![1_750_000_000i64 + i],
            )
            .unwrap();
        }
        // EVENTS : n lignes réparties sur les sources sondées. `sources[i % len]` -> chaque source
        // grossit PROPORTIONNELLEMENT à n, ce qui est la mutation qui fait parler le théorème.
        let sources: [(&str, &str); 10] = [
            ("auditd", "exec"),
            ("web", "web"),
            ("kube-audit", "audit"),
            ("sshd", "auth"),
            ("ufw", "firewall"),
            ("dataaccess", "data"),
            ("integrity", "integrity"),
            ("portscan", "firewall"),
            ("fail2ban", "ban"),
            ("journal", "auth"),
        ];
        let mut st = conn
            .prepare("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,?3,1,'machine0','m')")
            .unwrap();
        for i in 0..n {
            let (s, c) = sources[(i % sources.len() as i64) as usize];
            st.execute(params![1_750_000_000i64 + i, s, c]).unwrap();
        }
        drop(st);
        // BATTEMENTS présents pour crowdsec/k8s-log SEULEMENT (cas nominal). Nombre FIXE : un battement
        // récent suffit, et c'est bien le propos — le coût nominal ne dépend pas non plus du volume.
        for src in ["crowdsec", "k8s-log"] {
            for j in 0..20i64 {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,'health',0,'machine0','beat')",
                    params![1_750_000_000i64 + n + j, src],
                )
                .unwrap();
            }
        }
        conn.execute_batch("ANALYZE").unwrap();
    }

    /// Base au cas pathologique à l'échelle `n`, telle que la PRODUCTION la construit (schema.sql +
    /// toute la chaîne de migrations), avec les index ts-leading créés en fond comme au boot.
    fn base_pathologique(n: i64) -> std::sync::Arc<parking_lot::Mutex<Connection>> {
        let db = std::sync::Arc::new(parking_lot::Mutex::new(test_db()));
        ensure_host_rollup_scan_indexes_background(&db); // idx_metric_ts / idx_snapshot_ts, comme au boot
        {
            let conn = db.lock();
            peuple_pathologique(&conn, n);
        }
        db
    }

    /// (1) LE THÉORÈME — le coût d'une sonde ne suit PAS le volume.
    ///
    /// On MULTIPLIE PAR 4 le nombre de lignes et on exige que le coût de CHAQUE sonde de `COLLECTORS`
    /// soit INCHANGÉ. Aucune constante magique n'est écrite ici : la seule chose affirmée est une
    /// invariance sous mutation du volume, ce qui est exactement l'énoncé « ce n'est pas O(N) ».
    ///
    /// Avant P3.7-a ce test échouait sur 6 sondes : MESURÉ le 2026-08-03 sur CETTE fixture, chacune
    /// passait de 2 014 à 8 014 VM steps quand le volume passait de 4 000 à 16 000 lignes — x4,000 exact
    /// pour x4 de volume. Elles y sont désormais à 13, CONSTANT. (Le chiffre n'est pas asserté ici : ce
    /// serait une constante magique. Il est reproductible par `sonde_cout_la_garde_mord`, qui retire
    /// l'index et ré-observe le dérapage.)
    #[test]
    fn sonde_cout_independant_du_volume() {
        let (petite, grande) = (4_000i64, 16_000i64); // x4 exact
        let db1 = base_pathologique(petite);
        let db2 = base_pathologique(grande);
        let (c1, c2) = (db1.lock(), db2.lock());
        // CONTRÔLE DE LA MUTATION : sans lui, le théorème serait vrai pour une mauvaise raison (deux
        // bases identiques donnent trivialement deux coûts identiques). Les BATTEMENTS sont en nombre
        // FIXE par construction (2 sources x 20) — seul le flux suit `n`, et c'est bien le flux qui
        // faisait déraper les sondes.
        const BATTEMENTS: i64 = 40;
        let compte = |c: &Connection| c.query_row::<i64, _, _>("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(
            compte(&c2) - BATTEMENTS,
            4 * (compte(&c1) - BATTEMENTS),
            "la grande base doit porter EXACTEMENT 4x le flux de la petite"
        );
        let mut derapent: Vec<String> = Vec::new();
        for (id, _, _, sonde, _) in COLLECTORS.iter() {
            let (a, b) = (cout_vm(&c1, sonde), cout_vm(&c2, sonde));
            if a != b {
                derapent.push(format!("{id} : {a} -> {b} VM steps quand le volume est x4 ({:?})", sonde.requete().cout()));
            }
        }
        assert!(
            derapent.is_empty(),
            "LE COÛT D'UNE SONDE NE DOIT PAS SUIVRE LE VOLUME. Sondes qui dérapent :\n  {}",
            derapent.join("\n  ")
        );
    }

    /// (2) LA GARDE MORD — et l'index ne change AUCUNE valeur.
    ///
    /// Le même théorème, l'index PARTIEL RETIRÉ : au moins une sonde doit DÉRAPER. Sans ce
    /// contre-exemple, (1) pourrait devenir vrai par accident (table vidée, sonde supprimée, fixture
    /// cassée) et personne ne le saurait.
    ///
    /// Et dans le MÊME geste, l'invariant d'INTÉGRITÉ : les VALEURS rendues par les 23 sondes sont
    /// IDENTIQUES avec et sans l'index. L'index change le CHEMIN D'ACCÈS, jamais la RÉPONSE — c'est ce
    /// qui rend la migration v114 mode 0 byte-identique, et c'est vérifié, pas affirmé.
    #[test]
    fn sonde_cout_la_garde_mord() {
        let db1 = base_pathologique(4_000);
        let db2 = base_pathologique(16_000);
        let (c1, c2) = (db1.lock(), db2.lock());
        let (avant1, avant2) = (valeurs(&c1), valeurs(&c2));

        for c in [&*c1, &*c2] {
            c.execute(&format!("DROP INDEX {IDX_BATTEMENT_SANTE}"), []).unwrap();
            c.execute_batch("ANALYZE").unwrap();
        }
        let derapent: Vec<&str> = COLLECTORS
            .iter()
            .filter(|(_, _, _, sonde, _)| cout_vm(&c1, sonde) != cout_vm(&c2, sonde))
            .map(|(id, ..)| *id)
            .collect();
        assert!(
            !derapent.is_empty(),
            "CONTRÔLE POSITIF : sans {IDX_BATTEMENT_SANTE}, au moins une sonde DOIT suivre le volume. \
             Si plus aucune ne dérape, ce n'est pas que le défaut a disparu — c'est que le test ne \
             mesure plus rien."
        );
        assert!(
            derapent.iter().all(|id| id.ends_with("-health")),
            "ce sont bien les sondes de BATTEMENT que l'index sert, et elles seules : {derapent:?}"
        );

        // INTÉGRITÉ : la réponse ne dépend pas du chemin d'accès.
        assert_eq!(avant1, valeurs(&c1), "les valeurs rendues ne dépendent pas de l'index (petite base)");
        assert_eq!(avant2, valeurs(&c2), "les valeurs rendues ne dépendent pas de l'index (grande base)");
    }

    /// (3) L'EXPLICATION — ce que chaque sonde DÉCLARE est confronté au plan RÉEL : l'index qui la sert
    /// (`IndexCouvrant`) ou la table dont la cardinalité la borne (`BorneParLaTable`). Le `Cout` écrit
    /// dans `Sonde::requete` n'est donc pas un commentaire. Attrape le jour où un index est droppé
    /// « parce qu'il paraissait redondant » — ou celui où une sonde bornée par la flotte se met à
    /// toucher une table de volume.
    #[test]
    fn sonde_plan_nomme_son_index() {
        let db = base_pathologique(4_000);
        let conn = db.lock();
        for (id, _, _, sonde, _) in COLLECTORS.iter() {
            let r = sonde.requete();
            let mut s = conn.prepare(&format!("EXPLAIN QUERY PLAN {}", r.sql())).unwrap();
            let plan: String = s
                .query_map(rusqlite::params_from_iter(r.binds().iter()), |row| row.get::<_, String>(3))
                .unwrap()
                .flatten()
                .collect::<Vec<_>>()
                .join(" | ");
            match r.cout() {
                // On exige un SEEK sur l'index DÉCLARÉ, pas l'étiquette « COVERING ».
                // POURQUOI (mesuré le 2026-08-03, et c'est une leçon d'INSTRUMENT) : sur la MÊME requête
                // et le MÊME schéma, le CLI SQLite 3.53 rend `SEARCH … USING COVERING INDEX
                // idx_event_health_beat` là où le SQLCipher EMBARQUÉ (rusqlite 0.31) rend `SEARCH …
                // USING INDEX idx_event_health_beat`. Même chemin d'accès, étiquette différente selon la
                // version. Le COÛT, lui, est identique et constant (13 VM steps, invariant sous x4
                // volume) : c'est pourquoi le juge est le théorème (1) et pas cette chaîne de caractères.
                // Assertion tirée sur ce qui NE dépend pas de la version : un SEEK, jamais un balayage.
                Cout::IndexCouvrant(ix) => {
                    assert!(plan.contains(ix), "{id} : déclare {ix}, plan = {plan}");
                    assert!(
                        plan.contains("SEARCH") && !plan.contains("SCAN"),
                        "{id} : un SEEK sur {ix}, jamais un balayage — un balayage lit la LIGNE de chaque \
                         candidat, ce qui est exactement le défaut P3.7-a. plan = {plan}"
                    );
                }
                // La sonde d'instantané balaie `snapshot` (MESURÉ : `SCAN snapshot | USE TEMP B-TREE
                // FOR GROUP BY` — le GROUP BY host empêche l'usage d'idx_snapshot(kind, ts)). Ce qu'on
                // exige ici n'est donc PAS un index, c'est que la table BALAYÉE soit bien celle dont la
                // cardinalité est bornée par la flotte, et JAMAIS une table de volume.
                Cout::BorneParLaTable(t) => {
                    assert!(plan.contains(t), "{id} : déclare un coût borné par `{t}`, plan = {plan}");
                    for volumineuse in ["event", "metric"] {
                        assert!(
                            !plan.contains(volumineuse),
                            "{id} : une sonde à coût borné par `{t}` ne doit JAMAIS toucher `{volumineuse}`. plan = {plan}"
                        );
                    }
                }
            }
        }
    }

    /// (4) ZÉRO DÉRIVE — la DDL de l'index de battement existe à TROIS endroits (le type qui la porte,
    /// la création en fond sur base migrée, `db/schema.sql` pour les bases neuves). Elle n'est écrite
    /// qu'une fois : les deux autres la RÉFÉRENCENT. Ce test tient le seul lien que le compilateur ne
    /// peut pas tenir — le fichier SQL.
    #[test]
    fn sonde_index_battement_declare_partout() {
        let schema = include_str!("../../../db/schema.sql");
        assert!(
            schema.contains(DDL_IDX_BATTEMENT_SANTE),
            "db/schema.sql doit porter EXACTEMENT la DDL de `sondes::DDL_IDX_BATTEMENT_SANTE` (base NEUVE : \
             `event` est vide, le CREATE est instantané) — sinon une base neuve naît sans l'index et les \
             sondes de battement y sont en O(N) jusqu'au premier passage de la tâche de fond."
        );
        // et la base que la production construit le porte réellement.
        let conn = test_db();
        assert!(
            conn.query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![IDX_BATTEMENT_SANTE], |_| Ok(()))
                .is_ok(),
            "{IDX_BATTEMENT_SANTE} présent sur une base neuve migrée"
        );
    }

    /// La création EN FOND sur base MIGRÉE (le chemin de la production, où `event` porte des millions de
    /// lignes et où un CREATE synchrone au boot tuerait la liveness) : idempotente, et elle comble le
    /// trou d'une base qui n'a pas l'index.
    #[test]
    fn sonde_index_battement_cree_en_fond_et_idempotent() {
        let db = std::sync::Arc::new(parking_lot::Mutex::new(test_db()));
        db.lock().execute(&format!("DROP INDEX {IDX_BATTEMENT_SANTE}"), []).unwrap();
        ensure_event_health_beat_index_background(&db);
        ensure_event_health_beat_index_background(&db); // 2e passage : court-circuit, aucune erreur
        assert!(
            db.lock()
                .query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![IDX_BATTEMENT_SANTE], |_| Ok(()))
                .is_ok(),
            "la tâche de fond comble le trou sur une base migrée"
        );
    }
