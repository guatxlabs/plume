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
        // UNE SEULE TRANSACTION POUR TOUT LE PEUPLEMENT. Le CONTENU est identique — seul le coût de
        // construction de la fixture change (mesuré le 2026-08-27 : la fixture à 64 000 lignes passe
        // de 2,9 s à 0,4 s). C'est ce qui rend l'ablation de `P3.7-b` jouable sur trois volumes sans
        // peser sur la suite.
        conn.execute_batch("BEGIN").unwrap();
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
        conn.execute_batch("COMMIT").unwrap();
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

    /// (5) `P3.7-b` — L'ABLATION, JOUÉE. CE QUE LE DÉBIT PERD QUAND ON RETIRE L'INDEX, ET À PARTIR
    /// DE QUEL VOLUME LES SONDES DOMINENT VRAIMENT.
    ///
    /// CE QUE `P3.7-a` NE PROUVAIT PAS. La clé d'origine a fermé le coût par un index partiel, et
    /// (1)/(2) ci-dessus prouvent que le coût d'une sonde ne suit plus le volume. Rien n'établissait
    /// pour autant que ces sondes étaient le CONTRIBUTEUR DOMINANT de ce qui se passe sous le verrou
    /// d'écriture : le correctif était cru sur sa vraisemblance. Ce test mène l'ablation — la même
    /// ronde de production (un lot d'ingest, puis UNE passe complète de sondes, comme toutes les
    /// 20 s) jouée sur DEUX bases identiques dont une seule porte l'index, en ALTERNANCE ronde par
    /// ronde pour que les deux bras subissent le même ordonnancement, à TROIS volumes dans un
    /// rapport de 4 exact.
    ///
    /// LE VERDICT MESURÉ LE 2026-08-27 (12 cœurs, binaire de test `debug`, lot de 500 événements,
    /// médiane sur 5 rondes) — et il NUANCE le constat d'origine au lieu de le confirmer en bloc :
    ///
    /// | volume `event` | passe AVEC index | passe SANS index | part de la ronde SANS | équivalent en événements d'ingest |
    /// |----------------|------------------|------------------|-----------------------|-----------------------------------|
    /// |          4 000 | 0,29 ms (630 VM) | 0,96 ms (25 142 VM) |  7,2 %             |  38,6 événements                  |
    /// |         16 000 | 0,23 ms (630 VM) | 2,30 ms (61 142 VM) | 15,5 %             |  91,7 événements                  |
    /// |         64 000 | 0,25 ms (630 VM) | 9,74 ms (205 142 VM)| 42,4 %             | 367,7 événements                  |
    ///
    /// CE QUE ÇA DIT, ET CE QUE ÇA NE DIT PAS :
    ///   * l'index tient : AVEC lui, la passe coûte 630 pas de machine virtuelle et ~1,9 % de la
    ///     ronde, À TOUS LES VOLUMES — c'est ça, « pas O(N) », vu en débit et plus seulement en coût ;
    ///   * SANS lui, le coût marginal vaut EXACTEMENT 3 pas de VM par ligne d'`event` (36 000 pas de
    ///     plus pour 12 000 lignes de plus, 144 000 de plus pour 48 000 lignes de plus) : la loi de
    ///     `P3.7-a` — 5 pas par ligne postérieure au dernier battement — se retrouve à l'identique,
    ///     multipliée par les six sondes que la fixture laisse sans battement et par le dixième des
    ///     lignes que chacune voit ;
    ///   * MAIS LES SONDES NE DOMINENT PAS À TOUT VOLUME. À 4 000 lignes elles pèsent 7 % de la ronde :
    ///     le contributeur dominant y est l'ingest lui-même. La bascule est PROGRESSIVE et le point
    ///     de croisement se lit dans les mesures ci-dessus — la passe égale le lot de 500 événements
    ///     vers 80 000 lignes d'`event` sur ce banc. **Le constat d'origine (« les sondes dominaient »)
    ///     est donc VRAI SEULEMENT AU-DELÀ D'UN VOLUME, et il ne l'était pas au volume du banc de
    ///     l'époque.** Ce qui reste vrai sans condition, et qui justifie le correctif à lui seul :
    ///     sans l'index le coût est NON BORNÉ en volume, et une base de production dépasse ces
    ///     volumes de plusieurs ordres de grandeur.
    ///
    /// CE QUI EST EXTRAPOLÉ ET DIT COMME TEL : la ligne « au volume de production » n'est PAS mesurée.
    /// La loi mesurée (3 pas de VM par ligne) est exacte sur les trois points ; la traduire en
    /// millisecondes à un million de lignes serait une extrapolation, et elle n'est pas écrite ici.
    ///
    /// CE QUE LE TEST ASSERTE, ET AVEC QUELLE FORCE. Le dur est DÉTERMINISTE et sans horloge : les pas
    /// de machine virtuelle, constants avec l'index, et dont les incréments suivent SANS l'index le
    /// rapport EXACT des incréments de volume. MUTATION EXÉCUTÉE le 2026-08-27 — annuler l'ablation
    /// (ne plus retirer l'index) rend `[630, 630, 630]` et fait rougir cette assertion.
    ///
    /// LE MUR NE JUGE RIEN, ET C'EST UNE DÉCISION MESURÉE. Ce test a d'abord porté deux assertions de
    /// mur ; l'une d'elles est devenue ROUGE SOUS CHARGE le 2026-08-27 sans qu'une ligne du produit ne
    /// bouge (le détail est dans le corps du test). Elle n'apportait rien que les pas de VM ne
    /// tiennent déjà, exactement, et sans dépendre de la machine. Le mur est donc IMPRIMÉ — c'est le
    /// verdict en débit que la clé demandait — et il n'entre dans aucune assertion.
    #[test]
    fn sondes_ablation_du_debit_avec_et_sans_index() {
        /// Volumes dans un rapport de 4 EXACT : c'est le rapport, pas les valeurs, qui porte
        /// l'assertion déterministe ci-dessous.
        const VOLUMES: [i64; 3] = [4_000, 16_000, 64_000];
        /// Lot d'ingest d'une ronde. Il fixe l'unité dans laquelle le coût d'une passe est traduit
        /// (« combien d'événements d'ingest coûte une passe »), il n'entre dans aucune assertion.
        const LOT: i64 = 500;
        /// Rondes alternées. La MÉDIANE réduit — sous préemption, une moyenne rapprocherait les deux
        /// bras et l'ablation deviendrait aveugle.
        const RONDES: usize = 5;

        let mut vm_avec: Vec<i64> = Vec::new();
        let mut vm_sans: Vec<i64> = Vec::new();
        for volume in VOLUMES {
            let bases = [base_pathologique(volume), base_pathologique(volume)];
            // BRAS 1 : L'ABLATION. Même base, même contenu, l'index partiel en moins.
            {
                let c = bases[1].lock();
                c.execute(&format!("DROP INDEX {IDX_BATTEMENT_SANTE}"), []).unwrap();
                c.execute_batch("ANALYZE").unwrap();
            }
            let mut t_ingest: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
            let mut t_passe: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
            let mut vm = [0i64; 2];
            for r in 0..RONDES {
                for bras in 0..2 {
                    let c = bases[bras].lock();
                    // LA RONDE DE PRODUCTION : un lot d'ingest sur les sources SANS battement (le cas
                    // du dead-man's-switch : le collecteur est mort, sa source continue d'être
                    // alimentée par ailleurs), puis UNE passe complète de sondes.
                    let ts = 1_760_000_000i64 + (r as i64) * LOT * 10;
                    let srcs = ["ufw", "dataaccess", "integrity", "portscan", "fail2ban", "journal"];
                    let cats = ["firewall", "data", "integrity", "firewall", "ban", "auth"];
                    let t0 = std::time::Instant::now();
                    {
                        let mut st = c
                            .prepare("INSERT INTO event(ts,source,category,severity,host,message) VALUES(?1,?2,?3,1,'machine0','m')")
                            .unwrap();
                        c.execute_batch("BEGIN").unwrap();
                        for i in 0..LOT {
                            let k = (i % srcs.len() as i64) as usize;
                            st.execute(params![ts + i, srcs[k], cats[k]]).unwrap();
                        }
                        c.execute_batch("COMMIT").unwrap();
                    }
                    let t1 = std::time::Instant::now();
                    vm[bras] = COLLECTORS.iter().map(|(_, _, _, sonde, _)| cout_vm(&c, sonde)).sum();
                    let t2 = std::time::Instant::now();
                    t_ingest[bras].push((t1 - t0).as_secs_f64() * 1000.0);
                    t_passe[bras].push((t2 - t1).as_secs_f64() * 1000.0);
                }
            }
            let med = |v: &mut Vec<f64>| {
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                v[v.len() / 2]
            };
            let (ia, ib) = (med(&mut t_ingest[0]), med(&mut t_ingest[1]));
            let (pa, pb) = (med(&mut t_passe[0]), med(&mut t_passe[1]));
            eprintln!(
                "[P3.7-b] volume {volume:>6} | AVEC index : passe {pa:6.3} ms ({} VM), {:5.1} % de la ronde, \
                 {:6.1} événements-équivalents | SANS index : passe {pb:6.3} ms ({} VM), {:5.1} % de la ronde, \
                 {:6.1} événements-équivalents | l'ablation coûte x{:.1}",
                vm[0], 100.0 * pa / (ia + pa), LOT as f64 * pa / ia,
                vm[1], 100.0 * pb / (ib + pb), LOT as f64 * pb / ib,
                pb / pa
            );
            vm_avec.push(vm[0]);
            vm_sans.push(vm[1]);
        }

        // (A) LE DUR, SANS AUCUNE HORLOGE. Avec l'index, le coût de la passe ne bouge PAS d'un pas de
        // VM quand le volume est multiplié par 4 puis encore par 4.
        assert!(
            vm_avec[0] == vm_avec[1] && vm_avec[1] == vm_avec[2],
            "AVEC l'index, le coût d'une passe complète doit être INDÉPENDANT du volume : {vm_avec:?} pas de VM \
             aux volumes {VOLUMES:?}"
        );
        // (A bis) SANS l'index, le coût est linéaire en volume — et c'est l'ABLATION : les incréments
        // de coût sont dans le RAPPORT EXACT des incréments de volume. Aucune constante n'est écrite
        // ici ; le 4 vient de la mutation du volume, qui est exacte par construction.
        let (d1, d2) = (vm_sans[1] - vm_sans[0], vm_sans[2] - vm_sans[1]);
        assert!(
            d1 > 0 && d2 == 4 * d1,
            "SANS l'index, le coût d'une passe doit suivre le volume LINÉAIREMENT : {vm_sans:?} pas de VM aux \
             volumes {VOLUMES:?}, soit des incréments de {d1} puis {d2} là où les incréments de volume sont \
             dans un rapport de 4. Si ce rapport n'est plus 4, ce n'est pas l'ablation qui a changé, c'est la \
             fixture ou la loi de coût de `P3.7-a`."
        );
        // (B) LE MUR NE JUGE PAS — IL REND, ET C'EST UNE DÉCISION MESURÉE, PAS UNE PARESSE.
        // Ce test a d'abord porté DEUX assertions de mur : « l'ablation coûte plus que 1 » à chaque
        // volume, et « la perte grossit avec le volume ». MESURÉ le 2026-08-27 sous charge (24
        // brûleurs sur 12 cœurs), la seconde est devenue ROUGE sans qu'une seule ligne du produit ne
        // change : la préemption a gonflé le bras INDEXÉ du petit volume (0,27 -> 0,49 ms), le
        // rapport y est monté de x4,0 à x11,1, et l'assertion « le gros volume doit valoir au moins
        // le double du petit » (x20,7 contre x22,2 exigés) est tombée. C'est exactement la faute que
        // `P6.9-a` a fermée ailleurs, et la réintroduire ici pour décorer l'ablation d'un chiffre de
        // mur serait un recul. Deux raisons de plus de ne pas la garder :
        //   * ce qu'elle prétendait garder — « le coût suit le volume » — est DÉJÀ asserté au-dessus,
        //     de façon EXACTE et insensible à la machine, par les incréments de pas de VM ;
        //   * aucune mutation essayée ne la faisait rougir SEULE : annuler l'ablation est intercepté
        //     avant elle par l'assertion déterministe.
        // Le mur reste donc IMPRIMÉ (c'est le verdict en débit que `P3.7-b` demandait, et il est
        // reproductible avec `--nocapture`), et il ne juge rien.
    }
