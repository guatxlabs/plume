// =====================================================================================
// `P10.28-l` (reste des semis par nom) — « VUE D'ENSEMBLE (RAPIDE) » ET « BANNI / PASS » S'ÉCRIVENT ENTIERS OU PAS DU
// TOUT.
//
// LE DÉFAUT, LU SUR aa5556fd : `seed_rollup_dashboard` (main.rs) et `seed_banpass_dashboard` (rollups.rs) lisaient la
// présence par `.is_ok()`, écrivaient l'en-tête hors transaction, le rattachement en `let _` puis chaque panneau en
// `let _ = conn.execute(...)` (sept et quatre). Un panneau refusé laissait un tableau PARTIEL que l'idempotence par nom
// tenait pour semé : jamais réparé. L'énoncé disait « lecture ratée = présent » : c'est l'INVERSE — `.is_ok()` d'une
// lecture ratée est `false`, le semis continuait et écrivait un SECOND tableau du même nom (témoin
// `srbp_une_presence_non_lue_n_ecrit_rien`, rouge sur la forme d'avant). Un en-tête qui rendait `Ok(0)` laissait les
// panneaux s'accrocher à l'identifiant d'une autre ligne.
//
// DÉSORMAIS : « Vue d'ensemble (rapide) » passe par `seed_dashboard_head_named` (une transaction, compté sous
// `scheduler`) ; « Banni / Pass », générique sur `SqlExec` et appelé aussi par la migration v52 sous `MigTx`, écrit sous
// un `SAVEPOINT` (tout ou rien dans les deux contextes), dit au journal, non compté.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base EN SERVICE déjà amputée (tableau présent, panneaux manquants) n'est pas
// réparée ; le rattachement de « Vue d'ensemble (rapide) » qui rend `Ok(0)` reste accepté (celui de
// `seed_dashboard_head_named`) ; un `ROLLBACK TO` refusé n'est pas provoqué (au démarrage la transaction resterait
// ouverte, l'aveu dit « ANNULATION REFUSÉE ») ; le refus de « Banni / Pass » n'est pas compté ; l'aveu de « Vue
// d'ensemble (rapide) » est celui, inchangé, de `semer_sous_son_drapeau`. Aucune variable d'environnement n'est lue par
// ces semis.
// =====================================================================================
mod semis_rapide_et_banni_pass_entiers_ou_annules {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const SRBP_RAPIDE: &str = "Vue d'ensemble (rapide)";

    /// Les panneaux d'avant, « titre|requête|is_soql|viz|position|cols|ttl|managed » (ttl NULL écrit `-`), recopiés des
    /// littéraux d'aa5556fd : la requête est jugée octet pour octet.
    fn srbp_panneaux_rapide() -> Vec<String> {
        [
            ("Volume dans le temps", "SELECT bucket, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY bucket ORDER BY bucket", "line"),
            ("Par source", "SELECT source, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY source ORDER BY n DESC LIMIT 20", "bar"),
            ("Sévérité >=3 par source", "SELECT source, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 GROUP BY source ORDER BY n DESC LIMIT 20", "bar"),
            ("Par action (CIM)", "SELECT action, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND action<>'' GROUP BY action ORDER BY n DESC LIMIT 20", "bar"),
            ("Par sévérité", "SELECT severity, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY severity ORDER BY severity", "bar"),
            ("Sévérité >=3 par src_ip", "SELECT src_ip, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 AND src_ip<>'' GROUP BY src_ip ORDER BY n DESC LIMIT 20", "bar"),
            ("Volume par host", "SELECT host, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND host<>'' GROUP BY host ORDER BY n DESC LIMIT 20", "bar"),
        ]
        .iter()
        .enumerate()
        .map(|(i, (t, q, v))| format!("{t}|{q}|0|{v}|{i}|2|-|2"))
        .collect()
    }

    fn srbp_panneaux_banni_pass() -> Vec<String> {
        [
            ("Banlist par source", "SELECT source, COUNT(DISTINCT src_ip) AS ips FROM banned_ip WHERE last_seen >= __FROM__ GROUP BY source ORDER BY ips DESC", "bar", 120),
            ("IPs bannies (dernier ban dans la fenêtre)", "SELECT COUNT(DISTINCT src_ip) AS ips_bannies FROM banned_ip WHERE last_seen >= __FROM__", "stat", 120),
            ("Attaquants NON mitigés (non bannis, fenêtre)", BANPASS_UNMITIGATED_SQL, "table", 300),
            ("Couverture de ban (% attaquants déjà bannis)", BANPASS_COVERAGE_SQL, "table", 300),
        ]
        .iter()
        .enumerate()
        .map(|(i, (t, q, v, ttl))| format!("{t}|{q}|0|{v}|{i}|2|{ttl}|2"))
        .collect()
    }

    /// (étiquette, nom, semis, vue, panneaux d'avant).
    type SrbpSemis = (&'static str, &'static str, fn(&Connection), &'static str, Vec<String>);

    fn srbp_banni_pass(conn: &Connection) {
        seed_banpass_dashboard(conn);
    }

    fn srbp_semis() -> Vec<SrbpSemis> {
        vec![
            ("rapide", SRBP_RAPIDE, seed_rollup_dashboard, "SOC", srbp_panneaux_rapide()),
            ("banni_pass", NOM_DU_BANNI_PASS, srbp_banni_pass, "Détection", srbp_panneaux_banni_pass()),
        ]
    }

    fn srbp_tableaux(conn: &Connection, nom: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux de ce nom")
    }

    fn srbp_panneaux_en_tout(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM panel", [], |r| r.get(0)).expect("panneaux")
    }

    fn srbp_panneaux(conn: &Connection, nom: &str) -> Vec<String> {
        let mut st = conn
            .prepare(
                "SELECT p.title||'|'||p.query||'|'||p.is_soql||'|'||p.viz||'|'||p.position||'|'||p.cols||'|'||IFNULL(p.panel_cache_ttl_s,'-')||'|'||p.managed \
                 FROM panel p JOIN dashboard d ON d.id=p.dashboard_id WHERE d.name=?1 ORDER BY p.position, p.id",
            )
            .expect("select");
        st.query_map(params![nom], |r| r.get::<_, String>(0)).expect("panneaux").collect::<Result<Vec<_>, _>>().expect("panneaux lus")
    }

    /// (vue, replié, visibilité, managed) du tableau.
    fn srbp_en_tete(conn: &Connection, nom: &str) -> (Option<String>, i64, String, i64) {
        conn.query_row(
            "SELECT v.name, d.collapsed, d.visibility, d.managed FROM dashboard d LEFT JOIN view v ON v.id=d.view_id WHERE d.name=?1",
            params![nom],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("en-tête du tableau")
    }

    /// Retire le tableau de ce nom et ses panneaux (la migration v52 a déjà semé « Banni / Pass » dans `test_db`).
    fn srbp_sans(conn: &Connection, nom: &str) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom]).expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![nom]).expect("tableau retiré");
        assert_eq!(srbp_tableaux(conn, nom), 0, "instrument : base sans « {nom} »");
    }

    fn srbp_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    fn srbp_refuser_la_lecture_du_nom(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "dashboard" && column_name == "name" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn srbp_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// INVERSE NOMINAL : chaque semis écrit son tableau (partagé, rattaché à sa vue, replié) et ses panneaux comme avant,
    /// octet pour octet ; un second appel n'ajoute rien ; le « Banni / Pass » semé par la migration v52 (`MigTx`) est
    /// le même.
    #[test]
    fn srbp_un_semis_nominal_ecrit_son_tableau_entier_une_seule_fois() {
        let conn = test_db();
        assert_eq!(srbp_tableaux(&conn, NOM_DU_BANNI_PASS), 1, "migration v52 : « Banni / Pass » semé une fois");
        assert_eq!(srbp_panneaux(&conn, NOM_DU_BANNI_PASS), srbp_panneaux_banni_pass(), "migration v52 : panneaux d'avant");
        assert_eq!(
            srbp_en_tete(&conn, NOM_DU_BANNI_PASS),
            (Some("Détection".to_string()), 1, "shared".to_string(), 2),
            "migration v52 : vue, repli, visibilité"
        );
        for (tag, nom, semer, vue, attendus) in srbp_semis() {
            let conn = test_db();
            srbp_sans(&conn, nom);
            semer(&conn);
            assert_eq!(srbp_tableaux(&conn, nom), 1, "`{tag}` : un tableau");
            assert_eq!(srbp_panneaux(&conn, nom), attendus, "`{tag}` : panneaux d'avant, dans l'ordre, octet pour octet");
            assert_eq!(srbp_en_tete(&conn, nom), (Some(vue.to_string()), 1, "shared".to_string(), 2), "`{tag}` : vue, repli, visibilité");
            let total = srbp_panneaux_en_tout(&conn);
            semer(&conn);
            assert_eq!(srbp_tableaux(&conn, nom), 1, "`{tag}` : second appel, aucun doublon");
            assert_eq!(srbp_panneaux_en_tout(&conn), total, "`{tag}` : second appel, aucun panneau de plus");
            assert!(conn.is_autocommit(), "`{tag}` : aucune transaction laissée ouverte");
        }
    }

    /// CE QU'IL TIENT : chaque panneau refusé à son tour, par `RAISE(ABORT)` et par `RAISE(IGNORE)` (qui rend `Ok(0)`) :
    /// aucun tableau de ce nom ni panneau de plus, transaction fermée ; au démarrage suivant le tableau entier ; ensuite
    /// rien de plus.
    /// MUTATIONS QUI LE FONT ROUGIR : forme d'avant (`AB4_rapide_forme_d_avant`, `AB4_bp_forme_d_avant`) ; panneau avalé
    /// (`AB4_rapide_panneau_avale`, `AB4_bp_panneau_avale`) ; `Ok(0)` accepté (`AB4_rapide_ok0_accepte`,
    /// `AB4_bp_panneau_ok0`) ; refus validé au lieu d'annulé (`AB4_bp_sans_annulation`).
    #[test]
    fn srbp_un_panneau_refuse_annule_le_tableau_entier_et_le_semis_suivant_le_reprend() {
        for (tag, nom, semer, _vue, attendus) in srbp_semis() {
            for rang in 0..attendus.len() {
                for (forme, corps) in [("ABORT", "RAISE(ABORT,'srbp refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                    let conn = test_db();
                    srbp_sans(&conn, nom);
                    let avant = srbp_panneaux_en_tout(&conn);
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER srbp_refus BEFORE INSERT ON panel WHEN NEW.position={rang} BEGIN SELECT {corps}; END;"
                    ))
                    .expect("déclencheur de refus");
                    semer(&conn);
                    assert_eq!(srbp_tableaux(&conn, nom), 0, "`{tag}` ({forme}, panneau {rang}) : aucun tableau conservé après le refus");
                    assert_eq!(srbp_panneaux_en_tout(&conn), avant, "`{tag}` ({forme}, panneau {rang}) : aucun panneau conservé");
                    assert!(conn.is_autocommit(), "`{tag}` ({forme}, panneau {rang}) : transaction fermée");
                    conn.execute_batch("DROP TRIGGER srbp_refus;").expect("base revenue");
                    semer(&conn);
                    assert_eq!(srbp_panneaux(&conn, nom), attendus, "`{tag}` ({forme}, panneau {rang}) : rejoué ENTIER ensuite");
                    semer(&conn);
                    assert_eq!(srbp_tableaux(&conn, nom), 1, "`{tag}` ({forme}, panneau {rang}) : aucun doublon ensuite");
                }
            }
        }
    }

    /// L'EN-TÊTE REFUSÉ (ABORT, et IGNORE : l'identifiant lu ensuite serait celui d'un leurre écrit juste avant) et LE
    /// RATTACHEMENT REFUSÉ (ABORT ; et IGNORE pour « Banni / Pass », qui exige `Ok(1)`) : aucun tableau, aucun panneau ;
    /// entier ensuite.
    /// MUTATIONS QUI LE FONT ROUGIR : formes d'avant ; `Ok(0)` accepté pour l'en-tête (`AB4_bp_entete_ok0`) ; rattachement
    /// avalé (`AB4_bp_rattachement_avale`) ; rattachement `Ok(0)` accepté (`AB4_bp_rattachement_ok0`).
    #[test]
    fn srbp_un_en_tete_ou_un_rattachement_refuse_n_ecrit_rien() {
        for (tag, nom, semer, _vue, attendus) in srbp_semis() {
            let nom_sql = nom.replace('\'', "''");
            let mut cas = vec![
                ("en-tête ABORT", format!("BEFORE INSERT ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(ABORT,'srbp refus'); END")),
                ("en-tête IGNORE", format!("BEFORE INSERT ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(IGNORE); END")),
                ("rattachement ABORT", "BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(ABORT,'srbp refus'); END".to_string()),
            ];
            if nom == NOM_DU_BANNI_PASS {
                cas.push(("rattachement IGNORE", "BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(IGNORE); END".to_string()));
            }
            for (etape, declencheur) in cas {
                let conn = test_db();
                srbp_sans(&conn, nom);
                let avant = srbp_panneaux_en_tout(&conn);
                conn.execute_batch(&format!("CREATE TRIGGER srbp_refus {declencheur};")).expect("déclencheur de refus");
                // Un leurre écrit juste avant : sur un en-tête `Ok(0)` accepté, `last_insert_rowid` rendrait SON identifiant
                // et les panneaux s'y accrocheraient (le rattachement, lui, trouverait une ligne et rendrait `Ok(1)`).
                conn.execute("INSERT INTO dashboard(name,created) VALUES('srbp leurre',0)", []).expect("leurre");
                semer(&conn);
                assert_eq!(srbp_tableaux(&conn, nom), 0, "`{tag}` ({etape}) : aucun tableau");
                assert_eq!(srbp_panneaux_en_tout(&conn), avant, "`{tag}` ({etape}) : aucun panneau, ni ici ni sous un autre tableau");
                assert!(conn.is_autocommit(), "`{tag}` ({etape}) : transaction fermée");
                conn.execute_batch("DROP TRIGGER srbp_refus;").expect("base revenue");
                semer(&conn);
                assert_eq!(srbp_panneaux(&conn, nom), attendus, "`{tag}` ({etape}) : rejoué entier ensuite");
            }
        }
    }

    /// LA PRÉSENCE NON LUE (lecture de `dashboard.name` refusée) n'écrit RIEN : ni sur une base sans le tableau (semé au
    /// démarrage suivant), ni sur une base qui l'a (aucun second tableau du même nom — la forme d'avant en écrivait un).
    /// « Vue d'ensemble (rapide) » la compte sous « présence non lue », et un panneau refusé sous « écriture ou COMMIT
    /// refusé » (base sur disque : le compte des témoins est tenu par base).
    /// MUTATIONS QUI LE FONT ROUGIR : formes d'avant ; lecture ratée prise pour une absence (`AB4_bp_lecture_ratee_absente`).
    #[test]
    fn srbp_une_presence_non_lue_n_ecrit_rien() {
        for (tag, nom, semer, _vue, attendus) in srbp_semis() {
            let (_tmp, conn) = srbp_base_sur_disque(&format!("srbp-presence-{tag}"));
            srbp_sans(&conn, nom);
            let compte = |etape: &str| compte_des_temoins(&conn, &format!("geste de fond non validé seed : {GESTE_TABLEAU_SEME_PAR_NOM} : {etape}"));
            let avant = srbp_panneaux_en_tout(&conn);

            srbp_refuser_la_lecture_du_nom(&conn);
            semer(&conn);
            srbp_rendre_la_main(&conn);
            assert_eq!(srbp_tableaux(&conn, nom), 0, "`{tag}` : présence non lue, tableau absent : rien n'est écrit");
            assert_eq!(srbp_panneaux_en_tout(&conn), avant, "`{tag}` : présence non lue, tableau absent : aucun panneau");
            assert!(conn.is_autocommit(), "`{tag}` : aucune transaction ouverte");

            semer(&conn);
            assert_eq!(srbp_panneaux(&conn, nom), attendus, "`{tag}` : démarrage suivant, semé entier");
            let total = srbp_panneaux_en_tout(&conn);

            srbp_refuser_la_lecture_du_nom(&conn);
            semer(&conn);
            srbp_rendre_la_main(&conn);
            assert_eq!(srbp_tableaux(&conn, nom), 1, "`{tag}` : présence non lue, tableau présent : aucun second tableau du même nom");
            assert_eq!(srbp_panneaux_en_tout(&conn), total, "`{tag}` : présence non lue, tableau présent : aucun panneau de plus");

            if nom == SRBP_RAPIDE {
                assert_eq!((compte(ETAPE_PRESENCE_NON_LUE), compte(ETAPE_ECRITURE_REFUSEE)), (2, 0), "`{tag}` : deux présences non lues comptées");
                srbp_sans(&conn, nom);
                conn.execute_batch("CREATE TRIGGER srbp_refus BEFORE INSERT ON panel WHEN NEW.position=4 BEGIN SELECT RAISE(ABORT,'srbp refus'); END;")
                    .expect("déclencheur de refus");
                semer(&conn);
                conn.execute_batch("DROP TRIGGER srbp_refus;").expect("base revenue");
                assert_eq!(srbp_tableaux(&conn, nom), 0, "`{tag}` : panneau refusé, aucun tableau");
                assert_eq!((compte(ETAPE_PRESENCE_NON_LUE), compte(ETAPE_ECRITURE_REFUSEE)), (2, 1), "`{tag}` : panneau refusé compté une fois");
            }
        }
    }

    /// LE POINT DE REPRISE DE « BANNI / PASS » : son ouverture refusée n'écrit rien ; sa validation (`RELEASE`, le
    /// `COMMIT` au démarrage) refusée annule tout et ferme la transaction ; le démarrage suivant sème le tableau entier.
    /// MUTATIONS QUI LE FONT ROUGIR : ouverture refusée ignorée (`AB4_bp_point_ignore`) ; validation refusée laissée telle
    /// quelle, transaction ouverte (`AB4_bp_release_refuse_laisse`) ; forme d'avant (aucun point de reprise).
    #[test]
    fn srbp_le_point_de_reprise_refuse_n_ecrit_rien() {
        for operation in [TransactionOperation::Begin, TransactionOperation::Release] {
            let conn = test_db();
            srbp_sans(&conn, NOM_DU_BANNI_PASS);
            let avant = srbp_panneaux_en_tout(&conn);
            let refuse = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marque = refuse.clone();
            conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: op, savepoint_name }
                    if op == operation && savepoint_name == POINT_DU_BANNI_PASS && !marque.swap(true, std::sync::atomic::Ordering::SeqCst) =>
                {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            seed_banpass_dashboard(&conn);
            srbp_rendre_la_main(&conn);
            assert!(refuse.load(std::sync::atomic::Ordering::SeqCst), "({operation:?}) : instrument — le refus a bien joué");
            assert!(conn.is_autocommit(), "({operation:?}) : transaction fermée");
            assert_eq!(srbp_tableaux(&conn, NOM_DU_BANNI_PASS), 0, "({operation:?}) : aucun tableau");
            assert_eq!(srbp_panneaux_en_tout(&conn), avant, "({operation:?}) : aucun panneau");
            seed_banpass_dashboard(&conn);
            assert_eq!(srbp_panneaux(&conn, NOM_DU_BANNI_PASS), srbp_panneaux_banni_pass(), "({operation:?}) : semé entier ensuite");
        }
    }

    /// LE CHEMIN DE LA MIGRATION V52 (`MigTx`) : un panneau de « Banni / Pass » refusé par un refus de classe A
    /// (`RAISE(ABORT)`, une contrainte) ou un `Ok(0)` (`RAISE(IGNORE)`) pendant la chaîne des migrations : la chaîne va au
    /// bout, l'étape est validée SANS ce tableau (avant : un tableau partiel, que le démarrage ne réparait jamais), et le
    /// semis du démarrage l'écrit entier.
    /// MUTATIONS QUI LE FONT ROUGIR : `AB4_bp_forme_d_avant`, `AB4_bp_panneau_avale`, `AB4_bp_panneau_ok0` (IGNORE),
    /// `AB4_bp_sans_annulation`.
    #[test]
    fn srbp_sous_la_migration_un_panneau_refuse_ne_laisse_aucun_tableau_partiel() {
        for (forme, corps) in [("ABORT", "RAISE(ABORT,'srbp refus')"), ("IGNORE", "RAISE(IGNORE)")] {
            let conn = Connection::open_in_memory().expect("base");
            conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
            conn.execute_batch(&format!(
                "CREATE TRIGGER srbp_refus BEFORE INSERT ON panel WHEN NEW.title='Attaquants NON mitigés (non bannis, fenêtre)' BEGIN SELECT {corps}; END;"
            ))
            .expect("déclencheur de refus");
            assert!(migrate(&conn), "({forme}) : la chaîne de migrations va au bout");
            let version: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("version");
            assert!(version.parse::<i64>().expect("version entière") >= 52, "({forme}) : l'étape v52 a été validée");
            assert_eq!(srbp_tableaux(&conn, NOM_DU_BANNI_PASS), 0, "({forme}) : aucun « Banni / Pass » partiel après la migration");
            let banni_pass_orphelins: i64 = conn
                .query_row("SELECT COUNT(*) FROM panel WHERE title IN ('Banlist par source','IPs bannies (dernier ban dans la fenêtre)')", [], |r| r.get(0))
                .expect("panneaux");
            assert_eq!(banni_pass_orphelins, 0, "({forme}) : aucun panneau de « Banni / Pass » conservé");
            assert!(conn.is_autocommit(), "({forme}) : transaction fermée");
            conn.execute_batch("DROP TRIGGER srbp_refus;").expect("base revenue");
            seed_banpass_dashboard(&conn);
            assert_eq!(srbp_panneaux(&conn, NOM_DU_BANNI_PASS), srbp_panneaux_banni_pass(), "({forme}) : le démarrage le sème entier");
        }
    }

    /// LA LIGNE DE JOURNAL DE « BANNI / PASS », lue sur le stderr d'un sous-processus : une ligne par semis non validé
    /// (présence non lue, point de reprise non ouvert, panneau refusé), qui dit la cause ; aucune au nominal (ni par la
    /// migration v52 de `test_db`, ni par le semis du démarrage).
    /// MUTATION QUI LE FAIT ROUGIR : `AB4_bp_journal_muet`.
    #[test]
    fn srbp_le_refus_de_banni_pass_est_dit_au_journal() {
        const ENFANT: &str = "SRBP_ENFANT_JOURNAL";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let conn = test_db();
            srbp_sans(&conn, NOM_DU_BANNI_PASS);
            println!("SRBP-ENFANT-A-JOUE");
            srbp_refuser_la_lecture_du_nom(&conn);
            seed_banpass_dashboard(&conn);
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Begin, savepoint_name } if savepoint_name == POINT_DU_BANNI_PASS => {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            seed_banpass_dashboard(&conn);
            srbp_rendre_la_main(&conn);
            conn.execute_batch("CREATE TRIGGER srbp_refus BEFORE INSERT ON panel WHEN NEW.position=2 BEGIN SELECT RAISE(ABORT,'srbp refus'); END;")
                .expect("déclencheur de refus");
            seed_banpass_dashboard(&conn);
            conn.execute_batch("DROP TRIGGER srbp_refus;").expect("base revenue");
            seed_banpass_dashboard(&conn);
            seed_banpass_dashboard(&conn);
            assert_eq!(srbp_tableaux(&conn, NOM_DU_BANNI_PASS), 1, "enfant : semé une fois au nominal");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::semis_rapide_et_banni_pass_entiers_ou_annules::srbp_le_refus_de_banni_pass_est_dit_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("SRBP-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let prefixe = format!("[seed] le tableau de bord « {NOM_DU_BANNI_PASS} » NON semé : ");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with(&prefixe)).collect();
        assert_eq!(lignes.len(), 3, "une ligne par semis non validé, aucune au nominal : {stderr}");
        assert!(lignes[0].contains("sa présence n'a pas pu être lue (") && lignes[0].contains("rien n'est écrit"), "présence non lue : {}", lignes[0]);
        assert!(lignes[1].contains("point de reprise non ouvert (") && lignes[1].contains("rien n'est écrit"), "point de reprise : {}", lignes[1]);
        assert!(
            lignes[2].contains("une écriture ou sa validation a été refusée (") && lignes[2].contains("srbp refus") && lignes[2].contains("RIEN n'est conservé"),
            "panneau refusé : {}",
            lignes[2]
        );
    }
}
