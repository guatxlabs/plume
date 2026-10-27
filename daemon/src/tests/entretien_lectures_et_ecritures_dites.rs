// =====================================================================================
// `P10.20-b` (tranche ENTRETIEN, `maintenance.rs`) — UNE LECTURE RATÉE N'EST NI « ABSENT » NI « ZÉRO », ET UNE
// ÉCRITURE REFUSÉE N'EST JAMAIS SUIVIE DE LA LIGNE DE SUCCÈS.
//
// LE DÉFAUT, LU SUR 5100db29 (`daemon/src/maintenance.rs`) :
//  * `taille_de_la_table_des_evenements` en `unwrap_or(0)`, jalon `analyze_full_done` en `.ok()`, version en
//    `unwrap_or_else("0")`, `ANALYZE` et jalon en `let _` : une lecture ratée lançait un `ANALYZE` complet (ou le
//    sautait) et écrivait un jalon mesuré sur rien ; un `ANALYZE` refusé posait son jalon et disait « terminé » ;
//  * backfill FTS : jalon et watermark en `.ok()`, `MAX(id)+1` en `unwrap_or(0)`, watermark non entier lu par
//    `CAST(… AS INTEGER)` (0) : `lo = 0`, la boucle ne tournait pas et le backfill était DÉCLARÉ TERMINÉ (jalon écrit)
//    sans rien indexer ; watermark et jalon final en `let _` ;
//  * kill-switch FTS-fields et index d'expression : chaque DDL en `let _`, puis la ligne « présents » / « DROPPÉS
//    (kill-switch appliqué) » ;
//  * présences au catalogue en `.is_ok()` (lecture ratée = absent : `CREATE` tenté, `DROP` sauté, « subsumant pas
//    encore présent » affirmé) ; énumérations d'orphelins en `rows.flatten()` (ligne en erreur perdue) ;
//    `constat_au_catalogue` en `.ok()` (non lu rangé sous « MANQUENT »).
//
// CE QUE CES TÉMOINS TIENNENT : chaque site, par son point d'entrée (`reconcile_index_state`,
// `reconcile_expr_indexes_background`, les tâches `*_background`), lecture rendue illisible SEULE (autorisateur sur
// une colonne ou un geste, BLOB sur une ligne, n-ième lecture refusée, pas interrompu par le gestionnaire de
// progression), écriture refusée (`RAISE(ABORT)`) ou à zéro ligne (`RAISE(IGNORE)`) ; le compte rendu est jugé EN
// ENTIER (lignes à l'égalité, deux comptes) contre des phrases LITTÉRALES de ce fichier, et l'état de la base après
// coup (jalon, watermark, index) dit qu'aucun geste n'a été fait ni sauté en silence. Contrôles positifs : chemins
// nominaux (lignes de succès inchangées).
//
// LA SORTIE D'ERREUR, SEULE SURFACE QUE LES APPELANTS DE PRODUCTION LISENT (ils ignorent la valeur rendue) : un témoin
// relance son binaire en sous-processus et exige que les lignes rendues soient, à l'égalité et dans l'ordre, celles
// parties sur son stderr (`av4_journal_les_lignes_rendues_sont_celles_de_la_sortie_d_erreur`). Les autres témoins jugent
// la valeur rendue, que ce témoin-là relie au journal.
//
// TOUS LES GESTES SONT TENTÉS : un refus en TÊTE de liste (trigger `event_ff_ai`, premier `DROP` des index d'expression)
// exige que les gestes SUIVANTS aient eu lieu (un `break` après le premier refus rougit).
//
// CE QU'ILS NE TIENNENT PAS : `drop_prefix_subsumed_indexes_background` partage `drop_subsumed_index` avec
// `drop_redundant_event_indexes_background` et n'a pas de témoin propre ; le stderr n'est relu que pour
// `reconcile_index_state`, les autres tâches passant par le même `CompteRenduDEntretien::dire`.
// =====================================================================================
mod entretien_lectures_et_ecritures_dites {
    use super::*;
    use crate::maintenance::{
        analyze_full_background, drop_orphan_auto_field_indexes_background, drop_redundant_event_indexes_background,
        ensure_event_category_index_background, ensure_event_health_beat_index_background,
        ensure_event_src_ts_index_background, ensure_host_rollup_scan_indexes_background, fts_backfill_background,
        reconcile_expr_indexes_background, reconcile_index_state, retirer_les_index_de_champ_chaud_orphelins,
        CompteRenduDEntretien, MARQUEUR_INDEX_MANQUANTS, MARQUEUR_INDEX_NON_LUS,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const AV4_NON_AUTORISE: &str = "not authorized";
    /// La cause qu'écrit le moteur pour une LECTURE refusée par l'autorisateur (les autres gestes : `AV4_NON_AUTORISE`).
    const AV4_NOM_INTERDIT: &str = "access to sqlite_master.name is prohibited";
    const AV4_SQL_INTERDIT: &str = "access to sqlite_master.sql is prohibited";
    const AV4_ID_INTERDIT: &str = "access to event.id is prohibited";
    const AV4_VALEUR_INTERDITE: &str = "access to meta.value is prohibited";
    const AV4_INTERROMPU: &str = "interrupted";
    const AV4_BLOB: &str = "Invalid column type Blob at index: 0, name: value";
    const AV4_ZERO_LIGNE: &str = "Query changed 0 rows";
    const AV4_ABANDON: &str = "refus de test";
    const AV4_ORPHELIN_CHAUD: &str = "idx_ev_f_av4orphelin";
    const AV4_ORPHELIN_AUTO: &str = "idx_ev_auto_av4";

    fn av4_cr(lignes: &[String], lectures: usize, ecritures: usize) -> CompteRenduDEntretien {
        CompteRenduDEntretien { lignes: lignes.to_vec(), lectures_non_faites: lectures, ecritures_refusees: ecritures }
    }

    fn av4_db() -> Arc<parking_lot::Mutex<Connection>> {
        Arc::new(parking_lot::Mutex::new(test_db()))
    }

    fn av4_conf(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn av4_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Refuse la lecture de la colonne `name` de `sqlite_master` (toutes les présences au catalogue).
    fn av4_refuser_les_noms_du_catalogue(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "sqlite_master" && column_name == "name" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Refuse la N-ième lecture (à partir de 1) de `table.colonne`, et elle seule.
    fn av4_refuser_la_n_ieme_lecture(conn: &Connection, table: &'static str, colonne: &'static str, n: usize) {
        let mut vues = 0usize;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => {
                vues += 1;
                if vues == n { Authorization::Deny } else { Authorization::Allow }
            }
            _ => Authorization::Allow,
        }));
    }

    fn av4_present(conn: &Connection, nom: &str) -> bool {
        conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name=?1", params![nom], |r| r.get::<_, i64>(0)).expect("catalogue") == 1
    }

    fn av4_meta(conn: &Connection, cle: &str) -> Option<(String, String)> {
        use rusqlite::OptionalExtension as _;
        conn.query_row("SELECT typeof(value), CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default())))
            .optional()
            .expect("meta")
    }

    fn av4_trigger_meta(conn: &Connection, cle: &str, raise: &str) {
        conn.execute_batch(&format!(
            "CREATE TRIGGER av4_refus_meta BEFORE INSERT ON meta WHEN NEW.key='{cle}' BEGIN SELECT {raise}; END;"
        ))
        .expect("déclencheur de refus");
    }

    // ---------------------------------------------------------------------------------------------
    // reconcile_index_state : kill-switch FTS-fields et index d'expression
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn av4_fts_on_nominal_dit_presents() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        let v: String = conn.query_row("SELECT sqlite_version()", [], |r| r.get(0)).expect("version");
        let mut it = v.split('.');
        let (maj, min) = (it.next().expect("maj"), it.next().expect("min"));
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        assert_eq!(
            cr,
            av4_cr(&[format!("[reconcile] FTS-fields ON : event_fields_fts + triggers présents (SQLite {maj}.{min} ; delete FTS par reconstruction des tokens — pas de fuite disque)")], 0, 0)
        );
        assert!(av4_present(&conn, "event_ff_ad") && av4_present(&conn, "event_ff_ai") && av4_present(&conn, "event_fields_fts"));
    }

    #[test]
    fn av4_fts_on_ddl_refuse_dit_et_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::CreateTrigger { trigger_name, .. } if trigger_name == "event_ff_ad" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        av4_rendre_la_main(&conn);
        assert_eq!(
            cr,
            av4_cr(
                &[
                    format!("[reconcile] FTS-fields ON : CREATE du trigger event_ff_ad REFUSÉ ({AV4_NON_AUTORISE}) — retry au prochain boot"),
                    "[reconcile] FTS-fields ON INCOMPLET : 1 DDL refusé(s) sur 4 — event_fields_fts et ses triggers ne sont PAS tous en place ; retry au prochain boot".to_string(),
                ],
                0,
                1
            )
        );
        assert!(!av4_present(&conn, "event_ff_ad"), "le trigger AD n'est pas en place : la ligne ne dit pas « présents »");
        assert!(av4_present(&conn, "event_ff_ai"), "le DDL PRÉCÉDENT (CREATE de event_ff_ai) a été tenté");
    }

    /// Refus du DDL de TÊTE (le trigger `event_ff_ai`, deuxième des quatre gestes) : les DDL SUIVANTS (`DROP` puis
    /// `CREATE` de `event_ff_ad`) sont tentés quand même. MUTATION : `AV4b_fts_on_break` (`break` après le premier refus).
    #[test]
    fn av4_fts_on_ddl_de_tete_refuse_les_suivants_poses() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        assert!(!av4_present(&conn, "event_ff_ad"), "instrument : le trigger AD n'est pas déjà là");
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::CreateTrigger { trigger_name, .. } if trigger_name == "event_ff_ai" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        av4_rendre_la_main(&conn);
        assert_eq!(
            cr,
            av4_cr(
                &[
                    format!("[reconcile] FTS-fields ON : CREATE du trigger event_ff_ai REFUSÉ ({AV4_NON_AUTORISE}) — retry au prochain boot"),
                    "[reconcile] FTS-fields ON INCOMPLET : 1 DDL refusé(s) sur 4 — event_fields_fts et ses triggers ne sont PAS tous en place ; retry au prochain boot".to_string(),
                ],
                0,
                1
            )
        );
        assert!(!av4_present(&conn, "event_ff_ai"), "le trigger refusé n'est pas là");
        assert!(av4_present(&conn, "event_fields_fts"), "le DDL précédent a été tenté");
        assert!(av4_present(&conn, "event_ff_ad"), "les DDL SUIVANTS (DROP puis CREATE de event_ff_ad) ont été tentés malgré le refus de tête");
    }

    /// La version de SQLite NON LUE : la ligne de succès le dit avec la cause du moteur, elle n'invente pas « SQLite 0.0 ».
    /// Non comptée (la version ne décide d'aucun geste). MUTATION : `AV4b_version_invente`.
    #[test]
    fn av4_fts_on_version_non_lue_dite_jamais_inventee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("sqlite_version") => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cause = conn
            .query_row("SELECT sqlite_version()", [], |r| r.get::<_, String>(0))
            .expect_err("instrument : la lecture de la version est refusée")
            .to_string();
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        av4_rendre_la_main(&conn);
        assert_eq!(
            cr,
            av4_cr(&[format!("[reconcile] FTS-fields ON : event_fields_fts + triggers présents (version SQLite non lue ({cause}) ; delete FTS par reconstruction des tokens — pas de fuite disque)")], 0, 0)
        );
        assert!(av4_present(&conn, "event_ff_ad") && av4_present(&conn, "event_ff_ai") && av4_present(&conn, "event_fields_fts"));
    }

    /// LE JOURNAL : les lignes rendues sont, à l'égalité et dans l'ordre, celles parties sur la sortie d'erreur — seule
    /// surface que lisent les appelants de production (ils ignorent la valeur rendue). Sous-processus : le test relance
    /// son binaire (`current_exe()`) avec `AV4_ENFANT_JOURNAL` ; le bras de l'enfant joue un ON refusé en tête puis un
    /// OFF nominal, et imprime les lignes rendues sur stdout ; ce bras-ci compare au stderr. MUTATION : `AV4b_journal`.
    #[test]
    fn av4_journal_les_lignes_rendues_sont_celles_de_la_sortie_d_erreur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        const ENFANT: &str = "AV4_ENFANT_JOURNAL";
        const RENDUE: &str = "AV4-RENDUE:";
        const FIN: &str = "AV4-FIN:";
        if std::env::var(ENFANT).is_ok() {
            let conn = test_db();
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::CreateTrigger { trigger_name, .. } if trigger_name == "event_ff_ai" => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let mut cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
            av4_rendre_la_main(&conn);
            let off = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "0"), ("PLUME_EXPRINDEX", "0")]));
            cr.lignes.extend(off.lignes);
            for l in &cr.lignes {
                println!("{RENDUE}{l}");
            }
            println!("{FIN}{}", cr.lignes.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::entretien_lectures_et_ecritures_dites::av4_journal_les_lignes_rendues_sont_celles_de_la_sortie_d_erreur",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // `split_once` et non `strip_prefix` : libtest écrit « test <nom> ... » sans retour à la ligne avant la première.
        let rendues: Vec<String> = stdout.lines().filter_map(|l| l.split_once(RENDUE).map(|(_, r)| r)).map(str::to_string).collect();
        assert!(stdout.contains(&format!("{FIN}{}", rendues.len())), "contrôle : l'enfant a tout imprimé : {stdout}");
        assert_eq!(rendues.len(), 4, "plancher : refus + INCOMPLET + FTS OFF + index OFF : {rendues:?}");
        let journal: Vec<String> = stderr.lines().filter(|l| l.starts_with("[reconcile]")).map(str::to_string).collect();
        assert_eq!(journal, rendues, "chaque ligne rendue est partie sur la sortie d'erreur, et elle seule :\n{stderr}");
    }

    #[test]
    fn av4_fts_off_drop_refuse_dit_et_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        let on = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        assert_eq!(on.ecritures_refusees, 0, "instrument : infra FTS posée");
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::DropTrigger { trigger_name, .. } if trigger_name == "event_ff_ai" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "0"), ("PLUME_EXPRINDEX", "1")]));
        av4_rendre_la_main(&conn);
        assert_eq!(
            cr,
            av4_cr(
                &[
                    format!("[reconcile] FTS-fields OFF : DROP du trigger event_ff_ai REFUSÉ ({AV4_NON_AUTORISE}) — retry au prochain boot"),
                    "[reconcile] FTS-fields OFF INCOMPLET (PLUME_FTS_FIELDS!=1) : 1 DROP refusé(s) sur 3 — kill-switch NON appliqué en entier ; retry au prochain boot".to_string(),
                ],
                0,
                1
            )
        );
        assert!(av4_present(&conn, "event_ff_ai"), "le trigger refusé est toujours là : le kill-switch n'est pas dit appliqué");
        assert!(!av4_present(&conn, "event_ff_ad"), "les DROP suivants sont tentés");
    }

    /// Toute la famille posée, le `DROP` de TÊTE (`HOT_FIELDS[0]`) refusé : il est dit et compté, et les `DROP` SUIVANTS
    /// sont tentés — leurs index ont disparu. MUTATIONS : `AV4_expr_fast_let`, `AV4b_expr_off_break` (`break` après le
    /// premier refus).
    #[test]
    fn av4_index_d_expression_off_drop_refuse_par_l_entree() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        assert!(HOT_FIELDS.len() >= 2, "plancher : la liste chaude porte des champs");
        let conn = test_db();
        for c in HOT_FIELDS {
            conn.execute_batch(&format!(
                "CREATE INDEX IF NOT EXISTS idx_ev_f_{c} ON event(json_extract(fields,'$.{c}')) WHERE json_extract(fields,'$.{c}') IS NOT NULL;"
            ))
            .expect("index posé");
        }
        let champ = HOT_FIELDS[0];
        let nom = format!("idx_ev_f_{champ}");
        let refuse = nom.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::DropIndex { index_name, .. } if index_name == refuse => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "0"), ("PLUME_EXPRINDEX", "0")]));
        av4_rendre_la_main(&conn);
        assert_eq!(
            cr,
            av4_cr(
                &[
                    "[reconcile] FTS-fields OFF (PLUME_FTS_FIELDS!=1) : vtable + triggers DROPPÉS (kill-switch appliqué)".to_string(),
                    format!("[reconcile] index expression OFF : DROP INDEX {nom} REFUSÉ ({AV4_NON_AUTORISE}) — retry au prochain boot"),
                    format!(
                        "[reconcile] index expression OFF INCOMPLET (PLUME_EXPRINDEX!=1) : 1 DROP refusé(s) sur {} — kill-switch NON appliqué en entier ; retry au prochain boot",
                        HOT_FIELDS.len()
                    ),
                ],
                0,
                1
            )
        );
        assert!(av4_present(&conn, &nom), "l'index refusé est toujours là");
        for c in &HOT_FIELDS[1..] {
            assert!(!av4_present(&conn, &format!("idx_ev_f_{c}")), "le DROP SUIVANT de idx_ev_f_{c} a été tenté malgré le refus de tête");
        }
    }

    #[test]
    fn av4_index_d_expression_off_nominal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let conn = test_db();
        let cr = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "0"), ("PLUME_EXPRINDEX", "0")]));
        assert_eq!(
            cr,
            av4_cr(
                &[
                    "[reconcile] FTS-fields OFF (PLUME_FTS_FIELDS!=1) : vtable + triggers DROPPÉS (kill-switch appliqué)".to_string(),
                    format!("[reconcile] index expression OFF (PLUME_EXPRINDEX!=1) : {} index DROPPÉS (kill-switch appliqué ; full-scan json_extract)", HOT_FIELDS.len()),
                ],
                0,
                0
            )
        );
    }

    // ---------------------------------------------------------------------------------------------
    // constat au catalogue : non lu nommé à part
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn av4_constat_non_lu_nomme_a_part_jamais_sous_manquent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _levier = ReglageBackupPose::neuf("PLUME_EXPRINDEX", "1");
        assert!(HOT_FIELDS.len() >= 2, "plancher : la liste chaude porte des champs");
        let db = av4_db();
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "sqlite_master" && column_name == "sql" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let ligne = reconcile_expr_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        let non_lus: Vec<String> = HOT_FIELDS.iter().map(|c| format!("idx_ev_f_{c} ({AV4_SQL_INTERDIT})")).collect();
        let attendue = format!(
            "[reconcile-bg] 0/{} index expression partiels CONSTATÉS au catalogue — la passe n'a pas abouti pour tous, retry au prochain boot ; NON LUS AU CATALOGUE : {}",
            HOT_FIELDS.len(),
            non_lus.join(" ; ")
        );
        assert_eq!(ligne.as_deref(), Some(attendue.as_str()));
        assert!(!attendue.contains(MARQUEUR_INDEX_MANQUANTS), "instrument : la phrase attendue n'accuse aucun manquant");
    }

    /// Autorisateur du cas MÊLÉ : refuse le `CREATE` de `absent`, compte les lectures de `sqlite_master.sql`, et refuse
    /// celle de rang `refuser` (à partir de 1) si elle est donnée. Rend le compteur.
    fn av4_autorisateur_mele(conn: &Connection, absent: String, refuser: Option<usize>) -> Arc<AtomicUsize> {
        let vues = Arc::new(AtomicUsize::new(0));
        let compteur = Arc::clone(&vues);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::CreateIndex { index_name, .. } if index_name == absent => Authorization::Deny,
            AuthAction::Read { table_name, column_name } if table_name == "sqlite_master" && column_name == "sql" => {
                let rang = compteur.fetch_add(1, Ordering::SeqCst) + 1;
                if Some(rang) == refuser { Authorization::Deny } else { Authorization::Allow }
            }
            _ => Authorization::Allow,
        }));
        vues
    }

    /// CAS MÊLÉ : un index NON LU (lecture de sa définition refusée au compte rendu final) ET un index ABSENT (CREATE
    /// refusé). L'accusation des non lus PRÉCÈDE celle des manquants, et la liste introduite par
    /// `MARQUEUR_INDEX_MANQUANTS` reste la fin de la ligne : le lecteur `split_once(MARQUEUR_INDEX_MANQUANTS)` (garde
    /// `P6.8-f`) n'y lit QUE le manquant. Le rang de la lecture refusée est calibré sur une base jumelle (toutes les
    /// lectures de la passe comptées ; les `HOT_FIELDS.len()` dernières sont celles du compte rendu final, dans l'ordre
    /// de la déclaration). MUTATION : `AV4b_non_lus_apres`.
    #[test]
    fn av4_constat_mele_non_lus_avant_manquent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _levier = ReglageBackupPose::neuf("PLUME_EXPRINDEX", "1");
        let n = HOT_FIELDS.len();
        assert!(n >= 3, "plancher : la liste chaude porte au moins trois champs");
        let (non_lu, absent) = (HOT_FIELDS[0], HOT_FIELDS[1]);
        let nom_absent = format!("idx_ev_f_{absent}");
        // Calibration sur une base jumelle : aucune lecture refusée, toutes comptées.
        let jumelle = av4_db();
        let vues = av4_autorisateur_mele(&jumelle.lock(), nom_absent.clone(), None);
        let _ = reconcile_expr_indexes_background(&jumelle);
        av4_rendre_la_main(&jumelle.lock());
        let total = vues.load(Ordering::SeqCst);
        assert!(total >= 2 * n, "instrument : court-circuit puis compte rendu final lisent chacun {n} définitions ({total} lues)");
        // La base jugée : la lecture de la définition de HOT_FIELDS[0] au compte rendu final est refusée.
        let db = av4_db();
        let _vues = av4_autorisateur_mele(&db.lock(), nom_absent.clone(), Some(total - n + 1));
        let ligne = reconcile_expr_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        let attendue = format!(
            "[reconcile-bg] {}/{n} index expression partiels CONSTATÉS au catalogue — la passe n'a pas abouti pour tous, retry au prochain boot ; {MARQUEUR_INDEX_NON_LUS} idx_ev_f_{non_lu} ({AV4_SQL_INTERDIT}) ; {MARQUEUR_INDEX_MANQUANTS} {absent}",
            n - 2
        );
        assert_eq!(ligne.as_deref(), Some(attendue.as_str()));
        let annonces = ligne.as_deref().and_then(|l| l.split_once(MARQUEUR_INDEX_MANQUANTS)).map(|(_, fin)| fin.trim().to_string());
        assert_eq!(annonces.as_deref(), Some(absent), "la liste des manquants, lue jusqu'à la fin de la ligne, ne porte que le manquant");
        let c = db.lock();
        assert!(av4_present(&c, &format!("idx_ev_f_{non_lu}")), "l'index non lu est bien posé : seule sa lecture a été refusée");
        assert!(!av4_present(&c, &nom_absent), "instrument : l'index absent l'est vraiment");
    }

    // ---------------------------------------------------------------------------------------------
    // orphelins : énumération entière ou rien, DROP refusé compté
    // ---------------------------------------------------------------------------------------------

    fn av4_poser_l_orphelin_chaud(conn: &Connection) {
        conn.execute_batch(&format!("CREATE INDEX {AV4_ORPHELIN_CHAUD} ON event(json_extract(fields,'$.av4orphelin'));")).expect("orphelin posé");
    }

    #[test]
    fn av4_orphelins_chauds_enumeration_interrompue_dite_rien_retire() {
        let conn = test_db();
        av4_poser_l_orphelin_chaud(&conn);
        conn.progress_handler(1, Some(|| true));
        let r = retirer_les_index_de_champ_chaud_orphelins(&conn);
        conn.progress_handler(0, None::<fn() -> bool>);
        assert!(r.retires.is_empty());
        assert_eq!(
            r.compte_rendu,
            av4_cr(&[format!("[reconcile-bg] énumération des index de champ chaud ÉCHEC ({AV4_INTERROMPU}) — aucun retrait ce boot, retry au prochain boot")], 1, 0)
        );
        assert!(av4_present(&conn, AV4_ORPHELIN_CHAUD), "l'orphelin non lu reste, et c'est dit");
    }

    #[test]
    fn av4_orphelins_chauds_drop_refuse_compte_et_nominal_dit() {
        let conn = test_db();
        av4_poser_l_orphelin_chaud(&conn);
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::DropIndex { index_name, .. } if index_name == AV4_ORPHELIN_CHAUD => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = retirer_les_index_de_champ_chaud_orphelins(&conn);
        av4_rendre_la_main(&conn);
        assert!(r.retires.is_empty());
        assert_eq!(
            r.compte_rendu,
            av4_cr(&[format!("[reconcile-bg] DROP INDEX {AV4_ORPHELIN_CHAUD} ÉCHEC ({AV4_NON_AUTORISE}) — retry au prochain boot")], 0, 1)
        );
        let r = retirer_les_index_de_champ_chaud_orphelins(&conn);
        assert_eq!(r.retires, vec![AV4_ORPHELIN_CHAUD.to_string()]);
        assert_eq!(
            r.compte_rendu,
            av4_cr(&[format!("[reconcile-bg] {AV4_ORPHELIN_CHAUD} DROPPÉ (index de champ chaud ORPHELIN : « av4orphelin » n'est plus dans la liste chaude, plus rien ne savait le nommer — ni le kill-switch, ni la purge voisine ; P6.8-e)")], 0, 0)
        );
    }

    #[test]
    fn av4_orphelins_auto_enumeration_interrompue_dite_rien_retire() {
        let db = av4_db();
        db.lock().execute_batch(&format!("CREATE INDEX {AV4_ORPHELIN_AUTO} ON event(source);")).expect("orphelin posé");
        db.lock().progress_handler(1, Some(|| true));
        let cr = drop_orphan_auto_field_indexes_background(&db);
        db.lock().progress_handler(0, None::<fn() -> bool>);
        assert_eq!(
            cr,
            av4_cr(&[format!("[reconcile-bg] énumération des idx_ev_auto_* ÉCHEC ({AV4_INTERROMPU}) — aucun retrait ce boot, retry au prochain boot")], 1, 0)
        );
        assert!(av4_present(&db.lock(), AV4_ORPHELIN_AUTO));
    }

    #[test]
    fn av4_orphelins_auto_drop_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch(&format!("CREATE INDEX {AV4_ORPHELIN_AUTO} ON event(source);")).expect("orphelin posé");
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::DropIndex { index_name, .. } if index_name == AV4_ORPHELIN_AUTO => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = drop_orphan_auto_field_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[format!("[reconcile-bg] DROP INDEX {AV4_ORPHELIN_AUTO} ÉCHEC ({AV4_NON_AUTORISE}) — retry au prochain boot")], 0, 1));
        assert!(av4_present(&db.lock(), AV4_ORPHELIN_AUTO));
    }

    // ---------------------------------------------------------------------------------------------
    // présences au catalogue des tâches qui CRÉENT
    // ---------------------------------------------------------------------------------------------

    fn av4_presence_non_lue(nom: &str) -> String {
        format!("[reconcile-bg] présence de {nom} NON LUE au catalogue ({AV4_NOM_INTERDIT}) — CREATE non tenté ce boot, retry au prochain boot")
    }

    fn av4_create_refuse(nom: &str) -> String {
        format!("[reconcile-bg] CREATE INDEX {nom} ÉCHEC ({AV4_NON_AUTORISE}) — retry au prochain boot")
    }

    fn av4_refuser_le_create(conn: &Connection, nom: &'static str) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::CreateIndex { index_name, .. } if index_name == nom => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    #[test]
    fn av4_categorie_presence_non_lue_create_differe() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_category;").expect("retrait");
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = ensure_event_category_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_presence_non_lue("idx_event_category")], 1, 0));
        assert!(!av4_present(&db.lock(), "idx_event_category"), "aucun CREATE tenté sur une présence non lue");
    }

    #[test]
    fn av4_categorie_create_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_category;").expect("retrait");
        av4_refuser_le_create(&db.lock(), "idx_event_category");
        let cr = ensure_event_category_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_create_refuse("idx_event_category")], 0, 1));
    }

    #[test]
    fn av4_source_ts_presence_non_lue_create_differe() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_src_ts;").expect("retrait");
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = ensure_event_src_ts_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_presence_non_lue("idx_event_src_ts")], 1, 0));
        assert!(!av4_present(&db.lock(), "idx_event_src_ts"));
    }

    #[test]
    fn av4_source_ts_create_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_src_ts;").expect("retrait");
        av4_refuser_le_create(&db.lock(), "idx_event_src_ts");
        let cr = ensure_event_src_ts_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_create_refuse("idx_event_src_ts")], 0, 1));
    }

    #[test]
    fn av4_battement_presence_non_lue_create_differe() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_health_beat;").expect("retrait");
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = ensure_event_health_beat_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_presence_non_lue("idx_event_health_beat")], 1, 0));
        assert!(!av4_present(&db.lock(), "idx_event_health_beat"));
    }

    #[test]
    fn av4_battement_create_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_event_health_beat;").expect("retrait");
        av4_refuser_le_create(&db.lock(), "idx_event_health_beat");
        let cr = ensure_event_health_beat_index_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_create_refuse("idx_event_health_beat")], 0, 1));
    }

    #[test]
    fn av4_rollup_hotes_presence_non_lue_par_index() {
        let db = av4_db();
        db.lock().execute_batch("DROP INDEX IF EXISTS idx_metric_ts; DROP INDEX IF EXISTS idx_snapshot_ts;").expect("retrait");
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = ensure_host_rollup_scan_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_presence_non_lue("idx_metric_ts"), av4_presence_non_lue("idx_snapshot_ts")], 2, 0));
        assert!(!av4_present(&db.lock(), "idx_metric_ts") && !av4_present(&db.lock(), "idx_snapshot_ts"));
    }

    #[test]
    fn av4_rollup_hotes_create_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch("CREATE INDEX IF NOT EXISTS idx_snapshot_ts ON snapshot(ts); DROP INDEX IF EXISTS idx_metric_ts;").expect("état");
        av4_refuser_le_create(&db.lock(), "idx_metric_ts");
        let cr = ensure_host_rollup_scan_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_create_refuse("idx_metric_ts")], 0, 1));
    }

    // ---------------------------------------------------------------------------------------------
    // retraits d'index subsumés : redondant et subsumant non lus, DROP refusé
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn av4_subsume_redondant_non_lu_conserve_et_dit() {
        let db = av4_db();
        db.lock()
            .execute_batch("CREATE INDEX IF NOT EXISTS idx_event_sev ON event(severity); CREATE INDEX IF NOT EXISTS idx_event_src ON event(source);")
            .expect("redondants posés");
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = drop_redundant_event_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        let phrase = |nom: &str| format!("[reconcile-bg] présence de {nom} NON LUE au catalogue ({AV4_NOM_INTERDIT}) — DROP non tenté ce boot, retry au prochain boot");
        assert_eq!(cr, av4_cr(&[phrase("idx_event_sev"), phrase("idx_event_src")], 2, 0));
        assert!(av4_present(&db.lock(), "idx_event_sev") && av4_present(&db.lock(), "idx_event_src"));
    }

    #[test]
    fn av4_subsume_subsumant_non_lu_conserve_sous_sa_phrase() {
        let db = av4_db();
        db.lock()
            .execute_batch("DROP INDEX IF EXISTS idx_event_sev; CREATE INDEX IF NOT EXISTS idx_event_src ON event(source); CREATE INDEX IF NOT EXISTS idx_event_src_ts ON event(source, ts);")
            .expect("état");
        // Lectures de `name` : 1) idx_event_sev (absent), 2) idx_event_src (présent), 3) idx_event_src_ts -> refusée.
        av4_refuser_la_n_ieme_lecture(&db.lock(), "sqlite_master", "name", 3);
        let cr = drop_redundant_event_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(
            cr,
            av4_cr(
                &[format!("[reconcile-bg] idx_event_src CONSERVÉ ce boot : la présence de son subsumant idx_event_src_ts n'a PAS pu être lue ({AV4_NOM_INTERDIT}) (drop différé -> zéro fenêtre de scan ; retry au prochain boot)")],
                1,
                0
            )
        );
        assert!(av4_present(&db.lock(), "idx_event_src"));
        // Contrôle : un subsumant ABSENT (lu) garde la phrase d'avant, sans compte.
        db.lock().execute_batch("DROP INDEX idx_event_src_ts;").expect("subsumant retiré");
        let cr = drop_redundant_event_indexes_background(&db);
        assert_eq!(
            cr,
            av4_cr(&["[reconcile-bg] idx_event_src CONSERVÉ ce boot : son subsumant idx_event_src_ts n'est pas encore présent (drop différé -> zéro fenêtre de scan ; retry au prochain boot)".to_string()], 0, 0)
        );
    }

    #[test]
    fn av4_subsume_drop_refuse_compte() {
        let db = av4_db();
        db.lock().execute_batch("CREATE INDEX IF NOT EXISTS idx_event_sev ON event(severity); DROP INDEX IF EXISTS idx_event_src;").expect("état");
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::DropIndex { index_name, .. } if index_name == "idx_event_sev" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = drop_redundant_event_indexes_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[format!("[reconcile-bg] DROP INDEX idx_event_sev ÉCHEC ({AV4_NON_AUTORISE}) — retry au prochain boot")], 0, 1));
        assert!(av4_present(&db.lock(), "idx_event_sev"));
    }

    // ---------------------------------------------------------------------------------------------
    // ANALYZE complet
    // ---------------------------------------------------------------------------------------------

    /// Base sans jalon d'analyse ; rend (version de schéma, taille mesurée).
    fn av4_base_d_analyse() -> (Arc<parking_lot::Mutex<Connection>>, String, i64) {
        let db = av4_db();
        let (v, n) = {
            let c = db.lock();
            c.execute("DELETE FROM meta WHERE key='analyze_full_done'", []).expect("jalon retiré");
            let v: String = c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("version");
            let n: i64 = c.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).expect("taille");
            (v, n)
        };
        (db, v, n)
    }

    #[test]
    fn av4_analyse_nominale_dit_terminee_puis_rien() {
        let (db, v, n) = av4_base_d_analyse();
        let cr = analyze_full_background(&db);
        assert_eq!(cr, av4_cr(&[format!("[analyze] ANALYZE complet terminé (tâche de fond, jalon {v}@{n}) -> stats exactes pour les index composés")], 0, 0));
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), Some(("text".to_string(), format!("{v}@{n}"))));
        assert_eq!(analyze_full_background(&db), av4_cr(&[], 0, 0), "déjà faite : rien, en silence");
    }

    #[test]
    fn av4_analyse_jalon_illisible_ni_refaite_ni_tenue_pour_faite() {
        let (db, _, _) = av4_base_d_analyse();
        db.lock().execute("INSERT INTO meta(key,value) VALUES('analyze_full_done', x'00')", []).expect("jalon BLOB");
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            av4_cr(&[format!("[analyze] ANALYZE complet NON tenté : le jalon analyze_full_done n'a pas pu être lu ({AV4_BLOB}) — ni refait ni tenu pour fait, retry au prochain boot")], 1, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done").map(|m| m.0), Some("blob".to_string()), "jalon intact : aucun ANALYZE lancé");
    }

    #[test]
    fn av4_analyse_version_illisible_aucun_jalon() {
        let (db, _, _) = av4_base_d_analyse();
        db.lock().execute("UPDATE meta SET value=x'00' WHERE key='schema_version'", []).expect("version BLOB");
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            av4_cr(&[format!("[analyze] ANALYZE complet NON tenté : la version de schéma n'a pas pu être lue ({AV4_BLOB}) — aucun jalon écrit, retry au prochain boot")], 1, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    #[test]
    fn av4_analyse_version_absente_aucun_jalon() {
        let (db, _, _) = av4_base_d_analyse();
        db.lock().execute("DELETE FROM meta WHERE key='schema_version'", []).expect("version retirée");
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            av4_cr(&["[analyze] ANALYZE complet NON tenté : la version de schéma est ABSENTE de meta — aucun jalon écrit, retry au prochain boot".to_string()], 0, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    #[test]
    fn av4_analyse_taille_non_lue_aucun_jalon() {
        let (db, _, _) = av4_base_d_analyse();
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "event" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = analyze_full_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(
            cr,
            av4_cr(&[format!("[analyze] ANALYZE complet NON tenté : la taille de la table event n'a pas pu être lue ({AV4_ID_INTERDIT}) — aucun jalon écrit, retry au prochain boot")], 1, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    #[test]
    fn av4_analyse_refusee_aucun_jalon() {
        let (db, _, _) = av4_base_d_analyse();
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Analyze { .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = analyze_full_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[format!("[analyze] ANALYZE complet ÉCHEC ({AV4_NON_AUTORISE}) — jalon NON écrit, la passe sera retentée au prochain boot")], 0, 1));
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    #[test]
    fn av4_analyse_jalon_refuse_dit_jamais_terminee() {
        let (db, v, n) = av4_base_d_analyse();
        av4_trigger_meta(&db.lock(), "analyze_full_done", &format!("RAISE(ABORT, '{AV4_ABANDON}')"));
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            av4_cr(&[format!("[analyze] ANALYZE complet fait, mais son jalon {v}@{n} n'a PAS été écrit ({AV4_ABANDON}) — la passe sera refaite au prochain boot")], 0, 1)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    #[test]
    fn av4_analyse_jalon_a_zero_ligne_dit_jamais_terminee() {
        let (db, v, n) = av4_base_d_analyse();
        av4_trigger_meta(&db.lock(), "analyze_full_done", "RAISE(IGNORE)");
        let cr = analyze_full_background(&db);
        assert_eq!(
            cr,
            av4_cr(&[format!("[analyze] ANALYZE complet fait, mais son jalon {v}@{n} n'a PAS été écrit ({AV4_ZERO_LIGNE}) — la passe sera refaite au prochain boot")], 0, 1)
        );
        assert_eq!(av4_meta(&db.lock(), "analyze_full_done"), None);
    }

    // ---------------------------------------------------------------------------------------------
    // backfill FTS
    // ---------------------------------------------------------------------------------------------

    /// Les leviers du backfill, posés pour la portée (sous `VERROU_ENV_PROCESSUS.write()` chez l'appelant).
    struct Av4Leviers(#[allow(dead_code)] [ReglageBackupPose; 4]);

    fn av4_leviers_du_backfill() -> Av4Leviers {
        Av4Leviers([
            ReglageBackupPose::neuf("PLUME_FTS_FIELDS", "1"),
            ReglageBackupPose::neuf("PLUME_FTS_FIELDS_BACKFILL", "1"),
            ReglageBackupPose::neuf("PLUME_FTS_BACKFILL_BATCH", "100000"),
            ReglageBackupPose::neuf("PLUME_FTS_BACKFILL_SLEEP_MS", "0"),
        ])
    }

    /// Trois événements posés AVANT l'infra FTS (les triggers ne les indexent pas), puis l'infra posée ; rend la
    /// base et le premier watermark (`MAX(id)+1`).
    fn av4_base_de_backfill() -> (Arc<parking_lot::Mutex<Connection>>, i64) {
        let conn = test_db();
        for i in 0..3 {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,message,fields) VALUES(?1,'sshd','auth',1,'x','{\"user\":\"av4jeton\"}')",
                params![1_700_000_000 + i],
            )
            .expect("événement");
        }
        conn.execute("DELETE FROM meta WHERE key LIKE 'fts_fields_backfill_%'", []).expect("meta du backfill retirée");
        let on = reconcile_index_state(&conn, &av4_conf(&[("PLUME_FTS_FIELDS", "1"), ("PLUME_EXPRINDEX", "1")]));
        assert_eq!(on.ecritures_refusees, 0, "instrument : infra FTS posée");
        let lo: i64 = conn.query_row("SELECT COALESCE(MAX(id),0)+1 FROM event", [], |r| r.get(0)).expect("watermark initial");
        assert!(lo > 3 && lo <= 100_000, "instrument : un seul lot");
        (Arc::new(parking_lot::Mutex::new(conn)), lo)
    }

    fn av4_indexes(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM event_fields_fts WHERE event_fields_fts MATCH 'av4jeton'", [], |r| r.get(0)).expect("fts")
    }

    fn av4_demarrage(lo: i64) -> String {
        format!("[fts-backfill] démarrage backfill event_fields_fts (watermark id<{lo}, lot 100000)")
    }

    #[test]
    fn av4_backfill_nominal_termine_et_jalon() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        let cr = fts_backfill_background(&db);
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), "[fts-backfill] backfill event_fields_fts TERMINÉ (historique indexé)".to_string()], 0, 0));
        let c = db.lock();
        assert_eq!(av4_indexes(&c), 3);
        assert_eq!(av4_meta(&c, "fts_fields_backfill_done"), Some(("text".to_string(), "40".to_string())));
        assert_eq!(av4_meta(&c, "fts_fields_backfill_hi"), Some(("text".to_string(), "0".to_string())));
    }

    #[test]
    fn av4_backfill_presence_de_la_vtable_non_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, _) = av4_base_de_backfill();
        av4_refuser_les_noms_du_catalogue(&db.lock());
        let cr = fts_backfill_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(
            cr,
            av4_cr(&[format!("[fts-backfill] backfill NON tenté : la présence de event_fields_fts n'a pas pu être lue ({AV4_NOM_INTERDIT}) — retry au prochain boot")], 1, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None);
    }

    #[test]
    fn av4_backfill_jalon_illisible_rien_relance() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, _) = av4_base_de_backfill();
        db.lock().execute("INSERT INTO meta(key,value) VALUES('fts_fields_backfill_done', x'00')", []).expect("jalon BLOB");
        let cr = fts_backfill_background(&db);
        assert_eq!(
            cr,
            av4_cr(&[format!("[fts-backfill] backfill NON tenté : le jalon fts_fields_backfill_done n'a pas pu être lu ({AV4_BLOB}) — ni refait ni tenu pour fait, retry au prochain boot")], 1, 0)
        );
        let c = db.lock();
        assert_eq!(av4_indexes(&c), 0, "aucun lot indexé sur un jalon non lu");
        assert_eq!(av4_meta(&c, "fts_fields_backfill_hi"), None);
    }

    #[test]
    fn av4_backfill_watermark_non_lu_rien_relance() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, _) = av4_base_de_backfill();
        db.lock().execute("INSERT INTO meta(key,value) VALUES('fts_fields_backfill_hi', '2')", []).expect("watermark");
        // Lectures de meta.value : 1) jalon done, 2) watermark -> refusée.
        av4_refuser_la_n_ieme_lecture(&db.lock(), "meta", "value", 2);
        let cr = fts_backfill_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(
            cr,
            av4_cr(&[format!("[fts-backfill] backfill NON tenté : le watermark fts_fields_backfill_hi n'a pas pu être lu ({AV4_VALEUR_INTERDITE}) — retry au prochain boot")], 1, 0)
        );
        let c = db.lock();
        assert_eq!(av4_indexes(&c), 0);
        assert_eq!(av4_meta(&c, "fts_fields_backfill_done"), None);
        assert_eq!(av4_meta(&c, "fts_fields_backfill_hi"), Some(("text".to_string(), "2".to_string())));
    }

    #[test]
    fn av4_backfill_watermark_illisible_jamais_zero() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let phrase = |genre: &str| {
            format!("[fts-backfill] backfill NON tenté : le watermark fts_fields_backfill_hi est illisible ({genre}) — ni repris à zéro ni recommencé, retry au prochain boot")
        };
        let (db, _) = av4_base_de_backfill();
        db.lock().execute("INSERT INTO meta(key,value) VALUES('fts_fields_backfill_hi', 'abc')", []).expect("watermark texte");
        assert_eq!(fts_backfill_background(&db), av4_cr(&[phrase("texte non entier")], 1, 0));
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None, "un watermark illisible ne déclare pas le backfill terminé");
        db.lock().execute("UPDATE meta SET value=x'00' WHERE key='fts_fields_backfill_hi'", []).expect("watermark BLOB");
        assert_eq!(fts_backfill_background(&db), av4_cr(&[phrase("BLOB")], 1, 0));
        db.lock().execute("UPDATE meta SET value=NULL WHERE key='fts_fields_backfill_hi'", []).expect("watermark NULL");
        assert_eq!(fts_backfill_background(&db), av4_cr(&[phrase("NULL")], 1, 0));
        let c = db.lock();
        assert_eq!(av4_indexes(&c), 0);
        assert_eq!(av4_meta(&c, "fts_fields_backfill_done"), None);
    }

    /// Un texte qui n'est PAS EXACTEMENT l'écriture décimale d'un entier (espaces, `+`, zéro de tête, forme réelle), et
    /// un watermark NÉGATIF (`lo <= 0` : la boucle ne tournerait pas et le backfill serait DÉCLARÉ TERMINÉ sans rien
    /// indexer) : illisibles, jamais repris. MUTATIONS : `AV4b_wm_laxiste` (`trim` puis réel converti),
    /// `AV4b_wm_aller_retour` (sans l'aller-retour exact), `AV4b_wm_negatif` (négatif accepté).
    #[test]
    fn av4_backfill_watermark_inexact_ou_negatif_jamais_termine() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, _) = av4_base_de_backfill();
        db.lock().execute("INSERT INTO meta(key,value) VALUES('fts_fields_backfill_hi', '0')", []).expect("watermark");
        for (valeur, genre) in [
            (" 7", "texte non entier"),
            ("7 ", "texte non entier"),
            ("7.0", "texte non entier"),
            ("+7", "texte non entier"),
            ("07", "texte non entier"),
            ("-5", "entier négatif"),
        ] {
            db.lock().execute("UPDATE meta SET value=?1 WHERE key='fts_fields_backfill_hi'", params![valeur]).expect("watermark posé");
            assert_eq!(
                fts_backfill_background(&db),
                av4_cr(&[format!("[fts-backfill] backfill NON tenté : le watermark fts_fields_backfill_hi est illisible ({genre}) — ni repris à zéro ni recommencé, retry au prochain boot")], 1, 0),
                "watermark « {valeur} »"
            );
            let c = db.lock();
            assert_eq!(av4_indexes(&c), 0, "watermark « {valeur} » : aucun lot indexé");
            assert_eq!(av4_meta(&c, "fts_fields_backfill_done"), None, "watermark « {valeur} » : le backfill n'est pas déclaré terminé");
            assert_eq!(av4_meta(&c, "fts_fields_backfill_hi"), Some(("text".to_string(), valeur.to_string())), "watermark « {valeur} » : laissé tel quel");
        }
    }

    #[test]
    fn av4_backfill_max_id_non_lu_jamais_termine() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, _) = av4_base_de_backfill();
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "event" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = fts_backfill_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(
            cr,
            av4_cr(&[format!("[fts-backfill] backfill NON tenté : MAX(id) de event n'a pas pu être lu ({AV4_ID_INTERDIT}) — retry au prochain boot")], 1, 0)
        );
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None, "un MAX(id) non lu ne déclare pas le backfill terminé");
    }

    #[test]
    fn av4_backfill_lot_refuse_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "event_fields_fts" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cr = fts_backfill_background(&db);
        av4_rendre_la_main(&db.lock());
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), format!("[fts-backfill] lot [0,{lo}) ÉCHEC ({AV4_NON_AUTORISE}) — réessai au prochain boot")], 0, 1));
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None);
    }

    fn av4_watermark_refuse(lo: i64, cause: &str) -> String {
        format!("[fts-backfill] lot [0,{lo}) indexé, mais le watermark id<0 n'a PAS été écrit ({cause}) — backfill arrêté, reprise au dernier watermark écrit au prochain boot (sans doublon : NOT EXISTS)")
    }

    #[test]
    fn av4_backfill_watermark_refuse_arrete_et_dit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        av4_trigger_meta(&db.lock(), "fts_fields_backfill_hi", &format!("RAISE(ABORT, '{AV4_ABANDON}')"));
        let cr = fts_backfill_background(&db);
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), av4_watermark_refuse(lo, AV4_ABANDON)], 0, 1));
        let c = db.lock();
        assert_eq!(av4_meta(&c, "fts_fields_backfill_done"), None);
        assert_eq!(av4_indexes(&c), 3, "le lot validé reste indexé");
    }

    #[test]
    fn av4_backfill_watermark_a_zero_ligne_arrete_et_dit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        av4_trigger_meta(&db.lock(), "fts_fields_backfill_hi", "RAISE(IGNORE)");
        let cr = fts_backfill_background(&db);
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), av4_watermark_refuse(lo, AV4_ZERO_LIGNE)], 0, 1));
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None);
    }

    fn av4_jalon_refuse(cause: &str) -> String {
        format!("[fts-backfill] historique indexé, mais le jalon fts_fields_backfill_done n'a PAS été écrit ({cause}) — le backfill se rejouera au prochain boot (sans doublon : NOT EXISTS)")
    }

    #[test]
    fn av4_backfill_jalon_refuse_jamais_termine() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        av4_trigger_meta(&db.lock(), "fts_fields_backfill_done", &format!("RAISE(ABORT, '{AV4_ABANDON}')"));
        let cr = fts_backfill_background(&db);
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), av4_jalon_refuse(AV4_ABANDON)], 0, 1));
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_hi"), Some(("text".to_string(), "0".to_string())));
    }

    #[test]
    fn av4_backfill_jalon_a_zero_ligne_jamais_termine() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let _l = av4_leviers_du_backfill();
        let (db, lo) = av4_base_de_backfill();
        av4_trigger_meta(&db.lock(), "fts_fields_backfill_done", "RAISE(IGNORE)");
        let cr = fts_backfill_background(&db);
        assert_eq!(cr, av4_cr(&[av4_demarrage(lo), av4_jalon_refuse(AV4_ZERO_LIGNE)], 0, 1));
        assert_eq!(av4_meta(&db.lock(), "fts_fields_backfill_done"), None);
    }
}
