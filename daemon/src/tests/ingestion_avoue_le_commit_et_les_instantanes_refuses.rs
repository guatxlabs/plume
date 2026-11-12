// ================================================================================================
// L'INGESTION AVOUE AUSSI UN COMMIT DE LOT, UNE MÉTRIQUE ET UN INSTANTANÉ REFUSÉS PAR LE SUPPORT
// ================================================================================================
// CONSTAT : après que les deux sites d'échec d'insertion d'événements ont été classés (`ingestion_avoue_les_erreurs_du_support.rs`),
// cinq autres sites d'écriture de `ingest/mod.rs` n'atteignaient pas la classification
// (`sqlite_plafond::journaliser_si_erreur_du_support`, compte `ERREURS_DU_SUPPORT` lu par le composant `store` de la santé) :
// le COMMIT du lot journald (erreur jetée, sans ligne), le COMMIT du lot d'événements (ligne seule), l'inscription d'une
// métrique, d'un instantané neuf et le battement d'un instantané inchangé (erreurs jetées). `valider_la_transaction`
// (handlers/transaction_validee.rs) ne classe rien : il valide, annule sur un refus, et ne dit que l'écrivain resté pris.
//
// CE QUI CHANGE : chacun des cinq sites passe SON erreur à la classification existante, une fois. Le COMMIT journald gagne
// la ligne `[ingest] journal COMMIT refusé -> lot annulé (<base>) : <texte> [code étendu N]`. La ligne du COMMIT des
// événements reste celle d'avant, à l'octet. Les métriques et les instantanés n'ont pas de ligne neuve : la ligne du lot
// refusé est celle de sa mise en quarantaine, déjà écrite par l'appelant, une par lot.
//
// FABRICATION (sqlite3.c vendoré 3.39.4) :
// - COMMIT refusé par le SUPPORT : une E/S RÉELLEMENT refusée à l'écriture du COMMIT. Le crochet de course que le lot
//   appelle après l'insertion de l'événement (`point_de_course`, DANS la transaction du lot) borne la taille de fichier
//   du processus à zéro (`RLIMIT_FSIZE`, `SIGXFSZ` ignoré) ; aucune écriture de fichier n'a lieu avant le COMMIT (les
//   pages restent au cache), et celle du COMMIT rend `EFBIG`, que `unixWrite` traduit en `SQLITE_IOERR_WRITE`, 778
//   (« if( wrote<0 && pFile->lastErrno!=ENOSPC ) return SQLITE_IOERR_WRITE; »). La limite est relevée après le passage.
//   L'index plein-texte ne convient PAS ici, mesuré : retirer sa structure avant le passage fait échouer l'INSERT, la
//   retirer après l'insertion laisse le COMMIT réussir (les termes en attente sont vidés plus tôt, à un point de
//   sauvegarde : `fts5SavepointMethod`).
// - COMMIT refusé HORS support : une clé étrangère DIFFÉRÉE violée par un déclencheur d'insertion
//   (`SQLITE_CONSTRAINT_FOREIGNKEY`, 787), qui n'apparaît qu'au COMMIT.
// - Métrique, instantané neuf, battement refusés par le SUPPORT : un index plein-texte de TÉMOIN (`cg1_fts`), alimenté par un
//   déclencheur sur `metric` (insertion) ou `snapshot` (insertion, ou mise à jour pour le battement), dont l'enregistrement
//   des moyennes (id 1) est retiré : même mécanisme que les témoins de l'insertion d'événements (`fts5StorageLoadTotals`).
// - HORS support : `RAISE(ABORT, …)` dans le déclencheur (`SQLITE_CONSTRAINT_TRIGGER`, 1811).
//
// AMORCE : le compte est AMORCÉ dans l'enfant à une valeur écrite ici (une erreur, code 1034, instant 1000) avant le
// passage : APRÈS doit valoir exactement avant + 1 (instant du passage, code 778 au COMMIT, 267 ailleurs) pour le support,
// et avant à l'identique hors support.
//
// ISOLEMENT : chaque témoin se rejoue dans un SOUS-PROCESSUS qui ne joue que lui ; le parent lit la sortie d'erreur ENTIÈRE.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun disque réellement plein (`ENOSPC` rendrait `SQLITE_FULL`, compté par la même
// classification, non joué ici) ; aux sites des métriques et des instantanés la corruption est celle d'un index, posée par
// une écriture SQL ; les COMMIT des lots de métriques et d'instantanés et les insertions d'alertes de la
// voie des instantanés ne sont pas classés par ce changement.

#[cfg(test)]
mod cg1_ingestion_commit_metriques_instantanes {
    use super::*;

    const CG1_ENFANT: &str = "CG1_ENFANT_INGESTION";
    const CG1_RENDU: &str = "CG1-RENDU:";
    /// L'amorce du compte, écrite ici : une erreur, code étendu 1034 (`SQLITE_IOERR_FSYNC`), instant 1000.
    const AMORCE_CODE: i32 = 1034;
    const AMORCE_TS: i64 = 1000;
    /// `SQLITE_CORRUPT | (1 << 8)`, écrit ici.
    const CORRUPT_VTAB: i64 = 267;
    /// `SQLITE_CONSTRAINT | (3 << 8)` (`SQLITE_CONSTRAINT_FOREIGNKEY`), écrit ici.
    const CONSTRAINT_FOREIGNKEY: i64 = 787;
    /// `SQLITE_CONSTRAINT | (7 << 8)` (`SQLITE_CONSTRAINT_TRIGGER`), écrit ici.
    const CONSTRAINT_TRIGGER: i64 = 1811;
    /// `SQLITE_IOERR | (3 << 8)` (`SQLITE_IOERR_WRITE`), écrit ici.
    const IOERR_WRITE: i64 = 778;
    const TEXTE_CORROMPUE: &str = "database disk image is malformed";
    const TEXTE_E_S: &str = "disk I/O error";
    const TEXTE_CLE_ETRANGERE: &str = "FOREIGN KEY constraint failed";
    const LOT_EVENEMENTS: &str = "ingest-1-1.json";
    const LOT_JOURNALD: &str = "jrnl-1-1.ndjson";
    const LOT_METRIQUES: &str = "ingest-1-2.json";
    const LOT_INSTANTANE: &str = "ingest-1-3.json";
    const GENRE: &str = "cg1posture";
    const EMPREINTE: &str = "cg1-empreinte";
    const MACHINE: &str = "web01";
    /// Le crochet de course a posé la limite de taille de fichier (lu par l'enfant après le passage).
    static CG1_LIMITE_POSEE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// La limite d'avant, relevée après le passage.
    static CG1_LIMITE_D_AVANT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Base au schéma complet, état d'application et file d'ingest réelle (vide).
    fn cg1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, crate::tmp_possede::TmpPossede) {
        let path = ff_tmp_path(tag);
        {
            let conn = open_db(&path).expect("fixture : base");
            conn.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
            assert!(migrate(&conn), "fixture : migrations complètes");
        }
        let mut st = ds_file_state(&path);
        let spool = crate::tmp_possede::TmpPossede::neuf(&format!("{tag}-spool"));
        st.spool = Arc::new(spool.racine().as_str().to_string());
        (st, path, spool)
    }

    /// Dépose UN lot de la voie demandée ; rend son chemin.
    fn cg1_deposer(st: &AppState, voie: &str) -> std::path::PathBuf {
        let spool = std::path::PathBuf::from(st.spool.as_str());
        match voie {
            "evenements" => {
                let chemin = spool.join(LOT_EVENEMENTS);
                let lot = json!({ "kind": "events", "ts": now(), "data": { "events": [{ "source": "cg1src", "message": "cg1 sonde", "dedup": "cg1-d1" }] } });
                std::fs::write(&chemin, lot.to_string()).expect("fixture : lot déposé");
                chemin
            }
            "journald" => {
                let chemin = spool.join(LOT_JOURNALD);
                let ligne = json!({
                    "__REALTIME_TIMESTAMP": (now() as i128 * 1_000_000).to_string(),
                    "_HOSTNAME": MACHINE, "_COMM": "sshd",
                    "MESSAGE": "Failed password for invalid user cg1sonde from 203.0.113.7 port 22",
                    "PRIORITY": "5", "__CURSOR": "cg1-curseur-1"
                });
                std::fs::write(&chemin, format!("{ligne}\n")).expect("fixture : lot déposé");
                chemin
            }
            "metriques" => {
                // DEUX métriques : la première est refusée, la seconde ne doit pas être tentée (un compte par lot).
                let chemin = spool.join(LOT_METRIQUES);
                let lot = json!({ "kind": "metrics", "ts": now(), "data": { "metrics": [
                    { "name": "cg1.premiere", "value": 1.0 }, { "name": "cg1.seconde", "value": 2.0 }
                ] } });
                std::fs::write(&chemin, lot.to_string()).expect("fixture : lot déposé");
                chemin
            }
            "instantane_neuf" | "battement" => {
                let chemin = spool.join(LOT_INSTANTANE);
                let lot = json!({ "kind": GENRE, "ts": now(), "hash": EMPREINTE, "host": MACHINE, "data": { "cg1": true } });
                std::fs::write(&chemin, lot.to_string()).expect("fixture : lot déposé");
                chemin
            }
            autre => panic!("instrument : voie inconnue {autre}"),
        }
    }

    /// Le battement suppose une série dont la dernière empreinte est celle du lot : elle est inscrite AVANT d'armer.
    fn cg1_semer(st: &AppState, voie: &str) {
        if voie == "battement" {
            st.db
                .lock()
                .execute(
                    "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}',?4)",
                    params![AMORCE_TS, GENRE, EMPREINTE, MACHINE],
                )
                .expect("fixture : instantané précédent");
        }
    }

    /// La table et l'événement du déclencheur de chaque voie des métriques et des instantanés.
    fn cg1_cible(voie: &str) -> (&'static str, &'static str, &'static str) {
        match voie {
            "metriques" => ("INSERT", "metric", "new.name"),
            "instantane_neuf" => ("INSERT", "snapshot", "new.kind"),
            "battement" => ("UPDATE", "snapshot", "new.kind"),
            autre => panic!("instrument : voie sans déclencheur {autre}"),
        }
    }

    /// Arme la cause de l'échec sur la base de l'écrivain.
    fn cg1_armer(st: &AppState, voie: &str, cause: &str) {
        let conn = st.db.lock();
        match (voie, cause) {
            ("evenements" | "journald", "support") => {
                // La limite est posée DANS la transaction du lot, après l'insertion et avant le COMMIT.
                let cle = if voie == "journald" { "lot-journald" } else { "lot-d-evenements" };
                // SAFETY: appel système sans pointeur conservé ; l'enfant ne joue que ce test.
                unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) }; // l'écriture rend EFBIG au lieu de tuer le processus
                crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("{cle}:{}", st.db_path.as_str()), || {
                    let mut avant = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                    // SAFETY: appels système sans pointeur conservé.
                    let lue = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut avant) } == 0;
                    CG1_LIMITE_D_AVANT.store(avant.rlim_cur, std::sync::atomic::Ordering::SeqCst);
                    let zero = libc::rlimit { rlim_cur: 0, rlim_max: avant.rlim_max };
                    let posee = lue && unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero) } == 0;
                    CG1_LIMITE_POSEE.store(posee, std::sync::atomic::Ordering::SeqCst);
                });
            }
            ("evenements" | "journald", "hors_support") => {
                conn.execute_batch(
                    "PRAGMA foreign_keys=ON;
                     CREATE TABLE cg1_parent(id INTEGER PRIMARY KEY);
                     CREATE TABLE cg1_enfant(p INTEGER REFERENCES cg1_parent(id) DEFERRABLE INITIALLY DEFERRED);
                     CREATE TRIGGER cg1_differe AFTER INSERT ON event BEGIN INSERT INTO cg1_enfant VALUES(42); END;",
                )
                .expect("fixture : clé étrangère différée");
            }
            (_, "support") => {
                let (quand, table, valeur) = cg1_cible(voie);
                conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE cg1_fts USING fts5(x);
                     CREATE TRIGGER cg1_index AFTER {quand} ON {table} BEGIN INSERT INTO cg1_fts(x) VALUES({valeur}); END;"
                ))
                .expect("fixture : index plein-texte de témoin");
                let retire = conn.execute("DELETE FROM cg1_fts_data WHERE id=1", []).expect("fixture : moyennes retirées");
                assert_eq!(retire, 1, "contrôle : l'enregistrement des moyennes de l'index de témoin existait");
            }
            (_, "hors_support") => {
                let (quand, table, _) = cg1_cible(voie);
                conn.execute_batch(&format!(
                    "CREATE TRIGGER cg1_contrainte BEFORE {quand} ON {table} BEGIN SELECT RAISE(ABORT, 'cg1-contrainte'); END;"
                ))
                .expect("fixture : déclencheur");
            }
            autre => panic!("instrument : cas inconnu {autre:?}"),
        }
    }

    /// LE CORPS DE L'ENFANT : amorce du compte, compte avant, un passage (point d'entrée `ingest_once`), compte après.
    fn cg1_jouer(voie: &str, cause: &str) {
        let (st, path, _spool) = cg1_etat(&format!("cg1-{voie}-{cause}"));
        cg1_semer(&st, voie);
        let lot = cg1_deposer(&st, voie);
        cg1_armer(&st, voie, cause);
        crate::sqlite_plafond::ERREURS_DU_SUPPORT.noter(AMORCE_CODE, AMORCE_TS);
        let avant = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let t0 = now();
        let bilan = ingest_once(&st.tenants, &st.spool);
        let t1 = now();
        let limite_posee = CG1_LIMITE_POSEE.load(std::sync::atomic::Ordering::SeqCst);
        if limite_posee {
            let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: appels système sans pointeur conservé.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut l) }, 0, "contrôle : limite relue");
            l.rlim_cur = CG1_LIMITE_D_AVANT.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &l) }, 0, "contrôle : limite relevée");
        }
        let apres = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let nom = lot.file_name().and_then(|n| n.to_str()).expect("nom du lot").to_string();
        let en_quarantaine = std::path::Path::new(&crate::state::repertoire_de_quarantaine(&st.spool)).join(&nom).exists();
        let conn = st.db.lock();
        let compter = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).expect("relecture") };
        let rendu = json!({
            "chemin": path.as_str(),
            "avant": [avant.total, avant.derniere_ts, avant.dernier_code],
            "apres": [apres.total, apres.derniere_ts, apres.dernier_code],
            "t0": t0, "t1": t1,
            "bilan": format!("{bilan:?}"),
            "en_quarantaine": en_quarantaine,
            "reste_au_spool": lot.exists(),
            "evenements": compter("SELECT COUNT(*) FROM event"),
            "metriques": compter("SELECT COUNT(*) FROM metric"),
            "instantanes": compter("SELECT COUNT(*) FROM snapshot"),
            "ts_du_dernier": compter("SELECT COALESCE(MAX(ts), 0) FROM snapshot"),
            "autocommit": conn.is_autocommit(),
            "limite_posee": limite_posee,
        });
        println!("{CG1_RENDU}{rendu}");
    }

    /// Le rendu de l'enfant et sa sortie d'erreur entière.
    fn cg1_lire(sortie: &std::process::Output) -> (Value, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(CG1_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 1, "contrôle : l'enfant a joué son issue une fois : {stdout}\n{stderr}");
        (rendus[0].clone(), stderr)
    }

    /// Les lignes de la sortie d'erreur qui commencent par `tete`.
    fn cg1_lignes(stderr: &str, tete: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with(tete)).map(|l| l.to_string()).collect()
    }

    /// Ce que le comportement garde, quelle que soit la cause : le lot annulé (rien d'écrit de neuf), mis en quarantaine,
    /// compté comme UN abandon, l'écrivain libre ; la ligne de quarantaine telle qu'avant, une fois.
    fn cg1_lot_annule_et_ecarte(r: &Value, stderr: &str, voie: &str, support: bool) {
        assert_eq!(r["bilan"], "Lue(1)", "le passage rend UN abandon, comme avant : {r}");
        assert_eq!(r["en_quarantaine"], true, "le lot est en quarantaine : {r}");
        assert_eq!(r["reste_au_spool"], false, "le lot n'est plus au spool : {r}");
        assert_eq!(r["autocommit"], true, "l'écrivain n'est pas resté dans la transaction du lot : {r}");
        assert_eq!(r["evenements"], 0, "aucun événement écrit : {r}");
        assert_eq!(r["metriques"], 0, "aucune métrique écrite : {r}");
        let semees = if voie == "battement" { 1 } else { 0 };
        assert_eq!(r["instantanes"], semees, "aucun instantané neuf écrit : {r}");
        assert_eq!(r["ts_du_dernier"], if voie == "battement" { AMORCE_TS } else { 0 }, "le battement est annulé : {r}");
        let (raison, nom) = match voie {
            "evenements" => ("events INSERT échoué (ROLLBACK du batch)", LOT_EVENEMENTS),
            "journald" => ("journald INSERT échoué (ROLLBACK du batch)", LOT_JOURNALD),
            "metriques" => ("metrics INSERT échoué (ROLLBACK du batch)", LOT_METRIQUES),
            _ => ("snapshot INSERT échoué (ROLLBACK du batch)", LOT_INSTANTANE),
        };
        assert_eq!(
            cg1_lignes(stderr, "[ingest] "),
            [cg1_ligne_du_commit(voie, r, support), vec![format!("[ingest] {raison} -> quarantaine : {nom}")]].concat(),
            "les lignes `[ingest]` du passage, entières : celle du COMMIT pour les voies d'événements, celle de la quarantaine : {stderr}"
        );
    }

    /// Le code étendu et la description (`decrire_l_erreur`) attendus d'une erreur du support à la voie : l'E/S refusée au
    /// COMMIT pour les voies d'événements, l'index de témoin illisible pour les métriques et les instantanés.
    fn cg1_support_attendu(voie: &str) -> (i64, String) {
        if voie == "journald" || voie == "evenements" {
            (IOERR_WRITE, format!("{TEXTE_E_S} [SQLITE_IOERR_WRITE, code étendu {IOERR_WRITE}]"))
        } else {
            (CORRUPT_VTAB, format!("{TEXTE_CORROMPUE} [code étendu {CORRUPT_VTAB}]"))
        }
    }

    /// La ligne du COMMIT refusé attendue de la voie, ENTIÈRE ; aucune pour les métriques et les instantanés.
    fn cg1_ligne_du_commit(voie: &str, r: &Value, support: bool) -> Vec<String> {
        let chemin = r["chemin"].as_str().expect("chemin");
        match (voie, support) {
            // Ligne neuve : texte du moteur et code étendu.
            ("journald", true) => vec![format!("[ingest] journal COMMIT refusé -> lot annulé ({chemin}) : {}", cg1_support_attendu(voie).1)],
            ("journald", false) => vec![format!("[ingest] journal COMMIT refusé -> lot annulé ({chemin}) : {TEXTE_CLE_ETRANGERE} [code étendu {CONSTRAINT_FOREIGNKEY}]")],
            // Ligne d'avant, à l'octet : texte du moteur seul.
            ("evenements", true) => vec![format!("[ingest] events COMMIT refusé -> lot annulé ({chemin}) : {TEXTE_E_S}")],
            ("evenements", false) => vec![format!("[ingest] events COMMIT refusé -> lot annulé ({chemin}) : {TEXTE_CLE_ETRANGERE}")],
            _ => Vec::new(),
        }
    }

    /// Juge une issue « erreur du support » : avant = l'amorce écrite ; après = avant + 1, instant du passage, code de la
    /// cause ; la ligne `[sqlite]` ENTIÈRE, une fois.
    fn cg1_juger_support(r: &Value, stderr: &str, voie: &str) {
        let (code, description) = cg1_support_attendu(voie);
        if voie == "journald" || voie == "evenements" {
            assert_eq!(r["limite_posee"], true, "contrôle : la limite de taille a été posée dans la transaction du lot : {r}");
        }
        assert_eq!(r["avant"], json!([1, AMORCE_TS, AMORCE_CODE]), "AVANT : l'amorce écrite : {r}");
        assert_eq!(r["apres"][0], 2, "APRÈS : avant + 1, exactement : {r}\n{stderr}");
        let ts = r["apres"][1].as_i64().expect("instant");
        assert!(ts >= r["t0"].as_i64().unwrap() && ts <= r["t1"].as_i64().unwrap(), "l'instant est celui du passage : {r}");
        assert_eq!(r["apres"][2], code, "le code étendu retenu est celui de la cause : {r}");
        assert_eq!(
            cg1_lignes(stderr, "[sqlite] "),
            vec![format!("[sqlite] erreur du support de la base : {description}")],
            "la ligne de la classification, entière, une fois : {stderr}"
        );
        cg1_lot_annule_et_ecarte(r, stderr, voie, true);
    }

    /// Juge une issue hors support : le compte reste à l'amorce, à l'identique ; aucune ligne `[sqlite]`.
    fn cg1_juger_hors_support(r: &Value, stderr: &str, voie: &str) {
        assert_eq!(r["avant"], json!([1, AMORCE_TS, AMORCE_CODE]), "AVANT : l'amorce écrite : {r}");
        assert_eq!(r["apres"], r["avant"], "APRÈS : avant + 0 : {r}\n{stderr}");
        assert_eq!(cg1_lignes(stderr, "[sqlite] "), Vec::<String>::new(), "aucune ligne de la classification : {stderr}");
        cg1_lot_annule_et_ecarte(r, stderr, voie, false);
    }

    /// (1) SITE 1 — COMMIT DU LOT JOURNALD, E/S REFUSÉE À L'ÉCRITURE : compté, ligne neuve à code.
    ///
    /// MUTATIONS : `CG1_SANS_CLASSE_JOURNAL_COMMIT` (l'appel retiré de ce site) -> avant + 0 : ROUGE ;
    /// `CG1_JOURNAL_COMMIT_SANS_LIGNE` (la ligne retirée) : ROUGE ; `CG1_JOURNAL_COMMIT_LIGNE_SANS_CODE` (`{e}`) : ROUGE ;
    /// `CG1_JOURNAL_COMMIT_DEUX_FOIS` (classé deux fois) -> avant + 2 : ROUGE.
    #[test]
    fn journald_un_commit_refuse_par_le_support_est_compte_et_dit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("journald", "support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::journald_un_commit_refuse_par_le_support_est_compte_et_dit",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_support(&r, &stderr, "journald");
    }

    /// (2) SITE 1 — COMMIT DU LOT JOURNALD, CLÉ ÉTRANGÈRE DIFFÉRÉE : pas compté, ligne neuve à code 787.
    ///
    /// MUTATION : `CG1_JOURNAL_COMMIT_COMPTE_TOUT` (le site compte tout refus) -> avant + 1 : ROUGE.
    #[test]
    fn journald_un_commit_refuse_par_une_contrainte_differee_n_est_pas_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("journald", "hors_support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::journald_un_commit_refuse_par_une_contrainte_differee_n_est_pas_compte",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_hors_support(&r, &stderr, "journald");
    }

    /// (3) SITE 2 — COMMIT DU LOT D'ÉVÉNEMENTS, E/S REFUSÉE À L'ÉCRITURE : compté, ligne d'avant à l'octet.
    ///
    /// MUTATION : `CG1_SANS_CLASSE_EVENTS_COMMIT` -> avant + 0 : ROUGE.
    #[test]
    fn evenements_un_commit_refuse_par_le_support_est_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("evenements", "support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::evenements_un_commit_refuse_par_le_support_est_compte",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_support(&r, &stderr, "evenements");
    }

    /// (4) SITE 2 — COMMIT DU LOT D'ÉVÉNEMENTS, CLÉ ÉTRANGÈRE DIFFÉRÉE : pas compté, ligne d'avant à l'octet.
    ///
    /// MUTATION : `CG1_EVENTS_COMMIT_COMPTE_TOUT` -> avant + 1 : ROUGE.
    #[test]
    fn evenements_un_commit_refuse_par_une_contrainte_differee_n_est_pas_compte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("evenements", "hors_support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::evenements_un_commit_refuse_par_une_contrainte_differee_n_est_pas_compte",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_hors_support(&r, &stderr, "evenements");
    }

    /// (5) SITE 3 — MÉTRIQUE, INDEX ILLISIBLE : compté UNE fois pour un lot de deux métriques, aucune ligne `[ingest]`
    /// neuve (celle de la quarantaine suffit).
    ///
    /// MUTATIONS : `CG1_SANS_CLASSE_METRIQUE` -> avant + 0 : ROUGE ; `CG1_METRIQUE_SANS_ARRET` (la boucle continue après
    /// le refus) -> avant + 2 : ROUGE.
    #[test]
    fn metriques_une_insertion_refusee_par_le_support_est_comptee_une_fois_par_lot() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("metriques", "support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::metriques_une_insertion_refusee_par_le_support_est_comptee_une_fois_par_lot",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_support(&r, &stderr, "metriques");
    }

    /// (6) SITE 3 — MÉTRIQUE, CONTRAINTE : pas comptée.
    ///
    /// MUTATION : `CG1_METRIQUE_COMPTE_TOUT` -> avant + 1 : ROUGE.
    #[test]
    fn metriques_une_insertion_refusee_par_une_contrainte_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("metriques", "hors_support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::metriques_une_insertion_refusee_par_une_contrainte_n_est_pas_comptee",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_hors_support(&r, &stderr, "metriques");
    }

    /// (7) SITE 4 — INSTANTANÉ NEUF, INDEX ILLISIBLE : compté.
    ///
    /// MUTATION : `CG1_SANS_CLASSE_INSTANTANE` -> avant + 0 : ROUGE.
    #[test]
    fn instantane_neuf_une_inscription_refusee_par_le_support_est_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("instantane_neuf", "support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::instantane_neuf_une_inscription_refusee_par_le_support_est_comptee",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_support(&r, &stderr, "instantane_neuf");
    }

    /// (8) SITE 4 — INSTANTANÉ NEUF, CONTRAINTE : pas compté.
    ///
    /// MUTATION : `CG1_INSTANTANE_COMPTE_TOUT` -> avant + 1 : ROUGE.
    #[test]
    fn instantane_neuf_une_inscription_refusee_par_une_contrainte_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("instantane_neuf", "hors_support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::instantane_neuf_une_inscription_refusee_par_une_contrainte_n_est_pas_comptee",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_hors_support(&r, &stderr, "instantane_neuf");
    }

    /// (9) SITE 5 — BATTEMENT D'UN INSTANTANÉ INCHANGÉ, INDEX ILLISIBLE : compté, la ligne précédente garde son instant.
    ///
    /// MUTATION : `CG1_SANS_CLASSE_BATTEMENT` -> avant + 0 : ROUGE.
    #[test]
    fn battement_une_mise_a_jour_refusee_par_le_support_est_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("battement", "support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::battement_une_mise_a_jour_refusee_par_le_support_est_comptee",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_support(&r, &stderr, "battement");
    }

    /// (10) SITE 5 — BATTEMENT, CONTRAINTE : pas compté.
    ///
    /// MUTATION : `CG1_BATTEMENT_COMPTE_TOUT` -> avant + 1 : ROUGE.
    #[test]
    fn battement_une_mise_a_jour_refusee_par_une_contrainte_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CG1_ENFANT).is_ok() {
            cg1_jouer("battement", "hors_support");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cg1_ingestion_commit_metriques_instantanes::battement_une_mise_a_jour_refusee_par_une_contrainte_n_est_pas_comptee",
            ])
            .env(CG1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cg1_lire(&sortie);
        cg1_juger_hors_support(&r, &stderr, "battement");
    }
}
