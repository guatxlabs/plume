// ================================================================================================
// L'INGESTION AVOUE LES ERREURS DU SUPPORT (compte du composant `store`, ligne de journal à code étendu)
// ================================================================================================
// CONSTAT : chaque lot d'ingestion échouait sur « database disk image is malformed » (index plein-texte illisible)
// aux deux sites d'échec d'insertion de `ingest/mod.rs` (voie journald `ingest_journal_lines`, voie des événements
// `ingest_events_batch_env`) ; ces sites écrivaient leur propre ligne sans passer par la classification
// (`sqlite_plafond::journaliser_si_erreur_du_support`) : le compte des erreurs du support (`ERREURS_DU_SUPPORT`, lu par
// le composant `store` de la santé) restait à zéro, et la ligne ne portait pas le code étendu.
//
// CE QUI CHANGE : les deux sites passent l'erreur à la classification existante (une erreur du support est comptée
// avec son instant et son code étendu ; une base occupée ou une contrainte ne l'est pas) et leur ligne porte le code
// étendu (`decrire_l_erreur`), le reste de la ligne inchangé. Le lot est annulé et mis en quarantaine comme avant.
//
// FABRICATION : l'index plein-texte du schéma (`event_fts`, alimenté par le déclencheur `event_ai`) est rendu illisible
// en retirant son enregistrement des moyennes (`event_fts_data`, id 1). À l'insertion suivante, FTS5 relit cet
// enregistrement (`fts5StorageLoadTotals` -> `sqlite3Fts5IndexGetAverages` -> `fts5DataRead`) ; `sqlite3_blob_open` ne
// trouve pas la ligne et rend `SQLITE_ERROR`, que FTS5 convertit en `FTS5_CORRUPT` = `SQLITE_CORRUPT_VTAB` (sqlite3.c
// vendoré 3.39.4, « if( rc==SQLITE_ERROR ) rc = FTS5_CORRUPT; » dans `fts5DataRead`, `FTS5_CORRUPT` défini en
// `SQLITE_CORRUPT_VTAB` au même fichier). C'est la classe du constat : un index plein-texte illisible, pas le code 11.
// La base occupée (`SQLITE_BUSY`) est levée par une fonction substituée sur l'écrivain, appelée par un déclencheur
// d'insertion ; la contrainte par `RAISE(ABORT, …)`.
//
// ISOLEMENT : le compte et la sortie d'erreur sont des états de PROCESSUS. Chaque témoin se rejoue dans un
// SOUS-PROCESSUS qui ne joue que lui (`--exact --test-threads=1 --nocapture`) ; le parent lit la sortie d'erreur ENTIÈRE.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun disque réellement défaillant (la corruption est celle d'un index, posée
// par une écriture SQL) ; la base occupée au pas d'insertion est fabriquée (sous `BEGIN IMMEDIATE`, l'écrivain tient
// déjà le verrou).

#[cfg(test)]
mod cf2_ingestion_erreurs_du_support {
    use super::*;
    use rusqlite::functions::FunctionFlags;

    const CF2_ENFANT: &str = "CF2_ENFANT_INGESTION";
    const CF2_RENDU: &str = "CF2-RENDU:";
    /// `SQLITE_CORRUPT | (1 << 8)`, écrit ici.
    const CORRUPT_VTAB: i64 = 267;
    /// Le texte que le moteur rend pour le code primaire `SQLITE_CORRUPT`, écrit ici.
    const TEXTE_CORROMPUE: &str = "database disk image is malformed";
    /// Le texte que le moteur rend pour `SQLITE_BUSY`, écrit ici.
    const TEXTE_OCCUPEE: &str = "database is locked";
    /// Le message du déclencheur de contrainte, écrit ici.
    const TEXTE_CONTRAINTE: &str = "cf2-contrainte";
    /// `SQLITE_CONSTRAINT | (7 << 8)` (`SQLITE_CONSTRAINT_TRIGGER`).
    const CONSTRAINT_TRIGGER: i64 = 1811;
    const LOT_EVENEMENTS: &str = "ingest-1-1.json";
    const LOT_JOURNALD: &str = "jrnl-1-1.ndjson";

    /// Base au schéma complet, état d'application et file d'ingest réelle (vide).
    fn cf2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, crate::tmp_possede::TmpPossede) {
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

    /// Dépose UN lot dans la file : la voie des événements (`.json`) ou la voie journald (`.ndjson`).
    fn cf2_deposer(st: &AppState, voie: &str) -> std::path::PathBuf {
        let spool = std::path::PathBuf::from(st.spool.as_str());
        if voie == "evenements" {
            let chemin = spool.join(LOT_EVENEMENTS);
            let lot = json!({ "kind": "events", "ts": now(), "data": { "events": [{ "source": "cf2src", "message": "cf2 sonde", "dedup": "cf2-d1" }] } });
            std::fs::write(&chemin, lot.to_string()).expect("fixture : lot déposé");
            chemin
        } else {
            let chemin = spool.join(LOT_JOURNALD);
            let ligne = json!({
                "__REALTIME_TIMESTAMP": (now() as i128 * 1_000_000).to_string(),
                "_HOSTNAME": "web01", "_COMM": "sshd",
                "MESSAGE": "Failed password for invalid user cf2sonde from 203.0.113.7 port 22",
                "PRIORITY": "5", "__CURSOR": "cf2-curseur-1"
            });
            std::fs::write(&chemin, format!("{ligne}\n")).expect("fixture : lot déposé");
            chemin
        }
    }

    /// Arme la cause de l'échec d'insertion sur la base de l'écrivain.
    fn cf2_armer(st: &AppState, cause: &str) {
        let conn = st.db.lock();
        match cause {
            "corrompue" => {
                let retire = conn.execute("DELETE FROM event_fts_data WHERE id=1", []).expect("fixture : index rendu illisible");
                assert_eq!(retire, 1, "contrôle : l'enregistrement des moyennes de l'index existait");
            }
            "occupee" => {
                conn.create_scalar_function("cf2_lever", 0, FunctionFlags::SQLITE_UTF8, |_ctx| -> rusqlite::Result<i64> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None))
                })
                .expect("fixture : fonction substituée");
                conn.execute_batch("CREATE TRIGGER cf2_occupee BEFORE INSERT ON event BEGIN SELECT cf2_lever(); END;")
                    .expect("fixture : déclencheur");
            }
            "contrainte" => {
                conn.execute_batch(&format!(
                    "CREATE TRIGGER cf2_contrainte BEFORE INSERT ON event BEGIN SELECT RAISE(ABORT, '{TEXTE_CONTRAINTE}'); END;"
                ))
                .expect("fixture : déclencheur");
            }
            autre => panic!("instrument : cause inconnue {autre}"),
        }
    }

    /// LE CORPS DE L'ENFANT : compte avant, un passage de l'ingestion (point d'entrée `ingest_once`), compte après.
    fn cf2_jouer(voie: &str, cause: &str) {
        let (st, path, _spool) = cf2_etat(&format!("cf2-{voie}-{cause}"));
        let lot = cf2_deposer(&st, voie);
        cf2_armer(&st, cause);
        let avant = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let t0 = now();
        let bilan = ingest_once(&st.tenants, &st.spool);
        let t1 = now();
        let apres = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let nom = lot.file_name().and_then(|n| n.to_str()).expect("nom du lot").to_string();
        let en_quarantaine = std::path::Path::new(&crate::state::repertoire_de_quarantaine(&st.spool)).join(&nom).exists();
        let ecrits: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).expect("relecture des événements");
        let rendu = json!({
            "chemin": path.as_str(),
            "avant": [avant.total, avant.derniere_ts, avant.dernier_code],
            "apres": [apres.total, apres.derniere_ts, apres.dernier_code],
            "t0": t0, "t1": t1,
            "bilan": format!("{bilan:?}"),
            "en_quarantaine": en_quarantaine,
            "reste_au_spool": lot.exists(),
            "ecrits": ecrits,
        });
        println!("{CF2_RENDU}{rendu}");
    }

    /// Le rendu de l'enfant et sa sortie d'erreur entière.
    fn cf2_lire(sortie: &std::process::Output) -> (Value, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(CF2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 1, "contrôle : l'enfant a joué son issue une fois : {stdout}\n{stderr}");
        (rendus[0].clone(), stderr)
    }

    /// Les lignes de la sortie d'erreur qui commencent par `tete`.
    fn cf2_lignes(stderr: &str, tete: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with(tete)).map(|l| l.to_string()).collect()
    }

    /// Ce que le comportement de l'ingestion garde, quelle que soit la cause : le lot annulé (rien d'écrit), mis en
    /// quarantaine (plus au spool), compté comme UN abandon ; la ligne de quarantaine telle qu'avant.
    fn cf2_lot_annule_et_ecarte(r: &Value, stderr: &str, voie: &str) {
        assert_eq!(r["bilan"], "Lue(1)", "le passage rend UN abandon, comme avant : {r}");
        assert_eq!(r["ecrits"], 0, "le lot est annulé : rien d'écrit : {r}");
        assert_eq!(r["en_quarantaine"], true, "le lot est en quarantaine : {r}");
        assert_eq!(r["reste_au_spool"], false, "le lot n'est plus au spool : {r}");
        let (raison, nom) = if voie == "evenements" {
            ("events INSERT échoué (ROLLBACK du batch)", LOT_EVENEMENTS)
        } else {
            ("journald INSERT échoué (ROLLBACK du batch)", LOT_JOURNALD)
        };
        assert_eq!(
            cf2_lignes(stderr, &format!("[ingest] {raison}")),
            vec![format!("[ingest] {raison} -> quarantaine : {nom}")],
            "la ligne de quarantaine est inchangée : {stderr}"
        );
    }

    /// La ligne d'échec d'insertion, écrite ici en entier.
    fn cf2_ligne_d_echec(voie: &str, chemin: &str, texte: &str, code: i64) -> String {
        let mot = if voie == "evenements" { "events" } else { "journal" };
        format!("[ingest] {mot} INSERT échoué -> ROLLBACK du batch ({chemin}) : {texte} [code étendu {code}]")
    }

    /// Juge une issue « erreur du support » : zéro avant, une après, instant de la tentative, code retenu ; la ligne
    /// d'échec ENTIÈRE et la ligne `[sqlite]` ENTIÈRE, chacune une fois.
    fn cf2_juger_support(r: &Value, stderr: &str, voie: &str) {
        assert_eq!(r["avant"], json!([0, 0, 0]), "AVANT : aucune erreur du support comptée : {r}");
        assert_eq!(r["apres"][0], 1, "APRÈS : UNE erreur du support comptée : {r}\n{stderr}");
        let ts = r["apres"][1].as_i64().expect("instant");
        assert!(ts >= r["t0"].as_i64().unwrap() && ts <= r["t1"].as_i64().unwrap(), "l'instant est celui du passage : {r}");
        assert_eq!(r["apres"][2], CORRUPT_VTAB, "le code étendu retenu est celui de l'index illisible : {r}");
        let chemin = r["chemin"].as_str().expect("chemin");
        let mot = if voie == "evenements" { "events" } else { "journal" };
        assert_eq!(
            cf2_lignes(stderr, &format!("[ingest] {mot} INSERT échoué -> ")),
            vec![cf2_ligne_d_echec(voie, chemin, TEXTE_CORROMPUE, CORRUPT_VTAB)],
            "la ligne d'échec, entière, porte le code étendu : {stderr}"
        );
        assert_eq!(
            cf2_lignes(stderr, "[sqlite] "),
            vec![format!("[sqlite] erreur du support de la base : {TEXTE_CORROMPUE} [code étendu {CORRUPT_VTAB}]")],
            "la ligne de la classification, entière, une fois : {stderr}"
        );
        cf2_lot_annule_et_ecarte(r, stderr, voie);
    }

    /// Juge une issue hors support : rien compté, aucune ligne `[sqlite]`, la ligne d'échec entière avec son code.
    fn cf2_juger_hors_support(r: &Value, stderr: &str, voie: &str, texte: &str, code: i64) {
        assert_eq!(r["avant"], json!([0, 0, 0]), "AVANT : aucune erreur du support comptée : {r}");
        assert_eq!(r["apres"], json!([0, 0, 0]), "APRÈS : toujours rien de compté : {r}\n{stderr}");
        assert_eq!(cf2_lignes(stderr, "[sqlite] "), Vec::<String>::new(), "aucune ligne de la classification : {stderr}");
        let chemin = r["chemin"].as_str().expect("chemin");
        let mot = if voie == "evenements" { "events" } else { "journal" };
        assert_eq!(
            cf2_lignes(stderr, &format!("[ingest] {mot} INSERT échoué -> ")),
            vec![cf2_ligne_d_echec(voie, chemin, texte, code)],
            "la ligne d'échec, entière, porte le code étendu : {stderr}"
        );
        cf2_lot_annule_et_ecarte(r, stderr, voie);
    }

    /// (1) VOIE DES ÉVÉNEMENTS, INDEX PLEIN-TEXTE ILLISIBLE : compté (1, instant, `SQLITE_CORRUPT_VTAB`), ligne à code.
    ///
    /// MUTATIONS : `CF2_SANS_APPEL_EVENTS` (l'appel retiré du site des événements) -> 0 compté : ROUGE ;
    /// `CF2_LIGNE_SANS_CODE_EVENTS` (la ligne d'avant, `{e}`) -> ligne sans code : ROUGE.
    #[test]
    fn evenements_un_index_plein_texte_illisible_est_compte_comme_erreur_du_support() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF2_ENFANT).is_ok() {
            cf2_jouer("evenements", "corrompue");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cf2_ingestion_erreurs_du_support::evenements_un_index_plein_texte_illisible_est_compte_comme_erreur_du_support",
            ])
            .env(CF2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cf2_lire(&sortie);
        cf2_juger_support(&r, &stderr, "evenements");
    }

    /// (2) VOIE JOURNALD, INDEX PLEIN-TEXTE ILLISIBLE : même jugement.
    ///
    /// MUTATIONS : `CF2_SANS_APPEL_JOURNAL` -> 0 compté : ROUGE ; `CF2_LIGNE_SANS_CODE_JOURNAL` -> ligne sans code : ROUGE.
    #[test]
    fn journald_un_index_plein_texte_illisible_est_compte_comme_erreur_du_support() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF2_ENFANT).is_ok() {
            cf2_jouer("journald", "corrompue");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cf2_ingestion_erreurs_du_support::journald_un_index_plein_texte_illisible_est_compte_comme_erreur_du_support",
            ])
            .env(CF2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cf2_lire(&sortie);
        cf2_juger_support(&r, &stderr, "journald");
    }

    /// (3) VOIE DES ÉVÉNEMENTS, BASE OCCUPÉE : rien compté, la ligne porte le code 5.
    ///
    /// MUTATION : `CF2_COMPTE_TOUT` (la classification compte toute `SqliteFailure`) -> 1 compté : ROUGE.
    #[test]
    fn evenements_une_base_occupee_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF2_ENFANT).is_ok() {
            cf2_jouer("evenements", "occupee");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cf2_ingestion_erreurs_du_support::evenements_une_base_occupee_n_est_pas_comptee",
            ])
            .env(CF2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cf2_lire(&sortie);
        cf2_juger_hors_support(&r, &stderr, "evenements", TEXTE_OCCUPEE, i64::from(rusqlite::ffi::SQLITE_BUSY));
    }

    /// (4) VOIE JOURNALD, BASE OCCUPÉE : rien compté, la ligne porte le code 5.
    ///
    /// MUTATION : `CF2_COMPTE_TOUT` -> 1 compté : ROUGE.
    #[test]
    fn journald_une_base_occupee_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF2_ENFANT).is_ok() {
            cf2_jouer("journald", "occupee");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cf2_ingestion_erreurs_du_support::journald_une_base_occupee_n_est_pas_comptee",
            ])
            .env(CF2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cf2_lire(&sortie);
        cf2_juger_hors_support(&r, &stderr, "journald", TEXTE_OCCUPEE, i64::from(rusqlite::ffi::SQLITE_BUSY));
    }

    /// (5) VOIE DES ÉVÉNEMENTS, CONTRAINTE (déclencheur `RAISE(ABORT)`) : rien compté, la ligne porte le code 1811.
    ///
    /// MUTATION : `CF2_COMPTE_TOUT` -> 1 compté : ROUGE.
    #[test]
    fn evenements_une_contrainte_n_est_pas_comptee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CF2_ENFANT).is_ok() {
            cf2_jouer("evenements", "contrainte");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cf2_ingestion_erreurs_du_support::evenements_une_contrainte_n_est_pas_comptee",
            ])
            .env(CF2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (r, stderr) = cf2_lire(&sortie);
        cf2_juger_hors_support(&r, &stderr, "evenements", TEXTE_CONTRAINTE, CONSTRAINT_TRIGGER);
    }
}
