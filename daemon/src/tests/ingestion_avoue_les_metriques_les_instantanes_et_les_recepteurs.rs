// ================================================================================================
// L'INGESTION AVOUE LES REFUS DES LOTS DE MÉTRIQUES ET D'INSTANTANÉS, ET CEUX DES RÉCEPTEURS HTTP
// ================================================================================================
// CONSTAT (relu sur la base) : après les sites classés par `ingestion_avoue_les_erreurs_du_support.rs` et
// `ingestion_avoue_le_commit_et_les_instantanes_refuses.rs`, des sites d'écriture de l'ingestion n'atteignaient toujours
// pas la classification (`sqlite_plafond::journaliser_si_erreur_du_support`, compte `ERREURS_DU_SUPPORT` lu par le
// composant `store` de la santé) :
// - ingest/mod.rs, voie des fichiers du spool : le `BEGIN` des lots de métriques, d'instantanés, journald et d'événements
//   (ce dernier sert aussi `loki_push`) — dits par `dire_la_transaction_non_ouverte`, qui ne classe rien ; le COMMIT des
//   lots de métriques et d'instantanés (`tx.commit().is_ok()` : erreur jetée, ni classée ni dite) ; les trois insertions
//   d'alertes de la voie des instantanés (`.is_err()` : erreur jetée) ;
// - ingest/obs.rs, `metrics_prom` et `metrics_write` : le `BEGIN`, la ligne refusée (`annuler_le_lot_a_la_ligne_refusee`)
//   et le COMMIT refusé (`valider_la_transaction` puis `refuser_le_geste_non_valide`) — dits, jamais classés ;
// - une insertion de métrique ou d'instantané refusée HORS support ne laissait aucun texte du moteur au journal.
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ : `loki_push` ne passe pas à côté de la classification pour une ligne ou un COMMIT
// refusés : son lot passe par `ingest_events_batch_env`, dont l'insertion et le COMMIT sont classés depuis les deux
// changements précédents. Les témoins `l_insert` et `l_commit` le tiennent par la route : avant + 1, jamais + 2.
//
// CE QUI CHANGE : chacun de ces sites passe SON erreur à la classification existante, une fois. Les lignes existantes
// sont inchangées à l'octet (`BEGIN`, récepteurs HTTP, quarantaine). Les sites du spool qui n'avaient aucune ligne
// propre gagnent la leur, à la forme des voisines, avec le code étendu (`decrire_l_erreur`) et sans chemin de base ni
// texte lu dans le lot : `[ingest] metrics INSERT refusé -> lot annulé : …`, `[ingest] metrics COMMIT refusé -> …`,
// `[ingest] snapshot INSERT refusé -> …`, `[ingest] snapshot battement refusé -> …`,
// `[ingest] snapshot alerte <règle> refusée -> …` (la règle par son littéral), `[ingest] snapshot COMMIT refusé -> …`.
// Annulation, quarantaine, lot laissé au spool sur un `BEGIN` refusé, statut et corps HTTP : inchangés.
//
// FABRICATION (sqlite3.c vendoré 3.39.4) :
// - `BEGIN` refusé par le SUPPORT : l'en-tête de la base est rendu illisible entre deux transactions. Une seconde
//   connexion écrit puis fait un point de contrôle `TRUNCATE` (l'en-tête d'index du WAL change, le cache de l'écrivain est
//   donc purgé à son prochain `BEGIN` : `pagerBeginReadTransaction`, « if( rc!=SQLITE_OK || changed ){ pager_reset(pPager) »),
//   puis les seize octets du mot magique sont écrasés dans le fichier. `lockBtree` relit la page 1 et rend
//   `SQLITE_NOTADB` (« if( memcmp(page1, zMagicHeader, 16)!=0 ){ goto page1_init_failed; } », rc posé à `SQLITE_NOTADB`).
//   Les octets d'origine sont remis après le passage, avant toute relecture. Ce geste ouvre le fichier de base par un
//   second descripteur : admis ici parce que l'enfant ne joue que ce test, jamais à côté d'un démon.
// - `BEGIN` refusé par une base OCCUPÉE : une seconde connexion tient `BEGIN IMMEDIATE`, l'écrivain n'attend pas
//   (`busy_timeout` nul) : `SQLITE_BUSY`, non compté.
// - Insertion refusée par le SUPPORT : un index plein-texte de témoin (`ch3_fts`) alimenté par un déclencheur sur la table
//   visée, dont l'enregistrement des moyennes est retiré (`fts5DataRead` : `SQLITE_CORRUPT_VTAB`, 267). HORS support :
//   `RAISE(ABORT, …)` (`SQLITE_CONSTRAINT_TRIGGER`, 1811).
// - COMMIT refusé par le SUPPORT : un déclencheur d'insertion appelle une fonction de témoin qui borne la taille de fichier
//   du processus à zéro (`RLIMIT_FSIZE`, `SIGXFSZ` ignoré) ; les pages restent au cache jusqu'au COMMIT, dont l'écriture
//   rend `EFBIG`, traduit en `SQLITE_IOERR_WRITE`, 778 (`unixWrite`). La limite est relevée après le passage. HORS
//   support : une clé étrangère DIFFÉRÉE violée par un déclencheur (`SQLITE_CONSTRAINT_FOREIGNKEY`, 787).
//
// AMORCE : le compte est amorcé dans l'enfant à une valeur écrite ici (une erreur, code 1034, instant 1000) : après doit
// valoir avant + 1 exactement (instant du passage, code de la cause) sur le support, avant à l'identique sinon.
// ISOLEMENT : chaque cas se rejoue dans un SOUS-PROCESSUS qui ne joue que lui ; le parent lit la sortie d'erreur ENTIÈRE.
// Les récepteurs sont appelés par leur gestionnaire (`metrics_prom`, `metrics_write`, `loki_push`), avec un compte
// éditeur sans hôte lié ; le corps servi est comparé à l'octet, identifiant de corrélation compris (celui de l'enfant).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun disque réellement plein (`SQLITE_FULL` passerait par la même classification) ;
// la corruption d'une insertion est celle d'un index posée par une écriture SQL ; le `BEGIN` illisible est celui de
// l'en-tête, pas une panne de lecture du support ; le mode multi-tenant n'est pas joué.

#[cfg(test)]
mod ch3_ingestion_aveux_metriques_instantanes_recepteurs {
    use super::*;
    use rusqlite::functions::FunctionFlags;

    const CH3_ENFANT: &str = "CH3_ENFANT_INGESTION";
    const CH3_RENDU: &str = "CH3-RENDU:";
    const CH3_PREFIXE: &str = "tests::ch3_ingestion_aveux_metriques_instantanes_recepteurs::";
    /// L'amorce du compte, écrite ici : une erreur, code étendu 1034 (`SQLITE_IOERR_FSYNC`), instant 1000.
    const AMORCE_CODE: i32 = 1034;
    const AMORCE_TS: i64 = 1000;
    /// `SQLITE_NOTADB`, écrit ici.
    const NOTADB: i64 = 26;
    /// `SQLITE_CORRUPT | (1 << 8)`, écrit ici.
    const CORRUPT_VTAB: i64 = 267;
    /// `SQLITE_IOERR | (3 << 8)` (`SQLITE_IOERR_WRITE`), écrit ici.
    const IOERR_WRITE: i64 = 778;
    const TEXTE_NOTADB: &str = "file is not a database";
    const TEXTE_OCCUPEE: &str = "database is locked";
    const TEXTE_CORROMPUE: &str = "database disk image is malformed";
    const TEXTE_E_S: &str = "disk I/O error";
    const TEXTE_CLE_ETRANGERE: &str = "FOREIGN KEY constraint failed";
    const TEXTE_CONTRAINTE: &str = "ch3-contrainte";
    const LOT_EVENEMENTS: &str = "ingest-1-1.json";
    const LOT_JOURNALD: &str = "jrnl-1-1.ndjson";
    const LOT_METRIQUES: &str = "ingest-1-2.json";
    const LOT_INSTANTANE: &str = "ingest-1-3.json";
    const GENRE: &str = "ch3posture";
    const EMPREINTE: &str = "ch3-empreinte";
    const MACHINE: &str = "web01";
    const MAGIQUE: &[u8; 16] = b"SQLite format 3\0";
    /// La phrase servie par `loki_push` sur un lot annulé, écrite ici.
    const LOKI_ANNULE: &str = "ingestion Loki ANNULÉE (transaction rejetée) : aucune entrée de ce lot n'a été écrite — réémettez";
    /// Les phrases servies par les récepteurs de métriques, écrites ici.
    const CAUSE_NON_ECRIT: &str = "LOT NON ÉCRIT : la base n'a pas pris la transaction de ce lot (BEGIN ou COMMIT refusé : \
         verrou tenu, transaction d'un autre geste pendante, base en lecture seule ou pleine) — AUCUNE ligne de ce lot n'est \
         écrite. Réémettez-le tel quel.";
    const CAUSE_LIGNE: &str = "LOT NON ÉCRIT : la base a refusé une ligne de ce lot (contrainte, déclencheur, base pleine \
         ou en lecture seule) — sa transaction est ANNULÉE, AUCUNE ligne de ce lot n'est écrite. Réémettez-le tel quel ; un \
         refus qui persiste tient à la base, pas au lot.";

    static CH3_LIMITE_POSEE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static CH3_LIMITE_D_AVANT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[derive(prost::Message)]
    struct Ch3Ecriture {
        #[prost(message, repeated, tag = "1")]
        timeseries: Vec<Ch3Serie>,
    }
    #[derive(prost::Message)]
    struct Ch3Serie {
        #[prost(message, repeated, tag = "1")]
        labels: Vec<Ch3Etiquette>,
        #[prost(message, repeated, tag = "2")]
        samples: Vec<Ch3Point>,
    }
    #[derive(prost::Message)]
    struct Ch3Etiquette {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(string, tag = "2")]
        value: String,
    }
    #[derive(prost::Message)]
    struct Ch3Point {
        #[prost(double, tag = "1")]
        value: f64,
        #[prost(int64, tag = "2")]
        timestamp: i64,
    }

    /// Base au schéma complet, état d'application et file d'ingest réelle (vide).
    fn ch3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, crate::tmp_possede::TmpPossede) {
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

    /// La voie d'un site : `m` lot de métriques du spool, `s` instantané du spool, `j` journald, `e` événements du spool,
    /// `p` `metrics_prom`, `w` `metrics_write`, `l` `loki_push`.
    fn ch3_voie(site: &str) -> &str {
        site.split('_').next().expect("voie")
    }

    /// Le geste du site, sa partie après la voie : `begin`, `insert`, `commit`, `battement`, `fw`, `ctrl`, `vide`.
    fn ch3_geste(site: &str) -> &str {
        site.split_once('_').map(|(_, g)| g).expect("geste")
    }

    /// Dépose le lot du site (voies du spool) ; rend son chemin.
    fn ch3_deposer(st: &AppState, site: &str) -> Option<std::path::PathBuf> {
        let spool = std::path::PathBuf::from(st.spool.as_str());
        let (nom, contenu) = match ch3_voie(site) {
            "m" => (
                LOT_METRIQUES,
                json!({ "kind": "metrics", "ts": now(), "data": { "metrics": [
                    { "name": "ch3.premiere", "value": 1.0 }, { "name": "ch3.seconde", "value": 2.0 }
                ] } })
                .to_string(),
            ),
            "s" => {
                let (genre, empreinte, donnees) = match ch3_geste(site) {
                    "fw" => ("firewall", "ch3-fw", json!({ "control_docker_lockdown": { "ok": false } })),
                    "ctrl" => ("controls", "ch3-ctrl", json!({ "failed": 1, "controls": [{ "id": "ch3-controle", "ok": false }] })),
                    "vide" => ("controls", "ch3-vide", json!({ "failed": 0, "controls": [] })),
                    _ => (GENRE, EMPREINTE, json!({ "ch3": true })),
                };
                (LOT_INSTANTANE, json!({ "kind": genre, "ts": now(), "hash": empreinte, "host": MACHINE, "data": donnees }).to_string())
            }
            "j" => (
                LOT_JOURNALD,
                format!(
                    "{}\n",
                    json!({
                        "__REALTIME_TIMESTAMP": (now() as i128 * 1_000_000).to_string(),
                        "_HOSTNAME": MACHINE, "_COMM": "sshd",
                        "MESSAGE": "Failed password for invalid user ch3sonde from 203.0.113.7 port 22",
                        "PRIORITY": "5", "__CURSOR": "ch3-curseur-1"
                    })
                ),
            ),
            "e" => (
                LOT_EVENEMENTS,
                json!({ "kind": "events", "ts": now(), "data": { "events": [{ "source": "ch3src", "message": "ch3 sonde", "dedup": "ch3-d1" }] } })
                    .to_string(),
            ),
            _ => return None,
        };
        let chemin = spool.join(nom);
        std::fs::write(&chemin, contenu).expect("fixture : lot déposé");
        Some(chemin)
    }

    /// Le battement suppose une série dont la dernière empreinte est celle du lot : elle est inscrite AVANT d'armer.
    fn ch3_semer(st: &AppState, site: &str) {
        if site == "s_battement" {
            st.db
                .lock()
                .execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,'{}',?4)", params![AMORCE_TS, GENRE, EMPREINTE, MACHINE])
                .expect("fixture : instantané précédent");
        }
    }

    /// La table, l'événement et la valeur indexée du déclencheur du site.
    fn ch3_cible(site: &str) -> (&'static str, &'static str, &'static str) {
        match (ch3_voie(site), ch3_geste(site)) {
            ("m" | "p" | "w", _) => ("INSERT", "metric", "new.name"),
            ("s", "battement") => ("UPDATE", "snapshot", "new.kind"),
            ("s", "fw" | "ctrl" | "vide") => ("INSERT", "alert", "new.rule"),
            ("s", _) => ("INSERT", "snapshot", "new.kind"),
            ("l", _) => ("INSERT", "event", "new.message"),
            autre => panic!("instrument : site sans déclencheur {autre:?}"),
        }
    }

    /// Ce que l'armement laisse à défaire après le passage.
    struct Ch3Arme {
        /// Les octets d'en-tête écrasés, à remettre.
        entete: Option<[u8; 16]>,
        /// La connexion qui tient le verrou d'écriture.
        occupante: Option<Connection>,
    }

    /// Rend l'en-tête de la base illisible pour le prochain `BEGIN` de l'écrivain ; rend les octets d'origine.
    fn ch3_corrompre_l_entete(path: &str) -> [u8; 16] {
        use std::os::unix::fs::FileExt;
        let seconde = open_db(path).expect("fixture : seconde connexion");
        seconde.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('ch3-sonde','1')", []).expect("fixture : écriture de la seconde connexion");
        let occupe: i64 = seconde.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0)).expect("fixture : point de contrôle");
        assert_eq!(occupe, 0, "contrôle : le point de contrôle TRUNCATE a abouti");
        drop(seconde);
        let f = std::fs::OpenOptions::new().read(true).write(true).open(path).expect("fixture : fichier de base");
        let mut avant = [0u8; 16];
        f.read_exact_at(&mut avant, 0).expect("fixture : en-tête lu");
        assert_eq!(&avant, MAGIQUE, "contrôle : l'en-tête d'origine est le mot magique");
        f.write_all_at(&[0x5a; 16], 0).expect("fixture : en-tête écrasé");
        avant
    }

    /// Arme la cause de l'échec sur la base de l'écrivain.
    fn ch3_armer(st: &AppState, site: &str, cause: &str) -> Ch3Arme {
        let mut arme = Ch3Arme { entete: None, occupante: None };
        let geste = ch3_geste(site);
        match (geste, cause) {
            ("begin", "support") => arme.entete = Some(ch3_corrompre_l_entete(st.db_path.as_str())),
            ("begin", "occupee") => {
                st.db.lock().busy_timeout(std::time::Duration::ZERO).expect("fixture : l'écrivain n'attend pas");
                let occupante = open_db(st.db_path.as_str()).expect("fixture : seconde connexion");
                occupante.execute_batch("BEGIN IMMEDIATE").expect("fixture : la seconde connexion prend le verrou d'écriture");
                arme.occupante = Some(occupante);
            }
            ("commit", "support") => {
                let (quand, table, _) = ch3_cible(site);
                let conn = st.db.lock();
                // SAFETY: appel système sans pointeur conservé ; l'enfant ne joue que ce test.
                unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) }; // l'écriture rend EFBIG au lieu de tuer le processus
                conn.create_scalar_function("ch3_borner", 0, FunctionFlags::SQLITE_UTF8, |_ctx| -> rusqlite::Result<i64> {
                    if !CH3_LIMITE_POSEE.load(std::sync::atomic::Ordering::SeqCst) {
                        let mut avant = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                        // SAFETY: appels système sans pointeur conservé.
                        let lue = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut avant) } == 0;
                        CH3_LIMITE_D_AVANT.store(avant.rlim_cur, std::sync::atomic::Ordering::SeqCst);
                        let zero = libc::rlimit { rlim_cur: 0, rlim_max: avant.rlim_max };
                        let posee = lue && unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero) } == 0;
                        CH3_LIMITE_POSEE.store(posee, std::sync::atomic::Ordering::SeqCst);
                    }
                    Ok(1)
                })
                .expect("fixture : fonction de témoin");
                conn.execute_batch(&format!("CREATE TRIGGER ch3_borne AFTER {quand} ON {table} BEGIN SELECT ch3_borner(); END;"))
                    .expect("fixture : déclencheur de la borne");
            }
            ("commit", "hors") => {
                let (quand, table, _) = ch3_cible(site);
                st.db
                    .lock()
                    .execute_batch(&format!(
                        "PRAGMA foreign_keys=ON;
                         CREATE TABLE ch3_parent(id INTEGER PRIMARY KEY);
                         CREATE TABLE ch3_enfant(p INTEGER REFERENCES ch3_parent(id) DEFERRABLE INITIALLY DEFERRED);
                         CREATE TRIGGER ch3_differe AFTER {quand} ON {table} BEGIN INSERT INTO ch3_enfant VALUES(42); END;"
                    ))
                    .expect("fixture : clé étrangère différée");
            }
            (_, "support") => {
                let (quand, table, valeur) = ch3_cible(site);
                let conn = st.db.lock();
                conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE ch3_fts USING fts5(x);
                     CREATE TRIGGER ch3_index AFTER {quand} ON {table} BEGIN INSERT INTO ch3_fts(x) VALUES({valeur}); END;"
                ))
                .expect("fixture : index plein-texte de témoin");
                let retire = conn.execute("DELETE FROM ch3_fts_data WHERE id=1", []).expect("fixture : moyennes retirées");
                assert_eq!(retire, 1, "contrôle : l'enregistrement des moyennes de l'index de témoin existait");
            }
            (_, "hors") => {
                let (quand, table, _) = ch3_cible(site);
                st.db
                    .lock()
                    .execute_batch(&format!(
                        "CREATE TRIGGER ch3_contrainte BEFORE {quand} ON {table} BEGIN SELECT RAISE(ABORT, '{TEXTE_CONTRAINTE}'); END;"
                    ))
                    .expect("fixture : déclencheur");
            }
            autre => panic!("instrument : cas inconnu {autre:?}"),
        }
        arme
    }

    fn ch3_lot_remote_write() -> axum::body::Bytes {
        use prost::Message;
        let lot = Ch3Ecriture {
            timeseries: ["ch3_premiere", "ch3_seconde"]
                .iter()
                .map(|n| Ch3Serie {
                    labels: vec![Ch3Etiquette { name: "__name__".into(), value: (*n).into() }],
                    samples: vec![Ch3Point { value: 1.0, timestamp: now() * 1000 }],
                })
                .collect(),
        };
        let mut brut = Vec::new();
        lot.encode(&mut brut).expect("fixture : encodage protobuf");
        axum::body::Bytes::from(snap::raw::Encoder::new().compress_vec(&brut).expect("fixture : snappy"))
    }

    /// Un passage par le gestionnaire du récepteur du site ; rend le statut et le corps servis.
    fn ch3_route(st: &AppState, site: &str) -> (u16, String) {
        let au = sp_au("operateur", "editor");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de l'enfant");
        rt.block_on(async {
            let r = match ch3_voie(site) {
                "p" => metrics_prom(State(st.clone()), Extension(au), Query(HashMap::new()), "ch3_premiere 1\nch3_seconde 2\n".to_string()).await,
                "w" => metrics_write(State(st.clone()), Extension(au), ch3_lot_remote_write()).await,
                "l" => {
                    let mut entetes = axum::http::HeaderMap::new();
                    entetes.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/json"));
                    let corps = json!({ "streams": [{ "stream": { "job": "ch3" }, "values": [[(now() as i128 * 1_000_000_000).to_string(), "ch3 ligne"]] }] });
                    loki_push(State(st.clone()), Extension(au), entetes, axum::body::Bytes::from(corps.to_string())).await
                }
                autre => panic!("instrument : voie sans récepteur {autre}"),
            };
            let statut = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            (statut, String::from_utf8_lossy(&b).into_owned())
        })
    }

    /// LE CORPS DE L'ENFANT : armement, amorce du compte, compte avant, un passage (spool ou récepteur), compte après.
    fn ch3_jouer(site: &str, cause: &str) {
        let (st, path, _spool) = ch3_etat(&format!("ch3-{site}-{cause}"));
        ch3_semer(&st, site);
        let lot = ch3_deposer(&st, site);
        let arme = ch3_armer(&st, site, cause);
        crate::sqlite_plafond::ERREURS_DU_SUPPORT.noter(AMORCE_CODE, AMORCE_TS);
        let avant = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let t0 = now();
        let (issue, statut, corps) = match &lot {
            Some(_) => (format!("{:?}", ingest_once(&st.tenants, &st.spool)), 0u16, String::new()),
            None => {
                let (statut, corps) = ch3_route(&st, site);
                (String::new(), statut, corps)
            }
        };
        let t1 = now();
        let apres = crate::sqlite_plafond::ErreursDuSupport::du_processus();
        let limite_posee = CH3_LIMITE_POSEE.load(std::sync::atomic::Ordering::SeqCst);
        if limite_posee {
            let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: appels système sans pointeur conservé.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut l) }, 0, "contrôle : limite relue");
            l.rlim_cur = CH3_LIMITE_D_AVANT.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &l) }, 0, "contrôle : limite relevée");
        }
        if let Some(occupante) = &arme.occupante {
            occupante.execute_batch("ROLLBACK").expect("fixture : verrou rendu");
        }
        let entete_remise = match arme.entete {
            Some(octets) => {
                use std::os::unix::fs::FileExt;
                let f = std::fs::OpenOptions::new().write(true).open(path.as_str()).expect("fixture : fichier de base");
                f.write_all_at(&octets, 0).expect("fixture : en-tête remis");
                true
            }
            None => false,
        };
        let (en_quarantaine, reste_au_spool) = match &lot {
            Some(chemin) => {
                let nom = chemin.file_name().and_then(|n| n.to_str()).expect("nom du lot").to_string();
                (std::path::Path::new(&crate::state::repertoire_de_quarantaine(&st.spool)).join(&nom).exists(), chemin.exists())
            }
            None => (false, false),
        };
        let autocommit = st.db.lock().is_autocommit();
        // Relecture à froid, sur une connexion neuve (le cache de l'écrivain peut garder l'en-tête illisible).
        let froide = open_db(path.as_str()).expect("relecture à froid");
        let compter = |sql: &str| -> i64 { froide.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture de `{sql}` ({e})")) };
        let rendu = json!({
            "chemin": path.as_str(),
            "pid": std::process::id(),
            "avant": [avant.total, avant.derniere_ts, avant.dernier_code],
            "apres": [apres.total, apres.derniere_ts, apres.dernier_code],
            "t0": t0, "t1": t1,
            "issue": issue, "statut": statut, "corps": corps,
            "en_quarantaine": en_quarantaine,
            "reste_au_spool": reste_au_spool,
            "evenements": compter("SELECT COUNT(*) FROM event WHERE message LIKE 'ch3%' OR message LIKE '%ch3sonde%'"),
            "metriques": compter("SELECT COUNT(*) FROM metric WHERE name LIKE 'ch3%'"),
            "instantanes": compter("SELECT COUNT(*) FROM snapshot WHERE hash LIKE 'ch3-%'"),
            "ts_du_dernier": compter("SELECT COALESCE(MAX(ts), 0) FROM snapshot WHERE hash LIKE 'ch3-%'"),
            "alertes": compter("SELECT COUNT(*) FROM alert WHERE rule IN ('firewall.lockdown','control.catalog','control.catalog.vide')"),
            "autocommit": autocommit,
            "limite_posee": limite_posee,
            "entete_remise": entete_remise,
        });
        println!("{CH3_RENDU}{rendu}");
    }

    /// Ajoute à la commande de l'enfant (construite par le test) les arguments qui ne jouent que ce test ; rend sa sortie.
    fn ch3_lancer(commande: &mut std::process::Command, nom: &str) -> std::process::Output {
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{CH3_PREFIXE}{nom}")])
            .output()
            .expect("ré-exécution du binaire de test")
    }

    /// Le rendu de l'enfant et sa sortie d'erreur entière.
    fn ch3_lire(sortie: &std::process::Output) -> (Value, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let rendus: Vec<Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(CH3_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 1, "contrôle : l'enfant a joué son issue une fois : {stdout}\n{stderr}");
        (rendus[0].clone(), stderr)
    }

    fn ch3_lignes(stderr: &str, tete: &str) -> Vec<String> {
        stderr.lines().filter(|l| l.starts_with(tete)).map(|l| l.to_string()).collect()
    }

    /// Le code étendu, le texte du moteur et la description à code (`decrire_l_erreur`) attendus du cas.
    fn ch3_erreur_attendue(site: &str, cause: &str) -> (i64, &'static str, String) {
        match (ch3_geste(site), cause) {
            ("begin", "support") => (NOTADB, TEXTE_NOTADB, format!("{TEXTE_NOTADB} [code étendu {NOTADB}]")),
            ("begin", _) => (5, TEXTE_OCCUPEE, format!("{TEXTE_OCCUPEE} [code étendu 5]")),
            ("commit", "support") => (IOERR_WRITE, TEXTE_E_S, format!("{TEXTE_E_S} [SQLITE_IOERR_WRITE, code étendu {IOERR_WRITE}]")),
            ("commit", _) => (787, TEXTE_CLE_ETRANGERE, format!("{TEXTE_CLE_ETRANGERE} [code étendu 787]")),
            (_, "support") => (CORRUPT_VTAB, TEXTE_CORROMPUE, format!("{TEXTE_CORROMPUE} [code étendu {CORRUPT_VTAB}]")),
            _ => (1811, TEXTE_CONTRAINTE, format!("{TEXTE_CONTRAINTE} [code étendu 1811]")),
        }
    }

    /// La ligne d'un `BEGIN` refusé, telle que `dire_la_transaction_non_ouverte` l'écrit (inchangée), ENTIÈRE.
    fn ch3_ligne_du_begin(geste: &str, cause: &str) -> String {
        if cause == "support" {
            format!(
                "[ingest] ERREUR {geste} NON pris(e) : BEGIN refusé par la base, et ce n'est pas un verrou ({TEXTE_NOTADB}) — rien \
                 n'est écrit ; un nouvel essai sera refusé de même tant que la cause demeure (base en lecture seule, disque, E/S)"
            )
        } else {
            format!(
                "[ingest] WARN {geste} NON pris(e) : BEGIN refusé, verrou d'écriture tenu ailleurs ({TEXTE_OCCUPEE}) — rien n'est \
                 écrit ; un verrou passe, un nouvel essai (passage suivant ou geste rejoué) peut aboutir"
            )
        }
    }

    /// Les lignes `[ingest]` attendues du passage, ENTIÈRES et dans l'ordre.
    fn ch3_lignes_attendues(site: &str, cause: &str, r: &Value) -> Vec<String> {
        let chemin = r["chemin"].as_str().expect("chemin");
        let (_, texte, description) = ch3_erreur_attendue(site, cause);
        let quarantaine = |raison: &str, nom: &str| format!("[ingest] {raison} -> quarantaine : {nom}");
        let q_metriques = quarantaine("metrics INSERT échoué (ROLLBACK du batch)", LOT_METRIQUES);
        let q_instantane = quarantaine("snapshot INSERT échoué (ROLLBACK du batch)", LOT_INSTANTANE);
        match site {
            "m_begin" => vec![ch3_ligne_du_begin("lot de métriques du spool", cause)],
            "s_begin" => vec![ch3_ligne_du_begin("lot d'instantané du spool", cause)],
            "j_begin" => vec![ch3_ligne_du_begin("lot journald", cause)],
            "e_begin" | "l_begin" => vec![ch3_ligne_du_begin("lot d'événements", cause)],
            "p_begin" => vec![ch3_ligne_du_begin("lot de métriques Prometheus", cause)],
            "w_begin" => vec![ch3_ligne_du_begin("lot remote_write", cause)],
            "m_insert" => vec![format!("[ingest] metrics INSERT refusé -> lot annulé : {description}"), q_metriques],
            "m_commit" => vec![format!("[ingest] metrics COMMIT refusé -> lot annulé : {description}"), q_metriques],
            "s_insert" => vec![format!("[ingest] snapshot INSERT refusé -> lot annulé : {description}"), q_instantane],
            "s_battement" => vec![format!("[ingest] snapshot battement refusé -> lot annulé : {description}"), q_instantane],
            "s_fw" => vec![format!("[ingest] snapshot alerte firewall.lockdown refusée -> lot annulé : {description}"), q_instantane],
            "s_ctrl" => vec![format!("[ingest] snapshot alerte control.catalog refusée -> lot annulé : {description}"), q_instantane],
            "s_vide" => vec![format!("[ingest] snapshot alerte control.catalog.vide refusée -> lot annulé : {description}"), q_instantane],
            "s_commit" => vec![format!("[ingest] snapshot COMMIT refusé -> lot annulé : {description}"), q_instantane],
            // Lignes d'avant, à l'octet : texte du moteur seul.
            "p_insert" => vec![format!("[ingest] WARN lot de métriques Prometheus : une ligne refusée par la base ({texte}) — lot ANNULÉ, rien n'est écrit")],
            "w_insert" => vec![format!("[ingest] WARN lot remote_write : une ligne refusée par la base ({texte}) — lot ANNULÉ, rien n'est écrit")],
            "p_commit" => vec![format!("[ingest] WARN lot de métriques Prometheus NON validé(e) : {texte}")],
            "w_commit" => vec![format!("[ingest] WARN lot remote_write NON validé(e) : {texte}")],
            // Lot Loki : lignes de la voie des événements, d'avant, à l'octet.
            "l_insert" => vec![format!("[ingest] events INSERT échoué -> ROLLBACK du batch ({chemin}) : {description}")],
            "l_commit" => vec![format!("[ingest] events COMMIT refusé -> lot annulé ({chemin}) : {texte}")],
            autre => panic!("instrument : site inconnu {autre}"),
        }
    }

    /// Le corps servi attendu, à l'octet : une cause et l'identifiant de corrélation de l'enfant (`plume-e<pid>-<n>`).
    fn ch3_juger_le_corps(site: &str, r: &Value) {
        let (statut, cause) = match site {
            "p_begin" | "w_begin" | "l_begin" | "p_commit" | "w_commit" => (503, CAUSE_NON_ECRIT),
            "p_insert" | "w_insert" => (503, CAUSE_LIGNE),
            "l_insert" | "l_commit" => (500, LOKI_ANNULE),
            autre => panic!("instrument : site sans récepteur {autre}"),
        };
        assert_eq!(r["statut"], statut, "le statut servi est celui d'avant : {r}");
        let texte = r["corps"].as_str().expect("corps");
        let lu: Value = serde_json::from_str(texte).unwrap_or_else(|e| panic!("corps JSON ({e}) : {texte}"));
        let id = lu["id"].as_str().unwrap_or_else(|| panic!("identifiant de corrélation servi : {texte}"));
        let suffixe = id.strip_prefix(&format!("plume-e{}-", r["pid"])).unwrap_or_else(|| panic!("identifiant de l'enfant : {id}"));
        assert!(!suffixe.is_empty() && suffixe.bytes().all(|b| b.is_ascii_digit()), "rang de l'identifiant : {id}");
        let attendu = format!("{{\"error\":{},\"id\":\"{id}\"}}", serde_json::to_string(cause).expect("cause"));
        assert_eq!(texte, attendu, "le corps servi, à l'octet : {r}");
    }

    /// Ce que le comportement garde, quelle que soit la cause : rien d'écrit de neuf, l'écrivain libre ; lot laissé au
    /// spool sur un `BEGIN` refusé, en quarantaine sinon ; corps servi à l'octet pour un récepteur ; lignes entières.
    fn ch3_comportement_garde(site: &str, cause: &str, r: &Value, stderr: &str) {
        assert_eq!(r["autocommit"], true, "l'écrivain n'est pas resté dans une transaction : {r}");
        assert_eq!(r["evenements"], 0, "aucun événement écrit : {r}");
        assert_eq!(r["metriques"], 0, "aucune métrique écrite : {r}");
        assert_eq!(r["alertes"], 0, "aucune alerte écrite : {r}");
        let semees = if site == "s_battement" { 1 } else { 0 };
        assert_eq!(r["instantanes"], semees, "aucun instantané neuf écrit : {r}");
        assert_eq!(r["ts_du_dernier"], if site == "s_battement" { AMORCE_TS } else { 0 }, "le battement est annulé : {r}");
        match ch3_voie(site) {
            "p" | "w" | "l" => ch3_juger_le_corps(site, r),
            _ => {
                assert_eq!(r["issue"], "Lue(1)", "le passage rend UN abandon, comme avant : {r}");
                let begin = ch3_geste(site) == "begin";
                assert_eq!(r["reste_au_spool"], begin, "un BEGIN refusé laisse le lot au spool, un lot annulé le retire : {r}");
                assert_eq!(r["en_quarantaine"], !begin, "un lot annulé part en quarantaine, un lot non pris non : {r}");
            }
        }
        assert_eq!(
            ch3_lignes(stderr, "[ingest] "),
            ch3_lignes_attendues(site, cause, r),
            "les lignes `[ingest]` du passage, entières : {stderr}"
        );
    }

    /// Juge un cas « erreur du support » : avant = l'amorce écrite ; après = avant + 1, instant du passage, code de la
    /// cause ; la ligne `[sqlite]` ENTIÈRE, une fois.
    fn ch3_juger_support(site: &str, r: &Value, stderr: &str) {
        let (code, _, description) = ch3_erreur_attendue(site, "support");
        match ch3_geste(site) {
            "commit" => assert_eq!(r["limite_posee"], true, "contrôle : la limite de taille a été posée dans la transaction du lot : {r}"),
            "begin" => assert_eq!(r["entete_remise"], true, "contrôle : l'en-tête a été écrasé puis remis : {r}"),
            _ => {}
        }
        assert_eq!(r["avant"], json!([1, AMORCE_TS, AMORCE_CODE]), "AVANT : l'amorce écrite : {r}");
        assert_eq!(r["apres"][0], 2, "APRÈS : avant + 1, exactement : {r}\n{stderr}");
        let ts = r["apres"][1].as_i64().expect("instant");
        assert!(ts >= r["t0"].as_i64().unwrap() && ts <= r["t1"].as_i64().unwrap(), "l'instant est celui du passage : {r}");
        assert_eq!(r["apres"][2], code, "le code étendu retenu est celui de la cause : {r}");
        assert_eq!(
            ch3_lignes(stderr, "[sqlite] "),
            vec![format!("[sqlite] erreur du support de la base : {description}")],
            "la ligne de la classification, entière, une fois : {stderr}"
        );
        ch3_comportement_garde(site, "support", r, stderr);
    }

    /// Juge un cas hors support (contrainte, base occupée) : le compte reste à l'amorce, aucune ligne `[sqlite]`.
    fn ch3_juger_hors_support(site: &str, cause: &str, r: &Value, stderr: &str) {
        assert_eq!(r["avant"], json!([1, AMORCE_TS, AMORCE_CODE]), "AVANT : l'amorce écrite : {r}");
        assert_eq!(r["apres"], r["avant"], "APRÈS : avant + 0 : {r}\n{stderr}");
        assert_eq!(ch3_lignes(stderr, "[sqlite] "), Vec::<String>::new(), "aucune ligne de la classification : {stderr}");
        ch3_comportement_garde(site, cause, r, stderr);
    }

    /// (1) LOT DE MÉTRIQUES DU SPOOL, `BEGIN` : en-tête illisible compté, base occupée non comptée ; lot laissé au spool.
    /// MUTANT : `CH3_M_BEGIN` (classification retirée) -> avant + 0 : ROUGE.
    #[test]
    fn ch3_m_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("m_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_m_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("m_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_m_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("m_begin", "occupee", &r, &stderr);
    }

    /// (2) LOT DE MÉTRIQUES DU SPOOL, INSERTION : ligne neuve à code, sur le support comme sur une contrainte ; compté une
    /// fois pour un lot de deux métriques. MUTANTS : `CH3_M_INSERT_SANS_LIGNE` : ROUGE ; `CH3_M_INSERT_SANS_ARRET` (la
    /// boucle continue) -> avant + 2 : ROUGE.
    #[test]
    fn ch3_m_insert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("m_insert", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_m_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("m_insert", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_m_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("m_insert", "hors", &r, &stderr);
    }

    /// (3) LOT DE MÉTRIQUES DU SPOOL, COMMIT : E/S refusée comptée, clé étrangère différée non comptée ; ligne neuve à code.
    /// MUTANTS : `CH3_M_COMMIT` (classification retirée) : ROUGE ; `CH3_M_COMMIT_DEUX_FOIS` -> avant + 2 : ROUGE ;
    /// `CH3_M_COMMIT_SANS_LIGNE` : ROUGE ; `CH3_M_COMMIT_SANS_CODE` (`{e}`) : ROUGE ; `CH3_M_COMMIT_COMPTE_TOUT` : ROUGE.
    #[test]
    fn ch3_m_commit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("m_commit", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_m_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("m_commit", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_m_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("m_commit", "hors", &r, &stderr);
    }

    /// (4) INSTANTANÉ DU SPOOL, `BEGIN`. MUTANT : `CH3_S_BEGIN` : ROUGE.
    #[test]
    fn ch3_s_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_s_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_begin", "occupee", &r, &stderr);
    }

    /// (5) INSTANTANÉ NEUF : ligne neuve à code. MUTANT : `CH3_S_INSERT_SANS_LIGNE` : ROUGE.
    #[test]
    fn ch3_s_insert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_insert", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_insert", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_insert", "hors", &r, &stderr);
    }

    /// (6) BATTEMENT D'UN INSTANTANÉ INCHANGÉ : ligne neuve à code, la ligne précédente garde son instant.
    /// MUTANT : `CH3_S_BATTEMENT_SANS_LIGNE` : ROUGE.
    #[test]
    fn ch3_s_battement() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_battement", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_battement");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_battement", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_battement");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_battement", "hors", &r, &stderr);
    }

    /// (7) ALERTE `firewall.lockdown` : comptée sur le support, ligne neuve à code.
    /// MUTANTS : `CH3_S_FW` (classification retirée) : ROUGE ; `CH3_S_FW_SANS_LIGNE` : ROUGE.
    #[test]
    fn ch3_s_fw() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_fw", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_fw");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_fw", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_fw");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_fw", "hors", &r, &stderr);
    }

    /// (8) ALERTE `control.catalog`. MUTANT : `CH3_S_CTRL` : ROUGE.
    #[test]
    fn ch3_s_ctrl() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_ctrl", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_ctrl");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_ctrl", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_ctrl");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_ctrl", "hors", &r, &stderr);
    }

    /// (9) ALERTE `control.catalog.vide`. MUTANT : `CH3_S_VIDE` : ROUGE.
    #[test]
    fn ch3_s_vide() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_vide", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_vide");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_vide", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_vide");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_vide", "hors", &r, &stderr);
    }

    /// (10) INSTANTANÉ DU SPOOL, COMMIT. MUTANTS : `CH3_S_COMMIT` : ROUGE ; `CH3_S_COMMIT_DEUX_FOIS` -> avant + 2 : ROUGE ;
    /// `CH3_S_COMMIT_SANS_LIGNE` : ROUGE.
    #[test]
    fn ch3_s_commit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("s_commit", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_s_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("s_commit", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_s_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("s_commit", "hors", &r, &stderr);
    }

    /// (11) LOT JOURNALD, `BEGIN`. MUTANT : `CH3_J_BEGIN` : ROUGE.
    #[test]
    fn ch3_j_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("j_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_j_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("j_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_j_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("j_begin", "occupee", &r, &stderr);
    }

    /// (12) LOT D'ÉVÉNEMENTS DU SPOOL, `BEGIN` (le site que sert aussi `loki_push`). MUTANT : `CH3_E_BEGIN` : ROUGE.
    #[test]
    fn ch3_e_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("e_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_e_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("e_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_e_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("e_begin", "occupee", &r, &stderr);
    }

    /// (13) `metrics_prom`, `BEGIN` : 503 d'avant à l'octet. MUTANTS : `CH3_P_BEGIN` : ROUGE ; `CH3_P_BEGIN_COMPTE_TOUT` : ROUGE.
    #[test]
    fn ch3_p_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("p_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_p_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("p_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_p_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("p_begin", "occupee", &r, &stderr);
    }

    /// (14) `metrics_prom`, LIGNE REFUSÉE : comptée une fois pour un lot de deux lignes, ligne et 503 d'avant.
    /// MUTANTS : `CH3_P_INSERT` : ROUGE ; `CH3_P_INSERT_DEUX_FOIS` -> avant + 2 : ROUGE.
    #[test]
    fn ch3_p_insert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("p_insert", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_p_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("p_insert", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_p_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("p_insert", "hors", &r, &stderr);
    }

    /// (15) `metrics_prom`, COMMIT. MUTANT : `CH3_P_COMMIT` : ROUGE.
    #[test]
    fn ch3_p_commit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("p_commit", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_p_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("p_commit", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_p_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("p_commit", "hors", &r, &stderr);
    }

    /// (16) `metrics_write`, `BEGIN`. MUTANT : `CH3_W_BEGIN` : ROUGE.
    #[test]
    fn ch3_w_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("w_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_w_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("w_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_w_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("w_begin", "occupee", &r, &stderr);
    }

    /// (17) `metrics_write`, LIGNE REFUSÉE. MUTANTS : `CH3_W_INSERT` : ROUGE ; `CH3_W_INSERT_DEUX_FOIS` : ROUGE.
    #[test]
    fn ch3_w_insert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("w_insert", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_w_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("w_insert", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_w_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("w_insert", "hors", &r, &stderr);
    }

    /// (18) `metrics_write`, COMMIT. MUTANTS : `CH3_W_COMMIT` : ROUGE ; `CH3_W_COMMIT_DEUX_FOIS` : ROUGE.
    #[test]
    fn ch3_w_commit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("w_commit", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_w_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("w_commit", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_w_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("w_commit", "hors", &r, &stderr);
    }

    /// (19) `loki_push`, `BEGIN` (site du lot d'événements) : 503 d'avant à l'octet. MUTANT : `CH3_E_BEGIN` : ROUGE.
    #[test]
    fn ch3_l_begin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("l_begin", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_l_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("l_begin", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "occupee"), "ch3_l_begin");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("l_begin", "occupee", &r, &stderr);
    }

    /// (20) `loki_push`, LIGNE REFUSÉE — RÉFUTATION de l'énoncé : déjà classée (par l'insertion de la voie des événements),
    /// avant + 1 et jamais + 2, 500 d'avant à l'octet. MUTANTS : `CH3_EV_INSERT` (classification retirée du site des
    /// événements) -> avant + 0 : ROUGE ; `CH3_EV_INSERT_DEUX_FOIS` -> avant + 2 : ROUGE.
    #[test]
    fn ch3_l_insert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("l_insert", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_l_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("l_insert", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_l_insert");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("l_insert", "hors", &r, &stderr);
    }

    /// (21) `loki_push`, COMMIT REFUSÉ — RÉFUTATION de l'énoncé : déjà classé, avant + 1, 500 d'avant à l'octet.
    /// MUTANT : `CH3_EV_COMMIT` (classification retirée du COMMIT des événements) -> avant + 0 : ROUGE.
    #[test]
    fn ch3_l_commit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if let Ok(cause) = std::env::var(CH3_ENFANT) {
            ch3_jouer("l_commit", &cause);
            return;
        }
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "support"), "ch3_l_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_support("l_commit", &r, &stderr);
        let sortie = ch3_lancer(std::process::Command::new(std::env::current_exe().expect("binaire de test")).env(CH3_ENFANT, "hors"), "ch3_l_commit");
        let (r, stderr) = ch3_lire(&sortie);
        ch3_juger_hors_support("l_commit", "hors", &r, &stderr);
    }
}
