//! Migrations de schéma versionnées (meta.schema_version). Sur &Connection uniquement. Extrait
//! de main.rs (refactor split #25 — byte-identique). Refactor TIER 2 : l'échelle `if v < N { … }`
//! est décomposée en `migrate()` DISPATCHER + un `fn migrate_vN(conn)` VERBATIM par version (mêmes
//! gardes, même ordre, mêmes bumps schema_version). Exceptions gardées INLINE car leur branche
//! d'échec fait `return` (abandon de TOUT migrate() -> retry au boot) : v33, v67, v77.
//!
//! INTÉGRITÉ DE SCHÉMA : chaque `migrate_vN` est exécutée par `migrate_step` — UNE transaction par
//! version, bump `meta.schema_version` INCLUS -> un échec OPÉRATIONNEL (disque plein, base verrouillée ;
//! classe B, cf. `MigTx`) est ROLLBACKé et laisse la version à l'ANCIENNE valeur, l'étape étant
//! re-tentée au prochain démarrage. Les 3 exceptions INLINE (v33/v67/v77) ne sont PAS enveloppées :
//! elles implémentent DÉJÀ le bump conditionnel (closure faillible + `return` sur échec) et portent
//! leur propre logique de reprise après interruption sur des mouvements de données volumineux — les
//! toucher n'apporterait rien à l'intégrité du bump et en dégraderait la lisibilité.
use crate::*;

/// v105 (CHANGE 1) — GARDE ANTI-DOWNGRADE. Version de schéma la PLUS HAUTE que CE binaire sait migrer
/// ET opérer (= la dernière `migrate_vN` de `migrate()` ci-dessous). DOIT être bumpée EN MÊME TEMPS que
/// l'ajout d'une migration `if v < N` (le test `code_schema_max_matches_fresh_migrate` le verrouille).
///
/// POURQUOI : `migrate()` est `if v < N` uniquement. Un binaire ANCIEN (ex. rollback tar d'une image
/// précédente) ouvrant une base estampillée PLUS HAUT (déjà migrée par un binaire plus récent) NE migre
/// rien (toutes ses gardes `v < N` sont fausses) et OPÈRE À L'AVEUGLE sur un schéma qu'il ne connaît pas
/// -> risque de corruption (survivable AUJOURD'HUI car migrations additives, mais non gardé). On REFUSE
/// d'ouvrir : arrêt PROPRE (exit non-zéro), JAMAIS un panic, JAMAIS un « proceed » silencieux.
pub(crate) const CODE_SCHEMA_MAX: i64 = 111;

/// Lit `meta.schema_version` (défaut 1 si table/lignes absentes ou illisibles) — MÊME lecture que `migrate()`.
/// Une base NEUVE (pas encore de table meta) renvoie 1 -> jamais refusée par la garde.
pub(crate) fn read_schema_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// GARDE ANTI-DOWNGRADE (cœur testable, aucune I/O ni exit). `Ok(v)` sur le chemin NORMAL
/// (`v <= CODE_SCHEMA_MAX` : v==max ouvre tel quel, v<max sera migré) ; `Err(v)` si la base est PLUS
/// RÉCENTE que ce binaire (`v > CODE_SCHEMA_MAX`) -> l'appelant (open_and_migrate_db) refuse d'ouvrir.
pub(crate) fn schema_downgrade_guard(conn: &Connection) -> Result<i64, i64> {
    let v = read_schema_version(conn);
    if v > CODE_SCHEMA_MAX { Err(v) } else { Ok(v) }
}

/// INTÉGRITÉ DE SCHÉMA — les `migrate_vN` ignorent volontairement le résultat de leurs DDL (`let _ =`)
/// parce que la RÉ-APPLICATION est le cas NORMAL (base déjà partiellement au schéma). DEUX CLASSES
/// d'échec se cachaient derrière ce même `let _ =`, et il FAUT les distinguer :
///
///   CLASSE A — IDEMPOTENCE, « existe déjà » (`SQLITE_ERROR`/`SQLITE_CONSTRAINT` : « duplicate column
///     name » d'un `ALTER TABLE ADD COLUMN` déjà appliqué, « already exists », « no such table » sur le
///     DROP d'un objet legacy absent, UNIQUE sur un seed re-joué…). L'échec ne CHANGE PAS le résultat :
///     l'objet est déjà dans l'état voulu. On continue de l'IGNORER — c'est la raison d'être du `let _ =`
///     et le comportement HISTORIQUE, préservé à l'identique.
///   CLASSE B — ÉCHEC OPÉRATIONNEL (disque plein, base verrouillée, I/O, lecture seule, corruption) :
///     l'objet N'A PAS été créé et une nouvelle tentative peut réussir. Ignorer ce résultat rendait
///     l'échec INDISTINGUABLE de la classe A, et le bump `UPDATE meta SET value='N'` — une écriture EN
///     PLACE, qui n'alloue aucune page et réussit donc même disque plein — estampillait la base comme
///     migrée SANS ses objets. État IRRÉPARABLE : la garde anti-downgrade interdit tout retour à un
///     binaire antérieur, et `if v < N` ne re-tentera jamais l'étape.
///
/// `MigTx` est un `Connection` emprunté qui expose la MÊME SIGNATURE que `Connection::execute` /
/// `execute_batch` — les corps des `migrate_vN` restent donc VERBATIM, `let _ =` compris — et qui
/// MÉMORISE la première erreur de CLASSE B. `migrate_step` en fait la condition du COMMIT.
struct MigTx<'c> {
    conn: &'c Connection,
    /// Première erreur de CLASSE B rencontrée pendant l'étape (`None` = aucune).
    failure: std::cell::RefCell<Option<String>>,
}

impl std::ops::Deref for MigTx<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn
    }
}

impl<'c> MigTx<'c> {
    fn new(conn: &'c Connection) -> Self {
        MigTx { conn, failure: std::cell::RefCell::new(None) }
    }

    fn note<T>(&self, sql: &str, r: &rusqlite::Result<T>) {
        if let Err(e) = r {
            if is_operational_failure(e) && self.failure.borrow().is_none() {
                // extrait COURT de l'ordre SQL : suffisant pour situer l'échec dans le journal de
                // l'opérateur, sans recopier une DDL entière dans un log.
                let head: Vec<&str> = sql.split_whitespace().take(5).collect();
                *self.failure.borrow_mut() = Some(format!("{e} — sur « {}… »", head.join(" ")));
            }
        }
    }

    /// MÊME signature que `Connection::execute` : les appels des `migrate_vN` sont INCHANGÉS.
    fn execute<P: rusqlite::Params>(&self, sql: &str, params: P) -> rusqlite::Result<usize> {
        let r = self.conn.execute(sql, params);
        self.note(sql, &r);
        r
    }

    /// MÊME signature que `Connection::execute_batch` : les appels des `migrate_vN` sont INCHANGÉS.
    fn execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        let r = self.conn.execute_batch(sql);
        self.note(sql, &r);
        r
    }
}

/// CLASSE B (cf. `MigTx`) : codes SQLite qui signent un échec de l'ENVIRONNEMENT — l'opération n'a PAS
/// eu lieu et une nouvelle tentative peut réussir. Liste FERMÉE : tout le reste (dont `SQLITE_ERROR` et
/// `SQLITE_CONSTRAINT`, qui portent les échecs d'idempotence de la classe A) conserve EXACTEMENT le
/// comportement historique (résultat ignoré).
fn is_operational_failure(e: &rusqlite::Error) -> bool {
    use rusqlite::ErrorCode::*;
    match e {
        rusqlite::Error::SqliteFailure(err, _) => matches!(
            err.code,
            DiskFull
                | DatabaseBusy
                | DatabaseLocked
                | ReadOnly
                | OutOfMemory
                | SystemIoFailure
                | DatabaseCorrupt
                | NotADatabase
                | CannotOpen
                | PermissionDenied
                | FileLockingProtocolFailed
                | OperationInterrupted
                | OperationAborted
                | InternalMalfunction
        ),
        _ => false,
    }
}

/// Exécute UNE étape de migration DANS UNE TRANSACTION, bump `meta.schema_version` INCLUS.
/// `true` = étape COMMITÉE (version == `target`). `false` = ROLLBACK : la base est rendue à son état
/// d'AVANT l'étape, version comprise, et l'appelant ABANDONNE le reste de `migrate()` — `v` n'est lu
/// qu'UNE fois, donc laisser les étapes suivantes bumper la version SAUTERAIT définitivement l'étape
/// échouée (précédent : les blocs INLINE v33/v67/v77, qui `return` déjà sur échec de leur backfill).
/// L'étape est ainsi RE-TENTÉE au prochain démarrage.
///
/// SQLite : les DDL (CREATE/ALTER/DROP) et les DML sont transactionnelles. `migrate.rs` ne contient
/// AUCUN `VACUUM` ni `PRAGMA journal_mode` — les deux ordres qui ÉCHOUENT dans une transaction ; les
/// seuls PRAGMA présents sont `analysis_limit` (simple réglage) suivi d'`ANALYZE` (v32/v35), qui écrit
/// `sqlite_stat1` comme n'importe quel INSERT et s'exécute donc sans contrainte dans la transaction.
fn migrate_step(conn: &Connection, target: i64, body: fn(&MigTx)) -> bool {
    let before = read_schema_version(conn);
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        eprintln!(
            "[migration] v{target} ÉCHEC ouverture de transaction ({e}) — version laissée à {before}, \
             RE-TENTÉE au prochain démarrage (migrate interrompu)"
        );
        return false;
    }
    let tx = MigTx::new(conn);
    body(&tx);
    let failure = tx.failure.borrow().clone();
    // Le bump appartient à la TRANSACTION : on vérifie qu'il a bien eu lieu AVANT de committer (une
    // étape qui n'estampille pas la version est un échec, pas un succès silencieux).
    let stamped = read_schema_version(conn) == target;
    if failure.is_none() && stamped {
        if let Err(e) = conn.execute_batch("COMMIT") {
            let _ = conn.execute_batch("ROLLBACK");
            eprintln!(
                "[migration] v{target} ÉCHEC COMMIT ({e}) — version laissée à {before}, RE-TENTÉE au \
                 prochain démarrage (migrate interrompu)"
            );
            return false;
        }
        return true;
    }
    let _ = conn.execute_batch("ROLLBACK");
    let cause = failure.unwrap_or_else(|| format!("schema_version non estampillée à {target}"));
    eprintln!(
        "[migration] v{target} ÉCHEC ({cause}) — ROLLBACK : le message « schéma -> v{target} » \
         éventuellement affiché ci-dessus est ANNULÉ ; version laissée à {before}, RE-TENTÉE au prochain \
         démarrage (migrate interrompu)"
    );
    false
}

/// Migrations de schéma versionnées (meta.schema_version). Idempotent : les `ALTER`
/// déjà appliqués renvoient une erreur « duplicate column » qu'on ignore volontairement.
/// Indispensable car `CREATE TABLE IF NOT EXISTS` n'ajoute pas de colonnes aux tables existantes.
/// Chaque étape passe par `migrate_step` : UNE transaction par version, bump INCLUS -> une étape qui
/// échoue pour une raison OPÉRATIONNELLE (classe B, cf. `MigTx`) est ROLLBACKée et laisse la version
/// à l'ancienne valeur ; `migrate()` s'interrompt et l'étape est re-tentée au prochain démarrage.
pub(crate) fn migrate(conn: &Connection) {
    let v: i64 = conn
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    if v < 2 && !migrate_step(conn, 2, migrate_v2) { return; }
    if v < 3 && !migrate_step(conn, 3, migrate_v3) { return; }
    if v < 4 && !migrate_step(conn, 4, migrate_v4) { return; }
    if v < 5 && !migrate_step(conn, 5, migrate_v5) { return; }
    if v < 6 && !migrate_step(conn, 6, migrate_v6) { return; }
    if v < 7 && !migrate_step(conn, 7, migrate_v7) { return; }
    if v < 8 && !migrate_step(conn, 8, migrate_v8) { return; }
    if v < 9 && !migrate_step(conn, 9, migrate_v9) { return; }
    if v < 10 && !migrate_step(conn, 10, migrate_v10) { return; }
    if v < 11 && !migrate_step(conn, 11, migrate_v11) { return; }
    if v < 12 && !migrate_step(conn, 12, migrate_v12) { return; }
    if v < 13 && !migrate_step(conn, 13, migrate_v13) { return; }
    if v < 14 && !migrate_step(conn, 14, migrate_v14) { return; }
    if v < 15 && !migrate_step(conn, 15, migrate_v15) { return; }
    if v < 16 && !migrate_step(conn, 16, migrate_v16) { return; }
    if v < 17 && !migrate_step(conn, 17, migrate_v17) { return; }
    if v < 18 && !migrate_step(conn, 18, migrate_v18) { return; }
    if v < 19 && !migrate_step(conn, 19, migrate_v19) { return; }
    if v < 20 && !migrate_step(conn, 20, migrate_v20) { return; }
    if v < 21 && !migrate_step(conn, 21, migrate_v21) { return; }
    if v < 22 && !migrate_step(conn, 22, migrate_v22) { return; }
    if v < 23 && !migrate_step(conn, 23, migrate_v23) { return; }
    if v < 24 && !migrate_step(conn, 24, migrate_v24) { return; }
    if v < 25 && !migrate_step(conn, 25, migrate_v25) { return; }
    if v < 26 && !migrate_step(conn, 26, migrate_v26) { return; }
    if v < 27 && !migrate_step(conn, 27, migrate_v27) { return; }
    if v < 28 && !migrate_step(conn, 28, migrate_v28) { return; }
    if v < 29 && !migrate_step(conn, 29, migrate_v29) { return; }
    if v < 30 && !migrate_step(conn, 30, migrate_v30) { return; }
    if v < 31 && !migrate_step(conn, 31, migrate_v31) { return; }
    if v < 32 && !migrate_step(conn, 32, migrate_v32) { return; }
    if v < 33 {
        // v33 : ÉLARGIT event_rollup avec src_ip + host -> les panneaux « par src_ip / par host » lisent du
        // PRÉ-AGRÉGÉ (au lieu de scanner ~1,2M lignes chiffrées). SQLite ne sait pas ALTER une PK -> on
        // RECRÉE la table (event_rollup est DÉRIVÉE = reconstructible depuis event). CREATE..AS SELECT puis
        // DROP/RENAME (B-tree neuf, pas de réchiffrage page-par-page d'un ALTER). On repeuple sur la fenêtre
        // de rétention (PLUME_RETENTION_DAYS, défaut 30j).
        //
        // CARDINALITÉ src_ip — décision : src_ip peut EXPLOSER (scan réseau massif = 1M+ adresses/jour) et
        // ferait gonfler le rollup à des millions de lignes/jour, ruinant le gain. On BORNE DOUBLEMENT :
        // (1) seuil severity>=ROLLUP_SRCIP_MIN_SEV (défaut 3) -> sous le seuil, lump src_ip='' ;
        // (2) cap TOP-N par bucket (PLUME_ROLLUP_SRCIP_TOPN, défaut 50) -> même au-dessus du seuil, seules les
        // N IP les plus actives par heure sont gardées, le reste lumpé '' (cf. rollup_insert_sql_into). host
        // est de cardinalité faible (parc borné) -> toujours conservé. Cardinalité bornée même sous attaque.
        //
        // BACKFILL AVALÉ : la repopulation était avalée (let _ =) puis la version bumpée -> backfill perdu sans
        // retry. On ne bump la version QUE si CREATE+repopulation+DROP/RENAME réussissent ; sinon on logge
        // et on laisse la version à 32 -> la migration sera RE-TENTÉE au prochain boot (idempotente :
        // event_rollup_new recréée à blanc à chaque essai).
        let conf = load_config();
        let ev_days: i64 = cfg(&conf, "PLUME_RETENTION_DAYS", "30").parse().unwrap_or(30).max(1);
        let min_sev: i64 = cfg(&conf, "PLUME_ROLLUP_SRCIP_MIN_SEV", "3").parse().unwrap_or(3);
        let topn: i64 = rollup_srcip_topn(&conf);
        let cutoff = now() - ev_days * 86400;
        let repop = (|| -> Result<(), rusqlite::Error> {
            conn.execute("DROP TABLE IF EXISTS event_rollup_new", [])?; // table propre à chaque tentative
            // env_id (#2d/v67) est posé DÈS v33 sur base neuve : rollup_insert_sql_into peuple désormais
            // env_id, donc la table cible DOIT le porter. Sur une base déjà passée par v33 sans env_id,
            // c'est v67 qui l'ajoute (recréation préservant les données). Convergence garantie.
            conn.execute(
                "CREATE TABLE event_rollup_new(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
                 severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
                 host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
                 env_id TEXT NOT NULL DEFAULT 'prod', \
                 PRIMARY KEY(bucket,source,severity,action,src_ip,host,env_id))",
                [],
            )?;
            // Repopule depuis event raw, AVEC les deux bornes src_ip (seuil + cap top-N). Bornes = i64.
            conn.execute(&rollup_insert_sql_into("event_rollup_new", &format!("ts >= {cutoff}"), min_sev, topn), [])?;
            conn.execute("DROP TABLE IF EXISTS event_rollup", [])?;
            conn.execute("ALTER TABLE event_rollup_new RENAME TO event_rollup", [])?;
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rollup ON event_rollup(bucket)", [])?;
            Ok(())
        })();
        match repop {
            Ok(()) => {
                // watermark obsolète (ancien schéma) -> réinitialisé pour forcer une ré-agrégation propre.
                let _ = conn.execute("DELETE FROM meta WHERE key='event_rollup_wm'", []);
                let _ = conn.execute("UPDATE meta SET value='33' WHERE key='schema_version'", []);
                eprintln!("[migration] schéma -> v33 (event_rollup élargi src_ip+host ; src_ip borné sev>={min_sev} + top-{topn}/bucket)");
            }
            Err(e) => {
                // version NON bumpée -> retry au prochain boot (pas de backfill silencieusement perdu).
                // On ABANDONNE le reste de migrate() : sinon v34+ bumperaient la version >33 et v33 serait
                // sauté définitivement (v est lu une seule fois en tête). Au prochain boot, v=32 -> on
                // recommence à v33 (les migrations < 33 déjà appliquées sont no-op via leurs `if v<N`).
                eprintln!("[migration] v33 ÉCHEC repopulation event_rollup ({e}) — version laissée à 32, RE-TENTÉE au prochain démarrage (migrate interrompu)");
                return;
            }
        }
    }
    if v < 34 && !migrate_step(conn, 34, migrate_v34) { return; }
    if v < 35 && !migrate_step(conn, 35, migrate_v35) { return; }
    if v < 36 && !migrate_step(conn, 36, migrate_v36) { return; }
    if v < 37 && !migrate_step(conn, 37, migrate_v37) { return; }
    if v < 38 && !migrate_step(conn, 38, migrate_v38) { return; }
    if v < 39 && !migrate_step(conn, 39, migrate_v39) { return; }
    if v < 40 && !migrate_step(conn, 40, migrate_v40) { return; }
    if v < 41 && !migrate_step(conn, 41, migrate_v41) { return; }
    if v < 42 && !migrate_step(conn, 42, migrate_v42) { return; }
    if v < 43 && !migrate_step(conn, 43, migrate_v43) { return; }
    if v < 44 && !migrate_step(conn, 44, migrate_v44) { return; }
    if v < 45 && !migrate_step(conn, 45, migrate_v45) { return; }
    if v < 46 && !migrate_step(conn, 46, migrate_v46) { return; }
    if v < 47 && !migrate_step(conn, 47, migrate_v47) { return; }
    if v < 48 && !migrate_step(conn, 48, migrate_v48) { return; }
    if v < 49 && !migrate_step(conn, 49, migrate_v49) { return; }
    if v < 50 && !migrate_step(conn, 50, migrate_v50) { return; }
    if v < 51 && !migrate_step(conn, 51, migrate_v51) { return; }
    if v < 52 && !migrate_step(conn, 52, migrate_v52) { return; }
    if v < 53 && !migrate_step(conn, 53, migrate_v53) { return; }
    if v < 54 && !migrate_step(conn, 54, migrate_v54) { return; }
    if v < 55 && !migrate_step(conn, 55, migrate_v55) { return; }
    if v < 56 && !migrate_step(conn, 56, migrate_v56) { return; }
    if v < 57 && !migrate_step(conn, 57, migrate_v57) { return; }
    if v < 58 && !migrate_step(conn, 58, migrate_v58) { return; }
    if v < 59 && !migrate_step(conn, 59, migrate_v59) { return; }
    if v < 60 && !migrate_step(conn, 60, migrate_v60) { return; }
    if v < 61 && !migrate_step(conn, 61, migrate_v61) { return; }
    if v < 62 && !migrate_step(conn, 62, migrate_v62) { return; }
    if v < 63 && !migrate_step(conn, 63, migrate_v63) { return; }
    if v < 64 && !migrate_step(conn, 64, migrate_v64) { return; }
    if v < 65 && !migrate_step(conn, 65, migrate_v65) { return; }
    if v < 66 && !migrate_step(conn, 66, migrate_v66) { return; }
    if v < 67 {
        // v67 (#2d) : env_id sur les ROLLUPS pré-agrégés (event_rollup / event_dim_rollup) + INTÉGRATION à
        // la PK/agrégation -> le FILTRE par environnement est COHÉRENT partout : les requêtes raw (event a
        // déjà env_id v66) ET les agrégats (overview/freshness/dashboards, qui lisent les rollups) peuvent
        // filtrer par env. env_id est BASSE cardinalité (prod/staging/quelques sites) -> surcoût PK négligeable ;
        // les counts par (source[/dim]) restent EXACTS par environnement (dimension d'agrégation, cf.
        // rollup_insert_sql_into / dim_rollup_insert_sql qui peuplent désormais env_id).
        //
        // SQLite ne sait pas ALTER une PK -> on RECRÉE (tables DÉRIVÉES = reconstructibles). On PRÉSERVE les
        // lignes existantes en les stampant env_id='prod' (toute la donnée pré-v67 est prod : mode 0) -> AUCUN
        // re-scan de `event` (2,4 M lignes) au boot (leçon v33/v35 : un backfill synchrone bloque le bind ->
        // CrashLoop). L'env_id RÉEL apparaît ensuite sur la fenêtre chaude au 1er tick de rollup_events (qui
        // purge+ré-agrège toujours l'heure courante+précédente) ; les buckets historiques restent 'prod'
        // (correct). PAS de reset de watermark -> pas de rescan lourd. Idempotent : gardé par col_exists
        // (sur base neuve, event_rollup porte déjà env_id via la v33 mise à jour -> seule event_dim_rollup est
        // recréée). Sur ÉCHEC : version NON bumpée -> re-tentée au prochain boot (event_rollup_v67 droppée à
        // blanc à chaque essai) ; on ABANDONNE le reste de migrate() (v67 est la dernière migration).
        let recreate = |conn: &Connection, tbl: &str, cols: &str, tail_cols: &str, pk: &str, idx: &str| -> Result<(), rusqlite::Error> {
            if col_exists(conn, tbl, "env_id") {
                return Ok(()); // déjà porteur (base neuve via v33, ou re-run terminé) -> no-op
            }
            let tmp = format!("{tbl}_v67");
            // MIG-67 (robustesse fresh-install) : REPRISE d'une recréation interrompue par un crash dans la
            // fenêtre `DROP {tbl}` -> `RENAME {tmp}`. Dans cette fenêtre, {tbl} est DÉTRUITE mais {tmp} est
            // DÉJÀ PLEINEMENT peuplée (l'INSERT a réussi AVANT le DROP). L'ancien code re-DROPait {tmp} (perte)
            // puis lisait `FROM {tbl}` (disparue) -> échec PERMANENT (migration bloquée à v66 pour toujours).
            // Ici on TERMINE simplement le swap (rename + index) au lieu de repartir de zéro. Ne se déclenche
            // JAMAIS sur un run sain : sur base neuve/re-run {tbl} existe et {tmp} n'existe pas -> end-state v67
            // strictement IDENTIQUE (fresh-install atteint le même schéma).
            if !table_exists(conn, tbl) && table_exists(conn, &tmp) {
                conn.execute(&format!("ALTER TABLE {tmp} RENAME TO {tbl}"), [])?;
                conn.execute(idx, [])?;
                return Ok(());
            }
            conn.execute(&format!("DROP TABLE IF EXISTS {tmp}"), [])?; // table staging propre à chaque tentative
            conn.execute(&format!(
                "CREATE TABLE {tmp}({cols}, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY({pk}))"
            ), [])?;
            // copie stampée 'prod' (toute la donnée pré-v67 est prod) : préserve l'historique sans rescan event.
            conn.execute(&format!(
                "INSERT INTO {tmp}({tail_cols},env_id) SELECT {tail_cols},'prod' FROM {tbl}"
            ), [])?;
            conn.execute(&format!("DROP TABLE {tbl}"), [])?;
            conn.execute(&format!("ALTER TABLE {tmp} RENAME TO {tbl}"), [])?;
            conn.execute(idx, [])?;
            Ok(())
        };
        let done = (|| -> Result<(), rusqlite::Error> {
            recreate(
                conn, "event_rollup",
                "bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', severity INTEGER NOT NULL DEFAULT 0, \
                 action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '', \
                 n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0",
                "bucket,source,severity,action,src_ip,host,n,last_ts",
                "bucket,source,severity,action,src_ip,host,env_id",
                "CREATE INDEX IF NOT EXISTS idx_event_rollup ON event_rollup(bucket)",
            )?;
            recreate(
                conn, "event_dim_rollup",
                "bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', dim TEXT NOT NULL DEFAULT '', \
                 val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0",
                "bucket,source,dim,val,n",
                "bucket,source,dim,val,env_id",
                "CREATE INDEX IF NOT EXISTS idx_event_dim_rollup_q ON event_dim_rollup(source, dim, bucket)",
            )?;
            Ok(())
        })();
        match done {
            Ok(()) => {
                let _ = conn.execute("UPDATE meta SET value='67' WHERE key='schema_version'", []);
                eprintln!("[migration] schéma -> v67 (env_id sur event_rollup + event_dim_rollup : filtre par environnement cohérent agrégats+raw, #2d)");
            }
            Err(e) => {
                eprintln!("[migration] v67 ÉCHEC recréation rollups ({e}) — version laissée à 66, RE-TENTÉE au prochain démarrage (migrate interrompu)");
                return;
            }
        }
    }
    if v < 68 && !migrate_step(conn, 68, migrate_v68) { return; }
    if v < 69 && !migrate_step(conn, 69, migrate_v69) { return; }
    if v < 70 && !migrate_step(conn, 70, migrate_v70) { return; }
    if v < 71 && !migrate_step(conn, 71, migrate_v71) { return; }
    if v < 72 && !migrate_step(conn, 72, migrate_v72) { return; }
    if v < 73 && !migrate_step(conn, 73, migrate_v73) { return; }
    if v < 74 && !migrate_step(conn, 74, migrate_v74) { return; }
    if v < 75 && !migrate_step(conn, 75, migrate_v75) { return; }
    if v < 76 && !migrate_step(conn, 76, migrate_v76) { return; }
    if v < 77 {
        // v77 — HOST_ROLLUP : inventaire de FLOTTE pré-agrégé PAR HÔTE (backing de /api/fleet + /api/integrations).
        // BUG corrigé : les DEUX vues calculaient l'inventaire par `SELECT host,MAX(ts) FROM (event UNION ALL
        // metric UNION ALL snapshot) GROUP BY host` SANS borne temporelle -> idx_event_host (host-only, ne couvre
        // PAS ts) force un full-scan+déchiffrement des ~4,7 M lignes (~39 s) -> le watchdog 5 s du read-pool TUE
        // la requête -> `hosts` VIDE mis en cache (done=true codé en dur côté fleet) -> flotte FIGÉE à 0 hôte en
        // permanence. MÊME anti-pattern que la Fraîcheur (v64) : « jamais scanner event par requête au volume ».
        // FIX = petite table DÉRIVÉE `host_rollup` KEYÉE PAR HÔTE (cardinalité = taille de flotte, PAS volume
        // d'events) -> lecture sub-ms, watchdog jamais touché. MAINTENUE par rollup_hosts() (piggyback sur
        // rollup_events(), MÊME mécanique watermark que event_rollup) -> ZÉRO coût à l'ingest (ingest_events_batch
        // INCHANGÉ ; mode 0/data-plane byte-identique — aucune ligne event/metric/snapshot touchée). NON prunée
        // par la rétention (un hôte silencieux/mort reste VISIBLE : son last_ts colle). env_id (comme les rollups
        // v67) : mode 0 = tout 'prod', collapse sous GROUP BY host. ADDITIF & IDEMPOTENT (table DÉRIVÉE reconstruite
        // à blanc si le bloc re-tourne). Convergence base neuve/existante.
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS host_rollup(\
               host      TEXT NOT NULL,\
               env_id    TEXT NOT NULL DEFAULT 'prod',\
               last_ts   INTEGER NOT NULL DEFAULT 0,\
               first_ts  INTEGER NOT NULL DEFAULT 0,\
               sig_total INTEGER NOT NULL DEFAULT 0,\
               sig_hot   INTEGER NOT NULL DEFAULT 0,\
               updated   INTEGER,\
               PRIMARY KEY(host, env_id))",
            [],
        );
        // BACKFILL (seed des hôtes EXISTANTS) — UNE passe d'agrégation sur l'union (coût UNIQUE au boot, comme la
        // reconstruction event_rollup v33/v67 ; migrate() n'a PAS de watchdog -> tourne à terme). last_ts=MAX /
        // first_ts=MIN (immédiatement corrects, fenêtre chaude incluse) ; sig_total = count des heures DÉFINITIVES
        // [0, recent), sig_hot = count de la fenêtre CHAUDE [recent, now] -> cohérent avec l'invariant steady-state
        // de rollup_hosts (le watermark part à `recent`). DELETE d'abord -> re-jouable (rebuild à blanc de la table
        // dérivée) sans double-comptage. Bornes = i64 formatées (pas d'injection, comme rollup_events).
        let hn = now();
        let hrecent = ((hn / 3600) * 3600 - 3600).max(0);
        // BACKFILL AVALÉ — MIROIR de v33 : le backfill était `let _ =` (erreur avalée) PUIS la version
        // bumpée -> une INSERT en échec (SQLITE_NOMEM/FULL sur la grosse base) laissait host_rollup VIDE +
        // schema_version=77 (log « succès ») SANS retry -> les hôtes silencieux avant hrecent DISPARAISSAIENT
        // de /api/fleet + /api/integrations (la garantie « agent mort reste visible » VOLÉE). FIX : backfill dans
        // une closure FAILLIBLE (`?`) ; on ne bump la version + ne commit host_rollup_wm QUE si tout réussit ;
        // sinon on logge un ÉCHEC et on `return` (version laissée à 76 -> v77 RE-TENTÉE au prochain boot ;
        // DELETE-puis-INSERT idempotent = reconstruction à blanc de la table dérivée).
        let backfill = (|| -> Result<(), rusqlite::Error> {
            conn.execute("DELETE FROM host_rollup", [])?;
            conn.execute(
                &format!(
                    "INSERT INTO host_rollup(host, env_id, last_ts, first_ts, sig_total, sig_hot, updated) \
                     SELECT host, env_id, MAX(ts), MIN(ts), \
                            SUM(CASE WHEN ts <  {hrecent} THEN 1 ELSE 0 END), \
                            SUM(CASE WHEN ts >= {hrecent} THEN 1 ELSE 0 END), {hn} \
                     FROM (SELECT host,env_id,ts FROM event    WHERE host IS NOT NULL AND host<>'' \
                     UNION ALL SELECT host,env_id,ts FROM metric   WHERE host IS NOT NULL AND host<>'' \
                     UNION ALL SELECT host,env_id,ts FROM snapshot WHERE host IS NOT NULL AND host<>'') \
                     GROUP BY host, env_id"
                ),
                [],
            )?;
            conn.execute("DELETE FROM meta WHERE key='host_rollup_wm'", [])?;
            conn.execute("INSERT INTO meta(key,value) VALUES('host_rollup_wm', ?1)", params![hrecent.to_string()])?;
            Ok(())
        })();
        match backfill {
            Ok(()) => {
                let _ = conn.execute("UPDATE meta SET value='77' WHERE key='schema_version'", []);
                eprintln!("[migration] schéma -> v77 (host_rollup : inventaire flotte pré-agrégé par hôte -> /api/fleet + /api/integrations SANS scan event ; maintenu par rollup_hosts, non pruné, backfill des hôtes existants)");
            }
            Err(e) => {
                // version NON bumpée -> retry au prochain boot (pas de backfill silencieusement perdu). On ABANDONNE
                // le reste de migrate() (au prochain boot v=76 -> on recommence ; v78 attend que v77 réussisse).
                eprintln!("[migration] v77 ÉCHEC backfill host_rollup ({e}) — version laissée à 76, RE-TENTÉE au prochain démarrage (migrate interrompu)");
                return;
            }
        }
    }
    if v < 78 && !migrate_step(conn, 78, migrate_v78) { return; }
    if v < 79 && !migrate_step(conn, 79, migrate_v79) { return; }
    if v < 80 && !migrate_step(conn, 80, migrate_v80) { return; }
    if v < 81 && !migrate_step(conn, 81, migrate_v81) { return; }
    if v < 82 && !migrate_step(conn, 82, migrate_v82) { return; }
    if v < 83 && !migrate_step(conn, 83, migrate_v83) { return; }
    if v < 84 && !migrate_step(conn, 84, migrate_v84) { return; }
    if v < 85 && !migrate_step(conn, 85, migrate_v85) { return; }
    if v < 86 && !migrate_step(conn, 86, migrate_v86) { return; }
    if v < 87 && !migrate_step(conn, 87, migrate_v87) { return; }
    if v < 88 && !migrate_step(conn, 88, migrate_v88) { return; }
    if v < 89 && !migrate_step(conn, 89, migrate_v89) { return; }
    if v < 90 && !migrate_step(conn, 90, migrate_v90) { return; }
    if v < 91 && !migrate_step(conn, 91, migrate_v91) { return; }
    if v < 92 && !migrate_step(conn, 92, migrate_v92) { return; }
    if v < 93 && !migrate_step(conn, 93, migrate_v93) { return; }
    if v < 94 && !migrate_step(conn, 94, migrate_v94) { return; }
    if v < 95 && !migrate_step(conn, 95, migrate_v95) { return; }
    if v < 96 && !migrate_step(conn, 96, migrate_v96) { return; }
    if v < 97 && !migrate_step(conn, 97, migrate_v97) { return; }
    if v < 98 && !migrate_step(conn, 98, migrate_v98) { return; }
    if v < 99 && !migrate_step(conn, 99, migrate_v99) { return; }
    if v < 100 && !migrate_step(conn, 100, migrate_v100) { return; }
    if v < 101 && !migrate_step(conn, 101, migrate_v101) { return; }
    if v < 102 && !migrate_step(conn, 102, migrate_v102) { return; }
    if v < 103 && !migrate_step(conn, 103, migrate_v103) { return; }
    if v < 104 && !migrate_step(conn, 104, migrate_v104) { return; }
    if v < 105 && !migrate_step(conn, 105, migrate_v105) { return; }
    if v < 106 && !migrate_step(conn, 106, migrate_v106) { return; }
    if v < 107 && !migrate_step(conn, 107, migrate_v107) { return; }
    if v < 108 && !migrate_step(conn, 108, migrate_v108) { return; }
    if v < 109 && !migrate_step(conn, 109, migrate_v109) { return; }
    if v < 110 && !migrate_step(conn, 110, migrate_v110) { return; }
    if v < 111 && !migrate_step(conn, 111, migrate_v111) { return; }
}

/// v111 (BAN NATIF PLUME — chantier ② Phase 1) — store LIVE `net_ban` : IPs que le daemon bloque à SON niveau
/// HTTP (toutes ses routes, pour l'IP RÉELLE derrière Cloudflare), réversible, TTL (`expires_ts` NULL=permanent),
/// pilotable par l'API admin `/api/netban`. DISTINCT de `banned_ip` (analytique, miroir fail2ban/crowdsec/portscan
/// qui ne bloque RIEN). DDL PURE (CREATE TABLE/INDEX IF NOT EXISTS) idempotente -> sûre au boot (aucun scan de la
/// table `event` grasse ; posture différente de v102/v108 où c'était un CREATE INDEX lourd sur des millions de
/// lignes). ADDITIF, mode 0 byte-identique : table VIDE -> le cache in-mémoire est vide -> `net_ban_guard` est un
/// passthrough pur (aucune IP bloquée). Aussi déclarée dans `db/schema.sql` (doctrine « base = schema.sql » :
/// convergence base neuve / existante ; une base fraîche exécute schema.sql PUIS migrate v1..111 -> no-op).
///
/// ROLLBACK — bumpe le schéma à 111 : un binaire max=110 REFUSE d'ouvrir une base v111 (server.rs
/// open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err) -> restaurer le SNAPSHOT pré-migrate (initContainer).
/// Forward-only, idempotent (le CREATE IF NOT EXISTS re-tourné est no-op ; la version ré-écrit juste '111').
fn migrate_v111(conn: &MigTx) {
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS net_ban(\
         ip TEXT NOT NULL, reason TEXT, created_ts INTEGER, expires_ts INTEGER, \
         created_by TEXT, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(ip, env_id))",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_net_ban_ip ON net_ban(ip)", []);
    let _ = conn.execute("UPDATE meta SET value='111' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v111 (net_ban : ban natif HTTP plume, live-store DISTINCT de banned_ip analytique — chantier ② Phase 1)");
}

/// v108 (PERF — RECHERCHE RAW HAUT-VOLUME source=X sur fenêtre longue). MARQUEUR PUR (aucune DDL lourde
/// synchrone), MÊME posture EXACTE que v102 (idx_event_src). Comble l'index COMPOSITE MANQUANT
/// `idx_event_src_ts(source, ts)` sur la base MIGRÉE. `db/schema.sql` le déclare (bases NEUVES : table `event`
/// VIDE -> CREATE instantané) mais AUCUNE migration ne peut le créer ICI : un `CREATE INDEX` sur des MILLIONS
/// de lignes `event` chiffrées SQLCipher (auditd ~4M) au boot déchiffre+réécrit page par page et BLOQUE le bind
/// -> liveness k8s -> CrashLoopBackOff (leçon v102/v103/idx_event_category, migrate() tourne AVANT le bind).
/// Le CREATE est donc DÉLÉGUÉ à `ensure_event_src_ts_index_background`, lancé EN FOND APRÈS le bind (idempotent,
/// IF NOT EXISTS, MÊME nom que schema.sql -> aucun btree en double sur base neuve). Cette migration ne fait que
/// BUMPER la version -> ce qui DÉSYNCHRONISE 'analyze_full_done' (keyé sur schema_version) -> analyze_full_background
/// re-tourne UNE fois après bind -> sqlite_stat1 connaît le nouvel index (le planner le CHOISIT pour
/// `WHERE source=? AND ts>=?`).
///
/// POURQUOI (source, ts) : la recherche brute `search source=X earliest=-Nd` compile en `... FROM event WHERE
/// source=? AND ts>=?`. idx_event_src (source-seul, v102) SEEK source=X mais doit ensuite LIRE chaque ligne pour
/// filtrer/paginer sur ts ; le COMPOSITE couvre source+ts -> le COUNT BORNÉ de pagination (v/query.rs) devient
/// un balayage INDEX-ONLY (ZÉRO déchiffrement de la table grasse `message`/`fields`) plafonné, et la page
/// range-prune sur ts. source = TEXT court, faible cardinalité (~35) -> btree petit, disque, RAM négligeable
/// (budget 2 Go). ADDITIF, mode 0 byte-identique (l'index ne change AUCUNE sémantique de requête ; aucune donnée
/// modifiée). PURE optimisation (« optimiser, pas augmenter les ressources »).
///
/// ROLLBACK — bumpe le schéma à 108 : un binaire max=107 REFUSE d'ouvrir une base v108 (server.rs
/// open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err). Rollback = RESTAURER le SNAPSHOT pré-migrate
/// (initContainer). Forward-only, idempotent (le marqueur re-tourné ré-écrit juste value='108').
fn migrate_v108(conn: &MigTx) {
    let _ = conn.execute("UPDATE meta SET value='108' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v108 (marqueur : idx_event_src_ts(source,ts) créé EN FOND après bind, anti-crashloop ; re-ANALYZE ; COUNT pagination borné = index-only -> recherche raw source=X haut-volume sous budget)");
}

/// v109 (#16 COUCHE IA CONSEIL, Phase 1) — table `ai_provider` (miroir de `idp_provider`/v85). ADDITIF PUR,
/// VIDE -> mode 0 byte-identique (aucune ligne -> aucun endpoint IA n'agit ; +runtime `PLUME_AI_ENABLE`).
/// NON gated par la feature `ai` : le SCHÉMA ne doit pas dépendre des features de build (la table reste
/// inerte sans provider, exactement comme idp_provider). `secret` = SecretRef (jamais projeté). Idempotent,
/// forward-only. RENUMÉROTÉ v107->v109 : la branche différée `feat/ai-nl2soql` réservait v107 pour cette
/// migration, mais la ligne DÉPLOYÉE a pris v107 (saved_query) puis v108 (idx_event_src_ts) ; à l'intégration
/// la migration IA s'empile donc APRÈS le max courant (108) -> v109, jamais de collision. Sur base neuve
/// migrate stampe directement 109. ROLLBACK — bumpe le schéma à 109 : un binaire max=108 REFUSE d'ouvrir
/// une base v109 (server.rs open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err) -> restaurer le SNAPSHOT
/// pré-migrate (initContainer). Forward-only, idempotent.
/// v110 (ALLÈGEMENT INDEX HOT — P5). MARQUEUR PUR (aucune DDL synchrone), MÊME posture EXACTE que v102/v108 :
/// le TRAVAIL (DROP des index REDONDANTS) est délégué à `drop_redundant_event_indexes_background` (EN FOND
/// après le bind), cette migration ne fait que BUMPER la version -> ce qui DÉSYNCHRONISE 'analyze_full_done'
/// (keyé sur schema_version) -> analyze_full_background re-tourne UNE fois après bind, et sqlite_stat1 oublie
/// les deux index droppés (le planner re-coûte proprement les composites restants).
///
/// CE QUI EST RETIRÉ (2 index hot de `event`), chacun PRÉFIXE STRICT d'un composite qui le SUBSUME (règle
/// SQLite « préfixe » ; prouvé par EXPLAIN QUERY PLAN sur base réaliste — le retrait n'introduit AUCUN
/// full-scan, chaque seek garde un index de MÊME colonne de tête) :
///   idx_event_sev(severity) ⊂ idx_event_sev_srcip(severity, src_ip)  [migrate_v31, TOUJOURS présent sur
///       toute base ayant passé v31 -> garanti sur base neuve comme live] : `severity=?`/`severity>=?`
///       SEEK toujours severity via le composite. RETRAIT SÛR INCONDITIONNEL.
///   idx_event_src(source)   ⊂ idx_event_src_ts(source, ts) [v108]  ET  ⊂ idx_event_src_srcip(source, src_ip)
///       [v31] : `source=?` SEEK source via (source, ts) — le planner le choisissait DÉJÀ même quand
///       idx_event_src existait (idx_event_src était le contournement v102/v103 du planner qui ignorait
///       (source, src_ip) pour un `source=X` pur ; le composite (source, ts) de v108 le CHOISIT -> le
///       source-seul est devenu DEAD WEIGHT). RETRAIT GARDÉ par la présence de idx_event_src_ts côté fond
///       (jamais droppé avant que son remplaçant existe -> ZÉRO fenêtre de scan sur les gros flux auditd/k8s).
/// `db/schema.sql` ne DÉCLARE PLUS ces deux CREATE (base neuve = jamais créés). Le bg creator historique
/// `ensure_event_source_index_background` (qui RE-créait idx_event_src) est REMPLACÉ par le dropper -> plus
/// aucune recréation. DROP INDEX = cheap (libère les pages du btree, NE déchiffre PAS la table) -> sûr en fond
/// (contrairement à CREATE INDEX, la doctrine anti-crashloop ne s'applique pas). ADDITIF au sens sémantique :
/// AUCUNE requête ne change de résultat (un index redondant retiré n'altère jamais un résultat, seulement un
/// plan — et ici le plan reste un seek indexé). PURE optimisation disque (« optimiser, pas augmenter les ressources »).
///
/// ROLLBACK — bumpe le schéma à 110 : un binaire max=109 REFUSE d'ouvrir une base v110 (server.rs
/// open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err). Rollback = RESTAURER le SNAPSHOT pré-migrate
/// (initContainer) ; ré-armer les index = re-CREATE (réversible, aucune donnée touchée). Forward-only, idempotent.
fn migrate_v110(conn: &MigTx) {
    let _ = conn.execute("UPDATE meta SET value='110' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v110 (P5 allègement index hot : idx_event_sev + idx_event_src DROPPÉS EN FOND — préfixes redondants de idx_event_sev_srcip / idx_event_src_ts ; marqueur pur, re-ANALYZE ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

fn migrate_v109(conn: &MigTx) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ai_provider(
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            vendor      TEXT NOT NULL DEFAULT '',
            api_shape   TEXT NOT NULL DEFAULT 'openai',
            endpoint    TEXT NOT NULL DEFAULT '',
            secret      TEXT NOT NULL DEFAULT '',
            enabled     INTEGER NOT NULL DEFAULT 0,
            config_json TEXT NOT NULL DEFAULT '{}',
            created     INTEGER NOT NULL DEFAULT 0,
            updated     INTEGER NOT NULL DEFAULT 0
        );",
    );
    let _ = conn.execute("UPDATE meta SET value='109' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v109 (#16 IA conseil : table ai_provider ; additif, VIDE -> mode 0 byte-identique ; inerte sans provider+PLUME_AI_ENABLE ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

/// v104 (#3 INCIDENTS + RESPONSE WIZARD, Phase 1) — ADDITIF PUR, mode 0 byte-identique.
///  (1) 3 colonnes NULLABLES sur `incident` : `incident_tier` (NULL = case ordinaire, non-NULL = incident
///      DÉCLARÉ/élevé), `incident_type` (libellé libre du type d'incident), `commander` (pilote/assignée de
///      l'incident). SQLite ALTER ADD COLUMN sans DEFAULT réécrit -> NE TOUCHE AUCUNE ligne existante (toutes
///      restent incident_tier NULL = case ordinaire -> case_get_json/cases_list/client_case_* INCHANGÉS :
///      aucune requête existante ne lit ces colonnes). Idempotent (`let _ =` : ré-jouable, « duplicate column »
///      avalé).
///  (2) 3 tables ADDITIVES + VIDES (comme detection_override/workflow_action) : `runbook` (gabarit de runbook
///      keyé MITRE : match_kind tactic|technique|*), `runbook_step` (étapes ordonnées phasées : step_kind
///      manual|search|response ; les steps `response` RÉFÉRENCENT l'enum d'action FERMÉ, elles ne l'exécutent
///      pas — l'exécution reste /api/actions), `case_step` (progression PAR-INCIDENT : instancie/fige les steps
///      d'un runbook attaché à un case, status pending|done|skipped). VIDES -> aucune sémantique existante ->
///      un case sans incident_tier ni runbook attaché se comporte EXACTEMENT comme aujourd'hui.
/// Les 3 tables sont AUSSI dans db/schema.sql (doctrine « base = schema.sql » : convergence base neuve/existante ;
/// une base fraîche exécute schema.sql PUIS migrate v1..104 -> CREATE IF NOT EXISTS = no-op sur la table déjà
/// créée). Le SEED du contenu managé (seed_runbooks, managed=1) est SÉPARÉ (comme seed_detection_rules) et
/// idempotent par flag meta -> il tourne sur base neuve (migrate précède seeds) ET sur base déjà déployée
/// (tables créées vides par cette migration, flag `seeded_runbooks` absent -> seed insère). Aucun backfill de
/// donnée -> pas de garde d'échec/retry (contrairement à v33/v77). RESTE HORS de la projection client-read
/// (client_case_*) : aucune colonne/table n'y est ajoutée -> les incidents/runbooks NE FUITENT PAS au MSSP.
///
/// ROLLBACK — cette migration bumpe le schéma à 104 : un binaire v114 (max=103) REFUSE d'ouvrir une base v104
/// (server.rs:301 open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err). Un rollback de code exige donc de
/// RESTAURER le SNAPSHOT pré-migration (l'initContainer pre-migrate snapshotte AVANT migrate) — on ne peut pas
/// « dé-migrer » en place. Forward-only, idempotent.
/// v105 (#3 PHASE 3 — Part A : CIBLES DE RÉPONSE STRUCTURÉES). ADDITIF, nullable, best-effort. Trois colonnes
/// nullables portent l'ENTITÉ-CIBLE structurée d'une alerte (au lieu du seul `host` best-effort de Phase 1/2) :
///  - `alert.src_ip`   : IP source (attaquant) -> cible pré-remplie d'une step `ban_ip`/`unban_ip` du wizard.
///  - `alert.pid`      : PID (texte ; parsé/validé à l'exécution) -> cible pré-remplie d'une step `kill_pid`.
///  - `case_step.host` : hôte d'exécution figé sur une step `kill_pid` (un PID est inactionnable sans son hôte).
/// (`user` DÉLIBÉRÉMENT DIFFÉRÉ — A2 : aucune action_kind ne le consomme aujourd'hui.) Peuplées BEST-EFFORT à
/// la CRÉATION d'alerte par les DEUX moteurs row-aware (alerting.rs::run_advanced_rules quand le champ de
/// throttle EST src_ip/pid/host ; detection_advanced.rs correlation quand key_field EST src_ip/pid/host) ;
/// le moteur scalaire de base (detection.rs) n'a AUCUN contexte de ligne -> laisse NULL (repli blanc, comportement
/// analyste-tape-la-cible d'aujourd'hui). AUCUN backfill (colonnes NULL sur l'historique). AUCUNE modification
/// ingest/data-plane : l'entité est LUE du contexte déjà stocké au moment de l'alerte, pas replumbée. RESTE HORS
/// de la projection client-read (client_case_*) : ces colonnes vivent sur alert/case_step, jamais projetées au MSSP.
///
/// Idempotent par `col_exists` (re-jouable ; sur base neuve alert/case_step sont créés SANS ces colonnes par
/// schema.sql/v104 -> l'ALTER les ajoute ; miroir EXACT de la façon dont alert.host/alert.mitre vivent déjà en
/// migration-seule). INVARIANT ABSOLU mode 0 : colonnes NULLABLES sans DEFAULT réécrit -> SQLite ne touche AUCUNE
/// ligne existante, un case/une alerte ordinaire lit/écrit exactement comme aujourd'hui.
///
/// ROLLBACK — cette migration bumpe le schéma à 105 : un binaire max=104 REFUSE d'ouvrir une base v105
/// (server.rs open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err). Un rollback de code exige donc de RESTAURER le
/// SNAPSHOT pré-migration (l'initContainer pre-migrate snapshotte AVANT migrate) — on ne peut pas « dé-migrer » en
/// place. Forward-only, idempotent.
/// v106 (#4a CASE-OPS — DISPOSITION / VERDICT ANALYSTE). ADDITIF PUR, nullable, mode 0 byte-identique. Trois
/// colonnes NULLABLES sur `incident` capturent le VERDICT porté par l'analyste à la clôture (labels qui
/// s'accumulent pour un futur apprentissage supervisé — DIFFÉRÉ ; ce n'est PAS du ML, juste le modèle de donnée) :
///  - `disposition`    : le verdict FERMÉ ∈ {true_positive, false_positive, benign, duplicate} (NULL/'' = non-défini).
///  - `disposition_ts` : horodatage de la pose/du changement du verdict.
///  - `disposition_by` : utilisateur qui a posé le verdict (audité AUSSI au ledger via case.disposition).
/// SQLite ALTER ADD COLUMN sans DEFAULT réécrit -> NE TOUCHE AUCUNE ligne existante : toutes restent
/// disposition NULL (= non-défini) -> case_get_json/cases_list/client_case_* se comportent EXACTEMENT comme
/// aujourd'hui tant qu'aucun verdict n'est posé. VERDICT INTERNE : RESTE HORS de la projection client-read
/// (client_case_row) — jamais projeté au MSSP ([[plume-multitenant]] : contrat d'isolation client préservé).
/// Idempotent par `col_exists` (re-jouable). La table `incident` étant ENTIÈREMENT migration-only (cf. schema.sql
/// §incident #4a/#39), rien n'est ajouté à schema.sql — miroir exact de v104/v105.
///
/// ROLLBACK — bumpe le schéma à 106 : un binaire max=105 REFUSE d'ouvrir une base v106 (server.rs
/// open_and_migrate_db, `v > CODE_SCHEMA_MAX` -> Err). Rollback = RESTAURER le SNAPSHOT pré-migrate
/// (initContainer). Forward-only, idempotent.
/// v107 (SAVED QUERIES — outillage analyste per-user). UNE table NEUVE, VIDE -> ZÉRO effet tant qu'aucune
/// ligne (mode 0 byte-identique : aucun chemin de lecture/écriture ne la touche sans une requête
/// `/api/saved-queries` EXPLICITE de l'utilisateur). Modèle IDENTIQUE à `user_pref` (v99) / `user_mfa` (v68) :
/// table PAR-TENANT posée par migrate() (jamais dans schema.sql, comme user_pref/user_mfa/knowledge_*), donc en
/// mode 1 chaque base tenant a SA table -> un `alice` du tenant A et un `alice` du tenant B sont des LIGNES
/// distinctes dans des bases distinctes (isolation tenant STRUCTURELLE via req_db). `owner` = subject authentifié :
/// le handler ne lit/écrit QUE `WHERE owner = au.name` (list) et `WHERE id=? AND owner=?` (get/update/delete) ->
/// pas d'IDOR (l'id du client seul ne suffit JAMAIS à toucher la ligne d'autrui). `soql` = TEXTE de requête brut
/// (draft autorisé, jamais compilé au save : la compilation/validation/masquage a lieu UNIQUEMENT au run via le
/// chemin gardé /api/query). Ces requêtes sont de l'outillage INTERNE d'analyste -> JAMAIS exposées dans une
/// projection client-read multi-tenant. Additif pur (nullable/DEFAULT, aucune donnée existante touchée).
/// ROLLBACK = restaurer le snapshot pré-migrate (garde anti-downgrade : un binaire v106 REFUSE d'ouvrir une base
/// v107). NB : la branche différée `feat/ai-nl2soql` réservait v107 pour sa migration `ai_provider` — la ligne
/// DÉPLOYÉE prend v107 ici ; la migration NL->SOQL a été RENUMÉROTÉE en v109 à son intégration (après v108).
fn migrate_v107(conn: &MigTx) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS saved_query(
            id INTEGER PRIMARY KEY,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            soql TEXT NOT NULL DEFAULT '',
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS idx_saved_query_owner ON saved_query(owner, name);",
    );
    let _ = conn.execute("UPDATE meta SET value='107' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v107 (saved_query : requêtes SOQL nommées per-user, owner-scoped ; additif, VIDE -> mode 0 byte-identique ; outillage analyste INTERNE hors projection client ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

fn migrate_v106(conn: &MigTx) {
    let cols: &[(&str, &str, &str)] = &[
        ("incident", "disposition", "ALTER TABLE incident ADD COLUMN disposition TEXT"),
        ("incident", "disposition_ts", "ALTER TABLE incident ADD COLUMN disposition_ts INTEGER"),
        ("incident", "disposition_by", "ALTER TABLE incident ADD COLUMN disposition_by TEXT"),
    ];
    for (tbl, col, ddl) in cols {
        if !col_exists(conn, tbl, col) {
            let _ = conn.execute(ddl, []);
        }
    }
    let _ = conn.execute("UPDATE meta SET value='106' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v106 (#4a case-ops disposition/verdict analyste : incident.disposition/_ts/_by ; nullable/additif -> mode 0 byte-identique ; verdict INTERNE hors projection client ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

fn migrate_v105(conn: &MigTx) {
    let cols: &[(&str, &str, &str)] = &[
        ("alert", "src_ip", "ALTER TABLE alert ADD COLUMN src_ip TEXT"),
        ("alert", "pid", "ALTER TABLE alert ADD COLUMN pid TEXT"),
        ("case_step", "host", "ALTER TABLE case_step ADD COLUMN host TEXT"),
    ];
    for (tbl, col, ddl) in cols {
        if !col_exists(conn, tbl, col) {
            let _ = conn.execute(ddl, []);
        }
    }
    let _ = conn.execute("UPDATE meta SET value='105' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v105 (#3 P3-A cibles structurées : alert.src_ip/alert.pid + case_step.host ; nullable/additif -> mode 0 byte-identique ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

fn migrate_v104(conn: &MigTx) {
    // (1) colonnes incident (nullable, sans DEFAULT réécrit).
    let _ = conn.execute("ALTER TABLE incident ADD COLUMN incident_tier INTEGER", []);
    let _ = conn.execute("ALTER TABLE incident ADD COLUMN incident_type TEXT", []);
    let _ = conn.execute("ALTER TABLE incident ADD COLUMN commander TEXT", []);
    // (2) tables additives (miroir EXACT de db/schema.sql).
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS runbook(
            id INTEGER PRIMARY KEY,
            key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            match_kind TEXT NOT NULL DEFAULT '*',
            match_key TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            managed INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS runbook_step(
            id INTEGER PRIMARY KEY,
            runbook_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            phase TEXT NOT NULL,
            title TEXT NOT NULL,
            guidance TEXT NOT NULL DEFAULT '',
            step_kind TEXT NOT NULL DEFAULT 'manual',
            search_soql TEXT,
            action_kind TEXT
         );
         CREATE TABLE IF NOT EXISTS case_step(
            id INTEGER PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            runbook_id INTEGER NOT NULL,
            step_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            phase TEXT NOT NULL,
            title TEXT NOT NULL,
            guidance TEXT NOT NULL DEFAULT '',
            step_kind TEXT NOT NULL DEFAULT 'manual',
            search_soql TEXT,
            action_kind TEXT,
            target TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            actor TEXT,
            ts INTEGER,
            note TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_runbook_match ON runbook(match_kind, match_key);
         CREATE INDEX IF NOT EXISTS idx_runbook_step_rb ON runbook_step(runbook_id, ordinal);
         CREATE INDEX IF NOT EXISTS idx_case_step_inc ON case_step(incident_id, ordinal);",
    );
    let _ = conn.execute("UPDATE meta SET value='104' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v104 (#3 incidents : incident_tier/type/commander + runbook/runbook_step/case_step ; additif, VIDE -> mode 0 byte-identique ; ROLLBACK = restaurer le snapshot pré-migrate)");
}

/// v103 (P-HEC) — LIE une clé de livraison push (`token.kind='firehose'`) à SON connecteur push
/// (`token.connector_id` -> `connector.id`). ADDITIF metadata-only : un seul `ALTER TABLE token ADD COLUMN`
/// (NULLABLE, sans DEFAULT réécrit -> SQLite ne touche AUCUNE ligne existante). Idempotent (`let _ =` : re-jouable ;
/// la colonne existe déjà -> ALTER échoue silencieusement). Toutes les lignes token PRÉ-v103 gardent
/// connector_id NULL -> aucune n'est une clé Firehose (kind!='firehose'), donc firehose_token_lookup les rejette
/// (fail-closed). Mode 0 byte-identique (aucune sémantique d'auth existante changée : token_lookup exclut déjà
/// kind='firehose').
fn migrate_v103(conn: &MigTx) {
    let _ = conn.execute("ALTER TABLE token ADD COLUMN connector_id INTEGER", []);
    let _ = conn.execute("UPDATE meta SET value='103' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v103 (P-HEC : token.connector_id — clé de livraison push liée à son connecteur)");
}

/// v102 (CHANGE 4) — MARQUEUR pur (aucune DDL synchrone). Comble l'index MANQUANT idx_event_src (source-seul) sur
/// la base MIGRÉE. `db/schema.sql` le déclare déjà (bases neuves OK) mais AUCUNE migration ne l'a créé -> la base
/// live (montée par migrations) full-scanne `search source=X | ...` sur les GROS flux (auditd ~4M, k8s-log ~851k :
/// le composite idx_event_src_srcip(source,src_ip) est souvent ignoré par le planner pour un `source=X` pur) ->
/// budget requête 5s dépassé. Le CREATE n'est PAS fait ICI : un CREATE INDEX synchrone sur des millions de lignes
/// chiffrées bloque le bind -> liveness k8s -> CrashLoopBackOff (cf. idx_event_category). Il est
/// délégué à ensure_event_source_index_background, lancé EN FOND APRÈS le bind (idempotent, IF NOT EXISTS, même nom
/// que schema.sql -> pas de btree en double sur base neuve). Bumper la version DÉSYNCHRONISE 'analyze_full_done'
/// -> analyze_full_background re-tourne UNE fois après bind -> sqlite_stat1 connaît l'index (le planner le choisit).
/// source = TEXT court, faible cardinalité (~35 valeurs) -> index peu coûteux (RAM maîtrisée, budget 2 Go).
/// Additif, mode 0 byte-identique (aucune donnée modifiée, l'index ne change AUCUNE sémantique de requête).
fn migrate_v102(conn: &MigTx) {
    // CHANGE 5 (v103) — PURGE ONE-TIME de 5 sources-RÉSIDU gelées (artefacts de test/POC/probe restés en base,
    // 9 lignes event au total). MÊME pattern que la purge de sondes v48 (§4) : DELETE event + les DEUX rollups
    // (clés portant `source`). Gardé par `if v < 102` -> tourne UNE fois ; base neuve = aucune de ces lignes ->
    // no-op ; base déjà purgée (v>=102) -> ne re-tourne pas. On NE purge PAS par category='' (VÉRIFIÉ : 82 lignes
    // "catégorie vide" sont des sources LIVE légitimes — agent=81, web=1) ni `su` (source idle légitime) ni
    // category='test' par prédicat (cette unique ligne EST '__probe_moat', déjà couverte par la liste de sources).
    for s in ["plumeperftest228", "poc-recon", "slice7fw", "fortigate", "__probe_moat"] {
        let _ = conn.execute("DELETE FROM event WHERE source=?1", params![s]);
        let _ = conn.execute("DELETE FROM event_rollup WHERE source=?1", params![s]);
        let _ = conn.execute("DELETE FROM event_dim_rollup WHERE source=?1", params![s]);
    }
    // CHANGE 6 (v103) — DÉSACTIVE RÉTROACTIVEMENT le doublon 5xx-par-IP (T1190) sur la base LIVE. Le seed
    // (seed_purple_rules) pose désormais enabled=0, mais UNIQUEMENT sur base neuve : sur prod le flag meta
    // `seeded_purple_rules` est déjà posé -> seed_purple_rules court-circuite (return) -> la ligne existante
    // reste enabled=1. Ce UPDATE one-time (gardé par `if v < 102`) flippe la ligne live. Match sur name ET
    // mitre pour ne toucher QUE id 22 (jamais id 21=404-origin T1595.002 ni id 20=port-scan T1046). Style
    // `let _ =` idempotent des purges v48/CHANGE 5 : no-op sur base neuve (déjà enabled=0) ou si absente.
    let _ = conn.execute(
        "UPDATE rule SET enabled=0 WHERE name='Anomalie exploit web : pic de 5xx par IP (10 min)' AND mitre='T1190'",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='102' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v102 (marqueur : idx_event_src créé EN FOND après bind, anti-crashloop ; re-ANALYZE ; + purge one-time 5 sources-résidu gelées)");
}

/// v101 (#1c-toggle) — table `detection_override(kind,name,enabled,updated,updated_by)`, ADDITIVE et VIDE.
/// Persiste la décision ADMIN d'(dés)activer une règle/parseur/playbook OVERLAY (managed=1) : réappliquée
/// PAR-DESSUS l'overlay config.d au boot (apply_content_overrides) -> l'`enabled` du fichier git ne ré-impose
/// plus l'état, le choix de l'admin SURVIT au reboot. Miroir de la doctrine « base = schema.sql » (la table
/// est AUSSI dans db/schema.sql) : CREATE IF NOT EXISTS idempotent, convergence base neuve/existante. VIDE ->
/// aucun override -> apply_content_overrides ne touche 0 ligne -> boot BYTE-IDENTIQUE (mode 0). Ne porte que
/// `enabled` (jamais query/is_soql) -> aucune surface d'élévation SQL brut.
fn migrate_v101(conn: &MigTx) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS detection_override(
            kind TEXT NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL,
            updated INTEGER NOT NULL DEFAULT 0, updated_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(kind, name)
         );",
    );
    let _ = conn.execute("UPDATE meta SET value='101' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v101 (#1c-toggle detection_override : (dés)activation admin des overlays config.d, survit au reboot ; additif, VIDE -> mode 0 byte-identique)");
}

/// v100 — BACKFILL des règles de self-detection (identité / config-tamper /
/// RBAC-deny / export-de-masse) sur l'instance DÉJÀ DÉPLOYÉE. MÊME mécanique EXACTE que le backfill v75
/// (engagement) : on n'INSÈRE QUE si le seed a déjà tourné (`seeded_detection_rules` présent = instance live
/// où seed_detection_rules ne re-crée plus) ; sur PVC NEUF migrate() précède les seeds -> flag absent -> SKIP,
/// et seed_detection_rules pose les règles -> zéro doublon. Idempotent (« n'existe pas déjà par nom »).
/// event-driven : ces règles restent INERTES tant qu'aucun event plume-config/authz/audit n'est écrit
/// (mode 0 byte-identique). Source unique : DETECTION_RULES_SEC4.
fn migrate_v100(conn: &MigTx) {
    let seeded = conn.query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(())).is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_SEC4 {
            let exists = conn.query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(())).is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='100' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v100 (self-detection : identité/config-tamper/RBAC-deny/export-de-masse ; event-driven -> INERTE au repos, mode 0 byte-identique)");
}

/// v99 (#62 UI P1 — PRÉFÉRENCES UTILISATEUR self-scoped). UNE table NEUVE, VIDE -> ZÉRO effet tant qu'aucune
/// ligne (mode 0 byte-identique : aucun chemin de lecture/écriture ne la touche sans une requête `/api/prefs`
/// EXPLICITE de l'utilisateur). Modèle IDENTIQUE à `user_mfa` (v68) : table PAR-TENANT posée par migrate()
/// (jamais dans schema.sql, comme user_mfa/knowledge_*), donc en mode 1 chaque base tenant a SA table -> un
/// user `alice` du tenant A et un `alice` du tenant B sont des LIGNES DISTINCTES dans des bases distinctes
/// (isolation tenant STRUCTURELLE via req_db). Clé = `user` (self-scoping : le handler ne lit/écrit QUE
/// `WHERE user = au.name`, jamais un id fourni par le client). `prefs` = blob JSON UI-ONLY (visibilité/ordre
/// de colonnes, favoris de dashboards, plage temporelle par défaut, réglages par vue) — JAMAIS de secret,
/// JAMAIS rien qui change l'autorisation ; taille plafonnée côté handler (64 KiB). Additif pur.
fn migrate_v99(conn: &MigTx) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_pref(
            user TEXT PRIMARY KEY,
            prefs TEXT NOT NULL DEFAULT '{}',
            updated INTEGER NOT NULL DEFAULT 0
         );",
    );
    let _ = conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v99 (#62 user_pref : préférences UI self-scoped ; additif, VIDE -> mode 0 byte-identique)");
}

/// v98 (#39 TEAM CASE-OPS — readiness P1 : merge/link, MULTI-LEVEL SLA, MTTA/MTTR, per-assignee queues,
/// client-read API). ADDITIF & INERTE : deux tables NEUVES (VIDES) + colonnes NULLABLES/DEFAULT 0 sur
/// `incident`. INVARIANT ABSOLU mode 0 :
///   - `sla_policy` VIDE -> `sla_policy_for()` renvoie None -> ack_due/resolve_due restent NULL, la boucle
///     `sla_multilevel_tick` sélectionne 0 ligne (early-return, comme escalate_overdue_cases) : ZÉRO travail,
///     ZÉRO écriture. Le SLA LEGACY (`sla_due`/`escalated`, v69) est STRICTEMENT INCHANGÉ.
///   - `case_link` VIDE -> aucune association ; `incident.merged_into` NULL -> aucun case fusionné : les listes
///     et `case_get_json` se comportent EXACTEMENT comme avant (le filtre `merged_into IS NULL` par défaut ne
///     retire rien tant qu'aucune fusion n'a eu lieu).
///  Colonnes ajoutées par `col_exists` (re-jouable / idempotent), mêmes garanties que v69/v70.
fn migrate_v98(conn: &MigTx) {
    // 1) MULTI-LEVEL SLA : politiques configurables par priorité (ack + resolve distincts). VIDE = SLA legacy.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sla_policy(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            priority INTEGER NOT NULL,           -- tier : 1=critique .. 4=bas (match sur incident.priority)
            ack_target_s INTEGER NOT NULL,       -- délai d'ACQUITTEMENT cible (s) — MTTA
            resolve_target_s INTEGER NOT NULL,   -- délai de RÉSOLUTION cible (s) — MTTR
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,  -- doctrine #55 (2 = ad-hoc UI)
            created INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            updated INTEGER NOT NULL DEFAULT 0,
            UNIQUE(priority)                      -- une politique ACTIVE par tier (le CRUD upsert par priorité)
         );
         -- 2) LIENS de cases (association NON DESTRUCTIVE, distincte de la fusion). Symétrie logique gérée au
         --    read (on interroge src OU dst). kind : 'related' | 'duplicate' | 'blocks'.
         CREATE TABLE IF NOT EXISTS case_link(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_id INTEGER NOT NULL,
            dst_id INTEGER NOT NULL,
            kind TEXT NOT NULL DEFAULT 'related',
            note TEXT NOT NULL DEFAULT '',
            created INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            UNIQUE(src_id, dst_id, kind)
         );
         CREATE INDEX IF NOT EXISTS idx_case_link_src ON case_link(src_id);
         CREATE INDEX IF NOT EXISTS idx_case_link_dst ON case_link(dst_id);",
    );
    // 3) Colonnes ADDITIVES sur `incident` (idempotent via col_exists) :
    //  - merged_into      : id du case CIBLE d'une fusion (NULL = non fusionné ; la source est CONSERVÉE, jamais
    //                       supprimée -> soft-merge auditable/réversible-enough #39). Masqué de la liste active.
    //  - ack_due          : échéance d'ACQUITTEMENT SLA multi-niveau (NULL tant qu'aucune politique) — MTTA.
    //  - resolve_due      : échéance de RÉSOLUTION SLA multi-niveau (NULL tant qu'aucune politique) — MTTR.
    //  - ack_breached / resolve_breached : anti re-notif (0/1), posés par le tick multi-niveau, immutables.
    //  - sla_paused_since : epoch du DÉBUT de pause du chrono SLA (NULL = en cours) — pause/reprise par statut.
    //  - sla_pause_accum  : total (s) de pause ACCUMULÉE — décale ack_due/resolve_due sans TOUCHER `ts` (le
    //                       calcul de breach reste ancré sur des timestamps IMMUABLES + ce cumul).
    //  - sla_policy_id    : politique appliquée (audit ; NULL = SLA legacy).
    let cols: &[(&str, &str)] = &[
        ("merged_into", "ALTER TABLE incident ADD COLUMN merged_into INTEGER"),
        ("ack_due", "ALTER TABLE incident ADD COLUMN ack_due INTEGER"),
        ("resolve_due", "ALTER TABLE incident ADD COLUMN resolve_due INTEGER"),
        ("ack_breached", "ALTER TABLE incident ADD COLUMN ack_breached INTEGER NOT NULL DEFAULT 0"),
        ("resolve_breached", "ALTER TABLE incident ADD COLUMN resolve_breached INTEGER NOT NULL DEFAULT 0"),
        ("sla_paused_since", "ALTER TABLE incident ADD COLUMN sla_paused_since INTEGER"),
        ("sla_pause_accum", "ALTER TABLE incident ADD COLUMN sla_pause_accum INTEGER NOT NULL DEFAULT 0"),
        ("sla_policy_id", "ALTER TABLE incident ADD COLUMN sla_policy_id INTEGER"),
    ];
    for (col, ddl) in cols {
        if !col_exists(conn, "incident", col) {
            let _ = conn.execute(ddl, []);
        }
    }
    // Index PARTIEL : la liste active filtre `merged_into IS NULL` (la grande majorité) + le tick SLA balaie
    // ack_due/resolve_due non NULL (0 ligne tant qu'aucune politique).
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_notmerged ON incident(updated) WHERE merged_into IS NULL", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_slaml ON incident(ack_due, resolve_due) WHERE ack_due IS NOT NULL OR resolve_due IS NOT NULL", []);
    let _ = conn.execute("UPDATE meta SET value='98' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v98 (#39 team case-ops : sla_policy + case_link + incident.merged_into/ack_due/resolve_due/breach/pause ; additif, VIDE -> mode 0 byte-identique, SLA legacy inchangé)");
}

fn migrate_v97(conn: &MigTx) {
    // v97 (#60 KNOWLEDGE OBJECTS — reliquat DIFFÉRÉ de #46 : MACROS, AUTO-LOOKUPS/GeoIP, SCHEDULED REPORTS,
    //  WORKFLOW ACTIONS). QUATRE tables NEUVES, VIDES à la création -> ZÉRO effet tant qu'aucune ligne :
    //   - macro_def / auto_lookup se chargent dans le `KnowledgeSet` du tenant (via `knowledge_reload`). VIDE
    //     -> `KnowledgeSet` sans macro/auto-lookup -> le compilateur SOQL émet le SQL legacy À L'IDENTIQUE
    //     (mode 0 byte-identique, prouvé côté cœur par les tests `macro_mode0_*`/`auto_lookup_mode0_*`).
    //   - scheduled_report : tick de fond `run_due_reports` sélectionne 0 ligne -> no-op strict (aucun réseau).
    //   - workflow_action : métadonnées de menu contextuel console (navigation/URL/réponse) ; PUREMENT
    //     déclaratives, aucune injection dans le compilateur ni le moteur de réponse (kind='response' ne fait
    //     que RÉFÉRENCER l'enum d'action fermé ban/kill/stop — l'exécution reste le chemin /api/actions approuvé).
    //  Additif pur (aucune table existante touchée). `managed` DEFAULT 2 (= ad-hoc UI ; doctrine #55).
    //  >>> RENUMÉROTATION : si une migration v97 concurrente atterrit d'abord, renuméroter celle-ci en v98.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS macro_def(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            params TEXT NOT NULL DEFAULT '',   -- liste de paramètres séparés par ',' (idents SOQL)
            body TEXT NOT NULL DEFAULT '',      -- fragment SOQL avec placeholders $param$
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS auto_lookup(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,                 -- nom de la table lookup_kv à joindre
            key_field TEXT NOT NULL,            -- champ-clé événement (résolu via soql_field -> masqué #45)
            out_cols TEXT NOT NULL DEFAULT '',  -- colonnes de sortie séparées par ',' (vide -> val brut)
            kind TEXT NOT NULL DEFAULT 'lookup',-- 'lookup' | 'geoip' (label ; mécanique identique)
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            UNIQUE(name, key_field)
         );
         CREATE TABLE IF NOT EXISTS scheduled_report(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            dataset_id INTEGER NOT NULL,        -- FK dataset (#47) : le SOQL stocké à exécuter
            notifier_id INTEGER NOT NULL,       -- FK notifier (#53) : le canal de livraison (config admin)
            run_as_role TEXT NOT NULL DEFAULT 'viewer', -- IDENTITÉ d'exécution : le résultat est MASQUÉ par CE rôle
            tenant TEXT NOT NULL DEFAULT '',     -- TENANT du créateur : les field-filters tenant-scopés sont résolus DESSUS (parité /api/query)
            interval_s INTEGER NOT NULL DEFAULT 86400,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run INTEGER NOT NULL DEFAULT 0,
            last_ok INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            last_count INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS workflow_action(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL DEFAULT '',
            scope_field TEXT NOT NULL DEFAULT '*', -- champ auquel l'action s'attache ('*' = tout champ)
            kind TEXT NOT NULL DEFAULT 'search',   -- 'search' (SOQL navig.) | 'url' (navig.) | 'response' (enum)
            target TEXT NOT NULL DEFAULT '',       -- gabarit avec $field$ (search/url) OU ban|kill|stop (response)
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );",
    );
    let _ = conn.execute("UPDATE meta SET value='97' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v97 (#60 KO reliquat : macro_def + auto_lookup + scheduled_report + workflow_action ; additif, VIDES -> mode 0 byte-identique tant qu'aucune ligne)");
}

fn migrate_v96(conn: &MigTx) {
    // v96 (#59 GOUVERNANCE ENTREPRISE — reliquat DIFFÉRÉ de #38). DEUX tables PER-TENANT, VIDES à la
    //  création -> ZÉRO effet tant qu'aucune ligne (mode 0 byte-identique ; prouvé par les tests de parité
    //  `gov_mode0_*`). Aucune table existante n'est touchée (additif pur).
    //   - legal_hold  : RÉTENTION-LOCK / LEGAL-HOLD. Une ligne active ÉPINGLE les events dont la portée
    //                   (source + fenêtre temporelle) matche CONTRE toute suppression par retention_run
    //                   (global + per-index + plafonds). Enforcement FAIL-CLOSED : si l'état des holds ne peut
    //                   être déterminé, retention_run S'ABSTIENT de purger `event` (cf. rollups.rs). VIDE ->
    //                   aucun prédicat ajouté aux DELETE -> texte SQL byte-identique à l'historique.
    //   - ledger_sink : SINK d'EXPORT STREAMING du ledger (chaîne préservée). Config d'une destination
    //                   append-only (file/stdout/webhook/syslog) + CURSEUR incrémental (last_id/last_hash).
    //                   L'export est READ-ONLY sur `ledger` (aucun chemin de mutation vers le ledger) ; il ÉMET
    //                   la chaîne complète (prev_hash/hash) pour qu'un vérificateur externe détecte toute
    //                   altération. VIDE -> aucun export -> inerte.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS legal_hold(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            reason TEXT NOT NULL DEFAULT '',
            scope_source TEXT NOT NULL DEFAULT '',
            scope_start_ts INTEGER NOT NULL DEFAULT 0,
            scope_end_ts INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            released_ts INTEGER NOT NULL DEFAULT 0,
            released_by TEXT NOT NULL DEFAULT ''
         );
         CREATE INDEX IF NOT EXISTS idx_legal_hold_active ON legal_hold(active);
         CREATE TABLE IF NOT EXISTS ledger_sink(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL DEFAULT 'file',
            target TEXT NOT NULL DEFAULT '',
            secret_ref TEXT NOT NULL DEFAULT '',
            format TEXT NOT NULL DEFAULT 'jsonl',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_id INTEGER NOT NULL DEFAULT 0,
            last_hash TEXT NOT NULL DEFAULT '',
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            updated_by TEXT NOT NULL DEFAULT ''
         );",
    );
    let _ = conn.execute("UPDATE meta SET value='96' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v96 (#59 gouvernance : tables legal_hold + ledger_sink ; additif, VIDES -> mode 0 byte-identique tant qu'aucun hold/sink n'est défini)");
}

fn migrate_v95(conn: &MigTx) {
    // v95 (#47 DATA MODELS + PIVOT + DATASETS — couche SÉMANTIQUE au-dessus du CIM, façon Splunk data
    //  models). QUATRE tables NEUVES, VIDES à la création -> ZÉRO effet tant qu'aucune ligne : aucun de
    //  ces objets n'est INJECTÉ dans le compilateur SOQL (contrairement aux knowledge objects #46). Un data
    //  model ne PARTICIPE à la compilation QUE lorsqu'un Pivot/dataset est explicitement invoqué ; le chemin
    //  de recherche standard (Explore/panels/règles) est INCHANGÉ -> mode 0 byte-identique (le compilateur du
    //  cœur n'est pas touché ; prouvé côté cœur par `tests/plume_parity.rs` et côté daemon par
    //  `datamodels_mode0_byte_identical`). Additif pur (aucune table existante touchée). `managed` DEFAULT 2
    //  (= ad-hoc UI), aligné sur la doctrine #55 (0=builtin/seed, 1=overlay config.d, 2=ad-hoc UI).
    //   - data_model         : modèle sémantique nommé (optionnellement rattaché à une `category` CIM) ;
    //   - data_model_object  : objet HIÉRARCHIQUE (parent_id) + `constraint` (fragment de filtre SOQL,
    //                          compile-vérifié à la création) ; un enfant HÉRITE des contraintes du parent ;
    //   - data_model_field   : champ TYPÉ d'un objet (`type` string/number/ipv4/timestamp/boolean ; `expr`
    //                          optionnelle -> peut référencer un alias/champ-calculé #46). ALLOWLIST du Pivot :
    //                          un Pivot ne peut split-by/filtrer QUE des champs déclarés ici (mais le masque
    //                          #45 s'applique PAR-DESSUS via `soql_field`/`soql_filter_field`) ;
    //   - dataset            : définition de résultat SAUVEGARDÉE réutilisable (kind='pivot' -> `spec` JSON +
    //                          `object_id` ; kind='search' -> `soql` figé). Compile TOUJOURS via le chemin
    //                          SOQL masqué normal (jamais de SQL brut).
    //  >>> RENUMÉROTATION : si une migration v95 concurrente atterrit d'abord, renuméroter celle-ci en v96.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS data_model(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS data_model_object(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            parent_id INTEGER,
            constraint_soql TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            UNIQUE(model_id, name)
         );
         CREATE INDEX IF NOT EXISTS idx_dm_object_model ON data_model_object(model_id);
         CREATE TABLE IF NOT EXISTS data_model_field(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            ftype TEXT NOT NULL DEFAULT 'string',
            expr TEXT NOT NULL DEFAULT '',
            created INTEGER NOT NULL DEFAULT 0,
            UNIQUE(object_id, name)
         );
         CREATE INDEX IF NOT EXISTS idx_dm_field_object ON data_model_field(object_id);
         CREATE TABLE IF NOT EXISTS dataset(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL DEFAULT 'search',
            soql TEXT NOT NULL DEFAULT '',
            object_id INTEGER,
            spec TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );",
    );
    let _ = conn.execute("UPDATE meta SET value='95' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v95 (#47 data models + pivot + datasets : tables data_model/data_model_object/data_model_field/dataset ; additif, VIDES -> mode 0 byte-identique tant qu'aucun Pivot/dataset n'est invoqué)");
}

fn migrate_v94(conn: &MigTx) {
    // v94 (#46 KNOWLEDGE OBJECTS — objets de savoir SEARCH-TIME PERSISTÉS, parité Splunk / portabilité de
    //  contenu). QUATRE tables NEUVES, VIDES à la création -> ZÉRO effet tant qu'aucune ligne : le résolveur
    //  `knowledge_reload` produit un `KnowledgeSet` VIDE -> le compilateur SOQL émet le SQL legacy À
    //  L'IDENTIQUE (mode 0 byte-identique, invariant absolu — prouvé côté cœur par `tests/plume_parity.rs`).
    //  Additif pur (aucune table existante touchée). `managed` DEFAULT 2 (= ad-hoc UI), aligné sur la
    //  doctrine #55 (0=builtin/seed, 1=overlay config.d, 2=ad-hoc UI) pour un overlay config.d ULTÉRIEUR.
    //   - knowledge_alias   : `canonical -> source` (une recherche sur le canonique résout la source) ;
    //   - knowledge_calc    : `name = <expr eval>` (champ calculé search-time, ORDONNÉ par `ord`) ;
    //   - knowledge_eventtype : `name` + filtre SOQL (`eventtype=name` compile le filtre stocké) ;
    //   - knowledge_tag     : `label` sur une paire `field=value` (`tag=label` = OR des paires du label).
    //  >>> RENUMÉROTATION : si une migration v94 concurrente atterrit d'abord, renuméroter celle-ci en v95.
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS knowledge_alias(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            canonical TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS knowledge_calc(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            expr TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            ord INTEGER NOT NULL DEFAULT 0,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS knowledge_eventtype(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            filter TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS knowledge_tag(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            managed INTEGER NOT NULL DEFAULT 2,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0
         );
         CREATE INDEX IF NOT EXISTS idx_knowledge_tag_label ON knowledge_tag(label);",
    );
    let _ = conn.execute("UPDATE meta SET value='94' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v94 (#46 knowledge objects : tables knowledge_alias/calc/eventtype/tag ; additif, VIDES -> mode 0 byte-identique tant qu'aucun KO n'est défini)");
}

fn migrate_v93(conn: &MigTx) {
    // v93 (#55 OBSERVABILITY-AS-CODE — les OBJETS DE CONFIG du SOC deviennent DÉCLARABLES en fichiers
    //  config.d versionnés, comme le sont déjà rules/parsers/playbooks/sigma). ADDITIF & INERTE en mode 0 :
    //  cette migration n'AJOUTE qu'une colonne `managed` (+ un `name` sur notification_policy) aux tables
    //  d'objets de config qui n'en avaient pas -> ZÉRO overlay livré = ZÉRO ligne managed=1 = comportement
    //  BYTE-IDENTIQUE (le loader overlays_oac ne fait rien sans fichier). Sémantique de `managed` = celle,
    //  repo-wide, de rule/parser/index_policy : 0 = builtin/seed, 1 = overlay config.d (source git, verrouillé
    //  en UI + prunable), 2 = ad-hoc UI (CRUD destructif). DEFAULT 2 -> les objets EXISTANTS (créés en UI ou
    //  semés) sont marqués « ad-hoc UI » : jamais clobbérés par un overlay de même nom (le loader SAUTE un
    //  managed=2), jamais prunés (le prune ne touche que managed=1). Idempotent : ALTER guardé par col_exists
    //  (re-jouable ; sur base neuve, la table est créée par sa propre migration SANS `managed`, puis ALTÉRÉE
    //  ici -> convergence base neuve/existante). `dashboard`/`panel` (base schema.sql) portent aussi `managed`
    //  mirroré dans schema.sql (doctrine « base = schema.sql »). `notification_policy` gagne un `name`
    //  (identité d'overlay ; DEFAULT '' -> les policies UI existantes, keyées par id, restent name='').
    //  >>> RENUMÉROTATION : si une migration v93 concurrente atterrit d'abord, renuméroter celle-ci en v94.
    for tbl in ["dashboard", "panel", "library_panel", "connector", "notifier", "destination", "field_filter", "notification_policy"] {
        if !col_exists(conn, tbl, "managed") {
            let _ = conn.execute(&format!("ALTER TABLE {tbl} ADD COLUMN managed INTEGER NOT NULL DEFAULT 2"), []);
        }
    }
    // notification_policy : identité d'overlay = un `name` (les policies UI restent name='' -> jamais en
    // collision avec un overlay nommé ; le prune/UPSERT de policies overlay est keyé par ce name).
    if !col_exists(conn, "notification_policy", "name") {
        let _ = conn.execute("ALTER TABLE notification_policy ADD COLUMN name TEXT NOT NULL DEFAULT ''", []);
    }
    let _ = conn.execute("UPDATE meta SET value='93' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v93 (#55 observability-as-code : colonne `managed` sur dashboard/panel/library_panel/connector/notifier/destination/field_filter/notification_policy + `name` sur notification_policy ; additif, DEFAULT 2 -> objets existants = ad-hoc UI, mode 0 byte-identique tant qu'aucun overlay config.d n'est livré)");
}

fn migrate_v92(conn: &MigTx) {
    // v92 (#50 OUTPUTS / DESTINATIONS — forward des events normalisés vers un SINK EXTERNE) — ADDITIF &
    //  INERTE en mode 0. UNE table NEUVE, VIDE à la création -> ZÉRO effet tant qu'aucune ligne : le
    //  forwarder (`run_due_destinations`, thread dédié) sélectionne les destinations DUES -> 0 ligne ->
    //  no-op strict (aucun réseau, aucune écriture, aucun coût sur l'ingest — l'ingest ne touche JAMAIS
    //  cette table). Complète #40 (qui ROUTE en interne par env_id) : ici on SORT la donnée du périmètre.
    //   - `destination` : registre admin de SINKS externes nommés. `type` = syslog | hec | webhook (faits) ;
    //     s3 | kafka = DESIGN/STUB (last_error explicite, watermark jamais avancé, jamais de crash). L'IDENTITÉ
    //     de la cible vit dans `endpoint` (affiché, validé schéma https/tcp). `config` = BLOB de config qui
    //     PORTE le SECRET d'auth (hec_token / auth_header webhook) -> JAMAIS projeté (has_auth seul) et NIÉ en
    //     lecture SQL brute par l'authorizer read-pool (comme `notifier.config`, #44/#45). `filter` = sélecteur
    //     d'events ALLOWLISTÉ (category / env_id(#49) / source / min_severity — bound params, JAMAIS de SQL
    //     libre). `watermark` = plus grand `event.id` DÉJÀ forwardé (curseur) : at-least-once, avance UNIQUEMENT
    //     après un envoi RÉUSSI du lot -> un sink mort ne perd rien (re-tente au tick suivant) et ne bloque
    //     jamais l'ingest (thread séparé, envoi réseau HORS lock writer, lot BORNÉ `batch_max`).
    //  GOUVERNANCE : la donnée SOC qui QUITTE le périmètre est un événement d'audit -> create/enable/delete
    //  d'une destination est LEDGERISÉ (audit_config_change, source non-purgeable `plume-config`). Une
    //  destination reçoit des events NORMALISÉS BRUTS (feed machine, pas une lecture humaine) -> le masquage
    //  field-filter (#45, contrôle de LECTURE HUMAINE) ne s'y applique pas : c'est POURQUOI elle est admin-only
    //  + ledgerisée (l'admin décide explicitement où part sa donnée, comme le notifier webhook).
    //  Convergence base neuve/existante : ce bloc tourne aussi sur une base fraîche (après schema.sql).
    //  >>> RENUMÉROTATION : si une migration v92 concurrente atterrit d'abord, renuméroter celle-ci en v93.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS destination(\
           id          INTEGER PRIMARY KEY, \
           type        TEXT NOT NULL DEFAULT 'webhook', \
           name        TEXT NOT NULL DEFAULT 'Destination', \
           enabled     INTEGER NOT NULL DEFAULT 0, \
           endpoint    TEXT NOT NULL DEFAULT '', \
           config      TEXT NOT NULL DEFAULT '{}', \
           filter      TEXT NOT NULL DEFAULT '{}', \
           batch_max   INTEGER NOT NULL DEFAULT 500, \
           interval_s  INTEGER NOT NULL DEFAULT 30, \
           watermark   INTEGER NOT NULL DEFAULT 0, \
           last_run    INTEGER, \
           last_ok     INTEGER, \
           last_error  TEXT, \
           last_count  INTEGER NOT NULL DEFAULT 0, \
           error_count INTEGER NOT NULL DEFAULT 0, \
           created     INTEGER)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='92' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v92 (#50 outputs/destinations : table destination = forward des events vers un sink externe syslog/hec/webhook ; additif, table vide -> mode 0 byte-identique, aucun forward tant qu'aucune destination)");
}

fn migrate_v91(conn: &MigTx) {
    // v91 (#49 INDEXES LOGIQUES NOMMÉS + RÉTENTION/DIMENSIONNEMENT PAR INDEX) — ADDITIF & INERTE en mode 0.
    //  UNE table NEUVE, VIDE à la création -> ZÉRO effet tant qu'aucune ligne (retention_run reste
    //  BYTE-IDENTIQUE : sans policy la purge globale PLUME_RETENTION_DAYS s'applique exactement comme avant).
    //   - `index_policy` : registre admin d'INDEXES LOGIQUES NOMMÉS. L'IDENTITÉ d'un index = la colonne
    //     `event.env_id` (v66) — le MÊME axe que route déjà l'action ROUTE du processeur d'ingest #40
    //     (RRuleAction::Route pose EventRow.env_id) et qu'agrègent les rollups (event_rollup.env_id, v67).
    //     AUCUN concept de routage parallèle : `index_policy.name` == une valeur d'`env_id` (charset borné,
    //     cf. env_id_ok — la MÊME allowlist que #40). Un index HEC (`fields.index`) se route vers un env via
    //     une règle #40 `match fields.index eq <x> -> route env=<x>` : réutilisation, pas de couture neuve.
    //     `retention_days` > 0 -> l'index est purgé par SA politique (planché à 7 j, plafonné à 3650 j comme
    //     la rétention globale) et EXCLU de la purge globale ; = 0 -> l'index HÉRITE de la rétention globale.
    //     `max_rows` / `max_bytes` (>0) -> plafonds de dimensionnement OPTIONNELS (garde les plus RÉCENTS).
    //     Les events de CONTRÔLE du daemon (origin='daemon' + sources plume-*) restent NON-purgeables sur
    //     TOUS les chemins (per-index ET plafonds) -> une politique mal réglée ne peut PAS effacer l'audit.
    //  Convergence base neuve/existante : ce bloc tourne aussi sur une base fraîche (après schema.sql).
    //  >>> RENUMÉROTATION : si une migration v91 concurrente atterrit d'abord, renuméroter celle-ci en v92.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS index_policy(\
           id INTEGER PRIMARY KEY, \
           name TEXT NOT NULL UNIQUE, \
           retention_days INTEGER NOT NULL DEFAULT 0, \
           max_rows INTEGER NOT NULL DEFAULT 0, \
           max_bytes INTEGER NOT NULL DEFAULT 0, \
           description TEXT NOT NULL DEFAULT '', \
           enabled INTEGER NOT NULL DEFAULT 1, \
           managed INTEGER NOT NULL DEFAULT 2, \
           created INTEGER, updated INTEGER, updated_by TEXT)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='91' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v91 (#49 indexes logiques nommés : table index_policy = rétention/plafonds PAR env_id ; additif, table vide -> mode 0 byte-identique, purge globale inchangée)");
}

fn migrate_v90(conn: &MigTx) {
    // v90 (#54 ERGONOMIE DASHBOARDS + LARGEUR DES TYPES DE PANNEAUX) — ADDITIF & INERTE en mode 0.
    //  TROIS tables NEUVES, TOUTES vides à la création -> zéro effet tant qu'aucune ligne :
    //   - `library_panel` : définition de panneau RÉUTILISABLE (éditée une fois, référencée par N panneaux).
    //     Un panneau la référence via la colonne ADDITIVE `panel.library_panel_id` (NULL pour l'existant ->
    //     panneau autonome = résolution INCHANGÉE / mode 0 byte-identique). `is_soql=0` (SQL brut) reste
    //     réservé ADMIN à l'écriture (raw_sql_allowed, miroir de panel_create).
    //   - `playlist` : liste ORDONNÉE de dashboards qui défilent (NOC wall-board). `items` = JSON d'ids
    //     ordonnés ; `interval_s` = période de rotation. Aucune playlist -> aucun défilement.
    //   - `dashboard_snapshot` : capture POINT-IN-TIME des données DÉJÀ rendues d'un dashboard, partageable
    //     en LECTURE SEULE via un `token` CSPRNG (UNIQUE). ⚠ La capture passe par le CHEMIN SOQL MASQUÉ
    //     (effective_masks du rôle du créateur) -> un snapshot ne contient JAMAIS un champ que le créateur
    //     n'aurait pas pu voir. `data` = JSON résolu {panels:[{title,viz,columns,rows}]}. Le mot « snapshot »
    //     étant DÉJÀ un kind d'ingest télémétrie, cette table s'appelle `dashboard_snapshot` (pas de collision).
    //  Les types de panneaux SUPPLÉMENTAIRES (gauge/pie/heatmap/histogram) sont un rendu WEB pur (viz.js) et
    //  n'exigent AUCUN schéma : ils consomment le même {columns,rows} SOQL. Opt-in par `panel.viz`.
    //  Convergence base neuve/existante : ce bloc tourne aussi sur une base fraîche (après schema.sql).
    //  >>> RENUMÉROTATION : si une migration v90 concurrente atterrit d'abord, renuméroter celle-ci en v91.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS library_panel(\
           id INTEGER PRIMARY KEY, name TEXT NOT NULL, title TEXT NOT NULL DEFAULT 'Panneau', \
           query TEXT NOT NULL DEFAULT '', is_soql INTEGER NOT NULL DEFAULT 1, viz TEXT NOT NULL DEFAULT 'table', \
           drill TEXT NOT NULL DEFAULT '', owner TEXT, visibility TEXT NOT NULL DEFAULT 'shared', \
           created INTEGER, updated INTEGER)",
        [],
    );
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN library_panel_id INTEGER", []);
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS playlist(\
           id INTEGER PRIMARY KEY, name TEXT NOT NULL, interval_s INTEGER NOT NULL DEFAULT 30, \
           items TEXT NOT NULL DEFAULT '[]', owner TEXT, visibility TEXT NOT NULL DEFAULT 'shared', \
           created INTEGER, updated INTEGER)",
        [],
    );
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS dashboard_snapshot(\
           id INTEGER PRIMARY KEY, dashboard_id INTEGER, name TEXT NOT NULL DEFAULT '', \
           token TEXT NOT NULL UNIQUE, data TEXT NOT NULL DEFAULT '{}', \
           created INTEGER, created_by TEXT, role_at_capture TEXT, expires_at INTEGER NOT NULL DEFAULT 0)",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_snapshot_tok ON dashboard_snapshot(token)", []);
    let _ = conn.execute("UPDATE meta SET value='90' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v90 (#54 ergonomie dashboards : library_panel + panel.library_panel_id / playlist / dashboard_snapshot ; additif, vide/NULL -> mode 0 byte-identique)");
}

fn migrate_v89(conn: &MigTx) {
    // v89 (#48 + #53 MATURITÉ DE L'ALERTING) — ADDITIF & INERTE en mode 0 :
    //  (a) TABLES nouvelles, TOUTES vides à la création -> zéro effet tant qu'aucune ligne :
    //      - `notification_policy` : arbre de routage (matchers JSON -> points de contact = ids de canaux).
    //        Table VIDE -> dispatch_notifications retombe sur le FAN-OUT PLAT historique (byte-identique).
    //      - `silence` : mute temporisé par label-matcher (expires_at = auto-expiry). Table VIDE -> aucun mute.
    //      - `alert_throttle` : dernier tir par (règle, clé) pour la fenêtre de suppression / throttle-by-field.
    //  (b) COLONNES ADDITIVES sur `rule` (mode « avancé », NULL/0 pour l'existant -> traité EXACTEMENT comme
    //      aujourd'hui par run_due_rules, dont le WHERE exclut ces règles UNIQUEMENT quand elles sont posées) :
    //      - `suppress_window_s` (fenêtre de re-tir), `throttle_field` (dédup par valeur de champ),
    //      - `per_result` (une alerte par résultat). Miroir de `risk_score` (v80) : la capacité s'active par la
    //        DONNÉE, jamais par un flag. Idempotent : `let _ =` avale « duplicate column »/« already exists ».
    //  Convergence base neuve/existante : ce bloc tourne aussi sur une base fraîche (après schema.sql).
    //  >>> RENUMÉROTATION : si une migration v89 concurrente atterrit d'abord, renuméroter celle-ci en v90.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS notification_policy(\
           id INTEGER PRIMARY KEY, matchers TEXT NOT NULL DEFAULT '{}', \
           contact_points TEXT NOT NULL DEFAULT '', continue_ INTEGER NOT NULL DEFAULT 0, \
           enabled INTEGER NOT NULL DEFAULT 1, created INTEGER, created_by TEXT)",
        [],
    );
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS silence(\
           id INTEGER PRIMARY KEY, matchers TEXT NOT NULL DEFAULT '{}', \
           expires_at INTEGER NOT NULL DEFAULT 0, reason TEXT, created INTEGER, created_by TEXT)",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_silence_expiry ON silence(expires_at)", []);
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_throttle(\
           rule_id INTEGER NOT NULL, throttle_key TEXT NOT NULL, last_fire INTEGER NOT NULL, \
           PRIMARY KEY(rule_id, throttle_key))",
        [],
    );
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN suppress_window_s INTEGER", []);
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN throttle_field TEXT", []);
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN per_result INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE meta SET value='89' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v89 (#48/#53 alerting : notification_policy/silence/alert_throttle + rule.suppress_window_s/throttle_field/per_result ; additif, vide/NULL -> mode 0 byte-identique)");
}

fn migrate_v88(conn: &MigTx) {
    // v88 (#38 mapping de conformité) — TAG DE CADRE RÉGLEMENTAIRE PAR RÈGLE : colonne ADDITIVE
    // `rule.compliance` (CSV de `cadre[:contrôle]`, ex `pci_dss:8.7,hipaa:164.312`). Miroir EXACT de
    // `rule.mitre`/`rule.sigma_id` (v81) : NULL pour l'existant -> règle NON taguée -> comportement
    // BYTE-IDENTIQUE (run_due_rules/coverage/rules_list ignorent une colonne vide). La capacité s'active par
    // la DONNÉE (un tag posé en UI/API ou importé de Sigma), JAMAIS par un flag. Idempotent : `let _ =` avale
    // l'erreur « duplicate column » sur une base déjà migrée / neuve.
    // >>> RENUMÉROTATION : si une migration v88 concurrente atterrit d'abord, renuméroter celle-ci en v89.
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN compliance TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='88' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v88 (#38 conformité : colonne rule.compliance (tags cadre:contrôle) ; additive, NULL pour l'existant -> mode 0 byte-identique)");
}

fn migrate_v87(conn: &MigTx) {
    // v87 (#52 plume-as-a-datasource) — TOKEN read-scoped `datasource` : ajoute la colonne `role` à `token`
    // (NULLABLE). Les tokens datasource (kind='datasource') portent leur rôle de LECTURE (viewer|editor) ;
    // les tokens agent/hec existants gardent role NULL -> INCHANGÉS (jamais lus sur le seam datasource).
    // ADDITIF & INERTE : aucune surface existante ne lit `role` sur `token` ; datasource_token_lookup ne
    // matche QUE kind='datasource' (aucun token de ce kind avant qu'un admin n'en mint un). Idempotent :
    // `let _ =` avale l'erreur "duplicate column" sur une base déjà migrée / neuve.
    // >>> RENUMÉROTATION : si une migration v87 concurrente atterrit d'abord, renuméroter celle-ci en v88.
    let _ = conn.execute("ALTER TABLE token ADD COLUMN role TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='87' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v87 (#52 datasource : colonne token.role pour les jetons read-scoped `datasource` ; agent/hec inchangés / mode 0)");
}

fn migrate_v86(conn: &MigTx) {
    // v86 (#45) — FIELD FILTERS : masquage / contrôle d'accès AU NIVEAU CHAMP par rôle/tenant/env (équivalent
    // « Field filters » Splunk ; débloqueur PCI/PII). ADDITIF & INERTE en mode 0 : la table est VIDE à la
    // création -> `field_filters_reload` produit un registre VIDE -> la compilation SOQL et toutes les surfaces
    // de lecture restent BYTE-IDENTIQUES (aucun masque émis). La capacité s'active par la DONNÉE (une règle
    // configurée en UI admin), JAMAIS par un flag. Idempotent (CREATE TABLE IF NOT EXISTS).
    //
    //  - field : champ CIM/event masqué (nom NU, ex src_user|message|src_ip ; 'fields.k' normalisé -> k).
    //  - action : mask (`***`) | partial (`***`+last4) | hash (déterministe salé) | redact (drop->NULL) |
    //    deny (drop pour TOUS, admin compris ; sur colonne réelle -> AUSSI l'authorizer SQLite).
    //  - role : '' = défaut (viewer+editor masqués, admin en clair) | viewer|editor|admin = seuil (rank <= ->
    //    masqué). tenant/env : '' = tous. ord + spécificité -> most-specific-wins.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS field_filter(\
            id       INTEGER PRIMARY KEY,\
            name     TEXT NOT NULL UNIQUE,\
            field    TEXT NOT NULL,\
            action   TEXT NOT NULL DEFAULT 'mask',\
            role     TEXT NOT NULL DEFAULT '',\
            tenant   TEXT NOT NULL DEFAULT '',\
            env      TEXT NOT NULL DEFAULT '',\
            enabled  INTEGER NOT NULL DEFAULT 1,\
            ord      INTEGER NOT NULL DEFAULT 0,\
            created  INTEGER NOT NULL DEFAULT 0,\
            updated  INTEGER NOT NULL DEFAULT 0\
        )",
        [],
    );
    // SEL de HASH par-base, IMMUABLE, créé UNE fois (randomblob = CSPRNG SQLite). Sert au masquage HASH
    // (déterministe salé, non réversible sans le sel). INSERT OR IGNORE -> idempotent, jamais réécrit.
    // INERTE en mode 0 (meta n'est jamais projeté dans une requête d'événements -> lecture byte-identique).
    let _ = conn.execute(
        "INSERT OR IGNORE INTO meta(key,value) VALUES('field_mask_salt', lower(hex(randomblob(32))))",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='86' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v86 (#45 field-filters : table `field_filter` (masquage par champ) VIDE à la création -> lecture byte-identique / mode 0 ; + sel de hash meta.field_mask_salt)");
}

fn migrate_v85(conn: &MigTx) {
    // v85 (#44) — IdP NATIF : fournisseurs d'identité fédérée (OIDC / LDAP / SAML seam) + inscription MFA
    // (TOTP RFC 6238). ADDITIF & INERTE en mode 0 : les DEUX tables sont VIDES par défaut -> aucun provider
    // fédéré, aucune inscription MFA -> resolve_identity + login_post BYTE-IDENTIQUES (Basic/session/agent-
    // token/HEC/header-SSO strictement inchangés). La capacité s'active par la DONNÉE (un provider configuré
    // en UI, ou une inscription MFA volontaire), JAMAIS par un flag. Idempotent (CREATE TABLE IF NOT EXISTS).
    //
    //  - idp_provider : fournisseur fédéré configuré par un ADMIN. `config_json` = paramètres NON-secrets
    //    (issuer, client_id, scopes, group-claim, redirect_uri | url LDAP, base_dn, filtre...). Le SECRET
    //    (client_secret OIDC / mot de passe de bind LDAP) est dans la colonne DÉDIÉE `secret` (jamais dans la
    //    config, jamais projeté en réponse ; chiffré au repos par SQLCipher comme toute la base). `kind` ∈
    //    oidc|ldap|saml (saml = SEAM de config, login non implémenté -> 501). Miroir de la table `connector`.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS idp_provider(\
            id          INTEGER PRIMARY KEY,\
            name        TEXT NOT NULL UNIQUE,\
            kind        TEXT NOT NULL DEFAULT 'oidc',\
            enabled     INTEGER NOT NULL DEFAULT 0,\
            config_json TEXT NOT NULL DEFAULT '{}',\
            secret      TEXT NOT NULL DEFAULT '',\
            created     INTEGER NOT NULL DEFAULT 0,\
            updated     INTEGER NOT NULL DEFAULT 0\
        )",
        [],
    );
    //  - user_mfa : inscription TOTP PAR compte local. `secret` = graine base32 (RFC 4648) ; `enabled`=0
    //    tant que l'inscription n'est pas VÉRIFIÉE (un premier code valide -> 1). `recovery` = JSON des
    //    SHA-256 des codes de secours (jamais les codes en clair ; consommés à usage unique). Un compte SANS
    //    ligne (défaut) -> login_post inchangé (aucun challenge). PK = nom du compte (comme `user.name`).
    //  `last_step` = dernier pas TOTP (compteur RFC 6238) CONSOMMÉ avec succès -> ANTI-REJEU : un code déjà
    //  utilisé (ou d'un pas <= last_step) est refusé même dans sa fenêtre de validité (~90 s avec skew=1).
    //  Défaut -1 (aucun pas consommé ; un compteur légitime vaut ~5,9e7, jamais <= -1).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS user_mfa(\
            user      TEXT PRIMARY KEY,\
            secret    TEXT NOT NULL DEFAULT '',\
            enabled   INTEGER NOT NULL DEFAULT 0,\
            recovery  TEXT NOT NULL DEFAULT '[]',\
            last_step INTEGER NOT NULL DEFAULT -1,\
            created   INTEGER NOT NULL DEFAULT 0,\
            updated   INTEGER NOT NULL DEFAULT 0\
        )",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='85' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v85 (#44 IdP natif : tables `idp_provider` (OIDC/LDAP/SAML) + `user_mfa` (TOTP) ; VIDES à la création -> auth existante byte-identique / mode 0)");
}

// INTÉGRATION : v83 (#40 ingest processor) puis v84 (#37 détection avancée) — ordre du ladder garanti
// (v83 avant v84). Version finale du schéma intégré : v84.
fn migrate_v83(conn: &MigTx) {
    // v83 (#40) — PROCESSEUR D'INGEST : table de contrôle `ingest_rule` (règles ordonnées admin-managed
    // qui filtrent/masquent/routent/échantillonnent un event AVANT indexation). Bas-volume, CONTROL-plane
    // (jamais touchée à l'ingest chaud, seulement au reload). ADDITIVE : table NEUVE, VIDE à la création ->
    // le registre compilé de CE db_path reste vide -> `processors_apply` renvoie Keep -> INGEST BYTE-IDENTIQUE
    // (mode 0). Idempotent : CREATE TABLE IF NOT EXISTS ; la version n'est bumpée qu'une fois (garde v<83).
    //   ord         : ordre d'évaluation (asc) ; match_field : champ CIM allowlisté (category/source/... ,
    //                 fields.<clé>) ; match_op : any|eq|ne|contains|regex ; action : drop|mask|route|sample ;
    //   action_arg  : mask=champ à masquer ; route=env cible ; sample=N (1-sur-N).
    //   managed     : 2 (ad-hoc UI, supprimable) — aligné sur parser/rule pour delete_managed_row_tx.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS ingest_rule(\
            id INTEGER PRIMARY KEY,\
            name TEXT NOT NULL DEFAULT '',\
            ord INTEGER NOT NULL DEFAULT 0,\
            match_field TEXT NOT NULL DEFAULT 'category',\
            match_op TEXT NOT NULL DEFAULT 'eq',\
            match_value TEXT NOT NULL DEFAULT '',\
            action TEXT NOT NULL DEFAULT 'drop',\
            action_arg TEXT NOT NULL DEFAULT '',\
            enabled INTEGER NOT NULL DEFAULT 1,\
            managed INTEGER NOT NULL DEFAULT 2,\
            created INTEGER NOT NULL DEFAULT 0\
        )",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ingest_rule_ord ON ingest_rule(enabled, ord, id)", []);
    let _ = conn.execute("UPDATE meta SET value='83' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v83 (#40 processeur d'ingest : table ingest_rule ; VIDE à la création -> ingest byte-identique / mode 0)");
}

fn migrate_v84(conn: &MigTx) {
    // v84 (#37) — DÉTECTION AVANCÉE : corrélation multi-événements stateful (`correlation`) + baselining
    // statistique UEBA (`ueba_baseline` + `ueba_baseline_obs`). ADDITIF & INERTE en mode 0 : ces tables sont
    // VIDES par défaut (aucune corrélation/baseline seedée) -> run_correlations/run_baselines sélectionnent 0
    // ligne -> retour immédiat -> détection/ingest/data-plane BYTE-IDENTIQUES. Comme #24 (RBA), la capacité
    // s'active par la DONNÉE (une corrélation/baseline définie via l'UI), jamais par un flag. Convergence base
    // neuve/existante (v84 tourne aussi à froid). Idempotent (CREATE TABLE IF NOT EXISTS).
    //
    //  - correlation : séquence ORDONNÉE d'étapes SOQL keyée sur une entité. `steps` = JSON [{name,query,
    //    min_count}]. run_correlations (planifié, à côté de run_due_rules) apparie la séquence par entité dans
    //    la fenêtre `window_s` et lève UN finding-group dédupliqué `corr-<id>-<entity>` (ou contribue au RBA si
    //    risk_score>0). FAIL-CLOSED : une étape en erreur/timeout NE RÉSOUT PAS de groupe ouvert.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS correlation(\
           id           INTEGER PRIMARY KEY,\
           name         TEXT NOT NULL,\
           enabled      INTEGER NOT NULL DEFAULT 1,\
           key_field    TEXT NOT NULL DEFAULT 'src_ip',\
           entity_type  TEXT NOT NULL DEFAULT 'ip',\
           steps        TEXT NOT NULL DEFAULT '[]',\
           window_s     INTEGER NOT NULL DEFAULT 3600,\
           interval_s   INTEGER NOT NULL DEFAULT 300,\
           severity     INTEGER NOT NULL DEFAULT 3,\
           mitre        TEXT NOT NULL DEFAULT '',\
           risk_score   INTEGER NOT NULL DEFAULT 0,\
           last_run     INTEGER,\
           last_fired   INTEGER,\
           managed      INTEGER NOT NULL DEFAULT 2,\
           created      INTEGER)",
        [],
    );
    //  - baseline : baseline statistique glissante PAR ENTITÉ (moyenne+écart-type des buckets passés) + score
    //    de déviation (z-score) SANS ML. run_baselines (planifié) calcule la valeur du dernier bucket clos par
    //    entité, la persiste dans ueba_baseline_obs, et lève une anomalie (RBA si risk_score>0, sinon alerte
    //    discrète `baseline-<id>-<entity>-<bucket>`) quand z >= z_threshold. FAIL-CLOSED idem.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS ueba_baseline(\
           id           INTEGER PRIMARY KEY,\
           name         TEXT NOT NULL,\
           enabled      INTEGER NOT NULL DEFAULT 1,\
           query        TEXT NOT NULL DEFAULT '',\
           is_soql      INTEGER NOT NULL DEFAULT 1,\
           entity_type  TEXT NOT NULL DEFAULT 'host',\
           entity_field TEXT NOT NULL DEFAULT '',\
           value_field  TEXT NOT NULL DEFAULT '',\
           bucket_s     INTEGER NOT NULL DEFAULT 3600,\
           min_samples  INTEGER NOT NULL DEFAULT 5,\
           z_threshold  REAL NOT NULL DEFAULT 3.0,\
           window_s     INTEGER NOT NULL DEFAULT 604800,\
           interval_s   INTEGER NOT NULL DEFAULT 3600,\
           severity     INTEGER NOT NULL DEFAULT 2,\
           mitre        TEXT NOT NULL DEFAULT '',\
           risk_score   INTEGER NOT NULL DEFAULT 0,\
           last_run     INTEGER,\
           last_bucket  INTEGER,\
           managed      INTEGER NOT NULL DEFAULT 2,\
           created      INTEGER)",
        [],
    );
    //  - ueba_baseline_obs : historique par (baseline, entité, bucket). Reconstruit incrémentalement à
    //    chaque bucket clos (INSERT OR IGNORE -> idempotent) ; élagué à la fenêtre `window_s` (borné). PK
    //    (baseline_id, entité, bucket) -> une observation par entité/bucket.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS ueba_baseline_obs(\
           baseline_id  INTEGER NOT NULL,\
           entity_type  TEXT NOT NULL DEFAULT '',\
           entity       TEXT NOT NULL,\
           bucket       INTEGER NOT NULL,\
           value        REAL NOT NULL DEFAULT 0,\
           env_id       TEXT NOT NULL DEFAULT 'prod',\
           PRIMARY KEY(baseline_id, entity, bucket))",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_baseline_obs ON ueba_baseline_obs(baseline_id, entity, bucket)", []);
    let _ = conn.execute("UPDATE meta SET value='84' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v84 (#37 détection avancée : tables `correlation` + `ueba_baseline`/`ueba_baseline_obs` ; corrélation stateful de séquence + baselining statistique UEBA, INERTES tant qu'aucune corrélation/baseline définie -> mode 0 byte-identique)");
}

fn migrate_v2(conn: &MigTx) {
    // v2 : multi-hôte (agrégation de plusieurs machines) + champs réseau
    for stmt in [
        "ALTER TABLE event ADD COLUMN src_ip TEXT",
        "ALTER TABLE event ADD COLUMN dst_ip TEXT",
        "ALTER TABLE event ADD COLUMN url TEXT",
        "ALTER TABLE event ADD COLUMN xff TEXT",
        "ALTER TABLE metric ADD COLUMN host TEXT",
        "ALTER TABLE snapshot ADD COLUMN host TEXT",
        "ALTER TABLE alert ADD COLUMN host TEXT",
        "CREATE INDEX IF NOT EXISTS idx_event_host ON event(host)",
        "CREATE INDEX IF NOT EXISTS idx_event_srcip ON event(src_ip)",
    ] {
        let _ = conn.execute(stmt, []);
    }
    let _ = conn.execute("UPDATE meta SET value='2' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v2 (multi-hôte + réseau)");
}

fn migrate_v3(conn: &MigTx) {
    // v3 : notifications multi-canal
    let _ = conn.execute("ALTER TABLE alert ADD COLUMN notified INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS notifier(\
         id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT 'Canal', kind TEXT NOT NULL DEFAULT 'ntfy', \
         enabled INTEGER NOT NULL DEFAULT 1, url TEXT NOT NULL DEFAULT '', \
         min_severity INTEGER NOT NULL DEFAULT 2, config TEXT NOT NULL DEFAULT '{}')",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='3' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v3 (notifications)");
}

fn migrate_v4(conn: &MigTx) {
    // v4 : moteur de réponse (file d'actions auditées)
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS action(\
         id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, \
         status TEXT NOT NULL DEFAULT 'pending', dry_run INTEGER NOT NULL DEFAULT 1, \
         alert_id INTEGER, reason TEXT, result TEXT, done_ts INTEGER)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='4' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v4 (moteur de réponse)");
}

fn migrate_v5(conn: &MigTx) {
    // v5 : playbooks (détection -> réponse) + mode global observe/active
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS playbook(\
         id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT 'Playbook', enabled INTEGER NOT NULL DEFAULT 1, \
         query TEXT NOT NULL DEFAULT '', is_soql INTEGER NOT NULL DEFAULT 1, action_kind TEXT NOT NULL DEFAULT 'ban_ip', \
         interval_s INTEGER NOT NULL DEFAULT 300, window_s INTEGER NOT NULL DEFAULT 3600, \
         managed INTEGER NOT NULL DEFAULT 0, last_run INTEGER)",
        [],
    );
    let _ = conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('plume_mode','observe')", []);
    let _ = conn.execute("UPDATE meta SET value='5' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v5 (playbooks + mode)");
}

fn migrate_v6(conn: &MigTx) {
    // v6 : rollup métriques (downsampling pour rétention longue)
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS metric_rollup(ts INTEGER NOT NULL, name TEXT NOT NULL, host TEXT, avg REAL, min REAL, max REAL, n INTEGER)",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_metric_rollup ON metric_rollup(name,ts)", []);
    let _ = conn.execute("UPDATE meta SET value='6' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v6 (rollup métriques)");
}

fn migrate_v7(conn: &MigTx) {
    // v7 : intégrité (ledger à chaîne de hash + checkpoints signés)
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)",
        [],
    );
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ledger_hash TEXT, sig TEXT, pubkey TEXT)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='7' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v7 (intégrité ledger+checkpoints)");
}

fn migrate_v8(conn: &MigTx) {
    // v8 : tokens par agent (auth d'ingestion sans le mot de passe partagé)
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS token(id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created INTEGER, last_used INTEGER)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='8' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v8 (tokens agents)");
}

fn migrate_v9(conn: &MigTx) {
    // v9 : fenêtre temporelle propre à chaque panneau (0 = fenêtre globale)
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN window_s INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE meta SET value='9' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v9 (fenêtre par panneau)");
}

fn migrate_v10(conn: &MigTx) {
    // v10 : comptes multi-utilisateurs (RBAC) + ownership/visibilité des dashboards
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE,
             hash TEXT NOT NULL,
             role TEXT NOT NULL DEFAULT 'editor',
             created INTEGER NOT NULL DEFAULT (strftime('%s','now'))
         );",
    )
    .unwrap();
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN owner TEXT", []);
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'", []);
    // l'admin déjà configuré (wizard/meta) devient le 1er compte de la table user
    if let (Ok(au), Ok(ah)) = (
        conn.query_row("SELECT value FROM meta WHERE key='admin_user'", [], |r| r.get::<_, String>(0)),
        conn.query_row("SELECT value FROM meta WHERE key='admin_hash'", [], |r| r.get::<_, String>(0)),
    ) {
        let _ = conn.execute("INSERT OR IGNORE INTO user(name,hash,role) VALUES(?1,?2,'admin')", params![au, ah]);
    }
    let _ = conn.execute("UPDATE meta SET value='10' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v10 (comptes utilisateurs + ownership dashboards)");
}

fn migrate_v11(conn: &MigTx) {
    // v11 : niveau « vue » (ensemble de dashboards) + visibilité par panel et par requête
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS view(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             owner TEXT,
             visibility TEXT NOT NULL DEFAULT 'private',
             created INTEGER NOT NULL DEFAULT (strftime('%s','now'))
         );",
    )
    .unwrap();
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN view_id INTEGER", []);
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'", []);
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN query_private INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE meta SET value='11' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v11 (vues + visibilité panel/requête)");
}

fn migrate_v12(conn: &MigTx) {
    // v12 : panneaux redimensionnables (largeur en colonnes + hauteur en px)
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN cols INTEGER NOT NULL DEFAULT 1", []);
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN height INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE meta SET value='12' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v12 (panneaux redimensionnables)");
}

fn migrate_v13(conn: &MigTx) {
    // v13 (OBS-5) : labels dans le rollup métrique (sinon les séries sont écrasées) + index
    let _ = conn.execute("ALTER TABLE metric_rollup ADD COLUMN labels TEXT", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_metric_rollup_lbl ON metric_rollup(name,labels,ts)", []);
    let _ = conn.execute("UPDATE meta SET value='13' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v13 (rollup métrique par labels)");
}

fn migrate_v14(conn: &MigTx) {
    // v14 : requête de drilldown configurable par panneau (clic -> soql avec $value/$from/$to)
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN drill TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='14' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v14 (drilldown par panneau)");
}

fn migrate_v15(conn: &MigTx) {
    // v15 : layout des dashboards DANS une vue (grille : largeur en colonnes, hauteur px, ordre, replié)
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN position INTEGER", []);
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN cols INTEGER NOT NULL DEFAULT 2", []);
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN height INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE dashboard ADD COLUMN collapsed INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE dashboard SET position=id WHERE position IS NULL", []);
    let _ = conn.execute("UPDATE meta SET value='15' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v15 (layout dashboards dans la vue)");
}

fn migrate_v16(conn: &MigTx) {
    // v16 : gestion d'incident (cases). Table `incident` (le mot `case` est reserve en SQL)
    // + `incident_item` = timeline (notes + alertes/events/actions lies).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS incident(\
         id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, updated INTEGER NOT NULL, \
         title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', severity INTEGER NOT NULL DEFAULT 2, \
         owner TEXT, summary TEXT, closed_ts INTEGER)",
        [],
    );
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS incident_item(\
         id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL, ts INTEGER NOT NULL, \
         kind TEXT NOT NULL, author TEXT, body TEXT, ref TEXT)",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_item ON incident_item(incident_id, ts)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incident(status, updated)", []);
    let _ = conn.execute("UPDATE meta SET value='16' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v16 (gestion d'incident / cases)");
}

fn migrate_v17(conn: &MigTx) {
    // v17 : responder multi-hôte — `host` cible l'hôte qui doit appliquer (NULL = central/local) ;
    // `claimed_ts` = anti double-exécution quand un agent réclame une action à appliquer chez lui.
    let _ = conn.execute("ALTER TABLE action ADD COLUMN host TEXT", []);
    let _ = conn.execute("ALTER TABLE action ADD COLUMN claimed_ts INTEGER", []);
    let _ = conn.execute("UPDATE meta SET value='17' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v17 (responder multi-hôte : action.host + claim)");
}

fn migrate_v18(conn: &MigTx) {
    // v18 : token d'agent LIÉ à un hôte -> un agent ne peut réclamer/clore QUE les actions de SON
    // hôte (anti-IDOR cross-agent). NULL = token non lié (ingest only ; refusé sur le responder).
    let _ = conn.execute("ALTER TABLE token ADD COLUMN host TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='18' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v18 (token agent lié à un hôte)");
}

fn migrate_v19(conn: &MigTx) {
    // v19 : corrige les 2 règles hôte seedées qui utilisaient des noms de métriques PROMETHEUS
    // (node_load1 / node_memory_MemAvailable_bytes) -> noms NATIFS de resources.sh (load1 / mem_pct).
    // Elles erraient ("évaluation échouée") car prom-scrape ne livre pas ces séries. Idempotent.
    let _ = conn.execute(
        "UPDATE rule SET query='metric load1 | stats max(value)' WHERE query LIKE '%node_load1%'",
        [],
    );
    let _ = conn.execute(
        "UPDATE rule SET query='metric mem_pct | stats max(value)', op='>', threshold=90.0, name='hôte: mémoire élevée (%)' \
         WHERE query LIKE '%node_memory_MemAvailable_bytes%'",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='19' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v19 (règles hôte : noms métriques natifs)");
}

fn migrate_v20(conn: &MigTx) {
    // v20 : corrige les panneaux du dashboard OBS qui interrogeaient des métriques PROMETHEUS
    // (node_load1 / node_memory_MemAvailable_bytes / node_network_*) -> natifs resources.sh.
    // Sinon ces panneaux restent VIDES (la donnée existe en load1/mem_pct/net_rx_bps). Idempotent.
    let _ = conn.execute("UPDATE panel SET query='metric load1 | timechart span=1m avg(value)', title='CPU charge (load1)' WHERE query LIKE '%node_load1%'", []);
    let _ = conn.execute("UPDATE panel SET query='metric mem_pct | timechart span=1m avg(value)', title='Mémoire (%)' WHERE query LIKE '%node_memory_MemAvailable%'", []);
    let _ = conn.execute("UPDATE panel SET query='metric net_rx_bps | timechart span=1m avg(value)' WHERE query LIKE '%node_network_receive%'", []);
    let _ = conn.execute("UPDATE meta SET value='20' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v20 (panneaux OBS : métriques natives)");
}

fn migrate_v21(conn: &MigTx) {
    // v21 : rôle `analyst` renommé `editor` (triplet admin/editor/viewer, cohérent admin-console).
    let _ = conn.execute("UPDATE user SET role='editor' WHERE role='analyst'", []);
    let _ = conn.execute("UPDATE meta SET value='21' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v21 (rôle analyst -> editor)");
}

fn migrate_v22(conn: &MigTx) {
    // v22 : registre de PARSERS modulaire — extraction de champs (groupes nommés) à l'ingestion,
    // pour TOUTES les sources. builtin=défauts par outil (éditables/désactivables) ; custom = ajout opérateur.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS parser(\
         id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT '*', \
         pattern TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, builtin INTEGER NOT NULL DEFAULT 0, \
         managed INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0)",
        [],
    );
    // parsers par DÉFAUT (builtin) : qui/quoi/où sur les sources clés + génériques. source='*' = toutes.
    let seed: &[(&str, &str, &str)] = &[
        ("sshd — user + rhost", "sshd", r"for (?:invalid user )?(?P<user>\S+) from (?P<rhost>\S+)"),
        ("sshd-session — user + rhost", "sshd-session", r"for (?:invalid user )?(?P<user>\S+) from (?P<rhost>\S+)"),
        ("sudo — user + command", "sudo", r" : .*\bCOMMAND=(?P<command>.+)$"),
        ("générique — user=", "*", r"\buser=(?P<user>[^\s,;]+)"),
        ("générique — uid=", "*", r"\buid=(?P<uid>\d+)"),
    ];
    for (name, src, pat) in seed {
        let _ = conn.execute(
            "INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES(?1,?2,?3,1,1,?4)",
            params![name, src, pat, now()],
        );
    }
    let _ = conn.execute("UPDATE meta SET value='22' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v22 (registre de parsers modulaire)");
}

fn migrate_v23(conn: &MigTx) {
    // v23 : parsers par DÉFAUT pour les outils du stack qui émettent un message brut (crowdsec,
    // fail2ban, containerd, kube-state, sshd lignes hors "for X from"). builtin, activés, éditables.
    let seed: &[(&str, &str, &str)] = &[
        ("crowdsec — scénario + IP", "crowdsec", r"crowdsecurity/(?P<scenario>[\w/-]+) \(src (?P<src_ip>[0-9A-Fa-f.:]+)\)"),
        ("fail2ban — jail", "fail2ban", r"\((?P<jail>[a-z][\w/-]+)\)"),
        ("containerd — pod", "containerd", r"pod=(?P<pod>\S+)"),
        ("containerd — image", "containerd", r"image[=: ]+(?P<image>\S+)"),
        ("kube-state — namespace/workload", "k8s", r"^(?P<namespace>[\w-]+)/(?P<workload>[\w.-]+) :"),
        ("sshd — rhost élargi", "sshd", r"(?:from|new) (?P<rhost>(?:\d{1,3}\.){3}\d{1,3})"),
        ("sshd-session — rhost élargi", "sshd-session", r"(?:from|new) (?P<rhost>(?:\d{1,3}\.){3}\d{1,3})"),
        ("intégrité — chemin", "integrity", r": (?P<path>/\S+)"),
    ];
    for (name, src, pat) in seed {
        let _ = conn.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES(?1,?2,?3,1,1,?4)", params![name, src, pat, now()]);
    }
    let _ = conn.execute("UPDATE meta SET value='23' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v23 (parsers par défaut du stack)");
}

fn migrate_v24(conn: &MigTx) {
    // v24 : corrige les panneaux dashboard EXISTANTS — Pods Running pointait sur une métrique
    // inexistante (kube_pod_status_phase) ; spans figés (1m/5m/1h) -> AUTO (sinon 30j en buckets 1h) ;
    // retire le panneau Température (pas de sonde sur VM).
    let _ = conn.execute("UPDATE panel SET query='metric kube_pods_running | timechart avg(value)', viz='line' WHERE title='Pods Running'", []);
    for s in ["span=1m ", "span=5m ", "span=1h ", "span=10s "] {
        let _ = conn.execute("UPDATE panel SET query=REPLACE(query, ?1, '') WHERE query LIKE '%timechart%' AND query LIKE ?2", params![s, format!("%{s}%")]);
    }
    let _ = conn.execute("DELETE FROM panel WHERE title LIKE 'Temp%rature%'", []);
    let _ = conn.execute("UPDATE meta SET value='24' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v24 (correctifs panneaux dashboard)");
}

fn migrate_v25(conn: &MigTx) {
    // v25 : clamp les métriques RÉSEAU négatives déjà stockées (compteur /proc/net/dev qui repart
    // à 0 au reboot -> delta négatif -> point SOUS l'axe sur les graphes réseau). Source corrigée
    // dans resources.sh (clamp >=0). On nettoie l'existant ici (table live + rollups).
    let _ = conn.execute("UPDATE metric SET value=0 WHERE name IN ('net_rx_bps','net_tx_bps') AND value<0", []);
    let _ = conn.execute("UPDATE metric_rollup SET avg=0 WHERE name IN ('net_rx_bps','net_tx_bps') AND avg<0", []);
    let _ = conn.execute("UPDATE metric_rollup SET min=0 WHERE name IN ('net_rx_bps','net_tx_bps') AND min<0", []);
    let _ = conn.execute("UPDATE meta SET value='25' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v25 (clamp métriques réseau négatives)");
}

fn migrate_v26(conn: &MigTx) {
    // v26 : dédoublonne les panneaux réseau (retours opérateur) + egress "top destinations" inutile
    // (count=1 car conntrack dédupe par dst) -> liste en table.
    let _ = conn.execute("DELETE FROM panel WHERE title='Bande passante reçue (o/s)'", []);   // doublon de 'Réseau ↓'/'Réseau reçu'
    let _ = conn.execute("DELETE FROM panel WHERE title='Sorties externes récentes'", []);     // fusionné dans 'Destinations externes'
    let _ = conn.execute("DELETE FROM panel WHERE title='Connexions sortantes récentes'", []); // doublon (egress couvre)
    let _ = conn.execute("UPDATE panel SET title='Destinations externes', viz='table', query='search source=conntrack dir=outbound scope=external | sort -ts | table dst_ip,proc,dport' WHERE title='Destinations externes (top)'", []);
    let _ = conn.execute("UPDATE meta SET value='26' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v26 (dédup panneaux réseau + egress destinations en table)");
}

fn migrate_v27(conn: &MigTx) {
    // v27 : egress « Destinations externes » affiche le dst_host (rDNS, conntrack) -> lisible.
    let _ = conn.execute("UPDATE panel SET query='search source=conntrack dir=outbound scope=external | sort -ts | table dst_host,dst_ip,proc,dport' WHERE title='Destinations externes'", []);
    let _ = conn.execute("UPDATE meta SET value='27' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v27 (egress destinations + rDNS dst_host)");
}

fn migrate_v28(conn: &MigTx) {
    // v28 : parsers pour l'audit Vault (source=vault-audit, via collecteur custom) — extrait QUI
    // accède à QUEL secret (Varonis brique c). Vault HMAC les valeurs sensibles -> aucun secret en
    // clair n'est collecté. builtin, activés, éditables dans l'UI.
    let seed: &[(&str, &str, &str)] = &[
        ("vault — opération", "vault-audit", r#""operation":"(?P<operation>[^"]+)""#),
        ("vault — chemin secret", "vault-audit", r#""path":"(?P<path>[^"]+)""#),
        ("vault — adresse cliente", "vault-audit", r#""remote_address":"(?P<remote_address>[^"]+)""#),
        ("vault — identité", "vault-audit", r#""display_name":"(?P<user>[^"]+)""#),
        ("vault — type req/resp", "vault-audit", r#""type":"(?P<vtype>request|response)""#),
        ("vault — erreur", "vault-audit", r#""error":"(?P<error>[^"]+)""#),
    ];
    for (name, src, pat) in seed {
        let _ = conn.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES(?1,?2,?3,1,1,?4)", params![name, src, pat, now()]);
    }
    let _ = conn.execute("UPDATE meta SET value='28' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v28 (parsers audit Vault)");
}

fn migrate_v29(conn: &MigTx) {
    // v29 : champ `action` NORMALISÉ (CIM) sur toutes les sources (success/failure/allowed/blocked/
    // ban/read/modify/delete/...). Met à jour les panneaux EXISTANTS qui filtraient les anciennes
    // valeurs (les seeds sont idempotents par nom -> sinon désync sur l'instance déjà déployée).
    let _ = conn.execute("UPDATE panel SET query=REPLACE(query,'action=auth_fail','action=failure') WHERE query LIKE '%action=auth_fail%'", []);
    let _ = conn.execute("UPDATE meta SET value='29' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v29 (action normalisé CIM)");
}

fn migrate_v30(conn: &MigTx) {
    // v30 : rollups d'EVENTS — counts horaires par (source,severity,action) pour des dashboards
    // RAPIDES (panneaux SQL directs sur event_rollup, SANS toucher le compilateur soql partagé
    // guatx-core). Alimentée par retention_run (watermark meta 'event_rollup_wm'), même rétention
    // que `event`. La PK (bucket,source,severity,action) rend l'agrégation idempotente (OR REPLACE).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS event_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
         severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
         PRIMARY KEY(bucket,source,severity,action))",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_event_rollup ON event_rollup(bucket)", []);
    let _ = conn.execute("UPDATE meta SET value='30' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v30 (rollups d'events)");
}

fn migrate_v31(conn: &MigTx) {
    // v31 : index COMPOSÉS filtre+group sur src_ip. Sans eux, `WHERE severity>=3 GROUP BY src_ip`
    // SCAN les 1,24M lignes via idx_event_srcip (au lieu de SEARCH idx_event_sev) -> ~15s sur base
    // CHIFFRÉE (déchiffre toutes les pages). Avec (severity,src_ip) : SEARCH -> lit le sous-ensemble.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_event_sev_srcip ON event(severity, src_ip)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_event_src_srcip ON event(source, src_ip)", []);
    let _ = conn.execute("UPDATE meta SET value='31' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v31 (index composés severity/source + src_ip)");
}

fn migrate_v32(conn: &MigTx) {
    // v32 : ANALYZE (échantillonné) -> stats SQLite (sqlite_stat1) pour que le planificateur CHOISISSE
    // les index composés v31 (severity>=3 GROUP BY src_ip -> SEARCH (severity,src_ip) au lieu de SCAN).
    // Sans stats il garde le full-scan. analysis_limit borne l'échantillon -> ANALYZE rapide.
    let _ = conn.execute_batch("PRAGMA analysis_limit=400; ANALYZE;");
    let _ = conn.execute("UPDATE meta SET value='32' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v32 (ANALYZE pour les index composés)");
}

fn migrate_v34(conn: &MigTx) {
    // v34 : CACHE de résultats par panneau (schéma seul ; logique dans panel_data). 1 ligne / panel
    // (PK panel_id) -> taille bornée par le nombre de panneaux. range_key = fenêtre demandée
    // (« from=..,to=.. ») pour ne servir le cache QUE si la range == celle calculée. payload = JSON brut.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS panel_cache(panel_id INTEGER PRIMARY KEY, range_key TEXT NOT NULL, \
         computed_at INTEGER NOT NULL, payload TEXT NOT NULL)",
        [],
    );
    // colonne optionnelle de TTL par panneau (NULL = utilise le TTL global PLUME_PANEL_CACHE_TTL).
    let _ = conn.execute("ALTER TABLE panel ADD COLUMN panel_cache_ttl_s INTEGER", []);
    let _ = conn.execute("UPDATE meta SET value='34' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v34 (panel_cache : cache de résultats par panneau)");
}

fn migrate_v35(conn: &MigTx) {
    // v35 : ANALYZE RENFORCÉ. v32 (analysis_limit=400) échantillonnait trop peu -> le planificateur
    // ignorait idx_event_sev_srcip / idx_event_src_srcip et full-scannait. Il faut des stats exactes
    // (sqlite_stat1) pour que le planner choisisse l'index composé (EXPLAIN QUERY PLAN doit montrer
    // « SEARCH event USING INDEX idx_event_sev_srcip »).
    //
    // PERF : un ANALYZE COMPLET (analysis_limit=0) SYNCHRONE ici déchiffre TOUTE la table event
    // sur base SQLCipher volumineuse (1-2 min) -> bloque le bind du serveur -> la liveness probe k8s
    // échoue -> CrashLoopBackOff. FIX : on ne fait dans migrate() qu'un ANALYZE BORNÉ rapide
    // (analysis_limit=2000 : stats correctes immédiatement, quelques ms). Le ANALYZE COMPLET est lancé
    // EN TÂCHE DE FOND APRÈS le bind (cf. analyze_full_background), gardé par la meta clé
    // 'analyze_full_done' (idempotent : une seule fois). Le boot reste donc NON bloquant.
    let _ = conn.execute_batch("PRAGMA analysis_limit=2000; ANALYZE;");
    let _ = conn.execute("UPDATE meta SET value='35' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v35 (ANALYZE borné rapide ; complet en tâche de fond après bind)");
}

fn migrate_v36(conn: &MigTx) {
    // v36 : CACHE — colonne query_fp (empreinte de la requête) sur panel_cache. On lie le
    // payload caché à la requête courante -> un panel_update (requête/viz changée) ou un rowid panel
    // réutilisé après delete ne sert jamais un payload périmé/étranger. On VIDE le cache existant (les
    // anciennes lignes n'ont pas d'empreinte et le schéma de range_key a changé).
    let _ = conn.execute("ALTER TABLE panel_cache ADD COLUMN query_fp TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("DELETE FROM panel_cache", []);
    let _ = conn.execute("UPDATE meta SET value='36' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v36 (panel_cache.query_fp : cache lié à la requête, anti-fuite)");
}

fn migrate_v37(conn: &MigTx) {
    // v37 : ajoute les 2 panneaux rollup (par src_ip / par host) au dashboard « Vue d'ensemble
    // (rapide) » des bases EXISTANTES (seed_rollup_dashboard ne créait ces panneaux que
    // sur installs neuves). Idempotent : garde par (dashboard, titre) -> n'insère que s'ils manquent ;
    // ne touche AUCUN dashboard utilisateur.
    ensure_rollup_srcip_host_panels(conn);
    let _ = conn.execute("UPDATE meta SET value='37' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v37 (panneaux rollup src_ip/host ajoutés aux bases existantes)");
}

fn migrate_v38(conn: &MigTx) {
    // v38 : CACHE multi-emplacement. panel_cache avait PK=panel_id (1 SEULE ligne / panel)
    // -> 24 h / zoom / pré-chauffage se battaient pour l'unique emplacement -> évictions mutuelles ->
    // recomputes répétés. FIX : PK COMPOSITE (panel_id, range_key) -> une ligne PAR plage demandée.
    // C'est de la donnée DÉRIVÉE (se repeuple seule) -> DROP + CREATE à blanc (pas de migration de
    // données ; idempotent). On garde query_fp (anti-fuite, v36) + computed_at. Le SELECT existant
    // (panel_id+range_key+query_fp) et l'invalidation (DELETE WHERE panel_id=?) marchent tels quels.
    let _ = conn.execute("DROP TABLE IF EXISTS panel_cache", []);
    let _ = conn.execute(
        "CREATE TABLE panel_cache(panel_id INTEGER NOT NULL, range_key TEXT NOT NULL, \
         query_fp TEXT NOT NULL DEFAULT '', computed_at INTEGER NOT NULL, payload TEXT NOT NULL, \
         PRIMARY KEY(panel_id, range_key))",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='38' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v38 (panel_cache PK composite (panel_id, range_key) : cache multi-plage)");
}

fn migrate_v39(conn: &MigTx) {
    // v39 (PURPLE) : tag MITRE ATT&CK (ex 'T1110', 'T1190.001') sur les règles ET les alertes.
    // Mesure DÉFENSIVE (blue-team) : Forge (red) tire des techniques ATT&CK, chaque règle de détection
    // porte la technique qu'elle couvre -> l'alerte hérite du `mitre` de sa règle (run_due_rules) ->
    // /api/coverage/detections corrèle « combien de techniques tirées en red-team sont DÉTECTÉES »
    // (joint sur `mitre`, le champ commun Forge/Plume — cf. forge/README §boucle purple). Vide = non
    // mappée (rétro-compatible). NOT NULL DEFAULT '' -> jamais de NULL à propager. Idempotent (ALTER
    // déjà appliqué -> « duplicate column » ignoré).
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN mitre TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE alert ADD COLUMN mitre TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_mitre ON alert(mitre)", []);
    let _ = conn.execute("UPDATE meta SET value='39' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v39 (tag MITRE ATT&CK sur règles + alertes : mesure de couverture de détection)");
}

fn migrate_v40(conn: &MigTx) {
    // v40 (PHASE 1) : marqueur de schéma seulement. L'INFRA FTS5 (vtable event_fields_fts +
    // triggers event_ff_ai/ad) N'EST PLUS pilotée ICI (un DROP/CREATE gardé par
    // `if v<40` ne re-tourne JAMAIS une fois schema_version>=40 -> poser PLUME_FTS_FIELDS=0 +
    // redeploy ne droppait rien). Le pilotage d'état (create SI =1 / drop SI =0) est désormais dans
    // `reconcile_index_state`, fn IDEMPOTENTE appelée à CHAQUE boot (après migrate) -> le toggle env
    // s'applique réellement à chaque démarrage (vrai kill-switch). v40 ne fait que bumper la version.
    let _ = conn.execute("UPDATE meta SET value='40' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v40 (marqueur : pilotage FTS-fields déplacé dans reconcile_index_state, env-driven idempotent)");
}

fn migrate_v41(conn: &MigTx) {
    // v41 (PHASE 2) : marqueur de schéma seulement. Les 7 index expression partiels (action,user,
    // owner,kind,ns,role,scope) NE SONT PLUS créés ICI (un CREATE INDEX synchrone au boot sur une
    // table volumineuse bloque le bind -> échec de la sonde de liveness -> boucle de redémarrage ; et
    // un `if v<41` ne re-tourne jamais). Leur pilotage (create si PLUME_EXPRINDEX=1 / drop si =0)
    // est dans `reconcile_index_state` (drops instantanés synchrones) + le CREATE lourd est lancé EN
    // FOND après le bind (reconcile_expr_indexes_background). Le bump de version DÉSYNC
    // 'analyze_full_done' -> analyze_full_background se relance UNE fois après bind (stats exactes).
    let _ = conn.execute("UPDATE meta SET value='41' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v41 (marqueur : index expression pilotés par reconcile_index_state ; CREATE lourd en fond, anti-crashloop)");
}

fn migrate_v42(conn: &MigTx) {
    // v42 (PHASE 3, infra seule) : registre des index AUTO adaptatifs + compteurs de chaleur.
    // Table d'état uniquement ; la tâche de fond autoindex_maintain_background ne tourne que si
    // PLUME_AUTOINDEX=1 (OFF par défaut) -> v42 est INERTE par défaut. Création de table = gratuit,
    // sûr même si Phase 3 reste OFF. Pas de backfill.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS autoindex(\
         field TEXT PRIMARY KEY, \
         hits INTEGER NOT NULL DEFAULT 0, \
         slow_hits INTEGER NOT NULL DEFAULT 0, \
         last_seen INTEGER NOT NULL DEFAULT 0, \
         indexed INTEGER NOT NULL DEFAULT 0, \
         created INTEGER NOT NULL DEFAULT 0)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='42' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v42 (infra auto-index adaptatif : table autoindex ; OFF par défaut)");
}

fn migrate_v43(conn: &MigTx) {
    // v43 (DONNÉES VIVES, rebrand soc->plume) : aligne la base LIVE déjà semée sur la nomenclature
    // plume_* (les seeds frais sont déjà corrects depuis ce build — ceci répare l'existant). Idempotent :
    //  (a) renomme la clé meta du mode global 'soc_mode' -> 'plume_mode' (collision évitée : on ne
    //      renomme que si plume_mode n'existe pas encore, sinon on supprime la clé héritée résiduelle) ;
    //  (b) répare les panneaux dashboard déjà semés dont la requête vise les anciennes watches auditd
    //      (key=soc_creds / key=soc_etc / key=soc_data) -> key=plume_*.
    // (a) meta soc_mode -> plume_mode
    if conn.query_row("SELECT 1 FROM meta WHERE key='plume_mode'", [], |r| r.get::<_, i64>(0)).is_err() {
        // pas de plume_mode -> on renomme la clé héritée si elle existe (préserve la valeur observe/active)
        let _ = conn.execute("UPDATE meta SET key='plume_mode' WHERE key='soc_mode'", []);
    } else {
        // plume_mode déjà présent (re-run / seed frais) -> purge la clé héritée résiduelle éventuelle
        let _ = conn.execute("DELETE FROM meta WHERE key='soc_mode'", []);
    }
    // (b) panneaux semés : requêtes key=soc_* -> key=plume_*
    let _ = conn.execute("UPDATE panel SET query=REPLACE(query,'key=soc_creds','key=plume_creds') WHERE query LIKE '%key=soc_creds%'", []);
    let _ = conn.execute("UPDATE panel SET query=REPLACE(query,'key=soc_etc','key=plume_etc') WHERE query LIKE '%key=soc_etc%'", []);
    let _ = conn.execute("UPDATE panel SET query=REPLACE(query,'key=soc_data','key=plume_data') WHERE query LIKE '%key=soc_data%'", []);
    let _ = conn.execute("UPDATE meta SET value='43' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v43 (rebrand données vives : meta soc_mode->plume_mode + panneaux key=soc_*->plume_*)");
}

fn migrate_v44(conn: &MigTx) {
    // v44 (PHASE 3a) : PRÉ-AGRÉGATION PAR DIMENSION. (a) crée event_dim_rollup — peuplée
    // INCRÉMENTALEMENT par rollup_events (cold start borné à 24h, jamais de backfill bloquant ICI :
    // pas de scan des 2,3 M lignes au boot) ; (b) RÉÉCRIT les panneaux GROUP-BY par-source PURS déjà
    // semés (prod) en is_soql=0 sur le pré-agrégé -> <100 ms + pré-chauffables (cache_refresh_all_panels
    // filtre is_soql=0). Match par requête EXACTE (+ is_soql=1) : ciblage précis, NO-OP sûr si la
    // requête a divergé (le panneau est alors laissé en l'état, aucune régression).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS event_dim_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
         dim TEXT NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
         PRIMARY KEY(bucket,source,dim,val))",
        [],
    );
    // index de LECTURE des panneaux (SEARCH source=X AND dim=Y AND bucket>=F). La PK (menée par bucket)
    // sert déjà la purge de rétention `WHERE bucket<cutoff`.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_event_dim_rollup_q ON event_dim_rollup(source, dim, bucket)", []);
    // (b) réécriture des panneaux PURS existants. (old_query exact, source, dim, limit, non_empty).
    // Les nouvelles requêtes sont produites par dim_panel_sql -> IDENTIQUES à celles des seeds (pas de dérive).
    let rewrites: &[(&str, &str, &str, i64, bool)] = &[
        ("search source=web | stats count by vhost | sort -count", "web", "vhost", 0, false),
        ("search source=web | stats count by status | sort -count", "web", "status", 0, false),
        ("search source=web | stats count by path | sort -count | head 20", "web", "path", 20, false),
        ("search source=mail verdict=* | stats count by verdict | sort -count", "mail", "verdict", 0, true),
        ("search source=dataaccess | stats count by user | sort -count", "dataaccess", "user", 0, false),
        ("search source=dataaccess | stats count by action | sort -count", "dataaccess", "action", 0, false),
        ("search source=dataaccess | stats count by path | sort -count | head 20", "dataaccess", "path", 20, false),
        ("search source=dataacl | stats count by owner | sort -count", "dataacl", "owner", 0, false),
        ("search source=dataacl | stats count by group | sort -count", "dataacl", "group", 0, false),
        ("search source=kube-rbac | stats count by role | sort -count | head 20", "kube-rbac", "role", 20, false),
        ("search source=kube-rbac | stats count by subject | sort -count | head 20", "kube-rbac", "subject", 20, false),
    ];
    for (old_q, source, dim, limit, non_empty) in rewrites {
        let new_q = dim_panel_sql(source, dim, *limit, *non_empty);
        let _ = conn.execute("UPDATE panel SET query=?1, is_soql=0 WHERE query=?2 AND is_soql=1", params![new_q, old_q]);
    }
    let _ = conn.execute("UPDATE meta SET value='44' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v44 (event_dim_rollup : pré-agrégation par dimension + panneaux GROUP-BY par-source réécrits en is_soql=0)");
}

fn migrate_v45(conn: &MigTx) {
    // v45 (CHANGEMENT 3) : RE-TUNE les règles de détection Cloudflare déjà SEMÉES (prod : ids 25-29) à la
    // télémétrie RÉELLE. La prod CF Free émet du managed_challenge (action=challenged, 1 ruleId/event,
    // dc(ruleId)=1, plusieurs src_ip) -> les anciennes règles (action=blocked / cf_source=ratelimit /
    // dc(ruleId)>8 / cf_source=botManagement) ne matchaient JAMAIS. On remplace par des règles qui
    // matchent le réel. UPDATE des LIGNES EXISTANTES (le seed neuf est déjà corrigé ; guard
    // `query LIKE 'search source=cloudflare%'` -> ne touche QUE des règles CF, no-op sûr si l'id a dérivé).
    // (name, query, op, threshold, severity, interval_s, window_s, mitre) par id.
    let cf: &[(i64, &str, &str, &str, f64, i64, i64, i64, &str)] = &[
        (25, "CF: scan/bot absorbé au edge (>20 challenges managés/IP)", "search source=cloudflare action=challenged | stats count by src_ip | where count > 20 | stats count", ">", 0.0, 3, 300, 900, "T1595.002"),
        (26, "CF: exploit WAF managé (signatures SQLi/RCE/traversal)", "search source=cloudflare action=blocked cf_source=firewallManaged | stats count by src_ip | where count > 3 | stats count", ">", 0.0, 4, 300, 600, "T1190"),
        (27, "CF: L7 flood absorbé depuis une IP (>100 req)", "search source=cloudflare | stats count by src_ip | where count > 100 | stats count", ">", 0.0, 2, 300, 300, "T1498"),
        (28, "CF: recon multi-vhost depuis une IP (>3 vhosts)", "search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count", ">", 0.0, 2, 300, 900, "T1595"),
        (29, "CF: volume de challenges managés (IP distinctes)", "search source=cloudflare action=challenged | stats dc(src_ip)", ">", 20.0, 2, 300, 900, "T1595"),
    ];
    for (id, name, query, op, th, sev, intv, win, mitre) in cf {
        let _ = conn.execute(
            "UPDATE rule SET name=?1, query=?2, is_soql=1, op=?3, threshold=?4, severity=?5, interval_s=?6, window_s=?7, mitre=?8 \
             WHERE id=?9 AND query LIKE 'search source=cloudflare%'",
            params![name, query, op, th, sev, intv, win, mitre, id],
        );
    }
    let _ = conn.execute("UPDATE meta SET value='45' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v45 (re-tune règles CF 25-29 sur la télémétrie réelle : managed_challenge/action=challenged)");
}

fn migrate_v46(conn: &MigTx) {
    // v46 (PHASE 3d) : CLASSIFICATION ADAPTATIVE PAR PANNEAU. Stocke le COÛT mesuré (stats.elapsed_ms)
    // de la requête de CHAQUE panneau -> panel_data route LIVE (coût < PLUME_PANEL_LIVE_MS, défaut 100)
    // vs SWR (coût >= seuil). Clé = panel_id (1 ligne/panneau) -> la classe vaut GLOBALEMENT (où que le
    // panneau soit rendu), PAS par vue ; query_fp lie le coût à la requête courante (un panel_update le
    // rend « inconnu » -> re-mesuré LIVE). Donnée DÉRIVÉE (se re-mesure seule à chaque exécution/refresh)
    // -> CREATE à blanc, AUCUN backfill. Taille bornée (1 ligne / panneau).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS panel_cost(panel_id INTEGER PRIMARY KEY, query_fp TEXT NOT NULL DEFAULT '', \
         cost_ms REAL NOT NULL DEFAULT 0, measured_at INTEGER NOT NULL DEFAULT 0)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='46' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v46 (panel_cost : classification adaptative LIVE/SWR par coût mesuré)");
}

fn migrate_v47(conn: &MigTx) {
    // v47 : MARQUEUR. Ajoute l'index MANQUANT idx_event_category. Le filtre courant `category=auth`
    // n'avait AUCUN index (cf. EXPLAIN : SCAN event) -> full-scan déchiffré des 2,39M lignes. Les
    // autres filtres courants sont déjà couverts : severity (idx_event_sev + idx_event_sev_srcip),
    // source (idx_event_src + idx_event_src_srcip), host/src_ip (composites) -> on n'ajoute QUE category.
    //
    // Le CREATE n'est PAS fait ICI : un CREATE INDEX synchrone sur 2,39M lignes chiffrées bloque le
    // bind -> échec de la sonde de liveness. Il est délégué à
    // ensure_event_category_index_background, lancé EN FOND APRÈS le bind (idempotent, IF NOT EXISTS).
    // Bumper la version DÉSYNCHRONISE 'analyze_full_done' -> analyze_full_background re-tourne UNE fois
    // après bind -> sqlite_stat1 connaît le nouvel index (le planner le choisit). category = TEXT court,
    // cardinalité faible (auth/exec/network/...) -> index peu coûteux (RAM maîtrisée, budget 2 Go).
    let _ = conn.execute("UPDATE meta SET value='47' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v47 (marqueur : idx_event_category créé EN FOND après bind, anti-crashloop ; re-ANALYZE)");
}

fn migrate_v48(conn: &MigTx) {
    // v48 : RÉPARE LES PARSEURS CASSÉS sur l'instance DÉJÀ déployée (les seeds v22/v23 ne re-tournent
    // jamais une fois schema_version franchi -> il faut UPDATE/INSERT les lignes existantes), RE-HOME
    // les détections vers les sources qui portent réellement le signal, et PURGE (une seule fois) les
    // sources-sondes de bootstrap. Borné par schema_version : ne tourne qu'UNE fois.

    // (1) PARSEURS — corrige les builtin existants (match par nom ; no-op si le nom a dérivé). Validés
    //     contre des échantillons réels (journald sudo padding-gauche, fail2ban jails mail/<x>).
    let _ = conn.execute(
        r"UPDATE parser SET pattern=' : .*\bCOMMAND=(?P<command>.+)$' WHERE name='sudo — user + command' AND builtin=1",
        [],
    );
    let _ = conn.execute(
        r"UPDATE parser SET pattern='\((?P<jail>[a-z][\w/-]+)\)' WHERE name='fail2ban — jail' AND builtin=1",
        [],
    );
    // (2) PARSEURS — ajoute les manquants (idempotent par nom). sudo cible (USER=) ; sshd-session
    //     Invalid-user + preauth (Disconnected/Connection closed by invalid user -> src_ip que
    //     extract_src_ip ne voit pas, faute de `from` avant l'IP) ; su cible ; cloudflare url (host+path
    //     du message -> colonne url, peuplée via fields_url à l'ingestion des events).
    let add: &[(&str, &str, &str)] = &[
        ("sudo — utilisateur cible", "sudo", r" : .*\bUSER=(?P<target>\S+)"),
        ("sshd-session — invalid user + IP", "sshd-session", r"Invalid user (?P<user>\S+) from (?P<src_ip>\S+)"),
        ("sshd-session — IP preauth invalide", "sshd-session", r"(?:Disconnected from|Connection closed by) invalid user \S+ (?P<src_ip>[0-9A-Fa-f.:]+)"),
        ("su — cible", "su", r"\(to (?P<target>[\w.+-]+)\)"),
        ("cloudflare — url", "cloudflare", r"CF \S+ \S+ (?P<url>\S+) from "),
    ];
    for (name, src, pat) in add {
        let exists = conn.query_row("SELECT 1 FROM parser WHERE name=?1", params![name], |_| Ok(())).is_ok();
        if !exists {
            let _ = conn.execute("INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES(?1,?2,?3,1,1,?4)", params![name, src, pat, now()]);
        }
    }

    // (3) DÉTECTIONS RE-HOMÉES sur l'instance existante (match exact / guard précis -> no-op si dérivé).
    // Playbook brute-force : sshd (quasi vide, src_ip null) -> sshd-session (les vrais Invalid user).
    let _ = conn.execute(
        "UPDATE playbook SET query='search source=sshd-session severity>=3 | stats count by src_ip | where count > 10' \
         WHERE query='search source=sshd severity>=3 | stats count by src_ip | where count > 10'",
        [],
    );
    // Règle CF 26 : cf_source=waf (jamais émis) -> action=blocked cf_source=firewallManaged (réel).
    let _ = conn.execute(
        "UPDATE rule SET query='search source=cloudflare action=blocked cf_source=firewallManaged | stats count by src_ip | where count > 3 | stats count' \
         WHERE id=26 AND query LIKE '%cf_source=waf%'",
        [],
    );
    // Règle UFW port-scan : dir=inbound excluait silencieusement les 9112 events sans dir -> tolérante.
    let _ = conn.execute(
        "UPDATE rule SET query='search source=ufw | stats dc(dport) by src_ip | where dc > 15 | stats count' \
         WHERE query='search source=ufw dir=inbound | stats dc(dport) by src_ip | where dc > 15 | stats count'",
        [],
    );
    // Panneau mail « Échecs d'auth » : aligne le vocabulaire (auth_fail -> failure) si un panneau a été
    // semé APRÈS v29 (qui ne pouvait pas le rattraper). Idempotent.
    let _ = conn.execute("UPDATE panel SET query=REPLACE(query,'action=auth_fail','action=failure') WHERE query LIKE '%action=auth_fail%'", []);

    // (4) PURGE des sources-SONDES (artefacts de bootstrap/mTLS/selftest : ~1 event chacune) — UNE fois.
    // `integrity` est une VRAIE source (FIM) -> CONSERVÉE. Le DELETE sur `event` déclenche le trigger
    // contentless event_ff_ad (décrément FTS correct) quand FTS est actif ; on purge aussi
    // les deux rollups (clés portant `source`). Les caches in-memory sont vides au boot ; les caches de
    // panneaux (DB) se ré-hydratent au TTL.
    for s in ["agent", "verify", "mtls-test", "selftest", "journal"] {
        let _ = conn.execute("DELETE FROM event WHERE source=?1", params![s]);
        let _ = conn.execute("DELETE FROM event_rollup WHERE source=?1", params![s]);
        let _ = conn.execute("DELETE FROM event_dim_rollup WHERE source=?1", params![s]);
    }

    let _ = conn.execute("UPDATE meta SET value='48' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v48 (parseurs sudo/fail2ban/sshd-session/su/cloudflare réparés ; détections brute-force/CF26/UFW re-homées ; sondes purgées)");
}

fn migrate_v49(conn: &MigTx) {
    // v49 : MARQUEUR (aucune DDL synchrone — anti-crashloop M1/M4). Matérialise sur l'instance déployée
    // les rollups+index ajoutés pour TUER les full-scans SQLCipher des grosses sources (sections F/G de
    // l'audit : auditd `by exe`=13,8s, k8s-log `by severity`=7,7s, etc.). Tout se matérialise EN FOND /
    // INCRÉMENTAL, jamais au boot synchrone :
    //   (a) ROLLUPS par dimension — DIM_ROLLUP_SPECS gagne auditd/sshd-session/kube-audit/k8s-log/
    //       vault-audit/ufw/cloudflare/fail2ban/crowdsec/sudo. event_dim_rollup (table v44) les peuple
    //       INCRÉMENTALEMENT via rollup_events (cold start borné PLUME_ROLLUP_DIM_BACKFILL=24h, forward-
    //       fill ensuite) -> AUCUN backfill bloquant des 2,6M lignes ici. La rollup-route les sert dès
    //       qu'elles existent (served_from:rollup + approx/truncated pour les dims cappées top-N).
    //   (b) INDEX EXPRESSION — HOT_FIELDS gagne verb,resource,operation (filtres d'audit). Le CREATE est
    //       délégué à reconcile_expr_indexes_background (après le bind, 1 index à la fois, lock writer
    //       borné), JAMAIS ici : un CREATE INDEX sur l'historique chiffré bloquerait le bind -> échec de
    //       la sonde de liveness. expr_indexes_all_present rattrape les 3 manquants.
    // Bumper la version DÉSYNCHRONISE 'analyze_full_done' -> analyze_full_background re-tourne UNE fois
    // après bind -> sqlite_stat1 connaît les nouveaux index expression (le planner les choisit ;
    // SCAN->SEARCH USING idx_ev_f_{verb,resource,operation}).
    let _ = conn.execute("UPDATE meta SET value='49' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v49 (marqueur : rollups par-dim auditd/kube-audit/vault-audit/... peuplés incrémental + index expr verb/resource/operation créés EN FOND ; re-ANALYZE)");
}

fn migrate_v50(conn: &MigTx) {
    // v50 : POSE LES RÈGLES DE DÉTECTION des nouveaux signaux de télémétrie (minio-audit backup-delete,
    // auditd tamper, intégrité suid/persistance, conntrack beaconing, vault secret-read) sur l'instance
    // DÉJÀ déployée. Calque le pattern v48 : le seed (seed_detection_rules) ne re-tourne JAMAIS une fois
    // son flag `seeded_detection_rules` posé -> il faut INSÉRER ici, côté live, les mêmes règles (source
    // unique DETECTION_RULES_V50). Ces 7 règles continuent après les ids existants 1-29 (auto-increment
    // -> 30+). Dédup d'alerte : clé stable `rule-{id}` calculée à l'éval -> 1 notif/épisode, ré-armée au
    // retour sous le seuil (pas de re-notif par fenêtre — mécanique partagée run_due_rules).
    //
    // GARDE ANTI-DOUBLON : ne s'exécute QUE si le seed a déjà tourné (flag présent). Sur une DB NEUVE,
    // migrate() précède les seeds (cf. main : migrate -> seed_*) donc le flag est ABSENT ici -> on SKIP,
    // et seed_detection_rules créera ces règles lui-même (zéro doublon). Sur l'instance live (seedée de
    // longue date, 29 règles) le flag est présent -> on INSÈRE. IDEMPOTENT : chaque INSERT est borné par
    // « n'existe pas déjà par nom » -> une re-tentative de migrate (crash avant le bump) ne duplique pas.
    let seeded = conn
        .query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(()))
        .is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V50 {
            let exists = conn
                .query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(()))
                .is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='50' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v50 (règles de détection : minio backup-delete + auditd tamper + intégrité suid/persistance + conntrack beaconing + vault secret-read)");
}

fn migrate_v51(conn: &MigTx) {
    // v51 : RÈGLE 37 (durcissement standalone, item 2) — self-detection du brute-force sur l'auth
    // Plume (source=plume-auth, T1110). MÊME mécanique EXACTE que v50 : on n'INSÈRE QUE si le seed a
    // déjà tourné (flag seeded_detection_rules présent = instance live, où seed_detection_rules ne
    // re-crée plus). Sur PVC NEUF migrate() précède les seeds -> flag absent -> on SKIP, et
    // seed_detection_rules crée la règle lui-même (id 37, après les 36 existantes) -> zéro doublon.
    // IDEMPOTENT : INSERT borné par « n'existe pas déjà par nom ». Dédup d'alerte = clé `rule-{id}`
    // (mécanique partagée run_due_rules). Source unique : DETECTION_RULES_V51.
    let seeded = conn
        .query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(()))
        .is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V51 {
            let exists = conn
                .query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(()))
                .is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='51' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v51 (règle 37 : self-detection brute-force auth Plume — source=plume-auth, T1110)");
}

fn migrate_v52(conn: &MigTx) {
    // v52 : BANLIST MATÉRIALISÉE (`banned_ip`) + dashboard « Banni / Pass » + règle « attaquant actif
    // NON banni ». Objectif : surfacer les IPs qui ATTAQUENT mais ne sont PAS encore bannies, SANS la
    // requête naïve (`stats by src_ip` sur 140k web + join) qui timeoutait (>60s). Socle : une table
    // banlist (join cheap) peuplée INCRÉMENTALEMENT par materialize_banned_ip (watermark banned_ip_wm,
    // jamais de full-scan), des panneaux SWR (calculés en fond, servis instantanément) et une règle
    // bornée par sa fenêtre. DDL pure (CREATE TABLE/INDEX) idempotente -> sûre au boot (pas de scan).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS banned_ip(\
         src_ip TEXT NOT NULL, source TEXT NOT NULL, label TEXT, \
         first_seen INTEGER, last_seen INTEGER, PRIMARY KEY(src_ip, source))",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_banned_ip_srcip ON banned_ip(src_ip)", []);
    // RÈGLE v52 sur l'instance DÉJÀ déployée — MÊME mécanique EXACTE que v50/v51 : on n'INSÈRE QUE si le
    // seed a déjà tourné (flag seeded_detection_rules présent = instance live, où seed_detection_rules ne
    // re-crée plus). Sur PVC NEUF migrate() précède les seeds -> flag absent -> on SKIP, et
    // seed_detection_rules crée la règle lui-même -> zéro doublon. IDEMPOTENT : INSERT borné par « n'existe
    // pas déjà par nom ». Dédup d'alerte = clé `rule-{id}`. Source unique : DETECTION_RULES_V52.
    let seeded = conn
        .query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(()))
        .is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V52 {
            let exists = conn
                .query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(()))
                .is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    // panneaux : idempotents PAR NOM (seed_banpass_dashboard ne crée rien si le dashboard existe), donc
    // sûrs sur l'instance live ET sur PVC neuf (le boot les re-tente, no-op). Cf. v37 qui appelait déjà
    // ensure_rollup_srcip_host_panels depuis migrate(). panel_cache_ttl_s>0 dépend de la colonne ajoutée
    // par une migration antérieure (déjà appliquée à ce stade : v52 > celle-ci).
    seed_banpass_dashboard(conn);
    let _ = conn.execute("UPDATE meta SET value='52' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v52 (banned_ip + dashboard « Banni / Pass » + règle « attaquant actif non banni » — T1595)");
}

fn migrate_v53(conn: &MigTx) {
    // v53 : RÈGLE YARA (match malware/IOC -> source=yara category=malware, T1204). MÊME mécanique EXACTE
    // que v50/v51/v52 : on n'INSÈRE QUE si le seed a déjà tourné (flag seeded_detection_rules présent =
    // instance live, où seed_detection_rules ne re-crée plus). Sur PVC NEUF migrate() précède les seeds
    // -> flag absent -> on SKIP, et seed_detection_rules crée la règle lui-même -> zéro doublon.
    // IDEMPOTENT : INSERT borné par « n'existe pas déjà par nom ». Dédup d'alerte = clé `rule-{id}`.
    // Source unique : DETECTION_RULES_V53. event-driven : OFF par défaut (le collecteur host yara.sh est
    // inerte tant que `yara` absent / aucune règle déposée) -> la règle ne tire QUE sur un match réel.
    let seeded = conn
        .query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(()))
        .is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V53 {
            let exists = conn
                .query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(()))
                .is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='53' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v53 (règle YARA : match malware/IOC — source=yara, T1204 ; intégration OFF par défaut)");
}

fn migrate_v54(conn: &MigTx) {
    // v54 : DEBRUITAGE self/opérateur sur l'instance DÉJÀ déployée. Le navigateur de l'opérateur sur le
    // dashboard SOC (IP opérateur configurée via PLUME_OPERATOR_IPS, ex. doc 203.0.113.7 / 2001:db8::/32) génère un volume massif de challenges CF
    // + 4xx web qui REMONTENT en tête des vues « attaquants/scan/recon » et SUR-DÉCLENCHENT les règles.
    // On INJECTE le placeholder `__OPERATOR_EXCL__` (et `__SELF_EXCL__` pour le vhost self) dans les
    // requêtes des panneaux/règles ORIENTÉS MENACE EXTERNE — substitué à la compilation (configurable
    // PLUME_OPERATOR_IPS / PLUME_SELF_HOSTS). Calque le pattern v45/v48 : UPDATE des lignes EXISTANTES
    // (le seed neuf est déjà corrigé ; sur PVC neuf migrate() précède les seeds -> ces UPDATE sont no-op,
    // les seeds créent directement la version corrigée). IDEMPOTENT : guard `NOT LIKE '%__OPERATOR_EXCL__%'`
    // / match exact de l'ancienne requête -> jamais de double-injection, ne tourne qu'une fois (v<54).
    // JUDICIEUX : on ne touche QUE les vues « externe/menace » ; les vues où l'activité opérateur est le
    // signal voulu (dataaccess/auth/sudo, purple-team UFW/portscan/web-scan, egress) restent INTACTES.

    // (1) RÈGLES CF 25-29 (is_soql=1) : exclusion de l'IP opérateur par src_ip (challenges/flood/recon).
    let cf: &[(i64, &str)] = &[
        (25, "search source=cloudflare action=challenged __OPERATOR_EXCL__ | stats count by src_ip | where count > 20 | stats count"),
        (26, "search source=cloudflare action=blocked cf_source=firewallManaged __OPERATOR_EXCL__ | stats count by src_ip | where count > 3 | stats count"),
        (27, "search source=cloudflare __OPERATOR_EXCL__ | stats count by src_ip | where count > 100 | stats count"),
        (28, "search source=cloudflare __OPERATOR_EXCL__ | stats dc(vhost) by src_ip | where dc > 3 | stats count"),
        (29, "search source=cloudflare action=challenged __OPERATOR_EXCL__ | stats dc(src_ip)"),
    ];
    for (id, q) in cf {
        let _ = conn.execute(
            "UPDATE rule SET query=?1 WHERE id=?2 AND query LIKE 'search source=cloudflare%' AND query NOT LIKE '%__OPERATOR_EXCL__%'",
            params![q, id],
        );
    }

    // (2) RÈGLE 38 « attaquant actif NON banni » (is_soql=0) : exclusion opérateur dans les 2 branches.
    // Littéral porteur du placeholder (forme historique v54). NB : la migration v55 ci-dessous RÉVOQUE
    // cette exclusion sur la règle 38 — angle mort détection — et la const ATTACKER_UNMITIGATED_RULE_SQL
    // est désormais la forme CANONIQUE PROPRE (sans exclusion). Guard par nom + NOT LIKE token.
    const ATTACKER_UNMITIGATED_RULE_SQL_V54_EXCL: &str =
        "SELECT COUNT(*) AS non_mitiges FROM ( \
           SELECT a.src_ip FROM ( \
             SELECT src_ip, SUM(c) AS activite FROM ( \
               SELECT src_ip, COUNT(*) AS c FROM event \
                 WHERE source='cloudflare' AND ts>=__FROM__ AND json_extract(fields,'$.action')='challenged' \
                   AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ GROUP BY src_ip \
               UNION ALL \
               SELECT src_ip, COUNT(*) AS c FROM event \
                 WHERE source='web' AND ts>=__FROM__ AND CAST(json_extract(fields,'$.status') AS INTEGER)>=400 \
                   AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ GROUP BY src_ip \
             ) GROUP BY src_ip HAVING activite > 20 \
           ) a \
           LEFT JOIN banned_ip b ON b.src_ip=a.src_ip \
           WHERE b.src_ip IS NULL \
         )";
    let _ = conn.execute(
        "UPDATE rule SET query=?1 WHERE name='Attaquant actif NON banni (web 4xx / CF challenged sans mitigation)' \
         AND is_soql=0 AND query NOT LIKE '%__OPERATOR_EXCL__%'",
        params![ATTACKER_UNMITIGATED_RULE_SQL_V54_EXCL],
    );

    // (3) PANNEAUX web (is_soql=1) : « Top clients externes » (exclut l'IP opérateur) et « Erreurs 4xx/5xx »
    // (exclut l'IP opérateur ET le vhost de l'UI elle-même). Match EXACT de l'ancienne requête -> no-op
    // si déjà corrigé (idempotent). Les panneaux GROUP-BY purs (vhost/status/path) restent INTACTS (inventaire).
    let _ = conn.execute(
        "UPDATE panel SET query='search source=web scope=external __OPERATOR_EXCL__ | stats count by src_ip | sort -count | head 20' \
         WHERE query='search source=web scope=external | stats count by src_ip | sort -count | head 20'",
        [],
    );
    let _ = conn.execute(
        "UPDATE panel SET query='search source=web __OPERATOR_EXCL__ __SELF_EXCL__ | where severity>=2 | sort -ts | table vhost,path,status,src_ip,ua' \
         WHERE query='search source=web | where severity>=2 | sort -ts | table vhost,path,status,src_ip,ua'",
        [],
    );

    // (4) PANNEAUX « Banni / Pass » (is_soql=0) : « Attaquants NON mitigés » + « Couverture de ban » ->
    // exclusion opérateur (mêmes consts que le seed). Guard par titre + NOT LIKE token (idempotent).
    let _ = conn.execute(
        "UPDATE panel SET query=?1 WHERE title='Attaquants NON mitigés (non bannis, fenêtre)' \
         AND is_soql=0 AND query NOT LIKE '%__OPERATOR_EXCL__%'",
        params![BANPASS_UNMITIGATED_SQL],
    );
    let _ = conn.execute(
        "UPDATE panel SET query=?1 WHERE title='Couverture de ban (% attaquants déjà bannis)' \
         AND is_soql=0 AND query NOT LIKE '%__OPERATOR_EXCL__%'",
        params![BANPASS_COVERAGE_SQL],
    );

    let _ = conn.execute("UPDATE meta SET value='54' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v54 (debruitage self/opérateur : exclusion IP opérateur sur règles CF 25-29 + règle 38 « attaquant non banni » + panneaux banpass + web « top clients externes »/« erreurs 4xx-5xx » ; configurable PLUME_OPERATOR_IPS/PLUME_SELF_HOSTS)");
}

fn migrate_v55(conn: &MigTx) {
    // v55 : CORRECTIF SÉCURITÉ — RETRAIT de l'exclusion self/opérateur des RÈGLES DE DÉTECTION (v54
    // l'y avait injectée -> ANGLE MORT : si la machine opérateur est compromise et attaque depuis son
    // IP, les règles ne déclenchent plus). PRINCIPE : collecte + détection = ZÉRO exclusion (on doit
    // TOUT voir, y compris une attaque venant de l'IP opérateur) ; l'exclusion reste UNIQUEMENT sur les
    // PANNEAUX d'affichage (lisibilité ; donnée intacte en base + l'explore voit tout). Un faux positif
    // (l'opérateur apparaît dans une alerte) vaut mieux qu'un faux négatif sur un SOC.
    //
    // On RÉVOQUE donc l'exclusion sur les RÈGLES CF 25-29 + la règle 38 « attaquant non banni » (revenir
    // au SQL/soql SANS `__OPERATOR_EXCL__`). Mécanique des migrations précédentes (UPDATE idempotent des
    // lignes EXISTANTES ; sur PVC neuf migrate() précède les seeds -> no-op, les seeds posent déjà la
    // forme PROPRE). IDEMPOTENT : guard `query LIKE '%__OPERATOR_EXCL__%'` -> ne fire que si l'exclusion
    // est présente, ne tourne qu'une fois (v<55). Les PANNEAUX (banpass + web top clients/erreurs) v54
    // gardent leur exclusion -> on NE les touche PAS ici.

    // (1) RÈGLES CF 25-29 (is_soql=1) : retour à la forme SANS exclusion (détecte TOUTES les IPs).
    let cf_clean: &[(i64, &str)] = &[
        (25, "search source=cloudflare action=challenged | stats count by src_ip | where count > 20 | stats count"),
        (26, "search source=cloudflare action=blocked cf_source=firewallManaged | stats count by src_ip | where count > 3 | stats count"),
        (27, "search source=cloudflare | stats count by src_ip | where count > 100 | stats count"),
        (28, "search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count"),
        (29, "search source=cloudflare action=challenged | stats dc(src_ip)"),
    ];
    for (id, q) in cf_clean {
        let _ = conn.execute(
            "UPDATE rule SET query=?1 WHERE id=?2 AND query LIKE 'search source=cloudflare%' AND query LIKE '%__OPERATOR_EXCL__%'",
            params![q, id],
        );
    }

    // (2) RÈGLE 38 « attaquant actif NON banni » (is_soql=0) : retour à ATTACKER_UNMITIGATED_RULE_SQL
    // (forme CANONIQUE PROPRE, sans exclusion). Guard par nom + LIKE token (ne fire que si exclu présente).
    let _ = conn.execute(
        "UPDATE rule SET query=?1 WHERE name='Attaquant actif NON banni (web 4xx / CF challenged sans mitigation)' \
         AND is_soql=0 AND query LIKE '%__OPERATOR_EXCL__%'",
        params![ATTACKER_UNMITIGATED_RULE_SQL],
    );

    let _ = conn.execute("UPDATE meta SET value='55' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v55 (correctif sécurité : RETRAIT de l'exclusion self/opérateur des RÈGLES de détection CF 25-29 + règle 38 « attaquant non banni » — angle mort ; l'exclusion reste sur les PANNEAUX d'affichage seuls)");
}

fn migrate_v56(conn: &MigTx) {
    // v56 : RAFFINEMENTS PARSING + HEARTBEAT (audit cohérence). Mécanique v48-v55 (idempotent, borné par
    // schema_version, ne tourne qu'UNE fois ; sur PVC neuf migrate() court v0->56 -> le parseur ci-dessous
    // est aussi posé pour une base fraîche).
    //
    // (A) HEARTBEAT (event_based) — AUCUNE écriture DB : le flag vit dans COLLECTORS (code), pas en base.
    //     L'élargissement (dataaccess/integrity/k8s-log/crowdsec/fail2ban/ufw/portscan -> ÉVÉNEMENTIELS ;
    //     web/kube-audit -> CONTINUS) prend effet au redéploiement du binaire. Tracé ici pour mémoire :
    //     les capteurs rendus calmes par le débruitage ne crieront plus « muet » à tort, et les vrais
    //     continus (web/kube-audit/auditd/resources) alertent toujours s'ils se taisent.
    //
    // (B) PARSEUR MAIL — verdict (backstop). La voie NORMALE d'extraction du verdict amavis
    //     (Passed/Blocked CLEAN/SPAM/INFECTED/BANNED) est le COLLECTEUR mail.sh, qui pose DÉJÀ
    //     fields.verdict pour TOUTES les variantes (et fields.virus sur INFECTED). Ce parseur n'ajoute
    //     donc QUE de la défense en profondeur : si une ligne amavis atteint le daemon par une autre voie
    //     (journal/loki) sans que mail.sh ait posé le champ, parsers_apply (fusion SANS écrasement)
    //     l'extrait. ACTÉ + NOTÉ : le verdict est intrinsèquement RARE — amavis ne loggue un verdict QUE
    //     sur les messages réellement scannés (6/2362 events sur l'instance) ; les events de
    //     connexion/auth/postscreen/reject n'en portent pas -> on NE FABRIQUE PAS de faux verdict (le
    //     motif est ancré sur `amavis[<pid>]` et ne matche ni dovecot-login ni postfix-reject). Idempotent
    //     par nom (calque v48). Validé via parser-test sur échantillons réels (Passed CLEAN / Blocked
    //     INFECTED -> match ; dovecot/postfix -> no-match).
    //
    // (C) fail2ban (jail) & cloudflare (url) : DÉJÀ corrigés en v48 (8adfd56) — jail `[\w/-]` capte les
    //     jails mail/<x> (mail/postfix, mail/dovecot) ; url `CF \S+ \S+ <url> from ` capte action=blocked
    //     ET challenged. VÉRIFIÉ sur l'instance déployée : 0 NULL sur les events des ~90 dernières minutes
    //     (jail comme url). Le résidu NULL (~2815 jail / CF anciens) date d'AVANT v48 — les parseurs
    //     n'agissent qu'en AVANT (l'historique reste tel quel). Rien à re-corriger ici (garde-fou : ne pas
    //     toucher un parseur qui marche).
    let exists = conn
        .query_row("SELECT 1 FROM parser WHERE name='mail — verdict amavis'", [], |_| Ok(()))
        .is_ok();
    if !exists {
        let _ = conn.execute(
            "INSERT INTO parser(name,source,pattern,enabled,builtin,created) VALUES('mail — verdict amavis','mail',?1,1,1,?2)",
            params![r"\bamavis\[\d+\].*?(?P<verdict>(?:Passed|Blocked) [A-Z][A-Z-]+)", now()],
        );
    }
    let _ = conn.execute("UPDATE meta SET value='56' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v56 (heartbeat event_based élargi côté code : dataaccess/integrity/k8s-log/crowdsec/fail2ban/ufw/portscan ÉVÉNEMENTIELS, web/kube-audit CONTINUS ; parseur mail verdict amavis backstop ; fail2ban/cloudflare déjà OK depuis v48)");
}

fn migrate_v57(conn: &MigTx) {
    // v57 : DEAD-MAN'S-SWITCH CrowdSec — distingue « 0 attaque (normal) » de « moteur CrowdSec mort/cassé »
    // (incident : moteur aveugle 3,3 j sans alerte, car CrowdSec est ÉVÉNEMENTIEL -> son silence est toléré).
    //
    // (A) RÈGLE de détection « CrowdSec scénarios cassés (moteur dégradé) » (source=crowdsec category=health,
    //     fields.scenarios_broken>0 ; T1562.001, severity 4) posée sur l'instance DÉJÀ déployée — MÊME
    //     mécanique EXACTE que v50-v53 : on n'INSÈRE QUE si le seed a déjà tourné (flag
    //     seeded_detection_rules présent = instance live, où seed_detection_rules ne re-crée plus). Sur PVC
    //     NEUF migrate() précède les seeds -> flag absent -> on SKIP, et seed_detection_rules crée la règle
    //     lui-même -> zéro doublon. IDEMPOTENT : INSERT borné par « n'existe pas déjà par nom ». Dédup
    //     d'alerte = clé `rule-{id}`. Source unique : DETECTION_RULES_V57.
    //
    // (B) HEARTBEAT (event_based) — AUCUNE écriture DB : le NOUVEAU collecteur CONTINU `crowdsec-health`
    //     vit dans COLLECTORS (code), pas en base ; il prend effet au redéploiement du binaire. Le
    //     collecteur host crowdsec.sh émet désormais un battement de santé (source=crowdsec category=health)
    //     à CHAQUE run (timer 5 min) MÊME à 0 ban -> son SILENCE > 5x l'intervalle (25 min) lève une alerte
    //     MUET (collecteur/moteur mort) tandis que la ligne `crowdsec` (bans) reste ÉVÉNEMENTIELLE et ne
    //     crie jamais sur le calme normal des bans. Tracé ici pour mémoire.
    let seeded = conn
        .query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(()))
        .is_ok();
    if seeded {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V57 {
            let exists = conn
                .query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(()))
                .is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='57' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v57 (dead-man's-switch CrowdSec : règle « scénarios cassés / moteur dégradé » source=crowdsec category=health, T1562.001 + collecteur CONTINU crowdsec-health côté code — silence du battement de santé = collecteur/moteur CrowdSec mort)");
}

fn migrate_v58(conn: &MigTx) {
    // v58 : PANNEAU d'affichage « Cloudflare (hors self) » — surface l'activité CF EXTERNE réelle en
    // débruitant l'auto-trafic opérateur (son navigateur sur le dashboard, souvent l'essentiel des events
    // source=cloudflare) ET le vhost de l'UI, via les placeholders d'AFFICHAGE __OPERATOR_EXCL__/__SELF_EXCL__
    // (substitués SEULEMENT dans compile_panel_sql, jamais dans les règles de détection ni la collecte).
    // Posé sur le dashboard « Trafic web » (édge HTTP) déjà déployé. IDEMPOTENT : on n'INSÈRE que si le
    // dashboard existe ET que le panneau n'y est pas déjà (NOT EXISTS par titre). Sur PVC NEUF migrate()
    // PRÉCÈDE seed_web_dashboard -> « Trafic web » absent ici -> on SKIP, et seed_web_dashboard crée le
    // panneau lui-même (entrée de seed ajoutée) -> zéro doublon. Le collecteur CONTINU k8s-log-health
    // (FIX 4) est CODE-only (vit dans COLLECTORS) -> AUCUN seed DB, prend effet au redéploiement du binaire.
    if let Ok(did) = conn.query_row(
        "SELECT id FROM dashboard WHERE name='Trafic web'", [], |r| r.get::<_, i64>(0),
    ) {
        let exists = conn
            .query_row(
                "SELECT 1 FROM panel WHERE dashboard_id=?1 AND title='Cloudflare (hors self)'",
                params![did], |_| Ok(()),
            )
            .is_ok();
        if !exists {
            let pos: i64 = conn
                .query_row("SELECT COALESCE(MAX(position),-1)+1 FROM panel WHERE dashboard_id=?1", params![did], |r| r.get(0))
                .unwrap_or(0);
            let _ = conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) \
                 VALUES(?1,'Cloudflare (hors self)','search source=cloudflare __OPERATOR_EXCL__ __SELF_EXCL__ | stats count by src_ip | sort -count | head 30',1,'table',?2,2)",
                params![did, pos],
            );
        }
    }
    let _ = conn.execute("UPDATE meta SET value='58' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v58 (panneau d'affichage « Cloudflare (hors self) » sur « Trafic web » : active CF externe débruitée de l'opérateur/self ; + collecteur CONTINU k8s-log-health côté code = dead-man's-switch pod-logs)");
}

fn migrate_v59(conn: &MigTx) {
    // banned_ip = bans RÉELS (fail2ban+crowdsec+portscan) ; retrait 'ufw' (drop paquet sur port fermé ≠ ban)
    let _ = conn.execute("DELETE FROM banned_ip WHERE source='ufw'", []);
    // relabel honnête : total CUMULÉ sur la fenêtre retenue, pas « actuellement banni » (cf admin-console)
    let _ = conn.execute("UPDATE panel SET title='IPs bannies — cumul (fail2ban+crowdsec, fenêtre retenue)' WHERE title='IPs bannies (dédupliqué, total)'", []);
    // acteur de l'acquittement d'alerte (idempotent : `let _ =` avale l'erreur si la colonne pré-existe)
    let _ = conn.execute("ALTER TABLE alert ADD COLUMN acked_by TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='59' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v59 (banned_ip sans ufw + relabel ; alert.acked_by)");
}

fn migrate_v60(conn: &MigTx) {
    // v60 : PERSONNALISATION PHASE 1 — colonne `managed` sur parser/rule/playbook : 0 = builtin/seed,
    // 1 = overlay-file (config.d, source git versionnée, posée par load_overlays au boot), 2 = ad-hoc UI
    // (CRUD). Permet à un overlay de GAGNER durablement sur un builtin du même nom et de survivre au
    // re-seed. IDEMPOTENT : `let _ =` avale le « duplicate column » si la colonne pré-existe (fresh-DB
    // l'a déjà via les CREATE TABLE supra).
    let _ = conn.execute("ALTER TABLE parser ADD COLUMN managed INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN managed INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE playbook ADD COLUMN managed INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("UPDATE meta SET value='60' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v60 (colonne managed: parser/rule/playbook overlay)");
}

fn migrate_v61(conn: &MigTx) {
    // v61 : LOOKUP — tables d'enrichissement par référence pour l'opérateur SOQL `lookup <name>
    // <keyfield> [OUTPUT cols]`. `lookup_kv` : paires (name,key) -> `val` (JSON des colonnes de sortie),
    // jointes en LEFT JOIN par le compilo (guatx_core::soql). `lookup_meta` : métadonnées par lookup
    // (champ-clé, colonnes exposées, horodatage) pour l'endpoint admin /api/lookups et l'UI à venir.
    // CREATE IF NOT EXISTS -> fresh-DB (db/schema.sql) ET base existante CONVERGENT (idempotent).
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS lookup_kv(name TEXT NOT NULL, key TEXT NOT NULL, val TEXT NOT NULL, PRIMARY KEY(name,key));\
         CREATE TABLE IF NOT EXISTS lookup_meta(name TEXT PRIMARY KEY, key_field TEXT, cols TEXT, updated INTEGER);",
    );
    let _ = conn.execute("UPDATE meta SET value='61' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v61 (tables lookup_kv/lookup_meta : enrichissement SOQL `lookup`)");
}

fn migrate_v62(conn: &MigTx) {
    // v62 : COHÉRENCE « Banni / Pass » — le cumul des IPs bannies et la banlist par source ignoraient le
    // time picker (figés tout-historique) alors que « attaquants/couverture » honorent __FROM__. On les
    // borne par `banned_ip.last_seen >= __FROM__` (picker='Tout' -> from=0 -> tout-temps reste joignable),
    // et on passe le cumul mono-ligne en viz `stat` (supprime la colonne `#`=1 inutile du rendu table).
    let _ = conn.execute("UPDATE panel SET query='SELECT COUNT(DISTINCT src_ip) AS ips_bannies FROM banned_ip WHERE last_seen >= __FROM__', title='IPs bannies (dernier ban dans la fenêtre)', viz='stat' WHERE title='IPs bannies — cumul (fail2ban+crowdsec, fenêtre retenue)'", []);
    let _ = conn.execute("UPDATE panel SET query='SELECT source, COUNT(DISTINCT src_ip) AS ips FROM banned_ip WHERE last_seen >= __FROM__ GROUP BY source ORDER BY ips DESC' WHERE title='Banlist par source'", []);
    let _ = conn.execute("UPDATE meta SET value='62' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v62 (Banni/Pass: cumul/banlist fenêtrées last_seen + viz stat)");
}

fn migrate_v63(conn: &MigTx) {
    // v63 : SPLIT de la vue « Sécurité » (11 dashboards / 58 panneaux empilés sur UNE page) en vues
    // FOCALISÉES + adoption de l'orphelin OBS. GARDÉ — on ne RE-HOME que les dashboards encore dans la
    // vue Sécurité héritée (view_id=2 = défaut posé par les seeds) OU orphelins (view_id IS NULL : cas
    // « Infra & logs (OBS) »). Le garde `(view_id=2 OR view_id IS NULL)` signifie : JAMAIS un dashboard
    // que l'OPÉRATEUR a déjà rangé ailleurs (view_id ≠ 2). IDEMPOTENT : au 2e passage les dashboards sont
    // à leur NOUVEAU view_id (≠2) -> le WHERE ne matche plus -> no-op. On NE TOUCHE QUE
    // dashboard.view_id/collapsed (zéro écrasement de panneaux/layout utilisateur).
    let soc = find_or_create_view(conn, "SOC");
    let detection = find_or_create_view(conn, "Détection");
    let reseau = find_or_create_view(conn, "Réseau & Web");
    let mail = find_or_create_view(conn, "Mail");
    let data = find_or_create_view(conn, "Accès données");
    let infra_acc = find_or_create_view(conn, "Accès infra");
    let obs = find_or_create_view(conn, "Infra & logs");
    // (nom EXACT du dashboard, vue cible, collapsed) — déplacement PAR NOM, primaire=déplié(0), reste=replié(1).
    let moves: [(&str, Option<i64>, i64); 12] = [
        ("Vue d'ensemble (rapide)", soc, 1),            // SOC garde « SOC — Vue d'ensemble » (non touché)
        ("Sécurité & détection", detection, 0),
        ("Banni / Pass", detection, 1),
        ("Trafic web", reseau, 0),
        ("Réseau sortant (egress)", reseau, 1),
        ("Mail — flux & verdicts", mail, 0),
        ("Accès données (Varonis)", data, 0),
        ("Carte d'accès (Varonis)", data, 1),
        ("RBAC k8s (Varonis)", infra_acc, 0),
        ("MinIO / S3 (Varonis)", infra_acc, 1),
        ("Vault — accès secrets (Varonis)", infra_acc, 1),
        ("Infra & logs (OBS)", obs, 0),                 // orphelin (view_id NULL) adopté par « Infra & logs »
    ];
    for (name, vid, collapsed) in moves {
        if let Some(vid) = vid {
            // Param bindings -> pas d'échappement SQL des apostrophes (Vue d'ensemble / Carte d'accès…).
            let _ = conn.execute(
                "UPDATE dashboard SET view_id=?1, collapsed=?2 WHERE name=?3 AND (view_id=2 OR view_id IS NULL)",
                params![vid, collapsed, name],
            );
        }
    }
    let _ = conn.execute("UPDATE meta SET value='63' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v63 (split vue Sécurité en vues focalisées + adoption OBS)");
}

fn migrate_v64(conn: &MigTx) {
    // v64 : FRAÎCHEUR RÉELLE — colonne `last_ts` (vrai MAX(ts) du dernier event par (source,bucket)) sur
    // event_rollup. Le panneau Fraîcheur lisait MAX(bucket) = PLANCHER de l'heure (age dérivait 0->59 min
    // puis « rajeunissait » au changement d'heure). rollup_events écrit désormais `MAX(ts) AS last_ts` à
    // chaque ré-agrégation de la fenêtre chaude (heure courante+précédente, ~120 s) -> compute_freshness
    // lit COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)) = vrai âge en secondes, fallback plancher horaire.
    // ALTER ADD COLUMN avec DEFAULT 0 : O(1) (pas de réécriture), AUCUN backfill scan de `event` (les
    // anciennes lignes restent à 0 et retombent sur le fallback plancher — elles se réécrivent au vrai
    // last_ts dès leur prochaine ré-agrégation). IDEMPOTENT : `let _ =` avale le « duplicate column » si la
    // colonne pré-existe (fresh-DB l'a déjà via le CREATE event_rollup_new de v33).
    let _ = conn.execute("ALTER TABLE event_rollup ADD COLUMN last_ts INTEGER NOT NULL DEFAULT 0", []);
    // watermark chaud réinitialisé -> le prochain tick rollup_events ré-agrège la fenêtre chaude et
    // matérialise last_ts pour toute source active (les sources continues passent du plancher au vrai ts).
    let _ = conn.execute("DELETE FROM meta WHERE key='event_rollup_wm'", []);
    let _ = conn.execute("UPDATE meta SET value='64' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v64 (event_rollup.last_ts : Fraîcheur âge réel vs plancher horaire)");
}

fn migrate_v65(conn: &MigTx) {
    // v65 : ADMINISTRATION UI (#1b). `setting(scope,key,value)` = réglages runtime tenant-scopables —
    // aujourd'hui la RÉTENTION éditable à chaud (retention_run relit la BDD ; la BDD gagne sur env/conf).
    // `source_settings(scope,source,...)` = métadonnées DISPLAY-only par source (attendu/inattendu, label,
    // note, catégorie) — AUCUN impact ingest/collecte/règle (D1 option b ; mute d'affichage D4 et override
    // rétention par-source D3 volontairement DIFFÉRÉS, colonnes non créées). `scope`/couture multi-tenant
    // (#2) = toujours 'global', non exposée en UI. CREATE IF NOT EXISTS -> fresh-DB (db/schema.sql) ET base
    // existante CONVERGENT (idempotent, re-jouable).
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS setting(\
           scope TEXT NOT NULL DEFAULT 'global', key TEXT NOT NULL, value TEXT NOT NULL, \
           updated INTEGER, updated_by TEXT, PRIMARY KEY(scope, key));\
         CREATE TABLE IF NOT EXISTS source_settings(\
           scope TEXT NOT NULL DEFAULT 'global', source TEXT NOT NULL, \
           expected INTEGER NOT NULL DEFAULT 1, label TEXT, note TEXT, category TEXT, \
           updated INTEGER, updated_by TEXT, PRIMARY KEY(scope, source));",
    );
    let _ = conn.execute("UPDATE meta SET value='65' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v65 (setting + source_settings : Administration UI rétention/sources)");
}

fn migrate_v66(conn: &MigTx) {
    // v66 : FONDATION MULTI-TENANT (#2a-2a) — AXE ENVIRONNEMENT intra-tenant. ALTER ADDITIF
    // `env_id TEXT NOT NULL DEFAULT 'prod'` : metadata-only via DEFAULT (SQLite n'écrit PAS les
    // 2,4 M lignes — la valeur par défaut est servie à la lecture), donc cheap même sur grosse base ;
    // toutes les lignes existantes = env 'prod'. Portée = tables de DONNÉE client scopables par
    // environnement UNIQUEMENT (télémétrie/détection/réponse) : event, alert, metric, snapshot,
    // action, incident, incident_item, banned_ip. On N'AJOUTE PAS env_id au contenu de détection ni
    // à la config UI (rule/parser/playbook/dashboard/view/panel/lookup_*) : tenant-wide par nature
    // (une règle/un dashboard s'applique à tous les environnements du tenant — D7). INERTE en mode 0
    // (colonne posée, JAMAIS lue par un handler : le routing par env est #2a-2b/#2d). Idempotent par
    // col_exists : re-jouable ; sur base neuve, event/alert/metric/snapshot portent déjà env_id via
    // db/schema.sql -> sautés ; action/incident/incident_item/banned_ip (créées par migration) -> ALTER ici.
    for t in ["event", "alert", "metric", "snapshot", "action", "incident", "incident_item", "banned_ip"] {
        if !col_exists(conn, t, "env_id") {
            let _ = conn.execute(&format!("ALTER TABLE {t} ADD COLUMN env_id TEXT NOT NULL DEFAULT 'prod'"), []);
        }
    }
    let _ = conn.execute("UPDATE meta SET value='66' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v66 (env_id : axe environnement intra-tenant — fondation multi-tenant #2a-2a, INERTE en mode 0)");
}

fn migrate_v68(conn: &MigTx) {
    // v68 (#3a) — CONNECTEURS de sources externes (Microsoft Defender / Graph Security d'abord). Table
    // PAR-TENANT (config dans la base du tenant, comme `rule`/`notifier` ; mode 0 = base unique `default`).
    // ADDITIF metadata-only (CREATE TABLE) -> cheap même sur la base prod 2,4 M lignes ; convergence base
    // neuve/existante (la table est aussi implicitement créée par migrate() dans tenant_provision). INVARIANT
    // ABSOLU : table VIDE par défaut -> le poll loop (run_due_connectors) sélectionne les connecteurs DUS ->
    // 0 ligne -> no-op strict (aucun réseau, aucune écriture). `secret` = client_secret OAuth : protégé
    // at-rest par SQLCipher + denylist authorizer read-pool (deni de lecture en SQL brut, comme user.hash),
    // JAMAIS dans schema.sql (secret = jamais versionné). `watermark` = max `lastUpdateDateTime` (chaîne
    // ISO8601 UTC, comparable lexicographiquement, réinjectable tel quel dans le $filter Graph). `env_id`
    // colonne dédiée -> chaque event ingéré porte connector.env_id (défaut 'prod', axe environnement #2d).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS connector(\
           id          INTEGER PRIMARY KEY,\
           type        TEXT NOT NULL DEFAULT 'defender',\
           name        TEXT NOT NULL DEFAULT 'Connecteur',\
           enabled     INTEGER NOT NULL DEFAULT 0,\
           config_json TEXT NOT NULL DEFAULT '{}',\
           secret      TEXT NOT NULL DEFAULT '',\
           interval_s  INTEGER NOT NULL DEFAULT 300,\
           env_id      TEXT NOT NULL DEFAULT 'prod',\
           watermark   TEXT,\
           last_run    INTEGER,\
           last_ok     INTEGER,\
           last_error  TEXT,\
           last_count  INTEGER NOT NULL DEFAULT 0,\
           created     INTEGER)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='68' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v68 (connector : sources externes #3a — Defender ; INERTE tant qu'aucune ligne)");
}

fn migrate_v69(conn: &MigTx) {
    // v69 (#4a) — CASES FIRST-CLASS : la gestion d'incident (table `incident`/`incident_item`, v16)
    // devient OPÉRATIONNELLE. ADDITIF metadata-only : ALTER + colonnes à DEFAULT servi à la lecture
    // -> SQLite NE réécrit PAS les lignes existantes (cheap même sur grosse base). Idempotent par
    // col_exists (re-jouable ; sur base neuve, incident est créé par la v16 sans ces colonnes -> ALTER
    // ici). INVARIANT ABSOLU : `status` LEGACY (open/investigating/contained) JAMAIS réécrit — seules les
    // colonnes NEUVES sont posées/backfillées, donc les cases existants sont préservés et le mode 0 est
    // inchangé. `env_id` déjà présent (v66).
    //  - priority 1..4 (1=P1 critique .. 4=P4 bas), DISTINCTE de severity ; backfill depuis severity.
    //  - assignee : assignation dédiée (owner = créateur, conservé).
    //  - sla_due : échéance SLA (epoch s) = ts_création + cible(priority) ; overdue est calculé AU READ
    //    (pas de flag stocké), donc toujours cohérent avec l'horloge.
    //  - first_response_ts : 1er item de RÉPONSE analyste (MTTA).
    //  - escalated : anti re-notification de l'escalade SLA (0/1).
    for (col, ddl) in [
        ("priority", "ALTER TABLE incident ADD COLUMN priority INTEGER NOT NULL DEFAULT 3"),
        ("assignee", "ALTER TABLE incident ADD COLUMN assignee TEXT"),
        ("sla_due", "ALTER TABLE incident ADD COLUMN sla_due INTEGER"),
        ("first_response_ts", "ALTER TABLE incident ADD COLUMN first_response_ts INTEGER"),
        ("escalated", "ALTER TABLE incident ADD COLUMN escalated INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !col_exists(conn, "incident", col) {
            let _ = conn.execute(ddl, []);
        }
    }
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_sla ON incident(sla_due) WHERE sla_due IS NOT NULL", []);
    // Backfill priorité depuis severity (sev>=4 -> P1, 3 -> P2, 2 -> P3, <=1 -> P4), UNIQUEMENT les lignes
    // encore au défaut P3 -> idempotent + ne réécrase pas une priorité déjà éditée (re-run = WHERE priority=3
    // ne matche plus les cases dont sev>=3 déjà mappés).
    let _ = conn.execute(
        "UPDATE incident SET priority = CASE WHEN severity>=4 THEN 1 WHEN severity=3 THEN 2 WHEN severity=2 THEN 3 ELSE 4 END WHERE priority=3",
        [],
    );
    // Backfill sla_due = ts + cible(priority) pour les cases SANS échéance (idempotent : WHERE sla_due IS NULL).
    // Cibles (secondes) = MIROIR de sla_target_s() : P1=3600(1h) P2=14400(4h) P3=86400(24h) P4=259200(72h).
    let _ = conn.execute(
        "UPDATE incident SET sla_due = ts + CASE priority WHEN 1 THEN 3600 WHEN 2 THEN 14400 WHEN 3 THEN 86400 ELSE 259200 END WHERE sla_due IS NULL",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='69' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v69 (cases first-class #4a : priority/assignee/sla_due/first_response_ts/escalated + backfill ; status legacy préservé)");
}

fn migrate_v70(conn: &MigTx) {
    // v70 (#4a-bis) — ARCHIVE / SOFT-DELETE des cases. ADDITIF metadata-only (comme v69) : ALTER + colonnes
    // à DEFAULT SERVI À LA LECTURE -> SQLite NE réécrit PAS les lignes existantes (cheap même sur grosse
    // base). Idempotent par col_exists (re-jouable). INVARIANT ABSOLU mode 0 : `archived` DEFAULT 0 -> TOUS
    // les cases existants restent VISIBLES (comportement inchangé) ; l'archive est une capacité ADMIN qui
    // MASQUE de la liste par défaut SANS jamais supprimer la ligne ni sa timeline — append-only préservé
    // (archiver AJOUTE un item 'archive', ne retire rien). Les cases restent APPEND-ONLY : pas de DELETE.
    //  - archived    : 0 = actif (défaut, visible) / 1 = archivé (masqué de la liste par défaut).
    //  - archived_ts : epoch s de l'archivage (NULL tant qu'actif) — audit.
    //  - archived_by : auteur de l'archivage (NULL tant qu'actif) — audit.
    for (col, ddl) in [
        ("archived", "ALTER TABLE incident ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"),
        ("archived_ts", "ALTER TABLE incident ADD COLUMN archived_ts INTEGER"),
        ("archived_by", "ALTER TABLE incident ADD COLUMN archived_by TEXT"),
    ] {
        if !col_exists(conn, "incident", col) {
            let _ = conn.execute(ddl, []);
        }
    }
    // Index PARTIEL : la liste par défaut filtre `archived=0` (la grande majorité) -> il couvre le tri
    // updated DESC des cases ACTIFS sans jamais scanner les archivés. Léger (partiel, budget 2 Go).
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_active ON incident(updated) WHERE archived=0", []);
    let _ = conn.execute("UPDATE meta SET value='70' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v70 (#4a-bis : archive/soft-delete des cases — archived/archived_ts/archived_by ; masqué par défaut, append-only préservé, mode 0 inchangé)");
}

fn migrate_v71(conn: &MigTx) {
    // v71 (DURCISSEMENT SÉCU) — AUTORITÉ d'auto-exécution des playbooks. ADDITIF metadata-only : ALTER +
    // colonne à DEFAULT SERVI À LA LECTURE -> SQLite NE réécrit PAS les lignes existantes (cheap, budget 2 Go).
    // Idempotent par col_exists (re-jouable). INVARIANT ABSOLU mode 0 : `created_by_role` DEFAULT 'admin' ->
    // TOUS les playbooks existants (seeds/overlays/ad-hoc) restent ADMIN-authored -> auto-exécutables en mode
    // actif comme aujourd'hui (comportement inchangé). Seul un playbook créé/édité PAR un editor (désormais
    // refusé en amont par validate_detection_content pour toute action destructive) porterait 'editor' et NE
    // s'auto-approuverait PAS dans run_playbooks -> `/api/mode active` seul n'arme jamais une réponse editor.
    if !col_exists(conn, "playbook", "created_by_role") {
        let _ = conn.execute("ALTER TABLE playbook ADD COLUMN created_by_role TEXT NOT NULL DEFAULT 'admin'", []);
    }
    let _ = conn.execute("UPDATE meta SET value='71' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v71 (durcissement sécu : playbook.created_by_role — auto-exécution réservée admin-authored ; DEFAULT 'admin' = prod/seeds inchangés)");
}

fn migrate_v72(conn: &MigTx) {
    // v72 (DURCISSEMENT SÉCU) — DÉCOUPLE l'exclusion de rétention d'une valeur de source FORGEABLE
    // + INDEX de lecture pour /api/alerts tous-statuts (M6). ADDITIF metadata-only : ALTER + colonne à
    // DEFAULT SERVI À LA LECTURE -> SQLite NE réécrit PAS les lignes existantes (cheap, budget 2 Go).
    // Idempotent (col_exists / IF NOT EXISTS ; re-jouable). INVARIANT ABSOLU mode 0 inchangé.
    //  (a) event.origin (DEFAULT '') — marqueur d'ORIGINE. Posé à 'daemon' UNIQUEMENT quand le daemon écrit
    //      LUI-MÊME un event de contrôle (audit_config_change / marqueurs operator-access|tenant-admin|auth).
    //      Un event INGÉRÉ (agent/collecteur, via ingest_once/journal/loki) porte origin='' -> il ne peut
    //      plus (M1) usurper une source de contrôle NON-PURGEABLE. retention_run n'exclut désormais QUE
    //      (origin='daemon' AND source IN ('plume-config','plume-operator-access','plume-tenant-admin')).
    if !col_exists(conn, "event", "origin") {
        let _ = conn.execute("ALTER TABLE event ADD COLUMN origin TEXT NOT NULL DEFAULT ''", []);
    }
    //      BACKFILL anti-régression : les events de contrôle DÉJÀ présents (écrits avant v72) portent
    //      origin='' après l'ALTER -> sans ce backfill, la nouvelle purge (qui n'exclut QUE origin='daemon')
    //      les effacerait = perte de l'audit HISTORIQUE. On (re)marque 'daemon' EXACTEMENT ceux écrits par le
    //      daemon (host='plume-daemon', signature invariante de audit_config_change/emit_operator_access/
    //      tenant-admin) -> l'exclusion de rétention est PRÉSERVÉE à l'identique pour l'existant. Une éventuelle
    //      ligne 'plume-config' FORGÉE avant ce durcissement (host≠'plume-daemon') reste, elle, purgeable (correct).
    //      Ne touche QUE les rares events de contrôle (idx_event_src) -> cheap, budget 2 Go.
    let _ = conn.execute(
        "UPDATE event SET origin='daemon' WHERE origin='' AND host='plume-daemon' \
         AND source IN ('plume-config','plume-operator-access','plume-tenant-admin')",
        [],
    );
    //  (b) INDEX de lecture pour /api/alerts?status=all (M6) : le tri `ts DESC` (idx_alert_ts) et le pivot
    //      MITRE tous-statuts (idx_alert_mitre_ts) évitent le full-scan+tri de toute la table alert. Légers
    //      (complètent idx_alert_status/idx_alert_mitre déjà posés). Servent aussi coverage_detections.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert(ts)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_mitre_ts ON alert(mitre, ts)", []);
    let _ = conn.execute("UPDATE meta SET value='72' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v72 (durcissement sécu : event.origin — exclusion de rétention découplée d'une source forgeable ; idx_alert_ts + idx_alert_mitre_ts pour /api/alerts tous-statuts)");
}

fn migrate_v73(conn: &MigTx) {
    // v73 (DURCISSEMENT SÉCU — RÉVOCATION DE SESSION) — pose le compteur de révocation `session_epoch` dans
    // `meta` (KV), mélangé au HMAC des jetons par mint/verify_session. ADDITIF & IDEMPOTENT : INSERT OR
    // IGNORE (une base neuve l'a déjà via schema.sql -> MIROIR/CONVERGENCE). DEFAULT '0' -> aucun jeton
    // existant invalidé par la seule migration (l'invalidation vient d'un logout/reset EXPLICITE). INVARIANT
    // ABSOLU mode 0 : purement additif, aucun chemin data touché. Le bump est effectué à chaud (logout /
    // changement de mdp), pas par la migration.
    let _ = conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('session_epoch','0')", []);
    let _ = conn.execute("UPDATE meta SET value='73' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v73 (durcissement sécu : meta.session_epoch — révocation serveur des sessions ; DEFAULT 0, additif, mode 0 inchangé)");
}

fn migrate_v74(conn: &MigTx) {
    // v74 (DÉMOTE règle 25 en INFORMATIONNEL). La règle 25 (« CF: scan/bot absorbé au edge », T1595.002)
    // est un signal de VOLUME grossier, FP-prone sur le trafic OPÉRATEUR (challenges CF managés). La règle 43
    // (404-breadth : `dc(path)` par IP) est désormais le signal PRÉCIS. On rétrograde 25 en severity=1
    // (informationnel) -> elle cesse de lever des alertes haute-sévérité FP, tout en restant un signal de
    // volume consultable. Le SEED neuf pose déjà sev=1 (source unique) ; cette migration corrige la LIGNE
    // EXISTANTE (le seed INSERT OR IGNORE ne la mettrait pas à jour). IDEMPOTENT : guard `severity=3` (sa
    // valeur actuelle) -> ne fire qu'une fois, no-op si déjà à 1 ou modifiée à la main. Ciblée id=25 +
    // mitre='T1595.002' (jamais une autre règle si l'id a dérivé). Purement metadata (affichage/alerting),
    // AUCUN chemin data/collecte touché ; mode 0 inchangé.
    let _ = conn.execute(
        "UPDATE rule SET severity=1 WHERE id=25 AND mitre='T1595.002' AND severity=3 \
         AND query LIKE 'search source=cloudflare action=challenged%'",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='74' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v74 (démote règle 25 CF scan/bot en severity=1 informationnel ; règle 43 404-breadth = signal précis ; metadata-only, mode 0 inchangé)");
}

fn migrate_v75(conn: &MigTx) {
    // v75 — FONDATION DU MODE ENGAGEMENT AUTORISÉ (pentest natif black/grey/whitebox). ADDITIF & IDEMPOTENT.
    // INVARIANT ABSOLU mode 0/off : tout est INERTE (colonnes à DEFAULT '' JAMAIS lues sans PLUME_ENGAGEMENT_MODE=1
    // ET un engagement actif ; tables VIDES). Convergence base neuve/existante (v75 tourne aussi sur base fraîche).
    //
    // (a) COLONNE `engagement_id TEXT NOT NULL DEFAULT ''` — MÊME pattern que env_id v66 : ALTER metadata-only
    //     (la DEFAULT est SERVIE À LA LECTURE, SQLite NE réécrit PAS les lignes existantes -> cheap même sur
    //     base 2,4 M lignes), guardé par col_exists (re-jouable ; sur base neuve, event/alert la portent déjà
    //     via schema.sql -> sautés ; action/event_rollup/event_dim_rollup, créés par migration, ALTÉRÉS ici).
    //     Sur `event`/`alert` = TAG row-level (tag d'ingest + rapport de couverture scopé). Sur `action` +
    //     les ROLLUPS = colonne de forward-compat posée metadata-only : NON foldée dans la PK/GROUP BY des
    //     rollups (contrairement à env_id v67) car la couverture engagement lit la table `alert`, PAS les
    //     rollups -> recréer les rollups chauds serait une chirurgie gratuite sans bénéfice fondation (le fold
    //     PK est différé à une éventuelle vue Engagement agrégée). Byte-identique off : toutes les lignes ''.
    for t in ["event", "alert", "action", "event_rollup", "event_dim_rollup"] {
        if !col_exists(conn, t, "engagement_id") {
            let _ = conn.execute(&format!("ALTER TABLE {t} ADD COLUMN engagement_id TEXT NOT NULL DEFAULT ''"), []);
        }
    }
    // (b) TABLES `engagement` + `engagement_grant` (PAR-TENANT, comme connector/rule ; mode 0 = base `default`).
    //     CREATE IF NOT EXISTS -> idempotent. VIDES par défaut -> load_active_engagements/expire_due_engagements
    //     sélectionnent 0 ligne = no-op strict. `box` ∈ blackbox|greybox|whitebox ; `scope` = JSON [CIDR…] ;
    //     `status` scheduled|active|expired|revoked ; `adapter` = adaptateur enforcer HÔTE (pull). `engagement_grant`
    //     = INTENT de provisioning par box (blackbox=0, greybox=scoped_cred, whitebox=scoped_cred+config_read),
    //     cycle pending->issued->revoked (l'adaptateur de provisioning ÉMET+écrit ref ; le daemon DÉCLARE+RÉVOQUE).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS engagement(\
           id           TEXT PRIMARY KEY,\
           name         TEXT NOT NULL DEFAULT '',\
           box          TEXT NOT NULL DEFAULT 'blackbox',\
           scope        TEXT NOT NULL DEFAULT '[]',\
           window_start INTEGER NOT NULL DEFAULT 0,\
           window_end   INTEGER NOT NULL DEFAULT 0,\
           authorizer   TEXT NOT NULL DEFAULT '',\
           reason       TEXT NOT NULL DEFAULT '',\
           status       TEXT NOT NULL DEFAULT 'scheduled',\
           adapter      TEXT NOT NULL DEFAULT '',\
           env_id       TEXT NOT NULL DEFAULT 'prod',\
           created      INTEGER,\
           created_by   TEXT,\
           ended_ts     INTEGER)",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_engagement_status ON engagement(status, window_end)", []);
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS engagement_grant(\
           id            INTEGER PRIMARY KEY,\
           engagement_id TEXT NOT NULL,\
           kind          TEXT NOT NULL DEFAULT '',\
           ref           TEXT NOT NULL DEFAULT '',\
           idp_adapter   TEXT NOT NULL DEFAULT '',\
           issued_ts     INTEGER,\
           revoked_ts    INTEGER,\
           status        TEXT NOT NULL DEFAULT 'issued')",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_engagement_grant_eng ON engagement_grant(engagement_id, status)", []);
    // (c) RÈGLE self-detection « engagement autorisé déclaré » — MÊME mécanique que v51 : on n'INSÈRE
    //     QUE si le seed a déjà tourné (flag seeded_detection_rules présent = instance live où
    //     seed_detection_rules ne re-crée plus). Sur PVC NEUF migrate() précède les seeds -> flag absent
    //     -> SKIP, et seed_detection_rules crée la règle -> zéro doublon. Borné par « n'existe pas déjà
    //     par nom » -> idempotent. Source unique : DETECTION_RULES_V75_ENGAGEMENT.
    let seeded_v75 = conn.query_row("SELECT 1 FROM meta WHERE key='seeded_detection_rules'", [], |_| Ok(())).is_ok();
    if seeded_v75 {
        for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V75_ENGAGEMENT {
            let exists = conn.query_row("SELECT 1 FROM rule WHERE name=?1", params![name], |_| Ok(())).is_ok();
            if !exists {
                let _ = conn.execute(
                    "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
                    params![name, q, is_soql, op, th, sev, intv, win, mitre],
                );
            }
        }
    }
    let _ = conn.execute("UPDATE meta SET value='75' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v75 (FONDATION mode engagement autorisé : engagement + engagement_grant + engagement_id sur event/alert/action/rollups ; INERTE tant que PLUME_ENGAGEMENT_MODE=0)");
}

fn migrate_v76(conn: &MigTx) {
    // v76 — INDEX DE LECTURE pour le TRIAGE GROUPÉ des alertes (« 1 groupe = N occurrences »,
    // /api/alerts/groups + expansion via /api/alerts?gkey=). Le GROUP BY <col> + ORDER BY MAX(ts) et la
    // sous-requête corrélée du titre échantillon (`WHERE <col>=? ORDER BY ts DESC LIMIT 1`) deviennent des
    // SEEKS au lieu de scans. `mitre` a déjà idx_alert_mitre_ts (v72) ; `dedup` a déjà idx_alert_dedup
    // (UNIQUE, schema.sql) ; on ajoute donc les axes MANQUANTS `rule` et `host`. CREATE IF NOT EXISTS ->
    // idempotent & re-jouable. LÉGER (l'alerte est un agrégat de règle, table modeste). INVARIANT ABSOLU
    // mode 0/data-plane : purement additif (index de lecture), aucun chemin d'écriture/ingest touché.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_rule_ts ON alert(rule, ts)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_host_ts ON alert(host, ts)", []);
    let _ = conn.execute("UPDATE meta SET value='76' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v76 (triage groupé alertes : idx_alert_rule_ts + idx_alert_host_ts pour /api/alerts/groups ; index de lecture, additif, mode 0 inchangé)");
}

fn migrate_v78(conn: &MigTx) {
    // v78 — PARSEUR DÉCLARATIF (DSL CIM, Slice #7 pièce 2). Table des specs déclaratives chargées depuis
    // config.d/parsers/*.json (fichiers AVEC un objet `map` ; les fichiers legacy à `pattern` restent dans
    // `parser`). `spec` = JSON figé {match?, extract?, map} recompilé par dparsers_reload. ADDITIVE & INERTE :
    // AUCUN builtin seedé (aucune ligne -> registre vide -> ingest byte-identique, mode 0). managed : 0 (jamais
    // seedé ici), 1 (overlay git via load_overlay_dparsers). IDEMPOTENT (CREATE IF NOT EXISTS).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS dparser(\
         id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT '*', \
         spec TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, builtin INTEGER NOT NULL DEFAULT 0, \
         managed INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0)",
        [],
    );
    let _ = conn.execute("UPDATE meta SET value='78' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v78 (parseur déclaratif DSL CIM : table `dparser`, chargée de config.d, mapping source->CIM sans rebuild ; ADDITIF, mode 0 byte-identique)");
}

fn migrate_v79(conn: &MigTx) {
    // v79 (#23) — THREAT-INTEL : magasin d'IOC (indicateurs de compromission). Table PAR-TENANT (comme
    // connector/rule ; mode 0 = base unique `default`, le « tenant » du UNIQUE est donc la BASE elle-même,
    // et `env_id` est l'axe environnement intra-tenant #2d). ADDITIF metadata-only (CREATE TABLE + index)
    // -> cheap même sur la base prod 2,4 M lignes. INVARIANT ABSOLU mode 0 : table VIDE par défaut -> le
    // cache de match en mémoire (ioc_cache_reload) est vide -> ti_match_event est un NO-OP STRICT à
    // l'ingest (aucune mutation de fields) -> LIGNE STOCKÉE BYTE-IDENTIQUE. Convergence base neuve/existante
    // (v79 tourne aussi sur base fraîche, schema.sql démarre à v1). Un IOC est de la DONNÉE de renseignement,
    // PAS un secret (pas de denylist authorizer nécessaire, contrairement à connector.secret).
    //  - type : ip|domain|url|hash_md5|hash_sha1|hash_sha256|email (vocabulaire guatx_core::ti::IOC_TYPES).
    //  - value : NORMALISÉE (guatx_core::ti::normalize_ioc — domaine/url/hash/email en minuscules, IP trim).
    //  - source : nom du flux (feed) qui a apporté l'IOC (ex 'stix-import', 'manual') — vendor-agnostic.
    //  - confidence 0..100 ; severity 0..4 (sévérité d'une alerte éventuelle) ; expires : expiration (epoch
    //    s) = STIX valid_until -> le cache EXCLUT les IOC expirés (rétention/expiry servie à la lecture).
    //  - stix_id : provenance STIX (indicator--…) ; env_id : axe environnement (#2d), défaut 'prod'.
    //  - UNIQUE(type,value,source,env_id) : un même IOC réapporté par le même feed = UPDATE (last_seen), pas
    //    un doublon ; le MÊME IOC de DEUX feeds distincts = deux lignes (traçabilité de la source).
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS ioc(\
           id         INTEGER PRIMARY KEY,\
           type       TEXT NOT NULL,\
           value      TEXT NOT NULL,\
           source     TEXT NOT NULL DEFAULT '',\
           confidence INTEGER NOT NULL DEFAULT 0,\
           severity   INTEGER NOT NULL DEFAULT 2,\
           first_seen INTEGER,\
           last_seen  INTEGER,\
           expires    INTEGER,\
           stix_id    TEXT,\
           env_id     TEXT NOT NULL DEFAULT 'prod',\
           UNIQUE(type,value,source,env_id))",
        [],
    );
    // Index sur `value` : le match-on-ingest utilise le CACHE mémoire (jamais un SELECT par event), mais
    // les recherches admin / le rechargement du cache / la déduplication d'import lisent par valeur.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value)", []);
    // Index partiel expiration : le rechargement du cache filtre les IOC expirés (expires<=now) cheaply.
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_expires ON ioc(expires) WHERE expires IS NOT NULL", []);
    let _ = conn.execute("UPDATE meta SET value='79' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v79 (threat-intel #23 : table `ioc` + index value/expires ; match-on-ingest via cache mémoire, INERTE tant que la table est vide -> mode 0 byte-identique)");
}

fn migrate_v80(conn: &MigTx) {
    // v80 (#24) — RISK-BASED ALERTING (RBA, modèle Splunk ES) : au lieu d'UNE alerte par détection, les
    // détections CONTRIBUENT du RISQUE à des ENTITÉS (user/host/ip/…) ; le risque s'ACCUMULE par entité sur
    // une fenêtre ; quand le cumul franchit un seuil (ou ≥N tactiques MITRE distinctes, ou vélocité), on lève
    // UNE seule alerte risk-based pour cette entité -> réduit la fatigue d'alerte sans perdre le signal.
    //
    // INVARIANT ABSOLU mode 0 (comme #23/ioc) : ces tables sont VIDES par défaut. AUCUNE règle risk n'est
    // seedée (risk_score défaut 0 = comportement inchangé), l'IOC store est vide (aucun ti_match) -> AUCUN
    // risk_event n'est jamais émis -> risk_rollup vide -> AUCUNE alerte risk -> détection/ingest/data-plane
    // BYTE-IDENTIQUES. RBA est purement ADDITIF : il s'active par la DONNÉE (une règle passée en mode risk,
    // ou un IOC importé), jamais par un flag. Convergence base neuve/existante (v80 tourne aussi à froid).
    //
    //  - risk_event : le journal des CONTRIBUTIONS de risque (une ligne = un apport). Émis par (a) une règle
    //    de détection en MODE RISK (source='rule', run_risk_rules), (b) un match threat-intel à l'ingest
    //    (source='ti', composition avec #23), (c) manuel (source='manual'). `dedup` (UNIQUE, nullable) borne
    //    l'émission : une entité reçoit AU PLUS une contribution par (règle|ti, bucket-de-fenêtre) -> pas
    //    d'explosion sous attaque bruyante (un scanner qui matche un IOC = 1 apport/heure, pas 10 000).
    //  - risk_rollup : l'agrégat PAR ENTITÉ sur la fenêtre (score cumulé, nb de contributions, tactiques
    //    distinctes, vélocité en sous-fenêtre chaude, dernière activité). MATÉRIALISÉ dans la boucle rollup
    //    (rollup_risk, piggyback rollup_events) par RECONSTRUCTION depuis la PETITE table risk_event (JAMAIS
    //    un scan de `event` : discipline host_rollup/IOC_SET). La lecture (/api/risk/entities) sert le rollup
    //    en O(taille-de-flotte-risquée), ZÉRO scan. La reconstruction fenêtrée gère le DECAY (les vieilles
    //    contributions sortent naturellement de la fenêtre) sans purge de ligne.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS risk_event(\
           id          INTEGER PRIMARY KEY,\
           ts          INTEGER NOT NULL,\
           entity_type TEXT NOT NULL,\
           entity      TEXT NOT NULL,\
           risk_score  INTEGER NOT NULL DEFAULT 0,\
           source      TEXT NOT NULL DEFAULT 'rule',\
           rule_id     INTEGER,\
           reason      TEXT NOT NULL DEFAULT '',\
           mitre       TEXT NOT NULL DEFAULT '',\
           severity    INTEGER NOT NULL DEFAULT 2,\
           env_id      TEXT NOT NULL DEFAULT 'prod',\
           dedup       TEXT)",
        [],
    );
    // Index (entity_type,entity,ts) : timeline par-entité + reconstruction groupée du rollup. idx ts : la
    // reconstruction filtre la fenêtre ([now-window, now]) par range-scan indexé (pas de full-scan). dedup
    // UNIQUE partiel (comme alert.dedup) : borne d'émission via INSERT OR IGNORE (contribution déjà posée = no-op).
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_event_entity ON risk_event(entity_type, entity, ts)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_event_ts ON risk_event(ts)", []);
    let _ = conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_event_dedup ON risk_event(dedup) WHERE dedup IS NOT NULL", []);
    // risk_rollup : agrégat PAR ENTITÉ (PK entity_type+entity+env_id). Reconstruit à blanc à chaque tick
    // (petite table) -> pas de watermark (contrairement à host_rollup) : le decay fenêtré l'exige (une somme
    // monotone ne saurait DÉCROÎTRE quand une contribution sort de la fenêtre). score_hot/contrib_hot = même
    // agrégat borné à la SOUS-fenêtre de vélocité. tactics = set concaténé des techniques MITRE distinctes.
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS risk_rollup(\
           entity_type      TEXT NOT NULL,\
           entity           TEXT NOT NULL,\
           env_id           TEXT NOT NULL DEFAULT 'prod',\
           score            INTEGER NOT NULL DEFAULT 0,\
           contrib          INTEGER NOT NULL DEFAULT 0,\
           distinct_tactics INTEGER NOT NULL DEFAULT 0,\
           tactics          TEXT NOT NULL DEFAULT '',\
           score_hot        INTEGER NOT NULL DEFAULT 0,\
           contrib_hot      INTEGER NOT NULL DEFAULT 0,\
           max_severity     INTEGER NOT NULL DEFAULT 0,\
           first_ts         INTEGER NOT NULL DEFAULT 0,\
           last_ts          INTEGER NOT NULL DEFAULT 0,\
           updated          INTEGER,\
           PRIMARY KEY(entity_type, entity, env_id))",
        [],
    );
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_rollup_score ON risk_rollup(score DESC)", []);
    // ANNOTATION RISK sur `rule` (ADDITIVE) : risk_score=0 -> règle NORMALE (comportement inchangé, run_due_rules).
    // risk_score>0 -> règle en MODE RISK : run_risk_rules exécute sa requête (attendue en `… | stats count by
    // <entity>`) et pour chaque ligne CONTRIBUE risk_score points à l'entité nommée par `risk_entity_field`
    // (colonne du résultat), typée `risk_entity_type` (user|host|ip|…). run_due_rules EXCLUT les règles risk
    // (COALESCE(risk_score,0)=0) -> une règle risk ne lève PAS d'alerte scalaire par tir (« instead of » : la
    // seule alerte vient de l'ACCUMULATION). Défauts 0/'' -> mode 0 : sélection run_due_rules IDENTIQUE.
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN risk_entity_type TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN risk_entity_field TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("UPDATE meta SET value='80' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v80 (RBA #24 : tables `risk_event`/`risk_rollup` + colonnes risk sur `rule` ; scoring par-entité matérialisé dans rollup_risk, INERTE tant qu'aucune règle risk/IOC -> mode 0 byte-identique)");
}

fn migrate_v81(conn: &MigTx) {
    // v81 (#7) — DÉDUP SIGMA PAR `sigma_id` (UUID stable de la règle Sigma). Colonne ADDITIVE `rule.sigma_id`
    // (NULL pour TOUTES les lignes existantes -> AUCUNE mutation : mode 0 byte-identique ; les détections
    // natives/overlays/CRUD ne la renseignent pas). L'importeur Sigma (single ET bulk) y stocke l'`id` (UUID)
    // du document et l'utilise comme CLÉ D'IDEMPOTENCE : un ré-import d'un ruleset communautaire dont les
    // TITRES ont dérivé dédup toujours par l'UUID stable (UPDATE, plus de doublon). Absence d'`id` dans le
    // doc -> repli sur le titre (comportement HISTORIQUE strictement préservé). Index NON-UNIQUE (une règle
    // manuelle pourrait, en théorie, réutiliser une chaîne ; on ne veut jamais faire ÉCHOUER un import) pour la
    // recherche par sigma_id. Idempotence : `ALTER ADD COLUMN` déjà appliqué -> l'erreur « duplicate column »
    // est ignorée (`let _ =`) et la version n'est bumpée qu'une fois (garde `if v < 81` du dispatcher).
    let _ = conn.execute("ALTER TABLE rule ADD COLUMN sigma_id TEXT", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_sigma_id ON rule(sigma_id) WHERE sigma_id IS NOT NULL", []);
    let _ = conn.execute("UPDATE meta SET value='81' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v81 (dédup Sigma par sigma_id : colonne rule.sigma_id + index partiel ; additive, NULL pour l'existant -> mode 0 byte-identique)");
}

fn migrate_v82(conn: &MigTx) {
    // v82 — LIBELLÉ de provisioning `token.kind` (agent|hec). Colonne ADDITIVE, purement DESCRIPTIVE :
    // l'authentification (token_lookup) reste INCHANGÉE — un token créé ici s'authentifie EXACTEMENT comme
    // un token CLI, sur le seam agent (Bearer/responder) ET sur le collector HEC (`Splunk <tok>`), qui
    // partagent la même table. `kind` n'aiguille RIEN dans l'auth ; il ne sert qu'à l'UI d'admin (badge +
    // extrait forwarder HEC) et à la sémantique de provisioning (HEC : host optionnel ; agent responder :
    // host requis). NULL pour l'existant (tokens CLI) -> AUCUNE mutation : mode 0 byte-identique. Un token
    // sans kind est présenté comme 'agent' (défaut historique du CLI `plume-daemon token`).
    let _ = conn.execute("ALTER TABLE token ADD COLUMN kind TEXT", []);
    let _ = conn.execute("UPDATE meta SET value='82' WHERE key='schema_version'", []);
    eprintln!("[migration] schéma -> v82 (token.kind agent|hec : libellé de provisioning DESCRIPTIF pour l'UI ; auth inchangée ; NULL pour l'existant -> mode 0 byte-identique)");
}

#[cfg(test)]
mod v102_tests {
    use rusqlite::Connection;

    // CHANGE 6 (v103) : migrate_v102 doit désactiver RÉTROACTIVEMENT le doublon 5xx (id 22, T1190)
    // sur une base live, SANS toucher id 21 (404-origin, T1595.002) ni id 20 (port-scan, T1046).
    #[test]
    fn migrate_v102_disables_live_5xx_dup_only() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE rule(id INTEGER PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, mitre TEXT);
             INSERT INTO meta(key,value) VALUES('schema_version','101');
             INSERT INTO rule(id,name,enabled,mitre) VALUES(20,'Port-scan entrant (UFW, 10 min)',1,'T1046');
             INSERT INTO rule(id,name,enabled,mitre) VALUES(21,'Web-scan : pic de 404 par IP (10 min)',1,'T1595.002');
             INSERT INTO rule(id,name,enabled,mitre) VALUES(22,'Anomalie exploit web : pic de 5xx par IP (10 min)',1,'T1190');",
        )
        .unwrap();

        // `migrate_vN` prend désormais un `MigTx` (Connection + mémorisation des échecs de classe B) :
        // appel DIRECT hors transaction, comportement de la migration inchangé.
        super::migrate_v102(&super::MigTx::new(&conn));

        let e22: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=22", [], |r| r.get(0)).unwrap();
        let e21: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=21", [], |r| r.get(0)).unwrap();
        let e20: i64 = conn.query_row("SELECT enabled FROM rule WHERE id=20", [], |r| r.get(0)).unwrap();
        assert_eq!(e22, 0, "id 22 (5xx dup, T1190) doit être désactivée");
        assert_eq!(e21, 1, "id 21 (404-origin, T1595.002) doit rester activée");
        assert_eq!(e20, 1, "id 20 (port-scan, T1046) doit rester activée");

        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "102", "schema_version doit être bumpé à 102");
    }
}

/// INTÉGRITÉ DE SCHÉMA (défaut d'audit S4) — une migration qui ÉCHOUE pour une raison RÉELLE
/// (disque plein, base verrouillée) ne doit JAMAIS laisser la base ESTAMPILLÉE comme migrée.
/// Sinon : `meta.schema_version=N` sans les objets de vN, et la garde anti-downgrade
/// (`schema_downgrade_guard`) interdit tout retour en arrière -> aucun chemin de réparation.
#[cfg(test)]
mod tx_integrity_tests {
    use super::*;

    /// Base MINIMALE estampillée v110 (seule `meta` est nécessaire : v111 ne crée que `net_ban` +
    /// son index) puis SIMULATION DE DISQUE PLEIN : `PRAGMA max_page_count` plafonné au nombre de
    /// pages COURANT -> toute ALLOCATION de page échoue en SQLITE_FULL (l'un des deux échecs réels
    /// cités par l'audit), alors qu'un `UPDATE` EN PLACE de même longueur ('110' -> '111') n'alloue
    /// rien et RÉUSSIT. C'est exactement l'asymétrie qui produit le défaut.
    fn db_v110_disk_full() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO meta(key,value) VALUES('schema_version','110');",
        )
        .unwrap();
        let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        conn.execute_batch(&format!("PRAGMA max_page_count={pages}")).unwrap();
        conn
    }

    /// Échec RÉEL au milieu d'une migration -> la version DOIT rester l'ancienne (v110), pour que la
    /// migration soit RE-TENTÉE au prochain démarrage. AVANT correctif : le `CREATE TABLE net_ban`
    /// échoue (SQLITE_FULL, résultat ignoré par `let _ =`) mais `UPDATE meta SET value='111'` est
    /// INCONDITIONNEL -> base estampillée v111 SANS `net_ban`.
    #[test]
    fn failed_migration_leaves_schema_version_at_previous_value() {
        let conn = db_v110_disk_full();
        migrate(&conn);
        assert!(
            !table_exists(&conn, "net_ban"),
            "précondition du test : le CREATE TABLE doit avoir échoué (disque plein simulé)"
        );
        assert_eq!(
            read_schema_version(&conn),
            110,
            "migration échouée -> version NON bumpée (sinon base « migrée » sans ses objets, sans chemin de réparation)"
        );
    }

    /// Corollaire : la version laissée à l'ancienne valeur doit effectivement permettre le RETRY.
    /// Une fois la condition d'échec levée (place disque rendue), le démarrage suivant DOIT terminer
    /// la migration. AVANT correctif la base est déjà estampillée v111 -> `if v < 111` est faux ->
    /// `net_ban` n'est JAMAIS créée (perte silencieuse et définitive).
    #[test]
    fn migration_is_retried_after_failure_condition_clears() {
        let conn = db_v110_disk_full();
        migrate(&conn); // 1er démarrage : échoue (disque plein)
        // place rendue (le plafond REDESCEND jamais sous le nombre de pages courant : on le remonte
        // explicitement au maximum SQLite par défaut).
        conn.execute_batch("PRAGMA max_page_count=1073741823").unwrap();
        migrate(&conn); // 2e démarrage : doit RATTRAPER la migration
        assert!(table_exists(&conn, "net_ban"), "v111 doit être re-tentée et réussir au démarrage suivant");
        assert_eq!(read_schema_version(&conn), 111, "version bumpée SEULEMENT après succès réel");
    }

    /// Base DÉJÀ À JOUR (`== CODE_SCHEMA_MAX`, le cas de la PRODUCTION) : `migrate()` doit rester un
    /// NO-OP TOTAL — aucune étape ne s'exécute, donc aucune transaction ouverte, aucune écriture, et la
    /// version ne bouge pas. Verrou : le wrapper transactionnel ne doit JAMAIS re-jouer une migration
    /// déjà appliquée ni laisser une transaction pendante.
    #[test]
    fn up_to_date_database_is_left_untouched() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../db/schema.sql")).unwrap();
        migrate(&conn); // base neuve -> migrée jusqu'à CODE_SCHEMA_MAX
        assert_eq!(read_schema_version(&conn), CODE_SCHEMA_MAX, "base neuve migrée au maximum du code");
        // Empreinte : compteur de modifications de schéma SQLite (`PRAGMA schema_version` s'incrémente
        // à CHAQUE DDL) + DDL complète + contenu de `meta`.
        let snapshot = |c: &Connection| -> (i64, String, String) {
            let cookie: i64 = c.query_row("PRAGMA schema_version", [], |r| r.get(0)).unwrap();
            let ddl: String = c
                .query_row(
                    "SELECT COALESCE(group_concat(type||' '||name||' '||COALESCE(sql,'')),'') \
                     FROM (SELECT type,name,sql FROM sqlite_master ORDER BY type,name)",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let meta: String = c
                .query_row(
                    "SELECT COALESCE(group_concat(key||'='||COALESCE(value,'')),'') \
                     FROM (SELECT key,value FROM meta ORDER BY key)",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            (cookie, ddl, meta)
        };
        let before = snapshot(&conn);
        migrate(&conn); // 2e démarrage sur une base à jour
        assert_eq!(snapshot(&conn), before, "base à jour -> schéma ET meta INCHANGÉS (aucune migration re-jouée)");
        assert_eq!(read_schema_version(&conn), CODE_SCHEMA_MAX, "version inchangée");
        assert!(conn.is_autocommit(), "aucune transaction laissée ouverte");
    }
}
