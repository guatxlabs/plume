//! Réconciliation d'état d'index + tâches de fond (le vrai kill-switch env-driven, idempotent). Détection
//! version SQLite (`sqlite_runtime_version`), pilotage FTS-fields (`reconcile_fts_fields` + DDL vtable/
//! triggers) et index expression (`EXPR_INDEX_FIELDS`/`reconcile_expr_indexes_*`/`reconcile_index_state`),
//! CREATE lourds en tâche de fond post-bind (`ensure_*_index_background`/`analyze_full_background`/
//! `fts_backfill_background`), auto-indexation Phase 3 (`autoindex_maintain_background`/`autoindex_tick`/
//! `autoindex_create`, churn borné + éviction LRU) et `host_self`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// =====================================================================================
// RÉCONCILIATION D'ÉTAT D'INDEX (le VRAI kill-switch, env-driven, IDEMPOTENT).
//
// Les migrations v40/v41 ne font QUE bumper schema_version (cf. supra). Tout le pilotage d'état
// (créer/dropper la vtable+triggers FTS et les 7 index expression) vit ICI et est appelé À CHAQUE
// boot après migrate(). Conséquence : poser PLUME_FTS_FIELDS=0 (resp. PLUME_EXPRINDEX=0) + redeploy
// APPLIQUE réellement le DROP (pas de fuite, pas de coût ingest résiduel), et =1 re-crée si absent.
// Idempotent : CREATE/DROP ... IF [NOT] EXISTS -> re-jouable sans erreur.
// =====================================================================================

/// Les champs chauds indexés par index expression partiel (7 Phase 2 v41 + 3 v49). Source unique de vérité
/// partagée par reconcile_index_state, le background CREATE et la doc (= HOT_FIELDS).
const EXPR_INDEX_FIELDS: &[&str] = HOT_FIELDS;

/// Version d'exécution réelle de la SQLite liée (SQLCipher vendoré). On la lit au lieu
/// de supposer : le crate `libsqlite3-sys` 0.28 vendore SQLite 3.39.4 (< 3.43) -> `contentless_delete=1`
/// (ajouté en 3.43) N'EST PAS disponible. On vérifie donc à l'exécution et on documente le chemin pris.
fn sqlite_runtime_version(conn: &Connection) -> (i64, i64, i64) {
    let v: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .unwrap_or_else(|_| "0.0.0".into());
    let mut it = v.split('.').map(|p| p.parse::<i64>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// DDL de la vtable FTS5 contentless sur les valeurs aplaties de `fields` (1 colonne `v`). Inchangé
/// (partie VALIDÉE : contentless 1 colonne, tokenizer identités/chemins/IP/emails). `contentless_delete=1`
/// N'EST PAS ajouté car la SQLite liée est 3.39.4 (< 3.43) — cf. sqlite_runtime_version.
const FTS_FIELDS_VTABLE_DDL: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS event_fields_fts USING fts5(\
     v, content='', tokenize=\"unicode61 remove_diacritics 2 tokenchars '_-.:/@'\", prefix='2 3')";

/// Trigger AFTER INSERT : 1 doc FTS par event = group_concat des valeurs scalaires de `fields`.
/// (partie VALIDÉE, inchangée). PAS de trigger AU : `event` est append-only.
const FTS_FIELDS_AI_TRIGGER_DDL: &str = "CREATE TRIGGER IF NOT EXISTS event_ff_ai AFTER INSERT ON event \
     WHEN new.fields IS NOT NULL AND json_valid(new.fields) BEGIN \
       INSERT INTO event_fields_fts(rowid, v) \
       SELECT new.id, group_concat(je.value, ' ') \
         FROM json_each(new.fields) je \
        WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real'); \
     END";

/// Trigger AFTER DELETE qui fait un VRAI delete FTS5 sur table contentless.
/// AVANT : `VALUES('delete', old.id, '')` -> sur une vtable contentless, la commande 'delete' DOIT
/// recevoir les MÊMES tokens que ceux insérés (FTS5 ne stocke pas le contenu, il ne peut décrémenter
/// les postings que si on les lui re-fournit). Passer '' ne décrémentait RIEN -> postings orphelins ->
/// event_fields_fts grossissait indéfiniment à chaque DELETE de retention_run (fuite disque).
/// APRÈS : on RECONSTRUIT le flat depuis old.fields (group_concat IDENTIQUE au trigger AI) et on le
/// passe à 'delete' -> FTS5 décrémente exactement les bons postings -> pas de fuite. Chemin FALLBACK
/// (valide pour toute version FTS5 ; pas besoin de contentless_delete=1, indisponible en 3.39.4).
const FTS_FIELDS_AD_TRIGGER_DDL: &str = "CREATE TRIGGER IF NOT EXISTS event_ff_ad AFTER DELETE ON event \
     WHEN old.fields IS NOT NULL AND json_valid(old.fields) BEGIN \
       INSERT INTO event_fields_fts(event_fields_fts, rowid, v) \
       SELECT 'delete', old.id, group_concat(je.value, ' ') \
         FROM json_each(old.fields) je \
        WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real'); \
     END";

/// Réconcilie l'INFRA FTS-fields (vtable + triggers) avec l'env, à CHAQUE boot.
/// PLUME_FTS_FIELDS=1 -> s'assure que vtable+triggers existent (CREATE IF NOT EXISTS) ;
/// =0 -> DROP triggers PUIS vtable (kill-switch dur : supprime le coût ingest ET la fuite H1).
/// Instantané (DDL pur, aucun scan) -> sûr au boot synchrone. Idempotent.
fn reconcile_fts_fields(conn: &Connection, conf: &HashMap<String, String>) {
    if cfg(conf, "PLUME_FTS_FIELDS", "0") == "1" {
        let (maj, min, _) = sqlite_runtime_version(conn);
        let _ = conn.execute(FTS_FIELDS_VTABLE_DDL, []);
        let _ = conn.execute(FTS_FIELDS_AI_TRIGGER_DDL, []);
        // Le trigger AD a CHANGÉ -> on le RECRÉE inconditionnellement pour remplacer
        // l'ancienne forme buggée ('delete',id,'') qui aurait pu être posée par un boot antérieur.
        let _ = conn.execute("DROP TRIGGER IF EXISTS event_ff_ad", []);
        let _ = conn.execute(FTS_FIELDS_AD_TRIGGER_DDL, []);
        eprintln!(
            "[reconcile] FTS-fields ON : event_fields_fts + triggers présents (SQLite {maj}.{min} ; delete FTS par reconstruction des tokens — pas de fuite disque)"
        );
    } else {
        // OFF : kill-switch effectif. DROP triggers d'abord (dépendent de la vtable) puis la vtable.
        let _ = conn.execute("DROP TRIGGER IF EXISTS event_ff_ai", []);
        let _ = conn.execute("DROP TRIGGER IF EXISTS event_ff_ad", []);
        let _ = conn.execute("DROP TABLE IF EXISTS event_fields_fts", []);
        eprintln!("[reconcile] FTS-fields OFF (PLUME_FTS_FIELDS!=1) : vtable + triggers DROPPÉS (kill-switch appliqué)");
    }
}

/// Les index expression partiels (EXPR_INDEX_FIELDS) existent-ils déjà tous ? (lecture sqlite_master, pas de scan).
fn expr_indexes_all_present(conn: &Connection) -> bool {
    EXPR_INDEX_FIELDS.iter().all(|c| {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1",
            params![format!("idx_ev_f_{c}")],
            |_| Ok(()),
        )
        .is_ok()
    })
}

/// Réconcilie les INDEX EXPRESSION (EXPR_INDEX_FIELDS) avec l'env. Partie INSTANTANÉE seulement :
/// PLUME_EXPRINDEX=0 -> DROP tous (instantané, kill-switch dur). PLUME_EXPRINDEX=1 -> NE crée RIEN ici
/// (un CREATE INDEX sur une table volumineuse bloquerait le bind) ; la création est faite EN FOND par
/// reconcile_expr_indexes_background après le bind. Idempotent.
fn reconcile_expr_indexes_fast(conn: &Connection, conf: &HashMap<String, String>) {
    if cfg(conf, "PLUME_EXPRINDEX", "1") == "1" {
        // ON : on ne crée pas ici (anti-crashloop M1). Le background s'en charge. No-op synchrone.
    } else {
        for c in EXPR_INDEX_FIELDS {
            let _ = conn.execute(&format!("DROP INDEX IF EXISTS idx_ev_f_{c}"), []);
        }
        eprintln!("[reconcile] index expression OFF (PLUME_EXPRINDEX!=1) : {} index DROPPÉS (kill-switch appliqué ; full-scan json_extract)", EXPR_INDEX_FIELDS.len());
    }
}

/// Point d'entrée IDEMPOTENT appelé à CHAQUE boot APRÈS migrate(), AVANT le bind.
/// Ne contient QUE des opérations INSTANTANÉES (DDL pur, aucun scan de table) -> ne retarde pas le bind.
/// Le travail LOURD (CREATE INDEX sur l'historique) est délégué à reconcile_expr_indexes_background,
/// lancé en tâche de fond après le bind. C'est le vrai kill-switch : toggle env + redeploy => effet réel.
pub(crate) fn reconcile_index_state(conn: &Connection, conf: &HashMap<String, String>) {
    reconcile_fts_fields(conn, conf);
    reconcile_expr_indexes_fast(conn, conf);
}

/// CREATE des index expression (EXPR_INDEX_FIELDS) EN TÂCHE DE FOND (jamais au boot synchrone). Modèle
/// analyze_full_background : spawn après le bind, sleep initial laissant passer bind + liveness probe.
/// No-op si PLUME_EXPRINDEX!=1 (le DROP est déjà fait synchrone par reconcile_expr_indexes_fast). Chaque
/// CREATE INDEX partiel est borné (1 seul à la fois, jamais en boucle/churn) ; il tient le lock writer LE
/// TEMPS d'UN index (one-time, partiel WHERE expr IS NOT NULL -> petit), puis le relâche entre chaque ->
/// l'ingest respire. IF NOT EXISTS -> idempotent (no-op si déjà créés au boot précédent).
pub(crate) fn reconcile_expr_indexes_background(db: &Arc<Mutex<Connection>>) {
    let conf = load_config();
    if cfg(&conf, "PLUME_EXPRINDEX", "1") != "1" {
        return; // OFF : rien à créer (le drop est synchrone au boot).
    }
    // Court-circuit : si tout est déjà là, on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        if expr_indexes_all_present(&conn) {
            return;
        }
    }
    for c in EXPR_INDEX_FIELDS {
        // 1 SEUL CREATE INDEX à la fois, lock writer pris/relâché PAR index (borné, one-time) -> pas de
        // lock O(lignes) non borné tenu sur tout le lot. Partiel (WHERE expr IS NOT NULL) -> index minuscule.
        {
            let conn = db.lock();
            let r = conn.execute(
                &format!(
                    "CREATE INDEX IF NOT EXISTS idx_ev_f_{c} ON event(json_extract(fields,'$.{c}')) \
                     WHERE json_extract(fields,'$.{c}') IS NOT NULL"
                ),
                [],
            );
            if let Err(e) = r {
                eprintln!("[reconcile-bg] CREATE INDEX idx_ev_f_{c} ÉCHEC ({e}) — retry au prochain boot");
                // on continue avec les suivants ; l'idempotence (IF NOT EXISTS) rattrape au boot suivant.
            }
        }
        // respiration entre deux index : laisse l'ingest et les lectures passer (anti-famine writer).
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("[reconcile-bg] {} index expression partiels présents ({}) — créés en fond, boot non bloqué", EXPR_INDEX_FIELDS.len(), EXPR_INDEX_FIELDS.join(","));
}

/// Crée l'index MANQUANT idx_event_category EN TÂCHE DE FOND (jamais synchrone au boot :
/// un CREATE INDEX sur 2,39M lignes chiffrées bloquerait le bind -> liveness k8s -> CrashLoopBackOff).
/// Modèle reconcile_expr_indexes_background : court-circuit si déjà présent (pas de lock writer inutile),
/// sinon UN CREATE one-shot sous lock writer borné (one-time). IF NOT EXISTS -> idempotent (no-op au boot
/// suivant). L'index sert le filtre courant `category=auth` (sinon full-scan déchiffré). Le re-ANALYZE
/// (analyze_full_background, ré-armé par le bump v47) fait connaître l'index au planner.
pub(crate) fn ensure_event_category_index_background(db: &Arc<Mutex<Connection>>) {
    // court-circuit : déjà là -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        if conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_event_category'", [], |_| Ok(()))
            .is_ok()
        {
            return;
        }
    }
    let conn = db.lock();
    match conn.execute("CREATE INDEX IF NOT EXISTS idx_event_category ON event(category)", []) {
        Ok(_) => eprintln!("[reconcile-bg] idx_event_category créé en fond (filtre category=... ne full-scanne plus ; boot non bloqué)"),
        Err(e) => eprintln!("[reconcile-bg] CREATE INDEX idx_event_category ÉCHEC ({e}) — retry au prochain boot"),
    }
}

/// v110 (ALLÈGEMENT INDEX HOT — P5) — DROP EN TÂCHE DE FOND des deux index REDONDANTS de `event`, sur la base
/// LIVE (une base neuve ne les crée plus : `db/schema.sql` ne les DÉCLARE PLUS). REMPLACE l'ancien
/// `ensure_event_source_index_background` (CHANGE 4 v103) qui CRÉAIT idx_event_src : ce source-seul était un
/// contournement du planner (qui ignorait alors (source, src_ip) pour un `source=X` pur), rendu OBSOLÈTE par
/// idx_event_src_ts(source, ts) de v108 — que le planner CHOISIT pour `source=X` (prouvé EXPLAIN QUERY PLAN).
/// Chaque index retiré est le PRÉFIXE STRICT d'un composite qui le subsume -> le retrait n'introduit AUCUN
/// full-scan (le seek garde la même colonne de tête). DROP INDEX = cheap (libère les pages du btree, NE
/// déchiffre PAS la table grasse) -> SÛR en fond, contrairement à un CREATE INDEX (doctrine anti-crashloop
/// non applicable). Idempotent (court-circuit si déjà droppés) ; gardé par la présence du remplaçant.
///
///   1) idx_event_sev(severity) ⊂ idx_event_sev_srcip(severity, src_ip) [migrate_v31, garanti sur toute base
///      ayant passé v31] -> DROP INCONDITIONNEL (le composite sert tout seek severity).
///   2) idx_event_src(source)   ⊂ idx_event_src_ts(source, ts) [v108] -> DROP UNIQUEMENT si idx_event_src_ts
///      est CONFIRMÉ présent (jamais avant que son remplaçant existe -> ZÉRO fenêtre de scan ; si src_ts pas
///      encore créé par ensure_event_src_ts_index_background, on laisse source-seul et on retentera au boot
///      suivant). idx_event_src_srcip(source, src_ip) reste un filet supplémentaire de toute façon.
pub(crate) fn drop_redundant_event_indexes_background(db: &Arc<Mutex<Connection>>) {
    let conn = db.lock();
    // 1) severity-seul : subsumé INCONDITIONNELLEMENT par le composite (severity, src_ip) [v31].
    drop_subsumed_index(&conn, "idx_event_sev", Subsumant::ParConstruction("idx_event_sev_srcip(severity, src_ip) [v31]"), "P5 v110");
    // 2) source-seul : droppé SEULEMENT si le remplaçant (source, ts) existe -> zéro fenêtre de scan.
    drop_subsumed_index(&conn, "idx_event_src", Subsumant::Explicite("idx_event_src_ts"), "P5 v110");
}

/// CE QUI SUBSUME un index redondant — et, par là, CE QU'IL FAUT VÉRIFIER AVANT DE LE DROPPER. La
/// distinction n'est pas cosmétique : elle décide s'il existe ou non une FENÊTRE pendant laquelle la
/// base n'aurait plus AUCUN index de tête sur la colonne.
enum Subsumant<'a> {
    /// Le subsumant existe PAR CONSTRUCTION, donc rien à confirmer. Deux cas :
    ///  - l'AUTO-INDEX d'une contrainte `UNIQUE(...)` / `PRIMARY KEY(...)` : SQLite le crée AVEC la table
    ///    (`sqlite_autoindex_<table>_N`) et il ne peut pas en être séparé — si la table est là, il est là ;
    ///  - un index explicite posé par une migration ANTÉRIEURE et donc garanti sur toute base ayant passé
    ///    cette version (cas idx_event_sev_srcip / v31).
    /// Le `&str` porté est la DESCRIPTION lisible du subsumant, pour le journal — jamais un nom à chercher.
    ParConstruction(&'a str),
    /// Le subsumant est un index EXPLICITE dont la présence n'est PAS garantie à cet instant (il peut être
    /// créé par une autre tâche de fond, elle-même retentée au boot suivant). Le `&str` est son NOM, et il
    /// est CONFIRMÉ dans `sqlite_master` avant tout DROP — doctrine v110 : « jamais droppé avant que son
    /// remplaçant existe » -> ZÉRO fenêtre de scan sur les gros flux.
    Explicite(&'a str),
}

/// UN retrait d'index redondant, avec sa garde et son journal. Mécanique COMMUNE aux droppers de fond
/// (`drop_redundant_event_indexes_background` v110 et `drop_prefix_subsumed_indexes_background`) : elle est
/// EXTRAITE plutôt que recopiée, pour que la règle « on confirme le subsumant explicite, jamais l'auto-index »
/// n'existe qu'à UN endroit.
///
/// POURQUOI UN DROP EST SÛR EN TÂCHE DE FOND ALORS QU'UN CREATE NE L'EST PAS. `DROP INDEX` ne fait que rendre
/// au freelist les pages du btree de l'index : il NE LIT NI NE DÉCHIFFRE la table (aucune page de `event` /
/// `alert` n'est touchée), donc son coût ne dépend PAS du volume de lignes. `CREATE INDEX`, lui, doit
/// DÉCHIFFRER et trier la totalité de la table SQLCipher : sur des millions de lignes (auditd ~4M) il tient le
/// verrou d'écriture assez longtemps pour retarder le bind -> la liveness probe k8s échoue -> CrashLoopBackOff
/// (leçon idx_event_category / idx_event_src_ts). La doctrine anti-crashloop qui interdit un CREATE synchrone
/// ne s'applique donc PAS à un DROP.
///
/// Idempotent : court-circuit si l'index n'est plus là (aucune prise du writer inutile), `IF EXISTS` sinon.
/// Un échec n'est jamais fatal — il est NOMMÉ et retenté au boot suivant.
fn drop_subsumed_index(conn: &Connection, redondant: &str, subsumant: Subsumant<'_>, origine: &str) {
    let present = |name: &str| -> bool {
        conn.query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![name], |_| Ok(()))
            .is_ok()
    };
    if !present(redondant) {
        return; // déjà droppé (ou base neuve : plus aucune migration ne le crée) -> rien à faire
    }
    let quoi = match subsumant {
        Subsumant::ParConstruction(desc) => desc,
        Subsumant::Explicite(nom) => {
            if !present(nom) {
                eprintln!(
                    "[reconcile-bg] {redondant} CONSERVÉ ce boot : son subsumant {nom} n'est pas encore \
                     présent (drop différé -> zéro fenêtre de scan ; retry au prochain boot)"
                );
                return;
            }
            nom
        }
    };
    match conn.execute(&format!("DROP INDEX IF EXISTS {redondant}"), []) {
        Ok(_) => eprintln!("[reconcile-bg] {redondant} DROPPÉ (subsumé par {quoi} ; seek préservé sur la colonne de tête ; {origine})"),
        Err(e) => eprintln!("[reconcile-bg] DROP INDEX {redondant} ÉCHEC ({e}) — retry au prochain boot"),
    }
}

/// P10.2-d (ALLÈGEMENT INDEX, SUITE) — DROP EN TÂCHE DE FOND des NEUF index redondants que le schéma migré
/// posait encore, sur la base LIVE qui les porte déjà (une base neuve ne les crée plus : les `CREATE INDEX`
/// ont été RETIRÉS de `migrate.rs` à leur source, cf. les notes « P10.2-d » qui y sont laissées).
///
/// POURQUOI UNE FONCTION VOISINE ET PAS UNE EXTENSION DE `drop_redundant_event_indexes_background`. Ce nom-là
/// dit « event_indexes », et SEPT de ces neuf index ne sont PAS sur `event` (ils sont sur `alert`, `banned_ip`,
/// `case_link`, `dashboard_snapshot`, `data_model_field`, `data_model_object`, `net_ban`, `ueba_baseline_obs`,
/// `event_rollup`). Y verser neuf entrées aurait fabriqué exactement la classe fourre-tout que la règle du
/// dépôt interdit, et rendu FAUX un nom qui est aujourd'hui EXACT pour les deux index de v110. La règle
/// « extraire plutôt qu'allonger » est appliquée à la MÉCANIQUE, pas à la liste : le `has_index` + DROP +
/// journal + garde vit désormais dans `drop_subsumed_index`, et les DEUX droppers l'appellent. Chacun garde
/// un nom qui décrit exactement son périmètre, et la campagne v110 garde son identité (son marqueur, son
/// rollback documenté). ASSUMÉ : deux fonctions, zéro mécanique dupliquée.
///
/// LE CRITÈRE, UNIFORME : chaque index retiré est un PRÉFIXE (au sens SQLite : mêmes colonnes, dans le MÊME
/// ORDRE, en tête) d'un index qui le subsume -> tout seek que le redondant servait, le subsumant le sert avec
/// la MÊME colonne de tête. Le doublon EXACT est le cas dégénéré du préfixe (une liste est un préfixe
/// d'elle-même). AUCUNE requête ne change de RÉSULTAT (un index ne détermine qu'un PLAN) ; prouvé par mutation
/// (2026-08-05) : après DROP, aucun passage en SCAN et le planificateur NOMME l'index subsumant.
///
/// 1) DOUBLONS EXACTS d'une contrainte — l'auto-index existe PAR CONSTRUCTION avec la table -> INCONDITIONNEL :
///      idx_dashboard_snapshot_tok(token)                = UNIQUE(token) de dashboard_snapshot [v90]
///      idx_baseline_obs(baseline_id, entity, bucket)    = PRIMARY KEY(baseline_id, entity, bucket) [v84]
/// 2) PRÉFIXES STRICTS d'un auto-index de contrainte — même garantie de construction -> INCONDITIONNEL :
///      idx_banned_ip_srcip(src_ip)   ⊂ PK(src_ip, source)                          de banned_ip        [v52]
///      idx_case_link_src(src_id)     ⊂ UNIQUE(src_id, dst_id, kind)                de case_link        [v28]
///      idx_dm_field_object(object_id)⊂ UNIQUE(object_id, name)                     de data_model_field [v45]
///      idx_dm_object_model(model_id) ⊂ UNIQUE(model_id, name)                      de data_model_object[v45]
///      idx_event_rollup(bucket)      ⊂ PK(bucket, source, severity, action, src_ip, host, env_id)      [v33/v67]
///      idx_net_ban_ip(ip)            ⊂ PK(ip, env_id)                              de net_ban          [v111]
/// 3) PRÉFIXE STRICT d'un index EXPLICITE — le SEUL cas gardé, car son subsumant peut manquer sur une base
///    donnée (il vient d'une migration, pas d'une contrainte) :
///      idx_alert_mitre(mitre) ⊂ idx_alert_mitre_ts(mitre, ts) [v72] -> DROP UNIQUEMENT si idx_alert_mitre_ts
///      est CONFIRMÉ présent dans sqlite_master. Sinon on CONSERVE mitre-seul ce boot et on retente au suivant :
///      `/api/alerts?mitre=` et `coverage_detections` ne doivent jamais traverser une fenêtre sans index de tête
///      sur `mitre`.
///
/// NE SONT PAS ICI, et c'est délibéré : les index PARTIELS (`idx_event_health_beat` WHERE category='health',
/// `idx_incident_active`, `idx_incident_notmerged`). Un index partiel n'est JAMAIS subsumé par un index plein
/// de mêmes colonnes de tête — il est plus petit et sert un prédicat que l'autre ne porte pas. La garde dérivée
/// (`tests/index_redondance.rs`) les EXCLUT par la colonne `partial` de `PRAGMA index_list`, pour la même raison.
pub(crate) fn drop_prefix_subsumed_indexes_background(db: &Arc<Mutex<Connection>>) {
    let conn = db.lock();
    for (redondant, contrainte) in [
        ("idx_dashboard_snapshot_tok", "l'auto-index de UNIQUE(token) de dashboard_snapshot"),
        ("idx_baseline_obs", "l'auto-index de PRIMARY KEY(baseline_id, entity, bucket) de ueba_baseline_obs"),
        ("idx_banned_ip_srcip", "l'auto-index de PRIMARY KEY(src_ip, source) de banned_ip"),
        ("idx_case_link_src", "l'auto-index de UNIQUE(src_id, dst_id, kind) de case_link"),
        ("idx_dm_field_object", "l'auto-index de UNIQUE(object_id, name) de data_model_field"),
        ("idx_dm_object_model", "l'auto-index de UNIQUE(model_id, name) de data_model_object"),
        ("idx_event_rollup", "l'auto-index de PRIMARY KEY(bucket, source, severity, action, src_ip, host, env_id) de event_rollup"),
        ("idx_net_ban_ip", "l'auto-index de PRIMARY KEY(ip, env_id) de net_ban"),
    ] {
        drop_subsumed_index(&conn, redondant, Subsumant::ParConstruction(contrainte), "P10.2-d");
    }
    // Le SEUL dont le subsumant est un index EXPLICITE (v72) et non un auto-index -> garde obligatoire.
    drop_subsumed_index(&conn, "idx_alert_mitre", Subsumant::Explicite("idx_alert_mitre_ts"), "P10.2-d");
}

/// v108 (PERF recherche raw haut-volume) — crée l'index COMPOSITE MANQUANT idx_event_src_ts(source, ts) EN
/// TÂCHE DE FOND sur la base MIGRÉE. La recherche brute `search source=X earliest=-Nd` compile en `... FROM event
/// WHERE source=? AND ts>=?` : idx_event_src (source-seul) SEEK source mais doit LIRE chaque ligne pour ts, et le
/// COUNT de pagination non borné déchiffrait TOUTE la table grasse (message/fields) -> budget 60s dépassé. Le
/// COMPOSITE couvre source+ts -> le COUNT BORNÉ (query.rs) devient un balayage INDEX-ONLY plafonné (zéro
/// déchiffrement de table) et la page range-prune sur ts. `db/schema.sql` le déclare (bases NEUVES l'ont, table
/// vide) mais AUCUNE migration ne peut le créer synchrone : un CREATE INDEX sur des MILLIONS de lignes chiffrées
/// (auditd ~4M) bloquerait le bind -> liveness k8s -> CrashLoopBackOff (cf. idx_event_category/idx_event_src). MÊME
/// nom que schema.sql -> sur base neuve le court-circuit no-op (pas de btree en double), sur la base live on comble
/// le trou. Modèle EXACT de ensure_event_source_index_background : court-circuit si présent, sinon UN CREATE
/// one-shot IF NOT EXISTS (idempotent). Le re-ANALYZE (bump v108) fait connaître l'index au planner. `source` =
/// TEXT faible cardinalité (~35) -> btree petit, disque, RAM négligeable (budget 2 Go). PURE optimisation.
pub(crate) fn ensure_event_src_ts_index_background(db: &Arc<Mutex<Connection>>) {
    // court-circuit : déjà là (base neuve via schema.sql, ou déjà créé) -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        if conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_event_src_ts'", [], |_| Ok(()))
            .is_ok()
        {
            return;
        }
    }
    let conn = db.lock();
    match conn.execute("CREATE INDEX IF NOT EXISTS idx_event_src_ts ON event(source, ts)", []) {
        Ok(_) => eprintln!("[reconcile-bg] idx_event_src_ts(source,ts) créé en fond (recherche raw source=X sur fenêtre longue : COUNT pagination index-only borné + page range-prune ts ; boot non bloqué, v108)"),
        Err(e) => eprintln!("[reconcile-bg] CREATE INDEX idx_event_src_ts ÉCHEC ({e}) — retry au prochain boot"),
    }
}

/// P3.7-a (PERF INGEST — les sondes dead-man's-switch rendaient l'ingestion quadratique) — crée EN TÂCHE
/// DE FOND l'index PARTIEL `idx_event_health_beat(source, ts) WHERE category='health'` sur la base MIGRÉE.
///
/// CE QU'IL FERME. Les 8 sondes `Sonde::EventBattementSante` de `COLLECTORS` tournent DANS
/// `check_heartbeats`, SOUS LE VERROU D'ÉCRITURE, tous les 20 s. Leur `MAX(ts) WHERE source=? AND
/// category='health'` ne peut pas être servi par idx_event_src_ts(source, ts) : `category` n'y est pas,
/// donc SQLite SEEK la source puis REMONTE sa plage en lisant la LIGNE de chaque candidat jusqu'à trouver
/// un battement. MESURÉ le 2026-08-03 (compteur VM_STEP, déterministe) : `VM steps = 5 x (lignes de la
/// source postérieures au dernier battement) + c`, la PENTE valant EXACTEMENT 5 sur 5 points (`c` = petite
/// constante, 13 à 20 selon l'implémentation SQLite ; le 6e point, 0 ligne, est le cas dégénéré = coût
/// constant). À volume x4 les sondes dont la source n'a jamais battu passent EXACTEMENT x4, confirmé sur
/// DEUX implémentations SQLite indépendantes (CLI 3.53 et le SQLCipher embarqué : 2 014 -> 8 014 sans
/// l'index, 13 constant avec). Une sonde dead-man's-switch devient donc la plus
/// chère précisément quand le collecteur qu'elle surveille est MORT — panne AUTO-AMPLIFIANTE, et ce qu'elle
/// consomme sous le verrou, l'ingestion ne l'a pas.
///
/// POURQUOI PARTIEL et pas (source, category, ts) : MESURÉ, le composite plein coûte 25,5 o/LIGNE INGÉRÉE
/// (~250 Mio sur les 9,8 M lignes prod) + un insert btree sur le CHEMIN D'INGEST CHAUD ; le partiel coûte
/// 21,8 o/LIGNE DE BATTEMENT (~1,5 Mio pour 8 collecteurs battant toutes les 5 min sur 30 j) + un insert
/// toutes les ~37 s. 166x moins de disque, et l'objection d'amplification d'écriture qui avait fait écarter
/// le correctif (cf. handlers/freshness.rs) ne porte que sur le composite plein. Budget 2 Go préservé.
///
/// JAMAIS SYNCHRONE AU BOOT : un CREATE INDEX sur des millions de lignes chiffrées SQLCipher bloquerait le
/// bind -> liveness k8s -> CrashLoopBackOff (leçon idx_event_category / idx_event_src_ts). Modèle EXACT de
/// `ensure_event_src_ts_index_background` : court-circuit si présent (base neuve via schema.sql, ou déjà
/// créé), sinon UN CREATE one-shot IF NOT EXISTS (idempotent, MÊME nom que schema.sql -> aucun btree en
/// double). Le re-ANALYZE (bump v114) fait connaître l'index au planner. La DDL n'est PAS réécrite ici :
/// elle vient de `sondes::DDL_IDX_BATTEMENT_SANTE`, à côté des sondes qui en dépendent (zéro dérive).
/// ADDITIF, mode 0 byte-identique : l'index ne change AUCUNE valeur rendue, seulement le chemin d'accès.
pub(crate) fn ensure_event_health_beat_index_background(db: &Arc<Mutex<Connection>>) {
    // court-circuit : déjà là -> on évite même de prendre le lock writer.
    {
        let conn = db.lock();
        if conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![IDX_BATTEMENT_SANTE], |_| Ok(()))
            .is_ok()
        {
            return;
        }
    }
    let conn = db.lock();
    match conn.execute(DDL_IDX_BATTEMENT_SANTE, []) {
        Ok(_) => eprintln!(
            "[reconcile-bg] {IDX_BATTEMENT_SANTE}(source,ts) WHERE category='health' créé en fond \
             (les 8 sondes dead-man's-switch cessent de remonter la plage de leur source sous le verrou d'écriture ; P3.7-a)"
        ),
        Err(e) => eprintln!("[reconcile-bg] CREATE INDEX {IDX_BATTEMENT_SANTE} ÉCHEC ({e}) — retry au prochain boot"),
    }
}

/// ANTI FULL-SCAN (rollup_hosts sur metric/snapshot) — crée EN TÂCHE DE FOND les index ts-leading
/// idx_metric_ts / idx_snapshot_ts. `metric` n'a que idx_metric(name,ts) et `snapshot` idx_snapshot(kind,ts) :
/// ts n'y est PAS colonne de tête, donc le prédicat borné `ts >= recent` de rollup_hosts (chaque tick, sous le
/// lock writer) NE peut PAS range-pruner -> full-scan + déchiffrement SQLCipher de TOUTE la table metric/snapshot
/// -> famine de l'ingest (même lock) + le `MAX(ts)` par-requête de pipeline_is_fresh (integrations/fleet) qui
/// scannait pareil. Avec ces index : les fenêtres du rollup deviennent des range-scans indexés (O(lignes de la
/// fenêtre)) et `MAX(ts)` devient un simple max indexé O(1). JAMAIS synchrone au boot : un CREATE INDEX sur ~2M
/// lignes metric chiffrées bloquerait le bind -> liveness k8s -> CrashLoopBackOff (cf. idx_event_category). One-shot,
/// idempotent (IF NOT EXISTS + court-circuit), 1 index à la fois, lock writer pris/relâché PAR index (l'ingest
/// respire entre deux). PURE optimisation (aucune sémantique changée) — « optimiser, pas augmenter les ressources ».
pub(crate) fn ensure_host_rollup_scan_indexes_background(db: &Arc<Mutex<Connection>>) {
    for (name, ddl) in [
        ("idx_metric_ts",   "CREATE INDEX IF NOT EXISTS idx_metric_ts ON metric(ts)"),
        ("idx_snapshot_ts", "CREATE INDEX IF NOT EXISTS idx_snapshot_ts ON snapshot(ts)"),
    ] {
        // court-circuit : déjà là -> on évite même de prendre le lock writer.
        {
            let conn = db.lock();
            if conn.query_row("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1", params![name], |_| Ok(())).is_ok() {
                continue;
            }
        }
        {
            let conn = db.lock();
            match conn.execute(ddl, []) {
                Ok(_) => eprintln!("[reconcile-bg] {name} créé en fond (rollup_hosts range-prune metric/snapshot au lieu de full-scan ; MAX(ts) freshness = max indexé ; boot non bloqué)"),
                Err(e) => eprintln!("[reconcile-bg] CREATE INDEX {name} ÉCHEC ({e}) — retry au prochain boot"),
            }
        }
        // respiration entre deux index : laisse l'ingest et les lectures passer (anti-famine writer).
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Ajoute (idempotent) les panneaux « Sévérité >=3 par src_ip » et « Volume par host » au dashboard
/// « Vue d'ensemble (rapide) » s'ils manquent. Garde par (dashboard_id, titre) -> jamais de
/// doublon, et ne touche pas les dashboards utilisateurs. Réutilisable (migration v37 + filet au boot).
/// GÉNÉRIQUE SUR `SqlExec` (cf. migrate.rs) : `&Connection` depuis le boot (historique inchangé),
/// `&MigTx` depuis la migration v37 -> écritures SOUS le garde de l'étape.
pub(crate) fn ensure_rollup_srcip_host_panels<C: SqlExec>(conn: &C) {
    let did: i64 = match conn.query_row(
        "SELECT id FROM dashboard WHERE name='Vue d''ensemble (rapide)'",
        [],
        |r| r.get(0),
    ) {
        Ok(d) => d,
        Err(_) => return, // dashboard absent (install pré-seed) -> seed_rollup_dashboard s'en chargera
    };
    let extra: [(&str, &str, &str); 2] = [
        ("Sévérité >=3 par src_ip", "SELECT src_ip, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 AND src_ip<>'' GROUP BY src_ip ORDER BY n DESC LIMIT 20", "bar"),
        ("Volume par host", "SELECT host, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND host<>'' GROUP BY host ORDER BY n DESC LIMIT 20", "bar"),
    ];
    for (title, q, viz) in extra {
        let exists: bool = conn
            .query_row("SELECT 1 FROM panel WHERE dashboard_id=?1 AND title=?2", params![did, title], |_| Ok(()))
            .is_ok();
        if exists {
            continue;
        }
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) \
             VALUES(?1,?2,?3,0,?4,(SELECT COALESCE(MAX(position),-1)+1 FROM panel WHERE dashboard_id=?1),2)",
            params![did, title, q, viz],
        );
    }
}

/// ANALYZE COMPLET (analysis_limit=0) EN TÂCHE DE FOND : déchiffre toute la table `event`
/// (coûteux : 1-2 min sur base SQLCipher volumineuse) pour des stats exactes -> le planner choisit
/// idx_event_sev_srcip. Lancé APRÈS le bind (boot non bloquant). Gardé par la meta clé 'analyze_full_done'
/// = version du schéma au moment du ANALYZE : on ne le refait qu'une fois par schéma (idempotent, ré-armé
/// si un futur changement d'index bump la version). On prend le lock writer (ANALYZE écrit sqlite_stat1),
/// mais brièvement comparé au bind, et hors du chemin de démarrage.
pub(crate) fn analyze_full_background(db: &Arc<Mutex<Connection>>) {
    let conn = db.lock();
    let ver: String = conn
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
        .unwrap_or_else(|_| "0".into());
    let done: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key='analyze_full_done'", [], |r| r.get(0))
        .ok();
    if done.as_deref() == Some(ver.as_str()) {
        return; // déjà fait pour ce schéma
    }
    let _ = conn.execute_batch("PRAGMA analysis_limit=0; ANALYZE;");
    let _ = conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('analyze_full_done', ?1)",
        params![ver],
    );
    eprintln!("[analyze] ANALYZE complet terminé (tâche de fond) -> stats exactes pour les index composés");
}

/// PHASE 1 — BACKFILL EN FOND de `event_fields_fts` pour les 1,24M lignes existantes. Modèle
/// analyze_full_background : std::thread::spawn APRÈS le bind, sleep initial (laisse passer bind +
/// liveness). JAMAIS synchrone (anti-crashloop k8s). Actif SEULEMENT si PLUME_FTS_FIELDS=1 ET
/// PLUME_FTS_FIELDS_BACKFILL=1. IDEMPOTENT + REPRENABLE par WATERMARK décroissant (meta
/// 'fts_fields_backfill_hi' = plus petit id non encore traité) : on indexe du plus RÉCENT au plus
/// ancien -> les recherches récentes profitent du FTS en premier. Un kill k8s à mi-backfill reprend
/// au lot suivant (le watermark survit). Borné par lot sous lock writer COURT (modèle ingest batch)
/// + respiration entre lots (ne famine ni l'ingest ni les lectures). RAM bornée (INSERT...SELECT
/// streame, pas d'accumulation -> respecte <100Mo). Gardé final par meta 'fts_fields_backfill_done'.
pub(crate) fn fts_backfill_background(db: &Arc<Mutex<Connection>>) {
    let conf = load_config();
    if cfg(&conf, "PLUME_FTS_FIELDS", "0") != "1" || cfg(&conf, "PLUME_FTS_FIELDS_BACKFILL", "1") != "1" {
        return; // Phase 1 OFF ou backfill historique désactivé -> rien (les triggers indexent le neuf).
    }
    let batch: i64 = cfg(&conf, "PLUME_FTS_BACKFILL_BATCH", "5000").parse().unwrap_or(5000).clamp(100, 100_000);
    let sleep_ms: u64 = cfg(&conf, "PLUME_FTS_BACKFILL_SLEEP_MS", "200").parse().unwrap_or(200);
    let done_tag = "40"; // version de schéma à laquelle ce backfill correspond (comme analyze_full_done)

    // Garde idempotente : déjà terminé pour ce schéma -> no-op immédiat.
    {
        let conn = db.lock();
        // L'infra doit exister (PLUME_FTS_FIELDS=1 a créé la vtable en v40) ; sinon on s'abstient.
        let has_vtable: bool = conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_fields_fts'", [], |_| Ok(()))
            .is_ok();
        if !has_vtable {
            return;
        }
        let done: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key='fts_fields_backfill_done'", [], |r| r.get(0))
            .ok();
        if done.as_deref() == Some(done_tag) {
            return;
        }
    }

    // lo = watermark (plus petit id NON encore traité). Init = MAX(id)+1 (tout l'historique restant).
    let mut lo: i64 = {
        let conn = db.lock();
        let wm: Option<i64> = conn
            .query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key='fts_fields_backfill_hi'", [], |r| r.get(0))
            .ok();
        match wm {
            Some(v) => v,
            None => conn.query_row("SELECT COALESCE(MAX(id),0)+1 FROM event", [], |r| r.get(0)).unwrap_or(0),
        }
    };

    eprintln!("[fts-backfill] démarrage backfill event_fields_fts (watermark id<{lo}, lot {batch})");
    while lo > 0 {
        let next = (lo - batch).max(0);
        let inserted: i64 = {
            let conn = db.lock();
            // Transaction bornée (modèle ingest batch). INSERT...SELECT streame (RAM bornée).
            // NOT EXISTS rend chaque lot ré-insérable sans doublon (idempotent même si le watermark
            // est perdu). On indexe la tranche [next, lo).
            let r = conn.execute(
                "INSERT INTO event_fields_fts(rowid, v) \
                 SELECT e.id, (SELECT group_concat(je.value,' ') FROM json_each(e.fields) je \
                                WHERE je.value IS NOT NULL AND je.type IN ('text','integer','real')) \
                   FROM event e \
                  WHERE e.id >= ?1 AND e.id < ?2 \
                    AND e.fields IS NOT NULL AND json_valid(e.fields) \
                    AND NOT EXISTS (SELECT 1 FROM event_fields_fts WHERE rowid = e.id)",
                params![next, lo],
            );
            match r {
                Ok(n) => n as i64,
                Err(e) => {
                    eprintln!("[fts-backfill] lot [{next},{lo}) ÉCHEC ({e}) — réessai au prochain boot");
                    return; // watermark inchangé -> reprise au même endroit au prochain démarrage
                }
            }
        };
        // avance + persiste le watermark APRÈS le COMMIT du lot (reprise exacte). Lock writer relâché.
        lo = next;
        {
            let conn = db.lock();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('fts_fields_backfill_hi', ?1)",
                params![lo.to_string()],
            );
        }
        let _ = inserted;
        if lo > 0 {
            std::thread::sleep(Duration::from_millis(sleep_ms)); // respiration : laisse ingest + lectures passer
        }
    }
    {
        let conn = db.lock();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('fts_fields_backfill_done', ?1)",
            params![done_tag],
        );
    }
    eprintln!("[fts-backfill] backfill event_fields_fts TERMINÉ (historique indexé)");
}

/// PHASE 3 — AUTO-INDEX ADAPTATIF PLAFONNÉ (OFF par défaut). Détecte à l'usage les champs `fields.X`
/// réellement filtrés/groupés ET lents, et crée un index expression pour eux EN FOND, plafonné, sans
/// churn, éviction LRU. Modèle analyze_full_background : thread spawn après bind, sleep initial 120s
/// puis boucle toutes les PLUME_AUTOINDEX_INTERVAL. Tout sous lock writer BORNÉ (1 CREATE/DROP par
/// tick max). Si désactivé (PLUME_AUTOINDEX!=1), la boucle ne crée RIEN (les index déjà créés restent
/// et servent ; PLUME_AUTOINDEX_PURGE=1 pour les purger). Aucun travail dans migrate() -> pas de
/// crashloop : un échec de CREATE est loggé (`let _ =`), retry au tick suivant.
// #2a-2c : maintenance auto-index PAR TENANT. `mgr` -> for_each_active_tenant : mode 0 = 1 passe sur la base
// unique (comportement STRICTEMENT identique), mode 1 = setup + tick sur CHAQUE base tenant (chaque tenant
// gère ses propres index adaptatifs ; buffers/set d'index keyés db_path #2a-1). Itération SÉQUENTIELLE (pas
// de fan-out : budget 2 Go). Les tunables (seuils/intervalle/décroissance) sont globaux (config), une seule
// lecture pour tous les tenants.
pub(crate) fn autoindex_maintain_background(mgr: &TenantDbManager) {
    let conf = load_config();
    let purge = cfg(&conf, "PLUME_AUTOINDEX_PURGE", "0") == "1";
    // SETUP PAR TENANT (une fois au boot) : PURGE éventuelle (reset propre : DROP idx_ev_auto_* + vide la
    // table autoindex) PUIS chargement du set des champs déjà indexés (utile même si OFF : la garde anti-CAST
    // doit les connaître). En mode 0 : une seule passe sur la base unique = comportement identique.
    for_each_active_tenant(mgr, |_tid, db, db_path| {
        if purge {
            { let conn = db.lock();
                let fields: Vec<String> = conn
                    .prepare("SELECT field FROM autoindex WHERE indexed=1")
                    .and_then(|mut st| {
                        st.query_map([], |r| r.get::<_, String>(0)).map(|rows| rows.flatten().collect())
                    })
                    .unwrap_or_default();
                for f in &fields {
                    if soql_ident_ok(f) {
                        let _ = conn.execute(&format!("DROP INDEX IF EXISTS idx_ev_auto_{f}"), []);
                    }
                }
                let _ = conn.execute("DELETE FROM autoindex", []);
                autoindex_reload(&conn, db_path);
                eprintln!("[autoindex] PURGE effectuée ({} index auto droppés)", fields.len());
            }
        }
        { let conn = db.lock();
            autoindex_reload(&conn, db_path);
        }
    });

    if cfg(&conf, "PLUME_AUTOINDEX", "0") != "1" {
        return; // Phase 3 OFF : pas de tâche de maintenance (les index existants restent actifs).
    }
    let interval: u64 = cfg(&conf, "PLUME_AUTOINDEX_INTERVAL", "300").parse().unwrap_or(300).max(10);
    let min_hits: u32 = cfg(&conf, "PLUME_AUTOINDEX_MIN_HITS", "10").parse().unwrap_or(10);
    let min_slow: u32 = cfg(&conf, "PLUME_AUTOINDEX_MIN_SLOW", "3").parse().unwrap_or(3);
    let cap: i64 = cfg(&conf, "PLUME_AUTOINDEX_MAX", "8").parse().unwrap_or(8).max(0);
    let ttl: i64 = cfg(&conf, "PLUME_AUTOINDEX_TTL", "604800").parse().unwrap_or(604_800);
    // FACTEUR TEMPS (decay) : à chaque tick on multiplie hits/slow_hits par ce facteur (∈ ]0,1]) ->
    // les champs FROIDS (plus de trafic) retombent sous les seuils et sortent (purge anti-bloat).
    // DÉFAUT CONSERVATEUR 0.9 (oubli DOUX : ~10 ticks pour diviser par ~3) -> ne casse pas brutalement
    // le comportement cumulatif actuel. 1.0 = aucun oubli (comportement historique exact, kill-switch).
    let decay: f64 = cfg(&conf, "PLUME_AUTOINDEX_DECAY", "0.9").parse::<f64>().unwrap_or(0.9).clamp(0.0, 1.0);

    std::thread::sleep(Duration::from_secs(120)); // laisse le boot + le 1er trafic se faire
    loop {
        for_each_active_tenant(mgr, |_tid, db, db_path| {
            autoindex_tick(db, db_path, min_hits, min_slow, cap, ttl, decay);
        });
        std::thread::sleep(Duration::from_secs(interval));
    }
}

/// Un tick de maintenance auto-index : flush du buffer mémoire -> table, sélection d'1 candidat,
/// création OU éviction LRU (1 op max), sous lock writer borné. Tunables passés en arguments.
pub(crate) fn autoindex_tick(db: &Arc<Mutex<Connection>>, db_path: &str, min_hits: u32, min_slow: u32, cap: i64, ttl: i64, decay: f64) {
    let now_s = now();
    // 1) FLUSH du buffer mémoire -> UPSERT autoindex(hits+=, slow_hits+=, last_seen=now). On VIDE le
    //    buffer en une fois (drain) pour ne pas tenir le lock buffer pendant l'IO DB.
    //    MT-KEY : on ne draine QUE le buffer de CE db_path (les autres bases gardent le leur intact).
    let drained: Vec<(String, u32, u32)> = {
        let mut top = autoindex_buf().lock();
        top.get_mut(db_path).map(|b| b.drain().map(|(k, (h, s))| (k, h, s)).collect()).unwrap_or_default()
    };
    {
        let conn = db.lock();

        // 0) FACTEUR TEMPS (decay) : on multiplie d'ABORD les compteurs STOCKÉS par `decay` (∈ ]0,1[),
        //    PUIS on ajoute les increments frais de ce tick (EWMA) -> un champ qui ne reçoit plus de
        //    trafic décroît géométriquement et finit par repasser sous les seuils PUIS atteindre 0.
        //    decay>=1.0 = no-op (comportement cumulatif historique, kill-switch). On TRONQUE vers le bas
        //    (CAST sans biais) pour garantir une convergence STRICTE vers 0 (un +0.5 créerait un point
        //    fixe à 1 -> jamais purgé). last_seen n'est PAS touché ici (l'éviction LRU s'en sert).
        if decay < 1.0 {
            let _ = conn.execute(
                "UPDATE autoindex SET \
                   hits = CAST(hits * ?1 AS INTEGER), \
                   slow_hits = CAST(slow_hits * ?1 AS INTEGER)",
                params![decay],
            );
        }

        for (field, h, s) in &drained {
            // field validé (alphanum+_) avant toute interpolation SQL ultérieure.
            if !soql_ident_ok(field) {
                continue;
            }
            let _ = conn.execute(
                "INSERT INTO autoindex(field, hits, slow_hits, last_seen) VALUES(?1, ?2, ?3, ?4) \
                 ON CONFLICT(field) DO UPDATE SET hits=hits+?2, slow_hits=slow_hits+?3, last_seen=?4",
                params![field, *h as i64, *s as i64, now_s],
            );
        }

        // 1bis) PURGE ANTI-BLOAT : les lignes dont les compteurs ont décru ~0 ET qui ne portent PAS
        //       d'index (indexed=0) ne servent plus à rien -> on les retire pour borner la table.
        //       On NE TOUCHE JAMAIS une ligne indexed=1 (l'éviction LRU des index reste seule maîtresse
        //       du cycle de vie des index, anti-régression). No-op si decay désactivé (rien ne décroît).
        if decay < 1.0 {
            let _ = conn.execute(
                "DELETE FROM autoindex WHERE indexed=0 AND hits=0 AND slow_hits=0",
                [],
            );
        }

        // 2) Meilleur CANDIDAT : assez chaud + assez lent, non déjà indexé, hors whitelist figée, hors
        //    denylist cardinalité. Trié par chaleur décroissante (slow puis hits).
        let deny: Vec<String> = AUTOINDEX_DENY.iter().map(|s| s.to_string()).collect();
        let hot: Vec<String> = HOT_FIELDS.iter().map(|s| s.to_string()).collect();
        let is_excluded = |f: &str| deny.iter().any(|d| d == f) || hot.iter().any(|h| h == f);

        let candidate: Option<(String, i64)> = conn
            .prepare(
                "SELECT field, last_seen FROM autoindex \
                 WHERE indexed=0 AND slow_hits>=?1 AND hits>=?2 \
                 ORDER BY slow_hits DESC, hits DESC LIMIT 8",
            )
            .ok()
            .and_then(|mut st| {
                st.query_map(params![min_slow as i64, min_hits as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })
                .ok()
                .map(|rows| {
                    rows.flatten()
                        .find(|(f, _)| soql_ident_ok(f) && !is_excluded(f))
                })
                .flatten()
            });

        let candidate = match candidate {
            Some(c) => c,
            None => {
                drop(conn);
                return; // rien de chaud à indexer ce tick
            }
        };

        let count_idx: i64 = conn
            .query_row("SELECT COUNT(*) FROM autoindex WHERE indexed=1", [], |r| r.get(0))
            .unwrap_or(0);

        if cap == 0 {
            return; // CAP 0 = création désactivée (équivaut à OFF pour la création)
        }

        if count_idx < cap {
            // 3) Sous le CAP : créer l'index pour le candidat (1 SEUL par tick -> pas de pic d'écriture).
            autoindex_create(&conn, &candidate.0, now_s);
        } else {
            // 4) Au CAP : ÉVICTION LRU. On ne remplace QUE si le moins récemment chaud est plus vieux
            //    que le candidat ET plus vieux que TTL (anti-churn).
            if let Ok((victim, vlast)) = conn.query_row(
                "SELECT field, last_seen FROM autoindex WHERE indexed=1 ORDER BY last_seen ASC LIMIT 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            ) {
                if vlast < candidate.1 && (now_s - vlast) > ttl && soql_ident_ok(&victim) {
                    let _ = conn.execute(&format!("DROP INDEX IF EXISTS idx_ev_auto_{victim}"), []);
                    let _ = conn.execute(
                        "UPDATE autoindex SET indexed=0 WHERE field=?1",
                        params![victim],
                    );
                    eprintln!("[autoindex] éviction LRU '{victim}' (last_seen trop ancien) -> place pour '{}'", candidate.0);
                    autoindex_create(&conn, &candidate.0, now_s);
                }
            }
        }
        autoindex_reload(&conn, db_path);
    }
}

/// Crée l'index auto partiel pour `field` (même forme canonique que Phase 2 -> matché automatiquement
/// par le compilo) et marque indexed=1. `field` DOIT être validé par soql_ident_ok par l'appelant.
///
/// NB : ce CREATE INDEX tourne en TÂCHE DE FOND (autoindex_maintain_background,
/// hors hot path), JAMAIS au boot. Il tient le lock writer LE TEMPS d'UN index (one-time, partiel
/// WHERE expr IS NOT NULL -> petit) puis le relâche. Borné par construction : autoindex_tick n'appelle
/// autoindex_create qu'UNE FOIS par tick (1 seul CREATE INDEX à la fois, jamais en boucle), plafonné
/// par PLUME_AUTOINDEX_MAX (cap dur) avec éviction LRU anti-churn (pas de drop/recreate en boucle).
/// Donc : lock writer ponctuel one-time par index, jamais O(lignes) tenu en continu.
fn autoindex_create(conn: &Connection, field: &str, now_s: i64) {
    if !soql_ident_ok(field) {
        return; // garde anti-injection (défense en profondeur)
    }
    let r = conn.execute(
        &format!(
            "CREATE INDEX IF NOT EXISTS idx_ev_auto_{field} ON event(json_extract(fields,'$.{field}')) \
             WHERE json_extract(fields,'$.{field}') IS NOT NULL"
        ),
        [],
    );
    match r {
        Ok(_) => {
            let _ = conn.execute(
                "UPDATE autoindex SET indexed=1, created=?2 WHERE field=?1",
                params![field, now_s],
            );
            eprintln!("[autoindex] index auto créé pour '{field}' (idx_ev_auto_{field})");
        }
        Err(e) => {
            // indexed reste 0 -> retry au tick suivant. Pas d'abandon, pas de blocage.
            eprintln!("[autoindex] CREATE index '{field}' ÉCHEC ({e}) — retry au prochain tick");
        }
    }
}

/// Nom de l'hôte courant (central) : /etc/hostname, sinon $HOSTNAME, sinon "localhost".
/// Sert à savoir quelles actions le central applique lui-même (host local) vs déléguées aux agents.
pub(crate) fn host_self() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}
