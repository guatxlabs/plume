//! Matérialisation périodique (tick) : builders SQL des rollups d'events (`rollup_insert_sql*`,
//! event_rollup), rollups par dimension (`DIM_ROLLUP_*`/`merge_rollup_dims`/`dim_rollup_specs`/
//! `dim_rollup_insert_sql`), inventaire flotte par hôte (`rollup_hosts`/`enum HostFold`/
//! `host_rollup_upsert_sql`/`note_host_backfill_floor`), banlist matérialisée (`banned_ip_upsert_sqls`/
//! `materialize_banned_ip` + dashboard banpass), refresh SWR des panneaux (`cache_refresh_all_panels`)
//! et purge de rétention (`retention_run`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Cap de cardinalité src_ip du rollup : top-N adresses par bucket. Réglable via
/// PLUME_ROLLUP_SRCIP_TOPN (défaut 50). 0 = pas de cap top-N (seul le seuil de
/// sévérité borne alors). Lu hors chemin chaud (rollup périodique).
pub(crate) fn rollup_srcip_topn(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_ROLLUP_SRCIP_TOPN", "50").parse().unwrap_or(50).max(0)
}

/// Construit l'INSERT...SELECT de rollup avec DEUX bornes de cardinalité src_ip :
///   1) SEUIL DE SÉVÉRITÉ : src_ip n'est enrichi que pour severity>=`min_sev` (sinon lump src_ip='').
///   2) CAP TOP-N PAR BUCKET : parmi les src_ip enrichis, on ne GARDE que les `topn` IP avec le plus gros
///      COUNT *par bucket* (fonction fenêtre ROW_NUMBER OVER PARTITION BY bucket ORDER BY count DESC) ;
///      le reste est lumpé en src_ip='' puis ré-agrégé. -> cardinalité BORNÉE même sous attaque (brute-force
///      / scan distribué = des milliers d'IP severity=3 par heure ne font plus exploser le rollup), tout en
///      gardant le TOP des attaquants. `cond` = filtre WHERE sur `event` (bornes i64 formatées, pas
///      d'injection). `topn<=0` -> pas de window function (seul le seuil borne).
///
/// NB : la table event_rollup garde son grain (bucket,source,severity,action,src_ip,host) ; le cap est
/// calculé sur le COUNT par (bucket,src_ip) agrégé toutes dimensions confondues (la « grosseur » réelle
/// de l'attaquant dans ce bucket), puis appliqué uniformément aux lignes de ces src_ip.
fn rollup_insert_sql(cond: &str, min_sev: i64, topn: i64) -> String {
    rollup_insert_sql_into("event_rollup", cond, min_sev, topn)
}

/// Variante de `rollup_insert_sql` avec table cible paramétrable (réutilisée par la migration v33 qui
/// repeuple `event_rollup_new`). `table` est un littéral interne (jamais une entrée utilisateur). Le
/// CORPS SELECT est délégué à `rollup_select_sql` (source UNIQUE, partagée avec le scan lock-free du
/// sidecar cold #28 Phase A) -> l'INSERT et le SELECT-en-mémoire agrègent EXACTEMENT le même résultat.
pub(crate) fn rollup_insert_sql_into(table: &str, cond: &str, min_sev: i64, topn: i64) -> String {
    format!(
        "INSERT OR REPLACE INTO {table}(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) {}",
        rollup_select_sql(cond, min_sev, topn)
    )
}

/// CORPS SELECT (sans préfixe INSERT) du rollup event-grain : les 9 colonnes ordonnées
/// (bucket,source,severity,action,src_ip,host,n,last_ts,env_id). Utilisé (1) inline par
/// `rollup_insert_sql_into` (INSERT...SELECT du hot + migration v33) et (2) VERBATIM par le sidecar cold
/// (#28 Phase A) pour MATÉRIALISER les lignes de rollup EN MÉMOIRE via un scan READ-ONLY hors verrou writer
/// (le résultat est top-N-borné -> RAM bornée), avant un COMMIT court. Même SQL -> même résultat -> parité.
pub(crate) fn rollup_select_sql(cond: &str, min_sev: i64, topn: i64) -> String {
    // expression src_ip bornée par le SEUIL (réutilisée comme dimension de base).
    let srcip_sev = format!("CASE WHEN COALESCE(severity,0) >= {min_sev} THEN COALESCE(src_ip,'') ELSE '' END");
    if topn <= 0 {
        // pas de cap top-N : comportement seuil seul (compat). last_ts = MAX(ts) du bucket (v64, Fraîcheur réelle).
        // env_id (#2d/v67) : dimension d'agrégation supplémentaire (basse cardinalité prod/staging/sites) ->
        // les counts restent EXACTS par environnement. COALESCE défensif (event.env_id est NOT NULL DEFAULT 'prod').
        return format!(
            "SELECT (ts/3600)*3600, COALESCE(source,''), COALESCE(severity,0), COALESCE(json_extract(fields,'$.action'),''), \
             {srcip_sev}, COALESCE(host,''), COUNT(*), MAX(ts), COALESCE(env_id,'prod') \
             FROM event WHERE {cond} GROUP BY ts/3600, source, severity, json_extract(fields,'$.action'), {srcip_sev}, host, COALESCE(env_id,'prod')"
        );
    }
    // CTE base : agrégat au grain rollup (env_id inclus, #2d) avec src_ip déjà borné par le seuil de sévérité.
    // CTE ipsum : total par (bucket, env_id, src_ip) -> mesure la « grosseur » de l'IP dans le bucket/env.
    // CTE ranked : rang de l'IP dans son (bucket, env_id) — le cap top-N est PAR environnement (pas de
    //   compétition inter-env pour les slots) ; les src_ip='' lump existant ne sont jamais cappés -> rang 0.
    // final : on garde src_ip si rang<=topn (ou ''), sinon lump '' ; ré-agrégation (SUM) pour fusionner.
    format!(
        "WITH base AS ( \
           SELECT (ts/3600)*3600 AS bucket, COALESCE(source,'') AS source, COALESCE(severity,0) AS severity, \
                  COALESCE(json_extract(fields,'$.action'),'') AS action, {srcip_sev} AS src_ip, \
                  COALESCE(host,'') AS host, COALESCE(env_id,'prod') AS env_id, COUNT(*) AS n, MAX(ts) AS last_ts \
           FROM event WHERE {cond} \
           GROUP BY 1,2,3,4,5,6,7 \
         ), \
         ipsum AS ( \
           SELECT bucket, env_id, src_ip, SUM(n) AS ipn FROM base WHERE src_ip<>'' GROUP BY bucket, env_id, src_ip \
         ), \
         ranked AS ( \
           SELECT bucket, env_id, src_ip, ROW_NUMBER() OVER (PARTITION BY bucket, env_id ORDER BY ipn DESC, src_ip) AS rnk \
           FROM ipsum \
         ) \
         SELECT b.bucket, b.source, b.severity, b.action, \
                CASE WHEN b.src_ip='' THEN '' \
                     WHEN COALESCE(r.rnk, 999999) <= {topn} THEN b.src_ip ELSE '' END AS sip, \
                b.host, SUM(b.n), MAX(b.last_ts), b.env_id \
         FROM base b LEFT JOIN ranked r ON r.bucket=b.bucket AND r.env_id=b.env_id AND r.src_ip=b.src_ip \
         GROUP BY b.bucket, b.source, b.severity, b.action, sip, b.host, b.env_id"
    )
}

// =====================================================================================
// PHASE 3a — PRÉ-AGRÉGATION PAR DIMENSION (event_dim_rollup) : rend les panneaux GROUP-BY par-source
// (`search source=X | stats count by <dim>`) instantanés (<100 ms, RAM ~nulle) en les réécrivant en
// is_soql=0 sur une table pré-agrégée (bucket,source,dim,val,n), au lieu de scanner+déchiffrer ~1,2 M
// lignes de `event`. Peuplée incrémentalement par rollup_events (même mécanique que event_rollup),
// bornée par un cap top-N/(bucket,source,dim) (ROW_NUMBER) -> cardinalité maîtrisée (path/vhost).
// =====================================================================================

/// DIMENSIONS CHAUDES pré-agrégées par source — DÉFAUTS COMPILÉS (built-in). FUSIONNÉS au runtime avec
/// l'env `PLUME_ROLLUP_DIMS` (cf. `dim_rollup_specs`) : un opérateur AJOUTE une dim/source via le
/// déploiement, SANS recompiler. UNIQUEMENT les couples (source, dim) des panneaux semés « PURS »
/// `search source=X | stats count by <dim> [| head K]` SANS filtre secondaire (sinon le rollup, qui
/// n'agrège que par (source,dim,val), donnerait des comptes FAUX). Les panneaux à filtre additionnel
/// (egress dir/scope, vault vtype, etc.) restent en is_soql=1. mail/verdict est inclus : son filtre
/// `verdict=*` ≡ `verdict IS NOT NULL` ≡ `val<>''` côté rollup (cf. dim_panel_sql non_empty=true).
/// ⚠️ N'INSCRIRE QUE des dims BASSE-CARDINALITÉ (level, status, verb, ns...). JAMAIS `msg`/`trace_id`/
/// `time` : le rollup matérialiserait une explosion de valeurs (cap top-N/bucket les tronquerait de
/// toute façon -> chiffres faux).
const DIM_ROLLUP_SPECS: &[(&str, &[&str])] = &[
    ("web", &["status", "vhost", "path"]),
    ("mail", &["verdict"]),
    ("dataaccess", &["user", "action", "path"]),
    ("dataacl", &["owner", "group"]),
    ("kube-rbac", &["role", "subject"]),
    // v49 — GROSSES sources qui full-scannaient le `stats by` (déchiffrement SQLCipher de champs JSON non
    // indexés). UNIQUEMENT des dims présentes dans `fields` (vérifié sur l'instance) -> jamais un rollup de
    // valeurs vides. src_ip ABSENT À DESSEIN : colonne réelle servie EXACTE+rapide par idx_event_src_srcip
    // (COVERING) -> le router via le rollup approximatif serait une RÉGRESSION d'exactitude sans gain. Les
    // dims haute-cardinalité (auditd exe/comm, ufw dport ~16k ports) sont cappées top-N/bucket
    // (PLUME_ROLLUP_DIM_TOPN=50) -> rollup-route les marque served_from:rollup + approx + truncated (OK).
    ("auditd", &["exe", "comm", "auid", "key", "action"]),
    ("sshd-session", &["user", "action"]), // src_ip = NULL dans fields (promu colonne via rhost) -> exclu
    ("kube-audit", &["verb", "user", "resource", "action", "ns"]), // backwards corrigé (59k sans rollup vs kube-rbac 111)
    ("k8s-log", &["ns", "pod", "level"]), // PHASE 2 : `level` extrait (Phase 1) -> `stats count by level` servi en ms (Route B). BASSE cardinalité (info/warn/error/... <=50 = exact sous le cap top-N).
    ("vault-audit", &["path", "operation", "user"]),
    ("ufw", &["dport", "proto"]),
    ("cloudflare", &["cf_source", "action", "vhost"]), // src_ip exclu (colonne réelle, covering index)
    ("fail2ban", &["jail"]),
    ("crowdsec", &["scenario"]),
    ("sudo", &["action"]), // target = NULL dans fields tant que parser_reparse v48 n'a pas backfillé -> exclu
];

/// Plafond de dims pré-agrégées PAR source (défauts + env confondus) : borne la cardinalité du rollup
/// (chaque dim = jusqu'à top-N lignes/bucket horaire). BASSE cardinalité uniquement (cf. avertissement
/// DIM_ROLLUP_SPECS) — un opérateur ne peut pas faire exploser la table via PLUME_ROLLUP_DIMS.
pub(crate) const DIM_ROLLUP_MAX_DIMS_PER_SOURCE: usize = 6;

/// Fusionne une spec env `PLUME_ROLLUP_DIMS` (format `"src1:d1,d2;src2:d3"`) DANS les défauts `specs`.
/// Sémantique ADDITIVE (union, dédupliquée) : l'env AJOUTE des dims à une source connue et CRÉE des
/// sources nouvelles ; il ne RETIRE jamais un défaut (les panneaux semés en dépendent). Idents validés
/// (source via rollup_source_ok, dim via soql_ident_ok) -> toute entrée malformée est IGNORÉE
/// silencieusement (jamais de crash, jamais d'injection : ces noms deviennent des littéraux SQL). Cap
/// DIM_ROLLUP_MAX_DIMS_PER_SOURCE dims/source. PUR (pas d'I/O) -> testable.
pub(crate) fn merge_rollup_dims(specs: &mut Vec<(String, Vec<String>)>, raw: &str) {
    for group in raw.split(';') {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }
        let Some((src, dims_str)) = group.split_once(':') else {
            continue; // pas de `source:dims` -> entrée ignorée
        };
        let src = src.trim();
        if !rollup_source_ok(src) {
            continue; // source au charset borné (cf. rollup_source_ok) -> jamais d'injection
        }
        let new_dims: Vec<&str> = dims_str
            .split(',')
            .map(|d| d.trim())
            .filter(|d| soql_ident_ok(d))
            .collect();
        if new_dims.is_empty() {
            continue;
        }
        let entry = match specs.iter_mut().find(|(s, _)| s == src) {
            Some(e) => e,
            None => {
                specs.push((src.to_string(), Vec::new()));
                specs.last_mut().unwrap()
            }
        };
        for d in new_dims {
            if entry.1.len() >= DIM_ROLLUP_MAX_DIMS_PER_SOURCE {
                break; // cap par source -> cardinalité bornée même si l'env en demande plus
            }
            if !entry.1.iter().any(|x| x == d) {
                entry.1.push(d.to_string()); // union (dédup)
            }
        }
    }
}

/// Spécification EFFECTIVE des dims pré-agrégées par source = défauts compilés (DIM_ROLLUP_SPECS)
/// FUSIONNÉS avec l'env `PLUME_ROLLUP_DIMS` (cf. merge_rollup_dims). Calculée UNE fois (OnceLock) :
/// coût nul sur le chemin chaud (try_rollup_route, appelé par requête) et état STABLE partagé avec le
/// job de matérialisation (rollup_events). Un changement de `PLUME_ROLLUP_DIMS` exige un redémarrage,
/// comme les autres toggles mis en cache au boot (PLUME_FTS_FIELDS, etc.). PAS de recompilation requise.
pub(crate) fn dim_rollup_specs() -> &'static [(String, Vec<String>)] {
    static SPECS: std::sync::OnceLock<Vec<(String, Vec<String>)>> = std::sync::OnceLock::new();
    SPECS.get_or_init(|| {
        let mut specs: Vec<(String, Vec<String>)> = DIM_ROLLUP_SPECS
            .iter()
            .map(|(s, dims)| (s.to_string(), dims.iter().map(|d| d.to_string()).collect()))
            .collect();
        let raw = cfg(&load_config(), "PLUME_ROLLUP_DIMS", "");
        merge_rollup_dims(&mut specs, &raw);
        specs
    })
}

/// SQL is_soql=0 d'un panneau lisant le pré-agrégé par dimension. IDENTIQUE entre les seeds (install
/// neuve) et la migration v44 (UPDATE de l'existant) -> source unique de vérité, pas de dérive.
/// `source`/`dim` sont des LITTÉRAUX internes (cf. DIM_ROLLUP_SPECS) — jamais d'entrée utilisateur.
/// __FROM__ remplacé par la fenêtre (comme event_rollup). `non_empty` (mail/verdict=*) exclut la val
/// vide (= champ absent). `limit<=0` -> pas de LIMIT (la cardinalité est déjà bornée par le cap top-N).
pub(crate) fn dim_panel_sql(source: &str, dim: &str, limit: i64, non_empty: bool) -> String {
    let ne = if non_empty { " AND val<>''" } else { "" };
    let lim = if limit > 0 { format!(" LIMIT {limit}") } else { String::new() };
    format!(
        "SELECT val AS \"{dim}\", SUM(n) AS count FROM event_dim_rollup \
         WHERE source='{source}' AND dim='{dim}' AND bucket>=__FROM__{ne} \
         GROUP BY val ORDER BY count DESC{lim}"
    )
}

/// Construit l'INSERT...SELECT du rollup par dimension pour UN couple (source, dim), borné par `cond`
/// (filtre sur `ts` formaté en i64 -> pas d'injection ; source/dim = littéraux internes). Cap TOP-N par
/// bucket (ROW_NUMBER OVER PARTITION BY bucket) : pour une dim haute-cardinalité (path/vhost), seules les
/// `topn` valeurs les plus fréquentes par bucket horaire sont gardées, le reste est ABANDONNÉ (tolérance
/// documentée : une val toujours hors top-N par bucket n'apparaît pas, même si son cumul serait élevé).
/// val = COALESCE(json_extract(fields,'$.<dim>'),'') (convention event_rollup ; '' = champ absent).
pub(crate) fn dim_rollup_insert_sql(source: &str, dim: &str, cond: &str, topn: i64) -> String {
    dim_rollup_insert_sql_into("event_dim_rollup", source, dim, cond, topn)
}

/// Variante de `dim_rollup_insert_sql` avec table cible paramétrable (`table` = LITTÉRAL interne, jamais une
/// entrée utilisateur). RÉUTILISÉE par le SIDECAR ROLLUP COLD (#28 Phase A, `seal_cold_rollup`) qui matérialise
/// EXACTEMENT le même agrégat par-dimension dans `cold_dim_rollup` à partir des lignes d'un jour scellé -> le
/// rollup cold roule les MÊMES dims (spec `dim_rollup_specs`), de façon générique, sans code par-source.
pub(crate) fn dim_rollup_insert_sql_into(table: &str, source: &str, dim: &str, cond: &str, topn: i64) -> String {
    format!(
        "INSERT OR REPLACE INTO {table}(bucket,source,dim,val,n,env_id) {}",
        dim_rollup_select_sql(source, dim, cond, topn)
    )
}

/// PRÉFIXE RÉSERVÉ de la dimension qui porte LE RESTE — les événements que le plafond top-N a écartés.
///
/// POURQUOI IL NE PEUT PAS ENTRER EN COLLISION. Toute dimension qui atteint cette table a d'abord passé
/// `soql_ident_ok` (défauts de `DIM_ROLLUP_SPECS` d'un côté, `merge_rollup_dims` pour la spec
/// d'environnement de l'autre), et ce validateur n'accepte que `[A-Za-z0-9_]`. `!` en est exclu : aucune
/// dimension configurable ne peut donc produire `!<dim>`. La garde n'est pas une convention à respecter,
/// elle est portée par le validateur qui filtre DÉJÀ toute dimension — c'est le test
/// `le_prefixe_du_reste_ne_peut_pas_etre_une_dimension` qui l'épingle.
pub(crate) const RESTE_DIM_PREFIX: &str = "!";

/// Nom de dimension sous lequel le RESTE de `dim` est stocké — MÊME table, MÊME index, MÊME cycle de vie
/// (purge par bucket, delete-avant-ré-agrégation, rétention) que les lignes gardées. Un lecteur qui filtre
/// `dim='<dim>'` (route, panneaux) ne le voit JAMAIS : le reste ne pollue aucun résultat.
pub(crate) fn reste_dim(dim: &str) -> String {
    format!("{RESTE_DIM_PREFIX}{dim}")
}

/// CORPS SELECT (sans préfixe INSERT) du rollup par-dimension : les 6 colonnes ordonnées
/// (bucket,source,dim,val,n,env_id). Délégué par `dim_rollup_insert_sql_into` (INSERT du hot ET du sidecar
/// cold) et réutilisé VERBATIM par le scan lock-free du sidecar cold (#28 Phase A) qui MATÉRIALISE ces lignes
/// EN MÉMOIRE (résultat top-N-borné -> RAM bornée) hors du verrou writer. Même SQL -> même résultat -> parité.
///
/// LA LIGNE DE RESTE, ET POURQUOI ELLE EST ÉCRITE ICI ET NULLE PART AILLEURS. Le plafond top-N ABANDONNE
/// la queue des valeurs de chaque (bucket, env). Un drapeau `truncated` disait ensuite « des valeurs
/// manquent » — sans jamais dire COMBIEN, alors que c'est ici, et seulement ici, que le nombre existe :
/// l'agrégat complet (`base`) est sous la main juste avant d'être jeté. On l'écrit donc, dans la MÊME
/// instruction (donc le MÊME balayage : `ranked` est référencé deux fois, SQLite le matérialise), sous la
/// dimension réservée `reste_dim(dim)`.
///
/// ELLE EST ÉCRITE MÊME QUAND ELLE VAUT ZÉRO, et c'est le point. Si le reste n'était écrit que lorsqu'il
/// est non nul, son ABSENCE serait indiscernable de « ce bucket a été agrégé par une version qui ne le
/// notait pas » — c'est-à-dire, encore une fois, un zéro qui n'en est pas un. Une ligne à `n=0` dit « rien
/// n'a été écarté ici » ; PAS de ligne dit « on n'en sait rien », et la route l'AVOUE au lieu d'afficher 0.
///
/// CE QU'ELLE NE PORTE PAS. Le nombre de VALEURS distinctes absentes de la réponse n'est pas additif entre
/// buckets (une valeur écartée d'un bucket peut être gardée dans un autre) : l'établir demanderait
/// exactement le balayage que le plafond évite. Le compte d'ÉVÉNEMENTS, lui, est additif et exact.
pub(crate) fn dim_rollup_select_sql(source: &str, dim: &str, cond: &str, topn: i64) -> String {
    let valexpr = format!("COALESCE(json_extract(fields,'$.{dim}'),'')");
    let reste = reste_dim(dim);
    // env_id (#2d/v67) : dimension d'agrégation supplémentaire (COALESCE défensif ; event.env_id NOT NULL).
    let base = format!(
        "base AS ( \
           SELECT (ts/3600)*3600 AS bucket, {valexpr} AS val, COALESCE(env_id,'prod') AS env_id, COUNT(*) AS n \
           FROM event WHERE source='{source}' AND ({cond}) \
           GROUP BY 1, 2, 3 \
         )"
    );
    if topn <= 0 {
        // Pas de cap top-N : rien n'est jamais écarté. La ligne de reste est écrite QUAND MÊME, à 0 —
        // sinon « pas de cap » et « pas de trace » se ressembleraient, et la route ne pourrait pas
        // distinguer un reste nul d'un reste inconnu.
        return format!(
            "WITH {base} \
             SELECT bucket, '{source}', '{dim}', val, n, env_id FROM base \
             UNION ALL \
             SELECT bucket, '{source}', '{reste}', '', 0, env_id FROM base GROUP BY bucket, env_id"
        );
    }
    // Cap top-N/(bucket, env_id, source, dim) : le rang est calculé PAR environnement (#2d) -> pas de
    // compétition inter-env pour les slots ; le grain (source,dim) est fixe dans cet INSERT.
    format!(
        "WITH {base}, ranked AS ( \
           SELECT bucket, val, env_id, n, ROW_NUMBER() OVER (PARTITION BY bucket, env_id ORDER BY n DESC, val) AS rnk FROM base \
         ) \
         SELECT bucket, '{source}', '{dim}', val, n, env_id FROM ranked WHERE rnk <= {topn} \
         UNION ALL \
         SELECT bucket, '{source}', '{reste}', '', SUM(CASE WHEN rnk > {topn} THEN n ELSE 0 END), env_id \
         FROM ranked GROUP BY bucket, env_id"
    )
}

// =====================================================================================
// #28 PHASE A — SIDECAR ROLLUP COLD : pré-agrégation par-jour, calculée AU SCELLEMENT (aging hot->cold), stockée
// DANS LA BASE SQLCipher DU TENANT (`cold_rollup` = miroir d'`event_rollup` ; `cold_dim_rollup` = miroir
// d'`event_dim_rollup`). But : répondre à `stats count by <dim>` sur des fenêtres COLD gigantesques (jusqu'à ~1
// milliard de lignes cold) en QUELQUES MS, SANS ouvrir un seul fichier Parquet — la réécriture rollup-route
// (rollup_route::try_cold_rollup_route) unionne event_rollup(bucket>=B) ∪ cold_rollup(bucket<B) EN BASE.
//
// GATE : TOUT est `#[cfg(feature="cold_tier")]` + les tables sont créées PARESSEUSEMENT (uniquement au 1er
// scellement, cold ON) -> mode 0 (cold off) = base tenant BYTE-IDENTIQUE (aucune table en trop).
//
// GÉNÉRICITÉ : `cold_rollup` réutilise `rollup_insert_sql_into` VERBATIM (GROUP BY source/severity/action/
// src_ip/host/env_id) -> une source NOUVELLE/inconnue s'y agrège SANS AUCUN code par-source. `cold_dim_rollup`
// réutilise `dim_rollup_insert_sql_into` sur la spec `dim_rollup_specs` (mêmes dims que le hot).
//
// CRASH-SAFETY / IDEMPOTENCE : `seal_cold_rollup` est appelée par le writer DANS LA MÊME TRANSACTION que le
// COMMIT `last_file=1` de fin de PHASE 1 (writer::write_day_files), depuis le hot INTACT (PHASE 2/delete pas
// encore lancée). delete-jour-puis-insert borné à l'ensemble agé EXACT (env+jour+id<=max_id+NONPURGE) -> un
// re-run (resume Phase 1) recalcule le MÊME agrégat depuis le MÊME hot intact = idempotent, jamais de double.
// Une fois `last_file=1` durable, la Phase 1 (et donc ce rollup) ne re-tourne PLUS (age_one_day short-circuit).

/// Schéma de `cold_rollup` (miroir EXACT d'`event_rollup` moderne) + `cold_dim_rollup` (miroir d'`event_dim_rollup`
/// AVEC env_id, comme l'insert). Créées PARESSEUSEMENT (idempotent) -> mode 0 byte-identique. `bucket` indexé
/// pour la coupe frontière `WHERE bucket </>= B`.
#[cfg(feature = "cold_tier")]
pub(crate) fn ensure_cold_rollup_tables(conn: &Connection) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cold_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
           severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
           host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
           env_id TEXT NOT NULL DEFAULT 'prod', \
           PRIMARY KEY(bucket,source,severity,action,src_ip,host,env_id)); \
         CREATE INDEX IF NOT EXISTS idx_cold_rollup ON cold_rollup(bucket); \
         CREATE TABLE IF NOT EXISTS cold_dim_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
           dim TEXT NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
           env_id TEXT NOT NULL DEFAULT 'prod', \
           PRIMARY KEY(bucket,source,dim,val,env_id)); \
         CREATE INDEX IF NOT EXISTS idx_cold_dim_rollup_q ON cold_dim_rollup(source, dim, bucket);",
    );
}

/// #28 Phase A — PRÉDICAT de l'ensemble agé EXACT d'un jour scellé `(env_id, day)` : env + jour + `id<=max_id`
/// (ensemble FROZEN — l'ingest concurrent porte `id>max_id`, exclu) + NONPURGE. C'est LA MÊME tranche que
/// `count_and_max_id`/`read_cold_page`/`delete_file_rows` columnarisent/suppriment -> parité stricte. SOURCE
/// UNIQUE partagée par le scan lock-free (`compute_cold_rollup`) ET le repli sous verrou (`seal_cold_rollup`)
/// -> aucune divergence de périmètre entre les deux chemins. Bornes = i64 formatés + env_id échappé (charset
/// déjà validé `env_id_ok` en amont) -> pas d'injection.
#[cfg(feature = "cold_tier")]
fn cold_rollup_cond(env_id: &str, day: i64, max_id: i64) -> String {
    let day_start = day * 3600 * 24;
    let day_end = day_start + 3600 * 24;
    let env_esc = guatx_core::soql::soql_esc(env_id);
    format!("ts>={day_start} AND ts<{day_end} AND env_id='{env_esc}' AND id<={max_id} AND {RETENTION_NONPURGE}")
}

/// #28 Phase A — réglages de cardinalité du sidecar cold (identiques au hot). Lus HORS chemin chaud.
#[cfg(feature = "cold_tier")]
fn cold_rollup_caps() -> (i64, i64, i64) {
    let conf = load_config();
    (
        cfg(&conf, "PLUME_ROLLUP_SRCIP_MIN_SEV", "3").parse().unwrap_or(3),
        rollup_srcip_topn(&conf),
        cfg(&conf, "PLUME_ROLLUP_DIM_TOPN", "50").parse().unwrap_or(50).max(0),
    )
}

/// #28 Phase A — LIGNES de rollup cold MATÉRIALISÉES en mémoire par le scan lock-free (`compute_cold_rollup`),
/// prêtes à un INSERT COURT sous verrou (`apply_cold_rollup`). RAM BORNÉE : ce ne sont PAS les lignes brutes du
/// jour mais le RÉSULTAT AGRÉGÉ (GROUP BY + cap top-N par bucket, comme le hot) -> `events` est borné par
/// (24 buckets × source × severity × action × top-N src_ip × host × env) et `dims` par (couples (source,dim)
/// de `dim_rollup_specs` × 24 buckets × top-N × env) — la MÊME cardinalité que ce qui était déjà écrit dans
/// `cold_rollup`/`cold_dim_rollup`, jamais le volume brut du jour.
#[cfg(feature = "cold_tier")]
pub(crate) struct MaterializedColdRollup {
    /// (bucket, source, severity, action, src_ip, host, n, last_ts, env_id) — grain `cold_rollup`.
    events: Vec<(i64, String, i64, String, String, String, i64, i64, String)>,
    /// (bucket, source, dim, val, n, env_id) — grain `cold_dim_rollup`.
    dims: Vec<(i64, String, String, String, i64, String)>,
}

/// #28 Phase A — SCAN LOCK-FREE (hors verrou writer) : MATÉRIALISE en mémoire les lignes de rollup cold d'un
/// jour scellé `(env_id, day)` depuis le hot INTACT, borné à l'ensemble agé EXACT (`cold_rollup_cond`). Ouvre
/// une connexion READ-ONLY SÉPARÉE sur le MÊME fichier base (via `Connection::path()` -> robuste quel que soit
/// le db_path logique) -> l'ingest (verrou writer) CONTINUE sous WAL pendant le scan lourd. AUCUN authorizer /
/// masquage n'est installé (le hot rollup lit AUSSI la donnée BRUTE sur la connexion writer) -> parité stricte
/// des VALEURS. Le résultat est top-N-borné -> RAM bornée. Toute erreur (clé/chemin/scan) -> `Err` : l'appelant
/// REPLIE sur `seal_cold_rollup` (calcul sous verrou) -> le scellement a TOUJOURS un chemin correct, jamais un
/// seal cassé (cf. `writer::write_day_files`). L'ensemble `id<=max_id` étant FROZEN, ce scan est STABLE malgré
/// l'ingest concurrent (`id>max_id`, exclu) -> pas besoin du verrou d'écriture pour la cohérence.
#[cfg(feature = "cold_tier")]
pub(crate) fn compute_cold_rollup(
    db: &Arc<Mutex<Connection>>,
    db_path: &str,
    env_id: &str,
    day: i64,
    max_id: i64,
) -> Result<MaterializedColdRollup, String> {
    // Chemin PHYSIQUE réel du fichier base (ground-truth de la connexion writer) : robuste même quand le db_path
    // LOGIQUE est vide (tenant défaut / tests). Verrou writer pris le temps d'un accesseur -> relâché AVANT le scan.
    let real_path = {
        let conn = db.lock();
        conn.path().map(|s| s.to_string())
    };
    let real_path = match real_path {
        Some(p) if !p.trim().is_empty() && p != ":memory:" => p,
        _ => return Err("chemin base indisponible (in-memory / inconnu) -> repli sous verrou".into()),
    };
    // Connexion READ-ONLY dédiée : PAS le mutex writer -> l'ingest continue (WAL). Clé DU TENANT via
    // `apply_key_for(db_path)` (registre -> tenant, sinon db_key() global) : identique à la manière dont la
    // connexion writer lit la donnée. AUCUN wiring sécu (authorizer/fmask) -> valeurs BRUTES = parité hot.
    let rconn = Connection::open_with_flags(&real_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    apply_key_for(&rconn, db_path);
    let _ = rconn.execute_batch(&format!("PRAGMA query_only=ON; PRAGMA busy_timeout=3000; {}", sqlite_plafond::pragmas_memoire()));

    let cond = cold_rollup_cond(env_id, day, max_id);
    let (min_sev, topn, dim_topn) = cold_rollup_caps();

    // event-grain : SELECT-en-mémoire (même corps que l'INSERT hot -> même résultat). 9 colonnes ordonnées.
    let mut events = Vec::new();
    {
        let mut st = rconn.prepare(&rollup_select_sql(&cond, min_sev, topn)).map_err(|e| e.to_string())?;
        let it = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, String>(8)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in it {
            events.push(row.map_err(|e| e.to_string())?);
        }
    }
    // dim-grain : MÊME spec de dims que le hot (générique, aucun code par-source). 6 colonnes ordonnées.
    let mut dims = Vec::new();
    for (source, dim_list) in dim_rollup_specs().iter() {
        for dim in dim_list.iter() {
            let mut st = rconn
                .prepare(&dim_rollup_select_sql(source, dim, &cond, dim_topn))
                .map_err(|e| e.to_string())?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in it {
                dims.push(row.map_err(|e| e.to_string())?);
            }
        }
    }
    Ok(MaterializedColdRollup { events, dims })
}

/// #28 Phase A — SEAL COURT (sous verrou writer, DANS la transaction du COMMIT `last_file=1`) : delete-jour puis
/// INSERT des lignes DÉJÀ matérialisées (hors verrou) par `compute_cold_rollup`. Le verrou d'écriture n'est tenu
/// QUE pour ce bulk-insert borné, PAS pour le scan. `{delete-jour + insert}` reste ATOMIQUE dans la tx appelante
/// -> re-seal (resume Phase 1) idempotent : delete-jour-puis-insert (mêmes buckets, cet env) ne double ni n'efface.
#[cfg(feature = "cold_tier")]
pub(crate) fn apply_cold_rollup(conn: &Connection, env_id: &str, day: i64, mat: &MaterializedColdRollup) -> Result<(), String> {
    ensure_cold_rollup_tables(conn);
    let day_start = day * 3600 * 24;
    let day_end = day_start + 3600 * 24;
    // event-grain : delete-jour (cet env) puis INSERT des lignes matérialisées.
    conn.execute("DELETE FROM cold_rollup WHERE bucket>=?1 AND bucket<?2 AND env_id=?3", params![day_start, day_end, env_id])
        .map_err(|e| e.to_string())?;
    {
        let mut ins = conn
            .prepare("INSERT OR REPLACE INTO cold_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")
            .map_err(|e| e.to_string())?;
        for (bucket, source, severity, action, src_ip, host, n, last_ts, env) in &mat.events {
            ins.execute(params![bucket, source, severity, action, src_ip, host, n, last_ts, env]).map_err(|e| e.to_string())?;
        }
    }
    // dim-grain : delete-jour (cet env) puis INSERT des lignes matérialisées.
    conn.execute("DELETE FROM cold_dim_rollup WHERE bucket>=?1 AND bucket<?2 AND env_id=?3", params![day_start, day_end, env_id])
        .map_err(|e| e.to_string())?;
    {
        let mut ins = conn
            .prepare("INSERT OR REPLACE INTO cold_dim_rollup(bucket,source,dim,val,n,env_id) VALUES(?1,?2,?3,?4,?5,?6)")
            .map_err(|e| e.to_string())?;
        for (bucket, source, dim, val, n, env) in &mat.dims {
            ins.execute(params![bucket, source, dim, val, n, env]).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// #28 Phase A — CALCULE le sidecar rollup d'UN jour scellé `(env_id, day)` depuis le hot INTACT, borné à
/// l'ensemble columnarisé EXACT (env + jour + `id<=max_id` + NONPURGE) = LA MÊME tranche que
/// `count_and_max_id`/`read_cold_page`/`delete_file_rows`. -> `cold_rollup`/`cold_dim_rollup` comptent
/// EXACTEMENT les lignes qui partent en Parquet = ce que le chemin brut hot∪cold retourne pour `ts<B` (parité,
/// pas de sur/sous-comptage à la frontière). delete-jour-puis-insert (mêmes buckets, cet env) -> idempotent au
/// re-seal. CHEMIN DE REPLI (sous verrou writer, DANS la tx `last_file=1`) : le chemin NOMINAL matérialise
/// d'abord hors verrou (`compute_cold_rollup`) puis n'INSÈRE que le résultat court (`apply_cold_rollup`) ; ce
/// `seal_cold_rollup` est appelé UNIQUEMENT quand le scan lock-free échoue (clé/chemin) -> le scellement garde
/// TOUJOURS un chemin correct (jamais un seal cassé). Même SQL (`*_insert_sql_into` délègue au même corps SELECT
/// que le scan) -> résultat IDENTIQUE au chemin nominal.
#[cfg(feature = "cold_tier")]
pub(crate) fn seal_cold_rollup(conn: &Connection, env_id: &str, day: i64, max_id: i64) -> Result<(), String> {
    ensure_cold_rollup_tables(conn);
    let day_start = day * 3600 * 24;
    let day_end = day_start + 3600 * 24;
    let cond = cold_rollup_cond(env_id, day, max_id);
    let (min_sev, topn, dim_topn) = cold_rollup_caps();
    // event-grain (Route A : `stats count by source`). delete-jour (cet env) puis ré-agrège -> re-seal idempotent.
    conn.execute(
        "DELETE FROM cold_rollup WHERE bucket>=?1 AND bucket<?2 AND env_id=?3",
        params![day_start, day_end, env_id],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(&rollup_insert_sql_into("cold_rollup", &cond, min_sev, topn), [])
        .map_err(|e| e.to_string())?;
    // dim-grain (Route B : `search source=X | stats count by <dim>`), MÊME spec de dims que le hot (générique).
    conn.execute(
        "DELETE FROM cold_dim_rollup WHERE bucket>=?1 AND bucket<?2 AND env_id=?3",
        params![day_start, day_end, env_id],
    )
    .map_err(|e| e.to_string())?;
    for (source, dims) in dim_rollup_specs().iter() {
        for dim in dims.iter() {
            conn.execute(&dim_rollup_insert_sql_into("cold_dim_rollup", source, dim, &cond, dim_topn), [])
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Rollup d'events (tick ~5 min) : agrège les counts (source,severity,action,src_ip,host) dans
/// `event_rollup`. Ré-agrège TOUJOURS l'heure en cours + la précédente (latence ~tick + rattrape les
/// events tardifs), rattrape les heures définitives via le watermark `event_rollup_wm`, et RÉPARE les
/// bandes où une ligne est arrivée SOUS le watermark après son passage (cf. `rollup_coverage` — ce
/// n'était pas un retard mais un trou définitif, mesuré ×6,6 le 31/07). Publie enfin la COUVERTURE
/// (`event_rollup_cov_id`) que la route de rollups exige pour servir un corps comme EXACT.
/// Idempotent (OR REPLACE). NE touche PAS le compilateur soql partagé. Bornes = i64 (pas d'injection).
/// src_ip DOUBLEMENT BORNÉ : seuil severity>=PLUME_ROLLUP_SRCIP_MIN_SEV (défaut 3) + cap top-N
/// par bucket (PLUME_ROLLUP_SRCIP_TOPN, défaut 50) -> cardinalité bornée même sous attaque, top conservé.
pub(crate) fn rollup_events(conn: &Connection) {
    let n = now();
    let cur = (n / 3600) * 3600;
    let recent = (cur - 3600).max(0);   // fenêtre chaude = heure courante + précédente
    let meta_i64 = |k: &str| -> Option<i64> {
        conn.query_row("SELECT value FROM meta WHERE key=?1", params![k], |r| r.get::<_, String>(0))
            .ok().and_then(|s| s.parse().ok())
    };
    let wm: i64 = meta_i64(META_ROLLUP_WM).unwrap_or(0);
    let (min_sev, topn) = {
        let conf = load_config();
        (cfg(&conf, "PLUME_ROLLUP_SRCIP_MIN_SEV", "3").parse().unwrap_or(3), rollup_srcip_topn(&conf))
    };
    // ---- COUVERTURE (cf. rollup_coverage) : ce que le watermark VAUT réellement. ----
    // Un watermark dit « le job est passé par là ». La ROUTE, elle, a besoin de « le rollup est une image
    // d'`event` là ». Les deux divergent dès qu'une ligne est écrite SOUS le watermark après son passage
    // (import d'historique, agent qui vide un tampon hors-ligne, relais en retard). L'ancien tick avançait
    // alors le watermark PAR-DESSUS ces lignes et n'y revenait JAMAIS : trou DÉFINITIF, mesuré ×6,6.
    // Les lignes arrivées depuis la couverture sont EXACTEMENT `id > cov` (`event.id` = rowid, monotone à
    // l'insertion). La plus ancienne d'entre elles qui tombe sous `wm` RÉTRACTE le plancher d'agrégation
    // jusqu'à son bucket -> elle finit agrégée. `NOT INDEXED` force la porte rowid (sinon le planificateur
    // choisit `idx_event_ts` et rebalaie tout l'historique sous `wm`).
    let cov: Option<i64> = meta_i64(META_ROLLUP_COV_ID);
    let dirty_lo: Option<i64> = match cov {
        // COUVERTURE ABSENTE = base d'avant ce correctif, tick jamais passé, ou publication interrompue :
        // on ne peut rien affirmer sous `wm` -> on RECONSTRUIT, une fois. C'est ce qui répare une base dont
        // le rollup a été laissé en arrière (le cas mesuré).
        None => Some(0),
        Some(c) => conn
            .query_row("SELECT MIN(ts) FROM event NOT INDEXED WHERE id>?1 AND ts<?2", params![c, wm], |r| r.get::<_, Option<i64>>(0))
            .ok().flatten(),
    };
    // Le rollup ne peut témoigner que de ce qu'`event` porte ENCORE : on ne redescend JAMAIS sous le plus
    // vieux `ts` d'`event`. Les buckets plus anciens sont l'histoire que SEUL le rollup garde (lignes agées
    // en Parquet, ou purge non-symétrique de la rétention) — les recomposer depuis `event` les effacerait.
    let event_floor = conn.query_row("SELECT MIN(ts) FROM event", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten();
    let agg_from = match (dirty_lo, event_floor) {
        (Some(d), Some(f)) => ((d / 3600) * 3600).min(wm).max((f / 3600) * 3600),
        (Some(_), None) => recent, // `event` vide : rien à agréger, rien à réparer
        (None, _) => wm,           // rien de sale -> rattrapage nominal `[wm, recent)`
    };
    // BORNE D'IDENTIFIANT prise AVANT d'agréger, et POUSSÉE DANS la condition d'agrégation : le rollup
    // porte alors EXACTEMENT les lignes `id <= new_cov`, donc la couverture publiée plus bas est vraie par
    // CONSTRUCTION et non par espoir (une ligne insérée PENDANT l'agrégation ne peut plus y entrer à
    // moitié — elle sera rattrapée par le fragment retardataire de la route, puis par le tick suivant).
    let new_cov: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).unwrap_or(0);
    let mut aggregated = true;
    if recent > agg_from {
        // RÉTRACTER D'ABORD, RÉPARER ENSUITE : tant que la ré-agrégation n'a pas fini, la route doit servir
        // cette bande en BRUT (exact, plus lent) et non depuis un rollup qu'on SAIT incomplet. On efface donc
        // la couverture avant de toucher quoi que ce soit ; elle sera republiée si et seulement si on finit.
        let _ = conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]);
        // Buckets recomposés ENTIÈREMENT : le cap top-N src_ip peut laisser une ligne orpheline à PK
        // différente -> double comptage. Même purge-avant-agrégation que la fenêtre chaude ci-dessous.
        let _ = conn.execute("DELETE FROM event_rollup WHERE bucket >= ?1 AND bucket < ?2", params![agg_from, recent]);
        aggregated = conn
            .execute(&rollup_insert_sql(&format!("ts >= {agg_from} AND ts < {recent} AND id <= {new_cov}"), min_sev, topn), [])
            .is_ok();
    }
    // NB : le cap top-N peut faire SORTIR une IP du top entre deux ticks ; un simple OR REPLACE
    // laisserait alors une ligne orpheline (PK différente) -> double comptage. On PURGE d'abord les
    // buckets de la fenêtre chaude avant la ré-agrégation (les buckets définitifs <recent ne sont écrits
    // qu'une fois et restent stables). Borne = i64 (pas d'injection).
    let _ = conn.execute("DELETE FROM event_rollup WHERE bucket >= ?1", params![recent]);
    let _ = conn.execute(&rollup_insert_sql(&format!("ts >= {recent}"), min_sev, topn), []); // fenêtre chaude
    let _ = conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_WM]);
    let _ = conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_WM, recent.to_string()]);
    // PUBLICATION DE LA COUVERTURE — jamais avant, jamais seule. Si l'agrégation a échoué (base occupée,
    // interruption, disque), on N'ANNONCE RIEN : la clé reste absente, la route décline, le brut sert.
    // FAIL-CLOSED : une couverture qu'on n'a pas prouvée ne s'écrit pas.
    let _ = conn.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]);
    if aggregated {
        let _ = conn.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![META_ROLLUP_COV_ID, new_cov.to_string()]);
    }

    // ---- PHASE 3a : event_dim_rollup (pré-agrégation par DIMENSION) ----
    // Le jumeau d'`event_rollup`, et il portait le MÊME défaut de watermark plus un trou en propre : voir
    // `rollup_coverage` (section « LE JUMEAU »), qui porte la mesure — 19 991 lignes agrégées sur 1 440 007,
    // une bande de 25 h sur 28 jours, et un watermark posé PAR-DESSUS tout le reste. Ici, plus de watermark :
    // le job entretient une BANDE `[from, below)` DONT IL PEUT TÉMOIGNER, et cette bande bouge par trois
    // mouvements BORNÉS par le même `PLUME_ROLLUP_DIM_BACKFILL` (défaut 24 h) — elle MONTE (donc elle ne saute
    // plus une indisponibilité), elle DESCEND jusqu'à `MIN(event.ts)` (donc un démarrage à froid finit par tout
    // couvrir, sans jamais le scan bloquant que le plafond de 24 h évitait), et elle SE RÉTRACTE sur une
    // écriture rétro-datée (que la remontée reconstruit ensuite). Coût par tick : au plus DEUX tranches de
    // `dim_backfill`, soit le même ordre que l'unique tranche d'avant. La fenêtre VOLATILE `[recent, ∞)` reste
    // ré-agrégée intégralement à chaque tick — elle n'est pas dans la bande prouvée, elle est publiée à part.
    let dconf = load_config();
    // ALIGNÉ À L'HEURE, et pas seulement plancher à 3600 : les fronts se déplacent de ce pas, et un pas non
    // aligné poserait une borne de bande AU MILIEU d'un bucket -> le bucket coupé serait agrégé À MOITIÉ tout
    // en étant témoigné entier par la couverture. La contrainte vient du grain de la table, pas d'un goût.
    let dim_backfill: i64 = (cfg(&dconf, "PLUME_ROLLUP_DIM_BACKFILL", "86400").parse().unwrap_or(86400).max(3600) / 3600) * 3600;
    let dim_topn: i64 = cfg(&dconf, "PLUME_ROLLUP_DIM_TOPN", "50").parse().unwrap_or(50).max(0);
    // spec EFFECTIVE = défauts + env PLUME_ROLLUP_DIMS (cf. dim_rollup_specs). Pour CHAQUE (source,dim)
    // — y compris les dims EXTRAITES (Phase 1) comme k8s-log/level — dim_rollup_insert_sql matérialise
    // val = COALESCE(json_extract(fields,'$.<dim>'),'') : aucune distinction core/extrait, toute dim est
    // lue depuis le JSON `fields` (ns/pod/level vivent tous dans `fields`, pas en colonne réelle).
    // Renvoie false si UNE seule des agrégations a échoué -> fail-closed : on ne publiera RIEN.
    let dim_agg = |cond: String| -> bool {
        let mut ok = true;
        for (source, dims) in dim_rollup_specs().iter() {
            for dim in dims.iter() {
                ok &= conn.execute(&dim_rollup_insert_sql(source, dim, &cond, dim_topn), []).is_ok();
            }
        }
        ok
    };
    let dim_cov = DimRollupCoverage::of(conn);
    // Départ : la bande publiée, ou — rien n'étant établi — une bande VIDE posée au sommet (`recent`). Le
    // démarrage à froid est donc le cas dégénéré de la règle générale, pas une branche à part.
    let (mut band_lo, mut band_hi) = match dim_cov.band() {
        Some((from, below, _)) => (from, below),
        None => (recent, recent),
    };
    // RÉTRACTATION. Une ligne écrite SOUS la bande depuis sa publication (`id > at_id`, `event.id` = rowid
    // monotone à l'insertion) n'a pas été agrégée : la bande redescend jusqu'à SON bucket, et tout ce qui est
    // au-dessus cesse d'être témoigné jusqu'à ce que la remontée l'ait reconstruit. `NOT INDEXED` force la
    // porte rowid (sinon le planificateur balaie `idx_event_ts` sur toute la bande).
    if let Some(at) = dim_cov.late_floor_id() {
        if let Ok(Some(t)) = conn.query_row(
            "SELECT MIN(ts) FROM event NOT INDEXED WHERE id>?1 AND ts>=?2 AND ts<?3",
            params![at, band_lo, band_hi],
            |r| r.get::<_, Option<i64>>(0),
        ) {
            band_hi = (t / 3600) * 3600;
        }
    }
    // Les deux fronts, chacun d'au plus `dim_backfill`. Le bas s'arrête à ce qu'`event` porte ENCORE (sous
    // `MIN(event.ts)` il n'y a rien à agréger : les buckets plus vieux sont l'histoire que SEUL le rollup
    // garde, et les recomposer depuis `event` les effacerait — même règle que `event_rollup`).
    let dim_event_floor = conn
        .query_row("SELECT MIN(ts) FROM event", [], |r| r.get::<_, Option<i64>>(0))
        .ok()
        .flatten()
        .map(|t| (t / 3600) * 3600)
        .unwrap_or(recent);
    let down_lo = (band_lo - dim_backfill).max(dim_event_floor).min(band_lo);
    let up_hi = (band_hi + dim_backfill).min(recent).max(band_hi);
    // La BORNE D'IDENTIFIANT est prise AVANT d'agréger et POUSSÉE DANS la condition : la bande publiée porte
    // alors EXACTEMENT les lignes `id <= dim_at_id`, donc la couverture est vraie par CONSTRUCTION.
    let dim_at_id: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM event", [], |r| r.get(0)).unwrap_or(0);
    // RÉTRACTER D'ABORD, RÉPARER ENSUITE : tant que les tranches ne sont pas agrégées, la route doit décliner
    // (le brut sert, exact) plutôt que lire une table qu'on SAIT en cours de reconstruction.
    DimRollupCoverage::retract(conn);
    // Le cap top-N peut faire SORTIR une valeur du top entre deux ticks -> ligne orpheline à PK différente ->
    // double comptage. Chaque tranche est donc PURGÉE avant d'être ré-agrégée (même règle que la fenêtre chaude).
    let mut dim_ok = true;
    let mut dim_slice = |lo: i64, hi: i64| {
        if hi <= lo {
            return;
        }
        dim_ok &= conn.execute("DELETE FROM event_dim_rollup WHERE bucket >= ?1 AND bucket < ?2", params![lo, hi]).is_ok();
        dim_ok &= dim_agg(format!("ts >= {lo} AND ts < {hi} AND id <= {dim_at_id}"));
    };
    dim_slice(down_lo, band_lo); // le front BAS : vers l'histoire jamais agrégée
    dim_slice(band_hi, up_hi);   // le front HAUT : vers le présent, sans jamais sauter
    let _ = conn.execute("DELETE FROM event_dim_rollup WHERE bucket >= ?1", params![recent]); // purge fenêtre chaude (anti-orphelin top-N)
    dim_ok &= dim_agg(format!("ts >= {recent}"));                       // fenêtre chaude (ré-agrégée à chaque tick)
    // PUBLICATION — jamais avant, jamais partielle (une seule ligne `meta`), et JAMAIS si une agrégation a
    // échoué : une couverture qu'on n'a pas prouvée ne s'écrit pas, la route décline, le brut sert.
    if dim_ok {
        DimRollupCoverage::publish(conn, down_lo, up_hi, recent, dim_at_id);
    }
    // Le watermark HISTORIQUE ne doit plus exister : il ne vaut pas couverture, et le laisser là inviterait
    // une lecture future à le reprendre pour telle. C'est précisément l'erreur qu'on ferme.
    let _ = conn.execute("DELETE FROM meta WHERE key=?1", params![META_DIM_ROLLUP_WM_LEGACY]);

    // ---- PHASE host : host_rollup (inventaire de FLOTTE pré-agrégé PAR HÔTE) ----
    // MÊME tick, MÊME mécanique watermark que event_rollup, mais keyé par HÔTE (pas bucketé) -> /api/fleet +
    // /api/integrations lisent une PETITE table au lieu de scanner event∪metric∪snapshot (~4,7 M lignes -> tué
    // par le watchdog 5 s). ZÉRO coût à l'ingest (rollup_hosts ne touche PAS ingest_events_batch).
    rollup_hosts(conn);
}

/// Rollup d'HÔTES (piggyback sur rollup_events) : maintient `host_rollup`, l'inventaire de FLOTTE pré-agrégé PAR
/// HÔTE qui remplace le `SELECT host,MAX(ts) FROM (event∪metric∪snapshot) GROUP BY host` NON borné (~4,7 M lignes,
/// ~39 s -> tué par le watchdog 5 s du read-pool -> flotte FIGÉE à 0). Lecture depuis host_rollup = sub-ms
/// (cardinalité = taille de flotte). ZÉRO coût à l'ingest (ingest_events_batch INCHANGÉ). MÊME mécanique watermark
/// que event_rollup : fenêtre DÉFINITIVE [wm, recent) foldée 1x (sig_total += count) puis le watermark avance ;
/// fenêtre CHAUDE [recent, now] ré-agrégée à CHAQUE tick (sig_hot remis à 0 puis recalculé) -> signals EXACTS sans
/// double comptage. last_ts=MAX / first_ts=MIN (monotones, idempotents). host_rollup n'est JAMAIS prunée (un hôte
/// mort reste visible : son last_ts colle). Bornes = i64 formatées (pas d'injection — comme rollup_events).
pub(crate) fn rollup_hosts(conn: &Connection) {
    let n = now();
    let cur = (n / 3600) * 3600;
    let recent = (cur - 3600).max(0);   // fenêtre chaude = heure courante + précédente
    let wm: i64 = conn.query_row("SELECT value FROM meta WHERE key='host_rollup_wm'", [], |r| r.get::<_, String>(0))
        .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    // FENÊTRE DÉFINITIVE [wm, recent) : heures figées jamais encore comptées -> sig_total += count (1x). Bornée
    // par idx_event_ts / idx_metric_ts / idx_snapshot_ts (range-scan indexé — plus de full-scan+déchiffrement de
    // metric/snapshot chaque tick). Le fold ET l'avance du watermark sont désormais ATOMIQUES : BEGIN IMMEDIATE +
    // upsert du wm en UN statement (PLUS de DELETE-puis-INSERT). Un crash/erreur ne peut donc PLUS laisser le wm
    // absent entre le fold additif et sa réécriture -> plus de re-fold [0,recent) additif au tick suivant qui
    // DOUBLAIT sig_total (double-comptage). Sur échec -> ROLLBACK atomique (fold annulé) + retry au tick
    // suivant. `new_wm` = borne « définitif terminé » après ce tick (recent si on a avancé, sinon wm inchangé).
    let new_wm = if recent > wm {
        let _ = conn.execute_batch("BEGIN IMMEDIATE");
        let done = conn.execute(&host_rollup_upsert_sql(&format!("ts >= {wm} AND ts < {recent}"), HostFold::Definitive, n), [])
            .and_then(|_| conn.execute(
                "INSERT INTO meta(key,value) VALUES('host_rollup_wm', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![recent.to_string()],
            ));
        if done.is_ok() { let _ = conn.execute_batch("COMMIT"); recent } else { let _ = conn.execute_batch("ROLLBACK"); wm }
    } else { wm };
    // RATTRAPAGE des arrivées TARDIVES (events backdatés) : `host_rollup_backfill_floor` = plus vieux ts < wm
    // noté À L'INGEST (note_host_backfill_floor). Si floor < new_wm, on fold UNE fois la fenêtre BORNÉE
    // [floor, new_wm) (index-servie par idx_event_ts/idx_metric_ts/idx_snapshot_ts = le buffer d'un agent, petit)
    // en mode Backfill : sig_total posé seulement à l'INSERT d'un hôte entièrement backdaté (sinon MIN/MAX de
    // first_ts/last_ts) -> IDEMPOTENT, aucun double sur un hôte déjà présent même si [floor,new_wm) recouvre des
    // heures déjà définitives. Puis on REMONTE le floor à new_wm (il ré-avance avec le watermark ; un ingest
    // tardif le rabaissera). Sans donnée tardive (floor absent -> new_wm, ou floor==new_wm) : NO-OP, AUCUN scan.
    let floor: i64 = conn.query_row("SELECT value FROM meta WHERE key='host_rollup_backfill_floor'", [], |r| r.get::<_, String>(0))
        .ok().and_then(|s| s.parse().ok()).unwrap_or(new_wm);
    if floor < new_wm {
        let _ = conn.execute_batch("BEGIN IMMEDIATE");
        let done = conn.execute(&host_rollup_upsert_sql(&format!("ts >= {floor} AND ts < {new_wm}"), HostFold::Backfill, n), [])
            .and_then(|_| conn.execute(
                "INSERT INTO meta(key,value) VALUES('host_rollup_backfill_floor', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![new_wm.to_string()],
            ));
        if done.is_ok() { let _ = conn.execute_batch("COMMIT"); } else { let _ = conn.execute_batch("ROLLBACK"); }
    }
    // FENÊTRE CHAUDE [recent, now] : ré-agrégée à CHAQUE tick. On remet sig_hot=0 sur TOUTE la table (petite) puis
    // sig_hot = count de la fenêtre chaude -> aucun double comptage (le count définitif est déjà dans sig_total).
    // last_ts/first_ts idem via MAX/MIN (idempotents). Le read renvoie sig_total + sig_hot.
    let _ = conn.execute("UPDATE host_rollup SET sig_hot = 0", []);
    let _ = conn.execute(&host_rollup_upsert_sql(&format!("ts >= {recent}"), HostFold::Hot, n), []);
}

/// Mode de fold host_rollup pour UNE fenêtre temporelle :
///  - `Hot`        : fenêtre CHAUDE [recent, now] ré-agrégée à CHAQUE tick (sig_hot = count ; remis à 0 avant).
///  - `Definitive` : fenêtre DÉFINITIVE [wm, recent) foldée 1x quand le watermark avance (sig_total += count).
///  - `Backfill`   : RATTRAPAGE d'arrivées TARDIVES [floor, wm) (ts < wm apparus APRÈS coup — agent offline qui
///    rejoue son buffer journald). sig_total posé UNIQUEMENT à l'INSERT d'un hôte (entièrement backdaté, absent) ;
///    sur CONFLIT -> AUCUN changement de sig_total (seulement MIN/MAX de first_ts/last_ts). IDEMPOTENT : ré-agréger
///    la même fenêtre ne double JAMAIS un hôte déjà présent, même si [floor,wm) chevauche des heures déjà foldées
///    par la fenêtre définitive. -> corrige l'invisibilité/le first_seen trop récent SANS jamais sur-compter.
enum HostFold { Hot, Definitive, Backfill }

/// UPSERT host_rollup pour UNE fenêtre `cond` (filtre sur `ts`, littéraux i64 -> pas d'injection, comme
/// rollup_events). Agrège event∪metric∪snapshot GROUP BY (host,env_id). Un SEUL statement (agrégat batché,
/// PAS de travail par-ligne) -> O(lignes de la fenêtre), jamais O(total) — chaque fenêtre `ts` est bornée par
/// idx_event_ts / idx_metric_ts / idx_snapshot_ts (range-scan indexé, PAS de full-scan+déchiffrement de la table).
fn host_rollup_upsert_sql(cond: &str, mode: HostFold, n: i64) -> String {
    let (ins_total, ins_hot, conflict_sig) = match mode {
        HostFold::Hot        => ("0", "c", "sig_hot = excluded.sig_hot,"),
        HostFold::Definitive => ("c", "0", "sig_total = host_rollup.sig_total + excluded.sig_total,"),
        // Backfill : sig_total FIGÉ sur conflit (posé seulement à l'INSERT) -> rattrapage idempotent, pas de double.
        HostFold::Backfill   => ("c", "0", ""),
    };
    format!(
        "INSERT INTO host_rollup(host, env_id, last_ts, first_ts, sig_total, sig_hot, updated) \
         SELECT host, env_id, last_ts, first_ts, {ins_total}, {ins_hot}, {n} FROM (\
           SELECT host, env_id, MAX(ts) AS last_ts, MIN(ts) AS first_ts, COUNT(*) AS c FROM (\
                     SELECT host,env_id,ts FROM event    WHERE host IS NOT NULL AND host<>'' AND {cond} \
           UNION ALL SELECT host,env_id,ts FROM metric   WHERE host IS NOT NULL AND host<>'' AND {cond} \
           UNION ALL SELECT host,env_id,ts FROM snapshot WHERE host IS NOT NULL AND host<>'' AND {cond}) \
           GROUP BY host, env_id) \
         WHERE true \
         ON CONFLICT(host, env_id) DO UPDATE SET \
           last_ts  = MAX(host_rollup.last_ts, excluded.last_ts), \
           first_ts = MIN(host_rollup.first_ts, excluded.first_ts), \
           {conflict_sig} \
           updated  = excluded.updated"
    )
}

/// Note (à l'INGEST, coût O(1)/batch) le plancher `host_rollup_backfill_floor` = plus vieux `ts` d'un event
/// TARDIF (ts < watermark host_rollup) — un agent offline qui rejoue son buffer journald émet des ts vieux de
/// plusieurs heures dans la MÊME table `event` que le rollup agrège. Sans ce plancher, ces lignes tombent
/// SOUS le watermark et ne sont JAMAIS foldées (hôte sous-compté / first_seen trop récent / entièrement
/// invisible). Point-read meta indexé (PK) + upsert conditionnel MONOTONE DÉCROISSANT ; N'écrit RIEN quand la
/// donnée est courante (ts >= wm, cas nominal) -> ZÉRO surcoût ingest en régime normal, AUCUNE ligne
/// event/metric/snapshot touchée (data-plane byte-identique). rollup_hosts rattrapera [floor, wm) une fois.
pub(crate) fn note_host_backfill_floor(conn: &Connection, min_ts: i64) {
    let wm: i64 = conn.query_row("SELECT value FROM meta WHERE key='host_rollup_wm'", [], |r| r.get::<_, String>(0))
        .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    if min_ts < wm {
        let _ = conn.execute(
            "INSERT INTO meta(key,value) VALUES('host_rollup_backfill_floor', ?1) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE CAST(meta.value AS INTEGER) > CAST(excluded.value AS INTEGER)",
            params![min_ts.to_string()],
        );
    }
}

/// Construit les 4 UPSERT d'alimentation de `banned_ip` pour UNE fenêtre temporelle `cond` (filtre sur
/// `ts`, littéraux i64 formatés -> pas d'injection ; sources = littéraux internes). Une banlist
/// MATÉRIALISÉE rend le panneau « attaquants non mitigés » cheap : l'anti-join (LEFT JOIN ... IS NULL)
/// porte sur cette petite table au lieu d'un `NOT IN (sous-requête stats)` non supporté + coûteux. UPSERT
/// idempotent : first_seen=MIN(ts) (premier ban vu), last_seen=MAX(ts) (dernier) — fusionnés avec la ligne
/// existante via ON CONFLICT, donc ré-agréger la même fenêtre est SANS effet (sûr pour le tick chaud).
///   - fail2ban : category=ban (collecteur bans.sh) -> label=jail (parser fail2ban) ;
///   - crowdsec  : toute décision active -> label=scenario (parser crowdsec) ;
///   - ufw       : action block(ed) (collecteur ufw.sh émet 'blocked') -> label=proto ;
///   - portscan  : nft PORTSCAN -> label=dir.
/// src_ip = COLONNE réelle (jamais json_extract) -> exact + indexé (idx_event_src_srcip). Les `label`
/// sont en COALESCE('') -> jamais NULL même si le parser n'a pas (encore) enrichi le champ.
fn banned_ip_upsert_sqls(cond: &str) -> [String; 3] {
    let upsert = |source: &str, label: &str, extra: &str| -> String {
        format!(
            "INSERT INTO banned_ip(src_ip,source,label,first_seen,last_seen) \
             SELECT src_ip, '{source}', {label}, MIN(ts), MAX(ts) \
             FROM event WHERE source='{source}'{extra} AND src_ip IS NOT NULL AND src_ip<>'' AND ({cond}) \
             GROUP BY src_ip \
             ON CONFLICT(src_ip,source) DO UPDATE SET \
               first_seen=MIN(banned_ip.first_seen,excluded.first_seen), \
               last_seen=MAX(banned_ip.last_seen,excluded.last_seen), \
               label=excluded.label"
        )
    };
    // 'ufw' RETIRÉ : action IN ('block','blocked') = paquet DROPPÉ sur un port fermé, PAS un ban (gonflait
    // banned_ip de ~9900 IP de scan et n'ajoute aucune valeur d'anti-join — les attaquants tapent 80/443).
    [
        upsert("fail2ban", "COALESCE(json_extract(fields,'$.jail'),'')", " AND category='ban'"),
        upsert("crowdsec", "COALESCE(json_extract(fields,'$.scenario'),'')", ""),
        upsert("portscan", "COALESCE(json_extract(fields,'$.dir'),'')", ""),
    ]
}

/// MATÉRIALISATION INCRÉMENTALE de `banned_ip` (tick ~PLUME_ROLLUP_INTERVAL_S + filet horaire). MÊME
/// mécanique BORNÉE que rollup_events : ré-UPSERT l'heure courante + la précédente (fenêtre chaude, garde
/// last_seen frais ; idempotent via MIN/MAX) et rattrape UNE fois les heures définitives via le watermark
/// `banned_ip_wm`. JAMAIS de full-scan : au cold start le watermark est BORNÉ à PLUME_BANNED_IP_BACKFILL
/// (défaut 7 j — les bans persistent plus longtemps qu'un rollup de trafic) -> on ne scanne que
/// [recent-backfill, recent) des PETITES sources de ban (fail2ban/crowdsec/ufw/portscan), pas les 140k web.
/// Purge OPTIONNELLE (PLUME_BANNED_IP_RETENTION>0) des entrées dont le dernier ban remonte au-delà de la
/// rétention (bans expirés) — OFF par défaut (0). Bornes = i64 (pas d'injection).
pub(crate) fn materialize_banned_ip(conn: &Connection) {
    let n = now();
    let cur = (n / 3600) * 3600;
    let recent = (cur - 3600).max(0); // fenêtre chaude = heure courante + précédente
    let conf = load_config();
    let backfill: i64 = cfg(&conf, "PLUME_BANNED_IP_BACKFILL", "604800").parse().unwrap_or(604800).max(3600);
    let floor = (recent - backfill).max(0);
    let stored_wm: i64 = conn.query_row("SELECT value FROM meta WHERE key='banned_ip_wm'", [], |r| r.get::<_, String>(0))
        .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let wm = stored_wm.max(floor); // cold start / rattrapage BORNÉS à backfill (jamais de scan depuis 0)
    let upsert = |cond: String| {
        for stmt in banned_ip_upsert_sqls(&cond) {
            let _ = conn.execute(&stmt, []);
        }
    };
    if recent > wm {
        upsert(format!("ts >= {wm} AND ts < {recent}")); // heures définitives (bornées à backfill), 1x
    }
    upsert(format!("ts >= {recent}")); // fenêtre chaude (ré-UPSERT à chaque tick ; idempotent via MIN/MAX)
    let _ = conn.execute("DELETE FROM meta WHERE key='banned_ip_wm'", []);
    let _ = conn.execute("INSERT INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![recent.to_string()]);
    // purge OPTIONNELLE des bans expirés (last_seen trop ancien). OFF par défaut (0 -> no-op).
    let retention: i64 = cfg(&conf, "PLUME_BANNED_IP_RETENTION", "0").parse().unwrap_or(0);
    if retention > 0 {
        let _ = conn.execute("DELETE FROM banned_ip WHERE last_seen < ?1", params![n - retention]);
    }
}

/// Panneau « Attaquants NON mitigés » (SQL natif, source UNIQUE partagée par le SEED et la MIGRATION v54).
/// `__OPERATOR_EXCL__` exclut l'IP opérateur (bruit pur : son navigateur sur le dashboard ne doit pas
/// remonter comme « attaquant non banni »).
pub(crate) const BANPASS_UNMITIGATED_SQL: &str =
    "WITH attackers AS ( \
        SELECT src_ip, SUM(c) AS activite FROM ( \
          SELECT src_ip, COUNT(*) AS c FROM event \
            WHERE source='cloudflare' AND ts>=__FROM__ AND json_extract(fields,'$.action')='challenged' \
              AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ GROUP BY src_ip \
          UNION ALL \
          SELECT src_ip, COUNT(*) AS c FROM event \
            WHERE source='web' AND ts>=__FROM__ AND CAST(json_extract(fields,'$.status') AS INTEGER)>=400 \
              AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ GROUP BY src_ip \
        ) GROUP BY src_ip HAVING activite > 20 \
      ) \
      SELECT a.src_ip, a.activite FROM attackers a \
        LEFT JOIN banned_ip b ON b.src_ip=a.src_ip \
        WHERE b.src_ip IS NULL \
        ORDER BY a.activite DESC LIMIT 50";

/// Panneau « Couverture de ban » (même population d'attaquants que ci-dessus -> MÊME exclusion opérateur
/// pour rester cohérent : sinon l'opérateur gonflerait le dénominateur et fausserait le %).
pub(crate) const BANPASS_COVERAGE_SQL: &str =
    "WITH attackers AS ( \
        SELECT DISTINCT src_ip FROM ( \
          SELECT src_ip FROM event WHERE source='cloudflare' AND ts>=__FROM__ \
            AND json_extract(fields,'$.action')='challenged' AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ \
          UNION \
          SELECT src_ip FROM event WHERE source='web' AND ts>=__FROM__ \
            AND CAST(json_extract(fields,'$.status') AS INTEGER)>=400 AND src_ip IS NOT NULL AND src_ip<>'' AND __OPERATOR_EXCL__ \
        ) \
      ) \
      SELECT (SELECT COUNT(*) FROM attackers) AS attaquants, \
             (SELECT COUNT(*) FROM attackers a WHERE EXISTS(SELECT 1 FROM banned_ip b WHERE b.src_ip=a.src_ip)) AS bannis, \
             CASE WHEN (SELECT COUNT(*) FROM attackers)=0 THEN 0.0 \
                  ELSE ROUND(100.0*(SELECT COUNT(*) FROM attackers a WHERE EXISTS(SELECT 1 FROM banned_ip b WHERE b.src_ip=a.src_ip)) \
                             /(SELECT COUNT(*) FROM attackers),1) END AS couverture_pct";

/// Dashboard « Banni / Pass » — surface les IPs qui ATTAQUENT mais ne sont PAS bannies. Panneaux is_soql=0
/// (SQL natif : anti-join sur `banned_ip`, hors-portée du compilo GXQL) SWR-cachés (panel_cache_ttl_s>0 ->
/// calculés EN FOND par cache_refresh_all_panels, servis depuis panel_cache ; JAMAIS de LIVE-sync
/// timeout-able). Idempotent par nom (comme seed_rollup_dashboard). Vue 'Sécurité'. __FROM__ = fenêtre.
/// GÉNÉRIQUE SUR `SqlExec` (cf. migrate.rs) : `&Connection` depuis le boot (historique inchangé),
/// `&MigTx` depuis la migration v52 -> écritures SOUS le garde de l'étape.
pub(crate) fn seed_banpass_dashboard<C: SqlExec>(conn: &C) {
    if conn.query_row("SELECT 1 FROM dashboard WHERE name='Banni / Pass'", [], |r| r.get::<_, i64>(0)).is_ok() {
        return;
    }
    if conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('Banni / Pass', ?1, 'shared')", params![now()]).is_err() {
        return;
    }
    let did = conn.last_insert_rowid();
    // v63 : « Banni / Pass » -> vue « Détection » (à côté de « Sécurité & détection »), REPLIÉ (non primaire).
    if let Some(vid) = find_or_create_view(conn, "Détection") { let _ = conn.execute("UPDATE dashboard SET view_id=?1, collapsed=1 WHERE id=?2", params![vid, did]); }
    // (titre, requête is_soql=0, viz, panel_cache_ttl_s). TOUS les panneaux sont bornés par __FROM__
    // (fenêtre 24 h par défaut ; picker='Tout' -> from=0 -> tout l'historique) + LIMIT + SWR.
    let panels: [(&str, &str, &str, i64); 4] = [
        ("Banlist par source",
         "SELECT source, COUNT(DISTINCT src_ip) AS ips FROM banned_ip WHERE last_seen >= __FROM__ GROUP BY source ORDER BY ips DESC",
         "bar", 120),
        ("IPs bannies (dernier ban dans la fenêtre)",
         "SELECT COUNT(DISTINCT src_ip) AS ips_bannies FROM banned_ip WHERE last_seen >= __FROM__",
         "stat", 120),
        ("Attaquants NON mitigés (non bannis, fenêtre)",
         BANPASS_UNMITIGATED_SQL,
         "table", 300),
        ("Couverture de ban (% attaquants déjà bannis)",
         BANPASS_COVERAGE_SQL,
         "table", 300),
    ];
    for (i, (title, q, viz, ttl)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols,panel_cache_ttl_s) VALUES(?1,?2,?3,0,?4,?5,2,?6)",
            params![did, title, q, viz, i as i64, ttl],
        );
    }
}

/// Rafraîchit (best-effort) le cache de résultats des panneaux pour leur FENÊTRE PAR DÉFAUT (24 h
/// glissantes : la PWA envoie `from = now-86400, to = 0`, cf. index.html option 86400 `selected`).
/// PRÉ-CHAUFFAGE : on pré-chauffe EXACTEMENT cette fenêtre (from=now-defaut, to=0) -> même
/// range_key (clé sur la durée) que ce que la PWA demande -> 1er affichage instantané (HIT). But : que
/// le 1er affichage soit instantané au lieu d'attendre une exécution live. On exécute via run_query
/// (pool read-only) HORS du lock writer (on ne garde le lock que pour lister/écrire 1 ligne / panel).
/// BORNE DE CONCURRENCE : chaque run_query passe par le sémaphore `refresh_sem` (CHANGEMENT 1 : SÉPARÉ du query_sem
/// interactif ; try_acquire non bloquant) -> le pré-chauffage respecte sa PROPRE borne de concurrence sans
/// jamais voler de permis à /api/query ni /api/search. Idempotent (OR REPLACE) -> taille bornée (1 ligne /
/// panel). TTL global PLUME_PANEL_CACHE_TTL=0 -> no-op.
pub(crate) fn cache_refresh_all_panels(db: &Arc<Mutex<Connection>>, db_path: &str, refresh_sem: &Arc<tokio::sync::Semaphore>) {
    let conf = load_config();
    let ttl_global: i64 = cfg(&conf, "PLUME_PANEL_CACHE_TTL", "60").parse().unwrap_or(60);
    if ttl_global <= 0 {
        return;
    }
    // fenêtre par défaut de la PWA (s) : 24 h, réglable (doit refléter l'option `selected` de index.html).
    let default_window: i64 = cfg(&conf, "PLUME_PANEL_DEFAULT_WINDOW", "86400").parse().unwrap_or(86400).max(1);
    let now_s = now();
    let from_default = now_s - default_window; // borne glissante, comme currentFrom() côté PWA
    let range_key = cache_range_key(from_default, 0, now_s);
    // PHASE 3b — pré-chauffe TOUS les panneaux (plus de filtre is_soql=0) : les panneaux GXQL (Sécurité,
    // les plus coûteux) sont désormais aussi réchauffés en fond -> panel_data les sert du cache (SWR) sans
    // jamais lancer de live. TTL effectif > 0. On capture id+query+is_soql pour exécuter SANS tenir le lock.
    let panels: Vec<(i64, String, bool)> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare(
            "SELECT id, query, is_soql FROM panel \
             WHERE COALESCE(panel_cache_ttl_s, ?1) > 0",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = stmt.query_map(params![ttl_global], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)));
        match rows { Ok(it) => it.flatten().collect(), Err(_) => return }
    };
    for (id, query, is_soql) in panels {
        // fenêtre par défaut glissante (cohérent avec panel_data + ce que la PWA demande). GXQL compilé via
        // soql_to_sql ; SQL natif -> substitution __FROM__/__TO__. fingerprint sur le VRAI is_soql.
        // env=None (#2d) : le pré-chauffage remplit le slot cache TOUS-ENV (clé de plage sans préfixe env,
        // cf. env_range_key) ; les payloads par-env sont calculés À LA DEMANDE dans panel_data.
        let sql = match compile_panel_sql(&query, is_soql, from_default, 0, None) {
            Ok(s) => s,
            Err(_) => continue, // GXQL invalide -> on saute (le panneau retombe sur le fallback live)
        };
        let q_fp = query_fingerprint(&query, is_soql);
        // borne de concurrence sur le refresh_sem DÉDIÉ : si aucun permit libre, on saute ce
        // tick de pré-chauffage (jamais de permis pris à l'interactif ; le panneau reste servi du cache).
        let permit = match refresh_sem.try_acquire() { Ok(p) => p, Err(_) => break };
        if let Ok(v) = run_query(db_path, &sql) {
            let cost_ms = measured_cost_ms(&v); // PHASE 3d : pré-classe les panneaux dès le pré-chauffage
            if let Ok(payload) = serde_json::to_string(&v) {
                { let conn = db.lock();
                    // PHASE 3d : mémorise le coût (le 1er user ne paie plus la 1re mesure d'un panneau lourd).
                    if let Some(c) = cost_ms {
                        record_panel_cost(&conn, id, &q_fp, c, now_s);
                    }
                    // 1 ligne / (panel, range_key) sur PK composite : le pré-chauffage 24 h
                    // coexiste avec les plages zoom/preset (plus d'éviction mutuelle). computed_at = now_s
                    // (lu une fois, cohérent avec range_key).
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)",
                        params![id, range_key, q_fp, now_s, payload],
                    );
                    // même cap anti-explosion que panel_data (garde les K plages les plus récentes).
                    let _ = conn.execute(
                        "DELETE FROM panel_cache WHERE panel_id=?1 AND range_key NOT IN \
                         (SELECT range_key FROM panel_cache WHERE panel_id=?1 ORDER BY computed_at DESC LIMIT ?2)",
                        params![id, CACHE_MAX_RANGES_PER_PANEL],
                    );
                }
            }
        }
        drop(permit); // relâche le permit avant le panneau suivant (concurrence bornée, pas monopolisée)
    }
}

/// Fragment WHERE PARTAGÉ (#49) : events de CONTRÔLE du daemon JAMAIS purgés (audit config / accès
/// opérateur / tenant-admin / engagement), lié au marqueur `origin='daemon'` SEUL — un agent qui forge
/// `source` porte origin='' et reste purgeable (M1/M4). Réutilisé par la purge GLOBALE de `event`, par la
/// purge PER-INDEX (#49) et par les PLAFONDS -> garantie UNIQUE : une policy d'index mal réglée ne peut
/// JAMAIS effacer la preuve SOC-visible. Le texte produit reste IDENTIQUE au littéral historique (mode 0).
pub(crate) const RETENTION_NONPURGE: &str =
    "NOT (origin='daemon' AND source IN ('plume-config','plume-operator-access','plume-tenant-admin','plume-engagement'))";

/// MÊME clause, avec les colonnes QUALIFIÉES par `alias`. La PURGE EXPLICITE (`purge.rs`) doit joindre `event`
/// à `incident_item` — qui porte aussi une colonne `ts` — donc son prédicat ne peut pas laisser de colonne nue
/// (SQLite refuserait l'ambiguïté). Recopier le littéral aurait créé DEUX vérités qui dérivent en silence :
/// ajouter une source de contrôle d'un côté et pas de l'autre rendrait cette source purgeable par la purge
/// explicite alors que la rétention la protège. `alias` VIDE reproduit le littéral historique à l'octet près,
/// et le test `retention_nonpurge_qualified_matches_the_literal` VERROUILLE cette égalité : modifier l'un sans
/// l'autre fait rougir.
pub(crate) fn retention_nonpurge_for(alias: &str) -> String {
    let p = if alias.is_empty() { String::new() } else { format!("{alias}.") };
    format!(
        "NOT ({p}origin='daemon' AND {p}source IN ('plume-config','plume-operator-access','plume-tenant-admin','plume-engagement'))"
    )
}

/// #23 F3 — taille de LOT des purges de rétention chunkées. La 1re purge d'un gros backlog supprimait des
/// MILLIONS de lignes en UNE transaction sous le mutex WRITER (le plus long verrou d'écriture du daemon),
/// affamant l'ingest pendant toute la durée. On borne chaque DELETE à `RETENTION_PURGE_BATCH` lignes puis on
/// RELÂCHE le verrou entre les lots (l'ingest s'intercale). Réglable pour l'ops (défaut 10000, borné).
pub(crate) fn retention_purge_batch() -> i64 {
    cfg(&load_config(), "PLUME_RETENTION_PURGE_BATCH", "10000")
        .parse()
        .unwrap_or(10000)
        .clamp(500, 200_000)
}

/// #23 F3 — PURGE CHUNKÉE, verrou writer RELÂCHÉ ENTRE LES LOTS. Supprime PAR LOTS de `batch` lignes
/// (`rowid IN (SELECT rowid … WHERE <where_sql> LIMIT batch)`) jusqu'à ce qu'un lot supprime < batch lignes.
/// ÉTAT FINAL IDENTIQUE à un `DELETE … WHERE <where_sql>` non borné : `where_sql` est STABLE et les bornes
/// temporelles sont des cutoffs FIXES (calculés une fois depuis `now()`) -> les lignes ingérées PENDANT la
/// purge portent ts≈maintenant > cutoff, ne matchent jamais -> convergence garantie, mêmes lignes supprimées.
/// `where_sql`/`table` = LITTÉRAUX internes (jamais d'entrée utilisateur) ; `binds` = valeurs LIÉES (les
/// placeholders `?k` du where_sql). `batch` inliné (constante interne, jamais utilisateur -> injection-safe).
/// Erreur transitoire d'un lot -> arrêt du lot (les lignes restantes seront purgées au tick suivant : même
/// philosophie « swallow & continue » que les `let _ = execute` d'origine). Le verrou est repris à chaque lot.
pub(crate) fn chunked_purge(db: &Arc<Mutex<Connection>>, table: &str, where_sql: &str, binds: &[&dyn rusqlite::ToSql], batch: i64) {
    let sql = format!(
        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {where_sql} LIMIT {batch})"
    );
    loop {
        let affected = { db.lock().execute(&sql, binds).unwrap_or(0) };
        if (affected as i64) < batch {
            break; // dernier lot (partiel ou vide) -> toutes les lignes matchantes sont supprimées.
        }
    }
}

/// Plancher/plafond DURS de la rétention PER-INDEX (#49) — MÊME borne que la rétention globale `event`
/// (RETENTION_FIELDS : event >= 7 j, <= 3650 j). Appliqués À L'APPLICATION (load_index_policies) : une
/// valeur écrite hors bornes ou une policy agressive ne peut PAS purger un index sous 7 j (anti-effacement).
const INDEX_RETENTION_FLOOR_DAYS: i64 = 7;
const INDEX_RETENTION_CEIL_DAYS: i64 = 3650;

/// Une politique d'INDEX LOGIQUE NOMMÉ VALIDÉE (#49). `name` == valeur d'`env_id` (env_id_ok) — le MÊME
/// axe que route l'action ROUTE de #40 et qu'agrègent les rollups. `retention_days` : 0 = HÉRITE de la
/// rétention globale (l'index n'est PAS exclu du global) ; >0 = fenêtre PROPRE (déjà planchée/plafonnée).
pub(crate) struct IndexPolicy {
    pub name: String,
    pub retention_days: i64,
    pub max_rows: i64,
    pub max_bytes: i64,
}

/// Charge les policies d'index ACTIVES et VALIDES depuis `index_policy`. FAIL-SAFE de bout en bout :
///   - table absente (base pré-v91) -> Vec VIDE => retention_run reste BYTE-IDENTIQUE (mode 0) ;
///   - nom hors allowlist (env_id_ok) -> ligne ÉCARTÉE => l'index retombe sur la purge GLOBALE (jamais
///     sur-purgé, jamais un DELETE avec un nom non validé) ;
///   - retention_days>0 -> planché/plafonné [7,3650] (jamais sous le plancher event) ; <=0 -> 0 (hérite
///     du global pour le TEMPS mais garde ses plafonds max_rows/max_bytes) ;
///   - max_rows/max_bytes négatifs -> ramenés à 0 (no-op).
pub(crate) fn load_index_policies(conn: &Connection) -> Vec<IndexPolicy> {
    let mut out = Vec::new();
    let Ok(mut st) = conn.prepare("SELECT name, retention_days, max_rows, max_bytes FROM index_policy WHERE enabled=1") else {
        return out; // table absente (pré-v91) ou indisponible -> aucune policy (mode 0)
    };
    let Ok(rows) = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
    }) else {
        return out;
    };
    for (name, rdays, max_rows, max_bytes) in rows.flatten() {
        if !env_id_ok(&name) {
            continue; // fail-safe : nom invalide -> ignoré (l'index reste purgé par le global, jamais sur-purgé)
        }
        let retention_days = if rdays > 0 { rdays.clamp(INDEX_RETENTION_FLOOR_DAYS, INDEX_RETENTION_CEIL_DAYS) } else { 0 };
        out.push(IndexPolicy { name, retention_days, max_rows: max_rows.max(0), max_bytes: max_bytes.max(0) });
    }
    out
}

/// Purge de rétention PAR-INDEX pour UNE table portant `env_id` + une colonne temporelle `tscol`. `table`,
/// `tscol` et `extra` sont des LITTÉRAUX internes (jamais d'entrée utilisateur — `extra` = RETENTION_NONPURGE
/// ou ""). Deux passes :
///   1) PER-INDEX : chaque env_id à policy-temps (retention_days>0) est purgé à SON cutoff (paramètre lié) ;
///   2) GLOBAL : lignes < `global_cutoff` dont l'env_id N'A PAS de policy-temps (exclusion `NOT IN`).
/// MODE 0 (aucune policy-temps) -> la passe GLOBALE émet un statement BYTE-IDENTIQUE au littéral historique
/// (jamais `NOT IN ()`). Les NOMS d'index ne sont JAMAIS interpolés : seuls les placeholders `?k` le sont, les
/// valeurs sont LIÉES (injection-safe).
pub(crate) fn retention_prune_table(db: &Arc<Mutex<Connection>>, table: &str, tscol: &str, extra: &str, global_cutoff: i64, n: i64, policies: &[IndexPolicy]) {
    let guard = if extra.is_empty() { String::new() } else { format!(" AND {extra}") };
    let batch = retention_purge_batch();
    // 1) per-index (fenêtre propre) — borné par un index de TÊTE sur `tscol` : idx_event_ts pour `event`, et
    //    pour `event_rollup` l'AUTO-INDEX de sa PK (bucket, source, severity, action, src_ip, host, env_id),
    //    dont `bucket` est la colonne de tête (P10.2-d : idx_event_rollup(bucket), doublon de ce préfixe, a été
    //    retiré — le range sur tscol reste servi à l'identique). env_id filtré.
    //    #23 F3 : CHUNKÉ (verrou relâché entre lots) ; même prédicat, mêmes lignes finales supprimées.
    for p in policies.iter().filter(|p| p.retention_days > 0) {
        let cutoff = n - p.retention_days * 86400;
        chunked_purge(db, table, &format!("env_id=?1 AND {tscol} < ?2{guard}"), &[&p.name, &cutoff], batch);
    }
    // 2) global (exclut les env_id à policy-temps).
    let time_names: Vec<&String> = policies.iter().filter(|p| p.retention_days > 0).map(|p| &p.name).collect();
    if time_names.is_empty() {
        // MODE 0 : même ENSEMBLE FINAL que le littéral historique `DELETE … WHERE {tscol} < ? {guard}`
        // (purge chunkée #23 F3 ; guard IDENTIQUE -> aucune divergence de rétention).
        chunked_purge(db, table, &format!("{tscol} < ?1{guard}"), &[&global_cutoff], batch);
    } else {
        let ph: Vec<String> = (0..time_names.len()).map(|i| format!("?{}", i + 2)).collect();
        let where_sql = format!("{tscol} < ?1{guard} AND env_id NOT IN ({})", ph.join(","));
        let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(time_names.len() + 1);
        binds.push(&global_cutoff);
        for name in &time_names {
            binds.push(*name);
        }
        chunked_purge(db, table, &where_sql, binds.as_slice(), batch);
    }
}

/// PLAFONDS de dimensionnement (#49) d'une policy, appliqués à `event` : garde les events les plus RÉCENTS
/// de l'index, purge le surplus. Events de CONTRÔLE (RETENTION_NONPURGE) TOUJOURS protégés. Job horaire
/// (hors chemin chaud). 0 -> no-op. Bornes LIÉES (le nom d'index n'est jamais interpolé).
fn retention_apply_caps(conn: &Connection, p: &IndexPolicy, guard: &str) {
    // `guard` = RETENTION_NONPURGE (mode 0, byte-identique) OU RETENTION_NONPURGE + prédicat legal-hold (#59)
    // -> les events RETENUS par un hold actif ne sont JAMAIS purgés par un plafond mal réglé (fail-safe).
    if p.max_rows > 0 {
        // garde les max_rows lignes les plus récentes (ts DESC), purge le reste — hors events de contrôle/retenus.
        let _ = conn.execute(
            &format!(
                "DELETE FROM event WHERE env_id=?1 AND {guard} AND id NOT IN (\
                   SELECT id FROM event WHERE env_id=?1 ORDER BY ts DESC, id DESC LIMIT ?2)"
            ),
            params![p.name, p.max_rows],
        );
    }
    if p.max_bytes > 0 {
        // fenêtre glissante par TAILLE estimée (message+fields+~64 o d'overhead) : garde les lignes récentes
        // dont le cumul <= max_bytes, purge les plus anciennes au-delà. Estimation (jamais de sur-purge
        // catastrophique) ; events de contrôle/retenus protégés.
        let _ = conn.execute(
            &format!(
                "DELETE FROM event WHERE env_id=?1 AND {guard} AND id IN (\
                   SELECT id FROM (SELECT id, SUM(length(COALESCE(message,''))+length(COALESCE(fields,''))+64) \
                     OVER (ORDER BY ts DESC, id DESC) AS cum FROM event WHERE env_id=?1) WHERE cum > ?2)"
            ),
            params![p.name, p.max_bytes],
        );
    }
}

/// Point d'entrée HISTORIQUE (tenant default / mode 0) : db_path vide -> le tier cold (si activé) résout la
/// racine cold comme AVANT (`PLUME_COLD_DIR` ou `<parent PLUME_DB>/cold`). Comportement inchangé.
pub(crate) fn retention_run(db: &Arc<Mutex<Connection>>) {
    retention_run_tenant(db, "");
}

/// Point d'entrée PAR-TENANT (#2a) : `db_path` = base du tenant courant. Seul le tier COLD (#18, FIX #2)
/// l'utilise, pour dériver une racine cold DISJOINTE par tenant (cf. cold_store::cold_root). Tout le reste de
/// la rétention est INCHANGÉ (le db_path n'influe sur RIEN d'autre).
pub(crate) fn retention_run_tenant(db: &Arc<Mutex<Connection>>, db_path: &str) {
    let conf = load_config();
    let n = now();
    // #23 F3 — le mutex WRITER n'est PLUS tenu pour TOUTE la fonction (c'était le plus long verrou d'écriture
    // du daemon). Il est pris en COURTS scopes (résolution des fenêtres, INSERT de rollup, ledger/checkpoint),
    // et les PURGES volumineuses sont chunkées (chunked_purge / retention_prune_table) en le RELÂCHANT entre
    // les lots -> l'ingest s'intercale. Les cutoffs sont calculés UNE FOIS depuis `now()` (fixes) -> l'état
    // FINAL est identique à l'ancienne version mono-verrou (mêmes lignes supprimées, mêmes tables dérivées) ;
    // seule la latence d'ingest pendant la purge change. Sémantiques préservées : hot-reload, planchers durs,
    // RETENTION_NONPURGE, legal-hold (fail-closed), policies per-index/plafonds — TOUS inchangés.
    let (ev, snap, alert, metric, raw_h) = {
        let conn = db.lock();
        // HOT-RELOAD (#1b) : la table `setting` (éditée par l'UI admin) GAGNE, sinon env/conf, sinon défaut — via
        // le MÊME résolveur (setting_days) que les GET/preview (correctif H2 : jamais un défaut divergent). Les
        // PLANCHERS DURS (correctifs H1/M6 : event≥7j, alert≥30j...) sont appliqués ICI aussi (défense : une valeur
        // écrite hors bornes, un env trop bas ou une conf agressive ne peut PAS purger sous le plancher). Sans ligne
        // `setting`, comportement historique (env/conf/défaut). Une valeur écrite par l'UI est prise au tick suivant.
        (
            retention_effective(&conn, &conf, "retention_days"),
            retention_effective(&conn, &conf, "snapshot_days"),
            retention_effective(&conn, &conf, "alert_days"),
            retention_effective(&conn, &conf, "metric_days"),
            retention_effective(&conn, &conf, "metric_raw_hours"),
        )
    };
    let cutoff = n - raw_h * 3600;
    // métriques fines plus vieilles que raw_h -> moyenne/min/max horaire (un seul INSERT agrégé), PUIS purge du
    // raw. COR MED-1 (atomicité, v134) : l'INSERT de rollup ET la purge sont tenus sous UN SEUL verrou writer,
    // SANS relâchement entre les deux. Sinon une métrique BACKDATÉE (ts<cutoff) committée par l'ingest ENTRE le
    // rollup (verrou relâché) et la purge (re-verrou par-chunk) serait supprimée SANS avoir été agrégée =
    // PERTE silencieuse (elle ne serait PAS "rattrapée au tick suivant" : ses lignes brutes n'existent plus).
    // La table `metric` = jauges TEMPS RÉEL (fenêtre raw_h), PETITE -> une purge NON chunkée ne provoque pas le
    // stall d'ingest qui motivait le chunking des GROSSES tables (event/alert). État FINAL identique à la purge
    // chunkée (même prédicat `ts < cutoff`), seule l'atomicité change.
    {
        let conn = db.lock();
        let _ = conn.execute(
            "INSERT INTO metric_rollup(ts,name,host,labels,avg,min,max,n) \
             SELECT (ts/3600)*3600, name, host, labels, AVG(value), MIN(value), MAX(value), COUNT(*) \
             FROM metric WHERE ts < ?1 GROUP BY ts/3600, name, host, labels",
            params![cutoff],
        );
        // Purge ATOMIQUE (même verrou, même scope) : aucune fenêtre où une ligne <cutoff peut être purgée
        // sans avoir été rollup-ée. NON chunkée volontairement (table petite -> pas de stall d'ingest).
        let _ = conn.execute("DELETE FROM metric WHERE ts < ?1", params![cutoff]);
    }
    // #23 F3 — les re-runs `rollup_events` / `materialize_banned_ip` / `rollup_risk` (ancien « filet horaire »)
    // sont RETIRÉS : la boucle de rollup dédiée (spawn_rollup_loop, cadence `rollup_interval` ~120 s) appelle
    // EXACTEMENT ces trois fns sur le MÊME handle par-tenant à une cadence BIEN plus fine que ce tick horaire
    // -> strictement redondant (aucune fraîcheur perdue). Retirés du plus long verrou writer.
    // #49 — RÉTENTION PAR INDEX LOGIQUE NOMMÉ. L'index = `env_id` (l'axe que route déjà #40 / qu'agrègent les
    // rollups). Une `index_policy` avec retention_days>0 purge SON index à SA fenêtre (planchée 7 j) et l'EXCLUT
    // de la purge globale ; sans policy-temps -> purge globale INCHANGÉE (mode 0, cf. retention_prune_table).
    // Fail-safe : nom invalide -> écarté par load_index_policies (l'index retombe sur le global, jamais
    // sur-purgé). AUCUN nom d'index interpolé (paramètres liés) -> injection-safe.
    // #18 Phase 1 — AGING vers le tier COLD Parquet (opt-in). DOUBLE GATE : COMPILE (`cold_tier` — sans la
    // feature, cette ligne n'existe PAS -> retention_run byte-identique) + RUNTIME (`PLUME_COLD_TIER`, testé
    // DANS cold_age_run -> retour immédiat si absent). Placé AVANT la purge globale de `event` : la bande
    // agée [now-retention .. now-hot_window] est DISJOINTE de la bande hard-purgée (ts < now-retention) donc
    // l'ordre n'altère PAS l'état final. Feature OFF **ou** flag OFF -> aucun Parquet, aucune suppression cold.
    #[cfg(feature = "cold_tier")]
    crate::cold_store::cold_age_run(db, db_path, &conf, n, ev);
    #[cfg(not(feature = "cold_tier"))]
    let _ = db_path; // db_path n'est consommé QUE par le tier cold (gate compile) -> inerte sinon.
    let policies = { let conn = db.lock(); load_index_policies(&conn) };
    let global_cutoff = n - ev * 86400;
    // Rollups pré-agrégés (event_rollup / event_dim_rollup) purgés PAR LA MÊME policy -> les stats per-index
    // (compte/oldest lus depuis event_rollup) restent COHÉRENTES avec le brut conservé (un index à rétention
    // plus LONGUE que le global garde ses buckets). Purge chunkée (#23 F3), mêmes lignes finales supprimées.
    retention_prune_table(db, "event_rollup", "bucket", "", global_cutoff, n, &policies);
    retention_prune_table(db, "event_dim_rollup", "bucket", "", global_cutoff, n, &policies);
    // La purge vient de SUPPRIMER des buckets sous le cutoff : la bande publiée ne peut plus en témoigner.
    // On remonte son plancher (cf. `DimRollupCoverage::raise_floor`) — sinon la couverture affirmerait une
    // image sur des buckets qu'on vient d'effacer, ce qui est exactement le défaut qu'on ferme.
    { let conn = db.lock(); DimRollupCoverage::raise_floor(&conn, global_cutoff); }
    // RÉTENTION DE L'AUDIT : NE JAMAIS purger l'audit de config NI les marqueurs d'accès
    // opérateur/tenant-admin (client-visibles). Sinon un admin baisse la rétention, agit, et sous quelques
    // jours TOUTE la trace SOC-visible/alertable de ses changements — y compris l'event « rétention baissée »
    // lui-même — s'auto-effacerait. L'exclusion (RETENTION_NONPURGE) est liée au marqueur `origin='daemon'`
    // (posé par le DAEMON seul quand il écrit ces events, cf. audit_config_change/emit_operator_access) ET NON
    // à la seule valeur textuelle de `source` : un agent qui forge source='plume-config' porte origin='' -> il
    // est PURGÉ normalement (M1 : plus de lignes non-purgeables forgeables = anti-remplissage disque) et ne peut
    // usurper la preuve d'accès opérateur (M4). La MÊME garde s'applique aux chemins PER-INDEX et aux PLAFONDS
    // (#49) : une policy d'index mal réglée ne peut jamais effacer ces events de contrôle. v75 : `plume-engagement`
    // (création/expiry d'un engagement pentest) est aussi NON-PURGEABLE — preuve break-glass alertable.
    // #59 LEGAL-HOLD (fail-closed) : un hold actif ÉPINGLE les preuves de sa portée CONTRE toute suppression
    // (purge globale + per-index + plafonds). COUVERTURE (CRITICAL — corrigé) : le hold pince DÉSORMAIS les
    // TROIS classes de preuve NON-reconstructible :
    //   - `event`    : matché par (source ∈ portée) ∧ (ts ∈ fenêtre)  [LEGAL_HOLD_NOT_HELD] ;
    //   - `alert`    : texte d'alerte SYNTHÉTISÉ, pas de colonne `source` -> matché par la fenêtre `ts` d'un
    //                  hold à portée GLOBALE (scope_source='') UNIQUEMENT [legal_hold_not_held_global] ;
    //   - `snapshot` : capture d'ÉTAT forensique, pas de colonne `source` -> même règle globale que `alert`.
    // Autrement dit : un hold GLOBAL bloque event+alert+snapshot sur sa fenêtre ; un hold source-scopé ne
    // bloque que `event`. Mode 0 (aucun hold / table pré-v96) -> guard=RETENTION_NONPURGE EXACT pour `event` ET
    // littéraux snapshot/alert byte-identiques à l'historique. FailClosed (état des holds indéterminé alors que
    // la table existe) -> on S'ABSTIENT de purger event ET alert ET snapshot ce tick (jamais supprimer une
    // preuve dont on ne peut prouver qu'elle n'est pas retenue). Les agrégats reconstructibles (metric_rollup,
    // event_rollup/dim déjà purgés plus haut) NE sont PAS épinglés (non-preuve) et poursuivent toujours.
    // #18 P1.5 — HORIZON DU HARD-PURGE HOT de `event` (bande GLOBALE) ÉTENDU à `cold_ret` quand le tier cold
    // est ON (extension de rétention TOTALE). Sans cette réconciliation, le hard-purge à `now-retention_days`
    // supprimerait les lignes de la bande [retention_days, cold_ret] AVANT leur rétention effective = PERTE
    // PRÉMATURÉE. En régime normal l'aging draine le hot à hot_window (<< cold_ret) -> ce cutoff étendu n'est
    // qu'un FILET DE SÉCURITÉ pour les résidus in-ageables (defer H1 permanent). `cold_retention_days` est la
    // SOURCE UNIQUE partagée avec l'aging/expiry -> horizon jamais divergent. SHADOW cfg-gaté PLACÉ APRÈS les
    // purges de rollups (event_rollup/dim, agrégats hot NON archivés -> gardent l'horizon HISTORIQUE) et AVANT
    // la purge `event` -> SEULE la table `event` (données brutes archivées en cold) voit l'horizon étendu ; la
    // bande PER-INDEX (policies) reste inchangée (chaque index à policy purgé à SA fenêtre = eff_ret). DOUBLE
    // GATE : COMPILE (`cold_tier` — sans la feature ce shadow n'existe PAS -> `global_cutoff` INCHANGÉ -> BUILD
    // BYTE-IDENTIQUE) + RUNTIME (`PLUME_COLD_TIER` non posé OU knob non posé -> `cold_ret==ev` -> cutoff identique).
    #[cfg(feature = "cold_tier")]
    let global_cutoff = if cfg(&conf, "PLUME_COLD_TIER", "") == "1" {
        n - crate::cold_store::cold_retention_days(&conf, ev) * 86400
    } else {
        global_cutoff
    };
    // #18 size-caps #49 bypass sous COLD (NO-LOSS). Les plafonds count/byte (retention_apply_caps) suppriment
    // les PLUS VIEILLES lignes hot. Sous cold, l'aging a DÉJÀ columnarisé+supprimé les vieux jours ; les lignes
    // restées hot sont les RÉCENTES NON archivées (ts >= hot_cutoff) + stragglers deferred. Un plafond qui ne
    // garde que les N plus récentes supprimerait EXACTEMENT ces lignes non-archivées SANS copie cold -> PERTE
    // silencieuse, rompant la promesse de rétention cold. La taille hot est déjà bornée par l'aging (hot_window)
    // et l'empreinte totale par l'expiry cold (cold_ret) -> les plafonds NE DOIVENT PAS tourner sous cold.
    // DOUBLE GATE : COMPILE (`cold_tier` — sans la feature cette ligne + les gardes de boucle n'existent PAS ->
    // les deux boucles émettent verbatim -> BYTE-IDENTIQUE) + RUNTIME (`PLUME_COLD_TIER != "1"` -> caps_active
    // -> les plafonds tournent comme aujourd'hui). Rétention TEMPS per-index (retention_prune_table) et
    // hard-purge global INCHANGÉS — seuls les plafonds count/byte sont gatés.
    #[cfg(feature = "cold_tier")]
    let caps_active = cfg(&conf, "PLUME_COLD_TIER", "") != "1";
    let snap_cutoff = n - snap * 86400;
    let alert_cutoff = n - alert * 86400;
    let batch = retention_purge_batch();
    // #23 F3 — decision legal-hold lue en verrou COURT ; les purges qui suivent sont chunkées (verrou par-lot).
    let enforce = { let conn = db.lock(); legal_hold_enforcement(&conn) };
    match enforce {
        HoldEnforce::NoHolds => {
            retention_prune_table(db, "event", "ts", RETENTION_NONPURGE, global_cutoff, n, &policies);
            for p in &policies {
                #[cfg(feature = "cold_tier")]
                if !caps_active { continue; }
                let conn = db.lock();
                retention_apply_caps(&conn, p, RETENTION_NONPURGE);
            }
            // Même ENSEMBLE FINAL que les littéraux historiques (purge chunkée #23 F3 ; prédicats identiques).
            chunked_purge(db, "snapshot", "ts < ?1", &[&snap_cutoff], batch);
            chunked_purge(db, "alert", "status<>'new' AND ts < ?1", &[&alert_cutoff], batch);
        }
        HoldEnforce::Guard(pred) => {
            let guard = format!("{RETENTION_NONPURGE} AND {pred}");
            retention_prune_table(db, "event", "ts", &guard, global_cutoff, n, &policies);
            for p in &policies {
                #[cfg(feature = "cold_tier")]
                if !caps_active { continue; }
                let conn = db.lock();
                retention_apply_caps(&conn, p, &guard);
            }
            // alert/snapshot : SEUL un hold GLOBAL (scope_source='') les épingle (aucune colonne source).
            let sg = legal_hold_not_held_global("ts");
            chunked_purge(db, "snapshot", &format!("ts < ?1 AND {sg}"), &[&snap_cutoff], batch);
            chunked_purge(db, "alert", &format!("status<>'new' AND ts < ?1 AND {sg}"), &[&alert_cutoff], batch);
        }
        HoldEnforce::FailClosed => {
            eprintln!("[retention] legal-hold indéterminé (legal_hold illisible) -> purge de `event`+`alert`+`snapshot` SUSPENDUE ce tick (fail-closed) ; les agrégats reconstructibles (metric_rollup) poursuivent");
        }
    }
    chunked_purge(db, "metric_rollup", "ts < ?1", &[&(n - metric * 86400)], batch);
    // v105 (STEP 2) — signe le checkpoint si la clé est disponible ; sinon, sur un chemin Secret non-legacy
    // (clé absente/vide -> checkpoints NON signés, ex. Vault re-scellé), émet un signal SOC NON-PURGEABLE de
    // signature dégradée. DÉDUP HORAIRE (emit_ledger_health) -> 1 signal/heure malgré un tick retention_run
    // toutes les ~heures ET le signal de boot du même épisode -> pas de tempête. INERTE en régime normal
    // (chemin legacy on-PVC = clé auto-générée -> Some(k) -> signe comme avant, mode 0 byte-identique).
    // Verrou COURT (#23 F3) : ledger + checkpoint WAL sur un scope dédié.
    {
        let conn = db.lock();
        match ledger_key(&conf) {
            Some(k) => sign_checkpoint(&conn, &k),
            None => {
                let active = ledger_key_active_path(&conf);
                if !ledger_key_path_is_legacy(&active) {
                    let _ = emit_ledger_unsigned(&conn, n, &active);
                }
            }
        }
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
}
