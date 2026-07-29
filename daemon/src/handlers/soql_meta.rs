//! GXQL completion metadata (IDE-like autocomplete) — surfaces de LECTURE cheap/read-only pour la
//! complétion contextuelle de la barre Explore. 100 % natif : vocabulaire grammatical STATIQUE (consts
//! du cœur `guatx_core::soql`, source unique de vérité du compilateur fermé), champs CIM, valeurs
//! connues BORNÉES (enums CIM + `source` distinct du rollup pré-agrégé — JAMAIS un scan `event`), et une
//! bibliothèque de gabarits embarquée. Aucun LLM/modèle, aucun appel externe, aucune donnée sensible :
//! l'endpoint ne renvoie que des NOMS de champs, des valeurs d'ENUM fermées et des noms de source (déjà
//! affichés dans l'inventaire Sources). Auth : viewer+ (route_min_role -> Read, cf. section 6 rbac).
//!
//! INVARIANT « complétion ⊆ ce qui compile » : le vocabulaire (commandes/fonctions/opérateurs) provient
//! des consts `SOQL_*` du cœur que le compilateur RÉFÉRENCE/ACCEPTE (test `completion_vocab_*`), donc la
//! complétion ne peut JAMAIS suggérer un token que `to_sql` rejetterait.
use crate::*;
use guatx_core::soql::{
    to_sql, Schema, HOT_FIELDS, SOQL_BASE_KEYWORDS, SOQL_EVAL_FUNCTIONS, SOQL_FILTER_OPERATORS,
    SOQL_KEYWORDS, SOQL_PIPE_COMMANDS, SOQL_STATS_FUNCTIONS,
};

/// Bibliothèque de gabarits GXQL EMBARQUÉE (`include_str!` -> zéro I/O au runtime, servie verbatim).
/// La source vit dans `plume/docs/soql-templates/` : le Dockerfile la COPIE dans le contexte de build
/// AVANT `cargo build` (cf. `COPY plume/docs/soql-templates` — gotcha include_str-hors-daemon). Chaque
/// `soql` est prouvé compilable par le test `soql_templates_all_compile` -> un gabarit invalide casse la CI.
const SOQL_TEMPLATES_JSON: &str = include_str!("../../../docs/soql-templates/templates.json");

// =====================================================================================================
// v130 — DOCUMENTATION INLINE (feature 2) + LIVE VALIDATION (feature 1).
// =====================================================================================================

/// Longueur MAX du GXQL accepté par `/api/soql/validate`. Borne défensive anti-abus : la compilation est en
/// µs et le client débounce, mais on refuse un corps déraisonnable AVANT tout traitement (miroir des caps de
/// message 8 Kio du daemon ; le compilateur borne de toute façon en interne). Au-delà -> `valid:false` +
/// message, ZÉRO compilation. Le chemin réel `/api/query` n'a pas de cap dur sur la chaîne GXQL -> on en pose
/// un sain ici puisque c'est un endpoint appelé à chaque frappe.
pub(crate) const SOQL_VALIDATE_MAX_LEN: usize = 8192;

/// DOC INLINE de la complétion — 100 % STATIQUE et curée : une description d'UNE LIGNE par item de
/// vocabulaire, servie via `/api/soql/schema` (clé `docs`). AUCUNE donnée (ce sont des libellés d'aide fixes,
/// pas une lecture). Le test `soql_docs_cover_all_vocab` EXIGE une description NON VIDE pour CHAQUE token des
/// consts `SOQL_*` -> la doc ne peut PAS omettre silencieusement un token, ni dériver quand la grammaire évolue.
pub(crate) const DOC_BASE_KEYWORDS: &[(&str, &str)] = &[
    ("search", "Commande de base : sélectionne les événements bruts, filtrables par champ<op>valeur."),
    ("metric", "Commande de base : interroge les séries de métriques (observabilité)."),
];

/// Descriptions des commandes de pipe (miroir 1:1 de `SOQL_PIPE_COMMANDS`).
pub(crate) const DOC_COMMANDS: &[(&str, &str)] = &[
    ("stats", "Agrège les événements : mesures (count/sum/avg…) éventuellement groupées par champ (by)."),
    ("timechart", "Série temporelle : agrège une mesure par intervalle (span=), éventuellement par champ."),
    ("where", "Filtre les résultats sur une condition (comparaisons, and/or) après un pipe."),
    ("sort", "Trie les résultats par un ou plusieurs champs (préfixe - pour décroissant)."),
    ("head", "Ne conserve que les N premiers résultats."),
    ("limit", "Borne le nombre de résultats retournés."),
    ("rex", "Extrait des champs d'un texte via une regex à groupes nommés (?<nom>…)."),
    ("fields", "Restreint les colonnes retournées à la liste donnée."),
    ("table", "Affiche les résultats en table pour les champs listés."),
    ("rename", "Renomme un champ (champ as alias)."),
    ("dedup", "Supprime les doublons en gardant le premier événement par champ(s)."),
    ("top", "Valeurs les plus fréquentes d'un champ (compte + pourcentage)."),
    ("rare", "Valeurs les moins fréquentes d'un champ."),
    ("eventstats", "Comme stats mais rattache l'agrégat à chaque événement (ne réduit pas les lignes)."),
    ("rate", "Calcule un taux (événements par unité de temps)."),
    ("eval", "Crée ou dérive un champ à partir d'une expression (fonctions, arithmétique)."),
    ("append", "Ajoute les résultats d'une sous-recherche [search …] à la fin du flux."),
    ("join", "Joint le flux à une sous-recherche [search …] sur un champ commun."),
    ("mvexpand", "Éclate un champ multi-valué en une ligne par valeur."),
    ("lookup", "Enrichit les événements via une table de correspondance (reftable … OUTPUT …)."),
];

/// Descriptions des fonctions d'agrégation stats (miroir 1:1 de `SOQL_STATS_FUNCTIONS`).
pub(crate) const DOC_STATS_FUNCTIONS: &[(&str, &str)] = &[
    ("count", "Nombre d'événements (ou d'occurrences par groupe)."),
    ("sum", "Somme des valeurs d'un champ numérique."),
    ("avg", "Moyenne des valeurs d'un champ numérique."),
    ("min", "Valeur minimale d'un champ."),
    ("max", "Valeur maximale d'un champ."),
    ("dc", "Compte de valeurs DISTINCTES d'un champ (cardinalité)."),
    ("values", "Liste triée des valeurs distinctes d'un champ."),
    ("list", "Liste des valeurs d'un champ (ordre d'apparition, doublons conservés)."),
];

/// Descriptions des fonctions d'eval (miroir 1:1 de `SOQL_EVAL_FUNCTIONS`).
pub(crate) const DOC_EVAL_FUNCTIONS: &[(&str, &str)] = &[
    ("if", "if(cond, a, b) : renvoie a si la condition est vraie, sinon b."),
    ("coalesce", "Premier argument non nul parmi ceux fournis."),
    ("ifnull", "ifnull(x, y) : renvoie x s'il n'est pas nul, sinon y."),
    ("nullif", "nullif(a, b) : renvoie nul si a égale b, sinon a."),
    ("lower", "Convertit un texte en minuscules."),
    ("upper", "Convertit un texte en majuscules."),
    ("length", "Longueur (nombre de caractères) d'un texte."),
    ("len", "Longueur d'un texte (alias de length)."),
    ("abs", "Valeur absolue d'un nombre."),
    ("round", "Arrondit un nombre (round(x[, décimales]))."),
    ("min", "Plus petite valeur parmi les arguments."),
    ("max", "Plus grande valeur parmi les arguments."),
    ("substr", "Sous-chaîne : substr(texte, début[, longueur])."),
    ("replace", "Remplace des occurrences : replace(texte, motif, remplacement)."),
    ("trim", "Supprime les espaces en début et fin de texte."),
];

/// Descriptions des opérateurs de filtre (miroir 1:1 de `SOQL_FILTER_OPERATORS`).
pub(crate) const DOC_OPERATORS: &[(&str, &str)] = &[
    ("=", "Égalité (texte : correspondance ; * = glob)."),
    ("!=", "Différent de."),
    (">", "Strictement supérieur (comparaison numérique)."),
    (">=", "Supérieur ou égal."),
    ("<", "Strictement inférieur."),
    ("<=", "Inférieur ou égal."),
    (":", "Égalité (alias de =)."),
    ("=~", "Correspondance par expression régulière (REGEXP)."),
];

/// Descriptions des mots-clés structurants (miroir 1:1 de `SOQL_KEYWORDS`).
pub(crate) const DOC_KEYWORDS: &[(&str, &str)] = &[
    ("by", "Clause de regroupement des agrégats (stats/timechart … by champ)."),
    ("span=", "Taille de l'intervalle temporel d'un timechart (ex : span=5m)."),
    ("as", "Renomme/aliase un champ (rename champ as alias)."),
    ("OUTPUT", "Sélectionne les colonnes ramenées par un lookup."),
];

/// Descriptions des champs CŒUR CIM (`CIM_CORE_FIELDS`) — aide, jamais une donnée d'event.
pub(crate) const DOC_FIELDS: &[(&str, &str)] = &[
    ("ts", "Horodatage de l'événement (epoch)."),
    ("source", "Source/collecteur d'origine de l'événement."),
    ("category", "Catégorie CIM normalisée (firewall, auth, dns…)."),
    ("severity", "Sévérité 0=info … 4=critical."),
    ("message", "Message brut/normalisé de l'événement."),
    ("host", "Hôte associé à l'événement."),
    ("src_ip", "Adresse IP source."),
    ("dst_ip", "Adresse IP destination."),
    ("url", "URL associée (web/proxy)."),
    ("dedup", "Clé de déduplication de l'événement."),
    ("fields", "Sac JSON des champs étendus (non promus)."),
    ("engagement_id", "Identifiant d'engagement (mode pentest), vide sinon."),
    ("origin", "Origine/pipeline d'ingestion."),
    ("env_id", "Identifiant d'environnement (axe intra-tenant)."),
];

/// Description d'un `token` dans une table de doc (comparaison exacte). None si absent. Accessseur de TEST
/// (la coverage `soql_docs_cover_all_vocab` s'en sert) — `#[cfg(test)]` comme `soql_template_queries`.
#[cfg(test)]
pub(crate) fn doc_desc(table: &[(&'static str, &'static str)], token: &str) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == token).map(|(_, v)| *v)
}

/// Objet JSON `{token: description}` à partir d'une table de doc (servi tel quel dans `/api/soql/schema`).
fn docs_object(table: &[(&str, &str)]) -> Value {
    Value::Object(table.iter().map(|(k, v)| ((*k).to_string(), json!(v))).collect())
}

/// SWR cache des `source` connues, keyé par db_path (comme FRESHNESS_CACHE). Valeur = (calculé, liste).
/// TTL long : l'inventaire des sources change lentement ; la lecture est de toute façon BORNÉE (rollup).
fn known_sources_cache() -> &'static Mutex<HashMap<String, (Instant, Vec<String>)>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Vec<String>)>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}
const KNOWN_SOURCES_TTL: Duration = Duration::from_secs(120);

/// Valeurs `source` CONNUES, depuis la table DÉRIVÉE `event_rollup` (pré-agrégée, petite) — JAMAIS un
/// scan de `event` (respecte « jamais scanner event par requête »). Fonction PURE testable : si le rollup
/// est illisible/absent, renvoie vide (jamais un repli qui scannerait `event`). Bornée à 500 entrées.
pub(crate) fn soql_known_sources(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(mut s) = conn.prepare("SELECT DISTINCT source FROM event_rollup WHERE source<>'' ORDER BY source LIMIT 500") {
        if let Ok(rows) = s.query_map([], |r| r.get::<_, String>(0)) {
            for src in rows.flatten() {
                out.push(src);
            }
        }
    }
    out
}

/// `source` connues avec cache SWR borné (lecture rollup ~ms via read_with_watchdog). Ne bloque jamais
/// longtemps : la requête est sur la petite table rollup. Le cache évite de la refaire à chaque frappe.
fn cached_known_sources(db_path: &str) -> Vec<String> {
    if let Some((t, v)) = known_sources_cache().lock().get(db_path) {
        if t.elapsed() < KNOWN_SOURCES_TTL {
            return v.clone();
        }
    }
    let sources = read_with_watchdog(db_path, Vec::new(), |conn| soql_known_sources(conn));
    known_sources_cache()
        .lock()
        .insert(db_path.to_string(), (Instant::now(), sources.clone()));
    sources
}

/// GET /api/soql/schema — vocabulaire de complétion (commandes/fonctions/opérateurs/mots-clés issus des
/// consts du cœur), liste des CHAMPS (CIM core + champs étendus chauds) et VALEURS connues bornées
/// (category/severity/action = enums fermés ; source = rollup distinct caché). Read-only, viewer+.
pub(crate) async fn soql_schema(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db_path = req_db_path(&st, &au);
    let sources = cached_known_sources(db_path.as_str());
    // Niveaux de sévérité : enum statique 0..4 (miroir du SEV front ['info','low','medium','high','critical']).
    let severities: Vec<Value> = [
        (0, "info"), (1, "low"), (2, "medium"), (3, "high"), (4, "critical"),
    ]
    .iter()
    .map(|(n, label)| json!({ "value": n, "label": label }))
    .collect();
    Json(json!({
        "base_keywords": SOQL_BASE_KEYWORDS,
        "commands": SOQL_PIPE_COMMANDS,
        "stats_functions": SOQL_STATS_FUNCTIONS,
        "eval_functions": SOQL_EVAL_FUNCTIONS,
        "operators": SOQL_FILTER_OPERATORS,
        "keywords": SOQL_KEYWORDS,
        "fields": {
            // Champs CŒUR CIM (colonnes promues, filtrables directement) + champs ÉTENDUS chauds (clés
            // du sac JSON `fields`, couramment filtrées). NOMS uniquement — aucune donnée d'event.
            "core": CIM_CORE_FIELDS,
            "extended": HOT_FIELDS,
        },
        "values": {
            // Enums FERMÉS (statiques) — jamais une lecture de données.
            "category": CIM_CATEGORIES,
            "action": CIM_ACTION_VOCAB,
            "severity": severities,
            // Valeurs BORNÉES depuis le rollup (jamais un scan `event`) — noms de source déjà exposés
            // dans l'inventaire Sources (cohérent, non sensible).
            "source": sources,
        },
        // v130 DOC INLINE : description d'UNE LIGNE par item de vocabulaire (statique, curée). Le client
        // peuple le slot d'aide de la complétion. Coverage garanti par `soql_docs_cover_all_vocab`.
        "docs": {
            "base_keywords": docs_object(DOC_BASE_KEYWORDS),
            "commands": docs_object(DOC_COMMANDS),
            "stats_functions": docs_object(DOC_STATS_FUNCTIONS),
            "eval_functions": docs_object(DOC_EVAL_FUNCTIONS),
            "operators": docs_object(DOC_OPERATORS),
            "keywords": docs_object(DOC_KEYWORDS),
            "fields": docs_object(DOC_FIELDS),
        },
        "cim_version": CIM_VERSION,
    }))
}

/// POST /api/soql/validate — VALIDATION « compile-as-you-type » : compile le GXQL fourni via le compilateur
/// FERMÉ `guatx_core::soql::to_sql` (le MÊME dont le chemin GXQL de `/api/query` est ⊆) et renvoie
/// `{valid: bool, error?: string}`. Read-only, viewer+ (`is_readonly_post` -> mutating=false -> route_min_role
/// Read). 100 % natif (aucun modèle, aucun appel externe).
///
/// SÛRETÉ ABSOLUE — COMPILE SEULEMENT, ZÉRO EXÉCUTION : ce handler n'a PHYSIQUEMENT aucun chemin d'exécution.
/// Il ne prend AUCUN `State<AppState>`, n'ouvre AUCUN handle de base (`req_db_path`/`read_with_watchdog`
/// absents), ne lance AUCUN SQL, ne scanne AUCUN `event`. Il n'appelle QUE `to_sql` — qui RETOURNE une chaîne
/// SQL sans jamais l'exécuter — et JETTE le résultat (`Ok(_sql)`), ne renvoyant que le booléen de validité.
/// `from`/`to`=0 (comme les autres call-sites de validation : knowledge.rs, datamodels.rs) -> pas de filtre
/// temporel, compilation pure. Le test `validate_compiles_only_never_executes` prouve l'absence d'effet de bord.
pub(crate) async fn soql_validate(Json(body): Json<Value>) -> Json<Value> {
    let soql = body.get("soql").and_then(|v| v.as_str()).unwrap_or("").trim();
    if soql.is_empty() {
        return Json(json!({ "valid": false, "error": "requête vide" }));
    }
    // Borne défensive AVANT tout traitement (anti-abus) — jamais de compilation d'un corps déraisonnable.
    if soql.chars().count() > SOQL_VALIDATE_MAX_LEN {
        return Json(json!({
            "valid": false,
            "error": format!("requête trop longue (max {SOQL_VALIDATE_MAX_LEN} caractères)")
        }));
    }
    // COMPILE UNIQUEMENT : `to_sql` retourne le SQL (String) — on ne l'exécute JAMAIS, on ne garde que Ok/Err.
    match to_sql(soql, 0, 0, &Schema::events()) {
        Ok(_sql) => Json(json!({ "valid": true })),
        Err(e) => Json(json!({ "valid": false, "error": e })),
    }
}

/// GET /api/soql/templates — bibliothèque de gabarits GXQL curée (snippet palette). Servie depuis le JSON
/// embarqué (verbatim). Read-only, viewer+. Chaque `soql` est prouvé compilable (test dédié).
pub(crate) async fn soql_templates() -> Response {
    // Servie telle quelle (déjà du JSON valide, validé au build par le test de compilation des gabarits).
    (
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        SOQL_TEMPLATES_JSON,
    )
        .into_response()
}

/// Accès aux gabarits parsés (pour le test de compilation). Renvoie la liste des `soql` de chaque gabarit.
#[cfg(test)]
pub(crate) fn soql_template_queries() -> Vec<(String, String)> {
    let v: Value = serde_json::from_str(SOQL_TEMPLATES_JSON).expect("templates.json est un JSON valide");
    v.get("templates")
        .and_then(|t| t.as_array())
        .expect("templates.json a un tableau `templates`")
        .iter()
        .map(|t| {
            (
                t.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                t.get("soql").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            )
        })
        .collect()
}
