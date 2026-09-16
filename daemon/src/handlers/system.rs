//! DAY-2 OPS (#51) — CONSOLE D'OPÉRABILITÉ. Endpoints d'infra standard + self-métriques + santé par
//! composant + bundle de diagnostic + bulletin/MOTD.
//!  - `/healthz`  : LIVENESS (200 si le process sert) — UNAUTH (sonde k8s), aucune donnée sensible.
//!  - `/readyz`   : READINESS (DB ouvrable + migrations faites + port bindé) — UNAUTH.
//!  - `/metrics`  : exposition Prometheus texte — jeton de scrape (Bearer PLUME_METRICS_TOKEN) OU viewer+
//!    (gaté dans auth_guard) ; JAMAIS anonyme au monde (les compteurs fuient des volumes).
//!  - `/api/system/metrics` : self-métriques JSON (panneau UI « Système ») — viewer+.
//!  - `/api/system/health`  : santé R/J/V par composant — viewer+.
//!  - `/api/system/diag`    : bundle de diagnostic NON-SECRET (support hand-off) — ADMIN-ONLY, allowlist.
//!  - `/api/bulletin`       : MOTD/bandeau diffusé à tous — GET viewer+, POST/DELETE admin (setting row).
//! ADDITIF : aucun bulletin posé -> aucun bandeau ; aucune écriture DB en lecture -> mode 0 byte-identique.
use crate::*;
use rusqlite::OptionalExtension;

/// `P10.20-b` — LA CLÉ SOUS LAQUELLE UNE VERSION DE SCHÉMA NON ÉTABLIE S'AVOUE, la MÊME sur les quatre
/// surfaces qui la servent (sonde de vivacité, exposition Prometheus, écran Système, paquet de
/// diagnostic). Elle NOMME ce dont elle parle, indépendamment de la clé locale qui porte la valeur
/// (`schema` pour la sonde, `schema_version` pour les trois autres). ABSENTE du chemin nominal : un
/// aveu qui serait toujours là n'avouerait rien.
pub(crate) const CLE_VERSION_DE_SCHEMA_NON_ETABLIE: &str = "schema_version_non_etablie";

/// `P10.20-b` — L'OUVERTURE DE L'AVEU, commune aux trois causes distinguées ci-dessous.
pub(crate) const CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE: &str = "VERSION DE SCHÉMA NON ÉTABLIE : \
     `meta.schema_version` n'a pas rendu de version exploitable. Ce n'est PAS « version 1 » — une base \
     dont la table `meta` est illisible n'a pas la version un, elle n'en a AUCUNE d'établie.";

/// `P10.20-b` — LA VERSION DE SCHÉMA TELLE QU'ELLE A ÉTÉ OBTENUE, sur le modèle de
/// [`liste_bornee::TotalBorne`] : `Lue(v)` est un FAIT, `NonEtablie(cause)` n'en est pas un et porte
/// POURQUOI.
///
/// LE DÉFAUT QUE CE TYPE REND NON-ÉCRIVABLE. La lecture retombait sur `1` — un `unwrap_or(1)` justifié
/// en commentaire par « base neuve avant migrate, ne devrait pas arriver ». Ce repli couvrait TROIS
/// situations que rien ne séparait : la base neuve (aucune ligne), la valeur illisible, et la table
/// `meta` hors d'atteinte. Le `1` partait ensuite tel quel dans `/healthz` (UNAUTH, sonde k8s), dans
/// `plume_build_info{schema="1"}` (Prometheus, donc dans les tableaux de bord et les alertes de
/// l'exploitant), dans l'écran Système de la console et dans le paquet de diagnostic remis au
/// support — quatre surfaces qui affirmaient une version de schéma que personne n'avait lue, et la
/// seule version qu'un opérateur n'a AUCUNE chance de reconnaître comme fausse, puisque c'est celle
/// d'une base fraîche.
///
/// LES TROIS CAUSES SONT DISTINGUÉES À L'ÉCRIT et se confondent à l'AFFICHAGE, délibérément : ce
/// qu'une surface sert est `null` dans les trois cas — rien n'est établi — et la phrase dit laquelle.
pub(crate) enum VersionDeSchema {
    Lue(i64),
    NonEtablie(String),
}

impl VersionDeSchema {
    /// LA VALEUR SERVIE : le nombre LU, ou `null`. Jamais un repli qui a la forme d'une version.
    pub(crate) fn en_json(&self) -> Value {
        match self {
            VersionDeSchema::Lue(v) => json!(v),
            VersionDeSchema::NonEtablie(_) => Value::Null,
        }
    }

    /// L'ÉTIQUETTE PROMETHEUS de `plume_build_info` : le nombre, ou un mot qu'aucune version ne peut
    /// prendre. Une étiquette est une CHAÎNE pour Prometheus — `schema="non_etablie"` ne casse ni le
    /// type de la jauge ni son ingestion, et une règle qui comparait `schema` à un numéro cesse de
    /// matcher au lieu de matcher le mauvais.
    pub(crate) fn etiquette_prometheus(&self) -> String {
        match self {
            VersionDeSchema::Lue(v) => v.to_string(),
            VersionDeSchema::NonEtablie(_) => "non_etablie".to_string(),
        }
    }

    /// POSE L'AVEU dans un corps déjà construit, et RIEN quand la version a été lue — la forme du
    /// dépôt (`liste_bornee::corps_de_listes_illisibles`) : sur le chemin nominal le corps ressort
    /// byte-identique, donc un aveu inconditionnel est structurellement impossible.
    pub(crate) fn poser_l_aveu(&self, corps: &mut serde_json::Map<String, Value>) {
        if let VersionDeSchema::NonEtablie(cause) = self {
            corps.insert(CLE_VERSION_DE_SCHEMA_NON_ETABLIE.to_string(), json!(cause));
        }
    }
}

/// Version de schéma courante (meta) — lecture O(1). `NonEtablie` dès que la lecture ne rend pas un
/// entier : aucune ligne (base neuve avant `migrate`), valeur non entière, ou lecture NON FAITE.
pub(crate) fn schema_version(conn: &Connection) -> VersionDeSchema {
    match conn
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
        .optional()
    {
        Ok(Some(brut)) => match brut.parse::<i64>() {
            Ok(v) => VersionDeSchema::Lue(v),
            Err(_) => VersionDeSchema::NonEtablie(format!(
                "{CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE} La ligne existe mais ne porte pas un entier."
            )),
        },
        Ok(None) => VersionDeSchema::NonEtablie(format!(
            "{CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE} Aucune ligne `meta.schema_version` : cette base n'a \
             pas encore été estampillée par une migration."
        )),
        Err(e) => VersionDeSchema::NonEtablie(format!(
            "{CAUSE_VERSION_DE_SCHEMA_NON_ETABLIE} La lecture a échoué : {e}."
        )),
    }
}

/// LIVENESS — 200 tant que le process sert. UNAUTH (bypass host_guard + auth_guard). Ne révèle QUE
/// ok/version/schema (aucun compte, aucun volume). k8s : `livenessProbe.httpGet { path: /healthz }`.
pub(crate) async fn healthz(State(st): State<AppState>) -> Response {
    let schema = { let c = st.db.lock(); schema_version(&c) };
    // `P10.20-b` — `schema` porte la version LUE ou `null`, et l'aveu NOMMÉ n'apparaît que dans le second
    // cas. LE STATUT NE BOUGE PAS, ET C'EST UNE DÉCISION : cette sonde est la LIVENESS, celle dont un 503
    // fait TUER puis redémarrer le pod. Un redémarrage ne rend pas `meta` lisible — il remettrait le démon
    // en boucle de crash pour une ligne de métadonnée que le chemin chaud ne lit jamais. La sonde dit donc
    // ce qu'elle sait (« le process sert ») et avoue ce qu'elle ignore, au lieu de servir un « 1 » inventé.
    let mut corps = serde_json::Map::new();
    corps.insert("ok".to_string(), json!(true));
    corps.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));
    corps.insert("schema".to_string(), schema.en_json());
    schema.poser_l_aveu(&mut corps);
    (StatusCode::OK, Json(Value::Object(corps))).into_response()
}

/// READINESS — 200 si (migrations faites + port bindé = flag READY) ET la base est ouvrable (SELECT 1).
/// Sinon 503 (le pod est retiré du service jusqu'à ce qu'il soit prêt). UNAUTH. k8s : `readinessProbe`.
///
/// `P10.20-b` — CETTE SONDE NE LIT PAS LA VERSION DE SCHÉMA, ET C'EST UNE DÉCISION ÉCRITE, PAS UN OUBLI.
/// La question posée était : une version de schéma NON LUE doit-elle rendre la sonde NON PRÊTE ? Non,
/// pour deux raisons mesurables sur ce code-ci.
///   (1) LA PRÉMISSE EST ÉTABLIE AILLEURS, ET PLUS TÔT. « Migrations faites » n'est pas re-dérivé à
///       chaque sonde : `READY` n'est posé qu'APRÈS `open_and_migrate_db`, dont la garde anti-downgrade
///       REFUSE d'ouvrir une base plus récente que le binaire. Relire `meta` à chaque sonde ne
///       revérifierait pas cette garde — elle a déjà statué — mais ajouterait une lecture sur un chemin
///       appelé toutes les quelques secondes.
///   (2) LE PRIX D'UN 503 ICI N'EST PAS UN AVEU, C'EST UN RETRAIT DE SERVICE. Un `readyz` rouge sort le
///       pod du Service : l'ingest s'arrête et les recherches ne sont plus servies. Aveugler la collecte
///       d'un SOC parce qu'une ligne de métadonnée ne se lit plus est le compromis exactement inverse de
///       celui que ce dépôt tient ailleurs (`P10.17-a` : « la base d'un SOC ne doit pas geler pour une
///       troncature refusée — on rapporte »).
/// CE QUE CETTE DÉCISION NE TIENT PAS, ET IL FAUT LE LIRE : `SELECT 1` ne touche AUCUNE table, donc il
/// reste vert sur une base dont les tables sont devenues illisibles. La version non établie est alors
/// avouée par `/healthz`, `/metrics` et l'écran Système — pas par cette sonde-ci.
pub(crate) async fn readyz(State(st): State<AppState>) -> Response {
    let ready_flag = crate::READY.load(std::sync::atomic::Ordering::Relaxed);
    // DB ouvrable MAINTENANT (pas seulement au boot) : un SELECT 1 sur le writer (cheap). Lock indisponible
    // (writer occupé, ex. ANALYZE) -> on considère la DB vivante (ne pas sortir du service pour une écriture
    // en cours) : la readiness reflète « prêt à servir », pas « writer libre ».
    // parking_lot `try_lock` renvoie Option (pas de poison) : Some=libre, None=occupé (WouldBlock) -> vivant.
    let db_ok = match st.db.try_lock() {
        Some(c) => c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).map(|v| v == 1).unwrap_or(false),
        None => true,
    };
    let ready = ready_flag && db_ok;
    let code = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (code, Json(json!({ "ready": ready, "bound": ready_flag, "db": db_ok, "version": env!("CARGO_PKG_VERSION") }))).into_response()
}

/// Seuil % d'usage disque pour la santé « store » — même clé que le garde-fou d'ingest (#29), défaut 80.
fn disk_warn_pct() -> u8 {
    cfg(&load_config(), "PLUME_DISK_WARN_PCT", "80").parse().unwrap_or(80)
}

/// EXPOSITION PROMETHEUS (texte). Auth déjà appliquée en amont (auth_guard : jeton de scrape OU viewer+).
/// Lit la base OPÉRATEUR (host-wide) — les self-métriques sont process-globales, pas tenant. Reads petits/
/// indexés (rollup SUM, MAX(ts) indexé, COUNT status) -> lock writer bref, jamais un scan de `event`.
pub(crate) async fn metrics_endpoint(State(st): State<AppState>) -> Response {
    let spool = st.spool.as_str().to_string();
    let db_path = st.db_path.as_ref().clone();
    let warn = disk_warn_pct();
    let body = {
        let c = st.db.lock();
        let sv = schema_version(&c);
        crate::gather_prom(&c, &spool, &db_path, &sv, warn)
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// SELF-MÉTRIQUES JSON (panneau UI « Système »). viewer+. Base du tenant courant (req_db).
pub(crate) async fn system_metrics(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let c = db.lock();
    let sv = schema_version(&c);
    Json(crate::gather_json(&c, &spool, &db_path, &sv, warn))
}

/// SANTÉ PAR COMPOSANT (R/J/V) + posture globale. viewer+. Base du tenant courant.
pub(crate) async fn system_health(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let c = db.lock();
    let components = crate::component_health(&c, &spool, &db_path, warn);
    let posture = crate::worst_state(&components);
    Json(json!({ "ts": now(), "posture": posture, "components": components }))
}

// ---------- BUNDLE DE DIAGNOSTIC (admin-only, allowlist NON-SECRET) ----------
/// Clés de config SÛRES à exposer dans le bundle (drapeaux opérationnels, JAMAIS un secret/clé/mot de passe).
/// Allowlist EXPLICITE : tout ce qui n'est pas listé est absent. Garde-fou supplémentaire `key_is_secretish`.
const DIAG_CONFIG_KEYS: &[&str] = &[
    "PLUME_MULTI_TENANT", "PLUME_ADDR", "PLUME_HOST", "PLUME_HOST_STRICT", "PLUME_PUBLIC_DEMO",
    "PLUME_RETENTION_DAYS", "PLUME_ROLLUP_INTERVAL_S", "PLUME_PANEL_REFRESH_S", "PLUME_QUERY_CONCURRENCY",
    "PLUME_PANEL_REFRESH_CONCURRENCY", "PLUME_SEARCH_LIMIT", "PLUME_SEARCH_MAX", "PLUME_FTS_FIELDS",
    "PLUME_EXPRINDEX", "PLUME_INGEST_MIN_FREE_MB", "PLUME_INGEST_MAX_EVENTS",
    "PLUME_DISK_WARN_PCT", "PLUME_RL_IP_MAX", "PLUME_RL_AUTH_MAX",
    "PLUME_RL_GLOBAL_MAX", "PLUME_AUTH_LOCK_THRESHOLD", "PLUME_SESSION_TTL_S", "PLUME_GENERIC_EXTRACT",
    "PLUME_TLS_CERT", "PLUME_TLS_KEY", "PLUME_ENGAGEMENT_MODE",
];

/// Une clé de config a-t-elle une APPARENCE de secret ? Belt-and-suspenders : même si l'allowlist ne contient
/// que des clés sûres, on refuse d'émettre toute clé dont le nom évoque un secret (défense en profondeur).
pub(crate) fn key_is_secretish(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    ["KEY", "SECRET", "PASS", "TOKEN", "HASH", "CRED", "PRIVATE"].iter().any(|m| u.contains(m))
}

/// CONSTRUIT le bundle de diagnostic (fonction PURE testable) : schéma, résumé de config (drapeaux
/// non-secrets), self-métriques, santé, échantillon d'events opérationnels NON-PII, comptes agrégés.
/// N'exécute QUE des SELECT sur un ALLOWLIST de tables/colonnes -> ne peut PAS lire user.hash / token.* /
/// *.config / *.secret / user_mfa.* (les colonnes de la denylist query_exec) ni de PII (username/src_ip).
/// Bornes des trois listes du paquet de diagnostic (`P11.22-g`) : nommées, rendues à côté de chaque liste
/// (`<cle>_served`, `<cle>_window`, `<cle>_truncated`), lues avec leur ligne excédentaire. Un diagnostic
/// coupé se lit comme coupé, plus comme complet.
pub(crate) const DIAG_RECENT_EVENTS_WINDOW: i64 = 30;
pub(crate) const DIAG_HEARTBEAT_ALERTS_WINDOW: i64 = 20;
pub(crate) const DIAG_UNCLASSIFIED_SOURCES_WINDOW: i64 = 20;
pub(crate) fn diag_bundle_json(conn: &Connection, spool: &str, db_path: &str, warn: u8) -> Value {
    use crate::handlers::liste_bornee as aveu;
    let sv = schema_version(conn);
    // Résumé de config : allowlist + garde secretish. Valeur "" pour une clé non posée. Les chemins TLS_CERT/
    // KEY sont des CHEMINS de fichier (pas la clé elle-même) -> sûrs ; mais on émet juste "posé"/"" (booléen)
    // pour ne rien divulguer d'un chemin. TOKEN/PASS/KEY sont exclus par key_is_secretish de toute façon.
    let mut cfgmap = serde_json::Map::new();
    let conf = load_config();
    for k in DIAG_CONFIG_KEYS {
        if key_is_secretish(k) {
            // n'expose QUE la présence (posé/absent), jamais la valeur.
            let present = !cfg(&conf, k, "").trim().is_empty();
            cfgmap.insert((*k).to_string(), json!(if present { "set" } else { "" }));
            continue;
        }
        cfgmap.insert((*k).to_string(), json!(cfg(&conf, k, "")));
    }
    // `P10.7-g` — AUCUNE DES QUATRE LECTURES CI-DESSOUS NE COULE UN ÉCHEC DANS UN FAIT. Avant, les trois
    // listes s'aplatissaient par `.flatten()` et les comptes repliaient sur `unwrap_or(0)` : une préparation
    // ou une exécution ratée posait `[]` ou `0` — indiscernable d'un vrai vide, servi comme un fait dans un
    // bundle de support. Désormais chaque liste est lue par un `Result` (collect en BLOC) et posée par la
    // sœur `poser_la_sous_liste_ou_avouer`, qui avoue `non_lu` au lieu de `[]` ; chaque compte rend `null` +
    // son nom sur une lecture ratée. Tout ce qui n'a pas été lu rejoint `non_lus`, que le corps porte ensuite.
    let mut non_lus: Vec<&'static str> = Vec::new();
    // Events opérationnels self (NON-PII) : santé disque + changements de config audités (source plume-config/
    // plume-disk, jamais plume-auth/plume-operator-access qui portent username/src_ip). Derniers 30.
    let recent: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT ts, source, severity, message FROM event \
             WHERE source IN ('plume-disk','plume-config') ORDER BY ts DESC LIMIT ?1",
        )
        .and_then(|mut s| {
            s.query_map(params![aveu::borne_avec_ligne_excedentaire(DIAG_RECENT_EVENTS_WINDOW)], |r| {
                Ok(json!({ "ts": r.get::<_, i64>(0)?, "source": r.get::<_, String>(1)?, "severity": r.get::<_, i64>(2)?, "message": r.get::<_, String>(3)? }))
            })
            .and_then(|it| it.collect())
        });
    // Alertes heartbeat (capteur muet) ouvertes — signal d'angle mort, NON-PII (rule=heartbeat.<id>).
    let heartbeats: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT ts, rule, title FROM alert WHERE rule LIKE 'heartbeat.%' AND status IN ('new','ack') ORDER BY ts DESC LIMIT ?1",
        )
        .and_then(|mut s| {
            s.query_map(params![aveu::borne_avec_ligne_excedentaire(DIAG_HEARTBEAT_ALERTS_WINDOW)], |r| {
                Ok(json!({ "ts": r.get::<_, i64>(0)?, "rule": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)? }))
            })
            .and_then(|it| it.collect())
        });
    // Comptes AGRÉGÉS (des NOMBRES, jamais des lignes) — donnent l'échelle sans exposer de contenu. Un compte
    // qui n'aboutit pas est `null` (jamais 0) et son nom rejoint `non_lus` : un zéro rassurant n'est pas servi.
    let mut compte = |nom: &'static str, sql: &str| -> Value {
        match conn.query_row(sql, [], |r| r.get::<_, i64>(0)) {
            Ok(n) => json!(n),
            Err(_) => {
                non_lus.push(nom);
                Value::Null
            }
        }
    };
    let counts = json!({
        "rules_enabled": compte("rules_enabled", "SELECT COUNT(*) FROM rule WHERE enabled=1"),
        "rules_total": compte("rules_total", "SELECT COUNT(*) FROM rule"),
        "dashboards": compte("dashboards", "SELECT COUNT(*) FROM dashboard"),
        "users": compte("users", "SELECT COUNT(*) FROM user"),
        "alerts_open": compte("alerts_open", "SELECT COUNT(*) FROM alert WHERE status='new'"),
        "destinations": compte("destinations", "SELECT COUNT(*) FROM destination"),
        "connectors": compte("connectors", "SELECT COUNT(*) FROM connector"),
        // TAXONOMIE — CE QUE PLUME N'A PAS CLASSÉ, MESURÉ SUR LES DONNÉES ET NON SUR UN COMPTEUR DE
        // PROCESSUS. Une ligne à `category` vide est invisible à TOUTE règle `category=…` (l'axe de
        // composition des détections, docs/CIM.md §2) et le produit n'en disait rien : ni refus, ni
        // repli, ni journal (mesuré le 2026-08-02 : 4 événements à catégorie vide -> 4 stockés, 0
        // ligne). Le compte est fait EN SQL, donc il survit aux redémarrages et décrit l'état RÉEL de
        // la base — un compteur en mémoire n'aurait mesuré que la vie du process courant. Un COUNT raté
        // rend désormais `null` (et non 0), ce qui le rend SOLIDAIRE de sa ventilation ci-dessous.
        "events_without_category": compte("events_without_category", "SELECT COUNT(*) FROM event WHERE category IS NULL OR category=''"),
    });
    // Quel ÉMETTEUR n'a pas classé. Sans cette ventilation, le compte ci-dessus dit qu'il y a un trou
    // sans dire où le boucher. Borné à 20 sources (des NOMBRES et des noms de source, jamais de ligne).
    let unclassified: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT source, COUNT(*) n FROM event WHERE category IS NULL OR category='' \
             GROUP BY source ORDER BY n DESC LIMIT ?1",
        )
        .and_then(|mut s| {
            s.query_map(params![aveu::borne_avec_ligne_excedentaire(DIAG_UNCLASSIFIED_SOURCES_WINDOW)], |r| {
                Ok(json!({ "source": r.get::<_, String>(0)?, "events": r.get::<_, i64>(1)? }))
            })
            .and_then(|it| it.collect())
        });
    let mut paquet = json!({
        "generated_at": now(),
        "kind": "plume-diagnostic-bundle",
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": sv.en_json(),
        "config": Value::Object(cfgmap),
        "metrics": crate::gather_json(conn, spool, db_path, &sv, warn),
        "health": crate::component_health(conn, spool, db_path, warn),
        "recent_events": [],
        "heartbeat_alerts": [],
        "counts": counts,
        "unclassified_by_source": [],
    });
    // `P11.22-g` (coupe) + `P10.7-g` (lecture) — chaque sous-liste est posée par la sœur du fabricant, avec
    // sa coupe MESURÉE par la ligne excédentaire ET, si sa lecture a échoué, son aveu `non_lu` au lieu d'un
    // `[]` établi. LA CONTRADICTION EST FERMÉE PAR CONSTRUCTION : `events_without_category` (un compte) rend
    // `null` quand il n'est pas lu, et `unclassified_by_source` (sa ventilation) rend un objet `non_lu` quand
    // elle ne l'est pas — jamais respectivement un nombre et un `[]`. Aucun corps ne peut donc afficher
    // « N non classés » à côté de « aucune source n'en a » comme deux faits établis : soit les deux sont lus
    // et cohérents (même prédicat sur `event`), soit celui qui a échoué s'annonce non lu.
    if let Some(obj) = paquet.as_object_mut() {
        // `P10.20-b` — LE PAQUET REMIS AU SUPPORT DIT AUSSI QUAND SA VERSION DE SCHÉMA N'A PAS ÉTÉ LUE.
        // C'est le premier chiffre qu'une reprise d'incident regarde ; un `1` inventé y enverrait le
        // support chercher une base neuve. L'aveu NOMME sa clé et reste absent du chemin nominal.
        sv.poser_l_aveu(obj);
        if aveu::poser_la_sous_liste_ou_avouer(obj, "recent_events", recent, DIAG_RECENT_EVENTS_WINDOW as usize) {
            non_lus.push("recent_events");
        }
        if aveu::poser_la_sous_liste_ou_avouer(obj, "heartbeat_alerts", heartbeats, DIAG_HEARTBEAT_ALERTS_WINDOW as usize) {
            non_lus.push("heartbeat_alerts");
        }
        if aveu::poser_la_sous_liste_ou_avouer(obj, "unclassified_by_source", unclassified, DIAG_UNCLASSIFIED_SOURCES_WINDOW as usize) {
            non_lus.push("unclassified_by_source");
        }
        if !non_lus.is_empty() {
            obj.insert(
                "error".into(),
                json!(format!(
                    "bundle PARTIELLEMENT NON LU : {} — les comptes manquants sont `null`, les listes non lues \
                     portent `non_lu:true` ; aucun n'est une mesure établie",
                    non_lus.join(", ")
                )),
            );
            obj.insert("non_lus".into(), json!(non_lus));
        }
    }
    paquet
}

/// GET /api/system/diag — ADMIN-ONLY (route_min_role Admin + re-check ici). Bundle JSON pour le support.
/// Content-Disposition attachment -> le navigateur le télécharge en fichier. Aucun secret (allowlist).
pub(crate) async fn system_diag(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let spool = st.spool.as_str().to_string();
    let db_path = req_db_path(&st, &au);
    let warn = disk_warn_pct();
    let db = req_db(&st, &au);
    let bundle = {
        let c = db.lock();
        diag_bundle_json(&c, &spool, &db_path, warn)
    };
    let fname = format!("plume-diag-{}.json", now());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{fname}\""))],
        Json(bundle),
    )
        .into_response()
}

// ---------- BULLETIN / MOTD (setting row 'bulletin', diffusé à tous) ----------
const BULLETIN_KEY: &str = "bulletin";
/// Niveaux d'affichage autorisés du bandeau (enum fermé -> pas d'injection de classe CSS arbitraire).
fn bulletin_level_ok(l: &str) -> bool {
    matches!(l, "info" | "warn" | "critical")
}

/// Lit le bulletin courant (setting global). None si absent (mode 0 : aucun bandeau). Value {message,level,...}.
pub(crate) fn bulletin_read(conn: &Connection) -> Option<Value> {
    let raw: String = conn
        .query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY], |r| r.get(0))
        .ok()?;
    serde_json::from_str::<Value>(&raw).ok().filter(|v| v.get("message").and_then(|m| m.as_str()).map(|s| !s.is_empty()).unwrap_or(false))
}

/// GET /api/bulletin — viewer+ (tous les rôles voient le MOTD). {bulletin: {...} | null}.
pub(crate) async fn bulletin_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let db = req_db(&st, &au);
    let c = db.lock();
    Json(json!({ "bulletin": bulletin_read(&c) }))
}

/// POST /api/bulletin — ADMIN-ONLY (route_min_role default-deny Admin + re-check). {message, level?}.
/// Message vide -> efface (équivaut à DELETE). Ledgerisé (audit_config_change) — gouvernance.
pub(crate) async fn bulletin_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(body): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let message = body.get("message").and_then(|m| m.as_str()).unwrap_or("").trim().to_string();
    let level = body.get("level").and_then(|l| l.as_str()).unwrap_or("info");
    let level = if bulletin_level_ok(level) { level } else { "info" };
    let db = req_db(&st, &au);
    let c = db.lock();
    if message.is_empty() {
        let _ = c.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY]);
        let _ = audit_config_change(&c, "bulletin.clear", &format!("bulletin effacé par {}", au.name), 1, "bulletin effacé", "{}");
        return (StatusCode::OK, Json(json!({ "ok": true, "bulletin": Value::Null }))).into_response();
    }
    if message.len() > 2000 {
        return bad_req("message trop long (max 2000 caractères)");
    }
    let val = json!({ "message": message, "level": level, "updated_by": au.name, "updated": now() });
    let _ = c.execute(
        "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES('global',?1,?2,?3,?4) \
         ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
        params![BULLETIN_KEY, val.to_string(), now(), au.name],
    );
    let _ = audit_config_change(&c, "bulletin.set", &format!("bulletin posé par {} (niveau {level})", au.name), 1, "bulletin/MOTD mis à jour", &json!({ "level": level, "by": au.name }).to_string());
    (StatusCode::OK, Json(json!({ "ok": true, "bulletin": val }))).into_response()
}

/// DELETE /api/bulletin — ADMIN-ONLY. Efface le bandeau (retour à l'état mode 0 : aucun bandeau).
pub(crate) async fn bulletin_clear(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) {
        return r;
    }
    let db = req_db(&st, &au);
    let c = db.lock();
    let _ = c.execute("DELETE FROM setting WHERE scope='global' AND key=?1", params![BULLETIN_KEY]);
    let _ = audit_config_change(&c, "bulletin.clear", &format!("bulletin effacé par {}", au.name), 1, "bulletin effacé", "{}");
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}
