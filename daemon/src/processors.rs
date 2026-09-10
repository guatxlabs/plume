//! #40 — PROCESSEUR D'INGEST (edge/ingest-time pipeline). Filtre / masque / route / échantillonne un
//! event NORMALISÉ (`EventRow`) AVANT son indexation dans le store. C'est le premier levier de rétention
//! (« décider ce qu'on n'ingère PAS » -> ×10-100 sur le stockage, cf. analyse de dimensionnement).
//!
//! HOOK : `ingest_events_batch_env` (ingest/mod.rs), juste APRÈS la construction de l'`EventRow` enrichi
//! (parsers + extracteur générique + dparser CIM + threat-intel + tags) et JUSTE AVANT
//! `store().insert_event`. Point de passage UNIQUE : `/api/ingest`, spool, journal, HEC, Loki et
//! connecteurs y convergent tous -> une seule couture couvre toutes les surfaces d'ingest.
//!
//! CETTE PHRASE A ÉTÉ FAUSSE, ET RIEN NE L'ATTRAPAIT (clé P3.6-b, mesuré le 2026-08-04) : `loki_push`
//! écrivait un `INSERT` à 7 colonnes DIRECTEMENT dans `event`, donc DROP / **MASK (redaction PII)** /
//! ROUTE ne s'appliquaient pas aux logs Loki — pendant que la ligne ci-dessus affirmait le contraire.
//! Une allégation fausse arrête l'enquête du relecteur suivant : elle coûte plus que le trou.
//! Elle est désormais TENUE PAR UNE GARDE, pas par la mémoire de qui la lit :
//! `aucune_surface_dingestion_necrit_dans_event_en_direct` (src/tests/dedup_flotte.rs) rougit si un
//! fichier de `src/ingest/` écrit dans `event` sans implémenter le SPI `EventStore`.
//!
//! MODÈLE DE RÈGLE (admin-managed, ordonné, par-tenant, table `ingest_rule`) :
//!   prédicat  (champ CIM normalisé, allowlisté)  ->  action
//!     DROP    : l'event n'est PAS indexé (compté « dropped-by-policy », JAMAIS une perte silencieuse).
//!     MASK    : réécrit UN champ (redaction PII : message/host/src_ip/dst_ip/url/fields.<clé>).
//!     ROUTE   : pose l'environnement cible (`env_id`) -> classe de rétention / index logique.
//!     SAMPLE  : garde 1 event sur N d'une source bruyante (les N-1 autres droppés, comptés).
//!     RENAME  : `P4.12-b` (2026-09-10) — copie la valeur d'un champ vers une colonne d'ENTITÉ (`src_ip`,
//!               `dst_ip`, `url`, `host`) ou vers `fields.<clé>` : c'est le renommage champ->champ que
//!               seuls trois connecteurs offraient (`field_map`), rendu joignable depuis TOUTES les voies
//!               d'entrée par un prédicat sur la `source` — un attribut OTLP `otel.client.address`, une
//!               clé HEC `src`, un label Loki deviennent l'adresse que les règles par entité lisent. La
//!               valeur d'origine reste dans `fields` ; une colonne déjà posée par le producteur GAGNE
//!               (précédence collecteur > parseur, comme `dfield_put`) et la préemption est COMPTÉE.
//! Les règles s'appliquent DANS L'ORDRE (`ord`). DROP et SAMPLE-out court-circuitent (return) ; MASK,
//! ROUTE et RENAME mutent la ligne puis l'évaluation CONTINUE. Composition sur le modèle CIM — ZÉRO hardcode vendeur.
//!
//! INVARIANT MODE 0 (byte-identique) : AUCUNE règle définie -> le registre de `db_path` est vide ->
//! `processors_apply` renvoie `Keep` en un `read()` + `get()` (zéro allocation, ligne stockée IDENTIQUE).
//!
//! FAIL-SAFE (jamais de perte par bug de règle) : une règle qui ne COMPILE plus (regex invalide, action
//! inconnue, champ hors allowlist) est SKIPPÉE au reload (WARN + compteur d'erreurs) -> elle n'entre jamais
//! dans le pipeline chaud ; l'event est indexé INCHANGÉ. À l'évaluation, toute condition inattendue ->
//! « pas de match » (jamais un drop). On ne perd JAMAIS un event à cause d'une mauvaise règle.
//!
//! NON-SILENCE : chaque règle porte des compteurs atomiques (matched/dropped/masked/routed/sampled_out),
//! persistants À TRAVERS les reloads (clé (db_path,id)), surfacés en UI (philosophie garde-disque 503 :
//! une donnée non-indexée est COMPTÉE et VISIBLE, jamais un trou muet).
use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Valide un identifiant d'ENVIRONNEMENT / INDEX LOGIQUE (`env_id`). ALLOWLIST FERMÉE, partagée : la
/// cible de l'action ROUTE (#40) ET le nom d'un `index_policy` (#49) passent par CE contrôle -> le nom
/// d'un index est TOUJOURS une valeur d'env_id valide (jamais interpolé en SQL sans validation ; utilisé
/// UNIQUEMENT en paramètre lié côté rétention). Charset borné (alphanum + `.` `_` `-`), 1..=64 caractères.
pub(crate) fn env_id_ok(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Plafond agrégé de règles appliquées par event (borne le coût chaud, cf. DPARSER_MAX_TOTAL).
pub(crate) const PROC_RULE_MAX_TOTAL: usize = 256;
/// Longueur max d'une valeur/regex de prédicat (borne la compilation regex, anti-ReDoS trivial).
pub(crate) const PROC_VALUE_MAX: usize = 1000;

/// Champ CIM normalisé sur lequel un prédicat/MASK opère. ALLOWLIST FERMÉE (jamais interpolé en SQL ;
/// l'accès se fait par `match` sur ces variantes -> injection-safe). `Field(clé)` cible `fields.<clé>`
/// (un champ du sac JSON `fields`), la seule dimension dynamique — la clé est bornée, jamais du SQL.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MatchField {
    Category,
    Source,
    Severity,
    Host,
    SrcIp,
    DstIp,
    Url,
    Message,
    Field(String), // fields.<clé>
}

impl MatchField {
    /// Parse un nom de champ allowlisté. `fields.<clé>` -> `Field(clé)` (clé alphanum/._- bornée).
    pub(crate) fn parse(name: &str) -> Result<MatchField, String> {
        let n = name.trim();
        Ok(match n {
            "category" => MatchField::Category,
            "source" => MatchField::Source,
            "severity" => MatchField::Severity,
            "host" => MatchField::Host,
            "src_ip" => MatchField::SrcIp,
            "dst_ip" => MatchField::DstIp,
            "url" => MatchField::Url,
            "message" => MatchField::Message,
            other => {
                if let Some(k) = other.strip_prefix("fields.") {
                    if k.is_empty() || k.len() > 128
                        || !k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                    {
                        return Err(format!("clé fields invalide: '{k}'"));
                    }
                    MatchField::Field(k.to_string())
                } else {
                    return Err(format!("champ non allowlisté: '{other}'"));
                }
            }
        })
    }
    /// Un champ MASQUABLE (redaction). On refuse de masquer category/severity (dimensions de détection ;
    /// masquer = perte d'information de sécurité) — MASK vise la PII (message/host/ip/url/fields.<clé>).
    pub(crate) fn maskable(&self) -> bool {
        !matches!(self, MatchField::Category | MatchField::Severity)
    }
    /// Une CIBLE de RENAME (`P4.12-b`) : les colonnes d'entité et le sac `fields`. Ni `category` ni
    /// `severity` (dimensions de détection), ni `message` (le texte), ni `source` (l'identité du producteur,
    /// que l'inventaire des sources et les prédicats de ce moteur lisent) : réécrire l'une d'elles depuis
    /// un champ vendeur changerait ce que toutes les règles voient, pas seulement l'entité.
    pub(crate) fn cible_de_renommage(&self) -> bool {
        matches!(self, MatchField::SrcIp | MatchField::DstIp | MatchField::Url | MatchField::Host | MatchField::Field(_))
    }
    /// Le nom sous lequel ce champ se déclare (`src_ip`, `fields.<clé>`…) — pour compter et pour dire.
    pub(crate) fn nom(&self) -> String {
        match self {
            MatchField::Category => "category".into(),
            MatchField::Source => "source".into(),
            MatchField::Severity => "severity".into(),
            MatchField::Host => "host".into(),
            MatchField::SrcIp => "src_ip".into(),
            MatchField::DstIp => "dst_ip".into(),
            MatchField::Url => "url".into(),
            MatchField::Message => "message".into(),
            MatchField::Field(k) => format!("fields.{k}"),
        }
    }
    /// Valeur STRING du champ pour un event donné (lecture seule). `None` = champ absent.
    pub(crate) fn value_of(&self, row: &EventRow) -> Option<String> {
        match self {
            MatchField::Category => Some(row.category.clone()),
            MatchField::Source => Some(row.source.clone()),
            MatchField::Severity => Some(row.severity.to_string()),
            MatchField::Host => row.host.clone(),
            MatchField::SrcIp => row.src_ip.clone(),
            MatchField::DstIp => row.dst_ip.clone(),
            MatchField::Url => row.url.clone(),
            MatchField::Message => Some(row.message.clone()),
            MatchField::Field(k) => row
                .fields
                .as_deref()
                .and_then(|f| serde_json::from_str::<Value>(f).ok())
                .and_then(|v| v.get(k).map(|x| match x {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })),
        }
    }
}

/// Opérateur de prédicat. `Any` = matche tout event (règle inconditionnelle, ex. SAMPLE global d'une
/// source déjà filtrée en amont par un autre prédicat). `Regex` est PRÉ-COMPILÉ (jamais recompilé à chaud).
#[derive(Debug, Clone)]
pub(crate) enum MatchOp {
    Eq,
    Ne,
    Contains,
    Regex(regex::Regex),
    Any,
}

/// Action d'une règle. `Route.env` pose `EventRow.env_id` (routage environnement / classe de rétention).
#[derive(Debug, Clone)]
pub(crate) enum RuleAction {
    Drop,
    Mask { field: MatchField },
    Route { env: String },
    Sample { n: u32 },
    /// `P4.12-b` — copie `from` vers `to` (colonne d'entité ou `fields.<clé>`) quand `to` est vide.
    Rename { from: MatchField, to: MatchField },
}

/// La flèche qui sépare l'origine de la cible dans `action_arg` d'un RENAME : `fields.otel.client.address->src_ip`.
pub(crate) const RENAME_FLECHE: &str = "->";

/// Compteurs atomiques d'une règle (lock-free sur le chemin chaud). Persistants à travers les reloads
/// (stockés dans `PROC_COUNTERS`, clé (db_path,id)) -> l'UI voit un cumul stable, pas remis à zéro à
/// chaque CRUD. `seen` sert au décompte 1-sur-N de SAMPLE.
#[derive(Default, Debug)]
pub(crate) struct RuleCounters {
    pub matched: AtomicU64,
    pub dropped: AtomicU64,
    pub masked: AtomicU64,
    pub routed: AtomicU64,
    pub sampled_out: AtomicU64,
    pub seen: AtomicU64,
    /// `P4.12-b` — lignes dont la cible a été ÉCRITE (une origine vide ou une cible déjà posée ne comptent pas ici).
    pub renamed: AtomicU64,
}

/// Règle COMPILÉE (prête pour le chemin chaud). `counters` est partagé (Arc) avec le magasin stable.
#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub id: i64,
    pub field: MatchField,
    pub op: MatchOp,
    pub value: String,
    pub action: RuleAction,
    pub counters: Arc<RuleCounters>,
}

impl CompiledRule {
    /// Le prédicat matche-t-il cet event ? FAIL-SAFE : un champ absent -> pas de match (jamais un drop
    /// « par défaut »). `Any` matche toujours.
    fn matches(&self, row: &EventRow) -> bool {
        if let MatchOp::Any = self.op {
            return true;
        }
        let v = match self.field.value_of(row) {
            Some(v) => v,
            None => return false, // champ absent -> pas de match (fail-safe)
        };
        match &self.op {
            MatchOp::Eq => v == self.value,
            MatchOp::Ne => v != self.value,
            MatchOp::Contains => v.contains(&self.value),
            MatchOp::Regex(re) => re.is_match(&v),
            MatchOp::Any => true,
        }
    }
}

/// Verdict du pipeline pour un event : indexer (`Keep`) ou NON-indexer (`Drop`, compté).
#[derive(Debug, PartialEq)]
pub(crate) enum ProcVerdict {
    Keep,
    Drop,
}

// ---------------------------------------------------------------------------------------------------
// Registre compilé PAR db_path (MT-KEY, R4 — miroir de PARSERS/DPARSERS). Rechargé au boot + à chaque
// mutation CRUD. Mono-tenant : une seule entrée.
// ---------------------------------------------------------------------------------------------------
pub(crate) static PROCESSORS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Vec<CompiledRule>>>> =
    std::sync::OnceLock::new();
pub(crate) fn processors_cell() -> &'static parking_lot::RwLock<HashMap<String, Vec<CompiledRule>>> {
    PROCESSORS.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// Magasin STABLE de compteurs (survit aux reloads). Clé = (db_path, rule_id). `reload_errors` compte les
/// règles skippées faute de compilation (visible en UI : « N règles invalides ignorées »).
#[derive(Default)]
pub(crate) struct ProcCounterStore {
    pub rules: HashMap<(String, i64), Arc<RuleCounters>>,
    pub reload_errors: HashMap<String, u64>,
}
pub(crate) static PROC_COUNTERS: std::sync::OnceLock<parking_lot::RwLock<ProcCounterStore>> =
    std::sync::OnceLock::new();
pub(crate) fn proc_counters_cell() -> &'static parking_lot::RwLock<ProcCounterStore> {
    PROC_COUNTERS.get_or_init(|| parking_lot::RwLock::new(ProcCounterStore::default()))
}
/// Récupère (ou crée) le bloc de compteurs stable d'une règle (db_path,id).
fn rule_counters_for(db_path: &str, id: i64) -> Arc<RuleCounters> {
    let key = (db_path.to_string(), id);
    { let g = proc_counters_cell().read();
        if let Some(c) = g.rules.get(&key) {
            return c.clone();
        }
    }
    let mut w = proc_counters_cell().write();
    w.rules.entry(key).or_insert_with(|| Arc::new(RuleCounters::default())).clone()
}

/// Compile UNE ligne `ingest_rule` en `CompiledRule`. `Err` = règle invalide (SKIPPÉE au reload, fail-safe).
/// Bound params à la lecture (jamais de SQL construit à partir des valeurs).
pub(crate) fn compile_rule(
    db_path: &str,
    id: i64,
    match_field: &str,
    match_op: &str,
    match_value: &str,
    action: &str,
    action_arg: &str,
) -> Result<CompiledRule, String> {
    if match_value.len() > PROC_VALUE_MAX {
        return Err(format!("valeur de prédicat trop longue (>{PROC_VALUE_MAX})"));
    }
    let op = match match_op.trim() {
        "any" => MatchOp::Any,
        "eq" => MatchOp::Eq,
        "ne" => MatchOp::Ne,
        "contains" => MatchOp::Contains,
        "regex" => {
            let re = regex::Regex::new(match_value).map_err(|e| format!("regex invalide: {e}"))?;
            MatchOp::Regex(re)
        }
        other => return Err(format!("opérateur inconnu: '{other}'")),
    };
    // Le champ est requis SAUF pour `any` (prédicat inconditionnel).
    let field = if matches!(op, MatchOp::Any) {
        MatchField::parse(if match_field.trim().is_empty() { "category" } else { match_field })?
    } else {
        MatchField::parse(match_field)?
    };
    let action = match action.trim() {
        "drop" => RuleAction::Drop,
        "mask" => {
            let f = MatchField::parse(action_arg)
                .map_err(|e| format!("champ à masquer invalide: {e}"))?;
            if !f.maskable() {
                return Err(format!("champ non masquable: '{action_arg}'"));
            }
            RuleAction::Mask { field: f }
        }
        "route" => {
            let env = action_arg.trim();
            // MÊME allowlist que le nom d'un index logique (#49, env_id_ok) : la cible de ROUTE == un env_id.
            if !env_id_ok(env) {
                return Err(format!("environnement de routage invalide: '{env}'"));
            }
            RuleAction::Route { env: env.to_string() }
        }
        "sample" => {
            let n: u32 = action_arg.trim().parse().map_err(|_| "N d'échantillonnage invalide".to_string())?;
            if n < 1 {
                return Err("N d'échantillonnage doit être >= 1".to_string());
            }
            RuleAction::Sample { n }
        }
        "rename" => {
            let (de, vers) = action_arg
                .split_once(RENAME_FLECHE)
                .ok_or_else(|| format!("argument de rename invalide : attendu `<origine>{RENAME_FLECHE}<cible>` (ex. `fields.otel.client.address{RENAME_FLECHE}src_ip`)"))?;
            let from = MatchField::parse(de).map_err(|e| format!("origine de rename invalide: {e}"))?;
            let to = MatchField::parse(vers).map_err(|e| format!("cible de rename invalide: {e}"))?;
            if !to.cible_de_renommage() {
                return Err(format!("cible de rename refusée: '{}' (seules les colonnes d'entité src_ip/dst_ip/url/host et fields.<clé> se renomment)", vers.trim()));
            }
            if from == to {
                return Err("rename d'un champ vers lui-même".to_string());
            }
            RuleAction::Rename { from, to }
        }
        other => return Err(format!("action inconnue: '{other}'")),
    };
    Ok(CompiledRule {
        id,
        field,
        op,
        value: match_value.to_string(),
        action,
        counters: rule_counters_for(db_path, id),
    })
}

/// Recharge le registre de `db_path` depuis la table `ingest_rule` (ordonné par `ord`,`id`). Une règle
/// qui ne compile plus est SKIPPÉE (WARN + `reload_errors`) — JAMAIS fatal. Miroir de `dparsers_reload`.
pub(crate) fn processors_reload(conn: &Connection, db_path: &str) {
    let mut out: Vec<CompiledRule> = Vec::new();
    let mut errs: u64 = 0;
    if let Ok(mut st) = conn.prepare(
        "SELECT id,match_field,match_op,match_value,action,action_arg FROM ingest_rule WHERE enabled=1 ORDER BY ord, id",
    ) {
        if let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        }) {
            for (id, mf, mo, mv, act, arg) in rows.flatten() {
                if out.len() >= PROC_RULE_MAX_TOTAL {
                    eprintln!("[processor] WARN plafond de {PROC_RULE_MAX_TOTAL} règles atteint — règles supplémentaires IGNORÉES");
                    break;
                }
                match compile_rule(db_path, id, &mf, &mo, &mv, &act, &arg) {
                    Ok(c) => out.push(c),
                    Err(e) => {
                        errs += 1;
                        eprintln!("[processor] WARN règle #{id} ignorée (fail-safe, event indexé inchangé): {e}");
                    }
                }
            }
        }
    }
    { let mut w = processors_cell().write();
        w.insert(db_path.to_string(), out);
    }
    { let mut w = proc_counters_cell().write();
        w.reload_errors.insert(db_path.to_string(), errs);
    }
}

/// Réécrit un champ MASQUÉ en place (redaction). `message`/`host`/`src_ip`/`dst_ip`/`url` -> littéral
/// `[redacted]` ; `fields.<clé>` -> réécrit la clé dans le JSON (si présente). Ne crée jamais un champ
/// absent (masquer = redaction d'une donnée EXISTANTE, jamais une injection). FAIL-SAFE : un `fields`
/// JSON illisible est laissé INTACT (jamais de perte du sac).
fn apply_mask(row: &mut EventRow, field: &MatchField) -> bool {
    const RED: &str = "[redacted]";
    match field {
        MatchField::Message => { row.message = RED.to_string(); true }
        MatchField::Host => { if row.host.is_some() { row.host = Some(RED.to_string()); true } else { false } }
        MatchField::SrcIp => { if row.src_ip.is_some() { row.src_ip = Some(RED.to_string()); true } else { false } }
        MatchField::DstIp => { if row.dst_ip.is_some() { row.dst_ip = Some(RED.to_string()); true } else { false } }
        MatchField::Url => { if row.url.is_some() { row.url = Some(RED.to_string()); true } else { false } }
        MatchField::Source => { row.source = RED.to_string(); true }
        MatchField::Field(k) => {
            let raw = match row.fields.as_deref() { Some(f) => f, None => return false };
            let mut v: Value = match serde_json::from_str(raw) { Ok(v) => v, Err(_) => return false };
            if let Some(obj) = v.as_object_mut() {
                if obj.contains_key(k) {
                    obj.insert(k.clone(), Value::String(RED.to_string()));
                    row.fields = Some(v.to_string());
                    return true;
                }
            }
            false
        }
        // Non masquables (refusés à la compilation) : no-op défensif.
        MatchField::Category | MatchField::Severity => false,
    }
}

/// `P4.12-b` — COPIE `from` vers `to`. Rend `true` quand la cible a été écrite. Trois cas qui ne l'écrivent
/// pas, et ce qu'ils disent : une origine absente ou vide (rien à copier — pas une faute) ; une cible qui
/// porte DÉJÀ une autre valeur (le producteur l'a posée : sa précédence est l'invariant de `dfield_put`, et
/// la préemption est COMPTÉE par clé comme sous `P4.12-f`) ; un sac `fields` indécodable (no-op, comme MASK).
/// L'origine n'est jamais retirée : renommer ici, c'est promouvoir, pas perdre.
fn apply_rename(row: &mut EventRow, from: &MatchField, to: &MatchField) -> bool {
    let valeur = match from.value_of(row) {
        Some(v) if !v.trim().is_empty() => v,
        _ => return false,
    };
    let deja = match to.value_of(row) {
        Some(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    };
    if let Some(d) = deja {
        if d != valeur {
            crate::metrics::compter_un_champ_preempte(&to.nom());
        }
        return false;
    }
    match to {
        MatchField::SrcIp => { row.src_ip = Some(valeur); true }
        MatchField::DstIp => { row.dst_ip = Some(valeur); true }
        MatchField::Url => { row.url = Some(valeur); true }
        MatchField::Host => { row.host = Some(valeur); true }
        MatchField::Field(k) => {
            let mut v: Value = match row.fields.as_deref() {
                Some(f) => match serde_json::from_str(f) { Ok(v) => v, Err(_) => return false },
                None => json!({}),
            };
            match v.as_object_mut() {
                Some(obj) => { obj.insert(k.clone(), Value::String(valeur)); row.fields = Some(v.to_string()); true }
                None => false,
            }
        }
        // Refusées à la compilation : no-op défensif.
        MatchField::Category | MatchField::Severity | MatchField::Message | MatchField::Source => false,
    }
}

/// APPLIQUE le pipeline de `db_path` à un event NORMALISÉ (`row`) juste avant l'INSERT. Renvoie `Drop`
/// (ne pas indexer, déjà compté) ou `Keep` (indexer `row`, éventuellement muté par MASK/ROUTE).
///
/// MODE 0 : registre vide -> `Keep` immédiat (aucune mutation, ligne stockée byte-identique).
pub(crate) fn processors_apply(db_path: &str, row: &mut EventRow) -> ProcVerdict {
    processors_apply_inner(db_path, row, true)
}

/// DRY-RUN (test UI) : évalue le pipeline SANS incrémenter les compteurs live (ne pollue pas la vue
/// « dropped-by-policy »). Mêmes règles, même ordre, mêmes mutations MASK/ROUTE sur `row`.
pub(crate) fn processors_dryrun(db_path: &str, row: &mut EventRow) -> ProcVerdict {
    processors_apply_inner(db_path, row, false)
}

fn processors_apply_inner(db_path: &str, row: &mut EventRow, count: bool) -> ProcVerdict {
    let guard = processors_cell().read();
    let list = match guard.get(db_path) {
        Some(l) if !l.is_empty() => l,
        _ => return ProcVerdict::Keep, // AUCUNE règle -> chemin mode-0 (byte-identique)
    };
    for rule in list.iter() {
        if !rule.matches(row) {
            continue;
        }
        if count { rule.counters.matched.fetch_add(1, Ordering::Relaxed); }
        match &rule.action {
            RuleAction::Drop => {
                if count { rule.counters.dropped.fetch_add(1, Ordering::Relaxed); }
                return ProcVerdict::Drop;
            }
            RuleAction::Mask { field } => {
                if apply_mask(row, field) && count {
                    rule.counters.masked.fetch_add(1, Ordering::Relaxed);
                }
                // MASK ne court-circuite pas : l'évaluation continue (une règle DROP en aval peut suivre).
            }
            RuleAction::Route { env } => {
                row.env_id = Some(env.clone());
                if count { rule.counters.routed.fetch_add(1, Ordering::Relaxed); }
            }
            RuleAction::Rename { from, to } => {
                if apply_rename(row, from, to) && count {
                    rule.counters.renamed.fetch_add(1, Ordering::Relaxed);
                }
                // RENAME ne court-circuite pas : une règle MASK ou DROP en aval voit la colonne remplie.
            }
            RuleAction::Sample { n } => {
                // Garde 1 event sur N (le PREMIER de chaque fenêtre : seen % n == 0). Les N-1 autres sont
                // droppés (comptés sampled_out). n==1 -> tout gardé (no-op utile). DRY-RUN : `seen` n'avance
                // pas (count=false) -> un test isolé lit toujours la fenêtre courante sans la décaler.
                if count {
                    let k = rule.counters.seen.fetch_add(1, Ordering::Relaxed);
                    if *n > 1 && (k % (*n as u64)) != 0 {
                        rule.counters.sampled_out.fetch_add(1, Ordering::Relaxed);
                        return ProcVerdict::Drop;
                    }
                } else if *n > 1 {
                    // Dry-run : verdict déterministe = « gardé » (premier de fenêtre) — informatif, sans effet.
                }
            }
        }
    }
    ProcVerdict::Keep
}

/// Vue JSON des compteurs d'un `db_path` (pour l'UI admin) : par-règle + agrégats + erreurs de reload.
pub(crate) fn processors_counters_json(db_path: &str) -> Value {
    let g = proc_counters_cell().read();
    let mut per_rule = serde_json::Map::new();
    let (mut td, mut tm, mut tr, mut ts, mut tn) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for ((dbp, id), c) in g.rules.iter() {
        if dbp != db_path {
            continue;
        }
        let d = c.dropped.load(Ordering::Relaxed);
        let m = c.masked.load(Ordering::Relaxed);
        let r = c.routed.load(Ordering::Relaxed);
        let s = c.sampled_out.load(Ordering::Relaxed);
        let rn = c.renamed.load(Ordering::Relaxed);
        td += d; tm += m; tr += r; ts += s; tn += rn;
        per_rule.insert(id.to_string(), json!({
            "matched": c.matched.load(Ordering::Relaxed),
            "dropped": d, "masked": m, "routed": r, "sampled_out": s, "renamed": rn,
        }));
    }
    json!({
        "per_rule": per_rule,
        "totals": { "dropped": td, "masked": tm, "routed": tr, "sampled_out": ts, "renamed": tn, "not_indexed": td + ts },
        "reload_errors": g.reload_errors.get(db_path).copied().unwrap_or(0),
    })
}
