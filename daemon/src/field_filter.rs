//! FIELD FILTERS (#45) — masquage / contrôle d'accès AU NIVEAU CHAMP, par rôle/tenant/env (équivalent
//! « Field filters » Splunk ; débloqueur PCI/PII). Registre par db_path chargé depuis la table `field_filter`
//! (admin-only, migration v86), résolu pour l'appelant courant en un `guatx_core::soql::FieldMaskSet` qui est
//! INJECTÉ DANS LE SCHÉMA de compilation GXQL -> le masque est émis DANS le SQL (choke-point `soql_field`),
//! donc AVANT toute agrégation/renommage. VIDE (aucune règle) -> court-circuit -> compilation byte-identique
//! (mode 0). En PLUS : les règles DENY sur une COLONNE RÉELLE alimentent l'authorizer SQLite (query_exec.rs)
//! -> déni même en SQL brut admin, comme la denylist de secrets. Les surfaces NON-GXQL (/api/search, timeline
//! de cas) réutilisent `mask_json_value` sur leurs lignes construites à la main.
//!
//! FAIL-CLOSED : rôle indéterminé/inconnu -> rank 0 -> masqué par toute règle (protège par défaut). Action
//! illisible au reload -> traitée comme DENY (masque PLUS, jamais moins).
use crate::*;
use guatx_core::soql::{FieldMaskSet, MaskAction};

/// Colonnes RÉELLES de la table `event` : une règle DENY sur l'une d'elles est AUSSI posée dans l'authorizer
/// SQLite (déni au prepare(), même admin en SQL brut). Les autres champs (clés du sac JSON `fields`) ne sont
/// masquables qu'au niveau GXQL (l'authorizer ne voit que la colonne `fields`, pas ses clés).
pub(crate) const PHYSICAL_EVENT_COLS: &[&str] = &[
    "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message",
];

/// Champs STRUCTURELS jamais masquables (casseraient pagination/temps/anti-doublon/routage) : refusés à la
/// création. `category`/`severity` sont des DIMENSIONS de détection mais le masquage est QUERY-TIME (n'altère
/// pas la détection) -> autorisés (l'admin assume l'impact d'affichage).
const STRUCTURAL_DENY: &[&str] = &["id", "ts", "env_id", "dedup", "origin", "engagement_id", "fields"];

/// Une règle compilée (résolue de la table). `field` = nom CANONIQUE utilisé à la compilation GXQL (clé de
/// masque), déjà normalisé (`fields.k` -> `k`). `role` = seuil (cf. `role_threshold`). `tenant`/`env` = ''=tous.
pub(crate) struct CompiledFilter {
    pub field: String,
    pub action: MaskAction,
    pub role: String,
    pub tenant: String,
    pub env: String,
    pub specificity: u8, // (env!='')+(tenant!='')+(role!='') — most-specific-wins (appliqué en dernier)
    pub ord: i64,
    pub id: i64,
}

// Registre par db_path (comme PROCESSORS). VIDE/absent -> mode 0 (aucun masque).
pub(crate) static FIELD_FILTERS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Arc<Vec<CompiledFilter>>>>> =
    std::sync::OnceLock::new();
fn filters_cell() -> &'static parking_lot::RwLock<HashMap<String, Arc<Vec<CompiledFilter>>>> {
    FIELD_FILTERS.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
// Colonnes RÉELLES sous DENY par db_path (consultées par l'authorizer SQLite — déni all-roles, admin compris).
pub(crate) static FIELD_DENY_COLS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, std::collections::HashSet<String>>>> =
    std::sync::OnceLock::new();
pub(crate) fn field_deny_cols_cell() -> &'static parking_lot::RwLock<HashMap<String, std::collections::HashSet<String>>> {
    FIELD_DENY_COLS.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}
// Sel de HASH par db_path (créé immuable par migrate_v86 dans meta.field_mask_salt), caché au reload pour le
// masquage Rust des surfaces non-GXQL. Le HASH SQL (query_exec.rs) lit le sel directement sur sa connexion.
static FIELD_SALT: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, String>>> = std::sync::OnceLock::new();
fn salt_cell() -> &'static parking_lot::RwLock<HashMap<String, String>> {
    FIELD_SALT.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// Parse l'action textuelle. Inconnue -> `Deny` (FAIL-CLOSED : masque plus).
pub(crate) fn parse_action(s: &str) -> MaskAction {
    match s.trim().to_ascii_lowercase().as_str() {
        "mask" => MaskAction::Mask,
        "partial" | "last4" | "mask_partial" => MaskAction::MaskPartial,
        "hash" => MaskAction::Hash,
        "redact" => MaskAction::Redact,
        "deny" => MaskAction::Deny,
        _ => MaskAction::Deny,
    }
}
pub(crate) fn action_str(a: MaskAction) -> &'static str {
    match a {
        MaskAction::Mask => "mask",
        MaskAction::MaskPartial => "partial",
        MaskAction::Hash => "hash",
        MaskAction::Redact => "redact",
        MaskAction::Deny => "deny",
    }
}

/// Normalise un nom de champ pour la CLÉ de masque : `fields.k` -> `k`, trim. (Le compilo GXQL référence les
/// clés JSON par leur nom NU ; `fields.` est une commodité de config côté processors.)
pub(crate) fn normalize_field(raw: &str) -> String {
    let f = raw.trim();
    f.strip_prefix("fields.").unwrap_or(f).to_string()
}

/// Valide un nom de champ à la CRÉATION : identifiant GXQL sûr + hors denylist structurelle. Renvoie le nom
/// NORMALISÉ (clé de masque) ou une erreur. Empêche toute interpolation SQL (le masque agit sur la VALEUR).
pub(crate) fn validate_field(raw: &str) -> Result<String, String> {
    let f = normalize_field(raw);
    if f.is_empty() {
        return Err("champ requis".into());
    }
    if !f.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(format!("nom de champ invalide (alphanumérique + '_' seulement) : {raw}"));
    }
    if STRUCTURAL_DENY.contains(&f.as_str()) {
        return Err(format!("champ structurel non masquable : {f}"));
    }
    Ok(f)
}

/// Rank en-dessous OU ÉGAL duquel un appelant est MASQUÉ par cette règle. DENY = 3 (tout le monde, admin
/// compris — classe PCI, comme la denylist de secrets). Sinon seuil = rôle de la règle ('' = défaut editor ->
/// viewer+editor masqués, admin voit en clair ; 'admin' = masque admin AUSSI, opt-in explicite).
fn role_threshold(rule_role: &str, action: MaskAction) -> u8 {
    if action == MaskAction::Deny {
        return 3;
    }
    match rule_role {
        "viewer" => 1,
        "editor" => 2,
        "admin" => 3,
        _ => 2, // '' (défaut) : masque viewer+editor, PAS admin
    }
}

/// (Re)charge le registre des field-filters de CE db_path depuis la table `field_filter`. Idempotent, appelé
/// au bind (comme processors_reload) et après chaque écriture CRUD. VIDE -> mode 0. FAIL-SAFE : table absente
/// (base pré-v86) -> registre vide. Alimente AUSSI le set de colonnes réelles DENY (authorizer) et le sel.
pub(crate) fn field_filters_reload(conn: &Connection, db_path: &str) {
    let mut out: Vec<CompiledFilter> = Vec::new();
    let mut deny_cols: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Ok(mut st) = conn.prepare(
        "SELECT field,action,role,tenant,env,ord,id FROM field_filter WHERE enabled=1 ORDER BY ord, id",
    ) {
        if let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        }) {
            for (field, action_s, role, tenant, env, ord, id) in rows.flatten() {
                let field = normalize_field(&field);
                if field.is_empty() {
                    continue;
                }
                let action = parse_action(&action_s);
                // DENY sur une colonne RÉELLE -> authorizer (déni all-roles, admin compris, même SQL brut).
                if action == MaskAction::Deny && PHYSICAL_EVENT_COLS.contains(&field.as_str()) {
                    deny_cols.insert(field.clone());
                }
                let specificity =
                    (!env.is_empty()) as u8 + (!tenant.is_empty()) as u8 + (!role.is_empty()) as u8;
                out.push(CompiledFilter { field, action, role, tenant, env, specificity, ord, id });
            }
        }
    }
    // most-specific-wins : tri croissant de spécificité (puis ord, id) -> à l'application, le plus spécifique
    // (dernier) écrase dans la map.
    out.sort_by(|a, b| a.specificity.cmp(&b.specificity).then(a.ord.cmp(&b.ord)).then(a.id.cmp(&b.id)));
    // sel de HASH (immuable, posé par migrate_v86). Absent (base pré-v86) -> "".
    let salt: String = conn
        .query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0))
        .unwrap_or_default();
    { let mut w = filters_cell().write();
        w.insert(db_path.to_string(), Arc::new(out));
    }
    { let mut w = field_deny_cols_cell().write();
        w.insert(db_path.to_string(), deny_cols);
    }
    { let mut w = salt_cell().write();
        w.insert(db_path.to_string(), salt);
    }
}

/// Jeu de masques EFFECTIF pour l'appelant (role/tenant/env). VIDE si aucune règle applicable -> compilation
/// GXQL byte-identique (mode 0). FAIL-CLOSED : `role` inconnu -> rank 0 -> masqué par toute règle.
pub(crate) fn effective_masks(db_path: &str, role: &str, tenant: &str, env: Option<&str>) -> FieldMaskSet {
    let mut set = FieldMaskSet::new();
    let rules = match filters_cell().read().get(db_path).cloned() {
        Some(r) => r,
        None => return set, // pas de registre -> mode 0
    };
    if rules.is_empty() {
        return set;
    }
    let caller_rank = role_rank(role); // fail-closed : rôle inconnu -> 0 (masqué par tout)
    let env = env.unwrap_or("");
    // Passe 1 — résolution par SPÉCIFICITÉ (most-specific écrase). Rules triées spécificité ASC.
    for r in rules.iter() {
        if !r.tenant.is_empty() && r.tenant != tenant {
            continue;
        }
        if !r.env.is_empty() && r.env != env {
            continue;
        }
        if caller_rank > role_threshold(&r.role, r.action) {
            continue; // appelant trop privilégié pour CETTE règle
        }
        set.insert(r.field.clone(), r.action);
    }
    // Passe 2 — DENY est une CLASSE DURE (comme la denylist de secrets) : elle ne doit JAMAIS être rétrogradée
    // par une règle plus faible mais plus spécifique (ex : `pan deny role=''` battu par `pan mask role=admin`
    // dont le seuil admin=3 masquerait aussi viewer/editor -> pan passerait de Deny à Mask). On ré-applique
    // donc TOUTE règle Deny applicable (tenant/env, seuil DENY=tous) en overlay FINAL inconditionnel : un champ
    // avec un Deny applicable finit TOUJOURS en Deny, quel que soit l'ordre/la spécificité des autres règles.
    for r in rules.iter() {
        if r.action != MaskAction::Deny {
            continue;
        }
        if !r.tenant.is_empty() && r.tenant != tenant {
            continue;
        }
        if !r.env.is_empty() && r.env != env {
            continue;
        }
        // role_threshold(Deny) = 3 -> s'applique à TOUS les rôles (admin compris) : pas de garde de rank.
        set.insert(r.field.clone(), MaskAction::Deny);
    }
    set
}

/// Le jeu de masques contient-il AU MOINS une CLÉ DU SAC JSON (champ non-physique, ex src_user/email/pan) ?
/// Sert aux gardes /api/search : un filtre `fields:` ou plein-texte (si FTS_FIELDS) probe des clés JSON ->
/// à refuser si l'une d'elles est masquée pour l'appelant.
pub(crate) fn masks_touch_json_keys(masks: &FieldMaskSet) -> bool {
    masks.field_names().any(|f| !PHYSICAL_EVENT_COLS.contains(&f))
}

/// GARDE /api/search (#45) — fonction PURE (testable) répliquant l'analyse de tokens du handler `search`.
/// Refuse tout FILTRE qui SONDERAIT un champ masqué (chaque comparaison structurée/regex/joker est un oracle
/// par nombre de lignes), le blob `fields` BRUT (probe des clés JSON masquées), et la recherche PLEIN-TEXTE
/// (FTS scanne message/source/category, + valeurs JSON si `fts_fields`). Renvoie `Err(champ)` au 1er filtre
/// interdit, `Ok(())` sinon. VIDE -> `Ok(())` (mode 0, jamais restrictif). Miroir EXACT de la boucle du
/// handler (mêmes `search_tokens`/`soql_glue_spaced_ops`/`field_col`).
pub(crate) fn search_mask_guard(term: &str, masks: &FieldMaskSet, fts_fields: bool) -> Result<(), String> {
    if masks.is_empty() {
        return Ok(());
    }
    let json_key_masked = masks_touch_json_keys(masks);
    let mut has_free_text = false;
    for tok in soql_glue_spaced_ops(search_tokens(term)) {
        let low = tok.to_ascii_lowercase();
        if low.starts_with("limit:") || low.starts_with("limit=") || low.starts_with("max:") || low.starts_with("max=") {
            continue;
        }
        if low.starts_with("regex=") || low.starts_with("regex:") {
            if masks.get("message").is_some() {
                return Err("message".into());
            }
            continue;
        }
        if let Some(i) = tok.find(|c| c == ':' || c == '=') {
            if let Some(col) = field_col(&tok[..i].to_ascii_lowercase()) {
                if col == "fields" {
                    if json_key_masked {
                        return Err("fields".into());
                    }
                } else if masks.get(col).is_some() {
                    return Err(col.to_string());
                }
                continue;
            }
        }
        has_free_text = true;
    }
    if has_free_text {
        let ft_col_masked = ["message", "source", "category"].iter().any(|c| masks.get(c).is_some());
        if ft_col_masked || (fts_fields && json_key_masked) {
            return Err("plein-texte".into());
        }
    }
    Ok(())
}

/// Sel de HASH caché pour ce db_path (masquage Rust des surfaces non-GXQL). "" si inconnu.
fn salt_for(db_path: &str) -> String {
    salt_cell().read().get(db_path).cloned().unwrap_or_default()
}

/// Hachage DÉTERMINISTE salé partagé par le SQL (`plume_fmask_hash`) et le masquage Rust. SHA-256(sel||valeur)
/// tronqué en 16 hex : corrélation préservée (même valeur -> même hash), non réversible sans le sel.
pub(crate) fn fmask_hash(salt: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"\x00");
    h.update(value.as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(16);
    for b in &d[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Applique une action de masque à une VALEUR JSON déjà lue (surfaces NON-GXQL : /api/search, timeline de
/// cas). Miroir EXACT de la sémantique SQL de `mask_wrap` (Mask -> `***`, MaskPartial -> `***`+last4,
/// Hash -> `plume_fmask_hash`, Redact/Deny -> Null). NULL/absent reste inchangé.
pub(crate) fn mask_json_value(action: MaskAction, salt: &str, v: &Value) -> Value {
    let s = match v {
        Value::Null => return Value::Null,
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    };
    match action {
        MaskAction::Mask => Value::String("***".into()),
        MaskAction::MaskPartial => {
            let last4: String = s.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
            Value::String(format!("***{last4}"))
        }
        MaskAction::Hash => Value::String(fmask_hash(salt, &s)),
        MaskAction::Redact | MaskAction::Deny => Value::Null,
    }
}

/// Masque une VALEUR unique pour un champ nommé (surfaces ad-hoc : ex `ref_title` d'un item de timeline de
/// cas = `event.message`). Renvoie la valeur INCHANGÉE si le champ n'est pas masqué pour l'appelant.
pub(crate) fn mask_field_value(db_path: &str, masks: &FieldMaskSet, field: &str, v: &Value) -> Value {
    match masks.get(field) {
        Some(action) => mask_json_value(action, &salt_for(db_path), v),
        None => v.clone(),
    }
}

/// Masquage POST-REQUÊTE d'un résultat `{columns, rows}` (run_query_ex) par NOM DE COLONNE : pour les
/// surfaces OPAQUES où le masque ne peut pas être injecté dans le SQL (panneaux SQL BRUT is_soql=0). Caviarde
/// toute cellule d'une colonne dont le NOM correspond à un champ masqué. NB : ne couvre QUE la projection
/// directe (`SELECT src_ip …`) — un agrégat/alias échappe (limite documentée) ; à réserver au SQL brut opaque,
/// JAMAIS au GXQL (déjà masqué dans le SQL -> double-hash). VIDE -> no-op.
pub(crate) fn mask_query_result(db_path: &str, masks: &FieldMaskSet, v: &mut Value) {
    if masks.is_empty() {
        return;
    }
    let salt = salt_for(db_path);
    // indices des colonnes masquées + leur action.
    let cols: Vec<String> = v
        .get("columns")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    let plan: Vec<(usize, MaskAction)> =
        cols.iter().enumerate().filter_map(|(i, c)| masks.get(c).map(|a| (i, a))).collect();
    if plan.is_empty() {
        return;
    }
    if let Some(rows) = v.get_mut("rows").and_then(|r| r.as_array_mut()) {
        for row in rows.iter_mut() {
            if let Some(arr) = row.as_array_mut() {
                for &(i, action) in &plan {
                    if let Some(cell) = arr.get_mut(i) {
                        *cell = mask_json_value(action, &salt, cell);
                    }
                }
            }
        }
    }
}

/// Applique le jeu de masques effectif d'un appelant à une ligne d'événement construite HORS GXQL, indexée
/// par nom de champ (ex : /api/search -> {ts,source,severity,message,host,src_ip}). Chaque champ masqué est
/// remplacé en place. VIDE -> no-op (mode 0). Renvoie true si au moins un champ a été masqué.
pub(crate) fn mask_named_row(db_path: &str, masks: &FieldMaskSet, obj: &mut serde_json::Map<String, Value>) -> bool {
    if masks.is_empty() {
        return false;
    }
    let salt = salt_for(db_path);
    let mut touched = false;
    for (k, v) in obj.iter_mut() {
        if let Some(action) = masks.get(k) {
            *v = mask_json_value(action, &salt, v);
            touched = true;
        }
    }
    touched
}
