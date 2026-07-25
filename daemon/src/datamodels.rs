//! DATA MODELS + PIVOT + DATASETS (#47) — couche SÉMANTIQUE au-dessus du CIM (façon Splunk data models).
//! Ce module porte la LOGIQUE PURE + injection-safe : validation des objets/champs, résolution de la chaîne
//! de contraintes héritées, et surtout le GÉNÉRATEUR de Pivot `pivot_to_soql` (le CRUD HTTP vit dans
//! `handlers::datamodels`).
//!
//! PRINCIPE DE SÛRETÉ CENTRAL : un Pivot ne génère JAMAIS de SQL. Il produit une chaîne **SOQL** (le langage
//! pipe fermé du cœur) qui est ENSUITE compilée par le MÊME chemin que /api/query
//! (`soql_to_sql_masked_x` -> `guatx_core::soql`). Conséquences directes (invariants exigés par #47) :
//!   * MASQUAGE #45 JAMAIS CONTOURNÉ : chaque champ split-by/filtré/projeté traverse `soql_field`/
//!     `soql_filter_field` à la compilation -> un champ masqué reste masqué (split-by) et un filtre sur un
//!     champ masqué échoue-fermé (fail-closed), exactement comme une recherche tapée à la main.
//!   * DENYLIST DE SECRETS #query_exec intacte : le Pivot lit `event` via SOQL -> l'authorizer read-pool
//!     refuse toujours user.hash/token.token_hash/… même en aval (aucune surface SQL brute n'est ouverte).
//!   * ENUM FERMÉE : contraintes d'objet et filtres de Pivot compilent par le compilateur SOQL (jeu de
//!     commandes clos) ; tout ce qui ne parse pas est REJETÉ (aucune injection d'expression arbitraire).
//!   * MODE 0 BYTE-IDENTIQUE : le compilateur du cœur n'est PAS touché ; un data model ne participe à la
//!     compilation QUE lorsqu'un Pivot/dataset est explicitement invoqué. Le chemin de recherche standard
//!     est inchangé (prouvé par `datamodels_mode0_byte_identical`).
//!
//! ALLOWLIST DU PIVOT : un Pivot ne peut split-by/filtrer/agréger QUE des champs DÉCLARÉS dans l'objet
//! (`data_model_field`). C'est le contrat de la couche sémantique (l'objet expose SES champs) ; le masque
//! #45 s'applique EN PLUS (un champ déclaré mais masqué pour le rôle reste masqué / non filtrable).
//!
//! Module PUR (aucune dépendance daemon/rusqlite) : il n'émet que du texte SOQL et compile-vérifie via
//! `guatx_core::soql` (fully-qualified). Le CRUD/DB + I/O HTTP vivent dans `handlers::datamodels`.

/// Champs STRUCTURELS jamais utilisables comme nom d'objet/champ de data model (casseraient le routage/temps/
/// anti-doublon). Miroir du `STRUCTURAL_DENY` de #46 (les contraintes, elles, PEUVENT filtrer sur `ts` etc.).
const DM_STRUCTURAL_DENY: &[&str] = &["id", "dedup", "origin", "engagement_id"];

/// Types de champ acceptés (métadonnée sémantique ; n'altère PAS l'émission SQL — le typage reste indicatif
/// côté cœur, la coercition numérique se fait déjà à la compilation d'un filtre numérique). Fermé -> pas de
/// valeur arbitraire persistée.
pub(crate) const DM_FIELD_TYPES: &[&str] = &["string", "number", "ipv4", "timestamp", "boolean"];

/// Fonctions d'agrégat autorisées dans un Pivot (miroir EXACT du jeu `soql_agg` du cœur — enum fermée).
/// `count` est le seul agrégat sans champ.
pub(crate) const DM_STAT_FUNCS: &[&str] = &["count", "sum", "avg", "min", "max", "dc", "values", "list"];

/// Opérateurs de filtre de Pivot autorisés (fermé). Ils se traduisent en tokens SOQL `field op value` compilés
/// par `table_conds` (donc masque #45 + échappement). `!=`/`=` supportent en plus le joker `*` côté cœur.
pub(crate) const DM_FILTER_OPS: &[&str] = &["=", "!=", ">", "<", ">=", "<="];

/// Valide un NOM d'objet/champ de data model : identifiant SOQL sûr (alphanumérique + '_'), non vide, hors
/// denylist structurelle. Empêche toute interpolation de nom dans le SOQL généré (les noms sont ensuite
/// re-validés `soql_ident_ok` par le compilateur ; double garde).
pub(crate) fn validate_dm_ident(raw: &str) -> Result<String, String> {
    let f = raw.trim();
    if f.is_empty() {
        return Err("identifiant requis".into());
    }
    if !f.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
        return Err(format!("identifiant invalide (alphanumérique + '_' seulement) : {raw}"));
    }
    if DM_STRUCTURAL_DENY.contains(&f) {
        return Err(format!("champ structurel non utilisable : {f}"));
    }
    Ok(f.to_string())
}

/// Valide un type de champ (fermé).
pub(crate) fn validate_dm_ftype(raw: &str) -> Result<String, String> {
    let t = raw.trim().to_ascii_lowercase();
    let t = if t.is_empty() { "string".to_string() } else { t };
    if DM_FIELD_TYPES.contains(&t.as_str()) {
        Ok(t)
    } else {
        Err(format!("type de champ inconnu : {raw} (attendus : {})", DM_FIELD_TYPES.join(", ")))
    }
}

/// Valide une CONTRAINTE d'objet (fragment de filtre SOQL de base) en la COMPILANT via `search <constraint>`
/// sur le chemin SOQL normal (jeu de commandes clos, allowlist d'idents, échappement). Toute contrainte qui ne
/// parse pas / référence un opérateur ou un champ interdit est REJETÉE (fail-closed). Ne persiste rien, ne
/// touche pas la DB. Vide -> OK (objet racine sans contrainte propre).
pub(crate) fn validate_dm_constraint(constraint: &str) -> Result<(), String> {
    let c = constraint.trim();
    if c.is_empty() {
        return Ok(());
    }
    // La contrainte NE DOIT PAS introduire de pipeline (elle est un FILTRE de base, pas un pipeline complet) :
    // on interdit le pipe / les crochets de sous-recherche pour qu'un objet ne puisse pas injecter une étape
    // (`| delete`-like inexistant, mais aussi pas d'`append`/`join` non voulu dans une contrainte de modèle).
    if c.contains('|') || c.contains('[') || c.contains(']') {
        return Err("contrainte : un fragment de filtre ne peut pas contenir de pipeline ('|', '[', ']')".into());
    }
    guatx_core::soql::to_sql(&format!("search {c}"), 0, 0, &guatx_core::soql::Schema::events())
        .map(|_| ())
        .map_err(|e| format!("contrainte SOQL invalide : {e}"))
}

/// Une valeur de FILTRE de Pivot est-elle sûre à insérer dans le texte SOQL généré ? Le découpage de pipeline
/// du cœur (`soql_split_pipes`) opère AVANT la tokenisation et NE respecte PAS les guillemets -> un `|`/`[`/`]`
/// dans une valeur runtime pourrait INJECTER une étape. On REJETTE donc ces caractères structurels + les
/// guillemets (qui basculent l'état du tokenizer) + les caractères de contrôle. C'est le point de sûreté du
/// passage « sélection utilisateur -> texte SOQL » (les valeurs sont ENSUITE ré-échappées `soql_esc` par le
/// compilateur pour le littéral SQL final).
fn pivot_value_ok(v: &str) -> bool {
    !v.is_empty()
        && !v.chars().any(|c| matches!(c, '|' | '[' | ']' | '"' | '\'' | '`' | '\n' | '\r' | '\t' | '\0'))
}

/// Émet le token SOQL `field op value` d'un filtre de Pivot. `field` est déjà validé `validate_dm_ident` ET
/// appartient à l'allowlist de l'objet. `value` est validée par `pivot_value_ok`. Une valeur contenant un
/// espace est mise entre guillemets (le tokenizer du cœur les retire ; sans `|` interne, aucune injection de
/// pipeline). Numérique -> laissée nue (comparaison numérique `>`/`<` correcte).
fn pivot_filter_token(field: &str, op: &str, value: &str) -> Result<String, String> {
    if !DM_FILTER_OPS.contains(&op) {
        return Err(format!("opérateur de filtre interdit : {op}"));
    }
    if !pivot_value_ok(value) {
        return Err(format!(
            "valeur de filtre invalide (caractères structurels SOQL interdits) : {value}"
        ));
    }
    let is_num = {
        let s = value.strip_prefix('-').unwrap_or(value);
        !s.is_empty() && s.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) && s.matches('.').count() <= 1
    };
    let rendered = if is_num {
        value.to_string()
    } else if value.chars().any(|c| c.is_whitespace()) {
        format!("\"{value}\"")
    } else {
        value.to_string()
    };
    Ok(format!("{field}{op}{rendered}"))
}

/// Un agrégat de Pivot : `func` (fermé) + `field` optionnel (`count` seul est sans champ).
#[derive(Clone, Debug)]
pub(crate) struct PivotStat {
    pub func: String,
    pub field: Option<String>,
}

/// Un filtre de Pivot : `field op value` (tous fermés/validés).
#[derive(Clone, Debug)]
pub(crate) struct PivotFilter {
    pub field: String,
    pub op: String,
    pub value: String,
}

/// La spécification d'un Pivot (choisie par l'utilisateur dans l'UI report-builder — AUCUN SPL tapé).
#[derive(Clone, Debug, Default)]
pub(crate) struct PivotSpec {
    pub splitby: Vec<String>,
    pub stats: Vec<PivotStat>,
    pub filters: Vec<PivotFilter>,
    pub span: Option<String>, // Some -> timechart span=<span> (au lieu de stats by)
    pub limit: Option<i64>,
}

/// Le CŒUR de #47 : compile une `PivotSpec` (sur un objet résolu) en une chaîne **SOQL** injection-safe.
///
/// - `constraints` : la chaîne de contraintes HÉRITÉES de l'objet (parent -> enfant), chaque élément étant un
///   fragment de filtre déjà compile-vérifié à la création (`validate_dm_constraint`).
/// - `allowed` : l'ensemble ALLOWLIST des champs déclarés de l'objet. TOUT champ référencé par le Pivot
///   (split-by / champ d'agrégat / champ de filtre) DOIT y appartenir, sinon REJET (fail-closed).
///
/// Le SOQL produit a la forme : `search <constraints> <filtres> | stats|timechart <aggs> by <splitby> | head N`.
/// Il n'y a AUCUNE émission SQL ici : la sûreté finale (masquage #45, échappement, coercition numérique, enum
/// de commandes) est celle du compilateur du cœur, atteint via `soql_to_sql_masked_x`.
pub(crate) fn pivot_to_soql(
    constraints: &[String],
    allowed: &std::collections::HashSet<String>,
    spec: &PivotSpec,
) -> Result<String, String> {
    // 1) BASE : `search` + contraintes héritées + filtres du Pivot (allowlist + valeurs sûres).
    let mut base = String::from("search");
    for c in constraints {
        let c = c.trim();
        if !c.is_empty() {
            base.push(' ');
            base.push_str(c);
        }
    }
    for f in &spec.filters {
        let field = validate_dm_ident(&f.field)?;
        if !allowed.contains(&field) {
            return Err(format!("champ de filtre non déclaré dans l'objet : {field}"));
        }
        base.push(' ');
        base.push_str(&pivot_filter_token(&field, f.op.trim(), &f.value)?);
    }

    // 2) SPLIT-BY : valider chaque champ contre l'allowlist (le masque #45 s'appliquera à la compilation).
    let mut by: Vec<String> = Vec::new();
    for s in &spec.splitby {
        let field = validate_dm_ident(s)?;
        if !allowed.contains(&field) {
            return Err(format!("champ split-by non déclaré dans l'objet : {field}"));
        }
        by.push(field);
    }
    let by_clause = if by.is_empty() { String::new() } else { format!(" by {}", by.join(",")) };

    // 3) AGRÉGATS : func fermé + champ (sauf count) validé contre l'allowlist.
    let mut aggs: Vec<String> = Vec::new();
    for st in &spec.stats {
        let func = st.func.trim();
        if !DM_STAT_FUNCS.contains(&func) {
            return Err(format!("fonction d'agrégat interdite : {func}"));
        }
        if func == "count" && st.field.as_deref().unwrap_or("").trim().is_empty() {
            aggs.push("count".to_string());
            continue;
        }
        let raw = st.field.as_deref().unwrap_or("").trim();
        if raw.is_empty() {
            return Err(format!("l'agrégat '{func}' requiert un champ"));
        }
        let field = validate_dm_ident(raw)?;
        if !allowed.contains(&field) {
            return Err(format!("champ d'agrégat non déclaré dans l'objet : {field}"));
        }
        aggs.push(format!("{func}({field})"));
    }

    // 4) ÉTAGE STATS/TIMECHART.
    let mut pipeline = base;
    if let Some(span) = spec.span.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        // timechart span=<span> <aggs> [by <splitby>]. Span validé par le cœur (soql_dur) à la compilation.
        if !span.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("span invalide : {span}"));
        }
        let a = if aggs.is_empty() { "count".to_string() } else { aggs.join(",") };
        pipeline.push_str(&format!(" | timechart span={span} {a}{by_clause}"));
    } else if !aggs.is_empty() {
        pipeline.push_str(&format!(" | stats {}{by_clause}", aggs.join(",")));
    } else if !by.is_empty() {
        // split-by sans agrégat -> distinct par groupe : `stats count by ...` (Pivot minimal utile).
        pipeline.push_str(&format!(" | stats count{by_clause}"));
    }
    // sinon : ni agrégat ni split-by -> recherche filtrée brute (lignes de l'objet).

    // 5) HEAD borné (anti-explosion de page ; le run applique EN PLUS le plafond de run_query_ex).
    let n = spec.limit.filter(|&n| n > 0 && n <= 100_000).unwrap_or(1000);
    pipeline.push_str(&format!(" | head {n}"));
    Ok(pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guatx_core::soql::{FieldMaskSet, MaskAction, Schema};
    use std::collections::HashSet;

    fn allow(fields: &[&str]) -> HashSet<String> {
        fields.iter().map(|s| s.to_string()).collect()
    }

    // ------- Génération de base : SOQL attendu, déterministe -----------------------------------
    #[test]
    fn pivot_generates_expected_soql() {
        let spec = PivotSpec {
            splitby: vec!["user".into()],
            stats: vec![PivotStat { func: "count".into(), field: None }],
            filters: vec![PivotFilter { field: "action".into(), op: "=".into(), value: "failure".into() }],
            span: None,
            limit: Some(50),
        };
        let soql = pivot_to_soql(
            &["category=auth".to_string()],
            &allow(&["user", "action"]),
            &spec,
        )
        .unwrap();
        assert_eq!(soql, "search category=auth action=failure | stats count by user | head 50");
        // Et il compile en SQL read-only via le compilateur du cœur (aucun chemin SQL neuf).
        assert!(guatx_core::soql::to_sql(&soql, 0, 0, &Schema::events()).is_ok());
    }

    // ------- MODE 0 BYTE-IDENTIQUE (parité gelée) ---------------------------------------------
    // Un Pivot sans contrainte/masque produit EXACTEMENT le SOQL tapé à la main, et il compile
    // BYTE-IDENTIQUEMENT à cette recherche manuelle -> la couche data-model n'ouvre aucun chemin
    // d'émission neuf ; le compilateur du cœur reste la seule source de vérité (mode 0 préservé).
    #[test]
    fn datamodels_mode0_byte_identical() {
        let spec = PivotSpec {
            splitby: vec!["host".into()],
            stats: vec![PivotStat { func: "count".into(), field: None }],
            filters: vec![],
            span: None,
            limit: Some(1000),
        };
        let generated = pivot_to_soql(&[], &allow(&["host"]), &spec).unwrap();
        let hand = "search | stats count by host | head 1000";
        assert_eq!(generated, hand);
        let a = guatx_core::soql::to_sql(&generated, 0, 0, &Schema::events()).unwrap();
        let b = guatx_core::soql::to_sql(hand, 0, 0, &Schema::events()).unwrap();
        assert_eq!(a, b, "le SOQL Pivot compile byte-identique à la recherche manuelle");
        // Contrôle négatif : la présence de la couche n'altère pas une recherche ordinaire indépendante.
        let plain = guatx_core::soql::to_sql("search host=web01 | stats count", 0, 0, &Schema::events()).unwrap();
        assert!(plain.contains("FROM event"));
    }

    // ------- MASQUAGE NON CONTOURNÉ via un SPLIT-BY de Pivot -----------------------------------
    #[test]
    fn masking_not_bypassed_by_pivot_splitby() {
        // `user` masqué (Hash). Un split-by du Pivot dessus -> le SQL agrège la valeur DÉJÀ masquée.
        let mut m = FieldMaskSet::new();
        m.insert("user", MaskAction::Hash);
        let spec = PivotSpec {
            splitby: vec!["user".into()],
            stats: vec![PivotStat { func: "count".into(), field: None }],
            filters: vec![],
            span: None,
            limit: Some(100),
        };
        let soql = pivot_to_soql(&[], &allow(&["user", "host"]), &spec).unwrap();
        let sql = guatx_core::soql::to_sql(&soql, 0, 0, &Schema::events().with_masks(m)).unwrap();
        // La colonne de groupe est le HACHAGE de masque, jamais la valeur brute.
        assert!(sql.contains("plume_fmask_hash(json_extract(fields,'$.user'))"), "{sql}");
        assert!(!sql.contains("GROUP BY json_extract(fields,'$.user')\n"), "{sql}");
    }

    // ------- MASQUAGE NON CONTOURNÉ via un FILTRE de Pivot (fail-closed) -----------------------
    #[test]
    fn masking_not_bypassed_by_pivot_filter() {
        // `user` masqué (Mask). Un FILTRE de Pivot dessus est un ORACLE -> compilation REJETÉE (fail-closed),
        // exactement comme un filtre tapé à la main (#45).
        let mut m = FieldMaskSet::new();
        m.insert("user", MaskAction::Mask);
        let spec = PivotSpec {
            splitby: vec!["host".into()],
            stats: vec![PivotStat { func: "count".into(), field: None }],
            filters: vec![PivotFilter { field: "user".into(), op: "=".into(), value: "alice".into() }],
            span: None,
            limit: None,
        };
        let soql = pivot_to_soql(&[], &allow(&["user", "host"]), &spec).unwrap();
        let r = guatx_core::soql::to_sql(&soql, 0, 0, &Schema::events().with_masks(m));
        assert!(r.is_err(), "un filtre de Pivot sur un champ masqué doit échouer-fermé : {r:?}");
    }

    // ------- MASQUAGE NON CONTOURNÉ via la CONTRAINTE d'un objet -------------------------------
    #[test]
    fn masking_not_bypassed_by_object_constraint() {
        // La contrainte d'objet filtre sur un champ masqué -> REJET à la compilation (même oracle).
        let mut m = FieldMaskSet::new();
        m.insert("user", MaskAction::Mask);
        let spec = PivotSpec { splitby: vec!["host".into()], stats: vec![], filters: vec![], span: None, limit: None };
        let soql = pivot_to_soql(&["user=alice".to_string()], &allow(&["host"]), &spec).unwrap();
        assert!(guatx_core::soql::to_sql(&soql, 0, 0, &Schema::events().with_masks(m)).is_err());
    }

    // ------- DENYLIST DE SECRETS : un champ déclaré ne peut pas exposer un secret ---------------
    // On ne peut pas déclarer un champ nommé `hash` comme colonne réelle secrète : de toute façon le Pivot
    // ne lit que `event` (fields JSON), et l'authorizer read-pool refuse user.hash même en aval. Ici on prouve
    // que le SOQL généré ne référence QUE la table `event` (aucune table de secrets atteinte).
    #[test]
    fn pivot_only_touches_event_table() {
        let spec = PivotSpec {
            splitby: vec!["user".into()],
            stats: vec![PivotStat { func: "dc".into(), field: Some("src_ip".into()) }],
            filters: vec![],
            span: None,
            limit: Some(10),
        };
        let soql = pivot_to_soql(&[], &allow(&["user", "src_ip"]), &spec).unwrap();
        let sql = guatx_core::soql::to_sql(&soql, 0, 0, &Schema::events()).unwrap();
        assert!(sql.contains("FROM event"), "{sql}");
        assert!(!sql.to_lowercase().contains("from user"), "{sql}");
        assert!(!sql.to_lowercase().contains("token"), "{sql}");
    }

    // ------- ALLOWLIST : un champ non déclaré est refusé (couche sémantique) --------------------
    #[test]
    fn pivot_rejects_undeclared_field() {
        let spec = PivotSpec {
            splitby: vec!["secret_field".into()],
            stats: vec![],
            filters: vec![],
            span: None,
            limit: None,
        };
        assert!(pivot_to_soql(&[], &allow(&["user"]), &spec).is_err());
    }

    // ------- INJECTION DE PIPELINE : une valeur de filtre ne peut pas introduire d'étape --------
    #[test]
    fn pivot_filter_value_cannot_inject_pipeline() {
        let spec = PivotSpec {
            splitby: vec![],
            stats: vec![PivotStat { func: "count".into(), field: None }],
            filters: vec![PivotFilter {
                field: "user".into(),
                op: "=".into(),
                value: "x | delete".into(), // tentative d'injection de pipe
            }],
            span: None,
            limit: None,
        };
        assert!(
            pivot_to_soql(&[], &allow(&["user"]), &spec).is_err(),
            "une valeur de filtre avec '|' doit être rejetée (anti-injection de pipeline)"
        );
        // Idem crochets de sous-recherche.
        let spec2 = PivotSpec {
            filters: vec![PivotFilter { field: "user".into(), op: "=".into(), value: "a[b]".into() }],
            ..PivotSpec::default()
        };
        assert!(pivot_to_soql(&[], &allow(&["user"]), &spec2).is_err());
    }

    // ------- CONTRAINTE : compile-check + refus du pipeline ------------------------------------
    #[test]
    fn constraint_validation() {
        assert!(validate_dm_constraint("category=auth action=failure").is_ok());
        assert!(validate_dm_constraint("").is_ok());
        assert!(validate_dm_constraint("category=auth | delete").is_err()); // pipeline interdit
        assert!(validate_dm_constraint("category=auth [search x]").is_err()); // sous-recherche interdite
    }

    #[test]
    fn ident_and_type_validation() {
        assert!(validate_dm_ident("src_user").is_ok());
        assert!(validate_dm_ident("bad-name").is_err());
        assert!(validate_dm_ident("id").is_err()); // structurel
        assert_eq!(validate_dm_ftype("").unwrap(), "string");
        assert_eq!(validate_dm_ftype("IPv4").unwrap(), "ipv4");
        assert!(validate_dm_ftype("blob").is_err());
    }
}
