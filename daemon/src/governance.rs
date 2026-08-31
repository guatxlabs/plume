//! #59 GOUVERNANCE ENTREPRISE (reliquat DIFFÉRÉ de #38). TROIS primitives, cœurs PURS (testables sans
//! AppState), branchés sur les chemins existants sans les affaiblir :
//!
//!  1. LEGAL-HOLD / RÉTENTION-LOCK (`legal_hold`, per-tenant). Une ligne active ÉPINGLE les events dont la
//!     portée (source + fenêtre temporelle) matche CONTRE toute suppression par `retention_run` (purge
//!     globale + per-index #49 + plafonds). Enforcement FAIL-CLOSED : si l'état des holds ne peut être
//!     déterminé (table illisible), on S'ABSTIENT de purger `event` (jamais de suppression d'une preuve
//!     dont on ne peut prouver qu'elle n'est pas retenue). Mode 0 (aucun hold) -> AUCUN prédicat ajouté ->
//!     texte SQL byte-identique à l'historique. La portée couvre le TABLE `event` (preuve brute) ; les
//!     rollups dérivés (agrégats reconstructibles, non-preuve) ne sont PAS épinglés — assumé et documenté.
//!
//!  2. EXPORT STREAMING DU LEDGER (chaîne préservée). Cœurs `ledger_export_lines` (READ-ONLY sur `ledger`,
//!     aucun chemin de mutation) + `ledger_verify_export` (un vérificateur EXTERNE recalcule la chaîne de
//!     hash sur la copie exportée -> détecte toute altération). L'export ÉMET la chaîne complète
//!     (prev_hash + hash + id/ts/kind/detail) : c'est exactement ce que `verify_run` recompute -> une copie
//!     WORM externe reste vérifiable indépendamment. La signature ed25519 des checkpoints n'est jamais
//!     affaiblie (export = SELECT seul).
//!
//!  3. RÔLES COMPOSABLES (`role_def`, control-plane, catalogue global géré par le super-admin). Un rôle
//!     custom résout vers un `base_role` ∈ {viewer,editor,admin} : c'est SON PLAFOND (l'escalade est
//!     structurellement impossible — un rôle custom n'est jamais plus fort que sa base). Un ensemble
//!     `deny_perms` SOUSTRAIT des capacités (raw_sql, arm_response…) — jamais n'en ajoute (l'additif est
//!     DIFFÉRÉ, précisément parce que c'est le vecteur d'escalade). DEFAULT-DENY préservé : un nom de rôle
//!     INCONNU résout vers "" (rang 0 -> refusé). Le catalogue VIDE (mode 0 / pas de rôle custom) laisse
//!     `rbac_gate`/`raw_sql_allowed` byte-identiques (les rôles de base court-circuitent avant toute
//!     résolution custom).
use crate::*;

// =====================================================================================
// 1. LEGAL-HOLD — enforcement fail-closed dans le chemin de rétention
// =====================================================================================

/// Une table `event` existe-t-elle un hold ACTIF qui l'épingle ? Décision d'enforcement pour `retention_run`.
pub(crate) enum HoldEnforce {
    /// Aucun hold (table absente = pré-v96, OU zéro ligne active) -> purge INCHANGÉE (mode 0 byte-identique).
    NoHolds,
    /// >=1 hold actif -> le fragment WHERE `NOT (event est retenu)` à ANDer aux DELETE sur `event`.
    Guard(String),
    /// L'état des holds n'a PAS pu être déterminé alors que la table EXISTE -> FAIL-CLOSED : ne PAS purger
    /// `event` ce tick (on ne supprime jamais une preuve dont on ne peut prouver qu'elle n'est pas retenue).
    FailClosed,
}

/// Fragment WHERE : « cet event N'EST PAS retenu par un hold actif ». Corrélé à la ligne `event` en cours de
/// DELETE (référence `event.source`/`event.ts`, valides dans `DELETE FROM event WHERE …`). scope_source=''
/// -> tous ; fenêtre [start,end] ouverte si 0. LITTÉRAL interne (aucune entrée utilisateur interpolée).
pub(crate) const LEGAL_HOLD_NOT_HELD: &str =
    "NOT EXISTS (SELECT 1 FROM legal_hold h WHERE h.active=1 \
       AND (h.scope_source='' OR h.scope_source=event.source) \
       AND (h.scope_start_ts=0 OR event.ts>=h.scope_start_ts) \
       AND (h.scope_end_ts=0 OR event.ts<=h.scope_end_ts))";

/// COUVERTURE HOLD DES TABLES SANS COLONNE `source` (`alert` = texte d'alerte synthétisé, `snapshot` =
/// captures d'état forensiques) — CRITICAL #59. Ces deux tables portent une preuve NON-reconstructible mais
/// AUCUN `source` : un hold SCOPÉ à une source ne peut donc les matcher. La sémantique retenue : SEUL un hold
/// à portée GLOBALE (`scope_source=''`) épingle une ligne alert/snapshot, et UNIQUEMENT si sa fenêtre `ts`
/// la couvre. Autrement dit, un hold global bloque les TROIS classes (event + alert + snapshot) sur sa
/// fenêtre ; un hold source-scopé ne bloque QUE `event` (via LEGAL_HOLD_NOT_HELD). Fragment corrélé à la
/// ligne en cours de DELETE (`<tscol>` = littéral interne `ts` — jamais d'entrée utilisateur interpolée).
pub(crate) fn legal_hold_not_held_global(tscol: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM legal_hold h WHERE h.active=1 AND h.scope_source='' \
           AND (h.scope_start_ts=0 OR {tscol}>=h.scope_start_ts) \
           AND (h.scope_end_ts=0 OR {tscol}<=h.scope_end_ts))"
    )
}

/// True si la table `name` existe dans le schéma courant (distingue « pré-v96 » de « erreur d'accès »).
pub(crate) fn table_present(conn: &Connection, name: &str) -> bool {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", params![name], |_| Ok(()))
        .is_ok()
}

/// Décision d'enforcement legal-hold pour `retention_run` (FAIL-CLOSED). Cf. HoldEnforce.
pub(crate) fn legal_hold_enforcement(conn: &Connection) -> HoldEnforce {
    // 1) Présence de la table, en DISTINGUANT « absente » (pré-v96, sûr) de « schéma illisible » (incertain).
    //    Si sqlite_master lui-même n'est pas lisible -> on ne peut RIEN affirmer -> FAIL-CLOSED (ne pas purger).
    match conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='legal_hold'", [], |r| r.get::<_, i64>(0)) {
        Err(_) => HoldEnforce::FailClosed,
        Ok(0) => HoldEnforce::NoHolds, // table absente (base pré-v96) -> purge byte-identique (mode 0)
        Ok(_) => {
            // 2) Table présente : toute erreur de lecture du compte des holds actifs = incertitude -> FAIL-CLOSED.
            match conn.query_row("SELECT COUNT(*) FROM legal_hold WHERE active=1", [], |r| r.get::<_, i64>(0)) {
                Ok(0) => HoldEnforce::NoHolds,
                Ok(_) => HoldEnforce::Guard(LEGAL_HOLD_NOT_HELD.to_string()),
                Err(_) => HoldEnforce::FailClosed,
            }
        }
    }
}

/// Un event unitaire (source, ts) est-il RETENU par un hold actif ? Utilisé par les tests d'invariant (et
/// par une future prévisualisation). Pur sur &Connection. Fail-safe : erreur -> false (ne retient rien de
/// force côté LECTURE ; la garde de SUPPRESSION, elle, est fail-closed séparément dans legal_hold_enforcement).
pub(crate) fn event_is_held(conn: &Connection, source: &str, ts: i64) -> bool {
    conn.query_row(
        "SELECT 1 FROM legal_hold h WHERE h.active=1 \
           AND (h.scope_source='' OR h.scope_source=?1) \
           AND (h.scope_start_ts=0 OR ?2>=h.scope_start_ts) \
           AND (h.scope_end_ts=0 OR ?2<=h.scope_end_ts) LIMIT 1",
        params![source, ts],
        |_| Ok(()),
    )
    .is_ok()
}

// =====================================================================================
// 2. LEDGER — export streaming (chaîne préservée) + vérification externe
// =====================================================================================

/// Une ligne d'export du ledger, CANONIQUE : porte la chaîne complète (prev_hash + hash) pour qu'un
/// vérificateur externe recompute exactement ce que `verify_run` recompute. JSON (ordre de clés
/// déterministe via serde_json). READ-ONLY : construit depuis un SELECT, jamais réinjecté dans le ledger.
pub(crate) fn ledger_export_line(id: i64, ts: i64, kind: &str, detail: &str, prev_hash: &str, hash: &str) -> String {
    json!({
        "id": id, "ts": ts, "kind": kind, "detail": detail,
        "prev_hash": prev_hash, "hash": hash
    })
    .to_string()
}

/// Lit une TRANCHE du ledger (`id > from_id`, ordre croissant, borné `limit`) et rend (lignes JSONL,
/// dernier id, dernier hash). SELECT SEUL sur `ledger` -> AUCUN chemin de mutation (l'append-only reste
/// intact). `limit<=0` -> pas de borne (export complet).
///
/// `P10.7-s` — UNE TRANCHE QU'ON NE SAIT PAS LIRE N'EST PAS UNE TRANCHE VIDE, ET CE TYPE LE DIT. Jusqu'au
/// 2026-08-31 cette fonction APLATISSAIT : un `let Ok(…) else { return vide }` sur le préparatif, un
/// `flatten()` sur les lignes. Deux formes MESURÉES ce jour-là, et elles ne coûtent pas la même chose :
///
///  1. PRÉPARATIF RATÉ (table `ledger` absente, clé SQLCipher absente/incorrecte) -> ZÉRO ligne, curseur
///     inchangé, et `ledger_verify_export(&[], "")` rend `Ok(0)` : « export OK : 0 entrées chaînées
///     intègres ». Un verdict d'intégrité sur une copie qui n'a jamais été lue.
///  2. LIGNE ILLISIBLE (colonne d'un type inattendu — restauration partielle, écriture SQL directe). Deux
///     sous-formes, et la MESURE a REFUSÉ la version courte de l'énoncé qui a ouvert cette clé :
///       · la ligne illisible est la DERNIÈRE (3 maillons, le 3e abîmé) -> 2 lignes, `Ok(2)` du
///         vérificateur : « intègre », littéralement le faux vert annoncé. Curseur à 2 -> l'envoi suivant
///         relit la même ligne illisible, rend zéro, et la route répond `"exported": 0` : la copie WORM
///         est GELÉE, définitivement, sans un mot ;
///       · la ligne illisible est au MILIEU (le 2e des 3) -> 2 lignes AUSSI, mais le vérificateur d'export
///         les REJETTE (`rupture de chaîne`, ancrage `prev_hash`). L'énoncé disait « également déclarés
///         intègres » : c'est FAUX de cette sous-forme. Ce qui est vrai, et pire, c'est le CURSEUR : il
///         avance à 3, donc le maillon #2 n'entre JAMAIS dans la copie inaltérable — une lacune
///         PERMANENTE — et aucun appelant de production n'interroge le vérificateur sur ce chemin
///         (`ledger_sink_flush` écrit puis avance), si bien que ce refus-là n'est LU par personne.
///
/// LA LOI EST DONC CELLE DES VÉRIFICATEURS VOISINS (`verify_ledger_conn`, `control_ledger_verify_conn`),
/// À LA LETTRE : ce que la lecture ne rend PAS -> `Err`, aucun export. Ce qu'elle rend -> exporté, y
/// compris un `detail` NULL (seul nullable de la table), qui vaut chaîne vide comme en production.
///
/// CE QU'ON N'A PAS FAIT, ET C'EST DÉLIBÉRÉ : `ledger_verify_export` n'est PAS durci à rejeter un export
/// VIDE. Un export incrémental est LÉGITIMEMENT vide quand rien n'est neuf ; l'y forcer troquerait le faux
/// vert contre une fausse accusation, tous les jours. La distinction se fait ICI, à la LECTURE, où elle est
/// connue — pas plus tard, par une heuristique sur une longueur.
pub(crate) fn ledger_export_lines(conn: &Connection, from_id: i64, limit: i64) -> Result<(Vec<String>, i64, String), String> {
    let sql = if limit > 0 {
        "SELECT id,ts,kind,detail,prev_hash,hash FROM ledger WHERE id>?1 ORDER BY id ASC LIMIT ?2".to_string()
    } else {
        "SELECT id,ts,kind,detail,prev_hash,hash FROM ledger WHERE id>?1 ORDER BY id ASC".to_string()
    };
    let mut out = Vec::new();
    let (mut last_id, mut last_hash) = (from_id, String::new());
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("lecture ledger (table absente ? clé SQLCipher manquante/incorrecte ?): {e} — AUCUN export"))?;
    let bind: Vec<&dyn rusqlite::ToSql> = if limit > 0 { vec![&from_id, &limit] } else { vec![&from_id] };
    let rows = stmt
        .query_map(bind.as_slice(), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| format!("scan ledger: {e} — AUCUN export"))?;
    // Le rang est celui du SCAN dans la TRANCHE, pas l'`id` : l'`id` de la ligne fautive est justement ce
    // qu'on n'a pas su lire. Même formulation que les deux vérificateurs voisins.
    for (rang, ligne) in rows.enumerate() {
        let (id, ts, kind, detail, prev_hash, hash) = ligne.map_err(|e| {
            format!("maillon #{} de la tranche ILLISIBLE ({e}) — la tranche n'a pas pu être lue entièrement : AUCUN export, et le curseur NE bouge PAS", rang + 1)
        })?;
        out.push(ledger_export_line(id, ts, &kind, &detail, &prev_hash, &hash));
        last_id = id;
        last_hash = hash;
    }
    Ok((out, last_id, last_hash))
}

/// VÉRIFICATION EXTERNE d'une copie exportée (JSONL) : pour CHAQUE ligne, recompute sha256(prev|ts|kind|
/// detail)==hash (intégrité de l'entrée) ET vérifie prev_hash==hash de la ligne précédente (continuité de
/// chaîne DANS l'export). C'est la MÊME loi que `verify_run` -> un vérificateur tiers (sur un sink WORM)
/// détecte toute altération SANS accès à la base. `expect_prev` = hash attendu AVANT la 1re ligne (pour un
/// export incrémental : le last_hash du curseur ; pour un export complet : "" = genesis). Renvoie le nombre
/// d'entrées vérifiées, ou Err(message) à la 1re rupture.
pub(crate) fn ledger_verify_export(lines: &[String], expect_prev: &str) -> Result<usize, String> {
    let mut prev = expect_prev.to_string();
    let mut n = 0usize;
    for (i, line) in lines.iter().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("ligne {i}: JSON invalide: {e}"))?;
        let id = v.get("id").and_then(|x| x.as_i64()).ok_or_else(|| format!("ligne {i}: id manquant"))?;
        let ts = v.get("ts").and_then(|x| x.as_i64()).ok_or_else(|| format!("ligne {i}: ts manquant"))?;
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
        let detail = v.get("detail").and_then(|x| x.as_str()).unwrap_or("");
        let prev_hash = v.get("prev_hash").and_then(|x| x.as_str()).unwrap_or("");
        let hash = v.get("hash").and_then(|x| x.as_str()).unwrap_or("");
        if prev_hash != prev {
            return Err(format!("ligne {i} (entrée #{id}): rupture de chaîne (prev_hash != hash précédent)"));
        }
        let recomputed = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
        if recomputed != hash {
            return Err(format!("ligne {i} (entrée #{id}): hash altéré (recalcul != hash stocké)"));
        }
        prev = hash.to_string();
        n += 1;
    }
    Ok(n)
}

/// Écrit `lines` (JSONL) vers un sink APPEND-ONLY. Deux kinds sûrs et hors-réseau supportés ici (les sinks
/// réseau syslog/webhook sont un ajout mince, cf. report) : `file` (append au `target`, l'opérateur
/// synchronise ce fichier/dossier vers un object-store à object-lock = WORM) et `stdout`. Renvoie Err si
/// l'écriture échoue (l'appelant NE doit PAS avancer le curseur -> re-tentera la même tranche : at-least-once,
/// jamais de trou dans la copie WORM).
pub(crate) fn ledger_sink_write(kind: &str, target: &str, lines: &[String], confine_root: Option<&std::path::Path>) -> Result<(), String> {
    if lines.is_empty() {
        return Ok(());
    }
    let body = format!("{}\n", lines.join("\n"));
    match kind {
        "stdout" => {
            print!("{body}");
            use std::io::Write;
            std::io::stdout().flush().map_err(|e| e.to_string())
        }
        "file" => {
            use std::io::Write;
            if target.trim().is_empty() {
                return Err("sink file: target (chemin) vide".into());
            }
            // MEDIUN #59 : quand l'écriture vient du SINK WEB-configurable (`confine_root=Some`), la cible est
            // CONFINÉE à la racine d'export (canonicalisée, anti-`..`), l'ouverture est O_NOFOLLOW (jamais suivre
            // un lien substitué — anti-TOCTOU) et on RE-vérifie sur le FD ouvert que c'est un fichier RÉGULIER
            // (pas de FIFO/-device -> pas de hang/blocage/remplissage arbitraire). Le chemin CLI opérateur
            // (`confine_root=None`, shell de confiance) garde le comportement libre historique.
            let full: std::path::PathBuf = match confine_root {
                Some(root) => ledger_file_target_validate(root, target)?,
                None => std::path::PathBuf::from(target),
            };
            let mut oo = std::fs::OpenOptions::new();
            oo.create(true).append(true);
            if confine_root.is_some() {
                use std::os::unix::fs::OpenOptionsExt;
                oo.custom_flags(libc::O_NOFOLLOW);
            }
            let f = oo.open(&full).map_err(|e| format!("ouverture {}: {e}", full.display()))?;
            if confine_root.is_some() {
                let md = f.metadata().map_err(|e| format!("stat {}: {e}", full.display()))?;
                if !md.is_file() {
                    return Err("target: non-fichier-régulier refusé (FIFO/device/socket)".into());
                }
            }
            let mut f = f;
            f.write_all(body.as_bytes()).map_err(|e| format!("écriture {}: {e}", full.display()))
        }
        other => Err(format!("sink kind non supporté: {other} (attendu: file|stdout)")),
    }
}

/// Racine d'export AUTORISÉE des sinks kind=`file` (#59) : `PLUME_LEDGER_EXPORT_DIR` si défini, sinon
/// `<répertoire de la base>/ledger-export`. Créée best-effort (doit exister pour canonicaliser). Confine
/// les écritures de ledger déclenchées par un admin WEB (rôle SOC) — jamais un chemin hôte arbitraire.
pub(crate) fn ledger_export_root(conf: &HashMap<String, String>) -> std::path::PathBuf {
    let dir = cfg(conf, "PLUME_LEDGER_EXPORT_DIR", "");
    let root = if !dir.trim().is_empty() {
        std::path::PathBuf::from(dir.trim())
    } else {
        let db = cfg(conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        std::path::Path::new(&db).parent().unwrap_or_else(|| std::path::Path::new(".")).join("ledger-export")
    };
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Valide qu'une cible de sink `file` est CONFINÉE dans `root` : le RÉPERTOIRE parent existe et se
/// canonicalise DANS la racine (résout `..`/liens du chemin), le nom de fichier est un composant simple, et —
/// s'il existe déjà — la cible n'est NI un lien symbolique NI un non-fichier-régulier. Renvoie le chemin
/// canonique complet, ou Err(message) si la cible ÉVADE la racine / est un lien / n'est pas régulière. Appelée
/// au CREATE (rejet précoce du sink) ET à l'écriture (défense en profondeur avec O_NOFOLLOW).
pub(crate) fn ledger_file_target_validate(root: &std::path::Path, target: &str) -> Result<std::path::PathBuf, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("sink file: target (chemin) vide".into());
    }
    let root = root.canonicalize().map_err(|e| format!("racine d'export {} inaccessible: {e}", root.display()))?;
    let p = std::path::Path::new(target);
    let file_name = p.file_name().ok_or_else(|| "target: nom de fichier requis (pas un répertoire)".to_string())?;
    let parent = match p.parent() {
        Some(pp) if !pp.as_os_str().is_empty() => pp.to_path_buf(),
        _ => root.clone(),
    };
    let parent_canon = parent
        .canonicalize()
        .map_err(|e| format!("répertoire cible {} inaccessible: {e}", parent.display()))?;
    if !parent_canon.starts_with(&root) {
        return Err(format!("target hors de la racine d'export autorisée {}", root.display()));
    }
    let full = parent_canon.join(file_name);
    if let Ok(md) = std::fs::symlink_metadata(&full) {
        if md.file_type().is_symlink() {
            return Err("target: lien symbolique refusé".into());
        }
        if !md.is_file() {
            return Err("target: non-fichier-régulier refusé (FIFO/device/répertoire)".into());
        }
    }
    Ok(full)
}

// =====================================================================================
// 3. RÔLES COMPOSABLES — catalogue résolu (plafond=base, deny soustractif, default-deny)
// =====================================================================================

/// Un rôle custom résolu : plafond = `base` (∈ viewer/editor/admin), capacités RETIRÉES = `deny`.
#[derive(Clone, Debug)]
pub(crate) struct RoleDef {
    pub base: String,
    pub deny: Vec<String>,
}

/// Perms SOUSTRACTIBLES connues (enum FERMÉ). Un deny_perm HORS de cet ensemble est IGNORÉ au chargement
/// (fail-safe : jamais un flag muet qui « ouvrirait » quelque chose — le deny ne peut que retirer).
pub(crate) const KNOWN_DENY_PERMS: &[&str] =
    &["raw_sql", "arm_response", "ledger_export", "manage_users", "purge_events"];

/// Cache process-global du catalogue de rôles custom (control-plane). VIDE par défaut (mode 0 / aucun rôle
/// custom) -> tous les chemins RBAC restent byte-identiques. Rempli au boot (mode 1) + rafraîchi sur mutation.
pub(crate) static CUSTOM_ROLES: std::sync::OnceLock<Mutex<HashMap<String, RoleDef>>> = std::sync::OnceLock::new();
pub(crate) fn custom_roles_cell() -> &'static Mutex<HashMap<String, RoleDef>> {
    CUSTOM_ROLES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Un nom EST-il un rôle de base intégré ? (court-circuit : jamais résolu comme custom.)
/// #39 CORRECTIVE : `client` (rôle client-read API, rank-0 masqué, confiné aux routes client-read par
/// rbac_gate) est RÉSERVÉ ici -> custom_role_lookup("client")=None -> role_create/grant_set/valid_grant_role
/// REJETTENT le nom (impossible de définir/octroyer un rôle nommé `client` qui hériterait viewer/editor et
/// contournerait le confinement via le pipeline normal SSO/Basic). Ferme la collision de nom (couche a/2).
pub(crate) fn is_builtin_role(role: &str) -> bool {
    matches!(role, "admin" | "editor" | "viewer" | "agent" | "client")
}

/// (control-plane) Recharge le catalogue de rôles custom depuis `role_def`. base_role validé (∈ viewer/
/// editor/admin, sinon la ligne est ÉCARTÉE = fail-safe : un base invalide ne devient jamais un accès) ;
/// deny_perms filtré sur KNOWN_DENY_PERMS. Un nom qui collisionne un rôle de base est ÉCARTÉ (jamais
/// redéfinir admin/editor/viewer/agent). Idempotent, appelable à chaud.
pub(crate) fn reload_custom_roles(cp: &ControlPlane) {
    let mut map: HashMap<String, RoleDef> = HashMap::new();
    let mut raw: Vec<(String, String, String)> = Vec::new();
    let conn = cp.conn.lock();
    if let Ok(mut st) = conn.prepare("SELECT name, base_role, deny_perms FROM role_def") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
            for row in rows.flatten() {
                raw.push(row);
            }
        }
    }
    drop(conn);
    for (name, base, deny_csv) in raw {
        if is_builtin_role(&name) || !matches!(base.as_str(), "admin" | "editor" | "viewer") {
            continue; // fail-safe : jamais redéfinir un rôle de base ni admettre un base invalide.
        }
        let deny: Vec<String> = deny_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| KNOWN_DENY_PERMS.contains(&s.as_str()))
            .collect();
        map.insert(name, RoleDef { base, deny });
    }
    *custom_roles_cell().lock() = map;
}

/// Résout un rôle custom -> sa définition (base + deny). None pour un rôle de base OU un catalogue vide OU
/// un nom inconnu. (Un nom inconnu NON-base est traité par effective_base_role -> "" = deny.)
pub(crate) fn custom_role_lookup(role: &str) -> Option<RoleDef> {
    if is_builtin_role(role) {
        return None;
    }
    custom_roles_cell().lock().get(role).cloned()
}

/// Rôle de BASE effectif d'un nom de rôle (le PLAFOND RBAC) : rôle intégré -> lui-même ; rôle custom défini
/// -> son base_role ; nom INCONNU (ni base, ni custom défini) -> "" (rang 0 -> DEFAULT-DENY). C'est le seul
/// point où un nom devient une autorité : jamais au-dessus de sa base.
pub(crate) fn effective_base_role(role: &str) -> String {
    if is_builtin_role(role) {
        return role.to_string();
    }
    match custom_role_lookup(role) {
        Some(rd) => rd.base,
        None => String::new(), // inconnu -> aucune autorité (fail-closed)
    }
}

/// Un rôle (custom) RETIRE-t-il la permission `perm` ? Rôle de base -> jamais (pas de deny). Rôle custom ->
/// perm ∈ son deny-set. Nom inconnu -> true par prudence (il n'a de toute façon aucune base -> déjà refusé).
pub(crate) fn role_perm_denied(role: &str, perm: &str) -> bool {
    if is_builtin_role(role) {
        return false;
    }
    match custom_role_lookup(role) {
        Some(rd) => rd.deny.iter().any(|p| p == perm),
        None => true,
    }
}
