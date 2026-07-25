//! Réponse / actions (responder) : validation stricte (`action_valid`/`action_valid_ctx`/
//! `action_kind_valid`/`action_kind_destructive`), CRUD/approbation des actions, résolution de
//! commande (`which`/`action_command`), amorçage nft (`ensure_nft_blocklist`) et l'exécuteur root
//! `respond_run`. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// Validation stricte d'une action (utilisée à la création ET par le responder root — défense en profondeur).
/// Délègue à `action_valid_ctx` avec le drapeau engagement RÉEL (byte-identique quand off : le drapeau vaut
/// false -> la clause engagement n'est même pas évaluée -> comportement STRICTEMENT identique à aujourd'hui).
pub(crate) fn action_valid(kind: &str, target: &str, db_path: &str) -> Result<(), String> {
    action_valid_ctx(kind, target, engagement_enabled(), db_path)
}
/// Cœur testable de `action_valid` : `engagement_on` explicite (le drapeau global est injecté par l'appelant).
/// `db_path` = tenant acteur -> le guard Arm A ne consulte QUE le scope de CE tenant (isolation multi-tenant).
pub(crate) fn action_valid_ctx(kind: &str, target: &str, engagement_on: bool, db_path: &str) -> Result<(), String> {
    match kind {
        "ban_ip" | "unban_ip" => {
            let ok = !target.is_empty()
                && target.len() <= 45
                && target.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                && target.contains('.'); // v1 : IPv4
            if !ok { return Err("IPv4 invalide".into()); }
            // M2 : refuse le BAN d'une IP protégée (loopback/privée/opérateur/passerelle). L'unban reste permis
            // (inoffensif : ces IP ne sont jamais bannies -> no-op), on ne bride donc QUE le ban destructif.
            if kind == "ban_ip" && ip_is_protected(target) {
                return Err("IP protégée (loopback/privée/opérateur) — ban refusé".into());
            }
            // ARM A (v75, MODE ENGAGEMENT) : le BAN d'une IP dans le scope d'un engagement ACTIF est REFUSÉ —
            // le daemon suspend SON PROPRE auto-ban (run_playbooks skippe sur action_valid Err), EXACTEMENT comme
            // la protection opérateur. INVARIANT SACRÉ : ceci ne touche QUE l'enforcement (ban) ; run_due_rules
            // continue d'ALERTER et coverage_detections continue de COMPTER (l'attaquant scopé reste DÉTECTÉ,
            // juste pas auto-bloqué -> une exemption compromise est VISIBLE, jamais un angle mort). unban/kill/
            // stop inchangés. Byte-identique quand off : `engagement_on=false` -> clause court-circuitée.
            if kind == "ban_ip" && engagement_on && ip_in_active_engagement(target, db_path) {
                return Err("IP sous engagement autorisé actif — auto-ban suspendu (détection/alerte inchangées)".into());
            }
            Ok(())
        }
        "kill_pid" => match target.parse::<i64>() {
            Ok(p) if p > 300 => Ok(()),
            Ok(_) => Err("PID trop bas (refusé par sécurité)".into()),
            Err(_) => Err("PID invalide".into()),
        },
        "stop_service" => {
            let ok = !target.is_empty()
                && target.len() <= 100
                && target.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
            if ok { Ok(()) } else { Err("nom de service invalide".into()) }
        }
        _ => Err(format!("action inconnue : {kind}")),
    }
}

/// #1c — valide UNIQUEMENT le `kind` d'une action (ENUM FERMÉ), SANS cible, pour la sauvegarde d'un
/// playbook (garde-fou #3). `action_valid(kind,target)` valide kind+cible à l'EXÉCUTION ; à l'écriture
/// la cible n'existe pas encore (elle sort de la requête au runtime), on ne contrôle donc que le kind.
/// Miroir volontaire de l'enum d'`action_valid` : ban_ip | unban_ip | kill_pid | stop_service. Toute
/// autre valeur -> Err (aucune action custom/script : pas de nouvelle surface d'exécution).
pub(crate) fn action_kind_valid(kind: &str) -> Result<(), String> {
    match kind {
        "ban_ip" | "unban_ip" | "kill_pid" | "stop_service" => Ok(()),
        _ => Err(format!("action inconnue : {kind} (attendu ban_ip/unban_ip/kill_pid/stop_service)")),
    }
}

/// Une action de réponse est DESTRUCTIVE (effet réel sur un hôte : ban réseau, kill de process,
/// stop de service). L'ENUM FERMÉ actuel est INTÉGRALEMENT destructif -> poser un playbook qui en porte une
/// = armement d'une réponse automatique (réservé admin, cf validate_detection_content). Isolé pour évoluer si
/// un jour une action non-destructive (ex : `notify`) rejoint l'ENUM (elle resterait alors ouverte à l'editor).
pub(crate) fn action_kind_destructive(kind: &str) -> bool {
    matches!(kind, "ban_ip" | "unban_ip" | "kill_pid" | "stop_service")
}

pub(crate) async fn action_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let kind = b.str_field("kind").to_string();
    let target = b.trimmed("target");
    // db_path du tenant acteur -> le guard Arm A ne consulte que le scope d'engagement de CE tenant.
    if let Err(e) = action_valid(&kind, &target, &req_db_path(&st, &au)) {
        return Json(json!({ "error": e }));
    }
    let dry = b.bool_field("dry_run", true) as i64;
    let alert_id = b.get("alert_id").and_then(|v| v.as_i64());
    let reason = b.str_field("reason");
    // host optionnel : cible explicite (ex : depuis un event de ban qui porte son hôte). Absent/vide ->
    // action NON assignée, réclamée par l'agent du 1er hôte qui poll (cf actions_pending).
    let host = b.get("host").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
    crate::req_conn!(st, au, conn);
    let _ = conn.execute(
        "INSERT INTO action(ts,kind,target,status,dry_run,alert_id,reason,host) VALUES(?1,?2,?3,'pending',?4,?5,?6,?7)",
        params![now(), kind, target, dry, alert_id, reason, host],
    );
    let id = conn.last_insert_rowid();
    ledger_append(&conn, "action.queued", &format!("{kind} {target} dry={dry}"));
    Json(json!({ "id": id }))
}
pub(crate) async fn actions_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let mut stmt = conn.prepare("SELECT id,ts,kind,target,status,dry_run,reason,result,done_ts,host FROM action ORDER BY id DESC LIMIT 100").unwrap();
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "kind": r.get::<_, String>(2)?, "target": r.get::<_, String>(3)?,
            "status": r.get::<_, String>(4)?, "dry_run": r.get::<_, i64>(5)? != 0, "reason": r.get::<_, Option<String>>(6)?,
            "result": r.get::<_, Option<String>>(7)?, "done_ts": r.get::<_, Option<i64>>(8)?, "host": r.get::<_, Option<String>>(9)?
        }))
    }).unwrap();
    Json(json!({ "actions": rows.flatten().collect::<Vec<_>>() }))
}

/// Agent (token) : réclame les actions APPROUVÉES à appliquer sur SON hôte (ban/unban uniquement).
/// Réponse = TSV `id<TAB>kind<TAB>target<TAB>dry_run` (1 par ligne) -> parse trivial en shell, sans jq.
/// Marque chaque action `claimed_ts` (anti double-exécution) ; re-remise auto si pas de résultat sous 5 min.
/// SÉCURITÉ : l'hôte est dérivé du TOKEN (lié à un hôte), pas d'un paramètre -> un agent ne voit/claim
/// QUE les actions de son hôte (anti-IDOR cross-agent). Un token non lié à un hôte est refusé ici.
pub(crate) async fn actions_pending(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if au.role != "agent" || au.name.is_empty() {
        return (StatusCode::FORBIDDEN, "token agent lié à un hôte requis").into_response();
    }
    let host = au.name.clone();
    let now_ts = now();
    const STALE: i64 = 300; // re-remise si réclamée sans résultat depuis > 5 min (agent planté)
    crate::req_conn!(st, au, conn);
    // host=?1 : actions ciblant CET hôte. host NULL/'' : actions non assignées (créées depuis l'UI sans
    // cible explicite) -> réclamables par n'importe quel agent ; à la réclamation on les ASSIGNE à l'hôte
    // réclamant (cf plus bas) pour que action_result (AND host=?) puisse les clôturer + anti double-claim.
    // Anti-IDOR préservé : un agent ne voit JAMAIS une action ciblant un AUTRE hôte (host=<autre> exclu).
    let rows: Vec<(i64, String, String, bool)> = match conn.prepare(
        "SELECT id,kind,target,dry_run FROM action WHERE (host=?1 OR host IS NULL OR host='') AND status='approved' \
         AND kind IN ('ban_ip','unban_ip') AND (claimed_ts IS NULL OR ?2-claimed_ts>?3) ORDER BY id LIMIT 100",
    ) {
        Ok(mut s) => s
            .query_map(params![host, now_ts, STALE], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0)))
            .map(|m| m.flatten().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut body = String::new();
    for (id, kind, target, dry) in &rows {
        // assigne l'action à l'hôte réclamant (no-op si déjà ciblée sur lui) -> action_result peut clôturer
        let _ = conn.execute("UPDATE action SET claimed_ts=?2, host=?3 WHERE id=?1", params![id, now_ts, host]);
        body.push_str(&format!("{id}\t{kind}\t{target}\t{}\n", if *dry { 1 } else { 0 }));
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// Agent (token) : remonte le résultat d'une action appliquée chez lui -> clôt l'action + journalise.
/// Idempotent (n'agit que sur une action encore 'approved'). status: done | failed | dryrun.
/// SÉCURITÉ : ne clôt QUE les actions de l'hôte LIÉ au token (`AND host=?`) -> un agent ne peut pas
/// clôturer/injecter le résultat d'une action d'un autre hôte. `result` borné + nettoyé (anti-injection log).
pub(crate) async fn action_result(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    if au.role != "agent" || au.name.is_empty() {
        return Json(json!({ "ok": false, "error": "token agent lié à un hôte requis" }));
    }
    let host = au.name.clone();
    let id = b.i64_field("id", 0);
    let status = match b.str_field("status") {
        "done" => "done",
        "dryrun" => "dryrun",
        _ => "failed",
    };
    // borne + retire les caractères de contrôle (le résultat finit dans le ledger -> anti log-injection)
    let result: String = b
        .get("result")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect();
    if id == 0 {
        return Json(json!({ "ok": false, "error": "id requis" }));
    }
    crate::req_conn!(st, au, conn);
    let n = conn
        .execute(
            "UPDATE action SET status=?2, result=?3, done_ts=?4 WHERE id=?1 AND status='approved' AND host=?5",
            params![id, status, result, now(), host],
        )
        .unwrap_or(0);
    if n > 0 {
        ledger_append(&conn, "action.remote", &format!("#{id}@{host} -> {status} : {result}"));
    }
    Json(json!({ "ok": n > 0 }))
}
pub(crate) async fn action_approve(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    let _ = conn.execute("UPDATE action SET status='approved' WHERE id=?1 AND status='pending'", params![id]);
    ledger_append(&conn, "action.approved", &format!("id={id}"));
    // BAN NATIF PLUME (chantier ② Phase 1) : l'approbation d'un `ban_ip` NON dry-run ARME AUSSI le blocage HTTP
    // in-process (`net_ban`) -> plume s'auto-enforce pour l'IP réelle, EN PLUS de la décision CrowdSec/nft de
    // l'hôte (exécutée ensuite par le responder/agent). `unban_ip` retire le blocage. Additif : n'altère NI le
    // pipeline responder/agent existant NI le mode 0 (aucune action ban_ip -> aucun net_ban). TTL = mirror 4h
    // CrowdSec ; réversible via unban / DELETE /api/netban. Garde protected-IP redondante (déjà refusée à la
    // création par action_valid) mais défensive.
    if netban_from_actions_enabled() {
        if let Ok((kind, target, dry)) = conn.query_row(
            "SELECT kind, target, dry_run FROM action WHERE id=?1 AND status='approved'",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)),
        ) {
            // Canonicalise (mirror `real_client_ip`) ; les gardes protected/engagement ont déjà tourné à la création.
            let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| target.trim().to_string());
            if kind == "ban_ip" && !dry && !ip_is_protected(&canon) {
                netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: action ban_ip", &au.name, "prod");
            } else if kind == "unban_ip" {
                netban_remove(&conn, &canon);
            }
        }
    }
    StatusCode::NO_CONTENT
}

/// AUTO-INTÉGRATION action->net_ban OPT-IN (anti blast-radius). DÉFAUT **OFF** :
/// une action `ban_ip` (surtout un auto-approve de playbook) ne bloque PAS d'office l'opérateur au niveau HTTP
/// plume — le canal PRIMAIRE reste l'API admin `/api/netban` (pilotée par admin-console). Activable
/// `PLUME_NETBAN_FROM_ACTIONS=1` quand l'opérateur veut que ses actions ban_ip s'auto-enforcent aussi au HTTP.
pub(crate) fn netban_from_actions_enabled() -> bool {
    matches!(
        std::env::var("PLUME_NETBAN_FROM_ACTIONS").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Valide + CANONICALISE une IP pour un ban HTTP `net_ban`. Accepte IPv4 **ET
/// IPv6** (le gate HTTP voit l'IP réelle CF qui peut être v6 ; `action_valid` restait IPv4 pour le chemin nft hôte).
/// CANONICALISE (`IpAddr::to_string()`) -> l'entrée stockée matche EXACTEMENT l'IP calculée par `real_client_ip`
/// (fin du faux no-op `01.02.03.04`). Réutilise les gardes : jamais loopback/privé/opérateur/passerelle
/// (`ip_is_protected`), suspend sous engagement autorisé actif.
pub(crate) fn netban_validate_ip(ip: &str, db_path: &str) -> Result<String, String> {
    let parsed: std::net::IpAddr = ip.trim().parse().map_err(|_| "IP invalide".to_string())?;
    let canon = parsed.to_string();
    if ip_is_protected(&canon) {
        return Err("IP protégée (loopback/privée/opérateur/passerelle) — ban refusé".into());
    }
    if engagement_enabled() && ip_in_active_engagement(&canon, db_path) {
        return Err("IP sous engagement autorisé actif — ban suspendu (détection/alerte inchangées)".into());
    }
    Ok(canon)
}

// ---------- BAN NATIF PLUME — API admin `/api/netban` (chantier ② Phase 1) ----------
// admin-only (route_min_role -> Admin, GET compris) : c'est le canal qu'admin-console (plan de contrôle) appelle
// pour pousser/retirer un blocage HTTP. Par-tenant (req_db). Garde-fous : jamais bannir loopback/privé/opérateur/
// passerelle + engagement (netban_validate_ip). ACCEPTE IPv4+IPv6, canonicalise.

/// GET /api/netban — liste les bans LIVE (net_ban) + le compte des bans ACTIFS (permanent OU expiry futur).
pub(crate) async fn netban_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    let now_ts = now();
    let mut stmt = match conn.prepare(
        "SELECT ip,reason,created_ts,expires_ts,created_by,env_id FROM net_ban ORDER BY created_ts DESC",
    ) {
        Ok(s) => s,
        Err(_) => return Json(json!({ "bans": [], "active": 0 })),
    };
    let bans: Vec<Value> = stmt
        .query_map([], |r| {
            let expires: Option<i64> = r.get(3)?;
            Ok(json!({
                "ip": r.get::<_, String>(0)?,
                "reason": r.get::<_, Option<String>>(1)?,
                "created_ts": r.get::<_, Option<i64>>(2)?,
                "expires_ts": expires,
                "created_by": r.get::<_, Option<String>>(4)?,
                "env_id": r.get::<_, String>(5)?,
                "active": expires.map(|e| e > now_ts).unwrap_or(true),
            }))
        })
        .map(|m| m.flatten().collect())
        .unwrap_or_default();
    let active = bans.iter().filter(|b| b["active"].as_bool().unwrap_or(false)).count();
    Json(json!({ "bans": bans, "active": active }))
}

/// POST /api/netban `{ip, ttl_s?, reason?}` — pose/rafraîchit un ban HTTP. `ttl_s` absent/≤0 = PERMANENT.
pub(crate) async fn netban_add(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; } // défense en profondeur (route déjà admin-only)
    // Valide + CANONICALISE (IPv4/IPv6) : format + IP protégée refusée + engagement -> 400 explicite (anti
    // self-lockout). `ip` DEVIENT la forme canonique stockée (matche `real_client_ip` au gate).
    let ip = match netban_validate_ip(&b.trimmed("ip"), &req_db_path(&st, &au)) {
        Ok(c) => c,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, e),
    };
    let ttl = b.get("ttl_s").and_then(|v| v.as_i64()).filter(|t| *t > 0);
    let expires = ttl.map(|t| now() + t);
    let reason = b.str_field("reason");
    crate::req_conn!(st, au, conn);
    netban_upsert(&conn, &ip, expires, reason, &au.name, "prod");
    ledger_append(&conn, "netban.add", &format!("{ip} ttl={} by={}", ttl.map(|t| t.to_string()).unwrap_or_else(|| "permanent".into()), au.name));
    Json(json!({ "ok": true, "ip": ip, "expires_ts": expires })).into_response()
}

/// DELETE /api/netban/:ip — retire un ban HTTP (réversibilité). Idempotent (retirer une IP absente = ok).
pub(crate) async fn netban_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(ip): Path<String>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let ip = ip.trim().to_string();
    crate::req_conn!(st, au, conn);
    netban_remove(&conn, &ip);
    ledger_append(&conn, "netban.remove", &format!("{ip} by={}", au.name));
    Json(json!({ "ok": true, "ip": ip })).into_response()
}
pub(crate) async fn action_cancel(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    crate::req_conn!(st, au, conn);
    let _ = conn.execute("UPDATE action SET status='cancelled' WHERE id=?1 AND status IN ('pending','approved')", params![id]);
    StatusCode::NO_CONTENT
}

/// Un exécutable est-il dans le PATH ? (pour déléguer aux enforcers existants).
pub(crate) fn which(cmd: &str) -> bool {
    std::env::var("PATH")
        .map(|p| p.split(':').any(|d| std::path::Path::new(d).join(cmd).is_file()))
        .unwrap_or(false)
}

/// Commande système pour une action validée -> (programme, args). Args directs (pas de shell).
/// Principe : DÉLÉGUER le ban d'IP aux enforcers réseau existants (CrowdSec/fail2ban) ; nft = fallback.
pub(crate) fn action_command(kind: &str, target: &str, backend: &str, jail: &str) -> (String, Vec<String>) {
    let s = |v: &str| v.to_string();
    match kind {
        "ban_ip" => match backend {
            "crowdsec" => (s("cscli"), vec![s("decisions"), s("add"), s("--ip"), s(target), s("--duration"), s("4h"), s("--reason"), s("plume")]),
            "fail2ban" => (s("fail2ban-client"), vec![s("set"), s(jail), s("banip"), s(target)]),
            _ => (s("nft"), vec![s("add"), s("element"), s("inet"), s("plume"), s("blocklist"), format!("{{ {target} }}")]),
        },
        "unban_ip" => match backend {
            "crowdsec" => (s("cscli"), vec![s("decisions"), s("delete"), s("--ip"), s(target)]),
            "fail2ban" => (s("fail2ban-client"), vec![s("set"), s(jail), s("unbanip"), s(target)]),
            _ => (s("nft"), vec![s("delete"), s("element"), s("inet"), s("plume"), s("blocklist"), format!("{{ {target} }}")]),
        },
        "kill_pid" => (s("kill"), vec![s("-TERM"), s(target)]),
        "stop_service" => (s("systemctl"), vec![s("stop"), s(target)]),
        _ => (s("true"), vec![]),
    }
}

// ===================================================================================================
// EXÉCUTEUR PAR-PLATEFORME (#20/#21) — DESCRIPTEUR pour le VOCAB FERMÉ (ban_ip/unban_ip/kill_pid/stop_service).
// -----------------------------------------------------------------------------------------------------
// Objectif : rendre pluggable UNIQUEMENT le « COMMENT » (la commande native) d'une action DÉJÀ validée sur
// une plateforme donnée — JAMAIS le « QUOI ». Le vocab reste FERMÉ (`action_kind_valid` intouché) : une
// action hors vocab est toujours rejetée en amont ; le descripteur ne fait que CHOISIR la commande native.
//
// GARDE-FOUS (non-négociables) :
//   * un gabarit = argv FIXE (programme + arguments littéraux), JAMAIS `sh -c`, JAMAIS de chaînage.
//   * le SEUL point variable = un slot TYPÉ ({ip}/{pid}/{service}), 1 par action, rempli par l'arg du vocab
//     DÉJÀ type-validé (action_valid) -> injection impossible (pas de shell + charset typé).
//   * tout métacaractère shell dans le gabarit, tout placeholder inconnu/non résolu -> gabarit REJETÉ.
//   * plateforme "linux" (DÉFAUT) = chemin nft/fail2ban historique `action_command` : BYTE-IDENTIQUE.
// ===================================================================================================

/// Slot TYPÉ autorisé dans un gabarit — ENSEMBLE FERMÉ, miroir des args du vocab fermé (1 slot par action).
/// Tout autre `{...}` dans un gabarit est un placeholder INCONNU -> le gabarit est rejeté au rendu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Slot {
    Ip,
    Pid,
    Service,
}
impl Slot {
    /// Le jeton textuel exact reconnu dans un gabarit (le SEUL substituable pour cette action).
    fn token(self) -> &'static str {
        match self {
            Slot::Ip => "{ip}",
            Slot::Pid => "{pid}",
            Slot::Service => "{service}",
        }
    }
    /// Slot attendu par un `action_kind` du vocab fermé (None = hors vocab -> aucun rendu possible).
    fn for_kind(kind: &str) -> Option<Slot> {
        match kind {
            "ban_ip" | "unban_ip" => Some(Slot::Ip),
            "kill_pid" => Some(Slot::Pid),
            "stop_service" => Some(Slot::Service),
            _ => None,
        }
    }
    /// Défense en profondeur : la cible respecte-t-elle le charset TYPÉ du slot ? (déjà garanti par
    /// action_valid en amont ; re-vérifié ici pour que le rendu soit sûr même appelé isolément).
    /// Miroir STRICT des charsets d'`action_valid_ctx` (aucun caractère shell possible par construction).
    fn target_ok(self, target: &str) -> bool {
        match self {
            Slot::Ip => {
                !target.is_empty()
                    && target.len() <= 45
                    && target.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                    && target.contains('.')
            }
            Slot::Pid => target.parse::<i64>().map(|p| p > 0).unwrap_or(false),
            Slot::Service => {
                !target.is_empty()
                    && target.len() <= 100
                    && target.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
            }
        }
    }
}

/// Métacaractères shell INTERDITS dans TOUT jeton de gabarit (programme ou argument). Les accolades `{}`
/// sont traitées À PART (délimiteurs de slot) : un `{`/`}` résiduel APRÈS substitution = placeholder inconnu.
/// L'espace est inclus : un jeton argv ne contient jamais d'espace (le gabarit brut est splité dessus).
const SHELL_META: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '<', '>', '"', '\'', '*', '?', '~', '!', '#', '\\', '=', '\n', '\r', '\t', ' ',
];

/// Rend UN jeton d'argument : rejette les métacaractères, substitue le slot typé attendu, rejette tout
/// placeholder résiduel/inconnu. `=` est un métacaractère interdit ICI -> les gabarits `k=v` passent le
/// couple comme un seul jeton pré-formé côté `CmdTemplate` (voir windows) sans traverser cette fonction
/// via un split ; pour un gabarit brut admin on impose la forme `--flag valeur` (pas de `k=v`).
fn render_arg(tok: &str, slot: Slot, target: &str) -> Result<String, String> {
    if let Some(bad) = tok.chars().find(|c| SHELL_META.contains(c)) {
        return Err(format!("métacaractère shell interdit dans le gabarit ({bad:?}) : {tok:?}"));
    }
    let out = tok.replace(slot.token(), target);
    if out.contains('{') || out.contains('}') {
        return Err(format!("placeholder inconnu/non résolu dans le gabarit : {tok:?} (seul {} est permis)", slot.token()));
    }
    Ok(out)
}

/// Gabarit VETTÉ interne (windows/pfsense) : programme + arguments littéraux à trou typé. PAS un script.
struct CmdTemplate {
    prog: &'static str,
    args: &'static [&'static str],
}

/// Rend un gabarit VETTÉ (programme + args) en (prog, argv) sûr, pour l'action `kind`/`target`.
/// Ré-applique TOUS les garde-fous (défense en profondeur) : slot du vocab, charset cible, no-shell,
/// no-placeholder-inconnu. Les jetons `k=v` des gabarits internes (ex netsh `remoteip={ip}`) contiennent
/// `=` : ils sont substitués AVANT le contrôle métacaractère (le `=` littéral est ALORS toléré car il
/// provient d'un gabarit VETTÉ à la compilation, non d'une entrée). On distingue donc rendu interne vs brut.
fn render_vetted(tmpl: &CmdTemplate, kind: &str, target: &str) -> Result<(String, Vec<String>), String> {
    let slot = Slot::for_kind(kind).ok_or_else(|| format!("action hors vocab fermé : {kind}"))?;
    if !slot.target_ok(target) {
        return Err(format!("cible invalide pour le slot {} : {target:?}", slot.token()));
    }
    // le programme ne porte JAMAIS de slot ni de métacaractère.
    if tmpl.prog.is_empty() || tmpl.prog.chars().any(|c| SHELL_META.contains(&c) || c == '{' || c == '}') {
        return Err(format!("programme de gabarit invalide : {:?}", tmpl.prog));
    }
    let mut argv = Vec::with_capacity(tmpl.args.len());
    for raw in tmpl.args {
        // gabarit interne VETTÉ : on substitue d'abord le slot, puis on rejette tout {}/métacaractère
        // résiduel HORS `=` (toléré car il vient d'un littéral compilé `k=v`, jamais d'une entrée).
        let sub = raw.replace(slot.token(), target);
        if let Some(bad) = sub.chars().find(|c| SHELL_META.contains(c) && *c != '=') {
            return Err(format!("métacaractère shell interdit dans le gabarit interne ({bad:?}) : {raw:?}"));
        }
        if sub.contains('{') || sub.contains('}') {
            return Err(format!("placeholder inconnu/non résolu dans le gabarit interne : {raw:?}"));
        }
        argv.push(sub);
    }
    Ok((tmpl.prog.to_string(), argv))
}

/// Gabarit VETTÉ à la compilation pour (plateforme non-linux, action). None = paire non supportée.
/// Ces commandes NE lancent AUCUN shell : argv fixe, un seul slot typé. Elles reflètent le vocab fermé :
///   windows : netsh advfirewall (ban/unban) / taskkill (kill) / sc (stop).
///   pfsense : pfctl table plume_blocklist (ban/unban) / kill (kill) / service (stop) — base FreeBSD.
fn platform_template(platform: &str, kind: &str) -> Option<CmdTemplate> {
    match (platform, kind) {
        // --- WINDOWS ---------------------------------------------------------------------------------
        ("windows", "ban_ip") => Some(CmdTemplate {
            prog: "netsh",
            args: &["advfirewall", "firewall", "add", "rule", "name=plume-ban-{ip}", "dir=in", "action=block", "remoteip={ip}"],
        }),
        ("windows", "unban_ip") => Some(CmdTemplate {
            prog: "netsh",
            args: &["advfirewall", "firewall", "delete", "rule", "name=plume-ban-{ip}"],
        }),
        ("windows", "kill_pid") => Some(CmdTemplate { prog: "taskkill", args: &["/PID", "{pid}", "/F"] }),
        ("windows", "stop_service") => Some(CmdTemplate { prog: "sc", args: &["stop", "{service}"] }),
        // --- PFSENSE / FreeBSD ----------------------------------------------------------------------
        ("pfsense", "ban_ip") => Some(CmdTemplate { prog: "pfctl", args: &["-t", "plume_blocklist", "-T", "add", "{ip}"] }),
        ("pfsense", "unban_ip") => Some(CmdTemplate { prog: "pfctl", args: &["-t", "plume_blocklist", "-T", "delete", "{ip}"] }),
        ("pfsense", "kill_pid") => Some(CmdTemplate { prog: "kill", args: &["-TERM", "{pid}"] }),
        ("pfsense", "stop_service") => Some(CmdTemplate { prog: "service", args: &["{service}", "stop"] }),
        _ => None,
    }
}

/// Rend un gabarit BRUT admin-configuré (generic-appliance) : split sur les espaces (PAS de shell ->
/// pas d'expansion, pas de guillemets), 1er jeton = programme, jetons suivants = args à trou typé.
/// GARDE-FOUS DURS via `render_arg` : métacaractère (dont `=`) interdit -> forme `--flag valeur` imposée ;
/// placeholder inconnu interdit ; le programme ne porte ni slot ni métacaractère. Vide -> Err.
fn render_generic(raw: &str, kind: &str, target: &str) -> Result<(String, Vec<String>), String> {
    let slot = Slot::for_kind(kind).ok_or_else(|| format!("action hors vocab fermé : {kind}"))?;
    if !slot.target_ok(target) {
        return Err(format!("cible invalide pour le slot {} : {target:?}", slot.token()));
    }
    let mut toks = raw.split_whitespace();
    let prog = toks.next().ok_or_else(|| "gabarit generic vide".to_string())?;
    if prog.chars().any(|c| SHELL_META.contains(&c) || c == '{' || c == '}') {
        return Err(format!("programme de gabarit generic invalide : {prog:?}"));
    }
    let mut argv = Vec::new();
    for t in toks {
        argv.push(render_arg(t, slot, target)?);
    }
    Ok((prog.to_string(), argv))
}

/// POINT D'ENTRÉE : commande native FINALE pour (plateforme, action) du vocab fermé.
///   * "linux" (DÉFAUT) -> `action_command` intact (nft/fail2ban/crowdsec) : BYTE-IDENTIQUE.
///   * "windows"/"pfsense" -> gabarit VETTÉ compilé + substitution du slot typé.
///   * "generic-appliance" -> gabarit BRUT admin-configuré (`generic`) + substitution ; None -> Err.
/// `kind`/`target` sont supposés DÉJÀ validés par `action_valid` ; les garde-fous sont RÉ-appliqués (def-in-depth).
pub(crate) fn platform_command(
    platform: &str,
    kind: &str,
    target: &str,
    backend: &str,
    jail: &str,
    generic: Option<&str>,
) -> Result<(String, Vec<String>), String> {
    // le vocab reste FERMÉ : une action hors enum n'a AUCUN gabarit (verrou redondant avec action_kind_valid).
    if Slot::for_kind(kind).is_none() {
        return Err(format!("action hors vocab fermé : {kind}"));
    }
    match platform {
        "linux" => Ok(action_command(kind, target, backend, jail)), // chemin historique : intouché
        "generic-appliance" => match generic {
            Some(raw) => render_generic(raw, kind, target),
            None => Err(format!("generic-appliance : gabarit admin manquant pour {kind} (PLUME_EXEC_GENERIC_{})", kind.to_uppercase())),
        },
        _ => match platform_template(platform, kind) {
            Some(t) => render_vetted(&t, kind, target),
            None => Err(format!("plateforme inconnue ou action non supportée : {platform}/{kind}")),
        },
    }
}

/// Résout le gabarit BRUT generic-appliance pour un `kind` depuis la config (`PLUME_EXEC_GENERIC_<KIND>`).
/// Retour None si non configuré (le rendu échouera proprement -> action `blocked`, jamais d'exécution floue).
pub(crate) fn generic_template_for(conf: &std::collections::HashMap<String, String>, kind: &str) -> Option<String> {
    let key = format!("PLUME_EXEC_GENERIC_{}", kind.to_uppercase());
    let v = cfg(conf, &key, ""); // env PLUME_EXEC_GENERIC_* > conf > "" (non configuré)
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Crée (idempotent) l'infra nft dédiée à Plume pour les bans — table `inet plume` SÉPARÉE du ruleset existant.
pub(crate) fn ensure_nft_blocklist() {
    use std::process::Command;
    let runs: [&[&str]; 4] = [
        &["add", "table", "inet", "plume"],
        &["add", "set", "inet", "plume", "blocklist", "{ type ipv4_addr; }"],
        &["add", "chain", "inet", "plume", "input", "{ type filter hook input priority -150; policy accept; }"],
        &["add", "rule", "inet", "plume", "input", "ip", "saddr", "@blocklist", "drop"],
    ];
    for r in runs {
        let _ = Command::new("nft").args(r).status(); // idempotent : « File exists » ignoré
    }
}

/// Sous-commande `plume-daemon respond` (exécutée en ROOT par plume-respond) : n'exécute QUE les actions
/// approuvées + allowlistées + validées ; dry-run -> aucune modif ; tout est journalisé dans `action`.
pub(crate) fn respond_run() {
    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    let conn = match open_db(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("respond: open db: {e}");
            return;
        }
    };
    let allow: Vec<String> = std::fs::read_to_string("/etc/plume/responder.allow")
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    let jail = cfg(&conf, "PLUME_FAIL2BAN_JAIL", "sshd");
    // déléguer le ban à l'IPS existant ; nft = fallback seulement
    let backend = match cfg(&conf, "PLUME_BAN_BACKEND", "auto").as_str() {
        "auto" => {
            if which("cscli") { "crowdsec".to_string() }
            else if which("fail2ban-client") { "fail2ban".to_string() }
            else { "nft".to_string() }
        }
        other => other.to_string(),
    };
    // Le central n'applique QUE ses actions locales (host NULL/vide/hostname local) ; les actions
    // ciblant un autre hôte sont laissées 'approved' -> réclamées par l'agent de cet hôte (/api/actions/pending).
    // Plateforme d'EXÉCUTION de ce responder (#20/#21). DÉFAUT "linux" = chemin nft/fail2ban historique ->
    // BYTE-IDENTIQUE. Un responder tournant sur/pour un endpoint non-linux pose PLUME_EXEC_PLATFORM ;
    // le vocab reste FERMÉ, seule la commande native change (cf platform_command).
    let platform = cfg(&conf, "PLUME_EXEC_PLATFORM", "linux");
    let me = cfg(&conf, "PLUME_HOST_LABEL", &host_self());
    let pending: Vec<(i64, String, String, bool)> = match conn.prepare(
        "SELECT id,kind,target,dry_run FROM action WHERE status='approved' AND (host IS NULL OR host='' OR host=?1)",
    ) {
        Ok(mut s) => s
            .query_map(params![me], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0)))
            .map(|x| x.flatten().collect())
            .unwrap_or_default(),
        Err(_) => return,
    };
    if pending.is_empty() {
        return;
    }
    // nft = infra LINUX seulement : amorcée uniquement sur la plateforme linux (défaut) -> byte-identique
    // pour le chemin historique (platform=="linux" && backend=="nft" == backend=="nft" quand défaut).
    if platform == "linux" && backend == "nft" && pending.iter().any(|(_, k, _, d)| (k == "ban_ip" || k == "unban_ip") && !d) {
        ensure_nft_blocklist();
    }
    for (id, kind, target, dry) in pending {
        if let Err(e) = action_valid(&kind, &target, &db_path) {
            let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("invalide : {e}"), now()]);
            continue;
        }
        if kind == "stop_service" && !allow.contains(&target) {
            let _ = conn.execute("UPDATE action SET status='blocked', result='service hors allowlist (/etc/plume/responder.allow)', done_ts=?2 WHERE id=?1", params![id, now()]);
            continue;
        }
        // Résolution de la commande native via le descripteur par-plateforme (#20/#21). platform=="linux"
        // (défaut) -> action_command intact (BYTE-IDENTIQUE). Un gabarit invalide/plateforme inconnue ->
        // action `blocked` (jamais d'exécution floue). generic-appliance : gabarit admin PLUME_EXEC_GENERIC_*.
        let generic = generic_template_for(&conf, &kind);
        let (prog, args) = match platform_command(&platform, &kind, &target, &backend, &jail, generic.as_deref()) {
            Ok(pa) => pa,
            Err(e) => {
                let _ = conn.execute("UPDATE action SET status='blocked', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("gabarit plateforme refusé : {e}"), now()]);
                continue;
            }
        };
        if dry {
            let _ = conn.execute("UPDATE action SET status='dryrun', result=?2, done_ts=?3 WHERE id=?1", params![id, format!("[dry-run] {prog} {}", args.join(" ")), now()]);
            continue;
        }
        let (status, result) = match std::process::Command::new(&prog).args(&args).output() {
            Ok(o) => {
                let s = if o.status.success() { "done" } else { "failed" };
                let mut txt = String::from_utf8_lossy(&o.stdout).into_owned();
                txt.push_str(&String::from_utf8_lossy(&o.stderr));
                if txt.trim().is_empty() {
                    txt = format!("{prog} {} -> {}", args.join(" "), o.status);
                }
                (s, txt.chars().take(500).collect::<String>())
            }
            Err(e) => ("failed", format!("exec: {e}")),
        };
        let _ = conn.execute("UPDATE action SET status=?2, result=?3, done_ts=?4 WHERE id=?1", params![id, status, result, now()]);
        ledger_append(&conn, "action.exec", &format!("{kind} {target} -> {status}"));
        // BAN NATIF PLUME (chantier ② Phase 1) : quand le RESPONDER local exécute réellement un ban_ip/unban_ip,
        // synchronise AUSSI le store `net_ban` (blocage HTTP). Sur ce chemin (processus responder SÉPARÉ), le
        // reload ne rafraîchit que le cache de CE processus ; le daemon LIVE, lui, re-lit la table au tick de
        // maintenance (spawn_netban_maintenance) -> convergence. `action_approve`/`run_playbooks` couvrent déjà
        // le blocage IMMÉDIAT in-process ; ceci est le filet pour un chemin qui atteindrait 'approved' hors d'eux.
        if netban_from_actions_enabled() && status == "done" && !dry {
            let canon = target.trim().parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| target.trim().to_string());
            if kind == "ban_ip" && !ip_is_protected(&canon) {
                netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: responder ban_ip", "responder", "prod");
            } else if kind == "unban_ip" {
                netban_remove(&conn, &canon);
            }
        }
    }
}
