//! Notifications multi-canal (P-IR) : neutralisation d'en-têtes `oneline`, garde d'URL `safe_url`,
//! envoi `notify_send`, dispatch de fond `dispatch_notifications`, et CRUD/test des notifiers.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- notifications multi-canal (P-IR) ----------
/// Neutralise l'injection d'en-têtes (CR/LF) dans les valeurs passées à curl (Title/Subject/From/To).
pub(crate) fn oneline(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}
/// DURCISSEMENT — exécute `curl` en passant les options SENSIBLES (auth) via un fichier de
/// CONFIG lu sur STDIN (`-K -`), JAMAIS en argv : `/proc/<pid>/cmdline` est lisible par tout ce qui partage le
/// PID-ns (sidecar, `kubectl debug`, descendants). `secret_cfg` = lignes de config curl (`header = "…"` /
/// `user = "…"`) déjà échappées. Vide -> exécution argv-only classique (aucun secret à cacher).
fn curl_send(args: &[String], secret_cfg: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("curl");
    if !secret_cfg.is_empty() {
        cmd.arg("-K").arg("-"); // options sensibles lues depuis stdin, hors argv
    }
    cmd.args(args);
    if secret_cfg.is_empty() {
        return cmd.status().map(|s| s.success()).unwrap_or(false);
    }
    match cmd.stdin(Stdio::piped()).spawn() {
        Ok(mut child) => {
            if let Some(si) = child.stdin.as_mut() {
                let _ = si.write_all(secret_cfg.as_bytes());
            }
            let _ = child.stdin.take(); // ferme stdin -> curl lit EOF
            child.wait().map(|s| s.success()).unwrap_or(false)
        }
        Err(_) => false,
    }
}
/// Échappe une valeur pour une chaîne `"…"` d'un fichier de config curl (backslash + guillemet). Combiné à
/// `oneline` (retire CR/LF) -> aucune évasion de la ligne de config (anti config-injection).
fn curl_cfg_quote(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}
/// Schéma d'URL autorisé (anti argv flag-smuggling : empêche aussi une URL commençant par '-').
pub(crate) fn safe_url(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    ["http://", "https://", "smtp://", "smtps://"].iter().any(|p| u.starts_with(p))
}
/// URL d'ÉGRESS notifier VALIDE : schéma autorisé (`safe_url`) ET garde SSRF (`ssrf_guard` :
/// rejette loopback/link-local/RFC1918 + re-vérifie l'IP résolue, anti-rebind). Utilisée à la CRÉATION/MAJ
/// (retour d'erreur admin) ET au point d'ÉGRESS réel `notify_send` (choke-point non contournable, y compris
/// une `webhook_url` slack posée directement en config). `safe_url` NU reste pour la validation de GABARIT
/// (workflow_actions) où l'URL porte des placeholders `$field$` non encore résolus.
pub(crate) fn egress_url_ok(url: &str) -> bool {
    safe_url(url) && ssrf_guard(url).is_ok()
}

/// Envoie une notification via `curl` (https/SMTP sans dépendance Rust). Args directs + `--` = pas d'injection.
pub(crate) fn notify_send(kind: &str, url: &str, config: &Value, sev: i64, title: &str, detail: &str, host: &str, ts: i64) -> bool {
    use std::process::Command;
    let done = |r: std::io::Result<std::process::ExitStatus>| r.map(|s| s.success()).unwrap_or(false);
    match kind {
        "ntfy" => {
            if !egress_url_ok(url) { return false; } // garde SSRF au point d'égress (couvre aussi le bypass config direct)
            let prio = match sev { 4 => "5", 3 => "4", 2 => "3", 1 => "2", _ => "1" };
            let g = |k: &str| config.str_field(k);
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(),
                "-H".into(), format!("Title: {}", oneline(title)),
                "-H".into(), format!("Priority: {prio}"),
                "-H".into(), "Tags: rotating_light".into(),
                "-d".into(), format!("{detail}{}", if host.is_empty() { String::new() } else { format!("\n[{host}]") }),
            ];
            // Auth ntfy (serveurs en deny-all/protégés) : token Bearer (préféré) OU user/pass (basic). S2 : les
            // creds passent par la CONFIG STDIN (`curl_send`), plus jamais en argv (fuite /proc/<pid>/cmdline).
            let (token, user, pass) = (g("token"), g("user"), g("pass"));
            let mut secret_cfg = String::new();
            if !token.is_empty() {
                secret_cfg.push_str(&format!("header = \"Authorization: Bearer {}\"\n", curl_cfg_quote(&oneline(token))));
            } else if !user.is_empty() {
                secret_cfg.push_str(&format!("user = \"{}:{}\"\n", curl_cfg_quote(&oneline(user)), curl_cfg_quote(pass)));
            }
            args.push("--".into());
            args.push(url.to_string());
            curl_send(&args, &secret_cfg)
        }
        "webhook" => {
            if !egress_url_ok(url) { return false; } // garde SSRF au point d'égress
            let body = json!({ "ts": ts, "severity": sev, "title": title, "detail": detail, "host": host }).to_string();
            done(Command::new("curl").args([
                "-fsS", "--max-time", "10", "-X", "POST",
                "-H", "Content-Type: application/json", "-d", &body, "--", url,
            ]).status())
        }
        "email" => {
            let g = |k: &str| config.str_field(k);
            let (from, to, user, pass) = (g("from"), g("to"), g("user"), g("pass"));
            if url.is_empty() || from.is_empty() || to.is_empty() {
                return false;
            }
            let seq = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Le corps du mail (titre + détail de l'alerte) transite par un fichier temporaire que
            // curl téléverse. Il était effacé sur le SEUL chemin nominal : un `return false` après
            // une écriture PARTIELLE, ou une panique, laissait le contenu de l'alerte en clair dans
            // $TMPDIR. Le garde RAII l'efface sur TOUTE sortie de portée — et ses sidecars avec.
            let garde = crate::backup::PlaintextTempGuard(
                crate::tmp_possede::racine_systeme().join(format!("plume-mail-{ts}-{seq}.eml")),
            );
            let p = garde.path().to_path_buf();
            if !egress_url_ok(url) { // garde SSRF (smtp) au point d'égress
                return false;
            }
            let body = format!("From: {}\r\nTo: {}\r\nSubject: [Plume] {}\r\n\r\n{detail}\r\n[{host}]\r\n", oneline(from), oneline(to), oneline(title));
            if std::fs::write(&p, body).is_err() {
                return false;
            }
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "15".into(), "--url".into(), url.into(),
                "--mail-from".into(), oneline(from), "--mail-rcpt".into(), oneline(to),
                "--upload-file".into(), p.to_string_lossy().into_owned(),
            ];
            // S2 : creds SMTP via config STDIN (`curl_send`), plus en argv (fuite /proc/<pid>/cmdline).
            let mut secret_cfg = String::new();
            if !user.is_empty() {
                secret_cfg.push_str(&format!("user = \"{}:{}\"\n", curl_cfg_quote(&oneline(user)), curl_cfg_quote(pass)));
            }
            let r = curl_send(&args, &secret_cfg);
            // Plus de `remove_file` ici : le garde efface en sortie de portée, et il ÉCRASE le
            // contenu avant de délier (`secure_delete`) — un simple unlink laissait les pages du
            // corps d'alerte récupérables sur le volume.
            r
        }
        // #48 SLACK (incoming webhook). L'URL du webhook EST un secret -> elle vit dans `config.webhook_url`
        // (jamais projetée), PAS dans `url` (affiché). Payload « blocks » + fallback texte.
        "slack" => {
            let wh = config.str_field("webhook_url");
            if !egress_url_ok(wh) { // la webhook_url slack est un égress -> garde SSRF
                return false;
            }
            let body = slack_payload(sev, title, detail, host, ts).to_string();
            // S2 : la `webhook_url` (SECRET) passe par la config STDIN (`url = …`), plus en argv (fuite /proc).
            let args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), "Content-Type: application/json".into(), "-d".into(), body,
            ];
            curl_send(&args, &format!("url = \"{}\"\n", curl_cfg_quote(wh)))
        }
        // #48 PAGERDUTY (Events API v2, action trigger). La `routing_key` EST un secret -> `config.routing_key`.
        // Endpoint FIXE (pas de SSRF : la cible n'est pas pilotable par l'appelant). dedup_key = titre neutralisé.
        "pagerduty" => {
            let rk = config.str_field("routing_key");
            if rk.is_empty() {
                return false;
            }
            let endpoint = "https://events.pagerduty.com/v2/enqueue";
            let body = pagerduty_payload(rk, &oneline(title), sev, title, detail, host, ts).to_string();
            // S2 : le body embarque la `routing_key` (SECRET) -> config STDIN (`data = …`), plus en argv (fuite /proc).
            let args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), "Content-Type: application/json".into(), "--".into(), endpoint.into(),
            ];
            curl_send(&args, &format!("data = \"{}\"\n", curl_cfg_quote(&body)))
        }
        // #48 GÉNÉRIQUE HTTP avec gabarit SÛR. `url` = cible (non secrète). `config.template` = corps rendu par
        // substitution de placeholders CONNUS uniquement (pas de commande, pas de SSRF hors `url`). En-tête
        // d'auth optionnel `config.auth_header` (secret, ex `Authorization: Bearer x`), neutralisé CR/LF.
        "generic" => {
            if !egress_url_ok(url) { // garde SSRF au point d'égress
                return false;
            }
            let tmpl = config.str_field("template");
            let body = if tmpl.is_empty() {
                json!({ "ts": ts, "severity": sev, "title": title, "detail": detail, "host": host }).to_string()
            } else {
                render_template(tmpl, sev, title, detail, host, ts)
            };
            let ctype = config.str_field("content_type");
            let ctype = if ctype.is_empty() { "application/json" } else { ctype };
            let mut args: Vec<String> = vec![
                "-fsS".into(), "--max-time".into(), "10".into(), "-X".into(), "POST".into(),
                "-H".into(), format!("Content-Type: {}", oneline(ctype)),
            ];
            // S2 : l'`auth_header` (SECRET, ex. `Authorization: Bearer …`) passe par la config STDIN (`header = …`),
            // plus en argv (fuite /proc/<pid>/cmdline). CR/LF déjà neutralisés (`oneline`) + échappement config.
            let auth = config.str_field("auth_header");
            let secret_cfg = if auth.is_empty() { String::new() } else { format!("header = \"{}\"\n", curl_cfg_quote(&oneline(auth))) };
            args.push("-d".into());
            args.push(body);
            args.push("--".into());
            args.push(url.to_string());
            curl_send(&args, &secret_cfg)
        }
        // #48 output-to-lookup : PAS de réseau. Écrit dans une table lookup (#36) -> géré dans
        // dispatch_notifications (a besoin d'un `Connection`). Ici : no-op de garde (jamais appelé pour ce kind).
        "lookup" => false,
        _ => false,
    }
}

/// Kinds de canaux dont la CIBLE (endpoint) est dans `url` (donc `url` requis & validé à la création).
/// Slack/PagerDuty/lookup portent leur cible/clé dans `config` (secret) -> `url` peut rester vide.
pub(crate) fn notifier_kind_needs_url(kind: &str) -> bool {
    matches!(kind, "ntfy" | "webhook" | "email" | "generic")
}

/// Dispatche les alertes non notifiées, puis marque notified=1.
///
/// #48/#53 : le routage passe désormais par `plan_dispatch`. MODE 0 (aucune politique, aucun silence) :
///  - `plan_dispatch` renvoie `silenced=false` et `target_ids` = TOUS les canaux enabled -> la boucle d'envoi
///    (filtre `sev>=min_severity` PAR CANAL, inchangé) reproduit EXACTEMENT le fan-out plat historique ;
///  - un silence actif matche l'alerte -> elle est marquée notified=1 SANS envoi (mute gouverné) ;
///  - une politique présente -> l'alerte n'est envoyée qu'aux points de contact routés (most-specific-wins) ;
///  - un canal `lookup` (#36) n'émet pas de réseau : l'alerte est écrite dans la table lookup (enrichissement).
pub(crate) fn dispatch_notifications(db: &Arc<Mutex<Connection>>) {
    // NotifierRef complet (id inclus) pour le filtrage par politique.
    struct NotifierRef { id: i64, kind: String, url: String, min_severity: i64, config: String }
    #[allow(clippy::type_complexity)]
    let (alerts, notifiers, policies, silences): (
        Vec<(i64, i64, i64, String, String, String, String, String)>,
        Vec<NotifierRef>,
        Vec<Policy>,
        Vec<Vec<(String, String)>>,
    ) = {
        let conn = db.lock();
        // labels de routage : mitre / host / source(=rule) / env_id, en plus de ts/severity/title/detail.
        let alerts: Vec<(i64, i64, i64, String, String, String, String, String)> = match conn.prepare(
            "SELECT id,ts,severity,title,detail,COALESCE(host,''),COALESCE(mitre,''),COALESCE(rule,'') \
             FROM alert WHERE notified=0 ORDER BY ts LIMIT 20",
        ) {
            Ok(mut s) => s.query_map([], |r| Ok((
                r.get(0)?, r.get(1)?, r.get(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get(5)?, r.get(6)?, r.get(7)?,
            ))).map(|x| x.flatten().collect()).unwrap_or_default(),
            Err(_) => return,
        };
        if alerts.is_empty() {
            return;
        }
        let notifiers: Vec<NotifierRef> = match conn.prepare("SELECT id,kind,url,min_severity,config FROM notifier WHERE enabled=1 ORDER BY id") {
            Ok(mut s) => s.query_map([], |r| Ok(NotifierRef { id: r.get(0)?, kind: r.get(1)?, url: r.get(2)?, min_severity: r.get(3)?, config: r.get(4)? })).map(|x| x.flatten().collect()).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let policies = load_policies(&conn);
        let silences = load_active_silences(&conn, now());
        (alerts, notifiers, policies, silences)
    };
    let enabled_ids: Vec<i64> = notifiers.iter().map(|n| n.id).collect();
    for (id, ts, sev, title, detail, host, mitre, source) in &alerts {
        // env_id non porté par le SELECT (colonne rare en label) : reste vide -> matcher `env` inopérant en mode 0.
        let labels = alert_labels(*sev, mitre, host, source, "");
        let plan = plan_dispatch(&labels, &policies, &silences, &enabled_ids);
        if !plan.silenced {
            for n in &notifiers {
                if !plan.target_ids.contains(&n.id) || sev < &n.min_severity {
                    continue;
                }
                let config: Value = serde_json::from_str(&n.config).unwrap_or_else(|_| json!({}));
                if n.kind == "lookup" {
                    // écrit l'alerte dans le lookup configuré (défaut `alerts`, clé = host).
                    let name = { let s = config.str_field("lookup"); if s.is_empty() { "alerts".to_string() } else { s.to_string() } };
                    let key_field = { let s = config.str_field("key_field"); if s.is_empty() { "host".to_string() } else { s.to_string() } };
                    let key = match key_field.as_str() { "host" => host.clone(), "source" => source.clone(), "mitre" => mitre.clone(), _ => host.clone() };
                    let fields = json!({ "host": host, "source": source, "mitre": mitre, "severity": sev, "title": title, "ts": ts });
                    let conn = db.lock();
                    let _ = write_alert_to_lookup(&conn, &name, &key_field, &key, &fields);
                } else {
                    let _ = notify_send(&n.kind, &n.url, &config, *sev, title, detail, host, *ts);
                }
            }
        }
        let conn = db.lock();
        let _ = conn.execute("UPDATE alert SET notified=1 WHERE id=?1", params![id]);
    }
}

/// DURCISSEMENT : la colonne `config` porte le token ntfy / user:pass SMTP. Elle N'EST PLUS
/// JAMAIS projetée -> on renvoie `has_auth` (booléen, miroir de connectors_list `has_secret`). Un viewer/editor
/// est DÉJÀ bloqué par rbac_gate (admin-only, GET compris) ; ce re-check DOUBLE la garde (défense en profondeur).
pub(crate) async fn notifiers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let mut stmt = conn.prepare("SELECT id,name,kind,enabled,url,min_severity,config FROM notifier ORDER BY id").unwrap();
    let rows = stmt.query_map([], |r| {
        // has_auth = le canal porte un credential (token ntfy OU user/pass SMTP) non vide. Le blob `config`
        // (secret) N'EST PAS renvoyé -> aucune fuite de token/mot de passe, même pour un admin (édition = re-saisie).
        let cfg: String = r.get(6)?;
        // #48 : la liste des clés-secrets s'étend aux nouveaux canaux (webhook Slack, routing key PagerDuty,
        // en-tête d'auth du canal générique). AUCUNE n'est projetée -> `has_auth` booléen seul (défense en
        // profondeur ; rbac_gate bloque déjà tout non-admin, GET compris).
        let has_auth = serde_json::from_str::<Value>(&cfg)
            .ok()
            .map(|v| ["token", "user", "pass", "webhook_url", "routing_key", "auth_header"].iter().any(|k| v.get(*k).and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)))
            .unwrap_or(false);
        Ok(json!({
            "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
            "enabled": r.get::<_, i64>(3)? != 0, "url": r.get::<_, String>(4)?,
            "min_severity": r.get::<_, i64>(5)?, "has_auth": has_auth
        }))
    }).unwrap();
    Json(json!({ "notifiers": rows.flatten().collect::<Vec<_>>() })).into_response()
}
pub(crate) async fn notifier_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    if !au.is_admin() {
        return Json(json!({ "error": "réservé à l'administrateur" }));
    }
    let url = b.str_field("url");
    let kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("ntfy").to_string();
    // #48 : slack/pagerduty/lookup portent leur cible/clé dans `config` (secret) -> `url` peut être vide ;
    // les autres canaux exigent une `url` valide. SEC-FIX : on valide DÈS LA CRÉATION avec `egress_url_ok`
    // (= schéma autorisé ET garde SSRF) — pas seulement `safe_url` — sinon un notifier ciblant une adresse
    // interne (loopback/metadata) était accepté puis ÉCHOUAIT SILENCIEUSEMENT à chaque envoi (aucun last_error).
    // L'admin obtient un refus IMMÉDIAT explicite. NB (fix on-prem) : un relais SMTP interne en RFC1918 PASSE
    // par défaut (RFC1918 opt-in via PLUME_SSRF_BLOCK_PRIVATE) — seul le never-egress est refusé d'office.
    if notifier_kind_needs_url(&kind) && !egress_url_ok(url) {
        return Json(json!({ "error": "URL invalide : http(s):// (ntfy/webhook/generic) ou smtp(s):// (email) requis, et cible non-interne (SSRF)" }));
    }
    if !url.is_empty() && !egress_url_ok(url) {
        return Json(json!({ "error": "URL invalide : schéma non autorisé ou cible interne refusée (SSRF)" }));
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Canal").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let min_sev = b.i64_field("min_severity", 2);
    let config = b.get("config").and_then(|v| v.as_str()).unwrap_or("{}").to_string();
    crate::req_conn!(st, au, conn);
    // M3 : mutation + audit (ledger + event plume-config) DANS UNE transaction fail-closed (patron
    // source_settings_put) -> plus d'angle mort effaçable sans trace. Le `config` (token ntfy / user:pass SMTP)
    // n'est JAMAIS logué : l'audit ne porte que name/kind/enabled.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Json(json!({ "error": "verrou base indisponible" }));
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES(?1,?2,?3,?4,?5,?6)",
            params![name, kind, enabled, url, min_sev, config],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn,
            "config.notifier.create",
            &format!("notifier '{name}' ({kind}) créé par {}", au.name),
            3,
            &format!("canal de notification '{name}' ({kind}, enabled={}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "kind": kind, "enabled": enabled != 0, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => {
            let _ = conn.execute_batch("COMMIT");
            Json(json!({ "id": id }))
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            Json(json!({ "error": format!("échec transaction audit (aucune modification): {e}") }))
        }
    }
}
pub(crate) async fn notifier_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    if !au.is_admin() {
        return StatusCode::FORBIDDEN;
    }
    if let Some(v) = b.get("url").and_then(|x| x.as_str()) {
        // SEC-FIX : validation d'ÉGRESS complète (schéma + SSRF) à la MAJ, pas seulement le schéma -> pas de
        // notifier ré-pointé vers une cible interne qui échouerait ensuite en silence.
        if !egress_url_ok(v) {
            return StatusCode::BAD_REQUEST;
        }
    }
    crate::req_conn!(st, au, conn);
    // M3 : mutation + audit fail-closed. Le champ `config`/`url` peut porter un secret -> l'audit note QUELS
    // champs ont changé (NOMS), jamais leurs valeurs.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let outcome: rusqlite::Result<()> = (|| {
        for (k, col) in [("name", "name"), ("kind", "kind"), ("url", "url"), ("config", "config")] {
            if let Some(v) = b.get(k).and_then(|x| x.as_str()) {
                conn.execute(&format!("UPDATE notifier SET {col}=?1 WHERE id=?2"), params![v, id])?;
            }
        }
        if let Some(v) = b.get("min_severity").and_then(|x| x.as_i64()) { conn.execute("UPDATE notifier SET min_severity=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE notifier SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        let changed: Vec<&str> = ["name", "kind", "url", "config", "min_severity", "enabled"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn,
            "config.notifier.update",
            &format!("notifier #{id} modifié ({}) par {}", changed.join(","), au.name),
            3,
            &format!("canal #{id} modifié (champs: {}) par {}", changed.join(","), au.name),
            &json!({ "id": id, "changed": changed, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT }
        Err(_) => { let _ = conn.execute_batch("ROLLBACK"); StatusCode::INTERNAL_SERVER_ERROR }
    }
}
pub(crate) async fn notifier_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> StatusCode {
    if !au.is_admin() {
        return StatusCode::FORBIDDEN;
    }
    crate::req_conn!(st, au, conn);
    // M3 : suppression + audit fail-closed (une désactivation de canal ne doit pas être effaçable sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM notifier WHERE id=?1", params![id])?;
        audit_config_change(
            &conn,
            "config.notifier.delete",
            &format!("notifier #{id} supprimé par {}", au.name),
            3,
            &format!("canal de notification #{id} supprimé par {}", au.name),
            &json!({ "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT }
        Err(_) => { let _ = conn.execute_batch("ROLLBACK"); StatusCode::INTERNAL_SERVER_ERROR }
    }
}
pub(crate) async fn notifier_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    if !au.is_admin() {
        return Json(json!({ "error": "réservé à l'administrateur" }));
    }
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row("SELECT kind,url,config FROM notifier WHERE id=?1", params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))).ok()
    };
    let (kind, url, cfg) = match row {
        Some(x) => x,
        None => return Json(json!({ "error": "canal introuvable" })),
    };
    let config: Value = serde_json::from_str(&cfg).unwrap_or_else(|_| json!({}));
    let ts = now();
    let ok = tokio::task::spawn_blocking(move || notify_send(&kind, &url, &config, 3, "Test Plume", "Notification de test depuis Plume.", "", ts))
        .await.unwrap_or(false);
    Json(json!({ "ok": ok }))
}
