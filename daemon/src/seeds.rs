//! Seeds : peuplement initial (dashboards, règles de détection, playbooks, notifiers) + helpers
//! find_or_create_view / col_exists. Sur &Connection uniquement. Extrait de main.rs (refactor
//! split #25 — byte-identique).
use crate::*;

/// Crée un dashboard « Vue d'ensemble » au 1er démarrage (si aucun dashboard).
/// Les panneaux metric utilisent le jeton __FROM__ (remplacé par la fenêtre temporelle).
/// Données de DÉMO (PLUME_DEMO=1 uniquement) : peuple une instance FRAÎCHE pour la voir vivante en une
/// commande (`docker compose up`) — events/metrics/alertes d'exemple sur 24 h, sans agent ni setup.
/// OFF par défaut ; flag `seeded_demo` (une seule fois). Jamais en prod (n'active pas PLUME_DEMO).
pub(crate) fn seed_demo(conn: &Connection) {
    // Plume CANONICAL (PLUME_-only) : PLUME_DEMO uniquement.
    let demo = std::env::var("PLUME_DEMO").ok();
    if demo.as_deref() != Some("1") { return; }
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_demo'", [], |r| r.get::<_, String>(0)).is_ok() { return; }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_demo','1')", []);
    let now_ts = now();
    let ips = ["203.0.113.7", "198.51.100.42", "192.0.2.9", "192.0.2.18", "192.0.2.4", "192.0.2.10"];
    let host = "demo-host";
    // (source, category, severity, message{ip}, a_un_ip)
    let tpl: [(&str, &str, i64, &str, bool); 8] = [
        ("sshd", "auth", 3, "Failed password for invalid user admin from {ip} port 50122 ssh2", true),
        ("sshd", "auth", 3, "Invalid user test from {ip} port 41200", true),
        ("sshd", "auth", 0, "Accepted publickey for deploy from {ip} port 39920 ssh2", true),
        ("ufw", "firewall", 1, "UFW BLOCK [inbound] {ip} -> :3389/TCP", true),
        ("mail", "auth", 2, "imap-login: Disconnected (auth failed): user=<sales>, rip={ip}", true),
        ("conntrack", "network", 1, "net external out: curl -> {ip}:443", true),
        ("auditd", "exec", 2, "execve /usr/bin/wget by uid=0 (key=exec_tracking)", false),
        ("k8s-log", "k8s", 3, "authentik: authentication failed for user admin", false),
    ];
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    let (mut t, mut k) = (now_ts - 86400, 0usize);
    while t < now_ts {
        let (src, cat, sev, msg, has_ip) = tpl[k % tpl.len()];
        let ip = ips[k % ips.len()];
        let sip = if has_ip { Some(ip) } else { None };
        // NB (démo seulement, PLUME_DEMO=1) : events en direct alors que les métriques passent par
        // `store().insert_metric` — asymétrie cosmétique documentée dans l'en-tête STORE SPI (0 impact prod).
        let _ = conn.execute(
            "INSERT OR IGNORE INTO event(ts,source,category,severity,message,host,src_ip,dedup) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![t, src, cat, sev, msg.replace("{ip}", ip), host, sip, format!("demo-{k}")],
        );
        k += 1;
        t += 130 + (k as i64 % 7) * 40;   // ~2-7 min, varié
    }
    let (mut t, mut i) = (now_ts - 86400, 0i64);
    while t < now_ts {
        let vals = [("cpu_pct", 15.0 + (i % 30) as f64 * 1.7), ("mem_pct", 40.0 + (i % 12) as f64 * 2.0),
                    ("load1", 0.4 + (i % 10) as f64 * 0.15), ("net_rx_bps", 1000.0 + (i % 50) as f64 * 800.0),
                    ("net_tx_bps", 600.0 + (i % 40) as f64 * 500.0)];
        for (n, v) in vals { let _ = store().insert_metric(conn, &MetricRow { ts: t, name: n.to_string(), labels: None, value: v, host: Some(host.to_string()) }); }
        i += 1; t += 300;
    }
    for (rule, sev, title, detail) in [
        ("demo.bruteforce", 3, "Pic d'échecs SSH", "12 échecs depuis 203.0.113.7 en 5 min"),
        ("demo.scan", 2, "Scan de ports", "198.51.100.42 sonde 3389 / 445 / 22"),
    ] {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,host) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![now_ts - 600, rule, sev, title, detail, format!("demo-{rule}"), host],
        );
    }
    // ---- CASES de démo (PLUME_DEMO=1) : 2 incidents SYNTHÉTIQUES pour illustrer la vue case-detail (README).
    // 100% synthétiques : host `demo-host`, IPs déjà dans `ips` (RFC-5737/TEST-NET), aucun agent réel. Events
    // narratifs dédiés (dedup 'democase-*') liés en timeline pour que les chips alert/event se résolvent. Sous le
    // flag `seeded_demo` déjà posé -> idempotent (une seule fois). JAMAIS en prod (n'active pas PLUME_DEMO).
    let ev = |ts: i64, src: &str, cat: &str, sev: i64, msg: &str, ip: Option<&str>, dk: &str| -> i64 {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO event(ts,source,category,severity,message,host,src_ip,dedup) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![ts, src, cat, sev, msg, host, ip, dk],
        );
        conn.query_row("SELECT id FROM event WHERE dedup=?1", params![dk], |r| r.get::<_, i64>(0)).unwrap_or(0)
    };
    let alert_id = |dk: &str| -> Option<i64> {
        conn.query_row("SELECT id FROM alert WHERE dedup=?1", params![dk], |r| r.get::<_, i64>(0)).ok()
    };
    let item = |iid: i64, ts: i64, kind: &str, author: &str, body: &str, rf: Option<String>| {
        let _ = conn.execute(
            "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,?2,?3,?4,?5,?6)",
            params![iid, ts, kind, author, body, rf],
        );
    };

    // Case A — brute-force SSH puis accès (192.0.2.18), P2 haute, in_progress, sévérité 3.
    let ipa = ips[3]; // 192.0.2.18
    let a1 = ev(now_ts - 21600, "sshd", "auth", 3, &format!("Failed password for invalid user admin from {ipa} port 50122 ssh2"), Some(ipa), "democase-a1");
    let a2 = ev(now_ts - 21540, "sshd", "auth", 3, &format!("Failed password for root from {ipa} port 50140 ssh2"), Some(ipa), "democase-a2");
    let a3 = ev(now_ts - 21000, "sshd", "auth", 0, &format!("Accepted publickey for deploy from {ipa} port 39920 ssh2"), Some(ipa), "democase-a3");
    let a_ts = now_ts - 21600;
    let _ = conn.execute(
        "INSERT INTO incident(ts,updated,title,status,severity,owner,summary,priority,assignee,sla_due,first_response_ts) \
         VALUES(?1,?2,?3,'in_progress',3,'demo',?4,2,'analyste',?5,?6)",
        params![a_ts, now_ts - 600, format!("Brute-force SSH puis accès — {ipa}"),
            "Pic d'échecs d'authentification SSH depuis 192.0.2.18 (TEST-NET), suivi d'une connexion par clé publique acceptée pour le compte « deploy ». Corrélation brute-force → accès en cours d'investigation.",
            a_ts + 14400, now_ts - 21000],
    );
    let ca = conn.last_insert_rowid();
    item(ca, a_ts, "created", "demo", "Incident créé (corrélation détection demo.bruteforce)", None);
    item(ca, a_ts + 60, "note", "analyste", "Triage : source 192.0.2.18 (TEST-NET), rafale d'échecs sur admin/root en < 5 min.", None);
    item(ca, now_ts - 21300, "event", "analyste", "Échec d'authentification", Some(format!("event:{a1}")));
    item(ca, now_ts - 21290, "event", "analyste", "Échec d'authentification (root)", Some(format!("event:{a2}")));
    item(ca, now_ts - 21000, "event", "analyste", "Accès accepté après la rafale — pivot probable", Some(format!("event:{a3}")));
    if let Some(al) = alert_id("demo-demo.bruteforce") { item(ca, now_ts - 20990, "alert", "analyste", "Alerte de détection rattachée", Some(format!("alert:{al}"))); }
    item(ca, now_ts - 20980, "priority", "analyste", "priorité -> P2 (high)", None);
    item(ca, now_ts - 20970, "assign", "analyste", "assigné à analyste", None);
    item(ca, now_ts - 20960, "status", "analyste", "statut -> in_progress", None);
    item(ca, now_ts - 20000, "action", "analyste", "Bannissement de 192.0.2.18 (UFW) — cible src_ip proposée, en attente de validation.", None);
    item(ca, now_ts - 600, "note", "analyste", "Clé « deploy » à faire tourner ; audit des commandes post-login en cours.", None);

    // Case B — scan de ports entrant bloqué (192.0.2.9), P3 moyenne, résolu, verdict bénin.
    let ipb = ips[2]; // 192.0.2.9
    let b1 = ev(now_ts - 8000, "ufw", "firewall", 1, &format!("UFW BLOCK [inbound] {ipb} -> :3389/TCP"), Some(ipb), "democase-b1");
    let b2 = ev(now_ts - 7980, "ufw", "firewall", 1, &format!("UFW BLOCK [inbound] {ipb} -> :445/TCP"), Some(ipb), "democase-b2");
    let b3 = ev(now_ts - 7960, "ufw", "firewall", 1, &format!("UFW BLOCK [inbound] {ipb} -> :22/TCP"), Some(ipb), "democase-b3");
    let b_ts = now_ts - 8000;
    let _ = conn.execute(
        "INSERT INTO incident(ts,updated,title,status,severity,owner,summary,priority,assignee,sla_due,first_response_ts,closed_ts,disposition,disposition_ts,disposition_by) \
         VALUES(?1,?2,?3,'resolved',2,'demo',?4,3,'analyste',?5,?6,?7,'benign',?7,'analyste')",
        params![b_ts, now_ts - 300, format!("Scan de ports entrant bloqué (UFW) — {ipb}"),
            "Sonde TCP entrante sur 3389/445/22 depuis 192.0.2.9, intégralement bloquée par UFW en périmètre. Aucun paquet n'a atteint un service ; classé bruit de fond Internet.",
            b_ts + 86400, now_ts - 7000, now_ts - 300],
    );
    let cb = conn.last_insert_rowid();
    item(cb, b_ts, "created", "demo", "Incident créé (corrélation détection demo.scan)", None);
    item(cb, b_ts + 40, "note", "analyste", "Triage : balayage de ports classique (RDP/SMB/SSH), tout bloqué en entrée par UFW.", None);
    item(cb, now_ts - 7990, "event", "analyste", "Blocage UFW — 3389/TCP", Some(format!("event:{b1}")));
    item(cb, now_ts - 7975, "event", "analyste", "Blocage UFW — 445/TCP", Some(format!("event:{b2}")));
    item(cb, now_ts - 7955, "event", "analyste", "Blocage UFW — 22/TCP", Some(format!("event:{b3}")));
    if let Some(al) = alert_id("demo-demo.scan") { item(cb, now_ts - 7950, "alert", "analyste", "Alerte de détection rattachée", Some(format!("alert:{al}"))); }
    item(cb, now_ts - 7000, "status", "analyste", "statut -> triage", None);
    item(cb, now_ts - 400, "disposition", "analyste", "verdict -> benign", None);
    item(cb, now_ts - 300, "status", "analyste", "statut -> resolved", None);
    item(cb, now_ts - 300, "note", "analyste", "Aucune action requise : trafic absorbé par le pare-feu périmétrique. Clôturé bénin.", None);

    let _ = conn.execute_batch("COMMIT");
    eprintln!("[demo] données de démo seedées (PLUME_DEMO=1) — désactive PLUME_DEMO en prod");
}
/// Trouve une vue partagée par son nom, ou la crée (INSERT INTO view(name) seulement si absente) ->
/// renvoie son id (None si l'INSERT échoue). DRY entre les seeds `seed_*_dashboard` (parité PVC neuf)
/// et la migration v63 (split de la vue « Sécurité » en vues focalisées). Idempotent PAR NOM.
pub(crate) fn find_or_create_view(conn: &Connection, name: &str) -> Option<i64> {
    conn.query_row("SELECT id FROM view WHERE name=?1", params![name], |r| r.get::<_, i64>(0))
        .ok()
        .or_else(|| {
            conn.execute("INSERT INTO view(name,visibility) VALUES(?1,'shared')", params![name]).ok()?;
            Some(conn.last_insert_rowid())
        })
}

/// PROLOGUE COMMUN des seeds de dashboard PARTAGÉS (l'idiome méta-flag ->
/// INSERT dashboard `shared` -> rattachement à la vue était répété ~13×). Retourne `Some(did)` (le dashboard est
/// créé, prêt à recevoir ses panneaux) ou `None` si DÉJÀ seedé / INSERT échoué -> l'appelant `return`. Le
/// PANEL-LOOP reste DANS chaque fonction (données de panneaux spécifiques PRÉSERVÉES telles quelles = zéro
/// régression). `seed_default_dashboard` N'utilise PAS ce prologue (dashboard NON-`shared`, cas spécial). Flag =
/// `seeded_{flag}` (miroir exact des clés meta existantes). `collapsed` = dashboard replié dans la vue.
pub(crate) fn seed_dashboard_head(conn: &Connection, flag: &str, name: &str, view: &str, collapsed: bool) -> Option<i64> {
    let key = format!("seeded_{flag}");
    if conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get::<_, String>(0)).is_ok() {
        return None;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,'1')", params![key]);
    if conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES(?1,?2,'shared')", params![name, now()]).is_err() {
        return None;
    }
    let did = conn.last_insert_rowid();
    seed_dashboard_attach(conn, did, view, collapsed);
    Some(did)
}

/// PROLOGUE des seeds de dashboard idempotents PAR NOM (l'AUTRE moitié : `web`/`mail`/`dataaccess`/`dataacl`/
/// `sca`/`vuln` dédupent sur l'existence du DASHBOARD, sans méta-flag). Retourne `Some(did)` ou `None` si un
/// dashboard de ce nom existe déjà / INSERT échoué. Parametré (`name=?1`) -> plus sûr que l'ancien inline
/// SQL-escaped (`name='Carte d''accès…'`). Panel-loop préservé dans chaque fonction.
pub(crate) fn seed_dashboard_head_named(conn: &Connection, name: &str, view: &str, collapsed: bool) -> Option<i64> {
    if conn.query_row("SELECT 1 FROM dashboard WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).is_ok() {
        return None;
    }
    if conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES(?1,?2,'shared')", params![name, now()]).is_err() {
        return None;
    }
    let did = conn.last_insert_rowid();
    seed_dashboard_attach(conn, did, view, collapsed);
    Some(did)
}

/// Rattache un dashboard à sa vue (repliée ou non) — commun aux deux prologues.
fn seed_dashboard_attach(conn: &Connection, did: i64, view: &str, collapsed: bool) {
    if let Some(vid) = find_or_create_view(conn, view) {
        let sql = if collapsed {
            "UPDATE dashboard SET view_id=?1, collapsed=1 WHERE id=?2"
        } else {
            "UPDATE dashboard SET view_id=?1 WHERE id=?2"
        };
        let _ = conn.execute(sql, params![vid, did]);
    }
}

pub(crate) fn seed_default_dashboard(conn: &Connection) {
    let seeded: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key='seeded_default'", [], |r| r.get(0))
        .ok();
    if seeded.is_some() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_default','1')", []);
    if conn.execute("INSERT INTO dashboard(name,created) VALUES('SOC — Vue d''ensemble', ?1)", params![now()]).is_err() {
        return;
    }
    let did = conn.last_insert_rowid();
    // vue par défaut « SOC » (anchor du SOC) — find_or_create PARTAGÉ avec la migration v63 et
    // seed_rollup_dashboard, pour que « Vue d'ensemble (rapide) » rejoigne CETTE même vue (parité live).
    if let Some(vid) = find_or_create_view(conn, "SOC") {
        let _ = conn.execute("UPDATE dashboard SET view_id=?1 WHERE id=?2", params![vid, did]);
    }
    let panels: [(&str, &str, i64, &str); 7] = [
        ("Événements dans le temps", "search | timechart span=1h count", 1, "line"),
        ("Top sources", "search | stats count by source | sort -count | head 30", 1, "bar"),
        ("Événements à risque (sév≥3)", "search severity>=3 | stats count", 1, "stat"),
        ("CPU %", "SELECT ts AS bucket, value FROM metric WHERE name='cpu_pct' AND ts>=__FROM__ ORDER BY ts", 0, "line"),
        ("RAM %", "SELECT ts AS bucket, value FROM metric WHERE name='mem_pct' AND ts>=__FROM__ ORDER BY ts", 0, "line"),
        ("Réseau ↓ (o/s)", "SELECT ts AS bucket, value FROM metric WHERE name='net_rx_bps' AND ts>=__FROM__ ORDER BY ts", 0, "line"),
        ("Température °C", "SELECT ts AS bucket, value FROM metric WHERE name='temp_c' AND ts>=__FROM__ ORDER BY ts", 0, "line"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position) VALUES(?1,?2,?3,?4,?5,?6)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Sécurité & détection » (vitrine des collecteurs §8) — flag `seeded_security`.
/// Les panneaux sont vides tant que les collecteurs (vuln/clamav/conntrack/auditd/suricata/mail)
/// ne tournent pas, mais le dashboard est prêt.
pub(crate) fn seed_security_dashboard(conn: &Connection) {
    // v63 : « Sécurité & détection » est le dashboard PRIMAIRE (déplié) de la vue « Détection ».
    let Some(did) = seed_dashboard_head(conn, "security", "Sécurité & détection", "Détection", false) else { return };
    let panels: [(&str, &str, &str); 6] = [
        ("Vulnérabilités par sévérité", "search source=vuln | stats count by severity | sort -severity", "bar"),
        ("Malware détecté (ClamAV)", "search source=clamav | stats count", "stat"),
        ("Connexions sortantes récentes", "search source=conntrack | table ts,message", "table"),
        ("Exécutions & privesc (auditd)", "search source=auditd | timechart span=1h count", "line"),
        ("Alertes IDS (Suricata)", "search source=suricata category=alert | table ts,message", "table"),
        ("Mail suspect", "search source=mail | stats count by category | sort -count", "bar"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}

/// Règle « backup Velero en échec » — flag dédié `seeded_velero_rule` (arrive même si seeded_sts_rules
/// est déjà posé). OFF par défaut. La métrique `velero_failed` vient de kube-state.sh (statut des
/// backups.velero.io) -> un backup Failed/PartiallyFailed alerte (angle mort DR : un backup qui casse).
pub(crate) fn seed_velero_rule(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_velero_rule'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_velero_rule','1')", []);
    let _ = conn.execute(
        "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) \
         VALUES('Backup Velero en échec', 'metric velero_failed | stats max(value)', 1, '>', 0.0, 3, 600, 3600, 0)",
        [],
    );
}

/// Règle par défaut : alerte sur détection antivirus (ClamAV via amavis -> events
/// category=malware, cf collectors/mail.sh). DÉSACTIVÉE par défaut (opt-in : active pour la
/// notif ntfy). Idempotent PAR NOM -> ne duplique pas une règle déjà créée à la main.
pub(crate) fn seed_malware_rule(conn: &Connection) {
    if conn.query_row("SELECT 1 FROM rule WHERE name='ClamAV : virus détecté'", [], |r| r.get::<_, i64>(0)).is_ok() {
        return;
    }
    let _ = conn.execute(
        "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) \
         VALUES('ClamAV : virus détecté', 'search source=mail category=malware | stats count', 1, '>', 0.0, 4, 300, 300, 0)",
        [],
    );
}

/// Dashboard « Réseau sortant (egress) » — flag `seeded_egress`. Vue de ce que le serveur CONTACTE
/// (top destinations / processus / ports depuis conntrack) + bande passante (métriques net_tx/rx).
/// Réponse à « voir un apt upgrade tirer des miroirs, un curl suspect, etc. ». Vide tant que conntrack
/// (OPT-IN) ne tourne pas, mais prêt. Dans la vue 'Sécurité'.
pub(crate) fn seed_egress_dashboard(conn: &Connection) {
    // v63 : « Réseau sortant (egress) » -> vue « Réseau & Web », REPLIÉ (non primaire).
    let Some(did) = seed_dashboard_head(conn, "egress", "Réseau sortant (egress)", "Réseau & Web", true) else { return };
    // conntrack DÉDUPE par destination -> un "stats count by dst_ip" donnerait count=1 partout (inutile)
    // -> on liste les destinations distinctes (avec proc+port). Bande passante = envoyée seulement
    // (reçue = déjà 'Réseau ↓' sur la vue d'ensemble -> pas de doublon).
    let panels: [(&str, &str, &str); 4] = [
        ("Destinations externes", "search source=conntrack dir=outbound scope=external | sort -ts | table dst_host,dst_ip,proc,dport", "table"),
        ("Processus sortants", "search source=conntrack dir=outbound scope=external | stats count by proc | sort -count | head 15", "bar"),
        ("Ports de destination", "search source=conntrack dir=outbound scope=external | stats count by dport | sort -count | head 15", "bar"),
        ("Bande passante envoyée (o/s)", "metric net_tx_bps | timechart avg(value)", "line"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}

/// Dashboard « Trafic web » (FortiGate-like) — vue du trafic HTTP ENTRANT via les access-logs
/// Traefik (collecteur web.sh, events source=web). Idempotent PAR NOM. Vide tant que web.sh
/// (OPT-IN) ne tourne pas, mais prêt. Dans la vue 'Sécurité'.
pub(crate) fn seed_web_dashboard(conn: &Connection) {
    // v63 : « Trafic web » est le dashboard PRIMAIRE (déplié) de la vue « Réseau & Web ».
    let Some(did) = seed_dashboard_head_named(conn, "Trafic web", "Réseau & Web", false) else { return };
    // Panneaux GROUP-BY PURS (vhost/status/path) -> lisent le pré-agrégé event_dim_rollup (is_soql=0,
    // <100 ms, pré-chauffables) ; les autres (timechart / filtre scope / table détail) restent SOQL live.
    let (q_vhost, q_status, q_path) = (
        dim_panel_sql("web", "vhost", 0, false),
        dim_panel_sql("web", "status", 0, false),
        dim_panel_sql("web", "path", 20, false),
    );
    let panels: [(&str, &str, i64, &str); 7] = [
        ("Requêtes dans le temps", "search source=web | timechart count", 1, "line"),
        ("Top hôtes (sites)", q_vhost.as_str(), 0, "bar"),
        ("Codes statut", q_status.as_str(), 0, "bar"),
        ("Top clients externes", "search source=web scope=external __OPERATOR_EXCL__ | stats count by src_ip | sort -count | head 20", 1, "table"),
        ("Top URLs", q_path.as_str(), 0, "table"),
        ("Erreurs 4xx/5xx (détail)", "search source=web __OPERATOR_EXCL__ __SELF_EXCL__ | where severity>=2 | sort -ts | table vhost,path,status,src_ip,ua", 1, "table"),
        // CF EXTERNE débruité : l'essentiel des events source=cloudflare peut être de l'auto-trafic opérateur
        // (navigateur du dashboard). Les placeholders __OPERATOR_EXCL__ (IP opérateur) + __SELF_EXCL__ (vhost self),
        // substitués SEULEMENT dans compile_panel_sql (jamais dans les règles/la collecte), laissent l'activité CF
        // RÉELLE. Voie LIVE (les termes d'exclusion injectés bloquent le rollup-route -> soql_to_sql sur `event`).
        ("Cloudflare (hors self)", "search source=cloudflare __OPERATOR_EXCL__ __SELF_EXCL__ | stats count by src_ip | sort -count | head 30", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Mail — flux & verdicts » (IronPort-like) — passerelle mail : volume + verdicts amavis
/// (CLEAN/SPAM/INFECTED/BANNED), top expéditeurs/destinataires, menaces, échecs d'auth. Idempotent
/// par nom. Vide tant que mail.sh (OPT-IN) ne tourne pas. Vue 'Sécurité'.
pub(crate) fn seed_mail_dashboard(conn: &Connection) {
    // v63 : « Mail — flux & verdicts » est le seul dashboard (primaire/déplié) de la vue « Mail ».
    let Some(did) = seed_dashboard_head_named(conn, "Mail — flux & verdicts", "Mail", false) else { return };
    // « Verdicts » est un GROUP-BY pur (le filtre verdict=* ≡ verdict IS NOT NULL ≡ val<>'') -> pré-agrégé
    // is_soql=0. Les autres panneaux gardent un filtre/agrégat non couvert par le rollup -> SOQL live.
    let q_verdict = dim_panel_sql("mail", "verdict", 0, true);
    let panels: [(&str, &str, i64, &str); 6] = [
        ("Verdicts", q_verdict.as_str(), 0, "bar"),
        ("Flux mail dans le temps", "search source=mail verdict=* | timechart count", 1, "line"),
        ("Top expéditeurs", "search source=mail verdict=* | stats count by sender | sort -count | head 15", 1, "table"),
        ("Top destinataires", "search source=mail verdict=* | stats count by rcpt | sort -count | head 15", 1, "table"),
        ("Menaces (virus / bannis)", "search source=mail | where severity>=3 | sort -ts | table rcpt,sender,verdict,virus,src_ip", 1, "table"),
        ("Échecs d'authentification", "search source=mail action=failure | stats count by src_ip | sort -count | head 15", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Accès données (Varonis) » — gouvernance d'accès : QUI (humain) a fait QUELLE action
/// sur QUEL fichier sensible (events source=dataaccess, collecteur dataaccess.sh + watches auditd
/// plume_data/plume_etc/plume_creds). Idempotent par nom. Vide tant que dataaccess.sh ne tourne pas. Vue 'Sécurité'.
pub(crate) fn seed_dataaccess_dashboard(conn: &Connection) {
    // v63 : « Accès données (Varonis) » est le dashboard PRIMAIRE (déplié) de la vue « Accès données ».
    let Some(did) = seed_dashboard_head_named(conn, "Accès données (Varonis)", "Accès données", false) else { return };
    // GROUP-BY purs (user/action/path) -> pré-agrégé is_soql=0 ; creds/timechart/détail restent SOQL live.
    let (q_user, q_action, q_path) = (
        dim_panel_sql("dataaccess", "user", 0, false),
        dim_panel_sql("dataaccess", "action", 0, false),
        dim_panel_sql("dataaccess", "path", 20, false),
    );
    let panels: [(&str, &str, i64, &str); 6] = [
        ("Accès aux secrets / creds", "search source=dataaccess key=plume_creds | sort -ts | table user,action,path,comm", 1, "table"),
        ("Accès par utilisateur", q_user.as_str(), 0, "bar"),
        ("Accès par action", q_action.as_str(), 0, "bar"),
        ("Top fichiers touchés", q_path.as_str(), 0, "table"),
        ("Activité dans le temps", "search source=dataaccess | timechart count", 1, "line"),
        ("Détail récent (qui/action/fichier)", "search source=dataaccess | sort -ts | table user,action,path,key,comm", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Carte d'accès (Varonis) » — gouvernance : QUI PEUT accéder à QUOI + propriétaire
/// (events source=dataacl, collecteur dataacl.sh : perms/owner des chemins sensibles + flags risque).
/// Idempotent par nom. Vide tant que dataacl.sh ne tourne pas. Vue 'Sécurité'.
pub(crate) fn seed_dataacl_dashboard(conn: &Connection) {
    // v63 : « Carte d'accès (Varonis) » -> vue « Accès données », REPLIÉ (non primaire).
    let Some(did) = seed_dashboard_head_named(conn, "Carte d'accès (Varonis)", "Accès données", true) else { return };
    // GROUP-BY purs (owner/group) -> pré-agrégé is_soql=0 ; risques/carte/détail (filtre+table) SOQL live.
    let (q_owner, q_group) = (
        dim_panel_sql("dataacl", "owner", 0, false),
        dim_panel_sql("dataacl", "group", 0, false),
    );
    let panels: [(&str, &str, i64, &str); 5] = [
        ("Risques (accès global / SUID)", "search source=dataacl | where severity>=3 | sort -ts | table path,owner,mode,risk", 1, "table"),
        ("Par propriétaire", q_owner.as_str(), 0, "bar"),
        ("Par groupe", q_group.as_str(), 0, "bar"),
        ("Carte des dossiers (perms)", "search source=dataacl type=d | sort -ts | table path,owner,group,mode", 1, "table"),
        ("Tout (chemin / owner / perms)", "search source=dataacl | sort -ts | table path,owner,group,mode,flags,risk", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Posture de configuration (SCA/CIS) » (#57) — évaluation de conformité endpoint (BYO-agent :
/// Wazuh SCA, openscap, packs osquery). Events `category=posture` : hôte × benchmark × contrôle × pass|fail
/// × cadres de conformité. Idempotent par nom. VIDE tant qu'aucune télémétrie SCA n'est ingérée (source
/// endpoint via `PLUME_ENDPOINT_NORMALIZE`, défaut `wazuh`). Vue « Endpoint (BYO-agent) » — PRIMAIRE (déplié).
pub(crate) fn seed_sca_dashboard(conn: &Connection) {
    let Some(did) = seed_dashboard_head_named(conn, "Posture de configuration (SCA/CIS)", "Endpoint (BYO-agent)", false) else { return };
    // Panneaux SOQL live (volume posture modeste ; pas de rollup dédié). Composent sur `category=posture` +
    // champs `posture_*`/`agent_name` normalisés par `endpoint_normalize` -> lecture SOQL masquée (RBAC/#45).
    let panels: [(&str, &str, i64, &str); 5] = [
        ("Contrôles pass / fail", "search category=posture posture_kind=check | stats count by posture_result", 1, "bar"),
        ("Échecs par hôte", "search category=posture posture_result=fail | stats count by agent_name | sort -count | head 20", 1, "table"),
        ("Échecs par benchmark", "search category=posture posture_result=fail | stats count by posture_policy | sort -count | head 20", 1, "bar"),
        ("Cadres de conformité impactés", "search category=posture posture_result=fail | stats count by posture_framework | sort -count | head 15", 1, "table"),
        ("Contrôles échoués (détail)", "search category=posture posture_result=fail | sort -ts | table agent_name,posture_policy,posture_check_id,posture_check_title,posture_compliance", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « Vulnérabilités (CVE endpoint) » (#57) — inventaire des vulnérabilités remontées par l'agent
/// endpoint du client (BYO : Wazuh vulnerability-detector, EDR). Events `category=vuln` : hôte × CVE × paquet
/// × sévérité × statut. Idempotent par nom. VIDE tant qu'aucune télémétrie vuln n'est ingérée. Vue « Endpoint
/// (BYO-agent) » — REPLIÉ (non primaire).
pub(crate) fn seed_vuln_dashboard(conn: &Connection) {
    let Some(did) = seed_dashboard_head_named(conn, "Vulnérabilités (CVE endpoint)", "Endpoint (BYO-agent)", true) else { return };
    let panels: [(&str, &str, i64, &str); 5] = [
        ("CVE par sévérité", "search category=vuln | stats count by vuln_severity", 1, "bar"),
        ("Hôtes les plus vulnérables", "search category=vuln | stats count by agent_name | sort -count | head 20", 1, "table"),
        ("Top CVE", "search category=vuln | stats count by cve | sort -count | head 20", 1, "table"),
        ("Paquets les plus touchés", "search category=vuln | stats count by vuln_package | sort -count | head 20", 1, "table"),
        ("Critiques / hautes (détail)", "search category=vuln | where severity>=3 | sort -ts | table agent_name,cve,vuln_severity,vuln_package,vuln_package_version,vuln_cvss", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// #38 — Dashboard de POSTURE DE CONFORMITÉ pour UN cadre (PCI DSS / HIPAA / NIST 800-53…). SOQL-backed,
/// seedé au boot (idempotent par nom), dans la vue « Conformité (posture) ». Compose la posture SCA ingérée
/// (#57, `category=posture`) FILTRÉE au cadre (`posture_framework=*<fw>*`, wildcard -> LIKE injection-safe,
/// littéral) : pass/fail global, échecs par contrôle, par hôte, détail. HONNÊTE : c'est de la COUVERTURE /
/// POSTURE, pas une certification. VIDE tant qu'aucune télémétrie SCA de ce cadre n'est ingérée. Les DÉTECTIONS
/// mappées au cadre (`rule.compliance`) sont surfacées par `/api/compliance/posture` (table `rule`, hors event).
/// `primary` = déplié (1er cadre) ; les autres repliés. Le filtre `<fw>` est un id de vocab (jamais entrée user).
pub(crate) fn seed_compliance_dashboard(conn: &Connection, fw_id: &str, label: &str, primary: bool) {
    let dash_name = format!("Conformité — {label}");
    // primary -> déplié ; secondaire -> replié (collapsed = !primary).
    let Some(did) = seed_dashboard_head_named(conn, &dash_name, "Conformité (posture)", !primary) else { return };
    // Filtre cadre : `posture_framework=*<fw>*` (wildcard SOQL -> LIKE '%<fw>%', échappé par le compilo). Le
    // token <fw> est un id de vocab CONSTANT (aucune entrée utilisateur) -> injection-safe.
    let f = format!("posture_framework=*{fw_id}*");
    let q_passfail = format!("search category=posture posture_kind=check {f} | stats count by posture_result");
    let q_bycontrol = format!("search category=posture posture_result=fail {f} | stats count by posture_compliance | sort -count | head 20");
    let q_byhost = format!("search category=posture posture_result=fail {f} | stats count by agent_name | sort -count | head 20");
    let q_detail = format!("search category=posture posture_result=fail {f} | sort -ts | table agent_name,posture_check_id,posture_check_title,posture_compliance");
    let panels: [(&str, &str, &str); 4] = [
        ("Contrôles pass / fail", q_passfail.as_str(), "bar"),
        ("Échecs par contrôle", q_bycontrol.as_str(), "table"),
        ("Échecs par hôte", q_byhost.as_str(), "table"),
        ("Contrôles échoués (détail)", q_detail.as_str(), "table"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}

/// #38 — seed des dashboards de conformité pour les cadres MAJEURS (PCI DSS déplié, HIPAA + NIST 800-53 repliés).
/// Idempotent (chaque sous-seed l'est par nom). Additif : VIDES tant qu'aucune posture SCA n'est ingérée -> mode 0.
pub(crate) fn seed_compliance_dashboards(conn: &Connection) {
    seed_compliance_dashboard(conn, "pci_dss", "PCI DSS", true);
    seed_compliance_dashboard(conn, "hipaa", "HIPAA", false);
    seed_compliance_dashboard(conn, "nist_800_53", "NIST 800-53", false);
}

/// Dashboard « RBAC k8s (Varonis) » — gouvernance d'accès du cluster : QUI PEUT accéder à QUOI
/// (events source=kube-rbac, collecteur kube-rbac.sh : bindings -> sujet/rôle/scope + flags risque
/// cluster-admin / secrets-access). Idempotent par nom. Vue 'Sécurité'.
pub(crate) fn seed_kube_rbac_dashboard(conn: &Connection) {
    // v63 : « RBAC k8s (Varonis) » est le dashboard PRIMAIRE (déplié) de la vue « Accès infra ».
    let Some(did) = seed_dashboard_head_named(conn, "RBAC k8s (Varonis)", "Accès infra", false) else { return };
    // GROUP-BY purs (role/subject) -> pré-agrégé is_soql=0 ; cluster-admin/accès sensible/map (filtre+table) SOQL live.
    let (q_role, q_subject) = (
        dim_panel_sql("kube-rbac", "role", 20, false),
        dim_panel_sql("kube-rbac", "subject", 20, false),
    );
    let panels: [(&str, &str, i64, &str); 5] = [
        ("Cluster-admin (clés du royaume)", "search source=kube-rbac role=cluster-admin | table subject,kind,binding", 1, "table"),
        ("Accès sensible (secrets / cluster-admin)", "search source=kube-rbac | where severity>=3 | sort -severity | table subject,kind,role,scope,ns,risk", 1, "table"),
        ("Par rôle", q_role.as_str(), 0, "bar"),
        ("Par sujet", q_subject.as_str(), 0, "table"),
        ("Map complète (sujet -> rôle)", "search source=kube-rbac | sort -ts | table subject,kind,role,scope,ns,risk", 1, "table"),
    ];
    for (i, (title, q, is_soql, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,?4,?5,?6,2)",
            params![did, title, q, is_soql, viz, i as i64],
        );
    }
}

/// Dashboard « MinIO / S3 (Varonis) » — gouvernance du stockage objet : QUI a accès à QUEL bucket
/// (utilisateurs -> policy) + buckets exposés publiquement (events source=minio, collecteur minio.sh).
/// Idempotent par nom. Vue 'Sécurité'.
pub(crate) fn seed_minio_dashboard(conn: &Connection) {
    // v63 : « MinIO / S3 (Varonis) » -> vue « Accès infra », REPLIÉ (non primaire).
    let Some(did) = seed_dashboard_head_named(conn, "MinIO / S3 (Varonis)", "Accès infra", true) else { return };
    let panels: [(&str, &str, &str); 5] = [
        ("Buckets exposés (PUBLIC)", "search source=minio kind=bucket risk=public | table subject,access", "table"),
        ("Accès sensible (admin / rw)", "search source=minio kind=user | where severity>=2 | sort -severity | table subject,policy,risk,status", "table"),
        ("Utilisateurs -> policy", "search source=minio kind=user | table subject,policy,status,risk", "table"),
        ("Buckets (accès)", "search source=minio kind=bucket | table subject,access,risk", "table"),
        ("Stockage", "search source=minio kind=store | sort -ts | head 1 | table buckets,objects,versions", "table"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}

/// Dashboard « Vault — accès secrets (Varonis) » — QUI accède à QUEL secret (events source=vault-audit
/// via collecteur custom + parsers v28). VIDE tant que l'audit device Vault n'est pas activé (1 commande,
/// token OIDC) ; Vault HMAC les valeurs -> aucun secret en clair n'est collecté. Idempotent. Vue 'Sécurité'.
pub(crate) fn seed_vault_dashboard(conn: &Connection) {
    // v63 : « Vault — accès secrets (Varonis) » -> vue « Accès infra », REPLIÉ (non primaire).
    let Some(did) = seed_dashboard_head_named(conn, "Vault — accès secrets (Varonis)", "Accès infra", true) else { return };
    let panels: [(&str, &str, &str); 5] = [
        ("Accès secrets (volume)", "search source=vault-audit vtype=response | timechart count", "line"),
        ("Top chemins consultés", "search source=vault-audit vtype=response | stats count by path | sort -count | head 20", "table"),
        ("Par opération", "search source=vault-audit vtype=response | stats count by operation | sort -count", "bar"),
        ("Qui accède (identités)", "search source=vault-audit vtype=response | stats count by user | sort -count | head 20", "table"),
        ("Refus / erreurs", "search source=vault-audit | where error!=\"\" | sort -ts | table user,operation,path,error", "table"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}

/// Règles de détection egress — flag `seeded_egress_rules`, TOUTES OFF (opt-in : la détection
/// réseau sortante peut être bruyante ; l'analyste active après revue). (1) sortie externe sur port
/// inhabituel (>1024 = souvent C2) ; (2) pic de bande passante sortante (exfiltration / gros upload).
pub(crate) fn seed_egress_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_egress_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_egress_rules','1')", []);
    // (name, query, is_soql, op, threshold, severity, interval_s, window_s)
    let rules: [(&str, &str, i64, &str, f64, i64, i64, i64); 2] = [
        ("Egress externe sur port inhabituel (>1024)", "search source=conntrack dir=outbound scope=external | where dport>1024 | stats count", 1, ">", 0.0, 2, 600, 3600),
        ("Pic de bande passante sortante (exfil ?)", "SELECT value FROM metric WHERE name='net_tx_bps' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1", 0, ">", 10485760.0, 2, 300, 600),
    ];
    for (name, q, is_soql, op, th, sev, intv, win) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![name, q, is_soql, op, th, sev, intv, win],
        );
    }
}

/// Règles d'exemple — flag dédié `seeded_rules` (arrivent même si le dashboard a déjà été seedé).
pub(crate) fn seed_example_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_rules','1')", []);
    // Dernière colonne = tag MITRE ATT&CK (purple) : technique que la règle DÉTECTE. Sert de clé de
    // jointure avec les techniques tirées par Forge (red) -> /api/coverage/detections (detected/missed).
    // '' = règle opérationnelle non mappée (ex CPU) -> exclue de la couverture (filtre mitre<>'').
    let rules: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 2] = [
        ("Pic d'échecs d'authentification (1h)", "search severity>=3 | stats count", 1, ">", 100.0, 3, 300, 3600, "T1110"),
        ("CPU > 90% (10 min)", "SELECT value FROM metric WHERE name='cpu_pct' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1", 0, ">", 90.0, 2, 300, 600, ""),
    ];
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
}

/// Règles purple ATT&CK — flag DÉDIÉ `seeded_purple_rules` (PAS `seeded_rules`) : ainsi elles
/// s'insèrent même sur une DB DÉJÀ seedée par seed_example_rules (qui court-circuiterait sur son
/// propre flag). ENABLED=1 (détection live). Tag MITRE -> jointure couverture red/purple (Forge).
/// NB T1190 : la query est un PROXY 5xx par IP (pic d'erreurs serveur = signal d'exploit web) : elle
/// couvre les exploits qui font ÉCHOUER l'application. Complétez-la par vos propres règles applicatives
/// (autorisation/accès) selon les techniques que vous voulez couvrir.
pub(crate) fn seed_purple_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_purple_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_purple_rules','1')", []);
    // (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre, enabled)
    // CHANGE 6 (v103) : le 5xx-par-IP (T1190, `source=web status>=500`) est SEEDÉ enabled=0 — DOUBLON de
    // l'overlay id 89 « Exploit web : rafale de 5xx » (`category=web status>=500`, un SUR-ENSEMBLE : category
    // couvre TOUTES les sources web, pas juste source=web). L'overlay (règle de session Forge) reste le côté
    // GAGNANT. Ce seed captait UNIQUEMENT les floods 5xx mono-chemin (partiellement couverts par id 27) —
    // dédoublonnage acceptable. PORTÉE de ce enabled=0 : DÉFAUT base-neuve SEULEMENT — sur une base déjà
    // seedée (prod, flag meta `seeded_purple_rules` posé) cette fonction court-circuite (return) et ne
    // retouche JAMAIS la ligne existante. La désactivation de la ligne LIVE est faite par migrate_v102
    // (UPDATE rétroactif one-time, CHANGE 6). Les deux AUTRES règles purple (port-scan T1046, web-scan 404
    // T1595.002 = complémentaire d'un filtrage edge) restent enabled=1. (NB : id 21=404-origin reste activée ;
    // seul id 22=5xx est désactivé.)
    let rules: [(&str, &str, i64, &str, f64, i64, i64, i64, &str, i64); 3] = [
        ("Port-scan entrant (UFW, 10 min)", "search source=ufw | stats dc(dport) by src_ip | where dc > 15 | stats count", 1, ">", 0.0, 3, 300, 600, "T1046", 1),
        ("Web-scan : pic de 404 par IP (10 min)", "search source=web status=404 | stats dc(path) by src_ip | where dc > 30 | stats count", 1, ">", 0.0, 2, 300, 600, "T1595.002", 1),
        ("Anomalie exploit web : pic de 5xx par IP (10 min)", "search source=web status>=500 | stats count by src_ip | where count > 10 | stats count", 1, ">", 0.0, 4, 300, 600, "T1190", 0),
    ];
    for (name, q, is_soql, op, th, sev, intv, win, mitre, enabled) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre, enabled],
        );
    }
}

/// Règles de détection v50 — nouveaux signaux de télémétrie hôte/infra posés cette session
/// (minio-audit, auditd category=tamper, integrity kind/change, conntrack flux, vault-audit). Const
/// PARTAGÉE entre le SEED (seed_detection_rules -> repro sur PVC neuf) et la MIGRATION v50 (INSERT sur
/// l'instance DÉJÀ déployée : le seed ne re-tourne jamais une fois son flag posé). Toutes ENABLED=1,
/// is_soql=1, op '>' seuil 0.0 (= « count>0 sur la fenêtre »). Chaque requête est VALIDÉE contre les
/// vrais events (matche le signal, ne flood pas le trafic légitime) :
///   1. minio-audit `api=~^Delete[BM]` (DeleteBucket/DeleteMultipleObjects = wipe bulk / drop de bucket,
///      signature `mc rm`/ransomware) sur les buckets *backups. EXCLUT volontairement les DeleteObject/
///      DeleteObjectVersion par-objet (rotation velero / ILM NoncurrentVersionExpiration) -> pas de flood
///      sur la rotation légitime. T1490 (HIGH).
///   2. variante AccessDenied sur un Delete* backup = tentative de tamper refusée (tripwire, 0 légitime).
///   3. auditd category=tamper severity>=4 : le collecteur tague sev4 UNIQUEMENT sudoers.d/shadow/
///      ld.so.preload/creds/persist (`plume_sensitive`) ; le trafic normal n'écrit jamais ces chemins. T1565.
///   4. integrity kind=suid change=modif : binaire SUID réécrit in-place (hash changé) = trojanisation. T1554.
///   5. integrity change=ajout severity>=3 : nouveau vecteur de persistance (le collecteur tague sev>=3
///      preload/sudoersd/authkeys/pamd/rclocal/unit/crond/suid/crit ; sev1 = port/divers, exclu). T1543.
///   6. conntrack flux : MÊME (proc,dst_ip) externe sortant répété > 10 ticks = cadence beacon. La liste
///      d'exclusion `proc!=…` de la requête et le seuil de ticks sont des EXEMPLES / PLACEHOLDERS — à
///      REMPLACER par les gros causeurs d'égress légitime de VOTRE hôte (orchestrateur, runtime de conteneurs,
///      gestionnaire de paquets/registry…) et à calibrer sur VOTRE trafic. RÈGLE LA PLUS SENSIBLE À LA
///      BASELINE : définissez vos propres exclusions et seuils. T1071 (MEDIUM).
///   7. vault-audit lecture de secret par une identité HORS {SA external-secrets, identité OIDC humaine} =
///      seuls lecteurs légitimes attendus -> toute autre identité (nouveau SA, token volé, latéralisation) =
///      tripwire. T1552. NB : les deux identités de l'allowlist (`svc-secrets`, `oidc-admin`) sont des
///      PLACEHOLDERS génériques — à adapter aux noms réels du déploiement (SA ESO + compte OIDC opérateur).
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_V50: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 7] = [
    ("MinIO: destruction de backup (suppression bulk/bucket sur *backups)",
     "search source=minio-audit bucket=*backups api=~^Delete[BM] | stats count",
     1, ">", 0.0, 4, 120, 1800, "T1490"),
    ("MinIO: tentative de tamper backup (suppression REFUSÉE sur *backups)",
     "search source=minio-audit bucket=*backups api=Delete* status=AccessDenied | stats count",
     1, ">", 0.0, 3, 300, 1800, "T1490"),
    ("Hôte: tamper fichier sensible (auditd — sudoers/shadow/ld.so.preload/creds/persist)",
     "search source=auditd category=tamper severity>=4 | stats count",
     1, ">", 0.0, 4, 120, 600, "T1565"),
    ("Hôte: binaire SUID modifié in-place (intégrité — trojanisation)",
     "search source=integrity kind=suid change=modif | stats count",
     1, ">", 0.0, 4, 300, 3600, "T1554"),
    ("Hôte: vecteur de persistance ajouté (intégrité — unit/cron/sudoers.d/authkeys/ld.preload)",
     "search source=integrity change=ajout severity>=3 | stats count",
     1, ">", 0.0, 4, 300, 3600, "T1543"),
    // NB : les `proc!=…` ci-dessous sont des PLACEHOLDERS d'exemple (cf. point 6) — à adapter à votre hôte.
    ("Égress: beaconing C2 probable (cadence répétée vers une même IP externe, proc hors infra)",
     "search source=conntrack scope=external dir=outbound proc!=k3s-server proc!=buildkitd proc!=containerd proc!=buildctl proc!=cargo | stats count by dst_ip,proc | where count > 10 | stats count",
     1, ">", 0.0, 3, 300, 1800, "T1071"),
    ("Vault: lecture de secret par une identité inattendue (hors SA external-secrets + OIDC opérateur)",
     "search source=vault-audit operation=read path=secret* user!=svc-secrets user!=oidc-admin | stats count",
     1, ">", 0.0, 3, 300, 1800, "T1552"),
];

/// RÈGLE 37 (durcissement standalone, item 2) — le SOC se détecte LUI-MÊME : rafale d'échecs d'auth
/// sur l'application Plume (events AUTO-INGÉRÉS source=plume-auth action=failure par auth_guard sur
/// chaque échec Basic). >8 échecs/IP en 5 min = brute-force CONTRE le SIEM -> T1110. Distincte de la
/// règle générique "Brute-force auth par IP" (qui couvre toute source) : celle-ci vise l'auth de Plume.
/// Source unique partagée par le seed (PVC neuf) ET la migration v51 (instance déjà déployée).
pub(crate) const DETECTION_RULES_V51: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 1] = [
    ("SOC: brute-force sur l'auth Plume elle-même (self-detection)",
     "search source=plume-auth action=failure | stats count by src_ip | where count > 8 | stats count",
     1, ">", 0.0, 4, 60, 300, "T1110"),
];

/// RÈGLE v52 — « attaquant actif NON banni » : surface le TROU de mitigation. Agrège les src_ip à forte
/// activité hostile (web status>=400 OU cloudflare action=challenged) sur la fenêtre `window_s` de la
/// règle, n'en garde que les bursts (HAVING activite > seuil par-IP), puis ANTI-JOINT la banlist
/// matérialisée (`banned_ip`, peuplée incrémentalement) : LEFT JOIN ... WHERE banned_ip.src_ip IS NULL
/// = exactement les attaquants qui frappent ENCORE et ne sont PAS bannis. is_soql=0 (le compilo SOQL ne
/// sait pas faire de LEFT JOIN / anti-join). BORNÉE : la fenêtre `window_s` (1 h) limite le scan web 4xx,
/// le HAVING par-IP élague le bruit, et l'anti-join sur banned_ip (petite table) est cheap. eval_value lit
/// la DERNIÈRE cellule de la 1re ligne -> le COUNT(*) des non-mitigés. T1595 (active scanning, le signal
/// dominant ; recon/exploit web couverts aussi par T1190). Severity 3 (medium). __FROM__ = now-window_s.
pub(crate) const ATTACKER_UNMITIGATED_RULE_SQL: &str =
    "SELECT COUNT(*) AS non_mitiges FROM ( \
       SELECT a.src_ip FROM ( \
         SELECT src_ip, SUM(c) AS activite FROM ( \
           SELECT src_ip, COUNT(*) AS c FROM event \
             WHERE source='cloudflare' AND ts>=__FROM__ AND json_extract(fields,'$.action')='challenged' \
               AND src_ip IS NOT NULL AND src_ip<>'' GROUP BY src_ip \
           UNION ALL \
           SELECT src_ip, COUNT(*) AS c FROM event \
             WHERE source='web' AND ts>=__FROM__ AND CAST(json_extract(fields,'$.status') AS INTEGER)>=400 \
               AND src_ip IS NOT NULL AND src_ip<>'' GROUP BY src_ip \
         ) GROUP BY src_ip HAVING activite > 20 \
       ) a \
       LEFT JOIN banned_ip b ON b.src_ip=a.src_ip \
       WHERE b.src_ip IS NULL \
     )";

/// Règle v52 (attaquant actif non banni) — source unique partagée par le SEED (PVC neuf) et la MIGRATION
/// v52 (instance déjà déployée : le seed ne re-tourne plus une fois son flag posé). is_soql=0 (anti-join
/// SQL natif). op '>' seuil 2.0 = fire quand ≥3 src_ip à forte activité restent NON bannies sur la fenêtre
/// (gap de mitigation systémique) -> peu bruyant (dédup `rule-{id}`, ré-armé sous le seuil). window_s=3600.
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_V52: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 1] = [
    ("Attaquant actif NON banni (web 4xx / CF challenged sans mitigation)",
     ATTACKER_UNMITIGATED_RULE_SQL,
     0, ">", 2.0, 3, 300, 3600, "T1595"),
];

/// RÈGLE v53 — YARA : match d'une règle YARA = malware/IOC détecté sur l'hôte. Le collecteur host
/// `yara.sh` (OFF par défaut : inerte tant que le binaire `yara` est absent OU qu'aucune règle n'est
/// déposée dans /etc/plume/yara.d) émet, quand activé, des events `source=yara category=malware`
/// {rule,file,tags,sha256} en severity 4. Cette règle est event-driven : tant qu'aucun event source=yara
/// n'arrive (intégration OFF) elle ne tire jamais — `count>0` sur la fenêtre = au moins un match réel.
/// is_soql=1 (simple stats count, compilable SOQL), op '>' seuil 0.0, severity 4 (un match YARA = signal
/// fort, pas de bruit de fond : le collecteur ne ship QUE les MATCHES). BORNÉE par window_s (1 h) ; dédup
/// d'alerte = clé stable `rule-{id}` (1 notif/épisode, ré-armée sous le seuil). T1204 (User Execution —
/// exécution de malware ; les règles YARA ciblent binaires/scripts malveillants déposés/exécutés).
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_V53: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 1] = [
    ("YARA : match (malware/IOC détecté)",
     "search source=yara | stats count",
     1, ">", 0.0, 4, 300, 3600, "T1204"),
];

/// RÈGLE v57 — DEAD-MAN'S-SWITCH CrowdSec (PART 2) : le MOTEUR CrowdSec est DÉGRADÉ (scénarios cassés).
/// Fire sur le battement de SANTÉ émis par collectors/crowdsec.sh à CHAQUE run (source=crowdsec
/// category=health, fields.scenarios_broken) quand AU MOINS un scénario est cassé/tainted sur la fenêtre.
/// is_soql=0 (json_extract + CAST natif, comme ATTACKER_UNMITIGATED — le compilo SOQL ne garantit pas la
/// comparaison numérique sur un champ json) : `COUNT(*)` des battements à scenarios_broken>0 sur
/// __FROM__..now ; op '>' seuil 0.0 -> fire dès ≥1. severity 4 (HIGH). T1562.001 (Impair Defenses: Disable
/// or Modify Tools — un contrôle de sécurité, l'IPS CrowdSec, défaille). Dédup d'alerte = clé stable
/// `rule-{id}` (1 notif/épisode, ré-armée sous le seuil quand scenarios_broken repasse à 0). NB : l'agent
/// INJOIGNABLE (scenarios_broken=-1) ne fire PAS cette règle (CAST(-1)>0 faux) — VOULU : un agent
/// momentanément injoignable (rolling restart) ne doit pas pager ; le moteur TOTALEMENT mort est attrapé
/// par l'alerte MUET du collecteur CONTINU `crowdsec-health` (silence du battement de santé > 25 min).
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_V57: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 1] = [
    ("CrowdSec scénarios cassés (moteur dégradé)",
     "SELECT COUNT(*) AS scen_broken FROM event WHERE source='crowdsec' AND category='health' \
      AND ts>=__FROM__ AND CAST(json_extract(fields,'$.scenarios_broken') AS INTEGER) > 0",
     0, ">", 0.0, 4, 300, 1800, "T1562.001"),
];

/// RÈGLE v75 (MODE ENGAGEMENT) — SELF-DETECTION : déclarer un engagement autorisé = BAISSER une défense
/// (suspendre l'auto-ban sur un scope). L'audit sev=4 (source=plume-engagement category=config) est écrit par
/// audit_source_change ; SANS cette règle il n'était que PASSIVEMENT visible (search ad-hoc / ledger). Ici on
/// l'ALERTE ACTIVEMENT (mirroir de la self-detection plume-auth v51) : count>0 des events plume-engagement
/// config sur la fenêtre -> l'ouverture/clôture/expiry d'un engagement page le SOC. INERTE en mode 0/off : ces
/// events ne sont écrits QUE via le sous-système engagement (endpoints gated + expiry gated) -> aucun ne survient
/// -> la règle existe mais ne tire jamais (event-driven, comme YARA/CrowdSec). T1562 (Impair Defenses).
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_V75_ENGAGEMENT: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 1] = [
    ("SOC: engagement autorisé déclaré (défense auto-ban baissée)",
     "search source=plume-engagement category=config | stats count",
     1, ">", 0.0, 4, 60, 600, "T1562"),
];

/// RÈGLES DE SELF-DETECTION — plume détecte le contrôle de plume lui-même. Miroir exact de
/// la self-detection plume-auth (v51) / plume-engagement (v75) : les événements sont écrits DIRECTEMENT par le
/// daemon (origin='daemon') via audit_config_change / auto-ingest ; ces règles les ALERTENT ACTIVEMENT au lieu
/// de les laisser PASSIVEMENT dans le ledger. event-driven : INERTES au repos (mode 0) — aucune mutation
/// d'identité / aucun déni RBAC mutant / aucun export de masse -> count=0 -> aucune alerte.
///   - C1 : mutation d'IDENTITÉ (création de compte, escalade de rôle, reset mdp, suppression) — sev 4 (créer
///     un admin / resetter un mdp = persistance/prise de contrôle). fields.action='config.user.*'.
///   - M1 : RAFALE de tampering de config (rétention/mode/règle/parser/notifier… = surface de défense) — sev 2.
///     TUNING (anti-bruit) : le seuil est une RAFALE (> 20 mutations plume-config dans la fenêtre de 900 s), PAS
///     `count>0`. Une administration quotidienne normale (quelques changements) reste SOUS le seuil et ne lève
///     RIEN ; seul un burst anormal (mutation de masse / tampering scripté baissant la défense) tire. Les
///     mutations d'IDENTITÉ à fort impact restent couvertes par C1 (sev 4, count>0). Opérateur-tunable.
///   - M2 : RAFALE de dénis RBAC sur routes MUTANTES (source=plume-authz action=denied) — un principal qui
///     martèle des routes admin qu'il n'a pas le droit d'appeler (recon/priv-esc) — sev 3, seuil > 10/principal.
///   - M3 : LECTURE/EXPORT DE MASSE (source=plume-audit action=bulk_read, émis SEULEMENT au-delà du seuil de
///     lignes) — exfiltration potentielle via /api/query|/api/export — sev 3.
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const DETECTION_RULES_SEC4: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 4] = [
    ("SOC: mutation d'identité (compte créé / rôle / reset mdp / suppression)",
     "search source=plume-config action=config.user.* | stats count",
     1, ">", 0.0, 4, 60, 900, "T1136"),
    ("SOC: rafale de mutations de configuration (tamper-evidence plume-config)",
     "search source=plume-config category=config | stats count",
     1, ">", 20.0, 2, 300, 900, "T1562"),
    ("SOC: rafale de dénis RBAC sur route mutante (recon/priv-esc)",
     "search source=plume-authz action=denied | stats count by principal | where count > 10 | stats count",
     1, ">", 0.0, 3, 300, 600, "T1078"),
    ("SOC: lecture/export de masse (exfiltration potentielle)",
     "search source=plume-audit action=bulk_read | stats count",
     1, ">", 0.0, 3, 300, 900, "T1567"),
];

/// Règles de détection ciblées — flag DÉDIÉ `seeded_detection_rules` (même mécanique EXACTE que
/// seed_purple_rules : guard meta -> return si présent, sinon INSERT puis pose le flag). ENABLED=1.
/// Couvre : port-scan (source=portscan, alimentée par un log de firewall NON rate-limité — un log
/// throttlé ne suffit pas à détecter un scan), brute-force auth par-IP (journal/auth, T1110), et 5 règles
/// taguées source=cloudflare (mitigations edge invisibles à l'origine) -> T1595.002 / T1190 / T1498 / T1595.
/// + DETECTION_RULES_V50 : nouveaux signaux télémétrie (minio/auditd/integrity/conntrack/vault).
pub(crate) fn seed_detection_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_detection_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_detection_rules','1')", []);
    // (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
    let rules: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 7] = [
        ("Port-scan détecté (nft PORTSCAN, 10 min)", "search source=portscan dir=inbound | stats count", 1, ">", 0.0, 3, 300, 600, "T1046"),
        ("Brute-force auth par IP (5 min)", "search category=auth action=failure | stats count by src_ip | where count > 15 | stats count", 1, ">", 0.0, 3, 60, 300, "T1110"),
        // Règles CF calées sur la forme des events réellement émis par le connecteur (un plan Cloudflare
        // sans WAF managé n'émet essentiellement que `action=challenged`, 1 ruleId/event : une attente
        // `action=blocked` ou `dc(ruleId)>8` ne matcherait jamais). sev 1 (INFORMATIONNEL) : signal de VOLUME
        // grossier, sensible aux faux positifs ; la règle 404-breadth est le signal PRÉCIS. Seuils à calibrer.
        ("CF: scan/bot absorbé au edge (>20 challenges managés/IP)", "search source=cloudflare action=challenged | stats count by src_ip | where count > 20 | stats count", 1, ">", 0.0, 1, 300, 900, "T1595.002"),
        ("CF: exploit WAF managé (signatures SQLi/RCE/traversal)", "search source=cloudflare action=blocked cf_source=firewallManaged | stats count by src_ip | where count > 3 | stats count", 1, ">", 0.0, 4, 300, 600, "T1190"),
        ("CF: L7 flood absorbé depuis une IP (>100 req)", "search source=cloudflare | stats count by src_ip | where count > 100 | stats count", 1, ">", 0.0, 2, 300, 300, "T1498"),
        ("CF: recon multi-vhost depuis une IP (>3 vhosts)", "search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count", 1, ">", 0.0, 2, 300, 900, "T1595"),
        ("CF: volume de challenges managés (IP distinctes)", "search source=cloudflare action=challenged | stats dc(src_ip)", 1, ">", 20.0, 2, 300, 900, "T1595"),
    ];
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règles v50 (nouveaux signaux télémétrie) — repro sur PVC neuf (la MIGRATION v50 les pose sur
    // l'instance déjà déployée où ce seed ne re-tourne plus). Source unique : DETECTION_RULES_V50.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V50 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règle 37 v51 (self-detection brute-force auth Plume) — même mécanique : seed sur PVC neuf,
    // migration v51 sur l'instance déjà déployée. Source unique : DETECTION_RULES_V51.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V51 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règle v52 (attaquant actif NON banni — anti-join sur banned_ip) — même mécanique : seed sur PVC
    // neuf, migration v52 sur l'instance déjà déployée. Source unique : DETECTION_RULES_V52.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V52 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règle v53 (YARA : match malware/IOC) — même mécanique : seed sur PVC neuf, migration v53 sur
    // l'instance déjà déployée. event-driven : inerte tant qu'aucun event source=yara. Source unique :
    // DETECTION_RULES_V53. DARK-BY-DEFAULT (Wave 3, git-durability) : enabled=0 -> une règle qui ne peut
    // JAMAIS tirer (collecteur yara.sh OFF, category=malware jamais produite) ne doit pas suggérer une
    // couverture inexistante dans la console ; un admin l'ACTIVE via le toggle une fois un producteur yara
    // câblé. (Wave 1 avait row-flippé la LIVE DB ; une DB FRAÎCHE re-seedait enabled+dark sans ce fix.)
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V53 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règle v57 (DEAD-MAN'S-SWITCH CrowdSec : scénarios cassés / moteur dégradé — source=crowdsec
    // category=health, T1562.001) — même mécanique : seed sur PVC neuf, migration v57 sur l'instance déjà
    // déployée. Source unique : DETECTION_RULES_V57.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V57 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règle v75 (self-detection : engagement autorisé déclaré = défense baissée) — même mécanique : seed
    // sur PVC neuf, migration v75 sur l'instance déjà déployée. event-driven : inerte tant qu'aucun event
    // source=plume-engagement (mode 0/off). Source unique : DETECTION_RULES_V75_ENGAGEMENT.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_V75_ENGAGEMENT {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
    // + règles de self-detection (identité/config-tamper/RBAC-deny/export-de-masse) —
    // même mécanique : seed sur PVC neuf. event-driven : inertes en mode 0. Source unique : DETECTION_RULES_SEC4.
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in DETECTION_RULES_SEC4 {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        );
    }
}

/// ACTIVATION THREAT-INTEL (#23) — règles d'alerte MANAGÉES sur un match IOC de HAUTE CONFIANCE. Flag DÉDIÉ
/// `seeded_ti_alert_rules` (même mécanique EXACTE que seed_purple_rules : guard meta -> return si présent,
/// sinon INSERT + audit + pose le flag). managed=0 (builtin/seed : VISIBLE dans l'UI, ÉDITABLE — l'édition
/// l'ADOPTE en managed=2 —, RÉVERSIBLE — la suppression le DÉSACTIVE sans le détruire ; jamais un refus 409
/// comme un overlay config.d managed=1). AUDITÉ (audit_config_change) -> traçable comme toute activation.
///
/// INERTE tant qu'aucun IOC n'est chargé (store vide -> `ti_match` n'est jamais écrit dans `fields` ->
/// `search ti_match=1 …` renvoie 0 -> count>0 FAUX -> aucune alerte). Une fois des IOC importés, un event
/// dont une valeur (ip/domain/url/hash/email) matche un IOC actif de confiance >=80 lève une alerte dont la
/// SÉVÉRITÉ est DÉRIVÉE de la sévérité de l'IOC (bande haute `ti_severity>=4` -> sévérité 4 ; bande moyenne
/// `ti_severity<=3` -> sévérité 3), via les marqueurs plats `ti_confidence`/`ti_severity` posés par
/// l'enrichissement (ti_enrich). event-driven (comme YARA/CrowdSec) : pas de flood au repos.
/// (name, query, is_soql, op, threshold, severity, interval_s, window_s, mitre)
pub(crate) const TI_ALERT_RULES: [(&str, &str, i64, &str, f64, i64, i64, i64, &str); 2] = [
    ("Threat-intel : IOC haute-sévérité vu sur le réseau (confiance≥80)",
     "search ti_match=1 ti_confidence>=80 ti_severity>=4 | stats count",
     1, ">", 0.0, 4, 60, 300, ""),
    ("Threat-intel : IOC vu sur le réseau (confiance≥80)",
     "search ti_match=1 ti_confidence>=80 ti_severity<=3 | stats count",
     1, ">", 0.0, 3, 60, 300, ""),
];
pub(crate) fn seed_ti_alert_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_ti_alert_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_ti_alert_rules','1')", []);
    let mut n = 0i64;
    for (name, q, is_soql, op, th, sev, intv, win, mitre) in TI_ALERT_RULES {
        // managed=0 (défaut builtin/seed) -> éditable/réversible en UI. DARK-BY-DEFAULT (Wave 3,
        // git-durability) : enabled=0 -> tant qu'AUCUN feed IOC n'est ingéré, `ti_match` n'est jamais
        // écrit -> la règle est GHOST (ne peut pas tirer). Une règle activée-mais-dark suggère une
        // couverture threat-intel qui n'existe pas ; un admin l'ACTIVE via le toggle une fois un
        // producteur/feed IOC câblé. (Wave 1 avait row-flippé la LIVE DB ; une DB FRAÎCHE re-seedait
        // enabled+dark sans ce fix.)
        if conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
            params![name, q, is_soql, op, th, sev, intv, win, mitre],
        ).is_ok() { n += 1; }
    }
    // AUDIT (traçabilité de l'activation) — best-effort, hors transaction du boot (le seed n'est pas gated).
    let _ = audit_config_change(
        conn, "config.seed.ti_alert",
        &format!("{n} règle(s) d'alerte threat-intel seedée(s) DÉSACTIVÉES (dark-by-default)"),
        2,
        &format!("seed threat-intel : {n} règle(s) d'alerte MANAGÉE(S) sur match IOC confiance≥80, seedées DÉSACTIVÉES (dark-by-default : inertes tant qu'aucun IOC chargé ; un admin les active via le toggle une fois un feed câblé)"),
        &json!({ "seeded": n, "kind": "ti_alert_rules" }).to_string(),
    );
}

/// ACTIVATION RBA (#24) — règles de détection MANAGÉES en MODE RISK (risk_score>0). Flag DÉDIÉ
/// `seeded_risk_rules`. managed=0 (VISIBLE/ÉDITABLE/RÉVERSIBLE en UI, comme les autres seeds). Chaque règle
/// est exclue de run_due_rules (elle ne lève PAS d'alerte scalaire) et traitée par run_risk_rules : sa
/// requête `search … | stats count by <entity>` CONTRIBUE `risk_score` points à CHAQUE entité de la colonne
/// `risk_entity_field` (typée `risk_entity_type`). Le risque s'ACCUMULE par entité (rollup_risk) et lève UNE
/// alerte risk-based dédupliquée au franchissement d'un seuil (cumul / tactiques distinctes / vélocité).
///
///   1. brute-force par src_ip : échecs d'auth groupés par IP source -> risque sur l'entité `ip`. T1110.
///   2. recon/portscan par host : port-scans (nft PORTSCAN) + scans de service groupés par HÔTE ciblé ->
///      risque sur l'entité `host`. T1046.
/// INERTE au repos : sans trafic hostile la requête renvoie 0 ligne -> aucune contribution -> aucun
/// risk_event -> rollup_risk fast-path -> aucune alerte (mode 0 byte-identique tant qu'aucune donnée).
/// La composition ti->risk (#23->#24) est ON par défaut (PLUME_RISK_TI_SCORE=20) : un match IOC contribue
/// aussi du risque à l'entité — ces règles + la compo ti alimentent le MÊME accumulateur par entité.
/// (name, query, is_soql, window_s, severity, risk_score, risk_entity_type, risk_entity_field, interval_s, mitre)
pub(crate) const RISK_STARTER_RULES: [(&str, &str, i64, i64, i64, i64, &str, &str, i64, &str); 2] = [
    ("RBA : brute-force d'authentification (risque par IP source)",
     "search category=auth action=failure | stats count by src_ip | where count > 5",
     1, 3600, 3, 30, "ip", "src_ip", 300, "T1110"),
    ("RBA : reconnaissance / port-scan (risque par hôte ciblé)",
     "search source=portscan dir=inbound | stats count by host | where count > 0",
     1, 3600, 3, 20, "host", "host", 300, "T1046"),
];
pub(crate) fn seed_risk_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_risk_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_risk_rules','1')", []);
    let mut n = 0i64;
    for (name, q, is_soql, win, sev, risk_score, etype, efield, intv, mitre) in RISK_STARTER_RULES {
        // enabled=1 + risk_score>0 -> MODE RISK (run_risk_rules), managed=0 (éditable/réversible en UI).
        if conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,enabled,risk_score,risk_entity_type,risk_entity_field) \
             VALUES(?1,?2,?3,'>',0.0,?4,?5,?6,?7,1,?8,?9,?10)",
            params![name, q, is_soql, sev, intv, win, mitre, risk_score, etype, efield],
        ).is_ok() { n += 1; }
    }
    let _ = audit_config_change(
        conn, "config.seed.risk_rules",
        &format!("{n} règle(s) RBA (mode risque) activée(s) (seed managé)"),
        2,
        &format!("activation RBA : {n} règle(s) MANAGÉE(S) en mode risque (brute-force par IP, recon par hôte) ; composition ti->risk ON (PLUME_RISK_TI_SCORE=20)"),
        &json!({ "seeded": n, "kind": "risk_rules" }).to_string(),
    );
}

/// Playbook d'exemple (flag dédié). Sûr : en mode 'observe' (défaut) il ne fait que PROPOSER (pending+dry-run).
pub(crate) fn seed_example_playbooks(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_playbooks'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_playbooks','1')", []);
    let _ = conn.execute(
        "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s) \
         VALUES('SSH bruteforce -> ban IP (démo, OFF : laisser CrowdSec/fail2ban gérer)', 0, 'search source=sshd-session severity>=3 | stats count by src_ip | where count > 10', 1, 'ban_ip', 300, 3600)",
        [],
    );
}

/// Playbook CVE-2024-6387 (regreSSHion) — remplace le scénario CrowdSec ssh-cve quand on retire
/// la source ssh de CrowdSec (re-home off Loki). OFF par défaut (opt-in) ; en mode 'observe' il
/// PROPOSE le ban (pending + dry-run), en 'active' il l'applique (délégation nft/fail2ban).
/// NB enforcement multi-hôte : l'action se crée sur le central ; l'exécuter SUR le VPS nécessite
/// le responder agent-side (à venir) — pour l'instant détection + action en attente (l'analyste valide).
pub(crate) fn seed_ssh_cve_playbook(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_ssh_cve'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_ssh_cve','1')", []);
    let _ = conn.execute(
        "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s) \
         VALUES('SSH CVE-2024-6387 (regreSSHion) -> ban IP (OFF ; remplace le scénario CrowdSec ssh-cve)', \
                0, 'search source=~sshd \"Timeout before authentication\" | stats count by src_ip | where count > 5', 1, 'ban_ip', 300, 3600)",
        [],
    );
}

/// Règles filet-de-sécurité k8s/hôte — TOUTES seedées DÉSACTIVÉES (activer quand la métrique existe,
/// sinon faux positifs sur métrique absente). Flag dédié.
// OBS-4 : dashboard de parité (métriques + logs) — utilise la soql metric/rate/timechart + search.
pub(crate) fn seed_obs_dashboard(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_obs'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_obs','1')", []);
    if conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('Infra & logs (OBS)', ?1, 'shared')", params![now()]).is_err() {
        return;
    }
    let did = conn.last_insert_rowid();
    // v63 : ce dashboard (jadis orphelin, view_id NULL) rejoint la vue dédiée « Infra & logs » (primaire/déplié).
    if let Some(vid) = find_or_create_view(conn, "Infra & logs") { let _ = conn.execute("UPDATE dashboard SET view_id=?1 WHERE id=?2", params![vid, did]); }
    let panels: [(&str, &str, &str, i64); 6] = [
        ("CPU charge (load1)", "metric load1 | timechart span=1m avg(value)", "line", 2),
        ("Mémoire (%)", "metric mem_pct | timechart span=1m avg(value)", "line", 1),
        ("Réseau reçu (o/s)", "metric net_rx_bps | timechart span=1m avg(value)", "line", 1),
        ("Pods Running", "metric kube_pods_running | timechart avg(value)", "line", 1),
        ("Volume de logs (5m)", "search | timechart span=5m count", "line", 2),
        ("Top sources de logs", "search | stats count by source | sort -count | head 30", "bar", 1),
    ];
    for (i, (title, q, viz, cols)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,1,?4,?5,?6)",
            params![did, title, q, viz, i as i64, cols],
        );
    }
}

// OBS-6 : alertes métriques/logs d'exemple (DÉSACTIVÉES — à activer après branchement des données).
pub(crate) fn seed_obs_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_obs_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_obs_rules','1')", []);
    let rules: [(&str, &str, &str, f64, i64, i64, i64); 3] = [
        ("hôte: charge CPU élevée (load1)", "metric load1 | stats max(value)", ">", 8.0, 2, 120, 300),
        ("hôte: mémoire élevée (%)", "metric mem_pct | stats max(value)", ">", 90.0, 3, 120, 300),
        ("logs: pic d'erreurs (sév>=3)", "search severity>=3 | stats count", ">", 20.0, 2, 120, 300),
    ];
    for (name, q, op, th, sev, intv, win) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) VALUES(?1,?2,1,?3,?4,?5,?6,?7,0)",
            params![name, q, op, th, sev, intv, win],
        );
    }
}

/// §A — règles readiness StatefulSets (remplacent les alertes AM mailserver/vault/sts). Dépendent des
/// métriques `kube_sts_*` de kube-state.sh. OFF par défaut (tester puis activer). cf PROM-AM-DECOMMISSION.
pub(crate) fn seed_sts_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_sts_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_sts_rules','1')", []);
    // GÉNÉRIQUE (toute infra) : au moins 1 StatefulSet pas prêt (ready<desired) depuis la fenêtre.
    let _ = conn.execute(
        "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) \
         VALUES('k8s: StatefulSet pas prêt','metric kube_sts_notready | stats max(value)',1,'>',0.0,3,120,600,0)",
        [],
    );
    // PAR APP critique : INFRA-EN-CONFIG via PLUME_WATCH_STS="ns/nom …" (même variable que kube-state.sh,
    // qui émet kube_sts_ready_<nom>). 0 réplique prête = app down/absente -> alerte sév 4. Défaut = apps
    // GuatX (exemple/compat) ; produit générique : définir la liste de SON infra (ou vide = aucune).
    // Plume CANONICAL (PLUME_-only) : PLUME_WATCH_STS uniquement (contrat partagé kube-state.sh :
    // le script émet kube_sts_ready_<nom> sur la base de CETTE variable côté shell ; rename shell = CHUNK 2).
    let watch = std::env::var("PLUME_WATCH_STS").unwrap_or_default();   // défaut VIDE (générique) ; défini par déploiement (deployment.yaml env / k8s.conf)
    for w in watch.split_whitespace() {
        let name = w.rsplit('/').next().unwrap_or(w);
        if name.is_empty() { continue; }
        let san: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
        let q = format!("metric kube_sts_ready_{san} | stats min(value)");
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) VALUES(?1,?2,1,'<',1.0,4,120,300,0)",
            params![format!("{name} indisponible (statefulset)"), q],
        );
    }
}

/// Canal de notification ntfy déclaré par ENV (GitOps/Vault-friendly, rebuild-safe) :
/// PLUME_NOTIFY_NTFY_URL (+ PLUME_NOTIFY_NTFY_TOKEN via Vault/ESO, PLUME_NOTIFY_MIN_SEV, défaut 3).
/// Upsert par nom 'ntfy (env)' -> pas de doublon au redémarrage ; URL vide => ne touche à rien
/// (les canaux créés à la main dans l'UI sont préservés).
pub(crate) fn seed_env_notifier(conn: &Connection, conf: &HashMap<String, String>) {
    let url = cfg(conf, "PLUME_NOTIFY_NTFY_URL", "");
    if url.trim().is_empty() {
        return;
    }
    // SECRET-PROVIDER PHASE 1 — token ntfy lu depuis `PLUME_NOTIFY_NTFY_TOKEN_FILE` (mount RO) si posé, sinon
    // repli env `PLUME_NOTIFY_NTFY_TOKEN` (v116). Fail-closed si le fichier configuré est illisible/vide.
    let token = cfg_secret(conf, "PLUME_NOTIFY_NTFY_TOKEN");
    let minsev: i64 = cfg(conf, "PLUME_NOTIFY_MIN_SEV", "3").parse().unwrap_or(3);
    let config = if token.is_empty() { "{}".to_string() } else { json!({ "token": token }).to_string() };
    let existing: Option<i64> = conn.query_row("SELECT id FROM notifier WHERE name='ntfy (env)'", [], |r| r.get(0)).ok();
    match existing {
        Some(id) => {
            let _ = conn.execute(
                "UPDATE notifier SET kind='ntfy', enabled=1, url=?1, min_severity=?2, config=?3 WHERE id=?4",
                params![url, minsev, config, id],
            );
        }
        None => {
            let _ = conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('ntfy (env)','ntfy',1,?1,?2,?3)",
                params![url, minsev, config],
            );
        }
    }
}

/// Règle « fuite slab noyau » : SUnreclaim (mem_slab_mb de resources.sh) anormalement haut = mémoire
/// tenue par le noyau (kmalloc/skbuff...) que mem_pct ne voit pas ; un reboot la rend. OFF par défaut.
/// Garde dédiée pour apparaître même dans une DB déjà seedée.
pub(crate) fn seed_slab_rule(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_slab_rule'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_slab_rule','1')", []);
    // normal ~500-1500 Mo ; > 2500 Mo = fuite probable (à surveiller / planifier un reboot).
    let _ = conn.execute(
        "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) \
         VALUES('noyau: fuite slab (SUnreclaim > 2.5 Go)', 'metric mem_slab_mb | stats max(value)', 1, '>', 2500.0, 3, 600, 1800, 0)",
        [],
    );
}

pub(crate) fn seed_k8s_rules(conn: &Connection) {
    if conn.query_row("SELECT value FROM meta WHERE key='seeded_k8s_rules'", [], |r| r.get::<_, String>(0)).is_ok() {
        return;
    }
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_k8s_rules','1')", []);
    let last = |name: &str| format!("SELECT value FROM metric WHERE name='{name}' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1");
    // (name, query, is_soql, op, threshold, severity, interval_s, window_s)
    let rules: [(&str, String, i64, &str, f64, i64, i64, i64); 7] = [
        ("k8s: problème pod (CrashLoop/OOMKilled)", "search source=k8s severity>=3 | stats count".to_string(), 1, ">", 0.0, 3, 120, 900),
        ("k8s: deployment dégradé", last("kube_deploy_unavailable"), 0, ">", 0.0, 3, 120, 600),
        ("k8s: node NotReady", last("kube_nodes_notready"), 0, ">", 0.0, 4, 120, 600),
        ("k8s: stockage > 85%", last("kube_storage_pct"), 0, ">", 85.0, 3, 300, 600),
        ("k8s: cert expire < 14j", last("cert_days_min"), 0, "<", 14.0, 3, 3600, 86400),
        ("k8s: backup Velero en échec", last("velero_failed"), 0, ">", 0.0, 3, 600, 86400),
        ("hôte: disque / > 90%", last("disk_root_pct"), 0, ">", 90.0, 3, 300, 600),
    ];
    for (name, q, is_soql, op, th, sev, intv, win) in rules {
        let _ = conn.execute(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,interval_s,window_s,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![name, q, is_soql, op, th, sev, intv, win],
        );
    }
}

/// #3 INCIDENTS Phase 1 — SEED des runbooks MANAGÉS (managed=1), gabarits de réponse guidée keyés sur la
/// TACTIQUE MITRE que la détection de Plume émet réellement (grep des règles seedées/overlays : recon T1595,
/// discovery T1046, initial-access T1190, credential-access T1110, execution T1059, impact T1490/T1485). MÊME
/// mécanique EXACTE que seed_purple_rules/seed_detection_rules : flag meta DÉDIÉ `seeded_runbooks` -> INSERT une
/// seule fois (base neuve : migrate crée les tables VIDES avant les seeds ; base déjà déployée : migrate_v104
/// crée les tables vides, le flag est absent -> on insère). managed=1 (baseline git-durable, comme les overlays
/// config.d) -> git définit le CONTENU. Chaque runbook = une courte checklist PHASÉE (triage -> investigation ->
/// containment -> eradication -> recovery) ; une step `response` RÉFÉRENCE l'enum d'action FERMÉ (ban_ip/kill_pid/
/// stop_service) — elle NE l'exécute PAS (le wizard PRÉSENTE l'action + pré-remplit la cible ; l'exécution reste
/// /api/actions, avec arm/approbation/admin/ledger/allowlist root INCHANGÉS). Les steps `search` portent un
/// gabarit SOQL `$target$` (compile-vérifié par le test seed_runbook_searches_compile ; recompilé à la
/// résolution, comme workflow_action search) -> jamais de SQL brut.
pub(crate) fn seed_runbooks(conn: &Connection) {
    // Phase 2 : IDEMPOTENCE PAR-KEY (et NON plus un flag global court-circuitant). Chaque runbook managé est
    // INSÉRÉ-SI-ABSENT (key UNIQUE : `INSERT` échoue -> `continue`). Conséquences DOCTRINE detection_override :
    //  - un nouveau gabarit managé (nouvelle key) s'ajoute au PROCHAIN boot d'une base DÉJÀ seedée (là où le
    //    flag global aurait tout sauté) ;
    //  - un managé DÉSACTIVÉ par l'admin (active=0) N'EST JAMAIS ré-inséré -> son état d'activation SURVIT au
    //    re-seed (on ne le ré-active pas) ;
    //  - une PERSONNALISATION admin (clone managed=0) porte une AUTRE key -> jamais touchée.
    // Le flag `seeded_runbooks` reste écrit comme MARQUEUR (observabilité) mais ne court-circuite plus.
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded_runbooks','1')", []);
    let t = now();
    // (key, name, match_kind, match_key, description). match_kind='tactic' -> le picker choisit par la tactique
    // DOMINANTE des alertes liées (guatx_core::attack::tactic_for_technique) ; '*' = repli générique.
    // (phase, title, guidance, step_kind, search_soql (Option), action_kind (Option))
    type Step = (&'static str, &'static str, &'static str, &'static str, Option<&'static str>, Option<&'static str>);
    let runbooks: &[(&str, &str, &str, &str, &str, &[Step])] = &[
        // 1) RECONNAISSANCE / SCAN (T1595, T1595.002 web-scan ; le picker route AUSSI discovery T1046 port-scan ici).
        ("recon-scan", "Scan / reconnaissance externe", "tactic", "reconnaissance",
         "Balayage/scan entrant (port-scan, web-scan 404, énumération). Confirmer la portée, écarter le trafic légitime, contenir la source si hostile.",
         &[
            ("triage", "Confirmer la portée du scan", "Quels hôtes/ports/chemins la source a-t-elle touchés ? Ouvrir la recherche pré-remplie sur l'IP source.", "search", Some("search src_ip=$target$ | stats count by source"), None),
            ("triage", "Écarter une source connue/autorisée", "Vérifier si l'IP source est un scanner interne autorisé, un moniteur, ou un partenaire (allowlist).", "manual", None, None),
            ("investigation", "Revoir les alertes de cette source (fenêtre récente)", "Corréler toutes les alertes émises par la même IP source.", "search", Some("search src_ip=$target$ severity>=2 | stats count by rule"), None),
            ("containment", "Bannir l'IP source si hostile", "Si le scan est hostile et l'IP externe, mettre en file un ban (approbation + ledger).", "response", None, Some("ban_ip")),
            ("recovery", "Documenter la conclusion et clore", "Consigner la cause/portée dans le résumé du case, puis résoudre.", "manual", None, None),
         ]),
        // 2) INITIAL ACCESS / EXPLOITATION D'APP PUBLIQUE (T1190).
        ("initial-access-exploit", "Exploitation d'application exposée", "tactic", "initial-access",
         "Tentative d'exploitation d'un service exposé (pic de 5xx, injection, upload). Confirmer l'atteinte, préserver les preuves, contenir.",
         &[
            ("triage", "Confirmer la cible et la nature", "Quel service/chemin est visé ? Ouvrir la recherche des erreurs serveur de la source.", "search", Some("search src_ip=$target$ status>=500 | stats count by path"), None),
            ("investigation", "Évaluer le succès de l'exploitation", "Rechercher les signes d'atteinte (réponse anormale, webshell, création de compte, exécution).", "search", Some("search src_ip=$target$ | stats count by status"), None),
            ("containment", "Bannir l'IP attaquante", "Mettre en file un ban de l'IP source (approbation + ledger).", "response", None, Some("ban_ip")),
            ("eradication", "Corriger/patcher la vulnérabilité exploitée", "Appliquer le correctif ou le contournement (WAF rule, désactivation de l'endpoint).", "manual", None, None),
            ("recovery", "Vérifier l'intégrité et clore", "Confirmer l'absence de persistance, documenter, résoudre.", "manual", None, None),
         ]),
        // 3) CREDENTIAL ACCESS / BRUTE-FORCE (T1110).
        ("credential-access-bruteforce", "Brute-force / accès aux identifiants", "tactic", "credential-access",
         "Pic d'échecs d'authentification / bourrage d'identifiants. Confirmer la cible, vérifier une compromission, contenir la source et durcir le compte.",
         &[
            ("triage", "Confirmer le compte/service ciblé", "Quel compte ou service subit les tentatives ? Ouvrir la recherche des échecs d'auth de la source.", "search", Some("search src_ip=$target$ severity>=3 | stats count by host"), None),
            ("investigation", "Vérifier une authentification RÉUSSIE", "Y a-t-il eu un succès après la rafale d'échecs (compromission probable) ?", "manual", None, None),
            ("containment", "Bannir l'IP source", "Mettre en file un ban de l'IP à l'origine du brute-force (approbation + ledger).", "response", None, Some("ban_ip")),
            ("eradication", "Réinitialiser/verrouiller le compte ciblé", "Forcer une rotation du mot de passe / MFA sur le compte visé si compromission suspectée.", "manual", None, None),
            ("recovery", "Documenter et clore", "Consigner la portée et les mesures, puis résoudre.", "manual", None, None),
         ]),
        // 4) EXECUTION / MALWARE (T1059, T1204).
        ("execution-malware", "Exécution suspecte / malware", "tactic", "execution",
         "Exécution de commande/malware sur un hôte (process anormal, beacon, binaire modifié). Confirmer, isoler le process, éradiquer.",
         &[
            ("triage", "Confirmer l'hôte et le process", "Quel hôte et quel process/commande ? Ouvrir la recherche des events de l'hôte.", "search", Some("search host=$target$ severity>=3 | stats count by source"), None),
            ("investigation", "Tracer l'origine et le C2", "Remonter la chaîne parentale du process et rechercher des connexions sortantes (beacon).", "manual", None, None),
            ("containment", "Tuer le process malveillant", "Mettre en file un kill du PID identifié (approbation + ledger).", "response", None, Some("kill_pid")),
            ("eradication", "Supprimer la persistance", "Retirer les mécanismes de persistance (service, cron, unit, clé run) et le binaire.", "manual", None, None),
            ("recovery", "Restaurer et clore", "Vérifier l'intégrité de l'hôte, restaurer si besoin, documenter, résoudre.", "manual", None, None),
         ]),
        // 5) IMPACT / DESTRUCTION-RANSOMWARE (T1490/T1485/T1486/T1565/T1498).
        ("impact-destruction", "Impact : destruction / ransomware / DoS", "tactic", "impact",
         "Destruction de données, chiffrement (ransomware), sabotage de sauvegardes ou déni de service. Contenir immédiatement, préserver, restaurer.",
         &[
            ("triage", "Confirmer l'ampleur de l'impact", "Quelles données/services sont touchés ? Ouvrir la recherche des events de l'hôte impacté.", "search", Some("search host=$target$ severity>=4 | stats count by source"), None),
            ("containment", "Arrêter le service compromis", "Mettre en file l'arrêt du service à l'origine de la destruction (approbation + ledger + allowlist responder).", "response", None, Some("stop_service")),
            ("containment", "Isoler l'hôte du réseau", "Bannir/couper la connectivité de l'hôte compromis pour stopper la propagation.", "response", None, Some("ban_ip")),
            ("eradication", "Éliminer la charge active", "Identifier et supprimer le process/binaire de chiffrement/destruction.", "manual", None, None),
            ("recovery", "Restaurer depuis une sauvegarde saine", "Restaurer les données depuis le dernier backup vérifié non compromis, documenter, résoudre.", "manual", None, None),
         ]),
        // 6) GÉNÉRIQUE (repli quand aucune tactique dominante ne matche).
        ("generic-default", "Runbook générique", "*", "",
         "Checklist d'investigation générique quand aucun runbook spécifique à la tactique ne s'applique.",
         &[
            ("triage", "Confirmer et qualifier l'alerte", "L'alerte est-elle un vrai positif ? Quelle en est la portée initiale ?", "manual", None, None),
            ("investigation", "Collecter le contexte", "Rassembler les events/alertes liés, hôtes et entités concernés.", "manual", None, None),
            ("containment", "Décider d'une mesure de containment", "Si nécessaire, contenir via l'action de réponse appropriée (ban/kill/stop) — via /api/actions.", "manual", None, None),
            ("recovery", "Documenter et clore", "Consigner la conclusion dans le résumé, puis résoudre/clore.", "manual", None, None),
         ]),
        // ============================ PHASE 2 — GABARITS MANAGÉS SUPPLÉMENTAIRES ============================
        // Couvrent d'AUTRES tactiques ATT&CK émises par les règles seedées (persistence, defense-evasion, discovery,
        // lateral-movement, collection, c2, exfiltration, privilege-escalation). Même forme de checklist phasée.
        // NB : PAS de gabarit tactic='discovery' (T1046 port-scan route déjà vers reconnaissance via l'alias du
        // picker — décision produit figée par le test Phase 1). Les techniques de discovery sont couvertes ci-dessous
        // au NIVEAU-TECHNIQUE (T1083/T1057), qui ne collisionne pas avec l'alias tactique.
        // 7) PERSISTENCE (T1053/T1136/T1543/T1547/T1505…).
        ("persistence-mechanism", "Persistance établie", "tactic", "persistence",
         "Mécanisme de persistance détecté (tâche planifiée, service, compte, autostart, webshell). Confirmer, éradiquer le mécanisme, vérifier l'absence de réinfection.",
         &[
            ("triage", "Confirmer le mécanisme et l'hôte", "Quel hôte, quel type de persistance ? Ouvrir la recherche des events de l'hôte.", "search", Some("search host=$target$ severity>=2 | stats count by source"), None),
            ("investigation", "Tracer l'origine de l'installation", "Remonter à l'événement/processus ayant posé la persistance et à l'accès initial.", "manual", None, None),
            ("eradication", "Supprimer le mécanisme de persistance", "Retirer la tâche/service/compte/clé run/webshell identifié.", "manual", None, None),
            ("containment", "Contenir la source si active", "Si un process/connexion alimente encore la persistance, tuer le PID.", "response", None, Some("kill_pid")),
            ("recovery", "Vérifier l'absence de réinfection et clore", "Re-scanner l'hôte, confirmer la disparition, documenter, résoudre.", "manual", None, None),
         ]),
        // 8) DEFENSE EVASION (T1562 impair defenses, T1070 indicator removal…).
        ("defense-evasion", "Évasion défensive / sabotage de la détection", "tactic", "defense-evasion",
         "Désactivation d'outils de sécurité, effacement de journaux, obfuscation. Confirmer ce qui a été touché, restaurer la visibilité, contenir.",
         &[
            ("triage", "Confirmer l'altération et l'hôte", "Quel contrôle (log, agent, pare-feu) a été désactivé/effacé ? Ouvrir la recherche de l'hôte.", "search", Some("search host=$target$ severity>=3 | stats count by rule"), None),
            ("investigation", "Évaluer l'angle mort créé", "Quelle fenêtre de visibilité a été perdue ? Corréler avec les autres sources encore vivantes.", "manual", None, None),
            ("containment", "Isoler l'hôte compromis", "Couper la connectivité de l'hôte pour stopper l'action de l'attaquant.", "response", None, Some("ban_ip")),
            ("eradication", "Restaurer les contrôles de sécurité", "Réactiver l'agent/le logging, restaurer les journaux depuis une source centrale.", "manual", None, None),
            ("recovery", "Documenter et clore", "Consigner la portée et la restauration, puis résoudre.", "manual", None, None),
         ]),
        // 9) LATERAL MOVEMENT (T1021 remote services, T1550, T1570…).
        ("lateral-movement", "Mouvement latéral", "tactic", "lateral-movement",
         "Propagation d'un hôte à un autre (RDP/SSH/SMB, pass-the-hash, transfert d'outil). Cartographier la propagation, couper les pivots, contenir.",
         &[
            ("triage", "Confirmer le pivot et la cible", "Quel hôte source, quel hôte cible ? Ouvrir la recherche des connexions de l'hôte.", "search", Some("search host=$target$ severity>=2 | stats count by source"), None),
            ("investigation", "Cartographier la propagation", "Reconstituer la chaîne d'hôtes touchés et les identifiants réutilisés.", "manual", None, None),
            ("containment", "Bannir/isoler l'hôte pivot", "Couper la connectivité de l'hôte servant de relais.", "response", None, Some("ban_ip")),
            ("eradication", "Révoquer les identifiants réutilisés", "Rotation des comptes/clés utilisés pour le mouvement latéral.", "manual", None, None),
            ("recovery", "Vérifier le confinement et clore", "Confirmer l'arrêt de la propagation, documenter, résoudre.", "manual", None, None),
         ]),
        // 10) COLLECTION / STAGING (T1560 archive, T1005, T1074 staging…).
        ("collection-staging", "Collecte / staging de données", "tactic", "collection",
         "Agrégation/archivage de données avant exfiltration (staging). Confirmer le périmètre des données, contenir avant la sortie.",
         &[
            ("triage", "Confirmer les données et l'hôte", "Quelles données sont rassemblées, sur quel hôte ? Ouvrir la recherche de l'hôte.", "search", Some("search host=$target$ severity>=2 | stats count by source"), None),
            ("investigation", "Identifier la zone de staging", "Localiser l'archive/le répertoire de staging et évaluer la sensibilité des données.", "manual", None, None),
            ("containment", "Stopper le process de collecte", "Tuer le process qui agrège/archive les données.", "response", None, Some("kill_pid")),
            ("recovery", "Documenter la portée et clore", "Consigner les données touchées (préavis fuite éventuel), résoudre.", "manual", None, None),
         ]),
        // 11) COMMAND & CONTROL (T1071/T1571/T1090/T1105 beacon).
        ("command-control", "Command & Control (beacon)", "tactic", "command-and-control",
         "Canal C2 détecté (beacon périodique, tunnel, proxy, download de charge). Couper le canal, identifier l'implant, éradiquer.",
         &[
            ("triage", "Confirmer le canal et l'hôte", "Quel hôte communique avec quel endpoint C2 ? Ouvrir la recherche de l'hôte.", "search", Some("search host=$target$ severity>=3 | stats count by source"), None),
            ("investigation", "Caractériser le beacon", "Périodicité, endpoint distant, protocole. Corréler avec la threat-intel.", "manual", None, None),
            ("containment", "Bloquer l'endpoint C2", "Bannir l'IP/l'endpoint distant pour couper le canal.", "response", None, Some("ban_ip")),
            ("eradication", "Tuer l'implant et retirer la persistance", "Tuer le process du beacon puis retirer son mécanisme de persistance.", "response", None, Some("kill_pid")),
            ("recovery", "Vérifier le silence radio et clore", "Confirmer l'arrêt du beacon, documenter, résoudre.", "manual", None, None),
         ]),
        // 12) EXFILTRATION (T1041/T1048/T1567).
        ("exfiltration", "Exfiltration de données", "tactic", "exfiltration",
         "Sortie de données hors du périmètre (canal C2, protocole alternatif, service cloud). Couper la sortie IMMÉDIATEMENT, évaluer le volume, notifier.",
         &[
            ("triage", "Confirmer la sortie et l'hôte", "Quel hôte exfiltre vers quel destinataire ? Ouvrir la recherche de l'hôte.", "search", Some("search host=$target$ severity>=3 | stats count by source"), None),
            ("containment", "Couper le canal d'exfiltration", "Bannir l'IP de destination pour stopper la sortie immédiatement.", "response", None, Some("ban_ip")),
            ("investigation", "Évaluer le volume et la nature des données", "Estimer la quantité et la sensibilité des données sorties (obligations de notification).", "manual", None, None),
            ("eradication", "Retirer l'outil d'exfiltration", "Tuer le process/retirer le mécanisme utilisé pour la sortie.", "response", None, Some("kill_pid")),
            ("recovery", "Notifier et clore", "Déclencher les obligations légales/contractuelles éventuelles, documenter, résoudre.", "manual", None, None),
         ]),
        // 13) PRIVILEGE ESCALATION (T1548/T1068/T1055/T1134).
        ("privilege-escalation", "Élévation de privilèges", "tactic", "privilege-escalation",
         "Obtention de droits supérieurs (exploit noyau, abus sudo/UAC, injection de process, vol de jeton). Confirmer, contenir l'accès élevé, durcir.",
         &[
            ("triage", "Confirmer l'élévation et l'hôte", "Quel compte a gagné quels droits, sur quel hôte ? Ouvrir la recherche de l'hôte.", "search", Some("search host=$target$ severity>=3 | stats count by rule"), None),
            ("investigation", "Tracer la technique d'élévation", "Identifier l'exploit/l'abus utilisé et l'accès initial associé.", "manual", None, None),
            ("containment", "Tuer le process élevé", "Tuer le process ayant obtenu les privilèges élevés.", "response", None, Some("kill_pid")),
            ("eradication", "Corriger la faille et révoquer l'accès", "Patcher/durcir la voie d'élévation, révoquer les comptes/jetons compromis.", "manual", None, None),
            ("recovery", "Vérifier et clore", "Confirmer l'absence d'accès élevé résiduel, documenter, résoudre.", "manual", None, None),
         ]),
        // ==================== PHASE 2 — GABARITS NIVEAU-TECHNIQUE (plus spécifiques que la tactique) ====================
        // Un incident dominé par CES techniques précises PRÉFÈRE ces runbooks (pick_runbook_id : technique > tactique).
        // 14) BRUTE-FORCE ciblé (T1110) — plus spécifique que le runbook de tactique credential-access.
        ("technique-bruteforce-t1110", "Brute-force ciblé (T1110)", "technique", "T1110",
         "Bourrage/brute-force d'identifiants ciblé (T1110). Runbook spécifique : identifier le compte visé, vérifier un succès, bannir la source, durcir MFA.",
         &[
            ("triage", "Confirmer le compte/service ciblé", "Quel compte subit la rafale ? Ouvrir la recherche des échecs d'auth de la source.", "search", Some("search src_ip=$target$ severity>=3 | stats count by host"), None),
            ("investigation", "Vérifier un succès après la rafale", "Y a-t-il eu une authentification réussie de la source après les échecs (compromission) ?", "search", Some("search src_ip=$target$ | stats count by status"), None),
            ("containment", "Bannir l'IP source", "Mettre en file un ban de l'IP à l'origine du brute-force (approbation + ledger).", "response", None, Some("ban_ip")),
            ("eradication", "Durcir le compte (rotation + MFA)", "Forcer rotation du mot de passe et MFA sur le compte visé.", "manual", None, None),
            ("recovery", "Documenter et clore", "Consigner la portée et les mesures, résoudre.", "manual", None, None),
         ]),
        // 15) DÉCOUVERTE HÔTE (T1083 file / T1057 process discovery) — énumération LOCALE post-compromission
        //     (distincte du scan RÉSEAU T1046 -> reconnaissance). Runbook niveau-technique T1083.
        ("technique-host-discovery-t1083", "Découverte locale de l'hôte (T1083)", "technique", "T1083",
         "Énumération locale post-compromission (fichiers/répertoires, processus). Confirmer l'étendue de la reconnaissance interne, remonter à l'accès, contenir.",
         &[
            ("triage", "Confirmer l'hôte et l'étendue", "Quel hôte est énuméré ? Ouvrir la recherche des events de l'hôte.", "search", Some("search host=$target$ severity>=2 | stats count by source"), None),
            ("investigation", "Remonter à l'accès initial", "Quel process/compte réalise l'énumération ? D'où vient l'accès ?", "manual", None, None),
            ("containment", "Tuer le process d'énumération si malveillant", "Si un implant énumère l'hôte, tuer le PID.", "response", None, Some("kill_pid")),
            ("recovery", "Documenter et clore", "Consigner la portée de la reconnaissance interne, résoudre.", "manual", None, None),
         ]),
    ];
    for (key, name, mkind, mkey, desc, steps) in runbooks {
        if conn.execute(
            "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,?2,?3,?4,?5,1,1,?6)",
            params![key, name, mkind, mkey, desc, t],
        ).is_err() { continue; }
        let rb_id = conn.last_insert_rowid();
        for (i, (phase, title, guidance, step_kind, soql, act)) in steps.iter().enumerate() {
            let _ = conn.execute(
                "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![rb_id, i as i64, phase, title, guidance, step_kind, soql, act],
            );
        }
    }
}

/// Colonne présente sur une table ? (via PRAGMA table_info). Utilitaire des ALTER additifs idempotents
/// (v66 env_id) : on n'exécute l'ALTER que si la colonne manque -> re-jouable, et sur une base neuve les
/// tables déjà porteuses via db/schema.sql sont sautées (pas de dépendance à l'ordre schema.sql/migrate).
pub(crate) fn col_exists(conn: &Connection, table: &str, col: &str) -> bool {
    let mut found = false;
    if let Ok(mut st) = conn.prepare(&format!("PRAGMA table_info({table})")) {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(1)) {
            for c in rows.flatten() {
                if c == col { found = true; break; }
            }
        }
    }
    found
}

/// True si `table` EXISTE dans le schéma courant. Utilisé par les migrations recréant une table (v67 : DROP
/// {tbl} -> RENAME {tmp}) pour REPRENDRE proprement une recréation interrompue dans cette fenêtre sans perte.
pub(crate) fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |_| Ok(()),
    ).is_ok()
}
