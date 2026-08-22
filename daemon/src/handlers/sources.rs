//! Sources d'ingestion : l'inventaire (`GET /api/sources`), les métadonnées d'affichage par source
//! (`GET|PUT /api/sources/settings`) et — ce qui donne son sens au mot « inattendu » — la DÉRIVATION
//! d'une source ATTENDUE PAR CONSTRUCTION. Extrait de `admin_ui.rs` (P11.3-a).
//!
//! CE QUI ÉTAIT CASSÉ. Le verdict « attendu / inattendu » reposait sur une liste ÉCRITE À LA MAIN
//! (`KNOWN_EXTRA_SOURCES`, dix-sept noms) accolée aux identifiants de capteurs de `COLLECTORS`. Six
//! sources que ce dépôt LIVRE lui-même — `cloudflare-http`, `engagement-adapter`, `nft`, `origin-drop`,
//! `portprobe`, `kube-rbac`, chacune avec son collecteur sous `collectors/` et son timer sous
//! `systemd/` — n'y figuraient pas et s'affichaient « inattendu » dans l'inventaire, à côté d'un badge
//! qu'aucun éditeur ne pouvait acquitter. Une liste énumérée ne peut que vieillir ; la présente
//! dérivation est tenue par une garde qui lit les fichiers livrés.
//!
//! QUATRE DÉRIVATIONS, AUCUNE LISTE LIBRE. Une source est attendue par construction si :
//!   1. un fichier LIVRÉ l'émet (`SOURCES_LIVREES` : table MIROIR de ce que l'extracteur de la garde
//!      `sources_livrees_est_le_miroir_des_fichiers_livres` dérive des collecteurs, de l'agent, des
//!      collecteurs Rust et du démon lui-même — ajouter une entrée non dérivée ROUGIT, omettre une
//!      source dérivée ROUGIT aussi) ;
//!   2. une sonde de `COLLECTORS` l'observe (`sondes.rs`, descripteur typé) ;
//!   3. le produit l'agrège (`dim_rollup_specs` : défauts compilés + `PLUME_ROLLUP_DIMS` du déploiement) ;
//!   4. un connecteur configuré dans cette base la déclare (table `connector`).
//! Tout le reste est un SIGNAL — une source que personne n'a déclarée — jusqu'à ce qu'un éditeur la
//! marque « attendue » (`set_expected`), geste persistant, réversible, audité, et rendu dans
//! l'inventaire avec son auteur et sa date.
//!
//! CE QUE LA DÉRIVATION NE VOIT PAS, ET QUI RESTE DONC « INATTENDU » JUSQU'AU MARQUAGE : les sources
//! DÉFINIES AU DÉPLOIEMENT — entrées scriptées de `custom.sh` (`SOURCE=` dans un `.input`), sources
//! déclaratives `[[source]]` de l'agent, identifiants du journal Windows. C'est la bonne sémantique :
//! une source que l'exploitant a créée hors de ce dépôt est précisément ce que le signal doit montrer
//! une fois, et que le marquage acquitte ensuite.
use crate::*;

// Plafonds de longueur (caractères) des métadonnées de source éditables — bornage anti-abus avant écriture.
const LABEL_MAX: usize = 200;
const NOTE_MAX: usize = 2000;
const CAT_MAX: usize = 100;

/// Sources ÉMISES par un fichier LIVRÉ de ce dépôt : `(source, fichier livré qui l'émet)`. La citation est un
/// SUFFIXE de chemin qui doit désigner UN SEUL fichier de la surface balayée par la garde.
///
/// CETTE TABLE N'EST PAS TENUE À LA MAIN — elle est le MIROIR de ce que l'extracteur de la garde ramène
/// (positions de producteur reconnues : objet JSON `"source":"X"` d'un collecteur shell/python, clé `source:` nue
/// de `jq`, premier argument littéral des aides de `lib.sh` qui émettent sous un nom de source
/// (`heartbeat`, `plume_unavailable`, `plume_disabled`, `plume_lecture_echouee`, `plume_lecture_partielle`,
/// `plume_report_availability`), `INSERT INTO event(...) VALUES(?1,'X'`, `source: "X".into()`,
/// `audit_source_change(conn, "X"`, `"source": "X"` et les descripteurs `sources: &[...]` /
/// `SOURCES_JOURNAL` du démon et des collecteurs Rust). Une source est listée UNE fois, avec le fichier le
/// plus direct ; la garde exige que ce fichier la produise et qu'aucune source dérivée ne manque ici.
pub(crate) const SOURCES_LIVREES: &[(&str, &str)] = &[
    ("agent", "agent/src/main.rs"),
    ("auditd", "collectors/auditd.sh"),
    ("clamav", "collectors/clamav.sh"),
    ("cloudflare", "collectors/cloudflare.sh"),
    ("cloudflare-http", "collectors/cloudflare-http.sh"),
    ("conntrack", "collectors/conntrack.sh"),
    ("containerd", "collectors/containerd.sh"),
    ("controls", "collectors/controls.sh"),
    ("crowdsec", "collectors/crowdsec.sh"),
    ("custom", "collectors/custom.sh"),
    ("dataaccess", "collectors/dataaccess.sh"),
    ("dataacl", "collectors/dataacl.sh"),
    ("defender", "daemon/src/handlers/connectors/mod.rs"),
    ("engagement-adapter", "collectors/engagement-adapter.sh"),
    ("fail2ban", "collectors/bans.sh"),
    ("falco", "collectors/falco.sh"),
    ("firewall", "collectors/firewall.sh"),
    ("integrity", "collectors/integrity.sh"),
    ("journal", "collectors/journal.sh"),
    ("k8s", "collectors/kube-state.sh"),
    ("k8s-log", "collectors/pod-logs.sh"),
    ("kube-audit", "collectors/kube-audit.sh"),
    ("kube-rbac", "collectors/kube-rbac.sh"),
    ("mail", "collectors/mail.sh"),
    ("mail-audit", "collector-mail/src/main.rs"),
    ("minio", "collectors/minio.sh"),
    ("minio-audit", "collectors/minio-audit-relay.py"),
    ("nft", "collectors/nft.sh"),
    ("origin-drop", "collectors/origin-drop.sh"),
    ("plume-audit", "daemon/src/handlers/query.rs"),
    ("plume-auth", "daemon/src/auth.rs"),
    ("plume-authz", "daemon/src/auth.rs"),
    ("plume-config", "daemon/src/ledger.rs"),
    ("plume-disk", "daemon/src/disk.rs"),
    ("plume-engagement", "daemon/src/handlers/engagement.rs"),
    ("plume-operator-access", "daemon/src/rbac.rs"),
    ("plume-tenant-admin", "daemon/src/rbac.rs"),
    ("portprobe", "collectors/portprobe.sh"),
    ("portscan", "collectors/portscan.sh"),
    ("prom-scrape", "collectors/prom-scrape.sh"),
    ("resources", "collectors/resources.sh"),
    ("sshd", "daemon/src/sondes.rs"),
    ("sshd-session", "daemon/src/sondes.rs"),
    ("su", "daemon/src/sondes.rs"),
    ("sudo", "daemon/src/sondes.rs"),
    ("suricata", "collectors/suricata.sh"),
    ("ufw", "collectors/ufw.sh"),
    ("update", "collectors/imgdrift.sh"),
    ("vuln", "collectors/vuln.sh"),
    ("web", "collectors/web.sh"),
    ("yara", "collectors/yara.sh"),
];

/// POURQUOI une source est attendue sans qu'un humain l'ait marquée. Rendu tel quel dans l'inventaire
/// (`raison_attendue`) : le lecteur voit d'où vient le verdict au lieu de devoir le deviner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RaisonAttendue {
    /// Un fichier livré de ce dépôt l'émet.
    Livree { fichier: &'static str },
    /// Une sonde de `COLLECTORS` l'observe (identifiant du capteur).
    Sonde { capteur: &'static str },
    /// Le produit l'agrège (dimensions de rollup compilées ou déclarées au déploiement).
    Agregee,
    /// Un connecteur configuré dans cette base la déclare (identifiant du connecteur).
    Connecteur { id: i64 },
}

impl RaisonAttendue {
    pub(crate) fn libelle(&self) -> String {
        match self {
            RaisonAttendue::Livree { fichier } => format!("émise par un fichier livré ({fichier})"),
            RaisonAttendue::Sonde { capteur } => format!("observée par la sonde « {capteur} »"),
            RaisonAttendue::Agregee => "agrégée par le produit (dimensions de rollup)".to_string(),
            RaisonAttendue::Connecteur { id } => format!("déclarée par le connecteur #{id}"),
        }
    }
}

/// Sources déclarées par les connecteurs CONFIGURÉS dans cette base (dérivation 4). `defender` écrit sous un
/// nom fixe ; `http_pull` sous `config.source` ou, à défaut, `http:<id>` (même repli que l'ingestion) ;
/// `taxii2` n'émet pas d'événement (indicateurs), donc aucune source. Table absente -> rien.
fn sources_declarees_par_connecteurs(conn: &Connection) -> Vec<(String, i64)> {
    let Ok(mut s) = conn.prepare("SELECT id, type, config_json FROM connector") else { return Vec::new() };
    let Ok(rows) = s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) else {
        return Vec::new();
    };
    rows.flatten()
        .filter_map(|(id, ctype, cfg)| match ctype.as_str() {
            "defender" => Some(("defender".to_string(), id)),
            "http_pull" => {
                let declared = serde_json::from_str::<Value>(&cfg)
                    .ok()
                    .and_then(|v| v.get("source").and_then(|x| x.as_str()).map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty());
                Some((declared.unwrap_or_else(|| format!("http:{id}")), id))
            }
            _ => None,
        })
        .collect()
}

/// LA DÉRIVATION. `Some(raison)` si la source est attendue par construction, `None` sinon (signal).
/// L'ordre des dérivations fixe la raison RENDUE quand plusieurs s'appliquent (la plus directe d'abord) ;
/// le verdict, lui, ne dépend pas de l'ordre.
pub(crate) fn raison_attendue_par_construction(conn: &Connection, source: &str) -> Option<RaisonAttendue> {
    if let Some((_, fichier)) = SOURCES_LIVREES.iter().find(|(s, _)| *s == source) {
        return Some(RaisonAttendue::Livree { fichier });
    }
    for (id, _, _, sonde, _) in COLLECTORS.iter() {
        if *id == source || imputer_alerte_de_capteur(sonde).iter().any(|s| s == source) {
            return Some(RaisonAttendue::Sonde { capteur: *id });
        }
    }
    if dim_rollup_specs().iter().any(|(s, _)| s == source) {
        return Some(RaisonAttendue::Agregee);
    }
    sources_declarees_par_connecteurs(conn)
        .into_iter()
        .find(|(s, _)| s == source)
        .map(|(_, id)| RaisonAttendue::Connecteur { id })
}

pub(crate) fn source_attendue_par_construction(conn: &Connection, source: &str) -> bool {
    raison_attendue_par_construction(conn, source).is_some()
}

/// L'ensemble des sources attendues par construction SANS connexion (dérivations 1 à 3), pour le registre
/// d'exclusions (`daemon_excl_registry`) : ce qu'un lecteur du registre peut vérifier contre le code livré.
pub(crate) fn sources_attendues_sans_base() -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = SOURCES_LIVREES.iter().map(|(s, _)| (*s).to_string()).collect();
    for (id, _, _, sonde, _) in COLLECTORS.iter() {
        out.insert((*id).to_string());
        for s in imputer_alerte_de_capteur(sonde) {
            if s != SOURCE_INDETERMINABLE {
                out.insert(s);
            }
        }
    }
    for (s, _) in dim_rollup_specs() {
        out.insert(s.clone());
    }
    out.into_iter().collect()
}

/// GET /api/sources -> INVENTAIRE read-only dérivé (join observé x attendu x métadonnées d'affichage). Observé =
/// event_rollup GROUP BY source (budget : jamais `event`) ; attendu = `raison_attendue_par_construction` OU
/// marquage persistant (`source_settings.expected`) ; `unexpected` = SIGNAL (ni l'un ni l'autre).
/// Accessible à TOUS les rôles (pas de contrôle de mutation ici) -> PAS de guard admin (délibéré).
pub(crate) async fn sources_inventory(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let now_ts = now();
    let db_path = req_db_path(&st, &au);
    tokio::task::spawn_blocking(move || {
        read_with_watchdog(db_path.as_str(), Json(json!({ "ok": false, "sources": [], "generated": now_ts })), move |conn| {
            let d1 = now_ts - 86400;
            let cut7 = now_ts - 7 * 86400;
            let pipe_fresh = pipeline_is_fresh(conn, now_ts);
            // OBSERVÉ (event_rollup uniquement : ~ms, jamais un scan de `event`). source -> (last_seen, n_24h).
            let mut obs: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
            if let Ok(mut s) = conn.prepare(
                "SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) \
                 FROM event_rollup WHERE bucket>=?2 AND source<>'' GROUP BY source HAVING SUM(n)>=3",
            ) {
                if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                    for (src, last, n) in rows.flatten() {
                        obs.insert(src, (last, n));
                    }
                }
            }
            // MÉTADONNÉES D'AFFICHAGE (source_settings). Une source labellisée mais dormante reste listée (entry 0,0).
            #[allow(clippy::type_complexity)]
            let mut meta: HashMap<String, (bool, Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>)> = HashMap::new();
            if let Ok(mut s) = conn.prepare("SELECT source,expected,label,note,category,updated_by,updated FROM source_settings WHERE scope='global'") {
                if let Ok(rows) = s.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)? != 0,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                    ))
                }) {
                    for (src, exp, lbl, note, cat, by, upd) in rows.flatten() {
                        obs.entry(src.clone()).or_insert((0, 0));
                        meta.insert(src, (exp, lbl, note, cat, by, upd));
                    }
                }
            }
            let mut sources: Vec<Value> = Vec::new();
            for (src, (last, n24)) in &obs {
                let raison = raison_attendue_par_construction(conn, src);
                let m = meta.get(src);
                // Le marquage persistant l'emporte sur la dérivation, dans les DEUX sens (réversible) ; sans
                // ligne de réglage, le verdict est celui de la construction.
                let expected = m.map(|x| x.0).unwrap_or(raison.is_some());
                let age = now_ts - last;
                // MÊME vocabulaire que Fraîcheur : la cadence déclarée par la sonde, le statut qui en dérive
                // (`statut_de_source`). `dormant` = ligne de réglage sans aucune donnée observée sur 7 j.
                let cadence = cadence_declaree("event", src);
                let status = if *last == 0 { "dormant" } else { statut_de_source(age, pipe_fresh, Some(&cadence)) };
                // D'OÙ VIENT LE VERDICT, en clair : la raison de construction, ou le marquage (qui/quand).
                let raison_attendue = match (m, &raison) {
                    (Some(x), _) if x.0 && raison.is_none() => Some(format!(
                        "marquée attendue par {}{}",
                        x.4.clone().unwrap_or_else(|| "?".to_string()),
                        x.5.map(|t| format!(" (ts {t})")).unwrap_or_default()
                    )),
                    (_, Some(r)) => Some(r.libelle()),
                    _ => None,
                };
                let mut entry = json!({
                    "source": src,
                    "in_collectors": raison.is_some(),
                    "raison_attendue": raison_attendue,
                    "expected": expected,
                    "unexpected": !expected,
                    "marquage": m.map(|x| json!({ "expected": x.0, "updated_by": x.4, "updated": x.5 })),
                    "label": m.and_then(|x| x.1.clone()),
                    "note": m.and_then(|x| x.2.clone()),
                    "category": m.and_then(|x| x.3.clone()),
                    "updated_by": m.and_then(|x| x.4.clone()),
                    "updated": m.and_then(|x| x.5),
                    "last_seen": if *last == 0 { Value::Null } else { json!(last) },
                    "age_s": if *last == 0 { Value::Null } else { json!(age) },
                    "n_24h": n24,
                    "status": status,
                });
                if let (Some(o), Value::Object(c)) = (entry.as_object_mut(), cadence_json(&cadence, *n24)) {
                    o.extend(c);
                }
                sources.push(entry);
            }
            Json(json!({ "ok": true, "generated": now_ts, "pipeline_fresh": pipe_fresh, "sources": sources }))
        })
    })
    .await
    .unwrap_or_else(|_| Json(json!({ "ok": false, "sources": [], "generated": now_ts })))
}

/// GET /api/sources/settings -> liste brute source_settings (métadonnées d'affichage). Lecture : tout rôle
/// (rien ici n'est secret — l'inventaire rend déjà ces colonnes) ; le path-guard RBAC applique la même règle.
pub(crate) async fn source_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare("SELECT source,expected,label,note,category,updated,updated_by FROM source_settings WHERE scope='global' ORDER BY source") {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("source_settings indisponible: {e}")).into_response(),
    };
    let settings: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "source": r.get::<_, String>(0)?,
                "expected": r.get::<_, i64>(1)? != 0,
                "label": r.get::<_, Option<String>>(2)?,
                "note": r.get::<_, Option<String>>(3)?,
                "category": r.get::<_, Option<String>>(4)?,
                "updated": r.get::<_, Option<i64>>(5)?,
                "updated_by": r.get::<_, Option<String>>(6)?,
            }))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "ok": true, "settings": settings })).into_response()
}

/// POST|PUT /api/sources/settings {source, action, value?} -> métadonnées d'AFFICHAGE par source. Enum d'actions
/// FERMÉ : set_expected(bool) | set_label(str) | set_note(str) | set_category(str) | clear. EDITOR+ (un
/// acquittement d'inventaire est un geste éditorial, pas d'administration) + double-audit transactionnel
/// fail-closed. B8 : set_expected(true) sur une source que RIEN ne déclare = suppression d'un SIGNAL -> sev 3
/// (sinon sev 2). AUCUN champ ici ne touche l'ingest, la collecte ni les règles.
///
/// LA LIGNE NAÎT AVEC LE VERDICT DE CONSTRUCTION. Poser un libellé ou une note sur une source inattendue
/// créait une ligne dont `expected` valait le DÉFAUT DE COLONNE (1) : la source passait « attendue » sans que
/// personne ne l'ait dit, et sans l'audit de sévérité 3. La ligne est désormais créée avec la valeur
/// DÉRIVÉE ; seul `set_expected` la change.
pub(crate) async fn source_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) {
        return r;
    }
    let source = b.trimmed("source");
    if source.is_empty() {
        return (StatusCode::BAD_REQUEST, "champ 'source' requis").into_response();
    }
    if source.chars().count() > 256 {
        return (StatusCode::BAD_REQUEST, "source trop longue (max 256)").into_response();
    }
    let action = b.str_field("action");
    // ENUM FERMÉ — toute action inconnue = 400 AVANT d'ouvrir la transaction.
    if !matches!(action, "set_expected" | "set_label" | "set_note" | "set_category" | "clear") {
        return (StatusCode::BAD_REQUEST, "action inconnue (enum fermé)").into_response();
    }
    crate::req_conn!(st, au, conn);
    let attendue = source_attendue_par_construction(&conn, &source);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
    }
    let outcome: rusqlite::Result<()> = (|| {
        let ts = now();
        let (human, sev): (String, i64) = if action == "clear" {
            conn.execute("DELETE FROM source_settings WHERE scope='global' AND source=?1", params![source])?;
            ("réinitialisée (clear)".to_string(), 2)
        } else {
            // garantit la ligne (upsert, `expected` = verdict de construction à la création), puis applique le
            // champ selon l'enum fermé (col = littéral, jamais user-input).
            conn.execute(
                "INSERT INTO source_settings(scope,source,expected,updated,updated_by) VALUES('global',?1,?4,?2,?3) \
                 ON CONFLICT(scope,source) DO UPDATE SET updated=?2,updated_by=?3",
                params![source, ts, au.name.as_str(), attendue as i64],
            )?;
            match action {
                "set_expected" => {
                    let v = b.get("value").and_then(|x| x.as_bool()).unwrap_or(true);
                    conn.execute("UPDATE source_settings SET expected=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![v as i64, ts, au.name.as_str(), source])?;
                    // B8 : reconnaître (expected=true) une source que rien ne déclare = étouffer un signal -> bruyant.
                    let sev = if v && !attendue { 3 } else { 2 };
                    (format!("attendu={v}"), sev)
                }
                "set_label" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(LABEL_MAX).collect();
                    conn.execute("UPDATE source_settings SET label=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("label défini ({} car.)", s.chars().count()), 2)
                }
                "set_note" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(NOTE_MAX).collect();
                    conn.execute("UPDATE source_settings SET note=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    ("note définie".to_string(), 2)
                }
                "set_category" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(CAT_MAX).collect();
                    conn.execute("UPDATE source_settings SET category=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("catégorie définie ({} car.)", s.chars().count()), 2)
                }
                _ => unreachable!("action pré-validée"),
            }
        };
        audit_config_change(
            &conn,
            "source.settings",
            &format!("{source}: {human} par {}", au.name),
            sev,
            &format!("source {source}: {human} par {}", au.name),
            &json!({ "source": source, "action": action, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}
