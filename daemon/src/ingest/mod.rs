//! Couche d'ingestion (data-plane). Sous-modules extraits de main.rs (refactor split #25 —
//! byte-identique). `store` = SPI de stockage enfichable.
use crate::*;

pub(crate) mod store;
pub(crate) use store::*;
// Tier WARM DuckDB (#15) — FEATURE-GATED, OFF par défaut : absent du build SMB (mode 0 byte-identique,
// pas de link `duckdb`). Monte la SPI backend-neutre `guatx_core::store::EventStore` (preuve #18 Ph1).
#[cfg(feature = "duckdb")]
pub(crate) mod duckdb_store;
// Tier COLD/scale ClickHouse (#18) — FEATURE-GATED, OFF par défaut : absent du build SMB (mode 0
// byte-identique, pas de link `clickhouse`/`serde`). Monte la SPI backend-neutre `EventStore` (preuve #18 Ph2).
#[cfg(feature = "clickhouse")]
pub(crate) mod clickhouse_store;
// Tier COLD/scale DISTRIBUÉ (#70, HA multi-nœud) — SCAFFOLD INERTE derrière la sous-feature
// `clickhouse-ha` (qui active `clickhouse`). ABSENT du build par défaut ET du build `--features
// clickhouse` (#18) : fondations typées (topologie, DDL Distributed/Replicated injection-safe,
// coordination Keeper, ingest stateless, hot→cold) SANS cluster vivant, NON câblé au runtime -> mode 0
// byte-identique. Aucun ré-export glob : le scaffold n'a pas d'appelant (on évite un ré-export mort).
#[cfg(feature = "clickhouse-ha")]
pub(crate) mod clickhouse_ha;
pub(crate) mod obs;
pub(crate) use obs::*;
pub(crate) mod minio;
pub(crate) use minio::*;
pub(crate) mod hec;
pub(crate) use hec::*;
// OTLP (#41) — récepteur OpenTelemetry TRACES (OTLP/HTTP JSON). Additif, GATE par `PLUME_OTLP_TRACES`
// (défaut OFF -> handler 404) -> mode 0 byte-identique tant qu'aucune trace ne circule.
pub(crate) mod otlp;
pub(crate) use otlp::*;
// P-HEC — récepteur PUSH AWS Kinesis Firehose (CloudTrail/GuardDuty) : POST /api/ingest/firehose. Additif,
// s'auto-authentifie par clé de livraison (X-Amz-Firehose-Access-Key -> firehose_token_lookup) HORS auth_guard.
// INERTE tant qu'aucune source push n'est provisionnée -> mode 0 byte-identique.
pub(crate) mod firehose;
pub(crate) use firehose::*;
// P-HEC — récepteur PUSH GCP Pub/Sub (Cloud Audit Logs) : POST /api/ingest/pubsub?token=… . SIBLING du
// récepteur Firehose : s'auto-authentifie par clé de livraison en query (-> pubsub_token_lookup) HORS auth_guard.
pub(crate) mod pubsub;
pub(crate) use pubsub::*;
// #57 — normalisation CIM des télémétries de sécurité endpoint (BYO-agent : Wazuh SCA/vuln/FIM/syscollector).
// Additif, GATE PAR SOURCE (défaut `wazuh`) -> mode 0 byte-identique tant qu'aucun event endpoint ne circule.
pub(crate) mod endpoint;
pub(crate) use endpoint::*;
// #40 item 2 — federated search / search-without-ingest : DESIGN NOTE + couture (STUB, cf. fichier).
// Additif, non appelé sur le data-plane -> mode 0 inchangé. Accès via `federated::` (pas de glob : la
// couture n'a pas encore d'appelant, on évite un ré-export mort).
pub(crate) mod federated;

// ---------------------------------------------------------------------------------------------------
// Journal + ingest (data-plane) : parsing journald (extract_src_ip/journal_user/journal_action),
// ingestion NDJSON (ingest_journal/ingest_journal_lines), batch d'events génériques
// (ingest_events_batch), endpoint HTTP (ingest_journal_post) et boucle de fond spool->DB (ingest_once).
// Extrait de main.rs (refactor split #25 — byte-identique).
// ---------------------------------------------------------------------------------------------------
/// Ingestion des entrées journald brutes (.ndjson, 1 objet/ligne) -> table `event`.
/// La transformation est faite ici (Rust) plutôt qu'en shell+jq.
/// Extrait une IP source d'un message type « ... from 1.2.3.4 port 22 » (auth/SSH).
fn extract_src_ip(msg: &str) -> Option<String> {
    let i = msg.find(" from ")?;
    let raw = msg[i + 6..].split_whitespace().next()?;
    // sshd journalise l'IP sous plusieurs habillages : nue (`1.2.3.4`), entre crochets avec port
    // (`[203.0.113.132]:36630`, IPv4 comme IPv6), ou en CIDR (`1.2.3.4/32`, lignes srclimit). On
    // dénude l'IP : crochets -> intérieur (jette `:port`), sinon on tronque au `/` (CIDR). On NE
    // découpe PAS sur `:` hors crochets (un IPv6 nu `2001:db8:...` doit rester entier).
    let tok = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        raw.split('/').next().unwrap_or(raw)
    };
    let ipish = tok.len() >= 3
        && tok.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && tok.chars().any(|c| c == '.' || c == ':');
    ipish.then(|| tok.to_string())
}

/// ING-1 : renvoie `None` si le fichier est ILLISIBLE (transitoire -> laissé au spool, rejoué au prochain
/// tick, CALQUE de la voie events `.json` qui `continue`), `Some(Ok(n))` = batch committé (l'appelant
/// supprime), `Some(Err(n))` = INSERT/COMMIT échoué + ROLLBACK (l'appelant met en QUARANTAINE au lieu de
/// supprimer -> aucune perte silencieuse d'events journald/auth sous pression disque).
fn ingest_journal(db: &Arc<Mutex<Connection>>, db_path: &str, path: &std::path::Path, forced_host: Option<&str>) -> Option<Result<usize, usize>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let conn = db.lock();
    Some(ingest_journal_lines(&conn, db_path, &content, forced_host))
}

/// Cœur d'ingestion journald (NDJSON brut, 1 objet/ligne) -> table `event`. Réutilisé par le
/// spool local (.ndjson du central) ET par l'endpoint HTTP /api/ingest/journal (agents distants :
/// le parsing reste côté daemon, sans jq côté agent). Renvoie le nombre de lignes traitées.
/// Utilisateur visé d'une ligne sshd/sudo ("… for <u> from", "Invalid user <u> from", "<u> : TTY=").
fn journal_user(msg: &str) -> Option<String> {
    // sudo/su : la ligne journald est REMBOURRÉE à gauche (`  ubuntu : PWD=… ; USER=root ; COMMAND=…`)
    // -> l'ancre `^` et le `\S+` initial échouaient. On découpe sur le 1er ` : ` (espace-colon-espace,
    // absent des lignes pam `pam_unix(sudo:session): …` car le `:` n'y est pas entouré d'espaces) et on
    // garde le préfixe s'il est un identifiant simple (= l'invocateur). Couvre `: PWD=` ET `: TTY=`.
    if let Some(p) = msg.find(" : ") {
        let u = msg[..p].trim();
        if !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return Some(u.to_string());
        }
    }
    // sshd : `… for [invalid user ]<u> from <ip>` (Accepted/Postponed/Starting session)
    if let Some(fp) = msg.find(" for ") {
        let after = &msg[fp + 5..];
        let rest = after.strip_prefix("invalid user ").unwrap_or(after);
        if let Some(fr) = rest.find(" from ") {
            let u = rest[..fr].trim();
            if !u.is_empty() { return Some(u.to_string()); }
        }
    }
    // `Invalid user <u> from <ip>` (ligne d'auth, I majuscule)
    if let Some(p) = msg.find("Invalid user ") {
        if let Some(u) = msg[p + 13..].split_whitespace().next() { if !u.is_empty() { return Some(u.to_string()); } }
    }
    // preauth (i minuscule, SANS `from` avant l'IP) : `Disconnected from invalid user <u> <ip> …` /
    // `Connection closed by invalid user <u> <ip> …` -> le spray T1110 (admin/postgres/root) était perdu.
    if let Some(p) = msg.find("invalid user ") {
        if let Some(u) = msg[p + 13..].split_whitespace().next() { if !u.is_empty() { return Some(u.to_string()); } }
    }
    // `Disconnected from user <u> <ip>` (déconnexion d'une session authentifiée)
    if let Some(p) = msg.find("from user ") {
        if let Some(u) = msg[p + 10..].split_whitespace().next() { if !u.is_empty() { return Some(u.to_string()); } }
    }
    // pam : `session opened/closed for user <u>(uid=…)` -> compte ciblé
    if let Some(p) = msg.find("for user ") {
        if let Some(tok) = msg[p + 9..].split_whitespace().next() {
            let u = tok.split('(').next().unwrap_or(tok);
            if !u.is_empty() { return Some(u.to_string()); }
        }
    }
    // su : `(to <cible>) <invocateur> on <tty>` -> l'INVOCATEUR (qui a lancé le su)
    if let Some(p) = msg.find("(to ") {
        if let Some(cp) = msg[p..].find(") ") {
            if let Some(u) = msg[p + cp + 2..].split_whitespace().next() { if !u.is_empty() { return Some(u.to_string()); } }
        }
    }
    None
}
/// Action normalisée (quoi) d'une ligne auth -> champ groupable.
fn journal_action(msg: &str) -> Option<&'static str> {
    let m = msg.to_ascii_lowercase();
    if m.contains("accepted ") { Some("success") }
    else if m.contains("failed password") || m.contains("authentication failure") || m.contains("failed publickey")
         // échecs sudo/su -> `action=failure` (étaient invisibles : aucune des branches ne matchait, la
         // ligne d'échec porte un COMMAND= et tombait à tort dans la branche "sudo").
         || m.contains("not in sudoers") || m.contains("incorrect password") || m.contains("user not allowed")
         || m.contains("command not allowed") || m.contains("a password is required") || m.contains("a terminal is required") { Some("failure") }
    else if m.contains("invalid user") { Some("failure") }
    else if m.contains("command=") { Some("sudo") }
    else if m.contains("session opened") { Some("session_open") }
    else if m.contains("session closed") { Some("session_close") }
    else { None }
}

/// TAMPON DE VERSION CIM PAR EVENT (Reorg Wave 2) — pose `fields.cim = CIM_VERSION` sur CHAQUE event
/// à l'ingest, pour rendre la DÉRIVE DE CONTRAT DÉTECTABLE AU REPOS : une ligne SANS la clé a été écrite
/// AVANT ce tampon (lue « pré-tampon », convention inconnue) ; une valeur ANCIENNE (< `CIM_VERSION`) signale
/// un contrat périmé sur des données figées. Requêtable en SOQL (`json_extract(fields,'$.cim')`).
///
/// LOWEST-BLAST-RADIUS choisi : un champ du sac `fields` déjà sérialisé, PAS une colonne — aucune migration
/// de schéma, aucun changement d'`EventRow`/`EVENT_INSERT_SQL` (donc aucune parité de store à re-prouver).
/// Le sac `fields` est DÉJÀ parsé/re-sérialisé plusieurs fois sur le chemin chaud (parsers/extract/ti-match),
/// donc ce round-trip serde n'ajoute pas de coût d'ordre nouveau.
///
/// ADDITIF / idempotent / fail-safe : n'ÉCRASE jamais une clé `cim` déjà posée (un connecteur/parser pourrait
/// la fournir) ; un sac absent/vide devient `{"cim":"<ver>"}` ; un JSON non-objet imprévu est renvoyé
/// INCHANGÉ (jamais une perte de donnée). Le tampon NE participe PAS au `dedup` (explicite ou NULL, jamais
/// calculé depuis `fields`) -> l'idempotence `INSERT OR IGNORE` est préservée.
pub(crate) fn cim_stamp(fields: Option<String>) -> Option<String> {
    use serde_json::{Map, Value};
    let ver = guatx_core::cim::CIM_VERSION;
    // Sac absent / vide / trivial -> objet à une seule clé (chemin sans allocation JSON de parse).
    let trivial = matches!(fields.as_deref().map(str::trim), None | Some("") | Some("{}") | Some("null"));
    if trivial {
        return Some(format!(r#"{{"cim":"{ver}"}}"#));
    }
    let s = fields.as_deref().unwrap(); // non-trivial ci-dessus
    match serde_json::from_str::<Map<String, Value>>(s) {
        Ok(mut m) => {
            m.entry("cim".to_string()).or_insert_with(|| Value::String(ver.to_string()));
            Some(Value::Object(m).to_string())
        }
        // JSON non-objet imprévu : ne JAMAIS perdre la donnée -> renvoyer tel quel (reste « pré-tampon »).
        Err(_) => fields,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  CATÉGORIE HORS TAXONOMIE À L'INGEST — DÉCISION : ON N'EN REJETTE AUCUNE, ON LA REND VISIBLE.
// ───────────────────────────────────────────────────────────────────────────────────────────────
//  ÉTAT MESURÉ AVANT (2026-07-28, `ingest_events_batch_env`) : la `category` DÉCLARÉE par un
//  collecteur n'était confrontée à `CIM_CATEGORIES` NULLE PART sur le chemin d'ingest — pas même un
//  `warn`. Les seuls garde-fous existants sont en AMONT et ailleurs : chargement d'un parseur
//  d'overlay (`overlays.rs`, warn), création d'un data-model (`handlers/datamodels.rs`, refus) et
//  mapping HEC (`ingest/hec.rs`, ne mappe PAS une valeur hors contrat). C'est très exactement ce
//  trou qui a laissé les deux collecteurs Windows écrire `category='process'` pendant des mois sans
//  qu'aucune ligne de journal ne le dise.
//
//  POURQUOI PAS UN REFUS. Le CIM est un contrat de PARSE/MAP/ENRICH, jamais un DROP (invariant écrit
//  dans le cœur, `cim_category_ok`, et dans le bandeau CIM de main.rs). Refuser une catégorie
//  inconnue ferait jeter au SOC les événements d'un collecteur tiers mal réglé — au moment PRÉCIS
//  où l'opérateur en a le plus besoin, et sans qu'il puisse les rejouer. Un SOC bruyant se corrige ;
//  un SOC qui jette silencieusement ne se rattrape pas. La réduction de collecte a déjà son chemin
//  EXPLICITE et audité (whitelists #10, audit sev 3) — ce n'est pas au CIM de la décider.
//
//  CE QUI CHANGE : la ligne est stockée À L'IDENTIQUE, et la PREMIÈRE occurrence de chaque couple
//  (source, category) hors taxonomie est JOURNALISÉE en nommant le collecteur fautif et la version de
//  contrat. Une seule ligne par couple et par vie du process : un collecteur déréglé qui pousse un
//  million d'événements produit UNE ligne, pas un million (un warn qui noie le journal n'avertit
//  personne). Mémo BORNÉ par la cardinalité (source × category) d'un parc, pas par le débit.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// BORNE DU MÉMO. `source` ET `category` viennent de l'ÉVÉNEMENT : ce sont des chaînes choisies par
/// l'ÉMETTEUR. Un mémo non borné serait donc un levier de croissance illimitée (mémoire ET journal)
/// pour un token d'agent compromis. 256 couples DISTINCTS hors taxonomie est déjà 1 à 2 ordres de
/// grandeur au-dessus d'un parc réel (la taxonomie compte 40 catégories) ; au plafond on cesse de
/// mémoriser ET de signaler. L'INGEST, lui, reste strictement inchangé — on ne jette toujours rien.
pub(crate) const CIM_NONCANON_MEMO_MAX: usize = 256;

/// Première fois qu'on voit ce couple (source, category) hors `CIM_CATEGORIES` ? Seam PUR et testable
/// (le mémo est l'état, le journal est l'effet). N'est appelée que sur le chemin DÉJÀ non canonique.
/// Verrou empoisonné -> `false` (aucun signal), jamais une panique sur le chemin d'ingest.
pub(crate) fn cim_note_noncanonical(source: &str, category: &str) -> bool {
    static SEEN: std::sync::OnceLock<std::sync::RwLock<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    let key = format!("{source}\u{1}{category}");
    // Cas répété (le plus fréquent) et cas « plafond atteint » : un verrou en LECTURE, aucune écriture.
    if seen.read().map(|s| s.contains(&key) || s.len() >= CIM_NONCANON_MEMO_MAX).unwrap_or(true) {
        return false;
    }
    match seen.write() {
        // Re-test SOUS le verrou d'écriture (une course a pu insérer/atteindre le plafond entre-temps).
        Ok(mut s) if s.len() < CIM_NONCANON_MEMO_MAX => s.insert(key),
        _ => false,
    }
}

/// AVERTIT (une fois par couple) qu'une `category` déclarée est hors taxonomie. NE REJETTE JAMAIS —
/// l'appelant continue et stocke la ligne inchangée. Vide -> rien (le dparser tranchera côté serveur).
fn cim_warn_if_noncanonical(source: &str, category: &str) {
    if category.is_empty() || cim_category_ok(category) {
        return;
    }
    if cim_note_noncanonical(source, category) {
        eprintln!(
            "[cim] WARN collecteur '{source}' : category='{category}' hors taxonomie CIM v{} — \
             événement ACCEPTÉ et stocké tel quel (le CIM ne jette jamais), mais AUCUNE règle \
             `category=…` canonique ne le verra. Corrigez le collecteur ou déclarez un parseur de \
             mapping (cf. docs/CIM.md). Signalé UNE fois par couple (source, category).",
            guatx_core::cim::CIM_VERSION
        );
    }
}

/// ING-1 : `Ok(n)` = n lignes traitées et COMMITTÉES ; `Err(n)` = ROLLBACK atomique après un INSERT (ou le
/// COMMIT) échoué -> l'appelant (`ingest_journal`) remonte le signal pour QUARANTAINER le fichier (rejouable)
/// au lieu de le supprimer. Mirroir STRICT de `ingest_events_batch` (voie `.json`), pour que la voie journald
/// NE PERDE PLUS silencieusement des events auth (sshd/sudo/su) sur une écriture DB en échec (disque plein,
/// base verrouillée). Succès : sémantique/lignes stockées INCHANGÉES (parité mode 0).
fn ingest_journal_lines(conn: &Connection, db_path: &str, content: &str, forced_host: Option<&str>) -> Result<usize, usize> {
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    let mut n = 0usize;
    let mut batch_min = i64::MAX;   // plus vieux ts du batch -> plancher de rattrapage host_rollup (buffer journald tardif)
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let j: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ts = j
            .get("__REALTIME_TIMESTAMP")
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|us| us / 1_000_000)
            .unwrap_or_else(now);
        if ts < batch_min { batch_min = ts; }
        // M1 : `_COMM` (nom de commande journald) est de la donnée agent -> namespace `plume-*` réservé.
        let source = ext_ingest_source(j.get("_COMM").and_then(|x| x.as_str()).unwrap_or("journal"));
        let msg = match j.get("MESSAGE") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(a)) => format!("<binaire {} octets>", a.len()),
            _ => String::new(),
        };
        let pri = j.get("PRIORITY").and_then(|x| x.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(6);
        let ml = msg.to_lowercase();
        let severity = if ml.contains("fail") || ml.contains("invalid") || ml.contains("error") || ml.contains("denied") {
            3
        } else if pri <= 3 {
            3
        } else if pri == 4 {
            2
        } else {
            0
        };
        let dedup = j.get("__CURSOR").and_then(|x| x.as_str()).map(|c| c.to_string());
        let fields = json!({
            "pid": j.get("_PID").and_then(|x| x.as_str()),
            "uid": j.get("_UID").and_then(|x| x.as_str()),
            "unit": j.get("_SYSTEMD_UNIT").and_then(|x| x.as_str()),
            "user": journal_user(&msg),       // qui (compte visé sshd/sudo) -> groupable
            "action": journal_action(&msg),   // outcome normalisé CIM (success/failure/sudo/session_*)
        })
        .to_string();
        let fields = parsers_apply(db_path, &source, &msg, Some(fields)).unwrap_or_default();   // registre de parsers de CE db_path (enrichit, sans écraser ; input Some -> sortie Some)
        // M2 : host forcé (agent lié au token) ÉCRASE `_HOSTNAME` -> un agent ne peut pas usurper un autre hôte.
        let host = match forced_host {
            Some(fh) => Some(fh.to_string()),
            None => j.get("_HOSTNAME").and_then(|x| x.as_str()).map(|s| s.to_string()),
        };
        // src_ip de colonne : `… from <ip>` direct, SINON promotion depuis les fields parsés (src_ip/rhost) —
        // ALIGNE ce chemin sur celui des events (cf. fields_ip plus bas). Sans ça les IP des lignes preauth
        // (`… invalid user <u> <ip>`, sans `from` avant l'IP) et srclimit (`new <ip>/32`) restaient nulles.
        let src_ip = extract_src_ip(&msg).or_else(|| fields_ip(&Some(fields.clone())));
        // MATCH-ON-INGEST THREAT-INTEL (#23) : même confrontation que la voie events génériques, sur la
        // src_ip d'auth + les fields parsés. Cache O(1) ; vide en mode 0 -> `fields` INCHANGÉ (byte-identique).
        let (fields, ti_hit) = ti_match_event_ex(db_path, src_ip.as_deref(), None, None, Some(fields));
        let fields = fields.unwrap_or_default();
        // COUTURE STORE (data-plane) : INSERT event via le store. `category='auth'` (littéral legacy),
        // dst_ip/url/engagement_id/origin/env_id omis à l'origine -> DEFAULT de colonne (== EventRow ci-dessous)
        // -> ligne stockée BYTE-IDENTIQUE.
        // ING-1 FAIL-SAFE : sur erreur d'INSERT mid-batch (base verrouillée, disque plein…) -> ROLLBACK
        // ATOMIQUE + `Err(n)` remonté (le daemon NE tombe PAS) -> l'appelant met le fichier en QUARANTAINE
        // (rejouable) au lieu de le supprimer -> aucune perte silencieuse (CALQUE de `ingest_events_batch`).
        if let Err(e) = store().insert_event(conn, &EventRow {
            ts,
            source,
            category: "auth".into(),
            severity,
            message: msg,
            host,
            src_ip,
            dst_ip: None,
            url: None,
            dedup,
            // TAMPON DE VERSION CIM (Reorg Wave 2) : même tampon `fields.cim` que la voie events génériques,
            // pour que la voie journald (auth) soit AUSSI datable au repos.
            fields: cim_stamp(Some(fields)),
            engagement_id: String::new(),
            origin: String::new(),
            env_id: None,
        }) {
            eprintln!("[ingest] journal INSERT échoué -> ROLLBACK du batch ({db_path}) : {e}");
            let _ = conn.execute_batch("ROLLBACK");
            return Err(n);
        }
        // COMPOSITION RBA (#24) : un match threat-intel CONTRIBUE du risque à son entité (dans la MÊME
        // transaction que l'event -> atomique/cohérent). INERTE en mode 0 (aucun IOC -> ti_hit None).
        if let Some(h) = &ti_hit { ti_risk_contribution(conn, h, ts, "prod"); }
        n += 1;
    }
    // Plancher de rattrapage host_rollup (buffer journald tardif d'un agent offline) — cf. note_host_backfill_floor.
    if batch_min != i64::MAX { note_host_backfill_floor(conn, batch_min); }
    // ING-1 : le COMMIT peut échouer (I/O au flush WAL sous disque plein) -> ROLLBACK + `Err` (quarantaine)
    // au lieu d'avaler l'erreur et de supprimer un fichier dont les events n'ont PAS été durcis.
    if conn.execute_batch("COMMIT").is_err() {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(n);
    }
    // #51 DAY-2 OPS : compteur monotone d'events ingérés (voie journald NDJSON), cf. plume_ingest_events_total.
    crate::INGEST_EVENTS_TOTAL.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    Ok(n)
}

/// Cœur d'ingestion des events génériques (`kind=events`, spool `.json`) -> table `event`, en UNE
/// transaction par batch/fichier (BEGIN IMMEDIATE/COMMIT, CALQUE de `ingest_journal_lines`). AVANT : un
/// `INSERT OR IGNORE` autonome par event = une transaction SQLCipher/event (pire cas du surcoût de
/// chiffrement) ; ICI une seule transaction pour tout le fichier -> ×3-10 débit. Sémantique STRICTEMENT
/// préservée : `INSERT OR IGNORE` (dédup sur `dedup UNIQUE`), `ext:plume-*` (M1, source assainie tôt),
/// host forcé (M2), extracteur générique + promotions src_ip/dst_ip/url, colonne `origin` par défaut
/// (ingéré, non 'daemon'). La transaction reste sur LA connexion tenant fournie par l'appelant (résolue
/// per-fichier par `resolve_ingest_target`) -> JAMAIS inter-tenant. Fail-safe : sur erreur mid-batch
/// (base verrouillée, disque plein…) -> `ROLLBACK` ATOMIQUE + log, le daemon NE tombe PAS ; `Err(n)`
/// signale à l'appelant de mettre le fichier en quarantaine (rejouable, aucune perte silencieuse).
/// Renvoie `Ok(n)` = events traités et committés (avant dédup) ou `Err(n)` = rollback après n tentatives.
pub(crate) fn ingest_events_batch(
    conn: &Connection,
    db_path: &str,
    events: &[Value],
    default_ts: i64,
    host: Option<&str>,
    forced_host: Option<&str>,
) -> Result<usize, usize> {
    // Délègue à la variante env-aware avec `env_id=None` (-> le store lie 'prod' comme avant). Renvoie le
    // compte TRAITÉ (parité STRICTE avec l'historique : mêmes valeurs de retour pour tous les appelants/tests).
    ingest_events_batch_env(conn, db_path, events, default_ts, host, forced_host, None).map(|(processed, _)| processed)
}

/// Variante env-aware du cœur d'ingestion (ci-dessus). ADDITIVE : `ingest_events_batch` délègue ici avec
/// `env_id=None` -> ligne stockée BYTE-IDENTIQUE (`env_id: None` == le DEFAULT 'prod' du store) et
/// `ti_risk_contribution` sur 'prod' — parité mode-0 totale. Un CONNECTEUR (pull vendeur) passe son `env_id`
/// PAR-CONNECTEUR : l'event enrichi (parsers + extracteur générique + MATCH-ON-INGEST threat-intel ->
/// ti_match/threat_intel + composition RBA) atterrit dans le bon environnement du tenant, avec la MÊME
/// sémantique de ligne (ts/host/source/category/severity/fields/dedup) qu'un event ingéré nativement.
/// Renvoie `Ok((traités, insérés))` : `traités` = events parcourus (== retour historique) ; `insérés` =
/// lignes RÉELLEMENT écrites (INSERT OR IGNORE : les doublons dédupliqués comptent 0) -> `last_count`
/// dédup-aware pour le connecteur. `Err(n)` = ROLLBACK atomique après n events (quarantaine côté appelant).
pub(crate) fn ingest_events_batch_env(
    conn: &Connection,
    db_path: &str,
    events: &[Value],
    default_ts: i64,
    host: Option<&str>,
    forced_host: Option<&str>,
    env_id: Option<&str>,
) -> Result<(usize, usize), usize> {
    let _ = conn.execute_batch("BEGIN IMMEDIATE");
    let mut n = 0usize;
    let mut inserted = 0usize;
    let mut batch_min = i64::MAX;   // plus vieux ts du batch -> plancher de rattrapage host_rollup (arrivées tardives)
    for ev in events {
        let ets = ev.get("ts").and_then(|x| x.as_i64()).unwrap_or(default_ts);
        if ets < batch_min { batch_min = ets; }
        // M1 : réserve le namespace de contrôle `plume-*` (renommé `ext:plume-*` s'il est usurpé par
        // l'ingest). Appliqué TÔT -> parsers/extracteur/INSERT voient la source assainie (cohérence).
        let source = ext_ingest_source(ev.get("source").and_then(|x| x.as_str()).unwrap_or("agent"));
        let sev = ev.get("severity").and_then(|x| x.as_i64()).unwrap_or(0);
        let cat = ev.get("category").and_then(|x| x.as_str()).unwrap_or("");
        // CIM (warn-only, JAMAIS un drop) : une catégorie DÉCLARÉE hors taxonomie est signalée UNE fois
        // par couple (source, category) — cf. le bandeau « CATÉGORIE HORS TAXONOMIE À L'INGEST ». La ligne
        // stockée est INCHANGÉE (aucune branche d'écriture ne dépend de ce test).
        cim_warn_if_noncanonical(&source, cat);
        let m = ev.get("message").and_then(|x| x.as_str()).unwrap_or("");
        // M2 : le host forcé (agent lié) ÉCRASE le host de l'event ; sinon host event -> host fichier.
        let ehost = match forced_host {
            Some(fh) => Some(fh),
            None => ev.get("host").and_then(|x| x.as_str()).or(host),
        };
        let edd = ev.get("dedup").and_then(|x| x.as_str());
        let efields = ev.get("fields").filter(|f| !f.is_null()).map(|f| f.to_string()); // JSON structure (ex: mail: account/folder/msgid)
        let efields = parsers_apply(db_path, &source, m, efields);   // registre de parsers de CE db_path : enrichit toute source à l'ingestion
        // EXTRACTEUR GÉNÉRIQUE (PARSER PHASE 1) : opt-in par source (PLUME_GENERIC_EXTRACT), kv/
        // logfmt/json -> fields, AVANT la promotion src_ip/dst_ip ci-dessous (pour qu'une IP
        // extraite soit promue). MERGE sans écrasement (collecteur > parser > générique).
        let efields = match extract_generic(&source, m, efields.as_deref().unwrap_or("{}")) {
            Some(f) => Some(f),
            None => efields,
        };
        // PARSEUR DÉCLARATIF (DSL CIM, Slice #7 pièce 2) : mappe `source` -> champs CIM (category/severity +
        // fields src_ip/dst_ip/url/action) SANS rebuild Rust, APRÈS parsers_apply/extract_generic (mêmes
        // fields en entrée) et AVANT la promotion src_ip/dst_ip/url ci-dessous (une IP mappée est promue en
        // colonne). ADDITIF/MODE 0 : si AUCUN dparser n'est déclaré ou ne cible cette source -> (efields
        // inchangé, None, None) -> ligne stockée BYTE-IDENTIQUE. ENRICH/MAP only, jamais un drop.
        let (efields, dpar_cat, dpar_sev) = dparsers_apply(db_path, &source, m, efields);
        // NORMALISEUR ENDPOINT (#57, BYO-agent) : reconnaît le schéma d'alerte Wazuh (SCA/vuln/FIM/
        // syscollector) et mappe ses familles endpoint-sécurité vers le CIM (posture/vuln/integrity/
        // inventory + fields.*), APRÈS le DSL déclaratif (un dparser client GAGNE) et AVANT la promotion
        // src_ip/dst_ip. ADDITIF/MODE 0 : gate par source (`PLUME_ENDPOINT_NORMALIZE`, défaut `wazuh`) ->
        // hors source endpoint = (efields inchangé, None, None) = ligne BYTE-IDENTIQUE (aucun parse JSON).
        // ENRICH-only : fields fusionnés sans écraser ; category/severity = OVERRIDE CANDIDAT (dparser prioritaire).
        let (efields, ep_cat, ep_sev) = endpoint_normalize(&source, m, efields);
        let dpar_cat = dpar_cat.or(ep_cat);   // dparser (config.d client) prioritaire, sinon preset built-in Wazuh
        let dpar_sev = dpar_sev.or(ep_sev);
        // src_ip / dst_ip : du collecteur, sinon promus depuis les fields PARSÉS (champs explicitement
        // source/dest -> jamais d'inversion de sens). crowdsec/sshd-penalise -> src_ip ; conntrack -> les deux.
        // F6 : valeurs fournies par le collecteur (colonnes). src_ip/dst_ip gardent une chaîne vide (pas de
        // filtre `!is_empty` — comportement historique) ; url filtre "" (fallback promotion si vide).
        let ev_ip: Option<String> = ev.get("src_ip").and_then(|x| x.as_str()).map(|s| s.to_string());
        let ev_dst: Option<String> = ev.get("dst_ip").and_then(|x| x.as_str()).map(|s| s.to_string());
        let ev_url: Option<String> = ev.get("url").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        // F6 : quand au moins une colonne manque, parse `efields` UNE SEULE FOIS pour promouvoir les trois
        // (au lieu de 3 parses via fields_ip/dst/url). Précédence/fallback IDENTIQUES -> valeurs promues
        // BYTE-IDENTIQUES ; `.or(...)` ne retient une valeur promue que si la colonne collecteur est None,
        // exactement comme les `.or_else(...)` d'origine (un parse promu inutilisé est simplement ignoré).
        let (pip, pdst, purl) = if ev_ip.is_none() || ev_dst.is_none() || ev_url.is_none() {
            fields_promote_src_dst_url(&efields)
        } else {
            (None, None, None)
        };
        let eip: Option<String> = ev_ip.or(pip);
        let edst: Option<String> = ev_dst.or(pdst);
        // url de colonne : du collecteur, sinon promue depuis les fields parsés (ex. parser cloudflare).
        let eurl: Option<String> = ev_url.or(purl);
        // MATCH-ON-INGEST THREAT-INTEL (#23) : confronte les valeurs indicatrices (src_ip/dst_ip/url +
        // domain/hashes dans fields) au magasin d'IOC via le CACHE mémoire (O(1), jamais un SELECT/event).
        // ENRICH-NOT-SUPPRESS : sur hit -> ajoute fields.threat_intel + fields.ti_match=1 ; sinon fields
        // INCHANGÉS. INVARIANT mode 0 : cache vide (aucun IOC) -> renvoie efields tel quel -> BYTE-IDENTIQUE.
        let (efields, ti_hit) = ti_match_event_ex(db_path, eip.as_deref(), edst.as_deref(), eurl.as_deref(), efields);
        // TAG ENGAGEMENT (v75) : hors mode engagement OU sans engagement actif, `engagement_tag_for_ip` renvoie
        // "" en un SEUL test de drapeau atomique / index scope VIDE -> ZÉRO travail chaud -> l'INSERT écrit
        // engagement_id='' (= le DEFAULT de la colonne) -> LIGNE STOCKÉE BYTE-IDENTIQUE à aujourd'hui. En mode
        // engagement avec un engagement actif, un `eip` dans le scope reçoit son engagement_id (tag row-level,
        // comme env_id) -> route l'AFFICHAGE (vue Engagement) ; NE modifie JAMAIS détection/collecte (invariant).
        let eng_id: String = engagement_tag_for_ip(db_path, eip.as_deref());
        // PROVENANCE NON-FORGEABLE des auto-reports de config (chantier whitelists→webui — anti-empoisonnement
        // du panneau anti-angle-mort). Un event `category='config'` sert de VÉRITÉ TERRAIN au panneau
        // Suppressions ; or `source`/`fields`/`type` sont DÉCLARÉS par l'appelant (forgeable via /api/ingest).
        // SEULS `origin` (colonne SERVEUR — jamais lue de l'event) et `host` (forcé au token, M2) sont
        // non-forgeables. On tamponne donc l'origine de CHAQUE report de config :
        //   forced_host présent (token AGENT lié) -> origin='agent'      (ATTESTÉ : host = hôte lié au token)
        //   forced_host absent  (token central / non lié) -> origin='unverified' (host AUTO-DÉCLARÉ, non attesté)
        // Le panneau surface report_host+age+attested (+ hôtes contestés) -> un report FORGÉ ne peut plus se
        // faire passer SILENCIEUSEMENT pour la config réelle (il ressort unverified / hôte incohérent / périmé),
        // sans jamais devenir pilotable (invariants a/b : visibilité seule, contrôle à la frontière hôte). Tout
        // autre event garde origin='' (DEFAULT) -> LIGNE BYTE-IDENTIQUE à aujourd'hui (parité mode-0).
        let origin: &str = if cat == "config" {
            if forced_host.is_some() { "agent" } else { "unverified" }
        } else {
            ""
        };
        // COUTURE STORE (data-plane, chemin CHAUD) : INSERT event via le store. `env_id` omis à l'origine
        // (-> DEFAULT 'prod') est reproduit par `env_id: None` (le store lie 'prod'). Ligne BYTE-IDENTIQUE.
        let mut row = EventRow {
            ts: ets,
            source,
            // category/severity : ENRICH-only — parité avec le contrat `fields` (collecteur
            // prioritaire). Un dparser NE remplit category/severity QUE si le collecteur ne les a PAS déjà
            // déclarées (category vide / severity au défaut 0). Une catégorie DÉCLARÉE par le collecteur GAGNE
            // -> pas de re-catégorisation SILENCIEUSE hors du scope de détection (ex. un parseur `source:"*"`
            // ne peut plus réécrire la category `malware`/`ids` d'un FortiGate). Sinon = byte-identique.
            // NB : le calcul `origin` ci-dessus lit le `cat` D'ORIGINE (provenance des auto-reports `config`
            // inchangée — un dparser enrichit, il ne re-tamponne pas).
            category: if cat.is_empty() { dpar_cat.as_deref().unwrap_or(cat).to_string() } else { cat.to_string() },
            severity: if sev == 0 { dpar_sev.unwrap_or(sev) } else { sev },
            message: m.to_string(),
            host: ehost.map(|s| s.to_string()),
            src_ip: eip,
            dst_ip: edst,
            url: eurl,
            dedup: edd.map(|s| s.to_string()),
            // TAMPON DE VERSION CIM (Reorg Wave 2) : pose `fields.cim = CIM_VERSION` -> dérive détectable au
            // repos. Additif/idempotent (cf. cim_stamp) ; appliqué AVANT processors_apply pour qu'une règle de
            // masquage/route puisse quand même agir sur la ligne finale.
            fields: cim_stamp(efields),
            engagement_id: eng_id,
            origin: origin.to_string(),
            // env_id : `None` (appelants historiques) -> le store lie 'prod' == ligne BYTE-IDENTIQUE. Un
            // connecteur passe son env_id PAR-CONNECTEUR (routage environnement, comme le chemin direct).
            env_id: env_id.map(|s| s.to_string()),
        };
        // PROCESSEUR D'INGEST (#40) : filtre/masque/route/échantillonne l'event NORMALISÉ AVANT indexation.
        // MODE 0 : aucune règle sur ce db_path -> `processors_apply` renvoie Keep en un read()+get() (ligne
        // stockée BYTE-IDENTIQUE). DROP (ou SAMPLE-out) -> event NON indexé mais COMPTÉ (dropped-by-policy,
        // visible en UI) : on l'a TRAITÉ (n += 1, parité du retour) sans l'écrire et sans contribution RBA
        // (aucun event stocké). FAIL-SAFE : une règle invalide est déjà skippée au reload -> jamais un drop
        // silencieux par bug. MASK/ROUTE ont muté `row` en place.
        if let ProcVerdict::Drop = processors_apply(db_path, &mut row) {
            n += 1;
            continue;
        }
        match store().insert_event(conn, &row) {
            // INSERT OR IGNORE : `c` = 1 si la ligne est écrite, 0 si dédupliquée -> `inserted` = lignes neuves.
            Ok(c) => inserted += c,
            Err(e) => {
                // FAIL-SAFE : erreur mid-batch -> ROLLBACK ATOMIQUE du fichier + log ; le daemon NE tombe
                // PAS. L'appelant met le fichier en quarantaine (rejouable, aucune perte silencieuse).
                eprintln!("[ingest] events INSERT échoué -> ROLLBACK du batch ({db_path}) : {e}");
                let _ = conn.execute_batch("ROLLBACK");
                return Err(n);
            }
        }
        // COMPOSITION RBA (#24) : un match threat-intel CONTRIBUE du risque à son entité (MÊME transaction
        // que l'event). INERTE en mode 0 (aucun IOC -> ti_hit None) -> aucun risk_event -> byte-identique.
        // env : `env_id` du connecteur (ou 'prod' par défaut historique) -> RBA scopé au bon environnement.
        if let Some(h) = &ti_hit { ti_risk_contribution(conn, h, ets, env_id.unwrap_or("prod")); }
        n += 1;
    }
    // Plancher de rattrapage host_rollup : si un event du batch est ANTÉRIEUR au watermark host_rollup (agent
    // offline qui rejoue), on l'enregistre pour que rollup_hosts folde [floor, wm) une fois (sinon il serait
    // perdu). NO-OP quand tout est courant (ts>=wm). DANS la transaction du batch -> cohérent avec un rollback.
    if batch_min != i64::MAX { note_host_backfill_floor(conn, batch_min); }
    let _ = conn.execute_batch("COMMIT");
    // #51 DAY-2 OPS : compteur monotone d'events ingérés (self-métrique `plume_ingest_events_total`) — voie
    // batch générique `kind=events` (spool .json + HEC/MinIO normalisés). La voie journald NDJSON compte à
    // part (ingest_journal_lines). Une seule addition par batch (Relaxed, ~1 ns) -> mode 0 identique.
    crate::INGEST_EVENTS_TOTAL.fetch_add(inserted as u64, std::sync::atomic::Ordering::Relaxed);
    Ok((n, inserted))
}

/// Agent (token) : ingestion du journald brut (NDJSON) shippé depuis un hôte distant (sshd/sudo/su...).
/// `ship.sh` POSTe ici les fichiers `.ndjson` (que le loop `*.json` n'expédiait pas -> trou de collecte).
/// Écrit dans le spool (atomique) -> ingéré par la boucle de fond (comme `ingest_post`). NE fait PAS
/// le travail DB sur le worker tokio : sinon une rafale de .ndjson sature le runtime -> serveur muet.
pub(crate) async fn ingest_journal_post(State(st): State<AppState>, Extension(au): Extension<AuthUser>, body: String) -> Response {
    if body.trim().is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    // L1 — GARDE DISQUE (avant écriture spool) : 503 explicite en pré-saturation, l'agent réémet ses NDJSON.
    // La taille du corps est déjà bornée par DefaultBodyLimit (8 Mio) -> cardinalité par-fichier bornée.
    if let Some(resp) = ingest_disk_guard(&st) {
        return resp;
    }
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker(&st, &au); // R8 : tenant du token encodé dans le nom -> routé à la relecture
    let hk = spool_host_marker(&au); // M2 : host LIÉ au token agent -> écrase event.host à la relecture (anti-forge)
    let tmp = format!("{}/.jrnl-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/jrnl-{}-{}{}{}.ndjson", st.spool, now(), n, mk, hk);
    if std::fs::write(&tmp, body.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return server_err("écriture spool échouée");
    }
    // durcis le spool (0600) avant la publication atomique : umask 022 laissait les fichiers en 0644 (world-readable) -> dataacl.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if std::fs::rename(&tmp, &dst).is_err() {
        let _ = std::fs::remove_file(&tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return server_err("écriture spool échouée");
    }
    (StatusCode::ACCEPTED, Json(json!({ "queued": true }))).into_response()
}

/// ING-4 : âge minimal (s) d'un `.tmp` spool orphelin avant balayage au démarrage. SÛRETÉ : n'efface JAMAIS
/// un `.tmp` récent (un récepteur push peut être en train de l'écrire/le renommer). Aligné sur le seuil du
/// balayage de backup (`BACKUP_ORPHAN_MAX_AGE_SECS`).
pub(crate) const INGEST_TMP_ORPHAN_MAX_AGE_SECS: u64 = 3600; // 1 h

/// ING-4 — BALAYAGE DE DÉMARRAGE des `.tmp` spool ORPHELINS. Un récepteur push écrit `.<prefix>-<ts>-<n>.tmp`
/// puis `rename`. Si l'écriture/le rename ÉCHOUE (crash, disque plein), le `.tmp` subsiste et `ingest_once`
/// l'IGNORE (dotfile) -> fuite permanente (pire sous pression disque). Ce balayage (calqué sur
/// `backup::sweep_orphan_temps`) efface les `.tmp` dont la mtime dépasse `max_age`. GARDE-FOUS : (1) filtre
/// STRICT `.` initial + suffixe `.tmp` -> ne touche JAMAIS un fichier spool publié (`.json`/`.ndjson`) ni le
/// sous-dossier `quarantine` ; (2) seuil d'âge -> épargne un `.tmp` d'un POST concurrent en vol. Renvoie le
/// nombre de fichiers effacés (observabilité + assertion de test).
pub(crate) fn sweep_orphan_ingest_tmps(spool: &str, max_age: std::time::Duration) -> u64 {
    let now = std::time::SystemTime::now();
    let mut removed = 0u64;
    let rd = match std::fs::read_dir(spool) { Ok(r) => r, Err(_) => return 0 };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        // convention des récepteurs push : `.<prefix>-<ts>-<n>.tmp` (dotfile temporaire pré-rename).
        if !(name.starts_with('.') && name.ends_with(".tmp")) { continue; }
        let meta = match ent.metadata() { Ok(m) => m, Err(_) => continue };
        if !meta.is_file() { continue; }
        // mtime illisible OU trop récente -> ÉPARGNE (ne jamais clobber un `.tmp` d'un POST concurrent en vol).
        match meta.modified().ok().and_then(|m| now.duration_since(m).ok()) {
            Some(age) if age >= max_age => {}
            _ => continue,
        }
        let _ = std::fs::remove_file(ent.path());
        removed += 1;
    }
    removed
}

pub(crate) fn ingest_once(mgr: &TenantDbManager, spool: &str) {
    let rd = match std::fs::read_dir(spool) {
        Ok(r) => r,
        Err(_) => return,
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let path = ent.path();
        // CONC-2 : corps PAR FICHIER isolé par catch_unwind — le fil d'ingest est une boucle infinie SANS
        // supervision (asymétrie avec les boucles connecteurs/destinations/rapports). Un panic sur un fichier
        // empoisonné est CAPTURÉ -> QUARANTAINE (données préservées, rejouables) + on CONTINUE : jamais de
        // boucle de panic (le fichier n'est plus re-sélectionné) ni d'arrêt SILENCIEUX de l'ingestion. Happy
        // path INCHANGÉ ; un `continue` de boucle devient un `return` de closure (MÊME flux de contrôle).
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // ROUTING FAIL-CLOSED (R8) : le tenant PORTEUR est encodé dans le nom (marqueur #T#…#T#, posé par
        // ingest_post/journal/minio) -> on résout SA base (writer + db_path). Mode 0 -> toujours (st.db,
        // st.db_path). Mode 1, tenant inconnu/suspendu/clé non résolue -> QUARANTAINE (jamais d'insert dans
        // une base client, jamais de repli sur `default`). Fichier sans marqueur -> `default` (collecteurs
        // hôte centraux / mode 0 / fichiers en vol pré-migration = base opérateur/self, pas un client).
        let tenant = spool_file_tenant(&name);
        // M2 : host LIÉ au token de l'agent émetteur (marqueur `#H#…#H#`, posé par ingest_post/journal_post
        // pour un agent à token lié). Some(h) -> ÉCRASE `event.host` de tous les events du fichier (un agent
        // ne peut donc pas forger le host d'un AUTRE agent). None -> comportement historique (host de l'event).
        let forced_host = spool_file_host(&name);
        let (handle, tdb_path) = match resolve_ingest_target(mgr, &tenant) {
            Some(t) => t,
            None => {
                quarantine_spool_file(spool, &path, &name, "spool non routable (tenant inconnu/suspendu)");
                return; // (closure CONC-2 : ex-`continue`)
            }
        };
        let db = &handle;
        let db_path = tdb_path.as_str();
        if name.ends_with(".ndjson") {
            crate::INGEST_FILES_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed); // #51 DAY-2 : fichiers spool consommés
            // ING-1 : ne supprime le fichier QUE si le batch a été COMMITTÉ. Illisible (None) -> laissé pour
            // rejouer ; INSERT/COMMIT échoué (Some(Err)) -> QUARANTAINE (rejouable) au lieu d'une perte silencieuse.
            match ingest_journal(db, db_path, &path, forced_host.as_deref()) {
                None => {}
                Some(Ok(_)) => { let _ = std::fs::remove_file(&path); }
                Some(Err(_)) => quarantine_spool_file(spool, &path, &name, "journald INSERT échoué (ROLLBACK du batch)"),
            }
            return; // (closure CONC-2 : ex-`continue`)
        }
        if !name.ends_with(".json") {
            return; // (closure CONC-2 : ex-`continue`)
        }
        crate::INGEST_FILES_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed); // #51 DAY-2 : fichiers spool consommés
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // (closure CONC-2 : ex-`continue`)
        };
        let v: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return; // (closure CONC-2 : ex-`continue`)
            }
        };
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
        let ts = v.get("ts").and_then(|x| x.as_i64()).unwrap_or_else(now);
        let hash = v.get("hash").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let data = v.get("data").cloned().unwrap_or_else(|| json!({}));
        // M2 : host forcé (marqueur agent) GAGNE sur le host déclaré dans le fichier ; sinon host de l'event.
        let host = forced_host.as_deref().or_else(|| v.get("host").and_then(|x| x.as_str()));
        if kind == "events" {
            // ingestion générique d'events (FIM, agents Windows/Mac/Linux, réseau…) — UNE transaction par
            // fichier-spool (BEGIN IMMEDIATE/COMMIT, CALQUE du chemin journal) : ×3-10 débit ; dédup /
            // routing per-tenant / host forcé / origin PRÉSERVÉS (cf. `ingest_events_batch`).
            let conn = db.lock();
            let arr = data.get("events").or_else(|| v.get("events")).and_then(|e| e.as_array()).cloned().unwrap_or_default();
            // ROUTAGE ENVIRONNEMENT (P-HEC) : une enveloppe events peut PORTER `env_id` (posé par le récepteur
            // Firehose = env_id du connecteur push lié). Présent -> ingest_events_batch_env (stampe la colonne
            // env_id, comme un connecteur pull) ; ABSENT (agent/HEC/OTLP/MinIO/journal historiques) -> chemin
            // ingest_events_batch INCHANGÉ (env_id None -> 'prod') = ligne stockée BYTE-IDENTIQUE (parité mode 0).
            let committed = match v.get("env_id").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                Some(env) => ingest_events_batch_env(&conn, db_path, &arr, ts, host, forced_host.as_deref(), Some(env)).map(|(processed, _)| processed),
                None => ingest_events_batch(&conn, db_path, &arr, ts, host, forced_host.as_deref()),
            };
            drop(conn);
            match committed {
                Ok(_) => { let _ = std::fs::remove_file(&path); }
                // ROLLBACK (fail-safe) -> quarantaine : données préservées/rejouables, pas de perte silencieuse ni de boucle.
                Err(_) => quarantine_spool_file(spool, &path, &name, "events INSERT échoué (ROLLBACK du batch)"),
            }
            return; // (closure CONC-2 : ex-`continue`)
        }
        if kind == "metrics" {
            let conn = db.lock();
            // ING-1 : UNE transaction par fichier (CALQUE de la voie events) -> l'insert des métriques est
            // ATOMIQUE. Sur échec -> ROLLBACK + QUARANTAINE (rejouable, pas de ré-insertion partielle au
            // retry) au lieu d'avaler l'erreur et de supprimer le fichier (perte silencieuse sous disque plein).
            // CONC-3 : garde RAII `Txn` (BEGIN IMMEDIATE au begin ; ROLLBACK au Drop sauf `.commit()`). Un panic
            // entre BEGIN et le terminateur — capturé par le catch_unwind CONC-2 par-fichier ci-dessus — LIBÈRE
            // quand même l'écrivain PROCESS-GLOBAL (sinon transaction ouverte fuitée -> toutes les écritures
            // suivantes « cannot start a transaction within a transaction »). Succès + erreur d'insert = byte-identiques.
            let committed = if let Ok(tx) = Txn::begin(&conn) {
                let mut ok = true;
                if let Some(arr) = data.get("metrics").and_then(|m| m.as_array()) {
                    for m in arr {
                        let name = m.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let val = m.get("value").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        if !name.is_empty() {
                            // COUTURE STORE (data-plane) : `labels=None` == littéral NULL du legacy -> ligne identique.
                            if store().insert_metric(&conn, &MetricRow { ts, name: name.to_string(), labels: None, value: val, host: host.map(|s| s.to_string()) }).is_err() {
                                ok = false;
                                break;
                            }
                        }
                    }
                }
                // ok -> COMMIT (Txn::commit) ; !ok OU COMMIT en échec -> Drop(tx) = ROLLBACK (identique au manuel).
                ok && tx.commit().is_ok()
            } else {
                // BEGIN IMMEDIATE indisponible (writer déjà en transaction / verrou) -> quarantaine (rejouable).
                false
            };
            drop(conn);
            if committed {
                let _ = std::fs::remove_file(&path);
            } else {
                quarantine_spool_file(spool, &path, &name, "metrics INSERT échoué (ROLLBACK du batch)");
            }
            return; // (closure CONC-2 : ex-`continue`)
        }
        // ING-1 : snapshot/firewall/controls en UNE transaction (CALQUE de la voie events). Sur échec d'une
        // écriture (insert snapshot / heartbeat / alerte) -> ROLLBACK + QUARANTAINE (rejouable) au lieu
        // d'avaler l'erreur et de supprimer le fichier -> pas de perte silencieuse d'un snapshot de posture.
        let committed = {
            let conn = db.lock();
            // CONC-3 : garde RAII `Txn` (cf. bloc metrics ci-dessus) — un panic entre BEGIN et le terminateur,
            // capturé par le catch_unwind CONC-2 par-fichier, LIBÈRE quand même l'écrivain PROCESS-GLOBAL au
            // Drop (ROLLBACK) au lieu de fuiter une transaction ouverte. Succès + erreur d'écriture = byte-identiques.
            // `done` LIÉ (pas en position de queue) : le temporaire `Result<Txn>` est ainsi dropé AVANT `conn`.
            let done = if let Ok(tx) = Txn::begin(&conn) {
                let mut ok = true;
                let last: Option<String> = conn
                    .query_row(
                        "SELECT hash FROM snapshot WHERE kind=?1 ORDER BY ts DESC LIMIT 1",
                        params![kind],
                        |r| r.get(0),
                    )
                    .ok();
                if hash.is_empty() || last.as_deref() != Some(hash.as_str()) {
                    // COUTURE STORE (data-plane). kind/hash CLONÉS (réutilisés dans la branche else = heartbeat).
                    if store().insert_snapshot(&conn, &SnapshotRow { ts, kind: kind.clone(), hash: hash.clone(), data: data.to_string(), host: host.map(|s| s.to_string()) }).is_err() { ok = false; }
                } else {
                    // même état (hash inchangé) -> on TOUCHE le ts du dernier snapshot = heartbeat. Sinon un
                    // capteur stable (ex Control Catalog 3-manquants constants) est marqué "muet" à tort (dédup).
                    if conn.execute(
                        "UPDATE snapshot SET ts=?1 WHERE kind=?2 AND ts=(SELECT MAX(ts) FROM snapshot WHERE kind=?2)",
                        params![ts, kind],
                    ).is_err() { ok = false; }
                }
                if ok && kind == "firewall" {
                    let fw_ok = data
                        .get("control_docker_lockdown")
                        .and_then(|c| c.get("ok"))
                        .and_then(|b| b.as_bool())
                        .unwrap_or(true);
                    if !fw_ok {
                        let dedup = format!("fw-lockdown-{}", ts / 86400);
                        if conn.execute(
                            "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,host) \
                             VALUES(?1,'firewall.lockdown',3,?2,?3,?4,?5)",
                            params![ts, "Contrôle firewall docker-lan-lockdown ABSENT", data.to_string(), dedup, host],
                        ).is_err() { ok = false; }
                    }
                }
                if ok && kind == "controls" {
                    let failed = data.get("failed").and_then(|x| x.as_i64()).unwrap_or(0);
                    if failed > 0 {
                        // dédup sur l'ÉTAT (hash) + jour : 1 alerte/jour tant que l'état ne change pas
                        // (avant : /3600 = toutes les heures = verbeux pour un manque de contrôle persistant).
                        let dedup = format!("controls-{}-{}", hash, ts / 86400);
                        if conn.execute(
                            "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,host) \
                             VALUES(?1,'control.catalog',3,?2,?3,?4,?5)",
                            params![ts, format!("{failed} contrôle(s) de défense MANQUANT(S)"), data.to_string(), dedup, host],
                        ).is_err() { ok = false; }
                    }
                }
                // ok -> COMMIT (Txn::commit) ; !ok OU COMMIT en échec -> Drop(tx) = ROLLBACK (identique au manuel).
                ok && tx.commit().is_ok()
            } else {
                // BEGIN IMMEDIATE indisponible (writer déjà en transaction / verrou) -> quarantaine (rejouable).
                false
            };
            done
        };
        if committed {
            let _ = std::fs::remove_file(&path);
        } else {
            quarantine_spool_file(spool, &path, &name, "snapshot INSERT échoué (ROLLBACK du batch)");
        }
        })); // fin du corps par-fichier isolé (CONC-2)
        if res.is_err() {
            quarantine_spool_file(spool, &path, &name, "panic interne pendant l'ingest (capturé)");
        }
    }
}
