//! Intégrité + IP protégées. Ledger append-only à chaîne de hash tamper-evident (`ledger_append`),
//! double-audit fail-closed des mutations de config/source (`audit_config_change`/`audit_source_change`),
//! checkpoints signés Ed25519 (`ledger_key`/`sign_checkpoint`/`verify_run`), et denylist d'IP protégées
//! (`PROTECTED_IP_MATCHERS`/`protected_ip_matchers`/`ip_is_protected` : loopback/RFC1918/opérateur ->
//! jamais bannies). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- intégrité : ledger append-only à chaîne de hash + checkpoints Ed25519 (P3) ----------
/// Ajoute une entrée au journal d'intégrité (chaîne de hash, append-only, tamper-evident).
pub(crate) fn ledger_append(conn: &Connection, kind: &str, detail: &str) {
    let ts = now();
    let prev: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap_or_default();
    let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
    let _ = conn.execute("INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)", params![ts, kind, detail, prev, hash]);
}
/// Double-audit d'une mutation de config (#1b), DANS la transaction courante (correctif M5, fail-closed) :
/// (1) ledger append-only tamper-evident ; (2) event source='plume-config' category='config' SOC-visible ET
/// alertable (c'est CE qui rend un admin malveillant — baisse de rétention / mute de source — visible dans la
/// durée). Renvoie Err si l'un des deux writes échoue -> l'appelant ROLLBACK (mutation JAMAIS persistée sans
/// audit). NE PAS remplacer par ledger_append (best-effort, avale l'erreur) : ici l'erreur DOIT remonter.
pub(crate) fn audit_config_change(conn: &Connection, ledger_kind: &str, ledger_detail: &str, severity: i64, msg: &str, fields: &str) -> rusqlite::Result<()> {
    audit_source_change(conn, "plume-config", ledger_kind, ledger_detail, severity, msg, fields)
}
/// GÉNÉRALISATION de `audit_config_change` avec `source` de contrôle paramétrable (le double-write reste
/// fail-closed transactionnel). Le `source` DOIT appartenir à la liste NON-PURGEABLE de retention_run (v72/v75 :
/// plume-config / plume-operator-access / plume-tenant-admin / plume-engagement) sinon l'event serait purgé. v75 :
/// `plume-engagement` (sev haute) = une DÉFENSE BAISSÉE (création d'un engagement pentest) -> le SOC alerte dessus.
pub(crate) fn audit_source_change(conn: &Connection, source: &str, ledger_kind: &str, ledger_detail: &str, severity: i64, msg: &str, fields: &str) -> rusqlite::Result<()> {
    let ts = now();
    let prev: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap_or_default();
    let hash = sha256_hex(format!("{prev}|{ts}|{ledger_kind}|{ledger_detail}").as_bytes());
    conn.execute("INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)", params![ts, ledger_kind, ledger_detail, prev, hash])?;
    conn.execute(
        // origin='daemon' (v72/M1) : SEUL le daemon pose ce marqueur -> cet audit est exclu de la purge
        // (retention_run) et un agent ne peut pas forger une ligne de contrôle non-purgeable équivalente.
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,?2,'config',?3,?4,'plume-daemon',?5,'daemon')",
        params![now(), source, severity, msg, fields],
    )?;
    Ok(())
}
/// v105 (CHANGE 2) — emplacement HISTORIQUE de la clé ledger, SUR le volume de données (co-localisée avec
/// la base). C'est le SEUL cas où une clé ABSENTE est AUTO-GÉNÉRÉE (compat ascendante : first-run d'une base
/// neuve). Un chemin de SECRET monté HORS /data (Vault->ESO, ex. /etc/plume/ledger/ledger.key) doit EXISTER :
/// s'il est absent/vide on REFUSE de générer (fail-closed) — sinon un restore sur volume neuf régénérerait une
/// clé DIFFÉRENTE et casserait EN SILENCE la vérification des checkpoints (continuité tamper-evidence perdue).
pub(crate) const LEDGER_KEY_LEGACY_DEFAULT: &str = "/var/lib/plume/db/ledger.key";

/// Un chemin est-il un emplacement LEGACY on-PVC (auto-génération d'une clé absente AUTORISÉE) ? Vrai pour le
/// défaut compilé ET tout chemin sous `/data/` (le manifest live pose `PLUME_LEDGER_KEY=/data/ledger.key`).
/// Un Secret monté HORS /data (ex. `/etc/plume/ledger/ledger.key`) -> FAUX -> la clé DOIT préexister (fail-closed).
pub(crate) fn ledger_key_path_is_legacy(path: &str) -> bool {
    path == LEDGER_KEY_LEGACY_DEFAULT || path.starts_with("/data/")
}

/// v105 — chemin ACTIF de la clé ledger, résolu comme `ledger_key` : `PLUME_LEDGER_KEY_PATH` (préféré, v105)
/// puis `PLUME_LEDGER_KEY` (compat) puis le défaut compilé. Une valeur VIDE de `PLUME_LEDGER_KEY_PATH`
/// n'écrase pas le fallback. Extrait pour que le backstop de cutover (server.rs) et le signal SOC de
/// signature dégradée (retention_run) raisonnent EXACTEMENT sur le même chemin que le chargement de la clé.
pub(crate) fn ledger_key_active_path(conf: &HashMap<String, String>) -> String {
    let p = cfg(conf, "PLUME_LEDGER_KEY_PATH", "");
    if !p.trim().is_empty() { p } else { cfg(conf, "PLUME_LEDGER_KEY", LEDGER_KEY_LEGACY_DEFAULT) }
}

/// Charge (ou génère+persiste, 0600) la clé Ed25519 de signature des checkpoints. Chemin résolu par
/// `ledger_key_active_path`. La décision AUTO-GÉNÉRER vs FAIL-CLOSED dépend de `ledger_key_path_is_legacy`.
pub(crate) fn ledger_key(conf: &HashMap<String, String>) -> Option<ed25519_dalek::SigningKey> {
    let path = ledger_key_active_path(conf);
    let allow_generate = ledger_key_path_is_legacy(&path);
    ledger_key_load(&path, allow_generate)
}

/// v105 (CHANGE 2 backstop — HIGH d'audit) — verdict de la vérification d'ÉGALITÉ de clé au CUTOVER Vault.
/// La relocalisation de la clé (legacy on-PVC -> Secret Vault/ESO) suppose qu'un HUMAIN escrow la MÊME clé
/// hex dans Vault. Ce backstop CODE compare, quand les deux fichiers coexistent transitoirement, la clé
/// ACTIVE (Secret non-legacy) et la clé LEGACY résiduelle -> un écart = la clé Vault n'est PAS celle qui a
/// signé la chaîne existante -> fork SILENCIEUX de la tamper-evidence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LedgerKeyCutover {
    /// Pas de fenêtre de cutover comparable : chemin actif legacy, OU un des deux fichiers absent/vide/illisible
    /// -> aucune décision (pas de faux positif : on ne bloque JAMAIS sur une simple absence).
    NotApplicable,
    /// Chemin actif non-legacy + legacy résiduel présent, MÊME clé -> continuité prouvée (cutover cohérent).
    Match,
    /// Chemin actif non-legacy + legacy résiduel présent, clés DIFFÉRENTES -> l'appelant REFUSE de démarrer.
    Mismatch,
}

/// v105 — cœur TESTABLE (aucun env, aucune génération, lecture pure de deux fichiers). Compare la clé
/// Ed25519 (32 o) à `active_path` (Secret Vault non-legacy) et à `legacy_path` (résidu on-PVC). Ne renvoie
/// `Mismatch` QUE si les DEUX décodent en 32 octets valides ET diffèrent (compare les OCTETS décodés, pas le
/// texte hex -> insensible casse/espaces). Chemin actif legacy, ou l'un des deux absent/vide/illisible/mal
/// formé -> `NotApplicable` (fail-open côté détection : ce backstop n'existe QUE pour attraper un ESCROW
/// DIVERGENT pendant la fenêtre de cutover, jamais pour bloquer un démarrage normal).
pub(crate) fn ledger_key_cutover_check(active_path: &str, legacy_path: &str) -> LedgerKeyCutover {
    if ledger_key_path_is_legacy(active_path) {
        return LedgerKeyCutover::NotApplicable; // pas de cutover Vault en cours
    }
    if active_path == legacy_path {
        return LedgerKeyCutover::NotApplicable; // même fichier -> rien à comparer
    }
    let read_key = |p: &str| -> Option<[u8; 32]> {
        let hex = std::fs::read_to_string(p).ok()?;
        let hex = hex.trim();
        if hex.is_empty() { return None; }
        hex_decode(hex)?.try_into().ok()
    };
    match (read_key(active_path), read_key(legacy_path)) {
        (Some(a), Some(l)) => if a == l { LedgerKeyCutover::Match } else { LedgerKeyCutover::Mismatch },
        _ => LedgerKeyCutover::NotApplicable, // un côté absent/vide/mal formé -> pas de fenêtre comparable
    }
}

/// SECRET-PROVIDER PHASE 1 (hygiène finale) — décision PURE et TESTABLE : le résidu legacy on-disque
/// (`/data/ledger.key`) est-il RETIRABLE en toute sécurité ? OUI (`true`) UNIQUEMENT si le cutover Vault est
/// PROUVÉ COHÉRENT — verdict `Match` de `ledger_key_cutover_check` : chemin actif NON-legacy + résidu présent
/// + MÊME clé Ed25519 décodée. Cette unique condition garantit :
///  - JAMAIS de retrait sur `Mismatch` (c'est tout l'intérêt du backstop : le résidu est alors la vérité, la
///    clé Vault a divergé -> on garde le résidu et on refuse de booter en amont) ;
///  - JAMAIS de retrait sur `NotApplicable` (résidu absent -> rien à faire ; OU chemin actif ENCORE legacy ->
///    le résidu POURRAIT être la clé active, on n'y touche pas).
/// Idempotent : une fois le résidu retiré, le prochain boot voit `NotApplicable` (résidu absent) -> no-op.
pub(crate) fn ledger_residue_removable(active_path: &str, residue_path: &str) -> bool {
    ledger_key_cutover_check(active_path, residue_path) == LedgerKeyCutover::Match
}

/// v105 (CHANGE 2 / STEP 2 — MED-HIGH) — émet UN signal SOC NON-PURGEABLE de SANTÉ DE SIGNATURE du ledger.
/// `source='plume-config'` + `origin='daemon'` -> déjà couvert par `RETENTION_NONPURGE` (JAMAIS purgé,
/// SOC-visible et alertable, comme l'audit de config). `category='health'`. DÉDUP HORAIRE (INSERT OR IGNORE
/// sur `dedup` UNIQUE) -> au plus 1 signal/heure par `kind` tant que la condition dure : un boot en
/// crashloop OU des ticks retention_run répétés ne tempêtent PAS (miroir de `emit_disk_health`). Renvoie
/// true si une ligne a été écrite. `now_ts` injecté pour la testabilité (comme emit_disk_health).
fn emit_ledger_health(conn: &Connection, now_ts: i64, kind: &str, severity: i64, msg: String, fields: String) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE -> 1 signal/heure max (anti-tempête, y compris crashloop)
    let dedup = format!("plume-ledger-{kind}-{bucket}");
    let n = store().insert_event(conn, &EventRow {
        ts: now_ts,
        source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
        category: "health".into(),
        severity,
        message: msg,
        host: Some("plume-daemon".into()),
        src_ip: None, dst_ip: None, url: None,
        dedup: Some(dedup),
        fields: Some(fields),
        engagement_id: String::new(),
        origin: "daemon".into(), // marqueur DAEMON -> exclut de la purge (un agent forgeur porte origin='')
        env_id: None,
    }).unwrap_or(0);
    n > 0
}

/// v105 (STEP 2) — signal SOC : la SIGNATURE des checkpoints est DÉGRADÉE (clé absente/vide sur un chemin
/// Secret NON-legacy -> `ledger_key()` a renvoyé None -> checkpoints NON signés). Fragilité Vault-reseal
/// oblige : l'opérateur DOIT le voir dans la console, pas seulement sur stderr. Sévérité 4 (P1).
pub(crate) fn emit_ledger_unsigned(conn: &Connection, now_ts: i64, active_path: &str) -> bool {
    let msg = format!(
        "SIGNATURE DU LEDGER DÉGRADÉE : clé absente/vide à '{active_path}' (chemin Secret non-legacy) — \
         checkpoints d'intégrité NON signés. Escrow/peuplement de la clé Vault requis (fail-closed : aucune \
         clé divergente générée). Vérifier ExternalSecret/Vault (reseal ?)."
    );
    let fields = json!({ "signing": "degraded", "reason": "key-absent-or-empty", "path": active_path }).to_string();
    emit_ledger_health(conn, now_ts, "unsigned", 4, msg, fields)
}

/// v105 (STEP 1) — signal SOC : la clé Vault ACTIVE DIFFÈRE de la clé LEGACY résiduelle au cutover (fork
/// silencieux de la chaîne d'intégrité). Émis JUSTE AVANT le refus-de-boot (server.rs) pour qu'une trace
/// non-purgeable subsiste malgré l'arrêt. Sévérité 4 (P1).
pub(crate) fn emit_ledger_key_mismatch(conn: &Connection, now_ts: i64, active_path: &str, legacy_path: &str) -> bool {
    let msg = format!(
        "CLÉ LEDGER INCOHÉRENTE AU CUTOVER : la clé Vault active '{active_path}' DIFFÈRE de la clé legacy \
         résiduelle '{legacy_path}'. La clé escrow dans Vault n'est PAS celle qui a signé la chaîne existante \
         -> fork d'intégrité. Escrow le BON hex avant le cutover, ou retirer le résidu legacy. Démarrage REFUSÉ."
    );
    let fields = json!({ "signing": "fork-risk", "reason": "vault-key-differs-from-legacy", "active": active_path, "legacy": legacy_path }).to_string();
    emit_ledger_health(conn, now_ts, "key-mismatch", 4, msg, fields)
}

/// Cœur TESTABLE (aucun env) : lit la clé Ed25519 (32 o hex) à `path`. Si absente :
///  - `allow_generate` (chemin legacy on-PVC) -> génère+persiste 0600 (comportement historique) ;
///  - sinon (Secret monté attendu) -> FAIL-CLOSED : `None` + log clair, JAMAIS de nouvelle clé silencieuse
///    (une clé divergente rendrait les checkpoints invérifiables sans le dire). Les appelants
///    (`sign_checkpoint` via `if let Some(k)`) sautent simplement la signature -> dégradation SÛRE.
///  - `path` présent mais VIDE (Secret pas encore peuplé par ESO) suit la MÊME règle que l'absence.
pub(crate) fn ledger_key_load(path: &str, allow_generate: bool) -> Option<ed25519_dalek::SigningKey> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::read_to_string(path) {
        // clé PRÉSENTE et non vide : lecture normale (inchangée) — legacy comme Secret.
        Ok(hex) if !hex.trim().is_empty() => {
            let bytes: [u8; 32] = hex_decode(hex.trim())?.try_into().ok()?;
            Some(ed25519_dalek::SigningKey::from_bytes(&bytes))
        }
        // fichier PRÉSENT mais VIDE (Secret monté non encore peuplé par ESO, ou clé tronquée) : on NE régénère
        // JAMAIS par-dessus (ni legacy ni Secret) — écraser une clé possiblement corrompue romprait la
        // continuité de vérification. Fail-closed : None (comportement legacy historique préservé) + log si Secret.
        Ok(_) => {
            if !allow_generate {
                eprintln!(
                    "[ledger] clé VIDE à '{path}' — chemin NON-legacy (Secret escrow attendu, non peuplé ?) : \
                     fail-closed, checkpoints NON signés. NE PAS régénérer (romprait la vérification du ledger)."
                );
            }
            None
        }
        // fichier ABSENT : génération AUTORISÉE uniquement sur emplacement legacy on-PVC (first-run base neuve).
        Err(_) => {
            if !allow_generate {
                eprintln!(
                    "[ledger] clé ABSENTE à '{path}' — chemin NON-legacy (Secret escrow attendu) : REFUS de \
                     générer une nouvelle clé (fail-closed). Checkpoints NON signés jusqu'à provisionnement. \
                     NE PAS régénérer : une clé divergente romprait EN SILENCE la continuité de vérification."
                );
                return None;
            }
            use std::io::Read;
            let mut b = [0u8; 32];
            std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
            let _ = std::fs::write(path, hex_encode(&b));
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            Some(ed25519_dalek::SigningKey::from_bytes(&b))
        }
    }
}
/// Signe la tête de chaîne du ledger -> checkpoint vérifiable avec la clé publique.
pub(crate) fn sign_checkpoint(conn: &Connection, key: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer;
    let head: String = conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap_or_else(|_| "genesis".into());
    let sig = key.sign(head.as_bytes());
    let _ = conn.execute(
        "INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4)",
        params![now(), head, hex_encode(&sig.to_bytes()), hex_encode(key.verifying_key().as_bytes())],
    );
}
/// `plume-daemon verify` : recalcule la chaîne + vérifie les signatures des checkpoints.
/// INVARIANT : ouvre la base par le chemin KEYÉ (READ-ONLY + `PRAGMA key` via apply_key, comme
/// `open_db`/`ledger-export`) — SANS quoi une base SQLCipher est illisible et un `.unwrap()`
/// PANIQUERAIT (l'outil de détection de falsification ne tournerait jamais sur une base chiffrée). Toute erreur (clé absente/
/// incorrecte, base absente, ledger illisible) remonte proprement en `exit(2)` — jamais de panic.
pub(crate) fn verify_run() {
    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    match verify_ledger(&db_path) {
        Ok((n, sig_ok, sig_bad, broken)) => match broken {
            Some(id) => {
                println!("INTÉGRITÉ COMPROMISE : rupture de chaîne à l'entrée #{id} ({n} entrées)");
                std::process::exit(1);
            }
            // v134 (#11) — avec un PIN escrow (PLUME_LEDGER_PUBKEY) configuré, un checkpoint KO signifie un
            // pubkey in-band NON de confiance (re-signature) ou une signature invalide -> ÉCHEC DUR (exit 1).
            // SANS pin, KO>0 reste un simple signalement (dégradation de signature, ex. Vault re-scellé).
            None if ledger_pinned_pubkey().is_some() && sig_bad > 0 => {
                println!("INTÉGRITÉ COMPROMISE (PIN) : {sig_bad} checkpoint(s) NON signé(s) par la clé escrow épinglée (OK={sig_ok}, {n} entrées) — re-signature possible");
                std::process::exit(1);
            }
            None => println!("ledger OK : {n} entrées chaînées intègres ; checkpoints signés OK={sig_ok} KO={sig_bad}"),
        },
        Err(e) => {
            eprintln!("verify: {e}"); // clé manquante/incorrecte, base illisible, etc. — jamais un panic
            std::process::exit(2);
        }
    }
}
/// Ouvre la base en READ-ONLY + applique la clé SQLCipher (apply_key = PRAGMA key si PLUME_DB_KEY, sinon
/// no-op sur base en clair) puis délègue à `verify_ledger_conn`. FAIL-CLOSED : ouverture/lecture impossible
/// (clé absente/incorrecte -> `SELECT ... FROM ledger` échoue) -> `Err` (jamais un panic).
pub(crate) fn verify_ledger(db_path: &str) -> Result<(usize, i64, i64, Option<i64>), String> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("ouverture {db_path}: {e}"))?;
    apply_key(&conn); // clé SQLCipher (PLUME_DB_KEY) — mirroir de open_db/ledger-export ; DOIT précéder toute requête
    let _ = sqlite_plafond::armer(&conn);
    // v134 (#11) — applique le PIN escrow (PLUME_LEDGER_PUBKEY) s'il est configuré (sinon None -> comportement
    // historique : on fait confiance au pubkey IN-BAND de chaque checkpoint).
    let pinned = ledger_pinned_pubkey();
    verify_ledger_conn(&conn, pinned.as_ref())
}
/// v134 (#11) — PUBKEY ESCROW ÉPINGLÉ (OPTIONNEL) : `PLUME_LEDGER_PUBKEY` (hex 64 chars, ou base64 standard)
/// = la clé PUBLIQUE ed25519 de confiance (escrow hors-bande). POSÉ -> la vérification REFUSE tout checkpoint
/// dont le pubkey IN-BAND diffère (un attaquant DB-write-SANS-ledger.key aurait re-signé avec SA clé, pubkey
/// in-band inclus -> auto-cohérent mais NON de confiance). NON POSÉ -> None -> comportement historique préservé.
pub(crate) fn ledger_pinned_pubkey() -> Option<[u8; 32]> {
    let raw = std::env::var("PLUME_LEDGER_PUBKEY").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    parse_ed25519_pubkey(raw)
}
/// Parse une clé publique ed25519 (32 o) depuis hex (64 chars — format des checkpoints en base, prioritaire)
/// ou base64 standard. `None` si non décodable / mauvaise longueur.
pub(crate) fn parse_ed25519_pubkey(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if let Some(b) = hex_decode(s) {
        if let Ok(a) = <[u8; 32]>::try_from(b) {
            return Some(a);
        }
    }
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
        if let Ok(a) = <[u8; 32]>::try_from(b) {
            return Some(a);
        }
    }
    None
}
/// Cœur testable (aucune ouverture de fichier ni env) : recalcule la chaîne de hash + vérifie les signatures
/// Ed25519 des checkpoints sur une connexion DÉJÀ ouverte+keyée. Renvoie (nb_entrées, sig_ok, sig_ko,
/// première_rupture). Aucun `unwrap` : une base illisible (clé incorrecte) -> `Err` propre.
/// v134 (#11) — PIN escrow OPTIONNEL : `pinned=Some(pk)` -> un checkpoint dont le pubkey in-band != `pk` FAIL
/// (compté en sig_ko) AVANT toute vérif de signature (on ne fait jamais confiance à un pubkey non-épinglé).
/// `pinned=None` -> comportement historique (confiance au pubkey in-band). Le RESTE est inchangé.
pub(crate) fn verify_ledger_conn(conn: &Connection, pinned: Option<&[u8; 32]>) -> Result<(usize, i64, i64, Option<i64>), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut stmt = conn.prepare("SELECT id,ts,kind,detail,prev_hash,hash FROM ledger ORDER BY id")
        .map_err(|e| format!("lecture ledger (clé SQLCipher manquante/incorrecte ?): {e}"))?;
    let rows: Vec<(i64, i64, String, String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?.unwrap_or_default(), r.get(4)?, r.get(5)?)))
        .map_err(|e| format!("scan ledger: {e}"))?
        .flatten().collect();
    let mut prev = String::new();
    let mut broken: Option<i64> = None;
    for (id, ts, kind, detail, prev_hash, hash) in &rows {
        let h = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
        if prev_hash != &prev || &h != hash {
            broken = Some(*id);
            break;
        }
        prev = hash.clone();
    }
    let mut cs = conn.prepare("SELECT ledger_hash,sig,pubkey FROM checkpoint ORDER BY id")
        .map_err(|e| format!("lecture checkpoints: {e}"))?;
    let cps: Vec<(String, String, String)> = cs.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|e| format!("scan checkpoints: {e}"))?
        .flatten().collect();
    let (mut sig_ok, mut sig_bad) = (0i64, 0i64);
    for (lh, sig, pk) in &cps {
        let ok = (|| {
            let pkb: [u8; 32] = hex_decode(pk)?.try_into().ok()?;
            // v134 (#11) — PIN escrow : si un pubkey est épinglé et que le pubkey IN-BAND diffère, ce
            // checkpoint FAIL AVANT toute vérif de signature (re-signature attaquant : la signature serait
            // valide vis-à-vis de SA clé, mais cette clé n'est pas la clé de confiance escrow).
            if let Some(p) = pinned {
                if &pkb != p {
                    return Some(false);
                }
            }
            let sgb: [u8; 64] = hex_decode(sig)?.try_into().ok()?;
            let vk = VerifyingKey::from_bytes(&pkb).ok()?;
            Some(vk.verify(lh.as_bytes(), &Signature::from_bytes(&sgb)).is_ok())
        })().unwrap_or(false);
        if ok { sig_ok += 1; } else { sig_bad += 1; }
    }
    Ok((rows.len(), sig_ok, sig_bad, broken))
}

/// DENYLIST d'IP PROTÉGÉES qu'un ban ne doit JAMAIS toucher : loopback
/// (127.0.0.0/8, ::1), link-local (169.254/16, fe80::/10), RFC1918 (10/8, 172.16-31/12, 192.168/16),
/// ULA IPv6 (fc00::/7), PLUS les préfixes opérateur/self configurés (PLUME_OPERATOR_IPS + PLUME_PROTECTED_IPS,
/// ex. passerelle/DNS). Empêche qu'un event forgé (src_ip=IP tierce/interne) — même s'il franchit la validation
/// de format — déclenche le ban d'une IP loopback/privée/opérateur (self-DoS ou coupure de l'infra). Sûr : les
/// IP à bannir sont des attaquants EXTERNES (publiques) ; les collecteurs/réponses légitimes ne visent pas ces
/// plages. Configurable via PLUME_OPERATOR_IPS / PLUME_PROTECTED_IPS (CSV, notation exacte ou CIDR/`*`).
static PROTECTED_IP_MATCHERS: std::sync::OnceLock<Vec<(String, bool)>> = std::sync::OnceLock::new();
pub(crate) fn protected_ip_matchers() -> &'static Vec<(String, bool)> {
    PROTECTED_IP_MATCHERS.get_or_init(|| {
        let conf = load_config();
        let mut v = Vec::new();
        // opérateur (défaut = l'opérateur plateforme) + liste additionnelle passerelle/DNS (défaut vide).
        for item in cfg(&conf, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT).split(',') {
            if let Some(m) = parse_excl_item(item) { v.push(m); }
        }
        for item in cfg(&conf, "PLUME_PROTECTED_IPS", "").split(',') {
            if let Some(m) = parse_excl_item(item) { v.push(m); }
        }
        v
    })
}
/// Rabat une IPv4-mapped IPv6 (`::ffff:a.b.c.d`) sur son IPv4 embarqué -> FERME le contournement d'encodage
/// `[::ffff:169.254.169.254]` (et une résolution AAAA vers une mapped). `None` si la chaîne n'est pas une IP
/// (nom d'hôte : le verdict viendra de la résolution DNS, pas d'ici). Classification robuste par `IpAddr`.
pub(crate) fn ssrf_norm_ip(ip: &str) -> Option<std::net::IpAddr> {
    use std::net::IpAddr;
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
        v4 => Some(v4),
    }
}
/// Plages qui ne sont JAMAIS une cible d'égress légitime NI une IP à bannir : loopback (127/8, ::1),
/// link-local (169.254/16 = metadata cloud AWS/GCP/Azure ; fe80::/10), unspecified (0.0.0.0, :: -> résout
/// loopback sous Linux), ULA IPv6 (fc00::/7). Classification par `IpAddr` (pas de préfixe string fragile).
pub(crate) fn ip_never_egress(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() { return true; }
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),                    // 169.254/16
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xffc0) == 0xfe80 || (s0 & 0xfe00) == 0xfc00   // fe80::/10 (link-local) | fc00::/7 (ULA)
        }
    }
}
/// RFC1918 privé IPv4 (10/8, 172.16/12, 192.168/16). `Ipv4Addr::is_private` = EXACTEMENT ces 3 plages.
pub(crate) fn ip_is_rfc1918(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V4(v4) if v4.is_private())
}
/// PROTECTION BAN (anti self-DoS) : une IP loopback / link-local / unspecified / RFC1918 / ULA (IPv4-mapped
/// IPv6 incluse) + les préfixes opérateur/self configurés ne sont JAMAIS bannissables. NB : ici RFC1918 reste
/// TOUJOURS protégé (bannir sa passerelle interne = auto-DoS) — la garde SSRF, elle, a sa PROPRE politique où
/// RFC1918 est opt-in (cf. `ssrf_ipaddr_blocked`) : ne PAS confondre les deux usages.
pub(crate) fn ip_is_protected(ip: &str) -> bool {
    let ip = ip.trim();
    if ip.is_empty() { return false; }
    let low = ip.to_ascii_lowercase();
    if let Some(p) = ssrf_norm_ip(&low) {
        if ip_never_egress(p) || ip_is_rfc1918(p) { return true; }
    }
    // opérateur / self / passerelle-DNS configurés (préfixe LIKE ou égalité exacte).
    protected_ip_matchers().iter().any(|(val, is_prefix)| if *is_prefix { low.starts_with(&val.to_ascii_lowercase()) } else { low == val.to_ascii_lowercase() })
}

// ---------- garde SSRF applicative (défense en profondeur au-dessus du confinement réseau) ----------
/// Politique de blocage RFC1918 en SSRF : OPT-IN via `PLUME_SSRF_BLOCK_PRIVATE=1` (défaut OFF). RATIONALE
/// (produit) : un SOC ON-PREM cible LÉGITIMEMENT des ressources internes en 10/172.16/192.168 — relais SMTP
/// interne pour les notifiers email, webhook/ntfy/SIEM on-prem, endpoint OIDC d'un IdP interne. Bloquer TOUT
/// le RFC1918 par défaut casserait ces configs out-of-the-box. Un opérateur CLOUD durcit avec le flag ; le
/// never-egress (loopback/link-local=metadata/unspecified/ULA) reste TOUJOURS bloqué (jamais une cible légitime).
static SSRF_BLOCK_PRIVATE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
fn ssrf_block_private() -> bool {
    *SSRF_BLOCK_PRIVATE.get_or_init(|| {
        let conf = load_config();
        matches!(cfg(&conf, "PLUME_SSRF_BLOCK_PRIVATE", "").trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}
/// Politique SSRF EXPLICITE (testable sans env) : never-egress INCONDITIONNEL + RFC1918 SELON `block_private`.
pub(crate) fn ssrf_blocked_policy(ip: std::net::IpAddr, block_private: bool) -> bool {
    ip_never_egress(ip) || (block_private && ip_is_rfc1918(ip))
}
/// Cible interdite pour un ÉGRESS SSRF (applique le flag env). Distinct de `ip_is_protected` : le ban protège
/// TOUJOURS le RFC1918, l'égress non par défaut.
pub(crate) fn ssrf_ipaddr_blocked(ip: std::net::IpAddr) -> bool {
    ssrf_blocked_policy(ip, ssrf_block_private())
}

/// Entrée d'allowlist SSRF : hôte exact (nom DNS), ou réseau IP/CIDR (une IP nue = /32|/128).
pub(crate) enum SsrfAllow { Host(String), Net(std::net::IpAddr, u32) }
/// Parse une entrée `PLUME_SSRF_ALLOW` : `host.interne`, `10.0.0.5`, ou `10.20.0.0/16` (CIDR). None si vide/invalide.
pub(crate) fn parse_ssrf_allow(item: &str) -> Option<SsrfAllow> {
    let it = item.trim().to_ascii_lowercase();
    if it.is_empty() { return None; }
    if let Some((net, bits)) = it.split_once('/') {
        let ip = net.parse::<std::net::IpAddr>().ok()?;
        let bits = bits.parse::<u32>().ok()?;
        if bits > if ip.is_ipv4() { 32 } else { 128 } { return None; }
        Some(SsrfAllow::Net(ip, bits))
    } else if let Ok(ip) = it.parse::<std::net::IpAddr>() {
        Some(SsrfAllow::Net(ip, if ip.is_ipv4() { 32 } else { 128 }))
    } else {
        Some(SsrfAllow::Host(it))
    }
}
/// `ip` ∈ réseau `net/bits` ? (masque sur l'entier ; IPv4-mapped normalisée des deux côtés).
pub(crate) fn ip_in_cidr(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u32) -> bool {
    use std::net::IpAddr;
    let norm = |a: IpAddr| match a { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)), v4 => v4 };
    match (norm(ip), norm(net)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m: u32 = if bits >= 32 { u32::MAX } else if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & m) == (u32::from(b) & m)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m: u128 = if bits >= 128 { u128::MAX } else if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & m) == (u128::from(b) & m)
        }
        _ => false,
    }
}
/// Échappatoire OPÉRATEUR : `PLUME_SSRF_ALLOW` (CSV d'hôtes EXACTS et/ou de CIDR, ex. `10.20.0.0/16` pour tout
/// un sous-réseau interne légitime) — court-circuite la garde SSRF POUR CES cibles. Vide par défaut (deny strict).
static SSRF_ALLOW: std::sync::OnceLock<Vec<SsrfAllow>> = std::sync::OnceLock::new();
fn ssrf_allowlist() -> &'static Vec<SsrfAllow> {
    SSRF_ALLOW.get_or_init(|| {
        let conf = load_config();
        cfg(&conf, "PLUME_SSRF_ALLOW", "").split(',').filter_map(parse_ssrf_allow).collect()
    })
}
/// L'hôte (nom OU IP littérale) est-il explicitement allowlisté ? (nom exact, ou IP littérale ∈ CIDR permis).
fn ssrf_host_allowed(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let lit = ssrf_norm_ip(&h);
    ssrf_allowlist().iter().any(|a| match a {
        SsrfAllow::Host(x) => x == &h,
        SsrfAllow::Net(net, bits) => lit.map(|ip| ip_in_cidr(ip, *net, *bits)).unwrap_or(false),
    })
}
/// Une IP RÉSOLUE est-elle allowlistée par un CIDR/IP opérateur ? (les entrées `Host` nom ne matchent pas une IP.)
fn ssrf_ip_allowed(ip: std::net::IpAddr) -> bool {
    ssrf_allowlist().iter().any(|a| matches!(a, SsrfAllow::Net(net, bits) if ip_in_cidr(ip, *net, *bits)))
}
/// Extrait `(host, port)` de l'autorité d'une URL (déjà privée de son schéma et de son chemin), en gérant
/// l'`user:pass@` (userinfo) et le littéral IPv6 `[::1]:port`. `default_port` sert si aucun port explicite.
fn ssrf_split_authority(authority: &str, default_port: u16) -> (String, u16) {
    let authority = authority.rsplit('@').next().unwrap_or(authority); // retire un éventuel userinfo
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 littéral : [host]:port
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default_port);
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        // rsplit_once sur un host:port ; un IPv6 nu (plusieurs ':') est invalide sans crochets -> traité comme host
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() =>
            (h.to_string(), p.parse().unwrap_or(default_port)),
        _ => (authority.to_string(), default_port),
    }
}
/// GARDE SSRF réutilisable — appliquée à TOUTE URL sortante pilotée par un admin/utilisateur (notifiers,
/// destinations #50, connecteur http_pull + ses URL de pagination/`next`, endpoints IdP OIDC discovery/token/
/// jwks). REJETTE :
///  - un schéma hors `http(s)`/`smtp(s)` (donc `file://`, `gopher://`, `-flag`…) ;
///  - un hôte NEVER-EGRESS : loopback (127/8, ::1), link-local (169.254/16 = metadata cloud, fe80::/10),
///    unspecified (0.0.0.0, ::), ULA IPv6 (fc00::/7) — l'IPv4-mapped IPv6 (`::ffff:x.x.x.x`) est NORMALISÉE
///    d'abord (ferme `[::ffff:169.254.169.254]`). RFC1918 en SUS UNIQUEMENT si `PLUME_SSRF_BLOCK_PRIVATE=1`
///    (défaut OFF : on-prem cible ses ressources internes légitimement — cf. `ssrf_block_private`) ;
///  - un HÔTE dont la RÉSOLUTION DNS pointe vers une de ces plages (on re-vérifie CHAQUE IP résolue).
/// FAIL-CLOSED : hôte vide, schéma interdit, ou résolution DNS impossible -> `Err` (deny sur l'incertitude).
/// Échappatoire : `PLUME_SSRF_ALLOW` (hôtes exacts ET/OU CIDR). Cette garde s'applique aux URL d'égress
/// fixées via l'UI/API.
///
/// PORTÉE : la validation d'adresse a lieu AVANT la connexion. C'est une DÉFENSE EN PROFONDEUR, pas un
/// substitut au confinement réseau : en déploiement sans politique réseau, restreignez l'égress du service
/// au strict nécessaire (politique de sortie / pare-feu de votre plateforme).
pub(crate) fn ssrf_guard(url: &str) -> Result<(), String> {
    let low = url.trim().to_ascii_lowercase();
    let (rest, default_port) = if let Some(r) = low.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = low.strip_prefix("http://") {
        (r, 80)
    } else if let Some(r) = low.strip_prefix("smtps://") {
        (r, 465)
    } else if let Some(r) = low.strip_prefix("smtp://") {
        (r, 25)
    } else {
        return Err("SSRF: schéma d'URL non autorisé (http/https/smtp attendu)".into());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("SSRF: hôte d'URL vide".into());
    }
    let (host, port) = ssrf_split_authority(authority, default_port);
    ssrf_check_host(&host, port)
}
/// Cœur réutilisable de la garde SSRF sur un couple (host, port) — permet aux transports NON-URL (le syslog
/// `tcp://` des destinations #50) de partager EXACTEMENT la même politique. Voir `ssrf_guard`.
pub(crate) fn ssrf_check_host(host: &str, port: u16) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err("SSRF: hôte d'URL vide".into());
    }
    // échappatoire opérateur explicite (nom exact OU IP littérale ∈ CIDR permis)
    if ssrf_host_allowed(&host) {
        return Ok(());
    }
    // littéral IP interne ? (rejet immédiat, avant toute résolution ; IPv4-mapped normalisée)
    if let Some(ip) = ssrf_norm_ip(&host) {
        if ssrf_ipaddr_blocked(ip) {
            return Err(format!("SSRF: cible interne interdite ({host})"));
        }
    }
    // résolution DNS + re-check de CHAQUE IP ; échec de résolution -> deny (fail-closed)
    let mut resolved = 0usize;
    let addrs = (host.as_str(), port).to_socket_addrs()
        .map_err(|e| format!("SSRF: résolution de '{host}' impossible (deny): {e}"))?;
    for a in addrs {
        resolved += 1;
        let ip = a.ip();
        if ssrf_ip_allowed(ip) { continue; } // CIDR/IP opérateur : exempte cette IP résolue
        if ssrf_ipaddr_blocked(ip) {
            return Err(format!("SSRF: '{host}' résout vers une adresse interne ({ip}) — refus"));
        }
    }
    if resolved == 0 {
        return Err(format!("SSRF: aucune IP résolue pour '{host}' (deny)"));
    }
    Ok(())
}
