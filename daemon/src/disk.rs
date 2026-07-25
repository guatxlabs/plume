//! Garde disque / cardinalité à l'ingest + alerte pré-saturation disque (#29).
//! Extrait verbatim de main.rs (pure move) — la mesure statvfs (`unsafe`) reste ici.
use crate::*;

// ================================================================================================
// L1 — GARDE DISQUE / CARDINALITÉ À L'INGEST (anti disk-pressure : rejeu de l'incident image-GC).
// INVARIANT ANTI-ANGLE-MORT : les seuils sont TRÈS au-dessus d'un batch légitime ; on ne coupe QU'un flux
// pathologique ou un disque en pré-saturation, JAMAIS la collecte réelle. Tout refus est EXPLICITE (l'agent
// RÉÉMET plus tard) -> jamais une perte silencieuse. Le daemon MESURE le disque (statvfs), il ne pilote PAS
// l'hôte. Fonctions PURES (décision) + une helper d'effet -> testables sans monter de serveur.
// ================================================================================================

/// Espace LIBRE (Mo) du système de fichiers contenant `path`, via statvfs(3) — MESURE RÉELLE du volume
/// (WAL, backups, autres fichiers inclus), robuste vs une simple somme de fichiers du spool. `None` si
/// l'appel échoue (chemin absent, FS exotique) -> l'appelant FAIL-OPEN (ne bloque JAMAIS la collecte sur
/// une erreur de mesure : l'invariant anti-angle-mort prime ; le garde ne coupe que quand on SAIT le disque
/// saturé).
pub(crate) fn fs_free_mb(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY : statvfs remplit une struct zéro-initialisée ; on ne lit ses champs qu'en cas de succès (rc==0).
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut sv) };
    if rc != 0 {
        return None;
    }
    // f_bavail = blocs libres pour un process NON privilégié (borne réaliste) ; f_frsize = taille d'un bloc.
    let free = (sv.f_bavail as u64).saturating_mul(sv.f_frsize as u64);
    Some(free / (1024 * 1024))
}

/// DÉCISION PURE du garde disque : `true` = REFUSER l'ingest. `min_free_mb == 0` -> garde désactivé (jamais).
/// `free_mb == None` (mesure indisponible) -> FAIL-OPEN (ne refuse pas). Refuse ssi l'espace libre est
/// STRICTEMENT sous le seuil.
pub(crate) fn ingest_disk_reject(min_free_mb: u64, free_mb: Option<u64>) -> bool {
    min_free_mb != 0 && free_mb.map(|f| f < min_free_mb).unwrap_or(false)
}

/// DÉCISION PURE du plafond de cardinalité : `true` = REFUSER (413). Ne compte que le tableau `events`
/// (kind=events) ; les autres kinds (metrics/firewall/controls…) ne sont pas concernés. `max == 0` ->
/// désactivé.
pub(crate) fn ingest_events_over_cap(v: &Value, max: usize) -> bool {
    max != 0 && v.get("events").and_then(|e| e.as_array()).map(|a| a.len() > max).unwrap_or(false)
}

/// GARDE DISQUE (effet) — à appeler AVANT toute écriture spool. Renvoie `Some(503 + Retry-After)` si le
/// volume du spool est en pré-saturation (refus EXPLICITE, l'agent réémet), `None` sinon (ingest autorisé).
pub(crate) fn ingest_disk_guard(st: &AppState) -> Option<Response> {
    if ingest_disk_reject(st.ingest_min_free_mb, fs_free_mb(st.spool.as_str())) {
        let free = fs_free_mb(st.spool.as_str()).unwrap_or(0);
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "60".to_string())],
            Json(json!({
                "error": format!("espace disque insuffisant ({free} Mo libres < {} Mo requis) — ingest temporairement refusé, réémettez plus tard", st.ingest_min_free_mb),
                "retry": true
            })),
        ).into_response());
    }
    None
}

// ================================================================================================
// GARDE-FOU #29 — ALERTE PRÉ-SATURATION DISQUE (>80%). Le garde d'ingest ci-dessus REFUSE l'ingest sous un
// plancher d'espace LIBRE (512 Mo) : c'est un dernier rempart, invisible tant qu'il ne coupe pas. Ici on
// rend le RISQUE de disk-pressure VISIBLE DANS LE SOC bien avant : un EVENT santé (source=plume-disk,
// category=health) quand l'usage du volume de données dépasse un seuil %, RATE-LIMITÉ (dedup horaire ->
// au plus 1 warn/heure). Réponse directe à l'incident VPS (/ à 94% -> kubelet image-GC -> SOC+plume down) :
// le SOC se prévient LUI-MÊME de sa propre pré-saturation. INERTE si seuil=0 (désactivé) ou mesure
// indisponible (fail-open, comme fs_free_mb). Émis depuis la boucle rollup (periodique, sous lock writer).
// ================================================================================================

/// Espace du volume de `path` : (total_mo, dispo_mo) via statvfs. Étend fs_free_mb (qui ne renvoie QUE le
/// libre) pour aussi exposer le TOTAL -> calcul d'un % d'utilisation. None si la mesure échoue.
pub(crate) fn fs_total_avail_mb(path: &str) -> Option<(u64, u64)> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY : statvfs remplit une struct zéro-initialisée ; champs lus seulement sur succès (rc==0).
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut sv) } != 0 {
        return None;
    }
    let frsize = sv.f_frsize as u64;
    let total = (sv.f_blocks as u64).saturating_mul(frsize) / (1024 * 1024);
    let avail = (sv.f_bavail as u64).saturating_mul(frsize) / (1024 * 1024);
    if total == 0 {
        return None;
    }
    Some((total, avail))
}

/// % d'utilisation (0..100) d'un volume depuis (total_mo, dispo_mo). None si total==0. CONSERVATEUR : compte
/// les blocs réservés (total - dispo-non-privilégié) comme utilisés -> alerte un poil plus tôt (voulu pour un
/// garde-fou de pré-saturation). PURE (testable sans FS).
pub(crate) fn disk_used_pct(total_mb: u64, avail_mb: u64) -> Option<u8> {
    if total_mb == 0 {
        return None;
    }
    let used = total_mb.saturating_sub(avail_mb);
    Some((used.saturating_mul(100) / total_mb).min(100) as u8)
}

/// DÉCISION PURE : émettre l'alerte santé disque ? `threshold_pct==0` -> garde désactivé (jamais). Émet ssi
/// l'usage dépasse STRICTEMENT le seuil.
pub(crate) fn disk_health_should_warn(used_pct: u8, threshold_pct: u8) -> bool {
    threshold_pct != 0 && used_pct > threshold_pct
}

/// EFFET : si le volume de `path` est au-delà de `threshold_pct` %, émet UN event santé MANAGÉ (source=
/// plume-disk, category=health, sévérité 3, origin=daemon) RATE-LIMITÉ par dedup horaire (INSERT OR IGNORE
/// -> au plus 1 warn/heure tant que la condition dure). Renvoie true si un event a été écrit. Mesure
/// indisponible / seuil 0 -> no-op (fail-open). N'ALERTE JAMAIS deux fois la même heure (anti-spam).
pub(crate) fn emit_disk_health(conn: &Connection, path: &str, threshold_pct: u8, now_ts: i64) -> bool {
    let (total, avail) = match fs_total_avail_mb(path) {
        Some(x) => x,
        None => return false,
    };
    let pct = match disk_used_pct(total, avail) {
        Some(p) => p,
        None => return false,
    };
    if !disk_health_should_warn(pct, threshold_pct) {
        return false;
    }
    let bucket = now_ts / 3600; // dedup HORAIRE -> 1 warn/heure max (rate-limit anti-spam)
    let dedup = format!("plume-disk-warn-{bucket}");
    let msg = format!(
        "disque de données à {pct}% d'utilisation ({avail} Mo libres / {total} Mo) — pré-saturation (seuil >{threshold_pct}%)"
    );
    let fields = json!({
        "used_pct": pct, "free_mb": avail, "total_mb": total, "threshold_pct": threshold_pct, "path": path
    }).to_string();
    let n = store().insert_event(conn, &EventRow {
        ts: now_ts,
        source: "plume-disk".into(),
        category: "health".into(),
        severity: 3,
        message: msg,
        host: Some("plume-daemon".into()),
        src_ip: None, dst_ip: None, url: None,
        dedup: Some(dedup),
        fields: Some(fields),
        engagement_id: String::new(),
        origin: "daemon".into(),
        env_id: None,
    }).unwrap_or(0);
    n > 0
}
