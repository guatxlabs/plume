use super::*;

// ===================== TOTP (RFC 6238, HMAC-SHA1) =====================

/// HMAC-SHA1 (RFC 2104) — l'algo par défaut des applis TOTP (Google Authenticator/Authy). SHA-1 est
/// standard et sûr pour ce HMAC (RFC 6238) ; pas de crypto « maison » (primitive RustCrypto `sha1`).
fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        let d = Sha1::digest(key);
        block[..20].copy_from_slice(&d);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let inner = { let mut h = Sha1::new(); h.update(ipad); h.update(msg); h.finalize() };
    let mut h = Sha1::new();
    h.update(opad);
    h.update(inner);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    out
}

/// Base32 RFC 4648 (alphabet A-Z2-7), sans padding, insensible à la casse/espaces. `encode` pour publier la
/// graine (URI otpauth) ; `decode` pour la vérif. Retourne None sur caractère invalide (fail-closed).
pub(crate) fn base32_encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        if c == '=' || c == ' ' || c == '-' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            'A'..='Z' => c.to_ascii_uppercase() as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Code TOTP à un compteur donné (HOTP RFC 4226 : troncature dynamique sur HMAC(secret, counter_be)).
pub(crate) fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let off = (mac[19] & 0x0f) as usize;
    let bin = ((mac[off] as u32 & 0x7f) << 24)
        | ((mac[off + 1] as u32) << 16)
        | ((mac[off + 2] as u32) << 8)
        | (mac[off + 3] as u32);
    let modulo = 10u32.pow(digits);
    format!("{:0width$}", bin % modulo, width = digits as usize)
}

/// Vérifie un code TOTP (RFC 6238) et RENVOIE le compteur (pas) qui matche, dans [now-skew .. now+skew]
/// (absorption de la dérive d'horloge). None = aucun pas ne matche. Le pas retourné permet à l'appelant
/// l'ANTI-REJEU (persister `last_step` et refuser un code de pas <= last_step). Parcourt TOUTE la fenêtre
/// SANS court-circuit (pas de timing par offset) ; comparaison à temps constant.
pub(crate) fn totp_verify_step(secret_b32: &str, code: &str, time: i64, step: i64, digits: u32, skew: i64) -> Option<i64> {
    let code = code.trim();
    if code.is_empty() || code.len() != digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secret = base32_decode(secret_b32)?;
    if secret.is_empty() {
        return None;
    }
    let step = step.max(1);
    let base = time / step;
    let mut matched: Option<i64> = None;
    for d in -skew..=skew {
        let ctr = (base + d).max(0);
        let cand = hotp(&secret, ctr as u64, digits);
        // temps constant + on parcourt TOUTE la fenêtre : on retient le pas matché (au plus un en pratique).
        if ct_eq(cand.as_bytes(), code.as_bytes()) {
            matched = Some(ctr);
        }
    }
    matched
}

/// Vérifie un code TOTP (booléen). Wrapper de `totp_verify_step` (sans anti-rejeu ; pour les chemins qui
/// n'ont pas d'état persistant, ex. la désactivation qui supprime la ligne de toute façon).
pub(crate) fn totp_verify(secret_b32: &str, code: &str, time: i64, step: i64, digits: u32, skew: i64) -> bool {
    totp_verify_step(secret_b32, code, time, step, digits, skew).is_some()
}

/// URI otpauth:// standard (à encoder en QR côté client). Le secret base32 y figure (c'est sa raison d'être :
/// l'enrôlement). Ne JAMAIS logger/persister cet URI ailleurs que dans la réponse d'enrôlement show-once.
pub(crate) fn totp_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        url_encode(issuer), url_encode(account), secret_b32, url_encode(issuer),
    )
}

/// Génère un lot de codes de secours (usage unique) + leurs SHA-256 (à persister ; les codes CLAIRS ne
/// sont montrés qu'une fois). Format lisible `xxxx-xxxx` (10 hex). None si entropie indisponible.
pub(crate) fn gen_recovery_codes(n: usize) -> Option<(Vec<String>, Vec<String>)> {
    let mut clear = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for _ in 0..n {
        let b = rand_bytes(5)?;
        let hexs = hex_encode(&b); // 10 hex chars
        let code = format!("{}-{}", &hexs[..4], &hexs[4..]);
        hashes.push(sha256_hex(code.as_bytes()));
        clear.push(code);
    }
    Some((clear, hashes))
}
