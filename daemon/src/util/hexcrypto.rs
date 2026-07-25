//! Primitives hex + crypto pures (sha256/hmac/comparaison à temps constant), sans dépendance
//! sur AppState. Extrait de main.rs (refactor split #25 — byte-identique). Utilisé par
//! ledger, backup, session (form-login) et engagement.

/// HMAC-SHA256 (RFC 2104) sur sha2 — clé de longueur quelconque, sortie 32 octets.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let inner = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(msg);
        h.finalize()
    };
    let mut h = Sha256::new();
    h.update(opad);
    h.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Comparaison à temps constant (anti timing-oracle sur la vérif de signature / CSRF).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}
pub(crate) fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
