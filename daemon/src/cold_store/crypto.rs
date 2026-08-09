//! cold_store::crypto — CHIFFREMENT AT-REST DU TIER FROID (#18) : dérivation de clé AEAD + writer/reader age STREAM.
//!
//! CHIFFREMENT AT-REST (durcissement confidentialité #18) — le tier froid ÉGALE désormais le chiffrement
//! at-rest du hot (SQLCipher) : modèle de menace « NE PAS FAIRE CONFIANCE AU DISQUE ». Le jour-file N'est
//! JAMAIS écrit EN CLAIR. Pipeline d'écriture : `SerializedFileWriter` Parquet -> writer age STREAM (AEAD
//! ChaCha20-Poly1305 : nonce par-fichier ALÉATOIRE + compteur de chunk -> nonces AEAD uniques par chunk,
//! JAMAIS de réutilisation ; tag Poly1305 par chunk ; construction STREAM d'age, la MÊME que le backup
//! chiffré) -> fichier temp. À AUCUN instant le fichier temp ne contient d'octet Parquet en clair (seul
//! l'en-tête age — sans données — précède le flux chiffré).
//!
//! DOMAINE SÉPARÉ (HKDF) : la CLÉ cold est dérivée par HKDF-SHA256 (label de DOMAINE `plume-cold-aead-v1`) de
//! la clé SQLCipher du tenant (`PLUME_DB_KEY`), JAMAIS la clé brute ; AUCUN nouveau secret Vault. On NE réutilise
//! JAMAIS la clé SQLCipher brute pour l'AEAD cold. Cold ON EXIGE le chiffrement : si la clé est indisponible ->
//! FAIL-CLOSED (rien n'est agé, rien n'est écrit, rien n'est supprimé).
//!
//! LECTURE : déchiffrement STREAMÉ -> tampon `Bytes` EN MÉMOIRE (fichiers ~8 Mio -> borné/bon marché ; le lecteur
//! parquet exige un accès aléatoire au footer alors que le déchiffrement est séquentiel) -> décodage row-group par
//! row-group. JAMAIS de plaintext sur DISQUE.

use super::*;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use age::secrecy::SecretString;
use bytes::Bytes;
use parquet::file::reader::SerializedFileReader;

/// #28 P3.5 — COMPTEUR GLOBAL DE DÉCHIFFREMENTS COLD (observabilité + PREUVE d'élagage). `open_cold_reader` est
/// le POINT D'ENTRÉE UNIQUE de toute lecture cold (verify + décode) -> l'incrémenter ici capture CHAQUE
/// déchiffrement de fichier, quel que soit le chemin (oracle `hydrate_cold`/`decode_one_file` ou vectorisé
/// `open_verified`). La PREUVE d'élagage seal (P3.5) est directe : un fichier ÉLAGUÉ n'atteint jamais
/// `open_cold_reader` -> 0 incrément pour lui. Le harnais RESET puis lit ce compteur pour prouver que seuls les
/// fichiers SCANNÉS sont déchiffrés (le ×10-100 enterprise = ce compteur qui s'effondre N -> ~1 sur `source=rare`).
static COLD_DECRYPT_CALLS: AtomicU64 = AtomicU64::new(0);

/// Nombre cumulé d'appels `open_cold_reader` (= déchiffrements de fichiers cold). Consommé par le harnais de
/// preuve d'élagage (cfg(test)) et disponible pour l'observabilité future.
#[allow(dead_code)]
pub(super) fn cold_decrypt_count() -> u64 {
    COLD_DECRYPT_CALLS.load(Ordering::Relaxed)
}

/// RESET du compteur de déchiffrements (tests). Non utilisé en production.
#[allow(dead_code)]
pub(super) fn cold_decrypt_count_reset() {
    COLD_DECRYPT_CALLS.store(0, Ordering::Relaxed);
}

/// Label de DOMAINE (HKDF-SHA256 `info`) : sépare la clé cold de tout autre usage de la clé SQLCipher.
const COLD_AEAD_INFO: &[u8] = b"plume-cold-aead-v1";

/// Résout le SECRET DE BASE (la clé SQLCipher du tenant) dont on DÉRIVE la clé cold. Ordre (le plus SPÉCIFIQUE
/// d'abord) : (1) REGISTRE par-tenant (frontière crypto multi-tenant #2a-3 : entrée `Some(k)` = clé du tenant ;
/// `None` = tenant EN CLAIR -> pas de clé -> cold fail-closed) ; (2) `db_key_depuis(conf)` pour le tenant DÉFAUT
/// / mode 0. `None` -> l'appelant FAIL-CLOSE (cold ON EXIGE le chiffrement ; JAMAIS de cold en clair).
///
/// P8.7-b — IL N'Y A PLUS DE TROISIÈME BRANCHE, ET C'EST LE CORRECTIF. Il y en avait une :
/// `cfg(conf, "PLUME_DB_KEY", "")`, atteinte quand `db_key()` (qui ne lisait QUE l'environnement) rendait
/// `None`. C'est PAR ELLE que le tier froid chiffrait avec une clé écrite dans `soc.conf` pendant que la base
/// chaude, ouverte par `db_key()`, restait EN CLAIR. `db_key_depuis(conf)` FINIT par cette même lecture -> la
/// branche est devenue littéralement redondante et sa suppression rend la divergence IMPOSSIBLE À ÉCRIRE : les
/// deux moitiés du chiffrement at-rest ne dérivent plus de deux lectures, mais d'un seul appel sur le MÊME
/// `HashMap` que celui de l'ouverture. Les tests qui fournissent leur clé par une conf explicite passent par
/// exactement le même chemin (`cfg` env > conf), inchangés.
pub(super) fn cold_base_secret(conf: &HashMap<String, String>, db_path: &str) -> Option<String> {
    if let Some(entry) = db_key_registry().lock().get(db_path).cloned() {
        return entry; // tenant enregistré : Some(clé)=chiffré / None=en clair (-> cold fail-closed, pas de clé)
    }
    db_key_depuis(conf) // tenant défaut / mode 0 : fichier monté RO (fail-closed) -> env -> fichier de conf
}

/// Dérive la PASSPHRASE age du tier cold : HKDF-SHA256(ikm = clé SQLCipher, salt = ∅, info = `plume-cold-aead-v1`)
/// -> 32 octets, encodés base64 (matériel TEXTE pour le stanza scrypt d'age). DOMAINE SÉPARÉ : on NE réutilise
/// JAMAIS la clé SQLCipher brute pour l'AEAD cold. `None` si aucun secret de base -> l'appelant FAIL-CLOSE.
pub(super) fn cold_aead_passphrase(conf: &HashMap<String, String>, db_path: &str) -> Option<String> {
    let base = cold_base_secret(conf, db_path)?;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, base.as_bytes()); // salt ∅ : le domaine est porté par `info`
    let mut okm = [0u8; 32];
    // 32 octets (= 1 bloc SHA-256) << 255*32 -> `expand` ne peut PAS échouer ; `.ok()?` défensif.
    hk.expand(COLD_AEAD_INFO, &mut okm).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(okm))
}

/// Encryptor age (STREAM AEAD) pour la passphrase cold dérivée, à facteur scrypt FIXÉ (`COLD_SCRYPT_LOG_N`).
pub(super) fn cold_encryptor(pass: &str) -> Result<age::Encryptor, String> {
    let mut rcpt = age::scrypt::Recipient::new(SecretString::from(pass.to_owned()));
    rcpt.set_work_factor(COLD_SCRYPT_LOG_N);
    age::Encryptor::with_recipients(std::iter::once(&rcpt as &dyn age::Recipient)).map_err(pe)
}

/// DÉCHIFFRE EN FLUX un jour-file cold vers un tampon EN MÉMOIRE (`Bytes`) = les octets Parquet EN CLAIR. Le
/// lecteur parquet exige un accès ALÉATOIRE (footer en fin de fichier) alors que le déchiffrement age est
/// SÉQUENTIEL -> on matérialise le Parquet déchiffré dans un `Bytes` (fichiers ~8 Mio -> borné/bon marché) sur
/// lequel `SerializedFileReader` décode ensuite row-group par row-group. JAMAIS de plaintext écrit sur DISQUE.
/// Toute erreur (en-tête age, MAUVAISE clé, tag AEAD invalide / troncature -> corruption) REMONTE (jamais avalée).
///
/// KNOWN P2 (Finding C, DIFFÉRÉ) : ce `read_to_end` matérialise le jour ENTIER déchiffré en RAM (borné ~8 Mio en
/// P1, acceptable). Le lecteur de requête P2 devra déchiffrer en flux BORNÉ (streaming) plutôt que tout charger ;
/// ne PAS retravailler ce buffering ici (le P2 refactorise ce chemin de toute façon).
pub(super) fn cold_decrypt_to_bytes(path: &Path, pass: &str) -> Result<Bytes, String> {
    let f = File::open(path).map_err(|e| format!("ouverture cold {}: {e}", path.display()))?;
    let r = std::io::BufReader::new(f);
    let decryptor = age::Decryptor::new_buffered(r).map_err(|e| format!("en-tête age {}: {e}", path.display()))?;
    let mut id = age::scrypt::Identity::new(SecretString::from(pass.to_owned()));
    id.set_max_work_factor(COLD_SCRYPT_MAX_LOG_N);
    let mut reader = decryptor
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| format!("déchiffrement cold {} (mauvaise clé/corruption ?): {e}", path.display()))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf)
        .map_err(|e| format!("lecture flux déchiffré {} (tronqué / tag AEAD invalide ?): {e}", path.display()))?;
    Ok(Bytes::from(buf))
}

/// Ouvre un `SerializedFileReader` sur les octets Parquet DÉCHIFFRÉS d'un jour-file cold (déchiffre -> `Bytes`
/// -> reader parquet EN MÉMOIRE). Point d'entrée UNIQUE de TOUTE lecture cold (verify, round-trip, footer).
pub(super) fn open_cold_reader(path: &Path, pass: &str) -> Result<SerializedFileReader<Bytes>, String> {
    // #28 P3.5 — INSTRUMENTATION : chaque déchiffrement passe ICI (point d'entrée unique). Un fichier élagué par
    // le seal (min/max/bloom) n'atteint jamais ce point -> le compteur PROUVE l'évitement du déchiffrement.
    COLD_DECRYPT_CALLS.fetch_add(1, Ordering::Relaxed);
    let bytes = cold_decrypt_to_bytes(path, pass)?;
    SerializedFileReader::new(bytes).map_err(pe)
}
