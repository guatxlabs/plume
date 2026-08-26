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
//! la clé SQLCipher du tenant — CELLE QUI OUVRE LA BASE CHAUDE, quelle que soit sa provenance (`P8.7-c`) —,
//! JAMAIS la clé brute ; AUCUN nouveau secret Vault. On NE réutilise
//! JAMAIS la clé SQLCipher brute pour l'AEAD cold. Cold ON EXIGE le chiffrement : si la clé est indisponible ->
//! FAIL-CLOSED (rien n'est agé, rien n'est écrit, rien n'est supprimé) — et il DIT laquelle des provenances
//! il a essayées (`enonce_sans_cle`), un froid muet faisant croire à une rétention qu'on n'a pas.
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
pub(super) const COLD_AEAD_INFO: &[u8] = b"plume-cold-aead-v1";

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
///
/// `P8.7-c` — LA PROVENANCE EST **UNE**, ET C'EST LE MÊME `or_else` QUE `db_key()`. `P9.6-a` a donné une
/// TROISIÈME provenance à la clé d'ouverture — celle qu'une base NÉE chiffrée s'engendre à elle-même
/// (`cle_auto_chemin`) — et cette moitié-ci ne la lisait pas : une base née sous la clé auto avait sa moitié
/// chaude chiffrée et son tier froid FAIL-CLOSED. Ce n'était pas une régression (sans clé, le froid ne
/// s'écrivait déjà pas) mais l'ASYMÉTRIE de la famille `P8.7-b`, à l'envers. Le repli est écrit ici avec la
/// MÊME expression que dans `db_key()` : ce qui OUVRE la base et ce dont le froid DÉRIVE son AEAD ne
/// peuvent plus répondre différemment.
///
/// CE QUI NE CHANGE POUR AUCUNE BASE EXISTANTE, et c'est le témoin qui compte (comme pour `P9.6-a`) : le
/// repli n'est ÉVALUÉ que lorsque la clé explicite est absente, et il ne lit qu'un fichier que le démon
/// n'écrit QUE sur une base NEUVE. Sur toute base antérieure — chiffrée par clé explicite (le repli n'est
/// jamais atteint) comme restée en clair (le fichier n'existe pas) — le secret rendu est le MÊME qu'avant,
/// donc les jours-files déjà écrits restent déchiffrables et le fail-closed reste fail-closed.
pub(super) fn cold_base_secret(conf: &HashMap<String, String>, db_path: &str) -> Option<String> {
    if let Some(entry) = db_key_registry().lock().get(db_path).cloned() {
        return entry; // tenant enregistré : Some(clé)=chiffré / None=en clair (-> cold fail-closed, pas de clé)
    }
    // tenant défaut / mode 0 : fichier monté RO (fail-closed) -> env -> fichier de conf -> clé auto-engendrée.
    db_key_depuis(conf).or_else(|| cle_auto_lire(&cle_auto_chemin(conf)))
}

/// `P8.7-c` — CE QU'UN TIER FROID QUI REFUSE D'ÉCRIRE DIT DE LUI-MÊME. Un froid inerte et muet fait croire
/// à une rétention longue qu'on n'a pas ; « PLUME_DB_KEY indisponible » — le seul mot qu'il disait — nomme
/// UNE provenance sur trois et se trompe carrément quand la cause est un tenant enregistré EN CLAIR.
///
/// LES DEUX CAUSES SONT DEUX FAITS, PAS UN SEUL : un tenant dont la base chaude n'est pas chiffrée ne PEUT
/// pas voir son froid chiffré (ce serait la divergence `P8.7-b`, à l'envers), alors qu'un déploiement sans
/// aucune clé attend seulement qu'on lui en donne une. Les confondre a un coût : le premier n'a rien à
/// corriger, le second si.
///
/// LA LISTE DES PROVENANCES EST **DÉRIVÉE** de `CLES_AT_REST` — la table de précédence que la voie
/// d'ouverture parcourt — et du chemin de clé auto RÉSOLU pour cette configuration. Elle ne peut donc pas
/// se désaccorder de ce que `cold_base_secret` vient réellement d'essayer : une quatrième provenance
/// ajoutée à la table entre dans la phrase sans que personne n'y touche.
pub(super) fn enonce_sans_cle(conf: &HashMap<String, String>, db_path: &str) -> String {
    if db_key_registry().lock().get(db_path).map(|e| e.is_none()).unwrap_or(false) {
        return format!(
            "le tenant `{db_path}` est ENREGISTRÉ EN CLAIR : sa base chaude n'est pas chiffrée, et \
             chiffrer son tier froid avec la clé d'un autre remettrait les deux moitiés en désaccord. \
             Il n'y a RIEN à corriger ici : chiffrer ce tenant est le geste qui débloque son froid"
        );
    }
    format!(
        "aucune provenance ne rend de clé — ni {} (fournies au déploiement), ni `{}` (clé qu'une base \
         NÉE chiffrée s'engendre). Le tier froid dérive son secret de la MÊME provenance que l'ouverture \
         de la base chaude : sans clé chaude, aucun jour-file ne peut être écrit",
        CLES_AT_REST.map(|c| format!("`{c}`")).join(" / "),
        cle_auto_chemin(conf)
    )
}

/// Dérive la PASSPHRASE age du tier cold : HKDF-SHA256(ikm = clé SQLCipher, salt = ∅, info = `plume-cold-aead-v1`)
/// -> 32 octets, encodés base64 (matériel TEXTE pour le stanza scrypt d'age). DOMAINE SÉPARÉ : on NE réutilise
/// JAMAIS la clé SQLCipher brute pour l'AEAD cold. `None` si aucun secret de base -> l'appelant FAIL-CLOSE.
pub(super) fn cold_aead_passphrase(conf: &HashMap<String, String>, db_path: &str) -> Option<String> {
    let base = cold_base_secret(conf, db_path)?;
    // `sha2_v11` = `sha2` 0.11 (SHA-256 de la génération `digest` 0.11), et NON le `sha2` 0.10 direct de la
    // crate : `hkdf` 0.13 exige `H: digest 0.11::EagerHash`. MÊME algorithme, MÊME sortie — HKDF-SHA256 est
    // RFC 5869 des deux côtés, et `cold_hkdf_derivation_gelee_rfc5869` gèle l'octet.
    let hk = hkdf::Hkdf::<sha2_v11::Sha256>::new(None, base.as_bytes()); // salt ∅ : domaine porté par `info`
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
