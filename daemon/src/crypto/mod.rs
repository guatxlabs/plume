//! Crypto/clés : ouverture SQLCipher (db_key/open_db/ensure_encrypted), registre de clés par base
//! (DB_KEY_REGISTRY) et résolution de clé Vault (VAULT_KEY_CACHE, resolve/fetch, racines TLS).
//! Dépend de util::http_client (http_get) — appel résolu via glob re-export. Extrait de main.rs
//! (refactor split #25 — byte-identique).
use crate::*;

/// Connexion **read-only** + vérif `stmt.readonly()` (double garde-fou) + budget temps
/// (interruption ~3s, anti-requête-folle) + plafond de lignes. Renvoie colonnes/lignes + coût.
/// Chiffrement at-rest SQLCipher (OPT-IN) : si `PLUME_DB_KEY` est défini, la base est ouverte/chiffrée
/// avec cette clé (`PRAGMA key`, qui DOIT précéder toute requête). Vide/absent -> base en clair
/// (rétrocompat total). La clé vient typiquement de Vault -> ExternalSecret -> env PLUME_DB_KEY.
pub(crate) fn db_key() -> Option<String> {
    db_key_depuis(&load_config())
}

// ================================================================================================
// P8.7-b — LA CLÉ SQLCIPHER SE LIT PAR UNE SEULE VOIE
// ------------------------------------------------------------------------------------------------
// CE QUI ÉTAIT CASSÉ, ET CE QUE ÇA COÛTAIT. `PLUME_DB_KEY` était la SEULE clé lue par les DEUX voies
// de configuration du démon, et elles ne s'accordaient pas : `db_key()` — celle qui OUVRE la base
// chaude — la lisait dans l'environnement SEUL, tandis que `cold_store::crypto` la lisait par
// `cfg()`, donc AUSSI dans `/etc/plume/soc.conf`. Or `systemd/plume-daemon.service` ne porte AUCUN
// `EnvironmentFile` (délibérément : il exporterait `PLUME_PASS_HASH`/`PLUME_DB_KEY` dans
// `/proc/<pid>/environ`) et pose `PLUME_CONFIG=/etc/plume/soc.conf` : sur un hôte, le fichier 0640
// est LE bon endroit pour cette clé, et c'est le seul endroit où elle n'agissait pas.
//
// LE CAS QUE ÇA FABRIQUAIT, REPRODUIT PAR EXÉCUTION LE 2026-08-09 (binaire `38a23da`, `--features
// cold_tier`, environnement VIDE hormis `PLUME_CONFIG`) : `soc.conf` portant `PLUME_DB_KEY` +
// `PLUME_COLD_TIER=1` -> le jour-file froid `cold/prod/2026-07-30-0000.parquet` commence par
// `age-encryption.org/v1` (CHIFFRÉ ; déchiffré hors-processus avec HKDF(clé de soc.conf) -> `PAR1`),
// pendant que `db/plume.db` commence par `53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00`
// (`SQLite format 3\0`, EN CLAIR : `sqlite3` nu y relit les messages d'événement). Le processus n'a
// dit qu'une chose de tout ça : « rétention OK ». La moitié FROIDE était chiffrée, la moitié CHAUDE
// — les 7 derniers jours, donc les incidents récents — ne l'était pas, sans un mot.
//
// L'ARBITRAGE : `cfg()`, comme P8.7-a, PAS une garde. Une garde qui refuse aurait NOMMÉ le silence
// sans donner à l'opérateur d'hôte ce qu'il demandait ; `cfg()` interroge l'environnement AVANT le
// fichier -> c'est un SUR-ENSEMBLE STRICT (Docker/k3s posent `PLUME_CONFIG=/nonexistent` et tout en
// `env:` : la carte de fichier est VIDE, le résultat est inchangé par construction — MESURÉ, cf.
// `tests/cle_at_rest_voie_unique.rs`). Et la prémisse qui avait fait écarter ce lot — « `db_key()` est
// appelée sans configuration en main, avant le chargement » — est FAUSSE : il n'existe aucune phase
// de chargement dans ce démon. `load_config()` est une fonction PURE (lit `PLUME_CONFIG`, lit un
// fichier, rend une `HashMap`) appelée à la demande une trentaine de fois dans l'arbre, dès la
// PREMIÈRE ligne de `main()`. Il n'y a donc aucun ordre d'initialisation à changer.
//
// LE FAIL-CLOSED N'EST PAS TOUCHÉ : la branche `PLUME_DB_KEY_FILE` reste PREMIÈRE et garde son
// `exit(78)`. Elle passe elle aussi par `cfg()` — sinon on aurait déplacé le même défaut d'un cran
// (un `PLUME_DB_KEY_FILE` écrit dans `soc.conf` aurait été ignoré, et avec lui le fail-closed censé
// l'attraper : exactement la faute que `38a23da` vient de corriger pour l'escrow de sauvegarde).
//
// RELU À CHAQUE APPEL (pas de `OnceLock`) : `db_key()` est appelée à l'OUVERTURE d'une connexion,
// pas par ligne ni par requête (le read-pool plafonne à `READ_POOL_CAP` = 8 handles réutilisés) ->
// une lecture de fichier par ouverture, comme `reglage_sauvegarde()` en fait une par sauvegarde.
// ================================================================================================

/// Les deux noms de ce lot, écrits UNE fois : ils alimentent le LECTEUR et l'ANNONCE de bascule, qui
/// ne peuvent donc pas diverger. L'ordre du tableau est l'ordre de PRÉCÉDENCE (le fichier de clé
/// monté RO gagne sur la passphrase).
pub(crate) const CLE_DB_KEY_FILE: &str = "PLUME_DB_KEY_FILE";
pub(crate) const CLE_DB_KEY: &str = "PLUME_DB_KEY";
pub(crate) const CLES_AT_REST: [&str; 2] = [CLE_DB_KEY_FILE, CLE_DB_KEY];

/// LA voie unique de résolution de la clé SQLCipher, `env > fichier PLUME_CONFIG > aucune clé`.
///
/// F1 — PRIORITÉ au FICHIER monté RO (`PLUME_DB_KEY_FILE`), modèle de `ledger.key` : la clé SQLCipher
/// (crown-jewel) ne transite pas par /proc/1/environ (lisible via `kubectl exec`, ps e, crash-dump,
/// héritage enfant). FAIL-CLOSED : si `PLUME_DB_KEY_FILE` est posé mais que le fichier est absent/
/// illisible/vide -> on REFUSE de démarrer plutôt que de retomber EN SILENCE sur la passphrase (qui
/// pourrait être absente -> base ouverte/écrite EN CLAIR = corruption/perte). Non posé -> repli sur
/// `PLUME_DB_KEY`. Vide/absent partout -> `None` (base en clair, rétrocompat).
///
/// `conf` EXPLICITE : les appelants qui tiennent déjà la configuration (démarrage, rétention, tier
/// froid) passent LA LEUR — la clé qui ouvre la base et celle dont le tier froid dérive son AEAD
/// viennent alors littéralement du même `HashMap`, plus seulement du même fichier.
pub(crate) fn db_key_depuis(conf: &HashMap<String, String>) -> Option<String> {
    let chemin = cfg(conf, CLE_DB_KEY_FILE, "");
    if !chemin.is_empty() {
        match db_key_from_file(&chemin) {
            Ok(k) => return Some(k),
            Err(e) => {
                eprintln!("[FATAL] {e} — refus de démarrer (fail-closed ; ne retombe PAS sur PLUME_DB_KEY)");
                std::process::exit(78); // EX_CONFIG
            }
        }
    }
    let k = cfg(conf, CLE_DB_KEY, "");
    if k.is_empty() { None } else { Some(k) }
}

/// PURE — LA BASCULE : le nom de la clé at-rest qui devient EFFECTIVE à ce démarrage, c'est-à-dire
/// celle qui gagne la précédence APRÈS P8.7-b alors que la lecture d'AVANT (environnement SEUL) en
/// aurait pris une autre (ou aucune). `None` = rien ne change pour cet hôte -> AUCUN bruit (c'est le
/// cas de Docker et de k3s, où tout arrive par `env:` : mesuré, 0 annonce).
///
/// Les deux clés sont évaluées dans l'ORDRE DE PRÉCÉDENCE, sur les DEUX lectures : un
/// `PLUME_DB_KEY_FILE` écrit dans le fichier prend le pas sur un `PLUME_DB_KEY` posé dans
/// l'environnement, et ce changement-là doit être annoncé aussi (il change la clé, pas seulement sa
/// provenance).
pub(crate) fn bascule_at_rest(
    fichier: &HashMap<String, String>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<&'static str> {
    let gagnante = |lire: &dyn Fn(&'static str) -> String| -> Option<&'static str> {
        CLES_AT_REST.into_iter().find(|c| !lire(c).is_empty())
    };
    // AVANT : l'environnement SEUL (le fichier était invisible pour ces deux clés).
    let avant = gagnante(&|c| env(c).unwrap_or_default());
    // APRÈS : `cfg()` — env PRÉSENT (même vide) gagne, sinon le fichier. Miroir exact de `cfg`.
    let apres = gagnante(&|c| env(c).unwrap_or_else(|| fichier.get(c).cloned().unwrap_or_default()));
    if avant == apres { None } else { apres }
}

/// PURE — LE MESSAGE DE BASCULE. Il doit dire trois choses qu'un opérateur ne peut pas deviner : que
/// sa clé était ignorée par la voie qui ouvre la base, ce qui va arriver à la base EXISTANTE (le
/// verdict de `probe_db`, calculé AVANT toute écriture), et comment revenir en arrière. Ne
/// journalise JAMAIS de valeur — seulement le NOM de la clé.
pub(crate) fn annonce_bascule_at_rest(cle: Option<&str>, verdict: DbProbe) -> Option<String> {
    let cle = cle?;
    let effet = match verdict {
        DbProbe::Plaintext =>
            "la base EXISTANTE est EN CLAIR sur le disque : elle va être RÉÉCRITE chiffrée maintenant \
             (copie de sécurité, export SQLCipher, échange atomique, puis effacement de la copie en \
             clair). Prévoyez ~2× sa taille en espace libre et la durée d'une réécriture complète.",
        DbProbe::WrongKeyOrCorrupt =>
            "la base EXISTANTE ne s'ouvre PAS avec cette clé : le démarrage va être REFUSÉ \
             (fail-closed, exit 78) et la base ne sera PAS modifiée. Posez la clé qui l'a chiffrée.",
        DbProbe::Fresh =>
            "aucune base existante (absente ou vide) : elle sera créée chiffrée d'office.",
        DbProbe::OpensWithKey =>
            "la base EXISTANTE s'ouvre déjà avec cette clé : rien à réécrire.",
        DbProbe::Locked =>
            "la base est VERROUILLÉE (SQLITE_BUSY) : son état n'a pas pu être classé maintenant ; la \
             réécriture éventuelle sera retentée.",
        DbProbe::Unopenable =>
            "la base est présente mais non ouvrable (I/O ou permission) : elle ne sera PAS touchée.",
    };
    Some(format!(
        "[sqlcipher] CHANGEMENT DE COMPORTEMENT (P8.7-b) : {cle}, écrite dans votre fichier de \
         configuration, était jusqu'ici IGNORÉE par la voie qui OUVRE la base — la base CHAUDE \
         restait donc EN CLAIR sur le disque (et si le tier froid était actif, LUI chiffrait ses \
         jours-files avec CETTE clé : une moitié protégée, l'autre non). À partir de ce démarrage \
         elle suit la MÊME précédence que tous les autres réglages (env > fichier PLUME_CONFIG) et \
         couvre les DEUX moitiés.\n  - {effet}\n  \
         Aucune valeur n'est journalisée. Les sous-commandes (backup, retention, db-stats) exigent \
         désormais cette clé elles aussi. Pour revenir au comportement précédent, retirez {cle} du \
         fichier — mais si la base a déjà été réécrite chiffrée, elle deviendrait ILLISIBLE : \
         restaurez-la d'abord."
    ))
}

/// L'ADAPTATEUR : confronte le fichier RÉEL à l'environnement RÉEL et journalise l'annonce si quelque
/// chose change pour cet hôte. Appelé au démarrage du démon, AVANT `ensure_encrypted` — c'est-à-dire
/// avant la réécriture qu'il annonce. Silencieux quand rien ne change.
pub(crate) fn annoncer_bascule_at_rest(conf: &HashMap<String, String>, db_path: &str) {
    let Some(cle) = bascule_at_rest(conf, |c| std::env::var(c).ok()) else { return };
    // Le verdict est calculé avec la clé EFFECTIVE (celle que `db_key_depuis` vient de rendre).
    // `None` est inatteignable ici (une bascule implique une clé non vide) ; `Fresh` est le repli
    // le plus neutre si elle survenait quand même.
    let verdict = match db_key_depuis(conf) {
        Some(k) => probe_db(db_path, &k),
        None => DbProbe::Fresh,
    };
    if let Some(msg) = annonce_bascule_at_rest(Some(cle), verdict) {
        eprintln!("{msg}");
    }
}

/// Lecture PURE et TESTABLE de la clé SQLCipher depuis un FICHIER (secret mount RO). `Err` (FATAL, à
/// traiter fail-closed) si absent/illisible/non-UTF8/VIDE (0 octet).
///
/// LECTURE **VERBATIM, AUCUN strip** : le MÊME secret alimente et l'ancien env `PLUME_DB_KEY` (via
/// `env::var`, qui ne retire RIEN) et ce fichier (projection du secret par le volume, byte-pour-byte
/// identique — un montage de secret n'ajoute AUCUN newline). Retirer un `\n` final
/// ici FABRIQUERAIT une divergence : si la valeur du Secret se terminait par `\n`, l'ancien chemin env
/// l'incluait dans la clé SQLCipher (la base a été chiffrée AVEC), le nouveau chemin fichier le retirerait ->
/// clé DIFFÉRENTE au cutover -> base illisible (outage évitable). On lit donc les octets TELS QUELS ->
/// `file == env` inconditionnellement (par construction), la classe ENTIÈRE de divergence disparaît et le
/// préflight devient trivial (les deux sont identiques). Aucune raison légitime de stripper ne subsiste :
/// la convention `echo`/éditeur (fichier édité à la main) ne s'applique pas ici — le fichier N'EST PAS édité,
/// c'est la projection brute du même Secret. Seules validations : non-UTF8 -> Err, 0 octet -> Err (fail-closed),
/// exactement comme `env::var(..).filter(|k| !k.is_empty())` rejette la chaîne vide "".
pub(crate) fn db_key_from_file(path: &str) -> Result<String, String> {
    // PHASE 2 — DÉLÉGUÉ à `guatx_core::secret::FileProvider` (octets DÉPLACÉS, byte-identiques). Politique
    // STRICTE fail-closed : `NotFound` (absent OU vide) et `Unreadable`/`Malformed` -> `Err` (db_key()
    // exit 78). VERBATIM conservé (file == env au cutover -> SQLCipher décrypte avec la MÊME clé). On
    // reconstruit le préfixe `PLUME_DB_KEY_FILE={path}` des messages historiques (non-secret, cosmétique).
    use guatx_core::secret::{SecretError, SecretOutcome, SecretProvider, SecretRef};
    match guatx_core::secret::FileProvider.get(&SecretRef::file(path)) {
        Ok(SecretOutcome::Present(v)) => Ok(v.into_string()), // VERBATIM
        Ok(SecretOutcome::NotFound) => Err(format!("PLUME_DB_KEY_FILE={path} absent ou vide")),
        Err(SecretError::Unreadable(e)) => Err(format!("PLUME_DB_KEY_FILE={path} illisible ({e})")),
        Err(SecretError::Malformed(_)) => Err(format!("PLUME_DB_KEY_FILE={path} : contenu non-UTF8")),
        Err(SecretError::Backend(e)) => Err(e), // inatteignable pour file:
    }
}
/// Applique la clé SQLCipher à une connexion fraîchement ouverte (no-op si pas de clé / SQLite simple).
pub(crate) fn apply_key(conn: &Connection) {
    if let Some(k) = db_key() {
        // (v108) busy_timeout AVANT `PRAGMA key` : un verrou RESIDUEL (sidecar backup) fait ATTENDRE
        // (<=5s) au lieu d'un PRAGMA key qui echoue instantanement puis est avale. Chemin CLE uniquement
        // (dans le `if let Some(k) = db_key()`) -> le cas EN CLAIR (db_key()=None) n'est PAS touche.
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let _ = conn.execute_batch(&format!("PRAGMA key = '{}';", k.replace('\'', "''")));
    }
}
// L'ouverture NUE (ex-`open_db`) a DÉMÉNAGÉ dans `db_open` : c'est le seul module qui peut encore
// nommer `Connection::open`, et il n'en rend que deux choses — un `PreparedDb` (contrat de schéma
// appliqué) ou une ouverture au nom explicite `open_db_*_without_schema_contract`. `apply_key` reste
// ici : elle sert aussi aux connexions LECTURE SEULE (ledger), qui n'ont pas de contrat à satisfaire.
/// Migration de chiffrement (idempotente, NON destructive) : si `PLUME_DB_KEY` est posé MAIS que la base
/// existante est EN CLAIR, on la sauvegarde (`.plaintext.bak`) puis on la chiffre (sqlcipher_export) —
/// une seule fois. Ne touche RIEN si pas de clé, base déjà chiffrée, ou base illisible.
/// Efface un fichier « best-effort » : écrase son contenu (zéros) puis le supprime, pour qu'une
/// copie EN CLAIR de la base ne subsiste pas en clair sur le volume /data (récupérable). Le shred parfait est
/// impossible sur SSD/COW (wear-leveling) mais l'écrasement + unlink retire la copie logique et couvre le cas
/// disque magnétique/ext4. Toute erreur est avalée (au pire il reste `remove_file`).
pub(crate) fn shred_file(p: &str) {
    use std::io::Write;
    if let Ok(meta) = std::fs::metadata(p) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
            let zeros = [0u8; 64 * 1024];
            let mut left = meta.len();
            while left > 0 {
                let n = (left.min(zeros.len() as u64)) as usize;
                if f.write_all(&zeros[..n]).is_err() { break; }
                left -= n as u64;
            }
            let _ = f.flush();
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(p);
}

/// SELF-CHECK boot — verdict de la CLASSIFICATION NON destructive d'un fichier DB
/// vis-à-vis d'une clé SQLCipher. Distingue explicitement « base neuve/vide » (SQLCipher la créera) de « base
/// chiffrée existante, MAUVAISE clé » : ce dernier cas doit fail-CLOSE au boot (clair) au lieu de laisser
/// l'échec surgir à une requête ultérieure aléatoire. Reproduit la logique keyed-open/keyless-open que
/// `ensure_encrypted` faisait déjà en ligne (aucune écriture, aucune mutation du fichier).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum DbProbe {
    /// Fichier absent ou VIDE (0 octet) : SQLCipher le créera chiffré d'office — rien à faire, PAS d'erreur.
    /// (Une base neuve s'ouvre avec N'IMPORTE quelle clé — d'où la nécessité de ce cas pour éviter tout
    /// faux positif WrongKey au premier boot / à l'install fraîche.)
    Fresh,
    /// Lisible AVEC la clé (sqlite_master lu) : base déjà chiffrée, clé CORRECTE -> rien à faire.
    OpensWithKey,
    /// Lisible SANS clé : base EN CLAIR -> migration de chiffrement.
    Plaintext,
    /// Fichier NON VIDE, illisible AVEC la clé ET illisible SANS -> MAUVAISE clé ou corruption : FAIL-CLOSED.
    WrongKeyOrCorrupt,
    /// Fichier présent mais non ouvrable du tout (I/O/permission) : on NE touche pas (comportement historique).
    Unopenable,
    /// (v108 follow-up) Sonde entravée par un VERROU SQLite (`SQLITE_BUSY`/`SQLITE_LOCKED`) — p.ex. le sidecar
    /// backup tenant un write-lock au-delà du `busy_timeout` pendant un chevauchement de boot. Un verrou est
    /// TRANSITOIRE : on ne peut RIEN conclure sur la clé tant qu'il tient. Distinct de `WrongKeyOrCorrupt` pour
    /// que `ensure_encrypted` réessaie (backoff borné) au lieu d'un faux `exit(78)` -> faux crashloop.
    Locked,
}

/// (v108) L'erreur rusqlite dénote-t-elle un VERROU (contention transitoire) et non un échec de clé/corruption ?
/// On matche le CODE ffi (`DatabaseBusy`/`DatabaseLocked`), pas une chaîne. Une mauvaise clé remonte
/// `SQLITE_NOTADB` (« file is not a database ») -> PAS un verrou -> reste `WrongKeyOrCorrupt` -> exit(78).
fn is_lock_err(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

/// F1a — classe `path` vis-à-vis de `key`, SANS jamais modifier le fichier (aucune écriture). Voir `DbProbe`.
/// `busy_timeout` modeste sur les deux ouvertures : une contention de verrou transitoire (sidecar backup en
/// vol) ATTEND au lieu d'être prise à tort pour une corruption -> pas de faux `WrongKeyOrCorrupt` sur un lock.
pub(crate) fn probe_db(path: &str, key: &str) -> DbProbe {
    probe_db_with_busy(path, key, std::time::Duration::from_secs(5))
}

/// (v108) Cœur testable de `probe_db` avec `busy` paramétrable. `busy=0` -> `SQLITE_BUSY` IMMÉDIAT si un verrou
/// tient (tests déterministes, sans attente). En prod `probe_db` fixe 5 s. On CLASSE les erreurs de lecture :
/// un verrou (`SQLITE_BUSY`/`SQLITE_LOCKED`) sur l'une OU l'autre ouverture -> `Locked` (transitoire, on ne peut
/// PAS conclure sur la clé) ; sinon (p.ex. `SQLITE_NOTADB`) -> `WrongKeyOrCorrupt`. Ainsi une MAUVAISE clé sur
/// une base NON verrouillée reste fail-closed (exit 78), et un verrou ne déclenche PAS de faux fail-closed.
pub(crate) fn probe_db_with_busy(path: &str, key: &str, busy: std::time::Duration) -> DbProbe {
    // FRESH = fichier absent OU 0 octet. Une base 0-octet est « neuve » : s'ouvre avec toute clé (SQLCipher la
    // matérialise au 1er write) -> ne JAMAIS la classer WrongKey (pas de faux positif install/premier boot).
    let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if len == 0 { return DbProbe::Fresh; }
    let kesc = key.replace('\'', "''");
    // Un verrou vu sur N'IMPORTE laquelle des deux ouvertures rend le verdict clé/corruption INDÉCIDABLE :
    // on remonte `Locked` (l'appelant réessaiera) plutôt qu'un faux `WrongKeyOrCorrupt`.
    let mut saw_lock = false;
    // 1) lisible AVEC la clé ? (base déjà chiffrée, BONNE clé)
    // SANS CONTRAT, et c'est le point : cette sonde CLASSE un fichier (chiffré / en clair / illisible)
    // AVANT que la notion de schéma existe. Lui demander le contrat serait circulaire.
    if let Ok(c) = open_db_keyed_without_schema_contract(path, None) {
        let _ = c.busy_timeout(busy);
        let _ = c.execute_batch(&format!("PRAGMA key = '{}';", kesc));
        match c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
            Ok(_) => return DbProbe::OpensWithKey,
            Err(e) if is_lock_err(&e) => saw_lock = true, // verrou -> pas une preuve de mauvaise clé
            Err(_) => {}                                  // NOTADB/HMAC/... -> possible mauvaise clé (cf. étape 2/3)
        }
    }
    // 2) lisible SANS clé ? (base EN CLAIR -> à migrer). Ouverture impossible -> on NE touche pas.
    let plain = match open_db_keyed_without_schema_contract(path, None) { Ok(c) => c, Err(_) => return DbProbe::Unopenable };
    let _ = plain.busy_timeout(busy);
    match plain.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
        Ok(_) => return DbProbe::Plaintext,
        Err(e) if is_lock_err(&e) => saw_lock = true,
        Err(_) => {}
    }
    // 3) Un verrou a masqué au moins une lecture -> INDÉCIDABLE, transitoire : `Locked` (retry côté appelant),
    //    JAMAIS `WrongKeyOrCorrupt`. Sans verrou : non vide, ni déchiffrable par la clé, ni en clair -> mauvaise
    //    clé / corruption (fail-closed conservé).
    if saw_lock { return DbProbe::Locked; }
    DbProbe::WrongKeyOrCorrupt
}

/// P8.7-b — `conf` EXPLICITE. L'appelant unique (`open_and_migrate_db`) tient déjà la configuration :
/// la lui prendre supprime une lecture AMBIANTE sur le chemin qui DÉCIDE du chiffrement at-rest, et
/// rend la fonction mesurable sans toucher à `PLUME_CONFIG` — donc testable en parallèle. (Ce n'est
/// pas cosmétique : la première version de ce lot testait via `PLUME_CONFIG`, et la suite complète a
/// rendu ROUGE deux tests d'incidents sans rapport — un `PRAGMA key` appliqué à leur base en clair
/// par un `db_key()` qui voyait la configuration d'un test voisin. La mesure a nommé le défaut de
/// conception : un chemin qui décide du chiffrement ne doit pas lire un état global du processus
/// quand son appelant tient déjà la valeur.)
pub(crate) fn ensure_encrypted(conf: &HashMap<String, String>, path: &str) {
    let key = match db_key_depuis(conf) { Some(k) => k, None => return };
    if !std::path::Path::new(path).exists() { return; }              // base neuve -> créée chiffrée d'office
    let bak = format!("{path}.plaintext.bak");
    // BALAYAGE au démarrage — un `.plaintext.bak` résiduel (run précédent interrompu APRÈS le swap
    // mais AVANT le nettoyage) est une copie EN CLAIR persistante -> on l'efface d'emblée. Sûr : la base
    // chiffrée est déjà en place (sinon on retomberait dans le chemin d'export ci-dessous qui recrée un bak).
    if std::path::Path::new(&bak).exists() { shred_file(&bak); }
    // F1a — SELF-CHECK au boot : classer la base AVANT toute écriture. Une clé PRÉSENTE mais FAUSSE sur une
    // base NON VIDE fail-CLOSE ici (exit 78), au lieu du `return` silencieux historique (qui laissait open_db()
    // « réussir » puis une requête ultérieure planter à un endroit aléatoire) -> même signal PROPRE qu'un
    // fichier de clé absent (fail-closed de db_key()). Rollback = revert du manifeste (env restauré).
    // (v108 follow-up) Un VERROU transitoire (sidecar backup tenant un write-lock au-delà du busy_timeout pendant
    // un chevauchement de boot) NE DOIT PAS être pris pour une clé fausse -> re-sonde avec BACKOFF BORNÉ. Si le
    // verrou persiste, on PROCÈDE (return) : `open_db()` gérera la contention avec son propre busy_timeout ; un
    // verrou N'EST PAS une condition fail-closed (contrairement à une mauvaise clé). Bornage strict = pas de
    // boucle infinie sur un verrou coincé. AUCUNE modification du fichier dans tout ce chemin.
    let mut verdict = probe_db(path, &key);
    if verdict == DbProbe::Locked {
        // Backoff borné : 0,5 s + 1 s + 2 s (max ~3,5 s d'attentes + les busy_timeout internes des sondes).
        for attempt in 1..=3u32 {
            std::thread::sleep(std::time::Duration::from_millis(500u64 << (attempt - 1)));
            eprintln!("[sqlcipher] self-check : base verrouillée (SQLITE_BUSY) — re-sonde {attempt}/3 (un verrou est transitoire)");
            verdict = probe_db(path, &key);
            if verdict != DbProbe::Locked { break; }
        }
        if verdict == DbProbe::Locked {
            eprintln!("[sqlcipher] base TOUJOURS verrouillée après re-sondes bornées — on PROCÈDE sans conclure (open_db gérera la contention ; un verrou n'est PAS un fail-closed). Fichier NON modifié.");
            return;
        }
    }
    match verdict {
        DbProbe::Fresh | DbProbe::OpensWithKey | DbProbe::Unopenable => return,
        DbProbe::Locked => return, // défensif : déjà traité ci-dessus (retries épuisés -> on ne touche à rien)
        DbProbe::WrongKeyOrCorrupt => {
            eprintln!(
                "[FATAL] clé SQLCipher invalide — la clé fournie n'ouvre pas {path} ; \
                 vérifiez PLUME_DB_KEY_FILE/PLUME_DB_KEY (la base existe, est chiffrée, et cette clé ne la \
                 déchiffre pas : mauvaise clé ou base corrompue). Refus de démarrer (fail-closed) ; la base \
                 n'est PAS modifiée. Restaurez la BONNE clé (ou une sauvegarde compatible)."
            );
            std::process::exit(78); // EX_CONFIG — même code que le fail-closed de db_key()
        }
        DbProbe::Plaintext => { /* base EN CLAIR confirmée -> migration ci-dessous */ }
    }
    let kesc = key.replace('\'', "''");
    // 3) checkpoint WAL, backup clair, export chiffré -> temp, swap atomique (base EN CLAIR confirmée par probe_db)
    // SANS CONTRAT, assumé : ce chemin CHIFFRE une base at-rest, il tourne AVANT `prepare_schema` (le
    // daemon l'appelle juste avant d'ouvrir) et il doit fonctionner sur une base au schéma quelconque.
    let plain = match open_db_keyed_without_schema_contract(path, None) { Ok(c) => c, Err(_) => return };
    crate::db_open::checkpoint_wal_tronque(&plain, "sqlcipher");
    if std::fs::copy(path, &bak).is_err() { eprintln!("[sqlcipher] backup impossible -> abandon (base en clair intacte)"); return; }
    let enc = format!("{path}.enc.tmp");
    let _ = std::fs::remove_file(&enc);
    let sql = format!("ATTACH DATABASE '{}' AS enc KEY '{}'; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;",
                      enc.replace('\'', "''"), kesc);
    if let Err(e) = plain.execute_batch(&sql) { eprintln!("[sqlcipher] export échoué: {e} (base en clair intacte)"); let _ = std::fs::remove_file(&enc); return; }
    drop(plain);
    if std::fs::rename(&enc, path).is_ok() {
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
        // NETTOYAGE : le swap chiffré est vérifié en place -> on EFFACE la copie EN CLAIR (shred+unlink) au lieu
        // de la laisser traîner sur /data (l'ancien message « supprimer après vérif » comptait sur l'opérateur
        // et laissait une base en clair persistante). La base chiffrée reste la source de vérité.
        shred_file(&bak);
        eprintln!("[sqlcipher] base chiffrée at-rest OK (copie en clair effacée : {bak})");
    } else {
        eprintln!("[sqlcipher] swap échoué (base en clair intacte ; chiffrée disponible en {enc})");
    }
}

// ================================================================================================
// FRONTIÈRE CRYPTO PAR TENANT (#2a-3) — REGISTRE db_path -> clé résolue + client Vault minimal.
//
// Le read-pool (READ_POOL) est keyé par db_path (#2a-1). L'ouverture d'une connexion pour un db_path DOIT
// appliquer la clé DE CE TENANT (celle résolue depuis son key_ref), PAS la clé globale db_key(). Le
// manager enregistre ici, au moment où il résout un tenant, l'association (db_path -> clé effective) ;
// read_conn_open (chemin de lecture) consulte ce registre. Mode 0 : la base unique n'est JAMAIS enregistrée
// -> read_conn_open retombe sur apply_key()/db_key()/PLUME_DB_KEY = comportement STRICTEMENT identique.
// FAIL-CLOSED : un tenant dont la clé ne résout pas n'est JAMAIS enregistré, ET son db_path n'est jamais
// produit par resolve/req_db_path/handle_for -> aucune ouverture d'un fichier tenant avec une clé par défaut.
// ================================================================================================
pub(crate) static DB_KEY_REGISTRY: std::sync::OnceLock<Mutex<HashMap<String, Option<String>>>> = std::sync::OnceLock::new();
pub(crate) fn db_key_registry() -> &'static Mutex<HashMap<String, Option<String>>> {
    DB_KEY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Enregistre (db_path -> clé effective) : `None` = base en clair, `Some` = clé SQLCipher DU TENANT.
pub(crate) fn register_db_key(db_path: &str, key: Option<String>) {
    db_key_registry().lock().insert(db_path.to_string(), key);
}
/// Oublie l'entrée (destruction crypto / éviction).
#[allow(dead_code)]
pub(crate) fn unregister_db_key(db_path: &str) {
    db_key_registry().lock().remove(db_path);
}
/// Applique à une connexion la clé DU `db_path` : d'abord le registre (clé PAR tenant), sinon repli sur la
/// clé globale db_key() (base par défaut mode 0 / appelants internes / tests). Le registre étant keyé par
/// db_path, JAMAIS la clé d'un AUTRE tenant n'est appliquée. Une valeur enregistrée `None` = ouverture EN
/// CLAIR explicite (aucune PRAGMA key).
pub(crate) fn apply_key_for(conn: &Connection, db_path: &str) {
    let entry = db_key_registry().lock().get(db_path).cloned();
    match entry {
        Some(Some(k)) => {
            let _ = conn.execute_batch(&format!("PRAGMA key = '{}';", k.replace('\'', "''")));
        }
        Some(None) => { /* enregistré EN CLAIR : aucune clé */ }
        None => apply_key(conn), // non enregistré -> clé globale (invariant mode 0 préservé)
    }
}

// --- CLIENT VAULT MINIMAL (aucune dépendance nouvelle : std::net + rustls déjà présent + base64/serde_json).
//     GET $PLUME_VAULT_ADDR/v1/<CHEMIN>, header X-Vault-Token, extraction data.data.key (KV v2). La clé
//     résolue est mise en cache par CHEMIN (évite un appel Vault par requête) ; SEULS les succès sont
//     cachés (une panne Vault transitoire reste re-tentable). La clé n'apparaît JAMAIS dans un log/erreur.
pub(crate) static VAULT_KEY_CACHE: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
pub(crate) fn vault_key_cache() -> &'static Mutex<HashMap<String, String>> {
    VAULT_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(crate) fn vault_key_cache_get(path: &str) -> Option<String> {
    vault_key_cache().lock().get(path).cloned()
}
pub(crate) fn vault_key_cache_put(path: &str, key: &str) {
    vault_key_cache().lock().insert(path.to_string(), key.to_string());
}
#[allow(dead_code)]
pub(crate) fn vault_key_cache_forget(path: &str) {
    vault_key_cache().lock().remove(path);
}

/// v134 (#8) — TOKEN Vault : PRIORITÉ au FICHIER monté RO (`PLUME_VAULT_TOKEN_FILE`), MIROIR de
/// `db_key`/`PLUME_DB_KEY_FILE` : le token (credential) ne transite plus par `/proc/<pid>/environ` (lisible
/// via `kubectl exec`, `ps e`, crash-dump, héritage enfant). FAIL-CLOSED : si `PLUME_VAULT_TOKEN_FILE` est
/// posé mais que le fichier est absent/illisible/vide -> `Err` (jamais de repli SILENCIEUX sur l'env, qui
/// pourrait être absent -> auth Vault ratée EN SILENCE). Non posé -> repli rétrocompat sur l'env
/// `PLUME_VAULT_TOKEN` (mode historique). Absent partout -> `Err` (FAIL-CLOSED, comme le comportement
/// antérieur). Lecture VERBATIM du fichier (`FileProvider`, byte-pour-byte, comme la clé SQLCipher : la
/// projection d'un Secret k8s n'ajoute aucun newline).
pub(crate) fn vault_token() -> Result<String, String> {
    if let Ok(path) = std::env::var("PLUME_VAULT_TOKEN_FILE") {
        if !path.is_empty() {
            return vault_token_from_file(&path);
        }
    }
    std::env::var("PLUME_VAULT_TOKEN").ok().filter(|s| !s.is_empty())
        .ok_or_else(|| "vault: mais PLUME_VAULT_TOKEN (ou PLUME_VAULT_TOKEN_FILE) non défini (FAIL-CLOSED)".to_string())
}

/// v134 (#8) — lecture VERBATIM et TESTABLE du token Vault depuis un FICHIER (secret mount RO). Réutilise le
/// MÊME `guatx_core::secret::FileProvider` que `db_key_from_file` (octets tels quels). `Err` fail-closed si
/// absent/vide/illisible/non-UTF8 (messages scopés à `PLUME_VAULT_TOKEN_FILE`, jamais le contenu).
pub(crate) fn vault_token_from_file(path: &str) -> Result<String, String> {
    use guatx_core::secret::{SecretError, SecretOutcome, SecretProvider, SecretRef};
    match guatx_core::secret::FileProvider.get(&SecretRef::file(path)) {
        Ok(SecretOutcome::Present(v)) => Ok(v.into_string()), // VERBATIM
        Ok(SecretOutcome::NotFound) => Err(format!("PLUME_VAULT_TOKEN_FILE={path} absent ou vide (FAIL-CLOSED)")),
        Err(SecretError::Unreadable(e)) => Err(format!("PLUME_VAULT_TOKEN_FILE={path} illisible ({e})")),
        Err(SecretError::Malformed(_)) => Err(format!("PLUME_VAULT_TOKEN_FILE={path} : contenu non-UTF8")),
        Err(SecretError::Backend(e)) => Err(e), // inatteignable pour file:
    }
}

/// PHASE 2 — résout un secret Vault KV-v2 avec CHAMP paramétrable (généralise l'ancien `data.data.key`
/// codé en dur en `data.data.<field>`). Cache par `path#field` (un même path peut porter plusieurs
/// champs). FAIL-CLOSED identique : Vault non configuré / injoignable / champ absent -> `Err`.
pub(crate) fn resolve_vault_key_field(path: &str, field: &str) -> Result<String, String> {
    let cache_key = format!("{path}#{field}");
    if let Some(k) = vault_key_cache_get(&cache_key) {
        return Ok(k);
    }
    let addr = std::env::var("PLUME_VAULT_ADDR").ok().filter(|s| !s.is_empty())
        .ok_or("vault: mais PLUME_VAULT_ADDR non défini (FAIL-CLOSED)")?;
    let token = vault_token()?;
    let key = vault_fetch_field(&addr, &token, path, field)?;
    if key.is_empty() {
        return Err("Vault a renvoyé une valeur vide".into());
    }
    vault_key_cache_put(&cache_key, &key);
    Ok(key)
}

/// Effectue le GET Vault et extrait `data.data.<field>` (KV v2). `field` généralise l'ancien `key` codé
/// en dur (défaut `key` côté `SecretRef::vault_path_field`). Ne journalise JAMAIS le corps (il porte le secret).
pub(crate) fn vault_fetch_field(addr: &str, token: &str, path: &str, field: &str) -> Result<String, String> {
    let req_path = format!("/v1/{}", path.trim_start_matches('/'));
    let body = http_get(addr, &req_path, &[("X-Vault-Token", token)])?;
    let v: Value = serde_json::from_slice(&body).map_err(|_| "réponse Vault non-JSON".to_string())?;
    v.get("data")
        .and_then(|d| d.get("data"))
        .and_then(|d| d.get(field))
        .and_then(|k| k.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("champ absent dans la réponse Vault (data.data.{field})"))
}

/// PHASE 2 — `SecretProvider` `vault:` (HTTP KV-v2). Enveloppe le client Vault EXISTANT derrière la SPI ;
/// AUCUN nouveau code Vault. `rest == "MOUNT/path#field"` (défaut `#key`). FAIL-CLOSED -> `Backend`. NB :
/// ceci est le `vault:` HTTP (db-key/tenant/{KEY}_REF) — DISTINCT du `vault:` par ENV-PROJECTION des
/// overlays (`overlays_oac::resolve_secret_ref`), qui reste une forme atteignable séparée.
pub(crate) struct VaultProvider;

impl guatx_core::secret::SecretProvider for VaultProvider {
    fn scheme(&self) -> &'static str {
        "vault"
    }
    fn get(
        &self,
        r: &guatx_core::secret::SecretRef,
    ) -> Result<guatx_core::secret::SecretOutcome, guatx_core::secret::SecretError> {
        use guatx_core::secret::{SecretError, SecretOutcome, SecretValue};
        let (path, field) = r.vault_path_field();
        match resolve_vault_key_field(path, field) {
            Ok(k) => Ok(SecretOutcome::Present(SecretValue::new(k))),
            Err(e) => Err(SecretError::Backend(e)), // Vault non configuré/injoignable/champ absent -> fail-closed
        }
    }
}

/// Magasin de racines TLS pour Vault : PLUME_VAULT_CA (PEM, ex. CA in-cluster montée dans le pod) puis
/// bundles système. FAIL-CLOSED : aucune racine chargée -> `Err` (jamais de vérification désactivée).
pub(crate) fn vault_root_store() -> Result<rustls::RootCertStore, String> {
    let mut roots = rustls::RootCertStore::empty();
    let mut loaded = 0usize;
    let mut paths: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("PLUME_VAULT_CA") {
        if !p.is_empty() { paths.push(p); }
    }
    for p in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"] {
        paths.push(p.to_string());
    }
    for p in paths {
        if let Ok(pem) = std::fs::read_to_string(&p) {
            for der in pem_certs(&pem) {
                if roots.add(rustls::pki_types::CertificateDer::from(der)).is_ok() { loaded += 1; }
            }
            if loaded > 0 { break; }
        }
    }
    if loaded == 0 {
        return Err("aucune racine TLS chargée (PLUME_VAULT_CA / bundle système) — https Vault impossible".into());
    }
    Ok(roots)
}

/// Extrait les blocs DER des certificats PEM (base64 entre BEGIN/END CERTIFICATE) — réutilise base64.
pub(crate) fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let t = line.trim();
        if t == "-----BEGIN CERTIFICATE-----" { in_cert = true; b64.clear(); continue; }
        if t == "-----END CERTIFICATE-----" {
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) { out.push(der); }
            in_cert = false; continue;
        }
        if in_cert { b64.push_str(t); }
    }
    out
}
