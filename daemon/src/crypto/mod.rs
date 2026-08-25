//! Crypto/clés : ouverture SQLCipher (db_key/open_db/ensure_encrypted), registre de clés par base
//! (DB_KEY_REGISTRY) et résolution de clé Vault (VAULT_KEY_CACHE, resolve/fetch, racines TLS).
//! Dépend de util::http_client (http_get) — appel résolu via glob re-export. Extrait de main.rs
//! (refactor split #25 — byte-identique).
use crate::*;

/// Connexion **read-only** + vérif `stmt.readonly()` (double garde-fou) + budget temps
/// (interruption ~3s, anti-requête-folle) + plafond de lignes. Renvoie colonnes/lignes + coût.
/// Chiffrement at-rest SQLCipher : si `PLUME_DB_KEY` est défini, la base est ouverte/chiffrée
/// avec cette clé (`PRAGMA key`, qui DOIT précéder toute requête). La clé vient typiquement de
/// Vault -> ExternalSecret -> env PLUME_DB_KEY.
///
/// `P9.6-a` — TROISIÈME PROVENANCE, EN DERNIER RECOURS : la clé AUTO-ENGENDRÉE d'une base NÉE
/// chiffrée (`cle_auto_chemin`). Elle n'existe QUE si le démon l'a écrite lui-même, et il ne l'écrit
/// QUE sur une base neuve (cf. `decision_at_rest`). Sur une installation sans ce fichier — c'est le
/// cas de TOUTE installation antérieure à `P9.6-a` — ce repli rend `None` : le comportement est
/// identique au précédent, à l'octet près.
///
/// LE REPLI EST ICI ET **PAS** DANS `db_key_depuis`, et c'est la garantie structurelle qui empêche
/// une conversion accidentelle : `ensure_encrypted` décide sur `db_key_depuis` (clé EXPLICITE), donc
/// une clé auto-engendrée ne peut littéralement pas atteindre le chemin qui réécrit une base.
pub(crate) fn db_key() -> Option<String> {
    let conf = load_config();
    db_key_depuis(&conf).or_else(|| cle_auto_lire(&cle_auto_chemin(&conf)))
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
// CES DEUX FAITS SUR L'UNITÉ SONT TENUS PAR UNE GARDE (S29), PAS PAR CE PARAGRAPHE. Ajouter
// `EnvironmentFile=` à l'unité est le geste ORDINAIRE pour lui donner sa configuration : le démon
// démarrerait, servirait à l'identique, aucun test ne rougirait — la seule chose qui changerait est
// que la clé SQLCipher deviendrait lisible dans l'environnement du processus. Personne ne
// l'apprendrait. `tests::allegations_d_environnement` relit l'unité livrée (commentaires retirés :
// une directive commentée n'est pas une directive) et exige les deux moitiés — pas d'`EnvironmentFile`,
// et un `Environment=PLUME_CONFIG=` qui désigne bien le fichier. Son témoin positif est que 29 des
// unités livrées PORTENT cette directive (mesuré le 2026-08-20) : le détecteur sait donc la voir, et
// son silence sur celle du démon est une preuve, pas une cécité.
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
        // `P9.6-a` — CET ÉNONCÉ A ÉTÉ CORRIGÉ PARCE QU'IL EST DEVENU FAUX. Il annonçait une
        // réécriture « maintenant », au démarrage. Le démarrage ne convertit plus RIEN : il REFUSE,
        // et nomme le geste. Laisser la phrase d'avant aurait produit exactement la famille de
        // défaut que ce lot ferme — un fichier qui décrit un état qui n'existe plus.
        DbProbe::Plaintext =>
            "la base EXISTANTE est EN CLAIR sur le disque, et elle NE SERA PAS convertie par ce \
             démarrage : le démon va REFUSER de démarrer (exit 78) et ne touchera pas au fichier. La \
             conversion est un geste EXPLICITE et IRRÉVERSIBLE : `plume-daemon chiffrer-au-repos`. \
             Tant qu'il n'est pas fait, retirer la clé remet ce déploiement exactement dans son état \
             précédent.",
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
/// tient (tests déterministes, sans attente). Hors tests `probe_db` fixe 5 s. On CLASSE les erreurs de lecture :
/// un verrou (`SQLITE_BUSY`/`SQLITE_LOCKED`) sur l'une OU l'autre ouverture -> `Locked` (transitoire, on ne peut
/// PAS conclure sur la clé) ; sinon (p.ex. `SQLITE_NOTADB`) -> `WrongKeyOrCorrupt`. Ainsi une MAUVAISE clé sur
/// une base NON verrouillée reste fail-closed (exit 78), et un verrou ne déclenche PAS de faux fail-closed.
pub(crate) fn probe_db_with_busy(path: &str, key: &str, busy: std::time::Duration) -> DbProbe {
    // FRESH = fichier absent OU 0 octet. Une base 0-octet est « neuve » : s'ouvre avec toute clé (SQLCipher la
    // matérialise au 1er write) -> ne JAMAIS la classer WrongKey (pas de faux positif install/premier boot).
    //
    // S32 — « ABSENT » ET « PAS INTERROGEABLE » NE SE CONFONDENT PLUS. `unwrap_or(0)` rendait `Fresh` —
    // le verdict le PLUS RASSURANT du type — dès que `metadata` échouait pour un motif autre que
    // l'absence : droits sur le répertoire, erreur d'entrée-sortie, chemin dont un composant n'est pas
    // un répertoire. L'exploitant lisait alors « aucune base existante : elle sera créée chiffrée
    // d'office » au moment précis où une base est peut-être là, intacte, et simplement injoignable.
    // La variante juste EXISTAIT DÉJÀ et n'était pas atteinte par ce chemin : `Unopenable` — « présente
    // mais non ouvrable : elle ne sera PAS touchée ». Les deux verdicts laissent le fichier intact ;
    // c'est ce qui est ANNONCÉ qui change, et c'est justement ce qu'un exploitant lit avant de décider.
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        // Le fichier n'est pas là : c'est une LECTURE réussie, et son résultat est « rien ».
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        // Tout le reste : on n'a rien pu établir, et on ne prétend rien.
        Err(_) => return DbProbe::Unopenable,
    };
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

// ================================================================================================
// `P9.6-a` — UNE BASE **NEUVE** NAÎT CHIFFRÉE ; UNE BASE **EXISTANTE** N'EST JAMAIS CONVERTIE PAR UN
// DÉMARRAGE
// ------------------------------------------------------------------------------------------------
// CE QUI ÉTAIT MESURÉ, ET POURQUOI CE LOT EXISTE. La SAUVEGARDE compressée est toujours chiffrée —
// une seule enveloppe, sans option. La BASE, elle, restait EN CLAIR tant qu'aucune clé n'était
// fournie : le produit protégeait mieux sa copie que son original. L'argument qui justifiait ce
// défaut — « une clé rangée à côté de la base ne protège pas d'une machine compromise » — est vrai,
// et il ne dit rien du vol de disque ni d'un volume mal décommissionné, qui sont les menaces au
// repos les plus banales. Le dépôt portait DÉJÀ ce geste pour une autre clé, avec sa justification
// écrite : `ledger_key_load` engendre une clé absente sur un emplacement on-PVC, et REFUSE de le
// faire ailleurs. Ce lot suit cette forme plutôt que d'en inventer une.
//
// CE QUE CE LOT CHANGE, ET CE QU'IL NE CHANGE PAS :
//   * base ABSENTE (ou fichier vide) et aucune clé configurée -> une clé est ENGENDRÉE, posée 0600,
//     et la base naît chiffrée ;
//   * base EXISTANTE, au DÉMARRAGE -> **RIEN**. Aucune écriture, aucune clé engendrée, aucune
//     conversion. C'est le témoin qui compte le plus, et il est tenu par `decision_at_rest` ;
//   * base EXISTANTE en clair + clé EXPLICITE -> le démarrage REFUSAIT de rien dire et CONVERTISSAIT
//     séance tenante. Il REFUSE désormais de démarrer et NOMME le geste. C'est un CHANGEMENT DE
//     COMPORTEMENT, délibéré : convertir les données vivantes d'un SOC parce qu'une variable
//     d'environnement a changé est une porte à sens unique franchie par accident. La conversion est
//     un geste explicite (`convertir_la_base_au_repos`), et rien d'autre.
//
// POURQUOI LA PORTE DE CONVERSION NE PEUT PAS S'OUVRIR TOUTE SEULE. `ensure_encrypted` décide sur
// `db_key_depuis` — la clé EXPLICITE — et la clé auto-engendrée n'entre QUE par `db_key()`, qui
// n'est appelée que pour OUVRIR. Il n'existe donc aucun chemin par lequel une clé que le démon s'est
// donnée à lui-même déclencherait une réécriture : ce n'est pas une convention de relecture, c'est
// la séparation des deux fonctions.
// ================================================================================================

/// `P9.6-a` — CHEMIN du fichier de clé AUTO-ENGENDRÉE. Vide/absent -> DÉRIVÉ de `PLUME_DB`
/// (`<base>.key`), c'est-à-dire posé sur le MÊME volume que la base, comme `ledger.key` l'est déjà.
/// Le chemin dérivé est le bon défaut parce que TOUS les processus du produit (démon, sous-commandes,
/// ordonnanceur) connaissent `PLUME_DB` : aucun d'eux ne peut se tromper de fichier faute d'avoir été
/// configuré. Un déploiement qui veut la clé ailleurs (volume séparé, montage chiffré) pose ce levier.
pub(crate) const CLE_DB_KEY_AUTO_PATH: &str = "PLUME_DB_KEY_AUTO_PATH";

/// `P9.6-a` — ACQUITTEMENT de MISE À L'ABRI de la clé auto-engendrée (`1/true/yes/on`). Tant qu'il
/// n'est pas posé, chaque ouverture de la base écrit un signal de posture NON PURGEABLE. Ce que ce
/// levier atteste est une DÉCLARATION de l'exploitant, pas un fait vérifié par le produit — le
/// message du signal le dit, parce qu'un acquittement qui se ferait passer pour une preuve serait
/// pire que pas d'acquittement du tout.
pub(crate) const CLE_DB_KEY_ESCROWED: &str = "PLUME_DB_KEY_ESCROWED";

/// LES TROIS NOMS QUI PEUVENT DONNER UNE CLÉ DE BASE À UN DÉPLOIEMENT, écrits UNE fois. `CLES_AT_REST`
/// (deux noms) reste ce qu'elle était — la précédence des clés FOURNIES, que l'annonce de bascule
/// parcourt ; ce tableau-ci dit autre chose : les provenances par lesquelles une base peut être
/// chiffrée du tout. C'est cette classe d'équivalence que lit la garde
/// `check_a_deployment_never_arms_a_task_it_cannot_run.py` pour savoir qu'un manifeste satisfait la
/// précondition de la sauvegarde compressée.
///
/// CE QUE `PLUME_DB_KEY_AUTO_PATH` SUBSTITUE EXACTEMENT, ET CE QU'IL NE SUBSTITUE PAS : sur une base
/// NÉE sous ce levier, la clé existe et la sauvegarde aboutit ; sur une base ANTÉRIEURE restée en
/// clair, aucune clé n'est engendrée (c'est l'invariant du lot) et poser ce levier n'y change rien.
/// La même réserve vaut pour `PLUME_DB_KEY_FILE`, qui nomme un fichier que la garde ne peut pas voir.
pub(crate) const CLES_QUI_DONNENT_UNE_CLE_DE_BASE: [&str; 3] =
    [CLE_DB_KEY_FILE, CLE_DB_KEY, CLE_DB_KEY_AUTO_PATH];

/// Le chemin de la base, résolu comme partout ailleurs dans l'arbre (`PLUME_DB`, défaut compilé).
/// Écrit ici pour que la clé auto et la base ne puissent pas être résolues par deux lectures
/// différentes — c'est exactement la divergence que `P8.7-b` a payée.
pub(crate) fn db_path_depuis(conf: &HashMap<String, String>) -> String {
    cfg(conf, "PLUME_DB", "/var/lib/plume/db/plume.db")
}

/// Le chemin du fichier de clé auto-engendrée : `PLUME_DB_KEY_AUTO_PATH` s'il est posé et non vide,
/// sinon `<PLUME_DB>.key`. Une valeur VIDE n'écrase pas le défaut (miroir de `ledger_key_active_path`).
pub(crate) fn cle_auto_chemin(conf: &HashMap<String, String>) -> String {
    let p = cfg(conf, CLE_DB_KEY_AUTO_PATH, "");
    if !p.trim().is_empty() { p.trim().to_string() } else { format!("{}.key", db_path_depuis(conf)) }
}

/// LECTURE de la clé auto-engendrée. `None` = fichier absent, illisible, ou VIDE une fois les espaces
/// retirés — c'est-à-dire « aucune clé », le comportement d'avant ce lot.
///
/// POURQUOI `trim()` ICI ALORS QUE `db_key_from_file` LIT VERBATIM. Ce ne sont pas les mêmes octets :
/// `PLUME_DB_KEY_FILE` est la PROJECTION d'un secret dont l'ancien jumeau était une variable
/// d'environnement, et y retirer un `\n` fabriquerait une clé différente de celle qui a chiffré la
/// base. Ce fichier-ci n'a pas de jumeau : il est écrit par `cle_auto_engendrer`, qui n'émet QUE
/// 64 caractères hexadécimaux sans terminaison. Le `trim()` ne peut donc rien changer à une clé que
/// le produit a écrite, et il fait fonctionner la copie qu'un exploitant restaure depuis son escrow
/// avec un `echo` (qui, lui, ajoute un saut de ligne). Sans lui, le geste de reprise le plus banal
/// rendrait la base illisible.
pub(crate) fn cle_auto_lire(chemin: &str) -> Option<String> {
    let brut = std::fs::read_to_string(chemin).ok()?;
    let k = brut.trim();
    if k.is_empty() { None } else { Some(k.to_string()) }
}

/// L'exploitant a-t-il DÉCLARÉ avoir mis la clé à l'abri ? Même grammaire de drapeau que les leviers
/// de sauvegarde (`1/true/yes/on`) — une seule grammaire dans le produit, jamais recopiée.
pub(crate) fn cle_mise_a_l_abri_declaree(conf: &HashMap<String, String>) -> bool {
    drapeau_sauvegarde(&cfg(conf, CLE_DB_KEY_ESCROWED, ""))
}

/// CE QUE LE FICHIER DE BASE PERMET D'ÉTABLIR — et la propriété sur laquelle repose TOUT ce lot.
///
/// LA DISSYMÉTRIE EST LE POINT. Se tromper en disant « existante » d'une base neuve laisse une base
/// en clair : c'est le défaut d'aujourd'hui, sans aggravation. Se tromper en disant « neuve » d'une
/// base existante engendrerait une clé pour une base qui n'en a pas — inacceptable. Ce type est donc
/// conçu pour que la seconde erreur ne puisse pas se produire : `Neuve` exige DEUX absences
/// indépendantes, et TOUTE incertitude tombe dans `Indecidable`, qui ne fait rien.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum EtatDuFichierDeBase {
    /// Le fichier principal est ABSENT ou de longueur ZÉRO, **et** aucun compagnon SQLite (`-wal`,
    /// `-shm`, `-journal`) ne porte d'octets. Deux témoins indépendants disent « il n'y a rien ».
    Neuve,
    /// Le fichier principal porte des octets, OU un compagnon en porte. Une seule preuve de contenu
    /// suffit à interdire la génération : c'est le sens SÛR de l'erreur.
    Existante,
    /// `metadata` a échoué pour un motif AUTRE que l'absence (droits sur le répertoire, entrée-sortie,
    /// composant de chemin qui n'est pas un répertoire). On n'a rien établi, on ne prétend rien —
    /// mirroir exact de `S32` sur `probe_db`, qui a déjà payé le prix de rendre le verdict le plus
    /// rassurant quand la mesure échoue.
    Indecidable,
}

/// Les suffixes des fichiers que SQLite tient À CÔTÉ de la base. Ils ne sont pas une liste
/// d'exceptions : ce sont les trois noms que le moteur peut créer, et chacun est une preuve que
/// quelque chose a vécu ici.
const COMPAGNONS_SQLITE: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Classe le fichier de base. Aucune écriture, aucune ouverture : rien que `metadata`.
pub(crate) fn etat_du_fichier_de_base(path: &str) -> EtatDuFichierDeBase {
    let taille = |p: &str| -> Result<u64, std::io::Error> { std::fs::metadata(p).map(|m| m.len()) };
    let principal = match taille(path) {
        Ok(n) => n,
        // Le fichier n'est pas là : c'est une LECTURE réussie, et son résultat est « rien ».
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        // Tout le reste : on n'a rien pu établir (cf. `S32`).
        Err(_) => return EtatDuFichierDeBase::Indecidable,
    };
    if principal > 0 {
        return EtatDuFichierDeBase::Existante;
    }
    for suffixe in COMPAGNONS_SQLITE {
        match taille(&format!("{path}{suffixe}")) {
            Ok(n) if n > 0 => return EtatDuFichierDeBase::Existante,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return EtatDuFichierDeBase::Indecidable,
        }
    }
    EtatDuFichierDeBase::Neuve
}

/// CE QUE LE DÉMARRAGE FAIT DE L'ÉTAT AT-REST. Fonction **PURE** : aucun accès disque, aucune
/// variable d'environnement, aucun `exit`. Elle existe pour que les cinq issues soient exerçables
/// dans les deux sens sans tuer le processus de test — le fail-closed d'`ensure_encrypted` sort en 78,
/// et un test qui l'atteindrait emporterait toute la suite.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum DecisionAtRest {
    /// Le démarrage continue et ne touche à RIEN. C'est la décision de TOUTE base existante.
    RienAFaire,
    /// Base neuve, aucune clé nulle part -> engendrer la clé auto puis continuer (`P9.6-a`).
    EngendrerLaCleAuto,
    /// Clé EXPLICITE posée sur une base EXISTANTE **en clair**. Le démarrage refuse et nomme le geste.
    RefusConversionRequise,
    /// Clé posée, base non vide, ni déchiffrable par cette clé ni lisible en clair (comportement
    /// historique, `exit(78)` inchangé).
    RefusCleQuiNOuvrePasLaBase,
    /// Une clé AUTO-ENGENDRÉE existe à côté d'une base EN CLAIR. Cet état ne peut pas naître d'un
    /// démarrage (la clé n'est engendrée que sur une base neuve) : il naît d'une conversion
    /// INTERROMPUE, ou d'un fichier de clé déposé à la main. Sans ce refus nommé, le démarrage
    /// échouerait quand même — mais sur un contrat de schéma incompréhensible.
    RefusCleAutoOrpheline,
}

/// La table de décision, écrite une fois. `verdict` vaut `None` quand il n'y a AUCUNE clé : il n'y a
/// alors rien à sonder, et seul l'état du fichier compte.
pub(crate) fn decision_at_rest(
    cle_explicite: bool,
    cle_auto: bool,
    verdict: Option<DbProbe>,
    etat: EtatDuFichierDeBase,
) -> DecisionAtRest {
    match (cle_explicite, cle_auto, verdict) {
        // AUCUNE CLÉ. Le seul cas où le démarrage écrit quoi que ce soit — et il n'écrit rien
        // d'autre que la clé, et seulement sur une base dont DEUX témoins disent qu'elle n'existe pas.
        (false, false, _) => match etat {
            EtatDuFichierDeBase::Neuve => DecisionAtRest::EngendrerLaCleAuto,
            EtatDuFichierDeBase::Existante | EtatDuFichierDeBase::Indecidable => DecisionAtRest::RienAFaire,
        },
        // UNE CLÉ, QUELLE QU'ELLE SOIT : le fichier n'est jamais modifié, on ne fait que CLASSER.
        (_, _, Some(DbProbe::WrongKeyOrCorrupt)) => DecisionAtRest::RefusCleQuiNOuvrePasLaBase,
        (true, _, Some(DbProbe::Plaintext)) => DecisionAtRest::RefusConversionRequise,
        (false, true, Some(DbProbe::Plaintext)) => DecisionAtRest::RefusCleAutoOrpheline,
        // `Fresh` (la base naîtra chiffrée), `OpensWithKey` (déjà chiffrée), `Unopenable` et `Locked`
        // (on ne conclut pas) : le démarrage continue, exactement comme avant ce lot.
        _ => DecisionAtRest::RienAFaire,
    }
}

/// ENGENDRE et POSE la clé auto. **La pose est FERMÉE** : toute erreur remonte, et l'appelant refuse
/// de démarrer plutôt que de créer une base en clair en silence sous un levier qui promet l'inverse.
///
/// TROIS PROPRIÉTÉS, TENUES PAR LE CODE ET NON PAR CE PARAGRAPHE :
///   1. `create_new(true)` — on n'ÉCRASE JAMAIS un fichier existant. C'est la règle de
///      `ledger_key_load` (« une clé possiblement corrompue ne se réécrit pas ») et c'est aussi ce
///      qui rend la course entre deux démarrages simultanés inoffensive : le second perd, et le dit ;
///   2. `mode(0o600)` **à la création** — le fichier n'est jamais lisible par autrui, pas même
///      l'instant d'un `chmod` d'après coup ; les droits sont RELUS et le fichier retiré si le
///      système de fichiers ne les a pas honorés (un montage `fat`/`9p` ne les porte pas) ;
///   3. `sync_all` sur le fichier **puis sur son répertoire** — une clé qui ne survit pas à la coupure
///      qui suit sa création laisserait une base chiffrée sans clé, c'est-à-dire la perte totale que
///      ce lot existe pour éviter.
pub(crate) fn cle_auto_engendrer(chemin: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut octets = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut octets))
        .map_err(|e| format!("aucune source d'aléa (/dev/urandom) : {e}"))?;
    let hex = hex_encode(&octets);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(chemin)
        .map_err(|e| format!("création de {chemin} impossible ({e})"))?;
    f.write_all(hex.as_bytes()).map_err(|e| format!("écriture de {chemin} : {e}"))?;
    f.sync_all().map_err(|e| format!("synchronisation de {chemin} : {e}"))?;
    drop(f);
    // Les droits sont RELUS : `mode()` est une DEMANDE au système de fichiers, pas une garantie.
    let mode = std::fs::metadata(chemin)
        .map_err(|e| format!("relecture des droits de {chemin} : {e}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        let _ = std::fs::remove_file(chemin);
        return Err(format!(
            "les droits de {chemin} valent {mode:o} et non 600 — ce système de fichiers ne porte pas \
             les droits POSIX ; la clé a été RETIRÉE plutôt que laissée lisible"
        ));
    }
    // Le répertoire aussi : sans cela, l'entrée de répertoire peut ne pas survivre à une coupure.
    if let Some(parent) = std::path::Path::new(chemin).parent() {
        let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
    }
    Ok(hex)
}

/// LE MESSAGE DE NAISSANCE. Il dit les trois choses qu'un exploitant ne peut pas deviner : que cette
/// clé EXISTE, ce qu'elle protège et ce qu'elle ne protège PAS, et qu'il vient d'acquérir une
/// nouvelle façon de tout perdre. Aucune valeur n'y figure, jamais — seulement le chemin.
pub(crate) fn annonce_cle_engendree(chemin: &str, db_path: &str) -> String {
    format!(
        "[sqlcipher] `P9.6-a` — BASE NEUVE : une clé de chiffrement at-rest vient d'être ENGENDRÉE et \
         posée en 0600 dans {chemin}. {db_path} naît CHIFFRÉE.\n  \
         CE QUE CELA PROTÈGE : le vol du disque, une image de volume, un stockage mal décommissionné — \
         les octets de la base ne s'y relisent plus avec un `sqlite3` nu.\n  \
         CE QUE CELA NE PROTÈGE PAS : une machine compromise, où la clé est lisible à côté de la base.\n  \
         METTEZ CETTE CLÉ À L'ABRI, HORS DE CETTE MACHINE, MAINTENANT. Perdre {chemin} c'est perdre \
         la base ENTIÈRE et toutes ses sauvegardes, définitivement : elles sont chiffrées avec elle. \
         Aucune récupération n'existe. Quand c'est fait, posez {CLE_DB_KEY_ESCROWED}=1 — sans quoi le \
         produit écrira un événement de posture NON PURGEABLE à chaque ouverture de la base."
    )
}

/// `P9.6-a` — SIGNAL SOC NON-PURGEABLE : la base tourne sous une clé que le produit s'est donnée à
/// lui-même, et rien n'atteste qu'elle a été mise à l'abri. JUMEAU EXACT de
/// `emit_backup_symmetric_signal` et `emit_backup_cycle_failed_signal` : source managée
/// `plume-config`, `category='health'`, `origin='daemon'` (donc `RETENTION_NONPURGE` — un exploitant
/// ne PEUT pas l'effacer), sévérité 4, déduplication HORAIRE. Une ligne de journal ne suffisait pas :
/// c'est précisément ce qui a laissé la sauvegarde muette invisible.
pub(crate) fn emit_cle_auto_sans_abri(conn: &Connection, now_ts: i64, chemin: &str) -> bool {
    let bucket = now_ts / 3600; // même horizon que tous les signaux de santé non purgeables du dépôt
    let dedup = format!("plume-cle-at-rest-sans-abri-{bucket}");
    let msg = format!(
        "CLÉ AT-REST NON MISE À L'ABRI : cette base est chiffrée avec une clé ENGENDRÉE par le produit \
         lui-même et rangée dans {chemin}, sur le même volume. Perdre ce fichier, c'est perdre la base \
         et toutes ses sauvegardes — elles sont chiffrées avec la même clé — DÉFINITIVEMENT, sans \
         aucune récupération possible. Copiez-la hors de cette machine, puis posez \
         {CLE_DB_KEY_ESCROWED}=1. CE QUE CET ACQUITTEMENT VAUT : une DÉCLARATION de l'exploitant. Le \
         produit ne peut pas vérifier qu'une copie existe ailleurs, et il ne prétend pas le faire."
    );
    let fields = json!({
        "at_rest_key": "self-generated",
        "escrowed": false,
        "path": chemin,
        "ack_setting": CLE_DB_KEY_ESCROWED,
    })
    .to_string();
    let n = store()
        .insert_event(
            conn,
            &EventRow {
                ts: now_ts,
                source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
                category: "health".into(),
                severity: 4,
                message: msg,
                host: Some("plume-daemon".into()),
                src_ip: None,
                dst_ip: None,
                url: None,
                dedup: Some(dedup),
                fields: Some(fields),
                engagement_id: String::new(),
                origin: "daemon".into(),
                env_id: None,
            },
        )
        .unwrap_or(0);
    n > 0
}

/// PURE — y a-t-il lieu de crier ? `Some(chemin)` quand la base tourne sous une clé auto-engendrée
/// PRÉSENTE et que la mise à l'abri n'est pas déclarée. `None` dans tous les autres cas, dont celui
/// d'une clé EXPLICITE : elle vient d'ailleurs par construction, le produit ne l'a pas fabriquée.
pub(crate) fn cle_auto_a_signaler(conf: &HashMap<String, String>) -> Option<String> {
    if db_key_depuis(conf).is_some() {
        return None;
    }
    let chemin = cle_auto_chemin(conf);
    cle_auto_lire(&chemin)?;
    if cle_mise_a_l_abri_declaree(conf) { None } else { Some(chemin) }
}

/// L'ADAPTATEUR appelé par LA PORTE (`db_open`), sur une connexion dont le contrat de schéma est
/// satisfait — c'est-à-dire au seul moment où `event` existe à coup sûr. PORTÉE DÉRIVÉE, PAS
/// ÉNUMÉRÉE : tout ce qui obtient une connexion d'écriture avec la clé de l'environnement passe par
/// là, y compris un chemin écrit demain. La déduplication horaire fait que le coût de cette
/// couverture large est UNE ligne par heure au plus.
pub(crate) fn signaler_la_cle_auto_si_besoin(conn: &Connection) {
    if let Some(chemin) = cle_auto_a_signaler(&load_config()) {
        let _ = emit_cle_auto_sans_abri(conn, now(), &chemin);
    }
}

/// P8.7-b — `conf` EXPLICITE. L'appelant unique (`open_and_migrate_db`) tient déjà la configuration :
/// la lui prendre supprime une lecture AMBIANTE sur le chemin qui DÉCIDE du chiffrement at-rest, et
/// rend la fonction mesurable sans toucher à `PLUME_CONFIG` — donc testable en parallèle. (Ce n'est
/// pas cosmétique : la première version de ce lot testait via `PLUME_CONFIG`, et la suite complète a
/// rendu ROUGE deux tests d'incidents sans rapport — un `PRAGMA key` appliqué à leur base en clair
/// par un `db_key()` qui voyait la configuration d'un test voisin. La mesure a nommé le défaut de
/// conception : un chemin qui décide du chiffrement ne doit pas lire un état global du processus
/// quand son appelant tient déjà la valeur.)
///
/// `P9.6-a` — CETTE FONCTION NE CONVERTIT PLUS RIEN. Elle CLASSE, et elle agit sur une seule chose :
/// engendrer la clé d'une base qui n'existe pas encore. Les quatre autres issues sont un « continue »
/// ou un refus NOMMÉ. La conversion d'une base existante vit dans `convertir_la_base_au_repos`, qui
/// n'est atteignable que par un geste explicite de l'exploitant.
pub(crate) fn ensure_encrypted(conf: &HashMap<String, String>, path: &str) {
    let explicite = db_key_depuis(conf);
    let chemin_auto = cle_auto_chemin(conf);
    // La clé auto n'est LUE que si aucune clé explicite ne gagne : la précédence est celle de
    // `db_key()`, écrite une seule fois pour les deux.
    let auto = if explicite.is_none() { cle_auto_lire(&chemin_auto) } else { None };
    let effective = explicite.as_deref().or(auto.as_deref());

    // BALAYAGE au démarrage — un `.plaintext.bak` résiduel (conversion d'une version ANTÉRIEURE
    // interrompue APRÈS le swap mais AVANT le nettoyage) est une copie EN CLAIR persistante -> on
    // l'efface. Condition INCHANGÉE (une clé est en jeu) pour que le cas « aucune clé » reste
    // byte-identique. Le geste de conversion de `P9.6-a` n'emploie PAS ce nom : son lien de sécurité
    // partage l'inode de la base tant que la bascule n'a pas eu lieu, et l'effacer effacerait la base.
    if effective.is_some() {
        let bak = format!("{path}.plaintext.bak");
        if std::path::Path::new(&bak).exists() {
            shred_file(&bak);
        }
    }

    // Le verdict n'existe que s'il y a une clé à opposer au fichier. AUCUNE ÉCRITURE : `probe_db`
    // classe sans jamais toucher au fichier, et le backoff sur un VERROU est celui d'avant (un verrou
    // est transitoire, ce n'est pas une condition fail-closed).
    let verdict = effective.map(|k| sonder_avec_reprise(path, k));

    match decision_at_rest(explicite.is_some(), auto.is_some(), verdict, etat_du_fichier_de_base(path)) {
        DecisionAtRest::RienAFaire => {}
        DecisionAtRest::EngendrerLaCleAuto => match cle_auto_engendrer(&chemin_auto) {
            Ok(_) => eprintln!("{}", annonce_cle_engendree(&chemin_auto, path)),
            Err(e) => {
                eprintln!(
                    "[FATAL] `P9.6-a` — la clé at-rest d'une base NEUVE n'a pas pu être posée : {e}. \
                     Refus de démarrer (fail-closed) : créer la base EN CLAIR alors que ce déploiement \
                     demande une clé serait une promesse non tenue, et personne ne l'apprendrait. Si le \
                     fichier existe déjà mais qu'il est VIDE (secret monté non peuplé), il n'est PAS \
                     réécrit : peuplez-le, ou retirez-le si aucune base n'a jamais été chiffrée avec."
                );
                std::process::exit(78); // EX_CONFIG — même code que les autres fail-closed at-rest
            }
        },
        DecisionAtRest::RefusCleQuiNOuvrePasLaBase => {
            eprintln!(
                "[FATAL] clé SQLCipher invalide — la clé fournie n'ouvre pas {path} ; \
                 vérifiez PLUME_DB_KEY_FILE/PLUME_DB_KEY (la base existe, est chiffrée, et cette clé ne la \
                 déchiffre pas : mauvaise clé ou base corrompue). Refus de démarrer (fail-closed) ; la base \
                 n'est PAS modifiée. Restaurez la BONNE clé (ou une sauvegarde compatible)."
            );
            std::process::exit(78); // EX_CONFIG — même code que le fail-closed de db_key()
        }
        DecisionAtRest::RefusConversionRequise => {
            eprintln!(
                "[FATAL] `P9.6-a` — une clé at-rest est configurée, et {path} est une base EXISTANTE \
                 EN CLAIR. CE DÉMARRAGE NE LA CONVERTIT PAS, et n'a rien modifié.\n  \
                 Chiffrer une base est une porte à SENS UNIQUE sur les données vivantes d'un SOC : elle \
                 ne se franchit pas parce qu'une variable d'environnement a changé. Le geste est \
                 explicite : `plume-daemon chiffrer-au-repos`. Il exige une sauvegarde produite ET \
                 vérifiée, de la place pour une seconde base, et l'acquittement {CLE_DB_KEY_ESCROWED}=1.\n  \
                 RETOUR EN ARRIÈRE, TANT QUE LE GESTE N'A PAS ÉTÉ FAIT : retirer la clé de la \
                 configuration remet ce déploiement EXACTEMENT dans son état précédent — la base n'a \
                 pas bougé d'un octet. APRÈS le geste, il n'y a plus de retour arrière."
            );
            std::process::exit(78);
        }
        DecisionAtRest::RefusCleAutoOrpheline => {
            eprintln!(
                "[FATAL] `P9.6-a` — une clé at-rest ENGENDRÉE PAR LE PRODUIT existe dans {chemin_auto}, \
                 et {path} est une base EN CLAIR. Ces deux faits sont incompatibles : cette clé n'est \
                 engendrée QUE sur une base dont deux témoins disent qu'elle n'existe pas. Deux causes \
                 connues — une base EN CLAIR restaurée par-dessus un déploiement qui, lui, était né \
                 chiffré (restaurez plutôt l'archive chiffrée qui va avec cette clé), ou un fichier de \
                 clé déposé là à la main (déplacez-le : il n'appartient pas à cette base). Aucun fichier \
                 n'a été modifié. Refus de démarrer plutôt que d'échouer plus loin sur un contrat de \
                 schéma qui ne dirait pas pourquoi."
            );
            std::process::exit(78);
        }
    }
}

/// Le backoff BORNÉ sur un verrou, extrait d'`ensure_encrypted` sans changer une valeur : un verrou
/// transitoire (le sidecar de sauvegarde tient un write-lock pendant un chevauchement de démarrage)
/// NE DOIT PAS être pris pour une clé fausse. Si le verrou tient, on rend `Locked` et l'appelant
/// PROCÈDE : un verrou n'est pas une condition fail-closed. AUCUNE modification du fichier.
fn sonder_avec_reprise(path: &str, key: &str) -> DbProbe {
    let mut verdict = probe_db(path, key);
    if verdict != DbProbe::Locked {
        return verdict;
    }
    // Backoff borné : 0,5 s + 1 s + 2 s (max ~3,5 s d'attentes + les busy_timeout internes des sondes).
    for attempt in 1..=3u32 {
        std::thread::sleep(std::time::Duration::from_millis(500u64 << (attempt - 1)));
        eprintln!("[sqlcipher] self-check : base verrouillée (SQLITE_BUSY) — re-sonde {attempt}/3 (un verrou est transitoire)");
        verdict = probe_db(path, key);
        if verdict != DbProbe::Locked {
            return verdict;
        }
    }
    eprintln!("[sqlcipher] base TOUJOURS verrouillée après re-sondes bornées — on PROCÈDE sans conclure (open_db gérera la contention ; un verrou n'est PAS un fail-closed). Fichier NON modifié.");
    verdict
}


// ================================================================================================
// `P9.6-a` — LE GESTE EXPLICITE : CHIFFRER UNE BASE EXISTANTE, UNE FOIS, EN LE SACHANT
// ------------------------------------------------------------------------------------------------
// POURQUOI CE N'EST PAS UN DÉMARRAGE. Chiffrer une base est une porte à SENS UNIQUE sur les données
// vivantes d'un SOC. Elle ne se franchit pas parce qu'une variable d'environnement a changé : elle
// exige un ACQUITTEMENT qui nomme un objet VÉRIFIÉ, comme toutes les portes irréversibles de ce
// produit. Ce geste REFUSE de partir tant que ses préconditions ne sont pas réunies, il ne touche
// JAMAIS l'original avant d'avoir prouvé la copie, et il bascule par UN SEUL `rename`, atomique.
//
// L'ORDRE EST LOAD-BEARING, ET IL EST INHABITUEL — LA MESURE A RÉFUTÉ LA SÉQUENCE ÉVIDENTE.
// « Sauvegarder, puis convertir » est impossible : `backup_compressed` ouvre sa source AVEC la clé
// (`raw_keyed` -> `PRAGMA key`) et une base EN CLAIR devient alors illisible (`SQLITE_NOTADB`) ; sans
// clé, il refuse dès sa première instruction. Le produit ne SAIT donc pas sauvegarder une base en
// clair, et c'est exactement le cul-de-sac que `P9.4-b` a nommé. La séquence tenable est :
//   exporter -> PROUVER que la copie porte le même contenu -> sauvegarder ET VÉRIFIER depuis la
//   copie -> basculer.
// Ce que l'archive garantit alors est ce qu'un exploitant veut au sinistre : une archive RESTAURÉE
// avec succès des données qui vont devenir la base vivante.
//
// AUCUN ÉTAT INTERMÉDIAIRE N'EST DÉMARRABLE, ET C'EST STRUCTUREL : la copie vit sous un nom
// (`.conversion-en-cours`) que le démon n'ouvre JAMAIS, l'original garde le sien jusqu'au `rename`,
// et il n'existe aucun instant où `PLUME_DB` désigne un fichier à moitié écrit. Un échec avant la
// bascule laisse l'original intact et servable ; un échec après ne peut plus concerner que la trace.
//
// CE QUI EST RÉVERSIBLE, ÉCRIT SANS COMPLAISANCE : AVANT la bascule, tout — retirer la clé de la
// configuration remet le déploiement dans son état exact, la base n'ayant pas bougé d'un octet.
// APRÈS la bascule, RIEN : il n'existe aucun déchiffrement au repos dans ce produit, et ce geste ne
// prétend pas le contraire.
// ================================================================================================

/// Le suffixe de la COPIE en cours d'écriture. Un nom que le démon n'ouvre jamais — c'est ce qui rend
/// l'état intermédiaire non démarrable.
const SUFFIXE_COPIE_EN_COURS: &str = ".conversion-en-cours";
/// Le suffixe du LIEN DUR de sécurité posé sur l'original juste avant la bascule. DISTINCT de
/// `.plaintext.bak` DÉLIBÉRÉMENT : ce lien PARTAGE l'inode de la base tant que le `rename` n'a pas eu
/// lieu, et le balayage de démarrage efface `.plaintext.bak` — lui donner ce nom-là ferait effacer la
/// base par le démarrage suivant.
const SUFFIXE_LIEN_AVANT: &str = ".avant-chiffrement";

/// CE QU'UNE CONVERSION A ÉTABLI. Chaque champ est un FAIT produit par le geste, jamais une intention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RapportDeConversion {
    /// Tables de DONNÉES comparées (dérivées du schéma, tables virtuelles et d'ombre écartées).
    pub(crate) tables: usize,
    /// Lignes relues dans la COPIE, toutes tables de données confondues, ÉGALES à celles de l'original.
    pub(crate) lignes: i64,
    /// Objets de schéma comparés un à un (`sqlite_master` : tables, index, vues, déclencheurs).
    pub(crate) objets_de_schema: usize,
    /// Entrées de la chaîne du journal inaltérable revérifiées SUR LA COPIE, avant la bascule.
    pub(crate) entrees_ledger: usize,
    /// Nom de base de l'archive produite et VÉRIFIÉE avant la bascule (jamais son chemin).
    pub(crate) archive: String,
    /// Lignes relues par la vérification COMPLÈTE de cette archive — restauration RÉELLE dans une base
    /// jetable, pas un contrôle structurel. C'est le nombre qui distingue « l'archive se déchiffre »
    /// de « des lignes en sont revenues ».
    pub(crate) lignes_restaurees: i64,
}

/// L'issue du geste. `DejaChiffree` n'est pas une erreur : relancer la conversion est sans effet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IssueConversion {
    /// La base s'ouvre déjà avec la clé — rien à faire, aucun fichier touché (idempotence).
    DejaChiffree,
    /// La bascule a eu lieu, et voici ce qui a été vérifié.
    Convertie(RapportDeConversion),
}

/// LA PLACE REQUISE, dérivée de ce que le geste écrit VRAIMENT : une seconde base ENTIÈRE (la copie
/// chiffrée), plus l'archive et la base JETABLE que sa vérification restaure. Le facteur 2,4 est une
/// borne de CONCEPTION, pas une mesure : l'archive est compressée (donc plus petite que la base) et la
/// base jetable est de l'ordre de la base. On préfère refuser à tort que remplir un volume au milieu
/// d'une porte à sens unique.
pub(crate) fn place_requise_octets(taille_base: u64) -> u64 {
    taille_base.saturating_mul(24) / 10
}

/// VERDICT DE PLACE — PUR. `dispo` vaut `None` quand la mesure a échoué : on REFUSE alors, au lieu du
/// fail-OPEN qu'emploie la garde d'ingest (`ingest_disk_reject`). La dissymétrie est délibérée et elle
/// est écrite ici : un ingest refusé à tort coûte un réessai, une conversion lancée sans savoir s'il y
/// a la place coûte la base.
pub(crate) fn verdict_de_place(taille_base: u64, dispo: Option<u64>) -> Result<(), String> {
    let requis = place_requise_octets(taille_base);
    let mo = |o: u64| o / (1024 * 1024);
    match dispo {
        None => Err(format!(
            "place disque NON MESURABLE sur le volume de la base — la conversion exige {} Mo libres \
             (base {} Mo × 2,4 : la copie chiffrée, l'archive de sécurité, et la base jetable de sa \
             vérification). Refus : une porte à sens unique ne se franchit pas sans savoir.",
            mo(requis), mo(taille_base)
        )),
        Some(d) if d < requis => Err(format!(
            "place disque INSUFFISANTE : {} Mo libres, {} Mo requis (base {} Mo × 2,4 : la copie \
             chiffrée, l'archive de sécurité, et la base jetable de sa vérification). RIEN n'a été \
             écrit. Libérez de la place, ou déportez PLUME_BACKUP_DEST sur un autre volume.",
            mo(d), mo(requis), mo(taille_base)
        )),
        Some(_) => Ok(()),
    }
}

/// L'EMPREINTE DE SCHÉMA d'une base : tout `sqlite_master` sauf les objets internes du moteur, trié.
/// DÉRIVÉE, jamais énumérée — une table ajoutée par une migration de demain entre dans la comparaison
/// le jour où elle est ajoutée, sans que personne ne la déclare.
fn empreinte_de_schema(conn: &Connection) -> Result<Vec<(String, String, String)>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT type, name, COALESCE(sql,'') FROM sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|e| format!("lecture du schéma : {e}"))?;
    let lignes = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        .map_err(|e| format!("énumération du schéma : {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("énumération du schéma : {e}"))?;
    if lignes.is_empty() {
        return Err("schéma VIDE : ce fichier ne porte aucun objet — il n'y a rien à comparer".into());
    }
    Ok(lignes)
}

/// LES TABLES QUI PORTENT LES DONNÉES, DÉRIVÉES du schéma : on écarte les tables VIRTUELLES et leurs
/// tables d'ombre (`<vtable>_…`), dont le contenu dépend de la façon dont l'index a été construit et
/// ne se compare donc à rien.
///
/// CETTE RÈGLE EXISTE DÉJÀ DANS LE PRODUIT — `verification::inventaire_restaure` — et elle n'est PAS
/// atteignable d'ici : `mod verification` est privé à `backup`, qui n'en réexporte que `verify_backup`.
/// Une règle écrite deux fois finit par diverger, et ce dépôt le sait. La divergence est donc fermée
/// AUTREMENT, et en PRODUCTION plutôt qu'en test : le geste compare son propre compte à celui que
/// `verify_backup` rend sur l'archive — c'est-à-dire au compte de l'AUTRE dérivation — et REFUSE de
/// basculer si les deux ne s'accordent pas. Le remède de fond tient en une ligne (ajouter
/// `inventaire_restaure`/`ContenuRestaure` à la réexportation de `backup/mod.rs`) et appartient au
/// périmètre de ce module-là.
fn tables_de_donnees(conn: &Connection) -> Result<Vec<String>, String> {
    let declarees: Vec<(String, String)> = empreinte_de_schema(conn)?
        .into_iter()
        .filter(|(t, _, _)| t == "table")
        .map(|(_, n, sql)| (n, sql))
        .collect();
    let virtuelles: Vec<&str> = declarees
        .iter()
        .filter(|(_, sql)| sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE"))
        .map(|(n, _)| n.as_str())
        .collect();
    Ok(declarees
        .iter()
        .filter(|(n, _)| {
            !virtuelles.contains(&n.as_str()) && !virtuelles.iter().any(|v| n.starts_with(&format!("{v}_")))
        })
        .map(|(n, _)| n.clone())
        .collect())
}

/// Le COMPTE de chaque table de données. Un `COUNT(*)` qui échoue est un VERDICT, pas un détail à
/// ignorer : il remonte tel quel et fait refuser la conversion.
fn compter_les_lignes(conn: &Connection, tables: &[String]) -> Result<Vec<(String, i64)>, String> {
    tables
        .iter()
        .map(|nom| {
            // Le nom vient de `sqlite_master` — on le cite tout de même en identifiant SQL.
            let cite = format!("\"{}\"", nom.replace('"', "\"\""));
            conn.query_row(&format!("SELECT COUNT(*) FROM {cite}"), [], |r| r.get::<_, i64>(0))
                .map(|n| (nom.clone(), n))
                .map_err(|e| format!("table `{nom}` illisible : {e}"))
        })
        .collect()
}

/// LA DIFFÉRENCE, DITE. Un `assert_eq!` sur deux vecteurs rendrait un mur illisible ; ce qu'un
/// exploitant doit lire, c'est CE QUI manque et CE QUI est en trop.
fn ecart_de_schema(avant: &[(String, String, String)], apres: &[(String, String, String)]) -> Option<String> {
    let nommer = |v: Vec<&(String, String, String)>| -> String {
        v.iter().map(|(t, n, _)| format!("{t} {n}")).collect::<Vec<_>>().join(", ")
    };
    let manquants: Vec<&(String, String, String)> = avant.iter().filter(|x| !apres.contains(x)).collect();
    let surnumeraires: Vec<&(String, String, String)> = apres.iter().filter(|x| !avant.contains(x)).collect();
    if manquants.is_empty() && surnumeraires.is_empty() {
        return None;
    }
    Some(format!(
        "ABSENTS de la copie : [{}] ; EN TROP dans la copie : [{}]",
        nommer(manquants),
        nommer(surnumeraires)
    ))
}

/// L'ÉQUIVALENCE, PROUVÉE AVANT LA BASCULE. Quatre lectures, toutes DÉRIVÉES du schéma :
///   1. `PRAGMA integrity_check` sur la copie — le moteur lui-même juge sa structure ;
///   2. l'empreinte de schéma, objet par objet, dans les DEUX sens ;
///   3. le compte de CHAQUE table de données, table par table (pas un total : deux erreurs qui se
///      compensent passeraient un total et pas une comparaison par table) ;
///   4. la chaîne du journal inaltérable, revérifiée SUR LA COPIE — c'est la table dont la raison
///      d'être est d'être infalsifiable, et une conversion qui la casserait sans le dire retirerait
///      au produit sa preuve de non-falsification au moment même où il en écrit une nouvelle copie.
/// Rend (objets de schéma comparés, tables de données, lignes totales, entrées de ledger).
fn prouver_l_equivalence(source: &Connection, copie: &Connection) -> Result<(usize, usize, i64, usize), String> {
    let verdict: String = copie
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| format!("integrity_check illisible sur la copie chiffrée : {e}"))?;
    if verdict != "ok" {
        return Err(format!("la copie chiffrée est STRUCTURELLEMENT abîmée (integrity_check : {verdict})"));
    }
    let avant = empreinte_de_schema(source)?;
    let apres = empreinte_de_schema(copie)?;
    if let Some(ecart) = ecart_de_schema(&avant, &apres) {
        return Err(format!("le schéma de la copie DIFFÈRE de celui de l'original — {ecart}"));
    }
    let tables = tables_de_donnees(source)?;
    if tables.is_empty() {
        return Err("aucune table de données dans l'original : ce fichier n'est pas une base plume".into());
    }
    let comptes_avant = compter_les_lignes(source, &tables)?;
    let comptes_apres = compter_les_lignes(copie, &tables)?;
    if comptes_avant != comptes_apres {
        let ecarts: Vec<String> = comptes_avant
            .iter()
            .zip(comptes_apres.iter())
            .filter(|((_, a), (_, b))| a != b)
            .map(|((n, a), (_, b))| format!("{n} : {a} -> {b}"))
            .collect();
        return Err(format!("le CONTENU de la copie diffère de l'original — {}", ecarts.join(", ")));
    }
    let lignes: i64 = comptes_apres.iter().map(|(_, n)| *n).sum();
    if lignes == 0 {
        return Err("la copie ne porte AUCUNE ligne : le schéma seul n'est pas une conversion".into());
    }
    // La chaîne d'intégrité, sur la COPIE, avec le pin d'escrow s'il est configuré.
    let pin = ledger_pinned_pubkey();
    let (entrees, _sig_ok, _sig_ko, rupture) = verify_ledger_conn(copie, pin.as_ref())
        .map_err(|e| format!("journal inaltérable ILLISIBLE dans la copie chiffrée : {e}"))?;
    if let Some(id) = rupture {
        return Err(format!(
            "journal inaltérable ROMPU dans la copie chiffrée à l'entrée #{id} ({entrees} entrées) — \
             la conversion est ABANDONNÉE et l'original n'a pas été touché"
        ));
    }
    Ok((avant.len(), tables.len(), lignes, entrees))
}

/// LE GESTE. Renvoie `Err` avec une cause LISIBLE à la première condition non tenue — et, à chaque
/// point de sortie avant la bascule, l'original est intact et le déploiement démarre encore
/// (il refusera de démarrer tant que la clé est posée : c'est la même invitation à finir le geste).
///
/// `#[allow(dead_code)]` — CE QUE CE MARQUEUR DIT, ET CE QU'IL NE CACHE PAS : la sous-commande qui
/// appelle cette fonction vit dans `main.rs`, hors du périmètre de fichiers de ce lot. Le moteur est
/// ici, éprouvé par ses tests ; son câblage est une addition de quelques lignes dans le répartiteur de
/// sous-commandes. Tant qu'il n'est pas fait, le geste n'est pas atteignable par un exploitant.
pub(crate) fn convertir_la_base_au_repos(
    conf: &HashMap<String, String>,
    db_path: &str,
) -> Result<IssueConversion, String> {
    // ── ① LA CLÉ, EXPLICITE ET SEULEMENT EXPLICITE ────────────────────────────────────────────────
    // Une base restée EN CLAIR n'a JAMAIS de clé auto-engendrée (l'invariant du lot : elle n'est
    // engendrée que sur une base neuve). Exiger la clé explicite n'est donc pas une restriction, c'est
    // la description du seul cas qui existe — et cela ferme, par construction, toute possibilité que le
    // produit convertisse vers une clé qu'il se serait donnée à lui-même.
    let key = db_key_depuis(conf).ok_or_else(|| {
        format!(
            "aucune clé at-rest configurée : posez {CLE_DB_KEY_FILE} (fichier monté en lecture seule, \
             préféré) ou {CLE_DB_KEY}. La clé que vous poserez sera la SEULE façon de relire cette base \
             et ses sauvegardes, pour toujours."
        )
    })?;

    // ── ② L'ACQUITTEMENT DE MISE À L'ABRI ─────────────────────────────────────────────────────────
    // Convertir vers une clé que personne n'a mise à l'abri, c'est fabriquer la perte totale au lieu
    // de la prévenir.
    if !cle_mise_a_l_abri_declaree(conf) {
        return Err(format!(
            "acquittement manquant : posez {CLE_DB_KEY_ESCROWED}=1 pour DÉCLARER que cette clé est \
             copiée hors de cette machine. Après la conversion, perdre la clé c'est perdre la base ET \
             toutes ses sauvegardes, DÉFINITIVEMENT — elles sont chiffrées avec elle. CE QUE CET \
             ACQUITTEMENT VAUT : une déclaration. Le produit ne peut pas vérifier qu'une copie existe \
             ailleurs, et il ne prétend pas le faire."
        ));
    }

    // ── ③ L'ÉTAT DE LA BASE — CLASSÉ SANS RIEN ÉCRIRE ─────────────────────────────────────────────
    match sonder_avec_reprise(db_path, &key) {
        DbProbe::Plaintext => {}
        DbProbe::OpensWithKey => return Ok(IssueConversion::DejaChiffree),
        DbProbe::Fresh => {
            return Err(format!(
                "{db_path} est absente ou vide : il n'y a rien à convertir. Une base NEUVE naît chiffrée \
                 d'office au premier démarrage."
            ))
        }
        DbProbe::WrongKeyOrCorrupt => {
            return Err(format!(
                "{db_path} n'est ni lisible en clair, ni déchiffrable avec la clé configurée : mauvaise \
                 clé ou base corrompue. Rien n'a été touché."
            ))
        }
        DbProbe::Locked => {
            return Err(format!(
                "{db_path} est VERROUILLÉE (SQLITE_BUSY) après re-sondes bornées : un autre processus \
                 l'écrit. ARRÊTEZ le démon avant de convertir — une conversion sous écriture concurrente \
                 perdrait les écritures postérieures à l'export. Rien n'a été touché."
            ))
        }
        DbProbe::Unopenable => {
            return Err(format!("{db_path} est présente mais non ouvrable (entrée-sortie ou droits). Rien n'a été touché."))
        }
    }

    // ── ④ LA PLACE, AVANT D'ÉCRIRE LE PREMIER OCTET ───────────────────────────────────────────────
    let taille_base = ["", "-wal"]
        .iter()
        .filter_map(|s| std::fs::metadata(format!("{db_path}{s}")).ok().map(|m| m.len()))
        .sum::<u64>();
    let volume = std::path::Path::new(db_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    verdict_de_place(taille_base, fs_free_mb(&volume).map(|mo| mo.saturating_mul(1024 * 1024)))?;

    // ── ⑤ L'EXPORT — L'ORIGINAL EST OUVERT EN LECTURE, LA COPIE NAÎT SOUS UN AUTRE NOM ────────────
    // SANS CONTRAT de schéma, assumé : ce chemin chiffre une base at-rest et doit fonctionner sur un
    // schéma quelconque (une base plus ancienne que ce binaire se convertit et se migre ensuite).
    let copie = format!("{db_path}{SUFFIXE_COPIE_EN_COURS}");
    let _ = std::fs::remove_file(&copie); // un résidu d'une tentative précédente n'est jamais réutilisé
    let source = open_db_keyed_without_schema_contract(db_path, None)
        .map_err(|e| format!("ouverture de l'original : {e}"))?;
    // Le WAL est replié dans le fichier principal : ce que l'export lit doit être TOUT ce qui existe.
    if let crate::db_open::Checkpoint::Refuse { restant_pages } =
        crate::db_open::checkpoint_wal_tronque(&source, "conversion-au-repos")
    {
        return Err(format!(
            "le journal d'écriture anticipée n'a pas pu être replié ({restant_pages} page(s) y restent) : \
             un lecteur tient la base. ARRÊTEZ tout ce qui la lit avant de convertir — sans ce repli, la \
             copie ne porterait pas les dernières écritures. Rien n'a été touché."
        ));
    }
    let kesc = key.replace('\'', "''");
    let sql = format!(
        "ATTACH DATABASE '{}' AS chiffree KEY '{}'; SELECT sqlcipher_export('chiffree'); DETACH DATABASE chiffree;",
        copie.replace('\'', "''"),
        kesc
    );
    if let Err(e) = source.execute_batch(&sql) {
        let _ = std::fs::remove_file(&copie);
        return Err(format!("export SQLCipher échoué : {e}. L'original est INTACT, la copie a été retirée."));
    }

    // ── ⑥ L'ÉQUIVALENCE, PROUVÉE — L'ORIGINAL N'A TOUJOURS PAS BOUGÉ ──────────────────────────────
    let nettoyer = |c: &str| {
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{c}{s}"));
        }
    };
    let ouverte = match open_db_keyed_without_schema_contract(&copie, Some(&key)) {
        Ok(c) => c,
        Err(e) => {
            nettoyer(&copie);
            return Err(format!("la copie chiffrée ne s'ouvre pas avec la clé : {e}. L'original est INTACT."));
        }
    };
    let (objets, tables, lignes, entrees) = match prouver_l_equivalence(&source, &ouverte) {
        Ok(v) => v,
        Err(e) => {
            drop(ouverte);
            nettoyer(&copie);
            return Err(format!("{e}. L'original est INTACT et le déploiement démarre encore ; la copie a été retirée."));
        }
    };
    drop(ouverte);
    drop(source);

    // ── ⑦ LA SAUVEGARDE FRAÎCHE **ET VÉRIFIÉE**, PRISE DEPUIS LA COPIE ────────────────────────────
    let archive = match produire_et_verifier_l_archive(conf, db_path, &copie, &key, lignes) {
        Ok(a) => a,
        Err(e) => {
            nettoyer(&copie);
            return Err(format!("{e}\nL'original est INTACT et la copie a été retirée : rien n'a été converti."));
        }
    };

    // ── ⑧ LA BASCULE — UN LIEN DUR, PUIS UN SEUL `rename` ─────────────────────────────────────────
    // Le lien dur donne un SECOND nom au MÊME inode : l'original survit au `rename` qui remplace son
    // entrée de répertoire. Deux `rename` successifs ouvriraient une fenêtre où `PLUME_DB` n'existe
    // pas — et un démarrage y créerait une base VIDE, chiffrée, d'apparence saine. C'est le seul état
    // vraiment dangereux du geste, et il est fermé par construction.
    // CE QUI SURVIT À UN ÉCHEC ICI, ET POURQUOI ON LE GARDE : l'archive de l'étape ⑦ est DÉJÀ
    // publiée. Elle reste, et c'est délibéré — c'est une sauvegarde vérifiée du contenu de cette base,
    // restaurable avec la clé configurée, et la rétention KEEP-N la traite comme les autres. La
    // retirer parce que la bascule a échoué priverait l'exploitant de la seule chose que ce geste
    // avait déjà produite de bon.
    let lien = format!("{db_path}{SUFFIXE_LIEN_AVANT}");
    let _ = std::fs::remove_file(&lien);
    if let Err(e) = std::fs::hard_link(db_path, &lien) {
        nettoyer(&copie);
        return Err(format!(
            "impossible de poser le lien de sécurité {lien} ({e}) : la bascule n'a PAS eu lieu. \
             L'original est INTACT, en clair, et démarre encore ; la copie a été retirée. L'archive \
             vérifiée {archive} reste publiée — elle est restaurable avec la clé configurée."
        ));
    }
    if let Err(e) = std::fs::rename(&copie, db_path) {
        let _ = std::fs::remove_file(&lien);
        nettoyer(&copie);
        return Err(format!(
            "la bascule atomique a échoué ({e}) : l'original est INTACT (le `rename` ne l'a pas touché), \
             en clair, et démarre encore ; la copie a été retirée. L'archive vérifiée {archive} reste \
             publiée — elle est restaurable avec la clé configurée."
        ));
    }
    // Les compagnons de l'ANCIENNE base : ils décrivent un fichier qui n'est plus là.
    for s in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{db_path}{s}"));
    }

    // ── ⑨ LA CONVERSION S'INSCRIT ELLE-MÊME AU JOURNAL INALTÉRABLE ────────────────────────────────
    // Après la bascule, délibérément : la ligne appartient à la base CHIFFRÉE, celle qui sert.
    let detail = format!(
        "base chiffrée au repos ({objets} objets de schéma comparés, {tables} tables de données, \
         {lignes} lignes, {entrees} entrées de journal revérifiées) — archive vérifiée : {archive}"
    );
    match open_db_keyed_without_schema_contract(db_path, Some(&key)) {
        Ok(c) => ledger_append(&c, "at_rest.converted", &detail),
        Err(e) => eprintln!(
            "[chiffrement] la base est CONVERTIE et servable, mais la trace au journal inaltérable n'a \
             pas pu être écrite ({e}) — la conversion est faite, elle n'est pas consignée."
        ),
    }

    // ── ⑩ LA COPIE EN CLAIR NE RESTE PAS SUR LE VOLUME ────────────────────────────────────────────
    // Depuis le `rename`, ce lien ne partage plus le nom de la base : l'effacer efface la seule copie
    // EN CLAIR restante, et c'est tout l'objet du chiffrement at-rest. La voie de reprise n'est plus
    // ce fichier, c'est l'archive vérifiée à l'étape ⑦ — et le message le dit.
    shred_file(&lien);
    eprintln!(
        "[chiffrement] {db_path} est CHIFFRÉE AU REPOS. La copie en clair a été effacée ; la seule voie \
         de reprise est l'archive {archive}, vérifiée par restauration avant la bascule. IL N'Y A PAS DE \
         RETOUR ARRIÈRE : ce produit ne sait pas déchiffrer une base au repos."
    );
    Ok(IssueConversion::Convertie(RapportDeConversion {
        tables,
        lignes,
        objets_de_schema: objets,
        entrees_ledger: entrees,
        archive: archive.clone(),
        lignes_restaurees: lignes,
    }))
}

/// LA PRÉCONDITION DE SAUVEGARDE, PRODUITE ET ÉPROUVÉE PAR LE GESTE LUI-MÊME.
///
/// CE QU'ELLE ÉTABLIT : une archive existe, à la destination de sauvegarde du déploiement ; elle se
/// déchiffre ; elle se REJOUE dans une base neuve ; et cette base restaurée rend le MÊME nombre de
/// lignes que la copie qui va devenir la base vivante. Le compte est confronté à celui qu'a produit
/// l'AUTRE dérivation du produit (`verify_backup` -> `inventaire_restaure`) : si les deux lectures de
/// « quelles tables portent les données » divergeaient, la conversion refuserait.
///
/// CE QU'ELLE N'ÉTABLIT PAS, ET C'EST ÉCRIT PLUTÔT QUE SOUS-ENTENDU : que l'archive soit STOCKÉE hors
/// de cette machine (sans destinataire age, elle est chiffrée par passphrase et le nœud la déchiffre) ;
/// qu'une restauration réussisse ailleurs, sur un autre matériel ou un autre binaire ; que les lignes
/// soient sémantiquement justes — seul leur NOMBRE est comparé ; ni que l'archive survive à la
/// rétention KEEP-N, qui l'élaguera comme les autres le moment venu.
///
/// LE MODE ASYMÉTRIQUE EST REFUSÉ QUAND L'IDENTITÉ MANQUE, et c'est le point le plus important : sans
/// l'identité privée d'escrow, `verify_backup` DÉGRADE en contrôle structurel — il dit « l'en-tête est
/// bien formé », pas « des lignes en reviennent ». Accepter ce verdict-là comme précondition d'une
/// porte à sens unique reviendrait exactement à ce que `P8.3-a` a nommé : un contrôle vert qui porte le
/// mot « restore » sans avoir rien restauré.
fn produire_et_verifier_l_archive(
    conf: &HashMap<String, String>,
    db_path: &str,
    copie: &str,
    key: &str,
    lignes_attendues: i64,
) -> Result<String, String> {
    let defaut = std::path::Path::new(db_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join("backups").to_string_lossy().into_owned())
        .unwrap_or_else(|| "backups".to_string());
    let dest = cfg(conf, "PLUME_BACKUP_DEST", &defaut);
    if dest.contains("://") {
        return Err(format!(
            "PLUME_BACKUP_DEST={dest} n'est pas un répertoire LOCAL : la précondition de sauvegarde exige \
             une archive que ce processus puisse RESTAURER pour la vérifier. Pointez une destination \
             locale le temps de la conversion."
        ));
    }
    std::fs::create_dir_all(&dest).map_err(|e| format!("destination de sauvegarde {dest} inutilisable : {e}"))?;
    let nom = format!("plume-{}.db.age", fmt_backup_ts(now()));
    let en_cours = std::path::Path::new(&dest).join(format!("{nom}.tmp"));
    let publiee = std::path::Path::new(&dest).join(&nom);
    let recipient = backup_age_recipient();

    let stats = backup_compressed(copie, &en_cours.to_string_lossy(), Some(key), recipient.as_deref())
        .map_err(|e| format!("SAUVEGARDE REFUSÉE avant conversion : {e}"))?;
    let _ = stats;

    let identite = backup_age_identity();
    let verdict = verify_backup(&en_cours.to_string_lossy(), Some(key), identite.as_ref());
    let (genre, contenu) = match verdict {
        Err(e) => {
            let _ = std::fs::remove_file(&en_cours);
            return Err(format!("l'archive de sécurité n'a PAS passé la vérification : {e}"));
        }
        Ok((_, None)) => {
            let _ = std::fs::remove_file(&en_cours);
            return Err(
                "l'archive de sécurité est chiffrée pour un destinataire age (escrow hors-machine) et \
                 l'identité privée n'est pas disponible ici : la vérification a DÉGRADÉ en contrôle \
                 structurel, qui ne prouve pas qu'une ligne revienne. Fournissez \
                 PLUME_BACKUP_AGE_IDENTITY_FILE le temps de la conversion, ou retirez \
                 PLUME_BACKUP_AGE_RECIPIENT pour une archive symétrique vérifiable sur place."
                    .into(),
            );
        }
        Ok((g, Some(c))) => (g, c),
    };
    if contenu.lignes != lignes_attendues {
        let _ = std::fs::remove_file(&en_cours);
        return Err(format!(
            "l'archive restaurée rend {} ligne(s) là où la copie chiffrée en porte {lignes_attendues} : \
             les deux lectures du produit ne s'accordent pas sur ce que contient cette base. La \
             conversion est ABANDONNÉE.",
            contenu.lignes
        ));
    }
    std::fs::rename(&en_cours, &publiee).map_err(|e| {
        let _ = std::fs::remove_file(&en_cours);
        format!("l'archive vérifiée n'a pas pu être publiée sous son nom canonique ({e})")
    })?;
    eprintln!(
        "[chiffrement] archive de sécurité {nom} produite ET VÉRIFIÉE par restauration : {} table(s), \
         {} ligne(s) relues. C'est la voie de reprise si la suite échoue.",
        contenu.tables, contenu.lignes
    );

    // ── CE QU'UNE ARCHIVE PUBLIÉE IMPLIQUE — ET LA GARDE QUI L'A RÉCLAMÉ ──────────────────────────
    // La première version de ce geste publiait une archive `plume-<TS>.db.age` sous le nom CANONIQUE
    // sans rien dire de ce qu'elle implique. La garde dérivée
    // `toute_ecriture_d_archive_en_production_emet_tous_les_signaux_de_posture` l'a REFUSÉ, et elle a
    // raison : une archive publiée est déchiffrable par le nœud quand aucun destinataire d'escrow
    // n'est configuré, et le produit doit le dire là où la posture se dit — pas sur la sortie d'erreur.
    // Les deux signaux partent donc d'ICI, comme ils partent du cycle natif.
    //
    // ET L'EXERCICE DE RESTAURATION EST ENREGISTRÉ, PARCE QU'IL A VRAIMENT EU LIEU. Ce geste vient de
    // RESTAURER cette archive dans une base jetable et d'en RECOMPTER les lignes : c'est la définition
    // exacte de l'exercice que `P8.3-a` réclame. Émettre « restauration jamais éprouvée » juste après
    // l'avoir éprouvée serait un énoncé FAUX ; l'attestation est donc consignée AVANT le signal, qui
    // se tait alors de lui-même. Le signal reste appelé : c'est lui qui décide, pas cette phrase.
    //
    // SANS CONTRAT DE SCHÉMA, ASSUMÉ : la copie porte le schéma de l'ORIGINAL, qui peut être plus
    // ancien que ce binaire. Passer par la porte la MIGRERAIT entre la preuve d'équivalence et la
    // bascule — c'est-à-dire changerait ce qu'on vient de prouver identique. Best-effort DANS LES DEUX
    // SENS, comme le cycle natif : un schéma qui ne porte pas `event` n'écrit rien, et le DIT.
    match open_db_keyed_without_schema_contract(copie, Some(key)) {
        Ok(c) => {
            let maintenant = now();
            let escrow_asymetrique = recipient.as_deref().is_some_and(|r| !r.is_empty());
            let _ = signal_backup_symmetric_if_needed(&c, recipient.as_deref(), maintenant);
            let exercice = crate::exercice_de_restauration::Exercice {
                ts: maintenant,
                archive: nom.clone(),
                archive_octets: std::fs::metadata(&publiee).map(|m| m.len()).unwrap_or(0),
                chiffrement: genre,
                tables: contenu.tables,
                lignes: contenu.lignes,
            };
            if let Err(e) = crate::exercice_de_restauration::enregistrer(&c, &exercice, maintenant) {
                eprintln!("[chiffrement] exercice de restauration NON consigné ({e}) — la vérification a bien eu lieu, sa trace non");
            }
            let _ = crate::exercice_de_restauration::signal_apres_sauvegarde(&c, escrow_asymetrique, maintenant);
        }
        Err(e) => eprintln!(
            "[chiffrement] signaux de posture NON émis sur la copie ({e}) : l'archive est publiée et \
             vérifiée, mais ce qu'elle implique n'est pas consigné dans la base."
        ),
    }
    Ok(nom)
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
