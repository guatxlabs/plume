//! Sauvegarde compressée + chiffrée (CLI `backup --compress` / `restore`) + helpers d'ouverture
//! SQLCipher à clé explicite. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ============================================================================
// SAUVEGARDE COMPRESSÉE + CHIFFRÉE  (CLI : `backup --compress` / `restore`)
// ----------------------------------------------------------------------------
// PROBLÈME : la DB SQLCipher est chiffrée at-rest -> INCOMPRESSIBLE (~2 GiB).
// SOLUTION : compresser (zstd) puis chiffrer (age) EN FLUX. Reste la question de CE QU'ON
//   fait passer dans le flux, et c'est là que les DEUX chemins de ce module diffèrent.
//
// DEUX CHEMINS, UNE SEULE ENVELOPPE. Le fichier produit est TOUJOURS `age( zstd( charge ) )` :
//   - couche EXTERNE : conteneur age v1 (en-tête « age-encryption.org/v1 », destinataire
//     scrypt/passphrase ou X25519) -> chiffrement authentifié, streaming ;
//   - couche INTERNE : frame zstd (magic 28 B5 2F FD) ;
//   - CHARGE : c'est elle qui change, et le restore la RECONNAÎT à son marqueur de tête —
//     JAMAIS au nom du fichier (les deux s'appellent `plume-<TS>.db.age`) :
//       * `PLUMEDUMP1\n`      -> DUMP TYPÉ STREAMING (défaut depuis B1, cf. section B1)
//       * `SQLite format 3\0` -> copie SQLite EN CLAIR (chemin HISTORIQUE)
//     Les sauvegardes en séquestre produites avant B1 sont donc toujours restaurables : c'est
//     le marqueur, pas une convention de nom, qui aiguille (`restore_compressed`).
//   Propriété de secours, valable pour les DEUX : hors de ce binaire,
//   `age -d -p < dest | zstd -d` redonne la charge avec des outils standard ; c'est une DB
//   SQLite directement ouvrable pour l'ancien format, le dump typé pour le nouveau.
//
// CE QUE LE CHEMIN HISTORIQUE COÛTE, ET POURQUOI IL N'EST PLUS LE DÉFAUT. `sqlcipher_export`
//   réécrit la base ENTIÈRE EN CLAIR dans un fichier temporaire de staging avant de la
//   compresser : pendant toute la durée du backup, une copie déchiffrée de tout le SOC est
//   posée sur un disque. Un garde RAII l'efface à la sortie et un balayage réape les orphelins
//   d'un SIGKILL — mais la fenêtre existe, et c'est elle que le streaming supprime.
//   Il reste joignable pour deux raisons : (1) REPLI AUTOMATIQUE sur les schémas que le dump
//   typé ne peut pas représenter fidèlement (cf. section B1) ; (2) ÉCHAPPATOIRE opérateur
//   explicite `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1`.
//
// CLÉ : la passphrase age = la clé SQLCipher (db_key()/PLUME_DB_KEY). UN seul secret.
//   Le scrypt d'age dérive sa propre clé (KDF) à partir de cette passphrase -> pas de
//   réutilisation directe de la clé brute. Requise (non vide) pour backup ET restore.
//
// RAM BORNÉE dans les deux cas : buffers de 1 MiB, pager SQLite à cache borné — JAMAIS la
//   base en heap. Le streaming n'ajoute au plus qu'UNE ligne à la fois (cf. section B1).
// ============================================================================

/// Buffer de copie en flux (1 MiB) -> RAM bornée quelle que soit la taille de la DB.
pub(crate) const BACKUP_BUF: usize = 1 << 20;
/// Niveau zstd : compromis ratio/CPU/RAM (fenêtre modérée -> sûr sous la limite 2 GiB).
pub(crate) const BACKUP_ZSTD_LEVEL: i32 = 7;

/// Âge minimal (s) d'un plaintext temporaire orphelin avant réapage au démarrage. Seuil de
/// SÛRETÉ : on n'efface JAMAIS un temp plus récent (backup concurrent potentiellement en vol).
pub(crate) const BACKUP_ORPHAN_MAX_AGE_SECS: u64 = 3600; // 1 h

/// Marqueur STRICT du nom d'un plaintext temporaire de backup (cf. `plain_temp_path`). Sert de
/// filtre au balayage : ne matche JAMAIS la vraie DB (`plume.db`/`-wal`/`-shm`) ni un `.age`.
pub(crate) const BACKUP_TEMP_MARKER: &str = ".plain.tmp.";

/// Sidecars SQLite qu'un `sqlcipher_export` vers un fichier temporaire peut créer À CÔTÉ du
/// temp (journal de rollback / WAL / shm). Ils contiennent aussi des pages EN CLAIR : à effacer
/// avec le temp. (Le nom du sidecar contient le marqueur -> le balayage les capte aussi.)
pub(crate) const TEMP_SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];

/// Garde RAII : efface un plaintext temporaire ET ses sidecars SQLite (`-journal`/`-wal`/`-shm`)
/// sur N'IMPORTE quelle sortie de portée (succès, erreur, panique, early-return). Le plaintext
/// en clair ne doit jamais subsister. NB : Drop ne s'exécute PAS sur SIGKILL/OOM-kill — c'est
/// le balayage de démarrage (`sweep_orphan_temps`) qui réape ces fuites-là.
pub(crate) struct PlaintextTempGuard(pub(crate) std::path::PathBuf);
impl PlaintextTempGuard {
    pub(crate) fn path(&self) -> &std::path::Path { &self.0 }
}
impl Drop for PlaintextTempGuard {
    fn drop(&mut self) {
        secure_delete(&self.0);
        // sidecars SQLite laissés par un export interrompu (mêmes pages en clair).
        if let Some(base) = self.0.to_str() {
            for sfx in TEMP_SIDECARS {
                secure_delete(std::path::Path::new(&format!("{base}{sfx}")));
            }
        }
    }
}

/// BALAYAGE DE DÉMARRAGE (réape les fuites d'un crash/OOM antérieur, où Drop n'a PAS pu tourner).
/// Scanne `dir` pour les fichiers dont le nom contient le marqueur `.plain.tmp.` (donc AUSSI leurs
/// sidecars `-journal`/`-wal`/`-shm`, qui héritent du marqueur) et dont la mtime dépasse `max_age`.
/// GARDE-FOUS : (1) le filtre par marqueur n'efface JAMAIS `plume.db`/`-wal`/`-shm` ni les `.age` ;
/// (2) le seuil d'âge épargne un temp récent d'une invocation CONCURRENTE en vol. Renvoie le
/// nombre de fichiers effacés (observabilité + assertion de test).
pub(crate) fn sweep_orphan_temps(dir: &std::path::Path, max_age: std::time::Duration) -> u64 {
    let now = std::time::SystemTime::now();
    let mut removed = 0u64;
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return 0 };
    for ent in rd.flatten() {
        let name = ent.file_name();
        if !name.to_string_lossy().contains(BACKUP_TEMP_MARKER) { continue; }
        let meta = match ent.metadata() { Ok(m) => m, Err(_) => continue };
        if !meta.is_file() { continue; }
        // mtime illisible OU trop récent -> on ÉPARGNE (ne jamais clobber un backup en vol).
        match meta.modified().ok().and_then(|m| now.duration_since(m).ok()) {
            Some(age) if age >= max_age => {}
            _ => continue,
        }
        secure_delete(&ent.path());
        removed += 1;
    }
    removed
}

/// Effacement best-effort d'un fichier sensible : écrase le contenu de zéros (1 passe,
/// buffers 1 MiB), fsync, puis supprime. NB : sur FS journalisé/CoW/SSD à wear-leveling
/// l'écrasement N'EST PAS une garantie cryptographique — la vraie protection reste le
/// chiffrement at-rest du volume. On réduit la fenêtre d'exposition + on garantit le retrait.
pub(crate) fn secure_delete(path: &std::path::Path) {
    use std::io::{Seek, SeekFrom, Write};
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len();
        if len > 0 {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; BACKUP_BUF.min(len as usize)];
                let _ = f.seek(SeekFrom::Start(0));
                let mut remaining = len;
                while remaining > 0 {
                    let n = (remaining as usize).min(zeros.len());
                    if f.write_all(&zeros[..n]).is_err() { break; }
                    remaining -= n as u64;
                }
                let _ = f.flush();
                let _ = f.sync_all();
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Copie en flux R -> W par buffers de 1 MiB. Renvoie le nombre d'octets copiés.
pub(crate) fn stream_copy<R: std::io::Read, W: std::io::Write>(r: &mut R, w: &mut W) -> std::io::Result<u64> {
    let mut buf = vec![0u8; BACKUP_BUF];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 { break; }
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

// L'ouverture à clé EXPLICITE (ex-`open_db_keyed`) a DÉMÉNAGÉ dans `db_open`. Sauvegarde et restore
// l'appellent par son nom SANS CONTRAT (`open_db_keyed_without_schema_contract`), et c'est délibéré :
// une base ABÎMÉE est exactement celle qu'il faut pouvoir sauvegarder/exporter. Refuser ici
// retirerait l'outil de diagnostic au moment précis où il sert — et la destination d'un backup n'est
// pas une base plume servie.

/// RÉPERTOIRE DE STAGING du plaintext temporaire. Priorité à l'env `PLUME_BACKUP_STAGING_DIR`
/// (orientez-le vers un volume ÉPHÉMÈRE, HORS du stockage durable/sauvegardé, de sorte qu'un crash ne
/// puisse JAMAIS laisser la DB EN CLAIR sur du stockage persistant) ;
/// sinon repli sur le répertoire de `dest` (comportement historique, rétrocompat CLI/test). Découple
/// l'emplacement du CLEARTEXT (qui DOIT être éphémère) de celui du `.age` chiffré (indifférent).
pub(crate) fn staging_dir(dest: &str) -> std::path::PathBuf {
    if let Ok(d) = std::env::var("PLUME_BACKUP_STAGING_DIR") {
        if !d.is_empty() { return std::path::PathBuf::from(d); }
    }
    std::path::Path::new(dest).parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Chemin de plaintext temporaire dans le répertoire de STAGING (`staging_dir` : PLUME_BACKUP_STAGING_DIR
/// si posé — volume éphémère — sinon à côté de `beside`). Unique (pid + horodatage + compteur monotone)
/// -> pas de collision parallèle. Le NOM conserve le marqueur `.plain.tmp.` (cible du balayage/RAII).
pub(crate) fn plain_temp_path(beside: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = staging_dir(beside);
    let name = std::path::Path::new(beside)
        .file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "backup".into());
    dir.join(format!(".{name}.plain.tmp.{}.{}.{n}", std::process::id(), now()))
}

/// DESTINATAIRE age asymétrique (clé PUBLIQUE `age1...`) si `PLUME_BACKUP_AGE_RECIPIENT` est posé.
/// Une clé PUBLIQUE n'est PAS un secret : peut vivre en clair dans l'env/ConfigMap du pod. Non posé ->
/// `None` -> repli sur le chiffrement SYMÉTRIQUE par passphrase (= clé SQLCipher) = comportement historique.
pub(crate) fn backup_age_recipient() -> Option<String> {
    std::env::var("PLUME_BACKUP_AGE_RECIPIENT").ok().filter(|s| !s.is_empty())
}

/// v134 (#7) — EXIGENCE OPT-IN d'un backup ASYMÉTRIQUE (escrow hors-cluster). `PLUME_BACKUP_REQUIRE_ASYMMETRIC`
/// vrai (1/true/yes/on) -> `backup_compressed` REFUSE de produire un backup symétrique (node-déchiffrable).
/// DÉFAUT OFF -> warn-only (comportement historique préservé pour l'usage symétrique/dev intentionnel).
pub(crate) fn backup_require_asymmetric() -> bool {
    matches!(
        std::env::var("PLUME_BACKUP_REQUIRE_ASYMMETRIC").ok().as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// ÉCHAPPATOIRE OPÉRATEUR — `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` vrai (1/true/yes/on) force le CHEMIN
/// HISTORIQUE (`sqlcipher_export` -> fichier SQLite EN CLAIR dans le staging, puis zstd+age) au lieu du dump
/// STREAMING. DÉFAUT OFF : le streaming est le défaut (cf. « DÉFAUT, PAS OPT-IN » dans l'en-tête de section B1).
/// Le nom dit le PRIX qu'on repaie en la posant : la base ENTIÈRE est réécrite EN CLAIR sur disque le temps du
/// backup. À ne poser que pour reproduire un incident sur le chemin historique, jamais en régime.
pub(crate) fn backup_force_plaintext_export() -> bool {
    matches!(
        std::env::var("PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT").ok().as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// v134 (#7) — SIGNAL SOC NON-PURGEABLE : les backups tombent en SYMÉTRIQUE (déchiffrables par le nœud, aucun
/// escrow hors-cluster) car `PLUME_BACKUP_AGE_RECIPIENT` n'est pas configuré. Miroir EXACT du pattern
/// `emit_disk_health`/`emit_ledger_unsigned` : source managée `plume-config`, category=health, origin='daemon'
/// (-> RETENTION_NONPURGE : un opérateur ne peut pas l'effacer), dedup HORAIRE (au plus 1 signal/heure malgré
/// un crashloop de boot). Sévérité 4 (P1 posture). `now_ts` injecté pour la testabilité. Renvoie true si écrit.
pub(crate) fn emit_backup_symmetric_signal(conn: &Connection, now_ts: i64) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE (anti-tempête, crashloop de boot inclus)
    let dedup = format!("plume-backup-symmetric-{bucket}");
    let msg = "POSTURE BACKUP DÉGRADÉE : PLUME_BACKUP_AGE_RECIPIENT (clé publique age1...) non configuré -> les \
               backups sont chiffrés SYMÉTRIQUEMENT (passphrase = clé SQLCipher, présente sur le nœud) et donc \
               DÉCHIFFRABLES PAR LE NŒUD : PAS d'escrow hors-cluster. Configurez un destinataire age asymétrique \
               (escrow hors-cluster), ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli."
        .to_string();
    let fields = json!({ "backup_encryption": "symmetric", "reason": "no-age-recipient", "node_decryptable": true }).to_string();
    let n = store().insert_event(conn, &EventRow {
        ts: now_ts,
        source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
        category: "health".into(),
        severity: 4,
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

/// v135 (#7) — émet le signal SOC de posture backup symétrique DEPUIS LE VRAI CHEMIN BACKUP (sidecar `plume-daemon
/// backup`), et UNIQUEMENT si le backup vient d'être produit SANS destinataire asymétrique (`recipient` None/"" ->
/// node-déchiffrable, pas d'escrow hors-cluster). Remplace le check de boot v134 mal placé dans `server::run` : le
/// conteneur PRINCIPAL ne fait JAMAIS de backup et n'a pas PLUME_BACKUP_AGE_RECIPIENT -> il émettait un faux signal
/// « posture dégradée » à chaque restart. Destinataire présent -> aucun signal (posture saine). `now_ts` injecté
/// pour la testabilité. Renvoie true si un signal a été écrit.
pub(crate) fn signal_backup_symmetric_if_needed(conn: &Connection, recipient: Option<&str>, now_ts: i64) -> bool {
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    symmetric_fallback && emit_backup_symmetric_signal(conn, now_ts)
}

/// IDENTITÉ age PRIVÉE (`AGE-SECRET-KEY-1...`) pour DÉCHIFFRER un backup asymétrique, fournie au
/// moment du DR depuis l'escrow HORS-cluster : fichier (`PLUME_BACKUP_AGE_IDENTITY_FILE`, prioritaire —
/// mount secret) puis valeur directe (`PLUME_BACKUP_AGE_IDENTITY`, DR ad-hoc). Normalement ABSENTE en
/// cluster (c'est tout l'intérêt : une compromission de pod ne donne pas la clé de déchiffrement).
pub(crate) fn backup_age_identity() -> Option<age::x25519::Identity> {
    if let Ok(p) = std::env::var("PLUME_BACKUP_AGE_IDENTITY_FILE") {
        if !p.is_empty() {
            return std::fs::read_to_string(&p).ok().and_then(|s| parse_age_identity_str(&s));
        }
    }
    std::env::var("PLUME_BACKUP_AGE_IDENTITY").ok().and_then(|s| parse_age_identity_str(&s))
}

/// Extrait et parse la 1re ligne `AGE-SECRET-KEY-...` (ignore les commentaires `# public key:` d'un fichier
/// d'identité age). `None` si aucune ligne d'identité valide.
pub(crate) fn parse_age_identity_str(s: &str) -> Option<age::x25519::Identity> {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("AGE-SECRET-KEY-"))
        .find_map(|l| l.parse::<age::x25519::Identity>().ok())
}

/// Ce qu'une sauvegarde compressée a réellement produit (log opérateur + assertions de test).
///
/// `plaintext_bytes` porte un nom HISTORIQUE, antérieur au chemin streaming, et il faut le lire pour ce
/// qu'il mesure aujourd'hui : la taille de la CHARGE SÉRIALISÉE avant zstd — la copie SQLite en clair sur
/// le chemin historique (où elle correspond bien à un fichier), le dump typé sur le chemin streaming (où
/// elle ne correspond à AUCUN fichier : rien n'est écrit en clair). Les deux valeurs ne se comparent donc
/// pas d'un chemin à l'autre sans savoir lequel a tourné — d'où le champ suivant.
///
/// `wrote_plaintext_to_disk` répond à la seule question que l'opérateur se pose vraiment : « ce cycle
/// a-t-il posé une copie EN CLAIR de la base sur un disque ? ». C'est lui, pas le nom du champ précédent,
/// qui porte la propriété.
pub(crate) struct BackupStats {
    pub(crate) plaintext_bytes: u64,
    pub(crate) dest_bytes: u64,
    pub(crate) wrote_plaintext_to_disk: bool,
}

/// SAUVEGARDE COMPRESSÉE+CHIFFRÉE — **CHEMIN LEGACY** (repli de B1, cf. `backup_compressed`).
/// Étapes (toutes en RAM bornée) :
///  1. EXPORT plaintext : ouvre `db_path` (clé SQLCipher), `ATTACH <tmp> AS plain KEY ''`
///     (clair), `SELECT sqlcipher_export('plain')` -> DB SQLite EN CLAIR `<tmp_plain>`
///     (snapshot cohérent même si la DB de prod est ouverte ailleurs).
///  2. STREAM : `<tmp_plain>` -> zstd::Encoder -> age(passphrase=key) -> `<dest>` (buffers 1 MiB).
///  3. Le garde RAII efface `<tmp_plain>` (succès comme erreur/panique).
/// Requiert une clé non vide (passphrase age). Renvoie {plaintext_bytes, dest_bytes, wrote_plaintext_to_disk=true}.
/// NB : ce chemin MATÉRIALISE la DB entière EN CLAIR dans un fichier temporaire (~2,4 Gio) — c'est
/// PRÉCISÉMENT ce que B1 (`backup_compressed_stream`) élimine. Il reste comme REPLI pour les schémas
/// que le dump typé B1 ne peut pas représenter fidèlement (FTS contentless/régulière, etc.).
fn backup_compressed_legacy(db_path: &str, dest: &str, key: Option<&str>, recipient: Option<&str>) -> Result<BackupStats, String> {
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
    };

    // v134 (#7) — GATE FAIL-CLOSED **AVANT tout export plaintext** : si un backup ASYMÉTRIQUE est EXIGÉ
    // (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) mais qu'aucun destinataire age n'est configuré, REFUSE IMMÉDIATEMENT
    // — n'écris JAMAIS un plaintext temporaire (ni un backup) qu'on va rejeter. DÉFAUT OFF -> warn-only plus bas
    // (comportement historique préservé). `recipient` None/"" = repli symétrique (node-déchiffrable).
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    if symmetric_fallback && backup_require_asymmetric() {
        return Err("backup REFUSÉ (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) : aucun PLUME_BACKUP_AGE_RECIPIENT \
                    (clé publique age1...) configuré -> un backup symétrique serait déchiffrable par le nœud \
                    (pas d'escrow hors-cluster). Configurez un destinataire age asymétrique, ou levez \
                    l'exigence pour un backup symétrique de dev.".into());
    }

    // Le BALAYAGE des orphelins vit chez l'appelant (`backup_compressed`) : il doit tourner à CHAQUE backup,
    // y compris quand le streaming réussit et que ce chemin-ci n'est jamais emprunté (sinon un plaintext
    // orphelin d'un crash antérieur ne serait plus JAMAIS réapé). Ici on se contente de créer le staging.
    let _ = std::fs::create_dir_all(staging_dir(dest));

    let tmp_guard = PlaintextTempGuard(plain_temp_path(dest));
    let tmp_plain = tmp_guard.path().to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&tmp_plain);   // ATTACH exige un chemin neuf

    // 1) EXPORT en clair : SQLCipher chiffré (main) -> SQLite clair (attaché). sqlcipher_export
    //    copie schéma + données via le pager SQLite -> RAM bornée (pas de chargement 2 GiB).
    {
        let conn = open_db_keyed_without_schema_contract(db_path, Some(&pass)).map_err(|e| format!("ouverture DB source : {e}"))?;
        // garde-fou : la source doit être lisible AVEC la clé (sinon clé fausse / DB illisible).
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|e| format!("DB source illisible (clé PLUME_DB_KEY incorrecte ?) : {e}"))?;
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        let sql = format!(
            "ATTACH DATABASE '{}' AS plain KEY ''; SELECT sqlcipher_export('plain'); DETACH DATABASE plain;",
            tmp_plain.replace('\'', "''"));
        conn.execute_batch(&sql).map_err(|e| format!("export plaintext (sqlcipher_export) : {e}"))?;
    }
    let plaintext_bytes = std::fs::metadata(&tmp_plain).map(|m| m.len()).unwrap_or(0);

    // v134 (#7) — LOUD WARN à chaque repli symétrique (backup DÉCHIFFRABLE PAR LE NŒUD : passphrase = clé
    // SQLCipher, présente sur le pod ; PAS d'escrow hors-cluster). Non-cassant (warn-only) : l'exigence
    // fail-closed a déjà été évaluée EN TÊTE (avant l'export plaintext). Le signal SOC NON-PURGEABLE est émis
    // par l'appelant du VRAI chemin backup (main.rs -> signal_backup_symmetric_if_needed) une fois le backup
    // symétrique effectivement produit — v135 a retiré le check de boot faux-positif de server.rs (le conteneur
    // principal ne fait jamais de backup) ; ici on n'a pas de conn writer dédiée.
    if symmetric_fallback {
        eprintln!(
            "[backup] ATTENTION : PLUME_BACKUP_AGE_RECIPIENT non configuré -> chiffrement SYMÉTRIQUE par \
             passphrase (= clé SQLCipher, présente sur le nœud). Ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS \
             d'escrow hors-cluster. Configurez une clé publique age (asymétrique, encrypt-only) pour un escrow \
             hors-cluster, ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli."
        );
    }
    // 2) STREAM : plaintext -> zstd -> age -> dest (chaîne de writers, buffers 1 MiB).
    let _ = std::fs::remove_file(dest);
    let out = std::fs::File::create(dest).map_err(|e| format!("création dest : {e}"))?;
    let out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
    // CHIFFREMENT : ASYMÉTRIQUE (destinataire public age1..., encrypt-only) si PLUME_BACKUP_AGE_RECIPIENT
    // est posé -> le pod ne détient PAS la clé de déchiffrement (escrow hors-cluster). Sinon SYMÉTRIQUE par
    // passphrase (= clé SQLCipher) = comportement HISTORIQUE (ship INERTE tant que le destinataire est absent).
    let encryptor = match recipient {
        Some(rcpt) if !rcpt.is_empty() => {
            let recipient = rcpt.parse::<age::x25519::Recipient>()
                .map_err(|e| format!("destinataire age invalide (clé publique age1... attendue) : {e}"))?;
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| format!("age with_recipients : {e}"))?
        }
        _ => age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(pass.clone())),
    };
    let age_w = encryptor.wrap_output(out).map_err(|e| format!("age wrap_output : {e}"))?;
    let mut z = zstd::Encoder::new(age_w, BACKUP_ZSTD_LEVEL).map_err(|e| format!("init zstd : {e}"))?;
    {
        let f = std::fs::File::open(&tmp_plain).map_err(|e| format!("ouverture plaintext : {e}"))?;
        let mut r = std::io::BufReader::with_capacity(BACKUP_BUF, f);
        stream_copy(&mut r, &mut z).map_err(|e| format!("flux zstd : {e}"))?;
    }
    let age_w = z.finish().map_err(|e| format!("finalisation zstd : {e}"))?;       // flush frame zstd
    age_w.finish().map_err(|e| format!("finalisation age : {e}"))?;                 // finalise le stream age

    let dest_bytes = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    // tmp_guard est droppé ici -> efface le plaintext temporaire.
    Ok(BackupStats { plaintext_bytes, dest_bytes, wrote_plaintext_to_disk: true })
}

// ============================================================================
// B1 — BACKUP STREAMING (élimine le PLAINTEXT TRANSITOIRE sur disque)
// ----------------------------------------------------------------------------
// PROBLÈME résiduel du legacy (backup_compressed_legacy) : sqlcipher_export matérialise
// la DB ENTIÈRE EN CLAIR dans un fichier temporaire (~2,4 Gio) avant compress+chiffre ->
// fenêtre d'exposition + pic disque.
//
// B1 : on ne matérialise JAMAIS le clair. On PARCOURT le schéma + les données ligne-à-ligne
// depuis la DB SQLCipher OUVERTE (déchiffrée EN MÉMOIRE par SQLCipher, jamais sur disque
// clair), on SÉRIALISE un DUMP typé binaire, pipe DIRECT -> zstd -> age -> `.age` final.
// AUCUN fichier clair intermédiaire.
//
// FORMAT de sortie : age( zstd( <DUMP B1> ) ). Les couches age+zstd sont IDENTIQUES au legacy
// -- SEULE la charge utile change. Le restore DISTINGUE les deux par le MARQUEUR de tête de la
// charge décompressée : `SQLite format 3\0` = ancien backup (age(zstd(fichier SQLite clair)))
// -> legacy ; `DUMP_MAGIC` = backup B1 -> streaming. -> rétrocompat TOTALE des backups EXISTANTS.
//
// FIDÉLITÉ (DATA-LOSS-CRITICAL) : chaque cellule est lue via ValueRef (classe de stockage EXACTE
// Null/Integer/Real/Text/Blob) et sérialisée SANS PERTE :
//   - Real -> f64::to_bits (8 o) : bit-exact, PAS de formatage décimal (0 perte de précision ;
//     -0.0, sous-normaux, NaN/Inf inclus).
//   - Blob -> octets BRUTS (longueur-préfixée) : octets nuls / 0xFF préservés.
//   - Text -> octets UTF-8 BRUTS (plume garantit l'UTF-8). Un TEXT non-UTF8 (valeur légale en SQLite
//     mais non représentable en dump typé) -> classé `PlanErr::Unsupported` (comme un schéma non-B1) :
//     l'appelant REPLIE AUTOMATIQUEMENT sur le legacy (sqlcipher_export copie les octets VERBATIM) ->
//     jamais de perte silencieuse, jamais un backup qui plante. NB : distinct d'une vraie panne
//     IO/chiffrement (Fatal) qui, elle, ne doit PAS être masquée par un fallback (risque de boucle).
//   - Integer/Null -> exacts.
// Au restore on RE-LIE (bind) ces Value dans un INSERT préparé : l'AFFINITÉ de colonne est
// ré-appliquée à l'IDENTIQUE (même schéma) -> IDEMPOTENTE -> classe de stockage reproduite
// exactement. rowid préservé (colonne alias INTEGER PRIMARY KEY, ou `rowid` explicite pour les
// tables rowid sans alias). sqlite_sequence (compteurs AUTOINCREMENT) préservé -> pas de
// réutilisation de rowid après restore.
//
// SCHÉMA : capturé depuis sqlite_master (tables/index/triggers/vues + colonnes ALTERées). Les FTS5
// à CONTENU EXTERNE (content='<table réelle>', ex: event_fts) sont RECONSTRUITES par `rebuild`
// depuis leur table de contenu (index DÉRIVÉ -> fidélité FONCTIONNELLE, correcte car le contenu
// source EST préservé bit-à-bit). Toute forme de schéma que B1 NE PEUT représenter fidèlement
// (FTS contentless `content=''` ex: event_fields_fts, FTS régulière, autre vtable) est DÉTECTÉE
// AVANT toute écriture -> REPLI AUTOMATIQUE sur le legacy (sqlcipher_export copie les shadow tables
// bit-à-bit). -> jamais de perte ; au pire pas d'élimination du clair pour ces schémas opt-in.
//
// 2 Gio-SAFE : lecture ligne-à-ligne via le pager SQLite (cache borné) + sérialisation immédiate
// dans le flux zstd -> au plus 1 ligne + buffers en RAM, JAMAIS toute la DB, JAMAIS de clair sur
// disque. Snapshot cohérent : lecture sous transaction ouverte (BEGIN) -> vue figée même si la DB
// de prod est écrite en parallèle.
// Le PLANCHER est structurel, pas espéré : `write_value_ref` sérialise la cellule EMPRUNTÉE au pager
// (`ValueRef`) sans la recopier, rien n'est retenu d'une ligne à l'autre, et aucun tampon ne grandit
// avec le nombre de lignes. Une LIGNE énorme coûte donc sa propre taille, pas celle de sa table :
// mesuré (`backup_streaming_carries_multi_mib_blobs_within_a_bounded_memory_delta`, 2026-08-08) sur
// 16 BLOB de 4 Mio = 64 Mio de charge -> PIC RSS à +20 Mio au-dessus de la référence, soit l'ordre de
// grandeur d'UNE ligne plus les tampons, pas celui de la base. La borne restante est le champ unique :
// `rd_bytes` alloue la valeur entière à la relecture, donc une cellule de 1 Gio coûterait 1 Gio.
//
// ----------------------------------------------------------------------------
// CE QUE LE DUMP N'EMPORTE PAS — l'échange, nommé et mesuré.
// ----------------------------------------------------------------------------
// L'ancien format était une DB SQLite COMPLÈTE : il emportait donc AUSSI les index B-tree, les tables
// shadow FTS5 (`*_data`/`*_idx`/`*_docsize`/`*_config`), les `sqlite_stat*` et les pages libres de la
// fragmentation. Le dump typé n'emporte QUE le DDL et les LIGNES ; tout le reste est DÉRIVÉ et se
// reconstruit à la restauration (`CREATE INDEX` rejoués, `INSERT INTO <fts>(<fts>) VALUES('rebuild')`).
// Ce n'est pas une perte de données — c'est un déplacement de coût de la sauvegarde vers la restauration.
//
// MESURE (`backup_streaming_is_smaller_than_the_plaintext_export_on_the_same_db`, 2026-08-08), MÊME base
// au schéma RÉEL de plume : 20 000 événements, `event_fts` peuplée, base SQLCipher de 7 221 248 o.
//     chemin        charge sérialisée   `.age` produit
//     streaming        3 714 129 o         321 017 o
//     historique       6 758 400 o         780 941 o
// Soit un `.age` 2,4x PLUS PETIT. La TAILLE est stable d'une exécution à l'autre ; le TEMPS de
// restauration, lui, ne l'est pas, et il faut le dire ainsi plutôt que de citer un chiffre unique :
//     suite en série (machine au repos)   : streaming 2 640 ms  vs historique 2 366 ms   (+12 %)
//     suite complète en parallèle         : streaming 4 614 ms  vs historique 1 936 ms   (+138 %)
// La reconstruction des index et de la FTS est du CPU pur : sous contention elle se dégrade bien plus
// vite que la simple recopie de pages du chemin historique. L'ORDRE est constant (le streaming restaure
// toujours plus lentement), l'AMPLEUR dépend de la charge de la machine — à provisionner dans le RTO
// comme un facteur pouvant approcher 2,5x, pas comme un surcoût de 20 %.
// Sur la base de PRODUCTION l'écart de TAILLE est structurellement plus grand encore : index + FTS y
// pesaient 644 Mio sur 1 494 Mio mesurés le 2026-08-08, soit 43 % du fichier — exactement la part que le
// dump n'emporte pas. La contrepartie grandit dans le même sens : plus il y a d'index à ne pas
// transporter, plus il y en a à reconstruire au restore.
//
// ----------------------------------------------------------------------------
// DÉFAUT, PAS OPT-IN — et pourquoi ce sens-là.
// ----------------------------------------------------------------------------
// Le streaming est le chemin par DÉFAUT ; l'ancien reste joignable par
// `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1` (`backup_force_plaintext_export`). Trois raisons de ne pas
// avoir laissé le défaut sur l'ancien : (1) la propriété achetée — pas de clair sur disque — ne vaut
// que si elle est prise par le chemin réellement emprunté en production, et un opt-in ne l'est jamais ;
// (2) le seul risque du streaming est une infidélité de représentation, et il est FERMÉ AVANT ÉCRITURE
// par le repli automatique (`PlanErr::Unsupported`) : un schéma ou une valeur qu'il ne sait pas rendre
// bit-à-bit ne produit pas un backup dégradé, il produit un backup de l'ANCIEN format ; (3) la
// restauration lit les DEUX formats au marqueur, donc basculer le défaut ne périme aucune sauvegarde
// déjà en séquestre. Le sens inverse — laisser l'ancien par défaut — aurait gardé la fenêtre de clair
// ouverte en échange d'aucune sécurité supplémentaire.
// ============================================================================

/// Marqueur de tête du DUMP B1 (11 octets). NE COLLISIONNE PAS avec `SQLite format 3\0` (les octets
/// diffèrent dès le 1er) -> le restore distingue B1 (streaming) de l'ancien format (fichier SQLite).
pub(crate) const DUMP_MAGIC: &[u8; 11] = b"PLUMEDUMP1\n";

/// Borne anti-OOM d'une valeur/chaîne lue depuis le dump (post-AEAD, donc déjà intègre : l'age
/// authentifie ; une altération -> échec de déchiffrement). Plancher > SQLITE_MAX_LENGTH (1 Gio).
const DUMP_MAX_FIELD: usize = 2 << 30; // 2 Gio

// -- primitives d'encodage little-endian, longueur-préfixée (format auto-descriptif, parse en flux) --
fn wr_u8<W: std::io::Write>(w: &mut W, v: u8) -> std::io::Result<()> { w.write_all(&[v]) }
fn wr_u16<W: std::io::Write>(w: &mut W, v: u16) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_u32<W: std::io::Write>(w: &mut W, v: u32) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_u64<W: std::io::Write>(w: &mut W, v: u64) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_i64<W: std::io::Write>(w: &mut W, v: i64) -> std::io::Result<()> { w.write_all(&v.to_le_bytes()) }
fn wr_bytes<W: std::io::Write>(w: &mut W, b: &[u8]) -> std::io::Result<()> { wr_u32(w, b.len() as u32)?; w.write_all(b) }
fn wr_str<W: std::io::Write>(w: &mut W, s: &str) -> std::io::Result<()> { wr_bytes(w, s.as_bytes()) }

fn rd_u8<R: std::io::Read>(r: &mut R) -> std::io::Result<u8> { let mut b = [0u8; 1]; r.read_exact(&mut b)?; Ok(b[0]) }
fn rd_u16<R: std::io::Read>(r: &mut R) -> std::io::Result<u16> { let mut b = [0u8; 2]; r.read_exact(&mut b)?; Ok(u16::from_le_bytes(b)) }
fn rd_u32<R: std::io::Read>(r: &mut R) -> std::io::Result<u32> { let mut b = [0u8; 4]; r.read_exact(&mut b)?; Ok(u32::from_le_bytes(b)) }
fn rd_u64<R: std::io::Read>(r: &mut R) -> std::io::Result<u64> { let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(u64::from_le_bytes(b)) }
fn rd_i64<R: std::io::Read>(r: &mut R) -> std::io::Result<i64> { let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(i64::from_le_bytes(b)) }
fn rd_bytes<R: std::io::Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let n = rd_u32(r)? as usize;
    if n > DUMP_MAX_FIELD { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("champ dump surdimensionné ({n} o) — corrompu"))); }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}
fn rd_str<R: std::io::Read>(r: &mut R) -> std::io::Result<String> {
    let b = rd_bytes(r)?;
    String::from_utf8(b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Writer transparent qui COMPTE les octets écrits (mesure la taille du DUMP EN CLAIR, pour le log/stat
/// de ratio) sans jamais matérialiser le clair.
struct CountWriter<'a, W: std::io::Write + 'a> { inner: &'a mut W, count: u64 }
impl<'a, W: std::io::Write + 'a> std::io::Write for CountWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { let n = self.inner.write(buf)?; self.count += n as u64; Ok(n) }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}

/// Cite un identifiant SQL (table/colonne) — double-quote + échappe les `"` internes.
fn quote_ident(name: &str) -> String { format!("\"{}\"", name.replace('"', "\"\"")) }

/// Sérialise UNE cellule (ValueRef -> flux typé). Text validé UTF-8 (invariant plume ; sinon la VALEUR
/// n'est pas représentable en dump typé -> `PlanErr::Unsupported` qui DÉCLENCHE le repli legacy, PAS une
/// erreur Fatale qui planterait tout le backup). Real via to_bits (bit-exact). Blob/octets bruts.
/// DISTINCTION CRITIQUE : une VALEUR non-représentable (TEXT non-UTF8) est RÉCUPÉRABLE via le legacy
/// (sqlcipher_export copie les octets verbatim) -> `Unsupported` ; une vraie erreur d'écriture flux
/// (IO/zstd/age) est une PANNE -> `Fatal` (jamais masquée par un fallback qui pourrait boucler). `table`
/// pour le message.
fn write_value_ref<W: std::io::Write>(w: &mut W, v: rusqlite::types::ValueRef, table: &str) -> Result<(), PlanErr> {
    use rusqlite::types::ValueRef as VR;
    let r = match v {
        VR::Null => wr_u8(w, 0),
        VR::Integer(i) => wr_u8(w, 1).and_then(|_| wr_i64(w, i)),
        VR::Real(f) => wr_u8(w, 2).and_then(|_| wr_u64(w, f.to_bits())),
        VR::Text(bytes) => {
            if std::str::from_utf8(bytes).is_err() {
                // VALEUR non fidèlement représentable en dump typé -> repli legacy (byte-verbatim), PAS Fatal.
                return Err(PlanErr::Unsupported(format!(
                    "TEXT non-UTF8 dans la table {table} — valeur non représentable en dump typé B1 (repli legacy octet-à-octet)")));
            }
            wr_u8(w, 3).and_then(|_| wr_bytes(w, bytes))
        }
        VR::Blob(bytes) => wr_u8(w, 4).and_then(|_| wr_bytes(w, bytes)),
    };
    r.map_err(|e| PlanErr::Fatal(format!("écriture valeur ({table}) : {e}")))
}

/// Désérialise UNE cellule (flux typé -> Value liable par bind). Reproduit exactement la classe de
/// stockage source.
fn read_value<R: std::io::Read>(r: &mut R) -> Result<rusqlite::types::Value, String> {
    use rusqlite::types::Value as V;
    let tag = rd_u8(r).map_err(|e| format!("lecture tag valeur : {e}"))?;
    let v = match tag {
        0 => V::Null,
        1 => V::Integer(rd_i64(r).map_err(|e| format!("lecture INTEGER : {e}"))?),
        2 => V::Real(f64::from_bits(rd_u64(r).map_err(|e| format!("lecture REAL : {e}"))?)),
        3 => V::Text(rd_str(r).map_err(|e| format!("lecture TEXT : {e}"))?),
        4 => V::Blob(rd_bytes(r).map_err(|e| format!("lecture BLOB : {e}"))?),
        other => return Err(format!("B1: tag de valeur inconnu {other} (dump corrompu)")),
    };
    Ok(v)
}

/// Erreur de collecte du plan : `Unsupported` -> l'appelant REPLIE sur le legacy (schéma non
/// représentable en dump typé) ; `Fatal` -> vraie erreur (DB illisible, IO...).
enum PlanErr { Unsupported(String), Fatal(String) }

struct TableDump { name: String, select_sql: String, insert_sql: String, ncols: usize }
enum PostStep { Sql(String), FtsRebuild(String) }
struct DumpPlan {
    pre_ddl: Vec<String>,      // CREATE TABLE des tables ordinaires
    tables: Vec<TableDump>,    // données à streamer (dans l'ordre pre_ddl)
    seqs: Vec<(String, i64)>,  // sqlite_sequence (compteurs AUTOINCREMENT)
    post: Vec<PostStep>,       // vtables + rebuild + index + triggers + vues, dans l'ordre d'application
}

/// `CREATE VIRTUAL TABLE ...` ?
fn is_virtual_table(sql: &str) -> bool { sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE") }

/// Table de contenu d'une FTS (3/4/5) à CONTENU EXTERNE (`content='X'`, X non vide) -> Some(X).
/// contentless (`content=''`), FTS régulière (pas de content=) ou pas FTS -> None (= NON B1-safe).
fn fts_external_content(sql: &str) -> Option<String> {
    let up = sql.to_ascii_uppercase();
    if !(up.contains("USING FTS5") || up.contains("USING FTS4") || up.contains("USING FTS3")) { return None; }
    let low = sql.to_ascii_lowercase();
    let mut idx = 0usize;
    while let Some(pos) = low[idx..].find("content") {
        let after = idx + pos + "content".len();
        idx = after;
        let rest = sql[after..].trim_start();
        if rest.starts_with('_') { continue; }       // content_rowid -> pas la clé content
        if !rest.starts_with('=') { continue; }
        let after_eq = rest[1..].trim_start();
        let q = match after_eq.chars().next() { Some(c) if c == '\'' || c == '"' => c, _ => continue };
        let body = &after_eq[1..];
        if let Some(endq) = body.find(q) {
            let val = &body[..endq];
            if val.is_empty() { return None; }        // content='' -> contentless
            return Some(val.to_string());
        }
    }
    None
}

/// Construit le plan de dump d'UNE table ordinaire : liste de colonnes + SELECT/INSERT.
/// Préserve le rowid : via l'alias INTEGER PRIMARY KEY quand il existe, sinon en préfixant `rowid`
/// explicitement (tables rowid sans alias) — sauf WITHOUT ROWID (pas de rowid).
fn build_table_dump(conn: &Connection, name: &str, create_sql: &str) -> Result<TableDump, String> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_ident(name)))
        .map_err(|e| format!("table_info {name} : {e}"))?;
    let cols: Vec<(String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(5)?))) // name, type, pk
        .map_err(|e| format!("table_info map {name} : {e}"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| format!("table_info collect {name} : {e}"))?;
    if cols.is_empty() { return Err(format!("table {name} sans colonnes")); }

    let without_rowid = create_sql.to_ascii_uppercase().replace([' ', '\t', '\n', '\r'], "").contains("WITHOUTROWID");
    let pk_cols: Vec<&(String, String, i64)> = cols.iter().filter(|c| c.2 > 0).collect();
    let has_int_pk_alias = pk_cols.len() == 1 && pk_cols[0].1.eq_ignore_ascii_case("INTEGER");
    let prepend_rowid = !without_rowid && !has_int_pk_alias;

    let mut sel_cols: Vec<String> = Vec::new();
    let mut ins_cols: Vec<String> = Vec::new();
    if prepend_rowid { sel_cols.push("rowid".into()); ins_cols.push("rowid".into()); }
    for (cn, _, _) in &cols { sel_cols.push(quote_ident(cn)); ins_cols.push(quote_ident(cn)); }
    let ncols = sel_cols.len();
    let select_sql = format!("SELECT {} FROM {}", sel_cols.join(", "), quote_ident(name));
    let placeholders = std::iter::repeat("?").take(ncols).collect::<Vec<_>>().join(", ");
    let insert_sql = format!("INSERT INTO {} ({}) VALUES ({})", quote_ident(name), ins_cols.join(", "), placeholders);
    Ok(TableDump { name: name.to_string(), select_sql, insert_sql, ncols })
}

/// Collecte le PLAN de dump depuis sqlite_master. Renvoie `Unsupported` (AVANT toute écriture) si le
/// schéma contient une table virtuelle non représentable en dump typé -> repli legacy propre.
fn collect_dump_plan(conn: &Connection) -> Result<DumpPlan, PlanErr> {
    let mut stmt = conn.prepare("SELECT type, name, COALESCE(sql,'') FROM sqlite_master ORDER BY rowid")
        .map_err(|e| PlanErr::Fatal(format!("prepare sqlite_master : {e}")))?;
    let master: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        .map_err(|e| PlanErr::Fatal(format!("query sqlite_master : {e}")))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| PlanErr::Fatal(format!("collect sqlite_master : {e}")))?;

    // tables virtuelles + set des shadow tables (<vt>_<suffixe>).
    // RISQUE LATENT (collision de nom) : ce set est HEURISTIQUE — il matche par NOM (<vtable>_<suffixe>),
    // pas par rattachement réel. Une vraie table UTILISATEUR nommée `<vt>_data`/`_idx`/... alors qu'une
    // vtable `<vt>` existe serait skippée du dump SANS erreur (perte silencieuse). AUJOURD'HUI INOFFENSIF :
    //   (1) le seul suffixe n'est ajouté que pour des vtables RÉELLEMENT présentes (`for vt in &vtables`) ;
    //   (2) le schéma plume actuel n'a AUCUNE table utilisateur de cette forme ;
    //   (3) en pratique SQLite REFUSE la coexistence — créer la vtable `<vt>` échoue si `<vt>_data` existe
    //       déjà (nom de shadow pris), et inversement -> les deux ne cohabitent pas dans une DB vivante.
    // Un durcissement exact (n'exclure que les shadow tables réellement rattachées) exige une détection
    // fiable non triviale (pas de flag propre en sqlite_master) -> laissé en l'état, risque documenté.
    let vtables: Vec<&String> = master.iter().filter(|(ty, _, sql)| ty == "table" && is_virtual_table(sql)).map(|(_, n, _)| n).collect();
    let shadow_suffixes = ["data", "idx", "docsize", "config", "content", "row", "segments", "segdir", "stat"];
    let mut shadow: std::collections::HashSet<String> = std::collections::HashSet::new();
    for vt in &vtables { for s in shadow_suffixes { shadow.insert(format!("{vt}_{s}")); } }

    let ordinary_names: std::collections::HashSet<String> = master.iter()
        .filter(|(ty, name, sql)| ty == "table" && !is_virtual_table(sql) && !name.starts_with("sqlite_") && !shadow.contains(name.as_str()))
        .map(|(_, name, _)| name.clone())
        .collect();

    let mut plan = DumpPlan { pre_ddl: vec![], tables: vec![], seqs: vec![], post: vec![] };
    let (mut virt_creates, mut rebuilds, mut indexes, mut triggers, mut views) =
        (Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new());

    for (ty, name, sql) in &master {
        match ty.as_str() {
            "table" => {
                if is_virtual_table(sql) {
                    match fts_external_content(sql) {
                        Some(content_table) if ordinary_names.contains(&content_table) => {
                            virt_creates.push(sql.clone());
                            rebuilds.push(name.clone());
                        }
                        _ => return Err(PlanErr::Unsupported(format!(
                            "table virtuelle {name} non représentable en dump typé (FTS contentless/régulière ou vtable non-FTS)"))),
                    }
                } else if name.starts_with("sqlite_") {
                    // sqlite_sequence : compteurs AUTOINCREMENT (données capturées plus bas, CREATE auto).
                    // sqlite_stat* / sqlite_autoindex_* : advisory/auto -> ignorés (régénérés par ANALYZE / à la création d'index).
                } else if shadow.contains(name.as_str()) {
                    // shadow d'une vtable -> recréée+repeuplée par le rebuild.
                } else {
                    plan.pre_ddl.push(sql.clone());
                    let td = build_table_dump(conn, name, sql).map_err(PlanErr::Fatal)?;
                    plan.tables.push(td);
                }
            }
            "index" => { if !sql.is_empty() { indexes.push(sql.clone()); } } // sqlite_autoindex_* -> sql vide -> skip
            "trigger" => { if !sql.is_empty() { triggers.push(sql.clone()); } }
            "view" => { if !sql.is_empty() { views.push(sql.clone()); } }
            _ => {}
        }
    }

    // sqlite_sequence : capture les compteurs (préserve la fenêtre AUTOINCREMENT -> anti-réutilisation rowid).
    if master.iter().any(|(ty, name, _)| ty == "table" && name == "sqlite_sequence") {
        let mut s = conn.prepare("SELECT name, seq FROM sqlite_sequence")
            .map_err(|e| PlanErr::Fatal(format!("prepare sqlite_sequence : {e}")))?;
        plan.seqs = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| PlanErr::Fatal(format!("query sqlite_sequence : {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| PlanErr::Fatal(format!("collect sqlite_sequence : {e}")))?;
    }

    // ordre d'application post : vtables -> rebuilds -> index -> triggers -> vues.
    for s in virt_creates { plan.post.push(PostStep::Sql(s)); }
    for n in rebuilds { plan.post.push(PostStep::FtsRebuild(n)); }
    for s in indexes { plan.post.push(PostStep::Sql(s)); }
    for s in triggers { plan.post.push(PostStep::Sql(s)); }
    for s in views { plan.post.push(PostStep::Sql(s)); }
    Ok(plan)
}

/// Sérialise le DUMP B1 (magic + schéma + données + sqlite_sequence + post-DDL) dans `w` (le flux
/// zstd->age). Lit les lignes en flux via le pager SQLite -> RAM bornée.
fn dump_stream<W: std::io::Write>(conn: &Connection, plan: &DumpPlan, w: &mut W) -> Result<(), PlanErr> {
    // Erreurs d'ÉCRITURE FLUX (IO/zstd/age) et de LECTURE DB (prepare/query) = vraies PANNES -> Fatal.
    // SEULE une valeur non représentable (write_value_ref -> Unsupported) déclenche le repli legacy.
    let we = |r: std::io::Result<()>| r.map_err(|e| PlanErr::Fatal(format!("dump : écriture flux : {e}")));
    we(w.write_all(DUMP_MAGIC))?;
    // section 1 : pre-DDL (CREATE TABLE).
    we(wr_u32(w, plan.pre_ddl.len() as u32))?;
    for s in &plan.pre_ddl { we(wr_str(w, s))?; }
    // section 2 : données.
    we(wr_u32(w, plan.tables.len() as u32))?;
    for t in &plan.tables {
        we(wr_str(w, &t.name))?;
        we(wr_u16(w, t.ncols as u16))?;
        we(wr_str(w, &t.insert_sql))?;
        let mut stmt = conn.prepare(&t.select_sql).map_err(|e| PlanErr::Fatal(format!("prepare select {} : {e}", t.name)))?;
        let mut rows = stmt.query([]).map_err(|e| PlanErr::Fatal(format!("query {} : {e}", t.name)))?;
        loop {
            match rows.next().map_err(|e| PlanErr::Fatal(format!("next {} : {e}", t.name)))? {
                Some(row) => {
                    we(wr_u8(w, 1))?; // ligne présente
                    for i in 0..t.ncols {
                        let vr = row.get_ref(i).map_err(|e| PlanErr::Fatal(format!("get_ref {} col {i} : {e}", t.name)))?;
                        write_value_ref(w, vr, &t.name)?;
                    }
                }
                None => { we(wr_u8(w, 0))?; break; } // fin de table
            }
        }
    }
    // section 3 : sqlite_sequence.
    we(wr_u32(w, plan.seqs.len() as u32))?;
    for (n, s) in &plan.seqs { we(wr_str(w, n))?; we(wr_i64(w, *s))?; }
    // section 4 : post-DDL.
    we(wr_u32(w, plan.post.len() as u32))?;
    for p in &plan.post {
        match p {
            PostStep::Sql(s) => { we(wr_u8(w, 1))?; we(wr_str(w, s))?; }
            PostStep::FtsRebuild(n) => { we(wr_u8(w, 2))?; we(wr_str(w, n))?; }
        }
    }
    we(wr_u8(w, 0xFF))?; // sentinelle de fin (détecte une troncature)
    Ok(())
}

/// B1 — SAUVEGARDE STREAMING (zéro clair transitoire). Ouvre la DB SQLCipher, fige un snapshot lecture
/// (BEGIN), collecte le plan (repli `Unsupported` AVANT toute écriture si schéma non-B1) puis dump ->
/// zstd -> age -> dest. Renvoie {plaintext_bytes(=taille du dump), dest_bytes, wrote_plaintext_to_disk=false}.
fn backup_compressed_stream(db_path: &str, dest: &str, pass: &str, recipient: Option<&str>) -> Result<BackupStats, PlanErr> {
    let conn = open_db_keyed_without_schema_contract(db_path, Some(pass)).map_err(|e| PlanErr::Fatal(format!("ouverture DB source : {e}")))?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| PlanErr::Fatal(format!("DB source illisible (clé PLUME_DB_KEY incorrecte ?) : {e}")))?;
    // BEGIN -> snapshot lecture figé pour toute la durée du dump (cohérence multi-tables, même sous écritures concurrentes).
    conn.execute_batch("BEGIN").map_err(|e| PlanErr::Fatal(format!("begin snapshot : {e}")))?;

    let plan = collect_dump_plan(&conn)?; // Unsupported -> repli AVANT toute écriture (rien créé).

    let _ = std::fs::remove_file(dest);
    let out = std::fs::File::create(dest).map_err(|e| PlanErr::Fatal(format!("création dest : {e}")))?;
    let out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
    // Chiffrement : ASYMÉTRIQUE (destinataire public age1..., escrow hors-cluster) si posé, sinon SYMÉTRIQUE
    // par passphrase (= clé SQLCipher) — IDENTIQUE au legacy.
    let encryptor = match recipient {
        Some(rcpt) if !rcpt.is_empty() => {
            let recipient = rcpt.parse::<age::x25519::Recipient>()
                .map_err(|e| PlanErr::Fatal(format!("destinataire age invalide (clé publique age1... attendue) : {e}")))?;
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| PlanErr::Fatal(format!("age with_recipients : {e}")))?
        }
        _ => age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(pass.to_string())),
    };
    let age_w = encryptor.wrap_output(out).map_err(|e| PlanErr::Fatal(format!("age wrap_output : {e}")))?;
    let mut z = zstd::Encoder::new(age_w, BACKUP_ZSTD_LEVEL).map_err(|e| PlanErr::Fatal(format!("init zstd : {e}")))?;
    let plaintext_bytes = {
        let mut cw = CountWriter { inner: &mut z, count: 0 };
        // dump_stream renvoie déjà un PlanErr TYPÉ : Unsupported (valeur non représentable, ex. TEXT
        // non-UTF8) -> repli legacy propre par l'appelant ; Fatal (IO/DB) -> vraie panne. On propage tel quel.
        dump_stream(&conn, &plan, &mut cw)?;
        cw.count
    };
    let age_w = z.finish().map_err(|e| PlanErr::Fatal(format!("finalisation zstd : {e}")))?;
    age_w.finish().map_err(|e| PlanErr::Fatal(format!("finalisation age : {e}")))?;
    let _ = conn.execute_batch("COMMIT"); // fin du snapshot (lecture seule).

    let dest_bytes = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    Ok(BackupStats { plaintext_bytes, dest_bytes, wrote_plaintext_to_disk: false })
}

/// SAUVEGARDE COMPRESSÉE+CHIFFRÉE — B1 par défaut (dump STREAMING, ZÉRO clair transitoire) avec REPLI
/// automatique sur le legacy (sqlcipher_export -> plaintext temporaire éphémère) pour les schémas non
/// représentables en dump typé (FTS contentless/régulière...). Format de sortie IDENTIQUE dans les
/// deux cas : age(zstd(<charge>)) ; le restore distingue via le marqueur de tête. Requiert une clé non
/// vide. Renvoie {plaintext_bytes, dest_bytes, wrote_plaintext_to_disk}.
pub(crate) fn backup_compressed(db_path: &str, dest: &str, key: Option<&str>, recipient: Option<&str>) -> Result<BackupStats, String> {
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
    };
    // GATE FAIL-CLOSED escrow (identique legacy) — AVANT toute écriture : refuse un backup symétrique si
    // l'asymétrique est EXIGÉ mais qu'aucun destinataire age n'est configuré.
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    if symmetric_fallback && backup_require_asymmetric() {
        return Err("backup REFUSÉ (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) : aucun PLUME_BACKUP_AGE_RECIPIENT \
                    (clé publique age1...) configuré -> un backup symétrique serait déchiffrable par le nœud \
                    (pas d'escrow hors-cluster). Configurez un destinataire age asymétrique, ou levez \
                    l'exigence pour un backup symétrique de dev.".into());
    }
    if symmetric_fallback {
        eprintln!(
            "[backup] ATTENTION : PLUME_BACKUP_AGE_RECIPIENT non configuré -> chiffrement SYMÉTRIQUE par \
             passphrase (= clé SQLCipher, présente sur le nœud). Ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS \
             d'escrow hors-cluster. Configurez une clé publique age (asymétrique, encrypt-only) pour un escrow \
             hors-cluster, ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli.");
    }
    // BALAYAGE DES ORPHELINS — à CHAQUE backup, quel que soit le chemin pris ensuite. Réape les plaintext
    // laissés par un run antérieur crashé/OOM-killé (Drop ne tourne pas sur SIGKILL). Cible le répertoire de
    // STAGING (PLUME_BACKUP_STAGING_DIR = volume éphémère si posé, sinon dossier de <dest>), seuil 1 h ->
    // épargne un backup concurrent en vol. Ne CRÉE rien : il ne fait que supprimer (la garde de staging vide
    // reste donc vraie pendant le chemin streaming).
    let stage_dir = staging_dir(dest);
    let n = sweep_orphan_temps(&stage_dir, std::time::Duration::from_secs(BACKUP_ORPHAN_MAX_AGE_SECS));
    if n > 0 { eprintln!("backup : {n} plaintext temporaire(s) orphelin(s) réapé(s) dans {}", stage_dir.display()); }

    // ÉCHAPPATOIRE OPÉRATEUR : retour explicite au chemin historique (plaintext matérialisé) sans rebuild.
    if backup_force_plaintext_export() {
        eprintln!("[backup] PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT posé -> chemin HISTORIQUE (sqlcipher_export) : \
                   la base ENTIÈRE est réécrite EN CLAIR dans le staging le temps du backup.");
        return backup_compressed_legacy(db_path, dest, key, recipient);
    }
    // B1 streaming d'abord ; repli legacy si le schéma n'est pas représentable en dump typé.
    match backup_compressed_stream(db_path, dest, &pass, recipient) {
        Ok(st) => Ok(st),
        Err(PlanErr::Unsupported(why)) => {
            eprintln!("[backup] schéma non-B1 ({why}) -> repli sur l'export legacy (plaintext temporaire éphémère)");
            backup_compressed_legacy(db_path, dest, key, recipient)
        }
        Err(PlanErr::Fatal(e)) => {
            let _ = std::fs::remove_file(dest); // pas de backup partiel/trompeur.
            Err(e)
        }
    }
}

/// B1 — RESTORE STREAMING : rejoue un DUMP B1 (déjà déchiffré+dézstd, le magic étant déjà consommé par
/// l'appelant) dans une DB SQLCipher NEUVE `dest_db`. ZÉRO clair sur disque. Tout dans UNE transaction
/// (atomique). Ordre : pre-DDL (tables) -> données (INSERT bindés, types EXACTS) -> sqlite_sequence ->
/// post-DDL (vtables + rebuild FTS + index + triggers + vues).
fn restore_stream<R: std::io::Read>(r: &mut R, dest_db: &str, pass: &str) -> Result<(), String> {
    let re = |x: std::io::Result<u32>| x.map_err(|e| format!("restore : lecture flux : {e}"));
    let conn = open_db_keyed_without_schema_contract(dest_db, Some(pass)).map_err(|e| format!("ouverture dest SQLCipher : {e}"))?;
    let _ = conn.execute_batch("PRAGMA foreign_keys=OFF;"); // ordre d'insertion libre pendant le chargement
    conn.execute_batch("BEGIN").map_err(|e| format!("begin restore : {e}"))?;

    // section 1 : pre-DDL (CREATE TABLE) — crée AUSSI sqlite_sequence si tables AUTOINCREMENT.
    let n_pre = re(rd_u32(r))?;
    for _ in 0..n_pre {
        let sql = rd_str(r).map_err(|e| format!("restore : lecture pre-DDL : {e}"))?;
        conn.execute_batch(&sql).map_err(|e| format!("CREATE TABLE (restore) : {e}"))?;
    }
    // section 2 : données.
    let n_tables = re(rd_u32(r))?;
    for _ in 0..n_tables {
        let name = rd_str(r).map_err(|e| format!("restore : nom table : {e}"))?;
        let ncols = rd_u16(r).map_err(|e| format!("restore : ncols {name} : {e}"))? as usize;
        let insert_sql = rd_str(r).map_err(|e| format!("restore : insert_sql {name} : {e}"))?;
        let mut stmt = conn.prepare(&insert_sql).map_err(|e| format!("prepare INSERT {name} : {e}"))?;
        loop {
            let tag = rd_u8(r).map_err(|e| format!("restore : tag ligne {name} : {e}"))?;
            if tag == 0 { break; }
            if tag != 1 { return Err(format!("restore : tag de ligne inconnu {tag} (table {name})")); }
            let mut vals: Vec<rusqlite::types::Value> = Vec::with_capacity(ncols);
            for _ in 0..ncols { vals.push(read_value(r)?); }
            stmt.execute(rusqlite::params_from_iter(vals.iter())).map_err(|e| format!("INSERT {name} : {e}"))?;
        }
    }
    // section 3 : sqlite_sequence (reproduit EXACTEMENT les compteurs — DELETE puis INSERT, comme SQLite .dump).
    let n_seq = re(rd_u32(r))?;
    if n_seq > 0 {
        let _ = conn.execute_batch("DELETE FROM sqlite_sequence;");
        let mut s = conn.prepare("INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)").map_err(|e| format!("prepare seq : {e}"))?;
        for _ in 0..n_seq {
            let name = rd_str(r).map_err(|e| format!("restore : nom seq : {e}"))?;
            let seq = rd_i64(r).map_err(|e| format!("restore : valeur seq : {e}"))?;
            s.execute(rusqlite::params![name, seq]).map_err(|e| format!("insert seq {name} : {e}"))?;
        }
    }
    // section 4 : post-DDL (vtables, rebuild FTS, index, triggers, vues).
    let n_post = re(rd_u32(r))?;
    for _ in 0..n_post {
        let tag = rd_u8(r).map_err(|e| format!("restore : tag post-DDL : {e}"))?;
        match tag {
            1 => { let sql = rd_str(r).map_err(|e| format!("restore : post-DDL sql : {e}"))?; conn.execute_batch(&sql).map_err(|e| format!("post-DDL (restore) : {e}"))?; }
            2 => {
                let name = rd_str(r).map_err(|e| format!("restore : nom rebuild : {e}"))?;
                let rebuild = format!("INSERT INTO {0}({0}) VALUES('rebuild');", quote_ident(&name));
                conn.execute_batch(&rebuild).map_err(|e| format!("rebuild FTS {name} : {e}"))?;
            }
            other => return Err(format!("restore : tag post-DDL inconnu {other}")),
        }
    }
    // sentinelle de fin.
    let tr = rd_u8(r).map_err(|e| format!("restore : lecture sentinelle : {e}"))?;
    if tr != 0xFF { return Err(format!("restore : sentinelle de fin absente (0x{tr:02X}) — dump tronqué/corrompu")); }
    conn.execute_batch("COMMIT").map_err(|e| format!("commit restore : {e}"))?;
    Ok(())
}

/// RESTAURATION (rejouabilité) — gère les DEUX formats via le MARQUEUR de tête de la charge décompressée :
///  - B1 (`DUMP_MAGIC`)     : rejoue le dump typé dans une DB SQLCipher NEUVE en STREAMING. ZÉRO clair
///    sur disque (`restore_stream`).
///  - LEGACY (`SQLite ...`) : age décrypte -> zstd décode -> DB SQLite EN CLAIR temporaire, puis
///    `sqlcipher_export` -> `<dest_db>` chiffré (garde RAII efface le temporaire).
/// Dans les deux cas : age auto-détecte le stanza (scrypt/passphrase = anciens backups symétriques ;
/// x25519 = identité PRIVÉE escrow si fournie). REFUSE d'écraser `<dest_db>` sauf `overwrite=true`.
pub(crate) fn restore_compressed(src: &str, dest_db: &str, key: Option<&str>, overwrite: bool, identity: Option<&age::x25519::Identity>) -> Result<(), String> {
    use std::io::Read;
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("restore : PLUME_DB_KEY requis (passphrase age)".into()),
    };
    if std::path::Path::new(dest_db).exists() && !overwrite {
        return Err(format!("restore : {dest_db} existe déjà — relancer avec --force pour écraser"));
    }

    // 1) age décrypte -> zstd décode -> flux clair EN MÉMOIRE (jamais tout sur disque pour B1).
    let f = std::fs::File::open(src).map_err(|e| format!("ouverture src : {e}"))?;
    let r = std::io::BufReader::with_capacity(BACKUP_BUF, f);
    let decryptor = age::Decryptor::new_buffered(r).map_err(|e| format!("en-tête age : {e}"))?;
    // AUTO-DÉTECTION : on présente à age DEUX identités et il apparie selon le stanza de l'en-tête :
    //   (1) scrypt/passphrase (= clé SQLCipher) -> anciens backups SYMÉTRIQUES (rétrocompat) ;
    //   (2) x25519 (identité PRIVÉE escrow, si PLUME_BACKUP_AGE_IDENTITY[_FILE] fournie) -> backups ASYMÉTRIQUES.
    let scrypt_id = age::scrypt::Identity::new(age::secrecy::SecretString::from(pass.clone()));
    let mut ids: Vec<&dyn age::Identity> = vec![&scrypt_id as &dyn age::Identity];
    if let Some(x) = identity { ids.push(x as &dyn age::Identity); }
    let reader = decryptor
        .decrypt(ids.into_iter())
        .map_err(|e| format!("déchiffrement age (passphrase / identité age incorrecte ou absente ?) : {e}"))?;
    let mut zd = zstd::Decoder::new(reader).map_err(|e| format!("init zstd : {e}"))?;

    // 2) MARQUEUR de format : lit les 1ers octets de la charge décompressée pour aiguiller B1 vs legacy.
    let mut magic = [0u8; 11];
    zd.read_exact(&mut magic).map_err(|e| format!("lecture marqueur de format (charge trop courte / corrompue ?) : {e}"))?;

    if &magic == DUMP_MAGIC {
        // --- FORMAT B1 (dump typé streaming) : rejoue dans une DB SQLCipher NEUVE. AUCUN clair sur disque.
        for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_db}{ext}")); }
        restore_stream(&mut zd, dest_db, &pass)
    } else if magic.starts_with(b"SQLite") {
        // --- FORMAT LEGACY (age(zstd(fichier SQLite clair))) : plaintext temporaire + sqlcipher_export.
        let tmp_guard = PlaintextTempGuard(plain_temp_path(dest_db));
        let tmp_plain = tmp_guard.path().to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&tmp_plain);
        {
            let out = std::fs::File::create(&tmp_plain).map_err(|e| format!("création plaintext : {e}"))?;
            let mut out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
            // ré-injecte les octets de tête déjà consommés pour la détection, puis stream le reste.
            std::io::Write::write_all(&mut out, &magic).map_err(|e| format!("écriture en-tête plaintext : {e}"))?;
            stream_copy(&mut zd, &mut out).map_err(|e| format!("flux unzstd : {e}"))?;
            std::io::Write::flush(&mut out).map_err(|e| format!("flush plaintext : {e}"))?;
        }
        for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_db}{ext}")); }
        {
            let conn = open_db_keyed_without_schema_contract(&tmp_plain, None).map_err(|e| format!("ouverture plaintext : {e}"))?;
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
                .map_err(|e| format!("plaintext illisible (passphrase invalide ?) : {e}"))?;
            let sql = format!(
                "ATTACH DATABASE '{}' AS enc KEY '{}'; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;",
                dest_db.replace('\'', "''"), pass.replace('\'', "''"));
            conn.execute_batch(&sql).map_err(|e| format!("re-chiffrement (sqlcipher_export) : {e}"))?;
        }
        Ok(())
    } else {
        Err(format!("restore : format de charge inconnu (ni dump B1 ni fichier SQLite) — backup corrompu ? tête={magic:?}"))
    }
}

// ============================================================================
// RÉTENTION GFS À PALIERS (grandfather-father-son) — sous-commande `backup-prune-plan`.
// ----------------------------------------------------------------------------
// LOGIQUE DE SÉLECTION PURE : lit une liste de NOMS d'objets (base-names ou clés complètes),
// calcule les noms à SUPPRIMER, ne touche JAMAIS S3/MinIO (le sidecar garde `mc`). Testable en
// isolation (fonction pure `names + now + params -> noms à supprimer`). Le rayon de souffle reste
// minuscule : ZÉRO capacité de suppression / crédential S3 dans le daemon.
//
// FORMAT DES NOMS (cf. scope) :
//   - régulier   : `plume-<TS>.db.age`                (backup 2h)
//   - premigrate : `premigrate-<sha>-<TS>.db.age`     (snapshot pré-migration)
//   avec `<TS> = YYYYMMDDTHHMMSSZ` (UTC, `date -u +%Y%m%dT%H%M%SZ`) -> tri lexicographique ==
//   chronologique. Une clé COMPLÈTE (`premigrate/premigrate-...`) est routée par son BASE-NAME.
//
// ALGORITHME (par palier, sur le set RÉGULIER ; premigrate = keep-N) :
//   age < DENSE_DAYS           -> KEEP tout           (granularité 2h)
//   DENSE_DAYS  <= age < DAILY  -> KEEP le DERNIER (max TS) par jour civil UTC
//   DAILY_DAYS  <= age < WEEKLY -> KEEP le DERNIER (max TS) par semaine ISO (lun-dim)
//   age >= WEEKLY_DAYS          -> DROP
//   premigrate                 -> KEEP les PREMIGRATE_KEEP plus récents (par TS), DROP le reste
//
// INVARIANTS DE SÛRETÉ (fail-safe / keep-if-unsure — tous testés) :
//   1. le régulier LE PLUS récent n'est JAMAIS supprimé (garde inconditionnelle, hors math paliers) ;
//   2. le premigrate LE PLUS récent n'est JAMAIS supprimé (keep-N borné à >= 1) ;
//   3. un nom NON parseable (format inconnu / TS invalide) est TOUJOURS gardé (jamais supprimé) ;
//   4. entrée vide -> sortie vide ;
//   5. idempotent : rejouer le plan sur (entrée - plan) -> sortie vide ;
//   6. déterministe : ordre d'entrée préservé, départage stable (TS puis nom).
// ============================================================================

/// Longueur exacte d'un horodatage `YYYYMMDDTHHMMSSZ` (UTC). 8 (date) + `T` + 6 (heure) + `Z`.
pub(crate) const BACKUP_TS_LEN: usize = 16;

/// Paramètres GFS (env-tunable, défauts validés par l'opérateur). Jours pour les paliers réguliers + nombre
/// de snapshots premigrate à conserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GfsParams {
    pub(crate) dense_days: i64,
    pub(crate) daily_days: i64,
    pub(crate) weekly_days: i64,
    pub(crate) premigrate_keep: usize,
}

impl GfsParams {
    /// Charge depuis l'env avec les défauts validés par l'opérateur (DENSE=2j, DAILY=14j, WEEKLY=90j,
    /// PREMIGRATE_KEEP=2). Une valeur illisible/négative -> DÉFAUT (fail-safe : jamais de palier
    /// dégénéré silencieux).
    pub(crate) fn from_env() -> Self {
        fn env_i64(k: &str, d: i64) -> i64 {
            std::env::var(k).ok().and_then(|v| v.trim().parse::<i64>().ok()).filter(|&n| n >= 0).unwrap_or(d)
        }
        fn env_usize(k: &str, d: usize) -> usize {
            std::env::var(k).ok().and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(d)
        }
        GfsParams {
            dense_days: env_i64("PLUME_BACKUP_DENSE_DAYS", 2),
            daily_days: env_i64("PLUME_BACKUP_DAILY_DAYS", 14),
            weekly_days: env_i64("PLUME_BACKUP_WEEKLY_DAYS", 90),
            premigrate_keep: env_usize("PLUME_BACKUP_PREMIGRATE_KEEP", 2),
        }
    }
}

/// Jours civils (UTC) depuis l'epoch Unix (1970-01-01) — algorithme de Howard Hinnant `days_from_civil`,
/// valide pour tout le calendrier grégorien proleptique. Aucune dépendance (chrono ABSENT du daemon).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;                                     // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };                  // mars=0 ... février=11
    let doy = (153 * mp + 2) / 5 + d - 1;                        // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;             // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse un horodatage `YYYYMMDDTHHMMSSZ` (UTC) -> secondes Unix. `None` si le format ne colle PAS
/// EXACTEMENT (longueur, séparateurs `T`/`Z`, chiffres, bornes calendaires) -> l'appelant KEEP (fail-safe :
/// on ne supprime JAMAIS sur un TS ambigu).
pub(crate) fn parse_backup_ts(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != BACKUP_TS_LEN { return None; }
    if b[8] != b'T' || b[15] != b'Z' { return None; }
    for (i, &c) in b.iter().enumerate() {
        if i == 8 || i == 15 { continue; }
        if !c.is_ascii_digit() { return None; }
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let year = num(&ts[0..4])?;
    let mon = num(&ts[4..6])?;
    let day = num(&ts[6..8])?;
    let hour = num(&ts[9..11])?;
    let min = num(&ts[11..13])?;
    let sec = num(&ts[13..15])?;
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) { return None; }
    if hour > 23 || min > 59 || sec > 60 { return None; }        // 60 tolère une seconde intercalaire
    Some(days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Clé de JOUR civil UTC (numéro de jour depuis l'epoch) d'un timestamp Unix.
pub(crate) fn day_key(ts: i64) -> i64 { ts.div_euclid(86400) }

/// Clé de SEMAINE ISO (lun-dim) : numéro de jour du LUNDI de la semaine. 1970-01-01 (jour 0) est un
/// JEUDI (index 3 avec lundi=0) -> `days - (days+3) mod 7` donne le lundi. Deux TS de la même semaine
/// ISO partagent la même clé -> groupement exact par semaine ISO sans arithmétique année/semaine ISO.
pub(crate) fn week_key(ts: i64) -> i64 {
    let days = ts.div_euclid(86400);
    days - (days + 3).rem_euclid(7)
}

/// Classe d'un nom d'objet de backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedBackup {
    /// `plume-<TS>.db.age` — backup régulier (secondes Unix parsées du TS).
    Regular(i64),
    /// `premigrate-<sha>-<TS>.db.age` — snapshot pré-migration (secondes Unix parsées du TS).
    Premigrate(i64),
    /// Format inconnu OU TS non parseable -> KEEP inconditionnel (jamais supprimé).
    Unparseable,
}

/// Classe un nom d'objet (base-name OU clé complète `dir/...` — routé par le BASE-NAME). Tout format
/// inattendu ou TS invalide -> `Unparseable` (l'appelant ne le supprimera JAMAIS).
pub(crate) fn classify_backup_name(raw: &str) -> ParsedBackup {
    let name = raw.rsplit('/').next().unwrap_or(raw);           // base-name (route même une clé complète)
    if let Some(mid) = name.strip_prefix("plume-").and_then(|s| s.strip_suffix(".db.age")) {
        return match parse_backup_ts(mid) {
            Some(ts) => ParsedBackup::Regular(ts),
            None => ParsedBackup::Unparseable,
        };
    }
    if let Some(mid) = name.strip_prefix("premigrate-").and_then(|s| s.strip_suffix(".db.age")) {
        // le TS = le suffixe après le DERNIER '-' (le <sha> n'en contient pas). Ex : `82c168b-<TS>`.
        if let Some(ts_str) = mid.rsplit('-').next() {
            if let Some(ts) = parse_backup_ts(ts_str) { return ParsedBackup::Premigrate(ts); }
        }
        return ParsedBackup::Unparseable;
    }
    ParsedBackup::Unparseable
}

/// PLAN de suppression GFS. Fonction PURE : `names` (noms bruts, ordre libre) + `now_secs` (secondes Unix
/// INJECTÉES -> testable) + `p` -> liste des noms à SUPPRIMER, dans l'ORDRE D'ENTRÉE, noms bruts préservés
/// tels quels (le sidecar les repasse à `mc rm`). Voir les invariants 1-6 dans l'en-tête de section.
pub(crate) fn backup_prune_plan(names: &[String], now_secs: i64, p: &GfsParams) -> Vec<String> {
    use std::collections::{BTreeSet, HashMap, HashSet};

    // Partition en (idx, ts) réguliers / premigrate ; les non parseables sont IGNORÉS (donc gardés).
    let mut regular: Vec<(usize, i64)> = Vec::new();
    let mut premigrate: Vec<(usize, i64)> = Vec::new();
    for (i, raw) in names.iter().enumerate() {
        match classify_backup_name(raw) {
            ParsedBackup::Regular(ts) => regular.push((i, ts)),
            ParsedBackup::Premigrate(ts) => premigrate.push((i, ts)),
            ParsedBackup::Unparseable => {}                     // INVARIANT 3 : jamais supprimé
        }
    }

    let mut delete_idx: BTreeSet<usize> = BTreeSet::new();

    // --- SET RÉGULIER : paliers GFS -------------------------------------------
    if !regular.is_empty() {
        let dense = p.dense_days.saturating_mul(86400);
        let daily = p.daily_days.saturating_mul(86400);
        let weekly = p.weekly_days.saturating_mul(86400);

        // Départage déterministe : (ts, nom) le plus GRAND gagne. `names[idx]` compare les chaînes brutes.
        let cand_wins = |c_ts: i64, c_idx: usize, w_ts: i64, w_idx: usize| -> bool {
            (c_ts, &names[c_idx]) > (w_ts, &names[w_idx])
        };

        // INVARIANT 1 : le régulier LE PLUS récent (max ts, départage nom) est TOUJOURS gardé.
        let newest = *regular.iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| names[a.0].cmp(&names[b.0])))
            .unwrap();

        let mut keep: HashSet<usize> = HashSet::new();
        keep.insert(newest.0);

        // Groupes "dernier par jour" / "dernier par semaine" : clé -> (ts_gagnant, idx_gagnant).
        let mut day_win: HashMap<i64, (i64, usize)> = HashMap::new();
        let mut week_win: HashMap<i64, (i64, usize)> = HashMap::new();

        for &(idx, ts) in &regular {
            let age = now_secs - ts;
            if age < dense {
                keep.insert(idx);                              // palier DENSE : tout gardé
            } else if age < daily {
                let k = day_key(ts);
                match day_win.get(&k) {
                    Some(&(w_ts, w_idx)) if !cand_wins(ts, idx, w_ts, w_idx) => {}
                    _ => { day_win.insert(k, (ts, idx)); }
                }
            } else if age < weekly {
                let k = week_key(ts);
                match week_win.get(&k) {
                    Some(&(w_ts, w_idx)) if !cand_wins(ts, idx, w_ts, w_idx) => {}
                    _ => { week_win.insert(k, (ts, idx)); }
                }
            }
            // age >= weekly -> candidat à la suppression (sauf s'il EST le newest, déjà dans keep).
        }
        for (_, (_, idx)) in day_win { keep.insert(idx); }
        for (_, (_, idx)) in week_win { keep.insert(idx); }

        for &(idx, _) in &regular {
            if !keep.contains(&idx) { delete_idx.insert(idx); }
        }
    }

    // --- SET PREMIGRATE : keep-N plus récents ---------------------------------
    if !premigrate.is_empty() {
        // Tri (ts, nom) DÉCROISSANT ; on garde les `premigrate_keep` premiers (borné à >= 1 : INVARIANT 2).
        let mut sorted = premigrate.clone();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| names[b.0].cmp(&names[a.0])));
        let keep_n = p.premigrate_keep.max(1);
        for &(idx, _) in sorted.iter().skip(keep_n) {
            delete_idx.insert(idx);
        }
    }

    // Sortie : noms bruts dans l'ORDRE D'ENTRÉE (BTreeSet<idx> itère croissant). INVARIANT 4 : vide -> vide.
    delete_idx.into_iter().map(|i| names[i].clone()).collect()
}

// ============================================================================
// OPS NATIVE — helpers du SCHEDULER DE BACKUP IN-DAEMON (portable host/Docker).
// ----------------------------------------------------------------------------
// Rendent `docker run` / le binaire host self-backup TURNKEY sans dépendre du sidecar shell k3s (mc/S3) :
//   - `fmt_backup_ts`            : nomme les backups `plume-<TS>.db.age` (inverse EXACT de `parse_backup_ts`)
//   - `backup_keep_recent_plan`  : rétention KEEP-N PURE (garde les N plus récents), fail-safe comme le GFS.
// L'orchestration (boucle intervalle, rename atomique, prune) vit dans `server.rs` ; ici = logique PURE testable.
// ============================================================================

/// Formate des secondes Unix -> horodatage compact `YYYYMMDDTHHMMSSZ` (UTC) — INVERSE EXACT de
/// `parse_backup_ts` (miroir de `date -u +%Y%m%dT%H%M%SZ`, le format que le sidecar shell produit déjà).
/// Aucune dépendance (chrono absent du daemon) : `civil_from_days` de Howard Hinnant. Le tri lexicographique
/// du nom résultant == tri chronologique -> compatible tel quel avec `classify_backup_name` / la rétention.
pub(crate) fn fmt_backup_ts(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, se) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{se:02}Z")
}

/// PLAN de rétention KEEP-N pour le SCHEDULER natif in-daemon. Fonction PURE : garde les `keep` backups
/// RÉGULIERS (`plume-<TS>.db.age`) les plus RÉCENTS (par TS parsé) et renvoie les noms des PLUS ANCIENS à
/// SUPPRIMER, dans l'ORDRE D'ENTRÉE. C'est le pendant « simple » (KEEP-N host/Docker) du GFS à paliers
/// (`backup_prune_plan`, sidecar k3s/S3) : il REJOUE les MÊMES primitives de parsing (`classify_backup_name`)
/// et les MÊMES invariants fail-safe :
///   - un nom NON parseable (format inconnu / TS invalide, ex. le `.tmp` d'un backup en cours) n'est JAMAIS
///     supprimé -> jamais de course avec un rename atomique en vol ;
///   - un `premigrate-*` n'est JAMAIS supprimé (hors périmètre du scheduler) ;
///   - `keep` est borné à >= 1 -> le répertoire n'est JAMAIS vidé (le plus récent survit toujours) ;
///   - entrée <= keep -> sortie vide ; déterministe (tri stable (TS puis nom brut)).
pub(crate) fn backup_keep_recent_plan(names: &[String], keep: usize) -> Vec<String> {
    let keep = keep.max(1); // garde-fou : au moins le plus récent survit (jamais tout supprimer).
    // (idx, ts) des SEULS backups réguliers ; premigrate + non-parseables IGNORÉS (donc gardés = fail-safe).
    let mut regular: Vec<(usize, i64)> = names.iter().enumerate()
        .filter_map(|(i, raw)| match classify_backup_name(raw) {
            ParsedBackup::Regular(ts) => Some((i, ts)),
            _ => None,
        })
        .collect();
    if regular.len() <= keep { return Vec::new(); } // rien de trop -> aucune suppression.
    // Tri (ts, nom brut) DÉCROISSANT : les `keep` premiers = les plus récents (gardés) ; le reste = à supprimer.
    regular.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| names[b.0].cmp(&names[a.0])));
    let mut del_idx: Vec<usize> = regular.iter().skip(keep).map(|&(i, _)| i).collect();
    del_idx.sort_unstable(); // ordre d'entrée (déterministe, indépendant du tri interne).
    del_idx.into_iter().map(|i| names[i].clone()).collect()
}

// ============================================================================
// VÉRIFICATION STRUCTURELLE d'un backup `.age` (SANS déchiffrer).
// ----------------------------------------------------------------------------
// Le restore-test in-cluster ne peut PAS détenir l'identité PRIVÉE d'un backup asymétrique (la mettre en
// cluster ruinerait le modèle : une compromission de pod la volerait). Pour ces backups, la vérif DÉGRADE
// vers un contrôle STRUCTUREL : en-tête age v1 bien formé + type de stanza destinataire + taille plausible.
// La vérif COMPLÈTE (déchiffrer + ouvrir la DB) devient un DRILL DR périodique avec la clé escrow (runbook).
// ============================================================================

/// Type de chiffrement d'un backup `.age`, déduit du stanza destinataire de l'en-tête (sans déchiffrer).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum BackupKind {
    /// Passphrase (scrypt) = clé SQLCipher -> déchiffrable EN cluster (rétrocompat / pré-cutover asymétrique).
    Symmetric,
    /// x25519 (destinataire public) -> déchiffrement = identité PRIVÉE escrow, HORS cluster.
    Asymmetric,
}

/// Taille plancher plausible d'un `.age` (en-tête v1 + stanza + MAC + nonce STREAM) : rejette un fichier
/// tronqué/vide. Un vrai backup compressé fait des dizaines de Mo ; on reste conservateur (faux négatifs nuls).
pub(crate) const BACKUP_MIN_PLAUSIBLE_BYTES: u64 = 200;

/// Inspecte l'EN-TÊTE age v1 textuel (sans déchiffrer) : valide l'intro `age-encryption.org/v1`, énumère les
/// tags de stanza (`->  <tag> …`), exige une ligne MAC de clôture (`--- <b64>`), et classe le backup
/// (Symmetric=scrypt / Asymmetric=X25519). Erreur si en-tête absent/malformé ou stanza inconnu -> le
/// restore-test échoue bruyamment sur un objet corrompu. Lit au plus 64 KiB (l'en-tête age est petit).
pub(crate) fn inspect_age_header<R: std::io::BufRead>(mut r: R) -> Result<BackupKind, String> {
    let mut head = vec![0u8; 64 * 1024];
    let read = r.read(&mut head).map_err(|e| format!("lecture en-tête : {e}"))?;
    let text = String::from_utf8_lossy(&head[..read]);
    let mut lines = text.lines();
    match lines.next() {
        Some("age-encryption.org/v1") => {}
        _ => return Err("en-tête age absent/invalide (intro age-encryption.org/v1 manquante)".into()),
    }
    let mut kind: Option<BackupKind> = None;
    let mut saw_mac = false;
    for line in lines {
        if let Some(rest) = line.strip_prefix("-> ") {
            let tag = rest.split_whitespace().next().unwrap_or("");
            // age insère des stanzas "grease" à tag ALÉATOIRE (agilité protocolaire) -> on IGNORE tout tag
            // non reconnu ; on ne classe QUE sur les stanzas destinataires réels (scrypt / X25519).
            let k = match tag {
                "scrypt" => Some(BackupKind::Symmetric),
                "X25519" => Some(BackupKind::Asymmetric),
                _ => None,
            };
            if let Some(k) = k {
                match kind {
                    None => kind = Some(k),
                    Some(prev) if prev != k => return Err("stanzas destinataires mixtes (incohérent)".into()),
                    _ => {}
                }
            }
        } else if line.starts_with("--- ") {
            saw_mac = true;
            break; // fin de l'en-tête (ligne MAC)
        }
    }
    let kind = kind.ok_or("aucun stanza destinataire dans l'en-tête age")?;
    if !saw_mac { return Err("en-tête age tronqué (ligne MAC `---` absente dans 64 KiB)".into()); }
    Ok(kind)
}

/// VÉRIFICATION d'un backup `.age` pour le restore-test. Contrôle STRUCTUREL toujours (en-tête + taille) ;
/// puis vérif COMPLÈTE (déchiffre + ouvre la DB) UNIQUEMENT si l'identité requise est disponible :
///   - Symmetric : clé SQLCipher (`key`) présente -> round-trip complet possible EN cluster (inchangé).
///   - Asymmetric : identité privée présente (PLUME_BACKUP_AGE_IDENTITY[_FILE]) -> round-trip ; SINON DÉGRADE
///     en structurel-seul et LOGue que la vérif complète exige la clé escrow (DRILL DR).
/// Renvoie `(BackupKind, full_verified)`. Ne place JAMAIS l'identité privée en cluster : c'est l'appelant/
/// l'opérateur qui la fournit au moment du DR.
pub(crate) fn verify_backup(src: &str, key: Option<&str>, identity: Option<&age::x25519::Identity>) -> Result<(BackupKind, bool), String> {
    let meta = std::fs::metadata(src).map_err(|e| format!("backup introuvable {src} : {e}"))?;
    if meta.len() < BACKUP_MIN_PLAUSIBLE_BYTES {
        return Err(format!("backup {src} trop petit ({} o < {} o) — tronqué/vide", meta.len(), BACKUP_MIN_PLAUSIBLE_BYTES));
    }
    let f = std::fs::File::open(src).map_err(|e| format!("ouverture {src} : {e}"))?;
    let kind = inspect_age_header(std::io::BufReader::with_capacity(BACKUP_BUF, f))?;
    // Peut-on déchiffrer EN cluster ?
    let can_full = match kind {
        BackupKind::Symmetric => key.map(|k| !k.is_empty()).unwrap_or(false),
        BackupKind::Asymmetric => identity.is_some(),
    };
    if !can_full {
        eprintln!("[backup-verify] {src} : {kind:?} — vérif STRUCTURELLE OK (en-tête age v1 + stanza {} + taille {} o). \
Vérif COMPLÈTE (déchiffrer+ouvrir la DB) requiert l'identité age PRIVÉE escrow HORS-cluster (DRILL DR) — non tentée.",
            match kind { BackupKind::Symmetric => "scrypt", BackupKind::Asymmetric => "X25519" }, meta.len());
        return Ok((kind, false));
    }
    // Vérif COMPLÈTE : restore vers un dest_db JETABLE dans le staging (prouve déchiffrement + DB ouvrable).
    // restore_compressed gère son propre plaintext temporaire (RAII) ; on efface ensuite le dest_db chiffré.
    let dest_probe = staging_dir(src)
        .join(format!(".verify.plain.tmp.{}.{}.db", std::process::id(), now()))
        .to_string_lossy().into_owned();
    let r = restore_compressed(src, &dest_probe, key, true, identity).map(|_| (kind, true));
    for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_probe}{ext}")); }
    r
}
