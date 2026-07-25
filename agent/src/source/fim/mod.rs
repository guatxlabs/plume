//! FIM natif (#58) — surveillance d'intégrité de fichiers PRODUITE par l'agent (plus seulement ingérée).
//!
//! #57 a apporté l'INGEST/normalisation CIM de la télémétrie FIM d'agents tiers (Wazuh `syscheck` ->
//! `category=integrity` + champs `fim_*`). #58 fait de plume un PRODUCTEUR : l'agent surveille lui-même
//! un jeu de chemins et émet des events au MÊME contrat CIM, de sorte que les panneaux/règles FIM déjà
//! livrés (`search source=integrity`, rollup santé `integrity`, vues #57 `fim_*`) s'allument SANS aucun
//! changement daemon.
//!
//! ## Architecture (cross-OS, testable)
//! - `trait FimBackend` : abstraction du WATCHER noyau. Linux = `FanotifyBackend` (préféré, CAP_SYS_ADMIN)
//!   avec repli `InotifyBackend` (sans capability) — cf. `linux.rs`. Windows = `ReadDirectoryChangesW`
//!   stubbé/feature-gated (cf. `windows.rs`). AUCUN backend disponible -> repli SCAN PLANIFIÉ (rescan
//!   borné à chaque cycle), donc l'agent fait quand même du FIM partout.
//! - `trait FsProbe` : lecture métadonnées+hash d'un chemin (abstraite pour tester la logique sans disque).
//! - `Baseline` : map chemin -> (sha256, taille, mode, uid, gid, mtime), persistée entre redémarrages ->
//!   PAS de ré-alarme au reboot. Le 1er run (baseline absente) SEED en silence (aucun event).
//! - `FimReader` (SourceReader) : draine le backend, diffe contre la baseline, émet des `Event` CIM.
//!
//! ## Invariants (charte plume)
//! - OBSERVATIONNEL STRICT : on lit/hashe/rapporte. JAMAIS d'écriture dans les arbres surveillés, jamais
//!   de quarantaine/remédiation. Aucune action live sur l'hôte.
//! - MODE 0 : `paths` vide -> reader inerte (aucun backend, aucun accès disque, aucun event). Une config
//!   agent sans source `fim` ne construit jamais de `FimReader` -> comportement byte-identique à la base.
//! - BORNES ANTI-OOM : `hash_max_bytes` (skip hash gros fichiers), `max_watches` (plafond watches noyau),
//!   `max_files` (plafond entrées baseline), coalescence par chemin (debounce des rafales d'écriture),
//!   traitement borné à `max` par cycle. Anti-évasion symlink : on ne SUIT jamais un lien hors racines.

use super::{Cursor, Event, NativeRecord, SourceReader, Wire};
use crate::config::FimCfg;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod sha256;

#[cfg(target_os = "linux")]
pub mod linux;
// Compilé sur TOUTES les cibles : les fonctions PURES du backend Windows (mapping `FILE_ACTION_*` ->
// `FsEventKind`, découpage `FILE_NOTIFY_INFORMATION`) sont testées sur Linux ; seule la FFI
// `ReadDirectoryChangesW`/completion-port est `#[cfg(all(windows, feature = "fim_windows_native"))]`
// (miroir de `source/windows.rs`, dont le mapping XML pur est testé hors Windows).
pub mod windows;

// ---------------------------------------------------------------------------------------------------
// Types partagés (backend + probe)
// ---------------------------------------------------------------------------------------------------

/// Métadonnées + empreinte d'un fichier régulier, à un instant. `sha256 = None` = fichier trop gros
/// (au-delà de `hash_max_bytes`) ou illisible : on suit alors la taille/attributs seuls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    pub sha256: Option<String>,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
}

/// Nature d'un changement de système de fichiers signalé par le backend (avant diff baseline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEventKind {
    Created,
    Modified,
    Deleted,
    Attrib,
    /// Un répertoire est apparu -> le backend récursif doit poser un watch dessus et l'énumérer.
    DirCreated,
}

/// Un event brut du watcher : un CHEMIN touché + la nature. Le diff baseline tranche ensuite
/// added/modified/deleted (le backend n'a pas forcément l'info exacte : create suivi d'un delete rapide
/// se résout par un simple probe du chemin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFsEvent {
    pub path: PathBuf,
    pub kind: FsEventKind,
}

/// Résultat d'un drainage non bloquant du backend.
#[derive(Debug, Default)]
pub struct PollResult {
    pub events: Vec<RawFsEvent>,
    /// La file noyau a débordé (IN_Q_OVERFLOW / FAN_Q_OVERFLOW) -> des events ont été perdus ->
    /// le reader DOIT faire un rescan complet pour se resynchroniser (récupère les changements manqués).
    pub overflowed: bool,
}

/// Backend watcher noyau. Implémenté par OS (`linux::*`) ; abstrait pour permettre un fake en test et un
/// slot Windows (`ReadDirectoryChangesW`) ultérieur.
pub trait FimBackend {
    /// Nom lisible (journalisé + renseigne `fim_mode`/`backend`).
    fn name(&self) -> &'static str;
    /// Pose un watch (récursif si demandé à la construction) sur `root`. Idempotent, best-effort :
    /// journalise et continue sur ENOSPC/EPERM (dégradation, jamais crash).
    fn watch_root(&mut self, root: &Path);
    /// Draine SANS BLOQUER jusqu'à `max` events disponibles. `overflowed=true` -> demander un rescan.
    fn poll(&mut self, max: usize) -> PollResult;
    /// Couverture DÉGRADÉE côté noyau : le plafond de watches/marks (`max_watches` ou ENOSPC noyau) a été
    /// atteint -> des sous-arbres ne sont PAS surveillés. Remonté au reader pour marquer `fim_coverage`
    /// (visibilité SOC), jamais juste un warning stderr d'hôte. Défaut : couverture pleine.
    fn degraded(&self) -> bool {
        false
    }
}

/// Lecture des métadonnées+empreinte d'un chemin. Abstraite -> la logique diff/CIM se teste sans disque.
pub trait FsProbe {
    /// `None` = le chemin n'existe pas / n'est pas un fichier régulier suivi (symlink, socket, dir…).
    fn probe(&self, path: &Path) -> Option<FileMeta>;
}

// ---------------------------------------------------------------------------------------------------
// Probe réelle (disque) — symlink-safe, hash borné
// ---------------------------------------------------------------------------------------------------

/// Probe disque : `symlink_metadata` (ne SUIT jamais un lien), hash SHA-256 borné par `hash_max_bytes`.
pub struct RealProbe {
    pub hash_max_bytes: u64,
}

impl FsProbe for RealProbe {
    fn probe(&self, path: &Path) -> Option<FileMeta> {
        probe_real(path, self.hash_max_bytes)
    }
}

/// Probe UNIX anti-TOCTOU : OUVRE le chemin UNE SEULE FOIS avec `O_NOFOLLOW` (le dernier composant, s'il
/// est un lien symbolique, fait échouer l'open -> jamais suivi) + `O_NONBLOCK` (un FIFO s'ouvre sans
/// bloquer, on le rejette ensuite sur `S_ISREG`). Ce descripteur est l'UNIQUE source de vérité : on
/// `fstat` LE FD (pas le chemin) pour taille/mode/uid/gid/mtime, on exige `S_ISREG` (les fifos, devices,
/// sockets, dirs et liens sont ignorés -> aucune lecture, aucun hang), et on hashe DEPUIS CE MÊME FD.
/// => aucune fenêtre entre le contrôle et l'usage : un attaquant ne peut pas substituer un lien vers
/// `/etc/shadow` entre le lstat et l'open (la faille corrigée). La lecture est bornée EN DUR à
/// `hash_max_bytes` DANS la boucle : un fichier qui grossit pendant la lecture (ou `/dev/zero`-like)
/// ne peut jamais faire lire l'agent à l'infini.
#[cfg(unix)]
fn probe_real(path: &Path, hash_max_bytes: u64) -> Option<FileMeta> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?; // ELOOP (lien) / ENXIO / EACCES … -> on dégrade en "non suivi" (skip)
    let fd = f.as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    // Seuls les fichiers RÉGULIERS sont suivis/hashés. Tout le reste (fifo/socket/device/dir/lien) est
    // ignoré sans lecture -> pas de blocage sur un FIFO sans écrivain, pas de lecture d'un device.
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return None;
    }
    let size = if st.st_size > 0 { st.st_size as u64 } else { 0 };
    let mode = (st.st_mode & 0o7777) as u32;
    let uid = st.st_uid as u32;
    let gid = st.st_gid as u32;
    let mtime = st.st_mtime as i64;
    let sha256 = if size <= hash_max_bytes {
        hash_reader_capped(f, hash_max_bytes) // grossit au-delà du cap -> None (taille seule)
    } else {
        None // déjà trop gros -> taille+attributs seuls (borne CPU/RAM)
    };
    Some(FileMeta { sha256, size, mode, uid, gid, mtime })
}

/// Probe non-unix (repli scan planifié) : `symlink_metadata` ne suit pas le lien, lecture bornée en dur.
#[cfg(not(unix))]
fn probe_real(path: &Path, hash_max_bytes: u64) -> Option<FileMeta> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    let size = md.len();
    let (mode, uid, gid) = meta_perms(&md);
    let mtime = meta_mtime(&md);
    let sha256 = if size <= hash_max_bytes {
        std::fs::File::open(path).ok().and_then(|f| hash_reader_capped(f, hash_max_bytes))
    } else {
        None
    };
    Some(FileMeta { sha256, size, mode, uid, gid, mtime })
}

#[cfg(not(unix))]
fn meta_perms(md: &std::fs::Metadata) -> (u32, u32, u32) {
    let ro = md.permissions().readonly();
    (if ro { 0o444 } else { 0o644 }, 0, 0)
}

#[cfg(not(unix))]
fn meta_mtime(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Hashe un lecteur par blocs (64 Kio) sans le charger en RAM, avec un ARRÊT DUR à `cap` octets DANS la
/// boucle. `None` si illisible OU si la source dépasse `cap` (fichier qui grossit / flux sans fin) ->
/// on retombe alors sur "taille seule" plutôt que de lire indéfiniment. `Some(hex)` si EOF dans le cap.
fn hash_reader_capped<R: std::io::Read>(mut r: R, cap: u64) -> Option<String> {
    let mut h = sha256::Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total: u64 = 0;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total = total.saturating_add(n as u64);
                if total > cap {
                    // A grossi au-delà du cap pendant la lecture -> trop gros, taille seule (ARRÊT DUR).
                    return None;
                }
                h.update(&buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(sha256::to_hex(&h.finalize()))
}

// ---------------------------------------------------------------------------------------------------
// Diff baseline -> changement CIM (COEUR PUR, testable)
// ---------------------------------------------------------------------------------------------------

/// Famille d'event FIM au vocabulaire #57 (`fim_event`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimEventKind {
    Added,
    Modified,
    Deleted,
}

impl FimEventKind {
    fn as_str(self) -> &'static str {
        match self {
            FimEventKind::Added => "added",
            FimEventKind::Modified => "modified",
            FimEventKind::Deleted => "deleted",
        }
    }
    /// Sévérité CIM alignée sur le normaliseur endpoint #57 : deleted=3, modified=2, added=1.
    fn severity(self) -> i64 {
        match self {
            FimEventKind::Deleted => 3,
            FimEventKind::Modified => 2,
            FimEventKind::Added => 1,
        }
    }
    /// `action` CIM (vocabulaire neutre) : modified->modify, deleted->delete, added->(aucune, comme #57).
    fn action(self) -> Option<&'static str> {
        match self {
            FimEventKind::Modified => Some("modify"),
            FimEventKind::Deleted => Some("delete"),
            FimEventKind::Added => None,
        }
    }
}

/// Détail fin du changement (au-delà du triptyque #57) — surfacé en `fim_change`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeDetail {
    Created,
    Content,
    Attrs,
    Deleted,
}

impl ChangeDetail {
    fn as_str(self) -> &'static str {
        match self {
            ChangeDetail::Created => "created",
            ChangeDetail::Content => "content",
            ChangeDetail::Attrs => "attrs",
            ChangeDetail::Deleted => "deleted",
        }
    }
}

/// Un changement détecté (diff baseline vs état courant). `before`/`after` portent l'avant/après.
#[derive(Debug, Clone, PartialEq)]
pub struct FimChange {
    pub kind: FimEventKind,
    pub detail: ChangeDetail,
    pub before: Option<FileMeta>,
    pub after: Option<FileMeta>,
}

/// COEUR PUR : compare l'état baseline (`prev`) et l'état courant (`cur`) d'UN chemin. `None` = pas de
/// changement significatif (mtime seul, ou apparition transitoire déjà repartie). Cette fonction est
/// TOTALEMENT testable sans disque (le disque est encapsulé dans `FsProbe`).
pub fn diff(prev: Option<&FileMeta>, cur: Option<&FileMeta>) -> Option<FimChange> {
    match (prev, cur) {
        (None, None) => None,
        (None, Some(a)) => Some(FimChange {
            kind: FimEventKind::Added,
            detail: ChangeDetail::Created,
            before: None,
            after: Some(a.clone()),
        }),
        (Some(p), None) => Some(FimChange {
            kind: FimEventKind::Deleted,
            detail: ChangeDetail::Deleted,
            before: Some(p.clone()),
            after: None,
        }),
        (Some(p), Some(a)) => {
            // Contenu : hash différent (les deux connus) OU taille différente (hash inconnu/égal).
            let hash_known = p.sha256.is_some() && a.sha256.is_some();
            let content_changed =
                (hash_known && p.sha256 != a.sha256) || (!hash_known && p.size != a.size);
            if content_changed {
                Some(FimChange {
                    kind: FimEventKind::Modified,
                    detail: ChangeDetail::Content,
                    before: Some(p.clone()),
                    after: Some(a.clone()),
                })
            } else if p.mode != a.mode || p.uid != a.uid || p.gid != a.gid {
                // Permissions / propriété changées (hash identique) -> altération d'attributs.
                Some(FimChange {
                    kind: FimEventKind::Modified,
                    detail: ChangeDetail::Attrs,
                    before: Some(p.clone()),
                    after: Some(a.clone()),
                })
            } else {
                // Seul mtime a bougé (touch) OU rien -> bruit, pas d'event (mais on rafraîchit la baseline).
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Mapping changement -> Event CIM (contrat #57 : category=integrity + champs fim_*)
// ---------------------------------------------------------------------------------------------------

/// Construit l'`Event` CIM à partir d'un changement. `source`/`category` figés sur `integrity` pour
/// s'aligner sur le collecteur `integrity.sh`, le panneau `search source=integrity` et le rollup santé.
/// Le sac `fields` est un SUR-ENSEMBLE : champs `fim_*` (#57) POUR les vues endpoint + miroir
/// `path/sha256/change` (style `integrity.sh`) -> toutes les vues existantes s'allument à l'identique.
pub fn change_to_event(
    change: &FimChange,
    path: &Path,
    host: &str,
    source: &str,
    mode_label: &str,
    backend: &str,
    ts: i64,
) -> Event {
    let path_s = path.to_string_lossy().to_string();
    let after = change.after.as_ref();
    let before = change.before.as_ref();
    let sha_after = after.and_then(|m| m.sha256.clone());
    let sha_before = before.and_then(|m| m.sha256.clone());

    let mut fields = json!({
        "fim_path": path_s,
        "fim_event": change.kind.as_str(),      // added | modified | deleted (#57)
        "fim_mode": mode_label,                  // realtime | scheduled (vs wazuh scheduled/whodata)
        "fim_change": change.detail.as_str(),    // created | content | attrs | deleted
        "backend": backend,                      // fanotify | inotify | scan
        // Miroir style integrity.sh (le panneau/regex historique lit `path`) :
        "path": path_s,
        "scope": "host",
    });
    let obj = fields.as_object_mut().unwrap();
    if let Some(s) = &sha_after {
        obj.insert("fim_sha256".into(), Value::String(s.clone()));
        obj.insert("sha256".into(), Value::String(s.clone()));
    }
    if let Some(s) = &sha_before {
        obj.insert("fim_sha256_before".into(), Value::String(s.clone()));
    }
    if let Some(a) = after {
        obj.insert("fim_size".into(), Value::String(a.size.to_string()));
        obj.insert("fim_mode_octal".into(), Value::String(format!("{:o}", a.mode)));
        obj.insert("fim_uid".into(), Value::String(a.uid.to_string()));
        obj.insert("fim_gid".into(), Value::String(a.gid.to_string()));
    }
    if let Some(b) = before {
        obj.insert("fim_size_before".into(), Value::String(b.size.to_string()));
    }
    if let Some(act) = change.kind.action() {
        obj.insert("action".into(), Value::String(act.to_string()));
    }
    // `change` style integrity.sh : ajout | modif (aide les vues historiques).
    obj.insert(
        "change".into(),
        Value::String(match change.kind {
            FimEventKind::Added => "ajout".into(),
            _ => "modif".into(),
        }),
    );

    let message = match change.kind {
        FimEventKind::Added => format!("FIM: fichier créé : {path_s}"),
        FimEventKind::Deleted => format!("FIM: fichier supprimé : {path_s}"),
        FimEventKind::Modified => match change.detail {
            ChangeDetail::Attrs => format!("FIM: attributs modifiés (droits/propriété) : {path_s}"),
            _ => format!("FIM: fichier modifié (contenu) : {path_s}"),
        },
    };

    // dedup : chemin + famille + signature après (hash sinon taille sinon avant). Un changement RÉEL
    // (nouveau hash) produit une nouvelle clé -> insère ; un doublon identique est ignoré côté daemon.
    let sig = sha_after
        .clone()
        .or_else(|| after.map(|a| format!("s{}", a.size)))
        .or_else(|| sha_before.clone())
        .unwrap_or_else(|| format!("t{ts}"));
    let dedup = Some(format!("fim:{}:{}:{}", change.kind.as_str(), path_s, sig));

    Event {
        ts,
        host: host.to_string(),
        source: source.to_string(),
        category: "integrity".to_string(),
        severity: change.kind.severity(),
        message,
        fields,
        dedup,
    }
}

// ---------------------------------------------------------------------------------------------------
// Baseline persistée
// ---------------------------------------------------------------------------------------------------

/// Baseline chemin -> métadonnées, persistée en JSON (BTreeMap -> ordre stable, diffs déterministes).
#[derive(Debug, Default)]
pub struct Baseline {
    map: BTreeMap<String, FileMeta>,
    dirty: bool,
}

impl Baseline {
    pub fn new() -> Self {
        Self { map: BTreeMap::new(), dirty: false }
    }

    /// Charge depuis un fichier JSON. Absent/corrompu -> baseline vide (traitée comme 1er run).
    pub fn load(path: &Path) -> Self {
        let mut b = Baseline::new();
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(&s) {
                for (k, v) in o {
                    if let Some(m) = meta_from_json(&v) {
                        b.map.insert(k, m);
                    }
                }
            }
        }
        b
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn get(&self, path: &str) -> Option<&FileMeta> {
        self.map.get(path)
    }
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    /// Insère/remplace (respecte le plafond `max_files` : au-delà on n'AJOUTE plus de NOUVELLES clés,
    /// mais on met à jour les existantes). Renvoie false si l'insertion a été refusée par le plafond.
    pub fn set(&mut self, path: String, meta: FileMeta, max_files: usize) -> bool {
        let exists = self.map.contains_key(&path);
        if !exists && self.map.len() >= max_files {
            return false;
        }
        self.map.insert(path, meta);
        self.dirty = true;
        true
    }

    pub fn remove(&mut self, path: &str) {
        if self.map.remove(path).is_some() {
            self.dirty = true;
        }
    }

    /// Persiste si modifiée (écriture atomique via tmp+rename, perms 0600 sur unix). Best-effort.
    pub fn save(&mut self, path: &Path) {
        if !self.dirty {
            return;
        }
        let obj: serde_json::Map<String, Value> =
            self.map.iter().map(|(k, m)| (k.clone(), meta_to_json(m))).collect();
        let body = Value::Object(obj).to_string();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("tmp");
        // La baseline contient des hash/chemins sensibles -> le fichier temporaire NE DOIT JAMAIS exister
        // avec des perms plus larges que 0600, même transitoirement. On le crée DIRECTEMENT en 0600 (unix)
        // au lieu d'écrire-puis-chmod (fenêtre umask-large). On retire un éventuel tmp résiduel d'abord
        // (O_CREAT n'abaisse pas les perms d'un fichier préexistant).
        let _ = std::fs::remove_file(&tmp);
        let write_ok = {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .and_then(|mut f| f.write_all(body.as_bytes()))
                    .is_ok()
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&tmp, body.as_bytes()).is_ok()
            }
        };
        if write_ok {
            if std::fs::rename(&tmp, path).is_ok() {
                self.dirty = false;
            } else {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

fn meta_to_json(m: &FileMeta) -> Value {
    json!({
        "h": m.sha256,
        "s": m.size,
        "m": m.mode,
        "u": m.uid,
        "g": m.gid,
        "t": m.mtime,
    })
}

fn meta_from_json(v: &Value) -> Option<FileMeta> {
    let o = v.as_object()?;
    Some(FileMeta {
        sha256: o.get("h").and_then(|x| x.as_str()).map(|s| s.to_string()),
        size: o.get("s").and_then(|x| x.as_u64()).unwrap_or(0),
        mode: o.get("m").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        uid: o.get("u").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        gid: o.get("g").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        mtime: o.get("t").and_then(|x| x.as_i64()).unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------------------------------
// Filtrage : allowlist racines + exclusions glob + anti-évasion symlink
// ---------------------------------------------------------------------------------------------------

/// Glob TRÈS simple (`*` = n'importe quoi, `?` = 1 char), matché sur le chemin absolu. Pas de classes ni
/// de `**` : suffisant pour `*/.git/*`, `*.swp`, `/var/log/*`. Ancré aux deux bouts (match total).
pub fn glob_match(pat: &str, s: &str) -> bool {
    fn rec(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => {
                // `*` absorbe 0..n caractères.
                rec(&p[1..], s) || (!s.is_empty() && rec(p, &s[1..]))
            }
            Some(b'?') => !s.is_empty() && rec(&p[1..], &s[1..]),
            Some(&c) => !s.is_empty() && s[0] == c && rec(&p[1..], &s[1..]),
        }
    }
    rec(pat.as_bytes(), s.as_bytes())
}

/// Un chemin candidat est-il RETENU : sous une racine autorisée ET non exclu par un glob.
pub fn path_allowed(path: &Path, roots: &[PathBuf], exclude: &[String]) -> bool {
    let under_root = roots.iter().any(|r| path == r || path.starts_with(r));
    if !under_root {
        return false;
    }
    let s = path.to_string_lossy();
    !exclude.iter().any(|pat| glob_match(pat, &s))
}

// ---------------------------------------------------------------------------------------------------
// Le lecteur FIM (SourceReader)
// ---------------------------------------------------------------------------------------------------

pub struct FimReader {
    cfg: FimCfg,
    host: String,
    /// Chemin du fichier baseline (`<state_dir>/fim-<id>.baseline.json`).
    baseline_path: PathBuf,
    /// Racines CANONIQUES retenues (existantes). Vide -> reader inerte.
    roots: Vec<PathBuf>,
    baseline: Baseline,
    backend: Option<Box<dyn FimBackend>>,
    probe: Box<dyn FsProbe>,
    /// Étiquette `fim_mode` : "realtime" si backend noyau, "scheduled" si repli rescan.
    mode_label: &'static str,
    backend_name: &'static str,
    inert: bool,
    initialized: bool,
    /// Journalise une seule fois l'atteinte du plafond `max_files`.
    warned_cap: bool,
    /// Dernière émission par chemin -> anti-rafale (`debounce_ms`) : on ne ré-émet pas plus d'une fois
    /// par fenêtre pour un même chemin (les états intermédiaires sont absorbés dans la baseline).
    /// BORNÉ : purgé sur suppression + balayage des entrées plus vieilles que la fenêtre debounce +
    /// plafond dur (anti-OOM sur arbre à churn de noms uniques).
    last_emit: std::collections::HashMap<String, std::time::Instant>,
    /// Chemins REFUSÉS par le plafond `max_files` (jamais entrés en baseline) -> exclus du diff pour ne
    /// PAS ré-émettre `added` à chaque rescan (le "storm" corrigé). Petit ensemble BORNÉ (`OVER_CAP_MAX`).
    over_cap: std::collections::HashSet<String>,
    /// Instant du dernier rescan complet FORCÉ -> borne la cadence des marches récursives (fix #4).
    last_rescan: Option<std::time::Instant>,
}

/// Plafond dur du set `over_cap` (fix #5) et du map `last_emit` (fix #3) — anti-OOM si un attaquant fait
/// churner des noms uniques. Au-delà, on purge (on retombe au pire sur le comportement borné antérieur,
/// jamais sur une croissance mémoire non bornée).
const OVER_CAP_MAX: usize = 65_536;
const LAST_EMIT_MAX: usize = 65_536;

/// Décision PURE de rate-limit des rescans (fix #4), testable sans horloge réelle : un rescan forcé n'est
/// autorisé que si aucun n'a eu lieu, ou si l'intervalle minimal est écoulé.
fn rescan_due(
    last: Option<std::time::Instant>,
    now: std::time::Instant,
    min: std::time::Duration,
) -> bool {
    last.map_or(true, |t| now.duration_since(t) >= min)
}

impl FimReader {
    pub fn new(cfg: FimCfg, host: String, state_dir: &Path) -> Self {
        let baseline_path = state_dir.join(format!("fim-{}.baseline.json", sanitize_id(&cfg.id)));
        let hash_cap = cfg.hash_max_bytes;
        Self {
            cfg,
            host,
            baseline_path,
            roots: Vec::new(),
            baseline: Baseline::new(),
            backend: None,
            probe: Box::new(RealProbe { hash_max_bytes: hash_cap }),
            mode_label: "scheduled",
            backend_name: "scan",
            inert: false,
            initialized: false,
            warned_cap: false,
            last_emit: std::collections::HashMap::new(),
            over_cap: std::collections::HashSet::new(),
            last_rescan: None,
        }
    }

    /// Test-only : injecte un backend + une probe factices et une baseline en mémoire (pas de disque).
    #[cfg(test)]
    fn with_fakes(
        cfg: FimCfg,
        host: String,
        roots: Vec<PathBuf>,
        backend: Box<dyn FimBackend>,
        probe: Box<dyn FsProbe>,
    ) -> Self {
        Self {
            cfg,
            host,
            baseline_path: PathBuf::from("/dev/null/never"),
            roots,
            baseline: Baseline::new(),
            backend: Some(backend),
            probe,
            mode_label: "realtime",
            backend_name: "fake",
            inert: false,
            initialized: true,
            warned_cap: false,
            last_emit: std::collections::HashMap::new(),
            over_cap: std::collections::HashSet::new(),
            last_rescan: None,
        }
    }

    /// Initialisation paresseuse (au 1er `next_batch`) : canonicalise les racines, charge/seed la
    /// baseline, construit le backend noyau (ou repli scan). Séparée d'`open()` pour rester testable.
    fn ensure_init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;

        // MODE 0 : aucune racine configurée -> reader inerte, on ne touche RIEN (ni disque ni syscall).
        let configured: Vec<PathBuf> = self.cfg.paths.iter().map(PathBuf::from).collect();
        if configured.is_empty() {
            self.inert = true;
            eprintln!("[fim:{}] aucune `paths` -> source inerte (mode 0)", self.cfg.id);
            return;
        }

        // Canonicalise chaque racine (résout les symlinks des racines mêmes -> confinement stable).
        for p in &configured {
            match std::fs::canonicalize(p) {
                Ok(c) => self.roots.push(c),
                Err(e) => eprintln!("[fim:{}] racine ignorée {} : {e}", self.cfg.id, p.display()),
            }
        }
        if self.roots.is_empty() {
            self.inert = true;
            eprintln!("[fim:{}] aucune racine valide -> source inerte", self.cfg.id);
            return;
        }

        // Baseline : charge l'existante, sinon 1er run -> seed silencieux (aucun event de démarrage).
        self.baseline = Baseline::load(&self.baseline_path);
        let first_run = self.baseline.is_empty();

        // Backend noyau (Linux fanotify->inotify ; sinon None -> repli scan planifié).
        self.backend = build_backend(&self.cfg);
        if let Some(b) = &mut self.backend {
            self.mode_label = "realtime";
            self.backend_name = b.name();
            for r in &self.roots.clone() {
                b.watch_root(r);
            }
        } else {
            self.mode_label = "scheduled";
            self.backend_name = "scan";
        }

        if first_run {
            eprintln!(
                "[fim:{}] 1er run : seed baseline (silencieux) sur {} racine(s), backend={}",
                self.cfg.id,
                self.roots.len(),
                self.backend_name
            );
            self.seed_baseline();
            self.baseline.save(&self.baseline_path);
        } else {
            eprintln!(
                "[fim:{}] baseline chargée ({} entrées), backend={}",
                self.cfg.id,
                self.baseline.len(),
                self.backend_name
            );
        }
    }

    /// Parcours initial des racines -> remplit la baseline SANS émettre (état de référence).
    fn seed_baseline(&mut self) {
        let mut files = Vec::new();
        for r in &self.roots.clone() {
            walk_root(r, self.cfg.recursive, self.cfg.max_files, &self.cfg.exclude, &mut files);
        }
        for p in files {
            if let Some(m) = self.probe.probe(&p) {
                let key = p.to_string_lossy().to_string();
                if !self.baseline.set(key, m, self.cfg.max_files) {
                    self.warn_cap();
                    break;
                }
            }
        }
    }

    fn warn_cap(&mut self) {
        if !self.warned_cap {
            self.warned_cap = true;
            eprintln!(
                "[fim:{}] plafond max_files={} atteint -> couverture partielle (anti-OOM)",
                self.cfg.id, self.cfg.max_files
            );
        }
    }

    /// Fix #3 : borne `last_emit`. Une entrée plus vieille que la fenêtre debounce ne peut plus JAMAIS
    /// supprimer une émission -> on peut la jeter sans changer le comportement. En dernier ressort, un
    /// plafond dur purge tout (dégradation bénigne : au pire une émission non debouncée). `debounce_ms=0`
    /// -> la map n'est jamais peuplée, on la garde vide.
    fn sweep_last_emit(&mut self) {
        if self.cfg.debounce_ms == 0 {
            if !self.last_emit.is_empty() {
                self.last_emit.clear();
            }
            return;
        }
        if self.last_emit.len() > 1024 {
            let now = std::time::Instant::now();
            let window = std::time::Duration::from_millis(self.cfg.debounce_ms);
            self.last_emit.retain(|_, t| now.duration_since(*t) < window);
        }
        if self.last_emit.len() > LAST_EMIT_MAX {
            self.last_emit.clear();
        }
    }

    /// Collecte les chemins candidats de ce cycle (events backend + rescan si overflow/repli scan),
    /// filtrés (allowlist + exclude), dédupliqués, bornés à `max`.
    fn collect_candidates(&mut self, max: usize) -> Vec<PathBuf> {
        use std::collections::BTreeSet;
        let mut set: BTreeSet<PathBuf> = BTreeSet::new();
        let mut need_rescan = self.backend.is_none(); // pas de backend -> scan planifié systématique

        if let Some(b) = &mut self.backend {
            let poll = b.poll(max.saturating_mul(4).max(64));
            if poll.overflowed {
                need_rescan = true;
            }
            for ev in poll.events {
                // Nouveau répertoire : le backend récursif l'ajoute lui-même ; on l'énumère pour capter
                // les fichiers déjà créés dedans avant la pose du watch (fenêtre de course).
                if ev.kind == FsEventKind::DirCreated {
                    let mut kids = Vec::new();
                    walk_root(&ev.path, self.cfg.recursive, self.cfg.max_files, &self.cfg.exclude, &mut kids);
                    for k in kids {
                        if path_allowed(&k, &self.roots, &self.cfg.exclude) {
                            set.insert(k);
                        }
                    }
                }
                if path_allowed(&ev.path, &self.roots, &self.cfg.exclude) {
                    set.insert(ev.path);
                }
            }
        }

        // Fix #4 : un rescan complet est COÛTEUX (marche récursive jusqu'à max_files). fanotify lève
        // `overflowed` à CHAQUE activité (pas de décodage DFID_NAME) et le repli scan le demande à chaque
        // cycle -> sans garde, la churn de routine déclenche des marches dos-à-dos toutes les
        // `flush_interval_secs`. On borne la cadence à `min_rescan_interval_secs` (indépendant du flush).
        // Les events PRÉCIS d'inotify, eux, restent traités à chaque cycle (déjà collectés ci-dessus).
        if need_rescan {
            let min = std::time::Duration::from_secs(self.cfg.min_rescan_interval_secs);
            if rescan_due(self.last_rescan, std::time::Instant::now(), min) {
                self.last_rescan = Some(std::time::Instant::now());
            } else {
                need_rescan = false; // trop tôt -> on saute la marche complète ce cycle
            }
        }

        if need_rescan {
            // Union(fichiers présents, chemins baseline) -> capte aussi les SUPPRESSIONS.
            for r in &self.roots.clone() {
                let mut files = Vec::new();
                walk_root(r, self.cfg.recursive, self.cfg.max_files, &self.cfg.exclude, &mut files);
                for f in files {
                    set.insert(f);
                }
            }
            let known: Vec<PathBuf> =
                self.baseline.paths().map(PathBuf::from).collect();
            for p in known {
                if path_allowed(&p, &self.roots, &self.cfg.exclude) {
                    set.insert(p);
                }
            }
        }

        set.into_iter().take(max).collect()
    }
}

impl SourceReader for FimReader {
    fn source_id(&self) -> &str {
        &self.cfg.id
    }

    fn wire(&self) -> Wire {
        Wire::Events
    }

    fn open(&mut self, _cursor: Cursor) {
        // FIM ne reprend PAS via curseur (l'état est la baseline persistée). L'init est paresseuse au
        // 1er next_batch pour ne rien faire tant que le reader n'est pas sollicité.
        if self.cfg.paths.is_empty() {
            self.inert = true; // signal précoce (utile aux tests / au diagnostic)
        }
    }

    fn next_batch(&mut self, max: usize) -> Vec<NativeRecord> {
        self.ensure_init();
        if self.inert || max == 0 {
            return Vec::new();
        }
        let ts = super::now_secs();
        let candidates = self.collect_candidates(max);
        let mut out = Vec::new();
        // Fix #6 : couverture DÉGRADÉE (plafond max_files déjà atteint OU plafond watches/marks noyau)
        // -> on marque les events `fim_coverage=partial` pour que la troncature soit VISIBLE côté SOC,
        // pas seulement un warning stderr d'hôte. Calculé une fois par cycle.
        let coverage_partial =
            self.warned_cap || self.backend.as_ref().map_or(false, |b| b.degraded());
        for path in candidates {
            let key = path.to_string_lossy().to_string();
            let cur = self.probe.probe(&path);
            let prev = self.baseline.get(&key).cloned();
            // Fix #5 : chemin déjà refusé par le plafond `max_files` et absent de la baseline -> exclu du
            // diff. Sans ça, diff(None, Some)=Added se ré-émettrait à CHAQUE rescan (storm sans fin). Il
            // sera reconsidéré si un slot se libère (il entrera alors en baseline) ou à sa suppression.
            let over_cap_ignored = prev.is_none() && self.over_cap.contains(&key);
            if !over_cap_ignored {
                if let Some(change) = diff(prev.as_ref(), cur.as_ref()) {
                    // Anti-rafale : si ce chemin a déjà émis dans la fenêtre `debounce_ms`, on absorbe le
                    // changement dans la baseline SANS ré-émettre (borne le bruit d'un fichier réécrit vite).
                    let now = std::time::Instant::now();
                    let debounced = self.cfg.debounce_ms > 0
                        && self
                            .last_emit
                            .get(&key)
                            .map(|t| now.duration_since(*t).as_millis() < self.cfg.debounce_ms as u128)
                            .unwrap_or(false);
                    if !debounced {
                        let mut ev = change_to_event(
                            &change,
                            &path,
                            &self.host,
                            &self.cfg.id,
                            self.mode_label,
                            self.backend_name,
                            ts,
                        );
                        if coverage_partial {
                            if let Some(o) = ev.fields.as_object_mut() {
                                o.insert("fim_coverage".into(), Value::String("partial".into()));
                            }
                        }
                        out.push(NativeRecord { raw: ev.to_value().to_string(), cursor: None });
                        // Fix #3 : on ne PEUPLE `last_emit` QUE si le debounce est actif (sinon fuite d'une
                        // entrée par émission alors que la map n'est jamais lue).
                        if self.cfg.debounce_ms > 0 {
                            self.last_emit.insert(key.clone(), now);
                        }
                    }
                }
            }
            // Rafraîchit la baseline dans TOUS les cas (y compris changement non significatif) pour ne
            // pas ré-émettre. Suppression -> retire l'entrée ET purge les états annexes (fix #3/#5).
            match cur {
                Some(m) => {
                    if self.baseline.set(key.clone(), m, self.cfg.max_files) {
                        self.over_cap.remove(&key); // entré en baseline -> plus over-cap
                    } else {
                        self.warn_cap();
                        if self.over_cap.len() < OVER_CAP_MAX {
                            self.over_cap.insert(key.clone()); // borné
                        }
                    }
                }
                None => {
                    self.baseline.remove(&key);
                    self.over_cap.remove(&key);
                    self.last_emit.remove(&key); // fix #3 : purge sur suppression
                }
            }
        }
        self.sweep_last_emit(); // fix #3 : borne la croissance de last_emit
        self.baseline.save(&self.baseline_path);
        out
    }

    fn cursor(&self) -> Cursor {
        // Non reprenable via curseur : l'état FIM vit dans la baseline persistée.
        Cursor(None)
    }

    fn to_event(&self, rec: &NativeRecord) -> Option<Event> {
        // `raw` est le JSON de `Event::to_value()` (produit dans next_batch) -> on le reconstruit, en
        // réinjectant `host` (absent du contrat d'event, porté par l'enveloppe).
        let v: Value = serde_json::from_str(&rec.raw).ok()?;
        Some(Event {
            ts: v.get("ts").and_then(|x| x.as_i64()).unwrap_or_else(super::now_secs),
            host: self.host.clone(),
            source: v.get("source").and_then(|x| x.as_str()).unwrap_or(&self.cfg.id).to_string(),
            category: v.get("category").and_then(|x| x.as_str()).unwrap_or("integrity").to_string(),
            severity: v.get("severity").and_then(|x| x.as_i64()).unwrap_or(0),
            message: v.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            fields: v.get("fields").cloned().unwrap_or_else(|| json!({})),
            dedup: v.get("dedup").and_then(|x| x.as_str()).map(|s| s.to_string()),
        })
    }
}

/// Construit le backend noyau adapté à l'OS. `None` -> l'agent bascule en scan planifié (FIM partout).
fn build_backend(cfg: &FimCfg) -> Option<Box<dyn FimBackend>> {
    #[cfg(target_os = "linux")]
    {
        return linux::new_backend(cfg);
    }
    #[cfg(all(windows, feature = "fim_windows_native"))]
    {
        return windows::new_backend(cfg);
    }
    #[allow(unreachable_code)]
    {
        let _ = cfg;
        None
    }
}

/// Nettoie un id pour en faire un nom de fichier sûr.
fn sanitize_id(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Parcours récursif d'une racine (borné par `max_files`), SANS suivre les symlinks (anti-évasion) et
/// en élaguant les répertoires exclus tôt. Ajoute les FICHIERS réguliers retenus à `out`.
pub fn walk_root(root: &Path, recursive: bool, max_files: usize, exclude: &[String], out: &mut Vec<PathBuf>) {
    // Pile explicite -> pas de récursion profonde (arbres hostiles). Borne dure via max_files.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= max_files {
            return;
        }
        let md = match std::fs::symlink_metadata(&dir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.file_type().is_symlink() {
            continue; // ne JAMAIS suivre un lien (dir ou fichier)
        }
        if md.is_file() {
            let s = dir.to_string_lossy();
            if !exclude.iter().any(|p| glob_match(p, &s)) {
                out.push(dir);
            }
            continue;
        }
        if !md.is_dir() {
            continue;
        }
        let s = dir.to_string_lossy().to_string();
        if exclude.iter().any(|p| glob_match(p, &s)) {
            continue; // répertoire exclu -> élagué (pas de descente)
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ent in entries.flatten() {
            if out.len() >= max_files {
                return;
            }
            let p = ent.path();
            let emd = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if emd.file_type().is_symlink() {
                continue;
            }
            if emd.is_dir() {
                if recursive {
                    stack.push(p);
                }
            } else if emd.is_file() {
                let ps = p.to_string_lossy();
                if !exclude.iter().any(|pat| glob_match(pat, &ps)) {
                    out.push(p);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
