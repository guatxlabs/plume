//! Backend FIM Windows (#16/#58) — `ReadDirectoryChangesW` + I/O completion port, feature-gated
//! (`fim_windows_native`). Satisfait le MÊME `FimBackend` que le backend Linux (fanotify/inotify) : les
//! events bruts sont mappés dans le MÊME `FsEventKind` interne, de sorte que `diff`/`change_to_event`
//! produisent un CIM IDENTIQUE (`source=integrity`, champs `fim_*`) — les panneaux/règles FIM #57
//! s'allument sans changement daemon.
//!
//! ## Boucle (par racine surveillée)
//! `CreateFileW(root, FILE_LIST_DIRECTORY, share R|W|D, OPEN_EXISTING,
//!  FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED|FILE_FLAG_OPEN_REPARSE_POINT)` -> HANDLE de répertoire,
//! associé à UN `CreateIoCompletionPort` (clé = index du watch). Chaque watch arme un
//! `ReadDirectoryChangesW(bWatchSubtree=recursive, FILE_NAME|DIR_NAME|LAST_WRITE|SIZE|SECURITY|CREATION)`
//! en OVERLAPPED. `poll` DRAINE le port SANS BLOQUER (`GetQueuedCompletionStatus` timeout 0) : pour chaque
//! complétion il parse les `FILE_NOTIFY_INFORMATION`, ré-arme le watch (réutilise le buffer), et mappe les
//! `FILE_ACTION_*`. NB : `bWatchSubtree` couvre AUTOMATIQUEMENT les nouveaux sous-répertoires (pas besoin
//! de reposer un watch comme inotify) — on émet quand même `DirCreated` pour énumérer la fenêtre de course.
//!
//! ## Invariants (identiques au backend Linux)
//! - OBSERVATIONNEL STRICT : on lit des notifications, JAMAIS d'écriture/quarantaine. Aucune action hôte.
//! - Anti-évasion reparse (équivalent `O_NOFOLLOW` / `FAN_MARK_DONT_FOLLOW`) : la racine est refusée si
//!   c'est un point de reparse (symlink/jonction), le HANDLE est ouvert `FILE_FLAG_OPEN_REPARSE_POINT`
//!   (ne suit pas un reparse au dernier composant), et `bWatchSubtree` ne traverse PAS une jonction vers
//!   une autre cible (les changements de la cible sont sur SON volume, non remontés par la jonction). La
//!   probe (`RealProbe`) rejette de toute façon les non-réguliers -> un lien ne peut pas être hashé.
//! - Bornes anti-OOM : buffer BORNÉ (`BUF_BYTES`) par watch, plafond de watches (`max_watches` -> couverture
//!   dégradée signalée), lot borné à `max` par `poll` (au-delà -> `overflowed` -> rescan).
//! - Débordement : buffer trop petit pour une rafale -> le noyau complète avec 0 octet (ou
//!   `ERROR_NOTIFY_ENUM_DIR`) -> `overflowed=true` -> le reader fait un rescan de resynchro (comme le
//!   chemin overflow fanotify). Aucune perte silencieuse.
//! - Sans la feature `fim_windows_native`, ce backend N'EST PAS construit -> le reader bascule en scan
//!   planifié borné (le FIM tourne quand même sur Windows). MODE 0 (`paths` vide) : reader inerte.
//!
//! ## Validation runtime
//! La partie FFI nécessite un HÔTE Windows (CI/runner) : `ReadDirectoryChangesW` ne peut pas être exercé
//! en cross-compile. Le mapping/parsing PUR est testé sur Linux (ci-dessous) ; l'E2E temps réel reste à
//! valider sur un runner Windows (miroir : le chemin fanotify #58 demandait un runner root).
#![cfg_attr(not(all(target_os = "windows", feature = "fim_windows_native")), allow(dead_code))]

use super::FsEventKind;

/// Taille du buffer `FILE_NOTIFY_INFORMATION` par watch (octets). Alloué en `Vec<u32>` -> alignement DWORD
/// requis par l'API. 64 Kio : borne la mémoire par watch tout en absorbant de larges rafales locales ; en
/// cas de dépassement le noyau signale un débordement (complétion 0 octet) -> rescan (jamais de perte).
const BUF_BYTES: usize = 64 * 1024;

// FILE_ACTION_* (winnt.h) — valeurs Win32 STABLES, redéclarées pour que le mapping PUR compile et se TESTE
// sur Linux. Le backend FFI utilise les constantes équivalentes de la crate `windows` (mêmes valeurs).
const FILE_ACTION_ADDED: u32 = 0x1;
const FILE_ACTION_REMOVED: u32 = 0x2;
const FILE_ACTION_MODIFIED: u32 = 0x3;
const FILE_ACTION_RENAMED_OLD_NAME: u32 = 0x4;
const FILE_ACTION_RENAMED_NEW_NAME: u32 = 0x5;

/// Enregistrements décodés d'un buffer `FILE_NOTIFY_INFORMATION` : `(FILE_ACTION_*, nom UTF-16 relatif)`.
pub type NotifyRecords = Vec<(u32, Vec<u16>)>;

/// PUR (testé sur Linux) : `FILE_ACTION_*` (+ le chemin est-il un répertoire) -> `FsEventKind` interne,
/// le MÊME que celui émis par le backend Linux -> `diff`/`change_to_event` produisent un CIM identique.
/// Renommage : OLD_NAME = l'ancien chemin disparaît (`Deleted`), NEW_NAME = le nouveau apparaît
/// (`Created`/`DirCreated`) — exactement comme `IN_MOVED_FROM`/`IN_MOVED_TO` côté inotify. `None` = action
/// inconnue (ignorée). Le diff baseline tranche ensuite added/modified/deleted réel (une notification
/// `Modified` sur un fichier au contenu inchangé ne produit aucun event).
pub fn map_action(action: u32, is_dir: bool) -> Option<FsEventKind> {
    match action {
        FILE_ACTION_ADDED | FILE_ACTION_RENAMED_NEW_NAME => Some(if is_dir {
            FsEventKind::DirCreated
        } else {
            FsEventKind::Created
        }),
        FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => Some(FsEventKind::Deleted),
        FILE_ACTION_MODIFIED => Some(FsEventKind::Modified),
        _ => None,
    }
}

/// PUR (testé sur Linux) : découpe un buffer `FILE_NOTIFY_INFORMATION` en `(action, nom UTF-16 relatif)`.
/// Format d'un enregistrement (le buffer en chaîne plusieurs) :
///   `NextEntryOffset:u32 | Action:u32 | FileNameLength:u32 (OCTETS) | FileName[WCHAR]` (non NUL-terminé).
/// TOTALEMENT borné : aucun accès hors `buf` (longueurs/offsets clampés) et un `NextEntryOffset` malformé
/// (=0 = dernier, ou qui n'avance pas) arrête la boucle -> jamais de lecture infinie sur buffer hostile.
pub fn parse_notify_buffer(buf: &[u8]) -> NotifyRecords {
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        // En-tête = 12 octets (3 × u32). S'il ne tient pas dans ce qui reste, on arrête (sans overflow).
        if buf.len() < off || buf.len() - off < 12 {
            break;
        }
        let rd_u32 = |i: usize| u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let next = rd_u32(off) as usize;
        let action = rd_u32(off + 4);
        let namelen = rd_u32(off + 8) as usize; // OCTETS
        let name_start = off + 12;
        let name_end = name_start.saturating_add(namelen).min(buf.len());
        // Décode les WCHAR réellement présents (paires d'octets), en s'arrêtant à la borne clampée.
        let mut wname = Vec::with_capacity((name_end - name_start) / 2);
        let mut i = name_start;
        while i + 2 <= name_end {
            wname.push(u16::from_ne_bytes([buf[i], buf[i + 1]]));
            i += 2;
        }
        out.push((action, wname));
        if next == 0 {
            break; // dernier enregistrement
        }
        let noff = off.saturating_add(next);
        if noff <= off {
            break; // garde anti-boucle : NextEntryOffset qui n'avance pas
        }
        off = noff;
    }
    out
}

// ===================================================================================================
// FFI ReadDirectoryChangesW + completion port — HÔTE Windows uniquement (feature `fim_windows_native`).
// ===================================================================================================
#[cfg(all(target_os = "windows", feature = "fim_windows_native"))]
mod ffi {
    use super::super::{glob_match, FimBackend, PollResult, RawFsEvent};
    use super::{map_action, parse_notify_buffer, NotifyRecords, BUF_BYTES};
    use crate::config::FimCfg;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
        FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::{
        CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };

    /// Un répertoire surveillé : HANDLE + buffer (aligné DWORD via `Vec<u32>`) + OVERLAPPED (adresse
    /// STABLE en tas via `Box` -> le noyau peut y écrire tant que la lecture est en vol).
    struct Watch {
        handle: HANDLE,
        root: PathBuf,
        recursive: bool,
        buf: Vec<u32>,
        overlapped: Box<OVERLAPPED>,
    }

    /// (Ré)arme un `ReadDirectoryChangesW` OVERLAPPED sur le watch. Best-effort : un échec laisse le watch
    /// non armé -> un rescan comblera les manques et le prochain `poll` retentera.
    fn arm(w: &mut Watch) {
        // Réinitialise l'OVERLAPPED (le noyau s'en sert pour suivre l'op ; hEvent inutilisé -> IOCP).
        *w.overlapped = unsafe { std::mem::zeroed() };
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_SECURITY
            | FILE_NOTIFY_CHANGE_CREATION;
        let _ = unsafe {
            ReadDirectoryChangesW(
                w.handle,
                w.buf.as_mut_ptr() as *mut core::ffi::c_void,
                BUF_BYTES as u32,
                BOOL(w.recursive as i32),
                filter,
                None, // lpBytesReturned : ignoré en OVERLAPPED (récupéré via le completion port)
                Some(&mut *w.overlapped as *mut OVERLAPPED),
                None, // pas de completion routine : on utilise le port
            )
        };
    }

    pub struct WindowsFimBackend {
        iocp: HANDLE,
        recursive: bool,
        max_watches: usize,
        exclude: Vec<String>,
        watches: Vec<Watch>,
        degraded: bool,
    }

    /// Fabrique le backend : crée un completion port neuf. `None` (repli scan) si la création échoue.
    pub fn new_backend(cfg: &FimCfg) -> Option<Box<dyn FimBackend>> {
        // CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0) crée un port non associé.
        let iocp = match unsafe {
            CreateIoCompletionPort(INVALID_HANDLE_VALUE, HANDLE::default(), 0, 0)
        } {
            Ok(h) if !h.is_invalid() => h,
            _ => {
                eprintln!(
                    "[fim:{}] ReadDirectoryChangesW : CreateIoCompletionPort échoué -> repli scan planifié",
                    cfg.id
                );
                return None;
            }
        };
        eprintln!("[fim:{}] backend = readdirectorychanges (completion port)", cfg.id);
        Some(Box::new(WindowsFimBackend {
            iocp,
            recursive: cfg.recursive,
            max_watches: cfg.max_watches,
            exclude: cfg.exclude.clone(),
            watches: Vec::new(),
            degraded: false,
        }))
    }

    impl WindowsFimBackend {
        fn excluded(&self, p: &Path) -> bool {
            let s = p.to_string_lossy();
            self.exclude.iter().any(|pat| glob_match(pat, &s))
        }
    }

    impl FimBackend for WindowsFimBackend {
        fn name(&self) -> &'static str {
            "readdirectorychanges"
        }

        fn degraded(&self) -> bool {
            self.degraded // plafond max_watches atteint -> sous-arbres non surveillés
        }

        fn watch_root(&mut self, root: &Path) {
            if self.watches.len() >= self.max_watches {
                if !self.degraded {
                    self.degraded = true;
                    eprintln!("[fim] ReadDirectoryChangesW : plafond max_watches atteint -> couverture partielle");
                }
                return;
            }
            // Anti-évasion : ne surveille PAS une racine qui est un point de reparse (symlink/jonction) ->
            // n'ouvre pas de HANDLE vers une cible hors allowlist. Exige un répertoire (l'API en a besoin).
            match std::fs::symlink_metadata(root) {
                Ok(m) if m.file_type().is_symlink() => return,
                Ok(m) if !m.is_dir() => return,
                Ok(_) => {}
                Err(_) => return,
            }
            let wide: Vec<u16> = root.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let handle = match unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    FILE_LIST_DIRECTORY.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT,
                    HANDLE::default(),
                )
            } {
                Ok(h) if !h.is_invalid() => h,
                _ => {
                    eprintln!(
                        "[fim] ReadDirectoryChangesW : ouverture racine échouée {} (best-effort, ignorée)",
                        root.display()
                    );
                    return;
                }
            };
            // Associe le HANDLE au port ; clé = index du watch (STABLE : jamais retiré en cours de run).
            let key = self.watches.len();
            if unsafe { CreateIoCompletionPort(handle, self.iocp, key, 0) }.is_err() {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return;
            }
            let mut w = Watch {
                handle,
                root: root.to_path_buf(),
                recursive: self.recursive,
                buf: vec![0u32; BUF_BYTES / 4],
                overlapped: Box::new(unsafe { std::mem::zeroed() }),
            };
            arm(&mut w);
            self.watches.push(w);
        }

        fn poll(&mut self, max: usize) -> PollResult {
            let mut res = PollResult::default();
            loop {
                let mut bytes: u32 = 0;
                let mut key: usize = 0;
                let mut ov: *mut OVERLAPPED = core::ptr::null_mut();
                let r = unsafe {
                    GetQueuedCompletionStatus(self.iocp, &mut bytes, &mut key, &mut ov, 0)
                };
                match r {
                    Ok(()) => {
                        // Phase 1 (emprunt COURT de self.watches) : extrait les records + ré-arme le watch.
                        let extracted: Option<(PathBuf, NotifyRecords)> =
                            match self.watches.get_mut(key) {
                                Some(w) => {
                                    let out = if bytes == 0 {
                                        // Débordement : buffer trop petit -> complétion 0 octet -> rescan.
                                        res.overflowed = true;
                                        None
                                    } else {
                                        let n = (bytes as usize).min(BUF_BYTES);
                                        let raw = unsafe {
                                            std::slice::from_raw_parts(w.buf.as_ptr() as *const u8, n)
                                        };
                                        Some((w.root.clone(), parse_notify_buffer(raw)))
                                    };
                                    arm(w); // réutilise le buffer APRÈS parse
                                    out
                                }
                                None => None,
                            };
                        // Phase 2 (plus de &mut watches) : filtre exclusions + mappe -> RawFsEvent.
                        if let Some((root, records)) = extracted {
                            for (action, wname) in records {
                                let name = std::ffi::OsString::from_wide(&wname);
                                let path = root.join(&name);
                                if self.excluded(&path) {
                                    continue;
                                }
                                // ReadDirectoryChangesW ne dit pas si c'est un répertoire -> on stat SANS
                                // suivre les reparse (symlink_metadata). Un lien/reparse -> is_dir=false ->
                                // traité comme fichier puis rejeté par la probe (non régulier).
                                let is_dir = std::fs::symlink_metadata(&path)
                                    .map(|m| m.is_dir() && !m.file_type().is_symlink())
                                    .unwrap_or(false);
                                if let Some(kind) = map_action(action, is_dir) {
                                    res.events.push(RawFsEvent { path, kind });
                                    if res.events.len() >= max {
                                        // Lot borné : on préfère resynchroniser par rescan.
                                        res.overflowed = true;
                                        return res;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if ov.is_null() {
                            // Aucun paquet retiré : WAIT_TIMEOUT (rien de prêt) ou port fermé -> fin.
                            break;
                        }
                        // Une I/O a complété EN ERREUR (ex. ERROR_NOTIFY_ENUM_DIR = débordement,
                        // ERROR_OPERATION_ABORTED à l'arrêt). `key` = le watch -> rescan + ré-arme.
                        res.overflowed = true;
                        if let Some(w) = self.watches.get_mut(key) {
                            arm(w);
                        }
                    }
                }
            }
            res
        }
    }

    impl Drop for WindowsFimBackend {
        fn drop(&mut self) {
            for w in &self.watches {
                unsafe {
                    let _ = CancelIoEx(w.handle, None); // annule la lecture en vol
                    let _ = CloseHandle(w.handle);
                }
            }
            unsafe {
                let _ = CloseHandle(self.iocp);
            }
        }
    }
}

#[cfg(all(target_os = "windows", feature = "fim_windows_native"))]
pub use ffi::new_backend;

// ===================================================================================================
// Tests PURS (compilés/exécutés sur TOUTES les cibles, y compris Linux — cf. le mapping XML de #57).
// ===================================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::fim::FsEventKind;

    /// Encode un enregistrement FILE_NOTIFY_INFORMATION dans `buf` (endianness native, comme le noyau).
    fn push_record(buf: &mut Vec<u8>, next: u32, action: u32, name: &str) {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let namelen = (wide.len() * 2) as u32;
        buf.extend_from_slice(&next.to_ne_bytes());
        buf.extend_from_slice(&action.to_ne_bytes());
        buf.extend_from_slice(&namelen.to_ne_bytes());
        for w in wide {
            buf.extend_from_slice(&w.to_ne_bytes());
        }
    }

    #[test]
    fn map_action_matches_linux_vocabulary() {
        assert_eq!(map_action(FILE_ACTION_ADDED, false), Some(FsEventKind::Created));
        assert_eq!(map_action(FILE_ACTION_ADDED, true), Some(FsEventKind::DirCreated));
        assert_eq!(map_action(FILE_ACTION_REMOVED, false), Some(FsEventKind::Deleted));
        assert_eq!(map_action(FILE_ACTION_MODIFIED, false), Some(FsEventKind::Modified));
        // Renommage : old = disparition (Deleted), new = apparition (Created/DirCreated) — cf. inotify.
        assert_eq!(map_action(FILE_ACTION_RENAMED_OLD_NAME, false), Some(FsEventKind::Deleted));
        assert_eq!(map_action(FILE_ACTION_RENAMED_NEW_NAME, false), Some(FsEventKind::Created));
        assert_eq!(map_action(FILE_ACTION_RENAMED_NEW_NAME, true), Some(FsEventKind::DirCreated));
        assert_eq!(map_action(0xDEAD, false), None);
    }

    #[test]
    fn parse_single_record_decodes_name_and_action() {
        let mut buf = Vec::new();
        push_record(&mut buf, 0, FILE_ACTION_MODIFIED, "sub\\file.txt");
        let recs = parse_notify_buffer(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, FILE_ACTION_MODIFIED);
        assert_eq!(String::from_utf16_lossy(&recs[0].1), "sub\\file.txt");
    }

    #[test]
    fn parse_multiple_chained_records() {
        let mut buf = Vec::new();
        // 1er : NextEntryOffset = 12 + longueur du nom (octets).
        let n1 = "a.txt";
        let next1 = 12 + (n1.encode_utf16().count() * 2) as u32;
        push_record(&mut buf, next1, FILE_ACTION_ADDED, n1);
        push_record(&mut buf, 0, FILE_ACTION_REMOVED, "b.log");
        let recs = parse_notify_buffer(&buf);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].0, FILE_ACTION_ADDED);
        assert_eq!(String::from_utf16_lossy(&recs[0].1), "a.txt");
        assert_eq!(recs[1].0, FILE_ACTION_REMOVED);
        assert_eq!(String::from_utf16_lossy(&recs[1].1), "b.log");
    }

    #[test]
    fn parse_stops_on_nonadvancing_offset() {
        // NextEntryOffset != 0 mais qui n'avance pas (=4) : ne doit PAS boucler à l'infini.
        let mut buf = Vec::new();
        push_record(&mut buf, 4, FILE_ACTION_ADDED, "x");
        let recs = parse_notify_buffer(&buf);
        assert_eq!(recs.len(), 1, "un offset non-avançant arrête le parsing (anti-boucle)");
    }

    #[test]
    fn parse_truncated_buffer_is_bounded() {
        // FileNameLength annonce plus d'octets que présents -> clampé, aucun accès hors borne.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes()); // next = 0
        buf.extend_from_slice(&FILE_ACTION_ADDED.to_ne_bytes());
        buf.extend_from_slice(&9999u32.to_ne_bytes()); // namelen énorme
        buf.extend_from_slice(&"hi".encode_utf16().flat_map(|w| w.to_ne_bytes()).collect::<Vec<_>>());
        let recs = parse_notify_buffer(&buf);
        assert_eq!(recs.len(), 1);
        assert_eq!(String::from_utf16_lossy(&recs[0].1), "hi");
    }

    #[test]
    fn parse_empty_buffer_yields_nothing() {
        assert!(parse_notify_buffer(&[]).is_empty());
        assert!(parse_notify_buffer(&[0u8; 8]).is_empty(), "en-tête incomplet -> rien");
    }
}
