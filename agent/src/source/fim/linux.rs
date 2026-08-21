//! Backends FIM Linux (#58) : `fanotify` (préféré, CAP_SYS_ADMIN) + repli `inotify` (sans capability).
//!
//! Sélection (`new_backend`) : on TENTE fanotify d'abord ; si `fanotify_init` échoue (EPERM sans
//! CAP_SYS_ADMIN, ENOSYS sur vieux noyau), on RETOMBE proprement sur inotify — jamais de crash. Sans
//! aucun des deux (impossible en pratique sur Linux), `None` -> le reader bascule en scan planifié.
//!
//! - `InotifyBackend` : watch par RÉPERTOIRE (les events enfants remontent avec `name`), reconstruit le
//!   chemin absolu via une table `wd -> dir`. Récursif : un `IN_CREATE|IN_ISDIR` pose un nouveau watch.
//!   Gère ENOSPC (plafond de watches noyau) et le plafond `max_watches` en DÉGRADANT (couverture
//!   partielle + log unique), jamais en plantant. Précis : produit un `RawFsEvent` par chemin touché.
//! - `FanotifyBackend` : marque récursivement les répertoires (FAN_MARK_ADD + FAN_EVENT_ON_CHILD) et
//!   fonctionne en SONNETTE (doorbell) : tout event draine le fd et lève `overflowed` -> le reader fait
//!   un rescan borné qui identifie exactement quoi a changé (diff baseline). On profite de la détection
//!   temps réel de fanotify sans dépendre du décodage `open_by_handle_at` (FAN_REPORT_DFID_NAME), qui
//!   demande une VALIDATION EN ROOT et est laissé à une itération ultérieure (cf. rapport #58).
//!   LIMITE connue : un sous-arbre créé APRÈS l'init n'est marqué qu'au niveau de son parent -> les
//!   changements profonds dans un tout nouveau sous-arbre peuvent n'être vus qu'au prochain rescan.
#![cfg(target_os = "linux")]

use super::{FimBackend, FsEventKind, PollResult, RawFsEvent};
use crate::config::FimCfg;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Fabrique le backend Linux : fanotify si permis, sinon inotify. `None` seulement si les DEUX échouent.
pub fn new_backend(cfg: &FimCfg) -> Option<Box<dyn FimBackend>> {
    match FanotifyBackend::try_new(cfg) {
        Some(f) => {
            eprintln!("[fim:{}] backend = fanotify (CAP_SYS_ADMIN présent)", cfg.id);
            Some(Box::new(f))
        }
        None => match InotifyBackend::try_new(cfg) {
            Some(i) => {
                eprintln!("[fim:{}] backend = inotify (fanotify indisponible)", cfg.id);
                Some(Box::new(i))
            }
            None => {
                eprintln!("[fim:{}] ni fanotify ni inotify -> repli scan planifié", cfg.id);
                None
            }
        },
    }
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn cpath(p: &Path) -> Option<CString> {
    CString::new(p.as_os_str().as_bytes()).ok()
}

// ===================================================================================================
// inotify
// ===================================================================================================

const IN_MASK: u32 = libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_CLOSE_WRITE
    | libc::IN_DONT_FOLLOW   // ne pas déréférencer un symlink lors de add_watch
    | libc::IN_EXCL_UNLINK;  // arrête d'émettre pour un enfant délié

pub struct InotifyBackend {
    fd: i32,
    recursive: bool,
    max_watches: usize,
    exclude: Vec<String>,
    wds: HashMap<i32, PathBuf>,
    warned_space: bool,
    /// `P4.1-q` — POINTS DE COUVERTURE ABANDONNÉS, comptés. Un `stat` refusé, un `read_dir` refusé,
    /// une entrée illisible, un chemin qu'on ne peut pas convertir, un watch refusé par le noyau :
    /// chacun retire de la surveillance un chemin — ou un SOUS-ARBRE ENTIER — sans que rien ne se
    /// passe. La couverture annoncée par la configuration cesse alors d'être la couverture réelle,
    /// et la détection s'éteint là SANS TRACE. Le parcours continue (une branche refusée ne doit pas
    /// faire perdre les autres), mais il COMPTE, `watch_root` rend le compte, et le lecteur avoue.
    perdus: usize,
}

impl InotifyBackend {
    pub fn try_new(cfg: &FimCfg) -> Option<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        Some(Self {
            fd,
            recursive: cfg.recursive,
            max_watches: cfg.max_watches,
            exclude: cfg.exclude.clone(),
            wds: HashMap::new(),
            warned_space: false,
            perdus: 0,
        })
    }

    fn excluded(&self, p: &Path) -> bool {
        let s = p.to_string_lossy();
        self.exclude.iter().any(|pat| super::glob_match(pat, &s))
    }

    /// Ajoute UN watch sur un chemin (dir OU fichier racine). Respecte le plafond et ENOSPC.
    fn add_one(&mut self, path: &Path) {
        if self.wds.len() >= self.max_watches {
            self.warn_space("max_watches");
            return;
        }
        let Some(cp) = cpath(path) else {
            // Un chemin qui ne se convertit pas (octet NUL) ne pourra JAMAIS être surveillé.
            self.perdus += 1;
            return;
        };
        let wd = unsafe { libc::inotify_add_watch(self.fd, cp.as_ptr(), IN_MASK) };
        if wd < 0 {
            let e = last_errno();
            if e == libc::ENOSPC {
                // Le plafond a déjà son drapeau (`warned_space`) : il n'entre pas dans `perdus`,
                // sans quoi la même dégradation serait annoncée deux fois.
                self.warn_space("ENOSPC noyau (fs.inotify.max_user_watches)");
            } else {
                // Refus du noyau (droits, chemin disparu) : ce point sort de la surveillance.
                self.perdus += 1;
            }
            return;
        }
        self.wds.insert(wd, path.to_path_buf());
    }

    fn warn_space(&mut self, why: &str) {
        if !self.warned_space {
            self.warned_space = true;
            eprintln!("[fim] inotify : plafond de watches atteint ({why}) -> couverture partielle (dégradation)");
        }
    }

    /// Marque récursivement les répertoires sous `root` (sans suivre les symlinks). Si `root` est un
    /// simple fichier, pose un watch dessus directement.
    fn add_recursive(&mut self, root: &Path) {
        let md = match std::fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(_) => {
                self.perdus += 1; // racine (ou sous-arbre) entière : elle ne sera JAMAIS surveillée
                return;
            }
        };
        if md.file_type().is_symlink() {
            return;
        }
        if md.is_file() {
            self.add_one(root);
            return;
        }
        if !md.is_dir() || self.excluded(root) {
            if md.is_dir() {
                return;
            }
            return;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if self.wds.len() >= self.max_watches {
                self.warn_space("max_watches");
                return;
            }
            self.add_one(&dir);
            if !self.recursive {
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    self.perdus += 1; // tout le contenu de ce répertoire sort de la surveillance
                    continue;
                }
            };
            for ent in entries {
                let ent = match ent {
                    Ok(e) => e,
                    Err(_) => {
                        self.perdus += 1; // une entrée non énumérée est une entrée non surveillée
                        continue;
                    }
                };
                let p = ent.path();
                match std::fs::symlink_metadata(&p) {
                    Ok(m) if m.is_dir() && !m.file_type().is_symlink() && !self.excluded(&p) => {
                        stack.push(p);
                    }
                    // LU : ce n'est pas un répertoire à descendre, ou c'est un lien qu'on ne suit
                    // jamais, ou il est exclu. Un constat, pas une incapacité — rien à compter.
                    Ok(_) => {}
                    Err(_) => self.perdus += 1,
                }
            }
        }
    }
}

impl FimBackend for InotifyBackend {
    fn name(&self) -> &'static str {
        "inotify"
    }

    fn degraded(&self) -> bool {
        // Plafond atteint, OU points abandonnés faute d'avoir pu lire / faire accepter un watch :
        // dans les deux cas des sous-arbres ne sont PAS surveillés.
        self.warned_space || self.perdus > 0
    }

    fn watch_root(&mut self, root: &Path) -> usize {
        let avant = self.perdus;
        self.add_recursive(root);
        self.perdus - avant
    }

    fn poll(&mut self, max: usize) -> PollResult {
        let mut res = PollResult::default();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = unsafe {
                libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n < 0 {
                // EAGAIN (= EWOULDBLOCK sur Linux) = plus rien à lire (fd non bloquant) -> fin
                // NORMALE, et EINTR se rejoue au prochain cycle. Toute AUTRE erreur veut dire que ce
                // backend n'entendra plus jamais rien : elle est COMPTÉE, jamais confondue avec du
                // calme (`P4.1-q` — une détection qui s'éteint doit laisser une trace).
                let e = last_errno();
                if e != libc::EAGAIN && e != libc::EINTR {
                    self.perdus += 1;
                }
                break;
            }
            if n == 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + 16 <= n {
                let wd = i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                let mask = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
                let len = u32::from_ne_bytes([buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]]) as usize;
                let name_start = off + 16;
                let name_end = (name_start + len).min(n);
                let name = &buf[name_start..name_end];
                off = name_start + len;

                if mask & libc::IN_Q_OVERFLOW != 0 {
                    res.overflowed = true;
                    continue;
                }
                // Watch retiré par le noyau (dir supprimé/démonté) -> nettoie la table.
                if mask & libc::IN_IGNORED != 0 {
                    self.wds.remove(&wd);
                    continue;
                }
                let Some(base) = self.wds.get(&wd).cloned() else { continue };
                // name est NUL-terminé/paddé -> tronque au premier NUL.
                let name_trim: &[u8] = match name.iter().position(|&b| b == 0) {
                    Some(i) => &name[..i],
                    None => name,
                };
                let path = if name_trim.is_empty() {
                    base
                } else {
                    base.join(std::ffi::OsStr::from_bytes(name_trim))
                };
                if self.excluded(&path) {
                    continue;
                }

                let is_dir = mask & libc::IN_ISDIR != 0;
                let kind = if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                    if is_dir {
                        FsEventKind::DirCreated
                    } else {
                        FsEventKind::Created
                    }
                } else if mask & (libc::IN_DELETE | libc::IN_DELETE_SELF | libc::IN_MOVED_FROM | libc::IN_MOVE_SELF) != 0 {
                    FsEventKind::Deleted
                } else if mask & libc::IN_ATTRIB != 0 {
                    FsEventKind::Attrib
                } else {
                    FsEventKind::Modified
                };

                // Nouveau sous-répertoire -> pose un watch (couverture récursive continue).
                if kind == FsEventKind::DirCreated && self.recursive {
                    self.add_recursive(&path);
                }
                res.events.push(RawFsEvent { path, kind });

                if res.events.len() >= max {
                    // Batch borné : on préfère resynchroniser par rescan que gonfler la RAM.
                    res.overflowed = true;
                    return res;
                }
            }
        }
        res
    }
}

impl Drop for InotifyBackend {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

// ===================================================================================================
// fanotify (préféré ; doorbell + rescan)
// ===================================================================================================

const FAN_MASK: u64 = libc::FAN_CREATE
    | libc::FAN_DELETE
    | libc::FAN_DELETE_SELF
    | libc::FAN_MOVED_FROM
    | libc::FAN_MOVED_TO
    | libc::FAN_MODIFY
    | libc::FAN_ATTRIB
    | libc::FAN_ONDIR
    | libc::FAN_EVENT_ON_CHILD;

pub struct FanotifyBackend {
    fd: i32,
    recursive: bool,
    max_watches: usize,
    exclude: Vec<String>,
    marks: usize,
    warned_space: bool,
    /// `P4.1-q` — POINTS DE COUVERTURE ABANDONNÉS (même rôle que dans `InotifyBackend`).
    perdus: usize,
}

impl FanotifyBackend {
    pub fn try_new(cfg: &FimCfg) -> Option<Self> {
        // FAN_CLASS_NOTIF (notification pure, pas de permission) + FAN_REPORT_DFID_NAME (identifie les
        // events d'entrée de répertoire) + non bloquant. EPERM (pas de CAP_SYS_ADMIN) / ENOSYS -> None.
        let flags = libc::FAN_CLASS_NOTIF
            | libc::FAN_REPORT_DFID_NAME
            | libc::FAN_NONBLOCK
            | libc::FAN_CLOEXEC;
        let fd = unsafe { libc::fanotify_init(flags, libc::O_RDONLY as u32) };
        if fd < 0 {
            return None;
        }
        Some(Self {
            fd,
            recursive: cfg.recursive,
            max_watches: cfg.max_watches,
            exclude: cfg.exclude.clone(),
            marks: 0,
            warned_space: false,
            perdus: 0,
        })
    }

    fn excluded(&self, p: &Path) -> bool {
        let s = p.to_string_lossy();
        self.exclude.iter().any(|pat| super::glob_match(pat, &s))
    }

    fn warn_space(&mut self) {
        if !self.warned_space {
            self.warned_space = true;
            eprintln!("[fim] fanotify : plafond de marks atteint -> couverture partielle");
        }
    }

    fn mark_one(&mut self, dir: &Path) {
        if self.marks >= self.max_watches {
            self.warn_space();
            return;
        }
        let Some(cp) = cpath(dir) else {
            // Un chemin qui ne se convertit pas (octet NUL) ne pourra JAMAIS être marqué.
            self.perdus += 1;
            return;
        };
        // FAN_MARK_DONT_FOLLOW : si `dir` est (devenu) un lien symbolique, NE PAS le déréférencer -> un
        // répertoire substitué par un lien ne peut pas faire marquer une cible HORS des racines (miroir
        // de IN_DONT_FOLLOW côté inotify). Anti-évasion symlink au niveau de la pose de mark.
        let r = unsafe {
            libc::fanotify_mark(
                self.fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_DONT_FOLLOW,
                FAN_MASK,
                libc::AT_FDCWD,
                cp.as_ptr(),
            )
        };
        if r == 0 {
            self.marks += 1;
        } else {
            // Le noyau a refusé la marque : ce répertoire ne signalera rien. Compté, jamais avalé.
            self.perdus += 1;
        }
    }

    fn mark_recursive(&mut self, root: &Path) {
        let md = match std::fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(_) => {
                self.perdus += 1; // racine (ou sous-arbre) entière : elle ne sera JAMAIS marquée
                return;
            }
        };
        if md.file_type().is_symlink() {
            return;
        }
        // fanotify marque des répertoires (les events enfants remontent via FAN_EVENT_ON_CHILD). Pour un
        // fichier racine isolé, on marque son répertoire parent.
        if md.is_file() {
            match root.parent() {
                Some(parent) => self.mark_one(parent),
                // Un fichier sans parent ne peut pas être marqué : il sort de la surveillance.
                None => self.perdus += 1,
            }
            return;
        }
        if !md.is_dir() || self.excluded(root) {
            return;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if self.marks >= self.max_watches {
                self.warn_space(); // le plafond se DIT ici aussi, pas seulement dans `mark_one`
                return;
            }
            self.mark_one(&dir);
            if !self.recursive {
                continue;
            }
            match std::fs::read_dir(&dir) {
                Ok(entries) => {
                    for ent in entries {
                        let ent = match ent {
                            Ok(e) => e,
                            Err(_) => {
                                self.perdus += 1; // entrée non énumérée = entrée non surveillée
                                continue;
                            }
                        };
                        let p = ent.path();
                        match std::fs::symlink_metadata(&p) {
                            Ok(m) => {
                                if m.is_dir() && !m.file_type().is_symlink() && !self.excluded(&p) {
                                    stack.push(p);
                                }
                            }
                            Err(_) => self.perdus += 1,
                        }
                    }
                }
                Err(_) => self.perdus += 1, // tout le contenu de ce répertoire sort de la surveillance
            }
        }
    }
}

impl FimBackend for FanotifyBackend {
    fn name(&self) -> &'static str {
        "fanotify"
    }

    fn degraded(&self) -> bool {
        // Plafond de marks atteint, OU points abandonnés faute d'avoir pu lire / faire accepter une
        // marque : dans les deux cas des sous-arbres ne sont PAS surveillés.
        self.warned_space || self.perdus > 0
    }

    fn watch_root(&mut self, root: &Path) -> usize {
        let avant = self.perdus;
        self.mark_recursive(root);
        self.perdus - avant
    }

    fn poll(&mut self, _max: usize) -> PollResult {
        // Doorbell : on DRAINE tout le fd sans décoder les records (le décodage DFID_NAME exact demande
        // open_by_handle_at + validation root). Toute activité -> `overflowed=true` -> le reader fait un
        // rescan borné qui identifie précisément les changements via la baseline.
        let mut res = PollResult::default();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = unsafe {
                libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n <= 0 {
                // EAGAIN (= EWOULDBLOCK sur Linux) = rien à lire, EINTR se rejoue : fin NORMALE.
                // Toute AUTRE erreur veut dire que la sonnette ne sonnera plus jamais — c'est une
                // détection qui s'éteint, et elle est COMPTÉE au lieu de passer pour du calme.
                if n < 0 {
                    let e = last_errno();
                    if e != libc::EAGAIN && e != libc::EINTR {
                        self.perdus += 1;
                    }
                }
                break;
            }
            res.overflowed = true; // activité détectée -> demander le rescan
        }
        res
    }
}

impl Drop for FanotifyBackend {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
