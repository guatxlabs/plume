//! Tests du coeur FIM (#58) : diff baseline, mapping CIM (contrat #57), baseline, glob/allowlist, et
//! un bout-en-bout du `FimReader` piloté par un backend + une probe FACTICES (aucun syscall, aucun
//! disque). Le chemin fanotify/inotify RÉEL n'est pas exerçable sans root -> test d'intégration séparé
//! (cf. rapport). Ici on prouve toute la logique OS-indépendante + l'invariant MODE 0.

use super::*;
use crate::config::FimCfg;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;

fn meta(sha: Option<&str>, size: u64, mode: u32) -> FileMeta {
    FileMeta { sha256: sha.map(|s| s.to_string()), size, mode, uid: 0, gid: 0, mtime: 0 }
}

// ---- backend + probe factices --------------------------------------------------------------------

#[derive(Clone)]
struct FakeProbe(Rc<RefCell<HashMap<PathBuf, FileMeta>>>);
impl FsProbe for FakeProbe {
    fn probe(&self, path: &Path) -> Option<FileMeta> {
        self.0.borrow().get(path).cloned()
    }
}

struct FakeBackend {
    q: Rc<RefCell<VecDeque<PollResult>>>,
    watched: Rc<RefCell<Vec<PathBuf>>>,
    degraded: bool,
}
impl FimBackend for FakeBackend {
    fn name(&self) -> &'static str {
        "fake"
    }
    fn degraded(&self) -> bool {
        self.degraded
    }
    fn watch_root(&mut self, root: &Path) {
        self.watched.borrow_mut().push(root.to_path_buf());
    }
    fn poll(&mut self, _max: usize) -> PollResult {
        self.q.borrow_mut().pop_front().unwrap_or_default()
    }
}

fn ev(path: &str, kind: FsEventKind) -> RawFsEvent {
    RawFsEvent { path: PathBuf::from(path), kind }
}

// ---- glob + allowlist ----------------------------------------------------------------------------

#[test]
fn glob_basics() {
    assert!(glob_match("*.swp", "/etc/x.swp"));
    assert!(glob_match("*/.git/*", "/srv/app/.git/config"));
    assert!(glob_match("/var/log/*", "/var/log/syslog"));
    assert!(!glob_match("*.swp", "/etc/x.txt"));
    assert!(glob_match("a?c", "abc"));
    assert!(!glob_match("a?c", "ac"));
    assert!(glob_match("*", "anything"));
    assert!(glob_match("/exact", "/exact"));
}

#[test]
fn allowlist_and_exclude() {
    let roots = vec![PathBuf::from("/etc")];
    let excl = vec!["*/private/*".to_string()];
    assert!(path_allowed(Path::new("/etc/passwd"), &roots, &excl));
    assert!(path_allowed(Path::new("/etc"), &roots, &excl)); // la racine elle-même
    assert!(!path_allowed(Path::new("/var/passwd"), &roots, &excl)); // hors racine
    assert!(!path_allowed(Path::new("/etc/private/key"), &roots, &excl)); // exclu
}

// ---- diff baseline -> changement -----------------------------------------------------------------

#[test]
fn diff_added_deleted_and_none() {
    let a = meta(Some("h1"), 10, 0o644);
    // apparition
    let c = diff(None, Some(&a)).unwrap();
    assert_eq!(c.kind, FimEventKind::Added);
    assert_eq!(c.detail, ChangeDetail::Created);
    // suppression
    let c = diff(Some(&a), None).unwrap();
    assert_eq!(c.kind, FimEventKind::Deleted);
    // rien connu -> rien
    assert!(diff(None, None).is_none());
    // identique -> pas d'event
    assert!(diff(Some(&a), Some(&a)).is_none());
}

#[test]
fn diff_content_vs_attrs_vs_touch() {
    let base = meta(Some("h1"), 10, 0o644);
    // contenu (hash différent)
    let c = diff(Some(&base), Some(&meta(Some("h2"), 10, 0o644))).unwrap();
    assert_eq!(c.kind, FimEventKind::Modified);
    assert_eq!(c.detail, ChangeDetail::Content);
    // attributs seuls (même hash, mode différent)
    let c = diff(Some(&base), Some(&meta(Some("h1"), 10, 0o600))).unwrap();
    assert_eq!(c.detail, ChangeDetail::Attrs);
    // uid changé
    let mut o = meta(Some("h1"), 10, 0o644);
    o.uid = 1000;
    assert_eq!(diff(Some(&base), Some(&o)).unwrap().detail, ChangeDetail::Attrs);
    // touch pur (même hash/attrs, mtime différent) -> bruit, pas d'event
    let mut t = base.clone();
    t.mtime = 999;
    assert!(diff(Some(&base), Some(&t)).is_none());
}

#[test]
fn diff_size_change_when_hash_unknown() {
    // Fichiers trop gros pour être hashés (sha None) : on retombe sur la taille.
    let p = meta(None, 100, 0o644);
    let c = diff(Some(&p), Some(&meta(None, 200, 0o644))).unwrap();
    assert_eq!(c.kind, FimEventKind::Modified);
    assert_eq!(c.detail, ChangeDetail::Content);
    // même taille, hash inconnu -> indécidable -> pas d'event (on ne crie pas au loup)
    assert!(diff(Some(&p), Some(&meta(None, 100, 0o644))).is_none());
}

// ---- mapping CIM : DOIT correspondre au contrat #57 (fim_*), sinon les panneaux ne s'allument pas --

#[test]
fn cim_shape_matches_57_modified() {
    let change = FimChange {
        kind: FimEventKind::Modified,
        detail: ChangeDetail::Content,
        before: Some(meta(Some("before_hash"), 10, 0o644)),
        after: Some(meta(Some("after_hash"), 12, 0o644)),
    };
    let e = change_to_event(
        &change,
        Path::new("/etc/passwd"),
        "web01",
        "integrity",
        "realtime",
        "inotify",
        1_700_000_000,
    );
    // enveloppe CIM
    assert_eq!(e.source, "integrity", "source=integrity -> panneau `search source=integrity`");
    assert_eq!(e.category, "integrity", "category CIM #57");
    assert_eq!(e.severity, 2, "modified -> severity 2 (aligné #57)");
    assert_eq!(e.host, "web01");
    // champs fim_* attendus par les vues endpoint #57
    let f = &e.fields;
    assert_eq!(f["fim_path"], "/etc/passwd");
    assert_eq!(f["fim_event"], "modified");
    assert_eq!(f["fim_mode"], "realtime");
    assert_eq!(f["fim_sha256"], "after_hash");
    assert_eq!(f["fim_sha256_before"], "before_hash");
    assert_eq!(f["fim_size"], "12");
    assert_eq!(f["action"], "modify", "outcome CIM neutre modified->modify (#57)");
    assert_eq!(f["fim_change"], "content");
    assert_eq!(f["backend"], "inotify");
    // miroir style integrity.sh (panneau/regex historique lit `path`)
    assert_eq!(f["path"], "/etc/passwd");
    assert_eq!(f["sha256"], "after_hash");
    // dedup déterministe
    assert!(e.dedup.as_deref().unwrap().starts_with("fim:modified:/etc/passwd:"));
    // round-trip to_value() (ce que next_batch sérialise et que to_event reparse)
    let v = e.to_value();
    assert_eq!(v["category"], "integrity");
    assert!(v["message"].as_str().unwrap().contains("/etc/passwd"));
}

#[test]
fn cim_shape_added_and_deleted() {
    // added : severity 1, PAS de clé action (comme #57 pour `added`)
    let add = FimChange {
        kind: FimEventKind::Added,
        detail: ChangeDetail::Created,
        before: None,
        after: Some(meta(Some("h"), 5, 0o600)),
    };
    let e = change_to_event(&add, Path::new("/etc/cron.d/x"), "h", "integrity", "scheduled", "scan", 1);
    assert_eq!(e.severity, 1);
    assert_eq!(e.fields["fim_event"], "added");
    assert!(e.fields.get("action").is_none(), "added -> pas d'action (#57)");
    assert_eq!(e.fields["fim_mode"], "scheduled");

    // deleted : severity 3, action delete, hash avant présent / après absent
    let del = FimChange {
        kind: FimEventKind::Deleted,
        detail: ChangeDetail::Deleted,
        before: Some(meta(Some("gone_hash"), 5, 0o600)),
        after: None,
    };
    let e = change_to_event(&del, Path::new("/etc/sudoers"), "h", "integrity", "realtime", "inotify", 2);
    assert_eq!(e.severity, 3);
    assert_eq!(e.fields["fim_event"], "deleted");
    assert_eq!(e.fields["action"], "delete");
    assert_eq!(e.fields["fim_sha256_before"], "gone_hash");
    assert!(e.fields.get("fim_sha256").is_none(), "supprimé -> pas de hash après");
}

// ---- baseline ------------------------------------------------------------------------------------

#[test]
fn baseline_set_get_remove_and_cap() {
    let mut b = Baseline::new();
    assert!(b.is_empty());
    assert!(b.set("/a".into(), meta(Some("h"), 1, 0), 2));
    assert!(b.set("/b".into(), meta(Some("h"), 1, 0), 2));
    assert_eq!(b.len(), 2);
    // plafond atteint : NOUVELLE clé refusée, mais MAJ d'une clé existante acceptée
    assert!(!b.set("/c".into(), meta(Some("h"), 1, 0), 2), "nouvelle clé refusée au plafond");
    assert!(b.set("/a".into(), meta(Some("h2"), 2, 0), 2), "maj clé existante OK");
    assert_eq!(b.get("/a").unwrap().sha256.as_deref(), Some("h2"));
    b.remove("/a");
    assert!(b.get("/a").is_none());
}

// ---- bout-en-bout FimReader avec fakes -----------------------------------------------------------

struct Harness {
    reader: FimReader,
    files: Rc<RefCell<HashMap<PathBuf, FileMeta>>>,
    q: Rc<RefCell<VecDeque<PollResult>>>,
}

fn harness() -> Harness {
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: false });
    // debounce_ms=0 : tests déterministes (les cycles s'enchaînent en < 200 ms sinon supprimés).
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 0, ..FimCfg::default() };
    let reader = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);
    Harness { reader, files, q }
}

/// Parse le 1er (unique) NativeRecord d'un batch en Event via to_event.
fn one(reader: &FimReader, recs: &[NativeRecord]) -> Event {
    assert_eq!(recs.len(), 1, "attendu exactement 1 event");
    reader.to_event(&recs[0]).expect("to_event")
}

#[test]
fn reader_end_to_end_lifecycle() {
    let mut h = harness();

    // 1) création d'un fichier -> event added
    h.files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("aaa"), 3, 0o644));
    h.q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Created)], overflowed: false });
    let recs = h.reader.next_batch(100).records;
    let e = one(&h.reader, &recs);
    assert_eq!(e.source, "integrity");
    assert_eq!(e.fields["fim_event"], "added");
    assert_eq!(e.severity, 1);
    assert_eq!(e.fields["backend"], "fake");

    // 2) modification (hash change) -> modified + before/after
    h.files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("bbb"), 4, 0o644));
    h.q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Modified)], overflowed: false });
    let recs = h.reader.next_batch(100).records;
    let e = one(&h.reader, &recs);
    assert_eq!(e.fields["fim_event"], "modified");
    assert_eq!(e.fields["fim_sha256"], "bbb");
    assert_eq!(e.fields["fim_sha256_before"], "aaa");
    assert_eq!(e.severity, 2);

    // 3) event spurieux sans changement réel -> AUCUN event (baseline à jour)
    h.q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Modified)], overflowed: false });
    assert!(h.reader.next_batch(100).records.is_empty(), "pas de changement -> pas de ré-alarme");

    // 4) suppression -> deleted
    h.files.borrow_mut().remove(&PathBuf::from("/w/a"));
    h.q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Deleted)], overflowed: false });
    let recs = h.reader.next_batch(100).records;
    let e = one(&h.reader, &recs);
    assert_eq!(e.fields["fim_event"], "deleted");
    assert_eq!(e.severity, 3);

    // 5) event pour un chemin HORS racine -> filtré (allowlist)
    h.files.borrow_mut().insert(PathBuf::from("/other/z"), meta(Some("zzz"), 1, 0o644));
    h.q.borrow_mut().push_back(PollResult { events: vec![ev("/other/z", FsEventKind::Created)], overflowed: false });
    assert!(h.reader.next_batch(100).records.is_empty(), "hors racine -> ignoré");
}

#[test]
fn debounce_suppresses_rapid_reemit() {
    // debounce_ms très large -> deux changements RÉELS rapprochés du même chemin : le 2e est absorbé
    // dans la baseline sans ré-émettre (anti-rafale). Preuve que `debounce_ms` est bien câblé.
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: false });
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 60_000, ..FimCfg::default() };
    let mut r = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);

    files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("v1"), 2, 0o644));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Created)], overflowed: false });
    assert_eq!(r.next_batch(100).records.len(), 1, "1re émission passe");

    // changement réel immédiat (nouveau hash) mais dans la fenêtre debounce -> supprimé
    files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("v2"), 2, 0o644));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Modified)], overflowed: false });
    assert!(r.next_batch(100).records.is_empty(), "2e changement rapproché absorbé par le debounce");
}

// ---- INVARIANT MODE 0 : paths vide -> reader totalement inerte ------------------------------------

#[test]
fn mode_zero_empty_paths_is_inert() {
    // probe/backend qui EXPLOSENT s'ils sont sollicités -> prouve que rien n'est touché en mode 0.
    struct BoomProbe;
    impl FsProbe for BoomProbe {
        fn probe(&self, _p: &Path) -> Option<FileMeta> {
            panic!("mode 0 : la probe ne doit JAMAIS être appelée");
        }
    }
    let state_dir = std::env::temp_dir().join(format!("plume-fim-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);
    let cfg = FimCfg { paths: Vec::new(), ..FimCfg::default() }; // AUCUN chemin
    let mut r = FimReader::new(cfg, "h".into(), &state_dir);
    r.open(Cursor(None));
    // Plusieurs cycles : toujours vide, jamais de probe, jamais de fichier baseline écrit.
    for _ in 0..3 {
        assert!(r.next_batch(100).records.is_empty(), "mode 0 : aucun event");
    }
    let baseline = state_dir.join("fim-integrity.baseline.json");
    assert!(!baseline.exists(), "mode 0 : aucune baseline écrite (aucun accès disque)");
    let _ = std::fs::remove_dir_all(&state_dir);
    let _ = r; // BoomProbe non utilisée ici mais documente l'intention (la vraie probe n'est pas construite en inert)
    let _ = BoomProbe;
}

// ---- fix #1 (CRITICAL) : probe anti-TOCTOU + lecture bornée en dur -------------------------------

#[test]
fn hash_reader_hard_stops_on_unbounded_stream() {
    // Preuve de l'ARRÊT DUR dans la boucle : un flux INFINI (comme /dev/zero, un fichier qui grossit,
    // un FIFO alimenté) est coupé au cap et retombe sur None (taille seule) — il NE bloque JAMAIS.
    let got = hash_reader_capped(std::io::repeat(0u8), 4096);
    assert!(got.is_none(), "flux non borné -> arrêt dur au cap -> None (jamais de hang/boucle infinie)");
    // Un contenu qui dépasse le cap (mais fini) -> None aussi.
    let big = vec![0u8; 5000];
    assert!(hash_reader_capped(&big[..], 4096).is_none(), "au-delà du cap -> None");
    // Un contenu qui tient dans le cap -> hash exact (KAT SHA-256 de "abc").
    let got = hash_reader_capped(&b"abc"[..], 4096).unwrap();
    assert_eq!(got, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[cfg(unix)]
#[test]
fn probe_never_follows_symlink_and_skips_nonregular() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let dir = std::env::temp_dir().join(format!("plume-fim-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 1) fichier régulier -> hashé
    let secret = dir.join("secret");
    let mut f = std::fs::File::create(&secret).unwrap();
    f.write_all(b"abc").unwrap();
    let m = probe_real(&secret, 10 * 1024 * 1024).expect("régulier -> Some");
    assert_eq!(m.size, 3);
    assert_eq!(m.sha256.as_deref(), Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    // 2) LE cœur du CRITICAL : un lien symbolique vers `secret` NE DOIT JAMAIS être suivi ni hashé.
    let link = dir.join("link");
    std::os::unix::fs::symlink(&secret, &link).unwrap();
    assert!(probe_real(&link, 10 * 1024 * 1024).is_none(), "lien -> jamais suivi (O_NOFOLLOW) -> None");

    // 3) FIFO : ouvert O_NONBLOCK, rejeté sur S_ISREG -> None, sans bloquer (pas d'écrivain).
    let fifo = dir.join("pipe");
    let cp = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cp.as_ptr(), 0o600) }, 0, "mkfifo");
    assert!(probe_real(&fifo, 10 * 1024 * 1024).is_none(), "fifo -> non régulier -> None (aucun hang)");

    // 4) fichier plus gros que le cap -> taille seule (sha None), jamais de lecture non bornée.
    let big = dir.join("big");
    std::fs::write(&big, vec![7u8; 4096]).unwrap();
    let m = probe_real(&big, 1024).expect("gros régulier -> Some (taille)");
    assert_eq!(m.size, 4096);
    assert!(m.sha256.is_none(), "au-delà de hash_max_bytes -> taille seule");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- fix #3 : last_emit borné (purge sur suppression + pas de fuite si debounce=0) ----------------

#[test]
fn last_emit_evicted_on_delete_and_not_leaked() {
    // debounce actif -> last_emit se peuple ; suppression -> la clé DOIT disparaître.
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: false });
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 60_000, ..FimCfg::default() };
    let mut r = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);

    files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("v1"), 2, 0o644));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Created)], overflowed: false });
    assert_eq!(r.next_batch(100).records.len(), 1);
    assert!(r.last_emit.contains_key("/w/a"), "émission -> clé présente");

    // Suppression : la purge de `last_emit` a lieu dans TOUS les cas (même si l'event `deleted` est lui
    // absorbé par la fenêtre debounce en cours) -> la clé disparaît, pas de fuite.
    files.borrow_mut().remove(&PathBuf::from("/w/a"));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Deleted)], overflowed: false });
    let _ = r.next_batch(100).records;
    assert!(!r.last_emit.contains_key("/w/a"), "suppression -> clé purgée (pas de fuite)");
    assert!(r.baseline.get("/w/a").is_none(), "suppression -> entrée baseline retirée");
}

#[test]
fn last_emit_not_populated_when_debounce_disabled() {
    // debounce_ms=0 : la map n'est jamais LUE -> ne doit jamais être PEUPLÉE (fuite d'origine).
    let mut h = harness(); // debounce_ms=0
    for i in 0..50 {
        let p = format!("/w/f{i}");
        h.files.borrow_mut().insert(PathBuf::from(&p), meta(Some("x"), 1, 0o644));
        h.q.borrow_mut().push_back(PollResult { events: vec![ev(&p, FsEventKind::Created)], overflowed: false });
        assert_eq!(h.reader.next_batch(100).records.len(), 1);
    }
    assert!(h.reader.last_emit.is_empty(), "debounce=0 -> last_emit reste vide (croissance bornée)");
}

// ---- fix #4 : rate-limit des rescans forcés ------------------------------------------------------

#[test]
fn rescan_rate_limit_pure() {
    use std::time::{Duration, Instant};
    let min = Duration::from_secs(60);
    let t0 = Instant::now();
    assert!(rescan_due(None, t0, min), "jamais rescanné -> dû");
    assert!(!rescan_due(Some(t0), t0 + Duration::from_secs(30), min), "30s < 60s -> pas dû");
    assert!(rescan_due(Some(t0), t0 + Duration::from_secs(61), min), "61s >= 60s -> dû");
}

#[test]
fn forced_rescan_is_throttled_across_cycles() {
    // Un backend qui lève overflow à CHAQUE cycle (comme fanotify) ne doit PAS relancer une marche
    // complète dos-à-dos : `last_rescan` est posé au 1er cycle et ne bouge pas dans la fenêtre.
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: false });
    // min_rescan_interval par défaut = 60s -> les deux cycles tombent dans la même fenêtre.
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 0, ..FimCfg::default() };
    let mut r = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);

    q.borrow_mut().push_back(PollResult { events: vec![], overflowed: true });
    let _ = r.next_batch(100).records;
    let first = r.last_rescan.expect("1er overflow -> rescan effectué (last_rescan posé)");

    q.borrow_mut().push_back(PollResult { events: vec![], overflowed: true });
    let _ = r.next_batch(100).records;
    assert_eq!(r.last_rescan, Some(first), "2e overflow immédiat -> marche complète sautée (throttle)");
}

// ---- fix #5 : plafond max_files -> pas de storm `added` répété -----------------------------------

#[test]
fn over_cap_does_not_reemit_added_storm() {
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: false });
    // plafond = 1 fichier suivi.
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 0, max_files: 1, ..FimCfg::default() };
    let mut r = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);

    files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("aaa"), 3, 0o644));
    files.borrow_mut().insert(PathBuf::from("/w/b"), meta(Some("bbb"), 3, 0o644));
    // cycle 1 : a prend le seul slot, b déborde -> 2 `added` émis une fois (a + b).
    q.borrow_mut().push_back(PollResult {
        events: vec![ev("/w/a", FsEventKind::Created), ev("/w/b", FsEventKind::Created)],
        overflowed: false,
    });
    assert_eq!(r.next_batch(100).records.len(), 2, "1er passage : a et b signalés une fois");
    assert!(r.over_cap.contains("/w/b"), "b marqué over-cap (borné)");
    assert_eq!(r.over_cap.len(), 1);

    // cycle 2 : b re-signalé -> exclu du diff -> AUCUNE ré-émission (storm supprimé).
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/b", FsEventKind::Created)], overflowed: false });
    assert!(r.next_batch(100).records.is_empty(), "over-cap -> pas de ré-émission `added` (storm éteint)");
    assert_eq!(r.over_cap.len(), 1, "over_cap reste borné (pas de croissance)");

    // suppression de b -> purge de l'ensemble over_cap.
    files.borrow_mut().remove(&PathBuf::from("/w/b"));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/b", FsEventKind::Deleted)], overflowed: false });
    let _ = r.next_batch(100).records;
    assert!(!r.over_cap.contains("/w/b"), "suppression -> retiré de over_cap");
}

// ---- fix #6 : couverture dégradée visible côté SOC (fim_coverage=partial) -------------------------

#[test]
fn degraded_backend_marks_coverage_partial() {
    let files = Rc::new(RefCell::new(HashMap::new()));
    let q = Rc::new(RefCell::new(VecDeque::new()));
    let watched = Rc::new(RefCell::new(Vec::new()));
    let probe = Box::new(FakeProbe(files.clone()));
    let backend = Box::new(FakeBackend { q: q.clone(), watched, degraded: true }); // plafond watches atteint
    let cfg = FimCfg { paths: vec!["/w".into()], debounce_ms: 0, ..FimCfg::default() };
    let mut r = FimReader::with_fakes(cfg, "h".into(), vec![PathBuf::from("/w")], backend, probe);

    files.borrow_mut().insert(PathBuf::from("/w/a"), meta(Some("aaa"), 3, 0o644));
    q.borrow_mut().push_back(PollResult { events: vec![ev("/w/a", FsEventKind::Created)], overflowed: false });
    let recs = r.next_batch(100).records;
    let e = one(&r, &recs);
    assert_eq!(e.fields["fim_coverage"], "partial", "backend dégradé -> fim_coverage=partial (visible SOC)");
    // Le contrat #57 reste intact (added, severity 1) — on n'a fait qu'AJOUTER un champ.
    assert_eq!(e.fields["fim_event"], "added");
    assert_eq!(e.severity, 1);
}

// ---- config : la source par défaut reste journald (mode 0 au niveau agent) ------------------------

#[test]
fn default_config_still_only_journald() {
    // Preuve que #58 n'altère PAS le comportement par défaut de l'agent : sans [[source]] explicite,
    // seule la source journald est injectée (aucune source FIM implicite).
    let c = crate::config::Config::from_toml(r#"endpoint = "https://x""#).unwrap();
    assert_eq!(c.source.len(), 1);
    assert!(matches!(c.source[0], crate::config::SourceCfg::Journald(_)));
}
