//! Recepteur syslog Plume (host-natif, service LONG-RUNNING) — cf. design "Syslog receiver + FortiGate".
//!
//! Ecoute UDP+TCP :514, decadre (framing), dispatche vers un parser vendeur PLUGGABLE (defaut
//! FortiGate), agrege en lots et ecrit des enveloppes `kind=events` dans le spool. `ship.sh` (timer)
//! POST le spool vers `/api/ingest` (mTLS + token, EXACTEMENT comme conntrack.sh). Le data-plane du
//! daemon N'EST PAS TOUCHE : on ajoute UNE source, rien de plus.
//!
//! Privilege : bind :514 sans root via `AmbientCapabilities=CAP_NET_BIND_SERVICE` (User=soc). Le
//! sandbox du daemon reste byte-identique (cf. systemd/plume-collector-syslog.service).

mod fortigate;
mod framing;
mod parser;
mod spool;

use framing::{next_frame, parse_syslog, FrameOutcome};
use parser::VendorParser;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0).unwrap_or(d)
}
fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

// --- Allowlist source-IP (CIDR v4/v6) : borne l'injection d'events sur un :514 non authentifie. ---
/// Un prefixe CIDR (`10.0.0.0/8`, `2001:db8::/32`) ou une IP nue (masque plein).
#[derive(Clone)]
struct Cidr {
    net: IpAddr,
    bits: u32,
}
/// Parse `IP` ou `IP/bits`. IP nue -> masque plein (/32 ou /128). Retourne None si invalide.
fn parse_cidr(s: &str) -> Option<Cidr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (ip_s, want_bits) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b.trim().parse::<u32>().ok()?)),
        None => (s, None),
    };
    let net: IpAddr = ip_s.trim().parse().ok()?;
    let maxbits = if net.is_ipv4() { 32 } else { 128 };
    let bits = want_bits.unwrap_or(maxbits);
    if bits > maxbits {
        return None;
    }
    Some(Cidr { net, bits })
}
/// L'adresse `ip` tombe-t-elle dans le prefixe `c` ? (compare les `bits` de poids fort).
fn cidr_contains(c: &Cidr, ip: &IpAddr) -> bool {
    fn mask_eq(net: &[u8], addr: &[u8], bits: u32) -> bool {
        let full = (bits / 8) as usize;
        if net[..full] != addr[..full] {
            return false;
        }
        let rem = (bits % 8) as u8;
        if rem == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        (net[full] & mask) == (addr[full] & mask)
    }
    match (c.net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => mask_eq(&n.octets(), &a.octets(), c.bits),
        (IpAddr::V6(n), IpAddr::V6(a)) => mask_eq(&n.octets(), &a.octets(), c.bits),
        _ => false, // familles differentes -> pas de match
    }
}
/// Parse `PLUME_SYSLOG_ALLOW` (CIDR/IP separes par virgule/espace). Entrees invalides ignorees (warn).
fn parse_allowlist(s: &str) -> Vec<Cidr> {
    s.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| {
            let c = parse_cidr(t);
            if c.is_none() {
                eprintln!("collector-syslog: entree allowlist invalide ignoree: {t:?}");
            }
            c
        })
        .collect()
}
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Configuration figee, partagee (Arc) par tous les threads.
struct Config {
    spool: String,
    host: String,
    source: String,
    max_frame: usize,
    max_conns: usize,
    udp_recv_buf: usize,
    /// Allowlist source-IP (vide = accepte tout, avec un WARN au boot). cf. PLUME_SYSLOG_ALLOW.
    allow: Vec<Cidr>,
    /// Budget disque du spool : au-dela, on JETTE (shed) plutot que de gonfler le disque sans borne.
    spool_max_bytes: u64,
    spool_max_files: usize,
    /// Anti-slowloris TCP : timeout d'inactivite par lecture + duree de vie MAX d'une connexion.
    tcp_idle_secs: u64,
    tcp_maxlife_secs: u64,
    /// Connexions TCP concurrentes MAX par IP source (une IP ne peut pas monopoliser tous les slots).
    max_conns_per_ip: usize,
}
impl Config {
    /// L'IP `ip` est-elle acceptee ? (allowlist vide -> tout accepte). Peer inconnu (None) -> accepte.
    fn ip_allowed(&self, ip: Option<IpAddr>) -> bool {
        if self.allow.is_empty() {
            return true;
        }
        match ip {
            Some(ip) => self.allow.iter().any(|c| cidr_contains(c, &ip)),
            None => true, // pas d'info peer (ne devrait pas arriver) -> ne pas bloquer a l'aveugle
        }
    }
}

/// Compteurs de pertes (observabilite : une perte silencieuse est pire qu'une perte comptee).
static DROPPED_QUEUE: AtomicU64 = AtomicU64::new(0); // debordement du tampon memoire
static DROPPED_SPOOL: AtomicU64 = AtomicU64::new(0); // shed sur budget disque
static DROPPED_ALLOW: AtomicU64 = AtomicU64::new(0); // datagrammes/connexions hors allowlist
// S33 — cycles de flush pendant lesquels la taille du spool n'a PAS pu etre mesuree : la borne disque
// n'a alors ete appliquee ni dans un sens ni dans l'autre. Ce n'est pas une perte, c'est une GARDE
// ETEINTE, et c'est precisement ce qui se lisait « sous le budget ».
static BUDGET_AVEUGLE: AtomicU64 = AtomicU64::new(0);

/// Tampon d'agregation : les producteurs (UDP/TCP) poussent, le flusher draine par lots.
/// BORNE (`max_buf`) : sous flood, si le flusher ne suit pas, on JETTE le nouvel event (compte) plutot
/// que de laisser le tampon croitre jusqu'a l'OOM-kill du cgroup (192Mi). Perte bornee et OBSERVABLE.
struct Batcher {
    buf: Mutex<Vec<Value>>,
    cv: Condvar,
    batch_max: usize,
    max_buf: usize,
}
impl Batcher {
    fn push(&self, ev: Value) {
        let mut g = self.buf.lock().unwrap();
        if g.len() >= self.max_buf {
            drop(g);
            DROPPED_QUEUE.fetch_add(1, Ordering::Relaxed);
            return;
        }
        g.push(ev);
        if g.len() >= self.batch_max {
            self.cv.notify_one();
        }
    }
}

fn main() {
    let parser_name = env_or("PLUME_SYSLOG_PARSER", "fortigate");
    // <= cap events/req du daemon (PLUME_INGEST_MAX_EVENTS, defaut 50000) ; defaut prudent.
    let batch_max = env_usize("PLUME_SYSLOG_BATCH_MAX", 500).min(50000);
    let flush_ms = env_usize("PLUME_SYSLOG_FLUSH_MS", 2000) as u64;
    let udp_addr = env_or("PLUME_SYSLOG_UDP", "0.0.0.0:514");
    let tcp_addr = env_or("PLUME_SYSLOG_TCP", "0.0.0.0:514");

    // Offset tz par defaut (device sans champ `tz`) : rend l'hypothese UTC explicite/configurable.
    fortigate::set_default_tz(std::env::var("PLUME_SYSLOG_TZ").ok().as_deref());

    let allow = parse_allowlist(&env_or("PLUME_SYSLOG_ALLOW", ""));
    let cfg = Arc::new(Config {
        spool: env_or("PLUME_SPOOL", "/var/lib/plume/spool"),
        host: env_or("PLUME_HOST", &hostname()),
        source: env_or("PLUME_SYSLOG_SOURCE", parser::default_source(&parser_name)),
        // cap dur d'une trame TCP + datagramme UDP (anti-DoS ; FortiGate en TCP peut depasser 1 Ko).
        max_frame: env_usize("PLUME_SYSLOG_MAX_FRAME", 65536),
        max_conns: env_usize("PLUME_SYSLOG_MAX_CONNS", 128),
        udp_recv_buf: env_usize("PLUME_SYSLOG_UDP_BUF", 16384),
        allow,
        // budget disque du spool (backpressure) : 0 = illimite. Defaut 512 Mio / 20000 fichiers.
        spool_max_bytes: env_u64("PLUME_SYSLOG_SPOOL_MAX_BYTES", 512 * 1024 * 1024),
        spool_max_files: env_usize("PLUME_SYSLOG_SPOOL_MAX_FILES", 20000),
        // anti-slowloris : inactivite 60s / vie max 1h ; 16 connexions concurrentes max par IP.
        tcp_idle_secs: env_u64("PLUME_SYSLOG_TCP_IDLE", 60),
        tcp_maxlife_secs: env_u64("PLUME_SYSLOG_TCP_MAXLIFE", 3600),
        max_conns_per_ip: env_usize("PLUME_SYSLOG_MAX_CONNS_PER_IP", 16),
    });

    std::fs::create_dir_all(&cfg.spool).ok();

    let parser: Arc<dyn VendorParser> = Arc::from(parser::select(&parser_name));
    // tampon memoire borne : ~40x le lot (bien sous le cap cgroup 192Mi), surchargeable.
    let max_buf = env_usize("PLUME_SYSLOG_QUEUE_MAX", batch_max.saturating_mul(40).max(20000));
    let batcher = Arc::new(Batcher {
        buf: Mutex::new(Vec::new()),
        cv: Condvar::new(),
        batch_max,
        max_buf,
    });

    eprintln!(
        "collector-syslog: parser={} source={} udp={} tcp={} spool={} batch<={} flush={}ms allow={} queue_max={}",
        parser.name(),
        cfg.source,
        if udp_addr.is_empty() { "off" } else { &udp_addr },
        if tcp_addr.is_empty() { "off" } else { &tcp_addr },
        cfg.spool,
        batch_max,
        flush_ms,
        if cfg.allow.is_empty() { "ANY".to_string() } else { format!("{} cidr", cfg.allow.len()) },
        max_buf,
    );
    if cfg.allow.is_empty() {
        eprintln!(
            "collector-syslog: AVERTISSEMENT — :514 accepte TOUTE source (syslog non authentifie). \
             Scope l'acces au(x) CIDR de tes appareils : PLUME_SYSLOG_ALLOW=<cidr,...> ET/OU une regle \
             pare-feu (ufw/nft) / loadBalancerSourceRanges. cf. deploy/SYSLOG.md (durcissement)."
        );
    }

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();

    // --- flusher : draine le tampon (reveil sur cap OU toutes les flush_ms) -> enveloppes spool. ---
    {
        let batcher = Arc::clone(&batcher);
        let cfg = Arc::clone(&cfg);
        handles.push(thread::spawn(move || flusher_loop(batcher, cfg, flush_ms)));
    }

    // --- UDP : 1 datagramme = 1 message. ---
    if !udp_addr.is_empty() {
        match UdpSocket::bind(&udp_addr) {
            Ok(sock) => {
                let batcher = Arc::clone(&batcher);
                let cfg = Arc::clone(&cfg);
                let parser = Arc::clone(&parser);
                handles.push(thread::spawn(move || udp_loop(sock, cfg, parser, batcher)));
            }
            Err(e) => eprintln!("collector-syslog: bind UDP {udp_addr} echoue: {e}"),
        }
    }

    // --- TCP : 1 tache par connexion (bornee), cadrage RFC6587. ---
    if !tcp_addr.is_empty() {
        match TcpListener::bind(&tcp_addr) {
            Ok(listener) => {
                let batcher = Arc::clone(&batcher);
                let cfg = Arc::clone(&cfg);
                let parser = Arc::clone(&parser);
                handles.push(thread::spawn(move || tcp_accept_loop(listener, cfg, parser, batcher)));
            }
            Err(e) => eprintln!("collector-syslog: bind TCP {tcp_addr} echoue: {e}"),
        }
    }

    if handles.len() <= 1 {
        eprintln!("collector-syslog: aucun listener actif (UDP et TCP desactives ou bind KO) — arret.");
        std::process::exit(1);
    }
    for h in handles {
        let _ = h.join();
    }
}

/// Boucle du flusher : attend jusqu'a flush_ms (ou reveil early sur cap), draine, ecrit par chunks.
fn flusher_loop(batcher: Arc<Batcher>, cfg: Arc<Config>, flush_ms: u64) {
    let mut last_report = Instant::now();
    let mut last_reported: (u64, u64, u64, u64) = (0, 0, 0, 0);
    loop {
        let drained: Vec<Value> = {
            let mut guard = batcher.buf.lock().unwrap();
            if guard.is_empty() {
                let (g, _timeout) = batcher
                    .cv
                    .wait_timeout(guard, Duration::from_millis(flush_ms))
                    .unwrap();
                guard = g;
            }
            std::mem::take(&mut *guard)
        };
        report_drops(&mut last_report, &mut last_reported);
        if drained.is_empty() {
            continue;
        }
        // BACKPRESSURE DISQUE : UDP ne se regule pas ; si le spool depasse son budget (shipper a la
        // traine / /api/ingest lent ou down / flood), on JETTE ce lot plutot que de remplir le disque
        // sans borne (cf. incident disk-pressure). Perte bornee et COMPTEE (jamais silencieuse).
        match spool_budget(&cfg) {
            Budget::Depasse => {
                DROPPED_SPOOL.fetch_add(drained.len() as u64, Ordering::Relaxed);
                continue;
            }
            // La contre-pression est AVEUGLE, pas satisfaite. On ecrit quand meme (cf. le bandeau de
            // `spool_budget`), et on le COMPTE : sans ce compteur, l'extinction de la borne serait
            // indiscernable d'une file qui tient largement dans son budget.
            Budget::NonMesurable => {
                BUDGET_AVEUGLE.fetch_add(1, Ordering::Relaxed);
            }
            Budget::Sous => {}
        }
        // 1 enveloppe par chunk <= batch_max (borne aussi le cap events/req du daemon).
        for chunk in drained.chunks(batcher.batch_max) {
            if let Err(e) = spool::write_events(&cfg.spool, &cfg.host, now(), chunk) {
                eprintln!("collector-syslog: ecriture spool echouee: {e}");
            }
        }
    }
}

/// CE QUE PESE LE SPOOL — TROIS REPONSES, PAS DEUX (`S33`).
///
/// LE DEFAUT FERME ICI. L'ancienne forme rendait un booleen, et un `read_dir` en echec y valait
/// `false` : « sous le budget ». La contre-pression disque s'eteignait donc SILENCIEUSEMENT au
/// moment precis ou l'on ne savait plus mesurer le disque — c'est-a-dire, souvent, quand il va mal.
/// Deux replis de plus poussaient dans la meme direction A L'INTERIEUR d'une mesure reussie :
/// `rd.flatten()` sautait les entrees illisibles et `if let Ok(md)` sautait celles dont le `stat`
/// echouait. Un parcours interrompu n'est pas un parcours complet : le total qui en sort est PLUS
/// PETIT que la file reelle, donc plus rassurant, exactement comme un zero.
///
/// LA DIRECTION RESTE FAIL-OPEN, ET C'EST UN CHOIX ECRIT : un recepteur syslog qui jetterait tout
/// parce qu'il n'arrive pas a lire son propre repertoire transformerait une panne de MESURE en perte
/// d'evenements, dont l'UDP n'est rejouable par personne. Ce qui change est que ce cas a desormais un
/// NOM, un compteur, et une ligne dans le rapport periodique — au lieu d'etre indiscernable de
/// « tout va bien ».
enum Budget {
    /// Mesure prise, la file tient dans son budget.
    Sous,
    /// Mesure prise, le budget est franchi -> shed.
    Depasse,
    /// La file n'a PAS pu etre mesuree (repertoire illisible, parcours interrompu, `stat` refuse).
    /// Aucun budget n'est applique, et ce fait est compte.
    NonMesurable,
}

/// Un `read_dir` par cycle de flush (~toutes les flush_ms) : bon marche tant que le spool draine ; ne
/// mord que sous accumulation.
fn spool_budget(cfg: &Config) -> Budget {
    if cfg.spool_max_bytes == 0 && cfg.spool_max_files == 0 {
        return Budget::Sous; // aucune borne demandee : il n'y a rien a mesurer, ce n'est pas un echec
    }
    let rd = match std::fs::read_dir(&cfg.spool) {
        Ok(rd) => rd,
        Err(_) => return Budget::NonMesurable,
    };
    let (mut bytes, mut files) = (0u64, 0usize);
    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            // Un compte partiel serait plus petit que la file reelle : on ne le rend pas.
            Err(_) => return Budget::NonMesurable,
        };
        match ent.metadata() {
            Ok(md) if md.is_file() => {
                bytes = bytes.saturating_add(md.len());
                files += 1;
            }
            Ok(_) => {}
            Err(_) => return Budget::NonMesurable,
        }
        if cfg.spool_max_bytes != 0 && bytes > cfg.spool_max_bytes {
            return Budget::Depasse;
        }
        if cfg.spool_max_files != 0 && files > cfg.spool_max_files {
            return Budget::Depasse;
        }
    }
    Budget::Sous
}

/// Journalise (au plus toutes les 30 s, et seulement si ca a bouge) les compteurs de perte. Une perte
/// est ainsi OBSERVABLE (log de l'operateur) au lieu d'etre silencieuse.
fn report_drops(last: &mut Instant, last_reported: &mut (u64, u64, u64, u64)) {
    if last.elapsed() < Duration::from_secs(30) {
        return;
    }
    *last = Instant::now();
    let now = (
        DROPPED_QUEUE.load(Ordering::Relaxed),
        DROPPED_SPOOL.load(Ordering::Relaxed),
        DROPPED_ALLOW.load(Ordering::Relaxed),
        BUDGET_AVEUGLE.load(Ordering::Relaxed),
    );
    if now != *last_reported {
        eprintln!(
            "collector-syslog: pertes cumulees — queue={} spool={} allowlist={} (events jetes sous pression/filtre) ; \
             cycles ou la taille du spool n'a PAS pu etre mesuree (borne disque INAPPLIQUEE, ni shed ni garantie)={}",
            now.0, now.1, now.2, now.3
        );
        *last_reported = now;
    }
}

/// Un datagramme UDP = un message syslog. Truncation possible cote emetteur (documenter TCP pour la
/// fidelite complete des feeds FortiGate volumineux).
fn udp_loop(
    sock: UdpSocket,
    cfg: Arc<Config>,
    parser: Arc<dyn VendorParser>,
    batcher: Arc<Batcher>,
) {
    let mut buf = vec![0u8; cfg.udp_recv_buf];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) if n > 0 => {
                // allowlist source-IP AVANT tout traitement (drop compte, jamais silencieux).
                if !cfg.ip_allowed(Some(peer.ip())) {
                    DROPPED_ALLOW.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                dispatch(&buf[..n], &cfg, &parser, &batcher, Some(peer));
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("collector-syslog: recv UDP: {e}");
                thread::sleep(Duration::from_millis(200)); // pas de boucle chaude sur erreur transitoire
            }
        }
    }
}

/// Accept-loop TCP : borne le nombre de connexions concurrentes (anti-exhaustion de threads/fd).
fn tcp_accept_loop(
    listener: TcpListener,
    cfg: Arc<Config>,
    parser: Arc<dyn VendorParser>,
    batcher: Arc<Batcher>,
) {
    let live = Arc::new(AtomicUsize::new(0));
    // connexions concurrentes par IP source (anti-slowloris : une IP ne monopolise pas tous les slots).
    let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let peer = stream.peer_addr().ok();
        // allowlist source-IP AVANT d'engager un slot/thread.
        if !cfg.ip_allowed(peer.map(|p| p.ip())) {
            DROPPED_ALLOW.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        }
        // cap GLOBAL sans TOCTOU : on reserve d'abord (fetch_add), on rend si depassement (fetch_sub).
        if live.fetch_add(1, Ordering::AcqRel) >= cfg.max_conns {
            live.fetch_sub(1, Ordering::AcqRel);
            drop(stream); // sature -> on ferme proprement (l'emetteur reessaiera / bascule UDP).
            continue;
        }
        // cap PAR IP : une seule IP ne peut pas occuper plus de max_conns_per_ip slots.
        let ip = peer.map(|p| p.ip());
        if let Some(ip) = ip {
            let mut m = per_ip.lock().unwrap();
            let c = m.entry(ip).or_insert(0);
            if *c >= cfg.max_conns_per_ip {
                drop(m);
                live.fetch_sub(1, Ordering::AcqRel);
                DROPPED_ALLOW.fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }
            *c += 1;
        }
        let cfg = Arc::clone(&cfg);
        let parser = Arc::clone(&parser);
        let batcher = Arc::clone(&batcher);
        let live2 = Arc::clone(&live);
        let per_ip2 = Arc::clone(&per_ip);
        thread::spawn(move || {
            handle_tcp_conn(stream, &cfg, &parser, &batcher, peer);
            live2.fetch_sub(1, Ordering::AcqRel);
            if let Some(ip) = ip {
                let mut m = per_ip2.lock().unwrap();
                if let Some(c) = m.get_mut(&ip) {
                    *c -= 1;
                    if *c == 0 {
                        m.remove(&ip);
                    }
                }
            }
        });
    }
}

/// Lit un flux TCP, extrait les trames (octet-counting OU LF), dispatche chacune.
///
/// ANTI-SLOWLORIS : (a) timeout d'INACTIVITE court (`tcp_idle_secs`, def 60s) — une connexion qui
/// n'envoie rien est fermee ; (b) duree de vie MAX absolue (`tcp_maxlife_secs`, def 1h) — une connexion
/// qui goutte 1 octet juste avant chaque timeout (re-armant l'inactivite a l'infini) est neanmoins
/// coupee. Combine au cap par-IP de l'accept-loop, 128 connexions gouttantes ne peuvent plus geler
/// l'ingestion TCP.
fn handle_tcp_conn(
    mut stream: TcpStream,
    cfg: &Config,
    parser: &Arc<dyn VendorParser>,
    batcher: &Arc<Batcher>,
    peer: Option<SocketAddr>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(cfg.tcp_idle_secs.max(1))));
    let deadline = Instant::now() + Duration::from_secs(cfg.tcp_maxlife_secs.max(1));
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    loop {
        // extrait toutes les trames completes deja presentes
        loop {
            match next_frame(&buf, cfg.max_frame) {
                FrameOutcome::Frame { message, consumed }
                | FrameOutcome::OversizeFlush { message, consumed } => {
                    dispatch(&message, cfg, parser, batcher, peer);
                    buf.drain(..consumed);
                }
                FrameOutcome::Incomplete => break,
            }
        }
        if Instant::now() >= deadline {
            break; // vie max atteinte -> on ferme (anti low-and-slow qui re-arme le timeout d'inactivite)
        }
        match stream.read(&mut tmp) {
            Ok(0) => break, // connexion fermee
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break, // timeout / erreur -> on ferme
        }
    }
    // reste sans terminateur a la fermeture (ex. un message UDP-like envoye en TCP sans LF).
    if !buf.is_empty() {
        dispatch(&buf, cfg, parser, batcher, peer);
    }
}

/// Un message brut -> frame -> event normalise -> tampon. `peer` = adresse TRANSPORT reelle de
/// l'emetteur (non falsifiable en TCP ; en UDP = source du datagramme). On l'enregistre comme provenance
/// NON controlee par l'emetteur (`fields.receiver_peer`) et on en scelle le dedup (anti pre-seed d'une
/// cle par une autre source). `parse_syslog` ne panique jamais ; on isole neanmoins le dispatch sous
/// `catch_unwind` pour qu'un futur parser bogue ne tue jamais le thread udp_loop/TCP (fail-safe).
fn dispatch(
    bytes: &[u8],
    cfg: &Config,
    parser: &Arc<dyn VendorParser>,
    batcher: &Arc<Batcher>,
    peer: Option<SocketAddr>,
) {
    let raw = String::from_utf8_lossy(bytes);
    if raw.trim().is_empty() {
        return;
    }
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let frame = parse_syslog(&raw);
        parser.parse(&frame, &cfg.source, &cfg.host, now())
    }));
    let mut ev = match built {
        Ok(ev) => ev,
        Err(_) => {
            eprintln!("collector-syslog: parser panic isole (message ignore)");
            return;
        }
    };
    // Provenance transport + scellage du dedup sur le PEER REEL (finding : peer jete = spoof indetectable
    // + pas d'allowlist possible ; dedup forge = suppression). N'ajoute QUE des champs, ne touche pas le
    // data-plane. En k3s derriere un LoadBalancer SNAT, le peer peut etre l'IP du LB (provenance honnete).
    if let (Some(peer), Some(obj)) = (peer, ev.as_object_mut()) {
        let ip = peer.ip().to_string();
        if let Some(fields) = obj.get_mut("fields").and_then(|f| f.as_object_mut()) {
            fields.entry("receiver_peer").or_insert_with(|| json!(ip));
        }
        if let Some(Value::String(d)) = obj.get_mut("dedup") {
            d.push_str(&format!("-r{ip}"));
        }
    }
    batcher.push(ev);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4_prefix_and_bare_ip() {
        let c = parse_cidr("10.0.0.0/8").unwrap();
        assert!(cidr_contains(&c, &ip("10.5.6.7")));
        assert!(!cidr_contains(&c, &ip("11.0.0.1")));
        let bare = parse_cidr("192.168.1.10").unwrap();
        assert!(cidr_contains(&bare, &ip("192.168.1.10")));
        assert!(!cidr_contains(&bare, &ip("192.168.1.11")));
        // non-octet-aligne : /12 sur 172.16/12
        let c12 = parse_cidr("172.16.0.0/12").unwrap();
        assert!(cidr_contains(&c12, &ip("172.31.255.255")));
        assert!(!cidr_contains(&c12, &ip("172.32.0.1")));
    }

    #[test]
    fn cidr_v6_and_family_mismatch() {
        let c = parse_cidr("2001:db8::/32").unwrap();
        assert!(cidr_contains(&c, &ip("2001:db8:1234::1")));
        assert!(!cidr_contains(&c, &ip("2001:dead::1")));
        // familles differentes -> jamais un match (pas de faux positif cross-famille).
        let v4 = parse_cidr("10.0.0.0/8").unwrap();
        assert!(!cidr_contains(&v4, &ip("::1")));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!(parse_cidr("").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none()); // > 32 bits
        assert!(parse_cidr("::1/129").is_none()); // > 128 bits
    }

    /// `S33` — UNE CONTRE-PRESSION QUI NE SAIT PLUS MESURER N'EST PAS UNE CONTRE-PRESSION SATISFAITE.
    ///
    /// ① SENS « NON MESURABLE » : le repertoire du spool n'existe pas -> `NonMesurable`, jamais
    ///    `Sous`. L'ancienne forme rendait `false` — « sous le budget » — donc la borne disque
    ///    s'eteignait SILENCIEUSEMENT au moment precis ou l'on ne savait plus mesurer le disque.
    /// ② SENS « MESURE, SOUS LA BORNE » : un repertoire qui EXISTE et tient dans son budget rend
    ///    `Sous`. Sans ce temoin, une version qui rendrait TOUJOURS `NonMesurable` passerait ① sans
    ///    rien prouver — et elle eteindrait la borne en permanence, ce qui est le meme defaut.
    /// ③ Et la borne MORD quand elle est franchie : sans ce troisieme point, ① et ② seraient
    ///    satisfaits par une fonction qui ne dirait jamais `Depasse`.
    #[test]
    fn un_spool_illisible_ne_se_lit_pas_comme_un_spool_sous_le_budget() {
        let base = std::env::temp_dir().join(format!("plume-s33-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let mut c = cfg_with_allow(Vec::new());
        c.spool = base.join("spool").to_string_lossy().into_owned();
        c.spool_max_files = 2;

        // ① la source n'est pas la : on ne SAIT PAS, et on le dit.
        assert!(matches!(spool_budget(&c), Budget::NonMesurable),
            "un spool absent ne doit pas se lire « sous le budget »");

        // ② le cas nominal : mesure prise, la file tient.
        std::fs::create_dir_all(&c.spool).unwrap();
        assert!(matches!(spool_budget(&c), Budget::Sous), "un spool vide et lisible EST sous le budget");
        std::fs::write(std::path::Path::new(&c.spool).join("a.json"), b"x").unwrap();
        assert!(matches!(spool_budget(&c), Budget::Sous));

        // ③ et la borne mord vraiment.
        for n in 0..4 {
            std::fs::write(std::path::Path::new(&c.spool).join(format!("b{n}.json")), b"x").unwrap();
        }
        assert!(matches!(spool_budget(&c), Budget::Depasse), "au-dela du plafond de fichiers, on jette");

        // AUCUNE BORNE DEMANDEE n'est PAS un echec de mesure : il n'y a rien a mesurer.
        c.spool_max_files = 0;
        c.spool_max_bytes = 0;
        assert!(matches!(spool_budget(&c), Budget::Sous));
        let _ = std::fs::remove_dir_all(&base);
    }

    fn cfg_with_allow(allow: Vec<Cidr>) -> Config {
        Config {
            spool: String::new(),
            host: "h".into(),
            source: "fortigate".into(),
            max_frame: 65536,
            max_conns: 128,
            udp_recv_buf: 16384,
            allow,
            spool_max_bytes: 0,
            spool_max_files: 0,
            tcp_idle_secs: 60,
            tcp_maxlife_secs: 3600,
            max_conns_per_ip: 16,
        }
    }

    #[test]
    fn allowlist_empty_accepts_all_but_set_filters() {
        let open = cfg_with_allow(vec![]);
        assert!(open.ip_allowed(Some(ip("203.0.113.9")))); // vide -> tout accepte
        let scoped = cfg_with_allow(parse_allowlist("10.0.0.0/8, 192.168.1.5"));
        assert!(scoped.ip_allowed(Some(ip("10.9.9.9"))));
        assert!(scoped.ip_allowed(Some(ip("192.168.1.5"))));
        assert!(!scoped.ip_allowed(Some(ip("203.0.113.9")))); // hors liste -> refuse
    }

    #[test]
    fn batcher_caps_and_counts_drops() {
        let before = DROPPED_QUEUE.load(Ordering::Relaxed);
        let b = Batcher { buf: Mutex::new(Vec::new()), cv: Condvar::new(), batch_max: 100, max_buf: 3 };
        for _ in 0..10 {
            b.push(json!({"x":1}));
        }
        assert_eq!(b.buf.lock().unwrap().len(), 3, "le tampon est borne a max_buf");
        assert_eq!(DROPPED_QUEUE.load(Ordering::Relaxed) - before, 7, "les 7 en trop sont comptes");
    }
}
