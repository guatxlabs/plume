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
mod lisibilite;
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

/// UN REGLAGE NON POSE EST LE CAS NOMINAL ; UN REGLAGE POSE ET NON COMPRIS EST UN ECHEC (`S36`).
///
/// LE DEFAUT FERME ICI. Ces lecteurs enchainaient `.ok().and_then(parse).unwrap_or(defaut)` : une
/// variable ABSENTE et une variable posee a `"10 Mio"` ou `"trente"` tombaient sur la MEME valeur,
/// celle du defaut. Un exploitant qui croit avoir releve un plafond ne l'a pas releve, et rien ne le
/// lui dit — la valeur qui sort est plausible, et c'est precisement ce qui la rend muette. Le cas
/// NOMINAL reste intact : ne rien poser garde le defaut, sans un mot.
///
/// `min` EST UN PARAMETRE, ET CE N'EST PAS UN DETAIL. L'ancien `env_usize` filtrait `n > 0` : poser
/// `PLUME_SYSLOG_SPOOL_MAX_FILES=0` retombait donc sur 20000 alors que la documentation du champ dit
/// « 0 = illimite ». Le reglage documente etait inatteignable, en silence. Les plafonds de spool ont
/// desormais `min = 0`, les autres `min = 1`.
fn env_nombre_u64(k: &str, d: u64, min: u64, fautes: &mut Vec<String>) -> u64 {
    match std::env::var(k) {
        // Variable non posee, ou posee vide : rien n'a ete demande, le defaut est le cas nominal.
        Err(_) => d,
        Ok(v) if v.trim().is_empty() => d,
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(n) if n >= min => n,
            // POSEE et non exploitable : on garde le defaut pour cet appel, mais la faute est
            // COLLECTEE — le demarrage refusera de continuer sous un reglage que personne n'a ecrit.
            _ => {
                fautes.push(format!("{k}={v:?} n'est pas un entier >= {min}"));
                d
            }
        },
    }
}

/// Meme regle, en `usize` (les plafonds de taille et de compte du recepteur).
fn env_nombre_usize(k: &str, d: usize, min: usize, fautes: &mut Vec<String>) -> usize {
    env_nombre_u64(k, d as u64, min as u64, fautes) as usize
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
/// LA LISTE D'ADRESSES AUTORISEES, LUE OU REFUSEE — jamais rabotee en silence (`S36`).
///
/// LE DEFAUT FERME ICI EST LE PLUS GRAVE DE CETTE SURFACE, ET IL N'EST PAS UN SILENCE DE DETECTION :
/// c'est une PORTE. L'ancienne forme jetait les entrees invalides UNE PAR UNE (`filter_map` + un
/// avertissement sur la sortie d'erreur), et rendait la liste des rescapees. Deux consequences, et
/// la seconde est fatale :
///   * une liste PARTIELLEMENT fautive devenait une liste PLUS PETITE que celle qui avait ete ecrite
///     — un appareil que l'exploitant croyait autorise etait refuse, sans que rien ne le relie a la
///     faute de frappe ;
///   * une liste ENTIEREMENT fautive (`10.0.0/8` : trois octets au lieu de quatre) devenait une liste
///     VIDE. Or une liste vide veut dire « aucun perimetre demande, on accepte tout » : le port :514,
///     qui n'est authentifie par rien, s'ouvrait au monde entier. L'exploitant, lui, venait justement
///     d'ecrire une regle pour l'en empecher.
///
/// LA REGLE APPLIQUEE, LA MEME QUE SUR LES AUTRES SURFACES DE CE LOT : un chemin par DEFAUT absent
/// reste le cas nominal — ne rien poser, c'est ne rien demander, et le demarrage le dit deja tres
/// fort ; mais une valeur POSEE par l'exploitant et non comprise est un REFUS. On ne devine pas ce
/// qu'il a voulu ecrire, et on ne se rabat sur AUCUNE des deux approximations : ni plus large (la
/// porte ouverte), ni plus etroite (la perte d'evenements attribuee a rien).
///
/// PURE ET PARAMETREE SUR SON TEXTE : la suite l'exerce sans variable d'environnement, donc sans
/// dependre de l'environnement de qui l'execute.
fn parse_allowlist(s: &str) -> lisibilite::Lecture<Vec<Cidr>> {
    let jetons: Vec<&str> = s.split([',', ' ', '\t', '\n']).map(str::trim).filter(|t| !t.is_empty()).collect();
    // AUCUN jeton : la liste n'a pas ete posee. C'est LU, et la valeur est un VRAI vide — sans ce
    // bras, un recepteur sans perimetre demande refuserait de demarrer, ce qui est le defaut
    // symetrique et tout aussi faux.
    if jetons.is_empty() {
        return lisibilite::Lecture::Lue(Vec::new());
    }
    let mut out = Vec::with_capacity(jetons.len());
    let mut fautives = Vec::new();
    for t in jetons {
        match parse_cidr(t) {
            Some(c) => out.push(c),
            None => fautives.push(format!("{t:?}")),
        }
    }
    if !fautives.is_empty() {
        return lisibilite::Lecture::Illisible {
            cause: lisibilite::CAUSE_FORME_INCONNUE,
            detail: format!(
                "{} entree(s) de PLUME_SYSLOG_ALLOW ne sont pas des CIDR/IP : {}. Une liste posee et \
                 non comprise n'est ni elargie ni retrecie : elle est REFUSEE (les ignorer rendrait \
                 une liste plus petite que celle qui a ete ecrite, et une liste entierement fautive \
                 rendrait une liste VIDE, c'est-a-dire un :514 ouvert a tout le monde)",
                fautives.len(),
                fautives.join(", ")
            ),
        };
    }
    lisibilite::Lecture::Lue(out)
}
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
/// L'IDENTITE DE CET HOTE, LUE OU AVOUEE — jamais inventee (`S36`). La lecture vit dans
/// `lisibilite::identite_hote_depuis`, parametree sur ses sources ; ce qui sort ici est un VERDICT.
fn identite_hote() -> lisibilite::Lecture<String> {
    lisibilite::identite_hote_depuis(
        std::path::Path::new("/proc/sys/kernel/hostname"),
        std::env::var("HOSTNAME").ok().as_deref(),
    )
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
    /// L'IP `ip` est-elle acceptee ?
    ///
    /// DEUX CAS, ET LE SECOND A CHANGE (`S36`). Allowlist VIDE : aucun perimetre n'a ete demande, on
    /// accepte — le demarrage le dit deja en toutes lettres, et c'est le cas nominal d'un recepteur
    /// borne par un pare-feu. Allowlist POSEE : l'appartenance doit etre ETABLIE, pas presumee.
    ///
    /// L'ANCIEN TROISIEME CAS ETAIT UN FAIL-OPEN. Un pair dont l'adresse n'a pas pu etre lue
    /// (`peer_addr()` en echec sur une connexion TCP qui se ferme aussitot) etait ACCEPTE, avec pour
    /// justification « ne devrait pas arriver ». Une adresse qu'on n'a pas su lire ne peut pas etre
    /// montree dans la liste : la traiter comme un membre, c'est ouvrir la porte sur un echec de
    /// lecture. Elle est desormais REFUSEE quand un perimetre est en vigueur, et le refus est COMPTE
    /// (`DROPPED_ALLOW`) — jamais silencieux.
    fn ip_allowed(&self, ip: Option<IpAddr>) -> bool {
        if self.allow.is_empty() {
            return true;
        }
        match ip {
            Some(ip) => self.allow.iter().any(|c| cidr_contains(c, &ip)),
            None => false,
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
    // LES REGLAGES POSES ET NON COMPRIS SONT COLLECTES ICI, PAS AVALES (`S36`). On les lit tous avant
    // de conclure : un exploitant qui a fait deux fautes de frappe doit les voir toutes les deux.
    let mut fautes: Vec<String> = Vec::new();
    // <= cap events/req du daemon (PLUME_INGEST_MAX_EVENTS, defaut 50000) ; defaut prudent.
    let batch_max = env_nombre_usize("PLUME_SYSLOG_BATCH_MAX", 500, 1, &mut fautes).min(50000);
    let flush_ms = env_nombre_u64("PLUME_SYSLOG_FLUSH_MS", 2000, 1, &mut fautes);
    let udp_addr = env_or("PLUME_SYSLOG_UDP", "0.0.0.0:514");
    let tcp_addr = env_or("PLUME_SYSLOG_TCP", "0.0.0.0:514");

    // Offset tz par defaut (device sans champ `tz`) : rend l'hypothese UTC explicite/configurable.
    fortigate::set_default_tz(std::env::var("PLUME_SYSLOG_TZ").ok().as_deref());

    // LA PORTE AVANT TOUT LE RESTE. Une liste POSEE et non comprise n'ouvre pas le :514 : elle
    // empeche le demarrage. C'est le seul resultat ou rien ne tourne sous une regle que personne n'a
    // ecrite — ni plus large que la regle voulue (la porte ouverte), ni plus etroite (des evenements
    // perdus sans que rien ne les relie a la faute de frappe).
    let demande_allow = env_or("PLUME_SYSLOG_ALLOW", "");
    let allow = match parse_allowlist(&demande_allow) {
        lisibilite::Lecture::Lue(a) => a,
        lisibilite::Lecture::Illisible { cause, detail } => {
            eprintln!(
                "collector-syslog: PLUME_SYSLOG_ALLOW NON EXPLOITABLE ({cause}) : {detail}\n\
                 collector-syslog: ARRET. Un perimetre a ete DEMANDE et n'a pas pu etre etabli ; \
                 demarrer sans lui ouvrirait :514 — qui n'est authentifie par rien — a toute source. \
                 Corrige la liste (CIDR ou IP separes par des virgules), ou retire la variable pour \
                 accepter deliberement toute source."
            );
            std::process::exit(2);
        }
    };

    // L'IDENTITE DE L'HOTE : lue, ou AVOUEE. `PLUME_HOST` est une identite DECLAREE par un
    // exploitant, elle n'a rien a prouver ; sinon on lit, et si la lecture echoue on publie le
    // VERDICT a la place du nom. `unknown` etait un nom PLAUSIBLE : toutes les machines en echec s'y
    // confondaient, et une machine reellement nommee ainsi recevait leurs evenements.
    let declare = std::env::var("PLUME_HOST").ok().filter(|v| !v.is_empty());
    let identite = match declare {
        Some(h) => lisibilite::Lecture::Lue(h),
        None => identite_hote(),
    };
    let host = identite.valeur().cloned().unwrap_or_else(|| lisibilite::HOTE_NON_LU.to_string());

    let cfg = Arc::new(Config {
        spool: env_or("PLUME_SPOOL", "/var/lib/plume/spool"),
        host,
        source: env_or("PLUME_SYSLOG_SOURCE", parser::default_source(&parser_name)),
        // cap dur d'une trame TCP + datagramme UDP (anti-DoS ; FortiGate en TCP peut depasser 1 Ko).
        max_frame: env_nombre_usize("PLUME_SYSLOG_MAX_FRAME", 65536, 1, &mut fautes),
        max_conns: env_nombre_usize("PLUME_SYSLOG_MAX_CONNS", 128, 1, &mut fautes),
        udp_recv_buf: env_nombre_usize("PLUME_SYSLOG_UDP_BUF", 16384, 1, &mut fautes),
        allow,
        // budget disque du spool (backpressure) : 0 = illimite -> `min` vaut 0 pour ces deux-la.
        spool_max_bytes: env_nombre_u64("PLUME_SYSLOG_SPOOL_MAX_BYTES", 512 * 1024 * 1024, 0, &mut fautes),
        spool_max_files: env_nombre_usize("PLUME_SYSLOG_SPOOL_MAX_FILES", 20000, 0, &mut fautes),
        // anti-slowloris : inactivite 60s / vie max 1h ; 16 connexions concurrentes max par IP.
        tcp_idle_secs: env_nombre_u64("PLUME_SYSLOG_TCP_IDLE", 60, 1, &mut fautes),
        tcp_maxlife_secs: env_nombre_u64("PLUME_SYSLOG_TCP_MAXLIFE", 3600, 1, &mut fautes),
        max_conns_per_ip: env_nombre_usize("PLUME_SYSLOG_MAX_CONNS_PER_IP", 16, 1, &mut fautes),
    });

    // MEME REGLE QUE POUR LA LISTE : un reglage POSE et non compris arrete le demarrage. C'est le
    // moment le moins couteux et le plus visible pour le dire ; continuer sous le defaut laisserait
    // l'exploitant croire que son plafond s'applique.
    if !fautes.is_empty() {
        eprintln!(
            "collector-syslog: {} reglage(s) POSE(s) et non exploitable(s) : {}\n\
             collector-syslog: ARRET. Ces valeurs ont ete ECRITES par un exploitant ; retomber en \
             silence sur le defaut ferait tourner le recepteur sous un reglage que personne n'a voulu.",
            fautes.len(),
            fautes.join(" ; ")
        );
        std::process::exit(2);
    }

    std::fs::create_dir_all(&cfg.spool).ok();

    // L'AVEU D'IDENTITE part AVANT la premiere trame : sans lui, des evenements arriveraient au
    // central sous un VERDICT sans que rien n'explique pourquoi. Il emprunte le canal
    // d'indisponibilite deja livre, sur lequel une regle ALERTE deja.
    if let lisibilite::Lecture::Illisible { cause, detail } = &identite {
        let ts = now();
        let ev = lisibilite::event_indisponibilite(
            lisibilite::HOTE_NON_LU,
            lisibilite::RAISON_CONFIG_ABSENTE,
            cause,
            &format!(
                "identite de l'hote non lue : {detail}. Les evenements de ce recepteur partent sous \
                 un VERDICT et non sous un nom ; pose PLUME_HOST=<nom>."
            ),
            ts,
        );
        eprintln!("collector-syslog: IDENTITE NON LUE ({cause}) : {detail}");
        if let Err(e) = spool::write_events(&cfg.spool, &cfg.host, ts, std::slice::from_ref(&ev)) {
            eprintln!("collector-syslog: aveu d'identite NON ecrit ({e}) — le trou reste invisible");
        }
    }

    let parser: Arc<dyn VendorParser> = Arc::from(parser::select(&parser_name));
    // tampon memoire borne : ~40x le lot (bien sous le cap cgroup 192Mi), surchargeable.
    // Le tampon memoire est lu APRES le controle des reglages ci-dessus ; une faute ici est donc
    // rapportee au meme endroit que les autres (le vecteur est encore vide a ce stade).
    let mut fautes_tampon: Vec<String> = Vec::new();
    let max_buf = env_nombre_usize(
        "PLUME_SYSLOG_QUEUE_MAX",
        batch_max.saturating_mul(40).max(20000),
        1,
        &mut fautes_tampon,
    );
    if !fautes_tampon.is_empty() {
        eprintln!(
            "collector-syslog: reglage POSE et non exploitable : {}\ncollector-syslog: ARRET.",
            fautes_tampon.join(" ; ")
        );
        std::process::exit(2);
    }
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
        let scoped = cfg_with_allow(lue("10.0.0.0/8, 192.168.1.5"));
        assert!(scoped.ip_allowed(Some(ip("10.9.9.9"))));
        assert!(scoped.ip_allowed(Some(ip("192.168.1.5"))));
        assert!(!scoped.ip_allowed(Some(ip("203.0.113.9")))); // hors liste -> refuse
    }

    /// Raccourci de suite : une liste que l'on SAIT bien formee. Toute autre issue est une faute du
    /// test lui-meme, pas du code exerce.
    fn lue(s: &str) -> Vec<Cidr> {
        match parse_allowlist(s) {
            lisibilite::Lecture::Lue(v) => v,
            lisibilite::Lecture::Illisible { cause, detail } => {
                panic!("liste supposee valide refusee ({cause}) : {detail}")
            }
        }
    }

    // =============================================================================================
    // `S36` — LA PORTE : UNE LISTE D'ADRESSES POSEE ET NON COMPRISE N'OUVRE PAS LE :514
    // =============================================================================================

    /// LA GARDE DERIVEE DE CETTE SURFACE, ET ELLE N'ENUMERE AUCUNE ENTREE FAUTIVE.
    ///
    /// LA PROPRIETE TENUE : pour TOUT texte de liste, si l'analyse rend une liste, alors cette liste
    /// a EXACTEMENT autant d'entrees que l'exploitant en a ecrit. Une seule phrase, et elle ferme les
    /// deux defauts d'un coup — le rabotage silencieux (liste plus petite que l'ecrit) et le cas
    /// fatal qui en decoule (liste entierement fautive -> liste VIDE -> « aucun perimetre demande »,
    /// c'est-a-dire un port d'ingestion non authentifie ouvert a tout le monde).
    ///
    /// LES ENTREES FAUTIVES SONT DERIVEES DES VALIDES PAR MUTATION, pas choisies a la main : on prend
    /// le corpus des formes que l'analyseur ACCEPTE et on les abime mecaniquement. Une forme
    /// d'adresse acceptee demain entre donc d'office dans le corpus, et ses mutations avec elle.
    #[test]
    fn une_liste_posee_ne_peut_jamais_produire_une_liste_vide() {
        // Le corpus des formes VALIDES — c'est le seul endroit ou quelque chose est enumere, et ce
        // sont les formes du contrat, pas des cas de defaut.
        let valides = ["10.0.0.0/8", "192.168.1.5", "2001:db8::/32", "::1", "172.16.0.0/12"];

        // ② LE TEMOIN NOMINAL, D'ABORD : chaque forme valide est LUE, et la liste rendue a
        //    exactement le nombre d'entrees ecrites. Sans lui, un analyseur qui refuserait TOUT
        //    passerait le temoin ① sans rien prouver — et il fermerait le recepteur en permanence.
        for v in valides {
            let r = parse_allowlist(v);
            assert_eq!(r.verdict(), lisibilite::VERDICT_LU, "forme valide refusee : {v}");
            assert_eq!(r.valeur().map(Vec::len), Some(1), "{v} : une entree ecrite, une entree lue");
        }
        let toutes = valides.join(", ");
        let r = parse_allowlist(&toutes);
        assert_eq!(
            r.valeur().map(Vec::len),
            Some(valides.len()),
            "une liste entierement valide rend AUTANT d'entrees qu'il en a ete ecrit"
        );

        // ① LES MUTATIONS : chaque abimage d'une forme valide doit etre REFUSE, seul comme melange
        //    a des formes valides. Aucune ne doit donner une liste — et surtout pas une liste vide.
        let abimages: [fn(&str) -> String; 4] = [
            // un octet en moins (`10.0.0/8` : la faute de frappe qui ouvrait la porte)
            |v| v.replacen(".0", "", 1),
            // un caractere qui n'appartient a aucune notation d'adresse
            |v| format!("{v}x"),
            // un prefixe hors bornes
            |v| format!("{}/999", v.split('/').next().unwrap_or(v)),
            // un separateur interne casse
            |v| v.replace('.', ",").replace(':', ";"),
        ];
        let mut mutations_exercees = 0usize;
        for v in valides {
            for abimer in abimages {
                let abime = abimer(v);
                // Une mutation qui rend par hasard une forme encore valide n'apprend rien : on ne la
                // compte pas, plutot que de la declarer couverte.
                if parse_cidr(&abime).is_some() {
                    continue;
                }
                mutations_exercees += 1;
                let seule = parse_allowlist(&abime);
                assert_eq!(
                    seule.verdict(),
                    lisibilite::VERDICT_ILLISIBLE,
                    "liste POSEE et fautive acceptee : {abime:?} — c'est le :514 ouvert au monde"
                );
                assert!(seule.valeur().is_none(), "{abime:?} : une liste refusee ne rend AUCUNE valeur");
                assert_eq!(seule.cause(), lisibilite::CAUSE_FORME_INCONNUE);

                // Melangee a des formes valides : la liste ne doit pas non plus etre RABOTEE.
                let melange = format!("10.0.0.0/8, {abime}, 192.168.1.5");
                let m = parse_allowlist(&melange);
                assert_eq!(
                    m.verdict(),
                    lisibilite::VERDICT_ILLISIBLE,
                    "liste partiellement fautive rabotee en silence : {melange:?}"
                );
            }
        }
        // PLANCHER DE NON-DEGENERESCENCE : sous ce seuil, ce sont les mutations qui ne mordent plus.
        assert!(
            mutations_exercees >= 12,
            "seulement {mutations_exercees} mutation(s) exercee(s) — l'instrument ne voit plus rien"
        );
    }

    /// ② LE CAS NOMINAL RESTE INTACT : ne RIEN poser n'est pas une faute, c'est l'absence de demande.
    /// Sans ce temoin, la correction transformerait chaque deploiement sans perimetre en refus de
    /// demarrage — le defaut symetrique, et tout aussi faux.
    #[test]
    fn une_liste_non_posee_reste_le_cas_nominal() {
        for vide in ["", "   ", ",", " , \t\n"] {
            let r = parse_allowlist(vide);
            assert_eq!(r.verdict(), lisibilite::VERDICT_LU, "{vide:?} : rien de pose, rien a refuser");
            assert_eq!(r.valeur().map(Vec::len), Some(0), "{vide:?} : un VRAI vide");
        }
        // Et une liste vide accepte bien tout le monde — c'est ce que veut dire « aucun perimetre ».
        assert!(cfg_with_allow(Vec::new()).ip_allowed(Some(ip("203.0.113.9"))));
    }

    /// LE TROISIEME TROU, INDEPENDANT DES DEUX AUTRES : un pair dont l'adresse n'a PAS pu etre lue.
    /// Il etait ACCEPTE (« ne devrait pas arriver -> ne pas bloquer a l'aveugle »), c'est-a-dire que
    /// l'echec d'une lecture ouvrait la porte. Une adresse inconnue ne peut pas etre montree dans la
    /// liste ; quand un perimetre est en vigueur, elle est refusee. Quand il n'y en a pas, il n'y a
    /// rien a etablir et elle passe, comme tout le monde.
    #[test]
    fn un_pair_dont_l_adresse_est_illisible_ne_franchit_pas_un_perimetre_pose() {
        let scoped = cfg_with_allow(lue("10.0.0.0/8"));
        assert!(!scoped.ip_allowed(None), "adresse non lue + perimetre pose -> REFUS");
        assert!(scoped.ip_allowed(Some(ip("10.1.2.3"))), "et le cas nominal passe toujours");
        let ouvert = cfg_with_allow(Vec::new());
        assert!(ouvert.ip_allowed(None), "sans perimetre, il n'y a rien a etablir");
    }

    // =============================================================================================
    // `S36` — LES REGLAGES POSES ET NON COMPRIS
    // =============================================================================================

    /// LA PAIRE. ① une valeur POSEE et non exploitable est COMPTEE comme faute (le demarrage
    /// s'arrete dessus) ; ② une valeur absente garde le defaut SANS faute, et une valeur valide est
    /// prise telle quelle. Le `min` parametre est exerce dans les deux sens : `0` est atteignable la
    /// ou il veut dire « illimite », et refuse la ou il n'a pas de sens.
    #[test]
    fn un_reglage_pose_et_non_compris_ne_retombe_pas_en_silence_sur_le_defaut() {
        let cle = "PLUME_SYSLOG_TEST_S36";
        let mut fautes = Vec::new();

        // ② absent -> defaut, AUCUNE faute.
        std::env::remove_var(cle);
        assert_eq!(env_nombre_u64(cle, 42, 1, &mut fautes), 42);
        assert!(fautes.is_empty(), "ne rien poser n'est pas une faute");

        // ② pose et valide -> la valeur ecrite.
        std::env::set_var(cle, "7");
        assert_eq!(env_nombre_u64(cle, 42, 1, &mut fautes), 7);
        assert!(fautes.is_empty());

        // ① pose et non exploitable -> faute COMPTEE (et le defaut rendu pour cet appel seulement).
        std::env::set_var(cle, "10 Mio");
        assert_eq!(env_nombre_u64(cle, 42, 1, &mut fautes), 42);
        assert_eq!(fautes.len(), 1, "une valeur posee et incomprise doit etre COMPTEE");
        assert!(fautes[0].contains(cle), "la faute nomme la variable : {:?}", fautes[0]);

        // ① bis — sous le minimum : c'est aussi une valeur qui ne fera pas ce qui est ecrit.
        fautes.clear();
        std::env::set_var(cle, "0");
        assert_eq!(env_nombre_u64(cle, 42, 1, &mut fautes), 42);
        assert_eq!(fautes.len(), 1);

        // ② bis — et `0` EST atteignable la ou il veut dire quelque chose (« illimite »).
        fautes.clear();
        assert_eq!(env_nombre_u64(cle, 42, 0, &mut fautes), 0, "0 = illimite doit etre atteignable");
        assert!(fautes.is_empty());
        std::env::remove_var(cle);
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
