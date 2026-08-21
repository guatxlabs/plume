//! Plume cross-OS endpoint agent (#16) — binaire AUTONOME installé SUR le poste.
//!
//! Lit les sources d'événements natives de l'OS (journald / Windows Event Log / macOS unified log),
//! tamponne sur disque (spool borné, at-least-once), et POST vers /api/ingest[/journal] du central
//! Plume. NE tourne PAS dans le pod SOC : il s'installe en service natif (systemd/launchd/SCM).
//!
//! CLI : `run | install | uninstall | status | test-ship`.

mod buffer;
mod config;
mod durable;
mod ship;
mod source;
mod service;

use anyhow::Result;
use buffer::{Backoff, CursorStore, Spool, SpoolEntry};
use clap::{Parser, Subcommand};
use config::Config;
use ship::{HttpTransport, Shipper};
use source::{build_reader, events_envelope, hostname, now_secs, Cursor, Event, SourceReader, Wire};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "plume-agent",
    version,
    about = "Agent d'endpoint Plume (#16) — shipper d'événements OS natifs vers /api/ingest"
)]
struct Cli {
    /// Chemin du fichier de configuration TOML (défaut par-OS).
    #[arg(long, short, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Boucle de collecte + expédition (mode service). `--once` fait un seul cycle (timer/cron).
    Run {
        #[arg(long)]
        once: bool,
    },
    /// Installe le service natif (unité systemd / plist launchd / SCM). Génère la config si `--endpoint`.
    Install {
        #[arg(long)]
        endpoint: Option<String>,
        /// Lit le jeton sur l'ENTRÉE STANDARD (`… install --endpoint URL --token-stdin <<< "$TOK"`).
        ///
        /// P5.5-a — IL N'Y A PAS DE `--token <valeur>`, ET C'EST LA CORRECTION. Un argument de processus
        /// est public : sous Linux tout utilisateur local le lit dans `/proc/<pid>/cmdline` (mesuré le
        /// 2026-08-02 : argv de 101 octets, secret verbatim) et journald le recopie dans `_CMDLINE` ;
        /// sous Windows il part dans l'événement 4688 et dans Sysmon ID 1 — **que cet agent expédie
        /// lui-même au central**. Le jeton arrivait donc en clair dans le SOC qu'il sert. Le fermer par
        /// une note de documentation ne le ferme pas : on retire l'argument.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Retire le service natif.
    Uninstall,
    /// État du service + profondeur du spool + curseurs persistés.
    Status,
    /// Envoie UN événement de santé synthétique au central (test de connectivité/auth/TLS).
    TestShip,
}

fn config_path(cli: &Cli) -> PathBuf {
    cli.config.clone().unwrap_or_else(config::default_config_path)
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("plume-agent: erreur: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let cpath = config_path(&cli);
    match &cli.cmd {
        Cmd::Run { once } => cmd_run(&cpath, *once),
        Cmd::Install { endpoint, token_stdin } => cmd_install(&cpath, endpoint.clone(), *token_stdin),
        Cmd::Uninstall => cmd_uninstall(),
        Cmd::Status => cmd_status(&cpath),
        Cmd::TestShip => cmd_test_ship(&cpath),
    }
}

/// Construit un Shipper prod (transport HTTP réel) à partir de la config.
fn shipper_for(cfg: &Config) -> Result<Shipper<HttpTransport>> {
    let transport = HttpTransport::new(&cfg.tls, Duration::from_secs(15))?;
    Ok(Shipper::new(
        transport,
        cfg.endpoint.clone(),
        cfg.auth_header(),
        cfg.host_header.clone(),
    ))
}

/// Un cycle : lit chaque source (batch borné), spool, draine. Renvoie les stats de drainage.
fn run_cycle(
    host: &str,
    batch_size: usize,
    readers: &mut [Box<dyn SourceReader>],
    spool: &Spool,
    shipper: &Shipper<HttpTransport>,
    cursors: &CursorStore,
    backoff: &mut Backoff,
) -> ship::DrainStats {
    for r in readers.iter_mut() {
        let recs = r.next_batch(batch_size);
        if recs.is_empty() {
            continue;
        }
        let entry = match r.wire() {
            Wire::Journal => {
                // journald brut -> ndjson concaténé -> /api/ingest/journal (le daemon parse).
                let ndjson = recs
                    .iter()
                    .map(|x| x.raw.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                SpoolEntry {
                    endpoint: Wire::Journal.endpoint().to_string(),
                    body: ndjson,
                    source_id: r.source_id().to_string(),
                    cursor: r.cursor().0,
                }
            }
            Wire::Events => {
                let events: Vec<Event> = recs.iter().filter_map(|x| r.to_event(x)).collect();
                if events.is_empty() {
                    continue;
                }
                let env = events_envelope(host, now_secs(), &events);
                SpoolEntry {
                    endpoint: Wire::Events.endpoint().to_string(),
                    body: env.to_string(),
                    source_id: r.source_id().to_string(),
                    cursor: r.cursor().0,
                }
            }
        };
        if let Err(e) = spool.push(&entry) {
            eprintln!("[run] écriture spool échouée ({}) : {e}", r.source_id());
        }
    }
    shipper.drain(spool, cursors, backoff)
}

fn cmd_run(cpath: &std::path::Path, once: bool) -> Result<()> {
    // Sur Windows, si le SCM a lancé ce processus, cède la main au dispatcher de service (qui rappelle
    // `run_loop` avec le drapeau d'arrêt du SCM). Lancé en console -> Ok(false) -> boucle normale.
    #[cfg(target_os = "windows")]
    {
        if service::windows_scm::dispatch_if_service(cpath)? {
            return Ok(());
        }
    }
    run_loop(cpath, once, Arc::new(AtomicBool::new(false)))
}

/// Boucle de collecte + expédition. Réutilisée par le mode console ET par le `ServiceMain` Windows
/// (SCM), qui lève `stop` sur SERVICE_CONTROL_STOP pour un arrêt propre.
pub(crate) fn run_loop(cpath: &std::path::Path, once: bool, stop: Arc<AtomicBool>) -> Result<()> {
    let cfg = Config::load(cpath)?;
    let host = cfg.host.clone().unwrap_or_else(hostname);
    let spool = Spool::open(&cfg.spool_dir, cfg.spool_cap)?;
    let cursors = CursorStore::open(&cfg.state_dir)?;
    let shipper = shipper_for(&cfg)?;

    // Construit les lecteurs et les ouvre sur leur dernier curseur ACKÉ (reprise).
    let mut readers: Vec<Box<dyn SourceReader>> =
        cfg.source.iter().map(|s| build_reader(s, &host, &cfg.state_dir, &cfg.tls)).collect();
    for r in &mut readers {
        let c = cursors.load(r.source_id());
        r.open(Cursor(c));
    }

    let flush = Duration::from_secs(cfg.flush_interval_secs.max(1));
    let mut backoff = Backoff::new(flush, Duration::from_secs(300));

    println!(
        "plume-agent: run host={host} endpoint={} sources={} batch={} flush={}s spool={} (cap {})",
        cfg.endpoint,
        readers.len(),
        cfg.batch_size,
        cfg.flush_interval_secs,
        cfg.spool_dir.display(),
        cfg.spool_cap,
    );

    loop {
        let st = run_cycle(
            &host,
            cfg.batch_size,
            &mut readers,
            &spool,
            &shipper,
            &cursors,
            &mut backoff,
        );
        if st.acked > 0 || st.poisoned > 0 || st.retried {
            eprintln!(
                "[run] cycle: acked={} poison={} retry={} spool_restant={}",
                st.acked,
                st.poisoned,
                st.retried,
                // `S33` — la profondeur n'est pas rendue à zéro faute de savoir : un spool illisible
                // s'affiche INCONNU, ce qui est le fait à voir, et non « plus rien en attente ».
                match spool.len() {
                    Ok(n) => n.to_string(),
                    Err(e) => format!("inconnu ({e})"),
                }
            );
        }
        if once || stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Recule si le central est down/surchargé, sinon cadence normale. On dort par tranches courtes
        // pour rester réactif à une demande d'arrêt (SCM/launchd) sans dépasser le délai voulu.
        let sleep = if st.retried { st.delay.unwrap_or(flush) } else { flush };
        if sleep_interruptible(sleep, &stop) {
            return Ok(());
        }
    }
}

/// Dort jusqu'à `total`, par tranches de 500 ms, en s'arrêtant tôt si `stop` est levé. Renvoie `true`
/// si l'arrêt a été demandé pendant l'attente.
fn sleep_interruptible(total: Duration, stop: &Arc<AtomicBool>) -> bool {
    let step = Duration::from_millis(500);
    let mut slept = Duration::ZERO;
    while slept < total {
        if stop.load(Ordering::SeqCst) {
            return true;
        }
        let chunk = step.min(total - slept);
        std::thread::sleep(chunk);
        slept += chunk;
    }
    stop.load(Ordering::SeqCst)
}

fn service_spec(cfg_path: &std::path::Path, cfg: &Config) -> Result<service::ServiceSpec> {
    Ok(service::ServiceSpec {
        exec_path: std::env::current_exe()?,
        config_path: cfg_path.to_path_buf(),
        spool_dir: cfg.spool_dir.clone(),
        state_dir: cfg.state_dir.clone(),
    })
}

fn cmd_install(cpath: &std::path::Path, endpoint: Option<String>, token_stdin: bool) -> Result<()> {
    // Génère un fichier de config minimal si absent et qu'un endpoint est fourni.
    if !cpath.exists() {
        let Some(ep) = endpoint else {
            anyhow::bail!(
                "config absente ({}) : fournis --endpoint <url> [--token-stdin] pour en générer une, \
                 ou crée le fichier à la main. Le jeton se lit sur l'ENTRÉE STANDARD, jamais en argument \
                 (un argument part dans /proc/<pid>/cmdline, dans `_CMDLINE` journald et, sous Windows, \
                 dans les événements 4688/Sysmon-1 que cet agent expédie lui-même au central).",
                cpath.display()
            );
        };
        if let Some(parent) = cpath.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut toml = format!("endpoint = \"{ep}\"\n");
        if token_stdin {
            use std::io::Read;
            let mut t = String::new();
            std::io::stdin().read_to_string(&mut t)?;
            let t = t.trim();
            if t.is_empty() {
                anyhow::bail!("--token-stdin : rien lu sur l'entrée standard — jeton NON écrit");
            }
            // Le TOML est écrit en 0600 juste en dessous ; on échappe `\` puis `"` pour ne pas produire
            // un fichier illisible si le jeton en contenait (ils n'en contiennent pas, mais on n'en dépend pas).
            toml.push_str(&format!("token = \"{}\"\n", t.replace('\\', "\\\\").replace('"', "\\\"")));
        }
        std::fs::write(cpath, toml)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(cpath, std::fs::Permissions::from_mode(0o600));
        }
        println!("config générée : {}", cpath.display());
    }
    let cfg = Config::load(cpath)?;
    let spec = service_spec(cpath, &cfg)?;
    conclure(service::current().install(&spec)?)
}

/// LA CONCLUSION D'UNE OPÉRATION DE SERVICE — une SEULE voie, pour les DEUX sens.
///
/// C'est ici que le mensonge sortait : `install` imprimait « service installé et démarré » depuis le
/// backend et rendait `Ok(())` ; `uninstall` imprimait « service retiré » sans avoir rien retiré.
/// Désormais aucun backend n'imprime : ils RENDENT ce qu'ils ont OBSERVÉ, et le code de sortie est
/// une FONCTION de ces observations. Trois issues, exhaustives : quelque chose a changé (0), il n'y
/// avait rien à faire (0, mais dit avec ces mots-là), ou un artefact résiste (NON NUL).
fn conclure(rapport: service::Outcome) -> Result<()> {
    println!("{}", rapport.render());
    let failed = rapport.failures();
    let (quoi, consequence) = match rapport.operation() {
        service::Operation::Pose => ("installation", "l'agent NE COLLECTE PAS"),
        service::Operation::Retrait => ("retrait", "l'agent tourne peut-être encore"),
    };
    if !failed.is_empty() {
        anyhow::bail!(
            "{quoi} INCOMPLET : {} artefact(s) pas dans l'état voulu ({}) — {consequence}",
            failed.len(),
            failed.join(", ")
        );
    }
    if !rapport.a_change() && rapport.operation() == service::Operation::Retrait {
        println!("plume-agent n'était pas installé ici : AUCUN retrait effectué.");
    }
    Ok(())
}

/// `uninstall` DIT CE QU'IL A FAIT, et échoue quand il n'a pas pu le faire (cf. `conclure`).
///
/// MESURÉ le 2026-08-02 sur la version précédente, sans rien d'installé : deux commandes systemctl
/// en échec affichées, 0 fichier supprimé, puis « service retiré : plume-agent.service » et un code
/// de retour **0**. Un opérateur qui retire l'agent d'un poste compromis lisait un succès qu'il
/// n'avait pas obtenu.
fn cmd_uninstall() -> Result<()> {
    conclure(service::current().uninstall()?)
}

fn cmd_status(cpath: &std::path::Path) -> Result<()> {
    println!("{}", service::current().status()?);
    // Profondeur du spool + curseurs (best-effort : ne pas échouer si la config manque).
    if let Ok(cfg) = Config::load(cpath) {
        if let Ok(spool) = Spool::open(&cfg.spool_dir, cfg.spool_cap) {
            match spool.len() {
                Ok(n) => println!("spool: {} entrée(s) en attente ({})", n, cfg.spool_dir.display()),
                Err(e) => println!(
                    "spool: profondeur INCONNUE — {} illisible ({e}). Ce n'est pas une file vide.",
                    cfg.spool_dir.display()
                ),
            }
        }
        if let Ok(cursors) = CursorStore::open(&cfg.state_dir) {
            for s in &cfg.source {
                let id = source_id_of(s);
                let cur = cursors.load(&id).unwrap_or_else(|| "(aucun)".into());
                println!("source {id}: curseur = {cur}");
            }
        }
    }
    Ok(())
}

fn source_id_of(s: &config::SourceCfg) -> String {
    match s {
        config::SourceCfg::Journald(j) => j.id.clone(),
        config::SourceCfg::Wineventlog(w) => w.id.clone(),
        config::SourceCfg::Oslog(m) => m.id.clone(),
        config::SourceCfg::Fim(f) => f.id.clone(),
        config::SourceCfg::File(fc) => fc.name.clone(),
        config::SourceCfg::Command(cc) => cc.name.clone(),
        config::SourceCfg::Http(hc) => hc.name.clone(),
    }
}

fn cmd_test_ship(cpath: &std::path::Path) -> Result<()> {
    let cfg = Config::load(cpath)?;
    let host = cfg.host.clone().unwrap_or_else(hostname);
    let ts = now_secs();
    let ev = Event {
        ts,
        host: host.clone(),
        source: "agent".to_string(),
        category: "health".to_string(),
        severity: 0,
        message: "plume-agent test-ship".to_string(),
        fields: serde_json::json!({ "selftest": 1 }),
        dedup: Some(format!("plume-agent-selftest-{ts}")),
    };
    let env = events_envelope(&host, ts, std::slice::from_ref(&ev));
    let shipper = shipper_for(&cfg)?;
    let url = shipper.url_for(Wire::Events.endpoint());
    println!("test-ship -> POST {url}");
    match shipper.post(Wire::Events.endpoint(), env.to_string().as_bytes()) {
        Ok(r) => {
            println!("réponse: HTTP {} {}", r.status, r.body);
            if matches!(ship::classify_status(r.status), ship::ShipOutcome::Acked) {
                println!("OK : le central a accepté l'événement (ACK).");
                Ok(())
            } else {
                anyhow::bail!("le central a répondu HTTP {} (attendu 202)", r.status)
            }
        }
        Err(e) => anyhow::bail!("échec d'envoi : {e}"),
    }
}
