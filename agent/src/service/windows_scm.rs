//! Service Windows (SCM) — IMPLÉMENTÉ (cfg(windows) pour la partie native).
//!
//! Deux volets, via la crate `windows-service` :
//!  1. Enregistrement SCM (install/uninstall/status) : `ServiceManager::create_service` (auto-start,
//!     SERVICE_WIN32_OWN_PROCESS) + `service.start()` ; `stop()`+`delete()` au retrait ;
//!     `query_status()` pour l'état.
//!  2. Boucle service : quand le SCM lance le binaire, `dispatch_if_service` cède la main au
//!     dispatcher (`service_dispatcher::start`) ; le `ServiceMain` généré enregistre un handler de
//!     contrôle (STOP -> lève le drapeau d'arrêt), signale RUNNING, exécute `crate::run_loop`, puis
//!     signale STOPPED. Lancé depuis une console (pas par le SCM), `service_dispatcher::start` renvoie
//!     ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063) -> on bascule sur la boucle normale.
//!
//! Le fichier compile sur toutes les cibles : `bin_path`/`args` sont purs et testés ; toute la FFI
//! `windows-service` est `cfg(target_os = "windows")` (hôte Windows requis pour la validation runtime).
//! Cross-compile depuis Linux : `cargo build --target x86_64-pc-windows-gnu` (ou `cargo-xwin` MSVC).
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use super::{Outcome, ServiceManager, ServiceSpec};

pub const SERVICE_NAME: &str = "plume-agent";
pub const DISPLAY_NAME: &str = "Plume endpoint agent (#16)";

pub struct WindowsScm {
    name: String,
}

impl WindowsScm {
    pub fn new() -> Self {
        Self { name: SERVICE_NAME.to_string() }
    }

    /// Arguments de lancement (après l'exe) que le SCM enregistrera : `run --config <cfg>`. Pur/testable.
    pub fn launch_args(spec: &ServiceSpec) -> Vec<String> {
        vec![
            "run".to_string(),
            "--config".to_string(),
            spec.config_path.display().to_string(),
        ]
    }

    /// binPath complet (exe entre guillemets + args) — représentation `sc create binPath=`. Pur/testable.
    pub fn bin_path(spec: &ServiceSpec) -> String {
        format!(
            "\"{}\" run --config \"{}\"",
            spec.exec_path.display(),
            spec.config_path.display()
        )
    }
}

impl ServiceManager for WindowsScm {
    fn service_name(&self) -> &str {
        &self.name
    }

    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<Outcome> {
        #[cfg(target_os = "windows")]
        {
            imp::install(spec)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = spec;
            anyhow::bail!("l'enregistrement SCM n'existe que sur Windows")
        }
    }

    fn uninstall(&self) -> anyhow::Result<Outcome> {
        #[cfg(target_os = "windows")]
        {
            imp::uninstall()
        }
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("l'enregistrement SCM n'existe que sur Windows")
        }
    }

    fn status(&self) -> anyhow::Result<String> {
        #[cfg(target_os = "windows")]
        {
            imp::status()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(format!("{SERVICE_NAME}: (statut SCM disponible sur Windows uniquement)"))
        }
    }
}

/// Si le processus a été lancé par le SCM, cède la main au dispatcher de service et renvoie `Ok(true)`
/// une fois le service arrêté. Lancé depuis une console -> `Ok(false)` (l'appelant fait la boucle normale).
/// No-op (`Ok(false)`) hors Windows pour un appel inconditionnel depuis `main`.
pub fn dispatch_if_service(config_path: &std::path::Path) -> anyhow::Result<bool> {
    #[cfg(target_os = "windows")]
    {
        imp::dispatch_if_service(config_path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = config_path;
        Ok(false)
    }
}

// --- implémentation native Windows ---------------------------------------------------------------
#[cfg(target_os = "windows")]
mod imp {
    use super::{DISPLAY_NAME, SERVICE_NAME};
    use crate::service::{Outcome, ServiceSpec};
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// Chemin de config transmis à `service_main` (le SCM n'achemine pas nos arguments de façon fiable).
    static CONFIG_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    /// POSE OBSERVÉE (cf. `Outcome`), jumeau du retrait ci-dessous. DEUX pièges Windows sont dits
    /// plutôt que devinés :
    ///  1. `create_service` ÉCHOUE si le service existe déjà (ERROR_SERVICE_EXISTS) — on ouvre alors
    ///     l'existant plutôt que d'abandonner : une ré-installation est légitime et idempotente.
    ///  2. `start()` rend Ok dès que le SCM a lancé le processus : le service peut MOURIR juste après
    ///     (DLL manquante, config illisible). On RE-SONDE donc `query_status()` jusqu'à un état
    ///     stable, et on ne dit « posé » que si l'état observé est RUNNING.
    /// NON VÉRIFIÉ À L'EXÉCUTION (aucune VM Windows) : ce qui est prouvé ici, c'est que ça compile
    /// et lie pour `x86_64-pc-windows-msvc`, et sur `windows-latest` (agent-ci).
    pub fn install(spec: &ServiceSpec) -> anyhow::Result<Outcome> {
        let mut r = Outcome::pose();
        // Répertoires spool/state — OBSERVÉS comme le reste (ils étaient créés avec un `?` hors du
        // rapport : le backend rendait donc un `Outcome` qui ne disait rien de deux artefacts qu'il
        // venait bel et bien de poser).
        for d in [&spec.spool_dir, &spec.state_dir] {
            let existait = d.is_dir();
            let res = std::fs::create_dir_all(d);
            r.observe(format!("répertoire {}", d.display()), existait, || match res {
                Ok(()) if d.is_dir() => Ok(()),
                Ok(()) => Err("créé sans erreur mais absent à la re-sonde".into()),
                Err(e) => Err(format!("{e} (élévation requise ?)")),
            });
        }
        if !r.failures().is_empty() {
            return Ok(r);
        }
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: spec.exec_path.clone(),
            launch_arguments: super::WindowsScm::launch_args(spec)
                .into_iter()
                .map(OsString::from)
                .collect(),
            dependencies: vec![],
            account_name: None, // LocalSystem (lecture du canal Security)
            account_password: None,
        };
        let acces = ServiceAccess::START | ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG;
        // Existait-il DÉJÀ, et tournait-il ? (les deux observations « avant », prises avant d'agir)
        let existait = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok();
        let tournait = etat_courant(&manager) == Some(ServiceState::Running);

        let cree = match manager.create_service(&info, acces) {
            Ok(s) => Ok(s),
            // Déjà enregistré -> on reprend la main sur l'existant (ré-installation idempotente) ET
            // on RÉÉCRIT sa configuration : sans `change_config`, une ré-installation qui change le
            // chemin du binaire ou du `--config` laisserait le SCM lancer l'ANCIENNE ligne de
            // commande pendant qu'on annonce « posé » (jumeau Windows du redémarrage systemd
            // ci-contre). NON VÉRIFIÉ À L'EXÉCUTION : compilé et lié pour x86_64-pc-windows-msvc.
            Err(e) => manager
                .open_service(SERVICE_NAME, acces)
                .map_err(|e2| {
                    anyhow::anyhow!(
                        "CreateService : {e} ; puis OpenService : {e2} (élévation requise ?)"
                    )
                })
                .and_then(|s| {
                    s.change_config(&info)
                        .map(|()| s)
                        .map_err(|e3| anyhow::anyhow!("ChangeServiceConfig : {e3}"))
                }),
        };
        let service = match cree {
            Ok(s) => s,
            Err(e) => {
                r.observe(format!("service SCM {SERVICE_NAME}"), existait, || Err(format!("{e}")));
                return Ok(r);
            }
        };
        r.observe(format!("service SCM {SERVICE_NAME} (enregistré, démarrage auto)"), existait, || {
            if manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok() {
                Ok(())
            } else {
                Err("absent du SCM juste après CreateService".into())
            }
        });
        let _ = service.set_description(
            "Lit les journaux Windows Event Log natifs et les expédie vers le endpoint d'ingest Plume.",
        );
        // Le service EXISTAIT : sa configuration vient d'être réécrite, mais le processus VIVANT est
        // encore celui de l'ANCIENNE ligne de commande. On l'arrête pour que le démarrage reprenne la
        // nouvelle (jumeau du `restart` systemd). `stop()` sur un service déjà arrêté n'est pas une
        // erreur ici : c'est la RE-SONDE qui tranche, jamais le code de retour.
        if existait {
            let _ = service.stop();
            let limite = std::time::Instant::now() + Duration::from_secs(10);
            while etat_courant(&manager) != Some(ServiceState::Stopped)
                && std::time::Instant::now() < limite
            {
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        let demarre = service.start::<OsString>(&[]);
        // PAS DE « déjà en place » ICI, ET C'EST DÉLIBÉRÉ. Contrairement à systemd, on ne sait pas
        // à bon compte si la configuration SCM enregistrée diffère de celle qu'on veut : on la
        // RÉÉCRIT donc systématiquement (`change_config`) puis on redémarre. Il y a donc toujours eu
        // un changement, et prétendre « déjà conforme » serait une affirmation non observée.
        // `tournait` reste sondé : il sert au diagnostic, pas au verdict.
        let _ = tournait;
        let deja_conforme = false;
        r.observe(format!("service SCM {SERVICE_NAME} (en cours d'exécution)"), deja_conforme, || {
            // RE-SONDE D'ABORD : `start()` rend une erreur si le service tourne DÉJÀ
            // (ERROR_SERVICE_ALREADY_RUNNING) — ce n'est pas un échec, c'est l'état voulu. Le code de
            // retour ne sert donc qu'à EXPLIQUER un état qu'on n'a pas obtenu.
            let limite = std::time::Instant::now() + Duration::from_secs(10);
            let contexte = |quoi: &str| match &demarre {
                Err(e) => format!("{quoi} — StartService : {e} (1053 = le processus n'a pas \
                                   répondu : binaire qui ne démarre pas ? config illisible ?)"),
                Ok(()) => quoi.to_string(),
            };
            loop {
                match etat_courant(&manager) {
                    Some(ServiceState::Running) => return Ok(()),
                    Some(ServiceState::Stopped) => {
                        return Err(contexte(
                            "ARRÊTÉ juste après le démarrage (Observateur d'événements : journal \
                             Système, source « Service Control Manager »)",
                        ))
                    }
                    _ if std::time::Instant::now() >= limite => {
                        return Err(contexte("pas RUNNING au bout de 10 s (état instable)"))
                    }
                    _ => std::thread::sleep(Duration::from_millis(250)),
                }
            }
        });
        Ok(r)
    }

    /// État SCM courant, ou `None` si le service ne s'ouvre pas / ne répond pas.
    fn etat_courant(manager: &ServiceManager) -> Option<ServiceState> {
        manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .ok()
            .and_then(|s| s.query_status().ok())
            .map(|st| st.current_state)
    }

    /// RETRAIT OBSERVÉ (cf. `Outcome`). DEUX pièges Windows sont dits ici plutôt que devinés :
    ///  1. `open_service` ÉCHOUE si le service n'existe pas — c'est le seul backend qui, avant ce
    ///     correctif, était déjà BRUYANT sur « rien à retirer » (erreur, code de retour non nul).
    ///     Il devient maintenant HONNÊTE : « absent », rendu 0, sans prétendre avoir retiré.
    ///  2. `DeleteService` marque le service pour suppression ; s'il tourne encore (arrêt lent, ou
    ///     handle ouvert par un autre outil), il ne DISPARAÎT qu'ensuite. On re-sonde donc l'état
    ///     après `stop()`+`delete()` et on ne dit `Removed` que si le service ne s'ouvre plus.
    /// NON VÉRIFIÉ À L'EXÉCUTION (aucune VM Windows allumée) : ce qui est prouvé, c'est que ça
    /// compile et lie sur `windows-latest` (agent-ci).
    pub fn uninstall() -> anyhow::Result<Outcome> {
        let mut r = Outcome::retrait();
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let opened = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        );
        let service = match opened {
            Ok(s) => s,
            Err(_) => {
                r.observe(format!("service SCM {SERVICE_NAME}"), true, || Ok(()));
                return Ok(r);
            }
        };
        let _ = service.stop(); // best-effort (peut déjà être arrêté)
        let supprime = service.delete();
        drop(service);
        // RE-SONDE : le service ne doit plus s'ouvrir. S'il s'ouvre encore, la suppression est
        // seulement EN ATTENTE — le dire, plutôt que de l'appeler « retiré ».
        r.observe(format!("service SCM {SERVICE_NAME}"), false, || {
            if let Err(e) = supprime {
                return Err(format!("DeleteService : {e} (élévation requise ?)"));
            }
            if manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok() {
                Err("suppression EN ATTENTE : le service est encore enregistré (processus vivant ou \
                     handle ouvert) — il partira à l'arrêt du service ou au redémarrage"
                    .into())
            } else {
                Ok(())
            }
        });
        Ok(r)
    }

    pub fn status() -> anyhow::Result<String> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
        let st = service.query_status()?;
        Ok(format!("{SERVICE_NAME}: {:?}", st.current_state))
    }

    pub fn dispatch_if_service(config_path: &Path) -> anyhow::Result<bool> {
        let _ = CONFIG_PATH.set(config_path.to_path_buf());
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(true),
            // 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT -> lancé hors SCM (console) : boucle normale.
            Err(windows_service::Error::Winapi(ref e)) if e.raw_os_error() == Some(1063) => {
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!("dispatcher de service : {e}")),
        }
    }

    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            eprintln!("plume-agent(service): {e:#}");
        }
    }

    fn run_service() -> anyhow::Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_handler = stop.clone();
        let event_handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    stop_for_handler.store(true, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        let running = ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running.clone())?;

        let cpath = CONFIG_PATH
            .get()
            .cloned()
            .unwrap_or_else(crate::config::default_config_path);
        // Boucle de collecte partagée avec le mode console ; s'arrête quand `stop` est levé.
        let result = crate::run_loop(&cpath, false, stop.clone());

        let exit_code = if result.is_err() {
            ServiceExitCode::ServiceSpecific(1)
        } else {
            ServiceExitCode::Win32(0)
        };
        status_handle.set_service_status(ServiceStatus {
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            ..running
        })?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            exec_path: PathBuf::from(r"C:\Program Files\plume-agent\plume-agent.exe"),
            config_path: PathBuf::from(r"C:\ProgramData\plume-agent\agent.toml"),
            spool_dir: PathBuf::from(r"C:\ProgramData\plume-agent\spool"),
            state_dir: PathBuf::from(r"C:\ProgramData\plume-agent\state"),
        }
    }

    #[test]
    fn launch_args_are_run_config() {
        let a = WindowsScm::launch_args(&spec());
        assert_eq!(a[0], "run");
        assert_eq!(a[1], "--config");
        assert!(a[2].contains("agent.toml"));
    }

    #[test]
    fn bin_path_quotes_exe_and_config() {
        let b = WindowsScm::bin_path(&spec());
        assert!(b.starts_with("\"C:\\Program Files\\plume-agent\\plume-agent.exe\""));
        assert!(b.contains("run --config"));
        assert!(b.contains("\"C:\\ProgramData\\plume-agent\\agent.toml\""));
    }

    #[test]
    fn service_name_is_stable() {
        assert_eq!(WindowsScm::new().service_name(), "plume-agent");
    }

    /// LE BINAIRE WINDOWS DOIT POUVOIR DÉMARRER SUR UN WINDOWS NEUF.
    ///
    /// Sans CRT statique, l'exe MSVC importe `VCRUNTIME140.dll`, absente d'un Windows fraîchement
    /// installé -> 0xC0000135 avant la première instruction de notre code (donc AUCUN diagnostic
    /// possible depuis le programme : la seule correction est de supprimer la dépendance). MESURÉ le
    /// 2026-08-02 en lisant la table d'imports PE des deux binaires produits ici : sans le drapeau,
    /// 3 259 392 o AVEC `VCRUNTIME140.dll` ; avec, 3 359 744 o SANS elle.
    ///
    /// Ce test lit `.cargo/config.toml` — le SEUL endroit où le drapeau est posé — et tourne sur les
    /// TROIS OS de `agent-ci`. Il ne peut pas remplacer une exécution sur Windows ; il empêche la
    /// RÉGRESSION SILENCIEUSE (retirer la ligne ne casse aucun build : ça ne casse que les machines
    /// des clients, et seulement celles qui n'ont pas le redistribuable).
    #[test]
    fn crt_statique_est_impose_pour_windows_msvc() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cargo/config.toml");
        let txt = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{} illisible : {e}", p.display()));
        let bloc = txt
            .split("[target.")
            .find(|s| s.starts_with("x86_64-pc-windows-msvc]"))
            .unwrap_or_else(|| panic!("aucun bloc [target.x86_64-pc-windows-msvc] dans {}", p.display()));
        assert!(
            bloc.contains("target-feature=+crt-static"),
            "le bloc MSVC n'impose plus la CRT statique -> l'exe importera VCRUNTIME140.dll et ne \
             démarrera pas sur un Windows sans redistribuable :\n{bloc}"
        );
    }

    #[test]
    fn dispatch_is_noop_off_windows() {
        // Hors Windows, l'appel inconditionnel depuis main doit renvoyer false (fait la boucle normale).
        #[cfg(not(target_os = "windows"))]
        assert_eq!(dispatch_if_service(std::path::Path::new("/x")).unwrap(), false);
    }
}
