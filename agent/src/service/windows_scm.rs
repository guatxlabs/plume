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

use super::{Removal, ServiceManager, ServiceSpec};

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

    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<()> {
        // Répertoires spool/state.
        for d in [&spec.spool_dir, &spec.state_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| anyhow::anyhow!("création {}: {e}", d.display()))?;
        }
        #[cfg(target_os = "windows")]
        {
            imp::install(spec)
        }
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("l'enregistrement SCM n'existe que sur Windows")
        }
    }

    fn uninstall(&self) -> anyhow::Result<Removal> {
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
    use crate::service::{Disposition, Removal, ServiceSpec};
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

    pub fn install(spec: &ServiceSpec) -> anyhow::Result<()> {
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
        let service = manager.create_service(
            &info,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG,
        )?;
        let _ = service.set_description(
            "Lit les journaux Windows Event Log natifs et les expédie vers le endpoint d'ingest Plume.",
        );
        service.start::<OsString>(&[])?;
        println!("service installé et démarré : {SERVICE_NAME}");
        Ok(())
    }

    /// RETRAIT OBSERVÉ (cf. `Removal`). DEUX pièges Windows sont dits ici plutôt que devinés :
    ///  1. `open_service` ÉCHOUE si le service n'existe pas — c'est le seul backend qui, avant ce
    ///     correctif, était déjà BRUYANT sur « rien à retirer » (erreur, code de retour non nul).
    ///     Il devient maintenant HONNÊTE : « absent », rendu 0, sans prétendre avoir retiré.
    ///  2. `DeleteService` marque le service pour suppression ; s'il tourne encore (arrêt lent, ou
    ///     handle ouvert par un autre outil), il ne DISPARAÎT qu'ensuite. On re-sonde donc l'état
    ///     après `stop()`+`delete()` et on ne dit `Removed` que si le service ne s'ouvre plus.
    /// NON VÉRIFIÉ À L'EXÉCUTION (aucune VM Windows allumée) : ce qui est prouvé, c'est que ça
    /// compile et lie sur `windows-latest` (agent-ci).
    pub fn uninstall() -> anyhow::Result<Removal> {
        let mut r = Removal::default();
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let opened = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        );
        let service = match opened {
            Ok(s) => s,
            Err(_) => {
                r.note(format!("service SCM {SERVICE_NAME}"), Disposition::Absent);
                return Ok(r);
            }
        };
        let _ = service.stop(); // best-effort (peut déjà être arrêté)
        if let Err(e) = service.delete() {
            r.note(
                format!("service SCM {SERVICE_NAME}"),
                Disposition::Failed(format!("DeleteService : {e} (élévation requise ?)")),
            );
            return Ok(r);
        }
        drop(service);
        // RE-SONDE : le service ne doit plus s'ouvrir. S'il s'ouvre encore, la suppression est
        // seulement EN ATTENTE — le dire, plutôt que de l'appeler « retiré ».
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(_) => r.note(
                format!("service SCM {SERVICE_NAME}"),
                Disposition::Failed(
                    "suppression EN ATTENTE : le service est encore enregistré (processus vivant ou \
                     handle ouvert) — il partira à l'arrêt du service ou au redémarrage"
                        .into(),
                ),
            ),
            Err(_) => r.note(format!("service SCM {SERVICE_NAME}"), Disposition::Removed),
        }
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

    #[test]
    fn dispatch_is_noop_off_windows() {
        // Hors Windows, l'appel inconditionnel depuis main doit renvoyer false (fait la boucle normale).
        #[cfg(not(target_os = "windows"))]
        assert_eq!(dispatch_if_service(std::path::Path::new("/x")).unwrap(), false);
    }
}
