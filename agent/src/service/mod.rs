//! Gestion du service natif (install/enable/start l'agent comme daemon système).
//!
//! `ServiceManager` = SPI par-OS. `systemd` (Linux) est PLEINEMENT implémenté ; `launchd` (macOS) et
//! `windows_scm` (Windows) sont des stubs avec l'esquisse plist/SCM. `current()` renvoie le manager
//! adapté à l'OS de compilation.

pub mod systemd;
pub mod launchd;
pub mod windows_scm;

/// Paramètres d'installation du service.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// Chemin absolu du binaire de l'agent (argv0 résolu).
    pub exec_path: std::path::PathBuf,
    /// Chemin du fichier de config à passer en `--config`.
    pub config_path: std::path::PathBuf,
    /// Répertoires à créer/posséder (spool, state).
    pub spool_dir: std::path::PathBuf,
    pub state_dir: std::path::PathBuf,
}

pub trait ServiceManager {
    /// Nom du service (unité systemd / label launchd / nom SCM).
    #[allow(dead_code)] // exposé pour diagnostics/futurs appelants
    fn service_name(&self) -> &str;
    /// Installe l'unité, crée les répertoires, active et démarre le service.
    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<()>;
    /// Arrête, désactive et retire l'unité.
    fn uninstall(&self) -> anyhow::Result<()>;
    /// État courant (texte lisible) — actif/inactif + code retour.
    fn status(&self) -> anyhow::Result<String>;
}

/// Manager adapté à l'OS courant.
pub fn current() -> Box<dyn ServiceManager> {
    #[cfg(target_os = "linux")]
    {
        Box::new(systemd::Systemd::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(launchd::Launchd::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_scm::WindowsScm::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(systemd::Systemd::new())
    }
}
