//! Service launchd (macOS) — IMPLÉMENTÉ.
//!
//! Installe un LaunchDaemon (root, au boot) : /Library/LaunchDaemons/com.guatx.plume-agent.plist,
//! crée les répertoires spool/state, puis `launchctl bootstrap system <plist>` +
//! `launchctl enable system/<label>` + `launchctl kickstart -k system/<label>` (repli hérité
//! `launchctl load -w`). `uninstall` : `launchctl bootout system/<label>` + suppression du plist.
//! `status` : `launchctl print system/<label>`. Nécessite root.
//!
//! Le fichier compile sur toutes les cibles (comme systemd.rs) : `plist_text`/`bin` sont purs et
//! testés ; les invocations `launchctl` n'existent qu'à l'exécution (hôte macOS requis).

use super::{ServiceManager, ServiceSpec};
use std::process::Command;

pub const LABEL: &str = "com.guatx.plume-agent";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.guatx.plume-agent.plist";
const DOMAIN_TARGET: &str = "system/com.guatx.plume-agent";

pub struct Launchd {
    #[allow(dead_code)] // lu par service_name() (API de trait)
    name: String,
}

impl Launchd {
    pub fn new() -> Self {
        Self { name: LABEL.to_string() }
    }

    /// Génère le plist LaunchDaemon (pur -> testable indépendamment).
    pub fn plist_text(spec: &ServiceSpec) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>{LABEL}</string>\n\
             <key>ProgramArguments</key><array>\
             <string>{exec}</string><string>run</string><string>--config</string><string>{config}</string>\
             </array>\n\
             <key>RunAtLoad</key><true/>\n\
             <key>KeepAlive</key><true/>\n\
             <key>ProcessType</key><string>Background</string>\n\
             <key>StandardErrorPath</key><string>/var/log/plume-agent.err.log</string>\n\
             <key>StandardOutPath</key><string>/var/log/plume-agent.out.log</string>\n\
             </dict></plist>\n",
            exec = spec.exec_path.display(),
            config = spec.config_path.display(),
        )
    }

    fn launchctl(args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("launchctl").args(args).status()?;
        if !status.success() {
            anyhow::bail!("launchctl {:?} a échoué (code {:?})", args, status.code());
        }
        Ok(())
    }
}

impl Default for Launchd {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for Launchd {
    fn service_name(&self) -> &str {
        &self.name
    }

    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<()> {
        // Répertoires spool/state (0750).
        for d in [&spec.spool_dir, &spec.state_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| anyhow::anyhow!("création {}: {e}", d.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750));
            }
        }
        // Écrit le plist (launchd exige un plist NON inscriptible par le groupe/monde : 0644 root).
        std::fs::write(PLIST_PATH, Self::plist_text(spec))
            .map_err(|e| anyhow::anyhow!("écriture {PLIST_PATH}: {e} (root requis ?)"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(0o644));
        }

        // Décharge une éventuelle instance précédente (best-effort) puis (ré)amorce.
        let _ = Command::new("launchctl").args(["bootout", DOMAIN_TARGET]).status();
        // macOS 11+ : bootstrap ; repli hérité si indisponible.
        if Self::launchctl(&["bootstrap", "system", PLIST_PATH]).is_err() {
            Self::launchctl(&["load", "-w", PLIST_PATH])?;
        }
        let _ = Command::new("launchctl").args(["enable", DOMAIN_TARGET]).status();
        // Force un (re)démarrage immédiat.
        let _ = Command::new("launchctl").args(["kickstart", "-k", DOMAIN_TARGET]).status();
        println!("service installé et démarré : {LABEL}");
        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        let _ = Command::new("launchctl").args(["bootout", DOMAIN_TARGET]).status();
        let _ = Command::new("launchctl").args(["unload", "-w", PLIST_PATH]).status(); // repli hérité
        if std::path::Path::new(PLIST_PATH).exists() {
            std::fs::remove_file(PLIST_PATH)
                .map_err(|e| anyhow::anyhow!("suppression {PLIST_PATH}: {e}"))?;
        }
        println!("service retiré : {LABEL}");
        Ok(())
    }

    fn status(&self) -> anyhow::Result<String> {
        let out = Command::new("launchctl").args(["print", DOMAIN_TARGET]).output();
        match out {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                // Extrait la ligne `state = ...` si présente, sinon indique chargé.
                let state = text
                    .lines()
                    .find(|l| l.trim_start().starts_with("state ="))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "chargé".to_string());
                Ok(format!("{LABEL}: {state}"))
            }
            _ => Ok(format!("{LABEL}: non chargé")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            exec_path: PathBuf::from("/usr/local/bin/plume-agent"),
            config_path: PathBuf::from("/Library/Application Support/plume-agent/agent.toml"),
            spool_dir: PathBuf::from("/Library/Application Support/plume-agent/spool"),
            state_dir: PathBuf::from("/Library/Application Support/plume-agent/state"),
        }
    }

    #[test]
    fn plist_is_well_formed() {
        let p = Launchd::plist_text(&spec());
        assert!(p.contains("<key>Label</key><string>com.guatx.plume-agent</string>"));
        assert!(p.contains("<string>/usr/local/bin/plume-agent</string><string>run</string>"));
        assert!(p.contains("--config"));
        assert!(p.contains("<key>RunAtLoad</key><true/>"));
        assert!(p.contains("<key>KeepAlive</key><true/>"));
        assert!(p.contains("<!DOCTYPE plist"));
    }

    #[test]
    fn service_name_is_label() {
        assert_eq!(Launchd::new().service_name(), "com.guatx.plume-agent");
    }
}
