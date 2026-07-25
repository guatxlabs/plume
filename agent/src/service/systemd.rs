//! Service systemd (Linux) — PLEINEMENT implémenté.
//!
//! Écrit /etc/systemd/system/plume-agent.service (unité durcie, alignée sur le durcissement des
//! collecteurs Plume : DynamicUser off — on tourne en root pour lire journald/Security, mais Protect*/
//! NoNewPrivileges/SystemCallFilter réduisent la surface), crée les répertoires, `daemon-reload`,
//! `enable --now`. `uninstall` : `disable --now` + suppression de l'unité + reload. Nécessite root.

use super::{ServiceManager, ServiceSpec};
use std::process::Command;

pub const UNIT_NAME: &str = "plume-agent.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/plume-agent.service";

pub struct Systemd {
    #[allow(dead_code)] // lu par service_name() (API de trait)
    name: String,
}

impl Systemd {
    pub fn new() -> Self {
        Self { name: UNIT_NAME.to_string() }
    }

    /// Génère le texte de l'unité (pur -> testable sans écrire ni exécuter systemctl).
    pub fn unit_text(spec: &ServiceSpec) -> String {
        format!(
            "[Unit]\n\
             Description=Plume endpoint agent (#16) — native OS event shipper\n\
             Documentation=https://github.com/guatxlabs/plume\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exec} run --config {config}\n\
             Restart=always\n\
             RestartSec=5\n\
             # Lecture de journald (et Security côté Windows n/a) -> root ; surface réduite par le durcissement.\n\
             User=root\n\
             StateDirectory=plume-agent\n\
             RuntimeMaxSec=infinity\n\
             # --- durcissement (aligné sur systemd/plume-collector-common.conf) ---\n\
             NoNewPrivileges=yes\n\
             ProtectSystem=strict\n\
             ProtectHome=yes\n\
             PrivateTmp=yes\n\
             ProtectKernelTunables=yes\n\
             ProtectKernelModules=yes\n\
             ProtectControlGroups=yes\n\
             RestrictSUIDSGID=yes\n\
             RestrictRealtime=yes\n\
             MemoryDenyWriteExecute=yes\n\
             LockPersonality=yes\n\
             SystemCallArchitectures=native\n\
             SystemCallFilter=@system-service\n\
             # spool + state accessibles en écriture malgré ProtectSystem=strict\n\
             ReadWritePaths={spool} {state}\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            exec = spec.exec_path.display(),
            config = spec.config_path.display(),
            spool = spec.spool_dir.display(),
            state = spec.state_dir.display(),
        )
    }

    fn systemctl(args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("systemctl").args(args).status()?;
        if !status.success() {
            anyhow::bail!("systemctl {:?} a échoué (code {:?})", args, status.code());
        }
        Ok(())
    }
}

impl Default for Systemd {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager for Systemd {
    fn service_name(&self) -> &str {
        &self.name
    }

    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<()> {
        // Répertoires spool/state (0750 root).
        for d in [&spec.spool_dir, &spec.state_dir] {
            std::fs::create_dir_all(d)
                .map_err(|e| anyhow::anyhow!("création {}: {e}", d.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750));
            }
        }
        // Écrit l'unité.
        std::fs::write(UNIT_PATH, Self::unit_text(spec))
            .map_err(|e| anyhow::anyhow!("écriture {UNIT_PATH}: {e} (root requis ?)"))?;
        Self::systemctl(&["daemon-reload"])?;
        Self::systemctl(&["enable", "--now", UNIT_NAME])?;
        println!("service installé et démarré : {UNIT_NAME}");
        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        // best-effort : ne pas échouer si déjà arrêté/absent.
        let _ = Command::new("systemctl").args(["disable", "--now", UNIT_NAME]).status();
        if std::path::Path::new(UNIT_PATH).exists() {
            std::fs::remove_file(UNIT_PATH)
                .map_err(|e| anyhow::anyhow!("suppression {UNIT_PATH}: {e}"))?;
        }
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        println!("service retiré : {UNIT_NAME}");
        Ok(())
    }

    fn status(&self) -> anyhow::Result<String> {
        let out = Command::new("systemctl")
            .args(["is-active", UNIT_NAME])
            .output()?;
        let active = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(format!("{UNIT_NAME}: {}", if active.is_empty() { "inconnu".into() } else { active }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            exec_path: PathBuf::from("/usr/local/bin/plume-agent"),
            config_path: PathBuf::from("/etc/plume-agent/agent.toml"),
            spool_dir: PathBuf::from("/var/lib/plume-agent/spool"),
            state_dir: PathBuf::from("/var/lib/plume-agent/state"),
        }
    }

    #[test]
    fn unit_text_is_well_formed() {
        let u = Systemd::unit_text(&spec());
        assert!(u.contains("[Unit]"));
        assert!(u.contains("[Service]"));
        assert!(u.contains("[Install]"));
        assert!(u.contains(
            "ExecStart=/usr/local/bin/plume-agent run --config /etc/plume-agent/agent.toml"
        ));
        assert!(u.contains("Restart=always"));
        assert!(u.contains("WantedBy=multi-user.target"));
        // durcissement présent
        assert!(u.contains("NoNewPrivileges=yes"));
        assert!(u.contains("SystemCallFilter=@system-service"));
        assert!(u.contains(
            "ReadWritePaths=/var/lib/plume-agent/spool /var/lib/plume-agent/state"
        ));
    }
}
