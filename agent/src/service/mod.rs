//! Gestion du service natif (install/enable/start l'agent comme daemon système).
//!
//! `ServiceManager` = SPI par-OS. `systemd` (Linux) est PLEINEMENT implémenté ; `launchd` (macOS) et
//! `windows_scm` (Windows) sont des stubs avec l'esquisse plist/SCM. `current()` renvoie le manager
//! adapté à l'OS de compilation.

pub mod systemd;
pub mod launchd;
pub mod windows_scm;

/// CE QU'UN RETRAIT A RÉELLEMENT FAIT — artefact par artefact, OBSERVÉ, jamais supposé.
///
/// LE DÉFAUT QUE CE TYPE REND NON-ÉCRIVABLE. `uninstall()` renvoyait `Result<()>` : chaque backend
/// faisait `let _ = Command::new("systemctl")…status();`, ne vérifiait rien, imprimait
/// « service retiré » et rendait `Ok(())`. MESURÉ le 2026-08-02 sur cette machine, sans rien
/// d'installé : `plume-agent uninstall` a affiché « Failed to disable unit: Connection timed out »
/// PUIS « Reload daemon failed » PUIS « service retiré : plume-agent.service », et est sorti **0** —
/// 0 fichier supprimé, 2 commandes en échec, un succès annoncé. Un opérateur qui croit avoir retiré
/// l'agent d'un poste compromis n'a rien retiré du tout.
///
/// La correction n'est pas un drapeau : c'est que le TYPE DE RETOUR ne permet plus de conclure sans
/// dire quoi. Une disposition ne s'écrit qu'à partir d'une observation (`probe`), et « rien trouvé »
/// n'est PAS « retiré ».
#[derive(Debug, Default)]
pub struct Removal {
    entries: Vec<(String, Disposition)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// L'artefact ÉTAIT là, et il n'y est plus (re-observé après l'action).
    Removed,
    /// L'artefact n'était pas là : rien à faire. Honnête, mais ce n'est PAS un retrait.
    Absent,
    /// L'artefact est TOUJOURS là après l'action, ou l'action a échoué. C'est un échec.
    Failed(String),
}

impl Removal {
    pub fn note(&mut self, what: impl Into<String>, how: Disposition) {
        self.entries.push((what.into(), how));
    }
    /// Vrai si au moins un artefact a réellement été retiré.
    pub fn removed_any(&self) -> bool {
        self.entries.iter().any(|(_, d)| *d == Disposition::Removed)
    }
    pub fn failures(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|(w, d)| matches!(d, Disposition::Failed(_)).then_some(w.as_str()))
            .collect()
    }
    /// Rapport lisible. « rien à retirer » est dit avec ces mots-là : jamais « retiré ».
    pub fn render(&self) -> String {
        if self.entries.is_empty() {
            return "aucun artefact inspecté (backend sans retrait) — rien n'est affirmé".into();
        }
        let mut out = Vec::new();
        for (what, how) in &self.entries {
            out.push(match how {
                Disposition::Removed => format!("  retiré   : {what}"),
                Disposition::Absent => format!("  absent   : {what} (rien à retirer)"),
                Disposition::Failed(why) => format!("  ÉCHEC    : {what} — {why}"),
            });
        }
        if !self.removed_any() && self.failures().is_empty() {
            out.push("  => rien n'était installé : AUCUN retrait effectué.".into());
        }
        out.join("\n")
    }
}

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
    /// Arrête, désactive et retire l'unité. RENVOIE CE QUI A ÉTÉ FAIT, artefact par artefact :
    /// un backend ne peut pas annoncer un succès sans nommer ce qu'il a retiré (cf. `Removal`).
    fn uninstall(&self) -> anyhow::Result<Removal>;
    /// État courant (texte lisible) — actif/inactif + code retour.
    fn status(&self) -> anyhow::Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LE DÉFAUT MESURÉ, FIGÉ : « rien trouvé » ne doit JAMAIS s'écrire « retiré ». C'est le mot
    /// exact que l'ancien code imprimait avec un code de retour 0 sur une machine où rien n'était
    /// installé (mesuré le 2026-08-02). Ce test tourne sur les TROIS OS (agent-ci) : il porte sur le
    /// TYPE, donc il garde aussi les backends qu'on ne peut pas exécuter ici.
    #[test]
    fn rien_trouve_ne_se_dit_jamais_retire() {
        let mut r = Removal::default();
        r.note("service plume-agent.service", Disposition::Absent);
        r.note("/etc/systemd/system/plume-agent.service", Disposition::Absent);
        assert!(!r.removed_any(), "aucun artefact retiré");
        assert!(r.failures().is_empty());
        let txt = r.render();
        assert!(txt.contains("rien à retirer"), "{txt}");
        assert!(txt.contains("AUCUN retrait effectué"), "{txt}");
        assert!(!txt.contains("  retiré   :"), "un rapport sans retrait ne peut pas dire « retiré » : {txt}");
    }

    #[test]
    fn un_artefact_resistant_est_un_echec_nomme() {
        let mut r = Removal::default();
        r.note("service plume-agent.service", Disposition::Failed("toujours actif".into()));
        r.note("/etc/systemd/system/plume-agent.service", Disposition::Removed);
        assert_eq!(r.failures(), vec!["service plume-agent.service"]);
        assert!(r.removed_any(), "un échec partiel n'efface pas ce qui a bien été retiré");
        assert!(r.render().contains("ÉCHEC"), "{}", r.render());
    }

    #[test]
    fn un_retrait_reel_est_dit_retire() {
        let mut r = Removal::default();
        r.note("service plume-agent.service (arrêté et désactivé)", Disposition::Removed);
        assert!(r.removed_any());
        assert!(r.failures().is_empty());
        let txt = r.render();
        assert!(txt.contains("retiré   : service plume-agent.service"), "{txt}");
        assert!(!txt.contains("AUCUN retrait"), "{txt}");
    }
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
