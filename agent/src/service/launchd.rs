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

use super::{interrogation, Constat, Outcome, ServiceManager, ServiceSpec};
use crate::lisibilite::Lecture;
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

    /// Le daemon est-il CHARGÉ — LU, ou AVOUÉ (`S36`). `launchctl print system/<label>` rend 0 quand
    /// il l'est.
    ///
    /// CE QUI EST TENU ICI, ET CE QUI NE L'EST PAS — dit franchement plutôt que promis. Le repli
    /// `unwrap_or(false)` faisait de « `launchctl` n'a pas pu être LANCÉ » un « le daemon n'est pas
    /// chargé » : le retrait en concluait « rien à retirer », code de sortie nul, alors que rien
    /// n'avait été mesuré. Ce cas-là est désormais un aveu.
    ///
    /// CE QUI RESTE OUVERT, ET POURQUOI : un `print` qui rend un code NON NUL est encore lu comme
    /// « pas chargé ». Séparer là « le daemon est absent du domaine » de « le domaine n'a pas
    /// répondu » demanderait de connaître les codes que rend cet outil, et cela se MESURE sur un hôte
    /// macOS — il n'y en a pas sous la main, et une table écrite d'imagination serait exactement le
    /// genre d'affirmation que cette campagne retire. La limite est donc nommée, pas comblée.
    fn est_charge() -> Lecture<bool> {
        match Command::new("launchctl").args(["print", DOMAIN_TARGET]).output() {
            Err(e) => interrogation::pas_lance("launchctl print", &e),
            Ok(o) => Lecture::Lue(o.status.success()),
        }
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

    /// POSE OBSERVÉE (cf. `Outcome`) — même structure que le backend systemd : chaque artefact est
    /// sondé, agi, RE-SONDÉ. `launchctl bootstrap` peut rendre 0 sans que le daemon soit chargé
    /// (plist refusé, binaire absent) : la conclusion vient de `launchctl print`, pas du code retour.
    /// NON VÉRIFIÉ À L'EXÉCUTION (aucun hôte macOS ici) ; ce qui est prouvé, c'est que ça compile.
    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<Outcome> {
        let mut r = Outcome::pose();
        // Répertoires spool/state (0750).
        for d in [&spec.spool_dir, &spec.state_dir] {
            let existait = d.is_dir();
            let res = std::fs::create_dir_all(d);
            #[cfg(unix)]
            if res.is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750));
            }
            r.observe(format!("répertoire {}", d.display()), Constat::mesure(existait), || match res {
                Ok(()) if d.is_dir() => Ok(()),
                Ok(()) => Err("créé sans erreur mais absent à la re-sonde".into()),
                Err(e) => Err(format!("{e} (root requis ?)")),
            });
        }
        // Écrit le plist (launchd exige un plist NON inscriptible par le groupe/monde : 0644 root).
        let voulu = Self::plist_text(spec);
        let deja = std::fs::read_to_string(PLIST_PATH).map(|t| t == voulu).unwrap_or(false);
        let ecrit = std::fs::write(PLIST_PATH, &voulu);
        #[cfg(unix)]
        if ecrit.is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(0o644));
        }
        r.observe(PLIST_PATH, Constat::mesure(deja), || match ecrit {
            Err(e) => Err(format!("{e} (root requis ?)")),
            Ok(()) => match std::fs::read_to_string(PLIST_PATH) {
                Ok(t) if t == voulu => Ok(()),
                Ok(_) => Err("écrit mais son contenu diffère à la relecture".into()),
                Err(e) => Err(format!("écrit mais illisible ensuite : {e}")),
            },
        });
        if !r.failures().is_empty() {
            return Ok(r);
        }

        // Décharge une éventuelle instance précédente (best-effort) puis (ré)amorce. Le plist a-t-il
        // CHANGÉ ? Si oui, l'état voulu n'était PAS atteint même si le daemon tournait : c'était
        // l'ANCIEN plist qui tournait (même raison que le redémarrage explicite côté systemd).
        let lu_charge = Self::est_charge();
        let etait_conforme = match &lu_charge {
            Lecture::Lue(charge) => Constat::mesure(*charge && deja),
            aveu => Constat::depuis_aveu(aveu).unwrap_or(Constat::NonConforme),
        };
        let _ = Command::new("launchctl").args(["bootout", DOMAIN_TARGET]).status();
        // macOS 11+ : bootstrap ; repli hérité si indisponible.
        let amorce = if Self::launchctl(&["bootstrap", "system", PLIST_PATH]).is_err() {
            Self::launchctl(&["load", "-w", PLIST_PATH])
        } else {
            Ok(())
        };
        let _ = Command::new("launchctl").args(["enable", DOMAIN_TARGET]).status();
        // Force un (re)démarrage immédiat.
        let _ = Command::new("launchctl").args(["kickstart", "-k", DOMAIN_TARGET]).status();
        r.observe(format!("daemon {LABEL} (chargé et démarré)"), etait_conforme, || {
            if let Err(e) = amorce {
                return Err(format!("{e}"));
            }
            match Self::est_charge() {
                Lecture::Lue(true) => Ok(()),
                Lecture::Lue(false) => Err("NON chargé après `launchctl bootstrap` \
                                            (`launchctl print system/…`, \
                                            /var/log/plume-agent.err.log)"
                    .into()),
                Lecture::Illisible { cause, detail } => Err(format!(
                    "l'état du daemon n'a PAS pu être interrogé après `launchctl bootstrap` \
                     ({cause} : {detail}) — le chargement n'est donc PAS constaté"
                )),
            }
        });
        Ok(r)
    }

    /// RETRAIT OBSERVÉ (cf. `Outcome`) : on sonde `launchctl print` avant/après, et le plist avant/
    /// après. NON VÉRIFIÉ À L'EXÉCUTION (aucun hôte macOS ici) : la STRUCTURE est celle du backend
    /// systemd, qui l'est ; ce qui est prouvé sur macOS, à ce jour, c'est que ça compile (agent-ci).
    fn uninstall(&self) -> anyhow::Result<Outcome> {
        let mut r = Outcome::retrait();
        // « JE N'AI PAS PU INTERROGER » N'EST PAS « RIEN À RETIRER » (`S36`) : c'est ici que le repli
        // de `is_loaded` sortait, jumeau exact du backend systemd — l'outil absent valait « déchargé »,
        // la re-sonde rappelait la même fonction et rendait le même « déchargé », et le rapport
        // annonçait « absent (rien à retirer) » avec un code de sortie nul.
        let lu_charge = Self::est_charge();
        let constat = match &lu_charge {
            Lecture::Lue(charge) => Constat::mesure(!*charge),
            aveu => Constat::depuis_aveu(aveu).unwrap_or(Constat::NonConforme),
        };
        // L'ACTION reste tentée — c'est ce que l'opérateur a demandé, et elle est idempotente.
        let _ = Command::new("launchctl").args(["bootout", DOMAIN_TARGET]).status();
        let _ = Command::new("launchctl").args(["unload", "-w", PLIST_PATH]).status(); // repli hérité
        let nom = match &constat {
            Constat::Conforme => format!("daemon {LABEL}"),
            _ => format!("daemon {LABEL} (déchargé)"),
        };
        r.observe(nom, constat, || match Self::est_charge() {
            Lecture::Lue(false) => Ok(()),
            Lecture::Lue(true) => {
                Err("toujours chargé après `launchctl bootout` (root requis ?)".into())
            }
            Lecture::Illisible { cause, detail } => Err(format!(
                "l'état du daemon n'a PAS pu être interrogé après `launchctl bootout` \
                 ({cause} : {detail}) — RIEN n'est affirmé sur ce qui reste chargé sur cet hôte"
            )),
        });
        let plist = std::path::Path::new(PLIST_PATH);
        let deja_absent = !plist.exists();
        let supprime = if deja_absent { Ok(()) } else { std::fs::remove_file(plist) };
        r.observe(PLIST_PATH, Constat::mesure(deja_absent), || match supprime {
            Err(e) => Err(format!("{e} (root requis ?)")),
            Ok(()) if plist.exists() => Err("toujours présent après suppression".into()),
            Ok(()) => Ok(()),
        });
        Ok(r)
    }

    /// L'ÉTAT AFFICHÉ — ou l'aveu qu'il n'a pas été lu (`S36`). Le bras attrape-tout rendait
    /// « non chargé » aussi bien pour un daemon réellement absent du domaine que pour un `launchctl`
    /// qui n'avait pas pu être lancé : le seul mot que l'opérateur lisait était le rassurant.
    fn status(&self) -> anyhow::Result<String> {
        match Command::new("launchctl").args(["print", DOMAIN_TARGET]).output() {
            Err(e) => {
                let aveu: Lecture<()> = interrogation::pas_lance("launchctl print", &e);
                Ok(format!(
                    "{LABEL}: état NON INTERROGÉ ({}) — {}",
                    aveu.cause(),
                    aveu.detail().unwrap_or("")
                ))
            }
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                // La ligne `state = …` si elle est là ; sinon le fait qui EST mesuré — le code de
                // retour nul dit que le daemon est dans le domaine — sans prétendre en connaître
                // l'état fin.
                let state = text
                    .lines()
                    .find(|l| l.trim_start().starts_with("state ="))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "chargé (état fin non rendu par l'outil)".to_string());
                Ok(format!("{LABEL}: {state}"))
            }
            Ok(_) => Ok(format!("{LABEL}: non chargé")),
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
