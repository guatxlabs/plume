//! Service systemd (Linux) — PLEINEMENT implémenté.
//!
//! Écrit /etc/systemd/system/plume-agent.service (unité durcie, alignée sur le durcissement des
//! collecteurs Plume : DynamicUser off — on tourne en root pour lire journald/Security, mais Protect*/
//! NoNewPrivileges/SystemCallFilter réduisent la surface), crée les répertoires, `daemon-reload`,
//! `enable --now`. `uninstall` : `disable --now` + suppression de l'unité + reload. Nécessite root.

use super::{Outcome, ServiceManager, ServiceSpec};
use std::path::Path;
use std::process::Command;

pub const UNIT_NAME: &str = "plume-agent.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/plume-agent.service";

/// LE DURCISSEMENT DE L'UNITÉ, DÉCLARÉ AVEC CE QU'IL REND INVISIBLE AU SERVICE.
///
/// POURQUOI CETTE TABLE EXISTE. Le durcissement était un bloc de texte libre dans `unit_text`, et
/// l'`ExecStart` était le chemin courant du binaire, écrit tel quel. Les deux se contredisaient sans
/// que personne ne puisse le voir : MESURÉ le 2026-08-02 (systemd 261, manager utilisateur, sonde
/// différentielle à une seule variable) — même exécutable, **sans** `ProtectHome` le service tourne
/// (`ActiveState=active`, `ExecMainStatus=0`) ; **avec** `ProtectHome=yes` et un exécutable sous
/// `$HOME` il meurt en `status=203/EXEC` (« Unable to locate executable … No such file or directory »),
/// et le `systemctl start` rend quand même **0**. Idem pour `/tmp` sous `PrivateTmp=yes` (203). Le
/// service ne pouvait pas lire son propre binaire, et la commande annonçait « démarré ».
///
/// CE QUE LA TABLE CHANGE. `unit_text` est RENDU depuis ici, et la vérification de joignabilité
/// (`chemin_cache_par`) lit la MÊME source de vérité. On ne peut donc pas ajouter une directive de
/// bac à sable sans DIRE quels préfixes elle masque — le tuple ne compile pas sans son second champ.
/// La garde n'énumère pas trois cas connus : elle est l'union, par construction, de ce que l'unité
/// s'impose à elle-même.
///
/// NB `ProtectSystem=strict` ne masque RIEN : il rend l'arborescence LECTURE SEULE. Un binaire sous
/// `/usr/bin` reste exécutable — c'est le CONTRÔLE de la sonde différentielle, mesuré depuis
/// `/usr/bin` (et `/usr/local/bin` relève de la même directive).
///
/// DEUX FAÇONS DE MASQUER, ET ELLES NE SE CORRIGENT PAS PAREIL — mesuré, contre l'intuition.
/// `ReadWritePaths=` (que l'unité pose sur spool+state) RE-EXPOSE un chemin protégé par `ProtectHome`
/// mais NE PEUT RIEN pour `PrivateTmp`, qui REMPLACE le point de montage par un tmpfs neuf où le
/// chemin n'existe simplement pas. MESURÉ le 2026-08-02, quatre unités, une seule variable :
///   - `ReadWritePaths=$HOME/…` + `ProtectHome=yes` -> `active/running` : le service tourne ;
///   - `ReadWritePaths=/tmp/…`  + `PrivateTmp=yes`  -> `status=226/NAMESPACE`, service mort ;
///   - `ExecStart` sous `$HOME` + `ProtectHome=yes` (pas dans ReadWritePaths) -> `203/EXEC` ;
///   - contrôle sans la directive -> `active/running`, `ExecMainStatus=0`.
/// D'où la distinction ci-dessous, qui est la SEULE façon de ne pas refuser un déploiement légitime
/// (spool sous /home) tout en refusant ceux qui ne peuvent pas marcher.
enum Masquage {
    /// Ne cache rien (lecture seule, filtres d'appels système, capacités…).
    Rien,
    /// Cache ces préfixes — mais `ReadWritePaths=` les RE-EXPOSE (mesuré).
    Chemins(&'static [&'static str]),
    /// REMPLACE ces points de montage : `ReadWritePaths=` n'y peut rien (mesuré, 226/NAMESPACE).
    Remplace(&'static [&'static str]),
}

const HARDENING: [(&str, Masquage); 13] = [
    ("NoNewPrivileges=yes", Masquage::Rien),
    ("ProtectSystem=strict", Masquage::Rien),
    ("ProtectHome=yes", Masquage::Chemins(&["/home", "/root", "/run/user"])),
    ("PrivateTmp=yes", Masquage::Remplace(&["/tmp", "/var/tmp"])),
    ("ProtectKernelTunables=yes", Masquage::Rien),
    ("ProtectKernelModules=yes", Masquage::Rien),
    ("ProtectControlGroups=yes", Masquage::Rien),
    ("RestrictSUIDSGID=yes", Masquage::Rien),
    ("RestrictRealtime=yes", Masquage::Rien),
    ("MemoryDenyWriteExecute=yes", Masquage::Rien),
    ("LockPersonality=yes", Masquage::Rien),
    ("SystemCallArchitectures=native", Masquage::Rien),
    ("SystemCallFilter=@system-service", Masquage::Rien),
    // Une directive ajoutée ici DOIT dire CE QU'ELLE MASQUE ET COMMENT : `PrivateDevices=yes`
    // vaudrait `Masquage::Remplace(&["/dev"])`, `ProtectProc=invisible` `Remplace(&["/proc"])`.
    // Le tuple ne compile pas sans son second champ, et `Masquage` n'a pas de variante par défaut.
];

/// Le préfixe qui rend ce chemin INUTILISABLE par le service, s'il y en a un, avec la directive
/// responsable. `reexpose` = ce chemin figure-t-il dans `ReadWritePaths=` de l'unité ? Si oui, seul
/// un `Remplace` est fatal (mesuré). Comparaison PAR COMPOSANTS (`Path::starts_with`) :
/// `/homeless-binary` n'est PAS sous `/home`.
pub fn chemin_cache_par(p: &Path, reexpose: bool) -> Option<(&'static str, &'static str)> {
    // Best-effort : on résout les liens quand c'est possible (un binaire lancé via un symlink de
    // /usr/local/bin vers /home reste, lui, sous /home du point de vue du noyau).
    let reel = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    for (directive, masquage) in HARDENING.iter() {
        let prefixes: &[&str] = match masquage {
            Masquage::Rien => &[],
            // Re-exposé par ReadWritePaths -> ce masquage-là n'est plus un problème.
            Masquage::Chemins(pfx) => {
                if reexpose {
                    &[]
                } else {
                    pfx
                }
            }
            Masquage::Remplace(pfx) => pfx,
        };
        for c in prefixes {
            if reel.starts_with(c) {
                return Some((directive, c));
            }
        }
    }
    None
}

pub struct Systemd {
    #[allow(dead_code)] // lu par service_name() (API de trait)
    name: String,
}

impl Systemd {
    pub fn new() -> Self {
        Self { name: UNIT_NAME.to_string() }
    }

    /// Génère le texte de l'unité (pur -> testable sans écrire ni exécuter systemctl). Le bloc de
    /// durcissement est RENDU depuis `HARDENING` (même source de vérité que `chemin_cache_par`),
    /// texte byte-identique à la version littérale — figé par `bloc_durcissement_est_byte_identique`.
    pub fn unit_text(spec: &ServiceSpec) -> String {
        let durcissement: String =
            HARDENING.iter().map(|(d, _)| format!("{d}\n")).collect::<String>();
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
             {durcissement}\
             # spool + state accessibles en écriture malgré ProtectSystem=strict\n\
             ReadWritePaths={spool} {state}\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            durcissement = durcissement,
            exec = spec.exec_path.display(),
            config = spec.config_path.display(),
            spool = spec.spool_dir.display(),
            state = spec.state_dir.display(),
        )
    }

    /// L'unité est-elle ACTIVE ? Observation, pas hypothèse : `systemctl is-active` rend 0 quand
    /// elle l'est. Une erreur d'exécution (systemd injoignable) est traitée comme « pas actif » —
    /// et c'est sans risque ici, parce que le retrait RE-SONDE et ne conclut jamais sans preuve.
    fn is_active() -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn systemctl(args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("systemctl").args(args).status()?;
        if !status.success() {
            anyhow::bail!("systemctl {:?} a échoué (code {:?})", args, status.code());
        }
        Ok(())
    }

    /// Propriétés d'unité lues d'un coup (`KEY=VALUE` par ligne — on ne suppose PAS l'ordre).
    fn show(props: &[&str]) -> std::collections::HashMap<String, String> {
        let mut cmd = Command::new("systemctl");
        cmd.arg("show");
        for p in props {
            cmd.arg("-p").arg(p);
        }
        cmd.arg(UNIT_NAME);
        let mut out = std::collections::HashMap::new();
        if let Ok(o) = cmd.output() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Some((k, v)) = line.split_once('=') {
                    out.insert(k.to_string(), v.to_string());
                }
            }
        }
        out
    }

    /// LE SERVICE TOURNE-T-IL VRAIMENT — et TIENT-IL ?
    ///
    /// LA COURSE QUI REND UNE SONDE INSTANTANÉE INUTILE (mesurée, et elle m'a piégé). `Type=simple` :
    /// le job de démarrage se termine au FORK, avant l'`exec`. MESURÉ le 2026-08-02, 3 fois sur 3,
    /// sur une unité dont l'`ExecStart` est injoignable depuis son bac à sable :
    ///   - échantillon IMMÉDIAT après le démarrage : `ActiveState=active SubState=running
    ///     Result=success ExecMainStatus=0` — c'est-à-dire le SUCCÈS ;
    ///   - le MÊME service à +1,2 s : `activating / auto-restart / exit-code / 203`.
    /// Une sonde qui conclut au premier échantillon valide donc EXACTEMENT le défaut qu'elle est
    /// censée attraper. Ce n'est pas un détail d'implémentation : c'est la garde centrale.
    ///
    /// LA FORME. On n'observe pas un instant, on observe une DURÉE : `active/running` avec
    /// `ExecMainStatus=0` doit tenir SANS INTERRUPTION pendant `STABILITE`. Toute observation
    /// contraire — `failed`, `auto-restart` — est un ÉCHEC immédiat (avec `Restart=always`, une
    /// boucle de redémarrage n'est PAS une attente), et toute observation intermédiaire
    /// (`activating/start`) REMET le compteur de stabilité à zéro.
    ///
    /// POURQUOI UN DELTA DE `NRestarts` ET PAS SA VALEUR. Un redémarrage automatique PENDANT notre
    /// fenêtre est un échec — mais la valeur absolue ne le dit pas : MESURÉ le 2026-08-02, un service
    /// PARFAITEMENT SAIN porte `NRestarts=3` s'il a été relancé 3 fois par le passé
    /// (`ActiveState=active SubState=running Result=success ExecMainStatus=0 NRestarts=3`). Tester
    /// `NRestarts > 0` aurait donc déclaré en échec une ré-installation sur un service en bonne
    /// santé au passé chargé. On compare à la valeur lue AVANT de démarrer. (Mesuré aussi :
    /// `systemctl restart` REMET `NRestarts` à 0 et `Result` à `success`.)
    const STABILITE: std::time::Duration = std::time::Duration::from_millis(2500);
    fn tourne_vraiment(budget: std::time::Duration, restarts_avant: u32) -> Result<(), String> {
        let debut = std::time::Instant::now();
        let mut stable_depuis: Option<std::time::Instant> = None;
        let mut dernier;
        loop {
            let p = Self::show(&["ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts"]);
            let actif = p.get("ActiveState").map(String::as_str).unwrap_or("");
            let sub = p.get("SubState").map(String::as_str).unwrap_or("");
            let res = p.get("Result").map(String::as_str).unwrap_or("");
            let code = p.get("ExecMainStatus").map(String::as_str).unwrap_or("");
            let restarts = p.get("NRestarts").map(String::as_str).unwrap_or("0");
            dernier = format!(
                "ActiveState={actif} SubState={sub} Result={res} ExecMainStatus={code} NRestarts={restarts}"
            );
            let echec = matches!((actif, sub), ("failed", _) | (_, "auto-restart") | (_, "failed"))
                || restarts.parse::<u32>().unwrap_or(0) > restarts_avant;
            if echec {
                return Err(format!(
                    "le service NE TOURNE PAS après `systemctl enable --now` ({dernier}){}",
                    if code == "203" {
                        " — 203/EXEC : l'ExecStart est INJOIGNABLE depuis le bac à sable de \
                         l'unité (binaire sous /home, /root ou /tmp ?). `journalctl -u \
                         plume-agent -n 20` pour la ligne exacte."
                    } else if code == "226" {
                        " — 226/NAMESPACE : un chemin de l'unité (spool/state) n'existe pas dans \
                         son bac à sable. `journalctl -u plume-agent -n 20`."
                    } else {
                        " — `journalctl -u plume-agent -n 20` pour la cause."
                    }
                ));
            }
            if (actif, sub) == ("active", "running") && code == "0" {
                let t0 = *stable_depuis.get_or_insert_with(std::time::Instant::now);
                if t0.elapsed() >= Self::STABILITE {
                    return Ok(());
                }
            } else {
                stable_depuis = None; // la continuité est rompue : on recommence à compter.
            }
            if debut.elapsed() >= budget {
                return Err(format!(
                    "le service n'a pas tenu {:?} d'affilée en {budget:?} ({dernier})",
                    Self::STABILITE
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// L'unité est-elle ACTIVÉE AU BOOT ? (`is-enabled` : 0 = enabled). Observation distincte de
    /// `is-active` — un service lancé à la main mais non activé redémarrerait muet au prochain boot,
    /// et l'artefact que l'on nomme « actif AU BOOT et maintenant » n'a pas le droit de l'affirmer
    /// sans l'avoir regardé.
    fn is_enabled() -> bool {
        Command::new("systemctl")
            .args(["is-enabled", "--quiet", UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
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

    /// POSE OBSERVÉE, pas annoncée — jumeau exact de `uninstall` ci-dessous, et pour la même raison.
    ///
    /// 1. PRÉ-VOL : on refuse d'écrire une unité qui SE CONTREDIT (un chemin de la spec masqué par le
    ///    durcissement que cette même unité impose). AUCUNE unité n'est écrite, AUCUN service n'est
    ///    touché, et le message dit quoi faire. (Le fichier de config, lui, a pu être généré plus tôt
    ///    par `cmd_install --endpoint` : c'est écrit ici pour qu'on ne lise pas « rien n'est écrit ».)
    ///    C'est ce que le README demandait à l'humain de vérifier à la main.
    /// 2. Chaque artefact est SONDÉ avant, agi, puis RE-SONDÉ (cf. `Outcome`) : le service n'est dit
    ///    « posé » que si `tourne_vraiment()` l'a vu actif ET STABLE, et `is_enabled()` activé.
    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<Outcome> {
        // 1. PRÉ-VOL dérivé de HARDENING × ServiceSpec::paths() (destructuration exhaustive).
        for (role, p, reexpose) in spec.paths() {
            if let Some((directive, prefixe)) = chemin_cache_par(p, reexpose) {
                // La panne annoncée est CELLE QU'ON A MESURÉE pour ce cas-là : un chemin que le
                // service doit EXÉCUTER/LIRE meurt en 203/EXEC ; un chemin listé dans
                // `ReadWritePaths=` dont le point de montage est remplacé meurt en 226/NAMESPACE.
                let panne = if reexpose { "226/NAMESPACE" } else { "203/EXEC" };
                anyhow::bail!(
                    "REFUS d'installer une unité qui ne pourrait pas fonctionner : {role} = {} est \
                     sous {prefixe}, que l'unité elle-même masque au service ({directive}) — le \
                     service ne pourrait pas s'en servir (échec systemd {panne} en boucle de \
                     redémarrage, mesuré). Place ce chemin hors de {prefixe} : le binaire dans \
                     /usr/local/bin (`sudo install -m0755 <bin> /usr/local/bin/plume-agent`), la \
                     config dans /etc/plume, le spool et l'état sous /var/lib/plume-agent.",
                    p.display()
                );
            }
        }

        let mut r = Outcome::pose();

        // 2. Répertoires spool/state (0750 root) — re-sondés (un create_dir_all « réussi » sur un
        //    chemin qui n'est pas un répertoire ne doit pas passer pour une pose).
        for d in [&spec.spool_dir, &spec.state_dir] {
            let existait = d.is_dir();
            let res = std::fs::create_dir_all(d);
            #[cfg(unix)]
            if res.is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o750));
            }
            r.observe(format!("répertoire {}", d.display()), existait, || match res {
                Ok(()) if d.is_dir() => Ok(()),
                Ok(()) => Err("créé sans erreur mais absent à la re-sonde".into()),
                Err(e) => Err(format!("{e} (root requis ?)")),
            });
        }
        if !r.failures().is_empty() {
            // Sans spool/state, l'unité ne pourrait pas démarrer : ne pas laisser un fichier
            // d'unité ORPHELIN dans /etc/systemd/system sur un échec qu'on connaît déjà.
            return Ok(r);
        }

        // 3. L'unité sur le disque — re-sonde par RELECTURE : le fichier doit contenir CE QU'ON A
        //    voulu écrire (/etc en lecture seule, disque plein, écriture partielle).
        let voulu = Self::unit_text(spec);
        let deja = std::fs::read_to_string(UNIT_PATH).map(|t| t == voulu).unwrap_or(false);
        let ecrit = std::fs::write(UNIT_PATH, &voulu);
        r.observe(UNIT_PATH, deja, || match ecrit {
            Err(e) => Err(format!("{e} (root requis ?)")),
            Ok(()) => match std::fs::read_to_string(UNIT_PATH) {
                Ok(t) if t == voulu => Ok(()),
                Ok(_) => Err("écrite mais son contenu diffère à la relecture".into()),
                Err(e) => Err(format!("écrite mais illisible ensuite : {e}")),
            },
        });
        if !r.failures().is_empty() {
            return Ok(r); // inutile de démarrer une unité qu'on n'a pas pu poser.
        }

        // 4. Activation + démarrage — RE-SONDÉ (`Type=simple` : `enable --now` rend 0 avant l'exec).
        //
        // RÉ-INSTALLATION AVEC UNE UNITÉ MODIFIÉE : `enable --now` sur un service DÉJÀ actif ne le
        // redémarre PAS. Le processus vivant resterait celui de l'ANCIENNE unité (ancien ExecStart,
        // ancien `--config`) pendant que le rapport dirait « posé » — le même mensonge, une couche
        // plus bas. Quand le texte de l'unité a CHANGÉ, on redémarre donc explicitement ; l'état
        // « voulu » n'est pas « une unité à jour sur le disque », c'est « le service qui tourne EST
        // celui que décrit cette unité ». `restart` démarre aussi une unité inactive : un seul
        // chemin couvre les deux cas.
        let tournait = Self::is_active();
        let etait_active_au_boot = Self::is_enabled();
        // Valeur de RÉFÉRENCE du compteur de redémarrages : c'est son AUGMENTATION pendant notre
        // fenêtre qui trahit une boucle, pas sa valeur (cf. `tourne_vraiment`).
        let restarts_avant: u32 = Self::show(&["NRestarts"])
            .get("NRestarts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let unite_modifiee = !deja;
        // `daemon-reload` N'EST PAS best-effort : s'il échoue, systemd garde EN MÉMOIRE l'ancienne
        // unité, et le `restart` qui suit relancerait exactement le service qu'on croit remplacer —
        // avec un `active/running` parfaitement stable à la re-sonde. Son échec doit donc sortir.
        let demarrage = Self::systemctl(&["daemon-reload"]).and_then(|()| {
            if unite_modifiee && tournait {
                Self::systemctl(&["enable", UNIT_NAME])
                    .and_then(|()| Self::systemctl(&["restart", UNIT_NAME]))
            } else {
                Self::systemctl(&["enable", "--now", UNIT_NAME])
            }
        });
        // « déjà en place » exige les TROIS : il tournait, il était activé au boot, et l'unité n'a
        // pas bougé. Sinon quelque chose a bel et bien changé.
        let deja_conforme = tournait && etait_active_au_boot && !unite_modifiee;
        r.observe(format!("service {UNIT_NAME} (actif au boot et maintenant)"), deja_conforme, || {
            if let Err(e) = demarrage {
                return Err(format!("{e}"));
            }
            Self::tourne_vraiment(std::time::Duration::from_secs(12), restarts_avant)?;
            // L'artefact dit « au boot » : on le VÉRIFIE, on ne le déduit pas de `enable`.
            if Self::is_enabled() {
                Ok(())
            } else {
                Err("le service tourne mais n'est PAS activé au boot (`systemctl is-enabled \
                     plume-agent` ne rend pas 0) : il ne repartirait pas au redémarrage"
                    .into())
            }
        });
        Ok(r)
    }

    /// RETRAIT OBSERVÉ, pas annoncé. Chaque artefact est SONDÉ avant, agi, puis RE-SONDÉ : c'est la
    /// seconde observation qui autorise à écrire `Removed`. « best-effort » restait légitime pour
    /// l'ACTION (désactiver une unité déjà arrêtée n'est pas une erreur) ; ce qui ne l'était pas,
    /// c'est de conclure sans regarder.
    fn uninstall(&self) -> anyhow::Result<Outcome> {
        let mut r = Outcome::retrait();

        // 1. Le service tourne-t-il, ET est-il activé au boot ? État VOULU = ni l'un ni l'autre.
        //    Les DEUX sont sondés, parce que l'artefact dit les deux : une unité désactivée mais
        //    encore active, ou arrêtée mais toujours activée au boot, n'est pas « retirée ».
        let deja_arrete = !Self::is_active() && !Self::is_enabled();
        let _ = Command::new("systemctl").args(["disable", "--now", UNIT_NAME]).status();
        let nom = if deja_arrete {
            format!("service {UNIT_NAME}")
        } else {
            format!("service {UNIT_NAME} (arrêté et désactivé)")
        };
        r.observe(nom, deja_arrete, || match (Self::is_active(), Self::is_enabled()) {
            (false, false) => Ok(()),
            (true, _) => Err("toujours ACTIF après `systemctl disable --now` (droits root ? \
                              systemd injoignable ?)"
                .into()),
            (false, true) => Err("arrêté, mais TOUJOURS ACTIVÉ au boot : il repartira au \
                                  redémarrage (`systemctl is-enabled plume-agent`)"
                .into()),
        });

        // 2. L'unité est-elle sur le disque ? État VOULU = absente.
        let unit = std::path::Path::new(UNIT_PATH);
        let deja_absente = !unit.exists();
        let supprime = if deja_absente { Ok(()) } else { std::fs::remove_file(unit) };
        if !deja_absente {
            let _ = Command::new("systemctl").arg("daemon-reload").status();
        }
        r.observe(UNIT_PATH, deja_absente, || match supprime {
            Err(e) => Err(format!("{e} (root requis ?)")),
            Ok(()) if unit.exists() => Err("toujours présent après suppression".into()),
            Ok(()) => Ok(()),
        });
        Ok(r)
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

    /// PARITÉ : le bloc de durcissement RENDU depuis `HARDENING` est BYTE-IDENTIQUE au bloc littéral
    /// d'avant (v533dc0b). Si quelqu'un touche la table, ce test dit exactement ce qui a bougé — le
    /// passage à une table n'a pas le droit de changer une seule ligne de l'unité posée en production.
    #[test]
    fn bloc_durcissement_est_byte_identique() {
        const AVANT: &str = "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n\
             PrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n\
             ProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n\
             MemoryDenyWriteExecute=yes\nLockPersonality=yes\nSystemCallArchitectures=native\n\
             SystemCallFilter=@system-service\n";
        let rendu: String =
            HARDENING.iter().map(|(d, _)| format!("{d}\n")).collect::<Vec<_>>().join("");
        assert_eq!(rendu, AVANT);
        assert!(Systemd::unit_text(&spec()).contains(AVANT));
    }

    /// LA GARDE DÉRIVÉE. Un chemin est refusé PARCE QUE la table dit qu'une directive le masque —
    /// pas parce que quelqu'un a listé /home et /tmp dans un `if`. Mesuré le 2026-08-02 : sous
    /// `ProtectHome=yes` un exécutable de `$HOME` meurt en 203/EXEC, idem `/tmp` sous `PrivateTmp`.
    #[test]
    fn chemins_masques_par_le_durcissement_sont_refuses() {
        for (p, directive) in [
            ("/home/tech/plume/agent/target/release/plume-agent", "ProtectHome=yes"),
            ("/root/plume-agent", "ProtectHome=yes"),
            ("/tmp/plume-agent", "PrivateTmp=yes"),
            ("/var/tmp/plume-agent", "PrivateTmp=yes"),
        ] {
            let got = chemin_cache_par(Path::new(p), false);
            assert_eq!(got.map(|(d, _)| d), Some(directive), "{p} doit être refusé");
        }
        // Les chemins d'installation NORMAUX passent — sinon la garde serait inutilisable.
        for p in ["/usr/local/bin/plume-agent", "/etc/plume/agent.toml", "/var/lib/plume-agent/spool"] {
            assert_eq!(chemin_cache_par(Path::new(p), false), None, "{p} doit passer");
        }
        // Frontière de COMPOSANT : /homeless-clown n'est pas sous /home.
        assert_eq!(chemin_cache_par(Path::new("/homeless-clown/bin/plume-agent"), false), None);

        // RE-EXPOSITION PAR `ReadWritePaths=` — mesuré le 2026-08-02 : un chemin listé dans
        // ReadWritePaths échappe à ProtectHome (le service TOURNE) mais PAS à PrivateTmp
        // (226/NAMESPACE). La garde doit donc laisser passer un spool sous /home et refuser le
        // même spool sous /tmp — sans quoi elle interdirait un déploiement qui marche.
        assert_eq!(chemin_cache_par(Path::new("/home/soc/plume/spool"), true), None,
            "spool re-exposé par ReadWritePaths : ProtectHome ne le masque plus (mesuré)");
        assert_eq!(chemin_cache_par(Path::new("/tmp/plume/spool"), true).map(|(d, _)| d),
            Some("PrivateTmp=yes"),
            "PrivateTmp REMPLACE /tmp : ReadWritePaths n'y peut rien (mesuré, 226/NAMESPACE)");
    }

    /// TOUS les chemins de la spec sont couverts, pas seulement l'ExecStart : une config sous /home
    /// est illisible au service exactement comme le binaire, et un spool sous /tmp casse le
    /// namespace. `ServiceSpec::paths()` destructure exhaustivement -> un champ ajouté demain ne
    /// compile pas sans être classé.
    #[test]
    fn la_garde_couvre_tous_les_chemins_de_la_spec() {
        let s = ServiceSpec {
            exec_path: PathBuf::from("/usr/local/bin/plume-agent"),
            config_path: PathBuf::from("/home/tech/agent.toml"),
            spool_dir: PathBuf::from("/var/lib/plume-agent/spool"),
            state_dir: PathBuf::from("/var/lib/plume-agent/state"),
        };
        let refuses: Vec<&str> = s
            .paths()
            .iter()
            .filter(|(_, p, reexpose)| chemin_cache_par(p, *reexpose).is_some())
            .map(|(role, _, _)| *role)
            .collect();
        assert_eq!(refuses, vec!["--config (fichier de configuration)"]);
        assert_eq!(s.paths().len(), 4, "les 4 chemins de la spec sont vérifiés");
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
