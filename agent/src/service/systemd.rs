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
/// IL N'Y A QU'UNE FAÇON DE MASQUER — et AUCUNE directive de l'unité ne la défait. Ce bloc a porté
/// l'affirmation inverse, datée et donc crédible : « `ReadWritePaths=` RE-EXPOSE un chemin protégé
/// par `ProtectHome` ». RÉFUTÉ à la re-mesure du 2026-08-20 (systemd 261, unités transitoires, une
/// seule variable à la fois, témoin positif ET négatif) :
///   - `ExecStart` sous un répertoire personnel, sans protection             -> `0`, le service tourne ;
///   - le même + `ProtectHome=yes`                                          -> `203/EXEC` ;
///   - le même + `ReadWritePaths=` sur son répertoire, ou sur le fichier     -> `203/EXEC`, INCHANGÉ ;
///   - le même + `BindPaths=`, `BindReadOnlyPaths=` ou `ReadOnlyPaths=`      -> `203/EXEC`, INCHANGÉ ;
///   - `ExecStart` joignable + `ReadWritePaths=` sur un spool ainsi protégé  -> `0`, ET le service
///     lit « Permission denied » sur ce spool : AUCUNE panne au démarrage, une écriture impossible.
///
/// Vu du service, le répertoire personnel porte un dernier montage `tmpfs` sur
/// `/systemd/inaccessible/dir`, posé APRÈS les directives candidates : `ProtectHome=` REMPLACE le
/// point de montage, exactement comme `PrivateTmp=`. Les deux variantes qu'on distinguait n'en
/// faisaient donc qu'une, et la variante « re-exposable » est retirée faute de membre.
/// (`collectors/integrity.sh` mesurait déjà ce montage-là, et le LIT dans `/proc/self/mountinfo`
/// au lieu de le déduire d'un répertoire vide.)
///
/// CE QUE CETTE PROSE N'A PLUS LE DROIT DE PROMETTRE. Le dernier cas est le pire : rien n'échoue au
/// démarrage, et une sonde qui regarde l'unité tourner la déclare saine. Aucun commentaire ne peut
/// tenir une propriété pareille — `sonde_le_bac_a_sable` la MESURE, sur l'hôte, au moment où la
/// décision d'installer est prise. La table ci-dessous n'est plus qu'un refus CONSERVATEUR de ce
/// qu'on sait impossible, sans échappatoire ; c'est la mesure qui tranche le reste.
enum Masquage {
    /// Ne cache rien (lecture seule, filtres d'appels système, capacités…).
    Rien,
    /// REMPLACE ces points de montage par un répertoire vide : le chemin n'existe plus pour le
    /// service, et AUCUNE des quatre directives de re-exposition candidates ne le ramène (mesuré).
    Remplace(&'static [&'static str]),
}

const HARDENING: [(&str, Masquage); 13] = [
    ("NoNewPrivileges=yes", Masquage::Rien),
    ("ProtectSystem=strict", Masquage::Rien),
    ("ProtectHome=yes", Masquage::Remplace(&["/home", "/root", "/run/user"])),
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
/// responsable. Verdict SANS ÉCHAPPATOIRE : aucune autre directive de l'unité ne défait un masquage
/// de la table (mesuré, quatre candidates). Comparaison PAR COMPOSANTS (`Path::starts_with`) :
/// `/homeless-binary` n'est PAS sous `/home`.
///
/// CE QU'ELLE NE PEUT PAS SAVOIR — et ce qui le sait à sa place. Elle raisonne sur des préfixes
/// ÉCRITS ICI, pas sur le bac à sable réel de l'hôte : elle refuse ce qui est connu impossible, elle
/// ne CONFIRME rien. Un `None` ne veut donc pas dire « ce chemin est joignable », mais « la table
/// n'a pas de raison de le refuser » — la joignabilité, elle, se mesure (`sonde_le_bac_a_sable`).
pub fn chemin_cache_par(p: &Path) -> Option<(&'static str, &'static str)> {
    // Best-effort : les liens sont résolus quand c'est possible (un binaire lancé via un symlink de
    // /usr/local/bin vers /home reste, lui, sous /home du point de vue du noyau).
    let reel = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    for (directive, masquage) in HARDENING.iter() {
        let prefixes: &[&str] = match masquage {
            Masquage::Rien => &[],
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

/// LA DÉCISION DE PRÉ-VOL — extraite d'`install` pour être EXERÇABLE sans root ni systemd.
///
/// POURQUOI ELLE N'EST PAS RESTÉE DANS `install`. Le prédicat `chemin_cache_par` était testé, mais
/// la décision qui s'en sert, non : c'est là que l'allégation réfutée agissait, sous la forme d'un
/// argument passé au prédicat pour lui faire dire « non caché ». Un prédicat correct appelé avec une
/// échappatoire reste un défaut, et aucun test ne le voyait. Cette fonction met la décision à portée
/// de test ; `prevol_refuse_ce_qui_ne_pourrait_pas_demarrer` la ré-exerce sur les QUATRE chemins.
///
/// Elle refuse ce qui est connu impossible et ne CONFIRME rien : ce qu'elle laisse passer est ensuite
/// MESURÉ sur l'hôte par `sonde_le_bac_a_sable`.
pub fn prevol(spec: &ServiceSpec) -> Result<(), String> {
    for (role, p, _) in spec.paths() {
        if let Some((directive, prefixe)) = chemin_cache_par(p) {
            return Err(format!(
                "REFUS d'installer une unité qui ne pourrait pas fonctionner : {role} = {} est \
                 sous {prefixe}, dont l'unité elle-même REMPLACE le point de montage par un \
                 répertoire vide ({directive}) — le service n'y trouverait rien, et aucune \
                 directive de re-exposition ne l'en sort (mesuré le 2026-08-20, systemd 261, \
                 quatre candidates). Selon le rôle du chemin, cela se voit en 203/EXEC, en \
                 226/NAMESPACE, ou PAS DU TOUT — l'unité démarre et l'écriture est refusée \
                 ensuite. Place ce chemin hors de {prefixe} : le binaire dans /usr/local/bin \
                 (`sudo install -m0755 <bin> /usr/local/bin/plume-agent`), la config dans \
                 /etc/plume, le spool et l'état sous /var/lib/plume-agent.",
                p.display()
            ));
        }
    }
    Ok(())
}

/// L'unité TRANSITOIRE de la sonde — distincte de l'unité posée, et `--collect` la retire qu'elle
/// réussisse ou non : la mesure ne laisse rien derrière elle.
const UNITE_SONDE: &str = "plume-agent-sonde-bac-a-sable";

/// CE QUE LA MESURE SUR PLACE A RENDU. Trois issues, et la troisième n'est PAS un succès.
pub enum Sonde {
    /// MESURÉ : depuis le bac à sable de l'unité, tous les chemins de la spec sont utilisables.
    Utilisables,
    /// MESURÉ : le chemin de cet indice dans `spec.paths()` ne l'est pas.
    Inutilisable(usize),
    /// La mesure n'a PAS pu être faite, avec sa raison. Refuser de conclure et le dire — une sonde
    /// muette qu'on lirait comme un feu vert serait exactement le défaut que cette sonde corrige.
    PasDeMesure(String),
}

/// LA COMMANDE DE LA SONDE — CONSTRUITE depuis les mêmes sources que l'unité, jamais écrite à la
/// main (pure, donc testable sans systemd). Elle rejoue le bac à sable de l'unité — MÊME table
/// `HARDENING`, MÊME `ReadWritePaths=` — et y fait exécuter un `test(1)` par chemin de la spec, avec
/// le mode d'accès que ce chemin exige. Une directive ajoutée à la table entre donc dans la mesure
/// sans que personne y pense, et un chemin ajouté à `ServiceSpec` aussi.
///
/// LE SCRIPT REND UN INDICE, PAS UN TEXTE : rien à citer, donc aucune question de quoting, et les
/// chemins passent en ARGUMENTS (`$1`…) plutôt que dans le corps du script — un chemin avec un
/// espace, une apostrophe ou un `$` ne peut pas changer ce qui est exécuté.
fn commande_de_sonde(spec: &ServiceSpec) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--wait".into(),
        "--quiet".into(),
        "--collect".into(),
        "--pipe".into(),
        format!("--unit={UNITE_SONDE}"),
    ];
    for (directive, _) in HARDENING.iter() {
        args.push(format!("--property={directive}"));
    }
    args.push(format!(
        "--property=ReadWritePaths={} {}",
        spec.spool_dir.display(),
        spec.state_dir.display()
    ));
    let chemins = spec.paths();
    let mut script = String::new();
    for (i, (_, _, acces)) in chemins.iter().enumerate() {
        script.push_str(&format!(
            "test {} \"${}\" || {{ echo {}; exit 1; }}; ",
            acces.test_posix(),
            i + 1,
            i + 1
        ));
    }
    script.push_str("exit 0");
    args.push("/bin/sh".into());
    args.push("-c".into());
    args.push(script);
    args.push("sonde-plume-agent".into()); // $0 du script
    for (_, p, _) in chemins {
        args.push(p.display().to_string());
    }
    args
}

/// LA VÉRIFICATION SUR PLACE — la seule chose qui puisse tenir une propriété de bac à sable.
///
/// POURQUOI ELLE EXISTE, ET CE QUE LA GARDE DE PRÉFIXES NE VOIT PAS. Mesuré le 2026-08-20 : une
/// unité dont le spool est sous un répertoire personnel protégé DÉMARRE — `ExecMainStatus=0`, aucun
/// `203/EXEC`, aucun `226/NAMESPACE` — et le service reçoit « Permission denied » à la première
/// écriture. Ni le code de retour de `systemctl`, ni l'observation du service en train de tourner,
/// ni une table de préfixes écrite d'avance ne peuvent attraper cela : il faut EXÉCUTER quelque
/// chose dans le bac à sable et regarder. C'est ce que fait cette fonction, à l'instant où la
/// décision d'installer est prise, sur l'hôte où elle est prise.
pub fn sonde_le_bac_a_sable(spec: &ServiceSpec) -> Sonde {
    let sortie = match Command::new("systemd-run").args(commande_de_sonde(spec)).output() {
        Ok(o) => o,
        Err(e) => return Sonde::PasDeMesure(format!("`systemd-run` n'a pas pu être lancé : {e}")),
    };
    if sortie.status.success() {
        return Sonde::Utilisables;
    }
    // Le script rend l'indice (1-based) du premier chemin inutilisable. TOUTE autre sortie signifie
    // que la sonde elle-même n'a pas tourné (bus injoignable, systemd-run trop ancien, unité déjà
    // là) : cela ne se lit pas comme un verdict sur les chemins.
    let dit = String::from_utf8_lossy(&sortie.stdout).trim().to_string();
    match dit.parse::<usize>() {
        Ok(i) if (1..=spec.paths().len()).contains(&i) => Sonde::Inutilisable(i - 1),
        _ => Sonde::PasDeMesure(format!(
            "`systemd-run` a rendu {:?} sans désigner de chemin ({})",
            sortie.status.code(),
            {
                let err = String::from_utf8_lossy(&sortie.stderr).trim().to_string();
                if err.is_empty() { format!("sortie standard : {dit:?}") } else { err }
            }
        )),
    }
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
    /// 1. PRÉ-VOL EN DEUX TEMPS, et le second est une MESURE. (a) La table refuse ce qu'on sait
    ///    impossible d'avance — un chemin de la spec sous un point de montage que le durcissement de
    ///    cette même unité remplace. (b) Puis, une fois spool et état créés, le bac à sable de
    ///    l'unité est RÉELLEMENT monté (`sonde_le_bac_a_sable`) et l'on regarde si le service peut
    ///    se servir de chaque chemin. Le (b) existe parce que le (a) ne peut pas tout voir : il
    ///    raisonne sur des préfixes écrits d'avance, alors que le bac à sable réel dépend de l'hôte —
    ///    et le pire cas mesuré (spool protégé, unité qui DÉMARRE, écriture refusée ensuite) ne
    ///    produit aucun code d'erreur à observer. AUCUNE unité n'est écrite tant que les deux n'ont
    ///    pas conclu, et le message dit quoi faire. (Le fichier de config, lui, a pu être généré plus
    ///    tôt par `cmd_install --endpoint` : c'est écrit ici pour qu'on ne lise pas « rien n'est
    ///    écrit ».) C'est ce que le README demandait à l'humain de vérifier à la main.
    /// 2. Chaque artefact est SONDÉ avant, agi, puis RE-SONDÉ (cf. `Outcome`) : le service n'est dit
    ///    « posé » que si `tourne_vraiment()` l'a vu actif ET STABLE, et `is_enabled()` activé.
    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<Outcome> {
        // 1a. PRÉ-VOL dérivé de HARDENING × ServiceSpec::paths() (destructuration exhaustive).
        if let Err(refus) = prevol(spec) {
            anyhow::bail!("{refus}");
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

        // 1b. LA MESURE SUR PLACE — après les répertoires (`test -w` exige qu'ils existent) et AVANT
        //     d'écrire l'unité. Elle monte le bac à sable de l'unité pour de vrai et regarde.
        match sonde_le_bac_a_sable(spec) {
            Sonde::Utilisables => {}
            Sonde::Inutilisable(i) => {
                let (role, p, acces) = spec.paths().swap_remove(i);
                anyhow::bail!(
                    "REFUS d'installer une unité qui ne pourrait pas fonctionner : MESURÉ à \
                     l'instant, depuis le bac à sable que cette unité impose, {role} = {} n'est pas \
                     utilisable en `test {}`. Le durcissement de l'unité et ce chemin se \
                     contredisent sur cet hôte. Selon le rôle, le service mourrait en 203/EXEC, en \
                     226/NAMESPACE — ou DÉMARRERAIT en échouant à la première écriture, sans rien \
                     signaler. Chemins sûrs : binaire dans /usr/local/bin, config dans /etc/plume, \
                     spool et état sous /var/lib/plume-agent.",
                    p.display(),
                    acces.test_posix()
                );
            }
            // Ni un feu vert ni un motif de refus : la mesure n'a pas eu lieu, et le dire est la
            // seule chose honnête. L'installation se poursuit sur la garde de préfixes seule —
            // c'est-à-dire sur strictement ce qui existait avant cette sonde, sans le prétendre
            // vérifié.
            Sonde::PasDeMesure(raison) => eprintln!(
                "plume-agent: AVERTISSEMENT — la vérification sur place du bac à sable n'a PAS pu \
                 être faite ({raison}). Les chemins n'ont donc PAS été mesurés depuis l'intérieur \
                 de l'unité : seule la garde de préfixes a statué. Après `install`, vérifier que le \
                 service écrit bien dans son spool (`journalctl -u {UNIT_NAME} -n 20`)."
            ),
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
    /// pas parce que quelqu'un a listé /home et /tmp dans un `if`. Mesuré le 2026-08-20 (systemd
    /// 261) : sous `ProtectHome=yes` un exécutable d'un répertoire personnel meurt en 203/EXEC,
    /// idem `/tmp` sous `PrivateTmp`.
    #[test]
    fn chemins_masques_par_le_durcissement_sont_refuses() {
        for (p, directive) in [
            ("/home/tech/plume/agent/target/release/plume-agent", "ProtectHome=yes"),
            ("/root/plume-agent", "ProtectHome=yes"),
            ("/tmp/plume-agent", "PrivateTmp=yes"),
            ("/var/tmp/plume-agent", "PrivateTmp=yes"),
        ] {
            let got = chemin_cache_par(Path::new(p));
            assert_eq!(got.map(|(d, _)| d), Some(directive), "{p} doit être refusé");
        }
        // TÉMOIN — les chemins d'installation NORMAUX passent. Une garde qui refuse tout n'est pas
        // une garde : sans cette moitié, le test resterait vert sur un `Some` inconditionnel.
        for p in ["/usr/local/bin/plume-agent", "/etc/plume/agent.toml", "/var/lib/plume-agent/spool"] {
            assert_eq!(chemin_cache_par(Path::new(p)), None, "{p} doit passer");
        }
        // Frontière de COMPOSANT : /homeless-clown n'est pas sous /home.
        assert_eq!(chemin_cache_par(Path::new("/homeless-clown/bin/plume-agent")), None);
    }

    /// L'ALLÉGATION RÉFUTÉE, FIGÉE PAR UN TEST — c'est-à-dire la mutation qui a produit le défaut.
    ///
    /// La garde a laissé passer, pendant tout le temps où ce commentaire a été cru, un spool ou un
    /// état sous un répertoire personnel : la table portait une échappatoire (« ce chemin est dans
    /// `ReadWritePaths=`, donc `ProtectHome` ne le concerne plus »), affirmée en prose avec sa date.
    /// RE-MESURÉ le 2026-08-20, systemd 261 : la re-exposition n'a PAS lieu — le service reçoit
    /// « Permission denied » sur ce spool, et l'unité DÉMARRE quand même. Ré-introduire
    /// l'échappatoire fait échouer ce test-ci, en nommant le chemin qu'elle laisserait passer.
    #[test]
    fn aucun_chemin_de_donnees_n_echappe_a_protecthome() {
        for p in ["/home/soc/plume/spool", "/root/plume/state", "/run/user/1000/plume/spool"] {
            assert_eq!(
                chemin_cache_par(Path::new(p)).map(|(d, _)| d),
                Some("ProtectHome=yes"),
                "{p} : AUCUNE directive de l'unité ne re-expose un chemin ainsi protégé (mesuré le \
                 2026-08-20 sur systemd 261 : ReadWritePaths=, BindPaths=, BindReadOnlyPaths= et \
                 ReadOnlyPaths= laissent le montage inaccessible en place). Un spool laissé passer \
                 ici produit une unité qui DÉMARRE et n'écrit rien."
            );
        }
    }

    /// TOUS les chemins de la spec sont couverts, pas seulement l'ExecStart : une config sous un
    /// répertoire personnel est illisible au service exactement comme le binaire, et un spool sous
    /// /tmp casse le namespace. `ServiceSpec::paths()` destructure exhaustivement -> un champ ajouté
    /// demain ne compile pas sans être classé.
    #[test]
    fn la_garde_couvre_tous_les_chemins_de_la_spec() {
        let s = ServiceSpec {
            exec_path: PathBuf::from("/usr/local/bin/plume-agent"),
            config_path: PathBuf::from("/home/tech/agent.toml"),
            spool_dir: PathBuf::from("/var/lib/plume-agent/spool"),
            state_dir: PathBuf::from("/home/tech/plume/state"),
        };
        let refuses: Vec<&str> = s
            .paths()
            .iter()
            .filter(|(_, p, _)| chemin_cache_par(p).is_some())
            .map(|(role, _, _)| *role)
            .collect();
        // Le state_dir est dans la liste : c'est EXACTEMENT ce que l'échappatoire laissait passer.
        assert_eq!(refuses, vec!["--config (fichier de configuration)", "state_dir"]);
        assert_eq!(s.paths().len(), 4, "les 4 chemins de la spec sont vérifiés");
        // TÉMOIN : la même spec, chemins conventionnels -> plus rien n'est refusé.
        assert!(
            spec().paths().iter().all(|(_, p, _)| chemin_cache_par(p).is_none()),
            "une spec conventionnelle doit rester installable"
        );
    }

    /// LA DÉCISION, PAS SEULEMENT LE PRÉDICAT. C'est ici que l'allégation réfutée agissait : le
    /// prédicat était juste, et la décision lui passait de quoi rendre « non caché ». Chacun des
    /// QUATRE chemins de la spec est donc ré-exercé à travers `prevol`, et le refus doit NOMMER le
    /// rôle fautif — un refus qui ne dit pas lequel n'aide personne à corriger.
    ///
    /// TÉMOIN : la spec conventionnelle passe. Sans lui, un `prevol` qui refuserait tout serait vert.
    #[test]
    fn prevol_refuse_ce_qui_ne_pourrait_pas_demarrer() {
        assert!(prevol(&spec()).is_ok(), "une spec conventionnelle doit rester installable");
        for (role, deplace) in [
            ("ExecStart (binaire de l'agent)", 0usize),
            ("--config (fichier de configuration)", 1),
            ("spool_dir", 2),
            ("state_dir", 3),
        ] {
            let mut s = spec();
            // Le MÊME chemin protégé pour les quatre rôles : seul le rôle change d'un cas à l'autre.
            let sous_home = PathBuf::from("/home/soc/plume-agent");
            match deplace {
                0 => s.exec_path = sous_home,
                1 => s.config_path = sous_home,
                2 => s.spool_dir = sous_home,
                _ => s.state_dir = sous_home,
            }
            // `expect_err` prendrait un littéral : le rôle n'y serait PAS interpolé, et l'échec ne
            // nommerait pas le chemin laissé passer. Le `match` le nomme.
            let refus = match prevol(&s) {
                Err(m) => m,
                Ok(()) => panic!(
                    "{role} sous un répertoire personnel a été ACCEPTÉ : l'unité démarrerait sans \
                     pouvoir s'en servir"
                ),
            };
            assert!(refus.contains(role), "le refus doit nommer {role} — lu : {refus}");
            assert!(refus.contains("/home"), "le refus doit nommer le préfixe fautif");
        }
    }

    /// LA MESURE SUR PLACE EST DÉRIVÉE, pas écrite à la main. La commande de la sonde doit porter
    /// TOUTE la table de durcissement (sinon elle mesure un autre bac à sable que celui de l'unité),
    /// le `ReadWritePaths=` de l'unité, et UN `test(1)` par chemin de la spec avec le mode d'accès
    /// que ce chemin exige. Retirer une directive de la sonde, ou oublier un chemin, fait échouer
    /// ici — c'est ce qui empêche la sonde de dériver silencieusement de l'unité qu'elle imite.
    #[test]
    fn la_sonde_rejoue_le_bac_a_sable_de_l_unite() {
        let s = spec();
        let cmd = commande_de_sonde(&s);
        for (directive, _) in HARDENING.iter() {
            assert!(
                cmd.iter().any(|a| a == &format!("--property={directive}")),
                "la sonde doit imposer {directive} comme l'unité le fait"
            );
        }
        assert!(cmd.iter().any(|a| a
            == "--property=ReadWritePaths=/var/lib/plume-agent/spool /var/lib/plume-agent/state"));
        let script = cmd.iter().find(|a| a.starts_with("test ")).expect("script de la sonde");
        assert_eq!(script.matches("test ").count(), s.paths().len(), "un test par chemin");
        assert!(script.contains("test -x \"$1\""), "l'ExecStart se teste en exécutable");
        assert!(script.contains("test -r \"$2\""), "la config se teste en lecture");
        assert!(script.contains("test -w \"$3\"") && script.contains("test -w \"$4\""));
        // Les chemins passent en ARGUMENTS, jamais dans le corps du script : rien à échapper.
        for (_, p, _) in s.paths() {
            let t = p.display().to_string();
            assert!(cmd.contains(&t), "{t} doit être un argument");
            assert!(!script.contains(&t), "{t} n'a rien à faire dans le corps du script");
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

