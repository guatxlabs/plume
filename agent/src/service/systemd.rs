//! Service systemd (Linux) — PLEINEMENT implémenté.
//!
//! Écrit /etc/systemd/system/plume-agent.service (unité durcie, alignée sur le durcissement des
//! collecteurs Plume : DynamicUser off — on tourne en root pour lire journald/Security, mais Protect*/
//! NoNewPrivileges/SystemCallFilter réduisent la surface), crée les répertoires, `daemon-reload`,
//! `enable --now`. `uninstall` : `disable --now` + suppression de l'unité + reload. Nécessite root.

use super::{interrogation, Constat, Outcome, ServiceManager, ServiceSpec};
use crate::lisibilite::Lecture;
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
    // La résolution des liens est BEST-EFFORT, et son échec est un CAS, pas un silence : il est
    // rendu explicite en `None` et la fonction paramétrée ci-dessous en décide.
    chemin_cache_par_avec(p, std::fs::canonicalize(p).ok().as_deref())
}

/// LA MÊME DÉCISION, PARAMÉTRÉE SUR SA SECONDE SOURCE — le chemin RÉSOLU, ou `None` quand la
/// résolution n'a pas abouti. La suite exerce donc les deux cas sans dépendre de l'arborescence de la
/// machine qui l'exécute, ce qu'une fonction appelant `canonicalize` en dur ne pouvait faire dans
/// aucun cas (elle aurait fallu créer un lien sous un préfixe réellement masqué de CET hôte-là).
pub fn chemin_cache_par_avec(p: &Path, resolu: Option<&Path>) -> Option<(&'static str, &'static str)> {
    // DEUX chemins sont confrontés à la table, et c'est délibéré :
    //  - le chemin LITTÉRAL, parce que c'est lui que l'unité écrit dans `ExecStart=` / `ReadWritePaths=`
    //    et que c'est lui que le service ouvre depuis son bac à sable — un lien placé SOUS un préfixe
    //    masqué est inatteignable même quand sa cible, elle, ne l'est pas ;
    //  - le chemin RÉSOLU quand la résolution aboutit, parce qu'un lien de /usr/local/bin vers un
    //    répertoire personnel reste, lui, sous ce répertoire du point de vue du noyau.
    // UNE RÉSOLUTION QUI ÉCHOUE NE VAUT PLUS « RÉSOLU, RIEN À REDIRE » (`S36`) : elle échouait en
    // particulier quand le chemin n'existe PAS ENCORE — spool et état sont créés plus tard, c'est le
    // cas NORMAL — et son échec retombait sur le seul littéral sans que rien ne le dise. Le littéral
    // est désormais confronté DANS TOUS LES CAS ; ce qui reste perdu quand la résolution échoue est
    // nommé : la cible d'un lien qu'on n'a pas su suivre. C'est la mesure sur place qui la voit
    // (`sonde_le_bac_a_sable`), et un `None` ne dit toujours pas « joignable ».
    let mut candidats: Vec<&Path> = vec![p];
    if let Some(reel) = resolu {
        if reel != p {
            candidats.push(reel);
        }
    }
    for (directive, masquage) in HARDENING.iter() {
        let prefixes: &[&str] = match masquage {
            Masquage::Rien => &[],
            Masquage::Remplace(pfx) => pfx,
        };
        for c in prefixes {
            if candidats.iter().any(|cand| cand.starts_with(c)) {
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

/// CE QUE LES LECTURES D'ÉTAT AUTORISENT À FAIRE — la décision de démarrage, EXTRAITE d'`install`
/// pour être EXERÇABLE sans root ni systemd, exactement comme `prevol` l'a été avant elle.
///
/// POURQUOI ELLE N'EST PAS RESTÉE DANS `install` (`S36`). C'est là que le défaut AGISSAIT : trois
/// interrogations dont l'échec valait `false` / `0`, et une branche — `enable --now` ou `restart` —
/// choisie sur ces valeurs-là. Un prédicat correct nourri d'une lecture qui n'a pas eu lieu reste un
/// défaut, et aucun test ne pouvait le voir tant que la décision vivait au milieu des `Command`.
#[derive(Debug)]
pub enum Demarrage {
    /// LES TROIS LECTURES ONT ABOUTI : de quoi choisir la branche, et rien qui soit supposé.
    Decidable { tournait: bool, active_au_boot: bool, restarts_avant: u32 },
    /// UNE LECTURE N'A PAS ABOUTI : on ne démarre RIEN. Le constat porte l'aveu, et le texte dit ce
    /// qu'agir à l'aveugle coûterait.
    Refus(Constat, String),
}

/// LA DÉCISION, DÉRIVÉE DES TROIS LECTURES — pure, donc testable dans les deux sens.
pub fn decision_de_demarrage(
    actif: Lecture<bool>,
    au_boot: Lecture<bool>,
    restarts: Lecture<u32>,
) -> Demarrage {
    match (&actif, &au_boot, &restarts) {
        (Lecture::Lue(a), Lecture::Lue(b), Lecture::Lue(n)) => {
            Demarrage::Decidable { tournait: *a, active_au_boot: *b, restarts_avant: *n }
        }
        (a, b, n) => {
            let constat = Constat::premier_aveu([
                Constat::depuis_aveu(a),
                Constat::depuis_aveu(b),
                Constat::depuis_aveu(n),
            ])
            // Ce bras n'est atteint que si l'une des trois lectures a échoué : `premier_aveu` en rend
            // donc toujours un. Le second membre n'est pas un repli rassurant — il refuse lui aussi.
            .unwrap_or(Constat::NonObserve {
                cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
                detail: "interrogation du gestionnaire de services sans verdict".to_string(),
            });
            let raison = format!(
                "l'état du service n'a PAS pu être interrogé ({}) — AUCUN démarrage n'a été tenté. \
                 `systemctl enable --now` ne redémarre PAS un service déjà actif : agir sans cette \
                 lecture laisserait tourner le processus de l'ANCIENNE unité pendant que ce rapport \
                 annoncerait « posé ». L'unité est écrite sur le disque ; relancer `plume-agent \
                 install` une fois le gestionnaire de services joignable.",
                constat.aveu_dit()
            );
            Demarrage::Refus(constat, raison)
        }
    }
}

/// LE CONSTAT ANTÉRIEUR D'UN RETRAIT, dérivé des deux lectures — extrait pour la même raison.
/// L'état VOULU du retrait est « ni actif, ni activé au boot » : il exige donc que les DEUX aient
/// été lues. Une seule qui manque, et il n'y a pas de constat à faire.
pub fn constat_de_retrait(actif: &Lecture<bool>, au_boot: &Lecture<bool>) -> Constat {
    match (actif, au_boot) {
        (Lecture::Lue(a), Lecture::Lue(b)) => Constat::mesure(!a && !b),
        (a, b) => Constat::premier_aveu([Constat::depuis_aveu(a), Constat::depuis_aveu(b)])
            .unwrap_or(Constat::NonObserve {
                cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
                detail: "interrogation du gestionnaire de services sans verdict".to_string(),
            }),
    }
}

/// LA RE-SONDE DU RETRAIT, dérivée des deux lectures d'APRÈS l'action. C'est elle qui autorise — ou
/// non — à écrire « retiré » : un `Ok(())` n'est rendu que sur DEUX lectures qui ont abouti et qui
/// disent toutes deux « non ».
pub fn verdict_de_retrait(actif: &Lecture<bool>, au_boot: &Lecture<bool>) -> Result<(), String> {
    match (actif, au_boot) {
        (Lecture::Lue(false), Lecture::Lue(false)) => Ok(()),
        (Lecture::Lue(true), _) => Err("toujours ACTIF après `systemctl disable --now` (droits \
                                        root ? systemd injoignable ?)"
            .into()),
        (Lecture::Lue(false), Lecture::Lue(true)) => {
            Err("arrêté, mais TOUJOURS ACTIVÉ au boot : il repartira au redémarrage \
                 (`systemctl is-enabled plume-agent`)"
                .into())
        }
        (a, b) => Err(format!(
            "l'état du service n'a PAS pu être interrogé après `systemctl disable --now` ({}) — RIEN \
             n'est affirmé sur ce qui reste installé sur cet hôte : ce retrait n'est PAS constaté. \
             Vérifier `systemctl is-active {UNIT_NAME}` et `systemctl is-enabled {UNIT_NAME}` une \
             fois le gestionnaire de services joignable.",
            Constat::premier_aveu([Constat::depuis_aveu(a), Constat::depuis_aveu(b)])
                .map(|c| c.aveu_dit())
                .unwrap_or_else(|| "verdict manquant".to_string())
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

    /// L'unité est-elle ACTIVE — LUE, ou AVOUÉE (`S36`).
    ///
    /// CE QUI ÉTAIT ÉCRIT ICI, ET POURQUOI C'ÉTAIT FAUX. « Une erreur d'exécution (systemd
    /// injoignable) est traitée comme "pas actif" — et c'est sans risque ici, parce que le retrait
    /// RE-SONDE et ne conclut jamais sans preuve. » La re-sonde appelait CETTE MÊME fonction : elle
    /// rendait donc le même « pas actif », et le retrait concluait « rien à retirer », code de sortie
    /// nul, sur un hôte où le service pouvait parfaitement tourner. Une re-sonde n'est une preuve que
    /// si elle sait dire qu'elle n'a rien pu mesurer.
    ///
    /// `--quiet` EST RETIRÉ, ET C'EST LE CŒUR DU CORRECTIF : c'est le MOT qui porte la mesure, pas le
    /// code de retour (cf. `interrogation`). Mesuré le 2026-08-21 (systemd 261) : sur une unité
    /// ABSENTE, `is-active` sort **4** en disant `inactive` — une réponse ; gestionnaire injoignable,
    /// il sort **1** sans un mot — pas une réponse. Avec `--quiet` les deux étaient indiscernables.
    fn est_actif() -> Lecture<bool> {
        interrogation::oui_non(
            match Command::new("systemctl").args(["is-active", UNIT_NAME]).output() {
                Err(e) => interrogation::pas_lance("systemctl is-active", &e),
                Ok(o) => interrogation::verdict_de_mot(
                    "systemctl is-active",
                    o.status.code(),
                    &o.stdout,
                    &o.stderr,
                    &MOTS_IS_ACTIVE,
                ),
            },
        )
    }

    fn systemctl(args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("systemctl").args(args).status()?;
        if !status.success() {
            anyhow::bail!("systemctl {:?} a échoué (code {:?})", args, status.code());
        }
        Ok(())
    }

    /// PROPRIÉTÉS D'UNITÉ — LUES, ou AVOUÉES (`S36`). C'est LE site cité par la campagne :
    /// « `systemctl show` en échec -> "pas en échec" ».
    ///
    /// L'ANCIENNE FORME rendait une table VIDE sur un échec de lancement, et n'ouvrait JAMAIS le code
    /// de retour. Un gestionnaire injoignable produisait donc exactement ce que produit un
    /// gestionnaire muet : rien. L'appelant lisait `ActiveState` absent, en faisait `""` par
    /// `unwrap_or("")`, et son prédicat d'échec — qui cherche `failed` ou `auto-restart` — ne pouvait
    /// plus tirer : un service en boucle de redémarrage passait pour « pas en échec ». L'échec de la
    /// mesure devenait le verdict le plus rassurant.
    ///
    /// Mesuré le 2026-08-21 (systemd 261) : sur une unité ABSENTE, `show -p …` sort **0** et imprime
    /// TOUTES les clés demandées (`LoadState=not-found`, `UnitFileState=`) — une mesure, valeurs
    /// vides comprises ; gestionnaire injoignable, il sort non nul SANS une seule ligne.
    fn proprietes(props: &[&str]) -> Lecture<std::collections::HashMap<String, String>> {
        let mut cmd = Command::new("systemctl");
        cmd.arg("show");
        for p in props {
            cmd.arg("-p").arg(p);
        }
        cmd.arg(UNIT_NAME);
        match cmd.output() {
            Err(e) => interrogation::pas_lance("systemctl show", &e),
            Ok(o) => interrogation::proprietes(
                "systemctl show",
                o.status.code(),
                &o.stdout,
                &o.stderr,
                props,
            ),
        }
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
        const PROPS: [&str; 5] =
            ["ActiveState", "SubState", "Result", "ExecMainStatus", "NRestarts"];
        let debut = std::time::Instant::now();
        let mut stable_depuis: Option<std::time::Instant> = None;
        let mut dernier;
        loop {
            // UNE INTERROGATION QUI N'ABOUTIT PAS ARRÊTE LA MESURE, elle ne la traverse pas (`S36`).
            // L'ancienne forme recevait une table VIDE et continuait : le prédicat d'échec ci-dessous
            // ne pouvait plus tirer, et la boucle rendait au bout du budget « le service n'a pas tenu
            // 2,5 s d'affilée », c'est-à-dire un diagnostic sur un service qu'elle n'avait jamais
            // regardé. On ne patiente pas non plus : `enable --now` vient de réussir, donc le
            // gestionnaire répondait il y a un instant ; s'il ne répond plus, c'est un fait à dire.
            let p = match Self::proprietes(&PROPS) {
                Lecture::Lue(p) => p,
                Lecture::Illisible { cause, detail } => {
                    return Err(format!(
                        "l'état du service n'a PAS pu être interrogé après `systemctl enable --now` \
                         ({cause} : {detail}) — RIEN n'est conclu sur ce service : « aucun échec \
                         observé » et « rien observé » ne sont pas le même verdict. \
                         `journalctl -u {UNIT_NAME} -n 20` une fois le gestionnaire joignable."
                    ))
                }
            };
            // AUCUN REPLI ICI : une propriété absente est une lecture qui a échoué, pas une valeur
            // vide. `Self::proprietes` la refuse déjà ; ce second filet ne rend pas de valeur non plus.
            let champ = |k: &str| -> Result<&str, String> {
                p.get(k).map(String::as_str).ok_or_else(|| {
                    format!("`systemctl show` a répondu sans {k} : l'état du service n'a pas été établi")
                })
            };
            let actif = champ("ActiveState")?;
            let sub = champ("SubState")?;
            let res = champ("Result")?;
            let code = champ("ExecMainStatus")?;
            let restarts = champ("NRestarts")?;
            dernier = format!(
                "ActiveState={actif} SubState={sub} Result={res} ExecMainStatus={code} NRestarts={restarts}"
            );
            // Un `NRestarts` non numérique est une FORME qu'on ne comprend pas ; l'ancien `unwrap_or(0)`
            // en faisait zéro, c'est-à-dire « aucun redémarrage », c'est-à-dire le côté rassurant du
            // comparateur : la boucle de redémarrage ne pouvait plus être détectée.
            let restarts_lus: u32 = restarts.parse().map_err(|_| {
                format!(
                    "`systemctl show` a rendu NRestarts={restarts:?}, qui n'est pas un compteur — le \
                     redémarrage en boucle ne peut pas être mesuré, donc il n'est pas exclu"
                )
            })?;
            let echec = matches!((actif, sub), ("failed", _) | (_, "auto-restart") | (_, "failed"))
                || restarts_lus > restarts_avant;
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

    /// LE COMPTEUR DE REDÉMARRAGES, LU OU AVOUÉ. Il sert de RÉFÉRENCE : c'est son augmentation
    /// pendant la fenêtre d'observation qui trahit une boucle, pas sa valeur (cf. `tourne_vraiment`).
    /// Une référence qu'on n'a pas su lire ne vaut donc PAS zéro : zéro est la valeur qui rend le
    /// comparateur le plus SÉVÈRE au tour suivant, et surtout elle prétend savoir.
    fn nombre_de_redemarrages() -> Lecture<u32> {
        match Self::proprietes(&["NRestarts"]) {
            Lecture::Illisible { cause, detail } => Lecture::Illisible { cause, detail },
            Lecture::Lue(p) => match p.get("NRestarts").map(|v| v.trim().parse::<u32>()) {
                Some(Ok(n)) => Lecture::Lue(n),
                autre => Lecture::Illisible {
                    cause: crate::lisibilite::CAUSE_FORME_INCONNUE,
                    detail: format!(
                        "`systemctl show` a rendu un NRestarts qui n'est pas un compteur ({autre:?})"
                    ),
                },
            },
        }
    }

    /// L'unité est-elle ACTIVÉE AU BOOT — LUE, ou AVOUÉE. Observation distincte de `est_actif` : un
    /// service lancé à la main mais non activé redémarrerait muet au prochain boot, et l'artefact que
    /// l'on nomme « actif AU BOOT et maintenant » n'a pas le droit de l'affirmer sans l'avoir regardé
    /// — ni de l'INFIRMER sans l'avoir regardé, ce que le repli faisait.
    fn est_active_au_boot() -> Lecture<bool> {
        interrogation::oui_non(
            match Command::new("systemctl").args(["is-enabled", UNIT_NAME]).output() {
                Err(e) => interrogation::pas_lance("systemctl is-enabled", &e),
                Ok(o) => interrogation::verdict_de_mot(
                    "systemctl is-enabled",
                    o.status.code(),
                    &o.stdout,
                    &o.stderr,
                    &MOTS_IS_ENABLED,
                ),
            },
        )
    }
}

/// LE VOCABULAIRE FERMÉ DE `systemctl is-active`, et ce que chaque mot VAUT pour « le service
/// tourne-t-il ». Les valeurs reproduisent le code de retour documenté de la commande (0 pour
/// `active`, `reloading` et `refreshing`), à ceci près qu'ici c'est le MOT qui est lu : le code de
/// retour, lui, vaut aussi non-nul quand la commande n'a rien pu mesurer.
const MOTS_IS_ACTIVE: [(&str, bool); 8] = [
    ("active", true),
    ("reloading", true),
    ("refreshing", true),
    ("activating", false),
    ("deactivating", false),
    ("inactive", false),
    ("failed", false),
    ("maintenance", false),
];

/// LE VOCABULAIRE FERMÉ DE `systemctl is-enabled`, et ce que chaque mot VAUT pour « repartira-t-il au
/// prochain démarrage ». Les valeurs reproduisent le code de retour documenté de la commande.
///
/// POURQUOI CETTE QUESTION N'EST PAS DÉRIVÉE DE `systemctl show`, alors qu'une interrogation de moins
/// serait tentante : MESURÉ le 2026-08-21 (systemd 261) sur une unité du système, `is-enabled` rend
/// `alias` — donc ACTIVÉ, code 0 — pendant que `UnitFileState` vaut `disabled`. Les deux ne répondent
/// pas à la même question, et la fondre aurait remplacé un repli commode par une équivalence fausse.
const MOTS_IS_ENABLED: [(&str, bool); 14] = [
    ("enabled", true),
    ("enabled-runtime", true),
    ("alias", true),
    ("static", true),
    ("indirect", true),
    ("generated", true),
    ("transient", true),
    ("linked", false),
    ("linked-runtime", false),
    ("masked", false),
    ("masked-runtime", false),
    ("disabled", false),
    ("not-found", false),
    ("bad", false),
];

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
            r.observe(format!("répertoire {}", d.display()), Constat::mesure(existait), || match res {
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
        r.observe(UNIT_PATH, Constat::mesure(deja), || match ecrit {
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
        //
        // LES TROIS LECTURES DONT DÉPEND LA DÉCISION SONT PRISES ENSEMBLE ET AVANT D'AGIR (`S36`).
        // Si l'une n'aboutit pas, AUCUNE commande de démarrage n'est lancée : le choix entre
        // `enable --now` et `restart` se fait sur « le service tourne-t-il déjà », et se tromper là
        // ne produit pas un angle mort — cela laisse vivre le processus de l'ANCIENNE unité pendant
        // que ce rapport dirait « posé ». Un verdict « je n'ai pas pu interroger » n'est pas « tout
        // va bien » : ici, il REFUSE d'agir plutôt que d'agir sur un état supposé.
        let artefact = format!("service {UNIT_NAME} (actif au boot et maintenant)");
        // Valeur de RÉFÉRENCE du compteur de redémarrages : c'est son AUGMENTATION pendant notre
        // fenêtre qui trahit une boucle, pas sa valeur (cf. `tourne_vraiment`).
        let (tournait, etait_active_au_boot, restarts_avant) = match decision_de_demarrage(
            Self::est_actif(),
            Self::est_active_au_boot(),
            Self::nombre_de_redemarrages(),
        ) {
            Demarrage::Decidable { tournait, active_au_boot, restarts_avant } => {
                (tournait, active_au_boot, restarts_avant)
            }
            Demarrage::Refus(constat, raison) => {
                r.observe(artefact, constat, || Err(raison));
                return Ok(r);
            }
        };
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
        r.observe(artefact, Constat::mesure(deja_conforme), || {
            if let Err(e) = demarrage {
                return Err(format!("{e}"));
            }
            Self::tourne_vraiment(std::time::Duration::from_secs(12), restarts_avant)?;
            // L'artefact dit « au boot » : on le VÉRIFIE, on ne le déduit pas de `enable` — et une
            // vérification qui n'aboutit pas se dit AUTREMENT qu'un « non ». L'ancienne forme
            // annonçait « n'est PAS activé au boot » quand elle n'avait rien pu lire, ce qui envoyait
            // corriger une activation qui n'avait peut-être jamais manqué.
            match Self::est_active_au_boot() {
                Lecture::Lue(true) => Ok(()),
                Lecture::Lue(false) => Err("le service tourne mais n'est PAS activé au boot \
                                            (`systemctl is-enabled plume-agent` répond `disabled`) : \
                                            il ne repartirait pas au redémarrage"
                    .into()),
                Lecture::Illisible { cause, detail } => Err(format!(
                    "le service tourne, mais son activation AU BOOT n'a PAS pu être vérifiée \
                     ({cause} : {detail}) — cet artefact dit « au boot », et cela ne s'affirme pas \
                     sans l'avoir lu"
                )),
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
        //    ET « JE N'AI PAS PU INTERROGER » N'EST PAS « RIEN À RETIRER » (`S36`). C'est ici que le
        //    défaut de cette campagne était le plus direct : les deux sondes rendaient `false` quand
        //    la commande n'aboutissait pas, `false && false` valait « déjà arrêté et désactivé », la
        //    re-sonde rappelait LES MÊMES fonctions et rendait le même `false`, et le rapport
        //    concluait « absent (rien à retirer) » avec un code de sortie NUL — sur un hôte où le
        //    service pouvait parfaitement tourner. Un opérateur qui retire l'agent d'un poste
        //    compromis lisait un succès qu'il n'avait pas obtenu, deuxième fois, par une autre porte.
        let constat = constat_de_retrait(&Self::est_actif(), &Self::est_active_au_boot());
        // L'ACTION EST TOUJOURS TENTÉE — c'est ce que l'opérateur a demandé, et elle est idempotente.
        // Ce qui change est le VERDICT : il ne peut plus être tiré d'une lecture qui n'a pas eu lieu.
        let _ = Command::new("systemctl").args(["disable", "--now", UNIT_NAME]).status();
        let nom = match &constat {
            Constat::Conforme => format!("service {UNIT_NAME}"),
            _ => format!("service {UNIT_NAME} (arrêté et désactivé)"),
        };
        r.observe(nom, constat, || {
            verdict_de_retrait(&Self::est_actif(), &Self::est_active_au_boot())
        });

        // 2. L'unité est-elle sur le disque ? État VOULU = absente.
        let unit = std::path::Path::new(UNIT_PATH);
        let deja_absente = !unit.exists();
        let supprime = if deja_absente { Ok(()) } else { std::fs::remove_file(unit) };
        if !deja_absente {
            let _ = Command::new("systemctl").arg("daemon-reload").status();
        }
        r.observe(UNIT_PATH, Constat::mesure(deja_absente), || match supprime {
            Err(e) => Err(format!("{e} (root requis ?)")),
            Ok(()) if unit.exists() => Err("toujours présent après suppression".into()),
            Ok(()) => Ok(()),
        });
        Ok(r)
    }

    /// L'ÉTAT AFFICHÉ — ou l'aveu qu'il n'a pas été lu (`S36`).
    ///
    /// L'ancienne forme jetait le code de retour, prenait la sortie standard telle quelle et
    /// remplaçait une sortie vide par « inconnu ». Un gestionnaire injoignable produisait donc soit
    /// ce mot-là, indiscernable d'un état réellement indéterminé, soit — sur un hôte où `systemctl`
    /// existe sans que systemd soit le gestionnaire — un mot d'état parfaitement crédible qu'aucune
    /// mesure ne soutenait. Ici, ce qui n'a pas été lu se DIT.
    fn status(&self) -> anyhow::Result<String> {
        let l = match Command::new("systemctl").args(["is-active", UNIT_NAME]).output() {
            Err(e) => interrogation::pas_lance("systemctl is-active", &e),
            Ok(o) => interrogation::verdict_de_mot(
                "systemctl is-active",
                o.status.code(),
                &o.stdout,
                &o.stderr,
                &MOTS_IS_ACTIVE,
            ),
        };
        Ok(match l {
            Lecture::Lue((mot, _)) => format!("{UNIT_NAME}: {mot}"),
            Lecture::Illisible { cause, detail } => {
                format!("{UNIT_NAME}: état NON INTERROGÉ ({cause}) — {detail}")
            }
        })
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

    // =============================================================================================
    // `S36` — UNE INTERROGATION QUI ÉCHOUE NE DÉCIDE PLUS D'UNE ACTION
    //
    // LES DEUX SENS, ET LE SECOND EST LE CŒUR. ① La lecture échoue -> verdict d'échec NOMMÉ, aucune
    // conclusion, aucune action. ② Elle aboutit sur un service réellement sain (ou une unité
    // réellement absente) -> le verdict normal. Sans ②, une version qui ne saurait JAMAIS rien
    // passerait ① sans rien prouver et rendrait `install`/`uninstall` inutilisables.
    //
    // INDÉPENDANTS DE LA MACHINE : les décisions sont EXTRAITES des fonctions qui parlent à systemd
    // (comme `prevol` l'a été avant elles), et elles reçoivent des `Lecture` fabriquées. Rien ici
    // n'exige un gestionnaire de services : les trois OS d'intégration continue exécutent le même
    // test, et un hôte où l'agent est installé rend le même verdict qu'un hôte où il ne l'est pas.
    // =============================================================================================

    fn illisible<T>() -> Lecture<T> {
        Lecture::Illisible {
            cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
            detail: "`systemctl is-active` n'a rendu AUCUN mot (code Some(1))".to_string(),
        }
    }

    /// ① LE DÉFAUT MESURÉ, FIGÉ, CÔTÉ RETRAIT. Les deux sondes rendaient `false` quand la commande
    /// n'aboutissait pas ; `!false && !false` valait « déjà arrêté et désactivé », la re-sonde
    /// rappelait les mêmes fonctions et rendait le même `false`, et le rapport disait « absent (rien
    /// à retirer) » avec un code de sortie NUL. Chacune des TROIS combinaisons où une lecture manque
    /// est ré-exercée : le constat ne peut plus être « conforme », et la re-sonde ne peut plus rendre
    /// `Ok`.
    #[test]
    fn une_interrogation_ratee_ne_vaut_jamais_rien_a_retirer() {
        for (actif, au_boot, quoi) in [
            (illisible::<bool>(), Lecture::Lue(false), "l'état courant"),
            (Lecture::Lue(false), illisible::<bool>(), "l'activation au boot"),
            (illisible::<bool>(), illisible::<bool>(), "les deux"),
        ] {
            let constat = constat_de_retrait(&actif, &au_boot);
            assert!(
                matches!(constat, Constat::NonObserve { .. }),
                "{quoi} n'a pas été lu : le constat antérieur ne peut pas être une mesure"
            );
            let verdict = verdict_de_retrait(&actif, &au_boot);
            let dit = match verdict {
                Err(m) => m,
                Ok(()) => panic!("{quoi} n'a pas été lu, et le retrait a pourtant été CONSTATÉ"),
            };
            assert!(dit.contains("n'a PAS pu être interrogé"), "le verdict se nomme : {dit}");
            assert!(dit.contains("RIEN n'est affirmé"), "{dit}");
            assert!(!dit.contains("toujours ACTIF"), "on n'accuse pas un état qu'on n'a pas lu : {dit}");
            // LE RAPPORT COMPLET : un artefact en ÉCHEC, donc un code de sortie NON NUL (cf. `conclure`).
            let mut r = Outcome::retrait();
            r.observe(format!("service {UNIT_NAME}"), constat, || verdict_de_retrait(&actif, &au_boot));
            assert_eq!(r.failures().len(), 1, "{}", r.render());
            let txt = r.render();
            assert!(!txt.contains("rien à retirer"), "{txt}");
            assert!(!txt.contains("AUCUN retrait effectué"), "{txt}");
        }
    }

    /// ② LE TÉMOIN INVERSE, ET C'EST LUI QUI PROTÈGE LE CAS NOMINAL. Une unité réellement absente
    /// est LUE comme telle — mesuré le 2026-08-21 (systemd 261) : `is-active` répond `inactive` et
    /// `is-enabled` répond `not-found`, tous deux avec un code de retour 4. Le retrait doit donc
    /// continuer de dire « rien à retirer », code de sortie nul. Sans cette moitié, une version qui
    /// ne saurait jamais rien passerait le test précédent en rendant la commande inutilisable.
    #[test]
    fn une_unite_reellement_absente_se_dit_toujours_rien_a_retirer() {
        let actif = interrogation::oui_non(interrogation::verdict_de_mot(
            "systemctl is-active", Some(4), b"inactive\n", b"", &MOTS_IS_ACTIVE));
        let au_boot = interrogation::oui_non(interrogation::verdict_de_mot(
            "systemctl is-enabled", Some(4), b"not-found\n", b"", &MOTS_IS_ENABLED));
        assert!(matches!(constat_de_retrait(&actif, &au_boot), Constat::Conforme));
        assert_eq!(verdict_de_retrait(&actif, &au_boot), Ok(()));
        let mut r = Outcome::retrait();
        r.observe(format!("service {UNIT_NAME}"), constat_de_retrait(&actif, &au_boot), || {
            verdict_de_retrait(&actif, &au_boot)
        });
        let txt = r.render();
        assert!(txt.contains("rien à retirer"), "{txt}");
        assert!(r.failures().is_empty(), "{txt}");
        // Et un service RÉELLEMENT actif reste, lui, un retrait à faire puis à constater.
        let tourne = Lecture::Lue(true);
        assert!(matches!(constat_de_retrait(&tourne, &Lecture::Lue(true)), Constat::NonConforme));
        assert!(verdict_de_retrait(&tourne, &Lecture::Lue(true)).unwrap_err().contains("toujours ACTIF"));
    }

    /// ① CÔTÉ POSE, LE DÉFAUT EST PIRE : il fait AGIR. Le choix entre `enable --now` et `restart` se
    /// fait sur « le service tourne-t-il déjà » ; une lecture ratée valant `false` faisait prendre la
    /// branche `enable --now`, qui NE REDÉMARRE PAS un service déjà actif — le processus de
    /// l'ANCIENNE unité survivait pendant que le rapport annonçait « posé ». La décision REFUSE
    /// désormais, pour chacune des trois lectures.
    #[test]
    fn une_interrogation_ratee_refuse_de_demarrer_plutot_que_d_agir() {
        let cas: [(Lecture<bool>, Lecture<bool>, Lecture<u32>, &str); 3] = [
            (illisible(), Lecture::Lue(false), Lecture::Lue(0), "l'état courant"),
            (Lecture::Lue(false), illisible(), Lecture::Lue(0), "l'activation au boot"),
            (Lecture::Lue(false), Lecture::Lue(false), illisible(), "le compteur de redémarrages"),
        ];
        for (actif, au_boot, restarts, quoi) in cas {
            let (constat, raison) = match decision_de_demarrage(actif, au_boot, restarts) {
                Demarrage::Refus(c, m) => (c, m),
                Demarrage::Decidable { .. } => {
                    panic!("{quoi} n'a pas été lu, et le démarrage a pourtant été DÉCIDÉ")
                }
            };
            assert!(matches!(constat, Constat::NonObserve { .. }));
            assert!(raison.contains("AUCUN démarrage n'a été tenté"), "{raison}");
            assert!(raison.contains("n'a PAS pu être interrogé"), "{raison}");
            let mut r = Outcome::pose();
            r.observe("service (actif au boot et maintenant)", constat, || Err(raison));
            let txt = r.render();
            assert_eq!(r.failures().len(), 1, "{txt}");
            assert!(!txt.contains("posé     :"), "{txt}");
            assert!(!txt.contains("en place "), "{txt}");
        }
    }

    /// ② LE TÉMOIN INVERSE CÔTÉ POSE : trois lectures qui aboutissent rendent la décision, telle
    /// quelle, y compris le compteur de redémarrages d'un service SAIN au passé chargé (mesuré le
    /// 2026-08-02 : `NRestarts=3` sur un service `active/running`). Sans ce témoin, un refus
    /// inconditionnel rendrait `install` inopérant et passerait le test précédent.
    #[test]
    fn trois_lectures_qui_aboutissent_decident_normalement() {
        match decision_de_demarrage(Lecture::Lue(true), Lecture::Lue(true), Lecture::Lue(3)) {
            Demarrage::Decidable { tournait, active_au_boot, restarts_avant } => {
                assert!(tournait && active_au_boot);
                assert_eq!(restarts_avant, 3, "la RÉFÉRENCE est la valeur lue, pas zéro");
            }
            Demarrage::Refus(_, m) => panic!("trois lectures abouties, et pourtant un refus : {m}"),
        }
    }

    /// LES DEUX VOCABULAIRES SONT FERMÉS, NON DÉGÉNÉRÉS, ET CONTIENNENT CE QUE L'OUTIL REND
    /// RÉELLEMENT. Une table dont tous les mots vaudraient `false` ferait passer les tests d'échec
    /// sans rien mesurer ; une table à laquelle manque le mot du cas NOMINAL transformerait un hôte
    /// sain en aveu permanent. Les mots cités ici ont été mesurés le 2026-08-21 (systemd 261).
    #[test]
    fn les_vocabulaires_couvrent_les_mots_mesures_et_ne_degenerent_pas() {
        for (table, vrais, faux) in [
            (&MOTS_IS_ACTIVE[..], &["active"][..], &["inactive", "failed", "activating"][..]),
            (&MOTS_IS_ENABLED[..], &["enabled"][..], &["disabled", "not-found", "masked"][..]),
        ] {
            for m in vrais {
                assert_eq!(table.iter().find(|(w, _)| w == m).map(|(_, v)| *v), Some(true), "{m}");
            }
            for m in faux {
                assert_eq!(table.iter().find(|(w, _)| w == m).map(|(_, v)| *v), Some(false), "{m}");
            }
            assert!(table.iter().any(|(_, v)| *v), "une table tout-à-faux ne mesure rien");
            assert!(table.iter().any(|(_, v)| !*v), "une table tout-à-vrai non plus");
        }
    }

    /// UN CHEMIN LITTÉRAL SOUS UN PRÉFIXE MASQUÉ EST REFUSÉ MÊME QUAND SA CIBLE NE L'EST PAS.
    ///
    /// LA MUTATION QUE CE TEST FIGE. La garde ne confrontait à la table que le chemin RÉSOLU dès lors
    /// que la résolution aboutissait : un lien placé sous un répertoire personnel et pointant vers
    /// /usr/local/bin passait. Or c'est le LITTÉRAL que l'unité écrit dans `ExecStart=`, et c'est lui
    /// que le service ouvre depuis un bac à sable où ce répertoire est REMPLACÉ par un répertoire
    /// vide : l'unité serait posée pour mourir en 203/EXEC. Symétriquement, une résolution qui échoue
    /// (le cas NORMAL pour un spool pas encore créé) ne vaut plus « rien à redire ».
    ///
    /// PARAMÉTRÉ SUR LES DEUX SOURCES, donc indépendant de la machine : aucun lien n'est créé, aucune
    /// arborescence n'est lue, et le test rend le même verdict sur les trois OS d'intégration continue.
    #[test]
    fn le_chemin_litteral_est_confronte_meme_quand_la_resolution_aboutit() {
        let sous_home = Path::new("/home/soc/plume-agent");
        let cible_sage = Path::new("/usr/local/bin/plume-agent");
        // ① Résolution ABOUTIE vers une cible parfaitement joignable : le littéral décide quand même.
        assert_eq!(
            chemin_cache_par_avec(sous_home, Some(cible_sage)).map(|(d, _)| d),
            Some("ProtectHome=yes"),
            "le chemin écrit dans l'unité est le littéral : c'est lui que le service ouvrira"
        );
        // ② Résolution ÉCHOUÉE (chemin pas encore créé) : le littéral est confronté, pas ignoré.
        assert_eq!(
            chemin_cache_par_avec(sous_home, None).map(|(d, _)| d),
            Some("ProtectHome=yes")
        );
        // ③ L'INVERSE — un littéral sage dont la CIBLE est masquée reste refusé : c'est la moitié que
        //    la version paramétrée ne doit pas perdre en gagnant l'autre.
        assert_eq!(
            chemin_cache_par_avec(cible_sage, Some(Path::new("/home/soc/bin/plume-agent")))
                .map(|(d, _)| d),
            Some("ProtectHome=yes")
        );
        // ④ TÉMOIN : littéral sage, cible sage -> installable. Sans lui, une garde qui refuserait
        //    tout passerait les trois assertions précédentes.
        assert_eq!(chemin_cache_par_avec(cible_sage, Some(cible_sage)), None);
        assert_eq!(chemin_cache_par_avec(cible_sage, None), None);
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

