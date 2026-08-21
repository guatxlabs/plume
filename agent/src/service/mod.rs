//! Gestion du service natif (install/enable/start l'agent comme daemon système).
//!
//! `ServiceManager` = SPI par-OS. `systemd` (Linux), `launchd` (macOS) et `windows_scm` (Windows)
//! sont implémentés ; `current()` renvoie le manager adapté à l'OS de compilation. Les trois rendent
//! un `Outcome` — CE QU'ILS ONT OBSERVÉ — au lieu d'imprimer un verdict qu'ils n'ont pas vérifié.

pub mod interrogation;
pub mod systemd;
pub mod launchd;
pub mod windows_scm;

/// CE QUI A ÉTÉ OBSERVÉ DE L'ÉTAT D'UN ARTEFACT AVANT D'AGIR — TROIS cas, et le troisième n'est
/// AUCUN des deux autres.
///
/// POURQUOI UN BOOLÉEN NE POUVAIT PAS TENIR (`S36`). Cette observation était un `bool`, et un `bool`
/// n'a pas de place pour « je n'ai pas pu regarder ». Tout site dont l'interrogation échouait devait
/// donc CHOISIR entre deux affirmations qu'il ne pouvait pas tenir — et le choix commode, celui
/// qu'un `unwrap_or(false)` produit tout seul, menait à « l'état voulu est déjà atteint », c'est-à-dire
/// « rien à faire », c'est-à-dire un code de sortie nul. La forme la plus directe du défaut de cette
/// campagne : l'échec d'une mesure devient le verdict le plus rassurant.
///
/// AUCUN CONSTRUCTEUR NE REND UNE VALEUR FAUTE DE SAVOIR. `mesure` exige un booléen qui vient d'une
/// observation qui a eu lieu ; `depuis_aveu` ne rend un `NonObserve` QUE si on lui présente une
/// lecture qui a réellement échoué. Il n'existe pas de troisième porte, et pas de `Default`.
#[derive(Debug)]
pub enum Constat {
    /// OBSERVÉ : l'artefact était DÉJÀ dans l'état voulu.
    Conforme,
    /// OBSERVÉ : il ne l'était pas.
    NonConforme,
    /// PAS OBSERVÉ : l'interrogation n'a pas abouti, avec la CAUSE du vocabulaire fermé partagé avec
    /// le démon et les capteurs (`crate::lisibilite`).
    NonObserve { cause: &'static str, detail: String },
}

impl Constat {
    /// L'observation a EU LIEU et voici ce qu'elle a rendu. À n'appeler que là — un appelant qui
    /// n'a pas su lire passe par `depuis_aveu`.
    pub fn mesure(conforme: bool) -> Self {
        if conforme {
            Constat::Conforme
        } else {
            Constat::NonConforme
        }
    }

    /// LE CONSTAT QU'ON NE PEUT PAS FAIRE, portant le mot de la lecture qui a échoué. `None` quand la
    /// lecture a abouti : il n'existe donc aucun chemin vers `NonObserve` sans un aveu réel.
    pub fn depuis_aveu<T>(l: &crate::lisibilite::Lecture<T>) -> Option<Self> {
        match l {
            crate::lisibilite::Lecture::Lue(_) => None,
            crate::lisibilite::Lecture::Illisible { cause, detail } => {
                Some(Constat::NonObserve { cause, detail: detail.clone() })
            }
        }
    }

    /// Le premier aveu de plusieurs lectures — l'ordre des arguments est celui des interrogations.
    /// `None` quand elles ont TOUTES abouti : c'est la seule façon d'obtenir le droit d'agir.
    pub fn premier_aveu(aveux: impl IntoIterator<Item = Option<Constat>>) -> Option<Constat> {
        aveux.into_iter().flatten().next()
    }

    /// L'aveu EN TEXTE, pour le message qui accompagne un refus. Un constat qui a été OBSERVÉ n'a
    /// rien à avouer et le dit — cette branche-là n'ouvre aucun chemin vers un verdict rassurant.
    pub fn aveu_dit(&self) -> String {
        match self {
            Constat::NonObserve { cause, detail } => format!("{cause} : {detail}"),
            Constat::Conforme | Constat::NonConforme => "observation faite".to_string(),
        }
    }
}

/// CE QU'UNE OPÉRATION DE SERVICE A RÉELLEMENT FAIT — artefact par artefact, OBSERVÉ, jamais supposé.
/// UN SEUL TYPE POUR LES DEUX SENS (pose ET retrait) : c'est la MÊME question qui était mal répondue
/// des deux côtés — « l'artefact est-il dans l'état VOULU, et l'ai-je VÉRIFIÉ ? ».
///
/// LE DÉFAUT QUE CE TYPE REND NON-ÉCRIVABLE, DANS LES DEUX SENS.
///
/// RETRAIT (corrigé le 2026-08-02). `uninstall()` renvoyait `Result<()>` : chaque backend faisait
/// `let _ = Command::new("systemctl")…status();`, ne vérifiait rien, imprimait « service retiré » et
/// rendait `Ok(())`. MESURÉ sur cette machine, sans rien d'installé : « Failed to disable unit… »,
/// PUIS « Reload daemon failed », PUIS « service retiré : plume-agent.service », sortie **0** —
/// 0 fichier supprimé, 2 commandes en échec, un succès annoncé.
///
/// POSE (corrigé le 2026-08-02, MÊME FAMILLE). `install()` renvoyait `Result<()>` et imprimait
/// « service installé et démarré » dès que `systemctl enable --now` rendait 0. Or ce code de retour
/// ne dit RIEN de l'exécution : MESURÉ ce jour-là avec systemd 261, une unité dont l'`ExecStart` est
/// injoignable DEPUIS SON PROPRE BAC À SABLE part en `status=203/EXEC`, `Result=exit-code`,
/// `SubState=auto-restart` — et `systemctl enable --now` rend **0** (le job de démarrage réussit :
/// l'échec a lieu APRÈS le fork, dans le namespace). Le technicien lisait « démarré », sortie 0,
/// sur une machine qui ne collecte RIEN et redémarre en boucle toutes les 5 s.
///
/// LA FORME. Une disposition ne s'ÉCRIT pas : elle se DÉRIVE de DEUX observations — l'état AVANT
/// l'action, et une RE-SONDE fournie au moment de conclure. La partition (constat, re-sonde) est
/// FERMÉE (trois constats × deux issues, `match` exhaustif) : il n'existe pas de cas à oublier — et
/// depuis `S36` le constat antérieur porte lui-même le cas « pas observé ». Les variantes
/// sont PRIVÉES (module `disposition`) : aucun backend ne peut écrire `Removed`/`Started` à la main,
/// ni conclure sans re-sonder — **le défaut ne compile pas**.
pub use disposition::Disposition;

mod disposition {
    /// Disposition d'UN artefact. OPAQUE : `Etat` est privé au module, donc l'unique façon d'en
    /// obtenir une est `derive()`, qui EXIGE les deux observations. (Mutation : écrire
    /// `Disposition::Change` dans un backend ne compile pas — la variante n'est pas nommable.)
    #[derive(Debug, PartialEq, Eq)]
    pub struct Disposition(Etat);

    #[derive(Debug, PartialEq, Eq)]
    enum Etat {
        /// L'artefact n'était PAS dans l'état voulu, il y est maintenant (RE-OBSERVÉ).
        Change,
        /// Il y était DÉJÀ : rien à faire. Honnête — et ce n'est PAS un changement.
        DejaConforme,
        /// Il n'y est PAS après l'action. C'est un échec, avec sa raison.
        Echec(String),
        /// Il Y EST à la re-sonde, mais son état ANTÉRIEUR n'a pas pu être observé : on ne sait donc
        /// pas si quelque chose a changé. Ce n'est ni `Change` (rien ne le prouve) ni `DejaConforme`
        /// (rien ne le prouve non plus) — c'est le troisième cas, et il se dit (`S36`, forme de `S33`).
        AtteintSansAvant { cause: &'static str, detail: String },
    }

    impl Disposition {
        /// SEULE fabrique. `avant` = ce qui a été OBSERVÉ de l'état antérieur (trois cas, dont
        /// « pas observé ») ; `apres` = la RE-SONDE : `Ok(())` si l'état voulu est atteint,
        /// `Err(raison)` sinon — y compris quand la re-sonde n'a pas pu mesurer, car un état qu'on
        /// n'a pas pu vérifier n'est pas un état atteint.
        ///
        /// LA PARTITION RESTE FERMÉE : trois constats × deux issues de re-sonde, `match` exhaustif,
        /// aucune valeur par défaut.
        pub(super) fn derive(avant: super::Constat, apres: Result<(), String>) -> Self {
            use super::Constat;
            Disposition(match (avant, apres) {
                (_, Err(why)) => Etat::Echec(why),
                (Constat::NonConforme, Ok(())) => Etat::Change,
                (Constat::Conforme, Ok(())) => Etat::DejaConforme,
                (Constat::NonObserve { cause, detail }, Ok(())) => {
                    Etat::AtteintSansAvant { cause, detail }
                }
            })
        }
        pub fn a_change(&self) -> bool {
            matches!(self.0, Etat::Change)
        }
        pub fn echec(&self) -> Option<&str> {
            match &self.0 {
                Etat::Echec(w) => Some(w.as_str()),
                _ => None,
            }
        }
        /// L'état antérieur n'a pas été observé : la cause et son détail. Ce que `a_change()` ne peut
        /// pas dire, et qu'un rapport n'a pas le droit de taire.
        pub fn sans_avant(&self) -> Option<(&'static str, &str)> {
            match &self.0 {
                Etat::AtteintSansAvant { cause, detail } => Some((cause, detail.as_str())),
                _ => None,
            }
        }
    }
}

/// LE SENS de l'opération — il ne change QUE le vocabulaire du rapport, jamais la logique.
/// « rien trouvé » se dit « absent (rien à retirer) » au retrait et ne peut pas se dire « retiré » ;
/// symétriquement une pose sans changement se dit « déjà en place » et jamais « posé ».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Pose,
    Retrait,
}

#[derive(Debug)]
pub struct Outcome {
    op: Operation,
    entries: Vec<(String, Disposition)>,
}

impl Outcome {
    pub fn pose() -> Self {
        Self { op: Operation::Pose, entries: Vec::new() }
    }
    pub fn retrait() -> Self {
        Self { op: Operation::Retrait, entries: Vec::new() }
    }
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// Note un artefact À PARTIR DE DEUX OBSERVATIONS. `etait_conforme` = état voulu déjà atteint
    /// AVANT d'agir ; `resonde` = la RE-SONDE, évaluée ICI (après l'action) — `Ok(())` = l'état voulu
    /// est atteint, `Err(raison)` = il ne l'est pas. Il n'existe AUCUNE autre façon d'ajouter une
    /// ligne au rapport : conclure sans re-sonder est un trou dans la signature, pas un oubli.
    pub fn observe(
        &mut self,
        what: impl Into<String>,
        etait_conforme: Constat,
        resonde: impl FnOnce() -> Result<(), String>,
    ) {
        let d = Disposition::derive(etait_conforme, resonde());
        self.entries.push((what.into(), d));
    }

    /// Vrai si au moins un artefact a RÉELLEMENT changé d'état (retiré, ou posé et démarré).
    pub fn a_change(&self) -> bool {
        self.entries.iter().any(|(_, d)| d.a_change())
    }
    pub fn failures(&self) -> Vec<&str> {
        self.entries.iter().filter_map(|(w, d)| d.echec().map(|_| w.as_str())).collect()
    }
    /// Les artefacts dont l'état ANTÉRIEUR n'a pas pu être observé. Tant qu'il y en a un, « rien
    /// n'avait besoin d'être fait » est une phrase que ce rapport n'a pas le droit de prononcer.
    pub fn sans_avant(&self) -> Vec<&str> {
        self.entries.iter().filter_map(|(w, d)| d.sans_avant().map(|_| w.as_str())).collect()
    }
    /// Rapport lisible. Le vocabulaire vient du SENS : « rien à retirer » est dit avec ces mots-là,
    /// jamais « retiré » ; « déjà en place » n'est jamais « posé ».
    pub fn render(&self) -> String {
        if self.entries.is_empty() {
            return "aucun artefact inspecté — rien n'est affirmé".into();
        }
        let (verbe_change, verbe_conforme, rien) = match self.op {
            Operation::Retrait => (
                "retiré   ",
                "absent   ",
                ("(rien à retirer)", "  => rien n'était installé : AUCUN retrait effectué."),
            ),
            Operation::Pose => (
                "posé     ",
                "en place ",
                ("(déjà conforme)", "  => tout était déjà en place : AUCUNE pose effectuée."),
            ),
        };
        let mut out = Vec::new();
        for (what, how) in &self.entries {
            out.push(if let Some(why) = how.echec() {
                format!("  ÉCHEC    : {what} — {why}")
            } else if let Some((cause, detail)) = how.sans_avant() {
                format!(
                    "  ATTEINT  : {what} — état voulu VÉRIFIÉ, état ANTÉRIEUR non observé \
                     ({cause} : {detail}) : aucun changement n'est affirmé"
                )
            } else if how.a_change() {
                format!("  {verbe_change}: {what}")
            } else {
                format!("  {verbe_conforme}: {what} {}", rien.0)
            });
        }
        // La phrase de clôture AFFIRME qu'il n'y avait rien à faire. Elle exige donc que TOUS les
        // états antérieurs aient été observés : un seul non observé, et cette affirmation-là est
        // exactement le verdict rassurant que ce lot retire.
        if !self.a_change() && self.failures().is_empty() && self.sans_avant().is_empty() {
            out.push(rien.1.into());
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

/// COMMENT le service doit pouvoir se servir d'un chemin. Ce troisième champ portait autrefois une
/// AFFIRMATION (« ce chemin est re-exposé par `ReadWritePaths=`, donc le masquage ne le concerne
/// pas ») que rien ne vérifiait et qui s'est révélée FAUSSE à la re-mesure ; il porte désormais un
/// fait EXERCÉ : `systemd::sonde_le_bac_a_sable` exécute ce `test(1)`-là sur ce chemin-là, depuis
/// l'intérieur du bac à sable de l'unité, au moment de l'installation. Une classification erronée ne
/// rend donc plus un verdict optimiste : elle rend une mesure fausse, qui échoue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acces {
    /// Le service doit EXÉCUTER ce chemin (l'`ExecStart`).
    Execute,
    /// Le service doit LIRE ce chemin.
    Lu,
    /// Le service doit ÉCRIRE dans ce chemin.
    Ecrit,
}

impl Acces {
    /// L'opérateur `test(1)` que la sonde fait exécuter, dans le bac à sable de l'unité, pour ce mode
    /// d'accès.
    ///
    /// CETTE LIGNE A PORTÉ UNE PROMESSE QU'AUCUN MÉCANISME NE POUVAIT TENIR : « POSIX, donc tenu par le
    /// `/bin/sh` de n'importe quel hôte ». Le shell d'un hôte qu'on n'a pas sous la main ne se vérifie
    /// pas depuis ici, et une propriété d'environnement affirmée en prose n'a aucun moyen de vieillir :
    /// le jour où elle cesse d'être vraie, rien ne rougit. CE QUI EST RÉELLEMENT SU, et qui suffit à la
    /// décision : `systemd::sonde_le_bac_a_sable` ne lit un verdict que si la sonde rend l'indice d'un
    /// chemin. TOUTE autre sortie — opérateur absent, shell qui ne l'implémente pas, sonde qui n'a pas
    /// pu tourner — devient `Sonde::PasDeMesure`, c'est-à-dire un aveu NOMMÉ, jamais un « tous les
    /// chemins sont utilisables ». La propriété tenue n'est donc pas « ces opérateurs existent
    /// partout », c'est « leur absence se dit au lieu de passer pour un succès ».
    pub fn test_posix(self) -> &'static str {
        match self {
            Acces::Execute => "-x",
            Acces::Lu => "-r",
            Acces::Ecrit => "-w",
        }
    }
}

impl ServiceSpec {
    /// TOUS les chemins que l'unité fera manipuler au service : le rôle qui les nomme dans un message
    /// d'erreur, le chemin, et le MODE D'ACCÈS dont le service a besoin.
    ///
    /// DESTRUCTURATION EXHAUSTIVE (aucun `..`) : un champ ajouté demain à `ServiceSpec` NE COMPILE
    /// PAS tant qu'il n'a pas été classé ici — c'est ce qui rend la garde de préfixes
    /// (`systemd::chemin_cache_par`) ET la mesure sur place (`systemd::sonde_le_bac_a_sable`) closes
    /// par construction plutôt qu'énumérées à la main.
    pub fn paths(&self) -> Vec<(&'static str, &std::path::Path, Acces)> {
        let ServiceSpec { exec_path, config_path, spool_dir, state_dir } = self;
        vec![
            ("ExecStart (binaire de l'agent)", exec_path.as_path(), Acces::Execute),
            ("--config (fichier de configuration)", config_path.as_path(), Acces::Lu),
            ("spool_dir", spool_dir.as_path(), Acces::Ecrit),
            ("state_dir", state_dir.as_path(), Acces::Ecrit),
        ]
    }
}

pub trait ServiceManager {
    /// Nom du service (unité systemd / label launchd / nom SCM).
    #[allow(dead_code)] // exposé pour diagnostics/futurs appelants
    fn service_name(&self) -> &str;
    /// Installe l'unité, crée les répertoires, active et démarre le service. RENVOIE CE QUI A ÉTÉ
    /// FAIT ET RE-OBSERVÉ (cf. `Outcome`) — un backend ne peut plus imprimer « installé et démarré »
    /// puis rendre `Ok(())` sans avoir regardé si le service TOURNE.
    fn install(&self, spec: &ServiceSpec) -> anyhow::Result<Outcome>;
    /// Arrête, désactive et retire l'unité. RENVOIE CE QUI A ÉTÉ FAIT, artefact par artefact :
    /// un backend ne peut pas annoncer un succès sans nommer ce qu'il a retiré (cf. `Outcome`).
    fn uninstall(&self) -> anyhow::Result<Outcome>;
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
        let mut r = Outcome::retrait();
        r.observe("service plume-agent.service", Constat::Conforme, || Ok(()));
        r.observe("/etc/systemd/system/plume-agent.service", Constat::Conforme, || Ok(()));
        assert!(!r.a_change(), "aucun artefact retiré");
        assert!(r.failures().is_empty());
        let txt = r.render();
        assert!(txt.contains("rien à retirer"), "{txt}");
        assert!(txt.contains("AUCUN retrait effectué"), "{txt}");
        assert!(!txt.contains("  retiré   :"), "un rapport sans retrait ne peut pas dire « retiré » : {txt}");
    }

    #[test]
    fn un_artefact_resistant_est_un_echec_nomme() {
        let mut r = Outcome::retrait();
        r.observe("service plume-agent.service", Constat::NonConforme, || Err("toujours actif".into()));
        r.observe("/etc/systemd/system/plume-agent.service", Constat::NonConforme, || Ok(()));
        assert_eq!(r.failures(), vec!["service plume-agent.service"]);
        assert!(r.a_change(), "un échec partiel n'efface pas ce qui a bien été retiré");
        assert!(r.render().contains("ÉCHEC"), "{}", r.render());
    }

    #[test]
    fn un_retrait_reel_est_dit_retire() {
        let mut r = Outcome::retrait();
        r.observe("service plume-agent.service (arrêté et désactivé)", Constat::NonConforme, || Ok(()));
        assert!(r.a_change());
        assert!(r.failures().is_empty());
        let txt = r.render();
        assert!(txt.contains("retiré   : service plume-agent.service"), "{txt}");
        assert!(!txt.contains("AUCUN retrait"), "{txt}");
    }

    /// LE JUMEAU, CÔTÉ POSE — le défaut mesuré le 2026-08-02 : `install` imprimait « service installé
    /// et démarré » et sortait 0 alors que le service partait en 203/EXEC et redémarrait en boucle.
    /// Une RE-SONDE qui échoue produit un ÉCHEC NOMMÉ, et le rapport ne contient JAMAIS le mot « posé »
    /// pour cet artefact.
    #[test]
    fn un_service_qui_ne_tourne_pas_ne_se_dit_jamais_pose() {
        let mut r = Outcome::pose();
        r.observe("/etc/systemd/system/plume-agent.service", Constat::NonConforme, || Ok(()));
        r.observe("service plume-agent.service (actif)", Constat::NonConforme, || {
            Err("inactif après `systemctl enable --now` (status=203/EXEC)".into())
        });
        assert_eq!(r.failures(), vec!["service plume-agent.service (actif)"]);
        let txt = r.render();
        assert!(txt.contains("ÉCHEC    : service plume-agent.service (actif)"), "{txt}");
        assert!(txt.contains("203/EXEC"), "la raison OBSERVÉE est rendue : {txt}");
        assert!(
            !txt.contains("posé     : service"),
            "un service qui ne tourne pas ne peut pas être annoncé posé : {txt}"
        );
    }

    /// Une pose IDEMPOTENTE (tout était déjà en place) ne se dit pas « posé » non plus — symétrique
    /// exact de « rien trouvé ne se dit jamais retiré ».
    #[test]
    fn une_pose_sans_changement_se_dit_deja_en_place() {
        let mut r = Outcome::pose();
        r.observe("service plume-agent.service (actif)", Constat::Conforme, || Ok(()));
        assert!(!r.a_change());
        assert!(r.failures().is_empty());
        let txt = r.render();
        assert!(txt.contains("en place "), "{txt}");
        assert!(txt.contains("AUCUNE pose effectuée"), "{txt}");
        assert!(!txt.contains("posé     :"), "{txt}");
    }

    /// LA PARTITION EST FERMÉE : (constat, re-sonde) est un produit TROIS × DEUX et `derive` les
    /// couvre TOUS. Le cas absurde (« c'était conforme, ça ne l'est plus ») est un ÉCHEC, pas un
    /// silence ; et le cas ajouté par `S36` — l'état voulu est vérifié, l'état ANTÉRIEUR n'a pas pu
    /// l'être — n'est ni « changé » ni « déjà conforme ».
    #[test]
    fn la_partition_avant_apres_est_close() {
        let cas: [(fn() -> Constat, Result<(), String>, &str); 6] = [
            (|| Constat::NonConforme, Ok(()), "change"),
            (|| Constat::Conforme, Ok(()), "deja"),
            (|| Constat::NonConforme, Err("x".to_string()), "echec"),
            (|| Constat::Conforme, Err("x".to_string()), "echec"),
            (
                || Constat::NonObserve {
                    cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
                    detail: "gestionnaire injoignable".to_string(),
                },
                Ok(()),
                "sans-avant",
            ),
            (
                || Constat::NonObserve {
                    cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
                    detail: "gestionnaire injoignable".to_string(),
                },
                Err("x".to_string()),
                "echec",
            ),
        ];
        for (avant, apres, attendu) in cas {
            let mut r = Outcome::pose();
            r.observe("a", avant(), || apres);
            let got = if !r.failures().is_empty() {
                "echec"
            } else if !r.sans_avant().is_empty() {
                "sans-avant"
            } else if r.a_change() {
                "change"
            } else {
                "deja"
            };
            assert_eq!(got, attendu, "attendu {attendu}");
        }
    }

    /// LE TROISIÈME CAS SE DIT, ET IL NE SE DIT NI « POSÉ » NI « DÉJÀ EN PLACE ». C'est la forme du
    /// troisième verdict de `S33`, portée ici : quand l'état antérieur n'a pas pu être interrogé,
    /// le rapport VÉRIFIE l'état voulu, l'écrit, et refuse d'affirmer qu'il n'y avait rien à faire.
    #[test]
    fn un_etat_anterieur_non_observe_n_est_ni_pose_ni_deja_en_place() {
        let mut r = Outcome::pose();
        r.observe(
            "service plume-agent.service (actif au boot et maintenant)",
            Constat::NonObserve {
                cause: crate::lisibilite::CAUSE_SOURCE_ILLISIBLE,
                detail: "`systemctl is-active` n'a rendu AUCUN mot".to_string(),
            },
            || Ok(()),
        );
        assert!(!r.a_change(), "on ne peut pas affirmer un changement qu'on n'a pas mesuré");
        assert!(r.failures().is_empty(), "l'état voulu EST vérifié : ce n'est pas un échec");
        assert_eq!(r.sans_avant().len(), 1);
        let txt = r.render();
        assert!(txt.contains("ATTEINT"), "{txt}");
        assert!(txt.contains("état ANTÉRIEUR non observé"), "{txt}");
        assert!(txt.contains("AUCUN mot"), "l'aveu de la lecture est rendu tel quel : {txt}");
        assert!(!txt.contains("posé     :"), "{txt}");
        assert!(
            !txt.contains("AUCUNE pose effectuée"),
            "« il n'y avait rien à faire » est précisément ce qu'on ne sait pas : {txt}"
        );
    }

    /// LE TÉMOIN INVERSE DU PRÉCÉDENT — sans lui, un `render` qui dirait TOUJOURS « état antérieur
    /// non observé » passerait le test ci-dessus sans rien prouver, et le cas nominal (une pose
    /// idempotente sur un hôte parfaitement interrogeable) aurait disparu.
    #[test]
    fn une_observation_qui_a_eu_lieu_ne_porte_aucune_reserve() {
        let mut r = Outcome::pose();
        r.observe("service plume-agent.service (actif)", Constat::mesure(true), || Ok(()));
        assert!(r.sans_avant().is_empty());
        let txt = r.render();
        assert!(!txt.contains("ATTEINT"), "{txt}");
        assert!(txt.contains("AUCUNE pose effectuée"), "{txt}");
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
