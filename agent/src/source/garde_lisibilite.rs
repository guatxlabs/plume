// `S36` — LA GARDE DÉRIVÉE DE LA SURFACE D'ENTRÉE DE L'AGENT.
//
// CE QU'ELLE REFUSE, ET POURQUOI ELLE N'ÉNUMÈRE AUCUN LECTEUR. Le défaut de cette surface n'est pas
// un site : c'est une FORME. Tout lecteur de source pouvait rendre `Vec::new()` sur un chemin
// d'échec, et un lot vide est ce que rend une source lue dont il ne s'est rien passé. La première
// jambe de la garde est donc le TYPE : `Releve` n'a ni `Default` ni conversion depuis un `Vec`, et
// ses trois constructeurs sont NOMMÉS — un lecteur écrit demain ne peut pas rendre « rien » sans
// choisir entre `lu`, `illisible` et `partiel`. Le compilateur refuse l'ancien défaut.
//
// LA SECONDE JAMBE EST CELLE-CI, ET ELLE EST DÉRIVÉE DE L'ÉNUMÉRATION DES FORMES DE SOURCE. Le
// `match` de `forme_de` est EXHAUSTIF : une forme de source ajoutée à `SourceCfg` fait échouer la
// COMPILATION de cette garde tant que son auteur ne l'a pas classée, et le `match` de
// `cas_de_la_forme` la force ensuite à fournir ses témoins ou à écrire sa dispense. Une huitième
// forme livrée demain est donc contrôlée d'office, sans que personne n'ait à y penser.
//
// LES DEUX TÉMOINS, ET LE SECOND EST LE CŒUR :
//   ① SOURCE RETIRÉE -> verdict `illisible`, cause DANS l'ensemble fermé, raison DANS l'ensemble
//      fermé, et AUCUN enregistrement. C'est le défaut d'origine.
//   ② SOURCE PRÉSENTE ET RÉELLEMENT VIDE -> verdict `lu`, et zéro enregistrement. Sans ce témoin, un
//      lecteur qui crierait « illisible » en permanence passerait ① sans rien prouver — et il serait
//      le défaut symétrique, exactement aussi grave : il noierait le SOC d'aveux faux et ferait
//      disparaître le cas nominal, celui d'un hôte calme.
//
// CE QUI EST HORS PÉRIMÈTRE, ET POURQUOI C'EST DIT. Trois formes lisent un SOUS-SYSTÈME DE L'HÔTE
// que la garde ne paramètre pas (journald, journal d'événements Windows, unified log macOS) : les
// exercer ferait dépendre le verdict de la machine qui exécute la garde — présence de `journalctl`,
// droits sur le canal `Security`, version de `log`. Elles sont donc DISPENSÉES des témoins exécutés,
// et la garde exerce à leur place le lecteur de REPLI qu'elles reçoivent sur tout OS où le
// sous-système n'existe pas. La dispense est écrite, pas implicite.

#![cfg(test)]

use super::{build_reader, SourceReader, UnsupportedReader};
use crate::config::{CommandCfg, FileCfg, FimCfg, HttpCfg, JournaldCfg, OsLogCfg, SourceCfg, TlsConfig, WinEventCfg};
use crate::lisibilite::{CAUSES, RAISONS, VERDICT_ILLISIBLE, VERDICT_LU};
use std::path::{Path, PathBuf};

/// Plancher de NON-DÉGÉNÉRESCENCE : sous ce nombre de formes réellement exercées, c'est l'instrument
/// qui est cassé, pas la surface. La garde refuse alors de conclure au lieu de rendre vert en étant
/// aveugle. Quatre formes sont exerçables sans rien emprunter à la machine : file, command, http, fim.
#[cfg(unix)]
const MIN_FORMES_EXERCEES: usize = 4;
/// LE PLANCHER EST PLUS BAS HORS UNIX, ET C'EST DIT PLUTÔT QUE SUBI. Le témoin ② de la forme
/// `command` demande de fabriquer un exécutable qui n'écrit rien : poser un bit d'exécution est une
/// notion Unix, et la garde préfère ne PAS compter cette forme là où elle ne sait pas la fabriquer
/// plutôt que de la déclarer couverte. Son témoin ① (binaire introuvable) reste exercé partout.
#[cfg(not(unix))]
const MIN_FORMES_EXERCEES: usize = 3;

/// Les formes de source déclarables. Ce type n'existe QUE pour rendre la garde dérivée : le `match`
/// de `forme_de` ci-dessous est exhaustif sur `SourceCfg`, donc une variante ajoutée là-bas ne
/// compile plus ici tant qu'elle n'a pas été classée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forme {
    Journald,
    Wineventlog,
    Oslog,
    Fim,
    Fichier,
    Commande,
    Http,
}

/// EXHAUSTIF PAR CONSTRUCTION — c'est ce `match` qui casse quand une forme de source est ajoutée.
fn forme_de(c: &SourceCfg) -> Forme {
    match c {
        SourceCfg::Journald(_) => Forme::Journald,
        SourceCfg::Wineventlog(_) => Forme::Wineventlog,
        SourceCfg::Oslog(_) => Forme::Oslog,
        SourceCfg::Fim(_) => Forme::Fim,
        SourceCfg::File(_) => Forme::Fichier,
        SourceCfg::Command(_) => Forme::Commande,
        SourceCfg::Http(_) => Forme::Http,
    }
}

/// Toutes les formes, une configuration par forme. Le `match` est exhaustif sur `Forme` : l'auteur
/// d'une forme nouvelle DOIT écrire ici comment on la fabrique.
fn toutes_les_formes(tmp: &Path) -> Vec<SourceCfg> {
    [
        Forme::Journald,
        Forme::Wineventlog,
        Forme::Oslog,
        Forme::Fim,
        Forme::Fichier,
        Forme::Commande,
        Forme::Http,
    ]
    .into_iter()
    .map(|f| config_de(f, tmp))
    .collect()
}

fn config_de(f: Forme, tmp: &Path) -> SourceCfg {
    match f {
        Forme::Journald => SourceCfg::Journald(JournaldCfg::default()),
        Forme::Wineventlog => SourceCfg::Wineventlog(WinEventCfg {
            id: "winlog".into(),
            channels: vec!["Security".into()],
            query: String::new(),
        }),
        Forme::Oslog => SourceCfg::Oslog(OsLogCfg {
            id: "oslog".into(),
            predicate: None,
            since: "5m".into(),
        }),
        Forme::Fim => SourceCfg::Fim(FimCfg {
            id: "integrite".into(),
            paths: vec![tmp.join("arbre-surveille").to_string_lossy().into_owned()],
            ..FimCfg::default()
        }),
        Forme::Fichier => SourceCfg::File(FileCfg {
            name: "journal-applicatif".into(),
            path: tmp.join("applicatif.log").to_string_lossy().into_owned(),
            category: "application".into(),
            severity: 2,
            parser: None,
            from_start: true,
        }),
        Forme::Commande => SourceCfg::Command(CommandCfg {
            name: "sonde".into(),
            // Fabriquée SOUS le temporaire : présente ou absente selon le témoin, jamais selon la
            // machine. Un chemin absolu évite d'hériter du `PATH` de qui exécute la garde.
            cmd: tmp.join("sonde-fabriquee").to_string_lossy().into_owned(),
            args: vec![],
            interval: 0,
            category: "custom".into(),
            severity: 1,
            parser: None,
            max_lines: 100,
        }),
        Forme::Http => SourceCfg::Http(HttpCfg {
            name: "poll".into(),
            // Port 1 en bouclage : refus de connexion IMMÉDIAT, sans réseau et sans résolution DNS.
            url: "http://127.0.0.1:1/flux".into(),
            interval: 0,
            category: "custom".into(),
            severity: 1,
            parser: None,
            max_lines: 100,
        }),
    }
}

/// Ce que la garde sait exercer pour une forme donnée. Exhaustif sur `Forme` : une forme nouvelle
/// doit CHOISIR entre fournir ses témoins et écrire sa dispense.
enum Cas {
    /// La source est entièrement fabriquée par la garde : les DEUX témoins sont exécutés.
    DeuxTemoins,
    /// Seul le témoin ① est exécutable : le second demanderait un serveur, et la garde n'en monte
    /// pas (elle ne doit rien emprunter à la machine, réseau compris).
    TemoinIllisibleSeul,
    /// Dispensée des témoins exécutés, avec sa raison ÉCRITE. Le lecteur de repli est exercé à la
    /// place — c'est lui que reçoit tout OS où le sous-système n'existe pas.
    Dispensee(&'static str),
}

fn cas_de_la_forme(f: Forme) -> Cas {
    match f {
        Forme::Journald => Cas::Dispensee(
            "lit `journalctl`, un sous-système de l'hôte que la garde ne paramètre pas : le verdict \
             dépendrait de la présence du binaire et des droits sur le journal de la machine de CI",
        ),
        Forme::Wineventlog => Cas::Dispensee(
            "lit le journal d'événements Windows par FFI : hors d'un hôte Windows, il n'y a rien à \
             exercer, et sur un hôte Windows le verdict dépendrait des droits sur le canal",
        ),
        Forme::Oslog => Cas::Dispensee(
            "lit l'unified log macOS via `log show` : même raison, et le binaire n'existe pas ailleurs",
        ),
        Forme::Fim => Cas::DeuxTemoins,
        Forme::Fichier => Cas::DeuxTemoins,
        Forme::Commande => Cas::DeuxTemoins,
        // Le témoin ② demanderait un serveur HTTP : la garde n'en monte pas. Le témoin ① n'a besoin
        // de rien — un port fermé en bouclage refuse la connexion sans réseau.
        Forme::Http => Cas::TemoinIllisibleSeul,
    }
}

/// Un répertoire temporaire POSSÉDÉ : rien de la machine qui exécute la garde n'entre dans un verdict.
struct TmpPossede(PathBuf);

impl TmpPossede {
    fn neuf(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("plume-s36-garde-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temporaire possédé");
        Self(d)
    }
    fn chemin(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpPossede {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn lecteur(cfg: &SourceCfg, etat: &Path) -> Box<dyn SourceReader> {
    let mut r = build_reader(cfg, "hote-de-garde", etat, &TlsConfig::default());
    r.open(super::Cursor(None));
    r
}

/// Fabrique la source de la forme, de sorte qu'elle existe ET soit RÉELLEMENT VIDE (témoin ②).
/// Renvoie `false` si la garde ne sait pas la fabriquer (elle ne prétend alors pas l'avoir exercée).
fn fabriquer_source_vide(f: Forme, tmp: &Path) -> bool {
    match f {
        Forme::Fichier => {
            std::fs::write(tmp.join("applicatif.log"), b"").is_ok()
        }
        Forme::Fim => std::fs::create_dir_all(tmp.join("arbre-surveille")).is_ok(),
        Forme::Commande => fabriquer_commande_muette(&tmp.join("sonde-fabriquee")),
        _ => false,
    }
}

/// Une commande qui n'écrit RIEN et sort en succès — fabriquée par la garde, jamais empruntée à
/// l'hôte. Sans elle, le témoin ② de la forme `command` dépendrait des utilitaires installés.
#[cfg(unix)]
fn fabriquer_commande_muette(chemin: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::write(chemin, b"#!/bin/sh\nexit 0\n").is_err() {
        return false;
    }
    std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o755)).is_ok()
}

#[cfg(not(unix))]
fn fabriquer_commande_muette(_chemin: &Path) -> bool {
    // Pas de bit d'exécution portable ici : la forme `command` n'est pas exercée sur cette
    // plateforme, et la garde le DIT plutôt que de prétendre l'avoir couverte.
    false
}

/// LA GARDE. Elle ne nomme aucun lecteur : elle balaie les formes de source déclarables, et pour
/// chacune exige soit ses deux témoins, soit une dispense écrite.
#[test]
fn aucune_source_ne_peut_rendre_un_lot_vide_sans_dire_si_elle_a_lu() {
    let tmp = TmpPossede::neuf("formes");
    let etat = tmp.chemin().join("etat");
    std::fs::create_dir_all(&etat).unwrap();
    let mut exercees = 0usize;
    let mut dispensees: Vec<(Forme, &'static str)> = Vec::new();

    for cfg in toutes_les_formes(tmp.chemin()) {
        let f = forme_de(&cfg);
        match cas_de_la_forme(f) {
            Cas::Dispensee(pourquoi) => {
                assert!(!pourquoi.is_empty(), "une dispense sans raison écrite n'est pas une dispense");
                dispensees.push((f, pourquoi));
                // Le lecteur de REPLI, lui, est exercé : c'est ce que reçoit tout OS dépourvu du
                // sous-système, et il ne doit pas non plus se lire « rien à signaler ».
                let mut repli = UnsupportedReader::new(format!("{f:?}"), "sous-système absent");
                let r = repli.next_batch(10);
                assert_eq!(
                    r.lisibilite.verdict(),
                    VERDICT_ILLISIBLE,
                    "{f:?} : le lecteur de repli doit AVOUER, pas rendre un lot calme"
                );
                assert!(r.records.is_empty());
                continue;
            }
            Cas::DeuxTemoins | Cas::TemoinIllisibleSeul => {}
        }

        // ① LA SOURCE N'EST PAS LÀ (ou n'est pas joignable) : verdict d'échec, cause et raison
        //    NOMMÉES dans leurs ensembles fermés, et AUCUN enregistrement.
        let mut r = lecteur(&cfg, &etat);
        let releve = r.next_batch(50);
        assert_eq!(
            releve.lisibilite.verdict(),
            VERDICT_ILLISIBLE,
            "{f:?} : une source absente ou injoignable ne doit pas se lire « rien à signaler »"
        );
        assert!(
            CAUSES.contains(&releve.lisibilite.cause()),
            "{f:?} : cause hors de l'ensemble fermé : {:?}",
            releve.lisibilite.cause()
        );
        assert!(
            RAISONS.contains(&releve.raison),
            "{f:?} : raison hors du vocabulaire du contrat d'indisponibilité : {:?}",
            releve.raison
        );
        assert!(releve.records.is_empty(), "{f:?} : une source illisible ne rend aucun enregistrement");
        assert!(
            releve.lisibilite.detail().map(|d| !d.is_empty()).unwrap_or(false),
            "{f:?} : un aveu sans détail ne se répare pas"
        );

        if matches!(cas_de_la_forme(f), Cas::TemoinIllisibleSeul) {
            exercees += 1;
            continue;
        }

        // ② LA SOURCE EST LÀ ET RÉELLEMENT VIDE : verdict `lu`, et zéro enregistrement. C'est ce
        //    témoin qui interdit à un lecteur de crier « illisible » en permanence.
        if !fabriquer_source_vide(f, tmp.chemin()) {
            // La garde ne sait pas fabriquer cette source ici : elle ne compte PAS la forme comme
            // exercée, plutôt que de la déclarer couverte sans l'avoir vue.
            continue;
        }
        let etat2 = tmp.chemin().join(format!("etat-{f:?}"));
        std::fs::create_dir_all(&etat2).unwrap();
        let mut r = lecteur(&cfg, &etat2);
        let releve = r.next_batch(50);
        assert_eq!(
            releve.lisibilite.verdict(),
            VERDICT_LU,
            "{f:?} : une source PRÉSENTE et réellement vide doit être LUE ({:?})",
            releve.lisibilite.detail()
        );
        assert!(
            releve.records.is_empty(),
            "{f:?} : une source réellement vide ne fabrique pas d'enregistrement"
        );
        exercees += 1;
    }

    // PLANCHER DE NON-DÉGÉNÉRESCENCE : sous ce seuil, c'est la garde qui est cassée.
    assert!(
        exercees >= MIN_FORMES_EXERCEES,
        "seulement {exercees} forme(s) réellement exercée(s) (plancher {MIN_FORMES_EXERCEES}) — \
         l'instrument ne voit plus rien, il ne doit pas conclure. Dispensées : {dispensees:?}"
    );
    // Et la garde DIT ce qu'elle ne prouve pas, plutôt que de laisser croire à une couverture totale.
    assert!(
        dispensees.len() <= 3,
        "plus de formes dispensées que prévu : {dispensees:?} — une dispense doit rester l'exception"
    );
}

/// LA RÉFÉRENCE D'INTÉGRITÉ — LA PAIRE, ET C'EST LE SILENCE LE PLUS COÛTEUX DE CETTE SURFACE.
///
/// ① Une référence PRÉSENTE mais dont la forme n'est pas comprise ne doit PAS se lire « premier
///    passage » : le premier passage sème en silence, et tout ce qui a changé depuis la dernière
///    référence valide serait absorbé sans qu'aucun événement ne soit émis.
/// ② Une référence ABSENTE, elle, EST un vrai premier passage : elle est LUE, vide, et sème sans
///    bruit. Sans ce second témoin, la correction rendrait chaque installation neuve bruyante — et
///    ferait disparaître le cas nominal.
#[test]
fn une_reference_d_integrite_illisible_ne_se_lit_pas_comme_un_premier_passage() {
    use crate::lisibilite::Lecture;
    use crate::source::fim::Baseline;

    let tmp = TmpPossede::neuf("reference");
    let absente = tmp.chemin().join("jamais-ecrite.json");
    // ② le cas nominal d'abord.
    match Baseline::load(&absente) {
        Lecture::Lue(b) => assert!(b.is_empty(), "référence absente -> premier passage, vide et LUE"),
        Lecture::Illisible { cause, .. } => panic!("une référence jamais écrite doit être LUE : {cause}"),
    }

    // ① présente, lue, mais ce n'est pas une référence.
    let corrompue = tmp.chemin().join("corrompue.json");
    std::fs::write(&corrompue, b"ceci n'est pas une reference d'integrite").unwrap();
    let v = Baseline::load(&corrompue);
    assert_eq!(v.verdict(), VERDICT_ILLISIBLE, "une référence corrompue n'est pas un premier passage");
    assert_eq!(v.cause(), crate::lisibilite::CAUSE_FORME_INCONNUE);

    // ① bis — une référence dont CERTAINES entrées sont illisibles est partielle, donc fausse : elle
    // produirait des « créations » pour des fichiers présents depuis toujours.
    let partielle = tmp.chemin().join("partielle.json");
    std::fs::write(&partielle, br#"{"/etc/passwd":{"s":1,"m":420,"u":0,"g":0,"t":1},"/etc/shadow":"pas un objet"}"#).unwrap();
    let v = Baseline::load(&partielle);
    assert_eq!(v.verdict(), VERDICT_ILLISIBLE, "une référence partielle n'est pas une référence");

    // ② bis — une référence bien formée est LUE, et ses entrées sont là.
    let bonne = tmp.chemin().join("bonne.json");
    std::fs::write(&bonne, br#"{"/etc/passwd":{"h":"ab","s":1,"m":420,"u":0,"g":0,"t":1}}"#).unwrap();
    match Baseline::load(&bonne) {
        Lecture::Lue(b) => assert_eq!(b.len(), 1, "une référence bien formée est lue telle quelle"),
        Lecture::Illisible { detail, .. } => panic!("référence bien formée refusée : {detail}"),
    }
}
