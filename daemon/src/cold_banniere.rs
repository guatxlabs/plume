//! CE QUE LE DÉMON DIT DE SON TIER FROID AU DÉMARRAGE — trois états, dont celui que rien ne disait.
//!
//! LE DÉFAUT QU'IL FERME, MESURÉ LE 2026-08-05. En production le démon gère **157 Mio répartis en 59
//! fichiers-jour Parquet** et n'en dit RIEN au démarrage : `kubectl logs … | grep -i cold` rend ZÉRO
//! ligne, AVANT comme APRÈS l'activation de la fonctionnalité. C'est ce mutisme qui a rendu invisible
//! pendant TROIS JOURS le fait que la capacité avait disparu du binaire : la production déclarait
//! `PLUME_COLD_TIER=1` et quatre autres variables, le démon ne les honorait pas, et absolument rien ne
//! le disait. Un composant qui travaille sans le dire est INDISTINGUABLE d'un composant ABSENT — et
//! c'est exactement ce qui s'est produit.
//!
//! TROIS ÉTATS EXCLUSIFS, d'où un type et un `match` EXHAUSTIF (aucun bras `_`) : un quatrième état
//! inventé demain ne compile pas tant que sa phrase n'est pas écrite.
//!   1. la capacité n'est pas COMPILÉE dans ce binaire (`--features cold_tier` absent) ;
//!   2. elle est compilée mais DÉSACTIVÉE à l'exécution (`PLUME_COLD_TIER` absent ou ≠ 1) ;
//!   3. elle est compilée ET active — et alors la ligne publie ce qui se VÉRIFIE : le répertoire, la
//!      fenêtre chaude, la rétention cold, le nombre de fichiers-jour sur le disque et leur volume.
//!
//! LE CAS (1) N'EST PAS UNE INFORMATION NEUTRE dès que `PLUME_COLD_TIER=1` est posé : la variable
//! PROMET une capacité que le binaire NE PEUT PAS rendre. La ligne le traite donc comme une ANOMALIE
//! DE CONFIGURATION, et nomme les variables `PLUME_COLD_*` qui resteront sans effet — DÉRIVÉES du
//! préfixe, jamais énumérées : une variable de tier froid ajoutée demain est dénoncée le jour même,
//! sans que personne ait à tenir une liste à jour.
//!
//! LA CONTRAINTE QUI DÉCIDE DE LA FORME DU MODULE. `cold_store` n'existe QUE sous
//! `--features cold_tier` : une bannière écrite LÀ-BAS ne pourrait, par construction, JAMAIS dire le
//! cas (1) — le seul qui était invisible. D'où la découpe : le TYPE et les PHRASES vivent ici, hors de
//! tout gate (donc dans les DEUX binaires) ; seule la RÉCOLTE de l'état a deux corps
//! (`#[cfg(feature)]` / `#[cfg(not(feature))]`), à l'image de `SUBCOMMANDS_COLD` dans `main.rs`.
//!
//! CE QUE ÇA COÛTE AU DÉMARRAGE, sous la contrainte dure de 2 Gio : un `readdir` de la racine cold et
//! d'un niveau de sous-répertoires, plus un `stat` par fichier `.parquet` — BORNÉ à `PLAFOND_ENTREES`.
//! AUCUNE lecture de la table `event`, AUCUN déchiffrement Parquet, AUCUNE requête sur l'index
//! `cold_seal`. À la volumétrie de production (59 fichiers) c'est une poignée de syscalls ; au plafond
//! l'inventaire est PARTIEL et il le DIT, plutôt que de ralentir le démarrage (cf. `Inventaire`).
//!
//! CE QUE CE MODULE NE FERME PAS, écrit pour être opposable :
//!   - il dit l'ÉTAT, jamais la SANTÉ. Un aging qui échoue à chaque tour, un fichier corrompu, un seal
//!     orphelin ne se voient pas ici : la ligne est un point de départ d'enquête, pas un verdict.
//!   - l'inventaire lit le DISQUE, pas l'index `cold_seal`. Un fichier écrit mais non scellé (crash
//!     entre l'écriture et le seal) est COMPTÉ ici alors qu'il ne sera jamais lu ; l'écart entre les
//!     deux comptes n'est pas publié.
//!   - il décrit le TENANT PAR DÉFAUT (`PLUME_DB`). En mode `PLUME_MULTI_TENANT`, chaque tenant a sa
//!     propre racine cold (cf. `cold_store::cold_root`) et elles ne sont PAS énumérées ici.
//!   - c'est une ligne de DÉMARRAGE : elle ne dit rien de ce que devient le tier froid ensuite.
use crate::*;
use std::path::{Path, PathBuf};

/// Préfixe des variables d'exploitation du tier froid. La liste des variables n'est jamais ÉCRITE :
/// elle est DÉRIVÉE de ce préfixe sur l'environnement ET le fichier de conf, donc une variable
/// `PLUME_COLD_*` ajoutée demain est couverte le jour où elle est ajoutée.
const PREFIXE_COLD: &str = "PLUME_COLD_";

/// PLAFOND D'ENTRÉES examinées par l'inventaire de démarrage. Un `stat` coûte des microsecondes, mais
/// un démarrage n'a pas à en payer un nombre non borné : au-delà, le balayage S'ARRÊTE et les deux
/// comptes deviennent des MINORANTS annoncés comme tels. Dimensionné TRÈS au-dessus du réel : à
/// `COLD_FILE_MAX_ROWS` lignes par fichier, 10 000 fichiers-jour valent des centaines de Gio — la
/// production en compte 59 (2026-08-05).
const PLAFOND_ENTREES: usize = 10_000;

/// CE QUE LE BINAIRE SAIT FAIRE, ET CE QU'IL FAIT. Trois cas EXCLUSIFS : le premier est une propriété
/// du BINAIRE (compilation), les deux autres une propriété de la CONFIGURATION. Les confondre est
/// exactement la faute payée en production — d'où trois variantes et aucun booléen.
pub(crate) enum EtatTierFroid {
    /// (1) La capacité n'est pas DANS ce binaire (`--features cold_tier` absent au build).
    /// `demande` = `PLUME_COLD_TIER=1` est posé -> la configuration promet ce que le binaire ne peut
    /// pas rendre : ANOMALIE. `variables_ignorees` = les `PLUME_COLD_*` posées et sans effet.
    NonCompile { demande: bool, variables_ignorees: Vec<String> },
    /// (2) Compilée, mais le gate RUNTIME est fermé : rien n'âge, rien n'est relu en Parquet.
    Inactif,
    /// (3) Compilée ET active : les nombres qui suivent sont ceux que le processus applique.
    Actif { racine: PathBuf, fenetre_chaude_jours: i64, retention_jours: i64, inventaire: Inventaire },
}

/// CE QU'IL Y A SUR LE DISQUE — et, quand ce n'est pas mesurable, le fait qu'on ne l'a PAS mesuré.
/// Un « 0 fichier » rendu par un répertoire absent et un « 0 fichier » rendu par un répertoire vide
/// sont deux faits DIFFÉRENTS (le premier est souvent un `PLUME_COLD_DIR` fautif) : les rendre par le
/// même nombre, c'est lire « ça passe » là où il faut lire « je n'ai pas mesuré ».
pub(crate) struct Inventaire {
    /// `false` : la racine n'existe pas ou n'est pas lisible -> les compteurs ne sont PAS une mesure.
    pub(crate) racine_lisible: bool,
    pub(crate) fichiers: usize,
    pub(crate) octets: u64,
    /// `Some(n)` : le balayage s'est ARRÊTÉ après `n` entrées -> les deux compteurs sont des MINORANTS.
    pub(crate) borne: Option<usize>,
    /// Entrées ou sous-répertoires que le balayage N'A PAS SU LIRE (`P4.1-r`) : chacun cache un nombre
    /// inconnu de fichiers-jour, donc les deux compteurs sont des MINORANTS — comme sous `borne`. Avant,
    /// ils étaient sautés en silence et l'inventaire se présentait comme complet.
    pub(crate) illisibles: usize,
}

impl Inventaire {
    /// PURE, donc exerçable dans les trois formes (mesuré / borné / non mesuré) sans toucher au disque.
    pub(crate) fn phrase(&self) -> String {
        if !self.racine_lisible {
            return "répertoire ABSENT ou ILLISIBLE — RIEN n'a été compté (aucun fichier-jour n'a donc \
                    été observé, ce qui n'est PAS la même chose que zéro)"
                .to_string();
        }
        let phrase = match self.borne {
            Some(n) => format!(
                "≥{} fichier(s)-jour, ≥{} sur le disque — balayage ARRÊTÉ à {n} entrées : inventaire \
                 PARTIEL, ces deux nombres sont des MINORANTS et jamais un total",
                self.fichiers,
                mio(self.octets)
            ),
            None if self.illisibles > 0 => format!(
                "≥{} fichier(s)-jour, ≥{} sur le disque — {} entrée(s) ou sous-répertoire(s) ILLISIBLE(S) \
                 non comptés : ces deux nombres sont des MINORANTS et jamais un total",
                self.fichiers,
                mio(self.octets),
                self.illisibles
            ),
            None => format!("{} fichier(s)-jour, {} sur le disque", self.fichiers, mio(self.octets)),
        };
        if self.borne.is_some() && self.illisibles > 0 {
            return format!("{phrase} ; {} entrée(s) illisible(s) de surcroît", self.illisibles);
        }
        phrase
    }
}

/// PURE — c'est la forme qui rend la bannière opposable : les TROIS cas se lisent sans base, sans
/// disque et sans démarrage. Le `match` est EXHAUSTIF (aucun bras `_`).
pub(crate) fn banniere(etat: EtatTierFroid) -> String {
    match etat {
        EtatTierFroid::NonCompile { demande, variables_ignorees } => {
            let liste = if variables_ignorees.is_empty() {
                String::new()
            } else {
                format!(
                    " {} variable(s) PLUME_COLD_* posée(s) et SANS EFFET dans ce binaire : {}.",
                    variables_ignorees.len(),
                    variables_ignorees.join(", ")
                )
            };
            if demande {
                format!(
                    "tier froid NON COMPILÉ dans ce binaire (bâti sans `--features cold_tier`) ALORS QUE \
                     PLUME_COLD_TIER=1 est posé — ANOMALIE DE CONFIGURATION : cette variable promet une \
                     capacité que ce binaire NE PEUT PAS rendre. Rien n'est columnarisé, rien n'est relu \
                     en Parquet, et des fichiers-jour écrits par un autre binaire seraient INVISIBLES à \
                     celui-ci.{liste} Corriger : bâtir avec `--features cold_tier`, ou retirer ces variables."
                )
            } else {
                format!(
                    "tier froid NON COMPILÉ dans ce binaire (bâti sans `--features cold_tier`) et NON \
                     DEMANDÉ (PLUME_COLD_TIER ≠ 1) : tout vit dans le hot SQLite.{liste}"
                )
            }
        }
        EtatTierFroid::Inactif => "tier froid COMPILÉ dans ce binaire mais DÉSACTIVÉ à l'exécution \
                                   (PLUME_COLD_TIER ≠ 1) : aucun jour n'est columnarisé, aucun Parquet \
                                   n'est relu — tout vit dans le hot SQLite. PLUME_COLD_TIER=1 l'allume."
            .to_string(),
        EtatTierFroid::Actif { racine, fenetre_chaude_jours, retention_jours, inventaire } => format!(
            "tier froid ACTIF — racine {}, fenêtre chaude {fenetre_chaude_jours} j (au-delà, un jour \
             révolu part en Parquet et quitte le hot), rétention cold {retention_jours} j, {}",
            racine.display(),
            inventaire.phrase()
        ),
    }
}

/// L'unité que lit un exploitant. Un volume en octets bruts se relit mal à 3 h du matin.
fn mio(octets: u64) -> String {
    format!("{:.1} Mio", octets as f64 / (1024.0 * 1024.0))
}

/// LES VARIABLES DU TIER FROID RÉELLEMENT POSÉES, DÉRIVÉES DU PRÉFIXE — jamais une liste écrite à la
/// main (elle divergerait le jour où une variable est ajoutée, c'est-à-dire le jour où on en a besoin).
/// Les deux SOURCES que `cfg` consulte sont couvertes : l'environnement ET le fichier de conf.
/// PURE (l'environnement est PASSÉ, pas lu) -> testable sans muter `std::env`, ce qui empoisonnerait
/// les tests tournant en parallèle.
fn variables_cold_posees(conf: &HashMap<String, String>, cles_env: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = conf
        .keys()
        .cloned()
        .chain(cles_env)
        .filter(|k| k.starts_with(PREFIXE_COLD))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// LE GATE RUNTIME, LU EXACTEMENT COMME LE TIER FROID LE LIT (`== "1"`, cf.
/// `cold_store::cold_tier_runtime_on` et les gates de `aging`/`rollups`). Une lecture plus permissive
/// ici rendrait la bannière fausse d'un côté ou de l'autre : elle annoncerait une activation que le
/// gate refuse. Sous `--features cold_tier`, l'égalité des deux lectures est EXERCÉE (cf. tests).
fn cold_tier_demande(conf: &HashMap<String, String>) -> bool {
    cfg(conf, "PLUME_COLD_TIER", "") == "1"
}

/// CE QU'IL Y A SUR LE DISQUE, BORNÉ. Layout attendu : `<racine>/<env_id>/<YYYY-MM-DD>-<NNNN>.parquet`
/// (cf. `cold_store::paths`) ; on compte aussi les `.parquet` posés directement sous la racine, pour
/// qu'un `PLUME_COLD_DIR` pointé un cran trop bas ne se lise pas « vide ». Le type d'entrée vient de
/// `readdir` (`d_type`), donc AUCUN `stat` n'est payé pour les répertoires ; un `stat` n'est payé que
/// pour un fichier `.parquet`, dont on veut la taille.
pub(crate) fn inventaire(racine: &Path, plafond: usize) -> Inventaire {
    let mut inv = Inventaire { racine_lisible: false, fichiers: 0, octets: 0, borne: None, illisibles: 0 };
    let Ok(entrees) = std::fs::read_dir(racine) else {
        return inv; // racine absente/illisible : on n'a RIEN mesuré, et `racine_lisible` le dit.
    };
    inv.racine_lisible = true;
    let mut examinees = 0usize;
    for e in entrees {
        // Une entrée que l'énumération refuse est un fichier-jour qu'on ne verra pas : COMPTÉE, et
        // l'inventaire se dit MINORANT — avant, `filter_map(Result::ok)` la taisait.
        let e = match e {
            Ok(e) => e,
            Err(_) => {
                inv.illisibles += 1;
                continue;
            }
        };
        if examinees >= plafond {
            inv.borne = Some(examinees);
            return inv;
        }
        examinees += 1;
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            // Un sous-répertoire (un environnement) qu'on ne sait pas lister cache un nombre inconnu de
            // fichiers-jour : compté comme illisible, jamais sauté en silence.
            let sous = match std::fs::read_dir(e.path()) {
                Ok(s) => s,
                Err(_) => {
                    inv.illisibles += 1;
                    continue;
                }
            };
            for s in sous {
                let s = match s {
                    Ok(s) => s,
                    Err(_) => {
                        inv.illisibles += 1;
                        continue;
                    }
                };
                if examinees >= plafond {
                    inv.borne = Some(examinees);
                    return inv;
                }
                examinees += 1;
                compte_fichier_jour(&s.path(), &mut inv);
            }
        } else {
            compte_fichier_jour(&e.path(), &mut inv);
        }
    }
    inv
}

/// Un fichier-jour, et rien d'autre : les `.tmp` d'une écriture en cours ne sont PAS des fichiers-jour
/// (ils ne sont ni scellés ni lisibles) — les compter gonflerait un inventaire qui doit rester vrai.
fn compte_fichier_jour(chemin: &Path, inv: &mut Inventaire) {
    if chemin.extension().and_then(|e| e.to_str()) != Some("parquet") {
        return;
    }
    inv.fichiers += 1;
    inv.octets += std::fs::metadata(chemin).map(|m| m.len()).unwrap_or(0);
}

/// LA RÉCOLTE, CORPS « CAPACITÉ PRÉSENTE ». Les nombres publiés sont ceux que le processus APPLIQUE :
/// la fenêtre chaude vient de la source unique de l'aging (clamp compris), la rétention cold de la
/// même fonction que le hard-purge hot. Les publier depuis les variables brutes annoncerait des
/// valeurs que le clamp peut contredire.
#[cfg(feature = "cold_tier")]
pub(crate) fn etat(conn: &Connection, conf: &HashMap<String, String>, db_path: &str) -> EtatTierFroid {
    if !cold_store::cold_tier_runtime_on(conf) {
        return EtatTierFroid::Inactif; // gate fermé -> on ne touche NI la base NI le disque.
    }
    let retention_globale = retention_effective(conn, conf, "retention_days");
    let racine = cold_store::cold_root(conf, db_path);
    let inv = inventaire(&racine, PLAFOND_ENTREES);
    EtatTierFroid::Actif {
        fenetre_chaude_jours: cold_store::cold_hot_window_days(conn, conf, retention_globale),
        retention_jours: cold_store::cold_retention_days(conf, retention_globale),
        racine,
        inventaire: inv,
    }
}

/// LA RÉCOLTE, CORPS « CAPACITÉ ABSENTE » — celui qui n'existait pas, et sans lequel les trois jours
/// de silence se reproduiraient à l'identique. Il ne peut RIEN dire du tier froid (le module qui le
/// sait n'est pas compilé) : il dit ce qu'il sait, c'est-à-dire ce que la CONFIGURATION demande et que
/// ce binaire ne rendra pas.
#[cfg(not(feature = "cold_tier"))]
pub(crate) fn etat(_conn: &Connection, conf: &HashMap<String, String>, _db_path: &str) -> EtatTierFroid {
    EtatTierFroid::NonCompile {
        demande: cold_tier_demande(conf),
        variables_ignorees: variables_cold_posees(conf, std::env::vars().map(|(k, _)| k)),
    }
}

#[cfg(test)]
mod cold_banniere_tests {
    use super::*;
    // Le scanner de SOURCES est celui de `db_open` (LA PORTE), déjà réutilisé par `sqlite_plafond` :
    // même besoin, même dérivation des fichiers de test, même retrait du texte `#[cfg(test)]`.
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};

    fn inventaire_type() -> Inventaire {
        Inventaire { racine_lisible: true, fichiers: 59, octets: 164_940_000, borne: None, illisibles: 0 }
    }

    fn actif_type() -> EtatTierFroid {
        EtatTierFroid::Actif {
            racine: PathBuf::from("/var/lib/plume/db/cold"),
            fenetre_chaude_jours: 7,
            retention_jours: 365,
            inventaire: inventaire_type(),
        }
    }

    fn non_compile_type() -> EtatTierFroid {
        EtatTierFroid::NonCompile {
            demande: true,
            variables_ignorees: vec!["PLUME_COLD_DIR".into(), "PLUME_COLD_TIER".into()],
        }
    }

    /// LE CŒUR. Les trois états doivent se distinguer SANS AMBIGUÏTÉ dans le journal — c'est
    /// précisément ce qui manquait : « pas compilé » et « compilé mais éteint » se lisaient pareil
    /// (rien du tout), et un exploitant ne pouvait pas savoir lequel des deux il regardait.
    ///
    /// La distinction est vérifiée DEUX FOIS, parce qu'« être différents » ne suffit pas : deux
    /// textes peuvent différer d'une virgule et rester illisibles. Chaque cas doit donc porter SA
    /// marque, et AUCUNE autre.
    ///
    /// MUTATION : faire rendre au bras `NonCompile` le texte du bras `Inactif` ⇒ la 1re assertion
    /// passe au ROUGE en NOMMANT la confusion (« les cas (1) … et (2) … rendent le MÊME texte »).
    /// MUTATION : écrire « DÉSACTIVÉ » dans le texte du cas (1) ⇒ la 2e assertion passe au ROUGE
    /// (la marque du cas (2) serait portée par deux cas).
    #[test]
    fn la_banniere_distingue_les_trois_cas() {
        let cas = [
            ("(1) non compilé dans ce binaire", banniere(non_compile_type())),
            ("(2) compilé mais désactivé", banniere(EtatTierFroid::Inactif)),
            ("(3) compilé et actif", banniere(actif_type())),
        ];
        for i in 0..cas.len() {
            for j in (i + 1)..cas.len() {
                assert_ne!(
                    cas[i].1, cas[j].1,
                    "les cas {} et {} rendent le MÊME texte : le journal ne permet pas de les \
                     distinguer, et c'est EXACTEMENT le défaut mesuré (une capacité absente du binaire \
                     se lit comme une capacité simplement éteinte)",
                    cas[i].0, cas[j].0
                );
            }
        }
        // Les marques : ce qu'un exploitant CHERCHE dans le journal. Chacune doit désigner UN état.
        for (etat, marque) in [
            ("(1) non compilé dans ce binaire", "NON COMPILÉ"),
            ("(2) compilé mais désactivé", "DÉSACTIVÉ"),
            ("(3) compilé et actif", "ACTIF"),
        ] {
            let porteurs: Vec<&str> = cas.iter().filter(|(_, t)| t.contains(marque)).map(|(n, _)| *n).collect();
            assert_eq!(
                porteurs,
                vec![etat],
                "la marque « {marque} » doit désigner l'état {etat} et LUI SEUL — un exploitant qui la \
                 lit doit savoir lequel des trois états il regarde ; portée ici par : {porteurs:?}"
            );
        }
    }

    /// LE CAS (1) EST UNE ANOMALIE, PAS UNE INFORMATION. Poser `PLUME_COLD_TIER=1` sur un binaire qui
    /// ne sait pas le faire, c'est croire à une rétention longue qui n'existe pas : la ligne doit le
    /// dire FORT, nommer les variables sans effet, et donner les deux sorties.
    ///
    /// MUTATION : rendre le même texte que `demande` soit vrai ou faux ⇒ la dernière assertion passe
    /// au ROUGE (un binaire sans la capacité et sans la demande n'est PAS en anomalie — crier là
    /// dessus apprendrait à ignorer la ligne).
    #[test]
    fn le_cas_non_compile_denonce_la_variable_qui_ment() {
        let crie = banniere(non_compile_type());
        assert!(crie.contains("ANOMALIE DE CONFIGURATION"), "la promesse non tenue doit être qualifiée : {crie}");
        assert!(crie.contains("PLUME_COLD_TIER=1 est posé"), "la variable fautive doit être NOMMÉE : {crie}");
        assert!(
            crie.contains("--features cold_tier") && crie.contains("retirer ces variables"),
            "les DEUX sorties (bâtir la capacité / retirer la promesse) doivent être écrites : {crie}"
        );
        assert!(
            crie.contains("2 variable(s)") && crie.contains("PLUME_COLD_DIR"),
            "les variables posées et sans effet doivent être comptées ET listées : {crie}"
        );
        let muet = banniere(EtatTierFroid::NonCompile { demande: false, variables_ignorees: vec![] });
        assert!(
            !muet.contains("ANOMALIE") && muet.contains("NON COMPILÉ"),
            "sans demande, le même binaire n'est PAS en anomalie — il doit le dire sans crier : {muet}"
        );
    }

    /// LE CAS (3) PUBLIE CE QUI SE VÉRIFIE. Une ligne « tier froid actif » sans nombres n'apprend rien :
    /// l'exploitant doit pouvoir confronter CHAQUE terme au disque et à sa configuration.
    ///
    /// MUTATION : retirer `racine.display()` du bras `Actif` ⇒ la 1re assertion passe au ROUGE (on ne
    /// saurait plus OÙ regarder, c'est-à-dire qu'on ne pourrait plus vérifier les trois suivantes).
    #[test]
    fn le_cas_actif_publie_ce_qui_se_verifie() {
        let a = banniere(actif_type());
        assert!(a.contains("/var/lib/plume/db/cold"), "le RÉPERTOIRE doit être nommé : {a}");
        assert!(a.contains("fenêtre chaude 7 j"), "la fenêtre chaude APPLIQUÉE doit être publiée : {a}");
        assert!(a.contains("rétention cold 365 j"), "la rétention cold doit être publiée : {a}");
        assert!(a.contains("59 fichier(s)-jour"), "le nombre de fichiers-jour doit être publié : {a}");
        assert!(a.contains("157.3 Mio"), "et leur VOLUME, dans une unité lisible : {a}");
    }

    /// UN COMPTAGE QUI NE REND RIEN SE LIT « JE N'AI PAS MESURÉ », JAMAIS « ZÉRO ». Deux formes le
    /// menacent : la racine illisible (un `PLUME_COLD_DIR` fautif rendrait « 0 fichier » pour
    /// toujours) et le balayage BORNÉ (un total qui n'en est pas un).
    ///
    /// MUTATION : rendre `Inventaire::phrase` insensible à `racine_lisible` ⇒ la 1re assertion passe
    /// au ROUGE. MUTATION : ignorer `borne` ⇒ la 4e passe au ROUGE (un minorant serait présenté
    /// comme un total).
    #[test]
    fn linventaire_avoue_ce_quil_na_pas_mesure() {
        let absent = Inventaire { racine_lisible: false, fichiers: 0, octets: 0, borne: None, illisibles: 0 }.phrase();
        assert!(absent.contains("ABSENT ou ILLISIBLE"), "le répertoire introuvable doit se dire : {absent}");
        assert!(
            !absent.contains("0 fichier(s)-jour"),
            "« rien mesuré » ne doit PAS se présenter comme un compte de zéro : {absent}"
        );
        let borne = Inventaire { racine_lisible: true, fichiers: 10_000, octets: 1 << 40, borne: Some(10_000), illisibles: 0 }.phrase();
        assert!(
            borne.contains("≥10000 fichier(s)-jour") && borne.contains("MINORANTS"),
            "un balayage arrêté rend des MINORANTS, et doit le dire : {borne}"
        );
        assert!(borne.contains("ARRÊTÉ à 10000 entrées"), "la borne réellement appliquée doit être nommée : {borne}");
        let mesure = inventaire_type().phrase();
        assert!(
            !mesure.contains('≥') && mesure.contains("59 fichier(s)-jour"),
            "une mesure COMPLÈTE ne doit pas se déguiser en minorant : {mesure}"
        );
    }

    /// L'INSTRUMENT EST VALIDÉ PAR CONTRÔLE POSITIF : on ne suppose pas que le balayage voit les
    /// fichiers-jour, on en pose et on vérifie qu'il les compte — avec deux contrôles NÉGATIFS (un
    /// `.tmp` d'écriture en cours et un fichier étranger) qui ne doivent PAS être comptés. Sans ça, un
    /// balayage qui ne trouve jamais rien passerait au vert en ne prouvant rien.
    ///
    /// MUTATION : compter tout fichier au lieu des seuls `.parquet` ⇒ la 1re assertion passe au ROUGE
    /// (4 au lieu de 3). MUTATION : borner à `usize::MAX` ⇒ la 3e passe au ROUGE.
    #[test]
    fn linventaire_compte_les_fichiers_jour_sur_le_disque() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cold-inventaire");
        let racine = tmp.racine();
        let env_dir = racine.chemin().join("prod");
        std::fs::create_dir_all(&env_dir).expect("fixture : répertoire d'env");
        std::fs::write(env_dir.join("2026-08-01-0000.parquet"), vec![7u8; 1024]).expect("fixture");
        std::fs::write(env_dir.join("2026-08-02-0000.parquet"), vec![7u8; 2048]).expect("fixture");
        std::fs::write(env_dir.join("2026-08-03-0000.parquet.tmp"), vec![7u8; 4096]).expect("fixture");
        std::fs::write(env_dir.join("NOTES.txt"), b"pas un fichier-jour").expect("fixture");
        // Un `.parquet` posé DIRECTEMENT sous la racine (PLUME_COLD_DIR pointé un cran trop bas).
        std::fs::write(racine.chemin().join("2026-08-04-0000.parquet"), vec![7u8; 512]).expect("fixture");

        let inv = inventaire(racine.chemin(), PLAFOND_ENTREES);
        assert!(inv.racine_lisible, "précondition : la racine de la fixture est lisible");
        assert_eq!(inv.fichiers, 3, "seuls les `.parquet` sont des fichiers-jour (ni `.tmp`, ni fichier étranger)");
        assert_eq!(inv.octets, 1024 + 2048 + 512, "le VOLUME est la somme des tailles réelles, pas un compte");
        assert_eq!(inv.borne, None, "un inventaire complet ne s'annonce pas borné");

        let serre = inventaire(racine.chemin(), 2);
        assert!(serre.borne.is_some(), "un plafond bas doit ARRÊTER le balayage, pas le ralentir");
        assert!(
            serre.fichiers <= inv.fichiers,
            "un balayage borné rend un MINORANT ({} vu, {} au total)",
            serre.fichiers,
            inv.fichiers
        );

        let inexistant = inventaire(&racine.chemin().join("nulle-part"), PLAFOND_ENTREES);
        assert!(!inexistant.racine_lisible, "une racine absente ne se lit PAS comme un répertoire vide");
    }

    /// LA LISTE DES VARIABLES EST DÉRIVÉE, JAMAIS ÉNUMÉRÉE : une variable de tier froid ajoutée demain
    /// est dénoncée le jour même. Les DEUX sources que `cfg` consulte sont couvertes (env + conf), et
    /// une variable posée des deux côtés n'est comptée qu'une fois.
    ///
    /// MUTATION : ne lire que `conf` ⇒ la 1re assertion passe au ROUGE (la production pose ces
    /// variables par l'ENVIRONNEMENT, via le manifeste k3s — c'est le cas réel qu'on veut voir).
    #[test]
    fn les_variables_cold_sont_derivees_du_prefixe() {
        let conf: HashMap<String, String> = [
            ("PLUME_COLD_DIR", "/data/cold"),
            ("PLUME_COLD_TIER", "1"),
            ("PLUME_DB", "/data/plume.db"),
            ("PLUME_RETENTION_DAYS", "30"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let env = ["PLUME_COLD_TIER".to_string(), "PLUME_COLD_INVENTEE_DEMAIN".to_string(), "PATH".to_string()];
        assert_eq!(
            variables_cold_posees(&conf, env),
            vec!["PLUME_COLD_DIR", "PLUME_COLD_INVENTEE_DEMAIN", "PLUME_COLD_TIER"],
            "les deux sources sont couvertes, le doublon est fondu, et rien d'étranger n'entre"
        );
        assert!(
            variables_cold_posees(&HashMap::new(), Vec::<String>::new()).is_empty(),
            "aucune variable posée -> aucune dénonciation (sinon la ligne crierait sur tout le monde)"
        );
    }

    /// LE DÉMARRAGE QUI ANNONCE SON PLAFOND MÉMOIRE DOIT ANNONCER SON TIER FROID. La règle n'énumère
    /// PAS `server.rs` : elle est DÉRIVÉE d'un invariant déjà tenu — tout site qui imprime la bannière
    /// du plafond au démarrage est un site de démarrage, donc doit aussi imprimer celle du tier froid.
    /// Un second point d'entrée écrit demain est couvert le jour où il est écrit.
    ///
    /// C'est cette assertion, et elle seule, qui ferme le défaut MESURÉ (`grep -i cold` sur les
    /// journaux de production : ZÉRO ligne). Les tests ci-dessus prouvent que la ligne DIT le bon
    /// état ; celui-ci prouve qu'elle est PRONONCÉE.
    ///
    /// CE QU'IL EXIGE : une bannière CALCULÉE ne suffit pas, il faut qu'elle soit ÉCRITE — d'où
    /// l'exigence d'un `eprintln!` sur la ligne même de l'appel (un `let _ = banniere(...)` laisse le
    /// démon aussi muet qu'avant). FAIL-CLOSED : un appel étalé sur plusieurs lignes échoue aussi, et
    /// c'est voulu — on préfère un refus bruyant à un démarrage silencieux.
    ///
    /// MUTATION : remplacer l'`eprintln!` de `server.rs` par `let _ = …` ⇒ la 2e assertion passe au
    /// ROUGE en nommant le fichier redevenu muet.
    #[test]
    fn le_demarrage_qui_annonce_son_plafond_annonce_son_tier_froid() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        let (mut sites, mut muets) = (0usize, Vec::new());
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let production: Vec<String> = texte_de_production(f, &src).into_iter().map(|(_, l)| l).collect();
            if !production.iter().any(|l| l.contains("sqlite_plafond::banniere(")) {
                continue;
            }
            sites += 1;
            if !production.iter().any(|l| l.contains("cold_banniere::banniere(") && l.contains("eprintln!")) {
                muets.push(f.display().to_string());
            }
        }
        assert!(sites >= 1, "précondition : le scanner voit bien le(s) site(s) de bannière de démarrage ({sites})");
        assert!(
            muets.is_empty(),
            "démarrage(s) qui annonce(nt) le plafond mémoire et se TAISE(NT) sur le tier froid — c'est ce \
             silence exact qui a rendu invisible pendant trois jours la disparition de la capacité du \
             binaire :\n{muets:#?}"
        );
    }

    /// SANS LA FEATURE, L'ÉTAT EST « PAS DANS CE BINAIRE » — et ce n'est pas une opinion du code, c'est
    /// ce que la récolte RÉCOLTE. Ce test n'existe QUE dans le build par défaut : c'est le build qui a
    /// tourné trois jours en production en prétendant faire du tier froid.
    ///
    /// MUTATION : faire rendre `Inactif` à la récolte sans feature ⇒ ROUGE (le binaire prétendrait
    /// avoir une capacité éteinte alors qu'il ne l'a pas du tout).
    #[cfg(not(feature = "cold_tier"))]
    #[test]
    fn sans_la_feature_la_recolte_dit_non_compile() {
        let conn = Connection::open_in_memory().expect("connexion mémoire");
        let etat = etat(&conn, &HashMap::new(), "/var/lib/plume/db/plume.db");
        assert!(
            matches!(etat, EtatTierFroid::NonCompile { .. }),
            "un binaire bâti sans `--features cold_tier` ne peut RIEN faire de froid : la récolte doit le dire"
        );
        assert!(banniere(etat).contains("NON COMPILÉ"), "et la ligne du journal doit le porter");
    }

    /// AVEC LA FEATURE, LA RÉCOLTE NE PEUT PLUS DIRE « PAS COMPILÉ » — la capacité EST là, seul le gate
    /// runtime décide. On vérifie aussi que la bannière lit ce gate EXACTEMENT comme le tier froid le
    /// lit : deux lectures divergentes annonceraient une activation que le gate refuse (ou l'inverse).
    ///
    /// MUTATION : relâcher `cold_tier_demande` en `!= "0"` ⇒ la 2e assertion passe au ROUGE.
    #[cfg(feature = "cold_tier")]
    #[test]
    fn avec_la_feature_la_recolte_ne_dit_jamais_non_compile() {
        let conn = Connection::open_in_memory().expect("connexion mémoire");
        let conf = HashMap::new();
        assert!(
            !matches!(etat(&conn, &conf, "/var/lib/plume/db/plume.db"), EtatTierFroid::NonCompile { .. }),
            "la capacité est DANS ce binaire : seul le gate runtime peut l'éteindre"
        );
        for valeur in ["1", "0", "true", ""] {
            let mut c = HashMap::new();
            c.insert("PLUME_COLD_TIER".to_string(), valeur.to_string());
            assert_eq!(
                cold_tier_demande(&c),
                cold_store::cold_tier_runtime_on(&c),
                "la bannière et le tier froid doivent lire le MÊME gate (valeur « {valeur} ») — sinon la \
                 ligne annonce une activation que le gate refuse"
            );
        }
    }
}
