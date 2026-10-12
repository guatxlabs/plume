//! LE RÉPERTOIRE DE DÉVERSEMENT DES TRIS : où il est choisi, comment il est contrôlé, ce qui y subsiste.
//!
//! Module FEUILLE extrait de `sqlite_plafond` par déplacement pur (`P7.18-a`) : la préparation unique en
//! tête de processus (`deversement_init`), la mesure des résidus en clair (`residus_de_deversement`,
//! `S29`), le choix du répertoire — `SQLITE_TMPDIR` explicite respecté, sinon `sqltmp` à côté de la
//! base en `0700` (`repertoire_temporaire_init`) — et le contrôle positif par sonde d'écriture. Ce bloc
//! est dense en confidentialité : c'est lui qui décide où des valeurs d'événement en clair peuvent
//! atterrir hors de la base SQLCipher.
//!
//! DÉPENDANCES, DANS LES DEUX SENS. Il lit le mode (`deversement_actif`) et rend le type `Deversement`,
//! qui restent dans `sqlite_plafond` avec la bannière qui les consomme ; il lit le quota dans
//! `quota_deversement`. `sqlite_plafond` RÉ-EXPORTE `deversement_init` et `residus_de_deversement` :
//! tous les chemins `crate::sqlite_plafond::…` restent valides.
//!
//! IL NE DÉCIDE D'AUCUN RÉGLAGE MÉMOIRE DU MOTEUR. Le budget a un seul auteur, `sqlite_plafond.rs`, et
//! cette feuille n'a AUCUNE exception dans la garde du budget : un réglage écrit ici y est accusé.
use crate::quota_deversement::{controle_positif_de_la_mesure, figer_le_quota, quota_deversement_octets, quota_pour, SONDE_QUOTA};
use crate::sqlite_plafond::{deversement_actif, Deversement};

/// Sous-répertoire des temporaires SQLite, créé À CÔTÉ de la base : le déversement suit la donnée (même
/// volume, même dimensionnement, même surveillance de capacité) au lieu d'atterrir dans un `/tmp` hérité
/// — qui est un tmpfs sur la plupart des hôtes systemd, c'est-à-dire de la RAM comptée au MÊME cgroup :
/// le plafond y serait une ILLUSION.
const SOUS_REPERTOIRE_TEMP: &str = "sqltmp";

/// Prépare le déversement SI et SEULEMENT SI il est demandé. Au défaut, on ne crée même pas le répertoire :
/// un `sqltmp` présent sur le volume laisserait croire que des tris y passent.
pub(crate) fn deversement_init(db_path: &str) -> Deversement {
    if !deversement_actif() {
        return Deversement::Desactive;
    }
    match repertoire_temporaire_init(db_path) {
        Ok(d) => {
            let residus = residus_de_deversement(&d);
            // LE QUOTA EST RÉSOLU ICI ET NULLE PART AILLEURS (`P10.1-b`), au même endroit que le mode :
            // son contrôle positif exige le répertoire, et le figer ici garantit que TOUTE connexion
            // armée ensuite le tiendra sans avoir à re-jouer une écriture disque.
            let quota = quota_pour(quota_deversement_octets(), controle_positif_de_la_mesure(&d));
            figer_le_quota(&d, &quota);
            Deversement::Vers(d, residus, quota)
        }
        Err(e) => Deversement::Indisponible(e),
    }
}

/// LA MESURE DE L'ALLÉGATION D'HÔTE « SQLite délie son temporaire aussitôt ouvert » (`S29`) : les noms qui
/// subsistent dans le répertoire de déversement, hors la sonde d'écriture qui est à nous. Si l'allégation
/// tient, cette liste est VIDE à chaque démarrage ; un nom est la preuve qu'elle a lâché au moins une fois.
/// Paramétrée sur le répertoire, donc exerçable sans toucher à l'environnement du processus.
pub(crate) fn residus_de_deversement(dir: &std::path::Path) -> crate::mesure_environnement::Mesure<Vec<String>> {
    // LES DEUX SONDES DU PRODUIT SONT IGNORÉES PAR LE MÊME NOM QUE CELUI QUI LES ÉCRIT. Celle du
    // quota (`P10.1-b`) ne porte que des octets nuls et elle est déliée aussitôt ouverte ; la compter
    // comme un résidu EN CLAIR serait une fausse alerte de confidentialité — le mot `residus-en-clair`
    // est un contrat de supervision, et seul `=0` y est calme.
    crate::mesure_environnement::entrees_nommees_depuis(dir, &[SONDE_ECRITURE, SONDE_QUOTA])
}

/// Le répertoire où SQLite déversera. PRIVÉ : on passe par `deversement_init`, sinon un appelant peut
/// préparer un déversement que le mode n'autorise pas. DOIT être appelé AVANT le premier appel SQLite du processus :
/// `sqlite3_os_init()` lit `getenv("SQLITE_TMPDIR")` UNE SEULE FOIS, à l'initialisation de SQLite. D'où
/// l'appel unique en tête de `main`, avant tout branchement de sous-commande — un appel par sous-commande
/// serait une ÉNUMÉRATION, et c'est précisément ce genre de liste qui a déjà lâché dans ce dépôt.
///
/// SONDE VALIDÉE PAR CONTRÔLE POSITIF : on n'AFFIRME pas que le répertoire est utilisable, on y ÉCRIT un
/// octet et on le RELIT. Un répertoire créé mais non inscriptible (montage RO, quota, SELinux) rendrait un
/// plafond qui ne déverse pas — c'est-à-dire des requêtes qui ÉCHOUENT au lieu de ralentir.
///
/// Un `SQLITE_TMPDIR` posé EXPLICITEMENT par l'exploitant est RESPECTÉ (et seulement contrôlé) : c'est le
/// levier par lequel un déploiement place le déversement sur un support chiffré. On ne remplace que le
/// SILENCE — et le silence, chez le moteur vendoré (`unixTempFileDir`, lu dans `sqlite3.c`), vaut dans
/// l'ordre `TMPDIR`, puis `/var/tmp`, `/usr/tmp`, `/tmp`, puis le répertoire courant : un répertoire
/// PARTAGÉ dans tous les cas, et pas forcément `/tmp`.
fn repertoire_temporaire_init(db_path: &str) -> Result<std::path::PathBuf, String> {
    if let Ok(explicite) = std::env::var("SQLITE_TMPDIR") {
        if !explicite.trim().is_empty() {
            let dir = std::path::PathBuf::from(explicite);
            controle_positif(&dir)?;
            return Ok(dir);
        }
    }
    let base = std::path::Path::new(db_path)
        .parent()
        .ok_or_else(|| format!("chemin de base sans répertoire parent : {db_path}"))?;
    let dir = base.join(SOUS_REPERTOIRE_TEMP);
    std::fs::create_dir_all(&dir).map_err(|e| format!("création {} : {e}", dir.display()))?;
    // 0700 : les temporaires portent des valeurs d'événement EN CLAIR. SQLite les délie aussitôt, mais le
    // mode du RÉPERTOIRE est ce qui ferme la fenêtre entre `open` et `unlink`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    controle_positif(&dir)?;
    std::env::set_var("SQLITE_TMPDIR", &dir);
    Ok(dir)
}

/// Écrit un octet puis le relit. Une sonde qu'on n'a pas vue RÉUSSIR ne prouve rien de son sujet.
/// Le nom de la sonde d'écriture : UN SEUL auteur, parce que la mesure des résidus doit l'ignorer par le
/// même nom que le contrôle l'écrit.
const SONDE_ECRITURE: &str = ".sonde-ecriture";

pub(crate) fn controle_positif(dir: &std::path::Path) -> Result<(), String> {
    let sonde = dir.join(SONDE_ECRITURE);
    std::fs::write(&sonde, b"1").map_err(|e| format!("écriture impossible dans {} : {e}", dir.display()))?;
    let relu = std::fs::read(&sonde).map_err(|e| format!("relecture impossible dans {} : {e}", dir.display()))?;
    let _ = std::fs::remove_file(&sonde);
    if relu != b"1" {
        return Err(format!("contrôle positif échoué dans {} (relecture divergente)", dir.display()));
    }
    Ok(())
}
