//! mise_en_file_de_riposte — UNE RIPOSTE N'EST EN FILE QUE SI LA LIGNE A ÉTÉ ÉCRITE (`P10.20-t`).
//!
//! LE DÉFAUT QUE CE MODULE REND NON-ÉCRIVABLE. Les deux seuls gestes qui posent une ligne dans la
//! table `action` — la création par un analyste (`actions::action_create`) et la pose automatique par
//! un playbook dû (`playbooks::run_playbooks`) — écrivaient leur `INSERT` sous `let _ =`. La forme
//! n'a aucune branche d'échec : il n'existe nulle part où écrire ce qui n'a pas eu lieu. Ce qui
//! SUIVAIT cet `INSERT`, en revanche, affirmait qu'il avait eu lieu :
//!   * `action_create` lisait `last_insert_rowid()` — qui, l'écriture ratée, rend le dernier
//!     identifiant inséré SUR CETTE CONNEXION, c'est-à-dire la ligne d'une AUTRE table (le registre
//!     lui-même, un événement) ou `0` sur une connexion neuve — puis posait `action.queued` au
//!     registre tamper-evident et servait cet identifiant à la console, qui l'AFFICHE ;
//!   * `run_playbooks` armait le miroir de ban HTTP (`net_ban`) juste après, sur des variables
//!     LOCALES (`status`, `dry`) que l'écriture n'avait jamais confirmées : une action inexistante
//!     pouvait donc bloquer une adresse au niveau HTTP, pendant que l'exécuteur d'hôte — qui, lui,
//!     lit la table `action` — n'avait rien à exécuter, et que le bilan du tick publiait « 0
//!     abandon ».
//! C'est la famille de `P10.20-q` (un fait fabriqué dans une trace non purgeable), du côté de
//! l'ÉCRITURE et non de la lecture.
//!
//! LE GESTE : L'IDENTIFIANT NE SE LIT QU'APRÈS UNE ÉCRITURE COMPTÉE. `execute` rend le nombre de
//! lignes écrites ; `Posee` n'est construit que sur EXACTEMENT une, et c'est seulement là que
//! `last_insert_rowid()` est interrogé — sur une connexion tenue par l'appelant pendant tout le
//! geste, donc l'identifiant est celui de CETTE ligne. Tout le reste est `NonEcrite`, qui PORTE sa
//! cause : l'appelant refuse, compte, et n'affirme rien.
//!
//! POURQUOI UN TYPE NOMMÉ PLUTÔT QU'UN `Result<i64, _>`. Un `Result` offre `.ok()`, `.unwrap_or(0)`
//! et `.unwrap_or_default()` — les trois idiomes qui, sur une LECTURE, fabriquent exactement le fait
//! que ce dépôt poursuit (`P10.20-b`, `P10.20-q`). Le même repli sur une écriture rendrait
//! l'identifiant `0`, qu'aucun appel ne distingue d'une ligne réelle. `RiposteMiseEnFile` n'offre
//! aucun de ces raccourcis : on ne peut pas en sortir un identifiant sans avoir écrit la branche
//! d'échec.
//!
//! POURQUOI PAS `RETURNING id`, QUI SERAIT PLUS FORT ENCORE. Il prendrait l'identifiant DANS
//! l'écriture, sans dépendre de l'état de la connexion. Il exige un moteur SQLite 3.35 ou plus ;
//! l'arbre n'en porte AUCUN emploi, et le manifeste épingle la bibliothèque (`rusqlite`), pas la
//! version du moteur que le paquet groupé embarque. Adosser la correction d'une riposte perdue à un
//! numéro de moteur que rien ne vérifie déplacerait le risque au lieu de le fermer. Le comptage des
//! lignes écrites, lui, est une propriété de l'API, disponible partout.
//!
//! CE QUE CE MODULE NE TIENT PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU : il ne dit rien de ce que
//! l'appelant FAIT du refus (refuser, compter), ni des écritures qui SUIVENT la mise en file — la
//! pose du ban HTTP elle-même avale toujours son `INSERT` (`auth::netban_upsert`, hors de ce
//! chantier) et rend `true` quoi qu'il arrive.
use crate::*;

/// L'ÉNONCÉ DE LA MISE EN FILE — un seul, pour les deux gestes qui posent une riposte. Les colonnes
/// facultatives (`alert_id`, `host`) sont des paramètres liés : un playbook les laisse à `NULL` comme
/// avant, sans une seconde écriture de la même règle.
pub(crate) const SQL_METTRE_UNE_RIPOSTE_EN_FILE: &str =
    "INSERT INTO action(ts,kind,target,status,dry_run,alert_id,reason,host) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";

/// Ce qu'une mise en file rend. `Posee` PORTE l'identifiant de la ligne écrite — il n'existe pas
/// d'autre chemin vers un identifiant de riposte ; `NonEcrite` PORTE la cause, et aucun identifiant.
pub(crate) enum RiposteMiseEnFile {
    /// La ligne est écrite, et l'identifiant est celui de CETTE ligne.
    Posee(i64),
    /// L'écriture n'a pas eu lieu (ou n'a pas posé exactement une ligne) : la cause est portée, et
    /// rien — ni registre, ni armement, ni réponse à la console — ne doit affirmer le contraire.
    NonEcrite(String),
}

/// Pose UNE riposte dans la file, et ne rend son identifiant que si la ligne existe.
///
/// `conn` doit être tenue par l'appelant pendant tout le geste (c'est le cas des deux appelants : la
/// connexion de requête pour l'analyste, la connexion sous verrou pour le tick) — c'est ce qui fait
/// de `last_insert_rowid()` l'identifiant de la ligne que l'on vient d'écrire et d'aucune autre.
pub(crate) fn mettre_une_riposte_en_file(
    conn: &Connection,
    ts: i64,
    kind: &str,
    cible: &str,
    statut: &str,
    simulation: i64,
    alerte: Option<i64>,
    motif: &str,
    hote: Option<&str>,
) -> RiposteMiseEnFile {
    match conn.execute(
        SQL_METTRE_UNE_RIPOSTE_EN_FILE,
        params![ts, kind, cible, statut, simulation, alerte, motif, hote],
    ) {
        Ok(1) => RiposteMiseEnFile::Posee(conn.last_insert_rowid()),
        // Un `INSERT` sans clause de conflit écrit une ligne ou échoue ; la branche existe pour que
        // le jour où l'énoncé en gagne une (`OR IGNORE`), le silence ne soit pas le comportement par
        // défaut. `last_insert_rowid()` n'est PAS interrogé ici.
        Ok(n) => RiposteMiseEnFile::NonEcrite(format!("{n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => RiposteMiseEnFile::NonEcrite(e.to_string()),
    }
}
