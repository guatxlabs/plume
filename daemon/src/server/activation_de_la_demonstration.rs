//! `P10.28-j` — LA DÉMONSTRATION PUBLIQUE NE S'ACTIVE PAS SUR UN NOM QUI APPARTIENT DÉJÀ À QUELQU'UN.
//!
//! LE DÉFAUT, MESURÉ LE 2026-09-29 SUR LA FORME D'AVANT (routeur réel, aucun identifiant). La démonstration
//! (`PLUME_PUBLIC_DEMO=1`) sert tout visiteur anonyme sous `IDENTITE_DE_LA_DEMONSTRATION` ; au démarrage, rien ne
//! regardait si ce nom appartenait déjà à quelqu'un. Un compte `demo` présent (créé avant `P10.25-h`, posé par
//! l'assistant d'installation, fédéré par un annuaire) : l'anonyme listait sa requête privée AVEC son texte (200). Un
//! administrateur de configuration nommé `demo` (`PLUME_USER=demo`) : l'anonyme était servi sous son nom (200 sur
//! `/api/me`, `user: demo`), donc propriétaire de tout ce que cet administrateur tient par son nom. L'énoncé
//! sous-comptait les portes : l'assistant et `PLUME_USER` posaient ce nom sans refus.
//!
//! LA DÉCISION : REFUS À L'ACTIVATION, PAS AU DÉMARRAGE. Le démon démarre ; la démonstration demandée n'est PAS servie
//! (l'anonyme reçoit 401, comme sans démonstration), et la cause est dite au journal de démarrage avec son remède. Ne
//! pas démarrer aurait fait d'une option d'affichage une panne ; servir en l'avouant seulement aurait livré ce que le
//! nom tient à qui passe. Refusés : `PLUME_USER` vaut ce nom (avec un mot de passe de configuration) ; une ligne `user`
//! porte ce nom, quel qu'en soit le hachage (mot de passe local, compte fédéré, administrateur de l'assistant) ; sans
//! compte, ce nom tient des lignes par une colonne d'autorité ou l'annuaire l'a présenté
//! (`ce_que_le_nom_tient_sans_compte`, la lecture même de la création et de la fédération) ; et toute lecture qui n'a
//! pas eu lieu. Servis : une base où ce nom n'est à personne — l'inventaire des accès de la démonstration elle-même
//! (méthode `demo`) et le propriétaire des dossiers semés par `PLUME_DEMO=1` (`incident.owner`, qui n'octroie rien) ne
//! comptent pas.
//!
//! LE PRIX ASSUMÉ, ET IL EST DIT : des lignes qu'un visiteur anonyme a laissées sous ce nom AVANT `P10.28-i` (requêtes
//! enregistrées, préférences) refusent aussi l'activation — rien ne sépare leur provenance de celle d'une identité
//! réelle (aucune colonne de provenance). La démonstration est destinée à une instance isolée et jetable : le remède
//! est dans la phrase du refus.
//!
//! LE REFUS SE LIT AILLEURS QU'AU JOURNAL (correction de vérification) : il est inscrit au registre (maillon
//! `demo.activation.refusee`, sa phrase entière), et le paquet de diagnostic rend la démonstration SERVIE
//! (`public_demo_served`) à côté de la valeur de configuration — `PLUME_PUBLIC_DEMO=1` seul n'y dit plus qu'elle l'est.
use crate::*;
use rusqlite::OptionalExtension;

/// `P10.28-j` — LA DÉMONSTRATION DEMANDÉE PAR LA CONFIGURATION, QUI N'EST PAS LA DÉMONSTRATION SERVIE.
///
/// POURQUOI UN TYPE ET NON UN `bool` (correction de vérification, MESURÉ) : `run()` ne se joue pas en test, et c'est
/// le seul endroit où la décision d'activation prend effet. Tant que la valeur demandée était un `bool`, jeter le
/// verdict (`let _jugee = activer_la_demonstration_si_permise(…)`) ou l'enfermer dans un bloc laissait `AppState {
/// public_demo, … }` reprendre la valeur DEMANDÉE : compilé, servi au-dessus d'un nom qui appartient à quelqu'un,
/// pendant que le journal disait « NON ACTIVÉE » — et l'épingle du source restait verte. Ce type n'a ni champ lisible
/// hors de ce module, ni conversion, ni comparaison : la valeur DEMANDÉE ne se lit que par
/// `activer_la_demonstration_si_permise`, et l'état servi, qui prend un `bool`, la refuse À LA COMPILATION. Aucune
/// dérivation (`PartialEq`, `Debug`…) : chacune rouvrirait une voie vers le booléen demandé.
/// CE QUE CE TYPE NE TIENT PAS (correction de vérification, tour 2) : il ferme la REPRISE de la valeur demandée, pas la
/// fabrication d'une autre — un littéral `true`, ou un bloc qui appelle cette fonction puis rend autre chose que son
/// verdict, compile dans `AppState { public_demo, … }`. Ce reste est épinglé sur le source de `run()` (témoin `dlsp_`
/// (6) : la liaison servie lue entière, le verdict lié tel quel, pris par l'état en forme courte).
pub(crate) struct DemonstrationDemandee(bool);

impl DemonstrationDemandee {
    /// La lecture de `PLUME_PUBLIC_DEMO` par `boot_config` — et les témoins.
    pub(crate) fn depuis_la_configuration(demandee: bool) -> Self {
        Self(demandee)
    }
}

/// `P10.28-j` — POURQUOI LA DÉMONSTRATION DEMANDÉE N'EST PAS SERVIE.
#[derive(Debug, PartialEq)]
pub(crate) enum RefusDeLaDemonstration {
    /// `PLUME_USER` vaut le nom de la démonstration, et un mot de passe de configuration est posé.
    AdministrateurDeConfiguration,
    /// Une ligne `user` porte ce nom : (son rôle).
    CompteExistant(String),
    /// Sans compte, ce nom tient des lignes par une colonne d'autorité, ou l'annuaire l'a présenté : (le détail de
    /// `ce_que_le_nom_tient_sans_compte`).
    NomTenuSansCompte(Value),
    /// La lecture n'a pas eu lieu : (cause du moteur).
    NonVerifie(String),
}

impl RefusDeLaDemonstration {
    /// Code court, stable (jamais une phrase).
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::AdministrateurDeConfiguration => "administrateur_de_configuration",
            Self::CompteExistant(_) => "compte_existant",
            Self::NomTenuSansCompte(_) => "nom_tenu_sans_compte",
            Self::NonVerifie(_) => "non_verifie",
        }
    }

    /// La phrase du journal de démarrage : ce qui est refusé, pourquoi, et le remède.
    pub(crate) fn phrase(&self) -> String {
        let nom = crate::auth::IDENTITE_DE_LA_DEMONSTRATION;
        let raison = match self {
            Self::AdministrateurDeConfiguration => format!(
                "PLUME_USER vaut « {nom} », le nom sous lequel la démonstration sert tout visiteur anonyme : l'anonyme serait \
                 servi sous le nom de l'administrateur de configuration. Remède : donner un autre nom à PLUME_USER"
            ),
            Self::CompteExistant(role) => format!(
                "un compte « {nom} » existe (rôle {role}) : ses requêtes, tableaux de bord privés et préférences seraient servis \
                 à tout visiteur anonyme. Remède : supprimer ce compte (Réglages > Comptes), puis redémarrer"
            ),
            Self::NomTenuSansCompte(tenue) => format!(
                "sans compte, le nom « {nom} » tient déjà des lignes ou l'annuaire l'a présenté ({tenue}) : elles seraient \
                 servies à tout visiteur anonyme, et leur provenance ne se sépare pas de celle d'une identité réelle. \
                 Remède : sur une instance de démonstration jetable, repartir d'une base neuve ; sinon retirer ces lignes \
                 (geste d'exploitation), puis redémarrer"
            ),
            Self::NonVerifie(cause) => format!(
                "le démon n'a pas pu lire si le nom « {nom} » appartient déjà à quelqu'un ({cause}) : il ne sert pas la \
                 démonstration sur un nom qu'il n'a pas pu vérifier. Remède : réparer la base, puis redémarrer"
            ),
        };
        format!(
            "PLUME_PUBLIC_DEMO=1 demandée, démonstration NON ACTIVÉE ({}) — {raison}. Le démon sert sans démonstration : \
             l'accès anonyme est refusé (401).",
            self.code()
        )
    }
}

/// `P10.28-j` — LE NOM DE LA DÉMONSTRATION APPARTIENT-IL DÉJÀ À QUELQU'UN ? `administrateur_de_configuration` : le nom
/// de `PLUME_USER` quand un mot de passe de configuration est posé (même définition que `reserved_static_admin`).
pub(crate) fn juger_l_activation_de_la_demonstration(
    conn: &Connection,
    administrateur_de_configuration: Option<&str>,
) -> Result<(), RefusDeLaDemonstration> {
    let nom = crate::auth::IDENTITE_DE_LA_DEMONSTRATION;
    if administrateur_de_configuration == Some(nom) {
        return Err(RefusDeLaDemonstration::AdministrateurDeConfiguration);
    }
    match conn.query_row("SELECT role FROM user WHERE name=?1", params![nom], |r| r.get::<_, String>(0)).optional() {
        Ok(Some(role)) => return Err(RefusDeLaDemonstration::CompteExistant(role)),
        Ok(None) => {}
        Err(e) => return Err(RefusDeLaDemonstration::NonVerifie(e.to_string())),
    }
    match crate::handlers::users_lookups::ce_que_le_nom_tient_sans_compte(conn, nom) {
        Ok(None) => Ok(()),
        Ok(Some(tenue)) => Err(RefusDeLaDemonstration::NomTenuSansCompte(tenue)),
        Err(e) => Err(RefusDeLaDemonstration::NonVerifie(e.to_string())),
    }
}

/// `P10.28-j` — le maillon qui inscrit au registre le refus d'activer la démonstration demandée (sa phrase entière).
pub(crate) const MAILLON_DE_LA_DEMONSTRATION_REFUSEE: &str = "demo.activation.refusee";

/// `P10.28-j` — LA DÉMONSTRATION EFFECTIVEMENT SERVIE : demandée ET permise. C'est le SEUL chemin de la valeur demandée
/// (`DemonstrationDemandee`) au drapeau que sert l'état. Le journal de démarrage dit l'une ou l'autre issue (la bannière
/// d'avant, ou le refus nommé), et un refus est inscrit au registre (`MAILLON_DE_LA_DEMONSTRATION_REFUSEE`) ; non
/// demandée, rien n'est lu, dit ni inscrit.
pub(crate) fn activer_la_demonstration_si_permise(
    conn: &Connection,
    demandee: DemonstrationDemandee,
    administrateur_de_configuration: Option<&str>,
) -> bool {
    let DemonstrationDemandee(demandee) = demandee;
    if !demandee {
        return false;
    }
    match juger_l_activation_de_la_demonstration(conn, administrateur_de_configuration) {
        Ok(()) => {
            eprintln!("[demo] PLUME_PUBLIC_DEMO=1 : accès ANONYME en LECTURE SEULE (viewer) — NE PAS utiliser en prod");
            true
        }
        Err(refus) => {
            let phrase = refus.phrase();
            eprintln!("[demo] {phrase}");
            if let crate::ledger::MaillonDeRegistre::NonInscrit(cause) = ledger_append(conn, MAILLON_DE_LA_DEMONSTRATION_REFUSEE, &phrase) {
                eprintln!("[demo] WARN ce refus n'est PAS inscrit au registre : {cause}");
            }
            false
        }
    }
}
