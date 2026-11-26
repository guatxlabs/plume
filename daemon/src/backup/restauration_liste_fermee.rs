//! backup::restauration_liste_fermee — LA RESTAURATION N'ACCEPTE QUE LES FORMES D'INSTRUCTION QUE L'ÉCRIVAIN DU DUMP
//! ÉMET. Sous-module de `backup` ; `dump_restauration::restore_stream` (format courant) et
//! `dump_restauration::restore_compressed` (format ancien, `juger_le_schema_du_format_ancien`) s'en servent.
//!
//! Un dump B1 porte trois familles de chaînes SQL que la restauration fait jouer au moteur. L'écrivain
//! (`dump_restauration::collect_dump_plan`, `build_table_dump`, `dump_stream`) n'en émet que ces formes :
//!  - section 1 (tables) : le `sql` de `sqlite_master` d'une table ordinaire, donc UNE instruction `CREATE TABLE` ;
//!  - section 2 (données) : par table, `INSERT INTO "<table>" (<colonnes>) VALUES (?, …)` construit par
//!    `build_table_dump`, toutes les valeurs liées par des paramètres anonymes, autant que de valeurs par ligne ;
//!  - section 4 (post-DDL) : le `sql` de `sqlite_master` d'un index, d'un déclencheur, d'une vue, ou d'une table
//!    virtuelle FTS3/FTS4/FTS5 à contenu externe (`fts_external_content`), UNE instruction chacun ; et le NOM d'une
//!    table virtuelle à reconstruire (le démon écrit lui-même l'instruction `rebuild`).
//!
//! La connexion de restauration porte un AUTORISEUR À REFUS PAR DÉFAUT, réglé par PHASE (`Phase`) : chaque phase admet
//! la classe d'instruction de sa famille et les actions internes que le moteur fait lui-même pour elle ; tout le
//! reste est refusé (autre classe, objet temporaire ou base attachée, réglage, transaction, fonction). Les
//! instructions que le démon pose lui-même (réglage des clés étrangères, `BEGIN`, compteurs, reconstruction FTS,
//! `COMMIT`) passent chacune dans une phase nommée qui n'admet qu'elles.
//!
//! LES ACTIONS INTERNES ADMISES, relevées sur une restauration réelle du schéma complet de la tête :
//!  - toute création écrit `sqlite_master` (`INSERT` de la ligne, `UPDATE` de sa racine, lecture de son `ROWID`) ;
//!  - une contrainte `UNIQUE`/`PRIMARY KEY` d'un `CREATE TABLE` crée son index `sqlite_autoindex_*` et lit les colonnes
//!    qu'il couvre ; un `CREATE INDEX` lit les colonnes qu'il couvre (clause `WHERE` comprise) et remplit l'index
//!    (action `REINDEX` sur ce seul index) ;
//!  - un `CREATE INDEX` d'expression ou partiel appelle `json_extract` : c'est la forme des index de champ chaud que la
//!    production crée en tâche de fond (`maintenance::reconcile_expr_indexes_background`, `idx_ev_f_*`, et avant elle
//!    `idx_ev_auto_*`), seule fonction qu'un index du démon ait jamais appelée ; admise pendant la création d'un index
//!    seulement ;
//!  - un module FTS crée, remplit et lit SES tables fantômes (`<vt>_<suffixe>`, suffixes de l'écrivain), y compris leurs
//!    index automatiques, lit les réglages `data_version` (FTS5) et `page_size` (FTS3/FTS4), appelle `max` et `coalesce`
//!    (FTS3/FTS4) et, pour la reconstruction, lit la table de contenu. Il le fait pendant le `CREATE VIRTUAL TABLE`,
//!    pendant le `rebuild`, et quand il vide ses données en attente : au début de l'instruction d'écriture suivante (une
//!    autre chaîne de post-DDL) ou au `COMMIT`. Ces actions ne sont admises qu'une fois une table virtuelle créée par
//!    CETTE restauration, les écritures et lectures sur ses seules tables fantômes, et JAMAIS pendant la préparation
//!    d'une chaîne de l'archive : le module ne prépare ses propres instructions qu'à l'exécution, et une chaîne de
//!    l'archive ne peut donc pas emprunter ces actions (un index qui appellerait `coalesce` reste hors liste).
//! Aucune autre fonction n'est appelée par une restauration réelle (index de champ chaud de la production compris).
//!
//! UNE INSTRUCTION PAR CHAÎNE : la chaîne est découpée par le moteur (`rusqlite::Batch`, qui suit la fin
//! d'instruction que rend `sqlite3_prepare`) ; une seconde instruction, valide ou non, refuse la chaîne. Aucun
//! analyseur SQL n'est écrit ici.
//!
//! UNE TÊTE PAR CHAÎNE : l'autoriseur compte les actions qui SONT l'instruction de la famille (la création de table,
//! l'insertion dans la table annoncée, la création d'index, de déclencheur, de vue ou de table virtuelle). Une chaîne
//! qui n'en porte pas exactement une est refusée, même quand le moteur l'aurait refusée de lui-même : le refus dit
//! alors « hors liste » et non le texte du moteur. Ce compte est tenu PAR l'autoriseur : sans autoriseur, aucune
//! chaîne ne passe (repli fermé).
//!
//! REFUS : la restauration échoue entière (la transaction n'est jamais validée, l'appelant retire le temporaire et la
//! destination n'est pas touchée) ; l'erreur nomme la phase et la cause dans un vocabulaire fermé, sans recopier ni
//! le texte lu dans l'archive ni celui du moteur.
//!
//! REFUS DU MOTEUR : une chaîne que la liste admet et que le moteur refuse (préparation ou exécution), ou une valeur de
//! l'archive que le moteur refuse d'écrire, rend la phase, « refusée par le moteur » et le CODE d'erreur SQLite étendu
//! (`refusee_par_le_moteur`), jamais le texte du moteur, qui peut citer un morceau de la chaîne lue ; l'écriture d'un
//! compteur, dont le nom est lu dans l'archive, suit la même règle.
//!
//! LE FORMAT ANCIEN (un fichier SQLite en clair, recopié par `sqlcipher_export`) SUIT LA MÊME LISTE
//! (`juger_le_schema_du_format_ancien`). L'export rejoue le `sql` de chaque table et de chaque index du fichier, et
//! recopie TELLES QUELLES les lignes de schéma des vues, des déclencheurs et des tables virtuelles, que le moteur
//! relira à la première ouverture : un autoriseur posé sur la connexion de l'export ne verrait jamais ces trois
//! classes (relevé : il n'y voit ni `CreateView`, ni `CreateTrigger`, ni `CreateVtable`, seulement l'écriture brute de
//! `sqlite_master`). Chaque ligne de schéma du fichier est donc jugée AVANT l'export, sur une base de brouillon en
//! mémoire armée de la même liste : une table que l'export rejoue sous la phase `Tables` (hors tables fantômes,
//! ci-dessous), toute autre ligne sous la phase `PostDdl`. Seules exceptions, les tables que le moteur crée lui-même
//! (`TABLES_DU_MOTEUR`), à leur texte exact.
//! Un refus nomme la phase « format ancien ».
//! UNE TABLE VIRTUELLE Y EST JUGÉE COMME AU FORMAT COURANT : sa ligne est préparée sur le brouillon (module, classe
//! d'instruction, puis ARGUMENTS, ci-dessous), puis EXÉCUTÉE sous la liste, de sorte que ce que le module fait à sa
//! création est jugé comme au format courant. Le module y crée ses tables fantômes ; celles que le fichier porte (que
//! l'export rejoue avec leurs lignes) ne sont donc pas créées comme des tables, et doivent être exactement celles que le
//! module a créées, nom et texte.
//!
//! AUCUN INDEX NI AUCUN DÉCLENCHEUR SUR UNE TABLE FANTÔME, DANS LES DEUX FORMATS. Le module écrit lui-même dans ses tables
//! fantômes à chaque écriture dans la table virtuelle, après la restauration sur la connexion du démon, où aucun
//! autoriseur n'est posé : un index (`UNIQUE`, partiel) posé sur l'une d'elles y bornerait ou refuserait ces écritures,
//! un déclencheur y ferait jouer son corps. L'écrivain n'en émet jamais (le schéma de la tête n'en porte aucun). Sous la
//! phase post-DDL, l'autoriseur refuse donc la création d'un index (hors index automatique, que seul le moteur nomme) ou
//! d'un déclencheur dont la CIBLE, telle que le moteur la lui passe, est une table fantôme d'une table virtuelle créée par
//! cette restauration (`Cause::IndexOuDeclencheurSurUneTableFantome`) ; le format ancien juge ses index et ses
//! déclencheurs sous la même phase, sur le brouillon où ses tables virtuelles sont déjà créées.
//!
//! AUCUN OBJET DE L'ARCHIVE NE PREND LE NOM D'UNE TABLE FANTÔME, QUEL QUE SOIT SON GENRE, DANS LES DEUX FORMATS. La règle
//! porte sur le nom `<vt>_<suffixe>` (suffixes de l'écrivain) d'une table virtuelle de cette restauration, casse ASCII
//! ignorée du côté de la table virtuelle comme de celui de l'objet, comme le moteur résout les noms. Elle juge toute
//! création que porte une chaîne de l'archive et qui prend un nom dans l'espace de noms des tables (table, vue, index,
//! table virtuelle : `nom_dans_l_espace_des_tables`), jamais les tables que le module crée lui-même à l'exécution.
//! L'autoriseur refuse, sous sa propre cause (`Cause::ObjetAuNomDUneTableFantome`) :
//!  - la création d'une table virtuelle quand un objet créé AVANT elle porte le nom de l'une de ses tables fantômes : FTS4
//!    crée sa table `<vt>_stat` par `CREATE TABLE IF NOT EXISTS` et adopterait l'objet déjà là, table, vue ou table
//!    virtuelle, avec l'index ou le déclencheur qu'on y aurait posé (un déclencheur `INSTEAD OF` sur une vue y jouerait à
//!    chaque écriture du module, sur la connexion du démon) ;
//!  - la création d'un objet APRÈS la table virtuelle sous le nom de l'une de ses tables fantômes, dès que l'autoriseur en
//!    voit le nom.
//! Le moteur cherche le nom d'un INDEX ou d'une TABLE VIRTUELLE avant de montrer leur création à l'autoriseur
//! (`sqlite3CreateIndex`, `sqlite3StartTable`) : créés après la table virtuelle sous le nom d'une table fantôme qu'elle a
//! déjà créée, ils sont arrêtés par lui, et la chaîne, sans tête, est refusée comme hors classe ; sous un nom que ce module
//! ne crée pas, la liste les refuse sous la cause nommée. Au format ancien, le brouillon crée les tables, puis les vues,
//! avant toute table virtuelle : une table ou une vue du fichier y est toujours jugée avant elles, quel que soit son rang
//! dans le fichier ; une table rejouée au nom EXACT d'une table fantôme est une table fantôme du fichier, comparée à celles
//! que le module crée (ci-dessus). Un déclencheur ne prend aucun nom dans cet espace (les déclencheurs ont le leur) :
//! nommé comme une table fantôme, il reste admis sur une table ordinaire. L'écrivain ne rejoue pas une table dont le nom
//! est, AU TEXTE EXACT, celui d'une table fantôme d'une table virtuelle de la base (`collect_dump_plan` la tient pour
//! fantôme, le `rebuild` la recrée) ; une table dont le nom n'en diffère que par la casse est rejouée comme table
//! ordinaire, et la restauration la refuse ici.
//!
//! LES ARGUMENTS D'UNE TABLE VIRTUELLE, DANS LES DEUX FORMATS. L'autoriseur ne voit d'une création de table virtuelle que
//! son nom et son module (`SQLITE_CREATE_VTABLE`) : les arguments ne lui passent jamais. Une fois la chaîne préparée sous
//! la liste (une instruction, une tête, un module émis), `preparer_une_chaine_de_l_archive` relève donc les arguments
//! tels que le MOTEUR les découpe (`arguments_decoupes_par_le_moteur`, aucun découpage écrit ici) et juge chacun ENTIER,
//! au texte exact, casse et espaces compris, contre ce que l'écrivain émet (`argument_admis`) ; un seul argument hors de
//! cette liste refuse la chaîne, AVANT son exécution au format courant et avant l'export au format ancien.
use super::*;
use super::dump_restauration::SUFFIXES_DES_TABLES_FANTOMES;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

/// Les modules de table virtuelle que l'écrivain émet : `fts_external_content` n'accepte que `USING FTS5`, `FTS4` ou
/// `FTS3` (comparaison sans casse), le reste part au repli legacy et n'entre jamais dans un dump B1.
const MODULES_DE_TABLE_VIRTUELLE_EMIS: [&str; 3] = ["fts3", "fts4", "fts5"];

/// LES OPTIONS FIXES QUE L'ÉCRIVAIN ÉMET POUR FTS5, au texte exact : celles de la table du filtre de champs plein texte
/// (`maintenance::FTS_FIELDS_VTABLE_DDL`, `event_fields_fts`), la seule table virtuelle du démon qui en porte. Avec les
/// colonnes nues, `content='<table créée>'` (les trois modules, `event_fts` de `db/schema.sql` et la forme à contenu
/// externe qu'exige `fts_external_content`) et `content_rowid='<colonne nue>'` (FTS5, `event_fts`), c'est tout ce que
/// l'écrivain émet comme arguments ; relevé sur de vraies sauvegardes du schéma complet de la tête, dans les deux formats.
const OPTIONS_FIXES_DE_FTS5: [&str; 3] = [
    "content=''",
    "tokenize=\"unicode61 remove_diacritics 2 tokenchars '_-.:/@'\"",
    "prefix='2 3'",
];

/// La table de schéma que le moteur écrit lui-même pour toute création.
const TABLE_DE_SCHEMA: &str = "sqlite_master";

/// La table des compteurs AUTOINCREMENT : créée par le moteur à la première table `AUTOINCREMENT`, remplie par le démon
/// (section 3), jamais par une chaîne de l'archive.
const TABLE_DES_COMPTEURS: &str = "sqlite_sequence";

/// Le préfixe des index que le moteur crée lui-même pour une contrainte `UNIQUE`/`PRIMARY KEY` (nom réservé : aucune
/// chaîne ne peut créer un index sous ce nom).
const PREFIXE_DES_INDEX_AUTOMATIQUES: &str = "sqlite_autoindex_";

/// Les réglages qu'un module FTS lit (sans les écrire) : `data_version` (FTS5, la base a-t-elle changé sous lui) et
/// `page_size` (FTS3/FTS4, taille de ses blocs).
const PRAGMAS_LUS_PAR_LES_MODULES: [&str; 2] = ["data_version", "page_size"];

/// LES FONCTIONS ADMISES, toutes appelées par un module FTS3/FTS4 quand il vide ses données en attente dans ses tables
/// fantômes (prochain niveau et prochain bloc libres) ; relevées sur une restauration réelle. Aucune autre fonction
/// n'est appelée par une restauration conforme, et celles-ci ne le sont qu'une fois une table virtuelle créée.
const FONCTIONS_APPELEES_PAR_LES_MODULES: [&str; 2] = ["max", "coalesce"];

/// LES FONCTIONS QU'UN INDEX DU DÉMON APPELLE, dans son expression ou sa clause `WHERE` : `json_extract`, celle des index
/// de champ chaud (`maintenance::reconcile_expr_indexes_background`, créés par défaut en production). Admises pendant la
/// création d'un index de la section 4 seulement.
const FONCTIONS_DES_INDEX_EMIS: [&str; 1] = ["json_extract"];

/// Les phases de la restauration, dans l'ordre où `restore_stream` les traverse. Les phases « archive » exécutent du
/// texte lu dans le dump ; les phases « démon » n'exécutent que des instructions écrites dans `restore_stream`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Démon : `PRAGMA foreign_keys=OFF` puis `BEGIN`.
    Ouverture,
    /// Archive, section 1 : une création de table par chaîne.
    Tables,
    /// Archive, section 2 : le texte d'insertion d'une table, dans la seule table que la section annonce.
    Insertion,
    /// Démon : compteurs AUTOINCREMENT (`DELETE` puis `INSERT` dans `sqlite_sequence`).
    Compteurs,
    /// Archive, section 4 : création d'index, de déclencheur, de vue ou de table virtuelle des modules émis.
    PostDdl,
    /// Démon : `INSERT INTO "<vt>"("<vt>") VALUES('rebuild')` d'une table virtuelle créée par cette restauration.
    ReconstructionFts,
    /// Démon : `COMMIT`.
    Validation,
}

impl Phase {
    /// Le nom servi dans un refus (vocabulaire fermé).
    pub(super) fn nom(self) -> &'static str {
        match self {
            Phase::Ouverture => "ouverture",
            Phase::Tables => "tables",
            Phase::Insertion => "insertion",
            Phase::Compteurs => "compteurs",
            Phase::PostDdl => "post-DDL",
            Phase::ReconstructionFts => "reconstruction FTS",
            Phase::Validation => "validation",
        }
    }
}

/// Pourquoi une chaîne est refusée (vocabulaire fermé).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    /// L'autoriseur a refusé une action, ou la chaîne ne porte pas exactement une instruction de la famille.
    ClasseHorsListe,
    /// Le moteur a trouvé une seconde instruction derrière la première.
    PlusieursInstructions,
    /// Le texte d'insertion ne lie pas exactement les valeurs de la ligne par des paramètres anonymes (`?`), comme
    /// l'écrivain le fait.
    InsertionHorsForme,
    /// La table visée n'a pas été créée par cette restauration (insertion hors des tables de la section 1,
    /// reconstruction d'une table virtuelle que la section 4 n'a pas créée).
    TableNonCreee,
    /// Une création de table virtuelle porte un argument que l'écrivain n'émet pas (`argument_admis`).
    ArgumentDeTableVirtuelleHorsListe,
    /// Format ancien : les tables fantômes du fichier ne sont pas exactement celles que le module crée, nom et texte.
    TablesFantomesHorsDeCeQueCreeLeModule,
    /// Un index ou un déclencheur dont la cible est une table fantôme d'une table virtuelle créée par cette restauration
    /// (`admettre`).
    IndexOuDeclencheurSurUneTableFantome,
    /// Un objet de l'espace de noms des tables (table, vue, index, table virtuelle) qui porte, casse ASCII ignorée, le nom
    /// d'une table fantôme d'une table virtuelle de cette restauration : créé avant elle, sa création à elle est refusée ;
    /// créé après, la sienne (`admettre`, `prend_le_nom_d_une_table_fantome`).
    ObjetAuNomDUneTableFantome,
}

impl Cause {
    fn phrase(self) -> &'static str {
        match self {
            Cause::ClasseHorsListe => "classe d'instruction hors de la liste de la phase",
            Cause::PlusieursInstructions => "plus d'une instruction dans la chaîne",
            Cause::InsertionHorsForme => "insertion qui ne lie pas exactement les valeurs de la ligne",
            Cause::TableNonCreee => "table non créée par cette restauration",
            Cause::ArgumentDeTableVirtuelleHorsListe => "argument de table virtuelle hors de ce que l'écrivain émet",
            Cause::TablesFantomesHorsDeCeQueCreeLeModule => "tables fantômes autres que celles que le module crée",
            Cause::IndexOuDeclencheurSurUneTableFantome => "index ou déclencheur posé sur une table fantôme",
            Cause::ObjetAuNomDUneTableFantome => "objet au nom d'une table fantôme d'une table virtuelle",
        }
    }
}

/// Le nom de phase que sert le jugement du schéma d'un fichier de l'ancien format : il emprunte les phases `Tables` et
/// `PostDdl`, mais son refus nomme le format.
pub(super) const PHASE_DU_FORMAT_ANCIEN: &str = "format ancien";

/// Le refus servi : phase et cause, rien d'autre (ni le texte lu dans l'archive, ni celui du moteur).
pub(super) fn refus(phase: Phase, cause: Cause) -> String {
    refus_sous(phase.nom(), cause)
}

fn refus_sous(nom_de_phase: &str, cause: Cause) -> String {
    format!("restore : phase {nom_de_phase} : instruction hors liste ({})", cause.phrase())
}

/// LE REFUS DU MOTEUR SERVI, sans préfixe, sous le nom de phase `nom_de_phase` : la phase, « refusée par le moteur » et
/// le code d'erreur SQLite étendu ; jamais le texte du moteur. Une erreur qui ne vient pas du moteur (la bibliothèque
/// refuse un résultat qu'elle n'attendait pas, ou un texte qui n'est pas de l'UTF-8) n'a pas de code : elle le dit, sans
/// en inventer un. Le format courant le sert derrière `restore :` (`ListeFermee::refusee_par_le_moteur`) ; le format
/// ancien, derrière l'étape qui a échoué (`dump_restauration::restore_compressed`).
pub(super) fn refusee_par_le_moteur_sous(nom_de_phase: &str, e: &rusqlite::Error) -> String {
    // Une préparation refusée arrive en `SqlInputError` (le moteur y joint la chaîne et la position) ; le reste en
    // `SqliteFailure`. Les deux portent le code ; aucun texte n'est repris.
    let code = match e {
        rusqlite::Error::SqliteFailure(erreur, _) | rusqlite::Error::SqlInputError { error: erreur, .. } => Some(erreur.extended_code),
        _ => None,
    };
    match code {
        Some(code) => format!("phase {nom_de_phase} : refusée par le moteur (code {code})"),
        None => format!("phase {nom_de_phase} : refusée sans code d'erreur SQLite"),
    }
}

/// L'état que l'autoriseur lit et tient. Partagé entre la fermeture posée sur la connexion et `ListeFermee`.
struct Etat {
    phase: Phase,
    /// Insertion et reconstruction : la table annoncée par l'archive. Tables et post-DDL : l'objet que crée la chaîne
    /// en cours (table, table indexée, table virtuelle), posé par sa tête.
    cible: String,
    /// Index créé par la chaîne de post-DDL en cours (son remplissage est une action `REINDEX` sur lui seul).
    index_en_creation: String,
    /// Module de la table virtuelle que crée la chaîne en cours (posé par sa tête) : ses arguments restent à juger.
    module_en_creation: Option<String>,
    /// Tables ordinaires créées par la section 1 de CETTE restauration.
    tables_creees: std::collections::HashSet<String>,
    /// Tables virtuelles créées par la section 4 de CETTE restauration.
    tables_virtuelles_creees: std::collections::HashSet<String>,
    /// LES NOMS PRIS dans l'espace de noms des tables par une chaîne de l'archive de CETTE restauration (table, vue, index,
    /// table virtuelle ; `nom_dans_l_espace_des_tables`), au texte que le moteur passe à l'autoriseur. Un index du
    /// format ancien, que le brouillon prépare sans le créer, y entre comme les autres : l'export le créera.
    noms_pris: std::collections::HashSet<String>,
    /// Actions « tête » vues depuis l'entrée dans la phase (cf. en-tête du module).
    tetes: u32,
    /// Une chaîne lue dans l'archive est en cours de préparation : aucune action interne d'un module n'y est admise.
    preparation_de_l_archive: bool,
    /// L'autoriseur a refusé au moins une action depuis l'entrée dans la phase.
    refus: bool,
    /// Parmi ces refus, celui qui nomme sa propre cause (index ou déclencheur sur une table fantôme, objet au nom d'une
    /// table fantôme). Jamais remis à zéro : un refus arrête la restauration ou le jugement du format ancien.
    cause_nommee: Option<Cause>,
}

impl Etat {
    /// `nom` est une table fantôme d'une table virtuelle créée par cette restauration (`<vt>_<suffixe>`, suffixes de
    /// l'écrivain, `collect_dump_plan`).
    fn est_une_table_fantome(&self, nom: &str) -> bool {
        self.tables_virtuelles_creees.iter().any(|vt| est_une_table_fantome_de(vt, nom))
    }
}

/// `nom` est `<vt>_<suffixe>`, l'un des suffixes de l'écrivain (`SUFFIXES_DES_TABLES_FANTOMES`), au texte exact.
fn est_une_table_fantome_de(vt: &str, nom: &str) -> bool {
    nom.len() > vt.len() + 1
        && nom.starts_with(vt)
        && nom.as_bytes()[vt.len()] == b'_'
        && SUFFIXES_DES_TABLES_FANTOMES.contains(&&nom[vt.len() + 1..])
}

/// `nom` désigne, POUR LE MOTEUR, une table fantôme de `vt` : même règle, casse ASCII ignorée (le moteur résout les noms
/// de table sans elle, et un module qui crée `<vt>_stat` par `IF NOT EXISTS` trouve `<VT>_STAT`).
fn designe_une_table_fantome_de(vt: &str, nom: &str) -> bool {
    est_une_table_fantome_de(&vt.to_ascii_lowercase(), &nom.to_ascii_lowercase())
}

/// LE NOM QUE PREND, dans l'espace de noms des tables, la création que porte `action` : table, vue, index, table
/// virtuelle. Un déclencheur n'y prend aucun nom : les déclencheurs ont leur propre espace de noms (le module crée sa
/// table sous le nom d'un déclencheur déjà là).
fn nom_dans_l_espace_des_tables<'a>(action: &AuthAction<'a>) -> Option<&'a str> {
    use AuthAction as A;
    match *action {
        A::CreateTable { table_name } => Some(table_name),
        A::CreateView { view_name } => Some(view_name),
        A::CreateIndex { index_name, .. } => Some(index_name),
        A::CreateVtable { table_name, .. } => Some(table_name),
        _ => None,
    }
}

/// `nom`, que prend la création `action` d'une chaîne de l'archive, est celui d'une table fantôme, casse ASCII ignorée des
/// deux côtés (`designe_une_table_fantome_de`) :
///  - AVANT : `action` crée une table virtuelle et un nom déjà pris (`noms_pris`) est celui de l'une de ses tables
///    fantômes ; un module qui crée sa table par `CREATE TABLE IF NOT EXISTS` (FTS4 et sa table `<vt>_stat`) adopterait
///    l'objet déjà là, quel que soit son genre, avec ce qu'on y a posé ;
///  - APRÈS : `nom` est celui d'une table fantôme d'une table virtuelle déjà créée par cette restauration.
fn prend_le_nom_d_une_table_fantome(e: &Etat, action: &AuthAction<'_>, nom: &str) -> bool {
    let avant = matches!(*action, AuthAction::CreateVtable { .. }) && e.noms_pris.iter().any(|pris| designe_une_table_fantome_de(nom, pris));
    let apres = e.tables_virtuelles_creees.iter().any(|vt| designe_une_table_fantome_de(vt, nom));
    avant || apres
}

/// Les actions qu'un module FTS fait lui-même sur SES tables fantômes (cf. en-tête du module), dans toute phase où une
/// table virtuelle créée par cette restauration existe et peut travailler. Aucune avant la première création, aucune
/// pendant la préparation d'une chaîne de l'archive (le module ne prépare ses instructions qu'à l'exécution).
fn action_interne_d_un_module(e: &Etat, action: &AuthAction<'_>) -> bool {
    use AuthAction as A;
    if e.tables_virtuelles_creees.is_empty() || e.preparation_de_l_archive {
        return false;
    }
    match *action {
        A::CreateTable { table_name } => e.est_une_table_fantome(table_name),
        A::CreateIndex { index_name, table_name } => {
            index_name.starts_with(PREFIXE_DES_INDEX_AUTOMATIQUES) && e.est_une_table_fantome(table_name)
        }
        A::Insert { table_name } | A::Delete { table_name } | A::Update { table_name, .. } | A::Read { table_name, .. } => {
            e.est_une_table_fantome(table_name)
        }
        A::Select => true,
        A::Pragma { pragma_name, pragma_value: None } => PRAGMAS_LUS_PAR_LES_MODULES.iter().any(|p| p.eq_ignore_ascii_case(pragma_name)),
        A::Function { function_name } => FONCTIONS_APPELEES_PAR_LES_MODULES.iter().any(|f| f.eq_ignore_ascii_case(function_name)),
        _ => false,
    }
}

/// Le crochet de test `crochets_de_restauration::sans_refus_sur_les_tables_fantomes` est armé sur ce fil ; toujours faux
/// hors des tests.
fn tables_fantomes_ouvertes() -> bool {
    #[cfg(test)]
    return crochets_de_restauration::refus_sur_les_tables_fantomes_leve();
    #[cfg(not(test))]
    false
}

/// `sqlite_master`, que le moteur écrit et relit lui-même pour toute création.
fn action_interne_d_une_creation(action: &AuthAction<'_>) -> bool {
    use AuthAction as A;
    matches!(*action,
        A::Insert { table_name } | A::Update { table_name, .. } | A::Read { table_name, .. } if table_name == TABLE_DE_SCHEMA)
}

/// LA LISTE. Rend vrai si l'action est admise dans la phase courante ; tient au passage le compte des têtes et les
/// objets créés. Toute action qu'un bras ne nomme pas est refusée.
fn admettre(e: &mut Etat, ctx: &AuthContext<'_>) -> bool {
    use AuthAction as A;
    // Aucun déclencheur ni aucune vue ne s'exécute pendant une restauration conforme (les déclencheurs et les vues
    // sont créés en dernier, après les données) : une action portée par l'un d'eux n'est pas dans la liste.
    if ctx.accessor.is_some() {
        return false;
    }
    // UN OBJET AU NOM D'UNE TABLE FANTÔME : jugé sur toute création que porte une chaîne de l'archive, quels que soient sa
    // phase et son genre, avant le bras qui l'admettrait ; refusé sous sa propre cause. Le module crée ses tables
    // fantômes à l'exécution, jamais pendant la préparation d'une chaîne de l'archive : elles ne passent pas ici.
    if e.preparation_de_l_archive {
        match nom_dans_l_espace_des_tables(&ctx.action) {
            Some(nom) if prend_le_nom_d_une_table_fantome(e, &ctx.action, nom) => {
                e.cause_nommee = Some(Cause::ObjetAuNomDUneTableFantome);
                return false;
            }
            Some(nom) => {
                e.noms_pris.insert(nom.to_string());
            }
            None => {}
        }
    }
    match (e.phase, ctx.action) {
        // ── Démon ─────────────────────────────────────────────────────────────────────────────────────────────
        (Phase::Ouverture, A::Pragma { pragma_name, pragma_value: Some(v) }) => {
            pragma_name.eq_ignore_ascii_case("foreign_keys") && v.eq_ignore_ascii_case("OFF")
        }
        (Phase::Ouverture, A::Transaction { operation: TransactionOperation::Begin }) => true,
        (Phase::Compteurs, A::Delete { table_name }) | (Phase::Compteurs, A::Insert { table_name }) => table_name == TABLE_DES_COMPTEURS,
        // `COMMIT` arrive en `Unknown` : rusqlite 0.31 ne nomme que BEGIN, RELEASE et ROLLBACK. Un module FTS y vide ses
        // données en attente.
        (Phase::Validation, A::Transaction { operation: TransactionOperation::Unknown }) => true,
        (Phase::Validation, action) => action_interne_d_un_module(e, &action),
        // ── Archive, section 1 ────────────────────────────────────────────────────────────────────────────────
        (Phase::Tables, A::CreateTable { table_name }) => {
            // `sqlite_sequence` : création imbriquée que le moteur fait pour la première table AUTOINCREMENT.
            if table_name != TABLE_DES_COMPTEURS {
                e.tetes += 1;
                e.cible = table_name.to_string();
                e.tables_creees.insert(table_name.to_string());
            }
            true
        }
        // Index automatique d'une contrainte de la table en création, et lecture des colonnes qu'il couvre.
        (Phase::Tables, A::CreateIndex { index_name, table_name }) => {
            index_name.starts_with(PREFIXE_DES_INDEX_AUTOMATIQUES) && table_name == e.cible
        }
        (Phase::Tables, A::Read { table_name, .. }) if table_name == e.cible => true,
        (Phase::Tables, action) if action_interne_d_une_creation(&action) => true,
        // ── Archive, section 2 ────────────────────────────────────────────────────────────────────────────────
        (Phase::Insertion, A::Insert { table_name }) if table_name == e.cible => {
            e.tetes += 1;
            true
        }
        // ── Archive, section 4 ────────────────────────────────────────────────────────────────────────────────
        // UN INDEX OU UN DÉCLENCHEUR SUR UNE TABLE FANTÔME : refusé, sous sa propre cause. Le module écrit lui-même dans
        // ses tables fantômes, après la restauration sur la connexion du démon et sans autoriseur ; un index (`UNIQUE`,
        // partiel) y bornerait ses écritures, un déclencheur y ferait jouer son corps à chacune. La cible est celle que
        // le moteur passe à l'autoriseur (le nom de la table telle qu'il l'a trouvée), jamais lue dans le texte. Les
        // index automatiques d'une table fantôme, que seul le moteur nomme, restent des actions internes du module.
        (Phase::PostDdl, A::CreateIndex { index_name, table_name })
            if !index_name.starts_with(PREFIXE_DES_INDEX_AUTOMATIQUES) && e.est_une_table_fantome(table_name) && !tables_fantomes_ouvertes() =>
        {
            e.cause_nommee = Some(Cause::IndexOuDeclencheurSurUneTableFantome);
            false
        }
        (Phase::PostDdl, A::CreateTrigger { table_name, .. }) if e.est_une_table_fantome(table_name) && !tables_fantomes_ouvertes() => {
            e.cause_nommee = Some(Cause::IndexOuDeclencheurSurUneTableFantome);
            false
        }
        (Phase::PostDdl, A::CreateIndex { index_name, table_name }) if !index_name.starts_with(PREFIXE_DES_INDEX_AUTOMATIQUES) => {
            e.tetes += 1;
            e.cible = table_name.to_string();
            e.index_en_creation = index_name.to_string();
            true
        }
        // Lecture des colonnes que l'index en création couvre, et son remplissage.
        (Phase::PostDdl, A::Read { table_name, .. }) if !e.index_en_creation.is_empty() && table_name == e.cible => true,
        (Phase::PostDdl, A::Reindex { index_name }) => !e.index_en_creation.is_empty() && index_name == e.index_en_creation,
        // Expression ou clause `WHERE` de l'index en création : les fonctions des index du démon.
        (Phase::PostDdl, A::Function { function_name })
            if !e.index_en_creation.is_empty() && FONCTIONS_DES_INDEX_EMIS.iter().any(|f| f.eq_ignore_ascii_case(function_name)) =>
        {
            true
        }
        (Phase::PostDdl, A::CreateTrigger { .. }) | (Phase::PostDdl, A::CreateView { .. }) => {
            e.tetes += 1;
            true
        }
        (Phase::PostDdl, A::CreateVtable { table_name, module_name })
            if MODULES_DE_TABLE_VIRTUELLE_EMIS.iter().any(|m| m.eq_ignore_ascii_case(module_name)) =>
        {
            e.tetes += 1;
            e.tables_virtuelles_creees.insert(table_name.to_string());
            e.module_en_creation = Some(module_name.to_string());
            true
        }
        (Phase::PostDdl, action) if action_interne_d_une_creation(&action) || action_interne_d_un_module(e, &action) => true,
        // ── Démon, reconstruction FTS ─────────────────────────────────────────────────────────────────────────
        (Phase::ReconstructionFts, A::Insert { table_name }) if table_name == e.cible => true,
        // La table de contenu que le module relit : une table de la section 1.
        (Phase::ReconstructionFts, A::Read { table_name, .. }) if e.tables_creees.contains(table_name) => true,
        (Phase::ReconstructionFts, action) => action_interne_d_un_module(e, &action),
        _ => false,
    }
}

/// L'autoriseur posé sur la connexion de restauration et l'état qu'il tient.
pub(super) struct ListeFermee {
    etat: std::sync::Arc<std::sync::Mutex<Etat>>,
    /// Le nom de phase servi par chaque refus de `preparer_une_chaine_de_l_archive` et `executer_une_chaine` : `None`,
    /// celui de la phase (format courant) ; `Some`, celui du format ancien.
    nom_servi: Option<&'static str>,
}

impl ListeFermee {
    /// POSE L'AUTORISEUR. À appeler juste après l'ouverture (clé et réglages mémoire posés), avant toute instruction de
    /// la restauration.
    pub(super) fn armer(conn: &Connection) -> ListeFermee {
        #[cfg(test)]
        crochets_de_restauration::passer_la_connexion(conn);
        ListeFermee::armer_sous(conn, None)
    }

    /// POSE L'AUTORISEUR sur la base de brouillon où se juge le schéma d'un fichier de l'ancien format : même liste, et
    /// chaque refus nomme la phase « format ancien ».
    fn armer_pour_le_format_ancien(conn: &Connection) -> ListeFermee {
        ListeFermee::armer_sous(conn, Some(PHASE_DU_FORMAT_ANCIEN))
    }

    fn armer_sous(conn: &Connection, nom_servi: Option<&'static str>) -> ListeFermee {
        let etat = std::sync::Arc::new(std::sync::Mutex::new(Etat {
            phase: Phase::Ouverture,
            cible: String::new(),
            index_en_creation: String::new(),
            module_en_creation: None,
            tables_creees: Default::default(),
            tables_virtuelles_creees: Default::default(),
            noms_pris: Default::default(),
            tetes: 0,
            preparation_de_l_archive: false,
            refus: false,
            cause_nommee: None,
        }));
        let pour_le_moteur = etat.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            let mut e = pour_le_moteur.lock().unwrap_or_else(|p| p.into_inner());
            if admettre(&mut e, &ctx) {
                Authorization::Allow
            } else {
                e.refus = true;
                Authorization::Deny
            }
        }));
        ListeFermee { etat, nom_servi }
    }

    /// Le refus nommé de `phase`, sous le nom que cette liste sert.
    fn refus(&self, phase: Phase, cause: Cause) -> String {
        refus_sous(self.nom_servi.unwrap_or(phase.nom()), cause)
    }

    /// Le refus du moteur dans `phase`, sous le nom que cette liste sert (`refusee_par_le_moteur_sous`).
    pub(super) fn refusee_par_le_moteur(&self, phase: Phase, e: &rusqlite::Error) -> String {
        format!("restore : {}", refusee_par_le_moteur_sous(self.nom_servi.unwrap_or(phase.nom()), e))
    }

    fn etat(&self) -> std::sync::MutexGuard<'_, Etat> {
        self.etat.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Entre dans `phase` (compte des têtes, refus et objet en création remis à zéro), avec la cible `cible`
    /// (insertion, reconstruction ; vide ailleurs).
    pub(super) fn entrer(&self, phase: Phase, cible: &str) {
        let mut e = self.etat();
        e.phase = phase;
        e.cible = cible.to_string();
        e.index_en_creation.clear();
        e.module_en_creation = None;
        e.tetes = 0;
        e.refus = false;
    }

    /// L'autoriseur a refusé une action depuis l'entrée dans la phase courante.
    pub(super) fn a_refuse(&self) -> bool {
        self.etat().refus
    }

    /// `nom` est une table créée par la section 1 de cette restauration.
    pub(super) fn table_creee(&self, nom: &str) -> bool {
        self.etat().tables_creees.contains(nom)
    }

    /// `nom` est une table virtuelle créée par la section 4 de cette restauration.
    pub(super) fn table_virtuelle_creee(&self, nom: &str) -> bool {
        self.etat().tables_virtuelles_creees.contains(nom)
    }

    /// PRÉPARE UNE CHAÎNE LUE DANS L'ARCHIVE dans `phase` : l'autoriseur juge chaque action, la chaîne doit porter
    /// exactement une tête et aucune seconde instruction. Une chaîne de la famille que le moteur refuse de lui-même
    /// rend le refus du moteur (code, sans texte). Une création de table virtuelle est jugée en dernier sur ses arguments
    /// (`juger_les_arguments_de_la_table_virtuelle`) : aucune des causes précédentes n'est masquée.
    pub(super) fn preparer_une_chaine_de_l_archive<'c>(
        &self,
        conn: &'c Connection,
        phase: Phase,
        cible: &str,
        chaine: &str,
    ) -> Result<rusqlite::Statement<'c>, String> {
        self.entrer(phase, cible);
        let mut lot = rusqlite::Batch::new(conn, chaine);
        self.etat().preparation_de_l_archive = true;
        let premiere = lot.next();
        let (hors_liste, cause_nommee) = {
            let mut e = self.etat();
            e.preparation_de_l_archive = false;
            (e.refus || e.tetes != 1, e.cause_nommee)
        };
        if let Some(cause) = cause_nommee {
            return Err(self.refus(phase, cause));
        }
        let premiere = match premiere {
            _ if hors_liste => return Err(self.refus(phase, Cause::ClasseHorsListe)),
            Err(e) => return Err(self.refusee_par_le_moteur(phase, &e)),
            // Inatteignable : une chaîne sans instruction n'a pas de tête, le premier bras la refuse.
            Ok(None) => return Err(self.refus(phase, Cause::ClasseHorsListe)),
            Ok(Some(s)) => s,
        };
        self.etat().preparation_de_l_archive = true;
        let seconde = lot.next();
        self.etat().preparation_de_l_archive = false;
        if !matches!(seconde, Ok(None)) {
            return Err(self.refus(phase, Cause::PlusieursInstructions));
        }
        self.juger_les_arguments_de_la_table_virtuelle(phase, chaine)?;
        Ok(premiere)
    }

    /// LES ARGUMENTS DE LA TABLE VIRTUELLE que crée `chaine` (tête vue par l'autoriseur pendant sa préparation), chacun
    /// jugé par `argument_admis` contre les tables ordinaires créées jusqu'ici par cette restauration. Une chaîne qui ne
    /// crée pas de table virtuelle n'est pas concernée.
    fn juger_les_arguments_de_la_table_virtuelle(&self, phase: Phase, chaine: &str) -> Result<(), String> {
        #[cfg(test)]
        if crochets_de_restauration::arguments_non_juges() {
            return Ok(());
        }
        let (module, tables_creees) = {
            let e = self.etat();
            (e.module_en_creation.clone(), e.tables_creees.clone())
        };
        let admis = match module {
            None => true,
            // `None` des arguments : aucun relevé (cf. `arguments_decoupes_par_le_moteur`), le jugement reste fermé.
            Some(module) => arguments_decoupes_par_le_moteur(chaine)
                .map_or(false, |arguments| arguments.iter().all(|a| argument_admis(&module, a, &tables_creees))),
        };
        if admis { Ok(()) } else { Err(self.refus(phase, Cause::ArgumentDeTableVirtuelleHorsListe)) }
    }

    /// EXÉCUTE UNE CHAÎNE PRÉPARÉE sous la liste. Un refus de l'autoriseur PENDANT l'exécution (écriture interne d'un
    /// module hors de ses tables fantômes) rend le refus nommé de la phase ; toute autre erreur, le refus du moteur.
    pub(super) fn executer_une_chaine(&self, mut stmt: rusqlite::Statement<'_>, phase: Phase) -> Result<(), String> {
        match stmt.execute([]) {
            Ok(_) => Ok(()),
            Err(_) if self.a_refuse() => Err(self.refus(phase, Cause::ClasseHorsListe)),
            Err(e) => Err(self.refusee_par_le_moteur(phase, &e)),
        }
    }
}

/// LES ARGUMENTS D'UNE CRÉATION DE TABLE VIRTUELLE, TELS QUE LE MOTEUR LES DÉCOUPE (`argv[3..]` du constructeur du module :
/// le texte de chaque argument, de son premier à son dernier jeton, celui que le module lira). Aucun découpage n'est écrit
/// ici : `chaine` est jouée sur une base jetable en mémoire où les modules émis sont remplacés par un module ESPION qui
/// relève ses arguments puis refuse la création ; rien n'est créé, ni là ni sur la connexion de la restauration.
///
/// À n'appeler que sur une chaîne que la liste a déjà admise : une instruction, une tête `CreateVtable`, un module émis,
/// aucune fonction (l'autoriseur n'admet aucune action d'un module pendant la préparation d'une chaîne de l'archive).
/// Remplacer `fts5` sur la base jetable libère le contexte global du module FTS5 de CETTE connexion ; ce qui le cite
/// encore (le module `fts5vocab`, les fonctions `fts5()` et `fts5_*`) n'y est plus appelé : la seule instruction jouée
/// est la création admise, et la fermeture ne détruit ni l'un ni les autres par ce contexte (`fts5vocab` n'est pas
/// éponyme, ces fonctions n'ont pas de destructeur ; `sqlite3.c`, `fts5Init`).
///
/// `None` (refus) si rien n'a été relevé. C'est le cas d'une chaîne admise qui ne joue pas la création :
/// `EXPLAIN CREATE VIRTUAL TABLE …` a la même tête `CreateVtable`, mais son exécution rend le programme (une erreur, pour
/// `execute`) sans appeler l'espion ; une exécution réussie veut dire, elle aussi, qu'il ne l'a pas été. Un argument est
/// une tranche d'une chaîne UTF-8, donc de l'UTF-8.
fn arguments_decoupes_par_le_moteur(chaine: &str) -> Option<Vec<String>> {
    use rusqlite::ffi;
    use std::os::raw::{c_char, c_int, c_void};
    type Releve = std::sync::Mutex<Option<Option<Vec<String>>>>;
    unsafe extern "C" fn relever_puis_refuser(
        _: *mut ffi::sqlite3,
        aux: *mut c_void,
        argc: c_int,
        argv: *const *const c_char,
        _: *mut *mut ffi::sqlite3_vtab,
        _: *mut *mut c_char,
    ) -> c_int {
        // SAFETY : `aux` est le `Releve` que `arguments_decoupes_par_le_moteur` garde vivant tant que la base jetable est
        // ouverte ; `argv` porte `argc` chaînes C que SQLite garde vivantes pendant l'appel.
        let releve = &*(aux as *const Releve);
        let arguments = (3..argc.max(3))
            .map(|i| {
                let p = *argv.add(i as usize);
                if p.is_null() { None } else { std::ffi::CStr::from_ptr(p).to_str().ok().map(str::to_string) }
            })
            .collect::<Option<Vec<String>>>();
        *releve.lock().unwrap_or_else(|p| p.into_inner()) = Some(arguments);
        ffi::SQLITE_ERROR
    }
    // Le moteur ne joue le constructeur d'un module que s'il a aussi un destructeur (`sqlite3VtabCallCreate`, « no such
    // module » sinon). Celui-ci n'est jamais appelé : le constructeur refuse toujours, aucune table n'existe à détruire.
    unsafe extern "C" fn aucune_table_a_detruire(_: *mut ffi::sqlite3_vtab) -> c_int {
        ffi::SQLITE_OK
    }
    let releve: Box<Releve> = Box::new(std::sync::Mutex::new(None));
    // SAFETY : une structure C de pointeurs de fonction facultatifs et d'un entier, tous valides à zéro (aucun).
    let mut espion: Box<ffi::sqlite3_module> = Box::new(unsafe { std::mem::zeroed() });
    espion.xCreate = Some(relever_puis_refuser);
    espion.xDestroy = Some(aucune_table_a_detruire);
    {
        // Fermée à la fin de ce bloc, avant que `espion` et `releve`, qu'elle cite, ne soient libérés.
        let jetable = Connection::open_in_memory().ok()?;
        for module in MODULES_DE_TABLE_VIRTUELLE_EMIS {
            let nom = std::ffi::CString::new(module).ok()?;
            // SAFETY : la poignée vit autant que `jetable` ; le moteur recopie le nom ; `espion` et `releve` survivent à
            // `jetable`.
            let rc = unsafe {
                ffi::sqlite3_create_module_v2(jetable.handle(), nom.as_ptr(), &*espion, &*releve as *const Releve as *mut c_void, None)
            };
            if rc != ffi::SQLITE_OK {
                return None;
            }
        }
        let mut lot = rusqlite::Batch::new(&jetable, chaine);
        let premiere = lot.next();
        let creation_en_echec = match premiere {
            Ok(Some(mut creation)) => creation.execute([]).is_err(),
            Ok(None) | Err(_) => false,
        };
        if !creation_en_echec {
            return None;
        }
    }
    let releve: Releve = *releve;
    releve.into_inner().unwrap_or_else(|p| p.into_inner()).flatten()
}

/// Un nom nu : `[A-Za-z_][A-Za-z0-9_]*`, rien d'autre.
fn est_un_nom_nu(s: &str) -> bool {
    let mut octets = s.bytes();
    matches!(octets.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_') && octets.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `argument` est exactement `<cle>'<valeur>'`, la valeur sans apostrophe : rend la valeur.
fn valeur_entre_apostrophes<'a>(argument: &'a str, cle: &str) -> Option<&'a str> {
    let reste = argument.strip_prefix(cle)?;
    let valeur = reste.strip_prefix('\'')?.strip_suffix('\'')?;
    if valeur.contains('\'') { None } else { Some(valeur) }
}

/// UN ARGUMENT DE TABLE VIRTUELLE QUE L'ÉCRIVAIN ÉMET, jugé ENTIER, au texte exact (casse et espaces compris : une autre
/// écriture, même lue de la même façon par le module, n'est pas ce que l'écrivain émet) :
///  - un nom de colonne nu (`est_un_nom_nu`) ;
///  - `content='<table>'`, `<table>` étant une table ordinaire créée par CETTE restauration (`tables_creees`) : la table
///    de contenu que le module lira est une table que l'archive a restaurée ;
///  - pour FTS5 seulement : `content_rowid='<colonne nue>'` et les options de `OPTIONS_FIXES_DE_FTS5`.
/// Tout le reste est refusé : un autre découpeur, une autre option (dont les fonctions que FTS4 appellerait à chaque
/// écriture, `compress=`/`uncompress=`), une colonne typée, une valeur entre guillemets.
fn argument_admis(module: &str, argument: &str, tables_creees: &std::collections::HashSet<String>) -> bool {
    if est_un_nom_nu(argument) {
        return true;
    }
    match valeur_entre_apostrophes(argument, "content=") {
        Some(table) if !table.is_empty() => {
            return tables_creees.contains(table);
        }
        _ => {}
    }
    if !module.eq_ignore_ascii_case("fts5") {
        return false;
    }
    if OPTIONS_FIXES_DE_FTS5.contains(&argument) {
        return true;
    }
    valeur_entre_apostrophes(argument, "content_rowid=").map_or(false, est_un_nom_nu)
}

/// LES TABLES QUE LE MOTEUR CRÉE LUI-MÊME, au texte exact qu'il écrit dans `sqlite_master` : compteurs AUTOINCREMENT, et
/// statistiques d'`ANALYZE` (que la migration et l'entretien jouent). Relevé sur l'export ancien d'une base au schéma
/// complet de la tête : ces trois lignes, et le moteur refuse leur création par une chaîne (nom réservé, avant toute
/// action de l'autoriseur). L'export recrée les deux tables de statistiques par ce texte et remplit les compteurs dans
/// la table que crée la première table AUTOINCREMENT ; aucun autre texte n'est exempté, même sous l'un de ces noms.
const TABLES_DU_MOTEUR: [&str; 3] = [
    "CREATE TABLE sqlite_sequence(name,seq)",
    "CREATE TABLE sqlite_stat1(tbl,idx,stat)",
    "CREATE TABLE sqlite_stat4(tbl,idx,neq,nlt,ndlt,sample)",
];

/// Une ligne de schéma d'un fichier de l'ancien format, telle que l'export la traite.
struct LigneDuFormatAncien {
    /// `type = 'table' AND rootpage > 0` : l'export rejoue son `sql` comme une création de table.
    table_rejouee: bool,
    /// `type = 'table'` : avec `table_rejouee` faux, une table virtuelle (ou une ligne qui se dit table sans racine,
    /// jugée comme toute autre ligne).
    table: bool,
    /// `name`, vide s'il manque : le nom sous lequel une table fantôme du fichier se reconnaît.
    nom: String,
    /// `type = 'view'` : l'export la recopie telle quelle ; un déclencheur `INSTEAD OF` s'y appuie.
    vue: bool,
    sql: String,
}

/// LE SCHÉMA DU FICHIER EN CLAIR, dans l'ordre où il a été créé : toute ligne qui porte un `sql`. Une ligne sans `sql`
/// (index automatique d'une contrainte) n'est ni rejouée ni relue comme une instruction. Un `sql` qui n'est pas un texte
/// UTF-8 est refusé comme une valeur que la bibliothèque ne lit pas.
fn lire_le_schema_du_format_ancien(clair: &Connection) -> Result<Vec<LigneDuFormatAncien>, String> {
    let refusee = |e: rusqlite::Error| format!("restore : {}", refusee_par_le_moteur_sous(PHASE_DU_FORMAT_ANCIEN, &e));
    let mut s = clair
        .prepare(
            "SELECT COALESCE(type = 'table' AND rootpage > 0, 0), COALESCE(type = 'view', 0), sql, \
             COALESCE(type = 'table', 0), COALESCE(name, '') FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid",
        )
        .map_err(refusee)?;
    let lignes = s
        .query_map([], |r| Ok(LigneDuFormatAncien { table_rejouee: r.get(0)?, vue: r.get(1)?, sql: r.get(2)?, table: r.get(3)?, nom: r.get(4)? }))
        .map_err(refusee)?;
    lignes.collect::<rusqlite::Result<Vec<_>>>().map_err(refusee)
}

/// UNE COLLATION INCONNUE N'ARRÊTE PAS LE JUGEMENT. Ce n'est pas une classe d'instruction : le moteur la cherche en lisant
/// la colonne qui la nomme, et sans elle la préparation s'arrêterait là, le reste de la chaîne (une contrainte qui
/// appelle une fonction, par exemple) n'étant jamais montré à l'autoriseur. Le brouillon reçoit donc, pour tout nom
/// inconnu, une collation qui compare les octets ; elle n'existe que sur lui. L'export, qui joue ensuite la même chaîne
/// sur la connexion du fichier où ce nom reste inconnu, la refuse comme avant. Si l'inscription échouait, la collation
/// resterait absente et la préparation rendrait le refus du moteur : le jugement reste fermé.
fn accepter_toute_collation_sur_le_brouillon(brouillon: &Connection) {
    use rusqlite::ffi;
    use std::os::raw::{c_char, c_int, c_void};
    unsafe fn octets<'a>(p: *const c_void, n: c_int) -> &'a [u8] {
        if p.is_null() || n <= 0 { &[] } else { std::slice::from_raw_parts(p as *const u8, n as usize) }
    }
    unsafe extern "C" fn comparer_les_octets(_: *mut c_void, n1: c_int, p1: *const c_void, n2: c_int, p2: *const c_void) -> c_int {
        match octets(p1, n1).cmp(octets(p2, n2)) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
    unsafe extern "C" fn inscrire_la_collation_demandee(_: *mut c_void, db: *mut ffi::sqlite3, _: c_int, nom: *const c_char) {
        ffi::sqlite3_create_collation_v2(db, nom, ffi::SQLITE_UTF8, std::ptr::null_mut(), Some(comparer_les_octets), None);
    }
    // SAFETY : la poignée vit autant que `brouillon` ; le rappel n'emploie que les arguments que SQLite lui passe.
    unsafe {
        ffi::sqlite3_collation_needed(brouillon.handle(), std::ptr::null_mut(), Some(inscrire_la_collation_demandee));
    }
}

/// JUGE LE SCHÉMA D'UN FICHIER DE L'ANCIEN FORMAT, AVANT L'EXPORT (cf. en-tête du module). Sur un brouillon en mémoire
/// armé de la liste : chaque table que l'export rejoue est jugée sous `Tables` puis créée (index et déclencheurs
/// s'appuient sur elle) ; chaque vue est jugée sous `PostDdl` puis créée (un déclencheur `INSTEAD OF` s'y appuie) ; toute
/// autre ligne est jugée sous `PostDdl`, et seule une création de table virtuelle y est aussi EXÉCUTÉE, comme au format
/// courant : ce que le module fait à sa création passe sous la liste (`executer_une_chaine`), et il y crée ses tables
/// fantômes. Les index et déclencheurs ne sont que préparés : l'autoriseur juge une instruction pendant sa préparation.
/// Les arguments d'une table virtuelle, que l'autoriseur ne voit pas, sont jugés par `preparer_une_chaine_de_l_archive`
/// contre les tables créées sur le brouillon.
///
/// LES TABLES FANTÔMES DU FICHIER (une table rejouée nommée `<vt>_<suffixe>`, `vt` étant le nom d'une ligne de table non
/// rejouée du fichier) ne sont pas créées comme des tables : le module les crée sur le brouillon. Une fois toutes les
/// lignes jugées, l'ensemble de leurs noms et de leurs textes doit être EXACTEMENT celui des tables fantômes que les
/// modules ont créées sur le brouillon ; une table en trop, une table absente ou un texte réécrit refuse
/// (`Cause::TablesFantomesHorsDeCeQueCreeLeModule`). Un index ou un déclencheur du fichier dont la cible est l'une
/// d'elles est refusé pendant sa préparation (`admettre`, `Cause::IndexOuDeclencheurSurUneTableFantome`) ; une table
/// rejouée dont le nom n'en diffère que par la casse est créée comme une table ordinaire, et tout objet au nom d'une table
/// fantôme (table, vue, index, table virtuelle) est refusé à la création de la table virtuelle ou à la sienne
/// (`Cause::ObjetAuNomDUneTableFantome`, cf. en-tête du module). Leurs LIGNES,
/// que l'export recopie, ne sont pas jugées : une table sans contenu (`content=''`) n'a pas d'autre copie de ses données.
///
/// Le premier refus arrête le jugement et nomme la phase « format ancien ».
///
/// Un refus du MOTEUR pendant le jugement (une ligne que le brouillon ne sait pas préparer ou créer) reste servi, fermé,
/// sous « format ancien » et son code, quelle que soit la phase sous laquelle la ligne était jugée. Un fichier que le
/// moteur a relu y mène : le moteur relit un schéma sans résoudre les noms qu'il cite, et la préparation sur le
/// brouillon refuse alors une contrainte qui cite une colonne absente (une table) ou un index qui appelle une fonction
/// inconnue (code 1). Une collation inconnue, elle, est absorbée (`accepter_toute_collation_sur_le_brouillon`), et les
/// vues sont créées avant les déclencheurs qui s'y appuient.
pub(super) fn juger_le_schema_du_format_ancien(clair: &Connection) -> Result<(), String> {
    let lignes = lire_le_schema_du_format_ancien(clair)?;
    let refusee = |e: rusqlite::Error| format!("restore : {}", refusee_par_le_moteur_sous(PHASE_DU_FORMAT_ANCIEN, &e));
    let brouillon = Connection::open_in_memory().map_err(refusee)?;
    accepter_toute_collation_sur_le_brouillon(&brouillon);
    let liste = ListeFermee::armer_pour_le_format_ancien(&brouillon);
    let jugees: Vec<&LigneDuFormatAncien> = lignes.iter().filter(|l| !TABLES_DU_MOTEUR.contains(&l.sql.as_str())).collect();
    let virtuelles: Vec<&str> = jugees.iter().filter(|l| l.table && !l.table_rejouee).map(|l| l.nom.as_str()).collect();
    let fantome_du_fichier = |l: &LigneDuFormatAncien| l.table_rejouee && virtuelles.iter().any(|vt| est_une_table_fantome_de(vt, &l.nom));
    for l in jugees.iter().filter(|l| l.table_rejouee && !fantome_du_fichier(l)) {
        let stmt = liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::Tables, "", &l.sql)?;
        liste.executer_une_chaine(stmt, Phase::Tables)?;
    }
    for l in jugees.iter().filter(|l| !l.table_rejouee && l.vue) {
        let stmt = liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::PostDdl, "", &l.sql)?;
        liste.executer_une_chaine(stmt, Phase::PostDdl)?;
    }
    for l in jugees.iter().filter(|l| !l.table_rejouee && !l.vue) {
        let stmt = liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::PostDdl, "", &l.sql)?;
        let cree_une_table_virtuelle = liste.etat().module_en_creation.is_some();
        if cree_une_table_virtuelle {
            liste.executer_une_chaine(stmt, Phase::PostDdl)?;
        }
    }
    // Le jugement est fait : l'autoriseur est retiré pour relire le schéma du brouillon.
    brouillon.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let du_fichier: std::collections::BTreeSet<(String, String)> =
        jugees.iter().filter(|l| fantome_du_fichier(l)).map(|l| (l.nom.clone(), l.sql.clone())).collect();
    // HORS D'ATTEINTE par une archive : la relecture vise le brouillon en mémoire, dont toute ligne a été écrite par le
    // moteur sous la liste ; un échec y serait une panne du moteur, servie fermée sous « format ancien » et son code.
    let du_brouillon: std::collections::BTreeSet<(String, String)> = {
        let mut s = brouillon.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table'").map_err(refusee)?;
        let lues = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(refusee)?;
        let lues = lues.collect::<rusqlite::Result<Vec<_>>>().map_err(refusee)?;
        let e = liste.etat();
        lues.into_iter().filter(|(nom, _)| e.est_une_table_fantome(nom)).collect()
    };
    if du_fichier != du_brouillon {
        return Err(liste.refus(Phase::PostDdl, Cause::TablesFantomesHorsDeCeQueCreeLeModule));
    }
    Ok(())
}

/// CROCHETS DE TEST, propres au fil qui les arme (la restauration se joue sur le fil de son appelant) et désarmés quand
/// la garde rendue sort de portée :
///  - `sans_jugement_des_arguments` : `juger_les_arguments_de_la_table_virtuelle` admet tout argument, pour que les deux
///    gardes de la reconstruction FTS (lecture de la seule table de contenu créée par la restauration, fonctions des
///    seuls modules), que ce jugement rend inatteignables par une archive, gardent un témoin ;
///  - `sur_la_connexion` : une fermeture reçoit chaque connexion de restauration du format courant dès son ouverture
///    (`ListeFermee::armer`), avant toute instruction ; un témoin y abaisse une limite du moteur ;
///  - `sans_refus_sur_les_tables_fantomes` : `admettre` admet un index ou un déclencheur posé sur une table fantôme, pour
///    que les gardes qu'un tel objet était seul à atteindre (aucun déclencheur ne joue pendant la restauration, `COMMIT`
///    refusé par la liste ou par le moteur), devenues une défense en profondeur, gardent un témoin.
#[cfg(test)]
pub(crate) mod crochets_de_restauration {
    use std::cell::{Cell, RefCell};

    type SurLaConnexion = std::rc::Rc<dyn Fn(&rusqlite::Connection)>;

    thread_local! {
        static SANS_JUGEMENT: Cell<bool> = const { Cell::new(false) };
        static SUR_LA_CONNEXION: RefCell<Option<SurLaConnexion>> = const { RefCell::new(None) };
        static FANTOMES_OUVERTES: Cell<bool> = const { Cell::new(false) };
    }

    /// Désarme les crochets du fil en sortie de portée, panique comprise.
    pub(crate) struct Arme(());

    impl Drop for Arme {
        fn drop(&mut self) {
            SANS_JUGEMENT.with(|c| c.set(false));
            SUR_LA_CONNEXION.with(|c| *c.borrow_mut() = None);
            FANTOMES_OUVERTES.with(|c| c.set(false));
        }
    }

    pub(crate) fn sans_jugement_des_arguments() -> Arme {
        SANS_JUGEMENT.with(|c| c.set(true));
        Arme(())
    }

    pub(crate) fn sur_la_connexion(f: impl Fn(&rusqlite::Connection) + 'static) -> Arme {
        SUR_LA_CONNEXION.with(|c| *c.borrow_mut() = Some(std::rc::Rc::new(f)));
        Arme(())
    }

    pub(crate) fn sans_refus_sur_les_tables_fantomes() -> Arme {
        FANTOMES_OUVERTES.with(|c| c.set(true));
        Arme(())
    }

    pub(super) fn refus_sur_les_tables_fantomes_leve() -> bool {
        FANTOMES_OUVERTES.with(|c| c.get())
    }

    pub(super) fn arguments_non_juges() -> bool {
        SANS_JUGEMENT.with(|c| c.get())
    }

    pub(super) fn passer_la_connexion(conn: &rusqlite::Connection) {
        SUR_LA_CONNEXION.with(|c| c.borrow().clone()).into_iter().for_each(|f| f(conn));
    }
}
