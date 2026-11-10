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
//! mémoire armée de la même liste : une table que l'export rejoue sous la phase `Tables`, toute autre ligne sous la
//! phase `PostDdl`. Seules exceptions, les tables que le moteur crée lui-même (`TABLES_DU_MOTEUR`), à leur texte exact.
//! Un refus nomme la phase « format ancien ».
//! PORTÉE POUR UNE TABLE VIRTUELLE : sa ligne est jugée à la PRÉPARATION seulement (module et classe d'instruction) ;
//! ce que le format courant juge de plus en l'exécutant, c'est-à-dire ce que le module fait à sa création, n'est pas
//! rejoué ici. Ce reste est porté par la feuille de route.
use super::*;
use super::dump_restauration::SUFFIXES_DES_TABLES_FANTOMES;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

/// Les modules de table virtuelle que l'écrivain émet : `fts_external_content` n'accepte que `USING FTS5`, `FTS4` ou
/// `FTS3` (comparaison sans casse), le reste part au repli legacy et n'entre jamais dans un dump B1.
const MODULES_DE_TABLE_VIRTUELLE_EMIS: [&str; 3] = ["fts3", "fts4", "fts5"];

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
}

impl Cause {
    fn phrase(self) -> &'static str {
        match self {
            Cause::ClasseHorsListe => "classe d'instruction hors de la liste de la phase",
            Cause::PlusieursInstructions => "plus d'une instruction dans la chaîne",
            Cause::InsertionHorsForme => "insertion qui ne lie pas exactement les valeurs de la ligne",
            Cause::TableNonCreee => "table non créée par cette restauration",
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
    /// Tables ordinaires créées par la section 1 de CETTE restauration.
    tables_creees: std::collections::HashSet<String>,
    /// Tables virtuelles créées par la section 4 de CETTE restauration.
    tables_virtuelles_creees: std::collections::HashSet<String>,
    /// Actions « tête » vues depuis l'entrée dans la phase (cf. en-tête du module).
    tetes: u32,
    /// Une chaîne lue dans l'archive est en cours de préparation : aucune action interne d'un module n'y est admise.
    preparation_de_l_archive: bool,
    /// L'autoriseur a refusé au moins une action depuis l'entrée dans la phase.
    refus: bool,
}

impl Etat {
    /// `nom` est une table fantôme d'une table virtuelle créée par cette restauration (`<vt>_<suffixe>`, suffixes de
    /// l'écrivain, `collect_dump_plan`).
    fn est_une_table_fantome(&self, nom: &str) -> bool {
        self.tables_virtuelles_creees.iter().any(|vt| {
            nom.len() > vt.len() + 1
                && nom.starts_with(vt.as_str())
                && nom.as_bytes()[vt.len()] == b'_'
                && SUFFIXES_DES_TABLES_FANTOMES.contains(&&nom[vt.len() + 1..])
        })
    }
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
            tables_creees: Default::default(),
            tables_virtuelles_creees: Default::default(),
            tetes: 0,
            preparation_de_l_archive: false,
            refus: false,
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
    /// rend le refus du moteur (code, sans texte).
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
        let hors_liste = {
            let mut e = self.etat();
            e.preparation_de_l_archive = false;
            e.refus || e.tetes != 1
        };
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
        Ok(premiere)
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
            "SELECT COALESCE(type = 'table' AND rootpage > 0, 0), COALESCE(type = 'view', 0), sql \
             FROM sqlite_master WHERE sql IS NOT NULL ORDER BY rowid",
        )
        .map_err(refusee)?;
    let lignes = s
        .query_map([], |r| Ok(LigneDuFormatAncien { table_rejouee: r.get(0)?, vue: r.get(1)?, sql: r.get(2)? }))
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
/// s'appuient sur elle) ; chaque vue est jugée sous `PostDdl` puis créée (un déclencheur `INSTEAD OF` s'appuie sur
/// elle) ; toute autre ligne (index, déclencheur, table virtuelle, et tout autre type) est jugée sous `PostDdl` sans être
/// jouée — l'autoriseur juge une instruction pendant sa préparation, et aucune table virtuelle n'est créée, donc aucun
/// module ne travaille sur le brouillon. Le premier refus arrête le jugement et nomme la phase « format ancien ».
///
/// Un refus du MOTEUR pendant le jugement (une ligne que le brouillon ne sait pas préparer ou créer) reste servi, fermé,
/// sous « format ancien » et son code, quelle que soit la phase sous laquelle la ligne était jugée. Un fichier que le
/// moteur a relu y mène : le moteur relit un schéma sans résoudre les noms qu'il cite, et la préparation sur le
/// brouillon refuse alors une contrainte qui cite une colonne absente (une table) ou un index qui appelle une fonction
/// inconnue (code 1). Une collation inconnue, elle, est absorbée (`accepter_toute_collation_sur_le_brouillon`), et les
/// vues sont créées avant les déclencheurs qui s'y appuient.
pub(super) fn juger_le_schema_du_format_ancien(clair: &Connection) -> Result<(), String> {
    let lignes = lire_le_schema_du_format_ancien(clair)?;
    let brouillon = Connection::open_in_memory()
        .map_err(|e| format!("restore : {}", refusee_par_le_moteur_sous(PHASE_DU_FORMAT_ANCIEN, &e)))?;
    accepter_toute_collation_sur_le_brouillon(&brouillon);
    let liste = ListeFermee::armer_pour_le_format_ancien(&brouillon);
    let jugees: Vec<&LigneDuFormatAncien> = lignes.iter().filter(|l| !TABLES_DU_MOTEUR.contains(&l.sql.as_str())).collect();
    for l in jugees.iter().filter(|l| l.table_rejouee) {
        let stmt = liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::Tables, "", &l.sql)?;
        liste.executer_une_chaine(stmt, Phase::Tables)?;
    }
    for l in jugees.iter().filter(|l| !l.table_rejouee && l.vue) {
        let stmt = liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::PostDdl, "", &l.sql)?;
        liste.executer_une_chaine(stmt, Phase::PostDdl)?;
    }
    for l in jugees.iter().filter(|l| !l.table_rejouee && !l.vue) {
        liste.preparer_une_chaine_de_l_archive(&brouillon, Phase::PostDdl, "", &l.sql)?;
    }
    Ok(())
}
