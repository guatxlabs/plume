//! backup::restauration_liste_fermee — LA RESTAURATION N'ACCEPTE QUE LES FORMES D'INSTRUCTION QUE L'ÉCRIVAIN DU DUMP
//! ÉMET. Sous-module de `backup` ; seul `dump_restauration::restore_stream` s'en sert.
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
//!  - un module FTS crée, remplit et lit SES tables fantômes (`<vt>_<suffixe>`, suffixes de l'écrivain), y compris leurs
//!    index automatiques, lit les réglages `data_version` (FTS5) et `page_size` (FTS3/FTS4), appelle `max` et `coalesce`
//!    (FTS3/FTS4) et, pour la reconstruction, lit la table de contenu. Il le fait pendant le `CREATE VIRTUAL TABLE`,
//!    pendant le `rebuild`, et quand il vide ses données en attente : au début de l'instruction d'écriture suivante (une
//!    autre chaîne de post-DDL) ou au `COMMIT`. Ces actions ne sont admises qu'une fois une table virtuelle créée par
//!    CETTE restauration, et les écritures et lectures sur ses seules tables fantômes.
//! Aucune autre fonction n'est appelée par une restauration réelle.
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

/// Le refus servi : phase et cause, rien d'autre (ni le texte lu dans l'archive, ni celui du moteur).
pub(super) fn refus(phase: Phase, cause: Cause) -> String {
    format!("restore : phase {} : instruction hors liste ({})", phase.nom(), cause.phrase())
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
/// table virtuelle créée par cette restauration existe et peut travailler. Aucune avant la première création.
fn action_interne_d_un_module(e: &Etat, action: &AuthAction<'_>) -> bool {
    use AuthAction as A;
    if e.tables_virtuelles_creees.is_empty() {
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
}

impl ListeFermee {
    /// POSE L'AUTORISEUR. À appeler juste après l'ouverture (clé et réglages mémoire posés), avant toute instruction de
    /// la restauration.
    pub(super) fn armer(conn: &Connection) -> ListeFermee {
        let etat = std::sync::Arc::new(std::sync::Mutex::new(Etat {
            phase: Phase::Ouverture,
            cible: String::new(),
            index_en_creation: String::new(),
            tables_creees: Default::default(),
            tables_virtuelles_creees: Default::default(),
            tetes: 0,
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
        ListeFermee { etat }
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
    /// exactement une tête et aucune seconde instruction. `si_le_moteur_refuse` met en forme l'erreur d'une chaîne
    /// de la famille que le moteur refuse de lui-même (message d'avant ce module, inchangé).
    pub(super) fn preparer_une_chaine_de_l_archive<'c>(
        &self,
        conn: &'c Connection,
        phase: Phase,
        cible: &str,
        chaine: &str,
        si_le_moteur_refuse: impl FnOnce(rusqlite::Error) -> String,
    ) -> Result<rusqlite::Statement<'c>, String> {
        self.entrer(phase, cible);
        let mut lot = rusqlite::Batch::new(conn, chaine);
        let premiere = lot.next();
        let hors_liste = {
            let e = self.etat();
            e.refus || e.tetes != 1
        };
        let premiere = match premiere {
            _ if hors_liste => return Err(refus(phase, Cause::ClasseHorsListe)),
            Err(e) => return Err(si_le_moteur_refuse(e)),
            // Inatteignable : une chaîne sans instruction n'a pas de tête, le premier bras la refuse.
            Ok(None) => return Err(refus(phase, Cause::ClasseHorsListe)),
            Ok(Some(s)) => s,
        };
        if !matches!(lot.next(), Ok(None)) {
            return Err(refus(phase, Cause::PlusieursInstructions));
        }
        Ok(premiere)
    }
}
