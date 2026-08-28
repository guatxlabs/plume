//! PURGE EXPLICITE D'ÉVÉNEMENTS — la seule suppression de `event` DEMANDÉE PAR UN HUMAIN.
//!
//! CETTE LIGNE A ÉTÉ FAUSSE JUSQU'AU 2026-08-06, et le défaut mérite d'être laissé visible parce qu'il
//! porte sur une garantie d'INTÉGRITÉ. Elle annonçait « la seule suppression de `event` qui ne soit pas
//! la rétention temporelle » — donc, pour qui lit l'en-tête du module de référence : une porte unique.
//! Mesuré : il y en a QUATRE autres, toutes de production, aucune temporelle.
//!   `rollups.rs` (plafond `max_rows`)  — DELETE … WHERE id NOT IN (SELECT … ORDER BY ts DESC LIMIT ?)
//!   `rollups.rs` (plafond `max_bytes`) — même figure, sur la taille cumulée
//!     Ces deux-là NE SONT PAS du code mort : le job de rétention horaire les appelle, et leurs seuils
//!     s'éditent par l'API (`handlers/index_policies.rs`). Le critère est un NOMBRE DE LIGNES ou un
//!     VOLUME D'OCTETS, jamais un horodatage.
//!   `migrate.rs` ×2 (`migrate_v102`, `migrate_v48`) — DELETE … WHERE source=?1, au boot, sur des
//!     sources de test/sonde héritées ; ni registre de purge, ni ledger.
//!
//! L'affirmation EXACTE est celle que porte déjà `rbac.rs` : ce module est la seule surface qui détruit
//! des preuves **À LA DEMANDE**. Les quatre autres sont automatiques et bornées par une politique. La
//! nuance n'est pas cosmétique : « une seule porte » laisserait croire qu'auditer ce fichier suffit à
//! savoir tout ce qui efface un événement. Ce n'est pas le cas.
//!
//! POURQUOI CE MODULE EXISTE. Mesuré pendant un onboarding : nettoyer quelques events de test exigeait du SQL
//! direct sur une base SQLCipher, depuis une image qui ne contient que le daemon. Il n'y avait NI sous-commande
//! NI route. La réponse n'est pas « un DELETE de plus » : sur les données d'un SOC, une purge trop large est
//! irréversible et détruit des preuves. Ce module construit donc la purge de telle sorte que les fautes
//! connues ne soient pas VÉRIFIÉES quelque part, mais NON REPRÉSENTABLES.
//!
//! CE QUI EST NON REPRÉSENTABLE (et non « gardé par une revue ») :
//!
//!  1. UN PÉRIMÈTRE SANS BORNE TEMPORELLE. `PurgeScope` porte un champ `window: PurgeWindow` — pas un
//!     `Option`. `PurgeWindow` a des champs PRIVÉS et un seul constructeur faillible. Il n'existe donc aucune
//!     valeur de `PurgeScope` sans fenêtre : « purger tout l'historique » ne s'écrit pas.
//!
//!  2. UN PÉRIMÈTRE SANS AUCUN IDENTIFIANT. Le premier sélecteur est un CHAMP (`head: PurgeSelector`), pas un
//!     élément d'un `Vec` qui pourrait être vide. Un périmètre nomme donc TOUJOURS au moins une source /
//!     un `env_id` / une `origin` / un `engagement_id`. Et `PurgeSelector` est un enum FERMÉ : aucune variante
//!     ne transporte de prédicat libre (ni SQL, ni GXQL) — c'est exactement ce qui rend une purge
//!     accidentellement totale, et cette forme-là n'existe pas dans le type.
//!
//!  3. UNE EXÉCUTION SANS SIMULATION. `purge_apply` n'accepte qu'un `ConfirmedPurge` ; un `ConfirmedPurge` ne
//!     s'obtient que par `PurgePlan::confirm` ; un `PurgePlan` ne s'obtient que par `purge_plan`, qui EST la
//!     simulation. Il n'y a pas d'autre chemin vers la suppression, donc pas de chemin qui saute les refus
//!     (legal-hold, tier froid, case citant l'event, FTS désynchronisée). `confirm` prend `self` PAR VALEUR :
//!     un plan ne se confirme pas deux fois.
//!
//!  4. UNE CONFIRMATION QUI NE PROUVE PAS QU'ON A VU. Le jeton est l'EMPREINTE du plan (périmètre canonique +
//!     cardinalité + bornes d'`id`/`ts` + counts par source). Rejouer une URL ne suffit pas : l'exécution
//!     RE-SIMULE et recalcule l'empreinte. Si le contenu a bougé entre les deux (une ligne ingérée dans la
//!     fenêtre, un legal-hold posé entre-temps), l'empreinte diffère et la confirmation est CADUQUE.
//!
//!  5. UNE SUPPRESSION NON INSCRITE AU REGISTRE. `purge_delete_rows` exige un `&PurgeInscribed` dont il LIT le
//!     champ (`rows_declared`) : retirer le paramètre ne compile pas. `PurgeInscribed` a un champ privé et un
//!     seul producteur, `purge_inscribe`, qui écrit dans le registre chaîné par hachage ET dans le SOC
//!     (`audit_config_change`, fail-closed transactionnel). Une purge non inscrite ne peut pas s'exécuter.
//!
//!  6. UNE INSCRIPTION QUI FUIT LE CONTENU DÉTRUIT. `confirm` LAISSE TOMBER l'échantillon : `ConfirmedPurge`
//!     n'a pas de champ qui porte un message, une IP, un `fields`. `purge_inscribe` ne reçoit QUE ça — il ne
//!     PEUT pas journaliser ce qu'il n'a pas.
//!
//!  7. UNE PURGE QUI EFFACE SA PROPRE TRACE. Le prédicat de portée inclut TOUJOURS la clause non-purgeable de
//!     la rétention (`retention_nonpurge_for("event")`) : les events de contrôle `origin='daemon'`
//!     (plume-config / operator-access / tenant-admin / engagement) sont hors d'atteinte. L'audit de purge est
//!     écrit AVEC ce marqueur -> une purge ultérieure ne peut pas effacer la preuve d'une purge antérieure.
//!
//! CE QUE LA PURGE REFUSE DE COUVRIR (elle le NOMME au lieu de mentir) : cf. `PurgeRefusal` et
//! `PurgeUncovered`. Notamment : le TIER FROID (Parquet scellé, immuable — refus si la fenêtre le recouvre)
//! et les SAUVEGARDES DÉJÀ PRISES (une purge n'en retire rien ; c'est dit dans la sortie et dans la doc).

use crate::*;
use rusqlite::types::Value as SqlValue;

// =====================================================================================
// 1. PÉRIMÈTRE — par identifiants explicites, et borné dans le temps. Par construction.
// =====================================================================================

/// Durée MAXIMALE d'une fenêtre de purge (même plafond que la rétention : `RETENTION_FIELDS`/
/// `INDEX_RETENTION_CEIL_DAYS`/`COLD_RETENTION_CEIL_DAYS` = 3650 j). Ce n'est PAS une protection contre une
/// purge large — le refus de couvrir le tier froid et l'obligation de nommer un identifiant le sont — c'est
/// une borne de sanité qui empêche `end_ts` d'être un entier absurde (typo, millisecondes prises pour des
/// secondes) de devenir une fenêtre de plusieurs siècles.
pub(crate) const PURGE_WINDOW_MAX_DAYS: i64 = 3650;

/// Nombre de lignes d'échantillon rendues de chaque côté de la fenêtre (les plus VIEILLES et les plus
/// RÉCENTES). Le but est de prouver à l'humain ce qu'il détruit, pas de rendre le jeu de données.
pub(crate) const PURGE_SAMPLE_EACH_SIDE: usize = 5;

/// Longueur max du message rendu dans l'échantillon (l'échantillon sert à RECONNAÎTRE, pas à exporter).
const PURGE_SAMPLE_MSG_MAX: usize = 160;

/// SÉLECTEUR DE PÉRIMÈTRE — enum **FERMÉ** d'IDENTIFIANTS. Aucune variante ne porte de prédicat (ni SQL ni
/// GXQL) : « purger tout ce qui matche cette expression » n'est pas un état représentable. Chaque variante
/// se projette sur UNE colonne d'`event` connue à la compilation (`column()`), et sa valeur part toujours en
/// PARAMÈTRE LIÉ — jamais interpolée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PurgeSelector {
    /// `event.source` — le collecteur/parseur d'origine (sshd, suricata, un flux de test…).
    Source(String),
    /// `event.env_id` — l'environnement / index logique intra-tenant (#2d/#49).
    Env(String),
    /// `event.origin` — provenance structurelle. `daemon` est REFUSÉ : c'est la piste d'audit.
    Origin(String),
    /// `event.engagement_id` — le tag d'un engagement pentest (v75). Le cas d'usage canonique : effacer les
    /// traces d'un exercice une fois le rapport rendu.
    Engagement(String),
}

/// Sources de CONTRÔLE que la rétention n'efface jamais (`retention_nonpurge_for`). Les nommer comme
/// sélecteur de purge n'aurait aucun effet (le prédicat les exclut de toute façon) : on préfère le REFUS
/// EXPLICITE au « 0 ligne » silencieux, qui laisserait croire qu'il n'y avait rien à purger.
const PURGE_PROTECTED_SOURCES: &[&str] =
    &["plume-config", "plume-operator-access", "plume-tenant-admin", "plume-engagement"];

impl PurgeSelector {
    /// Construit un sélecteur depuis un couple (genre, valeur) TEXTE — le seul point d'entrée depuis la CLI
    /// et l'API. Genre inconnu -> Err (default-deny : jamais de sélecteur « inerte » qui élargirait le
    /// périmètre en silence). Valeur validée sur le charset d'identifiant partagé (`env_id_ok`).
    pub(crate) fn parse(kind: &str, value: &str) -> Result<Self, String> {
        let v = value.trim();
        if v.is_empty() {
            return Err(format!("sélecteur '{kind}' : valeur vide (un périmètre se NOMME)"));
        }
        if !env_id_ok(v) {
            return Err(format!(
                "sélecteur '{kind}={v}' : identifiant invalide (alphanumérique + '.' '_' '-', 1..64)"
            ));
        }
        match kind {
            "source" => {
                if PURGE_PROTECTED_SOURCES.contains(&v) {
                    return Err(format!(
                        "source '{v}' : piste d'audit NON purgeable (une purge ne peut pas effacer la trace \
                         des changements de configuration ni des accès opérateur)"
                    ));
                }
                Ok(PurgeSelector::Source(v.to_string()))
            }
            "env" | "env_id" => Ok(PurgeSelector::Env(v.to_string())),
            "origin" => {
                if v == "daemon" {
                    return Err(
                        "origin 'daemon' : lignes écrites par le daemon lui-même (audit/contrôle) — NON purgeables"
                            .into(),
                    );
                }
                Ok(PurgeSelector::Origin(v.to_string()))
            }
            "engagement" | "engagement_id" => Ok(PurgeSelector::Engagement(v.to_string())),
            other => Err(format!(
                "sélecteur inconnu '{other}' (attendu : source | env | origin | engagement)"
            )),
        }
    }

    /// Genre canonique (stable : il entre dans l'empreinte du plan et dans l'inscription au registre).
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            PurgeSelector::Source(_) => "source",
            PurgeSelector::Env(_) => "env",
            PurgeSelector::Origin(_) => "origin",
            PurgeSelector::Engagement(_) => "engagement",
        }
    }

    /// Colonne d'`event` visée. LITTÉRAL choisi par le compilateur depuis la variante — jamais une chaîne
    /// venue de l'appelant, donc jamais un vecteur d'injection.
    fn column(&self) -> &'static str {
        match self {
            PurgeSelector::Source(_) => "source",
            PurgeSelector::Env(_) => "env_id",
            PurgeSelector::Origin(_) => "origin",
            PurgeSelector::Engagement(_) => "engagement_id",
        }
    }

    pub(crate) fn value(&self) -> &str {
        match self {
            PurgeSelector::Source(v)
            | PurgeSelector::Env(v)
            | PurgeSelector::Origin(v)
            | PurgeSelector::Engagement(v) => v.as_str(),
        }
    }
}

/// FENÊTRE TEMPORELLE OBLIGATOIRE. Champs PRIVÉS, un seul constructeur, et il est FAILLIBLE : il n'existe
/// aucun moyen de fabriquer une fenêtre ouverte, inversée, ou de longueur absurde. C'est ce type qui rend
/// « purge sans borne » non représentable — pas un `if` dans un handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PurgeWindow {
    start_ts: i64,
    end_ts: i64,
}

impl PurgeWindow {
    /// Fenêtre INCLUSIVE `[start_ts, end_ts]` en secondes epoch. Refuse : borne négative, fenêtre vide ou
    /// inversée, durée > `PURGE_WINDOW_MAX_DAYS`.
    pub(crate) fn new(start_ts: i64, end_ts: i64) -> Result<Self, String> {
        if start_ts < 0 || end_ts < 0 {
            return Err("fenêtre : bornes epoch négatives".into());
        }
        if end_ts < start_ts {
            return Err(format!("fenêtre inversée : end_ts({end_ts}) < start_ts({start_ts})"));
        }
        let span = end_ts - start_ts;
        if span > PURGE_WINDOW_MAX_DAYS * 86_400 {
            return Err(format!(
                "fenêtre de {} j > plafond {PURGE_WINDOW_MAX_DAYS} j (borne de sanité : une durée absurde \
                 vient presque toujours d'un horodatage en millisecondes pris pour des secondes)",
                span / 86_400
            ));
        }
        Ok(PurgeWindow { start_ts, end_ts })
    }

    pub(crate) fn start(&self) -> i64 {
        self.start_ts
    }
    pub(crate) fn end(&self) -> i64 {
        self.end_ts
    }
}

/// PÉRIMÈTRE RÉSOLU. `head` est un CHAMP : un périmètre porte donc TOUJOURS au moins un identifiant (un `Vec`
/// seul aurait pu être vide, et « aucun sélecteur » veut dire « toute la fenêtre, toutes sources » — la purge
/// accidentellement totale). `window` est un CHAMP : jamais d'`Option`, jamais de borne implicite.
#[derive(Clone, Debug)]
pub(crate) struct PurgeScope {
    head: PurgeSelector,
    tail: Vec<PurgeSelector>,
    window: PurgeWindow,
}

impl PurgeScope {
    /// Les sélecteurs se CONJOIGNENT (AND) : ajouter un sélecteur ne peut que RÉTRÉCIR le périmètre. Deux
    /// sélecteurs du MÊME genre sont refusés — conjoints ils ne matcheraient rien, et l'intention de
    /// l'appelant (une union ? une restriction ?) serait devinée. Une purge ne se devine pas.
    pub(crate) fn new(head: PurgeSelector, tail: Vec<PurgeSelector>, window: PurgeWindow) -> Result<Self, String> {
        let mut seen = vec![head.kind()];
        for s in &tail {
            if seen.contains(&s.kind()) {
                return Err(format!(
                    "sélecteur '{}' fourni deux fois : les sélecteurs se conjoignent (AND), deux valeurs du \
                     même genre ne matcheraient aucune ligne",
                    s.kind()
                ));
            }
            seen.push(s.kind());
        }
        Ok(PurgeScope { head, tail, window })
    }

    pub(crate) fn window(&self) -> PurgeWindow {
        self.window
    }

    /// Tous les sélecteurs, `head` d'abord. Ordre STABLE (il entre dans la forme canonique).
    pub(crate) fn selectors(&self) -> impl Iterator<Item = &PurgeSelector> {
        std::iter::once(&self.head).chain(self.tail.iter())
    }

    /// Valeur du sélecteur `source` s'il y en a un (sert au recoupement legal-hold, qui est scopé par source).
    fn source_value(&self) -> &str {
        self.selectors()
            .find_map(|s| match s {
                PurgeSelector::Source(v) => Some(v.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    /// FORME CANONIQUE — texte déterministe (sélecteurs triés par genre) qui entre dans l'empreinte du plan
    /// et dans l'inscription au registre. Deux périmètres équivalents ont la MÊME forme ; deux périmètres
    /// différents en ont deux différentes (c'est ce qui rend un jeton non transférable d'un périmètre à
    /// l'autre).
    pub(crate) fn canonical(&self) -> String {
        let mut parts: Vec<String> =
            self.selectors().map(|s| format!("{}={}", s.kind(), s.value())).collect();
        parts.sort();
        format!("ts[{},{}] {}", self.window.start_ts, self.window.end_ts, parts.join(" "))
    }
}

// =====================================================================================
// 2. REFUS — ce que la purge ne fait PAS, en le nommant
// =====================================================================================

/// REFUS DE PURGER. Chaque variante NOMME ce qui bloque : une purge qui échoue sans dire quoi laisserait
/// l'opérateur croire à un bug et retenter, ou pire, contourner par du SQL direct — le point de départ.
#[derive(Debug, Clone)]
pub(crate) enum PurgeRefusal {
    /// >=1 legal-hold ACTIF recouvre le périmètre. Détruire une preuve sous rétention légale est une faute
    /// grave : on refuse TOUT le périmètre (jamais une purge partielle silencieuse « sauf les lignes tenues »).
    LegalHold(Vec<String>),
    /// L'état des holds n'a PAS pu être déterminé alors que la table existe -> FAIL-CLOSED (même règle que
    /// `retention_run` : on ne supprime jamais une preuve dont on ne peut pas prouver qu'elle n'est pas tenue).
    LegalHoldUndetermined,
    /// Des lignes de la fenêtre ont été COLUMNARISÉES dans le tier froid (Parquet scellé, chiffré, immuable).
    /// Vider `event` laisserait ces copies INTERROGEABLES : « purgé » serait un mensonge. On refuse et on
    /// nomme les fichiers/jours concernés.
    ColdTier { files: i64, days: i64 },
    /// Des events du périmètre sont CITÉS par la timeline d'un case/incident (`incident_item.ref='event:<id>'`).
    /// Purger casserait la chaîne de preuve d'une investigation ouverte : c'est à l'analyste de trancher.
    CitedByCase { ids: Vec<i64>, total: i64 },
    /// L'index plein-texte `event_fts` existe mais son trigger de suppression (`event_ad`) est absent : un
    /// DELETE laisserait les postings — le message resterait CHERCHABLE. Refus (purge qui mentirait).
    FtsDesync,
    /// Le jeton fourni n'est pas l'empreinte du plan re-simulé (rejeu, périmètre modifié, contenu changé).
    StaleToken { expected: String, got: String },
    /// Raison d'opération absente : une destruction de preuves se motive, et la motivation entre au registre.
    ReasonRequired,
    /// Divergence entre ce qui a été INSCRIT et ce qui a été SUPPRIMÉ -> transaction annulée en entier.
    CountMismatch { declared: i64, deleted: i64 },
    /// Erreur base (verrou, schéma, I/O). Aucune ligne supprimée.
    Db(String),
}

impl std::fmt::Display for PurgeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeRefusal::LegalHold(names) => write!(
                f,
                "REFUS — rétention légale : le périmètre est recouvert par {} legal-hold(s) ACTIF(s) [{}]. \
                 Lever le hold (/api/legal-holds/{{id}}/release) est un acte de gouvernance tracé ; la purge ne \
                 le contourne pas.",
                names.len(),
                names.join(", ")
            ),
            PurgeRefusal::LegalHoldUndetermined => write!(
                f,
                "REFUS — l'état des legal-holds est INDÉTERMINABLE (table `legal_hold` illisible). Fail-closed : \
                 on ne supprime jamais une preuve dont on ne peut pas prouver qu'elle n'est pas retenue."
            ),
            PurgeRefusal::ColdTier { files, days } => write!(
                f,
                "REFUS — TIER FROID : {files} fichier(s) Parquet scellé(s) sur {days} jour(s) recouvrent cette \
                 fenêtre. Ces copies columnarisées resteraient INTERROGEABLES après le vidage de `event` : \
                 « purgé » serait faux. La purge ne sait pas réécrire un Parquet scellé — elle refuse au lieu \
                 de mentir. Contournement : attendre l'expiration cold (cold_retention_days) ou restreindre la \
                 fenêtre aux jours encore chauds."
            ),
            PurgeRefusal::CitedByCase { ids, total } => write!(
                f,
                "REFUS — CHAÎNE DE PREUVE : {total} event(s) du périmètre sont cités par la timeline d'un \
                 case/incident (ex. id {ids:?}). Purger laisserait des références pendantes dans une \
                 investigation. Détacher l'item du case d'abord, ou restreindre la fenêtre."
            ),
            PurgeRefusal::FtsDesync => write!(
                f,
                "REFUS — index plein-texte DÉSYNCHRONISÉ : `event_fts` existe mais le trigger de suppression \
                 `event_ad` est absent. Un DELETE laisserait les postings : le message purgé resterait \
                 CHERCHABLE. Réconcilier l'index (redémarrage du daemon) avant de purger."
            ),
            PurgeRefusal::StaleToken { expected, got } => write!(
                f,
                "REFUS — CONFIRMATION CADUQUE : le jeton fourni ({got}) n'est pas l'empreinte du périmètre \
                 re-simulé ({expected}). Soit il est rejoué, soit le contenu a changé depuis la simulation \
                 (ligne ingérée dans la fenêtre, legal-hold posé). Re-simuler et re-confirmer."
            ),
            PurgeRefusal::ReasonRequired => {
                write!(f, "REFUS — une raison d'opération non vide est requise (elle entre au registre d'intégrité).")
            }
            PurgeRefusal::CountMismatch { declared, deleted } => write!(
                f,
                "REFUS — INCOHÉRENCE registre/base : {declared} ligne(s) inscrite(s), {deleted} supprimée(s). \
                 Transaction ANNULÉE en entier (le registre ne peut pas affirmer autre chose que la réalité)."
            ),
            PurgeRefusal::Db(e) => write!(f, "REFUS — base : {e} (aucune ligne supprimée)"),
        }
    }
}

/// Étiquette courte et STABLE du refus (sortie machine JSON, et tests adverses).
pub(crate) fn purge_refusal_code(r: &PurgeRefusal) -> &'static str {
    match r {
        PurgeRefusal::LegalHold(_) => "legal_hold",
        PurgeRefusal::LegalHoldUndetermined => "legal_hold_undetermined",
        PurgeRefusal::ColdTier { .. } => "cold_tier",
        PurgeRefusal::CitedByCase { .. } => "cited_by_case",
        PurgeRefusal::FtsDesync => "fts_desync",
        PurgeRefusal::StaleToken { .. } => "stale_token",
        PurgeRefusal::ReasonRequired => "reason_required",
        PurgeRefusal::CountMismatch { .. } => "count_mismatch",
        PurgeRefusal::Db(_) => "db",
    }
}

// =====================================================================================
// 3. PRÉDICAT DE PORTÉE — un seul constructeur, et il exige la décision legal-hold
// =====================================================================================

/// DÉCISION LEGAL-HOLD matérialisée. Champ privé, un seul producteur (`hold_guard`) : le constructeur du
/// prédicat de portée EXIGE cette valeur en paramètre, donc on ne peut pas écrire un `WHERE` de purge qui
/// « oublie » les rétentions légales — il ne compilerait pas.
struct HoldGuard(Option<String>);

/// Dérive la décision legal-hold pour la purge, avec la MÊME loi que `retention_run` (source unique :
/// `legal_hold_enforcement`). `FailClosed` remonte en REFUS.
fn hold_guard(conn: &Connection) -> Result<HoldGuard, PurgeRefusal> {
    match legal_hold_enforcement(conn) {
        HoldEnforce::NoHolds => Ok(HoldGuard(None)),
        HoldEnforce::Guard(pred) => Ok(HoldGuard(Some(pred))),
        HoldEnforce::FailClosed => Err(PurgeRefusal::LegalHoldUndetermined),
    }
}

/// SEUL constructeur du prédicat de portée, et il porte les trois invariants d'un coup :
///  - la FENÊTRE (bornes liées, jamais interpolées) ;
///  - la clause NON-PURGEABLE de la rétention (l'audit de contrôle est hors d'atteinte, y compris de la
///    purge — c'est ce qui empêche une purge d'effacer la preuve d'une purge) ;
///  - le fragment legal-hold, exigé EN PARAMÈTRE (défense en profondeur derrière le refus de `purge_plan`).
///
/// Les colonnes sont QUALIFIÉES `event.` : le même prédicat sert le `DELETE FROM event` ET la jointure sur
/// `incident_item` (qui porte aussi une colonne `ts` — non qualifié, SQLite refuserait l'ambiguïté).
fn scope_predicate(scope: &PurgeScope, hold: &HoldGuard) -> (String, Vec<SqlValue>) {
    let mut sql = String::from("event.ts >= ? AND event.ts <= ?");
    let mut binds: Vec<SqlValue> =
        vec![SqlValue::Integer(scope.window.start_ts), SqlValue::Integer(scope.window.end_ts)];
    for s in scope.selectors() {
        sql.push_str(" AND event.");
        sql.push_str(s.column());
        sql.push_str("=?");
        binds.push(SqlValue::Text(s.value().to_string()));
    }
    sql.push_str(" AND ");
    sql.push_str(&retention_nonpurge_for("event"));
    if let Some(pred) = &hold.0 {
        sql.push_str(" AND ");
        sql.push_str(pred);
    }
    (sql, binds)
}

// =====================================================================================
// 4. SIMULATION — SEUL producteur d'un `PurgePlan`
// =====================================================================================

/// Une ligne d'échantillon rendue à l'humain (message TRONQUÉ). Vit dans le PLAN et nulle part ailleurs :
/// `ConfirmedPurge` ne la porte pas, donc l'inscription au registre ne peut pas la journaliser.
#[derive(Debug, Clone)]
pub(crate) struct PurgeSampleRow {
    pub(crate) id: i64,
    pub(crate) ts: i64,
    pub(crate) source: String,
    pub(crate) severity: i64,
    pub(crate) message: String,
}

/// CE QUE LA PURGE NE COUVRE PAS, compté et rendu. Ne pas prétendre résoudre ce qu'on ne résout pas : chaque
/// champ est une promesse qu'on NE fait PAS, chiffrée sur le périmètre demandé.
#[derive(Debug, Clone, Default)]
pub(crate) struct PurgeUncovered {
    /// Alertes dont le `ts` tombe dans la fenêtre. Une alerte n'est pas une ligne dérivée d'`event` (elle a
    /// sa propre rétention et son propre cycle de vie), mais son `detail` peut CITER le texte d'un event
    /// purgé. La purge n'y touche pas : elle le dit.
    pub(crate) alerts_in_window: i64,
    /// Métriques dans la fenêtre. `metric` n'a ni `source` ni `origin` : le périmètre ne s'y projette pas.
    pub(crate) metrics_in_window: i64,
    /// Captures d'état (`snapshot`) dans la fenêtre. Même raison.
    pub(crate) snapshots_in_window: i64,
    /// Instantanés de dashboard partageables (`dashboard_snapshot`) : ils portent des RÉSULTATS RENDUS, donc
    /// possiblement du contenu purgé. Les détruire détruirait du travail utilisateur -> compté, pas touché.
    pub(crate) dashboard_snapshots: i64,
}

/// PLAN DE PURGE = le résultat de la SIMULATION. Champs PRIVÉS : hors de ce module, un `PurgePlan` ne se
/// fabrique pas, il s'OBTIENT de `purge_plan`. C'est ce qui rend « exécuter sans simuler » non représentable.
#[derive(Debug, Clone)]
pub(crate) struct PurgePlan {
    scope: PurgeScope,
    rows: i64,
    per_source: Vec<(String, i64)>,
    id_lo: i64,
    id_hi: i64,
    id_sum: i64,
    ts_lo: i64,
    ts_hi: i64,
    sample: Vec<PurgeSampleRow>,
    uncovered: PurgeUncovered,
    digest: String,
}

/// Au-delà de ce nombre de lignes, la sortie AVERTIT : la purge s'exécute en UNE transaction (l'inscription
/// au registre et la suppression ne peuvent pas être séparées sans rouvrir la faille), donc elle tient le
/// verrou d'écriture pendant toute sa durée et l'ingest attend. Ce n'est pas un refus — c'est l'opérateur qui
/// décide de sa fenêtre — mais il doit le savoir AVANT, pas le découvrir en production.
pub(crate) const PURGE_LARGE_ROWS_WARN: i64 = 100_000;

impl PurgePlan {
    /// COMPTE EXACT (pas une estimation : c'est un `COUNT(*)` sur le prédicat de portée exact).
    pub(crate) fn rows(&self) -> i64 {
        self.rows
    }
    pub(crate) fn per_source(&self) -> &[(String, i64)] {
        &self.per_source
    }
    pub(crate) fn sample(&self) -> &[PurgeSampleRow] {
        &self.sample
    }
    pub(crate) fn uncovered(&self) -> &PurgeUncovered {
        &self.uncovered
    }
    /// EMPREINTE du plan = le jeton de confirmation.
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn id_range(&self) -> (i64, i64) {
        (self.id_lo, self.id_hi)
    }
    pub(crate) fn ts_range(&self) -> (i64, i64) {
        (self.ts_lo, self.ts_hi)
    }
}

fn table_exists_purge(conn: &Connection, name: &str) -> bool {
    table_present(conn, name)
}

/// L'index plein-texte est-il cohérent ? `event_fts` absent -> rien à désynchroniser. Présent -> le trigger
/// `event_ad` (AFTER DELETE ON event) DOIT exister, sinon un DELETE laisse des postings et le message purgé
/// reste cherchable. Erreur de lecture du schéma -> traité comme désynchronisé (fail-closed).
fn fts_delete_trigger_ok(conn: &Connection) -> bool {
    if !table_exists_purge(conn, "event_fts") {
        return true;
    }
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='event_ad'",
        [],
        |_| Ok(()),
    )
    .is_ok()
}

/// Legal-holds ACTIFS qui RECOUVRENT le périmètre. CONSERVATEUR par construction :
///  - fenêtre du hold ouverte (0) -> elle recouvre toujours ;
///  - hold à portée GLOBALE (`scope_source=''`) -> il recouvre quel que soit le sélecteur ;
///  - purge SANS sélecteur `source` -> tout hold source-scopé peut recouvrir une ligne du périmètre -> il compte.
/// C'est le sens « refuser plutôt que deviner » : on ne purge pas « tout sauf ce qui est tenu ».
fn holds_covering(conn: &Connection, scope: &PurgeScope) -> Result<Vec<String>, PurgeRefusal> {
    if !table_exists_purge(conn, "legal_hold") {
        return Ok(Vec::new());
    }
    let src = scope.source_value().to_string();
    let (s, e) = (scope.window.start_ts, scope.window.end_ts);
    let mut st = conn
        .prepare(
            "SELECT name FROM legal_hold WHERE active=1 \
               AND (scope_start_ts=0 OR scope_start_ts <= ?1) \
               AND (scope_end_ts=0   OR scope_end_ts   >= ?2) \
               AND (scope_source='' OR ?3='' OR scope_source=?3) \
             ORDER BY name",
        )
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    let names: Vec<String> = st
        .query_map(params![e, s, src], |r| r.get::<_, String>(0))
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?
        .flatten()
        .collect();
    Ok(names)
}

/// Le TIER FROID recouvre-t-il la fenêtre ? INDÉPENDANT de la feature `cold_tier` : l'index `cold_seal` vit
/// dans la base, donc un binaire compilé SANS le tier froid voit quand même qu'une columnarisation a eu lieu
/// et refuse — sans quoi le build par défaut purgerait allègrement `event` en laissant les Parquet lisibles
/// par un binaire qui, lui, a la feature. Table absente -> aucun tier froid n'a jamais tourné sur cette base.
/// Table présente mais illisible -> REFUS (fail-closed).
fn cold_overlap(conn: &Connection, w: PurgeWindow) -> Result<(), PurgeRefusal> {
    if !table_exists_purge(conn, "cold_seal") {
        return Ok(());
    }
    let got: Result<(i64, i64), _> = conn.query_row(
        "SELECT COUNT(*), COUNT(DISTINCT day) FROM cold_seal WHERE ts_min <= ?1 AND ts_max >= ?2",
        params![w.end_ts, w.start_ts],
        |r| Ok((r.get(0)?, r.get(1)?)),
    );
    match got {
        Ok((0, _)) => Ok(()),
        Ok((files, days)) => Err(PurgeRefusal::ColdTier { files, days }),
        Err(e) => Err(PurgeRefusal::Db(format!("index cold_seal illisible (fail-closed) : {e}"))),
    }
}

/// Events du périmètre CITÉS par la timeline d'un case/incident (`incident_item.ref = 'event:<id>'`).
/// La jointure applique le prédicat de portée EXACT -> aucune divergence possible entre « ce qui serait
/// purgé » et « ce qui est vérifié ».
fn cited_by_case(
    conn: &Connection,
    pred: &str,
    binds: &[SqlValue],
) -> Result<Option<(Vec<i64>, i64)>, PurgeRefusal> {
    if !table_exists_purge(conn, "incident_item") {
        return Ok(None);
    }
    let sql = format!(
        "SELECT COUNT(*) FROM incident_item \
           JOIN event ON event.id = CAST(SUBSTR(incident_item.ref, 7) AS INTEGER) \
          WHERE incident_item.ref LIKE 'event:%' AND {pred}"
    );
    let total: i64 = conn
        .query_row(&sql, rusqlite::params_from_iter(binds.iter()), |r| r.get(0))
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    if total == 0 {
        return Ok(None);
    }
    let sql_ids = format!(
        "SELECT DISTINCT event.id FROM incident_item \
           JOIN event ON event.id = CAST(SUBSTR(incident_item.ref, 7) AS INTEGER) \
          WHERE incident_item.ref LIKE 'event:%' AND {pred} ORDER BY event.id LIMIT 10"
    );
    let mut st = conn.prepare(&sql_ids).map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    let ids: Vec<i64> = st
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| r.get::<_, i64>(0))
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?
        .flatten()
        .collect();
    Ok(Some((ids, total)))
}

/// SIMULATION. **Seul producteur d'un `PurgePlan`**, donc seul chemin vers une suppression. L'ORDRE des refus
/// est délibéré : d'abord ce qui INTERDIT (rétention légale), puis ce qu'on ne peut pas ATTEINDRE (tier
/// froid), puis ce qu'on casserait (chaîne de preuve, index plein-texte). Aucune écriture ici : la simulation
/// est READ-ONLY par construction (que des SELECT).
pub(crate) fn purge_plan(conn: &Connection, scope: PurgeScope) -> Result<PurgePlan, PurgeRefusal> {
    // (1) RÉTENTION LÉGALE, en DEUX temps et dans CET ordre :
    //     (a) l'état des holds est-il seulement DÉTERMINABLE ? Table présente mais illisible -> FAIL-CLOSED,
    //         et ce verdict doit précéder toute lecture détaillée (sinon la même corruption ressortirait en
    //         banale « erreur base », c'est-à-dire un refus qui ne dit pas qu'il protège une preuve) ;
    //     (b) un hold actif recouvre-t-il le périmètre ? -> refus TOTAL (jamais de purge partielle
    //         silencieuse « sauf les lignes tenues »). Le fragment `NOT held` est ENSUITE ajouté au
    //         prédicat : défense en profondeur derrière ce refus.
    let guard = hold_guard(conn)?;
    let holds = holds_covering(conn, &scope)?;
    if !holds.is_empty() {
        return Err(PurgeRefusal::LegalHold(holds));
    }

    // (2) TIER FROID — refus si des copies columnarisées recouvrent la fenêtre.
    cold_overlap(conn, scope.window)?;

    // (3) INDEX PLEIN-TEXTE — refus si un DELETE laisserait des postings cherchables.
    if !fts_delete_trigger_ok(conn) {
        return Err(PurgeRefusal::FtsDesync);
    }

    let (pred, binds) = scope_predicate(&scope, &guard);

    // (4) CHAÎNE DE PREUVE — refus si un case/incident cite un event du périmètre.
    if let Some((ids, total)) = cited_by_case(conn, &pred, &binds)? {
        return Err(PurgeRefusal::CitedByCase { ids, total });
    }

    // (5) CARDINALITÉ EXACTE + bornes. Un seul balayage, et c'est le MÊME prédicat que le DELETE.
    let agg_sql = format!(
        "SELECT COUNT(*), COALESCE(MIN(event.id),0), COALESCE(MAX(event.id),0), COALESCE(SUM(event.id),0), \
                COALESCE(MIN(event.ts),0), COALESCE(MAX(event.ts),0) FROM event WHERE {pred}"
    );
    let (rows, id_lo, id_hi, id_sum, ts_lo, ts_hi): (i64, i64, i64, i64, i64, i64) = conn
        .query_row(&agg_sql, rusqlite::params_from_iter(binds.iter()), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?;

    // (6) VENTILATION PAR SOURCE — l'humain voit QUELLES sources il détruit, pas seulement combien.
    let per_src_sql =
        format!("SELECT event.source, COUNT(*) FROM event WHERE {pred} GROUP BY event.source ORDER BY event.source");
    let mut st = conn.prepare(&per_src_sql).map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    let per_source: Vec<(String, i64)> = st
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?
        .flatten()
        .collect();
    drop(st);

    // (7) ÉCHANTILLON — les plus VIEILLES et les plus RÉCENTES lignes du périmètre. Prouver « j'ai vu » ne
    //     marche pas sur un seul bout : les deux extrémités montrent si la fenêtre a débordé.
    let mut sample = purge_sample(conn, &pred, &binds, "ASC")?;
    for r in purge_sample(conn, &pred, &binds, "DESC")? {
        if !sample.iter().any(|x| x.id == r.id) {
            sample.push(r);
        }
    }
    sample.sort_by_key(|r| (r.ts, r.id));

    // (8) CE QU'ON NE COUVRE PAS — compté sur la fenêtre, rendu tel quel.
    let uncovered = purge_uncovered(conn, scope.window);

    let digest = purge_digest(&scope, rows, id_lo, id_hi, id_sum, ts_lo, ts_hi, &per_source);
    Ok(PurgePlan { scope, rows, per_source, id_lo, id_hi, id_sum, ts_lo, ts_hi, sample, uncovered, digest })
}

fn purge_sample(
    conn: &Connection,
    pred: &str,
    binds: &[SqlValue],
    dir: &str,
) -> Result<Vec<PurgeSampleRow>, PurgeRefusal> {
    let sql = format!(
        "SELECT event.id, event.ts, event.source, event.severity, COALESCE(event.message,'') \
           FROM event WHERE {pred} ORDER BY event.ts {dir}, event.id {dir} LIMIT {PURGE_SAMPLE_EACH_SIDE}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    let out = st
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            let msg: String = r.get(4)?;
            Ok(PurgeSampleRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                source: r.get(2)?,
                severity: r.get(3)?,
                message: msg.chars().take(PURGE_SAMPLE_MSG_MAX).collect(),
            })
        })
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?
        .flatten()
        .collect();
    Ok(out)
}

fn purge_uncovered(conn: &Connection, w: PurgeWindow) -> PurgeUncovered {
    let count = |sql: &str| -> i64 {
        conn.query_row(sql, params![w.start_ts, w.end_ts], |r| r.get::<_, i64>(0)).unwrap_or(0)
    };
    PurgeUncovered {
        alerts_in_window: count("SELECT COUNT(*) FROM alert WHERE ts >= ?1 AND ts <= ?2"),
        metrics_in_window: count("SELECT COUNT(*) FROM metric WHERE ts >= ?1 AND ts <= ?2"),
        snapshots_in_window: count("SELECT COUNT(*) FROM snapshot WHERE ts >= ?1 AND ts <= ?2"),
        dashboard_snapshots: conn
            .query_row("SELECT COUNT(*) FROM dashboard_snapshot", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0),
    }
}

/// EMPREINTE DU PLAN — ce que le confirmateur doit rendre. Elle lie le périmètre CANONIQUE à ce que la
/// simulation a MESURÉ : cardinalité, bornes et somme des `id`, bornes de `ts`, counts par source. Toute
/// ligne ajoutée ou retirée du périmètre entre la simulation et l'exécution change au moins la cardinalité
/// et la somme des `id` -> l'empreinte change -> la confirmation devient caduque.
///
/// HONNÊTETÉ SUR LA FORCE : c'est une empreinte AGRÉGÉE, pas un hachage du contenu ligne à ligne. Elle
/// détecte tout changement de cardinalité, de bornes ou de répartition par source. Elle ne prétend PAS être
/// une preuve cryptographique d'égalité d'ensembles (deux ensembles distincts de même cardinalité, même
/// somme d'`id`, mêmes bornes et même ventilation par source auraient la même empreinte — un cas que
/// l'unicité et la monotonie d'`event.id` rendent difficile à provoquer, pas impossible à imaginer).
#[allow(clippy::too_many_arguments)]
fn purge_digest(
    scope: &PurgeScope,
    rows: i64,
    id_lo: i64,
    id_hi: i64,
    id_sum: i64,
    ts_lo: i64,
    ts_hi: i64,
    per_source: &[(String, i64)],
) -> String {
    let per: Vec<String> = per_source.iter().map(|(s, n)| format!("{s}:{n}")).collect();
    sha256_hex(
        format!(
            "plume-purge/v1|{}|rows={rows}|id=[{id_lo},{id_hi}]|idsum={id_sum}|ts=[{ts_lo},{ts_hi}]|src={}",
            scope.canonical(),
            per.join(",")
        )
        .as_bytes(),
    )
}

// =====================================================================================
// 5. CONFIRMATION — le jeton prouve qu'on a vu ; l'échantillon est LAISSÉ TOMBER
// =====================================================================================

/// PURGE CONFIRMÉE. Remarquer ce qui N'EST PAS là : aucun champ ne porte de message, d'IP, de `fields`, ni
/// l'échantillon. `purge_inscribe` ne reçoit QUE cette valeur — il ne peut donc pas journaliser le contenu
/// détruit, non pas parce qu'on a pensé à ne pas le faire, mais parce qu'il n'y a pas accès.
#[derive(Debug, Clone)]
pub(crate) struct ConfirmedPurge {
    scope: PurgeScope,
    rows: i64,
    per_source: Vec<(String, i64)>,
    digest: String,
    actor: String,
    reason: String,
}

/// Longueur max de la raison inscrite au registre (elle est libre, donc bornée).
pub(crate) const PURGE_REASON_MAX: usize = 500;

impl PurgePlan {
    /// CONFIRMATION. Prend `self` PAR VALEUR : un plan ne se confirme pas deux fois (le compilateur refuse la
    /// réutilisation d'une valeur déplacée). Le jeton doit être l'empreinte de CE plan — comme l'exécution
    /// re-simule d'abord, un jeton rejoué ou un contenu modifié échouent ici.
    pub(crate) fn confirm(self, token: &str, actor: &str, reason: &str) -> Result<ConfirmedPurge, PurgeRefusal> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(PurgeRefusal::ReasonRequired);
        }
        let token = token.trim();
        if token != self.digest {
            return Err(PurgeRefusal::StaleToken {
                expected: self.digest.clone(),
                got: token.to_string(),
            });
        }
        Ok(ConfirmedPurge {
            scope: self.scope,
            rows: self.rows,
            per_source: self.per_source,
            digest: self.digest,
            actor: actor.trim().to_string(),
            reason: reason.chars().take(PURGE_REASON_MAX).collect(),
        })
    }
}

// =====================================================================================
// 6. INSCRIPTION AU REGISTRE — obligatoire par TYPE, avant la suppression
// =====================================================================================

/// PREUVE D'INSCRIPTION au registre inviolable. Champ PRIVÉ, aucun constructeur littéral hors de ce module :
/// une purge non inscrite ne peut pas fabriquer cette valeur. `purge_delete_rows` la prend en paramètre ET
/// LIT son champ -> retirer le paramètre ne compile pas.
pub(crate) struct PurgeInscribed {
    /// Nombre de lignes DÉCLARÉ au registre. La suppression compare son propre résultat à ce nombre : le
    /// registre ne peut pas affirmer autre chose que ce que la base a fait (sinon tout est annulé).
    rows_declared: i64,
}

/// Genre d'entrée du registre pour une purge (stable, grep-able dans une copie WORM exportée).
pub(crate) const PURGE_LEDGER_KIND: &str = "config.purge.events";

/// INSCRIT la purge : (a) registre append-only chaîné par hachage ; (b) event SOC `source='plume-config'`
/// `origin='daemon'` — donc NON PURGEABLE (`retention_nonpurge_for`) et alertable. Les deux writes sont dans
/// la transaction de l'appelant et FAIL-CLOSED (`audit_config_change` remonte l'erreur) : si l'inscription
/// échoue, l'appelant ROLLBACK et rien n'est supprimé.
///
/// CONFIDENTIALITÉ : le détail ne porte QUE le périmètre résolu, les compteurs, l'empreinte, l'acteur et la
/// raison. Aucun message, aucune IP, aucun `fields` — cf. la forme de `ConfirmedPurge`.
fn purge_inscribe(conn: &Connection, c: &ConfirmedPurge) -> rusqlite::Result<PurgeInscribed> {
    let selectors: Vec<Value> = c
        .scope
        .selectors()
        .map(|s| json!({ "kind": s.kind(), "value": s.value() }))
        .collect();
    let per_source: Vec<Value> =
        c.per_source.iter().map(|(s, n)| json!({ "source": s, "rows": n })).collect();
    let detail = json!({
        "op": "purge",
        "kind": "event",
        "scope": {
            "window": { "start_ts": c.scope.window.start_ts, "end_ts": c.scope.window.end_ts },
            "selectors": selectors,
            "canonical": c.scope.canonical(),
        },
        "rows": c.rows,
        "per_source": per_source,
        "digest": c.digest,
        "actor": c.actor,
        "reason": c.reason,
    })
    .to_string();
    audit_config_change(
        conn,
        PURGE_LEDGER_KIND,
        &detail,
        4,
        &format!(
            "PURGE D'ÉVÉNEMENTS : {} ligne(s) détruite(s) par {} sur le périmètre [{}] — raison : {}",
            c.rows,
            c.actor,
            c.scope.canonical(),
            c.reason
        ),
        &detail,
    )?;
    Ok(PurgeInscribed { rows_declared: c.rows })
}

// =====================================================================================
// 7. SUPPRESSION — exige la preuve d'inscription, et réconcilie les artefacts dérivés
// =====================================================================================

/// CE QUI A ÉTÉ FAIT (rendu à l'appelant après COMMIT).
#[derive(Debug, Clone)]
pub(crate) struct PurgeReceipt {
    pub(crate) rows_deleted: i64,
    pub(crate) digest: String,
    pub(crate) canonical: String,
    pub(crate) rollup_buckets_rebuilt: (i64, i64),
    /// Les buckets ont-ils été RÉ-AGRÉGÉS depuis les lignes survivantes, ou seulement SUPPRIMÉS ? Le second
    /// cas survient quand le rollup n'avait PAS publié de couverture : il n'affirmait alors rien sur ces
    /// buckets (la route lit le brut), et le tick les reconstruira. On le DIT au lieu d'annoncer une
    /// reconstruction qui n'a pas eu lieu.
    pub(crate) rollup_reaggregated: bool,
    pub(crate) panel_cache_cleared: i64,
}

/// SUPPRESSION DES LIGNES + réconciliation des artefacts DÉRIVÉS, dans la transaction de l'appelant.
///
/// Le paramètre `proof` n'est pas décoratif : son champ `rows_declared` est LU pour vérifier que la base a
/// fait EXACTEMENT ce que le registre vient d'affirmer. Retirer ce paramètre ne compile pas — c'est la forme
/// choisie pour rendre « supprimer sans inscrire » impossible plutôt que « interdit ».
///
/// ARTEFACTS DÉRIVÉS traités ICI, dans la MÊME transaction (une purge qui laisserait des agrégats gonflés
/// des lignes détruites serait une purge qui ment) :
///  - `event_fts` : maintenu par le trigger `event_ad` (l'absence du trigger est un REFUS en amont) ;
///  - `event_rollup` / `event_dim_rollup` : les buckets recouvrant la fenêtre sont SUPPRIMÉS puis
///    RE-AGRÉGÉS depuis les lignes SURVIVANTES, avec la MÊME borne d'identifiant que la couverture publiée
///    (sans cette borne, les lignes `id > couverture` seraient comptées deux fois : une fois dans le rollup
///    re-agrégé, une fois dans le fragment retardataire que la route lit en brut) ;
///  - `panel_cache` : les payloads mis en cache portent des RÉSULTATS RENDUS, donc du contenu purgé -> vidés.
fn purge_delete_rows(
    conn: &Connection,
    c: &ConfirmedPurge,
    proof: &PurgeInscribed,
) -> Result<PurgeReceipt, PurgeRefusal> {
    // Le prédicat est RECONSTRUIT ici (même fonction, même invariants) et la décision legal-hold est RELUE
    // DANS la transaction. C'est ce qui ferme la fenêtre entre la simulation et le COMMIT : un hold posé
    // dans cet intervalle ajoute `NOT held` au DELETE -> les lignes tenues ne partent pas -> le compte
    // supprimé diffère de celui qui vient d'être inscrit -> `CountMismatch` -> ROLLBACK TOTAL. La course
    // n'aboutit donc pas à une purge partielle silencieuse, mais à un refus qui laisse la base intacte.
    let guard = hold_guard(conn)?;
    let (pred, binds) = scope_predicate(&c.scope, &guard);

    let del_sql = format!("DELETE FROM event WHERE {pred}");
    let deleted = conn
        .execute(&del_sql, rusqlite::params_from_iter(binds.iter()))
        .map_err(|e| PurgeRefusal::Db(e.to_string()))? as i64;

    // LE REGISTRE NE MENT PAS : ce qui a été inscrit DOIT être ce qui a été supprimé, sinon on annule tout
    // (l'appelant ROLLBACK, y compris l'entrée de registre).
    if deleted != proof.rows_declared {
        return Err(PurgeRefusal::CountMismatch { declared: proof.rows_declared, deleted });
    }

    let (b0, b1) = purge_rollup_band(c.scope.window);
    let rollup_reaggregated = purge_rebuild_rollups(conn, b0, b1)?;
    let panel_cache_cleared = panneau_avoue::cache_vider(conn) as i64;

    Ok(PurgeReceipt {
        rows_deleted: deleted,
        digest: c.digest.clone(),
        canonical: c.scope.canonical(),
        rollup_buckets_rebuilt: (b0, b1),
        rollup_reaggregated,
        panel_cache_cleared,
    })
}

/// Bande de BUCKETS HORAIRES recouvrant la fenêtre : `[floor(start), ceil(end))`. Alignée à l'heure parce que
/// c'est le grain des rollups — une borne au milieu d'un bucket laisserait un bucket agrégé À MOITIÉ.
fn purge_rollup_band(w: PurgeWindow) -> (i64, i64) {
    let b0 = (w.start_ts / 3600) * 3600;
    let b1 = (w.end_ts / 3600) * 3600 + 3600;
    (b0, b1)
}

fn meta_i64(conn: &Connection, key: &str) -> Option<i64> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Re-agrège `event_rollup` et `event_dim_rollup` sur la bande `[b0, b1)` DEPUIS LES LIGNES SURVIVANTES.
///
/// LA BORNE D'IDENTIFIANT N'EST PAS UN DÉTAIL. Chaque rollup publie une COUVERTURE qui dit « ces buckets sont
/// une image des lignes `id <= at_id` » ; la route sert le reste (`id > at_id`) en BRUT et fusionne. Si on
/// re-agrégeait sans la borne, les lignes récentes seraient comptées DEUX FOIS. On reprend donc exactement la
/// borne que la couverture affirme. Couverture ABSENTE -> aucune affirmation n'est faite sur ces buckets (la
/// route décline et lit le brut) -> on se contente de supprimer, le tick reconstruira.
///
/// Renvoie `true` si les buckets ont été RÉ-AGRÉGÉS, `false` s'ils ont seulement été SUPPRIMÉS (aucune
/// couverture publiée -> rien n'était affirmé sur eux). Le reçu rend cette distinction telle quelle.
fn purge_rebuild_rollups(conn: &Connection, b0: i64, b1: i64) -> Result<bool, PurgeRefusal> {
    let conf = load_config();
    let min_sev: i64 = cfg(&conf, "PLUME_ROLLUP_SRCIP_MIN_SEV", "3").parse().unwrap_or(3);
    let topn = rollup_srcip_topn(&conf);
    let dim_topn: i64 = cfg(&conf, "PLUME_ROLLUP_DIM_TOPN", "50").parse().unwrap_or(50).max(0);

    let mut reaggregated = false;
    conn.execute("DELETE FROM event_rollup WHERE bucket >= ?1 AND bucket < ?2", params![b0, b1])
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    if let Some(cov) = meta_i64(conn, META_ROLLUP_COV_ID) {
        let cond = format!("ts >= {b0} AND ts < {b1} AND id <= {cov}");
        conn.execute(&rollup_insert_sql_into("event_rollup", &cond, min_sev, topn), [])
            .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
        reaggregated = true;
    }

    conn.execute("DELETE FROM event_dim_rollup WHERE bucket >= ?1 AND bucket < ?2", params![b0, b1])
        .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
    if let Some(at_id) = DimRollupCoverage::of(conn).late_floor_id() {
        let cond = format!("ts >= {b0} AND ts < {b1} AND id <= {at_id}");
        for (source, dims) in dim_rollup_specs().iter() {
            for dim in dims.iter() {
                conn.execute(&dim_rollup_insert_sql(source, dim, &cond, dim_topn), [])
                    .map_err(|e| PurgeRefusal::Db(e.to_string()))?;
            }
        }
        reaggregated = true;
    }
    Ok(reaggregated)
}

/// EXÉCUTION. Une seule transaction : inscription au registre PUIS suppression PUIS réconciliation des
/// dérivés. Toute erreur -> ROLLBACK complet, y compris l'entrée de registre (le registre n'affirme jamais
/// une purge qui n'a pas eu lieu). Le seul argument est un `ConfirmedPurge` : il n'existe pas de signature
/// permettant d'exécuter sans avoir simulé ET confirmé.
pub(crate) fn purge_apply(conn: &Connection, c: ConfirmedPurge) -> Result<PurgeReceipt, PurgeRefusal> {
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Err(PurgeRefusal::Db("verrou base indisponible".into()));
    }
    let outcome = (|| -> Result<PurgeReceipt, PurgeRefusal> {
        let proof = purge_inscribe(conn, &c).map_err(|e| PurgeRefusal::Db(e.to_string()))?;
        purge_delete_rows(conn, &c, &proof)
    })();
    match outcome {
        Ok(r) => {
            if let Err(e) = conn.execute_batch("COMMIT") {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(PurgeRefusal::Db(format!("COMMIT refusé : {e}")));
            }
            Ok(r)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// SIMULER PUIS CONFIRMER PUIS EXÉCUTER, en un appel — la forme qu'utilisent la CLI et l'API. La re-simulation
/// est le point clé : le jeton est comparé à l'empreinte du périmètre **tel qu'il est maintenant**, pas telle
/// qu'elle était quand l'humain a regardé. Rejeu, périmètre élargi, ligne ingérée, hold posé : tout cela
/// change l'empreinte et fait échouer la confirmation.
pub(crate) fn purge_confirm_and_apply(
    conn: &Connection,
    scope: PurgeScope,
    token: &str,
    actor: &str,
    reason: &str,
) -> Result<PurgeReceipt, PurgeRefusal> {
    let plan = purge_plan(conn, scope)?;
    let confirmed = plan.confirm(token, actor, reason)?;
    purge_apply(conn, confirmed)
}

// =====================================================================================
// 8. RENDU — plan et reçu, en JSON (API) et en texte (CLI)
// =====================================================================================

/// AVERTISSEMENT NON NÉGOCIABLE, rendu dans le plan ET dans le reçu, en JSON ET en texte. Une purge ne retire
/// RIEN des sauvegardes déjà prises : le prétendre ferait de « purgé » une fausse promesse, notamment face à
/// une demande d'effacement de type RGPD.
pub(crate) const PURGE_BACKUP_WARNING: &str =
    "Les SAUVEGARDES DÉJÀ PRISES ne sont PAS touchées : une restauration réintroduirait les lignes purgées. \
     Pour une demande d'effacement, traiter aussi les sauvegardes (rotation/expiration) — la purge ne le fait pas.";

pub(crate) fn purge_plan_json(p: &PurgePlan) -> Value {
    let sample: Vec<Value> = p
        .sample
        .iter()
        .map(|r| json!({ "id": r.id, "ts": r.ts, "source": r.source, "severity": r.severity, "message": r.message }))
        .collect();
    let selectors: Vec<Value> =
        p.scope.selectors().map(|s| json!({ "kind": s.kind(), "value": s.value() })).collect();
    json!({
        "ok": true,
        "scope": {
            "window": { "start_ts": p.scope.window.start_ts, "end_ts": p.scope.window.end_ts },
            "selectors": selectors,
            "canonical": p.scope.canonical(),
        },
        "rows": p.rows,
        "per_source": p.per_source.iter().map(|(s, n)| json!({ "source": s, "rows": n })).collect::<Vec<_>>(),
        "id_range": [p.id_lo, p.id_hi],
        "ts_range": [p.ts_lo, p.ts_hi],
        "sample": sample,
        "token": p.digest,
        "not_covered": {
            "backups": PURGE_BACKUP_WARNING,
            "alerts_in_window": p.uncovered.alerts_in_window,
            "metrics_in_window": p.uncovered.metrics_in_window,
            "snapshots_in_window": p.uncovered.snapshots_in_window,
            "dashboard_snapshots": p.uncovered.dashboard_snapshots,
            "host_rollup": "l'inventaire de flotte (host_rollup) n'est PAS recalculé : ses compteurs restent \
                            gonflés des lignes purgées jusqu'au prochain rebuild complet",
        },
    })
}

pub(crate) fn purge_receipt_json(r: &PurgeReceipt) -> Value {
    json!({
        "ok": true,
        "rows_deleted": r.rows_deleted,
        "token": r.digest,
        "scope": r.canonical,
        "rollup_buckets_rebuilt": [r.rollup_buckets_rebuilt.0, r.rollup_buckets_rebuilt.1],
        "rollup_reaggregated": r.rollup_reaggregated,
        "panel_cache_cleared": r.panel_cache_cleared,
        "ledger_kind": PURGE_LEDGER_KIND,
        "not_covered": { "backups": PURGE_BACKUP_WARNING },
    })
}

/// Rendu TEXTE du plan pour la CLI (l'humain doit RECONNAÎTRE ce qu'il détruit avant de rendre le jeton).
pub(crate) fn purge_plan_text(p: &PurgePlan) -> String {
    let mut out = String::new();
    out.push_str("SIMULATION DE PURGE (aucune ligne supprimée)\n");
    out.push_str(&format!("  périmètre  : {}\n", p.scope.canonical()));
    out.push_str(&format!("  fenêtre    : [{} .. {}] (epoch s, inclusive)\n", p.scope.window.start_ts, p.scope.window.end_ts));
    out.push_str(&format!("  À DÉTRUIRE : {} ligne(s) de `event`\n", p.rows));
    if !p.per_source.is_empty() {
        out.push_str("  par source :\n");
        for (s, n) in &p.per_source {
            out.push_str(&format!("     - {s} : {n}\n"));
        }
    }
    if p.rows > 0 {
        out.push_str(&format!("  id         : [{} .. {}]\n", p.id_lo, p.id_hi));
        out.push_str(&format!("  ts         : [{} .. {}]\n", p.ts_lo, p.ts_hi));
        out.push_str("  échantillon (plus vieilles + plus récentes) :\n");
        for r in &p.sample {
            out.push_str(&format!("     #{} ts={} sev={} {} : {}\n", r.id, r.ts, r.severity, r.source, r.message));
        }
    }
    out.push_str("\nNON COUVERT (dit explicitement, pas résolu) :\n");
    out.push_str(&format!("  - sauvegardes : {PURGE_BACKUP_WARNING}\n"));
    out.push_str(&format!(
        "  - alertes dans la fenêtre : {} (rétention propre ; leur `detail` peut citer un event purgé)\n",
        p.uncovered.alerts_in_window
    ));
    out.push_str(&format!(
        "  - métriques : {} / captures d'état : {} (ni `source` ni `origin` : le périmètre ne s'y projette pas)\n",
        p.uncovered.metrics_in_window, p.uncovered.snapshots_in_window
    ));
    out.push_str(&format!(
        "  - instantanés de dashboard partageables : {} (résultats rendus, possiblement du contenu purgé)\n",
        p.uncovered.dashboard_snapshots
    ));
    out.push_str("  - inventaire de flotte (host_rollup) : compteurs non recalculés\n");
    if p.rows > PURGE_LARGE_ROWS_WARN {
        out.push_str(&format!(
            "\nATTENTION : {} lignes. La purge s'exécute en UNE transaction (l'inscription au registre et la \
             suppression ne se séparent pas) -> le verrou d'écriture est tenu pendant toute sa durée et \
             l'ingest attend. Restreindre la fenêtre si la coupure n'est pas acceptable.\n",
            p.rows
        ));
    }
    if p.rows > 0 {
        out.push_str(&format!(
            "\nPOUR EXÉCUTER, re-passer EXACTEMENT le même périmètre avec :\n  --confirm {}\n  --reason \"<motif>\"\n\
             Le jeton est l'empreinte de CE résultat : si une ligne entre ou sort du périmètre d'ici là, il devient caduc.\n",
            p.digest
        ));
    } else {
        out.push_str("\nRien à purger sur ce périmètre.\n");
    }
    out
}

pub(crate) fn purge_receipt_text(r: &PurgeReceipt) -> String {
    let rollups = if r.rollup_reaggregated {
        "supprimés PUIS ré-agrégés depuis les lignes survivantes"
    } else {
        "supprimés (aucune couverture publiée : le rollup n'affirmait rien sur cette bande ; le tick la reconstruira)"
    };
    format!(
        "PURGE EXÉCUTÉE\n  périmètre        : {}\n  lignes détruites : {}\n  registre         : {} (chaîné, tamper-evident)\n  \
         rollups [{} .. {}) : {}\n  cache de panneaux vidé : {} entrée(s)\n\nNON COUVERT : {}\n",
        r.canonical,
        r.rows_deleted,
        PURGE_LEDGER_KIND,
        r.rollup_buckets_rebuilt.0,
        r.rollup_buckets_rebuilt.1,
        rollups,
        r.panel_cache_cleared,
        PURGE_BACKUP_WARNING
    )
}

// =====================================================================================
// 9. ANALYSE DES BORNES TEMPORELLES (CLI/API) — jamais de borne implicite
// =====================================================================================

/// Analyse une borne temporelle : epoch en secondes (`1785520800`) ou décalage relatif au présent
/// (`-7d`, `-24h`, `-30m`, `-3600s`). Il n'y a PAS de valeur par défaut : les deux bornes sont exigées par
/// l'appelant, parce que `PurgeWindow` n'en accepte pas moins.
pub(crate) fn purge_parse_ts(s: &str, now_ts: i64) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("borne temporelle vide (une purge se borne TOUJOURS)".into());
    }
    if let Some(rest) = s.strip_prefix('-') {
        let (num, unit) = rest.split_at(rest.len().saturating_sub(1));
        let mult = match unit {
            "s" => 1i64,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            _ => return Err(format!("décalage '{s}' : unité attendue s|m|h|d (ex. -7d)")),
        };
        let n: i64 = num.parse().map_err(|_| format!("décalage '{s}' : nombre invalide"))?;
        if n < 0 {
            return Err(format!("décalage '{s}' : valeur négative"));
        }
        return Ok((now_ts - n * mult).max(0));
    }
    s.parse::<i64>()
        .map_err(|_| format!("borne '{s}' : attendu un epoch en secondes ou un décalage (-7d, -24h, -30m)"))
}

/// CONSTRUCTION DU PÉRIMÈTRE depuis des couples (genre, valeur) et deux bornes TEXTE — le point d'entrée
/// PARTAGÉ par la CLI et l'API, pour qu'il n'existe qu'UNE analyse des arguments (et donc qu'un seul jeu de
/// règles de validation). `sel` VIDE -> Err : `PurgeScope` exige un `head`, on ne peut pas en fabriquer un.
pub(crate) fn purge_scope_from_args(
    sel: &[(String, String)],
    since: &str,
    until: &str,
    now_ts: i64,
) -> Result<PurgeScope, String> {
    let mut built: Vec<PurgeSelector> = Vec::new();
    for (k, v) in sel {
        built.push(PurgeSelector::parse(k, v)?);
    }
    let mut it = built.into_iter();
    let head = it.next().ok_or_else(|| {
        "aucun identifiant de périmètre : une purge NOMME ce qu'elle détruit (--source / --env / --origin / \
         --engagement). « tout ce qui est dans cette fenêtre » n'est pas un périmètre acceptable."
            .to_string()
    })?;
    let tail: Vec<PurgeSelector> = it.collect();
    let w = PurgeWindow::new(purge_parse_ts(since, now_ts)?, purge_parse_ts(until, now_ts)?)?;
    PurgeScope::new(head, tail, w)
}

// =====================================================================================
// 10. SOUS-COMMANDE `plume-daemon purge` — deux temps, dans le binaire de l'image
// =====================================================================================

const PURGE_USAGE: &str = "\
usage : plume-daemon purge --since <borne> --until <borne> <au moins un identifiant> [--confirm <jeton> --reason \"<motif>\"]

  identifiants (au moins UN ; ils se conjoignent, donc chacun RÉTRÉCIT le périmètre)
    --source <nom>        event.source        (les sources d'audit de contrôle sont refusées)
    --env <id>            event.env_id
    --origin <val>        event.origin        ('daemon' est refusé : c'est la piste d'audit)
    --engagement <id>     event.engagement_id

  bornes (les DEUX sont OBLIGATOIRES — un périmètre sans borne n'existe pas)
    --since / --until     epoch en secondes, ou décalage relatif : -7d  -24h  -30m  -3600s

  exécution
    (sans --confirm)      SIMULE : compte exact, ventilation, échantillon, non-couvert, et le JETON
    --confirm <jeton>     EXÉCUTE si le jeton est encore l'empreinte du périmètre re-simulé
    --reason \"<motif>\"    OBLIGATOIRE avec --confirm (inscrit au registre d'intégrité)
    --json                sortie machine

exemple
    plume-daemon purge --source flux-de-test --since -2d --until -1h
    plume-daemon purge --source flux-de-test --since -2d --until -1h --confirm <jeton> --reason \"nettoyage onboarding\"
";

/// Acteur inscrit au registre pour une purge CLI. Pas d'identité applicative sur ce chemin : on inscrit ce
/// qu'on SAIT (compte système + pid), jamais un nom flatteur. `PLUME_PURGE_ACTOR` permet à un runbook de
/// nommer l'humain responsable — il s'AJOUTE à ce qu'on a mesuré, il ne le remplace pas.
fn purge_cli_actor() -> String {
    let sys = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "?".into());
    match std::env::var("PLUME_PURGE_ACTOR").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(who) => format!("cli:{sys}(pid {}) pour {who}", std::process::id()),
        None => format!("cli:{sys}(pid {})", std::process::id()),
    }
}

/// Pilote de la sous-commande. Sorties : 0 = simulation rendue / purge exécutée ; 2 = arguments invalides ou
/// base inouvrable ; 3 = REFUS motivé (legal-hold, tier froid, case citant, jeton caduc…). Un refus n'est PAS
/// un succès silencieux : il a son propre code de sortie, pour qu'un runbook ne l'avale pas.
pub(crate) fn purge_cli(args: &[String]) {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{PURGE_USAGE}");
        return;
    }
    let json_out = args.iter().any(|a| a == "--json");
    let flag = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let mut sel: Vec<(String, String)> = Vec::new();
    for (name, kind) in
        [("--source", "source"), ("--env", "env"), ("--origin", "origin"), ("--engagement", "engagement")]
    {
        if let Some(v) = flag(name) {
            sel.push((kind.to_string(), v));
        }
    }
    let (Some(since), Some(until)) = (flag("--since"), flag("--until")) else {
        eprintln!("purge : --since ET --until sont obligatoires (un périmètre sans borne n'existe pas).\n\n{PURGE_USAGE}");
        std::process::exit(2);
    };
    let scope = match purge_scope_from_args(&sel, &since, &until, now()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("purge : {e}\n\n{PURGE_USAGE}");
            std::process::exit(2);
        }
    };

    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    // MÊME PORTE que la rétention : une base qui ne satisfait pas le contrat de schéma n'est pas une base sur
    // laquelle on supprime des lignes. (Mesuré sur `retention` : sans cette porte, une base amputée sortait
    // en 0 et annonçait « OK ».)
    let conn = match PreparedDb::open(&db_path) {
        Ok(c) => c.into_connection(),
        Err(e) => {
            eprintln!("[schema] {e} — AUCUNE purge appliquée. Arrêt propre.");
            std::process::exit(2);
        }
    };

    let confirm = flag("--confirm");
    let reason = flag("--reason").unwrap_or_default();
    let result = match &confirm {
        // TEMPS 1 — simulation seule (aucune écriture).
        None => match purge_plan(&conn, scope) {
            Ok(p) => {
                if json_out {
                    println!("{}", serde_json::to_string_pretty(&purge_plan_json(&p)).unwrap_or_default());
                } else {
                    print!("{}", purge_plan_text(&p));
                }
                return;
            }
            Err(e) => Err(e),
        },
        // TEMPS 2 — re-simulation + comparaison du jeton + exécution.
        Some(tok) => purge_confirm_and_apply(&conn, scope, tok, &purge_cli_actor(), &reason).map(Some),
    };
    match result {
        Ok(Some(r)) => {
            if json_out {
                println!("{}", serde_json::to_string_pretty(&purge_receipt_json(&r)).unwrap_or_default());
            } else {
                print!("{}", purge_receipt_text(&r));
            }
        }
        Ok(None) => {}
        Err(e) => {
            if json_out {
                println!(
                    "{}",
                    json!({ "ok": false, "refusal": purge_refusal_code(&e), "message": e.to_string() })
                );
            } else {
                eprintln!("{e}");
            }
            std::process::exit(3);
        }
    }
}
