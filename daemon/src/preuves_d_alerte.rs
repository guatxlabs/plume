//! `P11.25-g` — LES PREUVES D'UNE ALERTE DE RÈGLE : les entités que son nombre compte, lues à l'instant où l'alerte
//! est levée, et servies avec elle.
//!
//! LE DÉFAUT. Une règle d'agrégat (« attaquant actif non banni », SQL natif) rend UN NOMBRE d'adresses ; l'alerte ne
//! portait que « nom : valeur > seuil » et le texte de la requête. Le forage de la console recentre une recherche sur
//! la fenêtre de la règle : pour une requête SQL qui rend un seul compte, il ne montre que ce compte, et l'exploitant
//! ne pouvait pas remonter aux adresses comptées.
//!
//! LE MÉCANISME, GÉNÉRIQUE. Une règle PEUT déclarer une requête de preuves (`rule.evidence_query`, v126, NULL = aucune) :
//! les lignes que son nombre compte, de même nature que sa requête (`is_soql` de la règle). Elle est jouée par le MÊME
//! chemin que la requête de la règle — même compilation (`rule_sql_a_l_instant`, même substitution de fenêtre), même
//! porte de lecture (`run_query_ex` : connexion du pool en lecture seule, autoriseur, budget interactif de
//! l'ordonnanceur) — pour les seules règles qui tirent, et le verdict est écrit sur l'alerte à sa levée
//! (`alert.evidence`, v126, un objet JSON). Aucun nom de règle n'est lu ici.
//!
//! CE QUI EST DIT, TOUJOURS : l'instant (`at`, celui de la levée de l'alerte) et la fenêtre ; puis l'une de trois
//! issues, chacune avec sa phrase :
//!   * `established` — les lignes, dans l'ordre de la requête, coupées à `BORNE_DES_PREUVES_D_ALERTE` ; la coupe est
//!     un fait dit (`total` lu, `served`, `truncated`, `total_exact` faux si le plafond de lecture a coupé avant) ;
//!   * `no_rows` — la lecture a réussi et n'a rien rendu (l'activité a cessé entre l'évaluation et cette lecture) ;
//!   * `not_established` — la lecture a échoué : une cause de l'ensemble fermé `CAUSES_D_ABANDON`
//!     (`detection_aveugle`), jamais le texte du moteur ni la requête. L'alerte est levée quand même.
//!
//! LES PREUVES SONT UN FAIT DATÉ : écrites par l'`INSERT` qui lève l'alerte, jamais par le rafraîchissement d'un
//! épisode ouvert (`run_due_rules`) ; la phrase servie le dit.
use serde_json::{json, Value};

/// Le nombre de lignes de preuves écrites sur une alerte (et donc servies avec elle). Au-delà, la coupe est dite.
pub(crate) const BORNE_DES_PREUVES_D_ALERTE: usize = 50;

/// Les états servis sous `evidence.state`. Les trois premiers sont écrits à la levée ; les deux derniers ne sont posés
/// qu'au service (`alerts.rs`).
pub(crate) const ETAT_PREUVES_ETABLIES: &str = "established";
pub(crate) const ETAT_PREUVES_SANS_LIGNE: &str = "no_rows";
pub(crate) const ETAT_PREUVES_NON_ETABLIES: &str = "not_established";
pub(crate) const ETAT_PREUVES_RETENUES: &str = "withheld";
pub(crate) const ETAT_PREUVES_ILLISIBLES: &str = "unreadable";

pub(crate) const PHRASE_PREUVES_ETABLIES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la \
fenêtre de la règle : toutes les lignes lues sont servies. Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_COUPEES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la \
fenêtre de la règle, COUPÉES : served lignes servies sur total lues (total_exact faux : au moins autant, le plafond de \
lecture a coupé avant). Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_SANS_LIGNE: &str = "Aucune ligne de preuve à l'instant où l'alerte a été levée (at) : \
la lecture a réussi et n'a rien rendu, l'activité comptée par la règle a cessé entre son évaluation et cette lecture. \
Fait daté : elles ne sont pas réécrites aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_NON_ETABLIES: &str = "Preuves NON ÉTABLIES : leur lecture a échoué à l'instant où \
l'alerte a été levée (at), pour la cause dite. L'alerte est levée quand même. Fait daté : elles ne sont pas réécrites \
aux tirs suivants.";
pub(crate) const PHRASE_PREUVES_RETENUES: &str = "Preuves retenues : un filtre de champs est actif pour votre rôle, et \
les preuves, lues sans masque par l'ordonnanceur, ne peuvent pas être masquées après coup.";
pub(crate) const PHRASE_PREUVES_ILLISIBLES: &str = "Preuves écrites sur l'alerte mais illisibles en base : rien n'en \
est servi.";

/// L'issue de la lecture des preuves.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Preuves {
    /// Au moins une ligne. `lignes` = TOUTES les lignes lues (bornées par le plafond de lecture) ; la borne des preuves
    /// est appliquée à l'écriture (`en_json`). `total_exact` faux : le plafond de lecture a coupé avant la fin.
    Etablies { colonnes: Vec<Value>, lignes: Vec<Value>, total_exact: bool },
    /// La lecture a réussi, zéro ligne.
    SansLigne { colonnes: Vec<Value> },
    /// La lecture a échoué : une cause de `detection_aveugle::CAUSES_D_ABANDON`.
    NonEtablies { cause: &'static str },
}

/// Les preuves d'une alerte, datées : l'instant de la levée et la fenêtre de la règle.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PreuvesDatees {
    pub(crate) instant: i64,
    pub(crate) window_s: i64,
    pub(crate) preuves: Preuves,
}

impl PreuvesDatees {
    /// La cause, quand les preuves ne sont pas établies (pour la ligne de journal de la levée).
    pub(crate) fn cause_non_etablie(&self) -> Option<&'static str> {
        match self.preuves {
            Preuves::NonEtablies { cause } => Some(cause),
            Preuves::Etablies { .. } | Preuves::SansLigne { .. } => None,
        }
    }

    /// L'objet écrit dans `alert.evidence` et servi tel quel sous la clé `evidence` de `/api/alerts`.
    pub(crate) fn en_json(&self) -> Value {
        let from = if self.window_s > 0 { self.instant - self.window_s } else { 0 };
        match &self.preuves {
            Preuves::Etablies { colonnes, lignes, total_exact } => {
                let total = lignes.len();
                let servies = total.min(BORNE_DES_PREUVES_D_ALERTE);
                let coupees = servies < total || !total_exact;
                json!({
                    "state": ETAT_PREUVES_ETABLIES,
                    "phrase": if coupees { PHRASE_PREUVES_COUPEES } else { PHRASE_PREUVES_ETABLIES },
                    "at": self.instant, "from": from, "window_s": self.window_s,
                    "columns": colonnes, "rows": &lignes[..servies],
                    "total": total, "total_exact": total_exact, "served": servies, "truncated": coupees,
                })
            }
            Preuves::SansLigne { colonnes } => json!({
                "state": ETAT_PREUVES_SANS_LIGNE,
                "phrase": PHRASE_PREUVES_SANS_LIGNE,
                "at": self.instant, "from": from, "window_s": self.window_s,
                "columns": colonnes, "rows": [],
                "total": 0, "total_exact": true, "served": 0, "truncated": false,
            }),
            Preuves::NonEtablies { cause } => json!({
                "state": ETAT_PREUVES_NON_ETABLIES,
                "phrase": PHRASE_PREUVES_NON_ETABLIES,
                "at": self.instant, "from": from, "window_s": self.window_s,
                "cause": cause,
            }),
        }
    }
}

/// LA REQUÊTE DE PREUVES SUIT LA REQUÊTE DE LA RÈGLE — le prédicat, écrit UNE fois et partagé par chaque geste qui
/// récrit la requête ou la nature d'une règle : la modification par l'API (`rule_update`) et les deux réimpositions
/// d'overlay `config.d` (`overlays::sql_reimposition_rule` pour `rules/*.json`, `load_overlay_sigma` pour
/// `sigma/*.yml`). Rend le membre `SET` qui garde `evidence_query` quand la ligne porte DÉJÀ la nature `nature` et la
/// requête `requete` (expressions SQL : un paramètre lié ou un littéral), et la passe à NULL sinon : une requête de
/// preuves ne vaut que pour la requête et la nature dont elle liste la population. Placé dans le même `UPDATE` que la
/// récriture (ou avant elle dans la même transaction) : SQLite évalue les membres droits sur la ligne d'AVANT la mise à
/// jour, la comparaison voit donc l'ancienne requête.
pub(crate) fn sql_preuves_gardees_si_requete_et_nature_inchangees(nature: &str, requete: &str) -> String {
    format!("evidence_query=CASE WHEN is_soql={nature} AND query={requete} THEN evidence_query END")
}

#[cfg(test)]
thread_local! {
    /// Le nombre de lectures de preuves faites sur ce fil (l'ordonnanceur les fait sur le sien, en séquence).
    pub(crate) static LECTURES_DE_PREUVES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// LIT LES PREUVES d'une règle qui tire, à l'instant `instant` (celui de la levée), par le chemin de la règle : même
/// compilation (`rule_sql_a_l_instant`), même porte de lecture et même budget que son évaluation (`run_query_ex`,
/// budget interactif). Ne rend jamais d'erreur : un échec est une issue (`NonEtablies`, cause fermée).
pub(crate) fn lire_les_preuves(db_path: &str, requete: &str, is_soql: bool, window_s: i64, instant: i64) -> PreuvesDatees {
    #[cfg(test)]
    LECTURES_DE_PREUVES.with(|n| n.set(n.get() + 1));
    let preuves = match crate::handlers::detection::rule_sql_a_l_instant(requete, is_soql, window_s, instant) {
        Err(_) => Preuves::NonEtablies { cause: crate::detection_aveugle::CAUSE_COMPILATION_REFUSEE },
        Ok(sql) => match crate::run_query_ex(db_path, &sql, crate::query_budget_interactive_ms(), None) {
            Err(e) => Preuves::NonEtablies { cause: crate::detection_aveugle::AbandonDEvaluation::erreur_de_requete(&e).cause },
            Ok(v) => {
                let colonnes = v.get("columns").and_then(Value::as_array).cloned().unwrap_or_default();
                let lignes = v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
                // `run_query_ex` pose toujours `stats.truncated` ; tout autre état que `false` est dit « au moins ».
                let total_exact = v.pointer("/stats/truncated") == Some(&Value::Bool(false));
                if lignes.is_empty() {
                    Preuves::SansLigne { colonnes }
                } else {
                    Preuves::Etablies { colonnes, lignes, total_exact }
                }
            }
        },
    };
    PreuvesDatees { instant, window_s, preuves }
}

/// CE QUE `/api/alerts` SERT D'UNE COLONNE `alert.evidence` NON NULLE : l'objet écrit à la levée, ou, s'il ne se relit
/// pas, l'état `unreadable` (jamais le texte en base).
pub(crate) fn preuves_servies(ecrites: &str) -> Value {
    match serde_json::from_str::<Value>(ecrites) {
        Ok(v) if v.is_object() => v,
        Ok(_) | Err(_) => json!({ "state": ETAT_PREUVES_ILLISIBLES, "phrase": PHRASE_PREUVES_ILLISIBLES }),
    }
}

/// CE QUE `/api/alerts` SERT À LA PLACE DES PREUVES quand un filtre de champs est actif pour l'appelant.
pub(crate) fn preuves_retenues() -> Value {
    json!({ "state": ETAT_PREUVES_RETENUES, "phrase": PHRASE_PREUVES_RETENUES })
}

// =====================================================================================================================
// LES PREUVES DANS UNE NOTIFICATION SORTANTE (`dispatch_notifications`, handlers/notifiers.rs).
//
// Une alerte levée emporte ses preuves FIGÉES (l'objet écrit à la levée, jamais une lecture rejouée), ajoutées APRÈS le
// détail de la notification : le texte d'avant n'est pas touché, et une alerte dont la règle ne déclare pas de requête
// de preuves et qui n'en porte pas part à l'identique (seule une ligne d'alerte qui ne se relit pas à l'envoi le dit,
// quelle que soit sa règle). Une notification n'a pas de destinataire authentifié : elle n'emporte JAMAIS plus que
// ce que `/api/alerts` sert au rôle le plus faible admis à voir l'alerte (le lecteur). Un lecteur est masqué par TOUTE
// règle de filtre de champs active qui le vise (`field_filter::role_threshold` : le seuil le plus bas est celui du
// lecteur) et `/api/alerts` lui sert alors les preuves RETENUES ; l'envoi les retient donc dès qu'une règle active
// existe dans la base, quels que soient son tenant et son environnement (au plus large), et quand ce registre ne se
// relit pas. L'objet joint est celui que la route sert, champ pour champ ; il est BORNÉ par la borne de lignes de la
// route (`BORNE_DES_PREUVES_D_ALERTE`) et, en octets, par `BORNE_D_OCTETS_DES_PREUVES_NOTIFIEES` : la coupe retire des
// lignes par la fin, et elle est dite (`served`, `truncated`, la phrase de la coupe et la mention).
// =====================================================================================================================

/// Taille maximale, en octets, de l'objet de preuves (JSON compact) joint à une notification sortante.
pub(crate) const BORNE_D_OCTETS_DES_PREUVES_NOTIFIEES: usize = 2048;

pub(crate) const MENTION_PREUVES_JOINTES: &str = "Preuves figées à la levée de l'alerte, telles que /api/alerts les sert :";
pub(crate) const MENTION_PREUVES_COUPEES_A_L_ENVOI: &str = "Preuves figées à la levée de l'alerte, COUPÉES pour tenir dans \
la notification (served lignes jointes) ; /api/alerts sert toutes les lignes écrites :";
pub(crate) const MENTION_PREUVES_TROP_GRANDES: &str = "Preuves figées à la levée de l'alerte : trop grandes pour la \
notification même sans aucune ligne, rien n'en est joint ; /api/alerts les sert.";
pub(crate) const MENTION_PREUVES_SANS_LIGNE: &str = "Preuves : aucune ligne à la levée de l'alerte (la lecture a réussi et \
n'a rien rendu).";
pub(crate) const MENTION_PREUVES_NON_ETABLIES: &str = "Preuves : non établies, leur lecture a échoué à la levée de l'alerte, \
cause :";
pub(crate) const CAUSE_DES_PREUVES_HORS_ENSEMBLE: &str = "inconnue";
pub(crate) const MENTION_PREUVES_NON_FIGEES: &str = "Preuves : non figées pour cette alerte, aucune lecture n'a été faite à \
sa levée.";
pub(crate) const MENTION_PREUVES_RETENUES_A_L_ENVOI: &str = "Preuves : retenues, un filtre de champs est actif ; elles ne \
sortent par aucune notification.";
pub(crate) const MENTION_PREUVES_MASQUAGE_NON_LU: &str = "Preuves : retenues, le registre des filtres de champs n'a pas pu \
être lu.";
pub(crate) const MENTION_PREUVES_ILLISIBLES_A_L_ENVOI: &str = "Preuves : écrites sur l'alerte mais illisibles en base, rien \
n'en est joint.";
pub(crate) const MENTION_PREUVES_NON_RELUES: &str = "Preuves : non relues, la ligne de l'alerte n'a pas pu être lue à \
l'envoi.";
pub(crate) const MENTION_PREUVES_FORME_INCONNUE: &str = "Preuves : forme inconnue, rien n'en est joint.";

/// Ce que l'envoi sait des filtres de champs de la base qui émet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MasquageALEnvoi {
    /// Aucune règle active : `/api/alerts` sert les preuves au lecteur telles qu'écrites.
    Aucun,
    /// Au moins une règle active (en base, ou armée dans le registre en mémoire) : retenues.
    Actif,
    /// La table des règles ne se relit pas : retenues.
    NonLu,
}

/// LE MASQUAGE VU PAR L'ENVOI. La table est lue avec la règle d'activité du registre (`read_field_filter_table` : seul
/// l'entier 0 éteint une règle, toute autre valeur la laisse active ; la colonne est d'affinité entière, un texte ou un
/// réel qui vaut 0 y est rangé en entier 0, et `enabled<>0` est vrai pour tout le reste) ; le registre en mémoire de cette base est aussi
/// consulté, pour une règle encore armée après un rechargement raté : au plus large comme la table, toute règle du
/// registre de cette base compte, quels que soient son tenant et son environnement, et la base est reconnue par son
/// chemin canonique (`field_filter::registre_porte_une_regle`).
pub(crate) fn masquage_a_l_envoi(conn: &rusqlite::Connection) -> MasquageALEnvoi {
    let registre_arme = conn.path().is_some_and(crate::field_filter::registre_porte_une_regle);
    match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM field_filter WHERE enabled<>0)",
        [],
        |r| r.get::<_, i64>(0),
    ) {
        Err(_) => MasquageALEnvoi::NonLu,
        Ok(n) if n != 0 || registre_arme => MasquageALEnvoi::Actif,
        Ok(_) => MasquageALEnvoi::Aucun,
    }
}

/// La ligne d'une alerte relue à l'envoi.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PreuvesLuesALEnvoi {
    /// `ecrites` : la colonne `alert.evidence` (`None` = NULL, `Some(None)` = cellule qui n'est pas un texte UTF-8) ;
    /// `declarees` : la règle qui a levé l'alerte déclare une requête de preuves non vide.
    Lues { ecrites: Option<Option<String>>, declarees: bool },
    /// La ligne n'a pas été lue (lecture refusée, ou ligne absente).
    NonLues,
}

/// RELIT, pour l'envoi, les preuves écrites sur l'alerte `alerte` et la déclaration de sa règle.
pub(crate) fn lire_les_preuves_a_l_envoi(conn: &rusqlite::Connection, alerte: i64) -> PreuvesLuesALEnvoi {
    let lue = conn.query_row(
        "SELECT alert.evidence, EXISTS(SELECT 1 FROM rule r WHERE ('rule.'||r.id)=alert.rule AND COALESCE(r.evidence_query,'')<>'') \
         FROM alert WHERE alert.id=?1",
        [alerte],
        |r| {
            let ecrites = match r.get_ref(0)? {
                rusqlite::types::ValueRef::Null => None,
                rusqlite::types::ValueRef::Text(t) => Some(std::str::from_utf8(t).ok().map(str::to_string)),
                _ => Some(None),
            };
            Ok(PreuvesLuesALEnvoi::Lues { ecrites, declarees: r.get::<_, i64>(1)? != 0 })
        },
    );
    match lue {
        Ok(l) => l,
        Err(_) => PreuvesLuesALEnvoi::NonLues,
    }
}

/// LE TEXTE AJOUTÉ AU DÉTAIL D'UNE NOTIFICATION : vide pour une alerte dont la règle ne déclare pas de preuves et qui
/// n'en porte pas ; sinon deux sauts de ligne, puis la mention, puis (preuves établies et servies) l'objet borné.
pub(crate) fn texte_des_preuves_a_l_envoi(lues: &PreuvesLuesALEnvoi, masquage: MasquageALEnvoi) -> String {
    let texte: Option<String> = match lues {
        PreuvesLuesALEnvoi::NonLues => Some(MENTION_PREUVES_NON_RELUES.to_string()),
        PreuvesLuesALEnvoi::Lues { ecrites: None, declarees: false } => None,
        PreuvesLuesALEnvoi::Lues { ecrites: None, declarees: true } => Some(MENTION_PREUVES_NON_FIGEES.to_string()),
        PreuvesLuesALEnvoi::Lues { ecrites: Some(ecrites), .. } => Some(match (masquage, ecrites) {
            (MasquageALEnvoi::Actif, _) => MENTION_PREUVES_RETENUES_A_L_ENVOI.to_string(),
            (MasquageALEnvoi::NonLu, _) => MENTION_PREUVES_MASQUAGE_NON_LU.to_string(),
            (MasquageALEnvoi::Aucun, None) => MENTION_PREUVES_ILLISIBLES_A_L_ENVOI.to_string(),
            (MasquageALEnvoi::Aucun, Some(texte)) => preuves_servies_a_l_envoi(&preuves_servies(texte)),
        }),
    };
    texte.map(|t| format!("\n\n{t}")).unwrap_or_default()
}

/// L'objet que `/api/alerts` sert sans masque, mis en texte de notification selon son état.
fn preuves_servies_a_l_envoi(servies: &Value) -> String {
    match servies.get("state").and_then(Value::as_str) {
        Some(ETAT_PREUVES_ETABLIES) => preuves_etablies_bornees(servies),
        Some(ETAT_PREUVES_SANS_LIGNE) => MENTION_PREUVES_SANS_LIGNE.to_string(),
        Some(ETAT_PREUVES_NON_ETABLIES) => {
            let cause = servies
                .get("cause")
                .and_then(Value::as_str)
                .filter(|c| crate::detection_aveugle::CAUSES_D_ABANDON.contains(c))
                .unwrap_or(CAUSE_DES_PREUVES_HORS_ENSEMBLE);
            format!("{MENTION_PREUVES_NON_ETABLIES} {cause}.")
        }
        Some(ETAT_PREUVES_ILLISIBLES) => MENTION_PREUVES_ILLISIBLES_A_L_ENVOI.to_string(),
        _ => MENTION_PREUVES_FORME_INCONNUE.to_string(),
    }
}

/// Des preuves établies, bornées : au plus `BORNE_DES_PREUVES_D_ALERTE` lignes et `BORNE_D_OCTETS_DES_PREUVES_NOTIFIEES`
/// octets d'objet. Les lignes sont retirées par la fin ; une coupe pose `served`, `truncated` et la phrase de la coupe
/// sur l'objet, et prend la mention de la coupe. Sans coupe, l'objet est celui que la route sert, à l'identique.
fn preuves_etablies_bornees(servies: &Value) -> String {
    let lignes: Vec<Value> = servies.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
    // Première estimation, par la taille des lignes seules ; la taille réelle de l'objet est jugée ensuite.
    let mut cumul = 0usize;
    let mut n = 0usize;
    for ligne in lignes.iter().take(BORNE_DES_PREUVES_D_ALERTE) {
        let taille = ligne.to_string().len() + 1;
        if cumul + taille > BORNE_D_OCTETS_DES_PREUVES_NOTIFIEES {
            break;
        }
        cumul += taille;
        n += 1;
    }
    loop {
        let mut objet = servies.clone();
        let coupe = n < lignes.len();
        if coupe {
            objet["rows"] = Value::Array(lignes[..n].to_vec());
            objet["served"] = json!(n);
            objet["truncated"] = json!(true);
            objet["phrase"] = json!(PHRASE_PREUVES_COUPEES);
        }
        let texte = objet.to_string();
        if texte.len() <= BORNE_D_OCTETS_DES_PREUVES_NOTIFIEES {
            let mention = if coupe { MENTION_PREUVES_COUPEES_A_L_ENVOI } else { MENTION_PREUVES_JOINTES };
            return format!("{mention}\n{texte}");
        }
        if n == 0 {
            return MENTION_PREUVES_TROP_GRANDES.to_string();
        }
        n -= 1;
    }
}
