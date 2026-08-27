//! `P3.9-a` — UNE RÈGLE QUI NE PEUT PAS ÊTRE ÉVALUÉE EST UNE DÉTECTION ÉTEINTE, ET ELLE LE DIT.
//!
//! LE DÉFAUT QUE CE MODULE FERME. Depuis `P4.1-r`, l'ordonnanceur COMPTE les règles dues qu'il
//! abandonne (compilation refusée, évaluation en échec, fil en panique) et la surface d'état affiche
//! le compte du dernier tick. Ce compte est un fait de TICK : il ne sait pas qu'une MÊME règle est
//! abandonnée à chaque intervalle depuis des heures, et personne ne regarde un panneau système pendant
//! un incident. Une règle livrée, dont la donnée était présente dans chaque fenêtre, a ainsi gardé le
//! silence pendant tout un incident : chaque évaluation dépassait le budget ou le verrou sur un nœud
//! en thrash, et rien ne distinguait ce silence d'un calme.
//!
//! CE QUE CE MODULE TIENT, EN TROIS FAITS :
//!   * LA CAUSE DE L'ABANDON EST CONSERVÉE. `eval_value_budget` rendait `Option<f64>` : l'erreur de
//!     requête, le dépassement de budget, une cellule non numérique et une panique du fil se
//!     fondaient en un même `None`. Ici, une évaluation rend sa valeur ou son `AbandonDEvaluation`,
//!     dont la cause est une clé de l'ensemble FERMÉ `CAUSES_D_ABANDON` (la forme de `S32`) ;
//!   * LES ABANDONS CONSÉCUTIFS SONT COMPTÉS PAR RÈGLE ET PERSISTENT (`rule.abandons_consecutifs`,
//!     v116) : un redémarrage du démon ne remet pas le compte à zéro, puisqu'il ne change rien à la
//!     cause. Le compte est remis à zéro à la PREMIÈRE évaluation réussie ;
//!   * AU SEUIL, UNE ALERTE — par le chemin des alertes de capteur muet (`INSERT OR IGNORE` sur une
//!     clé de déduplication STABLE par règle, résolution qui libère la clé) : elle arrive dans la liste
//!     des alertes comme les autres, et la table `alert` n'est jamais purgée. Son titre nomme la
//!     règle, la cause et le nombre d'évaluations ; elle se RÉSOUT d'elle-même à la première évaluation
//!     réussie, par la même mécanique que le retour sous le seuil d'une règle.
//!
//! LE SEUIL EST DÉRIVÉ, PAS CHOISI : `seuil_d_abandons_consecutifs` rend le nombre d'intervalles de la
//! règle qui tiennent dans UNE HEURE — l'horizon que les autres signaux de santé non purgeables
//! utilisent déjà pour leur déduplication (`emit_disk_health`, `emit_ledger_unsigned`,
//! `emit_backup_symmetric_signal` : un seau horaire) — avec un plancher de DEUX : un abandon isolé est
//! le régime transitoire que la re-planification au prochain intervalle traite déjà, et une alerte
//! au premier abandon rendrait chaque contention passagère bruyante. Une règle évaluée toutes les dix
//! minutes est donc dite aveugle après six abandons consécutifs ; une règle horaire, après deux.
//!
//! CE QUE CE MODULE NE FAIT PAS : il n'évalue rien et ne décide pas de re-tenter — l'ordonnanceur
//! re-planifie comme avant. Il ne couvre que les règles qu'il est appelé à consigner ; les autres
//! évaluateurs (règles avancées, règles de risque) comptent leurs abandons sans les consigner ici,
//! et la garde `toute_replanification_sans_evaluation_passe_par_le_consignateur` nomme cet écart.
use rusqlite::{params, Connection};

/// La requête a tourné et a été INTERROMPUE par le chien de garde du budget temps.
pub(crate) const CAUSE_BUDGET_DEPASSE: &str = "budget_depasse";
/// La requête a été REFUSÉE ou a ÉCHOUÉ (préparation, table absente, verrou, mémoire, plafond).
pub(crate) const CAUSE_ERREUR_REQUETE: &str = "erreur_requete";
/// La requête a rendu une cellule qui n'est pas un nombre (ou aucune ligne).
pub(crate) const CAUSE_VALEUR_NON_NUMERIQUE: &str = "valeur_non_numerique";
/// La requête de la règle ne COMPILE pas (le compilateur SOQL l'a refusée).
pub(crate) const CAUSE_COMPILATION_REFUSEE: &str = "compilation_refusee";
/// Le fil d'évaluation a PANIQUÉ : la règle n'a pas été évaluée, et l'ordonnanceur a survécu.
pub(crate) const CAUSE_EVALUATEUR_EN_PANNE: &str = "evaluateur_en_panne";
/// L'ENSEMBLE FERMÉ des causes d'abandon d'une règle. Un témoin vérifie que chaque cause rendue par
/// `evaluer_valeur_de_regle` et par les constructeurs ci-dessous en fait partie.
pub(crate) const CAUSES_D_ABANDON: [&str; 5] = [
    CAUSE_BUDGET_DEPASSE,
    CAUSE_ERREUR_REQUETE,
    CAUSE_VALEUR_NON_NUMERIQUE,
    CAUSE_COMPILATION_REFUSEE,
    CAUSE_EVALUATEUR_EN_PANNE,
];

/// L'horizon de cécité toléré avant l'alerte : UNE HEURE, l'unité que les signaux de santé non
/// purgeables utilisent déjà pour se dédupliquer.
pub(crate) const HORIZON_DE_CECITE_S: i64 = 3600;
/// Sous ce nombre d'abandons consécutifs, aucune alerte : un abandon isolé est un incident
/// transitoire que la re-planification traite déjà.
pub(crate) const PLANCHER_D_ABANDONS: u32 = 2;

/// Le préfixe de la clé de déduplication des alertes de cécité — UNE clé par règle, stable pour la
/// durée de l'épisode, libérée à la résolution (la mécanique de `rule-{id}` et de `hb-{id}`).
pub(crate) const DEDUP_PREFIXE: &str = "regle-aveugle-";
/// La famille de l'alerte dans `alert.rule` : `heartbeat.` est la famille des signaux d'angle mort
/// (capteur muet, flotte muette) que le bulletin de support relit déjà, et qu'aucune jointure sur
/// `rule` ne prend pour un tir.
pub(crate) const FAMILLE_ALERTE: &str = "heartbeat.regle-aveugle";

/// CE QU'UNE ÉVALUATION ABANDONNÉE LAISSE : sa cause (clé fermée) et le détail lisible par l'analyste.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AbandonDEvaluation {
    pub(crate) cause: &'static str,
    pub(crate) detail: String,
}

impl AbandonDEvaluation {
    /// Le SEUL constructeur : une cause hors de l'ensemble fermé est une faute de programmation, pas
    /// une donnée — elle est refusée en débogage, et un témoin relit l'ensemble en production.
    fn de(cause: &'static str, detail: String) -> Self {
        debug_assert!(CAUSES_D_ABANDON.contains(&cause), "cause d'abandon hors de l'ensemble fermé : {cause}");
        Self { cause, detail }
    }
    pub(crate) fn compilation_refusee(erreur: &str) -> Self {
        Self::de(CAUSE_COMPILATION_REFUSEE, erreur.to_string())
    }
    pub(crate) fn evaluateur_en_panne() -> Self {
        Self::de(CAUSE_EVALUATEUR_EN_PANNE, "le fil d'évaluation a paniqué".to_string())
    }
    /// La cause d'une erreur rendue par `run_query_ex`, dérivée de son message : le chien de garde
    /// du budget est le SEUL à produire « requête interrompue (budget … dépassé) » ; tout le reste
    /// est une requête qui a échoué.
    pub(crate) fn erreur_de_requete(erreur: &str) -> Self {
        let cause = if erreur.starts_with("requête interrompue (budget") { CAUSE_BUDGET_DEPASSE } else { CAUSE_ERREUR_REQUETE };
        Self::de(cause, erreur.to_string())
    }
    pub(crate) fn valeur_non_numerique(cellule: &serde_json::Value) -> Self {
        Self::de(CAUSE_VALEUR_NON_NUMERIQUE, format!("la dernière cellule de la première ligne n'est pas un nombre : {cellule}"))
    }
}

/// ÉVALUE LE SCALAIRE D'UNE RÈGLE — la valeur, ou l'abandon AVEC SA CAUSE. C'est la seule porte par
/// laquelle l'ordonnanceur évalue une règle ; `eval_value_budget` n'en est que la projection en
/// `Option` pour les appelants qui n'ont pas (encore) d'usage de la cause.
pub(crate) fn evaluer_valeur_de_regle(db_path: &str, sql: &str, budget_ms: u64) -> Result<f64, AbandonDEvaluation> {
    let v = crate::run_query_ex(db_path, sql, budget_ms, None).map_err(|e| AbandonDEvaluation::erreur_de_requete(&e))?;
    let cellule = v
        .get("rows")
        .and_then(|r| r.as_array())
        .and_then(|r| r.first())
        .and_then(|l| l.as_array())
        .and_then(|l| l.last())
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    cellule
        .as_f64()
        .or_else(|| cellule.as_i64().map(|n| n as f64))
        .ok_or_else(|| AbandonDEvaluation::valeur_non_numerique(&cellule))
}

/// LE SEUIL, DÉRIVÉ DE L'INTERVALLE DE LA RÈGLE : le nombre d'intervalles qui tiennent dans
/// `HORIZON_DE_CECITE_S`, arrondi vers le haut, jamais sous `PLANCHER_D_ABANDONS`. Un intervalle nul
/// ou négatif (une règle due à chaque tick) compte comme une seconde.
pub(crate) fn seuil_d_abandons_consecutifs(interval_s: i64) -> u32 {
    let intervalle = interval_s.max(1);
    let n = (HORIZON_DE_CECITE_S + intervalle - 1) / intervalle;
    u32::try_from(n).unwrap_or(u32::MAX).max(PLANCHER_D_ABANDONS)
}

pub(crate) fn cle_dedup(id: i64) -> String {
    format!("{DEDUP_PREFIXE}{id}")
}

/// Le titre de l'alerte : la règle, la cause et le nombre — ce qu'un analyste lit dans une liste.
pub(crate) fn titre(nom: &str, cause: &str, n: u32) -> String {
    format!("détection aveugle : {nom} — {cause}, {n} évaluations")
}

/// Ce que l'ordonnanceur a consigné pour une règle abandonnée : le compte consécutif atteint, et si
/// l'alerte est posée (ou rafraîchie) à ce tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct AbandonConsigne {
    pub(crate) consecutifs: u32,
    pub(crate) seuil: u32,
    pub(crate) alerte_posee: bool,
}

/// CONSIGNE UN ABANDON : re-planifie la règle (`last_run`), incrémente son compte consécutif, et dès
/// que ce compte atteint le seuil dérivé de son intervalle, pose l'alerte de cécité — `INSERT OR
/// IGNORE` sur la clé stable (no-op si l'épisode est déjà ouvert) puis rafraîchissement du titre, de
/// l'horodatage et du détail SANS toucher `notified` (pas de re-notification à chaque intervalle).
///
/// `None` si la règle n'a pas pu être relue après l'écriture : rien n'est posé, et l'abandon reste
/// compté par l'appelant (`P4.1-r`) — une alerte sur un compte qu'on n'a pas lu serait inventée.
pub(crate) fn consigner_abandon(
    conn: &Connection,
    id: i64,
    nom: &str,
    severity: i64,
    now_ts: i64,
    abandon: &AbandonDEvaluation,
) -> Option<AbandonConsigne> {
    let _ = conn.execute(
        "UPDATE rule SET last_run=?1, abandons_consecutifs=abandons_consecutifs+1 WHERE id=?2",
        params![now_ts, id],
    );
    let (consecutifs, interval_s): (u32, i64) = conn
        .query_row("SELECT abandons_consecutifs, interval_s FROM rule WHERE id=?1", params![id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })
        .ok()
        .map(|(n, i)| (u32::try_from(n).unwrap_or(u32::MAX), i))?;
    let seuil = seuil_d_abandons_consecutifs(interval_s);
    if consecutifs < seuil {
        return Some(AbandonConsigne { consecutifs, seuil, alerte_posee: false });
    }
    let dedup = cle_dedup(id);
    let titre = titre(nom, abandon.cause, consecutifs);
    let detail = format!(
        "La règle n'a pas pu être évaluée {consecutifs} fois de suite (seuil {seuil} : {HORIZON_DE_CECITE_S} s d'horizon \
         pour un intervalle de {interval_s} s). Dernière cause : {} — {}. Tant que cette alerte est ouverte, cette \
         détection est ÉTEINTE : elle ne peut ni tirer ni se résoudre. Elle se résout d'elle-même à la première \
         évaluation réussie.",
        abandon.cause, abandon.detail
    );
    // L'IMPUTATION est l'inconnu NOMMÉ : cette alerte se rapporte à une RÈGLE, pas à un flux — lui
    // imputer une source ferait basculer la pastille d'une source qui n'a rien fait (cf. flotte muette).
    let sources = crate::imputation_encoder(&[crate::SOURCE_INDETERMINABLE.to_string()]);
    let _ = conn.execute(
        "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,sources) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![now_ts, format!("{FAMILLE_ALERTE}.{id}"), severity, titre, detail, dedup, sources],
    );
    let _ = conn.execute(
        "UPDATE alert SET ts=?1, title=?2, detail=?3 WHERE dedup=?4 AND status IN ('new','ack')",
        params![now_ts, titre, detail, dedup],
    );
    Some(AbandonConsigne { consecutifs, seuil, alerte_posee: true })
}

/// CONSIGNE UNE ÉVALUATION RÉUSSIE : `last_run` et `last_value` comme avant, le compte consécutif
/// remis à zéro, et l'épisode de cécité RÉSOLU — la clé est libérée, un futur épisode se ré-arme.
pub(crate) fn consigner_evaluation_reussie(conn: &Connection, id: i64, now_ts: i64, valeur: f64) {
    let _ = conn.execute(
        "UPDATE rule SET last_run=?1, last_value=?2, abandons_consecutifs=0 WHERE id=?3",
        params![now_ts, valeur, id],
    );
    let _ = conn.execute(
        "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
        params![cle_dedup(id)],
    );
}

// ==================================================================================================
// `P9.5-a` — L'AUTRE FAÇON DONT UNE DÉTECTION EST ÉTEINTE : PLUS RIEN NE PEUT LA DÉCLENCHER.
//
// Tout ce qui précède éteint une règle parce que son ÉVALUATION échoue, et l'ordonnanceur a alors un
// abandon à consigner. Ici la règle s'évalue PARFAITEMENT et rend zéro pour toujours, parce qu'AUCUN
// fichier livré n'émet la source qu'elle interroge : il n'y a aucun abandon à compter, aucune alerte de
// cécité à poser, et rien ne la distingue d'un hôte sain. La matrice ATT&CK, elle, LA COMPTAIT :
// `handlers::alerts::build_attack_matrix` déclare une technique COUVERTE dès qu'une règle activée la
// tague. Croire surveillée une technique que rien n'observe est un défaut de sécurité, pas un défaut
// d'affichage. Ce qui alimente cette matrice est désormais `lire_la_couverture_des_regles_activees`
// (plus bas), et non plus une lecture nue des règles activées — et cette lecture rend TROIS états, parce
// qu'une première correction qui n'en rendait que deux a fait retomber la règle affamée dans le seau de
// « personne n'a jamais écrit de règle ».
//
// MESURÉ le 2026-08-27 sur l'arbre : sur toutes les règles qu'une base NEUVE reçoit active, une seule
// épingle une source qu'aucun fichier livré n'émet — `vault-audit` (la lecture de secret par une
// identité inattendue, taguée `T1552`), qu'aucune autre règle active ne tague : `T1552` s'affichait
// donc COUVERTE sur une installation fraîche où rien ne pouvait produire l'événement. Son producteur
// est une entrée SCRIPTÉE que l'exploitant dépose lui-même (`deploy/vault-audit.input.example`).
//
// LE CRITÈRE EST DÉRIVÉ DE DEUX CHOSES QUI EXISTAIENT DÉJÀ, ET D'AUCUNE LISTE DE NOMS :
//   * ce que la RÈGLE interroge — les épinglages POSITIFS et LITTÉRAUX de `source` dans sa requête,
//     lus par `sources_exigees` (le même texte que l'ordonnanceur exécute, pas une paraphrase) ;
//   * ce qu'un fichier LIVRÉ produit — `handlers::sources::SOURCES_LIVREES`, table MIROIR tenue dans
//     les DEUX SENS par `sources_livrees_est_le_miroir_des_fichiers_livres` (y ajouter une entrée
//     qu'aucun fichier n'émet rougit ; en omettre une qu'un fichier émet rougit aussi) — ou qu'une
//     SONDE livrée observe (`COLLECTORS`). Ces deux-là PRODUISENT. La troisième dérivation de
//     `raison_attendue_par_construction` — « le produit l'AGRÈGE » (`dim_rollup_specs`) — n'est
//     délibérément PAS un producteur : c'est exactement la classe de `vault-audit`, et la confondre
//     avec une production est le faux vert que cette clé ferme.
//
// CE QUE CE CRITÈRE NE JUGE PAS, ET C'EST ÉCRIT PLUTÔT QU'AFFIRMÉ FERMÉ :
//   * une règle qui n'épingle AUCUNE source (elle lit le CIM : `category=auth action=failure`,
//     `severity>=3`) — toute source peut la nourrir, il n'y a rien à rapprocher ;
//   * un épinglage qui n'est pas une ÉGALITÉ LITTÉRALE (`source=~motif`, `source=glob*`, `IN`,
//     `LIKE`) : le rapprochement n'est pas décidable, et un « aveugle » rendu sur une comparaison
//     qu'on ne sait pas résoudre serait une accusation inventée ;
//   * une NÉGATION (`source!=x`) n'épingle rien : elle exclut, elle n'exige pas ;
//   * les sources définies AU DÉPLOIEMENT — entrée scriptée de `custom.sh`, source déclarative de
//     l'agent, connecteur configuré en base. Elles n'existent pas au moment du semis : une règle qui
//     les attend est livrée ÉTEINTE, et l'exploitant l'ALLUME quand il branche le producteur. C'est
//     la doctrine déjà appliquée à YARA (`DETECTION_RULES_V53`) et aux règles de menace
//     (`seed_ti_alert_rules`), reprise ici au lieu d'être réinventée ;
//   * le grain du CHAMP (`fields.<X>`) n'est PAS jugé. `collected::COLLECTED_EXTENDED_FIELDS` cite UN
//     fichier par champ (le plus direct), pas TOUS ceux qui l'émettent : MESURÉ le 2026-08-27, la
//     citation de `collectors/web.sh` n'y porte que `dur_ms`/`router`/`ua` alors que la source `web`
//     émet aussi `status` et `path`. En dériver « ce champ est-il produit par CETTE source » rendrait
//     des aveugles FAUX. Non mesurable avec l'instrument disponible = non jugé.

/// Ce qu'une requête de règle EXIGE de la colonne `source`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SourcesExigees {
    /// Aucun épinglage : la règle lit le CIM, n'importe quelle source peut la nourrir.
    Aucune,
    /// Au moins un épinglage qu'on ne sait pas résoudre en NOMS (motif, glob, `IN`, `LIKE`).
    NonDecidable,
    /// La règle ne peut tirer que si l'UNE de ces sources arrive (DISJONCTION : une requête peut
    /// réunir plusieurs branches — le `UNION ALL` du SQL brut — et il suffit qu'une soit produite).
    Litterales(Vec<String>),
}

fn est_caractere_de_nom(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// LIT LES ÉPINGLAGES DE `source` D'UNE REQUÊTE — GXQL comme SQL brut, sans savoir lequel : les deux
/// écrivent `source` puis un opérateur puis une valeur, et un lecteur qui aurait besoin qu'on lui dise
/// laquelle des deux langues il lit se tromperait le jour où une règle change de forme.
///
/// Le balayage IGNORE ce qui est entre guillemets (une phrase cherchée n'est pas un épinglage) et
/// n'accepte `source` que précédé d'un caractère qui n'appartient pas à un nom : `cf_source=` est le
/// champ BRUT de Cloudflare, pas la source de l'événement.
pub(crate) fn sources_exigees(query: &str) -> SourcesExigees {
    let o: Vec<char> = query.chars().collect();
    let mut litterales: Vec<String> = Vec::new();
    let mut non_decidable = false;
    let mut i = 0usize;
    let mut guillemet: Option<char> = None;
    while i < o.len() {
        let c = o[i];
        if let Some(q) = guillemet {
            if c == q {
                guillemet = None;
            }
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            guillemet = Some(c);
            i += 1;
            continue;
        }
        if !(c == 's'
            && o[i..].starts_with(&['s', 'o', 'u', 'r', 'c', 'e'])
            && (i == 0 || !est_caractere_de_nom(o[i - 1]))
            && o.get(i + 6).map_or(true, |n| !est_caractere_de_nom(*n)))
        {
            i += 1;
            continue;
        }
        let mut j = i + 6;
        while j < o.len() && o[j].is_whitespace() {
            j += 1;
        }
        match o.get(j) {
            // `source!=x` — une exclusion n'exige rien.
            Some('!') => i = j + 1,
            Some('=') => {
                let mut k = j + 1;
                if o.get(k) == Some(&'=') {
                    k += 1; // `==` du SQL/GXQL
                }
                if o.get(k) == Some(&'~') {
                    non_decidable = true; // `source=~motif`
                    i = k + 1;
                    continue;
                }
                while k < o.len() && o[k].is_whitespace() {
                    k += 1;
                }
                let (valeur, fin) = lire_valeur(&o, k);
                i = fin.max(k + 1);
                match valeur {
                    Some(v) if !v.is_empty() && !v.contains('*') && !v.contains('?') => {
                        if !litterales.contains(&v) {
                            litterales.push(v);
                        }
                    }
                    // valeur vide, gabarit ou glob : on ne sait pas de quelle source il s'agit.
                    _ => non_decidable = true,
                }
            }
            _ => {
                // `source LIKE …`, `source IN (…)`, `source GLOB …` : un épinglage non résoluble.
                // Tout le reste (`stats count by source`, `ORDER BY source`) n'épingle rien.
                let mut k = j;
                let mut mot = String::new();
                while k < o.len() && o[k].is_ascii_alphabetic() {
                    mot.push(o[k].to_ascii_uppercase());
                    k += 1;
                }
                if mot == "LIKE" || mot == "IN" || mot == "GLOB" || mot == "REGEXP" || mot == "MATCH" {
                    non_decidable = true;
                }
                i = j.max(i + 6);
                if k > i {
                    i = k;
                }
            }
        }
    }
    if !litterales.is_empty() {
        return SourcesExigees::Litterales(litterales);
    }
    if non_decidable {
        return SourcesExigees::NonDecidable;
    }
    SourcesExigees::Aucune
}

/// La valeur d'un épinglage à partir de l'index `k` : citée (`'x'`, `"x"`) ou nue. `None` quand rien
/// de lisible ne suit. Rend aussi l'index où la lecture s'arrête.
fn lire_valeur(o: &[char], k: usize) -> (Option<String>, usize) {
    match o.get(k) {
        Some(&q) if q == '\'' || q == '"' => {
            let mut v = String::new();
            let mut i = k + 1;
            while i < o.len() && o[i] != q {
                v.push(o[i]);
                i += 1;
            }
            (Some(v), i + 1)
        }
        Some(_) => {
            let mut v = String::new();
            let mut i = k;
            while i < o.len() && (est_caractere_de_nom(o[i]) || o[i] == '*' || o[i] == '?') {
                v.push(o[i]);
                i += 1;
            }
            (if v.is_empty() { None } else { Some(v) }, i)
        }
        None => (None, k),
    }
}

/// UN FICHIER LIVRÉ PRODUIT-IL CETTE SOURCE ? Les deux dérivations qui PRODUISENT, et elles seules :
/// un fichier livré l'émet, ou une sonde livrée l'observe. « Le produit l'AGRÈGE » n'en fait PAS
/// partie — agréger une colonne n'a jamais rempli une table.
pub(crate) fn producteur_livre(source: &str) -> bool {
    if crate::handlers::sources::SOURCES_LIVREES.iter().any(|(s, _)| *s == source) {
        return true;
    }
    crate::COLLECTORS.iter().any(|(id, _, _, sonde, _)| {
        *id == source
            || crate::imputer_alerte_de_capteur(sonde)
                .into_iter()
                .any(|s| s != crate::SOURCE_INDETERMINABLE && s == source)
    })
}

/// LES SOURCES QU'UNE RÈGLE EXIGE ET QU'AUCUN PRODUCTEUR LIVRÉ NE PEUT FOURNIR. Vide = la règle peut
/// tirer, ou son exigence n'est pas décidable — dans les deux cas on ne l'accuse pas.
///
/// C'EST `sources_manquantes` SUR UNE BASE QUI N'A RIEN OBSERVÉ, et c'est écrit ainsi plutôt que
/// recopié : les deux répondent à la même question à deux MOMENTS — le semis ne sait rien de ce qui a
/// été reçu, la lecture le sait — et deux corps jumeaux auraient fini par répondre différemment.
pub(crate) fn sources_sans_producteur_livre(query: &str) -> Vec<String> {
    sources_manquantes(query, &[])
}

// ==================================================================================================
// `P9.5-a` (SUITE) — CE QUI RESTE VRAI SUR UNE BASE **DÉJÀ DÉPLOYÉE**, ET LE GESTE QU'ON N'A PAS FAIT.
//
// LE VERROU CI-DESSUS NE PROTÈGE QUE LES BASES NEUVES, ET C'EST MESURÉ, PAS SUPPOSÉ. `seed_detection_rules`
// court-circuite sur son marqueur `seeded_detection_rules` ; la ligne vivante d'une installation en service
// a été posée par `migrate_v50` (`migrate.rs`), dont l'INSERT lie `enabled` au LITTÉRAL `1`. Sur le parc
// réel — la base neuve est le cas rare — la règle Vault reste donc ACTIVE, et la matrice ATT&CK a continué
// d'annoncer `T1552` COUVERTE. Le témoin du semis ne pouvait pas le voir : il part d'une base à blanc, où
// `migrate_v50` s'auto-saute (le marqueur est absent quand migrate() précède les semeurs).
//
// CE QU'ON N'A PAS FAIT, ET POURQUOI — C'EST LE POINT QUI COMPTE. Le geste « évident » était une migration
// qui ÉTEINT la ligne vivante, sur le patron de `migrate_v102` (qui a éteint rétroactivement un doublon
// 5xx). IL A ÉTÉ ÉCARTÉ SUR MESURE, parce que la base NE SAIT PAS distinguer les deux populations qu'il
// écraserait ensemble :
//   * `rule.managed` ne tranche pas. `set_content_enabled_tx` (`handlers/detection.rs`) — l'interrupteur de
//     la ligne, la voie par laquelle un exploitant ACTIVE une détection — flippe `enabled` et n'écrit
//     AUCUNE marque sur un `managed=0` (c'est écrit dans son propre bandeau : « managed=0/2 : flippe
//     simplement `enabled` »). Seul le PATCH de formulaire adopte en `managed=2`, et personne n'édite un
//     formulaire pour cocher une case déjà cochée ;
//   * il n'y a de toute façon RIEN à marquer : la règle est livrée ALLUMÉE. L'exploitant qui la VEUT
//     allumée — parce qu'il a déposé l'entrée scriptée `vault-audit` dans `/etc/plume/inputs.d/` — n'a
//     AUCUN geste à faire. Sa volonté est, par construction, indistinguable du réglage d'usine ;
//   * l'audit ne rattrape pas ce silence : il n'enregistre que des gestes, et il n'y en a pas eu.
// Éteindre aurait donc coupé, en silence, la SEULE règle qui tague `T1552` chez l'exploitant qui l'avait
// câblée — un défaut pire que celui qu'on corrige, et de la même famille (décider à la place de quelqu'un
// sans pouvoir le dire). `migrate_v102` pouvait se le permettre : sa cible était un DOUBLON, une autre
// règle active tenait déjà la technique.
//
// CE QU'ON FAIT À LA PLACE : ON NE TOUCHE À L'ACTIVATION DE PERSONNE, ET C'EST LA **COUVERTURE** QUI DEVIENT
// HONNÊTE À LA LECTURE. C'est la seconde branche de l'attendu de la clé (« soit livrée INACTIVE, soit
// comptée à part dans la couverture »), et elle tient sur les DEUX populations à la fois — base neuve et
// base déployée — là où le verrou de semis n'en tenait qu'une.
//
// ET LE CRITÈRE DE LECTURE EST STRICTEMENT PLUS LARGE QUE CELUI DU SEMIS, DÉLIBÉRÉMENT : au semis, une base
// vierge n'a rien observé, et les deux seules dérivations disponibles sont « un fichier livré l'émet » et
// « une sonde livrée l'observe ». À la LECTURE, une troisième existe et elle est la plus forte des trois —
// **cette base a REÇU des événements de cette source**. Une source qui a rempli la table PRODUIT, quel que
// soit ce qui l'émet : entrée scriptée, connecteur d'un tiers, agent maison. L'exploitant qui a branché son
// audit Vault voit donc sa couverture comptée, sans avoir rien à déclarer. L'écart entre les deux critères
// n'est pas une incohérence : c'est ce que chacun des deux moments peut honnêtement savoir.
//
// CE QUE CETTE LECTURE NE TIENT PAS, ÉCRIT PLUTÔT QU'AFFIRMÉ FERMÉ :
//   * l'observation est lue dans `event_rollup` (la table pré-agrégée, jamais un scan d'`event` — c'est la
//     même borne que l'inventaire des sources), par `soql_known_sources`, qui est BORNÉ À 500 sources : une
//     base qui en porterait davantage pourrait laisser une source hors de la liste, et la règle qui
//     l'épingle cesserait alors d'être comptée. Le sens de l'erreur est celui qu'on choisit — on sous-compte
//     la couverture, on ne la sur-compte jamais ;
//   * `event_rollup` est purgé avec la rétention : une source qui n'a plus rien livré depuis la fenêtre de
//     rétention cesse de compter. C'est voulu — « couvert » veut dire « quelque chose arrive », pas
//     « quelque chose est arrivé une fois en 2024 » ;
//   * rien n'est éteint, rien n'est supprimé : `rule.enabled` est lu, jamais écrit par ce chemin. La règle
//     reste dans la console, active, éditable, et l'exploitant garde la main.

/// L'ÉNONCÉ DES RÈGLES QUI COMPTENT POUR LA COUVERTURE, ÉCRIT UNE SEULE FOIS. `mitre` seul ne suffit plus :
/// il faut la REQUÊTE pour savoir si la règle peut tirer. `COALESCE` défensif — une base d'avant le DEFAULT
/// de la colonne rendrait NULL, et une règle perdue par une erreur de décodage serait une couverture
/// silencieusement RETIRÉE.
pub(crate) const ENONCE_TAGS_ACTIFS: &str =
    "SELECT mitre, COALESCE(query,'') FROM rule WHERE enabled=1 AND mitre IS NOT NULL AND mitre<>''";

/// UN PRODUCTEUR EXISTE-T-IL POUR CETTE SOURCE, SUR CETTE BASE ? Les deux dérivations du semis, plus celle
/// que seule une base en service peut fournir : elle a REÇU des événements de cette source.
pub(crate) fn producteur_present(source: &str, sources_observees: &[String]) -> bool {
    producteur_livre(source) || sources_observees.iter().any(|s| s == source)
}

/// LES SOURCES QU'UNE RÈGLE EXIGE ET QUE **RIEN NE FOURNIT SUR CETTE BASE** — LA RAISON, PAS UN BOOLÉEN.
/// Vide = la règle peut tirer (aucun épinglage, épinglage non décidable, ou au moins une branche de la
/// disjonction nourrie) : on n'accuse jamais sur ce qu'on ne sait pas résoudre.
///
/// C'EST LE MÊME PRÉDICAT QUE `sources_sans_producteur_livre`, ÉLARGI À LA TROISIÈME DÉRIVATION (les
/// sources OBSERVÉES sur cette base). Les deux vivent côte à côte parce qu'ils répondent à deux moments :
/// le SEMIS ne sait rien de ce qui a été reçu, la LECTURE le sait.
pub(crate) fn sources_manquantes(query: &str, sources_observees: &[String]) -> Vec<String> {
    match sources_exigees(query) {
        SourcesExigees::Aucune | SourcesExigees::NonDecidable => Vec::new(),
        SourcesExigees::Litterales(v) => {
            if v.iter().any(|s| producteur_present(s, sources_observees)) {
                Vec::new()
            } else {
                v
            }
        }
    }
}

/// CE QU'UNE LECTURE DES RÈGLES ACTIVÉES REND — **TROIS ÉTATS, PAS DEUX**, ET C'EST TOUT L'OBJET.
///
/// LE DÉFAUT QUE CETTE FORME FERME, ET IL A ÉTÉ INTRODUIT PAR LA CORRECTION PRÉCÉDENTE. Le premier
/// remède rendait la seule liste `tirent` : une technique dont l'UNIQUE règle est activée mais que rien
/// ne nourrit retombait alors, à la lecture, dans le seau de « personne n'a jamais écrit de règle ». La
/// console y répondait « ANGLE MORT : aucune règle activée ne couvre cette technique », rendait INERTE
/// la sortie vers la règle — qui EXISTE — et mettait en avant « créer la règle ». Un mensonge en
/// remplaçait un autre, et il prescrivait le mauvais geste : une SECONDE règle qui n'épingle rien
/// re-annoncerait la technique COUVERTE sans que rien ne tire davantage.
///
/// LA RAISON ÉTAIT DÉJÀ CALCULÉE — `sources_manquantes` la rend là où le filtre décide — et elle était
/// JETÉE. Elle voyage désormais jusqu'à l'écran, parce qu'elle est ACTIONNABLE : brancher le producteur
/// suffit. C'est mot pour mot la seconde branche de l'attendu de `P9.5-a` (« comptée à part dans la
/// couverture AVEC SA RAISON »), que la première correction n'avait tenue qu'à moitié.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct LectureDeCouverture {
    /// Les tags MITRE des règles activées qui PEUVENT tirer. Ce sont les SEULES qui couvrent.
    pub(crate) tirent: Vec<String>,
    /// Les règles activées qu'AUCUN producteur ne nourrit : leur tag MITRE, et LES SOURCES QUI MANQUENT.
    /// Ni couvertes (rien ne peut les déclencher), ni absentes (la règle existe et reste éditable).
    pub(crate) en_attente_de_source: Vec<(String, Vec<String>)>,
}

/// LA LECTURE DES RÈGLES ACTIVÉES — **LE POINT UNIQUE**. Toute surface qui annonce une technique
/// couverte passe par ici ; la garde `aucune_surface_de_couverture_ne_lit_les_regles_actives_directement`
/// DÉRIVE de ce fichier l'ensemble des portes admises (celles qui lisent `ENONCE_TAGS_ACTIFS`, et leurs
/// projections dans ce module) et refuse qu'une seconde lecture des règles activées apparaisse ailleurs,
/// parce que c'est exactement ainsi que la première a survécu.
///
/// UNE LECTURE ÉCHOUÉE REND LES DEUX LISTES VIDES, et le sens est le bon dans les deux : une base
/// illisible ne prouve aucune surveillance (rien n'est annoncé couvert), et elle n'établit non plus
/// aucune RAISON (on n'accuse pas une règle sur une lecture qui n'a pas eu lieu).
pub(crate) fn lire_la_couverture_des_regles_activees(conn: &Connection) -> LectureDeCouverture {
    let observees = crate::handlers::soql_meta::soql_known_sources(conn);
    let Ok(mut stmt) = conn.prepare(ENONCE_TAGS_ACTIFS) else { return LectureDeCouverture::default() };
    let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) else {
        return LectureDeCouverture::default();
    };
    let mut lecture = LectureDeCouverture::default();
    for (mitre, query) in rows.flatten() {
        let manquantes = sources_manquantes(&query, &observees);
        if manquantes.is_empty() {
            lecture.tirent.push(mitre);
        } else {
            lecture.en_attente_de_source.push((mitre, manquantes));
        }
    }
    lecture
}

