//! `P11.18-i` — CE QU'UN INSTANTANÉ DE CONTRÔLES DE DÉFENSE DIT, ET CE QUE L'ALERTE EN REND.
//!
//! LE DÉFAUT MESURÉ (2026-08-25, sur l'arbre livré). L'alerte livrée `control.catalog` annonçait un
//! NOMBRE et rien d'autre — « n contrôle(s) de défense MANQUANT(S) ». Ni lesquels, ni sur quelle
//! machine, ni depuis quand. C'est la première chose qu'un exploitant cherche, et le capteur qui
//! alimente cette alerte AVERTIT LUI-MÊME, dans son en-tête, de ce que devient une alerte qu'on ne
//! peut pas ouvrir utilement : « l'exploitant finit par ne plus l'ouvrir, et le jour où c'est vrai il
//! ne le lira pas ».
//!
//! LES TROIS RÉPONSES ÉTAIENT DÉJÀ DANS LA BASE au moment où la phrase s'écrivait. Rien n'est collecté
//! de plus ici ; ce module RELIT ce que le démon tenait déjà :
//!   * LESQUELS — `alert.detail` porte la charge ENTIÈRE du capteur (`{"failed":n,"controls":[…]}`),
//!     recopiée à la levée. Elle est servie par `/api/alerts`, exportée en CSV… et rendue par AUCUNE
//!     surface : la file d'alertes ne lit `detail` que pour y chercher une adresse.
//!   * LA MACHINE — `alert.host` est LIÉ par l'INSERT depuis le cloisonnement de la voie snapshot
//!     (`SnapshotSeries`, `ingest/store.rs`). La requête de liste ne le SÉLECTIONNE pas.
//!   * DEPUIS QUAND — `snapshot` garde UNE LIGNE PAR ÉTAT : le heartbeat n'avance le `ts` que de la
//!     dernière, les lignes des états précédents gardent le leur, et aucune rétention ne les efface.
//!     Le dernier instant où cette machine a été dans un état DIFFÉRENT est donc lisible ; personne ne
//!     le lisait.
//!
//! LE CATALOGUE VIDE SE DIT — c'est l'invariant, pas une amélioration. Un catalogue sans aucun contrôle
//! ne rend pas une posture verte : il ne mesure RIEN, et un `0 manquant` est alors la valeur la plus
//! rassurante de la série. La propriété est DÉRIVÉE de la charge (« zéro contrôle évalué »), jamais de
//! la RAISON — aucun outil présent sur l'hôte, catalogue retiré, contrôles tous désactivés : les trois
//! se disent de la même façon, et un mécanisme d'administration écrit demain y tombe par construction.
//!
//! LA CHARGE PEUT AUSSI ÊTRE ILLISIBLE, ET C'EST UN TROISIÈME CAS, PAS LE VIDE. `POST /api/ingest`
//! accepte n'importe quel `kind` : une charge `controls` sans liste `controls` n'est pas un catalogue
//! vide, c'est une charge dont le démon ne peut RIEN dire. Confondre les deux ferait AFFIRMER « aucun
//! contrôle n'est évalué » là où la seule chose établie est que l'émetteur n'a pas décrit ce qu'il a
//! évalué. Les trois cas sont donc séparés par le TYPE, jamais par un compte.

use crate::*;

/// Au plus N identifiants nommés dans un énoncé, le reste compté. Un titre est lu dans une ligne de
/// file d'alertes : au-delà, il cesse d'informer et se met à masquer les alertes voisines.
const NOMMES_AU_PLUS: usize = 6;

/// LE CATALOGUE TEL QUE LA CHARGE LE DÉCLARE. `declare` sépare « l'émetteur a décrit ce qu'il a évalué »
/// (liste présente, même vide) de « il ne l'a pas fait » — sans quoi une charge muette se lirait comme
/// un catalogue vide, c'est-à-dire comme une affirmation que personne n'a faite.
pub(crate) struct EtatDuCatalogue {
    /// La charge porte une liste `controls` (tableau JSON), fût-elle vide.
    pub(crate) declare: bool,
    /// Nombre de contrôles décrits, tous verdicts confondus.
    pub(crate) attendus: usize,
    /// Les identifiants dont le verdict est `false` — TENUS pour manquants par le capteur.
    pub(crate) manquants: Vec<String>,
    /// Les identifiants dont le verdict est `null` : NI tenus, NI manquants (cf. l'en-tête de
    /// `collectors/controls.sh`). Ils ne comptent pas dans `failed`, donc le compte publié est un
    /// MINORANT tant qu'il y en a — et l'énoncé le dit plutôt que de laisser croire à un compte exact.
    pub(crate) indetermines: Vec<String>,
}

impl EtatDuCatalogue {
    /// VRAI seulement quand l'émetteur a DÉCLARÉ une liste et qu'elle est vide. Une charge sans liste
    /// rend `false` : le démon ne peut pas affirmer un vide qu'il n'a pas lu.
    pub(crate) fn declare_vide(&self) -> bool {
        self.declare && self.attendus == 0
    }
}

/// Lit le catalogue d'une charge d'instantané `kind=controls`. Fonction PURE (aucun accès base) : elle
/// s'exerce sur une charge fabriquée, y compris les charges qu'un émetteur tiers pourrait poster.
pub(crate) fn lire_le_catalogue(data: &Value) -> EtatDuCatalogue {
    let Some(liste) = data.get("controls").and_then(|c| c.as_array()) else {
        return EtatDuCatalogue { declare: false, attendus: 0, manquants: Vec::new(), indetermines: Vec::new() };
    };
    let mut manquants = Vec::new();
    let mut indetermines = Vec::new();
    for c in liste {
        let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("").trim();
        // Un identifiant vide n'est pas nommable ; il reste COMPTÉ dans `attendus` (il a été évalué)
        // mais ne peut pas être cité. L'écart entre le compte et les noms est dit par l'énoncé.
        match c.get("ok") {
            Some(Value::Bool(false)) if !id.is_empty() => manquants.push(id.to_string()),
            // `ok:null` ET `ok` absent : dans les deux cas le capteur n'a pas rendu de verdict.
            Some(Value::Bool(true)) => {}
            _ if !id.is_empty() => indetermines.push(id.to_string()),
            _ => {}
        }
    }
    EtatDuCatalogue { declare: true, attendus: liste.len(), manquants, indetermines }
}

/// DEPUIS QUAND CET ÉTAT DURE — le `ts` du dernier instantané de CETTE SÉRIE `(controls, host)` dont
/// l'empreinte DIFFÈRE de celle qui vient d'être écrite.
///
/// POURQUOI CETTE LECTURE EST EXACTE, ET CE QU'ELLE NE PROMET PAS. La voie snapshot n'écrit une ligne
/// que lorsque l'empreinte CHANGE ; tant qu'elle ne change pas, elle avance le `ts` de la dernière
/// ligne (heartbeat). L'instant d'apparition de l'état COURANT n'est donc pas conservé — mais le
/// dernier instant où la machine était dans un AUTRE état l'est, et il BORNE l'état courant par en
/// haut : il a commencé après. C'est ce que l'énoncé dit, mot pour mot, plutôt que de promettre une
/// date d'apparition que la table ne porte pas.
///
/// `host IS ?` (et non `=`) : la série sans hôte se sélectionne elle-même (SQLite traite `IS` comme
/// `IS NOT DISTINCT FROM`), exactement comme les deux opérations de `SnapshotSeries`.
/// À appeler APRÈS l'écriture de l'instantané courant : la ligne courante est alors exclue par son
/// empreinte, et non par un `ts` qu'il faudrait connaître.
///
/// CE QUE ÇA COÛTE, DIT PLUTÔT QUE SUPPOSÉ. La lecture parcourt les lignes `kind='controls'`
/// (`idx_snapshot(kind,ts)`), dont le nombre est celui des CHANGEMENTS D'ÉTAT jamais observés sur le
/// parc — pas celui des rapports : un état stable ne crée aucune ligne (heartbeat). Elle n'est faite
/// qu'au moment où une alerte de manque est écrite, c'est-à-dire au plus une fois par machine et par
/// rapport, dans la transaction d'ingestion qui vient déjà d'écrire cet instantané.
pub(crate) fn dernier_etat_different(conn: &Connection, host: Option<&str>, hash: &str) -> Option<i64> {
    conn.query_row(
        "SELECT MAX(ts) FROM snapshot WHERE kind='controls' AND host IS ?1 AND COALESCE(hash,'')<>?2",
        params![host, hash],
        |r| r.get::<_, Option<i64>>(0),
    )
    .ok()
    .flatten()
}

/// Le JOUR UTC d'un instant, rendu par SQLite. Aucune dépendance de calendrier n'entre dans l'arbre, et
/// aucun second calcul de date n'y est écrit : le seul autre du dépôt (`cold_store::paths`) vit derrière
/// une feature et n'est pas compilé par défaut — le recopier ici en ferait deux à tenir d'accord.
pub(crate) fn jour_utc(conn: &Connection, ts: i64) -> Option<String> {
    conn.query_row("SELECT date(?1,'unixepoch')", params![ts], |r| r.get::<_, Option<String>>(0))
        .ok()
        .flatten()
}

/// Les identifiants, bornés : au plus `NOMMES_AU_PLUS`, le reste COMPTÉ. Un « (+3) » dit qu'il en manque
/// trois ; une liste tronquée en silence dirait qu'il n'y en a pas d'autres.
fn liste_bornee(ids: &[String]) -> String {
    let nommes: Vec<&str> = ids.iter().take(NOMMES_AU_PLUS).map(String::as_str).collect();
    let reste = ids.len() - nommes.len();
    if reste == 0 {
        nommes.join(", ")
    } else {
        format!("{} (+{reste})", nommes.join(", "))
    }
}

/// SUR QUELLE MACHINE. Un hôte absent n'est pas escamoté : la série `(kind, NULL)` est une DÉCLARATION
/// de l'émetteur (« ceci décrit le déploiement, pas une machine »), et l'énoncé la rend telle quelle.
fn sur_la_machine(host: Option<&str>) -> String {
    match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => format!(" sur {h}"),
        None => " (hôte NON DÉCLARÉ par l'émetteur)".to_string(),
    }
}

/// L'ÉNONCÉ DE L'ALERTE `control.catalog` : combien, LESQUELS, SUR QUELLE MACHINE, DEPUIS QUAND.
///
/// `failed` est le compte que le CAPTEUR publie — c'est lui qui décide de la levée, et il n'est pas
/// recalculé ici. `etat` est ce que la charge permet de NOMMER. Les deux peuvent diverger (charge
/// tierce, identifiant vide, liste absente) : l'écart est DIT, parce qu'une liste plus courte que le
/// compte se lirait comme la liste complète.
pub(crate) fn enonce_des_manquants(
    etat: &EtatDuCatalogue, failed: i64, host: Option<&str>, depuis: Option<&str>,
) -> String {
    let mut s = format!("{failed} contrôle(s) de défense MANQUANT(S){}", sur_la_machine(host));
    if !etat.manquants.is_empty() {
        s.push_str(&format!(" : {}", liste_bornee(&etat.manquants)));
    }
    let nommables = etat.manquants.len() as i64;
    if nommables != failed {
        s.push_str(&format!(
            " — CHARGE INCOHÉRENTE : {failed} annoncé(s), {nommables} nommable(s) dans la liste"
        ));
    }
    match depuis {
        Some(j) => s.push_str(&format!(" — même état depuis au moins le {j}")),
        None => s.push_str(" — aucun état DIFFÉRENT n'a jamais été relevé pour cette machine"),
    }
    if !etat.indetermines.is_empty() {
        s.push_str(&format!(
            " ; {} contrôle(s) NON ÉTABLI(S) — le compte est un MINORANT",
            etat.indetermines.len()
        ));
    }
    s
}

/// L'ÉNONCÉ DE L'ALERTE `control.catalog.vide`. Elle existe pour que le zéro cesse d'être ambigu : sans
/// elle, « 0 manquant » se lit de la même façon qu'une machine tenue et qu'une machine où rien n'est
/// mesuré.
pub(crate) fn enonce_du_catalogue_vide(host: Option<&str>) -> String {
    format!(
        "AUCUN contrôle de défense n'est évalué{} : le catalogue attendu est VIDE — « 0 manquant » ne \
         veut pas dire « tenu », il ne mesure RIEN",
        sur_la_machine(host)
    )
}
