//! LA SONDE DE FLOTTE — « QUELLES MACHINES SE SONT TUES », RENDU COMME UN COMPTE ET NON COMME UNE
//! SÉRIE PAR HÔTE. Séparée de `sondes.rs` parce que ce n'en est pas une variante : les sondes de
//! `COLLECTORS` répondent « ce CAPTEUR parle-t-il ? », celle-ci répond « ce PARC parle-t-il ? ».
//! Elles n'observent pas la même chose, elles ne lisent pas la même table, et leur coût n'est pas
//! borné par la même grandeur.
//!
//! ====================================================================================================
//! P3.2-a — LE DÉFAUT, ET POURQUOI LA CORRECTION ÉVIDENTE EST LA MAUVAISE.
//!
//! CE QUI EST CASSÉ. Vingt sondes d'events et une sonde de métriques ont une portée « tous hôtes
//! confondus » (`Portee::FlotteConfondue`, déclarée par le type depuis P3.2-a). Leur requête est un
//! `MAX(ts)` sans filtre d'hôte : elle rend la donnée la plus FRAÎCHE du parc. Un parc dont une seule
//! machine parle encore est donc vu comme sain, quel que soit le nombre de machines mortes. Et les
//! sondes dont le statut suit `pipeline_is_fresh` ne s'en tirent pas mieux : cette fonction est
//! elle-même un `MAX(ts)` sur event∪metric∪snapshot SANS filtre d'hôte. Les 21 masquent.
//!
//! CE QUE L'INTERFACE MONTRAIT DÉJÀ, ET CE QU'ELLE NE FAISAIT PAS. `/api/fleet` classe chaque hôte
//! `fresh`/`stale`/`silent` depuis son dernier signal (`fleet_status`) : un hôte mort y est VISIBLE.
//! Mais rien ne se LÈVE — il faut que quelqu'un ouvre le panneau et compte. Un angle mort qui n'est
//! visible que pour qui le cherche déjà n'est pas couvert : il est documenté.
//!
//! LA CORRECTION ÉVIDENTE, ET POURQUOI ELLE EST REFUSÉE. Repasser les 21 sondes PAR HÔTE multiplie
//! tout par la taille de la flotte, sur deux axes :
//!   - CARDINALITÉ : 21 séries deviennent 21 x H. Pour une flotte de mille machines — l'ordre de
//!     grandeur que `host_rollup` annonce (« centaines/milliers ») — cela fait 21 000 séries à
//!     calculer, à sérialiser dans `/api/integrations` et à garder en cache, sous un budget de 2 Gio.
//!   - COÛT UNITAIRE : la requête par hôte d'une sonde d'event est `MIN` sur les `MAX(ts) GROUP BY
//!     host`. AUCUN index de `event` ne porte `host` derrière `source` : le `GROUP BY` force donc à
//!     lire toutes les lignes de la source, c'est-à-dire à retomber EXACTEMENT dans le O(N) mesuré en
//!     P3.7-a — mais cette fois pour vingt sondes, sous le verrou d'écriture, toutes les 20 s. La
//!     mesure (mutation du volume x4, compteur `SQLITE_STMTSTATUS_VM_STEP`) est dans
//!     `daemon/src/tests/hotes_muets.rs` : la variante par hôte suit le volume, l'actuelle non.
//! Une solution qui ignore ce point n'en est pas une. C'est pourquoi la portée des 21 sondes n'est pas
//! changée ici : elle est DÉCLARÉE (`Sonde::portee`) et rendue lisible, ce qui est un aveu, pas un
//! correctif.
//!
//! LA FORME DÉRIVÉE. La question « une machine s'est-elle tue ? » n'a pas besoin d'être posée vingt
//! fois par machine. Elle se pose UNE fois, sur l'inventaire déjà pré-agrégé `host_rollup` (v77), dont
//! la cardinalité EST la flotte et qui porte déjà `last_ts` = dernier signal de l'hôte, toutes tables
//! confondues. La sonde rend un COMPTE (`muets` sur `attendus`) et les quelques machines les plus en
//! retard ; elle ne rend JAMAIS une série par hôte. Sa cardinalité de sortie est donc CONSTANTE :
//! un verdict, au plus `PLAFOND_NOMS` noms, une alerte. Quelle que soit la taille du parc.
//!
//! LA CARDINALITÉ, DES DEUX CÔTÉS, ET LE PIRE CAS. En SORTIE : un verdict, au plus `PLAFOND_NOMS` noms,
//! une alerte — constant, prouvé en multipliant le parc par 25 sans qu'aucun de ces trois nombres bouge.
//! En ENTRÉE : le balayage est LINÉAIRE en la flotte, mesuré à 28 pas de machine virtuelle par machine
//! (2026-08-20) et strictement indépendant du volume d'events. Le pire cas est donc dit en toutes
//! lettres : pour mille machines, ~28 000 pas toutes les 20 s sous le verrou d'écriture. À comparer aux
//! ~21 000 SÉRIES et au coût O(volume) qu'aurait produits la voie par hôte, pour la même question.
//!
//! LE SEUIL N'EST PAS INVENTÉ ICI. « Muet » veut dire ce que `fleet_status` appelle déjà `silent`
//! (au-delà de `FLEET_STALE_S`), c'est-à-dire exactement ce que le panneau Flotte montre. Un littéral
//! de plus aurait fini par diverger du panneau en silence, et l'alerte aurait accusé des machines que
//! l'exploitant voit vertes.
//!
//! CE QUE ÇA NE COUVRE PAS — écrit pour être opposable :
//!   - un hôte dont UN collecteur est mort pendant que les autres parlent reste invisible : son
//!     `last_ts` est frais. Ce trou est le trou par-source-par-hôte, et il reste ouvert exprès (c'est
//!     la multiplication de cardinalité ci-dessus). Seule sa forme la plus grossière — l'hôte
//!     entièrement muet — est fermée.
//!   - une machine JAMAIS vue n'est pas comptée : l'inventaire est DÉCOUVERT, pas déclaré. Plume n'a
//!     pas de liste des machines attendues, donc « il en manque une » est indémontrable ici.
//!   - une machine DÉCOMMISSIONNÉE reste comptée muette indéfiniment : `host_rollup` n'est jamais
//!     prunée (c'est ce qui rend un agent mort visible, et c'est voulu). Contrairement au résidu de la
//!     sonde d'instantané, celui-ci NE se résorbe PAS tout seul. L'échange est tenu par l'EMPREINTE de
//!     l'ensemble muet (ci-dessous) : l'alerte n'est pas un épisode qui dure, c'est un épisode PAR
//!     ENSEMBLE — une machine décommissionnée laisse une alerte ouverte, mais elle n'empêche pas la
//!     suivante de lever la SIENNE, ce qui est le vrai risque d'un dead-man's-switch collant.
//!   - la valeur lue vient d'un rollup rafraîchi à la cadence de `spawn_rollup_loop` : l'âge rendu
//!     traîne d'au plus cet intervalle. Négligeable devant `FLEET_STALE_S`, mais dit.
//! ====================================================================================================
use crate::*;

/// Combien de machines l'alerte NOMME au plus. Le reste est COMPTÉ, jamais tu : « et 143 autres » dit
/// l'ampleur sans faire enfler la ligne d'alerte (budget 2 Gio, même discipline que `MAX_SOURCES`).
pub(crate) const PLAFOND_NOMS: usize = 5;

/// PRÉFIXE de la clé de déduplication de la famille. Une clé par ENSEMBLE muet (préfixe + empreinte),
/// et un seul épisode ouvert à la fois : cf. `check_heartbeats`.
pub(crate) const DEDUP_FLOTTE_MUETTE: &str = "hb-flotte-muets-";

/// LE VERDICT DE FLOTTE. Cardinalité CONSTANTE par construction : deux entiers, au plus `PLAFOND_NOMS`
/// noms, une empreinte. Rien ici ne grandit avec le parc — c'est l'invariant du chantier.
pub(crate) struct FlotteMuette {
    /// Hôtes connus de l'inventaire (le DÉNOMINATEUR — sans lui, « 19 muets » ne se lit pas).
    pub(crate) attendus: usize,
    /// Hôtes sans AUCUN signal depuis plus de `FLEET_STALE_S`.
    pub(crate) muets: usize,
    /// Les plus en retard d'abord, bornés à `PLAFOND_NOMS` : (hôte, dernier signal).
    pub(crate) pires: Vec<(String, i64)>,
    /// EMPREINTE de l'ENSEMBLE muet (noms ordonnés). Sert de clé d'épisode : tant que l'ensemble ne
    /// bouge pas, c'est le même épisode (zéro répétition) ; dès qu'une machine s'y ajoute ou en sort,
    /// c'est un ÉPISODE NEUF. Sans ça, la première machine décommissionnée garderait l'alerte ouverte
    /// pour toujours et la mort de la deuxième ne réveillerait plus personne.
    pub(crate) empreinte: u64,
}

impl FlotteMuette {
    /// La clé de déduplication de CET ensemble. `None` quand rien n'est muet : il n'y a pas d'épisode.
    pub(crate) fn cle_dedup(&self) -> Option<String> {
        (self.muets > 0).then(|| format!("{DEDUP_FLOTTE_MUETTE}{:016x}", self.empreinte))
    }
}

/// FNV-1a 64 bits, écrit ici en six lignes plutôt qu'emprunté à `DefaultHasher` : ce dernier n'a AUCUNE
/// stabilité garantie entre versions de la bibliothèque standard, or cette empreinte est écrite en base
/// (clé de déduplication) et relue par le binaire suivant. Une empreinte qui change à la recompilation
/// rouvrirait un épisode à chaque mise à jour, sur un parc inchangé.
fn empreinte_fnv1a(octets: &[u8], depart: u64) -> u64 {
    let mut h = depart;
    for o in octets {
        h ^= *o as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// LA SONDE. `None` = LA LECTURE A ÉCHOUÉ (table absente, verrou, ligne illisible) — et c'est
/// DÉLIBÉRÉMENT distinct de « zéro muet » : un `Some(0)` autorise l'appelant à RÉSOUDRE l'alerte
/// ouverte, un `None` le lui interdit. Une surface qui n'a pas pu observer ne doit pas se taire comme
/// si elle avait observé le vide — c'est l'invariant que la dette déclarée de `Sonde::derniere_collecte`
/// n'a pas encore fermé de son côté, et qu'on ne rouvre pas ici.
///
/// COÛT, MESURÉ ET NON SUPPOSÉ : un balayage de `host_rollup`, dont la cardinalité EST la flotte (pas
/// le volume d'events) — la même borne que celle qui a fait exister cette table (v77 : ne jamais
/// scanner `event` par requête au volume). MESURÉ le 2026-08-20 au compteur de pas de machine
/// virtuelle de SQLite : 587 pas pour 20 machines, 14 027 pour 500, soit une pente EXACTE de 28 pas par
/// machine (constante 27). PIRE CAS DIT : pour un parc de mille machines, ~28 000 pas toutes les 20 s
/// sous le verrou d'écriture, contre 16 pas pour une sonde d'event. Et sous mutation du volume d'events
/// (x4), ce coût ne bouge PAS d'un pas — c'est ce qui le distingue de la variante par hôte, qui suit le
/// volume. Mémoire : `PLAFOND_NOMS` noms retenus, jamais la liste (l'ensemble muet ne fait que traverser
/// une empreinte de 64 bits).
pub(crate) fn flotte_muette(conn: &Connection, now_ts: i64) -> Option<FlotteMuette> {
    // ORDER BY host : l'empreinte doit être une fonction de l'ENSEMBLE, pas de l'ordre de restitution.
    // GROUP BY host collapse les environnements (comme `host_inventory_simple`) -> une ligne par machine.
    let mut st = conn
        .prepare("SELECT host, MAX(last_ts) FROM host_rollup WHERE host<>'' GROUP BY host ORDER BY host")
        .ok()?;
    let mut lignes = st.query([]).ok()?;
    let (mut attendus, mut muets) = (0usize, 0usize);
    let mut empreinte = 0xcbf2_9ce4_8422_2325u64; // offset basis FNV-1a
    let mut pires: Vec<(String, i64)> = Vec::with_capacity(PLAFOND_NOMS + 1);
    // `while let Some(row) = ... .ok()?` : une ligne ILLISIBLE interrompt la mesure (None) au lieu de
    // se faire sauter en silence par un `flatten()` — sinon un parc partiellement illisible se
    // présenterait comme un parc partiellement sain.
    while let Some(row) = lignes.next().ok()? {
        let hote: String = row.get(0).ok()?;
        let dernier: i64 = row.get(1).ok()?;
        attendus += 1;
        if fleet_status(now_ts - dernier) != "silent" {
            continue;
        }
        muets += 1;
        empreinte = empreinte_fnv1a(hote.as_bytes(), empreinte);
        empreinte = empreinte_fnv1a(b"\n", empreinte);
        // Les `PLAFOND_NOMS` plus en retard, retenus par insertion : la liste complète n'est jamais
        // matérialisée (c'est la borne mémoire du chantier, sur un parc de plusieurs milliers).
        pires.push((hote, dernier));
        pires.sort_by_key(|(_, t)| *t);
        pires.truncate(PLAFOND_NOMS);
    }
    Some(FlotteMuette { attendus, muets, pires, empreinte })
}

/// LE TEXTE DE L'ALERTE, séparé de sa levée pour être éprouvable sans base : ce qu'un exploitant LIT
/// est ce qui décide s'il agit. Porte le dénominateur, le seuil, les machines (bornées) et le reste
/// COMPTÉ, et DIT sa portée — l'exploitant n'a pas à deviner que celle-ci est par hôte quand les 21
/// autres ne le sont pas.
pub(crate) fn detail_flotte_muette(f: &FlotteMuette, now_ts: i64) -> String {
    let mut d = format!(
        "{} hôte(s) sur {} sans aucun signal depuis plus de {} min (portée : {})",
        f.muets,
        f.attendus,
        FLEET_STALE_S / 60,
        Portee::ParHote.etiquette(),
    );
    if !f.pires.is_empty() {
        let noms: Vec<String> =
            f.pires.iter().map(|(h, t)| format!("{h} ({} min)", (now_ts - t) / 60)).collect();
        d.push_str(&format!(" — machines : {}", noms.join(", ")));
        if f.muets > f.pires.len() {
            d.push_str(&format!(", et {} autre(s)", f.muets - f.pires.len()));
        }
    }
    d
}
