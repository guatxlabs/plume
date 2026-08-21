//! `S36` — INTERROGER UN GESTIONNAIRE DE SERVICES : LE MOT RENDU EST LA MESURE, PAS LE CODE DE RETOUR.
//!
//! LE DÉFAUT QUE CE MODULE FERME, ET POURQUOI IL EST PIRE ICI QU'AILLEURS SUR CETTE SURFACE. Les
//! lecteurs de ce module-là n'alimentent aucun panneau : ils décident d'une ACTION — redémarrer ou
//! non, supprimer ou non, conclure « rien à retirer » avec un code de sortie nul. Chacun rendait un
//! booléen par `unwrap_or(false)`, et l'interrogation de propriétés rendait une TABLE VIDE quand la
//! commande n'avait pas abouti. Or un booléen n'a pas de place pour « je n'ai pas pu regarder » :
//! « pas actif », « pas activé au boot » et « pas en échec » étaient donc les mots que prenait un
//! gestionnaire injoignable, c'est-à-dire les plus rassurants de la série. Une lecture ratée ne
//! produisait pas un angle mort : elle faisait AGIR sur un état supposé.
//!
//! CE QUI SÉPARE LES DEUX CAS — MESURÉ le 2026-08-21 (systemd 261), témoin positif ET négatif :
//!   - unité ABSENTE, gestionnaire joignable : `is-active` sort **4** en disant `inactive`,
//!     `is-enabled` sort **4** en disant `not-found`, `show -p …` sort **0** et imprime TOUTES les
//!     clés demandées (`LoadState=not-found`). Ce sont des MESURES, et elles doivent être lues ;
//!   - gestionnaire INJOIGNABLE : les trois sortent non nul avec une SORTIE STANDARD VIDE et le
//!     motif de l'échec sur l'erreur standard.
//! Le code de retour ne sépare donc PAS « mesuré, pas actif » de « pas mesuré » — le MOT, lui, le
//! fait. C'est la raison d'être de ce module : classer sur le mot, et traiter un mot hors du
//! vocabulaire connu comme `forme_inconnue`, jamais comme un « non » commode.
//!
//! POURQUOI LE VOCABULAIRE EST FERMÉ PLUTÔT QU'INTERPRÉTÉ. Un mot inconnu est le cas qui se perd le
//! plus facilement : sans table, il devient « ce n'est pas `active`, donc le service est arrêté ».
//! Avec la table, il devient un aveu — et le jour où un gestionnaire ajoute un état, cela se voit au
//! lieu de se lire comme un service au repos.
//!
//! PUR, DONC EXERÇABLE SANS AUCUN GESTIONNAIRE DE SERVICES. Ces fonctions ne lancent rien : elles
//! reçoivent ce qu'une commande A RENDU (code, sortie standard, erreur standard) ou l'erreur de
//! lancement. La suite fabrique ces trois valeurs et exerce les deux sens sur les trois OS d'intégration
//! continue, dont deux n'ont pas de systemd — un test qui exigerait un gestionnaire réel ne prouverait
//! rien là où il ne tourne pas, et se dégraderait en silence là où il tourne.
//!
//! LE VOCABULAIRE DE CAUSES EST CELUI DE `crate::lisibilite`, REPRIS ET NON DOUBLÉ : mêmes mots que
//! le démon et que les capteurs (`source_absente`, `source_refusee`, `source_illisible`,
//! `forme_inconnue`), et `cause_io` traduit l'erreur système une seule fois pour tous les sites.

use crate::lisibilite::{cause_io, Lecture, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE};
use std::collections::HashMap;

/// LA COMMANDE N'A PAS PU ÊTRE LANCÉE — l'outil manque, le chemin est refusé, le processus n'a pas
/// démarré. Ce n'est PAS un verdict sur le service : c'est l'absence de verdict, et elle porte le mot
/// du démon (`cause_io`).
pub fn pas_lance<T>(outil: &str, e: &std::io::Error) -> Lecture<T> {
    Lecture::Illisible {
        cause: cause_io(e),
        detail: format!("`{outil}` n'a pas pu être lancé : {e}"),
    }
}

/// Le premier message d'erreur rendu par l'outil, pour l'aveu — jamais pour une clé.
fn trace(stderr: &[u8]) -> String {
    let t = String::from_utf8_lossy(stderr);
    match t.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(l) => l.to_string(),
        None => "aucun message sur l'erreur standard".to_string(),
    }
}

/// LE VERDICT PORTÉ PAR UN MOT, contre un vocabulaire FERMÉ — rend le mot canonique ET ce qu'il vaut.
///
/// TROIS ISSUES, et deux d'entre elles ne concluent RIEN sur le service :
///   - le mot est dans la table            -> `Lue`, la mesure a eu lieu (quel que soit le code de retour) ;
///   - aucun mot n'a été rendu             -> `source_illisible` : la commande a tourné sans répondre ;
///   - un mot hors table a été rendu       -> `forme_inconnue` : elle a répondu, on ne la comprend pas.
///
/// LE CODE DE RETOUR N'ENTRE PAS DANS LA DÉCISION, et c'est mesuré : `is-active` rend **4** sur une
/// unité absente tout en disant `inactive`, ce qui est une réponse parfaitement valable ; il rend
/// **1** avec une sortie vide quand le gestionnaire est injoignable, ce qui n'en est pas une. Le code
/// seul les confond ; il n'est gardé que pour ÉCLAIRER l'aveu.
pub fn verdict_de_mot(
    outil: &str,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    vocabulaire: &[(&'static str, bool)],
) -> Lecture<(&'static str, bool)> {
    let mot = String::from_utf8_lossy(stdout).trim().to_string();
    if mot.is_empty() {
        return Lecture::Illisible {
            cause: CAUSE_SOURCE_ILLISIBLE,
            detail: format!(
                "`{outil}` n'a rendu AUCUN mot (code {code:?}) : {} — l'état du service n'a pas été \
                 établi",
                trace(stderr)
            ),
        };
    }
    match vocabulaire.iter().find(|(m, _)| *m == mot) {
        Some((canonique, valeur)) => Lecture::Lue((canonique, *valeur)),
        None => Lecture::Illisible {
            cause: CAUSE_FORME_INCONNUE,
            detail: format!(
                "`{outil}` a répondu {mot:?} (code {code:?}), hors du vocabulaire connu de cet outil \
                 — un état non prévu ne vaut pas « au repos »"
            ),
        },
    }
}

/// Le verdict SEUL, quand l'appelant n'a que faire du mot canonique.
pub fn oui_non(l: Lecture<(&'static str, bool)>) -> Lecture<bool> {
    match l {
        Lecture::Lue((_, v)) => Lecture::Lue(v),
        Lecture::Illisible { cause, detail } => Lecture::Illisible { cause, detail },
    }
}

/// LES PROPRIÉTÉS D'UNE UNITÉ, LUES OU AVOUÉES — jamais une table vide qui se lirait « rien à
/// signaler ».
///
/// C'EST LE SITE CITÉ PAR LA CAMPAGNE : « l'interrogation en échec -> pas en échec ». L'ancienne
/// forme rendait une table vide sur un échec de lancement ET n'ouvrait jamais le code de retour ;
/// l'appelant lisait alors `ActiveState` absent, en faisait `""`, et son prédicat d'échec — qui
/// cherche `failed` ou `auto-restart` — ne pouvait plus tirer. Le service pouvait donc être en
/// boucle de redémarrage pendant que la mesure, muette, ne trouvait « pas d'échec ».
///
/// UNE CLÉ DEMANDÉE ET ABSENTE EST UNE `forme_inconnue`, pas un vide : c'est ce qui empêche de
/// reconstruire le défaut un cran plus bas. La contrepartie est nommée : un gestionnaire qui ne
/// connaîtrait pas l'une des propriétés demandées fait ÉCHOUER la lecture au lieu de la fausser —
/// c'est la direction voulue, et elle se voit tout de suite.
pub fn proprietes(
    outil: &str,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    attendues: &[&str],
) -> Lecture<HashMap<String, String>> {
    let texte = String::from_utf8_lossy(stdout);
    let mut table = HashMap::new();
    for ligne in texte.lines() {
        if let Some((k, v)) = ligne.split_once('=') {
            table.insert(k.trim().to_string(), v.to_string());
        }
    }
    if table.is_empty() {
        return Lecture::Illisible {
            cause: CAUSE_SOURCE_ILLISIBLE,
            detail: format!(
                "`{outil}` n'a rendu AUCUNE propriété (code {code:?}) : {} — l'état du service n'a \
                 pas été établi",
                trace(stderr)
            ),
        };
    }
    if let Some(manquante) = attendues.iter().find(|k| !table.contains_key(**k)) {
        return Lecture::Illisible {
            cause: CAUSE_FORME_INCONNUE,
            detail: format!(
                "`{outil}` a répondu sans la propriété {manquante:?} (code {code:?}) — une propriété \
                 absente ne vaut pas une valeur vide"
            ),
        };
    }
    Lecture::Lue(table)
}

#[cfg(test)]
mod tests;
