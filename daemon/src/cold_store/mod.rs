//! cold_store — TIER FROID PARQUET (#18) : WRITER colonnaire + branche d'AGING (hot SQLite -> Parquet) + LECTEUR
//! hot∪cold masqué. FAÇADE du module : ce fichier ne porte QUE les constantes partagées, la garde compile-time du
//! verrouillage scrypt, les déclarations de sous-modules et les RE-EXPORTS de la surface `pub(crate)`.
//!
//! OPT-IN de bout en bout : GATE DE COMPILATION `#[cfg(feature = "cold_tier")]` (sans la feature ce module n'existe
//! PAS -> build/mode 0 byte-identiques) PLUS un GATE RUNTIME `PLUME_COLD_TIER` (sans le flag, `cold_age_run`
//! retourne immédiatement -> `retention_run` se comporte EXACTEMENT comme aujourd'hui, aucun Parquet, aucune
//! suppression cold). RACINE COLD PAR-TENANT (FIX #2) et BORNE D'IDENTITÉ du DELETE (FIX #1) : cf. `paths` / `seal`.
//!
//! CARTE DES SOUS-MODULES (chacun porte l'invariant qu'il possède, en tête de fichier) :
//!   - `crypto`   : chiffrement at-rest (HKDF domaine séparé + writer/reader age STREAM).
//!   - `schema`   : `ColdRow` + schéma Parquet colonnaire + helpers d'écriture de colonnes.
//!   - `identity` : liaison d'identité (env_id, jour, seq) dans le footer AEAD + VERIFY décodage-intégral.
//!   - `paths`    : dérivation de chemins on-disk + racine cold par-tenant.
//!   - `seal`     : index `cold_seal` par-fichier (crash-safety, élagage sans déchiffrement).
//!   - `writer`   : writer streamé par-fichier + PHASE 1 (écriture/scellement) de l'aging.
//!   - `aging`    : machine DEUX PHASES (tail guard H1, immutabilité/reparse H2, crash-safety) + math de rétention.
//!   - `reader`   : P2b hydrate (primitive interne) + P3 union hot∪cold MASQUÉE (câblage requête).
//!   - `backup`   : planificateur d'escrow incrémental (2-tier) des jours-files scellés.

// `use crate::*` — la surface crate (Connection, params, EventRow, cfg, store, …). Les SOUS-MODULES la consomment
// via `use super::*` (source unique), tout comme le module enfant `tests`. `Display` sert `pe` ci-dessous.
use crate::*;
use std::fmt::Display;

// SURFACE TESTS-ONLY : le module enfant `tests` (via `use super::*`) référence directement `File`/`Path`/`PathBuf`
// et exige le trait `FileReader` EN SCOPE pour `reader.metadata()`. Les sous-modules de PRODUCTION portent leurs
// PROPRES imports parquet/std -> ce petit bloc, réservé aux tests, est `#[cfg(test)]` (jamais compilé en prod).
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use parquet::file::reader::FileReader;

// #18 — L'INVARIANT DE CORRECTION du tier froid : « aucune valeur dérivée d'un ensemble tronqué ne doit
// JAMAIS être rendue comme un nombre », porté par des TYPES (le `Value` d'un ensemble tronqué est
// séquestré ; la forme d'une réponse ne se déclare pas, elle se DÉRIVE). Cf. l'en-tête du fichier.
mod exactness;
mod crypto;
mod schema;
mod identity;
mod paths;
mod seal;
mod writer;
mod aging;
mod reader;
// #18 P2 — moteur de requête VECTORISÉ (kernels sur ColumnBatch). Pas encore câblé au routeur live (P4) ->
// ses items sont exercés par le harnais de PARITÉ + le BENCH (module `tests`, cfg(test)). `allow(dead_code)`
// délibéré : la surface pub(super) est consommée par P4 (câblage) et par les tests ; sans P4 le build
// `--features cold_tier` la verrait inutilisée (mode 0 / sans feature : le module n'existe pas -> byte-identique).
#[allow(dead_code)]
mod vectorized;
// #18 P4a — PLANNER / ROUTEUR : premier CÂBLAGE RUNTIME du moteur vectorisé. Décide, pour une requête
// pur-froid ET vectorisable, de la router vers les kernels (vitesse) ; tout le reste -> chemin actuel
// (`cold_union_query`) INCHANGÉ. Consomme la surface `pub(super)` de `vectorized` + les primitives de
// sélection de fichiers de `reader`/`seal`/`paths`/`crypto`. Le résultat routé == résultat actuel (invariant).
mod planner;
mod backup;

// Re-glob PRIVÉ de chaque sous-module -> tous les items intra-cold_store (`pub(super)`/`pub(crate)`) sont visibles
// par les SIBLINGS (via `use super::*`) et par le module `tests` (enfant), reproduisant EXACTEMENT la portée « tout
// visible dans cold_store » d'avant le split. N'ÉLARGIT rien hors de la crate (import privé, non ré-exporté).
use crypto::*;
use schema::*;
use identity::*;
use paths::*;
use seal::*;
use writer::*;
use aging::*;
// `reader` et `backup` ne sont référencés par AUCUN sibling en build de production (leaf-consumers) : leur seule
// surface non-façade (hydrate_cold, PARQUET_COLS, …) est consommée par le module `tests` -> glob gaté `#[cfg(test)]`
// (backup n'expose que `cold_backup_plan`, déjà dans la façade -> pas de glob du tout).
#[cfg(test)]
use reader::*;
// #18 P2 — les kernels vectorisés + la surface ColumnBatch/decode_batch sont exercés par le harnais de PARITÉ
// et le BENCH du module `tests` -> glob gaté `#[cfg(test)]`.
#[cfg(test)]
use vectorized::*;

// FAÇADE `pub(crate)` — surface consommée par les AUTRES modules du daemon (rollups, handlers, query_exec, main)
// via `crate::cold_store::X`. Re-exporte EXACTEMENT les symboles que les call-sites importent (grep), rien de plus.
pub(crate) use aging::{cold_age_run, cold_retention_days, reparse_lower_bound};
pub(crate) use paths::cold_root;
pub(crate) use backup::cold_backup_plan;
pub(crate) use reader::{cold_query_boundary, cold_tier_runtime_on, cold_union_query};
// #18 — l'invariant de correction, consommé par les handlers : ils reçoivent une `ColdAnswer` (jamais un
// `Value` nu) et DOIVENT la `render(AnswerShape)`. `AnswerShape` n'a pas de constructeur littéral -> un
// handler ne peut pas affirmer que sa requête ne dérive rien, il ne peut que le faire dériver.
pub(crate) use exactness::{AnswerShape, ColdAnswer, Rendered, TruncatedAggregate};
// #18 P4a — surface du routeur consommée par le handler /api/query (câblage runtime) + le harnais de parité.
pub(crate) use planner::{cold_keyset_page, cold_vectorized_armed, cold_vectorized_merge_try, cold_vectorized_try, prune_counters, route_counters, route_counters_reset};
#[cfg(test)]
pub(crate) use planner::{decode_gauge, decode_gauge_reset};
// #28 PHASE B — élagage dimensionnel : le type de prédicat + l'extracteur (parse le GXQL en égalités de dims
// universelles). `DimEq` est OPAQUE hors cold_store (champs pub(super)) -> query.rs ne fait que le transporter.
pub(crate) use seal::{extract_cold_dim_preds, DimEq};

/// Lignes par row-group (~256K -> ~32-128 Mio non compressé selon la taille d'event). On chunk le fichier en
/// row-groups de cette taille : chaque groupe matérialise ses colonnes en RAM puis est flushé -> borne la RAM
/// d'ÉCRITURE (jamais tout le fichier d'un coup). Les stats `ts` par groupe restent serrées (fichier trié).
pub(super) const ROW_GROUP_ROWS: usize = 262_144;

/// #18 P2b — PLAFOND DUR de lignes par FICHIER cold (split d'un jour en fichiers bornés en taille). Fixé ÉGAL
/// à `ROW_GROUP_ROWS` -> par défaut 1 fichier == 1 row-group. RATIONALE ~32 Mio : le LECTEUR cold (P2b)
/// déchiffre un fichier ENTIER en RAM (le reader Parquet exige un accès aléatoire au footer, incompatible avec
/// le déchiffrement age SÉQUENTIEL). Borner un fichier à `COLD_FILE_MAX_ROWS` lignes borne donc la RAM de
/// DÉCHIFFREMENT à toute échelle : à ~128 octets/event compressé un fichier plein pèse ~32 Mio sur disque et
/// se déchiffre en un tampon RAM du même ordre — TRÈS en-dessous du budget 2 Gio, QUEL QUE SOIT le volume du
/// jour (un jour énorme = PLUS de fichiers, pas des fichiers plus gros). Réglable/réductible en test/ops via
/// `PLUME_COLD_FILE_MAX_ROWS` (clampé `[1, COLD_FILE_MAX_ROWS]`) pour forcer le split sur de petits volumes.
pub(super) const COLD_FILE_MAX_ROWS: usize = 262_144;

pub(super) const SECS_PER_DAY: i64 = 86_400;

/// Plafond DUR de la rétention étendue du tier cold (#18 P1.5) — MÊME borne haute que la rétention `event`
/// (`RETENTION_FIELDS` : 3650 j) et que la rétention PER-INDEX (`INDEX_RETENTION_CEIL_DAYS`). Le plancher
/// n'est PAS une constante : c'est `retention_days` (voir `cold_retention_days`) — on ne raccourcit JAMAIS
/// le cold sous la rétention globale (garde anti-perte).
pub(super) const COLD_RETENTION_CEIL_DAYS: i64 = 3650;

/// Facteur de travail scrypt du stanza age (log2(N)). La passphrase age est DÉJÀ une clé de 256 bits PLEINE
/// ENTROPIE (sortie HKDF) -> l'étirement scrypt n'ajoute AUCUNE sécurité (rien à brute-forcer). On fixe donc
/// un facteur BAS **ET DÉTERMINISTE** (indépendant de la vitesse machine). Déterminisme = déchiffrabilité
/// cross-machine GARANTIE : le défaut d'age vise ~1 s mesuré sur la machine de CHIFFREMENT, ce qui pourrait
/// dépasser le plafond de déchiffrement d'une machine plus LENTE (`ExcessiveWork`) -> fichier illisible. Fixé
/// -> jamais ce piège, et coût scrypt négligeable (aging = tâche de fond quotidienne + lecture occasionnelle).
pub(super) const COLD_SCRYPT_LOG_N: u8 = 12;
/// Plafond de travail scrypt ACCEPTÉ au déchiffrement (anti-DoS d'un fichier malveillant à log_n énorme).
/// FIXÉ (indépendant de la vitesse machine) et SERRÉ juste au-dessus du facteur d'ÉCRITURE (`COLD_SCRYPT_LOG_N`
/// = 12). On écrit TOUJOURS à 12 (scrypt N=2^12) ; on tolère au déchiffrement jusqu'à 14 (N=2^14 ≈ 16 Mio de
/// RAM scrypt, une petite marge avant DOCUMENTÉE, TRÈS en-dessous du budget 2 Gio du daemon). Modèle « NE PAS
/// FAIRE CONFIANCE AU DISQUE » : un attaquant plantait auparavant un fichier minuscule dont l'en-tête age/scrypt
/// annonçait log_n=22 -> au resume-verify/lecture, scrypt allouait N=2^22 ≈ 4 Gio -> OOM/DoS. age vérifie ce
/// plafond DÈS l'en-tête (`unwrap_stanza` : `if log_n > max_work_factor -> ExcessiveWork`), AVANT toute allocation
/// scrypt -> un tel fichier est REJETÉ instantanément, jamais matérialisé. Nos propres fichiers (log_n=12 <= 14)
/// passent toujours. INVARIANT DE VERROUILLAGE (À NE JAMAIS ROMPRE) : le facteur d'ÉCRITURE et ce plafond
/// DOIVENT évoluer ENSEMBLE — si l'on relève un jour `COLD_SCRYPT_LOG_N`, relever ce plafond D'AUTANT (et pas
/// plus) ; ne JAMAIS laisser de mou entre les deux, chaque unité de mou = un facteur ×4 de RAM qu'un fichier
/// hostile peut forcer.
pub(super) const COLD_SCRYPT_MAX_LOG_N: u8 = 14;
// GARDE COMPILE-TIME — transforme l'« INVARIANT DE VERROUILLAGE (À NE JAMAIS ROMPRE) » ci-dessus d'un simple
// commentaire en ERREUR DE BUILD. Le plafond de déchiffrement DOIT rester >= le facteur d'écriture (sinon nos
// PROPRES fichiers deviennent illisibles : `ExcessiveWork`) ET le mou DOIT rester minuscule (<= 2). Chaque unité
// de mou = un facteur ×4 de RAM scrypt qu'un fichier hostile peut forcer à l'allocation -> toute violation est
// une régression DoS RAM-hostile. Le `&&` court-circuite AVANT la soustraction u8 -> pas d'underflow en const-eval.
const _: () = assert!(
    COLD_SCRYPT_MAX_LOG_N >= COLD_SCRYPT_LOG_N && COLD_SCRYPT_MAX_LOG_N - COLD_SCRYPT_LOG_N <= 2,
    "cold scrypt lockstep rompu: plafond de déchiffrement < facteur d'écriture, ou mou > 2 (chaque unité = ×4 RAM scrypt hostile) — régression DoS"
);

/// Mappe une erreur `parquet`/IO vers texte (les erreurs sont AVALÉES par jour côté aging — cf. la
/// philosophie « swallow & continue » de `retention_run` — mais restent inspectables par les tests).
pub(super) fn pe<E: Display>(e: E) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests;
