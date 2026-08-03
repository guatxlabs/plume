// plume-daemon : ingère le spool -> SQLite, sert l'API + la PWA, applique basic_auth + anti-rebinding.
// Binaire unique tout-en-un (pas de Caddy). Config via /etc/plume/plume.conf (ou variables d'env).
// CLI : `plume-daemon hashpw '<motdepasse>'` -> imprime un hash bcrypt pour PLUME_PASS_HASH.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::Mutex;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Extension, Json, Router,
};
use base64::Engine;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

// ---- Modules extraits de main.rs (refactor split #25 — réorganisation byte-identique) ----
mod db_open; // LA PORTE : seule détentrice d'une ouverture SQLite nue -> écrire sans le contrat de schéma ne compile pas
pub(crate) use db_open::*;
mod backup;
pub(crate) use backup::*;
mod disk; // garde disque / cardinalité à l'ingest + alerte pré-saturation (#29) — mesure statvfs (unsafe) isolée
pub(crate) use disk::*;
mod util;

mod tmp_possede; // LE COFFRE du répertoire temporaire : seule détentrice d'un accès à $TMPDIR -> une fixture qui ne possède pas son temporaire ne compile pas (build.rs)
pub(crate) use util::*;
mod collected; // INVENTAIRE de ce que les collecteurs/agent LIVRÉS émettent réellement -> ORACLE D'INERTIE (séparé de la table de TRADUCTION Sigma)
mod sigma;
pub(crate) use sigma::*;
mod seeds;
pub(crate) use seeds::*;
mod migrate;
pub(crate) use migrate::*;
mod overlays;
pub(crate) use overlays::*;
mod overlays_oac; // #55 observability-as-code : overlays config.d des OBJETS DE CONFIG (dashboards/notifiers/…)
pub(crate) use overlays_oac::*;
mod parsers;
pub(crate) use parsers::*;
mod processors;
pub(crate) use processors::*;
mod crypto;
pub(crate) use crypto::*;
mod ingest;
pub(crate) use ingest::*;
mod query_exec;
pub(crate) use query_exec::*;
mod query_timing; // LE DÉCOUPAGE DU TEMPS D'UNE REQUÊTE : l'attente d'un permit n'est fabricable QUE par l'acquisition
pub(crate) use query_timing::*;
mod soql_glue;
pub(crate) use soql_glue::*;
mod field_filter; // #45 FIELD FILTERS : registre de masquage par champ (rôle/tenant/env), résolu en FieldMaskSet
mod knowledge; // #46 KNOWLEDGE OBJECTS : registre alias/calc/eventtype/tag, résolu en KnowledgeSet (auto-appliqué au compilo GXQL)
mod datamodels; // #47 DATA MODELS + PIVOT : logique pure (validation objets/champs, chaîne de contraintes, générateur pivot_to_soql -> GXQL, jamais SQL)
pub(crate) use field_filter::*;
pub(crate) use knowledge::*;
pub(crate) use datamodels::*;
mod rollup_coverage; // L'INVARIANT de la route de rollups : ce que le rollup COUVRE ne se déclare pas, il s'établit
pub(crate) use rollup_coverage::*;
mod topn_cap; // Le PLAFOND top-N ne se déclare pas sans son AMPLEUR : `truncated` est un type, plus un booléen
pub(crate) use topn_cap::*;
mod rollup_route;
pub(crate) use rollup_route::*;
mod ledger;
pub(crate) use ledger::*;
mod governance; // #59 GOUVERNANCE ENTREPRISE : legal-hold (rétention-lock fail-closed), export streaming du ledger (chaîne préservée), rôles composables (plafond=base, default-deny)
pub(crate) use governance::*;
mod rollups;
pub(crate) use rollups::*;
// PURGE EXPLICITE D'ÉVÉNEMENTS — la seule suppression de `event` qui ne soit pas la rétention temporelle.
// Déclaré APRÈS `rollups` (il consomme `retention_nonpurge_for`/`rollup_insert_sql_into`) et APRÈS
// `governance` (legal-hold). Les TYPES du pipeline (`PurgeWindow`/`PurgeScope`/`PurgePlan`/`ConfirmedPurge`/
// `PurgeInscribed`) ont des champs PRIVÉS : ce `use` réexporte les NOMS, jamais de quoi les fabriquer
// autrement que par les constructeurs faillibles du module. C'est ce qui rend « purger sans borne / sans
// simuler / sans inscrire au registre » non représentable ailleurs dans la crate.
mod purge;
pub(crate) use purge::*;
// #18 Phase 1 — TIER FROID PARQUET (writer + aging). GATE DE COMPILATION `cold_tier` : sans la feature, ce
// module n'existe PAS -> build/mode 0 byte-identiques (aucune dép `parquet` linkée). Le gate RUNTIME
// `PLUME_COLD_TIER` (dans cold_age_run) le rend en plus inerte tant qu'il n'est pas explicitement activé.
#[cfg(feature = "cold_tier")]
mod cold_store;
mod maintenance;
pub(crate) use maintenance::*;
mod metrics; // #51 DAY-2 OPS : self-métriques process-globales + santé par composant + exposition Prometheus
pub(crate) use metrics::*;
mod handlers;
pub(crate) use handlers::system::*; // #51 DAY-2 OPS : healthz/readyz/metrics + system metrics/health/diag + bulletin
pub(crate) use handlers::field_filters::*;
pub(crate) use handlers::knowledge::*; // #46 CRUD knowledge objects (alias/calc/eventtype/tag)
pub(crate) use handlers::datamodels::*; // #47 CRUD data models + Pivot + datasets
pub(crate) use handlers::scheduled_reports::*; // #60 rapports planifiés (dataset -> notifier, masqués par run_as)
pub(crate) use handlers::workflow_actions::*; // #60 workflow actions (navigation + réponse enum-only)
pub(crate) use handlers::playbooks::*;
pub(crate) use handlers::prefs::*; // #62 préférences utilisateur self-scoped (GET/PUT /api/prefs)
pub(crate) use handlers::saved_queries::*; // requêtes GXQL nommées per-user, owner-scoped (CRUD /api/saved-queries)
pub(crate) use handlers::processors::*;
pub(crate) use handlers::admin_ui::*;
pub(crate) use handlers::engagement::*;
pub(crate) use handlers::actions::*;
pub(crate) use handlers::notifiers::*;
pub(crate) use handlers::alerting::*;
pub(crate) use handlers::freshness::*;
pub(crate) use handlers::governance::*; // #59 gouvernance : legal-hold + export ledger + sinks + rôles composables
pub(crate) use handlers::purge::*; // purge explicite d'événements (routes plan/apply, gate PLUME_PURGE_API)
pub(crate) use handlers::fleet::*;
pub(crate) use handlers::idp::*;
#[cfg(feature = "ai")]
pub(crate) use handlers::ai::*; // #16 couche IA conseil (NL→GXQL) — feature `ai` OFF par défaut -> module ENTIÈREMENT exclu à la compilation
pub(crate) use handlers::index_policies::*; // #49 indexes logiques nommés (rétention/plafonds par index)
pub(crate) use handlers::detection::*;
pub(crate) use handlers::detection_advanced::*;
pub(crate) use handlers::users_lookups::*;
pub(crate) use handlers::tokens::*;
pub(crate) use handlers::dash_ergonomics::*; // #54 library panels / playlists / dashboard snapshots
pub(crate) use handlers::dashboards::*;
pub(crate) use handlers::connectors::*;
pub(crate) use handlers::destinations::*; // #50 outputs/destinations (forward vers sink externe)
pub(crate) use handlers::threat_intel::*;
pub(crate) use handlers::rba::*;
pub(crate) use handlers::query::*;
pub(crate) use handlers::soql_meta::*; // complétion IDE (schema/templates de la barre Explore)
pub(crate) use handlers::search::*; // handler /api/search (extrait de main.rs, refactor split #25)
pub(crate) use handlers::datasource::*; // #52 plume-as-a-datasource (GXQL-HTTP + Prometheus read + Loki stub)
pub(crate) use handlers::cases::*;
pub(crate) use handlers::caseops::*; // #39 team case-ops
pub(crate) use handlers::incidents::*; // #3 incidents Phase 1 : élévation + runbooks + wizard de steps
pub(crate) use handlers::compliance::*; // #38 mapping de conformité (rollup posture + rapport + normalisation des tags)
pub(crate) use handlers::alerts::*;
pub(crate) use handlers::overview::*;
mod state;
pub(crate) use state::*;
mod auth;
pub(crate) use auth::*;
mod session;
pub(crate) use session::*;
mod rbac;
pub(crate) use rbac::*;
mod scim; // #59 SCIM 2.0 : provisioning/deprovisioning IdP (bearer scim_token, control-plane), mode 1 only
pub(crate) use scim::*;
mod idp;
pub(crate) use idp::*;
#[cfg(feature = "ai")]
mod ai; // #16 couche IA CONSEIL (advisory) : provider HTTP (feature `ai`) + garde cloud/budget ; NL→GXQL. Exclu du build DÉFAUT.
mod tenants;
pub(crate) use tenants::*;
mod server;
pub(crate) use server::*;



fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// CONC-3 — garde RAII de transaction sur l'écrivain PROCESS-GLOBAL. `Txn::begin` exécute `BEGIN IMMEDIATE` ;
/// le `Drop` exécute `ROLLBACK` SAUF si `.commit()` a été appelé. parking_lot ne POISONNE pas un mutex sur
/// panic, et CatchPanicLayer transforme un panic de handler en 500 : sans ce garde, un panic entre `BEGIN` et
/// le terminateur (COMMIT/ROLLBACK) laisserait la connexion partagée BLOQUÉE dans une transaction ouverte ->
/// TOUTES les écritures suivantes échoueraient (« cannot start a transaction within a transaction »). Le garde
/// existe AVANT le corps faillible -> un panic/return anticipé rejoue proprement un ROLLBACK au déroulage.
pub(crate) struct Txn<'c> {
    conn: &'c Connection,
    committed: bool,
}

impl<'c> Txn<'c> {
    /// Ouvre une transaction `IMMEDIATE`. Err = verrou base indisponible (BEGIN a échoué) : rien n'est ouvert.
    pub(crate) fn begin(conn: &'c Connection) -> rusqlite::Result<Self> {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Txn { conn, committed: false })
    }
    /// Valide (COMMIT). Consomme le garde : plus aucun ROLLBACK au Drop (succès). Sur échec de COMMIT, le
    /// garde retombe dans son Drop -> ROLLBACK best-effort (jamais de transaction demi-ouverte).
    pub(crate) fn commit(mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK"); // best-effort : libère TOUJOURS l'écrivain global
        }
    }
}

fn load_config() -> HashMap<String, String> {
    // Plume CANONICAL (PLUME_-only) : chemin via PLUME_CONFIG uniquement (aucun fallback hérité).
    // Lecture directe (pas via cfg()) : cfg() dépend de load_config() (chicken-and-egg).
    let path = std::env::var("PLUME_CONFIG")
        .unwrap_or_else(|_| "/etc/plume/plume.conf".into());
    let mut m = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    m
}

fn cfg(m: &HashMap<String, String>, key: &str, default: &str) -> String {
    // Plume CANONICAL (PLUME_-only) : la clé est `PLUME_*`. Aucun fallback hérité.
    // Ordre : env PLUME_* > conf PLUME_* > défaut.
    if let Ok(v) = std::env::var(key) {
        return v; // 1. env PLUME_*
    }
    if let Some(v) = m.get(key) {
        return v.clone(); // 2. conf PLUME_*
    }
    default.to_string() // 3. défaut
}

/// SECRET-PROVIDER PHASE 1 — lecture PURE et TESTABLE d'un secret depuis un FICHIER monté RO (secret mount),
/// modèle EXACT de `crypto::db_key_from_file`. VERBATIM, **aucun strip** : le MÊME secret alimente et
/// l'ancien env `{key}` (via `env::var`, qui ne retire rien) et ce fichier (projection brute du Secret,
/// byte-pour-byte identique — k8s n'ajoute aucun `\n`). Retirer un `\n` final fabriquerait une divergence
/// file≠env au cutover -> on lit les octets TELS QUELS => `file == env` par construction. Seules validations :
/// non-UTF8 -> Err, 0 octet -> Err (fail-closed), exactement comme `env::var(..).filter(|k| !k.is_empty())`
/// rejette "". NE JOURNALISE JAMAIS le contenu (les messages ne portent que le CHEMIN, non-secret).
fn read_secret_file(path: &str) -> Result<String, String> {
    // PHASE 2 — DÉLÉGUÉ à `guatx_core::secret::FileProvider` (les OCTETS EXACTS y ont été DÉPLACÉS,
    // byte-identiques). Politique STRICTE (= comportement historique de `read_secret_file`) : toute
    // issue sans valeur -> `Err` (l'appelant `cfg_secret`/`db_key` exit(78)). `NotFound` (absent OU
    // vide 0-octet) et `Unreadable` (perm/I/O) -> tous deux `Err` comme avant (l'ancien code ne
    // distinguait pas absent de perm : tout `std::fs::read` en échec -> `illisible ({e})`).
    use guatx_core::secret::{SecretError, SecretOutcome, SecretProvider, SecretRef};
    match guatx_core::secret::FileProvider.get(&SecretRef::file(path)) {
        Ok(SecretOutcome::Present(v)) => Ok(v.into_string()), // VERBATIM
        Ok(SecretOutcome::NotFound) => Err("absent ou vide".to_string()),
        Err(SecretError::Unreadable(e)) => Err(format!("illisible ({e})")),
        Err(SecretError::Malformed(_)) => Err("contenu non-UTF8".to_string()),
        Err(SecretError::Backend(e)) => Err(e), // inatteignable pour file: ; conservé par exhaustivité
    }
}

/// SECRET-PROVIDER PHASE 1 — résout un secret applicatif SOIT depuis un FICHIER monté RO (`{key}_FILE`,
/// PRÉFÉRÉ ; le secret ne transite alors plus par /proc/<pid>/environ / `kubectl exec` / `ps e` / crash-dump /
/// spec du pod), SOIT depuis l'env/conf `{key}` (REPLI rétrocompat -> comportement v116 INCHANGÉ tant que
/// `{key}_FILE` n'est pas posé). Généralisation stricte de `crypto::db_key()` aux autres secrets
/// (PLUME_PASS_HASH, PLUME_SSO_HEADER_SECRET, PLUME_NOTIFY_NTFY_TOKEN).
///
/// FAIL-CLOSED : si `{key}_FILE` est posé (non-vide) mais que le fichier est absent/illisible/non-UTF8/VIDE ->
/// on REFUSE de démarrer (exit 78, EX_CONFIG) plutôt que de retomber EN SILENCE sur l'env (qui pourrait être
/// absent -> secret vide -> SSO ouvert par défaut / notif muette / hash admin vide = MODE SETUP). Miroir exact
/// du fail-closed de `db_key()`. `{key}_FILE` non posé -> `cfg(key)` (env > conf > "") -> parité v116 stricte.
/// PHASE 2 — ChainResolver : dispatch d'un `SecretRef` sur le provider de son schéma, renvoyant l'issue
/// NEUTRE (`SecretOutcome`/`SecretError`). La POLITIQUE fail-closed/setup/clair est appliquée par
/// l'adaptateur APPELANT (cf. `resolve_ref_strict`/`resolve_ref_setup_safe`), pas ici. Schémas :
///   - `file:` (+ chemin NU « unscheme » -> file:, rétrocompat `{KEY}_FILE`/`{KEY}_REF`) — VERBATIM ;
///   - `env:`  — `env::var` filter-vide, ATTEIGNABLE UNIQUEMENT via un `env:` EXPLICITE (jamais un
///               défaut silencieux -> pas de secret happé depuis /proc/environ par accident) ;
///   - `literal:` — valeur directe ;
///   - `vault:` — HTTP KV-v2 (`crypto::VaultProvider`, généralise l'ancien `data.data.key` -> `#field`).
/// Schéma reconnu mais non géré ici -> `Backend` (fail-closed). NB : le `vault:` PAR ENV-PROJECTION de
/// l'overlay (caller-4) est une forme DISTINCTE, câblée dans `overlays_oac::resolve_secret_ref` (pas ici).
fn resolve_ref_outcome(
    r: &guatx_core::secret::SecretRef,
) -> Result<guatx_core::secret::SecretOutcome, guatx_core::secret::SecretError> {
    use guatx_core::secret::{SecretError, SecretProvider};
    match r.scheme() {
        "file" | "" => guatx_core::secret::FileProvider.get(r), // chemin nu -> file: (rétrocompat)
        "env" => guatx_core::secret::EnvProvider.get(r),
        "literal" => guatx_core::secret::LiteralProvider.get(r),
        "vault" => crypto::VaultProvider.get(r), // HTTP KV-v2 (#field)
        other => Err(SecretError::Backend(format!("schéma inconnu '{other}:'"))),
    }
}

/// PHASE 2 — adaptateur STRICT (politique de `cfg_secret`/`db_key`) : `Present` -> valeur ; `NotFound` /
/// `Unreadable` / `Malformed` / `Backend` -> `exit(78)` (EX_CONFIG, fail-closed — JAMAIS avalé en ""). Le
/// `label`+`refstr` sont journalisés (non-secret) ; la matière n'apparaît JAMAIS.
fn resolve_ref_strict(label: &str, refstr: &str) -> String {
    use guatx_core::secret::SecretOutcome;
    let r = guatx_core::secret::SecretRef::parse(refstr);
    match resolve_ref_outcome(&r) {
        Ok(SecretOutcome::Present(v)) => v.into_string(),
        Ok(SecretOutcome::NotFound) => {
            eprintln!("[FATAL] {label}={refstr} : source absente/vide — refus de démarrer (fail-closed)");
            std::process::exit(78);
        }
        Err(e) => {
            eprintln!("[FATAL] {label}={refstr} : {e} — refus de démarrer (fail-closed)");
            std::process::exit(78);
        }
    }
}

/// PHASE 2 — adaptateur SETUP-SAFE (politique de `cfg_secret_optional`, réservé `PLUME_PASS_HASH`) :
/// `Present` -> valeur ; `NotFound` -> `""` (mode setup légitime, PAS d'exit) ; `Unreadable`/`Malformed`/
/// `Backend` (source PRÉSENTE mais cassée) -> `exit(78)` (NE retombe PAS en setup — sinon re-bootstrap
/// d'auth CRITIQUE).
fn resolve_ref_setup_safe(label: &str, refstr: &str) -> String {
    use guatx_core::secret::SecretOutcome;
    let r = guatx_core::secret::SecretRef::parse(refstr);
    match resolve_ref_outcome(&r) {
        Ok(SecretOutcome::Present(v)) => v.into_string(),
        Ok(SecretOutcome::NotFound) => String::new(), // absent/vide -> "" -> mode setup
        Err(e) => {
            eprintln!(
                "[FATAL] {label}={refstr} : {e} — source PRÉSENTE mais cassée ; refus de démarrer \
                 (fail-closed ; NE retombe PAS en mode setup)"
            );
            std::process::exit(78);
        }
    }
}

fn cfg_secret(conf: &HashMap<String, String>, key: &str) -> String {
    // PHASE 2 (ADDITIF) : `{key}_REF` accepte N'IMPORTE QUEL SecretRef (env:/file:/literal:/vault:) et
    // GAGNE sur `{key}_FILE`/`{key}` s'il est posé. NON posé -> chemin v116 INCHANGÉ ci-dessous (default
    // path byte-identique). Politique STRICTE (fail-closed exit78), MÊME que le repli fichier.
    let ref_key = format!("{key}_REF");
    let refstr = cfg(conf, &ref_key, "");
    if !refstr.is_empty() {
        return resolve_ref_strict(&ref_key, &refstr);
    }
    let file_key = format!("{key}_FILE");
    let path = cfg(conf, &file_key, "");
    if !path.is_empty() {
        match read_secret_file(&path) {
            Ok(v) => return v,
            Err(e) => {
                // NE PAS journaliser le secret ; seulement le chemin + la nature de l'erreur.
                eprintln!(
                    "[FATAL] {file_key}={path} {e} — refus de démarrer (fail-closed ; ne retombe PAS sur {key} env)"
                );
                std::process::exit(78); // EX_CONFIG — même code que le fail-closed de db_key()
            }
        }
    }
    cfg(conf, key, "") // repli rétrocompat : env `{key}` > conf > "" (comportement v116)
}

/// SECRET-PROVIDER PHASE 1 (v118) — RÉSULTAT PUR & TESTABLE de la lecture setup-safe d'un secret OPTIONNEL
/// depuis un fichier monté RO. Réservé au SEUL `PLUME_PASS_HASH` (cf. `cfg_secret_optional`).
/// Distingue les 3 issues sécurité-critiques (assert le VARIANT en test, pas l'exit process) :
enum SetupSecret {
    NotSet,             // pas de secret -> "" -> MODE SETUP légitime (fichier ABSENT ou VIDE)
    Value(String),      // secret présent (fichier lisible non-vide) -> valeur VERBATIM (aucun strip)
    FailClosed(String), // fichier PRÉSENT mais cassé (perm/non-UTF8) -> l'appelant exit 78 ; message = CHEMIN + nature (JAMAIS le contenu)
}

/// Lecture SETUP-SAFE d'un fichier-secret (variante de `read_secret_file` pour un secret OPTIONNEL).
/// CRUX SÉCURITÉ : `PLUME_PASS_HASH` ABSENT est un état LÉGITIME (premier boot = MODE SETUP, le boot teste
/// `pass.is_empty()`) — on ne peut donc PAS traiter « fichier absent » en fail-closed comme SSO/ntfy. MAIS un
/// fichier PRÉSENT-MAIS-CASSÉ qui retomberait en mode setup serait un CONTOURNEMENT D'AUTH CRITIQUE (n'importe
/// qui re-bootstrappe l'admin). On DISTINGUE donc explicitement « absent » de « présent-mais-illisible » :
///   - ABSENT (`ErrorKind::NotFound`)              -> `NotSet`     (mode setup OK, PAS d'exit)  [mount k8s `optional: true` ⇒ Secret absent ⇒ fichier absent]
///   - VIDE (0 octet)                              -> `NotSet`     (hash vide = pas de hash -> mode setup OK ; miroir de `env::var(..).filter(!is_empty)`)
///   - PRÉSENT & lisible & non-vide                -> `Value(..)`  (hash VERBATIM, exactement comme `read_secret_file`)
///   - PRÉSENT mais illisible (perm/autre I/O)     -> `FailClosed` (fail-closed — NE retombe PAS en setup)
///   - PRÉSENT mais contenu non-UTF8               -> `FailClosed` (idem)
/// NE JOURNALISE JAMAIS le contenu (le message ne porte que le CHEMIN, non-secret).
fn read_secret_file_setup_safe(path: &str) -> SetupSecret {
    // PHASE 2 — DÉLÉGUÉ au MÊME `guatx_core::secret::FileProvider` que `read_secret_file` (byte-exact),
    // mais avec la politique SETUP-SAFE : `NotFound` (absent OU vide) -> `NotSet` (mode setup légitime,
    // PAS d'exit) ; `Unreadable`/`Malformed` (fichier PRÉSENT mais cassé) -> `FailClosed` (l'appelant
    // exit 78 ; NE retombe PAS en setup — sinon re-bootstrap d'auth CRITIQUE). La distinction ABSENT vs
    // PRÉSENT-MAIS-CASSÉ (triple-guard PASS_HASH) est portée par `FileProvider` (`NotFound` ≠ `Err`).
    use guatx_core::secret::{SecretError, SecretOutcome, SecretProvider, SecretRef};
    match guatx_core::secret::FileProvider.get(&SecretRef::file(path)) {
        Ok(SecretOutcome::Present(v)) => SetupSecret::Value(v.into_string()), // VERBATIM
        Ok(SecretOutcome::NotFound) => SetupSecret::NotSet,                   // absent OU vide -> setup OK
        Err(SecretError::Unreadable(e)) => SetupSecret::FailClosed(format!("illisible ({e})")),
        Err(SecretError::Malformed(_)) => SetupSecret::FailClosed("contenu non-UTF8".to_string()),
        Err(SecretError::Backend(e)) => SetupSecret::FailClosed(e), // inatteignable pour file:
    }
}

/// SECRET-PROVIDER PHASE 1 (v118) — résout un secret OPTIONNEL (`PLUME_PASS_HASH`) en mode SETUP-SAFE.
/// DIFFÈRE de `cfg_secret` (SSO/ntfy, strictement fail-closed) : l'absence du secret est LÉGITIME (mode setup).
///   - `{key}_FILE` posé  -> lecture setup-safe (`read_secret_file_setup_safe`) : absent/vide -> "" (setup) ;
///     présent-lisible -> hash verbatim ; présent-illisible/non-UTF8 -> exit(78) (fail-closed, PAS de setup).
///   - `{key}_FILE` non posé -> repli env `{key}` > conf > "" (parité v116/v117 STRICTE, mode setup préservé).
/// Retourne "" pour « pas de hash » -> le boot (`pass.is_empty()`) bascule alors en MODE SETUP.
fn cfg_secret_optional(conf: &HashMap<String, String>, key: &str) -> String {
    // PHASE 2 (ADDITIF) : `{key}_REF` accepte N'IMPORTE QUEL SecretRef, politique SETUP-SAFE (NotFound ->
    // "" -> setup ; source PRÉSENTE-mais-cassée -> exit78, NE retombe PAS en setup). NON posé -> chemin
    // v118 INCHANGÉ ci-dessous (default path byte-identique).
    let ref_key = format!("{key}_REF");
    let refstr = cfg(conf, &ref_key, "");
    if !refstr.is_empty() {
        return resolve_ref_setup_safe(&ref_key, &refstr);
    }
    let file_key = format!("{key}_FILE");
    let path = cfg(conf, &file_key, "");
    if !path.is_empty() {
        return match read_secret_file_setup_safe(&path) {
            SetupSecret::Value(v) => v,            // hash réel (fichier présent, lisible, non-vide)
            SetupSecret::NotSet => String::new(),  // absent OU vide -> "" -> MODE SETUP (surtout PAS exit)
            SetupSecret::FailClosed(what) => {
                // Fichier PRÉSENT mais cassé : refuser de démarrer plutôt que de retomber en mode setup
                // (retomber = laisser n'importe qui re-bootstrapper l'admin = contournement d'auth CRITIQUE).
                // NE PAS journaliser le secret ; seulement le chemin + la nature de l'erreur.
                eprintln!(
                    "[FATAL] {file_key}={path} {what} — fichier PRÉSENT mais illisible ; refus de démarrer \
                     (fail-closed ; NE retombe PAS en mode setup — sinon re-bootstrap d'auth possible)"
                );
                std::process::exit(78); // EX_CONFIG — même code que cfg_secret()/db_key()
            }
        };
    }
    // `{key}_FILE` non posé -> repli env `{key}` > conf > "" (v116/v117 ; "" = pas de hash -> mode setup).
    cfg(conf, key, "")
}

/// MODE MULTI-TENANT (#2, décision D2) — DÉFAUT 0 = comportement SMB STRICTEMENT identique à aujourd'hui
/// (control-plane jamais ouvert, tenant unique `default` = /data/plume.db, auth/ingest/query inchangés).
/// =1 active le control-plane + le routing per-tenant. INVARIANT ABSOLU : en mode 0, TOUT est identique.
/// NB (#2a-2a) : la couche IDENTITÉ & CATALOGUE du mode 1 est construite mais INERTE — les handlers data
/// lisent ENCORE st.db (la data-isolation par tenant est PENDING #2a-2b) -> NE PAS activer =1 en prod
/// tant que #2a-2b n'est pas livré (sinon 2 tenants partageraient la même base de données).
fn multi_tenant_enabled(conf: &HashMap<String, String>) -> bool {
    cfg(conf, "PLUME_MULTI_TENANT", "0") == "1"
}

// MODE ENGAGEMENT AUTORISÉ (pentest natif) — DÉFAUT off (mode 0 SMB/prod inchangé, même discipline que
// PLUME_MULTI_TENANT). `engagement_enabled_in` = forme PURE (testable) ; `engagement_enabled` lit le drapeau
// atomique POSÉ AU BOOT (set_engagement_mode), lu sur le chemin chaud d'ingest/ban SANS load_config. Off ->
// TOUT le sous-système est INERTE (index scope VIDE, tag/guard/endpoint no-op) => ingest/ban BYTE-IDENTIQUES.
fn engagement_enabled_in(conf: &HashMap<String, String>) -> bool {
    cfg(conf, "PLUME_ENGAGEMENT_MODE", "0") == "1"
}
static ENGAGEMENT_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn engagement_enabled() -> bool {
    ENGAGEMENT_ON.load(std::sync::atomic::Ordering::Relaxed)
}
fn set_engagement_mode(on: bool) {
    ENGAGEMENT_ON.store(on, std::sync::atomic::Ordering::Relaxed);
}
/// Fenêtre MAX d'un engagement (secondes) — plafond dur du window_end (auto-expiry : jamais d'exemption sans
/// fin). Défaut 24 h. Configurable via PLUME_ENGAGEMENT_MAX_WINDOW (borné >0).
fn engagement_max_window_s(conf: &HashMap<String, String>) -> i64 {
    cfg(conf, "PLUME_ENGAGEMENT_MAX_WINDOW", "86400").parse::<i64>().ok().filter(|&n| n > 0).unwrap_or(86400)
}

// ---- #1b ADMINISTRATION UI : rétention éditable (Partie A) + inventaire/métadonnées sources (Partie B) ----
// TOUT ce bloc est DISPLAY/CONFIG-only : aucune valeur ne coupe l'ingestion ni ne pilote l'hôte. L'ingest
// (ingest_post/ingest_journal_post) reste INSERT OR IGNORE INCONDITIONNEL.

/// Champs de rétention éditables. (setting_key == clé JSON de l'API, env_key PLUME_*, défaut, plancher, plafond).
/// PLANCHER = borne DURE anti-effacement (correctifs H1/M6) : event≥7j (l'audit SOC-visible `plume-config`
/// survit à toute baisse), alert≥30j, snapshot/metric≥7j, raw≥24h. Appliqué À L'ÉCRITURE (PUT clamp) ET À
/// L'APPLICATION (retention_run) : une baisse destructive ne peut jamais descendre sous le plancher, quelle
/// que soit la provenance de la valeur (UI setting, env, conf, défaut).
const RETENTION_FIELDS: [(&str, &str, i64, i64, i64); 5] = [
    ("retention_days", "PLUME_RETENTION_DAYS", 30, 7, 3650),
    ("snapshot_days", "PLUME_SNAPSHOT_DAYS", 30, 7, 3650),
    ("alert_days", "PLUME_ALERT_DAYS", 90, 30, 3650),
    ("metric_days", "PLUME_METRIC_DAYS", 90, 7, 3650),
    ("metric_raw_hours", "PLUME_METRIC_RAW_HOURS", 48, 24, 8760),
];

/// Résout la valeur COURANTE d'une clé de rétention par la MÊME chaîne que l'application (correctif H2) :
/// setting(scope='global',key) si présent&parsable -> sinon cfg (env PLUME_* > conf > défaut) -> clamp[plancher,plafond].
/// Utilisé À LA FOIS par retention_run (la BDD gagne, hot-reload) ET par les GET/preview -> jamais un défaut
/// codé en dur divergent (sinon une baisse destructive se déguiserait en hausse rassurante).
fn setting_days(conn: &Connection, conf: &HashMap<String, String>, skey: &str, env_key: &str, d: i64, floor: i64, ceil: i64) -> i64 {
    conn.query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![skey], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or_else(|| cfg(conf, env_key, &d.to_string()).parse().unwrap_or(d))
        .clamp(floor, ceil)
}

/// Valeur effective d'une clé de rétention (via RETENTION_FIELDS + setting_days). 0 si clé inconnue.
fn retention_effective(conn: &Connection, conf: &HashMap<String, String>, skey: &str) -> i64 {
    for (k, env_key, d, floor, ceil) in RETENTION_FIELDS {
        if k == skey {
            return setting_days(conn, conf, k, env_key, d, floor, ceil);
        }
    }
    0
}

/// Sources d'events "attendues par construction" au-delà des ids COLLECTORS : le collecteur `journal`
/// alimente sshd/sudo/su, `audit` alimente auditd ; nos propres audits = plume-config/plume-auth. Sert au
/// flag DISPLAY-only "inattendu" (inventaire) ET à la sévérité B8 (marquer expected une source hors de cet
/// ensemble = suppression d'un SIGNAL potentiel -> audit sev 3). AUCUN effet sur l'ingest/la collecte.
// (a) journal auth (sshd/su/sudo) + auditd + nos propres audits ; (b) FEEDS LÉGITIMES additionnels dont l'id
// de SOURCE (colonne `source` de l'event) diffère de l'id de COLLECTEUR — ils étaient donc flaggés « inattendu »
// à tort par l'inventaire alors que ce sont de vraies sources connues (minio/vault/cloudflare/conntrack/mail/
// containerd/k8s/dataacl/agent). Débruitage d'un FAUX signal : le flag « inattendu » reste actif pour toute
// source GÉNUINEMENT inconnue (ni ici, ni dans COLLECTORS, ni marquée expected par un admin).
const KNOWN_EXTRA_SOURCES: [&str; 17] = [
    "sshd", "sshd-session", "sudo", "su", "auditd", "plume-config", "plume-auth",
    "minio-audit", "vault-audit", "cloudflare", "conntrack", "mail", "containerd", "minio", "k8s", "dataacl", "agent",
];
fn source_is_known(source: &str) -> bool {
    COLLECTORS.iter().any(|c| c.0 == source) || KNOWN_EXTRA_SOURCES.contains(&source)
}

















// ---------- form-login : cookie de session signé HMAC + CSRF (4e méthode d'auth, ADDITIVE) ----------
// Cette section n'altère AUCUN chemin existant (Basic/SSO/Bearer) : elle AJOUTE une méthode d'auth.
// HMAC-SHA256 implémenté sur le crate `sha2` déjà présent (aucune dépendance ajoutée).














// ---------- handlers ----------





// soql_tokenize : SUPPRIMÉ (P1-H3) — copie locale byte-identique de guatx_core::soql::soql_tokenize.
// Les sites d'appel utilisent désormais directement guatx_core::soql::soql_tokenize.

/// Re-colle un filtre `champ op valeur` éclaté par des espaces (`source = "x"` -> `source="x"`),
/// pour tolérer la syntaxe SQL habituelle. Fusionne `<ident> <op…>` et tout jeton finissant par un
/// opérateur (= : ! < > ~) avec le jeton suivant. Un terme libre sans opérateur reste intact.
/// Copie locale du helper de guatx_core::soql (parité shadow / chemin /api/search, pas de churn cross-crate).
fn soql_glue_spaced_ops(tokens: Vec<String>) -> Vec<String> {
    fn is_op(c: char) -> bool { matches!(c, '=' | ':' | '!' | '<' | '>' | '~') }
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let mut t = tokens[i].clone();
        i += 1;
        let bare = !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if bare && i < tokens.len() && tokens[i].starts_with(is_op) { t.push_str(&tokens[i]); i += 1; }
        if t.ends_with(is_op) && i < tokens.len() { t.push_str(&tokens[i]); i += 1; }
        out.push(t);
    }
    out
}

fn soql_ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
// soql_esc / soql_qid : SUPPRIMÉS (P1-H3) — copies locales byte-identiques de
// guatx_core::soql::soql_esc et guatx_core::soql::soql_qid. Sites d'appel fully-qualifiés.

// =====================================================================================
// INDEX EXPRESSION SUR `fields` (Phases 2 & 3) — état mémoire + canonicalisation.
//
// Le planner SQLite n'utilise un `CREATE INDEX ... ON event(json_extract(fields,'$.X'))`
// QUE si la requête émet EXACTEMENT la même expression texte `json_extract(fields,'$.X')`
// (mêmes guillemets simples, même casse, pas d'espace). HOT_FIELDS + le cache auto-index
// pilotent la garde anti-CAST de soql_filter_field (cf. soql_changes). Tout ici est en
// MÉMOIRE — jamais de DB sur le chemin chaud de compilation/lecture.
// =====================================================================================

// =====================================================================================
//  CIM — Common Information Model (contrat EXPLICITE, versionné) — Slice #7, pièce 1.
// -------------------------------------------------------------------------------------
//  Formalise le contrat IMPLICITE sur lequel TOUTE détection compose déjà : la ligne
//  canonique `EventRow` (ts,source,category,severity,message,host,src_ip,dst_ip,url,dedup,
//  fields,engagement_id,origin,env_id) + le vocabulaire NEUTRE de `category` (produit par
//  fgt_category / parser.rs / les collecteurs, consommé par les règles `category=…`).
//  ⚠️ NE CHANGE AUCUN comportement runtime : mise au propre (SOURCE UNIQUE DE VÉRITÉ) de ce
//  que le code émet/consomme déjà. Miroir humain : docs/CIM.md ; miroir machine :
//  config.d/cim/cim.v1.json (le test `cim_contract_is_self_consistent_and_matches_schema`
//  interdit toute dérive entre les trois).
//  ⚠️ ANTI-ANGLE-MORT : le CIM est PARSE/MAP/ENRICH — JAMAIS un DROP. Reconnaître une
//  category ne supprime rien ; une category hors-taxonomie est ACCEPTÉE (ingest inchangé) et
//  seulement SIGNALÉE (warn), jamais rejetée. Toute réduction de collecte passe par les
//  whitelists (#10 / /api/sources/settings, audit sev 3), pas par le CIM.
// =====================================================================================







// ================================================================================================
// COUCHE IDENTITÉ & CATALOGUE MULTI-TENANT (#2a-2a) — INERTE EN MODE 0.
//
// Modèle (décision D1, hybride 3a) : CRYPTO PAR TENANT. Le FICHIER SQLCipher EST le tenant (1 base +
// 1 clé par tenant) ; il N'Y A PAS de colonne tenant_id (seul `env_id` est row-level, pour les
// environnements DANS un tenant). Le control-plane est une base SÉPARÉE (`plume-control.db`, sa propre
// clé) qui porte le catalogue (tenant/user/grant/token) — jamais exposée à un tenant.
//
// Cette phase construit l'IDENTITÉ (routing token->tenant + auth) et le
// CATALOGUE (control-plane + TenantDbManager). Elle NE rewire PAS encore les handlers data vers le
// handle par-tenant : c'est #2a-2b (les handlers data lisent ENCORE st.db). Donc le mode 1 n'est PAS
// fonctionnel end-to-end -> à NE PAS activer en prod tant que #2a-2b n'est pas livré.
//
// INVARIANT ABSOLU : mode 0 (PLUME_MULTI_TENANT absent/0) => control-plane JAMAIS ouvert, TenantDbManager
// en passthrough EXACT (un tenant `default` = (PLUME_DB, PLUME_DB_KEY) = st.db/st.db_path), identité lue
// de la base unique EXACTEMENT comme avant. Zéro changement de comportement.
// ================================================================================================








// ================================================================================================
// ONBOARDING / DESTRUCTION TENANT (#2a-3) — MÉCANISME (pas d'UI, pas de route HTTP). API interne
// consommée plus tard par #2c. Mode 0 (control=None) -> erreur (rien à provisionner sur la base unique).
// ================================================================================================








// ================================================================================================
// ROUTING REQUÊTE PAR TENANT (#2a-2b) — accesseurs par-requête + ingest fail-closed (R8).
//
// req_db/req_db_path routent le CHEMIN REQUÊTE (handlers data + ingest) vers la base du tenant COURANT
// (AuthUser.tenant, résolu par auth_guard). INVARIANT ABSOLU : mode 0 (multi_tenant=false / control=None)
// => req_db == st.db et req_db_path == st.db_path (tenant `default`) -> comportement STRICTEMENT identique.
// Mode 1 => TenantDbManager.handle_for / resolve. Le guard renvoie 403 quand le tenant n'est pas
// RÉSOLVABLE, mais ce n'est plus la seule cause d'indisponibilité : `handle_for` refuse aussi une base
// tenant dont le SCHÉMA n'est pas celui attendu (contrat `prepare_schema`), et ce cas-là n'est pas vu
// par le guard. Le repli de `req_db` n'est donc plus « la base opérateur `default` » — c'était une
// écriture chez un AUTRE tenant : c'est une base CUL-DE-SAC en mémoire `query_only` (cf.
// `unavailable_tenant_db`), où toute écriture et toute lecture échouent bruyamment.
//
// #2a-2c (FAIT, PAS un vecteur de fuite) : les JOBS DE FOND (run_due_rules / run_playbooks / retention_run /
// rollup_events / materialize_banned_ip / cache_refresh_all_panels / freshness périodique / autoindex)
// ITÈRENT désormais les tenants actifs via `for_each_active_tenant` (ci-dessous) : chaque tenant reçoit
// l'évaluation de SES règles, SA rétention (lue de SA base), SES rollups. Mode 0 = une seule itération
// `default`=st.db (cadence + comportement STRICTEMENT identiques) ; itération SÉQUENTIELLE (pas de fan-out,
// budget 2 Go) ; SKIP fail-closed d'un tenant à clé non résoluble (jamais de repli sur `default`). C'est de
// la complétude du mode 1 (les règles/rollups d'un tenant client tournent). La frontière de CLÉ PAR TENANT,
// elle, est posée par #2a-3 :
// resolve() enregistre (db_path -> clé du tenant) et read_conn_open applique CETTE clé (registre keyé
// db_path), le writer (handle_for) ouvre déjà avec la clé résolue -> chaque base tenant s'ouvre avec SA
// clé, FAIL-CLOSED (clé non résoluble -> resolve None -> aucune ouverture avec une clé par défaut). Mode 0
// (base unique jamais enregistrée) -> read_conn_open retombe sur db_key()/PLUME_DB_KEY = IDENTIQUE.
// ================================================================================================


















// ================================================================================================
// RBAC MULTI-TENANT (#2b, spec §B.3/B.5, décision D3) — parsing SSO groupes->tenant+rôle+superadmin,
// résolution du RÔLE PER-TENANT du user pour le tenant courant, et super-admin cross-tenant AUDITÉ
// (lecture double-ledger + marqueur `plume-operator-access` non désactivable ; écriture = break-glass).
// INVARIANT ABSOLU : ces fonctions ne sont appelées QU'EN MODE 1. En mode 0, auth_guard garde `sso_role`
// et le rôle d'ident (groupes Authentik -> admin/editor/viewer sur l'unique tenant `default`), INCHANGÉ.
// ================================================================================================
















// ================================================================================================
// GESTION DES TENANTS EN ROUTES HTTP (#2c) — EXPOSE l'onboarding/suspension/destruction + les grants
// des mécanismes internes #2a-3 (tenant_provision/tenant_destroy/tenant_generate_key). Toutes GATÉES
// SERVEUR : (a) path-guard `tenant_mgmt_gate` dans auth_guard ; (b) re-check role/superadmin DANS chaque
// handler (défense en profondeur). Le CRUD de tenant (créer/suspendre/détruire) + les grants CROSS-tenant
// = SUPER-ADMIN uniquement ; un tenant-admin ne gère QUE les grants de SON tenant courant (jamais un autre,
// jamais s'auto-escalader en superadmin — le rôle est un enum FERMÉ admin/editor/viewer et le flag
// is_superadmin n'est JAMAIS accessible ici). Toute mutation est auditée (control_ledger + event tenant).
// INVARIANT ABSOLU : en mode 0 (multi_tenant=false), toutes ces routes sont INERTES (état vide/`default`
// ou 404) et n'ouvrent JAMAIS de control-plane -> comportement STRICTEMENT identique à aujourd'hui.
// ================================================================================================












// ---------- (#2c) HANDLERS HTTP ----------









// ================================================================================================
// CONVENTION MULTI-TENANT (#2a-1) — MT-KEY: par db_path.
// TOUT cache / registre / pool PROCESS-GLOBAL qui contient de la DONNÉE TENANT (ou des connexions
// ouvertes sur une base tenant) DOIT être CLÉ PAR `db_path`. En mono-tenant il n'existe qu'un seul
// db_path (= st.db_path) -> une seule entrée par map -> comportement STRICTEMENT identique (perf incluse).
// En multi-tenant (futur, PLUME_MULTI_TENANT=1) le routing per-tenant fournit le db_path courant.
// NE JAMAIS réintroduire un singleton `static …Cache/Pool/Set/Registry` NON clé au-dessus du handle DB :
// l'état vit AU-DESSUS du chiffrement SQLCipher, il fuiterait donc inter-tenant MALGRÉ la crypto par
// tenant. Les 6 points re-clés ici : READ_POOL, EVENTS_COUNT_CACHE,
// FRESHNESS_CACHE, PARSERS, AUTOINDEX_SET/BUF, QUERY_CANCEL.
// ================================================================================================





// ---------- intégrations & heartbeat (P4) ----------

// ====================================================================================================
// LA SONDE DE FRAÎCHEUR — CE QU'ELLE OBSERVE EST TYPÉ, SA REQUÊTE EN EST DÉRIVÉE.
//
// CE QUI ÉTAIT CASSÉ. Le descripteur d'un capteur portait une CHAÎNE SQL LIBRE, et celle des deux
// capteurs d'INSTANTANÉ était `SELECT MAX(ts) FROM snapshot WHERE kind='…'` — sans filtre d'hôte, donc
// la donnée la PLUS FRAÎCHE du parc. MESURÉ le 2026-08-02 par le vrai chemin d'ingestion, parc de 50
// machines dont 49 se taisent depuis 2 h : la sonde livrée déclarait un âge de 101 s et le statut
// « actif », alors que la machine la plus en retard avait 7301 s de retard et que 49 hôtes sur 50
// étaient muets. `check_heartbeats` levait ZÉRO alerte. Un SOC qui affiche « frais » pendant que 49
// machines sur 50 se sont tues est pire qu'un SOC en retard : il donne une confiance FAUSSE.
//
// LA FORME DÉRIVÉE. Une sonde de fraîcheur répond « quand la donnée de ce capteur est-elle arrivée pour
// la dernière fois ». Sur un parc, la réponse utile n'est PAS celle de la machine la plus fraîche mais
// celle de la machine la PLUS EN RETARD : `MIN` sur les `MAX(ts)` PAR HÔTE. Propriété qui rend la
// bascule sûre : sur un déploiement MONO-HÔTE (le défaut PME) il n'y a qu'un groupe, donc
// `MIN(MAX(ts)) == MAX(ts)` — valeur IDENTIQUE, à la seconde près, aucune bascule de statut.
//
// POURQUOI UN TYPE ET PAS UNE RELECTURE DES DEUX LIGNES. Le champ n'est plus une chaîne : c'est ce que
// la sonde OBSERVE. Il n'existe AUCUNE façon d'ÉCRIRE une sonde d'instantané qui confonde les hôtes —
// `Sonde::Instantane` ne prend qu'un `kind`, et le `GROUP BY host` est posé par `derniere_collecte()`,
// pas par l'auteur du descripteur. Un 24ᵉ capteur ajouté demain par quelqu'un qui n'a jamais lu ce
// fichier est couvert PAR CONSTRUCTION : le défaut ne compile pas.
//
// CE QUE ÇA NE FERME PAS (écrit pour être opposable, pas pour rassurer) : les 20 sondes d'EVENTS
// (`EventFlotteConfondue`) et celle des MÉTRIQUES gardent leur portée « tous hôtes confondus » — dont
// 12 sont CONTINUES, donc leur statut dépend VRAIMENT de la valeur (les 9 autres sont événementielles :
// leur statut suit `pipeline_is_fresh`, la valeur ne sert qu'au texte du détail). C'est
// le MÊME défaut de famille — mesuré identique — mais il n'a PAS le même coût : `snapshot` ne garde
// qu'une ligne vivante par (kind, hôte) (le heartbeat la TOUCHE au lieu d'en insérer une), donc son
// `GROUP BY host` porte sur la cardinalité de la FLOTTE ; `event` compte ~9,8 M lignes en production et
// ces sondes tournent DANS `check_heartbeats`, sous le verrou d'écriture. La portée est donc désormais
// DÉCLARÉE (et comptée par `snapshot_sonde_instantanee_ancrage_de_portee`) au lieu d'être accidentelle :
// c'est une dette nommée, pas un angle mort. (Chantier séparé — cf. le rapport P3.2-a.)
//
// RÉSIDU ASSUMÉ, écrit parce qu'il compte : une machine DÉCOMMISSIONNÉE continue de tirer la sonde vers
// le retard tant que ses lignes `snapshot` n'ont pas expiré (`snapshot_days`, 30 j par défaut) — donc une
// alerte « capteur muet » qui NOMME cette machine reste ouverte jusque-là. L'échange est délibéré et il
// est asymétrique : le coût est une alerte bruyante mais VRAIE (« une machine qui rapportait ne rapporte
// plus ») et auto-résorbable, contre un angle mort silencieux qui, lui, ne se résorbe jamais. Le retirer
// exigerait un INVENTAIRE DÉCLARÉ des machines attendues, que Plume n'a pas (l'inventaire `host_rollup`
// est DÉCOUVERT : une machine qui se tait entièrement en sortirait, ce qui rouvrirait exactement le trou
// qu'on ferme).
// ====================================================================================================

/// CE QU'UNE SONDE DE FRAÎCHEUR OBSERVE — et donc, par dérivation, la requête qu'elle émet.
pub(crate) enum Sonde {
    /// INSTANTANÉ (`snapshot`) — un instantané décrit UNE machine (`firewall.sh` hashe le ruleset de
    /// CETTE machine, `controls.sh` n'inclut un contrôle que s'il s'applique SUR cette machine), donc la
    /// fraîcheur du PARC est celle de la machine la plus en retard. Le `kind` est LIÉ (paramètre), jamais
    /// interpolé.
    Instantane { kind: &'static str },
    /// EVENT — portée FLOTTE CONFONDUE, DÉCLARÉE (cf. bandeau ci-dessus) : `MAX(ts)` tous hôtes
    /// confondus. Le descripteur ne porte que le PRÉDICAT ; la table est figée par le variant.
    EventFlotteConfondue { predicat: &'static str },
    /// MÉTRIQUES — portée FLOTTE CONFONDUE, DÉCLARÉE. Aucun prédicat (toutes séries confondues).
    MetriqueFlotteConfondue,
}

impl Sonde {
    /// Dernière collecte OBSERVÉE. Le SQL ne SORT PAS de ce type : aucun appelant ne peut le réécrire,
    /// l'oublier, ni en dériver une variante sans hôte. `None` = jamais rien vu (statut « inconnu »),
    /// exactement comme un `MAX(ts)` sur table vide auparavant.
    pub(crate) fn derniere_collecte(&self, conn: &Connection) -> Option<i64> {
        let r = match self {
            // MIN sur les MAX PAR HÔTE = la machine la plus EN RETARD. Mono-hôte : un seul groupe ->
            // valeur strictement identique à l'ancien `MAX(ts) … WHERE kind=…`.
            Sonde::Instantane { kind } => conn.query_row(
                "SELECT MIN(l) FROM (SELECT host, MAX(ts) AS l FROM snapshot WHERE kind=?1 GROUP BY host)",
                params![kind],
                |r| r.get::<_, Option<i64>>(0),
            ),
            Sonde::EventFlotteConfondue { predicat } => conn.query_row(
                &format!("SELECT MAX(ts) FROM event WHERE {predicat}"),
                [],
                |r| r.get::<_, Option<i64>>(0),
            ),
            Sonde::MetriqueFlotteConfondue => {
                conn.query_row("SELECT MAX(ts) FROM metric", [], |r| r.get::<_, Option<i64>>(0))
            }
        };
        r.ok().flatten()
    }

    /// Les machines dont la dernière collecte est ANTÉRIEURE à `avant_ts`, la plus en retard d'abord.
    /// Sert à ce que l'alerte « capteur muet » NOMME les machines au lieu de dire « le capteur » :
    /// sur le parc mesuré (49 muettes sur 50), sans ça l'opérateur ne sait pas où regarder. Bornée à
    /// `max` entrées + le reste compté par l'appelant. Vide pour les sondes à portée flotte confondue
    /// (elles n'ont pas de notion d'hôte — c'est précisément la dette déclarée).
    pub(crate) fn hotes_en_retard(&self, conn: &Connection, avant_ts: i64, max: usize) -> Vec<(String, i64)> {
        let Sonde::Instantane { kind } = self else { return Vec::new() };
        let Ok(mut s) = conn.prepare(
            "SELECT COALESCE(host,''), MAX(ts) AS l FROM snapshot WHERE kind=?1 GROUP BY host \
             HAVING l < ?2 ORDER BY l ASC",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = s.query_map(params![kind, avant_ts], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) else {
            return Vec::new();
        };
        rows.flatten().take(max).collect()
    }
}

/// Capteurs attendus : (id, libellé, intervalle attendu s, SONDE (ce qu'elle observe), ÉVÉNEMENTIEL ?).
/// FIX #2 — `event_based=true` : capteur dont le débit dépend d'une ACTIVITÉ externe (ici les logins
/// SSH/sudo/su) et non d'un timer. Un hôte calme = pas de login = silence NORMAL -> ne JAMAIS le déclarer
/// MUET tant que le pipeline d'ingestion GLOBAL est frais (logique alignée sur compute_freshness, où
/// crowdsec/fail2ban/ufw/nft sont déjà de type « événement »). `false` = capteur CONTINU (timer/flux
/// régulier) : un silence > 5x son intervalle est un vrai angle mort -> alerte MUET légitime (auditd
/// inclus : sur un hôte vivant l'auditd exec/privesc remonte en continu, son silence = daemon mort).
const COLLECTORS: [(&str, &str, i64, Sonde, bool); 23] = [
    ("journal", "journald (auth)", 60, Sonde::EventFlotteConfondue { predicat: "source IN ('sshd','sshd-session','sudo','su')" }, true),
    ("resources", "ressources/réseau", 60, Sonde::MetriqueFlotteConfondue, false),
    ("firewall", "firewall", 120, Sonde::Instantane { kind: "firewall" }, false),
    ("controls", "Control Catalog", 300, Sonde::Instantane { kind: "controls" }, false),
    ("audit", "auditd (exec/privesc)", 120, Sonde::EventFlotteConfondue { predicat: "source='auditd'" }, false),
    // YARA (scan) — intégration OFF par défaut : le collecteur host yara.sh est inerte tant que `yara`
    // n'est pas installé / aucune règle n'est déposée (cf. bootstrap PLUME_WITH_YARA=1). event_based=true ->
    // statut 'inconnu' (UI : « en attente ») tant qu'aucun event source=yara n'arrive, et JAMAIS « muet »
    // sur son propre silence (le muet d'un capteur événementiel ne se juge que sur la santé du pipeline
    // global). Quand un match YARA remonte -> 'actif'. Présence ici = la pastille « Non branché : YARA »
    // (web app.js) s'efface d'elle-même (data-driven : l'intégration off devient une vraie intégration).
    ("yara", "YARA (scan)", 900, Sonde::EventFlotteConfondue { predicat: "source='yara'" }, true),
    // ── FIX (audit cohérence v56) — capteurs ÉVÉNEMENTIELS/ÉPARS : leur débit dépend d'une ACTIVITÉ externe
    // (un ban, un scan, un accès à un fichier sensible, un changement FIM) ET le débruitage les rend calmes
    // par construction (dataaccess = écritures seules, integrity = FIM, k8s-log = sev≥3). event_based=true ->
    // ils ne crient JAMAIS « muet » sur leur PROPRE silence (hôte calme = NORMAL) ; le « muet » ne se juge que
    // sur la santé du pipeline GLOBAL (pipeline_is_fresh). Sans ce flag ils alerteraient à tort dès qu'ils se
    // taisent — observé sur l'instance : k8s-log calme ~20 h, crowdsec ~3 j, portscan ~7 h, pipeline pourtant
    // frais. su/sudo/sshd sont DÉJÀ couverts (et event_based) par `journal` ci-dessus -> pas de doublon.
    ("dataaccess", "accès données sensibles (FIM)", 300, Sonde::EventFlotteConfondue { predicat: "source='dataaccess'" }, true),
    ("integrity", "intégrité fichiers (FIM)", 900, Sonde::EventFlotteConfondue { predicat: "source='integrity'" }, true),
    ("k8s-log", "logs pods k8s (sev≥3)", 300, Sonde::EventFlotteConfondue { predicat: "source='k8s-log'" }, true),
    // DEAD-MAN'S-SWITCH pod-logs (calque EXACT de crowdsec-health) — battement de SANTÉ ÉMIS À CHAQUE RUN par
    // collectors/pod-logs.sh (timer 5 min) MÊME quand 0 ligne sev≥3 : source=k8s-log category=health
    // {files_scanned,lines_scanned,sev3_shipped}. CONTINU (event_based=false) -> son SILENCE > 5x l'intervalle
    // (25 min) = collecteur pod-logs MORT -> alerte MUET (le vrai dead-man's-switch). Distingue « 0 ligne sev≥3
    // (normal : la ligne `k8s-log` ÉVÉNEMENTIELLE ci-dessus tolère le calme) » de « collecteur pod-logs mort ».
    // La requête matche sur source+category -> NE se confond PAS avec le flux d'events k8s (category=k8s).
    // Avant le 1er battement (PVC neuf) : last_seen NULL -> statut 'inconnu', jamais 'muet'. Pas de seed DB.
    ("k8s-log-health", "Pod-logs santé (collecteur)", 300, Sonde::EventFlotteConfondue { predicat: "source='k8s-log' AND category='health'" }, false),
    ("crowdsec", "CrowdSec (décisions)", 3600, Sonde::EventFlotteConfondue { predicat: "source='crowdsec'" }, true),
    // DEAD-MAN'S-SWITCH CrowdSec — battement de SANTÉ ÉMIS À CHAQUE RUN par collectors/crowdsec.sh (timer
    // 5 min) MÊME quand 0 ban : source=crowdsec category=health {scenarios_loaded,scenarios_broken,...}.
    // CONTINU (event_based=false, le SEUL de la famille crowdsec) -> son SILENCE > 5x l'intervalle (25 min)
    // = collecteur OU moteur CrowdSec MORT -> alerte MUET (le vrai dead-man's-switch). Distingue « 0 attaque
    // (normal : la ligne `crowdsec` ÉVÉNEMENTIELLE ci-dessus tolère le calme des bans) » de « CrowdSec
    // aveugle/cassé » (incident : moteur deadlock aveugle 3,3 j sans aucune alerte). La requête matche sur
    // source+category -> NE se confond PAS avec le flux de bans (category=network) -> 0 bruit pendant les
    // accalmies de ban normales. Avant le 1er battement (PVC neuf) : last_seen NULL -> statut 'inconnu', jamais
    // 'muet' (la logique CONTINU ne déclenche que sur Some(t) trop ancien). scenarios_broken>0 -> règle v57.
    ("crowdsec-health", "CrowdSec santé (moteur)", 300, Sonde::EventFlotteConfondue { predicat: "source='crowdsec' AND category='health'" }, false),
    ("fail2ban", "fail2ban (bans actifs)", 3600, Sonde::EventFlotteConfondue { predicat: "source='fail2ban'" }, true),
    ("ufw", "UFW (blocages firewall)", 300, Sonde::EventFlotteConfondue { predicat: "source='ufw'" }, true),
    ("portscan", "port-scan (nft PORTSCAN)", 900, Sonde::EventFlotteConfondue { predicat: "source='portscan'" }, true),
    // ── CONTINUS (event_based=false) : flux réguliers sur un hôte vivant -> un silence > 5x l'intervalle EST
    // un vrai angle mort -> alerte « muet » LÉGITIME (à garder, comme auditd/resources). web = accès/4xx d'un
    // site public (débit soutenu quand sain) ; kube-audit = audit de l'API k8s (flux constant). Ils DOIVENT
    // crier s'ils se taisent. Intervalles généreux pour tolérer les accalmies normales sans faux positif.
    ("web", "web (accès / 4xx)", 1800, Sonde::EventFlotteConfondue { predicat: "source='web'" }, false),
    ("kube-audit", "audit API k8s", 120, Sonde::EventFlotteConfondue { predicat: "source='kube-audit'" }, false),
    // ── DEAD-MAN'S-SWITCH des collecteurs ÉVÉNEMENTIELS SANS compagnon -health (calque EXACT de
    // crowdsec-health / k8s-log-health). Les feeds RÉELS ci-dessus (portscan/ufw/fail2ban/dataaccess/
    // integrity/journal) sont event_based=true -> ils NE crient JAMAIS « muet » sur leur propre silence
    // (hôte calme = normal). Mais un collecteur qui MEURT (timer stoppé, script cassé, host down) se tairait
    // sans un mot. Chaque collecteur émet donc à CHAQUE run un battement source=<x> category=health severity 0
    // MÊME quand 0 event réel (pas de dedup -> chaque battement s'INSÈRE -> MAX(ts) avance). Ces entrées
    // CONTINUES (event_based=false) surveillent CE battement : silence > 5x l'intervalle (25-75 min) = le
    // collecteur est mort -> alerte MUET (le VRAI dead-man's-switch). La requête matche source+category='health'
    // -> ne se confond PAS avec le flux réel (category='firewall'/'ban'/'data'/'integrity'/'auth'). Avant le 1er
    // battement (opt-in jamais activé / PVC neuf) : last_seen NULL -> statut 'inconnu', JAMAIS 'muet' (la logique
    // CONTINU ne déclenche que sur Some(t) trop ancien) -> zéro faux positif sur un collecteur non déployé.
    // Intervalles = max(300, cadence_timer) pour garder mute ≥ 25 min et ≥ 5 runs manqués. Chaque tuple obtient
    // AUSSI sa carte dans le panneau intégrations (integrations() est data-driven sur COLLECTORS). CODE-only :
    // aucune migration DB (comme crowdsec-health/k8s-log-health). Les entrées event_based ci-dessus NE bougent PAS.
    ("portscan-health",   "port-scan santé (nft)",         300, Sonde::EventFlotteConfondue { predicat: "source='portscan' AND category='health'" }, false),
    ("ufw-health",        "UFW santé (collecteur)",        300, Sonde::EventFlotteConfondue { predicat: "source='ufw' AND category='health'" }, false),
    ("fail2ban-health",   "bans santé (collecteur)",       600, Sonde::EventFlotteConfondue { predicat: "source='fail2ban' AND category='health'" }, false),
    ("dataaccess-health", "accès données santé (FIM)",     300, Sonde::EventFlotteConfondue { predicat: "source='dataaccess' AND category='health'" }, false),
    ("integrity-health",  "intégrité santé (FIM)",         900, Sonde::EventFlotteConfondue { predicat: "source='integrity' AND category='health'" }, false),
    ("journal-health",    "journald santé (shipper auth)", 300, Sonde::EventFlotteConfondue { predicat: "source='journal' AND category='health'" }, false),
];




static INGEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);







/// Rétention + rollup (cron horaire) : borne la croissance de la base. Cf. plan données.
/// Dashboard « Vue d'ensemble (rapide) » — agrégations PRÉ-CALCULÉES depuis `event_rollup` (panneaux
/// SQL directs, is_soql=0, __FROM__ = fenêtre). Évite de scanner `event` à chaque fois (la requête
/// `severity>=3 by source` passait de ~1,9 s à quasi instantané). Idempotent par nom. Vue 'Sécurité'.
fn seed_rollup_dashboard(conn: &Connection) {
    if conn.query_row("SELECT 1 FROM dashboard WHERE name='Vue d''ensemble (rapide)'", [], |r| r.get::<_, i64>(0)).is_ok() {
        return;
    }
    if conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('Vue d''ensemble (rapide)', ?1, 'shared')", params![now()]).is_err() {
        return;
    }
    let did = conn.last_insert_rowid();
    // v63 : « Vue d'ensemble (rapide) » rejoint la vue « SOC » (à côté de « SOC — Vue d'ensemble »), REPLIÉ.
    if let Some(vid) = find_or_create_view(conn, "SOC") { let _ = conn.execute("UPDATE dashboard SET view_id=?1, collapsed=1 WHERE id=?2", params![vid, did]); }
    // is_soql=0 -> SQL direct sur event_rollup (pré-agrégé) ; __FROM__/__TO__ remplacés par la fenêtre.
    // Les panneaux « par src_ip / par host » lisent désormais le PRÉ-AGRÉGÉ (v33) au lieu de scanner event.
    // Ces panneaux n'utilisent QUE les colonnes du rollup (pas de json_extract) -> robustes aux évolutions
    // du format `fields`. src_ip<>'' filtre le lump basse-sévérité (cf. borne v33). NB : SQL sur rollup =
    // is_soql=0, le compilateur soql guatx-core n'y touche pas (event_rollup n'est pas un objet GXQL).
    let panels: [(&str, &str, &str); 7] = [
        ("Volume dans le temps", "SELECT bucket, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY bucket ORDER BY bucket", "line"),
        ("Par source", "SELECT source, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY source ORDER BY n DESC LIMIT 20", "bar"),
        ("Sévérité >=3 par source", "SELECT source, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 GROUP BY source ORDER BY n DESC LIMIT 20", "bar"),
        ("Par action (CIM)", "SELECT action, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND action<>'' GROUP BY action ORDER BY n DESC LIMIT 20", "bar"),
        ("Par sévérité", "SELECT severity, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ GROUP BY severity ORDER BY severity", "bar"),
        ("Sévérité >=3 par src_ip", "SELECT src_ip, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND severity>=3 AND src_ip<>'' GROUP BY src_ip ORDER BY n DESC LIMIT 20", "bar"),
        ("Volume par host", "SELECT host, SUM(n) AS n FROM event_rollup WHERE bucket>=__FROM__ AND host<>'' GROUP BY host ORDER BY n DESC LIMIT 20", "bar"),
    ];
    for (i, (title, q, viz)) in panels.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,?2,?3,0,?4,?5,2)",
            params![did, title, q, viz, i as i64],
        );
    }
}











// Fabriques de réponses d'erreur JSON. Chacune émet EXACTEMENT
// `(StatusCode::X, Json(json!({"error": msg}))).into_response()` : statut + corps `{"error":"<msg>"}`
// BYTE-IDENTIQUES aux sites inline qu'elles remplacent (json! sérialise `String`/`&str` à l'identique).
// `err_json` est la base (statut variable) ; les 4 nommées figent le statut usuel.
/// UNE 500 LAISSE UNE TRACE QU'ON PEUT SUIVRE — des deux côtés.
///
/// CE QUI ÉTAIT CASSÉ (établi le 2026-08-02 par LECTURE et COMPTAGE, hors tests et hors
/// commentaires) : **234** chemins rendent un 5xx — **193** appels à `server_err(` et **41**
/// `INTERNAL_SERVER_ERROR` littéraux —, **aucun** TraceLayer / access-log n'est monté (déjà noté
/// dans `ingest/pubsub.rs`), et le mot `request_id` n'existe nulle part dans la couche HTTP. Le
/// client recevait `{"error":"erreur interne"}` et le serveur ne gardait **rien** : impossible de
/// relier le ticket d'un utilisateur à ce qui s'est passé sur la machine.
///
/// LA FORME DÉRIVÉE, ET SA PORTÉE EXACTE. On n'instrumente pas 234 sites : `err_json` est le point de
/// passage des erreurs JSON (`bad_req`/`forbidden`/`not_found`/`server_err` s'y réduisent), donc les
/// **197** chemins qui passent par lui — les 193 `server_err(` + 4 `err_json(INTERNAL_SERVER_ERROR…)`
/// — sont tracés d'un coup, y compris ceux qu'on ajoutera : la condition n'énumère aucun code, c'est
/// `code.is_server_error()`. Les 4xx (faute du client) gardent EXACTEMENT leur forme d'avant : aucun
/// champ ajouté, aucune ligne de journal.
///
/// CE QUE ÇA NE COUVRE PAS, COMPTÉ : **37** sites construisent leur 500 SANS passer par ici —
/// `(StatusCode::INTERNAL_SERVER_ERROR, "…").into_response()`, dont 10 dans `tenants.rs`, 7 dans
/// `handlers/admin_ui.rs`, 4 dans `handlers/notifiers.rs`, 4 dans `handlers/detection.rs`. Ils ne
/// rendent pas du JSON (corps texte nu) : les faire passer par `err_json` CHANGERAIT leur contrat de
/// réponse, ce qui n'est pas un correctif de traçabilité mais une modification d'API. Dette DÉCLARÉE
/// et comptée, pas un angle mort.
///
/// L'identifiant est court, greppable, et rendu au client : `plume-e<pid>-<n>`. Le journal du daemon
/// n'est PAS collecté par le collecteur `journal` (il ne suit que sshd/sudo/su) -> aucune boucle
/// d'auto-ingestion.
static ERR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn err_json(code: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    if code.is_server_error() {
        let n = ERR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = format!("plume-e{}-{n}", std::process::id());
        // La SEULE trace serveur d'un 5xx. `eprintln!` (stderr -> journald/conteneur), comme le reste
        // du diagnostic du daemon : aucune dépendance de journalisation ajoutée.
        eprintln!("[{id}] HTTP {} : {msg}", code.as_u16());
        return (code, Json(json!({ "error": msg, "id": id }))).into_response();
    }
    (code, Json(json!({ "error": msg }))).into_response()
}
/// #59 — valeur d'un flag CLI `--k <v>` dans argv (None si absent/sans valeur). Helper des sous-commandes.
fn flag_val(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
fn bad_req(msg: impl Into<String>) -> Response { err_json(StatusCode::BAD_REQUEST, msg) }
fn forbidden(msg: impl Into<String>) -> Response { err_json(StatusCode::FORBIDDEN, msg) }
fn not_found(msg: impl Into<String>) -> Response { err_json(StatusCode::NOT_FOUND, msg) }
fn server_err(msg: impl Into<String>) -> Response { err_json(StatusCode::INTERNAL_SERVER_ERROR, msg) }

// Accès ergonomique aux champs d'un corps JSON. Chaque méthode reproduit EXACTEMENT
// le motif inline `b.get(k).and_then(|v| v.as_T()).unwrap_or(def)` qu'elle remplace : mêmes défauts, mêmes
// types de retour, substitution mécanique byte-identique prouvée par la suite de tests. `str_field` fige
// le défaut `""` (seule variante inline courante) ; `i64_field`/`bool_field` gardent le défaut par site.
trait JsonBody {
    fn str_field(&self, k: &str) -> &str;
    fn trimmed(&self, k: &str) -> String;
    fn i64_field(&self, k: &str, def: i64) -> i64;
    fn bool_field(&self, k: &str, def: bool) -> bool;
}
impl JsonBody for serde_json::Value {
    fn str_field(&self, k: &str) -> &str { self.get(k).and_then(|v| v.as_str()).unwrap_or("") }
    fn trimmed(&self, k: &str) -> String { self.str_field(k).trim().to_string() }
    fn i64_field(&self, k: &str, def: i64) -> i64 { self.get(k).and_then(|v| v.as_i64()).unwrap_or(def) }
    fn bool_field(&self, k: &str, def: bool) -> bool { self.get(k).and_then(|v| v.as_bool()).unwrap_or(def) }
}


/// Sous-commandes qui n'existent QUE dans certains builds. Le dispatch de `cold-backup-plan` est
/// `#[cfg(feature = "cold_tier")]` : sans la feature, la branche N'EXISTE PAS. L'aide doit le dire
/// (« indisponible » plutôt que de la promettre), et le rejet doit le dire aussi — sinon un
/// opérateur qui suit la doc du tier froid lit « argument inconnu » et croit à une faute de frappe.
#[cfg(feature = "cold_tier")]
const SUBCOMMANDS_COLD: [(&str, &str); 1] =
    [("cold-backup-plan", "cold-backup-plan — plan de sauvegarde du tier froid (lecture seule)")];
#[cfg(not(feature = "cold_tier"))]
const SUBCOMMANDS_COLD: [(&str, &str); 1] = [(
    "cold-backup-plan",
    "cold-backup-plan — INDISPONIBLE dans ce binaire (compilé sans `--features cold_tier`)",
)];

/// LES SOUS-COMMANDES DU DAEMON, avec leur ligne d'aide. Sert UNIQUEMENT à l'affichage : la
/// détection d'une sous-commande INCONNUE, elle, n'est PAS une comparaison à cette liste (cf. la
/// garde en bas de `main`). La liste est tenue alignée sur le code par
/// `aide_cli_liste_les_memes_sous_commandes_que_le_dispatch` (elle lit `main.rs`).
const SUBCOMMANDS: [(&str, &str); 16] = [
    ("hashpw", "hashpw [<mdp>] — hash argon2 d'un mot de passe (stdin si omis)"),
    ("respond", "respond — boucle du moteur de réponse (service séparé)"),
    ("verify", "verify — vérifie la chaîne d'intégrité du ledger"),
    ("ledger-export", "ledger-export [--from <id>] [--out <f>] — export JSONL du ledger"),
    ("ledger-verify-export", "ledger-verify-export <f> — vérifie un export hors-ligne"),
    ("scim-token", "scim-token — génère/affiche le jeton SCIM"),
    ("token", "token <sous-commande> — jetons d'agent"),
    ("sigma-import", "sigma-import <chemin> — importe des règles Sigma"),
    ("retention", "retention — applique la rétention maintenant"),
    ("purge", "purge — purge ciblée (cf. docs/PURGE.md)"),
    ("backup", "backup [--out <f>] — sauvegarde chiffrée"),
    ("restore", "restore <f> — restaure une sauvegarde"),
    ("backup-verify", "backup-verify <f> — vérifie une sauvegarde sans restaurer"),
    ("backup-prune-plan", "backup-prune-plan — plan de purge des sauvegardes (lecture seule)"),
    ("migrate-check", "migrate-check — compare le schéma live au code (lecture seule)"),
    ("db-stats", "db-stats — occupation disque SQLite (lecture seule)"),
];

fn usage() -> String {
    let mut s = String::from(
        "plume-daemon — SOC/XDR souverain.\n\n\
         Usage :\n  \
         plume-daemon                    lance le serveur (aucun argument)\n  \
         plume-daemon <sous-commande>    outil ponctuel, puis sortie\n  \
         plume-daemon --version          version + version de schéma attendue\n\n\
         Sous-commandes :\n",
    );
    for (_, aide) in SUBCOMMANDS.iter().chain(SUBCOMMANDS_COLD.iter()) {
        s.push_str(&format!("  {aide}\n"));
    }
    s.push_str(
        "\nConfiguration : variables PLUME_* (cf. README.md). `<sous-commande> --help` quand elle\n\
         en propose une (p. ex. migrate-check).\n",
    );
    s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("hashpw") {
        let pw = match args.get(2) {
            Some(p) => p.clone(),
            None => {
                use std::io::Read;
                let mut s = String::new();
                let _ = std::io::stdin().read_to_string(&mut s);
                s.trim().to_string()
            }
        };
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        match argon2::Argon2::default().hash_password(pw.as_bytes(), &salt) {
            Ok(h) => println!("{h}"),
            Err(e) => {
                eprintln!("erreur hash: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("respond") {
        respond_run();
        return;
    }
    if args.get(1).map(String::as_str) == Some("verify") {
        verify_run();
        return;
    }
    // #59 — EXPORT du ledger (chaîne préservée) : `plume-daemon ledger-export [--from <id>] [--out <file>]`.
    // JSONL id,ts,kind,detail,prev_hash,hash à partir de --from (exclu ; défaut 0 = complet). READ-ONLY
    // (SELECT seul sur `ledger` -> aucune mutation). --out écrit un fichier (append-only WORM-friendly),
    // sinon stdout. La copie est vérifiable hors-ligne (ledger-verify-export).
    if args.get(1).map(String::as_str) == Some("ledger-export") {
        let from: i64 = flag_val(&args, "--from").and_then(|s| s.parse().ok()).unwrap_or(0).max(0);
        let out = flag_val(&args, "--out");
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        // SANS CONTRAT, assumé : l'export du ledger est un outil de DIAGNOSTIC (SELECT seul) et la
        // base qu'on veut exporter est souvent justement celle qui a un problème. Le refuser sur une
        // base abîmée retirerait la preuve au moment où elle sert.
        let conn = match open_db_without_schema_contract(&db_path) {
            Ok(c) => c,
            Err(e) => { eprintln!("ledger-export: ouverture {db_path}: {e}"); std::process::exit(2); }
        };
        let (lines, last_id, last_hash) = ledger_export_lines(&conn, from, 0);
        match &out {
            Some(path) => {
                // CLI opérateur (shell de confiance) -> confine_root=None : chemin d'export LIBRE (inchangé).
                if let Err(e) = ledger_sink_write("file", path, &lines, None) { eprintln!("ledger-export: {e}"); std::process::exit(2); }
                eprintln!("ledger-export : {} entrées -> {path} (last_id={last_id}, last_hash={last_hash})", lines.len());
            }
            None => {
                let _ = ledger_sink_write("stdout", "", &lines, None);
                eprintln!("ledger-export : {} entrées (last_id={last_id}, last_hash={last_hash})", lines.len());
            }
        }
        return;
    }
    // #59 — VÉRIFICATION EXTERNE d'une copie exportée : `plume-daemon ledger-verify-export <fichier>
    // [--prev <hash>]`. Recompute la chaîne de hash sur le JSONL (indépendamment de la base) -> OK/rupture.
    // --prev = hash attendu avant la 1re ligne (export incrémental) ; défaut "" (genesis / export complet).
    if args.get(1).map(String::as_str) == Some("ledger-verify-export") {
        let path = match args.iter().skip(2).find(|a| !a.starts_with('-')) {
            Some(p) => p.clone(),
            None => { eprintln!("usage : plume-daemon ledger-verify-export <fichier> [--prev <hash>]"); std::process::exit(2); }
        };
        let prev = flag_val(&args, "--prev").unwrap_or_default();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => { eprintln!("ledger-verify-export: lecture {path}: {e}"); std::process::exit(2); }
        };
        let lines: Vec<String> = content.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
        match ledger_verify_export(&lines, &prev) {
            Ok(n) => println!("export OK : {n} entrées chaînées intègres (vérifié hors-ligne)"),
            Err(e) => { println!("EXPORT COMPROMIS : {e}"); std::process::exit(1); }
        }
        return;
    }
    // #59 — jeton SCIM : `plume-daemon scim-token <tenant> [description]`. Crée un bearer de provisioning
    // (stocké HASHÉ sha256 dans le control-plane), scopé au tenant. Affiché UNE fois. Mode 1 (control-plane).
    if args.get(1).map(String::as_str) == Some("scim-token") {
        let tenant = match args.get(2) {
            Some(t) => t.clone(),
            None => { eprintln!("usage : plume-daemon scim-token <tenant> [description]"); std::process::exit(2); }
        };
        let desc = args.get(3).cloned().unwrap_or_default();
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        let cp = match init_control_plane(&conf, &db_path) {
            Ok(cp) => cp,
            Err(e) => { eprintln!("scim-token: control-plane indisponible: {e}"); std::process::exit(2); }
        };
        let mut b = [0u8; 32];
        {
            use std::io::Read;
            std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("urandom");
        }
        let token = hex_encode(&b);
        {
            let conn = cp.conn.lock();
            conn.execute("INSERT INTO scim_token(hash,tenant_id,description,created) VALUES(?1,?2,?3,?4)", params![sha256_hex(token.as_bytes()), tenant, desc, now()])
                .expect("insert scim_token");
        }
        println!("{token}");
        eprintln!("jeton SCIM pour le tenant '{tenant}' créé (Authorization: Bearer <token>) — affiché une seule fois.");
        return;
    }
    if args.get(1).map(String::as_str) == Some("token") {
        // crée un token d'agent : `plume-daemon token <name> <hôte>` (machine) OU `<name> --relais`
        // (forwarder multi-hôtes). Affiche le secret UNE fois (SHA-256 stocké). P5.2-b : la PORTÉE est
        // désormais DÉCLARÉE — la forme à deux arguments produisait un jeton non lié, avec lequel une
        // enveloppe `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` était acceptée et stockée sous ce nom (mesuré
        // le 2026-08-02). Le liage est aussi ce qui autorise le responder à agir sur cet hôte.
        let name = args.get(2).cloned().unwrap_or_else(|| "agent".into());
        let relais = args.iter().skip(3).any(|a| a == "--relais");
        let portee = match PorteeJeton::declarer(args.get(3).filter(|a| !a.starts_with("--")).map(String::as_str), relais) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("usage : plume-daemon token <nom> <hôte> | plume-daemon token <nom> --relais\n{e}");
                std::process::exit(2);
            }
        };
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        let mut b = [0u8; 32];
        {
            use std::io::Read;
            std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("urandom");
        }
        let token = hex_encode(&b);
        // Schéma qui n'est pas celui attendu -> on n'écrit pas de token dans une base à moitié migrée
        // (code 1 : la CLI est scriptée, un échec doit être détectable par `$?`). La PORTE le fait —
        // et depuis qu'elle le fait, une base PLUS RÉCENTE que ce binaire est refusée ici aussi.
        let conn = match PreparedDb::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[schema] {e} — token NON créé. Arrêt propre.");
                std::process::exit(1);
            }
        };
        inserer_jeton(&conn, &name, &sha256_hex(token.as_bytes()), None, None, &portee).expect("insert token");
        println!("{token}");
        match portee.hote_lie() {
            Some(h) => eprintln!("token agent '{name}' lié à l'hôte '{h}' créé — PLUME_TOKEN=... (responder autorisé sur cet hôte). Affiché une seule fois."),
            None => eprintln!("token RELAIS '{name}' créé — PLUME_TOKEN=... L'hôte des lignes reste celui que l'ÉMETTEUR déclare : il n'est PAS attesté, et quiconque tient ce jeton peut écrire sous n'importe quel nom d'hôte. Réservé aux forwarders multi-hôtes ; pour une machine, relancez avec son hôte. Affiché une seule fois."),
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("sigma-import") {
        // `plume-daemon sigma-import <fichier|dossier> [--dry-run]` — traduit des règles Sigma (YAML/JSON)
        // en règles Plume (GXQL) et les UPSERT en base (managed=2), OU affiche seulement le plan (--dry-run).
        // Émet un rapport JSON (importées / ignorées-avec-raison / résumé) sur stdout. GitOps -> préférer
        // config.d/sigma/ (managed=1) ; ce sous-commande sert l'import opérateur ponctuel / le pré-vol.
        let dry = args.iter().skip(2).any(|a| a == "--dry-run" || a == "-n");
        let path = match args.iter().skip(2).find(|a| !a.starts_with('-')) {
            Some(p) => p.clone(),
            None => { eprintln!("usage : plume-daemon sigma-import <fichier|dossier> [--dry-run]"); std::process::exit(2); }
        };
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        let p = std::path::Path::new(&path);
        let files: Vec<std::path::PathBuf> = if p.is_dir() {
            sigma_overlay_files(p)
        } else if p.is_file() {
            vec![p.to_path_buf()]
        } else {
            eprintln!("sigma-import : chemin introuvable : {path}"); std::process::exit(2);
        };
        let mut docs: Vec<(String, Value)> = Vec::new();
        for f in &files {
            match std::fs::read_to_string(f) {
                Ok(txt) => match sigma_yaml_to_docs(&txt) {
                    Ok(ds) => { for d in ds { docs.push((f.display().to_string(), d)); } }
                    Err(e) => eprintln!("[sigma] {} : parse : {e} — ignoré", f.display()),
                },
                Err(e) => eprintln!("[sigma] {} : lecture : {e} — ignoré", f.display()),
            }
        }
        // MÊME contrat de schéma que `token`, et par la MÊME porte (le booléen de `migrate` était JETÉ
        // ici : on UPSERTait des règles de détection dans une base dont on savait le schéma incomplet).
        // `--dry-run` n'ouvre aucune base -> rien à préparer, l'import est purement calculatoire.
        let conn = if dry {
            None
        } else {
            match PreparedDb::open(&db_path) {
                Ok(c) => Some(c),
                Err(e) => {
                    eprintln!("[schema] {e} — AUCUNE règle importée. Arrêt propre.");
                    std::process::exit(1);
                }
            }
        };
        let (mut imported, mut skipped): (Vec<Value>, Vec<Value>) = (Vec::new(), Vec::new());
        for (origin, d) in &docs {
            let title = d.get("title").and_then(|v| v.as_str()).unwrap_or("(sans titre)").to_string();
            match sigma_translate(d) {
                Ok(t) => {
                    if let Some(c) = &conn {
                        // #31 (cohérence avec e46a2f7) : dédup par `sigma_id` (UUID stable) D'ABORD — capte une
                        // DÉRIVE de titre (même règle, titre changé -> UPDATE, pas de doublon) — sinon par nom
                        // (comportement historique). MÊME résolution que les chemins web/bulk (sigma_find_existing).
                        let existing = sigma_find_existing(c, &t); // Option<(rowid, managed)>
                        // ADDITIF : ne pas écraser un overlay git (managed=1) NI une détection
                        // native (builtin/seed, managed=0). Seul managed=2 (ad-hoc) est mis à jour.
                        if let SigmaDisp::SkipManaged(m) = sigma_import_disposition(existing.map(|(_, m)| m)) {
                            let reason = if m == 1 { "existe comme overlay géré (managed=1) — non écrasé" }
                                         else { "existe comme détection native (builtin/seed, managed=0) — NON écrasée par un import Sigma" };
                            skipped.push(json!({ "title": t.name, "reason": reason, "source": origin }));
                            continue;
                        }
                        match existing {
                            // UPDATE ciblé par ROWID (résolu par sigma_id/nom) : rafraîchit la logique + `name`
                            // (titre possiblement DÉRIVÉ) + `sigma_id` (back-fill), (ré)active la règle.
                            Some((rowid, _)) => {
                                c.execute("UPDATE rule SET name=?1, enabled=1, query=?2, is_soql=1, op=?3, threshold=?4, severity=?5, interval_s=?6, window_s=?7, mitre=?8, sigma_id=?9, managed=2 WHERE id=?10",
                                    params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.sigma_id, rowid]).expect("update rule");
                            }
                            None => {
                                c.execute("INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,sigma_id,managed) VALUES(?1,1,?2,1,?3,?4,?5,?6,?7,?8,?9,2)",
                                    params![t.name, t.query, t.op, t.threshold, t.severity, t.interval_s, t.window_s, t.mitre, t.sigma_id]).expect("insert rule");
                            }
                        }
                    }
                    imported.push(json!({ "name": t.name, "severity": t.severity, "mitre": t.mitre, "query": t.query, "warnings": t.warnings, "source": origin }));
                }
                Err(e) => skipped.push(json!({ "title": title, "reason": e, "source": origin })),
            }
        }
        let report = json!({
            "dry_run": dry,
            "imported": imported,
            "skipped": skipped,
            "summary": { "imported": imported.len(), "skipped": skipped.len(), "files": files.len() }
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }
    if args.get(1).map(String::as_str) == Some("retention") {
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        // La rétention SUPPRIME des lignes : elle passe par la porte comme tout le reste. Mesuré AVANT
        // ce correctif, avec le vrai binaire : sur une base estampillée 111 amputée de `net_ban` (celle
        // que le daemon refuse de servir) `retention` sortait en 0 et annonçait « rétention OK ».
        let conn = match PreparedDb::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[schema] {e} — AUCUNE rétention appliquée. Arrêt propre.");
                std::process::exit(1);
            }
        };
        let db = Arc::new(Mutex::new(conn.into_connection()));
        retention_run(&db);
        println!("rétention OK");
        return;
    }
    // PURGE EXPLICITE D'ÉVÉNEMENTS — sous-commande DEUX TEMPS. Sans `--confirm`, elle SIMULE : elle rend le
    // compte EXACT, la ventilation par source, un échantillon des deux extrémités, ce qu'elle NE couvre PAS,
    // et un JETON qui est l'empreinte de ce résultat. Avec `--confirm <jeton>`, elle RE-SIMULE, compare, puis
    // exécute — donc un jeton rejoué ou un contenu qui a bougé entre les deux échoue.
    //
    // POURQUOI LA CLI EST LE CHEMIN PRINCIPAL : purger, c'est détruire des preuves. Ici l'appelant possède
    // déjà la clé SQLCipher et l'accès à l'hôte — soit exactement le pouvoir qu'il faudrait pour effacer la
    // base à la main. La sous-commande n'ajoute donc AUCUNE capacité nouvelle ; elle remplace un `DELETE`
    // manuel non tracé par un chemin borné, simulé, confirmé et INSCRIT AU REGISTRE. La surface HTTP, elle,
    // ajouterait une capacité de destruction À DISTANCE : elle existe (admin-only) mais reste FERMÉE par
    // défaut (`PLUME_PURGE_API`).
    if args.get(1).map(String::as_str) == Some("purge") {
        purge_cli(&args);
        return;
    }
    if args.get(1).map(String::as_str) == Some("backup") {
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        // `backup --compress [dest]` -> format age(zstd(sqlite clair)), ~5-10x plus petit (voir backup_compressed).
        // `backup [dest]`            -> mode HISTORIQUE : VACUUM INTO (copie SQLCipher chiffrée, incompressible).
        let compress = args.iter().skip(2).any(|a| a == "--compress" || a == "-z");
        // premier argument positionnel (non-flag) après le sous-commande = destination.
        let dest_pos = args.iter().skip(2).find(|a| !a.starts_with('-')).cloned();
        if compress {
            let dest = dest_pos.unwrap_or_else(|| format!("{db_path}.age"));
            // F3 — destinataire age asymétrique (clé publique, non-secret) si PLUME_BACKUP_AGE_RECIPIENT posé ;
            // sinon None -> passphrase symétrique (clé SQLCipher) = comportement historique (inerte par défaut).
            let recipient = backup_age_recipient();
            match backup_compressed(&db_path, &dest, db_key().as_deref(), recipient.as_deref()) {
                Ok(st) => {
                    // v135 (#7) — SIGNAL SOC NON-PURGEABLE émis depuis le VRAI chemin backup (ce sidecar) UNIQUEMENT
                    // quand un backup SYMÉTRIQUE a réellement été produit (recipient absent). Anciennement (v134) le
                    // signal partait à tort au boot du conteneur PRINCIPAL (server::run) qui NE fait JAMAIS de backup
                    // -> faux positif « posture dégradée » à chaque restart. Ici le repli symétrique est PROUVÉ (le
                    // backup vient d'aboutir sans destinataire) -> signal légitime. Best-effort : un échec d'ouverture
                    // DB writer ne bloque pas le backup déjà produit.
                    // Ce signal ÉCRIT (un événement SOC) -> il passe par la porte. Best-effort DANS LES
                    // DEUX SENS : un contrat non satisfait ne casse pas le backup DÉJÀ produit, mais il
                    // n'écrit rien non plus — il le DIT, au lieu d'écrire sur un schéma inconnu.
                    match PreparedDb::open(&db_path) {
                        Ok(conn) => { let _ = signal_backup_symmetric_if_needed(&conn, recipient.as_deref(), now()); }
                        Err(e) => eprintln!("[backup] signal de posture NON émis (la base n'a pas passé le contrat de schéma : {e})"),
                    }
                    let ratio = if st.dest_bytes > 0 { st.plaintext_bytes as f64 / st.dest_bytes as f64 } else { 0.0 };
                    println!(
                        "backup (compressé+chiffré) -> {dest}  plaintext={} o  dest={} o  ratio={:.1}x  format=age(zstd(sqlite))",
                        st.plaintext_bytes, st.dest_bytes, ratio);
                }
                Err(e) => {
                    eprintln!("backup --compress : {e}");
                    std::process::exit(1);
                }
            }
        } else {
            // sauvegarde compacte (VACUUM INTO) -> copie cohérente même DB ouverte
            let dest = dest_pos.unwrap_or_else(|| format!("{db_path}.bak"));
            // SANS CONTRAT, assumé (même raison que `backup --compress` ci-dessus) : sauvegarder une
            // base ABÎMÉE est précisément ce qu'on veut pouvoir faire — c'est ce que le message de refus
            // du daemon demande à l'opérateur AVANT de réparer.
            match open_db_without_schema_contract(&db_path).and_then(|c| c.execute("VACUUM INTO ?1", params![dest]).map(|_| ())) {
                Ok(_) => println!("backup -> {dest}"),
                Err(e) => {
                    eprintln!("backup: {e}");
                    std::process::exit(1);
                }
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("restore") {
        // `restore <src.age> [dest_db] [--force]` : déchiffre+décompresse <src> (format age(zstd(sqlite)))
        // puis re-chiffre en SQLCipher vers [dest_db] (défaut = PLUME_DB). REFUSE d'écraser sans --force.
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        let force = args.iter().skip(2).any(|a| a == "--force" || a == "-f");
        let positionals: Vec<String> = args.iter().skip(2).filter(|a| !a.starts_with('-')).cloned().collect();
        let src = match positionals.first() {
            Some(s) => s.clone(),
            None => {
                eprintln!("usage : plume-daemon restore <src.age> [dest_db] [--force]");
                std::process::exit(2);
            }
        };
        let dest_db = positionals.get(1).cloned().unwrap_or(db_path);
        // F3 — identité age PRIVÉE (escrow, hors-cluster) fournie au DR via PLUME_BACKUP_AGE_IDENTITY[_FILE] ;
        // None -> déchiffrement passphrase (anciens backups symétriques). age auto-détecte selon l'en-tête.
        let identity = backup_age_identity();
        match restore_compressed(&src, &dest_db, db_key().as_deref(), force, identity.as_ref()) {
            Ok(_) => println!("restore -> {dest_db}  (depuis {src})  [SQLCipher rejouable]"),
            Err(e) => {
                eprintln!("restore : {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("backup-verify") {
        // F3 — `backup-verify <src.age>` : contrôle STRUCTUREL (en-tête age v1 + stanza + taille) toujours ;
        // vérif COMPLÈTE (déchiffre+ouvre) seulement si l'identité requise est dispo EN cluster (Symmetric =
        // PLUME_DB_KEY ; Asymmetric = PLUME_BACKUP_AGE_IDENTITY escrow, normalement ABSENTE -> structurel-seul).
        // Sortie 0 = structurellement valide (full_verified indiqué) ; 1 = corrompu/illisible.
        let positionals: Vec<String> = args.iter().skip(2).filter(|a| !a.starts_with('-')).cloned().collect();
        let src = match positionals.first() {
            Some(s) => s.clone(),
            None => { eprintln!("usage : plume-daemon backup-verify <src.age>"); std::process::exit(2); }
        };
        let identity = backup_age_identity();
        match verify_backup(&src, db_key().as_deref(), identity.as_ref()) {
            Ok((kind, full)) => {
                println!("backup-verify -> {src}  kind={kind:?}  full_decrypt_verified={full}{}",
                    if full { "" } else { "  (structurel-seul ; vérif complète = DRILL DR avec identité escrow)" });
            }
            Err(e) => { eprintln!("backup-verify : {e}"); std::process::exit(1); }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("backup-prune-plan") {
        // RÉTENTION GFS À PALIERS — logique de SÉLECTION PURE (aucun accès S3/mc/suppression ici : le
        // sidecar garde `mc`). Lit les NOMS d'objets sur STDIN (un par ligne — le sidecar y pipe la sortie
        // `mc ls`), écrit sur STDOUT UNIQUEMENT les noms à SUPPRIMER (un par ligne -> `mc rm` un-par-un côté
        // sidecar = un seul DeleteObject, jamais récursif/multi -> pas de faux T1490). Tous les logs -> STDERR.
        // Paramètres env : PLUME_BACKUP_{DENSE,DAILY,WEEKLY}_DAYS + PLUME_BACKUP_PREMIGRATE_KEEP (défauts 2/14/90/2).
        use std::io::BufRead;
        let params = GfsParams::from_env();
        let names: Vec<String> = std::io::stdin().lock().lines()
            .map_while(Result::ok)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let plan = backup_prune_plan(&names, now(), &params);
        eprintln!(
            "[backup-prune-plan] entrées={} à_supprimer={}  (dense={}j daily={}j weekly={}j premigrate_keep={})",
            names.len(), plan.len(), params.dense_days, params.daily_days, params.weekly_days, params.premigrate_keep);
        // STDOUT = SEULEMENT les noms à supprimer (contrat : rien d'autre ne sort sur stdout).
        let mut out = String::new();
        for name in &plan { out.push_str(name); out.push('\n'); }
        print!("{out}");
        return;
    }
    // TIER FROID 2-TIER BACKUP (#18) — sous-commande `cold-backup-plan`, MIROIR de `backup-prune-plan` (logique de
    // SÉLECTION PURE, aucun accès S3/mc/copie ici : le sidecar garde `mc`). Le tier froid est déjà zstd + chiffré
    // age (AEAD) + IMMUABLE dès qu'un jour-file est scellé -> le backup cold = COPIE VERBATIM INCRÉMENTALE des
    // fichiers NOUVELLEMENT scellés absents du remote. Lit les CLÉS d'objets DÉJÀ présentes au remote sur STDIN
    // (une/ligne — le sidecar y pipe sa sortie `mc ls --recursive`), écrit sur STDOUT UNIQUEMENT `<chemin local>\t
    // <clé objet>` par fichier À COPIER (le sidecar exécute le `mc cp` un-par-un). Tous les logs -> STDERR.
    //
    // POSTURE DE CONFIANCE (identique à backup-prune-plan) : ZÉRO credential S3, ZÉRO copie/suppression dans le
    // daemon — il ne fait qu'ÉMETTRE des chemins. EXEMPT de PLUME_BACKUP_REQUIRE_ASYMMETRIC : le tier froid est
    // symétrique PAR CONCEPTION (escrow VERBATIM = option a), pas un repli dégradé -> ce gate (qui vise le hot
    // node-déchiffrable) NE s'applique PAS ici. DR : restaurer le tier froid depuis l'escrow EXIGE la clé du TENANT
    // (domaine Vault, la même clé SQLCipher dont dérive l'AEAD cold) ; l'escrow ASYMÉTRIQUE ne couvre QUE le hot.
    // Gaté `#[cfg(feature = "cold_tier")]` -> sans la feature la sous-commande N'EXISTE PAS (mode 0 byte-identique).
    #[cfg(feature = "cold_tier")]
    if args.get(1).map(String::as_str) == Some("cold-backup-plan") {
        use std::io::BufRead;
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        // Racine cold = MÊME dérivation par-tenant que l'aging (cold_root) -> jamais de divergence de chemin.
        let cold_dir = cold_store::cold_root(&conf, &db_path);
        // tenant_prefix : cette sous-commande tourne pour le TENANT DÉFAUT (PLUME_DB), comme `backup`/`backup-verify`
        // -> préfixe "default". Un escrow MULTI-TENANT (mode PLUME_MULTI_TENANT) itérerait les tenants et passerait
        // un préfixe stable par-tenant (basename du db_path) ; hors périmètre de ce sidecar mono-tenant.
        let tenant_prefix = "default";
        // Clés objets DÉJÀ au remote (STDIN) -> l'ensemble à partir duquel on calcule le DELTA à copier.
        let remote_keys: std::collections::HashSet<String> = std::io::stdin().lock().lines()
            .map_while(Result::ok)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        // Ouvre la base du tenant (clé SQLCipher) pour lire l'index cold_seal (métadonnées ; AUCUNE clé de
        // DÉCHIFFREMENT cold requise -> on ne lit AUCUN fichier Parquet). Garde de lisibilité : une clé fausse
        // ferait retourner un plan VIDE silencieux (= trou d'escrow) -> on ÉCHOUE bruyamment (exit 1).
        // SANS CONTRAT, assumé : ce plan est un CALCUL DE SAUVEGARDE (SELECT sur l'index cold_seal).
        // Le refuser sur une base au schéma inattendu ferait sauter l'escrow du tier froid au moment
        // exact où la base va mal — soit un TROU de sauvegarde, la panne qu'on veut le moins.
        let conn = match open_db_without_schema_contract(&db_path) {
            Ok(c) => c,
            Err(e) => { eprintln!("[cold-backup-plan] ouverture DB {db_path} : {e}"); std::process::exit(1); }
        };
        if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
            eprintln!("[cold-backup-plan] base illisible (clé PLUME_DB_KEY incorrecte ?) : {e}");
            std::process::exit(1);
        }
        let plan = cold_store::cold_backup_plan(&conn, &cold_dir, tenant_prefix, &remote_keys);
        eprintln!(
            "[cold-backup-plan] remote_keys={} à_copier={}  cold_dir={}  tenant_prefix={tenant_prefix}",
            remote_keys.len(), plan.len(), cold_dir.display());
        // STDOUT = SEULEMENT `<chemin local>\t<clé objet>` par fichier à copier (contrat : rien d'autre sur stdout).
        let mut out = String::new();
        for item in &plan {
            out.push_str(&item.local.to_string_lossy());
            out.push('\t');
            out.push_str(&item.key);
            out.push('\n');
        }
        print!("{out}");
        return;
    }
    if args.get(1).map(String::as_str) == Some("migrate-check") {
        // #23 — migrate-check : compare le schéma LIVE (meta.schema_version) à CODE_SCHEMA_MAX SANS migrer ni
        // écrire. But : un initContainer peut SAUTER le snapshot pré-migrate (coûteux) quand aucune migration
        // ne tournera. LECTURE SEULE (open read-only), rapide, AUCUN effet de bord.
        //   Exit 0 = migration EN ATTENTE (live < CODE_SCHEMA_MAX) -> l'appelant DOIT faire le snapshot pré-migrate ;
        //   Exit 1 = À JOUR (live >= CODE_SCHEMA_MAX)              -> aucune migration -> snapshot INUTILE ;
        //   Exit 2 = ERREUR (base introuvable/illisible)          -> l'appelant décide (fail-safe : faire le snapshot).
        if args.iter().skip(2).any(|a| a == "-h" || a == "--help") {
            println!(
                "usage : plume-daemon migrate-check\n  \
                 Compare meta.schema_version (LIVE) a CODE_SCHEMA_MAX={CODE_SCHEMA_MAX} SANS migrer (lecture seule, aucun effet de bord).\n  \
                 Base = $PLUME_DB (defaut /var/lib/plume/db/plume.db).\n  \
                 Codes de sortie :\n    \
                 0 = migration EN ATTENTE (live < {CODE_SCHEMA_MAX}) -> snapshot pre-migrate REQUIS\n    \
                 1 = A JOUR           (live >= {CODE_SCHEMA_MAX}) -> snapshot pre-migrate INUTILE\n    \
                 2 = ERREUR (base illisible/introuvable) -> l'appelant decide"
            );
            return;
        }
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        // Ouverture STRICTEMENT read-only (SQLITE_OPEN_READ_ONLY) + clé SQLCipher si présente -> aucune
        // écriture, aucun WAL-checkpoint, aucune migration. read_schema_version retombe sur 1 si meta illisible.
        let conn = match Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => {
                apply_key(&c);
                c
            }
            Err(e) => {
                eprintln!("migrate-check: ouverture read-only {db_path}: {e} [exit 2]");
                std::process::exit(2);
            }
        };
        let live = read_schema_version(&conn);
        if live < CODE_SCHEMA_MAX {
            eprintln!("[migrate-check] schema LIVE={live} < CODE_SCHEMA_MAX={CODE_SCHEMA_MAX} -> migration EN ATTENTE (snapshot pre-migrate REQUIS) [exit 0]");
            std::process::exit(0);
        }
        eprintln!("[migrate-check] schema LIVE={live} >= CODE_SCHEMA_MAX={CODE_SCHEMA_MAX} -> A JOUR (snapshot pre-migrate inutile) [exit 1]");
        std::process::exit(1);
    }
    if args.get(1).map(String::as_str) == Some("db-stats") {
        // db-stats : rapport LECTURE SEULE de l'occupation disque SQLite. Sert à DÉCIDER si un reclaim
        // (VACUUM / auto_vacuum=INCREMENTAL) vaut le coup : en régime permanent (ingest ≈ purge) SQLite
        // RÉUTILISE les pages libérées -> freelist petite -> reclaim marginal. Open read-only + clé
        // SQLCipher, AUCUN effet de bord, AUCUN WAL-checkpoint (lecteur concurrent sûr en WAL).
        let conf = load_config();
        let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        let conn = match Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(c) => { apply_key(&c); c }
            Err(e) => { eprintln!("db-stats: ouverture read-only {db_path}: {e}"); std::process::exit(2); }
        };
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(-1) };
        let page_size = q("PRAGMA page_size").max(0);
        let page_count = q("PRAGMA page_count").max(0);
        let freelist = q("PRAGMA freelist_count").max(0);
        let av = q("PRAGMA auto_vacuum"); // 0=none 1=full 2=incremental
        let total = page_size * page_count;
        let free = page_size * freelist;
        let events = conn.query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0)).unwrap_or(-1);
        let pct = if total > 0 { free as f64 * 100.0 / total as f64 } else { 0.0 };
        let mib = |b: i64| b as f64 / (1024.0 * 1024.0);
        println!("db-stats {db_path}");
        println!("  page_size={page_size} page_count={page_count} auto_vacuum={av} (0=none 1=full 2=incremental)");
        println!("  total    = {:.1} MiB ({total} o)", mib(total));
        println!("  freelist = {:.1} MiB ({free} o, {pct:.1}% RÉCUPÉRABLE par VACUUM)", mib(free));
        println!("  live     = {:.1} MiB", mib(total - free));
        println!("  events   = {events}");
        return;
    }
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    // ON N'ARRIVE ICI QUE SI AUCUNE SOUS-COMMANDE N'A RÉCLAMÉ L'ARGUMENT.
    //
    // CE QUI ÉTAIT CASSÉ (mesuré le 2026-08-02 sur le binaire release) : tout argument non reconnu
    // TOMBAIT dans le lancement du serveur. `plume-daemon --help` ne paniquait pas — il MIGRAIT LA
    // BASE, imprimait un JETON D'INSTALLATION à usage unique et se mettait à écouter sur :7000 ; il a
    // fallu le TUER (rc=124 sous `timeout 8`). Idem pour `--version`, `help`, et — c'est le cas qui
    // coûte — une sous-commande MAL ORTHOGRAPHIÉE : `plume-daemon bakcup` dans un timer de
    // maintenance ne sauvegarde rien et laisse un SECOND serveur vivant sur la machine.
    //
    // LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE : chaque bloc de sous-commande ci-dessus `return`/`exit`.
    // Atteindre cette ligne avec un `argv[1]` signifie donc, PAR CONSTRUCTION, qu'aucune branche ne
    // l'a reconnu — c'est le COMPLÉMENT calculé par le flot de contrôle. Une 18ᵉ sous-commande
    // ajoutée demain est couverte sans que personne ne pense à cette ligne. `SUBCOMMANDS` ne sert
    // qu'à AFFICHER l'aide (et un test la maintient alignée sur le dispatch).
    //
    // Le serveur, lui, se lance SANS aucun argument — c'est ce que font `systemd/plume-daemon.service`
    // (`ExecStart=/usr/local/bin/plume-daemon`) et l'`ENTRYPOINT ["plume-daemon"]` du Dockerfile ;
    // `plume-respond.service` passe `respond`, qui est une sous-commande. Aucun appelant de
    // production ne passe autre chose : la garde ne peut pas casser un déploiement existant.
    // ─────────────────────────────────────────────────────────────────────────────────────────────
    if let Some(arg) = args.get(1) {
        if matches!(arg.as_str(), "-h" | "--help" | "help") {
            print!("{}", usage());
            return;
        }
        if matches!(arg.as_str(), "-V" | "--version" | "version") {
            println!("plume-daemon {} (schéma {CODE_SCHEMA_MAX})", env!("CARGO_PKG_VERSION"));
            return;
        }
        // Une sous-commande RÉELLE mais absente de CE build (feature désactivée) : le dire, plutôt
        // que « argument inconnu ». On n'arrive ici que si sa branche `cfg` n'a pas été compilée.
        if SUBCOMMANDS_COLD.iter().any(|(n, _)| *n == arg.as_str()) {
            eprintln!(
                "plume-daemon: « {arg} » n'existe que dans un binaire compilé avec \
                 `--features cold_tier` — celui-ci ne l'est pas. AUCUN serveur n'a été lancé."
            );
            std::process::exit(2);
        }
        eprint!("plume-daemon: argument inconnu « {arg} » — AUCUN serveur n'a été lancé.\n\n{}", usage());
        std::process::exit(2);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

#[cfg(test)]
mod tests;
