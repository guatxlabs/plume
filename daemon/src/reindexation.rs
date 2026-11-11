//! LA RÉINDEXATION D'UNE BASE DONT DES INDEX ONT DÉSACCORDÉ DE LEUR TABLE — UN GESTE D'ÉCRITURE BORNÉ À CE QU'UN
//! `REINDEX` RÉPARE.
//!
//! CE QUI MANQUAIT. `integrity-check --full` peut rendre « corrompu » avec, pour seules lignes, des index qui ne
//! comptent pas les mêmes entrées que leur table : une entrée d'index orpheline (présente dans l'index, ligne absente
//! de la table) laissée par un incident de journal délié (`P10.33-u`) suffit. Toute lecture dont le plan atteint
//! l'entrée rend `SQLITE_CORRUPT`. Le produit n'avait aucun geste d'écriture pour la réparer : `integrity-check` est en
//! lecture seule, l'API SQL de l'administrateur aussi.
//!
//! CE QUE FAIT `plume-daemon reindex [--dry-run] [--accepter-les-ecritures-refusees] [<chemin>]` :
//!   1. JUGE D'ABORD par le contrôle complet d'`integrity_check` (`Mode::Complet`, même ouverture, mêmes refus). Sain :
//!      rien à faire, sortie 0, rien d'ouvert en écriture. Refus de conclure : le même refus, sortie 2.
//!   2. N'ÉCRIT QUE SI TOUTES les lignes sont de la classe « index désaccordé de sa table » : `wrong # of entries in
//!      index X` et `row N missing from index X`, formes relevées sur le moteur LIÉ par le témoin qui fabrique le
//!      défaut. Une seule autre ligne (page, arbre, liste libre, valeur, texte inconnu, ligne sur plusieurs lignes), un
//!      `cipher_integrity_check` en défaut, sans verdict sous clé ou interrompu par une erreur du moteur
//!      (`cipher_integrity_check_erreur`), un contrôle dont la lecture s'est interrompue ou qui a atteint son plafond
//!      de lignes (`integrity_check::PLAFOND_DE_LIGNES`, la liste des défauts est alors tronquée) : REFUS, sortie 2,
//!      rien d'écrit, et la ligne qui fait refuser est nommée (`ligne_refusee`). Une réindexation ne répare pas une
//!      table abîmée, et la tenter masquerait le défaut.
//!   3. Chaque nom d'index tiré d'une ligne est RELU dans `sqlite_master` (`type='index'`, égalité exacte) par
//!      l'ouverture en lecture seule d'`integrity_check` ; absent : refus. Il n'est employé que cité comme identifiant
//!      (guillemets doublés), sous la forme qualifiée `REINDEX "main".<nom>` : sans nom de schéma, SQLite lirait
//!      d'abord le nom comme celui d'une collation.
//!   `--dry-run` s'arrête ici : sortie 1 (la base n'est pas saine), `plan` dit ce qui serait réindexé, rien n'est
//!   ouvert en écriture.
//!   4. UN INDEX PAR TRANSACTION, dans l'ordre de première apparition dans les lignes, sans doublon : `BEGIN IMMEDIATE`
//!      (`ouvrir_sa_transaction`), `REINDEX`, `COMMIT` (`valider_la_transaction`) ; le verrou d'écriture est rendu entre
//!      deux index. L'attente pour PRENDRE le verrou est bornée (`ATTENTE_POUR_PRENDRE_LE_VERROU`) : une base occupée
//!      au-delà est l'échec de CET index, pas un blocage.
//!   5. Un `REINDEX` refusé (contrainte d'unicité, base occupée, objet disparu entre la relecture et l'écriture) :
//!      l'index est nommé avec sa cause et son code étendu, les suivants sont tentés, sortie 1.
//!   6. REJUGE APRÈS par le même contrôle complet : la sortie 0 n'est rendue que si chaque index est réindexé ET que
//!      ce second verdict est « sain ».
//!   UNE ligne JSON sur stdout : `avant` et `apres` (les rapports d'`integrity_check`), `plan`, `index` (pour chacun
//!   l'issue, la durée pendant laquelle le verrou a été tenu, la cause et le code), `code`, `verdict`, `cause`,
//!   `ligne_refusee`.
//!   UNE SORTIE AVANT TOUT EXAMEN, comme `integrity-check` : `78` quand `PLUME_DB_KEY_FILE` est posé mais illisible
//!   (`db_key()`, fail-closed, sans ligne JSON).
//!
//! LA CONNEXION D'ÉCRITURE. Ouverte par `open_db_keyed_without_schema_contract` sur l'URI `file:…?mode=rw` : SANS
//! création de fichier (ce mode retire `SQLITE_OPEN_CREATE`), SANS le contrat de schéma (il migrerait la base et
//! rejouerait `db/schema.sql` : des écritures que ce geste ne doit pas faire, sur une base qu'on sait abîmée), avec la
//! clé que le démon appliquerait (`db_key()`, passée par `main` comme pour `integrity-check`) et les réglages mémoire
//! de toute ouverture (`sqlite_plafond::armer`). Aucune fonction ni collation du démon n'y est enregistrée, et aucune
//! n'est nécessaire : celles qu'il enregistre (`regexp`, `re_cap`, `plume_fmask_hash` dans `query_exec` ;
//! `attack_tactic` dans `handlers::rba`) servent ses requêtes, aucun index ne les appelle ; ses index d'expression et
//! partiels n'appellent que `json_extract`, fonction du moteur (`maintenance`, `idx_ev_f_*`). Un témoin réindexe CHAQUE
//! index d'une base au schéma complet, plus un index de champ chaud, par cette connexion.
//!
//! LA LEÇON DE `P10.33-u`. Aucun descripteur n'est ouvert sur la base hors des connexions SQLite : l'état des fichiers
//! se lit par `stat` (dans `integrity_check`). Les refus de compagnons d'`integrity-check` s'appliquent tels quels au
//! jugement d'avant et à la relecture (un seul de `-wal`/`-shm`, `-journal` non vide). L'OUVERTURE EN ÉCRITURE D'UNE
//! BASE EN WAL FERMÉE PROPREMENT CRÉE `-wal` ET `-shm` dès sa première lecture : lancée sous `sudo`, ils naissent à
//! root. À la fermeture, la
//! dernière connexion sur la base fait son checkpoint et les retire ; si le démon tient la base, ils existaient déjà et
//! restent les siens. Un arrêt brutal du geste sur une base que personne d'autre ne tient les laisse en place (à root
//! sous `sudo`). Ce n'est pas empêché : c'est dit ici et dans l'aide.
//!
//! À CÔTÉ DU DÉMON VIVANT — CE QUE DEVIENNENT SES ÉCRITURES QUAND CE GESTE TIENT LE VERROU PLUS LONGTEMPS QUE LEUR
//! ATTENTE. Les connexions d'écriture du démon attendent un verrou 5 s (`busy_timeout=5000`, `server::tune`), puis :
//!   - un LOT D'INGESTION du spool : son `BEGIN IMMEDIATE` est refusé -> `LotNonEcrit::NonPris`, le fichier RESTE au
//!     spool et le passage suivant le reprend (`ingest`, bras `Err(LotNonEcrit::NonPris) => Sort::Abandonne`) : rien
//!     n'est perdu ni mis en quarantaine. Un récepteur HTTP rend 503 (`ingest::obs`) : le lot n'existe plus que chez
//!     l'émetteur, qui doit le réémettre ;
//!   - une ÉCRITURE DE CACHE de panneau : son refus est noté puis lu par `serve_swr`, le panneau est recalculé à
//!     l'interrogation suivante (`handlers::panneau_avoue::cache_ecrire_dit`) : un cache est dérivé, rien n'est perdu ;
//!   - un TICK DE DÉTECTION : l'alerte d'une règle qui tire est refusée, la règle n'avance pas (`last_run` non posé)
//!     et elle est réévaluée au tick suivant (`handlers::detection::run_due_rules`). MAIS sa requête est ancrée à
//!     l'instant de l'évaluation (`from = instant - window_s`, `rule_sql_masked_a_l_instant`) : la réévaluation porte
//!     sur une fenêtre qui a GLISSÉ, et un franchissement de seuil porté par des événements sortis de la fenêtre
//!     pendant l'attente est PERDU. De même, un lot rejoué après le verrou garde l'horodatage de ses événements : plus
//!     vieux que la fenêtre d'une règle, il n'est plus évalué par elle.
//! QUELQUE CHOSE PEUT DONC SE PERDRE : sans `--accepter-les-ecritures-refusees`, le geste n'écrit rien (sortie 2) et
//! sa ligne JSON le dit AVANT toute écriture (`PHRASE_DES_ECRITURES_REFUSEES`). Le drapeau est exigé dans tous les
//! cas, démon vivant ou arrêté (démon arrêté, aucune écriture du démon n'est refusée).
//! `--dry-run` n'en a pas besoin.
//!
//! CE QUE CE MODULE NE TIENT PAS : la course entre la relecture et l'ouverture en écriture (un compagnon apparu ou
//! retiré entre les deux n'est pas rejugé avant d'ouvrir ; le contrôle d'après porte sur l'état final) ; la mémoire
//! d'un `REINDEX` sur un très gros index (le tri est celui d'une création d'index de `maintenance`, sous les mêmes
//! réglages, non mesuré ici) ; la durée pendant laquelle le verrou est tenu est rendue sans témoin d'horloge ; une
//! erreur du moteur pendant `cipher_integrity_check` n'est pas fabriquée par un témoin : le refus qu'elle provoque est
//! éprouvé sur le rapport, pas sur une base.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::integrity_check::{self, Issue, Mode};

/// La base était saine (rien d'écrit), ou chaque index du plan est réindexé et le contrôle d'après rend « sain ».
pub(crate) const CODE_SAIN_OU_REPARE: i32 = 0;
/// Un index au moins n'est pas réindexé, ou le contrôle d'après ne rend pas « sain » ; avec `--dry-run` : la base
/// n'est pas saine et le plan est dit, rien n'est écrit.
pub(crate) const CODE_NON_REPARE: i32 = 1;
/// REFUS, RIEN D'ÉCRIT : contrôle d'avant sans verdict, défaut hors de la classe réparable, nom absent du schéma,
/// écritures refusées du démon non acceptées, ouverture en écriture impossible, argument inconnu.
pub(crate) const CODE_REFUS: i32 = 2;

/// L'attente BORNÉE du geste pour prendre un verrou (le `BEGIN IMMEDIATE` de chaque index, et les lectures des deux
/// contrôles). Au-delà, l'index échoue sur « base occupée » et le suivant est tenté : jamais d'attente sans fin.
pub(crate) const ATTENTE_POUR_PRENDRE_LE_VERROU: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) const DRAPEAU_SANS_ECRIRE: &str = "--dry-run";
pub(crate) const DRAPEAU_ACCEPTER_LES_ECRITURES_REFUSEES: &str = "--accepter-les-ecritures-refusees";

/// Ce que le geste dit, AVANT d'écrire, quand le drapeau d'acceptation manque.
pub(crate) const PHRASE_DES_ECRITURES_REFUSEES: &str = "écriture non tentée : pendant chaque REINDEX le verrou d'écriture est tenu, \
     et les écritures du démon vivant qui attendent plus de 5 s sont refusées — lot d'ingestion du spool laissé en place et rejoué, \
     lot d'un récepteur HTTP rendu en 503 (à réémettre par l'émetteur), cache de panneau recalculé, mais alerte d'une règle qui tire \
     réévaluée sur une fenêtre qui a glissé : un franchissement de seuil peut se PERDRE ; relancer avec \
     --accepter-les-ecritures-refusees pour passer outre, drapeau exigé dans tous les cas (démon arrêté, aucune \
     écriture du démon n'est refusée)";

/// Les deux formes de ligne que la réindexation répare, telles que le moteur lié les rend.
const FORME_DU_COMPTE: &str = "wrong # of entries in index ";
const FORME_DE_LA_LIGNE_DEBUT: &str = "row ";
const FORME_DE_LA_LIGNE_MILIEU: &str = " missing from index ";

/// Causes d'échec d'un index, par CODE du moteur (jamais par son texte, rendu à part dans `detail`).
pub(crate) const CAUSE_BASE_OCCUPEE: &str = "base occupée au-delà de l'attente : verrou d'écriture non pris, rien n'est écrit pour cet index";
pub(crate) const CAUSE_UNICITE: &str =
    "contrainte d'unicité violée : la table porte deux lignes de même clé, l'index ne peut pas être rebâti sans décider laquelle garder";
pub(crate) const CAUSE_REFUS_DU_MOTEUR: &str = "réindexation refusée par le moteur";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub(crate) sans_ecrire: bool,
    pub(crate) accepter_les_ecritures_refusees: bool,
    /// `None` : la base de la configuration (`PLUME_DB`).
    pub(crate) chemin: Option<String>,
}

/// Lit `reindex [--dry-run] [--accepter-les-ecritures-refusees] [<chemin>]` (`args[1]` est la sous-commande), dans
/// n'importe quel ordre. TOUT AUTRE ARGUMENT EST REFUSÉ, nommé : un drapeau mal écrit (`--dry_run`) ignoré ferait
/// ÉCRIRE la base, et un drapeau ignoré devant un chemin ferait réparer la base de la configuration à sa place.
/// `main` sort alors en `2`, sans ligne JSON. Un chemin qui commence par `-` s'écrit `./-…`.
pub(crate) fn analyser_les_arguments(args: &[String]) -> Result<Arguments, String> {
    const USAGE: &str = "usage : plume-daemon reindex [--dry-run] [--accepter-les-ecritures-refusees] [<chemin>]";
    let mut lus = Arguments { sans_ecrire: false, accepter_les_ecritures_refusees: false, chemin: None };
    for a in args.iter().skip(2) {
        if a == DRAPEAU_SANS_ECRIRE {
            lus.sans_ecrire = true;
        } else if a == DRAPEAU_ACCEPTER_LES_ECRITURES_REFUSEES {
            lus.accepter_les_ecritures_refusees = true;
        } else if a.starts_with('-') {
            return Err(format!(
                "reindex : drapeau inconnu « {a} », refusé plutôt qu'ignoré (ignoré, il pourrait faire écrire la base, ou \
                 réparer la base de la configuration à la place du chemin demandé) ; un chemin qui commence par « - » \
                 s'écrit « ./{a} » — {USAGE}"
            ));
        } else if lus.chemin.is_none() {
            lus.chemin = Some(a.clone());
        } else {
            return Err(format!("reindex : un seul chemin attendu, « {a} » en trop — {USAGE}"));
        }
    }
    Ok(lus)
}

/// Le nom de l'index qu'une ligne du contrôle désigne, si elle est de la classe réparable ; `None` sinon. Une ligne
/// qui porte un saut de ligne n'est jamais de la classe (le moteur préfixe certains défauts d'arbre par une ligne
/// d'en-tête dans la même valeur).
pub(crate) fn index_desaccorde(ligne: &str) -> Option<&str> {
    if ligne.contains('\n') || ligne.contains('\r') {
        return None;
    }
    match ligne.strip_prefix(FORME_DU_COMPTE) {
        Some(nom) => (!nom.is_empty()).then_some(nom),
        None => {
            let (rangee, nom) = ligne.strip_prefix(FORME_DE_LA_LIGNE_DEBUT)?.split_once(FORME_DE_LA_LIGNE_MILIEU)?;
            (!rangee.is_empty() && rangee.bytes().all(|b| b.is_ascii_digit()) && !nom.is_empty()).then_some(nom)
        }
    }
}

/// Un refus avant toute écriture : sa cause, et la ligne du contrôle qui le provoque quand c'en est une.
type RefusAvantEcriture = (String, Option<String>);

/// Le plan tiré du rapport d'un contrôle COMPLET qui a rendu « corrompu » : les noms d'index, dans l'ordre de première
/// apparition, sans doublon — ou le refus. Chaque bras de refus est un fait borné, dit comme tel.
pub(crate) fn plan_du_verdict(rapport: &Value) -> Result<Vec<String>, RefusAvantEcriture> {
    match rapport["plafond_atteint"].as_bool() {
        Some(false) => {}
        Some(true) => {
            return Err((
                format!(
                    "le contrôle a atteint son plafond de {} lignes : la liste des défauts est tronquée, ceux qui ne sont pas \
                     listés ne sont pas jugés — rien n'est écrit",
                    integrity_check::PLAFOND_DE_LIGNES
                ),
                None,
            ))
        }
        None => {
            return Err((
                format!(
                    "le contrôle n'a pas rendu toutes ses lignes ({}) : rien n'est écrit sur une liste incomplète",
                    rapport["cause"].as_str().unwrap_or("cause non dite")
                ),
                None,
            ))
        }
    }
    // Sous clé, SEUL un `[]` rendu sans erreur du moteur dit « HMAC sain » : interrompu avant sa première ligne, le
    // contrôle laisse aussi `[]`, et une erreur sur `cipher_version` laisse la valeur absente — l'erreur est alors dans
    // `cipher_integrity_check_erreur`. Sans clé, la seule valeur admise est l'absence.
    if !rapport["cipher_integrity_check_erreur"].is_null() {
        let erreur = &rapport["cipher_integrity_check_erreur"];
        return Err((
            "cipher_integrity_check interrompu par une erreur du moteur : le HMAC des pages n'est pas jugé, rien n'est écrit"
                .into(),
            Some(erreur.as_str().map_or_else(|| erreur.to_string(), str::to_string)),
        ));
    }
    let sous_cle = rapport["cle_appliquee"].as_bool();
    match &rapport["cipher_integrity_check"] {
        Value::Null if sous_cle == Some(false) => {}
        Value::Array(pages) if pages.is_empty() && sous_cle == Some(true) => {}
        Value::Array(pages) if !pages.is_empty() => {
            return Err((
                "cipher_integrity_check en défaut : une page chiffrée ne s'authentifie pas, une réindexation ne la répare pas"
                    .into(),
                Some(pages[0].as_str().map_or_else(|| pages[0].to_string(), str::to_string)),
            ))
        }
        autre => {
            return Err((
                format!(
                    "cipher_integrity_check n'a pas rendu de verdict (clé appliquée : {}) : rien n'est écrit sans lui",
                    sous_cle.map_or("non dit", |s| if s { "oui" } else { "non" })
                ),
                Some(autre.as_str().map_or_else(|| autre.to_string(), str::to_string)),
            ))
        }
    }
    let mut plan: Vec<String> = Vec::new();
    for ligne in rapport["lignes"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let texte = ligne.as_str().map_or_else(|| ligne.to_string(), str::to_string);
        match index_desaccorde(&texte) {
            Some(nom) => {
                if !plan.iter().any(|p| p == nom) {
                    plan.push(nom.to_string());
                }
            }
            None => {
                return Err((
                    "une ligne du contrôle n'est pas un index désaccordé de sa table : une réindexation ne répare pas ce \
                     défaut et le masquerait — rien n'est écrit"
                        .into(),
                    Some(texte),
                ))
            }
        }
    }
    Ok(plan)
}

/// Chaque nom du plan RELU dans `sqlite_master`, par l'ouverture en lecture seule d'`integrity_check` (mêmes refus de
/// compagnons, aucune création). Un nom absent, ou une relecture qui échoue, est un refus.
fn relire_au_schema(chemin: &str, cle: Option<&str>, attente: std::time::Duration, plan: &[String]) -> Result<(), RefusAvantEcriture> {
    let cle_appliquee = cle.is_some_and(|k| !k.is_empty());
    let mut ouverture = json!({});
    let conn = integrity_check::ouvrir_en_lecture_seule(chemin, cle, cle_appliquee, attente, &mut ouverture).map_err(|issue| {
        let cause = match issue {
            Issue::Corrompu(c) | Issue::Refus(c) => c,
        };
        (format!("relecture du schéma impossible ({cause}) : rien n'est écrit"), None)
    })?;
    for nom in plan {
        match conn.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1", [nom], |r| r.get::<_, i64>(0)) {
            Ok(n) if n > 0 => {}
            Ok(_) => {
                return Err((
                    format!("l'index « {nom} » nommé par le contrôle est absent du schéma relu : rien n'est écrit"),
                    Some(nom.clone()),
                ))
            }
            Err(e) => return Err((format!("relecture du schéma refusée pour « {nom} » ({e}) : rien n'est écrit"), None)),
        }
    }
    Ok(())
}

/// L'identifiant SQL cité : guillemets doublés, jamais interpolé nu.
fn citer(nom: &str) -> String {
    format!("\"{}\"", nom.replace('"', "\"\""))
}

/// L'URI d'ouverture EN ÉCRITURE SANS CRÉATION : le chemin échappé par la même fonction que l'ouverture immuable
/// d'`integrity_check` (`%`, `?`, `#`), son suffixe remplacé par `mode=rw`.
fn uri_en_ecriture_sans_creation(chemin: &str) -> String {
    let immuable = crate::db_open::uri_sqlite_immuable_d_un_chemin(chemin);
    format!("{}?mode=rw", immuable.trim_end_matches("?immutable=1"))
}

/// La connexion d'écriture : sans création de fichier, sans contrat de schéma, sous la clé donnée, l'attente bornée.
pub(crate) fn ouvrir_l_ecrivain(chemin: &str, cle: Option<&str>, attente: std::time::Duration) -> rusqlite::Result<Connection> {
    let conn = crate::db_open::open_db_keyed_without_schema_contract(&uri_en_ecriture_sans_creation(chemin), cle)?;
    conn.busy_timeout(attente)?;
    Ok(conn)
}

fn code_etendu(e: &rusqlite::Error) -> Option<i32> {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => Some(f.extended_code),
        _ => None,
    }
}

fn cause_de_l_echec(e: &rusqlite::Error) -> &'static str {
    match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy) => CAUSE_BASE_OCCUPEE,
        Some(rusqlite::ErrorCode::ConstraintViolation) => CAUSE_UNICITE,
        _ => CAUSE_REFUS_DU_MOTEUR,
    }
}

fn echec_d_un_index(nom: &str, verrou_tenu_ms: Option<u64>, e: &rusqlite::Error) -> Value {
    json!({
        "index": nom,
        "issue": "echec",
        "verrou_tenu_ms": verrou_tenu_ms,
        "cause": cause_de_l_echec(e),
        "code": code_etendu(e),
        "detail": e.to_string(),
    })
}

/// UN index, UNE transaction : le verrou est pris (attente bornée), l'index rebâti, la transaction validée, le verrou
/// rendu. `verrou_tenu_ms` est `null` quand le verrou n'a jamais été pris.
pub(crate) fn reindexer_un_index(conn: &Connection, nom: &str) -> Value {
    match crate::handlers::transaction_validee::ouvrir_sa_transaction(conn, "reindex", &format!("réindexation de « {nom} »")) {
        Ok(()) => {}
        Err(refus) => return echec_d_un_index(nom, None, &refus),
    }
    let pris = std::time::Instant::now();
    let fait = match conn.execute_batch(&format!("REINDEX \"main\".{}", citer(nom))) {
        Ok(()) => crate::handlers::transaction_validee::valider_la_transaction(conn),
        Err(refus) => {
            // Après un REINDEX refusé la transaction reste ouverte : elle est annulée. Si l'annulation échoue, le
            // `BEGIN` de l'index suivant est refusé à son tour et nommé : rien n'est écrit à la place de personne.
            let _ = conn.execute_batch("ROLLBACK");
            Err(refus)
        }
    };
    let tenu = pris.elapsed().as_millis() as u64;
    match fait {
        Ok(()) => json!({
            "index": nom,
            "issue": "reindexe",
            "verrou_tenu_ms": tenu,
            "cause": Value::Null,
            "code": Value::Null,
            "detail": Value::Null,
        }),
        Err(refus) => echec_d_un_index(nom, Some(tenu), &refus),
    }
}

/// Le rendu : le code de sortie et la ligne JSON (une seule, sur stdout).
#[derive(Debug, Clone)]
pub(crate) struct Rapport {
    pub(crate) code: i32,
    pub(crate) ligne: Value,
}

fn conclure(mut ligne: Value, code: i32, verdict: &str, cause: Option<String>, ligne_refusee: Option<String>) -> Rapport {
    ligne["code"] = json!(code);
    ligne["verdict"] = json!(verdict);
    ligne["cause"] = json!(cause);
    ligne["ligne_refusee"] = json!(ligne_refusee);
    Rapport { code, ligne }
}

/// Le geste entier, l'attente de production.
pub(crate) fn reindexer(chemin: &str, arguments: &Arguments, cle: Option<&str>) -> Rapport {
    reindexer_avec_attente(chemin, arguments, cle, ATTENTE_POUR_PRENDRE_LE_VERROU)
}

/// Le même, l'attente de verrou explicite (le témoin de la base occupée n'attend pas l'attente de production).
pub(crate) fn reindexer_avec_attente(chemin: &str, arguments: &Arguments, cle: Option<&str>, attente: std::time::Duration) -> Rapport {
    let ligne = json!({
        "base": chemin,
        "cle_appliquee": cle.is_some_and(|k| !k.is_empty()),
        "dry_run": arguments.sans_ecrire,
        "accepte_les_ecritures_refusees": arguments.accepter_les_ecritures_refusees,
        "attente_du_verrou_ms": attente.as_millis() as u64,
        "avant": Value::Null,
        "plan": [],
        "index": [],
        "apres": Value::Null,
    });
    reindexer_dans(ligne, chemin, arguments, cle, attente)
}

fn reindexer_dans(mut ligne: Value, chemin: &str, arguments: &Arguments, cle: Option<&str>, attente: std::time::Duration) -> Rapport {
    // ── 1. LE JUGEMENT D'AVANT, EN LECTURE SEULE ─────────────────────────────────────────────────
    let avant = integrity_check::verifier_avec_attente(chemin, Mode::Complet, cle, attente);
    ligne["avant"] = avant.rapport.clone();
    if avant.code == integrity_check::CODE_SAIN {
        return conclure(ligne, CODE_SAIN_OU_REPARE, "sain", None, None);
    }
    if avant.code != integrity_check::CODE_CORROMPU {
        let cause = format!(
            "le contrôle d'avant n'a pas conclu ({}) : rien n'est écrit",
            avant.rapport["cause"].as_str().unwrap_or("cause non dite")
        );
        return conclure(ligne, CODE_REFUS, "refus", Some(cause), None);
    }

    // ── 2. LA CLASSE DE CHAQUE LIGNE ─────────────────────────────────────────────────────────────
    let plan = match plan_du_verdict(&avant.rapport) {
        Ok(p) => p,
        Err((cause, refusee)) => return conclure(ligne, CODE_REFUS, "refus", Some(cause), refusee),
    };
    ligne["plan"] = json!(plan);

    // ── 3. CHAQUE NOM RELU AU SCHÉMA ─────────────────────────────────────────────────────────────
    #[cfg(test)]
    crochet(PHASE_APRES_LE_VERDICT_D_AVANT, chemin);
    match relire_au_schema(chemin, cle, attente, &plan) {
        Ok(()) => {}
        Err((cause, refusee)) => return conclure(ligne, CODE_REFUS, "refus", Some(cause), refusee),
    }
    if arguments.sans_ecrire {
        return conclure(ligne, CODE_NON_REPARE, "a_reindexer", None, None);
    }
    if !arguments.accepter_les_ecritures_refusees {
        return conclure(ligne, CODE_REFUS, "refus", Some(PHRASE_DES_ECRITURES_REFUSEES.to_string()), None);
    }

    // ── 4 ET 5. UN INDEX PAR TRANSACTION ─────────────────────────────────────────────────────────
    #[cfg(test)]
    crochet(PHASE_AVANT_L_OUVERTURE_EN_ECRITURE, chemin);
    let conn = match ouvrir_l_ecrivain(chemin, cle, attente) {
        Ok(c) => c,
        Err(e) => {
            let cause = format!("ouverture en écriture impossible ({e}) : rien n'est écrit");
            return conclure(ligne, CODE_REFUS, "refus", Some(cause), None);
        }
    };
    let mut issues: Vec<Value> = Vec::with_capacity(plan.len());
    let mut echecs = 0usize;
    for nom in &plan {
        let issue = reindexer_un_index(&conn, nom);
        if issue["issue"] != "reindexe" {
            echecs += 1;
        }
        issues.push(issue);
        #[cfg(test)]
        crochet(PHASE_APRES_UN_INDEX, chemin);
    }
    drop(conn);
    ligne["index"] = json!(issues);

    // ── 6. LE JUGEMENT D'APRÈS ───────────────────────────────────────────────────────────────────
    let apres = integrity_check::verifier_avec_attente(chemin, Mode::Complet, cle, attente);
    ligne["apres"] = apres.rapport.clone();
    if echecs > 0 {
        let cause = format!("{echecs} index sur {} non réindexé(s)", plan.len());
        return conclure(ligne, CODE_NON_REPARE, "non_repare", Some(cause), None);
    }
    if apres.code != integrity_check::CODE_SAIN {
        let cause = "chaque index du plan est réindexé, mais le contrôle d'après ne rend pas « sain »".to_string();
        return conclure(ligne, CODE_NON_REPARE, "non_repare", Some(cause), None);
    }
    conclure(ligne, CODE_SAIN_OU_REPARE, "repare", None, None)
}

// ── LES ARGUMENTS DE `main`, ET LES CROCHETS DES TÉMOINS ─────────────────────────────────────────

/// Les arguments que `main` analyse : ceux du processus.
#[cfg(not(test))]
pub(crate) fn arguments_a_analyser(args: &[String]) -> Vec<String> {
    args.to_vec()
}

/// Sous `cfg(test)` SEULEMENT : le binaire de test porte aussi les drapeaux de libtest, que l'analyse stricte
/// refuserait. Le témoin passe les arguments de la sous-commande, forme `argv` complète, en tableau JSON dans
/// `REINDEX_ARGUMENTS_DE_L_ENFANT`. Absente, ce sont ceux du processus. Le binaire livré n'a pas cette voie.
#[cfg(test)]
pub(crate) fn arguments_a_analyser(args: &[String]) -> Vec<String> {
    match std::env::var("REINDEX_ARGUMENTS_DE_L_ENFANT") {
        Ok(v) => serde_json::from_str(&v).expect("témoin : REINDEX_ARGUMENTS_DE_L_ENFANT est un tableau JSON de chaînes"),
        Err(_) => args.to_vec(),
    }
}

/// Les points où un témoin agit sur la base entre deux étapes (sur le fil appelant, compilé en test seulement).
#[cfg(test)]
pub(crate) const PHASE_APRES_LE_VERDICT_D_AVANT: &str = "apres_le_verdict_d_avant";
#[cfg(test)]
pub(crate) const PHASE_AVANT_L_OUVERTURE_EN_ECRITURE: &str = "avant_l_ouverture_en_ecriture";
#[cfg(test)]
pub(crate) const PHASE_APRES_UN_INDEX: &str = "apres_un_index";

/// Le crochet par défaut : un appel SANS alternative, aucune branche ne peut y abandonner quoi que ce soit.
#[cfg(test)]
pub(crate) fn sans_crochet(_phase: &str, _chemin: &str) {}

#[cfg(test)]
thread_local! {
    pub(crate) static CROCHET_DE_PHASE: std::cell::Cell<fn(&str, &str)> = const { std::cell::Cell::new(sans_crochet) };
}

#[cfg(test)]
fn crochet(phase: &str, chemin: &str) {
    CROCHET_DE_PHASE.with(|c| (c.get())(phase, chemin));
}
