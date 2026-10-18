//! `P10.33-v` — LE CONTRÔLE D'INTÉGRITÉ SQLITE DE LA BASE, EN LECTURE SEULE, SANS TOUCHER À SES COMPAGNONS.
//!
//! CE QUI MANQUAIT. Aucune sous-commande ne jugeait la STRUCTURE de la base : `backup-verify` ne juge
//! que l'archive, et le seul `PRAGMA integrity_check` du produit porte sur la copie de conversion
//! (`crypto`). Après l'incident du WAL délié (`P10.33-u`), l'exploitant n'avait aucun geste sûr pour
//! demander « la base vivante est-elle saine ? » sans ouvrir lui-même un `sqlite3` à côté du démon.
//!
//! CE QUE FAIT `plume-daemon integrity-check [--full] [<chemin>]` :
//!   - `PRAGMA quick_check` par défaut, `PRAGMA integrity_check` avec `--full` ;
//!   - `PRAGMA cipher_integrity_check` en plus quand une clé est appliquée (vérifie le HMAC de chaque
//!     page chiffrée ; ne lit pas le `-wal`, c'est la limite du moteur) ;
//!   - UNE ligne JSON sur stdout ; code de sortie `0` sain, `1` corrompu, `2` REFUS DE CONCLURE.
//!
//! UNE QUATRIÈME SORTIE, AVANT TOUT VERDICT : `78`. `main` lit la clé du démon (`db_key()`) avant
//! d'examiner quoi que ce soit, même sur un chemin explicite ou une base absente. Si
//! `PLUME_DB_KEY_FILE` est posé mais que le fichier est absent, illisible ou vide, `db_key_depuis`
//! termine le processus en `78` (EX_CONFIG, fail-closed, sans ligne JSON) au lieu de retomber sur
//! `PLUME_DB_KEY` : c'est la règle du démon, l'examen ne l'assouplit pas.
//!
//! LES TROIS SORTIES DU VERDICT, ET POURQUOI LA TROISIÈME. `2` couvre tout ce qui empêche un verdict : fichier
//! absent ou VIDE (`quick_check` rend « ok » sur zéro page : un faux vert), clé fausse ou en-tête abîmé
//! (SQLite ne les distingue pas : `SQLITE_NOTADB`), base occupée, erreur d'entrée-sortie, compagnons
//! incomplets ou journal chaud. Un `1` n'est rendu que sur un fait : une ligne du moteur qui n'est pas
//! « ok », ou une lecture qui rend `SQLITE_CORRUPT`.
//!
//! LA LEÇON DE `P10.33-u`, APPLIQUÉE. Aucun descripteur n'est ouvert sur la base hors de la connexion
//! SQLite : l'état des fichiers se lit par `std::fs::metadata` (un `stat`, sans descripteur), et la
//! connexion est ouverte `SQLITE_OPEN_READ_ONLY`, sans `CREATE` — un fichier absent n'est jamais créé.
//! Un lecteur en lecture seule ne peut pas prendre le verrou EXCLUSIVE de fermeture (son descripteur
//! est en lecture seule) : il ne fait ni checkpoint ni suppression du `-wal`/`-shm`.
//!
//! LE CHOIX D'OUVERTURE SE FAIT SUR LES COMPAGNONS, AVANT D'OUVRIR :
//!   - `-wal` ET `-shm` présents : ouverture VIVANTE, le verdict porte sur l'état que le démon sert
//!     (pages du WAL comprises) ;
//!   - ni `-wal` ni `-shm` : ouverture IMMUABLE (`immutable=1`) — sur une base en mode WAL fermée
//!     proprement, une ouverture ordinaire, même en lecture seule, CRÉERAIT `-wal` et `-shm` (sous
//!     `sudo`, propriété de root) ;
//!   - un seul des deux : REFUS, l'ouverture créerait l'autre ;
//!   - `-journal` non vide : REFUS, une ouverture en lecture seule ne rejoue pas un journal chaud et
//!     une ouverture immuable l'ignorerait (verdict sur un état qui n'est pas celui de la base).
//!
//! LA CLÉ. L'appelant passe la clé que le démon appliquerait (`db_key()`), même sur un chemin
//! explicite : une copie DÉCHIFFRÉE examinée avec une clé ambiante rend `2` (« clé fausse ou en-tête
//! illisible »), jamais un faux verdict, et le JSON dit `cle_appliquee`. Aucun drapeau ne retire la
//! clé : une copie déchiffrée s'examine dans un contexte SANS clé du démon, et `db_key()` en lit
//! trois sources : `PLUME_DB_KEY` et `PLUME_DB_KEY_FILE`, dans l'environnement ET dans le fichier de
//! configuration (`PLUME_CONFIG`, `/etc/plume/soc.conf` sur un hôte systemd) ; puis le fichier de clé
//! auto-engendrée (`PLUME_DB_KEY_AUTO_PATH`, défaut `<PLUME_DB>.key`). Le plus simple :
//! `PLUME_CONFIG` vers un fichier vide, `PLUME_DB` vers la copie, ces variables absentes.
//!
//! CE QUE CE MODULE NE TIENT PAS : en ouverture immuable, un écrivain en mode journal de retour
//! arrière qui écrirait pendant la lecture sans laisser de `-journal` visible au moment du `stat` ;
//! le démon tient sa base en WAL, ce cas ne vise qu'un fichier étranger. `cipher_integrity_check` ne
//! lit pas le `-wal`. LA COURSE ENTRE LE `stat` ET L'OUVERTURE VIVANTE : si le démon se ferme
//! proprement entre le moment où `-wal` et `-shm` sont vus et l'ouverture, il fait son checkpoint et
//! les délie ; l'ouverture en lecture seule qui suit les RECRÉE alors (c'est le cas même qui impose
//! l'ouverture immuable sur une base fermée). Fenêtre étroite, non mesurée, non fermée : l'examen se
//! joue démon tournant ou démon arrêté, pas pendant son arrêt.

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

/// Base lue entièrement, toutes les vérifications rendent « ok ».
pub(crate) const CODE_SAIN: i32 = 0;
/// Un fait de corruption : ligne du moteur autre que « ok », ou `SQLITE_CORRUPT` à la lecture.
pub(crate) const CODE_CORROMPU: i32 = 1;
/// Aucun verdict : la base n'a pas pu être lue de façon à conclure.
pub(crate) const CODE_REFUS: i32 = 2;

/// Le nombre maximal de lignes demandé au moteur (`PRAGMA quick_check(N)`). Atteint, c'est un fait
/// borné, dit par `plafond_atteint` — la base est corrompue, la liste des défauts est tronquée.
pub(crate) const PLAFOND_DE_LIGNES: usize = 100;

/// Le délai d'attente d'un verrou (lecteur WAL : en pratique jamais attendu ; journal de retour
/// arrière : un écrivain en cours). Les témoins passent le leur à `verifier_avec_attente`.
pub(crate) const ATTENTE_D_UN_VERROU: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `PRAGMA quick_check` : structure des pages et des arbres, sans le contenu des index.
    Rapide,
    /// `PRAGMA integrity_check` (`--full`) : le même, plus la concordance des index avec leurs tables.
    Complet,
}

impl Mode {
    fn pragma(self) -> &'static str {
        match self {
            Mode::Rapide => "quick_check",
            Mode::Complet => "integrity_check",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub(crate) mode: Mode,
    /// `None` : la base de la configuration (`PLUME_DB`).
    pub(crate) chemin: Option<String>,
}

/// Lit `integrity-check [--full] [<chemin>]` dans `args` (`args[1]` est la sous-commande). Les deux
/// formes `--full <chemin>` et `<chemin> --full` sont admises. TOUT AUTRE ARGUMENT EST REFUSÉ, nommé :
/// un drapeau inconnu (`-full`, `--ful`, `--help`…) comme un second chemin. Un drapeau ignoré ferait
/// juger la base de la configuration (`PLUME_DB`, la base VIVANTE) à la place du chemin demandé, et
/// la sortie `0` qui suivrait se lirait « la copie est saine ». `main` sort alors en `2`, sans ligne
/// JSON. Un chemin qui commence par `-` s'écrit `./-…`.
pub(crate) fn analyser_les_arguments(args: &[String]) -> Result<Arguments, String> {
    const USAGE: &str = "usage : plume-daemon integrity-check [--full] [<chemin>]";
    let mut mode = Mode::Rapide;
    let mut chemin: Option<String> = None;
    for a in args.iter().skip(2) {
        if a == "--full" {
            mode = Mode::Complet;
        } else if a.starts_with('-') {
            return Err(format!(
                "integrity-check : drapeau inconnu « {a} », refusé plutôt qu'ignoré (ignoré, il ferait juger la base \
                 de la configuration à la place du chemin demandé) ; un chemin qui commence par « - » s'écrit « ./{a} » — {USAGE}"
            ));
        } else if chemin.is_none() {
            chemin = Some(a.clone());
        } else {
            return Err(format!("integrity-check : un seul chemin attendu, « {a} » en trop — {USAGE}"));
        }
    }
    Ok(Arguments { mode, chemin })
}

/// Les arguments que `main` analyse : ceux du processus.
#[cfg(not(test))]
pub(crate) fn arguments_a_analyser(args: &[String]) -> Vec<String> {
    args.to_vec()
}

/// Sous `cfg(test)` SEULEMENT : le binaire de test porte aussi les drapeaux de libtest (`--exact`,
/// `--test-threads=1`…), que l'analyse stricte refuserait, et libtest refuse de son côté un drapeau
/// qu'il ne connaît pas (`-full`, `--full`). Le témoin passe donc les arguments de la sous-commande,
/// forme `argv` complète, en tableau JSON dans `P1033V_ARGUMENTS_DE_L_ENFANT`. Absente, ce sont ceux
/// du processus (et les drapeaux de libtest y sont refusés comme les autres). Le binaire livré n'a
/// pas cette voie.
#[cfg(test)]
pub(crate) fn arguments_a_analyser(args: &[String]) -> Vec<String> {
    match std::env::var("P1033V_ARGUMENTS_DE_L_ENFANT") {
        Ok(v) => serde_json::from_str(&v).expect("témoin : P1033V_ARGUMENTS_DE_L_ENFANT est un tableau JSON de chaînes"),
        Err(_) => args.to_vec(),
    }
}

/// Le verdict : le code de sortie et le rapport JSON (une ligne sur stdout).
#[derive(Debug, Clone)]
pub(crate) struct Verdict {
    pub(crate) code: i32,
    pub(crate) rapport: Value,
}

/// Ce qu'une étape a établi. `Corrompu` est un FAIT ; `Refus` dit pourquoi aucun verdict n'est rendu.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Issue {
    Corrompu(String),
    Refus(String),
}

/// Une erreur SQLite classée : seule `SQLITE_CORRUPT` est un fait de corruption, tout le reste est un
/// refus de conclure, nommé.
fn classer(e: &rusqlite::Error, cle_appliquee: bool) -> Issue {
    use rusqlite::ErrorCode as C;
    match e.sqlite_error_code() {
        Some(C::DatabaseCorrupt) => Issue::Corrompu(format!("SQLITE_CORRUPT à la lecture : {e}")),
        Some(C::NotADatabase) => Issue::Refus(format!(
            "clé fausse ou en-tête illisible (SQLite ne distingue pas les deux ; clé appliquée : {}) : {e}",
            if cle_appliquee { "oui" } else { "non" }
        )),
        Some(C::DatabaseBusy) | Some(C::DatabaseLocked) => Issue::Refus(format!("base occupée : {e}")),
        Some(C::ReadOnly) => Issue::Refus(format!("lecture seule impossible à établir (droits sur -shm ?) : {e}")),
        Some(C::CannotOpen) => Issue::Refus(format!("ouverture impossible : {e}")),
        Some(C::SystemIoFailure) => Issue::Refus(format!("erreur d'entrée-sortie : {e}")),
        Some(code) => Issue::Refus(format!("erreur SQLite {code:?} : {e}")),
        None => Issue::Refus(format!("erreur : {e}")),
    }
}

/// La taille d'un fichier par `stat` : `Ok(None)` s'il est absent. Aucun descripteur ouvert.
fn taille(chemin: &str) -> Result<Option<u64>, std::io::Error> {
    match std::fs::metadata(chemin) {
        Ok(m) => Ok(Some(m.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Le nom de fichier en URI SQLite (`file:` + chemin, `%`, `?` et `#` échappés).
fn uri_immuable(chemin: &str) -> String {
    let mut echappe = String::with_capacity(chemin.len());
    for c in chemin.chars() {
        match c {
            '%' => echappe.push_str("%25"),
            '?' => echappe.push_str("%3f"),
            '#' => echappe.push_str("%23"),
            _ => echappe.push(c),
        }
    }
    if echappe.starts_with('/') {
        format!("file://{echappe}?immutable=1")
    } else {
        format!("file:{echappe}?immutable=1")
    }
}


/// Le contrôle entier. `cle` : la clé SQLCipher à appliquer (`None` ou vide : base en clair).
pub(crate) fn verifier(chemin: &str, mode: Mode, cle: Option<&str>) -> Verdict {
    verifier_avec_attente(chemin, mode, cle, ATTENTE_D_UN_VERROU)
}

/// Le même, avec un délai d'attente de verrou explicite (le témoin de la base occupée n'attend pas
/// cinq secondes par étape).
pub(crate) fn verifier_avec_attente(chemin: &str, mode: Mode, cle: Option<&str>, attente: std::time::Duration) -> Verdict {
    let debut = std::time::Instant::now();
    let cle_appliquee = cle.is_some_and(|k| !k.is_empty());
    let mut rapport = json!({
        "base": chemin,
        "mode": mode.pragma(),
        "cle_appliquee": cle_appliquee,
        "plafond_de_lignes": PLAFOND_DE_LIGNES,
    });
    let issue = verifier_dans(chemin, mode, cle, cle_appliquee, attente, &mut rapport);
    let (code, verdict, cause) = match issue {
        None => (CODE_SAIN, "sain", None),
        Some(Issue::Corrompu(c)) => (CODE_CORROMPU, "corrompu", Some(c)),
        Some(Issue::Refus(c)) => (CODE_REFUS, "refus", Some(c)),
    };
    rapport["code"] = json!(code);
    rapport["verdict"] = json!(verdict);
    rapport["cause"] = json!(cause);
    rapport["duree_ms"] = json!(debut.elapsed().as_millis() as u64);
    Verdict { code, rapport }
}

/// Le corps : `None` = sain. Remplit `rapport` au fil des étapes. La connexion est fermée en sortie.
fn verifier_dans(
    chemin: &str,
    mode: Mode,
    cle: Option<&str>,
    cle_appliquee: bool,
    attente: std::time::Duration,
    rapport: &mut Value,
) -> Option<Issue> {
    // ── 1. LE FICHIER, PAR `stat` SEUL ──────────────────────────────────────────────────────────
    let principal = match std::fs::metadata(chemin) {
        Ok(m) if !m.is_file() => return Some(Issue::Refus("le chemin n'est pas un fichier ordinaire".into())),
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some(Issue::Refus("base absente : rien à vérifier, et rien n'a été créé".into()))
        }
        Err(e) => return Some(Issue::Refus(format!("état du fichier illisible ({:?})", e.kind()))),
    };
    if principal == 0 {
        return Some(Issue::Refus(
            "fichier vide : quick_check y rendrait « ok » sur zéro page, ce serait un faux vert".into(),
        ));
    }
    let compagnon = |suffixe: &str| taille(&format!("{chemin}{suffixe}"));
    let (wal, shm, journal) = match (compagnon("-wal"), compagnon("-shm"), compagnon("-journal")) {
        (Ok(w), Ok(s), Ok(j)) => (w, s, j),
        _ => return Some(Issue::Refus("état des compagnons (-wal, -shm, -journal) illisible".into())),
    };
    rapport["compagnons"] = json!({ "wal": wal.is_some(), "shm": shm.is_some(), "journal": journal.is_some() });
    if journal.is_some_and(|n| n > 0) {
        return Some(Issue::Refus(
            "-journal non vide (journal chaud) : une ouverture en lecture seule ne le rejoue pas, une ouverture \
             immuable l'ignorerait — aucun verdict sur un état qui n'est pas celui de la base"
                .into(),
        ));
    }
    let immuable = match (wal.is_some(), shm.is_some()) {
        (true, true) => false,
        (false, false) => true,
        (true, false) => return Some(Issue::Refus("-wal présent sans -shm : l'ouverture créerait -shm".into())),
        (false, true) => return Some(Issue::Refus("-shm présent sans -wal : l'ouverture créerait -wal".into())),
    };
    rapport["ouverture"] = json!(if immuable { "immuable" } else { "vivante" });

    // ── 2. L'OUVERTURE EN LECTURE SEULE, SANS CREATE ────────────────────────────────────────────
    let ouverte = if immuable {
        Connection::open_with_flags(uri_immuable(chemin), OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
    } else {
        Connection::open_with_flags(chemin, OpenFlags::SQLITE_OPEN_READ_ONLY)
    };
    let conn = match ouverte {
        Ok(c) => c,
        Err(e) => return Some(classer(&e, cle_appliquee)),
    };
    let _ = conn.busy_timeout(attente);
    if let Err(e) = crate::db_open::appliquer_une_cle_explicite(&conn, cle) {
        return Some(Issue::Refus(format!("la clé n'a pas pu être appliquée : {e}")));
    }
    let _ = crate::sqlite_plafond::armer(&conn);
    if let Err(e) = conn.execute_batch("PRAGMA query_only=ON;") {
        return Some(Issue::Refus(format!("connexion non bornée à la lecture seule : {e}")));
    }

    // ── 3. LA BASE EST-ELLE LISIBLE ? (clé, en-tête, schéma) ────────────────────────────────────
    if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
        let issue = classer(&e, cle_appliquee);
        return Some(issue);
    }
    match conn.query_row("PRAGMA page_count", [], |r| r.get::<_, i64>(0)) {
        Ok(n) => rapport["pages"] = json!(n),
        Err(e) => return Some(classer(&e, cle_appliquee)),
    }

    // ── 4. LE CONTRÔLE DE STRUCTURE ─────────────────────────────────────────────────────────────
    let pragma = mode.pragma();
    rapport["pragma"] = json!(pragma);
    let lignes = match lire_les_lignes(&conn, &format!("PRAGMA {pragma}({PLAFOND_DE_LIGNES})")) {
        Ok(l) => l,
        Err((lues, e)) => {
            rapport["lignes"] = json!(lues);
            let issue = classer(&e, cle_appliquee);
            return Some(issue);
        }
    };
    rapport["plafond_atteint"] = json!(lignes.len() >= PLAFOND_DE_LIGNES);
    let structure_saine = lignes.len() == 1 && lignes[0] == "ok";
    rapport["lignes"] = json!(lignes);

    // ── 5. LE HMAC DES PAGES CHIFFRÉES, SI UNE CLÉ EST APPLIQUÉE ────────────────────────────────
    let mut chiffrement: Option<Issue> = None;
    if !cle_appliquee {
        rapport["cipher_integrity_check"] = Value::Null;
    } else {
        match conn.query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0)) {
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                rapport["cipher_integrity_check"] = json!("indisponible : moteur sans SQLCipher");
                chiffrement = Some(Issue::Refus("une clé est appliquée mais le moteur n'est pas SQLCipher".into()));
            }
            Err(e) => chiffrement = Some(classer(&e, cle_appliquee)),
            Ok(_) => match lire_les_lignes(&conn, "PRAGMA cipher_integrity_check") {
                Ok(l) => {
                    if !l.is_empty() {
                        chiffrement = Some(Issue::Corrompu(format!("cipher_integrity_check : {} page(s) en défaut", l.len())));
                    }
                    rapport["cipher_integrity_check"] = json!(l);
                }
                Err((lues, e)) => {
                    rapport["cipher_integrity_check"] = json!(lues);
                    chiffrement = Some(classer(&e, cle_appliquee));
                }
            },
        }
    }
    drop(conn);

    // Un fait de corruption l'emporte sur un refus : il est établi.
    if !structure_saine {
        return Some(Issue::Corrompu(format!("{pragma} rend des défauts")));
    }
    chiffrement
}

/// Toutes les lignes (première colonne, texte) d'un `PRAGMA`. En cas d'erreur en cours de lecture :
/// les lignes déjà lues ET l'erreur — rien n'est avalé.
fn lire_les_lignes(conn: &Connection, sql: &str) -> Result<Vec<String>, (Vec<String>, rusqlite::Error)> {
    let mut stmt = conn.prepare(sql).map_err(|e| (Vec::new(), e))?;
    let mut rows = stmt.query([]).map_err(|e| (Vec::new(), e))?;
    let mut lues = Vec::new();
    loop {
        match rows.next() {
            Ok(Some(r)) => match r.get::<_, String>(0) {
                Ok(s) => lues.push(s),
                Err(e) => return Err((lues, e)),
            },
            Ok(None) => return Ok(lues),
            Err(e) => return Err((lues, e)),
        }
    }
}
