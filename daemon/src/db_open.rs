//! LA PORTE — OBTENIR UNE CONNEXION D'ÉCRITURE SUR UNE BASE PLUME.
//!
//! CE QUE LA REVUE A MESURÉ, ET POURQUOI CE MODULE EXISTE. La doc de `prepare_schema` affirmait que
//! « `migrate` est privée hors test, donc TOUT chemin de production qui prépare une base plume passe
//! forcément ici », suivie de la LISTE de ces chemins. C'était une ÉNUMÉRATION, et deux chemins LIVRÉS
//! étaient dehors. Mesuré sur le VRAI binaire, base fichier réelle estampillée 111 dont `net_ban` a été
//! droppée — l'état exact que le daemon REFUSE de servir :
//!   `plume-daemon token`     -> sortie 1, token NON créé            (le contrat mordait)
//!   `plume-daemon respond`   -> sortie 0, ET IL A ÉCRIT (action 1 `approved` -> `failed`, done_ts posé)
//!   `plume-daemon retention` -> sortie 0, « rétention OK »
//! et sur une base EN RETARD de 5 migrations (version forcée à 106, `ai_provider`/`saved_query`
//! absentes = ce que produit une montée de binaire) : `respond` et `retention` sortaient 0, écrivaient,
//! et laissaient la base en 106. `respond` n'est pas une commande de dépannage : c'est
//! `systemd/plume-respond.service`, lancée EN ROOT toutes les 20 s (`plume-respond.timer`).
//!
//! CE QUI ÉTAIT FERMÉ, ET CE QUI NE L'ÉTAIT PAS. `migrate` est privée hors test : « appeler `migrate`
//! sans le contrat » ne compile pas. Mais la propriété qui compte n'est pas celle-là, c'est « obtenir
//! une connexion capable d'ÉCRIRE sans le contrat » — et `open_db`/`open_db_keyed` étaient `pub(crate)`,
//! donc un appelant de plus l'obtenait sans rien demander à personne.
//!
//! CE QUE CE MODULE FERME, PAR LE COMPILATEUR. Les deux ouvertures NUES (`raw_env`, `raw_keyed`) sont
//! PRIVÉES à ce module : hors d'ici, aucun code du daemon ne peut les NOMMER. Il ne reste que deux
//! façons d'obtenir une connexion sur un fichier, et il faut CHOISIR :
//!   - `PreparedDb::open*` — la valeur n'EXISTE que si la garde anti-downgrade ET `prepare_schema` ont
//!     été satisfaits ; son champ est privé au module, il n'y a pas d'autre constructeur. C'est le même
//!     geste que `PreparedWriter` (cache des writers tenant), généralisé au chemin GÉNÉRAL ;
//!   - `open_db_without_schema_contract` / `open_db_keyed_without_schema_contract` — le nom est long et
//!     laid EXPRÈS. Un chemin qui doit légitimement ouvrir hors contrat (sauvegarde d'une base ABÎMÉE,
//!     export de diagnostic, base qui n'est PAS une base plume, chiffrement at-rest qui tourne AVANT
//!     qu'un schéma existe) doit l'ÉCRIRE, et ça se voit en revue.
//! Aucune liste d'appelants n'est tenue ici : c'est précisément ce qui a échoué trois tours de suite.
//!
//! CE QUE LA PORTE APPLIQUE, DANS CET ORDRE (et l'ordre est load-bearing) :
//!   1. GARDE ANTI-DOWNGRADE (`schema_downgrade_guard`) — une LECTURE, AVANT toute écriture : une base
//!      estampillée PLUS HAUT que `CODE_SCHEMA_MAX` n'est pas touchée. Elle ne s'appliquait qu'au
//!      daemon ; elle s'applique maintenant à tout ce qui écrit (le responder ROOT compris), et c'est
//!      nécessaire à la propriété visée : sur une base v112, `prepare_schema` SEUL ne signale rien (un
//!      sur-ensemble n'est pas un manque) et laisserait donc écrire à l'aveugle.
//!   2. le PRÉLUDE optionnel, sur la connexion nue (le daemon y pose ses PRAGMA — `busy_timeout` est
//!      load-bearing pour le cas de contention mesuré dans `prepare_schema`) ;
//!   3. `prepare_schema` — `db/schema.sql`, la chaîne de migrations, puis la vérification que la base
//!      porte ce que CE binaire déclare (objets ET colonnes).
//!
//! PÉRIMÈTRE, ÉCRIT POUR ÊTRE OPPOSABLE — CE QUE LA PORTE NE FERME PAS :
//!   - `rusqlite::Connection::open` reste appelable depuis n'importe quel fichier : c'est le type d'une
//!     dépendance, aucune visibilité de ce crate ne peut le cacher. Ce reste-là est fermé par un TEST
//!     qui lit les SOURCES (`the_door_is_the_only_way_in`, plus bas) — pas par le compilateur, et la
//!     distinction est écrite ici pour ne pas être surestimée.
//!   - `ATTACH DATABASE` sur une connexion DÉJÀ ouverte : cela n'OBTIENT pas une connexion, cela étend
//!     celle qu'on a. Les 3 sites de production sont des exports SQLCipher vers un fichier de
//!     DESTINATION, jamais une base plume servie (mesuré :
//!     `grep -rn 'ATTACH DATABASE' daemon/src | grep -v daemon/src/tests/ | grep -v '//' | wc -l` -> 3 ;
//!     le filtre des commentaires exclut CETTE ligne-ci, qui sinon se compterait elle-même et rendrait 4).
//!   - le contrat porte sur le SCHÉMA, pas sur le CONTENU : une base au bon schéma dont les LIGNES ont
//!     été détruites passe la porte (périmètre déjà écrit dans `schema_gaps`).
use crate::*;

/// Ouverture NUE, clé SQLCipher de l'ENVIRONNEMENT. PRIVÉE au module — c'est tout le mécanisme.
/// Corps VERBATIM de l'ancien `crypto::open_db` (`apply_key` avale son erreur et pose le
/// `busy_timeout` de 5 s UNIQUEMENT dans la branche « une clé existe » : une base EN CLAIR n'en a
/// toujours aucun, cf. la doc de `prepare_schema`).
fn raw_env(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    apply_key(&conn);
    Ok(conn)
}

/// Ouverture NUE, clé EXPLICITE (paramètre, PAS l'env) — backup/restore et bases tenant ne dépendent
/// pas de `PLUME_DB_KEY`. PRIVÉE au module. Corps VERBATIM de l'ancien `backup::open_db_keyed` :
/// `None`/"" -> base EN CLAIR, et l'échec du `PRAGMA key` est PROPAGÉ (il est avalé côté `raw_env` :
/// cette asymétrie est historique et conservée telle quelle).
fn raw_keyed(path: &str, key: Option<&str>) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    if let Some(k) = key {
        if !k.is_empty() {
            conn.execute_batch(&format!("PRAGMA key = '{}';", k.replace('\'', "''")))?;
        }
    }
    Ok(conn)
}

/// Pourquoi la porte a refusé. Trois causes DISTINCTES parce que les appelants les traitent
/// différemment (le daemon n'imprime pas le même message pour un rollback d'image et pour un schéma
/// amputé), et parce qu'un appelant qui les confondrait serait illisible en exploitation.
#[derive(Debug)]
pub(crate) enum DbOpenError {
    /// Le fichier ne s'ouvre pas du tout (I/O, permission, chemin).
    Ouverture(rusqlite::Error),
    /// Base estampillée PLUS HAUT que ce binaire (rollback d'image sur une base déjà migrée).
    PlusRecenteQueCeBinaire(i64),
    /// Le contrat de schéma a refusé — message VERBATIM de `prepare_schema` (il nomme l'élément).
    Contrat(String),
}

impl std::fmt::Display for DbOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // message historique de `PreparedWriter::open` — conservé mot pour mot.
            DbOpenError::Ouverture(e) => write!(f, "ouverture impossible ({e})"),
            DbOpenError::PlusRecenteQueCeBinaire(v) => write!(
                f,
                "base en schema_version={v} > CODE_SCHEMA_MAX={CODE_SCHEMA_MAX} — ce binaire est TROP \
                 ANCIEN pour cette base (probable rollback d'image sur une base déjà migrée par un \
                 binaire plus récent). Aucune écriture effectuée"
            ),
            DbOpenError::Contrat(e) => write!(f, "{e}"),
        }
    }
}

/// UNE CONNEXION D'ÉCRITURE DONT LE CONTRAT DE SCHÉMA A ÉTÉ SATISFAIT — et ce n'est pas une convention
/// de relecture, c'est le TYPE : le champ est privé au module et il n'existe aucun autre constructeur.
/// `Deref` donne la `Connection` en lecture/écriture, mais on ne PEUT pas en obtenir une sans être
/// passé par `open*`.
pub(crate) struct PreparedDb(Connection);

impl PreparedDb {
    /// Clé SQLCipher de l'ENVIRONNEMENT (chemin des CLI et du daemon).
    pub(crate) fn open(path: &str) -> Result<Self, DbOpenError> {
        Self::open_with_prelude(path, |_| {})
    }

    /// Idem, avec un PRÉLUDE exécuté sur la connexion nue APRÈS la garde anti-downgrade et AVANT le
    /// contrat. Le daemon y pose ses PRAGMA (`tune`) : `busy_timeout` DOIT précéder `prepare_schema`,
    /// sinon une contention transitoire redevient un refus (mesuré,
    /// `write_contention_on_an_up_to_date_database_is_not_a_refusal`).
    pub(crate) fn open_with_prelude(path: &str, prelude: impl FnOnce(&Connection)) -> Result<Self, DbOpenError> {
        let conn = raw_env(path).map_err(DbOpenError::Ouverture)?;
        Self::seal(conn, prelude)
    }

    /// Clé EXPLICITE (base tenant : le fichier EST le tenant, sa clé n'est pas celle de l'env).
    pub(crate) fn open_keyed(path: &str, key: Option<&str>) -> Result<Self, DbOpenError> {
        Self::open_keyed_with_prelude(path, key, |_| {})
    }

    /// Clé explicite + prélude (provisioning d'un tenant : WAL/synchronous avant le contrat).
    pub(crate) fn open_keyed_with_prelude(
        path: &str,
        key: Option<&str>,
        prelude: impl FnOnce(&Connection),
    ) -> Result<Self, DbOpenError> {
        let conn = raw_keyed(path, key).map_err(DbOpenError::Ouverture)?;
        Self::seal(conn, prelude)
    }

    /// L'UNIQUE endroit où une `Connection` devient un `PreparedDb`. Tout ce qui est écrit dans la doc
    /// du module sur l'ORDRE se lit ici, en trois lignes.
    fn seal(conn: Connection, prelude: impl FnOnce(&Connection)) -> Result<Self, DbOpenError> {
        if let Err(v) = schema_downgrade_guard(&conn) {
            return Err(DbOpenError::PlusRecenteQueCeBinaire(v));
        }
        prelude(&conn);
        prepare_schema(&conn).map_err(DbOpenError::Contrat)?;
        Ok(PreparedDb(conn))
    }

    /// Rend la connexion (elle a passé le contrat — c'est la seule façon d'être arrivé ici).
    pub(crate) fn into_connection(self) -> Connection {
        self.0
    }
}

impl std::ops::Deref for PreparedDb {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}

/// OUVERTURE **SANS** LE CONTRAT DE SCHÉMA, clé de l'environnement. Le nom est la demande explicite :
/// il n'y a aucune liste d'appelants autorisés, il y a un nom qu'on lit en revue. À n'utiliser que
/// lorsque REFUSER serait pire que d'ouvrir : sauvegarder/exporter une base ABÎMÉE (refuser retirerait
/// l'outil de diagnostic au moment précis où il sert), ou toucher une base qui n'est PAS une base plume.
pub(crate) fn open_db_without_schema_contract(path: &str) -> rusqlite::Result<Connection> {
    raw_env(path)
}

/// Idem avec une clé EXPLICITE (backup/restore, control-plane, sondes de chiffrement at-rest).
pub(crate) fn open_db_keyed_without_schema_contract(path: &str, key: Option<&str>) -> rusqlite::Result<Connection> {
    raw_keyed(path, key)
}

/// VISIBILITÉ — ces deux noms n'existent QU'EN BUILD DE TEST, exactement comme `migrate` : les tests
/// fabriquent délibérément des bases qui ne satisfont PAS le contrat (base amputée, base en retard,
/// base d'un autre schéma), et c'est leur travail. En build de production ils n'existent pas : un
/// chemin de production qui les appellerait ne COMPILERAIT PAS (`cargo build --release`, dans la CI).
#[cfg(test)]
pub(crate) fn open_db(path: &str) -> rusqlite::Result<Connection> {
    raw_env(path)
}

/// Cf. `open_db` — test uniquement.
#[cfg(test)]
pub(crate) fn open_db_keyed(path: &str, key: Option<&str>) -> rusqlite::Result<Connection> {
    raw_keyed(path, key)
}

#[cfg(test)]
pub(crate) mod door_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    // ── LA MOITIÉ QUE LE COMPILATEUR NE FERME PAS ────────────────────────────────────────────────
    // `rusqlite::Connection::open` est le type d'une dépendance : aucune visibilité de ce crate ne
    // peut l'atteindre. Ce test lit les SOURCES et refuse qu'un fichier de production obtienne une
    // connexion ÉCRIVABLE ailleurs que par la porte. Il n'ÉNUMÈRE aucun appelant : il parcourt
    // l'arborescence, dérive lui-même quels fichiers sont des fichiers de TEST (depuis les
    // déclarations `#[cfg(test)] mod X;` du code), et échoue sur TOUT fichier de production non prévu.
    // Un fichier ajouté demain est couvert le jour où il est ajouté, sans que personne ne le déclare.

    /// Tous les `.rs` sous `daemon/src`, en profondeur.
    pub(crate) fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("lecture de {}: {e}", dir.display()))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    /// Les fichiers de TEST, DÉRIVÉS du code : tout `#[cfg(test)]` en colonne 0 suivi d'une
    /// déclaration de module FICHIER (`mod x;`) désigne `x.rs` ou `x/` — et tout ce qu'il contient.
    /// `#[cfg(test)] mod tests;` (main.rs, cold_store/mod.rs) tombe ici tout seul ; un futur
    /// `#[cfg(test)] mod autres_tests;` aussi.
    pub(crate) fn fichiers_de_test(files: &[PathBuf]) -> std::collections::BTreeSet<PathBuf> {
        let mut out = std::collections::BTreeSet::new();
        for f in files {
            let src = std::fs::read_to_string(f).unwrap();
            let lignes: Vec<&str> = src.lines().collect();
            for (i, l) in lignes.iter().enumerate() {
                if *l != "#[cfg(test)]" {
                    continue;
                }
                let Some(suivante) = lignes.get(i + 1) else { continue };
                let Some(reste) = suivante.strip_prefix("mod ").or_else(|| {
                    suivante.strip_prefix("pub(crate) mod ").or_else(|| suivante.strip_prefix("pub mod "))
                }) else {
                    continue;
                };
                let Some(nom) = reste.strip_suffix(';') else { continue }; // `mod x {` = module INLINE
                let dir = f.parent().unwrap();
                out.insert(dir.join(format!("{nom}.rs")));
                out.insert(dir.join(nom)); // forme `x/mod.rs` : le répertoire entier
            }
        }
        out
    }

    pub(crate) fn est_test(p: &Path, marques: &std::collections::BTreeSet<PathBuf>) -> bool {
        marques.iter().any(|m| p == m || p.starts_with(m))
    }

    /// Le TEXTE DE PRODUCTION d'un fichier : tout item en colonne 0 porté par `#[cfg(test)]` est
    /// retiré — module inline, fonction, `use`, `impl`, peu importe : la règle est la MÊME (sauter
    /// jusqu'au `;` ou jusqu'au `}` de la colonne 0), donc un item d'un genre inédit ne demande aucune
    /// ligne de plus. FAIL-CLOSED : un item qu'aucune des deux fins ne referme fait ÉCHOUER le test.
    pub(crate) fn texte_de_production(f: &Path, src: &str) -> Vec<(usize, String)> {
        let lignes: Vec<&str> = src.lines().collect();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < lignes.len() {
            if lignes[i] == "#[cfg(test)]" {
                // les autres attributs de l'item (`#[must_use]`, …) précèdent sa déclaration.
                let mut j = i + 1;
                while j < lignes.len() && lignes[j].starts_with("#[") {
                    j += 1;
                }
                assert!(j < lignes.len(), "{} : `#[cfg(test)]` sans item derrière", f.display());
                if lignes[j].ends_with(';') {
                    i = j + 1; // item d'une seule ligne (`mod x;`, `use x;`) — un module FICHIER est
                    continue; // traité par `fichiers_de_test`.
                }
                while j < lignes.len() && lignes[j] != "}" {
                    j += 1;
                }
                assert!(
                    j < lignes.len(),
                    "{}:{} — item `#[cfg(test)]` non refermé par un `}}` en colonne 0 : le scanner ne \
                     sait pas où il finit. Fail-closed : compléter la règle plutôt que l'ignorer.",
                    f.display(),
                    i + 1
                );
                i = j + 1;
                continue;
            }
            out.push((i + 1, sans_commentaire(lignes[i])));
            i += 1;
        }
        out
    }

    /// Retire le commentaire de fin de ligne. FAIL-CLOSED sur les cas douteux : une ligne portant une
    /// chaîne BRUTE (`r"`/`r#"`) n'est PAS tronquée (on préfère un faux positif bruyant à une
    /// troncature qui masquerait du code), et `://` (URL) n'ouvre pas un commentaire.
    pub(crate) fn sans_commentaire(l: &str) -> String {
        if l.contains("r\"") || l.contains("r#\"") {
            return l.to_string();
        }
        let b = l.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            if b[i] == b'/' && b[i + 1] == b'/' && (i == 0 || b[i - 1] != b':') {
                return l[..i].to_string();
            }
            i += 1;
        }
        l.to_string()
    }

    /// Cette ligne obtient-elle une connexion ÉCRIVABLE **sur une base plume** ? Dérivé de ce qu'EST une
    /// base plume — un fichier SQLite ouvert par `rusqlite` — et de ce qu'est l'écriture :
    ///   - `Connection::open*` (les 4 formes) et les deux noms de ce module réservés aux tests ;
    ///   - PAS `open_in_memory` : une base en mémoire n'est jamais la base d'un déploiement ;
    ///   - PAS `SQLITE_OPEN_READ_ONLY` : SQLite refuse alors toute écriture, et la propriété visée est
    ///     l'ÉCRITURE ;
    ///   - PAS un `Connection` QUALIFIÉ par un AUTRE moteur (`duckdb::Connection::open` — tier chaud
    ///     optionnel) : ce n'est ni SQLite, ni le fichier de la base plume, et aucun contrat de schéma
    ///     plume ne s'y applique. Renommer `rusqlite` pour se glisser dans cette exclusion est traité
    ///     comme une obtention (cf. les deux `use … as` ci-dessous).
    fn obtient_une_connexion_ecrivable(l: &str) -> bool {
        if l.contains("use rusqlite::Connection as") || l.contains("use rusqlite as") {
            return true; // renommer le type/le crate pour contourner le scanner est aussi une obtention
        }
        if l.contains("open_db(") || l.contains("open_db_keyed(") {
            return true;
        }
        match l.find("Connection::open") {
            None => false,
            Some(pos) => {
                let reste = &l[pos..];
                if reste.starts_with("Connection::open_in_memory") || l.contains("SQLITE_OPEN_READ_ONLY") {
                    return false;
                }
                // qualificateur éventuel : `x::Connection::open` — seul `rusqlite` est le moteur de la
                // base plume (un chemin NU est `rusqlite::Connection` importé au prélude du crate).
                match l[..pos].rfind("::") {
                    Some(fin) if fin + 2 == pos => {
                        let debut = l[..fin].rfind(|c: char| !c.is_alphanumeric() && c != '_').map_or(0, |i| i + 1);
                        &l[debut..fin] == "rusqlite"
                    }
                    _ => true,
                }
            }
        }
    }

    #[test]
    fn the_door_is_the_only_way_in() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner a trouvé les sources ({})", fichiers.len());
        let marques = fichiers_de_test(&fichiers);
        assert!(!marques.is_empty(), "précondition : au moins un module de test FICHIER est déclaré");
        let porte = racine.join("db_open.rs");

        let (mut fichiers_prod, mut lignes_prod, mut violations) = (0usize, 0usize, Vec::new());
        let mut la_porte_ouvre_vraiment = false;
        let mut sans_contrat: Vec<String> = Vec::new();
        for f in &fichiers {
            let src = std::fs::read_to_string(f).unwrap();
            if est_test(f, &marques) {
                continue;
            }
            fichiers_prod += 1;
            for (n, l) in texte_de_production(f, &src) {
                lignes_prod += 1;
                if *f != porte && l.contains("without_schema_contract(") {
                    sans_contrat.push(format!("{}:{n}: {}", f.display(), l.trim()));
                }
                if !obtient_une_connexion_ecrivable(&l) {
                    continue;
                }
                if *f == porte {
                    la_porte_ouvre_vraiment = true;
                } else {
                    violations.push(format!("{}:{n}: {}", f.display(), l.trim()));
                }
            }
        }
        println!(
            "[porte] {fichiers_prod} fichiers de production scannés ({} au total, {} sous un module de \
             test), {lignes_prod} lignes hors modules `#[cfg(test)]` ; {} ouverture(s) SANS contrat",
            fichiers.len(),
            fichiers.len() - fichiers_prod,
            sans_contrat.len()
        );
        assert!(
            la_porte_ouvre_vraiment,
            "ANTI-FAUX-VERT : le scanner n'a trouvé AUCUNE ouverture nue dans db_open.rs — le motif \
             cherché ne correspond plus au code, le test ne prouve donc plus rien."
        );
        assert!(
            violations.is_empty(),
            "un chemin de PRODUCTION obtient une connexion écrivable hors de la porte ({} site(s)) :\n{}\n\
             -> passer par `PreparedDb::open*` (contrat de schéma), ou dire explicitement \
             `open_db_without_schema_contract` / `open_db_keyed_without_schema_contract`.",
            violations.len(),
            violations.join("\n")
        );

        // LE NOM SUFFIT À RENDRE L'EXCEPTION VISIBLE ; LE COMPTE LA REND INÉVITABLE À VOIR. Sans ce
        // cliquet, un chemin qui écrit pourrait RETOURNER sous l'échappatoire (c'est exactement ce que
        // `respond` faisait) sans qu'un seul test bouge — mesuré : la mutation qui remet `respond` sur
        // `open_db_without_schema_contract` ne fait rougir AUCUN autre test. Le compte est une MESURE,
        // reproductible hors du test :
        //   grep -rn 'without_schema_contract(' daemon/src --include=*.rs | grep -v /tests/ | grep -v db_open.rs | wc -l
        // 13 depuis P8.3-a (exercice de restauration), et les DEUX ajouts sont des lectures qui
        // doivent aboutir PRÉCISÉMENT quand le schéma n'est pas celui de ce binaire :
        //   - `backup.rs` — la vérification d'une archive rouvre la base RESTAURÉE pour en compter le
        //     contenu. Une archive peut être plus ANCIENNE que le binaire qui la vérifie ; lui opposer
        //     le contrat transformerait un exercice de restauration réussi en échec, exactement quand
        //     il rend le plus service ;
        //   - `main.rs` — `restore-drill status` LIT une ligne `meta` et n'écrit rien. Passer par la
        //     porte la ferait MIGRER la base pour répondre à une question de lecture, et refuserait de
        //     dire depuis quand rien n'a été restauré au moment où cette réponse compte le plus.
        const SANS_CONTRAT_ATTENDUS: usize = 13;
        assert_eq!(
            sans_contrat.len(),
            SANS_CONTRAT_ATTENDUS,
            "le nombre d'ouvertures SANS contrat a changé. Ce n'est pas interdit — c'est un choix qui \
             doit se VOIR : mettre à jour SANS_CONTRAT_ATTENDUS dans le même commit, et dire dans le \
             message de commit pourquoi ce chemin doit écrire sur un schéma non vérifié.\nSites :\n{}",
            sans_contrat.join("\n")
        );
    }

    /// LE SCANNER LUI-MÊME EST MESURÉ, sinon il pourrait être vert en ne voyant rien. On lui donne les
    /// formes qu'il DOIT attraper et celles qu'il doit laisser passer — y compris celle qui a fait
    /// exister ce module (`open_db(` réintroduit dans un fichier de production).
    #[test]
    fn the_scanner_catches_what_it_claims_to_catch() {
        for attrape in [
            "    let conn = Connection::open(&path)?;",
            "let c = rusqlite::Connection::open(p).unwrap();",
            "let conn = Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;",
            "let conn = open_db(&db_path).expect(\"open db\");",
            "let conn = open_db_keyed(path, key)?;",
            "use rusqlite::Connection as C;",
        ] {
            assert!(obtient_une_connexion_ecrivable(attrape), "doit être attrapé : {attrape}");
        }
        for laisse in [
            "let conn = Connection::open_in_memory()?;",
            "let conn = Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;",
            "let db = PreparedDb::open(&db_path)?;",
            "let c = open_db_without_schema_contract(&path)?;",
            "let c = open_db_keyed_without_schema_contract(&path, key)?;",
            "let conn = duckdb::Connection::open(db_path).map_err(be)?;", // autre moteur, autre fichier
        ] {
            assert!(!obtient_une_connexion_ecrivable(laisse), "ne doit PAS être attrapé : {laisse}");
        }
        // le retrait des commentaires ne doit ni masquer du code, ni inventer des violations
        assert_eq!(sans_commentaire("let c = open_db(p); // note"), "let c = open_db(p); ");
        assert!(!obtient_une_connexion_ecrivable(&sans_commentaire("/// open_db(p) est le nom historique")));
        assert!(obtient_une_connexion_ecrivable(&sans_commentaire("let c = open_db(\"https://x\");")));
    }

    /// LE CONTRAT EST APPLIQUÉ PAR LA PORTE, SUR UNE BASE FICHIER RÉELLE — les trois issues, mesurées
    /// sur le comportement et pas sur la lecture du code : base saine acceptée, base AMPUTÉE refusée en
    /// NOMMANT l'objet et SANS rien réparer, base PLUS RÉCENTE refusée sans écrire une ligne.
    #[test]
    fn the_door_applies_the_contract_on_a_real_file() {
        let _tmpg1 = crate::tmp_possede::TmpPossede::neuf("porte");
        let base = _tmpg1.sous("plume.db").chemin().to_path_buf();
        let _ = std::fs::remove_file(&base);
        let p = base.to_str().unwrap();

        let db = PreparedDb::open(p).expect("base neuve : la porte la prépare");
        assert_eq!(read_schema_version(&db), CODE_SCHEMA_MAX);
        drop(db);
        assert!(PreparedDb::open(p).is_ok(), "2e ouverture sur une base à jour : acceptée");

        // (a) base AMPUTÉE d'un objet posé par une migration -> refus NOMMÉ, aucune réparation.
        {
            let c = open_db(p).unwrap();
            c.execute("DROP TABLE net_ban", []).unwrap();
        }
        match PreparedDb::open(p) {
            Err(DbOpenError::Contrat(e)) => assert!(e.contains("table net_ban"), "refus nommé : {e}"),
            autre => panic!("attendu : refus du contrat (obtenu : {})", autre.err().map(|e| e.to_string()).unwrap_or_else(|| "Ok".into())),
        }
        {
            let c = open_db(p).unwrap();
            let n: i64 = c
                .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name='net_ban'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "la porte CONSTATE : elle ne recrée rien en silence");
            c.execute_batch(
                "CREATE TABLE net_ban(ip TEXT NOT NULL, reason TEXT, created_ts INTEGER, expires_ts INTEGER, \
                 created_by TEXT, env_id TEXT NOT NULL DEFAULT 'prod', PRIMARY KEY(ip, env_id));",
            )
            .unwrap();
        }
        assert!(PreparedDb::open(p).is_ok(), "objet recréé : la base repasse la porte");

        // (b) base PLUS RÉCENTE que ce binaire : refus AVANT toute écriture.
        {
            let c = open_db(p).unwrap();
            c.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![(CODE_SCHEMA_MAX + 1).to_string()])
                .unwrap();
        }
        match PreparedDb::open(p) {
            Err(DbOpenError::PlusRecenteQueCeBinaire(v)) => assert_eq!(v, CODE_SCHEMA_MAX + 1),
            _ => panic!("attendu : refus anti-downgrade"),
        }
        {
            let c = open_db(p).unwrap();
            assert_eq!(read_schema_version(&c), CODE_SCHEMA_MAX + 1, "la version n'a pas été touchée");
        }
        let _ = std::fs::remove_file(&base);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// P10.17-a — LE CHECKPOINT WAL DIT S'IL A ÉCHOUÉ, AU LIEU DE SE TAIRE
// ═══════════════════════════════════════════════════════════════════════════════════════
//
// CE QUI ÉTAIT AVEUGLE. `PRAGMA wal_checkpoint(TRUNCATE)` ne rend PAS son verdict par un
// code d'erreur : il rend une LIGNE de trois colonnes `(busy, log, checkpointed)`. Un
// `busy` à 1 signifie que le checkpoint N'A PAS EU LIEU — un lecteur tenait le WAL. Or
// `execute_batch` ne lit aucune ligne de résultat : il rend `Ok(())` que la troncature ait
// eu lieu ou non. Les CINQ sites de production du démon appelaient tous `execute_batch`,
// et tous jetaient même ce `Ok` (`let _ =`).
//
// Le démon croyait donc tronquer son WAL après un backup, une fusion de rollups, un
// démarrage, un arrêt et une bascule SQLCipher — sans jamais distinguer « tronqué » de
// « refusé ». C'est la famille de défaut que cette campagne poursuit partout : un composant
// qui SAIT que son résultat est incomplet et le présente comme complet.
//
// POURQUOI UNE FONCTION UNIQUE ET NON CINQ CORRECTIFS. Corriger cinq appels laisse le
// sixième, écrit demain, aveugle. La garde `checkpoint_wal_passe_par_la_voie_unique`
// REFUSE tout `wal_checkpoint` en dehors d'ici : la couverture est acquise par
// CONSTRUCTION, pas par vigilance.
//
// CE QUE ÇA NE FAIT PAS : aucun changement de COMPORTEMENT. On ne réessaie pas, on ne
// bloque pas, on ne force pas de verrou — la base d'un SOC ne doit pas geler parce qu'une
// troncature a été refusée. On RAPPORTE, c'est tout. Le remède de fond (moins d'octets
// dans le WAL, via `journal_size_limit`) reste OUVERT sous `P10.16-a` : c'est un vrai
// changement de comportement sur une machine à 2 Gio, il ne se glisse pas dans ce lot.

/// Verdict d'un `wal_checkpoint(TRUNCATE)`, tel que SQLite le rend vraiment.
///
/// PAS `Copy` : la variante `Impossible` porte le message d'erreur. Le premier jet l'avait
/// dérivé et le compilateur a refusé — un `String` n'est pas copiable. Garder le message
/// plutôt que le type copiable : une panne muette ne vaut pas une commodité d'appel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Checkpoint {
    /// Le WAL a été replié ET tronqué. `pages` = pages recopiées dans la base.
    Tronque { pages: i64 },
    /// SQLite a rendu `busy=1` : un lecteur tenait le WAL, la troncature N'A PAS eu lieu.
    Refuse { restant_pages: i64 },
    /// Le PRAGMA lui-même a échoué (base fermée, E/S) — on nomme la cause au lieu de la taire.
    Impossible(String),
}

impl Checkpoint {
    pub(crate) fn a_tronque(&self) -> bool { matches!(self, Checkpoint::Tronque { .. }) }
}

/// Exécute `wal_checkpoint(TRUNCATE)` et LIT sa ligne de résultat.
///
/// `contexte` nomme l'appelant dans le journal : un « checkpoint refusé » sans savoir
/// lequel n'est pas exploitable.
pub(crate) fn checkpoint_wal_tronque(conn: &Connection, contexte: &str) -> Checkpoint {
    // `query_row` et NON `execute_batch` : c'est TOUT le correctif. Les trois colonnes sont
    // (busy, log, checkpointed) — cf. https://sqlite.org/pragma.html#pragma_wal_checkpoint
    let lu = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
    });
    match lu {
        // HORS MODE WAL, SQLite rend `busy=0` et `log = checkpointed = -1`. Le premier jet
        // tombait dans la branche nominale et annonçait « tronqué » avec `pages: -1` — un
        // succès pour une opération qui n'a pas eu lieu, c'est-à-dire le défaut même que
        // cette fonction existe pour fermer. Trouvé en ÉCRIVANT le témoin négatif du test.
        Ok((0, log, _)) if log < 0 => {
            Checkpoint::Impossible("base pas en mode WAL : il n'y a rien a tronquer".into())
        }
        Ok((0, _log, pages)) => Checkpoint::Tronque { pages },
        Ok((_busy, log, _)) => {
            eprintln!(
                "[wal] checkpoint TRUNCATE REFUSE ({contexte}) : un lecteur tient le WAL, \
                 {log} page(s) y restent. Rien n'a ete tronque — ce n'est pas une erreur, \
                 c'est un etat, et il est desormais VISIBLE."
            );
            Checkpoint::Refuse { restant_pages: log }
        }
        Err(e) => {
            eprintln!("[wal] checkpoint TRUNCATE IMPOSSIBLE ({contexte}) : {e}");
            Checkpoint::Impossible(e.to_string())
        }
    }
}
