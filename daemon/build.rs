//! Build script — GARDE-FOU CIM à la COMPILATION (compagnon du test runtime
//! `cim_const_mirror_matches_config_schema`).
//!
//! Extrait la `"version"` du contrat CIM EMBARQUÉ dans le dépôt plume
//! (`config.d/cim/cim.v1.json`) et l'émet en `const CIM_CONFIG_VERSION`. Le daemon
//! (`soql_glue.rs`) l'inclut puis assert-const qu'elle égale
//! `guatx_core::cim::CIM_VERSION` du cœur LINKÉ : un build lié à un cœur STALE/faux
//! (version divergente) ÉCHOUE à COMPILER — plus jamais un simple échec de test.
//!
//! Zéro dépendance de build ajoutée : extraction de champ à la main (robuste), pas de
//! serde_json. Compile-time only, aucun code runtime généré.

use std::{env, fs, path::Path};

// Le contrat CIM vit à la racine du dépôt plume ; ce build.rs tourne depuis `daemon/`.
const CIM_JSON: &str = "../config.d/cim/cim.v1.json";

/// LE COFFRE DU TEMPORAIRE : `src/tmp_possede.rs` est le SEUL fichier autorisé à demander la racine
/// temporaire du système. Partout ailleurs, un temporaire doit naître dans un répertoire POSSÉDÉ
/// (`TmpPossede`/`TmpDb`), effacé récursivement à sa destruction.
const COFFRE_TMP: &str = "src/tmp_possede.rs";
/// L'appel interdit hors du coffre. Cherché comme TEXTE de code (les mentions en commentaire sont
/// ignorées, cf. `appel_hors_commentaire`).
const APPEL_TMP: &str = "env::temp_dir";

fn main() {
    // Re-run le build script uniquement si le contrat CIM embarqué change.
    println!("cargo:rerun-if-changed={CIM_JSON}");
    garde_temporaire_possede();

    let json = fs::read_to_string(CIM_JSON).unwrap_or_else(|e| {
        panic!("build.rs: lecture impossible de {CIM_JSON} (contrat CIM embarqué) : {e}")
    });

    let version = extract_version(&json).unwrap_or_else(|| {
        panic!("build.rs: champ de tête \"version\": \"…\" introuvable dans {CIM_JSON}")
    });

    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("cim_config_version.rs");
    fs::write(
        &out,
        format!(
            "/// Version du CIM embarqué (`config.d/cim/cim.v1.json`), extraite au build par build.rs.\n\
             pub const CIM_CONFIG_VERSION: &str = \"{version}\";\n"
        ),
    )
    .unwrap_or_else(|e| panic!("build.rs: écriture impossible de {}: {e}", out.display()));
}

/// GARDE-FOU À LA COMPILATION — le temporaire POSSÉDÉ (P7.1-a).
///
/// Mesuré le 2026-08-03 sur `01a5cf0`, `$TMPDIR` détourné sur disque : la suite daemon laissait
/// **136 fichiers / 38,4 Mio par exécution**, dont **53 `-wal` + 53 `-shm` ORPHELINS** — les
/// fixtures effaçaient le chemin qu'elles avaient NOMMÉ, et SQLite en crée deux autres à côté que
/// personne n'avait nommés. La correction ne liste pas les sidecars à effacer : elle POSSÈDE le
/// répertoire qui les contient.
///
/// Cette garde ferme la voie de contournement. La liste des fichiers examinés est DÉRIVÉE (parcours
/// récursif de `src/`), jamais énumérée : un fichier ajouté demain est couvert le jour même, sans
/// que personne ait à y penser. Un appel direct à la racine temporaire du système hors du coffre
/// FAIT ÉCHOUER LE BUILD — plus jamais un test qui passe au vert en semant dans le `/tmp` d'autrui.
fn garde_temporaire_possede() {
    println!("cargo:rerun-if-changed=src");
    let mut fautifs = Vec::new();
    parcourir(Path::new("src"), &mut |f: &Path| {
        if f.extension().and_then(|e| e.to_str()) != Some("rs") {
            return;
        }
        // Le coffre EST l'exception, et il est nommé une seule fois (const ci-dessus).
        if f == Path::new(COFFRE_TMP) {
            return;
        }
        let Ok(src) = fs::read_to_string(f) else {
            return;
        };
        for (i, ligne) in src.lines().enumerate() {
            if appel_hors_commentaire(ligne) {
                fautifs.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    });
    if !fautifs.is_empty() {
        panic!(
            "\n\n  GARDE `tmp_possede` — {n} appel(s) direct(s) à la racine temporaire du système hors du coffre :\n\
             \x20   {liste}\n\n\
             \x20 Un temporaire doit être POSSÉDÉ : il naît dans un répertoire à lui, effacé\n\
             \x20 récursivement à la destruction du garde — donc AUSSI les `-wal`/`-shm`/`-journal`\n\
             \x20 que personne n'a nommés (c'était 90 % de la fuite mesurée).\n\n\
             \x20   fixture d'un fichier   -> crate::tmp_possede::TmpDb::neuf(\"étiquette\")\n\
             \x20   fixture d'un dossier   -> crate::tmp_possede::TmpPossede::neuf(\"étiquette\")\n\
             \x20   besoin PRODUCTION      -> crate::tmp_possede::racine_systeme()\n\n\
             \x20 Seul {COFFRE_TMP} peut interroger la racine du système.\n",
            n = fautifs.len(),
            liste = fautifs.join("\n     "),
        );
    }
}

/// Vrai si la ligne APPELLE la racine temporaire (et ne fait pas que la mentionner). Une occurrence
/// précédée d'un `//` sur la même ligne est du commentaire : la garde doit pouvoir être DOCUMENTÉE
/// sans se déclencher elle-même.
fn appel_hors_commentaire(ligne: &str) -> bool {
    match ligne.find(APPEL_TMP) {
        None => false,
        Some(pos) => match ligne.find("//") {
            Some(c) => c > pos, // `//` APRÈS l'appel -> l'appel est bien du code
            None => true,
        },
    }
}

/// Parcours récursif : la liste des fichiers gardés est DÉRIVÉE de l'arborescence, pas écrite à la main.
fn parcourir(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entrees) = fs::read_dir(dir) else {
        return;
    };
    for e in entrees.flatten() {
        let p = e.path();
        if p.is_dir() {
            parcourir(&p, f);
        } else {
            f(&p);
        }
    }
}

/// Extrait la valeur du champ objet `"version": "X"`. Cherche la CLÉ `"version"` suivie
/// (après espaces optionnels) d'un `:`, puis lit la chaîne entre guillemets qui suit. On
/// exige le `:` pour ne jamais confondre la clé avec une valeur textuelle valant "version".
fn extract_version(s: &str) -> Option<String> {
    const KEY: &str = "\"version\"";
    let b = s.as_bytes();
    let mut search = 0usize;
    while let Some(rel) = s[search..].find(KEY) {
        let mut i = search + rel + KEY.len();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < b.len() && b[i] == b':' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && b[i] == b'"' {
                i += 1;
                let start = i;
                while i < b.len() && b[i] != b'"' {
                    i += 1;
                }
                if i <= b.len() {
                    return Some(s[start..i].to_string());
                }
            }
        }
        search += rel + KEY.len();
    }
    None
}
