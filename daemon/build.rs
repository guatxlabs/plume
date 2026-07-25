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

fn main() {
    // Re-run le build script uniquement si le contrat CIM embarqué change.
    println!("cargo:rerun-if-changed={CIM_JSON}");

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
