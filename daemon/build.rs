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

/// LE COFFRE DE LA RÉSOLUTION PANNEAU∪BIBLIOTHÈQUE (P7.13-a) : `src/handlers/panneau_resolu.rs` est le
/// SEUL fichier autorisé à ÉCRIRE la résolution « la définition de bibliothèque gagne, sinon le panneau ».
const COFFRE_PANNEAU: &str = "src/handlers/panneau_resolu.rs";
/// Les DEUX formes que prend cette résolution en SQL : la jointure qui la rend possible, et la colonne
/// qui l'exprime. On garde le MÉCANISME (la jointure), pas l'orthographe d'une colonne : un futur site
/// qui résoudrait `title` ou un champ pas encore inventé est couvert le jour même.
const MOTIFS_RESOLUTION: &[&str] = &["LEFT JOIN library_panel", "COALESCE(lp."];

/// LE COFFRE DU CACHE DE PANNEAU (`P10.5-i`) : `src/handlers/panneau_avoue.rs` est le SEUL fichier de
/// PRODUCTION autorisé à lire ou écrire la table des résultats de panneaux mis en cache. Posséder ces
/// accès, c'est ce qui garantit qu'aucune réponse de panneau ne sort — servie, mémorisée ou figée dans
/// un instantané — sans l'aveu de provenance et l'horizon que le coffre estampe.
const COFFRE_CACHE_PANNEAU: &str = "src/handlers/panneau_avoue.rs";
/// LE NOM DE LA TABLE DANS SES QUATRE CONTEXTES D'ACCÈS SQL, ÉCRITS SOUS LEUR FORME NORMALISÉE
/// (cf. `ligne_normalisee_sql`). On garde le MÉCANISME (la table nommée là où SQL peut la lire ou
/// l'écrire), pas l'orthographe d'un INSERT : les motifs ancrés sur une écriture (`INTO panel_cache(`
/// sans espace, `SELECT payload` par adjacence) laissaient passer `INTO panel_cache (`,
/// `SELECT computed_at, payload` et `SELECT * FROM panel_cache`.
///
/// ET LA COMPARAISON EST NORMALISÉE, PARCE QUE LES MOTIFS SEULS RESTAIENT UNE ORTHOGRAPHE. MESURÉ : trois
/// écritures d'UNE SEULE LIGNE y échappaient encore — `"DELETE FROM  panel_cache …"` (deux espaces,
/// alignement de littéral banal ici), `"delete from panel_cache"` (SQL en minuscules, valide en SQLite,
/// et ce dépôt écrit déjà `"from user"` en minuscules) et `"SELECT payload FROM main.panel_cache"`
/// (schéma qualifié). La normalisation les ramène toutes les trois sur ces quatre motifs.
const MOTIFS_CACHE_PANNEAU: &[&str] =
    &["INTO PANEL_CACHE", "FROM PANEL_CACHE", "UPDATE PANEL_CACHE", "JOIN PANEL_CACHE"];
/// CE QUE LA GARDE NE PARCOURT PAS, ET POURQUOI CE N'EST PAS UN AVEU. `src/tests` est un SOUS-ARBRE
/// (dérivé), pas une liste de fichiers : un fichier de test ajouté demain en sort le jour même sans que
/// personne l'inscrive. Et rien n'y ship — `mod tests` est `#[cfg(test)]` —, donc aucun ÉCRIVAIN DE
/// PRODUCTION ne peut s'y cacher. Sans cette exclusion, la garde échouerait au premier `cargo build` sur
/// la fixture de `purge_clears_the_rendered_panel_cache`, que le correctif ne touche pas et qui n'a
/// aucune raison d'aller au coffre — et le module de témoins de ce même correctif, qui LIT la table pour
/// prouver que toute ligne porte son aveu, déclencherait la garde dans le même geste.
const HORS_PARCOURS_TESTS: &[&str] = &["src/tests"];

fn main() {
    // Re-run le build script uniquement si le contrat CIM embarqué change.
    println!("cargo:rerun-if-changed={CIM_JSON}");
    garde_temporaire_possede();
    garde_resolution_panneau();
    garde_cache_de_panneau();

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
    let fautifs = occurrences_hors_coffre(COFFRE_TMP, &[APPEL_TMP], &[], false);
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

/// GARDE-FOU À LA COMPILATION — LA RÉSOLUTION PANNEAU∪BIBLIOTHÈQUE VIT À UN SEUL ENDROIT (P7.13-a).
///
/// Mesuré le 2026-08-03 sur `3256e4d` : la porte « SQL brut = admin » de `panel_update` évaluait
/// `p.is_soql` pendant que l'exécuteur résolvait `COALESCE(lp.is_soql, p.is_soql)`. La bibliothèque
/// gagnait, la porte ne le savait pas : un `editor` rattachait une définition SQL BRUT d'admin (204)
/// et en lisait le résultat (200, 2 lignes de la table `user`). La résolution était écrite à TROIS
/// endroits ; c'est cette dispersion qui a permis à la porte d'en ignorer une.
///
/// La garde ne liste pas les sites — elle DÉRIVE (parcours récursif de `src/`) et interdit le
/// MÉCANISME hors du coffre : la jointure de résolution et sa forme colonne. Un quatrième site de
/// résolution ne peut donc plus naître en silence, il NE COMPILE PAS.
fn garde_resolution_panneau() {
    let fautifs = occurrences_hors_coffre(COFFRE_PANNEAU, MOTIFS_RESOLUTION, &[], false);
    if !fautifs.is_empty() {
        panic!(
            "\n\n  GARDE `panneau_resolu` — {n} résolution(s) panneau∪bibliothèque hors du coffre :\n\
             \x20   {liste}\n\n\
             \x20 La définition qu'un panneau EXÉCUTE (bibliothèque sinon panneau) se résout à UN SEUL\n\
             \x20 endroit, parce que la porte « SQL brut = admin » EMPRUNTE cette résolution. Une 2e\n\
             \x20 écriture la fait diverger de la porte — c'est exactement le contournement P7.13-a.\n\n\
             \x20   lire ce qu'un panneau exécute -> DefinitionExecutee::courante(conn, panel_id)\n\
             \x20   projeter ce qu'il exécutera   -> DefinitionExecutee::projetee(..)\n\
             \x20   projeter en SQL               -> panneau_resolu::JOINTURE / COL_QUERY / COL_IS_SOQL / …\n\n\
             \x20 Seul {COFFRE_PANNEAU} peut écrire la résolution.\n",
            n = fautifs.len(),
            liste = fautifs.join("\n     "),
        );
    }
}

/// GARDE-FOU À LA COMPILATION — LA TABLE DES RÉSULTATS DE PANNEAUX A UN SEUL PROPRIÉTAIRE (`P10.5-i`).
///
/// CE QU'ELLE PROTÈGE. Une réponse de panneau qui sort du démon — servie, mémorisée, ou figée dans un
/// instantané partageable par jeton — doit porter l'horizon sous lequel sa fenêtre n'a rien pu voir. Le
/// cache est le point de passage COMMUN de ces trois sorties : cinq écrivains distincts le remplissaient
/// (le handler de panneau à deux endroits, le rafraîchissement asynchrone, le pré-chauffage de fond) et
/// un aveu posé chez l'un aurait produit un champ dont la PRÉSENCE dépend de qui a rempli la ligne.
///
/// La garde ne liste pas les sites : elle DÉRIVE (parcours récursif de `src/`, moins le sous-arbre des
/// tests) et interdit le nom de la table hors du coffre, dans les quatre contextes où SQL peut la lire
/// ou l'écrire. Un sixième écrivain NE COMPILE PAS.
///
/// CE QU'ELLE NE TIENT PAS, ET IL FAUT LE DIRE : elle est LIGNE-À-LIGNE (`src.lines()`). Un énoncé qui
/// séparerait `FROM` de `panel_cache` par un retour à la ligne y échapperait. Le mécanisme est réutilisé
/// VERBATIM plutôt que remplacé par un scanner multi-ligne, et le résidu est nommé plutôt que tu.
fn garde_cache_de_panneau() {
    let fautifs = occurrences_hors_coffre(COFFRE_CACHE_PANNEAU, MOTIFS_CACHE_PANNEAU, HORS_PARCOURS_TESTS, true);
    if !fautifs.is_empty() {
        panic!(
            "\n\n  GARDE `cache_de_panneau` — {n} accès à la table des résultats de panneaux hors du coffre :\n\
             \x20   {liste}\n\n\
             \x20 Une réponse de panneau ne sort JAMAIS sans dire jusqu'où elle a pu voir. Le cache est le\n\
             \x20 point de passage commun des trois sorties (servie, mémorisée, figée dans un instantané) :\n\
             \x20 un écrivain de plus, et l'aveu devient un champ dont la présence dépend de QUI a rempli\n\
             \x20 la ligne.\n\n\
             \x20   écrire une réponse   -> panneau_avoue::cache_ecrire(..)\n\
             \x20   lire une réponse     -> panneau_avoue::cache_lire(..)\n\
             \x20   invalider / vider    -> panneau_avoue::cache_invalider_panneau / _bibliotheque / cache_vider\n\
             \x20   depuis un MigTx      -> panneau_avoue::SQL_VIDE_TOUT_LE_CACHE / SQL_INVALIDE_UN_PANNEAU\n\n\
             \x20 Seul {COFFRE_CACHE_PANNEAU} peut nommer cette table dans un accès. Le DDL, lui, reste au\n\
             \x20 moteur de migration : posséder les ACCÈS n'est pas posséder le SCHÉMA.\n",
            n = fautifs.len(),
            liste = fautifs.join("\n     "),
        );
    }
}

/// Les occurrences de CODE (hors commentaire) de `motifs` dans `src/`, en dehors du fichier-coffre et des
/// SOUS-ARBRES `exclus`.
/// La liste des fichiers examinés est DÉRIVÉE de l'arborescence : un fichier ajouté demain est couvert
/// le jour même, sans que personne ait à l'inscrire quelque part.
///
/// `normalise` — comparer sur la ligne NORMALISÉE (casse, espacement, schéma SQL qualifié) plutôt que sur
/// son orthographe. `false` -> comparaison BYTE À BYTE, strictement celle d'avant ce paramètre : les deux
/// gardes historiques cherchent des identifiants RUST (`env::temp_dir`, `COALESCE(lp.`), dont la casse
/// est portante et que normaliser rendrait faux.
fn occurrences_hors_coffre(coffre: &str, motifs: &[&str], exclus: &[&str], normalise: bool) -> Vec<String> {
    println!("cargo:rerun-if-changed=src");
    let mut fautifs = Vec::new();
    parcourir(Path::new("src"), exclus, &mut |f: &Path| {
        if f.extension().and_then(|e| e.to_str()) != Some("rs") {
            return;
        }
        // Le coffre EST l'exception, et il est nommé une seule fois (const en tête).
        if f == Path::new(coffre) {
            return;
        }
        let Ok(src) = fs::read_to_string(f) else {
            return;
        };
        for (i, ligne) in src.lines().enumerate() {
            let ligne = if normalise { ligne_normalisee_sql(ligne) } else { ligne.to_string() };
            if motifs.iter().any(|m| hors_commentaire(&ligne, m)) {
                fautifs.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    });
    fautifs
}

/// LA LIGNE RAMENÉE À LA FORME OÙ UN NOM DE TABLE SE COMPARE : majuscules (les mots-clés SQL sont
/// insensibles à la casse et ce dépôt en écrit déjà en minuscules), runs d'espacement réduits à UNE
/// espace (un littéral SQL aligné en porte deux), et préfixes de schéma SQLite retirés
/// (`main.` / `temp.`, les deux seuls que SQLite reconnaisse sans `ATTACH`). Le `//` d'un commentaire
/// survit à la transformation, donc `hors_commentaire` continue de trancher sur le résultat.
fn ligne_normalisee_sql(ligne: &str) -> String {
    let haut = ligne.to_ascii_uppercase().replace("MAIN.", "").replace("TEMP.", "");
    haut.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Vrai si la ligne porte le motif en tant que CODE (et ne fait pas que le mentionner). Une occurrence
/// précédée d'un `//` sur la même ligne est du commentaire : une garde doit pouvoir être DOCUMENTÉE
/// sans se déclencher elle-même.
fn hors_commentaire(ligne: &str, motif: &str) -> bool {
    match ligne.find(motif) {
        None => false,
        Some(pos) => match ligne.find("//") {
            Some(c) => c > pos, // `//` APRÈS l'occurrence -> c'est bien du code
            None => true,
        },
    }
}

/// Parcours récursif : la liste des fichiers gardés est DÉRIVÉE de l'arborescence, pas écrite à la main.
/// `exclus` = des SOUS-ARBRES (préfixes de chemin), jamais des fichiers : ce qu'on exclut est une zone
/// dont on peut dire une propriété (« rien n'y ship »), pas une liste d'exceptions qu'il faudrait tenir.
/// `&[]` -> parcours INCHANGÉ, byte-identique à celui d'avant ce paramètre.
fn parcourir(dir: &Path, exclus: &[&str], f: &mut impl FnMut(&Path)) {
    if exclus.iter().any(|x| dir.starts_with(Path::new(x))) {
        return;
    }
    let Ok(entrees) = fs::read_dir(dir) else {
        return;
    };
    for e in entrees.flatten() {
        let p = e.path();
        if p.is_dir() {
            parcourir(&p, exclus, f);
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
