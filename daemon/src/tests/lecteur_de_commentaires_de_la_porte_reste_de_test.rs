// =====================================================================================
// `P10.20-o` — LE LECTEUR DE COMMENTAIRES DE `db_open.rs` N'EXISTE QU'EN BUILD DE TEST.
//
// L'ÉNONCÉ, RE-MESURÉ LE 2026-10-07 SUR L'ARBRE `ddc7530`, ÉTAIT FAUX. Il disait qu'un cinquième
// lecteur de commentaires Rust « vit en PRODUCTION, dans `db_open.rs` ». Le lecteur
// (`sans_commentaire`, daemon/src/db_open.rs:564) est défini DANS `#[cfg(test)] pub(crate) mod
// door_tests` (db_open.rs:460, refermé en colonne 0 à la ligne 806) : il n'est pas compilé dans le
// binaire, et rien de ce que le démon fait à l'ouverture d'une base n'en dépend. Ses consommateurs sont
// tous des TESTS. Directs (import `door_tests::…sans_commentaire`), sous `daemon/src/tests/` :
// `backup_streaming`, `checkpoint_wal_voie_unique`, `cles_de_cause_gardees`,
// `posture_de_sauvegarde_native`, `wal_empreinte`. Indirects, par `texte_de_production` qui l'appelle :
// `door_tests` lui-même (la porte unique `the_door_is_the_only_way_in`), et les témoins qui lisent le
// texte de production (`cold_banniere`, `sqlite_plafond`, `dedup_flotte`, `partition_config`,
// `tri_en_memoire_voie_unique`, `enonces_du_vieillissement`, …). Aucun des 175 fichiers de production ne
// le nomme dans son texte hors `#[cfg(test)]`.
//
// CE QUE SA GRAMMAIRE LIT DE TRAVERS (mesuré contre le lecteur partagé `sans_commentaires_rust`,
// `.github/scripts/check_every_help_trigger_has_a_section.py`) : 150 lignes du corpus lues autrement,
// dont 35 dans le texte de production des fichiers non-test — 29 lignes portant une chaîne brute
// (`r"`) dont le commentaire de fin de ligne est GARDÉ (fail-closed voulu), 5 commentaires de bloc
// en ligne gardés comme du code, 1 ligne de code TRONQUÉE sur un `//` posé dans une chaîne
// (daemon/src/sink_s3.rs:305, `cle.contains("//") {`). Aucune ne fait apparaître ni disparaître une
// ouverture de connexion dans le texte de production : le verdict de la porte n'est pas déplacé
// aujourd'hui. Les angles morts (un `//` dans une chaîne masque ce qui suit sur la même ligne — sens
// muet ; un commentaire de bloc est lu comme du code — sens bruyant) relèvent d'une clé NEUVE et ne
// sont pas corrigés ici.
//
// CE QUE CE TÉMOIN TIENT, ET PAR QUEL MOYEN :
// 1. le `#[cfg(test)]` est COLLÉ à `pub(crate) mod door_tests {` dans le texte BRUT de db_open.rs : entre
//    les deux, seules des lignes qui ne sont QU'UN attribut (le `]` qui referme `#[` finit la ligne). Une
//    ligne `#[inline] fn _leurre() {}` porte un item qui prendrait le cfg : elle est refusée. C'est ce qui
//    met le lecteur hors du binaire ; ce n'est PAS lu par `texte_de_production`, dont le saut d'item
//    (`starts_with("#[")`) se laisse détourner par ce même leurre. Le test joue les leurres sur des
//    variantes du texte brut, et vérifie qu'un attribut seul sur sa ligne reste admis.
// 2. la définition existe une fois, et au moins 5 fichiers de test AUTRES QUE CE TÉMOIN l'importent.
// 3. le texte de production d'aucun fichier non-test ne nomme le lecteur. Ce point-là est lu par la
//    grammaire par ligne du lecteur lui-même : un appel posé après un `//` situé dans une chaîne, sur la
//    même ligne, lui échappe. Pour un fichier de production ce n'est pas un trou du binaire livré : tant
//    que le point 1 tient, `door_tests` n'existe pas hors test et `cargo build` refuse l'appel. Le point
//    3 rattrape le cas simple et nomme le site ; le point 1 est la garde.
// =====================================================================================
mod lecteur_de_commentaires_de_la_porte_reste_de_test {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    const DEFINITION_DU_LECTEUR: &str = "fn sans_commentaire(";
    const DECLARATION_DU_MODULE: &str = "pub(crate) mod door_tests {";
    const CE_TEMOIN: &str = "lecteur_de_commentaires_de_la_porte_reste_de_test.rs";

    /// Vrai si la ligne (rognée) n'est QU'UN attribut : elle commence par `#[` et le `]` qui referme ce
    /// `[` est son dernier caractère. Une ligne `#[inline] fn _leurre() {}` ou `#[derive(Debug)] struct
    /// _X;` porte un ITEM : elle prendrait le `#[cfg(test)]` au-dessus d'elle et doit donc arrêter la
    /// remontée. Un attribut sur plusieurs lignes n'est pas admis non plus (refus, sens bruyant).
    fn n_est_qu_un_attribut(l: &str) -> bool {
        if !l.starts_with("#[") {
            return false;
        }
        let mut profondeur = 0usize;
        for (k, c) in l.char_indices() {
            match c {
                '[' => profondeur += 1,
                ']' => {
                    profondeur -= 1;
                    if profondeur == 0 {
                        return k + 1 == l.len();
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Dans le texte BRUT : la déclaration du module existe une fois, et l'attribut `#[cfg(test)]` la
    /// précède immédiatement (seules d'autres lignes qui ne sont QU'UN attribut admises entre les deux).
    /// Rend `Err(raison)` sinon.
    fn cfg_test_colle_au_module(src: &str) -> Result<(), String> {
        let lignes: Vec<&str> = src.lines().collect();
        let declarations: Vec<usize> =
            lignes.iter().enumerate().filter(|(_, l)| l.trim() == DECLARATION_DU_MODULE).map(|(i, _)| i).collect();
        let [i] = declarations[..] else {
            return Err(format!("`{DECLARATION_DU_MODULE}` attendu une fois dans db_open.rs, vu {}", declarations.len()));
        };
        for j in (0..i).rev() {
            let l = lignes[j].trim();
            if l == "#[cfg(test)]" {
                return Ok(());
            }
            if !n_est_qu_un_attribut(l) {
                return Err(format!(
                    "db_open.rs:{} — `{}` s'interpose avant `{DECLARATION_DU_MODULE}` (ligne {}) sans `#[cfg(test)]` collé",
                    j + 1,
                    l,
                    i + 1
                ));
            }
        }
        Err("aucun `#[cfg(test)]` avant la déclaration du module".into())
    }
    const NOMS_DU_LECTEUR: [&str; 2] = ["sans_commentaire", "door_tests"];

    /// Les sites du TEXTE DE PRODUCTION (fichiers non-test, items `#[cfg(test)]` retirés) qui
    /// définissent ou nomment le lecteur de la porte.
    fn sites_de_production_du_lecteur(sources: &[(PathBuf, String)], tests: &BTreeSet<PathBuf>) -> Vec<String> {
        let mut sites = Vec::new();
        for (chemin, src) in sources {
            if est_test(chemin, tests) {
                continue;
            }
            for (ligne, texte) in texte_de_production(chemin, src) {
                if NOMS_DU_LECTEUR.iter().any(|n| texte.contains(n)) {
                    sites.push(format!("{}:{} — {}", chemin.display(), ligne, texte.trim()));
                }
            }
        }
        sites
    }

    fn corpus() -> (Vec<(PathBuf, String)>, BTreeSet<PathBuf>) {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let tests = fichiers_de_test(&fichiers);
        let sources: Vec<(PathBuf, String)> = fichiers
            .into_iter()
            .map(|p| {
                let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("lecture de {}: {e}", p.display()));
                (p, s)
            })
            .collect();
        (sources, tests)
    }

    #[test]
    fn le_lecteur_de_commentaires_de_db_open_n_existe_qu_en_build_de_test() {
        let (sources, tests) = corpus();

        // Témoin POSITIF : la définition existe, une fois, dans un fichier de PRODUCTION.
        let (chemin_db_open, src_db_open) = sources
            .iter()
            .find(|(p, _)| p.ends_with("db_open.rs"))
            .expect("daemon/src/db_open.rs introuvable : le témoin ne regarde plus rien");
        assert!(!est_test(chemin_db_open, &tests), "db_open.rs est un fichier de PRODUCTION");
        assert_eq!(
            src_db_open.matches(DEFINITION_DU_LECTEUR).count(),
            1,
            "le lecteur `sans_commentaire` doit être défini une fois dans db_open.rs : sinon ce témoin \
             ne prouve plus rien"
        );
        // La garde : le module qui porte le lecteur est attaché à `#[cfg(test)]`, lu sur le texte BRUT.
        if let Err(raison) = cfg_test_colle_au_module(src_db_open) {
            panic!("le module `door_tests` (et son lecteur de commentaires) n'est plus réservé au build de test : {raison}");
        }
        // Témoin POSITIF des consommateurs : des fichiers de TEST (ce témoin exclu) l'importent bel et bien.
        let consommateurs_de_test = sources
            .iter()
            .filter(|(p, s)| {
                !p.ends_with(CE_TEMOIN)
                    && est_test(p, &tests)
                    && s.contains("door_tests::")
                    && s.contains("sans_commentaire")
            })
            .count();
        // Témoin de la GARDE elle-même, sur des variantes du texte brut : un item d'une ligne portant un
        // attribut, glissé entre `#[cfg(test)]` et le module, prend le cfg et doit être refusé ; un
        // simple attribut supplémentaire reste admis.
        let collage = format!("#[cfg(test)]\n{DECLARATION_DU_MODULE}");
        assert_eq!(src_db_open.matches(&collage).count(), 1, "le collage `#[cfg(test)]` + module attendu tel quel");
        for leurre in ["#[inline] fn _leurre() {}", "#[derive(Debug)] struct _X;", "#[allow(dead_code)] const _A: [u8; 1] = [0];"] {
            let variante = src_db_open.replace(&collage, &format!("#[cfg(test)]\n{leurre}\n{DECLARATION_DU_MODULE}"));
            assert!(
                cfg_test_colle_au_module(&variante).is_err(),
                "la garde laisse passer `{leurre}` entre `#[cfg(test)]` et le module : le cfg irait à l'item"
            );
        }
        let admise = src_db_open.replace(&collage, &format!("#[cfg(test)]\n#[allow(dead_code)]\n{DECLARATION_DU_MODULE}"));
        assert!(cfg_test_colle_au_module(&admise).is_ok(), "un attribut seul sur sa ligne doit rester admis");

        assert!(
            consommateurs_de_test >= 5,
            "attendu au moins 5 fichiers de test (hors ce témoin) qui importent le lecteur, vu {consommateurs_de_test}"
        );

        // La propriété : aucun texte de production ne le définit ni ne le nomme.
        let sites = sites_de_production_du_lecteur(&sources, &tests);
        assert!(
            sites.is_empty(),
            "le lecteur de commentaires de la porte (`db_open::door_tests::sans_commentaire`) est sorti du \
             build de test — sa grammaire par ligne n'est pas faite pour décider en production :\n{}",
            sites.join("\n")
        );
    }
}
