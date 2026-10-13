// P7.18-a — LA COUVERTURE DU PLAFOND QUITTE `sqlite_plafond` ; LE PLAFOND, LUI, RESTE
// ================================================================================================
// Le bloc « couverture » (`enum Couverture`, `couverture_pour`, `impl Couverture` : verdict, prédicat
// `protege`, phrase de la bannière) est sorti de `sqlite_plafond.rs` vers la feuille
// `couverture_du_plafond.rs` par déplacement pur (empreinte SHA-256 de la tranche identique, à cinq
// `pub(crate) ` près). Le tri de la vague proposait d'emporter aussi `Plafond` + `plafond_pour` comme
// « coupe pure » : c'était FAUX. `Plafond::pragma` GRAVE `PRAGMA hard_heap_limit=…` — la déplacer
// faisait de la feuille un second auteur du budget mémoire, que la garde accuse. Ce que ces témoins
// tiennent :
//   (a) la feuille passe la garde du budget sans violation ;
//   (b) la feuille n'a AUCUNE exception dans la garde : posées dans la feuille, la ligne réelle qui grave
//       le plafond de tas (`Plafond` doit rester dans la façade), une LECTURE pure et une écriture
//       COMPOSÉE y sont accusées — ces deux dernières sont les voies que l'exception de lecture de
//       `tri_des_connexions.rs` laisse passer : c'est la GARDE qui est jugée, pas deux constantes ;
//   (c) la frontière : la façade ne définit plus `Couverture`, la feuille la définit une fois ; `Plafond`
//       reste défini une fois dans la façade et zéro dans la feuille ; l'état d'avant est refusé ;
//   (d) aucun changement de comportement : les phrases des QUATRE verdicts, octet pour octet, et
//       `rapport()` porte bien la phrase rendue par la feuille.
//
// CE QUE CES TÉMOINS NE PROUVENT PAS : la bannière sous un déversement RÉEL (processus lancé avec
// `PLUME_SQLITE_DEVERSEMENT=1`) — la suite tourne au défaut ; ni la couverture sous une VRAIE limite de
// cgroup franchie (la machine de test rend ce qu'elle rend : (d) n'accepte que l'une des phrases
// possibles pour la limite lue, il ne choisit pas laquelle).

#[cfg(test)]
mod couverture_du_plafond_hors_budget_tests {
    use crate::couverture_du_plafond::couverture_pour;
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    use crate::limite_cgroup::{limite_cgroup, LimiteCgroup};
    use crate::sqlite_plafond::plafond_tests::{juger_le_budget, FEUILLE_QUI_RELIT};
    use std::path::PathBuf;

    const FEUILLE: &str = "couverture_du_plafond.rs";
    const FACADE: &str = "sqlite_plafond.rs";
    /// Ce qui SORT : défini zéro fois dans la façade, une fois dans la feuille.
    const SORTIES: [&str; 3] = ["enum Couverture {", "fn couverture_pour(", "impl Couverture {"];
    /// Ce qui RESTE : défini une fois dans la façade, zéro fois dans la feuille.
    const RESTES: [&str; 3] = ["enum Plafond {", "fn plafond_pour(", "impl Plafond {"];

    fn racine() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn textes_reels() -> Vec<(PathBuf, String)> {
        let mut fichiers = Vec::new();
        rs_files(&racine(), &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        fichiers
            .iter()
            .filter(|f| !est_test(f, &marques))
            .map(|f| (f.clone(), std::fs::read_to_string(f).unwrap()))
            .collect()
    }

    fn lire(nom: &str) -> String {
        std::fs::read_to_string(racine().join(nom)).unwrap()
    }

    /// Lignes de PRODUCTION (hors `#[cfg(test)]`, hors commentaires) qui DÉFINISSENT `def`, `pub(crate) `
    /// admis devant.
    fn definitions(chemin: &str, src: &str, def: &str) -> usize {
        texte_de_production(std::path::Path::new(chemin), src)
            .iter()
            .filter(|(_, l)| l.starts_with(def) || l.strip_prefix("pub(crate) ").is_some_and(|r| r.starts_with(def)))
            .count()
    }

    /// LE JUGEMENT DE LA FRONTIÈRE, pur pour être exercé sur l'état d'AVANT.
    fn juger_la_frontiere(facade: &str, feuille: Option<&str>) -> Vec<String> {
        let mut v = Vec::new();
        let Some(feuille) = feuille else {
            return vec![format!("{FEUILLE} absente")];
        };
        for (def, dans_facade, dans_feuille) in SORTIES.iter().map(|d| (d, 0, 1)).chain(RESTES.iter().map(|d| (d, 1, 0))) {
            let n = definitions(FACADE, facade, def);
            if n != dans_facade {
                v.push(format!("{FACADE} définit `{def}` {n} fois (attendu {dans_facade})"));
            }
            let m = definitions(FEUILLE, feuille, def);
            if m != dans_feuille {
                v.push(format!("{FEUILLE} définit `{def}` {m} fois (attendu {dans_feuille})"));
            }
        }
        v
    }

    /// (a) La feuille est lue comme production et passe sans violation (l'absence d'exception est jugée
    /// sur la garde elle-même en (b)).
    #[test]
    fn a_la_feuille_de_couverture_na_aucune_exception_et_passe_la_garde() {
        assert_ne!(FEUILLE_QUI_RELIT, FEUILLE, "la feuille de couverture ne doit pas hériter de l'exception de lecture");
        let t = textes_reels();
        assert!(t.iter().any(|(f, _)| *f == racine().join(FEUILLE)), "précondition : la feuille est parmi les sources de production");
        let (ici, v) = juger_le_budget(&racine(), &t);
        assert!(ici >= 2, "l'auteur décide ({ici})");
        assert!(v.is_empty(), "{v:#?}");
    }

    /// (b) LA COUPE REFUSÉE, ET AUCUNE EXCEPTION. La ligne RÉELLE de `Plafond::pragma` (lue dans la façade,
    /// pas recopiée ici) posée dans la feuille y est accusée : déplacer `Plafond` ferait de la feuille un
    /// second auteur. Une lecture pure et une écriture composée y sont accusées aussi : une garde qui
    /// accorderait à cette feuille l'exception de lecture de `tri_des_connexions.rs` les laisserait passer.
    #[test]
    fn b_deplacer_plafond_dans_la_feuille_serait_accuse() {
        let facade = lire(FACADE);
        let grave: Vec<&str> = facade.lines().filter(|l| l.contains("Plafond::Applique(o) => format!(\" PRAGMA ")).collect();
        assert_eq!(grave.len(), 1, "précondition : la façade grave le plafond de tas en UNE ligne : {grave:#?}");
        let injections = [
            grave[0],
            "    let _: i64 = conn.query_row(\"PRAGMA temp_store\", [], |r| r.get(0)).unwrap();",
            "    let _ = conn.query_row(&format!(\"PRAGMA {}=2\", \"temp_store\"), [], |_| Ok(()));",
        ];
        for e in injections {
            let mut t = textes_reels();
            let feuille = racine().join(FEUILLE);
            let x = t.iter_mut().find(|(f, _)| *f == feuille).expect("la feuille est parmi les sources");
            x.1 = format!("{e}\n{}", x.1);
            let (_, v) = juger_le_budget(&racine(), &t);
            assert!(v.iter().any(|s| s.contains(FEUILLE)), "ligne non accusée dans la feuille : {e}\n{v:#?}");
        }
    }

    /// (c) La frontière, et l'état d'avant refusé (tout dans la façade, pas de feuille ; ou la feuille
    /// recollée dans la façade).
    #[test]
    fn c_la_frontiere_couverture_sort_plafond_reste() {
        let (facade, feuille) = (lire(FACADE), lire(FEUILLE));
        let v = juger_la_frontiere(&facade, Some(&feuille));
        assert!(v.is_empty(), "{v:#?}");
        // L'état d'avant jugé avec la VRAIE feuille : une feuille vide (`Some("")`) faisait refuser par la
        // seule feuille, quelle que soit la façade — le contrôle passait sans rien prouver (`P7.18-a`).
        let recollee = format!("{facade}\n{feuille}");
        assert!(
            !juger_la_frontiere(&recollee, Some(&feuille)).is_empty(),
            "l'état d'avant (la couverture dans la façade) doit être refusé"
        );
        let plafond_sorti = format!("{feuille}\nenum Plafond {{\n}}\n");
        assert!(!juger_la_frontiere(&facade, Some(&plafond_sorti)).is_empty(), "`Plafond` dans la feuille doit être refusé");
    }

    /// (d) LES PHRASES DES QUATRE VERDICTS, OCTET POUR OCTET — figées sur le texte d'avant le déplacement.
    #[test]
    fn d_les_quatre_phrases_de_couverture_sont_identiques_octet_pour_octet() {
        let gio = 1024 * 1024 * 1024;
        assert_eq!(
            couverture_pour(512 * 1024 * 1024, LimiteCgroup::Octets(gio)).phrase(),
            ", [couverture=protege] sous la limite mémoire du cgroup (1024 Mio)"
        );
        assert_eq!(
            couverture_pour(gio, LimiteCgroup::Octets(gio)).phrase(),
            ", AVERTISSEMENT [couverture=depasse] la limite mémoire du cgroup est 1024 Mio : LE PLAFOND NE \
             PROTÈGE PAS — l'OOM-killer arrivera avant le refus. Baisser PLUME_SQLITE_BUDGET_MB sous cette limite."
        );
        assert_eq!(
            couverture_pour(1, LimiteCgroup::Aucune).phrase(),
            ", AVERTISSEMENT [couverture=sans-limite] AUCUNE limite mémoire de cgroup n'est posée — l'interface \
             a été LUE, et elle ne borne rien. Ce n'est PAS une panne de mesure : le plafond ci-dessus borne \
             SQLite, mais RIEN n'arrête le processus avant la RAM de l'hôte, et le budget de 2 Gio du produit \
             n'est alors qu'une intention. Le poser : MemoryMax= (unité systemd), --memory (conteneur), \
             limits.memory (orchestrateur)."
        );
        assert_eq!(
            couverture_pour(1, LimiteCgroup::Illisible("montage absent".into())).phrase(),
            ", AVERTISSEMENT [couverture=illisible] limite mémoire du cgroup NON LISIBLE (montage absent) : \
             impossible de dire si ce budget protège de l'OOM-killer. Ce n'est PAS « il n'y a pas de limite », \
             c'est « il n'y a pas de mesure » — le plafond SQLite reste appliqué, sa couverture n'est pas vérifiée."
        );
        let verdicts: Vec<(&str, bool)> = [
            couverture_pour(1, LimiteCgroup::Octets(gio)),
            couverture_pour(gio, LimiteCgroup::Octets(gio)),
            couverture_pour(1, LimiteCgroup::Aucune),
            couverture_pour(1, LimiteCgroup::Illisible(String::new())),
        ]
        .iter()
        .map(|c| (c.verdict(), c.protege()))
        .collect();
        assert_eq!(verdicts, [("protege", true), ("depasse", false), ("sans-limite", false), ("illisible", false)]);
    }

    /// (d, suite) `rapport()` — la ligne `[plafond]` du démarrage — se TERMINE par la phrase que la
    /// feuille rend pour la limite lue sur cette machine (protégé ou dépassé selon le budget : les deux
    /// phrases possibles sont admises, aucune autre).
    #[test]
    fn d_le_rapport_porte_la_phrase_de_la_feuille() {
        let r = crate::sqlite_plafond::rapport();
        let candidates = [couverture_pour(1, limite_cgroup()).phrase(), couverture_pour(i64::MAX, limite_cgroup()).phrase()];
        assert!(candidates.iter().any(|c| r.ends_with(c.as_str())), "rapport : {r}\ncandidates : {candidates:#?}");
        assert_eq!(r.matches("[couverture=").count(), 1, "{r}");
    }
}

// Témoin des ré-exports de la façade réservés aux tests (`P7.18-a`), fichier propre.
include!("reexports_du_plafond_hors_production.rs");
