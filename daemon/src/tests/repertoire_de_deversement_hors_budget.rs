// P7.18-a — LE RÉPERTOIRE DE DÉVERSEMENT QUITTE `sqlite_plafond` SANS RIEN EMPORTER DU BUDGET
// ================================================================================================
// Le bloc « répertoire de déversement » (`deversement_init`, `residus_de_deversement`,
// `repertoire_temporaire_init`, `SONDE_ECRITURE`, `controle_positif`, `SOUS_REPERTOIRE_TEMP`) est sorti
// de `sqlite_plafond.rs` vers la feuille `repertoire_de_deversement.rs` par déplacement pur. Ce que ces
// témoins tiennent :
//   (a) la feuille n'a AUCUNE exception dans la garde du budget mémoire : elle n'est pas la feuille qui
//       relit, elle est lue comme production, et ses lignes réelles ne nomment aucun réglage ;
//   (b) une feuille qui ÉCRIT un réglage mémoire (cache, plafond de tas, mode des temporaires) est
//       accusée en la nommant — y compris une écriture composée par `format!` et une LECTURE pure de
//       `temp_store`, que l'exception PARTIELLE de `tri_des_connexions.rs` laisserait passer : c'est ce
//       qui prouve que la feuille ne reçoit ni l'exemption totale ni l'exception de lecture ;
//   (c) la frontière : la façade ne définit plus aucun des six éléments, la feuille les définit chacun
//       une fois — et l'état d'avant (tout dans la façade, pas de feuille) est refusé ;
//   (d) les chemins de la façade mènent au code déplacé, comportement compris : les deux sondes du
//       produit ne sont pas des résidus, un vrai résidu l'est, le contrôle positif ne laisse rien ;
//   (e) au défaut, `deversement_init` rend `Desactive` et ne crée pas `sqltmp` ni ne pose
//       `SQLITE_TMPDIR`, même pour une base dont le répertoire parent n'existe pas.
//
// CE QUE CES TÉMOINS NE PROUVENT PAS : la bannière sous un déversement RÉEL (processus lancé avec
// `PLUME_SQLITE_DEVERSEMENT=1`) — la suite tourne au défaut, et `deversement_init` y rend `Desactive`.

#[cfg(test)]
mod repertoire_de_deversement_hors_budget_tests {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    use crate::sqlite_plafond::plafond_tests::{juger_le_budget, FEUILLE_QUI_RELIT};
    use std::path::PathBuf;

    const FEUILLE: &str = "repertoire_de_deversement.rs";
    const FACADE: &str = "sqlite_plafond.rs";
    /// Les six définitions déplacées, telles qu'elles s'écrivent en tête de ligne.
    const DEFINITIONS: [&str; 6] = [
        "pub(crate) fn deversement_init(",
        "pub(crate) fn residus_de_deversement(",
        "fn repertoire_temporaire_init(",
        "const SONDE_ECRITURE:",
        "fn controle_positif(",
        "const SOUS_REPERTOIRE_TEMP:",
    ];

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

    /// Nombre de lignes de PRODUCTION (hors `#[cfg(test)]`, hors commentaires) qui DÉFINISSENT `def`
    /// (`pub(crate) ` admis devant, pour qu'une visibilité ne fasse pas sortir une définition du compte).
    fn definitions(chemin: &str, src: &str, def: &str) -> usize {
        texte_de_production(std::path::Path::new(chemin), src)
            .iter()
            .filter(|(_, l)| l.starts_with(def) || l.strip_prefix("pub(crate) ").is_some_and(|r| r.starts_with(def)))
            .count()
    }

    /// LE JUGEMENT DE LA FRONTIÈRE, pur pour être exercé sur l'état d'AVANT : chaque définition hors de
    /// la façade et une fois dans la feuille ; une feuille absente est un refus.
    fn juger_la_frontiere(facade: &str, feuille: Option<&str>) -> Vec<String> {
        let mut v = Vec::new();
        for def in DEFINITIONS {
            let n = definitions(FACADE, facade, def);
            if n != 0 {
                v.push(format!("{FACADE} définit encore `{def}` ({n})"));
            }
            match feuille {
                None => v.push(format!("{FEUILLE} absente : `{def}` n'y est pas")),
                Some(src) => {
                    let m = definitions(FEUILLE, src, def);
                    if m != 1 {
                        v.push(format!("{FEUILLE} définit `{def}` {m} fois (attendu 1)"));
                    }
                }
            }
        }
        v
    }

    /// (a) La feuille est lue comme production, n'est PAS la feuille qui relit, et passe sans violation.
    #[test]
    fn a_la_feuille_na_aucune_exception_et_passe_la_garde() {
        assert_ne!(FEUILLE_QUI_RELIT, FEUILLE, "la feuille du déversement ne doit pas hériter de l'exception de lecture");
        let t = textes_reels();
        assert!(t.iter().any(|(f, _)| *f == racine().join(FEUILLE)), "précondition : la feuille est parmi les sources de production");
        let (ici, v) = juger_le_budget(&racine(), &t);
        assert!(ici >= 2, "l'auteur décide ({ici})");
        assert!(v.is_empty(), "{v:#?}");
    }

    /// (b) Une feuille qui écrit un réglage mémoire est accusée, par chacune des voies.
    #[test]
    fn b_la_feuille_qui_ecrit_un_reglage_memoire_est_accusee() {
        let ecritures = [
            // Voies que l'exception de LECTURE de `tri_des_connexions.rs` ne voit pas : une écriture
            // composée (le `=` n'est pas collé au nom) et une lecture pure. Une feuille exemptée
            // partiellement les laisserait passer ; la nôtre, sans exception, les accuse.
            "    let _ = conn.query_row(&format!(\"PRAGMA {}=2\", \"temp_store\"), [], |_| Ok(()));",
            "    let _: i64 = conn.query_row(\"PRAGMA temp_store\", [], |r| r.get(0)).unwrap();",
            "    let _ = conn.execute_batch(\"PRAGMA cache_size=-1\");",
            "    let _ = conn.execute_batch(\"PRAGMA hard_heap_limit=0\");",
            "    let _ = conn.execute_batch(\"PRAGMA temp_store=FILE\");",
            "    let _ = conn.pragma_update(None, \"temp_store\", 1);",
            "    let _ = conn.execute_batch(\"PRAGMA soft_heap_limit=1\");",
        ];
        for e in ecritures {
            let mut t = textes_reels();
            let feuille = racine().join(FEUILLE);
            let x = t.iter_mut().find(|(f, _)| *f == feuille).expect("la feuille est parmi les sources");
            x.1 = format!("{e}\n{}", x.1);
            let (_, v) = juger_le_budget(&racine(), &t);
            assert!(v.iter().any(|s| s.contains(FEUILLE)), "écriture non accusée dans la feuille : {e}\n{v:#?}");
        }
    }

    /// (c) La frontière tient sur l'arbre, et l'état d'avant le déplacement est refusé.
    #[test]
    fn c_le_bloc_a_quitte_la_facade_et_letat_davant_est_refuse() {
        let facade = std::fs::read_to_string(racine().join(FACADE)).unwrap();
        let feuille = std::fs::read_to_string(racine().join(FEUILLE)).unwrap();
        let v = juger_la_frontiere(&facade, Some(&feuille));
        assert!(v.is_empty(), "{v:#?}");
        // Contrôle négatif : le bloc remis dans la façade, sans feuille — l'état d'avant.
        let avant = format!("{facade}\n{feuille}");
        let r = juger_la_frontiere(&avant, None);
        assert_eq!(r.len(), 2 * DEFINITIONS.len(), "l'état d'avant est refusé pour chaque définition : {r:#?}");
    }

    /// (d) Les chemins de la façade mènent au code déplacé, et il se comporte comme avant.
    #[test]
    fn d_les_chemins_de_la_facade_menent_au_code_deplace() {
        use crate::mesure_environnement::Mesure;
        use crate::tmp_possede::TmpPossede;
        let _init: fn(&str) -> crate::sqlite_plafond::Deversement = crate::sqlite_plafond::deversement_init;
        let tmp = TmpPossede::neuf("p718a-repertoire-de-deversement");
        std::fs::write(tmp.join(".sonde-ecriture"), b"1").expect("fixture : sonde d'écriture");
        std::fs::write(tmp.join(crate::quota_deversement::SONDE_QUOTA), b"\0").expect("fixture : sonde du quota");
        assert_eq!(crate::sqlite_plafond::residus_de_deversement(&tmp), Mesure::Lue(vec![]), "les deux sondes du produit ne sont pas des résidus");
        std::fs::write(tmp.join("etilqs_p718a"), b"clair").expect("fixture : résidu");
        assert_eq!(
            crate::sqlite_plafond::residus_de_deversement(&tmp),
            Mesure::Lue(vec!["etilqs_p718a".to_string()]),
            "un nom qui subsiste est un résidu"
        );
        std::fs::remove_file(tmp.join(".sonde-ecriture")).unwrap();
        assert!(crate::sqlite_plafond::controle_positif(&tmp).is_ok(), "un répertoire inscriptible passe le contrôle positif");
        assert!(!tmp.join(".sonde-ecriture").exists(), "le contrôle positif ne laisse pas sa sonde derrière lui");
        assert!(crate::sqlite_plafond::controle_positif(std::path::Path::new("/proc/repertoire-qui-nexiste-pas")).is_err());
    }

    /// (e) LA PORTE PAR DÉFAUT : la suite tourne sans `PLUME_SQLITE_DEVERSEMENT` (aucun test ne le pose).
    /// `deversement_init` doit rendre `Desactive` sans rien préparer. Base dans un parent INEXISTANT : si
    /// la porte s'ouvrait, `create_dir_all` créerait `sqltmp` sous ce parent (ou rendrait
    /// `Indisponible`) et `SQLITE_TMPDIR` serait posé vers lui — trois effets observables ici.
    #[test]
    fn e_au_defaut_deversement_init_ne_prepare_rien() {
        use crate::tmp_possede::TmpPossede;
        assert!(!crate::sqlite_plafond::deversement_actif(), "précondition : la suite tourne au défaut");
        let tmp = TmpPossede::neuf("p718a-porte-par-defaut");
        let parent = tmp.join("parent-absent");
        let base = parent.join("plume.db");
        let avant = std::env::var_os("SQLITE_TMPDIR");
        let d = crate::sqlite_plafond::deversement_init(base.to_str().unwrap());
        assert!(matches!(d, crate::sqlite_plafond::Deversement::Desactive), "au défaut, la porte reste fermée");
        assert!(!parent.exists(), "au défaut, aucun répertoire n'est créé ({})", parent.display());
        let apres = std::env::var_os("SQLITE_TMPDIR");
        assert!(
            apres.as_ref().map_or(true, |v| !std::path::Path::new(v).starts_with(&tmp)),
            "au défaut, SQLITE_TMPDIR n'est pas posé vers la base ({avant:?} -> {apres:?})"
        );
    }
}
