// LE PLANCHER DES TABLES DÉCLARÉES (`P11.23-g`) — un témoin qui boucle sur une table déclarée
// n'est vert que s'il a VRAIMENT bouclé.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE DÉFAUT, MESURÉ SUR CET ARBRE LE 2026-09-02
// ─────────────────────────────────────────────────────────────────────────────────────────────
// DIX tests de `daemon/src/` n'ont AUCUNE assertion sur un chemin garanti : toutes leurs
// assertions vivent dans une boucle sur une table déclarée AILLEURS qu'eux — douze tables au
// total, dont six vivent dans une caisse VOISINE (`guatx_core`). Vider l'une de ces tables ne
// fait pas rougir : la boucle itère zéro fois, le test rend la main, `libtest` compte un test
// PASSÉ de plus, et la propriété que le test annonce n'a été exercée sur rien.
//
// C'EST LA FORME DE `P11.23-e` SANS AUCUNE SORTIE ANTICIPÉE ET SANS AUCUNE BRANCHE. Il n'y a ni
// `return` à voir, ni jumelle muette : il n'y a qu'une boucle vide. La garde
// `check_a_test_that_declines_to_conclude_says_so.py` le dit dans son propre bandeau — « un
// corpus qui perd sa matière […] ce qui tient cette forme est un PLANCHER dans l'instrument qui
// produit le corpus, pas cette garde ».
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// POURQUOI CE N'EST PAS LE CANAL DE REFUS QUI CONVIENT ICI
// ─────────────────────────────────────────────────────────────────────────────────────────────
// Le canal (`P11.23-b`) laisse le test VERT et consigne son aveu : c'est le bon geste pour un
// ENVIRONNEMENT aveugle, où aucun geste ne pourrait refermer un rouge. Une table déclarée vidée
// n'est PAS un environnement : c'est une PANNE D'INSTRUMENT, et le geste qui la referme est une
// ligne de source. Y router l'aveu rendrait ces dix tests VERTS ET MUETS là où ils doivent
// ROUGIR. C'est la correction que le lot de `P11.23-e` s'est faite à lui-même sur deux de ses
// neuf sites, et c'est exactement cette forme-là qui est reprise ici.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE GESTE EST REPRIS, PAS RÉINVENTÉ
// ─────────────────────────────────────────────────────────────────────────────────────────────
// `allowlist_du_responder.rs::corpus_partage()` porte, depuis `P11.23-e`, un `assert!` de
// non-vacuité DANS LE FOURNISSEUR du corpus, pour que tout consommateur futur en hérite sans y
// penser. Une table `const` ne peut pas porter d'assertion : le fournisseur est donc CE
// module-ci, et le consommateur prend sa matière par lui.
//
// LE NOM DE LA TABLE EST DÉRIVÉ, JAMAIS ÉCRIT À LA MAIN. `table_declaree!(COLLECTORS)` rend le
// nom par `stringify!` : un nom recopié à côté d'une autre table enverrait chercher au mauvais
// endroit, et c'est précisément la faute que la garde du canal refuse déjà sur son 2e argument.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QUE CE PLANCHER NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
// ─────────────────────────────────────────────────────────────────────────────────────────────
//   · IL NE TIENT QUE LA VACUITÉ, PAS L'AMPLEUR. Une table de 23 entrées tombée à 1 le franchit.
//     Ce qui sépare « le témoin a bouclé » de « le témoin n'a pas bouclé » est le zéro, et lui
//     seul ; tout autre plancher serait un nombre choisi, pas une frontière mesurée.
//   · IL NE S'IMPOSE PAS TOUT SEUL. Un consommateur écrit demain qui itère la table NUE échappe
//     au plancher. Ce qui l'y oblige est la garde
//     `check_a_test_that_loops_over_a_declared_table_has_a_floor.py`, qui DÉRIVE la population de
//     l'arbre syntaxique et refuse un site nu.
//   · IL NE VOIT PAS UNE TABLE VIDÉE AU-DELÀ DE SON PROPRE ARGUMENT. Un test qui filtre la table
//     avant de boucler (`TABLE.iter().filter(…)`) peut itérer zéro fois sur une table PLEINE : le
//     plancher est franchi et le test reste muet. Aucun site de ce genre n'existe aujourd'hui
//     dans la population dérivée, et rien ici ne l'empêcherait demain.
pub(crate) mod tables_declarees {
    /// LE PLANCHER. Rend la table INCHANGÉE si elle porte au moins une entrée, et ACCUSE
    /// L'INSTRUMENT sinon — pas la propriété du témoin, qui n'a pas été mise en défaut : elle n'a
    /// pas été mise à l'épreuve du tout.
    ///
    /// Passer par `&[T]` plutôt que par un `IntoIterator` générique est délibéré : un `const`
    /// tranche déjà de sa forme (`&[…]` ou `[…; N]`), et `&$table[..]` les ramène tous les deux
    /// ici sans exiger `Copy` d'un élément qui ne l'est pas (`Sonde`, dans `COLLECTORS`).
    pub(crate) fn non_vide<'a, T>(nom: &str, table: &'a [T]) -> &'a [T] {
        assert!(
            !table.is_empty(),
            "INSTRUMENT : la table déclarée `{nom}` ne porte AUCUNE entrée. Le témoin qui boucle \
             dessus n'exercerait PAS UNE SEULE assertion et se présenterait VERT sans rien avoir \
             prouvé. Ce n'est pas la propriété annoncée par le témoin qui est fausse — c'est sa \
             MATIÈRE qui a disparu, et le geste qui referme ce rouge est une ligne de source."
        );
        table
    }
}

/// LA FORME QUE LES CONSOMMATEURS ÉCRIVENT. Le nom est DÉRIVÉ de l'expression, et `&$table[..]`
/// accepte indifféremment un `&[T]` (`SIGMA_LOGSOURCE_CATEGORY`, les `SOQL_*` du cœur) et un
/// `[T; N]` (`COLLECTORS`, `TI_ALERT_RULES`) — dans les deux cas la boucle reçoit `&T`, ce que
/// `for … in TABLE_SLICE` et `for … in TABLE.iter()` donnaient déjà.
macro_rules! table_declaree {
    ($table:expr) => {
        crate::tests::tables_declarees::non_vide(stringify!($table), &$table[..])
    };
}

/// LE TÉMOIN DE L'INSTRUMENT — sur des tables FABRIQUÉES ICI, jamais lues du produit. Un plancher
/// qui ne serait validé que par les tables réelles serait vert par construction le jour où elles
/// sont pleines, c'est-à-dire tous les jours sauf celui qui compte.
///
/// Les deux bras diffèrent PAR LA SEULE VACUITÉ de la table : même type, même appel, même macro.
/// Le second exige que le message NOMME la table — `stringify!` est donc prouvé, pas supposé.
#[test]
fn le_plancher_des_tables_declarees_accuse_l_instrument_et_nomme_la_table() {
    const TABLE_PLEINE: &[&str] = &["une", "deux"];
    const TABLE_VIDEE: &[&str] = &[];

    // (a) NÉGATIF — une table qui porte de la matière TRAVERSE le plancher sans rien changer.
    assert_eq!(
        table_declaree!(TABLE_PLEINE),
        TABLE_PLEINE,
        "le plancher rend la table INCHANGÉE : il fournit, il ne filtre pas"
    );

    // (b) POSITIF — la MÊME forme, vidée : le plancher rougit.
    let echec = std::panic::catch_unwind(|| {
        let _ = table_declaree!(TABLE_VIDEE);
    })
    .expect_err("une table déclarée VIDE doit faire ROUGIR le témoin qui boucle dessus");
    let message = echec
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| echec.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("le plancher panique avec un message lisible");

    assert!(
        message.contains("INSTRUMENT"),
        "le message doit accuser l'INSTRUMENT, pas la propriété du témoin : {message}"
    );
    assert!(
        message.contains("TABLE_VIDEE"),
        "le message doit NOMMER la table vidée (nom dérivé par `stringify!`, jamais recopié) : {message}"
    );
    assert!(
        !message.contains("TABLE_PLEINE"),
        "le nom est celui de la table PASSÉE, pas d'une voisine : {message}"
    );
}
