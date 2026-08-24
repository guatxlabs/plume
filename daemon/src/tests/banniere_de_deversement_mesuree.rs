// S38 — LA BANNIÈRE DE DÉVERSEMENT MESURE UNE CONNEXION ARMÉE, ET JOUE LES DEUX COUPLES RÉELS
// ================================================================================================
// LE DÉFAUT QUE CES TESTS FERMENT. La bannière de `S26` lisait ce que le moteur fait d'un tri sur une
// connexion NUE (`tri_dune_connexion_nue`), c'est-à-dire une connexion à laquelle personne ne pose
// `temp_store=FILE` — ce réglage n'est posé que par `armer`, sur les connexions qui servent. Sous
// `PLUME_SQLITE_DEVERSEMENT=1`, la bannière disait donc à CHAQUE démarrage « demandé mais tri en
// mémoire (local=0) », quel que soit ce que les connexions armées faisaient réellement. Une garde qui
// alerte toujours ne prouve rien ; pire, elle apprend à l'exploitant à ne plus la lire — et c'est sur
// cette ligne qu'il s'appuiera le jour d'un incident de confidentialité.
//
// POURQUOI LE TEST DE `S26` NE L'A PAS VU. Il appelait la bannière avec un verdict construit à la main
// (`Tri::SurDisque { local: 1 }`) : il prouvait que la bannière SAIT dire « tenu », pas que la mesure
// qu'elle reçoit en production peut le valoir. Le couple réel — déversement demandé, tri lu sur la
// connexion qui sert — ne se jouait nulle part, parce que la suite tourne au défaut et que `armer`
// fige le mode du processus ; d'où `armer_pour`, la même voie paramétrée sur le mode.
//
// CE QUE CHAQUE TEST PROUVE :
//   (a) déversement demandé ET tenu par une connexion ARMÉE sous ce mode → « demandé et TENU » ;
//   (b) déversement demandé, connexion VOLONTAIREMENT non armée → la contradiction est dite ;
//   (c) non demandé, connexion armée au défaut → la bannière est muette sur le déversement ;
//   (d) témoin inverse : sans mesure, la bannière dit « NON MESURÉ » et jamais « tenu » ;
//   (e) l'instrument : la lecture sur la connexion qui sert SUIT son réglage réel.

#[cfg(test)]
mod banniere_de_deversement_mesuree_tests {
    use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ABSENTE};
    use crate::sqlite_plafond::{armer_pour, banniere, constat_de_tri, tri_de_la_connexion_qui_sert, Deversement, Tri};
    use crate::tmp_possede::TmpDb;

    /// Le segment de la bannière qui parle du déversement : le rapport de plafond qui le précède nomme
    /// des chiffres et, selon l'hôte, un chemin système — il n'est pas le sujet.
    fn segment_de_deversement(b: &str) -> &str {
        b.split_once("— déversement").unwrap_or_else(|| panic!("la bannière ne porte plus de segment de déversement : {b}")).1
    }

    /// La mesure que la bannière publie, prise sur une vraie base fichier armée sous le mode donné —
    /// et VALIDÉE avant d'être crue : le réglage local relu doit être celui que ce mode pose (1 pour
    /// FILE, 2 pour MEMORY). Un instrument qui ne verrait pas son sujet rendrait les témoins (a) et (c)
    /// verts sans rien prouver.
    fn mesure_armee(deversement: bool, etiquette: &str) -> Mesure<Tri> {
        let coffre = TmpDb::neuf(etiquette);
        let c = rusqlite::Connection::open(coffre.as_str()).expect("base temporaire");
        let pose = armer_pour(&c, deversement);
        let attendu = if deversement { 1 } else { 2 };
        match &pose {
            Tri::SurDisque { local, .. } | Tri::EnMemoire { local, .. } => assert_eq!(
                *local, attendu,
                "INSTRUMENT : l'armement sous déversement={deversement} doit relire temp_store={attendu} — lu : {}",
                constat_de_tri(&pose)
            ),
            Tri::Illisible(e) => panic!("INSTRUMENT : le réglage doit se relire sur une connexion armée ({e})"),
        }
        let lue = tri_de_la_connexion_qui_sert(&c);
        assert_eq!(lue, Mesure::Lue(pose), "la mesure publiée est celle de la connexion armée, relue sur elle");
        lue
    }

    /// (a) DÉVERSEMENT DEMANDÉ ET TENU. La connexion est armée par la voie unique sous le mode
    /// déversement ; la bannière doit dire que la demande est TENUE, avec les chiffres lus, et ne plus
    /// contredire le mode.
    ///
    /// MUTATION : remettre `tri_dune_connexion_nue()` à la place de la mesure ⇒ ROUGE (« MAIS LA MESURE
    /// DIT AUTRE CHOSE » réapparaît, local=0).
    #[test]
    fn deversement_demande_et_tenu_par_une_connexion_armee() {
        let lue = mesure_armee(true, "s38-tenu");
        assert!(matches!(lue, Mesure::Lue(Tri::SurDisque { compile: 2, local: 1 })), "précondition : {lue:?}");
        let b = banniere(Deversement::Vers(std::path::PathBuf::from("/x/sqltmp"), Mesure::Lue(vec![]), crate::sqlite_plafond::QuotaDeversement::Arme(1024 * 1048576)), lue);
        let s = segment_de_deversement(&b);
        assert!(s.contains("ACTIVÉ vers /x/sqltmp"), "{b}");
        assert!(s.contains("demandé et TENU"), "la demande tenue doit être DITE comme telle : {b}");
        assert!(s.contains("temp_store local=1") && s.contains("TEMP_STORE=2"), "avec les chiffres LUS : {b}");
        assert!(!s.contains("MAIS LA MESURE DIT AUTRE CHOSE"), "plus de contradiction quand il n'y en a pas : {b}");
        assert!(!s.contains("NON MESURÉ"), "{b}");
    }

    /// (b) DÉVERSEMENT DEMANDÉ, CONNEXION VOLONTAIREMENT NON ARMÉE. C'est le cas qu'un batch refusé
    /// produit en production (base chiffrée ouverte sans clé, pragma refusé) : la connexion qui sert
    /// trie en mémoire alors que l'exploitant a demandé le déversement. La contradiction doit être
    /// dite — et elle l'est parce qu'elle est MESURÉE sur cette connexion, pas parce qu'une sonde nue
    /// la dirait de toute façon.
    ///
    /// MUTATION : rendre « tenu » inconditionnellement sous `Vers` ⇒ ROUGE.
    #[test]
    fn deversement_demande_mais_connexion_non_armee_contredit_le_mode() {
        let coffre = TmpDb::neuf("s38-non-armee");
        let c = rusqlite::Connection::open(coffre.as_str()).expect("base temporaire");
        // VOLONTAIREMENT aucun `armer` : la connexion reste nue, comme après un batch refusé.
        let lue = tri_de_la_connexion_qui_sert(&c);
        assert_eq!(lue, Mesure::Lue(Tri::EnMemoire { compile: 2, local: 0 }), "précondition : nue, donc local=0");
        let b = banniere(Deversement::Vers(std::path::PathBuf::from("/x/sqltmp"), Mesure::Lue(vec![]), crate::sqlite_plafond::QuotaDeversement::Arme(1024 * 1048576)), lue);
        let s = segment_de_deversement(&b);
        assert!(s.contains("MAIS LA MESURE DIT AUTRE CHOSE"), "{b}");
        assert!(s.contains("DEMANDÉ MAIS LE TRI RESTE EN MÉMOIRE") && s.contains("temp_store local=0"), "{b}");
        assert!(!s.contains("TENU"), "une demande non tenue ne doit JAMAIS être dite tenue : {b}");
    }

    /// (c) NON DEMANDÉ. La connexion est armée au défaut (`temp_store=MEMORY`, relu à 2) ; la bannière
    /// dit le défaut et sa mesure, et reste MUETTE sur toute idée de déversement tenu, contredit ou non
    /// mesuré — ni chemin, ni « TENU », ni contradiction.
    #[test]
    fn non_demande_la_banniere_est_muette_sur_le_deversement() {
        let lue = mesure_armee(false, "s38-defaut");
        assert!(matches!(lue, Mesure::Lue(Tri::EnMemoire { compile: 2, local: 2 })), "précondition : {lue:?}");
        let b = banniere(Deversement::Desactive, lue);
        let s = segment_de_deversement(&b);
        assert!(s.contains("DÉSACTIVÉ (défaut)") && s.contains("MESURÉ sur la connexion qui sert"), "{b}");
        assert!(s.contains("temp_store local=2"), "la mesure est celle de la connexion ARMÉE, pas d'une sonde nue : {b}");
        assert!(s.contains("Aucune valeur d'événement en clair"), "{b}");
        for interdit in ["TENU", "MAIS LA MESURE DIT AUTRE CHOSE", "NON MESURÉ", "/"] {
            assert!(!s.contains(interdit), "au défaut, « {interdit} » n'a rien à faire dans la bannière : {b}");
        }
    }

    /// (d) TÉMOIN INVERSE : UNE BANNIÈRE QUI DIRAIT « TENU » SANS MESURER ROUGIT. Quand aucune connexion
    /// armée n'est disponible, la mesure arrive `Illisible` avec sa cause, et la bannière doit le dire —
    /// dans les trois modes — sans jamais promettre ni le déversement ni la confidentialité.
    ///
    /// MUTATION : faire rendre « demandé et TENU » au cas `Illisible` ⇒ ROUGE sur la première assertion.
    #[test]
    fn sans_mesure_la_banniere_dit_non_mesure_et_jamais_tenu() {
        let non_mesure = || Mesure::<Tri>::Illisible {
            cause: CAUSE_SOURCE_ABSENTE,
            detail: "aucune connexion armée au moment de la bannière".into(),
        };
        let vers = banniere(Deversement::Vers(std::path::PathBuf::from("/x/sqltmp"), Mesure::Lue(vec![]), crate::sqlite_plafond::QuotaDeversement::Arme(1024 * 1048576)), non_mesure());
        let s = segment_de_deversement(&vers);
        assert!(!s.contains("TENU"), "sans mesure, rien n'est tenu : {vers}");
        assert!(s.contains("NON MESURÉ") && s.contains(CAUSE_SOURCE_ABSENTE), "la cause doit être dite : {vers}");
        assert!(!s.contains("MESURÉ sur la connexion qui sert"), "{vers}");

        let defaut = banniere(Deversement::Desactive, non_mesure());
        let s = segment_de_deversement(&defaut);
        assert!(s.contains("NON MESURÉ"), "{defaut}");
        assert!(!s.contains("Aucune valeur d'événement en clair"), "sans mesure, la confidentialité n'est pas promise : {defaut}");

        let indisponible = banniere(Deversement::Indisponible("montage RO".into()), non_mesure());
        let s = segment_de_deversement(&indisponible);
        assert!(s.contains("INDISPONIBLE") && s.contains("NON MESURÉ") && !s.contains("TENU"), "{indisponible}");
    }

    /// (e) L'INSTRUMENT SUIT LE RÉGLAGE RÉEL DE LA CONNEXION QUI SERT — dans les deux sens sur la MÊME
    /// connexion. Sans ce témoin, une lecture qui rendrait toujours la même valeur passerait (a) ou (b)
    /// selon la valeur choisie, et ne prouverait rien.
    #[test]
    fn la_mesure_sur_la_connexion_qui_sert_suit_son_reglage() {
        let coffre = TmpDb::neuf("s38-instrument");
        let c = rusqlite::Connection::open(coffre.as_str()).expect("base temporaire");
        assert_eq!(tri_de_la_connexion_qui_sert(&c), Mesure::Lue(Tri::EnMemoire { compile: 2, local: 0 }));
        assert_eq!(armer_pour(&c, true), Tri::SurDisque { compile: 2, local: 1 });
        assert_eq!(tri_de_la_connexion_qui_sert(&c), Mesure::Lue(Tri::SurDisque { compile: 2, local: 1 }));
        assert_eq!(armer_pour(&c, false), Tri::EnMemoire { compile: 2, local: 2 });
        assert_eq!(tri_de_la_connexion_qui_sert(&c), Mesure::Lue(Tri::EnMemoire { compile: 2, local: 2 }));
    }
}
