// P10.9-a (suite) — L'OBSERVATOIRE D'USAGE DES INDEX : CE QU'IL MESURE, CE QU'IL COÛTE, ET LES DEUX
// TÉMOINS SANS LESQUELS SON TABLEAU NE PROUVERAIT RIEN.
//
// POURQUOI CE FICHIER EXISTE. `index_usage_event.rs` rejoue le corpus FERMÉ de ce que le produit
// LIVRE, et il déclare lui-même ses deux limites : le corpus ne contient aucune requête d'analyste, et
// le plan y est lu sous des statistiques SYNTHÉTISÉES qui ne comportent AUCUNE statistique d'index
// détaillée. La seconde limite est le trou que `P10.9-a` nomme : sans statistiques détaillées, le
// rendement d'un prédicat de BORNE n'est pas estimé, et le verdict d'un index dont la colonne de tête
// n'est interrogée que par bornes ne peut pas être qualifié de représentatif.
//
// `crate::index_usage` comble ce trou par l'autre bout : il lit le plan À L'EXÉCUTION, sur la base
// déployée, où le planificateur dispose des statistiques RÉELLES — et il PUBLIE le régime sous lequel
// il a lu, de sorte qu'un verdict obtenu sans statistiques détaillées ne puisse pas se lire comme un
// verdict obtenu avec.
//
// CE QUE CE FICHIER PROUVE, ET DANS QUEL ORDRE :
//   ① LA MUTATION POSITIVE — un énoncé forcé sur un index précis fait bouger le compteur de CET index
//     et d'AUCUN autre. Dérivée : chaque index que le CATALOGUE déclare est éprouvé, aucun n'est nommé
//     ici, et l'index ajouté demain est couvert le jour où il est ajouté.
//   ② LA MUTATION NÉGATIVE — un énoncé qui n'emploie aucun index ne fait bouger AUCUN compteur.
//     Sans ce second témoin, un compteur qui monte toujours ne prouverait rien : c'est exactement la
//     panne d'instrument qu'un tableau d'usage ne peut pas se permettre.
//   ③ L'EXTINCTION NE CHANGE RIEN — éteint (le défaut), aucun plan n'est lu et l'exposition est la
//     chaîne VIDE, donc `/metrics` est inchangé octet pour octet.
//   ④ LE COÛT EST MESURÉ, pas promis — et il est IMPRIMÉ, jamais figé dans une constante de source.
//   ⑤ LA CARDINALITÉ EST BORNÉE DEUX FOIS — l'étiquette est un NOM D'INDEX (jamais une requête), et le
//     registre est plafonné. Le plafond est prouvé en le FAISANT MORDRE.
//   ⑥ LA LIMITE EST ÉCRITE LÀ OÙ LE VERDICT SE LIT — dans le `# HELP` de la série. Une garde le
//     vérifie : un jour où quelqu'un raccourcirait ce texte, le test rougirait.

/// UN OBSERVATOIRE NEUF, ALLUMÉ AU PAS DEMANDÉ. Jamais l'instance du processus : un plafond ne se
/// prouve qu'en le faisant mordre, et le faire mordre sur l'instance globale contaminerait la suite.
fn observatoire_neuf(plafond: usize, echantillon: u32) -> crate::index_usage::Observatoire {
    crate::index_usage::Observatoire::neuf(plafond, echantillon)
}

/// L'énoncé qui FORCE l'emploi d'un index donné (en rappelant son prédicat quand l'index est partiel :
/// SQLite refuse `INDEXED BY` sur un index partiel dont le `WHERE` n'implique pas le prédicat).
fn enonce_qui_force(ix: &IndexEvent) -> String {
    let mut clauses: Vec<String> = Vec::new();
    if let Some(p) = &ix.predicat {
        clauses.push(format!("({p})"));
    }
    if let Some(c0) = ix.cles.first() {
        clauses.push(format!("{c0} > 0"));
    }
    let ou = if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) };
    format!("SELECT count(*) FROM event INDEXED BY {}{ou}", ix.nom)
}

/// L'énoncé qui n'emploie AUCUN index : le témoin négatif.
const ENONCE_SANS_INDEX: &str = "SELECT count(*) FROM event NOT INDEXED WHERE message LIKE '%zz%'";

/// ① LA MUTATION POSITIVE, DÉRIVÉE DU CATALOGUE — et son exigence d'EXCLUSIVITÉ.
///
/// Pour chaque index que la base d'épreuve déclare sur `event`, un énoncé qui le force doit faire
/// monter SON compteur de exactement 1, et laisser TOUS les autres inchangés. Un instrument qui
/// incrémente le bon index ET ses voisins serait aussi inutilisable qu'un instrument aveugle : il
/// désignerait comme « employés » des index que rien n'emploie, c'est-à-dire exactement les index
/// qu'on cherche à distinguer.
#[test]
fn un_enonce_force_sur_un_index_ne_fait_bouger_que_le_compteur_de_cet_index() {
    let (_chemin, db) = base_au_schema_reel("idxobs-mutation-positive");
    let conn = db.lock();
    let index = index_de_event(&conn);
    assert!(
        index.len() >= 2,
        "base d'épreuve à moins de deux index : l'exigence d'EXCLUSIVITÉ ne pourrait rien distinguer"
    );

    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);
    let mut attendu: std::collections::BTreeMap<String, u64> =
        index.iter().map(|i| (i.nom.clone(), 0u64)).collect();

    for ix in &index {
        obs.observer(&conn, &enonce_qui_force(ix), crate::index_usage::Consommateur::Analyste);
        *attendu.get_mut(&ix.nom).expect("index connu") += 1;
        let constate: std::collections::BTreeMap<String, u64> =
            index.iter().map(|i| (i.nom.clone(), obs.total(&i.nom))).collect();
        assert_eq!(
            constate, attendu,
            "MUTATION EN ÉCHEC après avoir forcé {} : soit son compteur n'a pas bougé (l'observatoire \
             est aveugle sur cette forme, et tout « personne ne s'en sert » serait faux), soit un AUTRE \
             a bougé (l'observatoire impute à côté, et un index inemployé passerait pour employé).",
            ix.nom
        );
    }

    // La classe de consommateur porte aussi : tout est tombé dans `analyste`, rien ailleurs.
    for ix in &index {
        assert_eq!(
            obs.compte(&ix.nom, crate::index_usage::Consommateur::Analyste),
            1,
            "{} : l'observation n'a pas été imputée à la classe demandée",
            ix.nom
        );
        for autre in [
            crate::index_usage::Consommateur::Interactif,
            crate::index_usage::Consommateur::Automatique,
        ] {
            assert_eq!(
                obs.compte(&ix.nom, autre),
                0,
                "{} : une observation a fuité dans la classe {:?} — l'étiquette « par quoi » ne vaudrait rien",
                ix.nom,
                autre
            );
        }
    }
    assert_eq!(obs.plans_lus(), index.len() as u64, "un plan par énoncé échantillonné, ni plus ni moins");
    assert_eq!(obs.plans_sans_index(), 0, "tous ces énoncés nomment un index : aucun ne doit compter comme sans index");
}

/// ② LA MUTATION NÉGATIVE — LE TÉMOIN SANS LEQUEL LE PREMIER NE PROUVE RIEN.
///
/// Un compteur qui monte à chaque énoncé, quel qu'il soit, est indiscernable d'un compteur juste tant
/// qu'on ne lui présente pas un énoncé qui ne doit RIEN faire bouger. Ici : un balayage explicitement
/// non indexé. Il doit être COMPTÉ comme plan lu (la mesure a bien eu lieu) et pointé comme plan SANS
/// index — mais aucun compteur d'index ne doit bouger.
#[test]
fn un_enonce_sans_index_ne_deplace_aucun_compteur_dindex() {
    let (_chemin, db) = base_au_schema_reel("idxobs-mutation-negative");
    let conn = db.lock();
    let index = index_de_event(&conn);
    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);

    // D'abord un énoncé qui NOMME un index : sans lui, « rien n'a bougé » serait aussi la signature
    // d'un observatoire en panne. Le témoin négatif ne vaut qu'à côté d'un positif.
    let premier = index.first().expect("au moins un index sur `event`");
    obs.observer(&conn, &enonce_qui_force(premier), crate::index_usage::Consommateur::Automatique);
    let avant: Vec<u64> = index.iter().map(|i| obs.total(&i.nom)).collect();
    assert!(avant.iter().sum::<u64>() > 0, "l'observatoire n'a rien compté du tout : la mesure est en panne");

    obs.observer(&conn, ENONCE_SANS_INDEX, crate::index_usage::Consommateur::Automatique);
    let apres: Vec<u64> = index.iter().map(|i| obs.total(&i.nom)).collect();
    assert_eq!(
        avant, apres,
        "TÉMOIN NÉGATIF EN ÉCHEC : un balayage explicitement NON indexé a fait monter un compteur. \
         Un observatoire dont les compteurs montent toujours ne distingue pas un index employé d'un \
         index qui ne l'est pas — c'est-à-dire qu'il ne mesure rien."
    );
    assert_eq!(obs.plans_lus(), 2, "les deux énoncés ont bien été lus (le second n'a pas été sauté)");
    assert_eq!(
        obs.plans_sans_index(),
        1,
        "un plan sans index doit être COMPTÉ comme tel : c'est ce qui distingue « mesuré, aucun index » \
         de « pas mesuré »"
    );
    let (_, _, tronque) = obs.etat_registre();
    assert!(!tronque, "le plafond ne doit pas avoir mordu sur deux énoncés");
}

/// ③ ÉTEINT, IL NE FAIT RIEN — ET IL NE DIT RIEN.
///
/// Le défaut est `0`. La preuve demandée n'est pas « il consomme peu » mais « il ne change rien » :
/// aucun plan lu, aucun compteur, et une exposition qui est la chaîne VIDE — donc `/metrics` est
/// inchangé octet pour octet, ce qu'un bloc de zéros ne serait pas.
#[test]
fn lobservatoire_eteint_ne_lit_aucun_plan_et_nexpose_rien() {
    assert_eq!(
        crate::index_usage::ECHANTILLON_DEFAUT,
        0,
        "l'observatoire doit être ÉTEINT par défaut : un instrument qui s'allume tout seul est une \
         dépense que personne n'a décidée"
    );
    let (_chemin, db) = base_au_schema_reel("idxobs-eteint");
    let conn = db.lock();
    let index = index_de_event(&conn);
    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, crate::index_usage::ECHANTILLON_DEFAUT);

    for _ in 0..50 {
        for ix in &index {
            obs.observer(&conn, &enonce_qui_force(ix), crate::index_usage::Consommateur::Analyste);
        }
        obs.observer(&conn, ENONCE_SANS_INDEX, crate::index_usage::Consommateur::Automatique);
    }
    assert_eq!(obs.plans_lus(), 0, "ÉTEINT : aucun plan ne doit être lu");
    assert_eq!(obs.plans_refuses(), 0, "ÉTEINT : aucun plan ne doit même être tenté");
    assert_eq!(obs.plans_sans_index(), 0, "ÉTEINT : aucun compteur ne doit bouger");
    assert_eq!(obs.etat_registre().0, 0, "ÉTEINT : aucune étiquette ne doit être enregistrée");
    assert!(obs.regime().is_none(), "ÉTEINT : aucun régime de statistiques ne doit être constaté");
    assert_eq!(
        obs.exposition_prom(),
        "",
        "ÉTEINT : l'exposition doit être VIDE. Un bloc de zéros se lirait « mesuré, rien trouvé », ce \
         qui est une affirmation — et fausse."
    );
    // Et l'instance du PROCESSUS, que personne n'a configurée dans cette suite, est éteinte elle aussi.
    assert_eq!(
        crate::index_usage::observatoire().exposition_prom(),
        "",
        "l'observatoire du processus n'a pas été configuré : il doit être muet"
    );
}

/// ④ CE QUE L'OBSERVATION COÛTE — MESURÉ ET IMPRIMÉ, jamais promis.
///
/// Le coût d'une observation est celui d'une PRÉPARATION supplémentaire (`EXPLAIN QUERY PLAN`), pas
/// d'une exécution : elle ne touche aucune page de données. Ce test le chiffre sur la MÊME connexion
/// et le MÊME énoncé, éteint puis allumé au pas de 1 (le pire cas : à `N`, la dépense est divisée par
/// `N`). Le chiffre n'est PAS figé dans une assertion — une durée mesurée sur une machine quelconque
/// ne se transforme pas en seuil sans devenir un test instable. Ce qui est ASSERTÉ, c'est ce qui
/// rendrait le chiffre faux : que le bras éteint n'ait lu aucun plan et le bras allumé exactement un
/// par énoncé.
///
/// Rejouable : `cargo test --offline --locked le_cout_de_lobservation -- --nocapture --test-threads=1`
#[test]
fn le_cout_de_lobservation_est_mesure_et_publie() {
    let (_chemin, db) = base_au_schema_reel("idxobs-cout");
    let conn = db.lock();
    let index = index_de_event(&conn);
    let sql = enonce_qui_force(index.first().expect("au moins un index"));
    const TOURS: u32 = 300;

    let bras = |echantillon: u32| -> (std::time::Duration, u64) {
        let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, echantillon);
        // Une passe à blanc : le premier appel paie la création de l'étiquette et le premier cache de
        // pages. Mesurer avec elle attribuerait à l'observation un coût qui n'est pas le sien.
        obs.observer(&conn, &sql, crate::index_usage::Consommateur::Analyste);
        let t0 = std::time::Instant::now();
        for _ in 0..TOURS {
            obs.observer(&conn, &sql, crate::index_usage::Consommateur::Analyste);
        }
        (t0.elapsed(), obs.plans_lus())
    };

    let (eteint, lus_eteint) = bras(0);
    let (allume, lus_allume) = bras(1);
    let par_enonce = |d: std::time::Duration| d.as_secs_f64() * 1_000_000.0 / f64::from(TOURS);

    println!("\n=== CE QUE COÛTE UNE OBSERVATION D'USAGE D'INDEX ({TOURS} énoncés, même connexion) ===");
    println!("  ÉTEINT (défaut)      : {:>9.3} µs/énoncé — un chargement atomique, rien d'autre", par_enonce(eteint));
    println!("  ALLUMÉ au pas de 1   : {:>9.3} µs/énoncé — un EXPLAIN QUERY PLAN par énoncé", par_enonce(allume));
    println!(
        "  SURCOÛT              : {:>9.3} µs/énoncé au pas de 1, donc ce chiffre DIVISÉ PAR N au pas de N",
        par_enonce(allume) - par_enonce(eteint)
    );
    println!("  MÉMOIRE              : un compteur par (index nommé × classe), registre plafonné à {} étiquettes + 1", crate::index_usage::INDEX_CAP);
    println!("  CE QUE ÇA NE DIT PAS : une durée relevée ici ne vaut que pour cette machine et cet énoncé.");
    println!("=== fin ===\n");

    assert_eq!(lus_eteint, 0, "le bras ÉTEINT a lu {lus_eteint} plan(s) : le chiffre de référence serait faux");
    assert_eq!(
        lus_allume,
        u64::from(TOURS) + 1,
        "le bras ALLUMÉ n'a pas lu un plan par énoncé : le surcoût publié ne porterait pas sur ce qu'on croit"
    );
}

/// ⑤ L'ÉCHANTILLONNAGE — « UN SUR N » DOIT VOULOIR DIRE UN SUR N.
///
/// Un pas d'échantillonnage qui ne tiendrait pas ferait mentir le dénominateur : les compteurs par
/// index se lisent RELATIVEMENT à `plume_index_usage_plans_lus_total`.
#[test]
fn lechantillonnage_lit_exactement_un_plan_sur_n() {
    let (_chemin, db) = base_au_schema_reel("idxobs-echantillon");
    let conn = db.lock();
    let index = index_de_event(&conn);
    let sql = enonce_qui_force(index.first().expect("au moins un index"));
    for pas in [1u32, 2, 5, 10] {
        let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, pas);
        let enonces = 100u32;
        for _ in 0..enonces {
            obs.observer(&conn, &sql, crate::index_usage::Consommateur::Interactif);
        }
        assert_eq!(
            obs.plans_lus(),
            u64::from(enonces / pas),
            "pas {pas} : {} plans lus sur {enonces} énoncés — le dénominateur publié serait faux",
            obs.plans_lus()
        );
    }
}

/// ⑥ LE PLAFOND DU REGISTRE, PROUVÉ EN LE FAISANT MORDRE.
///
/// L'étiquette est un NOM D'INDEX : bornée par le schéma. Le plafond la rend bornée INDÉPENDAMMENT du
/// schéma — y compris des index d'expression que la configuration fait naître, dont le nombre n'est
/// pas fixé par ce dépôt. Ce qui est exigé au-delà du plafond : que la mesure SURVIVE (seau de
/// débordement) et que la troncature se DISE.
#[test]
fn le_plafond_du_registre_borne_la_cardinalite_de_lexposition() {
    let (_chemin, db) = base_au_schema_reel("idxobs-plafond");
    let conn = db.lock();
    let index = index_de_event(&conn);
    assert!(index.len() >= 3, "il faut plus d'index que le plafond d'épreuve pour le faire mordre");

    let plafond = 2usize;
    let obs = observatoire_neuf(plafond, 1);
    for ix in &index {
        obs.observer(&conn, &enonce_qui_force(ix), crate::index_usage::Consommateur::Automatique);
    }
    let (n, p, tronque) = obs.etat_registre();
    assert_eq!(p, plafond);
    assert!(tronque, "le plafond n'a pas mordu alors que {} index ont été observés", index.len());
    assert!(
        n <= plafond + 1,
        "cardinalité {n} au-delà de plafond+1 : la borne ne tient pas, et `/metrics` grandirait avec le schéma"
    );
    assert!(
        obs.total(crate::index_usage::ETIQUETTE_DEBORDEMENT) > 0,
        "le plafond a mordu et RIEN n'est tombé dans le seau de débordement : des observations ont été \
         perdues en silence, ce qui est pire qu'une attribution manquante"
    );
    // La somme est CONSERVÉE : plafonner l'attribution ne doit pas plafonner la mesure.
    let total_expose: u64 = {
        let e = obs.exposition_prom();
        e.lines()
            .filter(|l| l.starts_with("plume_index_usage_total{"))
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum()
    };
    assert_eq!(
        total_expose,
        obs.plans_lus(),
        "chaque plan lu nomme ici exactement un index : la somme exposée doit égaler le nombre de \
         plans lus, plafond ou pas"
    );
    // Et la cardinalité de l'exposition est bornée par (étiquettes × classes), jamais par le nombre
    // d'énoncés : c'est la propriété qui interdit une étiquette par requête.
    let lignes = obs.exposition_prom().lines().filter(|l| l.starts_with("plume_index_usage_total{")).count();
    assert_eq!(
        lignes,
        n * crate::index_usage::Consommateur::TOUS.len(),
        "l'exposition doit rendre exactement une série par (étiquette × classe)"
    );
}

/// ⑦ LA CLASSE DE CONSOMMATEUR EST DÉDUITE, ET SA DÉDUCTION EST PURE.
///
/// C'est elle qui répond à « employé PAR QUOI », donc elle qui distingue un index tenu par le chemin
/// interactif d'un index tenu par une tâche de fond. La règle est testée sans démarrer un serveur —
/// et ses trois cases sont éprouvées, y compris celle qui n'existe qu'en l'absence des deux autres.
#[test]
fn la_classe_de_consommateur_est_deduite_et_son_enumeration_est_close() {
    use crate::index_usage::Consommateur;
    let interactif = 12_345u64;
    assert_eq!(Consommateur::deduit(interactif, Some("q-1"), interactif), Consommateur::Analyste);
    assert_eq!(Consommateur::deduit(999, Some("q-1"), interactif), Consommateur::Analyste);
    assert_eq!(Consommateur::deduit(interactif, None, interactif), Consommateur::Interactif);
    assert_eq!(Consommateur::deduit(999, None, interactif), Consommateur::Automatique);

    // L'énumération est CLOSE et ses clés sont DISTINCTES : deux classes qui partageraient une clé
    // fusionneraient deux séries sans que rien ne le dise.
    let cles: std::collections::BTreeSet<&str> = Consommateur::TOUS.iter().map(|c| c.cle()).collect();
    assert_eq!(
        cles.len(),
        Consommateur::TOUS.len(),
        "deux classes de consommateur portent la même clé : leurs observations se confondraient"
    );
}

/// ⑧ LE RÉGIME DE STATISTIQUES — LE TROU NOMMÉ, RENDU LISIBLE DANS LE VERDICT.
///
/// C'est ce que `P10.9-a` demandait : sans statistiques d'index DÉTAILLÉES, un choix de plan n'est pas
/// représentatif pour un index dont la colonne de tête n'est interrogée que par bornes. L'observatoire
/// ne peut pas fabriquer ces statistiques — mais il peut refuser de laisser croire qu'il en avait.
/// Trois crans, éprouvés dans l'ordre où une base les traverse : rien, puis agrégées, puis détaillées.
///
/// LA CAPACITÉ DE SQLITE EST VÉRIFIÉE, PAS SUPPOSÉE. Le rejeu du corpus AFFIRMAIT que la SQLite
/// embarquée est compilée avec les statistiques détaillées, sans jamais le demander à SQLite. Une
/// affirmation de ce genre est vraie jusqu'au jour où une dépendance change d'options de compilation,
/// et ce jour-là c'est le verdict qui se dégrade en silence.
#[test]
fn le_regime_de_statistiques_est_constate_a_trois_crans_et_nomme() {
    use crate::index_usage::{regime_statistiques, RegimeStatistiques};
    let (_chemin, db) = base_au_schema_reel("idxobs-regime");
    let conn = db.lock();

    assert!(
        crate::index_usage::statistiques_detaillees_compilees(&conn),
        "la SQLite embarquée n'expose PAS les statistiques d'index détaillées : le régime `Detaillees` \
         serait inatteignable et tout verdict d'index dont la colonne de tête est interrogée par bornes \
         resterait non représentatif. C'est un constat, pas un détail de build."
    );

    // CRAN 0 — base neuve : aucune statistique. C'est ce que voit une instance fraîche, avant que
    // l'analyse de fond n'ait tourné.
    assert_eq!(
        regime_statistiques(&conn, "event"),
        RegimeStatistiques::Aucune,
        "base neuve : aucune statistique ne doit être constatée"
    );
    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);
    let index = index_de_event(&conn);
    obs.observer(&conn, &enonce_qui_force(index.first().expect("au moins un index")), crate::index_usage::Consommateur::Analyste);
    assert_eq!(obs.regime(), Some(RegimeStatistiques::Aucune), "le régime constaté doit être publié tel quel");

    // CRAN 1 — des statistiques AGRÉGÉES posées à la main, sans aucun échantillon : exactement ce que
    // le rejeu du corpus fermé sait produire, et exactement ce qui ne suffit pas.
    poser_stats_de_production(&conn, &[]);
    assert_eq!(
        regime_statistiques(&conn, "event"),
        RegimeStatistiques::Agregees,
        "un `sqlite_stat1` sans `sqlite_stat4` est un régime AGRÉGÉ, et doit se lire comme tel"
    );

    // CRAN 2 — la base est peuplée et ANALYSÉE pour de vrai : SQLite produit ses propres échantillons.
    peupler_event_au_profil(&conn, 3_000);
    conn.execute_batch("PRAGMA analysis_limit=0; ANALYZE;").expect("ANALYZE complet");
    assert_eq!(
        regime_statistiques(&conn, "event"),
        RegimeStatistiques::Detaillees,
        "après un ANALYZE complet sur une base peuplée, les statistiques d'index DÉTAILLÉES doivent \
         exister — sans elles le trou nommé par P10.9-a resterait ouvert"
    );
    // MUTATION DE L'INSTRUMENT : les crans sont ORDONNÉS, donc comparables. Un régime qui ne serait
    // pas ordonné ne permettrait pas de dire « ce verdict a été lu sous MOINS que ce qu'il faut ».
    assert!(RegimeStatistiques::Aucune < RegimeStatistiques::Agregees);
    assert!(RegimeStatistiques::Agregees < RegimeStatistiques::Detaillees);

    // Et l'observatoire RECONSTATE, au pas borné : les premiers énoncés d'un démarrage sont lus avant
    // l'analyse de fond, donc un régime figé à la première lecture mentirait pour tout le reste de la
    // vie du processus. Le pas est BORNÉ (le reconstat interroge le catalogue) : il faut donc
    // `PAS_DE_RECONSTAT_DU_REGIME` lectures pour le voir bouger, et c'est le comportement voulu.
    let sql = enonce_qui_force(index.first().expect("au moins un index"));
    for _ in 0..crate::index_usage::PAS_DE_RECONSTAT_DU_REGIME {
        obs.observer(&conn, &sql, crate::index_usage::Consommateur::Analyste);
    }
    assert_eq!(
        obs.regime(),
        Some(RegimeStatistiques::Detaillees),
        "l'observatoire doit reconstater le régime tant qu'il n'est pas au maximum"
    );
}

/// ⑨ CE QUE LA SÉRIE NE PROUVE PAS EST ÉCRIT LÀ OÙ LE VERDICT SE LIT.
///
/// Un lecteur de `/metrics` ne lit pas le source. Si la portée d'un compteur ne voyage pas AVEC lui,
/// elle est perdue au premier tableau de bord — et c'est un compteur à zéro, cité sans sa portée, qui
/// fait retirer un index. La garde exige donc que le `# HELP` de la série porte le texte, et que ce
/// texte dise les trois choses qui font la portée : le zéro, l'échantillonnage, le régime.
#[test]
fn lexposition_porte_ce_que_la_serie_ne_prouve_pas() {
    let (_chemin, db) = base_au_schema_reel("idxobs-limites");
    let conn = db.lock();
    let index = index_de_event(&conn);
    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);
    obs.observer(&conn, &enonce_qui_force(index.first().expect("au moins un index")), crate::index_usage::Consommateur::Analyste);
    let expose = obs.exposition_prom();

    let aide = expose
        .lines()
        .find(|l| l.starts_with("# HELP plume_index_usage_total "))
        .expect("la série d'usage doit porter une ligne d'aide")
        .to_string();
    assert!(
        aide.contains(crate::index_usage::LIMITES),
        "le `# HELP` de `plume_index_usage_total` ne porte pas le texte de portée : la limite ne \
         voyagerait pas avec le chiffre. Aide lue : {aide}"
    );
    // `P10.9-a`, 2026-08-28 — DEUX EXIGENCES DE PLUS, et elles ne sont pas décoratives : la campagne
    // d'observation en production a RÉFUTÉ la lecture qu'on croyait pouvoir faire de cette série, et le
    // texte publié ne portait rien de ce qui a été appris. « ABSENT » parce que le verdict se tire de
    // l'absence d'un index, jamais d'un zéro (un index jamais nommé n'a PAS de ligne ici) ; « trop
    // petite » parce que l'explication qui a survécu à l'épreuve est que le planificateur préfère un
    // parcours complet sur une petite table — ce qu'un observatoire d'usage ne sait pas distinguer de
    // l'inutilité, et ce qui rend la liste des index jamais nommés INEXPLOITABLE comme liste de retrait.
    for exigence in
        ["ECHANTILLONNE", "redemarrage", "plume_index_usage_stats_regime", "ABSENT", "trop petite", "plume_index_usage_lignes_estimees"]
    {
        assert!(
            crate::index_usage::LIMITES.contains(exigence),
            "le texte de portée ne dit rien de « {exigence} » — il ne suffirait pas à empêcher la \
             lecture fautive qu'il existe pour empêcher"
        );
    }
    // Le témoin négatif et le trou de mesure sont PUBLIÉS eux aussi : sans eux, un lecteur ne peut pas
    // distinguer « aucun index employé » de « rien n'a pu être lu ».
    for serie in [
        "plume_index_usage_plans_lus_total",
        "plume_index_usage_plans_refuses_total",
        "plume_index_usage_plans_sans_index_total",
        "plume_index_usage_stats_regime",
    ] {
        assert!(expose.contains(serie), "la série `{serie}` doit être publiée : elle porte la lecture du reste");
    }
    // Une ligne d'aide Prometheus tient sur UNE ligne : un texte multiligne casserait l'exposition.
    assert!(!crate::index_usage::LIMITES.contains('\n'), "le texte de portée doit tenir sur une seule ligne");
    // ET AUCUNE VALEUR D'ÉTIQUETTE NE PEUT CASSER LE DOCUMENT. Un guillemet dans un nom d'index ne
    // casserait pas seulement sa ligne : il rendrait TOUT `/metrics` illisible au collecteur, donc
    // toutes les autres séries du démon. Deux étiquettes par série -> exactement quatre guillemets.
    for l in expose.lines().filter(|l| l.starts_with("plume_index_usage_total{")) {
        assert_eq!(
            l.matches('"').count(),
            4,
            "ligne de série mal formée (une valeur d'étiquette porte un guillemet) : {l}"
        );
    }
}

/// ⑩ `P10.9-a` — LE CHIFFRE QUI DIT COMMENT LIRE LE RESTE : L'ESTIMATION DE LIGNES DU PLANIFICATEUR.
///
/// CE QUI A ÉTÉ MESURÉ, ET CE QUE ÇA A RENVERSÉ. La campagne d'observation en production (2026-08-23)
/// a rendu une liste d'index qu'AUCUN plan n'a nommés. L'hypothèse naturelle — « ils servent des
/// surfaces que personne n'a ouvertes » — a été mise à l'épreuve par une traversée délibérée de toutes
/// les routes de lecture, et RÉFUTÉE. Ce qui restait est autrement plus gênant : les tables concernées
/// sont assez petites pour que le planificateur préfère un parcours complet. **Un observatoire d'usage
/// ne sait pas distinguer « cet index ne sert à rien » de « cette table est trop petite pour qu'il
/// serve ».** Il ne l'apprendra pas ; ce n'est pas ce qu'il mesure.
///
/// CE QUE CE LOT CONSTRUIT, ET POURQUOI CE N'EST PAS UN CONFORT. L'observatoire ne peut pas trancher,
/// mais il peut PUBLIER le chiffre qui laisse le lecteur trancher — et il ne le publiait pas. Un
/// lecteur de `/metrics` voyait donc des compteurs d'usage sans aucun moyen de savoir si son
/// installation est à une échelle où le choix du planificateur veut dire quelque chose : un résultat
/// incomplet présenté comme complet, la famille même que ce dépôt poursuit.
///
/// CE QUE CE TÉMOIN EXIGE — et les trois faits sont indépendants :
///   ① la série est publiée, et sa valeur est CELLE du catalogue, pas une valeur inventée ;
///   ② MUTATION qui nomme la valeur qui change : la base grossit, l'analyse repasse, le chiffre PUBLIÉ
///      suit. Sans ce fait, un chiffre constaté une fois puis figé mentirait sur toute la vie du
///      processus — exactement ce que le régime, lui, a le droit de faire (il ne peut que monter) ;
///   ③ TÉMOIN NÉGATIF : sans statistique, RIEN n'est publié — pas `0`. Le planificateur devine alors
///      une constante, et publier une supposition sous le nom d'une estimation serait pire que le
///      silence. Et l'absence est prouvée SUR UNE EXPOSITION NON VIDE, sans quoi elle ne dirait rien.
#[test]
fn lexposition_publie_lestimation_de_lignes_dont_le_planificateur_se_sert() {
    // L'INSTRUMENT DE LECTURE, ÉCRIT AVANT DE S'EN SERVIR — et il a déjà été FAUX une fois, le
    // 2026-08-28 : chercher la sous-chaîne `plume_index_usage_lignes_estimees` dans l'exposition
    // rendait TOUJOURS vrai, parce que le texte de portée du `# HELP` NOMME la série pour renvoyer le
    // lecteur vers elle. Un motif ancré sur un flux dont on a soi-même changé le contenu ne mesure
    // rien. On lit donc une LIGNE DE SÉRIE : un nom en tête de ligne, jamais `# HELP`/`# TYPE`.
    let valeur_de_serie = |expose: &str, nom: &str| -> Option<i64> {
        expose.lines().find_map(|l| {
            let reste = l.strip_prefix(nom)?;
            let reste = reste.strip_prefix("{table=\"event\"}").unwrap_or(reste);
            reste.trim().parse::<i64>().ok()
        })
    };
    let serie_presente = |expose: &str, nom: &str| -> bool {
        expose.lines().any(|l| l.starts_with(nom) && !l.starts_with("# "))
    };

    // ③ D'ABORD LE TÉMOIN NÉGATIF : base au schéma réel, JAMAIS peuplée -> aucune statistique sur `event`.
    let (_chemin_vierge, db_vierge) = base_au_schema_reel("idxobs-lignes-vierge");
    {
        let conn = db_vierge.lock();
        let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);
        obs.observer(&conn, ENONCE_SANS_INDEX, crate::index_usage::Consommateur::Analyste);
        let expose = obs.exposition_prom();
        assert!(
            serie_presente(&expose, "plume_index_usage_plans_lus_total"),
            "CONTRÔLE : l'exposition doit être NON VIDE, sinon l'absence prouvée juste après ne prouverait rien"
        );
        assert!(
            expose.contains("plume_index_usage_lignes_estimees"),
            "CONTRÔLE INVERSE DE L'INSTRUMENT : le texte de portée doit bien NOMMER la série (c'est ce qui \
             a fait mentir la première version de ce test) — l'absence vérifiée juste après porte donc sur \
             la LIGNE DE SÉRIE, pas sur la mention"
        );
        assert!(
            !serie_presente(&expose, "plume_index_usage_lignes_estimees"),
            "sans statistique, l'estimation ne doit pas être publiée DU TOUT — pas publiée à `0`, qui \
             affirmerait une table vide. Exposition lue : {expose}"
        );
        assert_eq!(obs.lignes_estimees(), None, "et l'état interne dit la même chose que la série");
    }

    // ① PUIS LA PUBLICATION. Des lignes, une analyse, une observation — sur UN SEUL observatoire, parce
    // que c'est la persistance DANS UN observatoire vivant que la mutation ② éprouve : une première
    // version de ce test rebâtissait un observatoire neuf à chaque lecture, et sa mutation « constatée
    // une fois puis figée » restait VERTE. Un témoin dont la mutation ne change aucun verdict n'est pas
    // une garde ; celui-ci l'est devenu en cessant de repartir de zéro.
    let (_chemin, db) = base_au_schema_reel("idxobs-lignes");
    let semer = |n: i64| {
        let conn = db.lock();
        for i in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,'sshd','auth',3,'h','m','{}')",
                params![1_700_000_000i64 + i],
            )
            .expect("insertion");
        }
        conn.execute("ANALYZE", []).expect("analyse");
    };
    let obs = observatoire_neuf(crate::index_usage::INDEX_CAP, 1);
    let observer_n = |k: u64| {
        let conn = db.lock();
        for _ in 0..k {
            obs.observer(&conn, ENONCE_SANS_INDEX, crate::index_usage::Consommateur::Analyste);
        }
    };
    let publiee = || -> Option<i64> {
        let expose = obs.exposition_prom();
        let lue = valeur_de_serie(&expose, "plume_index_usage_lignes_estimees");
        // La série et l'état interne ne peuvent pas diverger : c'est la même lecture, publiée une fois.
        assert_eq!(lue, obs.lignes_estimees(), "la série publiée et l'état constaté doivent coïncider");
        lue
    };
    let attendu_du_catalogue = || -> i64 {
        let conn = db.lock();
        crate::index_usage::lignes_estimees(&conn, "event").expect("sqlite_stat1 porte `event` après ANALYZE")
    };

    semer(64);
    observer_n(1);
    let premier = publiee().expect("après ANALYZE, l'estimation DOIT être publiée");
    assert_eq!(premier, attendu_du_catalogue(), "la valeur publiée est CELLE du catalogue, pas une valeur reconstruite");
    assert!(premier > 0, "une estimation nulle après 64 insertions signalerait que le banc ne mesure rien");

    // ② LA MUTATION. La base est multipliée par dix et ré-analysée.
    semer(576); // 64 -> 640
    let catalogue_apres = attendu_du_catalogue();
    assert!(
        catalogue_apres > premier,
        "PRÉMISSE FAUSSE : le CATALOGUE lui-même n'a pas bougé ({premier} puis {catalogue_apres}) — alors \
         ce qui suit ne mesurerait pas l'observatoire, mais SQLite"
    );
    // ②a LA CADENCE EST RÉELLE : le constat ne se refait pas à chaque plan lu.
    observer_n(1);
    assert_eq!(
        publiee(),
        Some(premier),
        "le constat interroge le catalogue : s'il se refaisait à chaque plan, il coûterait plus cher que \
         la lecture de plan qu'il accompagne"
    );
    // ②b MAIS IL SE REFAIT AU PAS SUIVANT — le pas est LU dans la constante, jamais recopié.
    observer_n(crate::index_usage::PAS_DE_RECONSTAT_DU_REGIME);
    let second = publiee().expect("estimation toujours publiée");
    assert_eq!(second, catalogue_apres, "au pas suivant, la valeur publiée suit de nouveau le catalogue");
    assert!(
        second > premier,
        "MUTATION SANS EFFET : la base a été multipliée par dix et le chiffre publié n'a pas bougé \
         ({premier} puis {second}) — un chiffre constaté une fois puis figé mentirait sur toute la vie \
         du processus, et c'est précisément ce que cette série existe pour ne pas faire"
    );
}
