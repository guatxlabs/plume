// `P7.19-g` (second constat) — LA VERSION DU MOTEUR DE STOCKAGE EST ÉPINGLÉE, ET UNE DÉRIVE ROUGIT.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE TROU, MESURÉ LE 2026-09-02
// ─────────────────────────────────────────────────────────────────────────────────────────────
// Cet arbre asservit beaucoup de choses : les deux profils asservissent leur NOMBRE de tests,
// l'intégration asservit l'ÉCART entre profils, le manifeste ÉPINGLE la bibliothèque de liaison et
// le verrou de dépendances fige sa somme de contrôle. Mais la bibliothèque de liaison EMBARQUE un
// moteur — l'amalgame chiffré — et c'est LUI qui décide du plan de chaque requête, de ce qu'un
// `ANALYZE` écrit, et de ce que `sqlite_stat1` contient. Sa version n'était inscrite NULLE PART :
// ni dans le manifeste, ni dans le verrou, ni dans un témoin. Elle pouvait donc dériver de douze
// versions mineures sans qu'une seule ligne du dépôt ne le dise, et les deux témoins qui en
// dépendent seraient tombés SANS QUE RIEN NE NOMME LA CAUSE.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE PIÈGE DE CE TÉMOIN-CI, ET COMMENT IL EST ÉVITÉ — D'OÙ VIENT CHAQUE CÔTÉ
// ─────────────────────────────────────────────────────────────────────────────────────────────
// Un témoin qui vérifie une constante CONTRE ELLE-MÊME est vert par construction et ne vaut rien.
// Les deux côtés de chaque comparaison sont donc nommés, sans atténuation :
//
//   CÔTÉ GAUCHE — les constantes de ce fichier. Elles sont ÉCRITES À LA MAIN, à partir d'une
//   exécution dont la sortie a été LUE. Aucune n'est calculée, dérivée, ni recopiée depuis l'appel
//   qu'elle sert à juger : la première rédaction de ce fichier portait délibérément une valeur
//   FAUSSE, le témoin a rougi, et c'est la valeur que SON message d'échec a imprimée qui a été
//   recopiée ici. Si quelqu'un remplaçait un jour ces constantes par un appel au moteur, le témoin
//   deviendrait vert POUR TOUJOURS et ce fichier n'aurait plus aucune valeur.
//
//   CÔTÉ DROIT — le MOTEUR, interrogé à l'exécution : `sqlite_version()` sur une connexion
//   ouverte par la même bibliothèque que la production, et un `ANALYZE` réellement exécuté.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// POURQUOI DEUX ÉPINGLES, ET NON UNE
// ─────────────────────────────────────────────────────────────────────────────────────────────
// La chaîne de version est l'épingle NOMINALE : elle dit QUI est là. Elle ne dit pas ce que cela
// change. La seconde épingle est COMPORTEMENTALE et porte exactement le comportement dont deux
// témoins de cet arbre dépendent : ce qu'un `ANALYZE` écrit pour une table VIDE qui porte un index
// PARTIEL. MESURÉ hors caisse sur cinq moteurs (3.39.4, 3.45.3, 3.46.1, 3.50.4, 3.51.3), avec les
// mêmes options de compilation et le schéma de ce dépôt : les deux plus anciens n'écrivent RIEN,
// les trois plus récents écrivent une ligne `0 0 0` PAR INDEX PARTIEL et rien pour un index plein.
// La frontière est donc entre 3.45.3 et 3.46.1, trois versions mineures AVANT la rupture de
// compilation que `P7.19-e` décrit — les deux effets que la clé soudait ont des seuils DIFFÉRENTS.
//
// UNE ÉPINGLE NOMINALE SEULE SE CONTOURNE (on met la constante à jour et on passe) ; une épingle
// COMPORTEMENTALE oblige à REGARDER ce qui a changé. Les deux ensemble font que la seule façon de
// franchir une montée est de re-MESURER, jamais d'ajuster un chiffre.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QUE CE TÉMOIN NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
// ─────────────────────────────────────────────────────────────────────────────────────────────
//   · IL DÉTECTE, IL N'EMPÊCHE PAS. Il rougit APRÈS qu'une montée a été prise ; rien ici ne refuse
//     une montée en amont.
//   · IL NE COUVRE QUE CE QU'IL NOMME. Douze versions mineures de moteur changent bien d'autres
//     choses que la ligne mesurée ici — le choix d'index sur un prédicat de borne, notamment, dont
//     ce dépôt sait déjà qu'il n'est pas borné (cf. `P7.19-e`, « ce que l'enquête ne tient pas »).
//     Un vert ici ne dit pas « la montée est sûre » ; il dit « le moteur est celui qu'on croit ».
//   · IL NE DIT RIEN DU CODEC DE CHIFFREMENT. `sqlite_version()` rend la version de l'amalgame ;
//     la version du codec qui l'enrobe n'est pas lue ici.

/// LA VERSION DU MOTEUR, ÉCRITE À LA MAIN. Relevée le 2026-09-03 sur CETTE caisse, en lisant le
/// message d'échec de ce témoin même, armé d'une valeur volontairement fausse. Ce n'est PAS la
/// valeur d'un appel recopié par un outil : le jour où elle est fausse, la mettre à jour n'est pas
/// le geste — le geste est de rejouer la mesure comportementale ci-dessous et de dire ce qu'elle
/// donne.
const VERSION_DU_MOTEUR_EPINGLEE: &str = "3.39.4";

/// CE QU'UN `ANALYZE` ÉCRIT POUR UNE TABLE **VIDE** QUI PORTE UN INDEX **PARTIEL**, sous le moteur
/// épinglé. ÉCRIT À LA MAIN, d'après la mesure au banc hors caisse (5 moteurs) confirmée ici même
/// par une exécution réelle. `0` = le moteur épinglé n'écrit RIEN. À partir de 3.46.1 cette valeur
/// vaut le NOMBRE D'INDEX PARTIELS de la table (chacun à `0 0 0`), et c'est ce basculement qui fait
/// tomber deux témoins de cet arbre s'ils ne sont pas reformulés d'abord.
const LIGNES_ECRITES_POUR_UNE_TABLE_VIDE_A_INDEX_PARTIEL: i64 = 0;

/// LE MOTEUR EST CELUI QU'ON CROIT — par son NOM et par son COMPORTEMENT.
#[test]
fn la_version_du_moteur_de_stockage_est_epinglee_et_son_comportement_danalyse_avec() {
    // Une connexion ouverte par la MÊME bibliothèque que la production. En mémoire à dessein : ce
    // témoin ne juge pas un fichier de base, il juge le moteur lié dans ce binaire.
    let conn = Connection::open_in_memory().expect("connexion mémoire");

    // ── ÉPINGLE 1 : LE NOM. Gauche = constante écrite à la main ; droite = le moteur, interrogé.
    let version_rendue_par_le_moteur: String =
        conn.query_row("SELECT sqlite_version()", [], |r| r.get(0)).expect("le moteur rend sa version");
    assert_eq!(
        version_rendue_par_le_moteur, VERSION_DU_MOTEUR_EPINGLEE,
        "LE MOTEUR DE STOCKAGE A CHANGÉ. Épinglé : `{VERSION_DU_MOTEUR_EPINGLEE}` (écrit à la main \
         dans `daemon/src/tests/version_du_moteur_epinglee.rs`). Lu sur le moteur lié à ce binaire : \
         `{version_rendue_par_le_moteur}`. Ce n'est pas un détail de dépendance : ce moteur décide du \
         plan de CHAQUE requête et de ce qu'un `ANALYZE` écrit. Le geste n'est PAS de mettre la \
         constante à jour — c'est de rejouer le protocole de montée de `P7.19-e` (tableau de plans \
         AVANT/APRÈS, crête mémoire jouée SEULE) et de dire ce qu'il donne."
    );
    // Le même fait, demandé à la bibliothèque de liaison plutôt qu'au moteur par une requête : deux
    // chemins de lecture qui ne peuvent pas diverger sans que l'un des deux mente.
    assert_eq!(
        rusqlite::version(),
        VERSION_DU_MOTEUR_EPINGLEE,
        "la bibliothèque de liaison et le moteur interrogé par une requête ne rendent pas la même \
         version : l'un des deux chemins de lecture ment"
    );

    // ── ÉPINGLE 2 : LE COMPORTEMENT. Gauche = constante écrite à la main ; droite = un `ANALYZE`
    // RÉELLEMENT exécuté sur une table VIDE portant un index PARTIEL.
    conn.execute_batch(
        "CREATE TABLE epreuve_du_moteur(id INTEGER PRIMARY KEY, categorie TEXT, ts INTEGER);\n\
         CREATE INDEX ix_epreuve_plein ON epreuve_du_moteur(ts);\n\
         CREATE INDEX ix_epreuve_partiel ON epreuve_du_moteur(ts) WHERE categorie='sante';\n\
         ANALYZE;",
    )
    .expect("la table d'épreuve se construit et s'analyse");
    let lignes_ecrites: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_stat1 WHERE tbl='epreuve_du_moteur'", [], |r| r.get(0))
        .unwrap_or(0);
    // CONTRÔLE DE L'INSTRUMENT : la table de statistiques doit EXISTER, sinon le compte ci-dessus
    // vaudrait zéro pour la mauvaise raison — « le moteur n'écrit rien » et « je n'ai rien pu lire »
    // se ressembleraient, et c'est exactement la confusion que ce dépôt poursuit.
    assert_eq!(
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_stat1')",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap_or(0),
        1,
        "CONTRÔLE : `ANALYZE` n'a pas créé `sqlite_stat1` — le compte de lignes qui suit ne mesure \
         alors PAS le comportement du moteur, mais une lecture qui a échoué"
    );
    // Et le CONTRÔLE POSITIF de la mesure : la même base, PEUPLÉE, doit écrire des lignes. Sans lui,
    // un `0` ci-dessus serait indiscernable d'un `ANALYZE` qui n'aurait rien fait du tout.
    assert_eq!(
        lignes_ecrites, LIGNES_ECRITES_POUR_UNE_TABLE_VIDE_A_INDEX_PARTIEL,
        "LE COMPORTEMENT D'`ANALYZE` A CHANGÉ. Attendu sous le moteur épinglé \
         `{VERSION_DU_MOTEUR_EPINGLEE}` : {LIGNES_ECRITES_POUR_UNE_TABLE_VIDE_A_INDEX_PARTIEL} \
         ligne(s) de statistiques pour une table VIDE portant un index partiel. Constaté : \
         {lignes_ecrites}. À partir de 3.46.1 le moteur écrit une ligne `0 0 0` PAR INDEX PARTIEL — \
         ce qui fait basculer le régime de statistiques d'une base neuve et rendrait publiable une \
         estimation de lignes à ZÉRO. Voir `P7.19-f` et `P7.19-g`."
    );
    conn.execute_batch(
        "INSERT INTO epreuve_du_moteur(categorie, ts) VALUES('sante',1),('auth',2),('auth',3);\nANALYZE;",
    )
    .expect("la table d'épreuve se peuple et se ré-analyse");
    assert!(
        conn.query_row("SELECT COUNT(*) FROM sqlite_stat1 WHERE tbl='epreuve_du_moteur'", [], |r| r
            .get::<_, i64>(0))
        .unwrap_or(0)
            > 0,
        "CONTRÔLE POSITIF : une fois PEUPLÉE, la table d'épreuve doit porter des statistiques. Sans \
         cette ligne, le zéro mesuré juste au-dessus ne prouverait pas que le moteur s'abstient — il \
         pourrait signifier qu'`ANALYZE` n'écrit jamais rien ici."
    );
}
