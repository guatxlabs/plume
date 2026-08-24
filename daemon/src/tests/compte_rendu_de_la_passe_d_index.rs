// ================================================================================================
// P6.8-f — LE COMPTE RENDU DE LA PASSE D'INDEX EST CONSTATÉ AU CATALOGUE, IL N'EST PAS RÉCITÉ
// DEPUIS LA DÉCLARATION
// ================================================================================================
// LE DÉFAUT, DANS SA FORME EXACTE. La passe de fond qui crée les index d'expression des champs
// chauds attrape l'échec de CHAQUE `CREATE INDEX`, l'écrit sur la sortie d'erreur, CONTINUE — puis
// annonce à la fin un nombre d'index « présents » qui était `EXPR_INDEX_FIELDS.len()`, c'est-à-dire
// la longueur de la liste DÉCLARÉE, sans jamais relire le catalogue. Un démarrage où trois créations
// échouaient journalisait donc le compte complet. Le composant SAVAIT son résultat incomplet — il
// avait capturé chaque erreur, et venait de les écrire juste au-dessus — et le présentait comme
// complet.
//
// CE QUI REND CE DÉFAUT PIRE QU'UNE IMPRÉCISION, ET NON MOINDRE. Un court-circuit sort de la passe
// AVANT toute création dès que tous les index sont déjà là. La ligne trompeuse ne s'imprime donc
// JAMAIS en régime établi : elle ne s'imprime que lorsque la passe travaille pour de bon —
// exactement quand une création peut échouer. Le compte rendu était faux au seul moment où il avait
// quelque chose à apprendre, et muet le reste du temps. Un instrument qui ne peut rendre qu'un
// succès ne renseigne sur rien.
//
// COMMENT UNE CRÉATION EST FAITE ÉCHOUER, HONNÊTEMENT. Aucun drapeau de test n'existe dans le
// produit pour ça, et il ne faut pas en créer un : une voie qui n'existerait que pour la garde ne
// prouverait rien du chemin réel. On se sert d'une propriété de SQLite, VALIDÉE ici même par
// `un_nom_deja_pris_dans_le_schema_fait_echouer_la_creation` : `CREATE INDEX IF NOT EXISTS <nom>`
// ÉCHOUE quand `<nom>` est déjà porté par un objet d'un AUTRE TYPE (« there is already a table named
// <nom> »), et le `IF NOT EXISTS` ne masque PAS cette collision — il ne couvre que le cas d'un index
// homonyme. C'est une collision de noms dans le schéma, c'est-à-dire un mode d'échec de terrain
// (reliquat d'un objet posé à la main, migration à moitié appliquée), pas une mise en scène.
//
// LES DEUX SENS, ET LA VALEUR QUI CHANGE. La mutation nomme UNE valeur : le compte annoncé. Avec
// sabotage, la ligne doit dire un compte DIFFÉRENT du déclaré et NOMMER les champs manquants ; sans
// sabotage — le témoin inverse, sans lequel on ne prouverait que la capacité à se plaindre — elle
// doit dire le compte complet et ne nommer personne. Ni le compte attendu ni les noms ne sont écrits
// ici : ils sont DÉRIVÉS de `HOT_FIELDS`, et la liste annoncée est relue à partir du marqueur que le
// produit expose, plutôt que devinée dans la forme de la phrase.
//
// AUCUN ÉTAT DE PROCESSUS N'EST ÉCRIT ICI. Le régime du levier `PLUME_EXPRINDEX` est LU par la voie
// du produit (`env > fichier > défaut`) et NOMMÉ dans chaque verdict. Sous levier éteint la passe
// n'annonce RIEN, et c'est asserté comme tel : le silence est une propriété du produit, pas un test
// sauté.

#[cfg(test)]
mod compte_rendu_de_la_passe_d_index {
    use crate::maintenance::{reconcile_expr_indexes_background, MARQUEUR_INDEX_MANQUANTS};
    use crate::soql_glue::HOT_FIELDS;
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// La règle de nommage de la famille, telle que le produit l'applique. Elle est CONFRONTÉE au
    /// catalogue par `P6.8-d` (les index dérivés doivent exister après démarrage) : un renommage
    /// côté produit qui l'oublierait ici rend cette suite-là rouge, pas verte-et-aveugle.
    const PREFIXE_FAMILLE: &str = "idx_ev_f_";

    /// Le levier qui gouverne la famille, et sa valeur par défaut — les deux tels que le produit les
    /// écrit (`maintenance.rs`, `cfg(conf, "PLUME_EXPRINDEX", "1")`).
    const LEVIER: &str = "PLUME_EXPRINDEX";
    const LEVIER_DEFAUT: &str = "1";

    fn levier_arme() -> bool {
        crate::cfg(&crate::load_config(), LEVIER, LEVIER_DEFAUT) == LEVIER_DEFAUT
    }

    fn regime() -> &'static str {
        if levier_arme() {
            "ARMÉ"
        } else {
            "ÉTEINT"
        }
    }

    /// Le nom que le produit donnera à l'index d'un champ. Dérivé, jamais recopié.
    fn nom_derive(champ: &str) -> String {
        format!("{PREFIXE_FAMILLE}{champ}")
    }

    /// LA DDL DU PRODUIT pour un champ — index d'expression PARTIEL sur `event`. Elle n'est reprise
    /// ici que par `un_nom_deja_pris_dans_le_schema_fait_echouer_la_creation`, dont tout l'objet est
    /// de VALIDER L'INSTRUMENT : ce test doit exécuter la MÊME instruction que la passe, sinon il
    /// attesterait d'une propriété de SQLite que la passe ne rencontre pas.
    fn ddl_de_creation(champ: &str) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON event(json_extract(fields,'$.{champ}')) \
             WHERE json_extract(fields,'$.{champ}') IS NOT NULL",
            nom_derive(champ)
        )
    }

    /// LE SABOTAGE, ET IL EST HONNÊTE : on OCCUPE le nom de l'index par un objet d'un autre type. La
    /// création que la passe tentera échouera donc pour une raison que SQLite énonce lui-même, sans
    /// qu'aucune ligne du produit ait été ajoutée pour rendre cet échec possible.
    fn occuper_le_nom(conn: &Connection, champ: &str) {
        conn.execute(&format!("CREATE TABLE {} (x)", nom_derive(champ)), [])
            .unwrap_or_else(|e| panic!("le nom de l'index de « {champ} » doit pouvoir être occupé : {e}"));
    }

    /// L'index de ce champ est-il RÉELLEMENT au catalogue ? (le seul côté qui compte : pas ce que le
    /// code déclare, ce que la base porte).
    fn index_au_catalogue(conn: &Connection, champ: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1",
            rusqlite::params![nom_derive(champ)],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// LA LISTE QUE LA LIGNE ANNONCE COMME MANQUANTE — relue à partir du marqueur exposé par le
    /// produit, jamais devinée dans la forme de la phrase. `None` quand la ligne n'accuse personne.
    fn manquants_annonces(ligne: &str) -> Option<BTreeSet<String>> {
        let (_, queue) = ligne.split_once(MARQUEUR_INDEX_MANQUANTS)?;
        Some(queue.trim().split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect())
    }

    /// La base migrée, prête pour la passe de fond (le chemin réel : `db/schema.sql` + toute la
    /// chaîne de migrations).
    fn base_migree() -> Arc<Mutex<Connection>> {
        Arc::new(Mutex::new(super::test_db()))
    }

    /// La moitié des champs déclarés, prise UN SUR DEUX pour que les sabotés et les intacts soient
    /// entremêlés dans la déclaration : un compte rendu qui tronquerait la liste au lieu de la
    /// constater ne s'en tirerait pas par un préfixe ou un suffixe.
    fn partition_du_sabotage() -> (Vec<&'static str>, Vec<&'static str>) {
        let sabotes: Vec<&'static str> = HOT_FIELDS.iter().copied().step_by(2).collect();
        let intacts: Vec<&'static str> =
            HOT_FIELDS.iter().copied().filter(|c| !sabotes.contains(c)).collect();
        (sabotes, intacts)
    }

    // ============================================================================================

    /// VALIDATION DE L'INSTRUMENT — le sabotage fait-il vraiment échouer la création, et ne
    /// fait-il échouer que ce qu'il vise ?
    ///
    /// Sans ce test, la mutation qui suit prouverait seulement qu'un compte rendu peut se plaindre :
    /// si la collision de noms n'empêchait PAS la création (par exemple parce que `IF NOT EXISTS`
    /// l'absorbait), le compte annoncé serait complet et la garde rougirait pour une raison qui
    /// n'est pas celle qu'elle croit. Les DEUX témoins sont donc joués sur la MÊME instruction, sur
    /// le moteur RÉELLEMENT LIÉ au binaire : sans le nom occupé la création RÉUSSIT, avec le nom
    /// occupé elle ÉCHOUE et aucun index de ce nom n'apparaît.
    #[test]
    fn un_nom_deja_pris_dans_le_schema_fait_echouer_la_creation() {
        let (sabotes, intacts) = partition_du_sabotage();
        let sabote = *sabotes.first().expect("prémisse : au moins un champ déclaré à saboter");
        let intact = *intacts.first().expect("prémisse : au moins un champ déclaré laissé intact");

        let conn = super::test_db();

        // TÉMOIN NÉGATIF (aucun sabotage) : la DDL du produit passe.
        conn.execute(&ddl_de_creation(intact), []).unwrap_or_else(|e| {
            panic!(
                "TÉMOIN NÉGATIF RÉFUTÉ : la création d'index du produit échoue déjà sans sabotage \
                 ({e}) — la mutation qui suit ne mesurerait pas ce qu'elle croit"
            )
        });
        assert!(index_au_catalogue(&conn, intact), "témoin négatif : l'index créé doit être au catalogue");

        // TÉMOIN POSITIF : le nom occupé par un objet d'un AUTRE type -> la MÊME instruction échoue,
        // `IF NOT EXISTS` ne masquant que le cas d'un INDEX homonyme.
        occuper_le_nom(&conn, sabote);
        let r = conn.execute(&ddl_de_creation(sabote), []);
        assert!(
            r.is_err(),
            "L'INSTRUMENT NE MORD PAS : `CREATE INDEX IF NOT EXISTS` a réussi alors que le nom \
             `{}` est déjà porté par un objet d'un autre type. Le sabotage de la mutation suivante \
             serait sans effet et sa garde deviendrait verte en étant aveugle.",
            nom_derive(sabote)
        );
        assert!(
            !index_au_catalogue(&conn, sabote),
            "l'instrument doit laisser le catalogue SANS index de ce nom — c'est ce que la passe \
             devra constater"
        );
    }

    /// LA MUTATION — DES CRÉATIONS ÉCHOUENT, ET LA LIGNE LE DIT EN NOMMANT CE QUI MANQUE.
    ///
    /// LA VALEUR QUI CHANGE est le compte annoncé : il valait la longueur de la liste DÉCLARÉE quoi
    /// qu'il arrive ; il vaut désormais le nombre d'index CONSTATÉS au catalogue. La garde exige les
    /// deux faces de ce changement — que le compte complet NE soit PAS annoncé, et que le compte
    /// constaté le soit — puis que l'ensemble des champs nommés comme manquants soit EXACTEMENT
    /// celui des créations empêchées.
    #[test]
    fn le_compte_rendu_nomme_ce_qui_manque_quand_des_creations_echouent() {
        let (sabotes, intacts) = partition_du_sabotage();
        assert!(!sabotes.is_empty() && !intacts.is_empty(), "prémisse : la partition doit être non triviale");

        let db = base_migree();
        for champ in &sabotes {
            occuper_le_nom(&db.lock(), champ);
        }

        let annonce = reconcile_expr_indexes_background(&db);

        // LEVIER ÉTEINT : la passe ne crée rien et n'annonce rien. C'est une propriété du produit,
        // asserté comme telle — pas un test sauté.
        if !levier_arme() {
            assert!(
                annonce.is_none(),
                "LEVIER {} — la passe de fond a annoncé quelque chose alors qu'elle n'a rien à \
                 créer : {annonce:?}",
                regime()
            );
            return;
        }

        let ligne = annonce.unwrap_or_else(|| {
            panic!(
                "LEVIER {} — la passe a travaillé (des index manquaient) et n'a RIEN annoncé. Une \
                 passe qui crée sans rendre compte est le défaut d'à côté.",
                regime()
            )
        });

        let attendus = HOT_FIELDS.len();
        let constates = intacts.len();
        assert!(
            ligne.contains(&format!("{constates}/{attendus}")),
            "LEVIER {} — LE COMPTE ANNONCÉ N'EST PAS CELUI DU CATALOGUE : {constates} index sur \
             {attendus} ont pu être créés, la ligne ne le dit pas. Ligne : {ligne}",
            regime()
        );
        assert!(
            !ligne.contains(&format!("{attendus}/{attendus}")),
            "LEVIER {} — LE COMPTE RENDU ANNONCE LA DÉCLARATION : la ligne dit {attendus} index sur \
             {attendus} alors que {} créations ont échoué, chacune écrite juste au-dessus. C'est le \
             défaut P6.8-f dans sa forme exacte. Ligne : {ligne}",
            regime(),
            sabotes.len()
        );

        let nommes = manquants_annonces(&ligne).unwrap_or_else(|| {
            panic!(
                "LEVIER {} — LA LIGNE NE NOMME PERSONNE : elle constate un compte incomplet sans \
                 dire CE QUI manque. Un exploitant apprend qu'il y a un trou, pas où. Ligne : {ligne}",
                regime()
            )
        });
        let attendus_manquants: BTreeSet<String> = sabotes.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            nommes, attendus_manquants,
            "LEVIER {} — LES CHAMPS NOMMÉS COMME MANQUANTS NE SONT PAS CEUX DONT LA CRÉATION A \
             ÉCHOUÉ. Ligne : {ligne}",
            regime()
        );

        // Le catalogue est le juge : ce que la ligne dit manquer manque VRAIMENT, et ce qu'elle ne
        // nomme pas est VRAIMENT là. Sans ce dernier point, une ligne qui accuserait tout le monde
        // passerait les assertions ci-dessus le jour où le sabotage couvrirait toute la liste.
        let conn = db.lock();
        for champ in &sabotes {
            assert!(!index_au_catalogue(&conn, champ), "l'index de « {champ} » ne doit pas exister");
        }
        for champ in &intacts {
            assert!(
                index_au_catalogue(&conn, champ),
                "l'index de « {champ} » devait être créé par la passe : sans lui, le compte constaté \
                 ne mesurerait pas l'effet du sabotage"
            );
        }
    }

    /// LE TÉMOIN INVERSE — TOUT RÉUSSIT, LE COMPTE EST COMPLET ET PERSONNE N'EST NOMMÉ.
    ///
    /// Sans lui, la garde précédente prouverait seulement qu'un compte rendu sait se plaindre : un
    /// verdict qui accuserait TOUJOURS passerait la mutation et ne vaudrait rien. On exige en outre
    /// le SILENCE de la deuxième passe : le court-circuit sort avant toute création quand tout est
    /// déjà au catalogue, et ce silence-là est la propriété qui rendait le défaut d'origine invisible
    /// en régime établi.
    #[test]
    fn le_compte_rendu_est_complet_quand_toutes_les_creations_reussissent() {
        let db = base_migree();
        let annonce = reconcile_expr_indexes_background(&db);

        if !levier_arme() {
            assert!(
                annonce.is_none(),
                "LEVIER {} — la passe de fond a annoncé quelque chose alors qu'elle n'a rien à \
                 créer : {annonce:?}",
                regime()
            );
            return;
        }

        let ligne = annonce.unwrap_or_else(|| {
            panic!("LEVIER {} — la passe avait tout à créer sur une base migrée et n'a rien annoncé", regime())
        });
        let attendus = HOT_FIELDS.len();
        assert!(
            ligne.contains(&format!("{attendus}/{attendus}")),
            "LEVIER {} — le compte rendu d'une passe entièrement réussie doit annoncer les \
             {attendus} index constatés. Ligne : {ligne}",
            regime()
        );
        assert!(
            manquants_annonces(&ligne).is_none(),
            "LEVIER {} — LA LIGNE ACCUSE À VIDE : aucune création n'a échoué et elle nomme pourtant \
             des manquants. Ligne : {ligne}",
            regime()
        );

        // Deuxième passe : tout est là, le court-circuit sort AVANT toute création et n'annonce rien.
        assert!(
            reconcile_expr_indexes_background(&db).is_none(),
            "LEVIER {} — la seconde passe a annoncé quelque chose alors que tous les index étaient \
             déjà au catalogue : le court-circuit ne sort plus avant le travail",
            regime()
        );
    }
}
