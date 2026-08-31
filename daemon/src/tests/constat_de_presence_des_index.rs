// ================================================================================================
// P6.8-g — LE CONSTAT DE PRÉSENCE D'UN INDEX COMPARE LA DÉFINITION, PAS L'ÉTIQUETTE
// ================================================================================================
// LE DÉFAUT, DANS SA FORME EXACTE. Le constat de présence des index de champ chaud interrogeait le
// catalogue sur le seul NOM (`type='index' AND name=?`). Un objet de type index portant le nom
// attendu mais posé sur une AUTRE table — ou sur une autre expression — était donc compté
// « présent ». Le court-circuit de la passe de fond sortait alors sans rien faire, et le vrai index
// n'était JAMAIS créé : aucune alerte, aucune ligne, la passe croyait son travail fait.
//
// ET LE PRODUIT NE POUVAIT PAS S'EN REMETTRE TOUT SEUL. La création est idempotente sur le NOM
// (`CREATE INDEX IF NOT EXISTS`) : elle n'écrase pas l'occupant, elle se retire en silence. Un
// homonyme mal posé n'est donc pas un manque transitoire que le démarrage suivant réparerait — c'est
// un état stable que rien ne signalait. C'est la propriété que valide `la_creation_du_produit_ne_
// reprend_pas_un_nom_deja_porte_par_un_index` avant que les mutations ne s'appuient dessus.
//
// LE FAUX VERT EST SYMÉTRIQUE DE `P6.8-f`. Cette clé-là a rendu le compte CONSTATÉ au lieu de
// DÉCLARÉ ; celle-ci rend le constat FIDÈLE au lieu de nominal. Conséquence à retenir au-delà des
// deux : une preuve tirée du SILENCE d'un instrument ne vaut que ce que vaut le prédicat de cet
// instrument — le silence de la passe attestait que douze objets de type index PORTAIENT ces noms,
// pas qu'ils étaient posés sur la bonne table ni sur la bonne expression.
//
// CE QUE LES MUTATIONS NOMMENT COMME VALEUR QUI CHANGE. Deux valeurs, mesurées séparément :
//   * LE COMPTE ANNONCÉ. Un homonyme mal posé valait « présent » ; il vaut désormais « occupé par
//     autre chose », il est NOMMÉ avec sa raison, et le compte constaté baisse d'autant.
//   * LE TRAVAIL DE LA PASSE. Quand TOUS les noms attendus sont occupés par des homonymes, la passe
//     court-circuitait et ne rendait RIEN ; elle travaille désormais et rend sa ligne.
// Le témoin inverse — un index créé par le produit reste compté présent, la seconde passe
// court-circuite — interdit le verdict qui rejetterait tout, et il vaut EN OUTRE confrontation
// anti-no-op : si l'attente du constat cessait de correspondre à ce que la DDL du produit écrit,
// chaque index créé serait déclaré mal posé et le court-circuit ne se prendrait plus jamais.
//
// AUCUN ÉTAT DE PROCESSUS N'EST ÉCRIT ICI. Le régime du levier `PLUME_EXPRINDEX` est LU par la voie
// du produit (`env > fichier > défaut`) et NOMMÉ dans chaque verdict. Aucun nom de champ, d'index ni
// de table de témoin n'est inventé : tout est DÉRIVÉ de `HOT_FIELDS` et de la règle de nommage.

#[cfg(test)]
mod constat_de_presence_des_index {
    use crate::maintenance::{
        reconcile_expr_indexes_background, MARQUEUR_INDEX_MAL_POSES, MARQUEUR_INDEX_MANQUANTS,
    };
    use crate::soql_glue::HOT_FIELDS;
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::sync::Arc;

    /// La règle de nommage de la famille, telle que le produit l'applique — confrontée au catalogue
    /// par `P6.8-d` et au geste de création par `P6.8-e`.
    const PREFIXE_FAMILLE: &str = "idx_ev_f_";

    /// Le levier qui gouverne la famille, et sa valeur par défaut, tels que le produit les écrit.
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

    fn nom_derive(champ: &str) -> String {
        format!("{PREFIXE_FAMILLE}{champ}")
    }

    /// LA DDL DU PRODUIT pour un champ — index d'expression PARTIEL sur `event`. Reprise ici pour
    /// VALIDER L'INSTRUMENT : le témoin doit exécuter la MÊME instruction que la passe, sinon il
    /// attesterait d'une propriété de SQLite que la passe ne rencontre pas.
    fn ddl_de_creation(champ: &str) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON event(json_extract(fields,'$.{champ}')) \
             WHERE json_extract(fields,'$.{champ}') IS NOT NULL",
            nom_derive(champ)
        )
    }

    /// LA TABLE SUR LAQUELLE UN INDEX EST RÉELLEMENT POSÉ — une COLONNE du catalogue, pas du texte.
    /// `None` quand aucun index de ce nom n'existe.
    fn table_de_lindex(conn: &Connection, nom: &str) -> Option<String> {
        conn.query_row(
            "SELECT tbl_name FROM sqlite_master WHERE type='index' AND name=?1",
            rusqlite::params![nom],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    /// UN CHAMP QUE LA DÉCLARATION NE PEUT PAS PRODUIRE, CONSTRUIT À PARTIR D'ELLE. La concaténation
    /// de toutes les entrées n'est aucune d'elles — la propriété est ASSERTÉE, pas espérée.
    fn champ_hors_declaration() -> String {
        let concat = HOT_FIELDS.concat();
        assert!(
            !HOT_FIELDS.contains(&concat.as_str()),
            "prémisse du témoin : la concaténation de la liste chaude ne doit pas être elle-même une \
             entrée de la liste"
        );
        concat
    }

    /// LA TABLE D'ACCUEIL DU TÉMOIN — dérivée elle aussi de la déclaration, donc aucun nom inventé.
    /// Son absence du schéma est ASSERTÉE : poser le témoin sur une table du produit brouillerait la
    /// mesure.
    fn table_daccueil(conn: &Connection) -> String {
        let nom = format!("hors_declaration_{}", champ_hors_declaration());
        assert!(
            conn.query_row("SELECT 1 FROM sqlite_master WHERE name=?1", rusqlite::params![nom], |_| Ok::<(), _>(()))
                .is_err(),
            "prémisse du témoin : « {nom} » ne doit rien désigner dans le schéma du produit"
        );
        conn.execute(&format!("CREATE TABLE {nom} (x)"), [])
            .unwrap_or_else(|e| panic!("la table d'accueil du témoin doit pouvoir être créée : {e}"));
        nom
    }

    /// LE TÉMOIN — un index qui porte le nom attendu et qui est posé AILLEURS. C'est un mode d'échec
    /// de terrain : reliquat d'un objet posé à la main, migration à moitié appliquée, restauration
    /// partielle. Aucune ligne n'est ajoutée au produit pour le rendre possible.
    fn poser_homonyme_ailleurs(conn: &Connection, champ: &str, table: &str) {
        conn.execute(&format!("CREATE INDEX {} ON {table}(x)", nom_derive(champ)), []).unwrap_or_else(|e| {
            panic!("le nom de l'index de « {champ} » doit pouvoir être occupé sur « {table} » : {e}")
        });
    }

    /// LE SECOND TÉMOIN — un index qui porte le nom attendu, posé sur la BONNE table, mais sur une
    /// AUTRE expression. Il passe le critère de table : seule la définition le démasque.
    fn poser_homonyme_sur_une_autre_expression(conn: &Connection, champ: &str) {
        let autre = champ_hors_declaration();
        conn.execute(
            &format!("CREATE INDEX {} ON event(json_extract(fields,'$.{autre}'))", nom_derive(champ)),
            [],
        )
        .unwrap_or_else(|e| panic!("l'homonyme d'expression de « {champ} » doit pouvoir être posé : {e}"));
    }

    fn base_migree() -> Arc<Mutex<Connection>> {
        Arc::new(Mutex::new(super::test_db()))
    }

    /// LA LISTE DES MAL POSÉS TELLE QUE LA LIGNE L'ANNONCE — relue à partir du marqueur exposé par le
    /// produit, jamais devinée dans la forme de la phrase. Bornée par le marqueur voisin, qui vient
    /// après elle. `None` quand la ligne n'accuse aucun homonyme.
    fn mal_poses_annonces(ligne: &str) -> Option<&str> {
        let (_, queue) = ligne.split_once(MARQUEUR_INDEX_MAL_POSES)?;
        Some(match queue.split_once(MARQUEUR_INDEX_MANQUANTS) {
            Some((tete, _)) => tete.trim().trim_end_matches(';').trim(),
            None => queue.trim(),
        })
    }

    /// La ligne annoncée par la passe, ou `None` sous levier éteint — le silence est alors une
    /// propriété du produit, asserté comme telle et non un test sauté.
    fn ligne_de_la_passe(db: &Arc<Mutex<Connection>>) -> Option<String> {
        let annonce = reconcile_expr_indexes_background(db);
        if !levier_arme() {
            assert!(
                annonce.is_none(),
                "LEVIER {} — la passe a annoncé quelque chose alors qu'elle n'a rien à créer : {annonce:?}",
                regime()
            );
            return None;
        }
        Some(annonce.unwrap_or_else(|| {
            panic!(
                "LEVIER {} — la passe avait du travail et n'a RIEN annoncé. Une passe qui travaille \
                 sans rendre compte est le défaut d'à côté (`P6.8-f`).",
                regime()
            )
        }))
    }

    // ============================================================================================

    /// VALIDATION DE L'INSTRUMENT — UN NOM DÉJÀ PORTÉ PAR UN INDEX REND LA CRÉATION DU PRODUIT
    /// INOPÉRANTE, ET L'OCCUPANT SURVIT.
    ///
    /// Toutes les mutations qui suivent reposent sur ce fait : si `CREATE INDEX IF NOT EXISTS`
    /// remplaçait l'occupant, un homonyme mal posé serait un incident d'un instant que le démarrage
    /// suivant effacerait, et l'accuser serait du bruit. Les DEUX témoins sont joués sur la MÊME
    /// instruction et sur le moteur RÉELLEMENT LIÉ au binaire : sans occupant elle pose l'index sur
    /// `event`, avec occupant l'index de ce nom reste posé ailleurs.
    #[test]
    fn la_creation_du_produit_ne_reprend_pas_un_nom_deja_porte_par_un_index() {
        let champ = *HOT_FIELDS.first().expect("prémisse : la liste chaude n'est pas vide");
        let nom = nom_derive(champ);

        // TÉMOIN NÉGATIF — aucun occupant : la DDL du produit pose bien l'index sur `event`.
        let libre = super::test_db();
        libre.execute(&ddl_de_creation(champ), []).expect("la DDL du produit doit passer sur une base saine");
        assert_eq!(
            table_de_lindex(&libre, &nom).as_deref(),
            Some("event"),
            "TÉMOIN NÉGATIF RÉFUTÉ : la DDL du produit ne pose pas son index sur `event` — les \
             mutations qui suivent ne mesureraient pas ce qu'elles croient"
        );

        // TÉMOIN POSITIF — le nom occupé par un index posé ailleurs : la MÊME instruction laisse
        // l'occupant en place. Le produit ne peut donc pas se réparer tout seul.
        let occupe = super::test_db();
        let accueil = table_daccueil(&occupe);
        poser_homonyme_ailleurs(&occupe, champ, &accueil);
        let _ = occupe.execute(&ddl_de_creation(champ), []);
        assert_eq!(
            table_de_lindex(&occupe, &nom).as_deref(),
            Some(accueil.as_str()),
            "L'INSTRUMENT NE MORD PAS : la DDL du produit a délogé l'occupant du nom `{nom}`. Un \
             homonyme mal posé se réparerait alors tout seul, et le nommer n'apprendrait rien."
        );
    }

    /// LA MUTATION — UN HOMONYME POSÉ SUR UNE AUTRE TABLE N'EST PLUS COMPTÉ PRÉSENT.
    ///
    /// LA VALEUR QUI CHANGE est le compte annoncé : cet objet valait « présent » au seul titre de son
    /// nom, il vaut désormais « posé sur autre chose ». La garde exige les deux faces — que le compte
    /// complet NE soit PAS annoncé, et que l'homonyme soit NOMMÉ avec la table qui le porte — puis
    /// que le catalogue confirme qu'il est toujours là, hors de `event`.
    #[test]
    fn un_homonyme_pose_sur_une_autre_table_nest_pas_compte_present() {
        let champ = *HOT_FIELDS.first().expect("prémisse : la liste chaude n'est pas vide");
        let nom = nom_derive(champ);

        let db = base_migree();
        let accueil = {
            let conn = db.lock();
            let accueil = table_daccueil(&conn);
            poser_homonyme_ailleurs(&conn, champ, &accueil);
            accueil
        };

        let Some(ligne) = ligne_de_la_passe(&db) else {
            // `P11.23-b` — LEVIER ÉTEINT : la passe ne crée rien, donc il n'y a AUCUNE ligne de
            // compte rendu à confronter. Ce test ne peut rien prouver ici et il ne prétend rien ;
            // le refus part par le canal, la suite reste verte.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "un_homonyme_pose_sur_une_autre_table_nest_pas_compte_present",
                &format!(
                    "levier `{LEVIER}` {} : la passe de fond n'annonce aucune création, il n'y a \
                     pas de ligne de compte rendu à confronter — la présence des index n'est pas \
                     éprouvable dans ce régime. Rejouer la suite levier ARMÉ pour l'éprouver.",
                    regime()
                ),
            );
            return;
        };

        let attendus = HOT_FIELDS.len();
        let constates = attendus - 1;
        assert!(
            !ligne.contains(&format!("{attendus}/{attendus}")),
            "LEVIER {} — LE CONSTAT APPARIE ENCORE PAR LE NOM : la ligne annonce {attendus} index sur \
             {attendus} alors que `{nom}` est posé sur « {accueil} » et n'indexe aucun champ de \
             `event`. C'est le défaut P6.8-g dans sa forme exacte. Ligne : {ligne}",
            regime()
        );
        assert!(
            ligne.contains(&format!("{constates}/{attendus}")),
            "LEVIER {} — le compte annoncé n'est pas celui du catalogue : {constates} index sur \
             {attendus} sont conformes. Ligne : {ligne}",
            regime()
        );

        let accuses = mal_poses_annonces(&ligne).unwrap_or_else(|| {
            panic!(
                "LEVIER {} — LA LIGNE NE NOMME PAS L'HOMONYME : elle constate un compte incomplet sans \
                 dire que le nom attendu est OCCUPÉ. « manquant » et « occupé par autre chose » \
                 n'appellent pas le même geste — le premier se répare au démarrage suivant, le second \
                 jamais. Ligne : {ligne}",
                regime()
            )
        });
        assert!(
            accuses.contains(&nom) && accuses.contains(&accueil),
            "LEVIER {} — l'accusation doit NOMMER l'index en cause et la table qui le porte, faute de \
             quoi l'exploitant apprend qu'il y a un trou et pas où. Accusation : {accuses}",
            regime()
        );

        assert_eq!(
            table_de_lindex(&db.lock(), &nom).as_deref(),
            Some(accueil.as_str()),
            "prémisse de la mesure : l'homonyme doit AVOIR SURVÉCU à la passe — c'est ce qui rend son \
             silence d'antan définitif"
        );
    }

    /// LA MUTATION, SECONDE FORME — UN HOMONYME POSÉ SUR LA BONNE TABLE MAIS SUR UNE AUTRE EXPRESSION.
    ///
    /// Sans elle, la garde ne prouverait que la lecture de `tbl_name` : un constat qui se contenterait
    /// de la table resterait vert ici, alors que l'index n'indexe pas le champ déclaré. LA VALEUR QUI
    /// CHANGE est la même — le compte annoncé — mais le seul fait qui la porte est la DÉFINITION.
    #[test]
    fn un_homonyme_sur_une_autre_expression_nest_pas_compte_present() {
        let champ = *HOT_FIELDS.first().expect("prémisse : la liste chaude n'est pas vide");
        let nom = nom_derive(champ);

        let db = base_migree();
        poser_homonyme_sur_une_autre_expression(&db.lock(), champ);
        assert_eq!(
            table_de_lindex(&db.lock(), &nom).as_deref(),
            Some("event"),
            "prémisse : ce témoin doit passer le critère de table, sinon il mesure la même chose que \
             le précédent"
        );

        let Some(ligne) = ligne_de_la_passe(&db) else {
            // `P11.23-b` — LEVIER ÉTEINT : la passe ne crée rien, donc il n'y a AUCUNE ligne de
            // compte rendu à confronter. Ce test ne peut rien prouver ici et il ne prétend rien ;
            // le refus part par le canal, la suite reste verte.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "un_homonyme_sur_une_autre_expression_nest_pas_compte_present",
                &format!(
                    "levier `{LEVIER}` {} : la passe de fond n'annonce aucune création, il n'y a \
                     pas de ligne de compte rendu à confronter — la présence des index n'est pas \
                     éprouvable dans ce régime. Rejouer la suite levier ARMÉ pour l'éprouver.",
                    regime()
                ),
            );
            return;
        };

        let attendus = HOT_FIELDS.len();
        assert!(
            !ligne.contains(&format!("{attendus}/{attendus}")),
            "LEVIER {} — LE CONSTAT NE LIT PAS LA DÉFINITION : `{nom}` est bien sur `event` mais \
             n'indexe pas « {champ} », et la ligne annonce pourtant {attendus} index sur {attendus}. \
             Ligne : {ligne}",
            regime()
        );
        let accuses = mal_poses_annonces(&ligne).unwrap_or_else(|| {
            panic!("LEVIER {} — la ligne ne nomme pas l'homonyme d'expression. Ligne : {ligne}", regime())
        });
        assert!(
            accuses.contains(&nom),
            "LEVIER {} — l'accusation doit nommer `{nom}`. Accusation : {accuses}",
            regime()
        );
    }

    /// LA MUTATION SUR LE COURT-CIRCUIT — LA PASSE NE SORT PLUS SANS RIEN FAIRE.
    ///
    /// LA VALEUR QUI CHANGE est ici le TRAVAIL de la passe, pas un compte : tous les noms attendus
    /// occupés par des homonymes, le constat les disait tous présents, `expr_indexes_all_present`
    /// rendait vrai, et la passe se retirait AVANT toute création en ne rendant RIEN — le silence
    /// exact sur lequel une preuve de production s'était appuyée. Elle travaille désormais, et elle
    /// rend une ligne qui accuse chacun d'eux.
    #[test]
    fn le_court_circuit_ne_sort_plus_quand_tous_les_noms_sont_occupes() {
        let db = base_migree();
        let accueil = {
            let conn = db.lock();
            let accueil = table_daccueil(&conn);
            for champ in HOT_FIELDS {
                poser_homonyme_ailleurs(&conn, champ, &accueil);
            }
            accueil
        };

        let Some(ligne) = ligne_de_la_passe(&db) else {
            // `P11.23-b` — LEVIER ÉTEINT : la passe ne crée rien, donc il n'y a AUCUNE ligne de
            // compte rendu à confronter. Ce test ne peut rien prouver ici et il ne prétend rien ;
            // le refus part par le canal, la suite reste verte.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "le_court_circuit_ne_sort_plus_quand_tous_les_noms_sont_occupes",
                &format!(
                    "levier `{LEVIER}` {} : la passe de fond n'annonce aucune création, il n'y a \
                     pas de ligne de compte rendu à confronter — la présence des index n'est pas \
                     éprouvable dans ce régime. Rejouer la suite levier ARMÉ pour l'éprouver.",
                    regime()
                ),
            );
            return;
        };

        let attendus = HOT_FIELDS.len();
        assert!(
            ligne.contains(&format!("0/{attendus}")),
            "LEVIER {} — AUCUN des {attendus} index déclarés n'est conforme (tous les noms sont portés \
             par des index posés sur « {accueil} ») et la ligne ne l'annonce pas. Ligne : {ligne}",
            regime()
        );
        let accuses = mal_poses_annonces(&ligne).unwrap_or_else(|| {
            panic!("LEVIER {} — la ligne n'accuse aucun homonyme. Ligne : {ligne}", regime())
        });
        for champ in HOT_FIELDS {
            assert!(
                accuses.contains(&nom_derive(champ)),
                "LEVIER {} — « {champ} » n'est pas nommé parmi les mal posés. Accusation : {accuses}",
                regime()
            );
        }
    }

    /// LE TÉMOIN INVERSE — CE QUE LE PRODUIT CRÉE RESTE COMPTÉ PRÉSENT.
    ///
    /// Sans lui, tout ce qui précède prouverait seulement qu'on sait rejeter. Il vaut EN OUTRE
    /// confrontation ANTI-NO-OP, et c'est sa seconde raison d'être : le constat attend une table et un
    /// chemin JSON qu'il n'obtient pas de la DDL du produit mais de constantes qui lui sont propres.
    /// Si l'une des deux cessait de correspondre à ce que la passe écrit, CHAQUE index créé serait
    /// déclaré mal posé, le court-circuit ne se prendrait plus jamais et la passe rejouerait ses
    /// créations à chaque démarrage — ce test rougit alors au lieu de laisser dériver.
    #[test]
    fn les_index_que_le_produit_cree_restent_comptes_presents() {
        let db = base_migree();
        let Some(ligne) = ligne_de_la_passe(&db) else {
            // `P11.23-b` — LEVIER ÉTEINT : la passe ne crée rien, donc il n'y a AUCUNE ligne de
            // compte rendu à confronter. Ce test ne peut rien prouver ici et il ne prétend rien ;
            // le refus part par le canal, la suite reste verte.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "les_index_que_le_produit_cree_restent_comptes_presents",
                &format!(
                    "levier `{LEVIER}` {} : la passe de fond n'annonce aucune création, il n'y a \
                     pas de ligne de compte rendu à confronter — la présence des index n'est pas \
                     éprouvable dans ce régime. Rejouer la suite levier ARMÉ pour l'éprouver.",
                    regime()
                ),
            );
            return;
        };

        let attendus = HOT_FIELDS.len();
        assert!(
            ligne.contains(&format!("{attendus}/{attendus}")),
            "LEVIER {} — LE CONSTAT REFUSE CE QUE LE PRODUIT CRÉE : la passe a posé ses {attendus} \
             index et la ligne n'en constate pas autant. L'attente du constat (table, chemin JSON) a \
             cessé de correspondre à la DDL de la passe. Ligne : {ligne}",
            regime()
        );
        assert!(
            mal_poses_annonces(&ligne).is_none(),
            "LEVIER {} — LA LIGNE ACCUSE À VIDE : aucun nom n'est occupé et elle nomme pourtant des \
             mal posés. Ligne : {ligne}",
            regime()
        );
        assert!(
            !ligne.contains(MARQUEUR_INDEX_MANQUANTS),
            "LEVIER {} — la ligne accuse des manquants alors que tout a été créé. Ligne : {ligne}",
            regime()
        );

        assert!(
            reconcile_expr_indexes_background(&db).is_none(),
            "LEVIER {} — la seconde passe a travaillé alors que tous les index étaient conformes : le \
             court-circuit ne se prend plus, donc le constat refuse ce que le produit vient de poser",
            regime()
        );
    }
}
