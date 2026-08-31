// ================================================================================================
// P6.8-e — UN CHAMP RETIRÉ DE LA LISTE CHAUDE NE LAISSE PLUS SON INDEX À VIE
// ================================================================================================
// LE DÉFAUT, DANS SA FORME EXACTE. Le réconciliateur ne droppe que les noms qu'il DÉRIVE de la liste
// COURANTE des champs chauds. Retirer un champ de cette liste retire donc, du même geste, la seule
// chose qui savait NOMMER son index : celui-ci reste sur toute base déjà déployée, payé en disque ET
// en écriture d'arbre PAR LIGNE INGÉRÉE, et même l'interrupteur qui éteint la famille entière ne
// l'atteint pas, puisqu'il énumère lui aussi depuis la liste courante. La garde `P6.8-d` avait
// PROUVÉ cette survie ; elle rendait l'introduction d'un tel orphelin impossible en intégration
// continue, elle ne nettoyait aucune base qui en porterait déjà un.
//
// LE REMÈDE EST CELUI DE LA FAMILLE VOISINE. `drop_orphan_auto_field_indexes_background` décrit
// exactement ce mode d'échec pour le préfixe `idx_ev_auto_*` : un index que plus aucun code ne
// maintient ni ne peut retirer. `drop_orphan_expr_field_indexes` en est le symétrique pour
// `idx_ev_f_*`, et son critère est le PRÉFIXE — le seul qui SURVIVE au retrait d'un champ, puisque
// la liste, elle, vient de perdre le nom.
//
// LES DEUX SENS, ET SANS LE SECOND ON NE PROUVERAIT QUE SAVOIR TOUT EFFACER. Un index de la famille
// dont le champ n'est plus déclaré doit DISPARAÎTRE ; un index de la famille dont le champ EST
// déclaré doit SURVIVRE. Un objet qui n'est pas un index et qui porte un nom de la famille survit
// lui aussi : la purge est INCONDITIONNELLE, sa prudence tient donc entièrement à son critère.
//
// LE PIÈGE DU LEVIER, TRANCHÉ DANS LE PRODUIT ET VÉRIFIÉ ICI. La purge tourne dans les DEUX régimes
// de `PLUME_EXPRINDEX`, et elle est appelée AVANT que le levier ne soit lu. Un retrait qui n'aurait
// lieu que sous levier armé abandonnerait à jamais les orphelins d'une installation qui a ÉTEINT la
// famille — celle-là même qui ne veut plus payer un seul de ces index. La conséquence est vérifiée
// des deux façons possibles sans écrire dans l'environnement du processus : la mutation passe par le
// VRAI point d'entrée quel que soit le régime ambiant (elle n'a donc pas de branche à sauter), et
// l'ordre des deux gestes dans la passe est confronté au texte du produit.
//
// AUCUN NOM INVENTÉ N'EST ÉCRIT ICI. L'orphelin est fabriqué à partir de la déclaration elle-même —
// la concaténation de toutes ses entrées n'est aucune d'elles, et cette propriété est ASSERTÉE, pas
// espérée. Et la confrontation du préfixe au produit ne retrouve pas les index créés par leur NOM,
// ce qui serait circulaire, mais par l'EXPRESSION qu'ils portent.

#[cfg(test)]
mod index_de_champ_chaud_orphelin {
    use crate::maintenance::{drop_orphan_expr_field_indexes, reconcile_expr_indexes_background};
    use crate::soql_glue::HOT_FIELDS;
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::sync::Arc;

    /// La règle de nommage de la famille, telle que le produit l'applique — confrontée à ce qu'il
    /// CRÉE par `le_prefixe_de_la_famille_couvre_les_index_que_le_produit_cree`.
    const PREFIXE_FAMILLE: &str = "idx_ev_f_";

    /// Le levier qui gouverne la famille, et sa valeur par défaut, tels que le produit les écrit.
    const LEVIER: &str = "PLUME_EXPRINDEX";
    const LEVIER_DEFAUT: &str = "1";

    /// Le fichier du réconciliateur et les deux gestes dont l'ORDRE est le sujet.
    const FICHIER_RECONCILIATEUR: &str = "maintenance.rs";
    const SIGNATURE_DE_LA_PASSE: &str = "pub(crate) fn reconcile_expr_indexes_background";
    const APPEL_DU_RETRAIT: &str = "drop_orphan_expr_field_indexes(";

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

    /// La DDL du produit pour un champ — index d'expression PARTIEL sur `event`.
    fn ddl_de_creation(champ: &str) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON event(json_extract(fields,'$.{champ}')) \
             WHERE json_extract(fields,'$.{champ}') IS NOT NULL",
            nom_derive(champ)
        )
    }

    fn objet_existe(conn: &Connection, type_sqlite: &str, nom: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2",
            rusqlite::params![type_sqlite, nom],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// UN CHAMP QUE LA DÉCLARATION NE PEUT PAS PRODUIRE, CONSTRUIT À PARTIR D'ELLE. La concaténation
    /// de toutes les entrées n'est aucune d'elles — la propriété est ASSERTÉE, pas espérée. Aucun nom
    /// inventé n'est donc écrit dans ce fichier, pas même celui du témoin.
    fn champ_hors_declaration() -> String {
        let concat = HOT_FIELDS.concat();
        assert!(
            !HOT_FIELDS.contains(&concat.as_str()),
            "prémisse du témoin : la concaténation de la liste chaude ne doit pas être elle-même une \
             entrée de la liste (sinon l'orphelin fabriqué serait un index légitime)"
        );
        concat
    }

    fn base_migree() -> Arc<Mutex<Connection>> {
        Arc::new(Mutex::new(super::test_db()))
    }

    /// LES INDEX QUE LE PRODUIT A CRÉÉS POUR UN CHAMP, RETROUVÉS PAR L'EXPRESSION QU'ILS PORTENT —
    /// jamais par leur nom. Chercher par le nom reviendrait à confronter le préfixe à lui-même.
    fn index_portant_l_expression(conn: &Connection, champ: &str) -> Vec<String> {
        let motif = format!("%'$.{}'%", champ.replace('\\', "\\\\").replace('_', "\\_").replace('%', "\\%"));
        let mut st = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='event' \
                   AND sql LIKE ?1 ESCAPE '\\' ORDER BY name",
            )
            .expect("catalogue des index lisible");
        let it = st
            .query_map(rusqlite::params![motif], |r| r.get::<_, String>(0))
            .expect("catalogue des index lisible");
        it.map(|r| r.expect("nom d'index lisible")).collect()
    }

    fn source_du_reconciliateur() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(FICHIER_RECONCILIATEUR),
        )
        .unwrap_or_else(|e| panic!("{FICHIER_RECONCILIATEUR} lisible : {e}"))
    }

    // ============================================================================================

    /// LA MUTATION — UN INDEX DE LA FAMILLE DONT LE CHAMP N'EST PLUS DÉCLARÉ DISPARAÎT AU DÉMARRAGE.
    ///
    /// LA VALEUR QUI CHANGE est la présence de cet index au catalogue : elle valait « présent pour
    /// toujours » — la garde `P6.8-d` le prouvait en le voyant survivre au kill-switch — elle vaut
    /// désormais « absent après la passe de fond ». Le geste est exercé par le VRAI point d'entrée du
    /// démarrage, et non par la fonction de retrait prise à part : c'est le câblage qui manquait.
    ///
    /// Aucune branche à sauter selon le régime : la purge précédant la lecture du levier, l'attente
    /// est la MÊME dans les deux, et le régime ambiant est néanmoins NOMMÉ dans le verdict.
    #[test]
    fn un_index_de_la_famille_sans_champ_declare_disparait_au_demarrage() {
        let champ = champ_hors_declaration();
        let orphelin = nom_derive(&champ);

        let db = base_migree();
        db.lock().execute(&ddl_de_creation(&champ), []).expect("création de l'index témoin");
        assert!(
            objet_existe(&db.lock(), "index", &orphelin),
            "prémisse : sans orphelin au catalogue, la mutation ne mesurerait rien"
        );

        reconcile_expr_indexes_background(&db);

        assert!(
            !objet_existe(&db.lock(), "index", &orphelin),
            "LEVIER {} — `{orphelin}` A SURVÉCU AU DÉMARRAGE. Son champ n'est plus déclaré : ni le \
             réconciliateur synchrone ni le kill-switch ne savent le nommer, et la purge voisine ne \
             connaît que la famille `idx_ev_auto_*`. Il resterait sur toute base vivante, payé en \
             disque et en écriture d'arbre à chaque ligne ingérée, sans que plus personne puisse le \
             retirer.",
            regime()
        );
    }

    /// LE TÉMOIN INVERSE — UN INDEX DE LA FAMILLE DONT LE CHAMP EST DÉCLARÉ SURVIT AU MÊME PASSAGE.
    ///
    /// Sans lui, la mutation prouverait seulement qu'on sait tout effacer : une purge qui dropperait
    /// la famille entière la passerait.
    ///
    /// POURQUOI CE TÉMOIN N'EMPRUNTE PAS LE POINT D'ENTRÉE, ALORS QUE LA MUTATION LE FAIT. Sous
    /// levier armé, la passe CRÉE juste après avoir purgé : une purge trop large y serait MASQUÉE par
    /// la re-création, et ce témoin resterait vert en ne mesurant rien. Le critère est donc éprouvé
    /// là où il vit, en UN SEUL passage portant DEUX index de la MÊME famille — l'un déclaré, l'autre
    /// non — dont les issues doivent être opposées. Le passage rend en outre la liste de ce qu'il a
    /// retiré : on exige qu'elle soit EXACTEMENT l'orphelin, ce qui interdit aussi bien la purge trop
    /// large que le no-op.
    #[test]
    fn un_index_de_la_famille_dont_le_champ_est_declare_survit() {
        let champ_declare = *HOT_FIELDS.first().expect("prémisse : la liste chaude n'est pas vide");
        let declare = nom_derive(champ_declare);
        let champ_orphelin = champ_hors_declaration();
        let orphelin = nom_derive(&champ_orphelin);

        let conn = super::test_db();
        conn.execute(&ddl_de_creation(champ_declare), []).expect("création de l'index déclaré");
        conn.execute(&ddl_de_creation(&champ_orphelin), []).expect("création de l'orphelin");
        assert!(
            objet_existe(&conn, "index", &declare) && objet_existe(&conn, "index", &orphelin),
            "prémisse : les deux index de la famille sont au catalogue avant le passage"
        );

        let retires = drop_orphan_expr_field_indexes(&conn);

        assert_eq!(
            retires,
            vec![orphelin.clone()],
            "LE CRITÈRE DU RETRAIT N'EST PLUS « DE LA FAMILLE ET HORS DÉCLARATION ». Retirés : \
             {retires:?}. Attendu : le seul `{orphelin}` — `{declare}` porte un champ DÉCLARÉ et doit \
             survivre, faute de quoi chaque démarrage détruirait les index qu'il vient de promettre."
        );
        assert!(
            objet_existe(&conn, "index", &declare),
            "L'INDEX DU CHAMP DÉCLARÉ `{declare}` A DISPARU du catalogue"
        );
        assert!(
            !objet_existe(&conn, "index", &orphelin),
            "L'ORPHELIN `{orphelin}` EST ANNONCÉ RETIRÉ MAIS IL EST ENCORE AU CATALOGUE : le geste \
             rend compte de ce qu'il n'a pas fait"
        );
    }

    /// LA PRUDENCE D'UN GESTE INCONDITIONNEL — UN OBJET QUI N'EST PAS UN INDEX N'EST PAS TOUCHÉ.
    ///
    /// La purge tourne à chaque démarrage, dans les deux régimes du levier : elle ne peut donc pas se
    /// contenter d'un motif de nom. Un homonyme d'un AUTRE type (ici une table) est laissé en place,
    /// et son existence ne fait pas non plus échouer la passe.
    #[test]
    fn un_objet_homonyme_qui_n_est_pas_un_index_survit() {
        let champ = champ_hors_declaration();
        let homonyme = nom_derive(&champ);

        let db = base_migree();
        db.lock().execute(&format!("CREATE TABLE {homonyme} (x)"), []).expect("création de l'homonyme");

        reconcile_expr_indexes_background(&db);

        assert!(
            objet_existe(&db.lock(), "table", &homonyme),
            "LEVIER {} — LA PURGE A TOUCHÉ UN OBJET QUI N'EST PAS UN INDEX. Son critère ne filtre \
             plus sur `type='index'` : un geste inconditionnel qui se fie au seul nom finit par \
             retirer ce qu'il n'a jamais créé.",
            regime()
        );
    }

    /// LE PIÈGE DU LEVIER, VÉRIFIÉ DANS LE TEXTE DU PRODUIT — LE RETRAIT PRÉCÈDE LA LECTURE DU LEVIER.
    ///
    /// La décision est écrite dans le produit : le retrait est INCONDITIONNEL, faute de quoi une
    /// installation ayant éteint la famille garderait ses orphelins pour toujours. Cette décision ne
    /// tient qu'à un ORDRE — la lecture du levier ouvre une sortie anticipée — et un ordre ne se
    /// prouve pas en observant le seul régime sous lequel la suite tourne. On le confronte donc au
    /// texte, dans le CORPS de la passe et nulle part ailleurs, avec les deux repères asserté
    /// présents : une garde qui ne trouverait ni l'un ni l'autre serait verte en étant aveugle.
    #[test]
    fn le_retrait_des_orphelins_precede_la_lecture_du_levier() {
        let source = source_du_reconciliateur();
        let debut = source.find(SIGNATURE_DE_LA_PASSE).unwrap_or_else(|| {
            panic!(
                "LA PASSE A CHANGÉ DE NOM : `{FICHIER_RECONCILIATEUR}` ne porte plus \
                 `{SIGNATURE_DE_LA_PASSE}`. Cette garde lirait le mauvais corps."
            )
        });
        let corps = &source[debut..];
        let fin = corps.find("\n}\n").unwrap_or_else(|| panic!("fin du corps de la passe introuvable"));
        let corps = &corps[..fin];

        let i_retrait = corps.find(APPEL_DU_RETRAIT).unwrap_or_else(|| {
            panic!(
                "LA PASSE N'APPELLE PLUS LE RETRAIT DES ORPHELINS : `{APPEL_DU_RETRAIT}` est absent \
                 de son corps. Un champ retiré de la liste chaude laisserait de nouveau son index à \
                 vie, et les deux témoins ci-dessus deviendraient les seuls à en parler."
            )
        });
        let i_levier = corps.find(LEVIER).unwrap_or_else(|| {
            panic!(
                "LA PASSE NE LIT PLUS `{LEVIER}` : le repère qui borne cette garde a disparu, elle ne \
                 mesure donc plus l'ordre qu'elle prétend tenir."
            )
        });

        assert!(
            i_retrait < i_levier,
            "LE RETRAIT DES ORPHELINS EST PASSÉ DERRIÈRE LA LECTURE DU LEVIER. Cette lecture ouvre \
             une sortie anticipée : le retrait ne tournerait plus que `{LEVIER}` armé, et une \
             installation qui a ÉTEINT la famille — celle qui ne veut plus payer un seul de ces \
             index — garderait ses orphelins pour toujours, sans que rien ne sache plus les nommer."
        );
    }

    /// ANTI-FAUX-VERT — LE PRÉFIXE DONT LA PURGE DÉRIVE SON PÉRIMÈTRE EST CELUI QUE LE PRODUIT CRÉE.
    ///
    /// Toute la purge repose sur un préfixe. S'il cessait de correspondre à ce que le produit crée,
    /// elle deviendrait un no-op SILENCIEUX : plus rien à énumérer, aucune erreur, et les orphelins
    /// reviendraient sans qu'un test rougisse. On ne lit pas la source pour l'écarter : on fait
    /// tourner la passe sur une base migrée et on exige que chaque index créé porte ce préfixe — les
    /// index étant retrouvés par l'EXPRESSION qu'ils portent, jamais par leur nom, faute de quoi la
    /// confrontation serait circulaire.
    #[test]
    fn le_prefixe_de_la_famille_couvre_les_index_que_le_produit_cree() {
        assert!(!HOT_FIELDS.is_empty(), "prémisse : la déclaration des champs chauds est vide");

        let db = base_migree();
        reconcile_expr_indexes_background(&db);
        let conn = db.lock();

        if !levier_arme() {
            // Levier éteint : la passe ne crée rien, il n'y a aucun nom à confronter. On le DIT — et
            // la purge reste éprouvée par la mutation, qui ne dépend pas du régime.
            // `P11.23-b` — « On le DIT » était FAUX du point de vue de celui qui décide : `libtest`
            // avale la sortie d'un test qui réussit (mesuré : 0 occurrence sous `cargo test` nu).
            // L'aveu part désormais par le canal, que l'appelant relit après la suite.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "le_prefixe_de_la_famille_couvre_les_index_que_le_produit_cree",
                &format!(
                    "[P6.8-e] levier `{LEVIER}` ÉTEINT : la passe ne crée aucun index, il n'y a \
                     aucun nom à confronter au préfixe de famille. La purge, elle, reste éprouvée \
                     par la mutation (indépendante du régime). Rejouer la suite levier ARMÉ."
                ),
            );
            return;
        }

        let mut vus = 0usize;
        for champ in HOT_FIELDS {
            let crees = index_portant_l_expression(&conn, champ);
            assert!(
                !crees.is_empty(),
                "prémisse : la passe doit avoir créé l'index d'expression de « {champ} » — sans lui, \
                 il n'y a rien à confronter au préfixe"
            );
            for nom in crees {
                assert!(
                    nom.starts_with(PREFIXE_FAMILLE),
                    "LE PRODUIT CRÉE HORS DU PÉRIMÈTRE DE LA PURGE : l'index `{nom}` porte \
                     l'expression du champ déclaré « {champ} » mais ne commence pas par \
                     `{PREFIXE_FAMILLE}`. La purge des orphelins énumère sur ce préfixe : elle ne \
                     verrait jamais cet index, et redeviendrait un no-op silencieux le jour où le \
                     champ quitterait la déclaration."
                );
                vus += 1;
            }
        }
        assert!(vus >= HOT_FIELDS.len(), "prémisse : au moins un index confronté par champ déclaré");
    }
}
