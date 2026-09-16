// =====================================================================================
// `P10.20-i` — UNE `meta` SANS SA LIGNE DE VERSION, SUR UN FICHIER QUI PORTE UN SCHÉMA, EST REFUSÉE.
//
// LA QUESTION DE LA CLÉ, ET CE QUE LA MESURE Y RÉPOND (2026-09-16). « Cette forme legacy existe-t-elle
// encore quelque part — quel contrat l'a créée, une base réelle peut-elle encore la porter ? »
// Mesuré sur l'arbre : AUCUN contrat de ce dépôt ne la PRODUIT. `db/schema.sql` crée la table `meta`
// et pose `('schema_version','1')` dans le MÊME lot, à deux lignes d'écart, et il en est ainsi depuis
// la publication initiale du dépôt ; `prepare_schema` rejoue ce lot AVANT toute migration, à chaque
// démarrage ; aucune étape `migrate_vN` ne crée `meta` sans sa ligne ; et le seul
// `DELETE FROM meta WHERE key='schema_version'` de tout l'arbre est celui d'un TÉMOIN
// (`legacy_meta_without_a_version_row_is_recovered_by_the_contract`). Il n'y a donc pas de « version
// minimale du démon qui aurait posé la ligne » : elle a toujours été posée par le même lot que la
// table.
//
// CE QUE CELA CHANGE POUR LA DÉCISION. Un fichier qui porte un schéma ET pas sa ligne n'est pas une
// entrée legacy à rattraper : c'est un fichier ABÎMÉ (ligne effacée à la main, restauration
// partielle, page corrompue) dont la version est INCONNUE. Le « rattrapage » que le dépôt écrivait —
// `INSERT OR IGNORE … '1'` de `db/schema.sql` — ne rétablit pas une vérité, il en FABRIQUE une, et
// « 1 » est la pire des valeurs possibles : c'est celle d'une base FRAÎCHE, la seule pour laquelle
// la chaîne entière est faite pour se rejouer. Le prix est chiffré plus bas, sur le contrat.
//
// L'AUTRE ISSUE A ÉTÉ PESÉE ET REFUSÉE, ET LA RAISON EST DANS LE DÉPÔT. « Rattraper par une preuve
// écrite : le catalogue atteste la version courante » supposerait que la forme du fichier atteste ce
// que la chaîne a fait. Elle ne l'atteste pas : le contrôle de forme du produit (`schema_gaps` /
// `declared_shape`) ne regarde que tables, vues, triggers et colonnes — jamais les index, et jamais
// les LIGNES posées par une étape, ce qu'un témoin du dépôt fige explicitement
// (`step_rows_are_outside_the_perimeter_and_it_is_written_down`). Or les étapes destructrices de
// cette chaîne sont exactement des opérations sur des LIGNES (purges de sources one-time, `banned_ip`
// de source 'ufw', panneau retiré, `event_rollup` reconstruit, `host_rollup` rebâti à blanc). Une
// forme complète ne prouverait donc RIEN sur elles, et estampiller la base à la tête sur cette base-là
// serait inventer une estampille — la faute même que `P10.20-f` a fermée, refaite un cran plus loin.
//
// CE QUI EST FAIT : la ligne absente se juge sur LE CATALOGUE, comme la table absente. `meta` SEULE au
// catalogue -> il n'y a aucun schéma à détruire, la chaîne peut repartir de un, c'est la forme legacy
// et elle OUVRE. `meta` à côté d'un schéma -> `EstampilleDeSchema::NonLue`, MÊME phrase de tête
// (`CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE`), MÊME sauvegarde nommée, refus AVANT toute écriture. La cause
// écrite, elle, reste DISTINCTE : l'absence est ÉTABLIE, et la dire « pas lue » enverrait chercher une
// panne de lecture qui n'existe pas.
//
// D'OÙ VIENNENT CES TÉMOINS. Le premier et le troisième reprennent
// `p10_20f_la_forme_legacy_sans_ligne_reste_ouverte_et_son_prix_est_mesure`, qui vivait dans
// `estampille_de_schema_a_l_ouverture.rs` : sa moitié « la porte ouvre » est devenue fausse, sa moitié
// « voici le prix » reste la JUSTIFICATION du refus et continue d'être jouée — sur le CONTRAT, puisque
// la porte n'y mène plus. Les fixtures de ce fichier-là sont EMPRUNTÉES (préfixe `eso_`), jamais
// recopiées : deux fixtures jumelles finissent par diverger, et le jour où l'une apprend quelque chose
// l'autre ment.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils ne jouent pas le code de sortie du processus (le refus est
// jugé sur la lecture typée et sur le texte, pas sur `exit`) ; ils ne disent rien d'une base
// MULTI-TENANT dont une seule base de tenant porterait cette forme (la porte est la même, le chemin
// d'appel n'est pas joué) ; et le refus n'est pas peint par la console — un démon qui refuse de
// démarrer ne sert aucune route.
// =====================================================================================
mod meta_sans_ligne_de_version_sur_une_base_qui_porte_un_schema {
    use super::*;

    /// Le nombre d'objets que le fichier porte au catalogue — le discriminant lui-même, relu ici par
    /// le témoin au lieu d'être supposé.
    fn msl_objets_au_catalogue(p: &str) -> i64 {
        crate::db_open::open_db(p)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'", [], |r| r.get(0))
            .unwrap()
    }

    /// La ligne de version existe-t-elle ? Lisible après un refus, pour prouver qu'il n'a rien reposé.
    fn msl_la_ligne_existe(p: &str) -> bool {
        crate::db_open::open_db(p)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM meta WHERE key='schema_version'", [], |r| r.get::<_, i64>(0))
            .unwrap()
            > 0
    }

    fn msl_retirer_la_ligne(p: &str) {
        let c = crate::db_open::open_db(p).unwrap();
        c.execute("DELETE FROM meta WHERE key='schema_version'", []).expect("fixture : la ligne se retire");
    }

    // -------------------------------------------------------------------------------------
    // (1) LA BASE MIGRÉE DONT LA LIGNE MANQUE — REFUS, ET ELLE RESSORT INTACTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sur une base migrée et PEUPLÉE dont la ligne `schema_version` a été retirée,
    /// la lecture d'ouverture rend `NonLue`, la garde rend `EstampilleNonLue`, et la porte REFUSE avec
    /// la phrase ENTIÈRE (même cause de tête, clé au repos d'abord, sauvegarde nommée ensuite, « aucune
    /// écriture effectuée ») ; l'inventaire ressort IDENTIQUE, `db/schema.sql` n'a pas été rejoué
    /// (aucune table `meta` neuve à côté), et la ligne est TOUJOURS absente — le refus n'a rien reposé.
    /// Contrôle positif compté dans le même corps : la même base, avant qu'on retire la ligne, s'ouvre
    /// et ne perd rien.
    ///
    /// CE QU'IL NE TIENT PAS : il ne joue pas le code de sortie du démon, et il ne dit rien du chemin
    /// multi-tenant.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre `Ok(None) => EstampilleDeSchema::JamaisEstampillee`
    /// inconditionnel (la forme d'avant `P10.20-i`) — la porte rouvre, la chaîne se rejoue, et les cinq
    /// assertions du bloc de refus tombent.
    #[test]
    fn p10_20i_une_base_migree_dont_la_ligne_de_version_manque_est_refusee_et_ressort_intacte() {
        let (_t, p) = eso_base_migree("msl-refus");
        eso_semer(&p);

        // CONTRÔLE POSITIF — tant que la ligne est là, la porte ouvre et l'inventaire ne bouge pas.
        let avant = eso_inventaire(&p);
        assert!(avant.iter().all(|(_, n)| *n >= 1), "fixture : tout l'inventaire est posé : {avant:?}");
        drop(crate::db_open::PreparedDb::open(&p).expect("contrôle positif : base SAINE, la porte ouvre"));
        assert_eq!(eso_inventaire(&p), avant, "contrôle positif : une ouverture saine ne touche à rien");
        let metas_avant = eso_tables_meta(&p);

        msl_retirer_la_ligne(&p);
        let objets = msl_objets_au_catalogue(&p);
        assert!(objets > 50, "précondition : ce fichier porte bien un schéma ({objets} objets)");

        // LA LECTURE TYPÉE, PUIS LA GARDE, PUIS LA PORTE — les trois étages disent la même chose.
        {
            let c = crate::db_open::open_db(&p).unwrap();
            match lire_l_estampille_de_schema(&c) {
                EstampilleDeSchema::NonLue(cause) => {
                    assert!(cause.contains("ne porte AUCUNE ligne"), "la cause dit l'absence ÉTABLIE : {cause}");
                    assert!(
                        cause.contains(&format!("{objets} objet(s)")),
                        "et elle COMPTE ce que le fichier porte, au lieu de l'affirmer : {cause}"
                    );
                }
                EstampilleDeSchema::JamaisEstampillee => {
                    panic!("une base qui porte un schéma n'est PAS une forme legacy rattrapable")
                }
                EstampilleDeSchema::Lue(v) => panic!("aucune version ne peut être lue ici : {v}"),
                EstampilleDeSchema::BaseNeuve => panic!("ce n'est pas une base neuve"),
            }
            assert!(
                matches!(schema_downgrade_guard(&c), Err(RefusDOuverture::EstampilleNonLue(_))),
                "la garde d'ouverture REFUSE"
            );
        }

        let refus = eso_refus(&p);
        eso_le_refus_est_complet(&refus, "ligne de version RETIRÉE sur une base migrée");
        assert_eq!(eso_inventaire(&p), avant, "la base ressort INTACTE du refus");
        assert_eq!(eso_tables_meta(&p), metas_avant, "`db/schema.sql` n'a pas été rejoué");
        assert!(!msl_la_ligne_existe(&p), "et le refus n'a RIEN reposé — pas même la ligne manquante");
    }

    // -------------------------------------------------------------------------------------
    // (2) LE DISCRIMINANT JUGÉ DANS L'AUTRE SENS — `meta` SEULE OUVRE TOUJOURS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un fichier qui ne porte QUE la table `meta`, vide, reste la forme legacy —
    /// `JamaisEstampillee`, garde à un, la porte OUVRE, le contrat repose la ligne et migre jusqu'à la
    /// tête. C'est l'autre sens du discriminant : le refus du témoin (1) tient au SCHÉMA que le fichier
    /// porte, pas à l'absence de la ligne, et sans ce bloc un refus INCONDITIONNEL passerait pour une
    /// mesure.
    ///
    /// CE QU'IL NE TIENT PAS : il ne prétend pas que cette forme existe en exploitation — la mesure dit
    /// l'inverse (aucun contrat ne la produit). Il tient que la porte ne s'est pas RESSERRÉE sur un
    /// fichier qu'elle acceptait et qui n'a rien à perdre.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : refuser dès que la ligne manque, sans interroger le catalogue
    /// — ce bloc tombe entier, et c'est le sens dans lequel un correctif trop large se voit.
    #[test]
    fn p10_20i_un_fichier_qui_ne_porte_que_meta_reste_une_forme_legacy_et_s_ouvre() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("msl-meta-seule");
        let p = tmp.sous("plume.db").chemin().to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&p);
        {
            let c = crate::db_open::open_db(&p).unwrap();
            c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);").unwrap();
        }
        assert_eq!(msl_objets_au_catalogue(&p), 1, "ce fichier ne porte QUE `meta` (son auto-index est interne)");
        assert!(!msl_la_ligne_existe(&p), "précondition : et `meta` est vide");

        {
            let c = crate::db_open::open_db(&p).unwrap();
            assert!(
                matches!(lire_l_estampille_de_schema(&c), EstampilleDeSchema::JamaisEstampillee),
                "rien à détruire : c'est bien la forme legacy, et elle reste une absence ÉTABLIE"
            );
            assert_eq!(schema_downgrade_guard(&c), Ok(1), "la garde l'ouvre en v1");
        }
        let db = crate::db_open::PreparedDb::open(&p).expect("forme legacy : la porte OUVRE");
        assert_eq!(read_schema_version(&db), CODE_SCHEMA_MAX, "le contrat repose la ligne et remonte à la tête");
    }

    // -------------------------------------------------------------------------------------
    // (3) LE PRIX DU RATTRAPAGE — CHIFFRÉ SUR LE CONTRAT, PUISQUE LA PORTE N'Y MÈNE PLUS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : ce que le refus du témoin (1) ÉVITE, mesuré et non annoncé. Le contrat de boot
    /// (`prepare_schema`), appelé DIRECTEMENT sur une base migrée et peuplée dont la ligne a été
    /// retirée, repose la ligne à « 1 » et rejoue la chaîne : au moins cinq lignes d'inventaire
    /// changent. C'est la moitié utile de l'ancien témoin de `P10.20-f`, gardée telle quelle — si
    /// quelqu'un rouvre cette voie un jour, c'est ce chiffre-là qu'il faudra relire.
    ///
    /// CE QU'IL NE TIENT PAS : il ne passe PAS par la porte (c'est tout le sujet) ; il ne dit donc rien
    /// de ce qu'un démarrage réel ferait aujourd'hui — le témoin (1) le dit, et la réponse est « il
    /// refuse ».
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : rendre la chaîne idempotente sur ces cinq lignes — le refus
    /// perdrait sa justification, et ce témoin dirait qu'il est temps de la rediscuter.
    #[test]
    fn p10_20i_le_prix_du_rattrapage_reste_chiffre_sur_le_contrat_que_la_porte_n_atteint_plus() {
        let (_t, p) = eso_base_migree("msl-prix");
        eso_semer(&p);
        let avant = eso_inventaire(&p);
        msl_retirer_la_ligne(&p);

        {
            let c = crate::db_open::open_db(&p).unwrap();
            assert!(prepare_schema(&c).is_ok(), "le CONTRAT, lui, rattrape toujours : il repose la ligne et migre");
            assert_eq!(read_schema_version(&c), CODE_SCHEMA_MAX, "et il remonte la base à la tête");
        }

        let apres = eso_inventaire(&p);
        let touchees: Vec<&str> = avant
            .iter()
            .zip(apres.iter())
            .filter(|((_, a), (_, b))| a != b)
            .map(|((n, _), _)| *n)
            .collect();
        assert!(
            touchees.len() >= 5,
            "CE QUE LE REFUS ÉVITE : le rattrapage rejoue la chaîne et touche l'inventaire — \
             avant {avant:?} / après {apres:?} (touchées : {touchees:?})"
        );
    }
}
