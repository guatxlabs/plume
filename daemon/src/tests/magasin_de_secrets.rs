    // ================================================================================================
    // P9.8-a — UN MAGASIN DE SECRETS QUI NE PEUT PLUS SERVIR ÉTEINT LA ROTATION DES CLÉS, ET IL LE DIT.
    //
    // CE QUI A ÉTÉ PAYÉ EN VRAI. Un coffre scellé plusieurs jours a bloqué VINGT-SEPT secrets externes
    // de tous les espaces d'un cluster — émetteur de certificats, fournisseur d'identité, tunnel
    // d'entrée, pare-feu applicatif. Deux certificats ne se sont pas renouvelés pendant un mois, dont
    // celui du portail d'authentification, à seize heures de son expiration. Le démon, lui, servait
    // normalement : il tourne avec les secrets déjà injectés. RIEN ne l'a dit.
    //
    // CE QUE CES TESTS ÉTABLISSENT, DANS CET ORDRE :
    //   1. `mds_un_magasin_arrete_leve_une_alerte_et_une_seule` — LA LEVÉE, et la portée : le signal
    //      porte sur le MAGASIN. Vingt-sept consommateurs bloqués ne font toujours qu'UNE alerte, et
    //      un second tick n'en ouvre pas une deuxième.
    //   2. `mds_temoin_inverse_un_magasin_qui_sert_ne_leve_rien` — LE TÉMOIN NÉGATIF. Sans lui, une
    //      sonde qui alerte TOUJOURS passerait pour une réussite.
    //   3. `mds_le_signal_se_resout_quand_l_approvisionnement_repart` — l'ATTENDU de la cellule : un
    //      seul relevé « prêt » résout l'épisode et LIBÈRE la clé.
    //   4. `mds_un_releve_isole_ne_leve_ni_ne_resout` — LA MUTATION QUI NOMME LA VALEUR : le nombre de
    //      relevés passe de 1 à 2 et c'est CE nombre, et lui seul, qui fait basculer le verdict.
    //   5. `mds_unanimite_exigee_pour_lever` — un seul relevé sain dans la fenêtre suffit à interdire
    //      la levée. Mutation dans les deux sens sur la MÊME base.
    //   6. `mds_rien_de_rapporte_ne_conclut_rien` — l'installation sans magasin (ou dont le capteur
    //      n'est pas déployé) ne lève rien ET ne résout rien : le silence de ce signal ne vaut pas
    //      « l'approvisionnement va bien ».
    //   7. `mds_hors_fenetre_ne_compte_pas` — un vieux relevé ne fabrique pas un verdict d'aujourd'hui.
    //   8. `mds_lecture_impossible_est_avouee_et_ne_resout_rien` — une surface qui n'a pas pu observer
    //      ne se tait pas comme si elle avait observé le vide.
    //   9. `mds_cout_independant_du_volume` — LE COÛT, compté par SQLite (déterministe), sous mutation
    //      du volume x4 : les pas de machine virtuelle ne bougent pas d'un seul. Le CONTRÔLE POSITIF
    //      est dans le même corps : multiplier les relevés DE LA SÉRIE, eux, les fait bouger — sans
    //      quoi l'immobilité ne prouverait rien.
    //  10. `mds_cle_de_dedup_ne_collisionne_avec_aucun_capteur` — la famille ne peut pas marcher sur
    //      les clés `hb-<id>` des 23 capteurs ni sur le préfixe de la flotte muette.
    //  11. `mds_zero_sur_zero_n_est_pas_une_sante` — LE DÉNOMINATEUR EST CE QUI TRANCHE. Effacer les
    //      magasins pendant l'incident (opérateur désinstallé, espace de noms vidé, CRD retirée) faisait
    //      publier `0 pas prêt sur 0 déclaré` au capteur livré, et l'épisode se RÉSOLVAIT : le
    //      dead-man's-switch s'éteignait quand ce qu'il surveille disparaît. Mutation sur UN nombre.
    //  12. `mds_sans_denominateur_publie_le_comportement_est_conserve` — LA BORNE de la correction : un
    //      émetteur qui ne publie PAS le total n'hérite pas d'une alerte que rien ne peut plus résoudre.
    //  13. `mds_le_module_avoue_que_son_producteur_n_est_pas_arme` — L'AVEU DU MODULE SUR LUI-MÊME, tenu
    //      par une DÉRIVATION et non par une phrase. Ce module disqualifie son plus proche parent au
    //      motif qu'« un mécanisme posé mais non armé n'est pas un signal » ; son propre producteur est
    //      livré ÉTEINT et aucun capteur muet ne le couvre. Tant que ces deux faits tiennent sur l'arbre,
    //      le bandeau DOIT le dire ; le jour où l'un cesse de tenir, le témoin exige le RETRAIT de l'aveu,
    //      sans quoi ce serait une confession qui vieillit — le défaut d'à côté.
    // ================================================================================================

    // Les fichiers de tests partagent UN SEUL espace de noms (`include!` dans `mod tests`) : les
    // symboles trop génériques y sont donc RENOMMÉS à l'import, pas laissés se disputer la place.
    use crate::mesure_environnement::Mesure as MesureEnv;
    use crate::sonde_du_magasin_de_secrets::{
        detail_du_magasin, etat_du_magasin, verifier_le_magasin_de_secrets, EtatDuMagasin,
        DEDUP_MAGASIN, ENONCE_FENETRE, FAMILLE_ALERTE as FAMILLE_MAGASIN,
        FENETRE_DE_JUGEMENT_S as FENETRE_MAGASIN_S, PLANCHER_DE_RELEVES,
        SERIE_MAGASINS_NON_PRETS, SERIE_MAGASINS_TOTAL, SEVERITE as SEVERITE_MAGASIN,
    };

    /// L'instant de référence des tests. Fixe : aucun chiffre de ce fichier ne dépend de l'horloge.
    const MDS_NOW: i64 = 1_750_000_000;

    /// Un relevé du capteur, écrit PAR LA COLONNE QUE LA PRODUCTION ÉCRIT (`metric`), au ts donné.
    fn mds_releve(conn: &Connection, ts: i64, non_prets: f64, total: f64) {
        conn.execute(
            "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',?3)",
            params![ts, SERIE_MAGASINS_NON_PRETS, non_prets],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',?3)",
            params![ts, SERIE_MAGASINS_TOTAL, total],
        )
        .unwrap();
    }

    /// `n` relevés RÉGULIERS dans la fenêtre, tous portant le même compte de magasins pas prêts.
    /// Le plus ancien est posé à un quart de fenêtre : tout tient DANS la fenêtre, et le test 7 pose
    /// explicitement le cas contraire au lieu de dépendre d'un bord.
    fn mds_serie(conn: &Connection, n: usize, non_prets: f64) {
        for i in 0..n {
            mds_releve(conn, MDS_NOW - (FENETRE_MAGASIN_S / 4) + (i as i64) * 60, non_prets, 3.0);
        }
    }

    /// Les alertes ouvertes de la famille : (règle, statut, sévérité, clé de dédup).
    fn mds_alertes(conn: &Connection) -> Vec<(String, String, i64, Option<String>)> {
        let mut s = conn
            .prepare("SELECT rule, status, severity, dedup FROM alert WHERE rule LIKE 'heartbeat.magasin%' ORDER BY id")
            .unwrap();
        let r = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
        r
    }

    #[test]
    fn mds_un_magasin_arrete_leve_une_alerte_et_une_seule() {
        let conn = test_db();
        // Le cluster mesuré : UN magasin sur trois est à l'arrêt, et vingt-sept secrets en dépendent.
        // Le compte qui entre ici est celui des MAGASINS — c'est tout l'objet de la portée.
        mds_serie(&conn, 6, 1.0);
        assert!(
            matches!(
                etat_du_magasin(&conn, MDS_NOW),
                Some(EtatDuMagasin::NeSertPlus { non_prets: 1, total: Some(3), releves: 6, .. })
            ),
            "six relevés unanimes doivent établir l'arrêt de l'approvisionnement"
        );
        assert_eq!(verifier_le_magasin_de_secrets(&conn, MDS_NOW), MesureEnv::Lue(0));
        let a = mds_alertes(&conn);
        assert_eq!(a.len(), 1, "UNE alerte pour une cause unique — vingt-sept en seraient un second défaut");
        assert_eq!(a[0].0, FAMILLE_MAGASIN, "la famille est celle des angles morts, pas un tir de règle");
        assert_eq!(a[0].2, SEVERITE_MAGASIN);
        assert_eq!(a[0].3.as_deref(), Some(DEDUP_MAGASIN));
        // Un second tick : l'épisode reste UN épisode (INSERT OR IGNORE sur une clé STABLE).
        verifier_le_magasin_de_secrets(&conn, MDS_NOW + 300);
        assert_eq!(mds_alertes(&conn).len(), 1, "un second tick ne doit pas rouvrir un épisode déjà ouvert");
        // Ce que l'exploitant LIT dit la conséquence, pas seulement l'objet rouge — et il dit aussi ce
        // que ce signal NE couvre pas, sans quoi son silence passerait pour une preuve.
        let t: String = conn
            .query_row("SELECT detail FROM alert WHERE dedup=?1", params![DEDUP_MAGASIN], |r| r.get(0))
            .unwrap();
        assert!(t.contains("rotation des clés est éteinte"), "le détail doit dire la CONSÉQUENCE : {t}");
        assert!(t.contains("CE QU'ELLE NE COUVRE PAS"), "le détail doit dire sa limite : {t}");
    }

    #[test]
    fn mds_temoin_inverse_un_magasin_qui_sert_ne_leve_rien() {
        let conn = test_db();
        mds_serie(&conn, 6, 0.0);
        assert!(matches!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::Sert { releves: 6 })));
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert!(mds_alertes(&conn).is_empty(), "un approvisionnement qui sert ne doit produire AUCUNE alerte");
    }

    #[test]
    fn mds_le_signal_se_resout_quand_l_approvisionnement_repart() {
        let conn = test_db();
        mds_serie(&conn, 6, 1.0);
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn)[0].1, "new");
        // L'exploitant descelle le coffre : le capteur rapporte des magasins prêts. UN relevé suffit —
        // c'est l'asymétrie voulue (lever lentement, résoudre tout de suite).
        mds_releve(&conn, MDS_NOW + 300, 0.0, 3.0);
        assert_eq!(verifier_le_magasin_de_secrets(&conn, MDS_NOW + 300), MesureEnv::Lue(0));
        let a = mds_alertes(&conn);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].1, "resolved", "le rafraîchissement qui repart doit ÉTEINDRE le signal");
        assert_eq!(a[0].3, None, "la clé de dédup doit être LIBÉRÉE, sinon l'épisode suivant est avalé");
        // Et un épisode NEUF peut se rouvrir derrière, sinon la résolution serait une extinction.
        // LE PRIX DE L'UNANIMITÉ, ÉPROUVÉ ICI ET NON SUPPOSÉ : tant que le relevé sain est ENCORE
        // dans la fenêtre, il interdit la levée — un nouvel arrêt ne se dit donc qu'une fois ce
        // relevé sorti de l'heure. C'est le même échange que le plancher de relevés, et il est du
        // bon côté : l'épisode mesuré a duré des jours.
        let t = MDS_NOW + FENETRE_MAGASIN_S + 600;
        mds_releve(&conn, MDS_NOW + 900, 2.0, 3.0); // encore accompagné du relevé sain -> RIEN
        verifier_le_magasin_de_secrets(&conn, MDS_NOW + 960);
        assert_eq!(mds_alertes(&conn).len(), 1, "un relevé sain encore dans la fenêtre interdit la levée");
        for i in 0..PLANCHER_DE_RELEVES {
            mds_releve(&conn, t + (i as i64) * 60, 2.0, 3.0);
        }
        verifier_le_magasin_de_secrets(&conn, t + 60);
        let a = mds_alertes(&conn);
        assert_eq!(a.len(), 2, "après résolution, un nouvel arrêt doit rouvrir un épisode");
        assert_eq!(a[1].1, "new");
    }

    #[test]
    fn mds_un_releve_isole_ne_leve_ni_ne_resout() {
        // LA MUTATION QUI NOMME LA VALEUR : `releves`. Rien d'autre ne change entre les deux moitiés.
        let conn = test_db();
        mds_releve(&conn, MDS_NOW - 120, 1.0, 3.0);
        assert!(
            matches!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::Indecis { releves: 1 })),
            "un relevé isolé est le régime transitoire, il n'établit rien"
        );
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert!(mds_alertes(&conn).is_empty(), "un unique instantané ne doit pas réveiller quelqu'un");
        // Un épisode DÉJÀ ouvert ne doit pas non plus être résolu par un état indécis : le résoudre
        // serait affirmer un retour à la normale que RIEN n'a observé.
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,dedup) VALUES(?1,?2,4,'x','y',?3)",
            params![MDS_NOW - 600, FAMILLE_MAGASIN, DEDUP_MAGASIN],
        )
        .unwrap();
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn)[0].1, "new", "un état indécis ne doit RIEN résoudre");
        // LA MUTATION : un second relevé, et le verdict bascule. La valeur qui change est le COMPTE.
        mds_releve(&conn, MDS_NOW - 60, 1.0, 3.0);
        assert!(
            matches!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::NeSertPlus { releves: 2, .. })),
            "au plancher de relevés, le même fait devient établi"
        );
    }

    #[test]
    fn mds_unanimite_exigee_pour_lever() {
        let conn = test_db();
        // Cinq relevés « pas prêt » et UN seul « prêt » : l'unanimité est rompue, on ne lève pas.
        mds_serie(&conn, 5, 1.0);
        mds_releve(&conn, MDS_NOW - 30, 0.0, 3.0);
        assert!(matches!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::Sert { .. })));
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert!(mds_alertes(&conn).is_empty(), "un seul relevé sain interdit la levée");
        // MUTATION, sur la MÊME base : ce relevé sain passe à « pas prêt ». Rien d'autre ne bouge.
        conn.execute(
            "UPDATE metric SET value=1.0 WHERE name=?1 AND ts=?2",
            params![SERIE_MAGASINS_NON_PRETS, MDS_NOW - 30],
        )
        .unwrap();
        assert!(matches!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::NeSertPlus { releves: 6, .. })));
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn).len(), 1);
    }

    #[test]
    fn mds_rien_de_rapporte_ne_conclut_rien() {
        let conn = test_db();
        assert_eq!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::NonObserve));
        assert_eq!(
            verifier_le_magasin_de_secrets(&conn, MDS_NOW),
            MesureEnv::Lue(0),
            "une installation sans magasin de secrets n'est PAS un aveu — rien n'a échoué"
        );
        assert!(mds_alertes(&conn).is_empty());
        // Et surtout : un épisode ouvert ne se résout pas parce que le capteur s'est tu. C'est le
        // défaut exact que ce module ferme, retourné contre lui-même.
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,detail,dedup) VALUES(?1,?2,4,'x','y',?3)",
            params![MDS_NOW - 600, FAMILLE_MAGASIN, DEDUP_MAGASIN],
        )
        .unwrap();
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(
            mds_alertes(&conn)[0].1,
            "new",
            "un capteur qui se tait ne doit JAMAIS valoir « l'approvisionnement est reparti »"
        );
    }

    #[test]
    fn mds_hors_fenetre_ne_compte_pas() {
        let conn = test_db();
        // Six relevés unanimes, mais tous ANTÉRIEURS à la fenêtre : le verdict d'aujourd'hui ne se
        // fabrique pas avec les relevés d'hier.
        for i in 0..6 {
            mds_releve(&conn, MDS_NOW - FENETRE_MAGASIN_S - 3600 + i * 60, 1.0, 3.0);
        }
        assert_eq!(etat_du_magasin(&conn, MDS_NOW), Some(EtatDuMagasin::NonObserve));
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert!(mds_alertes(&conn).is_empty());
    }

    #[test]
    fn mds_lecture_impossible_est_avouee_et_ne_resout_rien() {
        let conn = test_db();
        mds_serie(&conn, 6, 1.0);
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn)[0].1, "new");
        // La série devient ILLISIBLE (table disparue). Ni levée, ni résolution — et un AVEU.
        conn.execute_batch("DROP TABLE metric").unwrap();
        assert_eq!(etat_du_magasin(&conn, MDS_NOW), None);
        let bilan = verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        match bilan {
            MesureEnv::Illisible { cause, ref detail } => {
                assert_eq!(cause, crate::mesure_environnement::CAUSE_SOURCE_ILLISIBLE);
                assert!(detail.contains(SERIE_MAGASINS_NON_PRETS), "l'aveu doit NOMMER la série : {detail}");
            }
            autre => panic!("une lecture impossible doit être AVOUÉE, pas comptée comme un tick calme : {autre:?}"),
        }
        assert_eq!(
            mds_alertes(&conn)[0].1,
            "new",
            "une surface qui n'a pas pu observer ne doit pas se taire comme si elle avait observé le vide"
        );
    }

    #[test]
    fn mds_cout_independant_du_volume() {
        // L'INSTRUMENT est celui de `tests/sondes_cout.rs` : `SQLITE_STMTSTATUS_VM_STEP`, compté par
        // SQLite lui-même — déterministe, donc insensible à la charge machine. L'énoncé mesuré est
        // CELUI QUE LA PRODUCTION EXÉCUTE (`ENONCE_FENETRE`), pas une copie.
        fn cout(conn: &Connection, now: i64) -> i64 {
            let mut s = conn.prepare(ENONCE_FENETRE).unwrap();
            let _: Result<(), _> =
                s.query_row(params![SERIE_MAGASINS_NON_PRETS, now - FENETRE_MAGASIN_S], |_| Ok(()));
            s.get_status(rusqlite::StatementStatus::VmStep) as i64
        }
        /// `n` lignes de métriques D'AUTRES séries dans la MÊME fenêtre — le volume ingéré ordinaire.
        fn volume(conn: &Connection, n: i64) {
            for i in 0..n {
                conn.execute(
                    "INSERT INTO metric(ts,name,labels,value) VALUES(?1,'cpu','{}',1.0)",
                    params![MDS_NOW - (i % 600)],
                )
                .unwrap();
            }
        }
        let conn = test_db();
        mds_serie(&conn, 6, 1.0);
        volume(&conn, 500);
        let a = cout(&conn, MDS_NOW);
        // MUTATION DU VOLUME x4 : rien de ce que la sonde regarde ne change.
        volume(&conn, 1500);
        let b = cout(&conn, MDS_NOW);
        assert_eq!(a, b, "le coût de la sonde ne doit PAS suivre le volume ingéré ({a} -> {b})");
        // CONTRÔLE POSITIF, dans le même corps : sans lui, un instrument qui rendrait une constante
        // passerait le témoin ci-dessus sans rien prouver. Ce sont les relevés DE LA SÉRIE qui bornent
        // le coût — les multiplier doit se voir.
        mds_serie(&conn, 40, 1.0);
        let c = cout(&conn, MDS_NOW);
        assert!(c > b, "l'instrument doit bouger quand la CADENCE de la série grandit ({b} -> {c})");
    }

    #[test]
    fn mds_cle_de_dedup_ne_collisionne_avec_aucun_capteur() {
        // La famille partage l'espace de clés de `check_heartbeats` (`hb-<id>`) et de la flotte muette
        // (`hb-flotte-muets-<empreinte>`). Une collision ferait qu'un capteur muet résoudrait l'alerte
        // du magasin, ou l'inverse — deux faits distincts éteints par un seul geste.
        for (id, _, _, _, _) in COLLECTORS.iter() {
            assert_ne!(format!("hb-{id}"), DEDUP_MAGASIN, "le capteur `{id}` collisionne avec la clé du magasin");
        }
        assert!(
            !DEDUP_MAGASIN.starts_with(crate::sonde_de_flotte::DEDUP_FLOTTE_MUETTE),
            "la clé du magasin ne doit pas tomber dans le préfixe d'épisode de la flotte muette"
        );
        // Et le texte ne prétend pas nommer un total qu'il n'a pas : un capteur qui n'a pas publié le
        // dénominateur le DIT, au lieu d'écrire un chiffre inventé.
        assert!(detail_du_magasin(2, None, 6, 3600).contains("dénominateur non publié"));
        assert!(detail_du_magasin(2, Some(3), 6, 3600).contains("sur 3 déclaré(s)"));
    }

    // ------------------------------------------------------------------------------------------------
    // 11. `mds_zero_sur_zero_n_est_pas_une_sante` — LE DÉFAUT MESURÉ SUR LE CAPTEUR LIVRÉ, ET LA VALEUR
    //     QUI TRANCHE. `collectors/kube-state.sh` publie `secretstore_total=0` ET `secretstore_notready=0`
    //     dès qu'un `get` réussit sur ZÉRO ressource : effacer les magasins pendant l'incident —
    //     désinstaller l'opérateur, vider l'espace de noms, retirer la CRD — faisait passer l'alerte à
    //     `resolved` et affirmait la santé. Un dead-man's-switch que la disparition de ce qu'il surveille
    //     ÉTEINT. La mutation ne touche qu'UN nombre : le DÉNOMINATEUR du relevé sain, 0 -> 3.
    #[test]
    fn mds_zero_sur_zero_n_est_pas_une_sante() {
        let conn = test_db();
        // Un épisode ÉTABLI : six relevés unanimes, un magasin sur trois à l'arrêt.
        mds_serie(&conn, 6, 1.0);
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn).len(), 1, "témoin positif : l'épisode doit être ouvert avant la mutation");

        // LES MAGASINS DISPARAISSENT PENDANT L'INCIDENT. Le capteur rapporte fidèlement « zéro pas prêt
        // sur zéro déclaré » — deux relevés, pour qu'aucun plancher ne porte le verdict à ma place.
        let t_efface = MDS_NOW + 300;
        mds_releve(&conn, t_efface, 0.0, 0.0);
        mds_releve(&conn, t_efface + 60, 0.0, 0.0);
        assert_eq!(
            etat_du_magasin(&conn, t_efface + 120),
            Some(EtatDuMagasin::NonObserve),
            "« zéro pas prêt sur zéro déclaré » n'observe RIEN de l'approvisionnement : ce n'est pas `Sert`"
        );
        verifier_le_magasin_de_secrets(&conn, t_efface + 120);
        let a = mds_alertes(&conn);
        assert_eq!(a.len(), 1, "aucune alerte ne doit être créée ni dupliquée par une absence");
        assert_eq!(
            a[0].1, "new",
            "l'épisode a été RÉSOLU par la disparition des magasins : le dead-man's-switch s'éteint quand \
             ce qu'il surveille s'efface — exactement le défaut que ce module poursuit, retourné contre lui"
        );
        assert_eq!(a[0].3.as_deref(), Some(DEDUP_MAGASIN), "la clé de déduplication doit rester TENUE");

        // LA MUTATION : le même relevé, avec un dénominateur qui vaut 3. Rien d'autre ne change — ni le
        // compte des non-prêts, ni le nombre de relevés, ni la fenêtre. Le verdict bascule.
        conn.execute(
            "UPDATE metric SET value=3.0 WHERE name=?1 AND ts>=?2",
            params![SERIE_MAGASINS_TOTAL, t_efface],
        )
        .unwrap();
        assert!(
            matches!(etat_du_magasin(&conn, t_efface + 120), Some(EtatDuMagasin::Sert { .. })),
            "un relevé qui dit « aucun pas prêt SUR TROIS DÉCLARÉS » témoigne, lui, d'un approvisionnement \
             qui sert"
        );
        verifier_le_magasin_de_secrets(&conn, t_efface + 120);
        let a = mds_alertes(&conn);
        assert_eq!(a[0].1, "resolved", "le retour OBSERVÉ doit résoudre l'épisode tout de suite");
        assert_eq!(a[0].3, None, "et LIBÉRER la clé, pour qu'un épisode suivant puisse se ré-armer");
    }

    // 12. `mds_sans_denominateur_publie_le_comportement_est_conserve` — LE TÉMOIN QUI BORNE LA CORRECTION.
    //     Un émetteur qui ne publie PAS le dénominateur (capteur d'une version antérieure, autre agent)
    //     ne doit pas se retrouver avec une alerte que plus rien ne peut résoudre : sans dénominateur il
    //     n'y a RIEN à apparier, et le comportement historique est conservé tel quel. Sans ce témoin, la
    //     correction ci-dessus créerait une alerte immortelle sur un parc hétérogène.
    #[test]
    fn mds_sans_denominateur_publie_le_comportement_est_conserve() {
        let conn = test_db();
        for i in 0..6i64 {
            conn.execute(
                "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',1.0)",
                params![MDS_NOW - (FENETRE_MAGASIN_S / 4) + i * 60, SERIE_MAGASINS_NON_PRETS],
            )
            .unwrap();
        }
        assert!(
            matches!(
                etat_du_magasin(&conn, MDS_NOW),
                Some(EtatDuMagasin::NeSertPlus { total: None, .. })
            ),
            "sans dénominateur, l'arrêt s'établit quand même — et le titre DIT que le total n'est pas publié"
        );
        verifier_le_magasin_de_secrets(&conn, MDS_NOW);
        assert_eq!(mds_alertes(&conn).len(), 1);
        // Le retour : un relevé « aucun pas prêt », toujours sans dénominateur. Il DOIT résoudre.
        conn.execute(
            "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,'{}',0.0)",
            params![MDS_NOW + 60, SERIE_MAGASINS_NON_PRETS],
        )
        .unwrap();
        assert!(matches!(etat_du_magasin(&conn, MDS_NOW + 120), Some(EtatDuMagasin::Sert { .. })));
        verifier_le_magasin_de_secrets(&conn, MDS_NOW + 120);
        assert_eq!(
            mds_alertes(&conn)[0].1,
            "resolved",
            "un émetteur sans dénominateur ne doit pas hériter d'une alerte immortelle"
        );
    }

    // ------------------------------------------------------------------------------------------------
    // 13. L'AVEU EST DÉRIVÉ DE L'ARBRE, DANS LES DEUX SENS.
    #[test]
    fn mds_le_module_avoue_que_son_producteur_n_est_pas_arme() {
        const AVEU: &str = "SUR UN DÉPLOIEMENT OÙ L'EXPLOITANT N'A PAS ARMÉ LE TIMER, CE
//!     SIGNAL EST MUET";
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("racine du dépôt");
        let module = std::fs::read_to_string(racine.join("daemon/src/sonde_du_magasin_de_secrets.rs"))
            .expect("le module du magasin de secrets doit être lisible");

        // ① LE PRODUCTEUR — DÉRIVÉ, jamais nommé de mémoire : le fichier livré qui émet la série. La
        //    table `SOURCES_LIVREES` est tenue MIROIR des collecteurs par sa propre garde, donc c'est
        //    elle qui dit quelle SOURCE ce fichier alimente.
        let collecteurs = racine.join("collectors");
        let emetteurs: Vec<String> = std::fs::read_dir(&collecteurs)
            .expect("collectors/ doit être lisible")
            .flatten()
            .filter(|e| e.path().extension().map_or(false, |x| x == "sh"))
            .filter(|e| {
                std::fs::read_to_string(e.path())
                    .map_or(false, |t| t.contains(crate::sonde_du_magasin_de_secrets::SERIE_MAGASINS_NON_PRETS))
            })
            .map(|e| format!("collectors/{}", e.file_name().to_string_lossy()))
            .collect();
        assert_eq!(
            emetteurs.len(),
            1,
            "instrument : {} fichier(s) livré(s) émettent `{}` ({emetteurs:?}) — l'aveu porte sur UN producteur \
             unique, et cette dérivation ne sait plus lequel",
            emetteurs.len(),
            crate::sonde_du_magasin_de_secrets::SERIE_MAGASINS_NON_PRETS
        );
        let producteur = &emetteurs[0];
        let source: Option<&str> = crate::handlers::sources::SOURCES_LIVREES
            .iter()
            .find(|(_, f)| f == producteur)
            .map(|(s, _)| *s);

        // ② EST-IL ARMÉ PAR DÉFAUT ? Dérivé de l'amorçage, qui est le seul lieu qui décide.
        let amorcage = std::fs::read_to_string(racine.join("bootstrap.sh")).expect("bootstrap.sh lisible");
        let unite = producteur
            .rsplit('/')
            .next()
            .and_then(|f| f.strip_suffix(".sh"))
            .map(|n| format!("plume-{n}.timer"))
            .expect("nom d'unité dérivé du producteur");
        assert!(
            amorcage.contains(&unite),
            "instrument : l'amorçage ne connaît pas `{unite}` — la dérivation « armé ou non » n'a plus de source"
        );
        let eteint_par_defaut = amorcage
            .lines()
            .any(|l| l.contains("systemctl disable") && l.contains(&unite));

        // ③ UN CAPTEUR MUET LE COUVRE-T-IL ? Dérivé de `COLLECTORS`, par sa source et par ce que sa sonde
        //    observe — jamais par un nom de capteur.
        let couvert_par_un_capteur_muet = source.is_some_and(|src| {
            crate::COLLECTORS.iter().any(|(id, _, _, sonde, _)| {
                *id == src
                    || crate::imputer_alerte_de_capteur(sonde)
                        .into_iter()
                        .any(|s| s != crate::SOURCE_INDETERMINABLE && s == src)
            })
        });

        // ④ LE VERDICT, DANS LES DEUX SENS.
        if eteint_par_defaut && !couvert_par_un_capteur_muet {
            assert!(
                module.contains(AVEU),
                "`{producteur}` est livré ÉTEINT (`{unite}` désactivée à l'amorçage) et AUCUNE entrée de \
                 `COLLECTORS` n'observe sa source ({source:?}) : ce module reproche exactement cela à son \
                 voisin `kube_sts_notready`. Son bandeau DOIT porter l'aveu que le signal est MUET tant que \
                 l'exploitant n'a pas armé le capteur — sans quoi la cellule pourrait être déclarée fermée \
                 sur un mécanisme posé et non armé."
            );
        } else {
            assert!(
                !module.contains(AVEU),
                "le bandeau avoue encore que son producteur n'est pas armé alors que ce n'est plus vrai \
                 (éteint par défaut : {eteint_par_defaut} ; couvert par un capteur muet : \
                 {couvert_par_un_capteur_muet}). Une confession qui vieillit est un mensonge de plus."
            );
        }
    }
