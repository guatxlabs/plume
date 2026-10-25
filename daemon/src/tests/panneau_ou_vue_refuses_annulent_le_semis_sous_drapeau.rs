// =====================================================================================
// `P10.28-l` (restes de la vague AN) — UN PANNEAU QUI N'ÉCRIT RIEN, OU UNE VUE NON LUE OU NON CRÉABLE, ANNULE LE SEMIS
// ENTIER DU TABLEAU DE BORD ; LE REFUS EST COMPTÉ ET LE DÉMARRAGE SUIVANT LE REJOUE ENTIER.
//
// LE DÉFAUT, LU SUR c6069774 (seeds.rs) :
//  * les `INSERT INTO panel` de `semer_la_vue_d_ensemble`, `seed_security_dashboard`, `seed_egress_dashboard` et
//    `semer_infra_et_logs` étaient propagés par `?` sans compter leur ligne : un panneau qui rend `Ok(0)` (un
//    déclencheur `RAISE(IGNORE)`) laissait le tableau VALIDÉ à panneau manquant, drapeau `seeded_*` posé, jamais rejoué ;
//  * `find_or_create_view` prenait une lecture ratée du nom de vue pour une absence (`.ok()` sur le `SELECT`) et créait
//    une SECONDE vue du même nom ; et `rattacher_le_tableau_a_sa_vue` sautait le rattachement sur `None` (vue non lue ou
//    non créable) : tableau validé HORS vue, drapeau posé ou nom présent, jamais réparé — alors que l'`UPDATE` du
//    rattachement à `Ok(0)` était déjà refusé.
//
// LE CHOIX POUR UNE VUE QUI RESTE NON CRÉABLE : le semis est REFUSÉ et COMPTÉ à chaque démarrage (compteur
// `plume_scheduler_gestes_de_fond_non_valides_total`, geste « tableau de bord semé sous drapeau » ou « … par nom »,
// journal `seed`), plutôt qu'un tableau hors vue définitif que rien ne signale. Le refus se répète tant que la base
// refuse la vue ; il se voit au compteur, pas seulement sur la sortie d'erreur.
//
// CE QUE CES TÉMOINS TIENNENT, sur une base sur disque (le compte des témoins est tenu par base) : le DERNIER panneau
// refusé (valeur discriminante : sur la forme d'avant, le tableau restait avec n-1 panneaux) -> ni tableau, ni panneau,
// ni drapeau, transaction fermée, compté une fois ; base revenue, le semis ENTIER (positions 0..n) dans sa vue, rien
// de plus compté ; puis aucun doublon. La vue non créable (`RAISE(IGNORE)` et `RAISE(ABORT)`) pour les quatre semis
// sous drapeau et un semis par nom (« Trafic web ») : deux démarrages, deux refus comptés, aucune vue écrite ; base
// revenue, le tableau dans SA vue, une seule vue de ce nom. La lecture du nom de vue rendue illisible SEULE
// (autorisateur sur `view.name`) : refus compté, aucune seconde vue ; et `find_or_create_view` direct rend `None` sans
// rien écrire, l'identifiant relu une fois la lecture rendue.
//
// CE QU'ILS NE TIENNENT PAS : une base déjà amputée (tableau validé à panneau manquant ou hors vue AVANT ce correctif)
// n'est pas réparée ; la ligne `[seed] … NON semé` n'est pas capturée ici (elle l'est, vague AQ, par
// `semis_vue_non_lue_banni_pass_compte_et_gabarits_repares.rs`, et une vue NON LUE y a sa phrase) ; le refus de Banni / Pass
// (rollups.rs) n'est pas compté ; `seed_runbooks` n'est pas touché. Aucune variable d'environnement n'est lue.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE sur son témoin : `AO1_ensemble_panneau`,
// `AO1_infra_panneau`, `AO1_securite_panneau`, `AO1_egress_panneau` (une_ligne_ecrite retirée au panneau d'un semis) ;
// `AO1_vue_none_silencieuse` (rattachement sauté sur une vue non lue ou non créable, la forme d'avant) ;
// `AO1_vue_ok0` (`INSERT INTO view` à `Ok(0)` accepté) ; `AO1_vue_lecture_absente` (lecture ratée prise pour une
// absence) ; `AO1_sans_compte` (refus d'un tableau sous drapeau non compté).
// =====================================================================================
mod panneau_ou_vue_refuses_annulent_le_semis_sous_drapeau {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// (étiquette, nom du tableau, drapeau, nombre de panneaux, vue, replié, semis, geste compté).
    type Ao1Semis = (&'static str, &'static str, Option<&'static str>, i64, &'static str, bool, fn(&Connection), &'static str);

    const AO1_VUE_D_ENSEMBLE: Ao1Semis =
        ("vue d'ensemble", "SOC — Vue d'ensemble", Some("seeded_default"), 7, "SOC", false, seed_default_dashboard, GESTE_TABLEAU_SEME_SOUS_DRAPEAU);
    const AO1_INFRA: Ao1Semis =
        ("infra & logs", "Infra & logs (OBS)", Some("seeded_obs"), 6, "Infra & logs", false, seed_obs_dashboard, GESTE_TABLEAU_SEME_SOUS_DRAPEAU);
    const AO1_SECURITE: Ao1Semis =
        ("sécurité", "Sécurité & détection", Some("seeded_security"), 6, "Détection", false, seed_security_dashboard, GESTE_TABLEAU_SEME_SOUS_DRAPEAU);
    const AO1_EGRESS: Ao1Semis =
        ("réseau sortant", "Réseau sortant (egress)", Some("seeded_egress"), 4, "Réseau & Web", true, seed_egress_dashboard, GESTE_TABLEAU_SEME_SOUS_DRAPEAU);
    const AO1_WEB: Ao1Semis = ("web", "Trafic web", None, 7, "Réseau & Web", false, seed_web_dashboard, GESTE_TABLEAU_SEME_PAR_NOM);

    fn ao1_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// (refus d'écriture comptés, présences non lues comptées) sous le geste du semis.
    fn ao1_comptes(conn: &Connection, geste: &str) -> (u64, u64) {
        let compte = |etape: &str| compte_des_temoins(conn, &format!("geste de fond non validé seed : {geste} : {etape}"));
        (compte(ETAPE_ECRITURE_REFUSEE), compte(ETAPE_PRESENCE_NON_LUE))
    }

    /// (tableaux de ce nom, leurs panneaux, drapeau posé).
    fn ao1_etat(conn: &Connection, nom: &str, drapeau: Option<&str>) -> (i64, i64, i64) {
        let tableaux: i64 = conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux");
        let panneaux: i64 = conn
            .query_row("SELECT COUNT(*) FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom], |r| r.get(0))
            .expect("panneaux");
        let pose: i64 = match drapeau {
            Some(d) => conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![d], |r| r.get(0)).expect("drapeau"),
            None => 0,
        };
        (tableaux, panneaux, pose)
    }

    /// Positions distinctes des panneaux du tableau de ce nom, et la plus haute.
    fn ao1_positions(conn: &Connection, nom: &str) -> (i64, Option<i64>) {
        conn.query_row(
            "SELECT COUNT(DISTINCT position), MAX(position) FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)",
            params![nom],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("positions")
    }

    fn ao1_panneaux_en_tout(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM panel", [], |r| r.get(0)).expect("panneaux")
    }

    fn ao1_vues_du_nom(conn: &Connection, vue: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM view WHERE name=?1", params![vue], |r| r.get(0)).expect("vues")
    }

    /// (nom de la vue du tableau, repli).
    fn ao1_vue(conn: &Connection, nom: &str) -> (Option<String>, i64) {
        conn.query_row(
            "SELECT v.name, d.collapsed FROM dashboard d LEFT JOIN view v ON v.id=d.view_id WHERE d.name=?1",
            params![nom],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)),
        )
        .expect("vue du tableau")
    }

    /// Base sans ce tableau ni son drapeau (l'instrument le vérifie).
    fn ao1_sans(conn: &Connection, nom: &str, drapeau: Option<&str>) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom]).expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![nom]).expect("tableau retiré");
        if let Some(d) = drapeau {
            conn.execute("DELETE FROM meta WHERE key=?1", params![d]).expect("drapeau retiré");
        }
        assert_eq!(ao1_etat(conn, nom, drapeau), (0, 0, 0), "instrument : base sans « {nom} »");
    }

    /// Refuse la lecture de la colonne `name` de `view`, et elle seule.
    fn ao1_refuser_la_lecture_du_nom_de_vue(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "view" && column_name == "name" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ao1_rendre_la_lecture(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Le DERNIER panneau du semis rend `Ok(0)` (`RAISE(IGNORE)` sur sa position, sous ce tableau seul).
    fn ao1_jouer_le_dernier_panneau_qui_n_ecrit_rien(cas: Ao1Semis) {
        let (tag, nom, drapeau, n, vue, replie, semer, geste) = cas;
        let (_tmp, conn) = ao1_base_sur_disque("ao1-panneau");
        ao1_sans(&conn, nom, drapeau);
        let avant = ao1_panneaux_en_tout(&conn);
        let nom_sql = nom.replace('\'', "''");
        conn.execute_batch(&format!(
            "CREATE TRIGGER ao1_refus BEFORE INSERT ON panel WHEN NEW.position={dernier} \
             AND NEW.dashboard_id IN (SELECT id FROM dashboard WHERE name='{nom_sql}') BEGIN SELECT RAISE(IGNORE); END;",
            dernier = n - 1
        ))
        .expect("déclencheur de refus");
        semer(&conn);
        assert_eq!(ao1_etat(&conn, nom, drapeau), (0, 0, 0), "`{tag}` : dernier panneau sans effet -> ni tableau, ni panneau, ni drapeau");
        assert_eq!(ao1_panneaux_en_tout(&conn), avant, "`{tag}` : aucun panneau conservé");
        assert!(conn.is_autocommit(), "`{tag}` : la transaction du semis est fermée");
        assert_eq!(ao1_comptes(&conn, geste), (1, 0), "`{tag}` : le refus est compté une fois, sous son étape");

        conn.execute_batch("DROP TRIGGER ao1_refus;").expect("base revenue");
        semer(&conn);
        // CONTRÔLE POSITIF : tous les panneaux, positions 0..n, dans la vue du tableau ; rien de plus compté.
        let attendu = (1, n, i64::from(drapeau.is_some()));
        assert_eq!(ao1_etat(&conn, nom, drapeau), attendu, "`{tag}` : rejoué ENTIER au démarrage suivant");
        assert_eq!(ao1_positions(&conn, nom), (n, Some(n - 1)), "`{tag}` : chaque position écrite, la dernière comprise");
        assert_eq!(ao1_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` : rattaché à sa vue");
        assert_eq!(ao1_comptes(&conn, geste), (1, 0), "`{tag}` : le semis validé ne compte rien de plus");
        semer(&conn);
        assert_eq!(ao1_etat(&conn, nom, drapeau), attendu, "`{tag}` : aucun doublon ensuite");
    }

    /// `semer_la_vue_d_ensemble` : 7e panneau `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AO1_ensemble_panneau`.
    #[test]
    fn ao1_vue_d_ensemble_dernier_panneau_qui_n_ecrit_rien_annule_le_semis() {
        ao1_jouer_le_dernier_panneau_qui_n_ecrit_rien(AO1_VUE_D_ENSEMBLE);
    }

    /// `semer_infra_et_logs` : 6e panneau `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AO1_infra_panneau`.
    #[test]
    fn ao1_infra_et_logs_dernier_panneau_qui_n_ecrit_rien_annule_le_semis() {
        ao1_jouer_le_dernier_panneau_qui_n_ecrit_rien(AO1_INFRA);
    }

    /// `seed_security_dashboard` : 6e panneau `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AO1_securite_panneau`.
    #[test]
    fn ao1_securite_dernier_panneau_qui_n_ecrit_rien_annule_le_semis() {
        ao1_jouer_le_dernier_panneau_qui_n_ecrit_rien(AO1_SECURITE);
    }

    /// `seed_egress_dashboard` : 4e panneau `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AO1_egress_panneau`.
    #[test]
    fn ao1_reseau_sortant_dernier_panneau_qui_n_ecrit_rien_annule_le_semis() {
        ao1_jouer_le_dernier_panneau_qui_n_ecrit_rien(AO1_EGRESS);
    }

    /// LA VUE NON CRÉABLE (la vue du semis renommée, son `INSERT` refusé par `RAISE(IGNORE)` puis `RAISE(ABORT)`), pour
    /// les quatre semis sous drapeau et « Trafic web » : deux démarrages -> rien d'écrit, aucune vue de ce nom, deux refus
    /// comptés ; base revenue -> le tableau entier dans SA vue, une seule vue de ce nom, rien de plus compté.
    /// MUTANTS QUI LE ROUGISSENT : `AO1_vue_none_silencieuse` (tableau semé hors vue, la forme d'avant), `AO1_vue_ok0`
    /// (IGNORE : l'identifiant du tableau lui-même pris pour une vue), `AO1_sans_compte` (refus non compté).
    #[test]
    fn ao1_vue_non_creable_refuse_le_semis_et_le_compte_a_chaque_demarrage() {
        let cas = [AO1_VUE_D_ENSEMBLE, AO1_INFRA, AO1_SECURITE, AO1_EGRESS, AO1_WEB];
        let formes = [("IGNORE", "RAISE(IGNORE)"), ("ABORT", "RAISE(ABORT,'ao1 refus de vue')")];
        let mut joues = 0;
        for (forme, corps) in formes {
            for (tag, nom, drapeau, n, vue, replie, semer, geste) in cas {
                let (_tmp, conn) = ao1_base_sur_disque("ao1-vue");
                ao1_sans(&conn, nom, drapeau);
                let vue_sql = vue.replace('\'', "''");
                conn.execute("UPDATE view SET name='ao1 ancienne vue' WHERE name=?1", params![vue]).expect("vue renommée");
                assert_eq!(ao1_vues_du_nom(&conn, vue), 0, "`{tag}` ({forme}) : instrument — la vue « {vue} » est absente");
                conn.execute_batch(&format!("CREATE TRIGGER ao1_vue_refusee BEFORE INSERT ON view WHEN NEW.name='{vue_sql}' BEGIN SELECT {corps}; END;"))
                    .expect("déclencheur de refus");
                semer(&conn);
                semer(&conn);
                assert_eq!(ao1_etat(&conn, nom, drapeau), (0, 0, 0), "`{tag}` ({forme}) : vue non créable -> rien n'est conservé");
                assert_eq!(ao1_vues_du_nom(&conn, vue), 0, "`{tag}` ({forme}) : aucune vue écrite");
                assert!(conn.is_autocommit(), "`{tag}` ({forme}) : la transaction du semis est fermée");
                assert_eq!(ao1_comptes(&conn, geste), (2, 0), "`{tag}` ({forme}) : un refus compté par démarrage");

                conn.execute_batch("DROP TRIGGER ao1_vue_refusee;").expect("base revenue");
                semer(&conn);
                assert_eq!(ao1_etat(&conn, nom, drapeau), (1, n, i64::from(drapeau.is_some())), "`{tag}` ({forme}) : rejoué entier");
                assert_eq!(ao1_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` ({forme}) : dans SA vue");
                assert_eq!(ao1_vues_du_nom(&conn, vue), 1, "`{tag}` ({forme}) : une seule vue de ce nom");
                assert_eq!(ao1_comptes(&conn, geste), (2, 0), "`{tag}` ({forme}) : le semis validé ne compte rien de plus");
                joues += 1;
            }
        }
        assert_eq!(joues, 10, "les dix cas sont joués");
    }

    /// LA LECTURE DU NOM DE VUE RATÉE (autorisateur sur `view.name` seul), la vue présente : rien d'écrit, aucune seconde
    /// vue du même nom, refus compté sous « nom de vue non lu » (`P10.28-l`, vague AQ : INVERSÉ, il l'était sous
    /// « écriture ou COMMIT refusé » ; ni sous « présence non lue », qui dit le nom du semis) ; lecture rendue -> le
    /// tableau entier dans la vue EXISTANTE.
    /// MUTANTS QUI LE ROUGISSENT : `AO1_vue_lecture_absente` (seconde vue du même nom, tableau validé),
    /// `AO1_vue_none_silencieuse` (tableau validé hors vue).
    #[test]
    fn ao1_vue_non_lue_refuse_le_semis_sans_seconde_vue() {
        let cas = [AO1_VUE_D_ENSEMBLE, AO1_INFRA, AO1_SECURITE, AO1_EGRESS, AO1_WEB];
        let mut joues = 0;
        for (tag, nom, drapeau, n, vue, replie, semer, geste) in cas {
            let (_tmp, conn) = ao1_base_sur_disque("ao1-lecture");
            ao1_sans(&conn, nom, drapeau);
            assert_eq!(ao1_vues_du_nom(&conn, vue), 1, "`{tag}` : instrument — la vue « {vue} » existe");
            let vid: i64 = conn.query_row("SELECT id FROM view WHERE name=?1", params![vue], |r| r.get(0)).expect("vue");
            ao1_refuser_la_lecture_du_nom_de_vue(&conn);
            semer(&conn);
            ao1_rendre_la_lecture(&conn);
            assert_eq!(ao1_etat(&conn, nom, drapeau), (0, 0, 0), "`{tag}` : vue non lue -> rien n'est conservé");
            assert_eq!(ao1_vues_du_nom(&conn, vue), 1, "`{tag}` : aucune seconde vue du même nom");
            assert!(conn.is_autocommit(), "`{tag}` : la transaction du semis est fermée");
            assert_eq!(ao1_comptes(&conn, geste), (0, 0), "`{tag}` : ni écriture refusée, ni présence non lue");
            let nom_non_lu = compte_des_temoins(&conn, &format!("geste de fond non validé seed : {geste} : {ETAPE_NOM_DE_VUE_NON_LU}"));
            assert_eq!(nom_non_lu, 1, "`{tag}` : compté une fois sous « nom de vue non lu »");
            semer(&conn);
            assert_eq!(ao1_etat(&conn, nom, drapeau), (1, n, i64::from(drapeau.is_some())), "`{tag}` : rejoué entier");
            assert_eq!(ao1_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` : dans sa vue");
            let rattache: Option<i64> = conn.query_row("SELECT view_id FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("view_id");
            assert_eq!(rattache, Some(vid), "`{tag}` : la vue EXISTANTE, pas une neuve");
            joues += 1;
        }
        assert_eq!(joues, 5, "les cinq cas sont joués");
    }

    /// `find_or_create_view` (migration v63, Banni / Pass) : lecture du nom ratée -> `None`, rien d'écrit, que la vue
    /// existe ou non ; lecture rendue -> l'identifiant de la vue existante, puis la vue absente créée.
    /// MUTANT QUI LE ROUGIT : `AO1_vue_lecture_absente` (la vue absente est créée sous une lecture ratée, la vue présente
    /// doublée).
    #[test]
    fn ao1_find_or_create_view_lecture_ratee_rend_none_sans_rien_ecrire() {
        let conn = test_db();
        let soc: i64 = conn.query_row("SELECT id FROM view WHERE name='SOC'", [], |r| r.get(0)).expect("vue SOC");
        let vues_avant: i64 = conn.query_row("SELECT COUNT(*) FROM view", [], |r| r.get(0)).expect("vues");
        ao1_refuser_la_lecture_du_nom_de_vue(&conn);
        let present = find_or_create_view(&conn, "SOC");
        let absent = find_or_create_view(&conn, "ao1 vue neuve");
        ao1_rendre_la_lecture(&conn);
        assert_eq!((present, absent), (None, None), "lecture ratée : `None` dans les deux cas");
        let vues_apres: i64 = conn.query_row("SELECT COUNT(*) FROM view", [], |r| r.get(0)).expect("vues");
        assert_eq!(vues_apres, vues_avant, "lecture ratée : aucune vue écrite");
        assert_eq!(find_or_create_view(&conn, "SOC"), Some(soc), "lecture rendue : la vue existante");
        let creee = find_or_create_view(&conn, "ao1 vue neuve");
        let lue: i64 = conn.query_row("SELECT id FROM view WHERE name='ao1 vue neuve'", [], |r| r.get(0)).expect("vue créée");
        assert_eq!(creee, Some(lue), "lecture rendue : la vue absente est créée, son identifiant");
    }
}
