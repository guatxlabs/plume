// =====================================================================================
// `P10.28-l` (restes de la vague AO) — « BANNI / PASS » N'EST PLUS SEMÉ HORS DE SA VUE, ET LES DEUX PANNEAUX AJOUTÉS À
// « VUE D'ENSEMBLE (RAPIDE) » NE SONT PLUS DOUBLÉS NI PERDUS EN SILENCE.
//
// LE DÉFAUT, LU SUR ac1f43b8 :
//  * `ecrire_le_banni_pass` (rollups.rs) : `if let Some(vid) = find_or_create_view(conn, "Détection") { UPDATE … }` —
//    une vue « Détection » non lue (lecture du nom ratée) ou non créable (`INSERT INTO view` refusé ou à `Ok(0)`)
//    sautait le rattachement : le tableau était validé HORS vue, nom présent, et l'idempotence par nom le tenait pour
//    semé (jamais réparé, la migration v63 ne rejoue pas sur une base à jour) ;
//  * `ensure_rollup_srcip_host_panels` (maintenance.rs) : présence du panneau lue par `.is_ok()` (une lecture ratée
//    valait absence : panneau écrit EN DOUBLE) puis `let _ = conn.execute(INSERT…)` (un refus ou un `Ok(0)` n'était
//    pas dit).
//
// DÉSORMAIS : Banni / Pass appelle `lire_ou_creer_la_vue` (seeds.rs) et exige `Ok(1)` du rattachement ; une vue non
// obtenue annule le point de reprise (rien n'est conservé), est dite sous sa propre phrase (`VueNonObtenue`, pas
// « une écriture a été refusée ») et le démarrage suivant reprend le semis entier. Les panneaux rapides : présence en
// trois issues (`.optional()`), non lue = rien d'écrit et une ligne de journal ; `INSERT` à une ligne
// (`une_ligne_ecrite`), sinon une ligne de journal.
//
// CE QUE CES TÉMOINS TIENNENT : (a) vue préexistante -> le tableau dans CETTE vue, replié ; (b) vue absente -> créée
// avec le tableau ; (c) lecture du nom de vue refusée SEULE (autorisateur sur `view.name`), vue présente ou absente ->
// aucun tableau, aucune vue de plus, aucun panneau ; (d) `INSERT INTO view` à `RAISE(IGNORE)` puis `RAISE(ABORT)`, et
// rattachement à `RAISE(IGNORE)` -> idem ; (e) base revenue -> le semis entier, sans doublon ; (f) la chaîne des
// migrations (v52 sous `MigTx`) avec la vue non créable -> chaîne au bout, aucun Banni / Pass hors vue, transaction
// fermée, le démarrage le sème entier ; (g) deux bases réelles semées par `seed_tenant_content`, une seule refuse la
// vue ; les lignes `[seed]` ENTIÈRES (égalité) lues sur le stderr d'un sous-processus, annulation refusée comprise, et
// le `RELEASE` refusé dit sous la phrase de l'écriture refusée (pas celle de la vue) ; panneaux rapides : lecture ratée
// sans doublon, `INSERT` du PREMIER panneau de la liste refusé dit, le panneau suivant écrit quand même, puis repris.
//
// CE QU'ILS NE TIENNENT PAS : une base déjà amputée (Banni / Pass validé hors vue AVANT ce correctif) n'est pas
// réparée ; le refus de Banni / Pass n'est pas compté (le compteur exige un `&Connection`) ; la lecture ratée du
// tableau « Vue d'ensemble (rapide) » dans `ensure_rollup_srcip_host_panels` n'est plus un retour muet depuis la vague
// AR (trois issues, une ligne `[seed]`, témoins `retention_lue_hors_de_la_passe.rs`) ; la migration v63 (`migrate.rs`) garde `if let Some(vid)` ; `seed_runbooks`. Aucune variable d'environnement n'est
// lue par ces semis.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `AP4_bp_if_let_some` (forme d'avant),
// `AP4_bp_vue_ok` (refus de la vue avalé par `.ok()`), `AP4_bp_rattachement_ok0` (rattachement `Ok(0)` accepté),
// `AP4_bp_vue_libelle_ecriture` (la vue non obtenue dite « écriture refusée »), `AP4_maint_is_ok` (lecture ratée =
// absence), `AP4_maint_lecture_muette` (lecture ratée non dite), `AP4_maint_let` (refus d'`INSERT` non dit),
// `AP4_maint_ok0` (`Ok(0)` accepté), `AP4V_bp_release_vers_vue` (le `RELEASE` refusé rangé sous la vue non obtenue),
// `AP4V_maint_insert_break` (un refus d'`INSERT` arrête la boucle des panneaux rapides).
// =====================================================================================
mod banni_pass_et_panneaux_rapides_rattaches_ou_refuses {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const AP4_VUE: &str = "Détection";
    const AP4_RAPIDE: &str = "Vue d'ensemble (rapide)";
    const AP4_TITRES_RAPIDES: [&str; 2] = ["Sévérité >=3 par src_ip", "Volume par host"];

    /// (tableaux « Banni / Pass », leurs panneaux, vues « Détection », panneaux en tout, vues en tout).
    fn ap4_etat(conn: &Connection) -> (i64, i64, i64, i64, i64) {
        let tableaux: i64 =
            conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![NOM_DU_BANNI_PASS], |r| r.get(0)).expect("tableaux");
        let panneaux: i64 = conn
            .query_row("SELECT COUNT(*) FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![NOM_DU_BANNI_PASS], |r| r.get(0))
            .expect("panneaux du tableau");
        let vues: i64 = conn.query_row("SELECT COUNT(*) FROM view WHERE name=?1", params![AP4_VUE], |r| r.get(0)).expect("vues du nom");
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM panel", [], |r| r.get(0)).expect("panneaux");
        let vues_en_tout: i64 = conn.query_row("SELECT COUNT(*) FROM view", [], |r| r.get(0)).expect("vues");
        (tableaux, panneaux, vues, total, vues_en_tout)
    }

    /// (nom de la vue de « Banni / Pass », replié, identifiant de vue).
    fn ap4_vue_du_banni_pass(conn: &Connection) -> (Option<String>, i64, Option<i64>) {
        conn.query_row(
            "SELECT v.name, d.collapsed, d.view_id FROM dashboard d LEFT JOIN view v ON v.id=d.view_id WHERE d.name=?1",
            params![NOM_DU_BANNI_PASS],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("vue du tableau")
    }

    fn ap4_sans_banni_pass(conn: &Connection) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![NOM_DU_BANNI_PASS])
            .expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![NOM_DU_BANNI_PASS]).expect("tableau retiré");
        assert_eq!(ap4_etat(conn).0, 0, "instrument : base sans « Banni / Pass »");
    }

    /// Retire la vue « Détection » (les tableaux qui y étaient passent hors vue : l'instrument ne les lit pas).
    fn ap4_sans_vue(conn: &Connection) {
        conn.execute("UPDATE dashboard SET view_id=NULL WHERE view_id IN (SELECT id FROM view WHERE name=?1)", params![AP4_VUE])
            .expect("tableaux détachés");
        conn.execute("DELETE FROM view WHERE name=?1", params![AP4_VUE]).expect("vue retirée");
        assert_eq!(ap4_etat(conn).2, 0, "instrument : base sans la vue « Détection »");
    }

    fn ap4_refuser_la_lecture_du_nom_de_vue(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "view" && column_name == "name" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ap4_refuser_la_lecture_du_titre_de_panneau(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "panel" && column_name == "title" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ap4_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Le semis repris entier : un tableau, quatre panneaux, dans la vue « Détection » (une seule), replié ; un second
    /// semis n'ajoute rien.
    fn ap4_repris_entier(conn: &Connection, cas: &str) {
        seed_banpass_dashboard(conn);
        let (tableaux, panneaux, vues, total, _) = ap4_etat(conn);
        assert_eq!((tableaux, panneaux, vues), (1, 4, 1), "{cas} : repris entier, une seule vue « Détection »");
        let (vue, replie, _) = ap4_vue_du_banni_pass(conn);
        assert_eq!((vue.as_deref(), replie), (Some(AP4_VUE), 1), "{cas} : dans sa vue, replié");
        seed_banpass_dashboard(conn);
        assert_eq!(ap4_etat(conn).0, 1, "{cas} : aucun doublon");
        assert_eq!(ap4_etat(conn).3, total, "{cas} : aucun panneau de plus");
        assert!(conn.is_autocommit(), "{cas} : transaction fermée");
    }

    /// (a) CONTRÔLE POSITIF — la vue « Détection » préexistante reçoit le tableau, replié ; aucune vue neuve.
    #[test]
    fn ap4_vue_preexistante_recoit_le_tableau_replie() {
        let conn = test_db();
        ap4_sans_banni_pass(&conn);
        let vid: i64 = conn.query_row("SELECT id FROM view WHERE name=?1", params![AP4_VUE], |r| r.get(0)).expect("vue préexistante");
        let (_, _, vues, _, vues_en_tout) = ap4_etat(&conn);
        assert_eq!(vues, 1, "instrument : une vue « Détection »");
        seed_banpass_dashboard(&conn);
        assert_eq!(ap4_vue_du_banni_pass(&conn), (Some(AP4_VUE.to_string()), 1, Some(vid)), "la vue EXISTANTE, repliée");
        let (tableaux, panneaux, vues_apres, _, vues_en_tout_apres) = ap4_etat(&conn);
        assert_eq!((tableaux, panneaux, vues_apres, vues_en_tout_apres), (1, 4, 1, vues_en_tout), "un tableau, quatre panneaux, aucune vue neuve");
    }

    /// (b) LA VUE ABSENTE est créée par le semis, avec le tableau rattaché.
    #[test]
    fn ap4_vue_absente_creee_avec_le_tableau() {
        let conn = test_db();
        ap4_sans_banni_pass(&conn);
        ap4_sans_vue(&conn);
        seed_banpass_dashboard(&conn);
        let vid: i64 = conn.query_row("SELECT id FROM view WHERE name=?1", params![AP4_VUE], |r| r.get(0)).expect("vue créée");
        assert_eq!(ap4_vue_du_banni_pass(&conn), (Some(AP4_VUE.to_string()), 1, Some(vid)), "rattaché à la vue créée, replié");
        let (tableaux, panneaux, vues, _, _) = ap4_etat(&conn);
        assert_eq!((tableaux, panneaux, vues), (1, 4, 1), "la vue et le tableau écrits");
    }

    /// (c) puis (e) — LA LECTURE DU NOM DE VUE REFUSÉE SEULE, vue présente ou absente : aucun tableau, aucune vue,
    /// aucun panneau, transaction fermée ; lecture rendue, le semis entier.
    /// MUTANTS QUI LE ROUGISSENT : `AP4_bp_if_let_some`, `AP4_bp_vue_ok`.
    #[test]
    fn ap4_nom_de_vue_illisible_refuse_le_semis_puis_reprise_entiere() {
        let mut joues = 0;
        for vue_presente in [true, false] {
            let cas = if vue_presente { "vue présente" } else { "vue absente" };
            let conn = test_db();
            ap4_sans_banni_pass(&conn);
            if !vue_presente {
                ap4_sans_vue(&conn);
            }
            let avant = ap4_etat(&conn);
            ap4_refuser_la_lecture_du_nom_de_vue(&conn);
            seed_banpass_dashboard(&conn);
            ap4_rendre_la_main(&conn);
            assert_eq!(ap4_etat(&conn), avant, "{cas} : nom de vue illisible, rien n'est écrit (ni tableau, ni vue, ni panneau)");
            assert!(conn.is_autocommit(), "{cas} : transaction fermée");
            ap4_repris_entier(&conn, cas);
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux cas sont joués");
    }

    /// (d) puis (e) — `INSERT INTO view` refusé (`RAISE(ABORT)`) ou à `Ok(0)` (`RAISE(IGNORE)`), et le rattachement à
    /// `Ok(0)` : aucun tableau, aucune vue, aucun panneau ; base revenue, le semis entier, sans doublon.
    /// MUTANTS QUI LE ROUGISSENT : `AP4_bp_if_let_some`, `AP4_bp_vue_ok` (vue) ; `AP4_bp_rattachement_ok0` (rattachement).
    #[test]
    fn ap4_vue_non_creable_ou_rattachement_ignore_refuse_le_semis() {
        let cas: [(&str, bool, String); 3] = [
            ("vue IGNORE", true, format!("BEFORE INSERT ON view WHEN NEW.name='{AP4_VUE}' BEGIN SELECT RAISE(IGNORE); END")),
            ("vue ABORT", true, format!("BEFORE INSERT ON view WHEN NEW.name='{AP4_VUE}' BEGIN SELECT RAISE(ABORT,'ap4 refus'); END")),
            ("rattachement IGNORE", false, "BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(IGNORE); END".to_string()),
        ];
        let mut joues = 0;
        for (etape, sans_vue, declencheur) in cas {
            let conn = test_db();
            ap4_sans_banni_pass(&conn);
            if sans_vue {
                ap4_sans_vue(&conn);
            }
            let avant = ap4_etat(&conn);
            conn.execute_batch(&format!("CREATE TRIGGER ap4_refus {declencheur};")).expect("déclencheur de refus");
            seed_banpass_dashboard(&conn);
            assert_eq!(ap4_etat(&conn), avant, "{etape} : rien n'est écrit (ni tableau, ni vue, ni panneau)");
            assert!(conn.is_autocommit(), "{etape} : transaction fermée");
            seed_banpass_dashboard(&conn);
            assert_eq!(ap4_etat(&conn), avant, "{etape} : démarrage suivant, base toujours hostile : toujours rien");
            conn.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
            ap4_repris_entier(&conn, etape);
            joues += 1;
        }
        assert_eq!(joues, 3, "les trois cas sont joués");
    }

    /// (f) — LA CHAÎNE DES MIGRATIONS (v52 sème Banni / Pass sous `MigTx`) avec la vue « Détection » non créable : la
    /// chaîne va au bout, aucun Banni / Pass (ni hors vue, ni panneau orphelin), transaction fermée ; base revenue, le
    /// semis du démarrage l'écrit entier dans sa vue.
    /// MUTANT QUI LE ROUGIT : `AP4_bp_if_let_some` (v52 validait le tableau hors vue, et v63 ne le rattachait pas).
    #[test]
    fn ap4_sous_la_migration_vue_non_creable_aucun_tableau_hors_vue() {
        let mut joues = 0;
        for (forme, corps) in [("IGNORE", "RAISE(IGNORE)"), ("ABORT", "RAISE(ABORT,'ap4 refus')")] {
            let conn = Connection::open_in_memory().expect("base");
            conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
            let depart: i64 = conn
                .query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'", [], |r| r.get(0))
                .expect("version de départ");
            assert!(depart < 11, "({forme}) instrument : la chaîne passe par v11 et v52 (départ {depart})");
            // La table `view` naît en v11 : posée ici avec la MÊME définition (v11 la crée `IF NOT EXISTS`), pour que le
            // déclencheur existe avant la chaîne.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS view(
                     id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     owner TEXT,
                     visibility TEXT NOT NULL DEFAULT 'private',
                     created INTEGER NOT NULL DEFAULT (strftime('%s','now'))
                 );",
            )
            .expect("table des vues, définition de v11");
            conn.execute_batch(&format!("CREATE TRIGGER ap4_refus BEFORE INSERT ON view WHEN NEW.name='{AP4_VUE}' BEGIN SELECT {corps}; END;"))
                .expect("déclencheur de refus");
            assert!(migrate(&conn), "({forme}) : la chaîne de migrations va au bout");
            let version: i64 = conn
                .query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'", [], |r| r.get(0))
                .expect("version");
            assert!(version >= 63, "({forme}) : les étapes v52 et v63 validées (version {version})");
            let (tableaux, panneaux, vues, _, _) = ap4_etat(&conn);
            assert_eq!((tableaux, panneaux, vues), (0, 0, 0), "({forme}) : aucun « Banni / Pass », aucune vue « Détection »");
            let orphelins: i64 = conn
                .query_row("SELECT COUNT(*) FROM panel WHERE title IN ('Banlist par source','IPs bannies (dernier ban dans la fenêtre)')", [], |r| r.get(0))
                .expect("panneaux");
            assert_eq!(orphelins, 0, "({forme}) : aucun panneau de « Banni / Pass » conservé");
            assert!(conn.is_autocommit(), "({forme}) : transaction fermée");
            conn.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
            ap4_repris_entier(&conn, forme);
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux formes sont jouées");
    }

    fn ap4_base_de_tenant(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// (g) — DEUX BASES RÉELLES semées par `seed_tenant_content` (le point commun du démarrage et de la création d'un
    /// tenant) ; seule la première refuse la vue « Détection » : elle n'a aucun Banni / Pass, la seconde l'a dans sa vue ;
    /// la première revenue, son semis suivant l'écrit entier.
    /// MUTANTS QUI LE ROUGISSENT : `AP4_bp_if_let_some`, `AP4_bp_vue_ok`.
    #[test]
    fn ap4_deux_tenants_seul_celui_qui_refuse_la_vue_n_a_pas_le_tableau() {
        let (_tmp_a, a) = ap4_base_de_tenant("ap4-tenant-a");
        let (_tmp_b, b) = ap4_base_de_tenant("ap4-tenant-b");
        for conn in [&a, &b] {
            ap4_sans_banni_pass(conn);
            ap4_sans_vue(conn);
        }
        a.execute_batch(&format!("CREATE TRIGGER ap4_refus BEFORE INSERT ON view WHEN NEW.name='{AP4_VUE}' BEGIN SELECT RAISE(ABORT,'ap4 refus'); END;"))
            .expect("déclencheur de refus");
        crate::tenants::seed_tenant_content(&a);
        crate::tenants::seed_tenant_content(&b);
        assert_eq!(ap4_etat(&a).0, 0, "tenant A (vue refusée) : aucun « Banni / Pass »");
        // Non asserté, faute de pouvoir échouer : l'absence de vue « Détection » chez A (le déclencheur `RAISE(ABORT)`
        // la garantit seul) et « B inchangé par le semis de A » (deux fichiers distincts, que le semis de A ne touche pas).
        assert!(a.is_autocommit() && b.is_autocommit(), "transactions fermées");
        assert_eq!(ap4_vue_du_banni_pass(&b).0.as_deref(), Some(AP4_VUE), "tenant B : « Banni / Pass » dans sa vue");
        let b_apres = ap4_etat(&b);
        assert_eq!((b_apres.0, b_apres.1, b_apres.2), (1, 4, 1), "tenant B : entier");
        a.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
        crate::tenants::seed_tenant_content(&a);
        let a_apres = ap4_etat(&a);
        assert_eq!((a_apres.0, a_apres.1, a_apres.2), (1, 4, 1), "tenant A revenu : entier, une seule vue");
        assert_eq!(ap4_vue_du_banni_pass(&a).0.as_deref(), Some(AP4_VUE), "tenant A revenu : dans sa vue");
    }

    /// Nombre de panneaux de ce titre sous « Vue d'ensemble (rapide) ».
    fn ap4_panneaux_rapides(conn: &Connection, titre: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM panel WHERE title=?2 AND dashboard_id=(SELECT id FROM dashboard WHERE name=?1)",
            params![AP4_RAPIDE, titre],
            |r| r.get(0),
        )
        .expect("panneaux rapides")
    }

    fn ap4_base_rapide() -> Connection {
        let conn = test_db();
        seed_rollup_dashboard(&conn);
        for t in table_declaree!(AP4_TITRES_RAPIDES) {
            assert_eq!(ap4_panneaux_rapides(&conn, t), 1, "instrument : « {t} » semé une fois");
        }
        conn
    }

    /// PANNEAUX RAPIDES — LA PRÉSENCE NON LUE n'écrit rien : panneaux présents, aucun doublon ; panneaux absents, aucun
    /// écrit ; lecture rendue, les absents écrits une fois (contrôle positif), puis plus rien.
    /// MUTANT QUI LE ROUGIT : `AP4_maint_is_ok` (lecture ratée = absence : chaque panneau en double).
    #[test]
    fn ap4_panneau_rapide_presence_non_lue_sans_doublon_puis_ajoute_une_fois() {
        let conn = ap4_base_rapide();
        ap4_refuser_la_lecture_du_titre_de_panneau(&conn);
        ensure_rollup_srcip_host_panels(&conn);
        ap4_rendre_la_main(&conn);
        for t in table_declaree!(AP4_TITRES_RAPIDES) {
            assert_eq!(ap4_panneaux_rapides(&conn, t), 1, "présents, lecture ratée : aucun second « {t} »");
        }
        conn.execute(
            "DELETE FROM panel WHERE title IN (?1,?2) AND dashboard_id=(SELECT id FROM dashboard WHERE name=?3)",
            params![AP4_TITRES_RAPIDES[0], AP4_TITRES_RAPIDES[1], AP4_RAPIDE],
        )
        .expect("panneaux retirés");
        ap4_refuser_la_lecture_du_titre_de_panneau(&conn);
        ensure_rollup_srcip_host_panels(&conn);
        ap4_rendre_la_main(&conn);
        for t in table_declaree!(AP4_TITRES_RAPIDES) {
            assert_eq!(ap4_panneaux_rapides(&conn, t), 0, "absents, lecture ratée : « {t} » non écrit");
        }
        ensure_rollup_srcip_host_panels(&conn);
        ensure_rollup_srcip_host_panels(&conn);
        for t in table_declaree!(AP4_TITRES_RAPIDES) {
            assert_eq!(ap4_panneaux_rapides(&conn, t), 1, "lecture rendue : « {t} » écrit une fois");
        }
    }

    fn ap4_retirer_les_panneaux_rapides(conn: &Connection) {
        conn.execute(
            "DELETE FROM panel WHERE title IN (?1,?2) AND dashboard_id=(SELECT id FROM dashboard WHERE name=?3)",
            params![AP4_TITRES_RAPIDES[0], AP4_TITRES_RAPIDES[1], AP4_RAPIDE],
        )
        .expect("panneaux retirés");
    }

    /// Position d'un panneau rapide sous « Vue d'ensemble (rapide) ».
    fn ap4_position_rapide(conn: &Connection, titre: &str) -> i64 {
        conn.query_row(
            "SELECT position FROM panel WHERE title=?2 AND dashboard_id=(SELECT id FROM dashboard WHERE name=?1)",
            params![AP4_RAPIDE, titre],
            |r| r.get(0),
        )
        .expect("position du panneau rapide")
    }

    /// Le déclencheur de refus vise le PREMIER panneau de la liste de `ensure_rollup_srcip_host_panels` : le panneau
    /// SUIVANT doit être écrit malgré ce refus (un refus n'arrête pas la boucle).
    fn ap4_declencheur_sur_le_premier_panneau_rapide(corps: &str) -> String {
        format!("CREATE TRIGGER ap4_refus BEFORE INSERT ON panel WHEN NEW.title='{}' BEGIN SELECT {corps}; END;", AP4_TITRES_RAPIDES[0])
    }

    /// PANNEAUX RAPIDES — L'`INSERT` du PREMIER panneau de la liste refusé (`RAISE(ABORT)`) ou à `Ok(0)`
    /// (`RAISE(IGNORE)`) : ce panneau absent, le panneau SUIVANT écrit quand même ; base revenue, le panneau repris une
    /// fois. L'instrument vérifie d'abord, au nominal, que `AP4_TITRES_RAPIDES[0]` est bien écrit AVANT
    /// `AP4_TITRES_RAPIDES[1]` (sinon « l'autre panneau écrit » serait vrai quelle que soit la boucle).
    /// MUTANT QUI LE ROUGIT : `AP4V_maint_insert_break` (un refus d'`INSERT` arrête la boucle : le panneau suivant n'est
    /// jamais écrit tant que le premier est refusé).
    #[test]
    fn ap4_panneau_rapide_insert_refuse_puis_repris() {
        let mut joues = 0;
        for (forme, corps) in [("IGNORE", "RAISE(IGNORE)"), ("ABORT", "RAISE(ABORT,'ap4 refus')")] {
            let conn = ap4_base_rapide();
            ap4_retirer_les_panneaux_rapides(&conn);
            ensure_rollup_srcip_host_panels(&conn);
            assert!(
                ap4_position_rapide(&conn, AP4_TITRES_RAPIDES[0]) < ap4_position_rapide(&conn, AP4_TITRES_RAPIDES[1]),
                "({forme}) instrument : « {} » est écrit AVANT « {} » (le refus vise le premier de la liste)",
                AP4_TITRES_RAPIDES[0],
                AP4_TITRES_RAPIDES[1]
            );
            ap4_retirer_les_panneaux_rapides(&conn);
            conn.execute_batch(&ap4_declencheur_sur_le_premier_panneau_rapide(corps)).expect("déclencheur de refus");
            ensure_rollup_srcip_host_panels(&conn);
            assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[0]), 0, "({forme}) : premier panneau refusé, absent");
            assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[1]), 1, "({forme}) : le panneau SUIVANT écrit malgré le refus");
            ensure_rollup_srcip_host_panels(&conn);
            assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[0]), 0, "({forme}) : base toujours hostile, toujours absent");
            assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[1]), 1, "({forme}) : aucun second panneau suivant");
            conn.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
            ensure_rollup_srcip_host_panels(&conn);
            ensure_rollup_srcip_host_panels(&conn);
            for t in table_declaree!(AP4_TITRES_RAPIDES) {
                assert_eq!(ap4_panneaux_rapides(&conn, t), 1, "({forme}) : « {t} » une fois après reprise");
            }
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux formes sont jouées");
    }

    /// LES LIGNES `[seed]` ENTIÈRES, lues sur le stderr d'un sous-processus : Banni / Pass (nom de vue illisible, vue
    /// IGNORE, vue ABORT, nom illisible avec l'annulation refusée, puis `RELEASE` refusé) et panneaux rapides (deux
    /// présences non lues, `INSERT` du premier panneau IGNORE puis ABORT, le suivant écrit à chaque fois) ; aucune ligne
    /// au nominal.
    /// MUTANTS QUI LE ROUGISSENT : `AP4_bp_if_let_some`, `AP4_bp_vue_ok` (aucune ligne Banni / Pass),
    /// `AP4_bp_vue_libelle_ecriture` (phrase de l'écriture refusée), `AP4V_bp_release_vers_vue` (RELEASE refusé dit sous
    /// la phrase de la vue), `AP4_maint_is_ok`, `AP4_maint_lecture_muette`, `AP4_maint_let`, `AP4_maint_ok0`,
    /// `AP4V_maint_insert_break` (l'enfant échoue : panneau suivant non écrit).
    #[test]
    fn ap4_les_lignes_seed_entieres_en_sous_processus() {
        const ENFANT: &str = "AP4_ENFANT_JOURNAL";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let conn = test_db();
            ap4_sans_banni_pass(&conn);
            println!("AP4-ENFANT-A-JOUE");
            ap4_refuser_la_lecture_du_nom_de_vue(&conn);
            seed_banpass_dashboard(&conn);
            ap4_rendre_la_main(&conn);
            ap4_sans_vue(&conn);
            for corps in ["RAISE(IGNORE)", "RAISE(ABORT,'ap4 refus')"] {
                conn.execute_batch(&format!("CREATE TRIGGER ap4_refus BEFORE INSERT ON view WHEN NEW.name='{AP4_VUE}' BEGIN SELECT {corps}; END;"))
                    .expect("déclencheur de refus");
                seed_banpass_dashboard(&conn);
                conn.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
            }
            // Nom de vue illisible ET `ROLLBACK TO` refusé : le point reste ouvert, l'aveu le dit ; l'enfant le ferme.
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, column_name } if table_name == "view" && column_name == "name" => Authorization::Deny,
                AuthAction::Savepoint { operation: TransactionOperation::Rollback, savepoint_name } if savepoint_name == POINT_DU_BANNI_PASS => {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            seed_banpass_dashboard(&conn);
            ap4_rendre_la_main(&conn);
            assert!(!conn.is_autocommit(), "enfant : annulation refusée, le point de reprise reste ouvert");
            conn.execute_batch(&format!("ROLLBACK TO {POINT_DU_BANNI_PASS}; RELEASE {POINT_DU_BANNI_PASS}")).expect("point fermé");
            assert_eq!(ap4_etat(&conn).0, 0, "enfant : rien n'est conservé");
            // La VALIDATION refusée (le premier `RELEASE` du point, la vue obtenue) : c'est une écriture refusée, pas une
            // vue non obtenue. Refus unique : le `RELEASE` de l'annulation passe et ferme le point.
            let release_refuse = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marque = release_refuse.clone();
            conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Release, savepoint_name }
                    if savepoint_name == POINT_DU_BANNI_PASS && !marque.swap(true, std::sync::atomic::Ordering::SeqCst) =>
                {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            seed_banpass_dashboard(&conn);
            ap4_rendre_la_main(&conn);
            assert!(release_refuse.load(std::sync::atomic::Ordering::SeqCst), "enfant : instrument — le refus du RELEASE a joué");
            assert!(conn.is_autocommit(), "enfant : RELEASE refusé, point fermé par l'annulation");
            assert_eq!(ap4_etat(&conn).0, 0, "enfant : RELEASE refusé, rien n'est conservé");
            seed_banpass_dashboard(&conn);
            seed_banpass_dashboard(&conn);
            assert_eq!(ap4_etat(&conn).0, 1, "enfant : semé une fois au nominal");

            seed_rollup_dashboard(&conn);
            ap4_retirer_les_panneaux_rapides(&conn);
            ap4_refuser_la_lecture_du_titre_de_panneau(&conn);
            ensure_rollup_srcip_host_panels(&conn);
            ap4_rendre_la_main(&conn);
            for corps in ["RAISE(IGNORE)", "RAISE(ABORT,'ap4 refus')"] {
                ap4_retirer_les_panneaux_rapides(&conn);
                conn.execute_batch(&ap4_declencheur_sur_le_premier_panneau_rapide(corps)).expect("déclencheur de refus");
                ensure_rollup_srcip_host_panels(&conn);
                conn.execute_batch("DROP TRIGGER ap4_refus;").expect("base revenue");
                assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[0]), 0, "enfant ({corps}) : premier panneau refusé, absent");
                assert_eq!(ap4_panneaux_rapides(&conn, AP4_TITRES_RAPIDES[1]), 1, "enfant ({corps}) : le panneau SUIVANT écrit malgré le refus");
            }
            ensure_rollup_srcip_host_panels(&conn);
            ensure_rollup_srcip_host_panels(&conn);
            for t in table_declaree!(AP4_TITRES_RAPIDES) {
                assert_eq!(ap4_panneaux_rapides(&conn, t), 1, "enfant : « {t} » une fois au nominal");
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::banni_pass_et_panneaux_rapides_rattaches_ou_refuses::ap4_les_lignes_seed_entieres_en_sous_processus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("AP4-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let bp = format!("[seed] le tableau de bord « {NOM_DU_BANNI_PASS} » NON semé : ");
        let rapide = "[seed] panneau « ";
        let lues: Vec<&str> = stderr.lines().filter(|l| l.starts_with(&bp) || l.starts_with(rapide)).collect();
        let zero = rusqlite::Error::StatementChangedRows(0).to_string();
        let vue = |cause: &str| {
            format!("{bp}la vue « Détection » n'a pas été obtenue, lecture ratée ou création refusée ({cause}) — RIEN n'est conservé, le semis sera retenté au prochain démarrage")
        };
        let ecriture_refusee = |cause: &str| {
            format!("{bp}une écriture ou sa validation a été refusée ({cause}) — RIEN n'est conservé, le semis sera retenté au prochain démarrage")
        };
        let attendues: Vec<String> = vec![
            vue("access to view.name is prohibited"),
            vue(&zero),
            vue("ap4 refus"),
            format!("{bp}la vue « Détection » n'a pas été obtenue, lecture ratée ou création refusée (access to view.name is prohibited) — ANNULATION REFUSÉE (not authorized)"),
            ecriture_refusee("not authorized"),
            format!("{rapide}Sévérité >=3 par src_ip » de « Vue d'ensemble (rapide) » NON ajouté : sa présence n'a pas pu être lue (access to panel.title is prohibited) — rien n'est écrit, retenté au prochain démarrage"),
            format!("{rapide}Volume par host » de « Vue d'ensemble (rapide) » NON ajouté : sa présence n'a pas pu être lue (access to panel.title is prohibited) — rien n'est écrit, retenté au prochain démarrage"),
            format!("{rapide}Sévérité >=3 par src_ip » de « Vue d'ensemble (rapide) » NON ajouté : son écriture a été refusée ({zero}) — retenté au prochain démarrage"),
            format!("{rapide}Sévérité >=3 par src_ip » de « Vue d'ensemble (rapide) » NON ajouté : son écriture a été refusée (ap4 refus) — retenté au prochain démarrage"),
        ];
        // Le RELEASE refusé se dit sous la phrase de l'écriture refusée, JAMAIS sous celle de la vue non obtenue.
        let release = lues.get(4).copied().unwrap_or_default();
        assert!(
            release.contains("une écriture ou sa validation a été refusée (not authorized)") && !release.contains("n'a pas été obtenue"),
            "RELEASE refusé : phrase de l'écriture refusée, pas celle de la vue : {release}\n{stderr}"
        );
        assert_eq!(lues, attendues, "lignes [seed] entières, dans l'ordre, aucune au nominal :\n{stderr}");
    }
}
