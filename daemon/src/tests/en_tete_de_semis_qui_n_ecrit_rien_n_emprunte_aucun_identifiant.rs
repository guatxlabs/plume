// =====================================================================================
// `P10.28-l` (famille « Ok(0) puis `last_insert_rowid` ») — UN EN-TÊTE DE TABLEAU, UNE VUE OU UN RATTACHEMENT QUI
// N'ÉCRIT RIEN EST UN REFUS : AUCUN IDENTIFIANT N'EST EMPRUNTÉ À UNE AUTRE LIGNE.
//
// LE DÉFAUT, LU SUR 60841412 : `seed_dashboard_head` (sécurité, réseau sortant), `semer_la_vue_d_ensemble` et
// `semer_infra_et_logs` (seeds.rs) écrivaient l'en-tête par `conn.execute(…)?` sans compter les lignes, puis lisaient
// `last_insert_rowid()`. Un `INSERT` qui rend `Ok(0)` (un déclencheur `RAISE(IGNORE)`) laisse dans cette valeur
// l'identifiant de la DERNIÈRE ligne insérée par la connexion : les panneaux et le rattachement à la vue allaient à ce
// tableau voisin, et le drapeau `seeded_*` était posé — jamais rejoué. `find_or_create_view` avait la même forme
// (`.ok()?` puis `Some(last_insert_rowid())`) : une vue non créée servait comme identifiant de vue celui du tableau
// qu'on rattachait. Le rattachement (`UPDATE dashboard SET view_id…`) acceptait aussi `Ok(0)` : tableau validé hors de
// sa vue, drapeau posé (ou nom présent), jamais réparé.
//
// CE QUE CES TÉMOINS TIENNENT : sur un leurre écrit juste avant (c'est SON identifiant que `last_insert_rowid` rendrait),
// aucun panneau ni rattachement ; aucun tableau du nom, aucun drapeau, transaction fermée ; base revenue, le semis entier
// avec SON identifiant ; puis rien de plus. Pour la vue : `None`, jamais l'identifiant d'une autre ligne.
//
// CE QU'ILS NE TIENNENT PAS : une base déjà amputée (ou un tableau déjà validé hors vue) n'est pas réparée ; un panneau
// qui rend `Ok(0)` dans ces quatre semis sous drapeau reste accepté (seeds.rs, les `INSERT INTO panel` de
// `semer_la_vue_d_ensemble`, `seed_security_dashboard`, `seed_egress_dashboard`, `semer_infra_et_logs`) ; une lecture
// ratée du nom de vue vaut absence dans `find_or_create_view` (comportement d'avant, hors lot) ; l'aveu au journal n'est
// pas capturé ; `seed_runbooks` n'est pas touché. Aucune variable d'environnement n'est lue par ces semis.
// INCOHÉRENCE LAISSÉE : une vue NON CRÉABLE (`find_or_create_view` rend `None`) laisse le tableau validé HORS vue, drapeau
// posé, jamais réparé (comportement d'avant, `P10.28-e`, tenu par `an1_vue_non_creee_rend_none_et_pas_un_identifiant_emprunte`)
// — l'état même que le rattachement `Ok(0)` refuse ci-dessous.
// Les boucles sur `[AN1_…]` itèrent un tableau littéral : aucun compteur d'itérations n'y est affirmé (il serait vrai par
// construction).
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE sur son seul témoin : `AN1_ensemble_ok0`,
// `AN1_infra_ok0`, `AN1_tete_ok0`, `AN1_rattachement_ok0`, `AN1_vue_ok0`. Et `AN1_id_emprunte` (contrôle positif du semis
// rejoué), vu ROUGE sur `an1_tete_partagee_…` et sur les deux autres témoins qui sèment par `seed_dashboard_head`.
// =====================================================================================
mod en_tete_de_semis_qui_n_ecrit_rien_n_emprunte_aucun_identifiant {
    use super::*;

    /// (étiquette, nom du tableau, drapeau, nombre de panneaux, vue, replié, semis).
    type An1Semis = (&'static str, &'static str, Option<&'static str>, i64, &'static str, bool, fn(&Connection));

    const AN1_VUE_D_ENSEMBLE: An1Semis = ("vue d'ensemble", "SOC — Vue d'ensemble", Some("seeded_default"), 7, "SOC", false, seed_default_dashboard);
    const AN1_INFRA: An1Semis = ("infra & logs", "Infra & logs (OBS)", Some("seeded_obs"), 6, "Infra & logs", false, seed_obs_dashboard);
    const AN1_SECURITE: An1Semis = ("sécurité", "Sécurité & détection", Some("seeded_security"), 6, "Détection", false, seed_security_dashboard);
    const AN1_EGRESS: An1Semis = ("réseau sortant", "Réseau sortant (egress)", Some("seeded_egress"), 4, "Réseau & Web", true, seed_egress_dashboard);
    const AN1_RAPIDE: An1Semis = ("rapide", "Vue d'ensemble (rapide)", None, 7, "SOC", true, seed_rollup_dashboard);
    const AN1_WEB: An1Semis = ("web", "Trafic web", None, 7, "Réseau & Web", false, seed_web_dashboard);

    const AN1_LEURRE: &str = "an1 leurre";

    /// Base sans ce tableau ni son drapeau (l'instrument le vérifie).
    fn an1_sans(conn: &Connection, nom: &str, drapeau: Option<&str>) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom]).expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![nom]).expect("tableau retiré");
        if let Some(d) = drapeau {
            conn.execute("DELETE FROM meta WHERE key=?1", params![d]).expect("drapeau retiré");
        }
        assert_eq!(an1_etat(conn, nom, drapeau), (0, 0, 0), "instrument : base sans « {nom} »");
    }

    /// Un tableau leurre écrit juste avant le semis : `last_insert_rowid()` rend SON identifiant.
    fn an1_leurre(conn: &Connection) -> i64 {
        conn.execute("INSERT INTO dashboard(name,created) VALUES(?1,0)", params![AN1_LEURRE]).expect("leurre");
        let id = conn.last_insert_rowid();
        let lu: i64 = conn.query_row("SELECT id FROM dashboard WHERE name=?1", params![AN1_LEURRE], |r| r.get(0)).expect("leurre relu");
        assert_eq!(id, lu, "instrument : `last_insert_rowid` désigne le leurre");
        id
    }

    /// (panneaux du leurre, sa vue, son repli) — attendu `(0, None, 0)`.
    fn an1_leurre_intact(conn: &Connection, leurre: i64) -> (i64, Option<i64>, i64) {
        let panneaux: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE dashboard_id=?1", params![leurre], |r| r.get(0)).expect("panneaux du leurre");
        let (vue, replie) = conn
            .query_row("SELECT view_id, collapsed FROM dashboard WHERE id=?1", params![leurre], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, i64>(1)?)))
            .expect("leurre");
        (panneaux, vue, replie)
    }

    /// (tableaux de ce nom, leurs panneaux, drapeau posé).
    fn an1_etat(conn: &Connection, nom: &str, drapeau: Option<&str>) -> (i64, i64, i64) {
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

    fn an1_panneaux_en_tout(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM panel", [], |r| r.get(0)).expect("panneaux")
    }

    /// (nom de la vue du tableau, repli).
    fn an1_vue(conn: &Connection, nom: &str) -> (Option<String>, i64) {
        conn.query_row(
            "SELECT v.name, d.collapsed FROM dashboard d LEFT JOIN view v ON v.id=d.view_id WHERE d.name=?1",
            params![nom],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?)),
        )
        .expect("vue du tableau")
    }

    /// L'en-tête rend `Ok(0)` (`RAISE(IGNORE)` sur l'`INSERT` du tableau de ce nom), un leurre écrit juste avant.
    fn an1_jouer_un_en_tete_qui_n_ecrit_rien(cas: An1Semis) {
        let (tag, nom, drapeau, n, vue, replie, semer) = cas;
        let conn = test_db();
        an1_sans(&conn, nom, drapeau);
        let avant = an1_panneaux_en_tout(&conn);
        let nom_sql = nom.replace('\'', "''");
        conn.execute_batch(&format!("CREATE TRIGGER an1_refus BEFORE INSERT ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(IGNORE); END;"))
            .expect("déclencheur de refus");
        let leurre = an1_leurre(&conn);
        semer(&conn);
        assert_eq!(an1_leurre_intact(&conn, leurre), (0, None, 0), "`{tag}` : aucun panneau ni rattachement sur le leurre");
        assert_eq!(an1_etat(&conn, nom, drapeau), (0, 0, 0), "`{tag}` : ni tableau, ni panneau, ni drapeau");
        assert_eq!(an1_panneaux_en_tout(&conn), avant, "`{tag}` : aucun panneau sous aucun tableau");
        assert!(conn.is_autocommit(), "`{tag}` : la transaction du semis est fermée");

        conn.execute_batch("DROP TRIGGER an1_refus;").expect("base revenue");
        semer(&conn);
        // CONTRÔLE POSITIF : les `n` panneaux sous LE tableau de ce nom (donc sous son identifiant), et aucun sous le
        // leurre. MUTANT QUI LE ROUGIT : `AN1_id_emprunte` (au semis rejoué, l'identifiant lu est celui de la ligne
        // d'avant, le leurre : panneaux et rattachement partent chez lui).
        let attendu = (1, n, i64::from(drapeau.is_some()));
        assert_eq!(an1_etat(&conn, nom, drapeau), attendu, "`{tag}` : rejoué ENTIER au démarrage suivant");
        assert_eq!(an1_leurre_intact(&conn, leurre), (0, None, 0), "`{tag}` : le leurre reste intact au semis rejoué");
        assert_eq!(an1_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` : rattaché à sa vue");
        semer(&conn);
        assert_eq!(an1_etat(&conn, nom, drapeau), attendu, "`{tag}` : aucun doublon ensuite");
    }

    /// `semer_la_vue_d_ensemble` : en-tête `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AN1_ensemble_ok0` (les 7 panneaux et
    /// le rattachement allaient au leurre, drapeau posé).
    #[test]
    fn an1_vue_d_ensemble_en_tete_qui_n_ecrit_rien_ne_seme_pas_sur_le_leurre() {
        an1_jouer_un_en_tete_qui_n_ecrit_rien(AN1_VUE_D_ENSEMBLE);
    }

    /// `semer_infra_et_logs` : en-tête `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AN1_infra_ok0`.
    #[test]
    fn an1_infra_et_logs_en_tete_qui_n_ecrit_rien_ne_seme_pas_sur_le_leurre() {
        an1_jouer_un_en_tete_qui_n_ecrit_rien(AN1_INFRA);
    }

    /// `seed_dashboard_head` (sécurité, réseau sortant) : en-tête `Ok(0)` = refus. MUTANT QUI LE ROUGIT : `AN1_tete_ok0`.
    #[test]
    fn an1_tete_partagee_en_tete_qui_n_ecrit_rien_ne_seme_pas_sur_le_leurre() {
        for cas in [AN1_SECURITE, AN1_EGRESS] {
            an1_jouer_un_en_tete_qui_n_ecrit_rien(cas);
        }
    }

    /// `rattacher_le_tableau_a_sa_vue` : un `UPDATE` qui rend `Ok(0)` (`RAISE(IGNORE)`) est un refus, pour les quatre
    /// semis sous drapeau et pour deux semis par nom (« Vue d'ensemble (rapide) », « Trafic web ») : rien n'est conservé,
    /// transaction fermée ; base revenue, le tableau entier DANS sa vue. MUTANT QUI LE ROUGIT : `AN1_rattachement_ok0`
    /// (tableau validé hors de sa vue, drapeau posé ou nom présent).
    #[test]
    fn an1_rattachement_qui_n_ecrit_rien_annule_le_semis() {
        for (tag, nom, drapeau, n, vue, replie, semer) in [AN1_VUE_D_ENSEMBLE, AN1_INFRA, AN1_SECURITE, AN1_EGRESS, AN1_RAPIDE, AN1_WEB] {
            let conn = test_db();
            an1_sans(&conn, nom, drapeau);
            let avant = an1_panneaux_en_tout(&conn);
            let nom_sql = nom.replace('\'', "''");
            conn.execute_batch(&format!("CREATE TRIGGER an1_refus BEFORE UPDATE ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(IGNORE); END;"))
                .expect("déclencheur de refus");
            semer(&conn);
            assert_eq!(an1_etat(&conn, nom, drapeau), (0, 0, 0), "`{tag}` : rattachement sans effet, rien n'est conservé");
            assert_eq!(an1_panneaux_en_tout(&conn), avant, "`{tag}` : aucun panneau conservé");
            assert!(conn.is_autocommit(), "`{tag}` : la transaction du semis est fermée");
            conn.execute_batch("DROP TRIGGER an1_refus;").expect("base revenue");
            semer(&conn);
            assert_eq!(an1_etat(&conn, nom, drapeau), (1, n, i64::from(drapeau.is_some())), "`{tag}` : rejoué entier");
            assert_eq!(an1_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` : contrôle positif, dans sa vue");
        }
    }

    /// `find_or_create_view` : un `INSERT INTO view` qui rend `Ok(0)` rend `None`, jamais l'identifiant de la dernière
    /// ligne insérée (le leurre ici) ; contrôle positif : base revenue, l'identifiant de la vue créée, puis le même relu.
    /// Par le semis : « Sécurité & détection » sans sa vue « Détection » (renommée) et la vue non créable — le tableau est
    /// semé HORS vue (`view_id` NULL, comportement documenté de `rattacher_le_tableau_a_sa_vue`), pas rattaché à son
    /// propre identifiant pris pour une vue. MUTANT QUI LE ROUGIT : `AN1_vue_ok0`.
    #[test]
    fn an1_vue_non_creee_rend_none_et_pas_un_identifiant_emprunte() {
        let conn = test_db();
        conn.execute_batch("CREATE TRIGGER an1_vue_refusee BEFORE INSERT ON view WHEN NEW.name='an1 vue neuve' BEGIN SELECT RAISE(IGNORE); END;")
            .expect("déclencheur de refus");
        let leurre = an1_leurre(&conn);
        assert_eq!(find_or_create_view(&conn, "an1 vue neuve"), None, "vue non créée : `None`, pas l'identifiant du leurre ({leurre})");
        let vues: i64 = conn.query_row("SELECT COUNT(*) FROM view WHERE name='an1 vue neuve'", [], |r| r.get(0)).expect("vues");
        assert_eq!(vues, 0, "aucune vue écrite");
        conn.execute_batch("DROP TRIGGER an1_vue_refusee;").expect("base revenue");
        let creee = find_or_create_view(&conn, "an1 vue neuve");
        let lue: i64 = conn.query_row("SELECT id FROM view WHERE name='an1 vue neuve'", [], |r| r.get(0)).expect("vue créée");
        assert_eq!(creee, Some(lue), "contrôle positif : l'identifiant de la vue créée");
        assert_eq!(find_or_create_view(&conn, "an1 vue neuve"), Some(lue), "vue présente : son identifiant, relu");

        let (_tag, nom, drapeau, n, _vue, _replie, semer) = AN1_SECURITE;
        let conn = test_db();
        an1_sans(&conn, nom, drapeau);
        conn.execute("UPDATE view SET name='an1 ancienne détection' WHERE name='Détection'", []).expect("vue renommée");
        conn.execute_batch("CREATE TRIGGER an1_vue_refusee BEFORE INSERT ON view WHEN NEW.name='Détection' BEGIN SELECT RAISE(IGNORE); END;")
            .expect("déclencheur de refus");
        let leurre = an1_leurre(&conn);
        semer(&conn);
        assert_eq!(an1_etat(&conn, nom, drapeau), (1, n, 1), "vue non créable : le tableau est semé, hors vue");
        let vue_id: Option<i64> = conn.query_row("SELECT view_id FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("view_id");
        assert_eq!(vue_id, None, "hors vue (`view_id` NULL), pas son propre identifiant pris pour une vue");
        assert_eq!(an1_leurre_intact(&conn, leurre), (0, None, 0), "le leurre reste intact");
        assert!(conn.is_autocommit(), "transaction fermée");
    }
}
