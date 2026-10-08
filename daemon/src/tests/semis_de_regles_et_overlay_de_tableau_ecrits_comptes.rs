// =====================================================================================
// `P10.20-w` (rang six) et `P10.28-l` (deux des treize semis) — LES DEUX SEMIS DE RÈGLES AUDITÉS ET LE CHARGEMENT
// D'OVERLAY DE TABLEAU DE BORD COMPTENT LEURS ÉCRITURES AVANT D'AFFIRMER QUOI QUE CE SOIT.
//
// LES DÉFAUTS, LUS SUR aa78ddd :
//  * `seed_ti_alert_rules`, `seed_risk_rules` (seeds.rs) : drapeau `seeded_*` posé EN PREMIER (écriture avalée), règles
//    comptées par `is_ok()`, puis `audit_config_change` attestait « {n} règle(s) seedée(s) ». Une règle refusée laissait
//    un semis PARTIEL, jamais retenté (drapeau posé), et un audit qui l'affirmait ; toutes refusées, un drapeau
//    définitif et un audit « 0 règle(s) ».
//  * `load_overlay_dashboards` (overlays_oac.rs) : INSERT du tableau avalé, puis `last_insert_rowid()` lu quand même,
//    puis `DELETE FROM panel WHERE dashboard_id=did AND managed=1` : sur un INSERT refusé, `did` est l'identifiant de
//    la dernière ligne insérée sur la connexion, et les panneaux managés d'un AUTRE tableau sont effacés, puis
//    remplacés par ceux du fichier.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les onze autres semis de `P10.28-l` (règles et playbooks : leur drapeau reste
// posé avant les données) ; la branche `Update` de `load_overlay_dashboards` (UPDATE `managed=1` avalé, identifiant
// juste) ; les panneaux d'overlay insérés un à un et avalés (un panneau refusé laisse un tableau incomplet) ; l'audit
// refusé APRÈS un semis validé (avoué sur la sortie d'erreur, non retenté).
// =====================================================================================
mod semis_de_regles_et_overlay_de_tableau_ecrits_comptes {
    use super::*;

    /// (règles semées de ces noms, drapeau posé, lignes d'audit de ce genre au registre).
    fn sroc_etat(conn: &Connection, noms: &[&str], drapeau: &str, genre: &str) -> (i64, i64, i64) {
        let mut regles = 0i64;
        for nom in noms {
            regles += conn.query_row("SELECT COUNT(*) FROM rule WHERE name=?1", params![nom], |r| r.get::<_, i64>(0)).expect("règles");
        }
        let pose: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau");
        let audits: i64 = conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![genre], |r| r.get(0)).expect("registre");
        (regles, pose, audits)
    }

    fn sroc_detail_d_audit(conn: &Connection, genre: &str) -> String {
        conn.query_row("SELECT detail FROM ledger WHERE kind=?1", params![genre], |r| r.get(0)).expect("une ligne d'audit")
    }

    /// CE QU'IL TIENT, pour les deux semis audités et trois refus (toutes les règles, la SECONDE règle seule, le
    /// drapeau) : après le refus, AUCUNE règle, AUCUN drapeau, AUCUN audit, transaction fermée ; au démarrage suivant
    /// (base revenue), le semis entier, le drapeau, UN audit qui porte le compte RÉEL (2) ; au démarrage d'après, rien
    /// de plus. MUTATIONS QUI LE FONT ROUGIR : un INSERT de règle replacé en `let _` (`VERIF_MUT=ti_let`, `risk_let`).
    #[test]
    fn sroc_un_semis_de_regles_refuse_n_est_ni_drapeaute_ni_audite_et_se_rejoue() {
        let ti: Vec<&str> = table_declaree!(TI_ALERT_RULES).iter().map(|r| r.0).collect();
        let rba: Vec<&str> = table_declaree!(RISK_STARTER_RULES).iter().map(|r| r.0).collect();
        let semis: [(&str, &str, &str, &Vec<&str>, fn(&Connection)); 2] = [
            ("ti", "seeded_ti_alert_rules", "config.seed.ti_alert", &ti, seed_ti_alert_rules),
            ("rba", "seeded_risk_rules", "config.seed.risk_rules", &rba, seed_risk_rules),
        ];
        let mut joues = 0;
        for (tag, drapeau, genre, noms, semer) in semis {
            let refus = [
                ("toutes les règles", "BEFORE INSERT ON rule BEGIN SELECT RAISE(ABORT,'sroc refus'); END".to_string()),
                (
                    "la seconde règle",
                    format!("BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT RAISE(ABORT,'sroc refus'); END", noms[1].replace('\'', "''")),
                ),
                ("le drapeau", format!("BEFORE INSERT ON meta WHEN NEW.key='{drapeau}' BEGIN SELECT RAISE(ABORT,'sroc refus'); END")),
            ];
            for (quoi, corps) in refus {
                let conn = test_db();
                conn.execute_batch(&format!("CREATE TRIGGER sroc_refus {corps};")).expect("déclencheur de refus");
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (0, 0, 0), "`{tag}`, {quoi} refusé(e) : ni règle, ni drapeau, ni audit");
                assert!(conn.is_autocommit(), "`{tag}`, {quoi} refusé(e) : la transaction du semis est fermée");
                conn.execute_batch("DROP TRIGGER sroc_refus;").expect("base revenue");
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (2, 1, 1), "`{tag}` : au démarrage suivant, le semis entier et UN audit");
                assert!(sroc_detail_d_audit(&conn, genre).starts_with("2 règle(s)"), "`{tag}` : l'audit porte le compte réel");
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (2, 1, 1), "`{tag}` : et rien de plus ensuite");
                joues += 1;
            }
        }
        assert_eq!(joues, 6, "les six cas sont joués");
    }

    /// RISQUE DE RÉFUTATION MESURÉ : une base qui porte DÉJÀ les règles de ce nom mais pas le drapeau (drapeau perdu)
    /// n'est pas refusée — `rule.name` n'a pas d'unicité, l'INSERT d'un homonyme passe, comme avant le correctif. Le
    /// tout-ou-rien ne rend donc pas un semis perpétuellement refusé sur doublon de nom ; et une base déjà semée
    /// (drapeau présent) n'est pas touchée du tout.
    #[test]
    fn sroc_un_homonyme_deja_present_ne_rend_pas_le_semis_perpetuellement_refuse() {
        let conn = test_db();
        seed_ti_alert_rules(&conn);
        seed_risk_rules(&conn);
        let avant: i64 = conn.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).unwrap();
        seed_ti_alert_rules(&conn);
        seed_risk_rules(&conn);
        let apres: i64 = conn.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0)).unwrap();
        assert_eq!(avant, apres, "base déjà semée : rien n'est réécrit");
        conn.execute_batch("DELETE FROM meta WHERE key IN ('seeded_ti_alert_rules','seeded_risk_rules');").unwrap();
        seed_ti_alert_rules(&conn);
        seed_risk_rules(&conn);
        let poses: i64 = conn
            .query_row("SELECT COUNT(*) FROM meta WHERE key IN ('seeded_ti_alert_rules','seeded_risk_rules')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(poses, 2, "les homonymes ne font pas refuser le semis");
    }

    /// LES DEUX SEMIS AUDITÉS, quand une écriture REND `Ok(0)` au lieu d'échouer (déclencheur `RAISE(IGNORE)`) : sur la
    /// seconde règle, sur toutes, sur le drapeau. CE QU'IL TIENT : une écriture qui n'a rien écrit est un REFUS — ni
    /// règle, ni drapeau, ni audit ; au démarrage suivant, le semis entier et UN audit dont le compte est celui des
    /// lignes de la table déclarée (pas des tentatives). MUTATIONS QUI LE FONT ROUGIR : `Ok(0)` accepté et compté par
    /// lignes écrites (`VERIF_MUT=ti_ok0`, `risk_ok0` — la forme du premier passage, semis PARTIEL validé, drapeau posé) ;
    /// le drapeau ignoré accepté (`VERIF_MUT=drapeau_ok0` — semis rejoué et ré-audité à chaque démarrage).
    #[test]
    fn sroc_une_ecriture_de_semis_qui_n_ecrit_rien_est_un_refus() {
        let ti: Vec<&str> = table_declaree!(TI_ALERT_RULES).iter().map(|r| r.0).collect();
        let rba: Vec<&str> = table_declaree!(RISK_STARTER_RULES).iter().map(|r| r.0).collect();
        let semis: [(&str, &str, &str, &Vec<&str>, fn(&Connection)); 2] = [
            ("ti", "seeded_ti_alert_rules", "config.seed.ti_alert", &ti, seed_ti_alert_rules),
            ("rba", "seeded_risk_rules", "config.seed.risk_rules", &rba, seed_risk_rules),
        ];
        let mut joues = 0;
        for (tag, drapeau, genre, noms, semer) in semis {
            let total = noms.len() as i64;
            assert!(total >= 2, "`{tag}` : le montage exige au moins deux règles déclarées");
            let ignores = [
                ("toutes les règles", "BEFORE INSERT ON rule BEGIN SELECT RAISE(IGNORE); END".to_string()),
                (
                    "la seconde règle",
                    format!("BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT RAISE(IGNORE); END", noms[1].replace('\'', "''")),
                ),
                ("le drapeau", format!("BEFORE INSERT ON meta WHEN NEW.key='{drapeau}' BEGIN SELECT RAISE(IGNORE); END")),
            ];
            for (quoi, corps) in ignores {
                let conn = test_db();
                conn.execute_batch(&format!("CREATE TRIGGER sroc_ignore {corps};")).expect("déclencheur d'ignorance");
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (0, 0, 0), "`{tag}`, {quoi} ignoré(e) (Ok(0)) : ni règle, ni drapeau, ni audit");
                assert!(conn.is_autocommit(), "`{tag}`, {quoi} ignoré(e) : la transaction du semis est fermée");
                conn.execute_batch("DROP TRIGGER sroc_ignore;").expect("base revenue");
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (total, 1, 1), "`{tag}` : au démarrage suivant, le semis entier et UN audit");
                assert_eq!(
                    sroc_detail_d_audit(&conn, genre).split(' ').next(),
                    Some(total.to_string().as_str()),
                    "`{tag}` : l'audit porte le compte des lignes écrites"
                );
                semer(&conn);
                assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (total, 1, 1), "`{tag}` : et rien de plus ensuite");
                joues += 1;
            }
        }
        assert_eq!(joues, 6, "les six cas sont joués");
    }

    /// LE `BEGIN` REFUSÉ de `semer_sous_son_drapeau` (une transaction déjà ouverte sur la connexion) : CE QU'IL TIENT —
    /// aucun des deux semis audités n'écrit d'audit, ni de règle, ni de drapeau, même lu DANS la transaction ouverte ;
    /// après sa fermeture, le semis suivant passe entier. MUTATION QUI LE FAIT ROUGIR : le `BEGIN` refusé rendu comme un
    /// semis validé (`VERIF_MUT=begin_true` — l'audit atteste « 0 règle(s) » d'un semis qui n'a pas eu lieu).
    #[test]
    fn sroc_un_begin_refuse_n_atteste_aucun_semis() {
        let ti: Vec<&str> = table_declaree!(TI_ALERT_RULES).iter().map(|r| r.0).collect();
        let rba: Vec<&str> = table_declaree!(RISK_STARTER_RULES).iter().map(|r| r.0).collect();
        let semis: [(&str, &str, &str, &Vec<&str>, fn(&Connection)); 2] = [
            ("ti", "seeded_ti_alert_rules", "config.seed.ti_alert", &ti, seed_ti_alert_rules),
            ("rba", "seeded_risk_rules", "config.seed.risk_rules", &rba, seed_risk_rules),
        ];
        for (tag, drapeau, genre, noms, semer) in semis {
            let conn = test_db();
            conn.execute_batch("BEGIN").expect("une transaction déjà ouverte");
            semer(&conn);
            assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (0, 0, 0), "`{tag}`, BEGIN refusé : ni règle, ni drapeau, ni audit");
            conn.execute_batch("ROLLBACK").expect("fermeture");
            semer(&conn);
            assert_eq!(sroc_etat(&conn, noms, drapeau, genre), (noms.len() as i64, 1, 1), "`{tag}` : ensuite, le semis entier et UN audit");
        }
    }

    fn sroc_panneaux(conn: &Connection, did: i64) -> Vec<String> {
        let mut st = conn.prepare("SELECT title FROM panel WHERE dashboard_id=?1 AND managed=1 ORDER BY id").unwrap();
        st.query_map(params![did], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap()
    }

    /// CE QU'IL TIENT : un tableau d'overlay dont l'INSERT est refusé est IGNORÉ et compté (`ignores` = 1, `charges` =
    /// 0), et les panneaux managés d'un AUTRE tableau — celui dont l'identifiant est le dernier inséré sur la
    /// connexion — restent INTACTS (ni effacés, ni remplacés) ; au chargement suivant (base revenue), le tableau est
    /// chargé avec ses panneaux, l'autre toujours intact. MUTATION QUI LE FAIT ROUGIR : l'INSERT replacé en `let _`
    /// suivi de `last_insert_rowid()` (`VERIF_MUT=overlay_let`, la forme d'avant).
    #[test]
    fn sroc_un_tableau_d_overlay_refuse_ne_touche_pas_les_panneaux_d_un_autre() {
        let conn = test_db();
        // L'AUTRE tableau : ses panneaux d'abord (pas de clé étrangère), puis lui-même, pour que son identifiant soit le
        // dernier inséré sur la connexion — celui qu'un `last_insert_rowid()` emprunterait.
        conn.execute_batch(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,managed) VALUES(9001,'autre-un','search *',1,'table',0,1);
             INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,managed) VALUES(9001,'autre-deux','search *',1,'table',1,1);
             INSERT INTO dashboard(id,name,created,managed) VALUES(9001,'sroc autre',0,1);",
        )
        .unwrap();
        assert_eq!(conn.last_insert_rowid(), 9001, "le montage : l'identifiant de l'autre tableau est le dernier inséré");
        let dir = crate::tmp_possede::TmpPossede::neuf("sroc-overlay");
        std::fs::write(
            dir.join("nouveau.json"),
            r#"{"name":"sroc nouveau","panels":[{"title":"du-fichier","query":"search source=sshd | stats count","viz":"table"}]}"#,
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER sroc_refus BEFORE INSERT ON dashboard BEGIN SELECT RAISE(ABORT,'sroc refus'); END;").unwrap();
        let ch = crate::overlays_oac::load_overlay_dashboards(&conn, &dir);
        assert_eq!((ch.charges, ch.ignores), (0, 1), "INSERT refusé : le tableau est ignoré ET compté");
        assert_eq!(sroc_panneaux(&conn, 9001), vec!["autre-un".to_string(), "autre-deux".to_string()], "les panneaux de l'AUTRE tableau sont intacts");
        let nouveau: i64 = conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name='sroc nouveau'", [], |r| r.get(0)).unwrap();
        assert_eq!(nouveau, 0, "aucun tableau écrit");
        conn.execute_batch("DROP TRIGGER sroc_refus;").unwrap();
        let ch = crate::overlays_oac::load_overlay_dashboards(&conn, &dir);
        assert_eq!((ch.charges, ch.ignores), (1, 0), "base revenue : le tableau est chargé");
        let did: i64 = conn.query_row("SELECT id FROM dashboard WHERE name='sroc nouveau'", [], |r| r.get(0)).unwrap();
        assert_eq!(sroc_panneaux(&conn, did), vec!["du-fichier".to_string()], "avec ses panneaux");
        assert_eq!(sroc_panneaux(&conn, 9001), vec!["autre-un".to_string(), "autre-deux".to_string()], "l'autre toujours intact");
    }

    /// LE BRAS `Ok(n)`, n ≠ 1, de `load_overlay_dashboards` : un déclencheur `RAISE(IGNORE)` sur `dashboard` fait rendre
    /// `Ok(0)` à l'INSERT. CE QU'IL TIENT : le tableau est ignoré et compté, les panneaux de l'AUTRE tableau (dernier
    /// identifiant inséré) restent intacts. MUTATION QUI LE FAIT ROUGIR : `Ok(n)` lu comme un succès
    /// (`VERIF_MUT=overlay_ok0` — l'identifiant d'un autre tableau est emprunté, ses panneaux sont remplacés).
    #[test]
    fn sroc_un_tableau_d_overlay_qui_n_ecrit_rien_ne_touche_pas_les_panneaux_d_un_autre() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,managed) VALUES(9002,'autre-un','search *',1,'table',0,1);
             INSERT INTO dashboard(id,name,created,managed) VALUES(9002,'sroc autre ok0',0,1);",
        )
        .unwrap();
        assert_eq!(conn.last_insert_rowid(), 9002, "le montage : l'identifiant de l'autre tableau est le dernier inséré");
        let dir = crate::tmp_possede::TmpPossede::neuf("sroc-overlay-ok0");
        std::fs::write(
            dir.join("nouveau.json"),
            r#"{"name":"sroc nouveau ok0","panels":[{"title":"du-fichier","query":"search source=sshd | stats count","viz":"table"}]}"#,
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER sroc_ignore BEFORE INSERT ON dashboard BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let ch = crate::overlays_oac::load_overlay_dashboards(&conn, &dir);
        assert_eq!((ch.charges, ch.ignores), (0, 1), "INSERT sans ligne écrite : le tableau est ignoré ET compté");
        assert_eq!(sroc_panneaux(&conn, 9002), vec!["autre-un".to_string()], "les panneaux de l'AUTRE tableau sont intacts");
    }
}
