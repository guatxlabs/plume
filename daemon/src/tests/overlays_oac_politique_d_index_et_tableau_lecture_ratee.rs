// =====================================================================================
// `P10.20-b` (restes nommés : chargeurs OAC `index_policy` et `dashboard`) — UNE LECTURE RATÉE N'EST PLUS UN
// « LE NOM N'EXISTE PAS » MUET, ET RIEN N'EST COMPTÉ CHARGÉ QUI N'A PAS ÉTÉ ÉCRIT.
//
// VU sur `1d9ba63c` (`overlays_oac.rs`) : `load_overlay_index_policies` lisait l'existant par la projection
// `plan_upsert` (`plan_upsert_lu(..).unwrap_or(Insert)`), jetait son écriture (`let _ = conn.execute(…)`) puis
// comptait `charges += 1` : une politique de rétention refusée par le moteur était annoncée chargée, la base
// gardant l'ancienne. `load_overlay_dashboards` lisait par la même projection (`dashboard` n'a aucun
// UNIQUE(name), `db/schema.sql` : lecture ratée = tableau DOUBLON), jetait l'UPDATE `managed=1`, puis le
// `DELETE` des panneaux managés et l'INSERT de chacun : un DELETE passé suivi d'un INSERT refusé VIDAIT le
// tableau, compté chargé.
//
// CE QUE CES TÉMOINS JUGENT :
//  (1) `index_policy`, ligne existante et lecture refusée : ignorée, `(0, 1)`, l'ancienne politique intacte ;
//  (2) `index_policy`, aucune ligne et lecture refusée : l'INSERT tenté, borné par UNIQUE(name), pose la
//      politique et la compte `(1, 0)` (choix de `plan_oac_nom_unique_ou_aveu`, comme `field_filter`) ;
//  (3) `index_policy`, UPDATE puis INSERT refusés (`RAISE(ABORT)`) : `(0, 1)`, ancienne politique intacte ;
//  (4) `dashboard`, lecture refusée : aucun doublon, `(0, 1)`, panneaux d'avant gardés ;
//  (5) `dashboard`, UPDATE `managed=1` refusé : `(0, 1)`, panneaux d'avant gardés ;
//  (6) `dashboard`, INSERT du 2e panneau refusé : `(0, 1)`, panneaux d'avant gardés (mêmes titres, même
//      compte), aucune transaction laissée ouverte ; sur un tableau neuf, la ligne `dashboard` est annulée aussi ;
//  (7) contre-épreuves nominales : `(1, 0)`, panneaux remplacés, politique mise à jour ;
//  (9) `dashboard`, DELETE des panneaux managés refusé : `(0, 1)`, panneaux d'avant gardés ;
//  (10) `dashboard`, UPDATE `managed=1` ou INSERT d'un panneau SANS EFFET (`RAISE(IGNORE)`, `Ok(0)`) : `(0, 1)`,
//      panneaux d'avant gardés ;
//  (11) `SAVEPOINT` refusé (authorizer) : `(0, 1)`, aucun panneau touché ; `RELEASE` refusé : `(0, 1)`, panneaux
//      d'avant gardés, et la connexion n'est pas laissée dans une transaction ouverte (ROLLBACK complet) ;
//  (8) chaque refus est DIT : une ligne `[oac] WARN` nommant le genre, le nom, le geste et la cause du moteur,
//      lue sur le stderr d'un sous-processus ; aucune après la levée.
// MUTANTS JOUÉS (VERIF_MUT sous cfg!(test), retirés du source avant le commit) : `U7_PLAN_INDEX` (repli
// `Insert` muet remis sur `index_policy` : (8) rougit), `U7_PLAN_DASH` (même repli sur `dashboard` : (4)
// rougit), `U7_JETTE_INDEX` (écriture jetée et comptée : (3) rougit), `U7_JETTE_DASH_UPDATE` (UPDATE `managed=1`
// jeté : (5)), `U7_SANS_SAVEPOINT` (SAVEPOINT retiré : (6)), `U7_CHARGE_AVANT` (`charges` incrémenté avant
// l'écriture : (4) à (6)), `U7_SANS_ROLLBACK` (`ROLLBACK TO` omis, `RELEASE` seul : (6)). Puis, sur les
// branches que ces sept-là ne jouaient pas : `DEL_ERR_AVALEE` (DELETE refusé avalé : (9)), `UPD_OK0_ACCEPTE` et
// `PAN_OK0_ACCEPTE` (écriture sans effet acceptée : (10)), `SP_ERR_CHARGE` et `RELEASE_ERR_CHARGE` (refus compté
// chargé : (11)), `SANS_ROLLBACK_COMPLET` (repli `ROLLBACK` retiré : (11), transaction laissée ouverte).
// CE QUE CE LOT NE TIENT PAS :
//  - la trace « SQL brut accepté » d'un panneau de tableau se pose AVANT l'écriture, donc aussi pour un tableau
//    ignoré (à reprendre comme `library_panel`) ;
//  - l'absence d'UNIQUE(name) sur `dashboard` (schéma, porte à sens unique) ;
//  - le déclenchement en production n'est pas observé : les pannes sont fabriquées (authorizer, déclencheurs).
// =====================================================================================
mod overlays_oac_politique_d_index_et_tableau_lecture_ratee {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    const U7_POLITIQUE: &str = "u7-prod";
    const U7_TABLEAU: &str = "u7-tableau";
    const U7_REFUS_PANNEAU: &str = "u7 refus panneau";

    fn u7_dossier(etiquette: &str) -> crate::tmp_possede::TmpPossede {
        crate::tmp_possede::TmpPossede::neuf(&format!("u7-oac-{etiquette}"))
    }

    fn u7_ecrire_politique(d: &std::path::Path, jours: i64) {
        std::fs::write(d.join("p.json"), json!({"name": U7_POLITIQUE, "retention_days": jours}).to_string()).unwrap();
    }

    fn u7_ecrire_tableau(d: &std::path::Path, titres: &[&str]) {
        let panneaux: Vec<Value> = titres.iter().map(|t| json!({"title": t, "query": "search severity>=3 | stats count", "is_soql": true})).collect();
        std::fs::write(d.join("t.json"), json!({"name": U7_TABLEAU, "panels": panneaux}).to_string()).unwrap();
    }

    fn u7_politique(c: &Connection, d: &std::path::Path) -> (u32, u32) {
        let ch = crate::overlays_oac::load_overlay_index_policies(c, d);
        (ch.charges, ch.ignores)
    }

    fn u7_tableau(c: &Connection, d: &std::path::Path) -> (u32, u32) {
        let ch = crate::overlays_oac::load_overlay_dashboards(c, d);
        (ch.charges, ch.ignores)
    }

    /// (nombre de lignes, rétention de la ligne si unique).
    fn u7_retention(c: &Connection) -> (i64, Option<i64>) {
        let n: i64 = c.query_row("SELECT COUNT(*) FROM index_policy WHERE name=?1", params![U7_POLITIQUE], |r| r.get(0)).unwrap();
        let rd = if n == 1 { Some(c.query_row("SELECT retention_days FROM index_policy WHERE name=?1", params![U7_POLITIQUE], |r| r.get(0)).unwrap()) } else { None };
        (n, rd)
    }

    fn u7_tableaux(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![U7_TABLEAU], |r| r.get(0)).unwrap()
    }

    /// Titres des panneaux managés de TOUS les tableaux de ce nom, dans l'ordre.
    fn u7_panneaux(c: &Connection) -> Vec<String> {
        let mut st = c
            .prepare("SELECT p.title FROM panel p JOIN dashboard d ON d.id=p.dashboard_id WHERE d.name=?1 AND p.managed=1 ORDER BY d.id, p.position")
            .unwrap();
        let titres = st.query_map(params![U7_TABLEAU], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        titres
    }

    fn u7_refuser_la_lecture(c: &Connection, table: &'static str) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    fn u7_lever(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn u7_refuser_le_deuxieme_panneau(c: &Connection) {
        c.execute_batch(&format!(
            "CREATE TRIGGER u7_refus_panneau BEFORE INSERT ON panel WHEN (SELECT COUNT(*) FROM panel WHERE dashboard_id=NEW.dashboard_id AND managed=1) >= 1 BEGIN SELECT RAISE(ABORT,'{U7_REFUS_PANNEAU}'); END"
        ))
        .unwrap();
    }

    /// Un tableau chargé avec les panneaux A, B, C (contrôle : chargé, trois panneaux).
    fn u7_tableau_d_avant(c: &Connection, d: &std::path::Path) {
        u7_ecrire_tableau(d, &["A", "B", "C"]);
        assert_eq!(u7_tableau(c, d), (1, 0), "contrôle : tableau d'avant chargé");
        assert_eq!(u7_panneaux(c), ["A", "B", "C"], "contrôle : panneaux d'avant posés");
    }

    /// (1) Ligne existante et lecture refusée : ignorée, ancienne politique intacte.
    #[test]
    fn u7_politique_lecture_ratee_ligne_existante_ignoree() {
        let c = test_db();
        let d = u7_dossier("pol-lue");
        u7_ecrire_politique(&d, 30);
        assert_eq!(u7_politique(&c, &d), (1, 0), "contrôle : politique d'avant chargée");
        u7_ecrire_politique(&d, 90);
        let refus = u7_refuser_la_lecture(&c, "index_policy");
        let bilan = u7_politique(&c, &d);
        u7_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : la lecture d'index_policy a été refusée");
        assert_eq!(bilan, (0, 1), "lecture ratée, ligne existante : ignorée, rien compté chargé");
        assert_eq!(u7_retention(&c), (1, Some(30)), "l'ancienne politique reste, sans doublon");
    }

    /// (2) Aucune ligne et lecture refusée : l'INSERT tenté pose la politique (UNIQUE(name) le borne).
    #[test]
    fn u7_politique_lecture_ratee_sans_ligne_pose_par_l_insert_borne() {
        let c = test_db();
        let d = u7_dossier("pol-absente");
        u7_ecrire_politique(&d, 90);
        let refus = u7_refuser_la_lecture(&c, "index_policy");
        let bilan = u7_politique(&c, &d);
        u7_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : la lecture d'index_policy a été refusée");
        assert_eq!(bilan, (1, 0), "aucune ligne : l'INSERT tenté a posé la politique, comptée une fois");
        assert_eq!(u7_retention(&c), (1, Some(90)));
    }

    /// (3) UPDATE puis INSERT refusés par le moteur : non comptés chargés, ancienne politique intacte.
    #[test]
    fn u7_politique_ecriture_refusee_n_est_pas_comptee_chargee() {
        let c = test_db();
        let d = u7_dossier("pol-refus");
        u7_ecrire_politique(&d, 30);
        assert_eq!(u7_politique(&c, &d), (1, 0), "contrôle : politique d'avant chargée");
        c.execute_batch("CREATE TRIGGER u7_refus_maj BEFORE UPDATE ON index_policy BEGIN SELECT RAISE(ABORT,'u7 refus'); END").unwrap();
        u7_ecrire_politique(&d, 90);
        assert_eq!(u7_politique(&c, &d), (0, 1), "UPDATE refusé : ignoré");
        assert_eq!(u7_retention(&c), (1, Some(30)), "UPDATE refusé : l'ancienne politique reste");
        let c = test_db();
        c.execute_batch("CREATE TRIGGER u7_refus_ins BEFORE INSERT ON index_policy BEGIN SELECT RAISE(ABORT,'u7 refus'); END").unwrap();
        assert_eq!(u7_politique(&c, &d), (0, 1), "INSERT refusé : ignoré");
        assert_eq!(u7_retention(&c), (0, None));
    }

    /// (7) Contre-épreuve : posée puis mise à jour, comptée chaque fois.
    #[test]
    fn u7_politique_nominale_posee_puis_mise_a_jour() {
        let c = test_db();
        let d = u7_dossier("pol-nominale");
        u7_ecrire_politique(&d, 30);
        assert_eq!(u7_politique(&c, &d), (1, 0));
        u7_ecrire_politique(&d, 90);
        assert_eq!(u7_politique(&c, &d), (1, 0));
        assert_eq!(u7_retention(&c), (1, Some(90)));
    }

    /// (4) Lecture du tableau refusée : aucun doublon, panneaux d'avant gardés.
    #[test]
    fn u7_tableau_lecture_ratee_pas_de_doublon() {
        let c = test_db();
        let d = u7_dossier("tab-lu");
        u7_tableau_d_avant(&c, &d);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        let refus = u7_refuser_la_lecture(&c, "dashboard");
        let bilan = u7_tableau(&c, &d);
        u7_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : la lecture de dashboard a été refusée");
        assert_eq!(bilan, (0, 1), "lecture ratée : ignoré, rien compté chargé");
        assert_eq!(u7_tableaux(&c), 1, "aucun tableau doublon");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "panneaux d'avant gardés");
    }

    /// (5) UPDATE `managed=1` refusé : ignoré, panneaux d'avant gardés.
    #[test]
    fn u7_tableau_mise_a_jour_refusee_garde_les_panneaux() {
        let c = test_db();
        let d = u7_dossier("tab-maj");
        u7_tableau_d_avant(&c, &d);
        c.execute_batch("CREATE TRIGGER u7_refus_tab BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(ABORT,'u7 refus tableau'); END").unwrap();
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "UPDATE refusé : ignoré");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "panneaux d'avant gardés");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (6) INSERT du 2e panneau refusé : le tableau garde ses panneaux d'avant ; tableau neuf : rien ne reste.
    #[test]
    fn u7_tableau_deuxieme_panneau_refuse_garde_les_panneaux_d_avant() {
        let c = test_db();
        let d = u7_dossier("tab-pan");
        u7_tableau_d_avant(&c, &d);
        let avant = u7_panneaux(&c);
        u7_refuser_le_deuxieme_panneau(&c);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "2e panneau refusé : ignoré, rien compté chargé");
        assert_eq!(u7_panneaux(&c), avant, "le tableau garde ses panneaux d'avant (même compte, mêmes titres)");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
        // Tableau neuf : la ligne `dashboard` insérée est annulée avec ses panneaux.
        let c = test_db();
        let d = u7_dossier("tab-neuf");
        u7_refuser_le_deuxieme_panneau(&c);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "tableau neuf, 2e panneau refusé : ignoré");
        assert_eq!((u7_tableaux(&c), u7_panneaux(&c).len()), (0, 0), "rien ne reste du tableau neuf");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (7) Contre-épreuve : panneaux remplacés, tableau compté, un seul tableau.
    #[test]
    fn u7_tableau_nominal_remplace_les_panneaux() {
        let c = test_db();
        let d = u7_dossier("tab-nominal");
        u7_tableau_d_avant(&c, &d);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (1, 0));
        assert_eq!(u7_panneaux(&c), ["X", "Y"]);
        assert_eq!(u7_tableaux(&c), 1);
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// Refuse l'opération `operation` sur le SAVEPOINT du chargeur ; rend le compteur de refus.
    fn u7_refuser_le_point_de_reprise(c: &Connection, operation: TransactionOperation) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Savepoint { operation: op, savepoint_name } if op == operation && savepoint_name == "oac_dashboard" => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// (9) DELETE des panneaux managés refusé : ignoré, panneaux d'avant gardés.
    #[test]
    fn u7_tableau_retrait_des_panneaux_refuse_garde_les_panneaux() {
        let c = test_db();
        let d = u7_dossier("tab-del");
        u7_tableau_d_avant(&c, &d);
        c.execute_batch("CREATE TRIGGER u7_refus_del BEFORE DELETE ON panel BEGIN SELECT RAISE(ABORT,'u7 refus retrait'); END").unwrap();
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "DELETE refusé : ignoré, rien compté chargé");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "panneaux d'avant gardés, aucun panneau du fichier ajouté");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (10) UPDATE `managed=1` sans effet (`RAISE(IGNORE)`, `Ok(0)`) : ignoré, panneaux d'avant gardés.
    #[test]
    fn u7_tableau_mise_a_jour_sans_effet_n_est_pas_comptee_chargee() {
        let c = test_db();
        let d = u7_dossier("tab-maj0");
        u7_tableau_d_avant(&c, &d);
        c.execute_batch("CREATE TRIGGER u7_maj_ignoree BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(IGNORE); END").unwrap();
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "UPDATE sans effet : ignoré");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "panneaux d'avant gardés");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (10) INSERT du 2e panneau sans effet (`RAISE(IGNORE)`, `Ok(0)`) : ignoré, le tableau n'est pas réduit.
    #[test]
    fn u7_tableau_panneau_sans_effet_garde_les_panneaux_d_avant() {
        let c = test_db();
        let d = u7_dossier("tab-pan0");
        u7_tableau_d_avant(&c, &d);
        c.execute_batch(
            "CREATE TRIGGER u7_panneau_ignore BEFORE INSERT ON panel WHEN (SELECT COUNT(*) FROM panel WHERE dashboard_id=NEW.dashboard_id AND managed=1) >= 1 BEGIN SELECT RAISE(IGNORE); END",
        )
        .unwrap();
        u7_ecrire_tableau(&d, &["X", "Y"]);
        assert_eq!(u7_tableau(&c, &d), (0, 1), "2e panneau sans effet : ignoré, rien compté chargé");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "le tableau garde ses panneaux d'avant, pas réduit à [X]");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (11) SAVEPOINT refusé : ignoré, aucun panneau touché.
    #[test]
    fn u7_tableau_point_de_reprise_refuse_ignore() {
        let c = test_db();
        let d = u7_dossier("tab-sp");
        u7_tableau_d_avant(&c, &d);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        let refus = u7_refuser_le_point_de_reprise(&c, TransactionOperation::Begin);
        let bilan = u7_tableau(&c, &d);
        u7_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : le SAVEPOINT a été refusé");
        assert_eq!(bilan, (0, 1), "SAVEPOINT refusé : ignoré, rien compté chargé");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "aucun panneau touché");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (11) RELEASE refusé : ignoré, écritures annulées, connexion rendue hors transaction.
    #[test]
    fn u7_tableau_validation_refusee_annule_tout_et_ferme_la_transaction() {
        let c = test_db();
        let d = u7_dossier("tab-rel");
        u7_tableau_d_avant(&c, &d);
        u7_ecrire_tableau(&d, &["X", "Y"]);
        let refus = u7_refuser_le_point_de_reprise(&c, TransactionOperation::Release);
        let bilan = u7_tableau(&c, &d);
        let hors_transaction = c.is_autocommit();
        u7_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : le RELEASE a été refusé");
        assert_eq!(bilan, (0, 1), "RELEASE refusé : ignoré, rien compté chargé");
        assert!(hors_transaction, "RELEASE refusé : la connexion n'est pas laissée dans une transaction ouverte");
        assert_eq!(u7_panneaux(&c), ["A", "B", "C"], "écritures annulées, panneaux d'avant gardés");
    }

    /// (8) Chaque refus est DIT au journal, avec la cause du moteur ; le chemin nominal reste muet.
    #[test]
    fn u7_refus_dits_au_journal() {
        const ENFANT: &str = "OAC_U7_ENFANT_JOURNAL";
        const LEVEE: &str = "OAC-U7-LEVEE";
        if std::env::var(ENFANT).is_ok() {
            let c = test_db();
            let dp = u7_dossier("j-pol");
            let dt = u7_dossier("j-tab");
            u7_ecrire_politique(&dp, 30);
            println!("OAC-U7-POL-AVANT:{:?}", u7_politique(&c, &dp));
            u7_tableau_d_avant(&c, &dt);
            u7_ecrire_politique(&dp, 90);
            u7_ecrire_tableau(&dt, &["X", "Y"]);
            u7_refuser_la_lecture(&c, "index_policy");
            let cause = plan_upsert_lu(&c, "index_policy", U7_POLITIQUE).err().expect("fixture : lecture refusée");
            println!("OAC-U7-CAUSE-POL:{cause}");
            eprintln!("OAC-U7-PHASE-POL");
            println!("OAC-U7-POL:{:?}", u7_politique(&c, &dp));
            u7_lever(&c);
            u7_refuser_la_lecture(&c, "dashboard");
            let cause = plan_upsert_lu(&c, "dashboard", U7_TABLEAU).err().expect("fixture : lecture refusée");
            println!("OAC-U7-CAUSE-TAB:{cause}");
            eprintln!("OAC-U7-PHASE-TAB");
            println!("OAC-U7-TAB:{:?}", u7_tableau(&c, &dt));
            u7_lever(&c);
            u7_refuser_le_deuxieme_panneau(&c);
            eprintln!("OAC-U7-PHASE-PAN");
            println!("OAC-U7-PAN:{:?}", u7_tableau(&c, &dt));
            c.execute_batch("DROP TRIGGER u7_refus_panneau").unwrap();
            eprintln!("{LEVEE}");
            println!("OAC-U7-NOMINAL:{:?}:{:?}", u7_politique(&c, &dp), u7_tableau(&c, &dt));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::overlays_oac_politique_d_index_et_tableau_lecture_ratee::u7_refus_dits_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let segment = |debut: &str, fin: &str| -> Vec<String> {
            let apres = stderr.split_once(debut).unwrap_or_else(|| panic!("contrôle : phase `{debut}` jouée : {stderr}")).1;
            let dedans = apres.split_once(fin).unwrap_or_else(|| panic!("contrôle : phase `{fin}` jouée : {stderr}")).0;
            dedans.lines().filter(|l| l.starts_with("[oac] WARN")).map(str::to_string).collect()
        };
        let cause = |etiquette: &str| -> String {
            stdout
                .lines()
                .find_map(|l| l.strip_prefix(&format!("OAC-U7-CAUSE-{etiquette}:")).map(str::to_string))
                .filter(|c| !c.trim().is_empty())
                .unwrap_or_else(|| panic!("contrôle : cause du moteur rendue ({etiquette}) : {stdout}"))
        };
        assert!(stdout.contains("OAC-U7-POL-AVANT:(1, 0)"), "contrôle : politique d'avant chargée : {stdout}");
        // Politique : la lecture ratée est avouée, puis l'INSERT tenté est refusé par UNIQUE(name) et dit.
        let pol = segment("OAC-U7-PHASE-POL", "OAC-U7-PHASE-TAB");
        let cause_pol = cause("POL");
        assert!(stdout.contains("OAC-U7-POL:(0, 1)"), "contrôle : politique ignorée : {stdout}");
        assert!(
            pol.iter().any(|l| l.starts_with(&format!("[oac] WARN index-policy '{U7_POLITIQUE}'"))
                && l.contains("lecture de l'existant NON faite")
                && l.contains(&format!("({cause_pol})"))),
            "la lecture ratée de la politique est dite, avec la cause du moteur `{cause_pol}` : {pol:?}"
        );
        assert!(
            pol.iter().any(|l| l.starts_with(&format!("[oac] WARN index-policy '{U7_POLITIQUE}'")) && l.contains("écriture refusée")),
            "l'INSERT refusé par UNIQUE(name) est dit : {pol:?}"
        );
        // Tableau : lecture ratée, une ligne, overlay ignoré.
        let tab = segment("OAC-U7-PHASE-TAB", "OAC-U7-PHASE-PAN");
        let cause_tab = cause("TAB");
        assert!(stdout.contains("OAC-U7-TAB:(0, 1)"), "contrôle : tableau ignoré : {stdout}");
        assert_eq!(tab.len(), 1, "une ligne, ni plus ni moins : {tab:?}");
        assert!(tab[0].starts_with(&format!("[oac] WARN dashboard '{U7_TABLEAU}'")), "genre et nom : {tab:?}");
        assert!(tab[0].contains("lecture de l'existant NON faite") && tab[0].contains(&format!("({cause_tab})")), "geste et cause `{cause_tab}` : {tab:?}");
        // Panneau refusé : une ligne qui nomme le panneau, la cause du moteur et l'annulation.
        let pan = segment("OAC-U7-PHASE-PAN", LEVEE);
        assert!(stdout.contains("OAC-U7-PAN:(0, 1)"), "contrôle : tableau ignoré sur panneau refusé : {stdout}");
        assert_eq!(pan.len(), 1, "une ligne, ni plus ni moins : {pan:?}");
        assert!(pan[0].starts_with(&format!("[oac] WARN dashboard '{U7_TABLEAU}'")), "genre et nom : {pan:?}");
        assert!(pan[0].contains("panneau 2 refusé") && pan[0].contains(U7_REFUS_PANNEAU), "panneau et cause du moteur : {pan:?}");
        assert!(pan[0].contains("écritures annulées, panneaux d'avant gardés"), "l'annulation est dite : {pan:?}");
        // Levée : chargés, muets.
        assert!(stdout.contains("OAC-U7-NOMINAL:(1, 0):(1, 0)"), "contrôle : levée, chargés : {stdout}");
        let apres = stderr.split_once(LEVEE).unwrap().1;
        assert_eq!(apres.lines().filter(|l| l.starts_with("[oac] WARN")).count(), 0, "chemin nominal muet : {apres}");
    }
}
