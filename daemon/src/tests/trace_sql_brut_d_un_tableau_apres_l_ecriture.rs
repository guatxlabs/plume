// =====================================================================================
// `P10.20-b` (reste nommé de U7 : la trace « SQL brut accepté » d'un panneau de tableau OAC) — LE REGISTRE NE DIT
// « ACCEPTÉ » QUE D'UN TABLEAU DONT L'ÉCRITURE A ÉTÉ VALIDÉE.
//
// VU sur `7c167699` : `load_overlay_dashboards` (`overlays_oac.rs`) appelait `tracer_panneau_sql_brut` dès qu'un
// panneau du fichier était en SQL brut, AVANT la lecture de l'existant (`plan_oac_ou_aveu`), avant le refus d'une
// copie UI homonyme (`SkipUser`), avant le SAVEPOINT et avant l'écriture : le registre non purgeable
// (`ledger`, `kind='config.overlay.raw_sql'`) affirmait « accepté au chargement » pour un tableau IGNORÉ — à chaque
// démarrage tant qu'un tableau UI du même nom existe. Le jumeau `library_panel` traçait déjà après l'écriture.
//
// CE QUE CES TÉMOINS JUGENT, par le point d'entrée `load_overlay_dashboards` (celui qu'appelle `load_overlays`) :
//  (1) tableau chargé avec un panneau SQL brut : `(1, 0)`, exactement une trace (contrôle positif) ;
//  (2) tableau de panneaux SOQL seuls : chargé, aucune trace ;
//  (3) tableau UI homonyme (`managed=2`) : `(0, 1)`, aucune trace, aucun tableau managé posé ;
//  (4) écriture d'un panneau refusée (`RAISE(ABORT)` sur `panel`) : `(0, 1)`, aucune trace, annulation entière
//      (panneaux d'avant gardés) ;
//  (5) lecture de l'existant refusée : `(0, 1)`, aucune trace ;
//  (6) SAVEPOINT refusé, puis RELEASE refusé : `(0, 1)`, aucune trace.
// MUTANTS JOUÉS (variable `VERIF_MUT` sous cfg!(test), retirés du source avant le commit) :
// `V3_TRACE_AVANT_LE_PLAN` (trace remise à son ancien site : (3), (4), (5), (6) rougissent),
// `V3_TRACE_DANS_LE_REFUS` (trace dans le bras d'écriture refusée : (1) et (4) rougissent),
// `V3_TRACE_SOUS_LE_POINT_DE_REPRISE` (trace posée sous le SAVEPOINT, avant l'écriture : reste VERT — le
// `ROLLBACK TO` emporte la trace avec l'écriture refusée ; mutant équivalent, ce site serait juste lui aussi).
// CE QUE CE LOT NE TIENT PAS :
//  - un tableau rechargé à l'identique à chaque démarrage est retracé à chaque démarrage (comme `library_panel`) ;
//  - si la trace elle-même est refusée par le moteur, `audit_config_change` reste jeté (`let _`, inchangé) ;
//  - le déclenchement en production n'est pas observé : les pannes sont fabriquées (authorizer, déclencheurs).
// =====================================================================================
mod trace_sql_brut_d_un_tableau_apres_l_ecriture {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    const V3_TABLEAU: &str = "v3-tableau";

    fn v3_dossier(etiquette: &str) -> crate::tmp_possede::TmpPossede {
        crate::tmp_possede::TmpPossede::neuf(&format!("v3-oac-{etiquette}"))
    }

    /// Tableau à deux panneaux : le second en SQL brut si `brut`, sinon les deux en SOQL.
    fn v3_ecrire_tableau(d: &std::path::Path, brut: bool) {
        let second = if brut {
            json!({"title": "B", "query": "SELECT COUNT(*) AS n FROM event", "is_soql": false})
        } else {
            json!({"title": "B", "query": "search severity>=3 | stats count", "is_soql": true})
        };
        let panneaux = json!([{"title": "A", "query": "search severity>=3 | stats count", "is_soql": true}, second]);
        std::fs::write(d.join("t.json"), json!({"name": V3_TABLEAU, "panels": panneaux}).to_string()).unwrap();
    }

    fn v3_charger(c: &Connection, d: &std::path::Path) -> (u32, u32) {
        let ch = crate::overlays_oac::load_overlay_dashboards(c, d);
        (ch.charges, ch.ignores)
    }

    fn v3_traces(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM ledger WHERE kind='config.overlay.raw_sql'", [], |r| r.get(0)).unwrap()
    }

    fn v3_panneaux(c: &Connection) -> Vec<String> {
        let mut st = c
            .prepare("SELECT p.title FROM panel p JOIN dashboard d ON d.id=p.dashboard_id WHERE d.name=?1 AND p.managed=1 ORDER BY d.id, p.position")
            .unwrap();
        let titres = st.query_map(params![V3_TABLEAU], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        titres
    }

    fn v3_lever(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// (1) Chargé avec un panneau SQL brut : une trace, exactement.
    #[test]
    fn v3_tableau_sql_brut_charge_trace_une_fois() {
        let c = test_db();
        let d = v3_dossier("nominal");
        v3_ecrire_tableau(&d, true);
        assert_eq!(v3_charger(&c, &d), (1, 0), "nominal : chargé");
        assert_eq!(v3_panneaux(&c), ["A", "B"], "nominal : panneaux posés");
        assert_eq!(v3_traces(&c), 1, "nominal : le SQL brut posé est tracé une fois");
    }

    /// (2) Panneaux SOQL seuls : chargé, rien tracé.
    #[test]
    fn v3_tableau_soql_seul_ne_trace_rien() {
        let c = test_db();
        let d = v3_dossier("soql");
        v3_ecrire_tableau(&d, false);
        assert_eq!(v3_charger(&c, &d), (1, 0), "SOQL seul : chargé");
        assert_eq!(v3_traces(&c), 0, "SOQL seul : aucune trace de SQL brut");
    }

    /// (3) Tableau UI homonyme (`managed=2`) : ignoré, rien tracé, aucun tableau managé posé.
    #[test]
    fn v3_copie_ui_homonyme_ne_trace_rien() {
        let c = test_db();
        let d = v3_dossier("ui");
        c.execute("INSERT INTO dashboard(name, created, managed) VALUES(?1, 0, 2)", params![V3_TABLEAU]).unwrap();
        v3_ecrire_tableau(&d, true);
        assert_eq!(v3_charger(&c, &d), (0, 1), "copie UI : ignoré");
        assert_eq!(v3_traces(&c), 0, "copie UI : aucune trace « accepté »");
        let poses_hors_ui: i64 = c.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1 AND managed<>2", params![V3_TABLEAU], |r| r.get(0)).unwrap();
        assert_eq!(poses_hors_ui, 0, "copie UI : aucun tableau overlay posé à côté");
        assert!(v3_panneaux(&c).is_empty(), "copie UI : aucun panneau managé");
    }

    /// (4) Écriture d'un panneau refusée : ignoré, rien tracé, annulation entière (panneaux d'avant gardés).
    #[test]
    fn v3_ecriture_refusee_ne_trace_rien_et_annule_tout() {
        let c = test_db();
        let d = v3_dossier("refus");
        v3_ecrire_tableau(&d, false);
        assert_eq!(v3_charger(&c, &d), (1, 0), "contrôle : tableau d'avant chargé");
        c.execute_batch(
            "CREATE TRIGGER v3_refus_panneau BEFORE INSERT ON panel WHEN NEW.is_soql=0 BEGIN SELECT RAISE(ABORT,'v3 refus panneau'); END",
        )
        .unwrap();
        v3_ecrire_tableau(&d, true);
        assert_eq!(v3_charger(&c, &d), (0, 1), "panneau refusé : ignoré");
        assert_eq!(v3_traces(&c), 0, "panneau refusé : aucune trace « accepté »");
        let bruts: i64 = c
            .query_row("SELECT COUNT(*) FROM panel p JOIN dashboard d ON d.id=p.dashboard_id WHERE d.name=?1 AND p.is_soql=0", params![V3_TABLEAU], |r| r.get(0))
            .unwrap();
        assert_eq!(bruts, 0, "panneau refusé : aucun panneau SQL brut posé dans ce tableau");
        assert_eq!(v3_panneaux(&c), ["A", "B"], "annulation entière : panneaux d'avant gardés");
        assert!(c.is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// (5) Lecture de l'existant refusée : ignoré, rien tracé.
    #[test]
    fn v3_lecture_ratee_ne_trace_rien() {
        let c = test_db();
        let d = v3_dossier("lecture");
        v3_ecrire_tableau(&d, true);
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "dashboard" => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        let bilan = v3_charger(&c, &d);
        v3_lever(&c);
        assert!(refus.load(SeqCst) >= 1, "fixture : la lecture de dashboard a été refusée");
        assert_eq!(bilan, (0, 1), "lecture refusée : ignoré");
        assert_eq!(v3_traces(&c), 0, "lecture refusée : aucune trace « accepté »");
    }

    /// (6) SAVEPOINT refusé, puis RELEASE refusé : ignoré, rien tracé.
    #[test]
    fn v3_point_de_reprise_ou_validation_refuses_ne_tracent_rien() {
        for operation in [TransactionOperation::Begin, TransactionOperation::Release] {
            let c = test_db();
            let d = v3_dossier("sp");
            v3_ecrire_tableau(&d, true);
            let refus = Arc::new(AtomicUsize::new(0));
            let compteur = refus.clone();
            c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: op, savepoint_name } if op == operation && savepoint_name == "oac_dashboard" => {
                    compteur.fetch_add(1, SeqCst);
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }));
            let bilan = v3_charger(&c, &d);
            v3_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "fixture : {operation:?} refusé");
            assert_eq!(bilan, (0, 1), "{operation:?} refusé : ignoré");
            assert_eq!(v3_traces(&c), 0, "{operation:?} refusé : aucune trace « accepté »");
            assert!(c.is_autocommit(), "{operation:?} refusé : aucune transaction laissée ouverte");
        }
    }
}
