// =====================================================================================
// `P10.31-v` (vague BA) — les échéances d'une politique inactive sont EFFACÉES, les files par assigné ne les comptent
// plus, et une fusion entre la sélection du tour et son marqueur ne marque pas.
//
// CE QUI MANQUAIT, LU SUR 26d7a24f : depuis la vague AZ le tour SLA ne JUGE plus une échéance dont la politique est
// désactivée ou disparue, mais l'état ancien restait en base, ni effacé ni avoué : la fiche du dossier (`cases.rs`,
// `ack_due`/`resolve_due` servis tels quels) le montrait comme un SLA en cours, et `case_queues_json` (caseops.rs) le
// comptait en `ack_pending` (sa clause ne lisait pas la gouvernance). La fusion dans la fenêtre sélection -> marqueur
// était relue par le marqueur (`merged_into`, `status`) sans témoin.
// REMÈDE : EFFACER (même règle que la désactivation et la suppression d'une politique) en tête du tour, AVANT la porte
// « aucune politique active » ; la porte lit dans la même requête s'il reste de telles échéances (aucune écriture
// sinon) ; une ligne de journal dit le nombre et le tenant ; un refus (écriture refusée, transaction d'un autre geste
// pendante) est dit par sa ligne et n'arrête pas le tour ; `ack_pending` lit la gouvernance.
// CE QU'ILS TIENNENT : effacement des actifs, terminaux, fusionnés, en pause, à identifiant pendant ou sans politique,
// gouvernés intacts, marqueurs et pause conservés, `sla_due` intact, legacy ni compté ni écrit ; porte ouverte par une
// politique désactivée seule et par un acquitté seul ; effacement sans aucune politique active ; files par le routeur
// réel au jeton du compte viewer, corps entier ; lignes de journal entières, deux tenants, lues sur le stderr d'un
// sous-processus ; mode 0 sans écriture tentée ; fusion par la route au premier envoi ; effacement refusé, où le filtre
// des sélections (vague AZ) reste seul à laisser sortir le vrai dépassement.
// CE QU'ILS NE TIENNENT PAS : la console (aucun écran de politiques SLA) ; un dossier rendu actif par son statut alors
// qu'il reste fusionné (`merged_into` seul relu par le marqueur : son seul écrivain, `case_merge`, pose aussi
// `status='closed'`, le mutant qui ne retire que `merged_into` est équivalent pour la fusion).
// Mutants (VERIF_MUT=BA4_*, posés sous cfg!(test) puis retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod echeances_d_une_politique_inactive_effacees {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const EPI_PENDANTE: i64 = 999;
    const EPI_ENFANT: &str = "EPI_ENFANT_JOURNAL";
    const EPI_PHASE: &str = "EPI-PHASE:";
    const EPI_REFUS: &str = "CREATE TRIGGER epi_refus BEFORE UPDATE OF ack_due ON incident WHEN NEW.ack_due IS NULL \
                             BEGIN SELECT RAISE(ABORT,'effacement refuse par le temoin epi'); END;";

    const EPI_LIGNE_ALPHA: &str = "[plume] chrono SLA (tenant 't-alpha') : 3 dossier(s) portaient les échéances d'une politique désactivée ou disparue : sla_policy_id, ack_due et resolve_due effacés (régime legacy), marqueurs de dépassement conservés";
    const EPI_LIGNE_BETA: &str = "[plume] chrono SLA (tenant 't-beta') : 2 dossier(s) portaient les échéances d'une politique désactivée ou disparue : sla_policy_id, ack_due et resolve_due effacés (régime legacy), marqueurs de dépassement conservés";
    const EPI_LIGNE_REFUS: &str = "[plume] chrono SLA (tenant 't-gamma') : échéances d'une politique désactivée ou disparue NON EFFACÉES ce tour-ci (la fiche du dossier les montre encore ; nouvel essai au tour suivant) : effacement refusé : effacement refuse par le temoin epi";
    const EPI_LIGNE_ETRANGERE: &str = "[plume] chrono SLA (tenant 't-delta') : échéances d'une politique désactivée ou disparue NON EFFACÉES ce tour-ci (la fiche du dossier les montre encore ; nouvel essai au tour suivant) : transaction d'un autre geste pendante sur l'écrivain";

    fn epi_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("epi-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('epi','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn epi_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("fixture : runtime")
    }

    fn epi_au(role: &str) -> AuthUser {
        AuthUser {
            name: "redacteur".into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn epi_sql(conn: &Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn epi_entier(conn: &Connection, sql: &str) -> Option<i64> {
        conn.query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn epi_politique(conn: &Connection, nom: &str, priorite: i64) -> i64 {
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé (assigné à alice, gouverné par la politique active de sa priorité s'il y en a une), puis
    /// `UPDATE incident SET <reglage>`.
    fn epi_dossier(conn: &Connection, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = dossier_seme(conn, "alice", titre, 4, "", Some("alice"), priorite);
        if !reglage.is_empty() {
            epi_sql(conn, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// (sla_policy_id, ack_due, resolve_due).
    fn epi_chrono(conn: &Connection, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        conn.query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    fn epi_tick(db: &Arc<Mutex<Connection>>) -> Vec<String> {
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    /// `n` dossiers à identifiant de politique pendant, échéances passées (état ancien).
    fn epi_orphelins(conn: &Connection, n: usize) {
        let t = now();
        for i in 0..n {
            epi_dossier(conn, &format!("O{i}"), 2, &format!("sla_policy_id={EPI_PENDANTE}, ack_due={}, resolve_due={}", t - 500, t - 500));
        }
    }

    fn epi_nombre_d_echeances(conn: &Connection) -> i64 {
        epi_entier(conn, "SELECT COUNT(*) FROM incident WHERE ack_due IS NOT NULL OR resolve_due IS NOT NULL").unwrap_or(0)
    }

    /// CE QU'IL TIENT (état ancien, effacement) : P1 active ; A (P1, échéances futures) gouverné. P2 gouverne B (actif,
    /// échu), T (clos), M (fusionné dans A, statut actif), Z (en pause), puis P2 est désactivée par un `UPDATE` brut qui
    /// laisse leurs échéances ; X porte un identifiant pendant et un marqueur `ack_breached` déjà posé ; N porte des
    /// échéances sans politique ; L est un legacy sans échéance. Après UN tour : B, T, M, Z, X, N n'ont plus ni
    /// politique ni échéance ; le marqueur de X, la pause de Z, le `sla_due` de B et L sont intacts ; A est intact et
    /// rien n'est notifié ; L n'a reçu aucune écriture (relevée par un déclencheur).
    /// MUTATIONS QUI LE FONT ROUGIR : `BA4_EFFACE_SANS_ECHEANCES` (L réécrit), `BA4_SANS_EFFACEMENT` (l'état ancien reste), `BA4_EFFACE_SANS_GOUVERNANCE` (A
    /// perd aussi ses échéances), `BA4_ENABLED_OMIS` (`p.enabled=1` retiré de l'effacement : B, T, M, Z gardent les
    /// échéances de P2 désactivée), `BA4_EFFACE_ACK_SEUL` (seul `ack_due` est lu : N, qui n'a qu'un `resolve_due`,
    /// reste).
    #[test]
    fn epi_etat_ancien_efface_au_tour_les_gouvernes_les_marqueurs_et_la_pause_intacts() {
        let (st, _t) = epi_etat("ancien");
        let n0 = now();
        let (a, b, t, m, z, x, nn, sla_due_b) = {
            let conn = st.db.lock();
            let _p1 = epi_politique(&conn, "P1", 1);
            let p2 = epi_politique(&conn, "P2", 2);
            let a = epi_dossier(&conn, "A", 1, "");
            let b = epi_dossier(&conn, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
            let t = epi_dossier(&conn, "T", 2, "status='closed'");
            let m = epi_dossier(&conn, "M", 2, &format!("merged_into={a}"));
            let z = epi_dossier(&conn, "Z", 2, &format!("status='waiting', sla_paused_since={}", n0 - 50));
            let x = epi_dossier(&conn, "X", 2, &format!("sla_policy_id={EPI_PENDANTE}, ack_breached=1, ack_due={}, resolve_due={}", n0 - 900, n0 - 900));
            let nn = epi_dossier(&conn, "N", 3, &format!("sla_policy_id=NULL, ack_due=NULL, resolve_due={}", n0 - 900));
            let l = epi_dossier(&conn, "L", 4, "");
            for id in [b, t, m, z] {
                assert_eq!(epi_chrono(&conn, id).0, Some(p2), "fixture : #{id} gouverné par P2");
            }
            epi_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            let sla_due_b = epi_entier(&conn, &format!("SELECT sla_due FROM incident WHERE id={b}"));
            assert!(sla_due_b.is_some(), "fixture : B porte un sla_due legacy");
            assert_eq!(epi_chrono(&conn, l), (None, None, None), "fixture : L legacy sans échéance");
            epi_sql(
                &conn,
                &format!(
                    "CREATE TABLE epi_ecrit(id INTEGER); CREATE TRIGGER epi_l AFTER UPDATE ON incident WHEN OLD.id={l} \
                     BEGIN INSERT INTO epi_ecrit VALUES(OLD.id); END;"
                ),
            );
            assert_eq!(epi_chrono(&conn, nn), (None, None, Some(n0 - 900)), "fixture : N n'a qu'un resolve_due");
            (a, b, t, m, z, x, nn, sla_due_b)
        };
        let chrono_a = epi_chrono(&st.db.lock(), a);
        assert!(chrono_a.0.is_some() && chrono_a.1.is_some() && chrono_a.2.is_some(), "fixture : A gouverné par P1");

        let envois = epi_tick(&st.db);
        assert_eq!(envois, Vec::<String>::new(), "rien n'est notifié : A n'est pas échu, les autres ne sont pas jugés");
        let conn = st.db.lock();
        for (nom, id) in [("B", b), ("T", t), ("M", m), ("Z", z), ("X", x), ("N", nn)] {
            assert_eq!(epi_chrono(&conn, id), (None, None, None), "{nom} : politique et échéances effacées (régime legacy)");
        }
        assert_eq!(epi_chrono(&conn, a), chrono_a, "A, gouverné par P1 active, est intact");
        assert_eq!(epi_entier(&conn, "SELECT COUNT(*) FROM epi_ecrit"), Some(0), "L, legacy sans échéance, n'a reçu aucune écriture");
        assert_eq!(epi_entier(&conn, &format!("SELECT ack_breached FROM incident WHERE id={x}")), Some(1), "le marqueur passé de X reste");
        assert_eq!(epi_entier(&conn, &format!("SELECT sla_paused_since FROM incident WHERE id={z}")), Some(n0 - 50), "la pause de Z reste");
        assert_eq!(epi_entier(&conn, &format!("SELECT sla_due FROM incident WHERE id={b}")), sla_due_b, "le sla_due legacy de B est intact");
        assert_eq!(epi_nombre_d_echeances(&conn), 1, "seules les échéances de A restent");
    }

    /// CE QU'IL TIENT (aucune politique active) : P2 désactivée (brut) gouvernait B ; C porte un identifiant pendant.
    /// AUCUNE politique n'est active : le tour s'arrête à sa porte, mais l'effacement a lieu AVANT elle.
    /// MUTATION QUI LE FAIT ROUGIR : `BA4_APRES_LA_PORTE` (effacement placé après le retour « aucune politique
    /// active » : B et C gardent leurs échéances).
    #[test]
    fn epi_sans_aucune_politique_active_l_effacement_a_lieu_quand_meme() {
        let (st, _t) = epi_etat("sans-active");
        let n0 = now();
        let (b, c) = {
            let conn = st.db.lock();
            let p2 = epi_politique(&conn, "P2", 2);
            let b = epi_dossier(&conn, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
            let c = epi_dossier(&conn, "C", 2, &format!("sla_policy_id={EPI_PENDANTE}"));
            assert_eq!(epi_chrono(&conn, b).0, Some(p2), "fixture : B gouverné par P2");
            epi_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            assert_eq!(epi_entier(&conn, "SELECT COUNT(*) FROM sla_policy WHERE enabled=1"), Some(0), "fixture : aucune politique active");
            assert_eq!(epi_nombre_d_echeances(&conn), 2, "fixture : B et C portent des échéances");
            (b, c)
        };
        assert_eq!(epi_tick(&st.db), Vec::<String>::new());
        let conn = st.db.lock();
        assert_eq!((epi_chrono(&conn, b), epi_chrono(&conn, c)), ((None, None, None), (None, None, None)), "B et C effacés");
    }

    /// CE QU'IL TIENT (files par assigné, PAR LE ROUTEUR RÉEL — authentification, `rbac_gate` — avec le jeton Basic du
    /// compte `viewer`, le rôle le plus faible admis, corps entier) : P1 et P2 actives ; quatre dossiers d'alice,
    /// échéance d'acquittement passée, non acquittés : A gouverné par P1 ; B gouverné par P2 puis P2 désactivée (brut,
    /// échéances laissées) ; X à identifiant pendant ; N sans politique. AUCUN tour n'est joué (l'état ancien est lu
    /// tel quel) : `GET /api/cases/queues` rend 200, `ack_pending` vaut 1 (A seul), `open` 4.
    /// MUTATION QUI LE FAIT ROUGIR : `BA4_FILES_SANS_GOUVERNANCE` (clause retirée : `ack_pending` vaut 4).
    #[tokio::test]
    async fn epi_files_par_assigne_ne_comptent_pas_une_echeance_d_une_politique_inactive() {
        let (st, _t) = router_test_state("epi-files");
        let n0 = now();
        {
            let conn = st.db.lock();
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
            let _p1 = epi_politique(&conn, "P1", 1);
            let p2 = epi_politique(&conn, "P2", 2);
            epi_dossier(&conn, "A", 1, &format!("ack_due={}", n0 - 100));
            let b = epi_dossier(&conn, "B", 2, &format!("ack_due={}", n0 - 100));
            epi_dossier(&conn, "X", 2, &format!("sla_policy_id={EPI_PENDANTE}, ack_due={}", n0 - 100));
            epi_dossier(&conn, "N", 3, &format!("ack_due={}", n0 - 100));
            assert_eq!(epi_chrono(&conn, b).0, Some(p2), "fixture : B gouverné par P2");
            epi_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            assert_eq!(
                epi_entier(&conn, &format!("SELECT COUNT(*) FROM incident WHERE ack_due<{n0} AND first_response_ts IS NULL AND sla_paused_since IS NULL")),
                Some(4),
                "fixture : quatre échéances d'acquittement passées"
            );
            assert_eq!(
                epi_entier(&conn, &format!("SELECT COUNT(*) FROM incident WHERE sla_due IS NOT NULL AND sla_due <= {}", n0 + 5)),
                Some(0),
                "fixture : aucun sla_due legacy échu"
            );
        }
        let addr = router_serve(st).await;
        let (code, reponse) = router_probe_envoi(addr, "GET", "/api/cases/queues", Some(&viewer_authz()), &[], "").await;
        assert_eq!(code, 200, "le viewer est admis sur la route des files : {reponse}");
        // Corps servi en `transfer-encoding: chunked` : un seul morceau, la ligne qui ouvre l'objet JSON.
        let morceau = reponse.split_once("\r\n\r\n").map(|(_, c)| c).unwrap_or("").lines().find(|l| l.starts_with('{')).unwrap_or("");
        let corps: Value = serde_json::from_str(morceau)
            .unwrap_or_else(|e| panic!("contrôle : corps JSON ({e}) : {reponse}"));
        assert_eq!(
            corps,
            json!({
                "queues": [{ "assignee": "alice", "open": 4, "overdue": 0, "ack_pending": 1, "breach": 0, "waiting": 0 }],
                "served": 1, "window": 500, "total": 1, "total_capped": false
            }),
            "seule l'échéance de A (politique active) est en attente d'acquittement"
        );
    }

    /// CE QU'IL TIENT (la PORTE s'ouvre pour le cas principal, joué SEUL) : P1 active ; P2 gouverne B (échu), puis P2
    /// est désactivée par un `UPDATE` brut — sa ligne existe encore. B est le SEUL porteur d'échéances inactives
    /// (aucun dossier à identifiant pendant ni sans politique, qui ouvriraient la porte à eux seuls). Après UN tour, B
    /// n'a plus ni politique ni échéance, rien n'est notifié.
    /// MUTATION QUI LE FAIT ROUGIR : `BA4_PORTE_ENABLED_OMIS` (`p.enabled=1` retiré de la PORTE seule : la ligne de P2
    /// existe, la porte reste fermée, B garde ses échéances).
    #[test]
    fn epi_seule_une_politique_desactivee_porte_les_echeances_la_porte_s_ouvre() {
        let (st, _t) = epi_etat("porte-desactivee");
        let n0 = now();
        let b = {
            let conn = st.db.lock();
            let _p1 = epi_politique(&conn, "P1", 1);
            let p2 = epi_politique(&conn, "P2", 2);
            let b = epi_dossier(&conn, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
            assert_eq!(epi_chrono(&conn, b), (Some(p2), Some(n0 - 100), Some(n0 - 100)), "fixture : B gouverné par P2, échu");
            epi_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            assert_eq!(epi_entier(&conn, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={p2}")), Some(1), "fixture : la ligne de P2 existe encore");
            assert_eq!(epi_nombre_d_echeances(&conn), 1, "fixture : B est le seul porteur d'échéances");
            b
        };
        assert_eq!(epi_tick(&st.db), Vec::<String>::new(), "B n'est pas jugé");
        assert_eq!(epi_chrono(&st.db.lock(), b), (None, None, None), "B : politique et échéances effacées");
    }

    /// CE QU'IL TIENT (la PORTE lit aussi `resolve_due`, joué SEUL) : P1 active ; B, ACQUITTÉ avant que P2 ne le
    /// gouverne (`first_response_ts` posé, `ack_due` NULL : `sla_apply_policy` n'écrit alors que `resolve_due`), puis P2
    /// désactivée (brut). B est le seul porteur et n'a qu'un `resolve_due`. Après UN tour, il est effacé.
    /// MUTATIONS QUI LE FONT ROUGIR : `BA4_PORTE_ACK_SEUL` (la PORTE seule ne lit que `ack_due` : elle reste fermée, B
    /// garde `resolve_due`), `BA4_PORTE_ENABLED_OMIS`.
    #[test]
    fn epi_seul_un_acquitte_porte_les_echeances_la_porte_s_ouvre() {
        let (st, _t) = epi_etat("porte-acquitte");
        let n0 = now();
        let b = {
            let conn = st.db.lock();
            let _p1 = epi_politique(&conn, "P1", 1);
            let p2 = epi_politique(&conn, "P2", 2);
            let b = epi_dossier(&conn, "B", 2, &format!("first_response_ts={}, ack_due=NULL, resolve_due={}", n0 - 200, n0 - 100));
            assert_eq!(epi_chrono(&conn, b), (Some(p2), None, Some(n0 - 100)), "fixture : B acquitté, gouverné par P2, resolve_due seul");
            epi_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            assert_eq!(epi_nombre_d_echeances(&conn), 1, "fixture : B est le seul porteur d'échéances");
            b
        };
        assert_eq!(epi_tick(&st.db), Vec::<String>::new(), "B n'est pas jugé");
        assert_eq!(epi_chrono(&st.db.lock(), b), (None, None, None), "B : politique et échéance de résolution effacées");
    }

    /// CE QU'IL TIENT (l'effacement ne touche QUE les porteurs d'échéances) : P1 active ; L legacy (aucune politique,
    /// aucune échéance), O à identifiant pendant ; un déclencheur relève toute écriture de L.
    /// `effacer_les_echeances_d_une_politique_inactive` rend `Ok(1)` (O seul : le nombre de la ligne de journal) et L
    /// n'a reçu AUCUNE écriture (une réécriture de NULL par NULL ne se voit pas sur ses valeurs, elle se voit ici).
    /// MUTATION QUI LE FAIT ROUGIR : `BA4_EFFACE_SANS_ECHEANCES` (`(ack_due IS NOT NULL OR resolve_due IS NOT NULL)`
    /// retiré de l'`UPDATE` : `Ok(2)`, L réécrit).
    #[test]
    fn epi_l_effacement_ne_compte_ni_n_ecrit_un_legacy() {
        let conn = test_db();
        epi_politique(&conn, "P1", 1);
        let l = epi_dossier(&conn, "L", 4, "");
        assert_eq!(epi_chrono(&conn, l), (None, None, None), "fixture : L legacy sans échéance");
        epi_orphelins(&conn, 1);
        epi_sql(
            &conn,
            &format!(
                "CREATE TABLE epi_ecrit(id INTEGER); CREATE TRIGGER epi_l AFTER UPDATE ON incident WHEN OLD.id={l} \
                 BEGIN INSERT INTO epi_ecrit VALUES(OLD.id); END;"
            ),
        );
        assert_eq!(effacer_les_echeances_d_une_politique_inactive(&conn), Ok(1), "seul O est compté");
        assert_eq!(epi_entier(&conn, "SELECT COUNT(*) FROM epi_ecrit"), Some(0), "L n'a reçu aucune écriture");
        assert_eq!(epi_nombre_d_echeances(&conn), 0, "O effacé");
    }

    /// CE QU'IL TIENT (fusion dans la fenêtre sélection -> marqueur) : P1 active ; A échu de 100 s, B échu de 10 s,
    /// C (cible, non échu). Le tour sélectionne A et B ; au PREMIER envoi (acquittement de A, verrou relâché), B est
    /// fusionné dans C PAR LA ROUTE (204). B n'est ensuite ni marqué ni notifié, ni en acquittement ni en résolution ;
    /// A l'est deux fois ; aucun dépassement de B au registre.
    /// MUTATION QUI LE FAIT ROUGIR : `BA4_MARQUEUR_SANS_FUSION` (le marqueur ne relit ni `merged_into` ni le statut :
    /// B marqué et notifié après sa fusion). Retirer `merged_into` SEUL reste vert : `case_merge` pose `status='closed'`
    /// dans la même écriture, le statut relu suffit (équivalent, dit en tête).
    #[test]
    fn epi_fusion_par_la_route_entre_la_selection_et_le_marqueur_ne_marque_pas() {
        let rt = epi_runtime();
        let (st, _t) = epi_etat("fusion");
        let n0 = now();
        let (a, b, c) = {
            let conn = st.db.lock();
            let _p1 = epi_politique(&conn, "P1", 1);
            let a = epi_dossier(&conn, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
            let b = epi_dossier(&conn, "B", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
            let c = epi_dossier(&conn, "C", 1, "");
            (a, b, c)
        };
        let mut envois: Vec<String> = Vec::new();
        let mut fusion: Option<u16> = None;
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            if fusion.is_none() {
                let rep = rt.block_on(case_merge_handler(State(st.clone()), Extension(epi_au("editor")), Path(b), Json(json!({ "into": c }))));
                fusion = Some(rep.status().as_u16());
            }
            true
        });
        assert_eq!(fusion, Some(204), "la fusion concurrente a eu lieu, par la route");
        let conn = st.db.lock();
        assert_eq!(
            conn.query_row("SELECT merged_into, status FROM incident WHERE id=?1", params![b], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?))).unwrap(),
            (Some(c), "closed".to_string()),
            "B fusionné dans C"
        );
        assert_eq!(
            envois,
            vec![
                format!("Case #{a} « A » : SLA acquittement (MTTA) P1 dépassé."),
                format!("Case #{a} « A » : SLA résolution (MTTR) P1 dépassé."),
            ],
            "B, sélectionné avant sa fusion, n'est pas notifié"
        );
        assert_eq!(
            epi_entier(&conn, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={b}")),
            Some(0),
            "B n'est pas marqué après sa fusion"
        );
        assert_eq!(epi_entier(&conn, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={a}")), Some(2), "A marqué deux fois");
        assert_eq!(
            epi_entier(&conn, &format!("SELECT COUNT(*) FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach') AND detail LIKE '#{b} %'")),
            Some(0),
            "aucun dépassement de B au registre"
        );
    }

    /// CE QU'IL TIENT (effacement refusé, filtre des sélections) : l'effacement passe AVANT les sélections, sous le même
    /// verrou ; tant qu'il réussit, le filtre de gouvernance des sélections (vague AZ) ne voit plus d'état ancien. Il
    /// ne sert donc plus que quand l'effacement est REFUSÉ : P1 active ; A (P1) échu de 10 s ; vingt dossiers plus
    /// anciens (échus de 1000 s) à identifiant pendant ; l'effacement est refusé par un déclencheur. Le tour notifie A
    /// (acquittement et résolution), les vingt gardent leurs échéances et ne sont ni notifiés ni marqués.
    /// MUTATIONS QUI LE FONT ROUGIR : `BA4_SELECTION_ACK_SANS_GOUVERNANCE` et `BA4_SELECTION_RES_SANS_GOUVERNANCE`
    /// (filtre retiré d'une sélection : les vingt occupent la fenêtre, A n'est pas notifié sur ce volet).
    #[test]
    fn epi_effacement_refuse_le_filtre_des_selections_laisse_sortir_le_vrai_depassement() {
        let (st, _t) = epi_etat("refus-fenetre");
        let n0 = now();
        let a = {
            let conn = st.db.lock();
            epi_politique(&conn, "P1", 1);
            let a = epi_dossier(&conn, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
            for i in 0..20 {
                epi_dossier(&conn, &format!("O{i}"), 2, &format!("sla_policy_id={EPI_PENDANTE}, ack_due={}, resolve_due={}", n0 - 1000, n0 - 1000));
            }
            epi_sql(&conn, EPI_REFUS);
            a
        };
        assert_eq!(
            epi_tick(&st.db),
            vec![
                format!("Case #{a} « A » : SLA acquittement (MTTA) P1 dépassé."),
                format!("Case #{a} « A » : SLA résolution (MTTR) P1 dépassé."),
            ],
            "seul A est notifié, en acquittement ET en résolution"
        );
        let conn = st.db.lock();
        assert_eq!(epi_nombre_d_echeances(&conn), 21, "l'effacement refusé n'a rien effacé");
        assert_eq!(
            epi_entier(&conn, "SELECT COUNT(*) FROM incident WHERE ack_breached=1 OR resolve_breached=1"),
            Some(1),
            "seul A est marqué"
        );
    }

    /// CE QU'IL TIENT (lignes de journal, lues sur le stderr d'un sous-processus, ENTIÈRES) :
    ///   · alpha (tenant 't-alpha') : trois dossiers à identifiant pendant et un legacy sans échéance -> une ligne,
    ///     « 3 dossier(s) » (le legacy n'est pas compté), le tenant ;
    ///   · beta (tenant 't-beta', autre base) : deux -> « 2 dossier(s) », SON tenant ; rejoué : aucune ligne ;
    ///   · refus (tenant 't-gamma') : effacement refusé par un déclencheur -> la ligne NON EFFACÉES avec la cause, les
    ///     échéances restent, et le tour CONTINUE (A, gouverné et échu, est notifié deux fois) ;
    ///   · transaction étrangère (tenant 't-delta') : un `BEGIN` laissé ouvert sur l'écrivain -> la ligne NON EFFACÉES
    ///     qui le nomme ; après `ROLLBACK`, l'échéance est toujours là ;
    ///   · mode 0 (aucune politique, aucune échéance, toute écriture sur `incident` refusée par l'autorisateur) :
    ///     aucune ligne, aucune écriture tentée.
    /// MUTATIONS QUI LE FONT ROUGIR : `BA4_LIGNE_MUETTE` (aucune ligne d'effacement), `BA4_TENANT_FIGE` (ligne sans le
    /// tenant du tour), `BA4_REFUS_MUET` (refus sans ligne), `BA4_REFUS_ARRETE` (un refus arrête le tour : A n'est pas
    /// notifié), `BA4_SANS_GARDE_AUTOCOMMIT` (l'effacement entre dans la transaction étrangère : ligne « effacés »),
    /// `BA4_TOUJOURS_ECRIRE` (l'effacement est tenté sans que la porte l'ait demandé : la ligne NON EFFACÉES sort en
    /// mode 0), `BA4_EFFACE_SANS_ECHEANCES` (le legacy compté : « 4 dossier(s) »), `BA4_SANS_EFFACEMENT`.
    #[test]
    fn epi_lignes_de_journal_entieres_par_tenant_refus_et_mode_0() {
        if std::env::var(EPI_ENFANT).is_ok() {
            let t = now();
            for (phase, tenant, n) in [("alpha", "t-alpha", 3usize), ("beta", "t-beta", 2usize)] {
                eprintln!("{EPI_PHASE}{phase}");
                let conn = test_db();
                epi_politique(&conn, "P1", 1);
                epi_dossier(&conn, "L", 4, "");
                epi_orphelins(&conn, n);
                let db = Arc::new(Mutex::new(conn));
                {
                    let _tenant = crate::metrics::nommer_le_tenant_du_tour(tenant);
                    epi_tick(&db);
                }
                println!("EPI-ECHEANCES-{phase}:{}", epi_nombre_d_echeances(&db.lock()));
                if phase == "beta" {
                    eprintln!("{EPI_PHASE}beta-rejoue");
                    let _tenant = crate::metrics::nommer_le_tenant_du_tour(tenant);
                    epi_tick(&db);
                }
            }
            eprintln!("{EPI_PHASE}refus");
            {
                let conn = test_db();
                conn.execute(
                    "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('epi','webhook',1,'https://example.invalid/h',0,'{}')",
                    [],
                )
                .unwrap();
                epi_politique(&conn, "P1", 1);
                epi_dossier(&conn, "A", 1, &format!("ack_due={}, resolve_due={}", t - 100, t - 100));
                epi_orphelins(&conn, 1);
                epi_sql(&conn, EPI_REFUS);
                let db = Arc::new(Mutex::new(conn));
                let envois = {
                    let _tenant = crate::metrics::nommer_le_tenant_du_tour("t-gamma");
                    epi_tick(&db)
                };
                println!("EPI-ENVOIS-refus:{}", envois.len());
                println!("EPI-ECHEANCES-refus:{}", epi_nombre_d_echeances(&db.lock()));
            }
            eprintln!("{EPI_PHASE}etrangere");
            {
                let conn = test_db();
                epi_orphelins(&conn, 1);
                epi_sql(&conn, "BEGIN");
                let db = Arc::new(Mutex::new(conn));
                {
                    let _tenant = crate::metrics::nommer_le_tenant_du_tour("t-delta");
                    epi_tick(&db);
                }
                let conn = db.lock();
                epi_sql(&conn, "ROLLBACK");
                println!("EPI-ECHEANCES-etrangere:{}", epi_nombre_d_echeances(&conn));
            }
            eprintln!("{EPI_PHASE}mode0");
            {
                let conn = test_db();
                epi_dossier(&conn, "L", 1, "");
                conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Update { table_name, .. } if table_name == "incident" => Authorization::Deny,
                    _ => Authorization::Allow,
                }));
                let db = Arc::new(Mutex::new(conn));
                {
                    let _tenant = crate::metrics::nommer_le_tenant_du_tour("t-zero");
                    epi_tick(&db);
                }
                db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
                println!("EPI-ECHEANCES-mode0:{}", epi_nombre_d_echeances(&db.lock()));
            }
            eprintln!("{EPI_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::echeances_d_une_politique_inactive_effacees::epi_lignes_de_journal_entieres_par_tenant_refus_et_mode_0",
            ])
            .env(EPI_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for (marque, attendu) in [
            ("EPI-ECHEANCES-alpha:", "0"),
            ("EPI-ECHEANCES-beta:", "0"),
            ("EPI-ENVOIS-refus:", "2"),
            ("EPI-ECHEANCES-refus:", "2"),
            ("EPI-ECHEANCES-etrangere:", "1"),
            ("EPI-ECHEANCES-mode0:", "0"),
        ] {
            assert!(stdout.lines().any(|l| l.ends_with(&format!(" {marque}{attendu}")) || l == format!("{marque}{attendu}")), "bilan {marque}{attendu} : {stdout}");
        }
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{EPI_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(EPI_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] chrono SLA")).map(str::to_string).collect()
        };
        assert_eq!(phase("alpha"), vec![EPI_LIGNE_ALPHA.to_string()], "alpha : une ligne entière, son nombre, son tenant");
        assert_eq!(phase("beta"), vec![EPI_LIGNE_BETA.to_string()], "beta : une ligne entière, son nombre, SON tenant");
        assert_eq!(phase("beta-rejoue"), Vec::<String>::new(), "beta rejoué : plus rien à effacer, aucune ligne");
        assert_eq!(phase("refus"), vec![EPI_LIGNE_REFUS.to_string()], "refus : la ligne NON EFFACÉES, avec la cause");
        assert_eq!(phase("etrangere"), vec![EPI_LIGNE_ETRANGERE.to_string()], "transaction étrangère : nommée, rien écrit");
        assert_eq!(phase("mode0"), Vec::<String>::new(), "mode 0 : aucune écriture tentée, aucune ligne");
    }
}
