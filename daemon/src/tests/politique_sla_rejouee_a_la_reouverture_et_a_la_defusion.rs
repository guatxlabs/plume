// =====================================================================================
// `P10.31-v` (reste vague AO : « réouverture par statut seul et `case_unmerge` ne rejouent pas `sla_apply_policy` »).
//
// CE QUI MANQUAIT, MESURÉ SUR ac1f43b8 : `case_apply_update` (cases.rs) n'appelait `sla_apply_policy` que sur une
// priorité écrite, et `case_unmerge` (caseops.rs) jamais. Un dossier terminal rouvert par son seul statut, ou un fusionné
// défusionné, gardait le `sla_policy_id` et les échéances d'AVANT sa clôture ou sa fusion : politique supprimée, désactivée
// ou d'une autre priorité, priorité changée pendant qu'il était clos (`sla_apply_policy` ne touche pas un terminal), ou
// politique activée entre-temps qu'il ne prenait pas.
// REMÈDE : à la mise à jour, « statut en base terminal ET statut effectif non terminal » est un second déclencheur du MÊME
// appel que le changement de priorité, mêmes bras (`Refuse` -> 503 `CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE`, `NonLu` ->
// 503 `CAUSE_CHRONO_SLA_NON_LU`) ; à la défusion, l'appel est joué dans la transaction du geste, après l'`UPDATE` et avant
// la chronologie (`Refuse` -> `NonEcrite`, `NonLu` -> `ChronoSlaNonLu`, 503 `CAUSE_DEFUSION_CHRONO_SLA_NON_LU` : la
// défusion entière est annulée). CORRECTION (vérificateur indépendant) : un dossier EN ATTENTE que la politique vient
// de gouverner (terminal non gouverné rouvert directement en `waiting`, legacy en attente passé à une priorité
// gouvernée) est mis en pause après la politique — il sortait gouverné SANS pause et le tour le notifiait.
// RÈGLE GARDÉE, ASSUMÉE (décision de l'orchestrateur) : les échéances sont tirées du `ts` IMMUABLE (+ cumul de pause),
// comme à la création et au changement de priorité. UN DOSSIER ANCIEN ROUVERT OU DÉFUSIONNÉ SOUS UNE POLITIQUE ACTIVE
// EST DONC EN DÉPASSEMENT DÈS LE TOUR SUIVANT : `prr_politique_activee_entre_temps_regouverne_le_rouvert` le montre
// (notifié par le tour). À la réouverture par la route, `ack_due` n'est pas reposé : l'élément de chronologie du statut
// fige `first_response_ts` avant l'appel ; à la défusion, l'appel précède l'élément « dé-fusionné » et `ack_due` est
// reposé si le dossier n'avait reçu aucune réponse.
// CE QU'ILS TIENNENT, PAR LE ROUTEUR RÉEL (compte `editor`, POST /api/cases/{id} et POST /api/cases/{id}/unmerge) :
// réouverture regouvernée sur une priorité écrite en terminal ; politique activée entre-temps prise ; terminal sans
// politique pour sa priorité (bord NULL, et politique pendante effacée, non notifiée) ; défusion regouvernée (pendante
// remplacée, ou effacée sans politique) ; refus d'écriture et lecture ratée à la réouverture (503 à corps entier, statut
// écrit avec sa chronologie) et à la défusion (503 à corps entier, toujours fusionné, ni chronologie ni registre) ;
// contrôle positif : statut actif -> actif et `{title}` seul ne rejouent pas la politique, terminal -> terminal ne change
// rien ; statut legacy `contained` (jamais réécrit par la migration) rouvert regouverné ; terminal non gouverné rouvert en
// `waiting` et legacy en attente passé à une priorité gouvernée : gouvernés ET en pause, non notifiés. Chaque témoin
// porte un voisin intact.
// CE QU'ILS NE TIENNENT PAS : une politique réactivée ou modifiée ne regouverne toujours pas les terminaux ni les fusionnés
// NON rouverts ; les marqueurs `ack_breached`/`resolve_breached` passés (conservés à dessein) ; `sla_due` (legacy) n'est
// pas recalculé à la défusion (le tour multi-niveau ne le lit pas) ; terminal -> terminal n'est pas un rejeu observable
// (`sla_apply_policy` garde déjà le terminal : la mutation « rouvert = etait_terminal » est équivalente) ; un dossier
// legacy en attente que la création ou le recalcul d'une POLITIQUE (upsert) gouverne, hors de `case_apply_update` ; la
// console.
// Mutants (AP3_*, posés sous cfg!(test) puis retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod politique_sla_rejouee_a_la_reouverture_et_a_la_defusion {
    use super::*;

    const PRR_PENDANT: i64 = 999;
    const PRR_MOTIF: &str = "prr refus du chrono";

    fn prr_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, chemin) = router_test_state(&format!("prr-{tag}"));
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('prr_edt',?1,'editor')", params![hash_pw("prrediteur12345").unwrap()])
            .expect("fixture : compte éditeur");
        prr_sql(&st, "DELETE FROM incident; DELETE FROM sla_policy;");
        (st, chemin)
    }

    fn prr_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("prr_edt:prrediteur12345"))
    }

    fn prr_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn prr_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn prr_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, String>(0)).expect("fixture : le texte se lit")
    }

    fn prr_politique(st: &AppState, priorite: i64, ack: i64, res: i64, active: bool) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,?3,?4,?5,0,'root',0)",
            params![format!("P{priorite}"), priorite, ack, res, active as i64],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé à la priorité donnée, puis `UPDATE incident SET <reglage> WHERE id=<id>` (vide : rien).
    fn prr_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            prr_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// (sla_policy_id, ack_due, resolve_due).
    fn prr_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    fn prr_ts(st: &AppState, id: i64) -> i64 {
        prr_entier(st, &format!("SELECT ts FROM incident WHERE id={id}")).expect("ts")
    }

    /// Statut et corps d'une réponse HTTP brute : `Value::Null` pour un corps vide (204).
    fn prr_rendu(code: u16, brut: &str) -> (u16, Value) {
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).expect("trame chunked")).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        if corps.is_empty() {
            (code, Value::Null)
        } else {
            (code, serde_json::from_str(&corps).unwrap_or_else(|_| json!({ "_texte": corps })))
        }
    }

    async fn prr_patch(addr: std::net::SocketAddr, id: i64, corps: Value) -> (u16, Value) {
        let (code, brut) = router_probe_envoi(addr, "POST", &format!("/api/cases/{id}"), Some(&prr_authz()), &[("Content-Type", "application/json")], &corps.to_string()).await;
        prr_rendu(code, &brut)
    }

    async fn prr_defusion(addr: std::net::SocketAddr, id: i64) -> (u16, Value) {
        let (code, brut) = router_probe_envoi(addr, "POST", &format!("/api/cases/{id}/unmerge"), Some(&prr_authz()), &[], "").await;
        prr_rendu(code, &brut)
    }

    fn prr_tick(st: &AppState) -> Vec<String> {
        prr_sql(st, "INSERT OR IGNORE INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('prr','webhook',1,'https://example.invalid/h',0,'{}')");
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _ti: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    fn prr_notifie(envois: &[String], id: i64) -> bool {
        envois.iter().any(|d| d.starts_with(&format!("Case #{id} ")))
    }

    /// Refuse toute écriture de `resolve_due` sur le dossier `id` (le chrono de `sla_apply_policy` l'écrit toujours).
    fn prr_refuser_le_chrono(st: &AppState, id: i64) {
        prr_sql(
            st,
            &format!("CREATE TRIGGER prr_chrono BEFORE UPDATE OF resolve_due ON incident WHEN OLD.id={id} BEGIN SELECT RAISE(ABORT,'{PRR_MOTIF}'); END;"),
        );
    }

    /// CE QU'IL TIENT : sous P3 (3000/30000) et P1 (60/600), D et V de priorité 3 gouvernés par P3, clos (`resolved`) par
    /// la route ; leur priorité passée à 1 en terminal (204, échéances INCHANGÉES : `sla_apply_policy` ne touche pas un
    /// terminal). D rouvert par son statut seul (`triage`) : 204, `sla_policy_id` = P1, `resolve_due` = ts + 600,
    /// `ack_due` figé (l'élément du statut a posé `first_response_ts` avant l'appel). V, non rouvert, garde P3.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_SANS_REOUVERTURE` (D garde P3), `AP3_INVERSE` (terminal/actif inversés : D
    /// garde P3).
    #[tokio::test]
    async fn prr_reouverture_par_le_statut_seul_regouverne_sur_la_priorite_ecrite_en_terminal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("priorite");
        let p3 = prr_politique(&st, 3, 3000, 30000, true);
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let d = prr_dossier(&st, "D", 3, "");
        let v = prr_dossier(&st, "V", 3, "");
        let addr = router_serve(st.clone()).await;
        for id in [d, v] {
            assert_eq!(prr_chrono(&st, id), (Some(p3), Some(prr_ts(&st, id) + 3000), Some(prr_ts(&st, id) + 30000)), "fixture : gouverné par P3");
            assert_eq!(prr_patch(addr, id, json!({ "status": "resolved" })).await, (204, Value::Null), "clôture");
        }
        let clos_d = prr_chrono(&st, d);
        let clos_v = prr_chrono(&st, v);
        for id in [d, v] {
            assert_eq!(prr_patch(addr, id, json!({ "priority": 1 })).await, (204, Value::Null), "priorité 1 écrite en terminal");
        }
        assert_eq!(prr_chrono(&st, d), clos_d, "contrôle : en terminal, la priorité écrite ne touche pas le chrono");

        assert_eq!(prr_patch(addr, d, json!({ "status": "triage" })).await, (204, Value::Null), "D rouvert par son statut seul");
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={d}")), "triage");
        assert_eq!(prr_chrono(&st, d), (Some(p1), clos_d.1, Some(prr_ts(&st, d) + 600)), "D regouverné par P1 (ack_due figé)");
        assert!(prr_entier(&st, &format!("SELECT first_response_ts FROM incident WHERE id={d}")).is_some(), "ack_due figé : MTTA déjà posé");
        assert_eq!(prr_chrono(&st, v), clos_v, "V, voisin non rouvert, intact (P3)");
    }

    /// CE QU'IL TIENT (décision ASSUMÉE : `ts` immuable) : P2 DÉSACTIVÉE, P1 active ; D et V de priorité 2, ANCIENS (`ts`
    /// reculé de 100 000 s), clos et non gouvernés. P2 activée entre-temps. D rouvert par la route : `sla_policy_id` = P2,
    /// `resolve_due` = ts + 1200 (déjà passé), `ack_due` NULL (MTTA posé par l'élément du statut) ; le tour NOTIFIE D en
    /// dépassement de résolution dès son passage. V, non rouvert, reste non gouverné et non notifié.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_SANS_REOUVERTURE` (D non gouverné, non notifié), `AP3_INVERSE`.
    #[tokio::test]
    async fn prr_politique_activee_entre_temps_regouverne_le_rouvert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("reactivee");
        let p2 = prr_politique(&st, 2, 120, 1200, false);
        let _p1 = prr_politique(&st, 1, 60, 600, true);
        let d = prr_dossier(&st, "D", 2, "ts = ts - 100000, status='closed'");
        let v = prr_dossier(&st, "V", 2, "ts = ts - 100000, status='closed'");
        for id in [d, v] {
            assert_eq!(prr_chrono(&st, id), (None, None, None), "fixture : non gouverné (P2 désactivée)");
        }
        prr_sql(&st, &format!("UPDATE sla_policy SET enabled=1 WHERE id={p2}"));
        let addr = router_serve(st.clone()).await;

        assert_eq!(prr_patch(addr, d, json!({ "status": "in_progress" })).await, (204, Value::Null), "D rouvert");
        assert_eq!(prr_chrono(&st, d), (Some(p2), None, Some(prr_ts(&st, d) + 1200)), "D gouverné par P2 activée entre-temps");
        assert_eq!(prr_chrono(&st, v), (None, None, None), "V, non rouvert, intact");
        let envois = prr_tick(&st);
        assert!(prr_notifie(&envois, d), "ASSUMÉ : D, ancien, est en dépassement dès le tour suivant : {envois:?}");
        assert!(!prr_notifie(&envois, v), "V, clos, n'est pas notifié : {envois:?}");
        assert_eq!(prr_entier(&st, &format!("SELECT resolve_breached FROM incident WHERE id={d}")), Some(1), "dépassement marqué sur D");
    }

    /// CE QU'IL TIENT : P1 active seule ; N terminal de priorité 4 non gouverné (bord NULL) ; E terminal de priorité 4 à
    /// politique PENDANTE (`sla_policy_id` 999) et échéances passées ; B de priorité 1 échu sous P1 (contrôle du tour) ;
    /// V comme E, non rouvert. N et E rouverts par la route (204) : (None, None, None) l'un et l'autre ; le tour ne notifie
    /// ni N ni E, notifie B ; V garde sa pendante.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_SANS_REOUVERTURE` (E garde 999, notifié).
    #[tokio::test]
    async fn prr_terminal_sans_politique_pour_sa_priorite_rouvert_au_regime_legacy() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("legacy");
        let echu = now() - 100;
        let n = prr_dossier(&st, "N", 4, "status='resolved'");
        let pendant = format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, status='closed'");
        let e = prr_dossier(&st, "E", 4, &pendant);
        let v = prr_dossier(&st, "V", 4, &pendant);
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let b = prr_dossier(&st, "B", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}"));
        let chrono_v = prr_chrono(&st, v);
        let addr = router_serve(st.clone()).await;

        for id in [n, e] {
            assert_eq!(prr_patch(addr, id, json!({ "status": "triage" })).await, (204, Value::Null), "rouvert");
            assert_eq!(prr_chrono(&st, id), (None, None, None), "aucune politique pour P4 : régime legacy");
        }
        assert_eq!(prr_chrono(&st, v), chrono_v, "V, voisin non rouvert, intact");
        let envois = prr_tick(&st);
        assert!(!prr_notifie(&envois, n) && !prr_notifie(&envois, e), "ni N ni E notifiés : {envois:?}");
        assert!(prr_notifie(&envois, b), "contrôle : B, échu sous P1, est notifié : {envois:?}");
    }

    /// CE QU'IL TIENT : P1 (60/600) active ; F de priorité 1 et G de priorité 4 FUSIONNÉS (`closed`) dans X, à politique
    /// PENDANTE et échéances passées, sans réponse (`first_response_ts` NULL) ; H comme F, non défusionné. F et G
    /// défusionnés par la route (204) : F = (P1, ts + 60, ts + 600), `ack_due` reposé (l'appel précède l'élément
    /// « dé-fusionné ») ; G = (None, None, None) ; H garde sa pendante et sa fusion.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_DEFUSION_SANS` (F et G gardent 999).
    #[tokio::test]
    async fn prr_defusion_regouverne_le_fusionne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("defusion");
        let echu = now() - 100;
        let x = prr_dossier(&st, "X", 3, "");
        let fusionne = format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, merged_into={x}, status='closed', first_response_ts=NULL");
        let f = prr_dossier(&st, "F", 1, &fusionne);
        let g = prr_dossier(&st, "G", 4, &fusionne);
        let h = prr_dossier(&st, "H", 1, &fusionne);
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let chrono_h = prr_chrono(&st, h);
        let addr = router_serve(st.clone()).await;

        for id in [f, g] {
            assert_eq!(prr_defusion(addr, id).await, (204, Value::Null), "défusion");
        }
        assert_eq!(prr_chrono(&st, f), (Some(p1), Some(prr_ts(&st, f) + 60), Some(prr_ts(&st, f) + 600)), "F regouverné par P1");
        assert_eq!(prr_chrono(&st, g), (None, None, None), "G, sans politique pour P4 : régime legacy");
        assert_eq!(prr_chrono(&st, h), chrono_h, "H, non défusionné, intact");
        assert_eq!(prr_entier(&st, &format!("SELECT merged_into FROM incident WHERE id={h}")), Some(x), "H toujours fusionné");
    }

    /// CE QU'IL TIENT (réouverture, refus d'écriture puis lecture ratée) : P1 active ; D1 et D2 de priorité 1 clos à
    /// politique pendante ; V voisin. Le chrono de D1 refusé (déclencheur sur `resolve_due`) : réouverture -> 503
    /// `{error: CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE, id}` à corps entier, statut ÉCRIT (`triage`, champ attesté dans sa
    /// transaction, avec sa chronologie), chrono inchangé. `sla_policy` illisible (renommée) : réouverture de D2 -> 503
    /// `{error: CAUSE_CHRONO_SLA_NON_LU, id}`, statut et chronologie écrits, chrono inchangé. V intact. (`updated` n'est
    /// pas jugé : l'élément de chronologie du statut le pose avant l'appel.)
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_REOUV_REFUSE_OK` (204 sur D1), `AP3_REOUV_NONLU_RIEN` (204 sur D2),
    /// `AP3_SANS_REOUVERTURE` (204 sur les deux).
    #[tokio::test]
    async fn prr_reouverture_refus_et_lecture_ratee_du_chrono_servis_nommes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("reouv-refus");
        let echu = now() - 100;
        let clos = format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, status='closed'");
        let d1 = prr_dossier(&st, "D1", 1, &clos);
        let d2 = prr_dossier(&st, "D2", 1, &clos);
        let v = prr_dossier(&st, "V", 1, &clos);
        prr_politique(&st, 1, 60, 600, true);
        let chrono = prr_chrono(&st, d1);
        let addr = router_serve(st.clone()).await;

        prr_refuser_le_chrono(&st, d1);
        let (statut, corps) = prr_patch(addr, d1, json!({ "status": "triage" })).await;
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("réouverture, chrono refusé", statut, &corps, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        prr_sql(&st, "DROP TRIGGER prr_chrono;");
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={d1}")), "triage", "le statut, attesté à part, est écrit");
        assert_eq!(prr_chrono(&st, d1), chrono, "chrono de D1 inchangé");
        assert_eq!(prr_entier(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={d1} AND body='statut -> triage'")), Some(1), "sa chronologie aussi");

        prr_sql(&st, "ALTER TABLE sla_policy RENAME TO prr_politique_cachee;");
        let (statut, corps) = prr_patch(addr, d2, json!({ "status": "triage" })).await;
        prr_sql(&st, "ALTER TABLE prr_politique_cachee RENAME TO sla_policy;");
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("réouverture, politique non lue", statut, &corps, crate::handlers::cases::CAUSE_CHRONO_SLA_NON_LU);
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={d2}")), "triage", "le statut est écrit");
        assert_eq!(prr_chrono(&st, d2), chrono, "chrono de D2 inchangé");
        assert_eq!(prr_entier(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={d2} AND body='statut -> triage'")), Some(1), "sa chronologie aussi");
        assert_eq!(prr_chrono(&st, v), chrono, "V intact");
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={v}")), "closed", "V toujours clos");
    }

    /// CE QU'IL TIENT (défusion, refus d'écriture puis lecture ratée) : P1 active ; F de priorité 1 fusionné (`closed`)
    /// dans X à politique pendante ; H voisin fusionné. Chrono de F refusé : défusion -> 503 `{error:
    /// CAUSE_DEFUSION_NON_ECRITE, id}`, F toujours fusionné et clos, chrono inchangé, aucun élément « dé-fusionné », aucun
    /// `case.unmerge`. `sla_policy` illisible : défusion -> 503 `{error: "<CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT> (relecture
    /// du dossier fusionné)", id}` sur `d50dc93c` (le dossier avait pourtant été lu) ; désormais `{error:
    /// CAUSE_DEFUSION_CHRONO_SLA_NON_LU, id}`, même état. Contrôle : levées, la défusion rend 204 et F est regouverné par
    /// P1. H intact.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_DEFUSION_REFUSE_OK` et `AP3_DEFUSION_NONLU_RIEN` (204, défusion non annulée),
    /// `AP3_DEFUSION_SANS` (204 sur les deux refus), `AP3C_DEFUSION_NONLU_DOSSIER` (phrase de `DossierNonLu`).
    #[tokio::test]
    async fn prr_defusion_refus_et_lecture_ratee_du_chrono_annulent_la_defusion() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("defusion-refus");
        let echu = now() - 100;
        let x = prr_dossier(&st, "X", 3, "");
        let fusionne = format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, merged_into={x}, status='closed'");
        let f = prr_dossier(&st, "F", 1, &fusionne);
        let h = prr_dossier(&st, "H", 1, &fusionne);
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let chrono = prr_chrono(&st, f);
        let addr = router_serve(st.clone()).await;
        let etat = |st: &AppState| {
            (
                prr_entier(st, &format!("SELECT merged_into FROM incident WHERE id={f}")),
                prr_texte(st, &format!("SELECT status FROM incident WHERE id={f}")),
                prr_chrono(st, f),
                prr_entier(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={f} AND body LIKE 'dé-fusionné%'")),
                prr_entier(st, "SELECT COUNT(*) FROM ledger WHERE kind='case.unmerge'"),
            )
        };
        let attendu = (Some(x), "closed".to_string(), chrono, Some(0), Some(0));

        prr_refuser_le_chrono(&st, f);
        let (statut, corps) = prr_defusion(addr, f).await;
        prr_sql(&st, "DROP TRIGGER prr_chrono;");
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("défusion, chrono refusé", statut, &corps, crate::handlers::caseops::CAUSE_DEFUSION_NON_ECRITE);
        assert_eq!(etat(&st), attendu, "défusion annulée : toujours fusionné, rien de tracé");

        prr_sql(&st, "ALTER TABLE sla_policy RENAME TO prr_politique_cachee;");
        let (statut, corps) = prr_defusion(addr, f).await;
        prr_sql(&st, "ALTER TABLE prr_politique_cachee RENAME TO sla_policy;");
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("défusion, politique non lue", statut, &corps, crate::handlers::caseops::CAUSE_DEFUSION_CHRONO_SLA_NON_LU);
        assert_eq!(etat(&st), attendu, "défusion annulée : toujours fusionné, rien de tracé");

        assert_eq!(prr_defusion(addr, f).await, (204, Value::Null), "contrôle : levées, la défusion aboutit");
        assert_eq!(prr_chrono(&st, f).0, Some(p1), "contrôle : F regouverné par P1");
        assert_eq!(prr_entier(&st, &format!("SELECT merged_into FROM incident WHERE id={h}")), Some(x), "H toujours fusionné");
        assert_eq!(prr_chrono(&st, h), chrono, "H intact");
    }

    /// CONTRÔLE POSITIF : P1 active ; A actif (`triage`) de priorité 1 à politique PENDANTE (valeur que la politique
    /// changerait), T clos de même. `{status: in_progress}` sur A, `{title}` seul sur A, `{status: resolved}` sur T
    /// (terminal -> terminal) et `{title}` seul sur T : 204 chacun, chrono de A et de T inchangé. Sur A, c'est l'absence de
    /// rejeu ; sur T, seulement « rien ne change » : `sla_apply_policy` garde le terminal, donc l'assertion sur T tient quoi
    /// que fasse le site de la réouverture (mutation « rouvert = etait_terminal » équivalente).
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3_TOUJOURS` (A regouverné par P1), `AP3_INVERSE` (actif -> actif rejoue).
    #[tokio::test]
    async fn prr_actif_vers_actif_et_titre_seul_ne_rejouent_pas_la_politique() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("controle");
        let echu = now() - 100;
        let a = prr_dossier(&st, "A", 1, &format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, status='triage'"));
        let t = prr_dossier(&st, "T", 1, &format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, status='closed'"));
        prr_politique(&st, 1, 60, 600, true);
        let chrono = prr_chrono(&st, a);
        assert_eq!(chrono, (Some(PRR_PENDANT), Some(echu), Some(echu)), "fixture : A porte la pendante");
        let addr = router_serve(st.clone()).await;

        assert_eq!(prr_patch(addr, a, json!({ "status": "in_progress" })).await, (204, Value::Null));
        assert_eq!(prr_chrono(&st, a), chrono, "actif -> actif : pas de rejeu");
        assert_eq!(prr_patch(addr, a, json!({ "title": "A2" })).await, (204, Value::Null));
        assert_eq!(prr_chrono(&st, a), chrono, "{{title}} seul : pas de rejeu");
        assert_eq!(prr_patch(addr, t, json!({ "status": "resolved" })).await, (204, Value::Null));
        assert_eq!(prr_patch(addr, t, json!({ "title": "T2" })).await, (204, Value::Null));
        assert_eq!(prr_chrono(&st, t), chrono, "terminal -> terminal et {{title}} : rien ne change");
    }

    /// `sla_paused_since` du dossier.
    fn prr_pause(st: &AppState, id: i64) -> Option<i64> {
        prr_entier(st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}"))
    }

    /// CE QU'IL TIENT (correction, statut legacy) : `contained` est un statut d'avant la v69 que la migration ne réécrit
    /// jamais ; il est terminal. P1 (60/600) active ; C et V de priorité 1 `contained`, à politique PENDANTE et échéances
    /// passées. C rouvert par la route (`triage`) : 204, `sla_policy_id` = P1, `resolve_due` = ts + 600 (`ack_due` figé :
    /// l'élément du statut a posé `first_response_ts`). V, non rouvert, garde sa pendante.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3C_SANS_CONTAINED` (`contained` hors des terminaux : C garde 999).
    #[tokio::test]
    async fn prr_contained_legacy_rouvert_regouverne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("contained");
        let echu = now() - 100;
        let contenu = format!("sla_policy_id={PRR_PENDANT}, ack_due={echu}, resolve_due={echu}, status='contained'");
        let c = prr_dossier(&st, "C", 1, &contenu);
        let v = prr_dossier(&st, "V", 1, &contenu);
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let chrono_v = prr_chrono(&st, v);
        assert_eq!(chrono_v, (Some(PRR_PENDANT), Some(echu), Some(echu)), "fixture : V porte la pendante");
        let addr = router_serve(st.clone()).await;

        assert_eq!(prr_patch(addr, c, json!({ "status": "triage" })).await, (204, Value::Null), "C rouvert");
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={c}")), "triage");
        assert_eq!(prr_chrono(&st, c), (Some(p1), Some(echu), Some(prr_ts(&st, c) + 600)), "C, legacy contained, regouverné par P1");
        assert_eq!(prr_chrono(&st, v), chrono_v, "V, non rouvert, intact");
        assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={v}")), "contained", "V toujours contained");
    }

    /// CE QU'IL TIENT (correction, défaut introduit par `d50dc93c`) : P1 (60/600) active ; D clos, ANCIEN (`ts` reculé de
    /// 100 000 s), NON gouverné (politique créée après lui) ; G clos, ancien, gouverné par P1 (contrôle : il portait une
    /// politique) ; B actif échu sous P1 (contrôle du tour). D et G rouverts directement en `waiting` par la route (204) :
    /// D = P1 ET en pause (`sla_paused_since` posé), G en pause ; le tour ne notifie ni D ni G, notifie B. Sur `d50dc93c`,
    /// D sortait gouverné sans pause et notifié en dépassement pendant l'attente.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3C_SANS_PAUSE` (D sans pause, notifié).
    #[tokio::test]
    async fn prr_terminal_non_gouverne_rouvert_en_attente_est_gouverne_et_en_pause() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("attente");
        let echu = now() - 100;
        let d = prr_dossier(&st, "D", 1, "ts = ts - 100000, status='closed'");
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let g = prr_dossier(&st, "G", 1, &format!("ts = ts - 100000, status='closed', sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}"));
        let b = prr_dossier(&st, "B", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}"));
        assert_eq!(prr_chrono(&st, d), (None, None, None), "fixture : D non gouverné");
        let addr = router_serve(st.clone()).await;

        for id in [d, g] {
            assert_eq!(prr_patch(addr, id, json!({ "status": "waiting" })).await, (204, Value::Null), "rouvert en attente");
            assert_eq!(prr_texte(&st, &format!("SELECT status FROM incident WHERE id={id}")), "waiting");
            assert_eq!(prr_chrono(&st, id).0, Some(p1), "gouverné par P1");
            assert!(prr_pause(&st, id).is_some(), "#{id} en attente gouverné : chrono EN PAUSE");
        }
        let envois = prr_tick(&st);
        assert!(!prr_notifie(&envois, d), "D en pause : pas de dépassement pendant l'attente : {envois:?}");
        assert!(!prr_notifie(&envois, g), "contrôle : G en pause, non notifié : {envois:?}");
        assert!(prr_notifie(&envois, b), "contrôle : B, échu et actif, est notifié : {envois:?}");
    }

    /// CE QU'IL TIENT (correction, classe préexistante du chemin de la priorité, couverte par le même remède) : P1 (60/600)
    /// active ; L de priorité 3, ANCIEN, EN ATTENTE, non gouverné (aucune politique P3) ; W, voisin pareil, laissé en P3 ;
    /// B actif échu sous P1. `{priority: 1}` sur L : 204, L = P1 ET en pause ; le tour ne notifie pas L, notifie B ; W reste
    /// non gouverné et sans pause. Sur `d50dc93c`, L sortait gouverné sans pause et notifié.
    /// MUTATIONS QUI LE FONT ROUGIR : `AP3C_SANS_PAUSE` (L sans pause, notifié).
    #[tokio::test]
    async fn prr_legacy_en_attente_passe_a_une_priorite_gouvernee_est_en_pause() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = prr_etat("attente-priorite");
        let echu = now() - 100;
        let l = prr_dossier(&st, "L", 3, "ts = ts - 100000, status='waiting'");
        let w = prr_dossier(&st, "W", 3, "ts = ts - 100000, status='waiting'");
        let p1 = prr_politique(&st, 1, 60, 600, true);
        let b = prr_dossier(&st, "B", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}"));
        assert_eq!((prr_chrono(&st, l), prr_pause(&st, l)), ((None, None, None), None), "fixture : L legacy, sans pause");
        let addr = router_serve(st.clone()).await;

        assert_eq!(prr_patch(addr, l, json!({ "priority": 1 })).await, (204, Value::Null), "L passé en P1");
        assert_eq!(prr_chrono(&st, l).0, Some(p1), "L gouverné par P1");
        assert!(prr_pause(&st, l).is_some(), "L en attente gouverné : chrono EN PAUSE");
        assert_eq!((prr_chrono(&st, w), prr_pause(&st, w)), ((None, None, None), None), "W, voisin, intact");
        let envois = prr_tick(&st);
        assert!(!prr_notifie(&envois, l), "L en pause : pas de dépassement pendant l'attente : {envois:?}");
        assert!(prr_notifie(&envois, b), "contrôle : B est notifié : {envois:?}");
    }
}
