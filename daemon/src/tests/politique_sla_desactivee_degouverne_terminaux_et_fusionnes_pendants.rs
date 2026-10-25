// =====================================================================================
// `P10.31-v` (reste, vague AO : « à la désactivation, les terminaux et fusionnés à politique pendante ou étrangère gardent
// leurs échéances, et rouverts ou défusionnés ils seraient notifiés en dépassement »).
//
// CE QUI MANQUAIT, MESURÉ SUR c6069774 : le second `UPDATE` de la désactivation (`sla_policy_upsert`, `enabled=false`)
// excluait `merged_into IS NOT NULL` et les statuts `resolved`/`closed`/`contained`. Un dossier terminal ou fusionné de la
// priorité qui portait le `sla_policy_id` d'une politique supprimée (pendant) ou d'une autre priorité (étranger) gardait
// ses échéances ; rouvert par son seul statut (`case_apply_update` ne rejoue `sla_apply_policy` que sur une priorité
// écrite) ou défusionné (`case_unmerge` non plus), le tour `sla_multilevel_tick_par` le NOTIFIAIT en dépassement dès qu'une
// autre politique restait active.
// REMÈDE : un troisième `UPDATE` dans la MÊME transaction, au prédicat COMPLÉMENTAIRE de celui des actifs (priorité,
// `sla_policy_id` non NULL, `merged_into IS NOT NULL OR status` terminal), posé après celui de la politique ; son compte
// entre dans `degouvernes` et, à part des actifs, dans le détail du maillon (« , dont T dossier(s) terminal(aux) ou
// fusionné(s) à politique pendante ou étrangère »). Même règle que `sla_policy_delete`. Recalcul toujours non rejoué.
// CE QU'ILS TIENNENT : bords 2, 1 et 0 relus au registre (terminal de la politique elle-même compté hors de la mention) ;
// fusionné à statut actif ; trois statuts terminaux à politique étrangère ; priorité voisine et dossiers non gouvernés à
// échéances orphelines intacts ; corps sans maillon (`degouvernes` total, `recomputed` 0) ; troisième effacement, `BEGIN`
// et `COMMIT` refusés : 500 à corps entier, rien posé ; ligne de journal du refus, entière, par capture en sous-processus ;
// fin de chaîne : un terminal rouvert PAR LA ROUTE du dossier et un fusionné défusionné PAR SA ROUTE ne sont pas notifiés,
// un dossier échu d'une politique active l'est.
// CE QU'ILS NE TIENNENT PAS : la réactivation ou la modification d'une politique (ne regouverne ni terminaux ni
// fusionnés NON rouverts) ; les marqueurs `ack_breached`/`resolve_breached` passés ; la console.
// INVERSÉ NOMMÉMENT (`P10.31-v`, vague AP) : la réouverture par le statut seul et `case_unmerge` REJOUENT désormais
// `sla_apply_policy` (témoins `prr_`, politique_sla_rejouee_a_la_reouverture_et_a_la_defusion.rs) ; les deux restes
// « la réouverture ne rejoue pas » et « `case_unmerge` qui ne rejoue pas la politique » sont retirés d'ici, et la fin de
// chaîne `ptf_fin_de_chaine_…` est désormais tenue par deux voies (voir son en-tête).
// Mutants (AO3_*, retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod politique_sla_desactivee_degouverne_terminaux_et_fusionnes_pendants {
    use super::*;

    const PTF_ENFANT: &str = "PTF_ENFANT_JOURNAL";
    const PTF_RENDU: &str = "PTF-RENDU";
    const PTF_MOTIF: &str = "ptf refus terminal";
    const PTF_PENDANT: i64 = 999;
    const PTF_SUFFIXE: &str = "dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)";

    fn ptf_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ptf-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ptf_editeur() -> AuthUser {
        AuthUser {
            name: "redacteur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ptf_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ptf_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn ptf_details(st: &AppState) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare("SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id").unwrap();
        s.query_map([], |x| x.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn ptf_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé à la priorité donnée, puis `UPDATE incident SET <reglage> WHERE id=<id>`.
    fn ptf_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            ptf_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// Dossier qui porte une politique et deux échéances PASSÉES (valeur discriminante : le tour les jugerait dépassées).
    fn ptf_gouverne(st: &AppState, titre: &str, priorite: i64, politique: i64, extra: &str) -> i64 {
        let e = now() - 100;
        let reglage = format!("sla_policy_id={politique}, ack_due={e}, resolve_due={e}{extra}");
        ptf_dossier(st, titre, priorite, &reglage)
    }

    fn ptf_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }

    async fn ptf_corps(rep: axum::response::Response) -> (u16, Vec<u8>) {
        let statut = rep.status().as_u16();
        (statut, axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    async fn ptf_upsert(st: &AppState, corps: Value) -> (u16, Vec<u8>) {
        ptf_corps(crate::handlers::caseops::sla_policy_upsert(State(st.clone()), Extension(ptf_editeur()), Json(corps)).await.into_response()).await
    }

    fn ptf_desactiver_p1() -> Value {
        json!({ "name": "P1", "priority": 1, "ack_target_s": 60, "resolve_target_s": 600, "enabled": false })
    }

    /// Le détail attendu du maillon : compte total, mention des actifs, puis mention des terminaux ou fusionnés.
    fn ptf_detail(degouvernes: usize, actifs: usize, terminaux: usize) -> String {
        let mut d = "P1 ack=60s resolve=600s enabled=0 by redacteur".to_string();
        if degouvernes > 0 {
            d.push_str(&format!(" ; {degouvernes} {PTF_SUFFIXE}"));
        }
        if actifs > 0 {
            d.push_str(&format!(", dont {actifs} dossier(s) actif(s) à politique pendante ou étrangère"));
        }
        if terminaux > 0 {
            d.push_str(&format!(", dont {terminaux} dossier(s) terminal(aux) ou fusionné(s) à politique pendante ou étrangère"));
        }
        d
    }

    /// Le cinq cents de l'upsert, corps ENTIER : `{id, reason, recomputed}`, la phrase fixe, `recomputed` 0.
    fn ptf_cinq_cents(statut: u16, corps: &[u8], motif: &str) -> String {
        let v: Value = serde_json::from_slice(corps).unwrap_or(Value::Null);
        assert_eq!(statut, 500, "{motif} : 500, jamais une désactivation annoncée : {v}");
        let mut cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        cles.sort_unstable();
        assert_eq!(cles, ["id", "reason", "recomputed"], "{motif} : ensemble exact des clés : {v}");
        assert_eq!(v["recomputed"], json!(0), "{motif} : {v}");
        assert_eq!(v["reason"], json!(crate::handlers::caseops::CAUSE_POLITIQUE_SLA_NON_ENREGISTREE), "{motif} : la phrase seule : {v}");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "{motif} : identifiant servi : {v}");
        id
    }

    /// CE QU'IL TIENT (bord 2) : sous P1 et P2 actives, A actif de P1, T1 terminal de P1 (dégouverné par le premier
    /// `UPDATE`, hors de la mention), D actif à politique PENDANTE, R `resolved` à politique PENDANTE, FE FUSIONNÉ à statut
    /// actif (`triage`) portant la politique ÉTRANGÈRE de P2. Désactiver P1 -> 204 ; les cinq au régime legacy ; registre
    /// « … ; 5 … , dont 1 … actif(s) …, dont 2 … terminal(aux) ou fusionné(s) … ».
    /// MUTATIONS QUI LE FONT ROUGIR : `AO3_DETAIL_OMIS`, `AO3_DEGOUVERNES_SANS_TERMINAUX` (« 3 »), `AO3_DOUBLE_COMPTE`
    /// (« 7 », « dont 3 actifs »), `AO3_ORDRE_INVERSE` (troisième `UPDATE` avant celui de la politique : T1 dans la
    /// mention, « dont 3 »), `AO3_STATUT_REVENU` (R intact), `AO3_FUSION_REVENUE` (FE intact).
    #[tokio::test]
    async fn ptf_bord_deux_terminal_pendant_et_fusionne_etranger_comptes_a_part() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le gestionnaire lit l'environnement
        let (st, _t) = ptf_etat("deux");
        let p1 = ptf_politique(&st, "P1", 1);
        let p2 = ptf_politique(&st, "P2", 2);
        let x = ptf_dossier(&st, "X", 3, "");
        let a = ptf_gouverne(&st, "A", 1, p1, "");
        let t1 = ptf_gouverne(&st, "T1", 1, p1, ", status='closed'");
        let d = ptf_gouverne(&st, "D", 1, PTF_PENDANT, "");
        let r = ptf_gouverne(&st, "R", 1, PTF_PENDANT, ", status='resolved'");
        let fe = ptf_gouverne(&st, "FE", 1, p2, &format!(", merged_into={x}, status='triage'"));
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "désactivation complète, maillon inscrit : 204 muet");
        for (nom, id) in [("A", a), ("T1", t1), ("D", d), ("R", r), ("FE", fe)] {
            assert_eq!(ptf_chrono(&st, id), (None, None, None), "{nom} au régime legacy");
        }
        assert_eq!(ptf_chrono(&st, x), (None, None, None), "contrôle : X, cible de fusion non gouvernée, sans chrono");
        assert_eq!(ptf_details(&st), vec![ptf_detail(5, 1, 2)], "le registre compte les cinq, actifs et terminaux à part");
    }

    /// CE QU'IL TIENT (bord 1) : P1 ne gouverne aucun dossier ; K `contained`, seul, à politique pendante. Désactiver P1 ->
    /// 204, K au régime legacy, registre « … ; 1 … , dont 1 dossier(s) terminal(aux) ou fusionné(s) … ».
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_BORD_UN` (`terminaux > 1`), `AO3_STATUT_REVENU`.
    #[tokio::test]
    async fn ptf_bord_un_terminal_seul_au_registre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("un");
        let _p1 = ptf_politique(&st, "P1", 1);
        let k = ptf_gouverne(&st, "K", 1, PTF_PENDANT, ", status='contained'");
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(ptf_chrono(&st, k), (None, None, None), "K au régime legacy");
        assert_eq!(ptf_details(&st), vec![ptf_detail(1, 0, 1)], "un seul terminal : le registre le dit");
    }

    /// CE QU'IL TIENT (bord 0) : A de P1 et D actif pendant, aucun terminal ni fusionné. Registre « … ; 2 …, dont 1 …
    /// actif(s) … » sans mention des terminaux.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_BORD_ZERO` (« , dont 0 dossier(s) terminal(aux) … » écrit).
    #[tokio::test]
    async fn ptf_bord_zero_terminal_sans_mention() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("zero");
        let p1 = ptf_politique(&st, "P1", 1);
        let a = ptf_gouverne(&st, "A", 1, p1, "");
        let d = ptf_gouverne(&st, "D", 1, PTF_PENDANT, "");
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!((ptf_chrono(&st, a), ptf_chrono(&st, d)), ((None, None, None), (None, None, None)));
        assert_eq!(ptf_details(&st), vec![ptf_detail(2, 1, 0)], "aucun terminal : aucune mention");
    }

    /// CE QU'IL TIENT : les trois statuts terminaux (`resolved`, `closed`, `contained`) d'un dossier de priorité 1 qui porte
    /// la politique ÉTRANGÈRE de P2 sont effacés, comptés à part ; B2, terminal de priorité 2 gouverné par P2 (active),
    /// est intact, et P2 aussi.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_STATUT_REVENU`, `AO3_SANS_PRIORITE` (B2 effacé).
    #[tokio::test]
    async fn ptf_trois_statuts_terminaux_a_politique_etrangere() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("etrangere");
        let _p1 = ptf_politique(&st, "P1", 1);
        let p2 = ptf_politique(&st, "P2", 2);
        let r = ptf_gouverne(&st, "R", 1, p2, ", status='resolved'");
        let c = ptf_gouverne(&st, "C", 1, p2, ", status='closed'");
        let k = ptf_gouverne(&st, "K", 1, p2, ", status='contained'");
        let b2 = ptf_gouverne(&st, "B2", 2, p2, ", status='resolved'");
        let avant_b2 = ptf_chrono(&st, b2);
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        for (nom, id) in [("resolved", r), ("closed", c), ("contained", k)] {
            assert_eq!(ptf_chrono(&st, id), (None, None, None), "{nom} à politique étrangère au régime legacy");
        }
        assert_eq!(ptf_chrono(&st, b2), avant_b2, "B2, priorité 2 gouvernée par P2, intact");
        assert_eq!(ptf_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=2"), Some(1), "P2 toujours active");
        assert_eq!(ptf_details(&st), vec![ptf_detail(3, 0, 3)], "les trois comptés à part des actifs");
    }

    /// CE QU'IL TIENT : V terminal et VF fusionné de priorité 2, tous deux à politique pendante, ne sont pas touchés par la
    /// désactivation de P1 ; rien compté.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_SANS_PRIORITE` (troisième `UPDATE` sans `priority=?1`).
    #[tokio::test]
    async fn ptf_priorite_voisine_terminale_et_fusionnee_intactes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("voisine");
        let _p1 = ptf_politique(&st, "P1", 1);
        let x = ptf_dossier(&st, "X", 3, "");
        let v = ptf_gouverne(&st, "V", 2, PTF_PENDANT, ", status='closed'");
        let vf = ptf_gouverne(&st, "VF", 2, PTF_PENDANT, &format!(", merged_into={x}, status='triage'"));
        let (avant_v, avant_vf) = (ptf_chrono(&st, v), ptf_chrono(&st, vf));
        assert_eq!((avant_v.0, avant_vf.0), (Some(PTF_PENDANT), Some(PTF_PENDANT)), "fixture : deux pendants de priorité 2");
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(ptf_chrono(&st, v), avant_v, "V, priorité 2, intact");
        assert_eq!(ptf_chrono(&st, vf), avant_vf, "VF, priorité 2, intact");
        assert_eq!(ptf_details(&st), vec![ptf_detail(0, 0, 0)], "rien compté");
    }

    /// CE QU'IL TIENT : L terminal et LF fusionné de priorité 1 au régime legacy (`sla_policy_id` NULL) qui portent des
    /// échéances orphelines ne sont ni effacés ni comptés (aucune politique portée : rien à dégouverner).
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_SANS_NON_NULL` (troisième `UPDATE` sans `sla_policy_id IS NOT NULL`).
    #[tokio::test]
    async fn ptf_terminal_et_fusionne_non_gouvernes_intacts() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("legacy");
        let _p1 = ptf_politique(&st, "P1", 1);
        let x = ptf_dossier(&st, "X", 3, "");
        let e = now() - 100;
        let l = ptf_dossier(&st, "L", 1, &format!("sla_policy_id=NULL, ack_due={e}, resolve_due={e}, status='resolved'"));
        let lf = ptf_dossier(&st, "LF", 1, &format!("sla_policy_id=NULL, ack_due={e}, resolve_due={e}, merged_into={x}"));
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(ptf_chrono(&st, l), (None, Some(e), Some(e)), "L legacy intact, échéances orphelines comprises");
        assert_eq!(ptf_chrono(&st, lf), (None, Some(e), Some(e)), "LF legacy intact, échéances orphelines comprises");
        assert_eq!(ptf_details(&st), vec![ptf_detail(0, 0, 0)], "ni L ni LF comptés");
    }

    /// CE QU'IL TIENT (corps sans maillon) : maillon refusé (trigger sur `ledger`) ; A de P1, R `resolved` pendant, FE
    /// fusionné étranger. Désactiver P1 -> 200, corps ENTIER `{degouvernes: 3, recomputed: 0, registre_sans_maillon}` :
    /// chacun compté une fois, dans `degouvernes`, jamais dans `recomputed`.
    /// MUTATIONS QUI LE FONT ROUGIR : `AO3_DEGOUVERNES_SANS_TERMINAUX` (1), `AO3_DOUBLE_COMPTE` (5).
    #[tokio::test]
    async fn ptf_sans_maillon_terminaux_dans_degouvernes_pas_dans_recomputed() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("corps");
        let p1 = ptf_politique(&st, "P1", 1);
        let p2 = ptf_politique(&st, "P2", 2);
        let x = ptf_dossier(&st, "X", 3, "");
        let a = ptf_gouverne(&st, "A", 1, p1, "");
        let r = ptf_gouverne(&st, "R", 1, PTF_PENDANT, ", status='resolved'");
        let fe = ptf_gouverne(&st, "FE", 1, p2, &format!(", merged_into={x}, status='closed'"));
        ptf_sql(&st, "CREATE TEMP TRIGGER ptf_reg BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'ptf reg'); END;");
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        ptf_sql(&st, "DROP TRIGGER ptf_reg;");
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "maillon manquant : 200 ({v})");
        let attendu = json!({
            "degouvernes": 3,
            "recomputed": 0,
            CLE_REGISTRE_SANS_MAILLON: format!("{CAUSE_GESTE_SANS_TRACE} ({})", crate::ledger::CAUSE_MAILLON_NON_ECRIT),
        });
        assert_eq!(v, attendu, "corps entier : les trois dans `degouvernes`, aucun recalcul compté");
        for (nom, id) in [("A", a), ("R", r), ("FE", fe)] {
            assert_eq!(ptf_chrono(&st, id), (None, None, None), "{nom} au régime legacy");
        }
        assert!(ptf_details(&st).is_empty(), "aucun maillon n'est entré");
    }

    /// Le scénario du troisième effacement refusé : trigger qui refuse l'effacement de l'échéance du seul terminal pendant
    /// (`resolved`). Rend le statut, le corps, et A (de P1), D (actif pendant), R (terminal pendant).
    async fn ptf_jouer_le_refus_du_terminal(st: &AppState) -> (u16, Vec<u8>, i64, i64, i64) {
        let p1 = ptf_politique(st, "P1", 1);
        let a = ptf_gouverne(st, "A", 1, p1, "");
        let d = ptf_gouverne(st, "D", 1, PTF_PENDANT, "");
        let r = ptf_gouverne(st, "R", 1, PTF_PENDANT, ", status='resolved'");
        ptf_sql(
            st,
            &format!(
                "CREATE TEMP TRIGGER ptf_refus BEFORE UPDATE OF ack_due ON incident \
                 WHEN OLD.sla_policy_id={PTF_PENDANT} AND OLD.status='resolved' \
                 BEGIN SELECT RAISE(ABORT, '{PTF_MOTIF}'); END;"
            ),
        );
        let (statut, corps) = ptf_upsert(st, ptf_desactiver_p1()).await;
        ptf_sql(st, "DROP TRIGGER ptf_refus;");
        (statut, corps, a, d, r)
    }

    /// CE QU'IL TIENT : le TROISIÈME effacement refusé (R seul visé ; ceux de A et de D passent) -> 500 à corps entier,
    /// désactivation ANNULÉE : P1 active, A, D et R gardent leur chrono, rien au registre.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_REFUS_AVALE` (`.unwrap_or(0)` : désactivation validée, R intact, 204).
    #[tokio::test]
    async fn ptf_effacement_des_terminaux_refuse_annule_tout() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("refus");
        let (statut, corps, a, d, r) = ptf_jouer_le_refus_du_terminal(&st).await;
        ptf_cinq_cents(statut, &corps, "troisième effacement refusé");
        assert_eq!(ptf_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "P1 GOUVERNE toujours");
        assert_eq!(ptf_chrono(&st, a).0, ptf_entier(&st, "SELECT id FROM sla_policy WHERE priority=1"), "A toujours gouverné par P1");
        assert!(ptf_chrono(&st, a).1.is_some(), "A garde ses échéances (premier effacement annulé)");
        assert_eq!(ptf_chrono(&st, d).0, Some(PTF_PENDANT), "D garde sa politique pendante (second effacement annulé)");
        assert!(ptf_chrono(&st, d).1.is_some(), "D garde ses échéances");
        assert_eq!(ptf_chrono(&st, r).0, Some(PTF_PENDANT), "R garde sa politique pendante");
        assert!(ptf_chrono(&st, r).1.is_some(), "R garde ses échéances");
        assert!(ptf_details(&st).is_empty(), "rien au registre");
    }

    /// CE QU'IL TIENT : `BEGIN IMMEDIATE` refusé (transaction étrangère ouverte) avec R `resolved` pendant -> 500 à corps
    /// entier ; R intact, lu AVANT le ROLLBACK de l'étrangère (une écriture faite dans cette transaction s'y verrait).
    /// Contrôle : ROLLBACK, la même désactivation aboutit et efface R.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_HORS_TRANSACTION` (effacement des terminaux joué avant le geste : il s'écrit dans
    /// la transaction étrangère).
    #[tokio::test]
    async fn ptf_begin_refuse_ne_touche_pas_le_terminal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("begin");
        let _p1 = ptf_politique(&st, "P1", 1);
        let r = ptf_gouverne(&st, "R", 1, PTF_PENDANT, ", status='resolved'");
        let avant = ptf_chrono(&st, r);
        ptf_sql(&st, "BEGIN");
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert!(!st.db.lock().is_autocommit(), "la transaction étrangère reste ouverte");
        ptf_cinq_cents(statut, &corps, "BEGIN refusé");
        assert_eq!(ptf_chrono(&st, r), avant, "R intact (lu dans la transaction étrangère)");
        assert!(ptf_details(&st).is_empty(), "rien au registre");
        ptf_sql(&st, "ROLLBACK");
        assert_eq!(ptf_upsert(&st, ptf_desactiver_p1()).await.0, 204, "contrôle : la même désactivation aboutit");
        assert_eq!(ptf_chrono(&st, r), (None, None, None), "contrôle : R effacé");
    }

    /// CE QU'IL TIENT : `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par un trigger temporaire) avec R pendant -> 500 à
    /// corps entier ; R intact, P1 active, rien au registre, aucune transaction laissée ouverte.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_HORS_TRANSACTION` (effacement validé avant le `BEGIN`, il survit au refus).
    #[tokio::test]
    async fn ptf_commit_refuse_ne_touche_pas_le_terminal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("commit");
        let _p1 = ptf_politique(&st, "P1", 1);
        let r = ptf_gouverne(&st, "R", 1, PTF_PENDANT, ", status='resolved'");
        let avant = ptf_chrono(&st, r);
        ptf_sql(
            &st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE ptf_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE ptf_enfant(p INTEGER REFERENCES ptf_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER ptf_fk AFTER UPDATE ON sla_policy BEGIN INSERT INTO ptf_enfant VALUES(999); END;",
        );
        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
        ptf_cinq_cents(statut, &corps, "COMMIT refusé");
        assert_eq!(ptf_chrono(&st, r), avant, "R intact");
        assert_eq!(ptf_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "P1 GOUVERNE toujours");
        assert!(ptf_details(&st).is_empty(), "rien au registre");
    }

    /// CE QU'IL TIENT (journal, par capture en sous-processus) : le troisième effacement refusé écrit UNE ligne `[caseops]`,
    /// ENTIÈRE : `[caseops] WARN politique SLA NON enregistrée (<id servi>) : effacement des échéances des dossiers terminaux
    /// ou fusionnés à politique pendante ou étrangère refusé (<motif>)` — distincte de celle des actifs.
    /// MUTATIONS QUI LE FONT ROUGIR : `AO3_REFUS_AVALE` (aucun cinq cents, aucune ligne), `AO3_JOURNAL_CONFONDU` (la phrase
    /// des actifs).
    #[tokio::test]
    async fn ptf_journal_du_refus_des_terminaux() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'enfant reçoit son environnement par `.env(`, le parent lit
        if std::env::var(PTF_ENFANT).is_ok() {
            let (st, _t) = ptf_etat("journal");
            let (statut, corps, _, _, _) = ptf_jouer_le_refus_du_terminal(&st).await;
            let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
            println!("{PTF_RENDU} {statut} {}", v["id"].as_str().unwrap_or("absent"));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::politique_sla_desactivee_degouverne_terminaux_et_fusionnes_pendants::ptf_journal_du_refus_des_terminaux",
            ])
            .env(PTF_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (statut, id) = stdout
            .lines()
            .find_map(|l| l.split_once(PTF_RENDU))
            .and_then(|(_, r)| r.trim().split_once(' ').map(|(s, i)| (s.to_string(), i.to_string())))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué le refus : {stdout}\n{stderr}"));
        assert_eq!(statut, "500", "l'enfant a lu le cinq cents : {stdout}");
        assert!(id.starts_with("plume-e"), "identifiant servi : {stdout}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("[caseops]")).collect();
        assert_eq!(
            lignes,
            vec![format!(
                "[caseops] WARN politique SLA NON enregistrée ({id}) : effacement des échéances des dossiers terminaux ou fusionnés à politique pendante ou étrangère refusé ({PTF_MOTIF})"
            )],
            "une ligne EXACTE, reliée au corps par l'identifiant :\n{stderr}"
        );
    }

    /// CE QU'IL TIENT (fin de chaîne, échéances PASSÉES) : sous P1 et P2 actives, T `resolved` de priorité 1 à politique
    /// PENDANTE, F de priorité 1 FUSIONNÉ (`closed`) portant la politique ÉTRANGÈRE de P2, B de priorité 2 échu sous P2.
    /// Désactiver P1 ; rouvrir T PAR LA ROUTE du dossier (`case_update`, statut seul : 204) ; défusionner F PAR SA ROUTE
    /// (`case_unmerge_handler` : 204). Le tour `sla_multilevel_tick_par` ne notifie ni T ni F, ne leur marque aucun
    /// dépassement, et notifie B (contrôle : le tour tourne et juge).
    /// INVERSÉ NOMMÉMENT (`P10.31-v`, vague AP) : il disait « MUTATIONS QUI LE FONT ROUGIR : `AO3_STATUT_REVENU` (T et F
    /// gardent leurs échéances et sont notifiés une fois rouverts ou défusionnés), `AO3_FUSION_REVENUE` sous sa forme
    /// `merged_into IS NULL` ». Ce n'est plus vrai : la réouverture par le statut et la défusion rejouent `sla_apply_policy`,
    /// qui, P1 désactivée, efface la pendante ou l'étrangère d'un dossier redevenu actif — T et F reviennent au régime legacy
    /// MÊME si la désactivation les avait laissés. La fin de chaîne est tenue par DEUX voies (désactivation, puis rejeu) ;
    /// le troisième `UPDATE` de la désactivation est tenu par `ptf_bord_deux`, `ptf_bord_un`, `ptf_bord_zero` et
    /// `pdp_fusionne` (relus avant toute réouverture), et le rejeu par les témoins `prr_` (mutants `AP3_*`). Le chrono de T
    /// et F, relu après la réouverture et la défusion, est (None, None, None).
    #[tokio::test]
    async fn ptf_fin_de_chaine_terminal_rouvert_et_fusionne_defusionne_non_notifies() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = ptf_etat("chaine");
        let _p1 = ptf_politique(&st, "P1", 1);
        let p2 = ptf_politique(&st, "P2", 2);
        let x = ptf_dossier(&st, "X", 3, "");
        let t = ptf_gouverne(&st, "T", 1, PTF_PENDANT, ", status='resolved'");
        let f = ptf_gouverne(&st, "F", 1, p2, &format!(", merged_into={x}, status='closed'"));
        let b = ptf_gouverne(&st, "B", 2, p2, "");
        ptf_sql(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('ptf','webhook',1,'https://example.invalid/h',0,'{}')");

        let (statut, corps) = ptf_upsert(&st, ptf_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "désactivation de P1");
        let (statut, corps) = ptf_corps(
            crate::handlers::cases::case_update(State(st.clone()), Extension(ptf_editeur()), axum::extract::Path(t), Json(json!({ "status": "triage" })))
                .await
                .into_response(),
        )
        .await;
        assert_eq!((statut, String::from_utf8_lossy(&corps).to_string()), (204, String::new()), "T rouvert par son statut seul");
        let (statut, corps) = ptf_corps(
            crate::handlers::caseops::case_unmerge_handler(State(st.clone()), Extension(ptf_editeur()), axum::extract::Path(f)).await.into_response(),
        )
        .await;
        assert_eq!((statut, String::from_utf8_lossy(&corps).to_string()), (204, String::new()), "F défusionné");
        assert_eq!(
            ptf_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE id IN ({t},{f}) AND merged_into IS NULL AND status='triage'")),
            Some(2),
            "contrôle : T et F sont ACTIFS et non fusionnés, donc à la portée du tour"
        );
        for (nom, id) in [("T rouvert", t), ("F défusionné", f)] {
            assert_eq!(ptf_chrono(&st, id), (None, None, None), "{nom} : régime legacy (désactivation, puis rejeu de la politique)");
        }

        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _ti: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        for (nom, id) in [("T rouvert", t), ("F défusionné", f)] {
            assert!(
                !envois.iter().any(|d| d.starts_with(&format!("Case #{id} "))),
                "{nom}, à politique pendante ou étrangère d'une priorité désactivée, n'est pas notifié : {envois:?}"
            );
            assert_eq!(
                ptf_entier(&st, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={id}")),
                Some(0),
                "aucun dépassement marqué sur {nom}"
            );
        }
        assert!(envois.iter().any(|d| d.starts_with(&format!("Case #{b} "))), "contrôle : B, échu sous P2 active, est notifié : {envois:?}");
    }
}
