// =====================================================================================
// `P10.31-v` (reste vague AP : « un legacy en attente gouverné par l'upsert d'une politique, hors `case_apply_update` »).
//
// CE QUI MANQUAIT, LU SUR 5c7b6de8 : le recalcul de l'upsert (`sla_recalcule_la_priorite_bornee`, caseops.rs) liste tous
// les dossiers actifs non fusionnés de la priorité, `waiting` compris, et leur applique `sla_apply_policy` sans reposer la
// pause. Un dossier legacy (ou non gouverné jusque-là) en attente sortait gouverné avec `sla_paused_since` NULL ; le tour
// multi-niveau (`sla_multilevel_tick_par`, filtre `sla_paused_since IS NULL`) le marquait et le NOTIFIAIT en dépassement
// pendant l'attente.
// REMÈDE : même patron que `case_apply_update` (cases.rs, politique PUIS pause) : `Ecrit` sur un dossier `waiting` ->
// `sla_on_status_change(conn, id, "waiting", t)`. Pause écrite ou déjà posée -> compté recalculé ; refusée ou non lue ->
// jamais compté, nommée dans `reason` sous sa propre phrase (refus et lecture ratée distincts), bornée à cinq.
// CE QU'ILS TIENNENT, PAR LE ROUTEUR RÉEL (compte `editor`, POST /api/sla-policies) puis le tour : legacy en attente
// gouverné ET en pause, non marqué, non notifié ; voisin actif de la même priorité gouverné SANS pause et notifié (le tour
// a bien tourné) ; en attente déjà en pause : pause d'avant conservée ; en attente d'une autre priorité et terminal
// intacts ; pause refusée -> 200 à corps entier, compte exact ; pause non lue -> 200 à corps entier, phrase distincte ;
// borne de cinq dans les deux phrases.
// CE QU'ILS NE TIENNENT PAS (limites, sans code) : une politique réactivée ou modifiée ne regouverne ni terminaux ni
// fusionnés (rejoué à la réouverture et à la défusion) ; `sla_due` legacy à la défusion ; les marqueurs
// `ack_breached`/`resolve_breached` passés (conservés à dessein) ; `ack_due` non reposé ; la console.
// Mutants (AS4_*, posés sous cfg!(test) puis retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod politique_sla_upsert_met_en_pause_l_attente {
    use super::*;

    const PUA_PENDANT: i64 = 999;
    const PUA_PAUSE_ANCIENNE: i64 = 1000;
    const PUA_REFUS: &str = "pause(s) REFUSÉE(S) par la base — ces cases EN ATTENTE ont leur nouvelle échéance mais leur chrono n'est PAS en pause, le tour peut les juger en dépassement pendant l'attente : ";
    const PUA_NON_LUE: &str = "pause(s) NON POSÉE(S) faute de LECTURE du chrono — ces cases EN ATTENTE ont leur nouvelle échéance mais leur chrono n'est PAS en pause, le tour peut les juger en dépassement pendant l'attente : ";

    fn pua_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, chemin) = router_test_state(&format!("pua-{tag}"));
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('pua_edt',?1,'editor')", params![hash_pw("puaediteur12345").unwrap()])
            .expect("fixture : compte éditeur");
        pua_sql(&st, "DELETE FROM incident; DELETE FROM sla_policy;");
        (st, chemin)
    }

    fn pua_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("pua_edt:puaediteur12345"))
    }

    fn pua_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pua_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    /// Dossier semé à la priorité donnée, puis `UPDATE incident SET <reglage> WHERE id=<id>` (vide : rien).
    fn pua_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            pua_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// (sla_policy_id, ack_due, resolve_due).
    fn pua_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    fn pua_ts(st: &AppState, id: i64) -> i64 {
        pua_entier(st, &format!("SELECT ts FROM incident WHERE id={id}")).expect("ts")
    }

    fn pua_pause(st: &AppState, id: i64) -> Option<i64> {
        pua_entier(st, &format!("SELECT sla_paused_since FROM incident WHERE id={id}"))
    }

    fn pua_politique_p3(st: &AppState) -> i64 {
        pua_entier(st, "SELECT id FROM sla_policy WHERE priority=3").expect("P3 écrite")
    }

    /// Statut et corps d'une réponse HTTP brute : `Value::Null` pour un corps vide (204).
    fn pua_rendu(code: u16, brut: &str) -> (u16, Value) {
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

    /// POST /api/sla-policies de P3 (3000/30000, active) au jeton éditeur.
    async fn pua_upsert_p3(addr: std::net::SocketAddr) -> (u16, Value) {
        let corps = json!({ "name": "P3", "priority": 3, "ack_target_s": 3000, "resolve_target_s": 30000 }).to_string();
        let (code, brut) = router_probe_envoi(addr, "POST", "/api/sla-policies", Some(&pua_authz()), &[("Content-Type", "application/json")], &corps).await;
        pua_rendu(code, &brut)
    }

    fn pua_tick(st: &AppState) -> Vec<String> {
        pua_sql(st, "INSERT OR IGNORE INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pua','webhook',1,'https://example.invalid/h',0,'{}')");
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _ti: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    fn pua_notifie(envois: &[String], id: i64) -> bool {
        envois.iter().any(|d| d.starts_with(&format!("Case #{id} ")))
    }

    /// (ack_breached, resolve_breached).
    fn pua_marqueurs(st: &AppState, id: i64) -> (Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT ack_breached, resolve_breached FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    }

    /// CE QU'IL TIENT : aucune politique ; dossiers ANCIENS (`ts` reculé de 100 000 s, échéances de P3 passées) :
    /// L priorité 3 EN ATTENTE legacy ; O priorité 3 `open` (voisin actif) ; P priorité 3 en attente DÉJÀ en pause
    /// (`sla_paused_since` = 1000, politique pendante) ; X priorité 2 en attente ; T priorité 3 `closed`. Upsert de P3 par la
    /// route : 204. Le tour, joué aussitôt : L ni marqué ni notifié, P non notifié, O notifié et marqué (contrôle : le tour
    /// a jugé la priorité). Puis : L gouverné par P3 ET en pause (posée par ce geste) ; O gouverné SANS pause ; P gouverné,
    /// pause d'avant CONSERVÉE (idempotence) ; X et T intacts, sans pause.
    /// MUTATIONS QUI LE FONT ROUGIR : `AS4_SANS_PAUSE` (L notifié en dépassement pendant l'attente), `AS4_PAUSE_AVANT`
    /// (pause jouée avant la politique : L legacy, `RienAFaire`, notifié), `AS4_TOUS_STATUTS` (O mis en pause), `AS4_PAUSE_DIRECTE` (pause
    /// écrite sans `sla_on_status_change` : celle de P écrasée).
    #[tokio::test]
    async fn pua_legacy_en_attente_gouverne_par_l_upsert_est_en_pause_et_non_notifie() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pua_etat("nominal");
        let l = pua_dossier(&st, "L", 3, "ts = ts - 100000, status='waiting'");
        let o = pua_dossier(&st, "O", 3, "ts = ts - 100000, status='open'");
        let p = pua_dossier(&st, "P", 3, &format!("ts = ts - 100000, status='waiting', sla_policy_id={PUA_PENDANT}, sla_paused_since={PUA_PAUSE_ANCIENNE}"));
        let x = pua_dossier(&st, "X", 2, "ts = ts - 100000, status='waiting'");
        let t = pua_dossier(&st, "T", 3, "ts = ts - 100000, status='closed'");
        assert_eq!((pua_chrono(&st, l), pua_pause(&st, l)), ((None, None, None), None), "fixture : L legacy, sans pause");
        assert_eq!(pua_chrono(&st, o), (None, None, None), "fixture : O legacy");
        let addr = router_serve(st.clone()).await;
        let avant = now();

        assert_eq!(pua_upsert_p3(addr).await, (204, Value::Null), "P3 posée, tout recalculé");
        // Le tour est joué et jugé AVANT le chrono : sans la pause, c'est la notification de L qui rougit (l'effet servi).
        let envois = pua_tick(&st);
        assert!(!pua_notifie(&envois, l), "L en attente : pas de dépassement notifié pendant l'attente : {envois:?}");
        assert_eq!(pua_marqueurs(&st, l), (Some(0), Some(0)), "L en attente : aucun dépassement marqué");
        assert!(!pua_notifie(&envois, p), "P en pause, non notifié : {envois:?}");
        assert!(pua_notifie(&envois, o), "contrôle : O, actif et échu sous P3, est notifié : {envois:?}");
        assert_eq!(pua_marqueurs(&st, o), (Some(1), Some(1)), "contrôle : O marqué");
        let p3 = pua_politique_p3(&st);
        for id in [l, o, p] {
            let ts = pua_ts(&st, id);
            assert_eq!(pua_chrono(&st, id), (Some(p3), Some(ts + 3000), Some(ts + 30000)), "#{id} gouverné par P3");
        }
        let pause_l = pua_pause(&st, l).expect("L en attente gouverné : chrono EN PAUSE");
        assert!(pause_l >= avant, "L : pause posée par ce geste ({pause_l} < {avant})");
        assert_eq!(pua_pause(&st, o), None, "O, actif : jamais mis en pause");
        assert_eq!(pua_pause(&st, p), Some(PUA_PAUSE_ANCIENNE), "P déjà en pause : pause d'avant conservée");
        assert_eq!((pua_chrono(&st, x), pua_pause(&st, x)), ((None, None, None), None), "X, autre priorité, intact");
        assert_eq!((pua_chrono(&st, t), pua_pause(&st, t)), ((None, None, None), None), "T, terminal, intact");

    }

    /// CE QU'IL TIENT : pause refusée sur R (déclencheur sur `sla_paused_since` de R seul) ; Q legacy en attente (pause
    /// écrite), P en attente déjà en pause, O actif. Upsert de P3 : 200, corps ENTIER `{recomputed: 3, reason: <refus> #R
    /// (sla_paused_since: écriture refusée par la base)}` ; R gouverné SANS pause, Q en pause.
    /// MUTATIONS QUI LE FONT ROUGIR : `AS4_REFUS_COMPTE` (R compté, 204), `AS4_RIEN_NON_COMPTE` (P non compté : 2),
    /// `AS4_ECRITE_NON_COMPTEE` (Q non compté : 2), `AS4_NONLU_COMME_REFUS` n'y joue pas (voir le témoin suivant).
    #[tokio::test]
    async fn pua_pause_refusee_nommee_et_jamais_recalculee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pua_etat("refus");
        let r = pua_dossier(&st, "R", 3, "status='waiting'");
        let q = pua_dossier(&st, "Q", 3, "status='waiting'");
        let p = pua_dossier(&st, "P", 3, &format!("status='waiting', sla_policy_id={PUA_PENDANT}, sla_paused_since={PUA_PAUSE_ANCIENNE}"));
        let o = pua_dossier(&st, "O", 3, "");
        pua_sql(
            &st,
            &format!("CREATE TRIGGER pua_refus BEFORE UPDATE OF sla_paused_since ON incident WHEN OLD.id={r} BEGIN SELECT RAISE(ABORT,'pua refus'); END;"),
        );
        let addr = router_serve(st.clone()).await;

        let attendu = json!({ "recomputed": 3, "reason": format!("1 {PUA_REFUS}#{r} (sla_paused_since: écriture refusée par la base)") });
        assert_eq!(pua_upsert_p3(addr).await, (200, attendu), "pause refusée : nommée, jamais comptée");
        let p3 = pua_politique_p3(&st);
        assert_eq!((pua_chrono(&st, r).0, pua_pause(&st, r)), (Some(p3), None), "R gouverné SANS pause (dit)");
        assert!(pua_pause(&st, q).is_some(), "Q, voisin en attente, en pause");
        assert_eq!(pua_pause(&st, p), Some(PUA_PAUSE_ANCIENNE), "P : pause d'avant");
        assert_eq!((pua_chrono(&st, o).0, pua_pause(&st, o)), (Some(p3), None), "O gouverné sans pause");
    }

    /// CE QU'IL TIENT : chrono de N illisible (`sla_paused_since` = BLOB sur N seul ; `sla_apply_policy` ne lit pas cette
    /// colonne : l'échéance s'écrit, la pause ne se lit pas) ; Q legacy en attente. Upsert de P3 : 200, corps ENTIER
    /// `{recomputed: 1, reason: <non lue> #N (chrono du dossier non lu)}` — phrase distincte du refus ; N gouverné, Q en
    /// pause.
    /// MUTATIONS QUI LE FONT ROUGIR : `AS4_NONLU_COMME_REFUS` (rangée sous la phrase du refus), `AS4_SANS_PAUSE` (204).
    #[tokio::test]
    async fn pua_pause_non_lue_nommee_sous_sa_phrase() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pua_etat("non-lue");
        let n = pua_dossier(&st, "N", 3, "status='waiting', sla_paused_since=X'00'");
        let q = pua_dossier(&st, "Q", 3, "status='waiting'");
        let addr = router_serve(st.clone()).await;

        let attendu = json!({ "recomputed": 1, "reason": format!("1 {PUA_NON_LUE}#{n} (chrono du dossier non lu)") });
        assert_eq!(pua_upsert_p3(addr).await, (200, attendu), "pause non lue : nommée sous sa phrase, jamais comptée");
        assert_eq!(pua_chrono(&st, n).0, Some(pua_politique_p3(&st)), "N gouverné (échéance écrite)");
        assert!(pua_pause(&st, q).is_some(), "Q, voisin en attente, en pause");
    }

    /// CE QU'IL TIENT : six pauses refusées (déclencheur sur toute écriture de `sla_paused_since`) puis, dans un second
    /// état, six pauses non lues (BLOB) : chaque phrase porte le compte entier (6), nomme les cinq premiers et finit par
    /// `, …`.
    /// MUTATIONS QUI LE FONT ROUGIR : `AS4_BORNE_REFUS` (six nommés au refus), `AS4_BORNE_NONLU` (six nommés à la lecture).
    #[tokio::test]
    async fn pua_six_pauses_non_posees_bornees_a_cinq_noms() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        for (tag, reglage, phrase, cause) in [
            ("borne-refus", "status='waiting'", PUA_REFUS, "sla_paused_since: écriture refusée par la base"),
            ("borne-non-lue", "status='waiting', sla_paused_since=X'00'", PUA_NON_LUE, "chrono du dossier non lu"),
        ] {
            let (st, _t) = pua_etat(tag);
            let ids: Vec<i64> = (0..6).map(|i| pua_dossier(&st, &format!("D{i}"), 3, reglage)).collect();
            assert_eq!(ids.len(), 6, "fixture : six dossiers");
            pua_sql(&st, "CREATE TRIGGER pua_refus_tous BEFORE UPDATE OF sla_paused_since ON incident BEGIN SELECT RAISE(ABORT,'pua refus'); END;");
            let addr = router_serve(st.clone()).await;
            let noms: Vec<String> = ids[..5].iter().map(|id| format!("#{id} ({cause})")).collect();
            let attendu = json!({ "recomputed": 0, "reason": format!("6 {phrase}{}, …", noms.join(", ")) });
            assert_eq!(pua_upsert_p3(addr).await, (200, attendu), "{tag} : compte entier, cinq noms, borne dite");
        }
    }
}
