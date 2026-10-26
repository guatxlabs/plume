// =====================================================================================
// `P10.31-v` (reste vague AS : « le rattrapage multi-niveau de `case_apply_update` joue la pause AVANT la politique »).
//
// CE QUI ÉTAIT FAUX, LU SUR 53488460 : `rattraper_les_echeances_multi_niveau` (cases.rs) rejoue la reprise (ou rien),
// puis `sla_apply_policy`, et s'arrête là. La pause (`sla_on_status_change`) est inerte sur un dossier qui ne portait
// aucune politique : un dossier LEGACY en attente passé par la demande à une priorité gouvernée, puis un champ suivant
// refusé (verdict, recalcul de `sla_due`, pause ou reprise du chemin nominal), sortait gouverné SANS pause, et le tour
// multi-niveau le notifiait en dépassement pendant l'attente ; la cause disait « échéances multi-niveau recalculées ».
// Le chemin nominal (`IssueDuChronoSla::Ecrit if effective_status == "waiting"`) rejoue la pause après la politique.
// REMÈDE : même patron dans le rattrapage, sur le statut EN BASE ; l'ordre pause-puis-politique d'avant est gardé.
// Pause refusée ou non lue : sa phrase fixe (`PAUSE DU CHRONO SLA NON ÉCRITE` / `NON LUE`), jamais « recalculées » ; et
// la relecture exige le chrono en pause d'un dossier gouverné en attente.
// TEST INVERSÉ NOMMÉMENT : `cse_priorite_ecrite_puis_pause_ou_reprise_refusee_suit_la_priorite`
// (chrono_sla_ecritures_comptees.rs) affirmait « recalculées » sur un dossier en attente gouverné sans pause.
// CE QU'ILS TIENNENT : par le routeur réel (compte `editor`, POST /api/cases/{id}), legacy en attente mis en pause, puis
// non notifié par le tour ; voisins : ouvert de même priorité gouverné SANS pause (notifié), en attente déjà en pause
// (pause inchangée), terminal et fusionné non gouvernés, voisin non touché intact ; 503 de la route à corps entier
// (inchangé). Par `case_apply_update` (ce que la route appelle, cause portée au journal) : les entrées du champ
// attesté refusé, du recalcul refusé, du statut `waiting` écrit, et de la pause du chemin nominal refusée (argument
// `None`) ; pause refusée, non lue, et relecture qui trouve le chrono sans pause.
// AJOUTÉS APRÈS VÉRIFICATION INDÉPENDANTE : le bras `NonLu` du chemin nominal (lecture de la pause refusée), la
// relecture impossible et le recalcul refusé qui disent AUSSI la pause, la VALEUR de la pause rejouée (instant de la
// demande, plus seulement « non NULL ») et le cas littéral (statut refusé après une priorité écrite).
// Mutants de la vérification (posés sous cfg!(test) puis retirés) : `V3_S3`, `V4_S4`, `V10_ERR_TAIL`, `V11_REFUS_TAIL`
// nommés sur leur témoin ; `V7_T0` (pause rejouée à 0) rougit chaque témoin qui lit l'instant de la pause (six).
// CE QU'ILS NE TIENNENT PAS : la console.
// Mutants (AT4_*, posés sous cfg!(test) puis retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod rattrapage_multi_niveau_rejoue_la_pause {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const RMP_RECALCULEES: &str = "échéances multi-niveau recalculées sur la priorité écrite";
    const RMP_ECHEANCE: &str = "échéance recalculée sur la priorité écrite";
    const RMP_PAUSE_NON_ECRITE: &str =
        "PAUSE DU CHRONO SLA NON ÉCRITE : le dossier en attente que la politique de la priorité écrite gouverne n'est PAS en pause";
    const RMP_PAUSE_NON_LUE: &str =
        "PAUSE DU CHRONO SLA NON LUE : le dossier en attente que la politique de la priorité écrite gouverne n'a PAS été mis en pause";
    const RMP_REFUS_DU_CHRONO: &str = "sla_paused_since: écriture refusée par la base";
    const RMP_PENDANT: i64 = 999;

    fn rmp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, chemin) = router_test_state(&format!("rmp-{tag}"));
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('rmp_edt',?1,'editor')", params![hash_pw("rmpediteur12345").unwrap()])
            .expect("fixture : compte éditeur");
        rmp_sql(&st, "DELETE FROM incident; DELETE FROM sla_policy;");
        let p1 = {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)",
                [],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        (st, chemin, p1)
    }

    fn rmp_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("rmp_edt:rmpediteur12345"))
    }

    fn rmp_au() -> AuthUser {
        AuthUser { name: "rmp_edt".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    fn rmp_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn rmp_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    /// Dossier semé à la priorité 3 (aucune politique P3 : legacy), ANCIEN, puis `UPDATE incident SET <reglage>`.
    fn rmp_dossier(st: &AppState, titre: &str, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, 3)
        };
        rmp_sql(st, &format!("UPDATE incident SET ts = ts - 100000, {reglage} WHERE id={id}"));
        id
    }

    /// (sla_policy_id, sla_paused_since).
    fn rmp_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, sla_paused_since FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    }

    /// Refuse l'écriture des colonnes `ecritures` de `incident` (l'énoncé échoue à la préparation).
    fn rmp_refuser(st: &AppState, ecritures: &'static [&'static str]) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, column_name } if table_name == "incident" && ecritures.iter().any(|c| *c == column_name) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Refuse l'écriture du verdict ET la PREMIÈRE lecture de `incident.sla_paused_since` ; rend le compteur de refus.
    fn rmp_refuser_la_premiere_lecture_de_la_pause(st: &AppState) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        use std::sync::atomic::Ordering::SeqCst;
        let refus = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compteur = refus.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, column_name } if table_name == "incident" && column_name == "disposition" => Authorization::Deny,
            AuthAction::Read { table_name, column_name, .. }
                if table_name == "incident" && column_name == "sla_paused_since" && compteur.load(SeqCst) == 0 =>
            {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// La pause rejouée vaut l'instant `t` de la demande (dans [avant, après]) : une pause à 0 (ou à tout autre instant)
    /// décalerait `resolve_due` du delta à la reprise.
    fn rmp_pause_a_l_instant_de_la_demande(pause: Option<i64>, avant: i64, apres: i64, quoi: &str) {
        let pause = pause.unwrap_or_else(|| panic!("{quoi} : sla_paused_since attendu, NULL lu"));
        assert!((avant..=apres).contains(&pause), "{quoi} : pause {pause} hors de [{avant}, {apres}] (instant de la demande)");
    }

    fn rmp_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La cause que `case_apply_update` (appelée par la route) porte au journal.
    fn rmp_cause(st: &AppState, id: i64, corps: Value) -> String {
        let au = rmp_au();
        match with_write(st, &au, |c| case_apply_update(c, id, &au.name, &corps)) {
            IssueDuDossierModifie::NonEcrite(cause) => cause,
            autre => panic!("`NonEcrite` attendu, pas {autre:?}"),
        }
    }

    /// `<champ>: <texte du moteur><sep><reste>` : le texte du moteur (refus de l'autorisateur) est non vide et ne contient
    /// pas le séparateur ; rend `<reste>`, que le témoin compare EN ENTIER.
    fn rmp_apres_le_refus<'a>(cause: &'a str, champ: &str, sep: &str) -> &'a str {
        let corps = cause.strip_prefix(&format!("{champ}: ")).unwrap_or_else(|| panic!("la cause commence par le champ {champ} : {cause}"));
        let (moteur, reste) = corps.split_once(sep).unwrap_or_else(|| panic!("séparateur `{sep}` : {cause}"));
        assert!(!moteur.is_empty(), "refus du moteur porté : {cause}");
        reste
    }

    fn rmp_rendu(code: u16, brut: &str) -> (u16, Value) {
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

    async fn rmp_patch(addr: std::net::SocketAddr, id: i64, corps: Value) -> (u16, Value) {
        let (code, brut) = router_probe_envoi(addr, "POST", &format!("/api/cases/{id}"), Some(&rmp_authz()), &[("Content-Type", "application/json")], &corps.to_string()).await;
        rmp_rendu(code, &brut)
    }

    fn rmp_tick(st: &AppState) -> Vec<String> {
        rmp_sql(st, "INSERT OR IGNORE INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('rmp','webhook',1,'https://example.invalid/h',0,'{}')");
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _ti: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    fn rmp_notifie(envois: &[String], id: i64) -> bool {
        envois.iter().any(|d| d.starts_with(&format!("Case #{id} ")))
    }

    /// CE QU'IL TIENT, PAR LA ROUTE : P1 (60/600) active, aucune politique P3. Verdict refusé par l'autorisateur ; même
    /// demande `{priority: 1, disposition}` (503 à corps entier) sur : L legacy EN ATTENTE -> gouverné par P1 ET en pause,
    /// non notifié ; O legacy OUVERT -> gouverné, SANS pause, notifié (ancien) ; A en attente déjà en pause -> pause
    /// INCHANGÉE (aucune seconde pause), non notifié ; T clos et F fusionné -> non gouvernés, sans pause. W, legacy en
    /// attente non touché : intact.
    /// MUTATIONS QUI LE FONT ROUGIR : `AT4_SANS_PAUSE` (L sans pause, notifié), `AT4_AVANT_POLITIQUE` (pause inerte
    /// avant la politique : L sans pause), `AT4_TOUT_STATUT` (O mis en pause).
    #[tokio::test]
    async fn rmp_legacy_en_attente_priorite_ecrite_puis_verdict_refuse_est_en_pause() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t, p1) = rmp_etat("route");
        let pause_a = now() - 1000;
        let l = rmp_dossier(&st, "L", "status='waiting'");
        let o = rmp_dossier(&st, "O", "status='open'");
        let a = rmp_dossier(&st, "A", &format!("status='waiting', sla_paused_since={pause_a}"));
        let t = rmp_dossier(&st, "T", "status='closed'");
        let x = rmp_dossier(&st, "X", "status='open'");
        let f = rmp_dossier(&st, "F", &format!("status='closed', merged_into={x}"));
        let w = rmp_dossier(&st, "W", "status='waiting'");
        assert_eq!(rmp_chrono(&st, l), (None, None), "fixture : L legacy sans pause");
        assert_eq!(rmp_chrono(&st, a), (None, Some(pause_a)), "fixture : A déjà en pause");
        let addr = router_serve(st.clone()).await;
        rmp_refuser(&st, &["disposition"]);
        let corps = json!({ "priority": 1, "disposition": "true_positive" });
        let avant = now();
        let (statut, rendu) = rmp_patch(addr, l, corps.clone()).await;
        let apres = now();
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("L", statut, &rendu, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        let (statut, rendu) = rmp_patch(addr, o, corps.clone()).await;
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("O", statut, &rendu, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        let (statut, rendu) = rmp_patch(addr, a, corps.clone()).await;
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("A", statut, &rendu, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        let (statut, rendu) = rmp_patch(addr, t, corps.clone()).await;
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("T", statut, &rendu, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        let (statut, rendu) = rmp_patch(addr, f, corps.clone()).await;
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("F", statut, &rendu, crate::handlers::cases::CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE);
        rmp_lever(&st);

        let pause_l = rmp_chrono(&st, l);
        assert_eq!(pause_l.0, Some(p1), "L gouverné par P1");
        rmp_pause_a_l_instant_de_la_demande(pause_l.1, avant, apres, "L en attente gouverné : chrono EN PAUSE");
        assert_eq!(rmp_chrono(&st, o), (Some(p1), None), "O ouvert : gouverné, jamais mis en pause");
        assert_eq!(rmp_chrono(&st, a), (Some(p1), Some(pause_a)), "A : pause d'origine inchangée, aucune seconde pause");
        assert_eq!(rmp_chrono(&st, t), (None, None), "T clos : non gouverné");
        assert_eq!(rmp_chrono(&st, f), (None, None), "F fusionné : non gouverné");
        assert_eq!(rmp_chrono(&st, w), (None, None), "W, voisin non touché, intact");
        assert_eq!(rmp_entier(&st, &format!("SELECT priority FROM incident WHERE id={w}")), Some(3), "W reste en P3");
        let envois = rmp_tick(&st);
        assert!(!rmp_notifie(&envois, l), "L en pause : pas de dépassement pendant l'attente : {envois:?}");
        assert!(!rmp_notifie(&envois, a), "A en pause : non notifié : {envois:?}");
        assert!(rmp_notifie(&envois, o), "contrôle : O, ancien, ouvert et gouverné, est notifié : {envois:?}");
    }

    /// CE QU'IL TIENT (entrée du champ attesté refusé, `rattraper_l_echeance`) : L legacy en attente, `{priority: 1,
    /// disposition}` verdict refusé -> cause entière après le refus : échéance puis « recalculées », et L en pause.
    /// MUTATIONS QUI LE FONT ROUGIR : `AT4_SANS_PAUSE`, `AT4_AVANT_POLITIQUE` (L sans pause, et la relecture dit
    /// « NON RECALCULÉES »).
    #[tokio::test]
    async fn rmp_champ_atteste_refuse_rejoue_la_pause() {
        let (st, _t, p1) = rmp_etat("champ");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        rmp_refuser(&st, &["disposition"]);
        let avant = now();
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "disposition": "true_positive" }));
        let apres = now();
        rmp_lever(&st);
        assert_eq!(rmp_apres_le_refus(&cause, "disposition", " ; "), format!("{RMP_ECHEANCE}, {RMP_RECALCULEES}"));
        let chrono = rmp_chrono(&st, l);
        assert_eq!(chrono.0, Some(p1));
        rmp_pause_a_l_instant_de_la_demande(chrono.1, avant, apres, "L en pause");
    }

    /// CE QU'IL TIENT (entrée du recalcul refusé, `sla_due`) : L legacy en attente, `{priority: 1}`, `sla_due` refusé ->
    /// cause « recalculées » et L en pause (statut en base lu au début de la demande).
    /// MUTATION QUI LE FAIT ROUGIR : `AT4_SANS_PAUSE`.
    #[tokio::test]
    async fn rmp_recalcul_refuse_rejoue_la_pause() {
        let (st, _t, p1) = rmp_etat("recalcul");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        rmp_refuser(&st, &["sla_due"]);
        let avant = now();
        let cause = rmp_cause(&st, l, json!({ "priority": 1 }));
        let apres = now();
        rmp_lever(&st);
        assert_eq!(rmp_apres_le_refus(&cause, "sla_due", ", "), RMP_RECALCULEES);
        let chrono = rmp_chrono(&st, l);
        assert_eq!(chrono.0, Some(p1));
        rmp_pause_a_l_instant_de_la_demande(chrono.1, avant, apres, "L en pause");
    }

    /// CE QU'IL TIENT (statut `waiting` ÉCRIT par la demande) : S legacy `in_progress`, `{priority: 1, status: waiting,
    /// disposition}` verdict refusé -> la pause d'avant la politique est inerte, celle d'après est posée.
    /// MUTATIONS QUI LE FONT ROUGIR : `AT4_SANS_PAUSE`, `AT4_AVANT_POLITIQUE`.
    #[tokio::test]
    async fn rmp_statut_attente_ecrit_puis_refus_rejoue_la_pause() {
        let (st, _t, p1) = rmp_etat("statut");
        let s = rmp_dossier(&st, "S", "status='in_progress'");
        rmp_refuser(&st, &["disposition"]);
        let avant = now();
        let cause = rmp_cause(&st, s, json!({ "priority": 1, "status": "waiting", "disposition": "true_positive" }));
        let apres = now();
        rmp_lever(&st);
        assert_eq!(rmp_apres_le_refus(&cause, "disposition", " ; "), format!("{RMP_ECHEANCE}, {RMP_RECALCULEES}"));
        assert_eq!(rmp_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={s} AND status='waiting'")), Some(1));
        let chrono = rmp_chrono(&st, s);
        assert_eq!(chrono.0, Some(p1));
        rmp_pause_a_l_instant_de_la_demande(chrono.1, avant, apres, "S en pause");
    }

    /// CE QU'IL TIENT (pause refusée dans le rattrapage) : L legacy en attente, verdict ET `sla_paused_since` refusés ->
    /// la cause nomme la pause refusée, jamais « recalculées » ; L gouverné sans pause.
    /// MUTATION QUI LE FAIT ROUGIR : `AT4_PAUSE_REFUS_TAIT` (la cause dit « NON RECALCULÉES (…pause) » sans nommer la pause).
    #[tokio::test]
    async fn rmp_pause_refusee_dite_jamais_recalculee() {
        let (st, _t, p1) = rmp_etat("refus");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        rmp_refuser(&st, &["disposition", "sla_paused_since"]);
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "disposition": "true_positive" }));
        rmp_lever(&st);
        assert_eq!(rmp_apres_le_refus(&cause, "disposition", " ; "), format!("{RMP_ECHEANCE} ; {RMP_PAUSE_NON_ECRITE} ({RMP_REFUS_DU_CHRONO})"));
        assert_eq!(rmp_chrono(&st, l), (Some(p1), None), "gouverné sans pause, comme la cause le dit");
    }

    /// CE QU'IL TIENT (entrée de la pause du chemin nominal refusée, argument `None`) : D `in_progress` à politique
    /// PENDANTE (la pause d'avant la politique est tentée), `{priority: 1, status: waiting}`, `sla_paused_since` refusé ->
    /// cause entière : le refus de la pause, puis celui de la pause rejouée, sans « recalculées » (c'était
    /// « …, échéances multi-niveau recalculées sur la priorité écrite »).
    /// MUTATIONS QUI LE FONT ROUGIR : `AT4_SANS_PAUSE`, `AT4_PAUSE_REFUS_TAIT`.
    #[tokio::test]
    async fn rmp_pause_nominale_refusee_rejouee_et_dite() {
        let (st, _t, p1) = rmp_etat("nominale");
        let d = rmp_dossier(&st, "D", &format!("status='in_progress', sla_policy_id={RMP_PENDANT}"));
        rmp_refuser(&st, &["sla_paused_since"]);
        let cause = rmp_cause(&st, d, json!({ "priority": 1, "status": "waiting" }));
        rmp_lever(&st);
        assert_eq!(cause, format!("{RMP_REFUS_DU_CHRONO} ; {RMP_PAUSE_NON_ECRITE} ({RMP_REFUS_DU_CHRONO})"));
        assert_eq!(rmp_chrono(&st, d), (Some(p1), None));
    }

    /// CE QU'IL TIENT (pause non lue) : L legacy en attente, verdict refusé, première lecture de `sla_paused_since` refusée
    /// (celle de la pause rejouée : rien ne la lit avant) -> la cause nomme la pause non lue ; L gouverné sans pause.
    /// MUTATION QUI LE FAIT ROUGIR : `AT4_PAUSE_NONLU_TAIT` (la cause dit « NON RECALCULÉES (…pause) »).
    #[tokio::test]
    async fn rmp_pause_non_lue_dite_jamais_recalculee() {
        let (st, _t, p1) = rmp_etat("nonlu");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        let refus = rmp_refuser_la_premiere_lecture_de_la_pause(&st);
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "disposition": "true_positive" }));
        rmp_lever(&st);
        assert_eq!(refus.load(std::sync::atomic::Ordering::SeqCst), 1, "fixture : une lecture de la pause refusée");
        assert_eq!(rmp_apres_le_refus(&cause, "disposition", " ; "), format!("{RMP_ECHEANCE} ; {RMP_PAUSE_NON_LUE} ({})", crate::handlers::caseops::CHRONO_DU_DOSSIER_NON_LU));
        assert_eq!(rmp_chrono(&st, l), (Some(p1), None));
    }

    /// CE QU'IL TIENT (relecture) : la pause est écrite (une ligne) puis effacée par un déclencheur -> la relecture trouve
    /// un dossier gouverné en attente SANS pause et ne dit pas « recalculées ».
    /// MUTATION QUI LE FAIT ROUGIR : `AT4_RELU_SANS_PAUSE` (« recalculées »).
    #[tokio::test]
    async fn rmp_relecture_sans_pause_dite_non_recalculee() {
        let (st, _t, p1) = rmp_etat("relu");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        rmp_sql(&st, "CREATE TEMP TRIGGER rmp_efface AFTER UPDATE OF sla_paused_since ON incident WHEN NEW.sla_paused_since IS NOT NULL BEGIN UPDATE incident SET sla_paused_since=NULL WHERE id=NEW.id; END;");
        rmp_refuser(&st, &["disposition"]);
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "disposition": "true_positive" }));
        rmp_lever(&st);
        assert_eq!(
            rmp_apres_le_refus(&cause, "disposition", " ; "),
            format!("{RMP_ECHEANCE} ; ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES sur la priorité écrite (ack_due/resolve_due/pause)")
        );
        assert_eq!(rmp_chrono(&st, l), (Some(p1), None));
    }

    /// CE QU'IL TIENT (entrée de la REPRISE/PAUSE non lue du chemin nominal, bras `NonLu`, argument `None`) : S legacy
    /// `in_progress`, `{priority: 1, status: waiting}`, la PREMIÈRE lecture de `sla_paused_since` (celle du chemin
    /// nominal) refusée -> `ChronoSlaNonLu` portant « recalculées », et S gouverné EN PAUSE à l'instant de la demande
    /// (la pause rejouée par le rattrapage relit la colonne, permise cette fois).
    /// MUTATION QUI LE FAIT ROUGIR : `V3_S3` (statut « open » passé au rattrapage du bras `NonLu` : S sans pause).
    #[tokio::test]
    async fn rmp_bras_non_lu_du_chemin_nominal_rejoue_la_pause() {
        use std::sync::atomic::Ordering::SeqCst;
        let (st, _t, p1) = rmp_etat("nonlu-nominal");
        let s = rmp_dossier(&st, "S", "status='in_progress'");
        let refus = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compteur = refus.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name, .. }
                if table_name == "incident" && column_name == "sla_paused_since" && compteur.load(SeqCst) == 0 =>
            {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        let au = rmp_au();
        let avant = now();
        let issue = with_write(&st, &au, |c| case_apply_update(c, s, &au.name, &json!({ "priority": 1, "status": "waiting" })));
        let apres = now();
        rmp_lever(&st);
        assert_eq!(refus.load(SeqCst), 1, "fixture : une lecture de la pause refusée");
        match issue {
            IssueDuDossierModifie::ChronoSlaNonLu(cause) => {
                assert_eq!(cause, format!("{}, {RMP_RECALCULEES}", crate::handlers::caseops::CHRONO_DU_DOSSIER_NON_LU))
            }
            autre => panic!("`ChronoSlaNonLu` attendu, pas {autre:?}"),
        }
        let chrono = rmp_chrono(&st, s);
        assert_eq!(chrono.0, Some(p1));
        rmp_pause_a_l_instant_de_la_demande(chrono.1, avant, apres, "S en attente gouverné : en pause");
    }

    /// CE QU'IL TIENT (relecture IMPOSSIBLE et pause non lue) : L legacy en attente, verdict refusé, toute lecture de
    /// `sla_paused_since` refusée -> la cause dit « NON RELUES après le rattrapage » PUIS la pause non lue ; L gouverné
    /// sans pause.
    /// MUTATION QUI LE FAIT ROUGIR : `V10_ERR_TAIL` (le bras `Err` de la relecture tait la pause).
    #[tokio::test]
    async fn rmp_relecture_impossible_dit_aussi_la_pause() {
        let (st, _t, p1) = rmp_etat("relu-err");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, column_name } if table_name == "incident" && column_name == "disposition" => Authorization::Deny,
            AuthAction::Read { table_name, column_name, .. } if table_name == "incident" && column_name == "sla_paused_since" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "disposition": "true_positive" }));
        rmp_lever(&st);
        let reste = rmp_apres_le_refus(&cause, "disposition", " ; ");
        let reste = reste.strip_prefix(&format!("{RMP_ECHEANCE} ; ÉCHÉANCES MULTI-NIVEAU NON RELUES après le rattrapage (")).unwrap_or_else(|| panic!("relecture impossible dite : {cause}"));
        assert!(
            reste.ends_with(&format!(") ; {RMP_PAUSE_NON_LUE} ({})", crate::handlers::caseops::CHRONO_DU_DOSSIER_NON_LU)),
            "la pause non lue est dite après la relecture impossible : {cause}"
        );
        assert_eq!(rmp_chrono(&st, l), (Some(p1), None), "gouverné sans pause, comme la cause le dit");
    }

    /// CE QU'IL TIENT (recalcul multi-niveau REFUSÉ et pause rejouée refusée) : D `in_progress` à politique PENDANTE,
    /// `{priority: 1, status: waiting, disposition}`, verdict et `sla_paused_since` refusés -> la cause dit « NON
    /// RECALCULÉES » (reprise refusée) PUIS la pause non écrite ; D gouverné sans pause.
    /// MUTATION QUI LE FAIT ROUGIR : `V11_REFUS_TAIL` (le bras du refus non vide tait la pause).
    #[tokio::test]
    async fn rmp_recalcul_refuse_dit_aussi_la_pause() {
        let (st, _t, p1) = rmp_etat("refus-pause");
        let d = rmp_dossier(&st, "D", &format!("status='in_progress', sla_policy_id={RMP_PENDANT}"));
        rmp_refuser(&st, &["disposition", "sla_paused_since"]);
        let cause = rmp_cause(&st, d, json!({ "priority": 1, "status": "waiting", "disposition": "true_positive" }));
        rmp_lever(&st);
        assert!(
            cause.ends_with(&format!(
                " ; ÉCHÉANCES MULTI-NIVEAU NON RECALCULÉES sur la priorité écrite ({RMP_REFUS_DU_CHRONO}) ; {RMP_PAUSE_NON_ECRITE} ({RMP_REFUS_DU_CHRONO})"
            )),
            "le refus de la reprise PUIS la pause non écrite : {cause}"
        );
        assert_eq!(rmp_chrono(&st, d), (Some(p1), None));
    }

    /// CE QU'IL TIENT (cas littéral de l'énoncé : STATUT refusé après une priorité écrite) : L legacy en attente,
    /// `{priority: 1, status: in_progress}`, `status` refusé -> L reste en attente, gouverné par P1 et en pause à
    /// l'instant de la demande ; cause entière après le refus : échéance puis « recalculées ».
    /// MUTATIONS QUI LE FONT ROUGIR : `V4_S4` (statut « open » passé par `rattraper_l_echeance`), `V7_T0` (pause à 0).
    #[tokio::test]
    async fn rmp_statut_refuse_apres_priorite_ecrite_rejoue_la_pause() {
        let (st, _t, p1) = rmp_etat("statut-refuse");
        let l = rmp_dossier(&st, "L", "status='waiting'");
        rmp_refuser(&st, &["status"]);
        let avant = now();
        let cause = rmp_cause(&st, l, json!({ "priority": 1, "status": "in_progress" }));
        let apres = now();
        rmp_lever(&st);
        assert_eq!(rmp_apres_le_refus(&cause, "status", " ; "), format!("{RMP_ECHEANCE}, {RMP_RECALCULEES}"));
        assert_eq!(rmp_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={l} AND status='waiting'")), Some(1), "statut refusé : L reste en attente");
        let chrono = rmp_chrono(&st, l);
        assert_eq!(chrono.0, Some(p1));
        rmp_pause_a_l_instant_de_la_demande(chrono.1, avant, apres, "L en pause");
    }
}
