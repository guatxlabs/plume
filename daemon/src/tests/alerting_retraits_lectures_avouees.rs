// =====================================================================================
// `P10.20-b` (rang quatre) — LES GESTES SUR UNE ROUTE DE NOTIFICATION OU UN SILENCE DISENT « NON LU » AU LIEU D'UNE
// FAUSSE ABSENCE : modification et suppression d'une politique (`policy_update`, `policy_delete`), modification et
// levée d'un silence (`silence_update`, `silence_delete`).
//
// VU sur `b96a8c7b` : `policy_update`, `policy_delete` et `silence_delete` lisaient l'existence par
// `query_row("SELECT 1 …").is_err()`, `silence_update` par `let Ok(..) = query_row(..) else` (forme que la garde
// single-row ne voit pas) : toute erreur du moteur rendait 404 « introuvable ». Fail-closed (rien n'était écrit), mais
// l'administrateur qui lève un silence en urgence lisait « silence introuvable » — donc déjà levé — alors que le silence
// étouffait peut-être toujours les notifications (`load_active_silences`).
//
// ATTENDU, tenu ici : l'absence ÉTABLIE garde le 404 JSON d'avant OCTET POUR OCTET ; la lecture NON FAITE rend un 503
// nommé, rien n'est écrit ni attesté, aucune transaction laissée ouverte, la route et le silence sont intacts — la
// LIGNE ENTIÈRE est relue avant et après (`arla_ligne` : chaque colonne du catalogue sous `quote()`, type compris :
// critères, canaux, activation ; critères, échéance, raison), et le silence étouffe toujours une alerte `host=web-01`
// (`arla_etouffe_web01`, jugé par `matchers_match`, pas par le seul compte des silences actifs) ; lecture rendue, le
// geste a lieu comme avant.
//
// LA LECTURE EST REFUSÉE sans toucher au code servi : un authorizer SQLite refuse UNE SEULE FOIS une lecture
// (`AuthAction::Read`) de la table visée (`notification_policy`, `silence`) — le procédé de `migrate.rs`
// (`helper_class_b_failure_without_abort_is_caught`) — puis laisse tout passer. La table reste donc INSCRIPTIBLE
// pendant le geste : « rien n'est écrit / supprimé » est tenu par le CODE (le bras `Err` rend avant toute écriture),
// pas par la fixture. (La première version renommait la table : une table renommée ne s'écrit pas non plus, et un
// mutant qui écrivait dans le bras `Err` restait vert.) Chaque témoin vérifie que le refus a bien eu lieu, une fois.
// Pour `silence_update`, une seconde fabrication rend la LIGNE indécodable (`expires_at` texte) — la table est
// lisible, la conversion échoue, et la forme d'avant le disait aussi « introuvable ». Sur ce chemin, la ligne entière
// (échéance texte comprise) et l'étouffement de web-01 sont jugés JUSTE APRÈS l'appel, AVANT que la fixture ne remette
// l'échéance : la version précédente remettait l'échéance d'abord, et un bras `Err` qui écrivait `expires_at=0` sur
// une erreur de décodage seulement (levant le silence) restait vert. Les gestionnaires sont appelés directement.
//
// MUTATIONS (vues ROUGES puis retirées) : `N5_PU_404`, `N5_PD_404`, `N5_SU_404`, `N5_SD_404` rétablissent le 404 sur
// la lecture ratée de leur site ; `N5_PU_INV`, `N5_PD_INV`, `N5_SU_INV`, `N5_SD_INV` inversent les deux issues
// (absence -> 503, lecture ratée -> 404). Chacune ne fait rougir que le témoin de son site. `N5_PU_WRITE`,
// `N5_PD_WRITE`, `N5_SU_WRITE`, `N5_SD_WRITE` écrivent dans le bras `Err` (UPDATE ou DELETE de la cible) puis rendent
// le 503 nommé attendu : rouges sur l'état relu (canaux, présence, raison, étouffement). Mutants posés le temps de la
// mesure puis retirés (seconde correction), chacun rouge sur le seul témoin de son site : `N5_PU_ENABLED` et
// `N5_PD_ENABLED` (route désactivée dans le bras `Err`), `N5_PU_MATCHERS` (critères web-01 -> web-99),
// `N5_SU_MATCHERS` et `N5_SD_MATCHERS` (silence redirigé vers web-99), `N5_SU_EXPIRE` (échéance à zéro sur toute
// erreur) et `N5_SU_EXPIRE_DECODE` (échéance à zéro sur une erreur de DÉCODAGE seulement) — tous rouges sur la
// comparaison de la ligne entière.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la cause du moteur écrite au journal (`eprintln!` du bras `Err`) — aucun témoin
// ne lit stderr ; ils tiennent seulement que le corps rendu est la constante exacte, donc sans texte du moteur ; la
// phrase que la console peint de ces 503 (aucun témoin de harnais) ; une
// lecture qui échoue par verrou ou interruption (même `Err`, non fabriqué) ; `run_advanced_rules` (rang trois, hors
// lot) ; le DELETE/UPDATE d'une ligne supprimée entre la lecture et la transaction (inchangé). L'assertion
// « étouffe toujours web-01 » n'a été vue rouge seule sous aucun mutant : la comparaison de la ligne entière, jouée
// avant elle, rougit d'abord ; elle reste comme lecture du prédicat de routage. La ligne entière ne tient que la
// ligne visée : une écriture du bras `Err` sur UNE AUTRE ligne ou une autre table n'est jugée que par le compte
// d'attestations et `is_autocommit`.
// =====================================================================================
mod alerting_retraits_lectures_avouees {
    use super::*;

    async fn arla_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn arla_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn arla_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn arla_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn arla_attestations(st: &AppState, kind: &str) -> i64 {
        arla_entier(st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='{kind}'"))
    }

    async fn arla_politique(st: &AppState) -> i64 {
        let corps = json!({ "matchers": { "host": "web-01" }, "contact_points": [1] });
        let (statut, cree) = arla_corps(policy_create(State(st.clone()), Extension(arla_adm()), Json(corps)).await).await;
        assert_eq!(statut, 200, "fixture : politique créée : {cree}");
        cree["id"].as_i64().expect("identifiant de politique")
    }

    async fn arla_silence(st: &AppState) -> i64 {
        let corps = json!({ "matchers": { "host": "web-01" }, "duration_s": 600, "reason": "arla" });
        let (statut, cree) = arla_corps(silence_create(State(st.clone()), Extension(arla_adm()), Json(corps)).await).await;
        assert_eq!(statut, 200, "fixture : silence posé : {cree}");
        cree["id"].as_i64().expect("identifiant de silence")
    }

    /// Arme un authorizer qui refuse la PREMIÈRE lecture de `table` puis laisse tout passer (la table reste
    /// inscriptible) ; rend le compteur de refus.
    fn arla_refuser_une_lecture(st: &AppState, table: &'static str) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::atomic::Ordering::SeqCst;
        let refus = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compteur = refus.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table && compteur.load(SeqCst) == 0 => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// Retire l'authorizer et vérifie que la lecture a bien été refusée, une fois.
    fn arla_rendre_la_lecture(st: &AppState, refus: &std::sync::atomic::AtomicUsize) {
        use rusqlite::hooks::{AuthContext, Authorization};
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(refus.load(std::sync::atomic::Ordering::SeqCst), 1, "fixture : la lecture de la cible a été refusée, une fois");
    }

    fn arla_etouffe(st: &AppState) -> usize {
        load_active_silences(&st.db.lock(), now()).expect("fixture : silences actifs lisibles").len()
    }

    /// Vrai si un silence actif étouffe une alerte `host=web-01` (l'hôte visé par la fixture) — jugé par
    /// `matchers_match`, le prédicat même du routage, et non par le seul compte des silences actifs.
    fn arla_etouffe_web01(st: &AppState) -> bool {
        let etiquettes: std::collections::HashMap<String, String> = [("host".to_string(), "web-01".to_string())].into_iter().collect();
        load_active_silences(&st.db.lock(), now())
            .expect("fixture : silences actifs lisibles")
            .iter()
            .any(|m| matchers_match(m, &etiquettes))
    }

    /// La ligne ENTIÈRE `id` de `table` : chaque colonne du catalogue (`PRAGMA table_info`) passée par `quote()`,
    /// qui garde le TYPE (un texte reste entre apostrophes, un entier nu) — comparer avant et après tient toutes les
    /// colonnes, pas une seule. Rend `None` si la ligne n'existe plus.
    fn arla_ligne(st: &AppState, table: &str, id: i64) -> Option<String> {
        use rusqlite::OptionalExtension as _;
        let conn = st.db.lock();
        let colonnes: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid"))
            .and_then(|mut q| q.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap_or_else(|e| panic!("fixture : colonnes de `{table}` lisibles ({e})"));
        assert!(colonnes.len() >= 4, "fixture : `{table}` a ses colonnes : {colonnes:?}");
        let expr = colonnes.iter().map(|c| format!("'{c}='||quote(\"{c}\")")).collect::<Vec<_>>().join("||' ; '||");
        conn.query_row(&format!("SELECT {expr} FROM {table} WHERE id=?1"), params![id], |r| r.get::<_, String>(0))
            .optional()
            .unwrap_or_else(|e| panic!("fixture : ligne de `{table}` lisible ({e})"))
    }

    /// `policy_update` : absence ÉTABLIE -> le 404 d'avant ; lecture refusée -> 503 nommé, la route garde ses
    /// canaux, rien d'attesté ; lecture rendue -> la modification a lieu.
    /// Rouge sous `N5_PU_404`, `N5_PU_INV`, `N5_PU_WRITE`, `N5_PU_ENABLED` et `N5_PU_MATCHERS`.
    #[tokio::test]
    async fn arla_modification_de_politique_non_lue_est_un_503_nomme() {
        let (st, _p) = sp_state("arla-pu");
        let pid = arla_politique(&st).await;
        let modifier = |id: i64| {
            let st = st.clone();
            async move {
                arla_corps(
                    policy_update(State(st), Extension(arla_adm()), Path(id), Json(json!({ "matchers": { "host": "web-02" }, "contact_points": [2] })))
                        .await,
                )
                .await
            }
        };
        let (statut, corps) = modifier(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "politique introuvable" })), "absence ÉTABLIE : sortie d'avant");

        let avant = arla_ligne(&st, "notification_policy", pid);
        assert!(avant.as_deref().is_some_and(|l| l.contains("web-01") && l.contains("enabled=1")), "fixture : route active sur web-01 : {avant:?}");
        let refus = arla_refuser_une_lecture(&st, "notification_policy");
        let (statut, corps) = modifier(pid).await;
        arla_rendre_la_lecture(&st, &refus);
        assert_eq!(statut, 503, "lecture non faite : pas « politique introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_POLITIQUE_DE_NOTIFICATION_INCHANGEE_NON_LUE), "le refus NOMME sa cause : {corps}");
        assert_eq!(arla_ligne(&st, "notification_policy", pid), avant, "la route ENTIÈRE est celle d'avant (critères, canaux, activation)");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM notification_policy WHERE id={pid} AND contact_points='1'")), 1, "canaux d'avant");
        assert_eq!(arla_attestations(&st, "config.notification-policy.update"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");

        let (statut, corps) = modifier(pid).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true })), "lecture rendue : la modification a lieu");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM notification_policy WHERE id={pid} AND contact_points='2'")), 1, "canaux neufs");
    }

    /// `policy_delete` : absence ÉTABLIE -> le 404 d'avant ; lecture refusée -> 503 nommé, la route est toujours
    /// là, rien d'attesté ; lecture rendue -> la suppression a lieu.
    /// Rouge sous `N5_PD_404`, `N5_PD_INV`, `N5_PD_WRITE` et `N5_PD_ENABLED`.
    #[tokio::test]
    async fn arla_suppression_de_politique_non_lue_est_un_503_nommee() {
        let (st, _p) = sp_state("arla-pd");
        let pid = arla_politique(&st).await;
        let supprimer = |id: i64| {
            let st = st.clone();
            async move { arla_corps(policy_delete(State(st), Extension(arla_adm()), Path(id)).await).await }
        };
        let (statut, corps) = supprimer(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "politique introuvable" })), "absence ÉTABLIE : sortie d'avant");

        let avant = arla_ligne(&st, "notification_policy", pid);
        assert!(avant.as_deref().is_some_and(|l| l.contains("web-01") && l.contains("enabled=1")), "fixture : route active sur web-01 : {avant:?}");
        let refus = arla_refuser_une_lecture(&st, "notification_policy");
        let (statut, corps) = supprimer(pid).await;
        arla_rendre_la_lecture(&st, &refus);
        assert_eq!(statut, 503, "lecture non faite : pas « politique introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_POLITIQUE_DE_NOTIFICATION_NON_SUPPRIMEE_NON_LUE), "le refus NOMME sa cause : {corps}");
        assert_eq!(arla_ligne(&st, "notification_policy", pid), avant, "la route ENTIÈRE est celle d'avant et route toujours");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM notification_policy WHERE id={pid}")), 1, "la route est toujours là");
        assert_eq!(arla_attestations(&st, "config.notification-policy.delete"), 0, "aucune suppression attestée");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");

        let (statut, corps) = supprimer(pid).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true })), "lecture rendue : la suppression a lieu");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM notification_policy WHERE id={pid}")), 0, "route retirée");
    }

    /// `silence_update` : absence ÉTABLIE -> le 404 d'avant ; lecture refusée ET ligne indécodable -> 503 nommé,
    /// le silence garde sa raison et étouffe toujours, rien d'attesté ; lecture rendue -> la modification a lieu.
    /// Rouge sous `N5_SU_404`, `N5_SU_INV`, `N5_SU_WRITE`, `N5_SU_MATCHERS`, `N5_SU_EXPIRE` et `N5_SU_EXPIRE_DECODE`.
    #[tokio::test]
    async fn arla_modification_de_silence_non_lu_est_un_503_nomme() {
        let (st, _p) = sp_state("arla-su");
        let sid = arla_silence(&st).await;
        let modifier = |id: i64| {
            let st = st.clone();
            async move { arla_corps(silence_update(State(st), Extension(arla_adm()), Path(id), Json(json!({ "reason": "autre" }))).await).await }
        };
        let (statut, corps) = modifier(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "silence introuvable" })), "absence ÉTABLIE : sortie d'avant");

        let avant = arla_ligne(&st, "silence", sid);
        assert!(arla_etouffe_web01(&st), "fixture : le silence étouffe web-01");
        let refus = arla_refuser_une_lecture(&st, "silence");
        let (statut, corps) = modifier(sid).await;
        arla_rendre_la_lecture(&st, &refus);
        assert_eq!(statut, 503, "lecture refusée : pas « silence introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_SILENCE_INCHANGE_NON_LU), "le refus NOMME sa cause : {corps}");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
        assert_eq!(arla_ligne(&st, "silence", sid), avant, "lecture refusée : le silence ENTIER est celui d'avant (critères, échéance, raison)");
        assert!(arla_etouffe_web01(&st), "lecture refusée : le silence étouffe toujours web-01");

        // Ligne indécodable : TOUT se juge AVANT la remise en état de l'échéance — sinon une écriture du bras `Err`
        // sur `expires_at` serait effacée par la fixture elle-même.
        let echeance = arla_entier(&st, &format!("SELECT expires_at FROM silence WHERE id={sid}"));
        arla_ecrire(&st, &format!("UPDATE silence SET expires_at='pas-un-entier' WHERE id={sid};"));
        let indecodable = arla_ligne(&st, "silence", sid);
        assert!(indecodable.as_deref().is_some_and(|l| l.contains("expires_at='pas-un-entier'")), "fixture : échéance texte : {indecodable:?}");
        let (statut, corps) = modifier(sid).await;
        assert_eq!(statut, 503, "ligne indécodable : pas « silence introuvable » : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_SILENCE_INCHANGE_NON_LU), "{corps}");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
        assert_eq!(arla_ligne(&st, "silence", sid), indecodable, "ligne indécodable : rien n'est écrit, l'échéance texte comprise");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM silence WHERE id={sid} AND typeof(expires_at)='text'")), 1, "échéance toujours texte");
        assert!(arla_etouffe_web01(&st), "ligne indécodable : le silence étouffe toujours web-01");
        arla_ecrire(&st, &format!("UPDATE silence SET expires_at={echeance} WHERE id={sid};"));
        assert_eq!(arla_ligne(&st, "silence", sid), avant, "fixture : échéance remise");

        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM silence WHERE id={sid} AND reason='arla'")), 1, "raison d'avant");
        assert_eq!(arla_attestations(&st, "config.silence.update"), 0, "aucune modification attestée");
        assert_eq!(arla_etouffe(&st), 1, "le silence étouffe toujours");
        assert!(arla_etouffe_web01(&st), "le silence étouffe toujours web-01");

        let (statut, corps) = modifier(sid).await;
        assert_eq!(statut, 200, "lecture rendue : la modification a lieu : {corps}");
        assert_eq!(corps["changed"], json!(true), "{corps}");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM silence WHERE id={sid} AND reason='autre'")), 1, "raison neuve");
    }

    /// `silence_delete` : absence ÉTABLIE -> le 404 d'avant ; lecture refusée -> 503 nommé, le silence est
    /// toujours là et étouffe toujours, rien d'attesté ; lecture rendue -> la levée a lieu, plus rien n'est étouffé.
    /// Rouge sous `N5_SD_404`, `N5_SD_INV`, `N5_SD_WRITE` et `N5_SD_MATCHERS`.
    #[tokio::test]
    async fn arla_levee_de_silence_non_lu_est_un_503_nomme() {
        let (st, _p) = sp_state("arla-sd");
        let sid = arla_silence(&st).await;
        let lever = |id: i64| {
            let st = st.clone();
            async move { arla_corps(silence_delete(State(st), Extension(arla_adm()), Path(id)).await).await }
        };
        let (statut, corps) = lever(999_999).await;
        assert_eq!((statut, corps), (404, json!({ "error": "silence introuvable" })), "absence ÉTABLIE : sortie d'avant");

        let avant = arla_ligne(&st, "silence", sid);
        assert!(arla_etouffe_web01(&st), "fixture : le silence étouffe web-01");
        let refus = arla_refuser_une_lecture(&st, "silence");
        let (statut, corps) = lever(sid).await;
        arla_rendre_la_lecture(&st, &refus);
        assert_eq!(statut, 503, "lecture non faite : pas « silence introuvable » (donc déjà levé) : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_SILENCE_NON_LEVE_NON_LU), "le refus NOMME sa cause : {corps}");
        assert_eq!(arla_entier(&st, &format!("SELECT COUNT(*) FROM silence WHERE id={sid}")), 1, "le silence est toujours là");
        assert_eq!(arla_ligne(&st, "silence", sid), avant, "le silence ENTIER est celui d'avant");
        assert_eq!(arla_etouffe(&st), 1, "il étouffe toujours");
        assert!(arla_etouffe_web01(&st), "il étouffe toujours web-01");
        assert_eq!(arla_attestations(&st, "config.silence.delete"), 0, "aucune levée attestée");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");

        let (statut, corps) = lever(sid).await;
        assert_eq!((statut, corps), (200, json!({ "ok": true })), "lecture rendue : la levée a lieu");
        assert_eq!(arla_etouffe(&st), 0, "plus rien n'est étouffé");
        assert!(!arla_etouffe_web01(&st), "web-01 n'est plus étouffé");
        assert_eq!(arla_attestations(&st, "config.silence.delete"), 1, "levée attestée");
    }
}
