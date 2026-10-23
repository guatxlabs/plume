// =====================================================================================
// `P10.20-l` (reste de la vague AE : écritures `let _` de `dash_delete`, `panel_delete`, `view_delete`, 503 sans corps,
// `snapshot_get` en 404, `library_panel_delete` en `is_err`) et `P10.33-l` (reste : lecture d'existence du panneau de
// bibliothèque) — UN RETRAIT REFUSÉ N'EST PAS UN SUCCÈS, UNE LECTURE RATÉE N'EST PAS UNE ABSENCE.
//
// LE DÉFAUT, MESURÉ SUR 536bda8a AVANT LE CORRECTIF (handlers/dashboards.rs). `dash_delete` enchaînait
// `let _ = DELETE FROM panel …` puis `let _ = DELETE FROM dashboard …` puis 204, HORS TRANSACTION : un effacement du
// tableau refusé rendait « supprimé » alors que le tableau restait — et ses panneaux, déjà effacés, étaient perdus.
// `panel_delete` avalait son DELETE, purgeait le cache du panneau resté en place et rendait 204 ; `view_delete` déliait
// les tableaux de la vue puis avalait l'effacement de la vue et rendait 204. `dash_delete` et `view_delete` rendaient un
// 503 SANS CORPS sur un propriétaire illisible. Dans handlers/dash_ergonomics.rs, `snapshot_get` rendait 404 « snapshot
// introuvable » sur une lecture ratée et `library_panel_delete` lisait l'existence par `.is_err()` -> 404.
//
// LE CORRECTIF (décision par défaut de la vague AF). Les écritures des trois retraits vivent sous le garde du geste
// (`ouvrir_le_garde_du_geste`, patron de `library_panel_delete`) : UNE ligne exigée là où l'objet vient d'être lu (le
// tableau, le panneau, la vue ; zéro panneau ou zéro tableau rangé est légitime), toute écriture refusée ou sans effet
// annule les autres, 503 nommé (`CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME`, `CAUSE_PANNEAU_NON_SUPPRIME`,
// `CAUSE_VUE_NON_SUPPRIMEE`, et leurs `…_TRANSACTION_NON_OUVERTE`), le cache du panneau purgé seulement après la
// validation. `dash_delete` et `view_delete` rendent une `Response`. Les deux lectures en trois issues : absente, le 404
// d'avant au corps près ; lecture ratée, 503 nommé (`CAUSE_INSTANTANE_NON_LU`,
// `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU`), rien n'est servi, détaché ni supprimé, aucun 403 décidé. Le texte
// du moteur ne part jamais au client : au journal seul, avec le geste, l'identifiant interne et l'identifiant de
// corrélation (ni nom de compte, ni jeton, ni requête).
//
// LES PANNES ÉPROUVÉES : un déclencheur `RAISE(ABORT)` (écriture refusée) ou `RAISE(IGNORE)` (écriture sans effet) ; le
// `BEGIN` refusé par une transaction étrangère pendante ; le `COMMIT` refusé par un autorisateur ; la lecture refusée par
// un autorisateur (panneau de bibliothèque) ou une colonne stockée en BLOB (instantané).
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : pour S ∈ {DASH, PANEL, VUE}
// `AF4_<S>_ECRITURE_AVALEE` (la forme d'avant), `AF4_<S>_ZERO_ACCEPTE`, `AF4_<S>_CAUSE_EXPOSEE`, `AF4_<S>_BEGIN_CAUSE`,
// `AF4_<S>_COMMIT_CAUSE` ; `AF4_DASH_HORS_TRANSACTION`, `AF4_DASH_PANNEAUX_AVALES`, `AF4_VUE_HORS_TRANSACTION`,
// `AF4_VUE_DETACHEMENT_AVALE`, `AF4_PANEL_PURGE_AVANT`, `AF4_PANEL_PURGE_RETIREE` ; `AF4_RETRAIT_SANS_JOURNAL`,
// `AF4_RETRAIT_JOURNAL_SUFFIXE` ; `AF4_DASH_LU_NU`, `AF4_VUE_LU_NU` (le 503 nu d'avant, jugé aussi par
// `lecture_ratee_des_tableaux_de_bord_jamais_404.rs`) ; pour L ∈ {BIB, SNAP} `AF4_<L>_LECTURE_EN_404`,
// `AF4_<L>_ABSENT_EN_503`, `AF4_<L>_CAUSE_EXPOSEE`, `AF4_<L>_SANS_JOURNAL`, `AF4_<L>_JOURNAL_SUFFIXE` ;
// `AF4_BIB_LECTURE_FAIT_LE_GESTE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (web/ hors périmètre, lu seulement : les retraits d'un
// tableau et d'un panneau passent par `peindreLeRefusDUnGeste`, qui lit `CAUSE_*_NON_SUPPRIME` en « rien n'a changé »
// (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`) et les `…_TRANSACTION_NON_OUVERTE` par `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE` ;
// la suppression d'une vue par `motDuRefusServeurDeVue`, qui colle la phrase du démon ; l'aperçu d'un instantané dit
// « aperçu indisponible » sur tout refus ; aucun écran n'appelle la suppression d'un panneau de bibliothèque) — écrans
// non joués ; un `COMMIT` que SQLite annule de lui-même (disque plein) ; `dash_editable` (`Err(_) => false`, 403 de
// cause fausse) et les `let _` de `dash_update`, `panel_update`, `view_update` restent hors lot ; `dash_delete` n'efface
// pas le cache des panneaux qu'il supprime (la garde `query_fp` reste la seule barrière) ; `snapshot_get` sert `{}` pour
// un `data` illisible en JSON ; le refus d'écriture de `library_panel_delete` sert encore le texte du moteur (`P10.29-l`).
// =====================================================================================
mod ecritures_des_retraits_de_tableaux_de_bord_jugees {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Le message d'un `RAISE(ABORT, …)` : la cause du moteur d'une écriture refusée, qui ne doit jamais sortir.
    const AF4_REFUS: &str = "refus-af4";
    const AF4_ABSENT: i64 = 987_654;
    const AF4_JETON: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const AF4_JETON_ABSENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn af4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn af4_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn af4_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 503 nommé, EN ENTIER : exactement `error` et `id`, l'erreur égale à la phrase, l'identifiant de corrélation, et
    /// aucune trace de la cause du moteur ni du jeton.
    fn af4_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : ni succès, ni absence, ni refus de droit : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        for interdit in [AF4_REFUS, "ligne(s)", "Blob", "prohibited", "authorized", AF4_JETON, "DELETE", "SELECT"] {
            assert!(!corps.contains(interdit), "{quoi} : `{interdit}` ne sort pas : {corps}");
        }
    }

    /// `COMMIT` refusé sur l'écrivain partagé (même forme que `commit_juge_connecteurs_ia_et_gouvernance.rs`).
    fn af4_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Toute lecture de `library_panel` refusée (la ligne existe, elle ne se lit pas).
    fn af4_refuser_la_lecture_des_bibliotheques(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "library_panel", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn af4_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Un tableau de bord PARTAGÉ d'alice ; rend son identifiant.
    fn af4_tableau(st: &AppState, nom: &str) -> i64 {
        af4_sql(st, &format!("INSERT INTO dashboard(name,created,owner,visibility) VALUES('{nom}',1000,'alice','shared');"));
        af4_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    /// Un panneau dans `did`, avec une ligne de cache ; rend son identifiant.
    fn af4_panneau(st: &AppState, did: i64, bibliotheque: Option<i64>) -> i64 {
        let lib = bibliotheque.map_or("NULL".to_string(), |l| l.to_string());
        af4_sql(st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,library_panel_id) VALUES({did},'p','search source=web | table message',1,'table',{lib});"));
        let pid = af4_compte(st, "SELECT MAX(id) FROM panel");
        af4_sql(st, &format!("INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES({pid},'r','fp',1,'{{}}');"));
        pid
    }

    /// Une vue privée d'alice et un tableau de bord rangé dedans ; rend (vue, tableau).
    fn af4_vue(st: &AppState) -> (i64, i64) {
        af4_sql(st, "INSERT INTO view(name,owner,visibility) VALUES('v-af4','alice','private');");
        let vue = af4_compte(st, "SELECT MAX(id) FROM view");
        let did = af4_tableau(st, "d-af4-vue");
        af4_sql(st, &format!("UPDATE dashboard SET view_id={vue} WHERE id={did};"));
        (vue, did)
    }

    /// Une définition PRIVÉE d'alice créée par le handler réel, et un panneau qui la référence ; rend (définition, panneau).
    async fn af4_definition(st: &AppState) -> (i64, i64) {
        let (statut, corps, v) = af4_reponse(
            library_panel_create(
                State(st.clone()),
                Extension(sp_au("alice", "editor")),
                Json(json!({ "name": "def-af4", "title": "t", "query": "search source=web | table message", "visibility": "private" })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : la définition est créée : {corps}");
        let lib = v["id"].as_i64().expect("fixture : identifiant servi");
        let did = af4_tableau(st, "d-af4-bib");
        (lib, af4_panneau(st, did, Some(lib)))
    }

    fn af4_instantane(st: &AppState) -> i64 {
        af4_sql(st, &format!("INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(1,'i-af4','{AF4_JETON}','{{}}',1000,'alice','editor');"));
        af4_compte(st, "SELECT MAX(id) FROM dashboard_snapshot")
    }

    async fn af4_retirer_le_tableau(st: &AppState, qui: &AuthUser, did: i64) -> (u16, String, Value) {
        af4_reponse(dash_delete(State(st.clone()), Extension(qui.clone()), Path(did)).await).await
    }

    async fn af4_retirer_le_panneau(st: &AppState, qui: &AuthUser, pid: i64) -> (u16, String, Value) {
        af4_reponse(panel_delete(State(st.clone()), Extension(qui.clone()), Path(pid)).await).await
    }

    async fn af4_retirer_la_vue(st: &AppState, qui: &AuthUser, vue: i64) -> (u16, String, Value) {
        af4_reponse(view_delete(State(st.clone()), Extension(qui.clone()), Path(vue)).await).await
    }

    async fn af4_retirer_la_definition(st: &AppState, qui: &AuthUser, lib: i64) -> (u16, String, Value) {
        af4_reponse(library_panel_delete(State(st.clone()), Extension(qui.clone()), Path(lib)).await).await
    }

    async fn af4_lire_l_instantane(st: &AppState, qui: &AuthUser, jeton: &str) -> (u16, String, Value) {
        af4_reponse(snapshot_get(State(st.clone()), Extension(qui.clone()), Path(jeton.to_string())).await).await
    }

    /// CE QU'IL TIENT (suppression d'un tableau de bord) : effacement du tableau refusé (`ABORT`) APRÈS celui de ses
    /// panneaux, effacement du tableau sans effet (`IGNORE`), effacement des panneaux refusé — chaque fois `503`
    /// `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME` en entier, le tableau ET ses deux panneaux restent, aucune transaction pendante ;
    /// `BEGIN` refusé : `503` `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_TRANSACTION_NON_OUVERTE`, la transaction étrangère n'est
    /// ni validée ni annulée à sa place ; `COMMIT` refusé : `503` `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME`, tout reste. Contrôle :
    /// la propriétaire supprime (`204` sans corps), tableau et panneaux effacés.
    /// MUTATIONS : `AF4_DASH_ECRITURE_AVALEE`, `AF4_DASH_ZERO_ACCEPTE`, `AF4_DASH_HORS_TRANSACTION`,
    /// `AF4_DASH_PANNEAUX_AVALES`, `AF4_DASH_CAUSE_EXPOSEE`, `AF4_DASH_BEGIN_CAUSE`, `AF4_DASH_COMMIT_CAUSE`.
    #[tokio::test]
    async fn af4_suppression_d_un_tableau_de_bord_ecriture_refusee_tout_reste_jamais_204() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af4-dash");
        let alice = sp_au("alice", "editor");
        let did = af4_tableau(&st, "d-af4-dash");
        let (p1, p2) = (af4_panneau(&st, did, None), af4_panneau(&st, did, None));
        let reste = |st: &AppState, quoi: &str| {
            assert_eq!(af4_compte(st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did}")), 1, "{quoi} : le tableau reste");
            assert_eq!(af4_compte(st, &format!("SELECT COUNT(*) FROM panel WHERE id IN ({p1},{p2}) AND dashboard_id={did}")), 2, "{quoi} : ses deux panneaux restent");
        };
        let cas = [
            ("effacement du tableau refusé", format!("CREATE TRIGGER af4_refus BEFORE DELETE ON dashboard BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;")),
            ("effacement du tableau sans effet", "CREATE TRIGGER af4_refus BEFORE DELETE ON dashboard BEGIN SELECT RAISE(IGNORE); END;".to_string()),
            ("effacement des panneaux refusé", format!("CREATE TRIGGER af4_refus BEFORE DELETE ON panel BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;")),
        ];
        assert!(cas.len() >= 3, "plancher : les trois écritures refusées ou sans effet");
        for (quoi, declencheur) in &cas {
            af4_sql(&st, declencheur);
            let r = af4_retirer_le_tableau(&st, &alice, did).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            af4_juger_503(quoi, &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME);
            reste(&st, quoi);
            assert!(st.db.lock().is_autocommit(), "{quoi} : aucune transaction pendante");
        }

        af4_sql(&st, "BEGIN;");
        let r = af4_retirer_le_tableau(&st, &alice, did).await;
        assert!(!st.db.lock().is_autocommit(), "BEGIN refusé : la transaction étrangère n'est ni validée ni annulée à sa place");
        af4_sql(&st, "ROLLBACK;");
        af4_juger_503("BEGIN refusé", &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_TRANSACTION_NON_OUVERTE);
        reste(&st, "BEGIN refusé");

        af4_refuser_le_commit(&st);
        let r = af4_retirer_le_tableau(&st, &alice, did).await;
        af4_lever_l_autorisateur(&st);
        af4_juger_503("COMMIT refusé", &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME);
        reste(&st, "COMMIT refusé");
        assert!(st.db.lock().is_autocommit(), "COMMIT refusé : aucune transaction pendante");

        let (statut, corps, _) = af4_retirer_le_tableau(&st, &alice, did).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la propriétaire supprime");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did}")), 0, "contrôle : le tableau est effacé");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={did}")), 0, "contrôle : ses panneaux aussi");
    }

    /// CE QU'IL TIENT (suppression d'un panneau) : effacement refusé (`ABORT`) ou sans effet (`IGNORE`) — `503`
    /// `CAUSE_PANNEAU_NON_SUPPRIME` en entier, le panneau ET son cache restent ; `BEGIN` refusé : `503`
    /// `CAUSE_PANNEAU_NON_SUPPRIME_TRANSACTION_NON_OUVERTE`, rien n'est purgé ; `COMMIT` refusé : `503`
    /// `CAUSE_PANNEAU_NON_SUPPRIME`, panneau et cache restent. Contrôle : `204`, panneau effacé, cache purgé.
    /// MUTATIONS : `AF4_PANEL_ECRITURE_AVALEE`, `AF4_PANEL_ZERO_ACCEPTE`, `AF4_PANEL_PURGE_AVANT`, `AF4_PANEL_PURGE_RETIREE`,
    /// `AF4_PANEL_CAUSE_EXPOSEE`, `AF4_PANEL_BEGIN_CAUSE`, `AF4_PANEL_COMMIT_CAUSE`.
    #[tokio::test]
    async fn af4_suppression_d_un_panneau_ecriture_refusee_panneau_et_cache_restent_jamais_204() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af4-panel");
        let alice = sp_au("alice", "editor");
        let did = af4_tableau(&st, "d-af4-panel");
        let pid = af4_panneau(&st, did, None);
        let reste = |st: &AppState, quoi: &str| {
            assert_eq!(af4_compte(st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 1, "{quoi} : le panneau reste");
            assert_eq!(af4_compte(st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "{quoi} : son cache n'est pas purgé");
        };
        let cas = [
            ("effacement refusé", format!("CREATE TRIGGER af4_refus BEFORE DELETE ON panel BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;")),
            ("effacement sans effet", "CREATE TRIGGER af4_refus BEFORE DELETE ON panel BEGIN SELECT RAISE(IGNORE); END;".to_string()),
        ];
        assert!(cas.len() >= 2, "plancher : les deux écritures refusées ou sans effet");
        for (quoi, declencheur) in &cas {
            af4_sql(&st, declencheur);
            let r = af4_retirer_le_panneau(&st, &alice, pid).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            af4_juger_503(quoi, &r, CAUSE_PANNEAU_NON_SUPPRIME);
            reste(&st, quoi);
            assert!(st.db.lock().is_autocommit(), "{quoi} : aucune transaction pendante");
        }

        af4_sql(&st, "BEGIN;");
        let r = af4_retirer_le_panneau(&st, &alice, pid).await;
        assert!(!st.db.lock().is_autocommit(), "BEGIN refusé : la transaction étrangère reste la sienne");
        af4_sql(&st, "ROLLBACK;");
        af4_juger_503("BEGIN refusé", &r, CAUSE_PANNEAU_NON_SUPPRIME_TRANSACTION_NON_OUVERTE);
        reste(&st, "BEGIN refusé");

        af4_refuser_le_commit(&st);
        let r = af4_retirer_le_panneau(&st, &alice, pid).await;
        af4_lever_l_autorisateur(&st);
        af4_juger_503("COMMIT refusé", &r, CAUSE_PANNEAU_NON_SUPPRIME);
        reste(&st, "COMMIT refusé");

        let (statut, corps, _) = af4_retirer_le_panneau(&st, &alice, pid).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la propriétaire supprime");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid}")), 0, "contrôle : le panneau est effacé");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 0, "contrôle : un succès purge le cache");
    }

    /// CE QU'IL TIENT (suppression d'une vue) : effacement de la vue refusé (`ABORT`) APRÈS le détachement, effacement sans
    /// effet (`IGNORE`), détachement refusé — chaque fois `503` `CAUSE_VUE_NON_SUPPRIMEE` en entier, la vue reste ET le
    /// tableau y reste rangé ; `BEGIN` refusé : `503` `CAUSE_VUE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE` ; `COMMIT` refusé :
    /// `503` `CAUSE_VUE_NON_SUPPRIMEE`, tout reste. Contrôle : `204`, vue effacée, tableau conservé et délié.
    /// MUTATIONS : `AF4_VUE_ECRITURE_AVALEE`, `AF4_VUE_ZERO_ACCEPTE`, `AF4_VUE_HORS_TRANSACTION`, `AF4_VUE_DETACHEMENT_AVALE`,
    /// `AF4_VUE_CAUSE_EXPOSEE`, `AF4_VUE_BEGIN_CAUSE`, `AF4_VUE_COMMIT_CAUSE`.
    #[tokio::test]
    async fn af4_suppression_d_une_vue_ecriture_refusee_vue_et_rattachements_restent_jamais_204() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af4-vue");
        let alice = sp_au("alice", "editor");
        let (vue, did) = af4_vue(&st);
        let reste = |st: &AppState, quoi: &str| {
            assert_eq!(af4_compte(st, &format!("SELECT COUNT(*) FROM view WHERE id={vue}")), 1, "{quoi} : la vue reste");
            assert_eq!(af4_compte(st, &format!("SELECT COALESCE(view_id,0) FROM dashboard WHERE id={did}")), vue, "{quoi} : le tableau y reste rangé");
        };
        let cas = [
            ("effacement de la vue refusé", format!("CREATE TRIGGER af4_refus BEFORE DELETE ON view BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;")),
            ("effacement de la vue sans effet", "CREATE TRIGGER af4_refus BEFORE DELETE ON view BEGIN SELECT RAISE(IGNORE); END;".to_string()),
            ("détachement refusé", format!("CREATE TRIGGER af4_refus BEFORE UPDATE OF view_id ON dashboard BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;")),
        ];
        assert!(cas.len() >= 3, "plancher : les trois écritures refusées ou sans effet");
        for (quoi, declencheur) in &cas {
            af4_sql(&st, declencheur);
            let r = af4_retirer_la_vue(&st, &alice, vue).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            af4_juger_503(quoi, &r, CAUSE_VUE_NON_SUPPRIMEE);
            reste(&st, quoi);
            assert!(st.db.lock().is_autocommit(), "{quoi} : aucune transaction pendante");
        }

        af4_sql(&st, "BEGIN;");
        let r = af4_retirer_la_vue(&st, &alice, vue).await;
        assert!(!st.db.lock().is_autocommit(), "BEGIN refusé : la transaction étrangère reste la sienne");
        af4_sql(&st, "ROLLBACK;");
        af4_juger_503("BEGIN refusé", &r, CAUSE_VUE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE);
        reste(&st, "BEGIN refusé");

        af4_refuser_le_commit(&st);
        let r = af4_retirer_la_vue(&st, &alice, vue).await;
        af4_lever_l_autorisateur(&st);
        af4_juger_503("COMMIT refusé", &r, CAUSE_VUE_NON_SUPPRIMEE);
        reste(&st, "COMMIT refusé");

        let (statut, corps, _) = af4_retirer_la_vue(&st, &alice, vue).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la propriétaire supprime");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM view WHERE id={vue}")), 0, "contrôle : la vue est effacée");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did} AND view_id IS NULL")), 1, "contrôle : le tableau est conservé, délié");
    }

    /// CE QU'IL TIENT (suppression d'un panneau de bibliothèque, lecture d'existence) : absente, `404` sans corps ; lecture
    /// refusée, `503` `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU` en entier pour la propriétaire, l'admin ET un
    /// tiers (aucun `403` décidé) — la définition reste, le panneau qui la référence y reste rattaché, aucune transaction
    /// pendante. Contrôle : lecture rendue, le tiers reçoit `403`, la propriétaire supprime (`204`), le référent est détaché.
    /// MUTATIONS : `AF4_BIB_LECTURE_EN_404`, `AF4_BIB_ABSENT_EN_503`, `AF4_BIB_LECTURE_FAIT_LE_GESTE`, `AF4_BIB_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn af4_suppression_d_un_panneau_de_bibliotheque_lecture_refusee_jamais_404_ni_403() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af4-bib");
        let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
        let (statut, corps, _) = af4_retirer_la_definition(&st, &alice, AF4_ABSENT).await;
        assert_eq!((statut, corps.as_str()), (404, ""), "contrôle : l'absence établie reste le 404 d'avant, sans corps");

        let (lib, pid) = af4_definition(&st).await;
        let qui_lisent = [("propriétaire", &alice), ("admin", &adm), ("tiers", &bob)];
        assert!(qui_lisent.len() >= 3, "plancher : les trois identités");
        for (qui, au) in qui_lisent {
            af4_refuser_la_lecture_des_bibliotheques(&st);
            let r = af4_retirer_la_definition(&st, au, lib).await;
            af4_lever_l_autorisateur(&st);
            af4_juger_503(&format!("lecture refusée ({qui})"), &r, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_NON_LU);
            assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 1, "{qui} : la définition reste");
            assert_eq!(af4_compte(&st, &format!("SELECT COALESCE(library_panel_id,0) FROM panel WHERE id={pid}")), lib, "{qui} : le référent reste rattaché");
            assert!(st.db.lock().is_autocommit(), "{qui} : aucune transaction pendante");
        }

        let (statut, corps, _) = af4_retirer_la_definition(&st, &bob, lib).await;
        assert_eq!((statut, corps.as_str()), (403, ""), "contrôle : lecture rendue, la définition privée d'alice est refusée au tiers");
        let (statut, corps, _) = af4_retirer_la_definition(&st, &alice, lib).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la propriétaire supprime");
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 0);
        assert_eq!(af4_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid} AND library_panel_id IS NULL")), 1, "contrôle : le référent est détaché, conservé");
    }

    /// CE QU'IL TIENT (lecture d'un instantané par son jeton) : jeton mal formé et jeton absent, `404` « snapshot
    /// introuvable » exactement ; ligne illisible, `503` `CAUSE_INSTANTANE_NON_LU` en entier (sans le jeton ni la cause du
    /// moteur) pour l'auteur comme pour un lecteur. Contrôle : ligne relisible, l'instantané est servi (`200`).
    /// MUTATIONS : `AF4_SNAP_LECTURE_EN_404`, `AF4_SNAP_ABSENT_EN_503`, `AF4_SNAP_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn af4_lecture_d_un_instantane_illisible_jamais_404() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af4-snap");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "viewer"));
        for jeton in ["mal-forme", AF4_JETON_ABSENT] {
            let (statut, corps, _) = af4_lire_l_instantane(&st, &alice, jeton).await;
            assert_eq!((statut, corps.as_str()), (404, "snapshot introuvable"), "contrôle : `{jeton}` reste le 404 d'avant, corps compris");
        }

        let sid = af4_instantane(&st);
        af4_sql(&st, &format!("UPDATE dashboard_snapshot SET name=X'00' WHERE id={sid};"));
        for (qui, au) in [("auteur", &alice), ("lecteur", &bob)] {
            let r = af4_lire_l_instantane(&st, au, AF4_JETON).await;
            af4_juger_503(&format!("instantané illisible ({qui})"), &r, CAUSE_INSTANTANE_NON_LU);
        }

        af4_sql(&st, &format!("UPDATE dashboard_snapshot SET name='i-af4' WHERE id={sid};"));
        let (statut, corps, v) = af4_lire_l_instantane(&st, &bob, AF4_JETON).await;
        assert_eq!(statut, 200, "contrôle : ligne relisible, l'instantané est servi : {corps}");
        assert_eq!(v["name"], json!("i-af4"), "contrôle : {corps}");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER : chaque retrait refusé écrit
    /// `[dashboards] WARN <geste> NON prise, transaction annulée (<identifiant servi>) : <écriture> : <cause du moteur>` ;
    /// la lecture refusée d'un panneau de bibliothèque et celle d'un instantané écrivent leur ligne avec l'identifiant
    /// servi — jamais le jeton, jamais un nom de compte. Les absences et les retraits nominaux n'en écrivent aucune.
    /// MUTATIONS : `AF4_RETRAIT_SANS_JOURNAL`, `AF4_RETRAIT_JOURNAL_SUFFIXE`, `AF4_BIB_SANS_JOURNAL`,
    /// `AF4_BIB_JOURNAL_SUFFIXE`, `AF4_SNAP_SANS_JOURNAL`, `AF4_SNAP_JOURNAL_SUFFIXE`.
    #[tokio::test]
    async fn af4_lignes_de_journal_des_retraits_refuses_et_des_lectures_ratees() {
        const ENFANT: &str = "AF4_ENFANT_JOURNAL";
        const PHASE: &str = "AF4-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("af4-journal");
            let adm = sp_au("adm", "admin");
            let abort = |table: &str, quand: &str| format!("CREATE TRIGGER af4_refus BEFORE {quand} ON {table} BEGIN SELECT RAISE(ABORT, '{AF4_REFUS}'); END;");
            eprintln!("{PHASE}dash");
            let did = af4_tableau(&st, "d-af4-j1");
            af4_sql(&st, &abort("dashboard", "DELETE"));
            let r = af4_retirer_le_tableau(&st, &adm, did).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-DASH:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}dashzero");
            af4_sql(&st, "CREATE TRIGGER af4_refus BEFORE DELETE ON dashboard BEGIN SELECT RAISE(IGNORE); END;");
            let r = af4_retirer_le_tableau(&st, &adm, did).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-DASHZERO:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}dashpanneaux");
            af4_panneau(&st, did, None);
            af4_sql(&st, &abort("panel", "DELETE"));
            let r = af4_retirer_le_tableau(&st, &adm, did).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-DASHPANNEAUX:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}panel");
            let pid = af4_panneau(&st, did, None);
            af4_sql(&st, &abort("panel", "DELETE"));
            let r = af4_retirer_le_panneau(&st, &adm, pid).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-PANEL:{}:{pid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}vue");
            let (vue, _) = af4_vue(&st);
            af4_sql(&st, &abort("view", "DELETE"));
            let r = af4_retirer_la_vue(&st, &adm, vue).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-VUE:{}:{vue}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}vuedetache");
            af4_sql(&st, &abort("dashboard", "UPDATE OF view_id"));
            let r = af4_retirer_la_vue(&st, &adm, vue).await;
            af4_sql(&st, "DROP TRIGGER af4_refus;");
            println!("AF4-STATUT-VUEDETACHE:{}:{vue}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}bib");
            let (lib, _) = af4_definition(&st).await;
            af4_refuser_la_lecture_des_bibliotheques(&st);
            let moteur = st.db.lock().query_row("SELECT 1 FROM library_panel WHERE id=?1", params![lib], |_| Ok(())).expect_err("fixture : lecture refusée").to_string();
            let r = af4_retirer_la_definition(&st, &adm, lib).await;
            af4_lever_l_autorisateur(&st);
            println!("AF4-STATUT-BIB:{}:{lib}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            println!("AF4-MOTEUR-BIB:{moteur}");
            eprintln!("{PHASE}snap");
            let sid = af4_instantane(&st);
            af4_sql(&st, &format!("UPDATE dashboard_snapshot SET name=X'00' WHERE id={sid};"));
            let r = af4_lire_l_instantane(&st, &adm, AF4_JETON).await;
            println!("AF4-STATUT-SNAP:{}:{sid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("af4-journal-calme");
            let did = af4_tableau(&st, "d-af4-calme");
            let pid = af4_panneau(&st, did, None);
            let (vue, _) = af4_vue(&st);
            let (lib, _) = af4_definition(&st).await;
            af4_instantane(&st);
            let issues = [
                af4_retirer_le_tableau(&st, &adm, AF4_ABSENT).await.0,
                af4_retirer_le_panneau(&st, &adm, AF4_ABSENT).await.0,
                af4_retirer_la_vue(&st, &adm, AF4_ABSENT).await.0,
                af4_retirer_la_definition(&st, &adm, AF4_ABSENT).await.0,
                af4_lire_l_instantane(&st, &adm, AF4_JETON_ABSENT).await.0,
                af4_retirer_le_panneau(&st, &adm, pid).await.0,
                af4_retirer_le_tableau(&st, &adm, did).await.0,
                af4_retirer_la_vue(&st, &adm, vue).await.0,
                af4_retirer_la_definition(&st, &adm, lib).await.0,
                af4_lire_l_instantane(&st, &adm, AF4_JETON).await.0,
            ];
            println!("AF4-STATUT-CALME:{}", issues.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ecritures_des_retraits_de_tableaux_de_bord_jugees::af4_lignes_de_journal_des_retraits_refuses_et_des_lectures_ratees",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste_de = |m: &str| -> String {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").to_string()
        };
        let marque = |m: &str| -> Vec<String> { reste_de(m).split(':').map(str::to_string).collect() };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[dashboards] ")).map(str::to_string).collect()
        };
        let zero = crate::handlers::dashboards::lignes_ecrites_au_lieu_d_une(0);
        let moteur_bib = reste_de("AF4-MOTEUR-BIB:");
        assert!(!moteur_bib.is_empty(), "contrôle : la cause du moteur de la lecture refusée est relevée : {stdout}");
        // (phase, marque, ligne attendue où `{id}` est l'objet et `{cid}` l'identifiant servi)
        let attendues = [
            ("dash", "AF4-STATUT-DASH:", format!("[dashboards] WARN suppression du tableau de bord #{{id}} NON prise, transaction annulée ({{cid}}) : effacement du tableau de bord : {AF4_REFUS}")),
            ("dashzero", "AF4-STATUT-DASHZERO:", format!("[dashboards] WARN suppression du tableau de bord #{{id}} NON prise, transaction annulée ({{cid}}) : effacement du tableau de bord : {zero}")),
            ("dashpanneaux", "AF4-STATUT-DASHPANNEAUX:", format!("[dashboards] WARN suppression du tableau de bord #{{id}} NON prise, transaction annulée ({{cid}}) : effacement des panneaux du tableau : {AF4_REFUS}")),
            ("panel", "AF4-STATUT-PANEL:", format!("[dashboards] WARN suppression du panneau #{{id}} NON prise, transaction annulée ({{cid}}) : effacement du panneau : {AF4_REFUS}")),
            ("vue", "AF4-STATUT-VUE:", format!("[dashboards] WARN suppression de la vue #{{id}} NON prise, transaction annulée ({{cid}}) : effacement de la vue : {AF4_REFUS}")),
            ("vuedetache", "AF4-STATUT-VUEDETACHE:", format!("[dashboards] WARN suppression de la vue #{{id}} NON prise, transaction annulée ({{cid}}) : détachement des tableaux de bord : {AF4_REFUS}")),
            ("bib", "AF4-STATUT-BIB:", format!("[dashboards] WARN panneau de bibliothèque #{{id}} NON lu pour la suppression, rien n'est détaché ni supprimé ({{cid}}) : {moteur_bib}")),
            ("snap", "AF4-STATUT-SNAP:", "[dashboards] WARN instantané NON lu par son jeton, rien n'est servi ({cid}) : Invalid column type Blob at index: 0, name: name".to_string()),
        ];
        assert!(attendues.len() >= 8, "plancher : six retraits refusés et deux lectures ratées");
        for (nom, m, gabarit) in &attendues {
            let st = marque(m);
            assert_eq!(st[0], "503", "contrôle : phase {nom}, servie 503 : {st:?}");
            assert!(st[2].starts_with("plume-e"), "contrôle : phase {nom}, identifiant servi : {st:?}");
            let attendue = gabarit.replace("{id}", &st[1]).replace("{cid}", &st[2]);
            assert_eq!(phase(nom), [attendue], "phase {nom} : une ligne et une seule, en entier (geste, identifiant servi, cause)");
        }
        assert!(!stderr.contains(AF4_JETON), "le jeton d'un instantané n'est jamais écrit au journal");
        assert!(!stderr.lines().any(|l| l.starts_with("[dashboards] ") && l.contains("adm")), "aucun nom de compte au journal : {stderr}");
        assert_eq!(
            marque("AF4-STATUT-CALME:"),
            ["404", "404", "404", "404", "404", "204", "204", "204", "204", "200"],
            "contrôle : cinq absences et cinq gestes nominaux"
        );
        assert!(phase("calme").is_empty(), "les absences et le nominal n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
