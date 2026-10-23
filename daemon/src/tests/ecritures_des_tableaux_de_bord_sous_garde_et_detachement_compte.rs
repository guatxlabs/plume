// =====================================================================================
// `P10.33-l` (reste : un détachement de panneau sans effet n'est pas refusé), `P10.20-l` (restes : `dash_editable`
// `Err` -> 403 ; écritures `let _` de `dash_update`, `panel_update`, `view_update` ; `dash_delete` ne purge pas le cache
// des panneaux qu'il efface) et `P10.29-l` (reste : `library_panel_delete` sert le texte du moteur sur écriture refusée).
//
// LE DÉFAUT, MESURÉ SUR 1011ec9f AVANT LE CORRECTIF.
//   · `library_panel_delete` (handlers/dash_ergonomics.rs) détachait les référents par un `UPDATE` dont le nombre de
//     lignes n'était pas jugé : un déclencheur qui ignore le détachement laissait passer la suppression — 204, et les
//     panneaux gardaient un `library_panel_id` vers une définition qui n'existe plus. Une écriture refusée servait
//     `{phrase} ({geste} : {cause du moteur})` au client.
//   · `dash_editable` (handlers/dashboards.rs) rendait `false` sur toute erreur : un propriétaire illisible et une ligne
//     absente devenaient un 403 « non modifiable » sur `dash_update`, `panel_create`, `panel_update` et `panel_delete` ;
//     `dash_get` relisait la ligne par elle et servait `editable:false` si cette seconde lecture manquait.
//   · `dash_update` (8 `let _`), `panel_update` (12) et `view_update` (2) avalaient chaque écriture et rendaient 204 ;
//     `panel_update` purgeait le cache sans condition.
//   · `dash_delete` effaçait les panneaux sans purger leur cache, et n'exigeait pas d'en effacer autant qu'il y en a.
//
// LE CORRECTIF (décision par défaut de la vague AG). Le nombre de référents se lit DANS la transaction de la
// suppression ; le détachement doit en écrire exactement autant, sinon annulation et 503
// `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME` (phrase fixe, cause du moteur au journal seul). `dash_editable` rend une
// issue à quatre bras (`PorteDuTableau`) : droit, refus (403 de la forme d'avant), absence (404), lecture refusée (503
// `CAUSE_DROIT_D_EDITION_NON_LU`, phrase déjà servie par `dash_ergonomics`) ; `dash_get` décide son drapeau sur sa
// propre lecture. Les trois modifications écrivent sous le garde du geste, une ligne exigée par écriture, 503 nommé
// (`CAUSE_TABLEAU_DE_BORD_INCHANGE`, `CAUSE_PANNEAU_INCHANGE`, `CAUSE_VUE_INCHANGEE` et leurs
// `…_TRANSACTION_NON_OUVERTE`), cache de panneau purgé après la validation seulement. `dash_delete` lit les panneaux à
// effacer dans sa transaction, exige d'en effacer autant, et purge leur cache après la validation.
//
// LES PANNES ÉPROUVÉES : déclencheurs `RAISE(ABORT)` et `RAISE(IGNORE)` (avec `WHEN` pour un effet partiel) ;
// autorisateurs SQLite sur l'écrivain partagé (lecture d'une colonne refusée, fonction `count` refusée, `BEGIN` et
// `COMMIT` refusés, lecture d'`id` ignorée à partir de la seconde pour une ligne qui disparaît entre deux lectures) ;
// les lignes de journal lues sur le stderr d'un sous-processus et comparées en entier.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AG3_BIB_ECART_ACCEPTE`, `AG3_BIB_ZERO_SEUL`,
// `AG3_BIB_COMPTE_NON_LU_PASSE`, `AG3_BIB_CAUSE_EXPOSEE`, `AG3_BIB_SANS_JOURNAL` ; `AG3_PORTE_ERR_REFUSEE`,
// `AG3_PORTE_ABSENT_REFUSEE`, `AG3_PORTE_CAUSE_EXPOSEE`, `AG3_PORTE_SANS_JOURNAL`, `AG3_PORTE_JOURNAL_SUFFIXE` ; pour
// C ∈ {DU, PC, PU, PD} `AG3_<C>_REFUSEE_PASSE`, `AG3_<C>_ABSENT_403`, `AG3_<C>_NONLUE_403` ; `AG3_GET_RELU` ; pour
// S ∈ {DU, PU, VU} `AG3_<S>_ECRITURE_AVALEE`, `AG3_<S>_BEGIN_204`, `AG3_<S>_COMMIT_AVALE`, `AG3_<S>_SANS_JOURNAL` ;
// `AG3_DU_JOURNAL_SUFFIXE` ; `AG3_AVALE_<écriture>` (une écriture avalée, une à une) ; `AG3_ZERO_ACCEPTE` ;
// `AG3_RETRAIT_CAUSE_EXPOSEE` ; `AG3_PU_PURGE_SUR_REFUS`, `AG3_PU_PURGE_RETIREE` ; `AG3_DD_PURGE_RETIREE`,
// `AG3_DD_ECART_ACCEPTE`, `AG3_DD_LECTURE_AVALEE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (web/ hors périmètre, lu seulement : les mutations de
// `/api/dashboard/{id}` et `/api/panels/{id}` passent par la forme partagée du refus, qui lit les causes `…_INCHANGE` en
// « rien n'a changé » par `OUVERTURE_DE_L_ECRITURE_NON_PRISE` et `CAUSE_DROIT_D_EDITION_NON_LU` en refus nommé) —
// écrans non joués ; un `COMMIT` que SQLite annule de lui-même (disque plein) ; la purge du cache elle-même
// (`cache_invalider_panneau`, `let _` du coffre `panneau_avoue`) n'est pas jugée ; `record_panel_cost` reste en `let _`
// (mesure de coût) ; `dash_list` ignore un filtre `?view=` non analysable ; la lecture de `dash_get` confond encore
// absence et lecture ratée (`.ok()`, 404) ; `library_panel_update` et `refus_de_la_porte_d_edition`
// (`dash_ergonomics`) servent encore le texte du moteur dans leur 503.
// =====================================================================================
mod ecritures_des_tableaux_de_bord_sous_garde_et_detachement_compte {
    use super::*;
    use crate::handlers::dash_ergonomics::{CAUSE_DROIT_D_EDITION_NON_LU, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME};
    use crate::handlers::dashboards::{
        CAUSE_PANNEAU_INCHANGE, CAUSE_PANNEAU_INCHANGE_TRANSACTION_NON_OUVERTE, CAUSE_TABLEAU_DE_BORD_INCHANGE,
        CAUSE_TABLEAU_DE_BORD_INCHANGE_TRANSACTION_NON_OUVERTE, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME, CAUSE_VUE_INCHANGEE,
        CAUSE_VUE_INCHANGEE_TRANSACTION_NON_OUVERTE,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Le message d'un `RAISE(ABORT, …)` : la cause du moteur d'une écriture refusée, qui ne sort jamais au client.
    const AG3_REFUS: &str = "refus-ag3";
    const AG3_ABSENT: i64 = 876_543;

    fn ag3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ag3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ag3_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ag3_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 503 nommé, EN ENTIER : exactement `error` et `id`, l'erreur égale à la phrase, l'identifiant de corrélation, et
    /// aucune trace de la cause du moteur.
    fn ag3_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : ni succès, ni absence, ni refus de droit : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        for interdit in [AG3_REFUS, "ligne(s)", "référent(s)", "prohibited", "not authorized", "UPDATE", "SELECT", "DELETE"] {
            assert!(!corps.contains(interdit), "{quoi} : `{interdit}` ne sort pas : {corps}");
        }
    }

    fn ag3_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La lecture de `dashboard.owner` refusée : la porte d'édition d'un tableau ne se lit pas.
    fn ag3_refuser_le_proprietaire(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "dashboard", column_name: "owner" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// La fonction `count` refusée : le comptage des référents d'une définition ne se fait pas.
    fn ag3_refuser_le_comptage(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Function { function_name } if function_name.eq_ignore_ascii_case("count") => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// La lecture de `panel.id` refusée : les panneaux d'un tableau à effacer ne se lisent pas.
    fn ag3_refuser_les_identifiants_de_panneaux(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "panel", column_name: "id" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ag3_refuser_la_transaction(st: &AppState, operation_refusee: TransactionOperation) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation } if operation == operation_refusee => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Un tableau de bord d'alice ; rend son identifiant.
    fn ag3_tableau(st: &AppState, nom: &str, visibilite: &str) -> i64 {
        ag3_sql(st, &format!("INSERT INTO dashboard(name,created,owner,visibility) VALUES('{nom}',1000,'alice','{visibilite}');"));
        ag3_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    /// Un panneau partagé dans `did`, avec une ligne de cache ; rend son identifiant.
    fn ag3_panneau(st: &AppState, did: i64, bibliotheque: Option<i64>) -> i64 {
        let lib = bibliotheque.map_or("NULL".to_string(), |l| l.to_string());
        ag3_sql(st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,library_panel_id) VALUES({did},'p','search source=web | table message',1,'table','shared',{lib});"));
        let pid = ag3_compte(st, "SELECT MAX(id) FROM panel");
        ag3_sql(st, &format!("INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES({pid},'r','fp',1,'{{}}');"));
        pid
    }

    fn ag3_cache(st: &AppState, pid: i64) -> i64 {
        ag3_compte(st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}"))
    }

    fn ag3_vue(st: &AppState) -> i64 {
        ag3_sql(st, "INSERT INTO view(name,owner,visibility) VALUES('v-ag3','alice','private');");
        ag3_compte(st, "SELECT MAX(id) FROM view")
    }

    /// Une définition PARTAGÉE d'alice, créée par le handler réel ; rend son identifiant.
    async fn ag3_definition(st: &AppState) -> i64 {
        let (statut, corps, v) = ag3_reponse(
            library_panel_create(
                State(st.clone()),
                Extension(sp_au("alice", "editor")),
                Json(json!({ "name": "def-ag3", "title": "t", "query": "search source=web | table message", "visibility": "shared" })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : la définition est créée : {corps}");
        v["id"].as_i64().expect("fixture : identifiant servi")
    }

    async fn ag3_retirer_la_definition(st: &AppState, qui: &AuthUser, lib: i64) -> (u16, String, Value) {
        ag3_reponse(library_panel_delete(State(st.clone()), Extension(qui.clone()), Path(lib)).await).await
    }

    async fn ag3_modifier_le_tableau(st: &AppState, qui: &AuthUser, did: i64, corps: Value) -> (u16, String, Value) {
        ag3_reponse(dash_update(State(st.clone()), Extension(qui.clone()), Path(did), Json(corps)).await).await
    }

    async fn ag3_creer_un_panneau(st: &AppState, qui: &AuthUser, did: i64) -> (u16, String, Value) {
        let corps = json!({ "dashboard_id": did, "title": "neuf", "query": "search source=web | table message", "is_soql": true });
        ag3_reponse(panel_create(State(st.clone()), Extension(qui.clone()), Json(corps)).await).await
    }

    async fn ag3_modifier_le_panneau(st: &AppState, qui: &AuthUser, pid: i64, corps: Value) -> (u16, String, Value) {
        ag3_reponse(panel_update(State(st.clone()), Extension(qui.clone()), Path(pid), Json(corps)).await).await
    }

    async fn ag3_retirer_le_panneau(st: &AppState, qui: &AuthUser, pid: i64) -> (u16, String, Value) {
        ag3_reponse(panel_delete(State(st.clone()), Extension(qui.clone()), Path(pid)).await).await
    }

    async fn ag3_modifier_la_vue(st: &AppState, qui: &AuthUser, vue: i64, corps: Value) -> (u16, String, Value) {
        ag3_reponse(view_update(State(st.clone()), Extension(qui.clone()), Path(vue), Json(corps)).await).await
    }

    async fn ag3_retirer_le_tableau(st: &AppState, qui: &AuthUser, did: i64) -> (u16, String, Value) {
        ag3_reponse(dash_delete(State(st.clone()), Extension(qui.clone()), Path(did)).await).await
    }

    /// CE QU'IL TIENT (`P10.33-l`, `P10.29-l`) : une définition à DEUX référents. Détachement sans effet (`IGNORE`),
    /// détachement partiel (`IGNORE` sur un seul référent), détachement refusé (`ABORT`), effacement de la définition
    /// refusé (`ABORT`), comptage des référents refusé (fonction `count`) : chaque fois `503`
    /// `CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME` en entier (jamais le texte du moteur), la définition reste, les deux
    /// référents y restent rattachés, aucune transaction pendante. Contrôles : une définition SANS référent se supprime
    /// (zéro compté, zéro détaché : `204`) ; la définition aux deux référents se supprime, les deux panneaux restent,
    /// détachés.
    /// MUTATIONS : `AG3_BIB_ECART_ACCEPTE`, `AG3_BIB_ZERO_SEUL`, `AG3_BIB_COMPTE_NON_LU_PASSE`, `AG3_BIB_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ag3_detachement_sans_effet_partiel_ou_non_compte_refuse_la_suppression_de_la_definition() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-bib");
        let alice = sp_au("alice", "editor");
        let lib = ag3_definition(&st).await;
        let did = ag3_tableau(&st, "d-ag3-bib", "shared");
        let (p1, p2) = (ag3_panneau(&st, did, Some(lib)), ag3_panneau(&st, did, Some(lib)));
        let reste = |st: &AppState, quoi: &str| {
            assert_eq!(ag3_compte(st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 1, "{quoi} : la définition reste");
            assert_eq!(
                ag3_compte(st, &format!("SELECT COUNT(*) FROM panel WHERE id IN ({p1},{p2}) AND library_panel_id={lib}")),
                2,
                "{quoi} : les deux référents restent rattachés"
            );
            assert!(st.db.lock().is_autocommit(), "{quoi} : aucune transaction pendante");
        };
        let cas = [
            ("détachement sans effet", "CREATE TRIGGER ag3_refus BEFORE UPDATE OF library_panel_id ON panel BEGIN SELECT RAISE(IGNORE); END;".to_string()),
            ("détachement partiel", format!("CREATE TRIGGER ag3_refus BEFORE UPDATE OF library_panel_id ON panel WHEN OLD.id={p1} BEGIN SELECT RAISE(IGNORE); END;")),
            ("détachement refusé", format!("CREATE TRIGGER ag3_refus BEFORE UPDATE OF library_panel_id ON panel BEGIN SELECT RAISE(ABORT, '{AG3_REFUS}'); END;")),
            ("effacement de la définition refusé", format!("CREATE TRIGGER ag3_refus BEFORE DELETE ON library_panel BEGIN SELECT RAISE(ABORT, '{AG3_REFUS}'); END;")),
        ];
        assert!(cas.len() >= 4, "plancher : les quatre écritures refusées, sans effet ou partielles");
        for (quoi, declencheur) in &cas {
            ag3_sql(&st, declencheur);
            let r = ag3_retirer_la_definition(&st, &alice, lib).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            ag3_juger_503(quoi, &r, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME);
            reste(&st, quoi);
        }
        ag3_refuser_le_comptage(&st);
        let r = ag3_retirer_la_definition(&st, &alice, lib).await;
        ag3_lever(&st);
        ag3_juger_503("comptage des référents refusé", &r, CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME);
        reste(&st, "comptage des référents refusé");

        let seule = ag3_definition(&st).await;
        let (statut, corps, _) = ag3_retirer_la_definition(&st, &alice, seule).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : zéro référent compté, zéro détaché, la définition se supprime");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={seule}")), 0);
        let (statut, corps, _) = ag3_retirer_la_definition(&st, &alice, lib).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la définition aux deux référents se supprime");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 0);
        assert_eq!(
            ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id IN ({p1},{p2}) AND library_panel_id IS NULL")),
            2,
            "contrôle : les deux référents sont détachés, conservés"
        );
    }

    /// CE QU'IL TIENT (`P10.20-l`, porte d'un tableau de bord sur les quatre gestes qui l'appellent) : propriétaire
    /// illisible — `503` `CAUSE_DROIT_D_EDITION_NON_LU` en entier pour `dash_update`, `panel_create`, `panel_update` et
    /// `panel_delete`, rien n'est écrit, créé ni supprimé ; refus de droit établi (tableau PRIVÉ d'alice, bob editor) —
    /// chaque `403` à sa forme d'avant (vide, texte, JSON, vide) ; tableau absent — `404` (vide pour `dash_update` et
    /// `panel_delete`, texte `dashboard introuvable` pour `panel_create`, JSON pour `panel_update`) ; contrôle : alice,
    /// lecture rendue, réussit les quatre gestes.
    /// MUTATIONS : `AG3_PORTE_ERR_REFUSEE`, `AG3_PORTE_ABSENT_REFUSEE`, `AG3_PORTE_CAUSE_EXPOSEE`, et pour
    /// C ∈ {DU, PC, PU, PD} `AG3_<C>_REFUSEE_PASSE`, `AG3_<C>_ABSENT_403`, `AG3_<C>_NONLUE_403`.
    #[tokio::test]
    async fn ag3_porte_du_tableau_lecture_refusee_503_refus_403_absence_404() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-porte");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let did = ag3_tableau(&st, "d-ag3-porte", "private");
        let pid = ag3_panneau(&st, did, None);
        let etat = |st: &AppState| {
            ag3_texte(
                st,
                &format!(
                    "SELECT (SELECT name FROM dashboard WHERE id={did})||'|'||(SELECT COUNT(*) FROM panel WHERE dashboard_id={did})||'|'||COALESCE((SELECT title FROM panel WHERE id={pid}),'-')"
                ),
            )
        };
        let avant = etat(&st);
        assert_eq!(avant, "d-ag3-porte|1|p", "fixture");

        // (1) propriétaire illisible : 503 nommé, rien d'écrit.
        ag3_refuser_le_proprietaire(&st);
        let gestes = [
            ("dash_update", ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "écrit" })).await),
            ("panel_create", ag3_creer_un_panneau(&st, &alice, did).await),
            ("panel_update", ag3_modifier_le_panneau(&st, &alice, pid, json!({ "title": "écrit" })).await),
            ("panel_delete", ag3_retirer_le_panneau(&st, &alice, pid).await),
        ];
        ag3_lever(&st);
        assert!(gestes.len() >= 4, "plancher : les quatre gestes qui passent la porte");
        for (geste, r) in &gestes {
            ag3_juger_503(&format!("{geste} : propriétaire illisible"), r, CAUSE_DROIT_D_EDITION_NON_LU);
        }
        assert_eq!(etat(&st), avant, "propriétaire illisible : rien n'est écrit, créé ni supprimé");
        assert_eq!(ag3_cache(&st, pid), 1, "propriétaire illisible : le cache du panneau est intact");
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");

        // (2) refus de droit établi : chaque 403 à sa forme d'avant.
        let r = ag3_modifier_le_tableau(&st, &bob, did, json!({ "name": "écrit" })).await;
        assert_eq!((r.0, r.1.as_str()), (403, ""), "dash_update : refus de droit, sans corps");
        let r = ag3_creer_un_panneau(&st, &bob, did).await;
        assert_eq!((r.0, r.1.as_str()), (403, "dashboard non modifiable"), "panel_create : refus de droit, texte d'avant");
        let r = ag3_modifier_le_panneau(&st, &bob, pid, json!({ "title": "écrit" })).await;
        assert_eq!((r.0, r.2.clone()), (403, json!({ "error": "dashboard non modifiable" })), "panel_update : refus de droit, JSON d'avant");
        let r = ag3_retirer_le_panneau(&st, &bob, pid).await;
        assert_eq!((r.0, r.1.as_str()), (403, ""), "panel_delete : refus de droit, sans corps");
        assert_eq!(etat(&st), avant, "refus de droit : rien n'est écrit, créé ni supprimé");

        // (3) tableau absent. `dash_update` : la ligne lue par la lecture d'existence ne l'est plus à la porte (la seconde
        //     lecture d'`id` est ignorée : la colonne vaut NULL, aucune ligne).
        let mut lectures_de_id = 0usize;
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "dashboard", column_name: "id" } => {
                lectures_de_id += 1;
                if lectures_de_id == 1 { Authorization::Allow } else { Authorization::Ignore }
            }
            _ => Authorization::Allow,
        }));
        let r = ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "écrit" })).await;
        ag3_lever(&st);
        assert_eq!((r.0, r.1.as_str()), (404, ""), "dash_update : ligne absente à la porte, 404 sans corps");
        let r = ag3_creer_un_panneau(&st, &alice, AG3_ABSENT).await;
        assert_eq!((r.0, r.1.as_str()), (404, "dashboard introuvable"), "panel_create : tableau absent, 404 texte");
        let orphelin = ag3_panneau(&st, AG3_ABSENT, None);
        let r = ag3_modifier_le_panneau(&st, &alice, orphelin, json!({ "title": "écrit" })).await;
        assert_eq!((r.0, r.2.clone()), (404, json!({ "error": "dashboard introuvable" })), "panel_update : tableau porteur absent, 404 JSON");
        let r = ag3_retirer_le_panneau(&st, &alice, orphelin).await;
        assert_eq!((r.0, r.1.as_str()), (404, ""), "panel_delete : tableau porteur absent, 404 sans corps");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={orphelin} AND title='p'")), 1, "absence : rien n'est écrit ni supprimé");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={AG3_ABSENT}")), 1, "absence : aucun panneau créé");
        assert_eq!(etat(&st), avant, "absence : rien n'est écrit");

        // (4) contrôle : lecture rendue, la propriétaire passe la porte des quatre gestes.
        assert_eq!(ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "écrit" })).await.0, 204, "contrôle : dash_update");
        assert_eq!(ag3_creer_un_panneau(&st, &alice, did).await.0, 200, "contrôle : panel_create");
        assert_eq!(ag3_modifier_le_panneau(&st, &alice, pid, json!({ "title": "écrit" })).await.0, 204, "contrôle : panel_update");
        assert_eq!(ag3_retirer_le_panneau(&st, &alice, pid).await.0, 204, "contrôle : panel_delete");
        assert_eq!(ag3_texte(&st, &format!("SELECT name FROM dashboard WHERE id={did}")), "écrit");
    }

    /// CE QU'IL TIENT (`P10.20-l`, `dash_get`) : le drapeau `editable` se décide sur la lecture qui a décidé l'accès.
    /// Toute lecture de `dashboard.owner` après la première refusée : la fiche d'alice et celle d'un tableau partagé
    /// vue par bob disent `editable: true` (la porte les laisse modifier). Contrôle : sans refus, même verdict ; un
    /// tableau privé d'alice reste refusé à bob (`403`).
    /// MUTATION : `AG3_GET_RELU` (le drapeau relu par une seconde lecture, échec = `false`).
    #[tokio::test]
    async fn ag3_le_drapeau_editable_ne_depend_pas_d_une_seconde_lecture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-get");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let partage = ag3_tableau(&st, "d-ag3-partage", "shared");
        let prive = ag3_tableau(&st, "d-ag3-prive", "private");
        let fiche = |st: AppState, qui: AuthUser, did: i64| async move { ag3_reponse(dash_get(State(st), Extension(qui), Path(did)).await).await };
        let lecteurs = [("alice", &alice, partage), ("bob", &bob, partage), ("alice", &alice, prive)];
        assert!(lecteurs.len() >= 3, "plancher");
        for (nom, qui, did) in lecteurs {
            let mut lectures_du_proprietaire = 0usize;
            st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name: "dashboard", column_name: "owner" } => {
                    lectures_du_proprietaire += 1;
                    if lectures_du_proprietaire == 1 { Authorization::Allow } else { Authorization::Deny }
                }
                _ => Authorization::Allow,
            }));
            let (statut, corps, v) = fiche(st.clone(), qui.clone(), did).await;
            ag3_lever(&st);
            assert_eq!(statut, 200, "{nom} #{did} : fiche servie : {corps}");
            assert_eq!(v["editable"], json!(true), "{nom} #{did} : la porte laisse modifier, le drapeau le dit : {corps}");
            let (statut, _, v) = fiche(st.clone(), qui.clone(), did).await;
            assert_eq!((statut, v["editable"].clone()), (200, json!(true)), "{nom} #{did} : contrôle sans refus");
        }
        let (statut, corps, _) = fiche(st.clone(), bob.clone(), prive).await;
        assert_eq!((statut, corps.as_str()), (403, "dashboard privé"), "contrôle : le tableau privé d'alice reste refusé à bob");
    }

    /// Les trois modifications : (route, table, ligne relue, corps complet, écritures nommées par leur colonne).
    struct Ag3Modif {
        nom: &'static str,
        table: &'static str,
        id: i64,
        ligne: String,
        corps: Value,
        colonnes: &'static [&'static str],
        phrase: &'static str,
    }

    async fn ag3_jouer(st: &AppState, qui: &AuthUser, m: &Ag3Modif) -> (u16, String, Value) {
        match m.nom {
            n if n.starts_with("dash_update") => ag3_modifier_le_tableau(st, qui, m.id, m.corps.clone()).await,
            "panel_update" => ag3_modifier_le_panneau(st, qui, m.id, m.corps.clone()).await,
            _ => ag3_modifier_la_vue(st, qui, m.id, m.corps.clone()).await,
        }
    }

    /// Les trois modifications d'une même base : tableau partagé d'alice (avec un panneau en cache), vue privée d'alice,
    /// définition partagée d'alice à rattacher. Rend (modifications, panneau, vue, définition).
    async fn ag3_trois_modifications(st: &AppState) -> (Vec<Ag3Modif>, i64, i64, i64) {
        let lib = ag3_definition(st).await;
        let did = ag3_tableau(st, "d-ag3-modif", "shared");
        let pid = ag3_panneau(st, did, None);
        let vue = ag3_vue(st);
        let modifs = vec![
            Ag3Modif {
                nom: "dash_update",
                table: "dashboard",
                id: did,
                ligne: format!(
                    "SELECT name||'|'||COALESCE(visibility,'-')||'|'||COALESCE(view_id,'-')||'|'||COALESCE(cols,'-')||'|'||COALESCE(height,'-')||'|'||COALESCE(collapsed,'-')||'|'||COALESCE(position,'-') FROM dashboard WHERE id={did}"
                ),
                corps: json!({ "name": "d-écrit", "visibility": "private", "view_id": vue, "cols": 3, "height": 240, "collapsed": true, "position": 7 }),
                colonnes: &["name", "visibility", "view_id", "cols", "height", "collapsed", "position"],
                phrase: CAUSE_TABLEAU_DE_BORD_INCHANGE,
            },
            Ag3Modif {
                nom: "panel_update",
                table: "panel",
                id: pid,
                ligne: format!(
                    "SELECT viz||'|'||title||'|'||query||'|'||is_soql||'|'||COALESCE(window_s,'-')||'|'||COALESCE(visibility,'-')||'|'||COALESCE(query_private,'-')||'|'||COALESCE(cols,'-')||'|'||COALESCE(height,'-')||'|'||COALESCE(drill,'-')||'|'||COALESCE(position,'-')||'|'||COALESCE(library_panel_id,'-') FROM panel WHERE id={pid}"
                ),
                corps: json!({
                    "viz": "bar", "title": "t-écrit", "query": "search source=dns | table message", "is_soql": true, "window_s": 600,
                    "visibility": "private", "query_private": true, "cols": 2, "height": 300, "drill": "d-écrit", "position": 5, "library_panel_id": lib
                }),
                colonnes: &["viz", "title", "query", "is_soql", "window_s", "visibility", "query_private", "cols", "height", "drill", "position", "library_panel_id"],
                phrase: CAUSE_PANNEAU_INCHANGE,
            },
            Ag3Modif {
                nom: "view_update",
                table: "view",
                id: vue,
                ligne: format!("SELECT name||'|'||COALESCE(visibility,'-') FROM view WHERE id={vue}"),
                corps: json!({ "name": "v-écrite", "visibility": "private" }),
                colonnes: &["name", "visibility"],
                phrase: CAUSE_VUE_INCHANGEE,
            },
        ];
        (modifs, pid, vue, lib)
    }

    /// CE QU'IL TIENT (`P10.20-l`, écritures de `dash_update`, `panel_update`, `view_update`) : CHAQUE écriture, refusée
    /// seule (`ABORT`) ou sans effet (`IGNORE`), annule TOUTES les autres : `503` à la phrase nommée en entier, la ligne
    /// entière comme avant, le cache du panneau intact, aucune transaction pendante. Contrôle : aucun déclencheur, toute
    /// la ligne est écrite (`204` sans corps) et le cache du panneau est purgé.
    /// `dash_update` porte DEUX écritures de `view_id` (`view_id: null` détache la vue, `view_id: n` la rattache) : un
    /// quatrième cas envoie `view_id: null` seul, sur un tableau déjà rattaché, pour que chacune ait son propre témoin.
    /// MUTATIONS : `AG3_DU_ECRITURE_AVALEE`, `AG3_PU_ECRITURE_AVALEE`, `AG3_VU_ECRITURE_AVALEE`, `AG3_AVALE_<écriture>`
    /// (une à une, dont `AG3_AVALE_vue_nulle` pour le seul détachement de vue), `AG3_ZERO_ACCEPTE`,
    /// `AG3_RETRAIT_CAUSE_EXPOSEE`, `AG3_PU_PURGE_SUR_REFUS`, `AG3_PU_PURGE_RETIREE`.
    #[tokio::test]
    async fn ag3_chaque_ecriture_d_une_modification_refusee_annule_tout_jamais_204() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-modif");
        let alice = sp_au("alice", "editor");
        let (mut modifs, pid, vue, lib) = ag3_trois_modifications(&st).await;
        // Le détachement de vue : tableau rattaché d'avance, sans quoi une écriture refusée qui fuirait serait invisible.
        let did = modifs[0].id;
        ag3_sql(&st, &format!("UPDATE dashboard SET view_id={vue} WHERE id={did};"));
        modifs.push(Ag3Modif {
            nom: "dash_update view_id null",
            table: "dashboard",
            id: did,
            ligne: modifs[0].ligne.clone(),
            corps: json!({ "view_id": null }),
            colonnes: &["view_id"],
            phrase: CAUSE_TABLEAU_DE_BORD_INCHANGE,
        });
        assert!(modifs.len() >= 4 && modifs.iter().map(|m| m.colonnes.len()).sum::<usize>() >= 22, "plancher : vingt-deux écritures dans trois gestes");
        let mut manquent: Vec<String> = Vec::new();
        for m in &modifs {
            let avant = ag3_texte(&st, &m.ligne);
            for col in m.colonnes {
                for (voie, action) in [("abort", format!("SELECT RAISE(ABORT, '{AG3_REFUS}');")), ("ignore", "SELECT RAISE(IGNORE);".to_string())] {
                    ag3_sql(&st, &format!("CREATE TRIGGER ag3_refus BEFORE UPDATE OF {col} ON {} BEGIN {action} END;", m.table));
                    let r = ag3_jouer(&st, &alice, m).await;
                    ag3_sql(&st, "DROP TRIGGER ag3_refus;");
                    let apres = ag3_texte(&st, &m.ligne);
                    let cache = ag3_cache(&st, pid);
                    let fermee = st.db.lock().is_autocommit();
                    let cles: Vec<String> = r.2.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
                    let corps_juste = r.0 == 503 && cles == ["error", "id"] && r.2["error"] == json!(m.phrase) && !r.1.contains(AG3_REFUS) && !r.1.contains("ligne(s)");
                    if !corps_juste || apres != avant || cache != 1 || !fermee {
                        manquent.push(format!("{} {col} ({voie}) : {} {}, ligne `{apres}` (attendu `{avant}`), cache {cache}, fermée {fermee}", m.nom, r.0, r.1));
                    }
                }
            }
        }
        assert!(manquent.is_empty(), "écritures dont le refus n'a pas tout annulé ou dont le 503 n'est pas la phrase nommée : {manquent:#?}");
        // CONTRÔLE : aucun déclencheur, chaque geste écrit toute sa ligne.
        let attendues = [
            format!("d-écrit|private|{vue}|3|240|1|7"),
            format!("bar|t-écrit|search source=dns | table message|1|600|private|1|2|300|d-écrit|5|{lib}"),
            "v-écrite|private".to_string(),
            "d-écrit|private|-|3|240|1|7".to_string(),
        ];
        for (m, attendue) in modifs.iter().zip(attendues.iter()) {
            let (statut, corps, _) = ag3_jouer(&st, &alice, m).await;
            assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : {} écrit", m.nom);
            assert_eq!(&ag3_texte(&st, &m.ligne), attendue, "contrôle : {} — la ligne entière est écrite", m.nom);
        }
        assert_eq!(ag3_cache(&st, pid), 0, "contrôle : la modification validée purge le cache du panneau");
    }

    /// CE QU'IL TIENT : un `BEGIN` refusé (`503` `…_TRANSACTION_NON_OUVERTE` en entier) puis un `COMMIT` refusé (`503` à la
    /// phrase de l'écriture non prise, en entier) sur les trois modifications : rien n'est écrit, le cache du panneau est
    /// intact, aucune transaction pendante.
    /// MUTATIONS : `AG3_DU_BEGIN_204`, `AG3_PU_BEGIN_204`, `AG3_VU_BEGIN_204`, `AG3_DU_COMMIT_AVALE`,
    /// `AG3_PU_COMMIT_AVALE`, `AG3_VU_COMMIT_AVALE`.
    #[tokio::test]
    async fn ag3_un_begin_ou_un_commit_refuse_sur_une_modification_rend_503_et_n_ecrit_rien() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-txn");
        let alice = sp_au("alice", "editor");
        let (modifs, pid, _, _) = ag3_trois_modifications(&st).await;
        let causes_begin = [
            CAUSE_TABLEAU_DE_BORD_INCHANGE_TRANSACTION_NON_OUVERTE,
            CAUSE_PANNEAU_INCHANGE_TRANSACTION_NON_OUVERTE,
            CAUSE_VUE_INCHANGEE_TRANSACTION_NON_OUVERTE,
        ];
        assert!(modifs.len() >= 3 && causes_begin.len() == modifs.len(), "plancher : trois gestes");
        for (m, cause_begin) in modifs.iter().zip(causes_begin) {
            let avant = ag3_texte(&st, &m.ligne);
            for (voie, operation, phrase) in [("BEGIN", TransactionOperation::Begin, cause_begin), ("COMMIT", TransactionOperation::Unknown, m.phrase)] {
                ag3_refuser_la_transaction(&st, operation);
                let r = ag3_jouer(&st, &alice, m).await;
                let fermee = st.db.lock().is_autocommit();
                ag3_lever(&st);
                ag3_juger_503(&format!("{} : {voie} refusé", m.nom), &r, phrase);
                assert!(fermee, "{} : {voie} refusé, la transaction est refermée", m.nom);
                assert_eq!(ag3_texte(&st, &m.ligne), avant, "{} : {voie} refusé, rien n'est écrit", m.nom);
                assert_eq!(ag3_cache(&st, pid), 1, "{} : {voie} refusé, le cache du panneau est intact", m.nom);
            }
        }
    }

    /// CE QU'IL TIENT (`P10.20-l`, `dash_delete`) : la suppression validée purge le cache de CHACUN des panneaux
    /// effacés, et seulement d'eux ; un effacement de panneaux partiel (`IGNORE` sur l'un d'eux) annule tout — `503`
    /// `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME` en entier, tableau, panneaux et caches restent ; la lecture des panneaux à
    /// effacer refusée annule aussi, même sur un tableau SANS panneau (rien ne permet alors de dire lesquels purger).
    /// MUTATIONS : `AG3_DD_PURGE_RETIREE`, `AG3_DD_ECART_ACCEPTE`, `AG3_DD_LECTURE_AVALEE`.
    #[tokio::test]
    async fn ag3_suppression_d_un_tableau_purge_le_cache_de_ses_panneaux_apres_validation() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ag3-dd");
        let alice = sp_au("alice", "editor");
        let did = ag3_tableau(&st, "d-ag3-dd", "shared");
        let (p1, p2) = (ag3_panneau(&st, did, None), ag3_panneau(&st, did, None));
        let voisin = ag3_panneau(&st, ag3_tableau(&st, "d-ag3-voisin", "shared"), None);

        ag3_sql(&st, &format!("CREATE TRIGGER ag3_refus BEFORE DELETE ON panel WHEN OLD.id={p1} BEGIN SELECT RAISE(IGNORE); END;"));
        let r = ag3_retirer_le_tableau(&st, &alice, did).await;
        ag3_sql(&st, "DROP TRIGGER ag3_refus;");
        ag3_juger_503("effacement partiel des panneaux", &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME);
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={did}")), 1, "partiel : le tableau reste");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id IN ({p1},{p2}) AND dashboard_id={did}")), 2, "partiel : ses deux panneaux restent");
        assert_eq!((ag3_cache(&st, p1), ag3_cache(&st, p2)), (1, 1), "partiel : leurs caches restent");

        let vide = ag3_tableau(&st, "d-ag3-vide", "shared");
        for (quoi, cible) in [("tableau à deux panneaux", did), ("tableau sans panneau", vide)] {
            ag3_refuser_les_identifiants_de_panneaux(&st);
            let r = ag3_retirer_le_tableau(&st, &alice, cible).await;
            let fermee = st.db.lock().is_autocommit();
            ag3_lever(&st);
            ag3_juger_503(&format!("{quoi} : panneaux non lus"), &r, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME);
            assert!(fermee, "{quoi} : aucune transaction pendante");
            assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={cible}")), 1, "{quoi} : le tableau reste");
        }
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={did}")), 2, "panneaux non lus : rien n'est effacé");

        let (statut, corps, _) = ag3_retirer_le_tableau(&st, &alice, did).await;
        assert_eq!((statut, corps.as_str()), (204, ""), "contrôle : la propriétaire supprime");
        assert_eq!(ag3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={did}")), 0, "contrôle : panneaux effacés");
        assert_eq!((ag3_cache(&st, p1), ag3_cache(&st, p2)), (0, 0), "le cache de chaque panneau effacé est purgé");
        assert_eq!(ag3_cache(&st, voisin), 1, "le cache d'un panneau d'un autre tableau n'est pas touché");
        assert_eq!(ag3_retirer_le_tableau(&st, &alice, vide).await.0, 204, "contrôle : un tableau sans panneau se supprime");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER (ligne `[dashboards] …` seule,
    /// identifiant servi compris) : porte illisible, chaque modification refusée, les trois refus de la suppression d'une
    /// définition (écart, comptage, effacement) et les deux de la suppression d'un tableau (lecture, écart). Jamais un nom
    /// de compte ; les gestes nominaux n'en écrivent aucune.
    /// MUTATIONS : `AG3_PORTE_SANS_JOURNAL`, `AG3_PORTE_JOURNAL_SUFFIXE`, `AG3_DU_SANS_JOURNAL`, `AG3_DU_JOURNAL_SUFFIXE`,
    /// `AG3_PU_SANS_JOURNAL`, `AG3_VU_SANS_JOURNAL`, `AG3_BIB_SANS_JOURNAL`, `AG3_DD_LECTURE_AVALEE`.
    #[tokio::test]
    async fn ag3_lignes_de_journal_des_refus_en_entier() {
        const ENFANT: &str = "AG3_ENFANT_JOURNAL";
        const PHASE: &str = "AG3-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ag3-journal");
            let alice = sp_au("alice", "editor");
            let abort = |table: &str, quand: &str| format!("CREATE TRIGGER ag3_refus BEFORE {quand} ON {table} BEGIN SELECT RAISE(ABORT, '{AG3_REFUS}'); END;");
            let did = ag3_tableau(&st, "d-ag3-j", "shared");
            let pid = ag3_panneau(&st, did, None);
            let vue = ag3_vue(&st);

            eprintln!("{PHASE}porte");
            ag3_refuser_le_proprietaire(&st);
            let moteur = st.db.lock().query_row("SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1", params![did], |_| Ok(())).expect_err("fixture : lecture refusée").to_string();
            let r = ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "x" })).await;
            ag3_lever(&st);
            println!("AG3-STATUT-PORTE:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            println!("AG3-MOTEUR-PORTE:{moteur}");

            eprintln!("{PHASE}du");
            ag3_sql(&st, &abort("dashboard", "UPDATE OF name"));
            let r = ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "x" })).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-DU:{}:{did}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            eprintln!("{PHASE}pu");
            ag3_sql(&st, &abort("panel", "UPDATE OF title"));
            let r = ag3_modifier_le_panneau(&st, &alice, pid, json!({ "title": "x" })).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-PU:{}:{pid}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            eprintln!("{PHASE}vu");
            ag3_sql(&st, &abort("view", "UPDATE OF name"));
            let r = ag3_modifier_la_vue(&st, &alice, vue, json!({ "name": "x" })).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-VU:{}:{vue}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            let lib = ag3_definition(&st).await;
            let porteur = ag3_tableau(&st, "d-ag3-j-bib", "shared");
            ag3_panneau(&st, porteur, Some(lib));
            ag3_panneau(&st, porteur, Some(lib));
            eprintln!("{PHASE}bibecart");
            ag3_sql(&st, "CREATE TRIGGER ag3_refus BEFORE UPDATE OF library_panel_id ON panel BEGIN SELECT RAISE(IGNORE); END;");
            let r = ag3_retirer_la_definition(&st, &alice, lib).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-BIBECART:{}:{lib}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            eprintln!("{PHASE}bibcompte");
            ag3_refuser_le_comptage(&st);
            let moteur = st.db.lock().query_row("SELECT COUNT(*) FROM panel WHERE library_panel_id=?1", params![lib], |_| Ok(())).expect_err("fixture : comptage refusé").to_string();
            let r = ag3_retirer_la_definition(&st, &alice, lib).await;
            ag3_lever(&st);
            println!("AG3-STATUT-BIBCOMPTE:{}:{lib}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            println!("AG3-MOTEUR-BIBCOMPTE:{moteur}");

            eprintln!("{PHASE}bibabort");
            ag3_sql(&st, &abort("library_panel", "DELETE"));
            let r = ag3_retirer_la_definition(&st, &alice, lib).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-BIBABORT:{}:{lib}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            eprintln!("{PHASE}ddlecture");
            let vide = ag3_tableau(&st, "d-ag3-j-vide", "shared");
            ag3_refuser_les_identifiants_de_panneaux(&st);
            let moteur = st.db.lock().query_row("SELECT id FROM panel WHERE dashboard_id=?1", params![vide], |_| Ok(())).expect_err("fixture : lecture refusée").to_string();
            let r = ag3_retirer_le_tableau(&st, &alice, vide).await;
            ag3_lever(&st);
            println!("AG3-STATUT-DDLECTURE:{}:{vide}:{}", r.0, r.2["id"].as_str().unwrap_or(""));
            println!("AG3-MOTEUR-DDLECTURE:{moteur}");

            eprintln!("{PHASE}ddecart");
            let deux = ag3_tableau(&st, "d-ag3-j-deux", "shared");
            let premier = ag3_panneau(&st, deux, None);
            ag3_panneau(&st, deux, None);
            ag3_sql(&st, &format!("CREATE TRIGGER ag3_refus BEFORE DELETE ON panel WHEN OLD.id={premier} BEGIN SELECT RAISE(IGNORE); END;"));
            let r = ag3_retirer_le_tableau(&st, &alice, deux).await;
            ag3_sql(&st, "DROP TRIGGER ag3_refus;");
            println!("AG3-STATUT-DDECART:{}:{deux}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            eprintln!("{PHASE}calme");
            let issues = [
                ag3_modifier_le_tableau(&st, &alice, did, json!({ "name": "y", "cols": 2 })).await.0,
                ag3_modifier_le_panneau(&st, &alice, pid, json!({ "title": "y" })).await.0,
                ag3_modifier_la_vue(&st, &alice, vue, json!({ "name": "y" })).await.0,
                ag3_creer_un_panneau(&st, &alice, did).await.0,
                ag3_retirer_la_definition(&st, &alice, lib).await.0,
                ag3_retirer_le_tableau(&st, &alice, deux).await.0,
                ag3_retirer_le_panneau(&st, &alice, pid).await.0,
            ];
            println!("AG3-STATUT-CALME:{}", issues.iter().map(u16::to_string).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ecritures_des_tableaux_de_bord_sous_garde_et_detachement_compte::ag3_lignes_de_journal_des_refus_en_entier",
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
        let moteur_porte = reste_de("AG3-MOTEUR-PORTE:");
        let moteur_compte = reste_de("AG3-MOTEUR-BIBCOMPTE:");
        let moteur_lecture = reste_de("AG3-MOTEUR-DDLECTURE:");
        assert!(!moteur_porte.is_empty() && !moteur_compte.is_empty() && !moteur_lecture.is_empty(), "contrôle : les causes du moteur sont relevées : {stdout}");
        let bib = "[dashboards] WARN suppression du panneau de bibliothèque #{id} NON prise, transaction annulée ({cid}) : ";
        let dd = "[dashboards] WARN suppression du tableau de bord #{id} NON prise, transaction annulée ({cid}) : ";
        // (phase, marque, ligne attendue où `{id}` est l'objet et `{cid}` l'identifiant servi)
        let attendues = [
            ("porte", "AG3-STATUT-PORTE:", format!("[dashboards] WARN droit d'édition du tableau de bord #{{id}} NON lu, rien n'est écrit ({{cid}}) : {moteur_porte}")),
            ("du", "AG3-STATUT-DU:", format!("[dashboards] WARN modification du tableau de bord #{{id}} NON prise, transaction annulée ({{cid}}) : nom : {AG3_REFUS}")),
            ("pu", "AG3-STATUT-PU:", format!("[dashboards] WARN modification du panneau #{{id}} NON prise, transaction annulée ({{cid}}) : title : {AG3_REFUS}")),
            ("vu", "AG3-STATUT-VU:", format!("[dashboards] WARN modification de la vue #{{id}} NON prise, transaction annulée ({{cid}}) : nom : {AG3_REFUS}")),
            ("bibecart", "AG3-STATUT-BIBECART:", format!("{bib}détachement des panneaux référents : 0 ligne(s) écrite(s) pour 2 référent(s) compté(s)")),
            ("bibcompte", "AG3-STATUT-BIBCOMPTE:", format!("{bib}comptage des panneaux référents : {moteur_compte}")),
            ("bibabort", "AG3-STATUT-BIBABORT:", format!("{bib}suppression de la définition : {AG3_REFUS}")),
            ("ddlecture", "AG3-STATUT-DDLECTURE:", format!("{dd}lecture des panneaux du tableau : {moteur_lecture}")),
            ("ddecart", "AG3-STATUT-DDECART:", format!("{dd}effacement des panneaux du tableau : 1 ligne(s) effacée(s) pour 2 panneau(x) lu(s)")),
        ];
        assert!(attendues.len() >= 9, "plancher : neuf refus journalisés");
        for (nom, m, gabarit) in &attendues {
            let st = marque(m);
            assert_eq!(st[0], "503", "contrôle : phase {nom}, servie 503 : {st:?}");
            assert!(st[2].starts_with("plume-e"), "contrôle : phase {nom}, identifiant servi : {st:?}");
            let attendue = gabarit.replace("{id}", &st[1]).replace("{cid}", &st[2]);
            assert_eq!(phase(nom), [attendue], "phase {nom} : une ligne et une seule, en entier (geste, identifiant servi, cause)");
        }
        assert!(!stderr.lines().any(|l| l.starts_with("[dashboards] ") && l.contains("alice")), "aucun nom de compte au journal : {stderr}");
        assert_eq!(marque("AG3-STATUT-CALME:"), ["204", "204", "204", "200", "204", "204", "204"], "contrôle : sept gestes nominaux");
        assert!(phase("calme").is_empty(), "les gestes nominaux n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
