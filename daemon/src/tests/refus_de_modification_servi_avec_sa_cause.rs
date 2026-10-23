// =====================================================================================
// `P10.33-l` (restes : le 503 de la MODIFICATION d'un panneau de bibliothèque ou d'une liste de lecture partait SANS
// CORPS ; `ergo_editable` rendait 403 sur une lecture refusée).
//
// LE DÉFAUT, MESURÉ SUR 7c167699 : `library_panel_update` et `playlist_update` rendaient un `StatusCode` ; leurs trois
// refus passaient par `err_json(..).status()` (ou `refus.status()`), si bien que la cause nommée — « la définition, sa
// visibilité … sont ceux d'avant », « une liste partagée le reste » — partait au journal seul et que la console lisait
// un 503 NU. Un compte qui bascule son objet en privé et dont l'écriture est refusée n'apprenait pas que l'objet
// restait PARTAGÉ. Et `ergo_editable` finissait en `Err(_) => false` : une lecture refusée du propriétaire et de la
// visibilité devenait « 403 FORBIDDEN », un refus de droit inventé.
//
// CE QUE CES TÉMOINS TIENNENT : écriture refusée (`RAISE(ABORT)`) ou sans effet (`RAISE(IGNORE)`), `BEGIN` puis
// `COMMIT` refusés -> 503 AVEC corps, la cause nommée en tête, l'ouverture que la console lit (copie des expressions de
// web/core.js) appliquée au corps SERVI, l'objet d'avant intact (le nom écrit plus tôt annulé) ; 204 nominal, corps
// vide ; lecture du droit refusée (autorisateur SQLite qui refuse la colonne `owner`) -> 503 nommé
// `CAUSE_DROIT_D_EDITION_NON_LU` et non 403, sur les QUATRE routes qui passent la porte (deux modifications, deux
// suppressions), rien d'écrit ; l'admin, qui ne lit pas la porte, passe sous le même autorisateur (204) ; le refus de
// droit établi reste 403.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : V5_STATUS (le `.status()` remis : corps perdu), V5_ERGO_FALSE
// (`Err(_) => false` remis), V5_503_EN_204 (204 rendu malgré le refus), V5_SANS_CAUSE (corps servi sans la cause),
// V5_OK0 (`Ok(0)` accepté), V5_EXISTENCE_NUE (le 503 de la lecture d'existence de `playlist_update` rendu sans corps),
// V5_NOROWS_403 (la branche 404 de la porte rendue 403).
//
// CE QU'ILS NE TIENNENT PAS : ce que la console PEINT de ces corps (web/ hors périmètre : seule l'ouverture est
// jugée, par copie de l'expression) ; la branche 404 de `refus_de_la_porte_d_edition` n'est atteinte que par un
// autorisateur à état (dans le démon, la lecture d'existence la précède sous le même verrou d'écrivain) ; la lecture
// `is_soql` de `library_panel_update`, qui rend toujours 404 sur une lecture refusée ; un détachement de panneau sans
// effet.
// =====================================================================================
mod refus_de_modification_servi_avec_sa_cause {
    use super::*;
    use crate::handlers::dash_ergonomics as de;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    fn rmc_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn rmc_lire(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, String>(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn rmc_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn rmc_corps(r: Response) -> (u16, Value, usize) {
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let n = b.len();
        (code, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })), n)
    }

    /// Copies des ouvertures de web/core.js (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`,
    /// `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`), le lookahead négatif traduit par une alternative fin/non-lettre.
    fn rmc_ouverture_ecriture() -> regex::Regex {
        regex::Regex::new(r"^[\p{Lu}', ]+ : la base n'a pas pris (?:l'écriture|l'effacement) [^()—]{1,80}, et la transaction est annulée(?:$|[^\p{L}\p{N}])").unwrap()
    }

    fn rmc_ouverture_transaction() -> regex::Regex {
        regex::Regex::new(r"^[\p{Lu}', ]+ : la base n'a pas pris la transaction [^()—]{1,60}\(BEGIN(?:$|[^\p{L}\p{N}])").unwrap()
    }

    #[derive(Clone, Copy)]
    enum Objet {
        Panneau,
        Liste,
    }

    impl Objet {
        fn table(self) -> &'static str {
            match self {
                Objet::Panneau => "library_panel",
                Objet::Liste => "playlist",
            }
        }
        fn cause_ecriture(self) -> &'static str {
            match self {
                Objet::Panneau => de::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE,
                Objet::Liste => de::CAUSE_LISTE_DE_LECTURE_INCHANGEE,
            }
        }
        fn cause_begin(self) -> &'static str {
            match self {
                Objet::Panneau => de::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE_TRANSACTION_NON_OUVERTE,
                Objet::Liste => de::CAUSE_LISTE_DE_LECTURE_INCHANGEE_TRANSACTION_NON_OUVERTE,
            }
        }
        fn ligne(self, id: i64) -> String {
            format!("SELECT name||'|'||visibility FROM {} WHERE id={id}", self.table())
        }
    }

    /// Un objet PARTAGÉ d'alice, créé par le handler réel, nommé « avant ».
    async fn rmc_objet_d_alice(st: &AppState, objet: Objet) -> i64 {
        let alice = sp_au("alice", "editor");
        let r = match objet {
            Objet::Panneau => {
                library_panel_create(State(st.clone()), Extension(alice), Json(json!({ "name": "avant", "query": "search source=web | table message" }))).await
            }
            Objet::Liste => playlist_create(State(st.clone()), Extension(alice), Json(json!({ "name": "avant", "items": [1] }))).await,
        };
        let (code, v, _) = rmc_corps(r).await;
        assert_eq!(code, 200, "fixture : l'objet est créé : {v}");
        let id = v["id"].as_i64().expect("fixture : identifiant servi");
        assert_eq!(rmc_lire(st, &objet.ligne(id)), "avant|shared", "fixture : partagé");
        id
    }

    async fn rmc_modifier(st: &AppState, objet: Objet, qui: &AuthUser, id: i64, corps: Value) -> (u16, Value, usize) {
        let r = match objet {
            Objet::Panneau => library_panel_update(State(st.clone()), Extension(qui.clone()), Path(id), Json(corps)).await,
            Objet::Liste => playlist_update(State(st.clone()), Extension(qui.clone()), Path(id), Json(corps)).await,
        };
        rmc_corps(r).await
    }

    async fn rmc_supprimer(st: &AppState, objet: Objet, qui: &AuthUser, id: i64) -> (u16, Value, usize) {
        let r = match objet {
            Objet::Panneau => library_panel_delete(State(st.clone()), Extension(qui.clone()), Path(id)).await,
            Objet::Liste => playlist_delete(State(st.clone()), Extension(qui.clone()), Path(id)).await,
        };
        rmc_corps(r).await
    }

    fn rmc_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn rmc_refuser_la_transaction(st: &AppState, operation_refusee: TransactionOperation) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation } if operation == operation_refusee => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Refuse la lecture de la colonne `owner` de `table` — celle que la porte d'édition lit, et qu'aucune autre
    /// instruction des quatre routes ne lit : la lecture d'existence passe, la porte échoue.
    fn rmc_refuser_la_lecture_du_droit(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == "owner" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Une bascule en privé refusée (ABORT) ou sans effet (IGNORE) : 503 AVEC la cause nommée en corps, à l'ouverture
    /// que la console lit, le nom écrit plus tôt annulé, l'objet toujours partagé. MUTATIONS QUI LE FONT ROUGIR :
    /// V5_STATUS (corps vide), V5_503_EN_204 (204), V5_SANS_CAUSE (cause absente du corps), V5_OK0 (voie IGNORE : 204).
    #[tokio::test]
    async fn rmc_une_bascule_en_prive_refusee_sert_sa_cause_en_corps() {
        let ouverture = rmc_ouverture_ecriture();
        for objet in [Objet::Panneau, Objet::Liste] {
            let (st, _tmp) = sp_state(&format!("rmc-ecriture-{}", objet.table()));
            let alice = sp_au("alice", "editor");
            let id = rmc_objet_d_alice(&st, objet).await;
            for (voie, action) in [("abort", "SELECT RAISE(ABORT,'refus de témoin');"), ("ignore", "SELECT RAISE(IGNORE);")] {
                rmc_ecrire(&st, &format!("CREATE TRIGGER rmc_refus BEFORE UPDATE OF visibility ON {} BEGIN {action} END;", objet.table()));
                let (code, v, _) = rmc_modifier(&st, objet, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
                rmc_ecrire(&st, "DROP TRIGGER rmc_refus;");
                let t = objet.table();
                assert_eq!(rmc_lire(&st, &objet.ligne(id)), "avant|shared", "({t}, {voie}) l'objet reste PARTAGÉ, son nom d'avant");
                assert_eq!(code, 503, "({t}, {voie}) une bascule refusée n'est pas un succès : {v}");
                let servie = v["error"].as_str().unwrap_or("");
                // `P10.29-l` (vague AH) — ASSERTION INVERSÉE : le corps portait aussi l'écriture refusée et le texte du moteur
                // (`({geste} : visibility : …)`) ; il ne porte plus que la phrase fixe, la cause va au journal seul.
                assert_eq!(servie, objet.cause_ecriture(), "({t}, {voie}) le corps porte la cause nommée, seule : {v}");
                assert!(!servie.contains("visibility"), "({t}, {voie}) l'écriture refusée ne sort plus au client : {v}");
                assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "({t}, {voie}) avec l'identifiant de corrélation du journal : {v}");
                assert!(ouverture.is_match(servie), "({t}, {voie}) à l'ouverture « écriture non prise » que la console lit : {servie}");
            }
            // CONTRÔLE POSITIF : 204, corps vide, objet écrit.
            let (code, v, n) = rmc_modifier(&st, objet, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
            assert_eq!((code, n), (204, 0), "({}) nominal : {v}", objet.table());
            assert_eq!(rmc_lire(&st, &objet.ligne(id)), "apres|private");
        }
    }

    /// `BEGIN` puis `COMMIT` refusés : 503 avec la cause de transaction (BEGIN, à l'ouverture « transaction non prise »)
    /// ou d'écriture (COMMIT) en corps, transaction refermée, rien d'écrit. MUTATION QUI LE FAIT ROUGIR : V5_STATUS.
    #[tokio::test]
    async fn rmc_un_begin_ou_un_commit_refuse_sert_sa_cause_en_corps() {
        let (ecriture, transaction) = (rmc_ouverture_ecriture(), rmc_ouverture_transaction());
        for objet in [Objet::Panneau, Objet::Liste] {
            let (st, _tmp) = sp_state(&format!("rmc-txn-{}", objet.table()));
            let alice = sp_au("alice", "editor");
            let id = rmc_objet_d_alice(&st, objet).await;
            for (voie, op) in [("BEGIN", TransactionOperation::Begin), ("COMMIT", TransactionOperation::Unknown)] {
                rmc_refuser_la_transaction(&st, op);
                let (code, v, _) = rmc_modifier(&st, objet, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
                let fermee = st.db.lock().is_autocommit();
                rmc_lever(&st);
                let t = objet.table();
                assert!(fermee, "({t}, {voie}) transaction refermée");
                assert_eq!(rmc_lire(&st, &objet.ligne(id)), "avant|shared", "({t}, {voie}) rien d'écrit");
                assert_eq!(code, 503, "({t}, {voie}) : {v}");
                let servie = v["error"].as_str().unwrap_or("");
                let (attendue, forme) = if voie == "BEGIN" { (objet.cause_begin(), &transaction) } else { (objet.cause_ecriture(), &ecriture) };
                assert_eq!(servie, attendue, "({t}, {voie}) le corps porte la cause nommée : {v}");
                assert!(forme.is_match(servie), "({t}, {voie}) à l'ouverture que la console lit : {servie}");
            }
        }
    }

    /// La lecture du droit refusée n'est pas un refus de droit : 503 nommé, jamais 403, sur les quatre routes, rien
    /// d'écrit ni d'effacé ; l'admin ne lit pas la porte et passe ; le refus de droit ÉTABLI reste 403. MUTATION QUI LE
    /// FAIT ROUGIR : V5_ERGO_FALSE (403).
    #[tokio::test]
    async fn rmc_une_lecture_du_droit_refusee_rend_503_nomme_et_non_403() {
        for objet in [Objet::Panneau, Objet::Liste] {
            let t = objet.table();
            let (st, _tmp) = sp_state(&format!("rmc-droit-{t}"));
            let (alice, bob, adm) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
            let id = rmc_objet_d_alice(&st, objet).await;

            rmc_refuser_la_lecture_du_droit(&st, t);
            let (code_maj, v_maj, _) = rmc_modifier(&st, objet, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
            let (code_del, v_del, _) = rmc_supprimer(&st, objet, &alice, id).await;
            rmc_lever(&st);
            assert_eq!(rmc_lire(&st, &objet.ligne(id)), "avant|shared", "({t}) rien d'écrit ni d'effacé");
            for (geste, code, v) in [("modification", code_maj, &v_maj), ("suppression", code_del, &v_del)] {
                assert_eq!(code, 503, "({t}, {geste}) une lecture refusée du droit n'est pas un refus de droit : {v}");
                assert!(
                    v["error"].as_str().unwrap_or("").starts_with(de::CAUSE_DROIT_D_EDITION_NON_LU),
                    "({t}, {geste}) cause nommée : {v}"
                );
            }
            // La cause de lecture ne dit pas « rien n'a changé » par une transaction.
            assert!(!rmc_ouverture_ecriture().is_match(de::CAUSE_DROIT_D_EDITION_NON_LU) && !rmc_ouverture_transaction().is_match(de::CAUSE_DROIT_D_EDITION_NON_LU));

            // L'ADMIN ne lit pas la porte : même autorisateur, modification écrite. (Contrôle que l'autorisateur ne
            // refuse que la lecture du droit, pas les écritures.)
            rmc_refuser_la_lecture_du_droit(&st, t);
            let (code, v, _) = rmc_modifier(&st, objet, &adm, id, json!({ "name": "par-admin" })).await;
            rmc_lever(&st);
            assert_eq!(code, 204, "({t}) l'admin passe : {v}");
            assert_eq!(rmc_lire(&st, &objet.ligne(id)), "par-admin|shared");

            // LE REFUS DE DROIT ÉTABLI : la propriétaire passe en privé (sans autorisateur), bob reste dehors.
            assert_eq!(rmc_modifier(&st, objet, &alice, id, json!({ "visibility": "private" })).await.0, 204, "({t}) fixture : privé d'alice");
            assert_eq!(rmc_modifier(&st, objet, &bob, id, json!({ "visibility": "shared" })).await.0, 403, "({t}) refus de droit établi (modification)");
            assert_eq!(rmc_supprimer(&st, objet, &bob, id).await.0, 403, "({t}) refus de droit établi (suppression)");
            assert_eq!(rmc_compte(&st, &format!("SELECT COUNT(*) FROM {t} WHERE id={id} AND visibility='private'")), 1, "({t}) toujours là, privé");
            // CONTRÔLE POSITIF : la propriétaire, sans autorisateur, supprime.
            assert_eq!(rmc_supprimer(&st, objet, &alice, id).await.0, 204, "({t}) nominal");
        }
    }

    /// La lecture d'existence de `playlist_update` refusée (autorisateur qui refuse la colonne `id`) : le 503
    /// part AVEC sa cause nommée en corps (`CAUSE_LISTE_DE_LECTURE_NON_LUE`) et l'identifiant de corrélation, rien
    /// d'écrit. MUTATION QUI LE FAIT ROUGIR : V5_EXISTENCE_NUE (`refus.status()` remis : 503 sans corps).
    #[tokio::test]
    async fn rmc_une_lecture_d_existence_refusee_sert_sa_cause_en_corps() {
        let (st, _tmp) = sp_state("rmc-existence");
        let alice = sp_au("alice", "editor");
        let id = rmc_objet_d_alice(&st, Objet::Liste).await;
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "playlist", column_name: "id" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (code, v, n) = rmc_modifier(&st, Objet::Liste, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
        rmc_lever(&st);
        assert_eq!(rmc_lire(&st, &Objet::Liste.ligne(id)), "avant|shared", "rien d'écrit");
        assert_eq!(code, 503, "une lecture d'existence refusée n'est ni une absence ni un succès : {v}");
        assert!(n > 0, "le 503 porte un corps : {v}");
        assert!(v["error"].as_str().unwrap_or("").starts_with(de::CAUSE_LISTE_DE_LECTURE_NON_LUE), "cause nommée en corps : {v}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "avec l'identifiant de corrélation : {v}");
    }

    /// La branche 404 de `refus_de_la_porte_d_edition` (la ligne n'est plus là à la lecture du droit) : un autorisateur à
    /// ÉTAT laisse passer la PREMIÈRE lecture de `id` (l'existence, ou `is_soql` pour le panneau) et IGNORE les
    /// suivantes (la colonne lue vaut NULL : la porte ne trouve aucune ligne). 404, jamais 403, rien d'écrit.
    /// MUTATION QUI LE FAIT ROUGIR : V5_NOROWS_403 (`QueryReturnedNoRows` rendu 403).
    #[tokio::test]
    async fn rmc_une_ligne_absente_a_la_lecture_du_droit_rend_404_et_non_403() {
        for objet in [Objet::Panneau, Objet::Liste] {
            let t = objet.table();
            let (st, _tmp) = sp_state(&format!("rmc-norows-{t}"));
            let alice = sp_au("alice", "editor");
            let id = rmc_objet_d_alice(&st, objet).await;
            let mut lectures_de_id = 0usize;
            st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, column_name: "id" } if table_name == t => {
                    lectures_de_id += 1;
                    if lectures_de_id == 1 { Authorization::Allow } else { Authorization::Ignore }
                }
                _ => Authorization::Allow,
            }));
            let (code, v, _) = rmc_modifier(&st, objet, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
            rmc_lever(&st);
            assert_eq!(rmc_lire(&st, &objet.ligne(id)), "avant|shared", "({t}) rien d'écrit");
            assert_eq!(code, 404, "({t}) aucune ligne à la lecture du droit : une absence, pas un refus de droit : {v}");
        }
    }
}
