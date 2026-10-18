// =====================================================================================
// `P10.33-l` (restes nommés : `playlist_update`, `playlist_delete`) — DEUX GESTES QUI RÉPONDAIENT 204 SUR UNE
// ÉCRITURE REFUSÉE.
//
// LE DÉFAUT, MESURÉ SUR 1d9ba63c : `playlist_update` enchaînait cinq `let _ = conn.execute(UPDATE playlist …)`
// (dont `visibility`, la bascule privé/partagé) puis rendait 204 ; `playlist_delete` avalait son `DELETE` et
// rendait 204 ; les deux lisaient l'existence par `query_row(..).is_err()` -> 404, qui confond une lecture
// refusée avec une absence. Une bascule en privé refusée laissait la liste PARTAGÉE pendant que la console
// lisait un succès.
//
// CE QUE CES TÉMOINS TIENNENT : chaque écriture refusée (`RAISE(ABORT)`, `Err`) ou sans effet (`RAISE(IGNORE)`,
// `Ok(0)`) -> 503 et la ligne entière comme avant (l'écriture qui précédait le refus est annulée) ; la
// suppression refusée -> 503 nommé, la liste toujours là ; le `BEGIN` puis le `COMMIT` refusés -> 503, rien
// d'écrit, transaction refermée ; la lecture d'existence refusée -> 503 (jamais 404), une absence -> 404 ;
// 403 inchangé ; nominal inchangé (contrôle positif dans chaque témoin) ; les quatre causes de transaction
// prennent les ouvertures que la console sait lire (copie des expressions de web/core.js, lookahead traduit pour
// `regex`) — servies en corps par la suppression comme par la modification (`P10.33-l`).
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : U8_VIS_LET (le `let _` remis sur visibility),
// U8_SANS_GARDE (écritures d'avant le refus validées), U8_OK0 (`Ok(0)` accepté), U8_LECTURE_404 (404 pour une
// lecture refusée), U8_503_EN_204 (204 rendu malgré le refus), U8_DEL_LET (le `DELETE` avalé).
//
// CE QU'ILS NE TIENNENT PAS : le corps du 503 de la MODIFICATION et la porte d'édition tri-état (`P10.33-l`) sont
// tenus par `refus_de_modification_servi_avec_sa_cause.rs`, pas ici ; ce que la console peint de ces refus (web/ hors
// périmètre) ; `case_detach_item`, troisième reste nommé de P10.33-l.
// =====================================================================================
mod listes_de_lecture_ecrites_ou_refusees {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    fn ldl_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ldl_lire(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, String>(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ldl_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ldl_corps(r: Response) -> (u16, Value) {
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    fn ldl_ligne(id: i64) -> String {
        format!("SELECT name||'|'||interval_s||'|'||items||'|'||visibility||'|'||COALESCE(updated,0) FROM playlist WHERE id={id}")
    }

    /// Une liste PARTAGÉE d'alice, créée par le handler réel, horodatage figé à 1 pour qu'une écriture se voie.
    async fn ldl_liste_d_alice(st: &AppState) -> i64 {
        let (code, v) = ldl_corps(
            playlist_create(State(st.clone()), Extension(sp_au("alice", "editor")), Json(json!({ "name": "avant", "interval_s": 30, "items": [1, 2] }))).await,
        )
        .await;
        assert_eq!(code, 200, "fixture : la liste est créée : {v}");
        let id = v["id"].as_i64().expect("fixture : identifiant servi");
        ldl_ecrire(st, &format!("UPDATE playlist SET updated=1 WHERE id={id};"));
        assert_eq!(ldl_lire(st, &ldl_ligne(id)), "avant|30|[1,2]|shared|1", "fixture : partagée");
        id
    }

    async fn ldl_modifier(st: &AppState, qui: &AuthUser, id: i64, corps: Value) -> u16 {
        playlist_update(State(st.clone()), Extension(qui.clone()), Path(id), Json(corps)).await.status().as_u16()
    }

    /// MUTATIONS QUI LE FONT ROUGIR : U8_VIS_LET (204, liste restée partagée), U8_SANS_GARDE (nom et intervalle
    /// validés), U8_503_EN_204 (204).
    #[tokio::test]
    async fn ldl_une_bascule_en_prive_refusee_rend_503_et_annule_le_nom_et_l_intervalle() {
        let (st, _tmp) = sp_state("ldl-vis");
        let alice = sp_au("alice", "editor");
        let id = ldl_liste_d_alice(&st).await;
        ldl_ecrire(&st, "CREATE TRIGGER ldl_refus BEFORE UPDATE OF visibility ON playlist BEGIN SELECT RAISE(ABORT,'refus de témoin'); END;");
        // Le nom et l'intervalle précèdent la visibilité : leur présence après le refus prouverait une écriture
        // partielle VALIDÉE.
        let code = ldl_modifier(&st, &alice, id, json!({ "name": "apres", "interval_s": 60, "visibility": "private" })).await;
        assert_eq!(code, 503, "une bascule refusée n'est pas un succès");
        assert_eq!(ldl_lire(&st, &ldl_ligne(id)), "avant|30|[1,2]|shared|1", "la liste reste PARTAGÉE, nom et intervalle d'avant");
        // CONTRÔLE POSITIF.
        ldl_ecrire(&st, "DROP TRIGGER ldl_refus;");
        assert_eq!(ldl_modifier(&st, &alice, id, json!({ "name": "apres", "interval_s": 60, "visibility": "private" })).await, 204);
        let ecrite = ldl_lire(&st, &ldl_ligne(id));
        assert!(ecrite.starts_with("apres|60|[1,2]|private|") && !ecrite.ends_with("|1"), "ligne écrite : {ecrite}");
    }

    /// CHAQUE écriture refusée seule (`Err`) ou sans effet (`Ok(0)`) annule toutes les autres. MUTATIONS QUI LE FONT
    /// ROUGIR : U8_OK0 (voies ignore), U8_VIS_LET (visibility abort), U8_SANS_GARDE.
    #[tokio::test]
    async fn ldl_chaque_ecriture_de_la_modification_refusee_rend_503_et_n_ecrit_rien() {
        let (st, _tmp) = sp_state("ldl-colonnes");
        let alice = sp_au("alice", "editor");
        let id = ldl_liste_d_alice(&st).await;
        let avant = ldl_lire(&st, &ldl_ligne(id));
        let corps = json!({ "name": "n2", "interval_s": 90, "items": [3], "visibility": "private" });
        let mut manquent: Vec<String> = Vec::new();
        for col in ["name", "interval_s", "items", "visibility", "updated"] {
            for (voie, action) in [("abort", "SELECT RAISE(ABORT,'refus de témoin');"), ("ignore", "SELECT RAISE(IGNORE);")] {
                ldl_ecrire(&st, &format!("CREATE TRIGGER ldl_refus BEFORE UPDATE OF {col} ON playlist BEGIN {action} END;"));
                let code = ldl_modifier(&st, &alice, id, corps.clone()).await;
                let apres = ldl_lire(&st, &ldl_ligne(id));
                ldl_ecrire(&st, "DROP TRIGGER ldl_refus;");
                if code != 503 || apres != avant {
                    manquent.push(format!("{col} ({voie}) : code {code}, ligne `{apres}` (attendu `{avant}`)"));
                }
            }
        }
        assert!(manquent.is_empty(), "écritures de la modification dont le refus n'a pas tout annulé : {manquent:#?}");
        // CONTRÔLE POSITIF.
        assert_eq!(ldl_modifier(&st, &alice, id, corps).await, 204);
        let ecrite = ldl_lire(&st, &ldl_ligne(id));
        assert!(ecrite.starts_with("n2|90|[3]|private|") && !ecrite.ends_with("|1"), "ligne écrite : {ecrite}");
    }

    /// MUTATIONS QUI LE FONT ROUGIR : U8_DEL_LET (204), U8_OK0 (voie ignore), U8_503_EN_204.
    #[tokio::test]
    async fn ldl_une_suppression_refusee_rend_503_nomme_et_la_liste_reste() {
        let (st, _tmp) = sp_state("ldl-del");
        let alice = sp_au("alice", "editor");
        let id = ldl_liste_d_alice(&st).await;
        for (voie, action) in [("abort", "SELECT RAISE(ABORT,'refus de témoin');"), ("ignore", "SELECT RAISE(IGNORE);")] {
            ldl_ecrire(&st, &format!("CREATE TRIGGER ldl_refus BEFORE DELETE ON playlist BEGIN {action} END;"));
            let (code, v) = ldl_corps(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(id)).await).await;
            ldl_ecrire(&st, "DROP TRIGGER ldl_refus;");
            assert_eq!(code, 503, "({voie}) une suppression refusée n'est pas un succès : {v}");
            assert!(
                v["error"].as_str().unwrap_or("").starts_with(crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE),
                "({voie}) le refus nomme sa cause : {v}"
            );
            assert_eq!(ldl_lire(&st, &ldl_ligne(id)), "avant|30|[1,2]|shared|1", "({voie}) la liste existe toujours, partagée");
        }
        // CONTRÔLE POSITIF.
        assert_eq!(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(id)).await.status().as_u16(), 204);
        assert_eq!(ldl_compte(&st, &format!("SELECT COUNT(*) FROM playlist WHERE id={id}")), 0);
    }

    fn ldl_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn ldl_refuser_le_begin(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ldl_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Refuse la PREMIÈRE lecture de `playlist` (celle qui établit l'existence), puis laisse tout passer : une route
    /// qui poursuivrait malgré la lecture refusée pourrait alors écrire, et « rien d'écrit » peut rougir. (Refuser
    /// toute lecture de `playlist` faisait aussi échouer chaque `UPDATE`/`DELETE … WHERE id=?` à sa préparation :
    /// l'assertion était vacante.)
    fn ldl_refuser_la_lecture_d_existence(st: &AppState) {
        let mut a_refuser = true;
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if a_refuser && table_name == "playlist" => {
                a_refuser = false;
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
    }

    /// `BEGIN` puis `COMMIT` refusés, sur les deux routes : 503, transaction refermée, rien d'écrit, cause nommée de
    /// la suppression selon le bout refusé.
    #[tokio::test]
    async fn ldl_un_begin_ou_un_commit_refuse_rend_503_et_n_ecrit_rien() {
        let (st, _tmp) = sp_state("ldl-txn");
        let alice = sp_au("alice", "editor");
        let id = ldl_liste_d_alice(&st).await;
        for (voie, refuser) in [("BEGIN", ldl_refuser_le_begin as fn(&AppState)), ("COMMIT", ldl_refuser_le_commit as fn(&AppState))] {
            refuser(&st);
            let code = ldl_modifier(&st, &alice, id, json!({ "name": "apres", "visibility": "private" })).await;
            let fermee = st.db.lock().is_autocommit();
            ldl_lever(&st);
            assert_eq!(code, 503, "({voie} refusé) la modification n'est pas un succès");
            assert!(fermee, "({voie} refusé) la transaction de la modification est refermée");
            assert_eq!(ldl_lire(&st, &ldl_ligne(id)), "avant|30|[1,2]|shared|1", "({voie}) rien d'écrit");

            refuser(&st);
            let r = playlist_delete(State(st.clone()), Extension(alice.clone()), Path(id)).await;
            let fermee = st.db.lock().is_autocommit();
            ldl_lever(&st);
            let (code, v) = ldl_corps(r).await;
            assert_eq!(code, 503, "({voie} refusé) la suppression n'est pas un succès : {v}");
            assert!(fermee, "({voie} refusé) la transaction de la suppression est refermée");
            let attendue = if voie == "BEGIN" {
                crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE
            } else {
                crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE
            };
            assert!(v["error"].as_str().unwrap_or("").starts_with(attendue), "({voie} refusé) le refus nomme sa cause : {v}");
            assert_eq!(ldl_compte(&st, &format!("SELECT COUNT(*) FROM playlist WHERE id={id}")), 1, "({voie}) la liste existe toujours");
        }
        // CONTRÔLE POSITIF.
        assert_eq!(ldl_modifier(&st, &alice, id, json!({ "name": "apres" })).await, 204);
        assert_eq!(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(id)).await.status().as_u16(), 204);
    }

    /// La lecture d'existence refusée n'est pas une absence : 503 (nommé pour la suppression), jamais 404, rien
    /// d'écrit ; une absence établie reste 404. MUTATIONS QUI LE FONT ROUGIR : U8_LECTURE_404 (404) ;
    /// U8_LECTURE_IGNOREE (la route poursuit malgré la lecture refusée : rougit sur « rien d'écrit », vérifié avant le
    /// code).
    #[tokio::test]
    async fn ldl_une_lecture_d_existence_refusee_rend_503_et_l_absence_404() {
        let (st, _tmp) = sp_state("ldl-lecture");
        let alice = sp_au("alice", "editor");
        let id = ldl_liste_d_alice(&st).await;
        ldl_refuser_la_lecture_d_existence(&st);
        let code_maj = ldl_modifier(&st, &alice, id, json!({ "visibility": "private" })).await;
        ldl_lever(&st);
        assert_eq!(ldl_lire(&st, &ldl_ligne(id)), "avant|30|[1,2]|shared|1", "rien d'écrit (modification)");
        assert_eq!(code_maj, 503, "une lecture refusée n'établit pas l'absence (modification)");
        ldl_refuser_la_lecture_d_existence(&st);
        let r = playlist_delete(State(st.clone()), Extension(alice.clone()), Path(id)).await;
        ldl_lever(&st);
        assert_eq!(ldl_compte(&st, &format!("SELECT COUNT(*) FROM playlist WHERE id={id}")), 1, "rien d'effacé (suppression)");
        let (code_del, v) = ldl_corps(r).await;
        assert_eq!(code_del, 503, "une lecture refusée n'établit pas l'absence (suppression) : {v}");
        assert!(v["error"].as_str().unwrap_or("").starts_with(crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_LUE), "cause nommée : {v}");
        // L'ABSENCE ÉTABLIE.
        assert_eq!(ldl_modifier(&st, &alice, 999_999, json!({ "visibility": "private" })).await, 404);
        assert_eq!(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(999_999)).await.status().as_u16(), 404);
    }

    /// Les contrôles d'accès passent AVANT toute écriture : un éditeur non propriétaire d'une liste privée garde son
    /// 403, déclencheurs posés ou non.
    #[tokio::test]
    async fn ldl_un_editeur_non_proprietaire_garde_son_403() {
        let (st, _tmp) = sp_state("ldl-acces");
        let alice = sp_au("alice", "editor");
        let bob = sp_au("bob", "editor");
        let id = ldl_liste_d_alice(&st).await;
        assert_eq!(ldl_modifier(&st, &alice, id, json!({ "visibility": "private" })).await, 204, "fixture : privée d'alice");
        ldl_ecrire(
            &st,
            "CREATE TRIGGER ldl_a BEFORE DELETE ON playlist BEGIN SELECT RAISE(ABORT,'x'); END; \
             CREATE TRIGGER ldl_b BEFORE UPDATE ON playlist BEGIN SELECT RAISE(ABORT,'x'); END;",
        );
        assert_eq!(ldl_modifier(&st, &bob, id, json!({ "visibility": "shared" })).await, 403);
        assert_eq!(playlist_delete(State(st.clone()), Extension(bob.clone()), Path(id)).await.status().as_u16(), 403);
    }

    /// Les causes « transaction annulée » et « transaction non prise » s'ouvrent comme la console sait les lire (la
    /// suppression et la modification les servent en corps)
    /// (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`, web/core.js — copie, le
    /// lookahead négatif traduit par une alternative fin/non-lettre).
    #[test]
    fn ldl_les_causes_prennent_les_ouvertures_que_la_console_lit() {
        let ecriture = regex::Regex::new(r"^[\p{Lu}', ]+ : la base n'a pas pris (?:l'écriture|l'effacement) [^()—]{1,80}, et la transaction est annulée(?:$|[^\p{L}\p{N}])").unwrap();
        let transaction = regex::Regex::new(r"^[\p{Lu}', ]+ : la base n'a pas pris la transaction [^()—]{1,60}\(BEGIN(?:$|[^\p{L}\p{N}])").unwrap();
        use crate::handlers::dash_ergonomics as de;
        for c in [de::CAUSE_LISTE_DE_LECTURE_INCHANGEE, de::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE] {
            assert!(ecriture.is_match(c), "ouverture « écriture non prise » attendue : {c}");
        }
        for c in [de::CAUSE_LISTE_DE_LECTURE_INCHANGEE_TRANSACTION_NON_OUVERTE, de::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE] {
            assert!(transaction.is_match(c), "ouverture « transaction non prise » attendue : {c}");
        }
        // CONTRÔLE NÉGATIF : la cause de lecture ne dit pas « rien n'a changé » par une transaction.
        assert!(!ecriture.is_match(de::CAUSE_LISTE_DE_LECTURE_NON_LUE) && !transaction.is_match(de::CAUSE_LISTE_DE_LECTURE_NON_LUE));
    }
}
