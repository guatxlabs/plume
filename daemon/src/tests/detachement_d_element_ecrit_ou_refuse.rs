// =====================================================================================
// `P10.33-l` (reste nommé : `case_detach_item`, queue de `P10.20-w`) — LE DÉTACHEMENT D'UN ÉLÉMENT N'EST ATTESTÉ
// QU'ÉCRIT.
//
// LE DÉFAUT, LU SUR 1d9ba63c : `case_detach_item` jetait son `DELETE` (`let _ = conn.execute(..)`), posait la note
// « détaché … » par `case_add_item` (qui jette la sienne) et rendait `true` ; `case_item_delete` répondait 204. Sur un
// effacement refusé, l'élément restait au dossier, la chronologie ATTESTAIT son détachement, la console retirait la
// ligne.
//
// CE QUE CES TÉMOINS TIENNENT, SUR LA ROUTE RÉELLE (`case_item_delete`) : effacement refusé par le moteur
// (`RAISE(ABORT)`), effacement sans effet (`RAISE(IGNORE)`, `Ok(0)`), note de détachement refusée, `COMMIT` refusé,
// `BEGIN` refusé — chaque fois 503 nommé, l'élément toujours là, AUCUNE note « détaché », la transaction fermée ;
// contre-épreuve nominale (204, élément parti, une note) ; élément d'un AUTRE dossier et élément déjà détaché : 404,
// rien d'effacé. Le point d'entrée `case_detach_item` rend `ElementAbsent` pour l'élément d'un autre dossier
// (`tests/cases.rs`, `case_detach_item_test`).
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : U5_DELETE_AVALE (le `let _ =` rétabli), U5_OK0_SUCCES (`Ok(0)`
// en succès), U5_SANS_TRANSACTION (corps joué hors transaction), U5_503_EN_204, U5_BEGIN_204, U5_COMMIT_204 — rouges ;
// U5_NOTE_AVANT (note posée avant l'effacement) reste VERT : ÉQUIVALENT sous la transaction (un refus de l'un ou de
// l'autre annule les deux), il n'est rouge que joint à l'absence de transaction, que U5_SANS_TRANSACTION tient.
//
// CORRECTION (vérification indépendante) : la relecture refusée par le moteur sert la cause de LECTURE
// (`CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT`), jamais un 404 ni la cause d'effacement ; le bras `ElementAbsent` du
// gestionnaire est tenu (404, rien d'écrit) ; la cause d'une note refusée est journalisée, non servie. MUTANTS :
// U5_RELU_ABSENT, U5_RELU_CAUSE_ECRITURE, U5_ABSENT_204, U5_NOTE_SERVIE — rouges.
//
// CE QU'ILS NE TIENNENT PAS : un effacement de PLUSIEURS lignes (`Ok(n>1)`) est refusé par le code mais injouable
// (`id` est la clé primaire) ; ce que la console peint du 503 (web/ hors périmètre : la forme de la cause est celle
// que `OUVERTURE_DE_L_ECRITURE_NON_PRISE`, `OUVERTURE_DE_LA_TRANSACTION_NON_PRISE` et
// `OUVERTURE_DE_L_ECRITURE_NON_VALIDEE` lisent, jugée ici par son préfixe seulement) ; le mode multi-tenant.
// =====================================================================================
mod detachement_d_element_ecrit_ou_refuse {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    async fn dee_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() { Value::Null } else { serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())) };
        (statut, corps)
    }

    fn dee_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn dee_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Un dossier, une alerte rattachée (`ref` = alert:7). Rend (dossier, élément).
    fn dee_dossier_et_element(st: &AppState) -> (i64, i64) {
        let id = dossier_seme(&st.db.lock(), "alice", "U5", 3, "", None, 2);
        dee_ecrire(st, &format!("INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES({id},1,'alert','alice','rattachée','alert:7')"));
        let item = dee_compte(st, &format!("SELECT id FROM incident_item WHERE incident_id={id} AND kind='alert'"));
        (id, item)
    }

    fn dee_element_present(st: &AppState, id: i64, item: i64) -> bool {
        dee_compte(st, &format!("SELECT COUNT(*) FROM incident_item WHERE id={item} AND incident_id={id}")) == 1
    }

    fn dee_notes_de_detachement(st: &AppState, id: i64) -> i64 {
        dee_compte(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='note' AND body LIKE 'détaché%'"))
    }

    async fn dee_detacher(st: &AppState, id: i64, item: i64) -> (u16, Value) {
        dee_corps(case_item_delete(State(st.clone()), Extension(sp_au("alice", "editor")), Path((id, item))).await).await
    }

    /// Juge un refus : 503, la cause nommée (préfixe), la cause du moteur jointe (ou, `moteur_servi` faux, la cause
    /// seule), l'élément toujours là, aucune note, la transaction fermée.
    fn dee_juger_refus_selon(st: &AppState, quoi: &str, (statut, corps): &(u16, Value), cause: &str, moteur_servi: bool, id: i64, item: i64) {
        let phrase = corps["error"].as_str().unwrap_or("");
        let mut manquent = Vec::new();
        for (propriete, tenue) in [
            ("statut 503", *statut == 503),
            ("cause nommée", phrase.starts_with(cause)),
            ("cause du moteur jointe ou absente selon le cas", (phrase.len() > cause.len() + 3 && phrase.ends_with(')')) == moteur_servi && (moteur_servi || phrase == cause)),
            ("l'élément est toujours au dossier", dee_element_present(st, id, item)),
            ("aucune note « détaché »", dee_notes_de_detachement(st, id) == 0),
            ("transaction fermée", st.db.lock().is_autocommit()),
        ] {
            if !tenue {
                manquent.push(propriete);
            }
        }
        assert!(manquent.is_empty(), "{quoi} : manquent {manquent:?} — servi {statut} {corps}");
    }

    fn dee_juger_refus(st: &AppState, quoi: &str, r: &(u16, Value), cause: &str, id: i64, item: i64) {
        dee_juger_refus_selon(st, quoi, r, cause, true, id, item);
    }

    #[tokio::test]
    async fn dee_nominal_204_element_parti_une_note() {
        let (st, _p) = sp_state("dee-nominal");
        let (id, item) = dee_dossier_et_element(&st);
        let r = dee_detacher(&st, id, item).await;
        assert_eq!(r, (204, Value::Null), "nominal : 204 sans corps");
        assert_eq!(dee_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='alert'")), 0, "l'alerte est détachée");
        assert_eq!(dee_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='note' AND body='détaché alert:7'")), 1, "une note atteste le détachement");
    }

    /// U5_DELETE_AVALE et U5_503_EN_204 le font rougir (204, note posée, élément toujours là).
    #[tokio::test]
    async fn dee_effacement_refuse_par_le_moteur_503_element_present_aucune_note() {
        let (st, _p) = sp_state("dee-abort");
        let (id, item) = dee_dossier_et_element(&st);
        dee_ecrire(&st, "CREATE TRIGGER dee_refus BEFORE DELETE ON incident_item BEGIN SELECT RAISE(ABORT, 'effacement refusé par le témoin'); END;");
        let r = dee_detacher(&st, id, item).await;
        dee_juger_refus(&st, "effacement refusé", &r, CAUSE_ELEMENT_NON_DETACHE, id, item);
        assert!(r.1["error"].as_str().unwrap_or("").contains("effacement refusé par le témoin"), "la cause du moteur est servie : {}", r.1);
        dee_ecrire(&st, "DROP TRIGGER dee_refus;");
        assert_eq!(dee_detacher(&st, id, item).await, (204, Value::Null), "contrôle positif : déclencheur retiré, 204");
        assert_eq!(dee_notes_de_detachement(&st, id), 1);
    }

    /// U5_OK0_SUCCES le fait rougir : sous le `BEGIN IMMEDIATE`, un `Ok(0)` n'est pas une disparition — l'élément est
    /// encore là, et un 404 « absent » ou un 204 serait faux.
    #[tokio::test]
    async fn dee_effacement_sans_effet_503_element_present_aucune_note() {
        let (st, _p) = sp_state("dee-ignore");
        let (id, item) = dee_dossier_et_element(&st);
        dee_ecrire(&st, "CREATE TRIGGER dee_ignore BEFORE DELETE ON incident_item BEGIN SELECT RAISE(IGNORE); END;");
        let r = dee_detacher(&st, id, item).await;
        dee_juger_refus(&st, "effacement sans effet", &r, CAUSE_ELEMENT_NON_DETACHE, id, item);
    }

    /// U5_SANS_TRANSACTION le fait rougir : l'effacement parti, la note refusée, l'élément perdu sans trace.
    #[tokio::test]
    async fn dee_note_refusee_annule_l_effacement() {
        let (st, _p) = sp_state("dee-note");
        let (id, item) = dee_dossier_et_element(&st);
        dee_ecrire(&st, "CREATE TRIGGER dee_note BEFORE INSERT ON incident_item WHEN NEW.kind='note' AND NEW.body LIKE 'détaché%' BEGIN SELECT RAISE(ABORT, 'note refusée par le témoin'); END;");
        let r = dee_detacher(&st, id, item).await;
        // La cause de `ajouter_l_element_au_dossier` est journalisée, jamais servie (son contrat) : U5_NOTE_SERVIE rougit.
        dee_juger_refus_selon(&st, "note refusée", &r, CAUSE_ELEMENT_NON_DETACHE, false, id, item);
        assert!(!r.1["error"].as_str().unwrap_or("").contains("note refusée par le témoin"), "cause de la note non servie : {}", r.1);
    }

    /// La RELECTURE de l'élément, dans la transaction, refusée par le moteur (l'autorisateur refuse `incident_item.ref`,
    /// que la pré-lecture du gestionnaire ne lit pas) : rien n'est su de l'élément — 503 sous la cause de la LECTURE
    /// (`CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT`), jamais un 404 « absent » ni « la base n'a pas pris l'effacement ».
    /// U5_RELU_ABSENT (404) et U5_RELU_CAUSE_ECRITURE (cause d'effacement) le font rougir.
    #[tokio::test]
    async fn dee_relecture_refusee_503_lecture_ni_absence_ni_effacement() {
        let (st, _p) = sp_state("dee-relecture");
        let (id, item) = dee_dossier_et_element(&st);
        let vu = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = vu.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "incident_item", column_name: "ref" } => {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        let r = dee_detacher(&st, id, item).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(vu.load(std::sync::atomic::Ordering::SeqCst) >= 1, "fixture : la lecture de `ref` a été demandée et refusée");
        dee_juger_refus(&st, "relecture refusée", &r, CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT, id, item);
        assert_eq!(dee_detacher(&st, id, item).await, (204, Value::Null), "contrôle positif : autorisateur retiré, 204");
    }

    /// L'élément ABSENT à la relecture dans la transaction alors que la pré-lecture l'a vu (l'autorisateur IGNORE
    /// `incident_id` dès sa deuxième lecture : la colonne lit NULL, aucune ligne) — le cas d'un effacement concurrent
    /// entre la pré-lecture et le `BEGIN IMMEDIATE`. 404 « absent de ce dossier » par le bras `ElementAbsent` du
    /// gestionnaire, rien d'effacé, AUCUNE note : un 204 attesterait un détachement que rien n'a écrit. U5_ABSENT_204
    /// le fait rougir.
    #[tokio::test]
    async fn dee_absent_a_la_relecture_404_rien_d_ecrit() {
        let (st, _p) = sp_state("dee-absent-relu");
        let (id, item) = dee_dossier_et_element(&st);
        let vu = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = vu.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "incident_item", column_name: "incident_id" } => {
                if c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Authorization::Allow
                } else {
                    Authorization::Ignore
                }
            }
            _ => Authorization::Allow,
        }));
        let r = dee_detacher(&st, id, item).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(vu.load(std::sync::atomic::Ordering::SeqCst) >= 2, "fixture : la pré-lecture ET la relecture ont lu `incident_id`");
        assert_eq!(r.0, 404, "absent à la relecture : 404 — {}", r.1);
        assert!(r.1["error"].as_str().unwrap_or("").starts_with(CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER), "cause d'absence : {}", r.1);
        assert!(dee_element_present(&st, id, item), "rien n'est effacé");
        assert_eq!(dee_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='note'")), 0, "aucune note");
        assert!(st.db.lock().is_autocommit(), "transaction fermée");
    }

    /// U5_COMMIT_204 le fait rougir.
    #[tokio::test]
    async fn dee_commit_refuse_503_rien_d_ecrit() {
        let (st, _p) = sp_state("dee-commit");
        let (id, item) = dee_dossier_et_element(&st);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = dee_detacher(&st, id, item).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        dee_juger_refus(&st, "COMMIT refusé", &r, CAUSE_ELEMENT_NON_DETACHE_TRANSACTION_NON_VALIDEE, id, item);
    }

    /// U5_BEGIN_204 le fait rougir.
    #[tokio::test]
    async fn dee_begin_refuse_503_rien_d_ecrit() {
        let (st, _p) = sp_state("dee-begin");
        let (id, item) = dee_dossier_et_element(&st);
        let avant = dee_compte(&st, "SELECT total_changes()");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = dee_detacher(&st, id, item).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        dee_juger_refus(&st, "BEGIN refusé", &r, CAUSE_ELEMENT_NON_DETACHE_TRANSACTION_NON_OUVERTE, id, item);
        assert_eq!(dee_compte(&st, "SELECT total_changes()"), avant, "BEGIN refusé : rien n'est écrit par l'écrivain");
    }

    /// Anti-IDOR et élément déjà détaché : 404 inchangé, rien d'effacé, aucune note.
    #[tokio::test]
    async fn dee_element_d_un_autre_dossier_ou_deja_detache_404() {
        let (st, _p) = sp_state("dee-404");
        let (id, item) = dee_dossier_et_element(&st);
        let (autre, item_autre) = dee_dossier_et_element(&st);
        let r = dee_detacher(&st, id, item_autre).await;
        assert_eq!(r.0, 404, "élément d'un autre dossier : 404 — {}", r.1);
        assert!(r.1["error"].as_str().unwrap_or("").starts_with(CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER), "cause d'absence : {}", r.1);
        assert!(dee_element_present(&st, autre, item_autre), "l'élément de l'autre dossier n'est pas effacé");
        assert_eq!(dee_notes_de_detachement(&st, id) + dee_notes_de_detachement(&st, autre), 0, "aucune note");
        assert_eq!(dee_detacher(&st, id, item).await, (204, Value::Null));
        let r = dee_detacher(&st, id, item).await;
        assert_eq!(r.0, 404, "élément déjà détaché : 404 — {}", r.1);
        assert!(r.1["error"].as_str().unwrap_or("").starts_with(CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER), "cause d'absence : {}", r.1);
        assert_eq!(dee_notes_de_detachement(&st, id), 1, "une seule note, celle du premier détachement");
    }
}
