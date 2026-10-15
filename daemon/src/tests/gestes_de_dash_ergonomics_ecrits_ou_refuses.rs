// =====================================================================================
// `P10.20-w` (gestes de `dash_ergonomics`) — TROIS GESTES QUI RÉPONDAIENT 204 SUR UNE ÉCRITURE REFUSÉE.
//
// CE QUE CES TÉMOINS TIENNENT. `library_panel_update` enchaînait cinq `let _ = conn.execute(UPDATE …)`
// (dont `visibility`, la bascule privé/partagé) puis rendait 204 ; `library_panel_delete` avalait le
// détachement des référents ET le DELETE ; `snapshot_delete` avalait son DELETE. Chaque témoin pose un
// déclencheur sur la table visée — `RAISE(ABORT)` (le moteur refuse : `Err`) ou `RAISE(IGNORE)` (aucune
// ligne écrite : `Ok(0)`) — joue la route RÉELLE, puis relit l'état par la clé : 503, état d'avant
// intact (la transaction annulée défait aussi les écritures qui précédaient le refus), cache non
// invalidé, référents toujours rattachés, instantané toujours servi par son jeton. Chaque témoin porte
// son CONTRÔLE POSITIF : le déclencheur retiré, la même route rend 204 avec les mêmes effets qu'avant.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : T8_UPD_LET (les `let _` de la modification
// rétablis), T8_UPD_204 (204 rendu malgré l'erreur), T8_DEL_LET, T8_DETACH_NON_ANNULE (détachement
// validé sur une suppression refusée), T8_SNAP_LET, T8_OK0 (`Ok(0)` traité en succès, les trois gestes).
//
// REPRISE (vérification indépendante) : CHAQUE écriture de la modification est refusée tour à tour (un
// déclencheur `BEFORE UPDATE OF <colonne>` par colonne, voies ABORT et IGNORE), le DÉTACHEMENT des
// référents est refusé (déclencheur sur `panel`), et le `BEGIN` puis le `COMMIT` des deux routes à
// transaction sont refusés par un autorisateur SQLite posé sur l'écrivain partagé. Mutants joués :
// T8C_BOUCLE (erreur de name/title/query/viz/drill avalée), T8C_SOQL, T8C_UPDATED (idem is_soql,
// updated), T8C_DETACH (refus du détachement avalé), T8C_BEGIN_UPD / T8C_BEGIN_DEL (204 sur BEGIN refusé),
// T8C_COMMIT_UPD / T8C_COMMIT_DEL (COMMIT refusé avalé, 204).
//
// CE QU'ILS NE TIENNENT PAS : un détachement SANS EFFET (`Ok(0)` du `UPDATE panel`, déclencheur IGNORE) n'est
// pas refusé — le nombre de référents n'est pas relu avant, la suppression passe et les panneaux gardent un
// `library_panel_id` orphelin ; le corps du 503 de la MODIFICATION (sa signature reste `StatusCode`, la
// cause part au journal) ; ce que la console peint de ces refus.
// =====================================================================================
mod gestes_de_dash_ergonomics_ecrits_ou_refuses {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const GDE_JETON: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn gde_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn gde_lire_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, String>(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn gde_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn gde_corps(r: Response) -> (u16, Value) {
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    /// Une définition PARTAGÉE d'alice, créée par le handler réel, un panneau d'alice qui la référence, et une
    /// ligne de cache de ce panneau. Rend (définition, panneau).
    async fn gde_definition_referencee(st: &AppState) -> (i64, i64) {
        let alice = sp_au("alice", "editor");
        let (code, v) = gde_corps(
            library_panel_create(State(st.clone()), Extension(alice), Json(json!({ "name": "def", "title": "avant", "query": "search source=web | table message" })))
                .await,
        )
        .await;
        assert_eq!(code, 200, "fixture : la définition est créée : {v}");
        let lib = v["id"].as_i64().expect("fixture : identifiant servi");
        gde_ecrire(st, "INSERT INTO dashboard(name,created,owner,visibility) VALUES('d-alice',1000,'alice','shared');");
        let did = gde_compte(st, "SELECT MAX(id) FROM dashboard");
        gde_ecrire(
            st,
            &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,library_panel_id) VALUES({did},'p','search source=web | table message',1,'table',{lib});"),
        );
        let pid = gde_compte(st, "SELECT MAX(id) FROM panel");
        gde_ecrire(st, &format!("INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES({pid},'r','fp',1,'{{}}');"));
        assert_eq!(gde_lire_texte(st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "shared", "fixture : partagée");
        (lib, pid)
    }

    fn gde_instantane_d_alice(st: &AppState) -> i64 {
        gde_ecrire(
            st,
            &format!("INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(1,'i','{GDE_JETON}','{{}}',1000,'alice','editor');"),
        );
        gde_compte(st, "SELECT MAX(id) FROM dashboard_snapshot")
    }

    async fn gde_lire_instantane(st: &AppState) -> u16 {
        snapshot_get(State(st.clone()), Extension(sp_au("alice", "editor")), Path(GDE_JETON.to_string())).await.status().as_u16()
    }

    async fn gde_modifier(st: &AppState, qui: &AuthUser, lib: i64, corps: Value) -> u16 {
        library_panel_update(State(st.clone()), Extension(qui.clone()), Path(lib), Json(corps)).await.as_u16()
    }

    /// MUTATIONS QUI LE FONT ROUGIR : T8_UPD_LET (204, titre écrit), T8_UPD_204 (204).
    #[tokio::test]
    async fn gde_une_bascule_en_prive_refusee_rend_503_et_laisse_la_definition_d_avant_et_son_cache() {
        let (st, _tmp) = sp_state("gde-upd-abort");
        let alice = sp_au("alice", "editor");
        let (lib, pid) = gde_definition_referencee(&st).await;
        let maj_avant = gde_compte(&st, &format!("SELECT COALESCE(updated,0) FROM library_panel WHERE id={lib}"));
        gde_ecrire(&st, "CREATE TRIGGER gde_refus BEFORE UPDATE OF visibility ON library_panel BEGIN SELECT RAISE(ABORT,'refus de témoin'); END;");
        // Le titre précède la visibilité dans l'ordre des écritures : sa présence après le refus prouverait
        // qu'une écriture partielle a été VALIDÉE.
        let code = gde_modifier(&st, &alice, lib, json!({ "title": "apres", "visibility": "private" })).await;
        assert_eq!(code, 503, "une bascule refusée n'est pas un succès");
        assert_eq!(gde_lire_texte(&st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "shared", "la définition reste PARTAGÉE, et la réponse l'a dit");
        assert_eq!(gde_lire_texte(&st, &format!("SELECT title FROM library_panel WHERE id={lib}")), "avant", "l'écriture qui précédait le refus est annulée");
        assert_eq!(gde_compte(&st, &format!("SELECT COALESCE(updated,0) FROM library_panel WHERE id={lib}")), maj_avant, "l'horodatage n'a pas bougé");
        assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "le cache des référents n'est pas invalidé");
        // CONTRÔLE POSITIF : déclencheur retiré, mêmes effets qu'avant le correctif.
        gde_ecrire(&st, "DROP TRIGGER gde_refus;");
        assert_eq!(gde_modifier(&st, &alice, lib, json!({ "title": "apres", "visibility": "private" })).await, 204);
        assert_eq!(gde_lire_texte(&st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "private");
        assert_eq!(gde_lire_texte(&st, &format!("SELECT title FROM library_panel WHERE id={lib}")), "apres");
        assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 0, "un succès purge le cache des référents");
    }

    /// MUTATION QUI LE FAIT ROUGIR : T8_OK0 (aucune ligne écrite traitée en succès -> 204).
    #[tokio::test]
    async fn gde_une_bascule_sans_effet_rend_503() {
        let (st, _tmp) = sp_state("gde-upd-ignore");
        let alice = sp_au("alice", "editor");
        let (lib, pid) = gde_definition_referencee(&st).await;
        gde_ecrire(&st, "CREATE TRIGGER gde_ignore BEFORE UPDATE OF visibility ON library_panel BEGIN SELECT RAISE(IGNORE); END;");
        assert_eq!(gde_modifier(&st, &alice, lib, json!({ "visibility": "private" })).await, 503, "aucune ligne écrite n'est pas un succès");
        assert_eq!(gde_lire_texte(&st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "shared");
        assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "le cache n'est pas invalidé");
        // CONTRÔLE POSITIF : déclencheur retiré, la même bascule est écrite.
        gde_ecrire(&st, "DROP TRIGGER gde_ignore;");
        assert_eq!(gde_modifier(&st, &alice, lib, json!({ "visibility": "private" })).await, 204);
        assert_eq!(gde_lire_texte(&st, &format!("SELECT visibility FROM library_panel WHERE id={lib}")), "private");
    }

    /// MUTATIONS QUI LE FONT ROUGIR : T8_DEL_LET (204), T8_DETACH_NON_ANNULE (référent détaché), T8_OK0 (voie IGNORE).
    #[tokio::test]
    async fn gde_une_suppression_de_definition_refusee_rend_503_nomme_et_laisse_les_referents_rattaches() {
        let (st, _tmp) = sp_state("gde-del");
        let alice = sp_au("alice", "editor");
        let (lib, pid) = gde_definition_referencee(&st).await;
        for (voie, declencheur) in [
            ("abort", "CREATE TRIGGER gde_refus BEFORE DELETE ON library_panel BEGIN SELECT RAISE(ABORT,'refus de témoin'); END;"),
            ("ignore", "CREATE TRIGGER gde_refus BEFORE DELETE ON library_panel BEGIN SELECT RAISE(IGNORE); END;"),
            // Le DÉTACHEMENT refusé : la suppression ne doit pas passer en laissant un `library_panel_id` orphelin.
            ("détachement", "CREATE TRIGGER gde_refus BEFORE UPDATE OF library_panel_id ON panel BEGIN SELECT RAISE(ABORT,'refus de témoin'); END;"),
        ] {
            gde_ecrire(&st, declencheur);
            let (code, v) = gde_corps(library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lib)).await).await;
            assert_eq!(code, 503, "({voie}) une suppression refusée n'est pas un succès : {v}");
            let cause = v["error"].as_str().unwrap_or("");
            assert!(cause.starts_with(crate::handlers::dash_ergonomics::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME), "({voie}) le refus nomme sa cause : {v}");
            assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 1, "({voie}) la définition existe toujours");
            assert_eq!(
                gde_compte(&st, &format!("SELECT COALESCE(library_panel_id,0) FROM panel WHERE id={pid}")), lib,
                "({voie}) le référent reste rattaché : le détachement est annulé avec la suppression"
            );
            gde_ecrire(&st, "DROP TRIGGER gde_refus;");
        }
        // CONTRÔLE POSITIF.
        let r = library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lib)).await;
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 0);
        assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={pid} AND library_panel_id IS NULL")), 1, "le référent est détaché, pas perdu");
    }

    /// MUTATIONS QUI LE FONT ROUGIR : T8_SNAP_LET (204), T8_OK0 (voie IGNORE).
    #[tokio::test]
    async fn gde_une_revocation_d_instantane_refusee_rend_503_nomme_et_l_instantane_reste_servi() {
        let (st, _tmp) = sp_state("gde-snap");
        let alice = sp_au("alice", "editor");
        let sid = gde_instantane_d_alice(&st);
        assert_eq!(gde_lire_instantane(&st).await, 200, "fixture : l'instantané est servi par son jeton");
        for (voie, corps) in [("abort", "SELECT RAISE(ABORT,'refus de témoin');"), ("ignore", "SELECT RAISE(IGNORE);")] {
            gde_ecrire(&st, &format!("CREATE TRIGGER gde_refus BEFORE DELETE ON dashboard_snapshot BEGIN {corps} END;"));
            let (code, v) = gde_corps(snapshot_delete(State(st.clone()), Extension(alice.clone()), Path(sid)).await).await;
            assert_eq!(code, 503, "({voie}) une révocation refusée n'est pas un succès : {v}");
            assert!(v["error"].as_str().unwrap_or("").starts_with(crate::handlers::dash_ergonomics::CAUSE_INSTANTANE_NON_SUPPRIME), "({voie}) cause nommée : {v}");
            assert_eq!(gde_lire_instantane(&st).await, 200, "({voie}) l'instantané reste lisible, et la réponse l'a dit");
            gde_ecrire(&st, "DROP TRIGGER gde_refus;");
        }
        // CONTRÔLE POSITIF.
        assert_eq!(snapshot_delete(State(st.clone()), Extension(alice.clone()), Path(sid)).await.status().as_u16(), 204);
        assert_eq!(gde_lire_instantane(&st).await, 404, "révoqué : plus servi");
    }

    /// CHAQUE écriture de la modification, refusée seule (`Err`) ou sans effet (`Ok(0)`), annule TOUTES les autres :
    /// 503, la ligne entière comme avant, le cache des référents intact. MUTATIONS QUI LE FONT ROUGIR : T8C_BOUCLE,
    /// T8C_SOQL, T8C_UPDATED.
    #[tokio::test]
    async fn gde_chaque_ecriture_de_la_modification_refusee_rend_503_et_n_ecrit_rien() {
        let (st, _tmp) = sp_state("gde-upd-colonnes");
        let alice = sp_au("alice", "editor");
        let (lib, pid) = gde_definition_referencee(&st).await;
        gde_ecrire(&st, &format!("UPDATE library_panel SET updated=1, viz='table', drill='avant' WHERE id={lib};"));
        let ligne = format!(
            "SELECT name||'|'||title||'|'||query||'|'||is_soql||'|'||viz||'|'||drill||'|'||visibility||'|'||COALESCE(updated,0) FROM library_panel WHERE id={lib}"
        );
        let avant = gde_lire_texte(&st, &ligne);
        let corps =
            json!({ "name": "n2", "title": "t2", "query": "search source=dns | table message", "viz": "bar", "drill": "d2", "is_soql": true, "visibility": "private" });
        let mut manquent: Vec<String> = Vec::new();
        for col in ["name", "title", "query", "viz", "drill", "is_soql", "visibility", "updated"] {
            for (voie, action) in [("abort", "SELECT RAISE(ABORT,'refus de témoin');"), ("ignore", "SELECT RAISE(IGNORE);")] {
                gde_ecrire(&st, &format!("CREATE TRIGGER gde_refus BEFORE UPDATE OF {col} ON library_panel BEGIN {action} END;"));
                let code = gde_modifier(&st, &alice, lib, corps.clone()).await;
                let apres = gde_lire_texte(&st, &ligne);
                let cache = gde_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}"));
                gde_ecrire(&st, "DROP TRIGGER gde_refus;");
                if code != 503 || apres != avant || cache != 1 {
                    manquent.push(format!("{col} ({voie}) : code {code}, ligne `{apres}` (attendu `{avant}`), cache {cache}"));
                }
            }
        }
        assert!(manquent.is_empty(), "écritures de la modification dont le refus n'a pas tout annulé : {manquent:#?}");
        // CONTRÔLE POSITIF : aucun déclencheur, toute la ligne est écrite.
        assert_eq!(gde_modifier(&st, &alice, lib, corps).await, 204);
        let ecrite = gde_lire_texte(&st, &ligne);
        assert!(ecrite.starts_with("n2|t2|search source=dns | table message|1|bar|d2|private|"), "ligne écrite : {ecrite}");
        assert_ne!(gde_compte(&st, &format!("SELECT updated FROM library_panel WHERE id={lib}")), 1, "l'horodatage est écrit");
    }

    fn gde_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn gde_refuser_le_begin(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn gde_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Un `BEGIN` refusé, puis un `COMMIT` refusé, sur la modification et sur la suppression : 503 chaque fois, la
    /// transaction refermée, rien d'écrit. MUTATIONS QUI LE FONT ROUGIR : T8C_BEGIN_UPD, T8C_COMMIT_UPD,
    /// T8C_BEGIN_DEL, T8C_COMMIT_DEL.
    #[tokio::test]
    async fn gde_un_begin_ou_un_commit_refuse_rend_503_et_n_ecrit_rien() {
        let (st, _tmp) = sp_state("gde-txn");
        let alice = sp_au("alice", "editor");
        let (lib, pid) = gde_definition_referencee(&st).await;
        for (voie, refuser) in [("BEGIN", gde_refuser_le_begin as fn(&AppState)), ("COMMIT", gde_refuser_le_commit as fn(&AppState))] {
            refuser(&st);
            let code = gde_modifier(&st, &alice, lib, json!({ "title": "apres", "visibility": "private" })).await;
            let fermee = st.db.lock().is_autocommit();
            gde_lever(&st);
            assert_eq!(code, 503, "({voie} refusé) la modification n'est pas un succès");
            assert!(fermee, "({voie} refusé) la transaction de la modification est refermée");
            assert_eq!(gde_lire_texte(&st, &format!("SELECT title||'|'||visibility FROM library_panel WHERE id={lib}")), "avant|shared", "({voie}) rien d'écrit");
            assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")), 1, "({voie}) cache intact");

            refuser(&st);
            let r = library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lib)).await;
            let fermee = st.db.lock().is_autocommit();
            gde_lever(&st);
            let (code, v) = gde_corps(r).await;
            assert_eq!(code, 503, "({voie} refusé) la suppression n'est pas un succès : {v}");
            assert!(fermee, "({voie} refusé) la transaction de la suppression est refermée");
            let cause = v["error"].as_str().unwrap_or("");
            let attendue = if voie == "BEGIN" {
                crate::handlers::dash_ergonomics::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE
            } else {
                crate::handlers::dash_ergonomics::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_NON_SUPPRIME
            };
            assert!(cause.starts_with(attendue), "({voie} refusé) le refus nomme sa cause : {v}");
            assert_eq!(gde_compte(&st, &format!("SELECT COUNT(*) FROM library_panel WHERE id={lib}")), 1, "({voie}) la définition existe toujours");
            assert_eq!(gde_compte(&st, &format!("SELECT COALESCE(library_panel_id,0) FROM panel WHERE id={pid}")), lib, "({voie}) le référent reste rattaché");
        }
        // CONTRÔLE POSITIF : autorisateur levé, les deux routes passent.
        assert_eq!(gde_modifier(&st, &alice, lib, json!({ "title": "apres" })).await, 204);
        assert_eq!(library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lib)).await.status().as_u16(), 204);
    }

    /// Les contrôles d'accès passent AVANT toute écriture : un éditeur non propriétaire garde son 403 et une
    /// ligne absente son 404, déclencheurs posés ou non.
    #[tokio::test]
    async fn gde_un_editeur_non_proprietaire_garde_son_403_et_l_absent_son_404() {
        let (st, _tmp) = sp_state("gde-acces");
        let alice = sp_au("alice", "editor");
        let bob = sp_au("bob", "editor");
        let (lib, _pid) = gde_definition_referencee(&st).await;
        assert_eq!(gde_modifier(&st, &alice, lib, json!({ "visibility": "private" })).await, 204, "fixture : privée d'alice");
        let sid = gde_instantane_d_alice(&st);
        gde_ecrire(
            &st,
            "CREATE TRIGGER gde_a BEFORE DELETE ON library_panel BEGIN SELECT RAISE(ABORT,'x'); END; \
             CREATE TRIGGER gde_b BEFORE UPDATE ON library_panel BEGIN SELECT RAISE(ABORT,'x'); END; \
             CREATE TRIGGER gde_c BEFORE DELETE ON dashboard_snapshot BEGIN SELECT RAISE(ABORT,'x'); END;",
        );
        assert_eq!(gde_modifier(&st, &bob, lib, json!({ "visibility": "shared" })).await, 403);
        assert_eq!(library_panel_delete(State(st.clone()), Extension(bob.clone()), Path(lib)).await.status().as_u16(), 403);
        assert_eq!(snapshot_delete(State(st.clone()), Extension(bob.clone()), Path(sid)).await.status().as_u16(), 403);
        assert_eq!(gde_modifier(&st, &alice, 999_999, json!({ "visibility": "shared" })).await, 404);
        assert_eq!(library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(999_999)).await.status().as_u16(), 404);
        assert_eq!(snapshot_delete(State(st.clone()), Extension(alice.clone()), Path(999_999)).await.status().as_u16(), 404);
    }
}
