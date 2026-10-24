// =====================================================================================
// `P10.34-g` (ingestion : un panic après le `BEGIN` laissait la transaction du lot ouverte ; voisin : un `UPDATE
// connector` qui ne touche aucune ligne passait pour un succès), `P10.20-l` (tranche AJ : `connector_update`,
// `connector_test`, `connector_poll` servaient une lecture ratée en 404) et `P10.29-l` (tranche AJ : création,
// modification et suppression d'un connecteur servaient le texte du moteur dans leur 500).
//
// LE DÉFAUT `P10.34-g`, RE-MESURÉ SUR 8639270b. `ingest_events_batch_env` (daemon/src/ingest/mod.rs) et
// `ingest_journal_lines`, que la clé ne citait pas, ouvraient leur transaction par `ouvrir_sa_transaction` et n'écrivaient
// leur `ROLLBACK` qu'aux chemins `Err` (`INSERT` refusé, `COMMIT` refusé) : un panic entre le `BEGIN` et la fin laissait
// l'écrivain partagé dans la transaction du lot. Le garde `TransactionDuLot` (local au module, `Drop` = `ROLLBACK` tant
// qu'il n'est pas consommé par `valider`) est posé après le `BEGIN` réussi ; les `ROLLBACK` manuels sont devenus son
// `Drop`, et le `COMMIT` nu de la voie journald passe par `valider_la_transaction` comme celui de la voie événements.
// `ecrire_l_etat_du_passage` (handlers/connectors/mod.rs) prenait `Ok(_)` pour un succès : un connecteur supprimé pendant
// le passage rendait `Ok(0)` sans un mot.
//
// CE QUE CES TÉMOINS TIENNENT :
//   - par récepteur de métriques (Prometheus texte, remote_write) : un panic injecté après la première écriture du lot
//     laisse l'écrivain en autocommit, sans cette écriture, et le lot suivant s'écrit ;
//   - renouvellement de la clé de livraison, trace refusée : 500, exactement la phrase nommée et l'identifiant, la
//     cause du moteur au journal seul sous cet identifiant, la clé inchangée ;
//   - par voie (événements, journald), au point d'entrée que le spool et les récepteurs appellent : un panic injecté
//     APRÈS la première écriture du lot (crochet `point_de_course`, sous `cfg(test)` seulement) est capturé, l'écrivain
//     est revenu en autocommit, la première écriture n'est pas restée, et un lot suivant s'écrit ; un `INSERT` refusé
//     (déclencheur) rend `Annule(1)` et un `COMMIT` refusé (autorisateur) `Annule(2)`, l'écrivain libre, rien d'écrit ;
//     le nominal rend `Ok(2)` ;
//   - zéro ligne : le crochet du planificateur supprime le connecteur avant son passage ; UNE ligne fixe
//     `[connecteurs] WARN connecteur #1 : type non supporté, état non écrit (connecteur disparu)`, comparée en entier ;
//     le passage nominal n'en écrit aucune ;
//   - `connector_update`, `connector_test`, `connector_poll` : absent = `404 {"error": "connecteur introuvable"}` à
//     l'octet ; lecture ratée (table retirée pour la modification, secret en BLOB pour l'essai et le poll : la ligne
//     existe, sa lecture échoue) = 503 nommé en entier (exactement `error` et `id`), sans la cause du moteur ; rien
//     n'est écrit ni collecté (nom, `last_run`, `last_error` d'avant ; aucune trace) ; lu = 200 ;
//   - création, modification, suppression avec la trace d'audit refusée (déclencheur sur `ledger`) : 500, exactement
//     `PHRASE_ECHEC_TRANSACTION_AUDIT` et l'identifiant, sans le texte du moteur ; rien n'a changé ;
//   - lignes de journal (sous-processus), en entier : une par lecture ratée (identifiant servi, cause du moteur), une
//     par trace refusée (`servir_l_echec_de_la_transaction_d_audit`), jamais le nom du connecteur, son URL ni son secret.
//
// MUTANTS JOUÉS (variable de mutation, retirés avant le commit) : AJ1_LOT_SANS_GARDE, AJ1_JOURNAL_SANS_GARDE,
// AJ1_JOURNAL_COMMIT_SANS_ANNULATION, AJ1_ZERO_LIGNE_MUET, AJ1_ZERO_LIGNE_PARTOUT, AJ1_MAJ_LECTURE_EN_404,
// AJ1_MAJ_ABSENT_EN_503, AJ1_MAJ_SANS_JOURNAL, AJ1_ESSAI_LECTURE_EN_404, AJ1_ESSAI_ABSENT_EN_503, AJ1_ESSAI_SANS_JOURNAL,
// AJ1_POLL_LECTURE_EN_404, AJ1_POLL_ABSENT_EN_503, AJ1_POLL_SANS_JOURNAL, AJ1_CREATION_MOTEUR_SERVI, AJ1_MAJ_MOTEUR_SERVI,
// AJ1_SUPPR_MOTEUR_SERVI. Correction après vérification (mêmes règles) : AJ1_PROM_SANS_GARDE, AJ1_WRITE_SANS_GARDE (les
// lots des récepteurs de métriques, `metrics_prom` et `metrics_write`, ingest/obs.rs, qui ouvrent aussi leur propre
// transaction : garde désarmé, transaction pendante après un panic), AJ1_CLE_MOTEUR_SERVI et AJ1_CLE_SANS_JOURNAL (le
// 500 d'une écriture refusée du renouvellement de la clé de livraison joignait « Refus de la base : <texte du moteur> »),
// AJ1_MAJ_LECTURE_IGNOREE (la lecture d'existence ratée laissée passer : la modification écrit).
//
// CE QU'ILS NE TIENNENT PAS : l'écran n'est pas joué (web/ hors périmètre : la console peint ces 503 par la forme
// partagée, `refus_nomme` pour la modification et le poll, `essai_refuse` pour l'essai, web/core.js) ; un `ROLLBACK` du
// garde lui-même refusé n'est pas joué (le garde ne le dit pas, comme `Txn`) ; un garde consommé par `valider` qui
// annulerait encore serait un mutant ÉQUIVALENT (le `Drop` suit immédiatement le `COMMIT` dans `valider`, sur un
// écrivain revenu en autocommit : rien à annuler).
// =====================================================================================
mod transaction_du_lot_annulee_et_connecteurs_lus_en_trois_issues {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const AJ1_ENFANT: &str = "PLUME_TEMOIN_AJ1_ENFANT";
    const AJ1_PHASE: &str = "AJ1-PHASE:";
    const AJ1_REFUS_DU_LOT: &str = "aj1 lot refuse";
    const AJ1_REGISTRE_REFUSE: &str = "aj1 registre hors d atteinte";
    const AJ1_MOTEUR_BLOB: &str = "Invalid column type Blob at index: 2, name: secret";
    const AJ1_MOTEUR_TABLE: &str = "no such table: connector";
    const AJ1_ABSENT: i64 = 987_654;
    const AJ1_NOM: &str = "aj1-connecteur-nomme";
    const AJ1_SECRET: &str = "aj1-valeur-du-secret";
    const AJ1_HOTE: &str = "203.0.113.31";
    const AJ1_TYPE_INCONNU: &str = "aj1-type-inconnu";

    // ---- ingestion (`P10.34-g`) ----

    const AJ1_VOIES: [&str; 2] = ["evenements", "journald"];

    fn aj1_cle_du_crochet(voie: &str, p: &str) -> String {
        if voie == "evenements" { format!("lot-d-evenements:{p}") } else { format!("lot-journald:{p}") }
    }

    /// Le lot `messages`, par le point d'entrée de la voie ; rend le compte traité, ou l'issue du lot non écrit.
    fn aj1_ingerer(conn: &Connection, p: &str, voie: &str, messages: &[&str]) -> Result<usize, crate::ingest::LotNonEcrit> {
        let ts = now();
        if voie == "evenements" {
            let evs: Vec<Value> = messages.iter().map(|m| json!({ "source": "aj1", "message": m, "dedup": m, "ts": ts })).collect();
            crate::ingest::ingest_events_batch_env(conn, p, &evs, ts, None, None, None).map(|(n, _)| n)
        } else {
            let lignes: Vec<String> = messages
                .iter()
                .map(|m| json!({ "MESSAGE": m, "__CURSOR": m, "_COMM": "aj1", "__REALTIME_TIMESTAMP": format!("{}", ts * 1_000_000) }).to_string())
                .collect();
            crate::ingest::ingest_journal_lines(conn, p, &lignes.join("\n"), None)
        }
    }

    fn aj1_evenements(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM event WHERE message LIKE 'aj1-%'", [], |r| r.get(0)).expect("événements lisibles")
    }

    /// CE QU'IL TIENT : par voie, un panic après la première écriture du lot laisse l'écrivain en autocommit, sans
    /// cette écriture, et le lot suivant s'écrit (`Ok(2)`).
    /// MUTATIONS : AJ1_LOT_SANS_GARDE (événements : transaction pendante), AJ1_JOURNAL_SANS_GARDE (journald : idem).
    #[test]
    fn aj1_un_panic_apres_une_ecriture_du_lot_annule_sa_transaction() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'ingestion lit l'environnement (extracteur, processeurs)
        assert!(AJ1_VOIES.len() >= 2, "plancher : deux voies");
        for voie in AJ1_VOIES {
            let (st, p) = sp_state(&format!("aj1-panic-{voie}"));
            crate::handlers::transaction_validee::poser_un_crochet_de_course(&aj1_cle_du_crochet(voie, &p), || {
                panic!("aj1 panic de temoin dans le lot")
            });
            let conn = st.db.lock();
            let issue = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| aj1_ingerer(&conn, &p, voie, &["aj1-a", "aj1-b"])));
            let libre = conn.is_autocommit();
            if !libre {
                conn.execute_batch("ROLLBACK").expect("fixture : la transaction laissée est fermée");
            }
            assert!(issue.is_err(), "{voie} : contrôle, le crochet a paniqué après la première écriture");
            assert!(libre, "{voie} : la transaction du lot est annulée au déroulage du panic");
            assert_eq!(aj1_evenements(&conn), 0, "{voie} : la première écriture du lot n'est pas restée");
            assert_eq!(aj1_ingerer(&conn, &p, voie, &["aj1-c", "aj1-d"]), Ok(2), "{voie} : le lot suivant s'écrit");
            assert_eq!(aj1_evenements(&conn), 2, "{voie} : et il est validé");
            assert!(conn.is_autocommit(), "{voie} : écrivain libre après le lot suivant");
        }
    }

    /// CE QU'IL TIENT : par voie, un `INSERT` refusé au second événement rend `Annule(1)` et un `COMMIT` refusé
    /// `Annule(2)` : l'écrivain est libre, rien n'est écrit ; le refus levé, le même lot s'écrit.
    /// MUTATIONS : AJ1_LOT_SANS_GARDE et AJ1_JOURNAL_SANS_GARDE (`INSERT` refusé : transaction pendante),
    /// AJ1_JOURNAL_COMMIT_SANS_ANNULATION (`COMMIT` refusé de la voie journald : transaction pendante).
    #[test]
    fn aj1_une_ecriture_ou_un_commit_refuse_annule_la_transaction_du_lot() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'ingestion lit l'environnement (extracteur, processeurs)
        assert!(AJ1_VOIES.len() >= 2, "plancher : deux voies");
        for voie in AJ1_VOIES {
            let (st, p) = sp_state(&format!("aj1-refus-{voie}"));
            let conn = st.db.lock();
            conn.execute_batch(&format!(
                "CREATE TRIGGER aj1_refus BEFORE INSERT ON event WHEN NEW.message='aj1-refus' BEGIN SELECT RAISE(ABORT, '{AJ1_REFUS_DU_LOT}'); END;"
            ))
            .expect("fixture : déclencheur");
            let issue = aj1_ingerer(&conn, &p, voie, &["aj1-a", "aj1-refus"]);
            let libre = conn.is_autocommit();
            if !libre {
                conn.execute_batch("ROLLBACK").expect("fixture : la transaction laissée est fermée");
            }
            assert_eq!(issue, Err(crate::ingest::LotNonEcrit::Annule(1)), "{voie} : INSERT refusé, lot annulé après un événement");
            assert!(libre, "{voie} : INSERT refusé, la transaction du lot est annulée");
            assert_eq!(aj1_evenements(&conn), 0, "{voie} : INSERT refusé, rien n'est écrit");
            conn.execute_batch("DROP TRIGGER aj1_refus").expect("fixture : déclencheur retiré");

            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny, // COMMIT (rusqlite le range sous `Unknown`),
                _ => Authorization::Allow,
            }));
            let issue = aj1_ingerer(&conn, &p, voie, &["aj1-a", "aj1-b"]);
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let libre = conn.is_autocommit();
            if !libre {
                conn.execute_batch("ROLLBACK").expect("fixture : la transaction laissée est fermée");
            }
            assert_eq!(issue, Err(crate::ingest::LotNonEcrit::Annule(2)), "{voie} : COMMIT refusé, lot annulé après deux événements");
            assert!(libre, "{voie} : COMMIT refusé, la transaction du lot est annulée");
            assert_eq!(aj1_evenements(&conn), 0, "{voie} : COMMIT refusé, rien n'est écrit");

            assert_eq!(aj1_ingerer(&conn, &p, voie, &["aj1-a", "aj1-b"]), Ok(2), "{voie} : contrôle, le lot s'écrit");
            assert_eq!(aj1_evenements(&conn), 2, "{voie} : contrôle, validé");
        }
    }

    // ---- connecteurs (`P10.20-l`, `P10.29-l`, zéro ligne de `P10.34-g`) ----

    fn aj1_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    /// Le connecteur n°1, d'un type que le démon ne sait pas interroger (aucune requête ne part), dû au planificateur.
    fn aj1_base_du_connecteur(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(tag);
        st.db
            .lock()
            .execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id,last_run,last_ok,last_count) \
                 VALUES(1,?1,?2,1,?3,?4,300,'prod',NULL,111,7)",
                params![AJ1_TYPE_INCONNU, AJ1_NOM, json!({ "url": format!("https://{AJ1_HOTE}/x") }).to_string(), AJ1_SECRET],
            )
            .expect("fixture : connecteur");
        (st, p)
    }

    fn aj1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn aj1_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    type Aj1Etat = (String, Option<i64>, Option<String>);

    fn aj1_etat(st: &AppState, table: &str) -> Aj1Etat {
        st.db
            .lock()
            .query_row(&format!("SELECT name,last_run,last_error FROM {table} WHERE id=1"), [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("état du connecteur lisible")
    }

    fn aj1_etat_d_avant() -> Aj1Etat {
        (AJ1_NOM.to_string(), None, None)
    }

    async fn aj1_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement `error` et `id`, la phrase attendue, l'identifiant de corrélation, aucune
    /// trace de la cause du moteur.
    fn aj1_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        for moteur in ["Blob", "no such table", "not authorized", "Refus de la base", AJ1_REFUS_DU_LOT, AJ1_REGISTRE_REFUSE] {
            assert!(!corps.contains(moteur), "{quoi} : la cause du moteur ne sort pas : {corps}");
        }
    }

    fn aj1_absent(quoi: &str, (statut, corps, v): &(u16, String, Value)) {
        assert_eq!(*statut, 404, "{quoi} : l'absence établie reste un 404 : {corps}");
        assert_eq!(*v, json!({ "error": "connecteur introuvable" }), "{quoi} : l'absence, rien d'autre : {corps}");
    }

    async fn aj1_modifier(st: &AppState, id: i64) -> (u16, String, Value) {
        aj1_reponse(connector_update(State(st.clone()), Extension(aj1_adm()), Path(id), Json(json!({ "name": "aj1-renomme" }))).await).await
    }

    async fn aj1_essayer(st: &AppState, id: i64) -> (u16, String, Value) {
        aj1_reponse(connector_test(State(st.clone()), Extension(aj1_adm()), Path(id)).await).await
    }

    async fn aj1_collecter(st: &AppState, id: i64) -> (u16, String, Value) {
        aj1_reponse(connector_poll(State(st.clone()), Extension(aj1_adm()), Path(id)).await).await
    }

    async fn aj1_creer(st: &AppState) -> (u16, String, Value) {
        let corps = json!({
            "type": "http_pull", "name": AJ1_NOM, "secret": AJ1_SECRET,
            "config": { "url": format!("https://{AJ1_HOTE}/api"), "records_path": "items", "field_map": { "id": "id" } },
        });
        aj1_reponse(connector_create(State(st.clone()), Extension(aj1_adm()), Json(corps)).await).await
    }

    async fn aj1_supprimer(st: &AppState, id: i64) -> (u16, String, Value) {
        aj1_reponse(connector_delete(State(st.clone()), Extension(aj1_adm()), Path(id)).await).await
    }

    fn aj1_secret_illisible(st: &AppState) {
        aj1_sql(st, "UPDATE connector SET secret=X'00' WHERE id=1");
    }

    fn aj1_registre_refuse(st: &AppState) {
        aj1_sql(st, &format!("CREATE TRIGGER aj1_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AJ1_REGISTRE_REFUSE}'); END;"));
    }

    /// CE QU'IL TIENT (modification) : absent, 404 à l'octet ; lecture d'existence refusée (autorisateur À ÉTAT : la
    /// PREMIÈRE lecture de `connector` est refusée, les suivantes passent, donc une modification qui continuerait
    /// ÉCRIRAIT), rien n'est écrit (nom d'avant, aucune trace), transaction fermée, puis 503
    /// `CAUSE_CONNECTEUR_INCHANGE_NON_LU` en entier ; contrôle : lu, 200 et renommé.
    /// MUTATIONS : AJ1_MAJ_LECTURE_EN_404 (la forme d'avant), AJ1_MAJ_ABSENT_EN_503, AJ1_MAJ_LECTURE_IGNOREE (la lecture
    /// ratée laissée passer : la modification écrit, « rien n'est écrit » rougit avant le 503).
    #[tokio::test]
    async fn aj1_modification_d_un_connecteur_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = aj1_base_du_connecteur("aj1-maj");
        aj1_absent("modification d'un absent", &aj1_modifier(&st, AJ1_ABSENT).await);

        let refusee = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let premiere = refusee.clone();
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "connector", .. } if !premiere.swap(true, std::sync::atomic::Ordering::SeqCst) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = aj1_modifier(&st, 1).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(refusee.load(std::sync::atomic::Ordering::SeqCst), "contrôle : la lecture d'existence a été refusée");
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");
        assert_eq!(aj1_etat(&st, "connector"), aj1_etat_d_avant(), "rien n'est écrit");
        assert_eq!(aj1_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.update'"), 0, "aucune modification attestée");
        aj1_juger_5xx("modification, lecture d'existence refusée", &r, 503, CAUSE_CONNECTEUR_INCHANGE_NON_LU);

        let (statut, corps, v) = aj1_modifier(&st, 1).await;
        assert_eq!((statut, v), (200, json!({ "ok": true })), "contrôle : un connecteur lisible se modifie : {corps}");
        assert_eq!(aj1_etat(&st, "connector").0, "aj1-renomme", "contrôle : renommé");
    }

    /// CE QU'IL TIENT (essai) : absent, 404 à l'octet ; secret en BLOB (la ligne existe), 503
    /// `CAUSE_ESSAI_DU_CONNECTEUR_NON_FAIT_NON_LU` en entier ; contrôle : lu, 200 et le corps d'essai d'un type inconnu.
    /// MUTATIONS : AJ1_ESSAI_LECTURE_EN_404 (la forme d'avant), AJ1_ESSAI_ABSENT_EN_503.
    #[tokio::test]
    async fn aj1_essai_d_un_connecteur_lecture_ratee_jamais_404() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = aj1_base_du_connecteur("aj1-essai");
        aj1_absent("essai d'un absent", &aj1_essayer(&st, AJ1_ABSENT).await);
        let (statut, corps, v) = aj1_essayer(&st, 1).await;
        assert_eq!(
            (statut, v),
            (200, json!({ "ok": false, "sample_count": 0, "error": format!("type non supporté : {AJ1_TYPE_INCONNU}") })),
            "contrôle : un connecteur lisible s'essaie : {corps}"
        );
        aj1_secret_illisible(&st);
        let r = aj1_essayer(&st, 1).await;
        aj1_juger_5xx("essai, secret illisible", &r, 503, CAUSE_ESSAI_DU_CONNECTEUR_NON_FAIT_NON_LU);
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");
    }

    /// CE QU'IL TIENT (poll manuel) : absent, 404 à l'octet ; secret en BLOB, 503 `CAUSE_POLL_DU_CONNECTEUR_NON_FAIT_NON_LU`
    /// en entier, rien n'est collecté ni écrit (`last_run`, `last_error` d'avant), aucune trace de poll ; contrôle : lu,
    /// 200, l'état du passage écrit et la trace posée.
    /// MUTATIONS : AJ1_POLL_LECTURE_EN_404 (la forme d'avant), AJ1_POLL_ABSENT_EN_503.
    #[tokio::test]
    async fn aj1_poll_d_un_connecteur_lecture_ratee_jamais_404_et_rien_n_est_collecte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = aj1_base_du_connecteur("aj1-poll");
        aj1_absent("poll d'un absent", &aj1_collecter(&st, AJ1_ABSENT).await);
        aj1_secret_illisible(&st);
        let r = aj1_collecter(&st, 1).await;
        aj1_juger_5xx("poll, secret illisible", &r, 503, CAUSE_POLL_DU_CONNECTEUR_NON_FAIT_NON_LU);
        assert!(st.db.lock().is_autocommit(), "aucune transaction pendante");
        assert_eq!(aj1_etat(&st, "connector"), aj1_etat_d_avant(), "rien n'est collecté ni écrit");
        assert_eq!(aj1_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.poll'"), 0, "aucune trace de poll");

        aj1_sql(&st, &format!("UPDATE connector SET secret='{AJ1_SECRET}' WHERE id=1"));
        let (statut, corps, v) = aj1_collecter(&st, 1).await;
        let erreur = format!("type de connecteur non supporté : {AJ1_TYPE_INCONNU}");
        assert_eq!((statut, v), (200, json!({ "ok": false, "count": 7, "error": erreur })), "contrôle : un connecteur lisible se collecte : {corps}");
        let (_, last_run, last_error) = aj1_etat(&st, "connector");
        assert!(last_run.is_some() && last_error.as_deref() == Some(erreur.as_str()), "contrôle : l'état du passage est écrit");
        assert_eq!(aj1_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.poll'"), 1, "contrôle : la trace est posée");
    }

    /// CE QU'IL TIENT : la trace d'audit refusée (déclencheur sur `ledger`), création, modification et suppression
    /// rendent 500 `PHRASE_ECHEC_TRANSACTION_AUDIT` et l'identifiant, en entier, sans le texte du moteur ; aucun
    /// connecteur de plus, le connecteur garde son nom et reste présent, transaction fermée.
    /// MUTATIONS : AJ1_CREATION_MOTEUR_SERVI, AJ1_MAJ_MOTEUR_SERVI, AJ1_SUPPR_MOTEUR_SERVI (la forme d'avant).
    #[tokio::test]
    async fn aj1_trace_d_audit_refusee_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = aj1_base_du_connecteur("aj1-ecritures");
        aj1_registre_refuse(&st);
        let cas = [
            ("création d'un connecteur", aj1_creer(&st).await),
            ("modification d'un connecteur", aj1_modifier(&st, 1).await),
            ("suppression d'un connecteur", aj1_supprimer(&st, 1).await),
        ];
        assert!(cas.len() >= 3, "plancher : les trois sites");
        for (quoi, r) in &cas {
            aj1_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
        }
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        aj1_sql(&st, "DROP TRIGGER aj1_ledger_refuse;");
        assert_eq!(aj1_compte(&st, "SELECT COUNT(*) FROM connector"), 1, "aucun connecteur de plus, aucun de moins");
        assert_eq!(aj1_etat(&st, "connector"), aj1_etat_d_avant(), "le connecteur garde son nom");
    }

    // ---- récepteurs de métriques (`P10.34-g`, correction : les deux autres lots qui ouvrent leur transaction) ----

    #[derive(prost::Message)]
    struct Aj1Ecriture {
        #[prost(message, repeated, tag = "1")]
        timeseries: Vec<Aj1Serie>,
    }
    #[derive(prost::Message)]
    struct Aj1Serie {
        #[prost(message, repeated, tag = "1")]
        labels: Vec<Aj1Etiquette>,
        #[prost(message, repeated, tag = "2")]
        samples: Vec<Aj1Point>,
    }
    #[derive(prost::Message)]
    struct Aj1Etiquette {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(string, tag = "2")]
        value: String,
    }
    #[derive(prost::Message)]
    struct Aj1Point {
        #[prost(double, tag = "1")]
        value: f64,
        #[prost(int64, tag = "2")]
        timestamp: i64,
    }

    /// Un lot remote_write d'UNE série à deux points (protobuf + snappy, la forme d'Alloy/Prometheus).
    fn aj1_lot_remote_write(nom: &str) -> axum::body::Bytes {
        use prost::Message;
        let ms = now() * 1000;
        let lot = Aj1Ecriture {
            timeseries: vec![Aj1Serie {
                labels: vec![Aj1Etiquette { name: "__name__".into(), value: nom.into() }],
                samples: vec![Aj1Point { value: 1.0, timestamp: ms }, Aj1Point { value: 2.0, timestamp: ms + 1000 }],
            }],
        };
        let mut brut = Vec::new();
        lot.encode(&mut brut).expect("fixture : encodage protobuf");
        axum::body::Bytes::from(snap::raw::Encoder::new().compress_vec(&brut).expect("fixture : snappy"))
    }

    /// Le lot de deux points de la métrique `nom` envoyé au récepteur, dans une tâche (un panic y est capturé par
    /// `JoinHandle`) ; rend `None` si la tâche a paniqué, sinon le statut.
    async fn aj1_envoyer_les_metriques(st: &AppState, recepteur: &str, nom: &str) -> Option<u16> {
        let (st, nom) = (st.clone(), nom.to_string());
        let tache = if recepteur == "prometheus" {
            tokio::spawn(async move { metrics_prom(State(st), Extension(aj1_adm()), Query(HashMap::new()), format!("{nom} 1\n{nom}{{i=\"b\"}} 2\n")).await })
        } else {
            tokio::spawn(async move { metrics_write(State(st), Extension(aj1_adm()), aj1_lot_remote_write(&nom)).await })
        };
        tache.await.ok().map(|r| r.status().as_u16())
    }

    /// CE QU'IL TIENT : par récepteur de métriques (`metrics_prom`, `metrics_write`), un panic après la première
    /// écriture du lot laisse l'écrivain en autocommit, sans cette écriture ; le lot suivant s'écrit (200 / 204, deux
    /// points).
    /// MUTATIONS : AJ1_PROM_SANS_GARDE, AJ1_WRITE_SANS_GARDE (garde désarmé : transaction pendante).
    #[tokio::test]
    async fn aj1_un_panic_apres_une_ecriture_d_un_lot_de_metriques_annule_sa_transaction() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les récepteurs lisent l'environnement (résolution d'hôte)
        let recepteurs = [("prometheus", "lot-de-metriques-prometheus", 200u16), ("remote_write", "lot-remote-write", 204)];
        assert!(recepteurs.len() >= 2, "plancher : deux récepteurs");
        for (recepteur, crochet, nominal) in recepteurs {
            let (st, _p) = sp_state(&format!("aj1-metriques-{recepteur}"));
            let nom = format!("aj1_panic_{}", recepteur.replace('_', ""));
            let compte = || aj1_compte(&st, &format!("SELECT COUNT(*) FROM metric WHERE name='{nom}'"));
            crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("{crochet}:{nom}"), || panic!("aj1 panic de temoin dans le lot de metriques"));
            let issue = aj1_envoyer_les_metriques(&st, recepteur, &nom).await;
            let libre = st.db.lock().is_autocommit();
            if !libre {
                aj1_sql(&st, "ROLLBACK");
            }
            assert_eq!(issue, None, "{recepteur} : contrôle, le crochet a paniqué après la première écriture");
            assert!(libre, "{recepteur} : la transaction du lot est annulée au déroulage du panic");
            assert_eq!(compte(), 0, "{recepteur} : la première écriture du lot n'est pas restée");
            assert_eq!(aj1_envoyer_les_metriques(&st, recepteur, &nom).await, Some(nominal), "{recepteur} : le lot suivant s'écrit");
            assert_eq!(compte(), 2, "{recepteur} : et il est validé");
            assert!(st.db.lock().is_autocommit(), "{recepteur} : écrivain libre après le lot suivant");
        }
    }

    // ---- renouvellement de la clé de livraison (`P10.29-l`, correction : le 500 joignait le texte du moteur) ----

    /// Une source push Pub/Sub créée par la route réelle ; rend son identifiant.
    async fn aj1_source_push(st: &AppState) -> i64 {
        let corps = json!({ "preset_id": "gcp-audit", "name": "aj1-source-push", "env_id": "prod" });
        let (statut, texte, v) =
            aj1_reponse(connector_push_source(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(aj1_adm()), Json(corps)).await).await;
        assert_eq!(statut, 200, "fixture : source push : {texte}");
        v["connector_id"].as_i64().expect("fixture : identifiant de la source")
    }

    async fn aj1_renouveler(st: &AppState, id: i64) -> (u16, String, Value) {
        aj1_reponse(connector_delivery_key_rotate(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(aj1_adm()), Path(id)).await).await
    }

    /// CE QU'IL TIENT : la trace du renouvellement refusée (déclencheur sur `ledger`), 500
    /// `CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE` EN ENTIER (exactement `error` et `id`), sans « Refus de la
    /// base » ni le texte du moteur ; aucune clé montrée ; la clé de la source n'a pas changé ; contrôle : levé, 200.
    /// MUTATION : AJ1_CLE_MOTEUR_SERVI (la forme d'avant).
    #[tokio::test]
    async fn aj1_renouvellement_de_cle_ecriture_refusee_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le secret des gestes se lit dans l'environnement
        let (st, _p) = sp_state("aj1-cle");
        let id = aj1_source_push(&st).await;
        let empreinte = || aj1_compte(&st, &format!("SELECT COUNT(*) FROM token WHERE connector_id={id}"));
        let cle_avant: String = st.db.lock().query_row("SELECT token_hash FROM token WHERE connector_id=?1", params![id], |r| r.get(0)).expect("fixture : clé");
        assert_eq!(empreinte(), 1, "fixture : une clé de livraison");
        aj1_registre_refuse(&st);
        let r = aj1_renouveler(&st, id).await;
        aj1_juger_5xx("renouvellement de la clé de livraison", &r, 500, CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE);
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        aj1_sql(&st, "DROP TRIGGER aj1_ledger_refuse;");
        let cle_apres: String = st.db.lock().query_row("SELECT token_hash FROM token WHERE connector_id=?1", params![id], |r| r.get(0)).expect("clé relue");
        assert_eq!((empreinte(), cle_apres), (1, cle_avant), "la clé de la source n'a pas changé");
        let (statut, texte, _) = aj1_renouveler(&st, id).await;
        assert_eq!(statut, 200, "contrôle : levé, le renouvellement a lieu : {texte}");
    }

    fn aj1_phase(stderr: &str, nom: &str) -> Vec<String> {
        let debut = stderr.split_once(&format!("{AJ1_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
        let corps = debut.split_once(AJ1_PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.starts_with("[connecteurs] ") || l.contains("] [connecteurs] ")).map(str::to_string).collect()
    }

    async fn aj1_enfant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes et le passage lisent l'environnement
        eprintln!("{AJ1_PHASE}lecture-maj");
        let (st, _p) = aj1_base_du_connecteur("aj1-j-maj");
        aj1_sql(&st, "ALTER TABLE connector RENAME TO connector_aj1_retiree;");
        let r = aj1_modifier(&st, 1).await;
        println!("AJ1-MAJ:{}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

        eprintln!("{AJ1_PHASE}lecture-essai");
        let (st, _p) = aj1_base_du_connecteur("aj1-j-essai");
        aj1_secret_illisible(&st);
        let r = aj1_essayer(&st, 1).await;
        println!("AJ1-ESSAI:{}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

        eprintln!("{AJ1_PHASE}lecture-poll");
        let (st, _p) = aj1_base_du_connecteur("aj1-j-poll");
        aj1_secret_illisible(&st);
        let r = aj1_collecter(&st, 1).await;
        println!("AJ1-POLL:{}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

        eprintln!("{AJ1_PHASE}ecritures");
        let (st, _p) = aj1_base_du_connecteur("aj1-j-ecritures");
        aj1_registre_refuse(&st);
        let refus = [aj1_creer(&st).await, aj1_modifier(&st, 1).await, aj1_supprimer(&st, 1).await];
        let [a, b, c] = refus.each_ref().map(|r| format!("{}={}", r.0, r.2["id"].as_str().unwrap_or("")));
        println!("AJ1-ECRITURES:{a}:{b}:{c}");

        eprintln!("{AJ1_PHASE}cle");
        let (st, _p) = sp_state("aj1-j-cle");
        let source = aj1_source_push(&st).await;
        aj1_registre_refuse(&st);
        let r = aj1_renouveler(&st, source).await;
        println!("AJ1-CLE:{}:{}:{source}", r.0, r.2["id"].as_str().unwrap_or(""));

        eprintln!("{AJ1_PHASE}disparu");
        let (st, p) = aj1_base_du_connecteur("aj1-j-disparu");
        let ecrivain = st.db.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("passage-du-connecteur:{p}:1"), move || {
            ecrivain.lock().execute_batch("DELETE FROM connector WHERE id=1").expect("crochet : le connecteur est supprimé");
        });
        let bilan = run_due_connectors(&st.db, &p);
        println!("AJ1-DISPARU:{}", if bilan == crate::mesure_environnement::Mesure::Lue(0) { "lue0" } else { "autre" });

        eprintln!("{AJ1_PHASE}calme");
        let (st, p) = aj1_base_du_connecteur("aj1-j-calme");
        let bilan = run_due_connectors(&st.db, &p);
        let statuts = [
            aj1_modifier(&st, 1).await.0,
            aj1_essayer(&st, 1).await.0,
            aj1_collecter(&st, 1).await.0,
            aj1_modifier(&st, AJ1_ABSENT).await.0,
            aj1_essayer(&st, AJ1_ABSENT).await.0,
            aj1_collecter(&st, AJ1_ABSENT).await.0,
        ];
        println!("AJ1-CALME:{}:{statuts:?}", if bilan == crate::mesure_environnement::Mesure::Lue(0) { "lue0" } else { "autre" });
        eprintln!("{AJ1_PHASE}fin");
    }

    /// CE QU'IL TIENT : les lignes de journal, lues sur le stderr d'un sous-processus et comparées EN ENTIER, par phase :
    /// une par lecture ratée (`[connecteurs] WARN connecteur #1 NON lu pour …, … (<identifiant servi>) : <cause du
    /// moteur>`), une par trace d'audit refusée (`[<identifiant servi>] [connecteurs] WARN <geste> refusé : …`), une
    /// pour le connecteur disparu pendant son passage ; aucune au nominal ni aux absences ; ni le nom, ni l'URL, ni le
    /// secret du connecteur dans une ligne `[connecteurs]`.
    /// MUTATIONS : AJ1_MAJ_SANS_JOURNAL, AJ1_ESSAI_SANS_JOURNAL, AJ1_POLL_SANS_JOURNAL (aucune ligne), AJ1_ZERO_LIGNE_MUET
    /// (disparu : aucune ligne), AJ1_ZERO_LIGNE_PARTOUT (calme : une ligne sur un succès), et les trois
    /// AJ1_*_MOTEUR_SERVI (écritures : aucune ligne).
    #[tokio::test]
    async fn aj1_lignes_de_journal_des_connecteurs() {
        if std::env::var(AJ1_ENFANT).is_ok() {
            aj1_enfant().await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::transaction_du_lot_annulee_et_connecteurs_lus_en_trois_issues::aj1_lignes_de_journal_des_connecteurs",
            ])
            .env(AJ1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let (maj, essai, poll) = (marque("AJ1-MAJ:"), marque("AJ1-ESSAI:"), marque("AJ1-POLL:"));
        for (quoi, m) in [("maj", &maj), ("essai", &essai), ("poll", &poll)] {
            assert_eq!(m[0], "503", "contrôle : {quoi}, lecture ratée en 503 : {m:?}");
            assert!(m[1].starts_with("plume-e"), "contrôle : {quoi}, identifiant servi : {m:?}");
        }
        let lectures = [
            ("lecture-maj", format!("[connecteurs] WARN connecteur #1 NON lu pour la modification, rien n'est écrit ({}) : {AJ1_MOTEUR_TABLE}", maj[1])),
            ("lecture-essai", format!("[connecteurs] WARN connecteur #1 NON lu pour l'essai, aucun essai ({}) : {AJ1_MOTEUR_BLOB}", essai[1])),
            ("lecture-poll", format!("[connecteurs] WARN connecteur #1 NON lu pour le poll manuel, aucun poll ({}) : {AJ1_MOTEUR_BLOB}", poll[1])),
        ];
        assert!(lectures.len() >= 3, "plancher : les trois lectures");
        for (nom, attendue) in &lectures {
            assert_eq!(&aj1_phase(&stderr, nom), &vec![attendue.clone()], "phase {nom} : la ligne ENTIÈRE, seule");
        }
        let ecritures: Vec<(String, String)> = marque("AJ1-ECRITURES:")
            .iter()
            .map(|e| e.split_once('=').map(|(s, i)| (s.to_string(), i.to_string())).unwrap_or_default())
            .collect();
        assert_eq!(ecritures.len(), 3, "contrôle : trois écritures : {ecritures:?}");
        assert!(ecritures.iter().all(|(s, i)| s == "500" && i.starts_with("plume-e")), "contrôle : trois 500 identifiés : {ecritures:?}");
        let refuse = |i: usize, geste: &str| {
            format!("[{}] [connecteurs] WARN {geste} refusé : transaction d'audit annulée, aucune modification ({AJ1_REGISTRE_REFUSE})", ecritures[i].1)
        };
        let attendues = vec![
            refuse(0, "création d'un connecteur http_pull"),
            refuse(1, "modification du connecteur #1"),
            refuse(2, "suppression du connecteur #1"),
        ];
        assert_eq!(aj1_phase(&stderr, "ecritures"), attendues, "phase ecritures : une ligne ENTIÈRE par trace refusée");
        let cle = marque("AJ1-CLE:");
        assert!(cle.len() == 3 && cle[0] == "500" && cle[1].starts_with("plume-e"), "contrôle : renouvellement, 500 identifié : {cle:?}");
        let renouvellement: Vec<String> = aj1_phase(&stderr, "cle").into_iter().filter(|l| l.contains("clé de livraison")).collect();
        assert_eq!(
            renouvellement,
            vec![format!(
                "[connecteurs] WARN renouvellement de la clé de livraison du connecteur #{} NON fait : écriture refusée, transaction annulée ({}) : {AJ1_REGISTRE_REFUSE}",
                cle[2], cle[1]
            )],
            "phase cle : la ligne ENTIÈRE, seule, sous l'identifiant servi, cause du moteur au journal"
        );
        assert_eq!(marque("AJ1-DISPARU:"), ["lue0"], "contrôle : le passage du connecteur disparu n'est pas un abandon");
        assert_eq!(
            aj1_phase(&stderr, "disparu"),
            vec!["[connecteurs] WARN connecteur #1 : type non supporté, état non écrit (connecteur disparu)".to_string()],
            "phase disparu : la ligne ENTIÈRE, seule"
        );
        assert_eq!(marque("AJ1-CALME:"), ["lue0", "[200, 200, 200, 404, 404, 404]"], "contrôle : nominal et absences");
        assert!(aj1_phase(&stderr, "calme").is_empty(), "phase calme : aucune ligne : {:?}", aj1_phase(&stderr, "calme"));
        for interdit in [AJ1_NOM, AJ1_SECRET, AJ1_HOTE] {
            assert!(
                !stderr.lines().any(|l| l.contains("[connecteurs] ") && l.contains(interdit)),
                "`{interdit}` ne paraît dans aucune ligne [connecteurs] : {stderr}"
            );
        }
    }
}
