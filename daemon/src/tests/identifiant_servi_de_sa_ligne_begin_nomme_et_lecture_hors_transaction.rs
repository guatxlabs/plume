// =====================================================================================
// `P10.27-x`, `P10.27-w` — UNE CRÉATION SERT L'IDENTIFIANT DE SA PROPRE LIGNE. `P10.28-p` — LE `BEGIN` REFUSÉ D'UN
// RETRAIT DE CONNECTEUR EST NOMMÉ. `P10.28-a` — UNE CONNEXION DE LECTURE RENDUE EN TRANSACTION N'EST PAS RECYCLÉE.
//
// `last_insert_rowid()` rend le dernier identifiant inséré sur LA CONNEXION, toutes tables confondues. Lu APRÈS
// `audit_config_change` — qui insère une ligne de registre puis un ÉVÉNEMENT de configuration —, il rend l'identifiant
// de cet événement, et c'est lui que la réponse servait comme identifiant de l'objet créé. Ces témoins tiennent, route
// par route, que l'identifiant servi DÉSIGNE la ligne créée (par son nom, relu dans sa table), et que le geste suivant
// d'un appelant qui s'en sert — rattacher un objet à « son » modèle, supprimer « son » objet — vise CET objet et aucun
// autre, en particulier pas celui qu'un autre compte a créé juste après.
//
// LA FORME DU JUGEMENT : chaque témoin relève TOUTES les propriétés avant de conclure et nomme celles qui manquent, avec
// ce que l'identifiant servi désignait réellement (la ligne de la table, et l'événement du journal portant ce numéro) :
// rejoué sur la forme d'avant, il dit le défaut mesuré, pas seulement le premier symptôme.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console web ne réemploie pas l'identifiant servi par ces créations (elle relit
// la liste) — le défaut frappait un client d'API qui enchaîne création puis geste ; les créations de tableaux de bord,
// panneaux, vues, playlists et instantanés qui AVALENT leur `INSERT` puis servent `last_insert_rowid()` (identifiant d'un
// autre geste sur une écriture refusée) restent tenues par l'ensemble de `check_a_swallowed_write_is_never_affirmed_as_a_fact.py`,
// pas ici ; les quatre-vingt-huit autres `BEGIN IMMEDIATE` nus de routes (500 générique) ne sont pas joués ; le mode
// multi-tenant et un `COMMIT` que SQLite annule de lui-même (disque plein, E/S) ne sont pas joués ; aucun module de
// `web/` n'est exercé.
// =====================================================================================
mod identifiant_servi_de_sa_ligne_begin_nomme_et_lecture_hors_transaction {
    use super::*;
    use crate::query_exec::connexions_de_lecture_au_repos;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    async fn isdl_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    /// Une création jouée par sa route : 200 exigé (sinon la fixture est fausse), et l'identifiant SERVI.
    async fn isdl_creer(quoi: &str, r: Response) -> i64 {
        let (statut, corps) = isdl_corps(r).await;
        assert_eq!(statut, 200, "fixture : {quoi} est créé(e) : {corps}");
        corps["id"].as_i64().unwrap_or_else(|| panic!("fixture : {quoi} sert un identifiant : {corps}"))
    }

    /// Ce que le processus lit, sur l'écrivain partagé.
    fn isdl_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn isdl_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn isdl_ecrire(st: &AppState, sql: &str) -> i64 {
        let c = st.db.lock();
        c.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
        c.last_insert_rowid()
    }

    /// UN ÉVÉNEMENT DÉJÀ INGÉRÉ : une base de SIEM en porte toujours. Table `event` VIDE, le premier numéro d'audit
    /// COÏNCIDE avec le premier identifiant de chaque table — mesuré sur la forme d'avant, sans cet événement : le modèle
    /// d'Alice servi 1, sa ligne 1 ; celui de Bob servi 2, sa ligne 2 —, et la coïncidence MASQUE le défaut. Un seul
    /// événement suffit à décaler les numéros d'audit devant ceux des objets, comme en production.
    fn isdl_un_evenement_deja_ingere(st: &AppState) {
        isdl_ecrire(st, "INSERT INTO event(ts,source,category,severity,host,message,fields) \
                         VALUES(1,'isdl','auth',2,'h','un événement déjà ingéré','{}')");
    }

    /// Le nom que porte la ligne `id` de `table`, s'il y en a une.
    fn isdl_nom_a(st: &AppState, table: &str, colonne: &str, id: i64) -> Option<String> {
        match st.db.lock().query_row(&format!("SELECT {colonne} FROM {table} WHERE id=?1"), params![id], |r| r.get::<_, String>(0)) {
            Ok(nom) => Some(nom),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => panic!("fixture : `{table}` se lit ({e})"),
        }
    }

    /// L'identifiant de la ligne qui porte `nom`, s'il y en a une.
    fn isdl_id_de(st: &AppState, table: &str, colonne: &str, nom: &str) -> Option<i64> {
        match st.db.lock().query_row(&format!("SELECT id FROM {table} WHERE {colonne}=?1"), params![nom], |r| r.get::<_, i64>(0)) {
            Ok(id) => Some(id),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => panic!("fixture : `{table}` se lit ({e})"),
        }
    }

    /// Le message de l'événement du journal qui porte ce numéro — ce que l'identifiant emprunté désignait.
    fn isdl_evenement(st: &AppState, id: i64) -> Option<String> {
        match st.db.lock().query_row("SELECT message FROM event WHERE id=?1", params![id], |r| r.get::<_, String>(0)) {
            Ok(m) => Some(m),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => panic!("fixture : `event` se lit ({e})"),
        }
    }

    /// L'identifiant servi désigne-t-il la ligne créée ? Sinon, dit ce qu'il désignait.
    fn isdl_l_id_servi_designe(st: &AppState, manquent: &mut Vec<String>, table: &str, colonne: &str, servi: i64, nom: &str) {
        let porte = isdl_nom_a(st, table, colonne, servi);
        if porte.as_deref() != Some(nom) {
            manquent.push(format!(
                "`{table}` : l'id servi {servi} désigne {porte:?} au lieu de '{nom}' (sa ligne porte l'id {:?} ; l'événement {servi} du \
                 journal : {:?})",
                isdl_id_de(st, table, colonne, nom),
                isdl_evenement(st, servi)
            ));
        }
    }

    /// Alice supprime « son » objet par l'identifiant qu'on lui a servi : le sien part, celui de Bob reste.
    fn isdl_la_suppression_vise_le_sien(
        st: &AppState,
        manquent: &mut Vec<String>,
        (table, colonne): (&str, &str),
        (servi, statut, corps): (i64, u16, &Value),
        (le_sien, l_autre): (&str, &str),
    ) {
        let reste_le_sien = isdl_id_de(st, table, colonne, le_sien).is_some();
        let reste_l_autre = isdl_id_de(st, table, colonne, l_autre).is_some();
        if reste_le_sien || !reste_l_autre {
            manquent.push(format!(
                "`{table}` : la suppression par l'id servi {servi} (statut {statut}, {corps}) laisse '{le_sien}' {} et '{l_autre}' {}",
                if reste_le_sien { "EN PLACE" } else { "supprimé" },
                if reste_l_autre { "en place" } else { "SUPPRIMÉ — l'objet d'un AUTRE compte" }
            ));
        }
    }

    fn isdl_conclure(quoi: &str, manquent: &[String]) {
        assert!(manquent.is_empty(), "{quoi} : {} propriété(s) manquent :\n  - {}", manquent.len(), manquent.join("\n  - "));
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.27-x` — MODÈLES DE DONNÉES : modèle, objet, champ, jeu de données
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : Alice puis Bob créent chacun un modèle ; chaque identifiant servi désigne SON modèle. Alice
    /// rattache un objet à « son » modèle par l'identifiant servi : l'objet est dans le modèle d'Alice. Elle déclare un
    /// champ sur « son » objet, crée un jeu de données, le supprime puis supprime « son » modèle, toujours par les
    /// identifiants servis : ce sont les siens qui partent, ceux de Bob restent.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : relire `conn.last_insert_rowid()` après la fermeture (après l'audit) dans
    /// `model_create`, `object_create`, `field_create` ou `dataset_create` — la forme d'avant.
    #[tokio::test]
    async fn isdl_modeles_de_donnees_servent_l_id_de_leur_ligne() {
        let (st, _p) = sp_state("isdl-modeles");
        isdl_un_evenement_deja_ingere(&st);
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let mut manquent: Vec<String> = Vec::new();

        let ma = isdl_creer("le modèle d'Alice", model_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "isdl_modele_alice" }))).await).await;
        let mb = isdl_creer("le modèle de Bob", model_create(State(st.clone()), Extension(bob.clone()), Json(json!({ "name": "isdl_modele_bob" }))).await).await;
        isdl_l_id_servi_designe(&st, &mut manquent, "data_model", "name", ma, "isdl_modele_alice");
        isdl_l_id_servi_designe(&st, &mut manquent, "data_model", "name", mb, "isdl_modele_bob");

        // Alice rattache un objet à « son » modèle, par l'identifiant qu'on lui a servi.
        let (statut, corps) = isdl_corps(object_create(State(st.clone()), Extension(alice.clone()), Path(ma), Json(json!({ "name": "isdl_objet_alice" }))).await).await;
        let modele_de_l_objet: Option<String> = st.db.lock().query_row(
            "SELECT m.name FROM data_model_object o JOIN data_model m ON m.id=o.model_id WHERE o.name='isdl_objet_alice'",
            [], |r| r.get(0)).ok();
        if modele_de_l_objet.as_deref() != Some("isdl_modele_alice") {
            manquent.push(format!("`data_model_object` : l'objet d'Alice, rattaché par l'id servi {ma} (statut {statut}, {corps}), est dans {modele_de_l_objet:?}"));
        }
        if statut == 200 {
            let oa = corps["id"].as_i64().expect("identifiant d'objet");
            isdl_l_id_servi_designe(&st, &mut manquent, "data_model_object", "name", oa, "isdl_objet_alice");
            // Un champ sur « son » objet, par l'identifiant servi.
            let (statut, corps) = isdl_corps(field_create(State(st.clone()), Extension(alice.clone()), Path(oa),
                Json(json!({ "name": "isdl_champ_alice", "type": "string" }))).await).await;
            let objet_du_champ: Option<String> = st.db.lock().query_row(
                "SELECT o.name FROM data_model_field f JOIN data_model_object o ON o.id=f.object_id WHERE f.name='isdl_champ_alice'",
                [], |r| r.get(0)).ok();
            if objet_du_champ.as_deref() != Some("isdl_objet_alice") {
                manquent.push(format!("`data_model_field` : le champ d'Alice, déclaré par l'id servi {oa} (statut {statut}, {corps}), est sur {objet_du_champ:?}"));
            }
            if statut == 200 {
                let fa = corps["id"].as_i64().expect("identifiant de champ");
                isdl_l_id_servi_designe(&st, &mut manquent, "data_model_field", "name", fa, "isdl_champ_alice");
            }
        }

        // Les jeux de données : Alice puis Bob ; Alice supprime « le sien » par l'identifiant servi.
        let da = isdl_creer("le jeu d'Alice", dataset_create(State(st.clone()), Extension(alice.clone()),
            Json(json!({ "name": "isdl_jeu_alice", "kind": "search", "soql": "search source=auth" }))).await).await;
        let db = isdl_creer("le jeu de Bob", dataset_create(State(st.clone()), Extension(bob.clone()),
            Json(json!({ "name": "isdl_jeu_bob", "kind": "search", "soql": "search source=web" }))).await).await;
        isdl_l_id_servi_designe(&st, &mut manquent, "dataset", "name", da, "isdl_jeu_alice");
        isdl_l_id_servi_designe(&st, &mut manquent, "dataset", "name", db, "isdl_jeu_bob");
        let (statut, corps) = isdl_corps(dataset_delete(State(st.clone()), Extension(alice.clone()), Path(da)).await).await;
        isdl_la_suppression_vise_le_sien(&st, &mut manquent, ("dataset", "name"), (da, statut, &corps), ("isdl_jeu_alice", "isdl_jeu_bob"));

        // Alice supprime « son » modèle par l'identifiant servi.
        let (statut, corps) = isdl_corps(model_delete(State(st.clone()), Extension(alice.clone()), Path(ma)).await).await;
        isdl_la_suppression_vise_le_sien(&st, &mut manquent, ("data_model", "name"), (ma, statut, &corps), ("isdl_modele_alice", "isdl_modele_bob"));

        isdl_conclure("modèles de données", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.27-x` — OBJETS DE SAVOIR : alias, champ calculé, type d'événement, étiquette, macro, enrichissement
    // -------------------------------------------------------------------------------------

    /// Une famille d'objets de savoir : Alice puis Bob créent, les deux identifiants servis sont jugés, puis Alice
    /// supprime « le sien » par l'identifiant servi.
    macro_rules! isdl_famille_de_savoir {
        ($st:expr, $manquent:expr, $alice:expr, $bob:expr, $creer:ident, $supprimer:ident, $table:expr, $colonne:expr,
         ($corps_a:expr, $nom_a:expr), ($corps_b:expr, $nom_b:expr)) => {{
            let sa = isdl_creer($nom_a, $creer(State($st.clone()), Extension($alice.clone()), Json($corps_a)).await).await;
            let sb = isdl_creer($nom_b, $creer(State($st.clone()), Extension($bob.clone()), Json($corps_b)).await).await;
            isdl_l_id_servi_designe(&$st, $manquent, $table, $colonne, sa, $nom_a);
            isdl_l_id_servi_designe(&$st, $manquent, $table, $colonne, sb, $nom_b);
            let (statut, corps) = isdl_corps($supprimer(State($st.clone()), Extension($alice.clone()), Path(sa)).await).await;
            isdl_la_suppression_vise_le_sien(&$st, $manquent, ($table, $colonne), (sa, statut, &corps), ($nom_a, $nom_b));
        }};
    }

    /// CE QU'IL TIENT : pour chacune des six familles, l'identifiant servi à Alice puis à Bob désigne SA ligne, et la
    /// suppression par l'identifiant servi à Alice retire l'objet d'Alice et laisse celui de Bob.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : relire `conn.last_insert_rowid()` après la fermeture (après l'audit) dans l'une
    /// des six créations de `knowledge.rs` — la forme d'avant.
    #[tokio::test]
    async fn isdl_objets_de_savoir_servent_l_id_de_leur_ligne() {
        let (st, _p) = sp_state("isdl-savoir");
        isdl_un_evenement_deja_ingere(&st);
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let mut manquent: Vec<String> = Vec::new();
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, alias_create, alias_delete, "knowledge_alias", "canonical",
            (json!({ "canonical": "isdl_canon_alice", "source": "isdl_src_alice" }), "isdl_canon_alice"),
            (json!({ "canonical": "isdl_canon_bob", "source": "isdl_src_bob" }), "isdl_canon_bob"));
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, calc_create, calc_delete, "knowledge_calc", "name",
            (json!({ "name": "isdl_calc_alice", "expr": "upper(severity)" }), "isdl_calc_alice"),
            (json!({ "name": "isdl_calc_bob", "expr": "lower(severity)" }), "isdl_calc_bob"));
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, eventtype_create, eventtype_delete, "knowledge_eventtype", "name",
            (json!({ "name": "isdl_type_alice", "filter": "source=web severity=HIGH" }), "isdl_type_alice"),
            (json!({ "name": "isdl_type_bob", "filter": "source=auth" }), "isdl_type_bob"));
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, tag_create, tag_delete, "knowledge_tag", "label",
            (json!({ "label": "isdl_tag_alice", "field": "user", "value": "alice" }), "isdl_tag_alice"),
            (json!({ "label": "isdl_tag_bob", "field": "user", "value": "bob" }), "isdl_tag_bob"));
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, macro_create, macro_delete, "macro_def", "name",
            (json!({ "name": "isdl_macro_alice", "params": ["src"], "body": "source=$src$" }), "isdl_macro_alice"),
            (json!({ "name": "isdl_macro_bob", "params": ["h"], "body": "host=$h$" }), "isdl_macro_bob"));
        isdl_famille_de_savoir!(st, &mut manquent, alice, bob, auto_lookup_create, auto_lookup_delete, "auto_lookup", "name",
            (json!({ "name": "isdl_lookup_alice", "key_field": "user", "out_cols": ["proprietaire"] }), "isdl_lookup_alice"),
            (json!({ "name": "isdl_lookup_bob", "key_field": "host", "out_cols": ["site"] }), "isdl_lookup_bob"));
        isdl_conclure("objets de savoir", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.27-w` — RAPPORTS PLANIFIÉS ET WORKFLOW-ACTIONS : le `COMMIT` est jugé, et l'identifiant est celui de la ligne
    // -------------------------------------------------------------------------------------

    /// `COMMIT` (et `END`) refusés sur l'écrivain partagé ; `BEGIN` et `ROLLBACK` restent permis.
    fn isdl_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// `BEGIN` refusé sur l'écrivain partagé ; tout le reste permis.
    fn isdl_refuser_le_begin(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn isdl_lever_l_autorisateur(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Un geste joué sous un autorisateur, levé ensuite : statut, corps, et si l'écrivain est hors transaction.
    async fn isdl_sous(st: &AppState, refuser: fn(&AppState), geste: impl std::future::Future<Output = Response>) -> (u16, Value, bool) {
        refuser(st);
        let r = geste.await;
        let fermee = st.db.lock().is_autocommit();
        isdl_lever_l_autorisateur(st);
        let (statut, corps) = isdl_corps(r).await;
        (statut, corps, fermee)
    }

    /// CE QU'IL TIENT : sous un `COMMIT` refusé, la création d'un rapport planifié et celle d'une workflow-action rendent
    /// le 503 NOMMÉ du geste sans identifiant, la transaction est fermée, rien n'est écrit à froid ni pour ce processus.
    /// Levé, chacune sert l'identifiant de SA ligne, et Alice qui supprime « son » rapport ou « son » action par cet
    /// identifiant ne touche pas ceux de Bob.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre le `COMMIT` de `report_create` ou de `workflow_action_create` à `let _ =`
    /// et servir `conn.last_insert_rowid()` — la forme d'avant.
    #[tokio::test]
    async fn isdl_rapports_et_workflow_actions_jugent_leur_commit_et_servent_l_id_de_leur_ligne() {
        let (st, p) = sp_state("isdl-rapports");
        isdl_un_evenement_deja_ingere(&st);
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let jeu = isdl_ecrire(&st, "INSERT INTO dataset(name,kind,soql,enabled,created,updated) VALUES('isdl_jeu','search','search source=auth',1,1,1)");
        let canal = isdl_ecrire(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('isdl_canal','webhook',1,'https://example.invalid/h',2,'{}')");
        let rapport = |nom: &str| json!({ "name": nom, "dataset_id": jeu, "notifier_id": canal });
        let action = |nom: &str| json!({ "name": nom, "kind": "search", "scope_field": "host", "target": "search host=$field$" });
        let mut manquent: Vec<String> = Vec::new();

        let (statut, corps, fermee) = isdl_sous(&st, isdl_refuser_le_commit,
            report_create(State(st.clone()), Extension(alice.clone()), Json(rapport("isdl_rapport_refuse")))).await;
        let sql = "SELECT COUNT(*) FROM scheduled_report WHERE name='isdl_rapport_refuse'";
        for (propriete, tenue) in [
            ("rapport : statut 503", statut == 503),
            ("rapport : cause nommée", corps["error"] == json!(CAUSE_RAPPORT_PLANIFIE_NON_CREE)),
            ("rapport : aucun identifiant d'objet servi", corps["id"].as_i64().is_none()),
            ("rapport : transaction FERMÉE", fermee),
            ("rapport : rien à froid", isdl_a_froid(&p, sql) == 0),
            ("rapport : rien pour ce processus", isdl_compte(&st, sql) == 0),
        ] {
            if !tenue {
                manquent.push(format!("{propriete} (statut {statut}, {corps})"));
            }
        }
        if !st.db.lock().is_autocommit() {
            let _ = st.db.lock().execute_batch("ROLLBACK"); // la forme d'avant laissait la transaction pendante
        }

        let (statut, corps, fermee) = isdl_sous(&st, isdl_refuser_le_commit,
            workflow_action_create(State(st.clone()), Extension(alice.clone()), Json(action("isdl_action_refusee")))).await;
        let sql = "SELECT COUNT(*) FROM workflow_action WHERE name='isdl_action_refusee'";
        for (propriete, tenue) in [
            ("workflow-action : statut 503", statut == 503),
            ("workflow-action : cause nommée", corps["error"] == json!(CAUSE_WORKFLOW_ACTION_NON_CREEE)),
            ("workflow-action : aucun identifiant d'objet servi", corps["id"].as_i64().is_none()),
            ("workflow-action : transaction FERMÉE", fermee),
            ("workflow-action : rien à froid", isdl_a_froid(&p, sql) == 0),
            ("workflow-action : rien pour ce processus", isdl_compte(&st, sql) == 0),
        ] {
            if !tenue {
                manquent.push(format!("{propriete} (statut {statut}, {corps})"));
            }
        }
        if !st.db.lock().is_autocommit() {
            let _ = st.db.lock().execute_batch("ROLLBACK");
        }

        // Levé : l'identifiant servi est celui de la ligne, et la suppression par lui vise la bonne.
        let ra = isdl_creer("le rapport d'Alice", report_create(State(st.clone()), Extension(alice.clone()), Json(rapport("isdl_rapport_alice"))).await).await;
        let rb = isdl_creer("le rapport de Bob", report_create(State(st.clone()), Extension(bob.clone()), Json(rapport("isdl_rapport_bob"))).await).await;
        isdl_l_id_servi_designe(&st, &mut manquent, "scheduled_report", "name", ra, "isdl_rapport_alice");
        isdl_l_id_servi_designe(&st, &mut manquent, "scheduled_report", "name", rb, "isdl_rapport_bob");
        let (statut, corps) = isdl_corps(report_delete(State(st.clone()), Extension(alice.clone()), Path(ra)).await).await;
        isdl_la_suppression_vise_le_sien(&st, &mut manquent, ("scheduled_report", "name"), (ra, statut, &corps), ("isdl_rapport_alice", "isdl_rapport_bob"));

        let aa = isdl_creer("l'action d'Alice", workflow_action_create(State(st.clone()), Extension(alice.clone()), Json(action("isdl_action_alice"))).await).await;
        let ab = isdl_creer("l'action de Bob", workflow_action_create(State(st.clone()), Extension(bob.clone()), Json(action("isdl_action_bob"))).await).await;
        isdl_l_id_servi_designe(&st, &mut manquent, "workflow_action", "name", aa, "isdl_action_alice");
        isdl_l_id_servi_designe(&st, &mut manquent, "workflow_action", "name", ab, "isdl_action_bob");
        let (statut, corps) = isdl_corps(workflow_action_delete(State(st.clone()), Extension(alice.clone()), Path(aa)).await).await;
        isdl_la_suppression_vise_le_sien(&st, &mut manquent, ("workflow_action", "name"), (aa, statut, &corps), ("isdl_action_alice", "isdl_action_bob"));

        isdl_conclure("rapports planifiés et workflow-actions", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.28-p` — LE `BEGIN` REFUSÉ DU RETRAIT D'UN CONNECTEUR EST NOMMÉ, ET NE TOUCHE À RIEN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, DANS LES DEUX CAUSES D'UN `BEGIN` REFUSÉ : une source push Firehose et sa clé de livraison. Sous un
    /// `BEGIN` refusé (autorisateur), puis sous la transaction d'un AUTRE geste restée ouverte sur l'écrivain, le retrait
    /// rend 503 et la cause NOMMÉE qui dit que les clés ne sont pas révoquées ; la clé authentifie toujours, le connecteur
    /// et la clé sont là à froid, aucun retrait n'est attesté ; la transaction étrangère n'est ni validée ni annulée par
    /// ce geste (toujours ouverte, son écriture toujours pendante et absente à froid). Levé, 204 : la clé est révoquée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `connector_delete` son `BEGIN IMMEDIATE` nu et son 500 générique.
    #[tokio::test]
    async fn isdl_un_begin_refuse_ne_retire_aucun_connecteur_et_le_dit() {
        let (st, p) = sp_state("isdl-connecteur");
        let adm = sp_au("adm", "admin");
        let (statut, corps) =
            isdl_corps(connector_push_source(State(st.clone()), Extension(adm.clone()), Json(json!({ "preset_id": "aws-cloudtrail" }))).await).await;
        assert_eq!(statut, 200, "fixture : source push : {corps}");
        let cle = corps["delivery_key"].as_str().expect("clé montrée une fois").to_string();
        let id = corps["connector_id"].as_i64().expect("connecteur");
        assert_eq!(firehose_token_lookup(&st, &cle).map(|i| i.connector_id), Some(id), "fixture : la clé authentifie");
        let mut manquent: Vec<String> = Vec::new();
        let juger = |cas: &str, statut: u16, corps: &Value, manquent: &mut Vec<String>| {
            for (propriete, tenue) in [
                ("statut 503", statut == 503),
                ("cause nommée", corps["error"] == json!(CAUSE_CONNECTEUR_NON_SUPPRIME_TRANSACTION_NON_OUVERTE)),
                ("la clé authentifie toujours", firehose_token_lookup(&st, &cle).map(|i| i.connector_id) == Some(id)),
                ("connecteur là à froid", isdl_a_froid(&p, "SELECT COUNT(*) FROM connector") == 1),
                ("clé là à froid", isdl_a_froid(&p, "SELECT COUNT(*) FROM token WHERE kind='firehose'") == 1),
                ("aucun retrait attesté", isdl_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.delete'") == 0),
            ] {
                if !tenue {
                    manquent.push(format!("{cas} : {propriete} (statut {statut}, {corps})"));
                }
            }
        };

        // (a) `BEGIN` refusé par la base (verrou) — l'écrivain est hors transaction.
        let (statut, corps, fermee) = isdl_sous(&st, isdl_refuser_le_begin,
            connector_delete(State(st.clone()), Extension(adm.clone()), Path(id))).await;
        juger("BEGIN refusé", statut, &corps, &mut manquent);
        if !fermee {
            manquent.push("BEGIN refusé : l'écrivain est resté en transaction".into());
        }

        // (b) La transaction d'un AUTRE geste est ouverte sur l'écrivain : ce geste ne la valide ni ne l'annule.
        isdl_ecrire(&st, "BEGIN; INSERT INTO meta(key,value) VALUES('isdl_etrangere','1');");
        let (statut, corps) = isdl_corps(connector_delete(State(st.clone()), Extension(adm.clone()), Path(id)).await).await;
        let etrangere_ouverte = !st.db.lock().is_autocommit();
        let etrangere_pendante = isdl_compte(&st, "SELECT COUNT(*) FROM meta WHERE key='isdl_etrangere'") == 1;
        let etrangere_a_froid = isdl_a_froid(&p, "SELECT COUNT(*) FROM meta WHERE key='isdl_etrangere'");
        juger("transaction étrangère", statut, &corps, &mut manquent);
        for (propriete, tenue) in [
            ("transaction étrangère : toujours ouverte (ni validée ni annulée par ce geste)", etrangere_ouverte),
            ("transaction étrangère : son écriture toujours pendante", etrangere_pendante),
            ("transaction étrangère : rien de validé à froid", etrangere_a_froid == 0),
        ] {
            if !tenue {
                manquent.push(propriete.into());
            }
        }
        if !st.db.lock().is_autocommit() {
            st.db.lock().execute_batch("ROLLBACK").expect("le témoin ferme la transaction qu'il a ouverte");
        }
        isdl_conclure("retrait de connecteur sous BEGIN refusé", &manquent);

        let (statut, corps) = isdl_corps(connector_delete(State(st.clone()), Extension(adm), Path(id)).await).await;
        assert_eq!(statut, 204, "levé, le retrait a lieu : {corps}");
        assert!(firehose_token_lookup(&st, &cle).is_none(), "levé, la clé est révoquée");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.28-a` — UNE CONNEXION DE LECTURE RENDUE EN TRANSACTION EST FERMÉE, PAS RECYCLÉE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une connexion du pool de lecture rendue avec son instantané OUVERT (`BEGIN` puis une lecture) n'est
    /// pas remise au pool ; la lecture suivante par le pool est hors transaction et VOIT une écriture validée entre-temps
    /// (la base est en WAL, comme en production). Contrôle positif : une connexion rendue hors transaction est recyclée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer le contrôle `is_autocommit()` de `read_conn_put` — la connexion revient au
    /// pool dans son instantané, et la lecture suivante sert l'état d'avant l'écriture.
    #[test]
    fn isdl_une_connexion_de_lecture_rendue_en_transaction_n_est_pas_recyclee() {
        let (st, p) = sp_state("isdl-lecture");
        let chemin = p.as_str();
        st.db.lock().execute_batch("PRAGMA journal_mode=WAL").expect("fixture : base en WAL, comme en production");
        let sql = "SELECT COUNT(*) FROM meta WHERE key LIKE 'isdl_lecture%'";

        let c = read_conn_get(chemin).expect("fixture : connexion de lecture");
        c.execute_batch("BEGIN").expect("fixture : instantané ouvert");
        let avant: i64 = c.query_row(sql, [], |r| r.get(0)).expect("fixture : lecture dans l'instantané");
        assert!(!c.is_autocommit(), "fixture : la connexion est en transaction");
        read_conn_put(chemin, c);
        let au_repos = connexions_de_lecture_au_repos(chemin);

        isdl_ecrire(&st, "INSERT INTO meta(key,value) VALUES('isdl_lecture_1','1')");
        let (hors_transaction, apres) = read_with(chemin, (false, -1), |c| {
            (c.is_autocommit(), c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(-2))
        });
        let mut manquent: Vec<String> = Vec::new();
        for (propriete, tenue) in [
            ("la connexion rendue EN TRANSACTION n'est pas remise au pool", au_repos == 0),
            ("la connexion servie ensuite est hors transaction", hors_transaction),
            ("la lecture suivante voit l'écriture validée (instantané frais)", apres == avant + 1),
        ] {
            if !tenue {
                manquent.push(format!("{propriete} (au repos : {au_repos} ; compte avant {avant}, après {apres})"));
            }
        }
        isdl_conclure("pool de lecture", &manquent);

        // Contrôle positif : hors transaction, la connexion est bien recyclée (le témoin ne passe pas parce que le pool
        // aurait cessé de recycler).
        let c = read_conn_get(chemin).expect("connexion de lecture");
        read_conn_put(chemin, c);
        assert!(connexions_de_lecture_au_repos(chemin) >= 1, "une connexion rendue hors transaction est remise au pool");
    }
}
