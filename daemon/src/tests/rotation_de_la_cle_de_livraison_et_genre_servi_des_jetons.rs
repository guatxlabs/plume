// =====================================================================================
// `P10.26-g` — LA CLÉ DE LIVRAISON D'UNE SOURCE PUSH SE RENOUVELLE PAR UNE ROUTE NOMMÉE.
//
// LE DÉFAUT, MESURÉ AVANT TOUT CORRECTIF le 2026-09-29 (lecture de l'arbre, la route n'existant pas il n'y avait rien à
// jouer) : aucune des routes de connecteurs (`server/groupes_de_routes.rs`) ne refrappait une clé, et
// `connector_update` ne fait tourner que `connector.secret`. Le seul geste était de supprimer la source push puis de la
// recréer : nom, environnement, configuration et identifiant perdus (la source recréée reprend un rowid libéré, mesuré
// par `push_source_delete_revokes_delivery_token`), flux coupé ; et `DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME`
// prescrivait ce détour. L'énoncé était exact ; il taisait ce coût, et le cas d'une source RESTÉE SANS CLÉ (la clé
// jamais servie d'un auteur supprimé est révoquée avec lui, `cjgi_la_cle_de_livraison_porte_son_auteur…`) qu'aucune
// route ne pouvait réalimenter.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (la route y refuse en 501 avant toute lecture, non joué) ; un
// `COMMIT` que SQLite annule de lui-même (disque plein, E/S) — seul l'autorisateur est joué ; la face console (bouton,
// confirmation, clé montrée une fois) est tenue par le harnais ESM (témoin 124), pas ici ; le flux du nuage lui-même
// (Pub/Sub, Firehose) n'est pas simulé : « refusé jusqu'au report » est mesuré sur les deux récepteurs d'authentification
// (`pubsub_token_lookup`, `firehose_token_lookup`), pas sur une relance réelle du nuage.
//
// `P10.26-f` — L'INVENTAIRE DES JETONS SERT LE GENRE ÉCRIT, JAMAIS UN GENRE DEVINÉ.
//
// LE DÉFAUT, MESURÉ AVANT TOUT CORRECTIF le 2026-09-29 (premier témoin ci-dessous joué sur la forme d'avant) :
// `tokens_list` projetait `kind` par un `match` fermé (`hec`, `datasource`, `client`, `firehose`) et rendait
// `_ => "agent"`. Une clé de livraison GCP (`gcp_pubsub`, frappée par `connector_push_source`) sortait donc
// « agent » sans hôte — ce que la console peint « relais — hôte non attesté » : l'inventaire annonçait un jeton qui
// écrit sous n'importe quel nom d'hôte sur le seam agent, alors que `token_lookup` REFUSE ce genre (seul
// `pubsub_token_lookup` l'authentifie, borné à son récepteur). Un administrateur qui révoque ce « relais
// orphelin » coupe l'ingestion GCP. L'énoncé sous-comptait : tout genre que le `match` ne connaît pas (un genre
// ajouté demain) aurait été maquillé de même en « agent ».
// =====================================================================================
mod rotation_de_la_cle_de_livraison_et_genre_servi_des_jetons {
    use super::*;
    use crate::secret_des_gestes::{
        SecretDesGestesPresente, SourceDuSecretDesGestes, CAUSE_SECRET_DES_GESTES_ABSENT, CAUSE_SECRET_DES_GESTES_FAUX,
        CAUSE_SECRET_DES_GESTES_NON_CONFIGURE,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    async fn rcdl_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn rcdl_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn rcdl_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn rcdl_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> String {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get::<_, rusqlite::types::Value>(0))
            .map(|v| match v {
                rusqlite::types::Value::Integer(n) => n.to_string(),
                rusqlite::types::Value::Text(t) => t,
                autre => format!("{autre:?}"),
            })
            .unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn rcdl_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn rcdl_refuser(st: &AppState, refuse: fn(&AuthAction<'_>) -> bool) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| if refuse(&ctx.action) { Authorization::Deny } else { Authorization::Allow }));
    }

    fn rcdl_le_commit(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Transaction { operation: TransactionOperation::Unknown })
    }

    fn rcdl_le_begin(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Transaction { operation: TransactionOperation::Begin })
    }

    fn rcdl_la_lecture_du_connecteur(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Read { table_name: "connector", .. })
    }

    fn rcdl_la_frappe_d_un_jeton(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Insert { table_name: "token" })
    }

    fn rcdl_la_revocation_des_cles(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Delete { table_name: "token" })
    }

    fn rcdl_la_trace_au_registre(a: &AuthAction<'_>) -> bool {
        matches!(a, AuthAction::Insert { table_name: "ledger" })
    }

    /// Crée une source push par la route réelle ; rend (identifiant, clé montrée une fois).
    async fn rcdl_source_push(st: &AppState, preset: &str, nom: &str, env: &str) -> (i64, String) {
        let (statut, corps) = rcdl_corps(
            connector_push_source(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(rcdl_adm()), Json(json!({ "preset_id": preset, "name": nom, "env_id": env }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : source push {preset} : {corps}");
        let cle = corps["delivery_token"].as_str().or_else(|| corps["delivery_key"].as_str()).expect("clé montrée").to_string();
        (corps["connector_id"].as_i64().expect("identifiant"), cle)
    }

    async fn rcdl_renouveler(st: &AppState, presente: SecretDesGestesPresente, au: AuthUser, id: i64) -> (u16, Value) {
        rcdl_corps(connector_delivery_key_rotate(State(st.clone()), presente, Extension(au), axum::extract::Path(id)).await).await
    }

    /// Ce qui décrit la source hors de sa clé : ce que le détour d'avant perdait.
    fn rcdl_la_source(st: &AppState, id: i64) -> (String, String, i64, String, String, i64) {
        st.db
            .lock()
            .query_row("SELECT type,name,enabled,config_json,env_id,interval_s FROM connector WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })
            .expect("fixture : la source se lit")
    }

    /// Les clés liées à la source : (nom, genre, empreinte, auteur, dernier usage).
    fn rcdl_les_cles(st: &AppState, id: i64) -> Vec<(String, String, String, Option<String>, Option<i64>)> {
        let c = st.db.lock();
        let mut stmt = c.prepare("SELECT name,kind,token_hash,created_by,last_used FROM token WHERE connector_id=?1 ORDER BY id").expect("fixture");
        let lues = stmt
            .query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .expect("fixture")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("fixture : les clés se lisent");
        lues
    }

    /// Aucune clé dans un corps de refus, ni sous l'un ni sous l'autre nom.
    fn rcdl_aucune_cle_montree(corps: &Value) -> bool {
        corps.get("delivery_token").is_none() && corps.get("delivery_key").is_none()
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.26-g` — L'ANCIENNE REFUSÉE, LA NEUVE SERVIE, LA SOURCE INTACTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur une source Pub/Sub puis une source Firehose créées par la route réelle, leur clé servie une fois :
    ///  * le renouvellement (par un AUTRE administrateur que l'auteur) rend 200, la clé NEUVE dans la forme de son
    ///    transport (`delivery_token` + `transport` ; `delivery_key` + `auth_header`), `cles_revoquees = 1` et des
    ///    instructions qui disent le report et le refus d'ici là — sans la clé ;
    ///  * l'ancienne clé est REFUSÉE par son récepteur, la neuve y est servie et résout vers le MÊME connecteur ; elle
    ///    reste refusée par l'autre récepteur et par le seam agent (isolation des genres intacte) ;
    ///  * la source garde son type, son nom, son activation, sa configuration, son environnement, son intervalle et son
    ///    identifiant ; une seule clé lui est liée, frappée par l'administrateur qui a renouvelé (`created_by`), jamais servie ;
    ///  * le registre porte une trace du renouvellement, et ni la trace ni l'événement de configuration ne portent
    ///    l'ancienne ou la nouvelle clé, ni leur empreinte ;
    ///  * la décision servie à la suppression d'un compte prescrit ce geste, et plus le détour.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (jouées) : retirer le `DELETE FROM token` du geste — l'ancienne clé authentifie
    /// encore ; frapper la clé sans son auteur (`created_by` vide) — l'auteur n'est pas celui qui a renouvelé.
    #[tokio::test]
    async fn rcdl_la_rotation_revoque_l_ancienne_cle_sert_la_neuve_et_garde_la_source() {
        let (st, _p) = sp_state("rcdl-rotation");
        let rot = || sp_au("rot", "admin");

        // PUB/SUB
        let (id, ancienne) = rcdl_source_push(&st, "gcp-audit", "gcp-rcdl", "staging").await;
        assert_eq!(pubsub_token_lookup(&st, &ancienne).map(|i| i.connector_id), Some(id), "fixture : la clé d'origine sert une fois");
        let source_avant = rcdl_la_source(&st, id);
        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rot(), id).await;
        assert_eq!(statut, 200, "le renouvellement a lieu : {corps}");
        let neuve = corps["delivery_token"].as_str().expect("clé Pub/Sub montrée sous `delivery_token`").to_string();
        assert_eq!(neuve.len(), 64, "32 octets d'entropie en hexadécimal : {corps}");
        assert_ne!(neuve, ancienne, "une clé NEUVE");
        assert_eq!(
            (&corps["connector_id"], &corps["endpoint_path"], &corps["transport"], &corps["cles_revoquees"]),
            (&json!(id), &json!("/api/ingest/pubsub"), &json!("query_token"), &json!(1)),
            "{corps}"
        );
        assert!(corps.get("delivery_key").is_none() && corps.get("auth_header").is_none(), "forme Pub/Sub, pas Firehose : {corps}");
        assert_eq!(corps["instructions"], json!(INSTRUCTIONS_DU_RENOUVELLEMENT_PUBSUB), "{corps}");
        assert!(!corps["instructions"].as_str().unwrap_or_default().contains(&neuve), "la clé ne vit que dans son champ");
        assert!(pubsub_token_lookup(&st, &ancienne).is_none(), "l'ANCIENNE clé est refusée par son récepteur");
        assert_eq!(pubsub_token_lookup(&st, &neuve).map(|i| i.connector_id), Some(id), "la neuve est servie, sur le MÊME connecteur");
        assert!(firehose_token_lookup(&st, &neuve).is_none() && token_lookup(&st, &neuve).is_none(), "isolation des genres intacte");
        assert_eq!(rcdl_la_source(&st, id), source_avant, "la source garde tout ce que le détour d'avant perdait");
        let cles = rcdl_les_cles(&st, id);
        assert_eq!(cles.len(), 1, "une seule clé liée : {cles:?}");
        assert_eq!(
            (&cles[0].0, &cles[0].1, &cles[0].2, cles[0].3.as_deref()),
            (&format!("gcp_pubsub-{id}"), &"gcp_pubsub".to_string(), &sha256_hex(neuve.as_bytes()), Some("rot")),
            "la clé neuve porte son nom, son genre, son empreinte et l'administrateur qui l'a frappée"
        );

        // FIREHOSE
        let (id_f, ancienne_f) = rcdl_source_push(&st, "aws-cloudtrail", "fh-rcdl", "prod").await;
        assert!(firehose_token_lookup(&st, &ancienne_f).is_some(), "fixture : la clé Firehose sert une fois");
        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rot(), id_f).await;
        assert_eq!(statut, 200, "{corps}");
        let neuve_f = corps["delivery_key"].as_str().expect("clé Firehose montrée sous `delivery_key`").to_string();
        assert_eq!(
            (&corps["endpoint_path"], &corps["auth_header"], &corps["cles_revoquees"], &corps["instructions"]),
            (&json!("/api/ingest/firehose"), &json!("X-Amz-Firehose-Access-Key"), &json!(1), &json!(INSTRUCTIONS_DU_RENOUVELLEMENT_FIREHOSE)),
            "{corps}"
        );
        assert!(firehose_token_lookup(&st, &ancienne_f).is_none(), "l'ancienne clé Firehose est refusée");
        assert_eq!(firehose_token_lookup(&st, &neuve_f).map(|i| i.connector_id), Some(id_f), "la neuve est servie sur le même connecteur");
        assert!(pubsub_token_lookup(&st, &neuve_f).is_none() && token_lookup(&st, &neuve_f).is_none(), "isolation des genres intacte");
        assert!(pubsub_token_lookup(&st, &neuve).is_some(), "le renouvellement d'une source ne touche pas la clé d'une autre");

        // LE REGISTRE, SANS LE SECRET
        assert_eq!(rcdl_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.delivery_key.rotate'"), 2, "chaque renouvellement est tracé");
        let traces: Vec<String> = {
            let c = st.db.lock();
            let mut stmt = c
                .prepare("SELECT detail FROM ledger WHERE kind='config.connector.delivery_key.rotate' UNION ALL SELECT message || ' ' || fields FROM event WHERE source='plume-config' AND fields LIKE '%delivery_key%'")
                .expect("fixture");
            let lues = stmt.query_map([], |r| r.get(0)).expect("fixture").collect::<rusqlite::Result<Vec<String>>>().expect("fixture : traces lues");
            lues
        };
        assert_eq!(traces.len(), 4, "deux maillons et deux événements de configuration : {traces:?}");
        for secret in [&ancienne, &neuve, &ancienne_f, &neuve_f] {
            let empreinte = sha256_hex(secret.as_bytes());
            assert!(traces.iter().all(|t| !t.contains(secret.as_str()) && !t.contains(&empreinte)), "aucune clé ni empreinte au registre : {traces:?}");
        }

        // LA DÉCISION DE LA SUPPRESSION D'UN COMPTE PRESCRIT CE GESTE
        assert!(
            DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME.contains("renouvelez la clé de sa source push") && !DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME.contains("recréez"),
            "la décision prescrit le renouvellement, plus le détour : {DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME}"
        );
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.26-g` — UN COMMIT, UN BEGIN, UNE LECTURE OU UNE ÉCRITURE REFUSÉS NE CHANGENT AUCUNE CLÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur une source Pub/Sub dont la clé sert :
    ///  * `COMMIT` refusé : 503 nommé, aucune clé dans le corps, transaction FERMÉE, l'ancienne clé authentifie toujours,
    ///    une seule clé liée, la même empreinte — ici ET à froid —, aucune trace ;
    ///  * `BEGIN` refusé : 503 nommé (`… TRANSACTION_NON_OUVERTE`), rien n'est écrit ;
    ///  * relecture du connecteur refusée : 503 nommé (`… SOURCE_NON_LUE`), rien n'est écrit ;
    ///  * frappe de la clé neuve refusée — APRÈS la révocation de l'ancienne dans la même transaction : 500 qui porte la
    ///    cause nommée, et l'ancienne clé authentifie toujours (la révocation est annulée avec la transaction) ;
    ///  * RÉVOCATION refusée (le `DELETE` des clés liées) : 500 qui porte la cause nommée, rien n'est frappé ni tracé —
    ///    le pire cas du geste : poursuivre laisserait DEUX clés liées à la source, dont l'ancienne, celle qu'on voulait
    ///    retirer, qui authentifie toujours ; `token.name` n'est pas UNIQUE (seul `token_hash` l'est), aucune contrainte
    ///    ne rattraperait la frappe ;
    ///  * TRACE refusée (l'écriture du registre) — APRÈS la révocation et la frappe : 500 qui porte la cause nommée, la
    ///    révocation et la frappe sont annulées avec la transaction, l'ancienne clé authentifie toujours ;
    ///  * levé : 200 — l'écrivain n'est resté dans aucune transaction.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (jouées) : rendre la clé malgré un `COMMIT` refusé (la forme que `P10.25-e` a
    /// fermée ailleurs) — 200 au lieu de 503 ; avaler l'écriture refusée de la frappe et poursuivre jusqu'à la validation
    /// — 200 au lieu de 500, l'ancienne clé révoquée sans remplaçante ; avaler la révocation refusée (`.unwrap_or(0)`) —
    /// 200, deux clés liées, l'ancienne valide ; avaler la trace refusée (`.ok()`) — 200, la crédence renouvelée sans
    /// aucune trace au registre.
    #[tokio::test]
    async fn rcdl_un_commit_un_begin_une_lecture_ou_une_ecriture_refuses_ne_changent_aucune_cle() {
        let (st, p) = sp_state("rcdl-refus");
        let (id, ancienne) = rcdl_source_push(&st, "gcp-audit", "gcp-rcdl", "prod").await;
        let empreinte = sha256_hex(ancienne.as_bytes());
        let rien_n_a_change = |st: &AppState, cas: &str| {
            assert!(st.db.lock().is_autocommit(), "{cas} : la transaction est fermée");
            assert!(pubsub_token_lookup(st, &ancienne).is_some(), "{cas} : l'ancienne clé authentifie toujours, comme la cause le dit");
            let cles = rcdl_les_cles(st, id);
            assert_eq!(cles.len(), 1, "{cas} : une seule clé liée : {cles:?}");
            assert_eq!(cles[0].2, empreinte, "{cas} : la même empreinte");
            assert_eq!(rcdl_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.delivery_key.rotate'"), 0, "{cas} : aucune trace");
        };
        let jouer = |st: AppState, refus: fn(&AuthAction<'_>) -> bool| async move {
            rcdl_refuser(&st, refus);
            let lu = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id).await;
            rcdl_lever(&st);
            lu
        };

        let (statut, corps) = jouer(st.clone(), rcdl_le_commit).await;
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_COMMIT_REFUSE)), "{corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "aucune clé montrée : {corps}");
        rien_n_a_change(&st, "COMMIT refusé");
        assert_eq!(rcdl_a_froid(&p, &format!("SELECT token_hash FROM token WHERE connector_id={id}")), empreinte, "et un redémarrage relirait l'ancienne");
        assert_eq!(rcdl_a_froid(&p, &format!("SELECT COUNT(*) FROM token WHERE connector_id={id}")), "1", "et elle seule");

        let (statut, corps) = jouer(st.clone(), rcdl_le_begin).await;
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_TRANSACTION_NON_OUVERTE)), "{corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "{corps}");
        rien_n_a_change(&st, "BEGIN refusé");

        let (statut, corps) = jouer(st.clone(), rcdl_la_lecture_du_connecteur).await;
        assert_eq!((statut, &corps["error"]), (503, &json!(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_SOURCE_NON_LUE)), "{corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "{corps}");
        rien_n_a_change(&st, "relecture du connecteur refusée");

        let (statut, corps) = jouer(st.clone(), rcdl_la_frappe_d_un_jeton).await;
        assert_eq!(statut, 500, "{corps}");
        assert!(corps["error"].as_str().is_some_and(|e| e.starts_with(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE)), "la cause nommée ouvre le refus : {corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "{corps}");
        rien_n_a_change(&st, "frappe refusée après la révocation");

        let (statut, corps) = jouer(st.clone(), rcdl_la_revocation_des_cles).await;
        assert_eq!(statut, 500, "révocation refusée : le geste s'arrête là, rien n'est frappé : {corps}");
        assert!(corps["error"].as_str().is_some_and(|e| e.starts_with(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE)), "la cause nommée ouvre le refus : {corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "{corps}");
        rien_n_a_change(&st, "révocation refusée");

        let (statut, corps) = jouer(st.clone(), rcdl_la_trace_au_registre).await;
        assert_eq!(statut, 500, "trace refusée : la crédence n'est pas renouvelée sans sa trace : {corps}");
        assert!(corps["error"].as_str().is_some_and(|e| e.starts_with(CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE)), "la cause nommée ouvre le refus : {corps}");
        assert!(rcdl_aucune_cle_montree(&corps), "{corps}");
        rien_n_a_change(&st, "trace refusée après la révocation et la frappe");

        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id).await;
        assert_eq!(statut, 200, "levé, le renouvellement a lieu : {corps}");
        assert!(pubsub_token_lookup(&st, &ancienne).is_none(), "et l'ancienne clé est refusée");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.26-g` — SANS LE SECRET DES GESTES, RIEN N'EST ÉCRIT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sur une source Pub/Sub dont la clé sert, le renouvellement SANS en-tête (403
    /// `secret_des_gestes_absent`), avec un secret FAUX (403 `secret_des_gestes_faux`) et sur un démon SANS secret configuré
    /// (403 `secret_des_gestes_non_configure`, jamais un repli permissif) : aucune clé montrée, l'ancienne authentifie
    /// toujours, la même empreinte, aucune trace de renouvellement. Contrôle positif : le bon secret, 200.
    ///
    /// AUCUN ORACLE SANS LE SECRET : le secret est exigé AVANT toute lecture du connecteur. Sans en-tête, un identifiant
    /// inconnu et un connecteur en PULL rendent le MÊME refus (403 `secret_des_gestes_absent`) qu'une source push, jamais
    /// le 404 ni le 400 qui diraient ce que l'identifiant désigne ; aucun jeton n'est écrit.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (jouées) : retirer l'appel à `exiger_le_secret_des_gestes` du geste — le premier
    /// cas (sans en-tête) rend 200 et une clé ; relire le type du connecteur AVANT le secret (404 et 400 servis sans
    /// secret) — l'identifiant inconnu rend 404.
    #[tokio::test]
    async fn rcdl_sans_le_secret_des_gestes_rien_n_est_ecrit() {
        let (mut st, _p) = sp_state("rcdl-secret");
        let (id, ancienne) = rcdl_source_push(&st, "gcp-audit", "gcp-rcdl", "prod").await;
        let empreinte = sha256_hex(ancienne.as_bytes());
        let sans = || SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
        let faux = || SecretDesGestesPresente { valeur: Some("ce-n-est-pas-le-secret-rcdl".into()), ip: "127.0.0.1".into() };
        let juger = |st: &AppState, statut: u16, corps: &Value, cause: &str| {
            assert_eq!((statut, &corps["cause"]), (403, &json!(cause)), "{corps}");
            assert!(rcdl_aucune_cle_montree(corps), "{corps}");
            assert!(pubsub_token_lookup(st, &ancienne).is_some(), "{cause} : l'ancienne clé authentifie toujours");
            assert_eq!(rcdl_les_cles(st, id).into_iter().map(|c| c.2).collect::<Vec<_>>(), vec![empreinte.clone()], "{cause} : la même clé, seule");
            assert_eq!(rcdl_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='config.connector.delivery_key.rotate'"), 0, "{cause} : aucune trace");
        };
        let (statut, corps) = rcdl_renouveler(&st, sans(), rcdl_adm(), id).await;
        juger(&st, statut, &corps, CAUSE_SECRET_DES_GESTES_ABSENT);
        let (statut, corps) = rcdl_renouveler(&st, faux(), rcdl_adm(), id).await;
        juger(&st, statut, &corps, CAUSE_SECRET_DES_GESTES_FAUX);
        let source = st.secret_des_gestes.clone();
        st.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::NonConfiguree);
        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id).await;
        juger(&st, statut, &corps, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE);
        st.secret_des_gestes = source;

        // AUCUN ORACLE SANS LE SECRET : un identifiant inconnu et un connecteur en PULL rendent le refus d'une source push.
        let (statut, corps) = rcdl_corps(
            connector_create(
                State(st.clone()),
                Extension(rcdl_adm()),
                Json(json!({ "type": "http_pull", "name": "pull-rcdl-secret", "secret": "credential-pull-rcdl",
                             "config": { "url": "https://api.exemple.invalid/journal", "records_path": "", "field_map": { "message": "$.m" } } })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : connecteur en PULL : {corps}");
        let id_pull = corps["id"].as_i64().expect("identifiant");
        let jetons_avant = rcdl_compte(&st, "SELECT COUNT(*) FROM token");
        for (cas, cible) in [("identifiant inconnu", 9_999), ("connecteur en PULL", id_pull)] {
            let (statut, corps) = rcdl_renouveler(&st, sans(), rcdl_adm(), cible).await;
            assert_eq!((statut, &corps["cause"]), (403, &json!(CAUSE_SECRET_DES_GESTES_ABSENT)), "{cas} : sans le secret, le refus d'une source push — ni 404 ni 400 : {corps}");
            assert!(rcdl_aucune_cle_montree(&corps), "{cas} : {corps}");
        }
        assert_eq!(rcdl_compte(&st, "SELECT COUNT(*) FROM token"), jetons_avant, "aucun jeton écrit sans le secret");

        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id).await;
        assert_eq!(statut, 200, "contrôle positif : le bon secret, le renouvellement a lieu : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.26-g` — SEULE UNE SOURCE PUSH PORTE UNE CLÉ ; LE DROIT EST EXIGÉ ; UNE SOURCE SANS CLÉ EN RETROUVE UNE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT :
    ///  * un connecteur en PULL (`http_pull`, créé par la route réelle avec son credential) : 400 qui porte le refus nommé
    ///    et le type lu, aucun jeton écrit, son credential intact ;
    ///  * un identifiant inconnu : 404, rien n'est écrit ;
    ///  * un éditeur et un lecteur : 403, rien n'est écrit (la route vérifie le droit elle-même, en plus du routeur) ;
    ///  * une source push restée SANS clé (celle dont la clé jamais servie est partie avec son auteur) : 200,
    ///    `cles_revoquees = 0`, et la clé neuve est servie sur ce connecteur — le cas qu'aucune route ne couvrait.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (jouées) : frapper une clé quel que soit le type du connecteur (retirer la garde
    /// `livraison_d_une_source_push`) — le connecteur en PULL reçoit une clé `firehose` ; retirer la vérification du droit
    /// dans la route — l'éditeur renouvelle la clé.
    #[tokio::test]
    async fn rcdl_seule_une_source_push_porte_une_cle_et_le_droit_est_exige() {
        let (st, _p) = sp_state("rcdl-garde");
        let (statut, corps) = rcdl_corps(
            connector_create(
                State(st.clone()),
                Extension(rcdl_adm()),
                Json(json!({ "type": "http_pull", "name": "pull-rcdl", "secret": "credential-pull-rcdl",
                             "config": { "url": "https://api.exemple.invalid/journal", "records_path": "", "field_map": { "message": "$.m" } } })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : connecteur en PULL : {corps}");
        let id_pull = corps["id"].as_i64().expect("identifiant");
        let credential = |st: &AppState| -> String {
            st.db.lock().query_row("SELECT secret FROM connector WHERE id=?1", params![id_pull], |r| r.get(0)).expect("fixture : credential lu")
        };
        let credential_avant = credential(&st);

        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id_pull).await;
        assert_eq!(statut, 400, "{corps}");
        let refus = corps["error"].as_str().unwrap_or_default();
        assert!(refus.starts_with(REFUS_CLE_DE_LIVRAISON_HORS_SOURCE_PUSH) && refus.contains("« http_pull »"), "le refus nommé et le type lu : {corps}");
        assert_eq!(rcdl_compte(&st, "SELECT COUNT(*) FROM token"), 0, "aucun jeton écrit");
        assert_eq!(credential(&st), credential_avant, "le credential du connecteur en PULL est intact");

        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), 9_999).await;
        assert_eq!(statut, 404, "{corps}");
        assert_eq!(rcdl_compte(&st, "SELECT COUNT(*) FROM token"), 0, "rien n'est écrit");

        let (id, ancienne) = rcdl_source_push(&st, "gcp-audit", "gcp-rcdl", "prod").await;
        for role in ["editor", "viewer"] {
            let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), sp_au("ed", role), id).await;
            assert_eq!(statut, 403, "{role} : {corps}");
            assert!(rcdl_aucune_cle_montree(&corps), "{role} : {corps}");
            assert!(pubsub_token_lookup(&st, &ancienne).is_some(), "{role} : l'ancienne clé authentifie toujours");
        }

        st.db.lock().execute("DELETE FROM token WHERE connector_id=?1", params![id]).expect("fixture : la source perd sa clé");
        let (statut, corps) = rcdl_renouveler(&st, crate::secret_des_gestes::presente_de_test(), rcdl_adm(), id).await;
        assert_eq!((statut, &corps["cles_revoquees"]), (200, &json!(0)), "une source sans clé en retrouve une : {corps}");
        let neuve = corps["delivery_token"].as_str().expect("clé montrée").to_string();
        assert_eq!(pubsub_token_lookup(&st, &neuve).map(|i| i.connector_id), Some(id), "servie sur ce connecteur");
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.26-f` — CHAQUE GENRE SERVI TEL QU'IL EST ÉCRIT ; NULL RESTE « agent »
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sept lignes `token` de genres différents, écrites comme leurs voies les écrivent (la ligne de
    /// commande laisse `kind` NULL). `tokens_list` sert `agent` pour NULL (défaut historique du CLI) et pour `agent`,
    /// et le genre ÉCRIT pour chacun des autres — `gcp_pubsub` compris, et un genre qu'aucune voie ne frappe encore
    /// (`genre_futur_rcdl`), dit par son nom au lieu d'être maquillé en agent. Une clé de livraison porte le connecteur
    /// qu'elle alimente (`connector_id`) ; les autres jetons n'en portent aucun. Aucun secret ni empreinte n'est servi.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR (jouées) : rétablir le `match` fermé et son `_ => "agent"` — `gcp_pubsub` et
    /// `genre_futur_rcdl` sortent « agent » ; servir `kind` brut sans le repli de NULL (témoin NÉGATIF) — le jeton de la
    /// ligne de commande sort `null`.
    #[tokio::test]
    async fn rcdl_l_inventaire_sert_le_genre_ecrit_de_chaque_jeton() {
        let (st, _p) = sp_state("rcdl-genres");
        {
            let c = st.db.lock();
            c.execute_batch(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id,created) VALUES(41,'gcp_pubsub','gcp-rcdl',1,'{}','',300,'prod',1);\
                 INSERT INTO token(name,token_hash,created,host) VALUES('cli-rcdl','h-cli',1,'db01');\
                 INSERT INTO token(name,token_hash,created,kind) VALUES('agent-rcdl','h-agent',2,'agent');\
                 INSERT INTO token(name,token_hash,created,kind) VALUES('hec-rcdl','h-hec',3,'hec');\
                 INSERT INTO token(name,token_hash,created,kind,role) VALUES('ds-rcdl','h-ds',4,'datasource','viewer');\
                 INSERT INTO token(name,token_hash,created,kind) VALUES('client-rcdl','h-client',5,'client');\
                 INSERT INTO token(name,token_hash,created,kind,connector_id) VALUES('gcp_pubsub-41','h-gcp',6,'gcp_pubsub',41);\
                 INSERT INTO token(name,token_hash,created,kind) VALUES('futur-rcdl','h-futur',7,'genre_futur_rcdl');",
            )
            .expect("fixture : sept jetons");
        }
        let (statut, corps) = rcdl_corps(tokens_list(State(st.clone()), Extension(rcdl_adm())).await).await;
        assert_eq!(statut, 200, "{corps}");
        assert!(corps.get("error").is_none(), "l'inventaire est lu : {corps}");
        let lus: Vec<(String, String, Value)> = corps["tokens"]
            .as_array()
            .expect("liste des jetons")
            .iter()
            .map(|t| (t["name"].as_str().unwrap_or("?").to_string(), t["kind"].as_str().unwrap_or("(non textuel)").to_string(), t["connector_id"].clone()))
            .collect();
        let attendus: Vec<(String, String, Value)> = [
            ("cli-rcdl", "agent", Value::Null),
            ("agent-rcdl", "agent", Value::Null),
            ("hec-rcdl", "hec", Value::Null),
            ("ds-rcdl", "datasource", Value::Null),
            ("client-rcdl", "client", Value::Null),
            ("gcp_pubsub-41", "gcp_pubsub", json!(41)),
            ("futur-rcdl", "genre_futur_rcdl", Value::Null),
        ]
        .into_iter()
        .map(|(n, k, c)| (n.to_string(), k.to_string(), c))
        .collect();
        assert_eq!(lus, attendus, "chaque genre servi tel qu'il est écrit, NULL -> agent : {corps}");
        let rendu = corps.to_string();
        assert!(!rendu.contains("h-gcp") && !rendu.contains("token_hash"), "ni empreinte ni colonne d'empreinte servies : {corps}");
    }
}
