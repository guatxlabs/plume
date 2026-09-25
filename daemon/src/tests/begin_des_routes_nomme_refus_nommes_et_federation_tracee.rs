// =====================================================================================
// `P10.28-d` — UNE ROUTE N'OUVRE PLUS SA TRANSACTION PAR UN `BEGIN` NU. `P10.29-a` — LE BANDEAU N'EST ANNONCÉ QU'ÉCRIT.
// `P10.28-c`, `P10.28-q`, `P10.28-r` — LES CANAUX ET LES EXCLUSIONS REFUSENT PAR LA FORME PARTAGÉE. `P10.29-b` — UN
// REFUS PAR FAIT SUR LES ROUTES DES DOSSIERS. `P10.28-v` — LA FÉDÉRATION REFUSÉE EST TRACÉE.
//
// LES DÉFAUTS, MESURÉS LE 2026-09-25 SUR LA FORME D'AVANT (sondes jouées sur l'arbre de `HEAD` avant tout correctif,
// autorisateur SQLite pour refuser un `BEGIN`, un `COMMIT`, une écriture ou une lecture) :
//  * un `BEGIN` refusé rendait un 500 GÉNÉRIQUE — JSON « verrou base indisponible » (quatre-vingts routes), TEXTE (trois),
//    SANS CORPS (deux canaux), deux cents `{error}` (création d'un canal) — et le journal ne disait rien ;
//  * le bandeau : une publication refusée rendait 200 et RENVOYAIT le bandeau comme posé, pendant que le registre
//    attestait « bulletin posé » et qu'aucune ligne n'existait ; un effacement refusé laissait le bandeau affiché à tous
//    les comptes avec « bulletin effacé » au registre ;
//  * les canaux : six formes de refus (200 `{error}`, 500 et 503 sans corps, 400 et 403 nus) ;
//  * les exclusions d'affichage : 400, 500 et 503 en TEXTE ;
//  * les dossiers : une lecture refusée servie comme une absence (404 nu) sur la modification, l'ajout d'élément,
//    l'archivage, la fusion, la déclaration d'incident et les runbooks ; la fusion rendait le même 404 pour cinq faits,
//    l'avancée d'étape rendait 404 pour un statut invalide ;
//  * la fédération (OIDC, SAML, LDAP) refusée sur un compte à mot de passe : aucun maillon, aucun événement.
//
// LA FORME DU JUGEMENT : chaque témoin relève TOUTES les propriétés avant de conclure et nomme celles qui manquent, avec
// le statut et le corps servis — rejoué sur la forme d'avant, il dit le défaut mesuré, pas seulement le premier symptôme.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les quatre sites des fournisseurs d'IA (derrière `--features ai`) sont convertis et
// compilés, mais aucun témoin ne les joue ; `purge_apply` garde son `BEGIN` nu (contrat propre de la purge, clé à venir) ;
// les trois balayages de fond des engagements et les ouvertures hors route (migrations, sauvegarde, tier froid, semis,
// spool) ne sont pas des routes ; la fédération n'est jouée qu'au niveau de son refus (`RefusDeLaFederation::servir`) — le
// câblage des trois portes est tenu par une lecture de source ; le mode multi-tenant n'est pas joué ; aucun module de `web/`
// n'est exercé (les causes neuves sont relues par la forme partagée de la console dans le harnais, témoins 115 et 117).
// =====================================================================================
mod begin_des_routes_nomme_refus_nommes_et_federation_tracee {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    async fn bdrn_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    fn bdrn_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn bdrn_refuser_le_begin(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bdrn_refuser_le_commit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bdrn_refuser_l_ecriture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } if table_name == table => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bdrn_refuser_la_lecture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bdrn_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bdrn_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn bdrn_ecrire(st: &AppState, sql: &str) -> i64 {
        let c = st.db.lock();
        c.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
        c.last_insert_rowid()
    }

    /// Les écritures faites par l'écrivain partagé depuis son ouverture : un geste qui n'écrit rien ne le fait pas bouger.
    fn bdrn_ecritures(st: &AppState) -> i64 {
        bdrn_compte(st, "SELECT total_changes()")
    }

    /// Ce que rend un geste joué sous un autorisateur, levé ensuite.
    struct BdrnRefus {
        statut: u16,
        corps: Value,
        fermee: bool,
        ecritures: i64,
    }

    async fn bdrn_sous(st: &AppState, refuser: impl FnOnce(&AppState), geste: impl std::future::Future<Output = Response>) -> BdrnRefus {
        let avant = bdrn_ecritures(st);
        refuser(st);
        let r = geste.await;
        let fermee = st.db.lock().is_autocommit();
        bdrn_lever(st);
        let ecritures = bdrn_ecritures(st) - avant;
        let (statut, corps) = bdrn_corps(r).await;
        BdrnRefus { statut, corps, fermee, ecritures }
    }

    async fn bdrn_sous_begin_refuse(st: &AppState, geste: impl std::future::Future<Output = Response>) -> BdrnRefus {
        bdrn_sous(st, bdrn_refuser_le_begin, geste).await
    }

    /// Le refus nommé d'un `BEGIN` refusé : 503, la cause du geste, la transaction fermée, RIEN d'écrit.
    fn bdrn_juger_begin(manquent: &mut Vec<String>, quoi: &str, r: &BdrnRefus, cause: &str) {
        for (propriete, tenue) in [
            ("statut 503", r.statut == 503),
            ("cause nommée sous `error`", r.corps["error"] == json!(cause)),
            ("transaction fermée", r.fermee),
            ("rien d'écrit par l'écrivain", r.ecritures == 0),
        ] {
            if !tenue {
                manquent.push(format!("{quoi} : {propriete} — statut {}, corps {}", r.statut, r.corps));
            }
        }
    }

    /// Un refus nommé quelconque : statut attendu et cause qui COMMENCE par la phrase attendue (certaines joignent la cause
    /// du moteur entre parenthèses).
    fn bdrn_juger_refus(manquent: &mut Vec<String>, quoi: &str, (statut, corps): &(u16, Value), attendu: u16, cause: &str) {
        let phrase = corps["error"].as_str().unwrap_or("");
        if *statut != attendu || !phrase.starts_with(cause) {
            manquent.push(format!("{quoi} : attendu {attendu} « {} », servi {statut} {corps}", &cause[..cause.len().min(60)]));
        }
    }

    /// Le refus du rôle : la phrase TEXTE de `rbac_gate`, seule forme que la console lit comme un refus de rôle.
    fn bdrn_juger_refus_du_role(manquent: &mut Vec<String>, quoi: &str, (statut, corps): &(u16, Value)) {
        if *statut != 403 || *corps != json!("réservé à l'administrateur") {
            manquent.push(format!("{quoi} : attendu 403 TEXTE « réservé à l'administrateur », servi {statut} {corps}"));
        }
    }

    fn bdrn_conclure(quoi: &str, manquent: &[String]) {
        assert!(manquent.is_empty(), "{quoi} — {} propriété(s) manquent :\n  * {}", manquent.len(), manquent.join("\n  * "));
    }

    /// Un mot de passe de fixture, composé (jamais un littéral entier : le scanner de secrets de la CI le lirait).
    fn bdrn_mot(graine: &str) -> String {
        format!("motdepasse-{graine}-bdrn-fixture")
    }

    fn bdrn_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    async fn bdrn_creer(quoi: &str, r: Response) -> i64 {
        let (statut, corps) = bdrn_corps(r).await;
        assert_eq!(statut, 200, "fixture : {quoi} est créé(e) : {corps}");
        corps["id"].as_i64().unwrap_or_else(|| panic!("fixture : {quoi} sert un identifiant : {corps}"))
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.29-a` — LE BANDEAU : ÉCRITURE COMPTÉE, TRACE DANS LA MÊME TRANSACTION, SUCCÈS APRÈS LE `COMMIT`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la publication puis l'effacement du bandeau, sous une écriture refusée, un `COMMIT` refusé et un
    /// `BEGIN` refusé — 503 NOMMÉ chaque fois, transaction fermée, le bandeau d'avant intact (à froid et pour ce processus),
    /// aucune ligne `bulletin.set`/`bulletin.clear` au registre. Levé, les corps de succès sont ceux d'avant, octet pour
    /// octet dans leurs clés (`{ok, bulletin}`, `{ok}`, `{ok, bulletin: null}`).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : rendre à `bulletin_set` son `let _ = c.execute(..)` (écriture avalée) — 200 et le
    /// bandeau renvoyé comme posé, « bulletin posé » au registre ; rendre à l'effacement son `let _ =` — 200 et le bandeau
    /// toujours là.
    #[tokio::test]
    async fn bdrn_bulletin_publication_et_effacement_refuses_ne_sont_ni_servis_ni_attestes() {
        let (st, p) = sp_state("bdrn-bulletin");
        let adm = bdrn_adm();
        let poser = |st: &AppState, message: &str| {
            bulletin_set(State(st.clone()), Extension(bdrn_adm()), Json(json!({ "message": message, "level": "warn" })))
        };
        let lignes = "SELECT COUNT(*) FROM setting WHERE scope='global' AND key='bulletin'";
        let publies = "SELECT COUNT(*) FROM ledger WHERE kind='bulletin.set'";
        let effaces = "SELECT COUNT(*) FROM ledger WHERE kind='bulletin.clear'";
        let mut manquent: Vec<String> = Vec::new();

        // PUBLICATION — écriture refusée, COMMIT refusé, BEGIN refusé.
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "setting"), poser(&st, "maintenance 22h")).await;
        bdrn_juger_refus(&mut manquent, "publication, écriture refusée", &(r.statut, r.corps.clone()), 503, CAUSE_BULLETIN_NON_PUBLIE_ECRITURE_REFUSEE);
        if !r.fermee { manquent.push("publication, écriture refusée : transaction ouverte".into()); }
        let r = bdrn_sous(&st, bdrn_refuser_le_commit, poser(&st, "maintenance 22h")).await;
        bdrn_juger_refus(&mut manquent, "publication, COMMIT refusé", &(r.statut, r.corps.clone()), 503, CAUSE_BULLETIN_NON_PUBLIE);
        if !r.fermee { manquent.push("publication, COMMIT refusé : transaction ouverte".into()); }
        let r = bdrn_sous_begin_refuse(&st, poser(&st, "maintenance 22h")).await;
        bdrn_juger_begin(&mut manquent, "publication, BEGIN refusé", &r, CAUSE_BULLETIN_NON_PUBLIE_TRANSACTION_NON_OUVERTE);
        for (propriete, tenue) in [
            ("aucun bandeau à froid", bdrn_a_froid(&p, lignes) == 0),
            ("aucun bandeau pour ce processus", bdrn_compte(&st, lignes) == 0),
            ("aucune publication attestée", bdrn_compte(&st, publies) == 0),
        ] {
            if !tenue { manquent.push(format!("publication refusée : {propriete}")); }
        }

        // CONTRÔLE POSITIF — le corps de succès d'avant.
        let (statut, corps) = bdrn_corps(poser(&st, "maintenance 22h").await).await;
        let cles: Vec<String> = corps["bulletin"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        if statut != 200 || corps["ok"] != json!(true) || corps["bulletin"]["message"] != json!("maintenance 22h")
            || cles != ["level", "message", "updated", "updated_by"] || corps.as_object().map(|o| o.len()) != Some(2)
        {
            manquent.push(format!("publication levée : corps d'avant attendu, servi {statut} {corps}"));
        }
        if bdrn_a_froid(&p, lignes) != 1 || bdrn_compte(&st, publies) != 1 {
            manquent.push("publication levée : le bandeau n'est pas écrit ou pas attesté une fois".into());
        }

        // EFFACEMENT — `DELETE` puis `POST` d'un message vide, sous écriture refusée ; COMMIT et BEGIN refusés.
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "setting"), bulletin_clear(State(st.clone()), Extension(adm.clone()))).await;
        bdrn_juger_refus(&mut manquent, "effacement, écriture refusée", &(r.statut, r.corps.clone()), 503, CAUSE_BULLETIN_NON_EFFACE_ECRITURE_REFUSEE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "setting"), poser(&st, "")).await;
        bdrn_juger_refus(&mut manquent, "effacement par message vide, écriture refusée", &(r.statut, r.corps.clone()), 503, CAUSE_BULLETIN_NON_EFFACE_ECRITURE_REFUSEE);
        let r = bdrn_sous(&st, bdrn_refuser_le_commit, bulletin_clear(State(st.clone()), Extension(adm.clone()))).await;
        bdrn_juger_refus(&mut manquent, "effacement, COMMIT refusé", &(r.statut, r.corps.clone()), 503, CAUSE_BULLETIN_NON_EFFACE);
        if !r.fermee { manquent.push("effacement, COMMIT refusé : transaction ouverte".into()); }
        let r = bdrn_sous_begin_refuse(&st, bulletin_clear(State(st.clone()), Extension(adm.clone()))).await;
        bdrn_juger_begin(&mut manquent, "effacement, BEGIN refusé", &r, CAUSE_BULLETIN_NON_EFFACE_TRANSACTION_NON_OUVERTE);
        for (propriete, tenue) in [
            ("le bandeau est toujours là à froid", bdrn_a_froid(&p, lignes) == 1),
            ("et pour ce processus (tous les comptes le voient)", bdrn_compte(&st, lignes) == 1),
            ("aucun effacement attesté", bdrn_compte(&st, effaces) == 0),
        ] {
            if !tenue { manquent.push(format!("effacement refusé : {propriete}")); }
        }

        // CONTRÔLE POSITIF — les deux corps d'avant.
        let (statut, corps) = bdrn_corps(bulletin_clear(State(st.clone()), Extension(adm.clone())).await).await;
        if statut != 200 || corps != json!({ "ok": true }) || bdrn_a_froid(&p, lignes) != 0 || bdrn_compte(&st, effaces) != 1 {
            manquent.push(format!("effacement levé : attendu 200 {{ok:true}}, bandeau effacé et attesté ; servi {statut} {corps}"));
        }
        let (statut, corps) = bdrn_corps(poser(&st, "").await).await;
        if statut != 200 || corps != json!({ "ok": true, "bulletin": null }) {
            manquent.push(format!("effacement par message vide levé : attendu 200 {{ok:true, bulletin:null}}, servi {statut} {corps}"));
        }
        bdrn_conclure("bandeau", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.28-c`, `P10.28-q` — LES CANAUX DE NOTIFICATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous un `BEGIN` refusé, un `COMMIT` refusé et une écriture refusée, la création, la modification et
    /// la suppression d'un canal rendent un refus JSON NOMMÉ (503 et la cause du geste ; 500 et « échec transaction audit »
    /// avec l'identifiant du 5xx), transaction fermée, rien de changé ; une URL interne est refusée en 400 JSON nommé ; le
    /// rôle en 403 TEXTE de `rbac_gate`. Levé, `{id}`, 204 et 204 — les succès d'avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : rendre à la modification son `StatusCode::SERVICE_UNAVAILABLE` nu sur un `COMMIT`
    /// refusé ; rendre à la création son deux cents `{error}`.
    #[tokio::test]
    async fn bdrn_canaux_de_notification_refusent_par_la_forme_partagee() {
        let (st, p) = sp_state("bdrn-canaux");
        let adm = bdrn_adm();
        let ed = sp_au("alice", "editor");
        let canal = json!({ "kind": "webhook", "url": "http://10.0.0.9/bdrn", "name": "bdrn-canal" });
        let mut manquent: Vec<String> = Vec::new();

        // Le rôle.
        let r = bdrn_corps(notifier_create(State(st.clone()), Extension(ed.clone()), Json(canal.clone())).await).await;
        bdrn_juger_refus_du_role(&mut manquent, "création par un éditeur", &r);
        let r = bdrn_corps(notifier_update(State(st.clone()), Extension(ed.clone()), Path(1), Json(json!({ "name": "x" }))).await).await;
        bdrn_juger_refus_du_role(&mut manquent, "modification par un éditeur", &r);
        let r = bdrn_corps(notifier_delete(State(st.clone()), Extension(ed.clone()), Path(1)).await).await;
        bdrn_juger_refus_du_role(&mut manquent, "suppression par un éditeur", &r);

        // La forme de la demande.
        let r = bdrn_corps(notifier_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "kind": "webhook", "url": "http://127.0.0.1/x" }))).await).await;
        bdrn_juger_refus(&mut manquent, "création vers une cible interne", &r, 400, "URL invalide");

        // La création sous BEGIN, écriture et COMMIT refusés.
        let r = bdrn_sous_begin_refuse(&st, notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal.clone()))).await;
        bdrn_juger_begin(&mut manquent, "création, BEGIN refusé", &r, CAUSE_CANAL_DE_NOTIFICATION_NON_CREE_TRANSACTION_NON_OUVERTE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "notifier"), notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal.clone()))).await;
        bdrn_juger_refus(&mut manquent, "création, écriture refusée", &(r.statut, r.corps.clone()), 500, "échec transaction audit");
        if r.corps["id"].as_str().is_none() || !r.fermee { manquent.push(format!("création, écriture refusée : identifiant du 5xx et transaction fermée attendus — {}", r.corps)); }
        let r = bdrn_sous(&st, bdrn_refuser_le_commit, notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal.clone()))).await;
        bdrn_juger_refus(&mut manquent, "création, COMMIT refusé", &(r.statut, r.corps.clone()), 503, CAUSE_CANAL_DE_NOTIFICATION_NON_CREE);
        if bdrn_a_froid(&p, "SELECT COUNT(*) FROM notifier") != 0 || bdrn_compte(&st, "SELECT COUNT(*) FROM notifier") != 0 {
            manquent.push("création refusée : un canal existe".into());
        }

        // Levé : le succès d'avant.
        let (statut, corps) = bdrn_corps(notifier_create(State(st.clone()), Extension(adm.clone()), Json(canal)).await).await;
        let nid = corps["id"].as_i64().unwrap_or(0);
        if statut != 200 || corps.as_object().map(|o| o.len()) != Some(1) || nid <= 0 {
            manquent.push(format!("création levée : attendu 200 {{id}}, servi {statut} {corps}"));
        }
        let nom = format!("SELECT COUNT(*) FROM notifier WHERE id={nid} AND name='bdrn-canal'");

        let r = bdrn_corps(notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "url": "http://169.254.169.254/" }))).await).await;
        bdrn_juger_refus(&mut manquent, "modification vers une cible interne", &r, 400, "URL invalide");
        for (quoi, refuser, attendu, cause) in [
            ("BEGIN refusé", bdrn_refuser_le_begin as fn(&AppState), 503, CAUSE_CANAL_DE_NOTIFICATION_INCHANGE_TRANSACTION_NON_OUVERTE),
            ("COMMIT refusé", bdrn_refuser_le_commit, 503, CAUSE_CANAL_DE_NOTIFICATION_INCHANGE),
        ] {
            let r = bdrn_sous(&st, refuser, notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "name": "renomme" })))).await;
            bdrn_juger_refus(&mut manquent, &format!("modification, {quoi}"), &(r.statut, r.corps.clone()), attendu, cause);
            if !r.fermee { manquent.push(format!("modification, {quoi} : transaction ouverte")); }
        }
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "notifier"), notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "name": "renomme" })))).await;
        bdrn_juger_refus(&mut manquent, "modification, écriture refusée", &(r.statut, r.corps.clone()), 500, "échec transaction audit");
        for (quoi, refuser, attendu, cause) in [
            ("BEGIN refusé", bdrn_refuser_le_begin as fn(&AppState), 503, CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME_TRANSACTION_NON_OUVERTE),
            ("COMMIT refusé", bdrn_refuser_le_commit, 503, CAUSE_CANAL_DE_NOTIFICATION_NON_SUPPRIME),
        ] {
            let r = bdrn_sous(&st, refuser, notifier_delete(State(st.clone()), Extension(adm.clone()), Path(nid))).await;
            bdrn_juger_refus(&mut manquent, &format!("suppression, {quoi}"), &(r.statut, r.corps.clone()), attendu, cause);
            if !r.fermee { manquent.push(format!("suppression, {quoi} : transaction ouverte")); }
        }
        let r = bdrn_sous(&st, |s| bdrn_refuser_l_ecriture(s, "notifier"), notifier_delete(State(st.clone()), Extension(adm.clone()), Path(nid))).await;
        bdrn_juger_refus(&mut manquent, "suppression, écriture refusée", &(r.statut, r.corps.clone()), 500, "échec transaction audit");
        if bdrn_a_froid(&p, &nom) != 1 || bdrn_compte(&st, &nom) != 1 {
            manquent.push("modification ou suppression refusée : le canal a changé".into());
        }

        // Levé : 204 et 204, sans corps, comme avant.
        let r = bdrn_corps(notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "name": "renomme" }))).await).await;
        if r != (204, Value::Null) { manquent.push(format!("modification levée : attendu 204 sans corps, servi {r:?}")); }
        let r = bdrn_corps(notifier_delete(State(st.clone()), Extension(adm.clone()), Path(nid)).await).await;
        if r != (204, Value::Null) || bdrn_a_froid(&p, "SELECT COUNT(*) FROM notifier") != 0 {
            manquent.push(format!("suppression levée : attendu 204 sans corps et le canal retiré, servi {r:?}"));
        }
        bdrn_conclure("canaux de notification", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.28-r` — LES EXCLUSIONS D'AFFICHAGE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une action inconnue en 400 JSON nommé, un `BEGIN` refusé et un `COMMIT` refusé en 503 JSON nommés
    /// (transaction fermée, aucun réglage écrit) ; le refus du rôle reste la phrase TEXTE de `rbac_gate`. Levé,
    /// `{ok, field, old, new}` comme avant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à la route `(code, msg).into_response()` — les refus redeviennent du texte.
    #[tokio::test]
    async fn bdrn_suppressions_refusent_en_json_nomme() {
        let (st, _p) = sp_state("bdrn-suppressions");
        let adm = bdrn_adm();
        let mut manquent: Vec<String> = Vec::new();
        let editer = |st: &AppState| suppressions_put(State(st.clone()), Extension(bdrn_adm()), Json(json!({ "action": "set_operator_excl", "value": "203.0.113.7" })));
        let r = bdrn_corps(suppressions_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "action": "inconnue" }))).await).await;
        bdrn_juger_refus(&mut manquent, "action inconnue", &r, 400, "action inconnue");
        let r = bdrn_sous_begin_refuse(&st, editer(&st)).await;
        bdrn_juger_begin(&mut manquent, "BEGIN refusé", &r, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE_TRANSACTION_NON_OUVERTE);
        let r = bdrn_sous(&st, bdrn_refuser_le_commit, editer(&st)).await;
        bdrn_juger_refus(&mut manquent, "COMMIT refusé", &(r.statut, r.corps.clone()), 503, CAUSE_EXCLUSION_D_AFFICHAGE_INCHANGEE);
        if !r.fermee { manquent.push("COMMIT refusé : transaction ouverte".into()); }
        let r = bdrn_corps(suppressions_put(State(st.clone()), Extension(sp_au("alice", "editor")), Json(json!({ "action": "clear_self_excl" }))).await).await;
        bdrn_juger_refus_du_role(&mut manquent, "édition par un éditeur", &r);
        let (statut, corps) = bdrn_corps(editer(&st).await).await;
        let cles: Vec<String> = corps.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        if statut != 200 || cles != ["field", "new", "ok", "old"] {
            manquent.push(format!("édition levée : attendu 200 {{ok, field, old, new}}, servi {statut} {corps}"));
        }
        bdrn_conclure("exclusions d'affichage", &manquent);
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.29-b` — LES ROUTES DES DOSSIERS : UN REFUS NOMMÉ PAR FAIT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : modification, ajout et retrait d'élément, archivage, fiche, runbooks, déclaration d'incident et
    /// avancée d'étape — 404 NOMMÉ sur une absence établie (dossier, élément, étape : trois phrases), 503 nommé sur une
    /// lecture refusée (plus jamais un 404), 400 nommé sur une demande mal formée (verdict, statut d'étape), le rôle en 403
    /// TEXTE. Les succès : 204.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `etablir_le_dossier` de `case_update` — la lecture refusée redevient un
    /// 404 ; retirer le jugement du statut de `case_step_set` — le statut invalide redevient un 404.
    #[tokio::test]
    async fn bdrn_dossiers_un_refus_nomme_par_fait() {
        let (st, _p) = sp_state("bdrn-dossiers");
        let (adm, ed) = (bdrn_adm(), sp_au("alice", "editor"));
        let id = dossier_seme(&st.db.lock(), "alice", "A", 3, "", None, 2);
        let absent = id + 9_999;
        let autre = dossier_seme(&st.db.lock(), "alice", "B", 3, "", None, 2);
        let item_d_un_autre = bdrn_ecrire(&st, &format!("INSERT INTO incident_item(incident_id,ts,kind,author,body) VALUES({autre},1,'note','alice','x')"));
        let mut m: Vec<String> = Vec::new();
        use crate::handlers::cases::{
            CAUSE_DOSSIER_INTROUVABLE as INTROUVABLE, CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT as NON_LU, CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER,
            CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT, CAUSE_VERDICT_DE_DOSSIER_REFUSE,
        };
        use crate::handlers::incidents::{CAUSE_ETAPE_ABSENTE_DE_CE_DOSSIER, CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT, CAUSE_STATUT_D_ETAPE_REFUSE};

        // Modification.
        let r = bdrn_corps(case_update(State(st.clone()), Extension(ed.clone()), Path(absent), Json(json!({ "status": "closed" }))).await).await;
        bdrn_juger_refus(&mut m, "modification d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), case_update(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "status": "closed" })))).await;
        bdrn_juger_refus(&mut m, "modification, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);
        let r = bdrn_corps(case_update(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "disposition": "nimporte" }))).await).await;
        bdrn_juger_refus(&mut m, "verdict hors liste", &r, 400, CAUSE_VERDICT_DE_DOSSIER_REFUSE);
        let r = bdrn_corps(case_update(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "priority": 1 }))).await).await;
        if r != (204, Value::Null) { m.push(format!("modification levée : attendu 204, servi {r:?}")); }

        // Ajout d'élément.
        let r = bdrn_corps(case_item_add(State(st.clone()), Extension(ed.clone()), Path(absent), Json(json!({ "body": "n" }))).await).await;
        bdrn_juger_refus(&mut m, "ajout d'élément, dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), case_item_add(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "body": "n" })))).await;
        bdrn_juger_refus(&mut m, "ajout d'élément, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);
        let r = bdrn_corps(case_item_add(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "body": "note bdrn" }))).await).await;
        if r != (204, Value::Null) { m.push(format!("ajout d'élément levé : attendu 204, servi {r:?}")); }
        let item = bdrn_compte(&st, &format!("SELECT id FROM incident_item WHERE incident_id={id} AND body='note bdrn'"));

        // Retrait d'élément : dossier absent, élément absent, élément d'un autre dossier, lecture refusée.
        let r = bdrn_corps(case_item_delete(State(st.clone()), Extension(ed.clone()), Path((absent, item))).await).await;
        bdrn_juger_refus(&mut m, "retrait, dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_corps(case_item_delete(State(st.clone()), Extension(ed.clone()), Path((id, 9_999_999))).await).await;
        bdrn_juger_refus(&mut m, "retrait, élément absent", &r, 404, CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER);
        let r = bdrn_corps(case_item_delete(State(st.clone()), Extension(ed.clone()), Path((id, item_d_un_autre))).await).await;
        bdrn_juger_refus(&mut m, "retrait, élément d'un autre dossier", &r, 404, CAUSE_ELEMENT_ABSENT_DE_CE_DOSSIER);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident_item"), case_item_delete(State(st.clone()), Extension(ed.clone()), Path((id, item)))).await;
        bdrn_juger_refus(&mut m, "retrait, lecture refusée", &(r.statut, r.corps.clone()), 503, CAUSE_ELEMENT_NON_LU_GESTE_NON_FAIT);
        let r = bdrn_corps(case_item_delete(State(st.clone()), Extension(ed.clone()), Path((id, item))).await).await;
        if r != (204, Value::Null) { m.push(format!("retrait levé : attendu 204, servi {r:?}")); }

        // Archivage.
        let r = bdrn_corps(case_archive(State(st.clone()), Extension(ed.clone()), Path(id)).await).await;
        bdrn_juger_refus_du_role(&mut m, "archivage par un éditeur", &r);
        let r = bdrn_corps(case_unarchive(State(st.clone()), Extension(ed.clone()), Path(id)).await).await;
        bdrn_juger_refus_du_role(&mut m, "désarchivage par un éditeur", &r);
        let r = bdrn_corps(case_archive(State(st.clone()), Extension(adm.clone()), Path(absent)).await).await;
        bdrn_juger_refus(&mut m, "archivage d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), case_archive(State(st.clone()), Extension(adm.clone()), Path(id))).await;
        bdrn_juger_refus(&mut m, "archivage, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);

        // Fiche, runbooks, déclaration d'incident.
        let r = bdrn_corps(case_get(State(st.clone()), Extension(ed.clone()), Path(absent)).await).await;
        bdrn_juger_refus(&mut m, "fiche d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_corps(case_runbooks_get(State(st.clone()), Extension(ed.clone()), Path(absent)).await).await;
        bdrn_juger_refus(&mut m, "runbooks d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), case_runbooks_get(State(st.clone()), Extension(ed.clone()), Path(id))).await;
        bdrn_juger_refus(&mut m, "runbooks, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);
        let r = bdrn_corps(incident_set(State(st.clone()), Extension(ed.clone()), Path(absent), Json(json!({ "tier": 2 }))).await).await;
        bdrn_juger_refus(&mut m, "déclaration sur un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), incident_set(State(st.clone()), Extension(ed.clone()), Path(id), Json(json!({ "tier": 2 })))).await;
        bdrn_juger_refus(&mut m, "déclaration, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);

        // Avancée d'étape.
        let etape = bdrn_ecrire(&st, &format!("INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,step_kind,status) VALUES({id},1,1,1,'triage','regarder','manual','pending')"));
        let r = bdrn_corps(case_step_set(State(st.clone()), Extension(ed.clone()), Path((id, etape)), Json(json!({ "status": "nimporte" }))).await).await;
        bdrn_juger_refus(&mut m, "statut d'étape invalide", &r, 400, CAUSE_STATUT_D_ETAPE_REFUSE);
        let r = bdrn_corps(case_step_set(State(st.clone()), Extension(ed.clone()), Path((absent, etape)), Json(json!({ "status": "done" }))).await).await;
        bdrn_juger_refus(&mut m, "étape d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_corps(case_step_set(State(st.clone()), Extension(ed.clone()), Path((autre, etape)), Json(json!({ "status": "done" }))).await).await;
        bdrn_juger_refus(&mut m, "étape d'un autre dossier", &r, 404, CAUSE_ETAPE_ABSENTE_DE_CE_DOSSIER);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "case_step"), case_step_set(State(st.clone()), Extension(ed.clone()), Path((id, etape)), Json(json!({ "status": "done" })))).await;
        bdrn_juger_refus(&mut m, "étape, lecture refusée", &(r.statut, r.corps.clone()), 503, CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT);
        let r = bdrn_corps(case_step_set(State(st.clone()), Extension(ed.clone()), Path((id, etape)), Json(json!({ "status": "done" }))).await).await;
        if r != (204, Value::Null) { m.push(format!("avancée d'étape levée : attendu 204, servi {r:?}")); }
        bdrn_conclure("routes des dossiers", &m);
    }

    /// CE QU'IL TIENT : la fusion, la défusion et le lien — les cinq faits que la fusion confondait sous un 404 nu sont
    /// NOMMÉS et distincts (400 sans cible ou même dossier ; 404 source ou cible absente ; 409 déjà fusionnée ou cycle ;
    /// 503 lecture refusée) ; la défusion : 404 absent, 409 pas fusionné ; le lien : 400 sans cible ou même dossier, 404
    /// dossier absent, 503 lecture refusée ; le retrait sans lien : 404 nommé. Les succès : 204.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `case_merge_handler` sa forme d'avant (`case_merge` seul, 404 nu).
    #[tokio::test]
    async fn bdrn_fusion_et_liens_un_refus_nomme_par_fait() {
        let (st, _p) = sp_state("bdrn-fusion");
        let ed = sp_au("alice", "editor");
        let (a, b, c) = {
            let conn = st.db.lock();
            (dossier_seme(&conn, "alice", "A", 3, "", None, 2), dossier_seme(&conn, "alice", "B", 3, "", None, 2), dossier_seme(&conn, "alice", "C", 3, "", None, 2))
        };
        let absent = c + 9_999;
        let fusion = |st: &AppState, de: i64, corps: Value| case_merge_handler(State(st.clone()), Extension(sp_au("alice", "editor")), Path(de), Json(corps));
        let mut m: Vec<String> = Vec::new();
        use crate::handlers::caseops::{
            CAUSE_AUCUN_LIEN_ENTRE_CES_DOSSIERS, CAUSE_DEFUSION_DOSSIER_NON_FUSIONNE, CAUSE_FUSION_CIBLE_INTROUVABLE,
            CAUSE_FUSION_DANS_LE_MEME_DOSSIER, CAUSE_FUSION_FERMERAIT_UN_CYCLE, CAUSE_FUSION_SANS_CIBLE, CAUSE_FUSION_SOURCE_DEJA_FUSIONNEE,
            CAUSE_LIEN_AVEC_LE_MEME_DOSSIER, CAUSE_LIEN_DOSSIER_INTROUVABLE, CAUSE_LIEN_SANS_CIBLE,
        };
        use crate::handlers::cases::{CAUSE_DOSSIER_INTROUVABLE as INTROUVABLE, CAUSE_DOSSIER_NON_LU_GESTE_NON_FAIT as NON_LU};

        let r = bdrn_corps(fusion(&st, a, json!({})).await).await;
        bdrn_juger_refus(&mut m, "fusion sans cible", &r, 400, CAUSE_FUSION_SANS_CIBLE);
        let r = bdrn_corps(fusion(&st, a, json!({ "into": a })).await).await;
        bdrn_juger_refus(&mut m, "fusion dans le même dossier", &r, 400, CAUSE_FUSION_DANS_LE_MEME_DOSSIER);
        let r = bdrn_corps(fusion(&st, absent, json!({ "into": b })).await).await;
        bdrn_juger_refus(&mut m, "fusion d'une source absente", &r, 404, INTROUVABLE);
        let r = bdrn_corps(fusion(&st, a, json!({ "into": absent })).await).await;
        bdrn_juger_refus(&mut m, "fusion vers une cible absente", &r, 404, CAUSE_FUSION_CIBLE_INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), fusion(&st, a, json!({ "into": b }))).await;
        bdrn_juger_refus(&mut m, "fusion, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);
        let r = bdrn_corps(fusion(&st, a, json!({ "into": b })).await).await;
        if r != (204, Value::Null) { m.push(format!("fusion levée : attendu 204, servi {r:?}")); }
        let r = bdrn_corps(fusion(&st, a, json!({ "into": c })).await).await;
        bdrn_juger_refus(&mut m, "fusion d'une source déjà fusionnée", &r, 409, CAUSE_FUSION_SOURCE_DEJA_FUSIONNEE);
        let r = bdrn_corps(fusion(&st, b, json!({ "into": a })).await).await;
        bdrn_juger_refus(&mut m, "fusion qui fermerait un cycle", &r, 409, CAUSE_FUSION_FERMERAIT_UN_CYCLE);

        let r = bdrn_corps(case_unmerge_handler(State(st.clone()), Extension(ed.clone()), Path(b)).await).await;
        bdrn_juger_refus(&mut m, "défusion d'un dossier non fusionné", &r, 409, CAUSE_DEFUSION_DOSSIER_NON_FUSIONNE);
        let r = bdrn_corps(case_unmerge_handler(State(st.clone()), Extension(ed.clone()), Path(absent)).await).await;
        bdrn_juger_refus(&mut m, "défusion d'un dossier absent", &r, 404, INTROUVABLE);
        let r = bdrn_corps(case_unmerge_handler(State(st.clone()), Extension(ed.clone()), Path(a)).await).await;
        if r != (204, Value::Null) { m.push(format!("défusion levée : attendu 204, servi {r:?}")); }

        let lier = |st: &AppState, de: i64, corps: Value| case_link_handler(State(st.clone()), Extension(sp_au("alice", "editor")), Path(de), Json(corps));
        let r = bdrn_corps(lier(&st, b, json!({})).await).await;
        bdrn_juger_refus(&mut m, "lien sans cible", &r, 400, CAUSE_LIEN_SANS_CIBLE);
        let r = bdrn_corps(lier(&st, b, json!({ "to": b })).await).await;
        bdrn_juger_refus(&mut m, "lien avec le même dossier", &r, 400, CAUSE_LIEN_AVEC_LE_MEME_DOSSIER);
        let r = bdrn_corps(lier(&st, b, json!({ "to": absent })).await).await;
        bdrn_juger_refus(&mut m, "lien vers un dossier absent", &r, 404, CAUSE_LIEN_DOSSIER_INTROUVABLE);
        let r = bdrn_sous(&st, |s| bdrn_refuser_la_lecture(s, "incident"), lier(&st, b, json!({ "to": c }))).await;
        bdrn_juger_refus(&mut m, "lien, lecture refusée", &(r.statut, r.corps.clone()), 503, NON_LU);
        let r = bdrn_corps(case_unlink_handler(State(st.clone()), Extension(ed.clone()), Path((b, c))).await).await;
        bdrn_juger_refus(&mut m, "retrait d'un lien qui n'existe pas", &r, 404, CAUSE_AUCUN_LIEN_ENTRE_CES_DOSSIERS);
        let r = bdrn_corps(lier(&st, b, json!({ "to": c })).await).await;
        if r != (204, Value::Null) { m.push(format!("lien levé : attendu 204, servi {r:?}")); }
        bdrn_conclure("fusion et liens", &m);
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.28-v` — LA FÉDÉRATION REFUSÉE EST TRACÉE COMME LE CHEMIN D'EN-TÊTES
    // -------------------------------------------------------------------------------------

    fn bdrn_traces(st: &AppState, nom: &str) -> (i64, i64) {
        let c = st.db.lock();
        let registre: i64 = c
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse' AND detail LIKE '%''' || ?1 || '''%'", params![nom], |r| r.get(0))
            .expect("registre");
        let evenements: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM event WHERE source='plume-auth' AND json_extract(fields,'$.action')='annuaire_refuse' AND json_extract(fields,'$.username')=?1",
                params![nom],
                |r| r.get(0),
            )
            .expect("événements");
        (registre, evenements)
    }

    /// CE QU'IL TIENT : la fédération refusée sur `bob` (compte `editor` À MOT DE PASSE) — la réponse d'avant (409 texte),
    /// UN maillon `auth.annuaire.refuse` et UN événement `plume-auth` (champs `porte` = `federation_oidc`, `cause`,
    /// `src_ip`), RIEN à l'inventaire des accès ; un second refus dans la fenêtre n'écrit rien ; la même identité refusée à
    /// une AUTRE porte (SAML) est un autre fait, tracé ; un nom non vérifié (lecture du hachage refusée) rend 503 et sa
    /// trace (`non_verifie`) ; une écriture de la ligne fédérée qui échoue n'est pas un refus de nom (rien de tracé) ; la
    /// trace du chemin d'en-têtes est INCHANGÉE (ni `porte` dans ses champs, ni phrase de fédération).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : faire de `RefusDeLaFederation::servir` la seule `reponse()` — aucune trace.
    #[tokio::test]
    async fn bdrn_federation_refusee_tracee_une_fois_par_fenetre() {
        use crate::auth::{tracer_le_refus_de_l_annuaire, PorteDeLAnnuaire, RefusDeLAnnuaire};
        let (st, _p) = sp_state("bdrn-federation");
        let mut m: Vec<String> = Vec::new();
        let refus = federer_le_nom(&st, &st.db.lock(), "bob", "admin").expect_err("fixture : bob porte un mot de passe local");
        let (statut, corps) = bdrn_corps(refus.servir(&st, PorteDeLAnnuaire::Oidc, "203.0.113.9")).await;
        if statut != 409 || !corps.as_str().unwrap_or("").contains("compte local existant") {
            m.push(format!("réponse de la fédération : attendu la réponse d'avant (409 texte), servi {statut} {corps}"));
        }
        if bdrn_traces(&st, "bob") != (1, 1) { m.push(format!("un maillon et un événement attendus, relevé {:?}", bdrn_traces(&st, "bob"))); }
        let champs: Value = st.db.lock()
            .query_row("SELECT fields FROM event WHERE source='plume-auth' AND json_extract(fields,'$.username')='bob'", [], |r| r.get::<_, String>(0))
            .map(|f| serde_json::from_str(&f).unwrap_or(Value::Null))
            .unwrap_or(Value::Null);
        if champs != json!({ "action": "annuaire_refuse", "username": "bob", "cause": "compte_a_mot_de_passe", "src_ip": "203.0.113.9", "porte": "federation_oidc" }) {
            m.push(format!("champs de l'événement : {champs}"));
        }
        if bdrn_compte(&st, "SELECT COUNT(*) FROM acces_observe WHERE nom='bob'") != 0 { m.push("le nom refusé est entré à l'inventaire des accès".into()); }
        let _ = refus.servir(&st, PorteDeLAnnuaire::Oidc, "203.0.113.9");
        if bdrn_traces(&st, "bob") != (1, 1) { m.push(format!("un second refus dans la fenêtre a écrit : {:?}", bdrn_traces(&st, "bob"))); }
        let _ = refus.servir(&st, PorteDeLAnnuaire::Saml, "203.0.113.9");
        if bdrn_traces(&st, "bob") != (2, 2) { m.push(format!("le refus à une autre porte n'est pas tracé : {:?}", bdrn_traces(&st, "bob"))); }

        // Nom non vérifié : la lecture du hachage refusée sur la connexion de la fédération.
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "user", column_name: "hash" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let refus = federer_le_nom(&st, &st.db.lock(), "carol-bdrn", "viewer");
        bdrn_lever(&st);
        match refus {
            Err(refus) => {
                let (statut, corps) = bdrn_corps(refus.servir(&st, PorteDeLAnnuaire::Ldap, "")).await;
                if statut != 503 || corps["error"] != json!(CAUSE_FEDERATION_NOM_NON_VERIFIE) { m.push(format!("nom non vérifié : servi {statut} {corps}")); }
                let cause: Option<String> = st.db.lock()
                    .query_row("SELECT json_extract(fields,'$.cause') FROM event WHERE json_extract(fields,'$.username')='carol-bdrn'", [], |r| r.get(0))
                    .ok();
                if cause.as_deref() != Some("non_verifie") { m.push(format!("nom non vérifié : trace {cause:?}")); }
            }
            Ok(()) => m.push("fixture : la lecture refusée du hachage n'a pas refusé la fédération".into()),
        }

        // Une écriture de la ligne fédérée qui échoue n'est pas un refus de nom.
        let avant = bdrn_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse'");
        let _ = crate::idp::RefusDeLaFederation::Ecriture("écriture refusée (témoin)".into()).servir(&st, PorteDeLAnnuaire::Oidc, "203.0.113.9");
        if bdrn_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='auth.annuaire.refuse'") != avant { m.push("une écriture ratée a été tracée comme un refus de nom".into()); }

        // Le chemin d'en-têtes : trace inchangée.
        tracer_le_refus_de_l_annuaire(&st, &RefusDeLAnnuaire::CompteAMotDePasse("dave-bdrn".into()), "198.51.100.1", PorteDeLAnnuaire::EnTetes);
        let (message, champs): (String, String) = st.db.lock()
            .query_row("SELECT message, fields FROM event WHERE json_extract(fields,'$.username')='dave-bdrn'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("trace du chemin d'en-têtes");
        if message != "identité de l'annuaire 'dave-bdrn' refusée (compte_a_mot_de_passe) depuis 198.51.100.1"
            || serde_json::from_str::<Value>(&champs).unwrap_or(Value::Null)
                != json!({ "action": "annuaire_refuse", "username": "dave-bdrn", "cause": "compte_a_mot_de_passe", "src_ip": "198.51.100.1" })
        {
            m.push(format!("trace du chemin d'en-têtes changée : « {message} » {champs}"));
        }
        bdrn_conclure("fédération refusée", &m);
    }

    /// CE QU'IL TIENT (lecture de source, faute d'IdP jouable dans un témoin) : les TROIS portes de fédération servies
    /// (`oidc_callback`, `saml_acs`, `ldap_login_post`) rendent leur refus par `RefusDeLaFederation::servir`, chacune sous
    /// SA porte, et aucune par la seule `reponse()`, qui ne trace pas.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à l'une des trois portes `return refus.reponse();`.
    #[test]
    fn bdrn_les_trois_portes_de_federation_tracent_leur_refus() {
        let source = include_str!("../handlers/idp.rs");
        let appels = source.matches("federer_le_nom(&st, &conn,").count();
        let portes: Vec<&str> = ["Oidc", "Saml", "Ldap"]
            .into_iter()
            .filter(|p| source.contains(&format!("refus.servir(&st, crate::auth::PorteDeLAnnuaire::{p},")))
            .collect();
        assert_eq!(appels, 3, "trois appels à `federer_le_nom` attendus dans handlers/idp.rs (instrument : la lecture a changé)");
        assert_eq!(portes, ["Oidc", "Saml", "Ldap"], "chaque porte rend son refus par `servir` sous SA porte");
        assert!(!source.contains("refus.reponse()"), "une porte rend son refus sans le tracer (`refus.reponse()`)");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.28-d` — CHAQUE ROUTE CONVERTIE, SOUS UN `BEGIN` REFUSÉ : 503 NOMMÉ, RIEN D'ÉCRIT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : détection (règles, parseurs, suppression gérée, bascule d'activation), routage (politiques,
    /// silences), détection avancée (corrélations, références UEBA), destinations — sous un `BEGIN` refusé, chaque geste
    /// rend 503 et SA cause nommée, la transaction est fermée, l'écrivain n'a rien écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `rule_create` son `BEGIN` nu et son 500 « verrou base indisponible ».
    #[tokio::test]
    async fn bdrn_begin_refuse_detection_routage_et_destinations() {
        let (st, _p) = sp_state("bdrn-begin-detection");
        let adm = bdrn_adm();
        let mut m: Vec<String> = Vec::new();
        let regle = json!({ "name": "bdrn-regle", "query": "search source=auth outcome=fail | stats count", "threshold": 3 });
        let parseur = json!({ "name": "bdrn-parseur", "source": "bdrn", "pattern": "bdrn=(?P<bdrn_champ>\\w+)" });
        let politique = json!({ "matchers": { "host": "web-01" }, "contact_points": [1] });
        let silence = json!({ "matchers": { "host": "web-01" }, "duration_s": 600, "reason": "bdrn" });
        let correlation = json!({ "name": "bdrn-corr", "key_field": "src_ip", "entity_type": "ip", "window_s": 3600,
            "steps": [{ "name": "s1", "query": "search source=auth outcome=fail", "min_count": 3 },
                      { "name": "s2", "query": "search source=auth outcome=success", "min_count": 1 }] });
        let reference = json!({ "name": "bdrn-base", "query": "search source=auth | stats count by host", "entity_field": "host", "entity_type": "host" });
        let sortie = json!({ "type": "webhook", "name": "bdrn-sortie", "endpoint": "http://10.0.0.9/bdrn", "enabled": true });

        let rid = bdrn_creer("la règle", rule_create(State(st.clone()), Extension(adm.clone()), Json(regle.clone())).await).await;
        let pid = bdrn_creer("le parseur", parser_create(State(st.clone()), Extension(adm.clone()), Json(parseur.clone())).await).await;
        let geree = bdrn_ecrire(&st, "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                                     VALUES('bdrn-geree',1,'search source=auth | stats count',1,'>',0,2,300,3600,2)");
        let polid = bdrn_creer("la politique", policy_create(State(st.clone()), Extension(adm.clone()), Json(politique.clone())).await).await;
        let sid = bdrn_creer("le silence", silence_create(State(st.clone()), Extension(adm.clone()), Json(silence.clone())).await).await;
        let cid = bdrn_creer("la corrélation", correlation_create(State(st.clone()), Extension(adm.clone()), Json(correlation.clone())).await).await;
        let bid = bdrn_creer("la référence", baseline_create(State(st.clone()), Extension(adm.clone()), Json(reference.clone())).await).await;
        let did = bdrn_creer("la destination", destination_create(State(st.clone()), Extension(adm.clone()), Json(sortie.clone())).await).await;

        macro_rules! jouer {
            ($quoi:expr, $cause:expr, $geste:expr) => {{
                let r = bdrn_sous_begin_refuse(&st, $geste).await;
                bdrn_juger_begin(&mut m, $quoi, &r, $cause);
            }};
        }
        jouer!("création de règle", CAUSE_REGLE_NON_CREEE_TRANSACTION_NON_OUVERTE, rule_create(State(st.clone()), Extension(adm.clone()), Json(regle)));
        jouer!("modification de règle", CAUSE_REGLE_INCHANGEE_TRANSACTION_NON_OUVERTE, rule_update(State(st.clone()), Extension(adm.clone()), Path(rid), Json(json!({ "threshold": 9 }))));
        jouer!("création de parseur", CAUSE_PARSEUR_NON_CREE_TRANSACTION_NON_OUVERTE, parser_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-p2", "source": "bdrn", "pattern": "x=(?P<x_y>\\w+)" }))));
        jouer!("modification de parseur", CAUSE_PARSEUR_INCHANGE_TRANSACTION_NON_OUVERTE, parser_update(State(st.clone()), Extension(adm.clone()), Path(pid), Json(json!({ "pattern": "b2=(?P<b_z>\\w+)" }))));
        jouer!("suppression gérée", CAUSE_SUPPRESSION_DE_CONTENU_NON_VALIDEE_TRANSACTION_NON_OUVERTE, rule_delete(State(st.clone()), Extension(adm.clone()), Path(geree)));
        jouer!("bascule d'activation", CAUSE_ACTIVATION_DE_CONTENU_INCHANGEE_TRANSACTION_NON_OUVERTE, rule_set_enabled(State(st.clone()), Extension(adm.clone()), Path(geree), Json(json!({ "enabled": false }))));
        jouer!("création de politique", CAUSE_POLITIQUE_DE_NOTIFICATION_NON_CREEE_TRANSACTION_NON_OUVERTE, policy_create(State(st.clone()), Extension(adm.clone()), Json(politique)));
        jouer!("modification de politique", CAUSE_POLITIQUE_DE_NOTIFICATION_INCHANGEE_TRANSACTION_NON_OUVERTE, policy_update(State(st.clone()), Extension(adm.clone()), Path(polid), Json(json!({ "matchers": { "host": "web-02" }, "contact_points": [2] }))));
        jouer!("suppression de politique", CAUSE_POLITIQUE_DE_NOTIFICATION_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE, policy_delete(State(st.clone()), Extension(adm.clone()), Path(polid)));
        jouer!("pose de silence", CAUSE_SILENCE_NON_POSE_TRANSACTION_NON_OUVERTE, silence_create(State(st.clone()), Extension(adm.clone()), Json(silence)));
        jouer!("modification de silence", CAUSE_SILENCE_INCHANGE_TRANSACTION_NON_OUVERTE, silence_update(State(st.clone()), Extension(adm.clone()), Path(sid), Json(json!({ "reason": "autre" }))));
        jouer!("levée de silence", CAUSE_SILENCE_NON_LEVE_TRANSACTION_NON_OUVERTE, silence_delete(State(st.clone()), Extension(adm.clone()), Path(sid)));
        jouer!("création de corrélation", CAUSE_CORRELATION_NON_CREEE_TRANSACTION_NON_OUVERTE, correlation_create(State(st.clone()), Extension(adm.clone()), Json(correlation)));
        jouer!("modification de corrélation", CAUSE_CORRELATION_INCHANGEE_TRANSACTION_NON_OUVERTE, correlation_update(State(st.clone()), Extension(adm.clone()), Path(cid), Json(json!({ "severity": 5 }))));
        jouer!("création de référence UEBA", CAUSE_REFERENCE_UEBA_NON_CREEE_TRANSACTION_NON_OUVERTE, baseline_create(State(st.clone()), Extension(adm.clone()), Json(reference)));
        jouer!("modification de référence UEBA", CAUSE_REFERENCE_UEBA_INCHANGEE_TRANSACTION_NON_OUVERTE, baseline_update(State(st.clone()), Extension(adm.clone()), Path(bid), Json(json!({ "severity": 4 }))));
        jouer!("création de destination", CAUSE_DESTINATION_NON_CREEE_TRANSACTION_NON_OUVERTE, destination_create(State(st.clone()), Extension(adm.clone()), Json(sortie)));
        jouer!("modification de destination", CAUSE_DESTINATION_INCHANGEE_TRANSACTION_NON_OUVERTE, destination_update(State(st.clone()), Extension(adm.clone()), Path(did), Json(json!({ "enabled": false }))));
        jouer!("suppression de destination", CAUSE_DESTINATION_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE, destination_delete(State(st.clone()), Extension(adm.clone()), Path(did)));
        bdrn_conclure("BEGIN refusé : détection, routage, destinations", &m);
    }

    /// CE QU'IL TIENT : runbooks (garde `Txn`), imports Sigma, indicateurs, règles d'ingestion, playbooks, politiques
    /// d'index — sous un `BEGIN` refusé, 503 nommé, transaction fermée, rien d'écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `runbook_create` son `match Txn::begin(&conn) { …, Err(_) => return
    /// server_err("verrou base indisponible") }`.
    #[tokio::test]
    async fn bdrn_begin_refuse_runbooks_imports_ingestion_et_index() {
        let (st, _p) = sp_state("bdrn-begin-runbooks");
        let adm = bdrn_adm();
        let mut m: Vec<String> = Vec::new();
        let runbook = |nom: &str| json!({ "name": nom, "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] });
        let doc = |titre: &str| json!({ "title": titre, "logsource": { "service": "sshd" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" }, "level": "medium" });
        let paquet = json!({ "bundle": { "type": "bundle", "id": "bundle--bdrn", "objects": [
            { "type": "indicator", "id": "indicator--bdrn", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '198.51.100.77']" }] } });
        let regle_ing = json!({ "name": "bdrn-jeter", "match_field": "category", "match_op": "eq", "match_value": "bdrn", "action": "drop" });
        let pb = json!({ "name": "bdrn-pb", "query": "search source=auth outcome=fail | stats count by src_ip", "action_kind": "ban_ip" });
        let index = json!({ "name": "bdrn-index", "retention_days": 30 });

        let rbid = bdrn_creer("le runbook", runbook_create(State(st.clone()), Extension(adm.clone()), Json(runbook("bdrn-runbook"))).await).await;
        let prid = bdrn_creer("la règle d'ingestion", processor_create(State(st.clone()), Extension(adm.clone()), Json(regle_ing.clone())).await).await;
        let pbid = bdrn_creer("le playbook", playbook_create(State(st.clone()), Extension(adm.clone()), Json(pb.clone())).await).await;
        let ixid = bdrn_creer("la politique d'index", index_policy_create(State(st.clone()), Extension(adm.clone()), Json(index.clone())).await).await;

        macro_rules! jouer {
            ($quoi:expr, $cause:expr, $geste:expr) => {{
                let r = bdrn_sous_begin_refuse(&st, $geste).await;
                bdrn_juger_begin(&mut m, $quoi, &r, $cause);
            }};
        }
        jouer!("création de runbook", CAUSE_RUNBOOK_NON_CREE_TRANSACTION_NON_OUVERTE, runbook_create(State(st.clone()), Extension(adm.clone()), Json(runbook("bdrn-autre"))));
        jouer!("modification de runbook", CAUSE_RUNBOOK_INCHANGE_TRANSACTION_NON_OUVERTE, runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(rbid), Json(runbook("bdrn-renomme"))));
        jouer!("bascule de runbook", CAUSE_ACTIVATION_DU_RUNBOOK_INCHANGEE_TRANSACTION_NON_OUVERTE, runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rbid), Json(json!({ "enabled": false }))));
        jouer!("clonage de runbook", CAUSE_RUNBOOK_NON_CLONE_TRANSACTION_NON_OUVERTE, runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path(rbid), Json(json!({ "name": "bdrn-copie" }))));
        jouer!("suppression de runbook", CAUSE_RUNBOOK_NON_SUPPRIME_TRANSACTION_NON_OUVERTE, runbook_delete(State(st.clone()), Extension(adm.clone()), Path(rbid)));
        jouer!("import Sigma", CAUSE_IMPORT_SIGMA_NON_ECRIT_TRANSACTION_NON_OUVERTE, sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [doc("bdrn sigma")] }))));
        jouer!("import Sigma en masse", CAUSE_IMPORT_SIGMA_EN_MASSE_NON_ECRIT_TRANSACTION_NON_OUVERTE, sigma_import_bulk(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [doc("bdrn masse")] }))));
        jouer!("ajout d'indicateur", CAUSE_INDICATEURS_NON_AJOUTES_TRANSACTION_NON_OUVERTE, ioc_add(State(st.clone()), Extension(adm.clone()), Json(json!({ "type": "ip", "value": "203.0.113.77" }))));
        jouer!("import STIX", CAUSE_IMPORT_STIX_NON_ECRIT_TRANSACTION_NON_OUVERTE, stix_import(State(st.clone()), Extension(adm.clone()), Json(paquet)));
        jouer!("création de règle d'ingestion", CAUSE_REGLE_D_INGESTION_NON_CREEE_TRANSACTION_NON_OUVERTE, processor_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-j2", "match_field": "category", "match_op": "eq", "match_value": "b2", "action": "drop" }))));
        jouer!("modification de règle d'ingestion", CAUSE_REGLE_D_INGESTION_INCHANGEE_TRANSACTION_NON_OUVERTE, processor_update(State(st.clone()), Extension(adm.clone()), Path(prid), Json(json!({ "match_value": "bdrn2" }))));
        jouer!("création de playbook", CAUSE_PLAYBOOK_NON_CREE_TRANSACTION_NON_OUVERTE, playbook_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-pb2", "query": "search source=auth outcome=fail | stats count by src_ip", "action_kind": "ban_ip" }))));
        jouer!("modification de playbook", CAUSE_PLAYBOOK_INCHANGE_TRANSACTION_NON_OUVERTE, playbook_update(State(st.clone()), Extension(adm.clone()), Path(pbid), Json(json!({ "interval_s": 900 }))));
        jouer!("création de politique d'index", CAUSE_POLITIQUE_D_INDEX_NON_CREEE_TRANSACTION_NON_OUVERTE, index_policy_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-index2", "retention_days": 30 }))));
        jouer!("modification de politique d'index", CAUSE_POLITIQUE_D_INDEX_INCHANGEE_TRANSACTION_NON_OUVERTE, index_policy_update(State(st.clone()), Extension(adm.clone()), Path(ixid), Json(json!({ "retention_days": 60 }))));
        bdrn_conclure("BEGIN refusé : runbooks, imports, ingestion, index", &m);
    }

    /// CE QU'IL TIENT : réglages (rétention, hôte, source), modèles de données (quatre étages, créations et
    /// suppressions), objets de savoir (six familles), élagage des overlays, rapports planifiés, actions de workflow —
    /// sous un `BEGIN` refusé, 503 nommé, transaction fermée, rien d'écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `alias_create` son `BEGIN` nu et son 500 « verrou base indisponible ».
    #[tokio::test]
    async fn bdrn_begin_refuse_reglages_modeles_savoir_rapports_et_actions() {
        let (st, _p) = sp_state("bdrn-begin-reglages");
        let adm = bdrn_adm();
        let mut m: Vec<String> = Vec::new();
        let mid = bdrn_creer("le modèle", model_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_modele" }))).await).await;
        let oid = bdrn_creer("l'objet", object_create(State(st.clone()), Extension(adm.clone()), Path(mid), Json(json!({ "name": "bdrn_objet" }))).await).await;
        let fid = bdrn_creer("le champ", field_create(State(st.clone()), Extension(adm.clone()), Path(oid), Json(json!({ "name": "bdrn_champ", "type": "string" }))).await).await;
        let dsid = bdrn_creer("le jeu", dataset_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_jeu", "kind": "search", "soql": "search source=auth" }))).await).await;
        let alias = bdrn_creer("l'alias", alias_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "canonical": "bdrn_canon", "source": "bdrn_src" }))).await).await;
        let calc = bdrn_creer("le calcul", calc_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_calc", "expr": "upper(severity)" }))).await).await;
        let etype = bdrn_creer("le type", eventtype_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_type", "filter": "source=auth" }))).await).await;
        let tag = bdrn_creer("l'étiquette", tag_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "label": "bdrn_tag", "field": "user", "value": "alice" }))).await).await;
        let mac = bdrn_creer("la macro", macro_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_macro", "params": ["src"], "body": "source=$src$" }))).await).await;
        let auto = bdrn_creer("la recherche automatique", auto_lookup_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_lookup", "key_field": "user", "out_cols": ["site"] }))).await).await;
        bdrn_ecrire(&st, "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                          VALUES('bdrn-orpheline',1,'search source=auth | stats count',1,'>',0,2,300,3600,1)");
        let canal = bdrn_ecrire(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('bdrn_canal','webhook',1,'https://example.invalid/h',2,'{}')");
        let rapport = bdrn_ecrire(&st, &format!("INSERT INTO scheduled_report(name,dataset_id,notifier_id) VALUES('bdrn_rapport',{dsid},{canal})"));
        let action = |nom: &str| json!({ "name": nom, "kind": "search", "scope_field": "host", "target": "search host=$field$" });
        let aid = bdrn_creer("l'action", workflow_action_create(State(st.clone()), Extension(adm.clone()), Json(action("bdrn_action"))).await).await;

        macro_rules! jouer {
            ($quoi:expr, $cause:expr, $geste:expr) => {{
                let r = bdrn_sous_begin_refuse(&st, $geste).await;
                bdrn_juger_begin(&mut m, $quoi, &r, $cause);
            }};
        }
        jouer!("réglage de la rétention", CAUSE_RETENTION_INCHANGEE_TRANSACTION_NON_OUVERTE, retention_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "retention_days": 45 }))));
        jouer!("déclaration d'hôte", CAUSE_DECLARATION_D_HOTE_INCHANGEE_TRANSACTION_NON_OUVERTE, host_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "host": "srv-9", "action": "set_attente", "value": "silence_attendu", "motif": "bdrn" }))));
        jouer!("réglage de source", CAUSE_REGLAGES_DE_SOURCE_INCHANGES_TRANSACTION_NON_OUVERTE, source_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "source": "okta", "action": "set_label", "value": "Okta" }))));
        let modele = CAUSE_MODELE_DE_DONNEES_NON_ECRIT_TRANSACTION_NON_OUVERTE;
        jouer!("création de modèle", modele, model_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_modele2" }))));
        jouer!("création d'objet", modele, object_create(State(st.clone()), Extension(adm.clone()), Path(mid), Json(json!({ "name": "bdrn_objet2" }))));
        jouer!("création de champ", modele, field_create(State(st.clone()), Extension(adm.clone()), Path(oid), Json(json!({ "name": "bdrn_champ2", "type": "string" }))));
        jouer!("création de jeu", modele, dataset_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_jeu2", "kind": "search", "soql": "search source=web" }))));
        jouer!("suppression de champ", modele, field_delete(State(st.clone()), Extension(adm.clone()), Path(fid)));
        jouer!("suppression de jeu", modele, dataset_delete(State(st.clone()), Extension(adm.clone()), Path(dsid)));
        jouer!("suppression d'objet", modele, object_delete(State(st.clone()), Extension(adm.clone()), Path(oid)));
        jouer!("suppression de modèle", modele, model_delete(State(st.clone()), Extension(adm.clone()), Path(mid)));
        let objet = CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE;
        jouer!("création d'alias", objet, alias_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "canonical": "bdrn_canon2", "source": "bdrn_src2" }))));
        jouer!("suppression d'alias", objet, alias_delete(State(st.clone()), Extension(adm.clone()), Path(alias)));
        jouer!("création de calcul", objet, calc_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_calc2", "expr": "lower(severity)" }))));
        jouer!("suppression de calcul", objet, calc_delete(State(st.clone()), Extension(adm.clone()), Path(calc)));
        jouer!("création de type", objet, eventtype_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_type2", "filter": "source=web" }))));
        jouer!("suppression de type", objet, eventtype_delete(State(st.clone()), Extension(adm.clone()), Path(etype)));
        jouer!("création d'étiquette", objet, tag_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "label": "bdrn_tag2", "field": "user", "value": "bob" }))));
        jouer!("suppression d'étiquette", objet, tag_delete(State(st.clone()), Extension(adm.clone()), Path(tag)));
        jouer!("création de macro", objet, macro_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_macro2", "params": ["h"], "body": "host=$h$" }))));
        jouer!("suppression de macro", objet, macro_delete(State(st.clone()), Extension(adm.clone()), Path(mac)));
        jouer!("création de recherche automatique", objet, auto_lookup_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_lookup2", "key_field": "host", "out_cols": ["site"] }))));
        jouer!("suppression de recherche automatique", objet, auto_lookup_delete(State(st.clone()), Extension(adm.clone()), Path(auto)));
        jouer!("élagage des overlays", CAUSE_ELAGAGE_DES_OVERLAYS_NON_FAIT_TRANSACTION_NON_OUVERTE, config_overlays_prune(State(st.clone()), Extension(adm.clone())));
        jouer!("création de rapport", CAUSE_RAPPORT_PLANIFIE_NON_CREE_TRANSACTION_NON_OUVERTE, report_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_rapport2", "dataset_id": dsid, "notifier_id": canal }))));
        jouer!("suppression de rapport", CAUSE_RAPPORT_PLANIFIE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE, report_delete(State(st.clone()), Extension(adm.clone()), Path(rapport)));
        jouer!("création d'action", CAUSE_WORKFLOW_ACTION_NON_CREEE_TRANSACTION_NON_OUVERTE, workflow_action_create(State(st.clone()), Extension(adm.clone()), Json(action("bdrn_action2"))));
        jouer!("suppression d'action", CAUSE_WORKFLOW_ACTION_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE, workflow_action_delete(State(st.clone()), Extension(adm.clone()), Path(aid)));
        bdrn_conclure("BEGIN refusé : réglages, modèles, savoir, rapports, actions", &m);
    }

    /// CE QU'IL TIENT : jetons, source push, fournisseurs d'identité, second facteur, engagements et mode, masques de
    /// champ, connecteurs, gels juridiques et puits du registre (dont l'envoi, par le garde `Txn`), comptes et tables
    /// d'enrichissement — sous un `BEGIN` refusé, 503 nommé, transaction fermée, rien d'écrit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `mfa_disable` son `BEGIN` nu (sa cause d'avant, qui n'est pas celle d'un
    /// `BEGIN` refusé).
    #[tokio::test]
    async fn bdrn_begin_refuse_identite_connecteurs_gouvernance_et_comptes() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("bdrn-begin-identite");
        let adm = bdrn_adm();
        let mut m: Vec<String> = Vec::new();
        let oidc: Value = json!({ "issuer": "https://idp.bdrn.example", "client_id": "bdrn", "redirect_uri": "https://plume.bdrn.example/cb" });
        let taxii: Value = json!({ "api_root": "https://taxii.bdrn.example/api", "collection_id": "bdrn" });
        let engagement = json!({ "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "bdrn", "window_end": now() + 3600 });

        let (statut, corps) = bdrn_corps(token_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "ag-bdrn", "kind": "agent", "host": "h-bdrn" }))).await).await;
        assert_eq!(statut, 200, "fixture : jeton frappé : {corps}");
        let idp = bdrn_creer("le fournisseur", idp_provider_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-idp", "kind": "oidc", "enabled": true, "config": oidc.clone() }))).await).await;
        let (statut, corps) = bdrn_corps(engagement_create(State(st.clone()), Extension(adm.clone()), Json(engagement.clone())).await).await;
        assert_eq!(statut, 200, "fixture : engagement créé : {corps}");
        let eid = corps["id"].as_str().expect("identifiant d'engagement").to_string();
        let masque = bdrn_creer("le masque", field_filter_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-masque", "field": "src_user", "action": "hash" }))).await).await;
        let connecteur = bdrn_creer("le connecteur", connector_create(State(st.clone()), Extension(adm.clone()),
            Json(json!({ "type": "taxii2", "name": "bdrn-conn", "enabled": true, "secret": format!("bdrn-{}", "a".repeat(24)), "config": taxii.clone() }))).await).await;
        let gel = bdrn_creer("le gel", legal_hold_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "litige-bdrn", "scope_source": "sshd" }))).await).await;
        let puits = bdrn_creer("le puits", ledger_sink_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "puits-bdrn", "kind": "stdout" }))).await).await;
        let compte = bdrn_creer("le compte", user_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "eve-bdrn", "password": bdrn_mot("eve"), "role": "editor" }))).await).await;
        let (statut, corps) = bdrn_corps(lookup_upload(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_lk", "key_field": "k", "rows": [{ "k": "a", "v": "1" }] }))).await).await;
        assert_eq!(statut, 200, "fixture : table d'enrichissement : {corps}");
        let pair: ConnectInfo<std::net::SocketAddr> = ConnectInfo("127.0.0.1:40000".parse().expect("adresse"));

        macro_rules! jouer {
            ($quoi:expr, $cause:expr, $geste:expr) => {{
                let r = bdrn_sous_begin_refuse(&st, $geste).await;
                bdrn_juger_begin(&mut m, $quoi, &r, $cause);
            }};
        }
        jouer!("frappe de jeton", CAUSE_JETON_NON_FRAPPE_TRANSACTION_NON_OUVERTE, token_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "ag-bdrn2", "kind": "agent", "host": "h-bdrn2" }))));
        jouer!("révocation de jeton", CAUSE_JETON_NON_REVOQUE_TRANSACTION_NON_OUVERTE, token_delete(State(st.clone()), Extension(adm.clone()), Path("ag-bdrn".to_string())));
        jouer!("source push", CAUSE_SOURCE_PUSH_NON_CREEE_TRANSACTION_NON_OUVERTE, connector_push_source(State(st.clone()), Extension(adm.clone()), Json(json!({ "preset_id": "aws-cloudtrail" }))));
        let fournisseur = CAUSE_FOURNISSEUR_D_IDENTITE_INCHANGE_TRANSACTION_NON_OUVERTE;
        jouer!("création de fournisseur", fournisseur, idp_provider_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-idp2", "kind": "oidc", "enabled": false, "config": oidc }))));
        jouer!("modification de fournisseur", fournisseur, idp_provider_update(State(st.clone()), Extension(adm.clone()), Path(idp), Json(json!({ "enabled": false }))));
        jouer!("suppression de fournisseur", fournisseur, idp_provider_delete(State(st.clone()), Extension(adm.clone()), Path(idp)));
        jouer!("désactivation du second facteur", CAUSE_MFA_NON_DESACTIVEE_TRANSACTION_NON_OUVERTE, mfa_disable(State(st.clone()), Extension(adm.clone()), Json(json!({ "code": "000000" }))));
        jouer!("création d'engagement", CAUSE_ENGAGEMENT_NON_CREE_TRANSACTION_NON_OUVERTE, engagement_create(State(st.clone()), Extension(adm.clone()), Json(engagement)));
        jouer!("clôture d'engagement", CAUSE_ENGAGEMENT_NON_CLOS_TRANSACTION_NON_OUVERTE, engagement_end(State(st.clone()), Extension(adm.clone()), Path(eid)));
        jouer!("bascule du mode", CAUSE_MODE_INCHANGE_TRANSACTION_NON_OUVERTE, mode_set(State(st.clone()), Extension(adm.clone()), Json(json!({ "mode": "active" }))));
        let masques = CAUSE_MASQUE_DE_CHAMP_INCHANGE_TRANSACTION_NON_OUVERTE;
        jouer!("pose de masque", masques, field_filter_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn-masque2", "field": "src_ip", "action": "hash" }))));
        jouer!("modification de masque", masques, field_filter_update(State(st.clone()), Extension(adm.clone()), Path(masque), Json(json!({ "action": "redact" }))));
        jouer!("retrait de masque", masques, field_filter_delete(State(st.clone()), Extension(adm.clone()), Path(masque)));
        jouer!("création de connecteur", CAUSE_CONNECTEUR_NON_CREE_TRANSACTION_NON_OUVERTE, connector_create(State(st.clone()), Extension(adm.clone()),
            Json(json!({ "type": "taxii2", "name": "bdrn-conn2", "enabled": true, "secret": format!("bdrn-{}", "b".repeat(24)), "config": taxii }))));
        jouer!("modification de connecteur", CAUSE_CONNECTEUR_INCHANGE_TRANSACTION_NON_OUVERTE, connector_update(State(st.clone()), Extension(adm.clone()), Path(connecteur), Json(json!({ "enabled": false }))));
        jouer!("pose de gel", CAUSE_GEL_JURIDIQUE_NON_POSE_TRANSACTION_NON_OUVERTE, legal_hold_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "litige-bdrn2", "scope_source": "sshd" }))));
        jouer!("levée de gel", CAUSE_GEL_JURIDIQUE_NON_LEVE_TRANSACTION_NON_OUVERTE, legal_hold_release(State(st.clone()), Extension(adm.clone()), Path(gel)));
        jouer!("création de puits", CAUSE_PUITS_DU_REGISTRE_INCHANGE_TRANSACTION_NON_OUVERTE, ledger_sink_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "puits-bdrn2", "kind": "stdout" }))));
        jouer!("suppression de puits", CAUSE_PUITS_DU_REGISTRE_INCHANGE_TRANSACTION_NON_OUVERTE, ledger_sink_delete(State(st.clone()), Extension(adm.clone()), Path(puits)));
        jouer!("envoi vers le puits", CAUSE_ENVOI_DU_PUITS_NON_FAIT, ledger_sink_flush(State(st.clone()), Extension(adm.clone()), Path(puits)));
        jouer!("création de compte", CAUSE_COMPTE_NON_CREE_TRANSACTION_NON_OUVERTE, user_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "fred-bdrn", "password": bdrn_mot("fred"), "role": "viewer" }))));
        jouer!("modification de compte", CAUSE_COMPTE_NON_MODIFIE_TRANSACTION_NON_OUVERTE, user_update(State(st.clone()), pair, Extension(adm.clone()), Path(compte), Json(json!({ "role": "viewer" }))));
        jouer!("suppression de compte", CAUSE_COMPTE_NON_SUPPRIME_TRANSACTION_NON_OUVERTE, user_delete(State(st.clone()), Extension(adm.clone()), Path(compte)));
        let table = CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE_TRANSACTION_NON_OUVERTE;
        jouer!("remplacement de table", table, lookup_upload(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "bdrn_lk", "key_field": "k", "rows": [{ "k": "b", "v": "2" }] }))));
        jouer!("suppression de table", table, lookup_delete(State(st.clone()), Extension(adm.clone()), Path("bdrn_lk".to_string())));
        eng_test_reset();
        bdrn_conclure("BEGIN refusé : identité, connecteurs, gouvernance, comptes", &m);
    }

    /// CE QU'IL TIENT : la SECONDE cause d'un `BEGIN` refusé — la transaction d'un AUTRE geste restée ouverte sur
    /// l'écrivain. Cinq routes de cinq fichiers (savoir, runbooks par le garde `Txn`, rétention, suppression gérée par
    /// l'aide `delete_managed_row_tx`, comptes) rendent chacune son 503 nommé ; la transaction étrangère n'est ni validée
    /// ni annulée par elles (toujours ouverte, son écriture toujours pendante, rien à froid).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à `delete_managed_row_tx` son `BEGIN` nu — 500 générique.
    #[tokio::test]
    async fn bdrn_un_begin_refuse_laisse_intacte_la_transaction_d_un_autre_geste() {
        let (st, p) = sp_state("bdrn-etrangere");
        let adm = bdrn_adm();
        let geree = bdrn_ecrire(&st, "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                                     VALUES('bdrn-geree',1,'search source=auth | stats count',1,'>',0,2,300,3600,2)");
        let mut m: Vec<String> = Vec::new();
        bdrn_ecrire(&st, "BEGIN; INSERT INTO meta(key,value) VALUES('bdrn_etrangere','1');");
        let runbook = json!({ "name": "bdrn-rb", "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] });
        let gestes: Vec<(&str, &str, Response)> = vec![
            ("création d'alias", CAUSE_OBJET_DE_SAVOIR_NON_ECRIT_TRANSACTION_NON_OUVERTE,
             alias_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "canonical": "bdrn_c", "source": "bdrn_s" }))).await),
            ("création de runbook", CAUSE_RUNBOOK_NON_CREE_TRANSACTION_NON_OUVERTE, runbook_create(State(st.clone()), Extension(adm.clone()), Json(runbook)).await),
            ("réglage de la rétention", CAUSE_RETENTION_INCHANGEE_TRANSACTION_NON_OUVERTE,
             retention_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "retention_days": 45 }))).await),
            ("suppression gérée", CAUSE_SUPPRESSION_DE_CONTENU_NON_VALIDEE_TRANSACTION_NON_OUVERTE, rule_delete(State(st.clone()), Extension(adm.clone()), Path(geree)).await),
            ("création de compte", CAUSE_COMPTE_NON_CREE_TRANSACTION_NON_OUVERTE,
             user_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "gus-bdrn", "password": bdrn_mot("gus"), "role": "viewer" }))).await),
        ];
        for (quoi, cause, r) in gestes {
            let r = bdrn_corps(r).await;
            bdrn_juger_refus(&mut m, &format!("{quoi} sous une transaction étrangère"), &r, 503, cause);
        }
        // Chaque relevé prend et rend le verrou de l'écrivain à part (un garde temporaire dans le tableau le tiendrait
        // pendant toute la boucle, et le relevé suivant l'attendrait).
        let ouverte = !st.db.lock().is_autocommit();
        let pendante = bdrn_compte(&st, "SELECT COUNT(*) FROM meta WHERE key='bdrn_etrangere'") == 1;
        let a_froid = bdrn_a_froid(&p, "SELECT COUNT(*) FROM meta WHERE key='bdrn_etrangere'");
        for (propriete, tenue) in [
            ("la transaction étrangère est toujours ouverte (ni validée ni annulée)", ouverte),
            ("son écriture est toujours pendante", pendante),
            ("rien de validé à froid", a_froid == 0),
        ] {
            if !tenue { m.push(propriete.to_string()); }
        }
        if !st.db.lock().is_autocommit() {
            st.db.lock().execute_batch("ROLLBACK").expect("le témoin ferme la transaction qu'il a ouverte");
        }
        bdrn_conclure("BEGIN refusé sous la transaction d'un autre geste", &m);
    }
}
