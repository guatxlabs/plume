// =====================================================================================
// `P10.31-u` (reste AG : neuf lignes `[session] WARN` de `session.rs` nommaient le compte ou l'administrateur),
// `P10.20-l` (reste, `handlers/incidents.rs` : lectures de la ligne d'un runbook et du dossier d'une déclaration lues
// comme une absence) et `P10.29-l` (reste, `handlers/incidents.rs` : texte du moteur servi au client).
//
// LE DÉFAUT, MESURÉ SUR 1287fb98 AVANT LE CORRECTIF.
//   * `session.rs` : `live_role_si_l_epoque_du_compte_vaut`, `compte_live` (deux lignes), `compte_via_l_ecrivain`,
//     `frapper_la_session_du_compte`, `l_epoque_du_compte_vaut` écrivaient `compte '<nom>'` ; `logout_post` écrivait
//     `déconnexion globale par '<nom de l'administrateur>'` (deux lignes) et `déconnexion de '<nom>'`.
//   * `incidents.rs` : `runbook_delete` et `runbook_set_enabled` lisaient `name,managed` par `Err(_) => 404` ; une lecture
//     ratée du drapeau `managed` (qui ARME le 400 du runbook managé) rendait « runbook introuvable ».
//     `update_custom_runbook` : `.map_err(|_| "runbook introuvable")`, servi en 400 de saisie. `incident_apply_tier` :
//     `.is_err()` -> `DossierIntrouvable`. `case_step_set` servait `CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT (<texte du moteur>)`
//     en 503 ; `runbook_delete` et `runbook_set_enabled` servaient `échec transaction: <texte du moteur>` en 500.
//
// LE CORRECTIF (décisions par défaut de la vague AH).
//   * Journal : `compte #<id>` par `compte_au_journal` là où une connexion est déjà en main (`compte_via_l_ecrivain`
//     passe le verrou qu'il tient) ou le verrou prouvé libre (les trois lignes de `logout_post`, prise neuve pour la
//     ligne seule) ; ailleurs — la lecture du compte ou de son époque vient d'échouer, ou l'appelant peut tenir le verrou
//     non réentrant —, la phrase FIXE `compte (identifiant non lu)`, sans relecture. Jamais le nom. Statuts, corps et
//     ordre des vérifications inchangés ; la cause du moteur reste au journal.
//   * Runbooks : la ligne lue en `.optional()` — lue, la porte suit ; absente, le refus d'avant à l'octet (404, ou 400
//     pour la modification) ; lecture ratée, 503 nommé (`CAUSE_RUNBOOK_NON_SUPPRIME_NON_LU`,
//     `CAUSE_ACTIVATION_DU_RUNBOOK_INCHANGEE_NON_LUE`, `CAUSE_RUNBOOK_INCHANGE_NON_LU`), phrase seule, jamais le 400 du
//     managé, rien d'écrit ; la cause du moteur au journal avec l'identifiant de corrélation servi. Les deux 500 servent
//     `PHRASE_ECHEC_TRANSACTION_AUDIT` (`servir_l_echec_de_la_transaction_d_audit`, statut inchangé).
//   * `incident_apply_tier` : dossier non lu -> `NonEcrite`, rien n'est écrit. `case_step_set` : la phrase seule, la
//     cause du moteur au journal avec l'identifiant de corrélation.
//
// LES PANNES ÉPROUVÉES : époque du compte illisible (texte), puis en BLOB (rôle et époque non lus sur les deux voies) ;
// `user.hash` en BLOB (mode 1) ; autorisateur SQLite qui refuse la lecture d'une table (`engagement_grant`, `user`,
// `case_step`, `incident`) ; déclencheurs `RAISE(ABORT)` sur `ledger` et sur `meta` ; `runbook.managed` en BLOB. Lignes de
// journal lues sur le stderr d'un sous-processus, chacune ENTIÈRE, par égalité ; corps de refus comparés EN ENTIER.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE. Production, le nom rendu au site :
// `AH1_S135`, `AH1_S186`, `AH1_S197`, `AH1_S262`, `AH1_S348`, `AH1_S380`, `AH1_S1422`, `AH1_S1426`, `AH1_S1440` ; la phrase
// fixe à la place de `compte_au_journal` : `AH1_S262_FIXE`, `AH1_S1422_FIXE`, `AH1_S1426_FIXE`, `AH1_S1440_FIXE`.
// `incidents.rs` : la forme d'avant au site (`AH1_I129`, `AH1_I989`, `AH1_I1258`, `AH1_I1469`, `AH1_I1498`, `AH1_I1486`,
// `AH1_I1513`) ; la ligne de journal retirée (`AH1_I989_SANS_JOURNAL`, `AH1_I1258_SANS_JOURNAL`,
// `AH1_I1469_SANS_JOURNAL`, `AH1_I1498_SANS_JOURNAL`) ; l'absence servie comme une lecture ratée (`AH1_I1258_ABSENT`,
// `AH1_I1469_ABSENT`, `AH1_I1498_ABSENT`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode 1 aux sites qui disent `compte #<id>` (la ligne `user` lue est celle de
// `st.db`) ; le bras `Ok(n)` de `persister_l_epoque_de_session` (une ligne au plus) ; la lecture de `name,managed` de
// `runbook_delete`/`runbook_set_enabled` reste HORS de la transaction du geste (le `DELETE … AND managed=0` retient le
// managé). Restes nommés : `refus_d_ecriture_de_runbook` sert encore la cause du moteur dans ses deux 503 d'avant (plafond
// non lu, étapes non écrites — affirmée par les témoins `etr_`) et dans les 400 d'une ligne `runbook` refusée ;
// `incident_set` sert `({cause})` de `NonEcrite`.
// =====================================================================================
mod compte_de_session_au_journal_et_runbook_non_lu {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Les noms des comptes : aucune sortie du témoin ne doit les porter.
    const AH1_PORTEUR: &str = "ah1porteur";
    const AH1_ADMIN: &str = "ah1admin";
    const AH1_ASSISTANT: &str = "ah1assistant";
    const AH1_CRED_SUFFIXE: &str = "ah1credential";
    const AH1_ANALYSTE: &str = "ah1analyste";
    const AH1_PASSE: &str = "motdepasse12345";
    const AH1_EPOQUE_ILLISIBLE: &str = "ah1-illisible";
    const AH1_MOTEUR_REGISTRE: &str = "ah1 registre refuse";
    const AH1_MOTEUR_EPOQUE: &str = "ah1 epoque refusee";
    const AH1_MOTEUR_AVANCEE: &str = "ah1 avancee refusee";
    const AH1_RUNBOOK_INTROUVABLE: &str = "runbook introuvable";
    const AH1_MANAGE_NON_SUPPRIMABLE: &str = "runbook managé (git) : non supprimable — désactivez-le ou clonez-le";
    const AH1_MANAGE_NON_MODIFIABLE: &str = "runbook managé (git) : non modifiable en place — clonez pour personnaliser";

    fn ah1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn ah1_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ah1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    fn ah1_refuser_la_lecture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ah1_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    async fn ah1_deconnexion(st: &AppState, jeton: &str, portee: Option<&str>) -> (u16, Value) {
        let mut en_tetes = axum::http::HeaderMap::new();
        en_tetes.insert(header::COOKIE, format!("plume_session={jeton}").parse().expect("en-tête"));
        if let Some(p) = portee {
            en_tetes.insert(PORTEE_DE_LA_DECONNEXION, p.parse().expect("en-tête"));
        }
        ah1_reponse(logout_post(State(st.clone()), en_tetes).await).await
    }

    fn ah1_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session frappée"))
    }

    fn ah1_corps_runbook(nom: &str) -> Value {
        json!({ "name": nom, "match_kind": "*", "steps": [{ "phase": "triage", "title": "regarder", "step_kind": "manual" }] })
    }

    /// Un 5xx nommé : le corps ENTIER est `{error: <cause>, id: <identifiant>}` ; rend l'identifiant servi.
    fn ah1_cinq_cents(quoi: &str, (statut, corps): &(u16, Value), attendu: u16, cause: &str) -> String {
        assert_eq!(*statut, attendu, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule, sans texte du moteur : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    /// LES LIGNES DE JOURNAL ET LES RÉPONSES, lues sur la sortie d'un sous-processus : chaque site atteint écrit sa ligne
    /// ENTIÈRE, l'identifiant interne ou la phrase fixe à la place du nom ; statuts et corps des refus EN ENTIER ; contrôles
    /// (absences, managé, nominal) au statut et au corps d'avant, sans ligne ; rien n'est écrit sur un refus ; aucun nom
    /// de compte nulle part dans la sortie. MUTATIONS : `AH1_S*`, `AH1_I*` (voir l'en-tête).
    #[tokio::test]
    async fn ah1_lignes_de_journal() {
        const ENFANT: &str = "AH1_ENFANT_JOURNAL";
        const PHASE: &str = "AH1-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("ah1-journal");
            let cred = format!("{}{AH1_CRED_SUFFIXE}", crate::handlers::engagement::ENG_CRED_PREFIX);
            for (n, r) in [(AH1_PORTEUR, "editor"), (AH1_ADMIN, "admin"), (cred.as_str(), "viewer")] {
                st.db
                    .lock()
                    .execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![n, hash_pw(AH1_PASSE).unwrap(), r])
                    .expect("fixture : compte posé");
            }
            *st.admin.lock() = Some((AH1_ASSISTANT.to_string(), hash_pw(AH1_PASSE).unwrap()));
            let cle = cle_de_l_epoque_du_compte(AH1_PORTEUR);
            let mut causes = serde_json::Map::new();
            let mut sortie = serde_json::Map::new();

            // L'époque du compte illisible : trois sites qui ne relisent pas le compte.
            eprintln!("{PHASE}s135");
            st.db.lock().execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![cle, AH1_EPOQUE_ILLISIBLE]).expect("fixture");
            sortie.insert("s135".into(), json!(live_role_si_l_epoque_du_compte_vaut(&st, AH1_PORTEUR, 0)));
            eprintln!("{PHASE}s380");
            sortie.insert("s380".into(), json!(l_epoque_du_compte_vaut(&st, AH1_PORTEUR, 0)));
            eprintln!("{PHASE}s348");
            let refus = frapper_la_session_du_compte(&st, AH1_PORTEUR, "editor").err().expect("fixture : aucune session frappée");
            sortie.insert("s348".into(), json!(ah1_reponse(refus).await));
            causes.insert("epoque".into(), json!(epoque_du_compte(&st.db.lock(), AH1_PORTEUR).expect_err("fixture").to_string()));

            // Rôle et époque non lus sur le read pool ET sur l'écrivain (valeur BLOB).
            eprintln!("{PHASE}s186");
            st.db.lock().execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1, x'00')", params![cle]).expect("fixture");
            sortie.insert("s186".into(), json!(live_role_for(&st, AH1_PORTEUR)));
            st.db.lock().execute("DELETE FROM meta WHERE key=?1", params![cle]).expect("fixture");

            // Mode 1 : le compte non lu au plan de contrôle (`user.hash` en BLOB).
            eprintln!("{PHASE}s197");
            let mut st1 = st.clone();
            st1.multi_tenant = true;
            ah1_sql(&st, &format!("UPDATE user SET hash=x'00' WHERE name='{AH1_PORTEUR}';"));
            sortie.insert("s197".into(), json!(live_role_for(&st1, AH1_PORTEUR)));
            let cause = st.db.lock().query_row("SELECT hash, role FROM user WHERE name=?1", params![AH1_PORTEUR], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            });
            causes.insert("plan".into(), json!(cause.expect_err("fixture : hash illisible").to_string()));
            st.db.lock().execute("UPDATE user SET hash=?1 WHERE name=?2", params![hash_pw(AH1_PASSE).unwrap(), AH1_PORTEUR]).expect("fixture");

            // La fenêtre d'un credential d'engagement non lue (lecture de `engagement_grant` refusée sur l'écrivain).
            eprintln!("{PHASE}s262");
            ah1_refuser_la_lecture(&st, "engagement_grant");
            sortie.insert("s262".into(), json!(live_role_for(&st, &cred)));
            let cause = crate::handlers::engagement::engagement_cred_within_window(&st.db.lock(), &cred, now());
            causes.insert("fenetre".into(), json!(cause.expect_err("fixture : fenêtre refusée").to_string()));
            ah1_lever(&st);

            // Déconnexion globale : le maillon refusé (compte en table, puis administrateur de l'assistant sans ligne).
            eprintln!("{PHASE}s1422");
            let jeton_admin = ah1_session(&st, AH1_ADMIN, "admin");
            ah1_sql(&st, &format!("CREATE TRIGGER ah1_registre BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_REGISTRE}'); END;"));
            sortie.insert("s1422".into(), json!(ah1_deconnexion(&st, &jeton_admin, Some("globale")).await));
            eprintln!("{PHASE}s1422_sans_ligne");
            let jeton_assistant = ah1_session(&st, AH1_ASSISTANT, "admin");
            sortie.insert("s1422_sans_ligne".into(), json!(ah1_deconnexion(&st, &jeton_assistant, Some("globale")).await));
            ah1_sql(&st, "DROP TRIGGER ah1_registre;");

            // Déconnexion globale : l'époque globale non persistée.
            eprintln!("{PHASE}s1426");
            ah1_sql(&st, &format!(
                "CREATE TRIGGER ah1_epoque_i BEFORE INSERT ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_EPOQUE}'); END; \
                 CREATE TRIGGER ah1_epoque_u BEFORE UPDATE ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_EPOQUE}'); END;"
            ));
            sortie.insert("s1426".into(), json!(ah1_deconnexion(&st, &jeton_admin, Some("globale")).await));
            ah1_sql(&st, "DROP TRIGGER ah1_epoque_i; DROP TRIGGER ah1_epoque_u;");

            // Déconnexion du compte : l'époque du compte non avancée ; puis la même, la ligne `user` non lue.
            eprintln!("{PHASE}s1440");
            let jeton_porteur = ah1_session(&st, AH1_PORTEUR, "editor");
            ah1_sql(&st, &format!(
                "CREATE TRIGGER ah1_avancee_i BEFORE INSERT ON meta WHEN NEW.key='{cle}' BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_AVANCEE}'); END; \
                 CREATE TRIGGER ah1_avancee_u BEFORE UPDATE ON meta WHEN NEW.key='{cle}' BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_AVANCEE}'); END;"
            ));
            sortie.insert("s1440".into(), json!(ah1_deconnexion(&st, &jeton_porteur, None).await));
            eprintln!("{PHASE}s1440_non_lu");
            ah1_refuser_la_lecture(&st, "user");
            sortie.insert("s1440_non_lu".into(), json!(ah1_deconnexion(&st, &jeton_porteur, None).await));
            ah1_lever(&st);
            ah1_sql(&st, "DROP TRIGGER ah1_avancee_i; DROP TRIGGER ah1_avancee_u;");

            // Le nominal : rôle résolu, déconnexion du compte prise, aucune ligne.
            eprintln!("{PHASE}calme_session");
            sortie.insert("calme_role".into(), json!(live_role_si_l_epoque_du_compte_vaut(&st, AH1_PORTEUR, 0)));
            sortie.insert("calme_deconnexion".into(), json!(ah1_deconnexion(&st, &jeton_porteur, None).await));

            // ---- incidents.rs ----
            let ed = sp_au("alice", "editor");
            let adm = sp_au("adm", "admin");
            let dossier = dossier_seme(&st.db.lock(), "alice", "ah1", 3, "", None, 2);
            let etape = {
                let c = st.db.lock();
                c.execute(
                    "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,step_kind,status) VALUES(?1,1,1,1,'triage','regarder','manual','pending')",
                    params![dossier],
                )
                .expect("fixture : étape posée");
                c.last_insert_rowid()
            };

            eprintln!("{PHASE}i989");
            ah1_refuser_la_lecture(&st, "case_step");
            let r = case_step_set(State(st.clone()), Extension(ed.clone()), Path((dossier, etape)), Json(json!({ "status": "done" }))).await;
            sortie.insert("i989".into(), json!(ah1_reponse(r).await));
            let cause = st.db.lock().query_row("SELECT 1 FROM case_step WHERE id=?1 AND incident_id=?2", params![etape, dossier], |_| Ok(()));
            causes.insert("etape".into(), json!(cause.expect_err("fixture : lecture refusée").to_string()));
            ah1_lever(&st);
            sortie.insert("i989_statut".into(), json!(st.db.lock().query_row("SELECT status FROM case_step WHERE id=?1", params![etape], |r| r.get::<_, String>(0)).expect("fixture")));

            eprintln!("{PHASE}i129");
            ah1_refuser_la_lecture(&st, "incident");
            let (issue, cause) = {
                let c = st.db.lock();
                let issue = incident_apply_tier(&c, dossier, AH1_ANALYSTE, Some(2), Some("ah1-type"), None);
                (issue, c.query_row("SELECT 1 FROM incident WHERE id=?1", params![dossier], |_| Ok(())).expect_err("fixture").to_string())
            };
            ah1_lever(&st);
            sortie.insert("i129".into(), json!(format!("{issue:?}")));
            causes.insert("dossier".into(), json!(cause));
            let absent = incident_apply_tier(&st.db.lock(), dossier + 9_999, AH1_ANALYSTE, Some(2), None, None);
            sortie.insert("i129_absent".into(), json!(format!("{absent:?}")));
            sortie.insert("i129_palier".into(), json!(ah1_entier(&st, &format!("SELECT COALESCE(incident_tier,-1) FROM incident WHERE id={dossier}"))));

            // Runbooks : un custom (une étape) et un managé.
            ah1_sql(&st, "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('custom-ah1','ah1-rb','*','','',0,1,0); \
                          INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('ah1-gere','ah1-gere','*','','',1,1,0);");
            let rb = ah1_entier(&st, "SELECT id FROM runbook WHERE key='custom-ah1'");
            let gere = ah1_entier(&st, "SELECT id FROM runbook WHERE key='ah1-gere'");
            ah1_sql(&st, &format!("INSERT INTO runbook_step(runbook_id,ordinal,phase,title,step_kind) VALUES({rb},0,'triage','regarder','manual');"));
            let absent_rb = rb + gere + 9_999;
            let etat_rb = |st: &AppState| -> Value {
                st.db
                    .lock()
                    .query_row(
                        "SELECT name, active, (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1) FROM runbook WHERE id=?1",
                        params![rb],
                        |r| Ok(json!([r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?])),
                    )
                    .unwrap_or_else(|e| json!(format!("absent : {e}")))
            };

            eprintln!("{PHASE}r_controles");
            let mut controles: Vec<(u16, Value)> = Vec::new();
            controles.push(ah1_reponse(runbook_delete(State(st.clone()), Extension(adm.clone()), Path(absent_rb)).await).await);
            controles.push(ah1_reponse(runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(absent_rb), Json(json!({ "enabled": false }))).await).await);
            controles.push(ah1_reponse(runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(absent_rb), Json(ah1_corps_runbook("ah1-renomme"))).await).await);
            controles.push(ah1_reponse(runbook_delete(State(st.clone()), Extension(adm.clone()), Path(gere)).await).await);
            controles.push(ah1_reponse(runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(gere), Json(ah1_corps_runbook("ah1-renomme"))).await).await);
            sortie.insert("r_controles".into(), json!(controles));

            ah1_sql(&st, &format!("UPDATE runbook SET managed=x'00' WHERE id={rb};"));
            let cause = st.db.lock().query_row("SELECT name,managed FROM runbook WHERE id=?1", params![rb], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)));
            causes.insert("ligne_du_runbook".into(), json!(cause.expect_err("fixture : managed illisible").to_string()));
            let cause = st.db.lock().query_row("SELECT managed FROM runbook WHERE id=?1", params![rb], |r| r.get::<_, i64>(0));
            causes.insert("managed".into(), json!(cause.expect_err("fixture : managed illisible").to_string()));
            eprintln!("{PHASE}r_suppression");
            sortie.insert("r_suppression".into(), json!(ah1_reponse(runbook_delete(State(st.clone()), Extension(adm.clone()), Path(rb)).await).await));
            eprintln!("{PHASE}r_bascule");
            let r = runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rb), Json(json!({ "enabled": false }))).await;
            sortie.insert("r_bascule".into(), json!(ah1_reponse(r).await));
            eprintln!("{PHASE}r_modification");
            let r = runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(rb), Json(ah1_corps_runbook("ah1-renomme"))).await;
            sortie.insert("r_modification".into(), json!(ah1_reponse(r).await));
            ah1_sql(&st, &format!("UPDATE runbook SET managed=0 WHERE id={rb};"));
            sortie.insert("r_etat_apres_non_lu".into(), etat_rb(&st));

            // L'audit refusé (maillon de registre refusé) : la transaction annulée, la phrase fixe.
            ah1_sql(&st, &format!("CREATE TRIGGER ah1_registre BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT,'{AH1_MOTEUR_REGISTRE}'); END;"));
            eprintln!("{PHASE}r_audit_bascule");
            let r = runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rb), Json(json!({ "enabled": false }))).await;
            sortie.insert("r_audit_bascule".into(), json!(ah1_reponse(r).await));
            eprintln!("{PHASE}r_audit_suppression");
            sortie.insert("r_audit_suppression".into(), json!(ah1_reponse(runbook_delete(State(st.clone()), Extension(adm.clone()), Path(rb)).await).await));
            ah1_sql(&st, "DROP TRIGGER ah1_registre;");
            sortie.insert("r_etat_apres_audit".into(), etat_rb(&st));

            eprintln!("{PHASE}r_nominal");
            let mut nominal: Vec<(u16, Value)> = Vec::new();
            nominal.push(ah1_reponse(runbook_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rb), Json(json!({ "enabled": false }))).await).await);
            nominal.push(ah1_reponse(runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(rb), Json(ah1_corps_runbook("ah1-renomme"))).await).await);
            nominal.push(ah1_reponse(runbook_delete(State(st.clone()), Extension(adm.clone()), Path(rb)).await).await);
            sortie.insert("r_nominal".into(), json!(nominal));
            sortie.insert("r_restants".into(), json!(ah1_entier(&st, &format!("SELECT COUNT(*) FROM runbook WHERE id={rb}"))));
            eprintln!("{PHASE}fin");

            let compte = |nom: &str| -> i64 {
                st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : identifiant")
            };
            let ids = json!({ "porteur": compte(AH1_PORTEUR), "admin": compte(AH1_ADMIN), "cred": compte(&cred), "dossier": dossier, "etape": etape, "rb": rb });
            println!("AH1-SORTIE:{}", Value::Object(sortie));
            println!("AH1-CAUSES:{}", Value::Object(causes));
            println!("AH1-IDS:{ids}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::compte_de_session_au_journal_et_runbook_non_lu::ah1_lignes_de_journal"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Value {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : {m} JSON ({e}) : {stdout}"))
        };
        let (s, causes, ids) = (marque("AH1-SORTIE:"), marque("AH1-CAUSES:"), marque("AH1-IDS:"));
        let cause = |k: &str| -> String { causes[k].as_str().unwrap_or_else(|| panic!("contrôle : cause {k} : {causes}")).to_string() };
        let id = |k: &str| -> i64 { ids[k].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant {k} : {ids}")) };
        let reponse = |k: &str| -> (u16, Value) {
            let v = &s[k];
            (v[0].as_u64().unwrap_or_else(|| panic!("contrôle : statut de {k} : {v}")) as u16, v[1].clone())
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[session]") || l.contains("[incidents]") || l.contains("[runbooks]")).map(str::to_string).collect()
        };
        let non_relu = "compte (identifiant non lu)";
        let (porteur, admin, cred) = (format!("compte #{}", id("porteur")), format!("compte #{}", id("admin")), format!("compte #{}", id("cred")));

        // ---- session.rs : statuts et corps d'avant, ligne ENTIÈRE par site ----
        assert_eq!((&s["s135"], &s["s380"], &s["s186"], &s["s197"], &s["s262"]), (&Value::Null, &json!(false), &Value::Null, &Value::Null, &Value::Null), "contrôle : refus d'avant");
        ah1_cinq_cents("session non frappée", &reponse("s348"), 503, CAUSE_EPOQUE_DU_COMPTE_NON_LUE);
        ah1_cinq_cents("déconnexion globale non tracée", &reponse("s1422"), 503, CAUSE_DECONNEXION_GLOBALE_NON_TRACEE);
        ah1_cinq_cents("déconnexion globale non tracée (assistant)", &reponse("s1422_sans_ligne"), 503, CAUSE_DECONNEXION_GLOBALE_NON_TRACEE);
        ah1_cinq_cents("déconnexion globale non persistée", &reponse("s1426"), 503, CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE);
        for k in ["s1440", "s1440_non_lu"] {
            assert_eq!(reponse(k), (503, json!({ "error": CAUSE_REVOCATION_DU_COMPTE_NON_ECRITE })), "{k} : corps d'avant");
        }
        assert_eq!(s["calme_role"], json!("editor"), "nominal : rôle résolu");
        assert_eq!(reponse("calme_deconnexion"), (200, json!({ "ok": true, "portee": "compte" })), "nominal : déconnexion prise");
        let epoque = cause("epoque");
        let attendues: [(&str, Vec<String>); 11] = [
            ("s135", vec![format!("[session] WARN époque du {non_relu} NON lue, session refusée : {epoque}")]),
            ("s380", vec![format!("[session] WARN époque du {non_relu} NON lue, session refusée : {epoque}")]),
            ("s348", vec![format!("[session] WARN époque du {non_relu} NON lue, aucune session frappée : {epoque}")]),
            ("s186", vec![format!("[session] WARN {non_relu} NON lu (read pool et écrivain), identité refusée")]),
            ("s197", vec![format!("[session] WARN {non_relu} NON lu au plan de contrôle, identité refusée : {}", cause("plan"))]),
            (
                "s262",
                vec![
                    format!("[session] WARN fenêtre d'engagement du credential du {cred} NON lue : {}", cause("fenetre")),
                    format!("[session] WARN {non_relu} NON lu (read pool et écrivain), identité refusée"),
                ],
            ),
            ("s1422", vec![format!("[session] WARN déconnexion globale par le {admin} NON tracée, rien n'est révoqué : {AH1_MOTEUR_REGISTRE}")]),
            (
                "s1422_sans_ligne",
                vec![format!("[session] WARN déconnexion globale par le compte sans ligne `user` NON tracée, rien n'est révoqué : {AH1_MOTEUR_REGISTRE}")],
            ),
            (
                "s1426",
                vec![format!("[session] WARN déconnexion globale par le {admin} : époque NON persistée, rien n'est révoqué : écriture refusée ({AH1_MOTEUR_EPOQUE})")],
            ),
            ("s1440", vec![format!("[session] WARN déconnexion du {porteur} : époque du compte NON avancée : {AH1_MOTEUR_AVANCEE}")]),
            ("s1440_non_lu", vec![format!("[session] WARN déconnexion du {non_relu} : époque du compte NON avancée : {AH1_MOTEUR_AVANCEE}")]),
        ];
        assert!(attendues.len() >= 11, "plancher : onze phases de session");
        for (nom, lignes) in &attendues {
            let nom: &str = nom;
            assert_eq!(&phase(nom), lignes, "phase {nom} : chaque ligne entière, jamais le nom du compte");
        }
        assert!(phase("calme_session").is_empty(), "le nominal n'écrit rien : {stderr}");

        // ---- incidents.rs ----
        let cid = ah1_cinq_cents("étape non lue", &reponse("i989"), 503, crate::handlers::incidents::CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT);
        assert_eq!(
            phase("i989"),
            [format!("[incidents] WARN étape #{} du dossier #{} NON lue, rien n'est écrit ({cid}) : {}", id("etape"), id("dossier"), cause("etape"))],
            "étape non lue : la cause du moteur au journal, avec l'identifiant servi"
        );
        assert_eq!(s["i989_statut"], json!("pending"), "étape non lue : rien n'est écrit");
        assert_eq!(s["i129"], json!(format!("{:?}", DeclarationDIncident::NonEcrite(format!("dossier non lu ({})", cause("dossier"))))), "dossier non lu : jamais introuvable");
        assert_eq!(s["i129_absent"], json!(format!("{:?}", DeclarationDIncident::DossierIntrouvable)), "dossier absent : l'issue d'avant");
        assert_eq!(s["i129_palier"], json!(-1), "dossier non lu : aucun palier écrit");
        assert!(phase("i129").is_empty(), "la déclaration n'écrit rien au journal : {stderr}");

        let controles: Vec<(u16, Value)> = serde_json::from_value(s["r_controles"].clone()).expect("contrôle : réponses");
        assert_eq!(
            controles,
            vec![
                (404, json!({ "error": AH1_RUNBOOK_INTROUVABLE })),
                (404, json!({ "error": AH1_RUNBOOK_INTROUVABLE })),
                (400, json!({ "error": AH1_RUNBOOK_INTROUVABLE })),
                (400, json!({ "error": AH1_MANAGE_NON_SUPPRIMABLE })),
                (400, json!({ "error": AH1_MANAGE_NON_MODIFIABLE })),
            ],
            "absent et managé : statut et corps d'avant, à l'octet"
        );
        assert!(phase("r_controles").is_empty(), "les refus d'avant n'écrivent rien : {stderr}");
        let ligne = cause("ligne_du_runbook");
        let rb = id("rb");
        let cid = ah1_cinq_cents("suppression, runbook non lu", &reponse("r_suppression"), 503, crate::handlers::incidents::CAUSE_RUNBOOK_NON_SUPPRIME_NON_LU);
        assert_eq!(phase("r_suppression"), [format!("[runbooks] WARN runbook #{rb} NON lu pour la suppression, rien n'est supprimé ({cid}) : {ligne}")]);
        let cid = ah1_cinq_cents("bascule, runbook non lu", &reponse("r_bascule"), 503, crate::handlers::incidents::CAUSE_ACTIVATION_DU_RUNBOOK_INCHANGEE_NON_LUE);
        assert_eq!(phase("r_bascule"), [format!("[runbooks] WARN runbook #{rb} NON lu pour la bascule d'activation, rien n'est écrit ({cid}) : {ligne}")]);
        let inchange = crate::handlers::incidents::CAUSE_RUNBOOK_INCHANGE_NON_LU;
        let cid = ah1_cinq_cents("modification, runbook non lu", &reponse("r_modification"), 503, inchange);
        assert_eq!(
            phase("r_modification"),
            [format!("[runbooks] WARN modification d'un runbook refusée, rien n'est écrit ({cid}) : {inchange} ({})", cause("managed"))]
        );
        assert_eq!(s["r_etat_apres_non_lu"], json!(["ah1-rb", 1, 1]), "runbook non lu : ni supprimé, ni basculé, ni modifié");
        let phrase = crate::handlers::users_lookups::PHRASE_ECHEC_TRANSACTION_AUDIT;
        let cid = ah1_cinq_cents("bascule, audit refusé", &reponse("r_audit_bascule"), 500, phrase);
        assert_eq!(
            phase("r_audit_bascule"),
            [format!("[{cid}] [runbooks] WARN bascule d'activation du runbook #{rb} refusé : transaction d'audit annulée, aucune modification ({AH1_MOTEUR_REGISTRE})")]
        );
        let cid = ah1_cinq_cents("suppression, audit refusé", &reponse("r_audit_suppression"), 500, phrase);
        assert_eq!(
            phase("r_audit_suppression"),
            [format!("[{cid}] [runbooks] WARN suppression du runbook #{rb} refusé : transaction d'audit annulée, aucune modification ({AH1_MOTEUR_REGISTRE})")]
        );
        assert_eq!(s["r_etat_apres_audit"], json!(["ah1-rb", 1, 1]), "audit refusé : transaction annulée, rien de changé");
        let nominal: Vec<(u16, Value)> = serde_json::from_value(s["r_nominal"].clone()).expect("contrôle : réponses");
        assert_eq!(
            nominal,
            vec![(200, json!({ "ok": true, "enabled": false })), (200, json!({ "ok": true })), (200, json!({ "ok": true }))],
            "nominal : bascule, modification et suppression prises"
        );
        assert_eq!(s["r_restants"], json!(0), "nominal : le runbook est supprimé");
        assert!(phase("r_nominal").is_empty(), "le nominal n'écrit rien : {stderr}");

        for (canal, texte) in [("stdout", &stdout), ("stderr", &stderr)] {
            for nom in [AH1_PORTEUR, AH1_ADMIN, AH1_ASSISTANT, AH1_CRED_SUFFIXE, AH1_ANALYSTE] {
                assert!(!texte.contains(nom), "{canal} de l'enfant : le nom `{nom}` n'est jamais écrit : {texte}");
            }
        }
    }
}
