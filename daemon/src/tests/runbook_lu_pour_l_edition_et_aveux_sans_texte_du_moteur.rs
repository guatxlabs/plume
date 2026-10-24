// =====================================================================================
// `P10.20-b` (rang quatre : `runbook_admin_json`, `handlers/incidents.rs`) et `P10.29-l` (reste : texte du moteur servi
// dans les aveux de la fiche de dossier et de la checklist, `handlers/incidents.rs`).
//
// LE DÉFAUT, MESURÉ SUR 307d4dc3 AVANT LE CORRECTIF.
//   * `runbook_admin_json` lisait la ligne du runbook par `.ok()` ; son seul appelant, `runbook_get` (GET
//     /api/runbooks/{id}, route ADMIN d'ÉDITION), rendait 404 « runbook introuvable » sur une absence COMME sur une
//     lecture ratée. Le formulaire d'édition réenregistre la procédure : un 404 sur une procédure qui existe se lit
//     « à recréer ».
//   * `case_runbooks_json` servait `recommandation_non_etablie` = `CAUSE_RECOMMANDATION_NON_ETABLIE` suivi du texte du
//     moteur (deux sites : fiche du runbook retenu non lue, choix du runbook non lu) et `runbook_attache_non_lu` =
//     `CAUSE_RUNBOOK_ATTACHE_NON_LU` suivi du texte du moteur ; `case_steps_json` servait `runbook_non_lu` de même
//     (étapes lues ou non).
//
// LE CORRECTIF. `runbook_admin_json` rend `Result<Option<_>>` (`.optional()`) : lu, la vue d'édition ; absent, le 404
// d'avant à l'octet ; lecture ratée, 503 `CAUSE_RUNBOOK_NON_LU_POUR_L_EDITION` (phrase seule, identifiant de
// corrélation), la cause du moteur au journal avec `runbook #id`. Les trois aveux gardent leur clé et leur ouverture à
// l'octet ; ce qui suit « Cause : » est une phrase FIXE, et la cause du moteur part au journal avec `dossier #id`.
//
// LES PANNES ÉPROUVÉES, toutes par les données (visibles de toute connexion) : `runbook.managed`, `runbook.description`,
// `runbook.key`, `case_step.runbook_id` et `case_step.title` en BLOB ; une vue qui coiffe `runbook` et rend l'`id` des
// runbooks génériques illisible. Tout passe par le ROUTEUR RÉEL (jeton admin pour l'édition, jeton du rôle le plus
// faible admis — viewer — pour le dossier) ; corps comparés EN ENTIER ; lignes de journal lues sur le stderr d'un
// sous-processus, chacune ENTIÈRE, par égalité.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE : `AK4_RB_OK` (lecture ratée servie
// 404), `AK4_RB_ABSENT` (absence servie 503), `AK4_RB_SANS_JOURNAL`, `AK4_RB_ROLE` (`require_admin` enjambé) ;
// `AK4_I423`, `AK4_I430`, `AK4_I441`, `AK4_I720` (le texte du moteur rendu au corps) et leurs `_SANS_JOURNAL`.
//
// CE QUE CE TÉMOIN NE TIENT PAS : le mode multi-tenant (la lecture est celle de l'écrivain du tenant par défaut) ; ce
// que `web/runbooks.js` peint d'un 503 (il ne s'ouvre pas sur un refus, `catch` -> « chargement échoué », lu, pas joué).
// =====================================================================================
mod runbook_lu_pour_l_edition_et_aveux_sans_texte_du_moteur {
    use super::*;

    const AK4_ENFANT: &str = "AK4_ENFANT_ROUTES";
    const AK4_PHASE: &str = "AK4-PHASE:";
    const AK4_EDITEUR: &str = "ak4editeur";
    const AK4_EDITEUR_PASSE: &str = "ak4editeurpw1234";
    const AK4_ADMIN_IDENT: &str = "root:rootpw1234567";
    const AK4_VIEWER_IDENT: &str = "vwr:viewerpw12345";
    const AK4_404_D_AVANT: &str = "runbook introuvable";

    fn ak4_basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    fn ak4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    /// GET par le routeur réel : statut et corps JSON (texte brut sinon).
    async fn ak4_get(addr: std::net::SocketAddr, chemin: &str, ident: &str) -> (u16, Value) {
        let (code, brut) = router_probe_envoi(addr, "GET", chemin, Some(&ak4_basic(ident)), &[], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        let v = if corps.is_empty() { Value::Null } else { serde_json::from_str(&corps).unwrap_or(Value::String(corps)) };
        (code, v)
    }

    async fn ak4_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    /// Un 503 nommé : le corps ENTIER est `{error: <cause>, id: <identifiant>}` ; rend l'identifiant servi.
    fn ak4_cinq_cent_trois(quoi: &str, (statut, corps): &(u16, Value), cause: &str) -> String {
        assert_eq!(*statut, 503, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    /// L'état des tables des runbooks et du registre, pour juger qu'un refus n'écrit rien.
    fn ak4_etat(st: &AppState) -> String {
        st.db
            .lock()
            .query_row(
                "SELECT (SELECT group_concat(id||':'||key||':'||name||':'||hex(managed)||':'||active, ',') FROM runbook) || '|' || \
                 (SELECT COUNT(*) FROM runbook_step) || '|' || (SELECT COUNT(*) FROM ledger)",
                [],
                |r| r.get::<_, String>(0),
            )
            .expect("fixture : état lu")
    }

    /// La cause du moteur que la lecture de `runbook_admin_json` rencontre (même énoncé, mêmes lectures, même ordre).
    fn ak4_cause_edition(st: &AppState, rb: i64) -> String {
        st.db
            .lock()
            .query_row(
                "SELECT id,key,name,match_kind,match_key,description,managed,active,created,\
                 (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=runbook.id) FROM runbook WHERE id=?1",
                params![rb],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?,
                    ))
                },
            )
            .expect_err("fixture : la ligne du runbook est illisible")
            .to_string()
    }

    /// La cause du moteur que la lecture de `runbook_meta_json` rencontre.
    fn ak4_cause_fiche(st: &AppState, rb: i64) -> String {
        st.db
            .lock()
            .query_row("SELECT id,key,name,match_kind,match_key,description,managed FROM runbook WHERE id=?1", params![rb], |r| {
                Ok((
                    r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?,
                ))
            })
            .expect_err("fixture : la fiche est illisible")
            .to_string()
    }

    /// La cause du moteur que la lecture de `runbook_attache` rencontre.
    fn ak4_cause_attache(st: &AppState, dossier: i64) -> String {
        st.db
            .lock()
            .query_row(
                "SELECT cs.runbook_id FROM case_step cs WHERE cs.incident_id=?1 GROUP BY cs.runbook_id \
                 HAVING COUNT(*) = (SELECT COUNT(*) FROM case_step WHERE incident_id=?1)",
                params![dossier],
                |r| r.get::<_, i64>(0),
            )
            .expect_err("fixture : l'attache est illisible")
            .to_string()
    }

    fn ak4_sans_moteur(quoi: &str, corps: &Value, moteur: &str) {
        assert!(!moteur.is_empty(), "{quoi} : contrôle : la cause du moteur est connue");
        assert!(!corps.to_string().contains(moteur), "{quoi} : le texte du moteur ne part jamais au client : {corps}");
    }

    /// LES TROIS ISSUES DE `runbook_get` ET LES TROIS AVEUX DU DOSSIER, PAR LA ROUTE, AVEC LEUR LIGNE DE JOURNAL.
    /// MUTATIONS : `AK4_*` (voir l'en-tête), chacune rougit une assertion de ce témoin.
    #[tokio::test]
    async fn ak4_trois_issues_de_l_edition_et_aveux_sans_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'enfant et les gestionnaires lisent l'environnement
        if std::env::var(AK4_ENFANT).is_ok() {
            let (st, _base) = router_test_state("ak4-routes");
            st.db
                .lock()
                .execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'editor')", params![AK4_EDITEUR, hash_pw(AK4_EDITEUR_PASSE).unwrap()])
                .expect("fixture : éditeur posé");
            let editeur_ident = format!("{AK4_EDITEUR}:{AK4_EDITEUR_PASSE}");
            // Le runbook à éditer : hors du choix générique (`tactic`), une étape.
            ak4_sql(&st, "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
                          VALUES('custom-ak4','ak4-edition','tactic','ak4-aucune','',0,1,0);");
            let rb: i64 = st.db.lock().query_row("SELECT id FROM runbook WHERE key='custom-ak4'", [], |r| r.get(0)).expect("fixture");
            ak4_sql(&st, &format!("INSERT INTO runbook_step(runbook_id,ordinal,phase,title,step_kind) VALUES({rb},0,'triage','regarder','manual');"));
            let absent = rb + 99_999;
            // Le dossier et son runbook générique ATTACHÉ par le geste réel.
            let (dossier, attache) = lqd_dossier_avec_runbook_attache(&st.db.lock());
            let reco = pick_runbook_id(&st.db.lock(), None, None).expect("fixture : choix lu").expect("fixture : un runbook générique");
            let addr = router_serve(st.clone()).await;
            let chemin = format!("/api/runbooks/{rb}");
            let (fiche_du_dossier, checklist) = (format!("/api/cases/{dossier}/runbooks"), format!("/api/cases/{dossier}/steps"));
            let mut attendus = serde_json::Map::new();

            // ---- runbook_get ----
            eprintln!("{AK4_PHASE}g_nominal");
            let nominal = ak4_get(addr, &chemin, AK4_ADMIN_IDENT).await;
            assert_eq!(nominal.0, 200, "contrôle : lu : {:?}", nominal.1);
            assert_eq!((&nominal.1["name"], nominal.1["step_list"].as_array().map(Vec::len)), (&json!("ak4-edition"), Some(1)), "contrôle : {:?}", nominal.1);
            attendus.insert("g_nominal".into(), json!([]));

            eprintln!("{AK4_PHASE}g_absent");
            assert_eq!(ak4_get(addr, &format!("/api/runbooks/{absent}"), AK4_ADMIN_IDENT).await, (404, json!({ "error": AK4_404_D_AVANT })), "absent : le 404 d'avant, à l'octet");
            attendus.insert("g_absent".into(), json!([]));

            eprintln!("{AK4_PHASE}g_role");
            let refus_role_nominal = ak4_get(addr, &chemin, &editeur_ident).await;
            assert_eq!(refus_role_nominal.0, 403, "le rôle plus faible : 403 : {:?}", refus_role_nominal.1);
            assert_eq!(ak4_get(addr, &format!("/api/runbooks/{absent}"), &editeur_ident).await, refus_role_nominal, "aucun oracle d'existence pour le rôle plus faible");
            attendus.insert("g_role".into(), json!([]));

            eprintln!("{AK4_PHASE}g_non_lu");
            ak4_sql(&st, &format!("UPDATE runbook SET managed=x'00' WHERE id={rb};"));
            let moteur = ak4_cause_edition(&st, rb);
            let avant = ak4_etat(&st);
            let non_lu = ak4_get(addr, &chemin, AK4_ADMIN_IDENT).await;
            let cid = ak4_cinq_cent_trois("édition non lue", &non_lu, crate::handlers::incidents::CAUSE_RUNBOOK_NON_LU_POUR_L_EDITION);
            ak4_sans_moteur("édition non lue", &non_lu.1, &moteur);
            assert_eq!(ak4_etat(&st), avant, "lecture ratée : rien n'est écrit");
            assert_eq!(ak4_get(addr, &chemin, &editeur_ident).await, refus_role_nominal, "lecture ratée : le rôle plus faible garde son 403 d'avant, à l'octet");
            let direct = ak4_reponse(runbook_get(State(st.clone()), Extension(sp_au(AK4_EDITEUR, "editor")), Path(rb)).await).await;
            assert_eq!(direct, (403, json!({ "error": "réservé à l'administrateur" })), "le gestionnaire refuse lui-même le rôle plus faible, avant toute lecture");
            attendus.insert("g_non_lu".into(), json!([format!("[runbooks] WARN runbook #{rb} NON lu pour l'édition, rien n'est servi ({cid}) : {moteur}")]));

            eprintln!("{AK4_PHASE}g_retabli");
            ak4_sql(&st, &format!("UPDATE runbook SET managed=0 WHERE id={rb};"));
            assert_eq!(ak4_get(addr, &chemin, AK4_ADMIN_IDENT).await, nominal, "rétabli : le même geste rend la vue d'édition d'avant");
            attendus.insert("g_retabli".into(), json!([]));

            // ---- case_runbooks_json et case_steps_json, par la route, rôle viewer ----
            eprintln!("{AK4_PHASE}c_nominal");
            let fiche_nominale = ak4_get(addr, &fiche_du_dossier, AK4_VIEWER_IDENT).await;
            let steps_nominales = ak4_get(addr, &checklist, AK4_VIEWER_IDENT).await;
            assert_eq!(fiche_nominale.0, 200, "contrôle : {:?}", fiche_nominale.1);
            assert_eq!(steps_nominales.0, 200, "contrôle : {:?}", steps_nominales.1);
            assert_eq!(fiche_nominale.1["attached_runbook_id"], json!(attache), "contrôle : attache lue : {:?}", fiche_nominale.1);
            assert_eq!(fiche_nominale.1["recommended"]["id"], json!(reco), "contrôle : recommandation lue : {:?}", fiche_nominale.1);
            assert_eq!(steps_nominales.1["runbook"]["id"], json!(attache), "contrôle : fiche de la checklist lue : {:?}", steps_nominales.1);
            for (k, v) in [("recommandation_non_etablie", &fiche_nominale.1), ("runbook_attache_non_lu", &fiche_nominale.1), ("runbook_non_lu", &steps_nominales.1)] {
                assert!(v.get(k).is_none(), "nominal muet ({k}) : {v}");
            }
            attendus.insert("c_nominal".into(), json!([]));

            // La fiche du runbook retenu non lue (`description` illisible : le catalogue `available` tombe aussi).
            eprintln!("{AK4_PHASE}c_fiche");
            ak4_sql(&st, &format!("UPDATE runbook SET description=x'FF' WHERE id={reco};"));
            let moteur = ak4_cause_fiche(&st, reco);
            let servi = ak4_get(addr, &fiche_du_dossier, AK4_VIEWER_IDENT).await;
            let mut attendu = fiche_nominale.1.clone();
            attendu["recommended"] = Value::Null;
            attendu["available"] = json!([]);
            attendu["recommandation_non_etablie"] = json!(format!(
                "{}{}",
                crate::handlers::incidents::CAUSE_RECOMMANDATION_NON_ETABLIE,
                crate::handlers::incidents::PHRASE_FICHE_DU_RUNBOOK_RETENU_NON_LUE
            ));
            assert_eq!(servi, (200, crate::handlers::liste_bornee::corps_de_listes_illisibles(attendu, &["available"])), "fiche retenue non lue : corps entier");
            ak4_sans_moteur("fiche retenue non lue", &servi.1, &moteur);
            attendus.insert(
                "c_fiche".into(),
                json!([format!("[incidents] WARN recommandation de runbook du dossier #{dossier} non établie : runbook #{reco} retenu, fiche NON lue : {moteur}")]),
            );
            ak4_sql(&st, &format!("UPDATE runbook SET description='' WHERE id={reco};"));

            // Le choix du runbook non lu (l'`id` des génériques illisible par une vue).
            eprintln!("{AK4_PHASE}c_choix");
            lqd_id_illisible_pour(&st.db.lock(), "*");
            let moteur = pick_runbook_id(&st.db.lock(), None, None).expect_err("fixture : choix illisible").to_string();
            let servi = ak4_get(addr, &fiche_du_dossier, AK4_VIEWER_IDENT).await;
            let mut attendu = fiche_nominale.1.clone();
            attendu["recommended"] = Value::Null;
            attendu["available"] = json!([]);
            attendu["recommandation_non_etablie"] = json!(format!(
                "{}{}",
                crate::handlers::incidents::CAUSE_RECOMMANDATION_NON_ETABLIE,
                crate::handlers::incidents::PHRASE_CHOIX_DU_RUNBOOK_NON_LU
            ));
            assert_eq!(servi, (200, crate::handlers::liste_bornee::corps_de_listes_illisibles(attendu, &["available"])), "choix non lu : corps entier");
            ak4_sans_moteur("choix non lu", &servi.1, &moteur);
            attendus.insert("c_choix".into(), json!([format!("[incidents] WARN recommandation de runbook du dossier #{dossier} non établie : choix du runbook NON lu : {moteur}")]));
            ak4_sql(&st, "DROP VIEW runbook; ALTER TABLE runbook_reel RENAME TO runbook;");

            // L'attache non lue : la fiche de dossier ET la checklist (étapes lues).
            eprintln!("{AK4_PHASE}c_attache");
            ak4_sql(&st, &format!("UPDATE case_step SET runbook_id=x'FF' WHERE incident_id={dossier};"));
            let moteur = ak4_cause_attache(&st, dossier);
            let aveu = format!("{}{}", crate::handlers::incidents::CAUSE_RUNBOOK_ATTACHE_NON_LU, crate::handlers::incidents::PHRASE_RUNBOOK_ATTACHE_NON_LU);
            let servi = ak4_get(addr, &fiche_du_dossier, AK4_VIEWER_IDENT).await;
            let mut attendu = fiche_nominale.1.clone();
            attendu["attached_runbook_id"] = Value::Null;
            attendu["runbook_attache_non_lu"] = json!(aveu);
            assert_eq!(servi, (200, attendu), "attache non lue (fiche de dossier) : corps entier");
            ak4_sans_moteur("attache non lue (fiche de dossier)", &servi.1, &moteur);
            let servi = ak4_get(addr, &checklist, AK4_VIEWER_IDENT).await;
            let mut attendu = steps_nominales.1.clone();
            attendu["runbook"] = Value::Null;
            attendu["runbook_non_lu"] = json!(aveu);
            assert_eq!(servi, (200, attendu), "attache non lue (checklist) : corps entier");
            ak4_sans_moteur("attache non lue (checklist)", &servi.1, &moteur);
            attendus.insert(
                "c_attache".into(),
                json!([
                    format!("[incidents] WARN runbook attaché du dossier #{dossier} NON lu pour la fiche de dossier : {moteur}"),
                    format!("[incidents] WARN runbook attaché du dossier #{dossier} NON lu pour la checklist : {moteur}"),
                ]),
            );

            // Étapes ET attache non lues : le bras où la checklist sert son aveu de liste à côté.
            eprintln!("{AK4_PHASE}c_etapes");
            ak4_sql(&st, &format!("UPDATE case_step SET title=x'FF' WHERE incident_id={dossier};"));
            let servi = ak4_get(addr, &checklist, AK4_VIEWER_IDENT).await;
            let mut attendu = crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "progress": Value::Null, "runbook": Value::Null }), "steps");
            attendu["runbook_non_lu"] = json!(aveu);
            assert_eq!(servi, (200, attendu), "étapes et attache non lues : corps entier");
            ak4_sans_moteur("étapes et attache non lues", &servi.1, &moteur);
            attendus.insert("c_etapes".into(), json!([format!("[incidents] WARN runbook attaché du dossier #{dossier} NON lu pour la checklist : {moteur}")]));
            ak4_sql(&st, &format!("UPDATE case_step SET runbook_id={attache}, title='Vérifier' WHERE incident_id={dossier};"));

            // La fiche du runbook attaché non lue (étapes lues).
            eprintln!("{AK4_PHASE}c_fiche_checklist");
            let cle: String = st.db.lock().query_row("SELECT key FROM runbook WHERE id=?1", params![attache], |r| r.get(0)).expect("fixture");
            ak4_sql(&st, &format!("UPDATE runbook SET key=x'FF' WHERE id={attache};"));
            let moteur = ak4_cause_fiche(&st, attache);
            let servi = ak4_get(addr, &checklist, AK4_VIEWER_IDENT).await;
            let mut attendu = steps_nominales.1.clone();
            attendu["runbook"] = Value::Null;
            attendu["runbook_non_lu"] = json!(aveu);
            assert_eq!(servi, (200, attendu), "fiche de la checklist non lue : corps entier");
            ak4_sans_moteur("fiche de la checklist non lue", &servi.1, &moteur);
            attendus.insert("c_fiche_checklist".into(), json!([format!("[incidents] WARN runbook attaché du dossier #{dossier} NON lu pour la checklist : {moteur}")]));
            st.db.lock().execute("UPDATE runbook SET key=?1 WHERE id=?2", params![cle, attache]).expect("fixture");

            eprintln!("{AK4_PHASE}c_retabli");
            assert_eq!(ak4_get(addr, &fiche_du_dossier, AK4_VIEWER_IDENT).await, fiche_nominale, "rétabli : la fiche de dossier d'avant");
            assert_eq!(ak4_get(addr, &checklist, AK4_VIEWER_IDENT).await, steps_nominales, "rétabli : la checklist d'avant");
            attendus.insert("c_retabli".into(), json!([]));
            eprintln!("{AK4_PHASE}fin");
            println!("AK4-ATTENDUS:{}", Value::Object(attendus));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::runbook_lu_pour_l_edition_et_aveux_sans_texte_du_moteur::ak4_trois_issues_de_l_edition_et_aveux_sans_texte_du_moteur"])
            .env(AK4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (ses assertions de corps tiennent) : {stdout}\n{stderr}");
        let reste = stdout.split_once("AK4-ATTENDUS:").unwrap_or_else(|| panic!("contrôle : attendus : {stdout}")).1;
        let attendus: serde_json::Map<String, Value> =
            serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : attendus JSON ({e}) : {stdout}"));
        assert!(attendus.len() >= 12, "plancher : douze phases jouées, {} rendues", attendus.len());
        for (nom, lignes) in &attendus {
            let debut = stderr.split_once(&format!("{AK4_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AK4_PHASE).map(|(c, _)| c).unwrap_or(debut);
            let vues: Vec<Value> = corps.lines().filter(|l| l.contains("[runbooks]") || l.contains("[incidents]")).map(|l| json!(l)).collect();
            assert_eq!(&Value::Array(vues), lignes, "phase {nom} : chaque ligne de journal entière, la cause du moteur au journal seul");
        }
    }
}
