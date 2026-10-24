// =====================================================================================
// `P10.29-l` (restes AL : `idp.rs` vers :433, `caseops.rs` vers :97, :105, :163, :191, :1395, `ai.rs` vers :72, :154,
// :168) — LE TEXTE DU MOTEUR NE PART PLUS AU CLIENT DEPUIS LA CRÉATION D'UN FOURNISSEUR D'IDENTITÉ, LE CHRONO SLA
// MULTI-NIVEAU, LA POLITIQUE DE CAVIARDAGE ET LE 501 DE L'ASSISTANT IA.
//
// LE DÉFAUT, MESURÉ SUR 583aa34b AVANT LE CORRECTIF :
// - `idp_provider_create` : `Err(_) => 409 TEXTE « échec de création (nom déjà pris ou audit) — réessayez »` — hors JSON,
//   un nom pris et une trace d'audit refusée confondus sous le même statut ;
// - `sla_apply_policy` / `sla_on_status_change` / `ecriture_du_chrono` : `NonLu(format!("ligne du dossier: {e}"))`,
//   `NonLu(format!("politique de la priorité {p}: {e}"))`, `NonLu(format!("chrono du dossier: {e}"))`,
//   `Refuse(format!("{colonnes}: {e}"))` — le texte du moteur (colonne, motif d'un déclencheur, refus de transaction)
//   servi par le corps de `case_create` (`echeances_multi_niveau_non_lues` / `_non_posees`) et le `reason` du 200 de
//   `sla_policy_upsert` ; `sla_recalcule_la_priorite_bornee` : `liste des cases ILLISIBLE ({e})` dans le même `reason` ;
// - `active_redaction_policy` : `stockee_detail` « … n'a pas pu être lue ({e}) … » et « … ne se décode pas ({e}) … » ;
// - `ai_worker_err` : `if e.contains("non compilé") { 501, e }` — tout texte du worker qui porte ces mots part tel quel.
//   CE N'EST PAS UN STUB SEULEMENT : sous `--features ai` (seul cas où `handlers/ai.rs` compile, le stub
//   n'existe pas), un fournisseur dont l'hôte est irrésoluble et porte ces mots (« http://non compilé.invalid ») fait
//   citer l'hôte par la garde SSRF, et un LECTEUR de l'assistant recevait 501 « backend IA : SSRF: résolution de
//   'non compilé.invalid' impossible (deny): … » — hôte compris, sous un statut faux.
//
// DÉCISIONS (orchestrateur, vague AM) : la création d'un fournisseur d'identité suit `ai_provider_create` — 409 JSON à
// phrase fixe sur la seule violation d'unicité de l'`INSERT` (route administrateur qui lit déjà les noms : aucun oracle
// neuf), tout autre échec de sa transaction en 500 par `servir_l_echec_de_la_transaction_d_audit` ; les causes du
// chrono deviennent des phrases fixes (le moule `{CAUSE} ({cause})` de `cases.rs` reste, seul le détail change), le
// moteur part à une ligne `[caseops] WARN` avec le dossier ; `stockee_detail` à phrase fixe, `stockee_cause` inchangée,
// le moteur à une ligne `[ia] WARN` ; le 501 n'est servi que sur le texte EXACT du stub, à phrase fixe ; tout autre
// texte est un échec du worker (500 à phrase fixe, nature au journal par liste blanche, `P10.29-l` vague AL).
//
// LES TÉMOINS, PAR LE ROUTEUR RÉEL (administrateur pour l'IdP et la politique de caviardage, rôle le plus faible admis :
// éditeur pour les dossiers et l'upsert, lecteur pour l'assistant) :
// (1) `am4_corps_servis_par_la_route` : chaque corps jugé EN ENTIER (clés exactes, phrase, identifiant), transaction
//     fermée et état inchangé après chaque refus, issues parcourues égales à `AM4_ORDRE` ; contrôles positifs : nom
//     libre écrit après un nom pris, création nominale sans aveu, upsert nominal en 204 muet ;
// (2) `am4_journal_des_refus` : le binaire se rejoue en sous-processus, le parent compare EN ENTIER les lignes `[idp]
//     WARN`, `[caseops] WARN` et la ligne `[cases]` du chrono non lu ;
// (3) (feature `ai`) `am4_ia_corps_servis_par_la_route` et `am4_ia_journal` : la politique de caviardage en quatre
//     issues (absente, stockée, BLOB illisible, indécodable), l'assistant sur un hôte « non compilé », le stub exact.
// Pannes : `idp_provider.name` UNIQUE (nom pris), autorisateur SQLite refusant l'INSERT sur `ledger` puis sur
// `idp_provider` ; cellule BLOB SEULE (`sla_policy.ack_target_s` d'une priorité, `incident.ts` d'un dossier,
// `incident.sla_paused_since` d'un dossier, `meta.value` de la politique) ; déclencheur `RAISE(ABORT)` sur `UPDATE OF
// ack_due` / `resolve_due` (d'un seul dossier) ; autorisateur refusant la LECTURE de `incident.merged_into` (la seule
// requête qui la lit est la liste du recalcul).
//
// MUTANTS JOUÉS (par variable d'environnement, retirés avant le commit) : `AM4_IDP_TEXTE`, `AM4_IDP_SANS_ROLLBACK`, `AM4_IDP_TOUT_409`,
// `AM4_IDP_DETECTE_TOUT`, `AM4_IDP_UNIQUE_IGNORE`, `AM4_CS_LIGNE`, `AM4_CS_POLITIQUE`, `AM4_CS_ECRITURE`, `AM4_CS_LISTE`
// font rougir (1) ; `AM4_CS_CHRONO`, `AM4_CS_NONLU_MUET`, `AM4_CS_ECRITURE_MUETTE`, `AM4_CS_LISTE_MUETTE`,
// `AM4_IDP_TEXTE` font rougir (2) ; `AM4_AI_LECTURE`, `AM4_AI_DECODAGE`, `AM4_AI_501`, `AM4_AI_501_CONTIENT` font
// rougir (3, corps) ; `AM4_AI_LECTURE_MUETTE`, `AM4_AI_DECODAGE_MUET` font rougir (3, journal).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (aucun écran ne lit le 409 de l'IdP ni `stockee_detail` en détail) ;
// les autres `({e})` de `cases.rs` (rattrapage : `sla_due`, `escalated`, relecture des échéances, `{CAUSE} ({e})` de
// l'échéance relue) — hors de ce lot ; le texte de la cause du registre (`registre_sans_maillon`), changé par un autre
// lot, jugé ici par son préfixe seul ; `SERVIES137`, `LienDeDossier::NonPose`, `LienRetire::NonRetire` (console).
// =====================================================================================
mod texte_du_moteur_hors_du_fournisseur_d_identite_et_du_chrono_sla {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AM4_ENFANT: &str = "AM4_ENFANT_JOURNAL";
    const AM4_RENDU: &str = "AM4-RENDU:";
    const AM4_FIN: &str = "AM4-FIN:";
    const AM4_ADMIN_IDENT: &str = "root:rootpw1234567";
    const AM4_MDP_EDITEUR: &str = "editeur-am4-0123456789";
    /// Les issues jouées, dans l'ordre.
    const AM4_ORDRE: [&str; 13] = [
        "idp_nominal", "idp_nom_pris", "idp_audit_refuse", "idp_insert_refuse", "idp_nom_libre",
        "cree_politique_non_lue", "cree_ecriture_refusee", "cree_nominale", "upsert_recalcul_partiel", "maj_chrono_non_lu",
        "upsert_liste_illisible", "upsert_liste_illisible_sans_maillon", "upsert_nominal",
    ];
    /// Un nom d'IdP n'apparaît dans aucun corps : la configuration OIDC minimale valide.
    const AM4_OIDC: &str = r#"{"issuer":"https://idp.exemple.invalid","client_id":"plume","redirect_uri":"https://plume.exemple.invalid/api/auth/oidc/callback"}"#;
    /// Les motifs des déclencheurs : ils ne doivent apparaître dans aucun corps.
    const AM4_MOTIF_ACK: &str = "am4 moteur ack_due";
    const AM4_MOTIF_RECALCUL: &str = "am4 moteur recalcul";
    /// Le texte du moteur d'une lecture refusée par l'autorisateur sur `incident.merged_into`.
    const AM4_LECTURE_INTERDITE: &str = "access to incident.merged_into is prohibited";

    /// Ce que l'enfant rend : les issues, puis les dossiers (A politique non lue, B écriture refusée, R refusé au
    /// recalcul, C ligne non lue, D chrono non lu).
    struct Am4Jeu {
        rendus: Vec<(&'static str, u16, String)>,
        dossiers: std::collections::BTreeMap<&'static str, i64>,
    }

    fn am4_basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    fn am4_editeur() -> String {
        am4_basic(&format!("edt:{AM4_MDP_EDITEUR}"))
    }

    fn am4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn am4_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn am4_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: &str, extra: &[(&str, &str)], corps: &str) -> (u16, String) {
        let mut entetes: Vec<(&str, &str)> = vec![("Content-Type", "application/json")];
        entetes.extend_from_slice(extra);
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(authz), &entetes, corps).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    fn am4_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn am4_refuser_l_insertion(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn am4_refuser_la_liste(st: &AppState, et_le_registre: bool) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "incident" && column_name == "merged_into" => Authorization::Deny,
            AuthAction::Insert { table_name } if et_le_registre && table_name == "ledger" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    async fn am4_jouer() -> Am4Jeu {
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();
        let mut dossiers = std::collections::BTreeMap::new();
        let (mut st, _base) = router_test_state("am4-routes");
        st.secret_des_gestes = Arc::new(crate::secret_des_gestes::SourceDuSecretDesGestes::Empreinte(crate::secret_des_gestes::empreinte_de_test()));
        am4_sql(&st, "DELETE FROM incident; DELETE FROM sla_policy;");
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(AM4_MDP_EDITEUR).unwrap()])
            .expect("fixture : compte éditeur");
        let addr = router_serve(st.clone()).await;
        let admin = am4_basic(AM4_ADMIN_IDENT);
        let secret = [(crate::secret_des_gestes::ENTETE_DU_SECRET_DES_GESTES, crate::secret_des_gestes::SECRET_DES_GESTES_DE_TEST)];
        let idp = |nom: &str| format!(r#"{{"name":"{nom}","kind":"oidc","enabled":true,"config":{AM4_OIDC}}}"#);

        // ---- fournisseur d'identité ----
        let (s, c) = am4_envoi(addr, "POST", "/api/idp/providers", &admin, &secret, &idp("am4-idp")).await;
        rendus.push(("idp_nominal", s, c));
        let (s, c) = am4_envoi(addr, "POST", "/api/idp/providers", &admin, &secret, &idp("am4-idp")).await;
        assert!(st.db.lock().is_autocommit(), "nom pris : la transaction est annulée");
        rendus.push(("idp_nom_pris", s, c));
        am4_refuser_l_insertion(&st, "ledger");
        let (s, c) = am4_envoi(addr, "POST", "/api/idp/providers", &admin, &secret, &idp("am4-idp-b")).await;
        let fermee = st.db.lock().is_autocommit();
        am4_lever(&st);
        assert!(fermee, "audit refusé : la transaction est annulée");
        rendus.push(("idp_audit_refuse", s, c));
        am4_refuser_l_insertion(&st, "idp_provider");
        let (s, c) = am4_envoi(addr, "POST", "/api/idp/providers", &admin, &secret, &idp("am4-idp-b")).await;
        let fermee = st.db.lock().is_autocommit();
        am4_lever(&st);
        assert!(fermee, "insertion refusée : la transaction est annulée");
        rendus.push(("idp_insert_refuse", s, c));
        let (s, c) = am4_envoi(addr, "POST", "/api/idp/providers", &admin, &secret, &idp("am4-idp-b")).await;
        rendus.push(("idp_nom_libre", s, c));

        // ---- chrono SLA : création ----
        am4_sql(
            &st,
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0);
             INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P2',2,X'00',900,1,0,'root',0);",
        );
        let editeur = am4_editeur();
        let (s, c) = am4_envoi(addr, "POST", "/api/cases", &editeur, &[], r#"{"title":"A","priority":2}"#).await;
        dossiers.insert("A", serde_json::from_str::<Value>(&c).ok().and_then(|v| v["id"].as_i64()).unwrap_or(0));
        rendus.push(("cree_politique_non_lue", s, c));
        am4_sql(&st, &format!("CREATE TEMP TRIGGER am4_ack BEFORE UPDATE OF ack_due ON incident BEGIN SELECT RAISE(ABORT, '{AM4_MOTIF_ACK}'); END;"));
        let (s, c) = am4_envoi(addr, "POST", "/api/cases", &editeur, &[], r#"{"title":"B","priority":1}"#).await;
        am4_sql(&st, "DROP TRIGGER am4_ack;");
        dossiers.insert("B", serde_json::from_str::<Value>(&c).ok().and_then(|v| v["id"].as_i64()).unwrap_or(0));
        rendus.push(("cree_ecriture_refusee", s, c));
        let (s, c) = am4_envoi(addr, "POST", "/api/cases", &editeur, &[], r#"{"title":"N","priority":1}"#).await;
        dossiers.insert("N", serde_json::from_str::<Value>(&c).ok().and_then(|v| v["id"].as_i64()).unwrap_or(0));
        rendus.push(("cree_nominale", s, c));

        // ---- chrono SLA : recalcul de l'upsert (H écrit, R refusé, C ligne non lue) ----
        let (h, r, c_id) = {
            let conn = st.db.lock();
            (dossier_seme(&conn, "alice", "H", 3, "", None, 3), dossier_seme(&conn, "alice", "R", 3, "", None, 3), dossier_seme(&conn, "alice", "C", 3, "", None, 3))
        };
        dossiers.insert("H", h);
        dossiers.insert("R", r);
        dossiers.insert("C", c_id);
        am4_sql(
            &st,
            &format!(
                "UPDATE incident SET ts=X'00' WHERE id={c_id};
                 CREATE TEMP TRIGGER am4_recalcul BEFORE UPDATE OF resolve_due ON incident WHEN OLD.id={r} BEGIN SELECT RAISE(ABORT, '{AM4_MOTIF_RECALCUL}'); END;"
            ),
        );
        let (s, c) = am4_envoi(addr, "POST", "/api/sla-policies", &editeur, &[], r#"{"name":"P3","priority":3,"ack_target_s":300,"resolve_target_s":3000}"#).await;
        am4_sql(&st, "DROP TRIGGER am4_recalcul;");
        rendus.push(("upsert_recalcul_partiel", s, c));

        // ---- chrono SLA : mise à jour, chrono non lu ----
        let d = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", "D", 3, "", None, 1)
        };
        dossiers.insert("D", d);
        am4_sql(&st, &format!("UPDATE incident SET sla_paused_since=X'00' WHERE id={d};"));
        let (s, c) = am4_envoi(addr, "POST", &format!("/api/cases/{d}"), &editeur, &[], r#"{"status":"waiting"}"#).await;
        am4_sql(&st, &format!("UPDATE incident SET sla_paused_since=NULL WHERE id={d};"));
        rendus.push(("maj_chrono_non_lu", s, c));

        // ---- chrono SLA : liste du recalcul illisible (avec puis sans maillon) ----
        am4_refuser_la_liste(&st, false);
        let (s, c) = am4_envoi(addr, "POST", "/api/sla-policies", &editeur, &[], r#"{"name":"P4","priority":4,"ack_target_s":400,"resolve_target_s":4000}"#).await;
        am4_lever(&st);
        rendus.push(("upsert_liste_illisible", s, c));
        am4_refuser_la_liste(&st, true);
        let (s, c) = am4_envoi(addr, "POST", "/api/sla-policies", &editeur, &[], r#"{"name":"P4","priority":4,"ack_target_s":410,"resolve_target_s":4100}"#).await;
        am4_lever(&st);
        rendus.push(("upsert_liste_illisible_sans_maillon", s, c));
        let (s, c) = am4_envoi(addr, "POST", "/api/sla-policies", &editeur, &[], r#"{"name":"P4","priority":4,"ack_target_s":420,"resolve_target_s":4200}"#).await;
        rendus.push(("upsert_nominal", s, c));

        // L'état que les corps décrivent, relu pour (1) (le parent de (2) ne relit pas la base de l'enfant).
        assert_eq!(am4_entier(&st, "SELECT COUNT(*) FROM idp_provider WHERE name IN ('am4-idp','am4-idp-b')"), 2, "les deux noms libres sont écrits, une fois chacun");
        assert_eq!(am4_entier(&st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.idp.create%'"), 2, "une trace par création réussie, aucune par refus");
        Am4Jeu { rendus, dossiers }
    }

    /// Un corps JSON jugé en entier.
    fn am4_egal(manquent: &mut Vec<String>, issue: &str, statut: u16, brut: &str, attendu_statut: u16, attendu: &Value) {
        let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
        if statut != attendu_statut || &v != attendu {
            manquent.push(format!("{issue} : attendu {attendu_statut} {attendu}, lu {statut} {brut}"));
        }
    }

    /// Un 5xx `{error, id}` jugé en entier.
    fn am4_cinq_cents(manquent: &mut Vec<String>, issue: &str, statut: u16, brut: &str, attendu: u16, phrase: &str) {
        let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
        let cles: Option<std::collections::BTreeSet<&str>> = v.as_object().map(|o| o.keys().map(String::as_str).collect());
        let tenu = statut == attendu
            && cles == Some(["error", "id"].into_iter().collect())
            && v["error"] == json!(phrase)
            && v["id"].as_str().unwrap_or("").starts_with("plume-e");
        if !tenu {
            manquent.push(format!("{issue} : attendu {attendu} {{error: {phrase}, id}}, lu {statut} {brut}"));
        }
    }

    /// (1) LES CORPS SERVIS, JUGÉS EN ENTIER.
    #[tokio::test]
    async fn am4_corps_servis_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let jeu = am4_jouer().await;
        let issues: Vec<&str> = jeu.rendus.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(issues, AM4_ORDRE.to_vec(), "chaque issue est jouée une fois, dans l'ordre");
        let d = |k: &str| *jeu.dossiers.get(k).unwrap_or_else(|| panic!("dossier {k} posé"));
        let mut manquent: Vec<String> = Vec::new();
        for (issue, statut, brut) in &jeu.rendus {
            let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
            match *issue {
                "idp_nominal" | "idp_nom_libre" => {
                    let id = v["id"].as_i64().unwrap_or(0);
                    am4_egal(&mut manquent, issue, *statut, brut, 200, &json!({ "id": id, "enabled": true }));
                    if id <= 0 {
                        manquent.push(format!("{issue} : identifiant servi : {brut}"));
                    }
                }
                "idp_nom_pris" => am4_egal(&mut manquent, issue, *statut, brut, 409, &json!({ "error": PHRASE_FOURNISSEUR_D_IDENTITE_NOM_DEJA_PRIS })),
                "idp_audit_refuse" | "idp_insert_refuse" => am4_cinq_cents(&mut manquent, issue, *statut, brut, 500, PHRASE_ECHEC_TRANSACTION_AUDIT),
                "cree_politique_non_lue" => {
                    let id = d("A");
                    let mut attendu = json!({ "id": id, "status": "new", "priority": 2, "priority_label": priority_label(2), "sla_due": v["sla_due"].clone() });
                    attendu["echeances_multi_niveau_non_lues"] = json!(format!("{CAUSE_ECHEANCES_MULTI_NIVEAU_NON_LUES} (politique de la priorité 2 non lue)"));
                    am4_egal(&mut manquent, issue, *statut, brut, 200, &attendu);
                    if !v["sla_due"].is_i64() {
                        manquent.push(format!("{issue} : échéance legacy servie : {brut}"));
                    }
                }
                "cree_ecriture_refusee" => {
                    let id = d("B");
                    let mut attendu = json!({ "id": id, "status": "new", "priority": 1, "priority_label": priority_label(1), "sla_due": v["sla_due"].clone() });
                    attendu["echeances_multi_niveau_non_posees"] =
                        json!(format!("{CAUSE_ECHEANCES_MULTI_NIVEAU_NON_POSEES} (sla_policy_id/ack_due/resolve_due: {ECRITURE_DU_CHRONO_REFUSEE})"));
                    am4_egal(&mut manquent, issue, *statut, brut, 200, &attendu);
                }
                "cree_nominale" => {
                    let id = d("N");
                    am4_egal(&mut manquent, issue, *statut, brut, 200, &json!({ "id": id, "status": "new", "priority": 1, "priority_label": priority_label(1), "sla_due": v["sla_due"].clone() }));
                    if !v["sla_due"].is_i64() {
                        manquent.push(format!("{issue} : échéance servie : {brut}"));
                    }
                }
                "upsert_recalcul_partiel" => {
                    let raison = format!(
                        "1 échéance(s) REFUSÉE(S) par la base — ces cases gardent leur ANCIENNE échéance : #{} (sla_policy_id/ack_due/resolve_due: {ECRITURE_DU_CHRONO_REFUSEE}) ; \
                         1 échéance(s) NON RECALCULÉE(S) faute de LECTURE (dossier ou politique non lu) — ces cases gardent leur ANCIENNE échéance : #{} ({CHRONO_LIGNE_DU_DOSSIER_NON_LUE})",
                        d("R"),
                        d("C")
                    );
                    am4_egal(&mut manquent, issue, *statut, brut, 200, &json!({ "recomputed": 1, "reason": raison }));
                }
                "maj_chrono_non_lu" => am4_cinq_cents(&mut manquent, issue, *statut, brut, 503, CAUSE_CHRONO_SLA_NON_LU),
                "upsert_liste_illisible" => am4_egal(&mut manquent, issue, *statut, brut, 200, &json!({ "recomputed": 0, "reason": LISTE_DES_CASES_ILLISIBLE })),
                "upsert_liste_illisible_sans_maillon" => {
                    // La cause du registre (après le préfixe) est changée par un autre lot : seul son préfixe est jugé ici.
                    let cles: std::collections::BTreeSet<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
                    let tenu = *statut == 200
                        && cles == ["degouvernes", "reason", "recomputed", CLE_REGISTRE_SANS_MAILLON].into_iter().collect()
                        && v["reason"] == json!(LISTE_DES_CASES_ILLISIBLE)
                        && v["recomputed"] == json!(0)
                        && v["degouvernes"] == json!(0)
                        && v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").starts_with(CAUSE_GESTE_SANS_TRACE);
                    if !tenu {
                        manquent.push(format!("{issue} : lu {statut} {brut}"));
                    }
                }
                "upsert_nominal" => {
                    if (*statut, brut.as_str()) != (204, "") {
                        manquent.push(format!("{issue} : 204 muet attendu, lu {statut} {brut}"));
                    }
                }
                autre => manquent.push(format!("issue inconnue {autre}")),
            }
            // Aucun texte du moteur ni motif de déclencheur dans aucun corps (hors la cause du registre, qu'un autre lot
            // change : `registre_sans_maillon` est retiré avant la recherche).
            let mut sans_registre = v.clone();
            if let Some(o) = sans_registre.as_object_mut() {
                o.remove(CLE_REGISTRE_SANS_MAILLON);
            }
            let lisible = if v.is_null() { brut.clone() } else { sans_registre.to_string() };
            for trace in [AM4_MOTIF_ACK, AM4_MOTIF_RECALCUL, AM4_LECTURE_INTERDITE, "Invalid column type", "UNIQUE constraint", "not authorized", "échec de création"] {
                if lisible.contains(trace) {
                    manquent.push(format!("{issue} : le corps porte « {trace} » : {brut}"));
                }
            }
        }
        assert!(manquent.is_empty(), "corps mal servis :\n{}", manquent.join("\n"));
    }

    /// (2) LE JOURNAL : lignes `[idp] WARN`, `[caseops] WARN` et la ligne `[cases]` du chrono non lu, EN ENTIER.
    #[tokio::test]
    async fn am4_journal_des_refus() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AM4_ENFANT).is_ok() {
            let jeu = am4_jouer().await;
            for (issue, statut, brut) in &jeu.rendus {
                let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
                println!("{AM4_RENDU} {issue} {statut} {}", v["id"].as_str().unwrap_or("absent"));
            }
            let dossiers: Vec<String> = jeu.dossiers.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("{AM4_FIN} {} {}", jeu.rendus.len(), dossiers.join(","));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::texte_du_moteur_hors_du_fournisseur_d_identite_et_du_chrono_sla::am4_journal_des_refus",
            ])
            .env(AM4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (joues, dossiers) = stdout
            .lines()
            .find_map(|l| l.split_once(AM4_FIN))
            .and_then(|(_, v)| v.trim().split_once(' ').map(|(a, b)| (a.parse::<usize>().unwrap_or(0), b.to_string())))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}"));
        assert_eq!(joues, AM4_ORDRE.len(), "contrôle : toutes les issues jouées par l'enfant : {stdout}");
        let dossiers: std::collections::BTreeMap<String, i64> = dossiers
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.parse::<i64>().unwrap_or(0)))
            .collect();
        let d = |k: &str| *dossiers.get(k).unwrap_or_else(|| panic!("contrôle : dossier {k} rendu par l'enfant : {stdout}"));
        let ids: std::collections::BTreeMap<&str, &str> = stdout
            .lines()
            .filter_map(|l| l.split_once(AM4_RENDU))
            .filter_map(|(_, r)| {
                let mut morceaux = r.split_whitespace();
                let issue = morceaux.next()?;
                let _statut = morceaux.next()?;
                Some((issue, morceaux.next()?))
            })
            .collect();
        assert_eq!(ids.len(), AM4_ORDRE.len(), "un identifiant (ou `absent`) par issue : {stdout}");
        let id_de = |issue: &str| ids.get(issue).copied().unwrap_or("manquant").to_string();

        let idp: Vec<&str> = stderr.lines().filter(|l| l.contains("[idp] WARN")).collect();
        assert_eq!(
            idp,
            vec![
                format!("[{}] [idp] WARN création du fournisseur d'identité 'am4-idp-b' refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("idp_audit_refuse")),
                format!("[{}] [idp] WARN création du fournisseur d'identité 'am4-idp-b' refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("idp_insert_refuse")),
            ],
            "une ligne EXACTE par échec de création :\n{stderr}"
        );
        let caseops: Vec<&str> = stderr.lines().filter(|l| l.contains("[caseops] WARN")).collect();
        assert_eq!(
            caseops,
            vec![
                format!("[caseops] WARN chrono SLA du dossier #{} : politique de la priorité 2 non lue : Invalid column type Blob at index: 1, name: ack_target_s", d("A")),
                format!("[caseops] WARN chrono SLA du dossier #{} : écriture de sla_policy_id/ack_due/resolve_due refusée : {AM4_MOTIF_ACK}", d("B")),
                format!("[caseops] WARN chrono SLA du dossier #{} : écriture de sla_policy_id/ack_due/resolve_due refusée : {AM4_MOTIF_RECALCUL}", d("R")),
                format!("[caseops] WARN chrono SLA du dossier #{} : ligne du dossier non lue : Invalid column type Blob at index: 0, name: ts", d("C")),
                format!("[caseops] WARN chrono SLA du dossier #{} : chrono du dossier non lu : Invalid column type Blob at index: 1, name: sla_paused_since", d("D")),
                format!("[caseops] WARN recalcul des échéances de la priorité 4 : liste des cases illisible, aucune échéance recalculée : {AM4_LECTURE_INTERDITE}"),
                format!("[caseops] WARN recalcul des échéances de la priorité 4 : liste des cases illisible, aucune échéance recalculée : {AM4_LECTURE_INTERDITE}"),
            ],
            "une ligne EXACTE par lecture ou écriture du chrono refusée :\n{stderr}"
        );
        let chrono: Vec<&str> = stderr.lines().filter(|l| l.contains("[cases] WARN") && l.contains("chrono SLA NON lu")).collect();
        assert_eq!(
            chrono,
            vec![format!("[cases] WARN dossier #{} : chrono SLA NON lu, mise à jour non écrite ({}) : {CHRONO_DU_DOSSIER_NON_LU}", d("D"), id_de("maj_chrono_non_lu"))],
            "la ligne du geste reprend la phrase fixe, le moteur est à la ligne `[caseops]` :\n{stderr}"
        );
    }
}

// =====================================================================================
// (3) FEATURE `ai` — la politique de caviardage et le 501 de l'assistant. Compilés et joués seulement sous
// `--features ai`.
// =====================================================================================
#[cfg(feature = "ai")]
mod texte_du_moteur_hors_de_la_politique_de_caviardage_et_du_stub_d_ia {
    use super::*;
    use crate::mesure_environnement::{CAUSE_AUCUNE, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE, VERDICT_LU};

    const AM4I_ENFANT: &str = "AM4I_ENFANT_JOURNAL";
    const AM4I_RENDU: &str = "AM4I-RENDU:";
    const AM4I_FIN: &str = "AM4I-FIN:";
    const AM4I_ADMIN_IDENT: &str = "root:rootpw1234567";
    const AM4I_LECTEUR_IDENT: &str = "vwr:viewerpw12345";
    const AM4I_ORDRE: [&str; 6] = ["nl_hote_non_compile", "politique_absente", "politique_stockee", "politique_blob", "politique_indecodable", "w_stub_exact"];
    /// L'hôte irrésoluble qui porte « non compilé » : il ne doit apparaître ni au corps ni au journal.
    const AM4I_HOTE: &str = "non compilé.invalid";
    /// La politique indécodable stockée.
    const AM4I_INDECODABLE: &str = "{ casse";

    fn am4i_basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    fn am4i_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    async fn am4i_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, ident: &str, corps: &str) -> (u16, String) {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(&am4i_basic(ident)), &entetes, corps).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    /// Le texte du moteur d'une lecture de `meta.value` en BLOB, relu sur une base de test (même requête).
    fn am4i_moteur_blob() -> String {
        let conn = test_db();
        conn.execute_batch("INSERT INTO meta(key,value) VALUES('ai_redaction_policy',X'00') ON CONFLICT(key) DO UPDATE SET value=X'00';").unwrap();
        conn.query_row("SELECT value FROM meta WHERE key='ai_redaction_policy'", [], |r| r.get::<_, String>(0)).unwrap_err().to_string()
    }

    fn am4i_cause_blob() -> &'static str {
        let conn = test_db();
        conn.execute_batch("INSERT INTO meta(key,value) VALUES('ai_redaction_policy',X'00') ON CONFLICT(key) DO UPDATE SET value=X'00';").unwrap();
        let e = conn.query_row("SELECT value FROM meta WHERE key='ai_redaction_policy'", [], |r| r.get::<_, String>(0)).unwrap_err();
        crate::bilan_de_tick::cause_sql(&e)
    }

    async fn am4i_jouer() -> (Vec<(&'static str, u16, String)>, i64) {
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();
        let (st, _base) = router_test_state("am4i-routes");
        let addr = router_serve(st.clone()).await;
        am4i_sql(
            &st,
            &format!(
                "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
                 VALUES('am4i-hote','local','openai','http://{AM4I_HOTE}','',1,'{{\"model\":\"am4i\"}}',1,1);"
            ),
        );
        let id: i64 = st.db.lock().query_row("SELECT id FROM ai_provider WHERE name='am4i-hote'", [], |r| r.get(0)).expect("fixture : fournisseur posé");
        let (s, c) = am4i_envoi(addr, "POST", "/api/ai/nl2soql", AM4I_LECTEUR_IDENT, r#"{"nl":"erreurs auth"}"#).await;
        rendus.push(("nl_hote_non_compile", s, c));
        let (s, c) = am4i_envoi(addr, "GET", "/api/ai/redaction-policy", AM4I_ADMIN_IDENT, "").await;
        rendus.push(("politique_absente", s, c));
        am4i_sql(&st, r#"INSERT INTO meta(key,value) VALUES('ai_redaction_policy','{"version":7,"deny_substr":["email"],"pii_allow":["user_name"]}');"#);
        let (s, c) = am4i_envoi(addr, "GET", "/api/ai/redaction-policy", AM4I_ADMIN_IDENT, "").await;
        rendus.push(("politique_stockee", s, c));
        am4i_sql(&st, "UPDATE meta SET value=X'00' WHERE key='ai_redaction_policy';");
        let (s, c) = am4i_envoi(addr, "GET", "/api/ai/redaction-policy", AM4I_ADMIN_IDENT, "").await;
        rendus.push(("politique_blob", s, c));
        am4i_sql(&st, &format!("UPDATE meta SET value='{AM4I_INDECODABLE}' WHERE key='ai_redaction_policy';"));
        let (s, c) = am4i_envoi(addr, "GET", "/api/ai/redaction-policy", AM4I_ADMIN_IDENT, "").await;
        rendus.push(("politique_indecodable", s, c));
        am4i_sql(&st, "DELETE FROM meta WHERE key='ai_redaction_policy';");
        // Le stub exact (feature éteinte) : la route ne l'atteint pas sous `--features ai`, le point d'entrée du
        // gestionnaire est appelé.
        let r = ai_worker_err(id, PHRASE_SUPPORT_IA_NON_COMPILE.to_string());
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        rendus.push(("w_stub_exact", statut, String::from_utf8_lossy(&b).into_owned()));
        (rendus, id)
    }

    fn am4i_detail_illisible() -> String {
        "meta['ai_redaction_policy'] : la politique stockée n'a pas pu être lue — le défaut v1 est appliqué ET affiché ; \
         ce qui est à l'écran n'est donc PAS ce qui est stocké, et le renvoyer par PUT écraserait la politique en place"
            .to_string()
    }

    fn am4i_detail_indecodable() -> String {
        "meta['ai_redaction_policy'] : une politique EST stockée mais ne se décode pas — le défaut v1 est appliqué ET \
         affiché ; ce qui est à l'écran n'est donc PAS ce qui est stocké, et le renvoyer par PUT écraserait la politique \
         en place"
            .to_string()
    }

    /// (3a) LES CORPS, EN ENTIER.
    #[tokio::test]
    async fn am4_ia_corps_servis_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // trois réglages posés pour la portée
        let _ia = ReglageBackupPose::neuf("PLUME_AI_ENABLE", "1");
        let _nuage = ReglageBackupPose::neuf("PLUME_AI_ALLOW_CLOUD", "1");
        let _budget = ReglageBackupPose::neuf("PLUME_AI_MAX_CALLS_PER_MIN", "1000");
        let (rendus, _id) = am4i_jouer().await;
        let issues: Vec<&str> = rendus.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(issues, AM4I_ORDRE.to_vec(), "chaque issue jouée une fois, dans l'ordre");
        let defaut = guatx_core::ai::default_redaction_policy();
        let politique = |version: i64, deny: Value, allow: Value| json!({ "version": version, "deny_substr": deny, "pii_allow": allow });
        let mut manquent: Vec<String> = Vec::new();
        for (issue, statut, brut) in &rendus {
            let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
            let attendu: (u16, Value) = match *issue {
                "nl_hote_non_compile" | "w_stub_exact" => {
                    let (code, phrase) = if *issue == "w_stub_exact" { (501, PHRASE_SUPPORT_IA_NON_COMPILE) } else { (500, PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE) };
                    let id = v["id"].as_str().unwrap_or("");
                    if !id.starts_with("plume-e") {
                        manquent.push(format!("{issue} : identifiant de corrélation : {brut}"));
                    }
                    (code, json!({ "error": phrase, "id": id }))
                }
                "politique_absente" => {
                    let mut p = politique(defaut.version, json!(defaut.deny_substr), json!(defaut.pii_allow));
                    p["stockee_verdict"] = json!(VERDICT_LU);
                    p["stockee_cause"] = json!(CAUSE_AUCUNE);
                    (200, p)
                }
                "politique_stockee" => {
                    let mut p = politique(7, json!(["email"]), json!(["user_name"]));
                    p["stockee_verdict"] = json!(VERDICT_LU);
                    p["stockee_cause"] = json!(CAUSE_AUCUNE);
                    (200, p)
                }
                "politique_blob" => {
                    let mut p = politique(defaut.version, json!(defaut.deny_substr), json!(defaut.pii_allow));
                    p["stockee_verdict"] = json!(VERDICT_ILLISIBLE);
                    p["stockee_cause"] = json!(am4i_cause_blob());
                    p["stockee_detail"] = json!(am4i_detail_illisible());
                    (200, p)
                }
                "politique_indecodable" => {
                    let mut p = politique(defaut.version, json!(defaut.deny_substr), json!(defaut.pii_allow));
                    p["stockee_verdict"] = json!(VERDICT_ILLISIBLE);
                    p["stockee_cause"] = json!(CAUSE_FORME_INCONNUE);
                    p["stockee_detail"] = json!(am4i_detail_indecodable());
                    (200, p)
                }
                autre => {
                    manquent.push(format!("issue inconnue {autre}"));
                    continue;
                }
            };
            if (*statut, &v) != (attendu.0, &attendu.1) {
                manquent.push(format!("{issue} : attendu {} {}, lu {statut} {brut}", attendu.0, attendu.1));
            }
            for trace in ["non compilé.invalid", "Invalid column type", "SSRF", "backend IA", "key must be", "line 1 column"] {
                if brut.contains(trace) {
                    manquent.push(format!("{issue} : le corps porte « {trace} » : {brut}"));
                }
            }
        }
        assert!(manquent.is_empty(), "corps mal servis :\n{}", manquent.join("\n"));
    }

    /// (3b) LE JOURNAL, EN ENTIER : les deux lignes neuves de la politique, la nature de l'échec du worker, et aucun hôte.
    #[tokio::test]
    async fn am4_ia_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AM4I_ENFANT).is_ok() {
            let (rendus, id) = am4i_jouer().await;
            for (issue, statut, brut) in &rendus {
                let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
                println!("{AM4I_RENDU} {issue} {statut} {}", v["id"].as_str().unwrap_or("absent"));
            }
            println!("{AM4I_FIN} {} {id}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::texte_du_moteur_hors_de_la_politique_de_caviardage_et_du_stub_d_ia::am4_ia_journal",
            ])
            .env(AM4I_ENFANT, "1")
            .env("PLUME_AI_ENABLE", "1")
            .env("PLUME_AI_ALLOW_CLOUD", "1")
            .env("PLUME_AI_MAX_CALLS_PER_MIN", "1000")
            .env_remove("PLUME_SSRF_ALLOW")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (joues, id) = stdout
            .lines()
            .find_map(|l| l.split_once(AM4I_FIN))
            .and_then(|(_, v)| v.trim().split_once(' ').map(|(a, b)| (a.parse::<usize>().unwrap_or(0), b.to_string())))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}"));
        assert_eq!(joues, AM4I_ORDRE.len(), "contrôle : toutes les issues jouées : {stdout}");
        let ids: std::collections::BTreeMap<&str, &str> = stdout
            .lines()
            .filter_map(|l| l.split_once(AM4I_RENDU))
            .filter_map(|(_, r)| {
                let mut morceaux = r.split_whitespace();
                let issue = morceaux.next()?;
                let _statut = morceaux.next()?;
                Some((issue, morceaux.next()?))
            })
            .collect();
        assert_eq!(ids.len(), AM4I_ORDRE.len(), "un identifiant (ou `absent`) par issue : {stdout}");
        let id_de = |issue: &str| ids.get(issue).copied().unwrap_or("manquant").to_string();
        let decodeur = serde_json::from_str::<Value>(AM4I_INDECODABLE).unwrap_err().to_string();
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("[ia] WARN")).collect();
        assert_eq!(
            lignes,
            vec![
                format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : adresse du fournisseur refusée par la garde SSRF (cible interne, résolution impossible ou schéma refusé), avant toute connexion", id_de("nl_hote_non_compile")),
                format!("[ia] WARN politique de caviardage stockée non lue, défaut v1 appliqué : {}", am4i_moteur_blob()),
                format!("[ia] WARN politique de caviardage stockée indécodable, défaut v1 appliqué : {decodeur}"),
            ],
            "une ligne EXACTE par échec :\n{stderr}"
        );
        let http: Vec<&str> = stderr.lines().filter(|l| l.contains(" HTTP 50")).collect();
        assert_eq!(
            http,
            vec![
                format!("[{}] HTTP 500 : {PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE}", id_de("nl_hote_non_compile")),
                format!("[{}] HTTP 501 : {PHRASE_SUPPORT_IA_NON_COMPILE}", id_de("w_stub_exact")),
            ],
            "les lignes HTTP portent la phrase seule :\n{stderr}"
        );
        let porteuses: Vec<&str> = stderr.lines().filter(|l| l.contains(AM4I_HOTE) || l.contains("backend IA")).collect();
        assert!(porteuses.is_empty(), "ni l'hôte ni le texte du worker au journal : {porteuses:?}");
    }
}
