// =====================================================================================
// `P10.20-b` (reste : `ai_status`, `ai_nl2soql`), `P10.29-l` (reste : `handlers/ai.rs`) et `P10.29-m` (témoins joués sous
// `--features ai`) — LE FOURNISSEUR D'IA ACTIF EST LU EN TROIS ISSUES, ET NI LE TEXTE DU MOTEUR NI CELUI DU WORKER NE
// PARTENT AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR 831785a9 AVANT LE CORRECTIF (daemon/src/handlers/ai.rs) :
// - `ai_status` : `Err(_) => (false, Value::Null)` — une lecture ratée du fournisseur actif était servie « aucun
//   fournisseur » (`has_provider: false`) ;
// - `ai_nl2soql` : `Err(_) => 409 « aucun provider IA actif »` — la même absence inventée, en refus ;
// - `ai_redaction_policy_put`, `ai_provider_update`, `ai_provider_delete` : `server_err(format!("échec transaction …: {e}"))`
//   — le texte du moteur SQLite servi en 500 ; et une forme d'API inconnue à la modification sortait par `InvalidQuery` en
//   500 « échec transaction » ;
// - `ai_provider_create` : tout échec de la transaction servi en 409 TEXTE « échec de création (nom déjà pris ou
//   audit) » — un nom pris et un audit refusé confondus, hors JSON ;
// - `ai_worker_err` : le texte du worker servi en 500 à tout lecteur de l'assistant — dont, depuis la garde SSRF
//   (`ledger.rs`) et le client HTTP interne (`util/http_client.rs`), l'hôte du fournisseur, son port et l'adresse
//   interne résolue.
//
// DÉCISIONS (orchestrateur, vague AL) : `ai_status` garde son corps d'avant à l'octet sur les deux issues lues et gagne,
// sur la lecture ratée, le champ additif `fournisseur_non_lu` (`has_provider: null`, `enabled: false`) ; `ai_nl2soql`
// garde son 409 à l'octet sur l'absence et rend un 503 nommé sur la lecture ratée, sans appel — ce 503 `{error, id}` est
// lu par `causeNommeeParLeDemon` (web/core.js:351, via `apiSend`, web/core.js:775) et rangé « refus nommé » par
// `natureDuRefusDUnGeste` (web/core.js:906-916 : aucune des trois ouvertures d'écriture ne s'applique, rien n'est écrit) ;
// les trois 500 d'audit passent par `servir_l_echec_de_la_transaction_d_audit` ; la création sert un 409 JSON à phrase
// fixe sur la seule violation d'unicité de l'`INSERT` (route administrateur, qui lit déjà les noms : pas d'oracle neuf),
// et tout autre échec de sa transaction passe par le même `servir_l_echec_de_la_transaction_d_audit` ; le 500 du worker sert
// `PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE`, et seule la NATURE de l'échec (liste blanche) part au journal.
//
// LES TÉMOINS, PAR LE ROUTEUR RÉEL (jeton lecteur pour l'état et l'assistant, administrateur pour les gestes) :
// (1) `al3_corps_servis_par_la_route` : chaque corps jugé EN ENTIER (clés exactes, phrase, identifiant ; les corps
//     d'avant comparés à l'octet), l'état de la base inchangé après chaque refus, et les issues parcourues égales à
//     `AL3_ORDRE` ; contrôles positifs : une forme d'API VALIDE à la modification rend 200 et s'écrit, une création
//     admise rend son identifiant et sa trace ;
// (2) `al3_journal_des_refus_et_des_echecs` : le binaire se rejoue en sous-processus (sans `PLUME_SSRF_ALLOW`, avec
//     `PLUME_AI_ENABLE=1`), le parent compare les lignes `[ia]` de son stderr EN ENTIER, et vérifie qu'aucune ligne ne
//     porte l'hôte ni le texte du worker ;
// (3) `al3_begin_refuse_des_quatre_gestes_d_ia` (`P10.29-m`) : les quatre gestes convertis par `P10.28-d` (pose de
//     politique, création, modification, suppression de fournisseur), joués sous une transaction étrangère pendante :
//     503 nommé `{error, id}` chacun, rien d'écrit, la transaction étrangère toujours pendante ; contrôle positif.
// La lecture est rendue illisible de deux façons : table `ai_provider` renommée le temps de l'appel ; cellule BLOB
// (`name`, `endpoint`) d'un fournisseur actif, table présente. Les écritures d'audit sont refusées par un autorisateur
// SQLite (INSERT sur `ledger`) ; l'`INSERT` du fournisseur lui-même est refusé de la même façon, pour une erreur de
// création qui n'est pas un nom pris. Le fournisseur actif pointe la boucle locale (`127.0.0.1:9`) : la garde SSRF le refuse
// avant toute connexion (dans l'enfant, `PLUME_SSRF_ALLOW` retirée ; dans le processus parent, s'il l'a figée, la
// connexion est refusée : même corps). Les natures que la route n'atteint pas sans réseau (statut HTTP, réponse
// invalide, réseau, nature inconnue, « non compilé ») sont jouées par l'appel direct d'`ai_worker_err`, le point
// d'entrée que le gestionnaire appelle.
//
// MUTANTS JOUÉS (par variable d'environnement, retirés avant le commit) : `AL3_POL`, `AL3_UPD`, `AL3_DEL` (le texte du moteur rendu au
// client), `AL3_FORME` (forme d'API inconnue non jugée avant la transaction), `AL3_ST_AVALE` (lecture ratée servie
// « aucun fournisseur »), `AL3_ST_INV` (absence servie « non lu »), `AL3_ST_ENABLED` (`enabled` vrai sur un fournisseur
// non lu), `AL3_NL_409` (lecture ratée servie 409), `AL3_NL_INV` (absence servie 503), `AL3_W_TEXTE` (texte du worker
// servi), `AL3_W_501` (le « non compilé » servi en 500) font rougir (1) ; `AL3_ST_MUET`, `AL3_NL_MUET`, `AL3_W_MUET`
// (ligne de journal tue), `AL3_W_SSRF`, `AL3_W_HTTP`, `AL3_W_REPONSE`, `AL3_W_RESEAU` (une nature de la liste blanche
// sautée) font rougir (2) ; `AL3_POL`, `AL3_UPD`, `AL3_DEL` rougissent aussi (2) ; `AL3_B_POL`, `AL3_B_CRE`, `AL3_B_UPD`,
// `AL3_B_DEL` (le geste se passe de sa transaction et écrit dans l'étrangère) font rougir (3). `AL3_M_FORMETOUT` (toute
// forme d'API refusée en 400 à la modification), `AL3_C_UNIQUE_IGNORE` (nom pris servi en 500 d'audit), `AL3_C_TOUT_409`
// (audit refusé servi en 409), `AL3_C_DETECTE_TOUT` (toute erreur de l'`INSERT` lue comme un nom pris), `AL3_C_TEXTE` (le
// 409 texte d'avant), `AL3_C_SANS_ROLLBACK` (transaction laissée ouverte sur le nom pris) et `AL3_T_SANS_ISSUE` (une
// issue non jouée) font rougir (1) ; `AL3_T_SANS_GESTE` (un geste non joué) fait rougir (3).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le bras de succès d'`ai_nl2soql` (aucun faux fournisseur joignable en test, voir
// `traces_ia_et_scope_sans_maillon_avouees.rs`) ; une nature servie depuis un vrai fournisseur (statut, réponse vide :
// jouées par l'appel direct) ; la console — `web/ai.js` appelle `showErr(e)` avec un seul argument (web/ai.js:67) et
// ne peint que « erreur IA » : la cause nommée n'atteint pas l'écran (reste console) ; le mode multi-tenant (501).
// Compilés et joués seulement sous `--features ai`.
// =====================================================================================
#[cfg(feature = "ai")]
mod fournisseur_d_ia_actif_lu_et_texte_du_worker_tu {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Variable qui fait de ce binaire l'enfant du témoin (2).
    const AL3_ENFANT: &str = "AL3_ENFANT_JOURNAL";
    /// Ce que l'enfant écrit sur stdout, par issue : `AL3-RENDU: <issue> <statut> <identifiant|absent>`.
    const AL3_RENDU: &str = "AL3-RENDU:";
    /// Ce que l'enfant écrit sur stdout pour prouver qu'il a joué jusqu'au bout.
    const AL3_FIN: &str = "AL3-FIN:";
    const AL3_ADMIN_IDENT: &str = "root:rootpw1234567";
    const AL3_LECTEUR_IDENT: &str = "vwr:viewerpw12345";
    /// Les issues jouées, dans l'ordre : `al3_jouer` doit les rendre toutes, une fois chacune, dans cet ordre.
    const AL3_ORDRE: [&str; 22] = [
        "statut_absent", "nl_absent", "statut_nominal", "nl_appel_refuse", "statut_table_illisible", "nl_table_illisible",
        "politique_audit_refuse", "maj_audit_refuse", "suppr_audit_refuse", "cre_audit_refuse", "cre_insert_refuse",
        "cre_nom_pris", "maj_forme_inconnue", "maj_forme_valide", "cre_succes",
        "statut_cellule_illisible", "nl_cellule_illisible", "w_http", "w_reponse", "w_reseau", "w_inconnue", "w_non_compile",
    ];
    const AL3_ISSUES: usize = AL3_ORDRE.len();
    const AL3_409_D_AVANT: &str = r#"{"error":"aucun provider IA actif — configurez-en un (admin)"}"#;
    const AL3_400_FORME: &str = r#"{"error":"api_shape non supporté (openai | ollama-native | anthropic)"}"#;
    /// Le 409 du nom déjà pris à la création, corps entier.
    const AL3_409_NOM_PRIS: &str = r#"{"error":"un fournisseur d'IA porte déjà ce nom : rien n'est créé, choisissez un autre nom"}"#;
    /// Le corps d'une création : un nom neuf, la boucle locale, inactif par défaut.
    const AL3_CREATION: &str = r#"{"name":"al3-neuf","endpoint":"http://127.0.0.1:11434","config":{"model":"al3"}}"#;
    /// Le même corps sous le nom du fournisseur déjà posé.
    const AL3_CREATION_NOM_PRIS: &str = r#"{"name":"al3-local","endpoint":"http://127.0.0.1:11434","config":{"model":"al3"}}"#;
    const AL3_NON_COMPILE: &str = "support IA non compilé (recompiler avec --features ai)";
    /// L'hôte d'un texte de worker synthétique : il ne doit apparaître ni au corps ni au journal.
    const AL3_HOTE_SYNTHETIQUE: &str = "192.0.2.10";

    fn al3_basic(ident: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(ident))
    }

    fn al3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn al3_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Une requête par le routeur réel : statut et corps brut (dé-chunké).
    async fn al3_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, ident: &str, corps: &str) -> (u16, String) {
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(&al3_basic(ident)), &entetes, corps).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    async fn al3_reponse(r: Response) -> (u16, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    fn al3_refuser_l_audit(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "ledger" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// L'`INSERT` du fournisseur lui-même refusé (une erreur qui n'est PAS une violation d'unicité).
    fn al3_refuser_l_insertion_du_fournisseur(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "ai_provider" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn al3_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// L'état que les refus ne doivent pas changer : le fournisseur (présent, actif, forme), la politique stockée, les
    /// traces de configuration IA.
    fn al3_etat(st: &AppState, id: i64) -> String {
        format!(
            "fournisseur={} actif={} forme={} politique={} traces={}",
            al3_entier(st, &format!("SELECT COUNT(*) FROM ai_provider WHERE id={id}")),
            al3_entier(st, &format!("SELECT COALESCE(MAX(enabled),-1) FROM ai_provider WHERE id={id}")),
            al3_entier(st, &format!("SELECT COUNT(*) FROM ai_provider WHERE id={id} AND api_shape='openai'")),
            al3_entier(st, "SELECT COUNT(*) FROM meta WHERE key='ai_redaction_policy'"),
            al3_entier(st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.ai.%' OR kind='ai.call'"),
        )
    }

    /// Joue toutes les issues ; rend `(issue, statut, corps brut)` dans l'ordre, l'identifiant du fournisseur posé et
    /// celui du fournisseur créé par la route.
    async fn al3_jouer() -> (Vec<(&'static str, u16, String)>, i64, i64) {
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();

        // ---- base A : aucun fournisseur, puis un fournisseur actif sur la boucle locale ----
        let (st, _base) = router_test_state("al3-routes");
        let addr = router_serve(st.clone()).await;
        let (s, c) = al3_envoi(addr, "GET", "/api/ai/status", AL3_LECTEUR_IDENT, "").await;
        rendus.push(("statut_absent", s, c));
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/nl2soql", AL3_LECTEUR_IDENT, r#"{"nl":"erreurs auth"}"#).await;
        rendus.push(("nl_absent", s, c));

        al3_sql(
            &st,
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
             VALUES('al3-local','local','openai','http://127.0.0.1:9','',1,'{\"model\":\"al3\"}',1,1);",
        );
        let id = al3_entier(&st, "SELECT id FROM ai_provider WHERE name='al3-local'");
        let (s, c) = al3_envoi(addr, "GET", "/api/ai/status", AL3_LECTEUR_IDENT, "").await;
        rendus.push(("statut_nominal", s, c));
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/nl2soql", AL3_LECTEUR_IDENT, r#"{"nl":"erreurs auth"}"#).await;
        rendus.push(("nl_appel_refuse", s, c));

        al3_sql(&st, "ALTER TABLE ai_provider RENAME TO ai_provider_hors_d_atteinte;");
        let (s, c) = al3_envoi(addr, "GET", "/api/ai/status", AL3_LECTEUR_IDENT, "").await;
        rendus.push(("statut_table_illisible", s, c));
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/nl2soql", AL3_LECTEUR_IDENT, r#"{"nl":"erreurs auth"}"#).await;
        rendus.push(("nl_table_illisible", s, c));
        al3_sql(&st, "ALTER TABLE ai_provider_hors_d_atteinte RENAME TO ai_provider;");

        // ---- gestes d'administration : audit refusé, puis forme d'API inconnue ----
        let avant = al3_etat(&st, id);
        assert_eq!(avant, "fournisseur=1 actif=1 forme=1 politique=0 traces=0", "contrôle : état de départ");
        al3_refuser_l_audit(&st);
        let (s, c) = al3_envoi(addr, "PUT", "/api/ai/redaction-policy", AL3_ADMIN_IDENT, r#"{"version":7}"#).await;
        let fermee_pol = st.db.lock().is_autocommit();
        rendus.push(("politique_audit_refuse", s, c));
        let (s, c) = al3_envoi(addr, "POST", &format!("/api/ai/providers/{id}"), AL3_ADMIN_IDENT, r#"{"enabled":false}"#).await;
        let fermee_maj = st.db.lock().is_autocommit();
        rendus.push(("maj_audit_refuse", s, c));
        let (s, c) = al3_envoi(addr, "DELETE", &format!("/api/ai/providers/{id}"), AL3_ADMIN_IDENT, "").await;
        let fermee_suppr = st.db.lock().is_autocommit();
        rendus.push(("suppr_audit_refuse", s, c));
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/providers", AL3_ADMIN_IDENT, AL3_CREATION).await;
        let fermee_cre = st.db.lock().is_autocommit();
        rendus.push(("cre_audit_refuse", s, c));
        al3_refuser_l_insertion_du_fournisseur(&st);
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/providers", AL3_ADMIN_IDENT, AL3_CREATION).await;
        let fermee_ins = st.db.lock().is_autocommit();
        rendus.push(("cre_insert_refuse", s, c));
        al3_lever(&st);
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/providers", AL3_ADMIN_IDENT, AL3_CREATION_NOM_PRIS).await;
        let fermee_pris = st.db.lock().is_autocommit();
        rendus.push(("cre_nom_pris", s, c));
        assert_eq!(
            (fermee_pol, fermee_maj, fermee_suppr, fermee_cre, fermee_ins, fermee_pris),
            (true, true, true, true, true, true),
            "aucune transaction laissée ouverte"
        );
        assert_eq!(al3_etat(&st, id), avant, "les gestes à l'audit refusé et le nom déjà pris n'ont rien changé");
        assert_eq!(al3_entier(&st, "SELECT COUNT(*) FROM ai_provider"), 1, "aucun fournisseur créé par les trois créations refusées");
        let (s, c) = al3_envoi(addr, "POST", &format!("/api/ai/providers/{id}"), AL3_ADMIN_IDENT, r#"{"api_shape":"inconnu","enabled":false}"#).await;
        rendus.push(("maj_forme_inconnue", s, c));
        assert_eq!(al3_etat(&st, id), avant, "la forme d'API inconnue n'a rien changé (ni forme, ni désactivation)");
        // Contrôle positif du jugement de forme : une forme VALIDE passe et s'écrit.
        let (s, c) = al3_envoi(addr, "POST", &format!("/api/ai/providers/{id}"), AL3_ADMIN_IDENT, r#"{"api_shape":"anthropic"}"#).await;
        rendus.push(("maj_forme_valide", s, c));
        let forme: String = st
            .db
            .lock()
            .query_row("SELECT api_shape FROM ai_provider WHERE id=?1", [id], |r| r.get(0))
            .expect("fixture : forme relue");
        assert_eq!(forme, "anthropic", "la forme d'API valide est écrite en base");
        // Le bras de succès de la création, nom neuf, audit admis.
        let (s, c) = al3_envoi(addr, "POST", "/api/ai/providers", AL3_ADMIN_IDENT, AL3_CREATION).await;
        rendus.push(("cre_succes", s, c));
        let id_neuf = al3_entier(&st, "SELECT COALESCE(MAX(id),-1) FROM ai_provider WHERE name='al3-neuf' AND enabled=0 AND api_shape='openai'");
        assert_eq!(
            al3_entier(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ai.provider.create'"),
            1,
            "la création admise écrit sa trace"
        );

        // ---- base B : un fournisseur actif dont `name` et `endpoint` sont des BLOB (table présente) ----
        let (st_b, _base_b) = router_test_state("al3-cellule");
        let addr_b = router_serve(st_b.clone()).await;
        al3_sql(
            &st_b,
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
             VALUES(X'00','local','openai',X'00','',1,'{\"model\":\"al3\"}',1,1);",
        );
        assert_eq!(al3_entier(&st_b, "SELECT typeof(name)='blob' AND typeof(endpoint)='blob' FROM ai_provider"), 1, "fixture : cellules BLOB");
        let (s, c) = al3_envoi(addr_b, "GET", "/api/ai/status", AL3_LECTEUR_IDENT, "").await;
        rendus.push(("statut_cellule_illisible", s, c));
        let (s, c) = al3_envoi(addr_b, "POST", "/api/ai/nl2soql", AL3_LECTEUR_IDENT, r#"{"nl":"erreurs auth"}"#).await;
        rendus.push(("nl_cellule_illisible", s, c));

        // ---- les natures que la route n'atteint pas sans réseau : le point d'entrée du gestionnaire ----
        for (issue, texte) in [
            ("w_http", "backend IA : HTTP 401".to_string()),
            ("w_reponse", "réponse IA invalide : complétion vide".to_string()),
            ("w_reseau", format!("backend IA : connexion {AL3_HOTE_SYNTHETIQUE}:443 : Connection refused (os error 111)")),
            ("w_inconnue", format!("panne imprévue vers {AL3_HOTE_SYNTHETIQUE}")),
            ("w_non_compile", AL3_NON_COMPILE.to_string()),
        ] {
            let (s, c) = al3_reponse(ai_worker_err(id, texte)).await;
            rendus.push((issue, s, c));
        }
        (rendus, id, id_neuf)
    }

    /// Un 5xx nommé : corps ENTIER `{error: <phrase>, id: plume-e…}`.
    fn al3_cinq_cents(manquent: &mut Vec<String>, issue: &str, statut: u16, brut: &str, attendu: u16, phrase: &str) {
        let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
        let cles: Option<std::collections::BTreeSet<&str>> = v.as_object().map(|o| o.keys().map(String::as_str).collect());
        for (propriete, tenue) in [
            ("statut", statut == attendu),
            ("clés exactes `error` et `id`", cles == Some(["error", "id"].into_iter().collect())),
            ("`error` égal à la phrase", v["error"] == json!(phrase)),
            ("identifiant de corrélation", v["id"].as_str().unwrap_or("").starts_with("plume-e")),
        ] {
            if !tenue {
                manquent.push(format!("{issue} : {propriete} — statut {statut}, corps {brut}"));
            }
        }
    }

    /// (1) LES CORPS SERVIS, JUGÉS EN ENTIER.
    #[tokio::test]
    async fn al3_corps_servis_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // `PLUME_AI_ENABLE` est posée pour la portée
        let _ia = ReglageBackupPose::neuf("PLUME_AI_ENABLE", "1");
        let (rendus, _id, id_neuf) = al3_jouer().await;
        let nuage = crate::ai::cloud_allowed();
        let illisible = json!({
            "enabled": false, "runtime": true, "has_provider": null, "provider": null, "cloud_allowed": nuage,
            "fournisseur_non_lu": CAUSE_FOURNISSEUR_D_IA_ACTIF_NON_LU,
        });
        let mut manquent: Vec<String> = Vec::new();
        // Les issues effectivement parcourues par la boucle : comparées après elle à `AL3_ORDRE` (une issue hors de
        // l'ordre tombe aussi dans le bras `autre`).
        let mut jugees: Vec<&str> = Vec::new();
        for (issue, statut, brut) in &rendus {
            let (issue, statut, brut) = (*issue, *statut, brut.as_str());
            let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
            jugees.push(issue);
            match issue {
                "statut_absent" => {
                    let attendu = json!({ "enabled": false, "runtime": true, "has_provider": false, "provider": null, "cloud_allowed": nuage }).to_string();
                    if (statut, brut) != (200, attendu.as_str()) {
                        manquent.push(format!("{issue} : le corps d'avant à l'octet {attendu} — lu {statut} {brut}"));
                    }
                }
                "statut_nominal" => {
                    let attendu = json!({
                        "enabled": true, "runtime": true, "has_provider": true,
                        "provider": { "name": "al3-local", "api_shape": "openai" }, "cloud_allowed": nuage,
                    })
                    .to_string();
                    if (statut, brut) != (200, attendu.as_str()) {
                        manquent.push(format!("{issue} : le corps d'avant à l'octet {attendu} — lu {statut} {brut}"));
                    }
                }
                "statut_table_illisible" | "statut_cellule_illisible" => {
                    if (statut, &v) != (200, &illisible) {
                        manquent.push(format!("{issue} : corps entier {illisible} — lu {statut} {brut}"));
                    }
                }
                "nl_absent" => {
                    if (statut, brut) != (409, AL3_409_D_AVANT) {
                        manquent.push(format!("{issue} : le 409 d'avant à l'octet — lu {statut} {brut}"));
                    }
                }
                "nl_table_illisible" | "nl_cellule_illisible" => {
                    al3_cinq_cents(&mut manquent, issue, statut, brut, 503, CAUSE_ASSISTANT_IA_NON_INTERROGE_FOURNISSEUR_NON_LU);
                }
                "nl_appel_refuse" | "w_http" | "w_reponse" | "w_reseau" | "w_inconnue" => {
                    al3_cinq_cents(&mut manquent, issue, statut, brut, 500, PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE);
                }
                "politique_audit_refuse" | "maj_audit_refuse" | "suppr_audit_refuse" | "cre_audit_refuse" | "cre_insert_refuse" => {
                    al3_cinq_cents(&mut manquent, issue, statut, brut, 500, PHRASE_ECHEC_TRANSACTION_AUDIT);
                }
                "cre_nom_pris" => {
                    if (statut, brut) != (409, AL3_409_NOM_PRIS) {
                        manquent.push(format!("{issue} : le 409 JSON du nom pris, corps entier {AL3_409_NOM_PRIS} — lu {statut} {brut}"));
                    }
                }
                "maj_forme_valide" => {
                    if (statut, brut) != (200, r#"{"ok":true}"#) {
                        manquent.push(format!("{issue} : une forme valide passe, 200 {{\"ok\":true}} — lu {statut} {brut}"));
                    }
                }
                "cre_succes" => {
                    let attendu = json!({ "id": id_neuf, "enabled": false }).to_string();
                    if id_neuf < 1 || (statut, brut) != (200, attendu.as_str()) {
                        manquent.push(format!("{issue} : corps entier {attendu} — lu {statut} {brut}"));
                    }
                }
                "maj_forme_inconnue" => {
                    if (statut, brut) != (400, AL3_400_FORME) {
                        manquent.push(format!("{issue} : 400 de la création à l'octet — lu {statut} {brut}"));
                    }
                }
                "w_non_compile" => {
                    // Un 501 est un 5xx : `err_json` y joint l'identifiant de corrélation, comme avant ce lot.
                    al3_cinq_cents(&mut manquent, issue, statut, brut, 501, AL3_NON_COMPILE);
                }
                autre => manquent.push(format!("issue inattendue : {autre}")),
            }
            for trace in ["no such table", "Invalid column", "not authorized", "SSRF", "backend IA", "127.0.0.1", AL3_HOTE_SYNTHETIQUE, "Query"] {
                if brut.contains(trace) {
                    manquent.push(format!("{issue} : le corps porte « {trace} » : {brut}"));
                }
            }
        }
        assert!(manquent.is_empty(), "corps mal servis :\n{}", manquent.join("\n"));
        assert_eq!(jugees, AL3_ORDRE, "chaque issue attendue jouée et jugée une fois, dans l'ordre");
    }

    /// (2) LE JOURNAL. L'enfant (variable `AL3_ENFANT` posée) joue toutes les issues ; le parent lit son stderr.
    #[tokio::test]
    async fn al3_journal_des_refus_et_des_echecs() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AL3_ENFANT).is_ok() {
            let (rendus, id, _id_neuf) = al3_jouer().await;
            for (issue, statut, brut) in &rendus {
                let v: Value = serde_json::from_str(brut).unwrap_or(Value::Null);
                println!("{AL3_RENDU} {issue} {statut} {}", v["id"].as_str().unwrap_or("absent"));
            }
            println!("{AL3_FIN} {} {id}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::fournisseur_d_ia_actif_lu_et_texte_du_worker_tu::al3_journal_des_refus_et_des_echecs",
            ])
            .env(AL3_ENFANT, "1")
            .env("PLUME_AI_ENABLE", "1")
            .env_remove("PLUME_SSRF_ALLOW")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (joues, id) = stdout
            .lines()
            .find_map(|l| l.split_once(AL3_FIN))
            .and_then(|(_, v)| v.trim().split_once(' ').map(|(a, b)| (a.parse::<usize>().unwrap_or(0), b.to_string())))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}"));
        assert_eq!(joues, AL3_ISSUES, "contrôle : {AL3_ISSUES} issues jouées par l'enfant : {stdout}");
        let ids: std::collections::BTreeMap<&str, &str> = stdout
            .lines()
            .filter_map(|l| l.split_once(AL3_RENDU))
            .filter_map(|(_, r)| {
                let mut morceaux = r.split_whitespace();
                let issue = morceaux.next()?;
                let _statut = morceaux.next()?;
                Some((issue, morceaux.next()?))
            })
            .collect();
        assert_eq!(ids.len(), AL3_ISSUES, "un identifiant (ou `absent`) par issue, issues distinctes : {stdout}");
        let id_de = |issue: &str| ids.get(issue).copied().unwrap_or("manquant").to_string();
        let attendues: Vec<String> = vec![
            format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : adresse du fournisseur refusée par la garde SSRF (cible interne, résolution impossible ou schéma refusé), avant toute connexion", id_de("nl_appel_refuse")),
            "[ia] WARN état de l'assistant IA servi indisponible : le fournisseur actif n'a pas pu être lu (no such table: ai_provider)".to_string(),
            format!("[{}] [ia] WARN assistant IA non interrogé : le fournisseur actif n'a pas pu être lu (no such table: ai_provider)", id_de("nl_table_illisible")),
            format!("[{}] [ia] WARN pose de la politique de caviardage v7 refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("politique_audit_refuse")),
            format!("[{}] [ia] WARN modification du fournisseur d'IA #{id} refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("maj_audit_refuse")),
            format!("[{}] [ia] WARN suppression du fournisseur d'IA #{id} refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("suppr_audit_refuse")),
            format!("[{}] [ia] WARN création du fournisseur d'IA 'al3-neuf' refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("cre_audit_refuse")),
            format!("[{}] [ia] WARN création du fournisseur d'IA 'al3-neuf' refusé : transaction d'audit annulée, aucune modification (not authorized)", id_de("cre_insert_refuse")),
            "[ia] WARN état de l'assistant IA servi indisponible : le fournisseur actif n'a pas pu être lu (Invalid column type Blob at index: 0, name: name)".to_string(),
            format!("[{}] [ia] WARN assistant IA non interrogé : le fournisseur actif n'a pas pu être lu (Invalid column type Blob at index: 2, name: endpoint)", id_de("nl_cellule_illisible")),
            format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : le fournisseur a répondu un statut d'échec, HTTP 401", id_de("w_http")),
            format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : réponse du fournisseur non JSON ou complétion vide", id_de("w_reponse")),
            format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : appel au fournisseur échoué (connexion, TLS, écriture ou lecture)", id_de("w_reseau")),
            format!("[{}] [ia] WARN appel du fournisseur d'IA #{id} échoué, aucune proposition servie : échec d'une nature non reconnue", id_de("w_inconnue")),
        ];
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("[ia] WARN")).collect();
        assert_eq!(lignes, attendues, "une ligne EXACTE par refus ou échec :\n{stderr}");
        // La ligne `HTTP 5xx` d'`err_json` de chaque refus porte l'identifiant servi et la phrase, rien d'autre.
        let mut manquent: Vec<String> = Vec::new();
        for (issue, code, phrase) in [
            ("nl_appel_refuse", 500, PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE),
            ("nl_table_illisible", 503, CAUSE_ASSISTANT_IA_NON_INTERROGE_FOURNISSEUR_NON_LU),
            ("w_inconnue", 500, PHRASE_APPEL_DU_FOURNISSEUR_D_IA_ECHOUE),
            ("maj_audit_refuse", 500, PHRASE_ECHEC_TRANSACTION_AUDIT),
            ("cre_audit_refuse", 500, PHRASE_ECHEC_TRANSACTION_AUDIT),
        ] {
            let http = format!("[{}] HTTP {code} : {phrase}", id_de(issue));
            if !stderr.lines().any(|l| l == http) {
                manquent.push(format!("{issue} : ligne « {http} » absente"));
            }
        }
        // Ni l'hôte du fournisseur ni le texte du worker ne partent au journal.
        for trace in ["SSRF:", "backend IA", AL3_HOTE_SYNTHETIQUE, "panne imprévue"] {
            let porteuses: Vec<&str> = stderr.lines().filter(|l| l.contains(trace)).collect();
            if !porteuses.is_empty() {
                manquent.push(format!("le journal porte « {trace} » : {porteuses:?}"));
            }
        }
        assert!(manquent.is_empty(), "journal mal tenu :\n{}\n{stderr}", manquent.join("\n"));
    }

    /// (3) `P10.29-m` — LES QUATRE GESTES D'IA À `BEGIN` REFUSÉ (`P10.28-d`), JOUÉS : une transaction étrangère pendante
    /// sur l'écrivain, la pose de politique, la création, la modification et la suppression d'un fournisseur rendent
    /// chacune son 503 nommé `{error, id}`, et rien n'est écrit (lu sur l'écrivain lui-même AVANT d'annuler la
    /// transaction étrangère : une écriture faite dedans y serait visible). Contrôle positif : transaction étrangère
    /// annulée, la modification a lieu.
    #[tokio::test]
    async fn al3_begin_refuse_des_quatre_gestes_d_ia() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _base) = router_test_state("al3-begin");
        let addr = router_serve(st.clone()).await;
        al3_sql(
            &st,
            "INSERT INTO ai_provider(name,vendor,api_shape,endpoint,secret,enabled,config_json,created,updated) \
             VALUES('al3-local','local','openai','http://127.0.0.1:11434','',1,'{\"model\":\"al3\"}',1,1);",
        );
        let id = al3_entier(&st, "SELECT id FROM ai_provider WHERE name='al3-local'");
        let avant = al3_etat(&st, id);
        assert_eq!(avant, "fournisseur=1 actif=1 forme=1 politique=0 traces=0", "contrôle : état de départ");
        let gestes: Vec<(&str, &str, String, &str, &str)> = vec![
            ("pose de politique", "PUT", "/api/ai/redaction-policy".to_string(), r#"{"version":8}"#, CAUSE_POLITIQUE_DE_CAVIARDAGE_INCHANGEE_TRANSACTION_NON_OUVERTE),
            ("création", "POST", "/api/ai/providers".to_string(), r#"{"name":"al3-neuf","endpoint":"http://127.0.0.1:11434","enabled":true,"config":{"model":"al3"}}"#, CAUSE_FOURNISSEUR_D_IA_INCHANGE_TRANSACTION_NON_OUVERTE),
            ("modification", "POST", format!("/api/ai/providers/{id}"), r#"{"enabled":false}"#, CAUSE_FOURNISSEUR_D_IA_INCHANGE_TRANSACTION_NON_OUVERTE),
            ("suppression", "DELETE", format!("/api/ai/providers/{id}"), "", CAUSE_FOURNISSEUR_D_IA_INCHANGE_TRANSACTION_NON_OUVERTE),
        ];
        let mut manquent: Vec<String> = Vec::new();
        // Les gestes effectivement joués par la boucle : comparés après elle aux quatre noms attendus.
        let mut joues: Vec<&str> = Vec::new();
        for (quoi, methode, chemin, corps, cause) in &gestes {
            joues.push(*quoi);
            al3_sql(&st, "BEGIN;");
            let (statut, brut) = al3_envoi(addr, methode, chemin, AL3_ADMIN_IDENT, corps).await;
            let pendante = !st.db.lock().is_autocommit();
            let apres = al3_etat(&st, id);
            let neufs = al3_entier(&st, "SELECT COUNT(*) FROM ai_provider WHERE name='al3-neuf'");
            if pendante {
                al3_sql(&st, "ROLLBACK;");
            }
            al3_cinq_cents(&mut manquent, quoi, statut, &brut, 503, cause);
            if !pendante {
                manquent.push(format!("{quoi} : la transaction étrangère n'est plus pendante (validée ou annulée par le geste)"));
            }
            if (apres.as_str(), neufs) != (avant.as_str(), 0) {
                manquent.push(format!("{quoi} : écrit dans la transaction étrangère — {apres}, fournisseurs neufs {neufs}"));
            }
        }
        assert!(manquent.is_empty(), "gestes à BEGIN refusé mal servis :\n{}", manquent.join("\n"));
        assert_eq!(joues, ["pose de politique", "création", "modification", "suppression"], "les quatre gestes joués, dans l'ordre");
        assert_eq!(al3_etat(&st, id), avant, "rien n'est écrit");
        let (statut, brut) = al3_envoi(addr, "POST", &format!("/api/ai/providers/{id}"), AL3_ADMIN_IDENT, r#"{"enabled":false}"#).await;
        assert_eq!((statut, brut.as_str()), (200, r#"{"ok":true}"#), "contrôle positif : sans transaction étrangère, la modification a lieu");
        assert_eq!(al3_entier(&st, &format!("SELECT enabled FROM ai_provider WHERE id={id}")), 0, "contrôle positif : désactivé");
    }
}
