// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi au client », suite) — CANAUX DE NOTIFICATION, INDICATEURS, EXCLUSION
// D'AFFICHAGE, HÔTES ET SOURCES DÉCLARÉS, IMPORTS SIGMA, ÉLAGAGE DES OVERLAYS, SOURCE PUSH, SUPPRESSION ET BASCULE
// D'UNE RÈGLE, LISTE DES CORRÉLATIONS : UNE ÉCRITURE OU UNE LECTURE REFUSÉE SERT UNE PHRASE FIXE ; LA CAUSE DU MOTEUR
// VA AU JOURNAL SEUL.
//
// LE DÉFAUT, MESURÉ SUR 88afe566 : quinze sites collaient le texte de l'erreur SQLite au corps servi —
// `notifier_create`, `notifier_update`, `notifier_delete` (notifiers.rs), `ioc_add`, `stix_import` (threat_intel.rs),
// `apply_display_excl_edit` (admin_ui.rs, servi par `suppressions_put`), `host_settings_put` (hotes_declares.rs),
// `source_settings_put` (sources.rs), `sigma_import`, `sigma_import_bulk` (sigma.rs), `config_overlays_prune`
// (overlays.rs), `connector_push_source` (connectors/presets.rs) : `échec transaction … : {e}` en 500 ;
// `delete_managed_row_tx` et `set_content_enabled_tx` (detection.rs, servis par `rule_delete` et `rule_set_enabled`)
// : le même texte dans le tuple d'erreur ; `correlations_list` (detection_advanced.rs) : `corrélations NON LUES : {e}`
// dans un corps deux cents.
//
// DÉCISION PAR DÉFAUT (vague AI) : statuts inchangés (500 ; 200 pour la liste des corrélations) ; phrase fixe
// `PHRASE_ECHEC_TRANSACTION_AUDIT` par `servir_l_echec_de_la_transaction_d_audit` là où le site rend une réponse ; la
// même phrase dans le tuple là où il rend `(StatusCode, String)` (l'appelant la sert par `err_json`, avec
// l'identifiant de corrélation ; le site journalise la cause sans cet identifiant, frappé plus haut) ;
// une phrase fixe littérale dans `format!` pour la liste (elle s'ouvre encore sur « corrélations NON LUES » : un
// littéral unique de `format!` sous la clé `error` est la forme que relit l'instrument 98 de `web_esm_harnais.mjs`), égale
// à `AI3_CAUSE_CORRELATIONS_ATTENDUE` par le témoin (1). Un adossement illisible de l'élagage garde sa phrase : c'est
// un refus de NOTRE code, pas du moteur.
//
// LES TÉMOINS.
// (1) Les quinze sites joués chacun sous un autorisateur SQLite qui refuse l'écriture d'une table du geste (la
//     lecture de la table des corrélations pour la liste) : chaque corps est jugé EN ENTIER (clés exactes, phrase
//     fixe, identifiant de corrélation pour les 500, aucun texte du moteur), statut, transaction fermée, rien changé.
// (2) Le journal : le binaire de test se rejoue en sous-processus, l'enfant joue les quinze sites, le parent lit son
//     stderr : une ligne par site, ÉGALE à la ligne attendue (identifiant servi en tête pour les onze sites qui
//     passent par l'assistant, geste, cause du moteur) ; pour les trois sites à tuple, la ligne `HTTP 500` de
//     `err_json` porte l'identifiant servi et la phrase fixe, rien d'autre.
// (3) L'élagage sur un adossement illisible garde sa phrase propre (bras laissé intact, témoigné ; le chemin et la
//     cause d'E/S qu'elle porte sont un RESTE, non figé par le témoin).
// (1) et (2) jouent sous un `PLUME_CONFIG_DIR` vide et temporaire (posé sous `VERROU_ENV_PROCESSUS.write()`, passé à
//     l'enfant par `.env(`) : le dossier par défaut de l'hôte ne décide pas de l'élagage.
//
// MUTANTS JOUÉS (`VERIF_MUT`, retirés du source avant le commit) : `AI3_NOTIF_C`, `AI3_NOTIF_M`, `AI3_NOTIF_S`,
// `AI3_TI_AJOUT`, `AI3_TI_STIX`, `AI3_EXCL`, `AI3_HOTE`, `AI3_SOURCE`, `AI3_SIGMA`, `AI3_SIGMA_MASSE`,
// `AI3_OVERLAYS`, `AI3_PRESET`, `AI3_DET_SUPPR`, `AI3_DET_BASCULE`, `AI3_CORR` (un site rend à nouveau `{e}` au
// client) font rougir (1) sur leur site ; `AI3_EXCL_J`, `AI3_DET_SUPPR_J`, `AI3_DET_BASCULE_J`, `AI3_CORR_J` (la
// ligne de journal tue) font rougir (2) ; `AI3_OVERLAYS_ADOS` (l'adossement servi par la phrase fixe) fait rougir (3).
// Correction : `AI3B_CORR_LIT` (la liste sert une autre phrase que le littéral attendu) fait rougir (1) ;
// `AI3B_HOSTILE_SANS_POSE` (un `PLUME_CONFIG_DIR` hostile hérité, un `rules/*.json` illisible, sans le dossier vide
// posé par le témoin) fait rougir (1) et (2), quand `AI3B_HOSTILE` (le même héritage, dossier vide posé) reste vert.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les sites d'`ai.rs` (feature éteinte) et de `connectors/mod.rs` (autre lot) ;
// les deux cents `journal NON LU : {cause}` (admin_ui.rs) et `inventaire NON LU : {cause}` (sources.rs), qui servent
// encore le texte du moteur ; `ti_coverage` (threat_intel.rs) sert encore son SQL et le texte du moteur sous
// `detail` et ses deux ventilations NON LUES dans un deux cents ; l'adossement illisible sert le chemin du fichier et
// la cause d'E/S ; le mode
// multi-tenant ; la console n'est pas exercée (elle lit `.error`).
// =====================================================================================
mod echec_de_transaction_sans_texte_du_moteur_canaux_indicateurs_sigma_detection {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Variable qui fait de ce binaire l'enfant du témoin (2).
    const AI3_ENFANT: &str = "AI3_ENFANT_JOURNAL";
    /// Ce que l'enfant écrit sur stdout pour prouver qu'il a joué.
    const AI3_MARQUE_ENFANT: &str = "AI3-ENFANT-A-JOUE";
    /// Ligne où l'enfant donne l'identifiant servi au client, un par site, dans l'ordre (`absent` sinon).
    const AI3_ID_ENFANT: &str = "AI3-ID-SERVI";
    /// Ligne où l'enfant donne l'identifiant du canal et celui de la règle de la fixture.
    const AI3_IDS_FIXTURE: &str = "AI3-IDS-FIXTURE";
    /// Le nombre de sites joués par (1) et (2).
    const AI3_SITES: usize = 15;
    /// La phrase que `correlations_list` doit servir sous `error` (littéral de son `format!`).
    const AI3_CAUSE_CORRELATIONS_ATTENDUE: &str = "corrélations NON LUES : la base n'a pas rendu la table des \
         corrélations — ce n'est PAS « aucune corrélation », c'est une lecture qui n'a pas eu lieu. Réessayez ; si le \
         refus persiste, la table des corrélations est illisible.";

    async fn ai3_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn ai3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ai3_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ai3_refuser_l_ecriture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } if table_name == table => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Refuse toute instruction SELECT : la liste des corrélations ne se prépare pas (« not authorized »).
    fn ai3_refuser_la_lecture(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ai3_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// L'état que les quinze sites refusés ne doivent pas changer.
    fn ai3_etat(st: &AppState, nid: i64, rid: i64) -> Vec<String> {
        vec![
            ai3_compte(st, "SELECT COUNT(*) FROM notifier WHERE name='ai3-neuf'").to_string(),
            ai3_texte(st, &format!("SELECT name FROM notifier WHERE id={nid}")),
            ai3_compte(st, "SELECT COUNT(*) FROM ioc").to_string(),
            ai3_compte(st, &format!("SELECT COUNT(*) FROM setting WHERE key='{EXCL_OP_SETTING}'")).to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM host_settings").to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM source_settings").to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM rule WHERE name LIKE 'ai3%'").to_string(),
            ai3_compte(st, &format!("SELECT COUNT(*) FROM rule WHERE id={rid} AND enabled=1")).to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM rule WHERE name='ai3-orpheline' AND managed=1").to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM connector").to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM ledger").to_string(),
            ai3_compte(st, "SELECT COUNT(*) FROM detection_override").to_string(),
        ]
    }

    /// Fixture : un canal (`ai3-canal`), une règle ad-hoc (`ai3-geree`, managed=2, active) et une orpheline
    /// `managed=1` qu'aucun fichier n'adosse (l'élagage la supprimerait).
    async fn ai3_fixture(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64, i64) {
        let (st, p) = sp_state(tag);
        let adm = sp_au("adm", "admin");
        let (s, c) = ai3_corps(notifier_create(State(st.clone()), Extension(adm), Json(json!({ "kind": "webhook", "url": "http://10.0.0.9/ai3", "name": "ai3-canal" }))).await).await;
        assert_eq!(s, 200, "fixture : canal créé : {c}");
        let nid = c["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant du canal : {c}"));
        let rid = {
            let conn = st.db.lock();
            conn.execute_batch(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                 VALUES('ai3-orpheline',1,'search source=auth | stats count',1,'>',0,2,300,3600,1)",
            )
            .expect("fixture : orpheline");
            conn.execute_batch(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
                 VALUES('ai3-geree',1,'search source=auth | stats count',1,'>',0,2,300,3600,2)",
            )
            .expect("fixture : règle ad-hoc");
            conn.last_insert_rowid()
        };
        (st, p, nid, rid)
    }

    /// Un document Sigma traduisible.
    fn ai3_sigma(titre: &str) -> Value {
        json!({ "title": titre, "logsource": { "service": "sshd" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" }, "level": "medium" })
    }

    /// Les quinze sites, chacun sous son refus : (site, statut, corps, transaction fermée).
    async fn ai3_jouer_les_quinze(st: &AppState, nid: i64, rid: i64) -> Vec<(&'static str, u16, Value, bool)> {
        let adm = sp_au("adm", "admin");
        let mut rendus = Vec::new();
        macro_rules! jouer {
            ($quoi:expr, $refuser:expr, $geste:expr) => {{
                $refuser;
                let r = $geste.await.into_response();
                let fermee = st.db.lock().is_autocommit();
                ai3_lever(st);
                let (statut, corps) = ai3_corps(r).await;
                rendus.push(($quoi, statut, corps, fermee));
            }};
        }
        jouer!("création du canal", ai3_refuser_l_ecriture(st, "notifier"),
            notifier_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "kind": "webhook", "url": "http://10.0.0.9/ai3-neuf", "name": "ai3-neuf" }))));
        jouer!("modification du canal", ai3_refuser_l_ecriture(st, "notifier"),
            notifier_update(State(st.clone()), Extension(adm.clone()), Path(nid), Json(json!({ "name": "ai3-renomme" }))));
        jouer!("suppression du canal", ai3_refuser_l_ecriture(st, "notifier"),
            notifier_delete(State(st.clone()), Extension(adm.clone()), Path(nid)));
        jouer!("ajout d'indicateurs", ai3_refuser_l_ecriture(st, "ledger"),
            ioc_add(State(st.clone()), Extension(adm.clone()), Json(json!({ "type": "ip", "value": "203.0.113.77" }))));
        let paquet = json!({ "bundle": { "type": "bundle", "id": "bundle--ai3", "objects": [
            { "type": "indicator", "id": "indicator--ai3", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '198.51.100.77']" }] } });
        jouer!("import STIX", ai3_refuser_l_ecriture(st, "ledger"),
            stix_import(State(st.clone()), Extension(adm.clone()), Json(paquet)));
        jouer!("exclusion d'affichage", ai3_refuser_l_ecriture(st, "setting"),
            suppressions_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "action": "set_operator_excl", "value": "203.0.113.7" }))));
        jouer!("déclaration d'hôte", ai3_refuser_l_ecriture(st, "host_settings"),
            host_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "host": "srv-ai3", "action": "set_attente", "value": "silence_attendu", "motif": "ai3" }))));
        jouer!("réglage d'une source", ai3_refuser_l_ecriture(st, "source_settings"),
            source_settings_put(State(st.clone()), Extension(adm.clone()), Json(json!({ "source": "okta", "action": "set_label", "value": "Okta" }))));
        jouer!("import Sigma", ai3_refuser_l_ecriture(st, "rule"),
            sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [ai3_sigma("ai3 sigma")] }))));
        jouer!("import Sigma en masse", ai3_refuser_l_ecriture(st, "rule"),
            sigma_import_bulk(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [ai3_sigma("ai3 masse")] }))));
        jouer!("élagage des overlays", ai3_refuser_l_ecriture(st, "ledger"),
            config_overlays_prune(State(st.clone()), Extension(adm.clone())));
        jouer!("source push", ai3_refuser_l_ecriture(st, "connector"),
            connector_push_source(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(adm.clone()), Json(json!({ "preset_id": "aws-cloudtrail", "name": "ai3-push" }))));
        jouer!("suppression de la règle", ai3_refuser_l_ecriture(st, "rule"),
            rule_delete(State(st.clone()), Extension(adm.clone()), Path(rid)));
        jouer!("bascule de la règle", ai3_refuser_l_ecriture(st, "rule"),
            rule_set_enabled(State(st.clone()), Extension(adm.clone()), Path(rid), Json(json!({ "enabled": false }))));
        jouer!("liste des corrélations", ai3_refuser_la_lecture(st),
            correlations_list(State(st.clone()), Extension(adm.clone())));
        rendus
    }

    /// (1) LE CORPS SERVI, JUGÉ EN ENTIER, SUR LES QUINZE SITES.
    #[tokio::test]
    async fn ai3_quinze_sites_refuses_servent_une_phrase_fixe_sans_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // `PLUME_CONFIG_DIR` est posée pour la portée
        let dossier = crate::tmp_possede::TmpPossede::neuf("ai3-config-d-vide");
        let _pose = ReglageBackupPose::neuf("PLUME_CONFIG_DIR", dossier.to_str().expect("chemin UTF-8"));
        let (st, _p, nid, rid) = ai3_fixture("ai3-corps").await;
        let avant = ai3_etat(&st, nid, rid);
        let rendus = ai3_jouer_les_quinze(&st, nid, rid).await;
        assert!(rendus.len() >= AI3_SITES, "plancher : quinze sites joués, {} rendus", rendus.len());
        let mut manquent: Vec<String> = Vec::new();
        for (quoi, statut, corps, fermee) in &rendus {
            let cles: Option<std::collections::BTreeSet<&str>> = corps.as_object().map(|o| o.keys().map(String::as_str).collect());
            let proprietes: Vec<(&str, bool)> = if *quoi == "liste des corrélations" {
                vec![
                    ("statut 200", *statut == 200),
                    ("clés exactes `correlations`, `error`, `lecture_non_faite`", cles == Some(["correlations", "error", "lecture_non_faite"].into_iter().collect())),
                    ("`correlations` nul", corps["correlations"] == Value::Null),
                    ("`error` égal à la phrase fixe", corps["error"] == json!(AI3_CAUSE_CORRELATIONS_ATTENDUE)),
                    ("`error` s'ouvre sur « corrélations NON LUES »", corps["error"].as_str().unwrap_or("").starts_with("corrélations NON LUES")),
                    ("`lecture_non_faite` vrai", corps["lecture_non_faite"] == json!(true)),
                ]
            } else {
                vec![
                    ("statut 500", *statut == 500),
                    ("clés exactes `error` et `id`", cles == Some(["error", "id"].into_iter().collect())),
                    ("`error` égal à la phrase fixe", corps["error"] == json!(PHRASE_ECHEC_TRANSACTION_AUDIT)),
                    ("identifiant de corrélation", corps["id"].as_str().unwrap_or("").starts_with("plume-e")),
                ]
            };
            for (propriete, tenue) in proprietes.into_iter().chain([
                ("aucun texte du moteur", !corps.to_string().contains("not authorized")),
                ("transaction fermée", *fermee),
            ]) {
                if !tenue {
                    manquent.push(format!("{quoi} : {propriete} — statut {statut}, corps {corps}"));
                }
            }
        }
        assert_eq!(ai3_etat(&st, nid, rid), avant, "les quinze sites refusés n'ont rien changé");
        assert!(manquent.is_empty(), "sites refusés mal servis :\n{}", manquent.join("\n"));
    }

    /// (2) LE JOURNAL. L'enfant (variable `AI3_ENFANT` posée) joue les quinze sites ; le parent lit son stderr.
    #[tokio::test]
    async fn ai3_quinze_sites_refuses_journalisent_la_cause_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'élagage et l'exclusion lisent leur conf (`cfg`)
        if std::env::var(AI3_ENFANT).is_ok() {
            let (st, _p, nid, rid) = ai3_fixture("ai3-journal-enfant").await;
            println!("{AI3_IDS_FIXTURE} {nid} {rid}");
            let rendus = ai3_jouer_les_quinze(&st, nid, rid).await;
            for (_, _, corps, _) in &rendus {
                println!("{AI3_ID_ENFANT} {}", corps["id"].as_str().unwrap_or("absent"));
            }
            println!("{AI3_MARQUE_ENFANT} {}", rendus.len());
            return;
        }
        // L'enfant joue sous un `PLUME_CONFIG_DIR` vide et temporaire, pas sous le dossier par défaut de l'hôte.
        let dossier = crate::tmp_possede::TmpPossede::neuf("ai3-config-d-vide-enfant");
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::echec_de_transaction_sans_texte_du_moteur_canaux_indicateurs_sigma_detection::ai3_quinze_sites_refuses_journalisent_la_cause_du_moteur",
            ])
            .env(AI3_ENFANT, "1")
            .env("PLUME_CONFIG_DIR", &*dossier)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(&format!("{AI3_MARQUE_ENFANT} {AI3_SITES}")), "contrôle : l'enfant a joué les quinze sites : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(AI3_ID_ENFANT)).map(|(_, id)| id.trim()).collect();
        let (nid, rid) = stdout
            .lines()
            .find_map(|l| l.split_once(AI3_IDS_FIXTURE))
            .and_then(|(_, v)| v.trim().split_once(' ').map(|(a, b)| (a.to_string(), b.to_string())))
            .unwrap_or_else(|| panic!("contrôle : identifiants de la fixture donnés : {stdout}"));
        assert_eq!(ids.len(), AI3_SITES, "contrôle : un identifiant (ou `absent`) par site : {stdout}");
        // (geste journalisé, la ligne porte-t-elle l'identifiant servi en tête)
        let gestes: Vec<(String, bool)> = vec![
            ("[notifiers] WARN création du canal 'ai3-neuf' refusé".to_string(), true),
            (format!("[notifiers] WARN modification du canal #{nid} refusé"), true),
            (format!("[notifiers] WARN suppression du canal #{nid} refusé"), true),
            ("[threat-intel] WARN ajout d'indicateurs refusé".to_string(), true),
            ("[threat-intel] WARN import STIX refusé".to_string(), true),
            ("[suppressions] WARN exclusion d'affichage operator refusée".to_string(), false),
            ("[hotes] WARN déclaration d'hôte refusé".to_string(), true),
            ("[sources] WARN réglage d'une source refusé".to_string(), true),
            ("[sigma] WARN import Sigma refusé".to_string(), true),
            ("[sigma] WARN import Sigma en masse refusé".to_string(), true),
            ("[overlays] WARN élagage des overlays orphelins refusé".to_string(), true),
            ("[connecteurs] WARN création de la source push 'ai3-push' refusé".to_string(), true),
            (format!("[detection] WARN suppression de rule #{rid} refusée"), false),
            (format!("[detection] WARN bascule d'activation de rule #{rid} refusée"), false),
        ];
        assert!(gestes.len() + 1 >= AI3_SITES, "plancher : quatorze lignes de transaction et celle de la liste attendues");
        let mut attendues: Vec<String> = Vec::new();
        let mut manquent: Vec<String> = Vec::new();
        for (i, (geste, avec_id)) in gestes.iter().enumerate() {
            let id = ids[i];
            if !id.starts_with("plume-e") {
                manquent.push(format!("site {i} ({geste}) : identifiant servi attendu, lu « {id} »"));
            }
            let ligne = format!("{geste} : transaction d'audit annulée, aucune modification (not authorized)");
            attendues.push(if *avec_id { format!("[{id}] {ligne}") } else { ligne });
            if !avec_id {
                // Le site à tuple : la ligne `HTTP 500` d'`err_json` relie l'identifiant servi à la phrase fixe.
                let http = format!("[{id}] HTTP 500 : {PHRASE_ECHEC_TRANSACTION_AUDIT}");
                if !stderr.lines().any(|l| l == http) {
                    manquent.push(format!("site {i} ({geste}) : ligne « {http} » absente"));
                }
            }
        }
        attendues.push("[detection] WARN liste des corrélations NON LUE, aucune liste servie (not authorized)".to_string());
        assert_eq!(ids[AI3_SITES - 1], "absent", "contrôle : la liste des corrélations (deux cents) ne sert pas d'identifiant");
        let lignes: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("transaction d'audit annulée") || l.contains("liste des corrélations NON LUE"))
            .collect();
        assert_eq!(lignes, attendues, "une ligne EXACTE par site refusé :\n{stderr}");
        // Aucune ligne `HTTP 500` de ces sites ne porte le texte du moteur (la phrase servie l'a quitté).
        let http_moteur: Vec<&str> = stderr.lines().filter(|l| l.contains("HTTP 500") && l.contains("not authorized")).collect();
        assert!(http_moteur.is_empty(), "la ligne `HTTP 500` porte encore le texte du moteur : {http_moteur:?}");
        assert!(manquent.is_empty(), "journal incomplet :\n{}\n{stderr}", manquent.join("\n"));
    }

    /// (3) L'ADOSSEMENT ILLISIBLE GARDE SA PHRASE : un `rules/*.json` invalide sous `PLUME_CONFIG_DIR` refuse l'élagage
    /// par le refus de NOTRE code, nommé, et non par la phrase fixe d'une transaction refusée par le moteur.
    #[tokio::test]
    async fn ai3_elagage_sur_adossement_illisible_garde_sa_phrase() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // `PLUME_CONFIG_DIR` est posée pour la portée
        let dossier = crate::tmp_possede::TmpPossede::neuf("ai3-config-d");
        std::fs::create_dir_all(dossier.join("rules")).expect("fixture : dossier des règles");
        std::fs::write(dossier.join("rules").join("ai3.json"), "{ pas du json").expect("fixture : fichier illisible");
        let _pose = ReglageBackupPose::neuf("PLUME_CONFIG_DIR", dossier.to_str().expect("chemin UTF-8"));
        let (st, _p, nid, rid) = ai3_fixture("ai3-adossement").await;
        let avant = ai3_etat(&st, nid, rid);
        let (statut, corps) = ai3_corps(config_overlays_prune(State(st.clone()), Extension(sp_au("adm", "admin"))).await).await;
        let cles: Option<std::collections::BTreeSet<&str>> = corps.as_object().map(|o| o.keys().map(String::as_str).collect());
        assert_eq!(statut, 500, "adossement illisible : 500 : {corps}");
        assert_eq!(cles, Some(["error", "id"].into_iter().collect()), "clés exactes `error` et `id` : {corps}");
        let error = corps["error"].as_str().unwrap_or("");
        assert!(
            error.starts_with("échec transaction prune (aucune modification): adossement illisible ("),
            "l'adossement illisible garde sa phrase, pas celle d'une transaction refusée : {corps}"
        );
        assert!(st.db.lock().is_autocommit(), "transaction fermée");
        assert_eq!(ai3_etat(&st, nid, rid), avant, "rien n'est élagué sur un adossement illisible");
    }
}
