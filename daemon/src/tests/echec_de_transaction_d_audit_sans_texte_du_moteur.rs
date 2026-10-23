// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi au client », gestes de comptes, de tables d'enrichissement et de
// jetons) — UNE ÉCRITURE OU UNE TRACE D'AUDIT REFUSÉE SERT UNE PHRASE FIXE ; LA CAUSE DU MOTEUR VA AU JOURNAL SEUL.
//
// LE DÉFAUT, MESURÉ SUR 2bbee64c : six sites (`user_create`, `user_delete`, `user_update`, `lookup_upload`,
// `lookup_delete` de `handlers/users_lookups.rs`, `token_delete` de `handlers/tokens.rs`) rendaient
// `server_err(format!("échec transaction audit (aucune modification): {e}"))` : `err_json` servait au client le
// texte de l'erreur SQLite sous `error`, à côté de l'identifiant de corrélation.
//
// DÉCISION PAR DÉFAUT (vague AD) : statut 500 inchangé, phrase fixe `PHRASE_ECHEC_TRANSACTION_AUDIT` (le préfixe
// d'avant, que la console affiche par `.error`), la cause du moteur au journal par
// `servir_l_echec_de_la_transaction_d_audit` (geste et nom visé, jamais un mot de passe, un hash, un jeton ni le
// contenu d'une table).
//
// LES TÉMOINS.
// (1) Les six gestes (plus la réinitialisation du mot de passe par `user_update`, septième jeu) joués sous un
//     autorisateur SQLite qui refuse l'écriture de leur table : chaque corps est jugé EN
//     ENTIER (clés exactes `error` et `id`, `error` égal à la phrase fixe, aucun texte du moteur), statut 500,
//     transaction fermée, rien de changé.
// (2) Le journal : le binaire de test se rejoue en sous-processus, l'enfant joue les six gestes refusés, le parent
//     lit son stderr : une ligne par geste, ÉGALE à la ligne attendue (identifiant de corrélation servi au client, geste,
//     nom visé, cause du moteur) ; dans TOUTE la sortie de l'enfant, ni le mot de passe soumis (création et
//     réinitialisation), ni un hash (`$argon2`), ni le secret du jeton frappé en fixture (hors sa ligne de contrôle).
//
// MUTANTS JOUÉS (`VERIF_MUT`, retirés du source avant le commit) : `AD4_S1` à `AD4_S6` (un site rend à nouveau
// `{e}` au client) font rougir (1) sur leur geste ; `AD4_J` (le journal muet) fait rougir (2). Correction : `AD4_L1`
// (le hash dans le geste de création), `AD4_L2` (le nouveau mot de passe dans le geste de modification) et `AD4_I`
// (la ligne sans l'identifiant de corrélation) font rougir (2).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les quelque quarante-cinq autres sites du même motif (alerting, détection,
// destinations, …) et ceux d'`idp.rs` et `governance.rs` (autres lots) ; le mode multi-tenant ; la console n'est pas
// exercée (elle lit `.error`, texte seulement plus court).
// =====================================================================================
mod echec_de_transaction_d_audit_sans_texte_du_moteur {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Variable qui fait de ce binaire l'enfant du témoin (2).
    const AD4_ENFANT: &str = "AD4_ENFANT_JOURNAL";
    /// Ce que l'enfant écrit sur stdout pour prouver qu'il a joué.
    const AD4_MARQUE_ENFANT: &str = "AD4-ENFANT-A-JOUE";
    /// Ligne de contrôle où l'enfant donne le secret du jeton frappé en fixture (la seule où il peut paraître).
    const AD4_SECRET_ENFANT: &str = "AD4-SECRET-DU-JETON";
    /// Ligne où l'enfant donne l'identifiant de corrélation servi au client, un par geste, dans l'ordre.
    const AD4_ID_ENFANT: &str = "AD4-ID-SERVI";

    /// Un mot de passe recevable, construit — jamais un littéral de clé.
    fn ad4_mot() -> String {
        format!("ad4-mot-{}", "q".repeat(PASSWORD_MIN_CHARS))
    }

    async fn ad4_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn ad4_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Un texte lu sous un verrou relâché au retour (deux verrous dans une même expression s'interbloqueraient).
    fn ad4_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ad4_refuser_l_ecriture(st: &AppState, table: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } | AuthAction::Delete { table_name } if table_name == table => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ad4_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// L'état que les six gestes refusés ne doivent pas changer.
    fn ad4_etat(st: &AppState) -> (i64, i64, i64, String, String) {
        (
            ad4_compte(st, "SELECT COUNT(*) FROM user"),
            ad4_compte(st, "SELECT COUNT(*) FROM lookup_kv WHERE name='ad4_lk'"),
            ad4_compte(st, "SELECT COUNT(*) FROM token WHERE name='ag-ad4'"),
            ad4_texte(st, "SELECT role FROM user WHERE name='bob'"),
            ad4_texte(st, "SELECT COALESCE(hash,'') FROM user WHERE name='bob'"),
        )
    }

    /// Fixture : l'état d'avant (une table d'enrichissement, un jeton) et l'identifiant de `alice` et de `bob`.
    async fn ad4_fixture(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64, i64, String) {
        let (st, p) = sp_state(tag);
        let adm = sp_au("adm", "admin");
        let (s, c) = ad4_corps(lookup_upload(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "ad4_lk", "key_field": "k", "rows": [{ "k": "a", "v": "1" }] }))).await).await;
        assert_eq!(s, 200, "fixture : table d'enrichissement : {c}");
        let (s, c) = ad4_corps(token_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(adm), Json(json!({ "name": "ag-ad4", "kind": "agent", "host": "h-ad4" }))).await).await;
        assert_eq!(s, 200, "fixture : jeton frappé : {c}");
        let secret = c["token"].as_str().filter(|t| t.len() >= 16).unwrap_or_else(|| panic!("fixture : secret du jeton : {c}")).to_string();
        let alice = ad4_compte(&st, "SELECT id FROM user WHERE name='alice'");
        let bob = ad4_compte(&st, "SELECT id FROM user WHERE name='bob'");
        (st, p, alice, bob, secret)
    }

    /// Les six gestes, chacun sous le refus d'écriture de sa table : (nom du geste, statut, corps, transaction fermée).
    async fn ad4_jouer_les_six(st: &AppState, alice: i64, bob: i64) -> Vec<(&'static str, u16, Value, bool)> {
        let adm = sp_au("adm", "admin");
        let pair: ConnectInfo<std::net::SocketAddr> = ConnectInfo("127.0.0.1:40404".parse().expect("adresse"));
        let mut rendus = Vec::new();
        macro_rules! jouer {
            ($quoi:expr, $table:expr, $geste:expr) => {{
                ad4_refuser_l_ecriture(st, $table);
                let r = $geste.await;
                let fermee = st.db.lock().is_autocommit();
                ad4_lever(st);
                let (statut, corps) = ad4_corps(r).await;
                rendus.push(($quoi, statut, corps, fermee));
            }};
        }
        jouer!("création du compte", "user", user_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(adm.clone()), Json(json!({ "name": "dora-ad4", "password": ad4_mot(), "role": "viewer" }))));
        jouer!("suppression du compte", "user", user_delete(State(st.clone()), Extension(adm.clone()), axum::extract::Path(alice)));
        jouer!("modification du compte", "user", user_update(State(st.clone()), crate::secret_des_gestes::presente_de_test(), pair, Extension(adm.clone()), axum::extract::Path(bob), Json(json!({ "role": "viewer" }))));
        jouer!("réinitialisation du mot de passe", "user", user_update(State(st.clone()), crate::secret_des_gestes::presente_de_test(), pair, Extension(adm.clone()), axum::extract::Path(bob), Json(json!({ "password": ad4_mot() }))));
        jouer!("remplacement de", "lookup_kv", lookup_upload(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "ad4_lk", "key_field": "k", "rows": [{ "k": "b", "v": "2" }] }))));
        jouer!("suppression de", "lookup_kv", lookup_delete(State(st.clone()), Extension(adm.clone()), axum::extract::Path("ad4_lk".to_string())));
        jouer!("révocation du jeton", "token", token_delete(State(st.clone()), Extension(adm.clone()), axum::extract::Path("ag-ad4".to_string())));
        rendus
    }

    /// (1) LE CORPS SERVI, JUGÉ EN ENTIER, SUR LES SIX GESTES.
    #[tokio::test]
    async fn ad4_six_gestes_refuses_servent_la_phrase_fixe_sans_texte_du_moteur() {
        let (st, _p, alice, bob, _secret) = ad4_fixture("ad4-corps").await;
        let avant = ad4_etat(&st);
        let rendus = ad4_jouer_les_six(&st, alice, bob).await;
        assert!(rendus.len() >= 7, "plancher : sept gestes joués, {} rendus", rendus.len());
        let mut manquent: Vec<String> = Vec::new();
        for (quoi, statut, corps, fermee) in &rendus {
            let cles: Option<std::collections::BTreeSet<&str>> = corps.as_object().map(|o| o.keys().map(String::as_str).collect());
            let id = corps["id"].as_str().unwrap_or("");
            for (propriete, tenue) in [
                ("statut 500", *statut == 500),
                ("clés exactes `error` et `id`", cles == Some(["error", "id"].into_iter().collect())),
                ("`error` égal à la phrase fixe", corps["error"] == json!(PHRASE_ECHEC_TRANSACTION_AUDIT)),
                ("identifiant de corrélation", id.starts_with("plume-e")),
                ("aucun texte du moteur", !corps.to_string().contains("not authorized")),
                ("transaction fermée", *fermee),
            ] {
                if !tenue {
                    manquent.push(format!("{quoi} : {propriete} — statut {statut}, corps {corps}"));
                }
            }
        }
        assert_eq!(ad4_etat(&st), avant, "les six gestes refusés n'ont rien changé");
        assert!(manquent.is_empty(), "gestes refusés mal servis :\n{}", manquent.join("\n"));
    }

    /// (2) LE JOURNAL. L'enfant (variable `AD4_ENFANT` posée) joue les six gestes refusés ; le parent lit son stderr.
    #[tokio::test]
    async fn ad4_six_gestes_refuses_journalisent_la_cause_du_moteur() {
        if std::env::var(AD4_ENFANT).is_ok() {
            let (st, _p, alice, bob, secret) = ad4_fixture("ad4-journal-enfant").await;
            println!("{AD4_SECRET_ENFANT} {secret}");
            let rendus = ad4_jouer_les_six(&st, alice, bob).await;
            for (_, _, corps, _) in &rendus {
                println!("{AD4_ID_ENFANT} {}", corps["id"].as_str().unwrap_or("absent"));
            }
            println!("{AD4_MARQUE_ENFANT} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::echec_de_transaction_d_audit_sans_texte_du_moteur::ad4_six_gestes_refuses_journalisent_la_cause_du_moteur",
            ])
            .env(AD4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(&format!("{AD4_MARQUE_ENFANT} 7")), "contrôle : l'enfant a joué les sept gestes : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(AD4_ID_ENFANT)).map(|(_, id)| id.trim()).collect();
        let secret = stdout.lines().find_map(|l| l.split_once(AD4_SECRET_ENFANT)).map(|(_, t)| t.trim()).unwrap_or_else(|| panic!("contrôle : secret donné : {stdout}"));
        let gestes = [
            "[comptes] WARN création du compte 'dora-ad4'",
            "[comptes] WARN suppression du compte 'alice'",
            "[comptes] WARN modification du compte 'bob'",
            "[comptes] WARN modification du compte 'bob'",
            "[lookup] WARN remplacement de 'ad4_lk'",
            "[lookup] WARN suppression de 'ad4_lk'",
            "[jetons] WARN révocation du jeton 'ag-ad4'",
        ];
        assert!(gestes.len() >= 7, "plancher : sept lignes attendues");
        assert_eq!(ids.len(), gestes.len(), "contrôle : un identifiant servi par geste : {stdout}");
        assert!(ids.iter().all(|id| id.starts_with("plume-e")), "contrôle : identifiants servis : {ids:?}");
        let attendues: Vec<String> = ids
            .iter()
            .zip(gestes)
            .map(|(id, geste)| format!("[{id}] {geste} refusé : transaction d'audit annulée, aucune modification (not authorized)"))
            .collect();
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("transaction d'audit annulée")).collect();
        assert_eq!(lignes, attendues, "une ligne EXACTE par geste refusé :\n{stderr}");
        let toute_la_sortie = format!("{stdout}\n{stderr}");
        assert!(!toute_la_sortie.contains(&ad4_mot()), "le mot de passe soumis n'est jamais journalisé :\n{stderr}");
        assert!(!toute_la_sortie.contains("$argon2"), "aucun hash n'est journalisé :\n{stderr}");
        let hors_controle: String = toute_la_sortie.lines().filter(|l| !l.contains(AD4_SECRET_ENFANT)).collect::<Vec<_>>().join("\n");
        assert!(!hors_controle.contains(secret), "le secret du jeton n'est jamais journalisé :\n{stderr}");
    }
}
