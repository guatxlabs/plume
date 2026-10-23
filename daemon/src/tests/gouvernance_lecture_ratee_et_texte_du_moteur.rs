// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/governance.rs) et `P10.29-l` (famille « texte du moteur servi ») —
// UNE LECTURE RATÉE DE LA GOUVERNANCE N'EST PAS UNE ABSENCE, ET LE TEXTE DU MOTEUR NE PART PAS AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR 2bbee64c AVANT LE CORRECTIF. `legal_hold_release`, `ledger_sink_delete` et `ledger_sink_flush`
// lisaient leur ligne par `match … { Ok(t) => t, Err(_) => return not_found(…) }` : une lecture qui n'avait pas eu lieu
// (ligne qui ne se convertit pas, table retirée) se servait 404 « hold introuvable » / « sink introuvable » — un gel
// toujours actif ou un puits toujours déclaré se disait inexistant. `legal_hold_create`, `legal_hold_release` et
// `ledger_sink_create` refusaient une écriture (geste ou trace d'audit) par un 500 `échec transaction audit (aucune
// modification): <phrase du moteur SQLite>`, et `ledger_sink_delete` par `échec transaction: <phrase du moteur>` (ce
// quatrième site n'était pas dans l'énoncé du tri : même forme, même fonction qu'un site listé).
//
// LE CORRECTIF (décision par défaut de la vague AD). Trois issues : présente, le geste suit ; absente, le 404 d'avant ;
// lecture ratée, 503 nommé (`CAUSE_GEL_JURIDIQUE_NON_LEVE_NON_LU`, `CAUSE_PUITS_DU_REGISTRE_INCHANGE_NON_LU`,
// `CAUSE_ENVOI_DU_PUITS_NON_FAIT_NON_LU`), RIEN n'est levé, supprimé ni exporté, la cause du moteur au journal seul.
// Les quatre 500 gardent leur statut et la phrase fixe `ECHEC_DE_LA_TRANSACTION_D_AUDIT`, la cause du moteur au journal.
//
// LES PANNES ÉPROUVÉES : un `name` stocké en BLOB (la ligne existe, sa lecture comme texte échoue) et la table retirée ;
// un déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (la trace d'audit refusée) ; les lignes de journal lues
// sur le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : par lecture (`GEL`, `PUITS`, `ENVOI`)
// `AD2_<L>_LECTURE_EN_404`, `AD2_<L>_ABSENT_EN_503`, `AD2_<L>_CAUSE_EXPOSEE`, `AD2_<L>_LECTURE_FAIT_LE_GESTE`,
// `AD2_<L>_SANS_JOURNAL` ; par 500 (`POSE`, `LEVEE`, `CREATION`, `SUPPRESSION`) `AD2_<S>_MOTEUR_SERVI`,
// `AD2_<S>_SANS_JOURNAL`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun écran de la console n'appelle ces routes (aucun module de web/ ne cite
// `legal-holds` ni `ledger-sinks`) — l'effet n'est jugé que sur l'API ; une lecture ratée par verrou n'est pas jouée
// (la conversion et la table retirée suffisent à atteindre le bras) ; l'absence d'envoi vers la copie sur une lecture
// ratée est observée par le curseur, pas par la copie (puits `stdout`).
// =====================================================================================
mod gouvernance_lecture_ratee_et_texte_du_moteur {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AD2_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée.
    const AD2_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AD2)";
    const AD2_ABSENT: i64 = 987_654;

    fn ad2_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn ad2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ad2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ad2_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur.
    fn ad2_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str, moteur: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!corps.contains(moteur) && !corps.contains("Blob") && !corps.contains("no such table") && !corps.contains("hors d atteinte"),
            "{quoi} : la cause du moteur ne sort pas : {corps}");
    }

    async fn ad2_poser_un_gel(st: &AppState, nom: &str) -> (u16, String, Value) {
        ad2_reponse(legal_hold_create(State(st.clone()), Extension(ad2_adm()), Json(json!({ "name": nom, "scope_source": "sshd" }))).await).await
    }

    async fn ad2_lever(st: &AppState, id: i64) -> (u16, String, Value) {
        ad2_reponse(legal_hold_release(State(st.clone()), Extension(ad2_adm()), Path(id)).await).await
    }

    async fn ad2_creer_un_puits(st: &AppState, nom: &str) -> (u16, String, Value) {
        ad2_reponse(ledger_sink_create(State(st.clone()), Extension(ad2_adm()), Json(json!({ "name": nom, "kind": "stdout" }))).await).await
    }

    async fn ad2_supprimer(st: &AppState, id: i64) -> (u16, String, Value) {
        ad2_reponse(ledger_sink_delete(State(st.clone()), Extension(ad2_adm()), Path(id)).await).await
    }

    async fn ad2_envoyer(st: &AppState, id: i64) -> (u16, String, Value) {
        ad2_reponse(ledger_sink_flush(State(st.clone()), Extension(ad2_adm()), Path(id)).await).await
    }

    /// Un gel posé par la route, puis rendu illisible (son `name` en BLOB) ; rend son identifiant.
    async fn ad2_gel_illisible(st: &AppState, nom: &str) -> i64 {
        let (statut, corps, v) = ad2_poser_un_gel(st, nom).await;
        assert_eq!(statut, 200, "fixture : le gel se pose : {corps}");
        let id = v["id"].as_i64().expect("identifiant du gel");
        ad2_sql(st, &format!("UPDATE legal_hold SET name=X'00' WHERE id={id}"));
        id
    }

    /// Un puits créé par la route, puis rendu illisible (son `name` en BLOB) ; rend son identifiant.
    async fn ad2_puits_illisible(st: &AppState, nom: &str) -> i64 {
        let (statut, corps, v) = ad2_creer_un_puits(st, nom).await;
        assert_eq!(statut, 200, "fixture : le puits se crée : {corps}");
        let id = v["id"].as_i64().expect("identifiant du puits");
        ad2_sql(st, &format!("UPDATE ledger_sink SET name=X'00' WHERE id={id}"));
        id
    }

    fn ad2_registre_refuse(st: &AppState) {
        ad2_sql(st, &format!("CREATE TRIGGER ad2_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AD2_MOTEUR_ECRITURE}'); END;"));
    }

    fn ad2_registre_rendu(st: &AppState) {
        ad2_sql(st, "DROP TRIGGER ad2_ledger_refuse;");
    }

    /// CE QU'IL TIENT (levée d'un gel) : absent, `404 {"error": "hold introuvable"}` exactement ; ligne illisible puis
    /// table retirée, `503` nommé `CAUSE_GEL_JURIDIQUE_NON_LEVE_NON_LU` en entier, sans la cause du moteur — jamais
    /// `404` ; le gel illisible reste ACTIF, aucune levée n'est attestée, la transaction est fermée. Contrôle : un gel
    /// lisible se lève (`200`).
    /// MUTATIONS : `AD2_GEL_LECTURE_EN_404` (la forme d'avant), `AD2_GEL_ABSENT_EN_503`, `AD2_GEL_CAUSE_EXPOSEE`,
    /// `AD2_GEL_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui lève quand même).
    #[tokio::test]
    async fn ad2_levee_d_un_gel_lecture_ratee_jamais_404_et_rien_n_est_leve() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ad2-gel");
        let (statut, corps, v) = ad2_lever(&st, AD2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "hold introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = ad2_gel_illisible(&st, "litige-ad2-illisible").await;
        let r = ad2_lever(&st, id).await;
        ad2_juger_5xx("gel illisible", &r, 503, CAUSE_GEL_JURIDIQUE_NON_LEVE_NON_LU, AD2_MOTEUR_LECTURE);
        assert_eq!(ad2_compte(&st, &format!("SELECT active FROM legal_hold WHERE id={id}")), 1, "le gel illisible reste ACTIF");
        assert_eq!(ad2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.legal_hold.release'"), 0, "aucune levée attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ad2_poser_un_gel(&st, "litige-ad2-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ad2_lever(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un gel lisible se lève : {corps}");

        ad2_sql(&st, "ALTER TABLE legal_hold RENAME TO legal_hold_ad2_retiree;");
        let r = ad2_lever(&st, id).await;
        ad2_juger_5xx("table des gels retirée", &r, 503, CAUSE_GEL_JURIDIQUE_NON_LEVE_NON_LU, "no such table");
        assert_eq!(ad2_compte(&st, &format!("SELECT active FROM legal_hold_ad2_retiree WHERE id={id}")), 1, "le gel reste actif");
    }

    /// CE QU'IL TIENT (suppression d'un puits) : absent, `404 {"error": "sink introuvable"}` exactement ; ligne
    /// illisible puis table retirée, `503` nommé `CAUSE_PUITS_DU_REGISTRE_INCHANGE_NON_LU` en entier, sans la cause du
    /// moteur ; le puits illisible reste DÉCLARÉ, aucun retrait attesté, transaction fermée. Contrôle : un puits lisible
    /// se supprime (`200`).
    /// MUTATIONS : `AD2_PUITS_LECTURE_EN_404`, `AD2_PUITS_ABSENT_EN_503`, `AD2_PUITS_CAUSE_EXPOSEE`,
    /// `AD2_PUITS_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui supprime quand même).
    #[tokio::test]
    async fn ad2_suppression_d_un_puits_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ad2-puits");
        let (statut, corps, v) = ad2_supprimer(&st, AD2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "sink introuvable" }), "l'absence, rien d'autre : {corps}");

        let id = ad2_puits_illisible(&st, "puits-ad2-illisible").await;
        let r = ad2_supprimer(&st, id).await;
        ad2_juger_5xx("puits illisible", &r, 503, CAUSE_PUITS_DU_REGISTRE_INCHANGE_NON_LU, AD2_MOTEUR_LECTURE);
        assert_eq!(ad2_compte(&st, &format!("SELECT COUNT(*) FROM ledger_sink WHERE id={id}")), 1, "le puits illisible reste DÉCLARÉ");
        assert_eq!(ad2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.ledger_sink.delete'"), 0, "aucun retrait attesté");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = ad2_creer_un_puits(&st, "puits-ad2-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, _) = ad2_supprimer(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un puits lisible se supprime : {corps}");

        ad2_sql(&st, "ALTER TABLE ledger_sink RENAME TO ledger_sink_ad2_retiree;");
        let r = ad2_supprimer(&st, id).await;
        ad2_juger_5xx("table des puits retirée", &r, 503, CAUSE_PUITS_DU_REGISTRE_INCHANGE_NON_LU, "no such table");
        assert_eq!(ad2_compte(&st, &format!("SELECT COUNT(*) FROM ledger_sink_ad2_retiree WHERE id={id}")), 1, "le puits reste déclaré");
    }

    /// CE QU'IL TIENT (envoi vers un puits, dont la lecture se fait SOUS le garde `Txn` déjà ouvert) : absent,
    /// `404 {"error": "sink introuvable"}` exactement ; ligne illisible puis table retirée, `503` nommé
    /// `CAUSE_ENVOI_DU_PUITS_NON_FAIT_NON_LU` en entier, sans la cause du moteur ; le curseur du puits illisible ne bouge
    /// pas (`last_id` = 0 alors que le registre a des maillons), la transaction du garde est fermée. Contrôle : un puits
    /// lisible exporte (`200`, au moins un maillon) et son curseur avance.
    /// MUTATIONS : `AD2_ENVOI_LECTURE_EN_404`, `AD2_ENVOI_ABSENT_EN_503`, `AD2_ENVOI_CAUSE_EXPOSEE`,
    /// `AD2_ENVOI_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui exporte quand même et avance le curseur).
    #[tokio::test]
    async fn ad2_envoi_vers_un_puits_lecture_ratee_jamais_404_et_rien_n_est_exporte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ad2-envoi");
        let (statut, corps, v) = ad2_envoyer(&st, AD2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "sink introuvable" }), "l'absence, rien d'autre : {corps}");
        assert!(st.db.lock().is_autocommit(), "contrôle : l'absence ferme aussi la transaction du garde");

        let id = ad2_puits_illisible(&st, "puits-ad2-envoi-illisible").await;
        assert!(ad2_compte(&st, "SELECT COUNT(*) FROM ledger") >= 1, "fixture : le registre a au moins un maillon à exporter");
        let r = ad2_envoyer(&st, id).await;
        ad2_juger_5xx("puits illisible", &r, 503, CAUSE_ENVOI_DU_PUITS_NON_FAIT_NON_LU, AD2_MOTEUR_LECTURE);
        assert_eq!(ad2_compte(&st, &format!("SELECT last_id FROM ledger_sink WHERE id={id}")), 0, "le curseur ne bouge pas");
        assert!(st.db.lock().is_autocommit(), "la transaction du garde est fermée");

        let (statut, corps, v) = ad2_creer_un_puits(&st, "puits-ad2-envoi-lisible").await;
        assert_eq!(statut, 200, "{corps}");
        let lisible = v["id"].as_i64().expect("identifiant");
        let (statut, corps, v) = ad2_envoyer(&st, lisible).await;
        assert_eq!(statut, 200, "contrôle : un puits lisible exporte : {corps}");
        assert!(v["exported"].as_i64().is_some_and(|n| n >= 1), "{corps}");
        assert!(ad2_compte(&st, &format!("SELECT last_id FROM ledger_sink WHERE id={lisible}")) >= 1, "contrôle : son curseur avance");

        ad2_sql(&st, "ALTER TABLE ledger_sink RENAME TO ledger_sink_ad2_retiree;");
        let r = ad2_envoyer(&st, id).await;
        ad2_juger_5xx("table des puits retirée", &r, 503, CAUSE_ENVOI_DU_PUITS_NON_FAIT_NON_LU, "no such table");
        assert!(st.db.lock().is_autocommit(), "la transaction du garde est fermée");
    }

    /// CE QU'IL TIENT (les quatre 500 d'écriture) : la trace d'audit refusée, la pose d'un gel, sa levée, la création et
    /// la suppression d'un puits rendent `500` dont le corps est EXACTEMENT `{error: ECHEC_DE_LA_TRANSACTION_D_AUDIT,
    /// id}` — sans la phrase du moteur ; rien n'est écrit (aucun gel ni puits de plus, le gel reste actif, le puits reste
    /// déclaré) et la transaction est fermée.
    /// MUTATIONS : `AD2_POSE_MOTEUR_SERVI`, `AD2_LEVEE_MOTEUR_SERVI`, `AD2_CREATION_MOTEUR_SERVI`,
    /// `AD2_SUPPRESSION_MOTEUR_SERVI` (la phrase du moteur réapposée, la forme d'avant).
    #[tokio::test]
    async fn ad2_ecriture_refusee_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ad2-moteur");
        let (_, corps, v) = ad2_poser_un_gel(&st, "litige-ad2-a-lever").await;
        let gel = v["id"].as_i64().unwrap_or_else(|| panic!("fixture : gel posé : {corps}"));
        let (_, corps, v) = ad2_creer_un_puits(&st, "puits-ad2-a-retirer").await;
        let puits = v["id"].as_i64().unwrap_or_else(|| panic!("fixture : puits créé : {corps}"));
        ad2_registre_refuse(&st);
        let cas = [
            ("pose d'un gel", ad2_poser_un_gel(&st, "litige-ad2-refuse").await),
            ("levée d'un gel", ad2_lever(&st, gel).await),
            ("création d'un puits", ad2_creer_un_puits(&st, "puits-ad2-refuse").await),
            ("suppression d'un puits", ad2_supprimer(&st, puits).await),
        ];
        assert!(cas.len() >= 4, "plancher : les quatre sites");
        for (quoi, r) in &cas {
            ad2_juger_5xx(quoi, r, 500, ECHEC_DE_LA_TRANSACTION_D_AUDIT, AD2_MOTEUR_ECRITURE);
        }
        ad2_registre_rendu(&st);
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        assert_eq!(ad2_compte(&st, "SELECT COUNT(*) FROM legal_hold"), 1, "aucun gel de plus");
        assert_eq!(ad2_compte(&st, &format!("SELECT active FROM legal_hold WHERE id={gel}")), 1, "le gel reste actif");
        assert_eq!(ad2_compte(&st, "SELECT COUNT(*) FROM ledger_sink"), 1, "aucun puits de plus, le puits reste déclaré");
        assert_eq!(ad2_compte(&st, &format!("SELECT COUNT(*) FROM ledger_sink WHERE id={puits}")), 1, "le puits reste déclaré");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : chaque lecture ratée et chaque écriture refusée
    /// écrit UNE ligne `[gouvernance] WARN <sujet> : <cause du moteur>` ; le nominal et les trois absences n'en écrivent
    /// aucune. MUTATIONS : `AD2_GEL_SANS_JOURNAL`, `AD2_PUITS_SANS_JOURNAL`, `AD2_ENVOI_SANS_JOURNAL`,
    /// `AD2_POSE_SANS_JOURNAL`, `AD2_LEVEE_SANS_JOURNAL`, `AD2_CREATION_SANS_JOURNAL`, `AD2_SUPPRESSION_SANS_JOURNAL`.
    #[tokio::test]
    async fn ad2_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AD2_ENFANT_JOURNAL";
        const PHASE: &str = "AD2-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ad2-journal");
            eprintln!("{PHASE}gel");
            let id = ad2_gel_illisible(&st, "litige-ad2-journal").await;
            println!("AD2-STATUT-GEL:{}:{id}", ad2_lever(&st, id).await.0);
            eprintln!("{PHASE}puits");
            let id = ad2_puits_illisible(&st, "puits-ad2-journal").await;
            println!("AD2-STATUT-PUITS:{}:{id}", ad2_supprimer(&st, id).await.0);
            eprintln!("{PHASE}envoi");
            println!("AD2-STATUT-ENVOI:{}:{id}", ad2_envoyer(&st, id).await.0);
            eprintln!("{PHASE}ecritures");
            let gel = ad2_poser_un_gel(&st, "litige-ad2-journal-a-lever").await.2["id"].as_i64().unwrap_or(0);
            let puits = ad2_creer_un_puits(&st, "puits-ad2-journal-a-retirer").await.2["id"].as_i64().unwrap_or(0);
            ad2_registre_refuse(&st);
            let a = ad2_poser_un_gel(&st, "litige-ad2-journal-refuse").await.0;
            let b = ad2_lever(&st, gel).await.0;
            let c = ad2_creer_un_puits(&st, "puits-ad2-journal-refuse").await.0;
            let d = ad2_supprimer(&st, puits).await.0;
            println!("AD2-STATUT-ECRITURES:{a}:{b}:{c}:{d}:{gel}:{puits}");
            ad2_registre_rendu(&st);
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("ad2-journal-calme");
            let g = ad2_poser_un_gel(&st, "litige-ad2-calme").await.2["id"].as_i64().unwrap_or(0);
            let s = ad2_creer_un_puits(&st, "puits-ad2-calme").await.2["id"].as_i64().unwrap_or(0);
            let e = ad2_envoyer(&st, s).await.0;
            let l = ad2_lever(&st, g).await.0;
            let r = ad2_supprimer(&st, s).await.0;
            let x = ad2_lever(&st, AD2_ABSENT).await.0;
            let y = ad2_supprimer(&st, AD2_ABSENT).await.0;
            let z = ad2_envoyer(&st, AD2_ABSENT).await.0;
            println!("AD2-STATUT-CALME:{e}:{l}:{r}:{x}:{y}:{z}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::gouvernance_lecture_ratee_et_texte_du_moteur::ad2_lignes_de_journal_des_refus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let gel = marque("AD2-STATUT-GEL:");
        let puits = marque("AD2-STATUT-PUITS:");
        let envoi = marque("AD2-STATUT-ENVOI:");
        let ecritures = marque("AD2-STATUT-ECRITURES:");
        assert_eq!((gel[0].as_str(), puits[0].as_str(), envoi[0].as_str()), ("503", "503", "503"), "contrôle : trois lectures ratées");
        assert_eq!(ecritures[..4], ["500", "500", "500", "500"], "contrôle : quatre écritures refusées");
        assert_eq!(marque("AD2-STATUT-CALME:"), ["200", "200", "200", "404", "404", "404"], "contrôle : nominal et absences");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[gouvernance] ")).map(str::to_string).collect()
        };
        let lectures = [
            ("gel", format!("[gouvernance] WARN gel juridique #{} NON lu pour la levée, rien n'est levé : ", gel[1])),
            ("puits", format!("[gouvernance] WARN puits du registre #{} NON lu pour la suppression, rien n'est supprimé : ", puits[1])),
            ("envoi", format!("[gouvernance] WARN envoi vers le puits du registre #{} NON fait : le puits n'a pas été lu, rien n'est exporté : ", envoi[1])),
        ];
        assert!(lectures.len() >= 3, "plancher : les trois lectures");
        for (nom, tete) in &lectures {
            let lignes = phase(nom);
            assert_eq!(lignes.len(), 1, "phase {nom} : une ligne et une seule : {lignes:?}");
            assert!(lignes[0].starts_with(tete.as_str()) && lignes[0].contains(AD2_MOTEUR_LECTURE), "phase {nom} : sujet et cause du moteur : {}", lignes[0]);
        }
        let (g, p) = (&ecritures[4], &ecritures[5]);
        let attendues = [
            "[gouvernance] WARN pose du gel juridique 'litige-ad2-journal-refuse' NON écrite, rien n'est gelé : ".to_string(),
            format!("[gouvernance] WARN levée du gel juridique 'litige-ad2-journal-a-lever' (#{g}) NON écrite, le gel reste actif : "),
            "[gouvernance] WARN création du puits du registre 'puits-ad2-journal-refuse' NON écrite, aucun puits créé : ".to_string(),
            format!("[gouvernance] WARN suppression du puits du registre 'puits-ad2-journal-a-retirer' (#{p}) NON écrite, le puits reste déclaré : "),
        ];
        assert!(attendues.len() >= 4, "plancher : les quatre écritures");
        let lignes = phase("ecritures");
        assert_eq!(lignes.len(), attendues.len(), "phase ecritures : une ligne par écriture refusée : {lignes:?}");
        for (ligne, tete) in lignes.iter().zip(attendues.iter()) {
            assert!(ligne.starts_with(tete.as_str()) && ligne.contains(AD2_MOTEUR_ECRITURE), "phase ecritures : sujet et cause du moteur : {ligne}");
        }
        assert!(phase("calme").is_empty(), "le nominal et les trois absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
