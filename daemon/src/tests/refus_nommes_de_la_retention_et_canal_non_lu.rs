// =====================================================================================
// `P10.29-l` (restes : `retention_settings_put`, `retention_preview`) et `P10.20-b` (rang quatre : `notifier_test`) —
// LES REFUS DE LA RÉTENTION SONT DES OBJETS `{error}` NOMMÉS, ET L'ESSAI D'UN CANAL DISTINGUE L'ABSENCE DE LA LECTURE RATÉE.
//
// LE DÉFAUT, MESURÉ SUR aa19c5fa AVANT LE CORRECTIF. `PUT /api/retention` refusait le rôle par un 403 en texte nu et
// une écriture refusée (réglage ou trace d'audit) par un 500 TEXTE `échec transaction audit (aucune modification
// appliquée): <phrase du moteur SQLite>` — la cause du moteur servie au client. `GET /api/retention/preview` refusait
// le rôle (403) et une clé inconnue (400) en texte nu. `POST /api/notifiers/{id}/test` lisait la ligne du canal par
// `.ok()` : une lecture ratée devenait une absence, servie 404 « canal introuvable ».
//
// LE CORRECTIF (décision par défaut de la vague AC). Mêmes statuts, corps `{"error": CAUSE_…}` ; l'écriture refusée
// passe de 500 à 503 nommé `CAUSE_RETENTION_INCHANGEE_ECRITURE_NON_PRISE` (ouverture « écriture non prise » que
// web/core.js lit déjà), cause du moteur au journal seul. `notifier_test` : présent = essayé, absent = le 404 d'avant,
// lecture ratée = 503 `CAUSE_CANAL_NON_ESSAYE_NON_LU`, cause du moteur au journal seul, aucun envoi.
//
// LES PANNES ÉPROUVÉES : déclencheurs `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (trace d'audit) et `BEFORE INSERT ON
// setting` (réglage) ; un `kind` de canal stocké en BLOB (illisible comme texte) et la table des canaux retirée ; les
// lignes de journal lues sur le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AC3_PUT_403_TEXTE`, `AC3_PUT_500_TEXTE_MOTEUR`,
// `AC3_PUT_CAUSE_EXPOSEE`, `AC3_PUT_EN_500`, `AC3_PUT_SANS_JOURNAL`, `AC3_APERCU_403_TEXTE`, `AC3_APERCU_400_TEXTE`,
// `AC3_CANAL_ABSENT_EN_503`, `AC3_CANAL_LECTURE_EN_404`, `AC3_CANAL_CAUSE_EXPOSEE`, `AC3_CANAL_SANS_JOURNAL`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le 403 du rôle sur l'essai d'un canal reste la phrase TEXTE partagée avec la
// création, la modification et la suppression (`refus_du_role_sur_un_canal`, que la console lit comme le refus du rôle
// et qu'un instrument du harnais ESM ancre) ; les 403 internes de la rétention ne sont joignables que par appel direct
// (le routeur refuse `/api/retention` à tout non-administrateur) ; l'absence d'envoi sur la lecture ratée découle du
// retour anticipé, elle n'est pas observée ; la console n'est pas jouée ici.
// =====================================================================================
mod refus_nommes_de_la_retention_et_canal_non_lu {
    use super::*;

    fn ac3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ac3-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.29-l` : la chaîne de migrations doit aller au bout");
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ac3_utilisateur(role: &str) -> AuthUser {
        AuthUser {
            name: "exploitant".into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ac3_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ac3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    async fn ac3_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    async fn ac3_regler(st: &AppState, role: &str, jours: i64) -> (u16, String, Value) {
        ac3_reponse(retention_settings_put(State(st.clone()), Extension(ac3_utilisateur(role)), Json(json!({ "retention_days": jours }))).await).await
    }

    async fn ac3_apercu(st: &AppState, role: &str, cle: &str) -> (u16, String, Value) {
        let q = Query(HashMap::from([("key".to_string(), cle.to_string()), ("value".to_string(), "10".to_string())]));
        ac3_reponse(retention_preview(State(st.clone()), Extension(ac3_utilisateur(role)), q).await).await
    }

    async fn ac3_essayer(st: &AppState, id: i64) -> (u16, String, Value) {
        ac3_reponse(notifier_test(State(st.clone()), Extension(ac3_utilisateur("admin")), Path(id)).await.into_response()).await
    }

    const AC3_REGLAGE_ECRIT: &str = "SELECT COUNT(*) FROM setting WHERE scope='global' AND key='retention_days'";
    const AC3_MOTEUR_REGISTRE: &str = "registre hors d atteinte (temoin AC3)";
    const AC3_MOTEUR_REGLAGE: &str = "reglage hors d atteinte (temoin AC3)";
    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AC3_MOTEUR_LECTURE: &str = "Invalid column type";
    /// Une valeur de rétention admise (plancher 7, plafond 3650) et distincte du défaut (30) : l'écriture a lieu.
    const AC3_JOURS: i64 = 45;
    const AC3_CANAL_ABSENT: i64 = 987_654;

    fn ac3_registre_refuse(st: &AppState) {
        ac3_sql(st, &format!("CREATE TRIGGER ac3_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AC3_MOTEUR_REGISTRE}'); END;"));
    }

    fn ac3_reglage_refuse(st: &AppState) {
        ac3_sql(st, &format!("CREATE TRIGGER ac3_setting_refuse BEFORE INSERT ON setting BEGIN SELECT RAISE(ABORT, '{AC3_MOTEUR_REGLAGE}'); END;"));
    }

    /// Un canal dont le `kind` est un BLOB : la ligne existe, sa lecture comme texte échoue.
    fn ac3_canal_illisible(st: &AppState) -> i64 {
        let conn = st.db.lock();
        conn.execute("INSERT INTO notifier(name,kind,url,enabled) VALUES('ac3',X'00','http://192.0.2.10/ac3',1)", []).unwrap();
        conn.last_insert_rowid()
    }

    /// CE QU'IL TIENT : un non-administrateur reçoit `403` dont le corps est un OBJET `{"error":
    /// CAUSE_RETENTION_RESERVEE_A_L_ADMINISTRATEUR}` ; rien n'est écrit. MUTATION : `AC3_PUT_403_TEXTE` (texte nu d'avant).
    #[tokio::test]
    async fn ac3_reglage_refuse_par_le_role_rend_un_403_nomme() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // load_config et le résolveur lisent l'environnement
        let (st, _tmp) = ac3_etat("role");
        let (statut, corps, v) = ac3_regler(&st, "editor", AC3_JOURS).await;
        assert_eq!(statut, 403, "{corps}");
        assert_eq!(v, json!({ "error": CAUSE_RETENTION_RESERVEE_A_L_ADMINISTRATEUR }), "un objet nommé, rien d'autre : {corps}");
        assert_eq!(ac3_compte(&st, AC3_REGLAGE_ECRIT), 0, "rien n'est écrit");
    }

    /// CE QU'IL TIENT : la trace d'audit refusée, PUIS le réglage refusé, rendent chacun `503` dont l'erreur est
    /// EXACTEMENT `CAUSE_RETENTION_INCHANGEE_ECRITURE_NON_PRISE`, avec identifiant de corrélation, sans la phrase du
    /// moteur ; rien n'est écrit et la transaction est fermée. La cause s'ouvre par la forme que la console lit
    /// « écriture non prise » (en-tête, « la base n'a pas pris l'écriture », « et la transaction est annulée », ni BEGIN
    /// ni COMMIT). Contrôle : sans panne, `200` et le réglage écrit.
    /// MUTATIONS : `AC3_PUT_500_TEXTE_MOTEUR` (la forme d'avant), `AC3_PUT_CAUSE_EXPOSEE`, `AC3_PUT_EN_500`.
    #[tokio::test]
    async fn ac3_ecriture_refusee_rend_un_503_nomme_sans_la_cause_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // load_config et le résolveur lisent l'environnement
        let c = CAUSE_RETENTION_INCHANGEE_ECRITURE_NON_PRISE;
        assert!(c.starts_with("RÉTENTION INCHANGÉE : la base n'a pas pris l'écriture ") && c.contains(", et la transaction est annulée —")
            && !c.contains("BEGIN") && !c.contains("COMMIT") && !c.contains('('), "l'ouverture « écriture non prise » : {c}");
        for (quoi, poser, moteur) in [
            ("trace d'audit", ac3_registre_refuse as fn(&AppState), AC3_MOTEUR_REGISTRE),
            ("réglage", ac3_reglage_refuse as fn(&AppState), AC3_MOTEUR_REGLAGE),
        ] {
            let (st, _tmp) = ac3_etat("ecriture");
            poser(&st);
            let (statut, corps, v) = ac3_regler(&st, "admin", AC3_JOURS).await;
            assert_eq!(statut, 503, "{quoi} refusé(e) : 503 nommé : {corps}");
            assert_eq!(v["error"], json!(c), "{quoi} : la phrase nommée, seule : {corps}");
            assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : le 5xx porte son identifiant : {corps}");
            assert!(!corps.contains(moteur) && !corps.contains("hors d atteinte"), "{quoi} : la cause du moteur ne sort pas : {corps}");
            assert_eq!(ac3_compte(&st, AC3_REGLAGE_ECRIT), 0, "{quoi} : rien n'est écrit");
            assert!(st.db.lock().is_autocommit(), "{quoi} : la transaction est fermée");
        }
        let (st, _tmp) = ac3_etat("nominal");
        let (statut, corps, v) = ac3_regler(&st, "admin", AC3_JOURS).await;
        assert_eq!(statut, 200, "contrôle : sans panne, le réglage passe : {corps}");
        assert_eq!(v["applied"]["retention_days"], json!(AC3_JOURS), "{corps}");
        assert_eq!(ac3_compte(&st, AC3_REGLAGE_ECRIT), 1, "contrôle : le réglage est écrit");
    }

    /// CE QU'IL TIENT : l'aperçu refuse un non-administrateur par `403 {"error":
    /// CAUSE_APERCU_DE_RETENTION_RESERVE_A_L_ADMINISTRATEUR}` et une clé inconnue par `400 {"error":
    /// CAUSE_APERCU_DE_RETENTION_CLE_INCONNUE}`. Contrôle : une clé connue rend `200`.
    /// MUTATIONS : `AC3_APERCU_403_TEXTE`, `AC3_APERCU_400_TEXTE`.
    #[tokio::test]
    async fn ac3_apercu_refuse_rend_403_et_400_nommes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // load_config et le résolveur lisent l'environnement
        let (st, _tmp) = ac3_etat("apercu");
        let (statut, corps, v) = ac3_apercu(&st, "editor", "retention_days").await;
        assert_eq!(statut, 403, "{corps}");
        assert_eq!(v, json!({ "error": CAUSE_APERCU_DE_RETENTION_RESERVE_A_L_ADMINISTRATEUR }), "{corps}");
        let (statut, corps, v) = ac3_apercu(&st, "admin", "cle_inconnue_ac3").await;
        assert_eq!(statut, 400, "{corps}");
        assert_eq!(v, json!({ "error": CAUSE_APERCU_DE_RETENTION_CLE_INCONNUE }), "{corps}");
        let (statut, corps, v) = ac3_apercu(&st, "admin", "retention_days").await;
        assert_eq!(statut, 200, "contrôle : une clé connue est servie : {corps}");
        assert_eq!(v["key"], json!("retention_days"), "{corps}");
    }

    /// CE QU'IL TIENT : un canal ABSENT reste `404` « canal introuvable » ; un canal dont la ligne ne se lit pas
    /// (`kind` en BLOB), puis une table des canaux retirée, rendent `503` dont l'erreur est EXACTEMENT
    /// `CAUSE_CANAL_NON_ESSAYE_NON_LU`, avec identifiant de corrélation, sans la cause du moteur — jamais `404`.
    /// MUTATIONS : `AC3_CANAL_ABSENT_EN_503`, `AC3_CANAL_LECTURE_EN_404` (la confusion d'avant), `AC3_CANAL_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ac3_canal_non_lu_rend_un_503_nomme_jamais_404() {
        let (st, _tmp) = ac3_etat("canal");
        let (statut, corps, v) = ac3_essayer(&st, AC3_CANAL_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v["error"], json!("canal introuvable"), "{corps}");

        let id = ac3_canal_illisible(&st);
        let (statut, corps, v) = ac3_essayer(&st, id).await;
        assert_eq!(statut, 503, "ligne illisible : 503 nommé, jamais 404 : {corps}");
        assert_eq!(v["error"], json!(CAUSE_CANAL_NON_ESSAYE_NON_LU), "la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "le 5xx porte son identifiant : {corps}");
        assert!(!corps.contains(AC3_MOTEUR_LECTURE) && !corps.contains("Blob"), "la cause du moteur ne sort pas : {corps}");

        ac3_sql(&st, "ALTER TABLE notifier RENAME TO notifier_ac3_retiree;");
        let (statut, corps, v) = ac3_essayer(&st, id).await;
        assert_eq!(statut, 503, "table retirée : 503 nommé, jamais 404 : {corps}");
        assert_eq!(v["error"], json!(CAUSE_CANAL_NON_ESSAYE_NON_LU), "{corps}");
        assert!(!corps.contains("no such table"), "la cause du moteur ne sort pas : {corps}");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : l'écriture refusée de la rétention écrit UNE
    /// ligne `[retention] WARN réglage de la rétention NON écrit, transaction annulée : <moteur>` ; le canal illisible
    /// écrit UNE ligne `[notifiers] WARN canal #<id> NON lu pour l'essai, aucun envoi : <moteur>` ; le nominal, le 403
    /// et le canal absent n'en écrivent aucune. MUTATIONS : `AC3_PUT_SANS_JOURNAL`, `AC3_CANAL_SANS_JOURNAL`.
    #[tokio::test]
    async fn ac3_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AC3_ENFANT_JOURNAL";
        const PHASE: &str = "AC3-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // load_config et le résolveur lisent l'environnement
            eprintln!("{PHASE}reglage");
            let (st, _tmp) = ac3_etat("journal-reglage");
            ac3_registre_refuse(&st);
            println!("AC3-STATUT-REGLAGE:{}", ac3_regler(&st, "admin", AC3_JOURS).await.0);
            eprintln!("{PHASE}canal");
            let (st, _tmp) = ac3_etat("journal-canal");
            let id = ac3_canal_illisible(&st);
            println!("AC3-STATUT-CANAL:{}:{id}", ac3_essayer(&st, id).await.0);
            eprintln!("{PHASE}calme");
            let (st, _tmp) = ac3_etat("journal-calme");
            let a = ac3_regler(&st, "admin", AC3_JOURS).await.0;
            let b = ac3_regler(&st, "editor", AC3_JOURS + 1).await.0;
            let c = ac3_essayer(&st, AC3_CANAL_ABSENT).await.0;
            println!("AC3-STATUT-CALME:{a}:{b}:{c}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::refus_nommes_de_la_retention_et_canal_non_lu::ac3_lignes_de_journal_des_refus",
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
        assert_eq!(marque("AC3-STATUT-REGLAGE:"), ["503"], "contrôle : écriture refusée");
        let canal = marque("AC3-STATUT-CANAL:");
        assert_eq!(canal[0], "503", "contrôle : canal illisible : {canal:?}");
        assert_eq!(marque("AC3-STATUT-CALME:"), ["200", "403", "404"], "contrôle : nominal, rôle, canal absent");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[retention] WARN") || l.starts_with("[notifiers] WARN")).map(str::to_string).collect()
        };
        let lignes = phase("reglage");
        assert_eq!(lignes.len(), 1, "phase reglage : une ligne et une seule : {lignes:?}");
        let attendu = format!("[retention] WARN réglage de la rétention NON écrit, transaction annulée : {AC3_MOTEUR_REGISTRE}");
        assert!(lignes[0].starts_with(&attendu), "phase reglage : sujet et cause du moteur : {}", lignes[0]);
        let lignes = phase("canal");
        assert_eq!(lignes.len(), 1, "phase canal : une ligne et une seule : {lignes:?}");
        let tete = format!("[notifiers] WARN canal #{} NON lu pour l'essai, aucun envoi : ", canal[1]);
        assert!(lignes[0].starts_with(&tete) && lignes[0].contains(AC3_MOTEUR_LECTURE), "phase canal : sujet et cause du moteur : {}", lignes[0]);
        assert!(phase("calme").is_empty(), "le nominal, le 403 et le canal absent n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
