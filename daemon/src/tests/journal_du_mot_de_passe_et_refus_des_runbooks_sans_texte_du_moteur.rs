// =====================================================================================
// `P10.31-u` (reste AH : quatre lignes `[password]` de `session.rs` nommaient le compte) et `P10.29-l` (reste AH,
// `handlers/incidents.rs` : texte du moteur servi au client).
//
// LE DÉFAUT, MESURÉ SUR 88afe566 AVANT LE CORRECTIF.
//   * `session.rs` : `juger_le_mot_de_passe_actuel` (compte non lu), `password_post` (classement non lu, pose de
//     l'administrateur de l'assistant refusée, changement de sa ligne non écrit) écrivaient `'<nom du compte>'`.
//   * `incidents.rs` : `incident_set` servait `CAUSE_DECLARATION_D_INCIDENT_NON_ECRITE (<texte du moteur>)` en 503 ;
//     `case_runbook_attach`, `CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES` suivie du texte du moteur ; `case_step_set`,
//     `CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT (<cause>)` et `CAUSE_ETAPE_NON_ECRITE (<cause>)` ; la création, la
//     modification et le clonage d'un runbook, `échec audit: <texte du moteur>` en 400, la ligne `runbook` refusée en
//     400 (`insertion runbook: …`, `update: …`, `insertion clone: …`) et les deux 503 (plafond non lu, étapes non
//     écrites) avec la cause du moteur à la suite de leur phrase.
//
// LE CORRECTIF (décisions par défaut de la vague AI).
//   * Journal : la phrase FIXE `compte (identifiant non lu)` là où la lecture du compte vient d'échouer (aucune
//     relecture) ; `compte #<id>` par `compte_au_journal` là où aucun verrou n'est tenu. Jamais le nom ; statuts et
//     ordre inchangés.
//   * Incidents : la phrase seule au client, la cause du moteur au journal avec l'identifiant de corrélation servi.
//   * Runbooks : refus typé (`RefusDuRunbook`) au lieu d'un `starts_with` sur la chaîne. Saisie : le 400 d'avant à
//     l'octet. Audit refusé : 500 `PHRASE_ECHEC_TRANSACTION_AUDIT` (`servir_l_echec_de_la_transaction_d_audit`) — il
//     rendait 400, CHANGEMENT DE STATUT ASSUMÉ. Plafond non lu, étapes non écrites, `managed` non lu : 503 à la phrase
//     seule. Ligne `runbook` refusée : 503 `CAUSE_LIGNE_DE_RUNBOOK_NON_ECRITE` (elle rendait 400). La forme entière va
//     au journal avec l'identifiant de corrélation.
//
// LES PANNES ÉPROUVÉES : autorisateur SQLite qui refuse la lecture d'une table ou d'une colonne (`user`, `runbook_step`,
// `runbook.managed`) ; déclencheurs `RAISE(ABORT)` / `RAISE(IGNORE)` sur `meta`, `user`, `incident`, `case_step`,
// `runbook`, `runbook_step`, `ledger` ; vue temporaire `case_step` sans `title`. Lignes de journal lues sur le stderr d'un
// sous-processus, chacune ENTIÈRE, par égalité ; corps de refus comparés EN ENTIER (ensemble exact des clés).
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE. `session.rs`, la forme d'avant au
// site : `AI1_S1080`, `AI1_S1200`, `AI1_S1230`, `AI1_S1264` ; la phrase fixe à la place de `compte_au_journal` :
// `AI1_S1230_FIXE`, `AI1_S1264_FIXE`. `incidents.rs`, la forme d'avant au site : `AI1_I882`, `AI1_I948`, `AI1_I1009`,
// `AI1_I1010`, `AI1_I_503` (les 503 des cœurs de runbook), `AI1_I_AUDIT` (400 `échec audit: …`), `AI1_I_LIGNE_400` ;
// la ligne de journal retirée : `AI1_I882_SANS_JOURNAL`, `AI1_I948_SANS_JOURNAL`, `AI1_I1009_SANS_JOURNAL`,
// `AI1_I1010_SANS_JOURNAL`, `AI1_I_503_SANS_JOURNAL`. Correction : `AI1C_S1230_SANS_LIGNE` (pose refusée, la constante
// `compte sans ligne `user`` à la place de `compte_au_journal`, rouge sur la phase multi-tenant avec ligne),
// `AI1C_A_DISPLAY` (`Display` des étapes d'attache non écrites rend la cause du moteur), `AI1C_M6_WRAP`
// (`update_custom_runbook` rend le `Debug` de son refus).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la face console des statuts changés (aucun écran ne lit ces lignes ; la console
// des runbooks peint le refus servi sans juger son statut, non rejoué ici) ; `cloner_le_runbook` lit encore la source
// par `.map_err(|_| "runbook source introuvable")` (une lecture ratée servie comme une absence, hors de ce lot) ; les
// corps d'aveu `registre_sans_maillon` d'`incident_set` et de `case_runbook_attach` portent toujours la cause du maillon
// (contrat documenté, non changé).
// =====================================================================================
mod journal_du_mot_de_passe_et_refus_des_runbooks_sans_texte_du_moteur {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Les noms : aucune ligne de journal touchée par ce lot ne doit les porter.
    const AI1_PORTEUR: &str = "ai1porteur";
    const AI1_ASSISTANT: &str = "ai1assistant";
    const AI1_ANALYSTE: &str = "ai1analyste";
    const AI1_PASSE: &str = "motdepasse-ai1-12345";
    const AI1_NEUF: &str = "nouveau-mot-de-passe-ai1-678";
    const AI1_MOTEUR_POSE: &str = "ai1 pose refusee";
    const AI1_MOTEUR_HACHE: &str = "ai1 hache refuse";
    const AI1_MOTEUR_DECLARATION: &str = "ai1 declaration refusee";
    const AI1_MOTEUR_ETAPE: &str = "ai1 etape refusee";
    const AI1_MOTEUR_ATTACHE: &str = "ai1 attache refusee";
    const AI1_MOTEUR_PAS: &str = "ai1 pas refuse";
    const AI1_MOTEUR_RETRAIT: &str = "ai1 retrait refuse";
    const AI1_MOTEUR_LIGNE: &str = "ai1 ligne refusee";
    const AI1_MOTEUR_REGISTRE: &str = "ai1 registre refuse";
    const AI1_PHASE: &str = "AI1-PHASE:";
    const AI1_NON_RELU: &str = "compte (identifiant non lu)";

    fn ai1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn ai1_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ai1_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// Le statut et l'ensemble trié des clés d'un succès (son corps peut porter un nom : il n'est pas imprimé).
    fn ai1_forme((statut, corps): &(u16, Value)) -> Value {
        let mut cles: Vec<String> = corps.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        cles.sort_unstable();
        json!([statut, cles])
    }

    /// Refuse la lecture d'une table (toutes colonnes) ou d'une seule de ses colonnes, sur l'écrivain.
    fn ai1_refuser(st: &AppState, table: &'static str, colonne: Option<&'static str>) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && colonne.map_or(true, |c| c == column_name) => {
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
    }

    fn ai1_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// L'erreur que rend `sql` (un paramètre entier ou texte) sous la panne posée : la cause du moteur attendue.
    fn ai1_cause(st: &AppState, sql: &str, p: &dyn rusqlite::ToSql) -> String {
        let c = st.db.lock();
        let e = if sql.contains("?1") { c.query_row(sql, [p], |_| Ok(())) } else { c.query_row(sql, [], |_| Ok(())) };
        e.expect_err("fixture : la lecture est refusée").to_string()
    }

    /// Un 5xx nommé : le corps ENTIER est `{error: <cause>, id: <identifiant>}` ; rend l'identifiant servi.
    fn ai1_cinq_cents(quoi: &str, (statut, corps): &(u16, Value), attendu: u16, cause: &str) -> String {
        assert_eq!(*statut, attendu, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule, sans texte du moteur : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    fn ai1_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:47474").parse().expect("adresse de test")
    }

    async fn ai1_changer(st: &AppState, nom: &str, ip: &str) -> (u16, Value) {
        let corps = json!({ "current": AI1_PASSE, "new": AI1_NEUF });
        ai1_reponse(password_post(State(st.clone()), ConnectInfo(ai1_pair(ip)), Extension(sp_au(nom, "admin")), Json(corps)).await).await
    }

    /// Les sorties de l'enfant : `(stdout, stderr)`, contrôle du code de sortie fait.
    fn ai1_sorties(sortie: std::process::Output) -> (String, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        (stdout, stderr)
    }

    fn ai1_marque(stdout: &str, m: &str) -> Value {
        let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
        serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : {m} JSON ({e}) : {stdout}"))
    }

    /// Les lignes `[password]`, `[incidents]` et `[runbooks]` écrites pendant une phase.
    fn ai1_phase(stderr: &str, nom: &str) -> Vec<String> {
        let debut = stderr.split_once(&format!("{AI1_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
        let corps = debut.split_once(AI1_PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.contains("[password]") || l.contains("[incidents]") || l.contains("[runbooks]")).map(str::to_string).collect()
    }

    fn ai1_reponse_de(s: &Value, k: &str) -> (u16, Value) {
        let v = &s[k];
        (v[0].as_u64().unwrap_or_else(|| panic!("contrôle : statut de {k} : {v}")) as u16, v[1].clone())
    }

    fn ai1_aucun_nom(stdout: &str, stderr: &str) {
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("[password]") || l.contains("[incidents]") || l.contains("[runbooks]")).collect();
        for nom in [AI1_PORTEUR, AI1_ASSISTANT, AI1_ANALYSTE] {
            assert!(!stdout.contains(nom), "stdout de l'enfant : le nom `{nom}` n'est jamais écrit : {stdout}");
            for l in &lignes {
                assert!(!l.contains(nom), "ligne de journal : le nom `{nom}` n'est jamais écrit : {l}");
            }
        }
    }

    /// `session.rs` — LES QUATRE LIGNES `[password]`, lues sur la sortie d'un sous-processus, ENTIÈRES : la phrase fixe
    /// là où la lecture du compte vient d'échouer, `compte #<id>` (ou `compte sans ligne `user``) ailleurs ; statuts et
    /// corps des refus d'avant EN ENTIER ; rien n'est écrit sur un refus ; le nominal n'écrit rien. La pose refusée de
    /// l'administrateur de l'assistant est jouée deux fois : mode 0 sans ligne (`compte sans ligne `user``) et
    /// multi-tenant avec sa ligne (`compte #<id>`), seule issue qui distingue `compte_au_journal` d'une constante.
    /// MUTATIONS : `AI1_S1080`, `AI1_S1200`, `AI1_S1230`, `AI1_S1230_FIXE`, `AI1_S1264`, `AI1_S1264_FIXE`,
    /// `AI1C_S1230_SANS_LIGNE` (la constante `compte sans ligne `user`` à la place de `compte_au_journal`).
    #[tokio::test]
    async fn ai1_mot_de_passe_au_journal_par_identifiant() {
        const ENFANT: &str = "AI1_ENFANT_MOT_DE_PASSE";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("ai1-mot-de-passe");
            st.db
                .lock()
                .execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'editor')", params![AI1_PORTEUR, hash_pw(AI1_PASSE).unwrap()])
                .expect("fixture : compte posé");
            *st.admin.lock() = Some((AI1_ASSISTANT.to_string(), hash_pw(AI1_PASSE).unwrap()));
            let hache_du_porteur = |st: &AppState| -> String {
                st.db.lock().query_row("SELECT hash FROM user WHERE name=?1", params![AI1_PORTEUR], |r| r.get(0)).expect("fixture : haché lisible")
            };
            let mut sortie = serde_json::Map::new();
            let mut causes = serde_json::Map::new();

            // Le classement du compte non lu (mode 0) : `ou_vit_le_mot_de_passe_de` en `Err`.
            eprintln!("{AI1_PHASE}s1200");
            ai1_refuser(&st, "user", None);
            sortie.insert("s1200".into(), json!(ai1_changer(&st, AI1_PORTEUR, "192.0.2.61").await));
            causes.insert("compte".into(), json!(ai1_cause(&st, "SELECT hash FROM user WHERE name=?1", &AI1_PORTEUR)));
            ai1_lever(&st);

            // Le compte non lu au jugement du mot de passe actuel (mode multi-tenant : le classement ne lit rien).
            eprintln!("{AI1_PHASE}s1080");
            let mut st_mt = st.clone();
            st_mt.multi_tenant = true;
            ai1_refuser(&st, "user", None);
            sortie.insert("s1080".into(), json!(ai1_changer(&st_mt, AI1_ASSISTANT, "192.0.2.62").await));
            ai1_lever(&st);

            // La pose de l'administrateur de l'assistant (sans ligne `user`) refusée.
            eprintln!("{AI1_PHASE}s1230");
            ai1_sql(&st, &format!(
                "CREATE TRIGGER ai1_pose_i BEFORE INSERT ON meta WHEN NEW.key='admin_user' BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_POSE}'); END; \
                 CREATE TRIGGER ai1_pose_u BEFORE UPDATE ON meta WHEN NEW.key='admin_user' BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_POSE}'); END;"
            ));
            sortie.insert("s1230".into(), json!(ai1_changer(&st, AI1_ASSISTANT, "192.0.2.63").await));
            ai1_sql(&st, "DROP TRIGGER ai1_pose_i; DROP TRIGGER ai1_pose_u;");
            let assistant = st.admin.lock().as_ref().map(|(_, h)| verify_pw(AI1_PASSE, h)).unwrap_or(false);
            sortie.insert("s1230_inchange".into(), json!(assistant));
            sortie.insert("s1230_lignes".into(), json!(ai1_entier(&st, &format!("SELECT COUNT(*) FROM user WHERE name='{AI1_ASSISTANT}'"))));

            // La même pose refusée en mode multi-tenant, l'administrateur de l'assistant AYANT sa ligne `user` (posée par
            // un `poser_l_administrateur` d'avant) : le classement ne lit pas la table, la ligne existe, `compte #<id>`.
            eprintln!("{AI1_PHASE}s1230mt");
            st.db
                .lock()
                .execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,'admin')", params![AI1_ASSISTANT, hash_pw(AI1_PASSE).unwrap()])
                .expect("fixture : ligne de l'administrateur de l'assistant");
            let assistant_id: i64 =
                st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![AI1_ASSISTANT], |r| r.get(0)).expect("fixture : identifiant");
            ai1_sql(&st, &format!(
                "CREATE TRIGGER ai1_pose_mt BEFORE UPDATE ON meta WHEN NEW.key='admin_user' BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_POSE}'); END; \
                 CREATE TRIGGER ai1_pose_mt_i BEFORE INSERT ON meta WHEN NEW.key='admin_user' BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_POSE}'); END;"
            ));
            sortie.insert("s1230mt".into(), json!(ai1_changer(&st_mt, AI1_ASSISTANT, "192.0.2.66").await));
            ai1_sql(&st, "DROP TRIGGER ai1_pose_mt; DROP TRIGGER ai1_pose_mt_i;");
            let ligne_inchangee: String =
                st.db.lock().query_row("SELECT hash FROM user WHERE id=?1", params![assistant_id], |r| r.get(0)).expect("fixture : haché lisible");
            let memoire_inchangee = st.admin.lock().as_ref().map(|(_, h)| verify_pw(AI1_PASSE, h)).unwrap_or(false);
            sortie.insert("s1230mt_inchange".into(), json!([verify_pw(AI1_PASSE, &ligne_inchangee), memoire_inchangee]));

            // Le changement du haché de la ligne non écrit.
            eprintln!("{AI1_PHASE}s1264");
            let avant = hache_du_porteur(&st);
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_hache BEFORE UPDATE OF hash ON user BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_HACHE}'); END;"));
            sortie.insert("s1264".into(), json!(ai1_changer(&st, AI1_PORTEUR, "192.0.2.64").await));
            ai1_sql(&st, "DROP TRIGGER ai1_hache;");
            sortie.insert("s1264_inchange".into(), json!(hache_du_porteur(&st) == avant));

            // Le nominal : le changement est pris, aucune ligne.
            eprintln!("{AI1_PHASE}calme");
            let r = ai1_changer(&st, AI1_PORTEUR, "192.0.2.65").await;
            sortie.insert("calme".into(), ai1_forme(&r));
            sortie.insert("calme_change".into(), json!(verify_pw(AI1_NEUF, &hache_du_porteur(&st))));
            eprintln!("{AI1_PHASE}fin");

            let porteur: i64 = st.db.lock().query_row("SELECT id FROM user WHERE name=?1", params![AI1_PORTEUR], |r| r.get(0)).expect("fixture : identifiant");
            println!("AI1-SORTIE:{}", Value::Object(sortie));
            println!("AI1-CAUSES:{}", Value::Object(causes));
            println!("AI1-IDS:{}", json!({ "porteur": porteur, "assistant": assistant_id }));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::journal_du_mot_de_passe_et_refus_des_runbooks_sans_texte_du_moteur::ai1_mot_de_passe_au_journal_par_identifiant",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (stdout, stderr) = ai1_sorties(sortie);
        let (s, causes, ids) = (ai1_marque(&stdout, "AI1-SORTIE:"), ai1_marque(&stdout, "AI1-CAUSES:"), ai1_marque(&stdout, "AI1-IDS:"));
        let compte = causes["compte"].as_str().unwrap_or_else(|| panic!("contrôle : cause : {causes}")).to_string();
        let porteur = format!("compte #{}", ids["porteur"].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant : {ids}")));
        let assistant = format!("compte #{}", ids["assistant"].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant : {ids}")));
        assert_ne!(porteur, assistant, "contrôle : deux comptes distincts");

        for k in ["s1200", "s1080"] {
            ai1_cinq_cents(k, &ai1_reponse_de(&s, k), 503, CAUSE_COMPTE_NON_LU_AU_CHANGEMENT);
        }
        for k in ["s1230", "s1230mt", "s1264"] {
            ai1_cinq_cents(k, &ai1_reponse_de(&s, k), 503, CAUSE_MOT_DE_PASSE_NON_CHANGE_ECRITURE_REFUSEE);
        }
        assert_eq!((&s["s1230_inchange"], &s["s1230_lignes"], &s["s1264_inchange"]), (&json!(true), &json!(0), &json!(true)), "refus : rien n'est écrit");
        assert_eq!(s["s1230mt_inchange"], json!([true, true]), "refus multi-tenant : ni la ligne ni la crédence en mémoire ne changent");
        assert_eq!(s["calme"], json!([200, ["ok", "user"]]), "nominal : le changement est pris");
        assert_eq!(s["calme_change"], json!(true), "nominal : le nouveau mot de passe vaut");
        let attendues: [(&str, Vec<String>); 5] = [
            ("s1200", vec![format!("[password] WARN {AI1_NON_RELU} NON lu au classement de son mot de passe : {compte}")]),
            ("s1080", vec![format!("[password] WARN {AI1_NON_RELU} NON lu au jugement du mot de passe actuel : {compte}")]),
            (
                "s1230",
                vec![format!(
                    "[password] changement du mot de passe de l'administrateur de l'assistant (compte sans ligne `user`) REFUSÉ, rien n'est écrit : écriture refusée : meta.admin_user : {AI1_MOTEUR_POSE}"
                )],
            ),
            (
                "s1230mt",
                vec![format!(
                    "[password] changement du mot de passe de l'administrateur de l'assistant ({assistant}) REFUSÉ, rien n'est écrit : écriture refusée : meta.admin_user : {AI1_MOTEUR_POSE}"
                )],
            ),
            ("s1264", vec![format!("[password] WARN changement du mot de passe du {porteur} NON écrit : {AI1_MOTEUR_HACHE}")]),
        ];
        assert!(attendues.len() >= 5, "plancher : quatre sites `[password]`, le troisième joué sans puis avec ligne `user`");
        for (nom, lignes) in &attendues {
            let nom: &str = nom;
            assert_eq!(&ai1_phase(&stderr, nom), lignes, "phase {nom} : chaque ligne entière, jamais le nom du compte");
        }
        assert!(ai1_phase(&stderr, "calme").is_empty(), "le nominal n'écrit rien : {stderr}");
        ai1_aucun_nom(&stdout, &stderr);
    }

    fn ai1_corps_runbook(nom: &str, titres: &[&str]) -> Value {
        let steps: Vec<Value> = titres.iter().map(|t| json!({ "phase": "triage", "title": t, "step_kind": "manual" })).collect();
        json!({ "name": nom, "match_kind": "*", "steps": steps })
    }

    /// `incidents.rs` — LES REFUS SANS TEXTE DU MOTEUR, par les gestionnaires réels, lus sur la sortie d'un
    /// sous-processus : chaque corps de refus EN ENTIER (phrase seule et identifiant), chaque ligne de journal ENTIÈRE
    /// (la cause du moteur, l'identifiant servi) ; les saisies gardent leur 400 d'avant à l'octet, sans ligne ; rien
    /// n'est écrit sur un refus ; le nominal n'écrit rien. MUTATIONS : `AI1_I882`, `AI1_I948`, `AI1_I1009`, `AI1_I1010`,
    /// `AI1_I_503`, `AI1_I_AUDIT`, `AI1_I_LIGNE_400` et les `*_SANS_JOURNAL`.
    #[tokio::test]
    async fn ai1_incidents_et_runbooks_sans_texte_du_moteur() {
        const ENFANT: &str = "AI1_ENFANT_INCIDENTS";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("ai1-incidents");
            let ed = sp_au(AI1_ANALYSTE, "editor");
            let adm = sp_au(AI1_ANALYSTE, "admin");
            let mut sortie = serde_json::Map::new();
            let mut causes = serde_json::Map::new();
            let dossier = dossier_seme(&st.db.lock(), "alice", "ai1", 3, "", None, 2);
            let etape = {
                let c = st.db.lock();
                c.execute(
                    "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,step_kind,status) VALUES(?1,1,1,1,'triage','regarder','manual','pending')",
                    params![dossier],
                )
                .expect("fixture : étape posée");
                c.last_insert_rowid()
            };
            let statut_de_l_etape = |st: &AppState| -> String {
                st.db.lock().query_row("SELECT status FROM case_step WHERE id=?1", params![etape], |r| r.get(0)).expect("fixture : étape lisible")
            };

            // La déclaration que la base ne prend pas.
            eprintln!("{AI1_PHASE}i882");
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_declaration BEFORE UPDATE ON incident BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_DECLARATION}'); END;"));
            let r = incident_set(State(st.clone()), Extension(ed.clone()), Path(dossier), Json(json!({ "tier": 2 }))).await;
            sortie.insert("i882".into(), json!(ai1_reponse(r).await));
            ai1_sql(&st, "DROP TRIGGER ai1_declaration;");
            sortie.insert("i882_palier".into(), json!(ai1_entier(&st, &format!("SELECT COALESCE(incident_tier,-1) FROM incident WHERE id={dossier}"))));

            // L'étape que la base n'écrit pas.
            eprintln!("{AI1_PHASE}i1010");
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_etape BEFORE UPDATE ON case_step BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_ETAPE}'); END;"));
            let r = case_step_set(State(st.clone()), Extension(ed.clone()), Path((dossier, etape)), Json(json!({ "status": "done" }))).await;
            sortie.insert("i1010".into(), json!(ai1_reponse(r).await));
            ai1_sql(&st, "DROP TRIGGER ai1_etape;");
            sortie.insert("i1010_statut".into(), json!(statut_de_l_etape(&st)));

            // L'étape relue au geste en erreur : la lecture d'appartenance passe (vue sans `title`), celle du titre échoue.
            eprintln!("{AI1_PHASE}i1009");
            ai1_sql(&st, "ALTER TABLE case_step RENAME TO case_step_source; CREATE TEMP VIEW case_step AS SELECT id, incident_id FROM case_step_source;");
            let r = case_step_set(State(st.clone()), Extension(ed.clone()), Path((dossier, etape)), Json(json!({ "status": "done" }))).await;
            sortie.insert("i1009".into(), json!(ai1_reponse(r).await));
            let cause = st.db.lock().query_row("SELECT title FROM case_step WHERE id=?1 AND incident_id=?2", params![etape, dossier], |_| Ok(()));
            causes.insert("titre".into(), json!(cause.expect_err("fixture : titre illisible").to_string()));
            ai1_sql(&st, "DROP VIEW case_step; ALTER TABLE case_step_source RENAME TO case_step;");
            sortie.insert("i1009_statut".into(), json!(statut_de_l_etape(&st)));

            // L'attache dont une étape n'est pas écrite.
            ai1_sql(&st, "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('custom-ai1-attache','ai1-attache','*','','',0,1,0);");
            let rb_attache = ai1_entier(&st, "SELECT id FROM runbook WHERE key='custom-ai1-attache'");
            ai1_sql(&st, &format!("INSERT INTO runbook_step(runbook_id,ordinal,phase,title,step_kind) VALUES({rb_attache},0,'triage','regarder','manual');"));
            let pas_attache = ai1_entier(&st, &format!("SELECT id FROM runbook_step WHERE runbook_id={rb_attache}"));
            let dossier_attache = dossier_seme(&st.db.lock(), "alice", "ai1-attache", 3, "", None, 2);
            eprintln!("{AI1_PHASE}i948");
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_attache BEFORE INSERT ON case_step BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_ATTACHE}'); END;"));
            let r = case_runbook_attach(State(st.clone()), Extension(ed.clone()), Path(dossier_attache), Json(json!({ "runbook_id": rb_attache }))).await;
            sortie.insert("i948".into(), json!(ai1_reponse(r).await));
            ai1_sql(&st, "DROP TRIGGER ai1_attache;");
            sortie.insert("i948_poses".into(), json!(ai1_entier(&st, &format!("SELECT COUNT(*) FROM case_step WHERE incident_id={dossier_attache}"))));

            // Le nominal des trois gestes : aucune ligne.
            eprintln!("{AI1_PHASE}i_nominal");
            let mut nominal: Vec<(u16, Value)> = Vec::new();
            nominal.push(ai1_reponse(incident_set(State(st.clone()), Extension(ed.clone()), Path(dossier), Json(json!({ "tier": 2 }))).await).await);
            nominal.push(ai1_reponse(case_step_set(State(st.clone()), Extension(ed.clone()), Path((dossier, etape)), Json(json!({ "status": "done" }))).await).await);
            nominal.push(ai1_reponse(case_runbook_attach(State(st.clone()), Extension(ed.clone()), Path(dossier_attache), Json(json!({ "runbook_id": rb_attache }))).await).await);
            sortie.insert("i_nominal".into(), json!(nominal));

            // ---- runbooks ----
            let rb = {
                let c = st.db.lock();
                let pas: Vec<NewStep> = ["a", "b"].iter().map(|t| ("triage".to_string(), t.to_string(), String::new(), "manual".to_string(), None, None)).collect();
                create_custom_runbook(&c, "ai1-rb", "*", "", "", &pas, true).expect("fixture : runbook écrit")
            };
            let etat_rb = |st: &AppState| -> Value {
                let c = st.db.lock();
                let nom: String = c.query_row("SELECT name FROM runbook WHERE id=?1", params![rb], |r| r.get(0)).expect("fixture : runbook lisible");
                let mut q = c.prepare("SELECT title FROM runbook_step WHERE runbook_id=?1 ORDER BY ordinal,id").expect("fixture : prepare");
                let titres = q.query_map(params![rb], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture");
                json!([nom, titres])
            };
            let customs = |st: &AppState| ai1_entier(st, "SELECT COUNT(*) FROM runbook WHERE managed=0");
            let traces = |st: &AppState| ai1_entier(st, "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.runbook.%'");
            let (customs_avant, traces_avant) = (customs(&st), traces(&st));
            macro_rules! creer {
                ($corps:expr) => {
                    ai1_reponse(runbook_create(State(st.clone()), Extension(adm.clone()), Json($corps)).await).await
                };
            }
            macro_rules! modifier {
                ($id:expr) => {
                    ai1_reponse(runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path($id), Json(ai1_corps_runbook("ai1-apres", &["x", "y", "z"]))).await).await
                };
            }
            macro_rules! cloner {
                ($id:expr) => {
                    ai1_reponse(runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path($id), Json(json!({ "name": "ai1-copie" }))).await).await
                };
            }

            // Une étape refusée (ABORT) : création, modification, copie du clone.
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_pas BEFORE INSERT ON runbook_step WHEN NEW.ordinal=1 BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_PAS}'); END;"));
            eprintln!("{AI1_PHASE}r_creation_pas");
            sortie.insert("r_creation_pas".into(), json!(creer!(ai1_corps_runbook("ai1-cree", &["un", "deux", "trois"]))));
            eprintln!("{AI1_PHASE}r_modification_pas");
            sortie.insert("r_modification_pas".into(), json!(modifier!(rb)));
            eprintln!("{AI1_PHASE}r_clonage_copie");
            sortie.insert("r_clonage_copie".into(), json!(cloner!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_pas;");

            // Une étape à zéro ligne (IGNORE) : création, clone amputé.
            ai1_sql(&st, "CREATE TRIGGER ai1_pas BEFORE INSERT ON runbook_step WHEN NEW.ordinal=1 BEGIN SELECT RAISE(IGNORE); END;");
            eprintln!("{AI1_PHASE}r_creation_zero");
            sortie.insert("r_creation_zero".into(), json!(creer!(ai1_corps_runbook("ai1-zero", &["un", "deux"]))));
            eprintln!("{AI1_PHASE}r_clonage_ampute");
            sortie.insert("r_clonage_ampute".into(), json!(cloner!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_pas;");

            // Le retrait des étapes d'avant refusé.
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_retrait BEFORE DELETE ON runbook_step BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_RETRAIT}'); END;"));
            eprintln!("{AI1_PHASE}r_modification_retrait");
            sortie.insert("r_modification_retrait".into(), json!(modifier!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_retrait;");

            // Le compte des étapes de la source non lu.
            eprintln!("{AI1_PHASE}r_clonage_compte");
            ai1_refuser(&st, "runbook_step", None);
            sortie.insert("r_clonage_compte".into(), json!(cloner!(rb)));
            causes.insert("compte_source".into(), json!(ai1_cause(&st, "SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1", &rb)));
            ai1_lever(&st);

            // Le plafond non lu : création et clonage.
            ai1_refuser(&st, "runbook", Some("managed"));
            eprintln!("{AI1_PHASE}r_quota_creation");
            sortie.insert("r_quota_creation".into(), json!(creer!(ai1_corps_runbook("ai1-quota", &["un"]))));
            eprintln!("{AI1_PHASE}r_quota_clonage");
            sortie.insert("r_quota_clonage".into(), json!(cloner!(rb)));
            causes.insert("quota".into(), json!(ai1_cause(&st, "SELECT COUNT(*) FROM runbook WHERE managed=0", &0)));
            ai1_lever(&st);

            // La ligne `runbook` refusée : création, clonage, modification.
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_ligne BEFORE INSERT ON runbook BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_LIGNE}'); END;"));
            eprintln!("{AI1_PHASE}r_ligne_creation");
            sortie.insert("r_ligne_creation".into(), json!(creer!(ai1_corps_runbook("ai1-ligne", &["un"]))));
            eprintln!("{AI1_PHASE}r_ligne_clonage");
            sortie.insert("r_ligne_clonage".into(), json!(cloner!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_ligne;");
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_ligne BEFORE UPDATE ON runbook BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_LIGNE}'); END;"));
            eprintln!("{AI1_PHASE}r_ligne_modification");
            sortie.insert("r_ligne_modification".into(), json!(modifier!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_ligne;");

            // La trace d'audit refusée : création, modification, clonage.
            ai1_sql(&st, &format!("CREATE TRIGGER ai1_registre BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_REGISTRE}'); END;"));
            eprintln!("{AI1_PHASE}r_audit_creation");
            sortie.insert("r_audit_creation".into(), json!(creer!(ai1_corps_runbook("ai1-audit", &["un"]))));
            eprintln!("{AI1_PHASE}r_audit_modification");
            sortie.insert("r_audit_modification".into(), json!(modifier!(rb)));
            eprintln!("{AI1_PHASE}r_audit_clonage");
            sortie.insert("r_audit_clonage".into(), json!(cloner!(rb)));
            ai1_sql(&st, "DROP TRIGGER ai1_registre;");
            sortie.insert("r_etat_apres_refus".into(), json!([etat_rb(&st), customs(&st) - customs_avant, traces(&st) - traces_avant]));

            // Les saisies : le 400 d'avant, à l'octet, sans ligne.
            eprintln!("{AI1_PHASE}r_saisies");
            let absent = rb + 9_999;
            let mut saisies: Vec<(u16, Value)> = Vec::new();
            saisies.push(modifier!(absent));
            saisies.push(cloner!(absent));
            saisies.push(creer!(json!({ "name": "ai1-vide", "match_kind": "*", "steps": [] })));
            sortie.insert("r_saisies".into(), json!(saisies));

            // Le nominal : modification, clonage, création pris ; aucune ligne.
            eprintln!("{AI1_PHASE}r_nominal");
            let nominal = [modifier!(rb), cloner!(rb), creer!(ai1_corps_runbook("ai1-nominal", &["un"]))];
            sortie.insert("r_nominal".into(), json!(nominal.iter().map(ai1_forme).collect::<Vec<_>>()));

            // Le quota ATTEINT : une saisie, le 400 d'avant à l'octet, sans ligne.
            {
                let c = st.db.lock();
                let deja: i64 = c.query_row("SELECT COUNT(*) FROM runbook WHERE managed=0", [], |r| r.get(0)).expect("fixture");
                for i in deja..200 {
                    c.execute(
                        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,?2,'*','','',0,1,0)",
                        params![format!("custom-ai1-plein-{i}"), format!("ai1-plein-{i}")],
                    )
                    .expect("fixture : runbook custom écrit");
                }
            }
            eprintln!("{AI1_PHASE}r_quota_atteint");
            sortie.insert("r_quota_atteint".into(), json!([creer!(ai1_corps_runbook("ai1-de-trop", &["un"])), cloner!(rb)]));
            eprintln!("{AI1_PHASE}fin");

            println!("AI1-SORTIE:{}", Value::Object(sortie));
            println!("AI1-CAUSES:{}", Value::Object(causes));
            println!("AI1-IDS:{}", json!({ "dossier": dossier, "etape": etape, "dossier_attache": dossier_attache, "rb_attache": rb_attache, "pas_attache": pas_attache, "rb": rb }));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::journal_du_mot_de_passe_et_refus_des_runbooks_sans_texte_du_moteur::ai1_incidents_et_runbooks_sans_texte_du_moteur",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (stdout, stderr) = ai1_sorties(sortie);
        let (s, causes, ids) = (ai1_marque(&stdout, "AI1-SORTIE:"), ai1_marque(&stdout, "AI1-CAUSES:"), ai1_marque(&stdout, "AI1-IDS:"));
        let cause = |k: &str| -> String { causes[k].as_str().unwrap_or_else(|| panic!("contrôle : cause {k} : {causes}")).to_string() };
        let id = |k: &str| -> i64 { ids[k].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant {k} : {ids}")) };
        let reponse = |k: &str| ai1_reponse_de(&s, k);
        use crate::handlers::incidents as inc;

        // ---- incidents.rs : la phrase seule, la cause au journal avec l'identifiant servi ----
        let cid = ai1_cinq_cents("déclaration non écrite", &reponse("i882"), 503, inc::CAUSE_DECLARATION_D_INCIDENT_NON_ECRITE);
        let mut attendues: Vec<(&str, String)> = vec![(
            "i882",
            format!("[incidents] WARN déclaration du dossier #{} NON enregistrée, rien n'a changé ({cid}) : {AI1_MOTEUR_DECLARATION}", id("dossier")),
        )];
        let cid = ai1_cinq_cents("étape non écrite", &reponse("i1010"), 503, inc::CAUSE_ETAPE_NON_ECRITE);
        attendues.push(("i1010", format!("[incidents] WARN étape #{} du dossier #{} NON écrite, rien n'est fait ({cid}) : {AI1_MOTEUR_ETAPE}", id("etape"), id("dossier"))));
        let cid = ai1_cinq_cents("étape non relue", &reponse("i1009"), 503, inc::CAUSE_ETAPE_NON_LUE_GESTE_NON_FAIT);
        attendues.push((
            "i1009",
            format!("[incidents] WARN étape #{} du dossier #{} NON relue au geste, rien n'est écrit ({cid}) : {}", id("etape"), id("dossier"), cause("titre")),
        ));
        let phrase_attache = inc::CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES;
        assert!(phrase_attache.ends_with("un nouvel essai reste possible."), "contrôle : la phrase servie finit sur elle-même : {phrase_attache}");
        let cid = ai1_cinq_cents("attache, étape non écrite", &reponse("i948"), 503, phrase_attache);
        attendues.push((
            "i948",
            format!(
                "[incidents] WARN runbook #{} NON attaché au dossier #{}, aucune étape posée ({cid}) : étape {} : {AI1_MOTEUR_ATTACHE}",
                id("rb_attache"),
                id("dossier_attache"),
                id("pas_attache")
            ),
        ));
        assert_eq!(
            (&s["i882_palier"], &s["i1010_statut"], &s["i1009_statut"], &s["i948_poses"]),
            (&json!(-1), &json!("pending"), &json!("pending"), &json!(0)),
            "refus : rien n'est écrit"
        );
        let nominal: Vec<(u16, Value)> = serde_json::from_value(s["i_nominal"].clone()).expect("contrôle : réponses");
        assert_eq!(nominal, vec![(204, Value::Null), (204, Value::Null), (200, json!({ "attached": 1 }))], "nominal : déclaration, étape, attache prises");
        assert!(ai1_phase(&stderr, "i_nominal").is_empty(), "le nominal n'écrit rien : {stderr}");

        // ---- runbooks : saisie 400 d'avant, audit 500 phrase fixe, base refusée 503 phrase seule ----
        let etapes = inc::CAUSE_ETAPES_DE_RUNBOOK_NON_ECRITES;
        let rb = id("rb");
        let base_refusee: [(&str, &str, &str, String); 11] = [
            ("r_creation_pas", "création d'un runbook", etapes, format!("{etapes} (étape 2 (ordinal 1) non écrite : {AI1_MOTEUR_PAS})")),
            ("r_modification_pas", "modification d'un runbook", etapes, format!("{etapes} (étape 2 (ordinal 1) non écrite : {AI1_MOTEUR_PAS})")),
            ("r_clonage_copie", "clonage d'un runbook", etapes, format!("{etapes} (étapes non copiées : {AI1_MOTEUR_PAS})")),
            ("r_creation_zero", "création d'un runbook", etapes, format!("{etapes} (étape 2 (ordinal 1) non écrite : 0 ligne écrite)")),
            ("r_clonage_ampute", "clonage d'un runbook", etapes, format!("{etapes} (étapes copiées : 1 sur 2)")),
            ("r_modification_retrait", "modification d'un runbook", etapes, format!("{etapes} (étapes d'avant non retirées : {AI1_MOTEUR_RETRAIT})")),
            ("r_clonage_compte", "clonage d'un runbook", etapes, format!("{etapes} (étapes de la source non comptées : {})", cause("compte_source"))),
            (
                "r_quota_creation",
                "création d'un runbook",
                inc::CAUSE_QUOTA_DE_RUNBOOKS_NON_LU,
                format!("{} ({})", inc::CAUSE_QUOTA_DE_RUNBOOKS_NON_LU, cause("quota")),
            ),
            (
                "r_quota_clonage",
                "clonage d'un runbook",
                inc::CAUSE_QUOTA_DE_RUNBOOKS_NON_LU,
                format!("{} ({})", inc::CAUSE_QUOTA_DE_RUNBOOKS_NON_LU, cause("quota")),
            ),
            ("r_ligne_creation", "création d'un runbook", inc::CAUSE_LIGNE_DE_RUNBOOK_NON_ECRITE, format!("insertion runbook: {AI1_MOTEUR_LIGNE}")),
            ("r_ligne_clonage", "clonage d'un runbook", inc::CAUSE_LIGNE_DE_RUNBOOK_NON_ECRITE, format!("insertion clone: {AI1_MOTEUR_LIGNE}")),
        ];
        assert!(base_refusee.len() >= 11, "plancher : onze refus de la base sur les cœurs de runbook");
        for (k, geste, phrase, forme) in &base_refusee {
            let cid = ai1_cinq_cents(k, &reponse(k), 503, phrase);
            attendues.push((k, format!("[runbooks] WARN {geste} refusée, rien n'est écrit ({cid}) : {forme}")));
        }
        let cid = ai1_cinq_cents("r_ligne_modification", &reponse("r_ligne_modification"), 503, inc::CAUSE_LIGNE_DE_RUNBOOK_NON_ECRITE);
        attendues.push(("r_ligne_modification", format!("[runbooks] WARN modification d'un runbook refusée, rien n'est écrit ({cid}) : update: {AI1_MOTEUR_LIGNE}")));
        let audit: [(&str, &str); 3] =
            [("r_audit_creation", "création d'un runbook"), ("r_audit_modification", "modification d'un runbook"), ("r_audit_clonage", "clonage d'un runbook")];
        assert!(audit.len() >= 3, "plancher : trois traces d'audit refusées");
        for (k, geste) in &audit {
            let cid = ai1_cinq_cents(k, &reponse(k), 500, crate::handlers::users_lookups::PHRASE_ECHEC_TRANSACTION_AUDIT);
            attendues.push((k, format!("[{cid}] [runbooks] WARN {geste} refusé : transaction d'audit annulée, aucune modification ({AI1_MOTEUR_REGISTRE})")));
        }
        assert!(attendues.len() >= 19, "plancher : dix-neuf phases à une ligne");
        for (nom, ligne) in &attendues {
            let nom: &str = nom;
            assert_eq!(ai1_phase(&stderr, nom), [ligne.clone()], "phase {nom} : la ligne entière, la cause du moteur au journal seul");
        }
        assert_eq!(s["r_etat_apres_refus"], json!([["ai1-rb", ["a", "b"]], 0, 0]), "refus : runbook inchangé, aucun créé ni copié, rien tracé");
        let saisies: Vec<(u16, Value)> = serde_json::from_value(s["r_saisies"].clone()).expect("contrôle : réponses");
        assert_eq!(
            saisies,
            vec![
                (400, json!({ "error": "runbook introuvable" })),
                (400, json!({ "error": "runbook source introuvable" })),
                (400, json!({ "error": "au moins une étape requise" })),
            ],
            "saisies : le 400 d'avant, à l'octet"
        );
        assert!(ai1_phase(&stderr, "r_saisies").is_empty(), "les saisies n'écrivent rien au journal : {stderr}");
        assert_eq!(s["r_nominal"], json!([[200, ["ok"]], [200, ["id"]], [200, ["id"]]]), "nominal : modification, clonage, création pris");
        assert!(ai1_phase(&stderr, "r_nominal").is_empty(), "le nominal n'écrit rien : {stderr}");
        let quota = json!({ "error": "quota de runbooks custom atteint (max 200)" });
        assert_eq!(s["r_quota_atteint"], json!([[400, quota.clone()], [400, quota]]), "quota atteint : le 400 d'avant, à l'octet");
        assert!(ai1_phase(&stderr, "r_quota_atteint").is_empty(), "le quota atteint n'écrit rien au journal : {stderr}");
        assert!(rb > 0, "contrôle : identifiant du runbook");
        ai1_aucun_nom(&stdout, &stderr);
    }

    /// `incidents.rs` — `RefusDAttache` : `Display` rend la phrase servie de chaque variante, ÉGALE à `phrase_servie`,
    /// jamais le texte du moteur (la forme « phrase Cause : cause » des étapes non écrites n'avait plus de consommateur ;
    /// un appelant qui servirait `to_string()` ne porterait pas la cause au client). MUTATION : `AI1C_A_DISPLAY`.
    #[test]
    fn ai1_refus_d_attache_affiche_la_phrase_seule() {
        use crate::handlers::incidents::{self as inc, RefusDAttache};
        let cas: [(RefusDAttache, &str); 4] = [
            (RefusDAttache::EtapesNonEcrites(format!("étape 7 : {AI1_MOTEUR_ATTACHE}")), inc::CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES),
            (RefusDAttache::Refuse("runbook introuvable".to_string()), "runbook introuvable"),
            (RefusDAttache::NonLu(inc::CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE), inc::CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE),
            (RefusDAttache::TransactionNonOuverte, inc::CAUSE_RUNBOOK_NON_ATTACHE_TRANSACTION_NON_OUVERTE),
        ];
        assert!(cas.len() >= 4, "plancher : les quatre variantes");
        for (refus, phrase) in &cas {
            assert_eq!(refus.phrase_servie(), *phrase, "phrase servie : {refus:?}");
            assert_eq!(refus.to_string(), *phrase, "Display : la phrase seule, sans texte du moteur : {refus:?}");
        }
    }

    /// `incidents.rs` — `update_custom_runbook` (cœur public, `Result<(), String>`) rend la chaîne d'avant, le `Display`
    /// de son refus typé, comparée EN ENTIER pour chaque genre : introuvable, managé, `managed` non lu, ligne `runbook`
    /// refusée, étapes d'avant non retirées ; le nominal rend `Ok`. MUTATION : `AI1C_M6_WRAP` (le `Debug` rendu).
    #[test]
    fn ai1_modification_de_runbook_rend_la_chaine_d_avant() {
        use crate::handlers::incidents as inc;
        let (st, _tmp) = sp_state("ai1-modification-coeur");
        let pas: Vec<NewStep> = ["a", "b"].iter().map(|t| ("triage".to_string(), t.to_string(), String::new(), "manual".to_string(), None, None)).collect();
        let rb = create_custom_runbook(&st.db.lock(), "ai1-modif", "*", "", "", &pas, true).expect("fixture : runbook écrit");
        ai1_sql(&st, "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('ai1-gere','ai1-gere','*','','',1,1,0);");
        let gere = ai1_entier(&st, "SELECT id FROM runbook WHERE key='ai1-gere'");
        let modifier = |st: &AppState, id: i64| inc::update_custom_runbook(&st.db.lock(), id, "ai1-modif-v2", "*", "", "", &pas);

        let mut issues: Vec<(&str, Result<(), String>, Result<(), String>)> = Vec::new();
        issues.push(("introuvable", modifier(&st, 987_654), Err("runbook introuvable".to_string())));
        issues.push((
            "managé",
            modifier(&st, gere),
            Err("runbook managé (git) : non modifiable en place — clonez pour personnaliser".to_string()),
        ));
        ai1_refuser(&st, "runbook", Some("managed"));
        let non_lu = modifier(&st, rb);
        let cause = ai1_cause(&st, "SELECT managed FROM runbook WHERE id=?1", &rb);
        ai1_lever(&st);
        issues.push(("managed non lu", non_lu, Err(format!("{} ({cause})", inc::CAUSE_RUNBOOK_INCHANGE_NON_LU))));
        ai1_sql(&st, &format!("CREATE TRIGGER ai1_m_ligne BEFORE UPDATE ON runbook BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_LIGNE}'); END;"));
        issues.push(("ligne refusée", modifier(&st, rb), Err(format!("update: {AI1_MOTEUR_LIGNE}"))));
        ai1_sql(&st, "DROP TRIGGER ai1_m_ligne;");
        ai1_sql(&st, &format!("CREATE TRIGGER ai1_m_retrait BEFORE DELETE ON runbook_step BEGIN SELECT RAISE(ABORT,'{AI1_MOTEUR_RETRAIT}'); END;"));
        issues.push((
            "retrait refusé",
            modifier(&st, rb),
            Err(format!("{} (étapes d'avant non retirées : {AI1_MOTEUR_RETRAIT})", inc::CAUSE_ETAPES_DE_RUNBOOK_NON_ECRITES)),
        ));
        ai1_sql(&st, "DROP TRIGGER ai1_m_retrait;");
        issues.push(("nominal", modifier(&st, rb), Ok(())));
        assert!(issues.len() >= 6, "plancher : six issues du cœur de modification");
        for (quoi, rendu, attendu) in &issues {
            assert_eq!(rendu, attendu, "{quoi} : la chaîne rendue, entière");
        }
        assert_eq!(ai1_entier(&st, &format!("SELECT COUNT(*) FROM runbook WHERE id={rb} AND name='ai1-modif-v2'")), 1, "contrôle : le nominal a écrit");
    }
}
