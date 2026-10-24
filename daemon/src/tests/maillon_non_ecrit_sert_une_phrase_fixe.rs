// =====================================================================================
// `P10.29-l` (reste « `NonInscrit(e.to_string())` nourrit les corps `registre_sans_maillon` ») — LA CAUSE D'UN
// MAILLON NON INSCRIT EST UNE PHRASE FIXE ; LE TEXTE DU MOTEUR RESTE À LA LIGNE DE LA PRIMITIVE.
//
// LE DÉFAUT, MESURÉ SUR 583aa34b. `ledger_append` (`ledger.rs`) rendait, sur l'`INSERT` refusé,
// `NonInscrit(e.to_string())`, et sur la tête de chaîne illisible `NonInscrit(format!("hachage précédent ILLISIBLE
// ({e}) …"))` ; `rbac::control_ledger_append` en est le miroir exact. Cette cause est recopiée telle quelle par les
// appelants : les corps `registre_sans_maillon` (`session.rs`, `rbac.rs`, `actions.rs`, `cases.rs`, `caseops.rs`,
// `incidents.rs`), le 503 de destruction de tenant (`tenants.rs`) et des lignes de journal. Le texte du moteur
// (message d'un déclencheur, nom de table, « no such table », type de colonne inattendu) partait donc au client.
//
// LE CORRECTIF EST À LA SOURCE : deux phrases fixes, `CAUSE_MAILLON_NON_ECRIT` (voie de l'écriture, sans le mot
// ILLISIBLE) et `CAUSE_TETE_DE_CHAINE_ILLISIBLE` (voie de la lecture, qui le garde : les deux voies restent
// distinctes, `journaux_avouent_leur_ecriture.rs` et `primitives_avouent_leur_ecriture.rs` le tiennent). La ligne de
// sortie d'erreur de la primitive, elle, porte toujours le moteur : c'est le seul endroit où il reste.
//
// LES VOIES SONT ISOLÉES. Écriture : un déclencheur `RAISE(ABORT)` sur le seul genre du geste joué (la tête de
// chaîne se lit). Lecture : une dernière ligne dont le `hash` est un BLOB (la lecture meurt, l'écriture resterait
// vivante) ; la table retirée n'est jouée qu'à la primitive, pour « no such table ».
//
// MUTANTS JOUÉS (interrupteurs de test sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `AM1_L106` (tête de
// chaîne du registre, remet `({e})`), `AM1_L121` (écriture du registre, remet `e.to_string()`), `AM1_R680` et
// `AM1_R698` (les deux miroirs du journal de contrôle).
//
// CE QU'ILS NE TIENNENT PAS : `rbac.rs` et `tenants.rs` sont joués par leur gestionnaire en mode 1 (super-
// administrateur), pas à travers le routeur ; les lignes de journal des appelants qui reprennent la cause
// (`session.rs`, `idp.rs`, `ingest/minio.rs`, activation de la démonstration) n'y portent plus le moteur, qui ne
// reste qu'à la ligne de la primitive, sans identifiant de corrélation ; ce que la console peint de ces corps n'est
// pas rejoué ; le bras « n ligne(s) écrite(s) au lieu d'une » (inatteignable par l'énoncé actuel) n'est pas joué.
// =====================================================================================
mod maillon_non_ecrit_sert_une_phrase_fixe {
    use super::*;

    /// Le message du déclencheur : il nomme une table, comme le ferait le moteur. Il ne doit sortir que sur la
    /// ligne de la primitive.
    const AM1_MOTEUR: &str = "am1 moteur du registre (table ledger_am1_hors_d_atteinte)";
    const AM1_MOTEUR_CONTROLE: &str = "am1 moteur du controle (table control_ledger_am1_hors_d_atteinte)";
    /// Ce que le moteur dit d'une colonne `hash` BLOB lue en texte, et d'une table retirée : jamais servi.
    const AM1_TEXTES_DU_MOTEUR: [&str; 4] = ["Invalid column type", "Blob", "no such table", "am1 moteur"];

    const AM1_ENFANT: &str = "AM1_ENFANT_JOURNAL";
    const AM1_MDP_EDITEUR: &str = "editeurpw12345";

    fn am1_sql(conn: &Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn am1_base_du_registre() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations va au bout");
        conn
    }

    fn am1_refuser_l_ecriture(table: &str, genre: &str, moteur: &str) -> String {
        format!("CREATE TRIGGER am1_refus BEFORE INSERT ON {table} WHEN NEW.kind='{genre}' BEGIN SELECT RAISE(ABORT, '{moteur}'); END;")
    }

    /// La dernière ligne du registre porte un `hash` NON TEXTUEL : la tête de chaîne ne se lit plus.
    fn am1_empoisonner_la_tete(conn: &Connection) {
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,'am1.poison','','',X'FF')",
            params![now()],
        )
        .expect("fixture : ligne de poison posée");
    }

    fn am1_cause(m: MaillonDeRegistre) -> String {
        m.cause_de_non_inscription().map(str::to_string).unwrap_or_else(|| panic!("le maillon refusé doit être RENDU non inscrit"))
    }

    fn am1_sans_moteur(quoi: &str, texte: &str) {
        for t in AM1_TEXTES_DU_MOTEUR {
            assert!(!texte.contains(t), "{quoi} : le texte du moteur (`{t}`) ne sort pas : {texte}");
        }
    }

    // -------------------------------------------------------------------------------------
    // (1) LES PRIMITIVES — une phrase fixe par voie, jamais le moteur.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `ledger_append` rend `CAUSE_MAILLON_NON_ECRIT` À L'IDENTIQUE quand l'`INSERT` est refusé
    /// (sans ILLISIBLE, sans le message du déclencheur), `CAUSE_TETE_DE_CHAINE_ILLISIBLE` à l'identique quand la tête
    /// est un BLOB (sans « Invalid column type ») ou quand la table est retirée (sans « no such table ») ; contrôle
    /// positif avant et après, et aucun maillon n'entre pendant les refus.
    /// MUTANTS : `AM1_L121`, `AM1_L106`.
    #[test]
    fn am1_le_registre_rend_une_phrase_fixe_par_voie() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let conn = am1_base_du_registre();
        let compte = |c: &Connection| -> i64 { c.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap() };
        assert!(ledger_append(&conn, "am1.sain", "contrôle positif").cause_de_non_inscription().is_none(), "registre sain : inscrit");
        let avant = compte(&conn);

        am1_sql(&conn, &am1_refuser_l_ecriture("ledger", "am1.ecriture", AM1_MOTEUR));
        let cause = am1_cause(ledger_append(&conn, "am1.ecriture", "maillon refusé"));
        assert_eq!(cause, CAUSE_MAILLON_NON_ECRIT, "voie de l'écriture : la phrase fixe, rien d'autre");
        assert!(!cause.contains("ILLISIBLE"), "c'est l'ÉCRITURE qui est tombée : {cause}");
        am1_sans_moteur("écriture", &cause);
        am1_sql(&conn, "DROP TRIGGER am1_refus;");

        am1_empoisonner_la_tete(&conn);
        assert!(ledger_prev_hash(&conn).is_err(), "CONTRÔLE D'INSTRUMENT : la tête de chaîne ne se lit plus");
        let cause = am1_cause(ledger_append(&conn, "am1.lecture", "maillon sans tête lisible"));
        assert_eq!(cause, CAUSE_TETE_DE_CHAINE_ILLISIBLE, "voie de la lecture : la phrase fixe, rien d'autre");
        am1_sans_moteur("lecture (BLOB)", &cause);
        am1_sql(&conn, "DELETE FROM ledger WHERE kind='am1.poison';");

        am1_sql(&conn, "ALTER TABLE ledger RENAME TO ledger_am1_hors_d_atteinte;");
        let cause = am1_cause(ledger_append(&conn, "am1.lecture", "maillon sans table"));
        assert_eq!(cause, CAUSE_TETE_DE_CHAINE_ILLISIBLE, "table retirée : la même phrase fixe");
        am1_sans_moteur("lecture (table retirée)", &cause);
        am1_sql(&conn, "ALTER TABLE ledger_am1_hors_d_atteinte RENAME TO ledger;");

        assert_eq!(compte(&conn), avant, "aucun maillon n'est entré pendant les refus");
        assert!(ledger_append(&conn, "am1.sain", "contrôle positif, seconde fois").cause_de_non_inscription().is_none(), "le refus n'est pas inconditionnel");
        assert_eq!(compte(&conn), avant + 1);
    }

    /// CE QU'IL TIENT : le miroir `control_ledger_append` rend les MÊMES phrases fixes, à l'identique, sur ses deux
    /// voies (déclencheur sur `control_ledger`, tête BLOB), sans le texte du moteur ; contrôle positif avant et après.
    /// MUTANTS : `AM1_R698`, `AM1_R680`.
    #[test]
    fn am1_le_journal_de_controle_rend_les_memes_phrases_fixes() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _cptmp) = un_control_plane_au_journal_vierge();
        let controle = |sql: &str| am1_sql(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), sql);
        assert!(control_ledger_append(&st, "am1.sain", "op-am1", "", "contrôle positif").cause_de_non_inscription().is_none());

        controle(&am1_refuser_l_ecriture("control_ledger", "am1.ecriture", AM1_MOTEUR_CONTROLE));
        let cause = am1_cause(control_ledger_append(&st, "am1.ecriture", "op-am1", "acme", "maillon refusé"));
        assert_eq!(cause, CAUSE_MAILLON_NON_ECRIT, "voie de l'écriture du journal de contrôle");
        assert!(!cause.contains("ILLISIBLE"), "{cause}");
        am1_sans_moteur("écriture du contrôle", &cause);
        controle("DROP TRIGGER am1_refus;");
        assert_eq!(compter_les_maillons_de_controle(&st), 1, "le maillon refusé n'est pas entré");

        rendre_le_maillon_de_controle_precedent_illisible(&st);
        let cause = am1_cause(control_ledger_append(&st, "am1.lecture", "op-am1", "acme", "maillon sans tête lisible"));
        assert_eq!(cause, CAUSE_TETE_DE_CHAINE_ILLISIBLE, "voie de la lecture du journal de contrôle");
        am1_sans_moteur("lecture du contrôle", &cause);
        controle("DELETE FROM control_ledger WHERE kind='poison';");

        assert!(control_ledger_append(&st, "am1.sain", "op-am1", "", "seconde fois").cause_de_non_inscription().is_none(), "le refus n'est pas inconditionnel");
        assert_eq!(compter_les_maillons_de_controle(&st), 2);
    }

    /// CE QU'IL TIENT : le texte du moteur n'est PAS perdu — la ligne de sortie d'erreur de chaque primitive, sur
    /// chaque voie, le porte encore, comparée EN ENTIER (sous-processus : la sortie d'erreur du test est capturée,
    /// le message lu par la primitive est recalculé dans l'enfant et transmis par la sortie standard).
    #[test]
    fn am1_la_ligne_de_la_primitive_garde_le_moteur() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AM1_ENFANT).is_ok() {
            let conn = am1_base_du_registre();
            am1_sql(&conn, &am1_refuser_l_ecriture("ledger", "am1.ecriture", AM1_MOTEUR));
            let _ = am1_cause(ledger_append(&conn, "am1.ecriture", "detail"));
            am1_sql(&conn, "DROP TRIGGER am1_refus;");
            am1_empoisonner_la_tete(&conn);
            println!("AM1-LECTURE-REGISTRE:{}", ledger_prev_hash(&conn).expect_err("tête illisible"));
            let _ = am1_cause(ledger_append(&conn, "am1.lecture", "detail"));

            let (st, _cptmp) = un_control_plane_au_journal_vierge();
            am1_sql(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), &am1_refuser_l_ecriture("control_ledger", "am1.ecriture", AM1_MOTEUR_CONTROLE));
            let _ = am1_cause(control_ledger_append(&st, "am1.ecriture", "op-am1", "acme", "detail"));
            am1_sql(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), "DROP TRIGGER am1_refus;");
            rendre_le_maillon_de_controle_precedent_illisible(&st);
            println!("AM1-LECTURE-CONTROLE:{}", control_ledger_prev_hash(&st.tenants.control.as_ref().expect("mode 1").conn.lock()).expect_err("tête illisible"));
            let _ = am1_cause(control_ledger_append(&st, "am1.lecture", "op-am1", "acme", "detail"));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::maillon_non_ecrit_sert_une_phrase_fixe::am1_la_ligne_de_la_primitive_garde_le_moteur"])
            .env(AM1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> String {
            stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1.lines().next().unwrap_or("").to_string()
        };
        let (lu_registre, lu_controle) = (marque("AM1-LECTURE-REGISTRE:"), marque("AM1-LECTURE-CONTROLE:"));
        assert!(lu_registre.contains("Blob") && lu_controle.contains("Blob"), "contrôle : le moteur a bien parlé : {lu_registre} / {lu_controle}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("WARN maillon 'am1.")).collect();
        assert_eq!(
            lignes,
            vec![
                format!("[ledger] WARN maillon 'am1.ecriture' NON inscrit : l'écriture n'a pas eu lieu ({AM1_MOTEUR})"),
                format!("[ledger] WARN maillon 'am1.lecture' NON écrit : hachage précédent ILLISIBLE ({lu_registre}) — l'écrire romprait la chaîne"),
                format!("[control_ledger] WARN maillon 'am1.ecriture' NON inscrit : l'écriture n'a pas eu lieu ({AM1_MOTEUR_CONTROLE})"),
                format!("[control_ledger] WARN maillon 'am1.lecture' NON écrit : hachage précédent ILLISIBLE ({lu_controle}) — l'écrire romprait la chaîne"),
            ],
            "les quatre lignes des primitives, entières : {stderr}"
        );
    }

    // -------------------------------------------------------------------------------------
    // (2) PAR LA ROUTE — chaque famille de corps `registre_sans_maillon` du mode 0, rôle le plus faible admis.
    // -------------------------------------------------------------------------------------

    struct Am1Routeur {
        st: AppState,
        _base: crate::tmp_possede::TmpDb,
        addr: std::net::SocketAddr,
        lecteur: String,
        editeur: String,
        admin: String,
    }

    async fn am1_routeur() -> Am1Routeur {
        let (st, base) = router_test_state("am1-route");
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt-am1',?1,'editor')", params![hash_pw(AM1_MDP_EDITEUR).unwrap()])
            .expect("fixture : compte éditeur");
        let addr = router_serve(st.clone()).await;
        let b64 = |s: String| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(s));
        Am1Routeur {
            st,
            _base: base,
            addr,
            lecteur: viewer_authz(),
            editeur: b64(format!("edt-am1:{AM1_MDP_EDITEUR}")),
            admin: b64("root:rootpw1234567".to_string()),
        }
    }

    /// Une requête à travers les six couches du routeur, la réponse ENTIÈRE (corps `chunked` recollé) : statut,
    /// texte brut du corps, et JSON (`Null` pour un corps vide).
    async fn am1_envoyer(r: &Am1Routeur, chemin: &str, authz: &str, corps: &str) -> (u16, String, Value) {
        let entetes = [("Content-Type", "application/json")];
        let (code, texte) = router_probe_envoi(r.addr, "POST", chemin, Some(authz), &entetes, corps).await;
        let (en_tete, corps_http) = texte.split_once("\r\n\r\n").unwrap_or(("", ""));
        let octets: Vec<u8> = if en_tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            shell_decouper(corps_http.as_bytes()).unwrap_or_else(|| panic!("trame chunked incomplète : {texte}"))
        } else {
            corps_http.as_bytes().to_vec()
        };
        let brut = String::from_utf8_lossy(&octets).into_owned();
        (code, brut.clone(), serde_json::from_str(&brut).unwrap_or(Value::Null))
    }

    /// Le geste d'une famille : chemin, jeton du rôle le plus faible admis, corps. Ce qui doit exister AVANT le
    /// geste (le dossier d'une déclaration d'incident) est créé ici, registre sain, avant que la panne soit posée.
    async fn am1_preparer(r: &Am1Routeur, famille: &str, phase: &str, rang: i64) -> (String, String, String) {
        match famille {
            "session" => ("/api/saved-queries".into(), r.lecteur.clone(), json!({ "name": format!("am1-{phase}"), "soql": "search *" }).to_string()),
            "actions" => ("/api/actions".into(), r.admin.clone(), json!({ "kind": "unban_ip", "target": "203.0.113.7" }).to_string()),
            "cases" => ("/api/cases".into(), r.editeur.clone(), json!({ "title": format!("Dossier am1 {phase}"), "severity": 3, "priority": 2 }).to_string()),
            "incidents" => {
                let corps = json!({ "title": format!("Dossier am1 incident {phase}"), "severity": 3, "priority": 2 }).to_string();
                let (code, brut, v) = am1_envoyer(r, "/api/cases", &r.editeur, &corps).await;
                assert_eq!(code, 200, "fixture : le dossier s'ouvre : {brut}");
                assert!(v.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "fixture : registre sain à la préparation : {brut}");
                let id = v["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant du dossier : {brut}"));
                (format!("/api/cases/{id}/incident"), r.editeur.clone(), json!({ "tier": 2, "incident_type": "rançongiciel", "commander": "pilote-am1" }).to_string())
            }
            "caseops" => (
                "/api/sla-policies".into(),
                r.editeur.clone(),
                json!({ "name": format!("am1-{phase}"), "priority": rang, "ack_target_s": 60, "resolve_target_s": 600 }).to_string(),
            ),
            autre => panic!("famille inconnue : {autre}"),
        }
    }

    /// CE QU'IL TIENT : par le routeur réel, pour chaque famille de corps `registre_sans_maillon` du mode 0 —
    /// `session.rs` (requête sauvegardée, lecteur), `actions.rs` (riposte en file, admin), `cases.rs` (dossier,
    /// éditeur), `incidents.rs` (déclaration, éditeur), `caseops.rs` (politique SLA, éditeur) — le geste fait sans
    /// trace sert un 200 dont l'aveu vaut EXACTEMENT « CAUSE_GESTE_SANS_TRACE (CAUSE_MAILLON_NON_ECRIT) » sur
    /// l'écriture refusée et « CAUSE_GESTE_SANS_TRACE (CAUSE_TETE_DE_CHAINE_ILLISIBLE) » sur la tête illisible, et
    /// aucun octet de la réponse ne porte le texte du moteur. Contrôle positif par famille, registre sain : aucun aveu.
    /// MUTANTS : `AM1_L121`, `AM1_L106`.
    #[tokio::test]
    async fn am1_par_la_route_chaque_famille_sert_la_phrase_fixe() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let r = am1_routeur().await;
        let familles: Vec<(&str, &str)> = vec![
            ("session", "saved_query.create"),
            ("actions", "action.queued"),
            ("cases", "case.create"),
            ("incidents", "case.incident"),
            ("caseops", "sla_policy.upsert"),
        ];
        assert!(familles.len() >= 5, "plancher : les cinq familles du mode 0");
        let mut jouees = 0usize;
        for (famille, genre) in &familles {
            // CONTRÔLE POSITIF — registre sain : aucun aveu.
            let (chemin, authz, corps) = am1_preparer(&r, famille, "sain", 1).await;
            let (code, brut, v) = am1_envoyer(&r, &chemin, &authz, &corps).await;
            assert!(matches!(code, 200 | 204), "{famille} : le geste nominal passe : {code} {brut}");
            assert!(v.get(CLE_REGISTRE_SANS_MAILLON).is_none(), "{famille} : registre sain, aucun aveu : {brut}");

            // L'ÉCRITURE REFUSÉE — sur le seul genre du geste.
            let (chemin, authz, corps) = am1_preparer(&r, famille, "ecriture", 2).await;
            am1_sql(&r.st.db.lock(), &am1_refuser_l_ecriture("ledger", genre, AM1_MOTEUR));
            let (code, brut, v) = am1_envoyer(&r, &chemin, &authz, &corps).await;
            am1_sql(&r.st.db.lock(), "DROP TRIGGER am1_refus;");
            assert_eq!(code, 200, "{famille} : le geste a eu lieu, sa trace manque : {brut}");
            assert_eq!(
                v[CLE_REGISTRE_SANS_MAILLON].as_str(),
                Some(format!("{CAUSE_GESTE_SANS_TRACE} ({CAUSE_MAILLON_NON_ECRIT})").as_str()),
                "{famille} : l'aveu de l'écriture refusée, à l'identique : {brut}"
            );
            am1_sans_moteur(famille, &brut);

            // LA TÊTE DE CHAÎNE ILLISIBLE — la lecture meurt seule.
            let (chemin, authz, corps) = am1_preparer(&r, famille, "lecture", 3).await;
            am1_empoisonner_la_tete(&r.st.db.lock());
            let (code, brut, v) = am1_envoyer(&r, &chemin, &authz, &corps).await;
            am1_sql(&r.st.db.lock(), "DELETE FROM ledger WHERE kind='am1.poison';");
            assert_eq!(code, 200, "{famille} : le geste a eu lieu, sa trace manque : {brut}");
            assert_eq!(
                v[CLE_REGISTRE_SANS_MAILLON].as_str(),
                Some(format!("{CAUSE_GESTE_SANS_TRACE} ({CAUSE_TETE_DE_CHAINE_ILLISIBLE})").as_str()),
                "{famille} : l'aveu de la tête illisible, à l'identique : {brut}"
            );
            am1_sans_moteur(famille, &brut);
            jouees += 1;
        }
        assert_eq!(jouees, familles.len(), "chaque famille a été jouée");
    }

    // -------------------------------------------------------------------------------------
    // (3) LE MODE 1 — journal de contrôle : aveu d'un grant (`rbac.rs`) et refus de destruction (`tenants.rs`).
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : en mode 1, par les gestionnaires (super-administrateur, le seul rôle admis) — le grant posé
    /// sans trace porte « CAUSE_GESTE_SANS_TRACE_DE_CONTROLE (phrase fixe) », et la destruction de tenant refusée sert
    /// un 503 dont le corps vaut EXACTEMENT `{error: "CAUSE_DESTRUCTION_SANS_TRACE (phrase fixe)", id}`, sur les deux
    /// voies, sans le texte du moteur ; la base du tenant reste intacte. Contrôle positif : grant sans aveu, puis
    /// destruction faite.
    /// MUTANTS : `AM1_R698`, `AM1_R680`.
    #[tokio::test]
    async fn am1_mode_1_grant_et_destruction_servent_la_phrase_fixe() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let _roles = CUSTOM_ROLES_TEST_LOCK.lock();
        let (st, _dir) = mk_mode1_state();
        let sa = au_super("op-am1");
        let controle = |sql: &str| am1_sql(&st.tenants.control.as_ref().expect("mode 1").conn.lock(), sql);
        let (statut, cree) =
            pb_json(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": "am1-acme", "name": "Am1Acme" }))).await).await;
        assert_eq!(statut, 201, "{cree}");
        let chemin: String = am1_chemin_du_tenant(&st);
        assert!(std::path::Path::new(&chemin).exists(), "fixture : la base du tenant existe");

        let grant = |user: &'static str| {
            let st = st.clone();
            let sa = sa.clone();
            async move {
                pb_json(grant_set(State(st), crate::secret_des_gestes::presente_de_test(), Extension(sa), Path("am1-acme".into()), Json(json!({ "user": user, "role": "editor" }))).await).await
            }
        };
        let detruire = || {
            let st = st.clone();
            let sa = sa.clone();
            async move { pb_json(tenant_delete(State(st), Extension(sa), Path("am1-acme".into()), Json(json!({ "confirm": "Am1Acme" }))).await).await }
        };

        let (statut, v) = grant("am1-carol").await;
        assert_eq!((statut, v.get(CLE_REGISTRE_SANS_MAILLON)), (200, None), "CONTRÔLE POSITIF : journal sain, aucun aveu : {v}");

        let voies: Vec<(&str, &str)> = vec![("ecriture", CAUSE_MAILLON_NON_ECRIT), ("lecture", CAUSE_TETE_DE_CHAINE_ILLISIBLE)];
        assert!(voies.len() >= 2, "plancher : les deux voies");
        let mut jouees = 0usize;
        for (voie, phrase) in &voies {
            if *voie == "ecriture" {
                controle(&format!("CREATE TRIGGER am1_refus BEFORE INSERT ON control_ledger BEGIN SELECT RAISE(ABORT, '{AM1_MOTEUR_CONTROLE}'); END;"));
            } else {
                rendre_le_maillon_de_controle_precedent_illisible(&st);
            }
            let (statut, v) = grant(if *voie == "ecriture" { "am1-dave" } else { "am1-erin" }).await;
            assert_eq!(statut, 200, "{voie} : le grant EST posé : {v}");
            assert_eq!(
                v[CLE_REGISTRE_SANS_MAILLON].as_str(),
                Some(format!("{CAUSE_GESTE_SANS_TRACE_DE_CONTROLE} ({phrase})").as_str()),
                "{voie} : l'aveu du grant, à l'identique : {v}"
            );
            am1_sans_moteur(voie, &v.to_string());

            let (statut, v) = detruire().await;
            assert_eq!(statut, 503, "{voie} : la destruction est refusée : {v}");
            let mut cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            cles.sort();
            assert_eq!(cles, vec!["error", "id"], "{voie} : corps entier, deux clés : {v}");
            assert_eq!(v["error"].as_str(), Some(format!("{CAUSE_DESTRUCTION_SANS_TRACE} ({phrase})").as_str()), "{voie} : le refus, à l'identique : {v}");
            assert!(v["id"].as_str().is_some_and(|id| id.starts_with("plume-e")), "{voie} : l'identifiant de corrélation : {v}");
            am1_sans_moteur(voie, &v.to_string());
            assert!(std::path::Path::new(&chemin).exists(), "{voie} : rien n'est détruit");

            if *voie == "ecriture" {
                controle("DROP TRIGGER am1_refus;");
            } else {
                controle("DELETE FROM control_ledger WHERE kind='poison';");
            }
            jouees += 1;
        }
        assert_eq!(jouees, voies.len(), "chaque voie a été jouée");

        // CONTRÔLE POSITIF — journal réparé : la même destruction a lieu.
        let (statut, v) = detruire().await;
        assert_eq!(statut, 200, "le refus n'est pas inconditionnel : {v}");
        assert!(!std::path::Path::new(&chemin).exists(), "la destruction a lieu");
    }

    fn am1_chemin_du_tenant(st: &AppState) -> String {
        let cp = st.tenants.control.as_ref().expect("mode 1");
        let c = cp.conn.lock();
        c.query_row("SELECT db_path FROM tenant WHERE id='am1-acme'", [], |r| r.get(0)).expect("fixture : le tenant est catalogué")
    }
}
