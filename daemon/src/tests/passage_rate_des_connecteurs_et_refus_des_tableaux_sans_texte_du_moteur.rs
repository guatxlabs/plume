// =====================================================================================
// `P10.34-b` (connecteurs : un lot non pris parce qu'une AUTRE connexion tient le verrou ne laissait aucune trace),
// `P10.29-l` (reste des tableaux de bord : le texte du moteur servi au client par `dash_ergonomics.rs`) et `P10.20-b`
// (reste des tableaux de bord : `record_panel_cost` jetait son écriture).
//
// LE DÉFAUT `P10.34-b`, RE-MESURÉ SUR 1287fb98 : `ingest_events_batch_env` rend `LotNonEcrit::NonPris` quand son
// `BEGIN IMMEDIATE` est refusé ; quand c'est parce qu'une autre connexion tient le verrou d'écriture, le même verrou
// refusait l'`UPDATE` (`let _ = conn.execute(..)`) qui devait poser `last_run` et `ECHEC_D_INGESTION_LOT_NON_PRIS` : ni
// trace en base, ni ligne de journal. Le watermark n'avance pas (rejouable, sans perte).
//
// CE QUE CES TÉMOINS TIENNENT, sur une base sur DISQUE (une seconde connexion, `BEGIN IMMEDIATE`, tient le verrou) et
// par le point d'entrée du planificateur (`poll_one_connector`), pour http_pull ET defender :
//   - verrou tenu pendant tout le passage : l'état du connecteur est celui d'avant (rien n'est écrit), et UNE ligne
//     `[connecteurs] WARN connecteur #1 : passage non pris, état non écrit (verrou d'écriture tenu ailleurs)`, comparée
//     en entier ;
//   - verrou libéré entre deux essais (crochet `point_de_course`, appelé une fois) : `last_run` et la phrase écrits,
//     `last_ok`, `last_count` et le watermark inchangés, aucune ligne ;
//   - refus du moteur qui n'est pas un verrou (déclencheur sur `connector`, `BEGIN` du lot refusé par un autorisateur,
//     écrivain libre) : la ligne dit `(refus du moteur qui n'est pas un verrou)` ;
//   - aucune ligne ne porte le nom du connecteur, son URL ni son secret.
// Tableaux de bord : chaque refus sert un corps `{error, id}` EXACT (la phrase fixe seule, l'identifiant de corrélation),
// sans le texte du moteur ; la ligne de journal, comparée en entier, porte l'identifiant servi et la cause du moteur
// rejouée sur la même base par la même instruction. Porte d'édition (quatre routes), lecture d'existence d'une liste
// (deux routes), modification d'un panneau de bibliothèque et d'une liste, suppression d'une liste, révocation d'un
// instantané. Coût d'un panneau : refus (ABORT) et écriture sans ligne (IGNORE) -> une ligne fixe sans l'empreinte de
// requête, par l'appel direct et par `consigner_l_issue_du_rafraichissement` ; écrit -> aucune ligne. Nominal : aucune
// ligne `[dashboards]`.
//
// INVERSION D'UN TÉMOIN EXISTANT : `refus_de_modification_servi_avec_sa_cause.rs` affirmait `servie.contains
// ("visibility")` (l'écriture refusée et le texte du moteur dans le corps) ; il affirme désormais la phrase seule.
//
// MUTANTS JOUÉS (variable de mutation, retirés avant le commit) : AH4_CONN_UN_SEUL_ESSAI, AH4_CONN_SANS_JOURNAL,
// AH4_CONN_NATURE_UNIQUE, AH4_CONN_HTTP_JETE, AH4_CONN_DEF_JETE, AH4_PORTE_CAUSE_EXPOSEE, AH4_PORTE_SANS_JOURNAL,
// AH4_LISTE_CAUSE_EXPOSEE, AH4_LISTE_SANS_JOURNAL, AH4_LPU_CAUSE_EXPOSEE, AH4_PLU_CAUSE_EXPOSEE, AH4_PLD_CAUSE_EXPOSEE,
// AH4_SNAP_CAUSE_EXPOSEE, AH4_SNAP_SANS_JOURNAL, AH4_COUT_OK0_ACCEPTE, AH4_COUT_SANS_JOURNAL.
//
// CE QU'ILS NE TIENNENT PAS : un verrou libéré pendant l'attente du `busy_timeout` d'un essai (non déterministe) ; ce que
// la console des connecteurs affiche de `last_error` (web/ hors périmètre). Le `NonPris` dû à une transaction étrangère
// pendante sur la même connexion (l'`UPDATE` n'y est plus essayé, `P10.34-f`) est tenu par
// `ecritures_d_etat_des_migrations_et_des_connecteurs_consommees.rs`, phases `etrangere-*`.
// =====================================================================================
mod passage_rate_des_connecteurs_et_refus_des_tableaux_sans_texte_du_moteur {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::atomic::{AtomicBool, Ordering};

    const AH4_ENFANT: &str = "PLUME_TEMOIN_AH4_ENFANT";
    const AH4_PHASE: &str = "AH4-PHASE:";
    const AH4_ATTENDUE: &str = "AH4-ATTENDUE:";
    const AH4_NOM_DU_CONNECTEUR: &str = "ah4-connecteur-nomme";
    const AH4_SECRET_DU_CONNECTEUR: &str = "ah4-valeur-du-secret";
    const AH4_HOTE: &str = "203.0.113.10";
    /// Le watermark enregistré : une date ISO antérieure à celles du passage (un watermark avancé se verrait).
    const AH4_WM: &str = "2020-01-01T00:00:00Z";
    const AH4_REFUS: &str = "ah4 refus de temoin";
    /// L'empreinte de requête d'un panneau : elle ne doit paraître dans aucune ligne.
    const AH4_EMPREINTE: &str = "ah4-empreinte-de-requete";

    // ---- connecteurs (`P10.34-b`) ----

    fn ah4_cfg_http() -> String {
        json!({
            "url": format!("https://{AH4_HOTE}/api/alertes"), "records_path": "items", "field_map": { "id": "id", "message": "msg" },
            "watermark": { "field_path": "ts", "param": "since", "format": "iso8601" },
        })
        .to_string()
    }

    fn ah4_fetch_http() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let corps = json!({ "items": [
                { "id": "ah4-a1", "msg": "un", "ts": "2026-07-01T10:00:00Z" },
                { "id": "ah4-a2", "msg": "deux", "ts": "2026-07-01T11:00:00Z" },
            ] });
            Ok(HttpResp { status: 200, headers: vec![], body: corps.to_string().into_bytes() })
        }
    }

    fn ah4_cfg(ctype: &str) -> String {
        if ctype == "http_pull" { ah4_cfg_http() } else { defender_cfg_json() }
    }

    /// Une base sur disque avec le connecteur n°1 (état d'avant : last_run=5, last_ok=111, last_count=7, watermark
    /// `AH4_WM`, aucune erreur) ; l'écrivain n'attend qu'un instant un verrou tenu ailleurs.
    fn ah4_base_du_connecteur(tag: &str, ctype: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(tag);
        let c = st.db.lock();
        c.execute(
            "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id,last_run,last_ok,last_count,watermark) \
             VALUES(1,?1,?2,1,?3,?4,300,'prod',5,111,7,?5)",
            params![ctype, AH4_NOM_DU_CONNECTEUR, ah4_cfg(ctype), AH4_SECRET_DU_CONNECTEUR, AH4_WM],
        )
        .expect("fixture : connecteur");
        c.busy_timeout(std::time::Duration::from_millis(20)).expect("fixture : attente courte de l'écrivain");
        drop(c);
        (st, p)
    }

    fn ah4_passer(st: &AppState, db_path: &str, ctype: &str, now_ts: i64) {
        let cfg = ah4_cfg(ctype);
        if ctype == "http_pull" {
            poll_one_connector(&st.db, db_path, 1, ctype, &cfg, AH4_SECRET_DU_CONNECTEUR, "prod", Some(AH4_WM), now_ts, ah4_fetch_http());
        } else {
            poll_one_connector(&st.db, db_path, 1, ctype, &cfg, AH4_SECRET_DU_CONNECTEUR, "prod", Some(AH4_WM), now_ts, mock_ok_fetch());
        }
    }

    type Ah4Etat = (i64, i64, i64, Option<String>, Option<String>);

    fn ah4_etat(c: &Connection) -> Ah4Etat {
        c.query_row("SELECT last_run,last_ok,last_count,watermark,last_error FROM connector WHERE id=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .expect("état du connecteur lisible")
    }

    fn ah4_etat_d_avant() -> Ah4Etat {
        (5, 111, 7, Some(AH4_WM.to_string()), None)
    }

    fn ah4_verrou_tenu_par_une_autre_connexion(p: &str) -> Connection {
        let autre = open_db(p).expect("fixture : seconde connexion");
        autre.execute_batch("BEGIN IMMEDIATE").expect("fixture : la seconde connexion prend le verrou d'écriture");
        autre
    }

    fn ah4_enfant_des_connecteurs() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le passage lit l'environnement (pages, configuration)
        let now_ts = now();
        for ctype in ["http_pull", "defender"] {
            // (1) le verrou est tenu pendant tout le passage.
            eprintln!("{AH4_PHASE}verrou-{ctype}");
            let (st, p) = ah4_base_du_connecteur(&format!("ah4-verrou-{ctype}"), ctype);
            let autre = ah4_verrou_tenu_par_une_autre_connexion(&p);
            ah4_passer(&st, &p, ctype, now_ts);
            autre.execute_batch("ROLLBACK").expect("fixture : le verrou est rendu");
            assert_eq!(ah4_etat(&st.db.lock()), ah4_etat_d_avant(), "{ctype} verrou tenu : rien n'est écrit, l'état est celui d'avant");

            // (2) le verrou est libéré entre deux essais.
            eprintln!("{AH4_PHASE}libere-{ctype}");
            let (st, p) = ah4_base_du_connecteur(&format!("ah4-libere-{ctype}"), ctype);
            let autre = ah4_verrou_tenu_par_une_autre_connexion(&p);
            let appele = Arc::new(AtomicBool::new(false));
            let appele_crochet = appele.clone();
            crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("passage-rate-du-connecteur:{}:1", &*p), move || {
                autre.execute_batch("ROLLBACK").expect("crochet : le verrou est rendu");
                appele_crochet.store(true, Ordering::SeqCst);
            });
            ah4_passer(&st, &p, ctype, now_ts);
            assert!(appele.load(Ordering::SeqCst), "{ctype} : le crochet entre deux essais a été appelé");
            assert_eq!(
                ah4_etat(&st.db.lock()),
                (now_ts, 111, 7, Some(AH4_WM.to_string()), Some(ECHEC_D_INGESTION_LOT_NON_PRIS.to_string())),
                "{ctype} verrou libéré au second essai : last_run et la phrase écrits, last_ok, last_count et watermark inchangés"
            );

            // (3) un refus du moteur qui n'est pas un verrou : le `BEGIN` du lot est refusé par un autorisateur (lot non
            // pris, écrivain LIBRE, `P10.34-f` : une transaction étrangère ferait sauter l'essai), le déclencheur refuse
            // l'`UPDATE`.
            eprintln!("{AH4_PHASE}moteur-{ctype}");
            let (st, p) = ah4_base_du_connecteur(&format!("ah4-moteur-{ctype}"), ctype);
            st.db
                .lock()
                .execute_batch(&format!(
                    "CREATE TRIGGER ah4_connecteur_refuse BEFORE UPDATE ON connector BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"
                ))
                .expect("fixture : déclencheur");
            st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            ah4_passer(&st, &p, ctype, now_ts);
            st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert!(st.db.lock().is_autocommit(), "{ctype} refus du moteur : contrôle, l'écrivain est libre");
            assert_eq!(ah4_etat(&st.db.lock()), ah4_etat_d_avant(), "{ctype} refus du moteur : rien n'est écrit");
        }
        eprintln!("{AH4_PHASE}fin");
    }

    /// CE QU'IL TIENT : voir l'en-tête (connecteurs). Les états sont jugés dans l'enfant (une assertion ratée le fait
    /// sortir en erreur) ; les lignes de journal, par phase et en entier, dans le parent.
    /// MUTATIONS : AH4_CONN_UN_SEUL_ESSAI (phase libere : état d'avant), AH4_CONN_SANS_JOURNAL et AH4_CONN_HTTP_JETE /
    /// AH4_CONN_DEF_JETE (phases verrou et moteur : aucune ligne ; libere : état d'avant), AH4_CONN_NATURE_UNIQUE (phase
    /// moteur : « verrou »).
    #[test]
    fn ah4_passage_rate_d_un_connecteur_sous_verrou_tenu_ailleurs_laisse_une_trace() {
        if std::env::var(AH4_ENFANT).is_ok() {
            ah4_enfant_des_connecteurs();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::passage_rate_des_connecteurs_et_refus_des_tableaux_sans_texte_du_moteur::ah4_passage_rate_d_un_connecteur_sous_verrou_tenu_ailleurs_laisse_une_trace",
            ])
            .env(AH4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (états jugés) : {stdout}\n{stderr}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AH4_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AH4_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[connecteurs] ")).map(str::to_string).collect()
        };
        let verrou = "[connecteurs] WARN connecteur #1 : passage non pris, état non écrit (verrou d'écriture tenu ailleurs)";
        // `P10.34-f` : la phase `moteur` ne pose plus de transaction étrangère (l'`UPDATE` n'y serait plus essayé) ; son
        // `BEGIN` est refusé par un autorisateur, l'écrivain reste libre, et la ligne dit toujours la nature du refus.
        let moteur = "[connecteurs] WARN connecteur #1 : passage non pris, état non écrit (refus du moteur qui n'est pas un verrou)";
        let cas = [
            ("verrou-http_pull", vec![verrou]),
            ("libere-http_pull", vec![]),
            ("moteur-http_pull", vec![moteur]),
            ("verrou-defender", vec![verrou]),
            ("libere-defender", vec![]),
            ("moteur-defender", vec![moteur]),
        ];
        assert!(cas.len() >= 6, "plancher : trois phases sur deux sites");
        for (nom, attendues) in cas {
            assert_eq!(phase(nom), attendues, "phase {nom} : lignes [connecteurs], en entier");
        }
        for interdit in [AH4_NOM_DU_CONNECTEUR, AH4_SECRET_DU_CONNECTEUR, AH4_HOTE] {
            assert!(!stderr.contains(interdit), "`{interdit}` ne paraît dans aucune ligne : {stderr}");
        }
    }

    // ---- tableaux de bord (`P10.29-l`, `P10.20-b`) ----

    async fn ah4_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 503 EN ENTIER : exactement `error` et `id`, la phrase seule, l'identifiant de corrélation, et ni la cause du
    /// moteur ni le refus du déclencheur. Rend l'identifiant servi.
    fn ah4_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str, moteur: &str) -> String {
        assert_eq!(*statut, 503, "{quoi} : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase fixe, seule : {corps}");
        let cid = v["id"].as_str().unwrap_or("").to_string();
        assert!(cid.starts_with("plume-e"), "{quoi} : identifiant de corrélation : {corps}");
        assert!(!moteur.is_empty(), "contrôle {quoi} : la cause du moteur est rejouée");
        for interdit in [moteur, AH4_REFUS, "not authorized", "visibility", "SELECT", "UPDATE", "DELETE"] {
            assert!(!corps.contains(interdit), "{quoi} : `{interdit}` ne sort pas : {corps}");
        }
        cid
    }

    fn ah4_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ah4_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get::<_, String>(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// La cause du moteur d'une instruction refusée, rejouée sur la même base (le refus doit avoir lieu).
    fn ah4_cause_lecture(st: &AppState, sql: &str, id: i64) -> String {
        st.db.lock().query_row(sql, params![id], |_| Ok(())).expect_err("fixture : la lecture est refusée").to_string()
    }

    fn ah4_cause_ecriture(st: &AppState, sql: &str, id: i64) -> String {
        st.db.lock().execute(sql, params![id]).expect_err("fixture : l'écriture est refusée").to_string()
    }

    fn ah4_refuser_la_colonne(st: &AppState, table: &'static str, colonne: &'static str) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ah4_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn ah4_attendue(phase: &str, ligne: String) {
        println!("{AH4_ATTENDUE}{phase}|{ligne}");
    }

    async fn ah4_objets(st: &AppState, alice: &AuthUser) -> (i64, i64) {
        let r = ah4_reponse(
            library_panel_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "avant", "query": "search source=web | table message" }))).await,
        )
        .await;
        let lp = r.2["id"].as_i64().unwrap_or_else(|| panic!("fixture : panneau créé : {}", r.1));
        let r = ah4_reponse(playlist_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "avant", "items": [1] }))).await).await;
        let pl = r.2["id"].as_i64().unwrap_or_else(|| panic!("fixture : liste créée : {}", r.1));
        (lp, pl)
    }

    fn ah4_instantane(st: &AppState, jeton: &str) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by) VALUES(NULL,'ah4',?1,'{}',0,'alice')",
            params![jeton],
        )
        .expect("fixture : instantané");
        c.last_insert_rowid()
    }

    async fn ah4_enfant_des_tableaux() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("ah4-tableaux");
        let alice = sp_au("alice", "editor");
        let (lp, pl) = ah4_objets(&st, &alice).await;
        let ligne_lp = format!("SELECT name||'|'||visibility FROM library_panel WHERE id={lp}");
        let ligne_pl = format!("SELECT name||'|'||visibility FROM playlist WHERE id={pl}");
        let corps_maj = || json!({ "name": "apres", "visibility": "private" });

        // Porte d'édition : la lecture du propriétaire refusée, sur les quatre routes qui la passent.
        eprintln!("{AH4_PHASE}porte");
        ah4_refuser_la_colonne(&st, "library_panel", "owner");
        let e_lp = ah4_cause_lecture(&st, "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM library_panel WHERE id=?1", lp);
        let r_maj = ah4_reponse(library_panel_update(State(st.clone()), Extension(alice.clone()), Path(lp), Json(corps_maj())).await).await;
        let r_del = ah4_reponse(library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lp)).await).await;
        ah4_lever(&st);
        ah4_refuser_la_colonne(&st, "playlist", "owner");
        let e_pl = ah4_cause_lecture(&st, "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM playlist WHERE id=?1", pl);
        let r_pmaj = ah4_reponse(playlist_update(State(st.clone()), Extension(alice.clone()), Path(pl), Json(corps_maj())).await).await;
        let r_pdel = ah4_reponse(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(pl)).await).await;
        ah4_lever(&st);
        let porte = [
            ("library_panel_update", &r_maj, "du panneau de bibliothèque", lp, &e_lp),
            ("library_panel_delete", &r_del, "du panneau de bibliothèque", lp, &e_lp),
            ("playlist_update", &r_pmaj, "de la liste de lecture", pl, &e_pl),
            ("playlist_delete", &r_pdel, "de la liste de lecture", pl, &e_pl),
        ];
        assert!(porte.len() >= 4, "plancher : les quatre routes qui passent la porte");
        for (geste, r, objet, id, e) in porte {
            let cid = ah4_juger_503(&format!("porte {geste}"), r, crate::handlers::dash_ergonomics::CAUSE_DROIT_D_EDITION_NON_LU, e);
            ah4_attendue("porte", format!("[dashboards] WARN droit d'édition {objet} #{id} NON lu, rien n'est écrit ({cid}) : {e}"));
        }
        assert_eq!((ah4_texte(&st, &ligne_lp), ah4_texte(&st, &ligne_pl)), ("avant|shared".into(), "avant|shared".into()), "porte : rien n'est écrit");

        // Lecture d'existence d'une liste refusée, sur ses deux routes.
        eprintln!("{AH4_PHASE}liste");
        ah4_refuser_la_colonne(&st, "playlist", "id");
        let e = ah4_cause_lecture(&st, "SELECT 1 FROM playlist WHERE id=?1", pl);
        let r_maj = ah4_reponse(playlist_update(State(st.clone()), Extension(alice.clone()), Path(pl), Json(corps_maj())).await).await;
        let r_del = ah4_reponse(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(pl)).await).await;
        ah4_lever(&st);
        let liste = [("playlist_update", &r_maj), ("playlist_delete", &r_del)];
        assert!(liste.len() >= 2, "plancher : les deux routes qui lisent l'existence");
        for (geste, r) in liste {
            let cid = ah4_juger_503(&format!("liste {geste}"), r, crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_LUE, &e);
            ah4_attendue("liste", format!("[dashboards] WARN liste de lecture #{pl} NON lue, rien n'est écrit ({cid}) : {e}"));
        }
        assert_eq!(ah4_texte(&st, &ligne_pl), "avant|shared", "liste : rien n'est écrit ni supprimé");

        // Modification d'un panneau de bibliothèque : la bascule en privé refusée.
        eprintln!("{AH4_PHASE}lpu");
        ah4_sql(&st, &format!("CREATE TRIGGER ah4_refus BEFORE UPDATE OF visibility ON library_panel BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"));
        let e = ah4_cause_ecriture(&st, "UPDATE library_panel SET visibility='private' WHERE id=?1", lp);
        let r = ah4_reponse(library_panel_update(State(st.clone()), Extension(alice.clone()), Path(lp), Json(corps_maj())).await).await;
        ah4_sql(&st, "DROP TRIGGER ah4_refus;");
        let cid = ah4_juger_503("library_panel_update", &r, crate::handlers::dash_ergonomics::CAUSE_PANNEAU_DE_BIBLIOTHEQUE_INCHANGE, &e);
        ah4_attendue("lpu", format!("[dashboards] WARN modification du panneau de bibliothèque #{lp} NON prise, transaction annulée ({cid}) : visibility : {e}"));
        assert_eq!(ah4_texte(&st, &ligne_lp), "avant|shared", "lpu : le nom d'avant, toujours partagé");

        // Modification d'une liste : la bascule en privé refusée.
        eprintln!("{AH4_PHASE}plu");
        ah4_sql(&st, &format!("CREATE TRIGGER ah4_refus BEFORE UPDATE OF visibility ON playlist BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"));
        let e = ah4_cause_ecriture(&st, "UPDATE playlist SET visibility='private' WHERE id=?1", pl);
        let r = ah4_reponse(playlist_update(State(st.clone()), Extension(alice.clone()), Path(pl), Json(corps_maj())).await).await;
        ah4_sql(&st, "DROP TRIGGER ah4_refus;");
        let cid = ah4_juger_503("playlist_update", &r, crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_INCHANGEE, &e);
        ah4_attendue("plu", format!("[dashboards] WARN modification de la liste de lecture #{pl} NON prise, transaction annulée ({cid}) : visibility : {e}"));
        assert_eq!(ah4_texte(&st, &ligne_pl), "avant|shared", "plu : le nom d'avant, toujours partagée");

        // Suppression d'une liste refusée.
        eprintln!("{AH4_PHASE}pld");
        ah4_sql(&st, &format!("CREATE TRIGGER ah4_refus BEFORE DELETE ON playlist BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"));
        let e = ah4_cause_ecriture(&st, "DELETE FROM playlist WHERE id=?1", pl);
        let r = ah4_reponse(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(pl)).await).await;
        ah4_sql(&st, "DROP TRIGGER ah4_refus;");
        let cid = ah4_juger_503("playlist_delete", &r, crate::handlers::dash_ergonomics::CAUSE_LISTE_DE_LECTURE_NON_SUPPRIMEE, &e);
        ah4_attendue("pld", format!("[dashboards] WARN suppression de la liste de lecture #{pl} NON prise, transaction annulée ({cid}) : suppression de la liste : {e}"));
        assert_eq!(ah4_texte(&st, &ligne_pl), "avant|shared", "pld : la liste est toujours là");

        // Révocation d'un instantané refusée.
        eprintln!("{AH4_PHASE}snap");
        let sid = ah4_instantane(&st, "ah4-jeton-refuse");
        ah4_sql(&st, &format!("CREATE TRIGGER ah4_refus BEFORE DELETE ON dashboard_snapshot BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"));
        let e = ah4_cause_ecriture(&st, "DELETE FROM dashboard_snapshot WHERE id=?1", sid);
        let r = ah4_reponse(snapshot_delete(State(st.clone()), Extension(alice.clone()), Path(sid)).await).await;
        ah4_sql(&st, "DROP TRIGGER ah4_refus;");
        let cid = ah4_juger_503("snapshot_delete", &r, crate::handlers::dash_ergonomics::CAUSE_INSTANTANE_NON_SUPPRIME, &e);
        ah4_attendue("snap", format!("[dashboards] WARN révocation de l'instantané #{sid} NON prise, rien n'est supprimé ({cid}) : suppression de l'instantané : {e}"));
        assert_eq!(ah4_texte(&st, &format!("SELECT token FROM dashboard_snapshot WHERE id={sid}")), "ah4-jeton-refuse", "snap : toujours là");

        // Coût d'un panneau : refus, écriture sans ligne, écrit.
        let compte_cout = |id: i64| -> i64 {
            st.db.lock().query_row("SELECT COUNT(*) FROM panel_cost WHERE panel_id=?1", params![id], |r| r.get(0)).expect("compte des coûts")
        };
        let mesure = || Ok(Ok(json!({ "stats": { "elapsed_ms": 12.5 } })));
        eprintln!("{AH4_PHASE}cout-refus");
        ah4_sql(&st, &format!("CREATE TRIGGER ah4_cout BEFORE INSERT ON panel_cost BEGIN SELECT RAISE(ABORT, '{AH4_REFUS}'); END;"));
        record_panel_cost(&st.db.lock(), 4242, AH4_EMPREINTE, 12.5, now());
        consigner_l_issue_du_rafraichissement(&st.db, "default", 4243, "1h", AH4_EMPREINTE, now(), 0, 0, mesure());
        ah4_sql(&st, "DROP TRIGGER ah4_cout;");
        ah4_attendue("cout-refus", "[dashboards] WARN panneau #4242 : coût mesuré non écrit, le panneau garde sa classe d'avant".into());
        ah4_attendue("cout-refus", "[dashboards] WARN panneau #4243 : coût mesuré non écrit, le panneau garde sa classe d'avant".into());
        assert_eq!((compte_cout(4242), compte_cout(4243)), (0, 0), "cout-refus : rien n'est écrit");
        eprintln!("{AH4_PHASE}cout-ignore");
        ah4_sql(&st, "CREATE TRIGGER ah4_cout BEFORE INSERT ON panel_cost BEGIN SELECT RAISE(IGNORE); END;");
        record_panel_cost(&st.db.lock(), 4244, AH4_EMPREINTE, 12.5, now());
        ah4_sql(&st, "DROP TRIGGER ah4_cout;");
        ah4_attendue("cout-ignore", "[dashboards] WARN panneau #4244 : coût mesuré non écrit, le panneau garde sa classe d'avant".into());
        assert_eq!(compte_cout(4244), 0, "cout-ignore : aucune ligne");
        eprintln!("{AH4_PHASE}cout-ok");
        record_panel_cost(&st.db.lock(), 4245, AH4_EMPREINTE, 12.5, now());
        consigner_l_issue_du_rafraichissement(&st.db, "default", 4246, "1h", AH4_EMPREINTE, now(), 0, 0, mesure());
        assert_eq!((compte_cout(4245), compte_cout(4246)), (1, 1), "cout-ok : contrôle, le coût est écrit");

        // Nominal : chaque geste réussit, aucune ligne.
        eprintln!("{AH4_PHASE}calme");
        let sid2 = ah4_instantane(&st, "ah4-jeton-calme");
        let calme = [
            ah4_reponse(library_panel_update(State(st.clone()), Extension(alice.clone()), Path(lp), Json(corps_maj())).await).await.0,
            ah4_reponse(playlist_update(State(st.clone()), Extension(alice.clone()), Path(pl), Json(corps_maj())).await).await.0,
            ah4_reponse(snapshot_delete(State(st.clone()), Extension(alice.clone()), Path(sid2)).await).await.0,
            ah4_reponse(playlist_delete(State(st.clone()), Extension(alice.clone()), Path(pl)).await).await.0,
            ah4_reponse(library_panel_delete(State(st.clone()), Extension(alice.clone()), Path(lp)).await).await.0,
        ];
        assert_eq!(calme, [204, 204, 204, 204, 204], "calme : contrôle, les cinq gestes réussissent");
        eprintln!("{AH4_PHASE}fin");
    }

    /// CE QU'IL TIENT : voir l'en-tête (tableaux de bord). Corps jugés dans l'enfant, lignes jugées dans le parent.
    /// MUTATIONS : AH4_PORTE_CAUSE_EXPOSEE, AH4_LISTE_CAUSE_EXPOSEE, AH4_LPU_CAUSE_EXPOSEE, AH4_PLU_CAUSE_EXPOSEE,
    /// AH4_PLD_CAUSE_EXPOSEE, AH4_SNAP_CAUSE_EXPOSEE (corps avec la cause du moteur : l'enfant échoue),
    /// AH4_PORTE_SANS_JOURNAL, AH4_LISTE_SANS_JOURNAL, AH4_SNAP_SANS_JOURNAL, AH4_COUT_SANS_JOURNAL (ligne absente),
    /// AH4_COUT_OK0_ACCEPTE (phase cout-ignore : aucune ligne).
    #[tokio::test]
    async fn ah4_refus_des_tableaux_phrase_fixe_et_cause_au_journal_seul() {
        if std::env::var(AH4_ENFANT).is_ok() {
            ah4_enfant_des_tableaux().await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::passage_rate_des_connecteurs_et_refus_des_tableaux_sans_texte_du_moteur::ah4_refus_des_tableaux_phrase_fixe_et_cause_au_journal_seul",
            ])
            .env(AH4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (corps jugés) : {stdout}\n{stderr}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AH4_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AH4_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[dashboards] ")).map(str::to_string).collect()
        };
        let attendues = |nom: &str| -> Vec<String> {
            stdout
                .lines()
                .filter_map(|l| l.split_once(AH4_ATTENDUE).map(|(_, r)| r))
                .filter_map(|r| r.split_once('|'))
                .filter(|(p, _)| *p == nom)
                .map(|(_, l)| l.to_string())
                .collect()
        };
        let cas = [("porte", 4), ("liste", 2), ("lpu", 1), ("plu", 1), ("pld", 1), ("snap", 1), ("cout-refus", 2), ("cout-ignore", 1), ("cout-ok", 0), ("calme", 0)];
        assert!(cas.len() >= 10, "plancher : dix phases");
        for (nom, n) in cas {
            let a = attendues(nom);
            assert_eq!(a.len(), n, "contrôle : {n} ligne(s) attendue(s) en phase {nom} : {a:?}");
            assert!(a.iter().all(|l| !l.contains("(plume-e") || l.contains(") : ")), "contrôle : forme : {a:?}");
            assert_eq!(phase(nom), a, "phase {nom} : lignes [dashboards], en entier");
        }
        assert!(!stderr.contains(AH4_EMPREINTE), "l'empreinte de requête ne paraît dans aucune ligne : {stderr}");
    }
}
