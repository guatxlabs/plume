// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi » : restes de handlers/governance.rs, et handlers/index_policies.rs) et
// `P10.20-l` (sites de la famille dans handlers/index_policies.rs) — L'EXPORT DU REGISTRE NE SERT NI LE TEXTE DU MOTEUR NI
// LA CIBLE DU PUITS ; UNE POLITIQUE D'INDEX NON LUE N'EST PAS UNE ABSENCE.
//
// LE DÉFAUT, MESURÉ SUR 536bda8a AVANT LE CORRECTIF. Les cinq 500 de l'export du registre (`ledger_export_get`,
// `control_ledger_export_get` et son bras « lecture interrompue », `ledger_sink_flush` sur une tranche illisible puis sur
// une copie non écrite) servaient `<préfixe> : {e}` ; pour la copie non écrite, `{e}` est le texte de
// `ledger_sink_write`, qui porte le CHEMIN de la cible du puits (`répertoire cible <chemin> inaccessible: …`), servi à
// l'administrateur et recopié au journal par `err_json` (`[id] HTTP 500 : <message>`). `index_policy_update` et
// `index_policy_delete` lisaient le régime de purge par `match … { Ok(x) => x, Err(_) => not_found(…) }` : une lecture
// qui n'avait pas eu lieu (colonne qui ne se convertit pas, table retirée) se servait 404 « index introuvable » ; leurs
// écritures refusées (création, modification) rendaient `500 échec transaction audit (aucune modification): <moteur>`.
//
// LE CORRECTIF (décision par défaut de la vague AF). Statut 500 inchangé, phrase fixe par geste, préfixes d'avant gardés
// (`export du ledger impossible`, `export du journal de contrôle impossible`, `export vers le sink`), la cause au
// journal sous l'identifiant de corrélation servi ; pour la copie non écrite, le journal ne garde que le dernier segment
// du motif s'il a la forme d'une erreur du système, les refus à texte fixe, le début fixe des autres, tout le reste TU
// (`motif_de_l_ecriture_sans_cible`, liste blanche : une cible peut contenir « : »). Le curseur
// d'un puits n'avance toujours pas. Politiques d'index : trois issues, absente = 404 d'avant au corps près, lecture
// ratée = 503 nommé (`CAUSE_POLITIQUE_D_INDEX_INCHANGEE_NON_LUE`, `CAUSE_POLITIQUE_D_INDEX_NON_SUPPRIMEE_NON_LUE`), rien
// n'est écrit ni supprimé ; les deux 500 par `servir_l_echec_de_la_transaction_d_audit`.
//
// LES PANNES ÉPROUVÉES : un maillon du registre au `hash` en BLOB ; un plan de contrôle au chemin absent ; une tâche
// de lecture qui panique ; un puits `file` dont le répertoire cible n'existe pas (dans la racine d'export posée par le
// témoin) ; `name`/`managed` d'une politique en BLOB et la table retirée ; un déclencheur `RAISE(ABORT)` sur
// `BEFORE INSERT ON ledger` ; les lignes de journal lues sur le stderr d'un sous-processus, comparées ENTIÈRES.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AF2_<S>_MOTEUR_SERVI` et `AF2_<S>_SANS_JOURNAL`
// pour `EXPORT`, `CONTROLE`, `INTERROMPU`, `TRANCHE`, `COPIE` ; `AF2_COPIE_CIBLE_AU_JOURNAL`, `AF2_COPIE_CURSEUR_AVANCE` ;
// `AF2_MOTIF_SEGMENT_VIDE`, `AF2_MOTIF_SANS_BARRE`, `AF2_MOTIF_SANS_NOM`, `AF2_MOTIF_NOM_VIDE_TU` (première passe), puis
// `AF2_MOTIF_PREMIER`, `AF2_MOTIF_TOUT_SEGMENT`, `AF2_MOTIF_SANS_TEXTE_FIXE`, `AF2_MOTIF_SANS_DEBUT_FIXE`,
// `AF2_MOTIF_DEBUT_ENTIER`, `AF2_MOTIF_SANS_CIBLE_CONTENANTE`, `AF2_MOTIF_BARRE_ADMISE` (liste blanche) ; par lecture
// (`MODIF`, `RETRAIT`) `AF2_<L>_LECTURE_EN_404`, `AF2_<L>_ABSENT_EN_503`, `AF2_<L>_CAUSE_EXPOSEE`,
// `AF2_<L>_LECTURE_FAIT_LE_GESTE`, `AF2_<L>_SANS_JOURNAL`, `AF2_<L>_403_SAUTE` ; `AF2_CREATION_MOTEUR_SERVI`,
// `AF2_CREATION_SANS_JOURNAL`, `AF2_MODIF_ECRITURE_MOTEUR_SERVI`, `AF2_MODIF_ECRITURE_SANS_JOURNAL`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun écran de la console n'appelle les routes d'export (aucun module de web/ ne
// cite `ledger/export`, `control-ledger` ni `ledger-sinks`) ; l'écran des index (web/index_policies.js) peint ces refus
// par `peindreLeRefusDUnGeste` en « refus nommé » avec la phrase entière — lu, non exécuté ; une lecture ratée par verrou
// n'est pas jouée ; le motif d'écriture d'un puits est une liste blanche : un texte futur de `ledger_sink_write` hors
// liste sera TU (jamais servi), et une cible dont un morceau a lui-même la forme `<texte> (os error <n>)` placé APRÈS le
// dernier « : » d'un texte passerait s'il n'est pas contenu tel quel dans la cible — aucun texte d'aujourd'hui ne finit
// par la cible ;
// `index_policy_create` lit encore son doublon par `.is_ok()` (hors lot).
// =====================================================================================
mod registre_et_politiques_d_index_texte_du_moteur_et_lecture_ratee {
    use super::*;

    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée.
    const AF2_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AF2)";
    const AF2_ABSENT: i64 = 987_654;
    /// Le répertoire absent de la cible d'un puits : il ne doit paraître ni dans un corps ni dans le journal.
    const AF2_SOUS_DOSSIER: &str = "af2-sous-dossier-absent";
    const AF2_COPIE: &str = "copie-af2.jsonl";

    fn af2_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn af2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn af2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn af2_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn af2_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucun des fragments interdits.
    fn af2_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str, interdits: &[&str]) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        for f in interdits {
            assert!(!corps.contains(f), "{quoi} : `{f}` ne sort pas : {corps}");
        }
    }

    /// Un maillon ajouté puis rendu illisible (son `hash` en BLOB) : la tranche depuis zéro ne se lit plus. Rend la cause
    /// du moteur telle que la lecture de la tranche l'écrit.
    fn af2_registre_illisible(st: &AppState, limite: i64) -> String {
        let c = st.db.lock();
        ledger_append(&c, "config.af2", "maillon af2");
        let premier: i64 = c.query_row("SELECT MIN(id) FROM ledger", [], |r| r.get(0)).expect("fixture : premier maillon");
        assert_eq!(c.execute("UPDATE ledger SET hash=X'FF' WHERE id=?1", params![premier]).expect("maillon abîmé"), 1);
        crate::governance::ledger_export_lines(&c, 0, limite).expect_err("fixture : la tranche ne se lit plus")
    }

    async fn af2_telecharger(st: &AppState) -> (u16, String, Value) {
        af2_reponse(ledger_export_get(State(st.clone()), Extension(af2_adm()), Query(HashMap::new())).await).await
    }

    async fn af2_telecharger_le_controle(st: &AppState) -> (u16, String, Value) {
        af2_reponse(control_ledger_export_get(State(st.clone()), Extension(af2_adm()), Query(HashMap::new())).await).await
    }

    async fn af2_envoyer(st: &AppState, id: i64) -> (u16, String, Value) {
        af2_reponse(ledger_sink_flush(State(st.clone()), Extension(af2_adm()), Path(id)).await).await
    }

    fn af2_puits(st: &AppState, nom: &str, kind: &str, cible: &str) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO ledger_sink(name,kind,target,enabled,last_id,last_hash) VALUES(?1,?2,?3,1,0,'')",
            params![nom, kind, cible],
        )
        .expect("fixture : puits déclaré");
        c.last_insert_rowid()
    }

    /// Un plan de contrôle dont le fichier n'existe pas : son ouverture en lecture échoue. Rend (état, chemin, cause).
    fn af2_plan_de_controle_absent(racine: &std::path::Path) -> (AppState, String, String) {
        let chemin = racine.join("plume-control-af2.db").to_string_lossy().into_owned();
        let conn = Connection::open_in_memory().expect("écrivain du plan de contrôle");
        migrate_control(&conn);
        let cp = ControlPlane { conn: Arc::new(Mutex::new(conn)), db_path: Arc::new(chemin.clone()) };
        let st = tenant_test_state("af2-adm", "af2-edi", "af2-sa", Some(cp));
        let cause = crate::state::lecture_validee_du_plan_de_controle(&chemin, None).err().expect("fixture : ouverture refusée");
        (st, chemin, cause)
    }

    /// Une lecture du plan de contrôle qui panique : l'erreur de tâche que la route recevrait.
    async fn af2_lecture_interrompue() -> tokio::task::JoinError {
        tokio::task::spawn_blocking(|| -> Result<(Vec<String>, i64, String), String> { panic!("af2 lecture interrompue") })
            .await
            .expect_err("fixture : la tâche panique")
    }

    async fn af2_creer_une_politique(st: &AppState, nom: &str) -> (u16, String, Value) {
        af2_reponse(index_policy_create(State(st.clone()), Extension(af2_adm()), Json(json!({ "name": nom, "retention_days": 30 }))).await).await
    }

    async fn af2_modifier(st: &AppState, qui: AuthUser, id: i64) -> (u16, String, Value) {
        af2_reponse(index_policy_update(State(st.clone()), Extension(qui), Path(id), Json(json!({ "retention_days": 90, "max_rows": 5 }))).await).await
    }

    async fn af2_supprimer(st: &AppState, qui: AuthUser, id: i64) -> (u16, String, Value) {
        af2_reponse(index_policy_delete(State(st.clone()), Extension(qui), Path(id)).await).await
    }

    async fn af2_politique(st: &AppState, nom: &str) -> i64 {
        let (statut, corps, v) = af2_creer_une_politique(st, nom).await;
        assert_eq!(statut, 200, "fixture : la politique se crée : {corps}");
        v["id"].as_i64().expect("identifiant de la politique")
    }

    /// La ligne entière d'une politique, relue après chaque appel (les colonnes qu'un geste écrirait).
    fn af2_ligne(st: &AppState, table: &str, id: i64) -> String {
        af2_texte(
            st,
            &format!(
                "SELECT quote(name)||'|'||quote(retention_days)||'|'||quote(max_rows)||'|'||quote(max_bytes)||'|'||quote(description)||'|'||quote(enabled)||'|'||quote(managed)||'|'||quote(updated)||'|'||quote(updated_by) FROM {table} WHERE id={id}"
            ),
        )
    }

    fn af2_registre_refuse(st: &AppState) {
        af2_sql(st, &format!("CREATE TRIGGER af2_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AF2_MOTEUR_ECRITURE}'); END;"));
    }

    fn af2_registre_rendu(st: &AppState) {
        af2_sql(st, "DROP TRIGGER af2_ledger_refuse;");
    }

    /// CE QU'IL TIENT (le motif d'une écriture de copie, au journal — liste blanche) : un refus à texte fixe passe tel quel
    /// (les cinq de `REFUS_PUITS_A_TEXTE_FIXE`, dont les deux « (FIFO/device/…) » à barre, qui ne portent pas la cible) ; un
    /// refus de la base vivante ou hors de la racine rend son début fixe seul ; sinon le segment après le DERNIER « : »
    /// passe s'il a la forme d'une erreur du système, même quand la cible contient « : » ; un texte qui finit par un
    /// morceau de la cible (sans forme d'erreur du système, ou contenu dans la cible, ou portant son nom de fichier, ou à
    /// barre) est TU ; jamais un fragment de la cible au journal.
    /// MUTATIONS : `AF2_MOTIF_PREMIER` (premier « : » au lieu du dernier), `AF2_MOTIF_TOUT_SEGMENT` (la forme d'avant :
    /// dernier segment sans liste blanche), `AF2_MOTIF_SANS_TEXTE_FIXE`, `AF2_MOTIF_SANS_DEBUT_FIXE`,
    /// `AF2_MOTIF_DEBUT_ENTIER`, `AF2_MOTIF_SANS_CIBLE_CONTENANTE`, `AF2_MOTIF_SANS_NOM`, `AF2_MOTIF_BARRE_ADMISE`.
    #[test]
    fn af2_le_motif_d_une_ecriture_de_copie_tait_la_cible() {
        const CIBLE_A_DEUX_POINTS: &str = "/srv/af2/sous: dossier/copie.jsonl";
        let base_vivante = format!("{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : le nom plume.db est celui d'un fichier de base ; nommer la cible autrement");
        let base_vivante_a_deux_points =
            format!("{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : le répertoire /srv/af2/sous: dossier est celui de la base ; poser la racine d'export ailleurs");
        let hors_racine = format!("{REFUS_PUITS_HORS_DE_LA_RACINE} /srv/af2: racine");
        let mut cas: Vec<(&str, &str, &str)> = vec![
            ("ouverture /srv/af2/copie-af2.jsonl: Permission denied (os error 13)", "copie-af2.jsonl", "Permission denied (os error 13)"),
            // La cible contient « : » : seul le DERNIER segment est l'erreur du système.
            (
                "répertoire cible /srv/af2/sous: dossier inaccessible: No such file or directory (os error 2)",
                CIBLE_A_DEUX_POINTS,
                "No such file or directory (os error 2)",
            ),
            ("écriture /srv/af2/sous: dossier/copie.jsonl: Broken pipe (os error 32)", CIBLE_A_DEUX_POINTS, "Broken pipe (os error 32)"),
            ("Broken pipe (os error 32)", "", "Broken pipe (os error 32)"),
            // Le morceau de la cible en DERNIÈRE position : jamais gardé.
            ("répertoire cible /srv/af2/sous: dossier inaccessible", CIBLE_A_DEUX_POINTS, MOTIF_TU_IL_PEUT_PORTER_LA_CIBLE),
            ("ouverture /srv/af2/x: Faux (os error 1)", "/srv/af2/x: Faux (os error 1)/copie.jsonl", MOTIF_TU_IL_PEUT_PORTER_LA_CIBLE),
            ("stat /srv/af2/c.jsonl: c.jsonl Permission denied (os error 13)", "c.jsonl", MOTIF_TU_IL_PEUT_PORTER_LA_CIBLE),
            ("stat x: sous/dossier (os error 2)", "c.jsonl", MOTIF_TU_IL_PEUT_PORTER_LA_CIBLE),
            ("lecture interrompue", "copie-af2.jsonl", MOTIF_TU_IL_PEUT_PORTER_LA_CIBLE),
            // Débuts fixes : la suite (un répertoire, parfois à « : ») ne part pas.
            (base_vivante.as_str(), "sous/plume.db", REFUS_PUITS_SUR_LA_BASE_VIVANTE),
            (base_vivante_a_deux_points.as_str(), CIBLE_A_DEUX_POINTS, REFUS_PUITS_SUR_LA_BASE_VIVANTE),
            (hors_racine.as_str(), "../evade.jsonl", REFUS_PUITS_HORS_DE_LA_RACINE),
        ];
        for fixe in REFUS_PUITS_A_TEXTE_FIXE {
            cas.push((fixe, CIBLE_A_DEUX_POINTS, fixe));
        }
        assert!(cas.len() >= 17, "plancher : les douze cas et les cinq refus à texte fixe");
        assert!(
            REFUS_PUITS_A_TEXTE_FIXE.contains(&"target: non-fichier-régulier refusé (FIFO/device/socket)")
                && REFUS_PUITS_A_TEXTE_FIXE.contains(&"target: non-fichier-régulier refusé (FIFO/device/répertoire)"),
            "les deux refus à barre sont reconnus fixes"
        );
        for (e, cible, attendu) in cas {
            let motif = motif_de_l_ecriture_sans_cible(e, cible);
            assert_eq!(motif, attendu, "motif de `{e}` pour la cible `{cible}`");
            for morceau in ["sous", "dossier", "copie", "srv", "Faux", "evade", "plume.db"] {
                assert!(!(motif.contains(morceau) && cible.contains(morceau)), "un morceau de la cible (`{morceau}`) part au journal : `{motif}`");
            }
        }
    }

    /// CE QU'IL TIENT (téléchargement du registre) : une tranche lisible rend `200` ; un maillon illisible rend `500` dont
    /// le corps est EXACTEMENT `{error: PHRASE_EXPORT_DU_REGISTRE_NON_LU, id}` (préfixe d'avant gardé), sans la cause du
    /// moteur. MUTATION : `AF2_EXPORT_MOTEUR_SERVI` (la forme d'avant).
    #[tokio::test]
    async fn af2_telechargement_du_registre_illisible_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af2-export");
        let (statut, corps, _) = af2_telecharger(&st).await;
        assert_eq!(statut, 200, "contrôle : la tranche lisible se télécharge : {corps}");
        let moteur = af2_registre_illisible(&st, 10_000);
        let r = af2_telecharger(&st).await;
        af2_juger_5xx("registre illisible", &r, 500, PHRASE_EXPORT_DU_REGISTRE_NON_LU, &[moteur.as_str(), "Blob", "ILLISIBLE"]);
        assert!(PHRASE_EXPORT_DU_REGISTRE_NON_LU.starts_with("export du ledger impossible : "), "le préfixe d'avant est gardé");
    }

    /// CE QU'IL TIENT (téléchargement du journal de contrôle) : un plan de contrôle qui ne s'ouvre pas rend `500`
    /// EXACTEMENT `{error: PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_NON_LU, id}`, sans la cause ni le chemin, et le fichier
    /// n'est pas créé ; une lecture interrompue (tâche paniquée), passée à `issue_de_la_lecture_du_plan_de_controle` que
    /// la route appelle, rend `500` EXACTEMENT `{error: PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_INTERROMPU, id}`, sans le texte
    /// de la tâche ; une tranche lue passe telle quelle. MUTATIONS : `AF2_CONTROLE_MOTEUR_SERVI`,
    /// `AF2_INTERROMPU_MOTEUR_SERVI`.
    #[tokio::test]
    async fn af2_telechargement_du_journal_de_controle_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // la route lit la clé du plan de contrôle dans l'environnement
        let racine = crate::tmp_possede::TmpPossede::neuf("af2-controle");
        let (st, chemin, cause) = af2_plan_de_controle_absent(&racine);
        let r = af2_telecharger_le_controle(&st).await;
        af2_juger_5xx("plan de contrôle absent", &r, 500, PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_NON_LU, &[cause.as_str(), "CannotOpen", chemin.as_str()]);
        assert!(!std::path::Path::new(&chemin).exists(), "le fichier du plan de contrôle n'est pas créé");

        let je = af2_lecture_interrompue().await;
        let texte = je.to_string();
        let refus = issue_de_la_lecture_du_plan_de_controle(Err(je)).err().expect("une lecture interrompue est un refus");
        let r = af2_reponse(refus).await;
        af2_juger_5xx("lecture interrompue", &r, 500, PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_INTERROMPU, &[texte.as_str(), "panicked", "af2 lecture"]);

        let lue = (vec!["l".to_string()], 7, "h".to_string());
        assert_eq!(issue_de_la_lecture_du_plan_de_controle(Ok(Ok(lue.clone()))).ok(), Some(lue), "une tranche lue passe telle quelle");
        assert!(
            PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_NON_LU.starts_with("export du journal de contrôle impossible : ")
                && PHRASE_EXPORT_DU_JOURNAL_DE_CONTROLE_INTERROMPU.starts_with("export du journal de contrôle impossible : lecture interrompue"),
            "les préfixes d'avant sont gardés"
        );
    }

    /// CE QU'IL TIENT (envoi vers un puits, tranche illisible) : `500` EXACTEMENT `{error:
    /// PHRASE_ENVOI_DU_PUITS_TRANCHE_NON_LUE, id}`, ni la cause du moteur ni le nom du puits ; le curseur reste à zéro, la
    /// transaction du garde est fermée. MUTATION : `AF2_TRANCHE_MOTEUR_SERVI`.
    #[tokio::test]
    async fn af2_envoi_tranche_illisible_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af2-tranche");
        let id = af2_puits(&st, "puits-af2-tranche", "stdout", "");
        let moteur = af2_registre_illisible(&st, 100_000);
        let r = af2_envoyer(&st, id).await;
        af2_juger_5xx("tranche illisible", &r, 500, PHRASE_ENVOI_DU_PUITS_TRANCHE_NON_LUE, &[moteur.as_str(), "Blob", "puits-af2-tranche"]);
        assert_eq!(af2_compte(&st, &format!("SELECT last_id FROM ledger_sink WHERE id={id}")), 0, "le curseur ne bouge pas");
        assert!(st.db.lock().is_autocommit(), "la transaction du garde est fermée");
        assert!(PHRASE_ENVOI_DU_PUITS_TRANCHE_NON_LUE.starts_with("export vers le sink impossible : "), "le préfixe d'avant est gardé");
    }

    /// CE QU'IL TIENT (envoi vers un puits `file` dont le répertoire cible n'existe pas, dans la racine d'export) : `500`
    /// EXACTEMENT `{error: PHRASE_ENVOI_DU_PUITS_COPIE_NON_ECRITE, id}` — ni le répertoire, ni le fichier, ni la racine, ni
    /// l'erreur du système, ni le nom du puits ; le curseur reste à zéro (invariant d'avant), la transaction est fermée.
    /// Contrôle : le répertoire créé, l'envoi exporte et le curseur avance.
    /// MUTATIONS : `AF2_COPIE_MOTEUR_SERVI` (la forme d'avant), `AF2_COPIE_CURSEUR_AVANCE` (le garde validé avant le refus).
    #[tokio::test]
    async fn af2_envoi_copie_non_ecrite_sans_la_cible_du_puits() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        let racine = crate::tmp_possede::TmpPossede::neuf("af2-copie");
        let _pose = ReglageBackupPose::neuf("PLUME_LEDGER_EXPORT_DIR", &racine.to_string_lossy());
        let (st, _p) = sp_state("af2-copie");
        ledger_append(&st.db.lock(), "config.af2", "maillon af2 a copier");
        let cible = racine.join(AF2_SOUS_DOSSIER).join(AF2_COPIE);
        let id = af2_puits(&st, "puits-af2-copie", "file", &cible.to_string_lossy());
        let r = af2_envoyer(&st, id).await;
        let racine_texte = racine.to_string_lossy().into_owned();
        af2_juger_5xx(
            "copie non écrite",
            &r,
            500,
            PHRASE_ENVOI_DU_PUITS_COPIE_NON_ECRITE,
            &[AF2_SOUS_DOSSIER, AF2_COPIE, racine_texte.as_str(), "No such file", "puits-af2-copie"],
        );
        assert_eq!(af2_compte(&st, &format!("SELECT last_id FROM ledger_sink WHERE id={id}")), 0, "le curseur n'avance pas");
        assert!(st.db.lock().is_autocommit(), "la transaction du garde est fermée");
        assert!(PHRASE_ENVOI_DU_PUITS_COPIE_NON_ECRITE.starts_with("export vers le sink impossible : "), "le préfixe d'avant est gardé");

        std::fs::create_dir_all(racine.join(AF2_SOUS_DOSSIER)).expect("fixture : répertoire cible");
        let (statut, corps, v) = af2_envoyer(&st, id).await;
        assert_eq!(statut, 200, "contrôle : le répertoire présent, l'envoi exporte : {corps}");
        assert!(v["exported"].as_i64().is_some_and(|n| n >= 1), "{corps}");
        assert!(af2_compte(&st, &format!("SELECT last_id FROM ledger_sink WHERE id={id}")) >= 1, "contrôle : le curseur avance");
    }

    /// CE QU'IL TIENT (modification d'une politique d'index) : absente, `404 {"error": "index introuvable"}` exactement ;
    /// un éditeur, `403` texte d'avant, rien d'écrit ; `name` illisible puis table retirée, `503` nommé
    /// `CAUSE_POLITIQUE_D_INDEX_INCHANGEE_NON_LUE` en entier, sans la cause du moteur — jamais `404` ; la ligne relue est
    /// identique, aucune modification attestée, la transaction est fermée. Contrôle : une politique lisible se modifie.
    /// MUTATIONS : `AF2_MODIF_LECTURE_EN_404`, `AF2_MODIF_ABSENT_EN_503`, `AF2_MODIF_CAUSE_EXPOSEE`,
    /// `AF2_MODIF_LECTURE_FAIT_LE_GESTE`, `AF2_MODIF_403_SAUTE`.
    #[tokio::test]
    async fn af2_modification_d_une_politique_lecture_ratee_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af2-modif");
        let (statut, corps, v) = af2_modifier(&st, af2_adm(), AF2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "index introuvable" }), "l'absence, rien d'autre : {corps}");

        let lisible = af2_politique(&st, "af2-modif-lisible").await;
        let avant = af2_ligne(&st, "index_policy", lisible);
        let (statut, corps, _) = af2_modifier(&st, sp_au("alice", "editor"), lisible).await;
        assert_eq!((statut, corps.as_str()), (403, "réservé à l'administrateur"), "un éditeur : le 403 d'avant");
        assert_eq!(af2_ligne(&st, "index_policy", lisible), avant, "un éditeur n'écrit rien");

        let id = af2_politique(&st, "af2-modif-illisible").await;
        af2_sql(&st, &format!("UPDATE index_policy SET name=X'00' WHERE id={id}"));
        let avant = af2_ligne(&st, "index_policy", id);
        let r = af2_modifier(&st, af2_adm(), id).await;
        af2_juger_5xx("politique illisible", &r, 503, CAUSE_POLITIQUE_D_INDEX_INCHANGEE_NON_LUE, &["Invalid column type", "Blob"]);
        assert_eq!(af2_ligne(&st, "index_policy", id), avant, "la politique illisible n'est pas écrite (ligne relue entière)");
        assert_eq!(af2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='config.index_policy.update'"), 0, "aucune modification attestée");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, v) = af2_modifier(&st, af2_adm(), lisible).await;
        assert_eq!(statut, 200, "contrôle : une politique lisible se modifie : {corps}");
        assert_eq!(v["retention_days"], json!(90), "{corps}");

        af2_sql(&st, "ALTER TABLE index_policy RENAME TO index_policy_af2_retiree;");
        let avant = af2_ligne(&st, "index_policy_af2_retiree", id);
        let r = af2_modifier(&st, af2_adm(), id).await;
        af2_juger_5xx("table des politiques retirée", &r, 503, CAUSE_POLITIQUE_D_INDEX_INCHANGEE_NON_LUE, &["no such table"]);
        assert_eq!(af2_ligne(&st, "index_policy_af2_retiree", id), avant, "rien n'est écrit");
    }

    /// CE QU'IL TIENT (suppression d'une politique d'index) : absente, `404 {"error": "index introuvable"}` exactement ; un
    /// éditeur, `403` texte d'avant, rien de supprimé ; `managed` illisible puis table retirée, `503` nommé
    /// `CAUSE_POLITIQUE_D_INDEX_NON_SUPPRIMEE_NON_LUE` en entier, sans la cause du moteur ; la politique reste là (ligne
    /// relue entière), aucun retrait attesté, transaction fermée. Contrôle : une politique lisible se supprime.
    /// MUTATIONS : `AF2_RETRAIT_LECTURE_EN_404`, `AF2_RETRAIT_ABSENT_EN_503`, `AF2_RETRAIT_CAUSE_EXPOSEE`,
    /// `AF2_RETRAIT_LECTURE_FAIT_LE_GESTE`, `AF2_RETRAIT_403_SAUTE`.
    #[tokio::test]
    async fn af2_suppression_d_une_politique_lecture_ratee_jamais_404_et_rien_n_est_supprime() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af2-retrait");
        let (statut, corps, v) = af2_supprimer(&st, af2_adm(), AF2_ABSENT).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v, json!({ "error": "index introuvable" }), "l'absence, rien d'autre : {corps}");

        let lisible = af2_politique(&st, "af2-retrait-lisible").await;
        let avant = af2_ligne(&st, "index_policy", lisible);
        let (statut, corps, _) = af2_supprimer(&st, sp_au("alice", "editor"), lisible).await;
        assert_eq!((statut, corps.as_str()), (403, "réservé à l'administrateur"), "un éditeur : le 403 d'avant");
        assert_eq!(af2_ligne(&st, "index_policy", lisible), avant, "un éditeur ne supprime rien");

        let id = af2_politique(&st, "af2-retrait-illisible").await;
        af2_sql(&st, &format!("UPDATE index_policy SET managed=X'00' WHERE id={id}"));
        let avant = af2_ligne(&st, "index_policy", id);
        let r = af2_supprimer(&st, af2_adm(), id).await;
        af2_juger_5xx("politique illisible", &r, 503, CAUSE_POLITIQUE_D_INDEX_NON_SUPPRIMEE_NON_LUE, &["Invalid column type", "Blob"]);
        assert_eq!(af2_ligne(&st, "index_policy", id), avant, "la politique illisible reste là (ligne relue entière)");
        assert_eq!(af2_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind IN ('config.index_policy.delete','config.index_policy.disable')"), 0, "aucun retrait attesté");
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");

        let (statut, corps, _) = af2_supprimer(&st, af2_adm(), lisible).await;
        assert_eq!(statut, 200, "contrôle : une politique lisible se supprime : {corps}");
        assert_eq!(af2_compte(&st, &format!("SELECT COUNT(*) FROM index_policy WHERE id={lisible}")), 0, "contrôle : elle est supprimée");

        af2_sql(&st, "ALTER TABLE index_policy RENAME TO index_policy_af2_retiree;");
        let avant = af2_ligne(&st, "index_policy_af2_retiree", id);
        let r = af2_supprimer(&st, af2_adm(), id).await;
        af2_juger_5xx("table des politiques retirée", &r, 503, CAUSE_POLITIQUE_D_INDEX_NON_SUPPRIMEE_NON_LUE, &["no such table"]);
        assert_eq!(af2_ligne(&st, "index_policy_af2_retiree", id), avant, "rien n'est supprimé");
    }

    /// CE QU'IL TIENT (les deux 500 d'écriture des politiques d'index) : la trace d'audit refusée, la création et la
    /// modification rendent `500` EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}` — sans la phrase du moteur ;
    /// aucune politique de plus, la politique modifiée est inchangée (ligne relue entière), la transaction est fermée.
    /// MUTATIONS : `AF2_CREATION_MOTEUR_SERVI`, `AF2_MODIF_ECRITURE_MOTEUR_SERVI`.
    #[tokio::test]
    async fn af2_ecriture_refusee_d_une_politique_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("af2-ecritures");
        let id = af2_politique(&st, "af2-ecriture-a-modifier").await;
        let avant = af2_ligne(&st, "index_policy", id);
        af2_registre_refuse(&st);
        let cas = [("création", af2_creer_une_politique(&st, "af2-ecriture-refusee").await), ("modification", af2_modifier(&st, af2_adm(), id).await)];
        assert!(cas.len() >= 2, "plancher : les deux sites");
        for (quoi, r) in &cas {
            af2_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT, &[AF2_MOTEUR_ECRITURE, "hors d atteinte"]);
        }
        af2_registre_rendu(&st);
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        assert_eq!(af2_compte(&st, "SELECT COUNT(*) FROM index_policy"), 1, "aucune politique de plus");
        assert_eq!(af2_ligne(&st, "index_policy", id), avant, "la politique modifiée est inchangée");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées ENTIÈRES (identifiant de corrélation
    /// servi compris) : chaque export refusé (cinq sites), chaque lecture ratée d'une politique (deux) et chaque écriture
    /// refusée (deux) écrit UNE ligne ; jamais la cible du puits, nulle part dans le stderr ; le nominal et les absences
    /// n'en écrivent aucune. MUTATIONS : `AF2_<S>_SANS_JOURNAL` (`EXPORT`, `CONTROLE`, `INTERROMPU`, `TRANCHE`, `COPIE`),
    /// `AF2_COPIE_CIBLE_AU_JOURNAL`, `AF2_MODIF_SANS_JOURNAL`, `AF2_RETRAIT_SANS_JOURNAL`, `AF2_CREATION_SANS_JOURNAL`,
    /// `AF2_MODIF_ECRITURE_SANS_JOURNAL`.
    #[tokio::test]
    async fn af2_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AF2_ENFANT_JOURNAL";
        const PHASE: &str = "AF2-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            let racine = crate::tmp_possede::TmpPossede::neuf("af2-journal");
            let _pose = ReglageBackupPose::neuf("PLUME_LEDGER_EXPORT_DIR", &racine.to_string_lossy());
            let id_de = |r: &(u16, String, Value)| format!("{}:{}", r.0, r.2["id"].as_str().unwrap_or(""));

            let (st, _p) = sp_state("af2-journal-export");
            let moteur = af2_registre_illisible(&st, 10_000);
            eprintln!("{PHASE}export");
            println!("AF2-EXPORT:{}:{moteur}", id_de(&af2_telecharger(&st).await));

            let (stc, _chemin, cause) = af2_plan_de_controle_absent(&racine);
            eprintln!("{PHASE}controle");
            println!("AF2-CONTROLE:{}:{cause}", id_de(&af2_telecharger_le_controle(&stc).await));

            let je = af2_lecture_interrompue().await;
            let texte = je.to_string();
            eprintln!("{PHASE}interrompu");
            let r = af2_reponse(issue_de_la_lecture_du_plan_de_controle(Err(je)).err().expect("refus")).await;
            println!("AF2-INTERROMPU:{}:{texte}", id_de(&r));

            let (st, _p) = sp_state("af2-journal-tranche");
            let puits = af2_puits(&st, "puits-af2-journal-tranche", "stdout", "");
            let moteur = af2_registre_illisible(&st, 100_000);
            eprintln!("{PHASE}tranche");
            println!("AF2-TRANCHE:{}:{puits}:{moteur}", id_de(&af2_envoyer(&st, puits).await));

            let (st, _p) = sp_state("af2-journal-copie");
            ledger_append(&st.db.lock(), "config.af2", "maillon af2 a copier");
            let cible = racine.join(AF2_SOUS_DOSSIER).join(AF2_COPIE);
            let puits = af2_puits(&st, "puits-af2-journal-copie", "file", &cible.to_string_lossy());
            eprintln!("{PHASE}copie");
            println!("AF2-COPIE:{}:{puits}", id_de(&af2_envoyer(&st, puits).await));

            let (st, _p) = sp_state("af2-journal-index");
            let m = af2_politique(&st, "af2-journal-modif").await;
            af2_sql(&st, &format!("UPDATE index_policy SET name=X'00' WHERE id={m}"));
            eprintln!("{PHASE}idx-modif");
            println!("AF2-IDX-MODIF:{}:{m}", af2_modifier(&st, af2_adm(), m).await.0);
            let s = af2_politique(&st, "af2-journal-retrait").await;
            af2_sql(&st, &format!("UPDATE index_policy SET managed=X'00' WHERE id={s}"));
            eprintln!("{PHASE}idx-retrait");
            println!("AF2-IDX-RETRAIT:{}:{s}", af2_supprimer(&st, af2_adm(), s).await.0);
            let e = af2_politique(&st, "af2-journal-a-modifier").await;
            af2_registre_refuse(&st);
            eprintln!("{PHASE}idx-creation");
            println!("AF2-IDX-CREATION:{}", id_de(&af2_creer_une_politique(&st, "af2-journal-refusee").await));
            eprintln!("{PHASE}idx-ecriture");
            println!("AF2-IDX-ECRITURE:{}:{e}", id_de(&af2_modifier(&st, af2_adm(), e).await));
            af2_registre_rendu(&st);

            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("af2-journal-calme");
            ledger_append(&st.db.lock(), "config.af2", "maillon af2 calme");
            let puits = af2_puits(&st, "puits-af2-calme", "stdout", "");
            let p = af2_politique(&st, "af2-journal-calme").await;
            let calme = [
                af2_telecharger(&st).await.0,
                af2_envoyer(&st, puits).await.0,
                af2_envoyer(&st, AF2_ABSENT).await.0,
                af2_modifier(&st, af2_adm(), p).await.0,
                af2_modifier(&st, af2_adm(), AF2_ABSENT).await.0,
                af2_supprimer(&st, af2_adm(), p).await.0,
                af2_supprimer(&st, af2_adm(), AF2_ABSENT).await.0,
            ];
            println!("AF2-CALME:{}", calme.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::registre_et_politiques_d_index_texte_du_moteur_et_lecture_ratee::af2_lignes_de_journal_des_refus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // Le reste de la ligne qui suit un marqueur, coupé en `n` champs au plus (le dernier garde ses « : »).
        let marque = |m: &str, n: usize| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").splitn(n, ':').map(str::to_string).collect()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[gouvernance] ") || l.contains("[index-policies] ")).map(str::to_string).collect()
        };
        let export = marque("AF2-EXPORT:", 3);
        let controle = marque("AF2-CONTROLE:", 3);
        let interrompu = marque("AF2-INTERROMPU:", 3);
        let tranche = marque("AF2-TRANCHE:", 4);
        let copie = marque("AF2-COPIE:", 3);
        let creation = marque("AF2-IDX-CREATION:", 2);
        let ecriture = marque("AF2-IDX-ECRITURE:", 3);
        let statuts = [&export[0], &controle[0], &interrompu[0], &tranche[0], &copie[0], &creation[0], &ecriture[0]];
        assert_eq!(statuts.map(String::as_str), ["500"; 7], "contrôle : sept refus en 500");
        assert_eq!(marque("AF2-IDX-MODIF:", 2)[0], "503", "contrôle : lecture ratée de la modification");
        assert_eq!(marque("AF2-IDX-RETRAIT:", 2)[0], "503", "contrôle : lecture ratée de la suppression");
        assert_eq!(marque("AF2-CALME:", 8), ["200", "200", "404", "200", "404", "200", "404"], "contrôle : nominal et absences");
        let attendues = [
            ("export", format!("[{}] [gouvernance] WARN export du registre refusé : la tranche n'a pas été lue ({})", export[1], export[2])),
            (
                "controle",
                format!("[{}] [gouvernance] WARN export du journal de contrôle refusé : le plan de contrôle n'a pas été ouvert ou lu ({})", controle[1], controle[2]),
            ),
            ("interrompu", format!("[{}] [gouvernance] WARN export du journal de contrôle refusé : lecture interrompue ({})", interrompu[1], interrompu[2])),
            (
                "tranche",
                format!(
                    "[{}] [gouvernance] WARN envoi vers le puits du registre #{} NON fait : la tranche du registre n'a pas été lue, rien n'est écrit dans la copie, le curseur n'a pas avancé ({})",
                    tranche[1], tranche[2], tranche[3]
                ),
            ),
            (
                "copie",
                format!(
                    "[{}] [gouvernance] WARN envoi vers le puits du registre #{} NON fait : l'écriture de la copie a échoué (puits file), le curseur n'a pas avancé (No such file or directory (os error 2))",
                    copie[1], copie[2]
                ),
            ),
            (
                "idx-modif",
                format!(
                    "[index-policies] WARN politique d'index #{} NON lue pour la modification, rien n'est écrit : Invalid column type Blob at index: 0, name: name",
                    marque("AF2-IDX-MODIF:", 2)[1]
                ),
            ),
            (
                "idx-retrait",
                format!(
                    "[index-policies] WARN politique d'index #{} NON lue pour la suppression, rien n'est supprimé : Invalid column type Blob at index: 0, name: managed",
                    marque("AF2-IDX-RETRAIT:", 2)[1]
                ),
            ),
            (
                "idx-creation",
                format!(
                    "[{}] [index-policies] WARN création de la politique d'index 'af2-journal-refusee' refusé : transaction d'audit annulée, aucune modification ({AF2_MOTEUR_ECRITURE})",
                    creation[1]
                ),
            ),
            (
                "idx-ecriture",
                format!(
                    "[{}] [index-policies] WARN modification de la politique d'index #{} refusé : transaction d'audit annulée, aucune modification ({AF2_MOTEUR_ECRITURE})",
                    ecriture[1], ecriture[2]
                ),
            ),
        ];
        assert!(attendues.len() >= 9, "plancher : les neuf refus journalisés");
        for (nom, attendu) in &attendues {
            let lignes = phase(nom);
            assert_eq!(lignes, [attendu.clone()], "phase {nom} : une ligne, entière");
        }
        assert!(!stderr.contains(AF2_SOUS_DOSSIER) && !stderr.contains(AF2_COPIE), "la cible du puits n'entre nulle part dans le journal : {stderr}");
        assert!(phase("calme").is_empty(), "le nominal et les absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}
