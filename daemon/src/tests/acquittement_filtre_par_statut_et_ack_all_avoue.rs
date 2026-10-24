// =====================================================================================
// `P10.31-u` (restes de la vague AA : `ack` sur une alerte résolue ou déjà acquittée, `ack_all` qui expose la cause
// du moteur et jette son maillon, ligne de journal du 503 d'`ack` sans témoin) —
// L'ACQUITTEMENT N'ÉCRASE PLUS RIEN, ET L'ACQUITTEMENT EN MASSE NE SERT PLUS LA CAUSE DU MOTEUR NI NE JETTE SON MAILLON.
//
// LE DÉFAUT, MESURÉ SUR aa5556fd AVANT LE CORRECTIF. `POST /api/alerts/{id}/ack` posait
// `UPDATE alert SET status='ack', acked_at=?1, acked_by=?2 WHERE id=?3` sans filtre de statut (limite écrite dans la
// doc de `ack`) : une alerte `resolved` repassait `ack`, une alerte déjà acquittée voyait `acked_by`/`acked_at`
// ÉCRASÉS par l'analyste suivant, et un second `alert.ack` entrait au registre. `POST /api/alerts/ack-all` servait
// `<CAUSE_ACQUITTEMENT_NON_ENREGISTRE> (<cause du moteur>)` au client, et jetait son maillon (`ledger_append` nu).
//
// LE CORRECTIF (décision par défaut de la vague AB). `ack` : le filtre `AND status='new'` est DANS le `WHERE` ; sur
// zéro ligne, une lecture du statut sur la même connexion départage — absente -> 404 `CAUSE_ALERTE_INTROUVABLE`,
// présente -> 409 `CAUSE_ALERTE_NON_ACQUITTABLE (statut constaté : « s »)`, lecture ratée -> 503
// `CAUSE_STATUT_DE_L_ALERTE_NON_LU`, cause du moteur au journal seul. `ack_all` : le 503 sert la cause nommée seule,
// la cause du moteur va au journal ; un maillon manquant s'avoue (`registre_sans_maillon`) à côté du compte.
//
// LES PANNES ÉPROUVÉES : déclencheurs `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` et `BEFORE UPDATE ON alert` ; un
// statut stocké en BLOB (illisible comme texte) pour la lecture ratée ; les lignes de journal lues sur le stderr
// d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : `AB1_ACK_SANS_FILTRE`, `AB1_ACK_NON_NEW_EN_404`,
// `AB1_ACK_409_SANS_STATUT`, `AB1_ACK_STATUT_NON_BORNE`, `AB1_ACK_STATUT_BORNE_EN_OCTETS`, `AB1_ACK_STATUT_BORNE_LACHE`,
// `AB1_ACK_LECTURE_RATEE_EN_404`, `AB1_ACK_LECTURE_CAUSE_EXPOSEE`, `AB1_ACK_LECTURE_SANS_JOURNAL`, `AB1_ACK_SANS_JOURNAL`,
// `AB1_ACKALL_CAUSE_EXPOSEE`, `AB1_ACKALL_SANS_JOURNAL`, `AB1_ACKALL_MAILLON_JETE`, `AB1_ACKALL_AVEU_SANS_PANNE`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (web/alerts.js) lit le 409 comme un refus quelconque et, dans
// l'acquittement par liste, s'arrête au premier refus (les suivantes ne partent pas) ; elle n'affiche pas
// `registre_sans_maillon` sur `ack` ni sur `ack_all`. Une levée concurrente entre l'`UPDATE` et la lecture du statut
// n'est pas jouée (la connexion est tenue sous verrou pendant les deux).
// =====================================================================================
mod acquittement_filtre_par_statut_et_ack_all_avoue {
    use super::*;

    fn ab1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ab1-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ab1_utilisateur(nom: &str) -> AuthUser {
        AuthUser {
            name: nom.into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ab1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ab1_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    /// Pose une alerte au statut donné (littéral SQL : `'new'`, `'resolved'`, `X'00'`…), acquittement d'origine inclus.
    fn ab1_alerte(st: &AppState, statut_sql: &str, acked_at: Option<i64>, acked_by: Option<&str>) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            &format!("INSERT INTO alert(ts,rule,severity,title,status,acked_at,acked_by) VALUES(1000,'rule.ab1',2,'Alerte AB1',{statut_sql},?1,?2)"),
            params![acked_at, acked_by],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn ab1_etat_de_l_alerte(st: &AppState, id: i64) -> (String, Option<i64>, Option<String>) {
        st.db
            .lock()
            .query_row("SELECT CAST(status AS TEXT), acked_at, acked_by FROM alert WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    async fn ab1_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    async fn ab1_acquitter(st: &AppState, qui: &str, id: i64) -> (u16, String, Value) {
        ab1_reponse(ack(State(st.clone()), Extension(ab1_utilisateur(qui)), Path(id)).await).await
    }

    async fn ab1_acquitter_tout(st: &AppState) -> (u16, String, Value) {
        ab1_reponse(ack_all(State(st.clone()), Extension(ab1_utilisateur("analyste"))).await).await
    }

    const AB1_MAILLONS_ACK: &str = "SELECT COUNT(*) FROM ledger WHERE kind='alert.ack'";
    const AB1_MAILLONS_ACK_ALL: &str = "SELECT COUNT(*) FROM ledger WHERE kind='alert.ack_all'";
    const AB1_MOTEUR_ALERTE: &str = "alerte hors d atteinte (temoin AB1)";
    const AB1_MOTEUR_REGISTRE: &str = "registre hors d atteinte (temoin AB1)";
    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AB1_MOTEUR_LECTURE: &str = "Invalid column type";
    /// Instant d'un acquittement d'origine, fixe : un écrasement par `now()` s'y lit.
    const AB1_ACK_D_ORIGINE: i64 = 4242;

    fn ab1_registre_refuse(st: &AppState) {
        ab1_sql(st, &format!("CREATE TRIGGER ab1_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AB1_MOTEUR_REGISTRE}'); END;"));
    }

    fn ab1_alertes_refusees(st: &AppState) {
        ab1_sql(st, &format!("CREATE TRIGGER ab1_alerte_refuse BEFORE UPDATE ON alert BEGIN SELECT RAISE(ABORT, '{AB1_MOTEUR_ALERTE}'); END;"));
    }

    /// CE QU'IL TIENT : une alerte DÉJÀ acquittée par `analyste` puis acquittée par `second` rend `409`
    /// `CAUSE_ALERTE_NON_ACQUITTABLE (statut constaté : « ack »)` ; `acked_by` et `acked_at` d'origine restent ; le
    /// registre garde son seul maillon. Contrôle : le premier acquittement (alerte `new`) reste un `204`.
    /// MUTATIONS : `AB1_ACK_SANS_FILTRE` (l'écrasement revient, 204), `AB1_ACK_NON_NEW_EN_404` (servie « introuvable »),
    /// `AB1_ACK_409_SANS_STATUT` (le statut constaté n'est pas dit).
    #[tokio::test]
    async fn ab1_acquitter_une_alerte_deja_acquittee_rend_409_sans_rien_ecraser() {
        let (st, _tmp) = ab1_etat("deja-ack");
        let id = ab1_alerte(&st, "'new'", None, None);
        let (statut, corps, _) = ab1_acquitter(&st, "analyste", id).await;
        assert_eq!(statut, 204, "contrôle : une alerte nouvelle s'acquitte : {corps}");
        ab1_sql(&st, &format!("UPDATE alert SET acked_at={AB1_ACK_D_ORIGINE} WHERE id={id}"));
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK), 1, "contrôle : un maillon pour le premier acquittement");

        let (statut, corps, v) = ab1_acquitter(&st, "second", id).await;
        assert_eq!(statut, 409, "déjà acquittée : 409 nommé, ni 204 ni 404 : {corps}");
        let phrase = v["error"].as_str().unwrap_or_else(|| panic!("le 409 porte une phrase : {corps}"));
        assert_eq!(phrase, format!("{CAUSE_ALERTE_NON_ACQUITTABLE} (statut constaté : « ack »)"), "le 409 dit le statut constaté");
        assert_eq!(
            ab1_etat_de_l_alerte(&st, id),
            ("ack".to_string(), Some(AB1_ACK_D_ORIGINE), Some("analyste".to_string())),
            "l'attribution d'origine reste : ni auteur ni heure remplacés"
        );
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK), 1, "aucun second maillon : rien n'a été acquitté");
    }

    /// CE QU'IL TIENT : une alerte `resolved` (le statut que les sondes écrivent) et une alerte `closed` (le mot du
    /// schéma) ne repassent PAS `ack` : `409` qui dit leur statut, alerte intacte, rien au registre.
    /// MUTATIONS : `AB1_ACK_SANS_FILTRE`, `AB1_ACK_NON_NEW_EN_404`.
    #[tokio::test]
    async fn ab1_acquitter_une_alerte_resolue_ou_close_rend_409_et_la_laisse_intacte() {
        let (st, _tmp) = ab1_etat("resolue");
        for statut_alerte in ["resolved", "closed"] {
            let id = ab1_alerte(&st, &format!("'{statut_alerte}'"), None, None);
            let (statut, corps, v) = ab1_acquitter(&st, "second", id).await;
            assert_eq!(statut, 409, "{statut_alerte} : 409 nommé : {corps}");
            assert_eq!(v["error"], json!(format!("{CAUSE_ALERTE_NON_ACQUITTABLE} (statut constaté : « {statut_alerte} »)")), "{corps}");
            assert_eq!(ab1_etat_de_l_alerte(&st, id), (statut_alerte.to_string(), None, None), "{statut_alerte} : l'alerte garde son état");
        }
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK), 0, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : le statut constaté recopié dans le 409 est BORNÉ à 32 CARACTÈRES, pas à 32 octets : un statut
    /// long n'est pas recopié entier, et un statut multi-octet dont le 32e octet tombe au milieu d'un caractère
    /// (`a` puis quarante `é` : l'octet 32 est le second octet du 16e `é`) rend quand même le 409, coupé à
    /// exactement 32 caractères — une borne en octets paniquerait (500) ou couperait à 16 caractères.
    /// MUTATIONS : `AB1_ACK_STATUT_NON_BORNE` (recopié entier), `AB1_ACK_STATUT_BORNE_EN_OCTETS` (tranche
    /// `statut[..len.min(32)]` : panique sur la frontière de caractère), `AB1_ACK_STATUT_BORNE_LACHE` (33 caractères).
    #[tokio::test]
    async fn ab1_le_statut_constate_du_409_est_borne() {
        let (st, _tmp) = ab1_etat("borne");
        let long = format!("a{}", "é".repeat(40));
        assert!(!long.is_char_boundary(32), "fixture : l'octet 32 tombe au milieu d'un caractère");
        let id = ab1_alerte(&st, &format!("'{long}'"), None, None);
        let (statut, corps, v) = ab1_acquitter(&st, "second", id).await;
        assert_eq!(statut, 409, "statut multi-octet : 409 nommé, ni panique ni 500 : {corps}");
        let attendu: String = long.chars().take(32).collect();
        assert_eq!(attendu.chars().count(), 32, "fixture : la borne attendue compte 32 caractères");
        assert_eq!(v["error"], json!(format!("{CAUSE_ALERTE_NON_ACQUITTABLE} (statut constaté : « {attendu} »)")), "{corps}");
    }

    /// CE QU'IL TIENT : l'acquittement ne touche aucune ligne ET le statut ne se relit pas (stocké en BLOB) : `503`
    /// dont l'erreur est EXACTEMENT `CAUSE_STATUT_DE_L_ALERTE_NON_LU`, avec identifiant de corrélation, sans la
    /// cause du moteur ; jamais un 404 ; rien au registre. Contrôle : un identifiant absent reste un 404.
    /// MUTATIONS : `AB1_ACK_LECTURE_RATEE_EN_404`, `AB1_ACK_LECTURE_CAUSE_EXPOSEE`.
    #[tokio::test]
    async fn ab1_statut_illisible_apres_zero_ligne_rend_503_nomme_jamais_404() {
        let (st, _tmp) = ab1_etat("illisible");
        let (statut, corps, v) = ab1_acquitter(&st, "second", 987_654).await;
        assert_eq!(statut, 404, "contrôle : l'absence établie reste un 404 : {corps}");
        assert_eq!(v["error"], json!(CAUSE_ALERTE_INTROUVABLE), "{corps}");

        let id = ab1_alerte(&st, "X'00'", None, None);
        let (statut, corps, v) = ab1_acquitter(&st, "second", id).await;
        assert_eq!(statut, 503, "lecture ratée : 503 nommé, jamais 404 : {corps}");
        assert_eq!(v["error"], json!(CAUSE_STATUT_DE_L_ALERTE_NON_LU), "la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "le 5xx porte son identifiant de corrélation : {corps}");
        assert!(!corps.contains(AB1_MOTEUR_LECTURE) && !corps.contains("Blob"), "la cause du moteur ne sort pas : {corps}");
        assert_eq!(ab1_etat_de_l_alerte(&st, id).2, None, "rien n'est écrit");
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK), 0, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : `ack_all` sur une écriture refusée sert `503` dont l'erreur est EXACTEMENT
    /// `CAUSE_ACQUITTEMENT_NON_ENREGISTRE` (l'ouverture que la console lit, sans la cause du moteur), rien au
    /// registre. (L'état de la file n'est pas asserté : le déclencheur `RAISE(ABORT)` refuse toute écriture, quelle
    /// que soit l'implémentation — une telle assertion ne pourrait pas rougir.) MUTATION : `AB1_ACKALL_CAUSE_EXPOSEE` (l'ancien `<cause> (<moteur>)`).
    #[tokio::test]
    async fn ab1_acquittement_en_masse_refuse_ne_sert_pas_la_cause_du_moteur() {
        let (st, _tmp) = ab1_etat("ack-all-refus");
        ab1_alerte(&st, "'new'", None, None);
        ab1_alertes_refusees(&st);
        let (statut, corps, v) = ab1_acquitter_tout(&st).await;
        assert_eq!(statut, 503, "{corps}");
        assert_eq!(v["error"], json!(CAUSE_ACQUITTEMENT_NON_ENREGISTRE), "la phrase nommée, seule : {corps}");
        assert!(CAUSE_ACQUITTEMENT_NON_ENREGISTRE.starts_with("ACQUITTEMENT NON ENREGISTRÉ :"), "l'ouverture lue par la console est inchangée");
        assert!(!corps.contains("hors d atteinte"), "la cause du moteur ne sort pas : {corps}");
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK_ALL), 0, "rien n'est attesté");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, `ack_all` acquitte (pas d'annulation) et rend `200`
    /// `{"acked":2,"registre_sans_maillon":"<CAUSE_GESTE_SANS_TRACE> (<cause>)"}` ; contrôle : registre sain, le
    /// corps est EXACTEMENT `{"acked":n}` et un maillon entre. MUTATIONS : `AB1_ACKALL_MAILLON_JETE` (compte nu sur
    /// un maillon refusé), `AB1_ACKALL_AVEU_SANS_PANNE` (aveu servi au nominal).
    #[tokio::test]
    async fn ab1_acquittement_en_masse_sans_maillon_reste_fait_et_l_avoue() {
        let (st, _tmp) = ab1_etat("ack-all-maillon");
        ab1_alerte(&st, "'new'", None, None);
        let (statut, corps, v) = ab1_acquitter_tout(&st).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(v, json!({ "acked": 1 }), "contrôle : le nominal est le compte seul, sans aveu : {corps}");
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK_ALL), 1, "contrôle : le maillon nominal entre");

        ab1_alerte(&st, "'new'", None, None);
        ab1_alerte(&st, "'new'", None, None);
        ab1_registre_refuse(&st);
        let (statut, corps, v) = ab1_acquitter_tout(&st).await;
        assert_eq!(statut, 200, "geste fait sans trace : 200 qui l'avoue, jamais un 5xx : {corps}");
        assert_eq!(v["acked"], json!(2), "le compte reste servi : {corps}");
        let aveu = v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or_else(|| panic!("l'aveu est porté : {corps}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains(AB1_MOTEUR_REGISTRE), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert_eq!(ab1_compte(&st, "SELECT COUNT(*) FROM alert WHERE status='new'"), 0, "l'acquittement n'est pas annulé");
        assert_eq!(ab1_compte(&st, AB1_MAILLONS_ACK_ALL), 1, "fixture : aucun second maillon n'est entré");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : `ack_all` refusé écrit UNE ligne
    /// `[alert.ack_all] WARN acquittement en masse NON écrit : <moteur>` ; `ack` refusé écrit sa ligne
    /// `[alert.ack] WARN acquittement de l'alerte #<id> NON écrit : <moteur>` (vague AA, sans témoin jusqu'ici) ; la
    /// lecture ratée écrit `[alert.ack] WARN statut de l'alerte #<id> NON relu … : <moteur>` ; le 409 et le nominal
    /// n'écrivent AUCUNE ligne `[alert.ack…]`. MUTATIONS : `AB1_ACKALL_SANS_JOURNAL`, `AB1_ACK_SANS_JOURNAL`,
    /// `AB1_ACK_LECTURE_SANS_JOURNAL`.
    #[tokio::test]
    async fn ab1_lignes_de_journal_des_refus_d_acquittement() {
        const ENFANT: &str = "AB1_ENFANT_JOURNAL";
        const PHASE: &str = "AB1-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            eprintln!("{PHASE}masse");
            let (st, _tmp) = ab1_etat("journal-ack-all");
            ab1_alerte(&st, "'new'", None, None);
            ab1_alertes_refusees(&st);
            println!("AB1-STATUT-ACK-ALL:{}", ab1_acquitter_tout(&st).await.0);
            eprintln!("{PHASE}unitaire");
            let (st, _tmp) = ab1_etat("journal-ack");
            let id = ab1_alerte(&st, "'new'", None, None);
            ab1_alertes_refusees(&st);
            println!("AB1-STATUT-ACK:{}:{id}", ab1_acquitter(&st, "analyste", id).await.0);
            eprintln!("{PHASE}lecture");
            let (st, _tmp) = ab1_etat("journal-lecture");
            let id = ab1_alerte(&st, "X'00'", None, None);
            println!("AB1-STATUT-LECTURE:{}:{id}", ab1_acquitter(&st, "analyste", id).await.0);
            eprintln!("{PHASE}calme");
            let (st, _tmp) = ab1_etat("journal-calme");
            let id = ab1_alerte(&st, "'new'", None, None);
            let a = ab1_acquitter(&st, "analyste", id).await.0;
            let b = ab1_acquitter(&st, "second", id).await.0;
            let c = ab1_acquitter_tout(&st).await.0;
            println!("AB1-STATUT-CALME:{a}:{b}:{c}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::acquittement_filtre_par_statut_et_ack_all_avoue::ab1_lignes_de_journal_des_refus_d_acquittement",
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
        assert_eq!(marque("AB1-STATUT-ACK-ALL:"), ["503"], "contrôle : ack_all refusé");
        let ack = marque("AB1-STATUT-ACK:");
        assert_eq!(ack[0], "503", "contrôle : ack refusé : {ack:?}");
        let lecture = marque("AB1-STATUT-LECTURE:");
        assert_eq!(lecture[0], "503", "contrôle : lecture ratée : {lecture:?}");
        assert_eq!(marque("AB1-STATUT-CALME:"), ["204", "409", "200"], "contrôle : nominal, 409, file vide");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[alert.ack")).map(str::to_string).collect()
        };
        for (nom, attendu) in [
            ("masse", format!("[alert.ack_all] WARN acquittement en masse NON écrit : {AB1_MOTEUR_ALERTE}")),
            ("unitaire", format!("[alert.ack] WARN acquittement de l'alerte #{} NON écrit : {AB1_MOTEUR_ALERTE}", ack[1])),
        ] {
            let lignes = phase(nom);
            assert_eq!(lignes.len(), 1, "phase {nom} : une ligne et une seule : {lignes:?}");
            assert!(lignes[0].starts_with(&attendu), "phase {nom} : sujet et cause du moteur : {}", lignes[0]);
        }
        let lignes = phase("lecture");
        assert_eq!(lignes.len(), 1, "phase lecture : une ligne et une seule : {lignes:?}");
        let tete = format!("[alert.ack] WARN statut de l'alerte #{} NON relu après un acquittement sans ligne : ", lecture[1]);
        assert!(lignes[0].starts_with(&tete) && lignes[0].contains(AB1_MOTEUR_LECTURE), "phase lecture : sujet et cause du moteur : {}", lignes[0]);
        assert!(phase("calme").is_empty(), "le nominal, le 409 et la file vide n'écrivent aucune ligne [alert.ack…] : {:?}", phase("calme"));
    }
}
