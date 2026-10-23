// =====================================================================================
// `P10.31-u` (fermeture côté démon des appels nus de `ledger_append`) et `P10.29-l` (reste : `mail_body` servait la
// sortie d'erreur de `PLUME_MAIL_BODY_CMD` et l'erreur d'exécution) — LES MAILLONS NUS SONT CONSOMMÉS, ET LE CORPS
// D'UN COURRIEL N'EST LU QU'APRÈS SA TRACE.
//
// LE DÉFAUT, MESURÉ SUR 1011ec9f AVANT LE CORRECTIF (onze appels nus de production, garde
// `check_a_ledger_link_is_never_dropped_bare.py` rejouée sur l'arbre d'avant : code 1, onze lignes) :
//   * `mail_body` (`ingest/minio.rs`) lançait la commande, POSAIT ENSUITE `mail.body.read` en jetant l'issue, puis
//     servait le corps : une lecture de boîte sans preuve d'audit quand le registre refuse la ligne. Le 502 servait les
//     300 premiers caractères de la sortie d'erreur de la commande, le 500 `exec: {e}` ;
//   * `case_link_remove` (`case.unlink`) et `attach_runbook` (`case.runbook_attach`) jetaient leur maillon : la route
//     servait 204 / `{attached}` comme un geste attesté ;
//   * quatre appels de `run_playbooks` et quatre traces de démarrage (`server/mod.rs`) jetaient le leur sans le nommer.
//
// LE CORRECTIF (décisions par défaut de l'orchestrateur, vague AG) :
//   * `mail_body` : trace AVANT la lecture ; non inscrite -> 503 `CAUSE_CORPS_DU_COURRIEL_NON_LU_SANS_TRACE`, la
//     commande N'EST PAS lancée ; 502 `PHRASE_BODY_FETCH_A_ECHOUE` et 500 `PHRASE_BODY_FETCH_NON_LANCE` en phrases
//     fixes ; journal : identifiant de corrélation + cause du moteur (503), code de sortie (502), nature de l'erreur
//     (500) — jamais la sortie d'erreur, le chemin, la boîte ni le compte ;
//   * `case.unlink` : lien retiré sans trace -> 200 `{ok, registre_sans_maillon}` (`geste_fait_sans_trace`), jamais un
//     204 muet, lien non rétabli ;
//   * `case.runbook_attach` : attache validée sans trace -> 200 `{attached, registre_sans_maillon}`, rien annulé ;
//   * `run_playbooks` et le démarrage : `.laisser_a_l_aveu_de_la_primitive()` (abandon déjà compté au site, ou aucune
//     surface) — comportement inchangé, tenu par la garde seule.
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)` ; la cause attendue est celle
// que la primitive rend sur la même connexion (sonde), jamais une phrase recopiée.
//
// MUTANTS (variable d'environnement de mutation, retirés avant le commit) : `AG2_MB_APRES` (la trace refusée n'arrête plus la lecture),
// `AG2_MB_STDERR` (502 avec la sortie d'erreur), `AG2_MB_EXEC` (500 avec l'erreur d'exécution), `AG2_MB_JOURNAL_503`
// (la ligne du 503 tue), `AG2_MB_JOURNAL_STDERR` (la sortie d'erreur au journal du 502), `AG2_UNLINK_JETTE` (204 sur un
// retrait sans trace), `AG2_UNLINK_AVEU_SANS_PANNE` (l'aveu sur un retrait nominal), `AG2_RB_JETTE` (`{attached}` seul
// sur une attache sans trace), `AG2_RB_AVEU_SANS_PANNE` (l'aveu sur une attache nominale).
//
// CORRECTION (vérification indépendante, vague AG) :
//   * le bras « arrêtée par un signal » du 502 n'avait aucun témoin (mutant du vérificateur `MB_SIGNAL_STDERR` vert) :
//     la commande fabriquée se tue par `SIGKILL` après avoir écrit sa sortie d'erreur sur le message `signal` ; témoin
//     HTTP et quatrième ligne du témoin de journal. MUTANT `AG2C_SIGNAL_STDERR` (la sortie d'erreur au journal du bras) ;
//   * l'attache validée sans maillon voyageait dans l'`Err` de `RefusDAttache` (variante `AttacheeSansTrace`, retirée) :
//     `crate::handlers::incidents::attach_runbook` rend `Ok(AttacheValidee::SansTrace { etapes, cause })` — un
//     `.is_err()` dit de nouveau « refusé ». Les témoins d'avant lisent `Result<i64, _>` : le raccourci
//     `attach_runbook` ci-dessous (module de test seulement) masque le point d'entrée et rend `Ok(etapes)`. MUTANT
//     `AG2C_RB_SANS_TRACE_EN_ERR` (l'attache sans maillon rendue en `Err`) ;
//   * le témoin du 502 compte la ligne `mail.body.read` mais ne prouve pas l'ORDRE : l'ordre « trace avant lancement »
//     est tenu par le témoin du 503 (trace refusée, commande NON lancée) ; l'assertion le dit.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (`web/viz.js` lit `j.error` : un 503 ou un 502 à phrase fixe s'y lit
// comme un refus générique ; aucun lecteur de `registre_sans_maillon` pour `case.unlink` ni l'attache) ; les sites de
// `run_playbooks` et du démarrage ne sont tenus que par la garde (comportement inchangé) ; le mode multi-tenant.
// =====================================================================================

/// RACCOURCI DES TÉMOINS (module de test seulement) : il MASQUE, pour tout `tests/`, le point d'entrée
/// `crate::handlers::incidents::attach_runbook` (importé par le glob du module) et rend le nombre d'étapes écrites, que
/// le maillon `case.runbook_attach` soit inscrit ou non — une attache validée sans trace est un `Ok`, comme en
/// production. Un témoin qui juge le maillon appelle le chemin complet.
fn attach_runbook(
    conn: &Connection,
    id: i64,
    runbook_id: i64,
    author: &str,
    targets: &PrefillTargets,
) -> Result<i64, RefusDAttache> {
    crate::handlers::incidents::attach_runbook(conn, id, runbook_id, author, targets).map(|a| a.etapes())
}

mod maillons_nus_consommes_et_corps_de_courriel_trace {
    use super::*;

    /// Variable qui fait de ce binaire l'enfant du témoin de journal.
    const AG2_ENFANT: &str = "AG2_ENFANT_JOURNAL";
    const AG2_MARQUE_ENFANT: &str = "AG2-ENFANT-A-JOUE";
    const AG2_ID_ENFANT: &str = "AG2-ID-SERVI";
    const AG2_CAUSE_ENFANT: &str = "AG2-CAUSE-DU-MOTEUR";
    /// La sortie d'erreur que la commande fabriquée écrit sur un échec : elle ne doit paraître NULLE PART.
    const AG2_SORTIE_D_ERREUR: &str = "AG2-SORTIE-D-ERREUR /chemin/prive/de/la/commande";
    /// La boîte et le demandeur : jamais au journal.
    const AG2_BOITE: &str = "boite.ag2.temoin";
    const AG2_DEMANDEUR: &str = "adm-ag2";
    const AG2_LEVIER: &str = "PLUME_MAIL_BODY_CMD";

    fn ag2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ag2-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ag2_admin() -> AuthUser {
        AuthUser {
            name: AG2_DEMANDEUR.into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ag2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Pose le déclencheur qui refuse toute ligne de registre, et rend la cause que la primitive rend alors (sonde).
    fn ag2_registre_hors_d_atteinte(st: &AppState) -> String {
        let conn = st.db.lock();
        conn.execute_batch(
            "CREATE TRIGGER ag2_registre_refuse BEFORE INSERT ON ledger \
             BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin AG2)'); END;",
        )
        .expect("fixture : déclencheur posé");
        let sonde = ledger_append(&conn, "ag2.sonde", "sonde");
        sonde.cause_de_non_inscription().map(str::to_string).expect("fixture : la sonde n'entre pas au registre")
    }

    fn ag2_registre_revenu(st: &AppState) {
        st.db.lock().execute_batch("DROP TRIGGER ag2_registre_refuse;").expect("fixture : déclencheur retiré");
    }

    async fn ag2_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    fn ag2_cles(v: &Value) -> Option<std::collections::BTreeSet<String>> {
        v.as_object().map(|o| o.keys().cloned().collect())
    }

    /// Le corps attendu d'un geste fait sans trace : `base` plus l'aveu sous `CLE_REGISTRE_SANS_MAILLON`.
    fn ag2_avec_l_aveu(mut base: Value, cause: &str) -> Value {
        base[CLE_REGISTRE_SANS_MAILLON] = json!(format!("{CAUSE_GESTE_SANS_TRACE} ({cause})"));
        base
    }

    // ---------------------------------------------------------------------------------
    // `mail_body`
    // ---------------------------------------------------------------------------------

    /// La commande fabriquée : elle note chaque lancement (identifiant du message) dans `lu`, échoue sur `echec`
    /// (sortie d'erreur + code 3), se tue par `SIGKILL` sur `signal` (sortie d'erreur d'abord), sinon rend un corps JSON.
    fn ag2_commande(dossier: &crate::tmp_possede::TmpPossede) -> (String, String) {
        use std::os::unix::fs::PermissionsExt;
        let lu = dossier.sous("lu").as_str().to_string();
        let script = dossier.sous("commande.sh").as_str().to_string();
        let corps = format!(
            "#!/bin/sh\necho \"$2\" >> \"{lu}\"\nif [ \"$2\" = echec ]; then echo \"{AG2_SORTIE_D_ERREUR}\" >&2; exit 3; fi\n\
             if [ \"$2\" = signal ]; then echo \"{AG2_SORTIE_D_ERREUR}\" >&2; kill -9 $$; fi\n\
             printf '{{\"subject\":\"objet ag2\",\"text\":\"corps ag2\"}}'\n"
        );
        std::fs::write(&script, corps).expect("fixture : commande écrite");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("fixture : commande exécutable");
        (script, lu)
    }

    /// Le levier posé le temps d'un témoin, remis à sa valeur d'avant à la sortie (panique comprise). À construire
    /// sous `VERROU_ENV_PROCESSUS.write()`.
    struct Ag2Levier(Option<String>);
    impl Ag2Levier {
        fn poser(valeur: &str) -> Self {
            let avant = std::env::var(AG2_LEVIER).ok();
            std::env::set_var(AG2_LEVIER, valeur);
            Ag2Levier(avant)
        }
    }
    impl Drop for Ag2Levier {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var(AG2_LEVIER, v),
                None => std::env::remove_var(AG2_LEVIER),
            }
        }
    }

    async fn ag2_lire(st: &AppState, message: &str) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "account": AG2_BOITE, "id": message, "folder": "INBOX" });
        ag2_reponse(mail_body(State(st.clone()), Extension(ag2_admin()), Json(corps)).await).await
    }

    fn ag2_lancements(lu: &str) -> Vec<String> {
        std::fs::read_to_string(lu).map(|t| t.lines().map(str::to_string).collect()).unwrap_or_default()
    }

    const AG2_TRACE_DE_LECTURE: &str = "SELECT COUNT(*) FROM ledger WHERE kind='mail.body.read'";

    /// CE QU'IL TIENT : registre hors d'atteinte, `mail_body` rend 503, corps EXACT `{error, id}` avec
    /// `CAUSE_CORPS_DU_COURRIEL_NON_LU_SANS_TRACE` (ni la cause du moteur ni la boîte), et la commande N'A PAS été
    /// lancée (aucun lancement noté) ; aucune ligne `mail.body.read`.
    /// MUTATION : `AG2_MB_APRES` (200, le corps servi, la commande lancée).
    #[tokio::test]
    async fn ag2_mail_body_trace_refusee_ne_lit_pas_le_corps() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-refus");
        let (script, lu) = ag2_commande(&dossier);
        let _levier = Ag2Levier::poser(&script);
        let (st, _tmp) = ag2_etat("mb-refus");
        let cause = ag2_registre_hors_d_atteinte(&st);

        let (statut, octets, v) = ag2_lire(&st, "m1").await;
        assert_eq!(statut, 503, "trace refusée : 503 nommé : {v}");
        assert_eq!(ag2_cles(&v), Some(["error", "id"].iter().map(|s| s.to_string()).collect()), "clés exactes : {v}");
        assert_eq!(v["error"], json!(CAUSE_CORPS_DU_COURRIEL_NON_LU_SANS_TRACE), "phrase fixe : {v}");
        assert!(v["id"].as_str().unwrap_or("").starts_with("plume-e"), "identifiant de corrélation : {v}");
        let texte = String::from_utf8_lossy(&octets);
        assert!(!texte.contains(&cause) && !texte.contains(AG2_BOITE), "ni cause du moteur ni boîte au client : {texte}");
        assert!(ag2_lancements(&lu).is_empty(), "le corps n'est PAS lu : la commande n'a pas été lancée ({:?})", ag2_lancements(&lu));
        assert_eq!(ag2_compte(&st, AG2_TRACE_DE_LECTURE), 0, "fixture : aucune trace entrée");
    }

    /// CONTRÔLE POSITIF : registre sain, la trace `mail.body.read` (boîte, dossier, message, demandeur) est écrite et
    /// le corps rendu par la commande est servi tel quel (200), la commande lancée une fois.
    #[tokio::test]
    async fn ag2_mail_body_nominal_trace_puis_corps() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-sain");
        let (script, lu) = ag2_commande(&dossier);
        let _levier = Ag2Levier::poser(&script);
        let (st, _tmp) = ag2_etat("mb-sain");

        let (statut, _, v) = ag2_lire(&st, "m1").await;
        assert_eq!(statut, 200, "lecture tracée : le corps est servi : {v}");
        assert_eq!(v, json!({ "subject": "objet ag2", "text": "corps ag2" }), "corps de la commande tel quel");
        assert_eq!(ag2_lancements(&lu), vec!["m1".to_string()], "la commande est lancée une fois");
        let detail: String = st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='mail.body.read'", [], |r| r.get(0)).expect("la trace est écrite");
        assert_eq!(detail, format!("{AG2_BOITE} INBOX/m1 by {AG2_DEMANDEUR}"), "la trace dit ce qui a été lu, et par qui");
    }

    /// CE QU'IL TIENT : la commande échoue (code 3, sortie d'erreur), la route rend 502, corps EXACT `{error, id}` avec
    /// `PHRASE_BODY_FETCH_A_ECHOUE` ; la sortie d'erreur ne part pas au client. La commande échouée vient
    /// APRÈS la trace (une ligne `mail.body.read`).
    /// MUTATION : `AG2_MB_STDERR` (la sortie d'erreur servie).
    #[tokio::test]
    async fn ag2_mail_body_commande_en_echec_sert_une_phrase_fixe() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-echec");
        let (script, lu) = ag2_commande(&dossier);
        let _levier = Ag2Levier::poser(&script);
        let (st, _tmp) = ag2_etat("mb-echec");

        let (statut, octets, v) = ag2_lire(&st, "echec").await;
        assert_eq!(statut, 502, "commande en échec : 502 : {v}");
        assert_eq!(ag2_cles(&v), Some(["error", "id"].iter().map(|s| s.to_string()).collect()), "clés exactes : {v}");
        assert_eq!(v["error"], json!(PHRASE_BODY_FETCH_A_ECHOUE), "phrase fixe : {v}");
        assert!(!String::from_utf8_lossy(&octets).contains("AG2-SORTIE-D-ERREUR"), "la sortie d'erreur reste au serveur : {v}");
        assert_eq!(ag2_lancements(&lu), vec!["echec".to_string()], "fixture : la commande a été lancée");
        assert_eq!(
            ag2_compte(&st, AG2_TRACE_DE_LECTURE),
            1,
            "la tentative est tracée (une ligne) ; l'ORDRE trace-avant-lancement est tenu par le témoin du 503"
        );
    }

    /// CE QU'IL TIENT (correction) : la commande se tue par `SIGKILL` après avoir écrit sa sortie d'erreur ; la route
    /// rend 502, corps EXACT `{error, id}` avec `PHRASE_BODY_FETCH_A_ECHOUE`, sans la sortie d'erreur. Le journal de ce
    /// bras est tenu par le témoin de journal (quatrième ligne).
    #[tokio::test]
    async fn ag2_mail_body_commande_tuee_par_un_signal_sert_une_phrase_fixe() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-signal");
        let (script, lu) = ag2_commande(&dossier);
        let _levier = Ag2Levier::poser(&script);
        let (st, _tmp) = ag2_etat("mb-signal");

        let (statut, octets, v) = ag2_lire(&st, "signal").await;
        assert_eq!(statut, 502, "commande tuée par un signal : 502 : {v}");
        assert_eq!(ag2_cles(&v), Some(["error", "id"].iter().map(|s| s.to_string()).collect()), "clés exactes : {v}");
        assert_eq!(v["error"], json!(PHRASE_BODY_FETCH_A_ECHOUE), "phrase fixe : {v}");
        assert!(!String::from_utf8_lossy(&octets).contains("AG2-SORTIE-D-ERREUR"), "la sortie d'erreur reste au serveur : {v}");
        assert_eq!(ag2_lancements(&lu), vec!["signal".to_string()], "fixture : la commande a été lancée");
    }

    /// CE QU'IL TIENT : la commande n'existe pas, la route rend 500, corps EXACT `{error, id}` avec
    /// `PHRASE_BODY_FETCH_NON_LANCE` ; ni le texte de l'erreur d'exécution, ni le chemin de la commande.
    /// MUTATION : `AG2_MB_EXEC` (`exec: {e}` servi).
    #[tokio::test]
    async fn ag2_mail_body_commande_non_lancee_sert_une_phrase_fixe() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-absente");
        let absente = dossier.sous("commande-absente").as_str().to_string();
        let _levier = Ag2Levier::poser(&absente);
        let (st, _tmp) = ag2_etat("mb-absente");

        let (statut, octets, v) = ag2_lire(&st, "m1").await;
        assert_eq!(statut, 500, "commande non lancée : 500 : {v}");
        assert_eq!(ag2_cles(&v), Some(["error", "id"].iter().map(|s| s.to_string()).collect()), "clés exactes : {v}");
        assert_eq!(v["error"], json!(PHRASE_BODY_FETCH_NON_LANCE), "phrase fixe : {v}");
        let texte = String::from_utf8_lossy(&octets);
        assert!(!texte.contains("exec:") && !texte.contains("commande-absente"), "ni erreur d'exécution ni chemin : {texte}");
    }

    /// LE JOURNAL. L'enfant (variable `AG2_ENFANT` posée) joue les quatre refus — trace refusée (503), commande en
    /// échec (502), commande tuée par un signal (502), commande absente (500) — et donne les identifiants servis et la cause du moteur ; le parent lit son
    /// stderr : une ligne `[mail]` par refus, ÉGALE à la ligne attendue ; dans TOUTE la sortie de l'enfant, ni la sortie
    /// d'erreur de la commande, ni la boîte, ni le demandeur.
    /// MUTATIONS : `AG2_MB_JOURNAL_503` (ligne absente), `AG2_MB_JOURNAL_STDERR` (sortie d'erreur au journal),
    /// `AG2C_SIGNAL_STDERR` (sortie d'erreur au journal du bras « signal »).
    #[tokio::test]
    async fn ag2_mail_body_journalise_sans_sortie_d_erreur_ni_boite() {
        if std::env::var(AG2_ENFANT).is_ok() {
            let _env = VERROU_ENV_PROCESSUS.write();
            let dossier = crate::tmp_possede::TmpPossede::neuf("ag2-mb-journal");
            let (script, _lu) = ag2_commande(&dossier);
            let (st, _tmp) = ag2_etat("mb-journal");
            let mut ids = Vec::new();
            {
                let _levier = Ag2Levier::poser(&script);
                let cause = ag2_registre_hors_d_atteinte(&st);
                println!("{AG2_CAUSE_ENFANT} {cause}");
                ids.push(ag2_lire(&st, "m1").await.2["id"].as_str().unwrap_or("absent").to_string());
                ag2_registre_revenu(&st);
                ids.push(ag2_lire(&st, "echec").await.2["id"].as_str().unwrap_or("absent").to_string());
                ids.push(ag2_lire(&st, "signal").await.2["id"].as_str().unwrap_or("absent").to_string());
            }
            {
                let _levier = Ag2Levier::poser(dossier.sous("commande-absente").as_str());
                ids.push(ag2_lire(&st, "m1").await.2["id"].as_str().unwrap_or("absent").to_string());
            }
            for id in &ids {
                println!("{AG2_ID_ENFANT} {id}");
            }
            println!("{AG2_MARQUE_ENFANT} {}", ids.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::maillons_nus_consommes_et_corps_de_courriel_trace::ag2_mail_body_journalise_sans_sortie_d_erreur_ni_boite",
            ])
            .env(AG2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(&format!("{AG2_MARQUE_ENFANT} 4")), "contrôle : l'enfant a joué les quatre refus : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<&str> = stdout.lines().filter_map(|l| l.split_once(AG2_ID_ENFANT)).map(|(_, id)| id.trim()).collect();
        let cause = stdout.lines().find_map(|l| l.split_once(AG2_CAUSE_ENFANT)).map(|(_, c)| c.trim()).unwrap_or_else(|| panic!("contrôle : cause donnée : {stdout}"));
        assert_eq!(ids.len(), 4, "contrôle : un identifiant servi par refus : {stdout}");
        assert!(ids.iter().all(|id| id.starts_with("plume-e")), "contrôle : identifiants servis : {ids:?}");
        let attendues = [
            format!("[{}] [mail] WARN corps du courriel NON lu : trace d'audit non inscrite ({cause})", ids[0]),
            format!("[{}] [mail] WARN body-fetch a echoue : code de sortie 3", ids[1]),
            format!("[{}] [mail] WARN body-fetch a echoue : arrêtée par un signal", ids[2]),
            format!("[{}] [mail] WARN body-fetch non lance : NotFound", ids[3]),
        ];
        let lues: Vec<&str> = stderr.lines().filter(|l| l.contains("] [mail] ")).collect();
        assert_eq!(lues, attendues.iter().map(String::as_str).collect::<Vec<_>>(), "lignes de journal, en entier :\n{stderr}");
        for interdit in ["AG2-SORTIE-D-ERREUR", AG2_BOITE, AG2_DEMANDEUR] {
            assert!(!stderr.contains(interdit) && !stdout.contains(interdit), "`{interdit}` ne paraît nulle part dans la sortie de l'enfant :\n{stderr}");
        }
    }

    // ---------------------------------------------------------------------------------
    // `case.unlink`
    // ---------------------------------------------------------------------------------

    fn ag2_deux_dossiers_lies(st: &AppState) -> (i64, i64) {
        let conn = st.db.lock();
        let a = dossier_seme(&conn, "adm", "Dossier A ag2", 3, "", None, 2);
        let b = dossier_seme(&conn, "adm", "Dossier B ag2", 3, "", None, 2);
        let pose = crate::handlers::caseops::case_link_add(&conn, a, b, "related", "", "adm");
        assert!(matches!(pose, crate::handlers::caseops::LienDeDossier::Pose), "fixture : lien posé");
        (a, b)
    }

    async fn ag2_delier(st: &AppState, a: i64, b: i64) -> (u16, Vec<u8>, Value) {
        ag2_reponse(case_unlink_handler(State(st.clone()), Extension(ag2_admin()), Path((a, b))).await).await
    }

    const AG2_LIENS: &str = "SELECT COUNT(*) FROM case_link";
    const AG2_TRACE_DE_DELIAISON: &str = "SELECT COUNT(*) FROM ledger WHERE kind='case.unlink'";

    /// CE QU'IL TIENT : registre hors d'atteinte, `case_link_remove` rend `RetireSansTrace(cause du moteur)` et la route
    /// rend 200, corps EXACT `{ok: true, registre_sans_maillon: "<CAUSE_GESTE_SANS_TRACE> (<cause>)"}` — jamais un 204
    /// muet ; le lien EST retiré (non rétabli) ; aucune ligne `case.unlink`.
    /// MUTATION : `AG2_UNLINK_JETTE` (204 servi).
    #[tokio::test]
    async fn ag2_deliaison_sans_maillon_l_avoue_et_reste_faite() {
        let (st, _tmp) = ag2_etat("unlink-panne");
        let (a, b) = ag2_deux_dossiers_lies(&st);
        // Le second lien est posé AVANT la panne : sa pose, elle aussi, écrit au registre.
        let (c, d) = ag2_deux_dossiers_lies(&st);
        let cause = ag2_registre_hors_d_atteinte(&st);
        let (statut, _, v) = ag2_delier(&st, a, b).await;
        assert_eq!(statut, 200, "lien retiré sans trace : 200 qui l'avoue, jamais 204 : {v}");
        assert_eq!(v, ag2_avec_l_aveu(json!({ "ok": true }), &cause), "corps exact");
        assert_eq!(ag2_compte(&st, &format!("SELECT COUNT(*) FROM case_link WHERE (src_id={a} AND dst_id={b}) OR (src_id={b} AND dst_id={a})")), 0, "le lien est retiré, pas rétabli");
        assert_eq!(ag2_compte(&st, AG2_TRACE_DE_DELIAISON), 0, "fixture : aucune trace entrée");

        // Le point d'entrée que le gestionnaire appelle, sur le second lien.
        let issue = case_link_remove(&st.db.lock(), c, d, "adm");
        assert!(matches!(&issue, crate::handlers::caseops::LienRetire::RetireSansTrace(x) if *x == cause), "`RetireSansTrace` avec la cause du moteur");
    }

    /// CONTRÔLE NÉGATIF : registre sain, 204 SANS corps, lien retiré, une ligne `case.unlink` ; et sous registre hors
    /// d'atteinte, aucun lien entre deux dossiers reste le 404 nommé d'avant (rien fait, rien à avouer).
    /// MUTATION : `AG2_UNLINK_AVEU_SANS_PANNE` (200 avec l'aveu sur le chemin nominal).
    #[tokio::test]
    async fn ag2_deliaison_nominale_reste_un_deux_cent_quatre_sans_corps() {
        let (st, _tmp) = ag2_etat("unlink-sain");
        let (a, b) = ag2_deux_dossiers_lies(&st);
        let (statut, octets, v) = ag2_delier(&st, a, b).await;
        assert_eq!(statut, 204, "retrait attesté : 204 inchangé : {v}");
        assert!(octets.is_empty(), "aucun corps : {:?}", String::from_utf8_lossy(&octets));
        assert_eq!(ag2_compte(&st, AG2_LIENS), 0, "le lien est retiré");
        assert_eq!(ag2_compte(&st, AG2_TRACE_DE_DELIAISON), 1, "le retrait est inscrit au registre");

        ag2_registre_hors_d_atteinte(&st);
        let (statut, _, v) = ag2_delier(&st, a, b).await;
        assert_eq!(statut, 404, "aucun lien : 404 d'avant : {v}");
        assert_eq!(v, json!({ "error": crate::handlers::caseops::CAUSE_AUCUN_LIEN_ENTRE_CES_DOSSIERS }), "corps exact, aucun aveu");
    }

    // ---------------------------------------------------------------------------------
    // `case.runbook_attach`
    // ---------------------------------------------------------------------------------

    /// Un dossier neuf et un runbook actif de deux étapes. Rend `(dossier, runbook)`.
    fn ag2_dossier_et_runbook(st: &AppState, cle: &str) -> (i64, i64) {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "adm", "Dossier ag2 runbook", 4, "", None, 2);
        conn.execute(
            "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,'Procédure ag2','*','','',0,1,1000)",
            params![cle],
        )
        .expect("fixture : le runbook");
        let rb = conn.last_insert_rowid();
        for (ordinal, titre) in [(0, "Vérifier"), (1, "Isoler")] {
            conn.execute(
                "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind) VALUES(?1,?2,'triage',?3,'','manual')",
                params![rb, ordinal, titre],
            )
            .expect("fixture : une étape");
        }
        (id, rb)
    }

    async fn ag2_attacher(st: &AppState, id: i64, rb: i64) -> (u16, Vec<u8>, Value) {
        ag2_reponse(case_runbook_attach(State(st.clone()), Extension(ag2_admin()), Path(id), Json(json!({ "runbook_id": rb }))).await).await
    }

    const AG2_TRACE_D_ATTACHE: &str = "SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach'";

    /// CE QU'IL TIENT : registre hors d'atteinte, la route rend 200, corps EXACT
    /// `{attached: 2, registre_sans_maillon: "<CAUSE_GESTE_SANS_TRACE> (<cause>)"}` ; les deux étapes et la chronologie
    /// sont écrites (rien annulé) ; aucune ligne `case.runbook_attach`. Le point d'entrée (`incidents::attach_runbook`) rend
    /// `Ok(AttacheValidee::SansTrace { etapes: 2, cause })` sur un second dossier — un succès, jamais un `Err` —, et
    /// le raccourci `attach_runbook` rend `Ok(2)` sur un troisième (un `.is_err()` y dit « refusé »).
    /// MUTATIONS : `AG2_RB_JETTE` (`{attached}` seul), `AG2C_RB_SANS_TRACE_EN_ERR` (l'attache sans maillon en `Err`).
    #[tokio::test]
    async fn ag2_attache_sans_maillon_l_avoue_et_reste_faite() {
        let (st, _tmp) = ag2_etat("rb-panne");
        let (id, rb) = ag2_dossier_et_runbook(&st, "ag2-rb-panne");
        let cause = ag2_registre_hors_d_atteinte(&st);
        let (statut, _, v) = ag2_attacher(&st, id, rb).await;
        assert_eq!(statut, 200, "attache validée sans trace : 200 qui l'avoue : {v}");
        assert_eq!(v, ag2_avec_l_aveu(json!({ "attached": 2 }), &cause), "corps exact");
        assert_eq!(ag2_compte(&st, &format!("SELECT COUNT(*) FROM case_step WHERE incident_id={id}")), 2, "les étapes sont écrites, pas annulées");
        assert_eq!(ag2_compte(&st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='runbook'")), 1, "la chronologie est écrite");
        assert_eq!(ag2_compte(&st, AG2_TRACE_D_ATTACHE), 0, "fixture : aucune trace entrée");

        let autre = dossier_seme(&st.db.lock(), "adm", "Dossier ag2 second", 4, "", None, 2);
        let issue = crate::handlers::incidents::attach_runbook(&st.db.lock(), autre, rb, "adm", &PrefillTargets::default());
        match issue {
            Ok(a) => assert_eq!(a, AttacheValidee::SansTrace { etapes: 2, cause: cause.clone() }, "étapes et cause portées"),
            Err(refus) => panic!("une attache validée sans maillon est un succès, pas le refus {refus:?}"),
        }
        let troisieme = dossier_seme(&st.db.lock(), "adm", "Dossier ag2 troisieme", 4, "", None, 2);
        let raccourci = attach_runbook(&st.db.lock(), troisieme, rb, "adm", &PrefillTargets::default());
        assert!(matches!(raccourci, Ok(2)), "le raccourci de test ne lit pas une attache validée comme un refus : {raccourci:?}");
        assert_eq!(ag2_compte(&st, &format!("SELECT COUNT(*) FROM case_step WHERE incident_id={troisieme}")), 2, "les étapes du troisième sont écrites");
    }

    /// CONTRÔLE NÉGATIF : registre sain, 200 corps EXACT `{attached: 2}` (sans aveu), une ligne `case.runbook_attach`.
    /// MUTATION : `AG2_RB_AVEU_SANS_PANNE` (l'aveu sur le chemin nominal).
    #[tokio::test]
    async fn ag2_attache_nominale_garde_son_corps_d_avant() {
        let (st, _tmp) = ag2_etat("rb-sain");
        let (id, rb) = ag2_dossier_et_runbook(&st, "ag2-rb-sain");
        let (statut, _, v) = ag2_attacher(&st, id, rb).await;
        assert_eq!(statut, 200, "attache attestée : {v}");
        assert_eq!(v, json!({ "attached": 2 }), "corps d'avant, sans aveu");
        assert_eq!(ag2_compte(&st, AG2_TRACE_D_ATTACHE), 1, "l'attache est inscrite au registre");

        let autre = dossier_seme(&st.db.lock(), "adm", "Dossier ag2 sain second", 4, "", None, 2);
        let issue = crate::handlers::incidents::attach_runbook(&st.db.lock(), autre, rb, "adm", &PrefillTargets::default());
        assert!(matches!(issue, Ok(AttacheValidee::Tracee { etapes: 2 })), "attache tracée : {issue:?}");
    }
}
