// =====================================================================================
// `P10.21-n` (volet démon) — UNE ACTION N'EST REMISE À L'AGENT QUE SI SA RÉCLAMATION EST ÉCRITE.
//
// LE DÉFAUT MESURÉ SUR LE SITE (`handlers/actions.rs::actions_pending`, arbre `ccfa087`) : pour chaque
// action lue, `let _ = conn.execute("UPDATE action SET claimed_ts=?2, host=?3 WHERE id=?1")` puis la
// ligne partait dans le TSV quoi qu'il arrive. Une réclamation refusée (base en lecture seule, verrou,
// déclencheur) remettait l'action SANS la réclamer : `claimed_ts` NULL, donc re-servie à chaque tour et
// prenable par le responder local ; une action non assignée gardait `host` NULL, que `action_result`
// (`AND host=?5`) ne peut jamais clore.
//
// CE QUE CES TÉMOINS TIENNENT : refus total (déclencheur `RAISE(ABORT)`, base en `query_only`, écriture
// sans effet `RAISE(IGNORE)`) -> 503 nommé, aucune ligne qui commence par un chiffre, rien de réclamé,
// `host` d'une action non assignée resté NULL ; refus sur UNE ligne de deux -> une seule servie ; le
// refus levé, l'action est servie UNE fois ; contre-épreuve nominale octet pour octet ; la rétention DITE
// au journal (stderr d'un sous-processus) : `Err` et `Ok(0)` sur une remise partielle, une ligne chacun avec
// l'identifiant et la cause, jamais la cible, chemin nominal muet.
//
// CE QU'ILS NE TIENNENT PAS — LE RESTE OUVERT DE `P10.21-n`, que ce lot n'avance pas : une riposte encore
// ré-exécutée après l'abandon de son verdict (l'agent `collectors/respond.sh` ; le central qui re-sert une
// riposte dont un verdict a été tenté), et la fenêtre de péremption de la réclamation
// (`RECLAMATION_PERIMEE_S`), à mesurer d'abord. Ni : la condition de réclamation n'est pas rejouée dans
// l'UPDATE (course avec le responder local, une autre connexion).
// =====================================================================================

/// Statut + corps texte d'une réponse.
async fn rca_texte(r: Response) -> (u16, String) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, String::from_utf8_lossy(&b).into_owned())
}

fn rca_ecrire(st: &AppState, sql: &str) {
    st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// Un jeton d'agent lié à un hôte fictif.
fn rca_agent() -> AuthUser {
    AuthUser {
        name: "hote-rca".into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
        method: "token".into(), csrf: String::new(), env: None,
    }
}

/// Deux actions approuvées : la 1 ciblée sur l'hôte, la 2 NON ASSIGNÉE (host NULL).
fn rca_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("rca-{tag}"));
    rca_ecrire(&st, "INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(1,1,'ban_ip','203.0.113.1','approved',1,'hote-rca');\
                     INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(2,2,'unban_ip','203.0.113.2','approved',0,NULL);");
    (st, p)
}

/// (claimed_ts non NULL, host) de l'action `id`.
fn rca_reclamation(st: &AppState, id: i64) -> (bool, Option<String>) {
    st.db
        .lock()
        .query_row("SELECT claimed_ts IS NOT NULL, host FROM action WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
}

async fn rca_appel(st: &AppState) -> (u16, String) {
    rca_texte(actions_pending(State(st.clone()), Extension(rca_agent())).await).await
}

/// Le jugement d'un refus total : 503, cause nommée, aucune ligne lisible comme une action, rien réclamé.
fn rca_juger_le_refus(st: &AppState, statut: u16, corps: &str, voie: &str) {
    assert_eq!(statut, 503, "{voie} : une file lue mais non réclamée n'est pas remise, et pas en 200 : {corps:?}");
    let v: Value = serde_json::from_str(corps).unwrap_or(Value::Null);
    assert_eq!(v["error"], json!(crate::handlers::actions::CAUSE_REMISE_D_ACTIONS_NON_RECLAMEE), "{voie} : le refus nomme sa cause : {corps:?}");
    assert!(
        corps.lines().all(|l| !l.starts_with(|c: char| c.is_ascii_digit())),
        "{voie} : aucune ligne du corps ne doit pouvoir être lue comme une action par l'agent : {corps:?}"
    );
    assert_eq!(rca_reclamation(st, 1), (false, Some("hote-rca".into())), "{voie} : action 1 non réclamée");
    assert_eq!(rca_reclamation(st, 2), (false, None), "{voie} : action non assignée ni réclamée ni attribuée");
}

#[tokio::test]
async fn p10_21n_reclamation_refusee_par_declencheur_rien_n_est_remis() {
    let (st, _p) = rca_etat("abort");
    rca_ecrire(&st, "CREATE TRIGGER rca_refus BEFORE UPDATE ON action BEGIN SELECT RAISE(ABORT,'rca refus'); END;");
    let (statut, corps) = rca_appel(&st).await;
    rca_juger_le_refus(&st, statut, &corps, "RAISE(ABORT)");
}

#[tokio::test]
async fn p10_21n_reclamation_sur_base_en_lecture_seule_rien_n_est_remis() {
    let (st, _p) = rca_etat("ro");
    rca_ecrire(&st, "PRAGMA query_only=1;");
    let (statut, corps) = rca_appel(&st).await;
    rca_ecrire(&st, "PRAGMA query_only=0;");
    rca_juger_le_refus(&st, statut, &corps, "query_only");
}

#[tokio::test]
async fn p10_21n_reclamation_sans_effet_n_est_pas_une_remise() {
    let (st, _p) = rca_etat("ignore");
    rca_ecrire(&st, "CREATE TRIGGER rca_sans_effet BEFORE UPDATE ON action BEGIN SELECT RAISE(IGNORE); END;");
    let (statut, corps) = rca_appel(&st).await;
    rca_juger_le_refus(&st, statut, &corps, "RAISE(IGNORE)");

    // Sans effet sur UNE ligne de deux : seule l'autre part.
    let (st2, _p2) = rca_etat("ignore-un");
    rca_ecrire(&st2, "CREATE TRIGGER rca_sans_effet BEFORE UPDATE ON action WHEN OLD.id=2 BEGIN SELECT RAISE(IGNORE); END;");
    let (statut, tsv) = rca_appel(&st2).await;
    assert_eq!(statut, 200);
    assert_eq!(tsv, "1\tban_ip\t203.0.113.1\t1\n", "réclamation sans effet sur la 2 : seule la 1 est remise");
    assert_eq!(rca_reclamation(&st2, 2), (false, None));
}

#[tokio::test]
async fn p10_21n_refus_sur_une_ligne_de_deux_seule_la_reclamee_part() {
    let (st, _p) = rca_etat("partiel");
    rca_ecrire(&st, "CREATE TRIGGER rca_refus BEFORE UPDATE ON action WHEN OLD.id=1 BEGIN SELECT RAISE(ABORT,'rca refus'); END;");
    let (statut, tsv) = rca_appel(&st).await;
    assert_eq!(statut, 200, "une réclamation partielle sert ce qui est réclamé : {tsv:?}");
    assert_eq!(tsv, "2\tunban_ip\t203.0.113.2\t0\n", "seule l'action réclamée part : {tsv:?}");
    assert_eq!(rca_reclamation(&st, 1), (false, Some("hote-rca".into())), "la 1, refusée, reste à réclamer");
    assert_eq!(rca_reclamation(&st, 2), (true, Some("hote-rca".into())), "la 2 est réclamée ET attribuée à l'hôte");
}

#[tokio::test]
async fn p10_21n_refus_leve_l_action_est_servie_une_fois() {
    let (st, _p) = rca_etat("leve");
    rca_ecrire(&st, "CREATE TRIGGER rca_refus BEFORE UPDATE ON action BEGIN SELECT RAISE(ABORT,'rca refus'); END;");
    let (statut, _) = rca_appel(&st).await;
    assert_eq!(statut, 503);
    rca_ecrire(&st, "DROP TRIGGER rca_refus;");
    let (statut, tsv) = rca_appel(&st).await;
    assert_eq!(statut, 200);
    assert_eq!(tsv, "1\tban_ip\t203.0.113.1\t1\n2\tunban_ip\t203.0.113.2\t0\n", "refus levé : les deux sont servies");
    let (statut, tsv) = rca_appel(&st).await;
    assert_eq!((statut, tsv.as_str()), (200, ""), "réclamées : elles ne sont pas re-servies dans la fenêtre");
}

#[tokio::test]
async fn p10_21n_contre_epreuve_nominale_octet_pour_octet() {
    let (st, _p) = rca_etat("nominal");
    let (statut, tsv) = rca_appel(&st).await;
    assert_eq!(statut, 200);
    assert_eq!(tsv, "1\tban_ip\t203.0.113.1\t1\n2\tunban_ip\t203.0.113.2\t0\n");
    assert_eq!(rca_reclamation(&st, 1), (true, Some("hote-rca".into())));
    assert_eq!(rca_reclamation(&st, 2), (true, Some("hote-rca".into())), "l'action non assignée est attribuée à l'hôte réclamant");
    // File vide : 200 vide, jamais le 503 (le refus ne vaut que pour des lignes LUES).
    let (statut, tsv) = rca_appel(&st).await;
    assert_eq!((statut, tsv.as_str()), (200, ""));
}

/// La rétention est DITE au journal, et c'est la seule trace d'une remise partielle (200 avec un TSV
/// partiel) : lue sur le stderr d'un sous-processus, phase par phase. Réclamation refusée (`Err`) sur la 1
/// -> exactement une ligne `[actions]` qui nomme l'identifiant, le geste et la cause du moteur ; réclamation
/// sans effet (`Ok(0)`) sur la 2 -> exactement une ligne qui nomme l'identifiant et le geste ; jamais la
/// cible (ni l'une ni l'autre adresse) ; chemin nominal muet.
#[test]
fn p10_21n_journal_de_la_retenue_porte_identifiant_et_cause_jamais_la_cible() {
    const ENFANT: &str = "RCA_ENFANT_JOURNAL";
    const PHASE: &str = "RCA-PHASE:";
    if std::env::var(ENFANT).is_ok() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        rt.block_on(async {
            eprintln!("{PHASE}err");
            let (st, _p) = rca_etat("journal-err");
            rca_ecrire(&st, "CREATE TRIGGER rca_refus BEFORE UPDATE ON action WHEN OLD.id=1 BEGIN SELECT RAISE(ABORT,'rca refus journal'); END;");
            println!("RCA-RENDU:err:{:?}", rca_appel(&st).await);
            eprintln!("{PHASE}ok0");
            let (st, _p) = rca_etat("journal-ok0");
            rca_ecrire(&st, "CREATE TRIGGER rca_sans_effet BEFORE UPDATE ON action WHEN OLD.id=2 BEGIN SELECT RAISE(IGNORE); END;");
            println!("RCA-RENDU:ok0:{:?}", rca_appel(&st).await);
            eprintln!("{PHASE}nominal");
            let (st, _p) = rca_etat("journal-nominal");
            println!("RCA-RENDU:nominal:{:?}", rca_appel(&st).await);
            eprintln!("{PHASE}fin");
        });
        return;
    }
    let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
        .args([
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "tests::p10_21n_journal_de_la_retenue_porte_identifiant_et_cause_jamais_la_cible",
        ])
        .env(ENFANT, "1")
        .output()
        .expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
    // Contrôle : les deux remises sont bien PARTIELLES (200, une ligne) — le journal est leur seule trace.
    assert!(stdout.contains("RCA-RENDU:err:(200, \"2\\tunban_ip\\t203.0.113.2\\t0\\n\")"), "contrôle : err partiel : {stdout}");
    assert!(stdout.contains("RCA-RENDU:ok0:(200, \"1\\tban_ip\\t203.0.113.1\\t1\\n\")"), "contrôle : ok0 partiel : {stdout}");
    assert!(stdout.contains("RCA-RENDU:nominal:(200, \"1\\tban_ip"), "contrôle : nominal servi : {stdout}");
    let phase = |nom: &str| -> Vec<String> {
        let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
        let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.starts_with("[actions]")).map(str::to_string).collect()
    };
    let jamais_la_cible = |l: &str| {
        assert!(!l.contains("203.0.113."), "la ligne de journal ne porte jamais la cible : {l}");
    };

    let err = phase("err");
    assert_eq!(err.len(), 1, "réclamation refusée : une ligne, ni plus ni moins : {err:?}\n{stderr}");
    assert!(err[0].starts_with("[actions] action 1 NON REMISE"), "l'identifiant et le geste : {}", err[0]);
    assert!(err[0].contains("réclamation non écrite"), "la voie nommée : {}", err[0]);
    assert!(err[0].contains("rca refus journal"), "la cause du moteur : {}", err[0]);
    jamais_la_cible(&err[0]);

    let ok0 = phase("ok0");
    assert_eq!(ok0.len(), 1, "réclamation sans effet : une ligne, ni plus ni moins : {ok0:?}\n{stderr}");
    assert!(ok0[0].starts_with("[actions] action 2 NON REMISE"), "l'identifiant et le geste : {}", ok0[0]);
    assert!(ok0[0].contains("réclamation sans effet"), "la voie nommée : {}", ok0[0]);
    jamais_la_cible(&ok0[0]);

    assert_eq!(phase("nominal"), Vec::<String>::new(), "chemin nominal muet : {stderr}");
}
