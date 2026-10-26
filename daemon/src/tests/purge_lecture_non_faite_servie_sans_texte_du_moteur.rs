// =====================================================================================
// `P10.29-l` (famille « texte du moteur servi ») — UN REFUS DE PURGE PAR LECTURE NON FAITE NE SERT PLUS LE TEXTE DU
// MOTEUR.
//
// LE DÉFAUT, MESURÉ SUR ac4ca5cd AVANT LE CORRECTIF. `purge_refusal_response` (handlers/purge.rs), seule fabrique de
// réponse de `purge_plan_route` et `purge_apply_route`, servait `"message": e.to_string()`. Pour `db`
// (`REFUS — base : {e} …`), `plan_row_unread` (`… n'a pas pu être lue ({cause}) …`) et `legal_hold_unread` (`… ({cause})
// …`), ce texte embarque le texte rendu par SQLite ; `prs_juger` (tests/purge_reponse_de_refus_servie.rs) AFFIRMAIT
// ce défaut (`message == e.to_string()` pour toute variante) et est inversé nommément dans le même changement.
// Impact borné : la route est réservée à l'administrateur et FERMÉE par défaut (`PLUME_PURGE_API`).
//
// CE QUE CES TÉMOINS JUGENT, par la ROUTE `purge_plan_route` entière (porte de témoin ouverte sur ce fil, compte admin) :
//  - un balayage d'interruptions de la route : chaque `db`, `plan_row_unread` et `legal_hold_unread` produit (les trois
//    sont exigés) est servi en 500, corps ENTIER
//    `{ok:false, refusal, message: <phrase fixe littérale>}`, et `interrupted` est absent de TOUT le corps ;
//    `legal_hold_undetermined` (atteint par le même balayage) garde son texte à l'octet ;
//  - une rétention légale au nom illisible (`legal_hold_unread`) : même corps entier, texte du moteur (relu par un appel
//    direct de `purge_plan`) absent de tout le corps ;
//  - le tier froid (`cold_tier`, décision lue) : texte du refus servi à l'octet, en 409 ;
//  - la ligne de journal `[purge]`, ligne ENTIÈRE, capturée en sous-processus : une par refus des trois classes
//    (texte du moteur échappé sur une ligne, site pour `plan_row_unread`, jamais la phrase du refus), aucune pour
//    `cold_tier`, `legal_hold_undetermined` et `transaction_not_opened`.
// MUTANTS JOUÉS (variable de mutation sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `AU4_DB_TEXTE`,
// `AU4_LIGNE_TEXTE`, `AU4_HOLD_TEXTE` (texte du refus rétabli par classe), `AU4_FROID_PHRASE`, `AU4_INDETERMINE_PHRASE`
// (phrase fixe appliquée à une variante qui garde son texte), `AU4_SANS_JOURNAL`, `AU4_JOURNAL_ENONCE` (la phrase du
// refus au journal au lieu du texte du moteur), `AU4_JOURNAL_SANS_SITE`.
// CORRECTION (même clé) : `db` porte aussi des écritures refusées ; il reçoit une phrase NEUTRE (ni lecture ni
// écriture), jugée ici et dans `purge_refus_d_ecriture_servi_sous_phrase_neutre.rs`. Les trois classes servent un `id`
// de corrélation, le même que celui de la ligne `[<id>] [purge]`.
// CE QUE CES TÉMOINS NE TIENNENT PAS : la CLI (`Display` inchangé, l'opérateur y détient la clé) ; le tenant n'est pas
// nommé sur la ligne (la fabrique ne le connaît pas) ; un texte du moteur qui citerait l'énoncé SQL part tel quel au
// journal.
// =====================================================================================
mod purge_lecture_non_faite_servie_sans_texte_du_moteur {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Phrase attendue, écrite ICI (pas relue dans la constante de production).
    const PLNF_PHRASE: &str = "REFUS — lecture de la base NON FAITE : la purge n'a rien décidé, aucune ligne \
         supprimée. La cause est écrite au journal du démon.";
    const PLNF_TEXTE_DU_MOTEUR: &str = "interrupted";
    const PLNF_MOTEUR_DB: &str = "disk I/O error \"plnf\"\nseconde ligne";
    const PLNF_MOTEUR_LIGNE: &str = "interrupted (plnf)";
    const PLNF_MOTEUR_HOLD: &str = "lecture d'une ligne de `legal_hold` non faite : blob (plnf)";

    /// Phrase servie pour `db` (neutre entre lecture et écriture), écrite ICI.
    const PLNF_PHRASE_DB: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, aucune ligne \
         supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// Corps attendu, `id` de corrélation compris (sa valeur est relue dans le corps servi, sa FORME jugée ici).
    fn plnf_corps_de_la_phrase(code: &str, servi: &Value) -> Value {
        let id = servi["id"].as_str().unwrap_or_default();
        assert!(id.starts_with(&format!("plume-e{}-", std::process::id())), "`id` de corrélation servi : {servi}");
        let phrase = if code == "db" { PLNF_PHRASE_DB } else { PLNF_PHRASE };
        json!({ "ok": false, "refusal": code, "message": phrase, "id": id })
    }

    fn plnf_rendre_le_nom_du_hold_illisible(st: &AppState, au: &AuthUser) {
        with_write(st, au, |c| {
            c.execute(
                "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
                 VALUES(X'FFFE','','flux-a',0,0,1,0,'admin')",
                [],
            )
            .unwrap()
        });
    }

    /// Texte du moteur du refus `legal_hold_unread` que la route va rencontrer, relu par un appel direct.
    fn plnf_cause_du_hold(st: &AppState, au: &AuthUser) -> String {
        match with_write(st, au, |c| purge_plan(c, pcr_scope())) {
            Err(PurgeRefusal::LegalHoldUnread(t)) => t,
            Err(e) => panic!("précondition : refus `legal_hold_unread` attendu, rendu `{e}`"),
            Ok(_) => panic!("précondition : la rétention au nom illisible refuse le plan"),
        }
    }

    /// Balayage d'interruptions de la ROUTE : `db`, `plan_row_unread` et `legal_hold_unread` servis sous la phrase
    /// fixe, corps entier.
    #[tokio::test]
    async fn plnf_balayage_de_la_route_sert_la_phrase_fixe() {
        let (st, _p) = pcr_etat("plnf-balayage");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let compte = std::sync::Arc::new(AtomicU64::new(0));
        let k = compte.clone();
        with_write(&st, &au, |c| {
            c.progress_handler(
                1,
                Some(move || {
                    k.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )
        });
        let (statut, corps) = pcr_plan(&st, &au).await;
        with_write(&st, &au, |c| c.progress_handler(0, None::<fn() -> bool>));
        assert_eq!(statut, 200, "précondition : plan nominal sous rappel inerte : {corps}");
        let total = compte.load(Ordering::Relaxed);
        assert!(total > 0, "instrument : la route exécute des pas du moteur");
        let mut vus: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
        for cible in 1..=total {
            with_write(&st, &au, |c| {
                let n = AtomicU64::new(0);
                c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible))
            });
            let (statut, corps) = pcr_plan(&st, &au).await;
            with_write(&st, &au, |c| c.progress_handler(0, None::<fn() -> bool>));
            if statut == 200 {
                continue;
            }
            let code = corps["refusal"].as_str().unwrap_or_default().to_string();
            match code.as_str() {
                "db" | "plan_row_unread" | "legal_hold_unread" => {
                    assert_eq!(statut, 500, "pas {cible} : `{code}` servi en 500 : {corps}");
                    assert_eq!(corps, plnf_corps_de_la_phrase(&code, &corps), "pas {cible} : `{code}` : corps entier");
                    assert!(
                        !corps.to_string().contains(PLNF_TEXTE_DU_MOTEUR),
                        "pas {cible} : le texte du moteur hors de tout le corps : {corps}"
                    );
                }
                "legal_hold_undetermined" => {
                    assert_eq!(statut, 500, "pas {cible} : `{code}` servi en 500 : {corps}");
                    assert_eq!(
                        corps,
                        json!({ "ok": false, "refusal": code, "message": PurgeRefusal::LegalHoldUndetermined.to_string() }),
                        "pas {cible} : `legal_hold_undetermined` garde son texte à l'octet"
                    );
                }
                autre => panic!("pas {cible} : refus inattendu `{autre}` en {statut} : {corps}"),
            }
            *vus.entry(code).or_default() += 1;
        }
        assert!(
            vus.contains_key("db") && vus.contains_key("plan_row_unread") && vus.contains_key("legal_hold_unread"),
            "précondition : le balayage ({total} pas) atteint les trois classes : {vus:?}"
        );
        assert_eq!(pcr_events_servis(&st, &au), 6, "rien supprimé");
    }

    /// Rétention légale au nom illisible, par la ROUTE : phrase fixe, texte du moteur absent de tout le corps.
    #[tokio::test]
    async fn plnf_retention_illisible_par_la_route_sert_la_phrase_fixe() {
        let (st, _p) = pcr_etat("plnf-hold");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        plnf_rendre_le_nom_du_hold_illisible(&st, &au);
        let cause = plnf_cause_du_hold(&st, &au);
        assert!(!cause.is_empty(), "instrument : le refus porte un texte du moteur");
        let (statut, corps) = pcr_plan(&st, &au).await;
        assert_eq!(statut, 500, "`legal_hold_unread` servi en 500 : {corps}");
        assert_eq!(corps, plnf_corps_de_la_phrase("legal_hold_unread", &corps), "corps entier");
        assert!(!corps.to_string().contains(&cause), "le texte du moteur `{cause}` hors de tout le corps : {corps}");
        assert_eq!(pcr_events_servis(&st, &au), 6, "rien supprimé");
    }

    /// Décision lue (tier froid), par la ROUTE : le texte du refus reste servi à l'octet, en 409.
    #[tokio::test]
    async fn plnf_tier_froid_par_la_route_garde_son_texte() {
        let (st, _p) = pcr_etat("plnf-froid");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        with_write(&st, &au, |c| pcr_sceller(c, 0, 0, 2_000));
        let attendu = match with_write(&st, &au, |c| purge_plan(c, pcr_scope())) {
            Err(e @ PurgeRefusal::ColdTier { .. }) => e.to_string(),
            Err(e) => panic!("précondition : refus `cold_tier` attendu, rendu `{e}`"),
            Ok(_) => panic!("précondition : un fichier scellé sur la fenêtre refuse le plan"),
        };
        let (statut, corps) = pcr_plan(&st, &au).await;
        assert_eq!(statut, 409, "`cold_tier` servi en 409 : {corps}");
        assert_eq!(corps, json!({ "ok": false, "refusal": "cold_tier", "message": attendu }), "corps entier, texte à l'octet");
    }

    /// LA LIGNE DE JOURNAL `[purge]`, entière, capturée en sous-processus.
    #[tokio::test]
    async fn plnf_ligne_de_journal_du_refus_par_lecture_non_faite() {
        const ENFANT: &str = "PLNF_ENFANT_JOURNAL";
        const PHASE: &str = "PLNF-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let statut = |r: Response| r.status().as_u16();
            let id_servi = |r: Response| async move {
                let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
                serde_json::from_slice::<Value>(&octets).expect("corps JSON")["id"].as_str().unwrap_or_default().to_string()
            };
            eprintln!("{PHASE}id");
            println!("PLNF-ID-DB:{}", id_servi(purge_refusal_response(PurgeRefusal::Db(PLNF_MOTEUR_DB.into()))).await);
            eprintln!("{PHASE}db");
            println!("PLNF-STATUT-DB:{}", statut(purge_refusal_response(PurgeRefusal::Db(PLNF_MOTEUR_DB.into()))));
            eprintln!("{PHASE}ligne");
            let ligne = PurgeRefusal::PlanRowUnread { site: "échantillon", cause: PLNF_MOTEUR_LIGNE.into() };
            println!("PLNF-STATUT-LIGNE:{}", statut(purge_refusal_response(ligne)));
            eprintln!("{PHASE}hold");
            let hold = PurgeRefusal::LegalHoldUnread(PLNF_MOTEUR_HOLD.into());
            println!("PLNF-STATUT-HOLD:{}", statut(purge_refusal_response(hold)));
            eprintln!("{PHASE}route");
            let (st, _p) = pcr_etat("plnf-journal-route");
            let au = pcr_admin();
            let _ouverte = porte_de_purge_de_temoin::ouvrir();
            plnf_rendre_le_nom_du_hold_illisible(&st, &au);
            println!("PLNF-CAUSE-ROUTE:{}", plnf_cause_du_hold(&st, &au));
            println!("PLNF-STATUT-ROUTE:{}", pcr_plan(&st, &au).await.0);
            eprintln!("{PHASE}muets");
            let muets = [
                purge_refusal_response(PurgeRefusal::ColdTier { files: 1, days: 1 }),
                purge_refusal_response(PurgeRefusal::LegalHoldUndetermined),
                purge_refusal_response(PurgeRefusal::TransactionNotOpened),
            ];
            println!("PLNF-STATUT-MUETS:{}", muets.into_iter().map(|r| statut(r).to_string()).collect::<Vec<_>>().join(":"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_lecture_non_faite_servie_sans_texte_du_moteur::plnf_ligne_de_journal_du_refus_par_lecture_non_faite",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> String {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").to_string()
        };
        assert_eq!(marque("PLNF-STATUT-DB:"), "500", "contrôle : db");
        assert_eq!(marque("PLNF-STATUT-LIGNE:"), "500", "contrôle : plan_row_unread");
        assert_eq!(marque("PLNF-STATUT-HOLD:"), "500", "contrôle : legal_hold_unread");
        assert_eq!(marque("PLNF-STATUT-ROUTE:"), "500", "contrôle : route, legal_hold_unread");
        assert_eq!(marque("PLNF-STATUT-MUETS:"), "409:500:503", "contrôle : cold_tier, legal_hold_undetermined, transaction");
        let cause_route = marque("PLNF-CAUSE-ROUTE:");
        assert!(!cause_route.is_empty(), "contrôle : cause de la route relue");
        let phase = |nom: &str| -> Vec<String> {
            let debut =
                stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            // `[<id>] [purge] …` : l'identifiant de corrélation est jugé (forme), puis retiré pour comparer la ligne.
            corps
                .lines()
                .filter(|l| l.contains("[purge]"))
                .map(|l| {
                    let (id, reste) = l.split_once("] ").unwrap_or_else(|| panic!("ligne sans identifiant : {l}"));
                    assert!(id.starts_with("[plume-e"), "identifiant de la ligne (pid de l'enfant) : {l}");
                    reste.to_string()
                })
                .collect()
        };
        let id_db = marque("PLNF-ID-DB:");
        assert!(id_db.starts_with("plume-e"), "contrôle : `id` servi pour db : {id_db}");
        let ligne_id: Vec<&str> = stderr
            .split_once(&format!("{PHASE}id"))
            .map(|(_, r)| r.split_once(PHASE).map(|(c, _)| c).unwrap_or(r))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("[purge]"))
            .collect();
        assert_eq!(ligne_id.len(), 1, "une ligne `[purge]` pour le refus db : {ligne_id:?}");
        assert!(
            ligne_id[0].starts_with(&format!("[{id_db}] [purge] WARN ")),
            "la ligne porte l'identifiant SERVI `{id_db}` : {}",
            ligne_id[0]
        );
        assert_eq!(
            phase("db"),
            [r#"[purge] WARN refus servi, refus de la base (db) : "disk I/O error \"plnf\"\nseconde ligne""#],
            "db : ligne entière, neutre (ni lecture ni écriture), texte échappé sur une ligne"
        );
        assert_eq!(
            phase("ligne"),
            [r#"[purge] WARN refus servi, lecture de la base non faite (plan_row_unread, échantillon) : "interrupted (plnf)""#],
            "plan_row_unread : ligne entière, site nommé"
        );
        assert_eq!(
            phase("hold"),
            [r#"[purge] WARN refus servi, lecture de la base non faite (legal_hold_unread) : "lecture d'une ligne de `legal_hold` non faite : blob (plnf)""#],
            "legal_hold_unread : ligne entière"
        );
        assert_eq!(
            phase("route"),
            [format!("[purge] WARN refus servi, lecture de la base non faite (legal_hold_unread) : {cause_route:?}")],
            "route : ligne entière, texte du moteur produit"
        );
        assert_eq!(phase("muets"), Vec::<String>::new(), "aucune ligne `[purge]` pour les refus qui gardent leur texte");
    }
}
