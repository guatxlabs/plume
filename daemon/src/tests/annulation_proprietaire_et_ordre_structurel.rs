// ================================================================================================
// P10.32-c — QUI PEUT ANNULER, ET DANS QUEL ORDRE : TÉMOINS STRUCTURELS DES RESTES DE `P10.31-y`
// ================================================================================================
// Suite de `annulation_reiteree.rs` et `annulation_cle_et_classement.rs`, mêmes aides.
//
// CE QUI ÉTAIT VRAI DANS L'ÉNONCÉ (re-mesuré sur f3d3fc38) :
//   · `annuler_les_requetes(db_path, qid)` ne comparait que `(base, qid)`, et `/api/cancel` ne lui passait
//     aucune identité : sur une même base (mono-tenant = tous les comptes), quiconque connaissait un qid
//     annulait la requête d'un autre ;
//   · l'ordre « drapeau d'abord » de `CancelEntry::annuler` et son interruption immédiate n'avaient pas de
//     témoin ; l'annulation testée AVANT le quota dans `classer_l_echec` non plus ;
//   · le témoin du réveil attendait 50 ms au chronomètre ; la période n'était jugée qu'au chronomètre.
//
// DÉCISION ÉCRITE (la plus sûre, posée par l'orchestrateur) : une annulation n'est honorée que pour
// l'identité qui a lancé la requête, ou pour un admin de la base ; sinon la réponse est EXACTEMENT celle
// d'un qid inconnu. `/api/query` lie le qid à `au.name` (`qid_d_annulation_de_la_requete`), le registre
// garde le propriétaire, `/api/cancel` passe `DemandeurDAnnulation::de(&au)`.
//
// TÉMOINS, chacun avec le mutant joué pendant la vérification qui le fait rougir (retiré du source livré) :
//   · `ordre_inverse` — réveil, interruption PUIS drapeau : les notes relues juste après chaque geste ;
//   · `sans_interruption_immediate` — l'interruption de `CancelEntry::annuler` retirée : une entrée SANS
//     réveil, sur une connexion qui garde un énoncé actif (SQLite n'efface plus le drapeau), n'est plus
//     interrompue quand la route rend la main ;
//   · `annulation_avant_quota` — `classer_l_echec` lit l'annulation avant la note de quota ;
//   · `proprietaire_ignore`, `admin_pour_tous`, `qid_non_lie`, `route_sans_identite` — la route atteint la
//     requête d'un autre compte ;
//   · `handler_qid_brut` — `/api/query` passe le qid du client sans le lier (témoin statique, mutant
//     appliqué au texte lu) ;
//   · `reveil_sans_notify` — le réveil ne notifie plus : la garde, constatée DANS son attente (drapeau posé
//     sous son verrou), n'interrompt jamais ;
//   · `attente_200`, `une_sur_vingt` — la garde demande 200 ms entre deux interruptions, ou n'émet qu'un
//     tour sur vingt : le déroulé noté sur le fil de la garde n'alterne plus « interruption, attente de
//     la période » ;
//   · `attente_en_plus` — une seconde attente dans la boucle (témoin statique, mutant appliqué au texte).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   · une entrée posée avec un qid NU (non lié) reste annulable par tout appelant de la base : c'est la
//     forme des témoins de `P10.31-y` (`annulation_cle_et_classement.rs` annule par la route, en lecteur,
//     une entrée nue). Aucune lecture de production ne la pose ; la liaison de `/api/query` est tenue par
//     un témoin STATIQUE (le gestionnaire entier n'est pas joué : il lance sa lecture sur un fil
//     `spawn_blocking` que le point d'arrêt de ce fil n'atteint pas) ;
//   · l'identité est `au.name` : deux identités de même nom sur une même base (un compte et un jeton
//     d'agent homonymes) se confondent ;
//   · la période est adossée à ce que la boucle DEMANDE (attente de `REITERATION_DE_L_INTERRUPTION`, une
//     seule par tour, aucune autre attente bloquante dans `query_exec.rs`). Que l'attente demandée soit
//     TENUE par l'ordonnanceur, et que l'interruption notée soit bien émise (mutant `B4` de `P10.31-y`),
//     reste jugé au chronomètre par `annulation_reiteree.rs` ;
//   · le quota et l'annulation sur la même instruction sont FABRIQUÉS : la note de quota est posée sur ce
//     fil par une connexion voisine sous un quota négatif, puis l'annulation frappe la requête. C'est la
//     priorité de classement qui est jugée, pas un franchissement réel pendant une annulation.

#[cfg(test)]
mod annulation_proprietaire_et_ordre_structurel {
    use super::annulation_reiteree::{attendre_au_moins, compte, Instruments, ATTENTE_MAX, LONGUE, SUIVANTE};
    use crate::query_exec::{DemandeurDAnnulation, GesteDAnnulation, PasDeLaGarde};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    /// La route `/api/cancel` (gestionnaire `handlers::query::cancel`) jouée dans un exécuteur à part, sur CE
    /// fil. Rend le statut et le corps servis, entiers.
    fn route_cancel(st: &super::AppState, au: &super::AuthUser, qid: &str) -> (u16, serde_json::Value) {
        let exec = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("exécuteur de test");
        exec.block_on(async {
            let r = crate::handlers::query::cancel(
                axum::extract::State(st.clone()),
                axum::Extension(au.clone()),
                axum::Json(serde_json::json!({ "qid": qid })),
            )
            .await;
            let statut = r.status().as_u16();
            let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            (statut, serde_json::from_slice(&corps).expect("corps JSON"))
        })
    }

    /// Le qid tel que `/api/query` le fait circuler pour `au`.
    fn qid_lie(au: &super::AuthUser, qid: &str) -> String {
        crate::query_exec::qid_d_annulation_de_la_requete(&serde_json::json!({ "qid": qid }), au)
            .expect("un qid non vide doit être lié")
    }

    /// Laisse un énoncé ACTIF sur la connexion : tant qu'il vit, SQLite n'efface plus le drapeau
    /// d'interruption au début de l'analyse (`if( db->nVdbeActive==0 )`).
    fn enonce_actif(c: &Connection) -> rusqlite::Statement<'_> {
        let mut s = c.prepare("SELECT 1 UNION ALL SELECT 2").unwrap();
        {
            let mut rows = s.raw_query();
            assert!(rows.next().unwrap().is_some(), "instrument : l'énoncé actif n'a rendu aucune ligne");
            std::mem::forget(rows);
        }
        s
    }

    /// LA DÉCISION, JOUÉE PAR LA ROUTE : la requête d'Alice (lectrice) n'est annulable que par Alice ou par
    /// un admin. Bob (éditeur, même base) reçoit EXACTEMENT la réponse d'un qid inconnu, et la requête
    /// d'Alice finit entière.
    #[test]
    fn la_route_cancel_n_atteint_que_les_requetes_de_l_appelant_ou_d_un_admin() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // run_on_conn lit PLUME_QUERY_MAX
        let (st, _p) = super::sp_state("apo-proprietaire");
        let (alice, bob, adm) = (super::sp_au("alice", "viewer"), super::sp_au("bob", "editor"), super::sp_au("adm", "admin"));
        let base = crate::req_db_path(&st, &alice);
        assert_eq!(base, crate::req_db_path(&st, &bob), "instrument : les comptes doivent partager la base");
        let qid = "qid-d-alice";
        let lie = qid_lie(&alice, qid);
        let c = Connection::open_in_memory().unwrap();
        let _i = Instruments::poser(&Arc::new(AtomicUsize::new(0)));
        // La réponse d'un qid INCONNU, prise avant toute requête en vol.
        let reference = route_cancel(&st, &bob, qid);
        assert_eq!(reference, (200, serde_json::json!({ "cancelled": 0, "qid": qid })), "instrument : réponse d'un qid inconnu");

        // (1) Bob annule le qid d'Alice pendant que la requête d'Alice est en vol.
        let vue_par_bob = Arc::new(parking_lot::Mutex::new(None));
        {
            let (st, bob, vue) = (st.clone(), bob.clone(), vue_par_bob.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                *vue.lock() = Some(route_cancel(&st, &bob, qid));
            })));
        }
        let r = crate::query_exec::run_on_conn(&c, &base, SUIVANTE, 600_000, Some(&lie));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        assert_eq!(
            vue_par_bob.lock().clone(),
            Some(reference.clone()),
            "Bob doit recevoir EXACTEMENT la réponse d'un qid inconnu : rien ne doit trahir que le qid d'Alice est en vol"
        );
        let v = r.unwrap_or_else(|e| panic!("la requête d'Alice a été annulée par Bob : {e}"));
        assert_eq!(compte(&v), 2_000_000, "la requête d'Alice doit finir entière malgré l'annulation de Bob");

        // (2) Alice annule son propre qid ; (3) un admin annule le qid d'Alice.
        for (qui, au) in [("Alice", &alice), ("l'admin", &adm)] {
            let atteintes = Arc::new(AtomicU32::new(u32::MAX));
            {
                let (st, au, atteintes) = (st.clone(), au.clone(), atteintes.clone());
                crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                    let (_, corps) = route_cancel(&st, &au, qid);
                    atteintes.store(corps["cancelled"].as_u64().unwrap_or(u64::MAX) as u32, Ordering::SeqCst);
                })));
            }
            let r = crate::query_exec::run_on_conn(&c, &base, LONGUE, 600_000, Some(&lie));
            crate::query_exec::avant_la_preparation_de_ce_fil(None);
            assert_eq!(atteintes.load(Ordering::SeqCst), 1, "l'annulation par {qui} doit atteindre la requête d'Alice");
            assert_eq!(r.expect_err("la requête annulée doit être abandonnée"), "requête annulée par l'utilisateur", "annulée par {qui}");
        }
    }

    /// LA FORME LIÉE NE SE FORGE PAS. Le client ne contrôle que la queue : un qid qui imite la forme liée
    /// au nom de Bob reste la requête d'Alice. Le nom est lu par sa LONGUEUR : un nom qui contient `:` ou
    /// des caractères sur plusieurs octets est relu entier.
    #[test]
    fn un_qid_lie_ne_se_forge_pas_et_le_nom_se_lit_par_sa_longueur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // run_on_conn lit PLUME_QUERY_MAX
        let (st, _p) = super::sp_state("apo-forge");
        let (alice, bob) = (super::sp_au("alice", "viewer"), super::sp_au("bob", "viewer"));
        let base = crate::req_db_path(&st, &alice);
        let c = Connection::open_in_memory().unwrap();

        let imite = "\u{1}3:bobx";
        let drapeau = Arc::new(AtomicBool::new(false));
        let entree = crate::query_exec::cancel_register(&base, &qid_lie(&alice, imite), c.get_interrupt_handle(), drapeau.clone());
        for q in [imite, "x", "bobx"] {
            assert_eq!(
                crate::query_exec::annuler_les_requetes_de(&base, q, &DemandeurDAnnulation::de(&bob)),
                0,
                "Bob a atteint la requête d'Alice par le qid {q:?}"
            );
        }
        assert!(!drapeau.load(Ordering::SeqCst), "la requête d'Alice a été annulée par Bob");
        assert_eq!(crate::query_exec::annuler_les_requetes_de(&base, imite, &DemandeurDAnnulation::de(&alice)), 1, "Alice annule son qid");
        drop(entree);

        let (proprio, voisin) = (super::sp_au("é:lo", "viewer"), super::sp_au("é", "viewer"));
        let drapeau = Arc::new(AtomicBool::new(false));
        let entree = crate::query_exec::cancel_register(&base, &qid_lie(&proprio, "q:1"), c.get_interrupt_handle(), drapeau.clone());
        assert_eq!(crate::query_exec::annuler_les_requetes_de(&base, "q:1", &DemandeurDAnnulation::de(&voisin)), 0, "un nom préfixe n'est pas le propriétaire");
        assert_eq!(crate::query_exec::annuler_les_requetes_de(&base, "lo:q:1", &DemandeurDAnnulation::de(&voisin)), 0, "le nom est lu par sa longueur");
        assert_eq!(crate::query_exec::annuler_les_requetes_de(&base, "q:1", &DemandeurDAnnulation::de(&proprio)), 1, "le propriétaire annule son qid");
        assert!(drapeau.load(Ordering::SeqCst));
        drop(entree);
        assert_eq!(qid_lie(&alice, "  q  "), qid_lie(&alice, "q"), "le qid du client est rogné comme avant");
        assert!(
            crate::query_exec::qid_d_annulation_de_la_requete(&serde_json::json!({ "qid": "  " }), &alice).is_none(),
            "un qid vide n'enregistre rien, comme avant"
        );
    }

    /// Les défauts de liaison du gestionnaire `/api/query` dans un source : la déclaration de `qid_owned`
    /// doit passer par `qid_d_annulation_de_la_requete(&body, &au)`, et aucune autre ligne de code ne lit
    /// le qid du corps hors de la route `/api/cancel`.
    fn fautes_de_liaison(source: &str) -> Vec<String> {
        let code: Vec<&str> = source.lines().map(str::trim).filter(|l| !l.starts_with("//")).collect();
        let mut fautes = Vec::new();
        let decl: Vec<&&str> = code.iter().filter(|l| l.contains("let qid_owned")).collect();
        if decl.len() != 1 || !decl[0].contains("crate::query_exec::qid_d_annulation_de_la_requete(&body, &au)") {
            fautes.push(format!("déclaration de qid_owned non liée : {decl:?}"));
        }
        for l in code.iter().filter(|l| l.contains("\"qid\"")) {
            if *l != "let qid = b.trimmed(\"qid\");" && *l != "Json(json!({ \"cancelled\": n, \"qid\": qid })).into_response()" {
                fautes.push(format!("lecture du qid hors liaison : {l}"));
            }
        }
        fautes
    }

    /// `/api/query` LIE TOUJOURS le qid à son appelant (témoin STATIQUE : voir l'aveu en tête de fichier).
    #[test]
    fn la_route_query_lie_le_qid_a_son_proprietaire() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let src = std::fs::read_to_string(racine.join("handlers").join("query.rs")).expect("handlers/query.rs lisible");
        let fautes = fautes_de_liaison(&src);
        assert!(fautes.is_empty(), "/api/query ne lie plus le qid à son appelant : {fautes:?}");
        // Contrôles HOSTILES de l'instrument.
        let ancienne = "    let qid_owned: Option<String> = body.get(\"qid\").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());";
        assert!(!fautes_de_liaison(ancienne).is_empty(), "l'instrument ne voit pas la forme d'avant P10.32-c");
        let liee = "    let qid_owned: Option<String> = crate::query_exec::qid_d_annulation_de_la_requete(&body, &au);";
        assert!(fautes_de_liaison(liee).is_empty(), "l'instrument accuse la forme liée");
        assert!(
            !fautes_de_liaison(&format!("{liee}\n    let autre = body.get(\"qid\");")).is_empty(),
            "l'instrument ne voit pas une seconde lecture du qid"
        );
    }

    /// L'ORDRE « DRAPEAU D'ABORD », jugé au geste de la route : juste après le réveil de la garde, et juste
    /// après l'interruption immédiate, le drapeau `cancelled` est déjà posé. Aucune fenêtre de temps.
    #[test]
    fn le_drapeau_est_pose_avant_le_reveil_et_avant_l_interruption() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // run_on_conn lit PLUME_QUERY_MAX
        let (st, _p) = super::sp_state("apo-ordre");
        let alice = super::sp_au("alice", "viewer");
        let base = crate::req_db_path(&st, &alice);
        let c = Connection::open_in_memory().unwrap();
        let _i = Instruments::poser(&Arc::new(AtomicUsize::new(0)));
        let garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 600_000);
        let drapeau = Arc::new(AtomicBool::new(false));
        let entree = crate::query_exec::cancel_register(
            &base,
            &qid_lie(&alice, "qid-ordre"),
            c.get_interrupt_handle(),
            crate::query_exec::DrapeauDAnnulation::avec_reveil(drapeau.clone(), garde.reveil()),
        );
        crate::query_exec::temoin_des_gestes_d_annulation_de_ce_fil(Some(Vec::new()));
        let (_, corps) = route_cancel(&st, &alice, "qid-ordre");
        let gestes = crate::query_exec::temoin_des_gestes_d_annulation_de_ce_fil(None).expect("témoin posé");
        drop(entree);
        drop(garde);
        assert_eq!(corps["cancelled"], 1, "instrument : la route n'a rien atteint");
        assert_eq!(
            gestes,
            vec![(GesteDAnnulation::Reveil, true), (GesteDAnnulation::Interruption, true)],
            "le drapeau doit être posé AVANT le réveil et avant l'interruption : sinon la requête interrompue lit \
             `cancelled = false` et sort classée budget"
        );
    }

    /// L'INTERRUPTION IMMÉDIATE frappe la requête AVANT que la route rende la main. Entrée SANS réveil (rien
    /// d'autre ne peut interrompre), connexion qui garde un énoncé actif (SQLite n'efface plus le drapeau) :
    /// l'analyse suivante, sur ce même fil et après le retour de la route, est interrompue.
    #[test]
    fn l_interruption_immediate_frappe_avant_que_la_route_rende_la_main() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // run_on_conn lit PLUME_QUERY_MAX
        let (st, _p) = super::sp_state("apo-immediate");
        let alice = super::sp_au("alice", "viewer");
        let base = crate::req_db_path(&st, &alice);
        let c = Connection::open_in_memory().unwrap();
        let actif = enonce_actif(&c);
        drop(c.prepare("SELECT 1 AS x").expect("instrument : l'analyse doit réussir avant l'annulation"));
        let drapeau = Arc::new(AtomicBool::new(false));
        let entree = crate::query_exec::cancel_register(&base, &qid_lie(&alice, "qid-immediat"), c.get_interrupt_handle(), drapeau.clone());
        let (_, corps) = route_cancel(&st, &alice, "qid-immediat");
        assert_eq!(corps["cancelled"], 1, "instrument : la route n'a rien atteint");
        let apres = c.prepare("SELECT 1 AS x").map(drop);
        drop(entree);
        drop(actif);
        match apres {
            Err(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::OperationInterrupted => {}
            autre => panic!("l'annulation n'a pas interrompu la connexion avant de rendre la main : {autre:?}"),
        }
    }

    /// UNE ANNULATION ET UN QUOTA SUR LA MÊME INSTRUCTION : le quota, seule cause qui laisse une note, est
    /// rendu — jamais « annulée » — et sa note est consommée.
    #[test]
    fn un_quota_franchi_pendant_une_annulation_est_rendu_comme_quota() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // run_on_conn lit PLUME_QUERY_MAX
        let (st, _p) = super::sp_state("apo-quota");
        let alice = super::sp_au("alice", "viewer");
        let base = crate::req_db_path(&st, &alice);
        let dir = crate::tmp_possede::TmpPossede::neuf("apo-quota-et-annulation");
        let chemin = dir.to_path_buf();
        // Une connexion voisine sous un quota NÉGATIF : la première mesure le franchit, la note est posée
        // sur CE fil, l'instruction voisine est arrêtée.
        let poser_la_note = move || {
            let voisine = Connection::open_in_memory().unwrap();
            crate::sqlite_plafond::poser_la_surveillance_du_quota(&voisine, chemin.clone(), -1);
            voisine.query_row(SUIVANTE, [], |r| r.get::<_, i64>(0)).is_err()
        };
        crate::sqlite_plafond::oublier_refus_de_quota();
        assert!(poser_la_note(), "instrument : la voisine n'a pas été arrêtée par le quota");
        assert!(crate::sqlite_plafond::refus_de_quota_de_deversement().is_some(), "instrument : aucune note de quota posée");

        let lie = qid_lie(&alice, "qid-quota");
        let c = Connection::open_in_memory().unwrap();
        let _i = Instruments::poser(&Arc::new(AtomicUsize::new(0)));
        let atteintes = Arc::new(AtomicU32::new(u32::MAX));
        let note_posee = Arc::new(AtomicBool::new(false));
        {
            let (st, alice, atteintes, note_posee) = (st.clone(), alice.clone(), atteintes.clone(), note_posee.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                note_posee.store(poser_la_note(), Ordering::SeqCst);
                let (_, corps) = route_cancel(&st, &alice, "qid-quota");
                atteintes.store(corps["cancelled"].as_u64().unwrap_or(u64::MAX) as u32, Ordering::SeqCst);
            })));
        }
        let r = crate::query_exec::run_on_conn(&c, &base, LONGUE, 600_000, Some(&lie));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        assert!(note_posee.load(Ordering::SeqCst), "instrument : la note de quota n'a pas été posée avant la requête");
        assert_eq!(atteintes.load(Ordering::SeqCst), 1, "instrument : l'annulation n'a pas atteint la requête");
        let err = r.expect_err("la requête annulée et hors quota doit échouer");
        assert!(err.contains("quota de déversement dépassé"), "le quota doit l'emporter sur l'annulation : {err}");
        assert!(!err.contains("annulée"), "un franchissement de quota rendu comme une annulation : {err}");
        assert!(crate::sqlite_plafond::refus_de_quota_de_deversement().is_none(), "la note de quota survit à sa requête");
    }

    /// Attend que le drapeau passe à `true` ; au-delà de `ATTENTE_MAX`, refuse de conclure (rend `false`).
    fn attendre_le_drapeau(a: &AtomicBool) -> bool {
        let t0 = Instant::now();
        while !a.load(Ordering::SeqCst) {
            if t0.elapsed() > ATTENTE_MAX {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    /// LE RÉVEIL ATTEINT UNE GARDE DONT L'ATTENTE EST CONSTATÉE, sans délai : la garde pose son témoin sous
    /// son verrou juste avant d'attendre, et le réveil prend ce verrou. Une garde réveillée sans notification
    /// attendrait son échéance (dix minutes) et le témoin refuserait de conclure.
    #[test]
    fn une_annulation_reveille_une_garde_dont_l_attente_est_constatee() {
        let (cle, qid) = (":memory:apo-garde-qui-attend", "qid-apo-garde-qui-attend");
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let attend = Arc::new(AtomicBool::new(false));
        let _i = Instruments::poser(&n);
        crate::query_exec::temoin_de_l_attente_de_ce_fil(Some(attend.clone()));
        let garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 600_000);
        crate::query_exec::temoin_de_l_attente_de_ce_fil(None);
        let drapeau = Arc::new(AtomicBool::new(false));
        let entree = crate::query_exec::cancel_register(
            cle,
            qid,
            c.get_interrupt_handle(),
            crate::query_exec::DrapeauDAnnulation::avec_reveil(drapeau.clone(), garde.reveil()),
        );
        assert!(attendre_le_drapeau(&attend), "instrument : la garde n'est jamais entrée dans son attente");
        assert_eq!(n.load(Ordering::SeqCst), 0, "instrument : la garde a interrompu avant toute annulation");
        let adm = super::sp_au("adm", "admin");
        assert_eq!(
            crate::query_exec::annuler_les_requetes_de(cle, qid, &DemandeurDAnnulation::de(&adm)),
            1,
            "instrument : l'annulation n'a rien atteint"
        );
        assert!(attendre_au_moins(&n, 1), "la garde qui attendait n'a pas été réveillée par l'annulation");
        drop(entree);
        drop(garde);
    }

    /// LA PÉRIODE, JUGÉE SUR CE QUE LA BOUCLE DEMANDE : sur le fil de la garde, chaque interruption est suivie
    /// d'UNE attente de `REITERATION_DE_L_INTERRUPTION`, puis de l'interruption suivante. Aucun chronomètre.
    #[test]
    fn la_garde_n_attend_entre_deux_interruptions_que_la_periode() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let deroule = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let _i = Instruments::poser(&n);
        crate::query_exec::temoin_du_deroule_de_ce_fil(Some(deroule.clone()));
        let garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
        crate::query_exec::temoin_du_deroule_de_ce_fil(None);
        assert!(attendre_au_moins(&n, 16), "instrument : la garde expirée n'a pas réitéré seize fois");
        drop(garde);
        let pas = deroule.lock().clone();
        let periode = crate::query_exec::REITERATION_DE_L_INTERRUPTION;
        assert!(pas.len() >= 31, "instrument : déroulé trop court ({} pas)", pas.len());
        for (i, p) in pas.iter().enumerate() {
            let attendu = if i % 2 == 0 { PasDeLaGarde::Interruption } else { PasDeLaGarde::Attente(periode) };
            assert_eq!(*p, attendu, "pas {i} du déroulé de la garde : {:?}", &pas[..pas.len().min(i + 3)]);
        }
    }

    /// Les lignes de CODE de `query_exec.rs` qui bloquent le fil (attente de condition, sommeil, parcage,
    /// réception) : il ne doit y en avoir que les deux attentes de la garde.
    fn attentes_bloquantes(source: &str) -> Vec<String> {
        const PRIMITIVES: [&str; 7] = [".wait", "sleep(", "park(", "park_timeout(", ".recv", "yield_now", "spin_loop"];
        source
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            .filter(|l| PRIMITIVES.iter().any(|p| l.contains(p)))
            .map(str::to_string)
            .collect()
    }

    /// La boucle de la garde n'attend que par ses deux attentes : celle de l'échéance et celle de la période
    /// (`attendre_la_reiteration`, dont le déroulé ci-dessus juge l'argument). Témoin STATIQUE.
    #[test]
    fn la_boucle_de_la_garde_n_attend_que_par_ses_deux_attentes() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let qe = std::fs::read_to_string(racine.join("query_exec.rs")).expect("query_exec.rs lisible");
        const REITERATION: &str = "interrupteur.attendre_la_reiteration(&g.woke, &mut etat, periode);";
        assert_eq!(
            attentes_bloquantes(&qe),
            vec![
                "woke.wait_while_for(etat, |e| !e.fini, demandee);".to_string(),
                "g.woke.wait_while_for(&mut etat, |e| !e.fini && !e.annulee, budget);".to_string(),
            ],
            "query_exec.rs bloque ailleurs que par les deux attentes de la garde : la période ne se lit plus sur ce \
             que la boucle demande"
        );
        assert_eq!(qe.matches(REITERATION).count(), 1, "la boucle de la garde n'attend plus par `attendre_la_reiteration`");
        for hostile in ["std::thread::sleep(d);", "g.woke.wait_for(&mut etat, d);", "std::thread::park_timeout(d);", "rx.recv()"] {
            assert_eq!(attentes_bloquantes(hostile).len(), 1, "l'instrument ne voit pas l'attente : {hostile}");
        }
        assert!(attentes_bloquantes("    // sleep dans un commentaire").is_empty(), "l'instrument accuse un commentaire");
    }
}
