// =====================================================================================
// `P10.20-l`, `P10.33-h`, `P10.29-l` (rapports planifiés) — LA DÉFINITION D'UN RAPPORT SE LIT EN TROIS ISSUES, ET
// LE TEXTE DU MOTEUR NE PART NI AU CLIENT NI DANS `last_error`.
//
// VU (re-mesuré au commit de départ, `handlers/scheduled_reports.rs`) :
// (a) les trois lectures de définition de `deliver_report` (rapport, jeu de données, canal) étaient
//     `.map_err(|_| "… introuvable ou désactivé")` : une ligne qui ne se décode pas, une table hors d'atteinte, se
//     servaient en 400 « introuvable ou désactivé » par `POST /api/scheduled-reports/{id}/run`, alors que la route
//     venait de lire le rapport en trois issues ;
// (b) le tick (`run_due_reports`) avalait ces issues (`Ok(Err(_)) => {}`) : une définition non lue, un jeu de données
//     ou un canal désactivé ne laissaient ni compte, ni ligne de journal, ni `last_error` — le rapport dû restait
//     invisible ;
// (c) l'échec d'exécution (`run_query_ex`) était écrit tel quel dans `last_error`, servi par la liste des rapports
//     (lecteur) et par le 400 de `/run` : pour une erreur du moteur, son texte, qui peut citer l'énoncé compilé.
//
// CE QUE CES TÉMOINS JOUENT : le routeur RÉEL (compte éditeur, liste lue en lecteur), le gestionnaire de `/run` sur
// deux tenants réels (mode 1), le point d'entrée du tick (`run_due_reports`) avec un notificateur intercepté (aucun
// réseau) ; chaque lecture rendue illisible SEULE (une valeur BLOB sur sa ligne) ; l'exécution refusée par une
// connexion de lecture déposée dans le pool de la base, dont l'autorisateur refuse la lecture de `event` ; le journal
// lu en entier sur le stderr d'un sous-processus ; deux ticks sans remise à zéro de `last_error` (la trace « déjà
// posée » jugée par lecture) ; un rapport désactivé pendant l'envoi d'un autre (le rapport plus dû) ; le tenant de la
// ligne du moteur sur un rapport créé par l'éditeur d'un tenant ; les phrases réelles de la mémoire sans plafond dur et
// du quota de déversement. Mutants joués un par branche (retirés avant le commit).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (aucun écran n'appelle `/api/scheduled-reports`) ; les phrases de
// plume que `run_query_ex` ne rend pas sans `qid` (annulation par l'utilisateur) ; la ligne du tick ne nomme pas le
// tenant (le tick ne le connaît que par le chemin de sa base, qui ne va pas au journal).
// =====================================================================================
mod rapport_planifie_definition_et_moteur_en_trois_issues {
    use super::*;
    use crate::handlers::scheduled_reports::{
        classer_l_echec_d_execution, render_report_detail, run_due_reports, temoin_d_envoi, EchecDuRendu,
        CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_CANAL_NON_LU, CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_JEU_DE_DONNEES_NON_LU,
        CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU, EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE, RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT,
        RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT,
    };
    use crate::mesure_environnement::Mesure;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const AO4_NOM: &str = "ao4-rapport-confidentiel";
    const AO4_URL: &str = "https://ao4:credence-ao4@198.51.100.41/hook";
    const AO4_MDP_EDITEUR: &str = "editeur-ao4-0123456789";
    const AO4_GXQL_CASSE: &str = "search | where (((";
    /// Au plus autant d'essais pour que la connexion armée serve (le pool de lecture est global, éviction entre bases).
    const AO4_ESSAIS: usize = 40;
    const AO4_RUN: &str = "/api/scheduled-reports/43/run";
    const AO4_LISTE: &str = "/api/scheduled-reports";
    const AO4_ALPHA: &str = "ao4-alpha";
    const AO4_BETA: &str = "ao4-beta";
    /// Le rapport que l'éditeur de beta crée par la route (`report_create` persiste SON tenant) : le second de la base de
    /// beta, après celui de la fixture.
    const AO4_NOM_CREE: &str = "ao4_cree_par_beta";
    const AO4_ID_CREE: i64 = 44;
    /// Remet la fixture d'aplomb : tout activé, valeurs textuelles, statut vierge, aucun déclencheur de refus.
    const AO4_RESTAURER: &str = "DROP TRIGGER IF EXISTS ao4_trace; \
         UPDATE scheduled_report SET run_as_role='viewer', enabled=1, last_run=0, last_ok=0, last_error=NULL, last_count=0 WHERE id=43; \
         UPDATE dataset SET soql='search | table message', enabled=1 WHERE id=41; \
         UPDATE notifier SET config='{}', enabled=1 WHERE id=42;";
    const AO4_RAPPORT_ILLISIBLE: &str = "UPDATE scheduled_report SET run_as_role=CAST(run_as_role AS BLOB) WHERE id=43";
    const AO4_JEU_ILLISIBLE: &str = "UPDATE dataset SET soql=CAST(soql AS BLOB) WHERE id=41";
    const AO4_CANAL_ILLISIBLE: &str = "UPDATE notifier SET config=CAST(config AS BLOB) WHERE id=42";
    const AO4_RAPPORT_DESACTIVE: &str = "UPDATE scheduled_report SET enabled=0 WHERE id=43";
    const AO4_JEU_DESACTIVE: &str = "UPDATE dataset SET enabled=0 WHERE id=41";
    const AO4_CANAL_DESACTIVE: &str = "UPDATE notifier SET enabled=0 WHERE id=42";
    const AO4_JEU_CASSE: &str = "UPDATE dataset SET soql='search | where (((' WHERE id=41";
    const AO4_TRACE_REFUSEE: &str = "CREATE TRIGGER ao4_trace BEFORE UPDATE OF last_error ON scheduled_report \
         BEGIN SELECT RAISE(ABORT,'trace refusee par le temoin ao4'); END;";
    const AO4_TRACE_SANS_EFFET: &str =
        "CREATE TRIGGER ao4_trace BEFORE UPDATE OF last_error ON scheduled_report BEGIN SELECT RAISE(IGNORE); END;";
    /// Ce que le moteur dit des trois lectures illisibles : au journal seul.
    const AO4_MOTEUR_RAPPORT: &str = "Invalid column type Blob at index: 3, name: run_as_role";
    const AO4_MOTEUR_JEU: &str = "Invalid column type Blob at index: 0, name: soql";
    const AO4_MOTEUR_CANAL: &str = "Invalid column type Blob at index: 2, name: config";
    /// Ce que le moteur dit de l'exécution refusée par l'autorisateur (lecture de `event`) : au journal seul.
    const AO4_MOTEUR_EXECUTION: &str = "access to event.ts is prohibited";
    const AO4_ENFANT: &str = "AO4_ENFANT_JOURNAL";
    const AO4_RENDU: &str = "AO4-RENDU:";
    const AO4_FIN: &str = "AO4-FIN:";

    type EtatDuRapport = (i64, i64, Option<String>);

    fn ao4_sql(db: &Arc<Mutex<Connection>>, sql: &str) {
        db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    /// Un événement, un jeu de données, un canal d'un genre inconnu (aucun réseau : l'envoi rend faux), un rapport dû.
    fn ao4_semer(c: &Connection) {
        c.execute(
            "INSERT INTO event(ts,source,category,severity,host,message,src_ip) VALUES(?1,'ao4','auth',3,'h1','contenu ao4','192.0.2.11')",
            params![now()],
        )
        .expect("fixture : événement");
        c.execute("INSERT INTO dataset(id,name,soql) VALUES(41,'ao4-ds','search | table message')", []).expect("fixture : jeu de données");
        c.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(42,'ao4-n','temoin-ao4',1,?1,0,'{}')",
            params![AO4_URL],
        )
        .expect("fixture : canal");
        c.execute("INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(43,?1,41,42,3600)", params![AO4_NOM])
            .expect("fixture : rapport");
    }

    /// Base mode 0 du routeur réel, semée, avec un compte éditeur.
    fn ao4_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, base) = router_test_state(&format!("ao4-{tag}"));
        {
            let c = st.db.lock();
            ao4_semer(&c);
            c.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(AO4_MDP_EDITEUR).unwrap()])
                .expect("fixture : compte éditeur");
        }
        (st, base)
    }

    fn ao4_evenements(db: &Arc<Mutex<Connection>>) -> i64 {
        db.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).expect("contrôle : événements comptés")
    }

    fn ao4_etat_du_rapport(db: &Arc<Mutex<Connection>>) -> EtatDuRapport {
        ao4_etat_de(db, 43)
    }

    fn ao4_etat_de(db: &Arc<Mutex<Connection>>, id: i64) -> EtatDuRapport {
        db.lock()
            .query_row("SELECT last_run,last_ok,last_error FROM scheduled_report WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("contrôle : état du rapport relu")
    }

    fn ao4_editeur() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt:{AO4_MDP_EDITEUR}")))
    }

    async fn ao4_envoi(addr: std::net::SocketAddr, methode: &str, chemin: &str, authz: &str) -> (u16, String) {
        let (code, brut) = router_probe_envoi(addr, methode, chemin, Some(authz), &[("Content-Type", "application/json")], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    /// Dépose dans le pool de `chemin` une connexion de lecture dont l'autorisateur refuse la lecture de `event`, après
    /// avoir vidé les connexions au repos de cette base. Le drapeau dit si le refus a été joué.
    fn ao4_armer_le_refus_de_l_execution(chemin: &str) -> Arc<AtomicBool> {
        ao4_desarmer(chemin);
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        let drapeau = joue.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name.eq_ignore_ascii_case("event") => {
                drapeau.store(true, Ordering::SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    fn ao4_desarmer(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    /// La phrase de compilation que plume écrit pour le GXQL cassé (servie telle quelle).
    fn ao4_phrase_de_compilation(chemin: &str) -> String {
        match render_report_detail(chemin, AO4_NOM, "viewer", "", AO4_GXQL_CASSE) {
            Err(EchecDuRendu::Plume(p)) => p,
            autre => panic!("instrument : le GXQL cassé doit être refusé par plume à la compilation : {autre:?}"),
        }
    }

    struct Ao4Rendu {
        issue: String,
        statut: u16,
        corps: String,
        etat: EtatDuRapport,
        /// Événements de la base au moment de l'appel : les lignes qu'un rapport sain rend (la base semée en porte
        /// d'autres que celui de la fixture).
        evenements: i64,
    }

    async fn ao4_cas(st: &AppState, addr: std::net::SocketAddr, issue: &str, panne: &str, authz: &str, methode: &str, route: &str) -> Ao4Rendu {
        if !panne.is_empty() {
            ao4_sql(&st.db, panne);
        }
        let (statut, corps) = ao4_envoi(addr, methode, route, authz).await;
        Ao4Rendu { issue: issue.to_string(), statut, corps, etat: ao4_etat_du_rapport(&st.db), evenements: ao4_evenements(&st.db) }
    }

    /// LA ROUTE : chaque issue dans l'ordre, la fixture remise d'aplomb avant chacune.
    async fn ao4_jouer_la_route() -> Vec<Ao4Rendu> {
        let (st, base) = ao4_etat("route");
        let chemin = base.as_str().to_string();
        let addr = router_serve(st.clone()).await;
        let ed = ao4_editeur();
        let lecteur = viewer_authz();
        let mut r = Vec::new();
        let cas: [(&str, &str, &str, &str, &str); 10] = [
            ("absent", "", "POST", "/api/scheduled-reports/999/run", "editeur"),
            ("lecteur", "", "POST", AO4_RUN, "lecteur"),
            ("nominal", "", "POST", AO4_RUN, "editeur"),
            ("rapport_desactive", AO4_RAPPORT_DESACTIVE, "POST", AO4_RUN, "editeur"),
            ("jeu_desactive", AO4_JEU_DESACTIVE, "POST", AO4_RUN, "editeur"),
            ("canal_desactive", AO4_CANAL_DESACTIVE, "POST", AO4_RUN, "editeur"),
            ("rapport_illisible", AO4_RAPPORT_ILLISIBLE, "POST", AO4_RUN, "editeur"),
            ("jeu_illisible", AO4_JEU_ILLISIBLE, "POST", AO4_RUN, "editeur"),
            ("canal_illisible", AO4_CANAL_ILLISIBLE, "POST", AO4_RUN, "editeur"),
            ("compilation_refusee", AO4_JEU_CASSE, "POST", AO4_RUN, "editeur"),
        ];
        for (issue, panne, methode, route, qui) in cas {
            ao4_sql(&st.db, AO4_RESTAURER);
            let authz = if qui == "lecteur" { &lecteur } else { &ed };
            r.push(ao4_cas(&st, addr, issue, panne, authz, methode, route).await);
        }
        // La liste, lue au rôle le plus faible admis (lecteur), après l'échec de compilation consigné.
        r.push(ao4_cas(&st, addr, "liste_apres_compilation", "", &lecteur, "GET", AO4_LISTE).await);
        // L'exécution refusée par la base : la connexion armée doit servir l'exécution de ce déclenchement.
        let mut servi = None;
        for _ in 0..AO4_ESSAIS {
            ao4_sql(&st.db, AO4_RESTAURER);
            let joue = ao4_armer_le_refus_de_l_execution(&chemin);
            let rendu = ao4_cas(&st, addr, "moteur_refuse", "", &ed, "POST", AO4_RUN).await;
            if joue.load(Ordering::SeqCst) {
                servi = Some(rendu);
                break;
            }
        }
        ao4_desarmer(&chemin);
        r.push(servi.unwrap_or_else(|| panic!("instrument : la connexion armée n'a servi /run en aucun des {AO4_ESSAIS} essais")));
        r.push(ao4_cas(&st, addr, "liste_apres_moteur", "", &lecteur, "GET", AO4_LISTE).await);
        r
    }

    fn ao4_corps_nominal(r: &Ao4Rendu) -> String {
        assert!(r.evenements >= 1, "contrôle : {} : la base porte l'événement de la fixture", r.issue);
        json!({ "ok": true, "rows": r.evenements, "delivered": false, "marque_ecrite": true, "statut_ecrit": true }).to_string()
    }

    /// Un 503 nommé : exactement `{error, id}`, la cause attendue, un identifiant de corrélation ; rend l'identifiant.
    fn ao4_refus_nomme(r: &Ao4Rendu, cause: &str) -> String {
        assert_eq!(r.statut, 503, "{} : 503 nommé : {}", r.issue, r.corps);
        let v: Value = serde_json::from_str(&r.corps).unwrap_or_else(|e| panic!("{} : corps JSON ({e}) : {}", r.issue, r.corps));
        let cles: Vec<&String> = v.as_object().map(|o| o.keys().collect()).unwrap_or_default();
        assert_eq!(cles, vec!["error", "id"], "{} : exactement error et id : {}", r.issue, r.corps);
        assert_eq!(v["error"], json!(cause), "{} : la cause nommée : {}", r.issue, r.corps);
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "{} : identifiant de corrélation : {}", r.issue, r.corps);
        id
    }

    fn ao4_trouver<'a>(rendus: &'a [Ao4Rendu], issue: &str) -> &'a Ao4Rendu {
        rendus.iter().find(|r| r.issue == issue).unwrap_or_else(|| panic!("issue {issue} jouée"))
    }

    /// (1) LA ROUTE : corps entiers, état du rapport relu après chaque appel.
    #[tokio::test]
    async fn ao4_route_corps_et_etat() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let rendus = ao4_jouer_la_route().await;
        assert_eq!(rendus.len(), 13, "contrôle : treize issues jouées");
        let vierge: EtatDuRapport = (0, 0, None);
        let r = ao4_trouver(&rendus, "absent");
        assert_eq!((r.statut, r.corps.clone()), (404, json!({ "error": "rapport introuvable" }).to_string()), "bras d'avant : absent");
        let r = ao4_trouver(&rendus, "lecteur");
        assert_eq!((r.statut, r.corps.clone()), (403, "lecture seule (rôle viewer)".to_string()), "bras d'avant : lecteur refusé par le routeur (texte du routeur)");
        assert_eq!(r.etat, vierge, "lecteur refusé : rien n'est écrit");
        let r = ao4_trouver(&rendus, "nominal");
        assert_eq!((r.statut, r.corps.clone()), (200, ao4_corps_nominal(r)), "contrôle positif : rapport sain exécuté");
        assert!(r.etat.0 > 0, "contrôle positif : marque d'échéance écrite : {:?}", r.etat);
        assert_eq!(r.etat.2.as_deref(), Some(crate::handlers::scheduled_reports::ENVOI_REFUSE_PAR_LE_NOTIFICATEUR), "statut d'après envoi écrit");
        // Absent ou désactivé : la phrase d'avant, à l'octet, et rien d'écrit par la route.
        for (issue, phrase) in [
            ("rapport_desactive", "rapport introuvable ou désactivé"),
            ("jeu_desactive", "dataset introuvable ou désactivé"),
            ("canal_desactive", "notifier introuvable ou désactivé"),
        ] {
            let r = ao4_trouver(&rendus, issue);
            assert_eq!((r.statut, r.corps.clone()), (400, json!({ "error": phrase }).to_string()), "{issue} : la phrase d'avant");
            assert_eq!(r.etat, vierge, "{issue} : la route n'écrit rien");
        }
        // Lecture ratée : 503 nommé, ni marque ni last_error.
        for (issue, cause) in [
            ("rapport_illisible", CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_NON_LU),
            ("jeu_illisible", CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_JEU_DE_DONNEES_NON_LU),
            ("canal_illisible", CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_CANAL_NON_LU),
        ] {
            let r = ao4_trouver(&rendus, issue);
            ao4_refus_nomme(r, cause);
            assert_eq!(r.etat, vierge, "{issue} : le 503 n'écrit ni last_run ni last_error");
        }
        // Échec de compilation : la phrase de plume, servie et consignée telle quelle.
        let phrase = ao4_phrase_de_compilation(":memory:ao4-compilation");
        let r = ao4_trouver(&rendus, "compilation_refusee");
        assert_eq!((r.statut, r.corps.clone()), (400, json!({ "error": phrase, "marque_ecrite": true }).to_string()), "phrase de compilation servie");
        assert!(r.etat.0 > 0 && r.etat.2.as_deref() == Some(phrase.as_str()), "phrase de compilation consignée : {:?}", r.etat);
        let r = ao4_trouver(&rendus, "liste_apres_compilation");
        let v: Value = serde_json::from_str(&r.corps).unwrap_or(Value::Null);
        assert_eq!(r.statut, 200, "{}", r.corps);
        assert_eq!(v["reports"].as_array().map(|a| a.len()), Some(1), "un rapport listé : {}", r.corps);
        assert_eq!(v["reports"][0]["last_error"], json!(phrase), "la liste sert la phrase de compilation : {}", r.corps);
        // Exécution refusée par la base : phrase fixe au client, dans last_error et dans la liste.
        let r = ao4_trouver(&rendus, "moteur_refuse");
        assert_eq!(
            (r.statut, r.corps.clone()),
            (400, json!({ "error": EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE, "marque_ecrite": true }).to_string()),
            "exécution refusée : phrase fixe"
        );
        assert!(r.etat.0 > 0 && r.etat.2.as_deref() == Some(EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE), "phrase fixe consignée : {:?}", r.etat);
        let r = ao4_trouver(&rendus, "liste_apres_moteur");
        let v: Value = serde_json::from_str(&r.corps).unwrap_or(Value::Null);
        assert_eq!(r.statut, 200, "{}", r.corps);
        assert_eq!(v["reports"][0]["last_error"], json!(EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE), "la liste sert la phrase fixe : {}", r.corps);
        for r in &rendus {
            for moteur in [AO4_MOTEUR_RAPPORT, AO4_MOTEUR_JEU, AO4_MOTEUR_CANAL, AO4_MOTEUR_EXECUTION, "prohibited", "Invalid column"] {
                assert!(!r.corps.contains(moteur), "{} : aucun texte du moteur au client : {}", r.issue, r.corps);
            }
            assert!(!r.corps.contains("credence-ao4") && !r.corps.contains("198.51.100.41"), "{} : jamais l'endpoint : {}", r.issue, r.corps);
        }
    }

    // ---------------- le tick ----------------

    fn ao4_compter_les_envois() -> Rc<Cell<u32>> {
        let n = Rc::new(Cell::new(0u32));
        let m = n.clone();
        temoin_d_envoi::poser(move |_k, _t, _d| {
            m.set(m.get() + 1);
            true
        });
        n
    }

    /// Un tick, fixture remise d'aplomb puis panne posée : (bilan, envois, état).
    fn ao4_tick(st: &AppState, chemin: &str, panne: &[&str]) -> (Mesure<u32>, u32, EtatDuRapport) {
        ao4_sql(&st.db, AO4_RESTAURER);
        for p in panne {
            ao4_sql(&st.db, p);
        }
        let envois = ao4_compter_les_envois();
        let b = run_due_reports(&st.db, chemin);
        temoin_d_envoi::retirer();
        (b, envois.get(), ao4_etat_du_rapport(&st.db))
    }

    /// Le tick dont l'exécution est refusée par la base (connexion armée), rejoué jusqu'à ce qu'elle serve.
    fn ao4_tick_moteur_refuse(st: &AppState, chemin: &str) -> (Mesure<u32>, u32, EtatDuRapport) {
        for _ in 0..AO4_ESSAIS {
            ao4_sql(&st.db, AO4_RESTAURER);
            let joue = ao4_armer_le_refus_de_l_execution(chemin);
            let envois = ao4_compter_les_envois();
            let b = run_due_reports(&st.db, chemin);
            temoin_d_envoi::retirer();
            if joue.load(Ordering::SeqCst) {
                ao4_desarmer(chemin);
                return (b, envois.get(), ao4_etat_du_rapport(&st.db));
            }
        }
        panic!("instrument : la connexion armée n'a servi le tick en aucun des {AO4_ESSAIS} essais");
    }

    /// (2) LE TICK : chaque lecture illisible seule est un abandon compté, rien d'écrit ; jeu de données ou canal
    /// désactivé : `last_error` à phrase fixe, écrite une fois ; trace refusée ou sans effet : comptée ; exécution
    /// refusée par la base : phrase fixe ; contrôle positif.
    #[test]
    fn ao4_tick_issues_comptes_et_traces() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'exécution lit l'environnement
        let (st, base) = ao4_etat("tick");
        let chemin = base.as_str().to_string();
        let vierge: EtatDuRapport = (0, 0, None);

        let (b, envois, etat) = ao4_tick(&st, &chemin, &[]);
        assert_eq!((b, envois), (Mesure::Lue(0), 1), "contrôle positif : un envoi, aucun abandon");
        assert!(etat.0 > 0 && etat.1 == etat.0 && etat.2.is_none(), "contrôle positif : marque et statut écrits : {etat:?}");

        for (issue, panne) in [("rapport", AO4_RAPPORT_ILLISIBLE), ("jeu", AO4_JEU_ILLISIBLE), ("canal", AO4_CANAL_ILLISIBLE)] {
            let (b, envois, etat) = ao4_tick(&st, &chemin, &[panne]);
            assert_eq!((b, envois), (Mesure::Lue(1), 0), "{issue} illisible : un abandon compté, aucun envoi");
            assert_eq!(etat, vierge, "{issue} illisible : ni marque ni last_error");
        }

        for (issue, panne, trace) in [
            ("jeu", AO4_JEU_DESACTIVE, RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT),
            ("canal", AO4_CANAL_DESACTIVE, RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT),
        ] {
            let (b, envois, etat) = ao4_tick(&st, &chemin, &[panne]);
            assert_eq!((b, envois), (Mesure::Lue(0), 0), "{issue} désactivé : aucun envoi, pas un abandon");
            assert_eq!(etat, (0, 0, Some(trace.to_string())), "{issue} désactivé : la trace fixe dans last_error, aucune marque");
            // Trace déjà posée : le tick suivant ne la récrit pas (une écriture refusée serait comptée).
            ao4_sql(&st.db, AO4_TRACE_REFUSEE);
            let envois = ao4_compter_les_envois();
            let b = run_due_reports(&st.db, &chemin);
            temoin_d_envoi::retirer();
            assert_eq!((b, envois.get()), (Mesure::Lue(0), 0), "{issue} : trace déjà posée, aucune écriture tentée");
            assert_eq!(ao4_etat_du_rapport(&st.db), (0, 0, Some(trace.to_string())), "{issue} : trace inchangée");
        }

        let (b, envois, etat) = ao4_tick(&st, &chemin, &[AO4_TRACE_REFUSEE, AO4_JEU_DESACTIVE]);
        assert_eq!((b, envois, etat.clone()), (Mesure::Lue(1), 0, vierge.clone()), "trace refusée : comptée, rien d'écrit");
        let (b, envois, etat) = ao4_tick(&st, &chemin, &[AO4_TRACE_SANS_EFFET, AO4_CANAL_DESACTIVE]);
        assert_eq!((b, envois, etat), (Mesure::Lue(1), 0, vierge.clone()), "trace sans effet : comptée comme un refus");

        // Un last_error d'un type inattendu ne rend pas la définition illisible : le rapport part.
        let (b, envois, etat) = ao4_tick(&st, &chemin, &["UPDATE scheduled_report SET last_error=CAST('ancienne' AS BLOB) WHERE id=43"]);
        assert_eq!((b, envois), (Mesure::Lue(0), 1), "last_error BLOB : la définition se lit, le rapport part");
        assert!(etat.0 > 0 && etat.2.is_none(), "last_error BLOB : le succès l'efface : {etat:?}");

        let phrase = ao4_phrase_de_compilation(&chemin);
        let (b, envois, etat) = ao4_tick(&st, &chemin, &[AO4_JEU_CASSE]);
        assert_eq!((b, envois), (Mesure::Lue(0), 0), "compilation refusée : consignée, aucun envoi");
        assert!(etat.0 > 0 && etat.2.as_deref() == Some(phrase.as_str()), "compilation : la phrase de plume consignée : {etat:?}");

        let (b, envois, etat) = ao4_tick_moteur_refuse(&st, &chemin);
        assert_eq!((b, envois), (Mesure::Lue(0), 0), "exécution refusée : consignée, aucun envoi");
        assert!(etat.0 > 0 && etat.2.as_deref() == Some(EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE), "exécution refusée : phrase fixe : {etat:?}");
    }

    /// (3) UN ABANDON PAR RAPPORT NON LU : deux rapports dus sur le même jeu de données illisible comptent deux.
    #[test]
    fn ao4_tick_un_abandon_par_rapport_non_lu() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, base) = ao4_etat("deux-rapports");
        ao4_sql(&st.db, "INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(44,'ao4-second',41,42,3600)");
        ao4_sql(&st.db, AO4_JEU_ILLISIBLE);
        let envois = ao4_compter_les_envois();
        let b = run_due_reports(&st.db, base.as_str());
        temoin_d_envoi::retirer();
        assert_eq!((b, envois.get()), (Mesure::Lue(2), 0), "deux rapports non lus : deux abandons, aucun envoi");
    }

    /// (4) LA LISTE BLANCHE DES PHRASES DE PLUME DE L'EXÉCUTION, entrée par entrée ; tout autre texte est du moteur, même
    /// s'il contient une ouverture ailleurs qu'en tête.
    #[test]
    fn ao4_phrases_de_plume_de_l_execution_par_ouverture() {
        let plume = |e: &str| assert_eq!(classer_l_echec_d_execution(e.to_string()), EchecDuRendu::Plume(e.to_string()), "phrase de plume : {e}");
        let moteur = |e: &str| assert_eq!(classer_l_echec_d_execution(e.to_string()), EchecDuRendu::Moteur(e.to_string()), "texte du moteur : {e}");
        plume("requête interrompue (budget 10 s dépassé)");
        plume("budget mémoire dépassé : cette requête a demandé plus que les 64 Mio concédés à SQLite. AUCUN résultat n'est rendu.");
        plume("mémoire épuisée pendant l'exécution (aucun plafond dur n'est appliqué). AUCUN résultat n'est rendu.");
        plume("quota de déversement dépassé : les tris de ce processus détiennent 9 Mio en clair hors de la base chiffrée.");
        moteur("no such table: event");
        moteur(AO4_MOTEUR_EXECUTION);
        moteur("near \"requête interrompue (budget \": syntax error");
        moteur("requête annulée par l'utilisateur");
    }

    /// (5) LES PHRASES RÉELLES : le budget franchi et le manque de mémoire, tels que `run_on_conn` les rend, sont des
    /// phrases de plume ; une erreur de pas du moteur ne l'est pas.
    #[test]
    fn ao4_phrases_reelles_de_l_execution() {
        use rusqlite::functions::FunctionFlags;
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let c = Connection::open_in_memory().unwrap();
        let e = crate::query_exec::run_on_conn(
            &c,
            ":memory:ao4-budget",
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1000000000) SELECT count(*) FROM c",
            1,
            None,
        )
        .expect_err("instrument : budget d'une milliseconde franchi");
        assert!(e.starts_with("requête interrompue (budget"), "instrument : phrase du budget : {e}");
        assert_eq!(classer_l_echec_d_execution(e.clone()), EchecDuRendu::Plume(e));
        c.create_scalar_function("ao4_manque_de_memoire", 1, FunctionFlags::SQLITE_UTF8, |_| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOMEM), None))
        })
        .unwrap();
        let e = crate::query_exec::run_on_conn(&c, ":memory:ao4-memoire", "SELECT ao4_manque_de_memoire(1)", 600_000, None)
            .expect_err("instrument : manque de mémoire au pas");
        assert_eq!(classer_l_echec_d_execution(e.clone()), EchecDuRendu::Plume(e));
        let e = crate::query_exec::run_on_conn(&c, ":memory:ao4-pas", "SELECT abs(-9223372036854775807 - 1)", 600_000, None)
            .expect_err("instrument : erreur de pas");
        assert_eq!(classer_l_echec_d_execution(e.clone()), EchecDuRendu::Moteur(e));
    }

    /// (8) LA TRACE « DÉJÀ POSÉE » EST CELLE DE LA LECTURE QUI MANQUE, JUGÉE PAR LECTURE : deux ticks, deux lectures
    /// différentes, sans remise à zéro de `last_error` entre eux. Le jeu de données revient et le canal manque : la trace
    /// du canal remplace celle du jeu (une trace « déjà posée » qui accepterait l'autre laisserait dire « dataset
    /// introuvable », faux) ; puis l'inverse.
    #[test]
    fn ao4_tick_trace_de_la_lecture_qui_manque() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, base) = ao4_etat("deux-traces");
        let chemin = base.as_str().to_string();
        for (premiere, trace_1, reactiver, seconde, trace_2) in [
            (
                AO4_JEU_DESACTIVE,
                RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT,
                "UPDATE dataset SET enabled=1 WHERE id=41",
                AO4_CANAL_DESACTIVE,
                RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT,
            ),
            (
                AO4_CANAL_DESACTIVE,
                RAPPORT_DU_NON_EXECUTE_CANAL_ABSENT,
                "UPDATE notifier SET enabled=1 WHERE id=42",
                AO4_JEU_DESACTIVE,
                RAPPORT_DU_NON_EXECUTE_JEU_DE_DONNEES_ABSENT,
            ),
        ] {
            let (b, envois, etat) = ao4_tick(&st, &chemin, &[premiere]);
            assert_eq!((b, envois, etat), (Mesure::Lue(0), 0, (0, 0, Some(trace_1.to_string()))), "premier tick : la trace de {premiere}");
            // Sans remise à zéro : la première référence revient, l'autre manque.
            ao4_sql(&st.db, reactiver);
            ao4_sql(&st.db, seconde);
            let envois = ao4_compter_les_envois();
            let b = run_due_reports(&st.db, &chemin);
            temoin_d_envoi::retirer();
            assert_eq!(
                (b, envois.get(), ao4_etat_du_rapport(&st.db)),
                (Mesure::Lue(0), 0, (0, 0, Some(trace_2.to_string()))),
                "second tick ({seconde}) : la trace de la lecture qui manque remplace l'autre"
            );
        }
    }

    /// (9) LE RAPPORT LUI-MÊME DÉSACTIVÉ ENTRE LA SÉLECTION ET SA LECTURE : il n'est plus dû — ni trace, ni compte, ni
    /// envoi. Deux rapports dus ; l'envoi du premier (le verrou est relâché pendant l'envoi) désactive l'autre.
    #[test]
    fn ao4_tick_rapport_desactive_depuis_la_selection() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, base) = ao4_etat("desactive-en-cours");
        let chemin = base.as_str().to_string();
        ao4_sql(&st.db, "INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES(44,'ao4-second',41,42,3600)");
        // Contrôle : les deux sont dus et partent quand rien ne les désactive.
        let envois = ao4_compter_les_envois();
        let b = run_due_reports(&st.db, &chemin);
        temoin_d_envoi::retirer();
        assert_eq!((b, envois.get()), (Mesure::Lue(0), 2), "contrôle : deux rapports dus, deux envois");
        ao4_sql(&st.db, "UPDATE scheduled_report SET last_run=0, last_ok=0, last_error=NULL, last_count=0");
        let db = st.db.clone();
        let envoyes: Rc<std::cell::RefCell<Vec<String>>> = Rc::new(std::cell::RefCell::new(Vec::new()));
        let vus = envoyes.clone();
        temoin_d_envoi::poser(move |_k, titre, _d| {
            if vus.borrow().is_empty() {
                let autre: i64 = if titre.ends_with(AO4_NOM) { 44 } else { 43 };
                db.lock().execute("UPDATE scheduled_report SET enabled=0 WHERE id=?1", params![autre]).expect("fixture : l'autre rapport désactivé");
            }
            vus.borrow_mut().push(titre.to_string());
            true
        });
        let b = run_due_reports(&st.db, &chemin);
        temoin_d_envoi::retirer();
        let envoyes = envoyes.borrow().clone();
        assert_eq!(envoyes.len(), 1, "un seul envoi : l'autre, désactivé pendant l'envoi, n'est plus dû : {envoyes:?}");
        let (servi, desactive) = if envoyes[0].ends_with(AO4_NOM) { (43, 44) } else { (44, 43) };
        assert_eq!(b, Mesure::Lue(0), "le rapport désactivé depuis la sélection n'est pas un abandon");
        assert_eq!(ao4_etat_de(&st.db, desactive), (0, 0, None), "désactivé depuis la sélection : ni marque, ni trace");
        let s = ao4_etat_de(&st.db, servi);
        assert!(s.0 > 0 && s.1 == s.0 && s.2.is_none(), "contrôle positif : le premier est servi : {s:?}");
    }

    /// (10) DEUX OUVERTURES DE LA LISTE BLANCHE TENUES PAR LEURS PRODUCTEURS RÉELS : la mémoire épuisée sans plafond dur
    /// (`PLUME_SQLITE_PLAFOND_DUR=0`, rendue par `message_erreur`, `sqlite_plafond.rs`) et le quota de déversement
    /// (rendu par la surveillance du quota, `quota_deversement.rs`) sont des phrases de plume. Une phrase changée chez son
    /// producteur passerait sinon en texte du moteur sans que rien ne le dise.
    #[test]
    fn ao4_phrases_reelles_sans_plafond_dur_et_quota() {
        use rusqlite::functions::FunctionFlags;
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write(); // la variable du plafond dur est posée puis rendue
        let c = Connection::open_in_memory().unwrap();
        c.create_scalar_function("ao4_manque_de_memoire", 1, FunctionFlags::SQLITE_UTF8, |_| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOMEM), None))
        })
        .unwrap();
        let avant = std::env::var("PLUME_SQLITE_PLAFOND_DUR").ok();
        std::env::set_var("PLUME_SQLITE_PLAFOND_DUR", "0");
        let r = crate::query_exec::run_on_conn(&c, ":memory:ao4-sans-plafond", "SELECT ao4_manque_de_memoire(1)", 600_000, None);
        match avant {
            Some(v) => std::env::set_var("PLUME_SQLITE_PLAFOND_DUR", v),
            None => std::env::remove_var("PLUME_SQLITE_PLAFOND_DUR"),
        }
        let e = r.expect_err("instrument : manque de mémoire au pas");
        assert!(e.contains("PLUME_SQLITE_PLAFOND_DUR=0)"), "instrument : la branche sans plafond dur est jouée : {e}");
        assert_eq!(classer_l_echec_d_execution(e.clone()), EchecDuRendu::Plume(e));
        // Un quota négatif est franchi à la première mesure (aucun déversement n'est nécessaire).
        let q = Connection::open_in_memory().unwrap();
        let dossier = crate::tmp_possede::TmpPossede::neuf("ao4-quota");
        crate::sqlite_plafond::poser_la_surveillance_du_quota(&q, dossier.to_path_buf(), -1);
        let e = crate::query_exec::run_on_conn(
            &q,
            ":memory:ao4-quota",
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000000) SELECT count(*) FROM c",
            600_000,
            None,
        )
        .expect_err("instrument : quota négatif franchi");
        assert!(e.contains("cette instruction est ARRÊTÉE"), "instrument : le refus du quota est rendu : {e}");
        assert_eq!(classer_l_echec_d_execution(e.clone()), EchecDuRendu::Plume(e));
    }

    // ---------------- deux tenants ----------------

    fn ao4_editeur_de(tenant: &str) -> AuthUser {
        AuthUser {
            name: "edt-ao4".into(),
            role: "editor".into(),
            tenant: tenant.into(),
            is_superadmin: false,
            method: "basic".into(),
            csrf: String::new(),
            env: None,
        }
    }

    async fn ao4_rendu(r: Response) -> (u16, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8_lossy(&b).into_owned())
    }

    async fn ao4_creer_le_tenant(st: &AppState, t: &str) -> Arc<Mutex<Connection>> {
        let (statut, corps) = ao4_rendu(
            tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-ao4")), Json(json!({ "id": t, "name": t })))
                .await,
        )
        .await;
        assert_eq!(statut, 201, "contrôle : tenant {t} créé : {corps}");
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        ao4_semer(&h.lock());
        h
    }

    async fn ao4_run_de(st: &AppState, t: &str, h: &Arc<Mutex<Connection>>, issue: &str) -> Ao4Rendu {
        ao4_run_du_rapport(st, t, h, 43, issue).await
    }

    async fn ao4_run_du_rapport(st: &AppState, t: &str, h: &Arc<Mutex<Connection>>, id: i64, issue: &str) -> Ao4Rendu {
        let (statut, corps) =
            ao4_rendu(crate::handlers::scheduled_reports::report_run_now(State(st.clone()), Extension(ao4_editeur_de(t)), axum::extract::Path(id)).await)
                .await;
        Ao4Rendu { issue: format!("{issue}:{t}"), statut, corps, etat: ao4_etat_de(h, id), evenements: ao4_evenements(h) }
    }

    /// Le rapport créé par l'éditeur du tenant `t`, par le gestionnaire réel de la création ; rend son identifiant.
    async fn ao4_creer_le_rapport_de(st: &AppState, t: &str) -> i64 {
        let corps_de_creation = json!({ "name": AO4_NOM_CREE, "dataset_id": 41, "notifier_id": 42, "run_as_role": "viewer", "interval_s": 3600 });
        let (statut, corps) = ao4_rendu(
            crate::handlers::scheduled_reports::report_create(State(st.clone()), Extension(ao4_editeur_de(t)), Json(corps_de_creation)).await,
        )
        .await;
        assert_eq!(statut, 200, "contrôle : rapport créé par l'éditeur de {t} : {corps}");
        serde_json::from_str::<Value>(&corps).ok().and_then(|v| v["id"].as_i64()).unwrap_or_else(|| panic!("contrôle : identifiant servi : {corps}"))
    }

    /// Deux tenants réels : alpha au jeu de données illisible pendant que beta est servi par SA base, puis beta au
    /// canal illisible pendant qu'alpha est servi.
    async fn ao4_jouer_deux_tenants() -> Vec<Ao4Rendu> {
        let (st, _dir) = mk_mode1_state();
        let alpha = ao4_creer_le_tenant(&st, AO4_ALPHA).await;
        let beta = ao4_creer_le_tenant(&st, AO4_BETA).await;
        let mut r = Vec::new();
        ao4_sql(&alpha, AO4_JEU_ILLISIBLE);
        r.push(ao4_run_de(&st, AO4_ALPHA, &alpha, "alpha_refusee").await);
        r.push(ao4_run_de(&st, AO4_BETA, &beta, "alpha_refusee").await);
        ao4_sql(&alpha, AO4_RESTAURER);
        ao4_sql(&beta, AO4_RESTAURER);
        ao4_sql(&beta, AO4_CANAL_ILLISIBLE);
        r.push(ao4_run_de(&st, AO4_BETA, &beta, "beta_refusee").await);
        r.push(ao4_run_de(&st, AO4_ALPHA, &alpha, "beta_refusee").await);
        // L'exécution refusée par la base chez beta, sur un rapport créé par l'éditeur de beta : le tenant que la ligne
        // du journal nomme est celui que la création a persisté.
        ao4_sql(&beta, AO4_RESTAURER);
        let id = ao4_creer_le_rapport_de(&st, AO4_BETA).await;
        assert_eq!(id, AO4_ID_CREE, "contrôle : le rapport créé est le second de la base de beta");
        let chemin_beta = crate::state::req_db_path(&st, &ao4_editeur_de(AO4_BETA));
        let mut servi = None;
        for _ in 0..AO4_ESSAIS {
            ao4_sql(&beta, &format!("UPDATE scheduled_report SET last_run=0, last_ok=0, last_error=NULL WHERE id={id}"));
            let joue = ao4_armer_le_refus_de_l_execution(&chemin_beta);
            let rendu = ao4_run_du_rapport(&st, AO4_BETA, &beta, id, "moteur_refuse").await;
            if joue.load(Ordering::SeqCst) {
                servi = Some(rendu);
                break;
            }
        }
        ao4_desarmer(&chemin_beta);
        r.push(servi.unwrap_or_else(|| panic!("instrument : la connexion armée n'a servi /run de beta en aucun des {AO4_ESSAIS} essais")));
        r
    }

    /// (6) DEUX TENANTS : le tenant à la lecture ratée reçoit le 503 nommé et n'écrit rien ; l'autre est exécuté par SA
    /// base (marque écrite chez lui seul) ; puis l'inverse ; puis l'exécution refusée par la base chez beta, sur le rapport
    /// créé par son éditeur (le tenant au journal est jugé par (7)).
    #[tokio::test]
    async fn ao4_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let rendus = ao4_jouer_deux_tenants().await;
        assert_eq!(rendus.len(), 5, "contrôle : cinq issues jouées");
        let r = ao4_trouver(&rendus, "alpha_refusee:ao4-alpha");
        ao4_refus_nomme(r, CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_JEU_DE_DONNEES_NON_LU);
        assert_eq!(r.etat, (0, 0, None), "alpha refusé : rien d'écrit chez alpha");
        let r = ao4_trouver(&rendus, "alpha_refusee:ao4-beta");
        assert_eq!((r.statut, r.corps.clone()), (200, ao4_corps_nominal(r)), "beta servi pendant le refus d'alpha");
        assert!(r.etat.0 > 0, "beta : marque écrite dans SA base : {:?}", r.etat);
        let r = ao4_trouver(&rendus, "beta_refusee:ao4-beta");
        ao4_refus_nomme(r, CAUSE_RAPPORT_PLANIFIE_NON_DECLENCHE_CANAL_NON_LU);
        assert_eq!(r.etat, (0, 0, None), "beta refusé : rien d'écrit chez beta");
        let r = ao4_trouver(&rendus, "beta_refusee:ao4-alpha");
        assert_eq!((r.statut, r.corps.clone()), (200, ao4_corps_nominal(r)), "alpha servi pendant le refus de beta");
        assert!(r.etat.0 > 0, "alpha : marque écrite dans SA base : {:?}", r.etat);
        let r = ao4_trouver(&rendus, "moteur_refuse:ao4-beta");
        assert_eq!(
            (r.statut, r.corps.clone()),
            (400, json!({ "error": EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE, "marque_ecrite": true }).to_string()),
            "beta, exécution refusée : phrase fixe"
        );
        assert!(r.etat.0 > 0 && r.etat.2.as_deref() == Some(EXECUTION_DU_RAPPORT_REFUSEE_PAR_LA_BASE), "beta : phrase fixe consignée : {:?}", r.etat);
        assert!(!r.corps.contains(AO4_MOTEUR_EXECUTION) && !r.corps.contains("prohibited"), "beta : aucun texte du moteur au client : {}", r.corps);
    }

    // ---------------- le journal ----------------

    /// Le tick, côté journal : les trois lectures illisibles, la trace refusée, l'exécution refusée par la base.
    fn ao4_jouer_le_tick_du_journal() -> Vec<String> {
        let (st, base) = ao4_etat("tick-journal");
        let chemin = base.as_str().to_string();
        let mut bilans = Vec::new();
        for panne in [AO4_RAPPORT_ILLISIBLE, AO4_JEU_ILLISIBLE, AO4_CANAL_ILLISIBLE] {
            bilans.push(format!("{:?}", ao4_tick(&st, &chemin, &[panne]).0));
        }
        bilans.push(format!("{:?}", ao4_tick(&st, &chemin, &[AO4_TRACE_REFUSEE, AO4_JEU_DESACTIVE]).0));
        bilans.push(format!("{:?}", ao4_tick_moteur_refuse(&st, &chemin).0));
        bilans
    }

    /// (7) LE JOURNAL, EN ENTIER, sur le stderr d'un sous-processus : une ligne par aveu, dans l'ordre ; l'identifiant
    /// du rapport, le tenant de l'appelant à la route, l'identifiant de corrélation servi, la cause du moteur ; jamais
    /// le nom du rapport ni l'endpoint du canal.
    #[tokio::test]
    async fn ao4_journal() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'enfant est désigné par l'environnement
        if std::env::var(AO4_ENFANT).is_ok() {
            for r in ao4_jouer_la_route().await {
                println!("{AO4_RENDU}{}", json!([format!("route:{}", r.issue), r.statut, r.corps]));
            }
            println!("{AO4_RENDU}{}", json!(["tick", 0, ao4_jouer_le_tick_du_journal().join(",")]));
            for r in ao4_jouer_deux_tenants().await {
                println!("{AO4_RENDU}{}", json!([format!("tenants:{}", r.issue), r.statut, r.corps]));
            }
            println!("{AO4_FIN}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::rapport_planifie_definition_et_moteur_en_trois_issues::ao4_journal"])
            .env(AO4_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(AO4_FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        let rendus: Vec<(String, u16, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AO4_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 13 + 1 + 5, "contrôle : toutes les issues rendues : {stdout}");
        let rendu = |issue: &str| rendus.iter().find(|(i, _, _)| i == issue).cloned().unwrap_or_else(|| panic!("issue {issue} : {stdout}"));
        assert_eq!(rendu("tick").2, "Lue(1),Lue(1),Lue(1),Lue(1),Lue(0)", "contrôle : bilans du tick");
        let cid = |issue: &str| -> String {
            let (_, statut, corps) = rendu(issue);
            assert_eq!(statut, 503, "contrôle : {issue} en 503 : {corps}");
            serde_json::from_str::<Value>(&corps).ok().and_then(|v| v["id"].as_str().map(str::to_string)).unwrap_or_else(|| panic!("identifiant : {corps}"))
        };
        let route = |tenant: &str, issue: &str, constat: &str, moteur: &str| {
            format!(
                "[rapports] WARN déclenchement du rapport planifié #43 (tenant '{tenant}') refusé : {constat}, rien n'est exécuté, envoyé ni écrit ({}) : {moteur}",
                cid(issue)
            )
        };
        let tick = |constat: &str, moteur: &str| {
            format!("[rapports] WARN rapport planifié #43 dû non exécuté : {constat}, rien n'est envoyé ni écrit, compté abandonné : {moteur}")
        };
        let execution = format!(
            "[rapports] WARN rapport planifié #43 (tenant '') : exécution refusée par la base, last_error porte une phrase fixe : {AO4_MOTEUR_EXECUTION}"
        );
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[rapports]") || l.starts_with("[plume] rapport planifié")).collect();
        let attendu: Vec<String> = vec![
            route("default", "route:rapport_illisible", "sa définition n'a pas pu être lue", AO4_MOTEUR_RAPPORT),
            route("default", "route:jeu_illisible", "son jeu de données n'a pas pu être lu", AO4_MOTEUR_JEU),
            route("default", "route:canal_illisible", "son canal n'a pas pu être lu", AO4_MOTEUR_CANAL),
            execution.clone(),
            tick("sa définition n'a pas pu être lue", AO4_MOTEUR_RAPPORT),
            tick("son jeu de données n'a pas pu être lu", AO4_MOTEUR_JEU),
            tick("son canal n'a pas pu être lu", AO4_MOTEUR_CANAL),
            "[plume] rapport planifié 43 : référence introuvable ou désactivée NON CONSIGNÉE (last_error) : trace refusee par le temoin ao4".to_string(),
            execution,
            route(AO4_ALPHA, "tenants:alpha_refusee:ao4-alpha", "son jeu de données n'a pas pu être lu", AO4_MOTEUR_JEU),
            route(AO4_BETA, "tenants:beta_refusee:ao4-beta", "son canal n'a pas pu être lu", AO4_MOTEUR_CANAL),
            // Le tenant persisté par la création, jamais une chaîne vide : la base de beta, le rapport de son éditeur.
            format!(
                "[rapports] WARN rapport planifié #{AO4_ID_CREE} (tenant '{AO4_BETA}') : exécution refusée par la base, last_error porte une phrase fixe : {AO4_MOTEUR_EXECUTION}"
            ),
        ];
        assert_eq!(journal, attendu, "une ligne EXACTE par aveu, dans l'ordre :\n{stderr}");
        for l in &journal {
            assert!(
                !l.contains(AO4_NOM) && !l.contains(AO4_NOM_CREE) && !l.contains("credence-ao4") && !l.contains("198.51.100.41"),
                "jamais le nom ni l'endpoint : {l}"
            );
        }
    }
}
