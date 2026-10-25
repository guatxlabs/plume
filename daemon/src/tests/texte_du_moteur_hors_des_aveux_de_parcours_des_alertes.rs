// =====================================================================================
// `P10.29-l` (restes AN : « les `{cause}` d'`alerts.rs` ») — LE TEXTE DU MOTEUR NE PART PLUS DANS LES QUATRE AVEUX DE
// PARCOURS D'`alerts.rs` : `/api/alerts`, `/api/alerts/groups`, `/api/coverage/detections` et `/api/coverage/attack`.
//
// LE DÉFAUT, LU SUR c6069774 AVANT LE CORRECTIF : `corps_de_liste_d_alertes`, `corps_de_liste_de_groupes`,
// `corps_de_couverture_des_detections` et `corps_de_matrice_attack` servaient `format!("{CAUSE_…}{cause}")`, où `cause`
// est `FinDeParcours::cause()`, un `e.to_string()` de rusqlite (`query_exec.rs`, `parcourir_chaque`, et les onze
// `NonCommence { cause: e.to_string() }` d'`alerts.rs`). Un lecteur recevait ainsi, dans un corps 200, le nom de table et
// de colonne refusés par la base (« access to alert.mitre is prohibited »), ou l'énoncé entier quand l'autorisateur
// refuse une fonction (mesuré par la vague AN sur le compte des mêmes listes).
//
// LE REMÈDE : chaque corps garde sa constante `CAUSE_…` en préfixe et la fait suivre d'une phrase fixe par classe
// (`phrase_de_la_fin`) : `FIN_DE_PARCOURS_INTERROMPUE` (le moteur a dit `SQLITE_INTERRUPT` : garde de budget ou annulation)
// ou `FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE` (toute autre cause). Le texte du moteur part à une ligne `[alerts] WARN` qui
// nomme l'objet parcouru (libellé fixe), la fin (interrompu / non commencé) et le tenant de l'appelant, écrite par les
// gestionnaires (`journaliser_la_fin_de_parcours`, même patron que `TotalDeListe::journaliser`).
//
// LES TÉMOINS :
// (1) `ao2_corps_servis_par_la_route` (routeur réel, mode 0, jeton lecteur) : chaque issue (nominale, refusée par la base,
//     interrompue) des quatre routes, plus la fenêtre d'engagement et la couverture scopée, corps comparé À L'OCTET ;
// (2) `ao2_journal_des_fins` : la même partie en sous-processus, lignes `[alerts] WARN` EN ENTIER, dans l'ordre ;
// (3) `ao2_classe_de_la_fin` : `phrase_de_la_fin` sur les textes que rusqlite écrit (avec et sans message de SQLite) ;
// (4) `ao2_corps_des_quatre_aveux` : les quatre fonctions de corps, appel direct, refus et interruption, corps entiers ;
// (5) `ao2_deux_tenants` : DEUX tenants réels (mode 1), gestionnaires appelés au rôle lecteur, sur les QUATRE routes
//     (alertes, groupes, couverture des détections, matrice ATT&CK) : la lecture refusée chez l'un rend la phrase fixe
//     et une ligne qui nomme CE tenant, pendant que l'autre est servi par SA base ; puis l'inverse. (Correction : les
//     groupes et la matrice n'y étaient pas ; un tenant `default` en dur dans ces deux appels restait vert.)
// (6) `ao2_deux_phrases_distinctes` : les deux phrases fixes, chacune à son littéral, et différentes l'une de l'autre
//     (les attendus des autres témoins sont construits sur ces mêmes symboles : un texte commun n'y rougirait pas).
// Pannes : une connexion de lecture DÉPOSÉE dans le pool de la base, armée soit d'un autorisateur qui refuse la SEULE
// PREMIÈRE lecture d'une colonne que seul l'énoncé visé lit, soit d'un rappel de progression qui interrompt le SEUL
// PREMIER pas (route à un seul énoncé). Le pool est global et borné : le témoin rejoue la requête tant que la connexion
// armée n'a pas servi, et le drapeau levé par la panne est l'instrument qui dit qu'elle a servi.
// L'interruption RÉELLE des quatre corps est aussi tenue par `troncature_sous_budget.rs` (inversé dans ce lot).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la matrice interrompue PAR LA ROUTE (ses énoncés de règles précèdent celui des
// alertes, la coupe par rappel de progression n'y est pas déterministe ; tenue par appel direct) ; le bras `Err` de
// `query_map` de la couverture globale (liaison d'un seul paramètre, sans panne atteignable : journalisé comme les
// autres, sans témoin) ; `FinDeParcours::cause()` servi ailleurs (`freshness.rs`, `detection.rs`, `admin_ui.rs`).
// =====================================================================================
mod aveux_de_parcours_sans_texte_du_moteur {
    use super::*;
    use crate::handlers::alerts::{
        corps_de_couverture_des_detections, corps_de_liste_d_alertes, corps_de_liste_de_groupes, corps_de_matrice_attack,
        phrase_de_la_fin, TotalDeListe, CAUSE_COMPTES_D_ALERTES_NON_ETABLIS, CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE,
        CAUSE_LISTE_DE_GROUPES_TRONQUEE, CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE,
        FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, Ordering};

    const AO2_ENFANT: &str = "AO2_ENFANT_JOURNAL";
    const AO2_RENDU: &str = "AO2-RENDU:";
    const AO2_FIN: &str = "AO2-FIN:";
    /// Au plus autant de requêtes pour que la connexion armée serve la route (le pool global peut l'évincer).
    const AO2_ESSAIS: usize = 40;
    const AO2_TENANT_MODE_0: &str = "default";
    const AO2_ENGAGEMENT: &str = "e-ao2";
    /// Les issues jouées par la route, dans l'ordre.
    const AO2_ORDRE: [&str; 13] = [
        "alertes_nominal", "alertes_refusee", "alertes_coupee", "groupes_nominal", "groupes_refusee",
        "detections_nominal", "detections_refusee", "detections_coupee", "scopee_nominal", "fenetre_refusee",
        "scopee_refusee", "matrice_nominale", "matrice_refusee",
    ];

    /// Ce qui arme la connexion déposée : le refus de la première lecture d'UNE colonne, ou la coupe du premier pas.
    #[derive(Clone, Copy)]
    enum Ao2Panne {
        Refus(&'static str, &'static str),
        Coupe,
    }

    fn ao2_moteur(panne: Ao2Panne) -> String {
        match panne {
            Ao2Panne::Refus(table, colonne) => format!("access to {table}.{colonne} is prohibited"),
            Ao2Panne::Coupe => "interrupted".to_string(),
        }
    }

    /// Dépose dans le pool de `chemin` une connexion de lecture armée de `panne`, après avoir vidé les connexions au
    /// repos de cette base (la connexion armée est la seule à prendre). Le drapeau rendu dit si la panne a été jouée.
    fn ao2_armer(chemin: &str, panne: Ao2Panne) -> Arc<AtomicBool> {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        let drapeau = joue.clone();
        match panne {
            Ao2Panne::Refus(table, colonne) => conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne && !drapeau.swap(true, Ordering::SeqCst) => {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            })),
            Ao2Panne::Coupe => conn.progress_handler(1, Some(move || !drapeau.swap(true, Ordering::SeqCst))),
        }
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    async fn ao2_envoi(addr: std::net::SocketAddr, chemin: &str) -> (u16, String) {
        let (code, brut) = router_probe_envoi(addr, "GET", chemin, Some(&viewer_authz()), &[], "").await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        (code, corps)
    }

    async fn ao2_en_panne(addr: std::net::SocketAddr, base: &str, route: &str, panne: Ao2Panne) -> (u16, String) {
        for _ in 0..AO2_ESSAIS {
            let joue = ao2_armer(base, panne);
            let rendu = ao2_envoi(addr, route).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi {route} en aucun des {AO2_ESSAIS} essais — le témoin ne conclut pas");
    }

    const REFUS_PAGE_D_ALERTES: Ao2Panne = Ao2Panne::Refus("incident_item", "incident_id");
    const REFUS_PAGE_DE_GROUPES: Ao2Panne = Ao2Panne::Refus("alert", "title");
    const REFUS_TECHNIQUES: Ao2Panne = Ao2Panne::Refus("alert", "mitre");
    const REFUS_FENETRE: Ao2Panne = Ao2Panne::Refus("engagement", "window_start");
    const REFUS_SCOPEE: Ao2Panne = Ao2Panne::Refus("alert", "engagement_id");

    struct Ao2Jeu {
        rendus: Vec<(&'static str, u16, String)>,
        /// La matrice attendue sans compte d'alertes, puis avec les comptes de la fixture (règles lues sur la même base).
        matrice_sans_comptes: Value,
        matrice_comptee: Value,
    }

    async fn ao2_jouer() -> Ao2Jeu {
        let mut rendus: Vec<(&'static str, u16, String)> = Vec::new();
        let (st, base) = router_test_state("ao2-routes");
        let chemin = base.as_str().to_string();
        st.db
            .lock()
            .execute_batch(&format!(
                "DELETE FROM incident_item; DELETE FROM alert; DELETE FROM engagement;
                 INSERT INTO engagement(id,name,box,scope,window_start,window_end,status,created) VALUES('{AO2_ENGAGEMENT}','n','blackbox','[]',0,5000,'active',0);
                 INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources,engagement_id) VALUES(1000,'rule.ao2a',2,'Alerte AO2 A','','new','T1046','','{AO2_ENGAGEMENT}');
                 INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources,engagement_id) VALUES(1001,'rule.ao2b',3,'Alerte AO2 B','','new','T1046','','{AO2_ENGAGEMENT}');"
            ))
            .expect("fixture : engagement et deux alertes");
        let (matrice_sans_comptes, matrice_comptee) = {
            let c = st.db.lock();
            let lecture = crate::detection_aveugle::lire_la_couverture_des_regles(&c);
            let comptes: HashMap<String, i64> = HashMap::from([("T1046".to_string(), 2)]);
            (
                build_attack_matrix(&lecture.tirent, &lecture.en_attente_de_source, &lecture.eteintes, &HashMap::new()),
                build_attack_matrix(&lecture.tirent, &lecture.en_attente_de_source, &lecture.eteintes, &comptes),
            )
        };
        let addr = router_serve(st.clone()).await;
        let scopee = format!("/api/coverage/detections?engagement={AO2_ENGAGEMENT}");

        let (s, c) = ao2_envoi(addr, "/api/alerts?status=all").await;
        rendus.push(("alertes_nominal", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/alerts?status=all", REFUS_PAGE_D_ALERTES).await;
        rendus.push(("alertes_refusee", s, c));
        // Le backlog (statut `new`, sans pagination) n'a pas de compte : son seul énoncé est la page, coupée au premier pas.
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/alerts", Ao2Panne::Coupe).await;
        rendus.push(("alertes_coupee", s, c));
        let (s, c) = ao2_envoi(addr, "/api/alerts/groups?group=rule").await;
        rendus.push(("groupes_nominal", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/alerts/groups?group=rule", REFUS_PAGE_DE_GROUPES).await;
        rendus.push(("groupes_refusee", s, c));
        let (s, c) = ao2_envoi(addr, "/api/coverage/detections").await;
        rendus.push(("detections_nominal", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/coverage/detections", REFUS_TECHNIQUES).await;
        rendus.push(("detections_refusee", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/coverage/detections", Ao2Panne::Coupe).await;
        rendus.push(("detections_coupee", s, c));
        let (s, c) = ao2_envoi(addr, &scopee).await;
        rendus.push(("scopee_nominal", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, &scopee, REFUS_FENETRE).await;
        rendus.push(("fenetre_refusee", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, &scopee, REFUS_SCOPEE).await;
        rendus.push(("scopee_refusee", s, c));
        let (s, c) = ao2_envoi(addr, "/api/coverage/attack").await;
        rendus.push(("matrice_nominale", s, c));
        let (s, c) = ao2_en_panne(addr, &chemin, "/api/coverage/attack", REFUS_TECHNIQUES).await;
        rendus.push(("matrice_refusee", s, c));
        Ao2Jeu { rendus, matrice_sans_comptes, matrice_comptee }
    }

    fn ao2_aveu(cause: &str, phrase: &str) -> Value {
        json!(format!("{cause}{phrase}"))
    }

    /// (1) LES CORPS SERVIS PAR LA ROUTE : chaque issue comparée à l'octet, contrôles positifs compris.
    #[tokio::test]
    async fn ao2_corps_servis_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let jeu = ao2_jouer().await;
        let issues: Vec<&str> = jeu.rendus.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(issues, AO2_ORDRE.to_vec(), "chaque issue est jouée une fois, dans l'ordre");
        let rendu = |issue: &str| -> (u16, String) {
            jeu.rendus.iter().find(|(i, _, _)| *i == issue).map(|(_, s, c)| (*s, c.clone())).unwrap_or_else(|| panic!("issue {issue} jouée"))
        };

        // Contrôles positifs : les deux listes nominales sont comptées et complètes, sans aveu.
        let (s, c) = rendu("alertes_nominal");
        let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
        assert!(
            s == 200 && v["total"] == json!(2) && v["alerts"].as_array().map(|a| a.len()) == Some(2) && v.get("error").is_none() && v.get("total_error").is_none(),
            "contrôle : liste nominale complète, comptée, sans aveu : {s} {c}"
        );
        let (s, c) = rendu("groupes_nominal");
        let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
        assert!(
            s == 200 && v["total"] == json!(2) && v["groups"].as_array().map(|a| a.len()) == Some(2) && v.get("error").is_none(),
            "contrôle : groupes nominaux complets, comptés, sans aveu : {s} {c}"
        );

        let mut alertes_refusee = json!({ "alerts": [] });
        alertes_refusee["total"] = json!(2);
        alertes_refusee["error"] = ao2_aveu(CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let mut alertes_coupee = json!({ "alerts": [] });
        alertes_coupee["error"] = ao2_aveu(CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE);
        let mut groupes_refusee = json!({ "groups": [], "group": "rule" });
        groupes_refusee["total"] = json!(2);
        groupes_refusee["error"] = ao2_aveu(CAUSE_LISTE_DE_GROUPES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let detections = json!([{ "mitre": "T1046", "count": 2, "first_ts": 1000 }]);
        let mut detections_refusee = json!({ "detections": [] });
        detections_refusee["error"] = ao2_aveu(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let mut detections_coupee = json!({ "detections": [] });
        detections_coupee["error"] = ao2_aveu(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE);
        let mut fenetre_refusee = json!({ "detections": [], "engagement": AO2_ENGAGEMENT });
        fenetre_refusee["error"] = ao2_aveu(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let mut scopee_refusee = json!({ "detections": [], "engagement": AO2_ENGAGEMENT, "window_start": 0, "window_end": 5000 });
        scopee_refusee["error"] = ao2_aveu(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let mut matrice_refusee = jeu.matrice_sans_comptes.clone();
        matrice_refusee["error"] = ao2_aveu(CAUSE_COMPTES_D_ALERTES_NON_ETABLIS, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);

        let lus: Vec<(&str, (u16, String))> = AO2_ORDRE.iter().filter(|i| !matches!(**i, "alertes_nominal" | "groupes_nominal")).map(|i| (*i, rendu(*i))).collect();
        let attendus: Vec<(&str, (u16, String))> = vec![
            ("alertes_refusee", (200, alertes_refusee.to_string())),
            ("alertes_coupee", (200, alertes_coupee.to_string())),
            ("groupes_refusee", (200, groupes_refusee.to_string())),
            ("detections_nominal", (200, json!({ "detections": detections }).to_string())),
            ("detections_refusee", (200, detections_refusee.to_string())),
            ("detections_coupee", (200, detections_coupee.to_string())),
            ("scopee_nominal", (200, json!({ "detections": detections, "engagement": AO2_ENGAGEMENT, "window_start": 0, "window_end": 5000 }).to_string())),
            ("fenetre_refusee", (200, fenetre_refusee.to_string())),
            ("scopee_refusee", (200, scopee_refusee.to_string())),
            ("matrice_nominale", (200, jeu.matrice_comptee.to_string())),
            ("matrice_refusee", (200, matrice_refusee.to_string())),
        ];
        assert_eq!(lus, attendus, "chaque corps à l'octet : la constante en préfixe, la phrase fixe de la classe, jamais le moteur");
        for (issue, _, brut) in &jeu.rendus {
            for trace in ["prohibited", "access to", "interrupted", "incident_item", "engagement_id"] {
                assert!(!brut.contains(trace), "{issue} : le corps porte « {trace} » : {brut}");
            }
        }
    }

    /// (2) LE JOURNAL : une ligne `[alerts] WARN` par fin ratée, EN ENTIER, qui nomme l'objet, la fin et le tenant.
    #[tokio::test]
    async fn ao2_journal_des_fins() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AO2_ENFANT).is_ok() {
            let jeu = ao2_jouer().await;
            for (issue, statut, _) in &jeu.rendus {
                println!("{AO2_RENDU} {issue} {statut}");
            }
            println!("{AO2_FIN} {}", jeu.rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::aveux_de_parcours_sans_texte_du_moteur::ao2_journal_des_fins"])
            .env(AO2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{AO2_FIN} {}", AO2_ORDRE.len())), "contrôle : l'enfant a joué toutes ses issues : {stdout}\n{stderr}");
        assert_eq!(stdout.lines().filter(|l| l.contains(AO2_RENDU)).count(), AO2_ORDRE.len(), "contrôle : une ligne par issue : {stdout}");
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[alerts] WARN")).collect();
        let t = AO2_TENANT_MODE_0;
        assert_eq!(
            journal,
            vec![
                format!("[alerts] WARN parcours de la liste d'alertes non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_PAGE_D_ALERTES)),
                format!("[alerts] WARN parcours de la liste d'alertes interrompu (tenant '{t}') : {}", ao2_moteur(Ao2Panne::Coupe)),
                format!("[alerts] WARN parcours de la liste de groupes par rule non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_PAGE_DE_GROUPES)),
                format!("[alerts] WARN parcours de la couverture des détections non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
                format!("[alerts] WARN parcours de la couverture des détections interrompu (tenant '{t}') : {}", ao2_moteur(Ao2Panne::Coupe)),
                format!("[alerts] WARN parcours de la fenêtre d'un engagement non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_FENETRE)),
                format!("[alerts] WARN parcours de la couverture des détections d'un engagement non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_SCOPEE)),
                format!("[alerts] WARN parcours des alertes par technique non commencé (tenant '{t}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
            ],
            "une ligne EXACTE par fin ratée, le texte du moteur au journal seul, aucune pour une issue nominale :\n{stderr}"
        );
    }

    /// (3) LA CLASSE D'UNE FIN RATÉE : seul ce que rusqlite écrit pour `SQLITE_INTERRUPT` (message de SQLite, ou
    /// description du code sans message) se dit « interrompu » ; tout autre texte est un refus de la base.
    #[test]
    fn ao2_classe_de_la_fin() {
        let sans_message = |code: std::ffi::c_int| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None).to_string();
        let interruption_sans_message = sans_message(rusqlite::ffi::SQLITE_INTERRUPT);
        assert_ne!(interruption_sans_message, "interrupted", "contrôle : les deux textes de l'interruption sont distincts");
        let lus = vec![
            ("message", phrase_de_la_fin("interrupted")),
            ("sans_message", phrase_de_la_fin(&interruption_sans_message)),
            ("refus", phrase_de_la_fin("access to alert.mitre is prohibited")),
            ("autorisateur", phrase_de_la_fin("not authorized to use function: COUNT in SELECT COUNT(*) FROM alert at offset 7")),
            ("ioerr", phrase_de_la_fin(&sans_message(rusqlite::ffi::SQLITE_IOERR))),
            ("mappeur", phrase_de_la_fin("Invalid column type Text at index: 1, name: n")),
            ("vide", phrase_de_la_fin("")),
        ];
        assert_eq!(
            lus,
            vec![
                ("message", FIN_DE_PARCOURS_INTERROMPUE),
                ("sans_message", FIN_DE_PARCOURS_INTERROMPUE),
                ("refus", FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
                ("autorisateur", FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
                ("ioerr", FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
                ("mappeur", FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
                ("vide", FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
            ],
            "deux classes, décidées par le seul texte de l'interruption"
        );
    }

    /// (6) LES DEUX PHRASES FIXES : chacune à son littéral, et distinctes (sinon les deux classes se confondent dans le
    /// corps sans qu'aucun autre témoin, construit sur ces mêmes symboles, ne rougisse).
    #[test]
    fn ao2_deux_phrases_distinctes() {
        assert_eq!(FIN_DE_PARCOURS_INTERROMPUE, "le parcours a été interrompu avant la fin (garde de budget de lecture ou annulation)");
        assert_eq!(FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE, "la base n'a pas rendu la lecture");
        assert_ne!(FIN_DE_PARCOURS_INTERROMPUE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE, "deux classes, deux phrases");
    }

    /// (4) LES QUATRE FONCTIONS DE CORPS, appel direct : refus (texte de l'autorisateur, énoncé compris) et interruption
    /// (texte sans message), corps entiers ; un parcours complet ne pose rien.
    #[test]
    fn ao2_corps_des_quatre_aveux() {
        let refus = FinDeParcours::NonCommence { cause: "not authorized to use function: COUNT in SELECT COUNT(*) FROM alert at offset 7".into() };
        let coupe = FinDeParcours::Interrompu {
            erreurs: 1,
            cause: rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT), None).to_string(),
        };
        let matrice = json!({ "tactics": [], "totals": {} });
        let avec = |mut v: Value, cause: &str, phrase: &str| {
            v["error"] = ao2_aveu(cause, phrase);
            v.to_string()
        };
        let lus = vec![
            corps_de_liste_d_alertes(vec![json!({ "id": 1 })], TotalDeListe::NonDemande, &refus).to_string(),
            corps_de_liste_d_alertes(vec![], TotalDeListe::NonDemande, &coupe).to_string(),
            corps_de_liste_d_alertes(vec![], TotalDeListe::NonDemande, &FinDeParcours::Complet).to_string(),
            corps_de_liste_de_groupes(vec![], TotalDeListe::NonDemande, "host", &refus).to_string(),
            corps_de_liste_de_groupes(vec![], TotalDeListe::NonDemande, "host", &coupe).to_string(),
            corps_de_liste_de_groupes(vec![], TotalDeListe::NonDemande, "host", &FinDeParcours::Complet).to_string(),
            corps_de_couverture_des_detections(vec![], None, &refus).to_string(),
            corps_de_couverture_des_detections(vec![], None, &coupe).to_string(),
            corps_de_couverture_des_detections(vec![], None, &FinDeParcours::Complet).to_string(),
            corps_de_matrice_attack(matrice.clone(), &refus).to_string(),
            corps_de_matrice_attack(matrice.clone(), &coupe).to_string(),
            corps_de_matrice_attack(matrice.clone(), &FinDeParcours::Complet).to_string(),
        ];
        let attendus = vec![
            avec(json!({ "alerts": [{ "id": 1 }] }), CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
            avec(json!({ "alerts": [] }), CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE),
            json!({ "alerts": [] }).to_string(),
            avec(json!({ "groups": [], "group": "host" }), CAUSE_LISTE_DE_GROUPES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
            avec(json!({ "groups": [], "group": "host" }), CAUSE_LISTE_DE_GROUPES_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE),
            json!({ "groups": [], "group": "host" }).to_string(),
            avec(json!({ "detections": [] }), CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
            avec(json!({ "detections": [] }), CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_INTERROMPUE),
            json!({ "detections": [] }).to_string(),
            avec(matrice.clone(), CAUSE_COMPTES_D_ALERTES_NON_ETABLIS, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE),
            avec(matrice.clone(), CAUSE_COMPTES_D_ALERTES_NON_ETABLIS, FIN_DE_PARCOURS_INTERROMPUE),
            matrice.to_string(),
        ];
        assert_eq!(lus, attendus, "la constante en préfixe, la phrase de la classe, rien d'autre ; aucun aveu sur un parcours complet");
    }

    const AO2_ENFANT_DEUX: &str = "AO2_ENFANT_DEUX_TENANTS";
    const AO2_ALPHA: &str = "ao2-alpha";
    const AO2_BETA: &str = "ao2-beta";

    fn ao2_lecteur(tenant: &str) -> AuthUser {
        AuthUser { name: "lecteur-ao2".into(), role: "viewer".into(), tenant: tenant.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }

    /// Crée le tenant `t` (vraie route de création), sème `alertes` alertes dans SA base, et rend le chemin de cette base.
    async fn ao2_creer_le_tenant(st: &AppState, t: &str, alertes: i64) -> String {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-ao2")), Json(json!({ "id": t, "name": t }))).await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        assert!(st.tenants.tenant_available(t), "contrôle : tenant {t} résolu pour le pool de lecture");
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        {
            let c = h.lock();
            for i in 0..alertes {
                c.execute(
                    "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(?1,?2,2,'Alerte AO2','','new','T1046','')",
                    params![1000 + i, format!("rule.{t}.{i}")],
                )
                .expect("fixture : alerte");
            }
        }
        st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant")
    }

    async fn ao2_alertes(st: &AppState, t: &str) -> String {
        let q: HashMap<String, String> = HashMap::from([("status".to_string(), "all".to_string())]);
        let r = crate::handlers::alerts::alerts(State(st.clone()), Extension(ao2_lecteur(t)), axum::extract::Query(q)).await;
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        String::from_utf8_lossy(&b).into_owned()
    }

    async fn ao2_detections(st: &AppState, t: &str) -> String {
        crate::handlers::alerts::coverage_detections(State(st.clone()), Extension(ao2_lecteur(t)), axum::extract::Query(HashMap::new())).await.0.to_string()
    }

    async fn ao2_alertes_refusees(st: &AppState, t: &str, chemin: &str) -> String {
        for _ in 0..AO2_ESSAIS {
            let joue = ao2_armer(chemin, REFUS_PAGE_D_ALERTES);
            let rendu = ao2_alertes(st, t).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi les alertes de {t} en aucun des {AO2_ESSAIS} essais");
    }

    async fn ao2_detections_refusees(st: &AppState, t: &str, chemin: &str) -> String {
        for _ in 0..AO2_ESSAIS {
            let joue = ao2_armer(chemin, REFUS_TECHNIQUES);
            let rendu = ao2_detections(st, t).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi la couverture de {t} en aucun des {AO2_ESSAIS} essais");
    }

    async fn ao2_groupes(st: &AppState, t: &str) -> String {
        let q: HashMap<String, String> = HashMap::from([("group".to_string(), "rule".to_string())]);
        let r = crate::handlers::alerts::alert_groups(State(st.clone()), Extension(ao2_lecteur(t)), axum::extract::Query(q)).await;
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        String::from_utf8_lossy(&b).into_owned()
    }

    async fn ao2_matrice(st: &AppState, t: &str) -> String {
        crate::handlers::alerts::coverage_attack(State(st.clone()), Extension(ao2_lecteur(t)), axum::extract::Query(HashMap::new())).await.0.to_string()
    }

    async fn ao2_groupes_refuses(st: &AppState, t: &str, chemin: &str) -> String {
        for _ in 0..AO2_ESSAIS {
            let joue = ao2_armer(chemin, REFUS_PAGE_DE_GROUPES);
            let rendu = ao2_groupes(st, t).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi les groupes de {t} en aucun des {AO2_ESSAIS} essais");
    }

    async fn ao2_matrice_refusee(st: &AppState, t: &str, chemin: &str) -> String {
        for _ in 0..AO2_ESSAIS {
            let joue = ao2_armer(chemin, REFUS_TECHNIQUES);
            let rendu = ao2_matrice(st, t).await;
            if joue.load(Ordering::SeqCst) {
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi la matrice de {t} en aucun des {AO2_ESSAIS} essais");
    }

    /// La matrice attendue du tenant `t`, sans compte puis avec ses `alertes` alertes T1046 (règles lues sur SA base).
    fn ao2_matrices_attendues(st: &AppState, t: &str, alertes: i64) -> (String, String) {
        let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let c = h.lock();
        let lecture = crate::detection_aveugle::lire_la_couverture_des_regles(&c);
        let comptes: HashMap<String, i64> = HashMap::from([("T1046".to_string(), alertes)]);
        (
            build_attack_matrix(&lecture.tirent, &lecture.en_attente_de_source, &lecture.eteintes, &HashMap::new()).to_string(),
            build_attack_matrix(&lecture.tirent, &lecture.en_attente_de_source, &lecture.eteintes, &comptes).to_string(),
        )
    }

    async fn ao2_jouer_deux_tenants() -> Vec<(String, String)> {
        let (st, _dir) = mk_mode1_state();
        let alpha = ao2_creer_le_tenant(&st, AO2_ALPHA, 1).await;
        let beta = ao2_creer_le_tenant(&st, AO2_BETA, 2).await;
        assert_ne!(alpha, beta, "contrôle : deux bases distinctes");
        let mut rendus: Vec<(String, String)> = Vec::new();
        rendus.push((format!("nominal:alertes:{AO2_ALPHA}"), ao2_alertes(&st, AO2_ALPHA).await));
        rendus.push((format!("nominal:alertes:{AO2_BETA}"), ao2_alertes(&st, AO2_BETA).await));
        rendus.push((format!("alpha_refusee:alertes:{AO2_ALPHA}"), ao2_alertes_refusees(&st, AO2_ALPHA, &alpha).await));
        rendus.push((format!("alpha_refusee:alertes:{AO2_BETA}"), ao2_alertes(&st, AO2_BETA).await));
        rendus.push((format!("beta_refusee:alertes:{AO2_BETA}"), ao2_alertes_refusees(&st, AO2_BETA, &beta).await));
        rendus.push((format!("beta_refusee:alertes:{AO2_ALPHA}"), ao2_alertes(&st, AO2_ALPHA).await));
        rendus.push((format!("nominal:detections:{AO2_ALPHA}"), ao2_detections(&st, AO2_ALPHA).await));
        rendus.push((format!("alpha_refusee:detections:{AO2_ALPHA}"), ao2_detections_refusees(&st, AO2_ALPHA, &alpha).await));
        rendus.push((format!("alpha_refusee:detections:{AO2_BETA}"), ao2_detections(&st, AO2_BETA).await));
        rendus.push((format!("beta_refusee:detections:{AO2_BETA}"), ao2_detections_refusees(&st, AO2_BETA, &beta).await));
        rendus.push((format!("beta_refusee:detections:{AO2_ALPHA}"), ao2_detections(&st, AO2_ALPHA).await));
        rendus.push((format!("nominal:groupes:{AO2_ALPHA}"), ao2_groupes(&st, AO2_ALPHA).await));
        rendus.push((format!("alpha_refusee:groupes:{AO2_ALPHA}"), ao2_groupes_refuses(&st, AO2_ALPHA, &alpha).await));
        rendus.push((format!("alpha_refusee:groupes:{AO2_BETA}"), ao2_groupes(&st, AO2_BETA).await));
        rendus.push((format!("beta_refusee:groupes:{AO2_BETA}"), ao2_groupes_refuses(&st, AO2_BETA, &beta).await));
        rendus.push((format!("beta_refusee:groupes:{AO2_ALPHA}"), ao2_groupes(&st, AO2_ALPHA).await));
        rendus.push((format!("nominal:matrice:{AO2_ALPHA}"), ao2_matrice(&st, AO2_ALPHA).await));
        rendus.push((format!("alpha_refusee:matrice:{AO2_ALPHA}"), ao2_matrice_refusee(&st, AO2_ALPHA, &alpha).await));
        rendus.push((format!("alpha_refusee:matrice:{AO2_BETA}"), ao2_matrice(&st, AO2_BETA).await));
        rendus.push((format!("beta_refusee:matrice:{AO2_BETA}"), ao2_matrice_refusee(&st, AO2_BETA, &beta).await));
        rendus.push((format!("beta_refusee:matrice:{AO2_ALPHA}"), ao2_matrice(&st, AO2_ALPHA).await));
        for (t, n) in [(AO2_ALPHA, 1), (AO2_BETA, 2)] {
            let (sans, comptee) = ao2_matrices_attendues(&st, t, n);
            rendus.push((format!("attendu:matrice_sans_comptes:{t}"), sans));
            rendus.push((format!("attendu:matrice_comptee:{t}"), comptee));
        }
        rendus
    }

    /// (5) DEUX TENANTS RÉELS (mode 1) : la lecture refusée chez l'un rend la phrase fixe et une ligne de journal qui
    /// nomme CE tenant ; l'autre est servi par SA base ; puis l'inverse. Corps à l'octet, lignes en entier, dans l'ordre.
    #[tokio::test]
    async fn ao2_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(AO2_ENFANT_DEUX).is_ok() {
            let rendus = ao2_jouer_deux_tenants().await;
            for (issue, corps) in &rendus {
                println!("{AO2_RENDU}{}", json!([issue, corps]));
            }
            println!("{AO2_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::aveux_de_parcours_sans_texte_du_moteur::ao2_deux_tenants"])
            .env(AO2_ENFANT_DEUX, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{AO2_FIN} 25")), "contrôle : l'enfant a joué ses vingt et une issues et rendu ses quatre matrices attendues : {stdout}\n{stderr}");
        let tous: Vec<(String, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once(AO2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        let attendu = |cle: &str| -> String {
            tous.iter().find(|(i, _)| i == cle).map(|(_, c)| c.clone()).unwrap_or_else(|| panic!("contrôle : {cle} rendu par l'enfant"))
        };
        let lus: Vec<(String, String)> = tous.iter().filter(|(i, _)| !i.starts_with("attendu:")).cloned().collect();
        let groupes_servis = |t: &str, issue: &str, n: i64| -> String {
            let c = lus.iter().find(|(i, _)| *i == format!("{issue}:groupes:{t}")).map(|(_, c)| c.clone()).unwrap_or_default();
            let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
            assert!(
                v["total"] == json!(n) && v["group"] == json!("rule") && v["groups"].as_array().map(|a| a.len()) == Some(n as usize) && v.get("error").is_none(),
                "contrôle : {t} sert SES {n} groupes : {c}"
            );
            c
        };
        let groupes_refuses = |n: i64| -> String {
            let mut v = json!({ "groups": [], "group": "rule" });
            v["total"] = json!(n);
            v["error"] = ao2_aveu(CAUSE_LISTE_DE_GROUPES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
            v.to_string()
        };
        let matrice_refusee = |t: &str| -> String {
            let mut v: Value = serde_json::from_str(&attendu(&format!("attendu:matrice_sans_comptes:{t}"))).expect("matrice attendue lisible");
            v["error"] = ao2_aveu(CAUSE_COMPTES_D_ALERTES_NON_ETABLIS, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
            v.to_string()
        };
        let matrice_comptee = |t: &str| attendu(&format!("attendu:matrice_comptee:{t}"));
        assert_ne!(matrice_comptee(AO2_ALPHA), matrice_comptee(AO2_BETA), "contrôle : les deux matrices comptées se distinguent (1 contre 2 alertes T1046)");
        let nominal = |t: &str| -> String { lus.iter().find(|(i, _)| *i == format!("nominal:alertes:{t}")).map(|(_, c)| c.clone()).unwrap_or_default() };
        let compte = |t: &str, n: i64| -> String {
            let c = nominal(t);
            let v: Value = serde_json::from_str(&c).unwrap_or(Value::Null);
            assert!(v["total"] == json!(n) && v["alerts"].as_array().map(|a| a.len()) == Some(n as usize) && v.get("error").is_none(), "contrôle : {t} sert SES {n} alertes : {c}");
            c
        };
        let alertes_refusees = |n: i64| -> String {
            let mut v = json!({ "alerts": [] });
            v["total"] = json!(n);
            v["error"] = ao2_aveu(CAUSE_LISTE_D_ALERTES_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
            v.to_string()
        };
        let detections = |n: i64| json!({ "detections": [{ "mitre": "T1046", "count": n, "first_ts": 1000 }] }).to_string();
        let mut detections_refusees = json!({ "detections": [] });
        detections_refusees["error"] = ao2_aveu(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE, FIN_DE_PARCOURS_REFUSEE_PAR_LA_BASE);
        let attendus: Vec<(String, String)> = vec![
            (format!("nominal:alertes:{AO2_ALPHA}"), compte(AO2_ALPHA, 1)),
            (format!("nominal:alertes:{AO2_BETA}"), compte(AO2_BETA, 2)),
            (format!("alpha_refusee:alertes:{AO2_ALPHA}"), alertes_refusees(1)),
            (format!("alpha_refusee:alertes:{AO2_BETA}"), compte(AO2_BETA, 2)),
            (format!("beta_refusee:alertes:{AO2_BETA}"), alertes_refusees(2)),
            (format!("beta_refusee:alertes:{AO2_ALPHA}"), compte(AO2_ALPHA, 1)),
            (format!("nominal:detections:{AO2_ALPHA}"), detections(1)),
            (format!("alpha_refusee:detections:{AO2_ALPHA}"), detections_refusees.to_string()),
            (format!("alpha_refusee:detections:{AO2_BETA}"), detections(2)),
            (format!("beta_refusee:detections:{AO2_BETA}"), detections_refusees.to_string()),
            (format!("beta_refusee:detections:{AO2_ALPHA}"), detections(1)),
            (format!("nominal:groupes:{AO2_ALPHA}"), groupes_servis(AO2_ALPHA, "nominal", 1)),
            (format!("alpha_refusee:groupes:{AO2_ALPHA}"), groupes_refuses(1)),
            (format!("alpha_refusee:groupes:{AO2_BETA}"), groupes_servis(AO2_BETA, "alpha_refusee", 2)),
            (format!("beta_refusee:groupes:{AO2_BETA}"), groupes_refuses(2)),
            (format!("beta_refusee:groupes:{AO2_ALPHA}"), groupes_servis(AO2_ALPHA, "beta_refusee", 1)),
            (format!("nominal:matrice:{AO2_ALPHA}"), matrice_comptee(AO2_ALPHA)),
            (format!("alpha_refusee:matrice:{AO2_ALPHA}"), matrice_refusee(AO2_ALPHA)),
            (format!("alpha_refusee:matrice:{AO2_BETA}"), matrice_comptee(AO2_BETA)),
            (format!("beta_refusee:matrice:{AO2_BETA}"), matrice_refusee(AO2_BETA)),
            (format!("beta_refusee:matrice:{AO2_ALPHA}"), matrice_comptee(AO2_ALPHA)),
        ];
        assert_eq!(lus, attendus, "chaque tenant servi par SA base, la phrase fixe chez le seul tenant refusé");
        let journal: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[alerts] WARN")).collect();
        assert_eq!(
            journal,
            vec![
                format!("[alerts] WARN parcours de la liste d'alertes non commencé (tenant '{AO2_ALPHA}') : {}", ao2_moteur(REFUS_PAGE_D_ALERTES)),
                format!("[alerts] WARN parcours de la liste d'alertes non commencé (tenant '{AO2_BETA}') : {}", ao2_moteur(REFUS_PAGE_D_ALERTES)),
                format!("[alerts] WARN parcours de la couverture des détections non commencé (tenant '{AO2_ALPHA}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
                format!("[alerts] WARN parcours de la couverture des détections non commencé (tenant '{AO2_BETA}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
                format!("[alerts] WARN parcours de la liste de groupes par rule non commencé (tenant '{AO2_ALPHA}') : {}", ao2_moteur(REFUS_PAGE_DE_GROUPES)),
                format!("[alerts] WARN parcours de la liste de groupes par rule non commencé (tenant '{AO2_BETA}') : {}", ao2_moteur(REFUS_PAGE_DE_GROUPES)),
                format!("[alerts] WARN parcours des alertes par technique non commencé (tenant '{AO2_ALPHA}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
                format!("[alerts] WARN parcours des alertes par technique non commencé (tenant '{AO2_BETA}') : {}", ao2_moteur(REFUS_TECHNIQUES)),
            ],
            "une ligne EXACTE par refus, qui nomme le tenant refusé :\n{stderr}"
        );
    }
}
