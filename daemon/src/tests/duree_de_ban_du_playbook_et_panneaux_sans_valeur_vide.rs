// =====================================================================================
// `P11.25-a` — LA DURÉE D'UN BAN POSÉ PAR UN PLAYBOOK SE RÈGLE, ET ELLE VA JUSQU'À L'EXÉCUTEUR.
// `P11.25-b` — LES PANNEAUX DE DIMENSION SEMÉS NE RENDENT PLUS LA VALEUR VIDE.
//
// (a) AVANT : `NETBAN_ACTION_TTL_S` (4 h) en dur pour le blocage HTTP natif, `--duration 4h` en littéral pour
// CrowdSec, aucun champ dans la création ni la modification d'un playbook. APRÈS (v124) : `playbook.ban_ttl_s`
// (NULL = 4 h, la durée d'avant), validé par la route (entier, d'une seconde à `BAN_TTL_MAX_S`, sinon 400
// `CAUSE_DUREE_DE_BAN_REFUSEE`), servi par la liste (`ban_ttl_s`, `ban_duration_s` EFFECTIVE, phrase de
// conséquence), porté par la riposte (`action.ban_ttl_s`, écrit tout ou rien avec la ligne), relu par
// l'approbation, le responder (miroir HTTP et commande CrowdSec). Une riposte créée à la main garde 4 h.
//
// (b) AVANT : `dim_panel_sql(…, false)` pour dix panneaux semés (web, dataaccess, dataacl, kube-rbac) : la valeur
// `''` (champ absent) sortait comme une barre. APRÈS : le seed passe `true` ; v124 réécrit les panneaux déjà
// semés dont la requête est EXACTEMENT celle d'origine (et `is_soql = 0`), jamais un panneau édité.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'agent d'un hôte distant (`collectors/respond.sh`) applique sa propre
// durée (`PLUME_BAN_DURATION`, défaut 4 h) — la file qu'il lit (`actions_pending`) ne la lui transmet que sous
// `Accept: application/x-ndjson`, qu'il n'envoie pas encore (témoins : `duree_de_ban_servie_a_l_agent.rs`) ; un playbook posé par un fichier `config.d` n'a pas de champ de durée (`overlays.rs`) ; le
// formulaire de la console n'envoie pas encore `ban_ttl_s`.
// =====================================================================================
mod duree_de_ban_du_playbook_et_panneaux_sans_valeur_vide {
    use super::*;
    use crate::handlers::mise_en_file_de_riposte::RiposteMiseEnFile;
    use crate::handlers::playbooks::{
        action_consequence_pour_la_duree, duree_de_ban_lisible, poser_la_riposte_du_playbook, run_playbooks,
        CAUSE_DUREE_DE_BAN_REFUSEE, POINT_DE_LA_RIPOSTE_ET_DE_SA_DUREE,
    };
    use crate::mesure_environnement::Mesure;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// La phrase EXACTE servie pour la durée par défaut — celle d'avant le lot, à l'octet.
    const DBP_PHRASE_DEFAUT: &str = "bannit l'IP source pendant 4 h (CrowdSec ou blocage HTTP natif ; fail2ban : durée du jail ; nft : jusqu'à unban) sur chaque hôte qui l'a vue dans la fenêtre";
    /// La phrase EXACTE servie pour une durée propre de 90 minutes.
    const DBP_PHRASE_90_MIN: &str = "bannit l'IP source pendant 90 min (CrowdSec du central ou blocage HTTP natif ; agent d'un hôte distant : sa propre durée ; fail2ban : durée du jail ; nft : jusqu'à unban) sur chaque hôte qui l'a vue dans la fenêtre";
    /// La phrase de refus, recopiée ici : le témoin ne relit pas la constante du code pour la juger.
    const DBP_REFUS: &str = "DURÉE DE BAN REFUSÉE : ban_ttl_s est un nombre ENTIER de secondes, d'une seconde à 31536000 (365 jours), ou null pour la durée par défaut (4 h). Une valeur décimale, textuelle, nulle, négative ou au-delà d'un an n'est ni arrondie ni remplacée : RIEN n'est écrit.";
    /// La phrase d'une durée de riposte non lue, recopiée ici (leçon AS2) : aucun témoin ne relit la constante du
    /// code (`DUREE_DE_BAN_NON_LUE`) pour juger une ligne.
    const DBP_DUREE_NON_LUE: &str = "durée du ban de cette riposte NON lue (colonne ban_ttl_s illisible ou hors borne) — rien n'est posé avec une durée devinée";
    /// Le texte du moteur pour une colonne `ban_ttl_s` illisible (BLOB), puis hors borne (0), recopié ici.
    const DBP_MOTEUR_BLOB: &str = "Invalid column type Blob at index: 0, name: ban_ttl_s";
    const DBP_MOTEUR_ZERO: &str = "Integer 0 out of range at index 0";
    const DBP_REQUETE: &str = "search source=auth outcome=fail | stats count by src_ip";
    const DBP_DEFAUT_S: i64 = 4 * 3600;
    const DBP_UN_AN_S: i64 = 365 * 86400;

    fn dbp_base(chemin: &str) {
        let conn = open_db(chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P11.25-a` : la chaîne de migrations doit aller au bout");
        conn.execute_batch("DELETE FROM playbook; DELETE FROM action; DELETE FROM net_ban;").unwrap();
    }

    fn dbp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dbp-{tag}"));
        dbp_base(&chemin);
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dbp_qui(role: &str) -> AuthUser {
        AuthUser {
            name: format!("dbp-{role}"), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dbp_un(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    async fn dbp_creer(st: &AppState, extra: Value) -> (u16, Value) {
        let mut corps = json!({ "name": "dbp-pb", "query": DBP_REQUETE, "action_kind": "ban_ip", "window_s": 3600, "interval_s": 300 });
        for (k, v) in extra.as_object().unwrap() {
            corps[k] = v.clone();
        }
        pb_json(playbook_create(State(st.clone()), Extension(dbp_qui("admin")), Json(corps)).await).await
    }

    async fn dbp_modifier(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(playbook_update(State(st.clone()), Extension(dbp_qui("admin")), Path(id), Json(corps)).await).await
    }

    /// La ligne servie par la liste pour ce playbook (rôle le plus faible admis à lire : `viewer`).
    async fn dbp_ligne_servie(st: &AppState, id: i64) -> Value {
        let v = playbooks_list(State(st.clone()), Extension(dbp_qui("viewer"))).await.0;
        assert!(v.get("error").is_none(), "la liste est lue : {v}");
        assert_eq!(v["ban_duration_s"], json!(DBP_DEFAUT_S), "la tête dit la durée PAR DÉFAUT, inchangée : {v}");
        v["playbooks"].as_array().expect("playbooks : tableau").iter().find(|p| p["id"] == json!(id)).cloned()
            .unwrap_or_else(|| panic!("playbook #{id} servi : {v}"))
    }

    // -------------------------------------------------------------------------------------
    // (1) LA ROUTE DE CRÉATION — durée acceptée aux deux bords, refusée au-delà, rien d'écrit sur refus.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sans durée, la ligne porte NULL et la liste sert 4 h et la phrase d'avant à l'octet ;
    /// avec 5400 s, la ligne porte 5400, la liste sert `ban_ttl_s: 5400`, `ban_duration_s: 5400` et la phrase « 90 min »
    /// avec l'aveu de l'agent distant ; une seconde et un an (les deux bords) passent ; zéro, négatif, un an plus une
    /// seconde, `3600.0`, `"3600"`, `true` sont refusés en 400 au corps EXACT `{"error": DBP_REFUS}` et rien n'est écrit.
    /// MUTATIONS : `M_CREATION`, `M_LISTE`, `M_PHRASE`, `M_PHRASE_AGENT`, `M_BORNE_BAS`, `M_BORNE_HAUT`, `M_DECIMAL`.
    #[tokio::test]
    async fn dbp_la_creation_pose_la_duree_bornee_et_la_liste_sert_la_duree_effective() {
        let (st, _tmp) = dbp_etat("creation");
        let (code, v) = dbp_creer(&st, json!({})).await;
        assert_eq!(code, 200, "création sans durée : {v}");
        let sans = v["id"].as_i64().unwrap();
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={sans}")), None, "sans durée : NULL (le défaut)");
        let l = dbp_ligne_servie(&st, sans).await;
        assert_eq!((l["ban_ttl_s"].clone(), l["ban_duration_s"].clone()), (Value::Null, json!(DBP_DEFAUT_S)), "{l}");
        assert_eq!(l["consequence"], json!(DBP_PHRASE_DEFAUT), "la phrase d'avant, à l'octet : {l}");

        let (code, v) = dbp_creer(&st, json!({ "ban_ttl_s": 5400 })).await;
        assert_eq!(code, 200, "création avec durée : {v}");
        let avec = v["id"].as_i64().unwrap();
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={avec}")), Some(5400));
        let l = dbp_ligne_servie(&st, avec).await;
        assert_eq!((l["ban_ttl_s"].clone(), l["ban_duration_s"].clone()), (json!(5400), json!(5400)), "{l}");
        assert_eq!(l["consequence"], json!(DBP_PHRASE_90_MIN), "{l}");

        for bord in [1, DBP_UN_AN_S] {
            let (code, v) = dbp_creer(&st, json!({ "ban_ttl_s": bord })).await;
            assert_eq!(code, 200, "bord {bord} admis : {v}");
            assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={}", v["id"])), Some(bord));
        }
        let avant = dbp_un(&st, "SELECT COUNT(*) FROM playbook");
        let refusees = [json!(0), json!(-1), json!(DBP_UN_AN_S + 1), json!(3600.0), json!("3600"), json!(true)];
        for mauvaise in refusees {
            let (code, v) = dbp_creer(&st, json!({ "ban_ttl_s": mauvaise })).await;
            assert_eq!((code, v.clone()), (400, json!({ "error": DBP_REFUS })), "{mauvaise} refusée, corps exact");
        }
        assert_eq!(dbp_un(&st, "SELECT COUNT(*) FROM playbook"), avant, "aucune création refusée n'a écrit de ligne");
        assert_eq!(CAUSE_DUREE_DE_BAN_REFUSEE, DBP_REFUS);
    }

    // -------------------------------------------------------------------------------------
    // (2) LA ROUTE DE MODIFICATION — posée, rendue au défaut par null, gardée si absente, refusée hors borne.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : 7200 s posée par la modification (lue en base, servie « 2 h ») ; une modification qui ne
    /// porte pas le champ la garde ; une durée hors borne rend 400 au corps exact et la valeur reste ; `null` la
    /// rend NULL (le défaut servi). MUTATIONS : `M_MODIF`, `M_MODIF_NULL`, `M_BORNE_HAUT`.
    #[tokio::test]
    async fn dbp_la_modification_pose_garde_rend_au_defaut_et_refuse_hors_borne() {
        let (st, _tmp) = dbp_etat("modification");
        let (code, v) = dbp_creer(&st, json!({})).await;
        assert_eq!(code, 200, "{v}");
        let id = v["id"].as_i64().unwrap();
        let (code, v) = dbp_modifier(&st, id, json!({ "ban_ttl_s": 7200 })).await;
        assert_eq!(code, 200, "durée posée : {v}");
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={id}")), Some(7200));
        assert_eq!(dbp_ligne_servie(&st, id).await["ban_duration_s"], json!(7200));
        let (code, v) = dbp_modifier(&st, id, json!({ "name": "dbp-renomme" })).await;
        assert_eq!(code, 200, "{v}");
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={id}")), Some(7200), "champ absent : gardée");
        let (code, v) = dbp_modifier(&st, id, json!({ "ban_ttl_s": DBP_UN_AN_S + 1 })).await;
        assert_eq!((code, v), (400, json!({ "error": DBP_REFUS })));
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={id}")), Some(7200), "refus : rien d'écrit");
        let (code, v) = dbp_modifier(&st, id, json!({ "ban_ttl_s": null })).await;
        assert_eq!(code, 200, "{v}");
        assert_eq!(dbp_un(&st, &format!("SELECT ban_ttl_s FROM playbook WHERE id={id}")), None, "null : retour au défaut");
        let l = dbp_ligne_servie(&st, id).await;
        assert_eq!((l["ban_ttl_s"].clone(), l["ban_duration_s"].clone()), (Value::Null, json!(DBP_DEFAUT_S)), "{l}");
    }

    /// CE QU'IL TIENT : une durée hors borne posée HORS des routes (SQL direct) rend la liste illisible et AVOUÉE
    /// (`playbooks: []` + `error`), jamais servie comme le défaut. MUTATION : `M_LISTE_BORNE`.
    #[tokio::test]
    async fn dbp_une_duree_hors_borne_en_base_rend_la_liste_avouee() {
        let (st, _tmp) = dbp_etat("liste-borne");
        let (code, v) = dbp_creer(&st, json!({})).await;
        assert_eq!(code, 200, "{v}");
        st.db.lock().execute("UPDATE playbook SET ban_ttl_s=0", []).unwrap();
        let v = playbooks_list(State(st.clone()), Extension(dbp_qui("viewer"))).await.0;
        assert_eq!(v["playbooks"], json!([]), "{v}");
        assert_eq!(v["error"], json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE), "{v}");
    }

    /// CE QU'IL TIENT : les trois formes de la durée dite (heures, minutes, secondes) et la voie CrowdSec
    /// (`h` entières, secondes sinon). MUTATIONS : `M_LISIBLE_H`, `M_LISIBLE_MIN`, `M_CSCLI`.
    #[test]
    fn dbp_la_duree_se_dit_en_heures_minutes_ou_secondes() {
        assert_eq!(duree_de_ban_lisible(7200), "2 h");
        assert_eq!(duree_de_ban_lisible(5400), "90 min");
        assert_eq!(duree_de_ban_lisible(45), "45 s");
        assert_eq!(crate::handlers::actions::duree_pour_cscli(14400), "4h");
        assert_eq!(crate::handlers::actions::duree_pour_cscli(5400), "5400s");
        assert_eq!(action_consequence_pour_la_duree("ban_ip", DBP_DEFAUT_S), DBP_PHRASE_DEFAUT);
        assert_eq!(action_consequence("ban_ip"), DBP_PHRASE_DEFAUT, "le défaut garde sa phrase");
    }

    // -------------------------------------------------------------------------------------
    // (3) LE PASSAGE DU PLAYBOOK — la riposte porte la durée, le miroir HTTP l'applique.
    // -------------------------------------------------------------------------------------

    fn dbp_db_de_playbook(tag: &str) -> (Arc<Mutex<Connection>>, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dbp-{tag}"));
        dbp_base(&chemin);
        let db = Arc::new(Mutex::new(open_db(&chemin).unwrap()));
        db.lock().execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap();
        (db, chemin)
    }

    fn dbp_playbook(db: &Arc<Mutex<Connection>>, nom: &str, cible: &str, ban_ttl_s: Option<i64>) {
        db.lock()
            .execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role,ban_ttl_s) \
                 VALUES(?1,1,?2,0,'ban_ip',0,3600,0,NULL,'admin',?3)",
                params![nom, format!("SELECT '{cible}'"), ban_ttl_s],
            )
            .unwrap();
    }

    fn dbp_sur(db: &Arc<Mutex<Connection>>, sql: &str) -> Option<i64> {
        db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    /// CE QU'IL TIENT : en mode actif, auto-armement posé, un playbook à 5400 s pose une riposte qui porte 5400 et
    /// arme `net_ban` jusqu'à `maintenant + 5400` ; son voisin sans durée pose une riposte à NULL et arme à
    /// `maintenant + 4 h` (le comportement d'avant). Une durée hors borne posée hors des routes (0) : le playbook
    /// n'est pas évalué, l'abandon est COMPTÉ, aucune riposte. Un playbook `kill_pid` à 5400 s pose sa riposte à NULL
    /// (seul un ban porte la durée). MUTATIONS : `M_NETBAN_PB`, `M_RIPOSTE_SANS_DUREE`, `M_LECTURE_PB_BORNE`,
    /// `M_DUREE_TOUT_GENRE`.
    #[test]
    fn dbp_le_passage_pose_la_riposte_avec_sa_duree_et_arme_le_ban_pour_elle() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let (db, _tmp) = dbp_db_de_playbook("passage");
        dbp_playbook(&db, "dbp-propre", "203.0.113.81", Some(5400));
        dbp_playbook(&db, "dbp-defaut", "203.0.113.82", None);
        let p = _tmp.to_string();
        let avant = now();
        assert_eq!(run_playbooks(&db, &p), Mesure::Lue(0), "rien d'abandonné");
        let apres = now();
        assert_eq!(dbp_sur(&db, "SELECT ban_ttl_s FROM action WHERE target='203.0.113.81'"), Some(5400), "la riposte porte sa durée");
        assert_eq!(dbp_sur(&db, "SELECT ban_ttl_s FROM action WHERE target='203.0.113.82'"), None, "sans durée : NULL");
        let propre = dbp_sur(&db, "SELECT expires_ts FROM net_ban WHERE ip='203.0.113.81'").expect("ban armé, échéance");
        assert!((avant + 5400..=apres + 5400).contains(&propre), "échéance = maintenant + 5400 : {propre} ({avant}..{apres})");
        let defaut = dbp_sur(&db, "SELECT expires_ts FROM net_ban WHERE ip='203.0.113.82'").expect("ban armé, échéance");
        assert!((avant + DBP_DEFAUT_S..=apres + DBP_DEFAUT_S).contains(&defaut), "échéance = maintenant + 4 h : {defaut}");

        db.lock().execute_batch("DELETE FROM playbook; DELETE FROM action;").unwrap();
        db.lock()
            .execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role,ban_ttl_s) \
                 VALUES('dbp-kill',1,'SELECT ''424243''',0,'kill_pid',0,3600,0,NULL,'admin',5400)",
                [],
            )
            .unwrap();
        assert_eq!(run_playbooks(&db, &p), Mesure::Lue(0), "kill_pid : rien d'abandonné");
        assert_eq!(dbp_sur(&db, "SELECT COUNT(*) FROM action WHERE kind='kill_pid' AND target='424243'"), Some(1), "fixture : riposte posée");
        assert_eq!(dbp_sur(&db, "SELECT ban_ttl_s FROM action WHERE target='424243'"), None, "une riposte autre qu'un ban ne porte pas la durée");

        db.lock().execute_batch("DELETE FROM playbook; DELETE FROM action;").unwrap();
        dbp_playbook(&db, "dbp-hors-borne", "203.0.113.83", Some(0));
        assert_eq!(run_playbooks(&db, &p), Mesure::Lue(1), "durée hors borne : le playbook n'est pas évalué, c'est compté");
        assert_eq!(dbp_sur(&db, "SELECT COUNT(*) FROM action"), Some(0), "aucune riposte");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : la durée ne s'écrit pas sur la riposte (déclencheur qui refuse, puis qui ignore l'écriture) :
    /// le passage COMPTE l'abandon, AUCUNE riposte ne reste (ni avec la durée par défaut), aucun ban n'est armé, et
    /// l'écrivain est rendu sans transaction pendante. MUTATIONS : `M_OK0`, `M_SANS_ROLLBACK`.
    #[test]
    fn dbp_une_duree_non_ecrite_sur_la_riposte_annule_la_riposte_entiere() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let (db, _tmp) = dbp_db_de_playbook("duree-non-ecrite");
        let p = _tmp.to_string();
        let declencheurs = ["SELECT RAISE(ABORT, 'dbp-refus');", "SELECT RAISE(IGNORE);"];
        for (i, corps) in declencheurs.iter().enumerate() {
            let cible = format!("203.0.113.9{i}");
            db.lock().execute_batch(&format!(
                "DELETE FROM playbook; DROP TRIGGER IF EXISTS dbp_duree; \
                 CREATE TRIGGER dbp_duree BEFORE UPDATE OF ban_ttl_s ON action BEGIN {corps} END;"
            )).unwrap();
            dbp_playbook(&db, "dbp-pb", &cible, Some(5400));
            assert_eq!(run_playbooks(&db, &p), Mesure::Lue(1), "déclencheur {corps} : abandon compté");
            assert!(db.lock().is_autocommit(), "déclencheur {corps} : aucune transaction pendante");
            assert_eq!(dbp_sur(&db, "SELECT COUNT(*) FROM action"), Some(0), "déclencheur {corps} : aucune riposte ne reste");
            assert_eq!(dbp_sur(&db, &format!("SELECT COUNT(*) FROM net_ban WHERE ip='{cible}'")), Some(0), "aucun ban armé");
        }
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : le point de reprise refusé à l'ouverture, puis à la libération (autorisateur), rend
    /// `NonEcrite` sans laisser de ligne ni de transaction ; contrôle positif : sans refus, `Posee` et la ligne porte
    /// la durée. MUTATIONS : `M_SAVEPOINT_IGNORE`, `M_RELEASE_IGNORE`.
    #[test]
    fn dbp_le_point_de_reprise_refuse_n_ecrit_rien() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbp-point");
        dbp_base(&chemin);
        let conn = open_db(&chemin).unwrap();
        let poser = |conn: &Connection, cible: &str| {
            poser_la_riposte_du_playbook(conn, 1000, "ban_ip", cible, "approved", 0, "playbook:dbp", None, Some(5400))
        };
        assert!(matches!(poser(&conn, "203.0.113.70"), RiposteMiseEnFile::Posee(_)), "contrôle positif");
        assert_eq!(conn.query_row("SELECT ban_ttl_s FROM action WHERE target='203.0.113.70'", [], |r| r.get::<_, i64>(0)).unwrap(), 5400);
        for operation in [TransactionOperation::Begin, TransactionOperation::Release] {
            let deja = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marque = deja.clone();
            let refusee = operation;
            conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation, savepoint_name }
                    if operation == refusee && savepoint_name == POINT_DE_LA_RIPOSTE_ET_DE_SA_DUREE
                        && !marque.swap(true, std::sync::atomic::Ordering::SeqCst) => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let issue = poser(&conn, "203.0.113.71");
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            assert!(matches!(issue, RiposteMiseEnFile::NonEcrite(_)), "{operation:?} refusé : NonEcrite");
            assert!(conn.is_autocommit(), "{operation:?} refusé : aucune transaction pendante");
            assert_eq!(conn.query_row("SELECT COUNT(*) FROM action WHERE target='203.0.113.71'", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "{operation:?}");
        }
    }

    // -------------------------------------------------------------------------------------
    // (4) L'APPROBATION — la riposte d'un playbook arme pour SA durée, une riposte à la main pour 4 h.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : approuver une riposte `ban_ip` à 5400 s arme `net_ban` jusqu'à `maintenant + 5400` ; une
    /// riposte à NULL (créée à la main) jusqu'à `maintenant + 4 h` ; une durée illisible (BLOB) puis hors borne (0)
    /// rend 503 au corps exact (`CAUSE_BAN_NON_ARME` et la phrase laissée au journal, plus l'identifiant), n'arme
    /// RIEN, et le registre `netban.non-arme` porte la ligne ENTIÈRE avec la phrase recopiée (`DBP_DUREE_NON_LUE`)
    /// suivie du texte du moteur recopié. MUTATIONS : `M_APPROBATION`, `M_APPROBATION_ERR`, `M_LIGNE_ACTION`,
    /// `V_APPROVE_CAUSE`, `BS_PHRASE_VIDEE`.
    #[tokio::test]
    async fn dbp_l_approbation_arme_pour_la_duree_de_la_riposte() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let (st, _tmp) = dbp_etat("approbation");
        let riposte = |cible: &str, duree: &str| -> i64 {
            let c = st.db.lock();
            c.execute(
                &format!("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,'ban_ip',?1,'pending',0,'dbp',{duree})"),
                params![cible],
            ).unwrap();
            c.last_insert_rowid()
        };
        let (propre, defaut, blob, zero) =
            (riposte("203.0.113.61", "5400"), riposte("203.0.113.62", "NULL"), riposte("203.0.113.63", "X'00'"), riposte("203.0.113.64", "0"));
        let avant = now();
        for id in [propre, defaut] {
            let (code, v) = pb_json(action_approve(State(st.clone()), Extension(dbp_qui("admin")), Path(id)).await).await;
            assert_eq!(code, 204, "riposte #{id} approuvée : {v}");
        }
        let apres = now();
        let propre_ts = dbp_un(&st, "SELECT expires_ts FROM net_ban WHERE ip='203.0.113.61'").expect("ban armé");
        assert!((avant + 5400..=apres + 5400).contains(&propre_ts), "riposte de playbook : + 5400 ({propre_ts})");
        let defaut_ts = dbp_un(&st, "SELECT expires_ts FROM net_ban WHERE ip='203.0.113.62'").expect("ban armé");
        assert!((avant + DBP_DEFAUT_S..=apres + DBP_DEFAUT_S).contains(&defaut_ts), "riposte à la main : + 4 h ({defaut_ts})");
        for (id, cible, moteur) in [(blob, "203.0.113.63", DBP_MOTEUR_BLOB), (zero, "203.0.113.64", DBP_MOTEUR_ZERO)] {
            let (code, v) = pb_json(action_approve(State(st.clone()), Extension(dbp_qui("admin")), Path(id)).await).await;
            assert_eq!(code, 503, "durée illisible : refus ({v})");
            assert_eq!(v["error"], json!(format!("{CAUSE_BAN_NON_ARME} ({CAUSE_DU_MOTEUR_LAISSEE_AU_JOURNAL})")), "{v}");
            assert_eq!(v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()), Some(vec!["error".to_string(), "id".to_string()]), "{v}");
            assert_eq!(dbp_un(&st, &format!("SELECT COUNT(*) FROM net_ban WHERE ip='{cible}'")), Some(0), "rien d'armé pour {cible}");
            let c = st.db.lock();
            let attendue = format!("{cible} NON armé (action {id}) : {DBP_DUREE_NON_LUE} ({moteur})");
            let lignes: Vec<String> = c
                .prepare(&format!("SELECT detail FROM ledger WHERE kind='netban.non-arme' AND detail LIKE '{cible} %'"))
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(lignes, vec![attendue], "le registre porte la ligne entière, cause nommée puis moteur");
        }
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : le miroir du responder sur une riposte exécutée à durée illisible n'arme rien et le registre
    /// `netban.non-arme` porte UNE ligne, comparée ENTIÈRE : cible, identifiant, phrase recopiée et texte du moteur
    /// recopié ; sur une riposte SANS LIGNE dans la file, il arme pour la durée par défaut (`maintenant + 4 h`), comme
    /// avant v124. MUTATIONS : `M_MIROIR_ERR`, `M_MIROIR_SANS_LIGNE`, `BS_MIROIR_MOTEUR`, `BS_PHRASE_VIDEE`.
    #[test]
    fn dbp_le_miroir_du_responder_n_arme_rien_sur_une_duree_illisible() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = dbp_etat("miroir");
        let id = {
            let c = st.db.lock();
            c.execute("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,'ban_ip','203.0.113.65','done',0,'dbp',X'00')", []).unwrap();
            c.last_insert_rowid()
        };
        let aveu = crate::handlers::actions::miroir_http_du_responder(&st.db.lock(), id, "ban_ip", "203.0.113.65", "done", false);
        assert_eq!(aveu, None, "le maillon est entré, rien à avouer en plus");
        assert_eq!(dbp_un(&st, "SELECT COUNT(*) FROM net_ban"), Some(0), "aucun ban armé");
        let lignes: Vec<String> = st.db.lock()
            .prepare("SELECT detail FROM ledger WHERE kind='netban.non-arme' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            lignes,
            vec![format!("203.0.113.65 NON armé (responder, action {id}) : {DBP_DUREE_NON_LUE} ({DBP_MOTEUR_BLOB})")],
            "le registre porte la ligne ENTIÈRE : le ban non armé, la phrase et le texte du moteur"
        );
        let sans_ligne = id + 1000;
        assert_eq!(dbp_un(&st, &format!("SELECT COUNT(*) FROM action WHERE id={sans_ligne}")), Some(0), "fixture : aucune ligne");
        let avant = now();
        let aveu = crate::handlers::actions::miroir_http_du_responder(&st.db.lock(), sans_ligne, "ban_ip", "203.0.113.66", "done", false);
        let apres = now();
        assert_eq!(aveu, None);
        let echeance = dbp_un(&st, "SELECT expires_ts FROM net_ban WHERE ip='203.0.113.66'").expect("riposte sans ligne : miroir armé");
        assert!((avant + DBP_DEFAUT_S..=apres + DBP_DEFAUT_S).contains(&echeance), "durée par défaut : {echeance}");
        netban_cache().write().clear();
    }

    // -------------------------------------------------------------------------------------
    // (5) LE RESPONDER — la commande CrowdSec porte la durée de la riposte (faux `cscli` en tête de PATH).
    // -------------------------------------------------------------------------------------

    const DBP_FAUX_CSCLI: &str = "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$DBP_BAC/appels\"\necho >> \"$DBP_BAC/appels\"\nexit 0\n";

    /// CE QU'IL TIENT, sur un sous-processus qui joue `respond_run` avec un faux `cscli` : une riposte à NULL part en
    /// `--duration 4h` (à l'octet d'avant), une à 7200 en `2h`, une à 5400 en `5400s` ; une riposte `ban_ip` à durée
    /// illisible (BLOB), posée EN TÊTE puis AU MILIEU de la file, n'est PAS exécutée, reste `approved`, et le journal
    /// porte sa ligne ENTIÈRE (identifiant compris) — les ripostes qui la suivent sont exécutées ; un `kill_pid`
    /// simulé à `ban_ttl_s` hors borne n'est pas retenu par la colonne (`dryrun`) ; le miroir HTTP de la riposte à
    /// 5400 s expire à `maintenant + 5400`. La ligne du journal est comparée ENTIÈRE à la phrase et au texte du moteur
    /// recopiés. MUTATIONS : `M_RESPONDER`, `M_RESPONDER_ERR`, `M_PLATEFORME`, `M_CSCLI`, `M_MIROIR`, `V_RESPOND_BREAK`,
    /// `V_RESPOND_JOURNAL_ID`, `M_RESPOND_TOUT_GENRE`, `BS_PHRASE_VIDEE`.
    #[test]
    fn dbp_le_responder_passe_la_duree_de_la_riposte_a_crowdsec() {
        const ENFANT: &str = "DBP_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("dbp-faux-cscli");
        let faux = bac.join("cscli");
        std::fs::write(&faux, DBP_FAUX_CSCLI).expect("fixture : faux cscli écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux cscli exécutable");
        }
        let base = bac.join("plume.db");
        let base = base.to_string_lossy().to_string();
        dbp_base(&base);
        {
            let c = open_db(&base).unwrap();
            let file = [
                ("ban_ip", "203.0.113.54", 0, "X'00'"),
                ("ban_ip", "203.0.113.51", 0, "NULL"),
                ("ban_ip", "203.0.113.55", 0, "X'00'"),
                ("ban_ip", "203.0.113.52", 0, "7200"),
                ("kill_pid", "424242", 1, "0"),
                ("ban_ip", "203.0.113.53", 0, "5400"),
            ];
            for (genre, cible, simulee, duree) in file {
                c.execute(
                    &format!("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,?1,?2,'approved',?3,'dbp',{duree})"),
                    params![genre, cible, simulee],
                ).unwrap();
            }
            let ordre: Vec<String> = c.prepare("SELECT target FROM action ORDER BY id").unwrap()
                .query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
            assert_eq!(ordre.first().map(String::as_str), Some("203.0.113.54"), "fixture : la riposte illisible est en tête");
        }
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        let avant = now();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::duree_de_ban_du_playbook_et_panneaux_sans_valeur_vide::dbp_le_responder_passe_la_duree_de_la_riposte_a_crowdsec",
            ])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("DBP_BAC", bac.as_os_str())
            .env("PLUME_DB", &base)
            .env("PLUME_BAN_BACKEND", "crowdsec")
            .env("PLUME_EXEC_PLATFORM", "linux")
            .env("PLUME_NETBAN_FROM_ACTIONS", "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let apres = now();
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stdout}\n{stderr}");
        let appels = std::fs::read_to_string(bac.join("appels")).unwrap_or_default();
        let lignes: Vec<&str> = appels.lines().collect();
        assert_eq!(lignes.len(), 3, "trois bans exécutés, aucun des deux illisibles : {appels}\n{stderr}");
        for (cible, duree) in [("203.0.113.51", "4h"), ("203.0.113.52", "2h"), ("203.0.113.53", "5400s")] {
            let attendue = format!("decisions add --ip {cible} --duration {duree} --reason plume ");
            assert_eq!(lignes.iter().filter(|l| **l == attendue).count(), 1, "« {attendue} » : {appels}");
        }
        let c = open_db(&base).unwrap();
        for cible in ["203.0.113.54", "203.0.113.55"] {
            let (id, statut): (i64, String) =
                c.query_row("SELECT id, status FROM action WHERE target=?1", params![cible], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            assert_eq!(statut, "approved", "{cible} durée illisible : non exécutée");
            let attendue = format!("[responder] WARN action {id} NON exécutée ce tour-ci : {DBP_DUREE_NON_LUE} ({DBP_MOTEUR_BLOB})");
            assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        }
        let (statut, resultat): (String, String) =
            c.query_row("SELECT status, result FROM action WHERE target='424242'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((statut.as_str(), resultat.as_str()), ("dryrun", "[dry-run] kill -TERM 424242"), "kill_pid : la colonne de durée ne le retient pas");
        let echeance: i64 = c.query_row("SELECT expires_ts FROM net_ban WHERE ip='203.0.113.53'", [], |r| r.get(0)).expect("miroir armé");
        assert!((avant + 5400..=apres + 5400).contains(&echeance), "miroir du responder : + 5400 ({echeance})");
    }

    /// Le bac d'un témoin du responder : un faux `cscli` exécutable, une base migrée et vidée, le PATH qui place le faux
    /// `cscli` en tête. Rend (bac, chemin de la base, PATH).
    fn dbp_bac_du_responder(tag: &str) -> (crate::tmp_possede::TmpPossede, String, String) {
        let bac = crate::tmp_possede::TmpPossede::neuf(tag);
        let faux = bac.join("cscli");
        std::fs::write(&faux, DBP_FAUX_CSCLI).expect("fixture : faux cscli écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux cscli exécutable");
        }
        let base = bac.join("plume.db").to_string_lossy().to_string();
        dbp_base(&base);
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        (bac, base, path)
    }

    /// CE QU'IL TIENT, en DEUX tours du responder (deux sous-processus qui jouent `respond_run`, faux `cscli`) : au
    /// premier, une riposte `ban_ip` à durée illisible (BLOB) n'est pas exécutée, reste `approved`, n'est PAS réclamée
    /// (`claimed_ts` et `done_ts` restent NULL), aucun `cscli` n'est appelé et le journal porte sa ligne ENTIÈRE ; la
    /// colonne corrigée en base (7200), le second tour l'exécute (`--duration 2h`) et la clôt `done`. MUTATIONS :
    /// `BS_RESP_RECLAME` (réclamer avant de passer : le second tour ne la voit plus), `BS_PHRASE_VIDEE`.
    #[test]
    fn dbp_le_responder_execute_au_tour_suivant_un_ban_dont_la_colonne_est_corrigee() {
        const ENFANT: &str = "DBP_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = dbp_bac_du_responder("dbp-deux-tours");
        let id = {
            let c = open_db(&base).unwrap();
            c.execute("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,'ban_ip','203.0.113.56','approved',0,'dbp',X'00')", []).unwrap();
            c.last_insert_rowid()
        };
        let nom = "tests::duree_de_ban_du_playbook_et_panneaux_sans_valeur_vide::dbp_le_responder_execute_au_tour_suivant_un_ban_dont_la_colonne_est_corrigee";
        let premier = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", nom])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("DBP_BAC", bac.as_os_str())
            .env("PLUME_DB", &base)
            .env("PLUME_BAN_BACKEND", "crowdsec")
            .env("PLUME_EXEC_PLATFORM", "linux")
            .output()
            .expect("premier tour du responder");
        let stderr = String::from_utf8_lossy(&premier.stderr).into_owned();
        assert_eq!(premier.status.code(), Some(0), "premier tour : sortie 0\n{stderr}");
        assert_eq!(std::fs::read_to_string(bac.join("appels")).unwrap_or_default(), "", "premier tour : aucun cscli appelé\n{stderr}");
        let attendue = format!("[responder] WARN action {id} NON exécutée ce tour-ci : {DBP_DUREE_NON_LUE} ({DBP_MOTEUR_BLOB})");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        {
            let c = open_db(&base).unwrap();
            let (statut, reclamee, close): (String, Option<i64>, Option<i64>) =
                c.query_row("SELECT status, claimed_ts, done_ts FROM action WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!((statut.as_str(), reclamee, close), ("approved", None, None), "premier tour : ni exécutée, ni réclamée, ni close");
            c.execute("UPDATE action SET ban_ttl_s=7200 WHERE id=?1", params![id]).unwrap();
        }
        let second = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", nom])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("DBP_BAC", bac.as_os_str())
            .env("PLUME_DB", &base)
            .env("PLUME_BAN_BACKEND", "crowdsec")
            .env("PLUME_EXEC_PLATFORM", "linux")
            .output()
            .expect("second tour du responder");
        let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
        assert_eq!(second.status.code(), Some(0), "second tour : sortie 0\n{stderr}");
        assert_eq!(
            std::fs::read_to_string(bac.join("appels")).unwrap_or_default(),
            "decisions add --ip 203.0.113.56 --duration 2h --reason plume \n",
            "second tour : le ban part avec la durée corrigée\n{stderr}"
        );
        let statut: String = open_db(&base).unwrap().query_row("SELECT status FROM action WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(statut, "done", "second tour : exécutée et close\n{stderr}");
    }

    /// CE QU'IL TIENT, sur un sous-processus qui joue `respond_run` (faux `cscli`, liste `stop_service` posée) : la
    /// colonne `ban_ttl_s` illisible ou hors borne, posée en SQL direct, ne retient AUCUNE riposte autre qu'un ban —
    /// `unban_ip` (BLOB) part en `cscli decisions delete` et se clôt `done`, `stop_service` (0) et `kill_pid` (BLOB)
    /// simulés se closent `dryrun` avec leur commande ; le journal ne dit aucune riposte retenue. MUTATION :
    /// `BS_RESP_GATE_KILL` (n'exempter que `kill_pid` : `unban_ip` et `stop_service` retenus).
    #[test]
    fn dbp_le_responder_ne_retient_par_la_colonne_aucune_riposte_autre_qu_un_ban() {
        const ENFANT: &str = "DBP_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = dbp_bac_du_responder("dbp-autres-genres");
        let allow = bac.join("responder.allow");
        std::fs::write(&allow, "dbp-svc\n").expect("fixture : liste stop_service écrite");
        {
            let c = open_db(&base).unwrap();
            for (genre, cible, simulee, duree) in [("unban_ip", "203.0.113.57", 0, "X'00'"), ("stop_service", "dbp-svc", 1, "0"), ("kill_pid", "424245", 1, "X'00'")] {
                c.execute(
                    &format!("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,?1,?2,'approved',?3,'dbp',{duree})"),
                    params![genre, cible, simulee],
                ).unwrap();
            }
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::duree_de_ban_du_playbook_et_panneaux_sans_valeur_vide::dbp_le_responder_ne_retient_par_la_colonne_aucune_riposte_autre_qu_un_ban",
            ])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("DBP_BAC", bac.as_os_str())
            .env("PLUME_DB", &base)
            .env("PLUME_BAN_BACKEND", "crowdsec")
            .env("PLUME_EXEC_PLATFORM", "linux")
            .env("PLUME_STOP_SERVICE_ALLOW", allow.as_os_str())
            .output()
            .expect("tour du responder");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "sortie 0\n{stderr}");
        assert_eq!(std::fs::read_to_string(bac.join("appels")).unwrap_or_default(), "decisions delete --ip 203.0.113.57 \n", "unban_ip exécuté\n{stderr}");
        assert!(!stderr.contains("NON exécutée ce tour-ci"), "aucune riposte retenue : {stderr}");
        let c = open_db(&base).unwrap();
        let lu = |cible: &str| -> (String, String) {
            c.query_row("SELECT status, IFNULL(result,'') FROM action WHERE target=?1", params![cible], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert_eq!(lu("203.0.113.57").0, "done", "unban_ip : clos\n{stderr}");
        assert_eq!(lu("dbp-svc"), ("dryrun".to_string(), "[dry-run] systemctl stop dbp-svc".to_string()), "stop_service : simulé\n{stderr}");
        assert_eq!(lu("424245"), ("dryrun".to_string(), "[dry-run] kill -TERM 424245".to_string()), "kill_pid : simulé\n{stderr}");
    }

    /// CE QU'IL TIENT : dans `run_playbooks`, un playbook `unban_ip`, `stop_service` ou `kill_pid` dont la colonne
    /// `ban_ttl_s` est posée en SQL direct — dans la borne (5400) puis hors borne (0) — est évalué comme avant v124 :
    /// rien d'abandonné, sa riposte est posée, et elle porte `ban_ttl_s` NULL. MUTATIONS : `BS_RUN_GATE_KILL` (n'exempter
    /// que `kill_pid` : `unban_ip` et `stop_service` portent 5400, puis ne sont pas évalués à 0), `BS_RUN_VALIDE_TOUT`
    /// (juger la colonne pour tout genre : les trois ne sont pas évalués à 0).
    #[test]
    fn dbp_le_passage_n_emploie_la_colonne_que_pour_un_ban() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (db, _tmp) = dbp_db_de_playbook("autres-genres");
        let p = _tmp.to_string();
        for duree in [5400, 0] {
            for (genre, cible) in [("unban_ip", "203.0.113.86"), ("stop_service", "dbp-svc"), ("kill_pid", "424246")] {
                db.lock().execute_batch("DELETE FROM playbook; DELETE FROM action;").unwrap();
                db.lock()
                    .execute(
                        "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role,ban_ttl_s) \
                         VALUES('dbp-genre',1,?1,0,?2,0,3600,0,NULL,'admin',?3)",
                        params![format!("SELECT '{cible}'"), genre, duree],
                    )
                    .unwrap();
                assert_eq!(run_playbooks(&db, &p), Mesure::Lue(0), "{genre} à ban_ttl_s={duree} : évalué, rien d'abandonné");
                assert_eq!(
                    dbp_sur(&db, &format!("SELECT COUNT(*) FROM action WHERE kind='{genre}' AND target='{cible}' AND ban_ttl_s IS NULL")),
                    Some(1),
                    "{genre} à ban_ttl_s={duree} : riposte posée, sans durée"
                );
            }
        }
    }

    /// CE QU'IL TIENT : la libération du point de reprise refusée PUIS son annulation (`ROLLBACK TO`) refusée — la cause
    /// rendue est celle du PREMIER refus, en entier ; le point reste ouvert (l'écrivain n'est plus en autocommit) ; la
    /// sonde des transactions orphelines que reprend le tour suivant (`ecrivain_sonde_avant_les_ecritures`) le voit et
    /// refuse d'écrire. MUTATIONS : `BS_ROLLBACK_PUIS_RELEASE` (libérer malgré l'annulation refusée : la ligne serait
    /// validée), `BS_ROLLBACK_CAUSE` (rendre la cause de l'annulation).
    #[test]
    fn dbp_une_annulation_refusee_laisse_le_point_ouvert_et_la_sonde_le_voit() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbp-annulation");
        dbp_base(&chemin);
        let db = Arc::new(Mutex::new(open_db(&chemin).unwrap()));
        let deja_release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deja_rollback = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (r1, r2) = (deja_release.clone(), deja_rollback.clone());
        let issue = {
            let conn = db.lock();
            conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Savepoint { operation: TransactionOperation::Release, savepoint_name }
                    if savepoint_name == POINT_DE_LA_RIPOSTE_ET_DE_SA_DUREE && !r1.swap(true, std::sync::atomic::Ordering::SeqCst) => Authorization::Deny,
                AuthAction::Savepoint { operation: TransactionOperation::Rollback, savepoint_name }
                    if savepoint_name == POINT_DE_LA_RIPOSTE_ET_DE_SA_DUREE && !r2.swap(true, std::sync::atomic::Ordering::SeqCst) => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            let issue = poser_la_riposte_du_playbook(&conn, 1000, "ban_ip", "203.0.113.72", "approved", 0, "playbook:dbp", None, Some(5400));
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            issue
        };
        assert!(deja_release.load(std::sync::atomic::Ordering::SeqCst) && deja_rollback.load(std::sync::atomic::Ordering::SeqCst), "fixture : libération et annulation refusées");
        match issue {
            RiposteMiseEnFile::NonEcrite(cause) => assert_eq!(cause, "point de reprise de la riposte non libéré : not authorized", "la cause du premier refus"),
            RiposteMiseEnFile::Posee(id) => panic!("riposte #{id} rendue posée"),
        }
        assert!(!db.lock().is_autocommit(), "le point de reprise reste ouvert");
        assert!(
            crate::server::boucles_de_fond::ecrivain_sonde_avant_les_ecritures(&db, "playbooks", crate::handlers::playbooks::SITE_MARQUEUR_ET_RIPOSTES).is_err(),
            "la sonde du tour suivant voit la transaction ouverte et refuse d'écrire"
        );
        let conn = db.lock();
        conn.execute_batch("ROLLBACK").expect("nettoyage : la transaction laissée ouverte s'annule");
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM action WHERE target='203.0.113.72'", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    // -------------------------------------------------------------------------------------
    // (6) `P11.25-b` — LES PANNEAUX DE DIMENSION SEMÉS.
    // -------------------------------------------------------------------------------------

    fn dbp_semer(conn: &Connection) {
        seed_web_dashboard(conn);
        seed_mail_dashboard(conn);
        seed_dataaccess_dashboard(conn);
        seed_dataacl_dashboard(conn);
        seed_kube_rbac_dashboard(conn);
    }

    fn dbp_requetes_de_dimension(conn: &Connection) -> Vec<(i64, String)> {
        conn.prepare("SELECT id, query FROM panel WHERE query LIKE '%FROM event_dim_rollup%' ORDER BY id")
            .and_then(|mut q| q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap()
    }

    /// CE QU'IL TIENT : sur une base NEUVE semée, chacun des onze panneaux de dimension exclut la valeur vide, la
    /// liste de v124 correspond EXACTEMENT aux dix d'entre eux qui ne sont pas `mail`/`verdict`, et un panneau
    /// exécuté sur des lignes où la valeur vide est la plus fréquente ne la rend pas. MUTATION : `B_SEED`.
    #[test]
    fn dbp_une_base_neuve_semee_ne_rend_pas_la_valeur_vide() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbp-neuve");
        dbp_base(&chemin);
        let conn = open_db(&chemin).unwrap();
        dbp_semer(&conn);
        let requetes = dbp_requetes_de_dimension(&conn);
        assert_eq!(requetes.len(), 11, "onze panneaux de dimension semés : {requetes:?}");
        for (id, q) in &requetes {
            assert!(q.contains(" AND val<>''"), "panneau #{id} exclut la valeur vide : {q}");
        }
        for (source, dim, limite) in crate::migrate::PANNEAUX_DE_DIMENSION_SEMES_V124 {
            let attendue = dim_panel_sql(source, dim, limite, true);
            assert_eq!(requetes.iter().filter(|(_, q)| *q == attendue).count(), 1, "{source}/{dim} semé tel que v124 l'écrit");
        }
        assert_eq!(requetes.iter().filter(|(_, q)| q.contains("source='mail'")).count(), 1, "le onzième est mail/verdict");
        conn.execute_batch(
            "INSERT INTO event_dim_rollup(bucket,source,dim,val,n) VALUES(100,'web','vhost','',693),(100,'web','vhost','a.example',5);",
        ).unwrap();
        let q = requetes.iter().map(|(_, q)| q.clone()).find(|q| q.contains("dim='vhost'")).unwrap().replace("__FROM__", "0");
        let vals: Vec<String> = conn.prepare(&q).unwrap().query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(vals, vec!["a.example".to_string()], "la valeur vide n'est pas servie");
    }

    /// CE QU'IL TIENT : une base v123 (colonnes `ban_ttl_s` retirées, panneaux de dimension à leur requête
    /// d'origine) migrée : les dix panneaux sont réécrits, le panneau ÉDITÉ par l'exploitant reste intact, un panneau
    /// GXQL (`is_soql = 1`) dont le texte est celui d'origine reste intact, les deux colonnes existent, un playbook
    /// existant garde la durée d'avant (NULL, servie 4 h), la version est à la tête. MUTATIONS : `B_GARDE_REQUETE`,
    /// `B_GARDE_SOQL`, `B_LISTE`, `B_COLONNE_ACTION`.
    #[tokio::test]
    async fn dbp_une_base_v123_migree_reecrit_les_panneaux_d_origine_et_garde_les_edites() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbp-v123");
        dbp_base(&chemin);
        let edite = "SELECT val AS \"vhost\", SUM(n) AS count FROM event_dim_rollup WHERE source='web' AND dim='vhost' AND bucket>=__FROM__ GROUP BY val ORDER BY count ASC";
        let gxql_meme_texte = dim_panel_sql("web", "status", 0, false);
        {
            let conn = open_db(&chemin).unwrap();
            dbp_semer(&conn);
            for (source, dim, limite) in crate::migrate::PANNEAUX_DE_DIMENSION_SEMES_V124 {
                conn.execute("UPDATE panel SET query=?1 WHERE query=?2", params![dim_panel_sql(source, dim, limite, false), dim_panel_sql(source, dim, limite, true)]).unwrap();
            }
            let did: i64 = conn.query_row("SELECT dashboard_id FROM panel LIMIT 1", [], |r| r.get(0)).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,'dbp-edite',?2,0,'bar',90,2)", params![did, edite]).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) VALUES(?1,'dbp-gxql',?2,1,'bar',91,2)", params![did, gxql_meme_texte]).unwrap();
            conn.execute("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s) VALUES('dbp-existant',0,?1,1,'ban_ip',300,3600)", params![DBP_REQUETE]).unwrap();
            conn.execute_batch(
                "ALTER TABLE playbook DROP COLUMN ban_ttl_s; ALTER TABLE action DROP COLUMN ban_ttl_s; \
                 UPDATE meta SET value='123' WHERE key='schema_version';",
            ).expect("une base v123 se fabrique en retirant les colonnes de v124");
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%FROM event_dim_rollup%' AND query NOT LIKE '%val<>%' AND is_soql=0 AND title NOT LIKE 'dbp-%'", [], |r| r.get::<_, i64>(0)).unwrap(),
                10,
                "fixture : dix panneaux à la requête d'origine"
            );
            assert!(migrate(&conn), "la migration 123 -> 124 passe");
            let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
            assert_eq!(v, CODE_SCHEMA_MAX.to_string());
            // `P11.25-f` (v125) : la chaîne va au-delà de 124 ; ce témoin tient « 124 est passée », pas « 124 est la dernière ».
            assert!(v.parse::<i64>().is_ok_and(|n| n >= 124), "v124 est passée : {v}");
            for (source, dim, limite) in crate::migrate::PANNEAUX_DE_DIMENSION_SEMES_V124 {
                let n: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE query=?1 AND is_soql=0", params![dim_panel_sql(source, dim, limite, true)], |r| r.get(0)).unwrap();
                assert_eq!(n, 1, "{source}/{dim} réécrit");
            }
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM panel WHERE query LIKE '%FROM event_dim_rollup%' AND query NOT LIKE '%val<>%' AND is_soql=0 AND title NOT LIKE 'dbp-%'", [], |r| r.get::<_, i64>(0)).unwrap(),
                0,
                "plus aucun panneau semé à la requête d'origine"
            );
            let lu = |titre: &str| conn.query_row("SELECT query FROM panel WHERE title=?1", params![titre], |r| r.get::<_, String>(0)).unwrap();
            assert_eq!(lu("dbp-edite"), edite, "le panneau édité n'est jamais écrasé");
            assert_eq!(lu("dbp-gxql"), gxql_meme_texte, "un panneau GXQL n'est pas réécrit");
            assert!(crate::seeds::col_exists(&conn, "action", "ban_ttl_s") && crate::seeds::col_exists(&conn, "playbook", "ban_ttl_s"), "les deux colonnes existent");
        }
        let st = ds_file_state(&chemin);
        let v = playbooks_list(State(st.clone()), Extension(dbp_qui("viewer"))).await.0;
        let rows = v["playbooks"].as_array().unwrap_or_else(|| panic!("{v}"));
        assert!(!rows.is_empty(), "le playbook existant est servi : {v}");
        for r in rows {
            assert_eq!((r["ban_ttl_s"].clone(), r["ban_duration_s"].clone()), (Value::Null, json!(DBP_DEFAUT_S)), "durée d'avant : {r}");
        }
    }
}
