// =====================================================================================
// `P10.33-h` (sorties) — TROIS FAITS QUE LA REPRISE DE LA VAGUE AW LAISSAIT SANS TÉMOIN.
//
// VU sur 309315de + lot-AW6 (re-mesuré par le lot, avis du vérificateur AW6) :
//   * `statut_du_rapport_ecrit` (handlers/scheduled_reports.rs) nomme le tenant du tour sur la ligne d'un statut de
//     rapport planifié refusé, mais aucun témoin ne passait par elle : la mention retirée de ce seul site restait verte
//     (mutant R_STATUT du vérificateur) ;
//   * la fenêtre de dispatch `ORDER BY ts LIMIT 20` (handlers/notifiers.rs) n'était dite que dans la tête d'un témoin :
//     aucune assertion ne la jugeait ;
//   * `run_due_rules` (handlers/detection.rs) laisse non compté un `Ok(0)` sur `population_vue` et `last_fired`
//     (« règle effacée ») : un commentaire seul, sans témoin.
//
// ATTENDU, tenu ici : tout dans UN sous-processus où seul ce témoin tourne (compteurs de processus exacts, lignes de
// journal comparées ENTIÈRES à des littéraux) :
//   * deux tenants réels en mode multi-tenant, parcourus par `for_each_active_tenant` : dans chacun, deux rapports dus
//     dont le jeu de données manque ; l'écriture de la trace d'absence (`last_error`) est refusée (`RAISE(ABORT)`) pour
//     l'un, sans effet (`RAISE(IGNORE)`) pour l'autre : chacun a SA ligne, qui nomme SON tenant, et compte un abandon ;
//     en mode 0 les mêmes lignes, sans tenant, à l'octet ;
//   * vingt alertes de tête au marqueur refusé durablement occupent la fenêtre : la vingt-et-unième ne part pas, deux
//     tours de suite (vingt lignes, vingt comptes par tour) ; avec dix-neuf refus durables la vingtième part au premier
//     tour et la vingt-et-unième au second ;
//   * une règle qui tire et qu'on efface entre l'évaluation et les écritures n'est pas comptée et n'écrit aucune ligne ;
//     une écriture de `population_vue` ou de `last_fired` ignorée par un déclencheur (`RAISE(IGNORE)`) non plus (limite
//     assumée, dite au site).
//
// MUTANTS (posés sous cfg!(test) par variable de mutation, retirés avant le commit), chacun rouge sur ce témoin :
// AX4_STATUT_SANS_TENANT (la mention retirée de `statut_du_rapport_ecrit`), AX4_FENETRE_21 et AX4_FENETRE_19 (la borne
// de la fenêtre), AX4_POP_OK0_COMPTE et AX4_FIRED_OK0_COMPTE (un `Ok(0)` compté abandonné).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par verrou ou disque plein (même `Err`, non fabriqué).
// =====================================================================================
mod statut_de_rapport_fenetre_de_dispatch_et_regle_effacee {
    use super::*;
    use crate::handlers::detection::run_due_rules;
    use crate::handlers::notifiers::dispatch_notifications;
    use crate::handlers::scheduled_reports::run_due_reports;
    use crate::mesure_environnement::Mesure;
    use crate::state::{for_each_active_tenant, migrate_control, ControlPlane, TenantDbManager};

    const AX4_ENFANT: &str = "AX4_ENFANT_STATUT_FENETRE_REGLE";
    const AX4_PHASE: &str = "AX4-PHASE:";
    const AX4_OBS: &str = "AX4-OBS:";
    const AX4_TENANT_A: &str = "t-ax4-alpha";
    const AX4_TENANT_B: &str = "t-ax4-beta";
    const AX4_RAPPORT_REFUSE: i64 = 81;
    const AX4_RAPPORT_SANS_EFFET: i64 = 82;
    const AX4_CAUSE_STATUT: &str = "statut refusé ax4";
    const AX4_CAUSE_SANS_EFFET: &str = "0 ligne(s) écrite(s) au lieu d'une";
    const AX4_CAUSE_MARQUEUR: &str = "marqueur durable ax4";
    const AX4_CANAL: i64 = 91;
    const AX4_REGLE_EFFACEE: &str = "ax4-effacee";

    // ---------------------------------------------------------------- les phrases attendues (littéraux)

    fn ax4_mention(tenant: Option<&str>) -> String {
        tenant.map(|t| format!(" (tenant '{t}')")).unwrap_or_default()
    }
    fn ax4_ligne_statut(tenant: Option<&str>, id: i64, cause: &str) -> String {
        format!(
            "[plume] rapport planifié {id}{} : référence introuvable ou désactivée NON CONSIGNÉE (last_error) : {cause}",
            ax4_mention(tenant)
        )
    }
    fn ax4_ligne_marqueur(id: i64) -> String {
        format!(
            "[plume] dispatch : alerte {id} : marqueur `notified` NON ÉCRIT, rien n'est envoyé pour elle ce tour-ci ; elle reste \
             à notifier et sera retentée au tour suivant, les alertes suivantes de ce tour sont traitées : {AX4_CAUSE_MARQUEUR}"
        )
    }

    // ---------------------------------------------------------------- fixtures : rapports

    /// Deux rapports dus dont le jeu de données manque ; la trace d'absence est refusée pour l'un, sans effet pour l'autre.
    fn ax4_garnir_les_rapports(conn: &Connection) {
        conn.execute_batch(&format!(
            "DELETE FROM scheduled_report; \
             INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES({AX4_RAPPORT_REFUSE},'ax4-refuse',8801,8802,3600); \
             INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s) VALUES({AX4_RAPPORT_SANS_EFFET},'ax4-sans-effet',8801,8802,3600); \
             CREATE TRIGGER ax4_statut_refuse BEFORE UPDATE OF last_error ON scheduled_report WHEN OLD.id={AX4_RAPPORT_REFUSE} \
               BEGIN SELECT RAISE(ABORT,'{AX4_CAUSE_STATUT}'); END; \
             CREATE TRIGGER ax4_statut_sans_effet BEFORE UPDATE OF last_error ON scheduled_report WHEN OLD.id={AX4_RAPPORT_SANS_EFFET} \
               BEGIN SELECT RAISE(IGNORE); END;"
        ))
        .unwrap();
    }

    /// Un gestionnaire en MODE MULTI-TENANT (control-plane sur disque) aux deux tenants, bases migrées puis garnies.
    fn ax4_mode_multi_tenant(tmp: &crate::tmp_possede::TmpPossede) -> TenantDbManager {
        let pc = tmp.sous("control.db").chemin().to_string_lossy().to_string();
        let cc = open_db_keyed(&pc, None).unwrap();
        migrate_control(&cc);
        let cp = ControlPlane { conn: Arc::new(Mutex::new(cc)), db_path: Arc::new(pc) };
        for t in [AX4_TENANT_A, AX4_TENANT_B] {
            let p = tmp.sous(&format!("{t}.db")).chemin().to_string_lossy().to_string();
            cp.conn
                .lock()
                .execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?1,'',?2,?3,0)", params![t, p, now()])
                .unwrap();
        }
        let mgr = TenantDbManager {
            default_db_path: Arc::new(String::new()),
            default_writer: Arc::new(Mutex::new(test_db())),
            control: Some(cp),
            writers: Arc::new(Mutex::new(HashMap::new())),
        };
        for t in [AX4_TENANT_A, AX4_TENANT_B] {
            let h = mgr.handle_for(t).expect("fixture : base du tenant");
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            ax4_garnir_les_rapports(&c);
        }
        mgr
    }

    // ---------------------------------------------------------------- fixtures : fenêtre de dispatch

    /// Une base aux alertes `premier..premier+n` (ts croissants, sévérité 3), un canal lookup qui prend tout (envois
    /// comptés dans `ax4_envois`) et le marqueur refusé durablement pour les `refusees` premières.
    fn ax4_base_fenetre(premier: i64, n: i64, refusees: i64) -> Arc<Mutex<Connection>> {
        let conn = test_db();
        conn.execute_batch(&format!(
            "DELETE FROM alert; DELETE FROM notifier; DELETE FROM notification_policy; DELETE FROM silence; \
             CREATE TABLE ax4_envois(cle TEXT); \
             CREATE TRIGGER ax4_compte_envoi AFTER INSERT ON lookup_kv BEGIN INSERT INTO ax4_envois VALUES(NEW.key); END; \
             CREATE TRIGGER ax4_marqueur_durable BEFORE UPDATE OF notified ON alert WHEN OLD.id < {} \
               BEGIN SELECT RAISE(ABORT,'{AX4_CAUSE_MARQUEUR}'); END;",
            premier + refusees
        ))
        .unwrap();
        conn.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(?1,'ax4','lookup',1,'',0,'{\"lookup\":\"ax4_pris\",\"key_field\":\"host\"}')",
            params![AX4_CANAL],
        )
        .unwrap();
        for i in 0..n {
            conn.execute(
                "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,?2,'r.ax4',3,'A','','new','','',?3)",
                params![premier + i, now() - 1000 + i, format!("192.0.2.{}", 100 + i)],
            )
            .unwrap();
        }
        Arc::new(Mutex::new(conn))
    }

    /// [ticks aveugles au total, sous `dispatch_marqueur`].
    fn ax4_marqueurs() -> [u64; 2] {
        [
            crate::metrics::TICKS_AVEUGLES_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
            crate::metrics::tick_aveugle_de("dispatch_marqueur").map(|(n, _)| n).unwrap_or(0),
        ]
    }

    /// `ecart total,marqueur : envois cumulés depuis la création de la base : identifiants marqués`.
    fn ax4_etat(avant: [u64; 2], db: &Arc<Mutex<Connection>>) -> String {
        let apres = ax4_marqueurs();
        let c = db.lock();
        let envois: i64 = c.query_row("SELECT COUNT(*) FROM ax4_envois", [], |r| r.get(0)).unwrap();
        let mut st = c.prepare("SELECT id FROM alert WHERE notified=1 ORDER BY id").unwrap();
        let marquees: Vec<String> = st.query_map([], |r| r.get::<_, i64>(0)).unwrap().map(|r| r.unwrap().to_string()).collect();
        format!("{},{}:{envois}:{}", apres[0] - avant[0], apres[1] - avant[1], marquees.join(","))
    }

    // ---------------------------------------------------------------- fixtures : règle

    /// Base sur disque pour `run_due_rules` (l'évaluation relit le fichier), avec une règle qui TIRE (`SELECT 5` > 1) ;
    /// `population_vue` vaut d'abord `ax4-avant` (le tir y écrit la chaîne vide : aucune population déclarée).
    fn ax4_base_regle(tag: &str, nom: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String, i64) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("ax4-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        let id = {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute_batch("DELETE FROM rule; DELETE FROM alert;").unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,population_vue) VALUES(?1,1,'SELECT 5',0,'>',1,3,600,3600,'ax4-avant')",
                params![nom],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        (tmp, db, p, id)
    }

    /// Le crochet d'avant les écritures du tick : efface la règle `AX4_REGLE_EFFACEE` (verrou relâché pendant l'évaluation).
    fn ax4_effacer_la_regle(db: &Arc<Mutex<Connection>>) {
        db.lock().execute("DELETE FROM rule WHERE name=?1", params![AX4_REGLE_EFFACEE]).unwrap();
    }

    // ---------------------------------------------------------------- l'enfant

    fn ax4_enfant() {
        // ① Statut de rapport refusé / sans effet, deux tenants réels, puis le mode 0.
        let tmp_mt = crate::tmp_possede::TmpPossede::neuf("ax4-mode-multi-tenant");
        let mgr = ax4_mode_multi_tenant(&tmp_mt);
        let mut visites = Vec::new();
        for_each_active_tenant(&mgr, |tid, handle, db_path| {
            visites.push(tid.to_string());
            eprintln!("{AX4_PHASE}{tid}");
            let bilan = run_due_reports(handle, db_path);
            println!("{AX4_OBS}bilan_{tid}:{bilan:?}");
        });
        visites.sort();
        println!("{AX4_OBS}visites:{}", visites.join(","));
        let base0 = Arc::new(Mutex::new(test_db()));
        ax4_garnir_les_rapports(&base0.lock());
        let mgr0 = TenantDbManager {
            default_db_path: Arc::new(String::new()),
            default_writer: base0.clone(),
            control: None,
            writers: Arc::new(Mutex::new(HashMap::new())),
        };
        for_each_active_tenant(&mgr0, |tid, handle, db_path| {
            eprintln!("{AX4_PHASE}mode0");
            println!("{AX4_OBS}mode0_tenant:{tid}");
            let bilan = run_due_reports(handle, db_path);
            println!("{AX4_OBS}bilan_mode0:{bilan:?}");
        });

        // ② La fenêtre de dispatch : vingt refus durables en tête sur vingt-et-une, puis dix-neuf.
        let db = ax4_base_fenetre(7101, 21, 20);
        for tour in 1..=2 {
            let avant = ax4_marqueurs();
            eprintln!("{AX4_PHASE}pleine_{tour}");
            dispatch_notifications(&db);
            println!("{AX4_OBS}pleine_{tour}:{}", ax4_etat(avant, &db));
        }
        let db = ax4_base_fenetre(7201, 21, 19);
        for tour in 1..=2 {
            let avant = ax4_marqueurs();
            eprintln!("{AX4_PHASE}avance_{tour}");
            dispatch_notifications(&db);
            println!("{AX4_OBS}avance_{tour}:{}", ax4_etat(avant, &db));
        }

        // ③ `Ok(0)` sur population_vue / last_fired : règle effacée pendant l'évaluation, puis chaque écriture ignorée.
        let (_t1, db, p, id) = ax4_base_regle("effacee", AX4_REGLE_EFFACEE);
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(ax4_effacer_la_regle));
        eprintln!("{AX4_PHASE}effacee");
        let m = run_due_rules(&db, &p);
        crate::handlers::detection::AVANT_LES_ECRITURES_DU_TICK.with(|h| h.set(crate::handlers::detection::sans_crochet));
        let restantes: i64 = db.lock().query_row("SELECT COUNT(*) FROM rule WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        println!("{AX4_OBS}effacee:{m:?}:{restantes}");
        for (nom, colonne) in [("ignore_population", "population_vue"), ("ignore_dernier_tir", "last_fired")] {
            let (_t, db, p, id) = ax4_base_regle(nom, &format!("ax4-{nom}"));
            db.lock()
                .execute_batch(&format!("CREATE TRIGGER ax4_{nom} BEFORE UPDATE OF {colonne} ON rule BEGIN SELECT RAISE(IGNORE); END;"))
                .unwrap();
            eprintln!("{AX4_PHASE}{nom}");
            let m = run_due_rules(&db, &p);
            let (vue, tir): (String, Option<i64>) =
                db.lock().query_row("SELECT population_vue, last_fired FROM rule WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            println!("{AX4_OBS}{nom}:{m:?}:{}:{}", vue == "ax4-avant", tir.is_some());
        }
        eprintln!("{AX4_PHASE}fin");
    }

    // ---------------------------------------------------------------- le témoin

    #[test]
    fn ax4_statut_de_rapport_nomme_le_tenant_fenetre_de_dispatch_bornee_et_ok0_d_une_regle_effacee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AX4_ENFANT).is_ok() {
            ax4_enfant();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::statut_de_rapport_fenetre_de_dispatch_et_regle_effacee::ax4_statut_de_rapport_nomme_le_tenant_fenetre_de_dispatch_bornee_et_ok0_d_une_regle_effacee",
            ])
            .env(AX4_ENFANT, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let obs = |nom: &str| -> String {
            let cle = format!("{AX4_OBS}{nom}:");
            stdout
                .lines()
                .find_map(|l| l.split_once(&cle).map(|(_, r)| r.to_string()))
                .unwrap_or_else(|| panic!("contrôle : observation {nom} : {stdout}"))
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AX4_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AX4_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps
                .lines()
                .filter(|l| l.starts_with("[plume] ") || l.starts_with("[rapports] ") || l.starts_with("[detection] "))
                .map(str::to_string)
                .collect()
        };

        // ① Chaque ligne de statut refusé nomme SON tenant ; le mode 0 n'en nomme aucun.
        assert_eq!(obs("visites"), format!("{AX4_TENANT_A},{AX4_TENANT_B}"), "contrôle : les deux tenants sont parcourus");
        for tenant in [AX4_TENANT_A, AX4_TENANT_B] {
            assert_eq!(
                phase(tenant),
                vec![
                    ax4_ligne_statut(Some(tenant), AX4_RAPPORT_REFUSE, AX4_CAUSE_STATUT),
                    ax4_ligne_statut(Some(tenant), AX4_RAPPORT_SANS_EFFET, AX4_CAUSE_SANS_EFFET),
                ],
                "tour de {tenant} : une ligne par statut non écrit, refusé puis sans effet, qui nomme le tenant"
            );
            assert_eq!(obs(&format!("bilan_{tenant}")), format!("{:?}", Mesure::<u32>::Lue(2)), "tour de {tenant} : deux abandons");
        }
        assert_eq!(obs("mode0_tenant"), "default", "contrôle : le mode 0 passe `default`");
        assert_eq!(
            phase("mode0"),
            vec![
                ax4_ligne_statut(None, AX4_RAPPORT_REFUSE, AX4_CAUSE_STATUT),
                ax4_ligne_statut(None, AX4_RAPPORT_SANS_EFFET, AX4_CAUSE_SANS_EFFET),
            ],
            "mode 0 : les lignes d'avant, à l'octet, sans « (tenant 'default') »"
        );
        assert_eq!(obs("bilan_mode0"), format!("{:?}", Mesure::<u32>::Lue(2)), "mode 0 : deux abandons");

        // ② La fenêtre `ORDER BY ts LIMIT 20` : vingt refus durables en tête l'occupent, la vingt-et-unième attend.
        let vingt: Vec<String> = (7101..=7120).map(ax4_ligne_marqueur).collect();
        for tour in 1..=2 {
            assert_eq!(obs(&format!("pleine_{tour}")), "20,20:0:", "tour {tour} : vingt comptes, aucun envoi, aucune alerte marquée");
            assert_eq!(phase(&format!("pleine_{tour}")), vingt, "tour {tour} : vingt lignes, une par alerte de la fenêtre");
        }
        // Dix-neuf refus durables : la file avance d'une alerte par tour.
        let dix_neuf: Vec<String> = (7201..=7219).map(ax4_ligne_marqueur).collect();
        assert_eq!(obs("avance_1"), "19,19:1:7220", "tour 1 : la vingtième part et est marquée, la vingt-et-unième hors fenêtre");
        assert_eq!(phase("avance_1"), dix_neuf, "tour 1 : dix-neuf lignes");
        assert_eq!(obs("avance_2"), "19,19:2:7220,7221", "tour 2 : la vingt-et-unième entre dans la fenêtre et part (envois cumulés : la vingtième ne repart pas)");
        assert_eq!(phase("avance_2"), dix_neuf, "tour 2 : les mêmes dix-neuf lignes");

        // ③ `Ok(0)` sur population_vue / last_fired : non compté, aucune ligne.
        assert_eq!(obs("effacee"), format!("{:?}:0", Mesure::<u32>::Lue(0)), "règle effacée pendant l'évaluation : rien d'abandonné, règle absente");
        assert!(phase("effacee").is_empty(), "règle effacée : aucune ligne : {:?}", phase("effacee"));
        assert_eq!(
            obs("ignore_population"),
            format!("{:?}:true:true", Mesure::<u32>::Lue(0)),
            "population_vue ignorée (restée `ax4-avant`) : non comptée (limite assumée), last_fired posé"
        );
        assert!(phase("ignore_population").is_empty(), "population_vue ignorée : aucune ligne : {:?}", phase("ignore_population"));
        assert_eq!(
            obs("ignore_dernier_tir"),
            format!("{:?}:false:false", Mesure::<u32>::Lue(0)),
            "last_fired ignoré (resté NULL) : non compté (limite assumée), population_vue écrite"
        );
        assert!(phase("ignore_dernier_tir").is_empty(), "last_fired ignoré : aucune ligne : {:?}", phase("ignore_dernier_tir"));
    }
}
