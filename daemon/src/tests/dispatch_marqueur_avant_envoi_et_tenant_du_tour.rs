// =====================================================================================
// `P10.33-h` (sorties) — LE MARQUEUR `notified` PRÉCÈDE LES ENVOIS, UNE ALERTE QU'AUCUN CANAL NE VISE EST COMPTÉE, UN
// RAFRAÎCHISSEMENT D'ALERTE SANS EFFET EST JUGÉ, ET LES LIGNES DU TOUR NOMMENT LE TENANT.
//
// VU sur e66bb760 (re-mesuré par le lot) :
//   * `dispatch_notifications` envoyait PUIS marquait ; au premier marqueur refusé, `return` : l'alerte, déjà partie,
//     restait `notified=0` et repartait à CHAQUE tour vers ses canaux, et un refus propre à une ligne bloquait la file en
//     tête (les suivantes jamais traitées) ;
//   * une alerte non silencée qu'aucun canal ne visait (aucun canal activé, aucun routé, tous au-dessus de sa sévérité)
//     n'entrait dans aucun compte (`compter_une_alerte_sans_aucun_envoi_pris` exige un canal visé) ;
//   * `run_due_rules` ne jugeait pas un `Ok(0)` du rafraîchissement de l'alerte ouverte : `INSERT OR IGNORE` à `Ok(0)`
//     (clé tenue par une alerte ni nouvelle ni prise en compte) puis rafraîchissement à `Ok(0)` = tir vu nulle part,
//     règle comptée saine ;
//   * la ligne d'un tick aveugle et celles du dispatch ne nommaient pas le tenant (dispatch appelé sans tenant) ;
//   * la phrase du marqueur était choisie en comparant une constante au littéral passé par l'appelant, et disait
//     « traitée (envoyée ou silencée) » même quand aucun canal n'était visé.
//
// ATTENDU, tenu ici : tout dans UN sous-processus où seul ce témoin tourne (compteurs de processus exacts, lignes de
// journal comparées ENTIÈRES à des littéraux) :
//   * marqueur refusé (`RAISE(ABORT)`) puis sans effet (`RAISE(IGNORE)`) sur la PREMIÈRE alerte de trois : rien ne part
//     pour elle, les deux suivantes partent et sont marquées, un compte et une ligne pour elle ; au tour suivant elle est
//     retentée, toujours sans envoi, et les deux autres ne repartent pas (compte des envois par déclencheur) ;
//   * deux tenants réels en mode multi-tenant, parcourus par `for_each_active_tenant` (le parcours de TOUTES les boucles
//     de fond : règles, rapports, rétention…) : chaque ligne (marqueur, envoi refusé, alerte remise nulle part, tick
//     aveugle réel `dispatch_notifiers`, rapport planifié dû non exécuté du tick des rapports) nomme SON tenant ; hors du
//     parcours, après une panique dans un corps, plus aucun nom ; un nom posé avant le parcours revient après lui ; en
//     mode 0 (la production actuelle) le parcours ne nomme rien : les lignes sont celles d'avant, à l'octet ;
//   * alerte hors de tout canal, par raison (aucun actif — un canal désactivé compris —, aucun routé, sous le seuil de
//     tous), jamais pour une alerte silencée, visée, ou dont le marqueur est refusé ; servie en JSON et en Prometheus ;
//   * rafraîchissement sans effet : chaque bras (alerte écrite à ce tir / clé déjà tenue) a sa ligne et compte la règle ;
//     un épisode ouvert rafraîchi et un tir neuf ne comptent rien.
//
// MUTANTS (posés sous cfg!(test) par variable de mutation, retirés avant le commit), chacun rouge sur ce témoin :
// MARQUEUR_RETURN (l'ancien `return`), MARQUEUR_PUIS_ENVOI (refus sans `continue`), MARQUEUR_OK0 (`Ok(0)` nominal),
// MARQUEUR_MUET (aucun compte), MARQUEUR_TOTAL_MUET (total non incrémenté), TENANT_NON_POSE, TENANT_FIGE,
// TENANT_NON_RENDU, MENTION_MARQUEUR, MENTION_REFUS, MENTION_AUCUN, MENTION_AVEUGLE (une mention retirée par site) ;
// correction : TENANT_MODE0_NOMME (le mode 0 nomme `default`), TENANT_RENDU_A_VIDE (le gardien remet « aucun » au lieu
// du nom d'avant), MENTION_RAPPORT (la ligne du tick des rapports sans le tenant) ; et l'instrument
// `reponse_lisible_et_destination::tick_des_alertes` rougit si la fermeture `catch_unwind` du planificateur ne nomme
// plus `tick_de_detection_d_un_tenant` (forme du lot avant correction, rejouée sur le binaire compilé) ;
// HORS_MUET, HORS_SILENCE_COMPTE, HORS_ROUTE_SEUIL (raisons permutées), HORS_ACTIF_ROUTE, HORS_NON_SERVI,
// RAFRAICHI_OK0_MUET, RAFRAICHI_BRAS_INVERSE, INSERT_TOUJOURS_ECRITE.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par verrou ou disque plein (même `Err`, non fabriqué) ; la mort du
// processus entre le marqueur et les envois (l'alerte n'est alors pas notifiée : au plus une fois, prix dit au site) ;
// une file dont les vingt premières alertes ont chacune un marqueur refusé durablement (elles occupent la fenêtre lue,
// `ORDER BY ts LIMIT 20` : les suivantes attendent, et un refus global coûte vingt lignes et vingt comptes par tour au
// lieu d'un) ; les lignes des autres boucles de fond qui n'écrivent pas par ces fonctions (une ligne `[rapports]` hors
// des deux reprises ici, `[retention]`…) ne nomment toujours pas le tenant.
// =====================================================================================
mod dispatch_marqueur_avant_envoi_et_tenant_du_tour {
    use super::*;
    use crate::handlers::detection::run_due_rules;
    use crate::handlers::notifiers::dispatch_notifications;
    use crate::mesure_environnement::Mesure;
    use crate::handlers::scheduled_reports::run_due_reports;
    use crate::state::{for_each_active_tenant, migrate_control, ControlPlane, TenantDbManager};

    const AW6_ENFANT: &str = "AW6_ENFANT_MARQUEUR_ET_TENANT";
    const AW6_PHASE: &str = "AW6-PHASE:";
    const AW6_OBS: &str = "AW6-OBS:";
    const AW6_CAUSE_MARQUEUR: &str = "marqueur refusé aw6";
    const AW6_CAUSE_SANS_EFFET: &str = "0 ligne(s) écrite(s) au lieu d'une";
    const AW6_CAUSE_LOOKUP: &str = "lookup refusé aw6";
    const AW6_CANAL: i64 = 61;
    const AW6_TENANT_A: &str = "t-aw6-alpha";
    const AW6_TENANT_B: &str = "t-aw6-beta";
    const AW6_RAPPORT: i64 = 71;

    // ---------------------------------------------------------------- fixtures

    /// Une base complète, sans alerte ni canal ; les alertes données (sévérité 3, hôtes distincts, dans l'ordre) ; chaque
    /// écriture dans `lookup_kv` (un envoi pris par un canal lookup) est comptée dans `aw6_envois`.
    fn aw6_base(alertes: &[i64]) -> Connection {
        let conn = test_db();
        aw6_garnir(&conn, alertes);
        conn
    }

    /// Le garnissage d'`aw6_base`, sur une base déjà ouverte (celle d'un tenant).
    fn aw6_garnir(conn: &Connection, alertes: &[i64]) {
        conn.execute_batch(
            "DELETE FROM alert; DELETE FROM notifier; DELETE FROM notification_policy; DELETE FROM silence; \
             CREATE TABLE aw6_envois(cle TEXT); \
             CREATE TRIGGER aw6_compte_envoi AFTER INSERT ON lookup_kv BEGIN INSERT INTO aw6_envois VALUES(NEW.key); END;",
        )
        .unwrap();
        for (i, id) in alertes.iter().enumerate() {
            conn.execute(
                "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,?2,'r.aw6',3,'A','','new','','',?3)",
                params![id, now() - 100 + i as i64, format!("192.0.2.{}", 60 + i)],
            )
            .unwrap();
        }
    }

    /// Le canal lookup `AW6_CANAL` (seuil `seuil`, activé ou non) vers le lookup `nom` ; `aw6_refuse` refuse toute écriture.
    fn aw6_canal_lookup(conn: &Connection, nom: &str, seuil: i64, actif: bool) {
        conn.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(?1,'aw6','lookup',?2,'',?3,?4)",
            params![AW6_CANAL, i64::from(actif), seuil, format!("{{\"lookup\":\"{nom}\",\"key_field\":\"host\"}}")],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS aw6_refus_lookup BEFORE INSERT ON lookup_kv WHEN NEW.name='aw6_refuse' \
             BEGIN SELECT RAISE(ABORT,'{AW6_CAUSE_LOOKUP}'); END;"
        ))
        .unwrap();
    }

    fn aw6_marqueur_refuse(conn: &Connection, id: i64, geste: &str) {
        conn.execute_batch(&format!(
            "CREATE TRIGGER aw6_marqueur_{id} BEFORE UPDATE OF notified ON alert WHEN OLD.id={id} BEGIN SELECT {geste}; END;"
        ))
        .unwrap();
    }

    fn aw6_envois(db: &Arc<Mutex<Connection>>) -> i64 {
        db.lock().query_row("SELECT COUNT(*) FROM aw6_envois", [], |r| r.get(0)).unwrap()
    }

    fn aw6_marques(db: &Arc<Mutex<Connection>>) -> String {
        let c = db.lock();
        let mut st = c.prepare("SELECT notified FROM alert ORDER BY id").unwrap();
        let v: Vec<i64> = st.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        v.iter().map(i64::to_string).collect()
    }

    /// [ticks aveugles au total, sous `dispatch_marqueur`].
    fn aw6_marqueurs() -> [u64; 2] {
        [
            crate::metrics::TICKS_AVEUGLES_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
            crate::metrics::tick_aveugle_de("dispatch_marqueur").map(|(n, _)| n).unwrap_or(0),
        ]
    }

    /// [total, aucun actif, aucun routé, sous le seuil de tous].
    fn aw6_hors() -> [u64; 4] {
        let m = crate::metrics::ALERTES_HORS_DE_TOUT_CANAL.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let de = |k: &str| m.get(k).copied().unwrap_or(0);
        [
            crate::metrics::ALERTES_HORS_DE_TOUT_CANAL_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
            de(crate::metrics::RAISON_AUCUN_CANAL_ACTIF),
            de(crate::metrics::RAISON_AUCUN_CANAL_ROUTE),
            de(crate::metrics::RAISON_SOUS_LE_SEUIL_DE_TOUS),
        ]
    }

    fn aw6_ecart<const N: usize>(avant: [u64; N], apres: [u64; N]) -> String {
        avant.iter().zip(apres.iter()).map(|(a, b)| (b - a).to_string()).collect::<Vec<_>>().join(",")
    }

    /// Une base de tenant pour le tour nommé : l'alerte `id` a son marqueur refusé, l'alerte `id + 1` part vers un lookup
    /// qui refuse (envoi refusé, puis remise nulle part) ; le rapport planifié `AW6_RAPPORT`, dû, a sa définition
    /// illisible (rôle d'exécution BLOB : dû non exécuté).
    fn aw6_garnir_le_tenant(conn: &Connection, id: i64) {
        aw6_garnir(conn, &[id, id + 1]);
        aw6_canal_lookup(conn, "aw6_refuse", 0, true);
        aw6_marqueur_refuse(conn, id, &format!("RAISE(ABORT,'{AW6_CAUSE_MARQUEUR}')"));
        conn.execute_batch(&format!(
            "DELETE FROM scheduled_report; DELETE FROM dataset WHERE id={AW6_RAPPORT}; INSERT INTO dataset(id,name,soql) VALUES({AW6_RAPPORT},'aw6-ds','search | table message'); \
             INSERT INTO scheduled_report(id,name,dataset_id,notifier_id,interval_s,run_as_role) \
             VALUES({AW6_RAPPORT},'aw6-rapport',{AW6_RAPPORT},{AW6_CANAL},3600,CAST('viewer' AS BLOB));"
        ))
        .unwrap();
    }

    /// Un gestionnaire en MODE MULTI-TENANT (control-plane sur disque) aux deux tenants `AW6_TENANT_A`/`AW6_TENANT_B`,
    /// bases en clair migrées puis garnies (`aw6_garnir_le_tenant`, alertes 6611/6621).
    fn aw6_mode_multi_tenant(tmp: &crate::tmp_possede::TmpPossede) -> TenantDbManager {
        let pc = tmp.sous("control.db").chemin().to_string_lossy().to_string();
        let cc = open_db_keyed(&pc, None).unwrap();
        migrate_control(&cc);
        let cp = ControlPlane { conn: Arc::new(Mutex::new(cc)), db_path: Arc::new(pc) };
        for t in [AW6_TENANT_A, AW6_TENANT_B] {
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
        for (t, id) in [(AW6_TENANT_A, 6611), (AW6_TENANT_B, 6621)] {
            let h = mgr.handle_for(t).expect("fixture : base du tenant");
            let c = h.lock();
            c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            let _ = migrate(&c);
            aw6_garnir_le_tenant(&c, id);
        }
        mgr
    }

    /// Une base dont la table des canaux manque : le dispatch déclare un tick aveugle réel (`dispatch_notifiers`).
    fn aw6_base_aveugle(id: i64) -> Arc<Mutex<Connection>> {
        let conn = aw6_base(&[id]);
        conn.execute_batch("DROP TABLE notifier;").unwrap();
        Arc::new(Mutex::new(conn))
    }

    /// Base sur disque pour `run_due_rules` (l'évaluation relit le fichier), sans règle ni alerte.
    fn aw6_base_regles(tag: &str) -> (crate::tmp_possede::TmpPossede, Arc<Mutex<Connection>>, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("aw6-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute_batch("DELETE FROM rule; DELETE FROM alert;").unwrap();
        }
        (tmp, db, p)
    }

    /// Une règle simple qui TIRE (`SELECT 5` > 1), rend son identifiant.
    fn aw6_regle_qui_tire(db: &Arc<Mutex<Connection>>) -> i64 {
        let c = db.lock();
        c.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) VALUES('aw6-tire',1,'SELECT 5',0,'>',1,3,600,3600)",
            [],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    // ---------------------------------------------------------------- les phrases attendues (littéraux)

    fn aw6_mention(tenant: Option<&str>) -> String {
        tenant.map(|t| format!(" (tenant '{t}')")).unwrap_or_default()
    }
    fn aw6_ligne_marqueur(tenant: Option<&str>, id: i64, cause: &str) -> String {
        format!(
            "[plume] dispatch{} : alerte {id} : marqueur `notified` NON ÉCRIT, rien n'est envoyé pour elle ce tour-ci ; elle reste \
             à notifier et sera retentée au tour suivant, les alertes suivantes de ce tour sont traitées : {cause}",
            aw6_mention(tenant)
        )
    }
    fn aw6_ligne_refus(tenant: Option<&str>, id: i64) -> String {
        format!(
            "[plume] dispatch{} : alerte {id} : envoi NON PRIS par le canal {AW6_CANAL} (genre lookup), aucun renvoi : {AW6_CAUSE_LOOKUP}",
            aw6_mention(tenant)
        )
    }
    fn aw6_ligne_aucun(tenant: Option<&str>, id: i64) -> String {
        format!(
            "[plume] dispatch{} : alerte {id} : AUCUN des 1 canal(aux) visé(s) n'a pris l'envoi, alerte remise nulle part ; aucun \
             renvoi n'est tenté (politique non décidée)",
            aw6_mention(tenant)
        )
    }
    fn aw6_debut_rapport(tenant: Option<&str>) -> String {
        format!("[rapports] WARN rapport planifié #{AW6_RAPPORT}{} dû non exécuté : ", aw6_mention(tenant))
    }
    fn aw6_ligne_aveugle(tenant: Option<&str>, balayage: &str, cause: &str) -> String {
        format!("[plume] balayage de fond AVEUGLE ({balayage}){} : aucun geste de ce balayage ce tour-ci : {cause}", aw6_mention(tenant))
    }
    fn aw6_ligne_cle_tenue(id: i64) -> String {
        format!(
            "[detection] WARN règle #{id} : l'alerte de son tir n'est pas écrite (clé déjà tenue, ou écriture ignorée par la base) et \
             aucune alerte ouverte sous sa clé n'a pris le rafraîchissement — ce tir peut n'être vu nulle part, la règle est comptée abandonnée"
        )
    }
    fn aw6_ligne_ecrite_non_rafraichie(id: i64) -> String {
        format!(
            "[detection] WARN règle #{id} : l'alerte de son tir est écrite mais son rafraîchissement n'a touché aucune ligne — instant \
             d'ouverture et re-notification ne sont pas posés, la règle est comptée abandonnée"
        )
    }

    // ---------------------------------------------------------------- l'enfant

    fn aw6_enfant() {
        // ① Marqueur refusé sur la PREMIÈRE alerte de trois, deux tours.
        let conn = aw6_base(&[6601, 6602, 6603]);
        aw6_canal_lookup(&conn, "aw6_pris", 0, true);
        aw6_marqueur_refuse(&conn, 6601, &format!("RAISE(ABORT,'{AW6_CAUSE_MARQUEUR}')"));
        let db = Arc::new(Mutex::new(conn));
        for tour in 1..=2 {
            let avant = aw6_marqueurs();
            eprintln!("{AW6_PHASE}refus_{tour}");
            dispatch_notifications(&db);
            println!("{AW6_OBS}refus_{tour}:{}:{}:{}", aw6_ecart(avant, aw6_marqueurs()), aw6_envois(&db), aw6_marques(&db));
        }
        // ② Marqueur SANS EFFET sur la première de deux.
        let conn = aw6_base(&[6604, 6605]);
        aw6_canal_lookup(&conn, "aw6_pris", 0, true);
        aw6_marqueur_refuse(&conn, 6604, "RAISE(IGNORE)");
        let db = Arc::new(Mutex::new(conn));
        let avant = aw6_marqueurs();
        eprintln!("{AW6_PHASE}sans_effet");
        dispatch_notifications(&db);
        println!("{AW6_OBS}sans_effet:{}:{}:{}", aw6_ecart(avant, aw6_marqueurs()), aw6_envois(&db), aw6_marques(&db));

        // ③ Deux tenants réels en mode multi-tenant, parcourus par `for_each_active_tenant` ; puis hors du parcours,
        //   après une panique dans un corps, un nom posé avant le parcours, et le mode 0.
        let tmp_mt = crate::tmp_possede::TmpPossede::neuf("aw6-mode-multi-tenant");
        let mgr = aw6_mode_multi_tenant(&tmp_mt);
        let aveugles: HashMap<&str, Arc<Mutex<Connection>>> =
            [(AW6_TENANT_A, aw6_base_aveugle(6613)), (AW6_TENANT_B, aw6_base_aveugle(6623))].into_iter().collect();
        let mut visites = Vec::new();
        for_each_active_tenant(&mgr, |tid, handle, db_path| {
            visites.push(tid.to_string());
            eprintln!("{AW6_PHASE}{tid}");
            dispatch_notifications(handle);
            dispatch_notifications(&aveugles[tid]);
            let _ = run_due_reports(handle, db_path);
        });
        visites.sort();
        println!("{AW6_OBS}visites:{}", visites.join(","));
        eprintln!("{AW6_PHASE}hors_tour");
        crate::metrics::compter_un_tick_aveugle("aw6_hors_tour", "cause aw6");
        eprintln!("{AW6_PHASE}panique");
        let paniquee = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for_each_active_tenant(&mgr, |_tid, _h, _p| panic!("panique aw6"));
        }));
        println!("{AW6_OBS}panique:{}", paniquee.is_err());
        crate::metrics::compter_un_tick_aveugle("aw6_apres_panique", "cause aw6");
        eprintln!("{AW6_PHASE}emboite");
        {
            let _externe = crate::metrics::nommer_le_tenant_du_tour("t-aw6-externe");
            for_each_active_tenant(&mgr, |_tid, _h, _p| {});
            crate::metrics::compter_un_tick_aveugle("aw6_emboite", "cause aw6");
        }
        eprintln!("{AW6_PHASE}mode0");
        let base0 = Arc::new(Mutex::new(test_db()));
        aw6_garnir_le_tenant(&base0.lock(), 6631);
        let mgr0 = TenantDbManager {
            default_db_path: Arc::new(String::new()),
            default_writer: base0.clone(),
            control: None,
            writers: Arc::new(Mutex::new(HashMap::new())),
        };
        let aveugle0 = aw6_base_aveugle(6633);
        for_each_active_tenant(&mgr0, |tid, handle, db_path| {
            println!("{AW6_OBS}mode0_tenant:{tid}");
            dispatch_notifications(handle);
            dispatch_notifications(&aveugle0);
            let _ = run_due_reports(handle, db_path);
        });

        // ④ Alerte hors de tout canal, par raison.
        let phases: Vec<(&str, Box<dyn Fn(&Connection)>)> = vec![
            ("hors_aucun_actif", Box::new(|_c: &Connection| {})),
            ("hors_canal_desactive", Box::new(|c: &Connection| aw6_canal_lookup(c, "aw6_pris", 0, false))),
            (
                "hors_aucun_route",
                Box::new(|c: &Connection| {
                    aw6_canal_lookup(c, "aw6_pris", 0, true);
                    c.execute("INSERT INTO notification_policy(matchers,contact_points,continue_,enabled) VALUES('{\"source\":\"r.autre\"}','61',0,1)", []).unwrap();
                }),
            ),
            ("hors_sous_le_seuil", Box::new(|c: &Connection| aw6_canal_lookup(c, "aw6_pris", 4, true))),
            ("hors_visee", Box::new(|c: &Connection| aw6_canal_lookup(c, "aw6_pris", 0, true))),
            (
                "hors_silencee",
                Box::new(|c: &Connection| {
                    c.execute(
                        "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES('{\"source\":\"r.aw6\"}',4102444800,'aw6',1,'adm')",
                        [],
                    )
                    .unwrap();
                }),
            ),
            ("hors_marqueur_refuse", Box::new(|c: &Connection| aw6_marqueur_refuse(c, 6641, &format!("RAISE(ABORT,'{AW6_CAUSE_MARQUEUR}')")))),
        ];
        println!("{AW6_OBS}phases_hors:{}", phases.len());
        for (nom, preparer) in &phases {
            let conn = aw6_base(&[6641]);
            preparer(&conn);
            let db = Arc::new(Mutex::new(conn));
            let avant = aw6_hors();
            eprintln!("{AW6_PHASE}{nom}");
            dispatch_notifications(&db);
            println!("{AW6_OBS}{nom}:{}:{}", aw6_ecart(avant, aw6_hors()), aw6_marques(&db));
        }

        // ⑤ Rafraîchissement de l'alerte d'une règle qui tire.
        let (_t1, db, p) = aw6_base_regles("cle-tenue");
        let id = aw6_regle_qui_tire(&db);
        db.lock()
            .execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre,sources) VALUES(?1,?2,3,'aw6','aw6',?3,'closed','','')",
                params![now() - 100, format!("rule.{id}"), format!("rule-{id}")],
            )
            .unwrap();
        eprintln!("{AW6_PHASE}cle_tenue");
        let m = run_due_rules(&db, &p);
        let ouvertes: i64 = db.lock().query_row("SELECT COUNT(*) FROM alert WHERE status IN ('new','ack')", [], |r| r.get(0)).unwrap();
        println!("{AW6_OBS}cle_tenue:{id}:{m:?}:{ouvertes}");

        let (_t2, db, p) = aw6_base_regles("non-rafraichie");
        let id = aw6_regle_qui_tire(&db);
        db.lock().execute_batch("CREATE TRIGGER aw6_raf BEFORE UPDATE OF current_value ON alert BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        eprintln!("{AW6_PHASE}non_rafraichie");
        let m = run_due_rules(&db, &p);
        let ouvertes: i64 =
            db.lock().query_row("SELECT COUNT(*) FROM alert WHERE status='new' AND opened_at IS NULL", [], |r| r.get(0)).unwrap();
        println!("{AW6_OBS}non_rafraichie:{id}:{m:?}:{ouvertes}");

        let (_t3, db, p) = aw6_base_regles("episode-ouvert");
        let id = aw6_regle_qui_tire(&db);
        db.lock()
            .execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,dedup,status,mitre,sources) VALUES(?1,?2,3,'aw6','aw6',?3,'ack','','')",
                params![now() - 100, format!("rule.{id}"), format!("rule-{id}")],
            )
            .unwrap();
        eprintln!("{AW6_PHASE}episode_ouvert");
        let m = run_due_rules(&db, &p);
        let rafraichies: i64 =
            db.lock().query_row("SELECT COUNT(*) FROM alert WHERE status='ack' AND current_value=5", [], |r| r.get(0)).unwrap();
        println!("{AW6_OBS}episode_ouvert:{id}:{m:?}:{rafraichies}");

        let (_t4, db, p) = aw6_base_regles("tir-neuf");
        let id = aw6_regle_qui_tire(&db);
        eprintln!("{AW6_PHASE}tir_neuf");
        let m = run_due_rules(&db, &p);
        let ouvertes: i64 =
            db.lock().query_row("SELECT COUNT(*) FROM alert WHERE status='new' AND opened_at IS NOT NULL", [], |r| r.get(0)).unwrap();
        println!("{AW6_OBS}tir_neuf:{id}:{m:?}:{ouvertes}");
        eprintln!("{AW6_PHASE}fin");

        // ⑥ La surface : `/api/metrics` (scheduler) et `/metrics`.
        let conn = test_db();
        let j = crate::gather_json(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
        println!("{AW6_OBS}json:{}", j["scheduler"]);
        let prom = crate::gather_prom(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
        for l in prom.lines().filter(|l| l.starts_with("plume_scheduler_alertes_hors")) {
            println!("{AW6_OBS}prom:{l}");
        }
    }

    // ---------------------------------------------------------------- le témoin

    #[test]
    fn aw6_marqueur_avant_envoi_hors_de_tout_canal_rafraichissement_et_tenant_du_tour() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(AW6_ENFANT).is_ok() {
            aw6_enfant();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::dispatch_marqueur_avant_envoi_et_tenant_du_tour::aw6_marqueur_avant_envoi_hors_de_tout_canal_rafraichissement_et_tenant_du_tour",
            ])
            .env(AW6_ENFANT, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let obs = |nom: &str| -> String {
            let cle = format!("{AW6_OBS}{nom}:");
            stdout
                .lines()
                .find_map(|l| l.split_once(&cle).map(|(_, r)| r.to_string()))
                .unwrap_or_else(|| panic!("contrôle : observation {nom} : {stdout}"))
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AW6_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AW6_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] ") || l.starts_with("[detection] ")).map(str::to_string).collect()
        };
        // La même, avec les lignes du tick des rapports.
        let phase_large = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AW6_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AW6_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] ") || l.starts_with("[rapports] ")).map(str::to_string).collect()
        };

        // ① Le marqueur précède les envois : la première alerte ne part pas, les deux suivantes partent, une fois.
        assert_eq!(obs("refus_1"), "1,1:2:011", "tour 1 : [total, dispatch_marqueur] +1, deux envois (6602, 6603), marqueurs 0,1,1");
        assert_eq!(phase("refus_1"), vec![aw6_ligne_marqueur(None, 6601, AW6_CAUSE_MARQUEUR)], "tour 1 : une ligne, pour la première");
        assert_eq!(obs("refus_2"), "1,1:2:011", "tour 2 : la première retentée sans envoi, les deux autres ne repartent pas");
        assert_eq!(phase("refus_2"), vec![aw6_ligne_marqueur(None, 6601, AW6_CAUSE_MARQUEUR)], "tour 2 : la même ligne, seule");
        assert_eq!(obs("sans_effet"), "1,1:1:01", "sans effet : compté, rien ne part pour elle, la suivante part et est marquée");
        assert_eq!(phase("sans_effet"), vec![aw6_ligne_marqueur(None, 6604, AW6_CAUSE_SANS_EFFET)], "sans effet : sa cause");

        // ③ Chaque ligne du parcours multi-tenant nomme SON tenant ; hors du parcours et après une panique, aucun nom ;
        //   le nom d'avant revient ; le mode 0 ne nomme rien.
        assert_eq!(obs("visites"), format!("{AW6_TENANT_A},{AW6_TENANT_B}"), "contrôle : les deux tenants sont parcourus");
        let avec_rapport = |lignes: Vec<String>, tenant: Option<&str>| -> (Vec<String>, usize) {
            let debut = aw6_debut_rapport(tenant);
            let n = lignes.iter().filter(|l| l.starts_with(&debut)).count();
            (lignes.into_iter().filter(|l| !l.starts_with("[rapports] ")).collect(), n)
        };
        for (tenant, id) in [(AW6_TENANT_A, 6611), (AW6_TENANT_B, 6621)] {
            let (lignes, rapports) = avec_rapport(phase_large(tenant), Some(tenant));
            assert_eq!(
                lignes,
                vec![
                    aw6_ligne_marqueur(Some(tenant), id, AW6_CAUSE_MARQUEUR),
                    aw6_ligne_refus(Some(tenant), id + 1),
                    aw6_ligne_aucun(Some(tenant), id + 1),
                    aw6_ligne_aveugle(Some(tenant), "dispatch_notifiers", "no such table: notifier"),
                ],
                "tour de {tenant} : marqueur, refus, remise nulle part et tick aveugle nomment le tenant"
            );
            assert_eq!(rapports, 1, "tour de {tenant} : la ligne du tick des rapports nomme le tenant : {:?}", phase_large(tenant));
        }
        assert_eq!(phase("hors_tour"), vec![aw6_ligne_aveugle(None, "aw6_hors_tour", "cause aw6")], "hors du parcours : plus de nom");
        assert_eq!(obs("panique"), "true", "contrôle : le corps a paniqué");
        assert_eq!(phase("panique"), vec![aw6_ligne_aveugle(None, "aw6_apres_panique", "cause aw6")], "après une panique dans un corps : le nom est rendu");
        assert_eq!(
            phase("emboite"),
            vec![aw6_ligne_aveugle(Some("t-aw6-externe"), "aw6_emboite", "cause aw6")],
            "un nom posé avant le parcours revient après lui"
        );
        assert_eq!(obs("mode0_tenant"), "default", "contrôle : le mode 0 passe `default`");
        let (lignes, rapports) = avec_rapport(phase_large("mode0"), None);
        assert_eq!(
            lignes,
            vec![
                aw6_ligne_marqueur(None, 6631, AW6_CAUSE_MARQUEUR),
                aw6_ligne_refus(None, 6632),
                aw6_ligne_aucun(None, 6632),
                aw6_ligne_aveugle(None, "dispatch_notifiers", "no such table: notifier"),
            ],
            "mode 0 : les lignes d'avant, à l'octet, sans « (tenant 'default') »"
        );
        assert_eq!(rapports, 1, "mode 0 : la ligne du tick des rapports, sans tenant : {:?}", phase_large("mode0"));

        // ④ Hors de tout canal : [total, aucun actif, aucun routé, sous le seuil] et les marqueurs.
        let attendus = [
            ("hors_aucun_actif", "1,1,0,0:1"),
            ("hors_canal_desactive", "1,1,0,0:1"),
            ("hors_aucun_route", "1,0,1,0:1"),
            ("hors_sous_le_seuil", "1,0,0,1:1"),
            ("hors_visee", "0,0,0,0:1"),
            ("hors_silencee", "0,0,0,0:1"),
            ("hors_marqueur_refuse", "0,0,0,0:0"),
        ];
        let jouees: usize = obs("phases_hors").parse().expect("compte des phases");
        assert!(jouees >= 7, "plancher : les sept phases hors de tout canal sont jouées ({jouees})");
        assert_eq!(jouees, attendus.len(), "chaque phase jouée a son attendu");
        for (nom, attendu) in attendus {
            assert_eq!(obs(nom), attendu, "phase {nom} : [total, aucun actif, aucun routé, sous le seuil]:marqueur");
        }
        for nom in ["hors_aucun_actif", "hors_canal_desactive", "hors_aucun_route", "hors_sous_le_seuil", "hors_visee", "hors_silencee"] {
            assert!(phase(nom).is_empty(), "phase {nom} : aucune ligne (le compte suffit) : {:?}", phase(nom));
        }

        // ⑤ Le rafraîchissement sans effet est jugé, bras par bras.
        let regle = |nom: &str| -> (i64, String, String) {
            let o = obs(nom);
            let mut it = o.splitn(3, ':');
            let id = it.next().unwrap().parse().unwrap();
            (id, it.next().unwrap().to_string(), it.next().unwrap().to_string())
        };
        let (id, m, ouvertes) = regle("cle_tenue");
        assert_eq!((m.as_str(), ouvertes.as_str()), (format!("{:?}", Mesure::<u32>::Lue(1)).as_str(), "0"), "clé tenue : la règle compte, aucune alerte ouverte");
        assert_eq!(phase("cle_tenue"), vec![aw6_ligne_cle_tenue(id)], "clé tenue : sa ligne, entière");
        let (id, m, ouvertes) = regle("non_rafraichie");
        assert_eq!((m.as_str(), ouvertes.as_str()), (format!("{:?}", Mesure::<u32>::Lue(1)).as_str(), "1"), "écrite non rafraîchie : comptée, l'alerte est là");
        assert_eq!(phase("non_rafraichie"), vec![aw6_ligne_ecrite_non_rafraichie(id)], "écrite non rafraîchie : sa ligne, entière");
        let (_, m, rafraichies) = regle("episode_ouvert");
        assert_eq!((m.as_str(), rafraichies.as_str()), (format!("{:?}", Mesure::<u32>::Lue(0)).as_str(), "1"), "épisode ouvert rafraîchi : rien d'abandonné");
        assert!(phase("episode_ouvert").is_empty(), "épisode ouvert : muet : {:?}", phase("episode_ouvert"));
        let (_, m, ouvertes) = regle("tir_neuf");
        assert_eq!((m.as_str(), ouvertes.as_str()), (format!("{:?}", Mesure::<u32>::Lue(0)).as_str(), "1"), "tir neuf : rien d'abandonné");
        assert!(phase("tir_neuf").is_empty(), "tir neuf : muet : {:?}", phase("tir_neuf"));

        // ⑥ La surface : sommes exactes des phases.
        let s: Value = serde_json::from_str(&obs("json")).expect("JSON du bilan");
        assert_eq!(s["alertes_hors_de_tout_canal_total"], json!(4), "quatre alertes hors de tout canal : {s}");
        assert_eq!(
            s["alertes_hors_de_tout_canal"],
            json!({ "aucun_canal_actif": 2, "aucun_canal_route": 1, "sous_le_seuil_de_tous": 1 }),
            "ventilation par raison : {s}"
        );
        // refus_1, refus_2, sans_effet, les deux tenants, le mode 0 et hors_marqueur_refuse (le corps qui panique ne
        // dispatche rien).
        assert_eq!(
            s["ticks_aveugles"]["dispatch_marqueur"],
            json!({ "n": 7, "derniere_cause": AW6_CAUSE_MARQUEUR }),
            "un compte par alerte dont le marqueur est refusé : {s}"
        );
        let prom: Vec<String> = stdout.lines().filter_map(|l| l.split_once(&format!("{AW6_OBS}prom:")).map(|(_, r)| r.to_string())).collect();
        assert_eq!(prom, vec!["plume_scheduler_alertes_hors_de_tout_canal_total 4".to_string()], "la série Prometheus : {stdout}");
    }
}
