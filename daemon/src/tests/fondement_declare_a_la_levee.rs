// =====================================================================================
// `P11.14-h` — CHAQUE ALERTE DÉCLARE SUR QUOI ELLE EST FONDÉE, à la levée, là où le démon sait ce qu'il
// fait, dans un vocabulaire FERMÉ (fondement.rs). Une alerte antérieure ne déclare rien (vide) et la
// console garde son refus honnête. La destination d'un fondement d'instantané est servie par genre ET
// machine — jamais l'instantané d'une autre machine. Migration v121.
// =====================================================================================
mod fondement_declare_a_la_levee {
    use super::*;
    use crate::fondement::Fondement;
    use crate::handlers::detection::run_due_rules;
    use crate::handlers::overview::snapshot_par_genre_et_machine;

    #[test]
    fn le_vocabulaire_est_ferme_et_fait_l_aller_retour() {
        assert_eq!(Fondement::TOUS.len(), 4, "quatre fondements, pas un de plus : un cinquième se traite dans fondement.rs");
        for f in Fondement::TOUS {
            assert_eq!(Fondement::depuis_le_mot(f.mot()), Some(f));
            assert!(!f.mot().is_empty() && f.mot().chars().all(|c| c.is_ascii_lowercase()), "un mot servi tel quel : {}", f.mot());
        }
        assert_eq!(Fondement::depuis_le_mot(""), None, "vide = non déclaré, pas un fondement");
        assert_eq!(Fondement::depuis_le_mot("rule.42"), None, "un jeton de règle n'est pas un fondement");
    }

    fn fdl_fichiers_rs(racine: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(racine).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() { fdl_fichiers_rs(&p, acc); } else if p.extension().is_some_and(|x| x == "rs") { acc.push(p); }
        }
    }

    /// GARDE DÉRIVÉE DE LA SOURCE : chaque site qui lève une alerte écrit `basis`. Un quatorzième site
    /// qui l'oublierait rougit ici ; la population est contrôlée (au moins treize) pour que le témoin ne
    /// passe pas par vacuité.
    #[test]
    fn chaque_site_qui_leve_une_alerte_ecrit_son_fondement() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        fdl_fichiers_rs(&racine, &mut fichiers);
        let (mut sites, mut sans) = (0usize, Vec::new());
        for chemin in fichiers {
            if chemin.to_string_lossy().contains("/tests/") { continue; }
            let src = std::fs::read_to_string(&chemin).unwrap();
            let mut idx = 0;
            while let Some(p) = src[idx..].find("INTO alert(") {
                let debut = idx + p + "INTO alert(".len();
                let fin = src[debut..].find(')').map(|x| debut + x).unwrap_or(src.len());
                let colonnes = &src[debut..fin];
                sites += 1;
                if !colonnes.split(',').any(|c| c.trim() == "basis") {
                    sans.push(format!("{} : ({})", chemin.display(), colonnes));
                }
                idx = fin;
            }
        }
        assert!(sites >= 13, "instrument : {sites} sites lus, la population attendue est d'au moins treize");
        assert!(sans.is_empty(), "sites qui lèvent une alerte SANS déclarer son fondement :\n{}", sans.join("\n"));
    }

    #[test]
    fn une_alerte_de_regle_est_fondee_sur_une_regle_et_une_alerte_ancienne_ne_declare_rien() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p1114h-regle");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
            conn.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('p1114h',1,'search source=p1114h | stats count',1,'>',0,2,0,3600)",
                [],
            ).unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'p1114h','auth',1,'x')", params![now]).unwrap();
            // une alerte ANTÉRIEURE (écrite sans fondement, comme avant v121)
            conn.execute("INSERT INTO alert(ts,rule,severity,title,dedup) VALUES(1000,'rule.9',2,'ancienne','rule-9-ancienne')", []).unwrap();
        }
        run_due_rules(&db, &p);
        let conn = db.lock();
        let (fondement_regle, ref_regle): (String, String) = conn
            .query_row("SELECT basis, basis_ref FROM alert WHERE rule='rule.'||(SELECT id FROM rule WHERE name='p1114h')", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("la règle a levé son alerte");
        assert_eq!((fondement_regle.as_str(), ref_regle.as_str()), (Fondement::Regle.mot(), ""), "une alerte de règle est fondée sur une règle, sans référence");
        let ancienne: String = conn.query_row("SELECT basis FROM alert WHERE title='ancienne'", [], |r| r.get(0)).unwrap();
        assert_eq!(ancienne, "", "une alerte antérieure ne déclare rien : la console garde son refus");
    }

    #[test]
    fn la_migration_v121_pose_le_fondement_vide_sur_les_alertes_anciennes() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("p1114h-migration");
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn));
        conn.execute_batch(
            "ALTER TABLE alert DROP COLUMN basis; ALTER TABLE alert DROP COLUMN basis_ref; \
             UPDATE meta SET value='120' WHERE key='schema_version';",
        ).expect("une base v120 se fabrique en retirant les colonnes de v121");
        conn.execute("INSERT INTO alert(ts,rule,severity,title,dedup) VALUES(1000,'rule.1',2,'ancienne','rule-1')", []).unwrap();
        assert!(migrate(&conn), "la migration 120 -> 121 passe");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, crate::migrate::CODE_SCHEMA_MAX.to_string());
        let (b, r): (String, String) = conn.query_row("SELECT basis, basis_ref FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((b.as_str(), r.as_str()), ("", ""), "rien n'est inventé pour une alerte antérieure");
    }

    /// LA DESTINATION D'UN FONDEMENT D'INSTANTANÉ : servie par genre ET machine, jamais celle d'une autre.
    #[tokio::test]
    async fn l_instantane_d_un_genre_pour_une_machine_est_servi_et_jamais_celui_d_une_autre() {
        let (st, _tmp) = sp_state("p1114h-instantane");
        let alice = sp_au("alice", "editor");
        {
            let conn = st.db.lock();
            conn.execute("INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(100,'controls','srv-7','h1','{\"failed\":1,\"controls\":[{\"id\":\"ufw\",\"ok\":false}]}')", []).unwrap();
            conn.execute("INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(200,'controls','srv-7','h2','{\"failed\":0,\"controls\":[{\"id\":\"ufw\",\"ok\":true}]}')", []).unwrap();
            conn.execute("INSERT INTO snapshot(ts,kind,host,hash,data) VALUES(300,'controls','srv-8','h3','{\"failed\":2,\"controls\":[]}')", []).unwrap();
        }
        let (code, v) = pb_json(snapshot_par_genre_et_machine(State(st.clone()), Extension(alice.clone()), Path(("controls".to_string(), "srv-7".to_string()))).await).await;
        assert_eq!(code, 200);
        assert_eq!((v["host"].as_str(), v["ts"].as_i64(), v["hash"].as_str()), (Some("srv-7"), Some(200), Some("h2")), "le DERNIER instantané de CETTE machine : {v}");
        assert_eq!(v["data"]["controls"][0]["ok"], serde_json::Value::Bool(true));
        let (code, _) = pb_json(snapshot_par_genre_et_machine(State(st.clone()), Extension(alice.clone()), Path(("controls".to_string(), "srv-9".to_string()))).await).await;
        assert_eq!(code, 404, "une machine sans instantané : 404, jamais l'instantané d'une autre");
        let (code, _) = pb_json(snapshot_par_genre_et_machine(State(st.clone()), Extension(alice.clone()), Path(("firewall".to_string(), "srv-7".to_string()))).await).await;
        assert_eq!(code, 404, "un autre genre : 404");
    }
}
