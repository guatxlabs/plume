// =====================================================================================
// `P4.12-h` — UN ÉPISODE OUVERT GARDE SON INSTANT D'OUVERTURE ET RE-NOTIFIE QUAND IL CHANGE DE NATURE.
// Mesuré le 2026-09-09 dans `handlers/detection.rs` : le rafraîchissement écrasait `ts` et ne touchait
// jamais `notified`, si bien qu'une condition continuellement vraie ne produisait qu'une notification,
// la première, et paraissait toujours récente. Critère retenu : la valeur a au moins doublé
// (`FACTEUR_DE_RENOTIFICATION`) depuis la dernière notification — un état stable ne re-notifie pas.
// =====================================================================================
mod alerte_chronique_renotifiee {
    use super::*;
    use crate::handlers::detection::{run_due_rules, FACTEUR_DE_RENOTIFICATION};
    use crate::handlers::notifiers::dispatch_notifications;

    struct Episode { notified: i64, valeur: Option<f64>, valeur_notifiee: Option<f64>, ts: i64, ouverture: Option<i64>, alertes: i64 }

    fn acr_base(tag: &str) -> (crate::tmp_possede::TmpPossede, String, Arc<Mutex<Connection>>) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn));
            conn.execute("DELETE FROM rule", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
        }
        (tmp, p, db)
    }

    fn acr_maintenant() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    fn acr_evenements(db: &Arc<Mutex<Connection>>, n: usize) {
        let conn = db.lock();
        for _ in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'p412h','auth',1,'échec')",
                params![acr_maintenant()],
            )
            .unwrap();
        }
    }

    fn acr_episode(db: &Arc<Mutex<Connection>>) -> Episode {
        let conn = db.lock();
        let alertes: i64 = conn.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap();
        conn.query_row(
            "SELECT notified,current_value,notified_value,ts,opened_at FROM alert WHERE rule LIKE 'rule.%' ORDER BY id LIMIT 1",
            [],
            |r| Ok(Episode { notified: r.get(0)?, valeur: r.get(1)?, valeur_notifiee: r.get(2)?, ts: r.get(3)?, ouverture: r.get(4)?, alertes }),
        )
        .expect("un épisode est ouvert")
    }

    #[test]
    fn un_episode_ouvert_garde_son_ouverture_et_renotifie_quand_sa_valeur_double() {
        let (_tmp, p, db) = acr_base("p412h-episode");
        db.lock()
            .execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES('p412h',1,'search source=p412h | stats count',1,'>',2,2,0,3600)",
                [],
            )
            .unwrap();
        acr_evenements(&db, 3);
        run_due_rules(&db, &p);
        let e1 = acr_episode(&db);
        assert_eq!((e1.alertes, e1.notified, e1.valeur), (1, 0, Some(3.0)), "l'épisode s'ouvre, à notifier, avec sa valeur");
        assert_eq!(e1.ouverture, Some(e1.ts), "le premier rafraîchissement pose l'ouverture sur le ts d'origine");

        // Le notificateur (aucun canal ici) marque l'alerte notifiée ET retient la valeur notifiée.
        dispatch_notifications(&db);
        let e2 = acr_episode(&db);
        assert_eq!((e2.notified, e2.valeur_notifiee), (1, Some(3.0)));

        // Une alerte ouverte il y a un quart d'heure, jamais rafraîchie depuis cette version (opened_at NULL,
        // comme toute alerte antérieure à la migration) : le rafraîchissement suivant prend l'ANCIEN ts pour
        // ouverture, puis ne le bouge plus, pendant que ts suit chaque évaluation.
        let il_y_a = e2.ts - 900;
        db.lock().execute("UPDATE alert SET opened_at=NULL, ts=?1", params![il_y_a]).unwrap();
        run_due_rules(&db, &p);
        let e3 = acr_episode(&db);
        assert_eq!(e3.ouverture, Some(il_y_a), "l'ouverture est l'ancien ts, capturé une fois");
        assert!(e3.ts >= e2.ts, "ts suit l'évaluation");
        assert_eq!(e3.notified, 1, "état stable (même valeur) : aucune re-notification");

        // L'épisode change de nature : 3 -> 6, la valeur a doublé -> notification due, ouverture inchangée.
        acr_evenements(&db, 3);
        run_due_rules(&db, &p);
        let e4 = acr_episode(&db);
        assert_eq!((e4.notified, e4.valeur, e4.ouverture, e4.alertes), (0, Some(6.0), Some(il_y_a), 1), "re-notifié, même épisode");
        dispatch_notifications(&db);
        assert_eq!(acr_episode(&db).valeur_notifiee, Some(6.0), "la barre est reposée à la valeur notifiée");

        // 6 -> 8 : sous le facteur, pas de re-notification ; l'épisode reste unique et ouvert depuis le même instant.
        acr_evenements(&db, 2);
        run_due_rules(&db, &p);
        let e5 = acr_episode(&db);
        assert_eq!((e5.notified, e5.valeur, e5.ouverture, e5.alertes), (1, Some(8.0), Some(il_y_a), 1));
        assert!(FACTEUR_DE_RENOTIFICATION > 1.0, "un facteur ≤ 1 re-notifierait à chaque tour un état stable");
    }

    /// La migration v120 pose les trois colonnes et N'INVENTE PAS l'ouverture des alertes antérieures :
    /// leur `opened_at` reste NULL (l'ouverture réelle est perdue ; `ts` n'est qu'une borne).
    #[test]
    fn la_migration_v120_pose_les_colonnes_sans_inventer_l_ouverture_des_alertes_anciennes() {
        let (_tmp, _p, db) = acr_base("p412h-migration");
        let conn = db.lock();
        conn.execute_batch(
            "ALTER TABLE alert DROP COLUMN opened_at; ALTER TABLE alert DROP COLUMN current_value; \
             ALTER TABLE alert DROP COLUMN notified_value; UPDATE meta SET value='119' WHERE key='schema_version';",
        )
        .expect("une base v119 se fabrique en retirant les colonnes de v120");
        conn.execute("INSERT INTO alert(ts,rule,severity,title,dedup) VALUES(1000,'rule.1',2,'ancienne','rule-1')", []).unwrap();
        assert!(migrate(&conn), "la migration 119 -> 120 passe");
        let v: String = conn.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, crate::migrate::CODE_SCHEMA_MAX.to_string());
        let (ouverture, valeur, notifiee): (Option<i64>, Option<f64>, Option<f64>) = conn
            .query_row("SELECT opened_at,current_value,notified_value FROM alert", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!((ouverture, valeur, notifiee), (None, None, None), "rien n'est inventé pour une alerte antérieure");
    }
}
