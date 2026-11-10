// =====================================================================================
// `P11.25-a` — UN BAN AUTOMATIQUE PLUS COURT NE RACCOURCIT JAMAIS LE BAN EN COURS (miroir HTTP `net_ban`).
//
// AVANT : l'approbation d'une riposte (`action_approve`), le miroir du responder (`miroir_http_du_responder`) et le
// passage d'un playbook (`run_playbooks`) posaient le blocage HTTP par `netban_upsert`, dont le `ON CONFLICT`
// REMPLACE l'échéance. Une adresse bannie 30 jours (ou à vie) par un administrateur, reprise par un playbook à
// 10 min, ressortait bloquée 10 min, et la riposte se disait armée (option `PLUME_NETBAN_FROM_ACTIONS`).
// APRÈS : ces trois poses passent par `netban_upsert_sans_raccourcir` — la nouvelle échéance n'est prise que si elle
// allonge (permanent l'emporte, sinon la plus lointaine) ; sinon la ligne reste entière (échéance, raison, auteur).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la pose MANUELLE (`POST /api/netban`) REMPLACE toujours, plus courte comprise
// (geste d'administrateur, épinglé par le contrôle du témoin (1)) ; la voie CrowdSec du démon ajoute une décision
// à côté des autres (non mesuré ici) ; l'agent d'un hôte distant a sa propre garde
// (`check_responder_applies_the_ban_duration_served_by_the_central.py`).
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `sql_remplace` (la primitive reprend l'upsert
// qui remplace), `raison_remplacee` (la raison du ban qui tient est écrasée), `permanent_raccourci` (un permanent lu
// comme une échéance zéro), `approbation_remplace`, `responder_remplace`, `responder_sans_ligne_remplace`,
// `playbook_remplace` (un appelant reprend `netban_upsert`).
// =====================================================================================
mod ban_automatique_ne_raccourcit_pas_le_miroir_http {
    use super::*;
    use crate::handlers::playbooks::run_playbooks;
    use crate::mesure_environnement::Mesure;

    const BANR_TRENTE_JOURS: i64 = 30 * 86400;

    fn banr_ligne(c: &Connection, ip: &str, env: &str) -> (Option<i64>, String, String) {
        c.query_row(
            "SELECT expires_ts, reason, created_by FROM net_ban WHERE ip=?1 AND env_id=?2",
            params![ip, env],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|e| panic!("ligne net_ban de {ip}/{env} : {e}"))
    }

    fn banr_base(chemin: &str) {
        let conn = open_db(chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute_batch("DELETE FROM playbook; DELETE FROM action; DELETE FROM net_ban;").unwrap();
    }

    fn banr_qui() -> AuthUser {
        AuthUser {
            name: "banr-admin".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// (1) LA PRIMITIVE. CE QU'IL TIENT : long puis court -> l'échéance longue, sa raison et son auteur restent ;
    /// court puis long -> allongé (raison et auteur du ban neuf) ; permanent puis court -> reste permanent ; échéance
    /// échue puis court -> la neuve ; échéance ÉGALE -> rien ne change ; un autre `env_id` n'est pas touché ; chaque
    /// pose rend `Arme`, une seule ligne par (ip, env), et le cache rechargé bloque encore au-delà de la courte.
    /// CONTRÔLE : la pose manuelle (`netban_upsert`) remplace toujours (geste d'administrateur).
    /// MUTATIONS : `sql_remplace`, `raison_remplacee`, `permanent_raccourci`.
    #[test]
    fn banr_la_primitive_garde_le_ban_le_plus_long() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let c = test_db();
        let t = now();
        let (long, court) = (t + 7200, t + 60);

        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.191", Some(long), "long", "op", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.191", Some(court), "court", "auto", "prod"), PoseDeBan::Arme),
                "un ban conservé reste une pose réussie : l'adresse est bannie au moins jusqu'à l'échéance demandée");
        assert_eq!(banr_ligne(&c, "203.0.113.191", "prod"), (Some(long), "long".into(), "op".into()),
                   "long puis court : le ban long tient, ENTIER (échéance, raison, auteur)");
        assert!(net_ban_is_blocked("203.0.113.191", court + 1), "le cache rechargé bloque au-delà de l'échéance courte");

        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.192", Some(court), "court", "auto", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.192", Some(long), "long", "auto2", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.192", "prod"), (Some(long), "long".into(), "auto2".into()), "court puis long : allongé");

        assert!(matches!(netban_upsert(&c, "203.0.113.193", None, "manuel", "admin", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.193", Some(court), "court", "auto", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.193", "prod"), (None, "manuel".into(), "admin".into()), "permanent puis court : reste permanent");
        assert!(net_ban_is_blocked("203.0.113.193", t + 10 * BANR_TRENTE_JOURS), "le permanent bloque toujours");

        assert!(matches!(netban_upsert(&c, "203.0.113.194", Some(t - 10), "echu", "admin", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.194", Some(court), "court", "auto", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.194", "prod"), (Some(court), "court".into(), "auto".into()), "échu puis court : la neuve");

        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.195", Some(long), "premier", "op", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.195", Some(long), "second", "auto", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.195", "prod"), (Some(long), "premier".into(), "op".into()), "échéance égale : rien ne change");

        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.196", Some(long), "autre", "op", "autre"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert_sans_raccourcir(&c, "203.0.113.196", Some(court), "prod", "auto", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.196", "autre"), (Some(long), "autre".into(), "op".into()), "l'autre env n'est pas touché");
        assert_eq!(banr_ligne(&c, "203.0.113.196", "prod"), (Some(court), "prod".into(), "auto".into()), "sa propre ligne");

        let lignes: i64 = c.query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).unwrap();
        assert_eq!(lignes, 7, "une ligne par (ip, env), jamais une seconde");

        // CONTRÔLE : la pose manuelle remplace, plus courte comprise.
        assert!(matches!(netban_upsert(&c, "203.0.113.197", Some(long), "long", "admin", "prod"), PoseDeBan::Arme));
        assert!(matches!(netban_upsert(&c, "203.0.113.197", Some(court), "court", "admin", "prod"), PoseDeBan::Arme));
        assert_eq!(banr_ligne(&c, "203.0.113.197", "prod").0, Some(court), "contrôle : la pose manuelle remplace");
        netban_cache().write().clear();
    }

    /// (2) LE MIROIR DU RESPONDER. CE QU'IL TIENT : une riposte exécutée à 600 s sur une adresse bannie 30 jours, puis
    /// sur une adresse bannie à vie, laisse chaque ban tel quel ; une riposte SANS LIGNE (défaut 4 h) sur une adresse
    /// bannie 30 jours aussi ; CONTRÔLE : sur une adresse non bannie, le miroir arme bien `maintenant + 600`.
    /// MUTATIONS : `responder_remplace`, `responder_sans_ligne_remplace`, `sql_remplace`.
    #[test]
    fn banr_le_miroir_du_responder_ne_raccourcit_pas() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let chemin = crate::tmp_possede::TmpDb::neuf("banr-miroir");
        banr_base(&chemin);
        let st = ds_file_state(&chemin);
        let t = now();
        let long = t + BANR_TRENTE_JOURS;
        {
            let c = st.db.lock();
            assert!(matches!(netban_upsert(&c, "203.0.113.181", Some(long), "manuel", "admin", "prod"), PoseDeBan::Arme));
            assert!(matches!(netban_upsert(&c, "203.0.113.182", None, "manuel", "admin", "prod"), PoseDeBan::Arme));
            assert!(matches!(netban_upsert(&c, "203.0.113.184", Some(long), "manuel", "admin", "prod"), PoseDeBan::Arme));
        }
        let riposte = |cible: &str| -> i64 {
            let c = st.db.lock();
            c.execute("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,'ban_ip',?1,'done',0,'banr',600)", params![cible]).unwrap();
            c.last_insert_rowid()
        };
        for cible in ["203.0.113.181", "203.0.113.182", "203.0.113.183"] {
            let id = riposte(cible);
            let aveu = crate::handlers::actions::miroir_http_du_responder(&st.db.lock(), id, "ban_ip", cible, "done", false);
            assert_eq!(aveu, None, "{cible} : rien à avouer");
        }
        let sans_ligne = 999_999;
        let aveu = crate::handlers::actions::miroir_http_du_responder(&st.db.lock(), sans_ligne, "ban_ip", "203.0.113.184", "done", false);
        assert_eq!(aveu, None);
        let apres = now();
        let c = st.db.lock();
        assert_eq!(banr_ligne(&c, "203.0.113.181", "prod"), (Some(long), "manuel".into(), "admin".into()), "30 jours puis 600 s : 30 jours");
        assert_eq!(banr_ligne(&c, "203.0.113.182", "prod"), (None, "manuel".into(), "admin".into()), "à vie puis 600 s : à vie");
        assert_eq!(banr_ligne(&c, "203.0.113.184", "prod"), (Some(long), "manuel".into(), "admin".into()), "sans ligne (4 h) : 30 jours");
        let arme = banr_ligne(&c, "203.0.113.183", "prod").0.expect("contrôle : armé à échéance");
        assert!((t + 600..=apres + 600).contains(&arme), "contrôle : adresse non bannie armée à + 600 ({arme})");
        drop(c);
        netban_cache().write().clear();
    }

    /// (3) L'APPROBATION. CE QU'IL TIENT : approuver une riposte à 600 s sur une adresse bannie 30 jours, puis à vie,
    /// rend 204 et laisse le ban tel quel ; CONTRÔLE : sur une adresse non bannie, l'approbation arme `+ 600`.
    /// MUTATIONS : `approbation_remplace`, `sql_remplace`.
    #[tokio::test]
    async fn banr_l_approbation_ne_raccourcit_pas() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let chemin = crate::tmp_possede::TmpDb::neuf("banr-approbation");
        banr_base(&chemin);
        let st = ds_file_state(&chemin);
        let t = now();
        let long = t + BANR_TRENTE_JOURS;
        {
            let c = st.db.lock();
            assert!(matches!(netban_upsert(&c, "203.0.113.171", Some(long), "manuel", "admin", "prod"), PoseDeBan::Arme));
            assert!(matches!(netban_upsert(&c, "203.0.113.172", None, "manuel", "admin", "prod"), PoseDeBan::Arme));
        }
        for cible in ["203.0.113.171", "203.0.113.172", "203.0.113.173"] {
            let id = {
                let c = st.db.lock();
                c.execute("INSERT INTO action(ts,kind,target,status,dry_run,reason,ban_ttl_s) VALUES(1000,'ban_ip',?1,'pending',0,'banr',600)", params![cible]).unwrap();
                c.last_insert_rowid()
            };
            let (code, v) = pb_json(action_approve(State(st.clone()), Extension(banr_qui()), Path(id)).await).await;
            assert_eq!(code, 204, "{cible} : riposte approuvée ({v})");
        }
        let apres = now();
        let c = st.db.lock();
        assert_eq!(banr_ligne(&c, "203.0.113.171", "prod"), (Some(long), "manuel".into(), "admin".into()), "30 jours puis 600 s : 30 jours");
        assert_eq!(banr_ligne(&c, "203.0.113.172", "prod"), (None, "manuel".into(), "admin".into()), "à vie puis 600 s : à vie");
        let arme = banr_ligne(&c, "203.0.113.173", "prod").0.expect("contrôle : armé à échéance");
        assert!((t + 600..=apres + 600).contains(&arme), "contrôle : adresse non bannie armée à + 600 ({arme})");
        drop(c);
        netban_cache().write().clear();
    }

    /// (4) LE PASSAGE D'UN PLAYBOOK. CE QU'IL TIENT : un playbook à 600 s sur une adresse bannie 30 jours ne la ramène
    /// pas à 600 s (rien d'abandonné) ; CONTRÔLE : son voisin sur une adresse non bannie arme `+ 600`.
    /// MUTATIONS : `playbook_remplace`, `sql_remplace`.
    #[test]
    fn banr_le_passage_d_un_playbook_ne_raccourcit_pas() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let chemin = crate::tmp_possede::TmpDb::neuf("banr-playbook");
        banr_base(&chemin);
        let db = Arc::new(Mutex::new(open_db(&chemin).unwrap()));
        db.lock().execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap();
        let t = now();
        let long = t + BANR_TRENTE_JOURS;
        assert!(matches!(netban_upsert(&db.lock(), "203.0.113.161", Some(long), "manuel", "admin", "prod"), PoseDeBan::Arme));
        for (nom, cible) in [("banr-long", "203.0.113.161"), ("banr-neuf", "203.0.113.162")] {
            db.lock()
                .execute(
                    "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role,ban_ttl_s) \
                     VALUES(?1,1,?2,0,'ban_ip',0,3600,0,NULL,'admin',600)",
                    params![nom, format!("SELECT '{cible}'")],
                )
                .unwrap();
        }
        let p = chemin.to_string();
        assert_eq!(run_playbooks(&db, &p), Mesure::Lue(0), "rien d'abandonné");
        let apres = now();
        let c = db.lock();
        assert_eq!(banr_ligne(&c, "203.0.113.161", "prod"), (Some(long), "manuel".into(), "admin".into()), "30 jours puis 600 s : 30 jours");
        let arme = banr_ligne(&c, "203.0.113.162", "prod").0.expect("contrôle : armé à échéance");
        assert!((t + 600..=apres + 600).contains(&arme), "contrôle : adresse non bannie armée à + 600 ({arme})");
        drop(c);
        netban_cache().write().clear();
    }
}
