// =====================================================================================
// `P10.32-a`, `P10.32-o` (hors `handlers/` : `rollups.rs` ; `handlers/dashboards.rs`) — LA FENÊTRE CHAUDE D'`event_rollup`,
// SES WATERMARKS ET SA COUVERTURE NE SONT PLUS ÉCRITS EN AVEUGLE ; UNE CHARGE UTILE PÉRIMÉE SERVIE DIT QUE SON
// RAFRAÎCHISSEMENT A ÉCHOUÉ.
//
// LES DÉFAUTS, LUS SUR 5100db29 :
//  * `rollup_events` : la purge et l'agrégation de la fenêtre chaude (`bucket >= recent`) étaient deux `let _` — une purge
//    refusée était suivie de l'INSERT OR REPLACE (orphelins top-N à côté des lignes neuves : double compte servi par les
//    panneaux qui lisent `event_rollup` au-dessus de `recent`), un INSERT refusé laissait la fenêtre vide, sans un mot ;
//    l'effacement puis l'écriture du watermark `event_rollup_wm` étaient deux `let _`, et la couverture était publiée
//    ensuite quoi qu'il arrive (watermark resté ancien, ou absent), sa propre écriture en `let _` ;
//  * `materialize_banned_ip` : `banned_ip_wm` lu par `.ok()…unwrap_or(0)` (absent et non lu confondus, muets) et réécrit
//    par deux `let _` ;
//  * `handlers/dashboards.rs` : un rafraîchissement en échec sur une charge utile VALIDE déjà en cache ne le disait qu'au
//    journal — la charge périmée était servie comme si rien ne s'était passé ; le pré-chauffage, de même ;
//  * trois `if let Ok(payload) = serde_json::to_string(&v)` sans `else` (`consigner_l_issue_du_rafraichissement`, le
//    chemin live de `panel_data`, `cache_refresh_all_panels`). HORS D'ATTEINTE en pratique (`serde_json::Value` se
//    sérialise toujours : clés `String`, nombres finis par construction), mais la branche muette existait : elle est
//    retirée (`Value::to_string`, infaillible, mêmes octets).
//
// RÉFUTÉ (reste de la vague T, « un budget dépassé n'est pas distingué d'une erreur SQL ») : depuis la vague AS
// (`EchecMisEnCache::de_la_requete`, classe relue par `en_classant`), une interruption au budget est servie par la phrase
// du produit « requête interrompue (budget N s dépassé) », une erreur SQL par la phrase fixe du rejet. Témoin (k) ci-dessous,
// sur la vraie chaîne (interruption armée au cœur de `panneau_avoue::executer`), mutant AV8_BUDGET_CONFONDU rouge.
//
// DÉSORMAIS : purge chaude refusée -> rien n'est ré-agrégé ce passage, compté et dit ; INSERT chaud refusé -> compté et dit ;
// watermark non effacé ou non écrit -> couverture NON publiée, compté et dit ; publication de la couverture refusée ->
// compté et dit ; `banned_ip_wm` en trois issues, non lu compté et dit (rattrapage depuis le plancher, le plus large et
// idempotent), son effacement et son écriture lus ; une charge utile valide périmée reçoit
// `stats.rafraichissement_en_echec = { cause : phrase de la classe, echoue_a }`, instant de calcul inchangé, par le
// rafraîchissement à la demande ET par le pré-chauffage ; le succès suivant la retire.
//
// VOIES D'ÉCHEC FABRIQUÉES : autorisateur SQLite (k-ième `DELETE`/`INSERT` sur `meta` ou `event_rollup`), valeur de
// `banned_ip_wm` non entière ou en BLOB, interruption et refus de l'autorisateur armés au cœur
// (`query_exec::panne_de_test_au_coeur`), `stats` non objet en cache, déclencheur qui refuse l'écriture de `panel_cache`.
// Journal lu sur le stderr d'un sous-processus, lignes ENTIÈRES.
//
// MUTANTS (variable d'environnement de mutation sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE :
//  * AV8_CHAUDE_PURGE_AVALEE (purge refusée puis INSERT, la forme d'avant) : (a) ;
//  * AV8_NON_COMPTE (aucun compte neuf) : (a), (b), (c), (d), (e), (f), (g), (h) ;
//  * AV8_JOURNAL_MUET (aucune ligne neuve de `[rollup]`) : (i) ;
//  * AV8_WM_EFFACEMENT_IGNORE : (c) ; AV8_WM_ECRITURE_IGNOREE : (d) (couverture publiée sans watermark écrit) ;
//  * AV8_BUDGET_CONFONDU (produit servi sous la phrase du rejet) : (k) ;
//  * AV8_AVEU_NON_JOINT (forme d'avant : journal seul) : (l), (n) ; AV8_CALCULE_A_NOW : (l) ; AV8_STATS_ECRASE : (m) ;
//  * AV8_PRECHAUFFE_MUET : (n), (o) ; AV8_NON_JOINT_TU : (o).
//  * AV8_PRECHAUFFE_NON_CLASSE (pré-chauffage sans `en_classant`, tout échec rangé `Moteur`) : (q) ;
//    AV8_PRECHAUFFE_ECHOUE_A_ZERO (instant de l'échec non porté au pré-chauffage) : (q) ;
//    AV8_JOURNAL_TEXTE_BRUT (journal du pré-chauffage au texte du moteur) : (o) ; AV8_NON_OBJET_ADMIS (filtre
//    `is_object` retiré) : (r).
//  * (p) : témoin de source ; son épreuve (corpus à l'ancienne forme) rougit dans le test même.
//  * AW1_WM_NON_REECRIT (réécriture du watermark sautée quand il vaut déjà `recent`) : (a), (b), (e) — le watermark y est
//    posé sous une autre forme textuelle avant le passage éprouvé (`av8_watermark_a_reecrire`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console n'affiche pas encore `stats.rafraichissement_en_echec` (web/ hors
// périmètre) ; la nouvelle tentative sur un périmé revient à chaque interrogation tant que l'échec dure (bornée par
// l'ensemble en vol et `refresh_sem`, délibéré) ; la purge optionnelle des bans expirés (`PLUME_BANNED_IP_RETENTION`,
// éteinte par défaut) reste en `let _`.
// =====================================================================================
mod av8_fenetre_chaude_watermarks_et_perime_avoue {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::rollup_coverage::{META_ROLLUP_COV_ID, META_ROLLUP_WM};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const AV8_COMPTE_CHAUDE_PURGE: &str = "geste de fond non validé rollup : fenêtre chaude d'event_rollup : purge refusée";
    const AV8_COMPTE_CHAUDE_INSERT: &str = "geste de fond non validé rollup : fenêtre chaude d'event_rollup : INSERT refusé";
    const AV8_COMPTE_WM_EFFACEMENT: &str = "geste de fond non validé rollup : watermark d'event_rollup : effacement refusé";
    const AV8_COMPTE_WM_ECRITURE: &str = "geste de fond non validé rollup : watermark d'event_rollup : écriture refusée";
    const AV8_COMPTE_COUVERTURE: &str = "geste de fond non validé rollup : couverture d'event_rollup : publication refusée";
    const AV8_COMPTE_BIP_LECTURE: &str = "geste de fond non validé rollup : watermark de banned_ip : lecture non faite";
    const AV8_COMPTE_BIP_EFFACEMENT: &str = "geste de fond non validé rollup : watermark de banned_ip : effacement refusé";
    const AV8_COMPTE_BIP_ECRITURE: &str = "geste de fond non validé rollup : watermark de banned_ip : écriture refusée";
    const AV8_TOUS_LES_COMPTES: [&str; 8] = [
        AV8_COMPTE_CHAUDE_PURGE,
        AV8_COMPTE_CHAUDE_INSERT,
        AV8_COMPTE_WM_EFFACEMENT,
        AV8_COMPTE_WM_ECRITURE,
        AV8_COMPTE_COUVERTURE,
        AV8_COMPTE_BIP_LECTURE,
        AV8_COMPTE_BIP_EFFACEMENT,
        AV8_COMPTE_BIP_ECRITURE,
    ];
    const AV8_IP_BANNIE: &str = "192.0.2.18";
    const AV8_WM_ILLISIBLE: &str = "av8-pas-un-entier";
    /// La phrase fixe du rejet par le moteur, écrite ici (et non empruntée à la production).
    const AV8_REJETEE: &str = "requête REFUSÉE par le moteur (ce n'est pas un résultat vide) : syntaxe, champ, motif ou accès rejeté — rien n'est rendu ; le détail est au journal de l'exploitant.";
    const AV8_SQL_MESSAGE: &str = "SELECT message FROM event";
    const AV8_TEXTE_DU_GESTE: &str = "av8 texte du moteur";

    fn av8_recent() -> i64 {
        ((now() / 3600) * 3600 - 3600).max(0)
    }

    fn av8_meta(conn: &rusqlite::Connection, cle: &str) -> Option<String> {
        conn.query_row("SELECT CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| r.get(0)).ok()
    }

    fn av8_event(conn: &rusqlite::Connection, ts: i64) -> i64 {
        conn.execute("INSERT INTO event(ts,host,source,severity,message) VALUES(?1,'av8','sshd',1,'m')", params![ts]).unwrap();
        conn.last_insert_rowid()
    }

    fn av8_max_id(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap()
    }

    /// La somme des comptes de la fenêtre chaude (`bucket >= recent`), lignes orphelines exclues.
    fn av8_chaude(conn: &rusqlite::Connection, recent: i64) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE bucket>=?1 AND host<>'av8-orphelin'", params![recent], |r| r.get(0)).unwrap()
    }

    fn av8_orphelin(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COALESCE(SUM(n),0) FROM event_rollup WHERE host='av8-orphelin'", [], |r| r.get(0)).unwrap()
    }

    /// Un premier passage nominal : un event à `recent - 7200 + 60`, un dans la fenêtre chaude ; watermark à `recent`,
    /// couverture à la borne. Contrôle de la fixture.
    fn av8_premier_passage(conn: &rusqlite::Connection, recent: i64) {
        av8_event(conn, recent - 7200 + 60);
        av8_event(conn, now() - 10);
        rollup_events(conn);
        assert_eq!(av8_meta(conn, META_ROLLUP_WM), Some(recent.to_string()), "fixture : watermark à recent");
        assert_eq!(av8_meta(conn, META_ROLLUP_COV_ID), Some(av8_max_id(conn).to_string()), "fixture : couverture à la borne");
        assert_eq!(av8_chaude(conn, recent), 1, "fixture : un event dans la fenêtre chaude");
    }

    /// Le watermark posé par le premier passage, RÉÉCRIT sous une forme textuelle différente qui se lit pareil
    /// (`0<recent>` : lu `recent`, la même tranche, aucune reconstruction) : l'assertion « watermark à recent » qui suit le
    /// passage éprouvé ne tient que s'il a RÉÉCRIT le watermark. Sans cela elle était déjà vraie avant le passage
    /// (vérification de la vague AV). Mutant AW1_WM_NON_REECRIT (réécriture sautée quand le watermark lu vaut `recent`).
    fn av8_watermark_a_reecrire(conn: &rusqlite::Connection, recent: i64) {
        conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![format!("0{recent}"), META_ROLLUP_WM]).unwrap();
        assert_eq!(av8_meta(conn, META_ROLLUP_WM), Some(format!("0{recent}")), "fixture : watermark à réécrire");
    }

    /// Autorisateur qui refuse le `rang`-ième `DELETE` (`supprimer`) ou `INSERT` sur `table`. Rend le nombre de refus.
    fn av8_refuser(conn: &rusqlite::Connection, supprimer: bool, table: &'static str, rang: usize) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = 0usize;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            let vise = match ctx.action {
                AuthAction::Delete { table_name } => supprimer && table_name == table,
                AuthAction::Insert { table_name } => !supprimer && table_name == table,
                _ => false,
            };
            if vise {
                vus += 1;
                if vus == rang {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }));
        refus
    }

    fn av8_lever(conn: &rusqlite::Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Les comptes neufs de cette base, sauf `sauf`, sont nuls.
    fn av8_aucun_autre_compte(conn: &rusqlite::Connection, sauf: &str, contexte: &str) {
        let mut juges = 0;
        for c in AV8_TOUS_LES_COMPTES {
            if c != sauf {
                assert_eq!(compte_des_temoins(conn, c), 0, "{contexte} : rien d'autre n'est compté ({c})");
            }
            juges += 1;
        }
        assert_eq!(juges, AV8_TOUS_LES_COMPTES.len(), "{contexte} : tous les comptes jugés");
    }

    /// (a) PURGE CHAUDE REFUSÉE : rien n'est ré-agrégé (la fenêtre garde le compte du passage précédent, 1, et non 2 ;
    /// l'orphelin, impossible à purger, reste seul à côté), compté une fois ; watermark et couverture publiés (la fenêtre
    /// chaude n'entre pas dans la couverture). Sous AV8_CHAUDE_PURGE_AVALEE : 2 (orphelin + lignes neuves), rien compté.
    /// Contrôle : sans refus, l'orphelin est purgé, la fenêtre compte 2.
    #[test]
    fn av8_une_purge_chaude_refusee_ne_re_agrege_pas_la_fenetre() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = av8_recent();
        for refuse in [false, true] {
            let (st, _p) = sp_state(&format!("av8-a-{refuse}"));
            let conn = st.db.lock();
            av8_premier_passage(&conn, recent);
            let b = (now() - 10) / 3600 * 3600;
            conn.execute(
                "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(?1,'sshd',1,'','','av8-orphelin',5,0,'')",
                params![b],
            )
            .unwrap();
            av8_event(&conn, now() - 5);
            av8_watermark_a_reecrire(&conn, recent);
            let refus = refuse.then(|| av8_refuser(&conn, true, "event_rollup", 1));
            rollup_events(&conn);
            av8_lever(&conn);
            assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "({refuse}) watermark RÉÉCRIT à recent");
            assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), Some(av8_max_id(&conn).to_string()), "({refuse}) couverture publiée");
            if let Some(refus) = refus {
                assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la purge chaude est refusée une fois");
                assert_eq!(av8_orphelin(&conn), 5, "purge refusée : l'orphelin reste");
                assert_eq!(av8_chaude(&conn, recent), 1, "purge refusée : la fenêtre n'est pas ré-agrégée par-dessus l'orphelin");
                assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_CHAUDE_PURGE), 1, "purge refusée : comptée une fois");
                av8_aucun_autre_compte(&conn, AV8_COMPTE_CHAUDE_PURGE, "purge refusée");
            } else {
                assert_eq!(av8_orphelin(&conn), 0, "contrôle : l'orphelin est purgé");
                assert_eq!(av8_chaude(&conn, recent), 2, "contrôle : la fenêtre est ré-agrégée");
                av8_aucun_autre_compte(&conn, "", "contrôle");
            }
        }
    }

    /// (b) INSERT CHAUD REFUSÉ : la fenêtre est vide (purgée), le refus est compté une fois ; watermark et couverture
    /// publiés. Sous AV8_NON_COMPTE : rien compté.
    #[test]
    fn av8_une_agregation_chaude_refusee_est_comptee() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-b");
        let conn = st.db.lock();
        av8_premier_passage(&conn, recent);
        av8_event(&conn, now() - 5);
        av8_watermark_a_reecrire(&conn, recent);
        let refus = av8_refuser(&conn, false, "event_rollup", 1);
        rollup_events(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'INSERT chaud est refusé une fois");
        assert_eq!(av8_chaude(&conn, recent), 0, "INSERT refusé : la fenêtre est vide");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_CHAUDE_INSERT), 1, "INSERT refusé : compté une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_CHAUDE_INSERT, "INSERT chaud refusé");
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "watermark RÉÉCRIT à recent");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), Some(av8_max_id(&conn).to_string()), "couverture publiée");
    }

    /// Fixture de (c) et (d) : premier passage, puis watermark ramené à `recent - 7200` (rattrapage demandé, valeur que
    /// le passage suivant DOIT changer).
    fn av8_rattrapage(conn: &rusqlite::Connection, recent: i64) {
        av8_premier_passage(conn, recent);
        conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![(recent - 7200).to_string(), META_ROLLUP_WM]).unwrap();
    }

    /// (c) EFFACEMENT DU WATERMARK REFUSÉ (deuxième `DELETE` sur `meta` : le premier est la rétractation) : l'ancien
    /// watermark reste, la couverture n'est PAS publiée, compté une fois. Sous AV8_WM_EFFACEMENT_IGNORE (la forme d'avant :
    /// publiée quoi qu'il arrive) : couverture publiée. Passage suivant sans refus : watermark et couverture rétablis.
    #[test]
    fn av8_un_watermark_non_efface_ne_publie_pas_la_couverture() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-c");
        let conn = st.db.lock();
        av8_rattrapage(&conn, recent);
        let refus = av8_refuser(&conn, true, "meta", 2);
        rollup_events(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'effacement du watermark est refusé une fois");
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some((recent - 7200).to_string()), "effacement refusé : l'ancien watermark reste");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), None, "effacement refusé : couverture NON publiée");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_WM_EFFACEMENT), 1, "effacement refusé : compté une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_WM_EFFACEMENT, "effacement refusé");
        rollup_events(&conn);
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "passage suivant : watermark à recent");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), Some(av8_max_id(&conn).to_string()), "passage suivant : couverture publiée");
    }

    /// (d) ÉCRITURE DU WATERMARK REFUSÉE (premier `INSERT` sur `meta`) : le watermark est ABSENT, la couverture n'est PAS
    /// publiée, compté une fois. Sous AV8_WM_ECRITURE_IGNOREE : couverture publiée sans watermark. Passage suivant sans
    /// refus : reconstruction, watermark et couverture rétablis.
    #[test]
    fn av8_un_watermark_non_ecrit_ne_publie_pas_la_couverture() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-d");
        let conn = st.db.lock();
        av8_rattrapage(&conn, recent);
        let refus = av8_refuser(&conn, false, "meta", 1);
        rollup_events(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'écriture du watermark est refusée une fois");
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), None, "écriture refusée : watermark absent");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), None, "écriture refusée : couverture NON publiée");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_WM_ECRITURE), 1, "écriture refusée : comptée une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_WM_ECRITURE, "écriture refusée");
        rollup_events(&conn);
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "passage suivant : watermark à recent");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), Some(av8_max_id(&conn).to_string()), "passage suivant : couverture publiée");
    }

    /// (e) PUBLICATION DE LA COUVERTURE REFUSÉE (deuxième `INSERT` sur `meta`) : clé absente, watermark à `recent`, compté
    /// une fois. Sous AV8_NON_COMPTE : rien compté (la forme d'avant : muette).
    #[test]
    fn av8_une_publication_de_couverture_refusee_est_comptee() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-e");
        let conn = st.db.lock();
        av8_premier_passage(&conn, recent);
        av8_event(&conn, now() - 5);
        av8_watermark_a_reecrire(&conn, recent);
        let refus = av8_refuser(&conn, false, "meta", 2);
        rollup_events(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la publication est refusée une fois");
        assert_eq!(av8_meta(&conn, META_ROLLUP_COV_ID), None, "publication refusée : clé absente");
        assert_eq!(av8_meta(&conn, META_ROLLUP_WM), Some(recent.to_string()), "watermark RÉÉCRIT à recent");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_COUVERTURE), 1, "publication refusée : comptée une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_COUVERTURE, "publication refusée");
    }

    fn av8_ban(conn: &rusqlite::Connection, ts: i64) {
        conn.execute(
            "INSERT INTO event(ts,host,source,category,severity,message,src_ip,fields) VALUES(?1,'av8','fail2ban','ban',2,'ban',?2,'{\"jail\":\"sshd\"}')",
            params![ts, AV8_IP_BANNIE],
        )
        .unwrap();
    }

    fn av8_bannie(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM banned_ip WHERE src_ip=?1 AND source='fail2ban'", params![AV8_IP_BANNIE], |r| r.get(0)).unwrap()
    }

    /// (f) `banned_ip_wm` EN TROIS ISSUES. Non lu (texte non entier, BLOB) : compté une fois, rattrapage depuis le plancher
    /// (le ban à `recent - 7200` entre), watermark réécrit à `recent`. Absent : rien compté, même rattrapage. Lu : rien
    /// compté. Sous AV8_NON_COMPTE : rien compté sur une valeur illisible (la forme d'avant).
    #[test]
    fn av8_un_watermark_de_banned_ip_non_lu_est_compte_et_rattrape() {
        let _env = VERROU_ENV_PROCESSUS.read(); // materialize_banned_ip lit cfg()
        let recent = av8_recent();
        let cas: [(&str, Option<rusqlite::types::Value>, u64); 4] = [
            ("absent", None, 0),
            ("lu", Some(rusqlite::types::Value::Text((recent - 7200).to_string())), 0),
            ("texte", Some(rusqlite::types::Value::Text(AV8_WM_ILLISIBLE.into())), 1),
            ("blob", Some(rusqlite::types::Value::Blob(vec![0])), 1),
        ];
        let mut joues = 0;
        for (nom, valeur, compte) in cas {
            let (st, _p) = sp_state(&format!("av8-f-{nom}"));
            let conn = st.db.lock();
            av8_ban(&conn, recent - 7200);
            if let Some(v) = valeur {
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![v]).unwrap();
            }
            materialize_banned_ip(&conn);
            assert_eq!(av8_bannie(&conn), 1, "({nom}) le ban de la tranche entre");
            assert_eq!(av8_meta(&conn, "banned_ip_wm"), Some(recent.to_string()), "({nom}) watermark réécrit à recent");
            assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_BIP_LECTURE), compte, "({nom}) lecture non faite comptée {compte} fois");
            joues += 1;
        }
        assert_eq!(joues, 4, "les quatre issues jouées");
    }

    /// (g) EFFACEMENT DE `banned_ip_wm` REFUSÉ : l'ancien watermark reste, compté une fois, le ban est entré.
    #[test]
    fn av8_un_watermark_de_banned_ip_non_efface_est_compte() {
        let _env = VERROU_ENV_PROCESSUS.read(); // materialize_banned_ip lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-g");
        let conn = st.db.lock();
        av8_ban(&conn, recent - 7200);
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![(recent - 7200).to_string()]).unwrap();
        let refus = av8_refuser(&conn, true, "meta", 1);
        materialize_banned_ip(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'effacement est refusé une fois");
        assert_eq!(av8_bannie(&conn), 1, "le ban est entré");
        assert_eq!(av8_meta(&conn, "banned_ip_wm"), Some((recent - 7200).to_string()), "effacement refusé : l'ancien watermark reste");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_BIP_EFFACEMENT), 1, "effacement refusé : compté une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_BIP_EFFACEMENT, "effacement de banned_ip_wm refusé");
    }

    /// (h) ÉCRITURE DE `banned_ip_wm` REFUSÉE : watermark absent, compté une fois ; passage suivant : réécrit.
    #[test]
    fn av8_un_watermark_de_banned_ip_non_ecrit_est_compte() {
        let _env = VERROU_ENV_PROCESSUS.read(); // materialize_banned_ip lit cfg()
        let recent = av8_recent();
        let (st, _p) = sp_state("av8-h");
        let conn = st.db.lock();
        av8_ban(&conn, recent - 7200);
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![(recent - 7200).to_string()]).unwrap();
        let refus = av8_refuser(&conn, false, "meta", 1);
        materialize_banned_ip(&conn);
        av8_lever(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'écriture est refusée une fois");
        assert_eq!(av8_meta(&conn, "banned_ip_wm"), None, "écriture refusée : watermark absent");
        assert_eq!(compte_des_temoins(&conn, AV8_COMPTE_BIP_ECRITURE), 1, "écriture refusée : comptée une fois");
        av8_aucun_autre_compte(&conn, AV8_COMPTE_BIP_ECRITURE, "écriture de banned_ip_wm refusée");
        materialize_banned_ip(&conn);
        assert_eq!(av8_meta(&conn, "banned_ip_wm"), Some(recent.to_string()), "passage suivant : watermark réécrit");
    }

    /// (i) LES HUIT LIGNES DE JOURNAL `[rollup]`, ENTIÈRES, une par phase, causes du moteur sondées dans l'enfant ; le
    /// passage nominal n'en écrit aucune. Sous AV8_JOURNAL_MUET : les huit manquent (toutes nommées dans l'échec).
    #[test]
    fn av8_lignes_de_journal_des_rollups() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        const ENFANT: &str = "AV8_ENFANT_JOURNAL_ROLLUPS";
        const PHASE: &str = "AV8-PHASE:";
        const MOTEUR: &str = "AV8-MOTEUR-";
        const TETES: [&str; 8] = [
            "[rollup] WARN purge de la fenêtre chaude d'event_rollup NON faite (",
            "[rollup] WARN agrégation de la fenêtre chaude d'event_rollup NON écrite (",
            "[rollup] WARN watermark d'event_rollup NON effacé (",
            "[rollup] WARN watermark d'event_rollup NON écrit (",
            "[rollup] WARN couverture d'event_rollup NON publiée (",
            "[rollup] WARN watermark banned_ip_wm NON lu (",
            "[rollup] WARN watermark banned_ip_wm NON effacé (",
            "[rollup] WARN watermark banned_ip_wm NON écrit (",
        ];
        if std::env::var(ENFANT).is_ok() {
            let recent = av8_recent();
            {
                let sonde = test_db();
                sonde.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Delete { .. } | AuthAction::Insert { .. } => Authorization::Deny,
                    _ => Authorization::Allow,
                }));
                let m = |r: rusqlite::Result<usize>| r.expect_err("sonde refusée").to_string();
                println!("{MOTEUR}DELETE:{}", m(sonde.execute("DELETE FROM meta WHERE key='av8'", [])));
                println!("{MOTEUR}INSERT:{}", m(sonde.execute("INSERT INTO meta(key,value) VALUES('av8','x')", [])));
                sonde.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            }
            let phases: [(&str, Option<(bool, &'static str, usize)>); 5] = [
                ("chaude-purge", Some((true, "event_rollup", 1))),
                ("chaude-insert", Some((false, "event_rollup", 1))),
                ("wm-efface", Some((true, "meta", 2))),
                ("wm-ecrit", Some((false, "meta", 1))),
                ("couverture", Some((false, "meta", 2))),
            ];
            for (nom, refus) in phases {
                let (st, _p) = sp_state(&format!("av8-i-{nom}"));
                let conn = st.db.lock();
                av8_premier_passage(&conn, recent);
                if nom.starts_with("wm-") {
                    conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![(recent - 7200).to_string(), META_ROLLUP_WM]).unwrap();
                } else {
                    av8_event(&conn, now() - 5);
                }
                eprintln!("{PHASE}{nom}");
                if let Some((supprimer, table, rang)) = refus {
                    let r = av8_refuser(&conn, supprimer, table, rang);
                    rollup_events(&conn);
                    av8_lever(&conn);
                    println!("AV8-REFUS-{nom}:{}", r.load(Ordering::Relaxed));
                }
            }
            for (nom, supprimer) in [("bip-efface", true), ("bip-ecrit", false)] {
                let (st, _p) = sp_state(&format!("av8-i-{nom}"));
                let conn = st.db.lock();
                av8_ban(&conn, recent - 7200);
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![(recent - 7200).to_string()]).unwrap();
                eprintln!("{PHASE}{nom}");
                let r = av8_refuser(&conn, supprimer, "meta", 1);
                materialize_banned_ip(&conn);
                av8_lever(&conn);
                println!("AV8-REFUS-{nom}:{}", r.load(Ordering::Relaxed));
            }
            {
                let (st, _p) = sp_state("av8-i-bip-lu");
                let conn = st.db.lock();
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![AV8_WM_ILLISIBLE]).unwrap();
                eprintln!("{PHASE}bip-lu");
                materialize_banned_ip(&conn);
            }
            {
                let (st, _p) = sp_state("av8-i-calme");
                let conn = st.db.lock();
                eprintln!("{PHASE}calme");
                av8_premier_passage(&conn, recent);
                av8_ban(&conn, recent - 7200);
                materialize_banned_ip(&conn);
                materialize_banned_ip(&conn);
                rollup_events(&conn);
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::av8_fenetre_chaude_watermarks_et_perime_avoue::av8_lignes_de_journal_des_rollups"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut premisses = 0;
        for nom in ["chaude-purge", "chaude-insert", "wm-efface", "wm-ecrit", "couverture", "bip-efface", "bip-ecrit"] {
            let m = format!("AV8-REFUS-{nom}:1");
            assert!(stdout.lines().any(|l| l.ends_with(&m)), "prémisse : {m} : {stdout}");
            premisses += 1;
        }
        assert_eq!(premisses, 7, "les sept prémisses jugées");
        let moteur = |nom: &str| -> String {
            let tete = format!("{MOTEUR}{nom}:");
            stdout.lines().find_map(|l| l.split_once(tete.as_str()).map(|(_, v)| v)).unwrap_or_else(|| panic!("sonde {nom} : {stdout}")).to_string()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| TETES.iter().any(|t| l.starts_with(t))).map(str::to_string).collect()
        };
        let (del, ins) = (moteur("DELETE"), moteur("INSERT"));
        let non_entier = rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(AV8_WM_ILLISIBLE.parse::<i64>().expect_err("instrument : la valeur n'est pas entière")),
        )
        .to_string();
        let attendus: [(&str, String); 8] = [
            ("chaude-purge", format!("{}{del}) — fenêtre chaude non ré-agrégée, lignes du passage précédent gardées, reprise au prochain passage", TETES[0])),
            ("chaude-insert", format!("{}{ins}) — fenêtre chaude vide jusqu'au prochain passage", TETES[1])),
            ("wm-efface", format!("{}{del}) — ancien watermark gardé, couverture non publiée (la route sert le brut), reprise au prochain passage", TETES[2])),
            ("wm-ecrit", format!("{}{ins}) — watermark absent, couverture non publiée (la route sert le brut), reconstruction depuis le plus vieil event au prochain passage", TETES[3])),
            ("couverture", format!("{}{ins}) — la route sert le brut, reconstruction au prochain passage", TETES[4])),
            ("bip-lu", format!("{}{non_entier}) — rattrapage depuis le début de la fenêtre de rattrapage, watermark réécrit si les upserts passent", TETES[5])),
            ("bip-efface", format!("{}{del}) — ancien watermark gardé, tranche rejouée au prochain passage", TETES[6])),
            ("bip-ecrit", format!("{}{ins}) — watermark absent, rattrapage depuis le début de la fenêtre de rattrapage au prochain passage", TETES[7])),
        ];
        let mut fautes = Vec::new();
        for (nom, ligne) in &attendus {
            let vu = phase(nom);
            if vu != vec![ligne.clone()] {
                fautes.push(format!("phase {nom} : attendu [{ligne}], vu {vu:?}"));
            }
        }
        assert_eq!(attendus.len(), 8, "plancher : huit lignes attendues");
        assert!(fautes.is_empty(), "une ligne ENTIÈRE par refus :\n{}\n{stderr}", fautes.join("\n"));
        assert!(phase("calme").is_empty(), "le passage nominal n'écrit aucune de ces lignes : {:?}", phase("calme"));
    }

    // ---------------------------------------------------------------------------------
    // Tableaux de bord.
    // ---------------------------------------------------------------------------------

    /// Une base de panneaux (celle des témoins de la vague T) avec un panneau de plus qui lit `event.message`.
    fn av8_panneau_message(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, dbp, _g, _panne, _s) = t3c_state(tag);
        let id = {
            let conn = st.db.lock();
            let did: i64 = conn.query_row("SELECT MIN(id) FROM dashboard", [], |r| r.get(0)).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'av8',?2,0,'table')", params![did, AV8_SQL_MESSAGE]).unwrap();
            conn.last_insert_rowid()
        };
        (st, dbp, id)
    }

    const AV8_SQL_REGEXP: &str = "SELECT message FROM event WHERE message REGEXP 'av8'";

    /// Une base de panneaux de la vague T avec un event et un panneau de plus dont l'énoncé appelle `regexp` (les pannes
    /// support et base occupée passent par cette UDF) ; le cache des autres panneaux est coupé : le pré-chauffage
    /// n'exécute que celui-ci, la panne armée sert donc à lui.
    fn av8_seul_panneau_regexp(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, dbp, _g, _panne, _s) = t3c_state(tag);
        let id = {
            let conn = st.db.lock();
            av8_event(&conn, now());
            let did: i64 = conn.query_row("SELECT MIN(id) FROM dashboard", [], |r| r.get(0)).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'av8',?2,0,'table')", params![did, AV8_SQL_REGEXP]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id<>?1", params![id]).unwrap();
            id
        };
        (st, dbp, id)
    }

    /// (k) RÉFUTATION — un budget dépassé EST distingué d'une erreur SQL. Sur la vraie chaîne (`en_classant` autour de
    /// `panneau_avoue::executer`, panne armée au cœur), le corps d'échec mis en cache porte la phrase du budget pour une
    /// interruption, la phrase fixe du rejet pour un refus de l'autorisateur, et les deux diffèrent. Sous
    /// AV8_BUDGET_CONFONDU : la phrase du rejet pour les deux.
    #[test]
    fn av8_un_budget_depasse_est_distingue_d_une_erreur_sql() {
        use crate::query_exec::panne_de_test_au_coeur::{demander, retirer, PanneAuCoeur};
        let _env = VERROU_ENV_PROCESSUS.read(); // query_budget_ms et panel_serve_cfg_de lisent l'environnement
        let budget = format!("requête interrompue (budget {} s dépassé)", crate::query_exec::query_budget_ms() / 1000);
        let mut vus = Vec::new();
        for (nom, panne, attendu) in [("budget", PanneAuCoeur::Interruption, budget.clone()), ("sql", PanneAuCoeur::RefusDeLAutorisateur, AV8_REJETEE.to_string())] {
            let (st, dbp, id) = av8_panneau_message(&format!("av8-k-{nom}"));
            let from = t3c_from();
            let (rk, fp, _) = t3c_cle(&st, id, from);
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            let pc = panneau_avoue::compile_panneau_avoue(AV8_SQL_MESSAGE, false, from, 0, None).expect("fixture : SQL brut compilé");
            demander(dbp.as_str(), panne);
            let issue = crate::query_exec::en_classant(|| panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from));
            retirer(dbp.as_str());
            assert!(issue.is_err(), "prémisse ({nom}) : la panne a servi");
            consigner_l_issue_du_rafraichissement(&st.db, "default", id, &rk, &fp, now(), from, ttl_global, Ok(issue));
            let (payload, _) = panneau_avoue::cache_lire(&st.db.lock(), id, &rk, &fp).expect("corps d'échec écrit");
            let v: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(v["error"], json!(attendu), "({nom}) la phrase de sa classe : {payload}");
            vus.push(v["error"].clone());
            ff_rm(&dbp);
        }
        assert_eq!(vus.len(), 2, "les deux classes jouées");
        assert_ne!(vus[0], vus[1], "un budget dépassé n'est pas servi comme une erreur SQL");
    }

    /// Une charge utile VALIDE périmée en cache pour le panneau en panne de la vague T (coût lourd : chemin SWR). Rend
    /// (clé de plage, empreinte, instant de calcul).
    fn av8_perime(st: &AppState, panne: i64, from: i64) -> (String, String, i64) {
        let (rk, fp, ttl) = t3c_cle(st, panne, from);
        let vieux = now() - ttl - 5;
        let conn = st.db.lock();
        record_panel_cost(&conn, panne, &fp, 10_000.0, now());
        panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, vieux, &json!({ "columns": ["a"], "rows": [[42]] }).to_string());
        (rk, fp, vieux)
    }

    fn av8_cles(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        c.sort();
        c
    }

    /// (l) PAR LA ROUTE : un rafraîchissement en échec sur une charge utile valide périmée y joint
    /// `stats.rafraichissement_en_echec` = { cause : phrase du rejet, echoue_a : instant de l'échec } (clés exactes),
    /// instant de calcul INCHANGÉ, lignes intactes, aucun `error` ; l'interrogation suivante le sert ; le succès suivant le
    /// retire. Sous AV8_AVEU_NON_JOINT (la forme d'avant : journal seul) : aucun aveu ; sous AV8_CALCULE_A_NOW : instant changé.
    #[tokio::test]
    async fn av8_un_perime_servi_dit_que_son_rafraichissement_a_echoue() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("av8-l");
        let au = t3c_admin();
        let from = t3c_from();
        let (rk, fp, vieux) = av8_perime(&st, panne, from);
        let avant = now();
        let (_, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
        assert_eq!(v["rows"], json!([[42]]), "1re interrogation : le périmé est servi ; corps {v}");
        t3c_attendre_la_tache(&st).await;
        let apres = now();
        {
            let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
            assert_eq!(calcule_a, vieux, "instant de calcul inchangé : {payload}");
            let v: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(v["rows"], json!([[42]]), "lignes intactes : {payload}");
            assert!(v.get("error").is_none(), "aucun corps d'échec : {payload}");
            let aveu = &v["stats"]["rafraichissement_en_echec"];
            assert_eq!(av8_cles(aveu), vec!["cause".to_string(), "echoue_a".to_string()], "clés exactes de l'aveu : {payload}");
            assert_eq!(aveu["cause"], json!(AV8_REJETEE), "la phrase de la classe : {payload}");
            let t = aveu["echoue_a"].as_i64().expect("instant entier");
            assert!(avant <= t && t <= apres, "l'instant de l'échec est celui de la tentative : {t} hors [{avant}, {apres}]");
        }
        let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
        assert_eq!(code, 200, "corps {v}");
        assert_eq!(v["rows"], json!([[42]]), "2e interrogation : lignes servies ; corps {v}");
        assert!(v.get("error").is_none(), "corps {v}");
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["cause"], json!(AV8_REJETEE), "2e interrogation : l'échec est servi ; corps {v}");
        t3c_attendre_la_tache(&st).await;
        st.db.lock().execute("UPDATE t3c_source SET v='{\"a\":1}'", []).unwrap();
        let _ = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
        t3c_attendre_la_tache(&st).await;
        {
            let (payload, _) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
            let v: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(v["rows"], json!([[1]]), "contrôle : le succès réécrit la ligne : {payload}");
            assert!(v["stats"].get("rafraichissement_en_echec").is_none(), "le succès retire l'aveu : {payload}");
        }
        ff_rm(&dbp);
    }

    /// (m) `stats` NON OBJET : la charge utile reste à l'octet (rien n'est écrasé), l'issue est « non jointe ». Sous
    /// AV8_STATS_ECRASE : `stats` remplacé.
    #[test]
    fn av8_un_stats_non_objet_n_est_pas_ecrase() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_serve_cfg_de lit load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("av8-m");
        let from = t3c_from();
        let (rk, fp, _) = t3c_cle(&st, panne, from);
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        let charge = json!({ "columns": ["a"], "rows": [[42]], "stats": 5 }).to_string();
        panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, now() - 5, &charge);
        let echec = crate::query_exec::EchecDeRequete::Moteur { nature: "av8 nature".into(), texte: AV8_TEXTE_DU_GESTE.into() };
        consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, now(), from, ttl_global, Ok(Err(echec)));
        let (payload, _) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
        assert_eq!(payload, charge, "`stats` non objet : la charge utile reste à l'octet");
        ff_rm(&dbp);
    }

    /// (n) PRÉ-CHAUFFAGE : sur une charge utile valide déjà en cache, l'échec y est joint (même aveu, instant de calcul
    /// inchangé). Sous AV8_PRECHAUFFE_MUET et AV8_AVEU_NON_JOINT : aucun aveu.
    #[test]
    fn av8_le_pre_chauffage_joint_l_echec_a_la_charge_valide() {
        let _env = VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels lit load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("av8-n");
        let from = t3c_from();
        let (rk, fp, vieux) = av8_perime(&st, panne, from);
        crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
        let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
        assert_eq!(calcule_a, vieux, "instant de calcul inchangé : {payload}");
        let v: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["rows"], json!([[42]]), "lignes intactes : {payload}");
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["cause"], json!(AV8_REJETEE), "le pré-chauffage joint l'échec : {payload}");
        ff_rm(&dbp);
    }

    /// (o) LES LIGNES DE JOURNAL des issues neuves, ENTIÈRES : rafraîchissement à la demande « non joint » (`stats` non
    /// objet ; écriture refusée par la base), pré-chauffage « joint » et « non joint », et pré-chauffage d'un échec du
    /// support journalisé par sa NATURE (jamais le texte du moteur, comme au rafraîchissement à la demande). Sous
    /// AV8_NON_JOINT_TU : la ligne d'une charge conservée sans rien dire ; sous AV8_PRECHAUFFE_MUET : « rien d'écrit » ;
    /// sous AV8_JOURNAL_TEXTE_BRUT : le texte du moteur dans la ligne du support.
    #[test]
    fn av8_lignes_de_journal_du_perime() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_serve_cfg_de et cache_refresh_all_panels lisent load_config()
        const ENFANT: &str = "AV8_ENFANT_JOURNAL_PERIME";
        const PHASE: &str = "AV8-PHASE:";
        const REFUS_DU_CACHE: &str = "av8 refus du cache";
        if std::env::var(ENFANT).is_ok() {
            let from = t3c_from();
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            for nom in ["stats", "ecriture"] {
                let (st, dbp, _g, panne, _s) = t3c_state(&format!("av8-o-{nom}"));
                let (rk, fp, _) = t3c_cle(&st, panne, from);
                let charge = if nom == "stats" { json!({ "columns": ["a"], "rows": [[42]], "stats": 5 }) } else { json!({ "columns": ["a"], "rows": [[42]] }) };
                panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, now() - 5, &charge.to_string());
                if nom == "ecriture" {
                    st.db
                        .lock()
                        .execute_batch(&format!("CREATE TRIGGER av8_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT,'{REFUS_DU_CACHE}'); END;"))
                        .unwrap();
                }
                eprintln!("AV8-ID-{nom}:{panne}");
                eprintln!("{PHASE}{nom}");
                let echec = crate::query_exec::EchecDeRequete::Moteur { nature: "av8 nature".into(), texte: AV8_TEXTE_DU_GESTE.into() };
                consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, now(), from, ttl_global, Ok(Err(echec)));
                ff_rm(&dbp);
            }
            for nom in ["prechauffe-jointe", "prechauffe-refus"] {
                let (st, dbp, _g, panne, _s) = t3c_state(&format!("av8-o-{nom}"));
                let pc = panneau_avoue::compile_panneau_avoue(T3C_SQL_EN_PANNE, false, from, 0, None).unwrap();
                eprintln!("AV8-CAUSE:{}", panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from).unwrap_err());
                av8_perime(&st, panne, from);
                if nom == "prechauffe-refus" {
                    st.db
                        .lock()
                        .execute_batch(&format!("CREATE TRIGGER av8_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT,'{REFUS_DU_CACHE}'); END;"))
                        .unwrap();
                }
                eprintln!("AV8-ID-{nom}:{panne}");
                eprintln!("{PHASE}{nom}");
                crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
                ff_rm(&dbp);
            }
            {
                use crate::query_exec::panne_de_test_au_coeur::{demander, retirer, PanneAuCoeur};
                let nom = "prechauffe-support";
                let (st, dbp, id) = av8_seul_panneau_regexp(&format!("av8-o-{nom}"));
                let pc = panneau_avoue::compile_panneau_avoue(AV8_SQL_REGEXP, false, from, 0, None).unwrap();
                demander(dbp.as_str(), PanneAuCoeur::ErreurDuSupport);
                let e = crate::query_exec::en_classant(|| panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from)).unwrap_err();
                retirer(dbp.as_str());
                eprintln!("AV8-TEXTE-SUPPORT:{}", e.texte());
                eprintln!("AV8-NATURE-SUPPORT:{}", crate::handlers::dashboards::EchecMisEnCache::de_la_requete(e).au_journal());
                av8_perime(&st, id, from);
                eprintln!("AV8-ID-{nom}:{id}");
                eprintln!("{PHASE}{nom}");
                demander(dbp.as_str(), PanneAuCoeur::ErreurDuSupport);
                crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
                retirer(dbp.as_str());
                ff_rm(&dbp);
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::av8_fenetre_chaude_watermarks_et_perime_avoue::av8_lignes_de_journal_du_perime"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lire = |marque: &str| -> String {
            stderr.lines().find_map(|l| l.strip_prefix(marque)).unwrap_or_else(|| panic!("contrôle : {marque} : {stderr}")).to_string()
        };
        let cause = lire("AV8-CAUSE:");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            let id = lire(&format!("AV8-ID-{nom}:"));
            corps
                .lines()
                .filter(|l| l.starts_with(&format!("[panel] WARN rafraîchissement du panneau {id} ")) || l.starts_with(&format!("[cache] WARN pré-chauffage du panneau {id} ")))
                .map(str::to_string)
                .collect()
        };
        let panel = |nom: &str, suite: &str| -> String {
            let id = lire(&format!("AV8-ID-{nom}:"));
            format!(
                "[panel] WARN rafraîchissement du panneau {id} en échec ({AV8_TEXTE_DU_GESTE}) — /api/panels/{{id}}/data, tenant 'default' — charge utile précédente conservée (périmée), échec NON joint au corps servi ({suite}), nouvelle tentative à la prochaine interrogation"
            )
        };
        let cache = |nom: &str, suite: &str| -> String {
            let id = lire(&format!("AV8-ID-{nom}:"));
            format!("[cache] WARN pré-chauffage du panneau {id} en échec ({cause}) — {suite}")
        };
        let nature = lire("AV8-NATURE-SUPPORT:");
        let texte = lire("AV8-TEXTE-SUPPORT:");
        assert_ne!(nature, texte, "prémisse : pour le support, la nature n'est pas le texte du moteur");
        let support = format!(
            "[cache] WARN pré-chauffage du panneau {} en échec ({nature}) — charge utile précédente conservée, échec joint au corps servi",
            lire("AV8-ID-prechauffe-support:")
        );
        let attendus: [(&str, String); 5] = [
            ("stats", panel("stats", "`stats` de la charge utile n'est pas un objet")),
            ("ecriture", panel("ecriture", REFUS_DU_CACHE)),
            ("prechauffe-jointe", cache("prechauffe-jointe", "charge utile précédente conservée, échec joint au corps servi")),
            ("prechauffe-refus", cache("prechauffe-refus", &format!("charge utile précédente conservée, échec NON joint au corps servi ({REFUS_DU_CACHE})"))),
            ("prechauffe-support", support),
        ];
        let mut fautes = Vec::new();
        for (nom, ligne) in &attendus {
            let vu = phase(nom);
            if vu != vec![ligne.clone()] {
                fautes.push(format!("phase {nom} : attendu [{ligne}], vu {vu:?}"));
            }
        }
        assert_eq!(attendus.len(), 5, "plancher : cinq lignes attendues");
        assert!(fautes.is_empty(), "une ligne ENTIÈRE par issue :\n{}\n{stderr}", fautes.join("\n"));
    }

    /// (q) PRÉ-CHAUFFAGE, CHAQUE CLASSE : sur une charge utile valide périmée, une interruption (budget), une base occupée
    /// et une erreur du support armées au cœur du pré-chauffage joignent CHACUNE la phrase de SA classe (jamais celle du
    /// rejet du moteur) et l'instant de la tentative ; instant de calcul et lignes inchangés. Sous AV8_PRECHAUFFE_NON_CLASSE :
    /// la phrase du rejet pour les trois ; sous AV8_PRECHAUFFE_ECHOUE_A_ZERO : `echoue_a` hors de la tentative.
    #[test]
    fn av8_le_pre_chauffage_joint_la_phrase_de_chaque_classe_et_l_instant() {
        use crate::handlers::query::{CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE};
        use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
        let _env = VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels et query_budget_ms lisent l'environnement
        let budget = format!("requête interrompue (budget {} s dépassé)", crate::query_exec::query_budget_ms() / 1000);
        let cas = [
            ("budget", PanneAuCoeur::Interruption, budget),
            ("occupee", PanneAuCoeur::BaseOccupee, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE.to_string()),
            ("support", PanneAuCoeur::ErreurDuSupport, CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE.to_string()),
        ];
        let mut vus = Vec::new();
        for (nom, panne, attendu) in cas {
            let (st, dbp, id) = av8_seul_panneau_regexp(&format!("av8-q-{nom}"));
            let from = t3c_from();
            let (rk, fp, vieux) = av8_perime(&st, id, from);
            demander(dbp.as_str(), panne);
            let avant = now();
            crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
            let apres = now();
            let servie = !encore_demandee(dbp.as_str());
            retirer(dbp.as_str());
            assert!(servie, "prémisse ({nom}) : la panne a servi au pré-chauffage");
            let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), id, &rk, &fp).expect("ligne de cache");
            assert_eq!(calcule_a, vieux, "({nom}) instant de calcul inchangé : {payload}");
            let v: Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(v["rows"], json!([[42]]), "({nom}) lignes intactes : {payload}");
            assert!(v.get("error").is_none(), "({nom}) aucun corps d'échec : {payload}");
            let aveu = &v["stats"]["rafraichissement_en_echec"];
            assert_eq!(av8_cles(aveu), vec!["cause".to_string(), "echoue_a".to_string()], "({nom}) clés exactes de l'aveu : {payload}");
            assert_eq!(aveu["cause"], json!(attendu), "({nom}) la phrase de sa classe : {payload}");
            let t = aveu["echoue_a"].as_i64().expect("instant entier");
            assert!(avant <= t && t <= apres, "({nom}) l'instant de l'échec est celui de la tentative : {t} hors [{avant}, {apres}]");
            vus.push(aveu["cause"].clone());
            ff_rm(&dbp);
        }
        assert_eq!(vus.len(), 3, "les trois classes jouées");
        assert!(!vus.contains(&json!(AV8_REJETEE)), "aucune classe servie sous la phrase du rejet : {vus:?}");
    }

    /// (r) UNE CHARGE UTILE EN CACHE QUI N'EST PAS UN OBJET n'est pas tenue pour valide : le corps d'échec la remplace
    /// (phrase de la classe sous `error`). Sous AV8_NON_OBJET_ADMIS : « non jointe », la charge reste et aucun échec
    /// n'est écrit.
    #[test]
    fn av8_une_charge_non_objet_n_est_pas_une_charge_valide() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_serve_cfg_de lit load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("av8-r");
        let from = t3c_from();
        let (rk, fp, _) = t3c_cle(&st, panne, from);
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, now() - 5, "[42]");
        let echec = crate::query_exec::EchecDeRequete::Moteur { nature: "av8 nature".into(), texte: AV8_TEXTE_DU_GESTE.into() };
        consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, now(), from, ttl_global, Ok(Err(echec)));
        let (payload, _) = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).expect("ligne de cache");
        let v: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["error"], json!(AV8_REJETEE), "une charge non objet est remplacée par le corps d'échec : {payload}");
        ff_rm(&dbp);
    }

    /// Les lignes de code (commentaires retirés) d'un source qui portent la sérialisation faillible jetée en silence.
    fn av8_serialisations_sautees(source: &str) -> Vec<String> {
        source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains("if let Ok(payload) = serde_json::to_string("))
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// (p) AUCUN `if let Ok(payload) = serde_json::to_string(…)` sans `else` ne reste dans `handlers/dashboards.rs` ni dans
    /// `rollups.rs` (la branche muette, hors d'atteinte en pratique, est retirée : `Value::to_string`). Épreuve : le corpus
    /// à l'ancienne forme est vu ; contrôle positif : les trois écritures passent par `to_string()`.
    #[test]
    fn av8_aucune_serialisation_sautee_en_silence() {
        let ancien = "            if let Ok(payload) = serde_json::to_string(&v) {\n                // `if let Ok(payload) = serde_json::to_string(&v)`\n";
        assert_eq!(av8_serialisations_sautees(ancien).len(), 1, "épreuve : l'ancienne forme est vue, le commentaire ne l'est pas");
        let tdb = include_str!("../handlers/dashboards.rs");
        let rollups = include_str!("../rollups.rs");
        assert!(tdb.len() > 10_000 && rollups.len() > 10_000, "contrôle : les deux sources sont lues");
        assert_eq!(av8_serialisations_sautees(tdb), Vec::<String>::new(), "handlers/dashboards.rs");
        assert_eq!(av8_serialisations_sautees(rollups), Vec::<String>::new(), "rollups.rs");
        let ecritures = tdb.matches("let payload = v.to_string();").count()
            + tdb.matches("cache_ecrire(&conn, id, &range_key, &q_fp, now_s, &v.to_string())").count()
            + rollups.matches("let payload = v.to_string();").count();
        assert_eq!(ecritures, 3, "contrôle : les trois écritures du cache sérialisent par `Value::to_string`");
    }
}
