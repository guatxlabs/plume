// =====================================================================================
// `P10.20-v` — LES DEUX PRIMITIVES AVOUENT LEUR ÉCRITURE : UN BAN NON ÉCRIT N'EST PAS « ARMÉ », UN
// MAILLON NON INSCRIT N'EST PAS UNE TRACE.
//
// LE DÉFAUT, MESURÉ LE 2026-09-19 AVANT TOUT CORRECTIF. Deux primitives écrivaient leur `INSERT`
// sous `let _ =` — la forme SANS branche d'échec — puis laissaient leurs appelants conclure :
//   * `auth::netban_upsert` rendait `true` quoi qu'il arrive, sous un `#[must_use]` qui promettait
//     qu'un ban refusé serait rapporté. Son jumeau `netban_remove`, lui, propage son erreur depuis
//     `P4.7-k` : la moitié POSE du même contrat était restée ouverte ;
//   * `ledger::ledger_append` traitait et avouait le refus AMONT (hachage précédent illisible) mais
//     avalait l'`INSERT` final — une ligne du registre tamper-evident pouvait manquer en silence.
//
// CE QUE L'ÉNONCÉ DE LA CLÉ SOUS-COMPTE, ET CE QUE CES TÉMOINS JOUENT À LA PLACE. La clé demande de
// compter les appelants de `ledger_append` qui « scrutent déjà sa valeur de retour » et ceux qui
// l'ignorent « (`let _ = ledger_append(`) ». La mesure donne ZÉRO des deux : la primitive rendait
// `()`, donc AUCUN appelant ne pouvait scruter quoi que ce soit, et la forme `let _ = ledger_append(`
// n'existe NULLE PART dans l'arbre. Il n'y avait pas deux populations à départager mais une seule —
// tous les appels, sans exception, étaient des appels nus à une fonction muette. Le défaut n'était
// donc pas dans les appelants : il était dans le TYPE.
//
// LES DEUX VOIES D'ÉCHEC D'ÉCRITURE, ET POURQUOI DEUX — la même paire que `P10.20-t`. La TABLE
// RETIRÉE (renommée sous les pieds de la primitive) fait échouer la PRÉPARATION de l'énoncé ; la VUE
// TEMPORAIRE — la table renommée, une vue de même nom posée par-dessus — laisse la LECTURE passer et
// fait échouer la seule ÉCRITURE. Sur `ledger`, cette paire sépare en outre les deux voies de
// non-inscription : sous la vue, `ledger_prev_hash` LIT la tête de chaîne et c'est l'`INSERT` qui
// tombe (la voie que cette clé ouvre) ; la table retirée, c'est la lecture amont qui tombe (la voie
// que `P10.7-m` avait fermée). Chaque témoin porte son CONTRÔLE POSITIF dans le même corps.
//
// LA QUESTION DE LA CLÉ, ET SA RÉPONSE EST DANS LE DERNIER TÉMOIN. « Une ligne de registre manquante
// casse-t-elle la chaîne de hachage à la vérification hors ligne, ou la trace se referme-t-elle sans
// trou visible ? » Elle se REFERME. Le maillon suivant s'accroche au dernier hachage PRÉSENT, donc
// la chaîne recalculée par `verify_ledger` est parfaitement continue et l'identifiant ne saute pas
// (`ledger.id` est un `INTEGER PRIMARY KEY` sans `AUTOINCREMENT` : une écriture ratée ne consomme
// aucun numéro). Le vérificateur hors ligne rend « intègre » sur un journal AMPUTÉ, et c'est
// précisément pourquoi la perte doit être dite À L'ÉCRITURE : après elle, plus rien ne la voit.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun module de `web/` ne lit les aveux neufs — la clé
// `registre_sans_maillon` d'un corps servi et le genre de registre `netban.non-arme` arrivent à
// l'écran sans phrase (`web/audit.js` rend tout genre inconnu tel quel) ; le rechargement du cache
// in-process est FAIL-STATIC, donc `PoseDeBan::Arme` dit « la ligne est écrite », jamais « ce
// processus bloque déjà » ; et les appelants de `ledger_append` hors de la famille `P10.20-q` /
// `P10.20-t` ignorent toujours l'issue rendue — leur perte n'est plus muette (la primitive l'avoue
// sur la sortie d'erreur) mais elle n'atteint aucun exploitant.
// =====================================================================================
mod primitives_avouent_leur_ecriture {
    use super::*;

    /// Une base plume COMPLÈTE, sur fichier : le renommage de table et la vue temporaire ont besoin
    /// d'une vraie connexion d'écriture, celle que le gestionnaire prend par `req_conn!`.
    fn pae_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pae-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-v` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM net_ban", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn pae_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn pae_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pae_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn pae_lignes_de_registre(st: &AppState) -> i64 {
        pae_compte(st, "SELECT COUNT(*) FROM ledger")
    }

    /// Le nombre de lignes de registre portant un genre donné — c'est ce qui rend un aveu FILTRABLE.
    fn pae_lignes_de_genre(st: &AppState, genre: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le compte par genre se lit")
    }

    /// La phrase servie par un refus (`err_json` la pose sous `error`).
    fn pae_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// L'aveu de trace manquante posé À CÔTÉ d'un succès, s'il y en a un.
    fn pae_aveu_de_trace(v: &Value) -> Option<String> {
        v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).map(str::to_string)
    }

    async fn pae_poser_un_ban(st: &AppState, ip: &str) -> (u16, Value) {
        let corps = json!({ "ip": ip, "ttl_s": 600, "reason": "temoin P10.20-v" });
        pb_json(netban_add(State(st.clone()), Extension(pae_au()), Json(corps)).await).await
    }

    // -------------------------------------------------------------------------------------
    // (1) LA VUE TEMPORAIRE SUR `net_ban` — la lecture passe, l'ÉCRITURE ne passe pas.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : quand la ligne du ban ne peut pas être écrite alors que le store se LIT,
    /// `POST /api/netban` REFUSE par un 503 nommé au lieu de rendre `ok: true` ; le registre — qui,
    /// lui, est parfaitement écrivable pendant le refus — ne porte AUCUNE ligne `netban.add` et porte
    /// à la place l'aveu filtrable `netban.non-arme` ; et la table des bans ne gagne aucune ligne. Le
    /// contrôle positif, dans le même corps, montre que le refus n'est pas inconditionnel.
    ///
    /// CE QU'IL NE TIENT PAS : il n'éprouve pas une base réellement en lecture seule (la cause de
    /// terrain), seulement un objet non modifiable — le chemin de code refusé est le même ; et il ne
    /// juge pas ce que la console peint de ce 503.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO net_ban…")`
    /// suivi de `true` dans `netban_upsert`. La route redevient 200 `ok: true`, le registre gagne une
    /// ligne `netban.add` pour un blocage qui n'existe nulle part, et l'aveu disparaît.
    #[tokio::test]
    async fn pae_un_ban_que_la_base_refuse_d_ecrire_n_est_ni_arme_ni_servi_comme_fait() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (st, _tmp) = pae_etat("vue-temporaire-net-ban");

        // LA VUE TEMPORAIRE : lisible, non modifiable. Elle vit sur LA connexion du gestionnaire.
        pae_ecrire(
            &st,
            "ALTER TABLE net_ban RENAME TO net_ban_source;\
             CREATE TEMP VIEW net_ban AS SELECT * FROM net_ban_source;",
        );
        let registre_avant = pae_lignes_de_registre(&st);
        let (statut, avoue) = pae_poser_un_ban(&st, "203.0.113.50").await;
        assert_eq!(statut, 503, "écriture impossible : la route REFUSE au lieu de servir « fait » : {avoue}");
        assert!(pae_phrase(&avoue).starts_with(CAUSE_BAN_NON_ARME), "le refus NOMME sa cause : {avoue}");
        assert_eq!(avoue.get("ok"), None, "AUCUN `ok: true` n'est servi sur un blocage qui n'existe pas : {avoue}");
        assert_eq!(
            pae_lignes_de_genre(&st, "netban.add"), 0,
            "le registre — écrivable pendant le refus — n'ATTESTE aucun ban : c'est la trace non \
             purgeable que l'ancienne forme remplissait pour un blocage inexistant"
        );
        assert_eq!(
            pae_lignes_de_genre(&st, "netban.non-arme"), 1,
            "et il porte l'aveu, sous son PROPRE genre : une trace qui ne se filtre pas ne se relit pas"
        );
        assert_eq!(pae_lignes_de_registre(&st), registre_avant + 1, "cet aveu, et lui seul");
        assert_eq!(pae_compte(&st, "SELECT COUNT(*) FROM net_ban_source"), 0, "aucun ban n'a été posé");
        assert!(!net_ban_is_blocked("203.0.113.50", now()), "et le gate HTTP ne bloque personne");

        // CONTRÔLE POSITIF — la vue retirée, le même ban se pose, et le registre l'atteste ALORS.
        pae_ecrire(&st, "DROP VIEW net_ban; ALTER TABLE net_ban_source RENAME TO net_ban;");
        let (statut, pose) = pae_poser_un_ban(&st, "203.0.113.50").await;
        assert_eq!(statut, 200, "le refus n'est pas inconditionnel : {pose}");
        assert_eq!(pose.get("ok").and_then(|v| v.as_bool()), Some(true), "{pose}");
        assert_eq!(pae_aveu_de_trace(&pose), None, "le chemin nominal n'avoue RIEN : {pose}");
        assert_eq!(pae_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.50'"), 1, "le ban est posé");
        assert_eq!(pae_lignes_de_genre(&st, "netban.add"), 1, "et le registre l'atteste");
    }

    // -------------------------------------------------------------------------------------
    // (2) LA TABLE RETIRÉE — la primitive elle-même, sans gestionnaire autour.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `net_ban` renommée sous les pieds de `netban_upsert`, la primitive rend
    /// `NonEcrit` avec sa cause — jamais `Arme`, jamais le refus de plafond, qui est une DÉCISION de
    /// la borne et non une panne. Le cache in-process ne gagne pas l'adresse, donc le gate ne la
    /// bloque pas. Contrôle positif compté AVANT le retrait, sur la même connexion.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien du chemin où l'écriture poserait un nombre de lignes
    /// inattendu (cet upsert pose une ligne ou échoue) ; et il ne juge aucun appelant.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute(..)` suivi de
    /// `netban_reload(conn); true`. La primitive redit « armé » sur une table qui n'existe plus.
    #[test]
    fn pae_une_table_de_bans_hors_d_atteinte_ne_rend_jamais_un_ban_arme() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.20-v` : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM net_ban", []).unwrap();

        // CONTRÔLE POSITIF — sur la même connexion, la pose ARME et la table gagne sa ligne.
        match netban_upsert(&conn, "203.0.113.51", None, "temoin", "op", "prod") {
            PoseDeBan::Arme => {}
            PoseDeBan::RefuseParLePlafond => panic!("le store n'est pas plein"),
            PoseDeBan::NonEcrit(cause) => panic!("la base est saine : {cause}"),
        }
        let poses: i64 = conn.query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).unwrap();
        assert_eq!(poses, 1, "la ligne est écrite");
        assert!(netban_cache().read().contains_key("203.0.113.51"), "et le cache la porte");

        // LA TABLE RETIRÉE — renommée, elle n'est plus sous le nom que l'énoncé attend.
        conn.execute_batch("ALTER TABLE net_ban RENAME TO net_ban_hors_d_atteinte;").unwrap();
        match netban_upsert(&conn, "203.0.113.52", None, "temoin", "op", "prod") {
            PoseDeBan::NonEcrit(cause) => assert!(!cause.is_empty(), "la cause de l'écriture ratée est PORTÉE"),
            PoseDeBan::Arme => panic!(
                "une table hors d'atteinte ne pose AUCUN ban — c'est l'armement affirmé que cette clé ferme"
            ),
            PoseDeBan::RefuseParLePlafond => panic!("le plafond est une décision de la borne, pas une panne"),
        }
        assert!(!netban_cache().read().contains_key("203.0.113.52"), "le cache n'a pas gagné l'adresse");
        assert!(!net_ban_is_blocked("203.0.113.52", now()), "et le gate HTTP ne la bloque pas");

        // LA TABLE REMISE : aucune ligne n'a été posée pour l'adresse refusée.
        conn.execute_batch("ALTER TABLE net_ban_hors_d_atteinte RENAME TO net_ban;").unwrap();
        let restantes: i64 = conn
            .query_row("SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.52'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(restantes, 0, "aucun ban n'existe pour l'adresse dont l'écriture a échoué");
        netban_cache().write().clear();
    }

    // -------------------------------------------------------------------------------------
    // (3) LE REGISTRE — les DEUX voies de non-inscription, rendues à l'appelant.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `ledger_append` rend `NonInscrit` avec sa cause sur les deux voies — la VUE
    /// TEMPORAIRE (la tête de chaîne se LIT, seule l'écriture tombe : la voie que cette clé ouvre) et
    /// la TABLE RETIRÉE (la lecture amont tombe : la voie de `P10.7-m`) — et le compte des maillons
    /// ne bouge dans aucun des deux cas. Contrôle positif compté deux fois dans le même corps.
    ///
    /// CE QU'IL NE TIENT PAS : il n'éprouve pas une base réellement en lecture seule ; et il ne dit
    /// rien de ce que les appelants font de l'issue — c'est l'objet des témoins qui suivent.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO ledger…")` dans
    /// `ledger_append`. La voie de la VUE TEMPORAIRE redevient `Inscrit` sur un maillon qui n'existe
    /// pas — la voie de la table retirée, elle, resterait `NonInscrit` : c'est la moitié déjà fermée.
    #[test]
    fn pae_un_maillon_de_registre_non_inscrit_est_rendu_a_l_appelant() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.20-v` : la chaîne de migrations doit aller au bout");
        let compte = |c: &Connection| -> i64 { c.query_row("SELECT COUNT(*) FROM ledger", [], |r| r.get(0)).unwrap() };

        // CONTRÔLE POSITIF — la base saine inscrit, et le compte monte d'exactement un.
        let avant = compte(&conn);
        assert!(
            ledger_append(&conn, "config.mode", "maillon du contrôle positif").cause_de_non_inscription().is_none(),
            "une base saine INSCRIT son maillon"
        );
        assert_eq!(compte(&conn), avant + 1, "et le registre en porte un de plus");

        // LA VUE TEMPORAIRE — la tête de chaîne se LIT, l'écriture ne passe pas. C'est la voie que
        // l'ancienne forme avalait : `ledger_prev_hash` réussissait, donc aucun aveu ne sortait.
        conn.execute_batch(
            "ALTER TABLE ledger RENAME TO ledger_source;\
             CREATE TEMP VIEW ledger AS SELECT * FROM ledger_source;",
        )
        .unwrap();
        assert!(
            ledger_prev_hash(&conn).is_ok(),
            "CONTRÔLE D'INSTRUMENT : sous la vue, la LECTURE de la tête de chaîne réussit — sans quoi \
             ce témoin éprouverait la voie amont et non l'écriture"
        );
        let cause = ledger_append(&conn, "config.mode", "maillon que la base refuse d'écrire")
            .cause_de_non_inscription()
            .map(str::to_string)
            .unwrap_or_else(|| panic!("l'écriture refusée doit être RENDUE, jamais avalée"));
        assert!(!cause.is_empty(), "la cause de l'écriture ratée est PORTÉE");
        let apres_vue: i64 = conn.query_row("SELECT COUNT(*) FROM ledger_source", [], |r| r.get(0)).unwrap();
        assert_eq!(apres_vue, avant + 1, "et AUCUN maillon n'est entré");

        // LA TABLE RETIRÉE — la lecture amont tombe : la voie déjà fermée par `P10.7-m`, qui porte
        // maintenant la MÊME issue nommée que l'autre. L'appelant n'a plus deux silences à distinguer.
        conn.execute_batch("DROP VIEW ledger; ALTER TABLE ledger_source RENAME TO ledger_hors_d_atteinte;").unwrap();
        let cause = ledger_append(&conn, "config.mode", "maillon sans tête de chaîne lisible")
            .cause_de_non_inscription()
            .map(str::to_string)
            .unwrap_or_else(|| panic!("la lecture amont ratée doit être RENDUE, elle aussi"));
        assert!(
            cause.contains("ILLISIBLE"),
            "la cause dit LAQUELLE des deux voies a tenu la plume : {cause}"
        );

        // CONTRÔLE POSITIF, SECONDE FOIS — la table remise, le maillon suivant entre normalement.
        conn.execute_batch("ALTER TABLE ledger_hors_d_atteinte RENAME TO ledger;").unwrap();
        assert!(
            ledger_append(&conn, "config.mode", "maillon d'après").cause_de_non_inscription().is_none(),
            "le refus n'est pas inconditionnel"
        );
        assert_eq!(compte(&conn), avant + 2, "deux maillons écrits, deux refusés : le compte le dit");
    }

    // -------------------------------------------------------------------------------------
    // (4) L'APPROBATION — un registre qui ne prend pas la ligne n'arme RIEN.
    // -------------------------------------------------------------------------------------

    /// Une riposte EN ATTENTE, telle qu'un analyste la trouve dans sa file.
    fn pae_riposte_en_attente(st: &AppState, kind: &str, target: &str) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1000,?1,?2,'pending',0,'')",
            params![kind, target],
        )
        .expect("fixture : la riposte s'insère");
        conn.last_insert_rowid()
    }

    /// CE QU'IL TIENT : quand le registre tamper-evident ne prend pas la ligne `action.approved`,
    /// `action_approve` REFUSE par un 503 nommé et n'ARME AUCUN ban — la trace de QUI a approuvé
    /// précède le fait qu'elle justifie. Contrôle positif dans le même corps : la vue retirée, la
    /// MÊME riposte s'approuve, le registre reçoit sa ligne et le miroir HTTP est armé.
    ///
    /// CE QU'IL NE TIENT PAS : le statut `approved`, lui, est déjà écrit quand le registre tombe —
    /// c'est dit par la phrase du refus, et le geste est rejouable ; et il ne juge pas ce que la
    /// console peint de ce 503.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO ledger…")` dans
    /// `ledger_append`. Le maillon repasse pour inscrit, la route redevient 204 et le ban est armé
    /// sur une approbation dont la trace non purgeable ne porte rien.
    #[tokio::test]
    async fn pae_une_approbation_dont_le_registre_n_a_pas_pris_la_ligne_n_arme_rien_et_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        // Le poseur de réglage PARTAGÉ de `common.rs` (il restaure au `Drop`, y compris sur panic).
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (st, _tmp) = pae_etat("registre-sous-vue");
        let cible = pae_riposte_en_attente(&st, "ban_ip", "203.0.113.53");

        // LA VUE TEMPORAIRE SUR `ledger` : la chaîne se lit, la ligne ne s'écrit pas.
        pae_ecrire(
            &st,
            "ALTER TABLE ledger RENAME TO ledger_source;\
             CREATE TEMP VIEW ledger AS SELECT * FROM ledger_source;",
        );
        let maillons_avant = pae_compte(&st, "SELECT COUNT(*) FROM ledger_source");
        let (statut, avoue) =
            pb_json(action_approve(State(st.clone()), Extension(pae_au()), Path(cible)).await).await;
        assert_eq!(statut, 503, "registre muet : la route REFUSE au lieu de rendre un 204 : {avoue}");
        assert!(
            pae_phrase(&avoue).starts_with(CAUSE_APPROBATION_SANS_TRACE),
            "le refus NOMME sa cause, et il la distingue de l'écriture du statut : {avoue}"
        );
        assert_eq!(
            pae_compte(&st, "SELECT COUNT(*) FROM ledger_source"), maillons_avant,
            "AUCUN maillon n'est entré"
        );
        assert_eq!(
            pae_compte(&st, "SELECT COUNT(*) FROM net_ban"), 0,
            "et AUCUN ban n'est armé — armer sur une approbation que le registre n'atteste pas, \
             c'est poser un fait sans sa trace"
        );

        // CONTRÔLE POSITIF — la vue retirée, la MÊME riposte s'approuve : le geste est rejouable.
        pae_ecrire(&st, "DROP VIEW ledger; ALTER TABLE ledger_source RENAME TO ledger;");
        let (statut, rejoue) =
            pb_json(action_approve(State(st.clone()), Extension(pae_au()), Path(cible)).await).await;
        assert_eq!(statut, 204, "le refus n'est pas inconditionnel : {rejoue}");
        assert_eq!(pae_lignes_de_registre(&st), maillons_avant + 1, "le registre reçoit alors sa ligne");
        assert_eq!(
            pae_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.53'"), 1,
            "et le miroir HTTP est armé — la seconde approbation ne réécrit rien, elle réinscrit et arme"
        );
        netban_cache().write().clear();
    }

    // -------------------------------------------------------------------------------------
    // (5) LE PLAYBOOK — un miroir HTTP non écrit entre dans le bilan du tick.
    // -------------------------------------------------------------------------------------

    /// Arme une base neuve avec UN playbook `ban_ip` dû, admin-authored, en mode ACTIF : la seule
    /// configuration où `run_playbooks` arme le miroir HTTP.
    fn pae_base_de_playbook(tag: &str, cible: &str) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pae-{tag}"));
        let p = chemin.to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-v` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM net_ban", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('pae-pb',1,?1,0,'ban_ip',0,3600,0,NULL,'admin')",
                params![format!("SELECT '{cible}'")],
            )
            .unwrap();
        }
        (db, p, chemin)
    }

    fn pae_compte_sur(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    /// CE QU'IL TIENT : en mode actif, la riposte de playbook est posée ET le miroir HTTP est armé
    /// (contrôle positif, bilan à ZÉRO abandon). Puis, la table des bans rendue NON MODIFIABLE par une
    /// vue temporaire — la LECTURE du store passe toujours —, le tick n'arme AUCUN ban pour la cible
    /// suivante et il le DIT : son bilan compte un abandon au lieu de publier « 0 », et le registre
    /// porte l'aveu sous son propre genre.
    ///
    /// CE QU'IL NE TIENT PAS : le bilan porte un NOMBRE, pas la cause (`Mesure::Lue`) ; et la riposte,
    /// elle, EST écrite — ce qui manque est son miroir HTTP, ce que le genre du registre dit.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO net_ban…")`
    /// suivi de `true` dans `netban_upsert`. Le tick redevient `Lue(0)` et rien ne dit que le blocage
    /// HTTP annoncé n'existe pas.
    #[test]
    fn pae_un_playbook_dont_le_miroir_http_n_est_pas_ecrit_le_compte_au_bilan_du_tick() {
        use crate::mesure_environnement::Mesure;
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (db, p, _tmp) = pae_base_de_playbook("playbook-net-ban", "203.0.113.60");

        // CONTRÔLE POSITIF — la riposte est posée et le miroir HTTP est ARMÉ.
        assert_eq!(crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(0), "base saine : rien d'abandonné");
        assert_eq!(pae_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.60'"), 1, "le ban est ARMÉ");

        // LA MÊME CHOSE SUR UNE AUTRE CIBLE, table des bans NON MODIFIABLE.
        {
            let conn = db.lock();
            conn.execute("UPDATE playbook SET query=?1, last_run=NULL WHERE name='pae-pb'", params!["SELECT '203.0.113.61'"])
                .unwrap();
            conn.execute_batch(
                "ALTER TABLE net_ban RENAME TO net_ban_source;\
                 CREATE TEMP VIEW net_ban AS SELECT * FROM net_ban_source;",
            )
            .unwrap();
        }
        assert_eq!(
            crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(1),
            "un miroir HTTP que la base n'a PAS écrit est un abandon COMPTÉ — publier « 0 abandon » \
             laisserait un tick vert sur un blocage annoncé qui n'existe pas"
        );
        assert_eq!(
            pae_compte_sur(&db, "SELECT COUNT(*) FROM ledger WHERE kind='netban.non-arme'"), 1,
            "et le registre porte l'aveu sous son PROPRE genre, distinct du refus de plafond"
        );
        assert_eq!(
            pae_compte_sur(&db, "SELECT COUNT(*) FROM ledger WHERE kind='netban.plafond'"), 0,
            "une écriture ratée n'est PAS un store plein : la confusion que ce lot ferme"
        );

        // LA TABLE REMISE : aucun ban n'a été posé pour la seconde cible.
        db.lock().execute_batch("DROP VIEW net_ban; ALTER TABLE net_ban_source RENAME TO net_ban;").unwrap();
        assert_eq!(pae_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.61'"), 0);
        assert_eq!(pae_compte_sur(&db, "SELECT COUNT(*) FROM net_ban"), 1, "le ban du contrôle positif, et lui seul");
        assert_eq!(
            pae_compte_sur(&db, "SELECT COUNT(*) FROM action WHERE target='203.0.113.61'"), 1,
            "la riposte, elle, EST en file : ce qui manque est son miroir HTTP, et c'est ce que l'aveu dit"
        );
        netban_cache().write().clear();
    }

    // -------------------------------------------------------------------------------------
    // (6) LA QUESTION DE LA CLÉ — ce que la vérification HORS LIGNE dit d'une ligne manquante.
    // -------------------------------------------------------------------------------------

    /// Une base FICHIER au schéma réel, journal ET points de contrôle réellement VIDES (la chaîne de
    /// migrations écrit des maillons : pour juger un compte, il faut partir de rien).
    fn pae_coffre(etiquette: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P10.20-v` : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle vidés");
        (coffre, conn)
    }

    /// LA RÉPONSE À LA QUESTION DE `P10.20-v`, PRISE PAR LE VRAI VÉRIFICATEUR HORS LIGNE
    /// (`verify_ledger`, celui que `plume-daemon verify` appelle sur un CHEMIN, en lecture seule).
    ///
    /// CE QU'IL TIENT : un journal dont un maillon N'A PAS pu être écrit se vérifie comme un journal
    /// INTACT. Quatre appels, trois lignes en base : le vérificateur rend « aucune rupture », le même
    /// verdict qu'il rendrait si rien n'avait été perdu, et l'identifiant du dernier maillon ne saute
    /// PAS — `ledger.id` est un `INTEGER PRIMARY KEY` sans `AUTOINCREMENT`, donc l'écriture ratée ne
    /// consomme aucun numéro et ne laisse pas même ce trou-là. LA TRACE SE REFERME SANS TROU VISIBLE.
    /// C'est ce qui rend l'aveu À L'ÉCRITURE non substituable : après lui, plus rien ne voit la perte.
    ///
    /// LE CONTRÔLE POSITIF EST DANS LE CORPS, et il porte sur l'INSTRUMENT : sur une seconde base, un
    /// `detail` altéré après coup fait NOMMER la rupture. Sans lui, le silence du premier verdict
    /// pourrait être celui d'un vérificateur aveugle plutôt qu'une propriété de la chaîne.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien des points de contrôle signés (aucun n'est posé ici, et
    /// `P10.7-v` juge déjà l'absence d'ancrage) ; et il n'exécute pas le binaire `verify`, seulement
    /// la fonction qu'il appelle.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO ledger…")` dans
    /// `ledger_append` — le troisième appel n'avoue plus rien, l'assertion de l'issue tombe, et le
    /// journal amputé devient indiscernable d'un journal complet à l'écriture COMME à la lecture.
    #[test]
    fn pae_une_ligne_de_registre_manquante_ne_rompt_pas_la_chaine_a_la_verification_hors_ligne() {
        let _env = VERROU_ENV_PROCESSUS.read(); // `verify_ledger` lit PLUME_DB_KEY / PLUME_LEDGER_PUBKEY

        // ---- ① LE JOURNAL AMPUTÉ : deux maillons, un TROISIÈME que la base refuse, puis un quatrième. ----
        let (coffre, conn) = pae_coffre("pae-journal-ampute");
        for i in 0..2 {
            assert!(
                ledger_append(&conn, "config.mode", &format!("maillon {i}")).cause_de_non_inscription().is_none(),
                "fixture : les deux premiers maillons sont écrits"
            );
        }
        conn.execute_batch(
            "ALTER TABLE ledger RENAME TO ledger_source;\
             CREATE TEMP VIEW ledger AS SELECT * FROM ledger_source;",
        )
        .unwrap();
        assert!(
            ledger_append(&conn, "config.mode", "maillon PERDU").cause_de_non_inscription().is_some(),
            "le maillon perdu est AVOUÉ à l'écriture — c'est le seul endroit où il se voit"
        );
        conn.execute_batch("DROP VIEW ledger; ALTER TABLE ledger_source RENAME TO ledger;").unwrap();
        assert!(
            ledger_append(&conn, "config.mode", "maillon d'après la perte").cause_de_non_inscription().is_none(),
            "fixture : le maillon suivant, lui, est écrit"
        );
        let (dernier_id, lignes): (i64, i64) = conn
            .query_row("SELECT MAX(id), COUNT(*) FROM ledger", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(lignes, 3, "fixture : QUATRE appels, TROIS lignes en base");
        assert_eq!(
            dernier_id, 3,
            "et l'identifiant ne saute PAS : une écriture ratée ne consomme aucun numéro, donc même le \
             compteur ne trahit pas la perte"
        );
        drop(conn);

        // ---- ② LE VERDICT HORS LIGNE SUR LE JOURNAL AMPUTÉ : « intègre ». ----
        let (n, sig_ok, sig_ko, rupture) = verify_ledger(coffre.as_str()).expect(
            "la vérification CONCLUT : le maillon suivant s'est accroché au dernier hachage PRÉSENT, \
             donc la chaîne recalculée est parfaitement continue",
        );
        assert_eq!(
            (n, sig_ok, sig_ko, rupture), (3, 0, 0, None),
            "LA RÉPONSE À LA QUESTION : la trace se REFERME SANS TROU VISIBLE — le vérificateur hors \
             ligne rend « intègre » sur un journal AMPUTÉ, exactement le verdict qu'il rendrait si rien \
             n'avait été perdu"
        );

        // ---- ③ CONTRÔLE POSITIF D'INSTRUMENT : une VRAIE rupture, elle, est NOMMÉE. ----
        let (coffre_rompu, conn) = pae_coffre("pae-journal-rompu");
        for i in 0..3 {
            assert!(
                ledger_append(&conn, "config.mode", &format!("maillon {i}")).cause_de_non_inscription().is_none(),
                "fixture : les trois maillons sont écrits"
            );
        }
        let vise: i64 = conn.query_row("SELECT MIN(id) + 1 FROM ledger", [], |r| r.get(0)).unwrap();
        conn.execute("UPDATE ledger SET detail='détail réécrit après coup' WHERE id=?1", params![vise]).unwrap();
        drop(conn);
        let (_n, _ok, _ko, rupture) = verify_ledger(coffre_rompu.as_str()).expect("la base se lit");
        assert_eq!(
            rupture, Some(vise),
            "CONTRÔLE POSITIF : le même vérificateur NOMME une rupture réelle. Son silence sur le \
             journal amputé est donc une propriété de la chaîne, pas un instrument aveugle"
        );
    }
}
