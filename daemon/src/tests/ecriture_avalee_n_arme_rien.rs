// =====================================================================================
// `P10.20-t` — UNE ÉCRITURE AVALÉE N'INSCRIT RIEN AU REGISTRE ET N'ARME RIEN.
//
// LE DÉFAUT, MESURÉ LE 2026-09-16 AVANT TOUT CORRECTIF. Les deux seuls gestes qui posent une ligne
// dans la table `action` écrivaient leur `INSERT` sous `let _ =` — la forme SANS branche d'échec,
// muette par construction — puis affirmaient qu'il avait eu lieu :
//   * `action_create` (handlers/actions.rs) lisait `conn.last_insert_rowid()`, posait
//     `action.queued` au registre tamper-evident et servait cet identifiant à la console ;
//   * `run_playbooks` (handlers/playbooks.rs) armait le miroir de ban HTTP (`net_ban`) juste après,
//     sur les variables LOCALES `status`/`dry` que l'écriture n'avait jamais confirmées.
// C'est la famille de `P10.20-q` — un fait fabriqué dans une trace non purgeable — prise du côté de
// l'ÉCRITURE, et c'est pourquoi aucune des gardes de LECTURE du dépôt ne la voyait.
//
// CE QUE L'ÉNONCÉ DE LA CLÉ SOUS-COMPTE, ET LES TÉMOINS D'ICI LE JOUENT. La clé écrit que
// `last_insert_rowid()` « peut rendre l'identifiant d'une AUTRE ligne ». La mesure est plus
// large : cette fonction rend le dernier identifiant inséré sur la CONNEXION, toutes tables
// confondues — donc la ligne d'une AUTRE TABLE (le registre lui-même, un événement), ou `0` sur une
// connexion qui n'a encore rien inséré. Le premier témoin AMORCE délibérément la connexion avec des
// lignes de registre : l'identifiant que l'ancienne forme aurait servi à la console — qui l'AFFICHE
// (`web/cases.js`, « Action mise en file (#…) ») et le repose sur les routes d'approbation et
// d'annulation — désigne une ligne du journal d'intégrité, pas une riposte.
//
// LES DEUX VOIES D'ÉCHEC D'ÉCRITURE, ET POURQUOI DEUX. La TABLE RETIRÉE (renommée sous les pieds du
// gestionnaire) fait échouer la PRÉPARATION de l'énoncé ; la VUE TEMPORAIRE — la table renommée,
// une vue de même nom posée par-dessus — laisse la LECTURE passer et fait échouer la seule
// ÉCRITURE. C'est elle qui sépare cette clé de `P10.20-q` : sur une vue, la relecture d'une riposte
// réussirait, et pourtant rien ne peut être écrit. Chaque témoin porte son CONTRÔLE POSITIF dans le
// même corps : sans lui, un refus INCONDITIONNEL passerait pour un refus fondé.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun module de `web/` ne lit le 503 neuf — `detection_admin.js`
// et `viz.js` appellent `apiSend` SANS `try/catch`, et `apiSend` LÈVE sur un statut non-2xx, donc le
// refus y est un no-op silencieux (`web/cases.js`, lui, l'attrape et le peint) ; la perte d'une
// riposte de playbook est COMPTÉE au bilan du tick mais sa cause n'y est pas portée (`Mesure::Lue`
// ne transporte qu'un nombre) ; et la pose du ban HTTP elle-même (`auth::netban_upsert`) avale
// toujours son propre `INSERT` et rend `true` quoi qu'il arrive — mesuré, hors de cette clé.
// =====================================================================================
mod ecriture_avalee_n_arme_rien {
    use super::*;

    /// Une base plume COMPLÈTE, sur fichier : le renommage de table et la vue temporaire ont besoin
    /// d'une vraie connexion d'écriture, celle que le gestionnaire prend par `req_conn!`.
    fn ean_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ean-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-t` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ean_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ean_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ean_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn ean_lignes_de_registre(st: &AppState) -> i64 {
        ean_compte(st, "SELECT COUNT(*) FROM ledger")
    }

    fn ean_bans_armes(st: &AppState) -> i64 {
        ean_compte(st, "SELECT COUNT(*) FROM net_ban")
    }

    /// LA CONNEXION EST AMORCÉE AVEC DES LIGNES D'UNE AUTRE TABLE. C'est l'instrument du premier
    /// témoin : après ces appels, `last_insert_rowid()` sur la connexion du gestionnaire désigne une
    /// ligne du REGISTRE. L'ancienne forme la servait comme identifiant de riposte.
    fn ean_amorcer_la_connexion_avec_des_lignes_de_registre(st: &AppState, combien: usize) {
        let conn = st.db.lock();
        for i in 0..combien {
            ledger_append(&conn, "temoin.amorce", &format!("amorce {i}"));
        }
    }

    async fn ean_creer(st: &AppState, corps: Value) -> (u16, Value) {
        pb_json(action_create(State(st.clone()), Extension(ean_au()), Json(corps)).await).await
    }

    fn ean_corps(cible: &str) -> Value {
        json!({ "kind": "ban_ip", "target": cible, "dry_run": false, "reason": "temoin P10.20-t" })
    }

    /// La phrase servie par le refus (`err_json` la pose sous `error`).
    fn ean_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// L'IDENTIFIANT DE RIPOSTE SERVI, s'il y en a un. Il est NUMÉRIQUE : le `id` que `err_json` pose
    /// sur un 5xx est une chaîne de corrélation (`plume-e<pid>-<n>`), et la confondre avec un
    /// identifiant de riposte rendrait ce témoin vert sur le défaut qu'il tient.
    fn ean_identifiant_servi(v: &Value) -> Option<i64> {
        v.get("id").and_then(|x| x.as_i64())
    }

    // -------------------------------------------------------------------------------------
    // (1) LA VUE TEMPORAIRE — la lecture passe, l'ÉCRITURE ne passe pas.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : quand la ligne de la riposte ne peut pas être écrite alors que la base
    /// répond, `action_create` REFUSE par un 503 nommé — AUCUN identifiant numérique n'est servi,
    /// AUCUNE ligne n'entre au registre (qui, lui, est parfaitement écrivable pendant le refus :
    /// l'amorçage vient d'y poser trois maillons), aucun ban n'est armé, et la table des ripostes ne
    /// gagne pas de ligne. Le contrôle positif, dans le même corps, montre que l'identifiant servi
    /// est bien celui de la ligne ÉCRITE.
    ///
    /// CE QU'IL NE TIENT PAS : il n'éprouve pas une base réellement en lecture seule (la cause de
    /// terrain), seulement un objet non modifiable — le chemin de code refusé est le même ; et il ne
    /// juge pas ce que la console peint de ce 503.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO action…")`
    /// suivi de `let id = conn.last_insert_rowid();` et du `ledger_append` inconditionnel. La route
    /// redevient 200, elle sert l'identifiant du DERNIER MAILLON DE REGISTRE posé par l'amorçage, et
    /// le registre gagne une ligne `action.queued` pour une riposte qui n'existe pas.
    #[tokio::test]
    async fn ean_une_riposte_que_la_base_refuse_d_ecrire_n_a_ni_identifiant_ni_ligne_de_registre() {
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (st, _tmp) = ean_etat("vue-temporaire");
        ean_amorcer_la_connexion_avec_des_lignes_de_registre(&st, 3);

        // LA VUE TEMPORAIRE : lisible, non modifiable. Elle vit sur LA connexion du gestionnaire.
        ean_ecrire(
            &st,
            "ALTER TABLE action RENAME TO action_source;\
             CREATE TEMP VIEW action AS SELECT * FROM action_source;",
        );
        let registre_avant = ean_lignes_de_registre(&st);
        let ripostes_avant = ean_compte(&st, "SELECT COUNT(*) FROM action_source");
        let (statut, avoue) = ean_creer(&st, ean_corps("203.0.113.30")).await;
        assert_eq!(statut, 503, "écriture impossible : la route REFUSE au lieu de servir un identifiant : {avoue}");
        assert!(
            ean_phrase(&avoue).starts_with(CAUSE_RIPOSTE_NON_MISE_EN_FILE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(
            ean_identifiant_servi(&avoue), None,
            "AUCUN identifiant de riposte n'est servi — celui que l'ancienne forme rendait désignait \
             un maillon du REGISTRE, que l'analyste aurait ensuite approuvé ou annulé : {avoue}"
        );
        assert_eq!(ean_lignes_de_registre(&st), registre_avant, "et le registre — écrivable — n'atteste RIEN");
        assert_eq!(ean_compte(&st, "SELECT COUNT(*) FROM action_source"), ripostes_avant, "aucune riposte n'a été posée");
        assert_eq!(ean_bans_armes(&st), 0, "et aucun ban n'est armé");

        // CONTRÔLE POSITIF — la vue retirée, la même riposte se met en file, le registre reçoit sa
        // ligne, et l'identifiant SERVI est celui de la ligne ÉCRITE (jamais celui d'une autre table).
        ean_ecrire(&st, "DROP VIEW action; ALTER TABLE action_source RENAME TO action;");
        let (statut, pose) = ean_creer(&st, ean_corps("203.0.113.30")).await;
        assert_eq!(statut, 200, "le refus n'est pas inconditionnel : {pose}");
        let servi = ean_identifiant_servi(&pose).unwrap_or_else(|| panic!("un identifiant numérique est servi : {pose}"));
        let ecrite: i64 = st
            .db
            .lock()
            .query_row("SELECT id FROM action WHERE target='203.0.113.30'", [], |r| r.get(0))
            .expect("la riposte est écrite");
        assert_eq!(servi, ecrite, "l'identifiant servi est celui de la ligne écrite");
        assert_eq!(ean_lignes_de_registre(&st), registre_avant + 1, "et le registre reçoit alors son unique ligne");
    }

    // -------------------------------------------------------------------------------------
    // (2) LA TABLE RETIRÉE — la PRÉPARATION échoue, même refus nommé.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `action` renommée sous les pieds du gestionnaire, la mise en file refuse par
    /// le même 503 nommé, ne sert aucun identifiant, n'écrit RIEN au registre (lisible pendant le
    /// refus) et n'arme aucun ban ; la table remise, elle ne porte toujours aucune riposte. Contrôle
    /// positif compté AVANT le retrait, sur la même base.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien du chemin où l'écriture poserait un nombre de lignes
    /// inattendu (un énoncé sans clause de conflit écrit une ligne ou échoue).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : la même qu'au témoin (1) — la route redevient 200 avec un
    /// identifiant emprunté, et `action.queued` part pendant que la table des ripostes est hors
    /// d'atteinte.
    #[tokio::test]
    async fn ean_une_table_de_ripostes_hors_d_atteinte_refuse_la_mise_en_file_sans_rien_ecrire() {
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (st, _tmp) = ean_etat("table-retiree");

        // CONTRÔLE POSITIF — sur la même base, une riposte se met en file et s'inscrit au registre.
        let registre_avant = ean_lignes_de_registre(&st);
        let (statut, pose) = ean_creer(&st, ean_corps("203.0.113.31")).await;
        assert_eq!(statut, 200, "{pose}");
        assert!(ean_identifiant_servi(&pose).is_some(), "{pose}");
        assert_eq!(ean_lignes_de_registre(&st), registre_avant + 1);

        // LA TABLE RETIRÉE — renommée, elle n'est plus sous le nom que l'énoncé attend.
        ean_ecrire(&st, "ALTER TABLE action RENAME TO action_hors_d_atteinte;");
        let registre_avant = ean_lignes_de_registre(&st);
        let (statut, avoue) = ean_creer(&st, ean_corps("203.0.113.32")).await;
        assert_eq!(statut, 503, "table hors d'atteinte : même refus : {avoue}");
        assert!(ean_phrase(&avoue).starts_with(CAUSE_RIPOSTE_NON_MISE_EN_FILE), "{avoue}");
        assert_eq!(ean_identifiant_servi(&avoue), None, "aucun identifiant de riposte n'est servi : {avoue}");
        assert_eq!(ean_lignes_de_registre(&st), registre_avant, "le registre, lui, était lisible — et il ne reçoit RIEN");
        assert_eq!(ean_bans_armes(&st), 0, "et aucun ban n'est armé");

        // LA TABLE REMISE : la riposte refusée n'existe nulle part.
        ean_ecrire(&st, "ALTER TABLE action_hors_d_atteinte RENAME TO action;");
        assert_eq!(
            ean_compte(&st, "SELECT COUNT(*) FROM action WHERE target='203.0.113.32'"), 0,
            "aucune ligne n'a été posée pour la riposte refusée"
        );
    }

    // -------------------------------------------------------------------------------------
    // (3) LE PLAYBOOK — une riposte non écrite n'arme AUCUN ban, et le tick le compte.
    // -------------------------------------------------------------------------------------

    /// Arme une base neuve avec UN playbook `ban_ip` dû, admin-authored, en mode ACTIF (donc
    /// auto-approuvé et réel) : c'est la seule configuration où `run_playbooks` arme le miroir HTTP.
    fn ean_base_de_playbook(tag: &str, cible: &str) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ean-{tag}"));
        let p = chemin.to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-t` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('ean-pb',1,?1,0,'ban_ip',0,3600,0,NULL,'admin')",
                params![format!("SELECT '{cible}'")],
            )
            .unwrap();
        }
        (db, p, chemin)
    }

    fn ean_compte_sur(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    /// CE QU'IL TIENT : en mode actif, avec l'auto-armement activé, un tick de playbook `ban_ip` pose
    /// la riposte ET arme le miroir HTTP (contrôle positif compté sur les deux quantités, bilan à
    /// ZÉRO abandon). Puis, la table des ripostes rendue NON MODIFIABLE par une vue temporaire — la
    /// LECTURE de déduplication passe toujours — le tick n'arme AUCUN ban pour la cible qu'il n'a pas
    /// pu écrire, et il le DIT : son bilan compte un abandon au lieu de publier « 0 ».
    ///
    /// CE QU'IL NE TIENT PAS : le bilan porte un NOMBRE, pas la cause (`Mesure::Lue`) ; et il ne juge
    /// pas la pose du ban elle-même, qui avale son propre `INSERT` (`auth::netban_upsert`).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO action…")` sans
    /// la branche d'échec. Le tick redevient `Lue(0)` et `net_ban` gagne la seconde adresse — un
    /// blocage HTTP posé pour une riposte qui n'existe dans aucune file, donc qu'aucun exécuteur
    /// d'hôte n'appliquera et qu'aucun écran ne montre.
    #[test]
    fn ean_un_playbook_dont_la_riposte_n_est_pas_ecrite_n_arme_aucun_ban_et_le_tick_le_compte() {
        use crate::mesure_environnement::Mesure;
        let _env = VERROU_ENV_PROCESSUS.write();
        // Le poseur de réglage PARTAGÉ de `common.rs` (il restaure au `Drop`, y compris sur panic).
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (db, p, _tmp) = ean_base_de_playbook("playbook-vue", "203.0.113.40");

        // CONTRÔLE POSITIF — la riposte est posée et le miroir HTTP est ARMÉ.
        assert_eq!(crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(0), "base saine : rien d'abandonné");
        assert_eq!(ean_compte_sur(&db, "SELECT COUNT(*) FROM action"), 1, "la riposte est posée");
        assert_eq!(ean_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.40'"), 1, "et le ban est ARMÉ");

        // LA MÊME CHOSE SUR UNE AUTRE CIBLE, table des ripostes NON MODIFIABLE. La déduplication —
        // une LECTURE — passe toujours ; seule l'écriture de la riposte est impossible.
        {
            let conn = db.lock();
            conn.execute("UPDATE playbook SET query=?1, last_run=NULL WHERE name='ean-pb'", params!["SELECT '203.0.113.41'"])
                .unwrap();
            conn.execute_batch(
                "ALTER TABLE action RENAME TO action_source;\
                 CREATE TEMP VIEW action AS SELECT * FROM action_source;",
            )
            .unwrap();
        }
        assert_eq!(
            crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(1),
            "une riposte que la base n'a PAS écrite est un abandon COMPTÉ — publier « 0 abandon » \
             laisserait un tick vert sur une réponse évaporée"
        );
        assert_eq!(
            ean_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.41'"), 0,
            "AUCUN ban n'est armé pour une action qui n'a pas été écrite — le blocage HTTP aurait \
             existé sans aucune ligne dans la file, donc sans exécution d'hôte et sans trace à l'écran"
        );
        assert_eq!(ean_compte_sur(&db, "SELECT COUNT(*) FROM net_ban"), 1, "le ban du contrôle positif, et lui seul");

        // LA TABLE REMISE : aucune riposte n'a été posée pour la seconde cible.
        db.lock().execute_batch("DROP VIEW action; ALTER TABLE action_source RENAME TO action;").unwrap();
        assert_eq!(ean_compte_sur(&db, "SELECT COUNT(*) FROM action WHERE target='203.0.113.41'"), 0);
        assert_eq!(ean_compte_sur(&db, "SELECT COUNT(*) FROM action"), 1, "la file ne porte que la riposte du contrôle positif");
    }
}
