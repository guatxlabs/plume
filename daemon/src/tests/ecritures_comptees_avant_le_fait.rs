// =====================================================================================
// `P10.20-w` — UNE ÉCRITURE SE COMPTE AVANT QU'UN FAIT NE L'AFFIRME (rangs UN, DEUX et CINQ).
//
// CE QUE CES TÉMOINS TIENNENT. La garde de forme `check_a_swallowed_write_is_never_affirmed_as_a_fact.py`
// constate qu'une FORME est absente des sources ; elle ne prouve jamais qu'une réponse RÉELLE refuse
// avant d'écrire au registre. C'est ce que ces témoins prennent en charge, sur les huit sites des
// rangs un, deux et cinq plus l'annulation de riposte, et la preuve est prise DES DEUX CÔTÉS : le
// statut servi, la ligne de registre comptée, la table des bans comptée, l'identifiant NON servi, et
// l'état relu de la ligne visée.
//
// LES DEUX VOIES D'ÉCHEC D'ÉCRITURE, REPRISES DE `P10.20-t` ET `P10.20-v`. La VUE TEMPORAIRE — la
// table renommée, une vue de même nom posée par-dessus — laisse la LECTURE passer et fait échouer la
// seule ÉCRITURE : c'est elle qui sépare cette famille de celle des lectures ratées, puisque tout ce
// qui relit réussit pendant que rien ne s'écrit. La TABLE RETIRÉE fait échouer la PRÉPARATION de
// l'énoncé. Chaque témoin porte son CONTRÔLE POSITIF dans le même corps : sans lui, un refus
// INCONDITIONNEL passerait pour un refus fondé.
//
// CE QUI ÉTAIT FAUX DANS LE CLASSEMENT DE LA CELLULE, ET QUE CES TÉMOINS MESURENT :
//   * RANG UN, `actions.rs::respond_run` — la cellule le range sous « une écriture dégradée précède
//     un armement ». L'armement n'était PAS atteignable sur l'écriture ratée : `unwrap_or(0)` rendait
//     `0`, le bloc « verdict conservé » prenait la main et se terminait par un `continue`. Ce que
//     l'écriture ratée produisait n'est pas un ban armé, c'est une ligne du registre tamper-evident
//     qui ATTRIBUE à un autre acteur un verdict que personne n'a rendu — `verdict `approved` déjà
//     posé, conservé` sur une action que ce responder venait d'exécuter pour de vrai. Le témoin joue
//     exactement ce couple : l'écriture refusée pendant que la relecture, elle, réussit ;
//   * RANG UN, `playbooks.rs::run_playbooks` — le marqueur `last_run` n'affirme RIEN des ripostes et
//     des bans qui suivent : il commande la SÉLECTION des playbooks dus. Le fait qu'il précède n'est
//     pas le fait qu'il affirme (la garde le dit elle-même : elle ne sait pas si l'écriture et le
//     fait parlent du même objet). Ce qu'il coûte, lui, se mesure : avalé, il laissait le playbook dû
//     indéfiniment pendant que le bilan du tick publiait « 0 abandon », et la seule chose qui
//     empêchait une SECONDE riposte et un SECOND armement était la fenêtre de déduplication
//     `window_s` — une colonne par playbook, qu'aucune borne n'oblige à couvrir l'écart entre deux
//     tours de l'ordonnanceur ;
//   * RANG CINQ, `cases.rs::ack_all` — la cellule le range sous « dégradé mais fail-closed : aucun
//     fait fabriqué, registre CONDITIONNEL ». Son `ledger_append` était INCONDITIONNEL : sur une
//     écriture ratée, `alert.ack_all 0 alertes` entrait dans la trace non purgeable et la route
//     servait `{"acked": 0}` sous un 200, que la console rend « aucune alerte à acquitter ». C'est un
//     fait fabriqué, donc un site de rang TROIS logé au rang cinq. Le témoin compte les lignes de
//     registre des deux côtés du refus.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU : ils n'éprouvent pas une base
// réellement en lecture seule (la cause de terrain), seulement un objet non modifiable — le chemin de
// code refusé est le même ; `respond_run` n'est joué qu'au niveau de sa clôture typée, jamais de bout
// en bout (il exécute des commandes système en root) ; aucun module de `web/` n'est exercé ici, donc
// rien ne dit ce que la console PEINT de ces refus ; et le bilan d'un tick porte un NOMBRE, pas la
// cause de l'abandon qu'il compte.
// =====================================================================================
mod ecritures_comptees_avant_le_fait {
    use super::*;

    // ---------------------------------------------------------------------------------
    // LA FIXTURE — une base plume COMPLÈTE, sur fichier : le renommage de table et la vue temporaire
    // ont besoin d'une vraie connexion d'écriture, celle que le gestionnaire prend par `req_conn!`
    // ou par `with_write`.
    // ---------------------------------------------------------------------------------
    fn ecf_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ecf-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-w` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM alert", []).unwrap();
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn ecf_admin() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn ecf_agent(hote: &str) -> AuthUser {
        AuthUser {
            name: hote.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
            method: "token".into(), csrf: String::new(), env: None,
        }
    }

    fn ecf_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ecf_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn ecf_lignes_de_registre(st: &AppState) -> i64 {
        ecf_compte(st, "SELECT COUNT(*) FROM ledger")
    }

    /// LA CONNEXION EST AMORCÉE AVEC DES LIGNES D'UNE AUTRE TABLE : après ces appels,
    /// `last_insert_rowid()` sur la connexion du gestionnaire désigne une ligne du REGISTRE. C'est
    /// l'identifiant que l'ancienne forme de `case_create_row` servait comme numéro de dossier.
    fn ecf_amorcer_la_connexion_avec_des_lignes_de_registre(st: &AppState, combien: usize) {
        let conn = st.db.lock();
        for i in 0..combien {
            ledger_append(&conn, "temoin.amorce", &format!("amorce {i}"));
        }
    }

    /// La phrase servie par un refus (`err_json` la pose sous `error`).
    fn ecf_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// L'IDENTIFIANT NUMÉRIQUE SERVI, s'il y en a un. Le `id` que `err_json` pose sur un 5xx est une
    /// chaîne de corrélation (`plume-e<pid>-<n>`) : la confondre avec un identifiant d'objet rendrait
    /// ces témoins verts sur le défaut même qu'ils tiennent.
    fn ecf_identifiant_servi(v: &Value) -> Option<i64> {
        v.get("id").and_then(|x| x.as_i64())
    }

    /// La vue temporaire sur une table : lisible, NON modifiable, posée sur LA connexion d'écriture.
    fn ecf_rendre_la_table_non_modifiable(st: &AppState, table: &str) {
        ecf_ecrire(
            st,
            &format!("ALTER TABLE {table} RENAME TO {table}_source; CREATE TEMP VIEW {table} AS SELECT * FROM {table}_source;"),
        );
    }

    fn ecf_rendre_la_table_modifiable(st: &AppState, table: &str) {
        ecf_ecrire(st, &format!("DROP VIEW {table}; ALTER TABLE {table}_source RENAME TO {table};"));
    }

    // =================================================================================
    // RANG UN (1/2) — LE RESPONDER : UNE CLÔTURE NON ÉCRITE N'EST PAS « UN AUTRE A TRANCHÉ ».
    // =================================================================================

    /// CE QU'IL TIENT : les trois issues de la clôture gardée du responder sont DISTINCTES sur la
    /// même base — la ligne écrite (`Posee`), l'action déjà tranchée (`VerdictDejaPose`, le cas pour
    /// lequel le bloc « verdict conservé » a été écrit) et l'écriture refusée (`NonEcrite`, qui porte
    /// sa cause). Et il joue le COUPLE que l'ancienne forme écrasait : pendant que l'écriture est
    /// refusée, la RELECTURE du verdict conservé réussit et rend `approved` — c'est exactement la
    /// paire que `unwrap_or(0)` transformait en « verdict `approved` déjà posé, conservé » dans la
    /// trace non purgeable, sur une action que personne n'avait tranchée.
    ///
    /// CE QU'IL NE TIENT PAS : il n'exécute pas `respond_run` de bout en bout (root, commandes
    /// système) ; ce que la boucle FAIT de chaque issue est lu à la source, pas exercé ici.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)` sur la clôture. Les deux zéros
    /// redeviennent un seul, `NonEcrite` disparaît, et l'assertion qui sépare l'écriture refusée de
    /// l'action déjà tranchée tombe.
    #[test]
    fn ecf_une_cloture_de_riposte_non_ecrite_ne_se_lit_pas_comme_un_verdict_deja_pose() {
        use crate::handlers::actions::{clore_une_action_approuvee, verdict_conserve_relu, ClotureDeRiposte, VerdictConserve};
        let (st, _tmp) = ecf_etat("responder-cloture");
        {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO action(ts,kind,target,status,dry_run) VALUES(?1,'ban_ip','203.0.113.50','approved',0)",
                params![now()],
            )
            .unwrap();
        }
        let id: i64 = ecf_compte(&st, "SELECT id FROM action WHERE target='203.0.113.50'");

        // CONTRÔLE POSITIF — la base saine : la ligne est écrite, et le statut relu le confirme.
        assert!(
            matches!(clore_une_action_approuvee(&st.db.lock(), id, "done", "ok"), ClotureDeRiposte::Posee),
            "base saine : la clôture écrit sa ligne"
        );
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM action WHERE id IN (SELECT id FROM action) AND status='done'"), 1);

        // L'ACTION EST DÉJÀ TRANCHÉE — aucune ligne ne correspond, et c'est un FAIT : le verdict posé
        // est conservé. Cette issue-là ne doit pas bouger, c'est le chemin nominal du bloc d'origine.
        assert!(
            matches!(clore_une_action_approuvee(&st.db.lock(), id, "failed", "second passage"), ClotureDeRiposte::VerdictDejaPose),
            "déjà tranchée : le verdict conservé est une absence ÉTABLIE"
        );

        // L'ÉCRITURE REFUSÉE — la table des ripostes est rendue non modifiable ; la LECTURE, elle,
        // passe toujours.
        ecf_rendre_la_table_non_modifiable(&st, "action");
        let cause = match clore_une_action_approuvee(&st.db.lock(), id, "done", "troisième passage") {
            ClotureDeRiposte::NonEcrite(cause) => cause,
            ClotureDeRiposte::Posee => panic!("l'écriture est impossible : la clôture ne peut pas se dire POSÉE"),
            ClotureDeRiposte::VerdictDejaPose => panic!(
                "l'écriture REFUSÉE se lit « un verdict plus informé est déjà posé » — c'est le récit \
                 que l'ancienne forme écrivait au registre tamper-evident"
            ),
        };
        assert!(!cause.is_empty(), "l'issue PORTE sa cause, pour que la ligne de registre la nomme");

        // ET VOICI LE COUPLE QUE L'ANCIENNE FORME ÉCRASAIT : la relecture du verdict conservé RÉUSSIT
        // pendant que l'écriture est refusée, et elle rend le statut d'avant.
        match verdict_conserve_relu(&st.db.lock(), id) {
            VerdictConserve::Lu(v) => assert_eq!(
                v, "done",
                "la relecture réussit et rend le statut d'AVANT : apparié au zéro d'`unwrap_or`, il \
                 devenait « verdict déjà posé, conservé » pour un verdict que personne n'avait rendu"
            ),
            VerdictConserve::LigneDisparue => panic!("la ligne est lisible : ce n'est pas une absence"),
            VerdictConserve::NonRelu(e) => panic!("la LECTURE doit passer sur une vue ({e})"),
        }

        ecf_rendre_la_table_modifiable(&st, "action");
    }

    // =================================================================================
    // RANG UN (2/2) — LE PLAYBOOK : UN MARQUEUR DE PASSAGE NON ÉCRIT N'ARME RIEN.
    // =================================================================================

    /// Arme une base neuve avec UN playbook `ban_ip` dû, admin-authored, en mode ACTIF : la seule
    /// configuration où `run_playbooks` arme le miroir HTTP.
    fn ecf_base_de_playbook(tag: &str, cible: &str) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("ecf-{tag}"));
        let p = chemin.to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-w` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','active')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('ecf-pb',1,?1,0,'ban_ip',0,3600,0,NULL,'admin')",
                params![format!("SELECT '{cible}'")],
            )
            .unwrap();
        }
        (db, p, chemin)
    }

    fn ecf_compte_sur(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    /// CE QU'IL TIENT : quand le marqueur de passage d'un playbook ne peut pas être écrit — la table
    /// `playbook` rendue non modifiable, la SÉLECTION des dus passant toujours —, le tour de ce
    /// playbook est refusé AVANT tout fait : aucune riposte n'entre dans la file, AUCUN ban n'est
    /// armé, et le bilan du tick compte un abandon au lieu de publier « 0 ». Contrôle positif dans le
    /// même corps : sur la base saine, le même tick pose la riposte, arme le miroir HTTP et rend un
    /// bilan à zéro abandon.
    ///
    /// CE QU'IL NE TIENT PAS : le bilan porte un NOMBRE, pas la cause ; et il ne dit rien du tour
    /// SUIVANT, où le playbook — resté dû — sera réévalué.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("UPDATE playbook SET
    /// last_run=…")`. Le tick redevient `Lue(0)` et `net_ban` gagne la seconde adresse : un blocage
    /// HTTP posé au nom d'un playbook dont l'ordonnanceur n'a jamais pu enregistrer le passage.
    #[test]
    fn ecf_un_marqueur_de_passage_non_ecrit_n_arme_aucun_ban_et_le_tick_le_compte() {
        use crate::mesure_environnement::Mesure;
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban, il déclare sa population
        let (db, p, _tmp) = ecf_base_de_playbook("playbook-marqueur", "203.0.113.60");

        // CONTRÔLE POSITIF — la riposte est posée, le miroir HTTP est ARMÉ, le marqueur est écrit.
        assert_eq!(crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(0), "base saine : rien d'abandonné");
        assert_eq!(ecf_compte_sur(&db, "SELECT COUNT(*) FROM action"), 1, "la riposte est posée");
        assert_eq!(ecf_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.60'"), 1, "et le ban est ARMÉ");
        assert_eq!(ecf_compte_sur(&db, "SELECT COUNT(*) FROM playbook WHERE last_run IS NOT NULL"), 1, "le passage est marqué");

        // LA MÊME CHOSE SUR UNE AUTRE CIBLE, TABLE `playbook` NON MODIFIABLE. La sélection des dus —
        // une LECTURE — passe toujours ; seule l'écriture du marqueur est impossible.
        {
            let conn = db.lock();
            conn.execute("UPDATE playbook SET query=?1, last_run=NULL WHERE name='ecf-pb'", params!["SELECT '203.0.113.61'"])
                .unwrap();
            conn.execute_batch(
                "ALTER TABLE playbook RENAME TO playbook_source;\
                 CREATE TEMP VIEW playbook AS SELECT * FROM playbook_source;",
            )
            .unwrap();
        }
        assert_eq!(
            crate::handlers::playbooks::run_playbooks(&db, &p), Mesure::Lue(1),
            "un marqueur de passage que la base n'a PAS écrit est un abandon COMPTÉ — publier « 0 \
             abandon » laisserait un tick vert sur un ordonnancement qu'on n'a pas su enregistrer"
        );
        assert_eq!(
            ecf_compte_sur(&db, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.61'"), 0,
            "AUCUN ban n'est armé sur un tour dont le marqueur n'est pas écrit : la même évaluation, \
             rejouée au tour suivant, en armerait un SECOND dès que `window_s` ne couvre pas l'écart"
        );
        assert_eq!(ecf_compte_sur(&db, "SELECT COUNT(*) FROM net_ban"), 1, "le ban du contrôle positif, et lui seul");
        assert_eq!(
            ecf_compte_sur(&db, "SELECT COUNT(*) FROM action WHERE target='203.0.113.61'"), 0,
            "et aucune riposte n'est entrée dans la file pour ce tour refusé"
        );
        assert_eq!(
            ecf_compte_sur(&db, "SELECT COUNT(*) FROM ledger WHERE kind='playbook.marqueur-non-ecrit'"), 1,
            "le refus porte son PROPRE genre au registre, donc il se filtre"
        );

        db.lock().execute_batch("DROP VIEW playbook; ALTER TABLE playbook_source RENAME TO playbook;").unwrap();
    }

    // =================================================================================
    // RANG DEUX (1/2) — LE DOSSIER : PAS D'IDENTIFIANT SANS LIGNE ÉCRITE.
    // =================================================================================

    async fn ecf_creer_un_dossier(st: &AppState, titre: &str) -> (u16, Value) {
        pb_json(
            case_create(State(st.clone()), Extension(ecf_admin()), Json(json!({ "title": titre, "severity": 3, "priority": 2 })))
                .await
                .into_response(),
        )
        .await
    }

    /// CE QU'IL TIENT : la table `incident` rendue non modifiable — donc lisible —, `POST /api/cases`
    /// REFUSE par un 503 qui nomme sa cause, ne sert AUCUN identifiant numérique, n'écrit AUCUNE
    /// ligne au registre (parfaitement écrivable pendant le refus : l'amorçage vient d'y poser trois
    /// maillons) et ne laisse aucun dossier derrière lui. Le contrôle positif, dans le même corps,
    /// montre que l'identifiant servi est celui de la ligne ÉCRITE et non d'un maillon du registre.
    ///
    /// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint de ce 503.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("INSERT INTO incident…")`
    /// suivi de `let id = conn.last_insert_rowid();`. La route redevient 200, elle sert l'identifiant
    /// du DERNIER MAILLON DE REGISTRE posé par l'amorçage, et `case.create` part pour un dossier qui
    /// n'existe pas — numéro sur lequel la console posera ensuite note, assignation et clôture.
    #[tokio::test]
    async fn ecf_un_dossier_que_la_base_refuse_d_ecrire_n_a_ni_identifiant_ni_ligne_de_registre() {
        let (st, _tmp) = ecf_etat("dossier-vue-temporaire");
        ecf_amorcer_la_connexion_avec_des_lignes_de_registre(&st, 3);
        ecf_rendre_la_table_non_modifiable(&st, "incident");

        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_creer_un_dossier(&st, "Dossier refusé").await;
        assert_eq!(statut, 503, "écriture impossible : la route REFUSE au lieu de servir un identifiant : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::cases::CAUSE_DOSSIER_NON_OUVERT),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(
            ecf_identifiant_servi(&avoue), None,
            "AUCUN identifiant de dossier n'est servi — celui que l'ancienne forme rendait désignait \
             un maillon du REGISTRE : {avoue}"
        );
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "et le registre — écrivable — n'atteste RIEN");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM incident_source"), 0, "aucun dossier n'a été ouvert");

        // CONTRÔLE POSITIF — la vue retirée, le même dossier s'ouvre, le registre reçoit sa ligne, et
        // l'identifiant SERVI est celui de la ligne ÉCRITE (jamais celui d'une autre table).
        ecf_rendre_la_table_modifiable(&st, "incident");
        let (statut, pose) = ecf_creer_un_dossier(&st, "Dossier refusé").await;
        assert_eq!(statut, 200, "le refus n'est pas inconditionnel : {pose}");
        let servi = ecf_identifiant_servi(&pose).unwrap_or_else(|| panic!("un identifiant numérique est servi : {pose}"));
        let ecrit: i64 = ecf_compte(&st, "SELECT id FROM incident WHERE title='Dossier refusé'");
        assert_eq!(servi, ecrit, "l'identifiant servi est celui de la ligne écrite");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.create'"), 1,
            "et le registre reçoit alors son unique ligne `case.create`"
        );
    }

    // =================================================================================
    // RANG DEUX (2/2) — LA TABLE RETIRÉE : MÊME REFUS, ET AUCUNE ÉCHÉANCE POSÉE.
    // =================================================================================

    /// CE QU'IL TIENT : `incident` renommée sous les pieds du gestionnaire, l'ouverture refuse par le
    /// MÊME 503 nommé, ne sert aucun identifiant, n'écrit rien au registre — et rien non plus dans la
    /// timeline (`incident_item`), qui est pourtant une AUTRE table, parfaitement écrivable : le
    /// refus est posé AVANT elle, pas seulement avant le registre. Contrôle positif compté AVANT le
    /// retrait, sur la même base.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien du chemin où l'écriture poserait un nombre de lignes
    /// inattendu (un `INSERT` sans clause de conflit écrit une ligne ou échoue).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : la même qu'au témoin précédent — la route redevient 200
    /// avec un identifiant emprunté, et la timeline gagne un item `created` rattaché à ce numéro
    /// emprunté, donc à un objet d'une autre table.
    #[tokio::test]
    async fn ecf_une_table_de_dossiers_hors_d_atteinte_refuse_l_ouverture_sans_rien_ecrire() {
        let (st, _tmp) = ecf_etat("dossier-table-retiree");

        // CONTRÔLE POSITIF — sur la même base, un dossier s'ouvre, s'inscrit et pose sa timeline.
        let (statut, pose) = ecf_creer_un_dossier(&st, "Dossier ouvert").await;
        assert_eq!(statut, 200, "{pose}");
        assert!(ecf_identifiant_servi(&pose).is_some(), "{pose}");
        let items_avant = ecf_compte(&st, "SELECT COUNT(*) FROM incident_item");
        assert_eq!(items_avant, 1, "la timeline porte l'item `created` du dossier ouvert");

        // LA TABLE RETIRÉE — renommée, elle n'est plus sous le nom que l'énoncé attend.
        ecf_ecrire(&st, "ALTER TABLE incident RENAME TO incident_hors_d_atteinte;");
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_creer_un_dossier(&st, "Dossier perdu").await;
        assert_eq!(statut, 503, "table hors d'atteinte : même refus : {avoue}");
        assert!(ecf_phrase(&avoue).starts_with(crate::handlers::cases::CAUSE_DOSSIER_NON_OUVERT), "{avoue}");
        assert_eq!(ecf_identifiant_servi(&avoue), None, "aucun identifiant de dossier n'est servi : {avoue}");
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "le registre, lui, était lisible — et il ne reçoit RIEN");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM incident_item"), items_avant,
            "et la timeline — une AUTRE table, écrivable — ne gagne aucun item rattaché à un numéro emprunté"
        );

        // LA TABLE REMISE : le dossier refusé n'existe nulle part.
        ecf_ecrire(&st, "ALTER TABLE incident_hors_d_atteinte RENAME TO incident;");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM incident WHERE title='Dossier perdu'"), 0);
    }

    // =================================================================================
    // RANG CINQ (1/5) — LE VERDICT D'UN AGENT : LES DEUX ZÉROS SONT SÉPARÉS.
    // =================================================================================

    async fn ecf_remonter_un_resultat(st: &AppState, hote: &str, id: i64) -> (u16, Value) {
        pb_json(
            action_result(State(st.clone()), Extension(ecf_agent(hote)), Json(json!({ "id": id, "status": "done", "result": "ok" })))
                .await
                .into_response(),
        )
        .await
    }

    /// CE QU'IL TIENT : les TROIS sorties de `POST /api/actions/result` sur la même base — la ligne
    /// écrite (200 `ok: true`, une ligne de registre), l'absence ÉTABLIE (200 `ok: false`, AUCUNE
    /// ligne de registre, contrat INCHANGÉ) et l'écriture refusée (503 nommé, aucune ligne de
    /// registre). Avant, les deux dernières rendaient le même `{"ok": false}` sous un 200 : l'agent,
    /// qui ne relit rien, passait à la riposte suivante en laissant celle-ci ouverte.
    ///
    /// CE QU'IL NE TIENT PAS : `collectors/respond.sh` jette la réponse de cette route (`-o
    /// /dev/null`, `|| true`) — le 503 y est invisible, et c'est écrit plutôt que supposé.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)`. Le refus redevient un 200
    /// `ok: false`, indiscernable de l'absence.
    #[tokio::test]
    async fn ecf_un_verdict_d_agent_non_ecrit_ne_se_lit_pas_comme_une_riposte_deja_close() {
        let (st, _tmp) = ecf_etat("verdict-agent");
        {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(?1,'ban_ip','203.0.113.70','approved',0,'hote-a')",
                params![now()],
            )
            .unwrap();
        }
        let id: i64 = ecf_compte(&st, "SELECT id FROM action WHERE target='203.0.113.70'");

        // ABSENCE ÉTABLIE — un identifiant qui ne désigne aucune riposte de cet hôte : contrat
        // INCHANGÉ (200, `ok: false`), et le registre n'en porte rien.
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, absence) = ecf_remonter_un_resultat(&st, "hote-a", id + 4242).await;
        assert_eq!(statut, 200, "l'absence garde EXACTEMENT sa sortie d'avant : {absence}");
        assert_eq!(absence["ok"], json!(false), "{absence}");
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "aucune ligne de registre sur une absence");

        // CONTRÔLE POSITIF — la riposte de cet hôte se clôt, et le registre le dit.
        let (statut, pose) = ecf_remonter_un_resultat(&st, "hote-a", id).await;
        assert_eq!(statut, 200, "{pose}");
        assert_eq!(pose["ok"], json!(true), "{pose}");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='action.remote'"), 1);
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM action WHERE status='done'"), 1);

        // L'ÉCRITURE REFUSÉE — la table est lisible, non modifiable.
        ecf_ecrire(&st, "UPDATE action SET status='approved' WHERE id=?1".replace("?1", &id.to_string()).as_str());
        ecf_rendre_la_table_non_modifiable(&st, "action");
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_remonter_un_resultat(&st, "hote-a", id).await;
        assert_eq!(statut, 503, "écriture refusée : 503 nommé, jamais `ok: false` : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::actions::CAUSE_RESULTAT_NON_ENREGISTRE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "et le registre n'atteste aucun verdict");
        ecf_rendre_la_table_modifiable(&st, "action");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM action WHERE id=? AND status='approved'".replace('?', &id.to_string()).as_str()),
            1,
            "la riposte est restée OUVERTE : c'est ce que le 503 dit, et `ok: false` disait le contraire"
        );
    }

    // =================================================================================
    // RANG CINQ (2/5) — L'ACQUITTEMENT EN MASSE : LE REGISTRE N'ÉTAIT PAS CONDITIONNEL.
    // =================================================================================

    async fn ecf_acquitter_tout(st: &AppState) -> (u16, Value) {
        pb_json(ack_all(State(st.clone()), Extension(ecf_admin())).await.into_response()).await
    }

    fn ecf_poser_une_alerte(st: &AppState, titre: &str) {
        st.db
            .lock()
            .execute(
                "INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'regle-temoin',3,?2,'new')",
                params![now(), titre],
            )
            .unwrap();
    }

    /// CE QU'IL TIENT — ET C'EST LA RÉFUTATION DU CLASSEMENT DE LA CELLULE : le `ledger_append` de
    /// `ack_all` n'était PAS conditionné au compte de lignes. Sur une écriture refusée, la trace non
    /// purgeable recevait `alert.ack_all 0 alertes` et la route servait `{"acked": 0}` sous un 200 —
    /// que la console rend « aucune alerte à acquitter » pendant que la file est pleine. Le témoin
    /// compte les lignes de registre DES DEUX CÔTÉS du refus et relit la file. Les deux autres
    /// sorties sont INCHANGÉES : file vide -> 200 `acked: 0` AVEC sa ligne de registre (le geste a
    /// bien été exercé), file pleine -> 200 avec le compte.
    ///
    /// CE QU'IL NE TIENT PAS : la console appelle `/alerts/ack-all` sans `try/catch`
    /// (`web/alerts.js`), donc le 503 y remonte comme un rejet non peint.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)` avant un `ledger_append`
    /// inconditionnel. Le registre gagne sa ligne `alert.ack_all 0 alertes` sur une base qui n'a rien
    /// pris, et le 503 redevient un 200.
    #[tokio::test]
    async fn ecf_un_acquittement_en_masse_non_ecrit_n_entre_pas_au_registre() {
        let (st, _tmp) = ecf_etat("ack-all");

        // FILE VIDE — absence ÉTABLIE : sortie INCHANGÉE, et le geste entre au registre comme avant.
        let (statut, vide) = ecf_acquitter_tout(&st).await;
        assert_eq!(statut, 200, "{vide}");
        assert_eq!(vide["acked"], json!(0), "{vide}");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='alert.ack_all'"), 1,
            "le geste a été exercé sur une file vide : la trace le dit, et c'est le contrat d'avant"
        );

        // CONTRÔLE POSITIF — deux alertes actives, acquittées, comptées.
        ecf_poser_une_alerte(&st, "alerte une");
        ecf_poser_une_alerte(&st, "alerte deux");
        let (statut, pose) = ecf_acquitter_tout(&st).await;
        assert_eq!(statut, 200, "{pose}");
        assert_eq!(pose["acked"], json!(2), "{pose}");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM alert WHERE status='new'"), 0);

        // L'ÉCRITURE REFUSÉE — une alerte active de plus, table `alert` non modifiable.
        ecf_poser_une_alerte(&st, "alerte trois");
        ecf_rendre_la_table_non_modifiable(&st, "alert");
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_acquitter_tout(&st).await;
        assert_eq!(statut, 503, "écriture refusée : 503 nommé, jamais « 0 alerte acquittée » : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::cases::CAUSE_ACQUITTEMENT_NON_ENREGISTRE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(
            ecf_lignes_de_registre(&st), registre_avant,
            "et AUCUNE ligne n'entre au registre — l'ancienne forme y posait `alert.ack_all 0 alertes`"
        );
        ecf_rendre_la_table_modifiable(&st, "alert");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM alert WHERE status='new'"), 1,
            "la file est intacte : le 200 à zéro disait le contraire"
        );
    }

    // =================================================================================
    // RANG CINQ (3/5 ET 4/5) — LES LIENS DE DOSSIERS : NI « DÉJÀ LIÉ », NI « AUCUN LIEN ».
    // =================================================================================

    async fn ecf_lier(st: &AppState, de: i64, vers: i64) -> (u16, Value) {
        pb_json(
            case_link_handler(State(st.clone()), Extension(ecf_admin()), Path(de), Json(json!({ "to": vers, "kind": "related" })))
                .await
                .into_response(),
        )
        .await
    }

    async fn ecf_delier(st: &AppState, de: i64, vers: i64) -> (u16, Value) {
        pb_json(
            case_unlink_handler(State(st.clone()), Extension(ecf_admin()), Path((de, vers))).await.into_response(),
        )
        .await
    }

    /// Deux dossiers frais, prêts à être liés.
    fn ecf_deux_dossiers(st: &AppState) -> (i64, i64) {
        let conn = st.db.lock();
        (dossier_seme(&conn, "alice", "A", 3, "", None, 2), dossier_seme(&conn, "alice", "B", 3, "", None, 2))
    }

    /// CE QU'IL TIENT (`case_link_add`) : une pose de lien refusée par la base sortait en 204 « fait »
    /// — le zéro d'`unwrap_or` se lisait « déjà lié (idempotent) » — pendant qu'aucun lien n'existait,
    /// qu'aucune timeline ne portait rien et que le registre n'attestait rien. Elle sort désormais en
    /// 503 nommé, et les deux autres issues sont INCHANGÉES : lien posé ou déjà posé -> 204 ; dossier
    /// absent -> 404 nu.
    ///
    /// CE QU'IL NE TIENT PAS : le 404 reste NU (aucun corps), donc la console ne peut toujours pas
    /// distinguer « dossier absent » de « identifiants égaux » — c'est le contrat d'avant, conservé.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)` dans `case_link_add` — la pose
    /// refusée redevient un 204 « déjà lié », et l'assertion de statut tombe.
    #[tokio::test]
    async fn ecf_une_pose_de_lien_non_ecrite_ne_se_lit_pas_comme_un_doublon() {
        let (st, _tmp) = ecf_etat("lien-pose");
        let (a, b) = ecf_deux_dossiers(&st);

        // CONTRÔLE POSITIF — le lien est posé, puis la seconde pose est idempotente.
        assert_eq!(ecf_lier(&st, a, b).await.0, 204, "le lien se pose");
        assert_eq!(ecf_lier(&st, a, b).await.0, 204, "seconde pose : idempotente, contrat INCHANGÉ");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM case_link"), 1, "dédup : un seul lien");

        // DOSSIER ABSENT — 404 nu, contrat INCHANGÉ.
        assert_eq!(ecf_lier(&st, a, a + 9999).await.0, 404, "dossier absent : 404, comme avant");

        // POSE REFUSÉE — la table des liens est lisible, non modifiable.
        ecf_rendre_la_table_non_modifiable(&st, "case_link");
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_lier(&st, b, a).await;
        assert_eq!(statut, 503, "écriture refusée : 503 nommé, jamais un 204 « déjà lié » : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::caseops::CAUSE_LIEN_NON_POSE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "aucune ligne `case.link` n'atteste un lien inexistant");
        ecf_rendre_la_table_modifiable(&st, "case_link");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM case_link"), 1, "et aucun second lien n'a été posé");
    }

    /// CE QU'IL TIENT (`case_link_remove`) : une suppression de lien refusée par la base sortait en
    /// 404 — « aucun lien ne reliait ces deux dossiers » — sur un lien bien vivant, que le relevé
    /// d'après retrouvait en place. Elle sort désormais en 503 nommé, le registre n'atteste aucune
    /// déliaison, et le lien est RELU en place ; l'absence réelle reste un 404 nu et le retrait réel
    /// un 204.
    ///
    /// CE QU'IL NE TIENT PAS : il ne juge pas le COMPTE de lignes effacées, qui n'est porté que par
    /// la ligne de registre (la route rend un 204 sans corps).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)` dans `case_link_remove` — la
    /// suppression refusée redevient un 404 « aucun lien », indiscernable de l'absence.
    #[tokio::test]
    async fn ecf_un_retrait_de_lien_non_ecrit_ne_se_lit_pas_comme_une_absence_de_lien() {
        let (st, _tmp) = ecf_etat("lien-retrait");
        let (a, b) = ecf_deux_dossiers(&st);
        assert_eq!(ecf_lier(&st, a, b).await.0, 204, "fixture : le lien est posé");

        // SUPPRESSION REFUSÉE — la table est lisible, non modifiable.
        ecf_rendre_la_table_non_modifiable(&st, "case_link");
        let registre_avant = ecf_lignes_de_registre(&st);
        let (statut, avoue) = ecf_delier(&st, a, b).await;
        assert_eq!(statut, 503, "suppression refusée : 503 nommé, jamais un 404 « aucun lien » : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::caseops::CAUSE_LIEN_NON_RETIRE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "et le registre n'atteste aucune déliaison");
        ecf_rendre_la_table_modifiable(&st, "case_link");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM case_link"), 1, "le lien est TOUJOURS là");

        // ABSENCE ÉTABLIE PUIS RETRAIT RÉEL — les deux sorties d'avant, inchangées.
        assert_eq!(ecf_delier(&st, a, a + 9999).await.0, 404, "aucun lien : 404, comme avant");
        assert_eq!(ecf_delier(&st, a, b).await.0, 204, "le lien se retire");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM case_link"), 0);
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='case.unlink'"), 1);
    }

    // =================================================================================
    // RANG CINQ (5/5) — LA POLITIQUE SLA : UNE SUPPRESSION REFUSÉE N'EST PAS UNE ABSENCE.
    // =================================================================================

    async fn ecf_supprimer_la_politique(st: &AppState, id: i64) -> (u16, Value) {
        pb_json(sla_policy_delete(State(st.clone()), Extension(ecf_admin()), Path(id)).await.into_response()).await
    }

    /// CE QU'IL TIENT : une politique SLA que la base refuse de supprimer sortait en 404 — « aucune
    /// politique ne porte cet identifiant » — alors qu'elle GOUVERNE toujours les échéances de sa
    /// priorité. Elle sort désormais en 503 nommé ; l'absence reste un 404 nu et la suppression réelle
    /// un 204, tous deux comptés dans le même corps, registre relu.
    ///
    /// CE QU'IL NE TIENT PAS : il ne juge pas le recalcul d'échéances que `sla_policy_upsert` déclenche
    /// (un autre geste, une autre clé).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or(0)` — la suppression refusée redevient
    /// un 404, et l'assertion qui la sépare de l'absence tombe.
    #[tokio::test]
    async fn ecf_une_politique_sla_non_supprimee_ne_se_lit_pas_comme_une_politique_absente() {
        let (st, _tmp) = ecf_etat("politique-sla");
        {
            let conn = st.db.lock();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
            conn.execute(
                "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) \
                 VALUES('temoin',1,900,3600,1,?1,'analyste',?1)",
                params![now()],
            )
            .unwrap();
        }
        let id: i64 = ecf_compte(&st, "SELECT id FROM sla_policy WHERE name='temoin'");

        // ABSENCE ÉTABLIE — 404 nu, contrat INCHANGÉ, aucune ligne de registre.
        let registre_avant = ecf_lignes_de_registre(&st);
        assert_eq!(ecf_supprimer_la_politique(&st, id + 9999).await.0, 404, "aucune politique : 404, comme avant");
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant);

        // SUPPRESSION REFUSÉE — la table est lisible, non modifiable.
        ecf_rendre_la_table_non_modifiable(&st, "sla_policy");
        let (statut, avoue) = ecf_supprimer_la_politique(&st, id).await;
        assert_eq!(statut, 503, "suppression refusée : 503 nommé, jamais un 404 : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::caseops::CAUSE_POLITIQUE_NON_SUPPRIMEE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(ecf_lignes_de_registre(&st), registre_avant, "et le registre n'atteste aucune suppression");
        ecf_rendre_la_table_modifiable(&st, "sla_policy");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM sla_policy WHERE id=? ".replace('?', &id.to_string()).as_str()), 1,
            "la politique GOUVERNE toujours : le 404 disait qu'elle n'existait pas"
        );

        // CONTRÔLE POSITIF — la même suppression aboutit, et le registre la porte.
        assert_eq!(ecf_supprimer_la_politique(&st, id).await.0, 204, "la politique se supprime");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"), 1);
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM sla_policy"), 0);
    }

    // =================================================================================
    // L'ANNULATION D'UNE RIPOSTE — LE DEUX CENT QUATRE N'EST PLUS INCONDITIONNEL.
    // =================================================================================

    async fn ecf_annuler(st: &AppState, id: i64) -> (u16, Value) {
        pb_json(action_cancel(State(st.clone()), Extension(ecf_admin()), Path(id)).await.into_response()).await
    }

    /// CE QU'IL TIENT : `POST /api/actions/{id}/cancel` rendait 204 quoi qu'il arrive — riposte
    /// inexistante, riposte déjà tranchée, base qui n'a rien pris. La console retirait alors la
    /// riposte de l'écran pendant qu'elle restait `pending`, donc approuvable et exécutable par un
    /// responder. Les trois issues sont séparées : 204 seulement si une ligne a été écrite, 404 si
    /// aucune ne correspondait, 503 nommé si l'écriture a échoué — et le statut est RELU des deux
    /// côtés du refus.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien de ce que `web/detection_admin.js` peint de ces deux
    /// refus (le geste y est enveloppé d'un `catch`, mais la phrase rendue n'est pas jugée ici).
    ///
    /// CE QUE LE CONTRAT PERD, ET C'EST ASSUMÉ : annuler DEUX fois la même riposte rend un 404 là où
    /// le second appel rendait 204. Cette idempotence reposait sur une écriture non comptée — « rien
    /// n'a changé » et « la riposte est annulée » y avaient la même réponse.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute(..)` suivi d'un
    /// `StatusCode::NO_CONTENT` inconditionnel. Les trois assertions de statut tombent d'un coup.
    #[tokio::test]
    async fn ecf_une_annulation_de_riposte_non_ecrite_n_est_pas_un_deux_cent_quatre() {
        let (st, _tmp) = ecf_etat("annulation");
        {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO action(ts,kind,target,status,dry_run) VALUES(?1,'ban_ip','203.0.113.80','pending',1)",
                params![now()],
            )
            .unwrap();
        }
        let id: i64 = ecf_compte(&st, "SELECT id FROM action WHERE target='203.0.113.80'");

        // ABSENCE ÉTABLIE — aucune riposte ne porte cet identifiant.
        let (statut, absente) = ecf_annuler(&st, id + 9999).await;
        assert_eq!(statut, 404, "aucune riposte annulable : 404 nommé : {absente}");
        assert!(ecf_phrase(&absente).starts_with(crate::handlers::actions::CAUSE_RIPOSTE_NON_ANNULABLE), "{absente}");

        // L'ÉCRITURE REFUSÉE — la table est lisible, non modifiable.
        ecf_rendre_la_table_non_modifiable(&st, "action");
        let (statut, avoue) = ecf_annuler(&st, id).await;
        assert_eq!(statut, 503, "écriture refusée : 503 nommé, jamais un 204 muet : {avoue}");
        assert!(
            ecf_phrase(&avoue).starts_with(crate::handlers::actions::CAUSE_ANNULATION_NON_ENREGISTREE),
            "le refus NOMME sa cause : {avoue}"
        );
        ecf_rendre_la_table_modifiable(&st, "action");
        assert_eq!(
            ecf_compte(&st, "SELECT COUNT(*) FROM action WHERE status='pending'"), 1,
            "la riposte est TOUJOURS en file — le 204 d'avant disait qu'elle était annulée"
        );

        // CONTRÔLE POSITIF — l'annulation aboutit, et le statut relu le confirme.
        assert_eq!(ecf_annuler(&st, id).await.0, 204, "la riposte s'annule");
        assert_eq!(ecf_compte(&st, "SELECT COUNT(*) FROM action WHERE status='cancelled'"), 1);

        // ET LE SECOND APPEL DIT MAINTENANT QU'IL N'A RIEN ÉCRIT (contrat changé, assumé).
        assert_eq!(ecf_annuler(&st, id).await.0, 404, "seconde annulation : aucune ligne écrite, et la route le dit");
    }
}
