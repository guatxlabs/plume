// =====================================================================================
// `P10.31-u` — LES LEVÉES DE BAN PAR `netban_remove` DE `actions.rs` (APPROBATION ET RESPONDER)
// CONSOMMENT LEUR ISSUE. Il en existe une troisième, `run_playbooks` (playbooks.rs), hors de ce lot.
//
// LE DÉFAUT, RELU SUR f54efa36 AVANT LE CORRECTIF. `action_approve` (kind `unban_ip`) et le
// responder levaient le miroir HTTP par un `match netban_remove(..)` dont les deux bras
// appelaient `ledger_append` et jetaient le maillon. Dans `action_approve`, le bras `Err` inscrivait
// `netban.remove.echec` au registre puis la route rendait le deux cent quatre muet de la réussite :
// l'adresse restait bloquée (ligne `net_ban` et cache intacts) et l'exploitant lisait « approuvé ».
// Le précédent était dans le même fichier : la pose ratée rend un cinq cent trois nommé, et
// `netban_delete` rend « le ban est TOUJOURS actif ».
//
// CE QUE CES TÉMOINS JOUENT. Un trigger `BEFORE DELETE ON net_ban` fait échouer la levée ; un
// trigger `BEFORE INSERT ON ledger` filtré par genre refuse le seul maillon visé (la ligne
// `action.approved`, posée avant, passe). Chaque témoin porte son contrôle positif.
//
// CE QU'ILS NE TIENNENT PAS : la console (`web/detection_admin.js`) ne reconnaît pas la phrase du
// cinq cent trois neuf parmi les refus nommés de l'approbation, et ignore le corps d'un succès
// (l'aveu `registre_sans_maillon` d'une levée faite n'atteint pas l'écran) ; `respond_run` n'est pas
// exécuté (il ouvre la base de la configuration et lance des commandes) : son miroir HTTP —
// garde englobante, condition de pose, branche de levée, aveu — est déplacé dans
// `miroir_http_du_responder`, que `lbi_le_miroir_du_responder_execute_garde_pose_et_levee` EXÉCUTE ;
// seul l'appel est relu dans le source (exigé une fois, mot pour mot, commentaires retirés ; un
// commentaire en fin de ligne de code sur cet appel le ferait rougir à tort) ; le rejeu de la levée refusée par approbation ne tient ni à l'écran (bouton Approuver
// réservé aux ripostes `pending`, web/detection_admin.js) ni par l'API une fois la riposte close par
// l'agent ou le responder (204 muet, rien de levé) : la phrase du cinq cent trois ne nomme donc que
// `DELETE /api/netban/{ip}` ; la relecture garde les littéraux tels quels (blancs compris) ; les causes sœurs (BAN NON ARMÉ, APPROBATION SANS TRACE) gardent
// l'ancienne promesse « approuver de nouveau », hors de ce lot ; les lignes `net_ban` indécodables
// que `netban_remove` saute par `.flatten()` (auth.rs) restent hors de ce lot.
// RESTES RELEVÉS PAR LA VÉRIFICATION, HORS DU PÉRIMÈTRE DE FICHIERS DE CE LOT :
// - la levée de `run_playbooks` (playbooks.rs:650-654) consomme son maillon, mais une levée RATÉE
//   dont l'échec est bien au registre compte 0 abandon au bilan du tick (une pose ratée compte 1,
//   playbooks.rs:641-643) : le ban reste actif et la surface d'état publie « 0 abandon » ;
// - `netban_remove` est désormais appelé depuis `lever_le_miroir_http`, absent du vocabulaire de
//   `check_a_swallowed_write_is_never_affirmed_as_a_fact.py` (l. 284-294) : une écriture avalée
//   future dans `action_approve` ou `respond_run` AVANT la levée échapperait à la garde (angle mort
//   de la fonction intermédiaire, déjà déclaré par la garde ; aucun site nommé n'est perdu).
//
// MUTATIONS JOUÉES (variable `VERIF_MUT` sous `cfg!(test)`, retirées du source avant le commit) :
// `lbi_err_avale` (le bras `NonLevee` rend 204), `lbi_maillon_jete` (le bras `LeveeSansTrace` rend
// 204), `lbi_503_sur_ok` (le bras `Levee` rend 503), `lbi_fabricant_maillon_jete` (le fabricant rend
// `Levee` quel que soit le maillon), `lbi_responder_muet` (l'aveu du responder rend toujours `None`).
// REPRISE après vérification : `lbi_zero_ligne_refuse` (le fabricant rend `NonLevee` sur `Ok(0)`),
// `lbi_aveu_trace_tue` (l'aveu du responder tait la trace manquante d'un échec), `lbi_eprintln_tue`
// (l'`eprintln!` de l'aveu retiré du corps de `respond_run`, l'appel conservé — joué sur le texte lu).
// SECONDE REPRISE : `lbi_emission_sous_condition` (le `if let` de l'aveu entouré d'un
// `if std::env::var("PLUME_RESPONDER_VERBOSE").is_ok()` — vert sous l'ancienne relecture à deux
// sous-chaînes, joué sur le texte lu), `lbi_ancrage_retire` (l'ancienne relecture rétablie : ses
// contrôles négatifs en mémoire rougissent), `lbi_phrase_ancienne` (le cinq cent trois rend l'ancienne
// phrase « l'approuver de nouveau rejoue la levée »).
// TROISIÈME REPRISE : mutants texte `T5` (`kind == "unban_ip "` dans la branche de `respond_run` :
// branche morte) et `T4` (`"auto:responder unban_ip"`), joués sur une copie du source lue par le
// témoin ; `lbi_blancs_partout` (l'ancienne relecture qui retirait aussi les blancs des littéraux :
// ses contrôles négatifs en mémoire rougissent) ; `lbi_phrase_ancienne` (le cinq cent trois promet de
// nouveau le rejeu par `POST /api/actions/{id}/approve`).
// QUATRIÈME REPRISE (crochets `VERIF_MUT` posés dans `actions.rs`, compilés une fois, retirés avant
// le commit ; chacun reproduit l'effet du mutant texte) : `T1` (blanc dans le `"unban_ip"` de la garde
// englobante : la levée ne passe plus la garde), `T3` (`status == "failed"` dans la garde), `T3b`
// (statut ignoré), `T4` (la levée routée dans la branche de pose : le responder re-bannit), `L8` (le
// `detail` de `netban.remove.echec` perd `({origine})`).
// CINQUIÈME REPRISE (même procédé) : `M10` (`else if kind == "unban_ip"` devenu `else` dans le miroir
// du responder : une pose `done` sur adresse protégée écrivait une ligne `netban.remove` fabriquée),
// `A8` (le cinq cent trois de la levée perd `({erreur})`), `L9` (la cause portée par `LeveeSansTrace`
// vidée), `M13` (la pose `done` du responder sans échéance : ban permanent), `M14` (le bras
// `NonEcrit` de cette pose muet), `MP` (le bras du plafond muet).
// SIXIÈME REPRISE (même procédé ; les cinq crochets posés dans `actions.rs` et celui d'`I1` dans ce
// fichier, retirés avant le commit) : `C1` (le cinq cent trois sert une phrase qui garde `DELETE` et
// promet en mots le rejeu par approbation — tenu par `LBI_PHRASE_DU_503`, littéral recopié), `R8`
// (l'aveu du responder perd `({erreur})`), `R9` (« non plus () »), `A10` et `M20` (la levée reçoit la
// cible brute au lieu de la forme canonique : `detail` en `::ffff:…`), `I1` (la recherche de levée en
// ligne retirée de la relecture : ses variantes sont désormais posées en tête de boucle).
// =====================================================================================
mod levee_de_ban_issue_consommee {
    use super::*;

    fn lbi_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("lbi-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM net_ban", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn lbi_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn lbi_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn lbi_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn lbi_genre(st: &AppState, genre: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le compte par genre se lit")
    }

    fn lbi_statut(st: &AppState, id: i64) -> String {
        st.db
            .lock()
            .query_row("SELECT status FROM action WHERE id=?1", params![id], |r| r.get(0))
            .expect("fixture : le statut se lit")
    }

    fn lbi_detail(st: &AppState, genre: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut stmt = conn.prepare("SELECT detail FROM ledger WHERE kind=?1 ORDER BY id").expect("fixture : la lecture se prépare");
        let lus = stmt.query_map(params![genre], |r| r.get::<_, String>(0)).expect("fixture : les details se lisent");
        lus.collect::<Result<Vec<_>, _>>().expect("fixture : chaque detail se décode")
    }

    fn lbi_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    /// Un ban actif, présent dans la table ET dans le cache in-process.
    fn lbi_ban_actif(st: &AppState, ip: &str) {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(?1,'temoin',1000,NULL,'analyste','prod')",
            params![ip],
        )
        .expect("fixture : le ban s'insère");
        netban_reload(&conn);
        assert!(net_ban_is_blocked(ip, now()), "fixture : le ban est actif dans le cache");
    }

    fn lbi_riposte(st: &AppState, kind: &str, target: &str) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1000,?1,?2,'pending',0,'')",
            params![kind, target],
        )
        .expect("fixture : la riposte s'insère");
        conn.last_insert_rowid()
    }

    /// LA PHRASE DU 503, RECOPIÉE MOT POUR MOT — et non lue dans `CAUSE_LEVEE_NON_FAITE`. Les
    /// témoins comparent la réponse SERVIE à ce littéral : une phrase qui garde `DELETE` mais promet
    /// en mots le rejeu par approbation (« ou en approuvant de nouveau la riposte, qui rejoue la
    /// levée ») rompt l'égalité, ce que deux sous-chaînes ne voyaient pas. Changer la phrase oblige à
    /// changer ce littéral, donc à relire sa promesse. MUTATION : `C1`.
    const LBI_PHRASE_DU_503: &str = "LEVÉE IMPOSSIBLE : la ligne du blocage HTTP n'a pas pu être retirée, donc le ban est TOUJOURS actif. La levée se fait directement par DELETE /api/netban/{ip} (approuver de nouveau la riposte ne la rejoue pas une fois la riposte exécutée).";

    const LBI_LEVEE_REFUSEE: &str = "CREATE TRIGGER lbi_levee_refusee BEFORE DELETE ON net_ban \
        BEGIN SELECT RAISE(ABORT, 'levee refusee par le temoin'); END;";

    fn lbi_maillon_refuse(genre: &str) -> String {
        format!(
            "CREATE TRIGGER lbi_maillon_refuse BEFORE INSERT ON ledger WHEN NEW.kind='{genre}' \
             BEGIN SELECT RAISE(ABORT, 'maillon refuse par le temoin'); END;"
        )
    }

    /// CE QU'IL TIENT : une levée que la base refuse rend un 503 nommé (`CAUSE_LEVEE_NON_FAITE`),
    /// la ligne `net_ban` et le cache bloquent toujours, la riposte reste `approved`, l'échec est au
    /// registre ; la base réparée, la MÊME approbation rejouée rend 204 et lève le ban.
    /// MUTATIONS : `lbi_err_avale` (204 sur l'échec), `lbi_503_sur_ok` (503 au rejeu), `A8` (la cause
/// `({erreur})` retirée de la phrase).
    #[tokio::test]
    async fn lbi_une_levee_refusee_rend_503_le_ban_reste_actif_et_le_geste_se_rejoue() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("levee-refusee");
        let ip = "203.0.113.61";
        lbi_ban_actif(&st, ip);
        let id = lbi_riposte(&st, "unban_ip", ip);
        lbi_ecrire(&st, LBI_LEVEE_REFUSEE);

        let (code, corps) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await).await;
        assert_eq!(code, 503, "levée refusée : la route REFUSE au lieu du 204 de la réussite : {corps}");
        assert!(lbi_phrase(&corps).starts_with(LBI_PHRASE_DU_503), "le refus nomme sa cause, mot pour mot : {corps}");
        assert_eq!(CAUSE_LEVEE_NON_FAITE, LBI_PHRASE_DU_503, "la constante est la phrase relue (MUTATION `C1`)");
        // La cause portée — l'erreur de la base — suit la phrase, et rien d'autre. MUTATIONS : `A8`, `C1`.
        assert_eq!(
            lbi_phrase(&corps),
            format!("{LBI_PHRASE_DU_503} (levee refusee par le temoin)"),
            "le refus porte l'erreur de la base : {corps}"
        );
        // Le geste annoncé est celui qui tient quel que soit le sort de la riposte : la levée
        // directe. Le rejeu par approbation n'est pas promis (il rend un 204 muet une fois la riposte
        // close, cf. `lbi_apres_cloture_seule_la_levee_directe_tient`). MUTATION : `lbi_phrase_ancienne`.
        assert!(lbi_phrase(&corps).contains("DELETE /api/netban/{ip}"), "le refus nomme la levée directe : {corps}");
        assert!(!lbi_phrase(&corps).contains("/approve"), "le refus ne promet pas un rejeu par approbation : {corps}");
        assert!(!lbi_phrase(&corps).contains("PAS au registre"), "l'échec, lui, est au registre : {corps}");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.61'"), 1, "la ligne du ban est intacte");
        assert!(net_ban_is_blocked(ip, now()), "et le cache bloque TOUJOURS l'adresse");
        assert_eq!(lbi_statut(&st, id), "approved", "la riposte reste approuvée : le geste est rejouable");
        assert_eq!(lbi_genre(&st, "netban.remove.echec"), 1, "l'échec est inscrit au registre");
        // Le `detail` de l'échec nomme son chemin (`origine`) : approbation, pas responder. MUTATION : `L8`.
        assert_eq!(
            lbi_detail(&st, "netban.remove.echec"),
            vec!["203.0.113.61 NON levé (auto: action unban_ip) : levee refusee par le temoin".to_string()],
            "le detail de l'échec est celui d'avant, origine comprise"
        );
        assert_eq!(lbi_genre(&st, "netban.remove"), 0, "aucune levée n'est attestée");

        // CONTRÔLE POSITIF — la base réparée, la même approbation relève la levée.
        lbi_ecrire(&st, "DROP TRIGGER lbi_levee_refusee;");
        let (code, rejoue) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await).await;
        assert_eq!(code, 204, "le refus n'est pas inconditionnel : {rejoue}");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban"), 0, "la ligne du ban est retirée");
        assert!(!net_ban_is_blocked(ip, now()), "et le cache ne bloque plus l'adresse");
        assert_eq!(lbi_genre(&st, "netban.remove"), 1, "la levée est attestée au registre");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : la levée refusée, puis la riposte CLOSE (`done`, ce qu'écrivent l'agent et le
    /// responder local qui réclament les ripostes sans hôte), une nouvelle approbation rend le 204
    /// muet et NE lève RIEN — c'est pourquoi la phrase du 503 ne la promet pas ; le geste qu'elle
    /// nomme, `DELETE /api/netban/{ip}`, lève bien le ban (table et cache).
    /// MUTATION : `lbi_phrase_ancienne` (le 503 promet de nouveau le rejeu par approbation).
    #[tokio::test]
    async fn lbi_apres_cloture_seule_la_levee_directe_tient() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("apres-cloture");
        let ip = "203.0.113.68";
        lbi_ban_actif(&st, ip);
        let id = lbi_riposte(&st, "unban_ip", ip);
        lbi_ecrire(&st, LBI_LEVEE_REFUSEE);

        let (code, corps) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await).await;
        assert_eq!(code, 503, "fixture : la levée est refusée : {corps}");
        let phrase = lbi_phrase(&corps);
        assert!(!phrase.contains("/approve"), "le 503 ne promet pas le rejeu par approbation : {corps}");
        assert!(phrase.contains("DELETE /api/netban/{ip}"), "le 503 nomme la levée directe : {corps}");
        // La phrase servie est le littéral relu, mot pour mot. MUTATION : `C1`.
        assert_eq!(phrase, format!("{LBI_PHRASE_DU_503} (levee refusee par le temoin)"), "{corps}");

        // La riposte close par un exécuteur, la base réparée : le rejeu par approbation ne lève rien.
        lbi_ecrire(&st, &format!("UPDATE action SET status='done' WHERE id={id}; DROP TRIGGER lbi_levee_refusee;"));
        let r = action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await;
        assert_eq!(r.status().as_u16(), 204, "le rejeu sur une riposte close rend le 204 muet");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.68'"), 1, "et la ligne du ban est intacte");
        assert!(net_ban_is_blocked(ip, now()), "et le cache bloque TOUJOURS l'adresse : ce rejeu ne tient pas");

        // Le geste nommé par la phrase, lui, lève.
        let (code, leve) = pb_json(netban_delete(State(st.clone()), Extension(lbi_au()), Path(ip.to_string())).await).await;
        assert_eq!(code, 200, "{leve}");
        assert_eq!(leve.get("retires"), Some(&json!(1)), "la levée directe retire la ligne : {leve}");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban"), 0, "la ligne du ban est retirée");
        assert!(!net_ban_is_blocked(ip, now()), "et le cache ne bloque plus l'adresse");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : quand l'échec de la levée n'entre pas non plus au registre, le 503 le dit.
    #[tokio::test]
    async fn lbi_une_levee_refusee_dont_l_echec_n_entre_pas_au_registre_le_dit() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("echec-sans-trace");
        let ip = "203.0.113.62";
        lbi_ban_actif(&st, ip);
        let id = lbi_riposte(&st, "unban_ip", ip);
        lbi_ecrire(&st, LBI_LEVEE_REFUSEE);
        lbi_ecrire(&st, &lbi_maillon_refuse("netban.remove.echec"));

        let (code, corps) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await).await;
        assert_eq!(code, 503, "{corps}");
        assert!(lbi_phrase(&corps).starts_with(LBI_PHRASE_DU_503), "{corps}");
        assert!(lbi_phrase(&corps).contains("PAS au registre non plus"), "la trace manquante de l'échec est dite : {corps}");
        // Les deux causes sont portées : l'erreur de la levée, puis celle du maillon. MUTATION : `A8`.
        // INVERSÉ NOMMÉMENT par `P10.29-l` (vague AM) : la cause du maillon est la phrase fixe, plus le texte du moteur.
        assert_eq!(
            lbi_phrase(&corps),
            format!(
                "{LBI_PHRASE_DU_503} (levee refusee par le temoin) ; cet échec n'est PAS au registre non plus ({CAUSE_MAILLON_NON_ECRIT})"
            ),
            "{corps}"
        );
        assert_eq!(lbi_genre(&st, "netban.remove.echec"), 0, "fixture : le maillon d'échec a bien été refusé");
        assert!(net_ban_is_blocked(ip, now()), "le ban reste actif");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : une levée FAITE dont le maillon `netban.remove` n'entre pas rend un succès qui
    /// porte l'aveu `registre_sans_maillon`, jamais un 204 muet ; le ban est bien levé.
    /// MUTATIONS : `lbi_maillon_jete`, `lbi_fabricant_maillon_jete`, `L9` (la cause portée par
    /// `LeveeSansTrace` vidée).
    #[tokio::test]
    async fn lbi_une_levee_faite_dont_le_maillon_manque_le_dit_a_cote_du_succes() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("levee-sans-trace");
        let ip = "203.0.113.63";
        lbi_ban_actif(&st, ip);
        let id = lbi_riposte(&st, "unban_ip", ip);
        lbi_ecrire(&st, &lbi_maillon_refuse("netban.remove"));

        let (code, corps) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await).await;
        assert_eq!(code, 200, "levée faite, trace manquante : un succès qui PARLE, pas un 204 muet : {corps}");
        assert_eq!(corps.get("ok"), Some(&json!(true)), "{corps}");
        let aveu = corps.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).unwrap_or("");
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu nomme la trace manquante : {corps}");
        // La cause du maillon refusé est portée par `LeveeSansTrace` jusqu'à la réponse. MUTATION : `L9`.
        // INVERSÉ NOMMÉMENT par `P10.29-l` (vague AM) : la cause portée est la phrase fixe du maillon non écrit.
        assert_eq!(aveu, format!("{CAUSE_GESTE_SANS_TRACE} ({CAUSE_MAILLON_NON_ECRIT})"), "{corps}");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban"), 0, "le ban est levé");
        assert!(!net_ban_is_blocked(ip, now()), "et le cache ne bloque plus");
        assert_eq!(lbi_genre(&st, "netban.remove"), 0, "fixture : le maillon a bien été refusé");
        assert_eq!(lbi_genre(&st, "action.approved"), 1, "le maillon d'approbation, lui, est entré");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : le chemin nominal est inchangé — levée 204 sans corps, `detail` du registre
    /// mot pour mot celui d'avant ; la pose `ban_ip` rend toujours 204 et arme.
    /// MUTATION : `lbi_503_sur_ok`.
    #[tokio::test]
    async fn lbi_le_chemin_nominal_reste_un_204_et_la_pose_est_inchangee() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin pose un ban
        let (st, _tmp) = lbi_etat("nominal");
        let ip = "203.0.113.64";
        lbi_ban_actif(&st, ip);
        let id = lbi_riposte(&st, "unban_ip", ip);
        let r = action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await;
        assert_eq!(r.status().as_u16(), 204);
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert!(octets.is_empty(), "204 sans corps, octet pour octet");
        let detail: String = st
            .db
            .lock()
            .query_row("SELECT detail FROM ledger WHERE kind='netban.remove'", [], |r| r.get(0))
            .expect("la levée est au registre");
        assert_eq!(detail, "203.0.113.64 retirés=1 (auto: action unban_ip)", "le detail est celui d'avant");
        assert!(!net_ban_is_blocked(ip, now()));

        let pose = lbi_riposte(&st, "ban_ip", "203.0.113.65");
        let (code, corps) = pb_json(action_approve(State(st.clone()), Extension(lbi_au()), Path(pose)).await).await;
        assert_eq!(code, 204, "la pose est inchangée : {corps}");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.65'"), 1, "et elle arme");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : une riposte `unban_ip` dont la cible est écrite sous la forme MAPPÉE
    /// (`::ffff:a.b.c.d`, que `cible_de_levee_acceptee` laisse passer) lève par la forme CANONIQUE —
    /// c'est elle que porte le `detail` de `netban.remove`, par l'approbation comme par le responder.
    /// Le retrait seul ne le distingue pas (`netban_remove` canonise aussi) : le registre, si.
    /// MUTATIONS : `A10` (l'approbation passe la cible brute), `M20` (le responder aussi).
    #[tokio::test]
    async fn lbi_une_levee_sur_forme_mappee_inscrit_la_forme_canonique() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("forme-mappee");

        // Par l'approbation.
        lbi_ban_actif(&st, "203.0.113.81");
        let id = lbi_riposte(&st, "unban_ip", "::ffff:203.0.113.81");
        let r = action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await;
        assert_eq!(r.status().as_u16(), 204, "la levée par forme mappée est nominale");
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.81'"), 0, "la ligne canonique est retirée");
        assert!(!net_ban_is_blocked("203.0.113.81", now()), "et le cache ne bloque plus");
        assert_eq!(
            lbi_detail(&st, "netban.remove"),
            vec!["203.0.113.81 retirés=1 (auto: action unban_ip)".to_string()],
            "le registre porte la forme canonique, pas la saisie mappée (MUTATION `A10`)"
        );

        // Par le miroir du responder.
        lbi_ban_actif(&st, "203.0.113.82");
        assert_eq!(miroir_http_du_responder(&st.db.lock(), 9, "unban_ip", "::ffff:203.0.113.82", "done", false), None);
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.82'"), 0, "la ligne canonique est retirée");
        assert!(!net_ban_is_blocked("203.0.113.82", now()), "et le cache ne bloque plus");
        assert_eq!(
            lbi_detail(&st, "netban.remove"),
            vec![
                "203.0.113.81 retirés=1 (auto: action unban_ip)".to_string(),
                "203.0.113.82 retirés=1 (auto: responder unban_ip)".to_string()
            ],
            "le registre porte la forme canonique, pas la saisie mappée (MUTATION `M20`)"
        );
        netban_cache().write().clear();
    }

    /// Retire les blancs HORS des littéraux seulement : un littéral de chaîne (`"…"`, échappements
    /// compris) et un littéral de caractère (`'x'`, `'\x'`) sont recopiés octet pour octet. Un blanc
    /// ajouté, retiré ou changé DANS un littéral rompt donc le motif. Ne tient pas : aucune variante de la
    /// liste ne met un blanc DANS un littéral, la mutation `lbi_blancs_partout` (l'ancienne forme, qui
    /// retirait aussi les blancs des littéraux) resterait verte.
    fn lbi_serrer_hors_litteraux(texte: &str) -> String {
        let c: Vec<char> = texte.chars().collect();
        let mut serre = String::with_capacity(c.len());
        let mut i = 0;
        while i < c.len() {
            match c[i] {
                '"' => {
                    serre.push('"');
                    i += 1;
                    while i < c.len() {
                        serre.push(c[i]);
                        if c[i] == '\\' && i + 1 < c.len() {
                            serre.push(c[i + 1]);
                            i += 2;
                            continue;
                        }
                        i += 1;
                        if c[i - 1] == '"' {
                            break;
                        }
                    }
                }
                '\'' if i + 2 < c.len() && c[i + 1] != '\\' && c[i + 2] == '\'' => {
                    serre.extend(&c[i..i + 3]);
                    i += 3;
                }
                '\'' if i + 3 < c.len() && c[i + 1] == '\\' && c[i + 3] == '\'' => {
                    serre.extend(&c[i..i + 4]);
                    i += 4;
                }
                x if x.is_whitespace() => i += 1,
                x => {
                    serre.push(x);
                    i += 1;
                }
            }
        }
        serre
    }

    /// L'APPEL DU MIROIR PAR LE RESPONDER, RELU SUR LE TEXTE SANS COMMENTAIRES, BLANCS RETIRÉS HORS
    /// DES LITTÉRAUX. Le miroir lui-même (garde, pose, levée, aveu) est EXÉCUTÉ par
    /// `lbi_le_miroir_du_responder_execute_garde_pose_et_levee` ; reste à tenir que `respond_run`
    /// l'appelle UNE fois, avec ses propres `id`, `kind`, `target`, `status` et `dry`, et émet l'aveu
    /// rendu sans condition. Un argument figé (`"done"`, `false`), un appel placé ou une émission
    /// placée sous une condition, une instruction intercalée, un aveu jeté rompent le motif ; un commentaire ajouté ne le rompt pas. Aucune levée en
    /// ligne dans `respond_run` (ni `netban_remove`, ni `lever_le_miroir_http`).
    fn lbi_cablage_du_responder(corps: &str) -> Result<(), String> {
        let sans_commentaires: String =
            corps.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        let serre = lbi_serrer_hors_litteraux(&sans_commentaires);
        // Ancré des deux côtés : il suit IMMÉDIATEMENT l'aveu du maillon `action.exec` (rien ne
        // s'intercale, rien ne l'entoure) et il est la dernière instruction de la boucle, qui ferme
        // le corps (`}}`).
        const BRANCHE: &str = concat!(
            "eprintln!(\"[responder] WARN action {id} exécutée : le registre n'a PAS pris son verdict ({cause})\");}",
            "ifletSome(aveu)=miroir_http_du_responder(&conn,id,&kind,&target,status,dry){",
            "eprintln!(\"{aveu}\");",
            "}}}"
        );
        // Le motif passe par le même serrage que le texte (il n'a aucun blanc hors littéraux : il en
        // ressort identique). La mutation `lbi_blancs_partout` n'est plus tuée ici : depuis l'extraction
        // de `miroir_http_du_responder`, aucune variante n'a de blanc dans un littéral.
        let branche = lbi_serrer_hors_litteraux(BRANCHE);
        match serre.matches(branche.as_str()).count() {
            1 => {}
            n => return Err(format!("câblage du responder : appel du miroir trouvé {n} fois (attendu 1) : {BRANCHE}")),
        }
        if serre.contains("netban_remove(") || serre.contains("lever_le_miroir_http(") {
            return Err("câblage du responder : une levée en ligne hors du miroir exécuté par le témoin".into());
        }
        Ok(())
    }

    /// CE QU'IL TIENT : une riposte `unban_ip` sur une adresse ABSENTE de `net_ban` (ban posé côté
    /// CrowdSec seulement, ou TTL de 4 h expiré) — `Ok(0)` — reste le 204 nominal sans corps, avec
    /// `retirés=0` au registre ; le fabricant rend `Levee` et le responder n'avoue rien.
    /// MUTATION : `lbi_zero_ligne_refuse` (le fabricant rend `NonLevee` sur `Ok(0)`).
    #[tokio::test]
    async fn lbi_une_levee_sans_ligne_a_retirer_reste_un_204_nominal() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("zero-ligne");
        let ip = "203.0.113.67";
        assert_eq!(lbi_compte(&st, "SELECT COUNT(*) FROM net_ban"), 0, "fixture : aucun ban à lever");
        let id = lbi_riposte(&st, "unban_ip", ip);

        let r = action_approve(State(st.clone()), Extension(lbi_au()), Path(id)).await;
        assert_eq!(r.status().as_u16(), 204, "zéro ligne retirée n'est pas une levée ratée");
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert!(octets.is_empty(), "204 sans corps : {}", String::from_utf8_lossy(&octets));
        assert_eq!(lbi_statut(&st, id), "approved");
        assert_eq!(lbi_genre(&st, "netban.remove.echec"), 0, "aucun échec inscrit");
        assert_eq!(
            lbi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='netban.remove' AND detail='203.0.113.67 retirés=0 (auto: action unban_ip)'"),
            1,
            "le compte nul de la levée est DIT au registre"
        );

        // Le même cas par le fabricant du responder.
        let issue = lever_le_miroir_http(&st.db.lock(), ip, "auto: responder unban_ip");
        assert!(matches!(issue, LeveeDuMiroirHttp::Levee), "{issue:?}");
        assert_eq!(aveu_du_responder_sur_la_levee(8, &issue), None, "rien à avouer sur zéro ligne");
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : l'aveu du responder sur sa levée — échec et trace manquante nommés avec
    /// l'identifiant de l'action, JAMAIS l'adresse ; rien sur le chemin nominal ; et `respond_run`
    /// passe bien par cet aveu (relu dans le source : plus aucun `match netban_remove` dans son corps).
    /// MUTATIONS : `lbi_responder_muet`, `lbi_fabricant_maillon_jete`, `lbi_aveu_trace_tue`,
    /// `lbi_eprintln_tue`.
    #[test]
    fn lbi_le_responder_avoue_sa_levee_sans_nommer_l_adresse() {
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("responder");
        let ip = "203.0.113.66";

        // (a) échec de la levée.
        lbi_ban_actif(&st, ip);
        lbi_ecrire(&st, LBI_LEVEE_REFUSEE);
        let issue = lever_le_miroir_http(&st.db.lock(), ip, "auto: responder unban_ip");
        assert!(matches!(issue, LeveeDuMiroirHttp::NonLevee { trace_manquante: None, .. }), "{issue:?}");
        let aveu = aveu_du_responder_sur_la_levee(7, &issue).expect("un échec de levée est avoué");
        assert!(aveu.contains("action 7") && aveu.contains("TOUJOURS actif"), "{aveu}");
        // L'aveu porte la cause de l'échec : quand l'échec manque aussi au registre, c'est le seul
        // endroit où elle survit. MUTATION : `R8` (l'aveu perd `({erreur})`).
        assert_eq!(
            aveu,
            "[responder] WARN action 7 : miroir HTTP NON levé, le ban HTTP est TOUJOURS actif (levee refusee par le temoin)",
            "l'aveu de l'échec porte sa cause"
        );
        assert!(!aveu.contains(ip), "l'aveu ne nomme pas l'adresse : {aveu}");
        assert!(net_ban_is_blocked(ip, now()), "le ban reste actif");
        // MUTATION : `L8` (le detail perd l'origine : le registre ne dit plus quel chemin a échoué).
        assert_eq!(
            lbi_detail(&st, "netban.remove.echec"),
            vec!["203.0.113.66 NON levé (auto: responder unban_ip) : levee refusee par le temoin".to_string()],
            "le detail de l'échec nomme le responder"
        );

        // (a') échec de la levée ET de son maillon : l'aveu dit que l'échec n'est pas au registre.
        // MUTATION : `lbi_aveu_trace_tue`.
        lbi_ecrire(&st, &lbi_maillon_refuse("netban.remove.echec"));
        let issue = lever_le_miroir_http(&st.db.lock(), ip, "auto: responder unban_ip");
        assert!(matches!(issue, LeveeDuMiroirHttp::NonLevee { trace_manquante: Some(_), .. }), "{issue:?}");
        let aveu = aveu_du_responder_sur_la_levee(7, &issue).expect("un échec sans trace est avoué");
        assert!(aveu.contains("TOUJOURS actif"), "{aveu}");
        assert!(aveu.contains("cet échec n'est PAS au registre non plus ("), "la trace manquante de l'échec est dite : {aveu}");
        // Les deux causes, celle de la levée puis celle du maillon refusé. MUTATIONS : `R8`, `R9`
        // (« non plus () » : la cause de la trace manquante vidée).
        // INVERSÉ NOMMÉMENT par `P10.29-l` (vague AM) : la cause du maillon est la phrase fixe, plus le texte du moteur.
        assert_eq!(
            aveu,
            format!("[responder] WARN action 7 : miroir HTTP NON levé, le ban HTTP est TOUJOURS actif (levee refusee par le temoin) ; cet échec n'est PAS au registre non plus ({CAUSE_MAILLON_NON_ECRIT})"),
            "l'aveu porte les deux causes"
        );
        assert!(!aveu.contains(ip), "{aveu}");
        assert_eq!(lbi_genre(&st, "netban.remove.echec"), 1, "fixture : seul l'échec de (a) est entré");
        lbi_ecrire(&st, "DROP TRIGGER lbi_maillon_refuse;");
        lbi_ecrire(&st, "DROP TRIGGER lbi_levee_refusee;");

        // (b) levée faite, maillon refusé.
        lbi_ecrire(&st, &lbi_maillon_refuse("netban.remove"));
        let issue = lever_le_miroir_http(&st.db.lock(), ip, "auto: responder unban_ip");
        // INVERSÉ NOMMÉMENT par `P10.29-l` (vague AM) : la cause portée est la phrase fixe du maillon non écrit.
        assert!(matches!(&issue, LeveeDuMiroirHttp::LeveeSansTrace(c) if c == CAUSE_MAILLON_NON_ECRIT), "la cause est portée (MUTATION `L9`) : {issue:?}");
        let aveu = aveu_du_responder_sur_la_levee(7, &issue).expect("une trace manquante est avouée");
        assert!(aveu.contains("action 7") && aveu.contains("PAS pris la levée"), "{aveu}");
        assert!(aveu.ends_with(&format!("PAS pris la levée ({CAUSE_MAILLON_NON_ECRIT})")), "l'aveu porte la cause : {aveu}");
        assert!(!aveu.contains(ip), "{aveu}");
        assert!(!net_ban_is_blocked(ip, now()), "le ban est levé");
        lbi_ecrire(&st, "DROP TRIGGER lbi_maillon_refuse;");

        // (c) nominal : aucun aveu, detail d'avant.
        lbi_ban_actif(&st, ip);
        let issue = lever_le_miroir_http(&st.db.lock(), ip, "auto: responder unban_ip");
        assert!(matches!(issue, LeveeDuMiroirHttp::Levee), "{issue:?}");
        assert_eq!(aveu_du_responder_sur_la_levee(7, &issue), None);
        assert_eq!(
            lbi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE kind='netban.remove' AND detail='203.0.113.66 retirés=1 (auto: responder unban_ip)'"),
            1
        );

        // (d) le câblage du responder.
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/actions.rs"),
        )
        .unwrap();
        let debut = src.find("pub(crate) fn respond_run() {").expect("le responder local existe");
        let fin = src[debut..].find("\n}\n").map(|x| debut + x + 3).unwrap_or(src.len());
        let corps = &src[debut..fin];
        lbi_cablage_du_responder(corps).unwrap_or_else(|e| panic!("{e}"));
        // CONTRÔLES NÉGATIFS — la relecture rougit quand l'aveu est rendu puis jeté sans être émis,
        // quand l'émission passe sous une condition (le `if let` entouré, ou l'`eprintln!` seul),
        // quand un argument est figé (le statut ou le dry-run lus ne décident plus), et quand une
        // levée en ligne réapparaît dans le corps.
        let emission = "if let Some(aveu) = miroir_http_du_responder(&conn, id, &kind, &target, status, dry) {\n            eprintln!(\"{aveu}\");\n        }";
        assert!(corps.contains(emission), "fixture : l'émission de l'aveu est bien dans le corps du responder");
        const TETE_DE_BOUCLE: &str = "    for (id, kind, target, dry) in pending {";
        assert_eq!(corps.matches(TETE_DE_BOUCLE).count(), 1, "fixture : la tête de la boucle du responder est unique");
        let variantes = [
            ("aveu jeté", corps.replacen("eprintln!(\"{aveu}\");", "", 1)),
            (
                "le `if let` sous un réglage d'environnement",
                corps.replacen(emission, &format!("if std::env::var(\"PLUME_RESPONDER_VERBOSE\").is_ok() {{ {emission} }}"), 1),
            ),
            (
                "l'`eprintln!` seul sous une condition",
                corps.replacen("eprintln!(\"{aveu}\");", "if std::env::var(\"PLUME_RESPONDER_VERBOSE\").is_ok() { eprintln!(\"{aveu}\"); }", 1),
            ),
            ("le statut figé à `done`", corps.replacen("&target, status, dry)", "&target, \"done\", dry)", 1)),
            ("le dry-run figé à `false`", corps.replacen("&target, status, dry)", "&target, status, false)", 1)),
            // Posées en TÊTE de boucle, loin de l'ancre : c'est la recherche de `netban_remove(` /
            // `lever_le_miroir_http(` qui les refuse, pas le motif. MUTATION : `I1` (recherche retirée).
            (
                "une levée en ligne (fabricant) en tête de boucle",
                corps.replacen(
                    TETE_DE_BOUCLE,
                    &format!("{TETE_DE_BOUCLE}\n        let _ = lever_le_miroir_http(&conn, &target, \"auto: responder unban_ip\");"),
                    1,
                ),
            ),
            (
                "une levée en ligne (`netban_remove`) en tête de boucle",
                corps.replacen(TETE_DE_BOUCLE, &format!("{TETE_DE_BOUCLE}\n        let _ = netban_remove(&conn, &target);"), 1),
            ),
            ("l'appel en double", corps.replacen(emission, &format!("{emission}\n{emission}"), 1)),
            (
                "une instruction intercalée avant l'appel",
                corps.replacen(emission, &format!("let _ = std::env::var(\"PLUME_RESPONDER_VERBOSE\");\n{emission}"), 1),
            ),
        ];
        for (quoi, variante) in &variantes {
            assert_ne!(variante.as_str(), corps, "fixture : la variante « {quoi} » modifie bien le corps");
            assert!(lbi_cablage_du_responder(variante).is_err(), "variante « {quoi} » : la relecture doit rougir");
        }
        // CONTRÔLE POSITIF — un commentaire ajouté dans la branche ne rompt pas le motif.
        let commente = corps.replacen(emission, &format!("// une note de relecture\n{emission}"), 1);
        assert_ne!(commente, corps);
        lbi_cablage_du_responder(&commente).unwrap_or_else(|e| panic!("un commentaire ajouté ne rompt pas le câblage : {e}"));
        netban_cache().write().clear();
    }

    /// CE QU'IL TIENT : le miroir HTTP du responder, EXÉCUTÉ (et non relu). Une levée `done` retire la
    /// ligne et le cache avec le `detail` d'avant ; une pose `done` arme avec l'auteur `responder` et
    /// l'échéance `NETBAN_ACTION_TTL_S` ; ni une riposte `failed`, ni un dry-run, ni une adresse
    /// protégée, ni un `kill_pid` ne touchent au miroir ni n'écrivent de levée au registre ; une pose
    /// dont l'écriture échoue et une pose sur store plein sont dites (`netban.non-arme`,
    /// `netban.plafond`) ; une cible inanalysable est dite (`netban.forme`) ; une levée refusée rend
    /// l'aveu et inscrit l'échec avec son `detail` exact ; le réglage éteint, rien ne bouge.
    /// MUTATIONS : `T1`, `T3`, `T3b`, `T4`, `L8`, `M10`, `M13`, `M14`, `MP` (cf. l'en-tête).
    #[test]
    fn lbi_le_miroir_du_responder_execute_garde_pose_et_levee() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = lbi_etat("miroir-responder");
        let ligne = |ip: &str| lbi_compte(&st, &format!("SELECT COUNT(*) FROM net_ban WHERE ip='{ip}'"));
        let miroir = |kind: &str, target: &str, status: &str, dry: bool| {
            miroir_http_du_responder(&st.db.lock(), 9, kind, target, status, dry)
        };

        // (1) levée `done` : ligne et cache levés, `detail` d'avant, rien à avouer. MUTATIONS : `T1`, `T3`, `T4`.
        lbi_ban_actif(&st, "203.0.113.71");
        assert_eq!(miroir("unban_ip", "203.0.113.71", "done", false), None);
        assert_eq!(ligne("203.0.113.71"), 0, "la levée `done` retire la ligne du ban");
        assert!(!net_ban_is_blocked("203.0.113.71", now()), "et le cache ne bloque plus l'adresse");
        assert_eq!(
            lbi_detail(&st, "netban.remove"),
            vec!["203.0.113.71 retirés=1 (auto: responder unban_ip)".to_string()],
            "la levée est au registre avec le detail d'avant"
        );

        // (2) levée `failed` et (3) levée en dry-run : le miroir n'est pas touché. MUTATION : `T3b`.
        lbi_ban_actif(&st, "203.0.113.72");
        assert_eq!(miroir("unban_ip", "203.0.113.72", "failed", false), None);
        assert_eq!(ligne("203.0.113.72"), 1, "une levée `failed` ne lève pas le miroir");
        lbi_ban_actif(&st, "203.0.113.73");
        assert_eq!(miroir("unban_ip", "203.0.113.73", "done", true), None);
        assert_eq!(ligne("203.0.113.73"), 1, "une levée en dry-run ne lève pas le miroir");
        assert!(net_ban_is_blocked("203.0.113.72", now()) && net_ban_is_blocked("203.0.113.73", now()));
        assert_eq!(lbi_genre(&st, "netban.remove"), 1, "aucune autre levée n'est inscrite");

        // (4) pose `done` : armée, auteur `responder` ; (5) pose `failed`, (6) adresse protégée,
        // (7) `kill_pid` : rien.
        let avant = now();
        assert_eq!(miroir("ban_ip", "203.0.113.74", "done", false), None);
        let apres = now();
        assert_eq!(
            lbi_compte(&st, "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.74' AND created_by='responder' AND reason='auto: responder ban_ip'"),
            1,
            "la pose `done` arme le miroir"
        );
        assert!(net_ban_is_blocked("203.0.113.74", now()));
        // La pose expire après `NETBAN_ACTION_TTL_S`, jamais permanente. MUTATION : `M13`.
        assert_eq!(
            lbi_compte(
                &st,
                &format!(
                    "SELECT COUNT(*) FROM net_ban WHERE ip='203.0.113.74' AND expires_ts BETWEEN {} AND {}",
                    avant + NETBAN_ACTION_TTL_S,
                    apres + NETBAN_ACTION_TTL_S
                )
            ),
            1,
            "la pose `done` porte l'échéance de `NETBAN_ACTION_TTL_S`"
        );
        assert_eq!(miroir("ban_ip", "203.0.113.75", "failed", false), None);
        assert_eq!(ligne("203.0.113.75"), 0, "une pose `failed` n'arme rien");
        assert_eq!(miroir("ban_ip", "10.0.0.5", "done", false), None);
        assert_eq!(ligne("10.0.0.5"), 0, "une adresse protégée n'est jamais armée");
        assert_eq!(miroir("kill_pid", "4242", "done", false), None);
        assert_eq!(lbi_genre(&st, "netban.forme"), 0, "un `kill_pid` n'écrit rien au sujet du miroir");
        // Ni la pose protégée ni le `kill_pid` ne passent par la levée : aucune ligne `netban.remove`
        // fabriquée pour une riposte qui n'est pas une levée, rien au registre sur l'adresse protégée.
        // MUTATION : `M10` (`else if kind == "unban_ip"` devenu `else`).
        assert_eq!(lbi_genre(&st, "netban.remove"), 1, "seule la levée (1) est attestée au registre");
        assert_eq!(
            lbi_compte(&st, "SELECT COUNT(*) FROM ledger WHERE detail LIKE '%10.0.0.5%'"),
            0,
            "une pose sur adresse protégée n'écrit rien au registre"
        );

        // (7b) pose `done` dont l'écriture échoue : dite au registre, rien d'armé. MUTATION : `M14`.
        lbi_ecrire(
            &st,
            "CREATE TRIGGER lbi_pose_refusee BEFORE INSERT ON net_ban WHEN NEW.ip='203.0.113.76' \
             BEGIN SELECT RAISE(ABORT, 'pose refusee par le temoin'); END;",
        );
        assert_eq!(miroir("ban_ip", "203.0.113.76", "done", false), None);
        assert_eq!(ligne("203.0.113.76"), 0, "fixture : la pose a bien été refusée");
        assert_eq!(
            lbi_detail(&st, "netban.non-arme"),
            vec!["203.0.113.76 NON armé (responder, action 9) : pose refusee par le temoin".to_string()],
            "la pose ratée est dite avec sa cause"
        );
        lbi_ecrire(&st, "DROP TRIGGER lbi_pose_refusee;");

        // (7c) pose `done` sur store plein : refusée et dite, rien d'écrit. MUTATION : `MP`.
        {
            let mut c = netban_cache().write();
            for i in 0..NETBAN_CACHE_CAP {
                c.insert(format!("2001:db8::{i:x}"), None);
            }
        }
        assert_eq!(miroir("ban_ip", "203.0.113.77", "done", false), None);
        assert_eq!(ligne("203.0.113.77"), 0, "store plein : rien n'est écrit");
        assert_eq!(
            lbi_detail(&st, "netban.plafond"),
            vec!["203.0.113.77 refusé : store live plein (responder, action 9)".to_string()],
            "le refus du plafond est dit"
        );
        netban_reload(&st.db.lock());

        // (8) cible inanalysable : dite, rien d'autre.
        assert_eq!(miroir("unban_ip", "pas-une-adresse", "done", false), None);
        assert_eq!(
            lbi_detail(&st, "netban.forme"),
            vec!["pas-une-adresse : forme non analysable — aucun miroir HTTP (responder, unban_ip, action 9)".to_string()]
        );

        // (9) levée refusée par la base : l'aveu est RENDU, l'échec inscrit avec son detail exact.
        // MUTATION : `L8`.
        lbi_ban_actif(&st, "203.0.113.79");
        lbi_ecrire(&st, LBI_LEVEE_REFUSEE);
        let aveu = miroir("unban_ip", "203.0.113.79", "done", false).expect("une levée refusée est avouée");
        assert!(aveu.contains("action 9") && aveu.contains("TOUJOURS actif"), "{aveu}");
        assert_eq!(
            aveu,
            "[responder] WARN action 9 : miroir HTTP NON levé, le ban HTTP est TOUJOURS actif (levee refusee par le temoin)",
            "l'aveu rendu par le miroir porte la cause (MUTATION `R8`)"
        );
        assert!(!aveu.contains("203.0.113.79"), "l'aveu ne nomme pas l'adresse : {aveu}");
        assert_eq!(
            lbi_detail(&st, "netban.remove.echec"),
            vec!["203.0.113.79 NON levé (auto: responder unban_ip) : levee refusee par le temoin".to_string()]
        );
        assert!(net_ban_is_blocked("203.0.113.79", now()), "le ban reste actif");
        lbi_ecrire(&st, "DROP TRIGGER lbi_levee_refusee;");

        // (10) réglage éteint : une levée `done` ne touche pas au miroir.
        {
            let _eteint = ReglageBackupPose::neuf("PLUME_NETBAN_FROM_ACTIONS", "0");
            assert_eq!(miroir("unban_ip", "203.0.113.79", "done", false), None);
            assert_eq!(ligne("203.0.113.79"), 1, "réglage éteint : le miroir n'est pas levé");
        }
        // CONTRÔLE POSITIF — réglage rallumé, la même levée passe.
        assert_eq!(miroir("unban_ip", "203.0.113.79", "done", false), None);
        assert_eq!(ligne("203.0.113.79"), 0);
        netban_cache().write().clear();
    }
}
