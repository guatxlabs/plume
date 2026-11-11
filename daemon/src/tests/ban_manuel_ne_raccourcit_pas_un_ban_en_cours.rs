// =====================================================================================
// `P11.25-a` — LA POSE MANUELLE D'UN BAN (`POST /api/netban`) NE RACCOURCIT JAMAIS UN BAN EN COURS.
//
// Décision de l'exploitant du 2026-11-10 : un ban ne raccourcit jamais un ban en cours, pose d'un administrateur
// comprise. AVANT : `netban_add` passait par la pose qui REMPLAÇAIT l'échéance du même `env_id`, plus courte comprise,
// et la réponse rendait l'échéance DEMANDÉE. APRÈS : `netban_add` passe par `auth::netban_poser_sans_raccourcir_et_relire`
// — même règle, même texte SQL que les poses automatiques (`SQL_NETBAN_POSE_SANS_RACCOURCIR` : l'échéance demandée n'est prise que
// si elle allonge, permanent l'emporte toujours, sinon la ligne reste entière ; une échéance illisible, que le chargement
// tient permanente, est conservée) ; la réponse rend l'échéance relue en base
// par l'écriture et `issue_du_ban` (`pose` / `allonge` / `conserve`) ; la ligne `netban.add` porte la durée demandée,
// l'issue, et, pour un ban conservé, l'échéance et l'auteur du ban qui tient. La levée reste la seule voie pour
// raccourcir. Chaque témoin passe par le point d'entrée `netban_add` (et `netban_delete` pour la levée), corps de
// réponse comparé EN ENTIER, ligne `net_ban` relue en base, ligne de registre comparée en entier.
//
// Un `BEGIN` refusé sert LE 503 de la forme commune (`ouvrir_le_garde_du_geste`, cause `CAUSE_BAN_NON_ARME`) : une seule
// réponse construite, donc une seule ligne `HTTP 503` au journal, sous l'identifiant que le client reçoit.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un `COMMIT` que SQLite annule de lui-même (disque plein, E/S) — le refus joué
// est celui d'un autorisateur ; la console ne lit pas encore `issue_du_ban`.
//
// MUTANTS JOUÉS (interrupteurs temporaires retirés avant le commit), chacun vu rouge, avec le témoin qui rougit :
//   `cmp_retournee` (`>` devient `<` dans les trois CASE) -> bmr_long_puis_court_conserve, bmr_court_puis_long_allonge ;
//   `egalite` (`>` devient `>=`) -> bmr_egalite_d_echeance_conserve ;
//   `permanent` (la clause `excluded.expires_ts IS NULL OR` retirée) -> bmr_duree_puis_permanent_allonge ;
//   `reponse_demandee` (le corps rend l'échéance demandée) -> bmr_long_puis_court_conserve, bmr_permanent_puis_duree_conserve ;
//   `registre_muet` (la ligne `netban.add` ne dit plus ce qui tient) -> bmr_long_puis_court_conserve,
//   bmr_permanent_puis_duree_conserve ;
//   `echue_allongee` (le bras de la ligne échue retiré) -> bmr_ligne_echue_puis_pose_pose ;
//   `conserve_retire` (le bras « échéance inchangée » retiré) -> bmr_egalite_d_echeance_conserve ;
//   `lecture_avant_avalee` (la lecture d'avant refusée lue comme « aucune ligne ») -> bmr_lecture_d_avant_refusee_n_ecrit_rien ;
//   `commit_avale` (`let _ = tx.commit();`) -> bmr_commit_refuse_n_ecrit_rien ;
//   `armer_demande` (le repli arme l'échéance demandée au lieu de celle qui tient) -> bmr_repli_apres_commit_arme_ce_qui_tient ;
//   `echue_bord` (`t <= maintenant` devient `<`) -> bmr_echue_a_la_seconde_meme_pose ;
//   `sql_real` (le SQL de l'administrateur tient un réel pour une durée) et `avant_real` (la lecture d'avant aussi)
//   -> bmr_echeance_reelle_conservee ; `illisible_dite_posee` (le bras de l'échéance illisible rendu `pose`) ->
//   bmr_echeance_texte_conservee, bmr_echeance_reelle_conservee ; `registre_illisible_muet` (le registre écrit
//   `permanent` pour une cellule illisible) -> bmr_echeance_texte_conservee ;
//   `begin_plafond` (le `BEGIN` refusé rendu comme un store plein) -> bmr_begin_refuse_n_ecrit_rien ;
//   `BEGIN_DEUX_REPONSES` (la réponse de la forme commune jetée, `netban_add` en construit une seconde) ->
//   bmr_begin_refuse_n_ecrit_rien, bmr_begin_refuse_une_seule_reponse_au_journal ; `REGISTRE_BEGIN_MUET` (la ligne
//   `netban.non-arme` du `BEGIN` refusé n'est plus écrite) -> bmr_begin_refuse_n_ecrit_rien ;
//   `vide_blanc` (un auteur vide en base écrit comme un blanc au registre) -> bmr_permanent_puis_duree_conserve ;
//   `admin_remplace` (la pose de l'administrateur reprend le SQL qui remplace) -> bmr_long_puis_court_conserve,
//   bmr_permanent_puis_duree_conserve, bmr_egalite_d_echeance_conserve, bmr_lever_puis_reposer_plus_court et le contrôle
//   inversé de banr_la_primitive_garde_le_ban_le_plus_long ; `auto_remplace` (les poses automatiques le reprennent) ->
//   les témoins banr_ et netban_repli_de_pose_courte_sur_permanent_meme_env_conservee.
// =====================================================================================
mod ban_manuel_ne_raccourcit_pas_un_ban_en_cours {
    use super::*;

    const BMR_LONG: i64 = 7200;
    const BMR_COURT: i64 = 60;

    fn bmr_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("bmr-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute_batch("DELETE FROM net_ban; DELETE FROM ledger;").unwrap();
        }
        (ds_file_state(&chemin), chemin)
    }

    fn bmr_alice() -> AuthUser {
        AuthUser {
            name: "alice".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// Une ligne `net_ban` posée par un AUTRE auteur (`bob`), avec une raison à elle : ce qu'un ban conservé doit garder.
    fn bmr_semer(st: &AppState, ip: &str, expires: Option<i64>, reason: &str, env: &str) {
        st.db
            .lock()
            .execute(
                "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) VALUES (?1, ?2, 0, ?3, 'bob', ?4)",
                params![ip, reason, expires, env],
            )
            .unwrap();
    }

    fn bmr_ligne(st: &AppState, ip: &str, env: &str) -> (Option<i64>, String, String) {
        st.db
            .lock()
            .query_row(
                "SELECT expires_ts, reason, created_by FROM net_ban WHERE ip = ?1 AND env_id = ?2",
                params![ip, env],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap_or_else(|e| panic!("ligne net_ban de {ip}/{env} : {e}"))
    }

    fn bmr_lignes(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM net_ban", [], |r| r.get(0)).unwrap()
    }

    /// Les détails des lignes `netban.add` du registre, dans l'ordre d'écriture.
    fn bmr_registre(st: &AppState) -> Vec<String> {
        let c = st.db.lock();
        let mut q = c.prepare("SELECT detail FROM ledger WHERE kind = 'netban.add' ORDER BY id").unwrap();
        let v: Vec<String> = q.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        v
    }

    async fn bmr_poser(st: &AppState, ip: &str, ttl: Option<i64>, reason: &str) -> (u16, Value) {
        let mut corps = json!({ "ip": ip, "reason": reason });
        if let Some(t) = ttl {
            corps["ttl_s"] = json!(t);
        }
        pb_json(netban_add(State(st.clone()), Extension(bmr_alice()), Json(corps)).await).await
    }

    fn bmr_preparer() {
        netban_cache().write().clear();
        crate::ledger::declarer_la_liste_pour_ce_temoin();
    }

    /// Ban long (bob) puis pose manuelle courte (alice) -> conservé : corps = échéance d'AVANT, ligne entière d'avant,
    /// registre = durée demandée + ce qui tient, et le cache bloque encore au-delà de l'échéance courte.
    #[tokio::test]
    async fn bmr_long_puis_court_conserve() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("long-court");
        let ip = "203.0.113.211";
        let long = now() + BMR_LONG;
        bmr_semer(&st, ip, Some(long), "long", "prod");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "court").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": long, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_ligne(&st, ip, "prod"), (Some(long), "long".into(), "bob".into()), "la ligne d'avant reste ENTIÈRE");
        assert_eq!(bmr_lignes(&st), 1);
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=conserve tient_jusqu_a={long} tient_par=bob")]);
        assert!(net_ban_is_blocked(ip, now() + 10 * BMR_COURT), "le cache bloque au-delà de l'échéance courte");
        netban_cache().write().clear();
    }

    /// Ban court (bob) puis pose longue (alice) -> allongé : l'échéance, la raison et l'auteur du ban neuf.
    #[tokio::test]
    async fn bmr_court_puis_long_allonge() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("court-long");
        let ip = "203.0.113.212";
        let avant = now();
        bmr_semer(&st, ip, Some(avant + BMR_COURT), "court", "prod");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_LONG), "long").await;
        let apres = now();
        assert_eq!(code, 200, "{corps}");
        let (echeance, raison, auteur) = bmr_ligne(&st, ip, "prod");
        let e = echeance.expect("une échéance finie");
        assert!(e >= avant + BMR_LONG && e <= apres + BMR_LONG, "la base porte l'échéance DEMANDÉE ({e})");
        assert_eq!((raison.as_str(), auteur.as_str()), ("long", "alice"));
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": e, "issue_du_ban": "allonge" }));
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_LONG} by=alice issue=allonge")]);
        assert!(net_ban_is_blocked(ip, avant + 10 * BMR_COURT), "le cache bloque au-delà de l'ancienne échéance");
        netban_cache().write().clear();
    }

    /// Ban à durée (bob) puis pose permanente (alice) -> allongé à permanent.
    #[tokio::test]
    async fn bmr_duree_puis_permanent_allonge() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("duree-permanent");
        let ip = "203.0.113.213";
        bmr_semer(&st, ip, Some(now() + BMR_LONG), "fini", "prod");
        let (code, corps) = bmr_poser(&st, ip, None, "sans-fin").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": null, "issue_du_ban": "allonge" }));
        assert_eq!(bmr_ligne(&st, ip, "prod"), (None, "sans-fin".into(), "alice".into()));
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl=permanent by=alice issue=allonge")]);
        assert!(net_ban_is_blocked(ip, now() + 100 * BMR_LONG), "le permanent bloque");
        netban_cache().write().clear();
    }

    /// Permanent (bob) puis pose à durée (alice) -> conservé permanent, ligne entière, registre qui le dit.
    #[tokio::test]
    async fn bmr_permanent_puis_duree_conserve() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("permanent-duree");
        let ip = "203.0.113.214";
        bmr_semer(&st, ip, None, "perm", "prod");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "court").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": null, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_ligne(&st, ip, "prod"), (None, "perm".into(), "bob".into()));
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=conserve tient_jusqu_a=permanent tient_par=bob")]);
        assert!(net_ban_is_blocked(ip, now() + 100 * BMR_LONG), "le permanent bloque toujours");

        // Auteur VIDE en base (ligne héritée) : le registre le dit `(vide)`, jamais un auteur inventé ni un blanc.
        let ip2 = "203.0.113.222";
        bmr_semer(&st, ip2, None, "perm", "prod");
        st.db.lock().execute("UPDATE net_ban SET created_by = NULL WHERE ip = ?1", params![ip2]).unwrap();
        let (code, corps) = bmr_poser(&st, ip2, Some(BMR_COURT), "court").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip2, "expires_ts": null, "issue_du_ban": "conserve" }));
        assert_eq!(
            bmr_registre(&st)[1],
            format!("{ip2} ttl={BMR_COURT} by=alice issue=conserve tient_jusqu_a=permanent tient_par=(vide)")
        );
        netban_cache().write().clear();
    }

    /// Ligne ÉCHUE (bob) puis pose (alice) -> posé : la pose demandée tient, avec sa raison et son auteur.
    #[tokio::test]
    async fn bmr_ligne_echue_puis_pose_pose() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("echue");
        let ip = "203.0.113.215";
        let avant = now();
        bmr_semer(&st, ip, Some(avant - 10), "echu", "prod");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "neuf").await;
        let apres = now();
        assert_eq!(code, 200, "{corps}");
        let (echeance, raison, auteur) = bmr_ligne(&st, ip, "prod");
        let e = echeance.expect("une échéance finie");
        assert!(e >= avant + BMR_COURT && e <= apres + BMR_COURT, "la base porte l'échéance demandée ({e})");
        assert_eq!((raison.as_str(), auteur.as_str()), ("neuf", "alice"));
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": e, "issue_du_ban": "pose" }));
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=pose")]);
        netban_cache().write().clear();
    }

    /// `typeof` et valeur brute de la cellule `expires_ts` (texte ou réel compris).
    fn bmr_cellule(st: &AppState, ip: &str) -> (String, String, String, String) {
        st.db
            .lock()
            .query_row(
                "SELECT typeof(expires_ts), CAST(expires_ts AS TEXT), reason, created_by FROM net_ban WHERE ip = ?1 AND env_id = 'prod'",
                params![ip],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    }

    /// Échéance ILLISIBLE en texte : le chargement la tient bloquée sans fin, c'est un ban permanent en cours. La pose
    /// (courte) la CONSERVE entière ; la réponse dit `conserve` et permanent ; le registre dit `illisible`. Réparer =
    /// lever puis reposer (contrôle en fin de témoin).
    #[tokio::test]
    async fn bmr_echeance_texte_conservee() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("illisible");
        let ip = "203.0.113.221";
        bmr_semer(&st, ip, Some(now() + BMR_LONG), "vieux", "prod");
        st.db.lock().execute("UPDATE net_ban SET expires_ts = 'jamais' WHERE ip = ?1", params![ip]).unwrap();
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "neuf").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": null, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_cellule(&st, ip), ("text".into(), "jamais".into(), "vieux".into(), "bob".into()), "cellule ENTIÈRE");
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=conserve tient_jusqu_a=illisible tient_par=bob")]);
        assert!(net_ban_is_blocked(ip, now() + 100 * BMR_LONG), "tenue bloquée sans fin");

        let (code, leve) = pb_json(netban_delete(State(st.clone()), Extension(bmr_alice()), Path(ip.to_string())).await).await;
        assert_eq!((code, leve["retires"].clone()), (200, json!(1)), "{leve}");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "neuf").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps["issue_du_ban"], json!("pose"), "lever puis reposer répare : {corps}");
        assert_eq!(bmr_cellule(&st, ip).0, "integer");
        netban_cache().write().clear();
    }

    /// Échéance RÉELLE (non entière), dans le PASSÉ comme nombre : le chargement la tient permanente (un réel ne se lit
    /// pas en entier). La pose la conserve — une comparaison NUMÉRIQUE l'aurait remplacée par un ban de 60 s.
    #[tokio::test]
    async fn bmr_echeance_reelle_conservee() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("reelle");
        let ip = "203.0.113.224";
        bmr_semer(&st, ip, Some(now() - 100), "vieux", "prod");
        st.db.lock().execute("UPDATE net_ban SET expires_ts = expires_ts + 0.5 WHERE ip = ?1", params![ip]).unwrap();
        let (typ, brut, _, _) = bmr_cellule(&st, ip);
        assert_eq!(typ, "real", "fixture");
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "neuf").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": null, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_cellule(&st, ip), ("real".into(), brut, "vieux".into(), "bob".into()), "cellule ENTIÈRE");
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=conserve tient_jusqu_a=illisible tient_par=bob")]);
        assert!(net_ban_is_blocked(ip, now() + 100 * BMR_LONG), "tenue bloquée sans fin");
        netban_cache().write().clear();
    }

    /// Ligne qui échoit à la SECONDE MÊME de la pose : la garde ne bloque plus (`exp > now` faux) -> `pose`, pas
    /// `allonge`. On rejoue tant que la requête ne tient pas dans la seconde de sa fixture.
    #[tokio::test]
    async fn bmr_echue_a_la_seconde_meme_pose() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("echue-bord");
        let ip = "203.0.113.225";
        let mut tenu = None;
        for _ in 0..20 {
            st.db.lock().execute_batch("DELETE FROM net_ban; DELETE FROM ledger WHERE kind = 'netban.add';").unwrap();
            let t0 = now();
            bmr_semer(&st, ip, Some(t0), "echu", "prod");
            assert!(!net_ban_is_blocked_snapshot_at(ip, t0), "contrôle : la garde ne bloque pas à la seconde même");
            let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "neuf").await;
            if now() == t0 {
                tenu = Some((t0, code, corps));
                break;
            }
        }
        let (t0, code, corps) = tenu.expect("une requête tenue dans la seconde de sa fixture");
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": t0 + BMR_COURT, "issue_du_ban": "pose" }));
        assert_eq!(bmr_ligne(&st, ip, "prod"), (Some(t0 + BMR_COURT), "neuf".into(), "alice".into()));
        assert_eq!(bmr_registre(&st), vec![format!("{ip} ttl={BMR_COURT} by=alice issue=pose")]);
        netban_cache().write().clear();
    }

    /// Verdict de la garde sur une échéance `t0` à l'instant `t0` (instantané pur, sans base).
    fn net_ban_is_blocked_snapshot_at(ip: &str, t0: i64) -> bool {
        let mut m = HashMap::new();
        m.insert(ip.to_string(), Some(t0));
        netban_snapshot_blocked(&m, ip, t0)
    }

    /// `COMMIT` refusé (un autorisateur refuse l'opération de transaction `COMMIT`, `BEGIN` et `ROLLBACK` permis) après
    /// une écriture réussie -> 503 nommé, corps entier, transaction fermée, rien d'écrit, rien attesté, rien d'armé.
    /// Contrôle positif : l'autorisateur retiré, la pose passe.
    #[tokio::test]
    async fn bmr_commit_refuse_n_ecrit_rien() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("commit-refuse");
        let ip = "203.0.113.226";
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        let fermee = st.db.lock().is_autocommit();
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(code, 503, "{corps}");
        let cles: Vec<&String> = corps.as_object().expect("un objet").keys().collect();
        assert_eq!(cles, vec!["error", "id"], "{corps}");
        assert_eq!(corps["error"], json!(format!("{CAUSE_BAN_NON_ARME} ({})", CauseLaisseeAuJournal)), "{corps}");
        assert!(fermee, "la transaction est fermée");
        assert_eq!(bmr_lignes(&st), 0, "rien d'écrit");
        assert!(bmr_registre(&st).is_empty(), "rien d'attesté");
        assert!(!net_ban_is_blocked(ip, now()), "rien d'armé");

        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        assert_eq!(code, 200, "contrôle positif : {corps}");
        assert_eq!(corps["issue_du_ban"], json!("pose"), "{corps}");
        netban_cache().write().clear();
    }

    /// Le rechargement refusé APRÈS le `COMMIT` (un autorisateur à état refuse les `SELECT` une fois le `COMMIT` passé) :
    /// le repli arme l'échéance QUI TIENT (le ban long conservé), pas la demandée (60 s). Contrôle : la base porte bien
    /// le ban long et le cache était vide avant la pose.
    #[tokio::test]
    async fn bmr_repli_apres_commit_arme_ce_qui_tient() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        use std::sync::atomic::{AtomicBool, Ordering};
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("repli-apres-commit");
        let ip = "203.0.113.227";
        let long = now() + BMR_LONG;
        bmr_semer(&st, ip, Some(long), "long", "prod");
        assert!(!net_ban_is_blocked(ip, now()), "contrôle : le cache ne porte pas la ligne semée");
        let valide = std::sync::Arc::new(AtomicBool::new(false));
        let v = valide.clone();
        let conn = st.db.lock();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => {
                v.store(true, Ordering::SeqCst);
                Authorization::Allow
            }
            AuthAction::Select if v.load(Ordering::SeqCst) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let issue = netban_poser_sans_raccourcir_et_relire(&conn, ip, Some(now() + BMR_COURT), "court", "alice", "prod");
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(valide.load(Ordering::SeqCst), "contrôle : le COMMIT est passé");
        match issue {
            PoseManuelleDeBan::Tient(t) => {
                assert_eq!((t.issue, t.expires_ts), (IssueDuBanManuel::Conserve, Some(long)));
            }
            _ => panic!("la pose devait tenir"),
        }
        drop(conn);
        assert_eq!(bmr_ligne(&st, ip, "prod"), (Some(long), "long".into(), "bob".into()));
        assert!(net_ban_is_blocked(ip, now() + 10 * BMR_COURT), "le repli arme le ban long qui tient");
        netban_cache().write().clear();
    }

    /// Échéance ÉGALE -> conservé, ligne entière (raison et auteur d'avant). Deux formes : une échéance finie égale à
    /// celle demandée (la seconde de la requête doit être celle de la fixture : on rejoue tant qu'elle ne l'est pas), et
    /// permanent puis permanent.
    #[tokio::test]
    async fn bmr_egalite_d_echeance_conserve() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("egalite");
        let ip = "203.0.113.216";
        let mut tenu = None;
        for _ in 0..20 {
            st.db.lock().execute_batch("DELETE FROM net_ban; DELETE FROM ledger WHERE kind = 'netban.add';").unwrap();
            let t0 = now();
            bmr_semer(&st, ip, Some(t0 + BMR_LONG), "premier", "prod");
            let (code, corps) = bmr_poser(&st, ip, Some(BMR_LONG), "second").await;
            if now() == t0 {
                tenu = Some((t0, code, corps));
                break;
            }
        }
        let (t0, code, corps) = tenu.expect("une requête tenue dans la seconde de sa fixture");
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": t0 + BMR_LONG, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_ligne(&st, ip, "prod"), (Some(t0 + BMR_LONG), "premier".into(), "bob".into()), "égalité : rien ne change");
        assert_eq!(
            bmr_registre(&st),
            vec![format!("{ip} ttl={BMR_LONG} by=alice issue=conserve tient_jusqu_a={} tient_par=bob", t0 + BMR_LONG)]
        );

        let ip2 = "203.0.113.217";
        bmr_semer(&st, ip2, None, "perm", "prod");
        let (code, corps) = bmr_poser(&st, ip2, None, "perm2").await;
        assert_eq!(code, 200, "{corps}");
        assert_eq!(corps, json!({ "ok": true, "ip": ip2, "expires_ts": null, "issue_du_ban": "conserve" }));
        assert_eq!(bmr_ligne(&st, ip2, "prod"), (None, "perm".into(), "bob".into()), "permanent puis permanent : rien ne change");
        netban_cache().write().clear();
    }

    /// Un ban d'un AUTRE `env_id` n'est pas touché : la pose crée la ligne `prod` (posé) et laisse l'autre entière.
    #[tokio::test]
    async fn bmr_autre_env_non_touche() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("autre-env");
        let ip = "203.0.113.218";
        let long = now() + BMR_LONG;
        bmr_semer(&st, ip, Some(long), "autre", "autre");
        let avant = now();
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "prod").await;
        let apres = now();
        assert_eq!(code, 200, "{corps}");
        assert_eq!(bmr_ligne(&st, ip, "autre"), (Some(long), "autre".into(), "bob".into()), "l'autre env n'est pas touché");
        let (echeance, raison, auteur) = bmr_ligne(&st, ip, "prod");
        let e = echeance.expect("une échéance finie");
        assert!(e >= avant + BMR_COURT && e <= apres + BMR_COURT, "sa propre ligne, à l'échéance demandée ({e})");
        assert_eq!((raison.as_str(), auteur.as_str()), ("prod", "alice"));
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": e, "issue_du_ban": "pose" }));
        assert_eq!(bmr_lignes(&st), 2);
        netban_cache().write().clear();
    }

    /// La levée reste la seule voie pour raccourcir : un ban long, levé (`DELETE /api/netban/{ip}`), puis reposé plus
    /// court -> posé, l'échéance courte tient en base et dans le cache. Sans la levée, la même pose est conservée.
    #[tokio::test]
    async fn bmr_lever_puis_reposer_plus_court() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("lever-reposer");
        let ip = "203.0.113.219";
        let long = now() + BMR_LONG;
        bmr_semer(&st, ip, Some(long), "long", "prod");
        let (_, sans_levee) = bmr_poser(&st, ip, Some(BMR_COURT), "court").await;
        assert_eq!(sans_levee["issue_du_ban"], json!("conserve"), "contrôle : sans la levée, la pose courte est conservée");

        let (code, leve) = pb_json(netban_delete(State(st.clone()), Extension(bmr_alice()), Path(ip.to_string())).await).await;
        assert_eq!(code, 200, "{leve}");
        assert_eq!(leve["retires"], json!(1), "{leve}");
        let avant = now();
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "court").await;
        let apres = now();
        assert_eq!(code, 200, "{corps}");
        let (echeance, raison, auteur) = bmr_ligne(&st, ip, "prod");
        let e = echeance.expect("une échéance finie");
        assert!(e >= avant + BMR_COURT && e <= apres + BMR_COURT && e < long, "l'échéance courte tient ({e})");
        assert_eq!((raison.as_str(), auteur.as_str()), ("court", "alice"));
        assert_eq!(corps, json!({ "ok": true, "ip": ip, "expires_ts": e, "issue_du_ban": "pose" }));
        assert!(!net_ban_is_blocked(ip, apres + 10 * BMR_COURT), "le cache ne tient plus l'échéance longue");
        netban_cache().write().clear();
    }

    /// Le `BEGIN` refusé (un autorisateur refuse les énoncés de transaction, sur la connexion du gestionnaire) -> le 503
    /// de la forme commune, corps entier, rien d'écrit, rien attesté comme posé, rien d'armé ; la ligne `netban.non-arme`
    /// du registre, entière. Contrôle positif : l'autorisateur retiré, la pose passe.
    /// INVERSÉ (complément du lot) : le corps portait `CAUSE_BAN_NON_ARME (<cause laissée au journal>)`, celui d'une
    /// SECONDE réponse construite par `netban_add` après que la réponse de la forme commune eut été jetée ; il porte
    /// désormais `CAUSE_BAN_NON_ARME` seule, la réponse de la forme commune servie telle quelle.
    #[tokio::test]
    async fn bmr_begin_refuse_n_ecrit_rien() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("begin-refuse");
        let ip = "203.0.113.223";
        st.db.lock().authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
            rusqlite::hooks::AuthAction::Transaction { .. } => rusqlite::hooks::Authorization::Deny,
            _ => rusqlite::hooks::Authorization::Allow,
        }));
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        st.db.lock().authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(None);
        assert_eq!(code, 503, "{corps}");
        let cles: Vec<&String> = corps.as_object().expect("un objet").keys().collect();
        assert_eq!(cles, vec!["error", "id"], "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_BAN_NON_ARME), "{corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-")), "{corps}");
        assert_eq!(bmr_lignes(&st), 0, "rien d'écrit");
        assert!(bmr_registre(&st).is_empty(), "rien d'attesté");
        assert_eq!(bmr_registre_non_arme(&st), vec![format!("{ip} NON armé by=alice : BEGIN refusé (dit au journal [netban])")]);
        assert!(!net_ban_is_blocked(ip, now()), "rien d'armé");

        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        assert_eq!(code, 200, "contrôle positif : {corps}");
        assert_eq!(corps["issue_du_ban"], json!("pose"), "{corps}");
        netban_cache().write().clear();
    }

    /// Les détails des lignes `netban.non-arme` du registre, dans l'ordre d'écriture.
    fn bmr_registre_non_arme(st: &AppState) -> Vec<String> {
        let c = st.db.lock();
        let mut q = c.prepare("SELECT detail FROM ledger WHERE kind = 'netban.non-arme' ORDER BY id").unwrap();
        let v: Vec<String> = q.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        v
    }

    /// Le `BEGIN` refusé, JOURNAL CAPTURÉ : l'enfant (variable posée) joue la pose sous un autorisateur qui refuse les
    /// énoncés de transaction ; le parent lit son stderr entre deux balises. CE QU'IL TIENT : UNE seule ligne de 5xx
    /// (`[<id>] HTTP 503 : <cause>`), égale à l'octet à celle de la réponse servie (même identifiant, cause seule), et la
    /// ligne `[netban]` du refus de `BEGIN` dite une fois. MUTANT : `BEGIN_DEUX_REPONSES`.
    #[tokio::test]
    async fn bmr_begin_refuse_une_seule_reponse_au_journal() {
        const ENFANT: &str = "BMR_ENFANT_BEGIN_REFUSE";
        const BALISE: &str = "BMR-BALISE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let _g = NETBAN_TEST_LOCK.lock();
            bmr_preparer();
            let (st, _tmp) = bmr_etat("begin-journal");
            st.db.lock().authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
                rusqlite::hooks::AuthAction::Transaction { .. } => rusqlite::hooks::Authorization::Deny,
                _ => rusqlite::hooks::Authorization::Allow,
            }));
            eprintln!("{BALISE}debut");
            let (code, corps) = bmr_poser(&st, "203.0.113.228", Some(BMR_COURT), "refus").await;
            eprintln!("{BALISE}fin");
            st.db.lock().authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(None);
            println!("BMR-SORTIE:{}", json!([code, corps]));
            netban_cache().write().clear();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact", "--nocapture", "--test-threads=1",
                "tests::ban_manuel_ne_raccourcit_pas_un_ban_en_cours::bmr_begin_refuse_une_seule_reponse_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let reste = stdout.split_once("BMR-SORTIE:").unwrap_or_else(|| panic!("contrôle : sortie de l'enfant : {stdout}")).1;
        let v: Value = serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : sortie JSON ({e}) : {stdout}"));
        assert_eq!(v[0], json!(503), "{v}");
        let id = v[1]["id"].as_str().unwrap_or_else(|| panic!("contrôle : identifiant servi : {v}")).to_string();
        let entre = stderr
            .split_once(&format!("{BALISE}debut\n"))
            .and_then(|(_, r)| r.split_once(&format!("{BALISE}fin")))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : balises de l'enfant : {stderr}"));
        let cinq_cents: Vec<&str> = entre.lines().filter(|l| l.contains(" HTTP 5")).collect();
        assert_eq!(cinq_cents, [format!("[{id}] HTTP 503 : {CAUSE_BAN_NON_ARME}").as_str()], "une seule réponse 5xx, celle servie : {entre}");
        let du_begin: Vec<&str> = entre.lines().filter(|l| l.starts_with("[netban] ") && l.contains("ban manuel NON pris(e) : BEGIN refusé")).collect();
        assert_eq!(du_begin.len(), 1, "le refus de BEGIN dit une fois : {entre}");
    }

    /// La lecture de l'échéance d'avant refusée (un autorisateur, sur la connexion du gestionnaire, refuse les énoncés
    /// `SELECT` : la lecture d'avant en est un, l'upsert non — la lecture refusée seule décide du refus) -> 503 nommé, corps entier, rien d'écrit, rien attesté, rien d'armé. Contrôle positif :
    /// l'autorisateur retiré, la même pose passe.
    #[tokio::test]
    async fn bmr_lecture_d_avant_refusee_n_ecrit_rien() {
        let _g = NETBAN_TEST_LOCK.lock();
        bmr_preparer();
        let (st, _tmp) = bmr_etat("lecture-avant");
        let ip = "203.0.113.220";
        st.db.lock().authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
            rusqlite::hooks::AuthAction::Select => rusqlite::hooks::Authorization::Deny,
            _ => rusqlite::hooks::Authorization::Allow,
        }));
        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        st.db.lock().authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(None);
        assert_eq!(code, 503, "{corps}");
        // Corps entier : la phrase fixe et l'identifiant de corrélation (variable, jugé par sa présence et sa forme).
        let cles: Vec<&String> = corps.as_object().expect("un objet").keys().collect();
        assert_eq!(cles, vec!["error", "id"], "{corps}");
        assert_eq!(corps["error"], json!(format!("{CAUSE_BAN_NON_ARME} ({})", CauseLaisseeAuJournal)), "{corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-")), "{corps}");
        assert_eq!(bmr_lignes(&st), 0, "rien d'écrit");
        assert!(bmr_registre(&st).is_empty(), "rien d'attesté");
        assert!(!net_ban_is_blocked(ip, now()), "rien d'armé");

        let (code, corps) = bmr_poser(&st, ip, Some(BMR_COURT), "refus").await;
        assert_eq!(code, 200, "contrôle positif : {corps}");
        assert_eq!(corps["issue_du_ban"], json!("pose"), "{corps}");
        netban_cache().write().clear();
    }
}
