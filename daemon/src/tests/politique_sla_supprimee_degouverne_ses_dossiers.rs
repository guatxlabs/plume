// =====================================================================================
// `P10.31-v` (volet démon) — SUPPRIMER UNE POLITIQUE SLA DÉGOUVERNE SES DOSSIERS, EN UNE ÉCRITURE ATOMIQUE.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR 824949d : `sla_policy_delete` n'écrivait que `DELETE FROM sla_policy` ; les dossiers
// gardaient `sla_policy_id` (politique disparue), `ack_due` et `resolve_due`, et `sla_multilevel_tick_par` — qui lit ces
// échéances sur `incident` sans joindre `sla_policy` — les marquait et les NOTIFIAIT en dépassement dès qu'une AUTRE
// politique restait active.
// CORRIGÉ : suppression + `UPDATE incident SET sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL WHERE
// sla_policy_id=?1` + registre dans UNE transaction (`jouer_le_geste_garde`) ; effacement refusé = 503
// `CAUSE_DOSSIERS_NON_DEGOUVERNES`, politique conservée, rien au registre ; nombre de dossiers dégouvernés au registre ;
// maillon manquant avoué (`CLE_REGISTRE_SANS_MAILLON`) ; sans dossier gouverné, 204 et détail d'avant.
//
// CE QU'ILS NE TIENNENT PAS : la console (`web/`, aveux du chrono non peints) ; une politique MODIFIÉE ou DÉSACTIVÉE
// (`sla_policy_upsert`) ; les marqueurs `ack_breached`/`resolve_breached` passés, conservés à dessein ; le refus du
// `BEGIN` ou du `COMMIT` est joué (`psd_begin_refuse_*`, `psd_commit_refuse_*`), mais par une transaction étrangère et
// une clé étrangère différée posées par le témoin, pas par une vraie contention de l'écrivain.
// Mutants (VERIF_MUT, retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod politique_sla_supprimee_degouverne_ses_dossiers {
    use super::*;

    fn psd_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("psd-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn psd_admin() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn psd_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn psd_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn psd_textes(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn psd_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier gouverné par `pid`, échéances posées à `now + decalage` (négatif = déjà échu).
    fn psd_dossier_gouverne(st: &AppState, titre: &str, priorite: i64, pid: i64, decalage: i64) -> i64 {
        let conn = st.db.lock();
        let id = dossier_seme(&conn, "alice", titre, 4, "", None, priorite);
        conn.execute(
            "UPDATE incident SET sla_policy_id=?1, ack_due=?2, resolve_due=?2 WHERE id=?3",
            params![pid, now() + decalage, id],
        )
        .unwrap();
        id
    }

    fn psd_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }

    /// Statut et octets bruts du corps.
    async fn psd_supprimer(st: &AppState, pid: i64) -> (u16, Vec<u8>) {
        let r = sla_policy_delete(State(st.clone()), Extension(psd_admin()), Path(pid)).await.into_response();
        let code = r.status().as_u16();
        (code, axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn psd_tick(st: &AppState) -> Vec<String> {
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    /// CE QU'IL TIENT : dossiers A et A2 gouvernés par P1, échus ; P2 reste active (dossier B gouverné par P2, échu, et C, à
    /// échoir). Supprimer P1 rend A ET A2 au régime legacy (trois colonnes NULL, `sla_due` legacy intact et égal à
    /// `ts + cible(priorité)`) ; le tour multi-niveau ne notifie plus A, notifie toujours B ; B et C intacts ; le
    /// registre dit « 2 dossier(s) dégouverné(s) » ; la route rend 204, corps vide.
    /// MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=J7_SANS_EFFACEMENT` (l'`UPDATE` retiré : la forme d'avant),
    /// `VERIF_MUT=J7_DETAIL_MUET` (le registre tait le nombre), `VERIF_MUT=J7_UN_SEUL_DOSSIER` (l'`UPDATE` borné au
    /// premier dossier de la politique : un témoin à un seul dossier ne le distinguait pas).
    #[tokio::test]
    async fn psd_supprimer_une_politique_degouverne_ses_dossiers_et_le_tick_ne_les_notifie_plus() {
        let (st, _t) = psd_etat("tick");
        let p1 = psd_politique(&st, "P1", 1);
        let p2 = psd_politique(&st, "P2", 2);
        let a = psd_dossier_gouverne(&st, "A", 1, p1, -100);
        let a2 = psd_dossier_gouverne(&st, "A2", 1, p1, -100);
        let b = psd_dossier_gouverne(&st, "B", 2, p2, -100);
        let c = psd_dossier_gouverne(&st, "C", 2, p2, 100_000);
        psd_sql(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('psd','webhook',1,'https://example.invalid/h',0,'{}')");
        let sla_due_a = psd_entier(&st, &format!("SELECT sla_due FROM incident WHERE id={a}"));
        let chrono_b = psd_chrono(&st, b);
        let chrono_c = psd_chrono(&st, c);

        let (statut, corps) = psd_supprimer(&st, p1).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "suppression réussie, maillon inscrit : 204, corps vide");
        assert_eq!(psd_chrono(&st, a), (None, None, None), "A n'est plus gouverné par une politique disparue");
        assert_eq!(psd_chrono(&st, a2), (None, None, None), "A2 non plus : TOUS les dossiers de P1, pas le premier");
        assert_eq!(
            psd_entier(&st, &format!("SELECT sla_due FROM incident WHERE id={a}")),
            sla_due_a,
            "le sla_due legacy n'est pas touché"
        );
        assert_eq!(
            psd_entier(&st, &format!("SELECT sla_due - ts FROM incident WHERE id={a}")),
            Some(sla_target_s(1)),
            "et il est bien celui du régime legacy de sa priorité"
        );
        assert_eq!(psd_chrono(&st, b), chrono_b, "B, gouverné par P2, intact");
        assert_eq!(psd_chrono(&st, c), chrono_c, "C, gouverné par P2, intact");
        assert_eq!(
            psd_textes(&st, "SELECT detail FROM ledger WHERE kind='sla_policy.delete'"),
            vec![format!("#{p1} by analyste ; 2 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)")],
            "le registre dit le nombre de dossiers dégouvernés"
        );

        let envois = psd_tick(&st);
        assert!(!envois.iter().any(|d| d.starts_with(&format!("Case #{a} "))), "A n'est plus notifié en dépassement : {envois:?}");
        assert!(!envois.iter().any(|d| d.starts_with(&format!("Case #{a2} "))), "A2 non plus : {envois:?}");
        assert!(envois.iter().any(|d| d.starts_with(&format!("Case #{b} "))), "B, échu sous P2 active, l'est toujours : {envois:?}");
        assert_eq!(
            psd_entier(&st, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={a}")),
            Some(0),
            "aucun dépassement marqué sur A"
        );
        assert_eq!(
            psd_entier(&st, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={a2}")),
            Some(0),
            "aucun dépassement marqué sur A2"
        );
    }

    /// CE QU'IL TIENT : sans dossier gouverné, le chemin nominal est celui d'avant octet pour octet — 204 corps vide,
    /// registre `#{id} by analyste` mot pour mot ; une politique absente reste un 404, sans registre.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=K1X` (WHERE élargi aux dossiers sans politique : le dossier Legacy, qui
    /// porte des échéances sans politique, les perd ; l'assertion du chrono précède celle du registre).
    #[tokio::test]
    async fn psd_supprimer_une_politique_sans_dossier_rend_le_204_d_avant() {
        let (st, _t) = psd_etat("nominal");
        let p1 = psd_politique(&st, "P1", 1);
        let legacy = {
            let conn = st.db.lock();
            let id = dossier_seme(&conn, "alice", "Legacy", 3, "", None, 3);
            // Échéances posées SANS politique : un `UPDATE` au WHERE élargi les effacerait, l'assertion le verrait.
            conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![now() + 100_000, id]).unwrap();
            id
        };
        let avant = psd_chrono(&st, legacy);
        assert!(matches!(avant, (None, Some(_), Some(_))), "fixture : le dossier non gouverné porte des échéances : {avant:?}");
        assert_eq!(psd_supprimer(&st, p1 + 999).await.0, 404, "absence : 404, comme avant");
        assert_eq!(psd_entier(&st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"), Some(0));
        let (statut, corps) = psd_supprimer(&st, p1).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(psd_chrono(&st, legacy), avant, "un dossier non gouverné garde ses échéances (WHERE non élargi)");
        assert_eq!(psd_textes(&st, "SELECT detail FROM ledger WHERE kind='sla_policy.delete'"), vec![format!("#{p1} by analyste")]);
        assert_eq!(psd_entier(&st, "SELECT COUNT(*) FROM sla_policy"), Some(0));
    }

    /// CE QU'IL TIENT : l'effacement des échéances refusé par la base (trigger `RAISE(ABORT)` sur l'`UPDATE` d'`incident`,
    /// jamais sur une lecture) -> 503 `CAUSE_DOSSIERS_NON_DEGOUVERNES`, la politique est TOUJOURS là (suppression annulée
    /// dans la même transaction), le dossier toujours gouverné, rien au registre. Contrôle : trigger levé, la même
    /// suppression aboutit.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=J7_REFUS_AVALE` (l'erreur de l'`UPDATE` lue comme zéro dossier).
    #[tokio::test]
    async fn psd_effacement_refuse_rend_503_et_conserve_la_politique() {
        let (st, _t) = psd_etat("refus");
        let p1 = psd_politique(&st, "P1", 1);
        let _p2 = psd_politique(&st, "P2", 2);
        let a = psd_dossier_gouverne(&st, "A", 1, p1, -100);
        let avant = psd_chrono(&st, a);
        psd_sql(&st, "CREATE TEMP TRIGGER psd_refus BEFORE UPDATE OF ack_due ON incident BEGIN SELECT RAISE(ABORT, 'psd refus'); END;");
        let (statut, corps) = psd_supprimer(&st, p1).await;
        let corps: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 503, "effacement refusé : 503 nommé : {corps}");
        // `P10.29-l` (vague AL) — INVERSÉ : il lisait le motif du moteur (« psd refus ») dans le corps ; la phrase seule
        // `{error, id}`, la cause au journal (témoin `al1_journal_des_refus_de_caseops`).
        super::dossier_refus_sans_texte_du_moteur::ak3_phrase_seule("effacement refusé", statut, &corps, crate::handlers::caseops::CAUSE_DOSSIERS_NON_DEGOUVERNES);
        assert_eq!(psd_entier(&st, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={p1}")), Some(1), "politique CONSERVÉE");
        assert_eq!(psd_chrono(&st, a), avant, "dossier toujours gouverné");
        assert_eq!(psd_entier(&st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"), Some(0), "rien attesté");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");

        psd_sql(&st, "DROP TRIGGER psd_refus;");
        assert_eq!(psd_supprimer(&st, p1).await.0, 204, "contrôle : la même suppression aboutit");
        assert_eq!(psd_chrono(&st, a), (None, None, None));
    }

    /// CE QU'IL TIENT : le registre refuse le maillon -> la suppression et l'effacement ont eu lieu (validés), et la
    /// réponse l'AVOUE sous `CLE_REGISTRE_SANS_MAILLON` avec le nombre de dossiers dégouvernés, au lieu d'un 204 muet.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=J7_MAILLON_TU` (204 quel que soit le maillon).
    #[tokio::test]
    async fn psd_maillon_refuse_est_avoue() {
        let (st, _t) = psd_etat("maillon");
        let p1 = psd_politique(&st, "P1", 1);
        let a = psd_dossier_gouverne(&st, "A", 1, p1, -100);
        psd_sql(&st, "CREATE TEMP TRIGGER psd_registre BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'psd registre'); END;");
        let (statut, corps) = psd_supprimer(&st, p1).await;
        let corps: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "le geste a eu lieu, sa trace manque : avoué : {corps}");
        assert_eq!(corps["degouvernes"], json!(1), "{corps}");
        let aveu = corps[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("");
        assert_eq!(aveu, format!("{CAUSE_GESTE_SANS_TRACE} ({CAUSE_MAILLON_NON_ECRIT})"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : phrase fixe du maillon non écrit, plus le texte du moteur : {corps}");
        psd_sql(&st, "DROP TRIGGER psd_registre;");
        assert_eq!(psd_entier(&st, "SELECT COUNT(*) FROM sla_policy"), Some(0), "suppression validée");
        assert_eq!(psd_chrono(&st, a), (None, None, None), "effacement validé");
    }
    /// Ce qui doit être TOUJOURS là quand la route a rendu 503 `CAUSE_POLITIQUE_NON_SUPPRIMEE` : la politique, le
    /// dossier gouverné avec ses échéances, aucun registre de suppression.
    fn psd_refus_de_transaction_conserve_tout(st: &AppState, p1: i64, a: i64, avant: (Option<i64>, Option<i64>, Option<i64>), statut: u16, corps: &[u8], motif: &str) {
        let corps: Value = serde_json::from_slice(corps).unwrap_or(Value::Null);
        assert_eq!(statut, 503, "{motif} : 503, pas une suppression annoncée : {corps}");
        assert!(
            corps["error"].as_str().unwrap_or("").starts_with(crate::handlers::caseops::CAUSE_POLITIQUE_NON_SUPPRIMEE),
            "{motif} : la cause nommée de la politique non supprimée : {corps}"
        );
        assert_eq!(psd_entier(st, &format!("SELECT COUNT(*) FROM sla_policy WHERE id={p1}")), Some(1), "{motif} : politique CONSERVÉE");
        assert_eq!(psd_chrono(st, a), avant, "{motif} : dossier toujours gouverné, échéances intactes");
        assert_eq!(psd_entier(st, "SELECT COUNT(*) FROM ledger WHERE kind='sla_policy.delete'"), Some(0), "{motif} : rien attesté");
    }

    /// CE QU'IL TIENT : le `BEGIN IMMEDIATE` du geste refusé (transaction étrangère déjà ouverte sur la connexion
    /// d'écriture) -> 503 `CAUSE_POLITIQUE_NON_SUPPRIMEE`, politique et dossier intacts, rien au registre ; la transaction
    /// étrangère reste la sienne (le geste n'y écrit rien). Contrôle : ROLLBACK de l'étrangère, la suppression aboutit.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=J7_NONOUVERT_204` (BEGIN refusé rendu 204).
    #[tokio::test]
    async fn psd_begin_refuse_rend_503_et_conserve_la_politique() {
        let (st, _t) = psd_etat("begin");
        let p1 = psd_politique(&st, "P1", 1);
        let a = psd_dossier_gouverne(&st, "A", 1, p1, -100);
        let avant = psd_chrono(&st, a);
        psd_sql(&st, "BEGIN");
        let (statut, corps) = psd_supprimer(&st, p1).await;
        assert!(!st.db.lock().is_autocommit(), "la transaction étrangère n'a été ni validée ni annulée par le geste");
        psd_sql(&st, "ROLLBACK");
        psd_refus_de_transaction_conserve_tout(&st, p1, a, avant, statut, &corps, "BEGIN refusé");
        assert_eq!(psd_supprimer(&st, p1).await.0, 204, "contrôle : la même suppression aboutit");
        assert_eq!(psd_chrono(&st, a), (None, None, None));
    }

    /// CE QU'IL TIENT : le `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par un trigger temporaire sur la suppression de
    /// la politique) -> 503 `CAUSE_POLITIQUE_NON_SUPPRIMEE`, tout annulé : politique conservée, dossier toujours gouverné,
    /// registre vide, aucune transaction laissée ouverte. Contrôle : trigger levé, la suppression aboutit.
    /// MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=J7_NONVALIDE_204` (COMMIT refusé rendu 204).
    #[tokio::test]
    async fn psd_commit_refuse_rend_503_et_conserve_la_politique() {
        let (st, _t) = psd_etat("commit");
        let p1 = psd_politique(&st, "P1", 1);
        let a = psd_dossier_gouverne(&st, "A", 1, p1, -100);
        let avant = psd_chrono(&st, a);
        psd_sql(
            &st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE psd_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE psd_enfant(p INTEGER REFERENCES psd_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER psd_fk AFTER DELETE ON sla_policy BEGIN INSERT INTO psd_enfant VALUES(999); END;",
        );
        let (statut, corps) = psd_supprimer(&st, p1).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte après le COMMIT refusé");
        psd_refus_de_transaction_conserve_tout(&st, p1, a, avant, statut, &corps, "COMMIT refusé");
        psd_sql(&st, "DROP TRIGGER psd_fk;");
        assert_eq!(psd_supprimer(&st, p1).await.0, 204, "contrôle : la même suppression aboutit");
        assert_eq!(psd_chrono(&st, a), (None, None, None));
    }
}
