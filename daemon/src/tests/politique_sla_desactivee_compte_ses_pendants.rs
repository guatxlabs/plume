// =====================================================================================
// `P10.31-v` (reste, vague AN : « les dossiers effacés par le recalcul ne sont pas comptés au registre »).
//
// CE QUI MANQUAIT, MESURÉ SUR 60841412 : désactiver une politique (`sla_policy_upsert`, `enabled=false`) effaçait dans sa
// transaction les seuls dossiers gouvernés par CETTE politique ; un dossier ACTIF non fusionné de la priorité qui portait
// un `sla_policy_id` PENDANT (politique supprimée avant `P10.31-v`) ou ÉTRANGER (celui d'une autre priorité) n'était rendu
// au régime legacy que par le recalcul rejoué APRÈS le `COMMIT`, compté dans `recomputed` seulement : le maillon
// `sla_policy.upsert` ne le comptait pas (`pde_desactivation_sans_maillon_compte_le_pendant_dans_recomputed` affirmait
// « degouvernes = 1, recomputed = 1 » ; il est INVERSÉ dans ce lot).
// REMÈDE (a) : un second `UPDATE` dans la MÊME transaction, au prédicat du recalcul (priorité, non fusionné, non terminal,
// `sla_policy_id` non NULL), posé APRÈS celui de la politique ; son compte entre dans `degouvernes` et dans le détail
// (« , dont K dossier(s) actif(s) à politique pendante ou étrangère ») ; le recalcul n'est plus rejoué à la désactivation.
// CE QU'ILS TIENNENT : bords 2, 1 et 0 du compte relus au registre ; le corps sans maillon (`recomputed` 0, pas de double
// compte) ; priorité voisine et actif legacy à échéances orphelines INTACTS et non comptés (fusionné et terminaux : voir
// plus bas, inversés en vague AO) ; second
// effacement refusé, `BEGIN` refusé, `COMMIT` refusé : 500 à corps entier, rien posé ; la ligne de journal du refus, entière,
// par capture en sous-processus.
// CE QU'ILS NE TIENNENT PAS : la réactivation ou la modification qui ne regouverne ni les terminaux ni les fusionnés (limite
// écrite, `sla_apply_policy`) ; les marqueurs `ack_breached`/`resolve_breached` passés (conservés à dessein) ; la console
// (aucun écran de politiques SLA).
// Mutants (AN3_*, retirés avant le commit) nommés sur chaque témoin.
// `P10.31-v` (vague AO) — DEUX TÉMOINS INVERSÉS NOMMÉMENT : la désactivation efface aussi les terminaux et fusionnés à
// politique pendante ou étrangère, comptés à part des actifs. `pdp_fusionne_a_politique_pendante_intact` devient
// `pdp_fusionne_a_politique_pendante_degouverne_et_compte_a_part` ; `pdp_terminaux_a_politique_pendante_intacts` devient
// `pdp_terminaux_a_politique_pendante_degouvernes_et_comptes_a_part` (mutants AO3_*). Les témoins neufs sont dans
// `politique_sla_desactivee_degouverne_terminaux_et_fusionnes_pendants.rs`.
// =====================================================================================
mod politique_sla_desactivee_compte_ses_pendants {
    use super::*;

    const PDP_ENFANT: &str = "PDP_ENFANT_JOURNAL";
    const PDP_RENDU: &str = "PDP-RENDU";
    const PDP_MOTIF: &str = "pdp refus pendant";
    const PDP_PENDANT: i64 = 999;
    const PDP_SUFFIXE: &str = "dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)";

    fn pdp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pdp-{tag}"));
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

    fn pdp_editeur() -> AuthUser {
        AuthUser {
            name: "redacteur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn pdp_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pdp_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn pdp_details(st: &AppState) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare("SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id").unwrap();
        s.query_map([], |x| x.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn pdp_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé à la priorité donnée, puis `UPDATE incident SET <reglage> WHERE id=<id>`.
    fn pdp_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            pdp_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// Dossier qui porte une politique et deux échéances (échues ou non, sans effet ici).
    fn pdp_gouverne(st: &AppState, titre: &str, priorite: i64, politique: i64, extra: &str) -> i64 {
        let e = now() + 1000;
        let reglage = format!("sla_policy_id={politique}, ack_due={e}, resolve_due={e}{extra}");
        pdp_dossier(st, titre, priorite, &reglage)
    }

    fn pdp_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }

    async fn pdp_upsert(st: &AppState, corps: Value) -> (u16, Vec<u8>) {
        let rep = sla_policy_upsert(State(st.clone()), Extension(pdp_editeur()), Json(corps)).await.into_response();
        let statut = rep.status().as_u16();
        (statut, axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn pdp_desactiver_p1() -> Value {
        json!({ "name": "P1", "priority": 1, "ack_target_s": 60, "resolve_target_s": 600, "enabled": false })
    }

    fn pdp_detail(degouvernes: usize, pendants: usize) -> String {
        let mut d = "P1 ack=60s resolve=600s enabled=0 by redacteur".to_string();
        if degouvernes > 0 {
            d.push_str(&format!(" ; {degouvernes} {PDP_SUFFIXE}"));
        }
        if pendants > 0 {
            d.push_str(&format!(", dont {pendants} dossier(s) actif(s) à politique pendante ou étrangère"));
        }
        d
    }

    /// `pdp_detail` suivi de la mention des terminaux ou fusionnés (vague AO), écrite seulement quand il y en a.
    fn pdp_detail_terminaux(degouvernes: usize, pendants: usize, terminaux: usize) -> String {
        let mut d = pdp_detail(degouvernes, pendants);
        if terminaux > 0 {
            d.push_str(&format!(", dont {terminaux} dossier(s) terminal(aux) ou fusionné(s) à politique pendante ou étrangère"));
        }
        d
    }

    /// Le cinq cents de l'upsert, corps ENTIER : `{id, reason, recomputed}`, la phrase fixe, `recomputed` 0.
    fn pdp_cinq_cents(statut: u16, corps: &[u8], motif: &str) -> String {
        let v: Value = serde_json::from_slice(corps).unwrap_or(Value::Null);
        assert_eq!(statut, 500, "{motif} : 500, jamais une désactivation annoncée : {v}");
        let mut cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        cles.sort_unstable();
        assert_eq!(cles, ["id", "reason", "recomputed"], "{motif} : ensemble exact des clés : {v}");
        assert_eq!(v["recomputed"], json!(0), "{motif} : {v}");
        assert_eq!(v["reason"], json!(crate::handlers::caseops::CAUSE_POLITIQUE_SLA_NON_ENREGISTREE), "{motif} : la phrase seule : {v}");
        let id = v["id"].as_str().unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "{motif} : identifiant servi : {v}");
        id
    }

    /// CE QU'IL TIENT (bord 2, maillon inscrit) : sous P1, A gouverné par P1 ; D actif à politique PENDANTE ; E actif de
    /// priorité 1 à politique ÉTRANGÈRE (celle de P2, active). Désactiver P1 -> 204 muet ; les trois au régime legacy ;
    /// registre « … ; 3 dossier(s) dégouverné(s) … , dont 2 dossier(s) actif(s) à politique pendante ou étrangère ».
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_DETAIL_OMIS` (le « dont » absent), `AN3_DEGOUVERNES_SANS_PENDANTS` (« 1
    /// dossier(s) »), `AN3_ORDRE_INVERSE` (second `UPDATE` avant celui de la politique : « dont 3 »).
    #[tokio::test]
    async fn pdp_bord_deux_pendant_et_etranger_comptes_au_registre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le gestionnaire lit l'environnement
        let (st, _t) = pdp_etat("deux");
        let p1 = pdp_politique(&st, "P1", 1);
        let p2 = pdp_politique(&st, "P2", 2);
        let a = pdp_gouverne(&st, "A", 1, p1, "");
        let d = pdp_gouverne(&st, "D", 1, PDP_PENDANT, "");
        let e = pdp_gouverne(&st, "E", 1, p2, "");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "désactivation complète, maillon inscrit : 204 muet");
        for (nom, id) in [("A", a), ("D", d), ("E", e)] {
            assert_eq!(pdp_chrono(&st, id), (None, None, None), "{nom} au régime legacy");
        }
        assert_eq!(pdp_details(&st), vec![pdp_detail(3, 2)], "le registre compte les trois, dont les deux non gouvernés par P1");
    }

    /// CE QU'IL TIENT (bord 1) : P1 ne gouverne aucun dossier ; D seul, actif à politique pendante. Désactiver P1 -> 204,
    /// D au régime legacy, registre « … ; 1 dossier(s) dégouverné(s) …, dont 1 … ».
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_BORD_UN` (`pendants > 1`).
    #[tokio::test]
    async fn pdp_bord_un_pendant_seul_au_registre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("un");
        let _p1 = pdp_politique(&st, "P1", 1);
        let d = pdp_gouverne(&st, "D", 1, PDP_PENDANT, "");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(pdp_chrono(&st, d), (None, None, None), "D au régime legacy");
        assert_eq!(pdp_details(&st), vec![pdp_detail(1, 1)], "un seul pendant : le registre le dit");
    }

    /// CE QU'IL TIENT (bord 0) : A seul, gouverné par P1, aucun pendant. Désactiver P1 -> 204, registre « … ; 1 dossier(s)
    /// dégouverné(s) … (régime legacy) » sans « dont ».
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_BORD_ZERO` (« , dont 0 … » écrit).
    #[tokio::test]
    async fn pdp_bord_zero_pendant_sans_mention() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("zero");
        let p1 = pdp_politique(&st, "P1", 1);
        let a = pdp_gouverne(&st, "A", 1, p1, "");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(pdp_chrono(&st, a), (None, None, None));
        assert_eq!(pdp_details(&st), vec![pdp_detail(1, 0)], "aucun pendant : aucune mention");
    }

    /// CE QU'IL TIENT (corps sans maillon) : maillon refusé (trigger sur `ledger`) ; A gouverné par P1, D pendant.
    /// Désactiver P1 -> 200, corps ENTIER `{degouvernes: 2, recomputed: 0, registre_sans_maillon}` : D compté une fois, dans
    /// `degouvernes`, plus dans `recomputed`.
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_DOUBLE_COMPTE` (remède « compter sans effacer » : D compté dans la transaction
    /// puis effacé et compté par le recalcul rejoué, `recomputed` 1), `AN3_DEGOUVERNES_SANS_PENDANTS` (`degouvernes` 1).
    #[tokio::test]
    async fn pdp_sans_maillon_pendant_dans_degouvernes_pas_dans_recomputed() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("corps");
        let p1 = pdp_politique(&st, "P1", 1);
        let a = pdp_gouverne(&st, "A", 1, p1, "");
        let d = pdp_gouverne(&st, "D", 1, PDP_PENDANT, "");
        pdp_sql(&st, "CREATE TEMP TRIGGER pdp_reg BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'pdp reg'); END;");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        pdp_sql(&st, "DROP TRIGGER pdp_reg;");
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "maillon manquant : 200 ({v})");
        let attendu = json!({
            "degouvernes": 2,
            "recomputed": 0,
            CLE_REGISTRE_SANS_MAILLON: format!("{CAUSE_GESTE_SANS_TRACE} ({})", crate::ledger::CAUSE_MAILLON_NON_ECRIT),
        });
        assert_eq!(v, attendu, "corps entier : les deux dans `degouvernes`, aucun recalcul compté");
        for (nom, id) in [("A", a), ("D", d)] {
            assert_eq!(pdp_chrono(&st, id), (None, None, None), "{nom} au régime legacy");
        }
        assert!(pdp_details(&st).is_empty(), "aucun maillon n'est entré");
    }

    /// Désactive P1 sur une base où rien ne doit être dégouverné, et vérifie l'intact : 204, chrono inchangé, registre
    /// sans compte.
    async fn pdp_intact_apres_desactivation(st: &AppState, id: i64, nom: &str) {
        let avant = pdp_chrono(st, id);
        assert_eq!(avant.0, Some(PDP_PENDANT), "fixture : {nom} porte une politique pendante");
        let (statut, corps) = pdp_upsert(st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "{nom} : 204 muet");
        assert_eq!(pdp_chrono(st, id), avant, "{nom} n'est pas dans le périmètre de l'effacement : intact");
        assert_eq!(pdp_details(st), vec![pdp_detail(0, 0)], "{nom} : rien compté au registre");
    }

    /// INVERSÉ en vague AO (`P10.31-v`) : il s'appelait `pdp_fusionne_a_politique_pendante_intact` et affirmait F intact
    /// et non compté. CE QU'IL TIENT désormais : F, FUSIONNÉ (statut actif `triage`, pour isoler la clause de fusion de
    /// celle du statut), à politique pendante, est effacé dans la transaction et compté À PART des actifs.
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_FUSION_REVENUE` (troisième `UPDATE` avec `merged_into IS NULL`).
    #[tokio::test]
    async fn pdp_fusionne_a_politique_pendante_degouverne_et_compte_a_part() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("fusion");
        let _p1 = pdp_politique(&st, "P1", 1);
        let x = pdp_dossier(&st, "X", 3, "");
        let f = pdp_gouverne(&st, "F", 1, PDP_PENDANT, &format!(", merged_into={x}, status='triage'"));
        assert_eq!(pdp_chrono(&st, f).0, Some(PDP_PENDANT), "fixture : F porte une politique pendante");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "F fusionné : 204 muet");
        assert_eq!(pdp_chrono(&st, f), (None, None, None), "F fusionné au régime legacy");
        assert_eq!(pdp_details(&st), vec![pdp_detail_terminaux(1, 0, 1)], "F compté à part des actifs");
    }

    /// INVERSÉ en vague AO (`P10.31-v`) : il s'appelait `pdp_terminaux_a_politique_pendante_intacts` et affirmait les trois
    /// intacts et `pdp_detail(0, 0)`. CE QU'IL TIENT désormais : trois TERMINAUX non fusionnés (`resolved`, `closed`,
    /// `contained`) à politique pendante, effacés et comptés à part des actifs (« , dont 3 dossier(s) terminal(aux) … »).
    /// MUTATION QUI LE FAIT ROUGIR : `AO3_STATUT_REVENU` (troisième `UPDATE` avec le filtre de statut d'avant).
    #[tokio::test]
    async fn pdp_terminaux_a_politique_pendante_degouvernes_et_comptes_a_part() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("terminaux");
        let _p1 = pdp_politique(&st, "P1", 1);
        let r = pdp_gouverne(&st, "R", 1, PDP_PENDANT, ", status='resolved'");
        let c = pdp_gouverne(&st, "C", 1, PDP_PENDANT, ", status='closed'");
        let k = pdp_gouverne(&st, "K", 1, PDP_PENDANT, ", status='contained'");
        let (avant_r, avant_c, avant_k) = (pdp_chrono(&st, r), pdp_chrono(&st, c), pdp_chrono(&st, k));
        assert_eq!((avant_r.0, avant_c.0, avant_k.0), (Some(PDP_PENDANT), Some(PDP_PENDANT), Some(PDP_PENDANT)), "fixture : trois pendants");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(pdp_chrono(&st, r), (None, None, None), "resolved, terminal, au régime legacy");
        assert_eq!(pdp_chrono(&st, c), (None, None, None), "closed, terminal, au régime legacy");
        assert_eq!(pdp_chrono(&st, k), (None, None, None), "contained, terminal, au régime legacy");
        assert_eq!(pdp_details(&st), vec![pdp_detail_terminaux(3, 0, 3)], "les trois terminaux comptés à part des actifs");
    }

    /// CE QU'IL TIENT : V, actif de priorité 2 à politique pendante, n'est pas touché par la désactivation de P1.
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_SANS_PRIORITE` (prédicat sans `priority=?1`).
    #[tokio::test]
    async fn pdp_priorite_voisine_intacte() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("voisine");
        let _p1 = pdp_politique(&st, "P1", 1);
        let v = pdp_gouverne(&st, "V", 2, PDP_PENDANT, "");
        pdp_intact_apres_desactivation(&st, v, "V priorité 2").await;
    }

    /// CE QU'IL TIENT : L, actif de priorité 1 au régime legacy (`sla_policy_id` NULL) qui porte des échéances orphelines,
    /// n'est ni effacé ni compté (le recalcul ne le touchait pas non plus : `UPDATE` conditionné à une politique portée).
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_SANS_NON_NULL` (prédicat sans `sla_policy_id IS NOT NULL`).
    #[tokio::test]
    async fn pdp_actif_legacy_a_echeances_orphelines_intact() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("legacy");
        let _p1 = pdp_politique(&st, "P1", 1);
        let e = now() + 5000;
        let l = pdp_dossier(&st, "L", 1, &format!("sla_policy_id=NULL, ack_due={e}, resolve_due={e}"));
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]));
        assert_eq!(pdp_chrono(&st, l), (None, Some(e), Some(e)), "L legacy intact, échéances orphelines comprises");
        assert_eq!(pdp_details(&st), vec![pdp_detail(0, 0)], "L non compté");
    }

    /// Le scénario du second effacement refusé : trigger qui refuse l'effacement de l'échéance d'un dossier à politique
    /// pendante seulement. Rend le statut, le corps, et A, D.
    async fn pdp_jouer_le_refus_du_pendant(st: &AppState) -> (u16, Vec<u8>, i64, i64) {
        let p1 = pdp_politique(st, "P1", 1);
        let a = pdp_gouverne(st, "A", 1, p1, "");
        let d = pdp_gouverne(st, "D", 1, PDP_PENDANT, "");
        pdp_sql(
            st,
            &format!(
                "CREATE TEMP TRIGGER pdp_refus BEFORE UPDATE OF ack_due ON incident WHEN OLD.sla_policy_id={PDP_PENDANT} \
                 BEGIN SELECT RAISE(ABORT, '{PDP_MOTIF}'); END;"
            ),
        );
        let (statut, corps) = pdp_upsert(st, pdp_desactiver_p1()).await;
        pdp_sql(st, "DROP TRIGGER pdp_refus;");
        (statut, corps, a, d)
    }

    /// CE QU'IL TIENT : le SECOND effacement refusé (D pendant seul visé par le trigger ; celui de A, gouverné par P1,
    /// passe) -> 500 à corps entier, désactivation ANNULÉE : P1 active, A et D gardent leur chrono, rien au registre.
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_REFUS_AVALE` (`.unwrap_or(0)` : désactivation validée, D intact, 204),
    /// `AN3_HORS_TRANSACTION` (effacement joué hors de la transaction du geste).
    #[tokio::test]
    async fn pdp_effacement_des_pendants_refuse_annule_tout() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("refus");
        let (statut, corps, a, d) = pdp_jouer_le_refus_du_pendant(&st).await;
        pdp_cinq_cents(statut, &corps, "second effacement refusé");
        assert_eq!(pdp_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "P1 GOUVERNE toujours");
        assert_eq!(pdp_chrono(&st, a).0, pdp_entier(&st, "SELECT id FROM sla_policy WHERE priority=1"), "A toujours gouverné par P1");
        assert!(pdp_chrono(&st, a).1.is_some(), "A garde ses échéances (premier effacement annulé)");
        assert_eq!(pdp_chrono(&st, d).0, Some(PDP_PENDANT), "D garde sa politique pendante");
        assert!(pdp_chrono(&st, d).1.is_some(), "D garde ses échéances");
        assert!(pdp_details(&st).is_empty(), "rien au registre");
    }

    /// CE QU'IL TIENT : `BEGIN IMMEDIATE` refusé (transaction étrangère ouverte) avec D pendant -> 500 à corps entier ; D
    /// intact, lu AVANT le ROLLBACK de l'étrangère (une écriture faite dans cette transaction s'y verrait encore).
    /// Contrôle : ROLLBACK, la même désactivation aboutit et efface D.
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_HORS_TRANSACTION` (effacement des pendants hors du geste : il s'écrit dans la
    /// transaction étrangère).
    #[tokio::test]
    async fn pdp_begin_refuse_ne_touche_pas_le_pendant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("begin");
        let _p1 = pdp_politique(&st, "P1", 1);
        let d = pdp_gouverne(&st, "D", 1, PDP_PENDANT, "");
        let avant = pdp_chrono(&st, d);
        pdp_sql(&st, "BEGIN");
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert!(!st.db.lock().is_autocommit(), "la transaction étrangère reste ouverte");
        pdp_cinq_cents(statut, &corps, "BEGIN refusé");
        assert_eq!(pdp_chrono(&st, d), avant, "D intact (lu dans la transaction étrangère)");
        assert!(pdp_details(&st).is_empty(), "rien au registre");
        pdp_sql(&st, "ROLLBACK");
        assert_eq!(pdp_upsert(&st, pdp_desactiver_p1()).await.0, 204, "contrôle : la même désactivation aboutit");
        assert_eq!(pdp_chrono(&st, d), (None, None, None), "contrôle : D effacé");
    }

    /// CE QU'IL TIENT : `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par un trigger temporaire) avec D pendant -> 500 à
    /// corps entier ; D intact, P1 active, rien au registre, aucune transaction laissée ouverte.
    /// MUTATION QUI LE FAIT ROUGIR : `AN3_HORS_TRANSACTION` (effacement validé avant le `BEGIN`, il survit au refus).
    #[tokio::test]
    async fn pdp_commit_refuse_ne_touche_pas_le_pendant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _t) = pdp_etat("commit");
        let _p1 = pdp_politique(&st, "P1", 1);
        let d = pdp_gouverne(&st, "D", 1, PDP_PENDANT, "");
        let avant = pdp_chrono(&st, d);
        pdp_sql(
            &st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE pdp_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE pdp_enfant(p INTEGER REFERENCES pdp_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER pdp_fk AFTER UPDATE ON sla_policy BEGIN INSERT INTO pdp_enfant VALUES(999); END;",
        );
        let (statut, corps) = pdp_upsert(&st, pdp_desactiver_p1()).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
        pdp_cinq_cents(statut, &corps, "COMMIT refusé");
        assert_eq!(pdp_chrono(&st, d), avant, "D intact");
        assert_eq!(pdp_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "P1 GOUVERNE toujours");
        assert!(pdp_details(&st).is_empty(), "rien au registre");
    }

    /// CE QU'IL TIENT (journal, par capture en sous-processus) : le second effacement refusé écrit UNE ligne `[caseops]`,
    /// ENTIÈRE : `[caseops] WARN politique SLA NON enregistrée (<id servi>) : effacement des échéances des dossiers actifs à
    /// politique pendante ou étrangère refusé (<motif>)` — distincte de celle du premier effacement.
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_REFUS_AVALE` (aucune ligne), `AN3_JOURNAL_CONFONDU` (la phrase du premier
    /// effacement).
    #[tokio::test]
    async fn pdp_journal_du_refus_des_pendants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'enfant reçoit son environnement par `.env(`, le parent lit
        if std::env::var(PDP_ENFANT).is_ok() {
            let (st, _t) = pdp_etat("journal");
            let (statut, corps, _, _) = pdp_jouer_le_refus_du_pendant(&st).await;
            let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
            println!("{PDP_RENDU} {statut} {}", v["id"].as_str().unwrap_or("absent"));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::politique_sla_desactivee_compte_ses_pendants::pdp_journal_du_refus_des_pendants",
            ])
            .env(PDP_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (statut, id) = stdout
            .lines()
            .find_map(|l| l.split_once(PDP_RENDU))
            .and_then(|(_, r)| r.trim().split_once(' ').map(|(s, i)| (s.to_string(), i.to_string())))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a joué le refus : {stdout}\n{stderr}"));
        assert_eq!(statut, "500", "contrôle : l'enfant a lu le cinq cents : {stdout}");
        assert!(id.starts_with("plume-e"), "contrôle : identifiant servi : {stdout}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.contains("[caseops]")).collect();
        assert_eq!(
            lignes,
            vec![format!(
                "[caseops] WARN politique SLA NON enregistrée ({id}) : effacement des échéances des dossiers actifs à politique pendante ou étrangère refusé ({PDP_MOTIF})"
            )],
            "une ligne EXACTE, reliée au corps par l'identifiant :\n{stderr}"
        );
    }
}
