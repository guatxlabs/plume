// =====================================================================================
// `P10.31-v` (vague AZ) — le tour SLA multi-niveau ne marque ni ne notifie un dossier au nom d'une politique désactivée.
//
// CE QUI MANQUAIT, LU SUR 092aade9 : `sla_multilevel_tick_par` (caseops.rs) sélectionnait les échéances échues
// d'`incident` sans joindre `sla_policy`, sous un verrou RELÂCHÉ avant les marqueurs, et chaque envoi passe entre deux
// dossiers. Deux chemins menaient donc à un dépassement marqué et notifié au nom d'une politique désactivée ou supprimée :
//   · un ÉTAT ANCIEN (échéances laissées par une version antérieure aux effacements de l'upsert et de la suppression) :
//     marqué et NOTIFIÉ dès qu'une autre politique restait active (mesuré sur la fixture de l'état ancien : quarante
//     fausses alertes au premier tour, le dépassement réel ne sortant qu'au tour suivant, avec un tour de retard) ;
//     le « ne sort jamais » ne vaudrait que pour un filtre posé au seul marqueur, d'où le filtre dans les sélections ;
//     la gouvernance doit être celle de la politique DU DOSSIER (`p.id = sla_policy_id`), pas « une politique active
//     de la même priorité » : un identifiant pendant sous une nouvelle politique active de sa priorité reste jugé sinon ;
//   · une COURSE entre la sélection et le marqueur (verrou relâché, envois entre deux dossiers) : politique désactivée
//     ou MODIFIÉE par la route (échéances recalculées dans le futur), dossier résolu, acquitté ou mis en pause.
// REMÈDE : `GOUVERNE_PAR_UNE_POLITIQUE_ACTIVE` dans les deux sélections ; le marqueur relit le prédicat COMPLET de la
// sélection (`ACQUITTEMENT_SLA_ECHU`, `RESOLUTION_SLA_ECHUE`, au même instant) ET la gouvernance.
// CE QU'ILS TIENNENT : état ancien (dix dossiers à politique désactivée, dix à politique disparue) jamais marqué, et le
// dépassement réel sort au PREMIER tour ; identifiant pendant sous une politique active de la même priorité jamais
// jugé ; courses jouées depuis l'envoyeur : désactivation et modification par la route `sla_policy_upsert`, résolution,
// acquittement et pause ; réactivation et modification par la route décrites de bout en bout (comportement de l'upsert,
// en place avant ce correctif : ces deux-là ne témoignent pas du tour) ; le terminal garde son échéance historique
// (modification) ou reste au régime legacy (réactivation) : limite écrite, rejouée à la réouverture et à la défusion.
// CE QU'ILS NE TIENNENT PAS : les marqueurs `ack_breached`/`resolve_breached` déjà posés (conservés à dessein) ; une
// écriture entre la relecture du marqueur et l'envoi (le marqueur est validé AVANT l'envoi, l'envoi suit son verdict) ;
// une fusion dans la même fenêtre (`merged_into` relu par le marqueur, non témoignée ici) ; la console (aucun écran de
// politiques SLA).
// Mutants (VERIF_MUT=AZ4_* puis AZ4C_*, posés sous cfg!(test) puis retirés avant le commit) nommés sur chaque témoin.
// =====================================================================================
mod tick_sla_jamais_au_nom_d_une_politique_desactivee {
    use super::*;

    const TPD_PENDANTE: i64 = 999;

    fn tpd_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("tpd-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
            conn.execute("DELETE FROM sla_policy", []).unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('tpd','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn tpd_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("fixture : runtime")
    }

    fn tpd_editeur() -> AuthUser {
        AuthUser {
            name: "redacteur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn tpd_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn tpd_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn tpd_textes(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |x| x.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn tpd_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé (gouverné par la politique active de sa priorité), puis `UPDATE incident SET <reglage>`.
    fn tpd_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            tpd_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    /// (sla_policy_id, ack_due, resolve_due).
    fn tpd_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
    }

    fn tpd_ts(st: &AppState, id: i64) -> i64 {
        tpd_entier(st, &format!("SELECT ts FROM incident WHERE id={id}")).expect("ts")
    }

    async fn tpd_upsert(st: &AppState, corps: Value) -> (u16, Vec<u8>) {
        let rep = sla_policy_upsert(State(st.clone()), Extension(tpd_editeur()), Json(corps)).await.into_response();
        let statut = rep.status().as_u16();
        (statut, axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn tpd_p2(ack: i64, res: i64, actif: bool) -> Value {
        json!({ "name": "P2", "priority": 2, "ack_target_s": ack, "resolve_target_s": res, "enabled": actif })
    }

    fn tpd_tick(st: &AppState) -> Vec<String> {
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    fn tpd_attendus(id: i64, titre: &str, priorite: i64) -> Vec<String> {
        vec![
            format!("Case #{id} « {titre} » : SLA acquittement (MTTA) P{priorite} dépassé."),
            format!("Case #{id} « {titre} » : SLA résolution (MTTR) P{priorite} dépassé."),
        ]
    }

    fn tpd_breches(st: &AppState) -> Vec<String> {
        tpd_textes(st, "SELECT kind || ' ' || detail FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach') ORDER BY id")
    }

    fn tpd_marques(st: &AppState) -> Vec<String> {
        tpd_textes(
            st,
            "SELECT id || ':' || ack_breached || ':' || resolve_breached FROM incident WHERE ack_breached=1 OR resolve_breached=1 ORDER BY id",
        )
    }

    /// CE QU'IL TIENT (état ancien) : P1 active ; A (P1) échu de 10 s. Vingt dossiers plus anciens (échus de 1000 s) à
    /// politique NON active : dix gouvernés par P2 puis P2 désactivée par un `UPDATE` brut (la forme d'avant les
    /// effacements, échéances laissées), dix à politique disparue (identifiant pendant). Le tour notifie A (acquittement
    /// et résolution, détails entiers), ne marque que A, n'inscrit que les deux dépassements de A.
    /// MUTATIONS QUI LE FONT ROUGIR : `AZ4_SELECTION_ACK` (filtre retiré de la sélection des acquittements : les vingt
    /// occupent la fenêtre, A n'est pas notifié en acquittement), `AZ4_SELECTION_RES` (idem en résolution),
    /// `AZ4_ENABLED_OMIS` (`p.enabled=1` retiré : les dix de P2 marqués et notifiés), `AZ4_TOUJOURS_FAUX` (plus rien ne
    /// sort, A compris).
    #[test]
    fn tpd_etat_ancien_a_politique_desactivee_ou_disparue_jamais_marque_et_ne_masque_pas_un_vrai_depassement() {
        let (st, _t) = tpd_etat("ancien");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        let graine = tpd_dossier(&st, "D", 2, &format!("ack_due={}, resolve_due={}", n0 - 1000, n0 - 1000));
        assert_eq!(tpd_chrono(&st, graine).0, Some(p2), "fixture : la graine est gouvernée par P2");
        tpd_sql(
            &st,
            &format!(
                "INSERT INTO incident(ts,updated,title,status,severity,priority,sla_policy_id,ack_due,resolve_due) \
                 WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<9) \
                 SELECT i.ts,i.updated,i.title||'-'||c.n,i.status,i.severity,i.priority,i.sla_policy_id,i.ack_due,i.resolve_due \
                 FROM incident i, c WHERE i.id={graine}; \
                 INSERT INTO incident(ts,updated,title,status,severity,priority,sla_policy_id,ack_due,resolve_due) \
                 WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<10) \
                 SELECT i.ts,i.updated,'X-'||c.n,i.status,i.severity,i.priority,{TPD_PENDANTE},i.ack_due,i.resolve_due \
                 FROM incident i, c WHERE i.id={graine}; \
                 UPDATE sla_policy SET enabled=0 WHERE id={p2};"
            ),
        );
        assert_eq!(
            tpd_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE sla_policy_id={p2} AND ack_due<{} AND resolve_due<{}", n0 - 10, n0 - 10)),
            Some(10),
            "fixture : dix dossiers à politique désactivée, plus anciens que A"
        );
        assert_eq!(
            tpd_entier(&st, &format!("SELECT COUNT(*) FROM incident WHERE sla_policy_id={TPD_PENDANTE} AND ack_due<{} AND resolve_due<{}", n0 - 10, n0 - 10)),
            Some(10),
            "fixture : dix dossiers à politique disparue, plus anciens que A"
        );

        let envois = tpd_tick(&st);
        assert_eq!(envois, tpd_attendus(a, "A", 1), "seul A est notifié, en acquittement ET en résolution");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1")], "seul A est marqué");
        assert_eq!(
            tpd_breches(&st),
            vec![format!("case.sla_ack_breach #{a} P1 acquittement (MTTA)"), format!("case.sla_resolve_breach #{a} P1 résolution (MTTR)")],
            "seuls les dépassements de A entrent au registre"
        );
        assert_eq!(tpd_tick(&st), Vec::<String>::new(), "tour suivant : rien de neuf (A déjà marqué, les vingt jamais)");
    }

    /// CE QU'IL TIENT (course) : P1 et P2 actives ; A (P1) échu de 100 s, B (P2) échu de 10 s. Le tour sélectionne A et
    /// B ; au PREMIER envoi (acquittement de A, verrou relâché), l'envoyeur désactive P2 par la route `sla_policy_upsert`
    /// (204, B dégouverné, registre « 1 dossier(s) dégouverné(s) »). B n'est ensuite ni marqué ni notifié, ni en
    /// acquittement ni en résolution ; A l'est deux fois.
    /// MUTATION QUI LE FAIT ROUGIR : `AZ4C_MARQUEUR_NU` (marqueur de la base, ni échéance ni gouvernance relues : B
    /// marqué et notifié au nom de P2 désactivée). Depuis la correction, l'échéance relue suffit à elle seule ici (la
    /// route efface les échéances) : retirer la seule gouvernance du marqueur le laisse vert, voir le témoin suivant.
    #[test]
    fn tpd_politique_desactivee_par_la_route_entre_la_selection_et_le_marqueur_ne_marque_pas() {
        let rt = tpd_runtime();
        let (st, _t) = tpd_etat("course");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        let b = tpd_dossier(&st, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        assert_eq!(tpd_chrono(&st, b).0, Some(p2), "fixture : B gouverné par P2");

        let mut envois: Vec<String> = Vec::new();
        let mut desactivation: Option<(u16, Vec<u8>)> = None;
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            if desactivation.is_none() {
                desactivation = Some(rt.block_on(tpd_upsert(&st, tpd_p2(60, 600, false))));
            }
            true
        });
        assert_eq!(desactivation, Some((204, Vec::new())), "la désactivation concurrente a eu lieu, par la route");
        assert_eq!(tpd_chrono(&st, b), (None, None, None), "B dégouverné par la désactivation");
        assert_eq!(
            tpd_textes(&st, "SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id"),
            vec!["P2 ack=60s resolve=600s enabled=0 by redacteur ; 1 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)".to_string()]
        );
        assert_eq!(envois, tpd_attendus(a, "A", 1), "B, sélectionné avant la désactivation, n'est pas notifié");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1")], "B n'est pas marqué au nom de P2 désactivée");
        assert_eq!(
            tpd_breches(&st),
            vec![format!("case.sla_ack_breach #{a} P1 acquittement (MTTA)"), format!("case.sla_resolve_breach #{a} P1 résolution (MTTR)")]
        );
    }

    /// CE QU'IL TIENT (désactivation puis réactivation par la route) : P1 active (le tour tourne) ; B actif (P2) et T
    /// terminal (P2), tous deux anciens (`ts` reculé de 100 000 s). Désactiver P2 : B et T dégouvernés, le tour ne
    /// notifie rien. Réactiver P2 (mêmes cibles) : 204, B regouverné (P2, ts + 60, ts + 600) et notifié en acquittement et
    /// en résolution ; T reste au régime legacy (limite écrite : rejoué à la réouverture) ; registre `enabled=1`.
    /// DESCRIPTION DE BOUT EN BOUT, PAS UN TÉMOIN DU TOUR : vert aussi sans le prédicat de gouvernance (l'upsert efface
    /// déjà les échéances à la désactivation) ; il tient l'upsert et la fin de chaîne par le tour.
    /// MUTATIONS QUI LE FONT ROUGIR : `AZ4_MODIF_SANS_RECALCUL` (la réactivation ne recalcule pas : B reste legacy, rien
    /// ne sort), `AZ4_TOUJOURS_FAUX` (B regouverné mais jamais notifié).
    #[test]
    fn tpd_reactivation_par_la_route_regouverne_l_actif_et_le_tour_le_juge() {
        let rt = tpd_runtime();
        let (st, _t) = tpd_etat("reactivation");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let b = tpd_dossier(&st, "B", 2, "");
        let t = tpd_dossier(&st, "T", 2, "status='closed'");
        tpd_sql(&st, &format!("UPDATE incident SET ts=ts-100000, ack_due=ack_due-100000, resolve_due=resolve_due-100000 WHERE id IN ({b},{t})"));
        let ts_b = tpd_ts(&st, b);
        assert_eq!(tpd_chrono(&st, t), (Some(p2), Some(tpd_ts(&st, t) + 60), Some(tpd_ts(&st, t) + 600)), "fixture : T gouverné par P2");

        assert_eq!(rt.block_on(tpd_upsert(&st, tpd_p2(60, 600, false))), (204, Vec::new()), "désactivation : 204");
        assert_eq!((tpd_chrono(&st, b), tpd_chrono(&st, t)), ((None, None, None), (None, None, None)), "B et T dégouvernés");

        assert_eq!(rt.block_on(tpd_upsert(&st, tpd_p2(60, 600, true))), (204, Vec::new()), "réactivation : 204, recalcul complet");
        assert_eq!(tpd_chrono(&st, b), (Some(p2), Some(ts_b + 60), Some(ts_b + 600)), "B regouverné par P2 depuis son ts");
        assert_eq!(tpd_chrono(&st, t), (None, None, None), "T terminal reste au régime legacy (limite écrite)");
        assert_eq!(
            tpd_textes(&st, "SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id").last().cloned(),
            Some("P2 ack=60s resolve=600s enabled=1 by redacteur".to_string())
        );
        assert_eq!(tpd_tick(&st), tpd_attendus(b, "B", 2), "B, regouverné et échu, est notifié");
        assert_eq!(tpd_marques(&st), vec![format!("{b}:1:1")]);
    }

    /// CE QU'IL TIENT (modification par la route) : P1 active, A (P1) échu de 10 s ; B actif (P2) et T terminal (P2),
    /// anciens (`ts` reculé de 100 000 s), échus sous 60 s / 600 s. Modifier P2 (1 000 000 s / 2 000 000 s) : 204, B
    /// recalculé (P2, ts + 1 000 000, ts + 2 000 000), T garde son échéance historique (limite écrite) ; le tour notifie A
    /// seul, B n'est plus jugé sur ses anciennes échéances ; registre `enabled=1` aux nouvelles cibles.
    /// DESCRIPTION DE BOUT EN BOUT, PAS UN TÉMOIN DU TOUR : la modification HORS course est tenue par l'upsert (en place
    /// avant ce correctif) ; la modification PENDANT le tour est tenue par
    /// `tpd_politique_modifiee_par_la_route_entre_la_selection_et_le_marqueur_ne_marque_pas`.
    /// MUTATION QUI LE FAIT ROUGIR : `AZ4_MODIF_SANS_RECALCUL` (B garde ses anciennes échéances et est notifié).
    #[test]
    fn tpd_modification_par_la_route_recalcule_l_actif_et_le_tour_ne_le_juge_plus_sur_l_ancienne_echeance() {
        let rt = tpd_runtime();
        let (st, _t) = tpd_etat("modification");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        let b = tpd_dossier(&st, "B", 2, "");
        let t = tpd_dossier(&st, "T", 2, "status='closed'");
        tpd_sql(&st, &format!("UPDATE incident SET ts=ts-100000, ack_due=ack_due-100000, resolve_due=resolve_due-100000 WHERE id IN ({b},{t})"));
        let ts_b = tpd_ts(&st, b);
        let chrono_t = tpd_chrono(&st, t);
        assert_eq!(tpd_chrono(&st, b), (Some(p2), Some(ts_b + 60), Some(ts_b + 600)), "fixture : B échu sous les anciennes cibles");

        assert_eq!(rt.block_on(tpd_upsert(&st, tpd_p2(1_000_000, 2_000_000, true))), (204, Vec::new()), "modification : 204");
        assert_eq!(tpd_chrono(&st, b), (Some(p2), Some(ts_b + 1_000_000), Some(ts_b + 2_000_000)), "B recalculé aux nouvelles cibles");
        assert_eq!(tpd_chrono(&st, t), chrono_t, "T terminal garde son échéance historique (limite écrite)");
        assert_eq!(
            tpd_textes(&st, "SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id"),
            vec!["P2 ack=1000000s resolve=2000000s enabled=1 by redacteur".to_string()]
        );
        assert_eq!(tpd_tick(&st), tpd_attendus(a, "A", 1), "B n'est plus jugé sur ses anciennes échéances");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1")]);
    }

    /// CE QU'IL TIENT (gouvernance = la politique DU DOSSIER) : P2 ACTIVE ; D (P2) porte un identifiant PENDANT (999,
    /// politique disparue, état ancien) et des échéances passées ; E (P2, gouverné par la P2 active) aussi échu, en
    /// contrôle. Le tour notifie et marque E seul ; D n'est ni notifié ni marqué. La fixture `tpd_etat_ancien` ne le
    /// tenait pas : ses dossiers pendants étaient en P2 désactivée, « politique disparue » et « aucune politique active
    /// pour la priorité » y étaient indiscernables.
    /// MUTATION QUI LE FAIT ROUGIR : `AZ4C_PRIORITE` (la gouvernance juge « une politique active de la même priorité » au
    /// lieu de la politique du dossier : D notifié et marqué).
    #[test]
    fn tpd_identifiant_pendant_sous_une_politique_active_de_meme_priorite_n_est_pas_juge() {
        let (st, _t) = tpd_etat("pendante-active");
        let p2 = tpd_politique(&st, "P2", 2);
        assert_ne!(p2, TPD_PENDANTE, "fixture : l'identifiant pendant n'est pas celui de P2");
        let n0 = now();
        let d = tpd_dossier(&st, "D", 2, &format!("sla_policy_id={TPD_PENDANTE}, ack_due={}, resolve_due={}", n0 - 1000, n0 - 1000));
        let e = tpd_dossier(&st, "E", 2, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        assert_eq!(tpd_chrono(&st, d), (Some(TPD_PENDANTE), Some(n0 - 1000), Some(n0 - 1000)), "fixture : D pendant et échu");
        assert_eq!(tpd_chrono(&st, e).0, Some(p2), "fixture : E gouverné par P2 active");

        assert_eq!(tpd_tick(&st), tpd_attendus(e, "E", 2), "seul E est notifié ; D (politique disparue) ne l'est pas");
        assert_eq!(tpd_marques(&st), vec![format!("{e}:1:1")], "D n'est pas marqué au nom de P2, qui n'est pas sa politique");
        assert_eq!(
            tpd_breches(&st),
            vec![format!("case.sla_ack_breach #{e} P2 acquittement (MTTA)"), format!("case.sla_resolve_breach #{e} P2 résolution (MTTR)")]
        );
    }

    /// CE QU'IL TIENT (course, modification) : P1 et P2 actives ; A (P1) échu de 100 s, B (P2) échu de 10 s. Au PREMIER
    /// envoi (acquittement de A), l'envoyeur MODIFIE P2 par la route (1 000 000 s / 2 000 000 s, 204) : B est recalculé
    /// dans le futur. B n'est ensuite ni marqué ni notifié ; A l'est deux fois.
    /// MUTATIONS QUI LE FONT ROUGIR : `AZ4C_MARQUEUR_ANCIEN` (marqueur de la première version : gouvernance seule, B
    /// marqué et notifié malgré une échéance future), `AZ4C_MARQUEUR_SANS_ECHEANCE` (échéance non relue).
    #[test]
    fn tpd_politique_modifiee_par_la_route_entre_la_selection_et_le_marqueur_ne_marque_pas() {
        let rt = tpd_runtime();
        let (st, _t) = tpd_etat("course-modif");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        let b = tpd_dossier(&st, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        let ts_b = tpd_ts(&st, b);

        let mut envois: Vec<String> = Vec::new();
        let mut modification: Option<(u16, Vec<u8>)> = None;
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            if modification.is_none() {
                modification = Some(rt.block_on(tpd_upsert(&st, tpd_p2(1_000_000, 2_000_000, true))));
            }
            true
        });
        assert_eq!(modification, Some((204, Vec::new())), "la modification concurrente a eu lieu, par la route");
        assert_eq!(tpd_chrono(&st, b), (Some(p2), Some(ts_b + 1_000_000), Some(ts_b + 2_000_000)), "B recalculé dans le futur");
        assert_eq!(envois, tpd_attendus(a, "A", 1), "B, sélectionné avant la modification, n'est pas notifié");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1")], "B n'est pas marqué sur une échéance qui n'est plus échue");
        assert_eq!(
            tpd_breches(&st),
            vec![format!("case.sla_ack_breach #{a} P1 acquittement (MTTA)"), format!("case.sla_resolve_breach #{a} P1 résolution (MTTR)")]
        );
    }

    /// CE QU'IL TIENT (course, état du dossier) : P1 active ; A échu de 100 s ; R, Q et Z (P1) échus de 10 s. Au PREMIER
    /// envoi (acquittement de A), R est résolu, Q acquitté (`first_response_ts`), Z mis en pause (`sla_paused_since`).
    /// Ensuite : Q reste notifié et marqué en RÉSOLUTION (seul son acquittement est acquis), R et Z ne sont ni notifiés ni
    /// marqués ; A l'est deux fois.
    /// MUTATIONS QUI LE FONT ROUGIR : `AZ4C_MARQUEUR_ANCIEN`, `AZ4C_MARQUEUR_SANS_ETAT` (état non relu : R, Q et Z marqués
    /// et notifiés en acquittement).
    #[test]
    fn tpd_dossier_resolu_acquitte_ou_mis_en_pause_entre_la_selection_et_le_marqueur_ne_marque_pas() {
        let (st, _t) = tpd_etat("course-etat");
        let _p1 = tpd_politique(&st, "P1", 1);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        let r = tpd_dossier(&st, "R", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        let q = tpd_dossier(&st, "Q", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));
        let z = tpd_dossier(&st, "Z", 1, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));

        let mut envois: Vec<String> = Vec::new();
        let mut fait = false;
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            if !fait {
                fait = true;
                tpd_sql(
                    &st,
                    &format!(
                        "UPDATE incident SET status='resolved' WHERE id={r}; \
                         UPDATE incident SET first_response_ts={n0} WHERE id={q}; \
                         UPDATE incident SET sla_paused_since={n0} WHERE id={z};"
                    ),
                );
            }
            true
        });
        let mut attendus = vec![format!("Case #{a} « A » : SLA acquittement (MTTA) P1 dépassé.")];
        attendus.push(format!("Case #{a} « A » : SLA résolution (MTTR) P1 dépassé."));
        attendus.push(format!("Case #{q} « Q » : SLA résolution (MTTR) P1 dépassé."));
        assert_eq!(envois, attendus, "R, Q (acquittement) et Z, sélectionnés avant le changement d'état, ne sont pas notifiés");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1"), format!("{q}:0:1")], "R et Z non marqués, Q en résolution seule");
    }

    /// CE QU'IL TIENT (course, politique désactivée SANS effacement) : P1 et P2 actives ; A (P1) échu de 100 s, B (P2)
    /// échu de 10 s. Au PREMIER envoi, P2 est désactivée par un `UPDATE` brut qui laisse les échéances de B (la forme
    /// d'avant les effacements de l'upsert, ou tout écrivain futur qui l'oublierait). B n'est ni marqué ni notifié : seule
    /// la gouvernance relue par le marqueur l'arrête, son échéance restant échue.
    /// MUTATION QUI LE FAIT ROUGIR : `AZ4C_MARQUEUR_SANS_GOUVERNANCE`.
    #[test]
    fn tpd_politique_desactivee_sans_effacement_entre_la_selection_et_le_marqueur_ne_marque_pas() {
        let (st, _t) = tpd_etat("course-brute");
        let _p1 = tpd_politique(&st, "P1", 1);
        let p2 = tpd_politique(&st, "P2", 2);
        let n0 = now();
        let a = tpd_dossier(&st, "A", 1, &format!("ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        let b = tpd_dossier(&st, "B", 2, &format!("ack_due={}, resolve_due={}", n0 - 10, n0 - 10));

        let mut envois: Vec<String> = Vec::new();
        let mut fait = false;
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            if !fait {
                fait = true;
                tpd_sql(&st, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
            }
            true
        });
        assert_eq!(tpd_chrono(&st, b), (Some(p2), Some(n0 - 10), Some(n0 - 10)), "B garde ses échéances échues");
        assert_eq!(envois, tpd_attendus(a, "A", 1), "B n'est pas notifié au nom de P2 désactivée");
        assert_eq!(tpd_marques(&st), vec![format!("{a}:1:1")], "B n'est pas marqué");
    }
}
