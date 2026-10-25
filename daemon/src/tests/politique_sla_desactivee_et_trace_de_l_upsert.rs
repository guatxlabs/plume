// =====================================================================================
// `P10.31-v` (reste : désactivation d'une politique par `sla_policy_upsert`) + `P10.31-u` (maillon de `sla_policy.upsert`).
//
// CE QUI MANQUAIT, MESURÉ SUR 2e4fe6eb : `enabled=false` ne passait que par le recalcul, qui ne parcourt que les dossiers
// ACTIFS non fusionnés de la priorité. Un dossier TERMINAL ou FUSIONNÉ gardait `sla_policy_id`, `ack_due` et `resolve_due`
// d'une politique désactivée ; rouvert ou défusionné (aucun des deux ne rejouait `sla_apply_policy` — ils la rejouent depuis
// la vague AP, `P10.31-v`, témoins `prr_`), le tour le NOTIFIAIT en
// dépassement dès qu'une autre politique restait active. Le registre écrivait « P1 ack=… resolve=… by … » sans `enabled` :
// une désactivation y était indiscernable d'une modification, et son maillon était jeté (204 muet sans trace).
// CE QU'ILS TIENNENT : la population entière de la politique désactivée (actif, acquitté, en dépassement, en pause,
// terminal, fusionné) dégouvernée ; une autre priorité et un dossier non gouverné intacts ; le tour muet sur eux après
// réouverture, reprise, défusion, alors qu'il notifie toujours un dossier échu d'une politique active ; le détail du
// registre (`enabled=0|1`, compte) ; le maillon manquant avoué (200 + `registre_sans_maillon`) ; l'effacement refusé
// annule la désactivation (500, rien au registre) ; une MODIFICATION (enabled=1) ne dégouverne pas les terminaux.
// Correction (vérification indépendante) : bords 1 et 0 du compte relus au registre ; BEGIN et COMMIT refusés (500, rien
// posé) ; recalcul rejoué dans les deux sens — désactivation (actif à politique pendante rendu au legacy, forme de
// 2e4fe6eb) et modification (échéance recalculée) ; `reason` gardé quand le maillon manque.
// Seconde correction : `recomputed` non nul dans le corps tracé (pendant compté, gouverné pas deux fois — INVERSÉ en vague
// AN, voir plus bas) ; état du refus
// de BEGIN lu AVANT le ROLLBACK de l'étrangère ; au plafond, la désactivation ne dit plus « ancienne échéance » d'une
// population déjà effacée, et le vrai plafond (pendants) reste dit.
// CE QU'ILS NE TIENNENT PAS : la console (`web/`, aucun écran de politiques SLA) ; la réactivation qui ne regouverne
// pas les terminaux ni les fusionnés (limite écrite) ; les marqueurs `ack_breached`/`resolve_breached` passés, conservés
// à dessein ; la route HTTP de défusion et celle du changement de statut (appelées par leurs fonctions ; jouées par le
// routeur depuis la vague AP, témoins `prr_`).
// Mutants (VERIF_MUT=L8_*, retirés avant le commit) nommés sur chaque témoin.
// `P10.31-v` (vague AN) — TROIS TÉMOINS INVERSÉS : les actifs à politique PENDANTE ou ÉTRANGÈRE sont désormais effacés dans
// la transaction de la désactivation et comptés au registre et dans `degouvernes` ; le recalcul n'est plus rejoué à la
// désactivation (`recomputed` 0). Inversés nommément : `pde_desactivation_rejoue_le_recalcul_sur_un_actif_a_politique_pendante`
// (devenu `pde_desactivation_degouverne_un_actif_a_politique_pendante_dans_la_transaction`, détail du registre),
// `pde_desactivation_sans_maillon_compte_le_pendant_dans_recomputed` (devenu
// `pde_desactivation_sans_maillon_compte_le_pendant_dans_degouvernes`), et la partie contrôle de
// `pde_plafond_a_la_desactivation_sans_fausse_alerte`. Les témoins neufs sont dans
// `politique_sla_desactivee_compte_ses_pendants.rs` (mutants AN3_*).
// =====================================================================================
mod politique_sla_desactivee_et_trace_de_l_upsert {
    use super::*;

    fn pde_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("pde-{tag}"));
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

    fn pde_editeur() -> AuthUser {
        AuthUser {
            name: "redacteur".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn pde_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pde_entier(st: &AppState, sql: &str) -> Option<i64> {
        st.db.lock().query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).expect("fixture : la valeur se lit")
    }

    fn pde_details(st: &AppState) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare("SELECT detail FROM ledger WHERE kind='sla_policy.upsert' ORDER BY id").unwrap();
        s.query_map([], |x| x.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn pde_politique(st: &AppState, nom: &str, priorite: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Dossier semé, puis `UPDATE incident SET <reglage> WHERE id=<id>`.
    fn pde_dossier(st: &AppState, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = {
            let conn = st.db.lock();
            dossier_seme(&conn, "alice", titre, 4, "", None, priorite)
        };
        if !reglage.is_empty() {
            pde_sql(st, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        }
        id
    }

    fn pde_chrono(st: &AppState, id: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        st.db
            .lock()
            .query_row("SELECT sla_policy_id, ack_due, resolve_due FROM incident WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    }

    fn pde_tick(st: &AppState) -> Vec<String> {
        let mut envois: Vec<String> = Vec::new();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, detail: &str, _h: &str, _n: i64| {
            envois.push(detail.to_string());
            true
        });
        envois
    }

    async fn pde_upsert(st: &AppState, corps: Value) -> (u16, Vec<u8>) {
        let rep = sla_policy_upsert(State(st.clone()), Extension(pde_editeur()), Json(corps)).await.into_response();
        let statut = rep.status().as_u16();
        (statut, axum::body::to_bytes(rep.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    fn pde_desactiver_p1() -> Value {
        json!({ "name": "P1", "priority": 1, "ack_target_s": 60, "resolve_target_s": 600, "enabled": false })
    }

    /// CE QU'IL TIENT : sous P1, A actif échu, Q acquitté (ack figé, résolution échue), R déjà en dépassement
    /// d'acquittement, W en pause, T terminal, F fusionné ; sous P2 (active) B échu ; N (priorité 3) non gouverné à
    /// échéances orphelines. Désactiver P1 par l'upsert : 204 muet ; les six à (None, None, None) ; pause de W conservée ;
    /// B et N intacts ; registre « P1 … enabled=0 by redacteur ; 6 dossier(s) dégouverné(s) … ». Puis T rouvert, W repris,
    /// F défusionné : le tour ne notifie aucun des six, ne marque aucun dépassement neuf, et notifie B.
    /// MUTATIONS QUI LE FONT ROUGIR : `L8_SANS_DEGOUVERNEMENT` (le recalcul seul, comportement d'avant : T et F gardent
    /// leurs échéances et sont notifiés), `L8_WHERE_ELARGI` (B et N effacés), `L8_EXCLUT_TERMINAUX`, `L8_EXCLUT_FUSIONNES`,
    /// `L8_EXCLUT_ACQUITTES`, `L8_EXCLUT_DEPASSES`, `L8_EXCLUT_PAUSE`, `L8_ENABLED_OMIS` (détail du registre).
    #[tokio::test]
    async fn pde_desactiver_une_politique_degouverne_toute_sa_population() {
        let (st, _t) = pde_etat("pop");
        let p1 = pde_politique(&st, "P1", 1);
        let p2 = pde_politique(&st, "P2", 2);
        let n0 = now();
        let echu = n0 - 100;
        let pause_depuis = n0 - 100;
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}"));
        let q = pde_dossier(
            &st,
            "Q",
            1,
            &format!("sla_policy_id={p1}, ack_due={}, resolve_due={echu}, first_response_ts={}", n0 + 100_000, n0 - 50),
        );
        let r = pde_dossier(&st, "R", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={echu}, ack_breached=1", n0 - 200));
        let w = pde_dossier(
            &st,
            "W",
            1,
            &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}, status='waiting', sla_paused_since={pause_depuis}", n0 - 10_000, n0 - 10_000),
        );
        let t = pde_dossier(&st, "T", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}, status='resolved'"));
        let x = pde_dossier(&st, "X", 3, "");
        let f = pde_dossier(&st, "F", 1, &format!("sla_policy_id={p1}, ack_due={echu}, resolve_due={echu}, merged_into={x}, status='closed'"));
        let n = pde_dossier(&st, "N", 3, &format!("sla_policy_id=NULL, ack_due={}, resolve_due={}", n0 + 100_000, n0 + 100_000));
        let b = pde_dossier(&st, "B", 2, &format!("sla_policy_id={p2}, ack_due={echu}, resolve_due={echu}"));
        pde_sql(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pde','webhook',1,'https://example.invalid/h',0,'{}')");
        let chrono_n = pde_chrono(&st, n);
        let chrono_b = pde_chrono(&st, b);
        assert!(chrono_n.1.is_some() && chrono_b.0 == Some(p2), "fixture : N orphelin, B gouverné par P2");
        for (nom, id) in [("A", a), ("Q", q), ("R", r), ("W", w), ("T", t), ("F", f)] {
            assert_eq!(pde_chrono(&st, id).0, Some(p1), "fixture : {nom} gouverné par P1");
        }

        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "désactivation réussie, maillon inscrit : 204 muet");
        assert_eq!(pde_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(0), "P1 est désactivée en base");
        for (nom, id) in [("A actif", a), ("Q acquitté", q), ("R en dépassement", r), ("W en pause", w), ("T terminal", t), ("F fusionné", f)] {
            assert_eq!(pde_chrono(&st, id), (None, None, None), "{nom} est dégouverné par la désactivation");
        }
        assert_eq!(
            pde_entier(&st, &format!("SELECT sla_paused_since FROM incident WHERE id={w}")),
            Some(pause_depuis),
            "la pause en cours de W est conservée"
        );
        assert_eq!(pde_chrono(&st, b), chrono_b, "B, autre priorité, intact");
        assert_eq!(pde_chrono(&st, n), chrono_n, "N, non gouverné, intact");
        assert_eq!(
            pde_details(&st),
            vec![
                "P1 ack=60s resolve=600s enabled=0 by redacteur ; 6 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)"
                    .to_string()
            ],
            "le registre dit la DÉSACTIVATION et le compte exact"
        );

        // Réouverture par `UPDATE` direct et reprise : aucune ne rejoue `sla_apply_policy`. INVERSÉ NOMMÉMENT (`P10.31-v`,
        // vague AP) : `case_unmerge` la rejoue désormais (P1 désactivée : `RienAFaire` sur F déjà effacé) ; la route de
        // réouverture aussi (témoins `prr_`), ce témoin ne la joue pas.
        pde_sql(&st, &format!("UPDATE incident SET status='triage', closed_ts=NULL WHERE id={t}"));
        {
            let conn = st.db.lock();
            assert_eq!(
                crate::handlers::caseops::sla_on_status_change(&conn, w, "triage", now()),
                crate::handlers::caseops::IssueDuChronoSla::Ecrit,
                "W repris sans politique portée"
            );
        }
        pde_sql(&st, &format!("UPDATE incident SET status='triage' WHERE id={w}"));
        {
            let conn = st.db.lock();
            assert_eq!(crate::handlers::caseops::case_unmerge(&conn, f, "alice"), crate::handlers::caseops::IssueDeLaFusion::Ecrite, "F défusionné");
        }
        let envois = pde_tick(&st);
        for (nom, id) in [("A", a), ("Q", q), ("R", r), ("W", w), ("T", t), ("F", f)] {
            assert!(
                !envois.iter().any(|d| d.starts_with(&format!("Case #{id} "))),
                "{nom}, gouverné par une politique DÉSACTIVÉE, n'est pas notifié : {envois:?}"
            );
        }
        assert!(envois.iter().any(|d| d.starts_with(&format!("Case #{b} "))), "contrôle : B, échu sous P2 active, est notifié : {envois:?}");
        for (nom, id, attendu) in [("A", a, 0), ("Q", q, 0), ("R", r, 1), ("W", w, 0), ("T", t, 0), ("F", f, 0)] {
            assert_eq!(
                pde_entier(&st, &format!("SELECT ack_breached + resolve_breached FROM incident WHERE id={id}")),
                Some(attendu),
                "aucun dépassement neuf marqué sur {nom} (R garde son marqueur passé)"
            );
        }
    }

    /// CE QU'IL TIENT : le maillon `sla_policy.upsert` refusé (trigger `RAISE(ABORT)` sur `ledger`) — désactivation : 200 +
    /// `{degouvernes: 1, registre_sans_maillon}` (politique désactivée, dossier dégouverné : le geste a eu lieu) ;
    /// modification : 200 + `registre_sans_maillon`, sans `reason` (recalcul complet). Trigger retiré, modification
    /// nominale : 204, détail `enabled=1`, et le dossier TERMINAL d'une politique simplement MODIFIÉE garde son chrono.
    /// MUTATIONS QUI LE FONT ROUGIR : `L8_MAILLON_JETE` (204 muet sans trace), `L8_ENABLED_OMIS`, `L8_DEGOUVERNE_TOUJOURS`
    /// (une modification dégouvernerait le terminal).
    #[tokio::test]
    async fn pde_maillon_de_l_upsert_manquant_avoue_et_modification_sans_degouvernement() {
        let (st, _t) = pde_etat("maillon");
        let p1 = pde_politique(&st, "P1", 1);
        let p2 = pde_politique(&st, "P2", 2);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let t2 = pde_dossier(&st, "T2", 2, &format!("sla_policy_id={p2}, ack_due={}, resolve_due={}, status='resolved'", n0 - 100, n0 - 100));
        let chrono_t2 = pde_chrono(&st, t2);

        pde_sql(&st, "CREATE TEMP TRIGGER pde_registre BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'pde registre'); END;");
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "maillon manquant : jamais un 204 muet ({v})");
        assert_eq!(v["degouvernes"], json!(1), "le geste a eu lieu, le compte est servi : {v}");
        assert!(
            v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").starts_with(CAUSE_GESTE_SANS_TRACE),
            "la trace manquante est avouée : {v}"
        );
        assert_eq!(pde_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(0), "la désactivation a eu lieu");
        assert_eq!(pde_chrono(&st, a), (None, None, None), "A dégouverné");

        let modif = json!({ "name": "P2", "priority": 2, "ack_target_s": 120, "resolve_target_s": 1200 });
        let (statut, corps) = pde_upsert(&st, modif.clone()).await;
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "modification sans maillon : 200 ({v})");
        assert!(v[CLE_REGISTRE_SANS_MAILLON].is_string() && v.get("reason").is_none(), "aveu de trace, recalcul complet : {v}");
        pde_sql(&st, "DROP TRIGGER pde_registre;");
        assert!(pde_details(&st).is_empty(), "aucun maillon n'est entré");

        let (statut, corps) = pde_upsert(&st, modif).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "modification nominale : 204 muet");
        assert_eq!(pde_details(&st), vec!["P2 ack=120s resolve=1200s enabled=1 by redacteur".to_string()], "le registre dit enabled=1");
        assert_eq!(pde_chrono(&st, t2), chrono_t2, "une politique MODIFIÉE (non désactivée) ne dégouverne pas son terminal");
    }

    /// CE QU'IL TIENT : l'effacement des échéances refusé (trigger sur l'`UPDATE` d'`ack_due`) -> 500, la politique reste
    /// ACTIVE (désactivation annulée dans la même transaction), le dossier garde son chrono, rien au registre.
    #[tokio::test]
    async fn pde_effacement_refuse_annule_la_desactivation() {
        let (st, _t) = pde_etat("refus");
        let p1 = pde_politique(&st, "P1", 1);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let chrono_a = pde_chrono(&st, a);
        pde_sql(&st, "CREATE TEMP TRIGGER pde_refus BEFORE UPDATE OF ack_due ON incident BEGIN SELECT RAISE(ABORT, 'pde refus'); END;");
        let (statut, _) = pde_upsert(&st, pde_desactiver_p1()).await;
        pde_sql(&st, "DROP TRIGGER pde_refus;");
        assert_eq!(statut, 500, "rien n'a été posé");
        assert_eq!(pde_entier(&st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "la politique GOUVERNE toujours");
        assert_eq!(pde_chrono(&st, a), chrono_a, "le dossier garde son chrono");
        assert!(pde_details(&st).is_empty(), "rien au registre");
    }

    /// CE QU'IL TIENT (bords du compte au registre, maillon INSCRIT) : désactiver P1 qui gouverne UN SEUL dossier -> 204,
    /// détail « … enabled=0 by redacteur ; 1 dossier(s) dégouverné(s) … » relu au registre ; désactiver P3 qui n'en
    /// gouverne AUCUN -> 204, détail sans suffixe.
    /// MUTATIONS QUI LE FONT ROUGIR : `L8C_BORD_UN` (`degouvernes > 1`), `L8C_BORD_ZERO` (`degouvernes >= 0`).
    #[tokio::test]
    async fn pde_bord_un_dossier_et_zero_dossier_au_registre() {
        let (st, _t) = pde_etat("bord");
        let p1 = pde_politique(&st, "P1", 1);
        let _p3 = pde_politique(&st, "P3", 3);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "un dossier dégouverné, maillon inscrit : 204 muet");
        assert_eq!(pde_chrono(&st, a), (None, None, None), "A dégouverné");
        let p3_off = json!({ "name": "P3", "priority": 3, "ack_target_s": 60, "resolve_target_s": 600, "enabled": false });
        let (statut, _) = pde_upsert(&st, p3_off).await;
        assert_eq!(statut, 204, "aucun dossier dégouverné : 204");
        assert_eq!(
            pde_details(&st),
            vec![
                "P1 ack=60s resolve=600s enabled=0 by redacteur ; 1 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)"
                    .to_string(),
                "P3 ack=60s resolve=600s enabled=0 by redacteur".to_string(),
            ],
            "un dossier : le registre le dit ; aucun : pas de suffixe"
        );
    }

    fn pde_refus_de_transaction_ne_pose_rien(
        st: &AppState,
        a: i64,
        avant: (Option<i64>, Option<i64>, Option<i64>),
        statut: u16,
        corps: &[u8],
        motif: &str,
    ) {
        let corps: Value = serde_json::from_slice(corps).unwrap_or(Value::Null);
        assert_eq!(statut, 500, "{motif} : 500, jamais une désactivation annoncée : {corps}");
        // `P10.29-l` (vague AL) — INVERSÉ : un `starts_with` laissait passer le texte du moteur à la suite ; le corps ENTIER
        // `{recomputed: 0, reason: <phrase fixe>, id}`, la cause au journal.
        let mut cles: Vec<&str> = corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        cles.sort_unstable();
        assert_eq!(cles, ["id", "reason", "recomputed"], "{motif} : ensemble exact des clés : {corps}");
        assert_eq!(corps["recomputed"], json!(0), "{motif} : rien recalculé : {corps}");
        assert_eq!(corps["reason"], json!(crate::handlers::caseops::CAUSE_POLITIQUE_SLA_NON_ENREGISTREE), "{motif} : la phrase seule : {corps}");
        assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{motif} : identifiant servi : {corps}");
        assert_eq!(pde_entier(st, "SELECT enabled FROM sla_policy WHERE priority=1"), Some(1), "{motif} : P1 GOUVERNE toujours");
        assert_eq!(pde_chrono(st, a), avant, "{motif} : le dossier garde son chrono");
        assert!(pde_details(st).is_empty(), "{motif} : rien au registre");
    }

    /// CE QU'IL TIENT : le `BEGIN IMMEDIATE` du geste refusé (transaction étrangère ouverte sur la connexion d'écriture)
    /// -> 500 « politique NON enregistrée », P1 active, dossier intact, registre vide ; la transaction étrangère reste
    /// ouverte. L'état est lu AVANT le ROLLBACK de l'étrangère, sur la même connexion : une écriture faite dans cette
    /// transaction s'y voit encore (lue après, le ROLLBACK l'aurait effacée et le témoin aurait été vacant).
    /// Contrôle : ROLLBACK de l'étrangère, la même désactivation aboutit.
    /// MUTATIONS QUI LE FONT ROUGIR : `L8C_NONOUVERT_204` (BEGIN refusé rendu 204), `L8D_NONOUVERT_ECRIT` (le bras
    /// `NonOuvert` désactive P1, efface le dossier et écrit le maillon dans la transaction étrangère, puis rend 500).
    #[tokio::test]
    async fn pde_begin_refuse_ne_pose_rien() {
        let (st, _t) = pde_etat("begin");
        let p1 = pde_politique(&st, "P1", 1);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let avant = pde_chrono(&st, a);
        pde_sql(&st, "BEGIN");
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert!(!st.db.lock().is_autocommit(), "la transaction étrangère n'a été ni validée ni annulée par le geste");
        pde_refus_de_transaction_ne_pose_rien(&st, a, avant, statut, &corps, "BEGIN refusé (lu dans la transaction étrangère)");
        pde_sql(&st, "ROLLBACK");
        assert_eq!(pde_upsert(&st, pde_desactiver_p1()).await.0, 204, "contrôle : la même désactivation aboutit");
        assert_eq!(pde_chrono(&st, a), (None, None, None));
    }

    /// CE QU'IL TIENT : le `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par un trigger temporaire sur la mise à jour de
    /// la politique) -> 500, tout annulé : P1 active, dossier gouverné, registre vide, aucune transaction laissée ouverte.
    /// Contrôle : trigger levé, la même désactivation aboutit.
    /// MUTATION QUI LE FAIT ROUGIR : `L8C_NONVALIDE_204` (COMMIT refusé rendu 204).
    #[tokio::test]
    async fn pde_commit_refuse_ne_pose_rien() {
        let (st, _t) = pde_etat("commit");
        let p1 = pde_politique(&st, "P1", 1);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let avant = pde_chrono(&st, a);
        pde_sql(
            &st,
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE pde_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE pde_enfant(p INTEGER REFERENCES pde_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER pde_fk AFTER UPDATE ON sla_policy BEGIN INSERT INTO pde_enfant VALUES(999); END;",
        );
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte après le COMMIT refusé");
        pde_refus_de_transaction_ne_pose_rien(&st, a, avant, statut, &corps, "COMMIT refusé");
        pde_sql(&st, "DROP TRIGGER pde_fk;");
        assert_eq!(pde_upsert(&st, pde_desactiver_p1()).await.0, 204, "contrôle : la même désactivation aboutit");
        assert_eq!(pde_chrono(&st, a), (None, None, None));
    }

    /// CE QU'IL TIENT (sens « désactivation ») : un dossier ACTIF de P1 portant un `sla_policy_id` PENDANT (999 : politique
    /// supprimée avant `P10.31-v`, aucune clé étrangère), échu. Désactiver P1 -> 204, il est rendu au régime legacy (None,
    /// None, None) et le tour ne le notifie pas, alors qu'il notifie B, échu sous P2 active.
    /// INVERSÉ (vague AN) : il s'appelait `pde_desactivation_rejoue_le_recalcul_sur_un_actif_a_politique_pendante` et
    /// affirmait que le registre ne le comptait PAS (effacé par le recalcul rejoué après le `COMMIT`) ; il est désormais
    /// effacé dans la transaction et compté : « 1 dossier(s) dégouverné(s) …, dont 1 … ».
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_DETAIL_OMIS`, `AN3_DEGOUVERNES_SANS_PENDANTS` (registre).
    #[tokio::test]
    async fn pde_desactivation_degouverne_un_actif_a_politique_pendante_dans_la_transaction() {
        let (st, _t) = pde_etat("pendant");
        let _p1 = pde_politique(&st, "P1", 1);
        let p2 = pde_politique(&st, "P2", 2);
        let n0 = now();
        let echu = n0 - 100;
        let d = pde_dossier(&st, "D", 1, &format!("sla_policy_id=999, ack_due={echu}, resolve_due={echu}"));
        let b = pde_dossier(&st, "B", 2, &format!("sla_policy_id={p2}, ack_due={echu}, resolve_due={echu}"));
        pde_sql(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pde','webhook',1,'https://example.invalid/h',0,'{}')");
        assert_eq!(pde_chrono(&st, d), (Some(999), Some(echu), Some(echu)), "fixture : D porte une politique pendante");
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "désactivation complète : 204 muet");
        assert_eq!(pde_chrono(&st, d), (None, None, None), "D, actif de la priorité désactivée, est rendu au régime legacy");
        let envois = pde_tick(&st);
        assert!(!envois.iter().any(|x| x.starts_with(&format!("Case #{d} "))), "D n'est pas notifié : {envois:?}");
        assert!(envois.iter().any(|x| x.starts_with(&format!("Case #{b} "))), "contrôle : B est notifié : {envois:?}");
        assert_eq!(
            pde_details(&st),
            vec![
                "P1 ack=60s resolve=600s enabled=0 by redacteur ; 1 dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy), dont 1 dossier(s) actif(s) à politique pendante ou étrangère"
                    .to_string()
            ],
            "D, pendant, effacé par la désactivation : compté au registre"
        );
    }

    /// CE QU'IL TIENT (sens « modification ») : modifier P1 (120 s / 1200 s) recalcule l'échéance de son dossier ACTIF A
    /// (ack_due = ts + 120, resolve_due = ts + 1200) -> 204. Puis maillon refusé ET recalcul refusé (trigger sur l'`UPDATE
    /// OF resolve_due`) : modification (180 s / 1800 s) -> 200 avec `registre_sans_maillon` ET `reason` (l'échéance
    /// refusée de A y est nommée), `recomputed` 0, `degouvernes` 0 ; A garde l'échéance d'avant.
    /// MUTATIONS QUI LE FONT ROUGIR : `L8C_RECALC_JAMAIS` (aucun recalcul), `L8C_REASON_OMIS` (`reason` absent du corps
    /// quand le maillon manque).
    #[tokio::test]
    async fn pde_modification_recalcule_et_garde_la_raison_quand_le_maillon_manque() {
        let (st, _t) = pde_etat("modif");
        let p1 = pde_politique(&st, "P1", 1);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let ts = pde_entier(&st, &format!("SELECT ts FROM incident WHERE id={a}")).expect("fixture : ts du dossier");
        let (statut, corps) =
            pde_upsert(&st, json!({ "name": "P1", "priority": 1, "ack_target_s": 120, "resolve_target_s": 1200 })).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "modification complète : 204 muet");
        assert_eq!(pde_chrono(&st, a), (Some(p1), Some(ts + 120), Some(ts + 1200)), "l'échéance de A est recalculée");

        pde_sql(
            &st,
            "CREATE TEMP TRIGGER pde_reg BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'pde reg'); END;
             CREATE TEMP TRIGGER pde_rec BEFORE UPDATE OF resolve_due ON incident BEGIN SELECT RAISE(ABORT, 'pde rec'); END;",
        );
        let (statut, corps) =
            pde_upsert(&st, json!({ "name": "P1", "priority": 1, "ack_target_s": 180, "resolve_target_s": 1800 })).await;
        pde_sql(&st, "DROP TRIGGER pde_reg; DROP TRIGGER pde_rec;");
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "{v}");
        assert!(v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").starts_with(CAUSE_GESTE_SANS_TRACE), "trace manquante avouée : {v}");
        assert!(
            v["reason"].as_str().unwrap_or("").contains(&format!("#{a} ")),
            "le recalcul incomplet reste dit quand le maillon manque, dossier nommé : {v}"
        );
        assert_eq!((v["recomputed"].clone(), v["degouvernes"].clone()), (json!(0), json!(0)), "{v}");
        assert_eq!(pde_chrono(&st, a), (Some(p1), Some(ts + 120), Some(ts + 1200)), "A garde l'échéance d'avant");
        assert_eq!(pde_entier(&st, "SELECT ack_target_s FROM sla_policy WHERE priority=1"), Some(180), "la politique est écrite");
    }

    /// CE QU'IL TIENT (corps tracé) : maillon refusé ; A gouverné par P1, D actif de priorité 1 à politique PENDANTE (999).
    /// Désactiver P1 -> 200, `degouvernes` = 2 (A et D, effacés dans la transaction), `recomputed` = 0 (aucun recalcul
    /// rejoué, D n'est pas compté deux fois), pas de `reason` ; les deux à (None, None, None).
    /// INVERSÉ (vague AN) : il s'appelait `pde_desactivation_sans_maillon_compte_le_pendant_dans_recomputed` et affirmait le
    /// défaut — « degouvernes = 1 (A seul), recomputed = 1 (D seul) » : D effacé hors du compte du registre.
    /// MUTATIONS QUI LE FONT ROUGIR : `AN3_DOUBLE_COMPTE` (D compté dans la transaction puis par le recalcul rejoué),
    /// `AN3_DEGOUVERNES_SANS_PENDANTS` (`degouvernes` 1).
    #[tokio::test]
    async fn pde_desactivation_sans_maillon_compte_le_pendant_dans_degouvernes() {
        let (st, _t) = pde_etat("compte");
        let p1 = pde_politique(&st, "P1", 1);
        let n0 = now();
        let a = pde_dossier(&st, "A", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        let d = pde_dossier(&st, "D", 1, &format!("sla_policy_id=999, ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        pde_sql(&st, "CREATE TEMP TRIGGER pde_reg BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, 'pde reg'); END;");
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        pde_sql(&st, "DROP TRIGGER pde_reg;");
        let v: Value = serde_json::from_slice(&corps).unwrap_or(Value::Null);
        assert_eq!(statut, 200, "maillon manquant : 200 ({v})");
        assert!(v[CLE_REGISTRE_SANS_MAILLON].as_str().unwrap_or("").starts_with(CAUSE_GESTE_SANS_TRACE), "trace manquante avouée : {v}");
        assert_eq!(v["degouvernes"], json!(2), "A (gouverné par P1) et D (pendant), dégouvernés dans la transaction : {v}");
        assert_eq!(v["recomputed"], json!(0), "aucun recalcul rejoué à la désactivation : D pas compté deux fois : {v}");
        assert!(v.get("reason").is_none(), "recalcul complet : {v}");
        for (nom, id) in [("A", a), ("D", d)] {
            assert_eq!(pde_chrono(&st, id), (None, None, None), "{nom} au régime legacy");
        }
    }

    /// CE QU'IL TIENT (plafond à la désactivation) : P1 gouverne `SLA_RECOMPUTE_CAP` + 1 dossiers ACTIFS. La désactiver
    /// -> 204 muet : tous effacés dans la transaction, le recalcul ne relit que les actifs à `sla_policy_id` non NULL et
    /// ne dit plus « … gardent leur ANCIENNE échéance » d'une population déjà rendue au legacy (fausse alerte mesurée
    /// avant ce correctif : 200 + `reason` plafond, `recomputed` 0). Registre : `SLA_RECOMPUTE_CAP` + 1 dégouvernés.
    /// CONTRÔLE INVERSÉ (vague AN) : les mêmes dossiers reprennent une politique PENDANTE (999) et des échéances ; il
    /// affirmait « désactiver à nouveau -> 200, `reason` plafond, `recomputed` = `SLA_RECOMPUTE_CAP`, un dossier au-delà
    /// garde son ancienne échéance » (le recalcul rejoué, borné, effaçait les pendants). Désormais l'effacement des
    /// pendants est un `UPDATE` de la transaction, sans plafond : 204 muet, aucun ne garde son échéance, et le registre
    /// les compte tous (`SLA_RECOMPUTE_CAP` + 1, dont autant de pendants).
    /// Les mutants `L8D_FILTRE_*` visaient `sla_recalcule_la_priorite_desactivee`, retiré avec le recalcul de désactivation.
    #[tokio::test]
    async fn pde_plafond_a_la_desactivation_sans_fausse_alerte() {
        let (st, _t) = pde_etat("plafond");
        let p1 = pde_politique(&st, "P1", 1);
        let cap = crate::handlers::caseops::SLA_RECOMPUTE_CAP;
        let n0 = now();
        let graine = pde_dossier(&st, "G", 1, &format!("sla_policy_id={p1}, ack_due={}, resolve_due={}", n0 + 1000, n0 + 1000));
        pde_sql(
            &st,
            &format!(
                "INSERT INTO incident(ts,updated,title,status,severity,priority,sla_policy_id,ack_due,resolve_due) \
                 WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<{cap}) \
                 SELECT i.ts,i.updated,i.title||'-'||c.n,i.status,i.severity,i.priority,i.sla_policy_id,i.ack_due,i.resolve_due \
                 FROM incident i, c WHERE i.id={graine}"
            ),
        );
        let actifs_de_p1 = format!(
            "SELECT COUNT(*) FROM incident WHERE priority=1 AND sla_policy_id={p1} AND merged_into IS NULL \
             AND status NOT IN ('resolved','closed','contained')"
        );
        assert_eq!(pde_entier(&st, &actifs_de_p1), Some(cap + 1), "fixture : P1 gouverne PLAFOND + 1 actifs");

        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert_eq!(
            (statut, String::from_utf8_lossy(&corps).to_string()),
            (204, String::new()),
            "tous dégouvernés, rien ne garde d'ancienne échéance : 204 muet, pas d'aveu de plafond"
        );
        assert_eq!(
            pde_entier(&st, "SELECT COUNT(*) FROM incident WHERE sla_policy_id IS NOT NULL OR ack_due IS NOT NULL OR resolve_due IS NOT NULL"),
            Some(0),
            "les PLAFOND + 1 dossiers sont au régime legacy"
        );
        assert_eq!(
            pde_details(&st),
            vec![format!(
                "P1 ack=60s resolve=600s enabled=0 by redacteur ; {} dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy)",
                cap + 1
            )],
            "le registre compte la population entière"
        );

        // Contrôle (INVERSÉ, vague AN) : PLAFOND + 1 actifs à politique PENDANTE -> tous effacés dans la transaction, sans
        // plafond, et comptés au registre.
        pde_sql(&st, &format!("UPDATE incident SET sla_policy_id=999, ack_due={}, resolve_due={}", n0 - 100, n0 - 100));
        let (statut, corps) = pde_upsert(&st, pde_desactiver_p1()).await;
        assert_eq!(
            (statut, String::from_utf8_lossy(&corps).to_string()),
            (204, String::new()),
            "les pendants sont effacés dans la transaction : 204 muet, aucun aveu de plafond"
        );
        assert_eq!(
            pde_entier(&st, "SELECT COUNT(*) FROM incident WHERE sla_policy_id IS NOT NULL OR ack_due IS NOT NULL OR resolve_due IS NOT NULL"),
            Some(0),
            "aucun dossier, même au-delà de PLAFOND, ne garde son ancienne échéance"
        );
        assert_eq!(
            pde_details(&st).last().cloned(),
            Some(format!(
                "P1 ack=60s resolve=600s enabled=0 by redacteur ; {n} dossier(s) dégouverné(s) : sla_policy_id, ack_due et resolve_due effacés (régime legacy), dont {n} dossier(s) actif(s) à politique pendante ou étrangère",
                n = cap + 1
            )),
            "le registre compte tous les pendants"
        );
    }

    /// CE QU'IL TIENT (l'autre côté du filtre de désactivation) : un dossier ACTIF L de priorité 1 au régime legacy
    /// (`sla_policy_id` NULL, aucune échéance), aucune politique. CRÉER P1 (60 s / 600 s, `enabled` par défaut) -> 204,
    /// et L est gouverné : (id de P1, ts + 60, ts + 600). Le recalcul d'une politique ACTIVE relit TOUS les actifs de
    /// la priorité, pas seulement ceux qui portent déjà un `sla_policy_id`.
    /// MUTATION QUI LE FAIT ROUGIR : `L8D_FILTRE_A_LA_MODIF` (le filtre de désactivation appliqué aussi à une politique
    /// active : L resterait legacy, en silence, 204 compris).
    #[tokio::test]
    async fn pde_politique_active_gouverne_un_actif_legacy() {
        let (st, _t) = pde_etat("legacy");
        let l = pde_dossier(&st, "L", 1, "sla_policy_id=NULL, ack_due=NULL, resolve_due=NULL");
        let ts = pde_entier(&st, &format!("SELECT ts FROM incident WHERE id={l}")).expect("fixture : ts du dossier");
        assert_eq!(pde_chrono(&st, l), (None, None, None), "fixture : L au régime legacy");
        let (statut, corps) = pde_upsert(&st, json!({ "name": "P1", "priority": 1, "ack_target_s": 60, "resolve_target_s": 600 })).await;
        assert_eq!((statut, corps.as_slice()), (204, &b""[..]), "création complète : 204 muet");
        let p1 = pde_entier(&st, "SELECT id FROM sla_policy WHERE priority=1 AND enabled=1");
        assert!(p1.is_some(), "P1 créée et active");
        assert_eq!(pde_chrono(&st, l), (p1, Some(ts + 60), Some(ts + 600)), "L, actif legacy, est gouverné par la politique créée");
    }
}
