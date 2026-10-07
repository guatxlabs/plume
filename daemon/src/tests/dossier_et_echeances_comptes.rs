// =====================================================================================
// `P10.20-w` (rang trois, suite) — LA MISE À JOUR, L'ARCHIVAGE ET LE TICK SLA MULTI-NIVEAU COMPTENT LEUR
// ÉCRITURE AVANT LE FAIT.
//
// CE QUE CES TÉMOINS TIENNENT. `case_apply_update` (cases.rs) avalait les `UPDATE incident` de l'assignation,
// du statut et du verdict (posé ou effacé) puis posait la chronologie et une ligne `case.assign`/`case.status`/
// `case.disposition` au registre non purgeable, et la route rendait 204 ; `case_set_archived` faisait de même
// avec `case.archive`/`case.unarchive`. Et `sla_multilevel_tick` (caseops.rs) envoyait la notification, AVALAIT
// `UPDATE incident SET ack_breached|resolve_breached=1`, puis attestait le dépassement : le marqueur restant à 0,
// CHAQUE tick renvoyait la notification ET ajoutait un `case.sla_*_breach` au registre (désormais : la
// notification est renvoyée à chaque tour, AVOUANT le dépassement non enregistré, mais le registre se tait). Les
// témoins jouent la table `incident` rendue NON MODIFIABLE (vue temporaire de même nom, comme les témoins `ecf_`
// et `fec_` : la lecture passe, seule l'écriture échoue), comptent registre, chronologie et ENVOIS, puis
// rejouent la base saine pour prouver que la sortie d'avant est intacte (contrôle positif, textes relus).
//
// CE QU'ILS NE TIENNENT PAS : aucune base réellement en lecture seule ; les bras `Ok(0)` (dossier disparu
// entre la lecture et l'écriture) ne sont pas fabriqués ; une écriture refusée APRÈS une écriture réussie dans
// la même mise à jour (le 503 avoue que les champs précédents ont pu être écrits, aucun témoin ne le joue) ; les
// écritures SANS registre de `case_apply_update` (titre, sévérité, propriétaire, résumé, priorité, échéance,
// `updated`) restent avalées ; rien de ce que la console PEINT des trois 503 neufs ; aucun envoi réseau réel
// (l'envoyeur est injecté) ; `step_advance` (incidents.rs), dernier site du rang trois.
// =====================================================================================
mod dossier_et_echeances_comptes {
    use super::*;

    fn dec_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("dec-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-w` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM incident", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn dec_utilisateur(role: &str) -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn dec_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn dec_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn dec_texte(st: &AppState, sql: &str) -> Vec<String> {
        let conn = st.db.lock();
        let mut s = conn.prepare(sql).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn dec_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    fn dec_table_incident_non_modifiable(st: &AppState) {
        dec_ecrire(st, "ALTER TABLE incident RENAME TO incident_source; CREATE TEMP VIEW incident AS SELECT * FROM incident_source;");
    }

    fn dec_table_incident_modifiable(st: &AppState) {
        dec_ecrire(st, "DROP VIEW incident; ALTER TABLE incident_source RENAME TO incident;");
    }

    fn dec_dossier(st: &AppState) -> i64 {
        let conn = st.db.lock();
        dossier_seme(&conn, "alice", "Dossier", 3, "", None, 2)
    }

    const DEC_TRACES: &str = "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'case.%' AND kind <> 'case.create'";

    async fn dec_mettre_a_jour(st: &AppState, id: i64, corps: Value) -> (u16, Value) {
        pb_json(case_update(State(st.clone()), Extension(dec_utilisateur("editor")), Path(id), Json(corps)).await).await
    }

    /// CE QU'IL TIENT (`case_apply_update`, quatre sites) : chacune des quatre écritures attestées — assignation,
    /// statut, verdict effacé, verdict posé — que la base refuse rend `NonEcrite` NOMMANT son champ, sans ligne de
    /// registre ni élément de chronologie ; la route sert un 503 NOMMÉ au lieu du 204. Contrôle positif dans le même
    /// corps : la base saine rend 204 et les traces sont EXACTEMENT celles d'avant (textes relus).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, une par site : avaler l'`UPDATE` de l'assignation, du statut, du verdict
    /// effacé ou du verdict posé (le bras `Err` qui continue, la forme d'avant) — la fonction rend `Ecrite` et le
    /// registre gagne la ligne d'un champ non écrit.
    #[tokio::test]
    async fn dec_une_mise_a_jour_non_ecrite_n_est_ni_un_deux_cent_quatre_ni_une_ligne_de_registre() {
        let (st, _tmp) = dec_etat("mise-a-jour");
        let id = dec_dossier(&st);
        // le verdict effacé ne se joue que sur un dossier qui en porte un : posé AVANT la table figée.
        assert_eq!(dec_mettre_a_jour(&st, id, json!({ "disposition": "benign" })).await.0, 204, "fixture : un verdict est posé");

        dec_table_incident_non_modifiable(&st);
        let registre_avant = dec_compte(&st, DEC_TRACES);
        let chronologie_avant = dec_compte(&st, "SELECT COUNT(*) FROM incident_item");
        for (corps, champ) in [
            (json!({ "assignee": "carol" }), "assignee"),
            (json!({ "status": "in_progress" }), "status"),
            (json!({ "disposition": "" }), "disposition"),
            (json!({ "disposition": "true_positive" }), "disposition"),
        ] {
            let issue = {
                let conn = st.db.lock();
                case_apply_update(&conn, id, "analyste", &corps)
            };
            match &issue {
                IssueDuDossierModifie::NonEcrite(cause) => {
                    assert!(cause.starts_with(&format!("{champ}: ")), "la cause NOMME le champ refusé ({corps}) : {cause}")
                }
                autre => panic!("écriture refusée de {corps} : la fonction doit rendre `NonEcrite`, pas {autre:?}"),
            }
            assert_eq!(dec_compte(&st, DEC_TRACES), registre_avant, "aucune ligne de registre n'atteste {corps} non écrit");
            assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident_item"), chronologie_avant, "aucune chronologie ne raconte {corps}");
        }
        let (statut, avoue) = dec_mettre_a_jour(&st, id, json!({ "assignee": "carol", "status": "in_progress" })).await;
        assert_eq!(statut, 503, "mise à jour non écrite : 503 nommé, jamais un 204 : {avoue}");
        assert!(dec_phrase(&avoue).starts_with(CAUSE_MISE_A_JOUR_DU_DOSSIER_NON_ECRITE), "le refus NOMME sa cause : {avoue}");
        assert!(dec_phrase(&avoue).contains("(assignee: "), "le refus nomme le PREMIER champ refusé : {avoue}");
        assert_eq!(dec_compte(&st, DEC_TRACES), registre_avant, "la route n'atteste rien non plus");
        dec_table_incident_modifiable(&st);
        assert_eq!(
            dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND assignee IS NULL AND status<>'in_progress' AND disposition='benign'")),
            1,
            "rien n'a été écrit"
        );

        // CONTRÔLE POSITIF — la sortie d'avant, octet pour octet.
        let (statut, corps) = dec_mettre_a_jour(&st, id, json!({ "assignee": "carol", "status": "in_progress", "disposition": "true_positive" })).await;
        assert_eq!(statut, 204, "base saine : 204, comme avant : {corps}");
        assert_eq!(dec_mettre_a_jour(&st, id, json!({ "disposition": "" })).await.0, 204);
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND assignee='carol' AND status='in_progress' AND disposition IS NULL")), 1);
        assert_eq!(
            dec_texte(&st, "SELECT kind || ' ' || detail FROM ledger WHERE kind LIKE 'case.%' AND kind <> 'case.create' ORDER BY id"),
            vec![
                format!("case.disposition #{id} -> benign by analyste"),
                format!("case.assign #{id} -> carol by analyste"),
                format!("case.status #{id} -> in_progress by analyste"),
                format!("case.disposition #{id} -> true_positive by analyste"),
                format!("case.disposition #{id} -> (aucun) by analyste"),
            ]
        );
        assert_eq!(
            dec_texte(&st, &format!("SELECT body FROM incident_item WHERE incident_id={id} AND kind IN ('assign','status','disposition') ORDER BY id")),
            vec!["verdict -> benign", "assigné à carol", "statut -> in_progress", "verdict -> true_positive", "verdict effacé"]
        );
        // l'absence établie garde sa sortie d'avant (`false`).
        let conn = st.db.lock();
        assert_eq!(case_apply_update(&conn, 999_999, "analyste", &json!({ "status": "closed" })), IssueDuDossierModifie::DossierAbsent);
    }

    /// CE QU'IL TIENT (`case_set_archived`, deux sites) : l'archivage puis le désarchivage que la base refuse d'écrire
    /// sortent en 503 NOMMÉ, sans `case.archive`/`case.unarchive` au registre ni chronologie, et l'état du dossier n'a
    /// pas bougé ; la fonction rend `NonEcrite`. Contrôle positif : 204, `archived` basculé, traces d'avant relues.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, une par site : avaler l'`UPDATE` de l'archivage, ou celui du désarchivage —
    /// 204 et la ligne de registre sur un dossier qui n'a pas bougé.
    #[tokio::test]
    async fn dec_un_archivage_non_ecrit_laisse_le_dossier_en_place_et_le_registre_muet() {
        let (st, _tmp) = dec_etat("archivage");
        let id = dec_dossier(&st);
        let archiver = |st: &AppState| {
            let st = st.clone();
            async move { pb_json(case_archive(State(st), Extension(dec_utilisateur("admin")), Path(id)).await).await }
        };
        let desarchiver = |st: &AppState| {
            let st = st.clone();
            async move { pb_json(case_unarchive(State(st), Extension(dec_utilisateur("admin")), Path(id)).await).await }
        };

        // (a) ARCHIVAGE refusé.
        dec_table_incident_non_modifiable(&st);
        let registre_avant = dec_compte(&st, DEC_TRACES);
        let chronologie_avant = dec_compte(&st, "SELECT COUNT(*) FROM incident_item");
        let (statut, avoue) = archiver(&st).await;
        assert_eq!(statut, 503, "archivage non écrit : 503 nommé, jamais un 204 : {avoue}");
        assert!(dec_phrase(&avoue).starts_with(CAUSE_ARCHIVAGE_NON_ECRIT), "le refus NOMME sa cause : {avoue}");
        {
            let conn = st.db.lock();
            assert!(matches!(case_set_archived(&conn, id, "analyste", true), IssueDuDossierModifie::NonEcrite(_)), "la fonction NOMME l'écriture refusée");
        }
        assert_eq!(dec_compte(&st, DEC_TRACES), registre_avant, "aucune ligne `case.archive`");
        assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident_item"), chronologie_avant, "aucune chronologie");
        dec_table_incident_modifiable(&st);
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND archived=0")), 1, "le dossier n'est PAS archivé");

        // CONTRÔLE POSITIF de l'archivage, puis (b) DÉSARCHIVAGE refusé.
        assert_eq!(archiver(&st).await.0, 204, "base saine : 204, comme avant");
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND archived=1 AND archived_by='analyste'")), 1);
        dec_table_incident_non_modifiable(&st);
        let registre_avant = dec_compte(&st, DEC_TRACES);
        let chronologie_avant = dec_compte(&st, "SELECT COUNT(*) FROM incident_item");
        let (statut, avoue) = desarchiver(&st).await;
        assert_eq!(statut, 503, "désarchivage non écrit : 503 nommé, jamais un 204 : {avoue}");
        assert!(dec_phrase(&avoue).starts_with(CAUSE_DESARCHIVAGE_NON_ECRIT), "le refus NOMME sa cause : {avoue}");
        assert_eq!(dec_compte(&st, DEC_TRACES), registre_avant, "aucune ligne `case.unarchive`");
        assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident_item"), chronologie_avant, "aucune chronologie");
        dec_table_incident_modifiable(&st);
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND archived=1")), 1, "le dossier est TOUJOURS archivé");

        // CONTRÔLE POSITIF — la sortie d'avant, octet pour octet.
        assert_eq!(desarchiver(&st).await.0, 204, "base saine : 204, comme avant");
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND archived=0 AND archived_by IS NULL")), 1);
        assert_eq!(
            dec_texte(&st, "SELECT kind || ' ' || detail FROM ledger WHERE kind IN ('case.archive','case.unarchive') ORDER BY id"),
            vec![format!("case.archive #{id} by analyste"), format!("case.unarchive #{id} by analyste")]
        );
        assert_eq!(
            dec_texte(&st, &format!("SELECT body FROM incident_item WHERE incident_id={id} AND kind IN ('archive','unarchive') ORDER BY id")),
            vec!["Case archivé (masqué de la liste ; historique conservé)", "Case désarchivé (ré-affiché dans la liste)"]
        );
        let conn = st.db.lock();
        assert_eq!(case_set_archived(&conn, 999_999, "analyste", true), IssueDuDossierModifie::DossierAbsent, "l'absence garde sa sortie d'avant");
    }

    /// CE QU'IL TIENT (`sla_multilevel_tick`) : un marqueur de dépassement que la base refuse d'écrire ne fait PAS
    /// taire un SLA réellement dépassé — un dossier dont l'acquittement ET la résolution sont échus, sur DEUX ticks :
    /// quatre envois (un par échéance et par tick, renvoyés comme avant le lot), chacun AVOUANT
    /// `DEPASSEMENT_SLA_NON_ENREGISTRE` — mais ni `case.sla_*_breach` ni chronologie, et le refus compté UNE fois par
    /// TOUR (+2 pour deux ticks, pas +4). Contrôle positif : la base saine, deux ticks -> UN envoi par échéance, sans
    /// aveu, une ligne de registre et une chronologie chacune, aux textes d'avant.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : (a) bras `Err` qui trace comme un marqueur écrit (la forme d'avant le lot) ->
    /// registre et chronologie non vides ; (b) bras `Err` sans envoi -> zéro envoi (le correctif qui ferait taire une
    /// vraie accusation) ; (c) compter par dossier dans le bras `Err` -> +4 ; (d) envoyer le `detail` nu -> aveu absent.
    #[test]
    fn dec_un_marqueur_de_depassement_sla_non_ecrit_notifie_quand_meme_en_l_avouant_sans_s_inscrire_au_registre() {
        let (st, _tmp) = dec_etat("sla");
        let id = {
            let conn = st.db.lock();
            conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)", [])
                .unwrap();
            let id = dossier_seme(&conn, "alice", "Échu", 4, "", None, 1);
            conn.execute("UPDATE incident SET ack_due=?1, resolve_due=?1 WHERE id=?2", params![now() - 10, id]).unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('dec_canal','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
            id
        };
        let mut envois: Vec<(String, String)> = Vec::new();
        let aveugles = || crate::metrics::tick_aveugle_de("sla_multilevel_marqueur").map(|(n, _)| n).unwrap_or(0);
        let aveu = crate::handlers::caseops::DEPASSEMENT_SLA_NON_ENREGISTRE;
        let traces_sla = "SELECT COUNT(*) FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach')";

        dec_table_incident_non_modifiable(&st);
        let aveugles_avant = aveugles();
        for _ in 0..2 {
            sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, titre: &str, detail: &str, _h: &str, _t: i64| {
                envois.push((titre.to_string(), detail.to_string()));
                true
            });
        }
        assert_eq!(envois.len(), 4, "un SLA dépassé ne se TAIT pas : un envoi par échéance et par tick, malgré le marqueur refusé : {envois:?}");
        assert!(envois.iter().all(|(_, d)| d.ends_with(aveu)), "chaque envoi AVOUE le dépassement non enregistré : {envois:?}");
        assert_eq!(dec_compte(&st, traces_sla), 0, "aucun dépassement attesté au registre");
        assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident_item WHERE kind='sla'"), 0, "aucune chronologie");
        assert_eq!(aveugles(), aveugles_avant + 2, "le refus est COMPTÉ une fois par TOUR, pas une fois par échéance (/metrics)");
        dec_table_incident_modifiable(&st);
        assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident WHERE ack_breached=1 OR resolve_breached=1"), 0, "aucun marqueur n'est posé");

        // CONTRÔLE POSITIF — deux ticks sur la base saine : un envoi par échéance, sans aveu, une trace chacune.
        envois.clear();
        for _ in 0..2 {
            sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, titre: &str, detail: &str, _h: &str, _t: i64| {
                envois.push((titre.to_string(), detail.to_string()));
                true
            });
        }
        let ack = format!("Case #{id} « Échu » : SLA acquittement (MTTA) P1 dépassé.");
        let res = format!("Case #{id} « Échu » : SLA résolution (MTTR) P1 dépassé.");
        assert_eq!(
            envois,
            vec![("SLA acquittement (MTTA) : Échu".to_string(), ack.clone()), ("SLA résolution (MTTR) : Échu".to_string(), res.clone())],
            "UN envoi par échéance sur deux ticks, sans aveu"
        );
        assert_eq!(aveugles(), aveugles_avant + 2, "base saine : plus aucun refus compté");
        assert_eq!(dec_compte(&st, &format!("SELECT COUNT(*) FROM incident WHERE id={id} AND ack_breached=1 AND resolve_breached=1")), 1);
        assert_eq!(
            dec_texte(&st, "SELECT kind || ' ' || detail FROM ledger WHERE kind IN ('case.sla_ack_breach','case.sla_resolve_breach') ORDER BY id"),
            vec![format!("case.sla_ack_breach #{id} P1 acquittement (MTTA)"), format!("case.sla_resolve_breach #{id} P1 résolution (MTTR)")]
        );
        assert_eq!(dec_texte(&st, "SELECT body FROM incident_item WHERE kind='sla' ORDER BY id"), vec![ack, res]);
    }

    /// CE QU'IL TIENT (porte de `sla_multilevel_tick_par`) : quand `EXISTS(sla_policy)` ne SE LIT PAS, le tour est
    /// sauté — aucun envoi, aucun marqueur — mais il est COMPTÉ au balayage `sla_multilevel_politique` (`/metrics`),
    /// au lieu de passer pour « aucune politique ». La lecture est cassée par une vue temporaire de même nom sans
    /// colonne `enabled` (le `prepare` échoue). Contrôle positif : la vue retirée, le même tour notifie l'échéance.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rendre à la porte son `.unwrap_or(0)` d'avant -> compte inchangé.
    /// CE QU'IL NE TIENT PAS : une base réellement illisible ; ce que la console affiche du compteur.
    #[test]
    fn dec_une_porte_sla_multi_niveau_non_lue_saute_le_tour_en_le_comptant() {
        let (st, _tmp) = dec_etat("sla-porte");
        {
            let conn = st.db.lock();
            conn.execute("INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES('P1',1,60,600,1,0,'root',0)", [])
                .unwrap();
            let id = dossier_seme(&conn, "alice", "Échu", 4, "", None, 1);
            conn.execute("UPDATE incident SET ack_due=?1 WHERE id=?2", params![now() - 10, id]).unwrap();
            conn.execute(
                "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('dec_canal','webhook',1,'https://example.invalid/h',0,'{}')",
                [],
            )
            .unwrap();
        }
        let aveugles = || crate::metrics::tick_aveugle_de("sla_multilevel_politique").map(|(n, _)| n).unwrap_or(0);
        let mut envois = 0usize;

        dec_ecrire(&st, "CREATE TEMP VIEW sla_policy AS SELECT 1 AS sans_colonne_enabled;");
        let avant = aveugles();
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, _d: &str, _h: &str, _ts: i64| {
            envois += 1;
            true
        });
        assert_eq!(aveugles(), avant + 1, "une porte NON LUE est comptée, pas prise pour « aucune politique » (/metrics)");
        assert_eq!(envois, 0, "porte non lue : le tour est sauté");
        assert_eq!(dec_compte(&st, "SELECT COUNT(*) FROM incident WHERE ack_breached=1"), 0, "aucun marqueur posé");

        // CONTRÔLE POSITIF — la porte se relit : le même tour notifie et ne compte plus rien.
        dec_ecrire(&st, "DROP VIEW temp.sla_policy;");
        sla_multilevel_tick_par(&st.db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, _d: &str, _h: &str, _ts: i64| {
            envois += 1;
            true
        });
        assert_eq!(envois, 1, "porte lue : l'échéance est notifiée");
        assert_eq!(aveugles(), avant + 1, "porte lue : rien de plus compté");
    }
}
