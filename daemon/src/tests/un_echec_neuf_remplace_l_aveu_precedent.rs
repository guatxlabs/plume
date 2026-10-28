// =====================================================================================================
// `P10.32-o` — UN ÉCHEC NEUF REMPLACE L'AVEU PRÉCÉDENT ; UNE LIGNE DE CACHE ILLISIBLE N'EST PAS UNE CHARGE VALIDE.
//
// LES DÉFAUTS (relevés par la vérification indépendante de la vague précédente, sans témoin capable de rougir) :
//  * la doc de `dashboards::joindre_l_echec_a_la_charge_valide` affirme qu'« un échec neuf remplace le précédent » dans
//    `stats.rafraichissement_en_echec`. Aucun témoin n'enchaînait deux échecs sur la même charge utile valide : garder
//    le premier aveu (`entry(..).or_insert`) restait vert, et une charge périmée qui échoue une deuxième fois aurait
//    servi la cause et l'instant du PREMIER échec ;
//  * `IssueDeLaChargeValide::Aucune` nomme trois cas (absence, corps d'échec, ligne illisible). La ligne illisible (une
//    charge en cache qui n'est pas du JSON) n'avait pas de témoin : la tenir pour une charge valide vide restait vert.
//
// TÉMOINS : (1) à la demande, par le point d'entrée du fil de rafraîchissement
// (`consigner_l_issue_du_rafraichissement`), deux échecs de classes différentes aux instants t1 puis t2, charge utile
// comparée EN ENTIER après chacun, puis servie par la route ; (2) au pré-chauffage (`rollups::cache_refresh_all_panels`),
// un aveu à t1 puis un échec d'une autre classe armé au cœur ; (3) une ligne illisible remplacée par le corps d'échec.
// Phrases écrites ici en littéraux, jamais empruntées à la production.
//
// MUTANTS (variable de mutation sous `cfg!(test)`, retirés du source avant le commit), chacun vu ROUGE :
//  AX1_AVEU_PREMIER_GARDE (le mutant de la vérification, premier aveu gardé) : (1), (2) ;
//  AX1_CAUSE_PREMIERE_GARDEE (instant renouvelé, cause du premier gardée) : (1), (2) ;
//  AX1_INSTANT_PREMIER_GARDE (cause renouvelée, instant du premier gardé) : (1), (2) ;
//  AX1_ILLISIBLE_TENU_VALIDE (ligne non JSON tenue pour une charge vide valide) : (3).
// =====================================================================================================

mod ax1_un_echec_neuf_remplace_l_aveu_precedent {
    use super::*;
    use crate::query_exec::EchecDeRequete;

    const AX1_REJETEE: &str = "requête REFUSÉE par le moteur (ce n'est pas un résultat vide) : syntaxe, champ, motif ou accès rejeté — rien n'est rendu ; le détail est au journal de l'exploitant.";
    const AX1_OCCUPEE: &str = "REQUÊTE NON SERVIE : la base est occupée (verrou tenu par une autre opération) — ce n'est PAS un résultat vide, et rien n'est rendu. Réessayez dans un instant.";
    const AX1_TEXTE_UN: &str = "ax1 texte du moteur un";
    const AX1_TEXTE_DEUX: &str = "ax1 texte du moteur deux";
    const AX1_ILLISIBLE: &str = "{ax1 pas du json";
    const AX1_SQL_REGEXP: &str = "SELECT message FROM event WHERE message REGEXP 'ax1'";

    fn ax1_charge() -> Value {
        json!({ "columns": ["a"], "rows": [[42]] })
    }

    /// La charge utile attendue, ENTIÈRE : lignes intactes, un seul champ sous `stats`, l'aveu à deux clés.
    fn ax1_charge_avec_aveu(cause: &str, echoue_a: i64) -> Value {
        json!({ "columns": ["a"], "rows": [[42]], "stats": { "rafraichissement_en_echec": { "cause": cause, "echoue_a": echoue_a } } })
    }

    fn ax1_moteur() -> EchecDeRequete {
        EchecDeRequete::Moteur { nature: "ax1 nature".into(), texte: AX1_TEXTE_UN.into() }
    }

    fn ax1_occupee() -> EchecDeRequete {
        EchecDeRequete::Occupee { nature: "ax1 nature".into(), texte: AX1_TEXTE_DEUX.into() }
    }

    fn ax1_lire(st: &AppState, id: i64, rk: &str, fp: &str) -> (Value, i64, String) {
        let (payload, calcule_a) = panneau_avoue::cache_lire(&st.db.lock(), id, rk, fp).expect("ligne de cache");
        let v: Value = serde_json::from_str(&payload).unwrap_or_else(|_| panic!("charge en cache illisible : {payload}"));
        (v, calcule_a, payload)
    }

    /// Une base de panneaux de la vague T avec un event et un panneau de plus dont l'énoncé appelle `regexp` (la panne
    /// « base occupée » passe par cette UDF) ; le cache des autres panneaux est coupé : le pré-chauffage n'exécute que
    /// celui-ci.
    fn ax1_seul_panneau_regexp(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, dbp, _g, _panne, _s) = t3c_state(tag);
        let id = {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO event(ts,host,source,category,severity,message,src_ip,fields) VALUES(?1,'ax1','sshd','auth',1,'ax1','192.0.2.31','{}')",
                params![now()],
            )
            .unwrap();
            let did: i64 = conn.query_row("SELECT MIN(id) FROM dashboard", [], |r| r.get(0)).unwrap();
            conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'ax1',?2,0,'table')", params![did, AX1_SQL_REGEXP]).unwrap();
            let id = conn.last_insert_rowid();
            conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id<>?1", params![id]).unwrap();
            id
        };
        (st, dbp, id)
    }

    /// (1) À LA DEMANDE, PUIS PAR LA ROUTE : sur une charge utile valide périmée, un rejet du moteur à t1 joint
    /// {cause : rejet, echoue_a : t1} (contrôle positif) ; une base occupée à t2 REMPLACE l'aveu par
    /// {cause : base occupée, echoue_a : t2}, charge comparée en entier, instant de calcul inchangé ; l'interrogation
    /// suivante sert ce second aveu. Rouge sous AX1_AVEU_PREMIER_GARDE, AX1_CAUSE_PREMIERE_GARDEE et
    /// AX1_INSTANT_PREMIER_GARDE.
    #[tokio::test]
    async fn ax1_un_echec_neuf_remplace_l_aveu_precedent_a_la_demande_et_par_la_route() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_data et panel_serve_cfg_de lisent load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("ax1-deux-echecs");
        let au = t3c_admin();
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, panne, from);
        assert!(ttl > 0, "prémisse : le cache des panneaux est actif");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        let calcule = now() - ttl - 5;
        {
            let conn = st.db.lock();
            record_panel_cost(&conn, panne, &fp, 10_000.0, now());
            panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, calcule, &ax1_charge().to_string());
        }
        let (t1, t2) = (calcule + 1, calcule + 2);
        consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, t1, from, ttl_global, Ok(Err(ax1_moteur())));
        let (v, calcule_a, payload) = ax1_lire(&st, panne, &rk, &fp);
        assert_eq!(v, ax1_charge_avec_aveu(AX1_REJETEE, t1), "contrôle positif : le premier échec est joint, à son instant : {payload}");
        assert_eq!(calcule_a, calcule, "contrôle positif : instant de calcul inchangé : {payload}");
        consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, t2, from, ttl_global, Ok(Err(ax1_occupee())));
        let (v, calcule_a, payload) = ax1_lire(&st, panne, &rk, &fp);
        assert_eq!(v, ax1_charge_avec_aveu(AX1_OCCUPEE, t2), "l'échec neuf remplace l'aveu précédent : sa cause ET son instant : {payload}");
        assert_eq!(calcule_a, calcule, "instant de calcul inchangé après le second échec : {payload}");
        let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
        assert_eq!(code, 200, "corps {v}");
        assert_eq!(v["rows"], json!([[42]]), "la charge périmée est servie : {v}");
        assert!(v.get("error").is_none(), "aucun corps d'échec servi : {v}");
        assert_eq!(
            v["stats"]["rafraichissement_en_echec"],
            json!({ "cause": AX1_OCCUPEE, "echoue_a": t2 }),
            "la route sert l'aveu du DERNIER échec : {v}"
        );
        t3c_attendre_la_tache(&st).await;
        ff_rm(&dbp);
    }

    /// (2) AU PRÉ-CHAUFFAGE : un aveu de rejet à t1 est déjà joint (par le rafraîchissement à la demande) ; le
    /// pré-chauffage, une base occupée armée au cœur, le REMPLACE par {cause : base occupée, echoue_a : instant du tick},
    /// postérieur à t1 ; charge comparée en entier, instant de calcul inchangé. Rouge sous les trois mutants de (1).
    #[test]
    fn ax1_au_pre_chauffage_un_echec_neuf_remplace_l_aveu_precedent() {
        use crate::query_exec::panne_de_test_au_coeur::{demander, encore_demandee, retirer, PanneAuCoeur};
        let _env = VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels et panel_serve_cfg_de lisent load_config()
        let (st, dbp, id) = ax1_seul_panneau_regexp("ax1-pre-chauffage");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, id, from);
        assert!(ttl > 0, "prémisse : le cache de ce panneau est actif");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        let calcule = now() - ttl - 5;
        panneau_avoue::cache_ecrire(&st.db.lock(), id, &rk, &fp, calcule, &ax1_charge().to_string());
        let t1 = calcule + 1;
        consigner_l_issue_du_rafraichissement(&st.db, "default", id, &rk, &fp, t1, from, ttl_global, Ok(Err(ax1_moteur())));
        let (v, _, payload) = ax1_lire(&st, id, &rk, &fp);
        assert_eq!(v, ax1_charge_avec_aveu(AX1_REJETEE, t1), "contrôle positif : le premier aveu est joint : {payload}");
        demander(dbp.as_str(), PanneAuCoeur::BaseOccupee);
        let avant = now();
        crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
        let apres = now();
        let servie = !encore_demandee(dbp.as_str());
        retirer(dbp.as_str());
        assert!(servie, "prémisse : la panne a servi au pré-chauffage");
        let (v, calcule_a, payload) = ax1_lire(&st, id, &rk, &fp);
        assert_eq!(calcule_a, calcule, "instant de calcul inchangé : {payload}");
        let t = v["stats"]["rafraichissement_en_echec"]["echoue_a"].as_i64().unwrap_or_else(|| panic!("instant de l'échec non entier : {payload}"));
        assert!(t > t1, "l'instant servi n'est plus celui du premier échec : {t} <= {t1} ; {payload}");
        assert!(avant <= t && t <= apres, "l'instant est celui du tick de pré-chauffage : {t} hors [{avant}, {apres}]");
        assert_eq!(v, ax1_charge_avec_aveu(AX1_OCCUPEE, t), "le pré-chauffage remplace l'aveu précédent : {payload}");
        ff_rm(&dbp);
    }

    /// (3) UNE LIGNE DE CACHE ILLISIBLE (pas du JSON) n'est pas une charge valide : le corps d'échec la remplace, à
    /// l'instant de la tentative, avec la phrase de la classe et sans aveu joint. Rouge sous AX1_ILLISIBLE_TENU_VALIDE
    /// (aveu joint à une charge vide, aucun `error`).
    #[test]
    fn ax1_une_ligne_illisible_n_est_pas_une_charge_valide() {
        let _env = VERROU_ENV_PROCESSUS.read(); // panel_serve_cfg_de lit load_config()
        let (st, dbp, _g, panne, _s) = t3c_state("ax1-illisible");
        let from = t3c_from();
        let (rk, fp, ttl) = t3c_cle(&st, panne, from);
        assert!(ttl > 0, "prémisse : le cache des panneaux est actif");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        let calcule = now() - ttl - 5;
        panneau_avoue::cache_ecrire(&st.db.lock(), panne, &rk, &fp, calcule, AX1_ILLISIBLE);
        let t = calcule + 1;
        consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, t, from, ttl_global, Ok(Err(ax1_moteur())));
        let (v, calcule_a, payload) = ax1_lire(&st, panne, &rk, &fp);
        assert_eq!(calcule_a, t, "le corps d'échec est écrit à l'instant de la tentative : {payload}");
        let mut cles: Vec<String> = v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        cles.sort();
        assert_eq!(cles, ["classe_d_echec", "columns", "error", "rows", "stats"].map(String::from).to_vec(), "clés du corps d'échec : {payload}");
        assert_eq!(v["error"], json!(AX1_REJETEE), "la phrase de la classe : {payload}");
        assert_eq!(v["classe_d_echec"], json!("moteur"), "la classe écrite : {payload}");
        assert_eq!(v["rows"], json!([]), "aucune ligne : {payload}");
        let stats: Vec<String> = v["stats"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        assert_eq!(stats, vec!["coverage".to_string()], "aucun aveu joint, seule la couverture : {payload}");
        assert!(!payload.contains(AX1_TEXTE_UN), "le texte du moteur n'est pas écrit : {payload}");
        ff_rm(&dbp);
    }
}
