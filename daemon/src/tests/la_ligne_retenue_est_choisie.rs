// `P7.19-i` — TROIS LECTURES DE PRODUCTION SERVAIENT UNE LIGNE ARBITRAIRE. LE TÉMOIN FABRIQUE
// L'ENSEMBLE MULTIPLE — c'est exactement le cas qu'aucune donnée de banc ne produisait, et c'est
// pour cela que le défaut a survécu.
//
// LES TROIS SITES, ET CE QUE « LA » LIGNE DOIT ÊTRE :
//   ① `handlers/incidents.rs` (deux surfaces) — LE RUNBOOK ATTACHÉ à un case. `case_step` porte UNE
//      LIGNE PAR ÉTAPE, donc l'ensemble est multiple DÈS QU'UN RUNBOOK EST ATTACHÉ. La bonne réponse
//      est LA SEULE ADMISSIBLE : le runbook qui rend compte de TOUTES les étapes. Multiple -> refus.
//   ② `handlers/alerts.rs` — L'INCIDENT d'une alerte. `case_item_add` insère sans contrainte
//      d'unicité : une alerte peut être liée à DEUX cases. La bonne réponse est LE RATTACHEMENT LE
//      PLUS RÉCENT, et surtout PAS un refus (le filtre `uncased` de la MÊME route est un `NOT EXISTS`
//      qui la compte casée : rendre `null` ferait se contredire deux surfaces).
//   ③ `handlers/engagement.rs` — LA FENÊTRE d'un credential d'engagement. C'est une porte
//      d'AUTHENTIFICATION : la bonne réponse est la liaison UNIQUE, et le multiple est un REFUS.
//
// CE QUE CHAQUE TÉMOIN PROUVE, DANS CET ORDRE : (a) l'instrument voit le cas NOMINAL (contrôle
// positif — un témoin qui ne constate rien avant de fabriquer ne prouve rien) ; (b) l'ensemble
// MULTIPLE fabriqué change la réponse de l'ANCIENNE forme, jouée ici telle qu'elle était, et cette
// réponse DÉPEND de l'ordre physique ; (c) la forme actuelle rend la MÊME chose sous les deux
// arrangements.
#[cfg(test)]
mod la_ligne_retenue_est_choisie {
    use super::*;

    /// L'ANCIENNE FORME, RECOPIÉE ICI POUR ÊTRE JOUÉE. Elle n'est plus dans la production ; c'est le
    /// seul endroit du dépôt où elle survit, et uniquement pour MESURER ce qu'elle rendait.
    fn ancienne_lecture_runbook(conn: &Connection, id: i64) -> Option<i64> {
        conn.query_row(
            "SELECT runbook_id FROM case_step WHERE incident_id=?1 LIMIT 1",
            params![id],
            |r| r.get::<_, i64>(0),
        )
        .ok()
    }

    /// Un case avec un runbook RÉELLEMENT attaché (N étapes, un seul `runbook_id`). Renvoie
    /// (id_du_case, id_du_runbook, nombre_d_etapes).
    fn case_avec_runbook(conn: &Connection) -> (i64, i64, i64) {
        seed_runbooks(conn);
        let id = case_create_row(conn, "alice", "exploit", 4, "", None, 2);
        let rb = pick_runbook_id(conn, Some("initial-access"), None).expect("un runbook actif seedé");
        let n = attach_runbook(conn, id, rb, "bob", &PrefillTargets::default()).expect("attache OK");
        (id, rb, n)
    }

    /// ① LE RUNBOOK ATTACHÉ — L'ENSEMBLE EST MULTIPLE, ET LE RÉSULTAT DÉPENDAIT DE L'ORDRE.
    ///
    /// Le seul écrivain de `case_step` (`attach_runbook`) refuse d'écrire quand des étapes existent
    /// déjà : c'est un invariant APPLICATIF, que le schéma ne tient pas (aucune contrainte d'unicité,
    /// aucune clé composite). Ce témoin l'ÉCARTE par une écriture directe, comme le ferait une
    /// migration, une restauration partielle ou un futur « détacher/ré-attacher », puis mesure.
    #[test]
    fn le_runbook_attache_est_le_seul_admissible_ou_rien() {
        let conn = test_db();
        let (id, rb, n) = case_avec_runbook(&conn);
        assert!(n >= 2, "il faut PLUSIEURS étapes pour que l'ensemble soit multiple (n={n})");

        // (a) CONTRÔLE POSITIF — le cas nominal est bien VU par les deux surfaces.
        let js = case_runbooks_json(&conn, id).expect("projection runbooks");
        assert_eq!(js["attached_runbook_id"], json!(rb), "nominal : le runbook attaché est nommé");
        assert_eq!(
            case_steps_json(&conn, id)["runbook"]["id"], json!(rb),
            "nominal : l'en-tête de la liste d'étapes nomme le MÊME runbook"
        );

        // (b) L'ENSEMBLE MULTIPLE, FABRIQUÉ : une étape d'un AUTRE runbook sur le même case.
        let rb_etranger: i64 = conn
            .query_row("SELECT id FROM runbook WHERE id<>?1 AND active=1 ORDER BY id LIMIT 1", params![rb], |r| r.get(0))
            .expect("un second runbook seedé");
        // ORDINAL NÉGATIF : la ligne étrangère se place AVANT toutes les autres dans l'index
        // `idx_case_step_inc(incident_id, ordinal)` — celui-là même qu'un `WHERE incident_id=?` sert.
        conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,step_kind,status) \
             VALUES(?1,?2,999,-1,'triage','étape étrangère','manual','pending')",
            params![id, rb_etranger],
        )
        .unwrap();
        let ancienne_devant = ancienne_lecture_runbook(&conn, id);
        // ...puis la MÊME ligne repoussée à la FIN. Rien d'autre ne change.
        conn.execute("UPDATE case_step SET ordinal=9999 WHERE incident_id=?1 AND runbook_id=?2", params![id, rb_etranger]).unwrap();
        let ancienne_derriere = ancienne_lecture_runbook(&conn, id);
        eprintln!(
            "[P7.19-i/runbook] ancienne forme (`LIMIT 1` sans ordre) : étrangère DEVANT -> {ancienne_devant:?}, \
             étrangère DERRIÈRE -> {ancienne_derriere:?} (réel={rb}, étranger={rb_etranger})"
        );
        // LA PROPRIÉTÉ, INDÉPENDANTE DU MOTEUR : l'ancienne forme NOMME un runbook alors que
        // l'ensemble n'en désigne aucun. Qu'elle nomme le bon ou le mauvais ne dépend que du plan.
        assert!(
            ancienne_devant.is_some() && ancienne_derriere.is_some(),
            "l'ancienne forme nommait TOUJOURS un runbook — sinon ce témoin ne mesure pas ce qu'il croit"
        );
        assert!(
            [ancienne_devant, ancienne_derriere].iter().any(|v| *v == Some(rb_etranger)),
            "l'ancienne forme a servi le runbook ÉTRANGER sous au moins un des deux arrangements : \
             c'est la définition d'un résultat qui dépend de l'ordre (devant={ancienne_devant:?}, \
             derrière={ancienne_derriere:?})"
        );

        // (c) LA FORME ACTUELLE : le même refus sous LES DEUX arrangements.
        for ordinal in [-1i64, 9999] {
            conn.execute("UPDATE case_step SET ordinal=?2 WHERE incident_id=?1 AND runbook_id=?3", params![id, ordinal, rb_etranger]).unwrap();
            let js = case_runbooks_json(&conn, id).expect("projection runbooks");
            assert_eq!(
                js["attached_runbook_id"], Value::Null,
                "ensemble multiple (ordinal={ordinal}) : aucun runbook ne rend compte de TOUTES les étapes -> \
                 la surface ne doit NOMMER personne"
            );
            let steps = case_steps_json(&conn, id);
            assert_eq!(steps["runbook"], Value::Null, "même refus sur la seconde surface (ordinal={ordinal})");
            // ...ET LE REFUS NE PERD RIEN : les étapes restent servies, toutes.
            assert_eq!(
                steps["progress"]["total"], json!(n + 1),
                "les étapes restent listées : le refus porte sur l'EN-TÊTE, pas sur le contenu"
            );
        }

        // (d) RÉVERSIBILITÉ — la ligne étrangère retirée, la surface reparle. Un refus DÉFINITIF
        //     serait un autre défaut.
        conn.execute("DELETE FROM case_step WHERE incident_id=?1 AND runbook_id=?2", params![id, rb_etranger]).unwrap();
        assert_eq!(
            case_runbooks_json(&conn, id).expect("projection")["attached_runbook_id"], json!(rb),
            "l'ensemble redevenu singleton, le runbook est de nouveau nommé"
        );
    }

    /// ② L'INCIDENT D'UNE ALERTE — LE RATTACHEMENT LE PLUS RÉCENT, ET IL NE DÉPEND PLUS DE L'ORDRE
    /// D'INSERTION.
    ///
    /// La preuve passe par la ROUTE (`alerts_query_page`), pas par le SQL : c'est le champ `case_id`
    /// servi à la console qui mentait. Les deux arrangements écrivent les MÊMES deux liens, dans les
    /// DEUX ordres d'insertion : la réponse doit être la même.
    #[test]
    fn le_case_d_une_alerte_est_le_rattachement_le_plus_recent() {
        for ordre_croissant in [true, false] {
            let conn = test_db();
            let t = now();
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,status) VALUES(?1,'rule.1',3,'a','new')",
                params![t],
            )
            .unwrap();
            let aid = conn.last_insert_rowid();
            let ancien = case_create_row(&conn, "alice", "case ANCIEN", 2, "", None, 3);
            let recent = case_create_row(&conn, "alice", "case RÉCENT", 2, "", None, 3);

            // (a) CONTRÔLE POSITIF — un seul lien : la route nomme CE case.
            case_add_item(&conn, ancien, t - 100, "alert", "sys", "lien 1", Some(&format!("alert:{aid}")));
            let (page, _, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 50, 0, false);
            assert_eq!(page.len(), 1);
            assert_eq!(page[0]["case_id"], json!(ancien), "nominal : le seul rattachement est servi");

            // (b) L'ENSEMBLE MULTIPLE : la MÊME alerte liée à un SECOND case, plus RÉCEMMENT.
            //     `ordre_croissant=false` réécrit les deux liens dans l'ordre d'insertion INVERSE —
            //     mêmes faits, disposition physique opposée.
            if ordre_croissant {
                case_add_item(&conn, recent, t, "alert", "sys", "lien 2", Some(&format!("alert:{aid}")));
            } else {
                conn.execute("DELETE FROM incident_item WHERE ref=?1", params![format!("alert:{aid}")]).unwrap();
                case_add_item(&conn, recent, t, "alert", "sys", "lien 2", Some(&format!("alert:{aid}")));
                case_add_item(&conn, ancien, t - 100, "alert", "sys", "lien 1", Some(&format!("alert:{aid}")));
            }
            let liens: i64 = conn
                .query_row("SELECT COUNT(*) FROM incident_item WHERE ref=?1", params![format!("alert:{aid}")], |r| r.get(0))
                .unwrap();
            assert_eq!(liens, 2, "l'ensemble fabriqué DOIT être multiple (ordre_croissant={ordre_croissant})");

            let (page, _, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 50, 0, false);
            assert_eq!(
                page[0]["case_id"], json!(recent),
                "ordre d'insertion {ordre_croissant} : « le » case d'une alerte doublement liée est le \
                 rattachement le PLUS RÉCENT, quel que soit l'ordre physique des lignes"
            );

            // (c) LE REMÈDE N'EST PAS UNE AGGRAVATION : la même route, filtre `uncased`, continue de
            //     compter cette alerte comme CASÉE. Un `null` servi ici l'aurait fait dire « non casée »
            //     par la ligne et « casée » par le filtre — deux surfaces qui se contredisent.
            let (backlog, _, _) = alerts_query_page(
                &conn,
                &FiltreAlertes { uncased: true, ..Default::default() },
                None, "", 50, 0, false,
            );
            assert!(
                backlog.is_empty(),
                "le filtre `uncased` ne doit PAS rendre une alerte liée à deux cases : la ligne et le \
                 filtre doivent dire la MÊME chose"
            );

            // (d) L'ÉGALITÉ D'HORODATAGE N'EST PAS UN CAS EXOTIQUE, C'EST LE CAS COURANT.
            //     `case_add_item` horodate à `now()`, en SECONDES : deux rattachements faits dans la
            //     même seconde — un analyste qui lie une alerte à deux cases d'affilée — portent le
            //     MÊME `ts`. Sans départage TOTAL, « le plus récent » redevient « le premier venu ».
            //     Le troisième lien porte l'horodatage du deuxième et doit gagner par son `id`.
            let troisieme = case_create_row(&conn, "alice", "case SIMULTANÉ", 2, "", None, 3);
            case_add_item(&conn, troisieme, t, "alert", "sys", "lien 3", Some(&format!("alert:{aid}")));
            let (page, _, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 50, 0, false);
            assert_eq!(
                page[0]["case_id"], json!(troisieme),
                "deux rattachements au MÊME instant (le cas courant : `now()` est en secondes) -> l'ordre \
                 doit rester TOTAL, départagé par la clé primaire, et non retomber sur l'ordre physique"
            );
        }
    }

    /// ③ LA FENÊTRE D'UN CREDENTIAL D'ENGAGEMENT — LE MULTIPLE EST UN REFUS, DANS LES DEUX SENS.
    ///
    /// C'est la seule des trois lectures dont l'arbitraire décidait d'une AUTHENTIFICATION : deux
    /// liaisons `issued` sur la même `ref`, l'une vers une fenêtre OUVERTE et l'autre vers une fenêtre
    /// CLOSE, et l'ancienne forme (`LIMIT 1` sans ordre) authentifiait ou refusait selon le plan.
    #[test]
    fn la_fenetre_d_un_credential_refuse_l_ensemble_multiple() {
        let conn = test_db();
        let maintenant = 1_000_000i64;
        let cred = format!("{ENG_CRED_PREFIX}0123456789ab");

        let engagement = |id: &str, debut: i64, fin: i64| {
            conn.execute(
                "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status) \
                 VALUES(?1,?1,'greybox','[]',?2,?3,'chef','essai','active')",
                params![id, debut, fin],
            )
            .unwrap();
        };
        let grant = |eng: &str| {
            conn.execute(
                "INSERT INTO engagement_grant(engagement_id,kind,ref,issued_ts,status) \
                 VALUES(?1,'scoped_cred',?2,0,'issued')",
                params![eng, cred],
            )
            .unwrap();
        };

        // (a) CONTRÔLE POSITIF ET NÉGATIF DE L'INSTRUMENT — une seule liaison, fenêtre OUVERTE puis
        //     CLOSE. Un témoin qui ne sait pas dire « oui » ne prouve rien en disant « non ».
        engagement("eng-ouvert", maintenant - 10, maintenant + 10);
        grant("eng-ouvert");
        assert!(
            engagement_cred_within_window(&conn, &cred, maintenant),
            "liaison UNIQUE, fenêtre ouverte -> la porte laisse passer (contrôle positif)"
        );
        assert!(
            !engagement_cred_within_window(&conn, &cred, maintenant + 1000),
            "liaison UNIQUE, fenêtre dépassée -> la porte refuse (contrôle négatif)"
        );

        // (b) L'ENSEMBLE MULTIPLE : une SECONDE liaison `issued` sur la MÊME `ref`, vers un engagement
        //     déjà CLOS. L'instant mesuré est DANS la fenêtre ouverte et HORS la fenêtre close : c'est
        //     exactement l'instant où le choix de la ligne décide de l'authentification.
        engagement("eng-clos", maintenant - 5000, maintenant - 4000);
        grant("eng-clos");
        let combien: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM engagement_grant WHERE ref=?1 AND kind='scoped_cred' AND status='issued'",
                params![cred], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(combien, 2, "l'ensemble fabriqué DOIT être multiple");
        assert!(
            !engagement_cred_within_window(&conn, &cred, maintenant),
            "deux liaisons `issued` sur la même ref -> la porte REFUSE (fail-closed), au lieu de tirer \
             une fenêtre au sort"
        );

        // (c) L'ORDRE N'Y FAIT RIEN. Les deux mêmes liaisons écrites dans l'ordre INVERSE (la close
        //     d'abord) : le refus est le même. C'est ce que l'ancienne forme ne tenait pas.
        conn.execute("DELETE FROM engagement_grant WHERE ref=?1", params![cred]).unwrap();
        grant("eng-clos");
        grant("eng-ouvert");
        assert!(
            !engagement_cred_within_window(&conn, &cred, maintenant),
            "ordre d'insertion inverse : le refus est INVARIANT"
        );

        // (d) LE REFUS N'EST PAS UNE PORTE MURÉE : la liaison surnuméraire révoquée (le geste que le
        //     produit fait réellement), la porte laisse de nouveau passer.
        conn.execute("UPDATE engagement_grant SET status='revoked' WHERE engagement_id='eng-clos'", []).unwrap();
        assert!(
            engagement_cred_within_window(&conn, &cred, maintenant),
            "l'ensemble redevenu singleton, la porte laisse passer : le refus portait sur l'AMBIGUÏTÉ, \
             pas sur le credential"
        );
    }
}
