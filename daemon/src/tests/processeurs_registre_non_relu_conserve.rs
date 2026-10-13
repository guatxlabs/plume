// =====================================================================================
// `P10.20-b` (hors `handlers/` : `processors_reload`) — UNE LECTURE RATÉE DU REGISTRE D'INGESTION NE
// DÉSARME PAS UNE RÈGLE MASK/DROP/ROUTE QU'ELLE N'A PAS RELUE.
//
// LE DÉFAUT, LU SUR 80ad700a. `processors_reload` lisait `ingest_rule` sous `if let Ok(..) = prepare` /
// `if let Ok(..) = query_map` sans branche d'échec, puis `rows.flatten()`, et REMPLAÇAIT le registre de
// `db_path` par ce qui avait été lu : une table illisible publiait un registre VIDE, une ligne
// indécodable (cellule blob dans une colonne TEXT, que le schéma v83 n'interdit pas) faisait disparaître
// SA règle ; `reload_errors` ne comptait que les règles qui ne compilent pas, il restait à zéro. Pour un
// MASK de redaction PII, la suite de l'ingestion était stockée EN CLAIR, irréversiblement.
//
// LES TÉMOINS. (1) blob dans `match_value` d'une règle MASK en place : la règle reste armée, un event est
// toujours masqué, l'échec est compté dans `reload_read_failures` (pas dans `reload_errors`) ; puis une
// règle posée pendant la panne et un rechargement raté de plus, la règle étant alors EN PLACE et RELUE :
// aucun doublon ; (2) table renommée : le registre en place est gardé, l'échec compté ;
// (3) contrôle négatif : une lecture RÉUSSIE de zéro ligne remplace par le vide (registre vide posé par
// l'exploitant, mode 0) ; (4) registre jamais chargé : il reçoit ce qui a pu être décodé ; (5) une règle
// posée pendant la panne est armée, et le registre uni suit l'ordre (`ord`, `id`) — la dernière ROUTE
// évaluée gagne ; (6) interruption du moteur à CHAQUE instruction d'un rechargement (`progress_handler`) :
// jamais de registre partiel, un pas raté compté, une règle relue prend sa version décodée une fois,
// une relue qui ne compile plus sort, une non relue reste ; (7) règle relue modifiée + ligne
// indécodable : une seule fois, version décodée ; (8) deux lignes ratées = deux échecs, à part d'une
// règle invalide ; (9) registre uni borné à `PROC_RULE_MAX_TOTAL` ; (10) parcours COMPLET : une règle
// supprimée et une règle éteinte depuis ne restent pas armées, la non décodée si ; (11) `ord` réel
// (SQL direct) : la règle est armée au chargement NOMINAL, rien compté ; (12) registre uni : `1.5` est
// tronqué, départagé de `1` par `id` ; (13) registre uni : `ord` texte et blob passent en dernier.
//
// MUTANTS JOUÉS (variable d'environnement de mutation, retirés du source avant le commit). Première
// passe : `M4_ANCIEN` (corps d'origine verbatim) -> (1) (2) (4) (5) rouges ; `M4_FLATTEN` -> (1) (4) (5) ;
// `M4_VIDE` -> (1) (2) (5) ; `M4_MUET` -> (1) (2) (4) ; `M4_SANS_TRI` -> (5) ; `M4_GARDE_TOUT` -> (3).
// Seconde passe : `PAS_MUET` (pas raté sans échec) -> (6) ; `PAS_COMPLET` (pas raté tenu pour parcours
// complet) -> (6) ; `RELUS_SI_COMPILE` (relue inscrite seulement si elle compile) -> (6) ; `SANS_FILTRE`
// (union sans filtre d'identifiant) -> (6) (7) (8) (10) ; `EN_PLACE_PREVAUT` (la version en place gagne)
// -> (6) (7) (8) (10) ; `SANS_PLAFOND` -> (9) ; `ECHECS_UN` (un échec par rechargement) -> (8) ;
// `ECHECS_DANS_ERREURS` (lectures ratées versées dans `reload_errors`) -> (1) (2) (6) (8) ;
// `TOUJOURS_INCOMPLET` (règle supprimée gardée même sur parcours complet) -> (10). Troisième passe :
// `W13_ORD_DANS_DECODE` (lecture faillible de `ord` dans le décodage) -> (11) (13) ; `W11_ORD_REEL_MAX`
// (`ord` réel en dernier) -> (12) ; `W12_ORD_AUTRE_MIN` (texte et blob en premier) -> (13) ;
// `M4T1_GARDE_TOUT` (union qui garde tout le registre en place, relu ou non) -> (1), sur le dernier
// rechargement seulement (le deuxième, registre en place sans règle relue, reste vert).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un registre JAMAIS chargé dont la table est illisible reste vide
// (rien à conserver) ; un parcours arrêté au plafond est tenu pour INCOMPLET (choix prudent, sans
// témoin qui le distingue de l'autre choix) ; la branche « identifiant illisible » est inatteignable
// (`id INTEGER PRIMARY KEY`) ; une cellule `enabled` de type inattendu sort toujours la règle par
// `WHERE enabled=1` ; la console n'affiche pas encore `reload_read_failures` (`web/processors.js`, hors
// périmètre) ; les messages de stderr ne sont pas témoignés.
// =====================================================================================
mod processeurs_registre_non_relu_conserve {
    use super::*;

    fn poser(conn: &Connection, ord: i64, mf: &str, mo: &str, mv: &str, action: &str, arg: &str) -> i64 {
        conn.execute(
            "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
             VALUES('t',?1,?2,?3,?4,?5,?6,1,2,0)",
            params![ord, mf, mo, mv, action, arg],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Règles qui ne compilent pas au dernier rechargement.
    fn erreurs(dbp: &str) -> Value {
        processors_counters_json(dbp)["reload_errors"].clone()
    }

    /// Échecs de LECTURE au dernier rechargement (compte À PART des règles qui ne compilent pas).
    fn lectures_ratees(dbp: &str) -> Value {
        processors_counters_json(dbp)["reload_read_failures"].clone()
    }

    fn action_de(dbp: &str, id: i64) -> Option<RuleAction> {
        processors_cell().read().get(dbp).and_then(|v| v.iter().find(|r| r.id == id).map(|r| r.action.clone()))
    }

    fn ids_du_registre(dbp: &str) -> Option<Vec<i64>> {
        processors_cell().read().get(dbp).map(|v| v.iter().map(|r| r.id).collect())
    }

    /// Ingère un event `source=pii` et rend le message STOCKÉ.
    fn message_stocke(conn: &Connection, dbp: &str, dedup: &str) -> String {
        let events = vec![json!({"ts": 1, "source": "pii", "message": "SSN=123-45-6789", "dedup": dedup})];
        ingest_events_batch(conn, dbp, &events, 1, None, None).unwrap();
        conn.query_row(&format!("SELECT message FROM event WHERE dedup='{}'", ddk(None, dedup)), [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn m4_blob_dans_match_value_la_regle_mask_reste_armee() {
        let conn = test_db();
        let dbp = "m4-blob-match-value";
        let id = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        processors_reload(&conn, dbp);
        assert_eq!(message_stocke(&conn, dbp, "b1"), "[redacted]", "contrôle : la règle MASK est armée");
        assert_eq!(lectures_ratees(dbp), 0, "contrôle : aucun échec");
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [id]).unwrap();
        let t: String = conn.query_row("SELECT typeof(match_value) FROM ingest_rule WHERE id=?1", [id], |r| r.get(0)).unwrap();
        assert_eq!(t, "blob", "contrôle : la cellule est bien devenue un blob");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id]), "la règle non relue reste au registre");
        assert_eq!(message_stocke(&conn, dbp, "b2"), "[redacted]", "un event est toujours masqué après la lecture ratée");
        assert_eq!(lectures_ratees(dbp), 1, "la ligne non lue est comptée dans reload_read_failures");
        assert_eq!(erreurs(dbp), 0, "elle n'est PAS une règle invalide ignorée : reload_errors reste à zéro");
        // Rechargement raté après rechargement raté, avec un registre en place LUI-MÊME issu d'une union :
        // `z`, posée pendant la panne, est armée par le troisième rechargement ; au quatrième, elle est à la
        // fois EN PLACE et RELUE (version décodée, une seule fois), `id` toujours non relue (gardée une fois).
        let z = poser(&conn, 1, "source", "eq", "app", "route", "z");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id, z]), "contrôle : la règle posée pendant la panne est armée");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id, z]), "rechargement raté après rechargement raté : aucun doublon");
        assert_eq!(lectures_ratees(dbp), 1, "toujours une seule ligne non lue");
    }

    #[test]
    fn m4_table_renommee_le_registre_en_place_est_garde() {
        let conn = test_db();
        let dbp = "m4-table-renommee";
        let id = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id]), "contrôle : règle chargée");
        conn.execute_batch("ALTER TABLE ingest_rule RENAME TO ingest_rule_ailleurs").unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(lectures_ratees(dbp), 1, "la préparation ratée est comptée");
        assert_eq!(erreurs(dbp), 0, "à part des règles invalides");
        assert_eq!(ids_du_registre(dbp), Some(vec![id]), "le registre en place est gardé");
        assert_eq!(message_stocke(&conn, dbp, "t1"), "[redacted]", "le masque tient pendant la panne");
    }

    #[test]
    fn m4_zero_ligne_lue_avec_succes_remplace_par_le_vide() {
        let conn = test_db();
        let dbp = "m4-zero-ligne";
        let id = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id]), "contrôle : règle chargée");
        conn.execute("DELETE FROM ingest_rule", []).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![]), "une lecture réussie de zéro ligne pose le registre vide");
        assert_eq!(lectures_ratees(dbp), 0, "aucun échec compté");
        assert_eq!(erreurs(dbp), 0, "aucune règle invalide");
        assert_eq!(message_stocke(&conn, dbp, "z1"), "SSN=123-45-6789", "registre vide : event stocké inchangé (mode 0)");
    }

    #[test]
    fn m4_registre_jamais_charge_recoit_les_regles_decodees() {
        let conn = test_db();
        let dbp = "m4-jamais-charge";
        let saine = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        let illisible = poser(&conn, 1, "source", "eq", "pii", "drop", "");
        conn.execute("UPDATE ingest_rule SET match_value=x'00ff' WHERE id=?1", [illisible]).unwrap();
        assert_eq!(ids_du_registre(dbp), None, "contrôle : registre jamais chargé");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![saine]), "seule la règle décodée est publiée");
        assert_eq!(lectures_ratees(dbp), 1, "la ligne non lue est comptée");
    }

    #[test]
    fn m4_regle_posee_pendant_la_panne_armee_et_union_triee_par_ord() {
        let conn = test_db();
        let dbp = "m4-union-ord";
        let x = poser(&conn, 2, "source", "eq", "app", "route", "b");
        processors_reload(&conn, dbp);
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [x]).unwrap();
        let y = poser(&conn, 1, "source", "eq", "app", "route", "a");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![y, x]), "registre uni : la règle posée est armée, ordre (ord, id)");
        let events = vec![json!({"ts": 1, "source": "app", "message": "x", "dedup": "u1"})];
        ingest_events_batch(&conn, dbp, &events, 1, None, None).unwrap();
        let env: String = conn.query_row(&format!("SELECT env_id FROM event WHERE dedup='{}'", ddk(None, "u1")), [], |r| r.get(0)).unwrap();
        assert_eq!(env, "b", "la ROUTE d'ord 2 (non relue, en place) est évaluée APRÈS celle d'ord 1 et gagne");
    }

    /// Interruption du moteur à CHAQUE instruction d'un rechargement (`progress_handler`) : aucune ne
    /// publie un registre partiel. Registre en place : a MASK, b MASK, c ROUTE ; en base, a est devenue
    /// DROP (compile) et b ne compile plus. Une interruption au pas laisse un parcours INCOMPLET : c non
    /// relue reste armée ; a, si elle a été relue, prend sa version décodée, une seule fois ; b, si elle a
    /// été relue (ce que dit `reload_errors`), sort du registre.
    #[test]
    fn m4_interruption_du_moteur_a_chaque_instruction_aucun_registre_partiel() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let conn = test_db();
        let dbp = "m4-interruption";
        let a = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        let b = poser(&conn, 1, "source", "eq", "pii", "mask", "host");
        let c = poser(&conn, 2, "source", "eq", "pii", "route", "z");
        let mettre_en_scene = || {
            conn.execute("UPDATE ingest_rule SET action='mask', action_arg='message' WHERE id=?1", [a]).unwrap();
            conn.execute("UPDATE ingest_rule SET match_op='eq' WHERE id=?1", [b]).unwrap();
            processors_reload(&conn, dbp);
            assert_eq!(ids_du_registre(dbp), Some(vec![a, b, c]), "contrôle : registre d'origine en place");
            conn.execute("UPDATE ingest_rule SET action='drop', action_arg='' WHERE id=?1", [a]).unwrap();
            conn.execute("UPDATE ingest_rule SET match_op='nope' WHERE id=?1", [b]).unwrap();
        };
        mettre_en_scene();
        let compte = Arc::new(AtomicU64::new(0));
        let k = compte.clone();
        conn.progress_handler(1, Some(move || { k.fetch_add(1, Ordering::Relaxed); false }));
        processors_reload(&conn, dbp);
        conn.progress_handler(1, None::<fn() -> bool>);
        let total = compte.load(Ordering::Relaxed);
        assert!(total > 5, "contrôle : un rechargement exécute plusieurs instructions ({total})");
        assert_eq!(ids_du_registre(dbp), Some(vec![a, c]), "contrôle nominal : b ne compile plus, a relue");
        assert_eq!((erreurs(dbp), lectures_ratees(dbp)), (json!(1), json!(0)), "contrôle nominal : comptes");
        let (mut interrompus, mut interrompus_apres_b) = (0, 0);
        for cible in 1..=total {
            mettre_en_scene();
            let n = AtomicU64::new(0);
            conn.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
            processors_reload(&conn, dbp);
            conn.progress_handler(1, None::<fn() -> bool>);
            let ids = ids_du_registre(dbp).unwrap();
            let ctx = format!("interruption à l'instruction {cible}/{total}");
            if lectures_ratees(dbp) == 0 {
                assert_eq!(ids, vec![a, c], "{ctx} : aucun échec compté, donc registre nominal — jamais partiel");
                continue;
            }
            interrompus += 1;
            assert_eq!(lectures_ratees(dbp), 1, "{ctx} : un pas raté = un échec compté");
            if erreurs(dbp) == 1 {
                interrompus_apres_b += 1;
                assert_eq!(ids, vec![a, c], "{ctx} : b relue non compilable sort, c non relue gardée, aucun doublon");
                assert!(matches!(action_de(dbp, a), Some(RuleAction::Drop)), "{ctx} : a relue prend sa version décodée");
            } else {
                assert_eq!(erreurs(dbp), 0, "{ctx}");
                assert_eq!(ids, vec![a, b, c], "{ctx} : b et c non relues gardées, aucun doublon");
            }
        }
        assert!(interrompus > 0, "contrôle : au moins une interruption a fait rater la lecture");
        assert!(interrompus_apres_b > 0, "contrôle : au moins une interruption après la relecture de b");
    }

    /// Parcours complet, une règle relue modifiée et une ligne indécodable : la relue figure UNE fois, dans
    /// sa version décodée (DROP), la non décodée garde sa version en place.
    #[test]
    fn m4_regle_relue_une_seule_fois_dans_sa_version_decodee() {
        let conn = test_db();
        let dbp = "m4-relue-une-fois";
        let a = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        let b = poser(&conn, 1, "source", "eq", "pii", "mask", "host");
        processors_reload(&conn, dbp);
        conn.execute("UPDATE ingest_rule SET action='drop', action_arg='' WHERE id=?1", [a]).unwrap();
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [b]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![a, b]), "aucun doublon");
        assert!(matches!(action_de(dbp, a), Some(RuleAction::Drop)), "la base fait foi pour la règle relue");
        assert!(matches!(action_de(dbp, b), Some(RuleAction::Mask { .. })), "la règle non décodée garde sa version en place");
    }

    /// Chaque ligne ratée est comptée (deux lignes, deux échecs), à part de la règle relue qui ne compile
    /// plus (un compte dans `reload_errors`) ; celle-ci sort du registre.
    #[test]
    fn m4_chaque_ligne_ratee_comptee_a_part_des_regles_invalides() {
        let conn = test_db();
        let dbp = "m4-deux-lignes";
        let a = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        let b = poser(&conn, 1, "source", "eq", "pii", "mask", "host");
        let c = poser(&conn, 2, "source", "eq", "pii", "route", "z");
        processors_reload(&conn, dbp);
        conn.execute("UPDATE ingest_rule SET match_op='nope' WHERE id=?1", [a]).unwrap();
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id IN (?1,?2)", [b, c]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![b, c]), "la relue non compilable sort, les non décodées restent");
        assert_eq!(lectures_ratees(dbp), 2, "deux lignes ratées, deux échecs");
        assert_eq!(erreurs(dbp), 1, "une règle invalide");
    }

    /// Le registre uni reste borné au plafond : 200 règles en place, 100 posées avant elles par `ord`
    /// (l'API ne plafonne pas la création), une ligne indécodable — le parcours s'arrête au plafond, donc
    /// incomplet, et l'union dépasserait 256.
    #[test]
    fn m4_registre_uni_borne_au_plafond() {
        let conn = test_db();
        let dbp = "m4-plafond";
        let mut anciens = Vec::new();
        for i in 0..200 {
            anciens.push(poser(&conn, 1000 + i, "source", "eq", &format!("o{i}"), "route", "e"));
        }
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp).unwrap().len(), 200, "contrôle");
        let mut nouveaux = Vec::new();
        for i in 0..100 {
            nouveaux.push(poser(&conn, i, "source", "eq", &format!("n{i}"), "route", "e"));
        }
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [anciens[0]]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(lectures_ratees(dbp), 1, "contrôle : lecture ratée");
        let ids = ids_du_registre(dbp).unwrap();
        assert_eq!(ids.len(), PROC_RULE_MAX_TOTAL, "borné au plafond");
        assert_eq!(&ids[..100], &nouveaux[..], "les plus petits ord d'abord");
        assert_eq!(ids[100], anciens[0], "la règle non décodée garde son rang");
    }

    /// Parcours COMPLET (une seule ligne indécodable, d'identifiant lisible) : une règle supprimée et une
    /// règle éteinte depuis le dernier chargement ne restent PAS armées ; la non décodée, si.
    #[test]
    fn m4_parcours_complet_regle_supprimee_ou_eteinte_desarmee() {
        let conn = test_db();
        let dbp = "m4-parcours-complet";
        let a = poser(&conn, 0, "source", "eq", "pii", "mask", "message");
        let b = poser(&conn, 1, "source", "eq", "pii", "drop", "");
        let c = poser(&conn, 2, "source", "eq", "pii", "route", "z");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![a, b, c]), "contrôle");
        conn.execute("DELETE FROM ingest_rule WHERE id=?1", [b]).unwrap();
        conn.execute("UPDATE ingest_rule SET enabled=0 WHERE id=?1", [c]).unwrap();
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [a]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(lectures_ratees(dbp), 1, "contrôle : lecture ratée");
        assert_eq!(ids_du_registre(dbp), Some(vec![a]), "le DROP supprimé et la ROUTE éteinte sont désarmés");
        assert_eq!(message_stocke(&conn, dbp, "pc1"), "[redacted]", "le MASK non décodé tient, l'event n'est plus jeté");
    }

    fn poser_ord_sql(conn: &Connection, ord_sql: &str, mv: &str, action: &str, arg: &str) -> i64 {
        conn.execute(
            &format!(
                "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
                 VALUES('t',{ord_sql},'source','eq',?1,?2,?3,1,2,0)"
            ),
            params![mv, action, arg],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn type_de_ord(conn: &Connection, id: i64) -> String {
        conn.query_row("SELECT typeof(ord) FROM ingest_rule WHERE id=?1", [id], |r| r.get(0)).unwrap()
    }

    /// Chemin NOMINAL : une règle MASK d'`ord` réel (posé par SQL direct) est armée ; la lecture de `ord`
    /// ne fait pas échouer la ligne (rien compté).
    #[test]
    fn m4_ord_reel_la_regle_reste_armee_au_chargement_nominal() {
        let conn = test_db();
        let dbp = "m4-ord-reel-nominal";
        let id = poser_ord_sql(&conn, "1.5", "pii", "mask", "message");
        assert_eq!(type_de_ord(&conn, id), "real", "contrôle : ord réel");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![id]), "la règle d'ord réel est au registre");
        assert_eq!(lectures_ratees(dbp), 0, "aucune lecture ratée");
        assert_eq!(erreurs(dbp), 0, "aucune règle invalide");
        assert_eq!(message_stocke(&conn, dbp, "or1"), "[redacted]", "le MASK d'ord réel masque");
    }

    /// Registre UNI : un `ord` réel est TRONQUÉ, `1.5` et `1` se départagent par `id` (le plus ancien
    /// d'abord), et non par leur valeur comme le ferait le SQL.
    #[test]
    fn m4_ord_reel_tronque_dans_le_registre_uni_departage_par_id() {
        let conn = test_db();
        let dbp = "m4-ord-reel-uni";
        let ra = poser_ord_sql(&conn, "1.5", "app", "route", "a");
        let rb = poser_ord_sql(&conn, "1", "app", "route", "b");
        let rc = poser_ord_sql(&conn, "0", "app", "route", "c");
        assert_eq!(type_de_ord(&conn, ra), "real", "contrôle : ord réel");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![rc, rb, ra]), "contrôle : ordre SQL (1 < 1.5)");
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [rc]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(lectures_ratees(dbp), 1, "contrôle : lecture ratée");
        assert_eq!(ids_du_registre(dbp), Some(vec![rc, ra, rb]), "registre uni : 1.5 tronqué à 1, départagé par id");
    }

    /// Registre UNI : un `ord` texte ou blob passe en DERNIER (après tout entier), départagé par `id`.
    #[test]
    fn m4_ord_texte_ou_blob_en_dernier_dans_le_registre_uni() {
        let conn = test_db();
        let dbp = "m4-ord-texte-blob";
        let rt = poser_ord_sql(&conn, "'abc'", "app", "route", "t");
        let rl = poser_ord_sql(&conn, "x'01'", "app", "route", "l");
        let rn = poser_ord_sql(&conn, "5", "app", "route", "n");
        let ru = poser_ord_sql(&conn, "1", "app", "route", "u");
        assert_eq!(type_de_ord(&conn, rt), "text", "contrôle : ord texte");
        assert_eq!(type_de_ord(&conn, rl), "blob", "contrôle : ord blob");
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp), Some(vec![ru, rn, rt, rl]), "contrôle : ordre SQL");
        assert_eq!(lectures_ratees(dbp), 0, "contrôle : un ord texte ou blob ne fait pas rater la ligne");
        conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [ru]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(lectures_ratees(dbp), 1, "contrôle : lecture ratée");
        assert_eq!(ids_du_registre(dbp), Some(vec![ru, rn, rt, rl]), "registre uni : ord texte et blob en dernier");
    }
}
