// =====================================================================================
// `P10.20-b` (hors `handlers/` : `processors_reload`, suite de `processeurs_registre_non_relu_conserve.rs`)
// — DEUX AFFIRMATIONS DE `regle_active` QU'AUCUN TÉMOIN NE TENAIT, ET LE COMPTE DE SES CELLULES INATTENDUES (19).
//
// (17) « Seul l'entier 0 éteint » : un ENTIER autre que 0 ou 1 (`2`, `-1`, le texte `'2'` que l'affinité
// `INTEGER` convertit en entier, `i64::MAX`), posé par SQL direct sur une règle MASK en place, la laisse
// ARMÉE — un event est masqué, rien n'est compté comme lecture ratée ni comme règle invalide — et l'arme
// dès le premier chargement d'un registre neuf. Le témoin (14) ne couvrait que blob, texte et réel.
//
// (18) « `enabled` AVANT le plafond » : une ligne ÉTEINTE qui suit la 256e règle active n'est pas comptée
// au plafond et ne coupe pas le parcours. Registre en place x (MASK, supprimée depuis) et y (ROUTE,
// devenue indécodable) ; en base, `PROC_RULE_MAX_TOTAL` règles décodables après elles, puis UNE ligne
// `enabled=0` (décodable, ou indécodable). Le parcours va au bout : il est COMPLET, x supprimée est
// désarmée (l'event `pii` est stocké en clair, comme l'exploitant l'a voulu en la supprimant), y non
// décodée reste, une seule lecture ratée. Contrôle : une ligne ACTIVE à la même place, elle, coupe le
// parcours (incomplet, x gardée) — c'est bien l'état `enabled` qui décide.
//
// (19) Une cellule `enabled` de type inattendu (blob `x'01'`, texte `'1abc'`, réel `1.5`, entiers `2` et `-1`) est
// COMPTÉE dans `reload_enabled_unexpected` (clé lue par la constante du démon) : un compte par règle
// concernée et par rechargement, remplacé (pas cumulé), jamais versé dans `reload_read_failures` ; la règle
// reste armée. Entiers 0 et 1 : compte 0 ; un rechargement sans anomalie remet à 0 ; un registre jamais
// chargé sert 0 (nominal).
//
// (20) La ligne qui fait atteindre le plafond, jugée par `regle_active` AVANT lui, n'est pas au registre :
// sa cellule `enabled=2` n'est PAS comptée. Contrôle : la même anomalie sur une règle sous le plafond, elle,
// est comptée (1).
//
// MUTANTS JOUÉS (variable d'environnement de mutation, retirés du source avant le commit) :
// `V6_ENTIER_AUTRE_ETEINT` (bras `Integer(_)` de `regle_active` -> éteint) -> (17) ;
// `V9_ENABLED_APRES_PLAFOND` (`regle_active` jugé juste après le test du plafond) -> (18) ;
// `O5_MUET` (compteur jamais incrémenté), `O5_VERSE` (anomalie versée dans les échecs de lecture),
// `O5_CUMUL` (compte ajouté au précédent), `O5_ETEINT` (type inattendu = éteint) -> (19) ;
// `O5_REEL_MUET` (bras `Real` de `regle_active` : armée sans compter) -> (19) ;
// `O5_AVANT_PLAFOND` (anomalie ajoutée au compte avant le test du plafond) -> (20).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le message de stderr qui nomme la nature de la cellule n'est pas
// témoigné ; l'affichage console de `reload_enabled_unexpected` n'existe pas ; les lignes au-delà de
// celle qui atteint le plafond ne sont pas lues ; une règle comptée puis indécodable (gardée par l'union
// en sa version précédente) reste comptée ; le commentaire d'include de `tests/mod.rs` (« sans rien
// compter ») est périmé, index partagé hors périmètre ; `O5_VERSE` rougit par le compte de lectures ratées et non
// par une règle supprimée gardée (parcours complet : l'union ne garde que les lus non décodés) ; voir
// aussi le bloc du même nom de `processeurs_registre_non_relu_conserve.rs`.
// =====================================================================================
mod processeurs_enabled_entier_et_ligne_eteinte_au_plafond {
    use super::*;

    fn poser(conn: &Connection, ord: i64, mv: &str, action: &str, arg: &str) -> i64 {
        conn.execute(
            "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) \
             VALUES('t',?1,'source','eq',?2,?3,?4,1,2,0)",
            params![ord, mv, action, arg],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn erreurs(dbp: &str) -> Value {
        processors_counters_json(dbp)["reload_errors"].clone()
    }

    fn lectures_ratees(dbp: &str) -> Value {
        processors_counters_json(dbp)["reload_read_failures"].clone()
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

    /// (17) `enabled` ENTIER autre que 0 ou 1 sur une règle MASK en place : la règle reste armée.
    #[test]
    fn n7_enabled_entier_autre_que_zero_ou_un_la_regle_mask_reste_armee() {
        for (k, cellule) in ["2", "-1", "'2'", "9223372036854775807"].into_iter().enumerate() {
            let conn = test_db();
            let dbp = format!("n7-enabled-entier-autre-{k}");
            let dbp = dbp.as_str();
            let id = poser(&conn, 0, "pii", "mask", "message");
            processors_reload(&conn, dbp);
            assert_eq!(message_stocke(&conn, dbp, &format!("ea{k}a")), "[redacted]", "contrôle : MASK armé ({cellule})");
            conn.execute(&format!("UPDATE ingest_rule SET enabled={cellule} WHERE id=?1"), [id]).unwrap();
            let (t, v): (String, i64) = conn
                .query_row("SELECT typeof(enabled), enabled FROM ingest_rule WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap();
            assert_eq!(t, "integer", "contrôle : enabled={cellule} est stocké en entier");
            assert!(v != 0 && v != 1, "contrôle : enabled={cellule} n'est ni 0 ni 1");
            processors_reload(&conn, dbp);
            assert_eq!(ids_du_registre(dbp), Some(vec![id]), "enabled={cellule} : la règle reste au registre");
            assert_eq!(message_stocke(&conn, dbp, &format!("ea{k}b")), "[redacted]", "enabled={cellule} : l'event est masqué");
            assert_eq!(lectures_ratees(dbp), 0, "enabled={cellule} : aucune lecture ratée");
            assert_eq!(erreurs(dbp), 0, "enabled={cellule} : aucune règle invalide");
            let neuf = format!("{dbp}-neuf");
            processors_reload(&conn, &neuf);
            assert_eq!(ids_du_registre(&neuf), Some(vec![id]), "enabled={cellule} : armée au premier chargement");
        }
    }

    /// (18) Une ligne ÉTEINTE après la 256e règle active ne compte pas au plafond : parcours COMPLET.
    #[test]
    fn n7_ligne_eteinte_apres_le_plafond_parcours_complet() {
        // (nom, la dernière ligne est éteinte, la dernière ligne est indécodable, x gardée)
        for (dbp, eteinte, indecodable, x_gardee) in [
            ("n7-eteinte-apres-plafond", true, false, false),
            ("n7-eteinte-indecodable-apres-plafond", true, true, false),
            ("n7-active-apres-plafond-controle", false, false, true),
        ] {
            let conn = test_db();
            let x = poser(&conn, 0, "pii", "mask", "message");
            let y = poser(&conn, 1, "pii", "route", "z");
            processors_reload(&conn, dbp);
            assert_eq!(ids_du_registre(dbp), Some(vec![x, y]), "{dbp} : contrôle");
            conn.execute("DELETE FROM ingest_rule WHERE id=?1", [x]).unwrap();
            conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [y]).unwrap();
            let remplissage: Vec<i64> =
                (0..PROC_RULE_MAX_TOTAL).map(|i| poser(&conn, 10 + i as i64, &format!("r{i}"), "route", "e")).collect();
            let derniere = poser(&conn, 100_000, "app", "route", "w");
            if eteinte {
                conn.execute("UPDATE ingest_rule SET enabled=0 WHERE id=?1", [derniere]).unwrap();
            }
            if indecodable {
                conn.execute("UPDATE ingest_rule SET match_value=x'ff' WHERE id=?1", [derniere]).unwrap();
            }
            processors_reload(&conn, dbp);
            assert_eq!(lectures_ratees(dbp), 1, "{dbp} : une seule lecture ratée (y), la ligne éteinte ne compte pas");
            assert_eq!(erreurs(dbp), 0, "{dbp} : aucune règle invalide");
            let ids = ids_du_registre(dbp).unwrap();
            assert_eq!(ids.len(), PROC_RULE_MAX_TOTAL, "{dbp} : registre uni borné au plafond");
            assert!(!ids.contains(&derniere), "{dbp} : la dernière ligne n'est pas au registre");
            if x_gardee {
                assert_eq!(&ids[..2], &[x, y], "{dbp} : contrôle, ligne ACTIVE au-delà du plafond = parcours incomplet, x gardée");
                assert_eq!(message_stocke(&conn, dbp, "l18"), "[redacted]", "{dbp} : contrôle, le MASK x tient");
            } else {
                assert!(!ids.contains(&x), "{dbp} : parcours complet, x supprimée désarmée");
                assert_eq!(ids[0], y, "{dbp} : y non décodée gardée");
                assert_eq!(&ids[1..], &remplissage[..PROC_RULE_MAX_TOTAL - 1], "{dbp} : remplissage dans l'ordre (ord, id)");
                assert_eq!(message_stocke(&conn, dbp, "l18"), "SSN=123-45-6789", "{dbp} : x supprimée ne masque plus");
            }
        }
    }

    fn inattendus(dbp: &str) -> Value {
        processors_counters_json(dbp)
            .get(CLE_ENABLED_DE_TYPE_INATTENDU)
            .cloned()
            .unwrap_or_else(|| panic!("{dbp} : la clé {CLE_ENABLED_DE_TYPE_INATTENDU} n'est pas servie"))
    }

    /// (19) `enabled` de type inattendu : compté par règle et par rechargement, à part, règle armée.
    #[test]
    fn o5_enabled_de_type_inattendu_compte_a_part_et_regle_armee() {
        assert_eq!(inattendus("o5-jamais-charge"), 0, "registre jamais chargé : 0 servi");
        for (k, (cellule, nature)) in
            [("x'01'", "blob"), ("'1abc'", "text"), ("1.5", "real"), ("2", "integer"), ("-1", "integer")].into_iter().enumerate()
        {
            let conn = test_db();
            let dbp = format!("o5-enabled-inattendu-{k}");
            let dbp = dbp.as_str();
            let a = poser(&conn, 0, "pii", "mask", "message");
            let b = poser(&conn, 1, "app", "route", "e");
            let c = poser(&conn, 2, "web", "route", "f");
            let d = poser(&conn, 3, "db", "route", "g");
            let x = poser(&conn, 4, "old", "route", "h");
            conn.execute("UPDATE ingest_rule SET enabled=0 WHERE id=?1", [d]).unwrap();
            processors_reload(&conn, dbp);
            assert_eq!(inattendus(dbp), 0, "{cellule} : contrôle, entiers 0 et 1 seulement -> 0");
            assert_eq!(ids_du_registre(dbp), Some(vec![a, b, c, x]), "{cellule} : contrôle");
            conn.execute("DELETE FROM ingest_rule WHERE id=?1", [x]).unwrap();
            for id in [a, b] {
                conn.execute(&format!("UPDATE ingest_rule SET enabled={cellule} WHERE id=?1"), [id]).unwrap();
                let t: String =
                    conn.query_row("SELECT typeof(enabled) FROM ingest_rule WHERE id=?1", [id], |r| r.get(0)).unwrap();
                assert_eq!(t, nature, "contrôle : enabled={cellule} stocké en {nature}");
            }
            processors_reload(&conn, dbp);
            assert_eq!(inattendus(dbp), 2, "{cellule} : deux règles concernées, deux comptées");
            assert_eq!(lectures_ratees(dbp), 0, "{cellule} : pas une lecture ratée");
            assert_eq!(erreurs(dbp), 0, "{cellule} : pas une règle invalide");
            assert_eq!(ids_du_registre(dbp), Some(vec![a, b, c]), "{cellule} : a et b armées, d éteinte, x supprimée désarmée");
            assert_eq!(message_stocke(&conn, dbp, &format!("o5{k}a")), "[redacted]", "{cellule} : le MASK tient");
            processors_reload(&conn, dbp);
            assert_eq!(inattendus(dbp), 2, "{cellule} : un compte par rechargement, pas un cumul");
            for id in [a, b] {
                conn.execute("UPDATE ingest_rule SET enabled=1 WHERE id=?1", [id]).unwrap();
            }
            processors_reload(&conn, dbp);
            assert_eq!(inattendus(dbp), 0, "{cellule} : rechargement sans anomalie -> 0");
            assert_eq!(ids_du_registre(dbp), Some(vec![a, b, c]), "{cellule} : nominal inchangé");
        }
    }

    /// (20) La ligne qui atteint le plafond n'est pas au registre : son `enabled` inattendu n'est pas compté.
    #[test]
    fn o5_ligne_qui_atteint_le_plafond_non_comptee() {
        let conn = test_db();
        let dbp = "o5-plafond-non-compte";
        let remplissage: Vec<i64> =
            (0..PROC_RULE_MAX_TOTAL).map(|i| poser(&conn, 10 + i as i64, &format!("r{i}"), "route", "e")).collect();
        let derniere = poser(&conn, 100_000, "app", "route", "w");
        conn.execute("UPDATE ingest_rule SET enabled=2 WHERE id=?1", [derniere]).unwrap();
        processors_reload(&conn, dbp);
        let ids = ids_du_registre(dbp).unwrap();
        assert_eq!(ids, remplissage, "contrôle : registre = les règles sous le plafond");
        assert!(!ids.contains(&derniere), "contrôle : la ligne au plafond n'est pas au registre");
        assert_eq!(inattendus(dbp), 0, "la ligne au plafond, absente du registre, n'est pas comptée");
        conn.execute("UPDATE ingest_rule SET enabled=2 WHERE id=?1", [remplissage[0]]).unwrap();
        processors_reload(&conn, dbp);
        assert_eq!(ids_du_registre(dbp).unwrap(), remplissage, "contrôle : la règle sous le plafond reste armée");
        assert_eq!(inattendus(dbp), 1, "contrôle : la même anomalie sous le plafond est comptée");
    }
}
