// =====================================================================================
// `P10.7-f` (lot 109) — LE DISPATCH DE NOTIFICATIONS NE MARQUE PLUS UNE ALERTE « ENVOYÉE » SANS CANAL LU.
//
// VU : `dispatch_notifications` lisait la file d'alertes et la liste des canaux en `.flatten()`+`unwrap_or_default`.
// Sur une lecture ratée des CANAUX, la liste retombait VIDE (`Err(_) => Vec::new()`) : la boucle ne dispatchait
// rien, MAIS l'alerte était quand même marquée `notified=1` en fin de tour — marquée envoyée, jamais dispatchée,
// une PERTE SILENCIEUSE. Désormais : canaux lus EN BLOC, tour refusé et COMPTÉ sur échec, aucune alerte marquée.
//
// CE QUE CE TÉMOIN JOUE : une alerte à notifier, la table `notifier` renommée sous le lecteur, un tour de
// dispatch — l'alerte reste `notified=0` et l'aveu est compté ; la table revenue, le tour suivant la marque.
// =====================================================================================

#[test]
fn p10_7f_dispatch_sans_canaux_lus_ne_marque_aucune_alerte_notifiee() {
    let conn = test_db();
    conn.execute(
        "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) VALUES(?1,'r.1',3,'A','','new','','')",
        params![now()],
    )
    .unwrap();
    let avant = crate::metrics::tick_aveugle_de("dispatch_notifiers").map(|(n, _)| n).unwrap_or(0);
    // La table des canaux hors d'atteinte : la file d'alertes se lit, les canaux non.
    conn.execute_batch("ALTER TABLE notifier RENAME TO notifier_hors_d_atteinte;").unwrap();
    let db = Arc::new(Mutex::new(conn));
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT notified FROM alert WHERE rule='r.1'", [], |r| r.get(0)).unwrap(),
            0,
            "canaux non lus : l'alerte n'est PAS marquée notifiée (sinon perte silencieuse)"
        );
        let (n, cause) = crate::metrics::tick_aveugle_de("dispatch_notifiers").expect("le tour aveugle est COMPTÉ, sous son nom");
        assert_eq!(n, avant + 1, "un tour aveugle = un compte de plus");
        assert!(cause.contains("no such table"), "la cause est celle du moteur : {cause}");
        c.execute_batch("ALTER TABLE notifier_hors_d_atteinte RENAME TO notifier;").unwrap();
    }
    dispatch_notifications(&db);
    let c = db.lock();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT notified FROM alert WHERE rule='r.1'", [], |r| r.get(0)).unwrap(),
        1,
        "la table revenue, le tour marque l'alerte notifiée"
    );
    assert_eq!(crate::metrics::tick_aveugle_de("dispatch_notifiers").map(|(n, _)| n), Some(avant + 1), "un tour lu ne compte rien");
}
