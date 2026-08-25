// =====================================================================================
// LES PORTES PAR LESQUELLES LE SUR-COMPTE DE LA ROUTE A S'ATTEINDRAIT — ET CE QU'ELLES LAISSENT PASSER.
//
// La ROUTE A (`stats count by source`) sur-compte quand `event_rollup` témoigne de buckets plus anciens
// que ce qu'`event` porte encore (cf. `route_a_sur_compte_sous_le_plancher_event_et_le_declare`, qui le
// FABRIQUE et l'épingle). La question tranchée ici n'est pas « est-ce possible » — c'est « par quelle
// porte la PRODUCTION y entre ». Il y en a deux : la RÉTENTION, fermée et prouvée ici ; le TIER FROID,
// ouverte dans la table mais fermée sur le chemin servi (route COLD partitionnée à `B`, épinglée par
// `phase_a_hot_cold_union_no_double_count_at_boundary` sous la feature `cold_tier`). La décision écrite
// sur ce qui reste — « le tier froid a tourné puis a été désactivé » — est en tête du test d'épinglage.
// =====================================================================================

    /// LA RÉTENTION NE LAISSE JAMAIS LE ROLLUP TÉMOIGNER D'HEURES QU'`event` N'A PLUS.
    ///
    /// C'EST LA MESURE QUI TRANCHE POUR LE RÉSIDU DE LA ROUTE A. La ROUTE A sur-compte quand
    /// `event_rollup` garde des buckets plus anciens que `MIN(event.ts)` (cf. le test d'épinglage
    /// `route_a_sur_compte_sous_le_plancher_event_et_le_declare`). Reste à savoir PAR QUELLE PORTE cet
    /// état s'atteint. La rétention en est une candidate évidente — et ce test montre qu'elle ne l'ouvre
    /// PAS : `retention_run_tenant` purge `event` ET `event_rollup` au MÊME cutoff, et purge même le
    /// rollup PLUS profondément (les sources de contrôle `origin='daemon'` sont épargnées dans `event`,
    /// pas dans le rollup). Après purge, aucun bucket de rollup n'est plus vieux que le plus vieux `ts`
    /// d'`event` : la ROUTE A ne peut rien sur-compter par cette porte.
    ///
    /// LA PORTE QUI RESTE, ET LA DÉCISION. Le tier froid, lui, supprime les lignes d'`event` d'un jour
    /// scellé SANS toucher aux rollups (c'est délibéré : `cold_rollup`/`cold_dim_rollup` servent ces
    /// heures). L'asymétrie y est donc RÉELLE — mais la route qui sert une fenêtre descendant sous la
    /// frontière `B` est la route COLD, qui partitionne à `B` et ne lit JAMAIS `event_rollup` en dessous
    /// (épinglé par `cold_route_a_ne_lit_jamais_event_rollup_sous_la_frontiere`, sous la feature).
    /// Il ne subsiste que l'état « le tier froid a tourné, puis a été désactivé » : la ROUTE A y sert
    /// alors la mémoire que le rollup garde d'événements RÉELS, sous `approx:true`, et la ROUTE B fait
    /// EXACTEMENT LA MÊME CHOSE (sa bande n'est remontée que par la rétention, pas par le vieillissement)
    /// — les deux routes restent donc d'accord entre elles. On LAISSE ce résidu, avec son test
    /// d'épinglage : le corriger reviendrait à effacer de la réponse des événements qui ont bel et bien
    /// existé, sur le seul chemin qui les compte encore.
    #[test]
    fn la_retention_ne_laisse_jamais_le_rollup_plus_vieux_qu_event() {
        let _g = VERROU_ENV_PROCESSUS.write();
        let conn = test_db();
        let n = now();
        // 20 jours d'histoire horaire + un event de CONTRÔLE très ancien (origin='daemon' : non purgeable
        // d'`event`, mais son bucket de rollup, lui, l'est) -> le cas le plus défavorable au rollup.
        for j in 1..=20 {
            dimt_seed(&conn, n - j * 86400, "web", "status", "200", 3, &format!("j{j}"));
        }
        conn.execute(
            "INSERT INTO event(ts,source,message,origin,dedup) VALUES(?1,'plume-config','tres ancien','daemon','ctrl')",
            params![n - 90 * 86400],
        )
        .unwrap();
        rollup_events(&conn);
        let plus_vieux_rollup = |c: &Connection| -> Option<i64> {
            c.query_row("SELECT MIN(bucket) FROM event_rollup", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()
        };
        assert!(plus_vieux_rollup(&conn).unwrap() < n - 15 * 86400, "socle : le rollup porte bien de l'histoire");

        // RÉTENTION à 7 jours, par le chemin de production.
        std::env::set_var("PLUME_RETENTION_DAYS", "7");
        let db = Arc::new(parking_lot::Mutex::new(conn));
        retention_run_tenant(&db, ":memory:");
        std::env::remove_var("PLUME_RETENTION_DAYS");
        let conn = db.lock();

        let plancher_event: i64 =
            conn.query_row("SELECT MIN(ts) FROM event", [], |r| r.get::<_, Option<i64>>(0)).unwrap().expect("event non vide");
        let plancher_rollup = plus_vieux_rollup(&conn).expect("le rollup garde des buckets récents");
        assert!(
            plancher_rollup >= (plancher_event / 3600) * 3600,
            "le rollup témoigne d'un bucket ({plancher_rollup}) plus ancien que ce qu'`event` porte ({plancher_event}) : \
             la ROUTE A sur-compterait par la porte de la RÉTENTION"
        );
        // …et la MÊME propriété PAR SOURCE, qui est celle qui MORD. La globale ci-dessus est rendue facile
        // par l'event de contrôle non purgeable : il tire `MIN(event.ts)` très bas, donc n'importe quel
        // plancher de rollup passe. Par source purgeable, il n'y a plus de filet — une rétention qui
        // garderait le rollup ne serait-ce qu'un cran plus profond qu'`event` casse ici (vérifié par mutation).
        let (p_ev_web, p_ro_web): (i64, i64) = (
            conn.query_row("SELECT MIN(ts) FROM event WHERE source='web'", [], |r| r.get(0)).unwrap(),
            conn.query_row("SELECT MIN(bucket) FROM event_rollup WHERE source='web'", [], |r| r.get(0)).unwrap(),
        );
        assert!(
            p_ro_web >= (p_ev_web / 3600) * 3600,
            "par source : le rollup de `web` remonte à {p_ro_web} alors qu'`event` s'arrête à {p_ev_web}"
        );
        // …et la ROUTE A, sur toute la fenêtre, ne rend alors RIEN DE PLUS que le brut.
        let rr = try_rollup_route_at(
            "search | stats count by source", 0, 0, None, n,
            RollupCoverage::unproven(), DimRollupCoverage::unproven(),
        )
        .expect("ROUTE A route toujours");
        let route: i64 = conn.query_row(&format!("SELECT COALESCE(SUM(\"count\"),0) FROM ({}) WHERE \"source\"='web'", rr.sql), [], |r| r.get(0)).unwrap();
        let brut: i64 = conn.query_row("SELECT COUNT(*) FROM event WHERE source='web'", [], |r| r.get(0)).unwrap();
        assert!(route <= brut, "SUR-COMPTE après rétention : {route} contre {brut} en brut");
        // L'ÉCART RESTANT EST UN SOUS-COMPTE, ET IL EST BORNÉ À UNE HEURE — mesuré ici, pas supposé. La
        // rétention supprime `event` par `ts < cutoff` et le rollup par `bucket < cutoff` ; comme un bucket
        // commence AVANT les `ts` qu'il contient, le bucket qui CHEVAUCHE le cutoff part du rollup alors que
        // ses lignes `ts >= cutoff` restent dans `event`. C'est ce qui rend le SUR-compte inatteignable par
        // cette porte, et c'est la contrepartie : un sous-compte confiné au bucket frontière, servi sous
        // `approx:true`. On l'épingle exactement, pour qu'il ne dérive pas en silence.
        let manquant: i64 = conn
            .query_row("SELECT COUNT(*) FROM event WHERE source='web' AND ts < ?1", params![plancher_rollup], |r| r.get(0))
            .unwrap();
        assert_eq!(route, brut - manquant, "le sous-compte doit valoir EXACTEMENT ce que le rollup ne couvre plus");
        assert!(manquant < 3 * 3, "…et rester confiné au bucket frontière (mesuré {manquant} sur {brut})");
    }
