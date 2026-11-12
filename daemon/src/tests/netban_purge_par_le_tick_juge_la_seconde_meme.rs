// `P11.25-a` (complément) — LE TICK DE MAINTENANCE PASSE À LA PURGE L'INSTANT QU'IL REÇOIT, À LA SECONDE PRÈS.
//
// Les témoins de `netban_purge_des_echus_juge_l_echeance_entiere.rs` jugent la règle « la seconde même comprise »
// sur `auth::netban_purger_les_echus` appelée directement ; ceux qui passent par le tick
// (`server::boucles_de_fond::netban_tick_de_maintenance`) posent leurs échéances à cent secondes de l'instant. Un
// tick qui purgerait à `now_ts + 1` (ou `now_ts - 1`) restait vert, et le rechargement qui suit la purge débloquait
// alors l'adresse une seconde trop tôt (`net_ban_is_blocked` ne lit que le cache).
//
// Ici, par le TICK : trois échéances entières, à l'instant moins un, à l'instant même et à l'instant plus un. Les deux
// premières sont purgées, la troisième gardée ; l'ensemble EXACT des adresses restantes est comparé, puis la carte
// entière du cache rechargé par le même tick. Mutants rouges : le tick passe `now_ts + 1` (l'adresse de l'instant
// plus un est purgée, le cache est vide), le tick passe `now_ts - 1` (l'adresse de l'instant même reste en base et
// au cache).
//
// NE TIENT PAS : l'horloge de la boucle (`now()` dans `spawn_netban_maintenance`) n'est pas jouée ; l'instant est
// injecté, comme dans les témoins voisins.

#[cfg(test)]
mod netban_purge_par_le_tick {
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    /// L'instant injecté du tick.
    const NPT_T: i64 = 1_900_000_000;

    fn npt_poser(c: &Connection, ip: &str, echeance: i64) {
        c.execute(
            "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) \
             VALUES (?1, 't', 0, ?2, 'operateur', 'prod')",
            params![ip, echeance],
        )
        .expect("fixture : ligne posée");
    }

    fn npt_restantes(c: &Connection) -> BTreeSet<String> {
        let mut s = c.prepare("SELECT ip FROM net_ban").unwrap();
        let v = s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<Result<BTreeSet<_>, _>>().unwrap();
        v
    }

    /// Par le tick : échéance à l'instant - 1 et à l'instant même purgées, à l'instant + 1 gardée ; le cache rechargé ne
    /// porte que la dernière, avec son échéance.
    #[test]
    fn netban_purge_par_le_tick_juge_la_seconde_meme() {
        let _g = NETBAN_TEST_LOCK.lock();
        let c = test_db();
        npt_poser(&c, "192.0.2.91", NPT_T - 1);
        npt_poser(&c, "192.0.2.92", NPT_T);
        npt_poser(&c, "192.0.2.93", NPT_T + 1);
        let typees: i64 = c
            .query_row("SELECT count(*) FROM net_ban WHERE typeof(expires_ts) = 'integer'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(typees, 3, "contrôle : les trois échéances sont stockées entières");
        netban_cache().write().clear();
        crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPT_T);
        let cache: HashMap<String, Option<i64>> = netban_cache().read().clone();
        netban_cache().write().clear();
        let attendues: BTreeSet<String> = ["192.0.2.93".to_string()].into_iter().collect();
        assert_eq!(
            npt_restantes(&c),
            attendues,
            "le tick purge à l'instant reçu : l'instant même compris, l'instant + 1 gardé"
        );
        let attendu: HashMap<String, Option<i64>> = [("192.0.2.93".to_string(), Some(NPT_T + 1))].into_iter().collect();
        assert_eq!(cache, attendu, "le cache rechargé par le même tick ne porte que l'échéance gardée");
    }
}
