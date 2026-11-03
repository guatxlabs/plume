// =====================================================================================
// `P10.32-o` (vague BI, correction) — LA BORNE DU REGISTRE DES REFUS JOUÉE SUR LE TYPE DE PRODUCTION, ET LE PRÉ-CHAUFFAGE
// QUI LIT CE REGISTRE.
//
// RELEVÉ PAR LE VÉRIFICATEUR DE LA VAGUE BI :
//  * la borne du registre (`panneau_avoue::retenir_un_refus_d_ecriture`) était générique, et son témoin la jouait sur des
//    `i64` (`impl InstantDuRefus for i64`, du code de production qui ne servait qu'au test). L'implémentation de la
//    production, `RefusDEcritureDeCache::refusee_a`, n'était jouée par aucun test : classer par `-refusee_a` (le refus le
//    plus RÉCENT retiré) restait vert, cibles et suite complète ;
//  * lu dans le code : `rollups::cache_refresh_all_panels` ne consultait pas le registre. Base qui refuse d'écrire ->
//    chaque panneau recalculé à chaque tick (`PLUME_PANEL_REFRESH_S`, 10 s par défaut) et une ligne `[cache] … NON ÉCRIT`
//    par panneau et par tick, alors que le 503 servi annonce « un nouveau calcul est armé au plus une fois par durée du
//    cache ».
//
// LE CORRECTIF : `retenir_un_refus_d_ecriture` ne prend plus que le type de la production (le trait et ses deux impls
// sont retirés) ; le pré-chauffage lit `refus_d_ecriture_de_cache` et saute, sans calcul ni ligne, un panneau dont le
// refus noté a moins que la durée du cache du panneau (le prédicat de `serve_swr::reessai_permis`).
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) la borne, sur des `RefusDEcritureDeCache` : au plein, une clé connue est remplacée ENTIÈRE (instant et ce qu'elle
//      portait) ; une clé neuve retire le refus de plus petit `refusee_a`, et lui seul ;
//  (B) par le site réel `cache_refresh_all_panels`, écriture de `panel_cache` refusée par un autorisateur : le premier
//      pré-chauffage note le refus (contrôle) ; refus antidaté d'une demi-durée du cache -> le pré-chauffage ne tente
//      RIEN (le refus reste à l'instant antidaté : aucune écriture tentée, donc aucun calcul écrit ni ligne de journal de
//      l'écriture refusée) ; antidaté au-delà de la durée -> une tentative, refus re-noté récent ; écriture rendue
//      possible et refus antidaté au-delà -> la ligne est écrite et le refus effacé.
// MUTANTS JOUÉS (variable de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `BI2C_P16`
// (classement par `-refusee_a`), `BI2C_PRECH` (le saut du pré-chauffage retiré).
// CE QUE CES TÉMOINS NE TIENNENT PAS : « rien de retiré » pour une clé connue — la clé mise à jour en (A) est la plus
// ANCIENNE, que l'éviction retirerait de toute façon, et la durée PROPRE du panneau — les panneaux de `t3c_state` n'en ont
// pas, elle égale la globale ; ces deux branches sont tenues par `borne_du_registre_et_duree_propre_du_panneau_au_prechauffage.rs`
// (vague BJ). La ligne `[cache]` d'un tick sauté n'est pas capturée (l'absence de tentative est
// jugée par le registre, que seule une tentative refusée réécrit) ; un pré-chauffage dont le calcul ÉCHOUE et dont
// l'aveu joint est refusé est sauté de même (même registre), sans témoin propre ici.
// =====================================================================================
mod prechauffage_lit_le_registre_des_refus_et_borne_sur_le_type_de_production {
    use super::*;
    use crate::handlers::panneau_avoue::RefusDEcritureDeCache;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    fn bi2c_refus(refusee_a: i64, echec: Option<&str>) -> RefusDEcritureDeCache {
        RefusDEcritureDeCache { refusee_a, echec_du_calcul: echec.map(str::to_string) }
    }

    // ---------------------------------------------------------------------------------
    // (A) LA BORNE, SUR LE TYPE DE LA PRODUCTION.
    // ---------------------------------------------------------------------------------
    #[test]
    fn bi2c_la_borne_du_registre_retire_le_refus_le_plus_ancien_du_type_de_production() {
        let borne = panneau_avoue::BORNE_DES_ECRITURES_DE_CACHE_REFUSEES;
        let cle = |i: i64| ("bi2c-base".to_string(), i, "w=86400".to_string(), "fp".to_string());
        let mut registre: HashMap<_, RefusDEcritureDeCache> = HashMap::new();
        // Instants DÉCROISSANTS avec la clé : l'ordre d'insertion ne désigne pas le plus ancien.
        for i in 1..=borne as i64 {
            panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(i), bi2c_refus(10_000_000 - i, None));
        }
        assert_eq!(registre.len(), borne, "contrôle : le registre est plein");
        let plus_ancien_d_abord = borne as i64; // instant 10_000_000 - borne, le plus petit
        // Clé connue, registre plein : remplacée entière, rien de retiré. Son instant devient le plus grand.
        panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(plus_ancien_d_abord), bi2c_refus(20_000_000, Some("phrase servie")));
        assert_eq!(registre.len(), borne, "clé connue, registre plein : rien n'est retiré");
        assert!((1..=borne as i64).all(|i| registre.contains_key(&cle(i))), "clé connue : toutes les clés restent");
        assert_eq!(
            registre.get(&cle(plus_ancien_d_abord)),
            Some(&bi2c_refus(20_000_000, Some("phrase servie"))),
            "clé connue : instant et échec porté remplacés"
        );
        // Le plus ancien est désormais la clé `borne - 1` (instant 10_000_000 - borne + 1).
        let neuve = borne as i64 + 1;
        panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(neuve), bi2c_refus(5, None));
        assert_eq!(registre.len(), borne, "clé neuve, registre plein : un refus retiré");
        assert!(!registre.contains_key(&cle(borne as i64 - 1)), "le refus de plus petit `refusee_a` est celui qui est retiré");
        assert!(registre.contains_key(&cle(plus_ancien_d_abord)), "le refus le plus RÉCENT reste");
        assert!(registre.contains_key(&cle(1)), "le premier inséré (instant le plus grand des anciens) reste");
        assert_eq!(registre.get(&cle(neuve)), Some(&bi2c_refus(5, None)), "la neuve est notée telle quelle");
        // Retrait suivant : la neuve (instant 5) est maintenant la plus ancienne.
        panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(neuve + 1), bi2c_refus(30_000_000, None));
        assert!(!registre.contains_key(&cle(neuve)), "la neuve la plus ancienne est retirée à son tour");
        assert_eq!(registre.len(), borne, "toujours à la borne");
    }

    // ---------------------------------------------------------------------------------
    // (B) LE PRÉ-CHAUFFAGE LIT LE REGISTRE.
    // ---------------------------------------------------------------------------------
    fn bi2c_refuser_le_cache(conn: &Connection, refuser: bool) {
        if refuser {
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        } else {
            conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        }
    }

    #[tokio::test]
    async fn bi2c_le_prechauffage_ne_retente_pas_avant_la_duree_du_cache_depuis_le_refus() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels et panel_serve_cfg_de lisent load_config()
        let (st, dbp, _gxql, _panne, sain) = t3c_state("bi2c-prechauffe");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        let ttl = panel_cache_ttl(&st.db.lock(), sain, ttl_global);
        assert!(ttl >= 4, "précondition : cache des panneaux actif, durée assez longue pour une demi-durée ({ttl})");
        let n = now();
        let rk = cache_range_key(n - 86_400, 0, n); // la clé du pré-chauffage (fenêtre par défaut de 24 h)
        let fp = query_fingerprint(T3C_SQL_SAIN, false);
        let refus = || panneau_avoue::ecriture_de_cache_refusee(&st.db.lock(), sain, &rk, &fp);
        let antidater = |instant: i64| {
            let r = panneau_avoue::cache_ecrire_dit(&st.db.lock(), sain, &rk, &fp, instant, "{}");
            assert!(r.is_err(), "fixture : l'écriture qui note le refus est bien refusée");
        };
        let prechauffer = || crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem, "default");

        bi2c_refuser_le_cache(&st.db.lock(), true);
        let avant = now();
        prechauffer();
        let r1 = refus().expect("contrôle : le pré-chauffage a tenté d'écrire, refus noté");
        assert!(r1 >= avant, "contrôle : refus noté à l'instant de la tentative ({r1} < {avant})");

        let demi = now() - ttl / 2;
        antidater(demi);
        assert_eq!(refus(), Some(demi), "contrôle : refus antidaté d'une demi-durée du cache");
        prechauffer();
        assert_eq!(refus(), Some(demi), "refus plus récent que la durée du cache : le pré-chauffage ne retente rien");
        assert!(panneau_avoue::cache_lire(&st.db.lock(), sain, &rk, &fp).is_none(), "contrôle, vrai par construction (l'autorisateur refuse tout INSERT de panel_cache) : rien d'écrit ; le juge est le refus resté à son instant antidaté");

        let echu = now() - ttl - 5;
        antidater(echu);
        let avant = now();
        prechauffer();
        let r3 = refus().expect("durée écoulée : une tentative, refusée, et re-notée");
        assert!(r3 >= avant, "durée écoulée : le refus re-noté est celui de la nouvelle tentative ({r3} < {avant})");

        antidater(now() - ttl - 5);
        bi2c_refuser_le_cache(&st.db.lock(), false);
        prechauffer();
        assert_eq!(refus(), None, "écriture rendue possible : le succès efface le refus");
        let ecrite = panneau_avoue::cache_lire(&st.db.lock(), sain, &rk, &fp).map(|(p, _)| p);
        let ecrite: Option<Value> = ecrite.and_then(|p| serde_json::from_str(&p).ok());
        assert_eq!(ecrite.map(|v| v["rows"].clone()), Some(json!([[1]])), "la ligne calculée est écrite");
        ff_rm(&dbp);
    }
}
