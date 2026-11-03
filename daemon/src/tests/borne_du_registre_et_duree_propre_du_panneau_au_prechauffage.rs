// =====================================================================================
// `P10.32-o` (vague BJ, reprise de la vague BI) — DEUX BRANCHES DU REGISTRE DES REFUS D'ÉCRITURE QUE LES TÉMOINS DE LA
// VAGUE BI LAISSAIENT SANS TÉMOIN.
//
// RELEVÉ PAR LE VÉRIFICATEUR DE LA VAGUE BI (mutants verts, cibles et suite complète) :
//  * `panneau_avoue::retenir_un_refus_d_ecriture` — la condition `!registre.contains_key(&cle)` (une clé déjà connue,
//    registre plein, est mise à jour sans rien retirer) : le témoin de
//    `prechauffage_lit_le_registre_des_refus_et_borne_sur_le_type_de_production.rs` ne met à jour que la clé la plus
//    ANCIENNE, celle que l'éviction aurait retirée de toute façon. Le mutant qui évince même pour une clé connue
//    (PA_BORNE_CLE_CONNUE_RETIRE) y restait vert ;
//  * `rollups::cache_refresh_all_panels` — la 4e colonne du SELECT, `COALESCE(panel_cache_ttl_s, ?1)`, borne le réessai
//    après un refus par la durée du cache PROPRE au panneau (le prédicat de `serve_swr::reessai_permis`) ; les panneaux
//    de `t3c_state` n'ont pas de `panel_cache_ttl_s`, donc la durée propre égalait la globale et le mutant qui prend la
//    globale (R_PRECH_TTL_GLOBAL) y restait vert.
//
// AUCUN CODE DE PRODUCTION NE CHANGE POUR CES DEUX BRANCHES : les témoins manquaient, pas le code.
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) registre plein, mise à jour de la clé la plus RÉCENTE puis d'une clé du MILIEU : taille inchangée, TOUTES les clés
//      restent (la plus ancienne comprise), la clé mise à jour porte le refus neuf entier ;
//  (B) par le site réel `cache_refresh_all_panels`, écriture de `panel_cache` refusée par un autorisateur, panneau à durée
//      PROPRE plus longue que la globale et refus antidaté entre les deux : le pré-chauffage ne retente rien (le refus garde
//      son instant antidaté) ;
//  (C) même site, durée PROPRE plus courte que la globale et refus antidaté entre les deux : le pré-chauffage retente (le
//      refus est re-noté à l'instant de la nouvelle tentative). (B) et (C) ensemble : la durée qui décide est celle du
//      panneau, dans les deux sens.
// MUTANTS JOUÉS (variable `VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// `PA_BORNE_CLE_CONNUE_RETIRE` (condition `!registre.contains_key(&cle)` neutralisée : (A)), `R_PRECH_TTL_GLOBAL`
// (4e colonne = `?1` : (B) et (C)).
// CE QUE CES TÉMOINS NE TIENNENT PAS : la borne n'est pas jouée sur le registre global du processus (le remplir
// évincerait les refus notés par les autres tests) ; elle l'est sur une table du type de la production, par la fonction
// que `noter_l_issue_de_l_ecriture` appelle.
// =====================================================================================
mod borne_du_registre_et_duree_propre_du_panneau_au_prechauffage {
    use super::*;
    use crate::handlers::panneau_avoue::RefusDEcritureDeCache;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    fn bj1_refus(refusee_a: i64, echec: Option<&str>) -> RefusDEcritureDeCache {
        RefusDEcritureDeCache { refusee_a, echec_du_calcul: echec.map(str::to_string) }
    }

    // ---------------------------------------------------------------------------------
    // (A) CLÉ CONNUE, REGISTRE PLEIN : RIEN N'EST RETIRÉ.
    // ---------------------------------------------------------------------------------
    #[test]
    fn bj1_cle_connue_la_plus_recente_mise_a_jour_au_plein_ne_retire_aucune_autre_cle() {
        let borne = panneau_avoue::BORNE_DES_ECRITURES_DE_CACHE_REFUSEES;
        let cle = |i: i64| ("bj1-base".to_string(), i, "w=86400".to_string(), "fp".to_string());
        let mut registre: HashMap<_, RefusDEcritureDeCache> = HashMap::new();
        // Instant CROISSANT avec la clé : `cle(1)` est la plus ancienne, `cle(borne)` la plus récente.
        for i in 1..=borne as i64 {
            panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(i), bj1_refus(1_000_000 + i, None));
        }
        assert_eq!(registre.len(), borne, "contrôle : le registre est plein");
        let plus_ancienne = cle(1);
        let plus_recente = borne as i64;
        // La plus RÉCENTE mise à jour : une éviction à tort retirerait `cle(1)`, pas elle.
        panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(plus_recente), bj1_refus(9_000_000, Some("phrase servie")));
        assert_eq!(registre.len(), borne, "clé connue (la plus récente), registre plein : la taille ne bouge pas");
        assert!(registre.contains_key(&plus_ancienne), "clé connue (la plus récente) : la plus ancienne n'est PAS retirée");
        assert_eq!(
            registre.get(&cle(plus_recente)),
            Some(&bj1_refus(9_000_000, Some("phrase servie"))),
            "clé connue : instant et échec porté remplacés"
        );
        // Une clé du MILIEU mise à jour : rien de retiré non plus.
        let milieu = borne as i64 / 2;
        panneau_avoue::retenir_un_refus_d_ecriture(&mut registre, cle(milieu), bj1_refus(9_000_001, None));
        assert_eq!(registre.len(), borne, "clé connue (du milieu), registre plein : la taille ne bouge pas");
        assert!(registre.contains_key(&plus_ancienne), "clé connue (du milieu) : la plus ancienne n'est PAS retirée");
        assert!(registre.contains_key(&cle(2)), "clé connue (du milieu) : la deuxième plus ancienne n'est pas retirée");
        assert_eq!(registre.get(&cle(milieu)), Some(&bj1_refus(9_000_001, None)), "clé du milieu : refus remplacé entier");
        let manquantes = (1..=borne as i64).filter(|i| !registre.contains_key(&cle(*i))).count();
        assert_eq!(manquantes, 0, "aucune clé connue retirée par une mise à jour");
    }

    // ---------------------------------------------------------------------------------
    // (B) et (C) LA DURÉE PROPRE DU PANNEAU DÉCIDE DU RÉESSAI AU PRÉ-CHAUFFAGE.
    // ---------------------------------------------------------------------------------
    fn bj1_refuser_le_cache(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// Pose la durée propre du panneau, refuse les écritures du cache, antidate le refus de `age` secondes, joue le
    /// pré-chauffage par son site réel ; rend (instant antidaté, instant noté après le pré-chauffage, instant d'avant
    /// le pré-chauffage).
    fn bj1_prechauffer_avec_un_refus_antidate(
        st: &AppState, dbp: &crate::tmp_possede::TmpDb, sain: i64, ttl_propre: i64, age: i64,
    ) -> (i64, Option<i64>, i64) {
        st.db.lock().execute("UPDATE panel SET panel_cache_ttl_s=?1 WHERE id=?2", params![ttl_propre, sain]).unwrap();
        assert_eq!(
            panel_cache_ttl(&st.db.lock(), sain, 0),
            ttl_propre,
            "contrôle : la durée propre du panneau est écrite et lue"
        );
        bj1_refuser_le_cache(&st.db.lock());
        let n = now();
        let rk = cache_range_key(n - 86_400, 0, n); // la clé du pré-chauffage (fenêtre par défaut de 24 h)
        let fp = query_fingerprint(T3C_SQL_SAIN, false);
        let antidate = now() - age;
        let r = panneau_avoue::cache_ecrire_dit(&st.db.lock(), sain, &rk, &fp, antidate, "{}");
        assert!(r.is_err(), "fixture : l'écriture qui note le refus est bien refusée");
        assert_eq!(
            panneau_avoue::ecriture_de_cache_refusee(&st.db.lock(), sain, &rk, &fp),
            Some(antidate),
            "contrôle : refus antidaté noté"
        );
        let avant = now();
        crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem, "default");
        (antidate, panneau_avoue::ecriture_de_cache_refusee(&st.db.lock(), sain, &rk, &fp), avant)
    }

    #[tokio::test]
    async fn bj1_duree_propre_plus_longue_que_la_globale_le_prechauffage_ne_retente_pas() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels lit load_config()
        let (st, dbp, _gxql, _panne, sain) = t3c_state("bj1-ttl-long");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        assert!(ttl_global > 0, "précondition : cache global des panneaux actif ({ttl_global})");
        // Globale < âge du refus < durée propre : seule la durée propre interdit le réessai.
        let ttl_propre = ttl_global + 1_800;
        let age = ttl_global + 30;
        let (antidate, apres, _avant) = bj1_prechauffer_avec_un_refus_antidate(&st, &dbp, sain, ttl_propre, age);
        assert_eq!(
            apres,
            Some(antidate),
            "refus plus récent que la durée PROPRE du panneau (mais plus vieux que la globale) : aucune tentative"
        );
        ff_rm(&dbp);
    }

    #[tokio::test]
    async fn bj1_duree_propre_plus_courte_que_la_globale_le_prechauffage_retente() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels lit load_config()
        let (st, dbp, _gxql, _panne, sain) = t3c_state("bj1-ttl-court");
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        assert!(ttl_global >= 8, "précondition : durée globale assez longue pour loger une durée propre plus courte ({ttl_global})");
        // Durée propre < âge du refus < globale : seule la durée propre permet le réessai.
        let ttl_propre = ttl_global / 4;
        let age = ttl_global / 2;
        let (antidate, apres, avant) = bj1_prechauffer_avec_un_refus_antidate(&st, &dbp, sain, ttl_propre, age);
        let apres = apres.expect("durée propre écoulée : une tentative, refusée, et re-notée");
        assert_ne!(apres, antidate, "durée propre écoulée (mais pas la globale) : le pré-chauffage a retenté");
        assert!(apres >= avant, "le refus re-noté est celui de la nouvelle tentative ({apres} < {avant})");
        ff_rm(&dbp);
    }
}
