// =====================================================================================
// `P10.24-e` et `P10.31-i` (correction après vérification) — DEUX ORDRES DE JUGEMENT TENUS PAR LA ROUTE.
//
//  * `P10.24-e` : `user_update` refuse en `409` le mot de passe d'une LIGNE de tenant sous un plan de contrôle, « jugé
//    AVANT toute lecture : rien n'est écrit, compté ni inscrit ». Aucun témoin ne jouait un secret des gestes FAUX ou
//    ABSENT sur la ligne d'un AUTRE compte : le refus déplacé après le secret restait vert (mesuré par le vérificateur :
//    `403 secret_des_gestes_faux`, une ligne au registre, un échec compté au frein de l'auteur).
//  * `P10.31-i` : la portée `globale` de `logout_post` relit le super-administrateur dans `platform_user` ; la lecture
//    ratée y était avalée en « pas super-administrateur » (`unwrap_or(false)`), et un super-administrateur recevait
//    `403 RÉSERVÉE À UN ADMINISTRATEUR`, cause fausse. Elle est désormais nommée : `503`
//    `CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE`, rien de révoqué.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `BB3C_UU_APRES_SECRET` (le refus `409` déplacé
// après l'examen du secret des gestes) ; `BB3C_AUTORITE_AVALEE` (la lecture du super-administrateur qui avale l'erreur,
// la forme d'avant).
// =====================================================================================
mod mot_de_passe_refuse_avant_le_secret_et_autorite_non_lue_nommee {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{
        rgsc_base, rgsc_basic, rgsc_cinq_cent_trois, rgsc_compter, rgsc_connexion, rgsc_deconnexion_globale, rgsc_envoyer, rgsc_epoques,
        rgsc_ligne, rgsc_me, rgsc_plateforme, rgsc_traces_globales, RGSC_JSON, RGSC_MOT_DE_PASSE, RGSC_MOT_DE_PASSE_DE_LA_LIGNE,
        RGSC_MOT_DE_PASSE_NEUF, RGSC_TENANT_B,
    };
    use super::*;
    use crate::secret_des_gestes::ENTETE_DU_SECRET_DES_GESTES;

    /// Les échecs comptés au frein du secret des gestes, tous auteurs et adresses confondus.
    fn mrs_echecs_au_frein_du_secret(st: &AppState) -> u32 {
        st.auth_fails.lock().iter().filter(|((principal, _), _)| principal.starts_with("<secret-des-gestes:")).map(|(_, f)| f.count).sum()
    }

    /// CE QU'IL TIENT (`P10.24-e`) : mode multi-tenant avec plan de contrôle, par la route. `rgsc-ben`, administrateur de
    /// B, pose un mot de passe sur la ligne `rgsc-ana` de B (le compte d'un AUTRE : le secret des gestes serait exigé)
    /// avec un secret FAUX, puis SANS secret : `409` les deux fois, corps exact
    /// `{error: CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME}` ; aucune ligne `secret_des_gestes` au registre (ni
    /// celui de `st.db`, ni la base de B) ; aucun échec compté au frein du secret ; le haché de la ligne inchangé.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BB3C_UU_APRES_SECRET » (le secret faux rend `403`, une ligne au registre, un
    /// échec compté ; le secret absent rend `403`).
    #[tokio::test]
    async fn mrs_le_mot_de_passe_d_une_ligne_de_tenant_est_refuse_avant_le_secret_des_gestes() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne_ana_b = rgsc_ligne(&st, RGSC_TENANT_B, "rgsc-ana", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let ben = rgsc_basic("rgsc-ben", RGSC_MOT_DE_PASSE);
        let refus = json!({ "error": CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME });
        let neuf = json!({ "password": RGSC_MOT_DE_PASSE_NEUF }).to_string();
        let tenant_b = ("x-plume-tenant", RGSC_TENANT_B);
        let essais: [(&str, Vec<(&str, &str)>); 2] = [
            ("secret faux", vec![RGSC_JSON, tenant_b, (ENTETE_DU_SECRET_DES_GESTES, "ce-n-est-pas-le-secret-des-gestes-mrs")]),
            ("sans secret", vec![RGSC_JSON, tenant_b]),
        ];
        for (essai, entetes) in &essais {
            let r = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne_ana_b}"), Some(&ben), entetes, &neuf).await;
            assert_eq!((r.statut, &r.corps), (409, &refus), "{essai} : {}", r.texte);
            assert_eq!(rgsc_compter(&st.db.lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "secret_des_gestes"), 0, "{essai} : rien d'inscrit");
            assert_eq!(rgsc_compter(&rgsc_base(&st, RGSC_TENANT_B).lock(), "SELECT COUNT(*) FROM ledger WHERE kind=?1", "secret_des_gestes"), 0, "{essai} : rien d'inscrit dans B");
            assert_eq!(mrs_echecs_au_frein_du_secret(&st), 0, "{essai} : aucun échec compté");
        }
        let h: String = rgsc_base(&st, RGSC_TENANT_B).lock().query_row("SELECT hash FROM user WHERE id=?1", params![ligne_ana_b], |r| r.get(0)).expect("ligne lue");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE, &h), "le haché de la ligne de B est inchangé");
    }

    /// CE QU'IL TIENT (`P10.31-i`) : mode multi-tenant avec plan de contrôle, `POST /api/logout` sous la portée `globale`,
    /// au routeur. `platform_user` rendue illisible (table renommée) : la session du super-administrateur `rgsc-sa` rend
    /// `503`, corps exact `{error: CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE, id}` — pas le `403` du refus de droit —,
    /// aucun cookie effacé, rien de révoqué ni d'inscrit. CONTRÔLE POSITIF, table rendue : `200`, l'époque globale avance,
    /// la ligne de registre le nomme, la session de `rgsc-ben` tombe.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « BB3C_AUTORITE_AVALEE » (la lecture ratée rend `403`
    /// `CAUSE_DECONNEXION_GLOBALE_RESERVEE_A_UN_ADMIN`).
    #[tokio::test]
    async fn mrs_le_super_administrateur_non_relu_est_un_refus_nomme_pas_un_refus_de_droit() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ben = rgsc_connexion(addr, "rgsc-ben").await;
        let sa = rgsc_connexion(addr, "rgsc-sa").await;
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "fixture : ben résout dans B");
        let plan = st.tenants.control.as_ref().expect("plan");

        plan.conn.lock().execute_batch("ALTER TABLE platform_user RENAME TO platform_user_ecartee_mrs").expect("fixture : platform_user illisible");
        let r = rgsc_deconnexion_globale(addr, &sa).await;
        rgsc_cinq_cent_trois(&r, CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE);
        assert!(!r.cookie_efface(), "aucun cookie effacé sur un refus");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");

        plan.conn.lock().execute_batch("ALTER TABLE platform_user_ecartee_mrs RENAME TO platform_user").expect("fixture : platform_user rendue");
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 200, "ben est encore connecté");
        let r = rgsc_deconnexion_globale(addr, &sa).await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "contrôle positif : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1));
        assert_eq!(rgsc_traces_globales(&st).len(), 1, "la révocation est inscrite");
        assert!(rgsc_traces_globales(&st)[0].contains("'rgsc-sa'"), "la ligne de registre nomme le super-administrateur");
        assert_eq!(rgsc_me(addr, &ben, Some(RGSC_TENANT_B)).await, 401, "la session de ben est révoquée");
    }
}
