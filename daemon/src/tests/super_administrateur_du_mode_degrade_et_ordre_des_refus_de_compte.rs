// =====================================================================================
// `P10.31-i` et `P10.24-e` (témoins après vérification) — SANS PLAN DE CONTRÔLE PERSONNE N'EST SUPER-ADMINISTRATEUR ;
// LES DEUX PORTES DE LA RÉVOCATION GLOBALE NOMMENT LA MÊME AUTORITÉ NON LUE ; LE MOT DE PASSE D'UNE LIGNE DE TENANT EST
// REFUSÉ AVANT TOUTE LECTURE.
//
// Trois cas relevés par le vérificateur, mesurés sur l'arbre du lot avant ce fichier :
//  * `rbac::platform_user_superadmin_lu`, branche « sans plan de contrôle » : la rendre `Ok(true)` ne faisait rougir
//    aucun témoin. Le mode multi-tenant dégradé (`PLUME_MULTI_TENANT=1`, plan de contrôle non initialisé) n'était joué
//    que par le SSO d'en-têtes, qui juge le super-administrateur par les groupes. Basic et cookie passent par cette
//    branche (`rbac::resolve_tenant_access`) : sous la mutation, l'administrateur de configuration révoque toutes les
//    sessions par bris de glace, et un lecteur se voit servir `is_superadmin: true`.
//  * `session::revocation_globale_post` jugeait `au.is_superadmin`, que `rbac::platform_user_is_superadmin` rend `false`
//    quand `platform_user` est illisible : un super-administrateur dont la valeur ne se lisait pas recevait le `403` de la
//    réserve, alors que l'autre porte (`logout_post`, portée `globale`) sert le `503` AUTORITÉ NON LUE. Corrigé : la route
//    relit la valeur pour Basic et cookie, et nomme l'échec de la même phrase.
//  * `handlers::users_lookups::user_update` : le commentaire dit le refus `409` du mot de passe d'une ligne de tenant
//    « jugé AVANT toute lecture » ; le déplacer après le bloc de lecture ne faisait rougir aucun témoin.
//
// MUTANTS JOUÉS (posés sous `VERIF_MUT`, retirés avant le commit), chacun vu ROUGE : `A4` (la branche sans plan de
// contrôle rend `Ok(true)`) ; `C4` (la route ne relit pas : la forme d'avant) ; `B10` (le refus `409` déplacé après la
// lecture de la cible et la validation du corps).
// =====================================================================================
mod super_administrateur_du_mode_degrade_et_ordre_des_refus_de_compte {
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{
        rgsc_basic, rgsc_cinq_cent_trois, rgsc_connexion, rgsc_deconnexion_globale, rgsc_envoyer, rgsc_epoques, rgsc_ligne, rgsc_plateforme, rgsc_traces_globales,
        RGSC_JSON, RGSC_MOT_DE_PASSE, RGSC_MOT_DE_PASSE_DE_LA_LIGNE, RGSC_TENANT_A,
    };
    use super::*;
    use std::sync::atomic::Ordering;

    const SDO_ROUTE_REVOCATION: &str = "/api/sessions/revocation-globale";

    /// Le mode multi-tenant dégradé, fabriqué par l'ÉTAT : la base du routeur (`vwr` lecteur, `root` administrateur de
    /// configuration, tous deux par Basic), `multi_tenant` vrai, AUCUN plan de contrôle.
    fn sdo_mode_degrade(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = router_test_state(&format!("sdo-{tag}"));
        st.installation_ouverte.store(false, Ordering::SeqCst);
        st.multi_tenant = true;
        assert!(st.tenants.control.is_none(), "fixture : aucun plan de contrôle");
        (st, p)
    }

    /// CE QU'IL TIENT (`P10.31-i`, mode dégradé, Basic) : sans plan de contrôle, `platform_user_superadmin_lu` rend
    /// `Ok(false)` pour `root` et `vwr`. Par le routeur, joués AVANT tout jugement puis jugés ensemble : `root`
    /// (administrateur de configuration) sous `default`, avec `x-plume-breakglass`, `POST /api/sessions/revocation-globale`
    /// -> `403`, aucun cookie effacé, époque globale `(0, 0)`, aucune ligne `auth.deconnexion.globale` ; `vwr` (lecteur)
    /// `GET /api/me` sous `default` ne se voit jamais servir `is_superadmin: true`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « A4 » (la branche sans plan de contrôle rend `Ok(true)` : la révocation globale
    /// `200` par bris de glace, l'époque avance, et `vwr` reçoit `200` avec `is_superadmin: true`).
    #[tokio::test]
    async fn sdo_mode_degrade_basic_personne_n_est_super_administrateur() {
        let (st, _p) = sdo_mode_degrade("basic");
        let lus: Vec<Result<bool, String>> = ["root", "vwr"].iter().map(|n| crate::rbac::platform_user_superadmin_lu(&st, n)).collect();
        let addr = router_serve(st.clone()).await;
        let root = rgsc_basic("root", "rootpw1234567");
        let r = rgsc_envoyer(addr, "POST", SDO_ROUTE_REVOCATION, Some(&root), &[("x-plume-tenant", "default"), ("x-plume-breakglass", "sdo-temoin")], "").await;
        let vwr = rgsc_basic("vwr", "viewerpw12345");
        let me = rgsc_envoyer(addr, "GET", "/api/me", Some(&vwr), &[("x-plume-tenant", "default")], "").await;
        let me_super = me.statut == 200 && me.corps["is_superadmin"] == json!(true);
        assert_eq!(
            (lus, r.statut, r.cookie_efface(), rgsc_epoques(&st), rgsc_traces_globales(&st).len(), me_super),
            (vec![Ok(false), Ok(false)], 403, false, (0, 0), 0, false),
            "sans plan de contrôle, ni root (bris de glace) ni vwr ne sont super-administrateurs : {} | {}",
            r.texte,
            me.texte
        );
    }

    /// La SEULE valeur `is_superadmin` de `nom` rendue illisible (BLOB), ou rendue à l'entier `valeur`.
    fn sdo_poser_is_superadmin(st: &AppState, nom: &str, valeur: Option<i64>) {
        let plan = st.tenants.control.as_ref().expect("fixture : plan de contrôle");
        let c = plan.conn.lock();
        let n = match valeur {
            None => c.execute("UPDATE platform_user SET is_superadmin=X'01' WHERE name=?1", params![nom]),
            Some(v) => c.execute("UPDATE platform_user SET is_superadmin=?1 WHERE name=?2", params![v, nom]),
        }
        .expect("fixture : is_superadmin posé");
        assert_eq!(n, 1, "fixture : une ligne {nom}");
    }

    /// CE QU'IL TIENT (`P10.31-i`, les deux portes) : mode multi-tenant avec plan de contrôle. `rgsc-sa`, super-administrateur
    /// administrateur de A, se connecte, puis sa SEULE valeur `is_superadmin` est rendue illisible. Par son cookie : la
    /// portée `globale` de `POST /api/logout` ET `POST /api/sessions/revocation-globale` sous A (jeton CSRF) rendent le même
    /// `503` nommé, `{error: CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE, id}` ; époque globale `(0, 0)`, rien d'inscrit.
    /// CONTRÔLE POSITIF, la valeur rendue à l'entier `1` : la route rend `200`, l'époque globale avance.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « C4 » (la route ne relit pas la valeur : le `403` de la réserve,
    /// `CAUSE_REVOCATION_GLOBALE_RESERVEE`, servi au super-administrateur).
    #[tokio::test]
    async fn sdo_les_deux_portes_nomment_l_autorite_non_lue() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let sa = rgsc_connexion(addr, "rgsc-sa").await;
        sdo_poser_is_superadmin(&st, "rgsc-sa", None);
        let (cookie, csrf) = (format!("plume_session={sa}"), csrf_for(st.session_secret.as_slice(), &sa));
        let entetes = [("Cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str()), ("x-plume-tenant", RGSC_TENANT_A)];

        let porte_1 = rgsc_deconnexion_globale(addr, &sa).await;
        rgsc_cinq_cent_trois(&porte_1, CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE);
        let porte_2 = rgsc_envoyer(addr, "POST", SDO_ROUTE_REVOCATION, None, &entetes, "").await;
        rgsc_cinq_cent_trois(&porte_2, CAUSE_DECONNEXION_GLOBALE_AUTORITE_NON_LUE);
        assert!(!porte_2.cookie_efface(), "aucun cookie effacé");
        assert_eq!(rgsc_epoques(&st), (0, 0), "rien n'est révoqué");
        assert!(rgsc_traces_globales(&st).is_empty(), "rien n'est inscrit");

        sdo_poser_is_superadmin(&st, "rgsc-sa", Some(1));
        let r = rgsc_envoyer(addr, "POST", SDO_ROUTE_REVOCATION, None, &entetes, "").await;
        assert_eq!((r.statut, &r.corps), (200, &json!({ "ok": true, "portee": "globale" })), "contrôle positif : {}", r.texte);
        assert_eq!(rgsc_epoques(&st), (1, 1), "contrôle positif : l'époque globale avance");
    }

    /// CE QU'IL TIENT (`P10.24-e`, l'ordre des refus de `user_update`) : mode multi-tenant avec plan de contrôle.
    /// `rgsc-dan`, administrateur de `default`, par Basic sous `default`, sans secret des gestes, joués AVANT tout jugement
    /// puis jugés ensemble : `{password}` sur un identifiant ABSENT -> `409`, et `{password, role: <invalide>}` sur une
    /// ligne de `default` -> `409`, corps exact `{error: CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME}` les deux
    /// fois — ni le `404` de la cible absente, ni le `400` du rôle invalide ; le haché et le rôle de la ligne inchangés.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : « B10 » (le refus déplacé après la lecture et la validation : `404` puis `400`).
    #[tokio::test]
    async fn sdo_le_mot_de_passe_d_une_ligne_de_tenant_est_refuse_avant_toute_lecture() {
        let (st, _dir) = rgsc_plateforme().await;
        let addr = router_serve(st.clone()).await;
        let ligne = rgsc_ligne(&st, "default", "sdo-cible", "editor", RGSC_MOT_DE_PASSE_DE_LA_LIGNE);
        let absent = ligne + 999_999;
        let dan = rgsc_basic("rgsc-dan", RGSC_MOT_DE_PASSE);
        let entetes = [RGSC_JSON, ("x-plume-tenant", "default")];
        let r_absent = rgsc_envoyer(addr, "POST", &format!("/api/users/{absent}"), Some(&dan), &entetes, &json!({ "password": "court" }).to_string()).await;
        let r_role = rgsc_envoyer(addr, "POST", &format!("/api/users/{ligne}"), Some(&dan), &entetes, &json!({ "password": "court", "role": "superviseur" }).to_string()).await;
        let refus = json!({ "error": CAUSE_MOT_DE_PASSE_NON_POSE_IDENTITE_DE_PLATEFORME });
        assert_eq!(
            ((r_absent.statut, &r_absent.corps), (r_role.statut, &r_role.corps)),
            ((409, &refus), (409, &refus)),
            "le refus de la ligne de tenant précède la lecture et la validation : {} | {}",
            r_absent.texte,
            r_role.texte
        );
        let (h, role): (String, String) = st.db.lock().query_row("SELECT hash, role FROM user WHERE id=?1", params![ligne], |r| Ok((r.get(0)?, r.get(1)?))).expect("ligne lue");
        assert!(verify_pw(RGSC_MOT_DE_PASSE_DE_LA_LIGNE, &h), "le haché de la ligne est inchangé");
        assert_eq!(role, "editor", "le rôle de la ligne est inchangé");
    }
}
