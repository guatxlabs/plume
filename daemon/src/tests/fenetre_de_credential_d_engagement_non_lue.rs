// =====================================================================================
// `P10.20-b` (rang quatre : `engagement_cred_within_window`) — UNE FENÊTRE D'ENGAGEMENT NON LUE N'EST PAS UNE
// FENÊTRE CLOSE, ET N'OUVRE AUCUN REPLI ADMINISTRATEUR.
//
// LE DÉFAUT, LU SUR 2e4fe6eb (ces témoins joués sur la forme d'avant par les mutations ci-dessous, qui la
// restituent). `engagement_cred_within_window` finissait par `.map(..).unwrap_or(false)` : une erreur du moteur
// valait « hors fenêtre ». Ses deux appelants en faisaient un compte ABSENT (`lookup_basic_ident_lu` pour le Basic,
// `compte_via_l_ecrivain` pour la session), et l'absence établie est précisément ce qui ouvre le repli sur l'admin de
// l'assistant ou le compte de configuration. Le client voyait le même 401 sur un compte ordinaire ; ce qui changeait
// était le repli, ouvert sur une lecture ratée, et un journal qui disait « absent ».
//
// GRAVITÉ, DITE ET NON GONFLÉE : le repli n'ouvre que si le nom `eng-cred-*` est AUSSI celui de l'admin de
// l'assistant ou de configuration. Ces témoins fabriquent cette coïncidence pour rendre le repli observable ; ils ne
// prouvent pas qu'elle survient en production. C'est un correctif de cause et de défense en profondeur.
//
// LA VOIE D'ÉCHEC : `window_start` posé en TEXTE non numérique (affinité INTEGER : la valeur reste du texte), donc
// `get::<i64>` échoue sur une ligne qui EXISTE — une lecture ratée, pas une absence.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une table `engagement` illisible ou verrouillée (même branche `Err`, non
// jouée ici) ; le mode 1 (les crédences d'engagement n'y passent pas par cette fenêtre : `platform_user`) ; le repli
// sur l'absence ÉTABLIE (hors fenêtre) reste ouvert pour un nom `eng-cred-*` qui serait celui de l'admin — ce lot ne
// le juge pas, il est constaté en (d) comme comportement d'avant inchangé.
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par variable d environnement de mutation sous `cfg!(test)`, puis retirées du source) :
//  * « L4_ERR_VAUT_FAUX » (`engagement_cred_within_window` rend `Ok(false)` sur une erreur, la forme d'avant) :
//    (a), (b), (c) ;
//  * « L4_BASIC_NONLU_VAUT_ABSENT » (`lookup_basic_ident_lu` traduit l'erreur de fenêtre en `Absent`) : (b) ;
//  * « L4_SESSION_NONLU_VAUT_ABSENT » (`compte_via_l_ecrivain` traduit l'erreur de fenêtre en `Absent`) : (c).
// =====================================================================================
mod fenetre_de_credential_d_engagement_non_lue {
    use super::*;

    const FCNL_SECRET_DU_CREDENTIAL: &str = "secret-du-credential-de-pentest-42";
    const FCNL_SECRET_DU_REPLI: &str = "secret-du-repli-administrateur-42";
    const FCNL_ENGAGEMENT: &str = "fcnl-engagement";

    fn fcnl_nom() -> String {
        format!("{ENG_CRED_PREFIX}0a1b2c3d4e5f")
    }

    fn fcnl_basic(nom: &str, secret: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{secret}")))
    }

    #[derive(Clone, Copy, Debug)]
    enum FcnlRepli {
        Configuration,
        Assistant,
    }

    fn fcnl_executer(conn: &rusqlite::Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Mode 0 : le credential `eng-cred-*` en table (rôle `viewer`), lié par UN grant `issued` à un engagement dont la
    /// fenêtre est OUVERTE maintenant ; le repli (configuration ou assistant) porte LE MÊME NOM, à un autre secret.
    fn fcnl_etat(tag: &str, repli: Option<FcnlRepli>) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(&format!("fcnl-{tag}"));
        let nom = fcnl_nom();
        let t = now();
        {
            let c = st.db.lock();
            c.execute(
                "INSERT INTO user(name,hash,role) VALUES(?1,?2,'viewer')",
                params![nom, hash_pw(FCNL_SECRET_DU_CREDENTIAL).expect("fixture : hash")],
            )
            .expect("fixture : compte du credential");
            fcnl_poser_un_engagement(&c, FCNL_ENGAGEMENT, t - 3600, t + 3600);
        }
        if let Some(repli) = repli {
            let h = hash_pw(FCNL_SECRET_DU_REPLI).expect("fixture : hash");
            match repli {
                FcnlRepli::Configuration => {
                    st.user = Arc::new(nom.clone());
                    st.pass_hash = Arc::new(h);
                }
                FcnlRepli::Assistant => *st.admin.lock() = Some((nom.clone(), h)),
            }
        }
        (st, p)
    }

    fn fcnl_poser_un_engagement(c: &rusqlite::Connection, id: &str, debut: i64, fin: i64) {
        c.execute(
            "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status) \
             VALUES(?1,?1,'greybox','[]',?2,?3,'chef','essai','active')",
            params![id, debut, fin],
        )
        .expect("fixture : engagement");
        c.execute(
            "INSERT INTO engagement_grant(engagement_id,kind,ref,issued_ts,status) VALUES(?1,'scoped_cred',?2,0,'issued')",
            params![id, fcnl_nom()],
        )
        .expect("fixture : grant");
    }

    fn fcnl_rendre_la_fenetre_illisible(st: &AppState) {
        fcnl_executer(&st.db.lock(), &format!("UPDATE engagement SET window_start='pas-un-entier' WHERE id='{FCNL_ENGAGEMENT}';"));
        let genre: String = st
            .db
            .lock()
            .query_row("SELECT typeof(window_start) FROM engagement WHERE id=?1", params![FCNL_ENGAGEMENT], |r| r.get(0))
            .expect("fixture : genre relu");
        assert_eq!(genre, "text", "fixture : la fenêtre doit être du TEXTE (ligne présente, lecture en entier ratée)");
    }

    fn fcnl_remettre_la_fenetre(st: &AppState) {
        let debut = now() - 3600;
        fcnl_executer(&st.db.lock(), &format!("UPDATE engagement SET window_start={debut} WHERE id='{FCNL_ENGAGEMENT}';"));
    }

    fn fcnl_lecture(st: &AppState) -> &'static str {
        match crate::state::lookup_basic_ident_lu(st, &fcnl_nom()) {
            crate::state::LectureDuCompteBasic::Trouve { .. } => "trouve",
            crate::state::LectureDuCompteBasic::Absent => "absent",
            crate::state::LectureDuCompteBasic::NonLu(_) => "non_lu",
        }
    }

    /// (a) LA FONCTION ELLE-MÊME : fenêtre lue et ouverte -> `Ok(true)` (contrôle positif) ; fenêtre illisible ->
    /// `Err`, jamais `Ok(false)` ; fenêtre remise -> `Ok(true)` de nouveau.
    #[test]
    fn fcnl_fenetre_illisible_rend_une_erreur_et_non_hors_fenetre() {
        let (st, _p) = fcnl_etat("a", None);
        let nom = fcnl_nom();
        assert!(
            matches!(engagement_cred_within_window(&st.db.lock(), &nom, now()), Ok(true)),
            "contrôle positif : liaison unique, fenêtre ouverte -> Ok(true)"
        );
        fcnl_rendre_la_fenetre_illisible(&st);
        let lu = engagement_cred_within_window(&st.db.lock(), &nom, now());
        assert!(lu.is_err(), "fenêtre NON LUE -> Err (rien de lu), jamais Ok(false) « hors fenêtre » ; rendu : {lu:?}");
        fcnl_remettre_la_fenetre(&st);
        assert!(
            matches!(engagement_cred_within_window(&st.db.lock(), &nom, now()), Ok(true)),
            "fenêtre remise -> Ok(true) : le refus portait sur la lecture, pas sur le credential"
        );
    }

    /// (b) LE BASIC : fenêtre non lue -> `NonLu` (cause nommée, sans le nom fourni), et l'ancien secret du repli au
    /// même nom n'ouvre RIEN — sur la forme d'avant il ouvrait avec le rôle admin. Le secret du credential non plus.
    #[test]
    fn fcnl_basic_fenetre_non_lue_refuse_sans_repli_admin() {
        for repli in [FcnlRepli::Configuration, FcnlRepli::Assistant] {
            let (st, _p) = fcnl_etat(&format!("b-{repli:?}"), Some(repli));
            let nom = fcnl_nom();
            let par_le_repli = fcnl_basic(&nom, FCNL_SECRET_DU_REPLI);
            let par_le_credential = fcnl_basic(&nom, FCNL_SECRET_DU_CREDENTIAL);

            assert_eq!(fcnl_lecture(&st), "trouve", "{repli:?} : contrôle positif, fenêtre ouverte -> compte trouvé");
            assert_eq!(
                authenticate(&st, &par_le_credential),
                Some((nom.clone(), "viewer".to_string())),
                "{repli:?} : fenêtre ouverte, le credential s'authentifie avec le rôle de la table"
            );
            assert_eq!(authenticate(&st, &par_le_repli), None, "{repli:?} : compte trouvé, la table fait autorité");

            fcnl_rendre_la_fenetre_illisible(&st);
            match crate::state::lookup_basic_ident_lu(&st, &nom) {
                crate::state::LectureDuCompteBasic::NonLu(cause) => {
                    assert!(cause.contains("fenêtre d'engagement"), "{repli:?} : la cause nomme la fenêtre : {cause}");
                    assert!(!cause.contains(&nom), "{repli:?} : la cause ne recopie pas le nom fourni : {cause}");
                }
                crate::state::LectureDuCompteBasic::Absent => {
                    panic!("{repli:?} : fenêtre NON LUE rendue « absent » — c'est l'absence qui ouvre le repli admin")
                }
                crate::state::LectureDuCompteBasic::Trouve { .. } => panic!("{repli:?} : fenêtre NON LUE rendue « trouvé »"),
            }
            assert_eq!(
                authenticate(&st, &par_le_repli),
                None,
                "{repli:?} : fenêtre NON LUE -> le secret du repli au même nom ne doit PAS ouvrir (rôle admin)"
            );
            assert_eq!(authenticate(&st, &par_le_credential), None, "{repli:?} : rien ne se conclut sur une lecture ratée");
            assert!(st.auth_cache.lock().is_empty(), "{repli:?} : aucun cache sur une lecture ratée");

            fcnl_remettre_la_fenetre(&st);
            assert_eq!(
                authenticate(&st, &par_le_credential),
                Some((nom.clone(), "viewer".to_string())),
                "{repli:?} : fenêtre remise, le credential s'authentifie de nouveau"
            );
        }
    }

    /// (c) LA SESSION (voie d'écrivain des `eng-cred-*`) : fenêtre non lue -> aucune identité, jamais le repli admin.
    #[test]
    fn fcnl_session_fenetre_non_lue_refuse_sans_repli_admin() {
        for repli in [FcnlRepli::Configuration, FcnlRepli::Assistant] {
            let (st, _p) = fcnl_etat(&format!("c-{repli:?}"), Some(repli));
            let nom = fcnl_nom();
            assert_eq!(live_role_for(&st, &nom).as_deref(), Some("viewer"), "{repli:?} : contrôle positif, rôle de la table");
            fcnl_rendre_la_fenetre_illisible(&st);
            assert_eq!(
                live_role_for(&st, &nom),
                None,
                "{repli:?} : fenêtre NON LUE -> aucune identité de session, jamais le repli admin au même nom"
            );
            fcnl_remettre_la_fenetre(&st);
            assert_eq!(live_role_for(&st, &nom).as_deref(), Some("viewer"), "{repli:?} : fenêtre remise, rôle de la table");
        }
    }

    /// (d) CONTRÔLES NÉGATIFS : une fenêtre LUE et close, ou une liaison MULTIPLE (refus d'ambiguïté `P7.19-i`),
    /// restent une absence ÉTABLIE — pas un « non lu ». Sans repli : aucune identité. Avec le repli au même nom : le
    /// comportement d'avant (repli ouvert sur l'absence établie), constaté et non jugé par ce lot.
    #[test]
    fn fcnl_hors_fenetre_et_liaison_multiple_restent_absents() {
        let nom = fcnl_nom();
        // fenêtre close (lue en entier, dépassée).
        let (st, _p) = fcnl_etat("d-close", None);
        fcnl_executer(&st.db.lock(), &format!("UPDATE engagement SET window_end={} WHERE id='{FCNL_ENGAGEMENT}';", now() - 10));
        assert!(matches!(engagement_cred_within_window(&st.db.lock(), &nom, now()), Ok(false)), "fenêtre close -> Ok(false)");
        assert_eq!(fcnl_lecture(&st), "absent", "fenêtre close -> absence établie, pas « non lu »");
        assert_eq!(live_role_for(&st, &nom), None, "fenêtre close, aucun repli -> aucune identité");

        // liaison multiple : deux grants `issued` sur la même ref, l'un et l'autre vers une fenêtre ouverte.
        let (st, _p) = fcnl_etat("d-multiple", None);
        {
            let c = st.db.lock();
            fcnl_poser_un_engagement(&c, "fcnl-second", now() - 100, now() + 100);
        }
        assert!(
            matches!(engagement_cred_within_window(&st.db.lock(), &nom, now()), Ok(false)),
            "liaison multiple -> Ok(false) (refus d'ambiguïté inchangé), pas Err"
        );
        assert_eq!(fcnl_lecture(&st), "absent", "liaison multiple -> absence établie, pas « non lu »");

        // le repli sur l'absence établie, au même nom : comportement d'avant, inchangé (discrimine absent / non lu).
        let (st, _p) = fcnl_etat("d-repli", Some(FcnlRepli::Configuration));
        fcnl_executer(&st.db.lock(), &format!("UPDATE engagement SET window_end={} WHERE id='{FCNL_ENGAGEMENT}';", now() - 10));
        assert_eq!(fcnl_lecture(&st), "absent", "fenêtre close -> absence établie");
        assert_eq!(
            live_role_for(&st, &nom).as_deref(),
            Some("admin"),
            "absence ÉTABLIE -> le repli d'avant joue (c'est la lecture ratée seule qui le ferme)"
        );
    }
}
