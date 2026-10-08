// =====================================================================================
// `P10.20-b` (hors handlers/ : authentification Basic) — UNE LECTURE RATÉE DE LA TABLE DES COMPTES N'EST PAS UN
// NOM ABSENT.
//
// LE DÉFAUT, MESURÉ SUR aa78ddd (ces témoins joués sur la forme d'avant). `lookup_basic_ident` lisait la ligne du
// compte par `query_row(..).ok()` : une lecture ratée rendait `None`, comme « aucune ligne ». `authenticate`
// traitait ce `None` comme une absence et retombait sur l'admin de l'assistant ou le compte de configuration :
// pendant que la table ne se lisait pas, l'ANCIEN secret de configuration d'un compte dont le mot de passe a changé
// en table était accepté pour le même nom, avec le rôle admin. Même trou dans la résolution d'une session
// (`compte_live`, rôle servi par `live_role_for`) : `NonLu` final, puis repli `admin`. Même forme en mode 1 sur
// `platform_user`.
//
// LA VOIE D'ÉCHEC : la table des comptes RENOMMÉE au moment de l'appel (« no such table »), puis remise.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement corrompue ou verrouillée (le chemin refusé est le même,
// toute erreur autre que « aucune ligne ») ; la résolution SSO par en-têtes (non traversée ici) ; le refus de
// l'époque du compte, tenu ailleurs (`P10.23-l`).
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées par `VERIF_MUT`, puis retirées du source) :
//  * « lecture_vaut_absent » (`lookup_basic_ident_lu` rend `Absent` sur une erreur de lecture, la forme d'avant) : (a), (d) ;
//  * « auth_nonlu_repli » (`authenticate` traite `NonLu` comme `Absent`) : (a), (d) ;
//  * « session_nonlu_repli » (`compte_live`, mode 0, `NonLu` final retombe sur le repli) : (c) ;
//  * « sso_nonlu » (mode 1 : la ligne `platform_user` à hash NULL, compte SSO, rendue `NonLu`) : (e) ;
//  * « session_absent_refuse » (mode 1 : `compte_live` refuse l'absence établie au lieu du repli) : (d), (e).
// =====================================================================================
mod authentification_basic_lecture_de_compte_non_lue {
    use super::*;

    const ABNL_ANCIEN_SECRET: &str = "ancien-secret-de-configuration";
    const ABNL_NOUVEAU_SECRET: &str = "nouveau-secret-pose-en-table-42";
    const ABNL_EXPLOITANT: &str = "guat";

    fn abnl_basic(nom: &str, secret: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{secret}")))
    }

    /// Les deux replis que la lecture ratée ouvrait : le compte de configuration et l'admin de l'assistant, tous deux
    /// au nom de l'exploitant et à l'ANCIEN secret.
    #[derive(Clone, Copy, Debug)]
    enum AbnlRepli {
        Configuration,
        Assistant,
    }

    fn abnl_poser_le_repli(st: &mut AppState, repli: AbnlRepli, nom: &str) {
        let ancien = hash_pw(ABNL_ANCIEN_SECRET).expect("fixture : hash");
        match repli {
            AbnlRepli::Configuration => {
                st.user = Arc::new(nom.to_string());
                st.pass_hash = Arc::new(ancien);
            }
            AbnlRepli::Assistant => *st.admin.lock() = Some((nom.to_string(), ancien)),
        }
    }

    /// Mode 0 : `alice`, `bob`, `adm` (fixture), plus l'exploitant en table au NOUVEAU secret, rôle `editor`.
    fn abnl_etat_mode_zero(tag: &str, repli: AbnlRepli, exploitant_en_table: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (mut st, p) = sp_state(&format!("abnl-{tag}"));
        if exploitant_en_table {
            st.db
                .lock()
                .execute(
                    "INSERT INTO user(name,hash,role) VALUES(?1,?2,'editor')",
                    params![ABNL_EXPLOITANT, hash_pw(ABNL_NOUVEAU_SECRET).expect("fixture : hash")],
                )
                .expect("fixture : compte de l'exploitant en table");
        }
        abnl_poser_le_repli(&mut st, repli, ABNL_EXPLOITANT);
        (st, p)
    }

    fn abnl_executer(conn: &rusqlite::Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn abnl_rendre_user_illisible(st: &AppState) {
        abnl_executer(&st.db.lock(), "ALTER TABLE user RENAME TO abnl_user_mise_a_l_ecart;");
    }

    fn abnl_remettre_user(st: &AppState) {
        abnl_executer(&st.db.lock(), "ALTER TABLE abnl_user_mise_a_l_ecart RENAME TO user;");
    }

    fn abnl_en_cache(st: &AppState, authz: &str) -> bool {
        st.auth_cache.lock().contains_key(authz)
    }

    /// (a) LE TÉMOIN QUI ROUGIT SUR LA FORME D'AVANT : compte présent en table à un autre secret, ancien secret au
    /// repli ; table illisible -> refus (et rien en cache), pour les deux replis. Lecture saine -> comportement d'avant.
    #[test]
    fn abnl_compte_en_table_lecture_ratee_refuse_l_ancien_secret_du_repli() {
        for repli in [AbnlRepli::Configuration, AbnlRepli::Assistant] {
            let (st, _p) = abnl_etat_mode_zero(&format!("a-{repli:?}"), repli, true);
            let ancien = abnl_basic(ABNL_EXPLOITANT, ABNL_ANCIEN_SECRET);
            let nouveau = abnl_basic(ABNL_EXPLOITANT, ABNL_NOUVEAU_SECRET);

            // lecture saine : la table fait autorité (comportement d'avant).
            assert_eq!(authenticate(&st, &ancien), None, "{repli:?} : lecture saine, l'ancien secret est refusé");
            assert_eq!(
                authenticate(&st, &nouveau),
                Some((ABNL_EXPLOITANT.to_string(), "editor".to_string())),
                "{repli:?} : lecture saine, le secret de la table ouvre avec le rôle de la table"
            );
            st.auth_cache.lock().clear();

            abnl_rendre_user_illisible(&st);
            assert_eq!(
                authenticate(&st, &ancien),
                None,
                "{repli:?} : table des comptes NON LUE -> l'ancien secret du repli ne doit pas ouvrir (admin)"
            );
            assert!(!abnl_en_cache(&st, &ancien), "{repli:?} : un refus sur lecture ratée n'entre pas en cache");
            assert_eq!(authenticate(&st, &nouveau), None, "{repli:?} : rien ne se conclut sur une lecture ratée");
            assert!(st.auth_cache.lock().is_empty(), "{repli:?} : cache vide après les lectures ratées");

            abnl_remettre_user(&st);
            assert_eq!(authenticate(&st, &ancien), None, "{repli:?} : table remise, ancien secret toujours refusé");
            assert_eq!(
                authenticate(&st, &nouveau),
                Some((ABNL_EXPLOITANT.to_string(), "editor".to_string())),
                "{repli:?} : table remise, le compte s'authentifie de nouveau"
            );
        }
    }

    /// (b) LE REPLI DE L'ABSENCE ÉTABLIE EST INCHANGÉ : compte absent de la table, repli posé -> admin (bootstrap,
    /// mode installation, exploitant). Un compte de la table s'authentifie toujours ; un mauvais secret est refusé.
    #[test]
    fn abnl_compte_absent_de_la_table_le_repli_reste_ouvert() {
        for repli in [AbnlRepli::Configuration, AbnlRepli::Assistant] {
            let (st, _p) = abnl_etat_mode_zero(&format!("b-{repli:?}"), repli, false);
            assert_eq!(
                authenticate(&st, &abnl_basic(ABNL_EXPLOITANT, ABNL_ANCIEN_SECRET)),
                Some((ABNL_EXPLOITANT.to_string(), "admin".to_string())),
                "{repli:?} : absence établie -> le repli ouvre, rôle admin"
            );
            assert_eq!(authenticate(&st, &abnl_basic(ABNL_EXPLOITANT, "faux")), None, "{repli:?} : mauvais secret refusé");
            assert_eq!(
                authenticate(&st, &abnl_basic("alice", "motdepasse12345")),
                Some(("alice".to_string(), "editor".to_string())),
                "{repli:?} : un compte de la table s'authentifie"
            );
            assert_eq!(
                live_role_for(&st, ABNL_EXPLOITANT).as_deref(),
                Some("admin"),
                "{repli:?} : la session de l'exploitant absent de la table résout admin (repli inchangé)"
            );
            assert_eq!(live_role_for(&st, "inconnu"), None, "{repli:?} : un nom ni en table ni au repli ne résout rien");
        }
    }

    /// (c) LA SESSION : read pool ET écrivain ne lisent pas la table -> le repli admin n'est pas servi.
    #[test]
    fn abnl_session_compte_non_lu_ne_retombe_pas_sur_le_repli_admin() {
        for repli in [AbnlRepli::Configuration, AbnlRepli::Assistant] {
            let (st, _p) = abnl_etat_mode_zero(&format!("c-{repli:?}"), repli, true);
            assert_eq!(live_role_for(&st, ABNL_EXPLOITANT).as_deref(), Some("editor"), "{repli:?} : lecture saine, rôle de la table");
            abnl_rendre_user_illisible(&st);
            assert_eq!(
                live_role_for(&st, ABNL_EXPLOITANT),
                None,
                "{repli:?} : compte NON LU (pool et écrivain) -> aucune identité, jamais le repli admin"
            );
            abnl_remettre_user(&st);
            assert_eq!(live_role_for(&st, ABNL_EXPLOITANT).as_deref(), Some("editor"), "{repli:?} : table remise, rôle de la table");
        }
    }

    /// (d) MODE 1 : même forme sur `platform_user` du plan de contrôle, pour le Basic et pour la session.
    #[test]
    fn abnl_mode_un_platform_user_non_lu_refuse() {
        let (cp, _tmp) = mk_test_control();
        let id = ensure_platform_user(&cp, ABNL_EXPLOITANT).expect("fixture : utilisateur créé");
        cp.conn
            .lock()
            .execute("UPDATE platform_user SET hash=?1 WHERE id=?2", params![hash_pw(ABNL_NOUVEAU_SECRET).expect("hash"), id])
            .expect("fixture : secret posé au plan de contrôle");
        let mut st = tenant_test_state("admins", "editors", "supers", Some(cp));
        abnl_poser_le_repli(&mut st, AbnlRepli::Configuration, ABNL_EXPLOITANT);
        let plan = st.tenants.control.as_ref().expect("mode 1").conn.clone();
        let ancien = abnl_basic(ABNL_EXPLOITANT, ABNL_ANCIEN_SECRET);
        let nouveau = abnl_basic(ABNL_EXPLOITANT, ABNL_NOUVEAU_SECRET);

        assert_eq!(authenticate(&st, &ancien), None, "lecture saine : ancien secret refusé");
        assert_eq!(authenticate(&st, &nouveau), Some((ABNL_EXPLOITANT.to_string(), "viewer".to_string())), "lecture saine");
        assert_eq!(live_role_for(&st, ABNL_EXPLOITANT).as_deref(), Some("viewer"), "lecture saine : rôle plancher");
        st.auth_cache.lock().clear();

        abnl_executer(&plan.lock(), "ALTER TABLE platform_user RENAME TO abnl_platform_user_mise_a_l_ecart;");
        assert_eq!(authenticate(&st, &ancien), None, "platform_user NON LU -> l'ancien secret du repli ne doit pas ouvrir");
        assert!(st.auth_cache.lock().is_empty(), "rien en cache");
        assert_eq!(live_role_for(&st, ABNL_EXPLOITANT), None, "platform_user NON LU -> aucune identité de session");
        abnl_executer(&plan.lock(), "ALTER TABLE abnl_platform_user_mise_a_l_ecart RENAME TO platform_user;");

        assert_eq!(authenticate(&st, &nouveau), Some((ABNL_EXPLOITANT.to_string(), "viewer".to_string())), "table remise");
        // absence établie en mode 1 : un nom hors du plan de contrôle retombe sur le repli, inchangé.
        let mut st_absent = st.clone();
        abnl_poser_le_repli(&mut st_absent, AbnlRepli::Configuration, "exploitant-hors-plan");
        assert_eq!(
            authenticate(&st_absent, &abnl_basic("exploitant-hors-plan", ABNL_ANCIEN_SECRET)),
            Some(("exploitant-hors-plan".to_string(), "admin".to_string())),
            "mode 1 : absence établie -> repli inchangé"
        );
        assert_eq!(
            live_role_for(&st_absent, "exploitant-hors-plan").as_deref(),
            Some("admin"),
            "mode 1 : absence établie (aucune ligne) -> la session de l'exploitant résout admin, repli inchangé"
        );
    }

    /// (e) MODE 1, COMPTE SSO DU MÊME NOM QUE L'EXPLOITANT : `platform_user` porte une ligne `guat` SANS secret (hash
    /// NULL, provisionnée par SSO). C'est une absence ÉTABLIE pour le Basic, pas une lecture ratée : le compte de
    /// configuration (ou l'admin de l'assistant) au même nom s'authentifie toujours, et sa session résout admin.
    #[test]
    fn abnl_mode_un_compte_sso_sans_secret_vaut_absence_etablie() {
        for repli in [AbnlRepli::Configuration, AbnlRepli::Assistant] {
            let (cp, _tmp) = mk_test_control();
            ensure_platform_user(&cp, ABNL_EXPLOITANT).expect("fixture : compte SSO créé (hash NULL)");
            let hash: Option<String> = cp
                .conn
                .lock()
                .query_row("SELECT hash FROM platform_user WHERE name=?1", params![ABNL_EXPLOITANT], |r| r.get(0))
                .expect("fixture : ligne SSO lue");
            assert_eq!(hash, None, "fixture : le compte SSO n'a pas de secret");
            let mut st = tenant_test_state("admins", "editors", "supers", Some(cp));
            abnl_poser_le_repli(&mut st, repli, ABNL_EXPLOITANT);
            assert_eq!(
                authenticate(&st, &abnl_basic(ABNL_EXPLOITANT, ABNL_ANCIEN_SECRET)),
                Some((ABNL_EXPLOITANT.to_string(), "admin".to_string())),
                "{repli:?} : ligne SSO sans secret -> absence établie, le repli de l'exploitant ouvre"
            );
            assert_eq!(
                authenticate(&st, &abnl_basic(ABNL_EXPLOITANT, "faux")),
                None,
                "{repli:?} : mauvais secret refusé"
            );
            assert_eq!(
                live_role_for(&st, ABNL_EXPLOITANT).as_deref(),
                Some("admin"),
                "{repli:?} : ligne SSO sans secret -> la session de l'exploitant résout admin"
            );
        }
    }
}
