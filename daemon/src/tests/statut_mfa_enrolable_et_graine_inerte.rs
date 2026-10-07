// =====================================================================================
// `P10.23-n` — LE STATUT DE DOUBLE AUTHENTIFICATION DIT SI LE COMPTE PEUT ENRÔLER, ET QU'UNE GRAINE EST INERTE.
//
// LE DÉFAUT, RE-MESURÉ LE 2026-10-07 SUR LA FORME D'AVANT : `mfa_status` ne rendait que `{enrolled, enabled}`. Un
// compte fédéré (hachage `IDP_HASH_SENTINEL`) porteur d'une graine activée (posée avant `P10.23-b`) recevait
// `{enrolled:true, enabled:true}`, que la console peint « Double authentification ACTIVE » — alors que la seule
// lecture de `user_mfa` qui décide d'une connexion (`login_post`) ne sert que les comptes à mot de passe local :
// cette graine n'est JAMAIS demandée. Et rien ne disait que ce compte ne peut pas enrôler (le refus nommé de
// `mfa_enroll` n'apparaissait qu'au clic).
//
// CE QUE CES TÉMOINS TIENNENT : les champs ADDITIFS `enrolable`, `cause_non_enrolable`, `graine_inerte`, jugés dans
// les DEUX sens (compte local avec graine : enrôlable, graine non inerte ; compte fédéré avec graine : non
// enrôlable, cause nommée, graine inerte), `enrolled`/`enabled` inchangés, la graine NON effacée (décision d'Hugo du
// 2026-09-29), et une lecture ratée du compte qui n'affirme ni l'un ni l'autre.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint (`web/idp.js`), tenu ailleurs par le témoin de harnais (96d-bis)
// de `.github/scripts/web_esm_harnais.mjs` ; les restes `P10.30-d` du même fichier (`mfa_verify` `.ok()` -> 400,
// `login_mfa_post` `.ok()` -> 401), non repris.
//
// MUTATIONS (jouées le 2026-10-07, retirées du code livré) : forcer `graine_inerte` à `false` dans `mfa_status` (le
// statut d'avant : la graine du compte fédéré n'est pas dite inerte) fait rougir (2) et (4) ; forcer `enrolable` à
// `true` fait rougir (2), (3) et (4). (1) reste vert sous les deux : c'est le contrôle négatif.
// =====================================================================================
mod statut_mfa_enrolable_et_graine_inerte {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    async fn smgi_statut(st: &AppState, user: &str) -> (u16, Value) {
        let r = mfa_status(State(st.clone()), Extension(sp_au(user, "editor"))).await;
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn smgi_poser_graine(st: &AppState, user: &str, enabled: i64) {
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,'GRAINE',?2,'[]',-1,0,0)",
                params![user, enabled],
            )
            .expect("fixture : graine posée");
    }

    fn smgi_graines(st: &AppState, user: &str) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM user_mfa WHERE user=?1", params![user], |r| r.get(0)).expect("fixture : lu")
    }

    fn smgi_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("smgi-{tag}"));
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('fed',?1,'editor')", params![IDP_HASH_SENTINEL])
            .expect("fixture : compte fédéré");
        (st, p)
    }

    /// (1) CONTRÔLE NÉGATIF — un compte LOCAL (`adm`, mot de passe réel) : graine activée -> enrôlable, graine NON
    /// inerte ; graine en attente (`bob`) -> enrôlable, non inerte ; sans graine (`alice`) -> enrôlable.
    #[tokio::test]
    async fn smgi_un_compte_local_avec_graine_est_enrolable_et_sa_graine_sert() {
        let (st, _p) = smgi_etat("local");
        smgi_poser_graine(&st, "adm", 1);
        smgi_poser_graine(&st, "bob", 0);
        for (user, enrolled, enabled) in [("adm", true, true), ("bob", true, false), ("alice", false, false)] {
            let (statut, c) = smgi_statut(&st, user).await;
            assert_eq!(statut, 200, "{user} : {c}");
            assert_eq!(c["enrolled"], json!(enrolled), "{user} : `enrolled` inchangé : {c}");
            assert_eq!(c["enabled"], json!(enabled), "{user} : `enabled` inchangé : {c}");
            assert_eq!(c["enrolable"], json!(true), "{user} : compte local, enrôlable : {c}");
            assert_eq!(c["cause_non_enrolable"], Value::Null, "{user} : aucune cause de refus : {c}");
            assert_eq!(c["graine_inerte"], json!(false), "{user} : la graine d'un compte local est demandée : {c}");
        }
    }

    /// (2) LE DÉFAUT — un compte FÉDÉRÉ porteur d'une graine ACTIVÉE : `enabled` reste vrai (la ligne telle quelle),
    /// mais le statut dit « non enrôlable » avec la cause de `mfa_enroll` et « graine inerte » ; la graine n'est PAS
    /// effacée. Même verdict pour une identité SSO d'en-têtes sans ligne locale (`hdr`).
    #[tokio::test]
    async fn smgi_un_compte_federe_avec_graine_la_voit_dite_inerte_et_non_effacee() {
        let (st, _p) = smgi_etat("federe");
        for user in ["fed", "hdr"] {
            smgi_poser_graine(&st, user, 1);
            let (statut, c) = smgi_statut(&st, user).await;
            assert_eq!(statut, 200, "{user} : {c}");
            assert_eq!(c["enrolled"], json!(true), "{user} : {c}");
            assert_eq!(c["enabled"], json!(true), "{user} : `enabled` n'est pas réécrit : {c}");
            assert_eq!(c["enrolable"], json!(false), "{user} : pas de mot de passe local, pas d'enrôlement : {c}");
            assert_eq!(
                c["cause_non_enrolable"],
                json!(crate::handlers::idp::CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL),
                "{user} : la cause est celle du refus d'enrôlement, mot pour mot : {c}"
            );
            assert_eq!(c["graine_inerte"], json!(true), "{user} : la graine n'est jamais demandée, elle est dite INERTE : {c}");
            assert_eq!(smgi_graines(&st, user), 1, "{user} : rien n'est effacé");
        }
    }

    /// (3) Un compte fédéré SANS graine : non enrôlable, cause nommée, et AUCUNE graine inerte affirmée.
    #[tokio::test]
    async fn smgi_un_compte_federe_sans_graine_n_est_pas_enrolable_et_rien_n_est_inerte() {
        let (st, _p) = smgi_etat("federe-vierge");
        let (statut, c) = smgi_statut(&st, "fed").await;
        assert_eq!(statut, 200, "{c}");
        assert_eq!(c["enrolled"], json!(false), "{c}");
        assert_eq!(c["enrolable"], json!(false), "{c}");
        assert_eq!(c["cause_non_enrolable"], json!(crate::handlers::idp::CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL), "{c}");
        assert_eq!(c["graine_inerte"], json!(false), "aucune graine, rien d'inerte : {c}");
    }

    /// (4) La lecture du COMPTE refusée (autorisateur) : `enrolled`/`enabled` servis (la ligne `user_mfa` a été lue),
    /// `enrolable` et `graine_inerte` à `null`, la cause nommée — ni « enrôlable » ni « inerte » ne sont affirmés.
    /// Passe aussi pour la preuve que le verrou de `user_mfa` est rendu avant le prédicat (sinon : interblocage).
    #[tokio::test]
    async fn smgi_une_lecture_ratee_du_compte_n_affirme_ni_enrolable_ni_inerte() {
        let (st, _p) = smgi_etat("compte-non-lu");
        smgi_poser_graine(&st, "fed", 1);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user" && column_name == "hash" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, c) = smgi_statut(&st, "fed").await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 200, "{c}");
        assert_eq!(c["enabled"], json!(true), "{c}");
        assert_eq!(c["enrolable"], Value::Null, "non lu : rien d'affirmé : {c}");
        assert_eq!(c["graine_inerte"], Value::Null, "non lu : rien d'affirmé : {c}");
        assert_eq!(c["cause_non_enrolable"], json!(crate::handlers::idp::CAUSE_COMPTE_NON_LU_AU_STATUT), "{c}");
    }
}
