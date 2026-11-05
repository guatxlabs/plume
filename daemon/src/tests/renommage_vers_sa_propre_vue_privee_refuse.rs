// =====================================================================================
// `P11.25-f` (correction de la troisième passe) — RENOMMER UNE VUE VERS LE NOM D'UNE AUTRE VUE PRIVÉE DU MÊME COMPTE
// EST UN DOUBLON.
//
// CE QUE CE TÉMOIN TIENT : la recherche d'homonyme de `view_update` compte les vues PRIVÉES DE L'APPELANT
// (`owner=?3` du périmètre de visibilité), pas seulement la vue commune et le cas administrateur : alice renomme sa
// vue privée P2 en « P1 », P1 étant à elle et privée -> 409 avec l'identifiant de SA P1, même quand une vue privée
// de bob du même nom porte un identifiant plus petit (bob n'est pas dans son périmètre) ; rien du corps n'est
// appliqué (ni nom ni partage). Contrôle positif : la même vue renommée vers un nom libre passe (204).
//
// CE QU'IL NE TIENT PAS : la création (`view_create`, tenue par `bt2_doublon_de_vue_409_dans_le_perimetre_du_createur` des témoins
// `vues_rattachements_multiples_et_toutes_les_vues.rs`) ; la vue commune, l'administrateur et la vue privée
// d'autrui au renommage (tenus par `bt2c_renommer_vers_une_vue_existante_est_refuse`).
//
// MUTATION (`VERIF_MUT=<nom>`, posée sous `cfg!(test)` le temps de la vérification puis retirée) :
// `BV2C_RENOMMAGE_SANS_PROPRIO` (la clause `owner=?3` neutralisée dans la recherche d'homonyme du renommage).
// =====================================================================================
mod renommage_vers_sa_propre_vue_privee_refuse {
    use super::*;

    const BV2C_RENOMMEE_VERS_UNE_EXISTANTE: &str = "VUE DÉJÀ EXISTANTE : une autre vue de ce nom existe déjà parmi celles que vous voyez — rien n'est renommé, rien du corps n'est appliqué. Complétez-la (POST /api/views/{id}/dashboards) ou choisissez un autre nom.";

    fn bv2c_vue(st: &AppState, nom: &str, owner: &str, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn bv2c_vue_lue(st: &AppState, vue: i64) -> (String, String) {
        st.db.lock().query_row("SELECT name,visibility FROM view WHERE id=?1", params![vue], |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
    }

    async fn bv2c_renommer(st: &AppState, au: &AuthUser, vue: i64, corps: Value) -> (u16, Value) {
        pb_json(view_update(State(st.clone()), Extension(au.clone()), Path(vue), Json(corps)).await).await
    }

    /// CE QU'IL TIENT : voir l'en-tête. MUTATION : `BV2C_RENOMMAGE_SANS_PROPRIO`.
    #[tokio::test]
    async fn bv2c_renommer_vers_sa_propre_vue_privee_est_refuse() {
        let (st, _p) = sp_state("bv2c-renommage-proprio");
        st.db.lock().execute_batch("DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;").expect("fixture : base vide");
        let alice = sp_au("alice", "editor");
        // La vue privée de bob du même nom vient AVANT (identifiant plus petit) : hors du périmètre d'alice, elle ne doit
        // être ni comptée ni nommée.
        let p1_bob = bv2c_vue(&st, "P1", "bob", "private");
        let p1 = bv2c_vue(&st, "P1", "alice", "private");
        let p2 = bv2c_vue(&st, "P2", "alice", "private");
        assert!(p1_bob < p1, "fixture : la vue de bob porte l'identifiant le plus petit");
        for corps in [json!({ "name": "P1" }), json!({ "name": "P1", "visibility": "shared" })] {
            assert_eq!(
                bv2c_renommer(&st, &alice, p2, corps.clone()).await,
                (409, json!({ "error": BV2C_RENOMMEE_VERS_UNE_EXISTANTE, "view_id": p1 })),
                "alice renomme P2 vers le nom de SA vue privée P1 ({corps})"
            );
            assert_eq!(bv2c_vue_lue(&st, p2), ("P2".to_string(), "private".to_string()), "rien du corps n'est appliqué ({corps})");
        }
        let (code, corps) = bv2c_renommer(&st, &alice, p2, json!({ "name": "P3" })).await;
        assert_eq!(code, 204, "contrôle positif : un nom libre passe : {corps}");
        assert_eq!(bv2c_vue_lue(&st, p2).0, "P3");
    }
}
