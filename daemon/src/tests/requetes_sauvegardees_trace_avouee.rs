// =====================================================================================
// `P10.31-u` (tranche : `handlers/saved_queries.rs`) — LES TROIS TRACES DES REQUÊTES SAUVEGARDÉES AVOUENT UN
// MAILLON MANQUANT.
//
// LE DÉFAUT, MESURÉ SUR 80ad700a AVANT LE CORRECTIF. Trois appels NUS de `ledger_append` jetaient leur maillon :
// création (`saved_query_create`), mise à jour (`saved_query_update`), suppression (`saved_query_delete`). La primitive
// avouait la perte sur la sortie d'erreur ; la réponse servait `{ok:true,id}` / `{ok:true}` sans un mot.
//
// LE CORRECTIF. Le geste a eu lieu : il n'est pas annulé, la réponse reste 200 et gagne `registre_sans_maillon`
// (`CAUSE_GESTE_SANS_TRACE` suivie de la cause du moteur) ; `id` de la création reste dans le corps. Chemin nominal
// octet pour octet (contrôles négatifs ci-dessous).
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)` (précédent :
// `attestations_d_identite_sans_maillon_avouees.rs`). Les écritures pures (`create`/`update`/`delete`) ne touchent
// pas `ledger`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la console (`web/savedqueries.js`) ne lit pas `registre_sans_maillon` ; la
// sortie d'erreur de la primitive n'est pas capturée ici ; les autres appels nus de `ledger_append` du dépôt.
// =====================================================================================
mod requetes_sauvegardees_trace_avouee {
    use super::*;

    async fn rqsta_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    fn rqsta_aveu(v: &Value) -> Option<String> {
        v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).map(str::to_string)
    }

    fn rqsta_registre_hors_d_atteinte(st: &AppState) {
        st.db
            .lock()
            .execute_batch(
                "CREATE TRIGGER rqsta_ledger_refuse BEFORE INSERT ON ledger \
                 BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin P10.31-u requetes)'); END;",
            )
            .expect("fixture : le déclencheur se pose");
    }

    fn rqsta_maillons(st: &AppState, kind: &str) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![kind], |r| r.get(0)).expect("fixture : le registre se lit")
    }

    /// `(lignes, nom)` de la requête `id` d'alice (nom vide si absente).
    fn rqsta_ligne(st: &AppState, id: i64) -> (i64, String) {
        st.db
            .lock()
            .query_row("SELECT COUNT(*), COALESCE(MAX(name),'') FROM saved_query WHERE id=?1 AND owner='alice'", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture : saved_query se lit")
    }

    fn rqsta_semer(st: &AppState) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO saved_query(owner,name,soql) VALUES('alice','rqsta-semee','search *')", []).expect("fixture : requête écrite");
        c.last_insert_rowid()
    }

    async fn rqsta_creer(st: &AppState) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "name": "rqsta-nommee", "soql": "search *" });
        rqsta_reponse(saved_query_create(State(st.clone()), Extension(sp_au("alice", "editor")), Json(corps)).await).await
    }

    async fn rqsta_modifier(st: &AppState, id: i64) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "name": "rqsta-renommee", "soql": "search * | head 1" });
        rqsta_reponse(saved_query_update(State(st.clone()), Extension(sp_au("alice", "editor")), Path(id), Json(corps)).await).await
    }

    async fn rqsta_supprimer(st: &AppState, id: i64) -> (u16, Vec<u8>, Value) {
        rqsta_reponse(saved_query_delete(State(st.clone()), Extension(sp_au("alice", "editor")), Path(id)).await).await
    }

    fn rqsta_aveu_conforme(v: &Value) {
        let aveu = rqsta_aveu(v).unwrap_or_else(|| panic!("le geste sans trace porte `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert!(!aveu.contains("alice") && !aveu.contains("rqsta-"), "l'aveu ne recopie pas le détail du maillon : {aveu}");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, la requête est créée et n'est pas annulée ; 200, `ok`, `id` (celui de
    /// la ligne écrite) ET `registre_sans_maillon`. Aucune ligne `saved_query.create` au registre.
    /// MUTATIONS : `m8_jeter_create`, `m8_cle_perdue`, `m8_id_absent`.
    #[tokio::test]
    async fn rqsta_creation_sans_maillon_reste_creee_et_l_avoue() {
        let (st, _tmp) = sp_state("rqsta-creation-panne");
        rqsta_registre_hors_d_atteinte(&st);
        let (statut, _, v) = rqsta_creer(&st).await;
        assert_eq!(statut, 200, "le geste a eu lieu, il n'est pas refusé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or_else(|| panic!("`id` reste servi sous l'aveu : {v}"));
        rqsta_aveu_conforme(&v);
        assert_eq!(rqsta_ligne(&st, id), (1, "rqsta-nommee".to_string()), "la requête est écrite et n'est pas annulée");
        assert_eq!(rqsta_maillons(&st, "saved_query.create"), 0, "fixture : le maillon n'est pas entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, `{"ok":true,"id":N}` octet pour octet et le maillon est posé.
    #[tokio::test]
    async fn rqsta_creation_nominale_octet_pour_octet() {
        let (st, _tmp) = sp_state("rqsta-creation-sain");
        let (statut, octets, v) = rqsta_creer(&st).await;
        assert_eq!(statut, 200, "{v}");
        let id = v.get("id").and_then(|x| x.as_i64()).expect("id servi");
        assert_eq!(octets, serde_json::to_vec(&json!({ "ok": true, "id": id })).unwrap(), "corps nominal octet pour octet : {v}");
        assert_eq!(rqsta_maillons(&st, "saved_query.create"), 1, "la création est inscrite au registre");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, la mise à jour est écrite et gardée ; 200, `ok` et l'aveu.
    /// MUTATION : `m8_jeter_update`.
    #[tokio::test]
    async fn rqsta_modification_sans_maillon_reste_faite_et_l_avoue() {
        let (st, _tmp) = sp_state("rqsta-modif-panne");
        let id = rqsta_semer(&st);
        rqsta_registre_hors_d_atteinte(&st);
        let (statut, _, v) = rqsta_modifier(&st, id).await;
        assert_eq!(statut, 200, "le geste a eu lieu, il n'est pas refusé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        rqsta_aveu_conforme(&v);
        assert_eq!(rqsta_ligne(&st, id), (1, "rqsta-renommee".to_string()), "la mise à jour est écrite et n'est pas annulée");
        assert_eq!(rqsta_maillons(&st, "saved_query.update"), 0, "fixture : le maillon n'est pas entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, `{"ok":true}` octet pour octet, maillon posé.
    #[tokio::test]
    async fn rqsta_modification_nominale_octet_pour_octet() {
        let (st, _tmp) = sp_state("rqsta-modif-sain");
        let id = rqsta_semer(&st);
        let (statut, octets, v) = rqsta_modifier(&st, id).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(octets, br#"{"ok":true}"#.to_vec(), "corps nominal octet pour octet : {v}");
        assert_eq!(rqsta_maillons(&st, "saved_query.update"), 1, "la mise à jour est inscrite au registre");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, la suppression a lieu (ligne disparue) ; 200, `ok` et l'aveu.
    /// MUTATION : `m8_jeter_delete`.
    #[tokio::test]
    async fn rqsta_suppression_sans_maillon_reste_faite_et_l_avoue() {
        let (st, _tmp) = sp_state("rqsta-suppr-panne");
        let id = rqsta_semer(&st);
        rqsta_registre_hors_d_atteinte(&st);
        let (statut, _, v) = rqsta_supprimer(&st, id).await;
        assert_eq!(statut, 200, "le geste a eu lieu, il n'est pas refusé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        rqsta_aveu_conforme(&v);
        assert_eq!(rqsta_ligne(&st, id).0, 0, "la suppression est faite et n'est pas annulée");
        assert_eq!(rqsta_maillons(&st, "saved_query.delete"), 0, "fixture : le maillon n'est pas entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, `{"ok":true}` octet pour octet, maillon posé.
    #[tokio::test]
    async fn rqsta_suppression_nominale_octet_pour_octet() {
        let (st, _tmp) = sp_state("rqsta-suppr-sain");
        let id = rqsta_semer(&st);
        let (statut, octets, v) = rqsta_supprimer(&st, id).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(octets, br#"{"ok":true}"#.to_vec(), "corps nominal octet pour octet : {v}");
        assert_eq!(rqsta_maillons(&st, "saved_query.delete"), 1, "la suppression est inscrite au registre");
    }
}
