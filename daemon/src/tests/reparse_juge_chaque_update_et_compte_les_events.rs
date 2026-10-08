// =====================================================================================
// `P10.27-i` (reprise après vérification) — LE REPARSE JUGE CHAQUE `UPDATE` AVANT LE SUIVANT ET COMPTE DES EVENTS.
//
// CE QUE LA VÉRIFICATION A MESURÉ SUR `58c26b1` : (a) les trois `UPDATE` d'un event s'exécutaient d'emblée (tableau
// d'`Option<Result>`) avant d'en juger un seul ; un refus qui fait ANNULER la transaction par le moteur
// (`RAISE(ROLLBACK)`) laissait l'`UPDATE` suivant du même event tourner hors transaction, validé d'office, et la route
// servait quand même 503 « AUCUN event n'a été modifié » (`dst_ip` promu à froid) ; (b) `updated` n'était tenu à
// compter des EVENTS par aucun témoin : toutes les fixtures n'avaient qu'une colonne promue par event.
//
// MUTANTS (joués par `VERIF_MUT`, retirés avant le commit) : `F8_TABLEAU` rend la forme d'avant (tout exécuter, puis
// juger) ; `F8_LIGNES` compte les lignes écrites au lieu des events.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le refus par disque plein, `IOERR` ou `NOMEM` n'est pas fabriqué (le
// déclencheur `RAISE(ROLLBACK)` produit la même annulation par le moteur, pas la même cause) ; le mode multi-tenant
// n'est pas joué.
// =====================================================================================
mod reparse_juge_chaque_update_et_compte_les_events {
    use super::*;

    async fn rju_corps(r: Response) -> (u16, Value, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let texte = String::from_utf8_lossy(&b).into_owned();
        (statut, serde_json::from_str(&texte).unwrap_or(Value::Null), texte)
    }

    fn rju_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    /// (1) Un `UPDATE` refusé par un `RAISE(ROLLBACK)` (le moteur annule lui-même la transaction) : 503
    /// `CAUSE_REPARSE_NON_APPLIQUE` et RIEN à froid — ni `src_ip`, ni `dst_ip` du même event, ni l'autre event.
    /// INVERSE : sans le déclencheur, 200, les deux colonnes promues. MUTATION : `F8_TABLEAU` — `dst_ip` validé à froid.
    #[tokio::test]
    async fn rju_un_rollback_du_moteur_ne_laisse_aucune_ecriture_du_meme_event() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rju-roll");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'rjuavant','m','{\"src_ip\":\"198.51.100.30\"}',''),
            (strftime('%s','now')-60,'rjuroll','m','{\"src_ip\":\"198.51.100.31\",\"dst_ip\":\"203.0.113.31\"}','');
            CREATE TRIGGER rju_roll BEFORE UPDATE OF src_ip ON event WHEN NEW.source='rjuroll' BEGIN SELECT RAISE(ROLLBACK,'rju roll'); END;")
            .expect("fixture");
        let (statut, corps, texte) = rju_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        let promus = "SELECT COUNT(*) FROM event WHERE source IN ('rjuavant','rjuroll') AND (COALESCE(src_ip,'')<>'' OR COALESCE(dst_ip,'')<>'')";
        assert_eq!(statut, 503, "{texte}");
        assert_eq!(corps["error"], json!(CAUSE_REPARSE_NON_APPLIQUE), "{texte}");
        // Pas d'assertion `is_autocommit()` ici : `RAISE(ROLLBACK)` ferme déjà la transaction, elle serait vraie quelle
        // que soit l'implémentation. La fermeture est tenue par `ecl_` (3), sur un `RAISE(ABORT)`.
        assert_eq!(rju_a_froid(&p, promus), 0, "la cause dit AUCUN event modifié : rien ne doit être validé à froid");

        st.db.lock().execute_batch("DROP TRIGGER rju_roll;").expect("fixture");
        let (statut, corps, texte) = rju_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["updated"], json!(2), "{texte}");
        assert_eq!(rju_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='rjuroll' AND src_ip='198.51.100.31' AND dst_ip='203.0.113.31'"), 1);
    }

    /// (2) Un event dont DEUX colonnes sont promues (`src_ip` ET `dst_ip`) compte UNE fois : `matched` 1, `updated` 1.
    /// MUTATION : `F8_LIGNES` — `updated` 2.
    #[tokio::test]
    async fn rju_un_event_a_deux_colonnes_promues_compte_une_fois() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rju-deux");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'rjudeux','m','{\"src_ip\":\"198.51.100.32\",\"dst_ip\":\"203.0.113.32\"}','');")
            .expect("fixture");
        let (statut, corps, texte) = rju_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["matched"], json!(1), "{texte}");
        assert_eq!(corps["updated"], json!(1), "un event, deux colonnes : compté une fois : {texte}");
        assert_eq!(rju_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='rjudeux' AND src_ip='198.51.100.32' AND dst_ip='203.0.113.32'"), 1, "les deux colonnes sont bien écrites");
    }
}
