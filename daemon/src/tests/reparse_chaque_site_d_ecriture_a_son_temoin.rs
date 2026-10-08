// =====================================================================================
// `P10.27-i` (seconde reprise après vérification) — CHAQUE SITE D'ÉCRITURE DU REPARSE A SON TÉMOIN.
//
// CE QUE LA VÉRIFICATION A MESURÉ SUR `b466906` : les témoins `ecl_` et `rju_` ne refusaient jamais que le site
// `src_ip`. Les sites `fields` et `dst_ip` pouvaient revenir chacun à `let _ = conn.execute(...)` (ou perdre le `?`
// après `juger`) sans qu'aucun témoin ne rougisse ; aucune fixture n'exerçait un event dont `fields` change (aucune
// source `k8s-log`, seule source de l'extraction générique par défaut) ; `lignes = k` au lieu de `lignes += k`
// restait vert ; et aucun témoin ne LISAIT le texte de `CAUSE_REPARSE_NON_APPLIQUE` (comparé à lui-même seulement).
//
// MUTANTS (joués par `VERIF_MUT`, retirés avant le commit) : `F8_MF1`/`F8_MD1` (site remis en `let _`),
// `F8_MF2`/`F8_MD2` (`let _ = juger(...)`, le `?` retiré), `F8_MR5` (`lignes = k`), `F8_MT` (ancien texte de la cause
// servi au 503). Les sites `src_ip` (`F8_MS1`/`F8_MS2`) et ceux de `obs.rs` (`F8_MP1`, `F8_MW1`) sont rejoués dans la
// même passe contre les témoins `ecl_`/`rju_` qui les tiennent déjà.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le refus par disque plein, `IOERR` ou `NOMEM` n'est pas fabriqué (un
// déclencheur `RAISE(ABORT)` produit le même `Err`, pas la même cause) ; le mode multi-tenant n'est pas joué ;
// une source d'extraction générique autre que `k8s-log` (`PLUME_GENERIC_EXTRACT`) n'est pas jouée.
// =====================================================================================
mod reparse_chaque_site_d_ecriture_a_son_temoin {
    use super::*;

    /// Fragment que seule la cause d'après `P10.27-i` porte : l'ancienne ne nommait que BEGIN et COMMIT.
    const RCS_FRAGMENT_DE_LA_CAUSE: &str = "mise à jour d'un event refusée";

    async fn rcs_corps(r: Response) -> (u16, Value, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let texte = String::from_utf8_lossy(&b).into_owned();
        (statut, serde_json::from_str(&texte).unwrap_or(Value::Null), texte)
    }

    fn rcs_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn rcs_cause_lue(corps: &Value, texte: &str) {
        let cause = corps["error"].as_str().unwrap_or_else(|| panic!("le 503 porte une cause : {texte}"));
        assert!(cause.contains(RCS_FRAGMENT_DE_LA_CAUSE), "la cause nomme la mise à jour refusée : {texte}");
        assert!(cause.contains("AUCUN event n'a été modifié"), "{texte}");
    }

    /// (1) SITE `dst_ip` — un `UPDATE OF dst_ip` refusé (`RAISE(ABORT)`) entre deux events promouvables : 503, cause
    /// LUE, et RIEN à froid (ni l'event d'avant, ni `src_ip` du même event, ni l'event d'après). INVERSE : sans le
    /// déclencheur, 200 et les trois events promus. MUTATIONS : `F8_MD1` (200 validé), `F8_MD2` (l'event d'après validé
    /// hors transaction), `F8_MT` (cause d'avant).
    #[tokio::test]
    async fn rcs_un_refus_sur_dst_ip_ne_laisse_rien_a_froid() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rcs-dst");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'rcsavant','m','{\"src_ip\":\"198.51.100.50\"}',''),
            (strftime('%s','now')-60,'rcsdst','m','{\"src_ip\":\"198.51.100.51\",\"dst_ip\":\"203.0.113.51\"}',''),
            (strftime('%s','now')-60,'rcsapres','m','{\"src_ip\":\"198.51.100.52\"}','');
            CREATE TRIGGER rcs_dst BEFORE UPDATE OF dst_ip ON event WHEN NEW.source='rcsdst' BEGIN SELECT RAISE(ABORT,'rcs dst'); END;")
            .expect("fixture");
        let promus = "SELECT COUNT(*) FROM event WHERE source IN ('rcsavant','rcsdst','rcsapres') AND (COALESCE(src_ip,'')<>'' OR COALESCE(dst_ip,'')<>'')";
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 503, "{texte}");
        rcs_cause_lue(&corps, &texte);
        assert_eq!(rcs_a_froid(&p, promus), 0, "la cause dit AUCUN event modifié : rien ne doit être validé à froid");

        st.db.lock().execute_batch("DROP TRIGGER rcs_dst;").expect("fixture");
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["updated"], json!(3), "{texte}");
        assert_eq!(rcs_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='rcsdst' AND dst_ip='203.0.113.51'"), 1);
    }

    /// (2) SITE `fields` — un `UPDATE OF fields` refusé sur une ligne `k8s-log` (extraction générique) entre deux events
    /// promouvables : 503, cause LUE, rien à froid. INVERSE : sans le déclencheur, 200, `fields` et `src_ip` écrits.
    /// MUTATIONS : `F8_MF1` (200, `src_ip` validé), `F8_MF2` (les écritures suivantes validées hors transaction).
    #[tokio::test]
    async fn rcs_un_refus_sur_fields_ne_laisse_rien_a_froid() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rcs-fields");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'rcsavant','m','{\"src_ip\":\"198.51.100.60\"}',''),
            (strftime('%s','now')-60,'k8s-log','user=alice src_ip=198.51.100.61','{}',''),
            (strftime('%s','now')-60,'rcsapres','m','{\"src_ip\":\"198.51.100.62\"}','');
            CREATE TRIGGER rcs_fields BEFORE UPDATE OF fields ON event WHEN NEW.source='k8s-log' BEGIN SELECT RAISE(ABORT,'rcs fields'); END;")
            .expect("fixture");
        let modifies = "SELECT COUNT(*) FROM event WHERE COALESCE(src_ip,'')<>'' OR (source='k8s-log' AND fields<>'{}')";
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 503, "{texte}");
        rcs_cause_lue(&corps, &texte);
        assert_eq!(rcs_a_froid(&p, modifies), 0, "la cause dit AUCUN event modifié : rien ne doit être validé à froid");

        st.db.lock().execute_batch("DROP TRIGGER rcs_fields;").expect("fixture");
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["updated"], json!(3), "{texte}");
        assert_eq!(rcs_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='k8s-log' AND fields LIKE '%alice%' AND src_ip='198.51.100.61'"), 1);
    }

    /// (3) COMPTE, site `fields` seul — un event dont SEULE `fields` change (aucune adresse) compte une fois.
    /// MUTATION : `F8_MF1` — l'écriture n'est plus comptée, `updated` 0.
    #[tokio::test]
    async fn rcs_un_event_dont_seul_fields_change_compte_une_fois() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rcs-fseul");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'k8s-log','user=alice','{}','');").expect("fixture");
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["matched"], json!(1), "{texte}");
        assert_eq!(corps["updated"], json!(1), "{texte}");
        assert_eq!(rcs_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='k8s-log' AND fields LIKE '%alice%' AND COALESCE(src_ip,'')=''"), 1);
    }

    /// (4) COMPTE, cumul des colonnes — `fields` écrit puis `src_ip` ignoré par la base (`RAISE(IGNORE)`, `Ok(0)`) :
    /// l'event a changé, il compte une fois. MUTATIONS : `F8_MR5` (`lignes = k` écrase le 1 de `fields` par le 0 de
    /// `src_ip` : `updated` 0), `F8_MF1`.
    #[tokio::test]
    async fn rcs_fields_ecrit_puis_src_ip_ignore_compte_l_event() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("rcs-fign");
        st.db.lock().execute_batch("INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'k8s-log','user=alice src_ip=198.51.100.71','{}','');
            CREATE TRIGGER rcs_ign BEFORE UPDATE OF src_ip ON event WHEN NEW.source='k8s-log' BEGIN SELECT RAISE(IGNORE); END;")
            .expect("fixture");
        let (statut, corps, texte) = rcs_corps(parser_reparse(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["matched"], json!(1), "{texte}");
        assert_eq!(corps["updated"], json!(1), "{texte}");
        assert_eq!(rcs_a_froid(&p, "SELECT COUNT(*) FROM event WHERE source='k8s-log' AND fields LIKE '%alice%' AND COALESCE(src_ip,'')=''"), 1);
    }
}
