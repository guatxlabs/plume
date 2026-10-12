// =====================================================================================
// `P10.20-b` (troisième passe) — L'UNION DU REGISTRE SUR LECTURE RATÉE SE FAIT PAR IDENTIFIANT ; LES
// REPLIS RESTÉS SANS TÉMOIN EN ONT UN.
//
// CE QUI ÉTAIT FAUX (relevé par vérification indépendante, mutants verts) :
// - l'union recopiait TOUT le registre décodé à chaque rechargement raté : 2 règles devenaient 12 après dix
//   rechargements, et le départage « la version décodée l'emporte » ne tenait qu'à l'ordre de
//   concaténation, sans témoin ;
// - une version en place PLUS SPÉCIFIQUE (rôle ou tenant) battait la version modifiée par la route PUT :
//   « plus de masques, jamais moins » était faux, le viewer recevait MaskPartial au lieu de Mask ;
// - `enabled` d'un type inattendu sortait la règle par `WHERE enabled=1`, sans échec ni écart : DENY
//   désarmé en silence ;
// - le bras `(_, None)` de `mask_json_value_closed` (MASK, PARTIAL, REDACT, DENY sans sel), « ord illisible
//   -> fin de liste », et le sel en cache gardé quand le sel est ABSENT n'avaient aucun témoin.
//
// MUTANTS JOUÉS (VERIF_MUT, lignes retirées avant le commit) : H4_GARDE_EN_PLACE (la version en place d'une
// règle relue l'emporte), H4_SANS_DEDUP (versions en place des règles relues gardées), H4_DENY_DECODE_SEUL
// (colonnes DENY prises des seules règles décodées), H4_CLOSED_AUTRES (sans sel, valeur rendue en clair),
// H4_ENABLED (enabled inattendu = éteinte), H4_ORD_MIN (ord illisible -> tête de liste),
// H4_SEL_ABSENT_EFFACE (sel absent -> cache effacé) — chacun rougit le témoin qui porte son nom.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la modification passe par un UPDATE SQL suivi de
// `field_filters_reload`, comme la route PUT, pas par la requête HTTP ; une règle SUPPRIMÉE ou ÉTEINTE pendant une
// lecture ratée reste armée jusqu'à une lecture réussie ou au redémarrage ; un `id` illisible n'est pas joué
// (clé primaire entière, la base ne peut pas le rendre autrement).
// =====================================================================================
mod masques_de_champ_union_par_identifiant {
    use super::*;
    use guatx_core::soql::MaskAction;

    fn base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("h4u-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,host,message,src_ip,fields) VALUES(?1,'sshd','auth',3,'h1','login alice','10.0.0.5',?2)",
            params![now(), r#"{"src_user":"alice"}"#],
        )
        .unwrap();
        (path, conn)
    }

    fn regle(conn: &Connection, name: &str, field: &str, action: &str) {
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES(?1,?2,?3,'')", params![name, field, action])
            .unwrap();
    }

    fn n_regles(path: &str) -> usize {
        FIELD_FILTERS.get().map(|c| c.read().get(path).map(|v| v.len()).unwrap_or(0)).unwrap_or(0)
    }

    fn deny_arme(path: &str, col: &str) -> bool {
        field_deny_cols_cell().read().get(path).map(|s| s.contains(col)).unwrap_or(false)
    }

    fn masque(path: &str, role: &str, tenant: &str, field: &str) -> Option<MaskAction> {
        effective_masks(path, role, tenant, None).get(field)
    }

    /// Registre chargé, puis la ligne `x` rendue illisible (nom de champ BLOB) : chaque rechargement rate.
    fn lecture_ratee(conn: &Connection, path: &str) {
        regle(conn, "x", "host", "mask");
        field_filters_reload(conn, path);
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='x'", []).unwrap();
    }

    // ---- H4_GARDE_EN_PLACE ----
    #[test]
    fn h4u_modif_resserree_pendant_lecture_ratee_est_armee() {
        let (path, conn) = base("resserree");
        regle(&conn, "u", "src_user", "hash");
        lecture_ratee(&conn, &path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", "src_user"), Some(MaskAction::Hash), "contrôle");
        conn.execute("UPDATE field_filter SET action='mask' WHERE name='u'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", "src_user"), Some(MaskAction::Mask), "resserrement HASH->MASK armé");
        assert_eq!(masque(&path, "viewer", "default", "host"), Some(MaskAction::Mask), "la règle non relue reste armée");
    }

    // ---- H4_SANS_DEDUP : version en place plus spécifique (rôle, puis tenant) ----
    #[test]
    fn h4u_modif_put_moins_specifique_prend_la_version_decodee() {
        let (path, conn) = base("put-role");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('m','message','partial','viewer')", []).unwrap();
        conn.execute("INSERT INTO field_filter(name,field,action,role,tenant) VALUES('t','url','partial','','default')", []).unwrap();
        lecture_ratee(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", "message"), Some(MaskAction::MaskPartial), "contrôle rôle");
        assert_eq!(masque(&path, "viewer", "default", "url"), Some(MaskAction::MaskPartial), "contrôle tenant");
        conn.execute("UPDATE field_filter SET field='message', action='mask', role='' WHERE name='m'", []).unwrap();
        conn.execute("UPDATE field_filter SET action='mask', tenant='' WHERE name='t'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", "message"), Some(MaskAction::Mask), "PUT partial/viewer -> mask/'' servi");
        assert_eq!(masque(&path, "viewer", "default", "url"), Some(MaskAction::Mask), "PUT partial/default -> mask/'' servi");
    }

    // ---- H4_SANS_DEDUP ----
    #[test]
    fn h4u_reloads_rates_sans_doublon() {
        let (path, conn) = base("doublons");
        regle(&conn, "u", "src_user", "hash");
        lecture_ratee(&conn, &path);
        let n0 = n_regles(&path);
        assert_eq!(n0, 2, "contrôle");
        for _ in 0..10 {
            field_filters_reload(&conn, &path);
        }
        assert_eq!(n_regles(&path), n0, "dix rechargements ratés : même taille de registre");
    }

    // ---- H4_DENY_DECODE_SEUL ----
    #[test]
    fn h4u_deny_non_relu_reste_dans_l_authorizer() {
        let (path, conn) = base("deny-non-relu");
        regle(&conn, "ip", "src_ip", "deny");
        regle(&conn, "u", "src_user", "hash");
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "contrôle");
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='ip'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "DENY d'une ligne devenue illisible : toujours dans l'authorizer");
        assert_eq!(masque(&path, "admin", "default", "src_ip"), Some(MaskAction::Deny));
    }

    // ---- H4_CLOSED_AUTRES ----
    #[test]
    fn h4u_sans_sel_mask_partial_redact_deny_restent_appliques() {
        let alice = json!("alice-4242");
        assert_eq!(mask_json_value_closed(MaskAction::Mask, None, &alice), json!("***"));
        assert_eq!(mask_json_value_closed(MaskAction::MaskPartial, None, &alice), mask_json_value(MaskAction::MaskPartial, "", &alice));
        assert_ne!(mask_json_value_closed(MaskAction::MaskPartial, None, &alice), alice);
        assert_eq!(mask_json_value_closed(MaskAction::Redact, None, &alice), Value::Null);
        assert_eq!(mask_json_value_closed(MaskAction::Deny, None, &alice), Value::Null);

        let (path, conn) = base("sans-sel-mask");
        regle(&conn, "m", "src_user", "mask");
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        let masks = effective_masks(&path, "viewer", "default", None);
        assert_eq!(masks.get("src_user"), Some(MaskAction::Mask), "contrôle");
        let mut row = serde_json::Map::new();
        row.insert("src_user".into(), json!("alice"));
        mask_named_row(&path, &masks, &mut row);
        assert_eq!(row["src_user"], json!("***"), "mask_named_row");
        assert_eq!(mask_field_value(&path, &masks, "src_user", &json!("alice")), json!("***"), "mask_field_value");
        let mut v = json!({"columns": ["src_user"], "rows": [["alice"]]});
        mask_query_result(&path, &masks, &mut v);
        assert_eq!(v["rows"][0][0], json!("***"), "mask_query_result");
    }

    // ---- H4_ENABLED ----
    #[test]
    fn h4u_enabled_de_type_inattendu_laisse_la_regle_active() {
        let (path, conn) = base("enabled");
        regle(&conn, "ip", "src_ip", "deny");
        regle(&conn, "off", "src_user", "mask");
        conn.execute("UPDATE field_filter SET enabled=0 WHERE name='off'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "contrôle");
        assert_eq!(masque(&path, "viewer", "default", "src_user"), None, "contrôle : enabled=0 éteint la règle");
        conn.execute("UPDATE field_filter SET enabled=X'01' WHERE name='ip'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "enabled=X'01' : DENY toujours dans l'authorizer");
        assert_eq!(masque(&path, "admin", "default", "src_ip"), Some(MaskAction::Deny));
        conn.execute("UPDATE field_filter SET enabled='oui' WHERE name='ip'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "enabled texte, registre jamais chargé : DENY armé");
    }

    // ---- H4_ORD_MIN ----
    #[test]
    fn h4u_ord_illisible_fin_de_liste() {
        let (path, conn) = base("ord-fin");
        regle(&conn, "a", "message", "partial");
        regle(&conn, "b", "message", "redact");
        conn.execute("UPDATE field_filter SET ord=5 WHERE name='b'", []).unwrap();
        conn.execute("UPDATE field_filter SET ord='x' WHERE name='a'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", "message"), Some(MaskAction::MaskPartial), "ord illisible = fin de liste");
    }

    // ---- H4_SEL_ABSENT_EFFACE ----
    #[test]
    fn h4u_sel_absent_sel_en_cache_garde() {
        let (path, conn) = base("sel-absent-cache");
        regle(&conn, "u", "src_user", "hash");
        let salt: String = conn.query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0)).unwrap();
        assert!(!salt.is_empty(), "contrôle : sel posé par la migration");
        field_filters_reload(&conn, &path);
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        field_filters_reload(&conn, &path);
        let masks = effective_masks(&path, "viewer", "default", None);
        assert_eq!(mask_field_value(&path, &masks, "src_user", &json!("alice")), json!(fmask_hash(&salt, "alice")));
    }
}
