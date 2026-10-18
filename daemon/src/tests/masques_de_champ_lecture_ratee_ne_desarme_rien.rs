// =====================================================================================
// `P10.20-b` (famille `P10.20-l` hors `handlers/`) — UNE LECTURE RATÉE DU REGISTRE DE MASQUAGE NE
// DÉSARME JAMAIS UN MASQUE.
//
// LE DÉFAUT, LU SUR b52f097. `field_filters_reload` lisait la table `field_filter` sous
// `if let Ok(..) = prepare` / `if let Ok(..) = query_map` sans branche d'échec, puis
// `rows.flatten()` (une ligne indécodable disparaissait en silence), et REMPLAÇAIT ensuite sans
// condition les trois cellules (règles, colonnes DENY de l'authorizer, sel) : une lecture ratée
// publiait un registre VIDE par-dessus celui en place — masquage et DENY désarmés, valeurs servies en
// clair. Le sel, lu par `.unwrap_or_default()` ici ET dans `install_fmask_udf`, valait "" s'il était
// absent ou illisible : HASH = SHA-256("\0"+valeur) tronqué, attaquable au dictionnaire.
//
// LES TÉMOINS. (1) une règle dont `ord` est du texte reste au registre, rechargé OU chargé pour la
// première fois ; (2) la table renommée sous les pieds du reload laisse le DENY en place, authorizer
// compris, et l'échec est COMPTÉ ; un registre vide relu avec succès remplace (contrôle positif : le
// vide POSÉ par l'exploitant reste légitime) ; (3) sel supprimé ou illisible : le HASH Rust rend `***`
// et jamais `fmask_hash("", v)`, un sel déjà en cache est gardé ; (4) côté SQL, `plume_fmask_hash`
// sans sel REFUSE au lieu de hacher sans sel, avec le contrôle positif du hash salé.
//
// MUTANTS JOUÉS (variable d'environnement de mutation, retirés avant le commit) : `H4_REMPLACE` (remplacement inconditionnel) ->
// (2) rouge ; (1a) reste VERT sous ce seul mutant (le décodage en fermé ne produit aucun échec, il n'y a
// rien à remplacer) — il ne rougit que combiné au décodage strict de l'ancien code ; `H4_DECODE_STRICT` (ligne à `ord` texte = échec) -> (1b) rouge ; `H4_SEL_VIDE`
// (sel "" au reload, l'ancien `unwrap_or_default`) -> (3) rouge ; `H4_SEL_VIDE_SQL` (idem dans
// `install_fmask_udf`) -> (4) rouge.
//
// Les replis restants (cellules action/rôle/tenant/env, parcours, ligne sans nom, premier chargement
// partiel, union avec une pose CRUD, sel vide, sel illisible côté SQL, sites `mask_query_result` et
// `mask_field_value`, NULL sans sel) ont leurs témoins dans `masques_de_champ_replis_fermes_temoignes.rs`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un registre JAMAIS chargé dont la lecture échoue entièrement
// (table absente au premier chargement) reste absent, donc sans masque — il n'y a rien à conserver,
// et un registre « tout masquer » n'existe pas ; le compteur n'est pas servi par `/metrics`.
// =====================================================================================
mod masques_de_champ_lecture_ratee_ne_desarme_rien {
    use super::*;
    use guatx_core::soql::MaskAction;

    /// Base migrée (table `field_filter` + sel v86), deux événements, connexion d'écriture rendue.
    fn base_masquee(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("h4-{tag}"));
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

    fn deny_src_ip_arme(path: &str) -> bool {
        field_deny_cols_cell().read().get(path).map(|s| s.contains("src_ip")).unwrap_or(false)
    }

    fn src_ip_masque_pour(path: &str, role: &str) -> Option<MaskAction> {
        effective_masks(path, role, "default", None).get("src_ip")
    }

    #[test]
    fn h4_ord_texte_ne_perd_pas_la_regle_d_un_registre_charge() {
        let (path, conn) = base_masquee("ord-recharge");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ip','src_ip','deny','')", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(src_ip_masque_pour(&path, "admin") == Some(MaskAction::Deny) && deny_src_ip_arme(&path), "contrôle : DENY chargé");
        conn.execute("UPDATE field_filter SET ord='pas-un-entier' WHERE field='src_ip'", []).unwrap();
        let t: String = conn.query_row("SELECT typeof(ord) FROM field_filter WHERE field='src_ip'", [], |r| r.get(0)).unwrap();
        assert_eq!(t, "text", "contrôle : la cellule est bien devenue du texte");
        field_filters_reload(&conn, &path);
        assert!(src_ip_masque_pour(&path, "viewer") == Some(MaskAction::Deny), "la règle à ord texte reste au registre");
        assert!(src_ip_masque_pour(&path, "admin") == Some(MaskAction::Deny), "DENY tient pour l'admin");
        assert!(deny_src_ip_arme(&path), "l'authorizer garde src_ip");
    }

    #[test]
    fn h4_ord_texte_au_premier_chargement_la_regle_est_chargee() {
        let (path, conn) = base_masquee("ord-premier");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ip','src_ip','deny','')", []).unwrap();
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('m','message','mask','')", []).unwrap();
        conn.execute("UPDATE field_filter SET ord='x' WHERE field='src_ip'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        let m = effective_masks(&path, "viewer", "default", None);
        assert!(m.get("message") == Some(MaskAction::Mask), "contrôle : la ligne saine est chargée");
        assert!(m.get("src_ip") == Some(MaskAction::Deny), "la ligne à ord texte est chargée en fermé, pas perdue");
        assert!(deny_src_ip_arme(&path), "l'authorizer reçoit src_ip");
    }

    #[test]
    fn h4_table_renommee_le_deny_en_place_tient_et_l_echec_est_compte() {
        let (path, conn) = base_masquee("table-renommee");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ip','src_ip','deny','')", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(deny_src_ip_arme(&path), "contrôle : DENY chargé");
        conn.execute_batch("ALTER TABLE field_filter RENAME TO field_filter_ailleurs").unwrap();
        let avant = field_filters_lectures_ratees_de(&path);
        field_filters_reload(&conn, &path);
        let apres = field_filters_lectures_ratees_de(&path);
        assert!(apres > avant, "la lecture ratée est comptée ({avant} -> {apres})");
        assert!(src_ip_masque_pour(&path, "admin") == Some(MaskAction::Deny), "le masque en place est conservé");
        assert!(deny_src_ip_arme(&path), "l'authorizer garde src_ip");
        drop(conn);
        assert!(run_query_ex(&path, "SELECT src_ip FROM event", 5000, None).is_err(), "SQL brut toujours refusé");
        // INVERSE NOMINAL : une lecture RÉUSSIE d'un registre vide (posé par l'exploitant) remplace.
        let conn = open_db(&path).unwrap();
        conn.execute_batch("ALTER TABLE field_filter_ailleurs RENAME TO field_filter; DELETE FROM field_filter;").unwrap();
        field_filters_reload(&conn, &path);
        assert!(src_ip_masque_pour(&path, "admin").is_none() && !deny_src_ip_arme(&path), "registre vide lu = vide servi");
    }

    fn hash_rust(path: &str) -> Value {
        let masks = effective_masks(path, "viewer", "default", None);
        assert!(masks.get("src_user") == Some(MaskAction::Hash), "contrôle : règle HASH chargée");
        let mut row = serde_json::Map::new();
        row.insert("src_user".into(), json!("alice"));
        assert!(mask_named_row(path, &masks, &mut row));
        row["src_user"].clone()
    }

    #[test]
    fn h4_sel_absent_ou_illisible_le_hash_rust_n_est_jamais_non_sale() {
        let non_sale = json!(fmask_hash("", "alice"));
        // ABSENT.
        let (path, conn) = base_masquee("sel-absent");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        field_filters_reload(&conn, &path);
        let v = hash_rust(&path);
        assert_ne!(v, non_sale, "sel absent : jamais le hash non salé");
        assert_eq!(v, json!("***"), "sel absent : HASH fermé");
        // ILLISIBLE (blob), registre jamais chargé.
        let (path2, conn2) = base_masquee("sel-illisible");
        conn2.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        conn2.execute("UPDATE meta SET value=X'00ff' WHERE key='field_mask_salt'", []).unwrap();
        field_filters_reload(&conn2, &path2);
        let v2 = hash_rust(&path2);
        assert_ne!(v2, non_sale, "sel illisible : jamais le hash non salé");
        assert_eq!(v2, json!("***"));
        // ILLISIBLE alors qu'un sel est en cache : il est gardé (le sel est immuable).
        let (path3, conn3) = base_masquee("sel-garde");
        conn3.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        let salt: String = conn3.query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0)).unwrap();
        field_filters_reload(&conn3, &path3);
        assert_eq!(hash_rust(&path3), json!(fmask_hash(&salt, "alice")), "contrôle positif : hash salé");
        conn3.execute("UPDATE meta SET value=X'00ff' WHERE key='field_mask_salt'", []).unwrap();
        field_filters_reload(&conn3, &path3);
        assert_eq!(hash_rust(&path3), json!(fmask_hash(&salt, "alice")), "sel en cache conservé");
    }

    #[test]
    fn h4_sel_absent_la_fonction_sql_refuse_au_lieu_de_hacher_sans_sel() {
        // CONTRÔLE POSITIF : avec son sel, la même requête rend le hash salé.
        let (ok_path, ok_conn) = base_masquee("sql-sale");
        ok_conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        let salt: String = ok_conn.query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0)).unwrap();
        field_filters_reload(&ok_conn, &ok_path);
        drop(ok_conn);
        let m = effective_masks(&ok_path, "viewer", "default", None);
        let sql = soql_to_sql_masked_x("search | table src_user", 0, 0, None, &m).unwrap();
        assert!(sql.contains("plume_fmask_hash"), "{sql}");
        let r = run_query_ex(&ok_path, &sql, 5000, None).unwrap();
        assert_eq!(r["rows"][0][0], json!(fmask_hash(&salt, "alice")), "contrôle : hash salé servi");

        let (path, conn) = base_masquee("sql-sans-sel");
        conn.execute("INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')", []).unwrap();
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        field_filters_reload(&conn, &path);
        drop(conn);
        let m = effective_masks(&path, "viewer", "default", None);
        let sql = soql_to_sql_masked_x("search | table src_user", 0, 0, None, &m).unwrap();
        match run_query_ex(&path, &sql, 5000, None) {
            // Sel ABSENT : le refus le dit tel, jamais « illisible » (vérification finale de la vague V, mutant
            // C10 : `SQLITE_DONE` rendu en échec de lecture restait vert sous un simple `contains("sel")`).
            Err(e) => {
                let e = e.to_string();
                assert!(e.contains("sel") && e.contains("absent"), "refus qui nomme le sel absent : {e}");
                assert!(!e.contains("illisible"), "un sel absent n'est pas un sel illisible : {e}");
            }
            Ok(r) => panic!("sans sel, la requête HASH doit échouer fermé, servi : {}", r["rows"]),
        }
    }
}
