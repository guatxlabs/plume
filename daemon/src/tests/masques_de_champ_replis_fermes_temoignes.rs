// =====================================================================================
// `P10.20-b` (reprise) — CHAQUE REPLI FERMÉ DU REGISTRE DE MASQUAGE A SON TÉMOIN, CHAQUE SITE AUSSI.
//
// CE QUI MANQUAIT (relevé par vérification indépendante, mutants verts) : les replis « décodé en fermé »
// des cellules action (-> deny), rôle (-> admin), tenant et env (-> tous) ; l'échec au PAS et la ligne sans
// nom de champ lisible sur un registre chargé ; le premier chargement partiel ; le sel VIDE ; le sel
// ILLISIBLE côté SQL ; les sites `mask_query_result` (panneaux SQL brut, instantanés) et `mask_field_value`
// (timeline de dossier, caseops) ; NULL qui reste NULL sans sel.
//
// LE REGISTRE GELÉ, CORRIGÉ ICI. Après une ligne à nom de champ illisible, chaque rechargement ratait et
// gardait le registre en place TEL QUEL : une règle posée ensuite par la route CRUD (qui rend 200 {id})
// n'était armée qu'au redémarrage. Le registre publié sur lecture ratée est désormais l'UNION du registre en
// place et de ce qui a été décodé : la pose est armée tout de suite. (Texte de cette passe ; depuis la passe
// suivante l'union se fait par identifiant : une règle RELUE prend sa version décodée, donc un relâchement
// par PUT retire bien le DENY — témoin dans masques_de_champ_tri_enabled_et_relachement_temoignes.rs.)
//
// MUTANTS JOUÉS (variable d'environnement VERIF_MUT, lignes retirées avant le commit) : M_ACTION, M_ROLE,
// M_TENANT, M_ENV (repli de cellule affaibli), M_LIGNE (ligne sans nom sautée sans échec), M_PARCOURS
// (échec au pas non poussé), M_COND_PREMIER (registre jamais chargé non publié sur lecture partielle),
// M_UNION (registre en place gardé tel quel : l'ancien gel), M_SEL_VIDE (sel '' accepté), M_UDF_ERR (sel
// illisible -> "" côté SQL), M_QUERY_RESULT et M_FIELD_VALUE (site revenu à `unwrap_or_default`),
// M_CLOSED_NULL (NULL masqué sans sel) — chacun rougit le témoin qui porte son nom ci-dessous.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la pose passe ici par `field_filters_reload` appelé comme le fait la
// route CRUD (handlers/field_filters.rs), pas par la requête HTTP ; tant que la lecture rate, une règle
// SUPPRIMÉE garde sa version en place jusqu'à une lecture réussie ou au redémarrage (une règle MODIFIÉE et
// relue prend, elle, sa version décodée : cf. masques_de_champ_union_par_identifiant.rs) ; les appelants HTTP de `mask_query_result`/`mask_field_value` ne sont pas rejoués.
// =====================================================================================
mod masques_de_champ_replis_fermes_temoignes {
    use super::*;
    use guatx_core::soql::MaskAction;

    fn base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("h4r-{tag}"));
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
        conn.execute(
            "INSERT INTO field_filter(name,field,action,role) VALUES(?1,?2,?3,'')",
            params![name, field, action],
        )
        .unwrap();
    }

    fn deny_arme(path: &str, col: &str) -> bool {
        field_deny_cols_cell().read().get(path).map(|s| s.contains(col)).unwrap_or(false)
    }

    fn masque(path: &str, role: &str, tenant: &str, env: Option<&str>, field: &str) -> Option<MaskAction> {
        effective_masks(path, role, tenant, env).get(field)
    }

    fn type_de(conn: &Connection, col: &str, name: &str) -> String {
        conn.query_row(&format!("SELECT typeof({col}) FROM field_filter WHERE name=?1"), [name], |r| r.get(0)).unwrap()
    }

    // ---- replis de cellule (M_ACTION, M_ROLE, M_TENANT, M_ENV) ----

    #[test]
    fn h4r_action_illisible_vaut_deny_pour_l_admin() {
        let (path, conn) = base("action");
        regle(&conn, "ip", "src_ip", "mask");
        conn.execute("UPDATE field_filter SET action=X'00ff' WHERE name='ip'", []).unwrap();
        assert_eq!(type_de(&conn, "action", "ip"), "blob", "contrôle : cellule action non textuelle");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), Some(MaskAction::Deny), "action illisible -> DENY, admin compris");
        assert!(deny_arme(&path, "src_ip"), "l'authorizer reçoit la colonne");
    }

    #[test]
    fn h4r_role_illisible_vaut_admin_et_masque_l_admin() {
        let (path, conn) = base("role");
        regle(&conn, "m", "message", "mask");
        // contrôle : rôle '' ne masque PAS l'admin.
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "message"), None, "contrôle : rôle '' laisse l'admin en clair");
        conn.execute("UPDATE field_filter SET role=X'00ff' WHERE name='m'", []).unwrap();
        assert_eq!(type_de(&conn, "role", "m"), "blob");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "message"), Some(MaskAction::Mask), "rôle illisible -> seuil admin");
    }

    #[test]
    fn h4r_tenant_illisible_vaut_tous_les_tenants() {
        let (path, conn) = base("tenant");
        regle(&conn, "m", "message", "mask");
        conn.execute("UPDATE field_filter SET tenant=X'00ff' WHERE name='m'", []).unwrap();
        assert_eq!(type_de(&conn, "tenant", "m"), "blob");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        for t in ["default", "autre"] {
            assert_eq!(masque(&path, "viewer", t, None, "message"), Some(MaskAction::Mask), "tenant illisible -> tous ({t})");
        }
    }

    #[test]
    fn h4r_env_illisible_vaut_tous_les_envs() {
        let (path, conn) = base("env");
        regle(&conn, "m", "message", "mask");
        conn.execute("UPDATE field_filter SET env=X'00ff' WHERE name='m'", []).unwrap();
        assert_eq!(type_de(&conn, "env", "m"), "blob");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        for e in [None, Some("prod")] {
            assert_eq!(masque(&path, "viewer", "default", e, "message"), Some(MaskAction::Mask), "env illisible -> tous ({e:?})");
        }
    }

    // ---- registre chargé : ligne sans nom (M_LIGNE), échec au pas (M_PARCOURS) ----

    #[test]
    fn h4r_ligne_sans_nom_lisible_le_registre_charge_tient() {
        let (path, conn) = base("ligne");
        regle(&conn, "ip", "src_ip", "deny");
        regle(&conn, "m", "message", "mask");
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "contrôle : DENY chargé");
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='ip'", []).unwrap();
        assert_eq!(type_de(&conn, "field", "ip"), "blob");
        let avant = field_filters_lectures_ratees_de(&path);
        field_filters_reload(&conn, &path);
        let apres = field_filters_lectures_ratees_de(&path);
        assert!(apres > avant, "la ligne illisible est comptée ({avant} -> {apres})");
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), Some(MaskAction::Deny), "la règle en place tient");
        assert!(deny_arme(&path, "src_ip"), "l'authorizer garde src_ip");
        assert_eq!(masque(&path, "viewer", "default", None, "message"), Some(MaskAction::Mask), "la ligne saine reste");
    }

    #[test]
    fn h4r_echec_au_pas_le_registre_charge_tient() {
        let (path, conn) = base("parcours");
        regle(&conn, "ip", "src_ip", "deny");
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "contrôle : DENY chargé");
        conn.execute_batch(
            "ALTER TABLE field_filter RENAME TO field_filter_t;
             CREATE VIEW field_filter AS SELECT field,action,role,tenant,env,abs(-9223372036854775807-1) AS ord,id,enabled FROM field_filter_t;",
        )
        .unwrap();
        // contrôle : la préparation réussit, c'est le PAS qui échoue.
        let sql = "SELECT field,action,role,tenant,env,ord,id FROM field_filter WHERE enabled=1 ORDER BY ord, id";
        let mut st = conn.prepare(sql).expect("contrôle : préparation réussie");
        assert!(st.query([]).and_then(|mut r| r.next().map(|_| ())).is_err(), "contrôle : erreur au pas");
        drop(st);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), Some(MaskAction::Deny), "échec au pas : registre en place gardé");
        assert!(deny_arme(&path, "src_ip"), "l'authorizer garde src_ip");
    }

    // ---- premier chargement partiel (M_COND_PREMIER) ----

    #[test]
    fn h4r_premier_chargement_partiel_publie_ce_qui_est_lu() {
        let (path, conn) = base("premier");
        regle(&conn, "ip", "src_ip", "deny");
        regle(&conn, "x", "message", "mask");
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='x'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), Some(MaskAction::Deny), "registre jamais chargé : la ligne lisible est publiée");
        assert!(deny_arme(&path, "src_ip"), "l'authorizer reçoit src_ip");
    }

    // ---- registre gelé (M_UNION) ----

    #[test]
    fn h4r_pose_apres_ligne_illisible_est_armee_sans_redemarrage() {
        let (path, conn) = base("gel");
        regle(&conn, "m", "message", "mask");
        regle(&conn, "x", "host", "mask");
        field_filters_reload(&conn, &path);
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='x'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "default", None, "host"), Some(MaskAction::Mask), "contrôle : rien n'est désarmé");
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), None, "contrôle : src_ip pas encore masqué");
        // Ce que fait la route CRUD : INSERT validé puis `field_filters_reload`, puis 200 {id}.
        regle(&conn, "ip", "src_ip", "deny");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "admin", "default", None, "src_ip"), Some(MaskAction::Deny), "la règle posée est armée tout de suite");
        assert!(deny_arme(&path, "src_ip"), "l'authorizer la reçoit");
        assert_eq!(masque(&path, "viewer", "default", None, "message"), Some(MaskAction::Mask), "l'existant tient");
        assert_eq!(masque(&path, "viewer", "default", None, "host"), Some(MaskAction::Mask), "la règle illisible en place tient");
    }

    // ---- sel vide (M_SEL_VIDE), sel illisible côté SQL (M_UDF_ERR) ----

    fn hash_src_user(path: &str) -> Value {
        let masks = effective_masks(path, "viewer", "default", None);
        assert_eq!(masks.get("src_user"), Some(MaskAction::Hash), "contrôle : règle HASH chargée");
        let mut row = serde_json::Map::new();
        row.insert("src_user".into(), json!("alice"));
        assert!(mask_named_row(path, &masks, &mut row));
        row["src_user"].clone()
    }

    #[test]
    fn h4r_sel_vide_vaut_absent_jamais_un_hash_non_sale() {
        let (path, conn) = base("sel-vide");
        regle(&conn, "u", "src_user", "hash");
        conn.execute("UPDATE meta SET value='' WHERE key='field_mask_salt'", []).unwrap();
        assert_eq!(read_field_mask_salt(&conn), Ok(None), "sel vide = absent");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        let v = hash_src_user(&path);
        assert_ne!(v, json!(fmask_hash("", "alice")), "jamais le hash non salé");
        assert_eq!(v, json!("***"));
        drop(conn);
        let m = effective_masks(&path, "viewer", "default", None);
        let sql = soql_to_sql_masked_x("search | table src_user", 0, 0, None, &m).unwrap();
        match run_query_ex(&path, &sql, 5000, None) {
            Err(e) => assert!(e.to_string().contains("sel"), "{e}"),
            Ok(r) => panic!("sel vide : la requête HASH doit refuser, servi {}", r["rows"]),
        }
    }

    #[test]
    fn h4r_sel_illisible_la_fonction_sql_refuse() {
        let (path, conn) = base("udf-illisible");
        regle(&conn, "u", "src_user", "hash");
        conn.execute("UPDATE meta SET value=X'00ff' WHERE key='field_mask_salt'", []).unwrap();
        assert!(read_field_mask_salt(&conn).is_err(), "contrôle : sel illisible (Err, pas absent)");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        drop(conn);
        let m = effective_masks(&path, "viewer", "default", None);
        let sql = soql_to_sql_masked_x("search | table src_user", 0, 0, None, &m).unwrap();
        assert!(sql.contains("plume_fmask_hash"), "{sql}");
        match run_query_ex(&path, &sql, 5000, None) {
            Err(e) => assert!(e.to_string().contains("sel"), "refus qui nomme le sel : {e}"),
            Ok(r) => panic!("sel illisible : la requête HASH doit refuser, servi {}", r["rows"]),
        }
    }

    // ---- sites (M_QUERY_RESULT, M_FIELD_VALUE) et NULL sans sel (M_CLOSED_NULL) ----

    fn base_sans_sel(tag: &str) -> crate::tmp_possede::TmpDb {
        let (path, conn) = base(tag);
        regle(&conn, "u", "src_user", "hash");
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        path
    }

    #[test]
    fn h4r_mask_query_result_sans_sel_ferme_et_null_reste_null() {
        let path = base_sans_sel("site-query-result");
        let masks = effective_masks(&path, "viewer", "default", None);
        assert_eq!(masks.get("src_user"), Some(MaskAction::Hash));
        let mut v = json!({"columns": ["src_user", "host"], "rows": [["alice", "h1"], [null, "h2"]]});
        mask_query_result(&path, &masks, &mut v);
        assert_ne!(v["rows"][0][0], json!(fmask_hash("", "alice")), "jamais le hash non salé");
        assert_eq!(v["rows"][0][0], json!("***"), "panneau SQL brut sans sel : fermé");
        assert_eq!(v["rows"][1][0], Value::Null, "NULL reste NULL");
        assert_eq!(v["rows"][0][1], json!("h1"), "colonne non masquée intacte");
    }

    #[test]
    fn h4r_mask_field_value_sans_sel_ferme() {
        let path = base_sans_sel("site-field-value");
        let masks = effective_masks(&path, "viewer", "default", None);
        let v = mask_field_value(&path, &masks, "src_user", &json!("alice"));
        assert_ne!(v, json!(fmask_hash("", "alice")), "jamais le hash non salé");
        assert_eq!(v, json!("***"), "timeline de dossier sans sel : fermé");
        assert_eq!(mask_field_value(&path, &masks, "src_user", &Value::Null), Value::Null, "NULL reste NULL");
    }
}
