// =====================================================================================
// `P10.20-b` (reste : comptage du sel de HASH) — UN SEL NON LU SE COMPTE, SUR SA BASE ET SUR ELLE SEULE.
//
// CE QUI MANQUAIT (re-mesuré sur 824949d) : `field_filters_reload` compte le sel ABSENT ou VIDE (bras
// `Ok(None)`) et le sel ILLISIBLE (bras `Err`) par `compter_lecture_ratee`, mais aucun test ne lisait le
// compte sur ces deux bras : les témoins du sel existants jugent le hash fermé (`***`) et l'erreur SQL qui
// nomme le sel, pas le compte. Retirer l'un ou l'autre appel laissait la suite verte.
//
// ICI : compte PAR BASE (`field_filters_lectures_ratees_de`), jamais le total du processus (atomique partagé
// entre fils de test). Égalité EXACTE (+1 par rechargement) : la table `field_filter` est lue sans échec,
// donc le seul incrément possible est celui du sel. Une seconde base, saine, sert de contrôle d'isolement.
//
// MUTANTS JOUÉS (variable d environnement de mutation, lignes retirées avant le commit) : J5_SEL_ABSENT_NON_COMPTE (appel retiré du bras
// `Ok(None)`) rougit j5s_sel_absent_* et j5s_sel_vide_* ; J5_SEL_ILLISIBLE_NON_COMPTE (appel retiré du bras
// `Err`) rougit j5s_sel_illisible_*.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le compte n'est pas servi par `/metrics` (limite écrite dans
// field_filter.rs) ; la préséance d'une règle corrompue n'est pas traitée ; aucun code de production n'est
// changé : ce fichier ne fait que témoigner d'un comportement déjà en place.
// =====================================================================================
mod masques_de_champ_sel_non_lu_compte_par_base {
    use super::*;
    use guatx_core::soql::MaskAction;

    fn base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("j5s-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        conn.execute(
            "INSERT INTO field_filter(name,field,action,role) VALUES('u','src_user','hash','')",
            [],
        )
        .unwrap();
        (path, conn)
    }

    fn sel(conn: &Connection) -> String {
        let s: String = conn.query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0)).unwrap();
        assert!(!s.is_empty(), "contrôle : sel posé par la migration");
        s
    }

    fn hash_alice(path: &str) -> Value {
        let masks = effective_masks(path, "viewer", "default", None);
        assert_eq!(masks.get("src_user"), Some(MaskAction::Hash), "contrôle : règle HASH chargée");
        mask_field_value(path, &masks, "src_user", &json!("alice"))
    }

    /// Recharge `n` fois la base dégradée et juge : +1 exact par rechargement sur elle, 0 sur la base saine.
    fn juge_compte(conn: &Connection, path: &str, conn_autre: &Connection, autre: &str, bras: &str) {
        for i in 1..=3u64 {
            let avant = field_filters_lectures_ratees_de(path);
            let avant_autre = field_filters_lectures_ratees_de(autre);
            field_filters_reload(conn, path);
            field_filters_reload(conn_autre, autre);
            assert_eq!(
                field_filters_lectures_ratees_de(path),
                avant + 1,
                "{bras} : rechargement {i}, le sel non lu compte exactement 1 sur sa base"
            );
            assert_eq!(field_filters_lectures_ratees_de(autre), avant_autre, "{bras} : la base saine ne bouge pas");
        }
    }

    // ---- (a) J5_SEL_ABSENT_NON_COMPTE ----
    #[test]
    fn j5s_sel_absent_compte_un_par_rechargement_sur_sa_base() {
        let (path, conn) = base("absent");
        let (autre, conn_autre) = base("absent-autre");
        conn.execute("DELETE FROM meta WHERE key='field_mask_salt'", []).unwrap();
        assert_eq!(read_field_mask_salt(&conn), Ok(None), "contrôle : sel absent");
        juge_compte(&conn, &path, &conn_autre, &autre, "sel absent");
    }

    // ---- (b) J5_SEL_ABSENT_NON_COMPTE (même bras, valeur vide) ----
    #[test]
    fn j5s_sel_vide_compte_un_par_rechargement_sur_sa_base() {
        let (path, conn) = base("vide");
        let (autre, conn_autre) = base("vide-autre");
        conn.execute("UPDATE meta SET value='' WHERE key='field_mask_salt'", []).unwrap();
        assert_eq!(read_field_mask_salt(&conn), Ok(None), "contrôle : sel vide = absent");
        juge_compte(&conn, &path, &conn_autre, &autre, "sel vide");
    }

    // ---- (c) J5_SEL_ILLISIBLE_NON_COMPTE ----
    #[test]
    fn j5s_sel_illisible_compte_un_par_rechargement_sur_sa_base() {
        let (path, conn) = base("illisible");
        let (autre, conn_autre) = base("illisible-autre");
        conn.execute("UPDATE meta SET value=X'00ff' WHERE key='field_mask_salt'", []).unwrap();
        assert!(read_field_mask_salt(&conn).is_err(), "contrôle : sel illisible (Err, pas absent)");
        juge_compte(&conn, &path, &conn_autre, &autre, "sel illisible");
    }

    // ---- (d) contrôle négatif : sel lu -> aucun compte ----
    #[test]
    fn j5s_sel_lu_ne_compte_rien() {
        let (path, conn) = base("lu");
        let s = sel(&conn);
        let avant = field_filters_lectures_ratees_de(&path);
        for _ in 0..3 {
            field_filters_reload(&conn, &path);
        }
        assert_eq!(field_filters_lectures_ratees_de(&path), avant, "sel lu : aucun échec compté");
        assert_eq!(hash_alice(&path), json!(fmask_hash(&s, "alice")), "sel lu : hash salé");
    }

    // ---- (e) sel en cache gardé après perte ; sans cache, `***` (jamais "") ----
    #[test]
    fn j5s_sel_perdu_cache_garde_sinon_ferme() {
        for degrade in ["DELETE FROM meta WHERE key='field_mask_salt'", "UPDATE meta SET value=X'00ff' WHERE key='field_mask_salt'"] {
            let (path, conn) = base("cache");
            let s = sel(&conn);
            field_filters_forget(&path);
            field_filters_reload(&conn, &path);
            assert_eq!(hash_alice(&path), json!(fmask_hash(&s, "alice")), "contrôle : sel en cache");
            conn.execute(degrade, []).unwrap();
            let avant = field_filters_lectures_ratees_de(&path);
            field_filters_reload(&conn, &path);
            assert_eq!(field_filters_lectures_ratees_de(&path), avant + 1, "{degrade} : compté");
            assert_eq!(hash_alice(&path), json!(fmask_hash(&s, "alice")), "{degrade} : sel en cache conservé");
            // Nouveau processus (cache oublié) : sans sel, HASH fermé, jamais le hash non salé.
            field_filters_forget(&path);
            field_filters_reload(&conn, &path);
            assert_eq!(field_filters_lectures_ratees_de(&path), avant + 2, "{degrade} : recompté");
            let v = hash_alice(&path);
            assert_ne!(v, json!(fmask_hash("", "alice")), "{degrade} : jamais le hash non salé");
            assert_eq!(v, json!("***"), "{degrade} : sans sel en cache, HASH fermé");
        }
    }
}
