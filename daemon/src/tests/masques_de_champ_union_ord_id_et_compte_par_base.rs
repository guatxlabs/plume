// =====================================================================================
// `P10.20-b` (cinquième passe) — LE REGISTRE UNI EST TRIÉ AUSSI SUR `ord` PUIS `id`, ET L'ÉCHEC DE
// LECTURE EST COMPTÉ PAR BASE.
//
// CE QUI MANQUAIT (relevé par vérification indépendante) :
// - le tri du registre uni (bras `(true, Some(_))` de `field_filters_reload`) n'était témoigné que sur sa
//   PREMIÈRE clé, la spécificité. Union triée sans `ord`, ou sans `id` : les témoins restaient verts, et le
//   viewer recevait MaskPartial (4 derniers caractères en clair) au lieu de Mask dès qu'une ligne du registre
//   devenait illisible. `ord` vaut 0 par défaut : c'est `id` qui départage le cas courant. Les deux tris
//   passent désormais par UN comparateur, `ordre_de_preseance` ;
// - « après > avant » sur `FIELD_FILTERS_LECTURE_RATEE_TOTAL` lit un atomique du PROCESSUS : sous
//   `cargo test` (un processus, plusieurs fils, ce que joue la CI) tout rechargement raté d'une AUTRE base
//   l'incrémente aussi, et le mutant « échec non compté » pouvait passer vert. Le compte se lit désormais par
//   base (`field_filters_lectures_ratees_de`), que seuls les rechargements de cette base touchent.
//
// MUTANTS JOUÉS (VERIF_MUT, lignes retirées avant le commit), chacun rougit le témoin qui porte son nom :
// I1C_UNION_SANS_ORD et I1C_PRESEANCE_SANS_ORD (union triée par spécificité puis id), I1C_UNION_SANS_ID et
// I1C_PRESEANCE_SANS_ID (spécificité puis ord), I1C_ECHEC_NON_COMPTE (échec de préparation non compté),
// I1C_COMPTE_SANS_BASE (compte par base tenu sous une clé commune à toutes les bases). Sous
// I1C_PRESEANCE_SANS_ID le contrôle (lecture réussie, tenue par l'`ORDER BY`) reste vert et c'est l'assertion
// du registre uni qui rougit : la dépendance à `id` est bien celle du tri de l'union. I1C_UNION_SANS_ID, posé
// en RE-TRI après le bon tri, est un mutant équivalent (tri stable sur une clé plus grossière : l'ordre ne
// bouge pas) — vert sans conséquence, la forme qui remplace le tri est I1C_PRESEANCE_SANS_ID.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS (RESTES AVOUÉS) :
// - le total du processus reste un atomique global : aucun témoin n'en mesure l'incrément exact, seul le
//   compte par base est jugé (le geste qui compte est UN appel qui touche les deux) ;
// - le tri de la lecture RÉUSSIE est aussi tenu par l'`ORDER BY ord, id` du SELECT : ces témoins ne
//   départagent le comparateur que sur le registre uni ;
// - la préséance d'une règle à cellule corrompue reste celle avouée par la quatrième passe.
// =====================================================================================
mod masques_de_champ_union_ord_id_et_compte_par_base {
    use super::*;
    use guatx_core::soql::MaskAction;

    fn base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("i1c-{tag}"));
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        let _ = migrate(&conn);
        (path, conn)
    }

    /// Insère une règle `role=''` (même spécificité pour toutes) et rend son id.
    fn regle(conn: &Connection, name: &str, field: &str, action: &str, ord: i64) -> i64 {
        conn.execute(
            "INSERT INTO field_filter(name,field,action,role,ord) VALUES(?1,?2,?3,'',?4)",
            params![name, field, action, ord],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn rendre_illisible(conn: &Connection, name: &str) {
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name=?1", params![name]).unwrap();
    }

    fn masque(path: &str, field: &str) -> Option<MaskAction> {
        effective_masks(path, "viewer", "default", None).get(field)
    }

    // ---- I1C_UNION_SANS_ORD / I1C_PRESEANCE_SANS_ORD : `ord` départage deux règles RELUES ----
    #[test]
    fn i1c_union_ord_departage_deux_regles_relues() {
        let (path, conn) = base("ord-relues");
        let m = regle(&conn, "m", "host", "mask", 10);
        let p = regle(&conn, "p", "host", "partial", 0);
        regle(&conn, "z", "message", "mask", 0);
        assert!(m < p, "contrôle : sans ord, l'id ferait gagner partial");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "host"), Some(MaskAction::Mask), "contrôle : ord 10 l'emporte sur ord 0");
        // Une ligne ÉTRANGÈRE au champ devient illisible : lecture ratée, m et p sont relues, le registre s'unit.
        rendre_illisible(&conn, "z");
        field_filters_reload(&conn, &path);
        assert_eq!(
            masque(&path, "host"),
            Some(MaskAction::Mask),
            "registre uni : ord 10 (mask) doit toujours l'emporter sur ord 0 (partial) — sinon MaskPartial"
        );
        assert_eq!(masque(&path, "message"), Some(MaskAction::Mask), "la règle non relue reste armée");
    }

    // ---- I1C_UNION_SANS_ORD / I1C_PRESEANCE_SANS_ORD : `ord` de la règle NON relue ----
    #[test]
    fn i1c_union_ord_de_la_regle_non_relue() {
        let (path, conn) = base("ord-non-relue");
        let m = regle(&conn, "m", "host", "mask", 10);
        let p = regle(&conn, "p", "host", "partial", 0);
        assert!(m < p, "contrôle : sans ord, l'id ferait gagner partial");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "host"), Some(MaskAction::Mask), "contrôle");
        // m devient illisible : sa version en place (ord 10) est gardée, p (ord 0) est relue.
        rendre_illisible(&conn, "m");
        field_filters_reload(&conn, &path);
        assert_eq!(
            masque(&path, "host"),
            Some(MaskAction::Mask),
            "registre uni : la version en place de m (ord 10) doit l'emporter sur p relue (ord 0) — sinon MaskPartial"
        );
    }

    // ---- I1C_UNION_SANS_ID / I1C_PRESEANCE_SANS_ID : à ord égal (défaut), `id` départage ----
    #[test]
    fn i1c_union_id_departage_a_ord_egal() {
        let (path, conn) = base("id");
        let p = regle(&conn, "p", "host", "partial", 0);
        let m = regle(&conn, "m", "host", "mask", 0);
        assert!(p < m, "contrôle : m a le plus grand id");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "host"), Some(MaskAction::Mask), "contrôle : à ord égal, le plus grand id gagne");
        // m devient illisible : sa version en place est mise en tête de l'union, p relue derrière. Seul l'id
        // remet m en dernier.
        rendre_illisible(&conn, "m");
        field_filters_reload(&conn, &path);
        assert_eq!(
            masque(&path, "host"),
            Some(MaskAction::Mask),
            "registre uni : à ord égal, m (id le plus grand, non relue) doit l'emporter sur p — sinon MaskPartial"
        );
    }

    // ---- I1C_ECHEC_NON_COMPTE / I1C_COMPTE_SANS_BASE : le compte est celui de CETTE base ----
    #[test]
    fn i1c_echec_compte_sur_sa_base_et_sur_elle_seule() {
        let (path, conn) = base("compte");
        let (autre, conn_autre) = base("compte-autre");
        regle(&conn, "ip", "src_ip", "deny", 0);
        regle(&conn_autre, "ip", "src_ip", "deny", 0);
        field_filters_reload(&conn, &path);
        field_filters_reload(&conn_autre, &autre);
        let avant = field_filters_lectures_ratees_de(&path);
        let avant_autre = field_filters_lectures_ratees_de(&autre);
        conn.execute_batch("ALTER TABLE field_filter RENAME TO field_filter_ailleurs").unwrap();
        field_filters_reload(&conn, &path);
        let apres = field_filters_lectures_ratees_de(&path);
        assert!(apres > avant, "la préparation ratée est comptée sur sa base ({avant} -> {apres})");
        assert_eq!(field_filters_lectures_ratees_de(&autre), avant_autre, "l'échec d'une base ne compte pas sur l'autre");
        // L'autre base échoue à son tour : le compte de la première ne bouge pas.
        conn_autre.execute_batch("ALTER TABLE field_filter RENAME TO field_filter_ailleurs").unwrap();
        field_filters_reload(&conn_autre, &autre);
        assert!(field_filters_lectures_ratees_de(&autre) > avant_autre, "l'autre base compte son échec");
        assert_eq!(field_filters_lectures_ratees_de(&path), apres, "et seulement le sien");
        assert_eq!(masque(&path, "src_ip"), Some(MaskAction::Deny), "le DENY en place tient");
    }
}
