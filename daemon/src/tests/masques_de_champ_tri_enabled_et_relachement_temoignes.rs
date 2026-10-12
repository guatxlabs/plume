// =====================================================================================
// `P10.20-b` (quatrième passe) — LE TRI DU REGISTRE UNI, L'ENTIER `enabled` AUTRE QUE 0 ET 1, ET LE
// RELÂCHEMENT PAR PUT PENDANT UNE LECTURE RATÉE ONT LEUR TÉMOIN.
//
// CE QUI MANQUAIT (relevé par vérification indépendante, mutants VERTS sur les témoins des trois passes
// précédentes et sur leur voisinage) :
// - le tri « le plus spécifique gagne » APRÈS l'union par identifiant (`field_filters_reload`, bras
//   `(true, Some(_))`) : sans lui, la version en place d'une règle non relue PLUS spécifique passe avant la
//   règle relue moins spécifique sur le même champ, et le viewer reçoit MaskPartial au lieu de Mask ;
// - un entier `enabled` autre que 0 et 1 : le code dit « seul l'entier 0 éteint la règle », seuls X'01' et
//   'oui' étaient joués ; le mutant qui rétablit `WHERE enabled=1` pour les entiers désarmait un DENY sans
//   un mot sur stderr ni compteur ;
// - le relâchement (DENY -> mask) par PUT pendant une lecture ratée, affirmé par la docstring et sans témoin.
//
// MUTANTS JOUÉS (VERIF_MUT, lignes retirées avant le commit), chacun rougit le témoin qui porte son nom :
// I1_SANS_TRI (union publiée sans tri), I1_ENABLED_ENTIER (entier `enabled` != 1 => règle éteinte),
// I1_DENY_GARDE (colonne DENY de la version en place d'une règle relue gardée dans l'authorizer).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS (RESTES AVOUÉS) :
// - la PRÉSÉANCE d'une règle à cellule corrompue : « décodé en fermé » élargit la PORTÉE, pas le rang. Un
//   rôle illisible devient `admin` (+1 de spécificité) et un `ord` illisible place la règle en fin de liste :
//   sur un champ couvert par deux règles, la règle corrompue l'emporte même si son action est plus faible
//   (mesuré par la vérification : `message` partial + `message` mask -> Mask ; rôle de la première rendu
//   X'00ff' -> MaskPartial pour le viewer). La valeur n'est jamais servie en clair, et un DENY reste tenu par
//   la passe 2 d'`effective_masks`, mais l'action servie est plus faible qu'avant la corruption. Non corrigé
//   ici : changer le rang d'une règle corrompue est une décision de sémantique, pas un témoin ;
// - la modification passe par un UPDATE SQL suivi de `field_filters_reload`, comme la route PUT, pas par la
//   requête HTTP ;
// - `P10.20-l` n'a toujours pas sa garde qui lit le bras `Err` : ces témoins ne la remplacent pas.
// =====================================================================================
mod masques_de_champ_tri_enabled_et_relachement_temoignes {
    use super::*;
    use guatx_core::soql::MaskAction;

    fn base(tag: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let path = crate::tmp_possede::TmpDb::neuf(&format!("i1-{tag}"));
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

    fn regle(conn: &Connection, name: &str, field: &str, action: &str, role: &str) {
        conn.execute(
            "INSERT INTO field_filter(name,field,action,role) VALUES(?1,?2,?3,?4)",
            params![name, field, action, role],
        )
        .unwrap();
    }

    fn deny_arme(path: &str, col: &str) -> bool {
        field_deny_cols_cell().read().get(path).map(|s| s.contains(col)).unwrap_or(false)
    }

    fn masque(path: &str, role: &str, field: &str) -> Option<MaskAction> {
        effective_masks(path, role, "default", None).get(field)
    }

    // ---- I1_SANS_TRI ----
    #[test]
    fn i1_union_triee_le_plus_specifique_non_relu_gagne() {
        let (path, conn) = base("tri");
        // x : host/mask/role=admin (spécificité 1, masque aussi le viewer) ; y : host/partial/role='' (0).
        regle(&conn, "x", "host", "mask", "admin");
        regle(&conn, "y", "host", "partial", "");
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "host"), Some(MaskAction::Mask), "contrôle : x, plus spécifique, gagne");
        // x devient illisible : la lecture rate, x garde sa version en place (non relue), y est relue.
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='x'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert_eq!(
            masque(&path, "viewer", "host"),
            Some(MaskAction::Mask),
            "registre uni : x (en place, plus spécifique) doit toujours l'emporter sur y (relue) — sinon MaskPartial"
        );
        assert_eq!(masque(&path, "editor", "host"), Some(MaskAction::Mask), "idem pour l'editor");
    }

    // ---- I1_ENABLED_ENTIER ----
    #[test]
    fn i1_enabled_entier_autre_que_zero_et_un_laisse_la_regle_active() {
        let (path, conn) = base("enabled-entier");
        regle(&conn, "ip", "src_ip", "deny", "");
        regle(&conn, "u", "url", "deny", "");
        regle(&conn, "off", "message", "mask", "");
        conn.execute("UPDATE field_filter SET enabled=0 WHERE name='off'", []).unwrap();
        conn.execute("UPDATE field_filter SET enabled=2 WHERE name='ip'", []).unwrap();
        conn.execute("UPDATE field_filter SET enabled=-1 WHERE name='u'", []).unwrap();
        let t: String = conn.query_row("SELECT typeof(enabled) FROM field_filter WHERE name='ip'", [], |r| r.get(0)).unwrap();
        assert_eq!(t, "integer", "contrôle : la cellule est bien un ENTIER");
        field_filters_forget(&path);
        field_filters_reload(&conn, &path);
        assert_eq!(masque(&path, "viewer", "message"), None, "contrôle : enabled=0 éteint la règle");
        assert!(deny_arme(&path, "src_ip"), "enabled=2 : DENY src_ip dans l'authorizer");
        assert!(deny_arme(&path, "url"), "enabled=-1 : DENY url dans l'authorizer");
        assert_eq!(masque(&path, "admin", "src_ip"), Some(MaskAction::Deny));
        assert_eq!(masque(&path, "admin", "url"), Some(MaskAction::Deny));
        // Registre déjà chargé, lecture réussie : même verdict (le remplacement ne les perd pas).
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip") && deny_arme(&path, "url"), "rechargement : DENY toujours armés");
    }

    // ---- I1_DENY_GARDE ----
    #[test]
    fn i1_relachement_put_pendant_lecture_ratee_retire_le_deny() {
        let (path, conn) = base("relachement");
        regle(&conn, "ip", "src_ip", "deny", "");
        regle(&conn, "x", "host", "mask", "");
        field_filters_reload(&conn, &path);
        assert!(deny_arme(&path, "src_ip"), "contrôle");
        conn.execute("UPDATE field_filter SET field=X'00ff' WHERE name='x'", []).unwrap();
        conn.execute("UPDATE field_filter SET action='mask' WHERE name='ip'", []).unwrap();
        field_filters_reload(&conn, &path);
        assert!(!deny_arme(&path, "src_ip"), "relâchement DENY -> mask relu : src_ip sort de l'authorizer");
        assert_eq!(masque(&path, "viewer", "src_ip"), Some(MaskAction::Mask), "la version décodée fait foi");
        assert_eq!(masque(&path, "admin", "src_ip"), None, "mask role='' ne masque pas l'admin");
        assert_eq!(masque(&path, "viewer", "host"), Some(MaskAction::Mask), "la règle non relue reste armée");
    }
}
