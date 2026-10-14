// =====================================================================================
// `P10.20-b` (suite : `parsers_reload`, `dparsers_reload`) — LA CRÉATION FAIT PARTIE DE L'IDENTITÉ DES DEUX
// REGISTRES, ET LE MÉMO SURVIT À UN RECHARGEMENT NON PUBLIÉ.
//
// VU (vérification de a635845a) : trois affirmations du code n'avaient aucun témoin qui rougisse.
// - `dparsers_reload` dit « même parti que `parsers_reload` (id + nom + création relus) », mais retirer
//   `created` de sa requête laissait les 25 témoins verts : seul le parser avait un témoin « même nom, autre
//   création ». Un dparser supprimé puis recréé sous le même nom, spec illisible, revenait sous le rowid réutilisé.
// - « Le mémo ne tient que les parseurs lus actifs au dernier rechargement PUBLIÉ » : un mutant qui écrit le
//   mémo avant le retour anticipé (registre GARDÉ après une préparation ratée) le vidait ; au rechargement
//   suivant, une cellule illisible faisait sortir le parseur du registre (détection éteinte), sans témoin rouge.
// - Une création illisible lue comme 0 (la valeur DEFAULT de la colonne) passait pour une identité confirmée.
//
// TENU ICI :
// - dparser : identifiant réutilisé par le MÊME nom et une AUTRE création, spec illisible -> pas republié ;
// - parser et dparser : préparation ratée (registre gardé, mémo NON réécrit), puis cellule illisible au
//   rechargement suivant -> la version du dernier rechargement publié est toujours appliquée ;
// - parser et dparser : création illisible (cellule non entière) -> identité non confirmée, rien republié,
//   même quand la création mémorisée vaut 0.
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : DR_SQL_SANS_CREE (`0` à la place de `created` dans la
// requête de `dparsers_reload`) rougit `prmc_dparser_meme_nom_autre_creation_*` et `prmc_dparser_creation_illisible_*` ;
// PR_MEMO_SUR_ECHEC et DR_MEMO_SUR_ECHEC (mémo écrit avant le retour du registre gardé) rougissent `prmc_*_memo_garde_*` ;
// LR_CREE_DEFAUT (création illisible lue 0 dans `lire_registre_de_parseurs`) rougit `prmc_*_creation_illisible_*`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne de journal de `dire_les_echecs` (seule trace d'un échec en
// prod) n'est pas tenue ici — son témoin est dans `parseurs_registre_memo_par_base.rs` (`prmb_*_journal_*`). Le reste avoué de `parseurs_registre_identite_confirmee.rs` (même id, nom et
// création recréés sans rechargement réussi entre) tient toujours.
// =====================================================================================
mod parseurs_registre_memo_et_creation {
    use super::*;

    const SPEC_DU: &str = r#"{"source":"prmc-d","match":"PRMC","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"category":"firewall","fields":{"prmc_user":"$u"}}}"#;
    const SPEC_DH: &str = r#"{"source":"prmc-d","match":"PRMC","extract":[{"regex":"host=(?P<h>\\w+)"}],"map":{"fields":{"prmc_host":"$h"}}}"#;
    const MSG: &str = "PRMC user=alice host=web1";

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn r(db: &str, k: &str) -> Option<String> {
        champ(&parsers_apply(db, "prmc-r", MSG, None), k)
    }
    fn d(db: &str, k: &str) -> Option<String> {
        champ(&dparsers_apply(db, "prmc-d", MSG, None).0, k)
    }
    fn parseur(conn: &Connection, name: &str, pattern: &str, created: i64) -> i64 {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES(?1,'prmc-r',?2,1,?3)", params![name, pattern, created]).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, name: &str, spec: &str, created: i64) -> i64 {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'prmc-d',?2,1,0,0,?3)", params![name, spec, created]).unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn prmc_dparser_meme_nom_autre_creation_pas_ressuscite() {
        let conn = test_db();
        let db = ":memory:prmc-d-autre-creation";
        dparseur(&conn, "prmc-d-user", SPEC_DU, 100);
        let id_host = dparseur(&conn, "prmc-d-host", SPEC_DH, 100);
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_host").as_deref(), Some("web1"));
        conn.execute("DELETE FROM dparser WHERE id=?1", params![id_host]).unwrap();
        let id_neuf = dparseur(&conn, "prmc-d-host", SPEC_DU, 200);
        assert_eq!(id_neuf, id_host, "précondition : SQLite redonne le rowid supprimé");
        conn.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![id_neuf]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_host"), None, "dparser : même nom, autre création -> l'ancien n'est pas republié");
        assert_eq!(d(db, "prmc_user").as_deref(), Some("alice"), "le voisin lisible reste appliqué");
    }

    #[test]
    fn prmc_parser_memo_garde_apres_preparation_ratee() {
        let conn = test_db();
        let db = ":memory:prmc-p-memo-prep";
        parseur(&conn, "prmc-user", r"user=(?P<prmc_user>\w+)", 100);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prmc_user").as_deref(), Some("alice"));
        conn.execute_batch("ALTER TABLE parser RENAME TO parser_hors").unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prmc_user").as_deref(), Some("alice"), "préparation ratée : registre gardé");
        conn.execute_batch("ALTER TABLE parser_hors RENAME TO parser").unwrap();
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE name='prmc-user'", []).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prmc_user").as_deref(), Some("alice"), "le mémo du dernier rechargement PUBLIÉ survit au rechargement non publié");
    }

    #[test]
    fn prmc_dparser_memo_garde_apres_preparation_ratee() {
        let conn = test_db();
        let db = ":memory:prmc-d-memo-prep";
        dparseur(&conn, "prmc-d-user", SPEC_DU, 100);
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_user").as_deref(), Some("alice"));
        conn.execute_batch("ALTER TABLE dparser RENAME TO dparser_hors").unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_user").as_deref(), Some("alice"), "préparation ratée : registre gardé");
        conn.execute_batch("ALTER TABLE dparser_hors RENAME TO dparser").unwrap();
        conn.execute("UPDATE dparser SET spec=x'ff' WHERE name='prmc-d-user'", []).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_user").as_deref(), Some("alice"), "le mémo du dernier rechargement PUBLIÉ survit au rechargement non publié");
    }

    #[test]
    fn prmc_parser_creation_illisible_identite_non_confirmee() {
        let conn = test_db();
        let db = ":memory:prmc-p-cree-illisible";
        // création mémorisée = 0, la valeur DEFAULT : une création illisible lue 0 passerait pour confirmée.
        parseur(&conn, "prmc-user", r"user=(?P<prmc_user>\w+)", 0);
        let id_host = parseur(&conn, "prmc-host", r"host=(?P<prmc_host>\w+)", 0);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prmc_host").as_deref(), Some("web1"));
        conn.execute("UPDATE parser SET pattern=x'ff', created=x'ff' WHERE id=?1", params![id_host]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prmc_host"), None, "création illisible : identité non confirmée, rien republié");
        assert_eq!(r(db, "prmc_user").as_deref(), Some("alice"), "le voisin lisible reste appliqué");
    }

    #[test]
    fn prmc_dparser_creation_illisible_identite_non_confirmee() {
        let conn = test_db();
        let db = ":memory:prmc-d-cree-illisible";
        dparseur(&conn, "prmc-d-user", SPEC_DU, 0);
        let id_host = dparseur(&conn, "prmc-d-host", SPEC_DH, 0);
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_host").as_deref(), Some("web1"));
        conn.execute("UPDATE dparser SET spec=x'ff', created=x'ff' WHERE id=?1", params![id_host]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prmc_host"), None, "création illisible : identité non confirmée, rien republié");
        assert_eq!(d(db, "prmc_user").as_deref(), Some("alice"), "le voisin lisible reste appliqué");
    }
}
