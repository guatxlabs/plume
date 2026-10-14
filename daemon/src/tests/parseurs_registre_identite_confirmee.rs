// =====================================================================================
// `P10.20-b` (suite : `parsers_reload`, `dparsers_reload`) — LE REPLI NE REPUBLIE QUE LA MÊME RÈGLE.
//
// VU (223fcb00) : le mémo des dernières versions compilées était indexé par le seul `id` des tables `parser`
// et `dparser`, un INTEGER PRIMARY KEY sans AUTOINCREMENT : SQLite redonne le rowid d'une ligne supprimée.
// Un parseur supprimé, puis un autre créé qui reprend son identifiant avec une cellule illisible, et le repli
// republiait l'ANCIEN parseur sous l'identifiant du nouveau (sondes du vérificateur, rouges sur 223fcb00).
// Et l'affirmation « le mémo ne garde pas un parseur supprimé ou désactivé » n'avait aucun témoin qui rougisse
// si le mémo gardait tout (assertions vacantes du fichier `parseurs_registre_non_relu_conserve.rs`).
//
// PARTI : l'identité d'une règle = identifiant + `name` + `created` relus sur la ligne. Le repli ne republie
// la version gardée que si les trois égalent ceux mémorisés avec elle ; identité différente ou illisible ->
// RIEN n'est republié pour cette ligne (l'échec reste compté). La source n'en fait pas partie (champ éditable
// de la même règle ; une source illisible garde la dernière version, témoin du fichier voisin).
//
// TENU ICI :
// - identifiant réutilisé par un AUTRE nom, sans rechargement entre la suppression et la création, ou après
//   un rechargement sauté par une préparation ratée -> l'ancien n'est pas republié (parser, dparser) ;
// - identifiant réutilisé par le MÊME nom mais une autre création -> pas republié ;
// - nom et motif illisibles sur la même ligne -> identité non confirmée -> pas republié ;
// - identifiant réutilisé par le MÊME nom et la MÊME création APRÈS un rechargement réussi -> pas republié :
//   le mémo a lâché le supprimé (parser, dparser) ;
// - parseur désactivé, rechargé, puis réactivé avec une cellule illisible -> pas republié : le mémo a lâché le
//   désactivé (parser, dparser).
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : IDENT_IGNOREE (repli par le seul identifiant, forme de
// 223fcb00) rougit `pric_*_autre_nom_*`, `pric_parser_meme_nom_autre_creation_*` et `pric_parser_nom_illisible_*` ;
// IDENT_CREE_SEUL (création seule comparée) rougit `pric_*_autre_nom_*` ; IDENT_NOM_SEUL (nom seul comparé) rougit
// `pric_parser_meme_nom_autre_creation_*` ; IDENT_ABSENTE_OK (identité illisible tenue pour confirmée) rougit
// `pric_parser_nom_illisible_*` ; PR_MEMO_GARDE_TOUT et DR_MEMO_GARDE_TOUT (mémo initialisé au précédent)
// rougissent `pric_*_meme_identite_apres_rechargement_*` et `pric_*_reactive_*` ; REPLI_JAMAIS (aucune version
// republiée) rougit `prnr_*_cellule_illisible_reste_applique` du fichier voisin.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une règle supprimée puis recréée sous le même identifiant, le même nom
// et le même horodatage de création (même seconde, ou écriture hors processus qui pose `created` à la main),
// SANS rechargement réussi entre les deux, avec une cellule illisible, reçoit l'ancienne version : rien de
// lisible ne la distingue (pas de colonne de génération, et le schéma n'en ajoute pas ici). Par l'API, la
// suppression recharge aussitôt et une cellule ne peut pas devenir illisible ; il faut une écriture directe
// en base. La ligne de journal de `dire_les_echecs` est tenue par
// `parseurs_registre_memo_par_base.rs`, pas ici.
// =====================================================================================
mod parseurs_registre_identite_confirmee {
    use super::*;

    const SPEC_DU: &str = r#"{"source":"pric-d","match":"PRIC","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"category":"firewall","fields":{"pric_user":"$u"}}}"#;
    const SPEC_DH: &str = r#"{"source":"pric-d","match":"PRIC","extract":[{"regex":"host=(?P<h>\\w+)"}],"map":{"fields":{"pric_host":"$h"}}}"#;
    const MSG: &str = "PRIC user=alice host=web1";

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn r(db: &str, k: &str) -> Option<String> {
        champ(&parsers_apply(db, "pric-r", MSG, None), k)
    }
    fn d(db: &str, k: &str) -> Option<String> {
        champ(&dparsers_apply(db, "pric-d", MSG, None).0, k)
    }
    fn parseur(conn: &Connection, name: &str, pattern: &str, created: i64) -> i64 {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES(?1,'pric-r',?2,1,?3)", params![name, pattern, created]).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, name: &str, spec: &str, created: i64) -> i64 {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'pric-d',?2,1,0,0,?3)", params![name, spec, created]).unwrap();
        conn.last_insert_rowid()
    }
    fn rendre_illisible(conn: &Connection, table: &str, colonne: &str, id: i64) {
        conn.execute(&format!("UPDATE {table} SET {colonne}=x'ff' WHERE id=?1"), params![id]).unwrap();
    }

    /// Deux parseurs (user, host) chargés ; host est le dernier, son identifiant sera réutilisé.
    fn deux_parseurs(conn: &Connection, db: &str) -> i64 {
        parseur(conn, "pric-user", r"user=(?P<pric_user>\w+)", 100);
        let id_host = parseur(conn, "pric-host", r"host=(?P<pric_host>\w+)", 100);
        parsers_reload(conn, db);
        assert_eq!(r(db, "pric_host").as_deref(), Some("web1"), "nominal");
        id_host
    }
    fn deux_dparseurs(conn: &Connection, db: &str) -> i64 {
        dparseur(conn, "pric-d-user", SPEC_DU, 100);
        let id_host = dparseur(conn, "pric-d-host", SPEC_DH, 100);
        dparsers_reload(conn, db);
        assert_eq!(d(db, "pric_host").as_deref(), Some("web1"), "nominal");
        id_host
    }

    #[test]
    fn pric_parser_id_reutilise_autre_nom_sans_rechargement_pas_ressuscite() {
        let conn = test_db();
        let db = ":memory:pric-p-autre-nom";
        let id_host = deux_parseurs(&conn, db);
        conn.execute("DELETE FROM parser WHERE id=?1", params![id_host]).unwrap();
        let id_neuf = parseur(&conn, "pric-neuf", "x", 100);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "parser", "pattern", id_neuf);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "l'ancien parseur n'est pas republié sous l'identifiant d'un autre nom");
        assert_eq!(r(db, "pric_user").as_deref(), Some("alice"), "le parseur sain reste publié");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "la cellule illisible reste comptée");
    }

    #[test]
    fn pric_parser_id_reutilise_autre_nom_apres_rechargement_rate_pas_ressuscite() {
        let conn = test_db();
        let db = ":memory:pric-p-autre-nom-rate";
        let id_host = deux_parseurs(&conn, db);
        conn.execute("DELETE FROM parser WHERE id=?1", params![id_host]).unwrap();
        conn.execute_batch("ALTER TABLE parser RENAME TO parser_hors").unwrap();
        parsers_reload(&conn, db); // préparation ratée : registre et mémo gardés
        conn.execute_batch("ALTER TABLE parser_hors RENAME TO parser").unwrap();
        let id_neuf = parseur(&conn, "pric-neuf", "x", 100);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "parser", "pattern", id_neuf);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "rechargement sauté puis identifiant réutilisé : l'ancien n'est pas republié");
        assert_eq!(r(db, "pric_user").as_deref(), Some("alice"));
    }

    #[test]
    fn pric_dparser_id_reutilise_autre_nom_sans_rechargement_pas_ressuscite() {
        let conn = test_db();
        let db = ":memory:pric-d-autre-nom";
        let id_host = deux_dparseurs(&conn, db);
        conn.execute("DELETE FROM dparser WHERE id=?1", params![id_host]).unwrap();
        let id_neuf = dparseur(&conn, "pric-d-neuf", SPEC_DU, 100);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "dparser", "spec", id_neuf);
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "pric_host"), None, "l'ancien parseur déclaratif n'est pas republié sous l'identifiant d'un autre nom");
        assert_eq!(d(db, "pric_user").as_deref(), Some("alice"));
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1);
    }

    #[test]
    fn pric_parser_meme_nom_autre_creation_pas_ressuscite() {
        let conn = test_db();
        let db = ":memory:pric-p-autre-creation";
        let id_host = deux_parseurs(&conn, db);
        conn.execute("DELETE FROM parser WHERE id=?1", params![id_host]).unwrap();
        let id_neuf = parseur(&conn, "pric-host", "x", 200);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "parser", "pattern", id_neuf);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "même nom, autre création : une autre règle, l'ancienne n'est pas republiée");
    }

    #[test]
    fn pric_parser_nom_illisible_identite_non_confirmee() {
        let conn = test_db();
        let db = ":memory:pric-p-nom-illisible";
        let id_host = deux_parseurs(&conn, db);
        rendre_illisible(&conn, "parser", "pattern", id_host);
        rendre_illisible(&conn, "parser", "name", id_host);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "nom illisible : identité non confirmée, rien republié pour cette ligne");
        assert_eq!(r(db, "pric_user").as_deref(), Some("alice"));
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "la cellule illisible reste comptée");
    }

    #[test]
    fn pric_parser_meme_identite_apres_rechargement_memo_lache_le_supprime() {
        let conn = test_db();
        let db = ":memory:pric-p-meme-identite";
        let id_host = deux_parseurs(&conn, db);
        conn.execute("DELETE FROM parser WHERE id=?1", params![id_host]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "supprimé puis rechargé");
        let id_neuf = parseur(&conn, "pric-host", "x", 100);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "parser", "pattern", id_neuf);
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "même identité lisible, mais le rechargement réussi a sorti le supprimé du mémo");
    }

    #[test]
    fn pric_dparser_meme_identite_apres_rechargement_memo_lache_le_supprime() {
        let conn = test_db();
        let db = ":memory:pric-d-meme-identite";
        let id_host = deux_dparseurs(&conn, db);
        conn.execute("DELETE FROM dparser WHERE id=?1", params![id_host]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "pric_host"), None, "supprimé puis rechargé");
        let id_neuf = dparseur(&conn, "pric-d-host", SPEC_DU, 100);
        assert_eq!(id_neuf, id_host, "précondition : SQLite réutilise l'identifiant");
        rendre_illisible(&conn, "dparser", "spec", id_neuf);
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "pric_host"), None, "même identité lisible, mais le rechargement réussi a sorti le supprimé du mémo");
    }

    #[test]
    fn pric_parser_reactive_illisible_memo_lache_le_desactive() {
        let conn = test_db();
        let db = ":memory:pric-p-reactive";
        let id_host = deux_parseurs(&conn, db);
        conn.execute("UPDATE parser SET enabled=0 WHERE id=?1", params![id_host]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "désactivé puis rechargé");
        conn.execute("UPDATE parser SET enabled=1, pattern=x'ff' WHERE id=?1", params![id_host]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "pric_host"), None, "réactivé avec un motif illisible : le mémo a lâché le désactivé");
        assert_eq!(r(db, "pric_user").as_deref(), Some("alice"));
    }

    #[test]
    fn pric_dparser_reactive_illisible_memo_lache_le_desactive() {
        let conn = test_db();
        let db = ":memory:pric-d-reactive";
        let id_host = deux_dparseurs(&conn, db);
        conn.execute("UPDATE dparser SET enabled=0 WHERE id=?1", params![id_host]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "pric_host"), None, "désactivé puis rechargé");
        conn.execute("UPDATE dparser SET enabled=1, spec=x'ff' WHERE id=?1", params![id_host]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "pric_host"), None, "réactivé avec une spec illisible : le mémo a lâché le désactivé");
        assert_eq!(d(db, "pric_user").as_deref(), Some("alice"));
    }
}
