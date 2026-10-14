// =====================================================================================
// `P10.20-b` (suite : `parsers_reload`, `dparsers_reload`) — UNE SOURCE ILLISIBLE GARDE LA VERSION DE LA RÈGLE,
// LIÉE À SA SOURCE ; UN NOM ILLISIBLE NE CONFIRME JAMAIS L'IDENTITÉ, MÊME QUAND LE NOM MÉMORISÉ EST VIDE.
//
// VU (seconde vérification de 25d24375) : trois affirmations du code n'avaient aucun témoin qui rougisse.
// - L'en-tête de `parsers_reload` dit qu'une source illisible garde la dernière version, et `dparsers_reload`
//   dit suivre « la même discipline » ; aucun témoin ne tenait le cas pour le dparser. Un mutant qui ne replie
//   pas une source illisible (bras `(Err(_), Ok(_)) => {}`) sortait le dparser du registre, détection éteinte
//   pour sa règle, et les 30 témoins restaient verts.
// - Une source illisible lue comme `'*'` (la valeur DEFAULT de la colonne) passait par la branche nominale :
//   le parseur s'appliquait alors à TOUTES les sources et ajoutait ses champs aux événements des autres.
//   Aucun témoin n'appliquait la version gardée à une AUTRE source (parser comme dparser).
// - Un nom illisible lu comme `""` passait pour une identité confirmée quand le nom mémorisé est vide (l'API
//   accepte un nom vide) : la version d'une autre règle pouvait revenir sous le rowid réutilisé.
//
// TENU ICI :
// - parser et dparser : source illisible -> la version gardée s'applique à SA source, et à aucune autre ;
// - dparser : source illisible -> la dernière version reste appliquée, l'échec est compté une fois ;
// - parser et dparser : nom illisible, nom mémorisé vide, motif/spec illisible -> rien republié.
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : PR_SRC_ETOILE (`l.source` illisible lue `"*"` dans
// `parsers_reload`) rougit `prsn_parser_source_illisible_reste_bornee_a_sa_source` ; DR_SRC_ETOILE (même geste
// dans `dparsers_reload`) rougit `prsn_dparser_source_illisible_reste_bornee_a_sa_source` ; DR_SRC_SANS_REPLI
// (bras `(Err(_), Ok(_)) => {}` avant le repli de `dparsers_reload`) rougit
// `prsn_dparser_source_illisible_garde_la_version` ; LR_NOM_DEFAUT (nom illisible lu `""` dans
// `lire_registre_de_parseurs`) rougit `prsn_*_nom_vide_illisible_identite_non_confirmee`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un nom ou une création illisible n'est ni dit au journal ni compté (la
// ligne perd seulement son identité : publiée si ses cellules se lisent, jamais republiée au repli) — l'en-tête
// de `parsers_reload` le dit désormais ; la ligne de journal de `dire_les_echecs` est tenue par
// `parseurs_registre_memo_par_base.rs` (`prmb_*_journal_*`), pas ici.
// =====================================================================================
mod parseurs_registre_source_et_nom_illisibles {
    use super::*;

    const SPEC: &str = r#"{"source":"prsn-d","match":"PRSN","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"fields":{"prsn_user":"$u"}}}"#;
    const MOTIF: &str = r"user=(?P<prsn_user>\w+)";
    const MSG: &str = "PRSN user=alice";

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn r(db: &str, source: &str) -> Option<String> {
        champ(&parsers_apply(db, source, MSG, None), "prsn_user")
    }
    fn d(db: &str, source: &str) -> Option<String> {
        champ(&dparsers_apply(db, source, MSG, None).0, "prsn_user")
    }
    fn parseur(conn: &Connection, name: &str) -> i64 {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES(?1,'prsn-r',?2,1,100)", params![name, MOTIF]).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, name: &str) -> i64 {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'prsn-d',?2,1,0,0,100)", params![name, SPEC]).unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn prsn_parser_source_illisible_reste_bornee_a_sa_source() {
        let conn = test_db();
        let db = ":memory:prsn-p-src-bornee";
        let id = parseur(&conn, "prsn-user");
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prsn-r").as_deref(), Some("alice"));
        assert_eq!(r(db, "prsn-autre"), None, "précondition : le parseur ne vise que sa source");
        conn.execute("UPDATE parser SET source=x'ff' WHERE id=?1", params![id]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prsn-r").as_deref(), Some("alice"), "source illisible : dernière version gardée");
        assert_eq!(r(db, "prsn-autre"), None, "source illisible : la version gardée garde SA source, pas '*'");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1);
    }

    #[test]
    fn prsn_dparser_source_illisible_garde_la_version() {
        let conn = test_db();
        let db = ":memory:prsn-d-src-garde";
        let id = dparseur(&conn, "prsn-d-user");
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-d").as_deref(), Some("alice"));
        conn.execute("UPDATE dparser SET source=x'ff' WHERE id=?1", params![id]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-d").as_deref(), Some("alice"), "dparser, source illisible : dernière version gardée");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1);
    }

    #[test]
    fn prsn_dparser_source_illisible_reste_bornee_a_sa_source() {
        let conn = test_db();
        let db = ":memory:prsn-d-src-bornee";
        let id = dparseur(&conn, "prsn-d-user");
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-autre"), None, "précondition : le dparser ne vise que sa source");
        conn.execute("UPDATE dparser SET source=x'ff' WHERE id=?1", params![id]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-autre"), None, "dparser, source illisible : la version gardée garde SA source, pas '*'");
    }

    #[test]
    fn prsn_parser_nom_vide_illisible_identite_non_confirmee() {
        let conn = test_db();
        let db = ":memory:prsn-p-nom-vide";
        let id = parseur(&conn, "");
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prsn-r").as_deref(), Some("alice"));
        conn.execute("UPDATE parser SET name=x'ff', pattern=x'ff' WHERE id=?1", params![id]).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(r(db, "prsn-r"), None, "nom illisible : identité non confirmée, même si le nom mémorisé est vide");
    }

    #[test]
    fn prsn_dparser_nom_vide_illisible_identite_non_confirmee() {
        let conn = test_db();
        let db = ":memory:prsn-d-nom-vide";
        let id = dparseur(&conn, "");
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-d").as_deref(), Some("alice"));
        conn.execute("UPDATE dparser SET name=x'ff', spec=x'ff' WHERE id=?1", params![id]).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d(db, "prsn-d"), None, "dparser, nom illisible : identité non confirmée, même si le nom mémorisé est vide");
    }
}
