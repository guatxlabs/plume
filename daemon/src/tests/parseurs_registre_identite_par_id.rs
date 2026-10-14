// =====================================================================================
// `P10.20-b` (suite : `parsers_reload`, `dparsers_reload`) — L'IDENTIFIANT FAIT PARTIE DE L'IDENTITÉ DE LA
// RÈGLE, ET LA LIGNE DE JOURNAL DIT LA BONNE SUITE D'UN ÉCHEC NON ATTRIBUABLE.
//
// VU (deuxième vérification indépendante) :
// - un mutant de `version_gardee_de_la_meme_regle` qui cherche la version gardée par (nom, création) dans TOUT
//   le mémo, sans regarder l'identifiant, laissait verts les 42 témoins du lot. Effet : B (« Parser »,
//   created=100) supprimé en base, puis C créé avec le même nom, la même création, un AUTRE identifiant et un
//   motif illisible -> la version de B republiée sous C : un parseur supprimé revient ;
// - un mutant qui échange dans `dire_les_echecs` « registre en place GARDÉ » et « aucun registre en place :
//   seuls les parseurs lus sont publiés » laissait verts les mêmes témoins : seule la suite d'une cellule
//   illisible était lue. La ligne de journal, seul aveu en production, pouvait mentir.
//
// TENU ICI : même (nom, création), autre identifiant, l'ancien supprimé -> rien de l'ancien ne revient
// (parser et dparser) ; deux règles vivantes de même (nom, création) sous deux identifiants, cellules
// illisibles -> chacune garde SA version (parser et dparser) ; préparation ratée avec registre en place ->
// la ligne dit « registre en place GARDÉ » ; préparation ratée au premier chargement -> la ligne dit « aucun
// registre en place : seuls les parseurs lus sont publiés » (parser et dparser).
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : VG_PAR_IDENTITE (recherche par (nom, création) sans
// l'identifiant) rougit `prip_*_autre_id_*` et `prip_*_deux_regles_*` ; DE_SUITE_NA_INVERSEE (les deux suites
// non attribuables échangées) rougit `prip_*_journal_*`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS (restes avoués) :
// - un parseur dont la cellule `enabled` est illisible (un blob) est écarté par `WHERE enabled=1` des deux
//   requêtes (`parsers_reload`, `dparsers_reload`) : il sort du registre SANS compte NI ligne de journal, et la
//   détection de cette règle s'éteint en silence. Non corrigé ici ;
// - `parseurs_lectures_ratees_de` (le compte par base) n'est lu que sous `cfg(test)` : en production le compte
//   est incrémenté mais servi par aucune surface (ni `/metrics`, ni l'API). « Compté par base » ne vaut que
//   pour les témoins ; la seule trace de production reste la ligne de journal.
// =====================================================================================
mod parseurs_registre_identite_par_id {
    use super::*;

    const MSG: &str = "PRIP user=alice host=web1";
    const SPEC_USER: &str = r#"{"source":"prip-d","match":"PRIP","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"fields":{"prip_user":"$u"}}}"#;
    const SPEC_HOST: &str = r#"{"source":"prip-d","match":"PRIP","extract":[{"regex":"host=(?P<h>\\w+)"}],"map":{"fields":{"prip_host":"$h"}}}"#;
    const SPEC_RIEN: &str = r#"{"source":"prip-d","match":"PRIP","extract":[{"regex":"zzz=(?P<z>\\w+)"}],"map":{"fields":{"prip_z":"$z"}}}"#;

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn parseur(conn: &Connection, name: &str, pat: &str) -> i64 {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES(?1,'prip-r',?2,1,100)", params![name, pat]).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, name: &str, spec: &str) -> i64 {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'prip-d',?2,1,0,0,100)", params![name, spec]).unwrap();
        conn.last_insert_rowid()
    }
    fn p(db: &str, k: &str) -> Option<String> { champ(&parsers_apply(db, "prip-r", MSG, None), k) }
    fn d(db: &str, k: &str) -> Option<String> { champ(&dparsers_apply(db, "prip-d", MSG, None).0, k) }

    #[test]
    fn prip_parser_autre_id_meme_nom_creation_supprime_pas_ressuscite() {
        let c = test_db();
        let db = ":memory:prip-p-autre-id";
        let id_b = parseur(&c, "Parser", r"host=(?P<prip_host>\w+)");
        parseur(&c, "prip-garde-haut", "zzz"); // rowid plus haut : C ne reprendra pas l'identifiant de B
        parsers_reload(&c, db);
        assert_eq!(p(db, "prip_host").as_deref(), Some("web1"));
        c.execute("DELETE FROM parser WHERE id=?1", params![id_b]).unwrap();
        let id_c = parseur(&c, "Parser", "x");
        assert_ne!(id_c, id_b, "précondition : autre identifiant");
        c.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![id_c]).unwrap();
        parsers_reload(&c, db);
        assert_eq!(p(db, "prip_host"), None, "la version de B ne revient pas sous l'identifiant de C (même nom, même création)");
    }

    #[test]
    fn prip_dparser_autre_id_meme_nom_creation_supprime_pas_ressuscite() {
        let c = test_db();
        let db = ":memory:prip-d-autre-id";
        let id_b = dparseur(&c, "Parser", SPEC_HOST);
        dparseur(&c, "prip-garde-haut", SPEC_RIEN);
        dparsers_reload(&c, db);
        assert_eq!(d(db, "prip_host").as_deref(), Some("web1"));
        c.execute("DELETE FROM dparser WHERE id=?1", params![id_b]).unwrap();
        let id_c = dparseur(&c, "Parser", SPEC_RIEN);
        assert_ne!(id_c, id_b, "précondition : autre identifiant");
        c.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![id_c]).unwrap();
        dparsers_reload(&c, db);
        assert_eq!(d(db, "prip_host"), None, "dparser : la version de B ne revient pas sous l'identifiant de C");
    }

    #[test]
    fn prip_parser_deux_regles_meme_nom_creation_chacune_sa_version() {
        let c = test_db();
        let db = ":memory:prip-p-deux";
        let x = parseur(&c, "Parser", r"user=(?P<prip_user>\w+)");
        let y = parseur(&c, "Parser", r"host=(?P<prip_host>\w+)");
        parsers_reload(&c, db);
        assert_eq!(p(db, "prip_user").as_deref(), Some("alice"));
        assert_eq!(p(db, "prip_host").as_deref(), Some("web1"));
        c.execute("UPDATE parser SET pattern=x'ff' WHERE id IN (?1, ?2)", params![x, y]).unwrap();
        parsers_reload(&c, db);
        assert_eq!(p(db, "prip_user").as_deref(), Some("alice"), "X garde SA version");
        assert_eq!(p(db, "prip_host").as_deref(), Some("web1"), "Y garde SA version");
    }

    #[test]
    fn prip_dparser_deux_regles_meme_nom_creation_chacune_sa_version() {
        let c = test_db();
        let db = ":memory:prip-d-deux";
        let x = dparseur(&c, "Parser", SPEC_USER);
        let y = dparseur(&c, "Parser", SPEC_HOST);
        dparsers_reload(&c, db);
        assert_eq!(d(db, "prip_user").as_deref(), Some("alice"));
        assert_eq!(d(db, "prip_host").as_deref(), Some("web1"));
        c.execute("UPDATE dparser SET spec=x'ff' WHERE id IN (?1, ?2)", params![x, y]).unwrap();
        dparsers_reload(&c, db);
        assert_eq!(d(db, "prip_user").as_deref(), Some("alice"), "dparser : X garde SA version");
        assert_eq!(d(db, "prip_host").as_deref(), Some("web1"), "dparser : Y garde SA version");
    }

    const SUITE_GARDE: &str = "— registre en place GARDÉ";
    const SUITE_PREMIER: &str = "— aucun registre en place : seuls les parseurs lus sont publiés";

    #[test]
    fn prip_parser_journal_preparation_ratee_suites() {
        let c = test_db();
        let a = ":memory:prip-p-journal-garde";
        parseur(&c, "prip-user", r"user=(?P<prip_user>\w+)");
        parsers_reload(&c, a);
        c.execute_batch("ALTER TABLE parser RENAME TO parser_hors").unwrap();
        parsers_reload(&c, a);
        let j = parseurs_journal_de(a);
        assert_eq!(j.len(), 1, "{j:?}");
        assert!(j[0].starts_with(&format!("[parser] lecture ratée du registre de parseurs de {a} : préparation ratée")), "{}", j[0]);
        assert!(j[0].ends_with(SUITE_GARDE), "registre en place : {}", j[0]);
        assert_eq!(p(a, "prip_user").as_deref(), Some("alice"), "et le registre est bien gardé");
        let b = ":memory:prip-p-journal-premier";
        parsers_reload(&c, b);
        let jb = parseurs_journal_de(b);
        assert_eq!(jb.len(), 1, "{jb:?}");
        assert!(jb[0].ends_with(SUITE_PREMIER), "premier chargement : {}", jb[0]);
    }

    #[test]
    fn prip_dparser_journal_preparation_ratee_suites() {
        let c = test_db();
        let a = ":memory:prip-d-journal-garde";
        dparseur(&c, "prip-d-user", SPEC_USER);
        dparsers_reload(&c, a);
        c.execute_batch("ALTER TABLE dparser RENAME TO dparser_hors").unwrap();
        dparsers_reload(&c, a);
        let j = parseurs_journal_de(a);
        assert_eq!(j.len(), 1, "{j:?}");
        assert!(j[0].starts_with(&format!("[dparser] lecture ratée du registre de parseurs de {a} : préparation ratée")), "{}", j[0]);
        assert!(j[0].ends_with(SUITE_GARDE), "registre en place : {}", j[0]);
        assert_eq!(d(a, "prip_user").as_deref(), Some("alice"), "et le registre est bien gardé");
        let b = ":memory:prip-d-journal-premier";
        dparsers_reload(&c, b);
        let jb = parseurs_journal_de(b);
        assert_eq!(jb.len(), 1, "{jb:?}");
        assert!(jb[0].ends_with(SUITE_PREMIER), "premier chargement : {}", jb[0]);
    }
}
