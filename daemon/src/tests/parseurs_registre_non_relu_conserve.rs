// =====================================================================================
// `P10.20-b` (reste hors handlers/ : `parsers_reload`, `dparsers_reload`) — UNE LECTURE RATÉE DU REGISTRE
// DE PARSEURS NE REMPLACE PLUS LE REGISTRE EN PLACE.
//
// VU (80ad700a) : les deux rechargements lisaient par `if let Ok(prepare)` / `if let Ok(query_map)` /
// `rows.flatten()` puis `insert` inconditionnel : une préparation ratée publiait un registre VIDE à la place
// de l'actif, une ligne illisible (motif ou spec stocké en blob) sautait son parseur, sans journal ni compte.
// Les règles de détection lisent les champs extraits : la détection s'éteignait sans bruit.
//
// TENU ICI, sur les deux registres :
// - cellule illisible avec registre en place -> la dernière version compilée de CE parseur reste appliquée à
//   l'ingestion, un parseur sain ajouté entre-temps l'est aussi (union par identifiant, pas conservation
//   aveugle), et l'échec est compté exactement une fois sur SA base ;
// - préparation ratée -> registre en place gardé, échec compté ;
// - lecture réussie de zéro ligne -> registre vide, aucun compte.
// - cellule TOUJOURS illisible sur trois rechargements -> la version gardée l'est encore au troisième (le
//   mémo est reporté dans le bras de repli, pas seulement dans le bras nominal) ;
// - ligne illisible au PAS (identifiant non lu : vue `parser` dont l'id vaut du texte, forme de la liste
//   tronquée P10.7-f) -> registre en place gardé entier, échec compté ;
// - source illisible -> comptée, dernière version gardée ;
// - le compte est PAR BASE : une autre base rechargée sans échec reste à zéro.
// - parseur SUPPRIMÉ ou DÉSACTIVÉ pendant que la cellule d'un AUTRE parseur est illisible -> il n'est pas
//   republié depuis le mémo (le repli ne vaut que pour l'identifiant dont une cellule est illisible) ;
// - deux échecs dans un même rechargement -> comptés deux ;
// - ligne illisible au pas sans registre en place (premier chargement) -> les parseurs lus sont publiés.
// (Le repli conditionné à l'IDENTITÉ de la règle et le mémo qui lâche un parseur supprimé ou désactivé sont
// tenus par `parseurs_registre_identite_confirmee.rs`.)
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : PARSERS_FLATTEN et DPARSERS_FLATTEN (ligne illisible
// sautée, forme d'avant) rougissent `*_cellule_illisible_*` ; PARSERS_VIDE_SUR_ERR et DPARSERS_VIDE_SUR_ERR
// (registre vide publié sur préparation ratée) rougissent `*_preparation_ratee_*` ; PR_MEMO_REPLI et
// DR_MEMO_REPLI (mémo non reporté au repli) rougissent `*_trois_rechargements` ; LR_ROW_NA (ligne illisible
// non marquée non attribuable) et LR_ROW_ECHEC (non comptée) rougissent `prnr_parser_ligne_illisible_au_pas_*` ;
// LR_SRC (source illisible non comptée) rougit `prnr_parser_source_illisible_comptee` ; LC_BASE (compteur
// qui ignore la base) rougit `prnr_compteur_par_base` ; PR_UNION_LARGE et DR_UNION_LARGE (tout le mémo précédent
// non relu republié dès qu'un échec survient) rougissent `*_supprime_ou_desactive_*` ; DE_PAR_RECHARGE (un
// seul échec compté par rechargement) rougit `prnr_parser_deux_echecs_un_rechargement_comptes_deux` ;
// PR_ENPLACE_VRAI et DR_ENPLACE_VRAI (registre réputé en place au premier chargement) rougissent
// `*_ligne_illisible_au_pas_sans_registre_publie_les_lus`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'erreur de pas n'est fabriquée que par une vue (type d'identifiant),
// pas par une corruption disque réelle ; le bras « exécution ratée » (query_map) n'est pas fabriqué ; le
// compteur n'est pas servi par `/metrics` ni lu par aucun code de production (son lecteur est `#[cfg(test)]`), et la ligne de journal
// (`dire_les_echecs`, seule trace en production) est tenue par `parseurs_registre_memo_par_base.rs`, pas ici ; le mode multi-tenant n'est pas joué (clé par db_path seulement) ;
// un redémarrage sur une base à ligne illisible n'a aucune version à garder et publie les seuls parseurs lus
// (compté) : le parseur illisible est absent jusqu'à réparation de sa ligne.
// =====================================================================================
mod parseurs_registre_non_relu_conserve {
    use super::*;

    const SPEC_D: &str = r#"{"source":"prnr-d","match":"PRNR","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"category":"firewall","fields":{"prnr_user":"$u"}}}"#;
    const SPEC_D2: &str = r#"{"source":"prnr-d","match":"PRNR","extract":[{"regex":"host=(?P<h>\\w+)"}],"map":{"fields":{"prnr_host":"$h"}}}"#;
    const SPEC_D3: &str = r#"{"source":"prnr-d","match":"PRNR","extract":[{"regex":"(?P<m>PRNR)"}],"map":{"fields":{"prnr_mot":"$m"}}}"#;
    const MSG: &str = "PRNR user=alice host=web1";

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn regex_champ(db: &str, k: &str) -> Option<String> {
        champ(&parsers_apply(db, "prnr-r", MSG, None), k)
    }
    fn d_champ(db: &str, k: &str) -> Option<String> {
        champ(&dparsers_apply(db, "prnr-d", MSG, None).0, k)
    }
    fn parseur(conn: &Connection, name: &str, pattern: &str) {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled) VALUES(?1,'prnr-r',?2,1)", params![name, pattern]).unwrap();
    }
    fn dparseur(conn: &Connection, name: &str, spec: &str) {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'prnr-d',?2,1,0,0,0)", params![name, spec]).unwrap();
    }

    #[test]
    fn prnr_parser_cellule_illisible_reste_applique() {
        let conn = test_db();
        let db = ":memory:prnr-parser-blob";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "nominal : parseur appliqué");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 0, "nominal : aucun échec compté");
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE name='prnr-user'", []).unwrap();
        parseur(&conn, "prnr-host", r"host=(?P<prnr_host>\w+)");
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "motif illisible : la dernière version du parseur reste appliquée à l'ingestion");
        assert_eq!(regex_champ(db, "prnr_host").as_deref(), Some("web1"), "union : le parseur sain ajouté est publié");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "l'échec est compté une fois sur SA base");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 0, "et pas sur l'autre registre");
    }

    #[test]
    fn prnr_parser_preparation_ratee_garde_le_registre() {
        let conn = test_db();
        let db = ":memory:prnr-parser-prep";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, db);
        conn.execute_batch("ALTER TABLE parser RENAME TO parser_hors_d_atteinte").unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "préparation ratée : registre en place gardé");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "préparation ratée comptée");
    }

    #[test]
    fn prnr_parser_zero_ligne_vide_le_registre() {
        let conn = test_db();
        let db = ":memory:prnr-parser-vide";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, db);
        conn.execute("UPDATE parser SET enabled=0", []).unwrap();
        parsers_reload(&conn, db);
        assert!(parsers_cell().read().get(db).map(|l| l.is_empty()).unwrap_or(false), "zéro ligne lue : registre vide publié");
        assert_eq!(regex_champ(db, "prnr_user"), None);
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 0, "zéro ligne n'est pas un échec");
    }

    #[test]
    fn prnr_dparser_cellule_illisible_reste_applique() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-blob";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"), "nominal : parseur déclaratif appliqué");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 0);
        conn.execute("UPDATE dparser SET spec=x'ff' WHERE name='prnr-d-user'", []).unwrap();
        dparseur(&conn, "prnr-d-host", SPEC_D2);
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"), "spec illisible : la dernière version compilée reste appliquée");
        assert_eq!(d_champ(db, "prnr_host").as_deref(), Some("web1"), "union : le parseur sain ajouté est publié");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1, "l'échec est compté une fois sur SA base");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 0);
    }

    #[test]
    fn prnr_dparser_preparation_ratee_garde_le_registre() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-prep";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparsers_reload(&conn, db);
        conn.execute_batch("ALTER TABLE dparser RENAME TO dparser_hors_d_atteinte").unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"), "préparation ratée : registre en place gardé");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1);
    }

    #[test]
    fn prnr_dparser_zero_ligne_vide_le_registre() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-vide";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparsers_reload(&conn, db);
        conn.execute("UPDATE dparser SET enabled=0", []).unwrap();
        dparsers_reload(&conn, db);
        assert!(dparsers_cell().read().get(db).map(|l| l.is_empty()).unwrap_or(false), "zéro ligne lue : registre vide publié");
        assert_eq!(d_champ(db, "prnr_user"), None);
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 0);
    }

    #[test]
    fn prnr_parser_cellule_illisible_persistante_trois_rechargements() {
        let conn = test_db();
        let db = ":memory:prnr-parser-trois";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, db);
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE name='prnr-user'", []).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "2e rechargement : version gardée");
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "3e rechargement, motif toujours illisible : version encore gardée");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 2, "un échec par rechargement raté");
    }

    #[test]
    fn prnr_dparser_cellule_illisible_persistante_trois_rechargements() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-trois";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparsers_reload(&conn, db);
        conn.execute("UPDATE dparser SET spec=x'ff' WHERE name='prnr-d-user'", []).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"), "2e rechargement : version gardée");
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"), "3e rechargement, spec toujours illisible : version encore gardée");
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 2);
    }

    #[test]
    fn prnr_parser_ligne_illisible_au_pas_garde_le_registre() {
        let conn = test_db();
        let db = ":memory:prnr-parser-pas";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parseur(&conn, "prnr-host", r"host=(?P<prnr_host>\w+)");
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"));
        // L'identifiant de `prnr-user` n'est plus lisible en entier : l'erreur sort au PAS, aucun id ne la situe.
        conn.execute_batch(
            "ALTER TABLE parser RENAME TO parser_reel; \
             CREATE VIEW parser AS SELECT CASE WHEN name='prnr-user' THEN 'pas-un-entier' ELSE id END AS id, name, source, pattern, enabled, created FROM parser_reel;",
        ).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "ligne sans identifiant lu : registre en place gardé entier");
        assert_eq!(regex_champ(db, "prnr_host").as_deref(), Some("web1"));
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "ligne illisible comptée");
    }

    #[test]
    fn prnr_parser_source_illisible_comptee() {
        let conn = test_db();
        let db = ":memory:prnr-parser-src";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, db);
        conn.execute("UPDATE parser SET source=x'ff' WHERE name='prnr-user'", []).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"), "source illisible : dernière version gardée");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "source illisible comptée");
    }

    #[test]
    fn prnr_compteur_par_base() {
        let conn = test_db();
        let a = ":memory:prnr-base-a";
        let b = ":memory:prnr-base-b";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parsers_reload(&conn, a);
        parsers_reload(&conn, b);
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE name='prnr-user'", []).unwrap();
        parsers_reload(&conn, a);
        assert_eq!(parseurs_lectures_ratees_de("parser", a), 1, "échec compté sur SA base");
        assert_eq!(parseurs_lectures_ratees_de("parser", b), 0, "la base saine ne bouge pas");
    }

    #[test]
    fn prnr_parser_supprime_ou_desactive_pendant_un_echec_n_est_pas_republie() {
        let conn = test_db();
        let db = ":memory:prnr-parser-absent";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parseur(&conn, "prnr-mot", r"(?P<prnr_mot>PRNR)");
        parseur(&conn, "prnr-host", r"host=(?P<prnr_host>\w+)");
        parsers_reload(&conn, db);
        let publies_avant = parsers_cell().read().get(db).map(|l| l.len()).unwrap_or(0);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"));
        assert_eq!(regex_champ(db, "prnr_mot").as_deref(), Some("PRNR"));
        // La cellule de `prnr-host` devient illisible ; dans le même temps `prnr-user` est supprimé et
        // `prnr-mot` désactivé : deux absences ÉTABLIES par une lecture réussie de leur état.
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE name='prnr-host'", []).unwrap();
        conn.execute("DELETE FROM parser WHERE name='prnr-user'", []).unwrap();
        conn.execute("UPDATE parser SET enabled=0 WHERE name='prnr-mot'", []).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_host").as_deref(), Some("web1"), "cellule illisible : dernière version de CE parseur gardée");
        assert_eq!(regex_champ(db, "prnr_user"), None, "parseur supprimé : pas republié depuis le mémo");
        assert_eq!(regex_champ(db, "prnr_mot"), None, "parseur désactivé : pas republié depuis le mémo");
        assert_eq!(parsers_cell().read().get(db).map(|l| l.len()), Some(publies_avant - 2), "registre publié : exactement les deux absents en moins");
        // Rechargement suivant : toujours absents. Cette assertion ne prouve PAS que le mémo les a lâchés (le repli
        // ne consulte que les identifiants relus) : c'est `parseurs_registre_identite_confirmee.rs` qui le tient.
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user"), None, "rechargement suivant : toujours absent");
        assert_eq!(regex_champ(db, "prnr_mot"), None, "rechargement suivant : toujours absent");
    }

    #[test]
    fn prnr_dparser_supprime_ou_desactive_pendant_un_echec_n_est_pas_republie() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-absent";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparseur(&conn, "prnr-d-mot", SPEC_D3);
        dparseur(&conn, "prnr-d-host", SPEC_D2);
        dparsers_reload(&conn, db);
        let publies_avant = dparsers_cell().read().get(db).map(|l| l.len()).unwrap_or(0);
        assert_eq!(d_champ(db, "prnr_user").as_deref(), Some("alice"));
        assert_eq!(d_champ(db, "prnr_mot").as_deref(), Some("PRNR"));
        conn.execute("UPDATE dparser SET spec=x'ff' WHERE name='prnr-d-host'", []).unwrap();
        conn.execute("DELETE FROM dparser WHERE name='prnr-d-user'", []).unwrap();
        conn.execute("UPDATE dparser SET enabled=0 WHERE name='prnr-d-mot'", []).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_host").as_deref(), Some("web1"), "spec illisible : dernière version de CE parseur gardée");
        assert_eq!(d_champ(db, "prnr_user"), None, "parseur déclaratif supprimé : pas republié depuis le mémo");
        assert_eq!(d_champ(db, "prnr_mot"), None, "parseur déclaratif désactivé : pas republié depuis le mémo");
        assert_eq!(dparsers_cell().read().get(db).map(|l| l.len()), Some(publies_avant - 2), "registre publié : exactement les deux absents en moins");
        // Même portée que pour `parser` : le mémo lâché est tenu par `parseurs_registre_identite_confirmee.rs`.
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_user"), None, "rechargement suivant : toujours absent");
        assert_eq!(d_champ(db, "prnr_mot"), None, "rechargement suivant : toujours absent");
    }

    #[test]
    fn prnr_parser_deux_echecs_un_rechargement_comptes_deux() {
        let conn = test_db();
        let db = ":memory:prnr-parser-deux";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parseur(&conn, "prnr-host", r"host=(?P<prnr_host>\w+)");
        parsers_reload(&conn, db);
        conn.execute("UPDATE parser SET pattern=x'ff' WHERE source='prnr-r'", []).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_user").as_deref(), Some("alice"));
        assert_eq!(regex_champ(db, "prnr_host").as_deref(), Some("web1"));
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 2, "deux cellules illisibles dans UN rechargement : deux échecs comptés");
    }

    #[test]
    fn prnr_parser_ligne_illisible_au_pas_sans_registre_publie_les_lus() {
        let conn = test_db();
        let db = ":memory:prnr-parser-pas-premier";
        parseur(&conn, "prnr-user", r"user=(?P<prnr_user>\w+)");
        parseur(&conn, "prnr-host", r"host=(?P<prnr_host>\w+)");
        conn.execute_batch(
            "ALTER TABLE parser RENAME TO parser_reel; \
             CREATE VIEW parser AS SELECT CASE WHEN name='prnr-user' THEN 'pas-un-entier' ELSE id END AS id, name, source, pattern, enabled, created FROM parser_reel;",
        ).unwrap();
        parsers_reload(&conn, db);
        assert_eq!(regex_champ(db, "prnr_host").as_deref(), Some("web1"), "aucun registre en place : les parseurs lus sont publiés");
        assert_eq!(regex_champ(db, "prnr_user"), None, "le parseur illisible n'a aucune version à garder");
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1);
    }

    #[test]
    fn prnr_dparser_ligne_illisible_au_pas_sans_registre_publie_les_lus() {
        let conn = test_db();
        let db = ":memory:prnr-dparser-pas-premier";
        dparseur(&conn, "prnr-d-user", SPEC_D);
        dparseur(&conn, "prnr-d-host", SPEC_D2);
        conn.execute_batch(
            "ALTER TABLE dparser RENAME TO dparser_reel; \
             CREATE VIEW dparser AS SELECT CASE WHEN name='prnr-d-user' THEN 'pas-un-entier' ELSE id END AS id, name, source, spec, enabled, created FROM dparser_reel;",
        ).unwrap();
        dparsers_reload(&conn, db);
        assert_eq!(d_champ(db, "prnr_host").as_deref(), Some("web1"), "aucun registre en place : les parseurs lus sont publiés");
        assert_eq!(d_champ(db, "prnr_user"), None);
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1);
    }
}
