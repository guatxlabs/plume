// =====================================================================================
// `P10.20-b` (reste de la vague O : `parsers_reload`, `dparsers_reload`) — UN `enabled` DE TYPE INATTENDU NE
// RETIRE PLUS LE PARSEUR EN SILENCE.
//
// VU (re-mesuré sur d8239ceb) : `parsers.rs:35` et `parsers.rs:538` lisaient `… WHERE enabled=1`. La colonne
// est `enabled INTEGER NOT NULL DEFAULT 1` : l'affinité INTEGER laisse passer un blob, un texte non numérique,
// un réel non entier (posés par SQL direct ou corruption). Aucun n'égale 1 : le parseur sortait du registre,
// sans échec, ni compte, ni ligne de journal — une lecture ratée prise pour une absence.
// CHOIX (même parti que `regle_active`, processors.rs) : l'entier 0 éteint, l'entier 1 arme, toute autre valeur
// laisse le parseur ACTIF, est dite au journal (identifiant + NATURE de la cellule, jamais sa valeur) et comptée
// par base et par registre (`parseurs_enabled_inattendus_de`, lu en test seulement).
// Le jugement se fait dans la lecture, AVANT le plafond `DPARSER_MAX_TOTAL` et le décodage : une ligne éteinte
// n'est ni lue, ni un échec, ni au plafond ; une ligne inattendue que le plafond écarte n'est ni dite ni comptée.
// CE QUE LE COMPTE ET LA LIGNE DISENT (correction après vérification) : le compte décrit le registre EN VIGUEUR
// — les parseurs à `enabled` inattendu qu'il APPLIQUE, comptés après la compilation. La ligne ne dit « gardé
// ACTIF » que d'un parseur publié par CE rechargement ; un motif invalide, trop long ou une spec rejetée est dit
// « NON publié », pas compté. REGISTRE GARDÉ (lecture non attribuable — préparation ratée, ligne illisible au
// pas — avec un registre en place, qui reste en vigueur) : le compte n'est PAS touché (il décrit toujours le
// registre gardé), chaque inattendu lu est dit « registre en place GARDÉ : ce rechargement ne publie rien ».
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : FILTRE_SQL (`WHERE enabled=1` rétabli), ZERO_ARME
// (0 n'éteint plus), INATTENDU_AVANT_PLAFOND (compté avant le test du plafond), COMPTE_NON_INCREMENTE,
// VALEUR_AU_JOURNAL (valeur recopiée dans la ligne), JOURNAL_SAUTE (aucune ligne) ; puis, à la correction,
// M20 / M20P (dire placé après le retour du registre gardé, dparser / parser), GARDE_COMPTE (le registre gardé
// pose quand même le compte), GARDE_DIT_ACTIF (« gardé ACTIF » sur le registre gardé), PUBLIE_IGNORE (compté et
// dit ACTIF avant la compilation) ; puis, à la seconde correction, A21 / A22 (garde = lecture non attribuable
// seule, sans « registre en place », parser / dparser : un premier chargement avec une ligne illisible dirait
// « registre en place GARDÉ » d'un parseur pourtant publié, sans le compter), A41 (id lu avant `enabled`), A35
// (blob écrit au format `{:?}`) ; puis, à la troisième correction, M58 / M59 (`publie` forcé à faux sur la
// seule voie de REPLI sur la version gardée, parser / dparser) ; puis, à la quatrième correction, ME8 (le
// compte dparser écrit aussi sous la clé parser de la même base), ME8R (l'inverse) et MF1 (le lecteur ignore
// le registre) — chacun nommé sur ses témoins.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le compte n'est servi par aucune surface de production (ni API, ni
// console, ni /metrics) — seule la ligne de stderr en témoigne ; le WARN du plafond `DPARSER_MAX_TOTAL`
// lui-même (ligne de stderr) n'est lu par aucun de ces témoins : seuls sont tenus ce qui est publié et compté
// au plafond (une ligne éteinte n'entre pas dans les lignes lues, donc ne le déclenche pas).
// =====================================================================================
mod parseurs_enabled_de_type_inattendu_compte {
    use super::*;

    const MSG: &str = "PREI user=alice";
    const SPEC: &str = r#"{"source":"prei-d","match":"PREI","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"fields":{"prei_user":"$u"}}}"#;

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    /// Parseur dont la cellule `enabled` reçoit l'expression SQL `enabled_sql` (littéral posé tel quel).
    fn parseur(conn: &Connection, enabled_sql: &str) -> i64 {
        conn.execute(&format!("INSERT INTO parser(name,source,pattern,enabled,created) VALUES('prei','prei-r','user=(?P<prei_user>\\w+)',{enabled_sql},100)"), []).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, enabled_sql: &str) -> i64 {
        conn.execute(&format!("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-d','prei-d',?1,{enabled_sql},0,0,100)"), params![SPEC]).unwrap();
        conn.last_insert_rowid()
    }
    fn arme_p(db: &str) -> bool { champ(&parsers_apply(db, "prei-r", MSG, None), "prei_user").as_deref() == Some("alice") }
    fn arme_d(db: &str) -> bool { champ(&dparsers_apply(db, "prei-d", MSG, None).0, "prei_user").as_deref() == Some("alice") }
    fn type_de(conn: &Connection, table: &str, id: i64) -> String {
        conn.query_row(&format!("SELECT typeof(enabled) FROM {table} WHERE id=?1"), params![id], |r| r.get(0)).unwrap()
    }
    /// Recrée `table` sans `NOT NULL` sur `enabled` (schéma altéré) pour poser un NULL.
    fn sans_not_null(conn: &Connection, table: &str) {
        let col = if table == "parser" { "pattern" } else { "spec" };
        conn.execute_batch(&format!("DROP TABLE {table}; CREATE TABLE {table}(id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL DEFAULT '*', {col} TEXT NOT NULL, enabled INTEGER, builtin INTEGER NOT NULL DEFAULT 0, managed INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0);")).unwrap();
    }

    /// blob, texte, réel, entier 2 : le parseur reste ACTIF, une ligne par cellule, le compte = 4.
    /// Rouge sous FILTRE_SQL (parseur retiré, compte 0), COMPTE_NON_INCREMENTE, JOURNAL_SAUTE.
    #[test]
    fn prei_parser_types_inattendus_actifs_dits_et_comptes() {
        let db = ":memory:prei-p-types";
        for (lit, nature, typ) in [("x'01'", "blob", "blob"), ("'oui'", "texte", "text"), ("1.5", "réel", "real"), ("2", "entier autre que 0 ou 1", "integer")] {
            let c = test_db();
            c.execute("DELETE FROM parser", []).unwrap();
            let id = parseur(&c, lit);
            assert_eq!(type_de(&c, "parser", id), typ, "précondition : la cellule garde son type ({lit})");
            let avant = parseurs_journal_de(db).len();
            parsers_reload(&c, db);
            assert!(arme_p(db), "{lit} : le parseur reste ACTIF");
            assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1, "{lit} : compté");
            let j = parseurs_journal_de(db);
            assert_eq!(j.len(), avant + 1, "{lit} : une ligne : {j:?}");
            assert_eq!(j[avant], format!("[parser] enabled ni 0 ni 1 dans le registre de parseurs de {db} : id={id} ({nature}) -> parseur gardé ACTIF"));
        }
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        for lit in ["x'01'", "'oui'", "1.5", "2"] { parseur(&c, lit); }
        parsers_reload(&c, db);
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 4, "quatre cellules inattendues, quatre au compte");
        assert_eq!(parsers_cell().read().get(db).map(|l| l.len()), Some(4), "les quatre publiés");
    }

    /// Même jugement côté dparser. Rouge sous FILTRE_SQL, COMPTE_NON_INCREMENTE, JOURNAL_SAUTE.
    #[test]
    fn prei_dparser_types_inattendus_actifs_dits_et_comptes() {
        let db = ":memory:prei-d-types";
        for (lit, nature) in [("x'01'", "blob"), ("'oui'", "texte"), ("1.5", "réel")] {
            let c = test_db();
            let id = dparseur(&c, lit);
            let avant = parseurs_journal_de(db).len();
            dparsers_reload(&c, db);
            assert!(arme_d(db), "{lit} : le parseur déclaratif reste ACTIF");
            assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1, "{lit} : compté");
            let j = parseurs_journal_de(db);
            assert_eq!(j.len(), avant + 1, "{lit} : une ligne : {j:?}");
            assert_eq!(j[avant], format!("[dparser] enabled ni 0 ni 1 dans le registre de parseurs de {db} : id={id} ({nature}) -> parseur gardé ACTIF"));
        }
    }

    /// NULL (schéma altéré) : actif, dit, compté — dans les deux registres. Rouge sous FILTRE_SQL.
    #[test]
    fn prei_null_actif_dit_et_compte() {
        let (dp, dd) = (":memory:prei-null-p", ":memory:prei-null-d");
        let c = test_db();
        sans_not_null(&c, "parser");
        sans_not_null(&c, "dparser");
        let ip = parseur(&c, "NULL");
        let id = dparseur(&c, "NULL");
        parsers_reload(&c, dp);
        dparsers_reload(&c, dd);
        assert!(arme_p(dp) && arme_d(dd), "NULL : actif dans les deux registres");
        assert_eq!((parseurs_enabled_inattendus_de("parser", dp), parseurs_enabled_inattendus_de("dparser", dd)), (1, 1));
        assert_eq!(parseurs_journal_de(dp), vec![format!("[parser] enabled ni 0 ni 1 dans le registre de parseurs de {dp} : id={ip} (NULL) -> parseur gardé ACTIF")]);
        assert_eq!(parseurs_journal_de(dd), vec![format!("[dparser] enabled ni 0 ni 1 dans le registre de parseurs de {dd} : id={id} (NULL) -> parseur gardé ACTIF")]);
    }

    /// 0 éteint (rien publié, rien compté, aucune ligne — un motif PUBLIABLE comme une cellule illisible), 1 arme
    /// (rien compté). Rouge sous ZERO_ARME dès « 0 éteint » (le parseur publiable s'arme).
    #[test]
    fn prei_zero_eteint_un_arme_sans_compte() {
        let (dp, dd) = (":memory:prei-01-p", ":memory:prei-01-d");
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        parseur(&c, "0"); // motif et spec publiables : seul `enabled = 0` les tient hors du registre
        dparseur(&c, "0");
        let ip = parseur(&c, "0");
        let id = dparseur(&c, "0");
        // Une ligne éteinte n'est pas lue : sa cellule illisible n'est pas un échec (comme quand le SQL l'écartait).
        c.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![ip]).unwrap();
        c.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![id]).unwrap();
        parsers_reload(&c, dp);
        dparsers_reload(&c, dd);
        assert!(!arme_p(dp) && !arme_d(dd), "0 éteint");
        assert_eq!(parsers_cell().read().get(dp).map(|l| l.len()), Some(0));
        assert_eq!(dparsers_cell().read().get(dd).map(|l| l.len()), Some(0));
        assert_eq!((parseurs_enabled_inattendus_de("parser", dp), parseurs_enabled_inattendus_de("dparser", dd)), (0, 0));
        assert_eq!((parseurs_lectures_ratees_de("parser", dp), parseurs_lectures_ratees_de("dparser", dd)), (0, 0), "ligne éteinte : aucun échec");
        assert!(parseurs_journal_de(dp).is_empty() && parseurs_journal_de(dd).is_empty());
        let c1 = test_db();
        c1.execute("DELETE FROM parser", []).unwrap();
        parseur(&c1, "1");
        dparseur(&c1, "1");
        let (dp1, dd1) = (":memory:prei-1-p", ":memory:prei-1-d");
        parsers_reload(&c1, dp1);
        dparsers_reload(&c1, dd1);
        assert!(arme_p(dp1) && arme_d(dd1), "1 arme");
        assert_eq!((parseurs_enabled_inattendus_de("parser", dp1), parseurs_enabled_inattendus_de("dparser", dd1)), (0, 0));
        assert!(parseurs_journal_de(dp1).is_empty() && parseurs_journal_de(dd1).is_empty());
    }

    /// Deux bases : le compte de A ne fuit pas dans B, et une table réparée retombe à 0.
    /// Rouge sous COMPTE_NON_INCREMENTE.
    #[test]
    fn prei_compte_par_base() {
        let (a, b) = (":memory:prei-base-a", ":memory:prei-base-b");
        let (ca, cb) = (test_db(), test_db());
        ca.execute("DELETE FROM parser", []).unwrap();
        cb.execute("DELETE FROM parser", []).unwrap();
        let ia = parseur(&ca, "x'01'");
        parseur(&cb, "1");
        let ida = dparseur(&ca, "'oui'");
        dparseur(&cb, "1");
        parsers_reload(&ca, a);
        dparsers_reload(&ca, a);
        parsers_reload(&cb, b);
        dparsers_reload(&cb, b);
        assert_eq!((parseurs_enabled_inattendus_de("parser", a), parseurs_enabled_inattendus_de("dparser", a)), (1, 1));
        assert_eq!((parseurs_enabled_inattendus_de("parser", b), parseurs_enabled_inattendus_de("dparser", b)), (0, 0), "rien ne fuit dans B");
        assert!(parseurs_journal_de(b).is_empty(), "aucune ligne pour B : {:?}", parseurs_journal_de(b));
        ca.execute("UPDATE parser SET enabled=1 WHERE id=?1", params![ia]).unwrap();
        ca.execute("UPDATE dparser SET enabled=1 WHERE id=?1", params![ida]).unwrap();
        parsers_reload(&ca, a);
        dparsers_reload(&ca, a);
        assert_eq!((parseurs_enabled_inattendus_de("parser", a), parseurs_enabled_inattendus_de("dparser", a)), (0, 0), "table réparée : 0");
    }

    /// Plafond : DPARSER_MAX_TOTAL actifs puis une ligne inattendue -> écartée par le plafond, NON comptée ; des
    /// lignes éteintes intercalées ne prennent pas de place au plafond : le DERNIER actif (un parseur témoin
    /// distinguable) est publié. Rouge sous INATTENDU_AVANT_PLAFOND ; sous ZERO_ARME dès le parseur témoin.
    #[test]
    fn prei_dparser_plafond_ligne_ecartee_non_comptee() {
        let db = ":memory:prei-plafond";
        let c = test_db();
        for i in 0..DPARSER_MAX_TOTAL - 1 {
            if i % 2 == 0 { dparseur(&c, "0"); }
            dparseur(&c, "1");
        }
        let spec_t = r#"{"source":"prei-t","match":"PREI","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"fields":{"prei_t":"$u"}}}"#;
        c.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-t','prei-t',?1,1,0,0,100)", params![spec_t]).unwrap();
        let id_en_trop = dparseur(&c, "x'01'");
        dparsers_reload(&c, db);
        assert_eq!(champ(&dparsers_apply(db, "prei-t", MSG, None).0, "prei_t").as_deref(), Some("alice"),
            "les éteintes ne prennent pas de place : le dernier actif, au rang DPARSER_MAX_TOTAL, est publié");
        assert_eq!(dparsers_cell().read().get(db).map(|l| l.len()), Some(DPARSER_MAX_TOTAL));
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 0, "la ligne écartée par le plafond n'est pas comptée");
        assert!(parseurs_journal_de(db).is_empty(), "ni dite : {:?}", parseurs_journal_de(db));
        // Contrôle : sous le plafond, la même ligne est comptée.
        c.execute("DELETE FROM dparser WHERE id < ?1 AND enabled=1 AND source='prei-d' AND id % 3 = 0", params![id_en_trop]).unwrap();
        dparsers_reload(&c, db);
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1, "contrôle : sous le plafond, comptée");
    }

    /// La ligne de journal dit la NATURE, jamais la valeur (ni en texte, ni en octets : hexadécimal ou liste
    /// décimale `{:?}` d'un blob). Rouge sous VALEUR_AU_JOURNAL et A35 (blob écrit au format `{:?}`).
    #[test]
    fn prei_journal_sans_valeur() {
        let db = ":memory:prei-valeur";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        parseur(&c, "'PREI-SECRET'");
        dparseur(&c, "x'5052454953'");
        parsers_reload(&c, db);
        dparsers_reload(&c, db);
        let j = parseurs_journal_de(db);
        assert_eq!(j.len(), 2, "{j:?}");
        for l in &j {
            assert!(!l.contains("PREI-SECRET") && !l.contains("PREIS") && !l.contains("5052") && !l.contains("80, 82"), "valeur au journal : {l}");
        }
    }

    /// La ligne écrite sur le STDERR RÉEL (sous-processus, technique de `prmb_journal_d_un_echec_sur_le_stderr_reel`) :
    /// une ligne par registre pour un blob, aucune pour une base saine. Rouge sous JOURNAL_SAUTE.
    #[test]
    fn prei_journal_sur_le_stderr_reel() {
        const BASES_DE_L_ENFANT: &str = "PREI_STDERR_BASES_DE_L_ENFANT";
        if let Ok(prefixe) = std::env::var(BASES_DE_L_ENFANT) {
            let saine = test_db();
            parseur(&saine, "1");
            parsers_reload(&saine, &format!("{prefixe}-s"));
            let c = test_db();
            let ip = parseur(&c, "x'01'");
            let id = dparseur(&c, "x'01'");
            parsers_reload(&c, &format!("{prefixe}-p"));
            dparsers_reload(&c, &format!("{prefixe}-d"));
            println!("PREI-ENFANT-A-JOUE ip={ip} id={id}");
            return;
        }
        let prefixe = format!("prei-stderr-{}", std::process::id());
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1",
                "tests::parseurs_enabled_de_type_inattendu_compte::prei_journal_sur_le_stderr_reel"])
            .env(BASES_DE_L_ENFANT, &prefixe)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant a réussi\n{stdout}\n{stderr}");
        let marque = stdout.lines().find_map(|l| l.split_once("PREI-ENFANT-A-JOUE ").map(|(_, r)| r))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a VRAIMENT joué\n{stdout}\n{stderr}"));
        let ids: Vec<&str> = marque.split_whitespace().collect();
        let (ip, id) = (ids[0].trim_start_matches("ip="), ids[1].trim_start_matches("id="));
        let compter = |p: &str| stderr.lines().filter(|l| l.starts_with(p)).count();
        assert_eq!(compter(&format!("[parser] enabled ni 0 ni 1 dans le registre de parseurs de {prefixe}-p : id={ip} (blob) -> parseur gardé ACTIF")), 1, "{stderr}");
        assert_eq!(compter(&format!("[dparser] enabled ni 0 ni 1 dans le registre de parseurs de {prefixe}-d : id={id} (blob) -> parseur gardé ACTIF")), 1, "{stderr}");
        assert_eq!(compter(&format!("[parser] enabled ni 0 ni 1 dans le registre de parseurs de {prefixe}-s ")), 0, "{stderr}");
    }

    const LIGNE: &str = "enabled ni 0 ni 1";
    const GARDE: &str = "registre en place GARDÉ : ce rechargement ne publie rien";
    fn lignes_enabled_depuis(db: &str, avant: usize) -> Vec<String> {
        parseurs_journal_de(db).into_iter().skip(avant).filter(|l| l.contains(LIGNE)).collect()
    }
    fn zone_p(db: &str) -> Option<String> { champ(&parsers_apply(db, "prei-r", "PREI user=alice zone=z1", None), "prei_zone") }
    fn zone_d(db: &str) -> Option<String> { champ(&dparsers_apply(db, "prei-d", "PREI user=alice zone=z1", None).0, "prei_zone") }
    const SPEC_ZONE: &str = r#"{"source":"prei-d","match":"PREI","extract":[{"regex":"zone=(?P<z>\\w+)"}],"map":{"fields":{"prei_zone":"$z"}}}"#;

    /// REGISTRE GARDÉ (parser) : ligne illisible au pas avec un registre en place. Le registre gardé reste en
    /// vigueur : le compte n'est pas touché (1, celui du registre gardé, et non 2 = les inattendus lus), le
    /// parseur neuf n'est pas appliqué, et chaque inattendu lu est dit « registre en place GARDÉ », jamais
    /// « gardé ACTIF ». Réparée, la table publie les deux. Rouge sous M20P, GARDE_COMPTE, GARDE_DIT_ACTIF.
    #[test]
    fn prei_parser_registre_garde_ligne_illisible() {
        let db = ":memory:prei-garde-p";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        let ia = parseur(&c, "x'01'");
        c.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES('prei-casse','prei-r','host=(?P<prei_host>\\w+)',1,100)", []).unwrap();
        parsers_reload(&c, db);
        assert!(arme_p(db));
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1);
        c.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES('prei-neuf','prei-r','zone=(?P<prei_zone>\\w+)','oui',100)", []).unwrap();
        let ic = c.last_insert_rowid();
        c.execute_batch(
            "ALTER TABLE parser RENAME TO parser_reel; \
             CREATE VIEW parser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, pattern, enabled, created FROM parser_reel;",
        ).unwrap();
        let avant = parseurs_journal_de(db).len();
        parsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "précondition : ligne illisible au pas, registre gardé");
        assert!(arme_p(db), "registre gardé en vigueur");
        assert_eq!(zone_p(db), None, "le parseur neuf n'est pas appliqué par un rechargement gardé");
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1, "registre gardé : le compte décrit toujours le registre en vigueur");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (blob) -> {GARDE}"),
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={ic} (texte) -> {GARDE}"),
        ]);
        c.execute_batch("DROP VIEW parser; ALTER TABLE parser_reel RENAME TO parser;").unwrap();
        parsers_reload(&c, db);
        assert_eq!(zone_p(db).as_deref(), Some("z1"), "réparée : le parseur neuf est publié");
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 2, "réparée : deux inattendus appliqués");
    }

    /// REGISTRE GARDÉ (dparser) : même règle. Rouge sous M20 (le site que le vérificateur a déplacé),
    /// GARDE_COMPTE, GARDE_DIT_ACTIF.
    #[test]
    fn prei_dparser_registre_garde_ligne_illisible() {
        let db = ":memory:prei-garde-d";
        let c = test_db();
        let ia = dparseur(&c, "x'01'");
        c.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-casse','prei-d',?1,1,0,0,100)", params![SPEC]).unwrap();
        dparsers_reload(&c, db);
        assert!(arme_d(db));
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1);
        c.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-neuf','prei-d',?1,'oui',0,0,100)", params![SPEC_ZONE]).unwrap();
        let ic = c.last_insert_rowid();
        c.execute_batch(
            "ALTER TABLE dparser RENAME TO dparser_reel; \
             CREATE VIEW dparser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, spec, enabled, created FROM dparser_reel;",
        ).unwrap();
        let avant = parseurs_journal_de(db).len();
        dparsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1, "précondition : ligne illisible au pas, registre gardé");
        assert!(arme_d(db), "registre gardé en vigueur");
        assert_eq!(zone_d(db), None, "le parseur neuf n'est pas appliqué par un rechargement gardé");
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1, "registre gardé : le compte décrit toujours le registre en vigueur");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (blob) -> {GARDE}"),
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={ic} (texte) -> {GARDE}"),
        ]);
        c.execute_batch("DROP VIEW dparser; ALTER TABLE dparser_reel RENAME TO dparser;").unwrap();
        dparsers_reload(&c, db);
        assert_eq!(zone_d(db).as_deref(), Some("z1"), "réparée : le parseur neuf est publié");
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 2, "réparée : deux inattendus appliqués");
    }

    /// REGISTRE GARDÉ par préparation ratée, dans les deux registres : rien n'est lu, le compte du registre gardé
    /// reste (1, et non 0 « rien lu »). Rouge sous GARDE_COMPTE. (Aucune assertion « aucune ligne `enabled` » :
    /// une préparation ratée ne lit aucune ligne, elle serait vraie par construction.)
    #[test]
    fn prei_preparation_ratee_compte_du_registre_garde_intact() {
        let db = ":memory:prei-garde-prep";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        parseur(&c, "x'01'");
        dparseur(&c, "'oui'");
        parsers_reload(&c, db);
        dparsers_reload(&c, db);
        assert_eq!((parseurs_enabled_inattendus_de("parser", db), parseurs_enabled_inattendus_de("dparser", db)), (1, 1));
        c.execute_batch("ALTER TABLE parser RENAME TO parser_hors_d_atteinte; ALTER TABLE dparser RENAME TO dparser_hors_d_atteinte;").unwrap();
        parsers_reload(&c, db);
        dparsers_reload(&c, db);
        assert_eq!((parseurs_lectures_ratees_de("parser", db), parseurs_lectures_ratees_de("dparser", db)), (1, 1), "précondition : préparation ratée");
        assert!(arme_p(db) && arme_d(db), "registres gardés en vigueur");
        assert_eq!((parseurs_enabled_inattendus_de("parser", db), parseurs_enabled_inattendus_de("dparser", db)), (1, 1),
            "registre gardé : le compte décrit toujours le registre en vigueur");
    }

    /// Lu mais NON publié (motif invalide, motif de plus de 1000 caractères, spec JSON invalide) : dit « NON
    /// publié », jamais « gardé ACTIF », et pas compté. Rouge sous PUBLIE_IGNORE.
    #[test]
    fn prei_inattendu_non_publie_dit_et_non_compte() {
        let db = ":memory:prei-non-publie";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        let i1 = parseur(&c, "x'01'");
        c.execute("UPDATE parser SET pattern='(' WHERE id=?1", params![i1]).unwrap();
        let i2 = parseur(&c, "'oui'");
        c.execute("UPDATE parser SET pattern=?2 WHERE id=?1", params![i2, "a".repeat(1001)]).unwrap();
        let id = dparseur(&c, "x'01'");
        c.execute("UPDATE dparser SET spec='{pas du json' WHERE id=?1", params![id]).unwrap();
        parsers_reload(&c, db);
        dparsers_reload(&c, db);
        assert_eq!(parsers_cell().read().get(db).map(|l| l.len()), Some(0), "précondition : aucun parseur publié");
        assert_eq!(dparsers_cell().read().get(db).map(|l| l.len()), Some(0), "précondition : aucun parseur déclaratif publié");
        assert_eq!((parseurs_enabled_inattendus_de("parser", db), parseurs_enabled_inattendus_de("dparser", db)), (0, 0), "non publié : non compté");
        let np = "parseur NON publié (motif ou spec rejeté, ou cellule illisible sans version gardée)";
        assert_eq!(lignes_enabled_depuis(db, 0), vec![
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={i1} (blob) -> {np}"),
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={i2} (texte) -> {np}"),
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={id} (blob) -> {np}"),
        ]);
    }

    /// AUCUN REGISTRE EN PLACE (premier chargement de la base) et ligne illisible au pas (parser) : rien n'est
    /// gardé, les parseurs lus SONT publiés — le parseur à `enabled` inattendu est dit « gardé ACTIF » et compté,
    /// jamais « registre en place GARDÉ ». Rouge sous A21 (garde = lecture non attribuable seule).
    #[test]
    fn prei_parser_jamais_charge_ligne_illisible() {
        let db = ":memory:prei-jamais-p";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        let ia = parseur(&c, "x'01'");
        c.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES('prei-casse','prei-r','host=(?P<prei_host>\\w+)',1,100)", []).unwrap();
        c.execute_batch(
            "ALTER TABLE parser RENAME TO parser_reel; \
             CREATE VIEW parser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, pattern, enabled, created FROM parser_reel;",
        ).unwrap();
        assert!(!parsers_cell().read().contains_key(db), "précondition : aucun registre en place");
        parsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "précondition : ligne illisible au pas");
        assert!(arme_p(db), "aucun registre gardé : le parseur lu est publié");
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1, "publié : compté");
        assert_eq!(lignes_enabled_depuis(db, 0), vec![
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (blob) -> parseur gardé ACTIF"),
        ]);
    }

    /// Même règle côté dparser. Rouge sous A22.
    #[test]
    fn prei_dparser_jamais_charge_ligne_illisible() {
        let db = ":memory:prei-jamais-d";
        let c = test_db();
        let ia = dparseur(&c, "x'01'");
        c.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-casse','prei-d',?1,1,0,0,100)", params![SPEC_ZONE]).unwrap();
        c.execute_batch(
            "ALTER TABLE dparser RENAME TO dparser_reel; \
             CREATE VIEW dparser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, spec, enabled, created FROM dparser_reel;",
        ).unwrap();
        assert!(!dparsers_cell().read().contains_key(db), "précondition : aucun registre en place");
        dparsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1, "précondition : ligne illisible au pas");
        assert!(arme_d(db), "aucun registre gardé : le parseur lu est publié");
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1, "publié : compté");
        assert_eq!(lignes_enabled_depuis(db, 0), vec![
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (blob) -> parseur gardé ACTIF"),
        ]);
    }

    /// `enabled` jugé AVANT l'identifiant aussi : une ligne éteinte dont l'id ne se lit pas (seulement à travers
    /// une vue — en production `id` est l'alias du rowid) n'est ni lue ni un échec, dans les deux registres.
    /// Rouge sous A41 (id lu avant `enabled`).
    #[test]
    fn prei_ligne_eteinte_id_illisible_pas_un_echec() {
        let (dp, dd) = (":memory:prei-eteinte-id-p", ":memory:prei-eteinte-id-d");
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        parseur(&c, "1");
        dparseur(&c, "1");
        c.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES('prei-casse','prei-r','host=(?P<prei_host>\\w+)',0,100)", []).unwrap();
        c.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES('prei-casse','prei-d',?1,0,0,0,100)", params![SPEC_ZONE]).unwrap();
        c.execute_batch(
            "ALTER TABLE parser RENAME TO parser_reel; \
             CREATE VIEW parser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, pattern, enabled, created FROM parser_reel; \
             ALTER TABLE dparser RENAME TO dparser_reel; \
             CREATE VIEW dparser AS SELECT CASE WHEN name='prei-casse' THEN 'pas-un-entier' ELSE id END AS id, name, source, spec, enabled, created FROM dparser_reel;",
        ).unwrap();
        parsers_reload(&c, dp);
        dparsers_reload(&c, dd);
        assert_eq!((parseurs_lectures_ratees_de("parser", dp), parseurs_lectures_ratees_de("dparser", dd)), (0, 0), "ligne éteinte : aucun échec");
        assert!(arme_p(dp) && arme_d(dd), "contrôle : la ligne active est publiée");
        assert!(parseurs_journal_de(dp).is_empty() && parseurs_journal_de(dd).is_empty());
    }

    /// REPLI SUR LA VERSION GARDÉE (parser) : `enabled` inattendu, motif devenu illisible APRÈS un premier
    /// chargement, identité (nom, création) inchangée : la version gardée est republiée, donc le parseur est
    /// APPLIQUÉ — dit « gardé ACTIF » et compté (1, et non 0). Contrôle inverse : la même cellule illisible avec
    /// un nom changé (identité non confirmée) ne republie rien — dit « NON publié », compte 0. Rouge sous M58
    /// (`publie` forcé à faux sur la seule voie de repli : compte 0, ligne « NON publié » d'un parseur appliqué).
    #[test]
    fn prei_parser_repli_version_gardee_publie_dit_actif_et_compte() {
        let db = ":memory:prei-repli-p";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        let ia = parseur(&c, "'oui'");
        parsers_reload(&c, db);
        assert!(arme_p(db));
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1);
        c.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![ia]).unwrap();
        let avant = parseurs_journal_de(db).len();
        parsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1, "précondition : motif illisible, ligne attribuée");
        assert!(arme_p(db), "précondition : version gardée republiée, parseur appliqué");
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 1, "repli publié : compté");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (texte) -> parseur gardé ACTIF"),
        ]);
        c.execute("UPDATE parser SET name='prei-autre' WHERE id=?1", params![ia]).unwrap();
        let avant = parseurs_journal_de(db).len();
        parsers_reload(&c, db);
        assert!(!arme_p(db), "contrôle : identité non confirmée, rien de republié");
        assert_eq!(parseurs_enabled_inattendus_de("parser", db), 0, "contrôle : non publié, non compté");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[parser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (texte) -> parseur NON publié (motif ou spec rejeté, ou cellule illisible sans version gardée)"),
        ]);
    }

    /// REPLI SUR LA VERSION GARDÉE (dparser) : même règle, spec devenue illisible. Rouge sous M59.
    #[test]
    fn prei_dparser_repli_version_gardee_publie_dit_actif_et_compte() {
        let db = ":memory:prei-repli-d";
        let c = test_db();
        let ia = dparseur(&c, "'oui'");
        dparsers_reload(&c, db);
        assert!(arme_d(db));
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1);
        c.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![ia]).unwrap();
        let avant = parseurs_journal_de(db).len();
        dparsers_reload(&c, db);
        assert_eq!(parseurs_lectures_ratees_de("dparser", db), 1, "précondition : spec illisible, ligne attribuée");
        assert!(arme_d(db), "précondition : version gardée republiée, parseur appliqué");
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 1, "repli publié : compté");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (texte) -> parseur gardé ACTIF"),
        ]);
        c.execute("UPDATE dparser SET name='prei-autre' WHERE id=?1", params![ia]).unwrap();
        let avant = parseurs_journal_de(db).len();
        dparsers_reload(&c, db);
        assert!(!arme_d(db), "contrôle : identité non confirmée, rien de republié");
        assert_eq!(parseurs_enabled_inattendus_de("dparser", db), 0, "contrôle : non publié, non compté");
        assert_eq!(lignes_enabled_depuis(db, avant), vec![
            format!("[dparser] {LIGNE} dans le registre de parseurs de {db} : id={ia} (texte) -> parseur NON publié (motif ou spec rejeté, ou cellule illisible sans version gardée)"),
        ]);
    }

    /// COMPTE PAR REGISTRE sur UNE MÊME base : deux parseurs à `enabled` inattendu côté parser, un côté dparser,
    /// même `db_path` : (2, 1), quel que soit l'ordre des rechargements ; dparser réparé : (2, 0) sans toucher
    /// parser. Rouge sous ME8 (le compte dparser écrit aussi sous la clé parser : (1, 1)), ME8R (l'inverse :
    /// (2, 2)) et MF1 (lecteur qui ignore le registre).
    #[test]
    fn prei_compte_par_registre_sur_une_meme_base() {
        let db = ":memory:prei-registres-meme-base";
        let c = test_db();
        c.execute("DELETE FROM parser", []).unwrap();
        parseur(&c, "x'01'");
        parseur(&c, "'oui'");
        let id = dparseur(&c, "1.5");
        let compte = || (parseurs_enabled_inattendus_de("parser", db), parseurs_enabled_inattendus_de("dparser", db));
        parsers_reload(&c, db);
        dparsers_reload(&c, db);
        assert_eq!(compte(), (2, 1), "parser puis dparser : chaque registre son compte");
        dparsers_reload(&c, db);
        parsers_reload(&c, db);
        assert_eq!(compte(), (2, 1), "dparser puis parser : chaque registre son compte");
        c.execute("UPDATE dparser SET enabled=1 WHERE id=?1", params![id]).unwrap();
        dparsers_reload(&c, db);
        assert_eq!(compte(), (2, 0), "dparser réparé : 0 de son côté, parser intact");
        assert!(arme_p(db) && arme_d(db), "contrôle : les deux registres appliqués");
    }
}
