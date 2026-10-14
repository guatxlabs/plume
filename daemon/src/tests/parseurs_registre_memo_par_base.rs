// =====================================================================================
// `P10.20-b` (suite : `parsers_reload`, `dparsers_reload`) — LE MÉMO DES VERSIONS GARDÉES EST SÉPARÉ PAR BASE,
// LE PLAFOND DES PARSEURS DÉCLARATIFS TIENT, ET LA LIGNE DE JOURNAL D'UN ÉCHEC EST ÉCRITE.
//
// VU (vérification indépendante de la reprise) :
// - le mémo `PARSERS_PAR_ID` / `DPARSERS_PAR_ID` est rangé sous `db_path`, mais une mutation qui range tout
//   sous une seule clé (`""`, en lecture et en écriture) laissait verts les 35 témoins du lot et les 49 tests
//   parser/dparser : aucun témoin n'avait DEUX bases. Effet de ce mutant : la base A republie la version
//   compilée de la base B quand les deux ont le même (id, nom, création), ou perd la sienne dès que B recharge ;
// - le plafond `DPARSER_MAX_TOTAL` de `dparsers_reload` (test déplacé dans la boucle réécrite) n'avait aucun
//   témoin, avant le lot comme après ;
// - la ligne de journal de `dire_les_echecs`, seule trace d'un échec en production, n'avait aucun témoin.
//   Elle passe désormais par `journaliser_l_echec`, qui sous `cfg(test)` seulement retient la ligne par base
//   (`parseurs_journal_de`) ; le binaire de production n'y gagne ni stockage ni surface.
//
// TENU ICI : deux bases, même (id, nom, création), motifs différents -> la version gardée de A est celle de A
// (parser et dparser) ; deux bases, même id, autre nom dans B -> A garde sa version après le rechargement de B
// (parser et dparser) ; DPARSER_MAX_TOTAL + 1 parseurs déclaratifs -> DPARSER_MAX_TOTAL publiés ; une cellule
// illisible -> une ligne de journal par échec, nommant registre, base, identifiant et suite donnée ; un
// rechargement sans échec -> aucune ligne.
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) : PR_MEMO_SANS_BASE et DR_MEMO_SANS_BASE (clé du mémo
// `""` au lieu de `db_path`) rougissent `prmb_*_memo_*` ; DR_PLAFOND_OTE (test du plafond retiré) rougit
// `prmb_dparser_plafond_tenu` ; DE_JOURNAL (appel de `journaliser_l_echec` sauté) rougit `prmb_*_journal_*`.
//
// REPRISE (vérification suivante) : l'`eprintln!` de `journaliser_l_echec` n'avait pas de témoin, et la raison
// donnée ici (« la sortie d'erreur n'est pas capturée par le harnais ») était FAUSSE : on la lit en ré-exécutant
// le binaire de test en sous-processus (`current_exe` + `--nocapture`, la technique de
// `epoque_globale_lue_et_persistee.rs`). `prmb_journal_d_un_echec_sur_le_stderr_reel` la tient : mutant
// JO_SANS_EPRINTLN (`eprintln!` retiré) rouge sur ce seul témoin. L'assertion « rien sur une autre base » de
// `prmb_dparser_journal_d_un_echec` portait sur une base qu'aucun code n'écrivait (toujours vraie) : elle porte
// désormais sur une base saine réellement rechargée après l'échec.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un `enabled` illisible (blob) écarte le parseur par `WHERE enabled=1`
// sans compte ni ligne de journal ; le compte par base (`parseurs_lectures_ratees_de`) n'est lu que sous
// cfg(test) — en production il est incrémenté mais aucune surface ne l'affiche (seule la ligne de stderr témoigne).
// =====================================================================================
mod parseurs_registre_memo_par_base {
    use super::*;

    const MSG: &str = "PRMB user=alice host=web1";
    const SPEC_USER: &str = r#"{"source":"prmb-d","match":"PRMB","extract":[{"regex":"user=(?P<u>\\w+)"}],"map":{"fields":{"prmb_user":"$u"}}}"#;
    const SPEC_HOST_EN_USER: &str = r#"{"source":"prmb-d","match":"PRMB","extract":[{"regex":"host=(?P<u>\\w+)"}],"map":{"fields":{"prmb_user":"$u"}}}"#;
    const SPEC_HOST: &str = r#"{"source":"prmb-d","match":"PRMB","extract":[{"regex":"host=(?P<h>\\w+)"}],"map":{"fields":{"prmb_host":"$h"}}}"#;

    fn champ(fields: &Option<String>, k: &str) -> Option<String> {
        fields.as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get(k).and_then(|x| x.as_str()).map(str::to_string))
    }
    fn parseur(conn: &Connection, name: &str, pat: &str) -> i64 {
        conn.execute("INSERT INTO parser(name,source,pattern,enabled,created) VALUES(?1,'prmb-r',?2,1,100)", params![name, pat]).unwrap();
        conn.last_insert_rowid()
    }
    fn dparseur(conn: &Connection, name: &str, spec: &str) -> i64 {
        conn.execute("INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'prmb-d',?2,1,0,0,100)", params![name, spec]).unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn prmb_parser_memo_par_base_meme_identite() {
        let (ca, cb) = (test_db(), test_db());
        let (a, b) = (":memory:prmb-pa1", ":memory:prmb-pb1");
        let ia = parseur(&ca, "prmb-user", r"user=(?P<prmb_user>\w+)");
        let ib = parseur(&cb, "prmb-user", r"host=(?P<prmb_user>\w+)");
        assert_eq!(ia, ib, "précondition : même identifiant dans les deux bases");
        parsers_reload(&ca, a);
        parsers_reload(&cb, b);
        assert_eq!(champ(&parsers_apply(a, "prmb-r", MSG, None), "prmb_user").as_deref(), Some("alice"));
        assert_eq!(champ(&parsers_apply(b, "prmb-r", MSG, None), "prmb_user").as_deref(), Some("web1"));
        ca.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![ia]).unwrap();
        parsers_reload(&ca, a);
        assert_eq!(champ(&parsers_apply(a, "prmb-r", MSG, None), "prmb_user").as_deref(), Some("alice"),
            "A garde SA version, jamais celle de B");
        assert_eq!(champ(&parsers_apply(b, "prmb-r", MSG, None), "prmb_user").as_deref(), Some("web1"));
    }

    #[test]
    fn prmb_parser_memo_par_base_autre_nom() {
        let (ca, cb) = (test_db(), test_db());
        let (a, b) = (":memory:prmb-pa2", ":memory:prmb-pb2");
        let ia = parseur(&ca, "prmb-user", r"user=(?P<prmb_user>\w+)");
        let ib = parseur(&cb, "prmb-autre", r"host=(?P<prmb_host>\w+)");
        assert_eq!(ia, ib, "précondition : même identifiant dans les deux bases");
        parsers_reload(&ca, a);
        parsers_reload(&cb, b);
        ca.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![ia]).unwrap();
        parsers_reload(&ca, a);
        assert_eq!(champ(&parsers_apply(a, "prmb-r", MSG, None), "prmb_user").as_deref(), Some("alice"),
            "A garde SA version après le rechargement de B");
    }

    #[test]
    fn prmb_dparser_memo_par_base_meme_identite() {
        let (ca, cb) = (test_db(), test_db());
        let (a, b) = (":memory:prmb-da1", ":memory:prmb-db1");
        let ia = dparseur(&ca, "prmb-d-user", SPEC_USER);
        let ib = dparseur(&cb, "prmb-d-user", SPEC_HOST_EN_USER);
        assert_eq!(ia, ib, "précondition : même identifiant dans les deux bases");
        dparsers_reload(&ca, a);
        dparsers_reload(&cb, b);
        assert_eq!(champ(&dparsers_apply(a, "prmb-d", MSG, None).0, "prmb_user").as_deref(), Some("alice"));
        assert_eq!(champ(&dparsers_apply(b, "prmb-d", MSG, None).0, "prmb_user").as_deref(), Some("web1"));
        ca.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![ia]).unwrap();
        dparsers_reload(&ca, a);
        assert_eq!(champ(&dparsers_apply(a, "prmb-d", MSG, None).0, "prmb_user").as_deref(), Some("alice"),
            "dparser : A garde SA version, jamais celle de B");
    }

    #[test]
    fn prmb_dparser_memo_par_base_autre_nom() {
        let (ca, cb) = (test_db(), test_db());
        let (a, b) = (":memory:prmb-da2", ":memory:prmb-db2");
        let ia = dparseur(&ca, "prmb-d-user", SPEC_USER);
        let ib = dparseur(&cb, "prmb-d-autre", SPEC_HOST);
        assert_eq!(ia, ib, "précondition : même identifiant dans les deux bases");
        dparsers_reload(&ca, a);
        dparsers_reload(&cb, b);
        ca.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![ia]).unwrap();
        dparsers_reload(&ca, a);
        assert_eq!(champ(&dparsers_apply(a, "prmb-d", MSG, None).0, "prmb_user").as_deref(), Some("alice"),
            "dparser : A garde SA version après le rechargement de B");
    }

    #[test]
    fn prmb_dparser_plafond_tenu() {
        let c = test_db();
        let db = ":memory:prmb-plafond";
        for i in 0..(DPARSER_MAX_TOTAL + 1) { dparseur(&c, &format!("prmb-{i}"), SPEC_USER); }
        dparsers_reload(&c, db);
        assert_eq!(dparsers_cell().read().get(db).map(|l| l.len()), Some(DPARSER_MAX_TOTAL),
            "au-delà du plafond, les parseurs déclaratifs supplémentaires ne sont pas publiés");
    }

    #[test]
    fn prmb_parser_journal_d_un_echec() {
        let c = test_db();
        let db = ":memory:prmb-journal-p";
        let id = parseur(&c, "prmb-user", r"user=(?P<prmb_user>\w+)");
        parsers_reload(&c, db);
        assert!(parseurs_journal_de(db).is_empty(), "rechargement sans échec : aucune ligne");
        c.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![id]).unwrap();
        parsers_reload(&c, db);
        let j = parseurs_journal_de(db);
        assert_eq!(j.len(), 1, "une ligne par échec : {j:?}");
        let attendu = format!("[parser] lecture ratée du registre de parseurs de {db} : cellule illisible (id={id})");
        assert!(j[0].starts_with(&attendu), "ligne : {}", j[0]);
        assert!(j[0].ends_with("— dernière version compilée de la même règle (id, nom, création) gardée s'il en a une"), "ligne : {}", j[0]);
        assert_eq!(parseurs_lectures_ratees_de("parser", db), 1);
    }

    #[test]
    fn prmb_dparser_journal_d_un_echec() {
        let c = test_db();
        let db = ":memory:prmb-journal-d";
        let i1 = dparseur(&c, "prmb-d1", SPEC_USER);
        let i2 = dparseur(&c, "prmb-d2", SPEC_HOST);
        dparsers_reload(&c, db);
        assert!(parseurs_journal_de(db).is_empty(), "rechargement sans échec : aucune ligne");
        c.execute("UPDATE dparser SET spec=x'ff' WHERE id IN (?1, ?2)", params![i1, i2]).unwrap();
        dparsers_reload(&c, db);
        let j = parseurs_journal_de(db);
        assert_eq!(j.len(), 2, "une ligne par échec : {j:?}");
        for id in [i1, i2] {
            let attendu = format!("[dparser] lecture ratée du registre de parseurs de {db} : cellule illisible (id={id})");
            assert!(j.iter().any(|l| l.starts_with(&attendu)), "ligne attendue pour id={id} : {j:?}");
        }
        // Une AUTRE base, rechargée après l'échec (le code passe bien par elle) et saine : aucune ligne n'y est
        // retenue, et celles de `db` n'ont pas bougé.
        let c2 = test_db();
        let db2 = ":memory:prmb-journal-d-saine";
        dparseur(&c2, "prmb-d1", SPEC_USER);
        dparsers_reload(&c2, db2);
        assert!(dparsers_cell().read().get(db2).is_some_and(|l| !l.is_empty()), "contrôle : la base saine a été rechargée");
        assert!(parseurs_journal_de(db2).is_empty(), "rien sur une autre base, saine : {:?}", parseurs_journal_de(db2));
        assert_eq!(parseurs_journal_de(db).len(), 2, "les lignes de la base en échec restent les siennes");
    }

    /// CE QU'IL TIENT : la ligne de journal écrite sur le STDERR RÉEL du processus (en production, la seule trace d'un
    /// échec). Ce binaire de test est ré-exécuté sur CE seul test ; l'enfant recharge une base saine (contrôle : aucune
    /// ligne), puis une cellule illisible dans chaque registre (parser, dparser) sous deux bases propres à l'enfant ;
    /// le parent compte sur le stderr de l'enfant exactement UNE ligne par registre, préfixe complet (registre, base,
    /// cause, identifiant), et aucune pour la base saine.
    /// LA MUTATION QUI LE FAIT ROUGIR : `eprintln!` retiré de `journaliser_l_echec` (JO_SANS_EPRINTLN) — la rétention
    /// sous cfg(test) reste, donc `prmb_*_journal_d_un_echec` restent verts, celui-ci rougit.
    #[test]
    fn prmb_journal_d_un_echec_sur_le_stderr_reel() {
        const BASES_DE_L_ENFANT: &str = "PRMB_STDERR_BASES_DE_L_ENFANT";
        if let Ok(prefixe) = std::env::var(BASES_DE_L_ENFANT) {
            let (dbs, dbp, dbd) = (format!("{prefixe}-s"), format!("{prefixe}-p"), format!("{prefixe}-d"));
            let saine = test_db();
            parseur(&saine, "prmb-user", r"user=(?P<prmb_user>\w+)");
            parsers_reload(&saine, &dbs);
            let cp = test_db();
            let ip = parseur(&cp, "prmb-user", r"user=(?P<prmb_user>\w+)");
            parsers_reload(&cp, &dbp);
            cp.execute("UPDATE parser SET pattern=x'ff' WHERE id=?1", params![ip]).unwrap();
            parsers_reload(&cp, &dbp);
            let cd = test_db();
            let id = dparseur(&cd, "prmb-d1", SPEC_USER);
            dparsers_reload(&cd, &dbd);
            cd.execute("UPDATE dparser SET spec=x'ff' WHERE id=?1", params![id]).unwrap();
            dparsers_reload(&cd, &dbd);
            println!("PRMB-ENFANT-A-JOUE ip={ip} id={id}");
            return;
        }
        let prefixe = format!("prmb-stderr-{}", std::process::id());
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::parseurs_registre_memo_par_base::prmb_journal_d_un_echec_sur_le_stderr_reel",
            ])
            .env(BASES_DE_L_ENFANT, &prefixe)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant a réussi\n{stdout}\n{stderr}");
        // libtest écrit « test <nom> ... » avant la sortie de l'enfant, sur la même ligne : on cherche la marque dedans.
        let marque = stdout.lines().find_map(|l| l.split_once("PRMB-ENFANT-A-JOUE ").map(|(_, reste)| reste))
            .unwrap_or_else(|| panic!("contrôle : l'enfant a VRAIMENT joué\n{stdout}\n{stderr}"));
        let ids: Vec<&str> = marque.split_whitespace().collect();
        let (ip, id) = (ids[0].trim_start_matches("ip="), ids[1].trim_start_matches("id="));
        let compter = |p: &str| stderr.lines().filter(|l| l.starts_with(p)).count();
        assert_eq!(compter(&format!("[parser] lecture ratée du registre de parseurs de {prefixe}-p : cellule illisible (id={ip})")), 1,
            "une ligne [parser] sur le stderr réel de l'enfant :\n{stderr}");
        assert_eq!(compter(&format!("[dparser] lecture ratée du registre de parseurs de {prefixe}-d : cellule illisible (id={id})")), 1,
            "une ligne [dparser] sur le stderr réel de l'enfant :\n{stderr}");
        assert_eq!(compter(&format!("[parser] lecture ratée du registre de parseurs de {prefixe}-s ")), 0,
            "aucune ligne pour la base saine :\n{stderr}");
    }
}
