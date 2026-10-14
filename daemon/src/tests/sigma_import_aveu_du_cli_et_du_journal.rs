// =====================================================================================
// `P10.20-b` (hors handlers/ : `sigma.rs`, bras `sigma-import` de `main.rs`) — L'ARRÊT DU CLI ET LA LIGNE DE JOURNAL DU
// REFUS SIGMA SONT TÉMOIGNÉS ; UNE ÉCRITURE REFUSÉE NE PANIQUE PLUS.
//
// VU SUR 55c7ecbb. La branche d'erreur du CLI (`Err(cause)` -> ligne d'ARRÊT + `exit(1)`) vivait dans `fn main`, donc
// hors de portée d'un test : un mutant qui remplaçait l'arrêt par `continue` (sortie 0, règle absente du rapport)
// laissait tout vert. La ligne `[sigma] WARN … NON fait … ({refus})` de `refuser_l_import_sigma_non_lu` est la SEULE à
// porter la cause du moteur (le corps 503 ne la porte pas) et n'était capturée par aucun test. Les deux écritures du
// CLI gardaient `.expect` : une écriture refusée paniquait (code 101) au lieu de rendre le message d'arrêt.
//
// LE GESTE. Le corps du bras est déplacé dans `sigma_cli_importer` (rapport ou `SigmaCliArret` : source, cause, nombre
// de règles déjà écrites ; `ligne()` = le texte d'avant, octet pour octet) ; `main` ne garde que l'impression et le
// `exit(1)`. Les deux `.expect` deviennent un `Err(message)` du même arrêt.
//
// LES TÉMOINS.
// (1) Lecture ratée (autorisateur qui refuse une colonne de `rule`) : `sigma_cli_importer` rend l'ARRÊT, la règle en
//     cause et les suivantes ne sont pas écrites, la native du même nom reste intacte et seule ; le compte des règles
//     déjà écrites est celui d'avant l'arrêt et la ligne est le texte d'avant ; une native protégée et un intraduisible
//     placés AVANT la règle écrite départagent ce compte (règles ÉCRITES, ni l'index du document ni les ignorées).
// (2) Écriture refusée (déclencheur `RAISE(ABORT)` sur INSERT, puis sur UPDATE) : ARRÊT avec la cause du moteur, pas de
//     panique ; déclencheurs levés : écrite.
// (3) La ligne de journal du refus web, lue sur le stderr RÉEL d'un sous-processus du binaire de test : une ligne par
//     refus (import unitaire, import en masse), la cause du moteur présente ; contre-épreuve : absence établie, aucune.
// (4) Le câblage de `main` : lu sur le TEXTE de `main.rs` (le bras délègue à `sigma_cli_importer`, sort en 1 sur l'arrêt,
//     n'appelle plus `sigma_cli_appliquer_une` lui-même). Témoin de TEXTE, pas de comportement : il ne joue pas le binaire.
//     Le jouer demanderait un test d'intégration `daemon/tests/` sur `CARGO_BIN_EXE_plume-daemon`, ce qui change les
//     comptes de la CI : non fait ici.
// (5) Nominal : `--dry-run` (aucune base) et base ouverte rendent le rapport d'avant, comparé entrée par entrée avec une
//     source distincte par document : l'importée avec ses six champs (name, severity, mitre, query, warnings, source),
//     la native ET l'overlay géré (managed=1) avec leur raison EXACTE, l'intraduisible avec la raison du traducteur, un
//     document sans titre nommé par le repli « (sans titre) ».
//
// MUTANTS JOUÉS (`VERIF_MUT`, retirés du source avant le commit) :
//  * « q6_arret_continue » (l'arrêt remplacé par `continue`) : (1), (2) ;
//  * « q6_expect » (`.expect` rétabli devant l'Err) : (2) (panique) ;
//  * « q6_warn_sans_cause » (cause du moteur retirée de la ligne WARN) : (3) ;
//  * « q6_main_non_cable » : SIMULÉ sur le texte lu par (4) (l'appel `sigma_cli_importer(` remplacé par l'ancien
//    `sigma_cli_appliquer_une(`) — (4) ne lit que ce texte, la simulation est donc exacte pour lui, mais rien ici
//    n'exécute `main` ;
//  * « q6_prot_overlay » (l'overlay géré reçoit la raison de la native) : (5) ;
//  * « q6_imp_sans_query » (`query` retiré de l'entrée importée) : (5) ;
//  * « q6_source_figee » (la source de l'entrée protégée figée sur le premier document) : (5) ;
//  * « arret_compte_index » (index du document au lieu des écrites) et « arret_compte_plus_skip » (écrites + ignorées) : (1) ;
//  * « tr_title_fallback » (repli `""` au lieu de « (sans titre) ») : (5).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la sortie réelle du binaire `plume-daemon sigma-import` (code 1, stderr) n'est pas
// jouée en sous-processus — seul le texte du bras l'est, donc une mutation de COMPORTEMENT en amont de l'appel (par
// exemple `conn` remplacée par `None` : import à blanc, sortie 0) laisse (4) vert ; le CLI n'ouvre pas de transaction : les règles écrites avant
// l'arrêt restent (la ligne le dit, le témoin (1) le mesure) ; un titre Sigma à caractères de contrôle (retour à la
// ligne, échappement) n'est filtré nulle part (`sigma_translate` ne fait que `trim`) et passe tel quel dans la ligne WARN
// et dans la ligne d'ARRÊT — non corrigé ici ; le mode multi-tenant n'est pas joué.
// =====================================================================================
mod sigma_import_aveu_du_cli_et_du_journal {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    fn q6_refuser_la_lecture(conn: &Connection, colonne: Option<&'static str>) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "rule" && colonne.map_or(true, |c| c == column_name) => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn q6_lever(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn q6_doc(titre: &str, id: Option<&str>) -> Value {
        let mut d = json!({ "title": titre, "logsource": { "service": "sshd" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" }, "level": "medium" });
        if let Some(i) = id {
            d["id"] = json!(i);
        }
        d
    }

    fn q6_docs(docs: &[(&str, Value)]) -> Vec<(String, Value)> {
        docs.iter().map(|(o, d)| (o.to_string(), d.clone())).collect()
    }

    fn q6_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn q6_natif(conn: &Connection, nom: &str) {
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES(?1,1,'search q6natif | stats count',1,0)", params![nom])
            .expect("fixture : règle native");
    }

    /// (1) LECTURE RATÉE : l'ARRÊT, rien d'écrit pour la règle en cause ni pour les suivantes, la native intacte et
    /// seule ; le compte des règles déjà écrites est exact et la ligne est le texte d'avant.
    #[test]
    fn q6_lecture_ratee_rend_l_arret_sans_ecrire_la_suite() {
        let conn = test_db();
        q6_natif(&conn, "Q6 Natif");

        // Colonne `name` de `rule` illisible (étage nom de la résolution), la native en premier : arrêt à zéro règle écrite.
        q6_refuser_la_lecture(&conn, Some("name"));
        let r = sigma_cli_importer(Some(&conn), &q6_docs(&[("q6/a.yml", q6_doc("Q6 Natif", None)), ("q6/a.yml", q6_doc("Q6 Apres", None))]));
        q6_lever(&conn);
        let arret = r.err().expect("étage nom illisible : ARRÊT attendu, jamais un rapport");
        assert_eq!((arret.origine.as_str(), arret.deja_ecrites), ("q6/a.yml", 0), "source et compte ({arret:?})");
        assert!(arret.cause.contains("« Q6 Natif »") && arret.cause.contains("NON LUE"), "cause nommée ({arret:?})");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Natif'"), 1, "la native reste SEULE");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Natif' AND managed=0 AND query='search q6natif | stats count'"), 1, "native intacte");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Apres'"), 0, "la suivante n'est pas jouée");

        // Étage `sigma_id` seul illisible : la native (protégée, IGNORÉE) et un intraduisible passent d'abord, puis la
        // première (sans id) s'écrit, la deuxième (avec id) arrête, la troisième n'est pas jouée — et la première RESTE
        // (le CLI n'a pas de transaction). Le compte départage : 1 ÉCRITE, alors que l'arrêt tombe sur le 4e document
        // et que deux documents ont été ignorés avant lui (un compte d'index ou d'ignorées rendrait 3).
        q6_refuser_la_lecture(&conn, Some("sigma_id"));
        let r = sigma_cli_importer(Some(&conn), &q6_docs(&[
            ("q6/n.yml", q6_doc("Q6 Natif", None)),
            ("q6/v.yml", json!({ "title": "Q6 Sans detection" })),
            ("q6/b.yml", q6_doc("Q6 Premiere", None)),
            ("q6/c.yml", q6_doc("Q6 Deuxieme", Some("q6-uuid-b"))),
            ("q6/d.yml", q6_doc("Q6 Troisieme", None)),
        ]));
        q6_lever(&conn);
        let arret = r.err().expect("étage sigma_id illisible : ARRÊT attendu");
        assert_eq!((arret.origine.as_str(), arret.deja_ecrites), ("q6/c.yml", 1), "arrêt sur la deuxième, une déjà écrite ({arret:?})");
        assert_eq!(
            arret.ligne(),
            format!("[sigma] q6/c.yml : {} — ARRÊT : cette règle et les suivantes NE sont PAS importées ; 1 règle(s) déjà écrite(s) le restent.", arret.cause),
            "la ligne d'arrêt est le texte d'avant l'extraction"
        );
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Premiere' AND managed=2"), 1, "la première reste écrite");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name IN ('Q6 Deuxieme','Q6 Troisieme')"), 0, "ni la deuxième ni la troisième");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Natif' AND managed=0 AND query='search q6natif | stats count'"), 1, "la native ignorée reste seule et intacte");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Sans detection'"), 0, "l'intraduisible n'est pas écrite");
    }

    /// (2) ÉCRITURE REFUSÉE : ARRÊT avec la cause du moteur, sans panique, à l'insertion comme à la mise à jour.
    #[test]
    fn q6_ecriture_refusee_rend_l_arret_sans_paniquer() {
        let conn = test_db();
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed,sigma_id) VALUES('Q6 Importee',0,'search q6 | stats count',1,2,'q6-uuid-u')", [])
            .expect("fixture : règle déjà importée");
        conn.execute_batch(
            "CREATE TRIGGER q6_refus_insert BEFORE INSERT ON rule BEGIN SELECT RAISE(ABORT, 'q6 insertion refusee'); END;
             CREATE TRIGGER q6_refus_update BEFORE UPDATE ON rule BEGIN SELECT RAISE(ABORT, 'q6 mise a jour refusee'); END;",
        )
        .expect("fixture : déclencheurs de refus");

        for (doc, motif, quoi) in [
            (q6_doc("Q6 Neuve", None), "q6 insertion refusee", "insertion"),
            (q6_doc("Q6 Importee v2", Some("q6-uuid-u")), "q6 mise a jour refusee", "mise à jour"),
        ] {
            let titre = doc["title"].as_str().unwrap_or_default().to_string();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sigma_cli_importer(Some(&conn), &q6_docs(&[("q6/w.yml", doc.clone())]))));
            let r = r.unwrap_or_else(|_| panic!("{quoi} refusée : PANIQUE (`.expect`), jamais le message d'arrêt"));
            let arret = r.err().unwrap_or_else(|| panic!("{quoi} refusée : ARRÊT attendu, jamais un rapport"));
            assert_eq!(arret.deja_ecrites, 0, "{quoi} : rien de déjà écrit ({arret:?})");
            assert!(arret.cause.contains(&format!("« {titre} »")) && arret.cause.contains("NON ÉCRITE") && arret.cause.contains(motif), "{quoi} : cause du moteur nommée ({arret:?})");
        }
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE sigma_id='q6-uuid-u' AND name='Q6 Importee' AND enabled=0"), 1, "la règle importée garde sa logique d'avant");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Neuve'"), 0, "rien d'inséré");

        conn.execute_batch("DROP TRIGGER q6_refus_insert; DROP TRIGGER q6_refus_update;").expect("fixture : levée");
        let rapport = sigma_cli_importer(Some(&conn), &q6_docs(&[("q6/w.yml", q6_doc("Q6 Neuve", None)), ("q6/w.yml", q6_doc("Q6 Importee v2", Some("q6-uuid-u")))]))
            .expect("levé : rapport");
        assert_eq!(rapport.imported.len(), 2, "levé : les deux écrites ({:?})", rapport.imported);
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE sigma_id='q6-uuid-u' AND name='Q6 Importee v2' AND enabled=1 AND managed=2"), 1, "levé : mise à jour");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Neuve' AND managed=2"), 1, "levé : insertion");
    }

    /// (3) LA LIGNE DE JOURNAL DU REFUS WEB, sur le stderr RÉEL d'un sous-processus. L'enfant (variable posée) joue un
    /// import unitaire et un import en masse sur une base dont `rule.name` est illisible, puis, levé, un import d'une
    /// règle absente. Le parent lit son stderr.
    #[tokio::test]
    async fn q6_refus_sigma_ecrit_une_ligne_de_journal_avec_la_cause_du_moteur() {
        const ENFANT: &str = "Q6_ENFANT_JOURNAL";
        const LEVEE: &str = "Q6-PHASE-LEVEE";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = sp_state("q6-journal");
            let adm = sp_au("adm", "admin");
            q6_natif(&st.db.lock(), "Q6 Natif");
            q6_refuser_la_lecture(&st.db.lock(), Some("name"));
            let attendu = sigma_find_existing(&st.db.lock(), &sigma_translate(&q6_doc("Q6 Natif", None)).expect("traduisible"))
                .err()
                .expect("fixture : la lecture est refusée");
            println!("Q6-CAUSE:{attendu}");
            let r = sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [q6_doc("Q6 Natif", None)] }))).await;
            println!("Q6-UNITAIRE:{}", r.status().as_u16());
            let r = sigma_import_bulk(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [q6_doc("Q6 Natif", None)], "enable": true }))).await;
            println!("Q6-MASSE:{}", r.status().as_u16());
            q6_lever(&st.db.lock());
            eprintln!("{LEVEE}");
            let r = sigma_import(State(st.clone()), Extension(adm.clone()), Json(json!({ "rules": [q6_doc("Q6 Absente", None)] }))).await;
            println!("Q6-LEVE:{}", r.status().as_u16());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::sigma_import_aveu_du_cli_et_du_journal::q6_refus_sigma_ecrit_une_ligne_de_journal_avec_la_cause_du_moteur",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for attendu in ["Q6-UNITAIRE:503", "Q6-MASSE:503", "Q6-LEVE:200"] {
            assert!(stdout.contains(attendu), "contrôle : l'enfant a joué ({attendu}) : {stdout}\n{stderr}");
        }
        // libtest écrit « test <nom> ... » sans fin de ligne avant de jouer : la première ligne de l'enfant s'y accole.
        let cause = stdout.lines().find_map(|l| l.split_once("Q6-CAUSE:").map(|(_, c)| c)).expect("contrôle : cause du moteur rendue par l'enfant").to_string();
        assert!(!cause.trim().is_empty(), "contrôle : cause non vide");

        let (avant, apres) = stderr.split_once(LEVEE).unwrap_or_else(|| panic!("contrôle : marqueur de levée sur stderr : {stderr}"));
        let lignes: Vec<&str> = avant.lines().filter(|l| l.starts_with("[sigma] WARN")).collect();
        assert_eq!(lignes.len(), 2, "une ligne par refus, ni plus ni moins : {lignes:?}\n{stderr}");
        for (ligne, geste) in lignes.iter().zip(["[sigma] WARN import Sigma NON fait", "[sigma] WARN import Sigma en masse NON fait"]) {
            assert!(ligne.starts_with(geste), "le geste nommé (`{geste}`) : {ligne}");
            assert!(ligne.contains("« Q6 Natif »"), "la règle nommée : {ligne}");
            assert!(ligne.contains(&format!("({cause})")), "la cause du moteur (`{cause}`) : {ligne}");
        }
        assert_eq!(apres.lines().filter(|l| l.starts_with("[sigma] WARN")).count(), 0, "contre-épreuve : absence établie, aucune ligne : {apres}");
    }

    /// (4) LE CÂBLAGE DE `main`, lu sur son texte : le bras `sigma-import` délègue à `sigma_cli_importer`, écrit la ligne
    /// de l'arrêt et sort en 1 ; plus aucun appel direct à `sigma_cli_appliquer_une` dans `main.rs`.
    #[test]
    fn q6_le_bras_sigma_import_de_main_delegue_et_sort_en_un() {
        let src = include_str!("../main.rs");
        let debut = src.find("Some(\"sigma-import\")").expect("le bras sigma-import existe");
        let fin = debut + src[debut..].find("Some(\"retention\")").expect("le bras suivant existe");
        let bras = &src[debut..fin];
        let appel = bras.find("sigma_cli_importer(conn.as_deref(), &docs)").unwrap_or_else(|| panic!("le bras délègue à sigma_cli_importer :\n{bras}"));
        let apres = &bras[appel..];
        let arret = apres.find("Err(arret)").expect("le bras traite l'arrêt");
        let ligne = apres.find("eprintln!(\"{}\", arret.ligne());").expect("le bras écrit la ligne d'arrêt");
        let sortie = apres.find("std::process::exit(1);").expect("le bras sort en 1");
        assert!(arret < ligne && ligne < sortie, "ordre : arrêt, ligne, sortie en 1");
        assert!(!src.contains("sigma_cli_appliquer_une("), "main.rs n'appelle plus le pas lui-même : la boucle vit dans sigma_cli_importer");
    }

    /// (5) NOMINAL : `--dry-run` (aucune base) et base ouverte rendent le rapport d'avant, entrée par entrée : chaque
    /// document a sa propre source, l'importée porte ses six champs, la native ET l'overlay géré portent chacun leur
    /// raison EXACTE (texte de `main.rs` sur 55c7ecbb).
    #[test]
    fn q6_rapport_nominal_dry_run_et_base_ouverte() {
        let neuve = json!({ "title": "Q6 Neuve", "level": "high", "tags": ["attack.t1110"], "logsource": { "service": "q6inconnu" },
            "detection": { "selection": { "action": "failure" }, "condition": "selection" } });
        let t = sigma_translate(&neuve).expect("fixture : la neuve se traduit");
        // Contrôles de non-vacuité : chaque champ lu ci-dessous porte une valeur qu'un champ manquant ne rend pas.
        assert_eq!((t.severity, t.mitre.as_str()), (3, "T1110"), "contrôle : sévérité et MITRE non triviales");
        assert!(!t.query.is_empty(), "contrôle : requête non vide");
        assert!(t.warnings.first().is_some_and(|w| w.starts_with("logsource non mappé")), "contrôle : un avertissement ({:?})", t.warnings);
        let importee = json!({ "name": "Q6 Neuve", "severity": 3, "mitre": "T1110", "query": t.query, "warnings": t.warnings, "source": "q6/neuve.yml" });
        let docs = q6_docs(&[
            ("q6/natif.yml", q6_doc("Q6 Natif", None)),
            ("q6/overlay.yml", q6_doc("Q6 Overlay", None)),
            ("q6/neuve.yml", neuve.clone()),
            ("q6/vide.yml", json!({ "title": "Q6 Sans detection" })),
            ("q6/sanstitre.yml", json!({ "level": "low" })),
        ]);
        let intraduisible = json!({ "title": "Q6 Sans detection", "reason": "règle Sigma sans bloc 'detection'", "source": "q6/vide.yml" });
        // Un document SANS titre : le rapport le nomme par le repli « (sans titre) » (texte de `main.rs` sur 55c7ecbb).
        let sans_titre = json!({ "title": "(sans titre)", "reason": "règle Sigma sans 'title'", "source": "q6/sanstitre.yml" });

        let sec = sigma_cli_importer(None, &docs).expect("dry-run : rapport");
        assert_eq!(sec.imported.len(), 3, "dry-run : les trois traduisibles ({:?})", sec.imported);
        assert_eq!(sec.imported[2], importee, "dry-run : l'entrée importée, champ par champ");
        assert_eq!(sec.skipped, vec![intraduisible.clone(), sans_titre.clone()], "dry-run : les deux intraduisibles, titre (repli compris), raison et source");

        let conn = test_db();
        q6_natif(&conn, "Q6 Natif");
        conn.execute("INSERT INTO rule(name,enabled,query,is_soql,managed) VALUES('Q6 Overlay',1,'search q6overlay | stats count',1,1)", [])
            .expect("fixture : overlay géré");
        let r = sigma_cli_importer(Some(&conn), &docs).expect("base ouverte : rapport");
        assert_eq!(r.imported, vec![importee], "base ouverte : la neuve seule, champ par champ");
        assert_eq!(
            r.skipped,
            vec![
                json!({ "title": "Q6 Natif", "reason": "existe comme détection native (builtin/seed, managed=0) — NON écrasée par un import Sigma", "source": "q6/natif.yml" }),
                json!({ "title": "Q6 Overlay", "reason": "existe comme overlay géré (managed=1) — non écrasé", "source": "q6/overlay.yml" }),
                intraduisible,
                sans_titre,
            ],
            "native et overlay protégés avec leur raison exacte, puis les deux intraduisibles"
        );
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Natif'"), 1, "native seule");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Overlay' AND managed=1 AND query='search q6overlay | stats count'"), 1, "overlay seul et intact");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Overlay'"), 1, "overlay non doublé");
        assert_eq!(q6_compte(&conn, "SELECT COUNT(*) FROM rule WHERE name='Q6 Neuve' AND managed=2 AND enabled=1 AND severity=3"), 1, "neuve écrite");
    }
}
