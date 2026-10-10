// =====================================================================================
// `P10.28-l` (trois des onze semis restants) et `P10.28-k` — LES SEMIS DE RÈGLES DE DÉTECTION ET LES GABARITS DE
// RUNBOOK S'ÉCRIVENT ENTIERS SOUS LEUR DRAPEAU, POSÉ EN DERNIER.
//
// LES DÉFAUTS, LUS SUR b52f097 :
//  * `seed_detection_rules`, `seed_purple_rules`, `seed_egress_rules` (seeds.rs) : drapeau `seeded_*` posé EN PREMIER
//    (écriture avalée), puis chaque INSERT de règle avalé (`let _`). Une règle refusée laissait un jeu de détection
//    PARTIEL, jamais retenté (drapeau posé).
//  * `seed_runbooks` : INSERT du gabarit testé par `.is_err()`, étapes avalées. Une étape refusée laissait le gabarit
//    sans cette étape pour toujours (sa clé existe au démarrage suivant, l'INSERT échoue sur l'unicité, `continue`) ;
//    un INSERT de gabarit qui rendait `Ok(0)` faisait rattacher ses étapes au gabarit PRÉCÉDENT (`last_insert_rowid`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les huit autres semis de `P10.28-l` (velero, example_rules, playbooks, ssh_cve,
// obs_rules, sts_rules, slab, k8s : drapeau toujours posé avant les données) ; un gabarit DÉJÀ amputé sur une base en
// service n'est pas réparé (sa clé existe : il n'est pas réécrit, seul son drapeau est posé) ; le marqueur
// d'observabilité `seeded_runbooks` reste écrit avalé (il ne garde rien).
// Ni l'audit d'extinction qui rend `Ok(0)` (`audit_source_change` n'exige pas `Ok(1)`), ni la famille « Ok(0) puis
// `last_insert_rowid` » des semis de tableaux (seed_dashboard_head, semer_la_vue_d_ensemble, semer_infra_et_logs,
// seed_dashboard_head_named).
// =====================================================================================
mod semis_de_regles_sous_leur_drapeau {
    use super::*;

    const SRSD_GENRE_EXTINCTION: &str = "config.seed.regle_sans_producteur";

    fn srsd_compte(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).expect("compte")
    }

    /// (règles, drapeau posé, audits d'extinction au registre).
    fn srsd_etat(conn: &Connection, drapeau: &str) -> (i64, i64, i64) {
        (
            srsd_compte(conn, "SELECT COUNT(*) FROM rule"),
            conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau"),
            conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![SRSD_GENRE_EXTINCTION], |r| r.get(0)).expect("registre"),
        )
    }

    fn srsd_semis() -> [(&'static str, &'static str, fn(&Connection)); 3] {
        [
            ("détection", "seeded_detection_rules", seed_detection_rules),
            ("purple", "seeded_purple_rules", seed_purple_rules),
            ("egress", "seeded_egress_rules", seed_egress_rules),
        ]
    }

    /// CE QU'IL TIENT, pour les trois semis et deux refus du même rang (la cinquième règle, ou la dernière si le semis
    /// en a moins : `RAISE(ABORT)` et `RAISE(IGNORE)`, qui rend `Ok(0)`) : après le refus, AUCUNE règle, AUCUN drapeau,
    /// AUCUN audit d'extinction (celui de `actif_si_un_producteur_livre_existe` est annulé avec le semis), transaction
    /// fermée ; au démarrage suivant (base revenue), le semis ENTIER, le drapeau et les audits d'une base neuve ; au
    /// démarrage d'après, rien de plus. MUTATIONS QUI LE FONT ROUGIR : un INSERT replacé en `let _`
    /// (`VERIF_MUT=det_let`, `purple_let`, `egress_let`).
    #[test]
    fn srsd_un_semis_de_regles_refuse_ne_garde_ni_regle_ni_drapeau_et_se_rejoue_entier() {
        let mut joues = 0;
        for (tag, drapeau, semer) in srsd_semis() {
            // L'attendu, MESURÉ sur une base neuve sans refus.
            let propre = test_db();
            let (base, _, audits_base) = srsd_etat(&propre, drapeau);
            semer(&propre);
            let (apres, pose, audits) = srsd_etat(&propre, drapeau);
            let n = apres - base;
            assert!(n >= 2 && pose == 1, "`{tag}` : instrument — le semis écrit des règles ({n}) et son drapeau");
            let rang = n.min(5);
            for (forme, corps) in [("ABORT", "RAISE(ABORT,'srsd refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                let conn = test_db();
                conn.execute_batch(&format!(
                    "CREATE TRIGGER srsd_refus BEFORE INSERT ON rule WHEN (SELECT COUNT(*) FROM rule) >= {} BEGIN SELECT {corps}; END;",
                    base + rang - 1
                ))
                .expect("déclencheur de refus");
                semer(&conn);
                assert_eq!(
                    srsd_etat(&conn, drapeau),
                    (base, 0, audits_base),
                    "`{tag}`, règle de rang {rang} refusée ({forme}) : ni règle, ni drapeau, ni audit d'extinction conservé"
                );
                assert!(conn.is_autocommit(), "`{tag}` ({forme}) : la transaction du semis est fermée");
                conn.execute_batch("DROP TRIGGER srsd_refus;").expect("base revenue");
                semer(&conn);
                assert_eq!(srsd_etat(&conn, drapeau), (apres, 1, audits), "`{tag}` ({forme}) : au démarrage suivant, le semis ENTIER");
                semer(&conn);
                assert_eq!(srsd_etat(&conn, drapeau), (apres, 1, audits), "`{tag}` ({forme}) : et rien de plus ensuite");
                joues += 1;
            }
        }
        assert_eq!(joues, 6, "les six cas sont joués");
    }

    /// CORRECTION — le déclencheur du témoin précédent refuse selon un COMPTE : il est COLLANT (il refuse aussi toutes les
    /// règles suivantes), si bien qu'une règle avalée dans une boucle était rattrapée par le `?` de la boucle d'après, et
    /// sept des huit boucles de `seed_detection_rules` pouvaient être avalées une à une sans rougir. Ici le refus vise UNE
    /// règle, par son NOM, et chacune à son tour (`ABORT` puis `IGNORE`) : la règle refusée est SEULE refusée, toutes les
    /// autres s'écriraient. CE QU'IL TIENT : pour CHAQUE règle des trois semis, aucun drapeau, aucune règle, aucun audit
    /// conservé, transaction fermée. MUTATIONS QUI LE FONT ROUGIR : n'importe lequel des huit `semer_une_regle_de_detection
    /// (..)?` de nouveau avalé (`let _ =`), et le `let _` des boucles purple et egress.
    #[test]
    fn srsd_chaque_regle_refusee_seule_par_son_nom_refuse_tout_son_semis() {
        let mut jouees = 0;
        for (tag, drapeau, semer) in srsd_semis() {
            let propre = test_db();
            let dernier: i64 = srsd_compte(&propre, "SELECT COALESCE(MAX(rowid),0) FROM rule");
            semer(&propre);
            let noms: Vec<String> = {
                let mut st = propre.prepare("SELECT DISTINCT name FROM rule WHERE rowid > ?1 ORDER BY rowid").expect("noms");
                let lus = st.query_map(params![dernier], |r| r.get::<_, String>(0)).expect("noms");
                lus.collect::<Result<Vec<_>, _>>().expect("noms")
            };
            assert!(noms.len() >= 2, "`{tag}` : instrument — des règles nommées ({})", noms.len());
            for (forme, corps) in [("ABORT", "RAISE(ABORT,'srsd refus nommé')"), ("IGNORE", "RAISE(IGNORE)")] {
                let conn = test_db();
                let avant = srsd_etat(&conn, drapeau);
                assert_eq!(avant.1, 0, "`{tag}` : instrument — base neuve non semée");
                for nom in &noms {
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER srsd_nomme BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT {corps}; END;",
                        nom.replace('\'', "''")
                    ))
                    .expect("déclencheur nommé");
                    semer(&conn);
                    assert_eq!(srsd_etat(&conn, drapeau), avant, "`{tag}`, « {nom} » seule refusée ({forme}) : rien n'est conservé, pas de drapeau");
                    assert!(conn.is_autocommit(), "`{tag}`, « {nom} » ({forme}) : transaction fermée");
                    conn.execute_batch("DROP TRIGGER srsd_nomme;").expect("base revenue");
                    jouees += 1;
                }
            }
        }
        assert!(jouees >= 2 * 20, "toutes les règles des trois semis sont jouées ({jouees})");
    }

    /// L'audit d'extinction d'une règle sans producteur, refusé, refuse le semis de détection entier (il était avalé :
    /// la règle restait semée éteinte SANS sa raison, et l'écriture continuait). Rejoué ensuite : chaque audit UNE fois.
    /// MUTATION QUI LE FAIT ROUGIR : l'audit de nouveau avalé (`VERIF_MUT=actif_avale`).
    #[test]
    fn srsd_un_audit_d_extinction_refuse_refuse_le_semis_de_detection() {
        let propre = test_db();
        let (base, _, audits_base) = srsd_etat(&propre, "seeded_detection_rules");
        seed_detection_rules(&propre);
        let (apres, _, audits) = srsd_etat(&propre, "seeded_detection_rules");
        assert!(audits > audits_base, "instrument : au moins une règle livrée est semée éteinte et auditée");
        let conn = test_db();
        conn.execute_batch(&format!(
            "CREATE TRIGGER srsd_audit BEFORE INSERT ON ledger WHEN NEW.kind='{SRSD_GENRE_EXTINCTION}' BEGIN SELECT RAISE(ABORT,'srsd audit'); END;"
        ))
        .expect("déclencheur");
        seed_detection_rules(&conn);
        assert_eq!(srsd_etat(&conn, "seeded_detection_rules"), (base, 0, audits_base), "audit refusé : rien n'est semé");
        conn.execute_batch("DROP TRIGGER srsd_audit;").expect("base revenue");
        seed_detection_rules(&conn);
        assert_eq!(srsd_etat(&conn, "seeded_detection_rules"), (apres, 1, audits), "rejoué : le semis entier, chaque audit une fois");
    }

    /// RISQUE DE RÉFUTATION MESURÉ : une base DÉJÀ semée par l'ancienne forme (drapeau posé) n'est pas touchée ; une
    /// base qui porte les règles mais a perdu son drapeau n'est pas refusée — `rule.name` n'a pas d'unicité, les
    /// homonymes passent comme avant, et le drapeau est posé : le tout-ou-rien ne rend pas un semis perpétuellement
    /// refusé sur doublon de nom.
    #[test]
    fn srsd_une_base_deja_semee_est_inchangee_et_un_homonyme_ne_fait_pas_refuser() {
        for (tag, drapeau, semer) in srsd_semis() {
            let conn = test_db();
            let base = srsd_compte(&conn, "SELECT COUNT(*) FROM rule");
            semer(&conn);
            let apres = srsd_compte(&conn, "SELECT COUNT(*) FROM rule");
            semer(&conn);
            assert_eq!(srsd_compte(&conn, "SELECT COUNT(*) FROM rule"), apres, "`{tag}` : base déjà semée, rien n'est réécrit");
            conn.execute("DELETE FROM meta WHERE key=?1", params![drapeau]).expect("drapeau perdu");
            semer(&conn);
            let (regles, pose, _) = srsd_etat(&conn, drapeau);
            assert_eq!((regles, pose), (base + 2 * (apres - base), 1), "`{tag}` : les homonymes ne font pas refuser le semis");
        }
    }

    /// (gabarits, étapes, drapeaux par gabarit).
    fn srsd_runbooks(conn: &Connection) -> (i64, i64, i64) {
        (
            srsd_compte(conn, "SELECT COUNT(*) FROM runbook"),
            srsd_compte(conn, "SELECT COUNT(*) FROM runbook_step"),
            srsd_compte(conn, "SELECT COUNT(*) FROM meta WHERE key LIKE 'seeded\\_runbook\\_%' ESCAPE '\\'"),
        )
    }

    fn srsd_etapes_de(conn: &Connection, cle: &str) -> Option<i64> {
        conn.query_row(
            "SELECT (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=r.id) FROM runbook r WHERE r.key=?1",
            params![cle],
            |r| r.get(0),
        )
        .ok()
    }

    /// Étapes par clé de gabarit.
    fn srsd_etapes_par_gabarit(conn: &Connection) -> std::collections::BTreeMap<String, i64> {
        let mut st = conn
            .prepare("SELECT r.key, (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=r.id) FROM runbook r")
            .expect("étapes par gabarit");
        let lus = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).expect("étapes par gabarit");
        lus.collect::<Result<_, _>>().expect("étapes par gabarit")
    }

    /// `P10.28-k` — CE QU'IL TIENT : la troisième étape de `recon-scan` refusée (`RAISE(ABORT)`), ce gabarit n'existe
    /// pas (ni étape, ni drapeau), les autres sont semés entiers ; au démarrage suivant il l'est avec ses cinq étapes ;
    /// ensuite rien de plus. Joué aussi en `RAISE(IGNORE)` (l'étape rend `Ok(0)`). MUTATIONS QUI LE FONT ROUGIR : l'INSERT
    /// d'étape replacé en `let _` (`VERIF_MUT=runbook_step_let` : gabarit à quatre étapes, drapeau posé, jamais réparé),
    /// et la garde `Ok(1)` de l'étape retirée (`issue?;` : la forme `IGNORE` rougit).
    #[test]
    fn srsd_une_etape_de_runbook_refusee_ne_laisse_pas_de_gabarit_ampute() {
        let propre = test_db();
        seed_runbooks(&propre);
        let entier = srsd_runbooks(&propre);
        let etapes_recon = srsd_etapes_de(&propre, "recon-scan").expect("instrument : recon-scan livré");
        assert!(etapes_recon >= 3 && entier.0 >= 2 && entier.2 == entier.0, "instrument : {entier:?}, {etapes_recon} étapes");
        for (forme, corps) in [("ABORT", "RAISE(ABORT,'srsd étape')"), ("IGNORE", "RAISE(IGNORE)")] {
        let conn = test_db();
        conn.execute_batch(&format!(
            "CREATE TRIGGER srsd_etape BEFORE INSERT ON runbook_step WHEN NEW.ordinal=2 \
             AND NEW.runbook_id=(SELECT id FROM runbook WHERE key='recon-scan') BEGIN SELECT {corps}; END;"
        ))
        .expect("déclencheur");
        seed_runbooks(&conn);
        assert_eq!(srsd_etapes_de(&conn, "recon-scan"), None, "étape refusée ({forme}) : le gabarit n'est pas conservé amputé");
        assert_eq!(
            srsd_runbooks(&conn),
            (entier.0 - 1, entier.1 - etapes_recon, entier.2 - 1),
            "les autres gabarits sont semés entiers, sans être bloqués"
        );
        assert!(conn.is_autocommit(), "transaction fermée");
        conn.execute_batch("DROP TRIGGER srsd_etape;").expect("base revenue");
        seed_runbooks(&conn);
        assert_eq!(srsd_etapes_de(&conn, "recon-scan"), Some(etapes_recon), "rejoué : le gabarit et toutes ses étapes");
        assert_eq!(srsd_runbooks(&conn), entier, "au démarrage suivant, tout");
        seed_runbooks(&conn);
        assert_eq!(srsd_runbooks(&conn), entier, "({forme}) et rien de plus ensuite");
        }
    }

    /// `P10.28-k` (famille « Ok(0) puis `last_insert_rowid` ») — l'INSERT du SECOND gabarit refusé, en `RAISE(ABORT)` (il
    /// était `continue` avant le correctif : rejoué ensuite) puis en `RAISE(IGNORE)` (`Ok(0)`) : ses étapes ne sont
    /// rattachées à AUCUNE autre ligne (en `IGNORE`, `last_insert_rowid` rendrait le rowid du drapeau `meta` posé juste
    /// avant : des étapes orphelines au moment de l'écriture, qu'un gabarit semé PLUS TARD adopte quand son identifiant
    /// rejoint ce rowid — mesuré : 72 étapes au lieu de 67, aucune orpheline à la fin ; d'où la comparaison PAR CLÉ), il n'existe pas, il n'est pas drapeauté, les autres sont entiers, et il est semé au
    /// démarrage suivant. MUTATIONS QUI LE FONT ROUGIR : l'erreur de l'INSERT du gabarit avalée en `return Ok(())`
    /// (forme `ABORT` : drapeau posé sans gabarit), la garde `Ok(1)` du gabarit retirée (forme `IGNORE` : étapes orphelines).
    #[test]
    fn srsd_un_gabarit_refuse_ne_prete_pas_son_identifiant_et_se_rejoue() {
        let propre = test_db();
        seed_runbooks(&propre);
        let entier = srsd_runbooks(&propre);
        let etapes_iae = srsd_etapes_de(&propre, "initial-access-exploit").expect("instrument : initial-access-exploit livré");
        assert!(etapes_iae >= 1, "instrument : le gabarit a des étapes");
        for (forme, corps) in [("ABORT", "RAISE(ABORT,'srsd gabarit')"), ("IGNORE", "RAISE(IGNORE)")] {
            let conn = test_db();
            conn.execute_batch(&format!(
                "CREATE TRIGGER srsd_gabarit BEFORE INSERT ON runbook WHEN NEW.key='initial-access-exploit' BEGIN SELECT {corps}; END;"
            ))
            .expect("déclencheur");
            seed_runbooks(&conn);
            let mut attendu = srsd_etapes_par_gabarit(&propre);
            attendu.remove("initial-access-exploit");
            assert_eq!(
                (srsd_etapes_par_gabarit(&conn), srsd_compte(&conn, "SELECT COUNT(*) FROM runbook_step WHERE runbook_id NOT IN (SELECT id FROM runbook)")),
                (attendu, 0),
                "({forme}) chaque autre gabarit garde exactement ses étapes, aucune n'est orpheline (identifiant emprunté)"
            );
            assert_eq!(srsd_etapes_de(&conn, "initial-access-exploit"), None, "({forme}) le gabarit refusé n'existe pas");
            assert_eq!(
                srsd_runbooks(&conn),
                (entier.0 - 1, entier.1 - etapes_iae, entier.2 - 1),
                "({forme}) il n'est pas drapeauté, les autres sont semés entiers"
            );
            assert!(conn.is_autocommit(), "({forme}) transaction fermée");
            conn.execute_batch("DROP TRIGGER srsd_gabarit;").expect("base revenue");
            seed_runbooks(&conn);
            assert_eq!(srsd_etapes_de(&conn, "initial-access-exploit"), Some(etapes_iae), "({forme}) rejoué avec ses étapes");
            assert_eq!(srsd_runbooks(&conn), entier, "({forme}) rejoué au démarrage suivant");
        }
    }

    /// RISQUE DE RÉFUTATION : une base semée par l'ANCIENNE forme (gabarits présents, aucun drapeau par gabarit) n'est
    /// pas refusée ni doublée : chaque clé présente est laissée telle quelle, son drapeau posé.
    #[test]
    fn srsd_une_base_de_runbooks_deja_semee_par_l_ancienne_forme_est_inchangee() {
        let conn = test_db();
        seed_runbooks(&conn);
        let entier = srsd_runbooks(&conn);
        conn.execute_batch("UPDATE runbook SET active=0 WHERE key='recon-scan'; DELETE FROM meta WHERE key LIKE 'seeded\\_runbook\\_%' ESCAPE '\\';")
            .expect("ancienne forme");
        seed_runbooks(&conn);
        assert_eq!(srsd_runbooks(&conn), entier, "ni doublon, ni refus : chaque drapeau posé");
        let actif: i64 = conn.query_row("SELECT active FROM runbook WHERE key='recon-scan'", [], |r| r.get(0)).unwrap();
        assert_eq!(actif, 0, "un gabarit désactivé n'est pas réécrit");
    }
}
