// =====================================================================================
// `P10.28-l` (restes de la vague AP) et `P10.28-k` (dernier reste) — LES LIGNES `[seed]` DES SEMIS DE `seeds.rs` ONT
// LEUR TÉMOIN, UNE LECTURE RATÉE DU NOM DE VUE A SON ÉTAPE, LE REFUS DE BANNI / PASS EST COMPTÉ AU DÉMARRAGE ET AU PROVISIONNEMENT
// D'UN TENANT, ET UN GABARIT DE RUNBOOK MANAGÉ DÉJÀ AMPUTÉ EST RÉPARÉ.
//
// LES DÉFAUTS, LUS SUR a759d83d :
//  * `semer_sous_son_drapeau` (seeds.rs) : ses trois lignes `[seed] … NON semé` (présence non lue, transaction
//    refusée, écriture refusée) n'avaient aucun témoin ;
//  * `rattacher_le_tableau_a_sa_vue` : `lire_ou_creer_la_vue(conn, view)?` rendait la lecture ratée du nom de vue comme
//    une écriture refusée — comptée sous « écriture ou COMMIT refusé », dite « une écriture a été refusée » ;
//  * `seed_banpass_dashboard` (rollups.rs) dit son refus sur la sortie d'erreur, sans compte ;
//  * `seed_runbooks` : une clé présente rendait `Ok(())` sans regarder ses étapes, et le drapeau
//    `seeded_runbook_<clé>` posé interdisait tout nouveau passage : un gabarit managé amputé le restait pour toujours ;
//    le marqueur `seeded_runbooks`, écrit avalé à chaque démarrage, n'avait aucun lecteur ;
//  * le `# HELP` de `plume_scheduler_gestes_de_fond_non_valides_total` ne citait pas les semis.
//
// CE QUE CES TÉMOINS TIENNENT : (a) les lignes `[seed]` ENTIÈRES (égalité, dans l'ordre), lues sur le stderr d'un
// sous-processus : présence non lue, `BEGIN` refusé, écriture refusée, nom de vue non lu (semis par nom et sous
// drapeau), vue non créable `RAISE(IGNORE)` puis `RAISE(ABORT)` (écriture refusée, pas nom non lu), réparation d'un
// gabarit refusée ; aucune ligne au nominal (le même tableau, retiré puis semé, et la réparation rejouée) ; (b) Banni /
// Pass par `seed_tenant_content` sur DEUX bases réelles, une seule refuse la vue : absence comptée chez elle seule,
// rien chez l'autre ni après reprise ; sa présence non lue comptée sous son étape, rien d'écrit ; (c) gabarits : un
// managé amputé de deux ordinaux ET désactivé, drapeau posé -> seuls ses ordinaux manquants réécrits, au contenu
// livré, actif reste à 0 ; un managé vidé SANS drapeau (forme d'avant la vague H) -> ses étapes réécrites ; une clé
// portée par un gabarit non managé amputé -> intacte ; tous les autres gabarits et leurs étapes inchangés à l'octet
// (identifiants compris) ; rejoué, rien de plus ; (d) la réparation refusée sur son PREMIER ordinal manquant
// (`RAISE(IGNORE)` et `RAISE(ABORT)`) -> le suivant n'est pas écrit non plus, transaction fermée, compté une fois,
// repris entier ensuite ; (e) le drapeau ou les étapes illisibles SEULS -> rien d'écrit, compté sous « présence non
// lue » ; (f) le `# HELP` servi par `exposition_prom`.
//
// LE DÉMARRAGE (`server/mod.rs`) appelle le même enrobage que `seed_tenant_content` : ce n'est tenu ici que par la
// garde de partition de `index_usage_event.rs` (`la_partition_du_corpus_est_close`, qui exige les mêmes semeurs des deux
// côtés), pas par un appel du démarrage.
//
// CE QU'ILS NE TIENNENT PAS : la migration v52 reste hors compte (sous `MigTx`) ; la migration v63 (`migrate.rs`)
// garde son `if let Some(vid)`. Aucune variable d'environnement n'est lue par ces semis.
//
// MUTANTS JOUÉS (retirés avant le commit), chacun vu ROUGE sur son témoin : `AQ2_vue_etape`, `AQ2_vue_phrase`,
// `AQ2_vue_creee_non_lue`, `AQ2_rb_drapeau_seul` (la forme d'avant), `AQ2_rb_drapeau_ok`, `AQ2_rb_etat_illisible_complet`,
// `AQ2_rb_sans_compte`, `AQ2_rb_ok0`, `AQ2_rb_tout_reecrire`, `AQ2_rb_non_manage_repare`, `AQ2_marqueur`,
// `AQ2_bp_compte_present`, `AQ2_bp_sans_compte`, `AQ2_bp_lecture_absente`, `AQ2_tenant_sans_enrobage`, `AQ2_aide_ancienne`.
// =====================================================================================
mod semis_vue_non_lue_banni_pass_compte_et_gabarits_repares {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const AQ2_WEB: &str = "Trafic web";
    const AQ2_VUE_WEB: &str = "Réseau & Web";
    const AQ2_EGRESS: &str = "Réseau sortant (egress)";
    const AQ2_AMPUTE: &str = "recon-scan";
    const AQ2_VIDE_SANS_DRAPEAU: &str = "credential-access-bruteforce";
    const AQ2_NON_MANAGE: &str = "initial-access-exploit";

    fn aq2_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    fn aq2_compte(conn: &Connection, geste: &str, etape: &str) -> u64 {
        compte_des_temoins(conn, &format!("geste de fond non validé seed : {geste} : {etape}"))
    }

    fn aq2_rendre_la_main(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Refuse la lecture de `table.colonne`, et elle seule.
    fn aq2_refuser_la_lecture(conn: &Connection, table: &'static str, colonne: &'static str) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn aq2_sans_tableau(conn: &Connection, nom: &str, drapeau: Option<&str>) {
        conn.execute("DELETE FROM panel WHERE dashboard_id IN (SELECT id FROM dashboard WHERE name=?1)", params![nom]).expect("panneaux retirés");
        conn.execute("DELETE FROM dashboard WHERE name=?1", params![nom]).expect("tableau retiré");
        if let Some(d) = drapeau {
            conn.execute("DELETE FROM meta WHERE key=?1", params![d]).expect("drapeau retiré");
        }
        assert_eq!(aq2_tableaux(conn, nom), 0, "instrument : base sans « {nom} »");
    }

    fn aq2_tableaux(conn: &Connection, nom: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux")
    }

    fn aq2_id_du_gabarit(conn: &Connection, cle: &str) -> i64 {
        conn.query_row("SELECT id FROM runbook WHERE key=?1", params![cle], |r| r.get(0)).expect("gabarit")
    }

    fn aq2_ordinaux(conn: &Connection, cle: &str) -> Vec<i64> {
        let mut st = conn
            .prepare("SELECT ordinal FROM runbook_step WHERE runbook_id=(SELECT id FROM runbook WHERE key=?1) ORDER BY ordinal")
            .expect("préparée");
        st.query_map(params![cle], |r| r.get(0)).expect("lue").collect::<rusqlite::Result<Vec<i64>>>().expect("ordinaux")
    }

    /// Une étape à l'octet : (id, gabarit, ordinal, phase, titre, consigne, genre, recherche, action).
    type Aq2Etape = (i64, i64, i64, String, String, String, String, Option<String>, Option<String>);

    fn aq2_etapes(conn: &Connection) -> Vec<Aq2Etape> {
        let mut st = conn
            .prepare("SELECT id,runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind FROM runbook_step ORDER BY id")
            .expect("préparée");
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))
            .expect("lue")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("étapes")
    }

    /// Le contenu livré des étapes d'un gabarit, par ordinal (sans identifiants).
    fn aq2_contenu(etapes: &[Aq2Etape], rb: i64) -> Vec<(i64, String, String, String, String, Option<String>, Option<String>)> {
        let mut c: Vec<_> = etapes
            .iter()
            .filter(|e| e.1 == rb)
            .map(|e| (e.2, e.3.clone(), e.4.clone(), e.5.clone(), e.6.clone(), e.7.clone(), e.8.clone()))
            .collect();
        c.sort();
        c
    }

    /// Les gabarits à l'octet : (id, clé, nom, genre, clé de rapprochement, description, managé, actif, créé).
    fn aq2_gabarits(conn: &Connection) -> Vec<(i64, String, String, String, String, String, i64, i64, i64)> {
        let mut st = conn
            .prepare("SELECT id,key,name,match_kind,match_key,description,managed,active,created FROM runbook ORDER BY id")
            .expect("préparée");
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))
            .expect("lue")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("gabarits")
    }

    fn aq2_drapeaux_de_gabarits(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM meta WHERE key LIKE 'seeded\\_runbook\\_%' ESCAPE '\\'", [], |r| r.get(0)).expect("drapeaux")
    }

    // -------------------------------------------------------------------------------------
    // (a) LES LIGNES `[seed]` ENTIÈRES
    // -------------------------------------------------------------------------------------

    /// MUTANTS QUI LE ROUGISSENT : `AQ2_vue_etape` et `AQ2_vue_phrase` (le nom non lu dit « une écriture a été
    /// refusée »), `AQ2_vue_creee_non_lue` (la vue non créable dite « nom non lu »), `AQ2_rb_ok0` (l'enfant échoue :
    /// l'ordinal suivant écrit).
    #[test]
    fn aq2_les_lignes_seed_entieres_en_sous_processus() {
        const ENFANT: &str = "AQ2_ENFANT_JOURNAL";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let conn = test_db();
            seed_runbooks(&conn);
            aq2_sans_tableau(&conn, AQ2_WEB, None);
            aq2_sans_tableau(&conn, AQ2_EGRESS, Some("seeded_egress"));
            println!("AQ2-ENFANT-A-JOUE");
            eprintln!("AQ2-DEBUT");
            // 1. présence non lue (semis par nom).
            aq2_refuser_la_lecture(&conn, "dashboard", "name");
            seed_web_dashboard(&conn);
            aq2_rendre_la_main(&conn);
            // 2. `BEGIN` refusé.
            conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            seed_web_dashboard(&conn);
            aq2_rendre_la_main(&conn);
            // 3. écriture refusée (un panneau).
            conn.execute_batch(&format!(
                "CREATE TRIGGER aq2_refus BEFORE INSERT ON panel WHEN NEW.dashboard_id IN (SELECT id FROM dashboard WHERE name='{AQ2_WEB}') \
                 BEGIN SELECT RAISE(ABORT,'aq2 refus'); END;"
            ))
            .expect("déclencheur de refus");
            seed_web_dashboard(&conn);
            conn.execute_batch("DROP TRIGGER aq2_refus;").expect("base revenue");
            // 4. nom de vue non lu (semis par nom), la vue présente.
            aq2_refuser_la_lecture(&conn, "view", "name");
            seed_web_dashboard(&conn);
            aq2_rendre_la_main(&conn);
            // 5. vue non créable, IGNORE puis ABORT : une écriture refusée, pas un nom non lu.
            conn.execute("UPDATE view SET name='aq2 ancienne vue' WHERE name=?1", params![AQ2_VUE_WEB]).expect("vue renommée");
            for corps in ["RAISE(IGNORE)", "RAISE(ABORT,'aq2 refus')"] {
                conn.execute_batch(&format!("CREATE TRIGGER aq2_refus BEFORE INSERT ON view WHEN NEW.name='{AQ2_VUE_WEB}' BEGIN SELECT {corps}; END;"))
                    .expect("déclencheur de refus");
                seed_web_dashboard(&conn);
                conn.execute_batch("DROP TRIGGER aq2_refus;").expect("base revenue");
            }
            // 6. nom de vue non lu (semis sous drapeau).
            aq2_refuser_la_lecture(&conn, "view", "name");
            seed_egress_dashboard(&conn);
            aq2_rendre_la_main(&conn);
            // 7. réparation d'un gabarit refusée sur son premier ordinal manquant.
            let rb = aq2_id_du_gabarit(&conn, AQ2_AMPUTE);
            conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1 AND ordinal IN (1,3)", params![rb]).expect("gabarit amputé");
            conn.execute_batch(&format!(
                "CREATE TRIGGER aq2_refus BEFORE INSERT ON runbook_step WHEN NEW.runbook_id={rb} AND NEW.ordinal=1 BEGIN SELECT RAISE(ABORT,'aq2 refus'); END;"
            ))
            .expect("déclencheur de refus");
            seed_runbooks(&conn);
            conn.execute_batch("DROP TRIGGER aq2_refus;").expect("base revenue");
            assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 2, 4], "enfant : réparation refusée, rien d'écrit");
            // 8. le nominal : aucune ligne.
            for _ in 0..2 {
                seed_web_dashboard(&conn);
                seed_egress_dashboard(&conn);
                seed_runbooks(&conn);
            }
            assert_eq!((aq2_tableaux(&conn, AQ2_WEB), aq2_tableaux(&conn, AQ2_EGRESS)), (1, 1), "enfant : semés une fois au nominal");
            assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 1, 2, 3, 4], "enfant : gabarit réparé au nominal");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::semis_vue_non_lue_banni_pass_compte_et_gabarits_repares::aq2_les_lignes_seed_entieres_en_sous_processus",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("AQ2-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lues: Vec<&str> = stderr.lines().skip_while(|l| *l != "AQ2-DEBUT").filter(|l| l.starts_with("[seed] ")).collect();
        let web = format!("[seed] le tableau de bord « {AQ2_WEB} » NON semé : ");
        let zero = rusqlite::Error::StatementChangedRows(0).to_string();
        let ecriture = |qui: &str, cause: &str| {
            format!(
                "{qui}une écriture a été refusée ({cause}) — RIEN n'est conservé (ni tableau, ni panneau, ni règle, ni drapeau), le semis sera retenté au prochain démarrage"
            )
        };
        let nom_de_vue = |qui: &str| {
            format!("{qui}le nom de sa vue n'a pas pu être lu (access to view.name is prohibited) — RIEN n'est conservé, le semis sera retenté au prochain démarrage")
        };
        let attendues: Vec<String> = vec![
            format!("{web}sa présence n'a pas pu être lue (access to dashboard.name is prohibited) — rien n'est écrit, le semis sera retenté au prochain démarrage"),
            format!("{web}transaction refusée (not authorized) — rien n'est écrit, le semis sera retenté au prochain démarrage"),
            ecriture(&web, "aq2 refus"),
            nom_de_vue(&web),
            ecriture(&web, &zero),
            ecriture(&web, "aq2 refus"),
            nom_de_vue("[seed] `seeded_egress` NON semé : "),
            ecriture(&format!("[seed] `seeded_runbook_{AQ2_AMPUTE}` NON semé : "), "aq2 refus"),
        ];
        assert_eq!(lues, attendues, "lignes [seed] entières, dans l'ordre, aucune au nominal :\n{stderr}");
    }

    // -------------------------------------------------------------------------------------
    // (b) BANNI / PASS : LE REFUS COMPTÉ AU PROVISIONNEMENT D'UN TENANT
    // -------------------------------------------------------------------------------------

    /// DEUX BASES RÉELLES semées par `seed_tenant_content` ; seule A refuse la vue « Détection » : A compte une absence
    /// après le semis, B rien (tableau présent) ; A revenue, semée entière, rien de plus.
    /// MUTANTS QUI LE ROUGISSENT : `AQ2_bp_sans_compte` (A : 0), `AQ2_bp_compte_present` (B : 1),
    /// `AQ2_tenant_sans_enrobage` (A : 0, `tenants.rs` appelle le semis nu).
    #[test]
    fn aq2_banni_pass_refuse_compte_au_provisionnement_deux_tenants() {
        let (_tmp_a, a) = aq2_base_sur_disque("aq2-tenant-a");
        let (_tmp_b, b) = aq2_base_sur_disque("aq2-tenant-b");
        for conn in [&a, &b] {
            aq2_sans_tableau(conn, NOM_DU_BANNI_PASS, None);
        }
        a.execute("UPDATE view SET name='aq2 ancienne vue' WHERE name='Détection'", []).expect("vue renommée");
        a.execute_batch("CREATE TRIGGER aq2_refus BEFORE INSERT ON view WHEN NEW.name='Détection' BEGIN SELECT RAISE(ABORT,'aq2 refus'); END;")
            .expect("déclencheur de refus");
        crate::tenants::seed_tenant_content(&a);
        crate::tenants::seed_tenant_content(&b);
        let comptes = |conn: &Connection| {
            (aq2_compte(conn, GESTE_BANNI_PASS, ETAPE_ABSENT_APRES_LE_SEMIS), aq2_compte(conn, GESTE_BANNI_PASS, ETAPE_PRESENCE_NON_LUE))
        };
        assert_eq!(aq2_tableaux(&a, NOM_DU_BANNI_PASS), 0, "A : aucun « Banni / Pass »");
        assert_eq!(comptes(&a), (1, 0), "A : l'absence après le semis est comptée une fois");
        assert_eq!(aq2_tableaux(&b, NOM_DU_BANNI_PASS), 1, "B : « Banni / Pass » semé");
        assert_eq!(comptes(&b), (0, 0), "B : un tableau présent ne compte rien");
        a.execute_batch("DROP TRIGGER aq2_refus;").expect("base revenue");
        crate::tenants::seed_tenant_content(&a);
        assert_eq!(aq2_tableaux(&a, NOM_DU_BANNI_PASS), 1, "A revenue : semé");
        assert_eq!(comptes(&a), (1, 0), "A revenue : rien de plus compté");
    }

    /// LA PRÉSENCE NON LUE (lecture de `dashboard.name` refusée seule) : rien d'écrit, comptée sous « présence non lue »
    /// (pas sous « absent après le semis ») ; lecture rendue, semé, rien de plus.
    /// MUTANT QUI LE ROUGIT : `AQ2_bp_lecture_absente` (comptée comme une absence).
    #[test]
    fn aq2_banni_pass_presence_non_lue_comptee_sans_rien_ecrire() {
        let (_tmp, conn) = aq2_base_sur_disque("aq2-bp-presence");
        aq2_sans_tableau(&conn, NOM_DU_BANNI_PASS, None);
        aq2_refuser_la_lecture(&conn, "dashboard", "name");
        seed_banpass_dashboard_et_compter_son_refus(&conn);
        aq2_rendre_la_main(&conn);
        let comptes = || (aq2_compte(&conn, GESTE_BANNI_PASS, ETAPE_ABSENT_APRES_LE_SEMIS), aq2_compte(&conn, GESTE_BANNI_PASS, ETAPE_PRESENCE_NON_LUE));
        assert_eq!(aq2_tableaux(&conn, NOM_DU_BANNI_PASS), 0, "présence non lue : rien d'écrit");
        assert!(conn.is_autocommit(), "transaction fermée");
        assert_eq!(comptes(), (0, 1), "présence non lue : comptée sous son étape");
        seed_banpass_dashboard_et_compter_son_refus(&conn);
        assert_eq!(aq2_tableaux(&conn, NOM_DU_BANNI_PASS), 1, "lecture rendue : semé");
        assert_eq!(comptes(), (0, 1), "lecture rendue : rien de plus compté");
    }

    // -------------------------------------------------------------------------------------
    // (c) À (e) GABARITS DE RUNBOOK
    // -------------------------------------------------------------------------------------

    /// RÉPARATION : un managé amputé des ordinaux 1 et 3 ET désactivé, drapeau posé ; un managé vidé sans drapeau ; une
    /// clé portée par un gabarit non managé, amputée -> seuls les deux premiers sont complétés, au contenu livré ; le
    /// désactivé reste désactivé ; tout le reste à l'octet ; rejoué, rien de plus ; le marqueur `seeded_runbooks` absent.
    /// MUTANTS QUI LE ROUGISSENT : `AQ2_rb_drapeau_seul` (l'amputé drapeau posé n'est pas réparé),
    /// `AQ2_rb_tout_reecrire` (ordinaux présents doublés), `AQ2_rb_non_manage_repare` (le non managé complété),
    /// `AQ2_marqueur` (marqueur écrit).
    #[test]
    fn aq2_gabarit_manage_ampute_repare_seul_le_reste_a_l_octet() {
        let (_tmp, conn) = aq2_base_sur_disque("aq2-reparation");
        seed_runbooks(&conn);
        let livre = aq2_etapes(&conn);
        let ampute = aq2_id_du_gabarit(&conn, AQ2_AMPUTE);
        let vide = aq2_id_du_gabarit(&conn, AQ2_VIDE_SANS_DRAPEAU);
        let non_manage = aq2_id_du_gabarit(&conn, AQ2_NON_MANAGE);
        let contenu_ampute = aq2_contenu(&livre, ampute);
        let contenu_vide = aq2_contenu(&livre, vide);
        assert_eq!((contenu_ampute.len(), contenu_vide.len()), (5, 5), "instrument : gabarits livrés à cinq étapes");
        conn.execute_batch(&format!(
            "DELETE FROM runbook_step WHERE runbook_id={ampute} AND ordinal IN (1,3);
             UPDATE runbook SET active=0 WHERE id={ampute};
             DELETE FROM runbook_step WHERE runbook_id={vide};
             DELETE FROM meta WHERE key='seeded_runbook_{AQ2_VIDE_SANS_DRAPEAU}';
             UPDATE runbook SET managed=0 WHERE id={non_manage};
             DELETE FROM runbook_step WHERE runbook_id={non_manage} AND ordinal=2;"
        ))
        .expect("gabarits amputés");
        let gabarits_avant = aq2_gabarits(&conn);
        let etapes_avant = aq2_etapes(&conn);
        let drapeaux_avant = aq2_drapeaux_de_gabarits(&conn);

        seed_runbooks(&conn);
        let etapes_apres = aq2_etapes(&conn);
        assert_eq!(aq2_contenu(&etapes_apres, ampute), contenu_ampute, "amputé : ses ordinaux manquants réécrits au contenu livré");
        assert_eq!(aq2_contenu(&etapes_apres, vide), contenu_vide, "vidé sans drapeau : ses étapes réécrites");
        assert_eq!(aq2_ordinaux(&conn, AQ2_NON_MANAGE), vec![0, 1, 3, 4], "non managé : jamais touché");
        let neuves: Vec<&Aq2Etape> = etapes_apres.iter().filter(|e| !etapes_avant.contains(e)).collect();
        assert_eq!(neuves.len(), 7, "deux étapes pour l'amputé, cinq pour le vidé, rien d'autre");
        assert!(neuves.iter().all(|e| e.1 == ampute || e.1 == vide), "aucune étape neuve ailleurs");
        assert!(etapes_avant.iter().all(|e| etapes_apres.contains(e)), "chaque étape d'avant inchangée à l'octet");
        assert_eq!(aq2_gabarits(&conn), gabarits_avant, "gabarits inchangés à l'octet : le désactivé reste désactivé");
        let actif: i64 = conn.query_row("SELECT active FROM runbook WHERE id=?1", params![ampute], |r| r.get(0)).expect("actif");
        assert_eq!(actif, 0, "le gabarit désactivé garde son état");
        assert_eq!(aq2_drapeaux_de_gabarits(&conn), drapeaux_avant + 1, "le drapeau du vidé posé, les autres gardés");
        assert_eq!(
            (aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_ECRITURE_REFUSEE), aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_PRESENCE_NON_LUE)),
            (0, 0),
            "la réparation validée ne compte rien"
        );
        let marqueur: i64 = conn.query_row("SELECT COUNT(*) FROM meta WHERE key='seeded_runbooks'", [], |r| r.get(0)).expect("marqueur");
        assert_eq!(marqueur, 0, "le marqueur sans lecteur n'est plus écrit");

        seed_runbooks(&conn);
        assert_eq!(aq2_etapes(&conn), etapes_apres, "rejoué : rien de plus");
    }

    /// LA RÉPARATION REFUSÉE sur le PREMIER ordinal manquant (1), `RAISE(IGNORE)` puis `RAISE(ABORT)` : le SUIVANT (3)
    /// n'est pas écrit non plus, transaction fermée, drapeau gardé, compté une fois sous « écriture ou COMMIT refusé » ;
    /// base revenue, repris entier.
    /// MUTANTS QUI LE ROUGISSENT : `AQ2_rb_ok0` (IGNORE : l'ordinal 3 écrit), `AQ2_rb_sans_compte` (rien compté).
    #[test]
    fn aq2_reparation_refusee_rien_d_ecrit_comptee_puis_reprise() {
        let formes = [("IGNORE", "RAISE(IGNORE)"), ("ABORT", "RAISE(ABORT,'aq2 refus')")];
        let mut joues = 0;
        for (forme, corps) in formes {
            let (_tmp, conn) = aq2_base_sur_disque("aq2-reparation-refusee");
            seed_runbooks(&conn);
            let rb = aq2_id_du_gabarit(&conn, AQ2_AMPUTE);
            conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1 AND ordinal IN (1,3)", params![rb]).expect("gabarit amputé");
            conn.execute_batch(&format!(
                "CREATE TRIGGER aq2_refus BEFORE INSERT ON runbook_step WHEN NEW.runbook_id={rb} AND NEW.ordinal=1 BEGIN SELECT {corps}; END;"
            ))
            .expect("déclencheur de refus");
            let drapeaux = aq2_drapeaux_de_gabarits(&conn);
            seed_runbooks(&conn);
            assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 2, 4], "({forme}) premier refusé : le suivant n'est pas écrit non plus");
            assert!(conn.is_autocommit(), "({forme}) transaction fermée");
            assert_eq!(aq2_drapeaux_de_gabarits(&conn), drapeaux, "({forme}) drapeaux gardés");
            assert_eq!(aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_ECRITURE_REFUSEE), 1, "({forme}) compté une fois");
            conn.execute_batch("DROP TRIGGER aq2_refus;").expect("base revenue");
            seed_runbooks(&conn);
            assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 1, 2, 3, 4], "({forme}) base revenue : réparé");
            assert_eq!(aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_ECRITURE_REFUSEE), 1, "({forme}) rien de plus compté");
            joues += 1;
        }
        assert_eq!(joues, 2, "les deux formes sont jouées");
    }

    /// LE DRAPEAU ILLISIBLE SEUL (`meta.key`), PUIS LES ÉTAPES ILLISIBLES SEULES (`runbook_step.ordinal`) : rien d'écrit,
    /// chaque gabarit compté sous « présence non lue » (jamais une absence, jamais un gabarit complet) ; lecture rendue,
    /// réparé, rien de plus.
    /// MUTANTS QUI LE ROUGISSENT : `AQ2_rb_drapeau_ok` (drapeau illisible pris pour une absence : réparé, rien compté),
    /// `AQ2_rb_etat_illisible_complet` (étapes illisibles prises pour un gabarit complet : rien compté).
    #[test]
    fn aq2_drapeau_ou_etapes_illisibles_rien_d_ecrit_presence_non_lue() {
        let (_tmp, conn) = aq2_base_sur_disque("aq2-illisible");
        seed_runbooks(&conn);
        let gabarits = i64::try_from(aq2_gabarits(&conn).len()).expect("nombre");
        assert!(gabarits >= 15, "instrument : les gabarits livrés sont semés ({gabarits})");
        let gabarits = u64::try_from(gabarits).expect("nombre");
        let rb = aq2_id_du_gabarit(&conn, AQ2_AMPUTE);
        conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1 AND ordinal=1", params![rb]).expect("gabarit amputé");
        let comptes =
            || (aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_PRESENCE_NON_LUE), aq2_compte(&conn, GESTE_GABARIT_DE_RUNBOOK, ETAPE_ECRITURE_REFUSEE));

        aq2_refuser_la_lecture(&conn, "meta", "key");
        seed_runbooks(&conn);
        aq2_rendre_la_main(&conn);
        assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 2, 3, 4], "drapeau illisible : rien d'écrit");
        assert_eq!(comptes(), (gabarits, 0), "drapeau illisible : chaque gabarit compté sous « présence non lue »");

        aq2_refuser_la_lecture(&conn, "runbook_step", "ordinal");
        seed_runbooks(&conn);
        aq2_rendre_la_main(&conn);
        assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 2, 3, 4], "étapes illisibles : rien d'écrit");
        assert_eq!(comptes(), (2 * gabarits, 0), "étapes illisibles : chaque gabarit compté sous « présence non lue »");
        assert!(conn.is_autocommit(), "aucune transaction ouverte");

        seed_runbooks(&conn);
        assert_eq!(aq2_ordinaux(&conn, AQ2_AMPUTE), vec![0, 1, 2, 3, 4], "lecture rendue : réparé");
        assert_eq!(comptes(), (2 * gabarits, 0), "lecture rendue : rien de plus compté");
    }

    // -------------------------------------------------------------------------------------
    // (f) LE `# HELP` DE LA SÉRIE
    // -------------------------------------------------------------------------------------

    /// MUTANT QUI LE ROUGIT : `AQ2_aide_ancienne` (l'aide d'avant, sans les semis).
    #[test]
    fn aq2_aide_de_la_serie_cite_les_semis() {
        let prom = crate::comptes_de_transaction::exposition_prom(&json!({ "scheduler": { "gestes_de_fond_non_valides_total": 0 } }));
        let aide = prom.lines().find(|l| l.starts_with("# HELP plume_scheduler_gestes_de_fond_non_valides_total ")).expect("la série est documentée");
        let termes = [
            "journal seed",
            "tableaux de bord semés par nom ou sous drapeau",
            "règles semées par nom",
            "tableau de bord Banni / Pass",
            "gabarits de runbook managés semés ou réparés",
            "présence non lue",
            "nom de vue non lu",
            "tableau absent après son semis",
            "P10.28-l",
            "P10.28-k",
            "/api/system/metrics scheduler.gestes_de_fond_non_valides",
        ];
        for terme in table_declaree!(termes) {
            assert!(aide.contains(terme), "le # HELP cite « {terme} » : {aide}");
        }
    }
}
