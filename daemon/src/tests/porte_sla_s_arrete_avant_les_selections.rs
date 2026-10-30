// =====================================================================================
// `P10.31-v` — LA PORTE DU TOUR SLA EFFACE PUIS S'ARRÊTE, ET LE BRAS « ZÉRO EFFACÉ » NE JOURNALISE RIEN.
//
// CE QUI MANQUAIT, LU SUR lot-BB5 (0466b8fd) : le commentaire de la porte (`sla_multilevel_tick_par`, caseops.rs) dit
// que, sans politique active, le tour efface les échéances d'une politique inactive « puis s'arrête avant les
// sélections », et citait un seul témoin (`epi_sans_aucune_politique_active_l_effacement_a_lieu_quand_meme`), qui ne
// tient que l'effacement : retirer le `return` de la porte le laissait vert. La preuve « hors d'atteinte » du bras
// `effaces == 0` disait qu'un écrivain d'un autre processus était la SEULE voie, et oubliait un déclencheur
// `BEFORE UPDATE` qui rend `RAISE(IGNORE)`.
// CE QU'ILS TIENNENT :
//   · l'arrêt : sans politique active, le tour efface, puis ne PRÉPARE aucune sélection (l'autorisateur de la
//     connexion, qui laisse tout passer, compte les lectures de `incident.title`, colonne que seules les deux
//     sélections lisent : 0), et n'envoie rien ; contrôle positif : avec une politique active, les sélections sont
//     préparées (au moins une lecture comptée) et le dépassement est notifié ;
//   · le bras `effaces == 0` : un déclencheur `BEFORE UPDATE ... RAISE(IGNORE)` sur `incident` fait rendre `Ok(0)` à
//     l'effacement, les échéances restent, et le tour n'écrit AUCUNE ligne « [plume] chrono SLA » (stderr d'un
//     sous-processus, lu en entier pour sa phase).
// MUTANTS (VERIF_MUT, posés sous `cfg!(test)` puis retirés avant le commit) : `BC5_PORTE_SANS_RETOUR` (le `return` de
// la porte retiré : lectures du titre comptées), `BC5_ZERO_JOURNALISE` (`effaces > 0` remplacé par `effaces >= 0` :
// la ligne « 0 dossier(s) » sort).
// CE QU'ILS NE TIENNENT PAS : l'écrivain d'un autre processus (même issue `Ok(0)`, non rejoué ici : la voie du
// déclencheur atteint le même bras).
// =====================================================================================
mod porte_sla_s_arrete_avant_les_selections {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PAS_PENDANTE: i64 = 999;
    const PAS_ENFANT: &str = "PAS_ENFANT_RAISE_IGNORE";
    const PAS_PHASE: &str = "PAS-PHASE:";
    const PAS_IGNORE: &str = "CREATE TRIGGER pas_ignore BEFORE UPDATE ON incident BEGIN SELECT RAISE(IGNORE); END;";

    fn pas_sql(conn: &Connection, sql: &str) {
        conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn pas_entier(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get::<_, i64>(0)).expect("fixture : la valeur se lit")
    }

    fn pas_base() -> Connection {
        let conn = test_db();
        pas_sql(&conn, "DELETE FROM incident; DELETE FROM sla_policy;");
        conn.execute(
            "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('pas','webhook',1,'https://example.invalid/h',0,'{}')",
            [],
        )
        .unwrap();
        conn
    }

    fn pas_politique(conn: &Connection, nom: &str, priorite: i64) -> i64 {
        conn.execute(
            "INSERT INTO sla_policy(name,priority,ack_target_s,resolve_target_s,enabled,created,created_by,updated) VALUES(?1,?2,60,600,1,0,'root',0)",
            params![nom, priorite],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn pas_dossier(conn: &Connection, titre: &str, priorite: i64, reglage: &str) -> i64 {
        let id = dossier_seme(conn, "alice", titre, 4, "", Some("alice"), priorite);
        pas_sql(conn, &format!("UPDATE incident SET {reglage} WHERE id={id}"));
        id
    }

    fn pas_echeances(conn: &Connection) -> i64 {
        pas_entier(conn, "SELECT COUNT(*) FROM incident WHERE ack_due IS NOT NULL OR resolve_due IS NOT NULL")
    }

    fn pas_tick(db: &Arc<Mutex<Connection>>) -> usize {
        let mut envois = 0usize;
        sla_multilevel_tick_par(db, &mut |_k: &str, _u: &str, _c: &Value, _s: i64, _t: &str, _d: &str, _h: &str, _n: i64| {
            envois += 1;
            true
        });
        envois
    }

    /// Autorisateur qui laisse TOUT passer et compte les lectures de `incident.title` (lue par les deux sélections du
    /// tour, par aucun autre énoncé avant elles).
    fn pas_compter_les_lectures_du_titre(conn: &Connection) -> Arc<AtomicUsize> {
        let lectures = Arc::new(AtomicUsize::new(0));
        let compte = lectures.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            if let AuthAction::Read { table_name: "incident", column_name: "title" } = ctx.action {
                compte.fetch_add(1, Ordering::SeqCst);
            }
            Authorization::Allow
        }));
        lectures
    }

    /// CE QU'IL TIENT (l'arrêt) : P2 gouverne B (échu), puis P2 est désactivée par un `UPDATE` brut ; AUCUNE politique
    /// active. Après un tour : B est effacé, rien n'est envoyé, et AUCUNE lecture de `incident.title` n'a été préparée.
    /// Contrôle positif (même instrument) : P1 active gouverne A échu : lectures du titre comptées, A notifié.
    /// MUTATION QUI LE FAIT ROUGIR : `BC5_PORTE_SANS_RETOUR` (les sélections sont préparées : lectures > 0).
    #[test]
    fn pas_sans_politique_active_le_tour_efface_puis_ne_prepare_aucune_selection() {
        let t = now();
        let conn = pas_base();
        let p2 = pas_politique(&conn, "P2", 2);
        let b = pas_dossier(&conn, "B", 2, &format!("ack_due={}, resolve_due={}", t - 100, t - 100));
        assert_eq!(pas_entier(&conn, &format!("SELECT COALESCE(sla_policy_id,0) FROM incident WHERE id={b}")), p2, "fixture : B gouverné par P2");
        pas_sql(&conn, &format!("UPDATE sla_policy SET enabled=0 WHERE id={p2}"));
        assert_eq!(pas_entier(&conn, "SELECT COUNT(*) FROM sla_policy WHERE enabled=1"), 0, "fixture : aucune politique active");
        assert_eq!(pas_echeances(&conn), 1, "fixture : B porte des échéances");
        let lectures = pas_compter_les_lectures_du_titre(&conn);
        let db = Arc::new(Mutex::new(conn));
        let envois = pas_tick(&db);
        db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(pas_echeances(&db.lock()), 0, "B effacé avant la porte");
        assert_eq!(envois, 0, "rien n'est envoyé");
        assert_eq!(lectures.load(Ordering::SeqCst), 0, "sans politique active, aucune sélection n'est préparée");

        // Contrôle positif : l'instrument voit les sélections quand la porte s'ouvre.
        let conn = pas_base();
        pas_politique(&conn, "P1", 1);
        pas_dossier(&conn, "A", 1, &format!("ack_due={}, resolve_due={}", t - 100, t - 100));
        let lectures = pas_compter_les_lectures_du_titre(&conn);
        let db = Arc::new(Mutex::new(conn));
        let envois = pas_tick(&db);
        db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(lectures.load(Ordering::SeqCst) >= 1, "contrôle : les sélections lisent incident.title");
        assert_eq!(envois, 2, "contrôle : A notifié (acquittement et résolution)");
    }

    /// CE QU'IL TIENT (bras `effaces == 0`) : un dossier à identifiant de politique pendant porte des échéances ; un
    /// déclencheur `BEFORE UPDATE ... RAISE(IGNORE)` sur `incident` saute la ligne. L'effacement rend `Ok(0)`, les
    /// échéances restent, et le tour (tenant nommé) n'écrit AUCUNE ligne « [plume] chrono SLA » ; rejoué sans le
    /// déclencheur, il écrit la ligne « 1 dossier(s) » (contrôle : la capture voit bien le journal du tour).
    /// MUTATION QUI LE FAIT ROUGIR : `BC5_ZERO_JOURNALISE` (ligne « 0 dossier(s) » dans la phase du déclencheur).
    #[test]
    fn pas_un_declencheur_raise_ignore_rend_zero_efface_et_le_tour_ne_journalise_rien() {
        if std::env::var(PAS_ENFANT).is_ok() {
            let t = now();
            let conn = pas_base();
            pas_dossier(&conn, "O", 2, &format!("sla_policy_id={PAS_PENDANTE}, ack_due={}, resolve_due={}", t - 500, t - 500));
            pas_sql(&conn, PAS_IGNORE);
            println!(
                "PAS-EFFACEMENT-DIRECT:{:?}",
                crate::handlers::caseops::effacer_les_echeances_d_une_politique_inactive(&conn)
            );
            let db = Arc::new(Mutex::new(conn));
            eprintln!("{PAS_PHASE}ignore");
            {
                let _tenant = crate::metrics::nommer_le_tenant_du_tour("t-pas");
                pas_tick(&db);
            }
            eprintln!("{PAS_PHASE}sans-declencheur");
            println!("PAS-ECHEANCES-ignore:{}", pas_echeances(&db.lock()));
            pas_sql(&db.lock(), "DROP TRIGGER pas_ignore");
            {
                let _tenant = crate::metrics::nommer_le_tenant_du_tour("t-pas");
                pas_tick(&db);
            }
            eprintln!("{PAS_PHASE}fin");
            println!("PAS-ECHEANCES-sans-declencheur:{}", pas_echeances(&db.lock()));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::porte_sla_s_arrete_avant_les_selections::pas_un_declencheur_raise_ignore_rend_zero_efface_et_le_tour_ne_journalise_rien",
            ])
            .env(PAS_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // `--nocapture` : la première ligne suit le nom du test sur la même ligne.
        let bilans: Vec<&str> = stdout.lines().filter_map(|l| l.find("PAS-").map(|i| &l[i..])).collect();
        assert_eq!(
            bilans,
            vec!["PAS-EFFACEMENT-DIRECT:Ok(0)", "PAS-ECHEANCES-ignore:1", "PAS-ECHEANCES-sans-declencheur:0"],
            "bilans : {stdout}\n{stderr}"
        );
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PAS_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PAS_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] chrono SLA")).map(str::to_string).collect()
        };
        assert_eq!(phase("ignore"), Vec::<String>::new(), "zéro effacé : aucune ligne de journal");
        assert_eq!(
            phase("sans-declencheur"),
            vec!["[plume] chrono SLA (tenant 't-pas') : 1 dossier(s) portaient les échéances d'une politique désactivée ou disparue : sla_policy_id, ack_due et resolve_due effacés (régime legacy), marqueurs de dépassement conservés".to_string()],
            "contrôle : sans le déclencheur, la ligne entière sort"
        );
    }
}
