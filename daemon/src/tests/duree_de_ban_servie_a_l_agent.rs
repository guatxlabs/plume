// =====================================================================================
// `P11.25-a` (volet agent) — LA FILE D'ACTIONS REMISE À UN AGENT PORTE LA DURÉE DU BAN.
//
// AVANT (base `212614c0`) : `actions_pending` (`handlers/actions.rs`) servait `SELECT id,kind,target,dry_run` en
// TSV à quatre champs ; l'agent d'un hôte distant (`collectors/respond.sh`) bannissait donc avec sa propre durée
// (`PLUME_BAN_DURATION`, 4 h) pendant que l'approbation, le miroir HTTP et la commande CrowdSec du responder local
// appliquaient `action.ban_ttl_s`. L'énoncé local `ACTIONS_A_RECLAMER_ICI` a la même forme, mais le responder local
// relit déjà la durée par `duree_de_ban_de_la_riposte` avant d'exécuter un ban.
//
// CE QUI NE TENAIT PAS DANS L'ÉNONCÉ : la route ne sert pas du JSON mais du TSV. Un cinquième champ casserait
// l'agent déjà déployé (`read -r id kind target dry` : `dry` vaudrait `1<TAB>3600`, une riposte simulée serait
// appliquée). APRÈS : le TSV reste la forme par défaut, à l'octet ; un agent qui envoie
// `Accept: application/x-ndjson` reçoit un objet JSON par ligne, où un `ban_ip` porte `"ban_ttl_s": <entier>`
// (la durée effective, en secondes) et où aucun autre genre ne le porte. `kill_pid` et `stop_service` ne sont
// jamais servis par cette route (`CONDITION_DE_RECLAMATION_D_AGENT` : `ban_ip` et `unban_ip` seuls).
//
// CE QUE CES TÉMOINS TIENNENT, par la route `actions_pending` (jeton d'agent lié à un hôte) :
//   * forme JSON par ligne : un ban posé par l'écrivain des playbooks à 5400 s porte 5400, un ban sans durée
//     porte le défaut (14400), un `unban_ip` dont la colonne vaut 7200 ne porte pas le champ, `kill_pid` et
//     `stop_service` approuvés ne sont ni servis ni réclamés ; corps comparé ENTIER à un littéral, type de contenu ;
//   * forme par défaut : sans en-tête, ou avec un autre type, le TSV d'avant à l'octet ; l'en-tête est lu parmi
//     plusieurs types, avec paramètres, sans égard à la casse ;
//   * durée illisible (BLOB en tête et au milieu, 0 hors borne) : action ni servie ni réclamée, laissée
//     `approved` ; la ligne de journal comparée ENTIÈRE à un littéral (sous-processus) ; les autres servies ; le
//     TSV la retient aussi ; une page dont seules restent des illisibles rend 200 vide, pas le 503 de réclamation ;
//     une illisible non assignée reste sans hôte ; cent illisibles en tête ne masquent pas la suite de la file ;
//   * un tour remet au plus cent actions, la page suivante ne remettant que ce qui manque ; une lecture ou une
//     réclamation ratée en page suivante sert les actions déjà réclamées (200, corps entier) au lieu d'un 503,
//     la lecture ratée laissant sa ligne entière au journal ; cent remises, la page suivante n'est pas lue ;
//   * rien remis (cent retenues en première page) puis lecture ou réclamation ratée en page suivante : 503 nommé,
//     corps entier, jamais un 200 vide ; le plafond compte les remises, pas les réclamations sans effet (la
//     page suivante complète jusqu'à cent) ; après le plafond, aucune ligne n'est lue pour sa durée (journal) ;
//   * la page suivante commence après la dernière lue : sur deux pages pleines de retenues, chacune a une ligne
//     de journal par tour, pas une de plus ;
//   * un poids nul (`q=0`) sur le type JSON par ligne est un refus : TSV ;
//   * un joker (`*/*`, celui qu'envoie le `curl` de `respond.sh`, `application/*`) ne demande pas le JSON : TSV à
//     quatre champs à l'octet par la route ;
//   * la colonne corrigée libère l'action au tour suivant, avec sa durée.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `BT1_TOUT_GENRE`, `BT1_OMIS`,
// `BT1_DEFAUT`, `BT1_ILLISIBLE_SERVIE`, `BT1_BREAK`, `BT1_JOURNAL_SANS_CAUSE`, `BT1_TOUJOURS_TSV`,
// `BT1_TOUJOURS_JSON`, `BT1_ACCEPT_SANS_VIRGULE`, `BT1_ACCEPT_SANS_PARAMETRE`, `BT1_ACCEPT_CASSE`,
// `BT1_ANOMALIE`, `BT1_RECLAMEE_SANS_DUREE`, `BT1_TYPE_DE_CONTENU`, `BT1_ACCEPT_PREMIERE_LIGNE`,
// `BT1_ACCEPT_PREFIXE`, `BT1_RETENUE_ASSIGNEE`, `BT1_PAGE_UNIQUE` ; puis `BU1_SANS_PLAFOND`, `BU1_PLAFOND_STRICT`,
// `BU1_COMPTE_STRICT`, `BU1_COMPTE_RETIRE`, `BU1_LECTURE_503`, `BU1_LECTURE_MUETTE`, `BU1_RECLAMATION_503`,
// `BU1_Q_IGNORE`, `BU1_Q_CASSE` ; puis `BU1C_CURSEUR_PREMIER`, `BU1C_SQL_GE` ; puis `W1_JOKER` ; puis `A13`, `A14`,
// `B12`, `B18`.
//
// CE QU'ILS NE TIENNENT PAS : l'agent lui-même (`collectors/respond.sh`, zone de la console) n'envoie pas encore
// l'en-tête et ne lit pas le champ.
// =====================================================================================
mod duree_de_ban_servie_a_l_agent {
    use super::*;
    use crate::handlers::mise_en_file_de_riposte::RiposteMiseEnFile;
    use crate::handlers::playbooks::poser_la_riposte_du_playbook;

    const DBS_HOTE: &str = "hote-dbs";
    const DBS_NDJSON: &str = "application/x-ndjson";
    /// La phrase d'une durée de riposte non lue et le texte du moteur, recopiés (leçon AS2).
    const DBS_DUREE_NON_LUE: &str = "durée du ban de cette riposte NON lue (colonne ban_ttl_s illisible ou hors borne) — rien n'est posé avec une durée devinée";
    const DBS_MOTEUR_BLOB: &str = "Invalid column type Blob at index: 0, name: ban_ttl_s";
    const DBS_MOTEUR_ZERO: &str = "Integer 0 out of range at index 0";

    fn dbs_base(chemin: &str) {
        let conn = open_db(chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture `P11.25-a` : la chaîne de migrations doit aller au bout");
        conn.execute_batch("DELETE FROM playbook; DELETE FROM action; DELETE FROM net_ban;").unwrap();
    }

    fn dbs_agent() -> AuthUser {
        AuthUser {
            name: DBS_HOTE.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
            method: "token".into(), csrf: String::new(), env: None,
        }
    }

    fn dbs_entetes(accept: Option<&str>) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if let Some(v) = accept {
            h.insert(axum::http::header::ACCEPT, axum::http::HeaderValue::from_str(v).unwrap());
        }
        h
    }

    /// (statut, type de contenu, corps) servis par la route.
    async fn dbs_servir(st: &AppState, accept: Option<&str>) -> (u16, String, String) {
        let r = actions_pending(State(st.clone()), Extension(dbs_agent()), dbs_entetes(accept)).await;
        let statut = r.status().as_u16();
        let genre = r.headers().get(axum::http::header::CONTENT_TYPE).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (statut, genre, String::from_utf8(corps.to_vec()).unwrap())
    }

    fn dbs_inserer(conn: &Connection, id: i64, genre: &str, cible: &str, simulee: i64, duree: &str) {
        conn.execute(
            &format!("INSERT INTO action(id,ts,kind,target,status,dry_run,reason,host,ban_ttl_s) VALUES(?1,1000,?2,?3,'approved',?4,'dbs',?5,{duree})"),
            params![id, genre, cible, simulee, DBS_HOTE],
        )
        .unwrap();
    }

    /// Les deux bans passent par l'écrivain des playbooks (`poser_la_riposte_du_playbook`), à 5400 s puis sans durée.
    fn dbs_page_lisible(conn: &Connection) -> (i64, i64) {
        let pose = |cible: &str, simulee: i64, duree: Option<i64>| match poser_la_riposte_du_playbook(conn, 1000, "ban_ip", cible, "approved", simulee, "dbs", Some(DBS_HOTE), duree) {
            RiposteMiseEnFile::Posee(id) => id,
            RiposteMiseEnFile::NonEcrite(c) => panic!("fixture : riposte non posée ({c})"),
        };
        let propre = pose("203.0.113.71", 0, Some(5400));
        let defaut = pose("203.0.113.72", 1, None);
        dbs_inserer(conn, 900, "unban_ip", "203.0.113.73", 0, "7200");
        dbs_inserer(conn, 901, "kill_pid", "424251", 0, "5400");
        dbs_inserer(conn, 902, "stop_service", "dbs-svc", 0, "5400");
        (propre, defaut)
    }

    fn dbs_reclamee(conn: &Connection, id: i64) -> Option<i64> {
        conn.query_row("SELECT claimed_ts FROM action WHERE id=?1", [id], |r| r.get(0)).unwrap()
    }

    /// CE QU'IL TIENT : sous `Accept: application/x-ndjson`, le corps ENTIER — `ban_ttl_s` = 5400 pour le ban du
    /// playbook à durée posée, 14400 (le défaut) pour le ban sans durée, absent pour `unban_ip` (colonne à 7200) ;
    /// `kill_pid` et `stop_service` ni servis ni réclamés ; les trois servis réclamés. MUTATIONS : `BT1_TOUT_GENRE`,
    /// `BT1_OMIS`, `BT1_DEFAUT`, `BT1_TOUJOURS_TSV`, `BT1_TYPE_DE_CONTENU`.
    #[tokio::test]
    async fn dbs_la_forme_json_porte_la_duree_effective_d_un_ban_et_seulement_d_un_ban() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-json");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        let (propre, defaut) = dbs_page_lisible(&st.db.lock());
        assert!(propre < defaut && defaut < 900, "fixture : ordre des identifiants");
        let (statut, genre, corps) = dbs_servir(&st, Some(DBS_NDJSON)).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(genre, "application/x-ndjson");
        let attendu = format!(
            "{{\"ban_ttl_s\":5400,\"dry_run\":false,\"id\":{propre},\"kind\":\"ban_ip\",\"target\":\"203.0.113.71\"}}\n\
             {{\"ban_ttl_s\":14400,\"dry_run\":true,\"id\":{defaut},\"kind\":\"ban_ip\",\"target\":\"203.0.113.72\"}}\n\
             {{\"dry_run\":false,\"id\":900,\"kind\":\"unban_ip\",\"target\":\"203.0.113.73\"}}\n"
        );
        assert_eq!(corps, attendu, "corps entier");
        let c = st.db.lock();
        for id in [propre, defaut, 900] {
            assert!(dbs_reclamee(&c, id).is_some(), "action {id} servie : réclamée");
        }
        for id in [901, 902] {
            assert_eq!(dbs_reclamee(&c, id), None, "action {id} (ni ban ni levée) : ni servie ni réclamée");
        }
    }

    /// CE QU'IL TIENT : sans en-tête, et avec `application/json`, le TSV d'avant à l'octet, sans durée.
    /// MUTATIONS : `BT1_TOUJOURS_JSON`.
    #[tokio::test]
    async fn dbs_sans_l_en_tete_le_tsv_d_avant_a_l_octet() {
        for accept in [None, Some("application/json")] {
            let chemin = crate::tmp_possede::TmpDb::neuf("dbs-tsv");
            dbs_base(&chemin);
            let st = ds_file_state(&chemin);
            let (propre, defaut) = dbs_page_lisible(&st.db.lock());
            let (statut, genre, corps) = dbs_servir(&st, accept).await;
            assert_eq!(statut, 200, "{accept:?} : {corps}");
            assert_eq!(genre, "text/plain; charset=utf-8", "{accept:?}");
            let attendu = format!("{propre}\tban_ip\t203.0.113.71\t0\n{defaut}\tban_ip\t203.0.113.72\t1\n900\tunban_ip\t203.0.113.73\t0\n");
            assert_eq!(corps, attendu, "{accept:?} : TSV à l'octet");
        }
    }

    /// CE QU'IL TIENT : l'en-tête `Accept` est lu parmi plusieurs types, avec paramètres, sans égard à la casse ; un
    /// autre type rend le TSV, y compris un type VOISIN (`application/x-ndjsonx`, `application/x-ndjson-v2`) ; un
    /// en-tête réparti sur deux lignes est lu en entier. MUTATIONS : `BT1_ACCEPT_PREMIERE_LIGNE`,
    /// `BT1_ACCEPT_PREFIXE`, : `BT1_ACCEPT_SANS_VIRGULE`, `BT1_ACCEPT_SANS_PARAMETRE`, `BT1_ACCEPT_CASSE`.
    #[test]
    fn dbs_l_en_tete_accept_est_lu_type_par_type() {
        use crate::handlers::actions::FormeDeLaFileDActions as F;
        for (accept, attendue) in [
            ("application/x-ndjson", F::JsonParLigne),
            ("text/plain, application/x-ndjson", F::JsonParLigne),
            ("application/x-ndjson;q=0.9", F::JsonParLigne),
            ("Application/X-NDJSON", F::JsonParLigne),
            ("application/json", F::Tsv),
            ("text/plain", F::Tsv),
            // Types voisins : le type est comparé EN ENTIER, pas par préfixe.
            ("application/x-ndjsonx", F::Tsv),
            ("application/x-ndjson-v2", F::Tsv),
            ("application/x-ndjson.v2;q=1", F::Tsv),
        ] {
            assert_eq!(F::demandee(&dbs_entetes(Some(accept))), attendue, "Accept: {accept}");
        }
        assert_eq!(F::demandee(&dbs_entetes(None)), F::Tsv, "sans en-tête");
        // Un en-tête `Accept` réparti sur plusieurs lignes : toutes sont lues, pas seulement la première.
        for (lignes, attendue) in [
            (["text/plain", "application/x-ndjson"], F::JsonParLigne),
            (["application/x-ndjson", "text/plain"], F::JsonParLigne),
            (["text/plain", "application/json"], F::Tsv),
        ] {
            let mut h = axum::http::HeaderMap::new();
            for v in lignes {
                h.append(axum::http::header::ACCEPT, axum::http::HeaderValue::from_static(v));
            }
            assert_eq!(h.get_all(axum::http::header::ACCEPT).iter().count(), 2, "fixture : deux lignes");
            assert_eq!(F::demandee(&h), attendue, "Accept sur deux lignes : {lignes:?}");
        }
    }

    /// CE QU'IL TIENT (sous-processus, pour lire le journal) : page [BLOB, ban 5400, 0, unban, BLOB, ban NULL] ;
    /// en JSON, les trois lisibles servies (corps entier), les trois illisibles ni servies ni réclamées, laissées
    /// `approved` sans hôte changé (la 15, non assignée, reste sans hôte), chacune avec sa ligne de journal
    /// ENTIÈRE ; puis un second tour en TSV (forme
    /// par défaut) : 200, corps vide (pas le 503 de réclamation), les illisibles toujours retenues et redites.
    /// MUTATIONS : `BT1_ILLISIBLE_SERVIE`, `BT1_BREAK`, `BT1_JOURNAL_SANS_CAUSE`, `BT1_ANOMALIE`,
    /// `BT1_RECLAMEE_SANS_DUREE`, `BT1_RETENUE_ASSIGNEE`.
    #[test]
    fn dbs_une_duree_illisible_retient_l_action_et_le_dit_au_journal() {
        const ENFANT: &str = "DBS_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let base = std::env::var("DBS_BASE").expect("base transmise");
            let bac = std::path::PathBuf::from(std::env::var("DBS_BAC").expect("bac transmis"));
            let st = ds_file_state(&base);
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            for (tour, accept) in [("json", Some(DBS_NDJSON)), ("tsv", None)] {
                let (statut, _, corps) = rt.block_on(dbs_servir(&st, accept));
                std::fs::write(bac.join(format!("{tour}.statut")), statut.to_string()).unwrap();
                std::fs::write(bac.join(format!("{tour}.corps")), corps).unwrap();
            }
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("dbs-illisible");
        let base = bac.join("plume.db").to_string_lossy().to_string();
        dbs_base(&base);
        {
            let c = open_db(&base).unwrap();
            dbs_inserer(&c, 11, "ban_ip", "203.0.113.81", 0, "X'00'");
            dbs_inserer(&c, 12, "ban_ip", "203.0.113.82", 0, "5400");
            dbs_inserer(&c, 13, "ban_ip", "203.0.113.83", 0, "0");
            dbs_inserer(&c, 14, "unban_ip", "203.0.113.84", 0, "X'00'");
            dbs_inserer(&c, 15, "ban_ip", "203.0.113.85", 0, "X'00'");
            dbs_inserer(&c, 16, "ban_ip", "203.0.113.86", 1, "NULL");
            // Une illisible NON ASSIGNÉE : une réclamation l'attribuerait à l'hôte ; retenue, elle reste sans hôte.
            c.execute("UPDATE action SET host=NULL WHERE id=15", []).unwrap();
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::duree_de_ban_servie_a_l_agent::dbs_une_duree_illisible_retient_l_action_et_le_dit_au_journal",
            ])
            .env(ENFANT, "1")
            .env("DBS_BASE", &base)
            .env("DBS_BAC", bac.as_os_str())
            .output()
            .expect("ré-exécution du binaire de test");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stderr}");
        let lire = |f: &str| std::fs::read_to_string(bac.join(f)).unwrap_or_else(|_| panic!("{f} écrit par l'enfant : {stderr}"));
        assert_eq!(lire("json.statut"), "200", "{stderr}");
        assert_eq!(
            lire("json.corps"),
            "{\"ban_ttl_s\":5400,\"dry_run\":false,\"id\":12,\"kind\":\"ban_ip\",\"target\":\"203.0.113.82\"}\n\
             {\"dry_run\":false,\"id\":14,\"kind\":\"unban_ip\",\"target\":\"203.0.113.84\"}\n\
             {\"ban_ttl_s\":14400,\"dry_run\":true,\"id\":16,\"kind\":\"ban_ip\",\"target\":\"203.0.113.86\"}\n",
            "les lisibles servies, corps entier : {stderr}"
        );
        assert_eq!(lire("tsv.statut"), "200", "second tour : ce n'est pas le 503 de réclamation : {}", lire("tsv.corps"));
        assert_eq!(lire("tsv.corps"), "", "second tour : rien à remettre, les illisibles restent retenues");
        let c = open_db(&base).unwrap();
        let lignes: [(i64, Option<&str>, String); 3] = [
            (11, Some(DBS_HOTE), format!("[actions] action 11 NON REMISE ce tour-ci : {DBS_DUREE_NON_LUE} ({DBS_MOTEUR_BLOB})")),
            (13, Some(DBS_HOTE), format!("[actions] action 13 NON REMISE ce tour-ci : {DBS_DUREE_NON_LUE} ({DBS_MOTEUR_ZERO})")),
            (15, None, format!("[actions] action 15 NON REMISE ce tour-ci : {DBS_DUREE_NON_LUE} ({DBS_MOTEUR_BLOB})")),
        ];
        for (id, hote_attendu, attendue) in &lignes {
            let (statut, reclamee, hote): (String, Option<i64>, Option<String>) =
                c.query_row("SELECT status, claimed_ts, host FROM action WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
            assert_eq!((statut.as_str(), reclamee, hote.as_deref()), ("approved", None, *hote_attendu), "action {id} : retenue, non réclamée, hôte inchangé");
            assert_eq!(stderr.lines().filter(|l| l == attendue).count(), 2, "une ligne par tour : « {attendue} »\n{stderr}");
        }
        assert!(!stderr.contains("203.0.113.8"), "le journal ne porte aucune cible : {stderr}");
        for id in [12, 14, 16] {
            assert!(dbs_reclamee(&c, id).is_some(), "action {id} servie : réclamée");
        }
    }

    /// CE QU'IL TIENT : un ban à durée illisible n'est pas servi ; la colonne corrigée (600) le libère au tour
    /// suivant, servi avec 600. MUTATIONS : `BT1_ILLISIBLE_SERVIE`, `BT1_DEFAUT`.
    #[tokio::test]
    async fn dbs_la_colonne_corrigee_libere_le_ban_au_tour_suivant_avec_sa_duree() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-corrigee");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        dbs_inserer(&st.db.lock(), 21, "ban_ip", "203.0.113.91", 0, "X'00'");
        assert_eq!(dbs_servir(&st, Some(DBS_NDJSON)).await, (200, "application/x-ndjson".into(), String::new()), "premier tour : retenu");
        assert_eq!(dbs_reclamee(&st.db.lock(), 21), None, "premier tour : non réclamé");
        st.db.lock().execute("UPDATE action SET ban_ttl_s=600 WHERE id=21", []).unwrap();
        let (statut, _, corps) = dbs_servir(&st, Some(DBS_NDJSON)).await;
        assert_eq!(
            (statut, corps.as_str()),
            (200, "{\"ban_ttl_s\":600,\"dry_run\":false,\"id\":21,\"kind\":\"ban_ip\",\"target\":\"203.0.113.91\"}\n"),
            "second tour : servi avec la durée corrigée"
        );
    }

    /// CE QU'IL TIENT : cent bans à durée illisible en tête de file (identifiants 1 à 100) ne masquent pas les
    /// actions suivantes de l'hôte : le `unban_ip` 101 et le ban 102 sont servis et réclamés DÈS le premier tour, et
    /// les cent restent retenues. MUTATIONS : `BT1_PAGE_UNIQUE`.
    #[tokio::test]
    async fn dbs_cent_illisibles_en_tete_ne_masquent_pas_la_suite_de_la_file() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-famine");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        {
            let c = st.db.lock();
            for id in 1..=100 {
                dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
            }
            dbs_inserer(&c, 101, "unban_ip", "203.0.113.98", 0, "NULL");
            dbs_inserer(&c, 102, "ban_ip", "203.0.113.97", 0, "600");
        }
        let (statut, _, corps) = dbs_servir(&st, Some(DBS_NDJSON)).await;
        assert_eq!(
            (statut, corps.as_str()),
            (
                200,
                "{\"dry_run\":false,\"id\":101,\"kind\":\"unban_ip\",\"target\":\"203.0.113.98\"}\n\
                 {\"ban_ttl_s\":600,\"dry_run\":false,\"id\":102,\"kind\":\"ban_ip\",\"target\":\"203.0.113.97\"}\n"
            ),
            "premier tour : la suite de la file est servie"
        );
        let c = st.db.lock();
        for id in [101, 102] {
            assert!(dbs_reclamee(&c, id).is_some(), "action {id} servie : réclamée");
        }
        let retenues: i64 = c.query_row("SELECT COUNT(*) FROM action WHERE id<=100 AND status='approved' AND claimed_ts IS NULL", [], |r| r.get(0)).unwrap();
        assert_eq!(retenues, 100, "les cent illisibles restent retenues");
    }

    /// `count` levées servables, d'identifiants `premier..premier+count`, cibles 198.51.100.x (x = id modulo 250).
    fn dbs_levees(conn: &Connection, premier: i64, count: i64) {
        for id in premier..premier + count {
            dbs_inserer(conn, id, "unban_ip", &format!("198.51.100.{}", id % 250), 0, "NULL");
        }
    }

    /// Le TSV des levées `ids`, tel que `dbs_levees` les pose.
    fn dbs_tsv_des_levees(ids: std::ops::RangeInclusive<i64>) -> String {
        ids.map(|id| format!("{id}\tunban_ip\t198.51.100.{}\t0\n", id % 250)).collect()
    }

    fn dbs_reclamees_entre(conn: &Connection, de: i64, a: i64) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM action WHERE id BETWEEN ?1 AND ?2 AND claimed_ts IS NOT NULL", [de, a], |r| r.get(0)).unwrap()
    }

    /// CE QU'IL TIENT : UN TOUR REMET AU PLUS CENT ACTIONS. (a) 150 levées servables : les cent premières servies
    /// (corps entier) et réclamées, les cinquante suivantes ni servies ni réclamées. (b) 99 bans illisibles en tête,
    /// puis 150 levées : la première page en remet une, la suivante ne remet que les 99 qui manquent — cent en
    /// tout, jamais 199 ; les levées 200 à 249 restent pour le tour suivant. MUTATIONS : `BU1_SANS_PLAFOND`,
    /// `BU1_PLAFOND_STRICT` (rouges sur (b)).
    #[tokio::test]
    async fn dbs_un_tour_remet_au_plus_cent_actions() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-cent-a");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        dbs_levees(&st.db.lock(), 1, 150);
        let (statut, _, corps) = dbs_servir(&st, None).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps, dbs_tsv_des_levees(1..=100), "(a) les cent premières, corps entier");
        {
            let c = st.db.lock();
            assert_eq!(dbs_reclamees_entre(&c, 1, 100), 100, "(a) les cent servies sont réclamées");
            assert_eq!(dbs_reclamees_entre(&c, 101, 150), 0, "(a) les cinquante suivantes attendent le tour suivant");
        }

        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-cent-b");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        {
            let c = st.db.lock();
            for id in 1..=99 {
                dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
            }
            dbs_levees(&c, 100, 150);
        }
        let (statut, _, corps) = dbs_servir(&st, None).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps.lines().count(), 100, "(b) cent remises, pas plus");
        assert_eq!(corps, dbs_tsv_des_levees(100..=199), "(b) la levée 100 puis les 99 qui manquent, corps entier");
        let c = st.db.lock();
        assert_eq!(dbs_reclamees_entre(&c, 1, 99), 0, "(b) les illisibles restent retenues");
        assert_eq!(dbs_reclamees_entre(&c, 100, 199), 100, "(b) les cent servies sont réclamées");
        assert_eq!(dbs_reclamees_entre(&c, 200, 249), 0, "(b) le reste attend le tour suivant, non réclamé");
    }

    /// CE QU'IL TIENT (sous-processus, pour lire le journal), trois scènes, chacune sur sa base :
    /// * `lecture` — 99 bans illisibles, la levée 100 servable, la levée 101 à cible BLOB : la première page
    ///   réclame la 100, la lecture de la suivante échoue ; la 100 est SERVIE (200, corps entier) au lieu d'un 503
    ///   qui la perdrait, et le journal porte la ligne ENTIÈRE avec le texte du moteur ;
    /// * `reclamation` — même file, la 101 lisible mais un déclencheur `RAISE(IGNORE)` rend sa réclamation sans
    ///   effet : la 100 est servie (200, corps entier), la 101 non servie, sa ligne d'anomalie au journal  —
    ///   c'est cette ligne qui prouve que la page suivante a été lue ;
    /// * `borne` — cent levées servables puis la 101 à cible BLOB : la page suivante n'est PAS lue une fois cent
    ///   actions remises (aucune ligne « page suivante » au journal), cent servies.
    /// MUTATIONS : `BU1_LECTURE_503`, `BU1_LECTURE_MUETTE`, `BU1_RECLAMATION_503`, `BU1_COMPTE_STRICT`,
    /// `BU1_COMPTE_RETIRE`.
    #[test]
    fn dbs_un_echec_en_page_suivante_remet_les_actions_deja_reclamees() {
        const ENFANT: &str = "DBS_PAGE_SUIVANTE_ENFANT";
        const SCENES: [&str; 3] = ["lecture", "reclamation", "borne"];
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let bac = std::path::PathBuf::from(std::env::var("DBS_BAC").expect("bac transmis"));
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            for scene in SCENES {
                let st = ds_file_state(&bac.join(format!("{scene}.db")).to_string_lossy());
                eprintln!("=== scène {scene} ===");
                let (statut, _, corps) = rt.block_on(dbs_servir(&st, None));
                std::fs::write(bac.join(format!("{scene}.statut")), statut.to_string()).unwrap();
                std::fs::write(bac.join(format!("{scene}.corps")), corps).unwrap();
            }
            eprintln!("=== fin ===");
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("dbs-page-suivante");
        for scene in SCENES {
            let base = bac.join(format!("{scene}.db")).to_string_lossy().to_string();
            dbs_base(&base);
            let c = open_db(&base).unwrap();
            if scene == "borne" {
                dbs_levees(&c, 1, 100);
            } else {
                for id in 1..=99 {
                    dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
                }
                dbs_inserer(&c, 100, "unban_ip", "203.0.113.7", 0, "NULL");
            }
            if scene == "reclamation" {
                dbs_inserer(&c, 101, "unban_ip", "203.0.113.8", 0, "NULL");
                c.execute_batch("CREATE TRIGGER dbs_reclamation_ignoree BEFORE UPDATE ON action WHEN NEW.id>100 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
            } else {
                c.execute("INSERT INTO action(id,ts,kind,target,status,dry_run,reason,host) VALUES(101,1000,'unban_ip',x'FF','approved',0,'dbs',?1)", [DBS_HOTE])
                    .unwrap();
            }
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::duree_de_ban_servie_a_l_agent::dbs_un_echec_en_page_suivante_remet_les_actions_deja_reclamees",
            ])
            .env(ENFANT, "1")
            .env("DBS_BAC", bac.as_os_str())
            .output()
            .expect("ré-exécution du binaire de test");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stderr}");
        let lire = |f: &str| std::fs::read_to_string(bac.join(f)).unwrap_or_else(|_| panic!("{f} écrit par l'enfant : {stderr}"));
        // Le journal de chaque scène : les lignes entre son marqueur et le suivant.
        let journal = |scene: &str| -> Vec<String> {
            let debut = format!("=== scène {scene} ===");
            stderr.lines().skip_while(|l| *l != debut).skip(1).take_while(|l| !l.starts_with("=== ")).map(str::to_string).collect()
        };
        const PAGE_SUIVANTE: &str = "[actions] page suivante de la file NON LUE ce tour-ci, les actions déjà réclamées sont remises : ";
        const MOTEUR_CIBLE_BLOB: &str = "Invalid column type Blob at index: 2, name: target";
        let page_suivante = |scene: &str| journal(scene).into_iter().filter(|l| l.starts_with(PAGE_SUIVANTE)).collect::<Vec<_>>();

        for scene in ["lecture", "reclamation"] {
            assert_eq!(lire(&format!("{scene}.statut")), "200", "{scene} : la 100, déjà réclamée, est servie — pas un 503 : {}", lire(&format!("{scene}.corps")));
            assert_eq!(lire(&format!("{scene}.corps")), "100\tunban_ip\t203.0.113.7\t0\n", "{scene} : corps entier\n{stderr}");
            let c = open_db(&bac.join(format!("{scene}.db")).to_string_lossy()).unwrap();
            assert_eq!(dbs_reclamees_entre(&c, 100, 100), 1, "{scene} : la 100 servie est réclamée");
            assert_eq!(dbs_reclamees_entre(&c, 1, 99), 0, "{scene} : les illisibles restent retenues");
        }
        // Rien n'est affirmé sur la réclamation de la 101 : dans les deux scènes elle serait vraie par construction
        // (`lecture` : la cible BLOB fait échouer la lecture de la page, la 101 n'atteint jamais l'UPDATE ;
        // `reclamation` : le déclencheur `RAISE(IGNORE)` interdit toute écriture). Ce sont les lignes du journal qui
        // prouvent que la page suivante a été lue.
        assert_eq!(page_suivante("lecture"), vec![format!("{PAGE_SUIVANTE}{MOTEUR_CIBLE_BLOB}")], "lecture : la ligne entière, une fois\n{stderr}");
        assert_eq!(
            journal("reclamation").iter().filter(|l| *l == "[actions] action 101 NON REMISE ce tour-ci : réclamation sans effet (0 ligne touchée)").count(),
            1,
            "reclamation : l'anomalie de la 101 au journal\n{stderr}"
        );
        assert_eq!(lire("borne.statut"), "200");
        assert_eq!(lire("borne.corps"), dbs_tsv_des_levees(1..=100), "borne : cent servies, corps entier");
        assert!(stderr.lines().any(|l| l == "=== scène borne ==="), "instrument : marqueur présent\n{stderr}");
        assert!(page_suivante("borne").is_empty(), "borne : cent remises, la page suivante n'est pas lue\n{stderr}");
    }

    /// CE QU'IL TIENT (sous-processus, pour lire le journal) : LA PAGE SUIVANTE COMMENCE APRÈS LA DERNIÈRE LUE.
    /// 200 bans illisibles (1 à 200, deux pages pleines de retenues) puis 150 levées (201 à 350), deux tours en
    /// TSV. Premier tour : les levées 201 à 300 servies (corps entier) ; second : 301 à 350. Chaque illisible a
    /// EXACTEMENT une ligne « NON REMISE » par tour (deux en tout), et le journal n'en porte aucune autre : un
    /// curseur qui relit une page déjà lue redit ses retenues (et multiplie les lectures sous le verrou de la
    /// base) sans changer aucun corps servi. MUTATIONS : `BU1C_CURSEUR_PREMIER`, `BU1C_SQL_GE`.
    #[test]
    fn dbs_chaque_page_est_lue_une_fois_par_tour() {
        const ENFANT: &str = "DBS_CURSEUR_ENFANT";
        const TOURS: [&str; 2] = ["un", "deux"];
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let bac = std::path::PathBuf::from(std::env::var("DBS_BAC").expect("bac transmis"));
            let st = ds_file_state(&bac.join("curseur.db").to_string_lossy());
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            for tour in TOURS {
                eprintln!("=== tour {tour} ===");
                let (statut, _, corps) = rt.block_on(dbs_servir(&st, None));
                std::fs::write(bac.join(format!("{tour}.statut")), statut.to_string()).unwrap();
                std::fs::write(bac.join(format!("{tour}.corps")), corps).unwrap();
            }
            eprintln!("=== fin ===");
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("dbs-curseur");
        let base = bac.join("curseur.db").to_string_lossy().to_string();
        dbs_base(&base);
        {
            let c = open_db(&base).unwrap();
            for id in 1..=200 {
                dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
            }
            dbs_levees(&c, 201, 150);
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::duree_de_ban_servie_a_l_agent::dbs_chaque_page_est_lue_une_fois_par_tour"])
            .env(ENFANT, "1")
            .env("DBS_BAC", bac.as_os_str())
            .output()
            .expect("ré-exécution du binaire de test");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stderr}");
        let lire = |f: &str| std::fs::read_to_string(bac.join(f)).unwrap_or_else(|_| panic!("{f} écrit par l'enfant : {stderr}"));
        assert_eq!((lire("un.statut").as_str(), lire("un.corps")), ("200", dbs_tsv_des_levees(201..=300)), "premier tour : les cent levées suivant les retenues");
        assert_eq!((lire("deux.statut").as_str(), lire("deux.corps")), ("200", dbs_tsv_des_levees(301..=350)), "second tour : le reste");
        for tour in TOURS {
            let debut = format!("=== tour {tour} ===");
            assert!(stderr.lines().any(|l| l == debut), "instrument : marqueur {tour} présent\n{stderr}");
            let non_remises: Vec<&str> =
                stderr.lines().skip_while(|l| *l != debut).skip(1).take_while(|l| !l.starts_with("=== ")).filter(|l| l.contains("NON REMISE")).collect();
            let attendues: Vec<String> = (1..=200).map(|id| format!("[actions] action {id} NON REMISE ce tour-ci : {DBS_DUREE_NON_LUE} ({DBS_MOTEUR_BLOB})")).collect();
            assert_eq!(non_remises.len(), 200, "tour {tour} : une ligne par retenue, pas une de plus (page relue ?)");
            assert_eq!(non_remises, attendues, "tour {tour} : chaque retenue une fois, dans l'ordre de la file");
        }
        let c = open_db(&base).unwrap();
        assert_eq!(dbs_reclamees_entre(&c, 1, 200), 0, "les illisibles restent retenues");
        assert_eq!(dbs_reclamees_entre(&c, 201, 350), 150, "les levées sont toutes réclamées en deux tours");
    }

    /// CE QU'IL TIENT : un poids nul sur le type JSON par ligne est un refus (RFC 9110) : TSV, quelle que soit la
    /// casse du paramètre ou l'écriture du zéro, parmi d'autres paramètres ou d'autres types, espace avant la virgule
    /// compris (RFC 9110, 5.6.1) ; un poids non nul le
    /// demande. Par la route : `application/x-ndjson;q=0` sert le TSV à l'octet. MUTATIONS : `BU1_Q_IGNORE`,
    /// `BU1_Q_CASSE`, `V20_SANS_TRIM` (valeur du poids lue sans `trim`).
    #[tokio::test]
    async fn dbs_un_poids_nul_refuse_la_forme_json() {
        use crate::handlers::actions::FormeDeLaFileDActions as F;
        for (accept, attendue) in [
            ("application/x-ndjson;q=0", F::Tsv),
            ("application/x-ndjson; Q=0.000", F::Tsv),
            ("application/x-ndjson;q=0.", F::Tsv),
            ("application/x-ndjson;level=1;q=0", F::Tsv),
            ("text/plain, application/x-ndjson;q=0", F::Tsv),
            ("application/x-ndjson;q=0 , text/plain", F::Tsv),
            ("application/x-ndjson;q=0.001", F::JsonParLigne),
            ("application/x-ndjson;q=1", F::JsonParLigne),
            ("application/x-ndjson;level=0", F::JsonParLigne),
        ] {
            assert_eq!(F::demandee(&dbs_entetes(Some(accept))), attendue, "Accept: {accept}");
        }
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-q0");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        let (propre, defaut) = dbs_page_lisible(&st.db.lock());
        let (statut, genre, corps) = dbs_servir(&st, Some("application/x-ndjson;q=0")).await;
        assert_eq!((statut, genre.as_str()), (200, "text/plain; charset=utf-8"), "{corps}");
        assert_eq!(corps, format!("{propre}\tban_ip\t203.0.113.71\t0\n{defaut}\tban_ip\t203.0.113.72\t1\n900\tunban_ip\t203.0.113.73\t0\n"), "TSV à l'octet");
    }

    /// CE QU'IL TIENT : L'AGENT DÉPLOYÉ REÇOIT LE TSV. `collectors/respond.sh` appelle `curl` sans `-H Accept` :
    /// curl envoie donc `Accept: */*`. Un joker (`*/*`, `application/*`, `text/plain, */*;q=0.8`) ne demande PAS
    /// la forme JSON par ligne, pas plus que l'absence d'en-tête : sinon chaque `respond.sh` déployé sauterait toutes
    /// les lignes (`case "$id" in *[!0-9]*) continue`) pourtant réclamées — ripostes perdues en silence. Par la route,
    /// `Accept: */*` (et les deux autres jokers) sert le TSV à quatre champs, corps comparé À L'OCTET à un littéral,
    /// type de contenu compris. MUTATIONS : `W1_JOKER`.
    #[tokio::test]
    async fn dbs_le_joker_de_curl_sert_le_tsv_a_quatre_champs() {
        use crate::handlers::actions::FormeDeLaFileDActions as F;
        const JOKERS: [&str; 3] = ["*/*", "application/*", "text/plain, */*;q=0.8"];
        for accept in JOKERS {
            assert_eq!(F::demandee(&dbs_entetes(Some(accept))), F::Tsv, "Accept: {accept}");
        }
        assert_eq!(F::demandee(&dbs_entetes(None)), F::Tsv, "sans en-tête");
        for accept in JOKERS {
            let chemin = crate::tmp_possede::TmpDb::neuf("dbs-joker");
            dbs_base(&chemin);
            let st = ds_file_state(&chemin);
            {
                let c = st.db.lock();
                dbs_inserer(&c, 11, "ban_ip", "203.0.113.71", 0, "5400");
                dbs_inserer(&c, 12, "ban_ip", "203.0.113.72", 1, "NULL");
                dbs_inserer(&c, 13, "unban_ip", "203.0.113.73", 0, "7200");
            }
            let (statut, genre, corps) = dbs_servir(&st, Some(accept)).await;
            assert_eq!((statut, genre.as_str()), (200, "text/plain; charset=utf-8"), "Accept: {accept} : {corps}");
            assert_eq!(corps, "11\tban_ip\t203.0.113.71\t0\n12\tban_ip\t203.0.113.72\t1\n13\tunban_ip\t203.0.113.73\t0\n", "Accept: {accept} : TSV à l'octet");
        }
    }

    /// Le corps ENTIER d'un 503 de `err_json` : exactement `error` (la phrase attendue) et `id` (`plume-e…`).
    fn dbs_affirmer_le_503(scene: &str, statut: u16, corps: &str, phrase: &str) {
        assert_eq!(statut, 503, "{scene} : rien réclamé, ce n'est pas une file vide — jamais un 200 vide : {corps:?}");
        let v: serde_json::Value = serde_json::from_str(corps).unwrap_or_else(|e| panic!("{scene} : corps JSON ({e}) : {corps:?}"));
        let objet = v.as_object().unwrap_or_else(|| panic!("{scene} : un objet : {corps:?}"));
        let mut cles: Vec<&str> = objet.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, vec!["error", "id"], "{scene} : ensemble exact des clés : {corps:?}");
        assert_eq!(objet["error"], serde_json::json!(phrase), "{scene} : la cause, à l'octet : {corps:?}");
        assert!(objet["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{scene} : identifiant de corrélation : {corps:?}");
    }

    /// CE QU'IL TIENT : LE 503 « RIEN RÉCLAMÉ » VAUT AUSSI EN PAGE SUIVANTE. Cent bans à durée illisible remplissent
    /// la première page sans rien réclamer ; la page suivante échoue alors que rien n'a été remis :
    /// * `lecture` — la 101 porte une cible BLOB, la lecture de la page suivante échoue : 503 « file d'actions NON
    ///   LUE », corps entier ;
    /// * `reclamation` — la 101 est lisible, mais un déclencheur `RAISE(IGNORE)` rend sa réclamation sans effet :
    ///   503 `CAUSE_REMISE_D_ACTIONS_NON_RECLAMEE`, corps entier.
    /// Dans les deux, rien n'est réclamé. Un 200 vide dirait « file vide » à l'agent (`P10.7-f`).
    /// MUTATIONS : `A13` (lecture ratée en page suivante, rien remis → `break`), `A14` (réclamation ratée en page
    /// suivante, rien remis → `break`).
    #[tokio::test]
    async fn dbs_rien_reclame_en_page_suivante_reste_un_503() {
        const NON_LUE: &str = "file d'actions NON LUE : la lecture des actions approuvées de cet hôte a échoué. \
                               AUCUNE action n'est remise ni réclamée ce tour-ci — ce n'est pas une file vide ; réessayer.";
        const NON_RECLAMEE: &str = "file d'actions NON RÉCLAMÉE : des actions approuvées de cet hôte ont été lues, mais leur réclamation \
                                    n'a pas pu être écrite. AUCUNE action n'est remise ce tour-ci — ce n'est pas une file vide ; réessayer.";
        for (scene, phrase) in [("lecture", NON_LUE), ("reclamation", NON_RECLAMEE)] {
            let chemin = crate::tmp_possede::TmpDb::neuf("dbs-503-suivante");
            dbs_base(&chemin);
            let st = ds_file_state(&chemin);
            {
                let c = st.db.lock();
                for id in 1..=100 {
                    dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
                }
                if scene == "lecture" {
                    c.execute("INSERT INTO action(id,ts,kind,target,status,dry_run,reason,host) VALUES(101,1000,'unban_ip',x'FF','approved',0,'dbs',?1)", [DBS_HOTE])
                        .unwrap();
                } else {
                    dbs_inserer(&c, 101, "unban_ip", "203.0.113.8", 0, "NULL");
                    c.execute_batch("CREATE TRIGGER dbs_reclamation_ignoree BEFORE UPDATE ON action WHEN NEW.id>100 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
                }
            }
            for accept in [None, Some(DBS_NDJSON)] {
                let (statut, _, corps) = dbs_servir(&st, accept).await;
                dbs_affirmer_le_503(&format!("{scene} ({accept:?})"), statut, &corps, phrase);
            }
            let c = st.db.lock();
            assert_eq!(dbs_reclamees_entre(&c, 1, 101), 0, "{scene} : rien n'est réclamé");
        }
    }

    /// CE QU'IL TIENT : LE PLAFOND COMPTE LES REMISES, PAS LES ANOMALIES. 110 levées servables ; un déclencheur
    /// `RAISE(IGNORE)` rend sans effet la réclamation des dix premières. La première page en remet 90 ; la page
    /// suivante complète avec les levées 101 à 110 : cent remises (corps entier), les dix premières non réclamées.
    /// MUTATION : `B12` (`remettre_au_plus` rend `reclamees + retenues_sur_anomalie` : 90 seulement).
    #[tokio::test]
    async fn dbs_les_reclamations_sans_effet_ne_comptent_pas_dans_le_plafond() {
        let chemin = crate::tmp_possede::TmpDb::neuf("dbs-plafond-anomalies");
        dbs_base(&chemin);
        let st = ds_file_state(&chemin);
        {
            let c = st.db.lock();
            dbs_levees(&c, 1, 110);
            c.execute_batch("CREATE TRIGGER dbs_reclamation_ignoree BEFORE UPDATE ON action WHEN NEW.id<=10 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        }
        let (statut, _, corps) = dbs_servir(&st, None).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps.lines().count(), 100, "90 de la première page + 10 de la suivante");
        assert_eq!(corps, dbs_tsv_des_levees(11..=110), "corps entier");
        let c = st.db.lock();
        assert_eq!(dbs_reclamees_entre(&c, 1, 10), 0, "les réclamations sans effet ne réclament rien");
        assert_eq!(dbs_reclamees_entre(&c, 11, 110), 100, "les cent servies sont réclamées");
    }

    /// CE QU'IL TIENT (sous-processus, pour lire le journal) : APRÈS LE PLAFOND, AUCUNE LIGNE N'EST LUE POUR SA
    /// DURÉE (doc de `remettre_au_plus`). 99 bans illisibles (1 à 99), cent levées (100 à 199), puis le ban 200 à
    /// durée illisible. La première page remet la 100, la suivante les 99 qui manquent et s'arrête au plafond :
    /// cent servies (corps entier), et le journal ne porte « NON REMISE » QUE pour les 99 premières — aucune
    /// ligne pour la 200, qui n'est ni lue pour sa durée, ni réclamée. MUTATION : `B18` (contrôle du plafond
    /// déplacé après la lecture de la durée : « action 200 NON REMISE » paraît).
    #[test]
    fn dbs_apres_le_plafond_aucune_duree_n_est_lue() {
        const ENFANT: &str = "DBS_APRES_PLAFOND_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let bac = std::path::PathBuf::from(std::env::var("DBS_BAC").expect("bac transmis"));
            let st = ds_file_state(&bac.join("plafond.db").to_string_lossy());
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            eprintln!("=== tour ===");
            let (statut, _, corps) = rt.block_on(dbs_servir(&st, None));
            eprintln!("=== fin ===");
            std::fs::write(bac.join("statut"), statut.to_string()).unwrap();
            std::fs::write(bac.join("corps"), corps).unwrap();
            return;
        }
        let bac = crate::tmp_possede::TmpPossede::neuf("dbs-apres-plafond");
        let base = bac.join("plafond.db").to_string_lossy().to_string();
        dbs_base(&base);
        {
            let c = open_db(&base).unwrap();
            for id in 1..=99 {
                dbs_inserer(&c, id, "ban_ip", "203.0.113.99", 0, "X'00'");
            }
            dbs_levees(&c, 100, 100);
            dbs_inserer(&c, 200, "ban_ip", "203.0.113.98", 0, "X'00'");
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::duree_de_ban_servie_a_l_agent::dbs_apres_le_plafond_aucune_duree_n_est_lue"])
            .env(ENFANT, "1")
            .env("DBS_BAC", bac.as_os_str())
            .output()
            .expect("ré-exécution du binaire de test");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stderr}");
        let lire = |f: &str| std::fs::read_to_string(bac.join(f)).unwrap_or_else(|_| panic!("{f} écrit par l'enfant : {stderr}"));
        assert_eq!((lire("statut").as_str(), lire("corps")), ("200", dbs_tsv_des_levees(100..=199)), "cent servies, corps entier");
        assert!(stderr.lines().any(|l| l == "=== tour ==="), "instrument : marqueur présent\n{stderr}");
        let non_remises: Vec<&str> =
            stderr.lines().skip_while(|l| *l != "=== tour ===").skip(1).take_while(|l| !l.starts_with("=== ")).filter(|l| l.contains("NON REMISE")).collect();
        let attendues: Vec<String> = (1..=99).map(|id| format!("[actions] action {id} NON REMISE ce tour-ci : {DBS_DUREE_NON_LUE} ({DBS_MOTEUR_BLOB})")).collect();
        assert_eq!(non_remises, attendues, "seules les 99 retenues avant le plafond ; la 200 n'est pas lue pour sa durée\n{stderr}");
        let c = open_db(&base).unwrap();
        assert_eq!(dbs_reclamees_entre(&c, 200, 200), 0, "la 200, après le plafond, n'est pas réclamée");
    }
}
