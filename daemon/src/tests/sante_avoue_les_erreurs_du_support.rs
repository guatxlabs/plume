// ================================================================================================
// LA SANTÉ DIT LES ERREURS DU SUPPORT DE LA BASE (composant `store` de `/api/system/health`)
// ================================================================================================
// CONSTAT : des lectures rendaient SQLITE_CORRUPT ; la ligne `[sqlite] erreur du support de la base : …`
// (`sqlite_plafond::journaliser_si_erreur_du_support`) s'écrivait à chaque échec, et pendant ce temps le composant
// `store` ne regardait que le disque (`statvfs`) : vert, et `posture` verte. Seul le journal du pod le disait.
//
// CE QUI CHANGE : le site unique de la ligne COMPTE aussi (trois atomiques : total, instant et code étendu de la
// dernière), sous la même condition (`est_erreur_du_support`) ; le composant `store` sert `support_errors`,
// `support_errors_last_ts`, `support_errors_last_code`, et passe au JAUNE (jamais au-delà, un rouge du disque reste
// rouge) tant que la dernière erreur a moins de `FENETRE_D_AVEU_DES_ERREURS_DU_SUPPORT_S` ; son détail nomme le geste
// `plume-daemon integrity-check --full`. Hors de la fenêtre, l'état et le détail reviennent tels quels, le compte reste.
//
// ISOLEMENT : le compte est un état de PROCESSUS. Le témoin de bout en bout tourne dans un SOUS-PROCESSUS qui ne joue
// que lui (`--exact --test-threads=1`) : les comptes y sont EXACTS, quelle que soit la suite qui tourne à côté. Les
// témoins de la fenêtre et des champs sont PURS (instantané et horloge injectés) ; celui du compteur joue une instance
// LOCALE du même type que le compte du processus.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les erreurs sont FABRIQUÉES (fonction `regexp` substituée sur la connexion du
// pool, qui rend le code au pas ; `message_erreur` appelé sur une erreur construite) — aucun disque réellement
// corrompu ; le compte est celui du processus, toutes bases de tenant confondues, et la phrase le dit.

#[cfg(test)]
mod ce2_sante_erreurs_du_support {
    use super::*;
    use crate::sqlite_plafond::{CompteDesErreursDuSupport, ErreursDuSupport};
    use rusqlite::functions::FunctionFlags;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CE2_ENFANT: &str = "CE2_ENFANT_SANTE";
    const CE2_RENDU: &str = "CE2-RENDU:";
    const CE2_FIN: &str = "CE2-FIN:";
    const CE2_ESSAIS: usize = 40;
    /// Seuil d'avertissement du disque relevé dans l'enfant : le témoin juge les erreurs du support, pas le
    /// remplissage du volume de la machine qui joue la suite.
    const CE2_SEUIL_DISQUE: &str = "99";
    /// Âge maximal nul : restauration et copie hors site NON SUIVIES (idle) dans l'enfant, pour que la posture ne
    /// dépende que de `store`.
    const CE2_NON_SUIVI: &str = "0";
    /// La durée de la fenêtre, ÉCRITE ICI (jamais tirée de la production).
    const CE2_FENETRE_S: i64 = 900;
    /// La portée du compte, écrite ici.
    const CE2_PORTEE: &str = "[compte du processus, toutes bases de tenant confondues, pas seulement celle-ci]";
    /// `SQLITE_IOERR | (2 << 8)`.
    const IOERR_READ: i32 = 266;
    /// L'âge, au-delà de la fenêtre, de l'erreur injectée dans l'issue « fenêtre échue ».
    const CE2_RETARD_S: i64 = 60;

    /// La phrase ajoutée au détail du disque, écrite ici en entier.
    fn ce2_phrase(detail: &str, total: u64, age: i64, code: &str) -> String {
        format!(
            "{detail} ; {total} erreur(s) du SUPPORT de la base depuis le démarrage {CE2_PORTEE} — des lectures ont été \
             refusées par le moteur (entrée-sortie, disque ou fichier corrompu), dernière il y a {age}s ({code}) : \
             vérifier la base par `plume-daemon integrity-check --full` ; aveu tenu 15 min après la dernière erreur"
        )
    }

    fn ce2_vider_le_pool(chemin: &str) {
        while crate::query_exec::connexions_de_lecture_au_repos(chemin) > 0 {
            drop(crate::query_exec::read_conn_get(chemin).expect("fixture : connexion au repos"));
        }
    }

    /// Dépose dans le pool de `chemin` UNE connexion de lecture dont `regexp` rend `code` au pas.
    fn ce2_armer(chemin: &str, code: i32) -> Arc<AtomicBool> {
        ce2_vider_le_pool(chemin);
        let conn = crate::query_exec::read_conn_get(chemin).expect("fixture : connexion de lecture");
        let joue = Arc::new(AtomicBool::new(false));
        let drapeau = joue.clone();
        conn.create_scalar_function("regexp", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, move |_ctx| -> rusqlite::Result<bool> {
            drapeau.store(true, Ordering::SeqCst);
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None))
        })
        .expect("fixture : regexp substituée");
        crate::query_exec::read_conn_put(chemin, conn);
        joue
    }

    async fn ce2_get(addr: std::net::SocketAddr, chemin: &str) -> (u16, Value) {
        let (code, brut) = router_probe_corps(addr, "GET", chemin, Some(&viewer_authz()), &[]).await;
        let (tete, corps) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière pour {chemin} : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(corps.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {chemin}"))).expect("corps UTF-8")
        } else {
            corps.to_string()
        };
        let mut v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("stats"); // durées de la recherche, variables
        }
        (code, v)
    }

    /// Une recherche servie par la connexion armée (réessayée tant qu'une autre connexion l'a servie).
    async fn ce2_recherche_en_panne(addr: std::net::SocketAddr, base: &str, code: i32) -> (u16, Value) {
        for _ in 0..CE2_ESSAIS {
            let joue = ce2_armer(base, code);
            let rendu = ce2_get(addr, "/api/search?q=host%3Ace2-h%20regex%3Dsonde").await;
            if joue.load(Ordering::SeqCst) {
                ce2_vider_le_pool(base);
                return rendu;
            }
        }
        panic!("instrument : la connexion armée n'a servi en aucun des {CE2_ESSAIS} essais — le témoin ne conclut pas");
    }

    /// Le composant `store` d'un corps de santé (présent exactement une fois).
    fn ce2_store(sante: &Value) -> Value {
        let trouves: Vec<Value> = sante["components"].as_array().expect("liste de composants").iter()
            .filter(|c| c["component"] == "store").cloned().collect();
        assert_eq!(trouves.len(), 1, "le composant `store` apparaît exactement une fois : {sante}");
        trouves[0].clone()
    }

    /// Les clés de l'objet, triées.
    fn ce2_cles(v: &Value) -> Vec<String> {
        let mut k: Vec<String> = v.as_object().expect("objet").keys().cloned().collect();
        k.sort();
        k
    }

    /// Le détail du disque seul (avant la phrase ajoutée), et ce qui suit.
    fn ce2_couper(detail: &str) -> (String, Option<String>) {
        match detail.split_once(" ; ") {
            Some((a, b)) => (a.to_string(), Some(b.to_string())),
            None => (detail.to_string(), None),
        }
    }

    /// (1) PAR LA ROUTE `/api/system/health` (routeur réel, jeton du lecteur), DANS UN SOUS-PROCESSUS : la santé d'avant
    /// (aucune erreur : `support_errors` 0, vert) ; une erreur de la REQUÊTE (motif refusé) et une base OCCUPÉE
    /// (`SQLITE_BUSY` au pas) ne comptent pas et laissent le vert ; une recherche dont la lecture rend `SQLITE_CORRUPT`
    /// (refus de recherche, `search_engine_error`) compte UNE erreur, sert l'instant et le code, jaunit le composant
    /// avec la phrase entière, et `posture` suit : VERTE avant (tous les autres composants verts ou inactifs dans
    /// l'enfant, contrôlé à chaque issue), JAUNE dans la fenêtre, VERTE de nouveau la fenêtre échue ; puis `message_erreur` sur les six classes du
    /// support et sept classes hors support (dont occupée, verrouillée, mémoire, droit, contrainte, interruption) :
    /// SIX de plus exactement, la dernière (`IOERR_READ`) fait le code servi. Le compte servi est ÉGAL au nombre de
    /// lignes `[sqlite]` capturées sur la sortie d'erreur de l'enfant. Enfin une erreur notée au compte du processus
    /// avec un instant antérieur à la fenêtre : la route rend l'état et le détail du disque seul, et sert toujours le
    /// compte (8), l'instant et le code injectés — c'est le BRANCHEMENT qui est jugé (horloge du point d'entrée,
    /// champs posés hors de la fenêtre), pas seulement les fonctions pures.
    ///
    /// MUTATIONS : `CE2_SANS_COMPTE` (le compte retiré du site) -> 0 servi : ROUGE ; `CE2_COMPTE_HORS_CONDITION` (compté
    /// pour toute `SqliteFailure`) -> la requête et l'occupée comptent : ROUGE ; `CE2_TOUJOURS_VERT` (la surface rend
    /// l'état tel quel) -> vert après la corruption : ROUGE ; `CE2_CHAMPS_HORS_DU_VERT_SEULEMENT` (champs posés
    /// seulement hors du vert) -> `support_errors` absent avant : ROUGE ; `CE2_PREMIER_CODE` (le premier code gardé)
    /// -> 11 servi au lieu de 266 : ROUGE ; `CE2_CABLAGE_HORLOGE_FIGEE` (l'instant de la dernière passé pour l'horloge)
    /// -> jaune hors fenêtre : ROUGE ; `CE2_CABLAGE_CHAMPS_DANS_LA_FENETRE` (champs posés dans la fenêtre seulement)
    /// -> `support_errors` absent hors fenêtre : ROUGE ; `CE2_POSTURE_SANS_STORE` (dans `system_health`, la posture
    /// calculée sur les composants sauf `store`) -> posture verte après la corruption : ROUGE.
    #[tokio::test]
    async fn la_sante_servie_avoue_une_erreur_du_support_vue_par_une_lecture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        if std::env::var(CE2_ENFANT).is_ok() {
            let (mut st, _base) = router_test_state("ce2-sante");
            // POSTURE VERTE AVANT : une file d'ingest RÉELLE (vide, lisible) et un événement FRAIS rendent `ingest`
            // vert ; restauration et copie hors site sont NON SUIVIES (idle) par l'environnement posé par le
            // parent ; détection, rollups, forwarder et passes de fond sont inactifs dans cet enfant. `store` est
            // alors le SEUL composant qui puisse quitter le vert : la posture servie le suit ou ne suit rien.
            let file_d_ingest = crate::tmp_possede::TmpPossede::neuf("ce2-spool");
            st.spool = Arc::new(file_d_ingest.racine().as_str().to_string());
            let chemin = st.db_path.as_ref().clone();
            open_db(&chemin)
                .expect("fixture : base")
                .execute(
                    "INSERT INTO event(ts,source,severity,message,host,src_ip) VALUES(?1,'ce2',1,'ce2sonde present','ce2-h',NULL)",
                    params![now()],
                )
                .expect("fixture : un événement frais");
            let addr = router_serve(st.clone()).await;
            let mut rendus: Vec<Value> = Vec::new();
            let mut noter = |issue: &str, recherche: Value, sante: (u16, Value), avant: i64, apres: i64| {
                rendus.push(json!([issue, recherche, sante.0, sante.1, avant, apres]));
            };
            let t = now();
            noter("avant", Value::Null, ce2_get(addr, "/api/system/health").await, t, now());
            let t = now();
            let (c, v) = ce2_get(addr, "/api/search?q=regex%3D%28").await;
            noter("requete", json!([c, v]), ce2_get(addr, "/api/system/health").await, t, now());
            let t = now();
            let (c, v) = ce2_recherche_en_panne(addr, &chemin, rusqlite::ffi::SQLITE_BUSY).await;
            noter("occupee", json!([c, v]), ce2_get(addr, "/api/system/health").await, t, now());
            let t = now();
            let (c, v) = ce2_recherche_en_panne(addr, &chemin, rusqlite::ffi::SQLITE_CORRUPT).await;
            noter("corrompue", json!([c, v]), ce2_get(addr, "/api/system/health").await, t, now());
            let t = now();
            use rusqlite::ffi as f;
            for code in [
                f::SQLITE_ERROR, f::SQLITE_CANTOPEN, f::SQLITE_BUSY, f::SQLITE_FULL, f::SQLITE_LOCKED, f::SQLITE_NOTADB,
                f::SQLITE_NOMEM, f::SQLITE_PROTOCOL, f::SQLITE_PERM, f::SQLITE_CORRUPT, f::SQLITE_CONSTRAINT,
                f::SQLITE_INTERRUPT, IOERR_READ,
            ] {
                let _ = crate::sqlite_plafond::message_erreur(&rusqlite::Error::SqliteFailure(f::Error::new(code), None));
            }
            noter("classes", Value::Null, ce2_get(addr, "/api/system/health").await, t, now());
            // FENÊTRE ÉCHUE, PAR LA ROUTE : une erreur notée au compte du processus il y a plus que la fenêtre
            // (l'instant est injecté, `noter` le garde tel quel) ; la santé lit alors l'horloge du point d'entrée.
            let ancien = now() - CE2_FENETRE_S - CE2_RETARD_S;
            crate::sqlite_plafond::ERREURS_DU_SUPPORT.noter(rusqlite::ffi::SQLITE_FULL, ancien);
            noter("echue", Value::Null, ce2_get(addr, "/api/system/health").await, ancien, ancien);
            for r in &rendus {
                println!("{CE2_RENDU}{r}");
            }
            println!("{CE2_FIN} {}", rendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ce2_sante_erreurs_du_support::la_sante_servie_avoue_une_erreur_du_support_vue_par_une_lecture",
            ])
            .env(CE2_ENFANT, "1")
            .env("PLUME_DISK_WARN_PCT", CE2_SEUIL_DISQUE)
            .env(crate::copie_hors_site::REGLAGE_AGE_MAX_HEURES, CE2_NON_SUIVI)
            .env(crate::exercice_de_restauration::CLE_AGE_MAX_JOURS, CE2_NON_SUIVI)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{CE2_FIN} 6")), "contrôle : l'enfant a joué ses six issues : {stdout}\n{stderr}");
        let rendus: Vec<Value> = stdout
            .lines()
            .filter_map(|l| l.split_once(CE2_RENDU))
            .map(|(_, v)| serde_json::from_str(v).unwrap_or_else(|e| panic!("contrôle : ligne de rendu lisible ({e}) : {v}")))
            .collect();
        assert_eq!(rendus.len(), 6, "contrôle : une ligne par issue : {stdout}");
        let rendu = |issue: &str| rendus.iter().find(|r| r[0] == issue).cloned().unwrap_or_else(|| panic!("{issue} rendu"));
        let sante = |issue: &str| {
            let r = rendu(issue);
            assert_eq!(r[2], 200, "{issue} : la santé se lit avec le jeton du lecteur : {r}");
            r[3].clone()
        };
        let cles_disque = ["component", "db_size_bytes", "db_size_bytes_cause", "db_size_bytes_verdict", "detail",
            "disk_used_pct", "disk_used_pct_cause", "disk_used_pct_verdict", "state"];
        let cles = |extra: &[&str]| {
            let mut v: Vec<String> = cles_disque.iter().chain(extra.iter()).map(|s| s.to_string()).collect();
            v.sort();
            v
        };
        // LA POSTURE SERVIE, JUGÉE CONTRE UNE VALEUR ÉCRITE ICI (jamais recalculée par la fonction du gestionnaire).
        // Contrôle d'abord : hors `store`, chaque composant est vert ou inactif à CHAQUE issue — sinon la posture ne
        // dirait rien du composant jugé et le témoin ne conclurait pas.
        let posture_suit = |issue: &str, s: &Value, attendue: &str| {
            let comps = s["components"].as_array().expect("composants");
            assert!(comps.len() >= 2, "contrôle : {issue} : plusieurs composants servis : {s}");
            for c in comps.iter().filter(|c| c["component"] != "store") {
                assert!(
                    c["state"] == "green" || c["state"] == "idle",
                    "contrôle : {issue} : hors `store`, le composant {} est vert ou inactif : {s}",
                    c["component"]
                );
            }
            assert_eq!(s["posture"], attendue, "{issue} : la posture servie suit le composant `store` : {s}");
        };

        // ① AVANT : aucune erreur, le vrai zéro est servi, rien d'autre ; le composant est vert.
        for issue in ["avant", "requete", "occupee"] {
            let s = sante(issue);
            let store = ce2_store(&s);
            assert_eq!(ce2_cles(&store), cles(&["support_errors"]), "{issue} : clés exactes du composant : {store}");
            assert_eq!(store["support_errors"], 0, "{issue} : aucune erreur du support comptée : {store}");
            assert_eq!(store["state"], "green", "{issue} : le composant reste vert : {store}");
            let (disque, ajout) = ce2_couper(store["detail"].as_str().unwrap_or_default());
            assert!(disque.starts_with("disque données ") && ajout.is_none(), "{issue} : le détail du disque seul : {store}");
            posture_suit(issue, &s, "green");
        }
        // Contrôles : la requête a bien été refusée par le moteur, l'occupée bien servie par la connexion armée.
        let refus = json!([200, { "results": [], "error": "le moteur de recherche a REFUSÉ cette requête (ce n'est pas « aucun résultat ») : motif rejeté par le moteur de recherche" }]);
        assert_eq!(rendu("requete")[1], refus, "contrôle : le motif est refusé par le moteur (erreur de la requête)");
        assert_eq!(rendu("occupee")[1][0], 200, "contrôle : la recherche occupée a répondu : {}", rendu("occupee"));
        assert_eq!(rendu("corrompue")[1][0], 200, "contrôle : la recherche corrompue a répondu : {}", rendu("corrompue"));

        // ② CORROMPUE : une erreur, son instant (pris pendant la lecture), son code ; jaune ; la phrase entière.
        let r = rendu("corrompue");
        let s = sante("corrompue");
        let store = ce2_store(&s);
        assert_eq!(
            ce2_cles(&store),
            cles(&["support_errors", "support_errors_last_code", "support_errors_last_ts"]),
            "clés exactes après l'erreur : {store}"
        );
        assert_eq!(store["support_errors"], 1, "UNE erreur du support comptée : {store}");
        assert_eq!(store["support_errors_last_code"], 11, "le code étendu de la dernière (SQLITE_CORRUPT) : {store}");
        let ts = store["support_errors_last_ts"].as_i64().expect("instant servi en entier");
        assert!(ts >= r[4].as_i64().unwrap() && ts <= r[5].as_i64().unwrap(), "l'instant est celui de la lecture : {r}");
        assert_eq!(store["state"], "yellow", "le composant quitte le vert, en jaune : {store}");
        let detail = store["detail"].as_str().unwrap_or_default();
        let (disque, _) = ce2_couper(detail);
        assert!(disque.starts_with("disque données "), "le détail du disque reste en tête : {store}");
        let age = ce2_age(detail);
        assert_eq!(detail, ce2_phrase(&disque, 1, age, "code étendu 11"), "la phrase entière : {store}");
        posture_suit("corrompue", &s, "yellow");

        // ③ CLASSES : six de plus exactement, la dernière fait le code.
        let s = sante("classes");
        let store = ce2_store(&s);
        assert_eq!(store["support_errors"], 7, "six classes du support comptées, sept hors support ignorées : {store}");
        assert_eq!(store["support_errors_last_code"], IOERR_READ, "le code de la DERNIÈRE : {store}");
        let detail = store["detail"].as_str().unwrap_or_default();
        let (disque, _) = ce2_couper(detail);
        let age = ce2_age(detail);
        assert_eq!(detail, ce2_phrase(&disque, 7, age, "SQLITE_IOERR_READ, code étendu 266"), "la phrase nomme le code : {store}");
        assert_eq!(store["state"], "yellow");
        posture_suit("classes", &s, "yellow");

        // ④ FENÊTRE ÉCHUE, PAR LA ROUTE : l'état et le détail du disque seul, à l'identique de l'avant ; le compte,
        // l'instant et le code de la dernière restent servis (un fait passé ne s'efface pas).
        let r = rendu("echue");
        let ancien = r[4].as_i64().expect("instant injecté");
        let s = sante("echue");
        let store = ce2_store(&s);
        assert_eq!(
            ce2_cles(&store),
            cles(&["support_errors", "support_errors_last_code", "support_errors_last_ts"]),
            "fenêtre échue : les champs du compte restent servis : {store}"
        );
        assert_eq!(store["support_errors"], 8, "fenêtre échue : le compte reste, une de plus : {store}");
        assert_eq!(store["support_errors_last_ts"], ancien, "fenêtre échue : l'instant de la dernière reste : {store}");
        assert_eq!(store["support_errors_last_code"], rusqlite::ffi::SQLITE_FULL, "fenêtre échue : son code reste : {store}");
        assert_eq!(store["state"], "green", "fenêtre échue : l'état d'avant (vert) : {store}");
        let (disque, ajout) = ce2_couper(store["detail"].as_str().unwrap_or_default());
        assert!(disque.starts_with("disque données ") && ajout.is_none(), "fenêtre échue : le détail du disque seul : {store}");
        posture_suit("echue", &s, "green");

        // ⑤ LE COMPTE NE DIVERGE PAS DE LA LIGNE : autant de lignes `[sqlite]` capturées que d'erreurs vues par les
        // lectures (sept, servies à l'issue ③) ; l'erreur de ④, injectée au compte, ne passe pas par le site de la ligne.
        let lignes = stderr.lines().filter(|l| l.starts_with("[sqlite] erreur du support de la base : ")).count();
        assert_eq!(lignes, 7, "une ligne de journal par erreur comptée : {stderr}");
    }

    /// L'âge lu dans la phrase servie (entre « dernière il y a » et « s (»), sans borne d'horloge.
    fn ce2_age(detail: &str) -> i64 {
        let apres = detail.split_once("dernière il y a ").map(|(_, b)| b).unwrap_or_else(|| panic!("âge dit : {detail}"));
        apres.split_once("s (").and_then(|(a, _)| a.parse().ok()).unwrap_or_else(|| panic!("âge entier : {detail}"))
    }

    /// (2) LA FENÊTRE ET SES BORDS, À HORLOGE INJECTÉE (`etat_de_surface_erreurs_du_support`) : âge 0, âge fenêtre-1 ->
    /// jaune et la phrase entière ; âge = fenêtre et fenêtre+1 -> état ET détail d'avant, à l'identique ; un rouge du
    /// disque reste rouge ; une horloge en arrière dit âge 0 ; un instantané sans erreur (total 0, même avec un instant
    /// posé : la course entre la pose de l'instant et l'incrément) rend tout tel quel, un instant jamais posé (horloge
    /// antérieure à l'époque) aussi ; le nom du code est dit quand la table le connaît, le nombre seul sinon.
    ///
    /// MUTATIONS : `CE2_TOUJOURS_VERT` -> jaune attendu : ROUGE ; `CE2_FENETRE_INCLUSE` (`>` au lieu de `>=`) -> âge =
    /// fenêtre encore jaune : ROUGE ; `CE2_ROUGE_EFFACE` (`"yellow"` au lieu du pire des deux) -> rouge rendu jaune :
    /// ROUGE ; `CE2_SANS_TOTAL_NUL` (garde du total retirée) -> total 0 jaunit : ROUGE ; `CE2_NOM_IGNORE` (nom du code
    /// jamais dit) -> ROUGE.
    #[test]
    fn la_fenetre_d_aveu_et_ses_bords_a_horloge_injectee() {
        const T: i64 = 1_800_000_000;
        const D: &str = "disque données 40% utilisé (600 Mo libres / 1000 Mo)";
        let e = ErreursDuSupport { total: 3, derniere_ts: T, dernier_code: IOERR_READ };
        let surface = |etat: &'static str, e: &ErreursDuSupport, now: i64| {
            crate::metrics::etat_de_surface_erreurs_du_support(etat, D.to_string(), e, now)
        };
        let nom = "SQLITE_IOERR_READ, code étendu 266";
        assert_eq!(surface("green", &e, T), ("yellow", ce2_phrase(D, 3, 0, nom)), "âge 0 : jaune");
        assert_eq!(surface("green", &e, T + CE2_FENETRE_S - 1), ("yellow", ce2_phrase(D, 3, CE2_FENETRE_S - 1, nom)), "âge fenêtre-1 : jaune");
        assert_eq!(surface("green", &e, T + CE2_FENETRE_S), ("green", D.to_string()), "âge = fenêtre : l'état d'avant");
        assert_eq!(surface("green", &e, T + CE2_FENETRE_S + 1), ("green", D.to_string()), "âge fenêtre+1 : l'état d'avant");
        assert_eq!(surface("yellow", &e, T + CE2_FENETRE_S), ("yellow", D.to_string()), "hors fenêtre, un jaune du disque reste");
        assert_eq!(surface("red", &e, T + 5), ("red", ce2_phrase(D, 3, 5, nom)), "un rouge du disque reste rouge");
        assert_eq!(surface("green", &e, T - 30), ("yellow", ce2_phrase(D, 3, 0, nom)), "horloge en arrière : âge 0");
        let course = ErreursDuSupport { total: 0, derniere_ts: T, dernier_code: IOERR_READ };
        assert_eq!(surface("green", &course, T + 1), ("green", D.to_string()), "total 0 : rien à avouer");
        assert_eq!(surface("green", &ErreursDuSupport::default(), T), ("green", D.to_string()), "aucune erreur : rien");
        let sans_instant = ErreursDuSupport { total: 2, derniere_ts: 0, dernier_code: IOERR_READ };
        assert_eq!(surface("green", &sans_instant, T), ("green", D.to_string()), "instant jamais posé : hors de la fenêtre");
        let corrompue = ErreursDuSupport { total: 1, derniere_ts: T, dernier_code: rusqlite::ffi::SQLITE_CORRUPT };
        assert_eq!(surface("green", &corrompue, T + 2), ("yellow", ce2_phrase(D, 1, 2, "code étendu 11")), "code hors table : le nombre seul");
    }

    /// (3) LES CHAMPS SERVIS (`poser_les_erreurs_du_support`) : un vrai zéro sans instant ni code quand aucune erreur ;
    /// le compte, l'instant et le code sinon — servis quelle que soit la fenêtre (la fonction ne lit pas l'horloge).
    ///
    /// MUTATIONS : `CE2_ZERO_ABSENT` (zéro non posé) -> ROUGE ; `CE2_INSTANT_TOUJOURS` (instant et code posés à zéro
    /// erreur) -> ROUGE.
    #[test]
    fn les_champs_du_compte_restent_servis() {
        let mut m = serde_json::Map::new();
        crate::metrics::poser_les_erreurs_du_support(&mut m, &ErreursDuSupport::default());
        assert_eq!(Value::Object(m), json!({ "support_errors": 0 }), "aucune erreur : le vrai zéro seul");
        let mut m = serde_json::Map::new();
        let e = ErreursDuSupport { total: 4, derniere_ts: 1_700_000_123, dernier_code: rusqlite::ffi::SQLITE_NOTADB };
        crate::metrics::poser_les_erreurs_du_support(&mut m, &e);
        assert_eq!(
            Value::Object(m),
            json!({ "support_errors": 4, "support_errors_last_ts": 1_700_000_123i64, "support_errors_last_code": 26 }),
            "le compte, l'instant et le code de la dernière"
        );
    }

    /// (4) LE COMPTEUR (instance LOCALE du type du compte du processus) : chaque erreur incrémente, l'instant et le code
    /// sont ceux de la DERNIÈRE notée, même quand son instant est antérieur (horloge reculée).
    ///
    /// MUTATIONS : `CE2_PREMIER_CODE` (code et instant posés seulement à la première) -> ROUGE ; `CE2_INCREMENT_FIGE`
    /// (`store(1)` au lieu d'un incrément) -> ROUGE.
    #[test]
    fn le_compteur_garde_la_derniere_erreur() {
        let c = CompteDesErreursDuSupport::neuf();
        assert_eq!(c.instantane(), ErreursDuSupport::default(), "neuf : rien");
        c.noter(rusqlite::ffi::SQLITE_CORRUPT, 1000);
        c.noter(IOERR_READ, 2000);
        assert_eq!(c.instantane(), ErreursDuSupport { total: 2, derniere_ts: 2000, dernier_code: IOERR_READ });
        c.noter(rusqlite::ffi::SQLITE_FULL, 1500);
        assert_eq!(c.instantane(), ErreursDuSupport { total: 3, derniere_ts: 1500, dernier_code: rusqlite::ffi::SQLITE_FULL });
    }
}
