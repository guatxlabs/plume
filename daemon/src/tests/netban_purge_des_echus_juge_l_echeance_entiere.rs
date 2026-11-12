// `P11.25-a` (reste « la purge périodique juge encore une échéance non entière comme un nombre ») — LA PURGE DES
// BANS ÉCHUS JUGE L'ÉCHÉANCE COMME LES POSES ET LE CHARGEMENT, ET DIT QUAND ELLE N'A PAS EU LIEU.
//
// CONSTAT MESURÉ (base b46ef997, `server/boucles_de_fond.rs`, `spawn_netban_maintenance`) : toutes les 15 s,
// `let _ = c.execute("DELETE FROM net_ban WHERE expires_ts IS NOT NULL AND expires_ts <= ?1", …)`. La colonne est
// `INTEGER` sans `STRICT` : un réel à partie fractionnaire (ou un texte qui s'y convertit, ou un infini) y reste
// réel, la comparaison `<=` le rangeait comme un nombre, et la ligne était SUPPRIMÉE une fois l'instant passé ;
// le chargement (`auth::netban_charger_cap`) tient la même ligne pour un ban SANS FIN (échéance illisible). Un ban
// disparaissait sans geste ni trace. Un refus du moteur était tu (`let _ =`).
//
// CE QUI CHANGE : `auth::netban_purger_les_echus` (connexion + instant, rend l'issue) ne supprime qu'une échéance
// ENTIÈRE échue (`typeof(net_ban.expires_ts) = 'integer'`, le prédicat des poses à la lettre) ; le tick
// (`server::boucles_de_fond::netban_tick_de_maintenance`) lit l'issue, la dit au journal au CHANGEMENT d'état
// (`netban_ligne_de_la_purge`), classe un refus par `sqlite_plafond::journaliser_si_erreur_du_support` au même
// changement puis toutes les 300 s tant qu'il persiste (`netban_reclasser_le_refus` : l'aveu de la santé, tenu 900 s
// après la dernière erreur comptée, n'expire pas sous un refus continu), puis recharge le cache comme avant.
//
// `IS NOT NULL` n'est plus écrit : `typeof` rend `null` sur une ligne vide, et déjà sur la base la clause était
// sans effet (une comparaison avec NULL rend NULL, sqlite3.c:90896 de l'amalgamation vendorée). Le témoin de la
// ligne vide rougit sous le mutant qui la compte comme échue.
//
// Les témoins qui touchent le cache global prennent `NETBAN_TEST_LOCK` (déclaré dans `netban.rs`). Le journal est
// lu sur la sortie d'erreur d'un SOUS-PROCESSUS (état de la dernière purge et compte des erreurs du support : propres
// au processus). Aucun témoin ne lit l'horloge : l'instant est injecté.
//
// NE TIENT PAS : l'attente de 15 s de la boucle n'est pas jouée (son texte est lu) ; les refus sont FABRIQUÉS (une
// fonction substituée, appelée par un déclencheur `BEFORE DELETE` posé sur UNE ligne, rend le code voulu : aucun
// disque réellement en panne, aucun verrou réel).

#[cfg(test)]
mod netban_purge_des_echus {
    use super::*;
    use rusqlite::functions::FunctionFlags;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    /// L'instant injecté de la purge.
    const NPE_T: i64 = 1_900_000_000;
    /// Le prédicat de type, écrit ICI (jamais tiré de la production).
    const NPE_PREDICAT: &str = "typeof(net_ban.expires_ts) = 'integer'";
    /// Le message de l'erreur fabriquée.
    const NPE_MESSAGE: &str = "npe refus fabrique";

    /// Pose une ligne dont l'échéance est une EXPRESSION SQL : le type stocké est celui que décide SQLite (affinité).
    fn npe_poser(c: &Connection, ip: &str, echeance_sql: &str) {
        c.execute(
            &format!(
                "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) \
                 VALUES (?1, 't', 0, {echeance_sql}, 'operateur', 'prod')"
            ),
            params![ip],
        )
        .expect("fixture : ligne posée");
    }

    fn npe_restantes(c: &Connection) -> BTreeSet<String> {
        let mut s = c.prepare("SELECT ip FROM net_ban").unwrap();
        let v = s.query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<Result<BTreeSet<_>, _>>().unwrap();
        v
    }

    fn npe_types(c: &Connection) -> BTreeMap<String, String> {
        let mut s = c.prepare("SELECT ip, typeof(expires_ts) FROM net_ban").unwrap();
        let v = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<BTreeMap<_, _>, _>>()
            .unwrap();
        v
    }

    fn npe_ensemble(ips: &[&str]) -> BTreeSet<String> {
        ips.iter().map(|s| s.to_string()).collect()
    }

    /// Un déclencheur `BEFORE DELETE` refuse la suppression de la ligne `ip` : la fonction `npe_lever()` rend une erreur
    /// au code courant de `code`, SANS message — rusqlite poserait le message par `sqlite3_result_error`, qui ramène le
    /// code de la fonction à `SQLITE_ERROR` (mesuré : code étendu 1) ; sans message, le moteur prend le texte de son
    /// code. Rend la poignée du code, pour le changer entre deux ticks ; `DROP TRIGGER npe_refus` rétablit.
    fn npe_refuser_la_purge_de(c: &Connection, ip: &str, code: i32) -> Arc<AtomicI32> {
        let code = Arc::new(AtomicI32::new(code));
        let lu = code.clone();
        c.create_scalar_function("npe_lever", 0, FunctionFlags::SQLITE_UTF8, move |_ctx| -> rusqlite::Result<i64> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(lu.load(Ordering::SeqCst)), None))
        })
        .expect("fixture : fonction substituée");
        c.execute_batch(&format!(
            "CREATE TRIGGER npe_refus BEFORE DELETE ON net_ban WHEN old.ip = '{ip}' BEGIN SELECT npe_lever(); END;"
        ))
        .expect("fixture : déclencheur");
        code
    }

    /// (1) CHAQUE TYPE D'ÉCHÉANCE, sur le schéma réel (`schema.sql` + migrations) : le type stocké est relevé, la purge
    /// est jouée à `NPE_T`, l'ensemble EXACT des adresses restantes est comparé, puis ce que le chargement en rend
    /// (carte entière et compte des échéances illisibles). Lignes illisibles en tête, au milieu et en fin d'insertion.
    /// Mutants rouges : prédicat de type retiré (1, 11, 12 purgées), `<=` devenu `<` (4 reste), ligne vide comptée
    /// échue (7 purgée), issue jetée (`Ok(0)`), ancienne purge de la base (1, 11, 12 purgées).
    #[test]
    fn netban_purge_ne_retire_que_les_echeances_entieres_echues() {
        let c = test_db();
        // (adresse, échéance écrite, type stocké attendu)
        let cas: [(&str, &str, &str); 15] = [
            ("192.0.2.1", "1899999899.5", "real"),       // réel fractionnaire échu
            ("192.0.2.2", "1899999900", "integer"),      // entier échu
            ("192.0.2.3", "'jamais'", "text"),           // texte non numérique
            ("192.0.2.4", "1900000000", "integer"),      // entier à l'instant même
            ("192.0.2.5", "x'00'", "blob"),              // blob
            ("192.0.2.6", "1900000100", "integer"),      // entier futur
            ("192.0.2.7", "NULL", "null"),               // sans fin
            ("192.0.2.8", "1899999900.0", "integer"),    // réel entier : rangé entier par l'affinité
            ("192.0.2.9", "'1899999900'", "integer"),    // texte numérique entier : rangé entier
            ("192.0.2.10", "' 1899999900 '", "integer"), // texte numérique entouré de blanc : rangé entier
            ("192.0.2.11", "'1899999899.5'", "real"),    // texte numérique fractionnaire : rangé réel
            ("192.0.2.12", "-1e999", "real"),            // réel infini négatif
            ("192.0.2.13", "1900000100.5", "real"),      // réel fractionnaire futur
            ("192.0.2.14", "1900000001", "integer"),     // entier à l'instant + 1
            ("192.0.2.15", "1899999999", "integer"),     // entier à l'instant - 1
        ];
        for (ip, exp, _) in &cas {
            npe_poser(&c, ip, exp);
        }
        let attendus: BTreeMap<String, String> = cas.iter().map(|(ip, _, t)| (ip.to_string(), t.to_string())).collect();
        assert_eq!(npe_types(&c), attendus, "contrôle : le type stocké de chaque échéance, mesuré sur le schéma réel");

        let issue = crate::auth::netban_purger_les_echus(&c, NPE_T);
        let restantes = npe_restantes(&c);
        let charge = crate::auth::netban_charger_cap(&c, 100).expect("chargement après la purge");
        let releve: Vec<String> = cas
            .iter()
            .map(|(ip, exp, t)| {
                format!(
                    "{ip} {exp} ({t}) -> {} ; chargement {:?}",
                    if restantes.contains(*ip) { "gardée" } else { "purgée" },
                    charge.map.get(*ip)
                )
            })
            .collect();
        println!("NPE-RELEVE\n{}", releve.join("\n"));
        assert_eq!(issue.as_ref().ok(), Some(&6), "l'issue rend le nombre exact de lignes purgées : {issue:?}\n{releve:#?}");
        assert_eq!(
            restantes,
            npe_ensemble(&[
                "192.0.2.1", "192.0.2.3", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.11", "192.0.2.12",
                "192.0.2.13", "192.0.2.14",
            ]),
            "seules les échéances ENTIÈRES échues (la seconde même comprise) sont purgées : {releve:#?}"
        );
        let carte_attendue: HashMap<String, Option<i64>> = [
            ("192.0.2.1", None),
            ("192.0.2.3", None),
            ("192.0.2.5", None),
            ("192.0.2.6", Some(NPE_T + 100)),
            ("192.0.2.7", None),
            ("192.0.2.11", None),
            ("192.0.2.12", None),
            ("192.0.2.13", None),
            ("192.0.2.14", Some(NPE_T + 1)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(charge.map, carte_attendue, "le chargement tient chaque échéance illisible gardée pour un ban sans fin");
        assert_eq!(charge.echeances_illisibles, 6, "six échéances illisibles (réels, texte, blob), toutes encore en base");
        assert_eq!(charge.ip_illisibles, 0);
    }

    /// (2) LE MÊME PRÉDICAT QUE LES POSES : les trois `CASE` de la pose sans raccourcir et la purge portent
    /// `typeof(net_ban.expires_ts) = 'integer'`, à la lettre. Mutants rouges : prédicat changé dans la pose, retiré de la
    /// purge.
    #[test]
    fn netban_purge_et_poses_portent_le_meme_predicat_de_type() {
        assert_eq!(crate::auth::SQL_NETBAN_POSE_SANS_RACCOURCIR.matches(NPE_PREDICAT).count(), 3, "les trois CASE de la pose");
        assert_eq!(crate::auth::SQL_NETBAN_PURGE_DES_ECHUS.matches(NPE_PREDICAT).count(), 1, "la purge");
        assert!(crate::auth::SQL_NETBAN_PURGE_DES_ECHUS.starts_with("DELETE FROM net_ban WHERE "), "la purge est un DELETE de net_ban");
    }

    /// (3) UNE PURGE REFUSÉE REND SON ERREUR, et aucune ligne n'est retirée : le refus tombe sur la SECONDE ligne échue
    /// (insérée après la première, donc jugée après elle), l'instruction est annulée entière. Mutant rouge : issue
    /// jetée (`Ok(0)`).
    #[test]
    fn netban_purge_refusee_rend_son_erreur_sans_rien_retirer() {
        let c = test_db();
        npe_poser(&c, "192.0.2.81", "1899999900");
        npe_poser(&c, "192.0.2.82", "1899999950");
        npe_poser(&c, "192.0.2.83", "1900000100");
        let _code = npe_refuser_la_purge_de(&c, "192.0.2.82", rusqlite::ffi::SQLITE_BUSY);
        let issue = crate::auth::netban_purger_les_echus(&c, NPE_T);
        assert_eq!(
            issue.as_ref().err().and_then(|e| e.sqlite_error()).map(|f| f.extended_code),
            Some(rusqlite::ffi::SQLITE_BUSY),
            "le refus du moteur est RENDU avec son code : {issue:?}"
        );
        assert_eq!(
            npe_restantes(&c),
            npe_ensemble(&["192.0.2.81", "192.0.2.82", "192.0.2.83"]),
            "purge refusée : aucune ligne retirée, la première échue comprise"
        );
    }

    /// (4) PURGE PUIS RECHARGEMENT : après un tick, le cache ne porte pas la ligne purgée. Mutant rouge : rechargement
    /// joué AVANT la purge (la ligne échue reste au cache).
    #[test]
    fn netban_tick_purge_puis_recharge() {
        let _g = NETBAN_TEST_LOCK.lock();
        let c = test_db();
        npe_poser(&c, "192.0.2.61", "1899999900");
        npe_poser(&c, "192.0.2.62", "1900000100");
        netban_cache().write().clear();
        crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPE_T);
        let cache: HashMap<String, Option<i64>> = netban_cache().read().clone();
        netban_cache().write().clear();
        assert_eq!(npe_restantes(&c), npe_ensemble(&["192.0.2.62"]), "contrôle : la ligne échue est purgée");
        let attendu: HashMap<String, Option<i64>> = [("192.0.2.62".to_string(), Some(NPE_T + 100))].into_iter().collect();
        assert_eq!(cache, attendu, "le cache est rechargé APRÈS la purge");
    }

    /// (5) LE RECHARGEMENT EST JOUÉ MÊME QUAND LA PURGE EST REFUSÉE (comportement d'avant) : une ligne posée depuis
    /// arrive au cache. Mutant rouge : rechargement conditionné au succès de la purge.
    #[test]
    fn netban_tick_recharge_meme_purge_refusee() {
        let _g = NETBAN_TEST_LOCK.lock();
        let c = test_db();
        npe_poser(&c, "192.0.2.71", "1899999900");
        npe_poser(&c, "192.0.2.72", "1900000100");
        c.execute_batch("CREATE TRIGGER npe_abort BEFORE DELETE ON net_ban BEGIN SELECT RAISE(ABORT, 'npe abort'); END;").unwrap();
        netban_cache().write().clear();
        crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPE_T);
        let cache: HashMap<String, Option<i64>> = netban_cache().read().clone();
        netban_cache().write().clear();
        assert_eq!(npe_restantes(&c), npe_ensemble(&["192.0.2.71", "192.0.2.72"]), "contrôle : purge refusée");
        let attendu: HashMap<String, Option<i64>> =
            [("192.0.2.71".to_string(), Some(NPE_T - 100)), ("192.0.2.72".to_string(), Some(NPE_T + 100))].into_iter().collect();
        assert_eq!(cache, attendu, "le cache est rechargé malgré la purge refusée");
    }

    /// (6) LA LIGNE DU JOURNAL, BORNÉE AU CHANGEMENT D'ÉTAT (fonction pure, état local) : réussite tue au départ, refus
    /// dit une fois, refus au code neuf dit, retour dit une fois, erreur sans code SQLite dite. Chaque ligne comparée
    /// ENTIÈRE à une constante du témoin. Mutants rouges : borne retirée, état non posé, code ignoré.
    #[test]
    fn netban_purge_ligne_au_changement_d_etat() {
        use crate::server::boucles_de_fond::{netban_ligne_de_la_purge, EtatDeLaPurgeDesBans as E};
        let refus = |code: i32| -> rusqlite::Result<usize> {
            Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(NPE_MESSAGE.into())))
        };
        let issues: Vec<rusqlite::Result<usize>> = vec![
            Ok(3),
            refus(rusqlite::ffi::SQLITE_BUSY),
            refus(rusqlite::ffi::SQLITE_BUSY),
            refus(rusqlite::ffi::SQLITE_IOERR_WRITE),
            refus(rusqlite::ffi::SQLITE_IOERR_WRITE),
            Ok(0),
            Ok(2),
            Err(rusqlite::Error::QueryReturnedNoRows),
            Err(rusqlite::Error::QueryReturnedNoRows),
        ];
        let mut etat = E::Faite;
        let mut rendu: Vec<(Option<String>, E)> = Vec::new();
        for i in &issues {
            let l = netban_ligne_de_la_purge(&mut etat, i);
            rendu.push((l, etat));
        }
        let s = |t: &str| Some(t.to_string());
        let attendu: Vec<(Option<String>, E)> = vec![
            (None, E::Faite),
            (
                s("[netban] WARN purge des bans échus refusée : npe refus fabrique [code étendu 5] ; les lignes échues restent en base jusqu'à une purge réussie"),
                E::Refusee(Some(5)),
            ),
            (None, E::Refusee(Some(5))),
            (
                s("[netban] WARN purge des bans échus refusée : npe refus fabrique [SQLITE_IOERR_WRITE, code étendu 778] ; les lignes échues restent en base jusqu'à une purge réussie"),
                E::Refusee(Some(778)),
            ),
            (None, E::Refusee(Some(778))),
            (s("[netban] purge des bans échus rétablie"), E::Faite),
            (None, E::Faite),
            (
                s("[netban] WARN purge des bans échus refusée : Query returned no rows ; les lignes échues restent en base jusqu'à une purge réussie"),
                E::Refusee(None),
            ),
            (None, E::Refusee(None)),
        ];
        assert_eq!(rendu, attendu);
    }

    /// Le bloc ENTIER de la boucle des ticks dans `spawn_netban_maintenance` : le sommeil de 15 s, la prise du verrou,
    /// l'appel du tick — rien d'autre. Le fichier ne définit `netban_tick_de_maintenance` qu'une fois.
    fn npe_boucle_appelle_le_tick(src: &str) -> Result<(), String> {
        let debut = src.find("fn spawn_netban_maintenance(").ok_or("site absent")?;
        let corps = &src[debut..];
        let corps = &corps[..corps.find("\n}\n").ok_or("fin du site absente")?];
        let boucle = &corps[corps.find("loop {").ok_or("boucle absente")?..];
        let instructions: Vec<&str> = boucle
            .lines()
            .skip(1)
            .map(str::trim)
            .take_while(|l| *l != "}")
            .filter(|l| !l.is_empty() && !l.starts_with("//"))
            .collect();
        let attendu = [
            "std::thread::sleep(Duration::from_secs(15));",
            "let c = db.lock();",
            "netban_tick_de_maintenance(&c, now());",
        ];
        if instructions != attendu {
            return Err(format!("bloc de la boucle lu : {instructions:#?}"));
        }
        if src.matches("fn netban_tick_de_maintenance(").count() != 1 {
            return Err("une seule définition du tick".into());
        }
        Ok(())
    }

    /// (7) LA BOUCLE APPELLE LE TICK (texte lu, comme le préchauffage voisin) ; contre-épreuves `if false { … }` et
    /// retour de l'ancienne purge refusées par le même lecteur. Mutant rouge : la boucle n'appelle plus le tick.
    #[test]
    fn netban_boucle_de_maintenance_appelle_le_tick() {
        let src = include_str!("../server/boucles_de_fond.rs");
        assert_eq!(npe_boucle_appelle_le_tick(src), Ok(()));
        let appel = "netban_tick_de_maintenance(&c, now());";
        let mort = src.replacen(appel, &format!("if false {{ {appel} }}"), 1);
        assert_ne!(mort, src, "contrôle : la contre-épreuve a réécrit l'appel");
        assert!(npe_boucle_appelle_le_tick(&mort).is_err(), "un appel mort est refusé");
        let ancien = src.replacen(
            appel,
            "let _ = c.execute(\"DELETE FROM net_ban WHERE expires_ts IS NOT NULL AND expires_ts <= ?1\", params![now()]);\n            netban_reload(&c);",
            1,
        );
        assert!(npe_boucle_appelle_le_tick(&ancien).is_err(), "l'ancienne purge à la place du tick est refusée");
    }

    /// (8) LE JOURNAL ET LE CLASSEMENT, CAPTURÉS sur la sortie d'erreur d'un ENFANT (processus neuf : état de la
    /// dernière purge au départ, compte des erreurs du support propre). Un PREMIER tick réussi (instant où rien n'est
    /// échu, aucun refus posé) : rien ne s'écrit, l'état de départ est `Faite`. Puis deux ticks refusés `SQLITE_BUSY`
    /// (hors support), trois ticks refusés `SQLITE_IOERR_WRITE` (support) à `NPE_T`, au rappel moins une seconde et
    /// au rappel, deux ticks réussis : une ligne `[netban]` par changement, la ligne `[sqlite]` et un compte de la
    /// santé au changement puis au rappel seulement. Chaque ligne est comparée ENTIÈRE. Mutants rouges : départ
    /// `Refusee` (une ligne « rétablie » avant tout refus), issue jetée au tick, borne retirée, classement retiré,
    /// classement à chaque tick refusé, classement au seul changement (rappel retiré).
    #[test]
    fn netban_purge_refusee_dite_au_journal_au_changement() {
        const ENFANT: &str = "NETBAN_PURGE_DES_ECHUS_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let _g = NETBAN_TEST_LOCK.lock();
            let c = test_db();
            npe_poser(&c, "192.0.2.51", "1899999900");
            npe_poser(&c, "192.0.2.52", "1899999950");
            npe_poser(&c, "192.0.2.53", "1900000100");
            crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPE_T - 1000);
            eprintln!("NPE-MARQUE initiale");
            println!("NPE-APRES-INITIALE={:?}", npe_restantes(&c));
            let code = npe_refuser_la_purge_de(&c, "192.0.2.52", rusqlite::ffi::SQLITE_BUSY);
            let t0 = crate::sqlite_plafond::ErreursDuSupport::du_processus().total;
            for i in 1..=2 {
                crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPE_T);
                eprintln!("NPE-MARQUE occupee-{i}");
            }
            let t1 = crate::sqlite_plafond::ErreursDuSupport::du_processus().total;
            println!("NPE-APRES-REFUS={:?}", npe_restantes(&c));
            code.store(rusqlite::ffi::SQLITE_IOERR_WRITE, Ordering::SeqCst);
            let rappel = crate::server::boucles_de_fond::NETBAN_RAPPEL_DU_CLASSEMENT_S;
            for (i, t) in [(1, NPE_T), (2, NPE_T + rappel - 1), (3, NPE_T + rappel)] {
                crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, t);
                eprintln!("NPE-MARQUE support-{i}");
            }
            let t2 = crate::sqlite_plafond::ErreursDuSupport::du_processus().total;
            c.execute_batch("DROP TRIGGER npe_refus;").unwrap();
            for i in 1..=2 {
                crate::server::boucles_de_fond::netban_tick_de_maintenance(&c, NPE_T);
                eprintln!("NPE-MARQUE retablie-{i}");
            }
            println!("NPE-COMPTES={},{}", t1 - t0, t2 - t1);
            println!("NPE-APRES-RETOUR={:?}", npe_restantes(&c));
            println!("NPE-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::netban_purge_des_echus::netban_purge_refusee_dite_au_journal_au_changement",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("NPE-A-JOUE"), "contrôle : l'enfant a joué : {stdout}\n{stderr}");
        assert!(
            stdout.contains("NPE-APRES-INITIALE={\"192.0.2.51\", \"192.0.2.52\", \"192.0.2.53\"}\n"),
            "contrôle : le premier tick, à un instant où rien n'est échu, n'a rien retiré : {stdout}"
        );
        assert!(
            stdout.contains("NPE-APRES-REFUS={\"192.0.2.51\", \"192.0.2.52\", \"192.0.2.53\"}\n"),
            "purge refusée : rien n'est retiré : {stdout}"
        );
        assert!(stdout.contains("NPE-APRES-RETOUR={\"192.0.2.53\"}\n"), "purge rétablie : les échues partent : {stdout}");
        assert!(
            stdout.contains("NPE-COMPTES=0,2\n"),
            "le compte des erreurs du support : 0 pour l'occupée, 2 pour l'E/S répétée trois fois (changement, rappel) : {stdout}"
        );
        let lignes: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("[netban]") || l.starts_with("[sqlite]") || l.starts_with("NPE-MARQUE"))
            .collect();
        let attendu = [
            "NPE-MARQUE initiale",
            "[netban] WARN purge des bans échus refusée : database is locked [code étendu 5] ; les lignes échues restent en base jusqu'à une purge réussie",
            "NPE-MARQUE occupee-1",
            "NPE-MARQUE occupee-2",
            "[netban] WARN purge des bans échus refusée : disk I/O error [SQLITE_IOERR_WRITE, code étendu 778] ; les lignes échues restent en base jusqu'à une purge réussie",
            "[sqlite] erreur du support de la base : disk I/O error [SQLITE_IOERR_WRITE, code étendu 778]",
            "NPE-MARQUE support-1",
            "NPE-MARQUE support-2",
            "[sqlite] erreur du support de la base : disk I/O error [SQLITE_IOERR_WRITE, code étendu 778]",
            "NPE-MARQUE support-3",
            "[netban] purge des bans échus rétablie",
            "NPE-MARQUE retablie-1",
            "NPE-MARQUE retablie-2",
        ];
        assert_eq!(lignes, attendu, "sortie d'erreur entière de l'enfant :\n{stderr}");
    }

    /// (9) LE RAPPEL DU CLASSEMENT (fonction pure, instant injecté) : classé au changement d'état quel que soit
    /// l'instant, tu sous le rappel, classé au rappel à la seconde même (l'instant du classement repart de là), classé
    /// sur une horloge revenue en arrière ; le rappel est sous la fenêtre d'aveu de la santé. Mutants rouges : `>=`
    /// devenu `>`, instant non reposé, rappel retiré, horloge en arrière tue.
    #[test]
    fn netban_purge_refus_reclasse_au_rappel() {
        use crate::server::boucles_de_fond::{netban_reclasser_le_refus, NETBAN_RAPPEL_DU_CLASSEMENT_S as R};
        assert_eq!(R, 300, "le rappel vaut le tiers de la fenêtre d'aveu de 900 s");
        assert!(R < crate::metrics::FENETRE_D_AVEU_DES_ERREURS_DU_SUPPORT_S, "le rappel tombe dans la fenêtre d'aveu");
        // (changement d'état, instant) -> (classé, instant du classement après)
        let pas: [(bool, i64, bool, i64); 8] = [
            (true, NPE_T, true, NPE_T),
            (false, NPE_T + 1, false, NPE_T),
            (false, NPE_T + R - 1, false, NPE_T),
            (false, NPE_T + R, true, NPE_T + R),
            (false, NPE_T + R + 1, false, NPE_T + R),
            (true, NPE_T + R + 2, true, NPE_T + R + 2),
            (false, NPE_T + R + 3, false, NPE_T + R + 2),
            (false, NPE_T - 50, true, NPE_T - 50),
        ];
        let mut classe_ts = 0;
        let mut rendu = Vec::new();
        for (change, t, _, _) in pas {
            let classe = netban_reclasser_le_refus(&mut classe_ts, change, t);
            rendu.push((change, t, classe, classe_ts));
        }
        assert_eq!(rendu, pas.to_vec());
    }
}
