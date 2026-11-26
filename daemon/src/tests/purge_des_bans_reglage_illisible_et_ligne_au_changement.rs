// =====================================================================================
// `P11.25-a` (`rollups.rs`, `materialize_banned_ip`) — LA PURGE OPTIONNELLE DES BANS EXPIRÉS DE `banned_ip` DIT UN RÉGLAGE
// ILLISIBLE, ET SA LIGNE DE REFUS N'EST PLUS ÉCRITE À CHAQUE PASSAGE.
//
// LES DÉFAUTS, LUS SUR ecc5b404 :
//  * `cfg(&conf, "PLUME_BANNED_IP_RETENTION", "0").parse().unwrap_or(0)` : une valeur vide, négative, non entière ou hors
//    de l'entier 64 bits valait l'absence — purge désactivée, sans un mot ;
//  * sous un refus continu de la base, `[rollup] WARN purge des bans expirés de banned_ip NON faite (...)` revenait à
//    chaque passage de la boucle des rollups.
//
// DÉSORMAIS : absent et `0` gardent leur sens (purge désactivée), un entier strictement positif (blancs autour admis)
// l'active ; tout le reste est ILLISIBLE, ne purge pas, et le dit au journal UNE fois par changement de lecture (cause
// dans un vocabulaire fermé, jamais la valeur), le retour à une valeur lisible se dit aussi. La ligne de refus de la
// purge n'est écrite qu'au changement d'état de la purge de CETTE base (code étendu compris), le retour à une purge
// faite se dit ; le compte du refus reste posé à chaque passage. Un redémarrage redit une fois (état en mémoire du
// processus : chaque sous-processus ci-dessous part de zéro, et sa première ligne est dite).
//
// Journal lu sur le stderr d'un sous-processus, lignes ENTIÈRES, phase par phase ; refus fabriqué par autorisateur
// SQLite (`DELETE` sur `banned_ip`).
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable d'environnement de mutation sous `cfg!(test)`, retirées du source avant
// le commit), chacune seule :
//  * « BANS_SANS_ROGNAGE » (pas de `trim`) : (a) ;
//  * « BANS_NEGATIVE_DESACTIVEE » (une valeur négative vaut l'absence, en silence) : (a), (c) ;
//  * « BANS_DEBORDEMENT_NON_ENTIER » (hors de l'entier 64 bits rangé sous « non entière ») : (a) ;
//  * « BANS_ILLISIBLE_REDIT » (la lecture illisible écrite à chaque passage) : (b), (c) ;
//  * « BANS_RELU_MUET » (le retour à une valeur lisible n'est pas dit) : (b), (c) ;
//  * « BANS_ILLISIBLE_PURGE » (une valeur illisible active la purge à zéro seconde) : (c) ;
//  * « BANS_REFUS_REDIT » (la ligne de refus écrite à chaque passage : la forme d'avant) : (d), (e) ;
//  * « BANS_RETABLIE_MUETTE » (le retour à une purge faite n'est pas dit) : (d), (e) ;
//  * « BANS_CODE_IGNORE » (un code étendu neuf n'est pas un état neuf) : (d) ;
//  * « BANS_ETAT_GLOBAL » (un seul état pour toutes les bases) : (e) ;
//  * « BANS_COMPTE_AU_CHANGEMENT » (le refus compté seulement quand la ligne est écrite) : (e) ;
//  * « BANS_CODE_PRIMAIRE » (l'état de la purge ne garde que le code primaire, `extended_code & 0xff`) : (d) ;
//  * « BANS_REGLAGE_PAR_BASE » (l'état du réglage remis à zéro quand la base change : une ligne par base) : (c).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la boucle elle-même (`server::boucles_de_fond::spawn_rollup_loop`) n'est pas
// jouée — `materialize_banned_ip` est appelée directement, comme par la boucle ; aucune surface de santé ne porte ce
// réglage (ses voisins `PLUME_BANNED_IP_BACKFILL`, `PLUME_ROLLUP_DIM_BACKFILL` n'y figurent pas non plus).
// =====================================================================================
mod purge_des_bans_reglage_illisible_et_ligne_au_changement {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use crate::rollups::{
        ligne_de_la_purge_des_bans, ligne_du_reglage_de_retention_des_bans, retention_des_bans_selon, RetentionDesBans,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const JOUR: i64 = 86400;
    const BANS_REGLAGE: &str = "PLUME_BANNED_IP_RETENTION";
    const BANS_IP: &str = "192.0.2.47";
    const BANS_TETE: &str = "[rollup]";
    const BANS_SUJET: &str = "purge des bans expirés de banned_ip";
    const BANS_PHASE: &str = "BANS-PHASE:";
    const BANS_COMPTE: &str = "geste de fond non validé rollup : purge des bans expirés de banned_ip : purge refusée";
    const BANS_LIGNE_REFUS_AUTH: &str =
        "[rollup] WARN purge des bans expirés de banned_ip NON faite (not authorized) — bans expirés gardés, purge reprise au prochain passage";
    const BANS_LIGNE_REFUS_OCCUPEE: &str =
        "[rollup] WARN purge des bans expirés de banned_ip NON faite (base occupée) — bans expirés gardés, purge reprise au prochain passage";
    const BANS_LIGNE_REFUS_IO: &str =
        "[rollup] WARN purge des bans expirés de banned_ip NON faite (disk I/O error) — bans expirés gardés, purge reprise au prochain passage";
    const BANS_LIGNE_REFUS_SANS_CODE: &str =
        "[rollup] WARN purge des bans expirés de banned_ip NON faite (Query returned no rows) — bans expirés gardés, purge reprise au prochain passage";
    const BANS_LIGNE_RETABLIE: &str = "[rollup] purge des bans expirés de banned_ip rétablie";
    const BANS_LIGNE_NON_ENTIERE: &str = "[rollup] WARN PLUME_BANNED_IP_RETENTION illisible (non entière) : ni absent, ni un entier positif ou nul — purge des bans expirés de banned_ip NON faite tant qu'il l'est";
    const BANS_LIGNE_NEGATIVE: &str = "[rollup] WARN PLUME_BANNED_IP_RETENTION illisible (négative) : ni absent, ni un entier positif ou nul — purge des bans expirés de banned_ip NON faite tant qu'il l'est";
    const BANS_LIGNE_VIDE: &str = "[rollup] WARN PLUME_BANNED_IP_RETENTION illisible (vide) : ni absent, ni un entier positif ou nul — purge des bans expirés de banned_ip NON faite tant qu'il l'est";
    const BANS_LIGNE_RELU_ACTIVE: &str =
        "[rollup] PLUME_BANNED_IP_RETENTION relu : purge des bans expirés de banned_ip active, rétention de 86400 s";
    const BANS_LIGNE_RELU_ACTIVE_60: &str =
        "[rollup] PLUME_BANNED_IP_RETENTION relu : purge des bans expirés de banned_ip active, rétention de 60 s";
    const BANS_LIGNE_RELU_DESACTIVEE: &str = "[rollup] PLUME_BANNED_IP_RETENTION relu : purge des bans expirés de banned_ip désactivée";

    fn ban_expire(conn: &rusqlite::Connection) {
        let vieux = now() - 10 * JOUR;
        conn.execute(
            "INSERT OR REPLACE INTO banned_ip(src_ip,source,label,first_seen,last_seen) VALUES(?1,'fail2ban','sshd',?2,?2)",
            params![BANS_IP, vieux],
        )
        .unwrap();
    }

    fn ban_present(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM banned_ip WHERE src_ip=?1", params![BANS_IP], |r| r.get(0)).unwrap()
    }

    fn refuser_la_purge(conn: &rusqlite::Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "banned_ip" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn laisser_passer(conn: &rusqlite::Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn erreur(code: i32, message: &str) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(message.to_string()))
    }

    /// Les lignes de la purge des bans (préfixe `[rollup]` et sujet), phase par phase.
    fn phase(stderr: &str, nom: &str) -> Vec<String> {
        let debut = stderr
            .split_once(&format!("{BANS_PHASE}{nom}\n"))
            .unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}"))
            .1;
        let corps = debut.split_once(BANS_PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.starts_with(BANS_TETE) && l.contains(BANS_SUJET)).map(str::to_string).collect()
    }

    /// (a) CHAQUE FORME DU RÉGLAGE, par la fonction que `materialize_banned_ip` appelle sur la valeur de `cfg`.
    #[test]
    fn a_chaque_forme_du_reglage() {
        // absent : `cfg` rend le défaut "0"
        assert_eq!(retention_des_bans_selon("0"), RetentionDesBans::Desactivee, "absent ou zéro : purge désactivée");
        assert_eq!(retention_des_bans_selon("-0"), RetentionDesBans::Desactivee, "« -0 » est zéro");
        assert_eq!(retention_des_bans_selon("86400"), RetentionDesBans::Active(86400), "entier positif : purge active");
        assert_eq!(retention_des_bans_selon("1"), RetentionDesBans::Active(1), "bord : un");
        assert_eq!(retention_des_bans_selon(" 86400 \n"), RetentionDesBans::Active(86400), "blancs autour : rognés");
        assert_eq!(retention_des_bans_selon("9223372036854775807"), RetentionDesBans::Active(i64::MAX), "bord haut de l'entier 64 bits");
        assert_eq!(retention_des_bans_selon(""), RetentionDesBans::Illisible("vide"), "vide");
        assert_eq!(retention_des_bans_selon("   "), RetentionDesBans::Illisible("vide"), "blancs seuls : vide");
        assert_eq!(retention_des_bans_selon("-1"), RetentionDesBans::Illisible("négative"), "bord : moins un");
        assert_eq!(retention_des_bans_selon("-86400"), RetentionDesBans::Illisible("négative"), "négative");
        assert_eq!(retention_des_bans_selon("1.5"), RetentionDesBans::Illisible("non entière"), "réel");
        assert_eq!(retention_des_bans_selon("30j"), RetentionDesBans::Illisible("non entière"), "unité collée");
        assert_eq!(retention_des_bans_selon("abc"), RetentionDesBans::Illisible("non entière"), "texte");
        assert_eq!(retention_des_bans_selon("9223372036854775808"), RetentionDesBans::Illisible("hors de l'entier 64 bits"), "bord : MAX + 1");
        assert_eq!(retention_des_bans_selon("-99999999999999999999"), RetentionDesBans::Illisible("hors de l'entier 64 bits"), "sous MIN");
    }

    /// (b) LA LIGNE DU RÉGLAGE, par sa fonction pure : dite au changement, pas à chaque lecture.
    #[test]
    fn b_ligne_du_reglage_au_changement() {
        let mut dernier: Option<&'static str> = None;
        assert_eq!(ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Active(86400)), None, "lisible au départ : rien");
        assert_eq!(ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Desactivee), None, "lisible au départ : rien");
        assert_eq!(
            ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Illisible("vide")).as_deref(),
            Some(BANS_LIGNE_VIDE),
            "illisible : la ligne entière"
        );
        assert_eq!(ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Illisible("vide")), None, "même lecture : rien");
        assert_eq!(
            ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Illisible("non entière")).as_deref(),
            Some(BANS_LIGNE_NON_ENTIERE),
            "cause neuve : ligne neuve"
        );
        assert_eq!(
            ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Desactivee).as_deref(),
            Some(BANS_LIGNE_RELU_DESACTIVEE),
            "retour à zéro : dit"
        );
        assert_eq!(ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Desactivee), None, "même lecture : rien");
        assert_eq!(
            ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Illisible("négative")).as_deref(),
            Some(BANS_LIGNE_NEGATIVE),
            "illisible à nouveau : dit"
        );
        assert_eq!(
            ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Active(60)).as_deref(),
            Some(BANS_LIGNE_RELU_ACTIVE_60),
            "retour à une rétention : dit avec sa valeur"
        );
        assert_eq!(ligne_du_reglage_de_retention_des_bans(&mut dernier, &RetentionDesBans::Active(60)), None, "même lecture : rien");
    }

    /// (c) LE RÉGLAGE PAR `materialize_banned_ip`, dans un sous-processus qui change le réglage entre les passages : ligne
    /// entière par phase, et l'effet sur le ban expiré (gardé tant que la purge ne tourne pas, retiré quand elle tourne).
    #[test]
    fn c_reglage_lu_par_la_materialisation() {
        let _env = VERROU_ENV_PROCESSUS.write(); // l'enfant pose le réglage dans son propre processus, sous ce même verrou
        const ENFANT: &str = "BANS_C_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = sp_state("bans-c");
            let conn = st.db.lock();
            let passe = |nom: &str, valeur: Option<&str>| {
                match valeur {
                    Some(v) => std::env::set_var(BANS_REGLAGE, v),
                    None => std::env::remove_var(BANS_REGLAGE),
                }
                ban_expire(&conn);
                eprintln!("{BANS_PHASE}{nom}");
                materialize_banned_ip(&conn);
                println!("BANS-BAN-{nom}:{}", ban_present(&conn));
            };
            passe("non_entiere_1", Some("abc"));
            passe("non_entiere_2", Some("abc"));
            passe("negative", Some("-5"));
            passe("active_1", Some("86400"));
            passe("active_2", Some("86400"));
            passe("absent", None);
            passe("zero", Some("0"));
            passe("vide", Some(""));
            passe("zero_apres_vide", Some("0"));
            drop(conn);
            // deux bases jouées en alternance sous un même réglage illisible : l'état du réglage est celui du PROCESSUS,
            // une seule ligne en tout (une ligne par base et par passage serait le défaut d'avant, multiplié par les tenants)
            let (sa, _pa) = sp_state("bans-c-a");
            let (sb, _pb) = sp_state("bans-c-b");
            let a = sa.db.lock();
            let b = sb.db.lock();
            std::env::set_var(BANS_REGLAGE, "abc");
            for nom in ["alterne_a_1", "alterne_b_1", "alterne_a_2", "alterne_b_2"] {
                let base: &rusqlite::Connection = if nom.contains("_a_") { &a } else { &b };
                ban_expire(base);
                eprintln!("{BANS_PHASE}{nom}");
                materialize_banned_ip(base);
                println!("BANS-BAN-{nom}:{}", ban_present(base));
            }
            eprintln!("{BANS_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_des_bans_reglage_illisible_et_ligne_au_changement::c_reglage_lu_par_la_materialisation",
            ])
            .env(ENFANT, "1")
            .env_remove(BANS_REGLAGE)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ban = |nom: &str| -> i64 {
            let m = format!("BANS-BAN-{nom}:");
            let reste = stdout.split_once(&m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste[..1].parse().unwrap()
        };
        assert_eq!(phase(&stderr, "non_entiere_1"), vec![BANS_LIGNE_NON_ENTIERE.to_string()], "illisible : dit une fois");
        assert_eq!(ban("non_entiere_1"), 1, "illisible : le ban expiré reste (aucune purge)");
        assert_eq!(phase(&stderr, "non_entiere_2"), Vec::<String>::new(), "même lecture au passage suivant : rien");
        assert_eq!(ban("non_entiere_2"), 1, "illisible : le ban expiré reste");
        assert_eq!(phase(&stderr, "negative"), vec![BANS_LIGNE_NEGATIVE.to_string()], "cause neuve : dite");
        assert_eq!(ban("negative"), 1, "négative : le ban expiré reste");
        assert_eq!(phase(&stderr, "active_1"), vec![BANS_LIGNE_RELU_ACTIVE.to_string()], "retour à une rétention : dit");
        assert_eq!(ban("active_1"), 0, "rétention active : le ban expiré part");
        assert_eq!(phase(&stderr, "active_2"), Vec::<String>::new(), "rétention inchangée : rien");
        assert_eq!(ban("active_2"), 0, "rétention active : le ban expiré part");
        assert_eq!(phase(&stderr, "absent"), Vec::<String>::new(), "absent après une rétention : lisible après lisible, rien");
        assert_eq!(ban("absent"), 1, "absent : purge désactivée, le ban reste");
        assert_eq!(phase(&stderr, "zero"), Vec::<String>::new(), "zéro après absent : même sens, rien");
        assert_eq!(ban("zero"), 1, "zéro : purge désactivée, le ban reste");
        assert_eq!(phase(&stderr, "vide"), vec![BANS_LIGNE_VIDE.to_string()], "vide : illisible, dit");
        assert_eq!(ban("vide"), 1, "vide : le ban reste");
        assert_eq!(phase(&stderr, "zero_apres_vide"), vec![BANS_LIGNE_RELU_DESACTIVEE.to_string()], "zéro après illisible : retour dit");
        assert_eq!(ban("zero_apres_vide"), 1, "zéro : le ban reste");
        assert_eq!(phase(&stderr, "alterne_a_1"), vec![BANS_LIGNE_NON_ENTIERE.to_string()], "base A, illisible : dit une fois");
        for nom in ["alterne_b_1", "alterne_a_2", "alterne_b_2"] {
            assert_eq!(phase(&stderr, nom), Vec::<String>::new(), "{nom} : même lecture, autre base ou non : rien");
            assert_eq!(ban(nom), 1, "{nom} : illisible, le ban expiré reste");
        }
    }

    /// (d) LA LIGNE DE LA PURGE, par sa fonction pure : un refus qui persiste une fois, un code étendu neuf, une erreur sans
    /// code SQLite, le retour.
    #[test]
    fn d_ligne_de_la_purge_au_changement() {
        let mut dernier: Option<Option<i32>> = None;
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &Ok(3)), None, "faite au départ : rien");
        let auth = || Err(erreur(rusqlite::ffi::SQLITE_AUTH, "not authorized"));
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &auth()).as_deref(), Some(BANS_LIGNE_REFUS_AUTH), "refus : la ligne entière");
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &auth()), None, "même refus : rien");
        assert_eq!(
            ligne_de_la_purge_des_bans(&mut dernier, &Err(erreur(rusqlite::ffi::SQLITE_BUSY, "base occupée"))).as_deref(),
            Some(BANS_LIGNE_REFUS_OCCUPEE),
            "code étendu neuf : ligne neuve"
        );
        // même code primaire (`SQLITE_IOERR`), codes étendus distincts, même message : l'état porte le code ÉTENDU, pas
        // seulement son octet bas
        let io = |code: i32| Err(erreur(code, "disk I/O error"));
        assert_eq!(
            ligne_de_la_purge_des_bans(&mut dernier, &io(rusqlite::ffi::SQLITE_IOERR_READ)).as_deref(),
            Some(BANS_LIGNE_REFUS_IO),
            "erreur d'entrée-sortie en lecture : ligne neuve"
        );
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &io(rusqlite::ffi::SQLITE_IOERR_READ)), None, "même code étendu : rien");
        assert_eq!(
            ligne_de_la_purge_des_bans(&mut dernier, &io(rusqlite::ffi::SQLITE_IOERR_WRITE)).as_deref(),
            Some(BANS_LIGNE_REFUS_IO),
            "même primaire, code étendu neuf (écriture après lecture) : ligne neuve"
        );
        assert_eq!(
            ligne_de_la_purge_des_bans(&mut dernier, &Err(rusqlite::Error::QueryReturnedNoRows)).as_deref(),
            Some(BANS_LIGNE_REFUS_SANS_CODE),
            "erreur sans code SQLite : état distinct"
        );
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &Err(rusqlite::Error::QueryReturnedNoRows)), None, "même erreur : rien");
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &Ok(0)).as_deref(), Some(BANS_LIGNE_RETABLIE), "retour : dit");
        assert_eq!(ligne_de_la_purge_des_bans(&mut dernier, &Ok(0)), None, "faite à nouveau : rien");
    }

    /// (e) LA PURGE PAR `materialize_banned_ip`, sous-processus, rétention d'un jour : deux passages refusés sur la même
    /// base -> une ligne, mais deux comptes ; le retour -> « rétablie » ; un nouveau refus -> la ligne à nouveau. Deux bases
    /// alternées (l'une refusée, l'autre non) n'ont qu'une ligne en tout : l'état est celui de chaque base.
    #[test]
    fn e_purge_lue_par_la_materialisation() {
        let _env = VERROU_ENV_PROCESSUS.read(); // l'enfant reçoit le réglage par son environnement
        const ENFANT: &str = "BANS_E_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = sp_state("bans-e");
            let conn = st.db.lock();
            let passe = |conn: &rusqlite::Connection, nom: &str, refuser: bool| {
                ban_expire(conn);
                if refuser {
                    refuser_la_purge(conn);
                }
                eprintln!("{BANS_PHASE}{nom}");
                materialize_banned_ip(conn);
                laisser_passer(conn);
            };
            passe(&conn, "refus_1", true);
            passe(&conn, "refus_2", true);
            println!("BANS-COMPTE-APRES-2:{}", compte_des_temoins(&conn, BANS_COMPTE));
            passe(&conn, "retour", false);
            println!("BANS-BAN-RETOUR:{}", ban_present(&conn));
            passe(&conn, "faite", false);
            passe(&conn, "refus_3", true);
            println!("BANS-COMPTE-APRES-3:{}", compte_des_temoins(&conn, BANS_COMPTE));
            drop(conn);
            let (sa, _pa) = sp_state("bans-e-a");
            let (sb, _pb) = sp_state("bans-e-b");
            let a = sa.db.lock();
            let b = sb.db.lock();
            passe(&a, "a_1", true);
            passe(&b, "b_1", false);
            passe(&a, "a_2", true);
            passe(&b, "b_2", false);
            eprintln!("{BANS_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_des_bans_reglage_illisible_et_ligne_au_changement::e_purge_lue_par_la_materialisation",
            ])
            .env(ENFANT, "1")
            .env(BANS_REGLAGE, "86400")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for m in ["BANS-COMPTE-APRES-2:2", "BANS-BAN-RETOUR:0", "BANS-COMPTE-APRES-3:3"] {
            assert!(stdout.contains(m), "compte posé à chaque passage refusé, purge faite au retour : {m} : {stdout}");
        }
        let refus = vec![BANS_LIGNE_REFUS_AUTH.to_string()];
        let rien = Vec::<String>::new();
        assert_eq!(phase(&stderr, "refus_1"), refus, "premier refus du processus : dit une fois");
        assert_eq!(phase(&stderr, "refus_2"), rien, "même refus au passage suivant : rien");
        assert_eq!(phase(&stderr, "retour"), vec![BANS_LIGNE_RETABLIE.to_string()], "retour : dit");
        assert_eq!(phase(&stderr, "faite"), rien, "faite à nouveau : rien");
        assert_eq!(phase(&stderr, "refus_3"), refus, "nouveau refus : dit");
        assert_eq!(phase(&stderr, "a_1"), refus, "base A refusée : dit");
        assert_eq!(phase(&stderr, "b_1"), rien, "base B faite : rien (son état n'est pas celui de A)");
        assert_eq!(phase(&stderr, "a_2"), rien, "base A refusée encore : rien");
        assert_eq!(phase(&stderr, "b_2"), rien, "base B faite encore : rien");
    }
}
