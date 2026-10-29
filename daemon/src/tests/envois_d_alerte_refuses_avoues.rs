// =====================================================================================
// `P10.33-h` (reste du dispatch) — UN ENVOI D'ALERTE QU'UN CANAL N'A PAS PRIS SE DIT ET SE COMPTE.
//
// VU (re-mesuré sur 2bbee64c) : `dispatch_notifications` jetait le verdict de chaque canal — `let _ =
// write_alert_to_lookup(..)` (un `Result`) et `let _ = notify_send(..)` (un booléen : faux pour la garde d'URL,
// une configuration incomplète, curl en échec, un genre inconnu) — puis posait `notified=1` : une alerte dont
// TOUS les canaux avaient refusé était marquée envoyée, sans journal ni compteur.
//
// DÉCISION PAR DÉFAUT (politique de renvoi non décidée, envoi irréversible côté PagerDuty/SMS) : avouer sans
// renvoyer ni changer le sens du marqueur. Chaque refus : une ligne (alerte, canal, genre, cause ; jamais l'URL,
// la configuration ni le contenu) et un compte par genre ; l'alerte qu'aucun canal visé n'a prise : une ligne et
// un compte, UNE fois par alerte.
//
// CE QUE CES TÉMOINS JOUENT : tout dans UN sous-processus (les compteurs sont des statiques de processus que
// d'autres témoins du dispatch font monter en parallèle — dans l'enfant, seul ce témoin tourne, donc les écarts
// sont EXACTS). Lookup refusé par un déclencheur `RAISE(ABORT)`, envoi refusé par la garde d'URL (adresse
// de bouclage : aucun réseau ; le faux curl n'est PAS appelé, c'est compté), genre inconnu (aucun réseau), canal sous le seuil, chemin nominal ; puis, par un FAUX
// `curl` en tête du `PATH` de l'enfant (patron `canal_remis_n_est_pas_lu`, adresse de documentation RFC 5737 que
// la garde laisse passer), un envoi réseau PRIS et un curl en échec ; un refus pour CHACUN des six genres réseau
// (chacun sur son compteur) ; une alerte sous silence (jamais « remise nulle part »).
// =====================================================================================
mod envois_d_alerte_refuses_avoues {
    use super::*;
    use crate::handlers::notifiers::{dispatch_notifications, GENRE_DE_CANAL_INCONNU};

    const AD3_ALERTE: i64 = 9101;
    const AD3_PHASE: &str = "AD3-PHASE:";
    const AD3_COMPTE: &str = "AD3-COMPTE:";
    /// Adresse de BOUCLAGE : la garde d'URL de `notify_send` la refuse avant tout réseau, quel que soit
    /// `PLUME_SSRF_BLOCK_PRIVATE` (une adresse RFC1918 comme `10.0.0.9` PASSAIT la garde par défaut avant `P7.20-a` : la version
    /// précédente de ce témoin lançait donc un vrai curl vers elle, refusé par l'expiration de `--max-time` et non par
    /// la garde ; le compte d'appels du faux curl le rend désormais visible). Porte un identifiant et un
    /// chemin reconnaissables, que la ligne de journal ne doit jamais contenir.
    const AD3_URL_BOUCLAGE: &str = "https://ad3:credence-ad3@127.0.0.9/sujet-ad3";
    const AD3_TITRE: &str = "TITRE-AD3";
    const AD3_DETAIL: &str = "DETAIL-AD3";
    const AD3_HOTE: &str = "192.0.2.77";
    const AD3_CAUSE_LOOKUP: &str = "lookup refuse par le temoin ad3";
    const AD3_CAUSE_ENVOI: &str = "envoi refusé : garde d'URL, configuration du canal incomplète ou curl en échec";
    const AD3_CAUSE_GENRE: &str = "genre de canal inconnu du démon, rien n'est parti";
    const AD3_GENRE_LIBRE: &str = "ad3-genre-libre";
    /// Adresse de documentation : la garde d'URL la laisse passer, le FAUX curl répond (aucun réseau). `ad3-echec`
    /// dans l'URL fait sortir le faux curl en 22 (le code de `-f` sur une réponse HTTP en erreur).
    const AD3_URL_PRISE: &str = "http://192.0.2.10/sujet-pris-ad3";
    const AD3_URL_ECHEC: &str = "http://192.0.2.10/ad3-echec";
    const AD3_FAUX_CURL: &str = "#!/bin/sh\n\
echo appel >> \"$AD3_APPELS\"\n\
cat > /dev/null\n\
case \"$*\" in *ad3-echec*) exit 22;; esac\n\
exit 0\n";
    /// Les compteurs lus, dans l'ordre des écarts : [total, alertes, puis un par genre].
    const AD3_GENRES: [&str; 8] = ["lookup", "ntfy", "webhook", "email", "slack", "pagerduty", "generic", GENRE_DE_CANAL_INCONNU];
    /// Fragments qui ne doivent paraître NULLE PART dans la sortie de l'enfant (URL, hôte, secrets de configuration,
    /// contenu de l'alerte, genre libre, nom du lookup).
    const AD3_INTERDITS: [&str; 17] = [
        "127.0.0.9", "credence-ad3", "sujet-ad3", "192.0.2.10", "sujet-pris-ad3", "ad3-echec", "jeton-ntfy-ad3",
        "slack-secret-ad3", "jeton-generic-ad3", "expediteur-ad3", "destinataire-ad3", "smtp-ad3",
        AD3_TITRE, AD3_DETAIL, AD3_HOTE, AD3_GENRE_LIBRE, "ad3_refuse",
    ];

    /// (id, genre, url, seuil, configuration)
    type Ad3Canal = (i64, &'static str, &'static str, i64, &'static str);
    const AD3_LOOKUP_REFUSE: Ad3Canal = (31, "lookup", "", 0, "{\"lookup\":\"ad3_refuse\",\"key_field\":\"host\"}");
    const AD3_LOOKUP_PRIS: Ad3Canal = (32, "lookup", "", 0, "{\"lookup\":\"ad3_pris\",\"key_field\":\"host\"}");
    const AD3_NTFY_REFUSE: Ad3Canal = (33, "ntfy", AD3_URL_BOUCLAGE, 0, "{}");
    const AD3_INCONNU: Ad3Canal = (34, AD3_GENRE_LIBRE, "", 0, "{}");
    const AD3_NTFY_SOUS_LE_SEUIL: Ad3Canal = (35, "ntfy", AD3_URL_BOUCLAGE, 4, "{}");
    const AD3_NTFY_PRIS: Ad3Canal = (36, "ntfy", AD3_URL_PRISE, 0, "{\"token\":\"jeton-ntfy-ad3\"}");
    const AD3_NTFY_CURL_ECHEC: Ad3Canal = (37, "ntfy", AD3_URL_ECHEC, 0, "{}");
    const AD3_WEBHOOK_REFUSE: Ad3Canal = (38, "webhook", AD3_URL_BOUCLAGE, 0, "{}");
    /// email : URL smtp de bouclage et configuration complète, donc refusé par la garde d'URL (pas par la configuration).
    const AD3_EMAIL_REFUSE: Ad3Canal =
        (39, "email", "smtp://smtp-ad3:x@127.0.0.9:25", 0, "{\"from\":\"expediteur-ad3@exemple.invalid\",\"to\":\"destinataire-ad3@exemple.invalid\"}");
    /// slack : la `webhook_url` (secrète) vise le bouclage, refusée par la garde d'URL.
    const AD3_SLACK_REFUSE: Ad3Canal = (40, "slack", "", 0, "{\"webhook_url\":\"https://127.0.0.9/slack-secret-ad3\"}");
    /// pagerduty : point d'arrivée FIXE (pas de garde d'URL à faire refuser) ; refusé par la configuration incomplète
    /// (`routing_key` absente), avant curl — le faux curl n'est donc pas appelé.
    const AD3_PAGERDUTY_REFUSE: Ad3Canal = (41, "pagerduty", "", 0, "{}");
    const AD3_GENERIC_REFUSE: Ad3Canal = (42, "generic", AD3_URL_BOUCLAGE, 0, "{\"auth_header\":\"Authorization: Bearer jeton-generic-ad3\"}");
    /// Phases où le faux curl est appelé (une fois chacune) : `reseau_pris`, `lookup_refuse_reseau_pris`, `curl_en_echec`.
    const AD3_APPELS_ATTENDUS: usize = 3;

    /// Une alerte de sévérité 3, non notifiée, et les canaux donnés ; le lookup `ad3_refuse` refuse toute écriture ;
    /// `silence` : un silence actif qui couvre l'alerte (par sa règle).
    fn ad3_base(canaux: &[Ad3Canal], silence: bool) -> Arc<Mutex<Connection>> {
        let conn = test_db();
        conn.execute_batch("DELETE FROM alert; DELETE FROM notifier;").unwrap();
        conn.execute(
            "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host) VALUES(?1,?2,'r.ad3',3,?3,?4,'new','','',?5)",
            params![AD3_ALERTE, now(), AD3_TITRE, AD3_DETAIL, AD3_HOTE],
        )
        .unwrap();
        for (id, kind, url, seuil, config) in canaux {
            conn.execute(
                "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(?1,'ad3',?2,1,?3,?4,?5)",
                params![id, kind, url, seuil, config],
            )
            .unwrap();
        }
        conn.execute_batch(&format!(
            "CREATE TRIGGER ad3_refus_lookup BEFORE INSERT ON lookup_kv WHEN NEW.name='ad3_refuse' \
             BEGIN SELECT RAISE(ABORT,'{AD3_CAUSE_LOOKUP}'); END;"
        ))
        .unwrap();
        if silence {
            conn.execute(
                "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES('{\"source\":\"r.ad3\"}',4102444800,'maintenance ad3',1,'adm')",
                [],
            )
            .unwrap();
        }
        Arc::new(Mutex::new(conn))
    }

    fn ad3_comptes() -> [u64; 10] {
        let mut c = [0u64; 10];
        c[0] = crate::metrics::ENVOIS_D_ALERTE_REFUSES_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
        c[1] = crate::metrics::ALERTES_SANS_AUCUN_ENVOI_PRIS_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
        for (i, g) in AD3_GENRES.iter().enumerate() {
            c[2 + i] = crate::metrics::envoi_d_alerte_refuse_de(g).map(|(n, _)| n).unwrap_or(0);
        }
        c
    }

    /// Les phases jouées par l'enfant : (nom, canaux, silence, écarts attendus
    /// [total, alertes, lookup, ntfy, webhook, email, slack, pagerduty, generic, inconnu]).
    #[allow(clippy::type_complexity)]
    fn ad3_phases() -> Vec<(&'static str, Vec<Ad3Canal>, bool, [u64; 10])> {
        vec![
            ("lookup_refuse", vec![AD3_LOOKUP_REFUSE], false, [1, 1, 1, 0, 0, 0, 0, 0, 0, 0]),
            ("envoi_refuse", vec![AD3_NTFY_REFUSE], false, [1, 1, 0, 1, 0, 0, 0, 0, 0, 0]),
            ("un_seul_refuse", vec![AD3_LOOKUP_PRIS, AD3_NTFY_REFUSE], false, [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            ("tous_refuses", vec![AD3_LOOKUP_REFUSE, AD3_NTFY_REFUSE], false, [2, 1, 1, 1, 0, 0, 0, 0, 0, 0]),
            ("genre_inconnu", vec![AD3_INCONNU], false, [1, 1, 0, 0, 0, 0, 0, 0, 0, 1]),
            ("sous_le_seuil", vec![AD3_NTFY_SOUS_LE_SEUIL], false, [0; 10]),
            ("nominal", vec![AD3_LOOKUP_PRIS], false, [0; 10]),
            ("reseau_pris", vec![AD3_NTFY_PRIS], false, [0; 10]),
            ("lookup_refuse_reseau_pris", vec![AD3_LOOKUP_REFUSE, AD3_NTFY_PRIS], false, [1, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
            ("curl_en_echec", vec![AD3_NTFY_CURL_ECHEC], false, [1, 1, 0, 1, 0, 0, 0, 0, 0, 0]),
            ("webhook_refuse", vec![AD3_WEBHOOK_REFUSE], false, [1, 1, 0, 0, 1, 0, 0, 0, 0, 0]),
            ("email_refuse", vec![AD3_EMAIL_REFUSE], false, [1, 1, 0, 0, 0, 1, 0, 0, 0, 0]),
            ("slack_refuse", vec![AD3_SLACK_REFUSE], false, [1, 1, 0, 0, 0, 0, 1, 0, 0, 0]),
            ("pagerduty_refuse", vec![AD3_PAGERDUTY_REFUSE], false, [1, 1, 0, 0, 0, 0, 0, 1, 0, 0]),
            ("generic_refuse", vec![AD3_GENERIC_REFUSE], false, [1, 1, 0, 0, 0, 0, 0, 0, 1, 0]),
            ("silencee", vec![AD3_NTFY_REFUSE], true, [0; 10]),
        ]
    }

    fn ad3_refus(canal: i64, genre: &str, cause: &str) -> String {
        format!("[plume] dispatch : alerte {AD3_ALERTE} : envoi NON PRIS par le canal {canal} (genre {genre}), aucun renvoi : {cause}")
    }
    fn ad3_aucun(vises: usize) -> String {
        format!(
            "[plume] dispatch : alerte {AD3_ALERTE} : AUCUN des {vises} canal(aux) visé(s) n'a pris l'envoi, alerte remise nulle part ; \
             aucun renvoi n'est tenté (politique non décidée)"
        )
    }

    /// Mutations éprouvées (retirées avant le commit) que ce témoin fait rougir : `ad3_lookup_muet` (lookup refusé pris pour un envoi),
    /// `ad3_envoi_muet` (envoi refusé non compté), `ad3_un_seul_suffit` (alerte comptée dès UN refus),
    /// `ad3_par_canal` (alerte comptée une fois par canal refusé), `ad3_sans_vise` (alerte sans canal visé comptée),
    /// `ad3_url_au_journal` (URL du canal dans la cause), `ad3_genre_brut` (genre libre pris comme clé) ; puis
    /// `ad3c_reseau_pris_non_compte` (envoi réseau réussi non compté comme pris), `ad3c_webhook_sous_ntfy`,
    /// `ad3c_email_inconnu`, `ad3c_slack_inconnu`, `ad3c_pagerduty_sous_generic`, `ad3c_generic_sous_webhook` (genre
    /// compté sous une autre clé), `ad3c_silencee_comptee` (alerte silencée comptée remise nulle part),
    /// `ad3c_url_autre_ligne` (URL du canal sur une autre ligne du journal), `ad3c_curl_toujours_pris` (curl en échec
    /// pris pour un succès).
    #[test]
    fn ad3_chaque_envoi_refuse_est_journalise_et_compte_et_l_alerte_remise_nulle_part_une_fois() {
        const ENFANT: &str = "AD3_ENFANT_ENVOIS_REFUSES";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            for (nom, canaux, silence, _) in ad3_phases() {
                let db = ad3_base(&canaux, silence);
                let avant = ad3_comptes();
                eprintln!("{AD3_PHASE}{nom}");
                dispatch_notifications(&db);
                let apres = ad3_comptes();
                let ecarts: Vec<String> = avant.iter().zip(apres.iter()).map(|(a, b)| (b - a).to_string()).collect();
                let marquee: i64 =
                    db.lock().query_row("SELECT notified FROM alert WHERE id=?1", params![AD3_ALERTE], |r| r.get(0)).unwrap();
                println!("{AD3_COMPTE}{nom}:{}:marquee={marquee}", ecarts.join(","));
            }
            eprintln!("{AD3_PHASE}fin");
            let conn = test_db();
            let j = crate::gather_json(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
            println!("AD3-JSON:{}", j["scheduler"]);
            let prom = crate::gather_prom(&conn, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
            for l in prom.lines().filter(|l| l.starts_with("plume_scheduler_envois_d_alerte") || l.starts_with("plume_scheduler_alertes_sans")) {
                println!("AD3-PROM:{l}");
            }
            return;
        }
        // Le faux curl, en tête du `PATH` de l'ENFANT seul (le processus du test n'est pas touché ; le verrou
        // d'environnement est tenu en lecture comme dans le patron).
        let bac = crate::tmp_possede::TmpPossede::neuf("ad3-faux-curl");
        let appels = bac.join("appels");
        let faux = bac.join("curl");
        std::fs::write(&faux, AD3_FAUX_CURL).expect("fixture : faux curl écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux curl exécutable");
        }
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::envois_d_alerte_refuses_avoues::ad3_chaque_envoi_refuse_est_journalise_et_compte_et_l_alerte_remise_nulle_part_une_fois",
            ])
            .env(ENFANT, "1")
            .env("PATH", &path)
            .env("AD3_APPELS", &appels)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let nb_appels = std::fs::read_to_string(&appels).unwrap_or_default().lines().count();
        assert_eq!(nb_appels, AD3_APPELS_ATTENDUS, "contrôle positif : le faux curl est appelé une fois par phase réseau : {stdout}\n{stderr}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AD3_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AD3_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[plume] dispatch :")).map(str::to_string).collect()
        };

        // Les écarts de compte, EXACTS (l'enfant ne fait tourner que ce témoin), et le marqueur posé comme avant.
        let phases = ad3_phases();
        assert!(phases.len() >= 16, "plancher : les seize phases sont jouées");
        for g in ["webhook", "email", "slack", "pagerduty", "generic"] {
            assert!(
                phases.iter().any(|(_, canaux, _, _)| canaux.iter().any(|c| c.1 == g)),
                "chaque genre réseau de `notify_send` a sa phase : {g}"
            );
        }
        for (nom, _, _, attendu) in &phases {
            let ecarts = attendu.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
            // `split_once` : libtest écrit le nom du test SANS saut de ligne, la première ligne servie le suit.
            let ligne = format!("{nom}:{ecarts}:marquee=1");
            assert!(
                stdout.lines().filter_map(|l| l.split_once(AD3_COMPTE).map(|(_, r)| r)).any(|r| r == ligne),
                "phase {nom} : écarts [total, alertes, lookup, ntfy, webhook, email, slack, pagerduty, generic, inconnu] attendus {ligne} : {stdout}"
            );
        }

        // Les lignes de journal, EXACTES, phase par phase.
        assert_eq!(phase("lookup_refuse"), vec![ad3_refus(31, "lookup", AD3_CAUSE_LOOKUP), ad3_aucun(1)], "lookup refusé : cause du moteur, puis l'alerte remise nulle part");
        assert_eq!(phase("envoi_refuse"), vec![ad3_refus(33, "ntfy", AD3_CAUSE_ENVOI), ad3_aucun(1)], "envoi refusé : la cause dit les causes possibles");
        assert_eq!(phase("un_seul_refuse"), vec![ad3_refus(33, "ntfy", AD3_CAUSE_ENVOI)], "un canal a pris l'envoi : le refus est dit, l'alerte n'est PAS remise nulle part");
        assert_eq!(
            phase("tous_refuses"),
            vec![ad3_refus(31, "lookup", AD3_CAUSE_LOOKUP), ad3_refus(33, "ntfy", AD3_CAUSE_ENVOI), ad3_aucun(2)],
            "tous refusés : deux refus, UNE ligne d'alerte remise nulle part"
        );
        assert_eq!(phase("genre_inconnu"), vec![ad3_refus(34, GENRE_DE_CANAL_INCONNU, AD3_CAUSE_GENRE), ad3_aucun(1)], "genre libre : un seul nom de compte");
        assert!(phase("sous_le_seuil").is_empty(), "aucun canal visé : rien à avouer : {:?}", phase("sous_le_seuil"));
        assert!(phase("nominal").is_empty(), "chemin nominal muet : {:?}", phase("nominal"));
        assert!(phase("reseau_pris").is_empty(), "envoi réseau pris : rien à avouer : {:?}", phase("reseau_pris"));
        assert_eq!(
            phase("lookup_refuse_reseau_pris"),
            vec![ad3_refus(31, "lookup", AD3_CAUSE_LOOKUP)],
            "le lookup refusé est dit ; le canal réseau a pris l'envoi : l'alerte n'est PAS remise nulle part"
        );
        assert_eq!(phase("curl_en_echec"), vec![ad3_refus(37, "ntfy", AD3_CAUSE_ENVOI), ad3_aucun(1)], "curl en échec : refus dit");
        for (nom, canal, genre) in [
            ("webhook_refuse", 38, "webhook"),
            ("email_refuse", 39, "email"),
            ("slack_refuse", 40, "slack"),
            ("pagerduty_refuse", 41, "pagerduty"),
            ("generic_refuse", 42, "generic"),
        ] {
            assert_eq!(phase(nom), vec![ad3_refus(canal, genre, AD3_CAUSE_ENVOI), ad3_aucun(1)], "{nom} : refus nommé sous son genre");
        }
        assert!(phase("silencee").is_empty(), "alerte silencée : ni refus ni « remise nulle part » : {:?}", phase("silencee"));
        // TOUTE la sortie de l'enfant (erreur ET standard), pas seulement les lignes du dispatch.
        for (flux, texte) in [("stderr", &stderr), ("stdout", &stdout)] {
            for interdit in AD3_INTERDITS {
                assert!(
                    !texte.contains(interdit),
                    "jamais l'URL, l'hôte, la configuration, le contenu ni le genre libre ({interdit}) sur {flux} : {texte}"
                );
            }
        }

        // Ce que sert le bilan (`/api/metrics` scheduler, `/metrics`) : la somme exacte des phases.
        let json_servi = stdout.lines().find_map(|l| l.split_once("AD3-JSON:").map(|(_, r)| r)).unwrap_or_else(|| panic!("contrôle : JSON servi : {stdout}"));
        let s: Value = serde_json::from_str(json_servi).expect("JSON du bilan");
        assert_eq!(s["envois_d_alerte_refuses_total"], json!(13), "treize envois non pris en tout : {s}");
        assert_eq!(s["alertes_sans_aucun_envoi_pris_total"], json!(10), "dix alertes remises nulle part (une par phase concernée) : {s}");
        assert_eq!(
            s["envois_d_alerte_refuses"],
            json!({
                "lookup": { "n": 3, "derniere_cause": AD3_CAUSE_LOOKUP },
                "ntfy": { "n": 4, "derniere_cause": AD3_CAUSE_ENVOI },
                "webhook": { "n": 1, "derniere_cause": AD3_CAUSE_ENVOI },
                "email": { "n": 1, "derniere_cause": AD3_CAUSE_ENVOI },
                "slack": { "n": 1, "derniere_cause": AD3_CAUSE_ENVOI },
                "pagerduty": { "n": 1, "derniere_cause": AD3_CAUSE_ENVOI },
                "generic": { "n": 1, "derniere_cause": AD3_CAUSE_ENVOI },
                GENRE_DE_CANAL_INCONNU: { "n": 1, "derniere_cause": AD3_CAUSE_GENRE },
            }),
            "ventilation par genre, exacte : {s}"
        );
        let prom: Vec<&str> = stdout.lines().filter_map(|l| l.split_once("AD3-PROM:").map(|(_, r)| r)).collect();
        assert_eq!(
            prom,
            vec!["plume_scheduler_envois_d_alerte_refuses_total 13", "plume_scheduler_alertes_sans_aucun_envoi_pris_total 10"],
            "les deux séries Prometheus : {stdout}"
        );
    }
}
