// LA COPIE HORS SITE ATTESTÉE : CE QUE PLUME EN DIT, PAR LA ROUTE ET PAR LES JAUGES.
// ================================================================================================
// LE DÉFAUT. Rien dans le produit ne disait si une copie des sauvegardes quittait le disque de la
// base, ni depuis quand. Le poste de l'exploitant TIRE la copie et dépose une ligne d'attestation ;
// le composant `copie_hors_site` (daemon/src/copie_hors_site.rs) la lit et en publie l'état.
//
// CE QUI EST TÉMOIGNÉ. Chaque état (non déclarée, non suivie, fraîche, périmée) et chaque refus
// nommé, PAR LA ROUTE `/api/system/health` (routeur réel, jeton du lecteur) avec l'objet du composant
// comparé EN ENTIER à un littéral, et par le gestionnaire de `/metrics` (jauges présentes ou
// absentes) ; le bord de l'âge maximal et de la tolérance d'horloge sur la fonction pure à horloge
// injectée (la route lit l'horloge réelle) ; aucun chemin de l'hôte dans le corps servi.
//
// Les réglages sont posés dans l'environnement du processus : chaque témoin qui les pose prend
// `VERROU_ENV_PROCESSUS.write()` et les retire en sortie (même sur échec).

    use crate::copie_hors_site as chs;

    const CHS_SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHS_ARCHIVE: &str = "plume-20261103T020000Z.db.age";
    const CHS_REFUS_TETE: &str = "attestation de copie hors site REFUSÉE : ";
    const CHS_REFUS_QUEUE: &str = " — ce n'est PAS « jamais copiée », l'âge de la dernière copie n'est pas établi";

    /// Retire les deux réglages à la sortie du témoin, échec compris.
    struct ChsReglages;
    impl Drop for ChsReglages {
        fn drop(&mut self) {
            std::env::remove_var(chs::REGLAGE_ATTESTATION);
            std::env::remove_var(chs::REGLAGE_AGE_MAX_HEURES);
        }
    }

    fn chs_poser(attestation: Option<&str>, age_max: Option<&str>) -> ChsReglages {
        match attestation {
            Some(v) => std::env::set_var(chs::REGLAGE_ATTESTATION, v),
            None => std::env::remove_var(chs::REGLAGE_ATTESTATION),
        }
        match age_max {
            Some(v) => std::env::set_var(chs::REGLAGE_AGE_MAX_HEURES, v),
            None => std::env::remove_var(chs::REGLAGE_AGE_MAX_HEURES),
        }
        ChsReglages
    }

    /// Le corps ENTIER de `/api/system/health` par le routeur réel, jeton du lecteur, et l'objet du
    /// composant (présent exactement une fois).
    async fn chs_sante(addr: std::net::SocketAddr) -> (String, Value) {
        let (code, brut) = router_probe_corps(addr, "GET", "/api/system/health", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "la santé se lit avec le jeton du lecteur : {brut}");
        let (tete, trame) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("réponse HTTP entière : {brut}"));
        let corps = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(trame.as_bytes()).unwrap_or_else(|| panic!("trame découpée lisible : {brut}"))).unwrap()
        } else {
            trame.to_string()
        };
        let corps = corps.as_str();
        let v: Value = serde_json::from_str(corps).unwrap_or_else(|e| panic!("corps JSON ({e}) : {corps}"));
        let trouves: Vec<Value> = v["components"].as_array().expect("liste de composants").iter()
            .filter(|c| c["component"] == chs::COMPOSANT).cloned().collect();
        assert_eq!(trouves.len(), 1, "le composant `copie_hors_site` apparaît exactement une fois : {corps}");
        (corps.to_string(), trouves[0].clone())
    }

    /// Les lignes de `/metrics` (gestionnaire de la route) qui portent sur la copie hors site.
    async fn chs_jauges(st: &AppState) -> Vec<String> {
        let r = crate::handlers::system::metrics_endpoint(State(st.clone())).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&b).lines()
            .filter(|l| !l.starts_with('#') && (l.starts_with("plume_offsite_copy") || l.contains("component=\"copie_hors_site\"")))
            .map(str::to_string).collect()
    }

    fn chs_refusee(detail_cause: &str, mot: &str, max_age_s: Value) -> Value {
        json!({
            "component": "copie_hors_site", "state": "yellow",
            "detail": format!("{CHS_REFUS_TETE}{detail_cause}{CHS_REFUS_QUEUE}"),
            "copy_state": "refusee", "refusal": mot, "overdue": null, "age_s": null,
            "last_copy_ts": null, "archive": null, "sha256": null, "max_age_s": max_age_s,
        })
    }

    /// Un refus par la route : objet entier, aucune jauge d'âge ni de retard, composant à 0.5.
    async fn chs_refus_par_la_route(addr: std::net::SocketAddr, st: &AppState, attendu: Value) {
        let (_, comp) = chs_sante(addr).await;
        assert_eq!(comp, attendu, "refus servi en entier");
        assert_eq!(chs_jauges(st).await, vec!["plume_component_up{component=\"copie_hors_site\"} 0.5".to_string()],
            "un refus n'établit rien : ni `plume_offsite_copy_overdue` ni `plume_offsite_copy_age_seconds`");
    }

    /// NON DÉCLARÉE : réglage absent, puis réglage fait d'espaces. Jaune, aucune jauge établie.
    #[tokio::test]
    async fn chs_non_declaree_est_jaune_et_n_etablit_aucune_jauge() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let (st, _dbp) = router_test_state("chs-non-declaree");
        let addr = router_serve(st.clone()).await;
        let attendu = json!({
            "component": "copie_hors_site", "state": "yellow",
            "detail": "copie hors site NON DÉCLARÉE (PLUME_COPIE_HORS_SITE_ATTESTATION vide) : plume ne sait pas si les sauvegardes quittent ce disque ; si elles y restent, perdre le disque perd la base ET ses sauvegardes",
            "copy_state": "non_declaree", "refusal": null, "overdue": null, "age_s": null,
            "last_copy_ts": null, "archive": null, "sha256": null, "max_age_s": 172800,
        });
        {
            let _r = chs_poser(None, None);
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "réglage absent : non déclarée, âge maximal par défaut servi");
            assert_eq!(chs_jauges(&st).await, vec!["plume_component_up{component=\"copie_hors_site\"} 0.5".to_string()]);
        }
        {
            let _r = chs_poser(Some("   "), None);
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "un chemin fait d'espaces n'est pas un chemin : non déclarée");
        }
    }

    /// FRAÎCHE puis PÉRIMÉE (défaut 48 h), puis bord de l'âge maximal réglé à 1 h (juste avant,
    /// juste après), par la route et par les jauges.
    #[tokio::test]
    async fn chs_fraiche_puis_perimee_par_la_route_et_les_jauges() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let (st, _dbp) = router_test_state("chs-fraiche");
        let addr = router_serve(st.clone()).await;
        let dir = crate::tmp_possede::TmpPossede::neuf("chs-fraiche");
        let f = dir.sous("attestation");
        let _r = chs_poser(Some(f.as_str()), None);

        // (1) trois heures : fraîche, verte, âge et retard établis.
        let ts = now() - 3 * 3600;
        std::fs::write(&*f, format!("{ts} {CHS_ARCHIVE} {CHS_SHA}\n")).unwrap();
        let (corps, mut comp) = chs_sante(addr).await;
        assert!(!corps.contains(dir.racine().as_str()), "le chemin du fichier n'est servi nulle part : {corps}");
        let age = comp["age_s"].as_i64().expect("âge établi");
        assert!(age >= 3 * 3600, "âge = maintenant - horodatage attesté : {age}");
        comp["age_s"] = json!("<age>");
        assert_eq!(comp, json!({
            "component": "copie_hors_site", "state": "green",
            "detail": "dernière copie hors site il y a 3 h (plume-20261103T020000Z.db.age)",
            "copy_state": "fraiche", "refusal": null, "overdue": false, "age_s": "<age>",
            "last_copy_ts": ts, "archive": CHS_ARCHIVE, "sha256": CHS_SHA, "max_age_s": 172800,
        }));
        // L'âge publié est ÉPINGLÉ : encadré entre deux relevés de l'horloge pris autour de la
        // lecture des jauges (un horodatage ou un âge doublé sort du cadre).
        let avant = now();
        let j = chs_jauges(&st).await;
        let apres = now();
        assert_eq!(j.len(), 3, "{j:?}");
        assert_eq!(j[0], "plume_component_up{component=\"copie_hors_site\"} 1");
        assert_eq!(j[1], "plume_offsite_copy_overdue 0");
        let age_publie: i64 = j[2].strip_prefix("plume_offsite_copy_age_seconds ").expect("jauge d'âge").parse().unwrap();
        assert!((avant - ts..=apres - ts).contains(&age_publie), "âge publié hors de [{}, {}] : {j:?}", avant - ts, apres - ts);

        // (2) quarante-neuf heures : périmée, jaune, retard 1.
        let ts = now() - 49 * 3600;
        std::fs::write(&*f, format!("{ts} {CHS_ARCHIVE} {CHS_SHA}\n")).unwrap();
        let (_, mut comp) = chs_sante(addr).await;
        assert!(comp["age_s"].as_i64().unwrap() >= 49 * 3600);
        comp["age_s"] = json!("<age>");
        assert_eq!(comp, json!({
            "component": "copie_hors_site", "state": "yellow",
            "detail": "dernière copie hors site il y a 2 j (plume-20261103T020000Z.db.age) — au-delà de l'âge maximal (PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES)",
            "copy_state": "perimee", "refusal": null, "overdue": true, "age_s": "<age>",
            "last_copy_ts": ts, "archive": CHS_ARCHIVE, "sha256": CHS_SHA, "max_age_s": 172800,
        }));
        let avant = now();
        let j = chs_jauges(&st).await;
        let apres = now();
        assert_eq!(&j[..2], &["plume_component_up{component=\"copie_hors_site\"} 0.5".to_string(), "plume_offsite_copy_overdue 1".to_string()]);
        let age_publie: i64 = j[2].strip_prefix("plume_offsite_copy_age_seconds ").expect("jauge d'âge").parse().unwrap();
        assert!((avant - ts..=apres - ts).contains(&age_publie), "âge publié hors de [{}, {}] : {j:?}", avant - ts, apres - ts);

        // (3) âge maximal 1 h (valeur entourée d'espaces) : dix minutes avant le bord, dix minutes après.
        drop(_r);
        let _r = chs_poser(Some(f.as_str()), Some(" 1 "));
        std::fs::write(&*f, format!("{} {CHS_ARCHIVE} {CHS_SHA}", now() - 3600 + 600)).unwrap();
        let (_, comp) = chs_sante(addr).await;
        assert_eq!((comp["copy_state"].clone(), comp["max_age_s"].clone()), (json!("fraiche"), json!(3600)),
            "juste avant le bord (sans `\\n` final) : {comp}");
        std::fs::write(&*f, format!("{} {CHS_ARCHIVE} {CHS_SHA}\n", now() - 3600 - 600)).unwrap();
        let (_, comp) = chs_sante(addr).await;
        assert_eq!(comp["copy_state"], "perimee", "juste après le bord : {comp}");
    }

    /// ZÉRO : suivi désactivé et DIT, `idle`, même quand le fichier déclaré est absent.
    #[tokio::test]
    async fn chs_zero_desactive_le_suivi_et_le_dit() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let (st, _dbp) = router_test_state("chs-zero");
        let addr = router_serve(st.clone()).await;
        let dir = crate::tmp_possede::TmpPossede::neuf("chs-zero");
        let f = dir.sous("absente");
        let _r = chs_poser(Some(f.as_str()), Some("0"));
        let (_, comp) = chs_sante(addr).await;
        assert_eq!(comp, json!({
            "component": "copie_hors_site", "state": "idle",
            "detail": "copie hors site NON SUIVIE (PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES=0) : l'âge de la dernière copie hors site n'est pas surveillé",
            "copy_state": "non_suivi", "refusal": null, "overdue": null, "age_s": null,
            "last_copy_ts": null, "archive": null, "sha256": null, "max_age_s": 0,
        }));
        assert_eq!(chs_jauges(&st).await, vec!["plume_component_up{component=\"copie_hors_site\"} 1".to_string()]);
    }

    /// LES REFUS DE LECTURE ET DE FORME, chacun nommé par la route, objet entier.
    #[tokio::test]
    async fn chs_chaque_refus_est_nomme_par_la_route() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let (st, _dbp) = router_test_state("chs-refus");
        let addr = router_serve(st.clone()).await;
        let dir = crate::tmp_possede::TmpPossede::neuf("chs-refus");
        let defaut = json!(172800);

        // absent
        let absent = dir.sous("absente");
        let r = chs_poser(Some(absent.as_str()), None);
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "fichier d'attestation absent au chemin de PLUME_COPIE_HORS_SITE_ATTESTATION", "attestation_absente", defaut.clone())).await;
        drop(r);

        // illisible : un composant du chemin est un fichier (ENOTDIR, errno 20), quel que soit l'utilisateur
        let fichier = dir.sous("fichier");
        std::fs::write(&*fichier, "x").unwrap();
        let sous_fichier = format!("{}/attestation", fichier.as_str());
        let r = chs_poser(Some(&sous_fichier), None);
        let (corps, _) = chs_sante(addr).await;
        assert!(!corps.contains(dir.racine().as_str()), "un refus ne sert pas le chemin : {corps}");
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "fichier d'attestation illisible (errno 20)", "attestation_illisible", defaut.clone())).await;
        drop(r);

        // pas un fichier : un répertoire
        let r = chs_poser(Some(dir.racine().as_str()), None);
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "le chemin de PLUME_COPIE_HORS_SITE_ATTESTATION n'est pas un fichier ordinaire", "attestation_pas_un_fichier", defaut.clone())).await;
        drop(r);

        // trop grand : la taille EXACTE (relue par stat) est dite ; le fichier commence par une ligne valide
        let f = dir.sous("attestation");
        let mut gros = format!("{} {CHS_ARCHIVE} {CHS_SHA}\n", now() - 60);
        gros.push_str(&"#".repeat(2000 - gros.len()));
        std::fs::write(&*f, &gros).unwrap();
        let r = chs_poser(Some(f.as_str()), None);
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "fichier d'attestation de 2000 octets, au-delà de la borne de 1024 octets : non lu", "attestation_trop_grande", defaut.clone())).await;
        // à la borne exacte : lu (et ici hors forme, ce qui prouve qu'il a été lu)
        std::fs::write(&*f, "#".repeat(1024)).unwrap();
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "attendu une seule ligne `<horodatage unix> <archive> <sha256>`", "ligne_hors_forme", defaut.clone())).await;

        // forme : horodatage, nom, empreinte
        let ok_ts = now() - 60;
        std::fs::write(&*f, format!("+{ok_ts} {CHS_ARCHIVE} {CHS_SHA}\n")).unwrap();
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "horodatage qui n'est pas un entier décimal positif", "horodatage_hors_forme", defaut.clone())).await;
        std::fs::write(&*f, format!("{ok_ts} /srv/sauvegardes/{CHS_ARCHIVE} {CHS_SHA}\n")).unwrap();
        let (corps, _) = chs_sante(addr).await;
        assert!(!corps.contains("/srv/sauvegardes"), "un nom refusé n'est pas servi : {corps}");
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "nom d'archive hors de la forme `plume-AAAAMMJJTHHMMSSZ.db.age`", "nom_d_archive_hors_forme", defaut.clone())).await;
        std::fs::write(&*f, format!("{ok_ts} {CHS_ARCHIVE} {}\n", &CHS_SHA[1..])).unwrap();
        chs_refus_par_la_route(addr, &st, chs_refusee(
            "empreinte qui n'est pas un SHA-256 hexadécimal de 64 caractères", "empreinte_hors_forme", defaut.clone())).await;

        // futur au-delà de la tolérance : l'avance servie est celle de l'instant du calcul
        let futur = now() + 100_000;
        std::fs::write(&*f, format!("{futur} {CHS_ARCHIVE} {CHS_SHA}\n")).unwrap();
        let t0 = now();
        let (_, comp) = chs_sante(addr).await;
        let t1 = now();
        let candidats: Vec<Value> = (t0..=t1).map(|t| chs_refusee(&format!(
            "attestation datée dans le futur ({} s d'avance, tolérance 3600 s) : horloge de qui écrit l'attestation ou de ce nœud à vérifier", futur - t),
            "datee_dans_le_futur", defaut.clone())).collect();
        assert!(candidats.contains(&comp), "futur refusé et nommé : {comp}");
        assert_eq!(chs_jauges(&st).await, vec!["plume_component_up{component=\"copie_hors_site\"} 0.5".to_string()]);
        drop(r);
    }

    /// RÉGLAGE D'ÂGE ILLISIBLE : refusé et nommé (jamais remplacé par le défaut), même sur un fichier
    /// valide ; `max_age_s` servi `null`.
    #[tokio::test]
    async fn chs_un_reglage_d_age_illisible_est_refuse_et_nomme() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let (st, _dbp) = router_test_state("chs-reglage");
        let addr = router_serve(st.clone()).await;
        let dir = crate::tmp_possede::TmpPossede::neuf("chs-reglage");
        let f = dir.sous("attestation");
        std::fs::write(&*f, format!("{} {CHS_ARCHIVE} {CHS_SHA}\n", now() - 60)).unwrap();
        let attendu = chs_refusee("PLUME_COPIE_HORS_SITE_MAX_AGE_HEURES n'est pas un entier positif ou nul", "reglage_age_illisible", Value::Null);
        {
            let _r = chs_poser(Some(f.as_str()), Some("-1"));
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "réglage -1");
        }
        {
            let _r = chs_poser(Some(f.as_str()), Some("1.5"));
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "réglage 1.5");
        }
        {
            let _r = chs_poser(Some(f.as_str()), Some("douze"));
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "réglage douze");
        }
        {
            let _r = chs_poser(Some(f.as_str()), Some("9223372036854775807"));
            let (_, comp) = chs_sante(addr).await;
            assert_eq!(comp, attendu, "réglage 9223372036854775807");
        }
        let _r = chs_poser(None, Some("douze"));
        chs_refus_par_la_route(addr, &st, attendu.clone()).await;
    }

    /// LA LIGNE, EN FONCTION PURE : chaque élément de la forme a son cas refusé.
    #[test]
    fn chs_la_ligne_refuse_chaque_ecart_de_forme() {
        let ok = format!("1762135200 {CHS_ARCHIVE} {CHS_SHA}");
        let attendu = chs::Attestation { ts: 1_762_135_200, archive: CHS_ARCHIVE.into(), sha256: CHS_SHA.into() };
        assert_eq!(chs::lire_la_ligne(&ok), Ok(attendu.clone()), "sans `\\n` final");
        assert_eq!(chs::lire_la_ligne(&format!("{ok}\n")), Ok(attendu), "un `\\n` final admis");
        let maj = CHS_SHA.to_uppercase();
        assert_eq!(chs::lire_la_ligne(&format!("1 {CHS_ARCHIVE} {maj}")).map(|a| a.sha256), Ok(maj.clone()), "hexadécimal majuscule admis, servi tel quel");
        use chs::Refus::*;
        let refuse = |ligne: String, refus: chs::Refus| assert_eq!(chs::lire_la_ligne(&ligne), Err(refus), "ligne {ligne:?}");
        refuse(String::new(), LigneHorsForme);
        refuse(format!("{ok}\n\n"), LigneHorsForme);
        refuse(format!("{ok}\r\n"), LigneHorsForme);
        refuse(format!("{ok}\nautre ligne"), LigneHorsForme);
        refuse(format!("1762135200 {CHS_ARCHIVE}"), LigneHorsForme);
        refuse(format!("{ok} en-trop"), LigneHorsForme);
        refuse(format!("1762135200  {CHS_ARCHIVE} {CHS_SHA}"), LigneHorsForme);
        refuse(format!("+1762135200 {CHS_ARCHIVE} {CHS_SHA}"), HorodatageHorsForme);
        refuse(format!("-1 {CHS_ARCHIVE} {CHS_SHA}"), HorodatageHorsForme);
        refuse(format!("99999999999999999999 {CHS_ARCHIVE} {CHS_SHA}"), HorodatageHorsForme);
        refuse(format!("1762135200 sauve-20261103T020000Z.db.age {CHS_SHA}"), NomDArchiveHorsForme);
        refuse(format!("1762135200 plume-20261103T020000Z.db {CHS_SHA}"), NomDArchiveHorsForme);
        refuse(format!("1762135200 plume-20261303T020000Z.db.age {CHS_SHA}"), NomDArchiveHorsForme);
        refuse(format!("1762135200 plume-2026-11-03.db.age {CHS_SHA}"), NomDArchiveHorsForme);
        refuse(format!("1762135200 {CHS_ARCHIVE} {}", &CHS_SHA[1..]), EmpreinteHorsForme);
        refuse(format!("1762135200 {CHS_ARCHIVE} {CHS_SHA}0"), EmpreinteHorsForme);
        refuse(format!("1762135200 {CHS_ARCHIVE} {}g", &CHS_SHA[1..]), EmpreinteHorsForme);
    }

    /// Octets non UTF-8 : refus de forme, pas une lecture ratée.
    #[test]
    fn chs_des_octets_non_utf8_sont_une_ligne_hors_forme() {
        let dir = crate::tmp_possede::TmpPossede::neuf("chs-utf8");
        let f = dir.sous("attestation");
        let mut b = format!("1762135200 {CHS_ARCHIVE} ").into_bytes();
        b.extend_from_slice(&[0xff; 64]);
        std::fs::write(&*f, &b).unwrap();
        assert_eq!(chs::lire_le_fichier(f.chemin()), Err(chs::Refus::LigneHorsForme));
    }

    /// LES BORDS, À HORLOGE INJECTÉE : âge maximal (égal = fraîche, +1 = périmée), tolérance d'horloge
    /// (égale = admise, âge 0 ; +1 = refusée avec l'avance), avance tolérée bornée à un âge nul.
    #[test]
    fn chs_les_bords_de_l_age_et_de_l_horloge() {
        let n = 2_000_000_000_i64;
        let ligne = |ts: i64| Some(Ok(format!("{ts} {CHS_ARCHIVE} {CHS_SHA}")));
        let a = |ts: i64| chs::Attestation { ts, archive: CHS_ARCHIVE.into(), sha256: CHS_SHA.into() };
        assert_eq!(chs::etat_selon(Ok(3600), ligne(n - 3600), n), chs::Etat::Fraiche { attestation: a(n - 3600), age_s: 3600 });
        assert_eq!(chs::etat_selon(Ok(3600), ligne(n - 3601), n), chs::Etat::Perimee { attestation: a(n - 3601), age_s: 3601 });
        assert_eq!(chs::etat_selon(Ok(3600), ligne(n + 3600), n), chs::Etat::Fraiche { attestation: a(n + 3600), age_s: 0 });
        assert_eq!(chs::etat_selon(Ok(3600), ligne(n + 3601), n),
            chs::Etat::Refusee(chs::Refus::DateeDansLeFutur { avance_s: 3601 }));
        assert_eq!(chs::etat_selon(Ok(3600), ligne(n + 10), n).age_s(), Some(0));
        assert_eq!(chs::etat_selon(Ok(0), ligne(n), n), chs::Etat::NonSuivi);
        assert_eq!(chs::etat_selon(Ok(3600), None, n), chs::Etat::NonDeclaree);
    }
