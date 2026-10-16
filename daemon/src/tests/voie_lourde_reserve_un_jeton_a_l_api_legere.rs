// `P10.32-q` (reste « famine ») — LA VOIE LOURDE LAISSE UN JETON À L'API LÉGÈRE.
//
// VU (re-mesuré par lecture sur 1d9ba63c) : un seul sémaphore interactif (`AppState::query_sem`, taille
// `PLUME_QUERY_CONCURRENCY`, construit dans `server/mod.rs`) pris par toutes les routes de lecture. Une requête
// `interactive:true` de `/api/query`, un export et le Pivot s'exécutent au budget INTERACTIF et tiennent leur jeton
// jusqu'à lui ; quelques-unes suffisaient donc à prendre TOUS les jetons, et la flotte, les alertes, la recherche
// attendaient en file sans borne.
//
// TENU : un couloir lourd (`semaphore_interactif::CouloirLourd`, taille `N − r`, `r` = `PLUME_QUERY_RESERVE_LIGHT`
// borné à `N − 1`, nul à `N = 1`), posé au démarrage par `poser_borne`. Une requête lourde prend le couloir AVANT
// le jeton interactif et le rend APRÈS lui (porte jumelle `acquire_query_permit_lourd`, `QueryClock::voie_lourde`) ;
// une légère ne prend que le jeton interactif. Témoins SANS HORLOGE : comptes de jetons et ordre d'admission, par
// sondage unique des futures (aucune attente, aucun budget de temps).
//
// CE QUE CE LOT NE TIENT PAS : la classe n'est posée qu'aux trois sites au budget grandi (`query` interactif,
// `export`, `run_generated_soql`) ; qu'aucune autre route ne tienne son jeton au-delà du budget automatique n'est
// pas vérifié ici (lu seulement pour `/api/search` et `/api/query` non interactif). Une légère peut toujours
// attendre derrière d'AUTRES légères : la réserve protège de la famine par les lourdes, pas de la saturation.
// L'attente au couloir est COMPTÉE (témoin 9 : `attentes()` de la route), mais sa DURÉE ne l'est pas par un témoin :
// que le chronomètre parte bien du couloir et non du jeton interactif quand la requête attend aux deux files
// (`file_depuis` repris par `let t`) ne se juge qu'à l'horloge, et ce dépôt refuse les témoins chronométriques —
// le mutant M12 (chronomètre repartant du jeton) reste donc vert.
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés avant le commit) : RESERVE_ZERO (réserve forcée à 0),
// COULOIR_APRES (couloir pris après le jeton interactif), CLASSE_INVERSEE (`/api/query` : la légère dans le
// couloir), SANS_CLAMP (borne `N − 1` retirée : à `N = 1` aucune lourde n'est admise), COULOIR_LIBERE_AVANT (jeton
// de couloir rendu avant le jeton interactif), GLOBAL_NON_POSE (`poser_borne` ne pose pas le couloir),
// GARDE_SANS_JUMELLE (la garde `P7.8-a` n'admet plus la porte jumelle), GARDE_EXPORT_LEGER (l'export repasse en
// porte légère dans le texte jugé par la garde de sites), M11 (l'attente au couloir n'arme plus le chronomètre : une
// lourde qui a fait la queue au couloir publie le zéro structurel et n'est pas comptée dans les attentes).
mod voie_lourde_reserve_un_jeton_a_l_api_legere {
    use super::*;
    use crate::semaphore_interactif::{exposition_prom, registre, reserve_effective, sous_route, CouloirLourd, Etiquette, Voie};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use tokio::sync::Semaphore;

    /// Un réveil qui exécute une action au moment exact où tokio remet un jeton à la future en file.
    struct Reveil(Box<dyn Fn() + Send + Sync>);
    impl Wake for Reveil {
        fn wake(self: Arc<Self>) {
            (self.0)()
        }
    }
    fn reveil_muet() -> Waker {
        Arc::new(Reveil(Box::new(|| {}))).into()
    }

    fn sonder<F: Future>(f: std::pin::Pin<&mut F>, w: &Waker) -> Poll<F::Output> {
        f.poll(&mut Context::from_waker(w))
    }

    /// Une acquisition qui doit être admise SANS attendre (un seul sondage).
    fn admise(sem: &Arc<Semaphore>, voie: Voie, couloir: &CouloirLourd) -> crate::semaphore_interactif::PermitMesure {
        let w = reveil_muet();
        let mut f = std::pin::pin!(acquerir_par_la_voie(sem, voie, couloir.semaphore()));
        match sonder(f.as_mut(), &w) {
            Poll::Ready(Ok((p, attente))) => {
                assert_eq!(attente.ms(), 0.0, "contrôle : une admission sans file publie le zéro structurel");
                p
            }
            Poll::Ready(Err(e)) => panic!("contrôle : sémaphore fermé inattendu ({e})"),
            Poll::Pending => panic!("une acquisition {voie:?} attendue admise a dû faire la queue"),
        }
    }

    /// (1) N = 3, r = 1 : deux lourdes tenues, la troisième attend AU COULOIR sans toucher au jeton réservé, une
    /// légère passe sans attendre ; à la libération d'une lourde, la plus ancienne en file est admise (FIFO).
    #[test]
    fn deux_lourdes_tenues_la_troisieme_attend_au_couloir_et_la_legere_passe() {
        let couloir = CouloirLourd::neuf(3, 1);
        assert_eq!(couloir.reserve(), 1, "réserve effective à N = 3, r = 1");
        let sem = Arc::new(Semaphore::new(3));
        let a = admise(&sem, Voie::Lourde, &couloir);
        let _b = admise(&sem, Voie::Lourde, &couloir);
        assert_eq!(sem.available_permits(), 1, "deux lourdes tiennent deux jetons interactifs");
        let w = reveil_muet();
        let mut c = std::pin::pin!(acquerir_par_la_voie(&sem, Voie::Lourde, couloir.semaphore()));
        assert!(sonder(c.as_mut(), &w).is_pending(), "la troisième lourde doit attendre (couloir plein)");
        let mut d = std::pin::pin!(acquerir_par_la_voie(&sem, Voie::Lourde, couloir.semaphore()));
        assert!(sonder(d.as_mut(), &w).is_pending(), "la quatrième lourde attend aussi");
        assert_eq!(
            sem.available_permits(),
            1,
            "les lourdes en file ne tiennent PAS le jeton réservé : elles attendent au couloir, pas au sémaphore"
        );
        let legere = admise(&sem, Voie::Legere, &couloir);
        drop(legere);
        drop(a);
        let _pc = match sonder(c.as_mut(), &w) {
            Poll::Ready(Ok((p, _))) => p,
            _ => panic!("la lourde la plus ANCIENNE en file doit être admise à la libération"),
        };
        assert!(sonder(d.as_mut(), &w).is_pending(), "la plus récente attend toujours (FIFO)");
        assert_eq!(sem.available_permits(), 1, "toujours un jeton libre pour les légères");
        drop(admise(&sem, Voie::Legere, &couloir));
    }

    /// (2) LE JETON DE COULOIR EST RENDU APRÈS LE JETON INTERACTIF. Observé au moment exact où tokio remet le jeton
    /// de couloir à la lourde en file (son réveil) : le jeton interactif de la lourde partante doit déjà être libre.
    #[test]
    fn le_jeton_de_couloir_est_rendu_apres_le_jeton_interactif() {
        let couloir = CouloirLourd::neuf(3, 1);
        let sem = Arc::new(Semaphore::new(3));
        let a = admise(&sem, Voie::Lourde, &couloir);
        let _b = admise(&sem, Voie::Lourde, &couloir);
        let vu = Arc::new(AtomicUsize::new(usize::MAX));
        let (vu2, sem2) = (vu.clone(), sem.clone());
        let w: Waker = Arc::new(Reveil(Box::new(move || vu2.store(sem2.available_permits(), Ordering::SeqCst)))).into();
        let mut c = std::pin::pin!(acquerir_par_la_voie(&sem, Voie::Lourde, couloir.semaphore()));
        assert!(sonder(c.as_mut(), &w).is_pending(), "contrôle : la troisième lourde est en file au couloir");
        drop(a);
        assert_eq!(
            vu.load(Ordering::SeqCst),
            2,
            "au réveil de la lourde en file, le jeton interactif de la partante doit déjà être rendu (2 libres sur 3, \
             une lourde restante) : rendu après, une lourde réveillée pourrait prendre le jeton réservé"
        );
        let _pc = match sonder(c.as_mut(), &w) {
            Poll::Ready(Ok((p, _))) => p,
            _ => panic!("contrôle : la lourde réveillée doit être admise"),
        };
        assert_eq!(sem.available_permits(), 1);
    }

    /// (3) N = 1 : aucune réserve (sinon aucune lourde ne passerait jamais), la lourde est admise.
    #[test]
    fn a_un_seul_jeton_la_lourde_est_admise() {
        let couloir = CouloirLourd::neuf(1, 1);
        assert_eq!(couloir.reserve(), 0, "à N = 1 la réserve effective est nulle");
        let sem = Arc::new(Semaphore::new(1));
        let _p = admise(&sem, Voie::Lourde, &couloir);
        assert_eq!(sem.available_permits(), 0);
    }

    /// (4) r = 0 : comportement d'avant — trois lourdes prennent les trois jetons.
    #[test]
    fn sans_reserve_le_comportement_d_avant() {
        let couloir = CouloirLourd::neuf(3, 0);
        assert_eq!(couloir.reserve(), 0);
        assert!(couloir.semaphore().is_none(), "aucun couloir à réserve nulle");
        let sem = Arc::new(Semaphore::new(3));
        let _t: Vec<_> = (0..3).map(|_| admise(&sem, Voie::Lourde, &couloir)).collect();
        assert_eq!(sem.available_permits(), 0);
    }

    /// (5) La réserve effective : bornée à N − 1, nulle sous N = 2.
    #[test]
    fn la_reserve_effective_est_bornee() {
        for (n, r, attendu) in [(3, 1, 1), (3, 5, 2), (2, 1, 1), (2, 2, 1), (1, 1, 0), (1, 0, 0), (3, 0, 0), (8, 3, 3)] {
            assert_eq!(reserve_effective(n, r), attendu, "reserve_effective({n}, {r})");
            assert_eq!(CouloirLourd::neuf(n, r).reserve(), attendu, "CouloirLourd::neuf({n}, {r})");
        }
    }

    /// (6) AU SITE : `/api/query` prend la voie lourde si et seulement si `interactive:true` — jugé sur le
    /// gestionnaire RÉEL, compté par route (`plume_query_permit_heavy_total`), sous une étiquette propre à l'essai.
    #[tokio::test]
    async fn api_query_interactive_prend_la_voie_lourde_et_l_automatique_la_legere() {
        let (st, _db) = router_test_state("p1032q-voie-au-site");
        const LOURDE: &str = "/essai-p1032q/interactive";
        const LEGERE: &str = "/essai-p1032q/automatique";
        for (etiquette, interactive) in [(LOURDE, true), (LEGERE, false)] {
            let corps = json!({ "soql": "search", "interactive": interactive });
            let _ = sous_route(
                Etiquette::Nommee(etiquette),
                crate::handlers::query::query(State(st.clone()), Extension(sp_au("adm", "admin")), Json(corps)),
            )
            .await;
        }
        let c_lourde = registre().existants(LOURDE).expect("contrôle : la requête interactive a pris un permis");
        let c_legere = registre().existants(LEGERE).expect("contrôle : la requête automatique a pris un permis");
        assert_eq!((c_lourde.acquisitions(), c_lourde.lourdes()), (1, 1), "interactive:true -> voie lourde");
        assert_eq!((c_legere.acquisitions(), c_legere.lourdes()), (1, 0), "interactive absent -> voie légère");
        let expo = exposition_prom();
        assert!(
            expo.contains(&format!("plume_query_permit_heavy_total{{route=\"{LOURDE}\"}} 1")),
            "la voie lourde est publiée par route : {expo}"
        );
        assert!(expo.contains(&format!("plume_query_permit_heavy_total{{route=\"{LEGERE}\"}} 0")));
    }

    /// (9) L'ATTENTE AU COULOIR EST PUBLIÉE. Une lourde qui a fait la queue au COULOIR puis trouvé le jeton interactif
    /// libre a attendu son tour : elle compte dans les attentes de sa route (`plume_query_permit_waits_total`), pas
    /// comme une admission immédiate. Sans horloge : le compte `attentes()`, sous une étiquette propre à l'essai.
    #[test]
    fn l_attente_au_couloir_est_comptee_comme_une_attente() {
        const SANS_FILE: &str = "/essai-p1032q/lourde-sans-file";
        const EN_FILE: &str = "/essai-p1032q/lourde-en-file-au-couloir";
        let couloir = CouloirLourd::neuf(3, 1);
        let sem = Arc::new(Semaphore::new(3));
        let w = reveil_muet();
        let mut tenue = std::pin::pin!(sous_route(Etiquette::Nommee(SANS_FILE), acquerir_par_la_voie(&sem, Voie::Lourde, couloir.semaphore())));
        let a = match sonder(tenue.as_mut(), &w) {
            Poll::Ready(Ok((p, _))) => p,
            _ => panic!("contrôle : la première lourde est admise sans file"),
        };
        let _b = admise(&sem, Voie::Lourde, &couloir);
        let mut c = std::pin::pin!(sous_route(Etiquette::Nommee(EN_FILE), acquerir_par_la_voie(&sem, Voie::Lourde, couloir.semaphore())));
        assert!(sonder(c.as_mut(), &w).is_pending(), "contrôle : la troisième lourde attend au couloir");
        assert_eq!(sem.available_permits(), 1, "contrôle : elle attend au COULOIR, le jeton interactif réservé reste libre");
        drop(a);
        assert_eq!(sem.available_permits(), 2, "contrôle : à son admission le jeton interactif est libre, seule la file du couloir a joué");
        let _pc = match sonder(c.as_mut(), &w) {
            Poll::Ready(Ok((p, _))) => p,
            _ => panic!("contrôle : la lourde en file est admise à la libération"),
        };
        let sans_file = registre().existants(SANS_FILE).expect("contrôle : la lourde sans file a pris un permis");
        assert_eq!((sans_file.acquisitions(), sans_file.attentes()), (1, 0), "une lourde admise sans file n'est pas une attente");
        let en_file = registre().existants(EN_FILE).expect("contrôle : la lourde en file a pris un permis");
        assert_eq!(
            (en_file.acquisitions(), en_file.attentes()),
            (1, 1),
            "une lourde qui a fait la queue au couloir doit être comptée comme une attente : sinon la saturation des \
             lourdes est publiée comme des admissions immédiates (plume_query_permit_waits_total muet)"
        );
    }

    const MARQUEURS_LOURDS: [&str; 2] = ["acquire_query_permit_lourd(&st.query_sem)", ".voie_lourde()"];

    /// Les fonctions d'un texte qui posent la porte lourde (commentaires de ligne retirés).
    fn sites_lourds_du_texte(src: &str) -> Vec<String> {
        let re = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)").unwrap();
        let mut courante = String::new();
        let mut out = Vec::new();
        for l in src.lines() {
            let code = l.split("//").next().unwrap_or("");
            if let Some(c) = re.captures(code) {
                courante = c[1].to_string();
            }
            if MARQUEURS_LOURDS.iter().any(|m| code.contains(m)) {
                out.push(courante.clone());
            }
        }
        out
    }

    /// (7) L'ENSEMBLE NOMMÉ DES SITES DE PORTE LOURDE, jugé dans les deux sens sur l'arbre (un site perdu = une
    /// requête au budget grandi qui reprend le jeton réservé ; un site gagné = une classe posée sans être dite).
    #[test]
    fn les_sites_de_porte_lourde_sont_exactement_ceux_du_budget_grandi() {
        // Épreuve de l'instrument sur extraits fabriqués, dans les deux sens.
        assert_eq!(
            sites_lourds_du_texte(
                "async fn a() { let _p = acquire_query_permit_lourd(&st.query_sem).await; }\n\
                 async fn b() { let _p = acquire_query_permit(&st.query_sem).await; }\n\
                 pub(crate) async fn c() {\n    let clock = if x { clock.voie_lourde() } else { clock };\n}"
            ),
            vec!["a".to_string(), "c".to_string()]
        );
        assert!(sites_lourds_du_texte("fn d() {\n    // acquire_query_permit_lourd(&st.query_sem)\n}").is_empty(), "un commentaire n'est pas un site");
        assert!(
            sites_lourds_du_texte("pub(crate) async fn acquire_query_permit_lourd(sem: &Arc<Semaphore>) {}\npub(crate) fn voie_lourde(self) -> Self {}").is_empty(),
            "une DÉFINITION n'est pas un site"
        );
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        crate::db_open::door_tests::rs_files(&racine, &mut fichiers);
        let mut vus = std::collections::BTreeSet::new();
        for p in fichiers {
            let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
            if rel.starts_with("tests/") {
                continue;
            }
            let src = std::fs::read_to_string(&p).expect("source lisible");
            for f in sites_lourds_du_texte(&src) {
                vus.insert((rel.clone(), f));
            }
        }
        let attendus: std::collections::BTreeSet<(String, String)> = [
            ("handlers/datamodels.rs", "run_generated_soql"),
            ("handlers/query.rs", "export"),
            ("handlers/query.rs", "query"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(vus, attendus, "sites de porte lourde (fichier, fonction) : un site perdu laisse une requête au budget grandi prendre le jeton réservé, un site gagné doit être nommé ici");
    }

    /// (8) BOUT EN BOUT AU DÉMARRAGE RÉEL — `boot_config` lit `PLUME_QUERY_RESERVE_LIGHT` par `cfg` (environnement,
    /// puis fichier `PLUME_CONFIG` du mode natif) et pose le couloir que la porte d'entrée des gestionnaires
    /// (`acquire_query_permit_lourd`) prend. Un sous-processus par cas : le couloir est global au processus.
    #[test]
    fn le_demarrage_reel_pose_le_couloir_que_la_porte_lourde_prend() {
        const ENFANT: &str = "P1032Q_ENFANT_COULOIR";
        const FIN: &str = "P1032Q-ENFANT-A-JOUE";
        const SIGNATURE_DE_TEST: &str = "temoin-p1032q-signature-de-test";
        if std::env::var(ENFANT).is_ok() {
            crate::server::rejouer_le_demarrage_pour_un_temoin();
            let expo = exposition_prom();
            let jauge = |nom: &str| -> usize {
                expo.lines()
                    .find_map(|l| l.strip_prefix(&format!("{nom} ")))
                    .unwrap_or_else(|| panic!("jauge {nom} absente : {expo}"))
                    .trim()
                    .parse()
                    .expect("jauge entière")
            };
            let n = jauge("plume_query_permits_limit");
            println!("P1032Q-RESERVE:{}", jauge("plume_query_permits_reserved"));
            let sem = Arc::new(Semaphore::new(n));
            let w = reveil_muet();
            let mut tenues = Vec::new();
            for _ in 0..=n {
                let mut f = std::pin::pin!(acquire_query_permit_lourd(&sem));
                match sonder(f.as_mut(), &w) {
                    Poll::Ready(Ok((p, _))) => tenues.push(p),
                    _ => break,
                }
            }
            println!("P1032Q-LOURDES:{}", tenues.len());
            let mut l = std::pin::pin!(acquire_query_permit(&sem));
            println!("P1032Q-LEGERE:{}", sonder(l.as_mut(), &w).is_ready());
            println!("{FIN}");
            return;
        }
        let dossier = crate::tmp_possede::TmpPossede::neuf("p1032q-configuration-native");
        let absente = dossier.join("inexistante.conf");
        let native = dossier.join("plume.conf");
        std::fs::write(&native, "PLUME_QUERY_RESERVE_LIGHT=2\n").expect("fichier de configuration du témoin");
        // (taille, réserve dans l'environnement, fichier de configuration, attendu (réserve, lourdes admises, légère admise))
        let cas: [(&str, Option<&str>, &std::path::Path, (usize, usize, bool)); 5] = [
            ("3", None, &absente, (1, 2, true)),
            ("3", Some("0"), &absente, (0, 3, false)),
            ("1", None, &absente, (0, 1, false)),
            ("3", None, &native, (2, 1, true)),
            ("3", Some("pas-un-nombre"), &absente, (1, 2, true)),
        ];
        for (taille, reserve, configuration, attendu) in cas {
            let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
            commande.args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::voie_lourde_reserve_un_jeton_a_l_api_legere::le_demarrage_reel_pose_le_couloir_que_la_porte_lourde_prend",
            ]);
            for (nom, _) in std::env::vars_os() {
                if nom.to_string_lossy().starts_with("PLUME_") {
                    commande.env_remove(&nom);
                }
            }
            commande
                .env(ENFANT, "1")
                .env("PLUME_CONFIG", configuration)
                .env("PLUME_SESSION_SECRET", SIGNATURE_DE_TEST)
                .env("PLUME_QUERY_CONCURRENCY", taille);
            if let Some(r) = reserve {
                commande.env("PLUME_QUERY_RESERVE_LIGHT", r);
            }
            let sortie = commande.output().expect("ré-exécution du binaire de test");
            let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
            assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout ({taille}, {reserve:?}) : {stdout}\n{stderr}");
            assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
            // Le harnais de test écrit son « test … ... » sur la même ligne que la première impression de
            // l'enfant : la clé se cherche DANS la ligne, pas en tête.
            let lu = |cle: &str| -> String {
                let prefixe = format!("P1032Q-{cle}:");
                stdout
                    .lines()
                    .find_map(|l| l.find(&prefixe).map(|i| &l[i + prefixe.len()..]))
                    .unwrap_or_else(|| panic!("{cle} absent : {stdout}"))
                    .to_string()
            };
            let obtenu = (
                lu("RESERVE").parse::<usize>().unwrap(),
                lu("LOURDES").parse::<usize>().unwrap(),
                lu("LEGERE") == "true",
            );
            assert_eq!(
                obtenu,
                attendu,
                "N = {taille}, réserve {reserve:?}, configuration {} : (réserve publiée, lourdes admises, légère admise ensuite)",
                configuration.display()
            );
        }
    }
}
