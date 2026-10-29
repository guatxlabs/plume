// `P10.32-q` — L'EXPORT ET LE PIVOT PRENNENT LE COULOIR LOURD, JUGÉS PAR LA ROUTE ; LES LÉGÈRES ENTRE ELLES SONT
// SERVIES DANS L'ORDRE D'ARRIVÉE.
//
// VU (re-mesuré par lecture sur 26d7a24f) : la classe lourde est posée au site par `acquire_query_permit_lourd` dans
// `handlers/query.rs::export` et `handlers/datamodels.rs::run_generated_soql` (Pivot et jeu de données exécuté) ; le
// seul témoin de ces deux sites était la garde de texte (`voie_lourde_reserve_un_jeton_a_l_api_legere.rs`, témoin 7),
// qui voit le marqueur mais pas la requête : un export qui passerait par une autre porte au même endroit, ou un
// couloir que la porte ne prendrait plus, la laissaient verte.
//
// TENU (1), PAR LA ROUTE, jeton `viewer` (le rôle le plus faible admis sur `/api/export` et `/api/pivot/run`), dans
// un sous-processus (le couloir est global au processus) : N = 3, r = 1, deux lourdes tenues par la porte des
// gestionnaires, donc le couloir est plein et un seul jeton interactif reste libre (le réservé). L'export, puis le
// Pivot, envoyés par le routeur réel ATTEIGNENT la porte et attendent AU COULOIR (compte test-only
// `semaphore_interactif::en_file_au_couloir`), sans prendre le jeton réservé ; une légère (`/api/query` sans
// `interactive`) passe pendant ce temps sur ce jeton, sans file ; à la libération d'une lourde, la requête en file
// est admise et servie en 200, comptée par route comme lourde ET comme attente. Sans horloge : comptes de jetons,
// compte de file, ordre d'admission.
//
// TENU (2) : la file des légères est dans l'ordre d'arrivée — une légère en file reçoit le jeton libéré avant une
// légère arrivée après elle, par la porte des gestionnaires (`acquire_query_permit`). C'est ce qui fait de la
// saturation des jetons par des légères une attente et non une famine (limite nommée dans `semaphore_interactif`).
//
// CE QUE CE FICHIER NE TIENT PAS : la DURÉE des attentes (horloge) ; le jeu de données exécuté
// (`/api/datasets/{id}/run`) partage la fonction de site du Pivot (`run_generated_soql`) mais n'est pas joué par sa
// propre route ici.
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés avant le commit) : BA5_EXPORT_LEGER (l'export repasse par la
// porte légère), BA5_PIVOT_LEGER (le Pivot repasse par la porte légère), BA5_LEGERE_SANS_FILE (la porte attend le
// jeton interactif en le retentant au lieu de faire la queue : une légère arrivée après double celle en file).
mod export_et_pivot_prennent_le_couloir_lourd_par_la_route {
    use super::*;
    use crate::semaphore_interactif::{couloir_lourd, en_file_au_couloir, poser_borne, registre};
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};
    use tokio::sync::Semaphore;

    struct ReveilMuet;
    impl Wake for ReveilMuet {
        fn wake(self: Arc<Self>) {}
    }

    fn sonder<F: Future>(f: std::pin::Pin<&mut F>, w: &Waker) -> Poll<F::Output> {
        f.poll(&mut Context::from_waker(w))
    }

    /// Statut et réponse brute d'un POST JSON par le routeur réel.
    async fn poster(addr: std::net::SocketAddr, route: String, qui: String, corps: String) -> (u16, String) {
        router_probe_envoi(addr, "POST", &route, Some(&qui), &[("Content-Type", "application/json")], &corps).await
    }

    const ENFANT: &str = "P1032Q_BA5_ENFANT_ROUTE";
    const FIN: &str = "P1032Q-BA5-ENFANT-A-JOUE";

    /// (1) PAR LA ROUTE : l'export et le Pivot attendent au couloir, la légère passe sur le jeton réservé, la lourde
    /// en file est admise à la libération. Le corps du témoin se joue dans un sous-processus (couloir global).
    #[test]
    fn l_export_et_le_pivot_attendent_au_couloir_par_la_route_et_la_legere_passe() {
        if std::env::var(ENFANT).is_ok() {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime de l'enfant");
            rt.block_on(jouer_l_enfant());
            println!("{FIN}");
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args([
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "tests::export_et_pivot_prennent_le_couloir_lourd_par_la_route::l_export_et_le_pivot_attendent_au_couloir_par_la_route_et_la_legere_passe",
        ]);
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
        commande.env(ENFANT, "1");
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant doit sortir en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(FIN), "l'enfant doit avoir joué jusqu'au bout : {stdout}\n{stderr}");
    }

    async fn jouer_l_enfant() {
        let (mut st, _db) = router_test_state("p1032q-ba5-couloir-par-la-route");
        st.query_sem = Arc::new(Semaphore::new(3));
        st.db
            .lock()
            .execute_batch(
                "INSERT INTO data_model(id,name,title) VALUES(1,'ba5','BA5'); \
                 INSERT INTO data_model_object(id,model_id,name,parent_id,constraint_soql,enabled) VALUES (10,1,'racine',NULL,'category=auth',1); \
                 INSERT INTO data_model_field(object_id,name,ftype,expr) VALUES (10,'host','string','');",
            )
            .expect("fixture : modèle de données du Pivot");
        poser_borne(3, 1);
        assert!(couloir_lourd().is_some(), "contrôle : N = 3, r = 1 pose un couloir");
        let addr = router_serve(st.clone()).await;
        let vwr = viewer_authz();
        // Deux lourdes tenues par la porte des gestionnaires : couloir plein (N − r = 2), un seul jeton interactif libre.
        let (b, _) = acquire_query_permit_lourd(&st.query_sem).await.expect("contrôle : première lourde admise");
        let mut a = Some(acquire_query_permit_lourd(&st.query_sem).await.expect("contrôle : seconde lourde admise").0);
        assert_eq!(st.query_sem.available_permits(), 1, "contrôle : deux lourdes tiennent deux jetons, le réservé est libre");
        let cas: [(&str, String); 2] = [
            ("/api/export", json!({ "soql": "search", "format": "json" }).to_string()),
            ("/api/pivot/run", json!({ "object_id": 10, "splitby": ["host"], "stats": [{ "func": "count" }] }).to_string()),
        ];
        assert!(cas.len() >= 2, "plancher : l'export et le Pivot");
        let mut legeres_servies = 0u64;
        for (route, corps) in cas {
            assert_eq!(en_file_au_couloir(), 0, "{route} : contrôle, personne en file au couloir avant l'envoi");
            let tache = tokio::spawn(poster(addr, route.to_string(), vwr.clone(), corps));
            // La requête a ATTEINT la porte quand elle est en file au couloir ; un mutant léger, lui, finit sans y passer.
            while en_file_au_couloir() == 0 && !tache.is_finished() {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                en_file_au_couloir(),
                1,
                "{route} (viewer) doit attendre AU COULOIR LOURD quand le couloir est plein : une requête classée légère \
                 prend le jeton réservé aux légères"
            );
            assert!(!tache.is_finished(), "{route} : en file au couloir, pas encore servie");
            assert_eq!(st.query_sem.available_permits(), 1, "{route} : en file, elle ne tient PAS le jeton réservé");
            assert_eq!(registre().existants(route).map(|c| c.acquisitions()).unwrap_or(0), 0, "{route} : pas encore admise");
            // Pendant ce temps, une légère par la route passe sur le jeton réservé, sans file.
            let (code, brut) = poster(addr, "/api/query".into(), vwr.clone(), json!({ "soql": "search" }).to_string()).await;
            assert_eq!(code, 200, "{route} en file : la légère /api/query est servie : {brut}");
            legeres_servies += 1;
            let q = registre().existants("/api/query").expect("contrôle : /api/query a pris un permis");
            assert_eq!(
                (q.acquisitions(), q.lourdes(), q.attentes()),
                (legeres_servies, 0, 0),
                "{route} en file : la légère est admise en voie légère, SANS attendre"
            );
            assert_eq!(en_file_au_couloir(), 1, "{route} : toujours en file au couloir après la légère");
            assert!(!tache.is_finished(), "{route} : toujours pas servie tant que le couloir est plein");
            // Une lourde rend ses jetons : la requête en file est admise et servie.
            drop(a.take());
            let (code, brut) = tache.await.expect("tâche de la requête lourde");
            assert_eq!(code, 200, "{route} : servie après la libération d'une lourde : {brut}");
            assert_eq!(en_file_au_couloir(), 0, "{route} : plus personne en file au couloir");
            let c = registre().existants(route).expect("contrôle : la requête a pris un permis");
            assert_eq!(
                (c.acquisitions(), c.lourdes(), c.attentes()),
                (1, 1, 1),
                "{route} : admise une fois, par la voie LOURDE, comptée comme une attente (file du couloir)"
            );
            // Le couloir se remplit de nouveau pour le cas suivant.
            a = Some(acquire_query_permit_lourd(&st.query_sem).await.expect("contrôle : lourde reprise").0);
            assert_eq!(st.query_sem.available_permits(), 1, "{route} : contrôle, le réservé est de nouveau seul libre");
        }
        drop(a);
        drop(b);
    }

    /// (2) LES LÉGÈRES ENTRE ELLES, DANS L'ORDRE D'ARRIVÉE : trois légères tiennent les trois jetons, une quatrième
    /// attend ; au jeton libéré, une cinquième arrivée APRÈS ne la double pas, la quatrième est admise, la cinquième
    /// l'est au jeton suivant. Par la porte des gestionnaires (`acquire_query_permit`), sondages uniques, sans horloge.
    #[test]
    fn une_legere_en_file_recoit_le_jeton_avant_une_legere_arrivee_apres() {
        let sem = Arc::new(Semaphore::new(3));
        let w: Waker = Arc::new(ReveilMuet).into();
        let mut tenues = Vec::new();
        for _ in 0..3 {
            let mut f = std::pin::pin!(acquire_query_permit(&sem));
            match sonder(f.as_mut(), &w) {
                Poll::Ready(Ok((p, _))) => tenues.push(p),
                _ => panic!("contrôle : une légère admise sans file tant qu'un jeton est libre"),
            }
        }
        assert_eq!(sem.available_permits(), 0, "contrôle : trois légères tiennent les trois jetons");
        let mut quatrieme = std::pin::pin!(acquire_query_permit(&sem));
        assert!(sonder(quatrieme.as_mut(), &w).is_pending(), "contrôle : la quatrième légère attend");
        drop(tenues.pop());
        let mut cinquieme = std::pin::pin!(acquire_query_permit(&sem));
        assert!(
            sonder(cinquieme.as_mut(), &w).is_pending(),
            "une légère arrivée APRÈS une légère en file ne doit pas prendre le jeton libéré : sans file, la saturation \
             par des légères deviendrait une famine pour celle qui attend"
        );
        let _q = match sonder(quatrieme.as_mut(), &w) {
            Poll::Ready(Ok((p, _))) => p,
            _ => panic!("la légère la plus ANCIENNE en file reçoit le jeton libéré"),
        };
        assert!(sonder(cinquieme.as_mut(), &w).is_pending(), "la cinquième attend le jeton suivant");
        drop(tenues.pop());
        assert!(
            matches!(sonder(cinquieme.as_mut(), &w), Poll::Ready(Ok(_))),
            "la cinquième est admise au jeton suivant"
        );
    }
}
