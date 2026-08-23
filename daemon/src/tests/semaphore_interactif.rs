// =================================================================================================
// `P7.8-a` — CE QUE COÛTE LA BORNE INTERACTIVE, ET QUI LA CONSOMME
//
// LE CONSTAT D'ORIGINE DISAIT « DIX-NEUF ROUTES », ET AVOUAIT QUE LE CHIFFRE N'AVAIT PAS ÉTÉ REFAIT.
// Refait le 2026-08-20 par dérivation depuis la source : 18 sites d'acquisition, qui se rattachent à
// 21 GABARITS de route (quatre sites vivent dans des fonctions d'aide partagées — `prom_run`,
// `prom_distinct_col`, `ds_soql_run`, `run_generated_soql` — et servent donc plusieurs routes). Le
// test `..._sont_derivees_et_tiennent_sous_le_plafond` refait ce décompte À CHAQUE EXÉCUTION : la
// prochaine route qui prendra un permit sera comptée sans que personne y pense, et c'est ce qui
// empêche ce nombre-ci de se périmer comme le précédent.
//
// LES DEUX GRANDEURS QU'UN TOTAL CONFOND. Une route lente et une route qui attend son tour se
// ressemblent vues du client ; les leviers, eux, sont opposés (élargir la borne aide la seconde et
// AGGRAVE la première — mesuré le 2026-08-01 : débit ×0,46 et daemon tué par le noyau en passant le
// sémaphore de 3 à 8). D'où deux séries séparées, et deux tests jumeaux :
//   * quand la file EXISTE, l'attente est VUE et n'est pas nulle ;
//   * quand la file N'EXISTE PAS, le compteur d'attente NE BOUGE PAS.
// Une métrique qui reste à zéro quoi qu'il arrive et une métrique qui compte une attente là où
// aucune file n'était possible sont le MÊME défaut : un chiffre qui ne réfute rien.
//
// LA CARDINALITÉ EST UNE CONTRAINTE DE MÉMOIRE, PAS UN GOÛT. Le budget du projet est de 2 Gio :
// l'étiquette doit donc être bornée par construction. Elle l'est deux fois — c'est le GABARIT de
// route qui étiquette (jamais l'URL : prouvé en servant réellement `/api/essai-p78a/42` et en
// vérifiant que l'étiquette enregistrée est `/api/essai-p78a/:id`), et le registre est PLAFONNÉ
// (prouvé en faisant mordre le plafond). Au pire : `ROUTES_CAP + 1` valeurs d'étiquette.
// =================================================================================================
mod semaphore_interactif_tests {
    use super::*;
    use crate::semaphore_interactif::{
        exposition_prom, permis_detenus, registre, sous_route, Etiquette, Registre,
        ETIQUETTE_DEBORDEMENT, ETIQUETTE_HORS_REQUETE, ROUTES_CAP,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    // ---------- lecture de la source de PRODUCTION (jamais les tests) ----------

    fn p78a_racine() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// Tous les fichiers de PRODUCTION : (chemin relatif, contenu). Les répertoires `tests` et les
    /// fichiers `tests.rs` sont écartés — ce sont des essais, pas du code qui sert des requêtes, et
    /// les y inclure ferait accuser des fixtures qui construisent un `AppState` à la main.
    fn p78a_fichiers() -> Vec<(String, String)> {
        let racine = p78a_racine();
        let mut out = Vec::new();
        let mut pile = vec![racine.clone()];
        while let Some(d) = pile.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                        continue;
                    }
                    pile.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                if p.file_name().map(|n| n == "tests.rs").unwrap_or(false) {
                    continue;
                }
                let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().to_string();
                out.push((rel, std::fs::read_to_string(&p).unwrap()));
            }
        }
        out.sort();
        out
    }

    fn p78a_est_commentaire(l: &str) -> bool {
        let t = l.trim_start();
        t.starts_with("//") || t.starts_with("/*") || t.starts_with('*')
    }

    /// LA PART CODE D'UNE LIGNE — ce qui précède un `//` de fin de ligne.
    ///
    /// MESURÉ EN ÉCRIVANT CETTE SONDE : `handlers/dashboards.rs` porte
    /// `let refresh_sem = st.refresh_sem.clone(); // … (jamais query_sem)`. Une sonde qui lit la ligne
    /// ENTIÈRE compte ce commentaire comme un site d'acquisition et rattache à la borne interactive
    /// une route qui, précisément, dit ne pas y toucher. Un commentaire ne prend pas de permit.
    fn p78a_code_seul(l: &str) -> &str {
        l.split("//").next().unwrap_or("")
    }

    /// La fonction englobante d'une ligne, par remontée jusqu'à la déclaration `fn` la plus proche.
    fn p78a_fonctions(contenu: &str) -> Vec<String> {
        let re = regex::Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)").unwrap();
        let mut courante = String::new();
        let mut out = Vec::new();
        for l in contenu.lines() {
            if !p78a_est_commentaire(l) {
                if let Some(c) = re.captures(l) {
                    courante = c[1].to_string();
                }
            }
            out.push(courante.clone());
        }
        out
    }

    /// LES SITES D'ACQUISITION, DÉRIVÉS : toute ligne de production qui NOMME le sémaphore
    /// interactif hors de son point de déclaration (`state.rs`) et de son câblage (`server/mod.rs`,
    /// la FAÇADE seule : l'exemption ne couvre PAS les sous-modules extraits en `P7.18-a`).
    /// Rendu : (fichier, n° de ligne, fonction englobante, texte).
    fn p78a_sites() -> Vec<(String, usize, String, String)> {
        let mut out = Vec::new();
        for (rel, contenu) in p78a_fichiers() {
            if rel == "state.rs" || rel == "server/mod.rs" {
                continue;
            }
            let fns = p78a_fonctions(&contenu);
            for (i, l) in contenu.lines().enumerate() {
                if p78a_est_commentaire(l) || !p78a_code_seul(l).contains("query_sem") {
                    continue;
                }
                out.push((rel.clone(), i + 1, fns[i].clone(), l.trim().to_string()));
            }
        }
        out
    }

    /// (handler -> gabarits de route) DÉRIVÉ des enregistrements du routeur — jamais une liste.
    fn p78a_gabarits_par_handler() -> BTreeMap<String, BTreeSet<String>> {
        let re_route = regex::Regex::new(r#"\.route\("([^"]+)""#).unwrap();
        let re_meth = regex::Regex::new(r"(?:get|post|put|patch|delete)\(\s*([A-Za-z0-9_]+)\s*\)").unwrap();
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (_, contenu) in p78a_fichiers() {
            for l in contenu.lines() {
                if p78a_est_commentaire(l) {
                    continue;
                }
                let Some(c) = re_route.captures(p78a_code_seul(l)) else { continue };
                let gabarit = c[1].to_string();
                for m in re_meth.captures_iter(p78a_code_seul(l)) {
                    out.entry(m[1].to_string()).or_default().insert(gabarit.clone());
                }
            }
        }
        out
    }

    /// Les fonctions qui APPELLENT `nom` (un cran d'indirection à la fois).
    fn p78a_appelants(nom: &str, fichiers: &[(String, String)]) -> BTreeSet<String> {
        let re = regex::Regex::new(&format!(r"\b{}\s*\(", regex::escape(nom))).unwrap();
        let mut out = BTreeSet::new();
        for (_, contenu) in fichiers {
            let fns = p78a_fonctions(contenu);
            for (i, l) in contenu.lines().enumerate() {
                let code = p78a_code_seul(l);
                if p78a_est_commentaire(l) || code.contains(&format!("fn {nom}")) || !re.is_match(code) {
                    continue;
                }
                if fns[i] != nom && !fns[i].is_empty() {
                    out.insert(fns[i].clone());
                }
            }
        }
        out
    }

    /// Les gabarits de route servis par une fonction : directement si elle est enregistrée dans le
    /// routeur, sinon par ses appelants (les quatre fonctions d'aide partagées).
    fn p78a_gabarits_de(
        f: &str,
        par_handler: &BTreeMap<String, BTreeSet<String>>,
        fichiers: &[(String, String)],
        vus: &mut BTreeSet<String>,
        profondeur: usize,
    ) -> BTreeSet<String> {
        if let Some(g) = par_handler.get(f) {
            return g.clone();
        }
        if profondeur == 0 || !vus.insert(f.to_string()) {
            return BTreeSet::new();
        }
        let mut out = BTreeSet::new();
        for a in p78a_appelants(f, fichiers) {
            out.extend(p78a_gabarits_de(&a, par_handler, fichiers, vus, profondeur - 1));
        }
        out
    }

    /// LE DÉCOMPTE, REFAIT À CHAQUE EXÉCUTION — et la borne de cardinalité VÉRIFIÉE, pas affirmée.
    ///
    /// Deux propriétés, aucune liste écrite à la main :
    ///   1. tout site d'acquisition se rattache à au moins un gabarit de route. Un site qui n'en a
    ///      aucun consommerait la borne depuis une tâche sans requête : il compterait sous
    ///      `(hors requête)`, c'est-à-dire dans un seau où personne ne le chercherait ;
    ///   2. le nombre de gabarits distincts tient sous `ROUTES_CAP`. C'est CE test qui rend la
    ///      phrase « la cardinalité est bornée » vérifiable : si le routeur grossit au point de
    ///      dépasser le plafond, la mesure ne se dégrade pas en silence, elle échoue ici.
    #[test]
    fn p78a_les_routes_qui_consomment_la_borne_sont_derivees_et_tiennent_sous_le_plafond() {
        let fichiers = p78a_fichiers();
        let par_handler = p78a_gabarits_par_handler();
        let sites = p78a_sites();
        assert!(!sites.is_empty(), "invariant vide = invariant mort : plus aucun site n'acquiert la borne interactive");
        assert!(
            par_handler.len() > 50,
            "la table des routes n'a pas été dérivée ({} entrées) : la sonde lit mal le routeur, et tout ce \
             qui suit serait vert par aveuglement",
            par_handler.len()
        );
        let mut gabarits: BTreeSet<String> = BTreeSet::new();
        let mut orphelins: Vec<String> = Vec::new();
        for (f, ligne, fonction, texte) in &sites {
            let mut vus = BTreeSet::new();
            let g = p78a_gabarits_de(fonction, &par_handler, &fichiers, &mut vus, 3);
            if g.is_empty() {
                orphelins.push(format!("{f}:{ligne} (fn {fonction}) — {texte}"));
            }
            gabarits.extend(g);
        }
        assert!(
            orphelins.is_empty(),
            "ces sites consomment la borne interactive sans se rattacher à aucune route du routeur : leur \
             attente et leur travail tomberont dans le seau « {ETIQUETTE_HORS_REQUETE} », où aucun \
             exploitant ne les cherchera. {orphelins:#?}"
        );
        assert!(
            gabarits.len() <= ROUTES_CAP,
            "{} gabarits de route consomment la borne interactive, pour un plafond de registre de \
             {ROUTES_CAP} : au-delà, des routes partageraient le seau « {ETIQUETTE_DEBORDEMENT} » et la \
             mesure perdrait son attribution. Relever `ROUTES_CAP` (et le coût de cardinalité qui va \
             avec), pas rétrécir la mesure. Routes : {gabarits:#?}",
            gabarits.len()
        );
    }

    /// AUCUN PERMIT NU NE CIRCULE HORS DU MODULE QUI LE MESURE.
    ///
    /// La garde jumelle de `the_interactive_semaphore_is_only_acquired_through_the_timed_gate` : la
    /// première dit que le permit s'obtient par UNE porte, celle-ci dit que ce qui SORT de cette
    /// porte est le permit MESURÉ. Sans elle, la porte pourrait être réécrite pour rendre un
    /// `OwnedSemaphorePermit` nu — le code compilerait, tous les tests de temps resteraient verts, et
    /// la durée de détention cesserait d'être publiée sans qu'une seule ligne rouge apparaisse.
    #[test]
    fn p78a_aucun_permit_nu_ne_sort_du_module_qui_le_mesure() {
        let mut fautifs: Vec<String> = Vec::new();
        let mut dedans = 0usize;
        for (rel, contenu) in p78a_fichiers() {
            for (i, l) in contenu.lines().enumerate() {
                if p78a_est_commentaire(l) || !p78a_code_seul(l).contains("OwnedSemaphorePermit") {
                    continue;
                }
                if rel == "semaphore_interactif.rs" {
                    dedans += 1;
                } else {
                    fautifs.push(format!("{rel}:{} — {}", i + 1, l.trim()));
                }
            }
        }
        assert!(dedans > 0, "invariant vide = invariant mort : `semaphore_interactif` ne manipule plus de permit");
        assert!(
            fautifs.is_empty(),
            "un permit NU du sémaphore interactif est nommé hors du module qui mesure sa détention : le \
             temps passé à occuper la borne cesserait d'être publié pour ce chemin, sans rien casser. \
             Passer par `semaphore_interactif::permis_pris` (via `acquire_query_permit`). {fautifs:#?}"
        );
    }

    // ---------- la métrique BOUGE, et elle ne bouge pas à tort ----------

    /// (a) QUAND LA FILE EXISTE, ELLE EST VUE. Sémaphore de taille 1, deux acquisitions qui se
    /// recouvrent : la seconde ne PEUT que faire la queue. L'attente publiée doit donc être non
    /// nulle — et le compteur de saturation doit valoir exactement 1 sur les deux acquisitions,
    /// puisque la première, elle, n'a pas attendu.
    ///
    /// Aucun seuil de durée : la propriété est « non nulle », pas « supérieure à N ms ». Un seuil
    /// serait un réglage à maintenir ; « non nulle » est vrai pour toujours.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn p78a_la_file_du_semaphore_est_mesuree_et_nest_pas_nulle() {
        const R: &str = "essai/route-en-file";
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let premier = sous_route(Etiquette::Nommee(R), acquire_query_permit(&sem)).await.unwrap();
        assert_eq!(premier.1.ms(), 0.0, "un permit LIBRE ne s'attend pas : c'est le zéro structurel");
        assert!(permis_detenus() >= 1, "un permit est détenu, la jauge doit le voir");

        let s2 = sem.clone();
        let attendeur = tokio::spawn(sous_route(Etiquette::Nommee(R), async move {
            let (permit, attente) = acquire_query_permit(&s2).await.unwrap();
            (permit, attente.ms())
        }));
        // On tient la borne pendant que l'autre demande : sans recouvrement, il n'y a pas de file et
        // le test ne mettrait rien en situation.
        tokio::time::sleep(Duration::from_millis(40)).await;
        drop(premier);
        let (permit2, attente_ms) = attendeur.await.unwrap();

        let c = registre().existants(R).expect("la route a acquis : elle doit être enregistrée");
        assert_eq!(c.acquisitions(), 2, "deux permis pris sous cette étiquette");
        assert_eq!(c.attentes(), 1, "une seule des deux acquisitions a fait la queue");
        assert!(
            c.attente_us() > 0 && c.attente_max_us() > 0,
            "la file a EXISTÉ (taille 1, deux clients qui se recouvrent) et l'attente publiée est nulle : \
             une métrique qui reste à zéro quoi qu'il arrive est le défaut, pas la mesure"
        );
        assert!(attente_ms > 0.0, "le champ `stats` et la série d'exploitation doivent dire la MÊME attente");
        drop(permit2);
        assert!(
            c.travail_us() > 0,
            "le temps passé permit EN MAIN n'est pas publié : sans lui, on ne peut pas distinguer une route \
             lente d'une route qui attend son tour — la question même que l'exploitant se pose"
        );

        let exposition = exposition_prom();
        assert!(exposition.contains(&format!("plume_query_permit_waits_total{{route=\"{R}\"}} 1")), "{exposition}");
        assert!(exposition.contains(&format!("plume_query_permit_acquisitions_total{{route=\"{R}\"}} 2")), "{exposition}");
        assert!(exposition.contains("plume_query_permits_held "), "la saturation instantanée doit être exposée");
        assert!(exposition.contains("plume_query_permit_routes_cap "), "la borne de cardinalité doit être exposée");
    }

    /// (b) LE TÉMOIN NÉGATIF — la garde mord dans l'AUTRE sens. Autant de permis que de clients :
    /// aucune file n'est possible, donc `attentes` doit rester à 0 alors que `acquisitions` monte.
    /// Sans ce test, (a) serait satisfait par un compteur qui s'incrémente à chaque acquisition, et
    /// la série de saturation ne saturerait jamais rien.
    ///
    /// Le même test vérifie la seconde propriété du seau `(hors requête)` : une acquisition faite
    /// SANS portée de route est comptée, sous une étiquette qui le dit — jamais perdue, jamais
    /// attribuée au hasard à une route voisine.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn p78a_sans_file_le_compteur_de_saturation_ne_bouge_pas() {
        const R: &str = "essai/route-sans-file";
        let sem = Arc::new(tokio::sync::Semaphore::new(2));
        let a = sous_route(Etiquette::Nommee(R), acquire_query_permit(&sem)).await.unwrap();
        let b = sous_route(Etiquette::Nommee(R), acquire_query_permit(&sem)).await.unwrap();
        let c = registre().existants(R).expect("la route a acquis : elle doit être enregistrée");
        assert_eq!(c.acquisitions(), 2);
        assert_eq!(
            c.attentes(), 0,
            "deux permis pour deux clients : aucune requête ne PEUT attendre son tour, et pourtant la \
             saturation est comptée. Un compteur qui monte toujours ne réfute rien."
        );
        assert_eq!(c.attente_us(), 0, "aucune file : le cumul d'attente doit être EXACTEMENT nul");
        drop(a);
        drop(b);

        // Hors de toute portée de route : la mesure existe, sous une étiquette qui l'avoue.
        let avant = registre().existants(ETIQUETTE_HORS_REQUETE).map(|c| c.acquisitions()).unwrap_or(0);
        let hors = acquire_query_permit(&sem).await.unwrap();
        let apres = registre().existants(ETIQUETTE_HORS_REQUETE).expect("le seau hors requête doit exister").acquisitions();
        assert!(apres > avant, "une acquisition hors requête doit être COMPTÉE, pas perdue");
        drop(hors);
    }

    /// LE PLAFOND DE CARDINALITÉ MORD, ET IL LE DIT. La borne mémoire n'est pas une intention : on la
    /// fait mordre sur un registre local (jamais celui du processus, qu'un essai n'a pas à polluer).
    /// Au-delà du plafond, la MESURE survit — elle rejoint le seau de débordement — mais son
    /// ATTRIBUTION est perdue, et `tronque` passe à 1 pour que l'exploitant sache qu'il lit un total
    /// et non une route. Une borne muette ne vaut pas mieux qu'aucune borne.
    #[test]
    fn p78a_le_plafond_du_registre_mord_et_le_dit() {
        let r = Registre::neuf(3);
        for i in 0..3 {
            r.compteurs(&format!("essai/route-{i}"));
        }
        assert_eq!(r.etat(), (3, 3, false), "sous le plafond : aucune troncature");
        let debordee = r.compteurs("essai/route-de-trop");
        let (n, _, tronque) = r.etat();
        assert_eq!(n, 4, "le seau de débordement est la SEULE entrée que le plafond autorise en plus");
        assert!(tronque, "le plafond a mordu et ne le dit pas : la troncature serait silencieuse");
        assert!(r.existants("essai/route-de-trop").is_none(), "l'attribution est perdue, c'est le prix");
        assert!(
            Arc::ptr_eq(&debordee, &r.existants(ETIQUETTE_DEBORDEMENT).unwrap()),
            "…mais la mesure, elle, doit survivre dans le seau de débordement"
        );
        let encore = r.compteurs("essai/encore-une-de-trop");
        assert!(Arc::ptr_eq(&debordee, &encore), "toutes les routes en trop partagent UN seau");
        assert_eq!(r.etat().0, 4, "la cardinalité ne dérive pas au-delà du plafond : c'est tout l'objet");
    }

    /// L'ÉTIQUETTE EST LE GABARIT DE ROUTE, PAS L'URL — et c'est de là que vient la borne.
    ///
    /// Le routeur est servi POUR DE VRAI (socket éphémère, HTTP/1.1 brut, la même sonde que la
    /// famille `router_*`) et interrogé sur deux URL distinctes du MÊME gabarit. Une étiquette prise
    /// sur l'URL ferait deux séries ici, et une par valeur d'identifiant en production : la
    /// cardinalité serait non bornée, c'est-à-dire une fuite mémoire à la vitesse du trafic.
    #[tokio::test]
    async fn p78a_l_etiquette_est_le_gabarit_de_route_pas_l_url() {
        let sem = Arc::new(tokio::sync::Semaphore::new(2));
        let s = sem.clone();
        let app = Router::new()
            .route(
                "/api/essai-p78a/:id",
                get(move || {
                    let s = s.clone();
                    async move {
                        let _permit = acquire_query_permit(&s).await.expect("permit");
                        "ok"
                    }
                }),
            )
            .route_layer(middleware::from_fn(crate::semaphore_interactif::etiqueter_route));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        assert_eq!(router_probe(addr, "GET", "/api/essai-p78a/42", None).await, 200);
        assert_eq!(router_probe(addr, "GET", "/api/essai-p78a/1337", None).await, 200);

        let c = registre()
            .existants("/api/essai-p78a/:id")
            .expect("l'étiquette doit être le GABARIT apparié par la table de routes");
        assert_eq!(c.acquisitions(), 2, "deux requêtes, deux acquisitions, UNE seule étiquette");
        for url in ["/api/essai-p78a/42", "/api/essai-p78a/1337"] {
            assert!(
                registre().existants(url).is_none(),
                "une étiquette a été prise sur l'URL ({url}) : la cardinalité de /metrics croîtrait avec le \
                 trafic, et le budget de 2 Gio ne tient pas contre une série par identifiant"
            );
        }
    }
}
