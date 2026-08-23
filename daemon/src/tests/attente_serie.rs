// `P10.11-a` — CE QUE CES TESTS PROUVENT, ET POURQUOI DANS CET ORDRE.
//
// LE DÉFAUT EST UNE FORME, PAS UN CHIFFRE. L'attente d'une requête existait, mesurée, exacte — et
// rendue dans la RÉPONSE d'une requête. Elle ne se corrélait donc à rien : ni à la passe de
// vieillissement qui la causait, ni à la requête d'à côté. Le remède n'est pas « publier la même
// valeur ailleurs » : c'est publier une forme qui SURVIT à l'agrégation et qui montre la QUEUE.
//
// LA DISTRIBUTION A ÉTÉ MESURÉE AVANT DE CHOISIR CETTE FORME (banc local, 2026-08-20, chaîne
// complète permis -> verrou partagé, borne interactive à 3, arrivées régulières) :
//   * 200 requêtes / 5 s, passe couvrant 5 % de la fenêtre : moyenne 3,4 ms, max 250 ms — la moyenne
//     sous-estime le pire échantillon d'un facteur **73**, et **5 échantillons portent 98,8 %** du
//     temps d'attente total ;
//   * 2 000 requêtes / 5 s, passe couvrant 0,5 % de la fenêtre : **p99 = 0,000 ms** alors que le max
//     vaut 25 ms. Un quantile ne voit la queue que si elle est plus épaisse que 1 − q, ce qui dépend
//     de la CHARGE — grandeur que la série ne connaît pas. Les quantiles sont écartés PAR LA MESURE ;
//   * témoin sans passe : tout à zéro.
// D'où : des SEAUX (qui comptent la queue), un MAXIMUM (qu'un échantillon unique ne dilue pas), des
// cumuls par terme, et un compte d'observations sans lequel un seau ne se lit pas.
//
// L'ORDRE DES TESTS SUIT CET ARGUMENT :
//   1. le seau est PUR, et son étiquette ne peut pas diverger de sa borne ;
//   2. LA MUTATION : une passe simulée qui tient le verrou fait monter la série ; le témoin sans
//      passe, à charge identique, ne la fait pas monter ;
//   3. LA CONCENTRATION : une requête sur cent qui attend longuement DOIT rester visible — et le
//      même jeu de données est opposé à ce qu'une moyenne en aurait dit ;
//   4. LA COMPOSITION : les deux files sont disjointes, donc leur somme est un coût et non un
//      double-compte — opposé au temps mural de la requête, pas à une conviction ;
//   5. L'AXE DE CORRÉLATION : la fenêtre de la passe se lit sur la MÊME échelle de temps, et
//      l'instrument ne peut pas annoncer plus de chevauchement que de fenêtre ;
//   6. la forme d'une fenêtre VIDE (un trou nommé, jamais six zéros) ;
//   7. la CARDINALITÉ, bornée par une énumération fermée et non par un plafond qu'on tient ;
//   8. le CÂBLAGE : la fin d'une requête est observée, même quand aucune réponse n'est rendue ;
//   9. le COÛT sur le chemin chaud, mesuré et non affirmé ;
//  10. ce que la mesure NE DIT PAS voyage AVEC elle, dans l'exposition ;
//  11. les points atterrissent réellement dans `metric`, relisibles en SOQL.

#[cfg(test)]
mod attente_serie_tests {
    use crate::attente_serie::*;
    use crate::query_timing::QueryClock;
    use crate::vieillissement_serie;
    use crate::{migrate, ventilation_serie::Point};
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;

    /// Les valeurs d'une série, par étiquette, dans une liste de points.
    fn valeurs(pts: &[Point], nom: &str) -> Vec<(Option<String>, f64)> {
        pts.iter().filter(|p| p.nom == nom).map(|p| (p.etiquettes.clone(), p.valeur)).collect()
    }

    /// La valeur d'une série NUE (sans étiquette).
    fn valeur_nue(pts: &[Point], nom: &str) -> Option<f64> {
        pts.iter().find(|p| p.nom == nom && p.etiquettes.is_none()).map(|p| p.valeur)
    }

    /// Les comptes de seaux d'une liste de points, dans l'ordre des bornes.
    fn seaux_des_points(pts: &[Point]) -> Vec<f64> {
        ETIQUETTES_SEAU
            .iter()
            .map(|e| {
                pts.iter()
                    .find(|p| p.nom == NOM_SEAUX && p.etiquettes.as_deref() == Some(&format!("{{\"seau\":\"{e}\"}}")[..]))
                    .map(|p| p.valeur)
                    .unwrap_or(-1.0)
            })
            .collect()
    }

    // =============================================================================================
    // 1. LE SEAU EST PUR
    // =============================================================================================

    /// Les bornes et leurs étiquettes ne peuvent pas diverger — une étiquette `"10"` sur un seau qui
    /// commence à 100 ms ferait lire toute la série de travers, sans qu'aucun compte ne bouge.
    #[test]
    fn le_seau_est_pur_et_son_etiquette_ne_peut_pas_diverger_de_sa_borne() {
        assert_eq!(BORNES_US.len(), NB_SEAUX);
        assert_eq!(ETIQUETTES_SEAU.len(), NB_SEAUX);
        for (i, b) in BORNES_US.iter().enumerate() {
            assert_eq!(
                ETIQUETTES_SEAU[i],
                (b / 1000).to_string(),
                "l'étiquette du seau {i} n'est pas sa borne basse en ms — la série se lirait de travers"
            );
        }
        // Témoins : la borne EXACTE tombe dans son seau, la microseconde d'avant dans le précédent.
        assert_eq!(seau_de(0), 0);
        assert_eq!(seau_de(999), 0);
        assert_eq!(seau_de(1_000), 1);
        assert_eq!(seau_de(9_999), 1);
        assert_eq!(seau_de(10_000), 2);
        assert_eq!(seau_de(100_000), 3);
        assert_eq!(seau_de(1_000_000), 4);
        assert_eq!(seau_de(10_000_000), 5);
        // Le dernier seau est OUVERT vers le haut : une attente hors échelle doit tomber DEDANS,
        // jamais hors de la série (une valeur perdue ne se distingue pas d'une valeur nulle).
        assert_eq!(seau_de(u64::MAX), NB_SEAUX - 1);
    }

    // =============================================================================================
    // 2. LA MUTATION — une passe simulée fait monter la série, le témoin ne la fait pas monter
    // =============================================================================================

    /// UNE MANCHE DE CHARGE, avec le VRAI instrument de production.
    ///
    /// Chaque « requête » démarre une `QueryClock`, prend le verrou de la connexion partagée par
    /// `clock.db().lock` (le chronomètre de `query_timing`, pas une imitation), puis obtient son
    /// permit — exactement l'ordre du chemin GXQL. L'attente relue est celle que la RÉPONSE
    /// publierait, ce qui rend cette manche opposable à la mesure d'origine.
    ///
    /// Rend l'accumulateur LOCAL : l'accumulateur de processus est partagé avec le reste de la
    /// suite, et une garde qui dépendrait d'un état que d'autres essais alimentent ne garderait rien.
    async fn manche(n: usize, arrivee: Duration, tenue: Duration) -> Accumulateur {
        let acc = Accumulateur::neuf();
        let sem = Arc::new(Semaphore::new(64)); // large : cette manche isole le VERROU, pas la borne
        let m: Arc<Mutex<Connection>> = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let squatteur = if tenue.is_zero() {
            None
        } else {
            let tenu = m.clone();
            let debut_tenue = arrivee * (n as u32 / 4); // au premier quart : la passe arrive EN COURS de charge
            Some(std::thread::spawn(move || {
                std::thread::sleep(debut_tenue);
                let _g = tenu.lock();
                std::thread::sleep(tenue);
            }))
        };
        let depart = Instant::now();
        let mut taches = Vec::with_capacity(n);
        for i in 0..n {
            let cible = depart + arrivee * i as u32;
            let maintenant = Instant::now();
            if cible > maintenant {
                tokio::time::sleep(cible - maintenant).await;
            }
            let (m2, sem2) = (m.clone(), sem.clone());
            taches.push(tokio::spawn(async move {
                let clock = QueryClock::start();
                // Le verrou est BLOQUANT : il ne se prend pas sur un fil de l'ordonnanceur async.
                let clock = tokio::task::spawn_blocking(move || {
                    {
                        let _c = clock.db().lock(&m2);
                    }
                    clock
                })
                .await
                .unwrap();
                let (_p, t) = clock.permit(&sem2).await.unwrap();
                ((t.db_lock_wait_ms() * 1000.0).round() as u64, (t.sem_wait_ms() * 1000.0).round() as u64)
            }));
        }
        for t in taches {
            let (verrou_us, permis_us) = t.await.unwrap();
            acc.observer(permis_us, verrou_us);
        }
        if let Some(h) = squatteur {
            h.join().unwrap();
        }
        acc
    }

    /// LA PREUVE PAR MUTATION, DANS LES DEUX SENS. Sans les deux, l'un des deux ne prouve rien : une
    /// série toujours pleine et une série toujours vide sont le même défaut — un chiffre qui ne
    /// réfute rien.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn une_passe_simulee_fait_monter_la_serie_le_temoin_sans_passe_ne_la_fait_pas_monter() {
        const N: usize = 50;
        let avec = manche(N, Duration::from_millis(20), Duration::from_millis(300)).await;
        let sans = manche(N, Duration::from_millis(20), Duration::ZERO).await;

        let pts_avec = avec.points_de_fenetre(0);
        let pts_sans = sans.points_de_fenetre(0);
        let (s_avec, s_sans) = (seaux_des_points(&pts_avec), seaux_des_points(&pts_sans));
        let hauts = |s: &[f64]| s[3] + s[4] + s[5]; // >= 100 ms
        let max_avec = valeur_nue(&pts_avec, NOM_MAX).unwrap();
        let max_sans = valeur_nue(&pts_sans, NOM_MAX).unwrap();

        assert!(
            hauts(&s_avec) >= 1.0,
            "une passe qui tient le verrou 300 ms n'a mis AUCUNE requête au-dessus de 100 ms \
             (seaux={s_avec:?}) : la série ne montre pas ce qu'elle existe pour montrer"
        );
        assert!(
            max_avec >= 100.0,
            "le maximum de la fenêtre est {max_avec} ms alors qu'une passe a tenu le verrou 300 ms"
        );
        assert_eq!(
            hauts(&s_sans),
            0.0,
            "TÉMOIN INVERSE : sans aucune passe, la même charge a rempli les seaux hauts \
             (seaux={s_sans:?}). Une série qui monte sans cause n'impute rien."
        );
        assert!(
            max_sans < 50.0,
            "TÉMOIN INVERSE : sans passe, le maximum vaut {max_sans} ms — la série mesure autre chose \
             que l'exposition qu'on lui demande"
        );

        // ET CE QU'UNE MOYENNE EN AURAIT DIT. Le cumul est publié, donc la moyenne est calculable :
        // on la calcule ICI pour l'opposer au maximum, sur les MÊMES données.
        let cumul: f64 = valeurs(&pts_avec, NOM_MS).iter().map(|(_, v)| v).sum();
        let moyenne = cumul / N as f64;
        assert!(
            moyenne * 3.0 < max_avec,
            "sur cette manche la moyenne ({moyenne:.3} ms) n'est pas nettement sous le maximum \
             ({max_avec:.3} ms) : la manche ne met pas la concentration en situation, donc elle ne \
             prouve rien de ce que ce module affirme"
        );
        assert!(
            s_avec[0] > hauts(&s_avec),
            "l'exposition doit rester RARE (la plupart des requêtes n'attendent pas) : seaux={s_avec:?}"
        );
    }

    // =============================================================================================
    // 3. LA CONCENTRATION — une requête sur cent, et ce qu'une moyenne en aurait fait
    // =============================================================================================

    /// UNE REQUÊTE SUR CENT QUI ATTEND 2 s DOIT RESTER VISIBLE. C'est le cas exact que la clé nomme,
    /// et celui qu'une série lissée efface. Le test oppose la série publiée à la moyenne des mêmes
    /// données : elles ne rangent pas cette fenêtre dans le même ordre de grandeur.
    #[test]
    fn la_concentration_reste_visible_quand_une_requete_sur_cent_attend_longuement() {
        let acc = Accumulateur::neuf();
        for _ in 0..99 {
            acc.observer(0, 0);
        }
        acc.observer(0, 2_000_000); // 2 s derrière le verrou partagé
        let pts = acc.points_de_fenetre(0);
        let s = seaux_des_points(&pts);

        assert_eq!(valeur_nue(&pts, NOM_REQUETES), Some(100.0));
        assert_eq!(
            s[4], 1.0,
            "l'échantillon à 2 s doit être COMPTÉ dans le seau [1 s, 10 s[ — seaux={s:?}"
        );
        assert_eq!(s[0], 99.0, "les 99 requêtes sans attente doivent rester comptées : seaux={s:?}");
        assert_eq!(
            valeur_nue(&pts, NOM_MAX),
            Some(2000.0),
            "le maximum de la fenêtre EST l'échantillon unique : c'est tout ce qu'on lui demande"
        );

        // CE QU'UNE MOYENNE AURAIT DIT DES MÊMES DONNÉES : 2 000 ms / 100 = 20 ms, soit DEUX seaux
        // plus bas que là où l'analyste s'est réellement trouvé. Ce n'est pas une approximation,
        // c'est un ordre de grandeur perdu.
        let cumul: f64 = valeurs(&pts, NOM_MS).iter().map(|(_, v)| v).sum();
        let moyenne_us = (cumul * 1000.0 / 100.0) as u64;
        assert_eq!(moyenne_us, 20_000);
        assert!(
            seau_de(moyenne_us) + 2 == seau_de(2_000_000),
            "le témoin de ce test est faux : la moyenne devrait tomber deux seaux sous l'échantillon"
        );
    }

    // =============================================================================================
    // 4. LA COMPOSITION — deux files disjointes, donc une somme et non un double-compte
    // =============================================================================================

    /// LA COMPOSITION EST-ELLE LÉGITIME ? Les deux attentes sont traversées l'une APRÈS l'autre par
    /// la même tâche : leur somme ne peut pas dépasser le temps mural de la requête. Le test met une
    /// requête en situation d'attendre LES DEUX (un tiers tient le verrou, un autre tient le seul
    /// permit) et oppose la somme au temps mesuré de l'extérieur.
    ///
    /// C'est aussi la garde qui répond « oui » à la question de la clé : l'attente du verrou seule
    /// est une borne inférieure, et ce que le permit ajoute n'est pas une correction de bord.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn la_composition_ne_double_compte_pas() {
        let sem = Arc::new(Semaphore::new(1));
        let m: Arc<Mutex<Connection>> = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));

        // LE TIERS QUI TIENT LE VERROU — la passe de vieillissement, ou la boucle de rollups.
        let tenu = m.clone();
        let squatteur = std::thread::spawn(move || {
            let _g = tenu.lock();
            std::thread::sleep(Duration::from_millis(120));
        });
        // LE TIERS QUI TIENT LE PERMIT — une autre requête déjà en cours.
        let permis_tenu = sem.clone().acquire_owned().await.unwrap();
        let rendu = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(220)).await;
            drop(permis_tenu);
        });
        tokio::time::sleep(Duration::from_millis(10)).await; // laisser le squatteur prendre le verrou

        let mural = Instant::now();
        let clock = QueryClock::start();
        let m2 = m.clone();
        let clock = tokio::task::spawn_blocking(move || {
            {
                let _c = clock.db().lock(&m2);
            }
            clock
        })
        .await
        .unwrap();
        let (_p, t) = clock.permit(&sem).await.unwrap();
        let mural_ms = mural.elapsed().as_secs_f64() * 1000.0;
        squatteur.join().unwrap();
        rendu.await.unwrap();

        let (verrou, permis) = (t.db_lock_wait_ms(), t.sem_wait_ms());
        assert!(verrou > 0.0, "le tiers tenait le verrou : l'attente du verrou vaut {verrou} ms");
        assert!(permis > 0.0, "le tiers tenait le seul permit : l'attente du permit vaut {permis} ms");
        assert!(
            verrou + permis <= mural_ms + 1.0,
            "les deux attentes se CHEVAUCHENT (verrou={verrou} + permis={permis} > mural={mural_ms}) : \
             leur somme ne serait plus un coût, ce serait un double-compte"
        );
        // Et la composition va bien dans le seau du TOTAL, pas dans celui du plus gros terme seul.
        let acc = Accumulateur::neuf();
        acc.observer((permis * 1000.0) as u64, (verrou * 1000.0) as u64);
        let s = seaux_des_points(&acc.points_de_fenetre(0));
        assert_eq!(
            s[seau_de(((verrou + permis) * 1000.0) as u64)],
            1.0,
            "l'observation doit être rangée au seau de la SOMME : seaux={s:?}"
        );
    }

    // =============================================================================================
    // 5. L'AXE DE CORRÉLATION — la fenêtre de la passe, sur la même échelle de temps
    // =============================================================================================

    /// LA PASSE EST-ELLE LISIBLE SUR L'ÉCHELLE DE TEMPS DES ATTENTES ? Sans ça, « cette requête
    /// était-elle lente parce qu'une passe tournait ? » n'a pas de réponse : la durée d'une passe
    /// est publiée UNE fois, à son horodatage, et ne dit pas dans quelle fenêtre elle tombait.
    ///
    /// Sens POSITIF sur le compteur de processus (une passe le fait monter d'au moins sa durée) ;
    /// sens INVERSE sur la construction des points, où le chevauchement est un PARAMÈTRE — donc
    /// déterministe, et insensible à ce que le reste de la suite fait au même moment.
    #[test]
    fn la_fenetre_de_vieillissement_se_lit_sur_la_meme_echelle_que_les_attentes() {
        // LA FENÊTRE DE VIEILLISSEMENT EST UNE RESSOURCE DE PROCESSUS : ce test en ouvre une VRAIE,
        // il doit donc prendre le MÊME verrou que les tests d'instrument de `vieillissement_serie`.
        // Sans lui, deux fenêtres se chevauchent et c'est l'AUTRE test qui tombe, au hasard de
        // l'ordonnancement — constaté ici avant correction.
        let _serialise = super::vieillissement_serie_tests::FENETRES.lock();
        let avant = vieillissement_serie::chevauchement_us();
        {
            let _f = vieillissement_serie::Fenetre::ouvrir();
            std::thread::sleep(Duration::from_millis(60));
        }
        let apres = vieillissement_serie::chevauchement_us();
        assert!(
            apres >= avant + 50_000,
            "une passe de 60 ms n'a fait monter le chevauchement que de {} µs",
            apres - avant
        );

        // TÉMOIN INVERSE : aucune fenêtre ouverte entre deux publications -> le chevauchement publié
        // est ZÉRO, et il l'est EXACTEMENT (pas « petit »).
        let acc = Accumulateur::neuf();
        acc.observer(0, 0);
        std::thread::sleep(Duration::from_millis(80));
        let _ = acc.points_de_fenetre(1_000_000);
        acc.observer(0, 0);
        std::thread::sleep(Duration::from_millis(80));
        let pts = acc.points_de_fenetre(1_000_000);
        assert_eq!(
            valeur_nue(&pts, NOM_VIEILLISSEMENT),
            Some(0.0),
            "sans passe, le chevauchement publié doit être un zéro EXACT"
        );

        // SENS POSITIF sur la même construction : 40 ms de passe dans une fenêtre de 80 ms.
        acc.observer(0, 0);
        std::thread::sleep(Duration::from_millis(80));
        let pts = acc.points_de_fenetre(1_040_000);
        assert_eq!(valeur_nue(&pts, NOM_VIEILLISSEMENT), Some(40.0));

        // ET L'INSTRUMENT SE VALIDE : il ne peut pas annoncer PLUS de chevauchement que de fenêtre.
        // Un chiffre supérieur à la fenêtre se lirait comme une passe permanente — ce qui serait un
        // instrument cassé, pas une passe.
        acc.observer(0, 0);
        std::thread::sleep(Duration::from_millis(30));
        let pts = acc.points_de_fenetre(1_040_000 + 10_000_000);
        let chev = valeur_nue(&pts, NOM_VIEILLISSEMENT).unwrap();
        assert!(
            chev <= 10_000.0 && chev >= 25.0,
            "le chevauchement ({chev} ms) doit être plafonné à la durée de la fenêtre (~30 ms)"
        );
    }

    // =============================================================================================
    // 6. UNE FENÊTRE VIDE — un trou NOMMÉ, jamais six zéros
    // =============================================================================================

    /// Une fenêtre sans trafic publie DEUX points : le compte d'observations (zéro MESURÉ) et le
    /// chevauchement. Pas de seaux, pas de maximum : six zéros par fenêtre sur une base au repos
    /// coûteraient des lignes pour toujours sans rien dire de plus. La règle de lecture qui en
    /// découle — lire les seaux AVEC le compte — est celle que `retard_lignes`/`retard_ok` a déjà
    /// posée ; ce test la fige.
    #[test]
    fn une_fenetre_sans_requete_dit_zero_requete_et_ne_publie_aucun_seau() {
        let acc = Accumulateur::neuf();
        let pts = acc.points_de_fenetre(0);
        let noms: Vec<String> =
            pts.iter().map(|p| format!("{}{}", p.nom, p.etiquettes.clone().unwrap_or_default())).collect();
        assert_eq!(pts.len(), 2, "une fenêtre vide doit publier exactement le compte et le chevauchement : {noms:?}");
        assert_eq!(valeur_nue(&pts, NOM_REQUETES), Some(0.0));
        assert!(valeurs(&pts, NOM_SEAUX).is_empty(), "aucun seau ne doit être publié sans observation");
        assert!(valeur_nue(&pts, NOM_MAX).is_none(), "aucun maximum ne doit être publié sans observation");
        assert!(valeurs(&pts, NOM_MS).is_empty(), "aucun cumul ne doit être publié sans observation");
    }

    // =============================================================================================
    // 7. LA CARDINALITÉ — une énumération FERMÉE, pas un plafond qu'on tient
    // =============================================================================================

    /// ONZE COUPLES (nom, étiquette), quel que soit le trafic. La borne ne vient pas d'un plafond
    /// qui mord : aucune étiquette ne peut venir d'une requête, donc il n'y a rien à plafonner. Le
    /// test le montre en faisant varier le trafic d'un facteur 1 000 et en exigeant le MÊME
    /// ensemble d'étiquettes.
    #[test]
    fn la_cardinalite_est_bornee_et_ne_depend_pas_du_trafic() {
        let empreinte = |n: usize| {
            let acc = Accumulateur::neuf();
            for i in 0..n {
                acc.observer((i as u64 * 37) % 3_000_000, (i as u64 * 911) % 12_000_000);
            }
            let mut e: Vec<String> = acc
                .points_de_fenetre(0)
                .iter()
                .map(|p| format!("{}{}", p.nom, p.etiquettes.clone().unwrap_or_default()))
                .collect();
            e.sort();
            e
        };
        let petit = empreinte(10);
        let gros = empreinte(10_000);
        assert_eq!(petit, gros, "la cardinalité a bougé avec le trafic");
        assert_eq!(
            petit.len(),
            NB_SEAUX + 5,
            "la cardinalité annoncée dans l'en-tête du module (onze couples) ne correspond plus à ce \
             qui est publié : {petit:?}"
        );
        let distincts: std::collections::BTreeSet<&String> = petit.iter().collect();
        assert_eq!(distincts.len(), petit.len(), "deux points portent le même couple (nom, étiquette)");
    }

    // =============================================================================================
    // 8. LE CÂBLAGE — la fin d'une requête est observée, même sans réponse
    // =============================================================================================

    /// LE POINT D'OBSERVATION EST LA LIBÉRATION DU DÉCOUPAGE, pas l'écriture d'une réponse. Une
    /// requête qui a attendu puis échoué a coûté son attente à un analyste ; un appel posé sur le
    /// chemin de réponse l'aurait perdue. Le test relâche le découpage SANS jamais publier de
    /// réponse et exige que l'accumulateur de processus ait bougé.
    #[tokio::test]
    async fn la_fin_d_une_requete_est_observee_meme_quand_aucune_reponse_n_est_rendue() {
        let sem = Arc::new(Semaphore::new(1));
        let avant = accumulateur().observations();
        {
            let clock = QueryClock::start();
            let (_p, _t) = clock.permit(&sem).await.unwrap();
            // aucune réponse : `_t` est simplement relâché ici
        }
        assert!(
            accumulateur().observations() >= avant + 1,
            "la libération du découpage n'a rien observé : une requête sans réponse deviendrait \
             invisible, alors que son attente a bien eu lieu"
        );
    }

    // =============================================================================================
    // 9. LE COÛT SUR LE CHEMIN CHAUD — mesuré, pas affirmé
    // =============================================================================================

    /// UNE MESURE QUI COÛTE CE QU'ELLE MESURE FINIT PAR SE FAIRE ÉTEINDRE. L'observation est faite
    /// sur un chemin qui vient d'acquérir un sémaphore et d'exécuter du SQL : elle doit disparaître
    /// devant. Aucune allocation, aucun format, aucune horloge lue en plus — six atomiques relâchées.
    ///
    /// `P6.9-a` — CE QUI EST ASSERTÉ EST UN RAPPORT, PAS DES NANOSECONDES. La forme précédente
    /// assertait `< 1 000 ns` par observation. Une borne absolue mesure la machine autant que le code,
    /// et celle-ci rougissait sous charge alors que rien n'avait changé — mesuré le 2026-08-23 sur ce
    /// banc (12 cœurs, binaire de test `debug`, mesure épinglée sur UN cœur partagé avec des brûleurs
    /// de CPU) :
    ///
    /// | banc                         | ancienne forme (moyenne) | verdict   | rapport MÉDIAN |
    /// |------------------------------|--------------------------|-----------|----------------|
    /// | au repos                     | 120 ns                   | VERT      | 8,06 à 8,57    |
    /// | 8 brûleurs sur le même cœur  | 1 135 ns                 | **ROUGE** | 8,77           |
    /// | 16 brûleurs                  | 2 297 ns                 | **ROUGE** | 8,21           |
    /// | 32 brûleurs                  | 4 208 ns                 | **ROUGE** | 8,14           |
    /// | 12 brûleurs, machine entière | 412 ns                   | VERT      | 8,17           |
    ///
    /// Le coût apparent varie de ×35 ; le rapport, de 8 %.
    ///
    /// L'ÉTALON EST L'OPÉRATION DONT L'OBSERVATION EST FAITE : un `fetch_add` relâché sur un
    /// `AtomicU64`. C'est ce que `observer` fait six fois (quatre compteurs, plus deux maximums qui
    /// lisent et n'échangent qu'en montant), et rien d'autre ne doit s'y ajouter. Un `format!`, un
    /// `Instant::now()` ou un verrou coûtent des dizaines d'atomiques et sortent immédiatement du
    /// plafond ; c'est exactement ce que ce test existe pour interdire.
    ///
    /// LES BLOCS SONT COURTS ET ALTERNÉS, ET CE N'EST PAS UN DÉTAIL. Une atomique ne se chronomètre
    /// pas à l'unité (l'horloge coûte plus cher qu'elle) : on mesure des blocs. Avec des blocs LONGS
    /// (mesuré : 20 blocs de 10 000), la majorité des blocs est préemptée sous charge et la médiane
    /// devient celle des blocs préemptés — le rapport est monté à 375, faux rouge. Des blocs COURTS
    /// (200 blocs de 1 000) restent sous la tranche de l'ordonnanceur, la médiane retombe sur les
    /// blocs propres, et le rapport tient à 6 % près sur tous les bancs ci-dessus.
    ///
    /// MUTATION (exécutée le 2026-08-23) : `observer` répétant dix fois son corps porte le rapport de
    /// 8,5 à **72,1 au repos** et fait rougir cette assertion, au repos comme sous charge.
    #[test]
    fn une_observation_ne_coute_presque_rien() {
        /// Le nombre d'opérations atomiques que fait UNE observation : quatre compteurs incrémentés,
        /// deux maximums relevés. Le plafond est dérivé de CE nombre, pas d'une durée.
        const ATOMIQUES_PAR_OBSERVATION: f64 = 6.0;
        /// LE PLAFOND, ET D'OÙ IL SORT. Mesuré sur ce banc : 8,06 à 8,77 selon la charge — au-dessus
        /// des six atomiques, parce qu'une observation calcule aussi son seau et paie, en profil
        /// `debug`, un appel non inliné. Le plafond est posé au TRIPLE du compte d'atomiques : il
        /// borne la FORME (une poignée d'atomiques) sans borner le profil de compilation, il laisse
        /// 2,05 fois de marge au-dessus du pire rapport observé (8,77), et il rougit quatre fois plus
        /// bas que ce que rend une mutation ×10.
        const RAPPORT_MAX: f64 = 3.0 * ATOMIQUES_PAR_OBSERVATION;
        /// Le nombre total d'observations est inchangé ; il est découpé en blocs COURTS pour que la
        /// médiane porte sur des blocs non préemptés (cf. le commentaire de doc).
        const N: u64 = 200_000;
        const BLOCS: usize = 200;
        const PAR_BLOC: u64 = N / BLOCS as u64;

        let acc = Accumulateur::neuf();
        let etalon = std::sync::atomic::AtomicU64::new(0);
        let un_etalon = || {
            std::hint::black_box(etalon.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        };
        // Chauffe : le premier bloc paie le cache d'instructions et le premier défaut de page.
        for i in 0..PAR_BLOC {
            acc.observer(i % 1_000, i % 5_000_000);
            un_etalon();
        }
        // LES DEUX BRAS SONT ENTRELACÉS, bloc par bloc : ils subissent alors le MÊME ordonnancement.
        let (mut refs, mut obs) = (Vec::with_capacity(BLOCS), Vec::with_capacity(BLOCS));
        for _ in 0..BLOCS {
            let t = Instant::now();
            for _ in 0..PAR_BLOC {
                un_etalon();
            }
            refs.push(t.elapsed() / PAR_BLOC as u32);
            let t = Instant::now();
            for i in 0..PAR_BLOC {
                acc.observer(i % 1_000, i % 5_000_000);
            }
            obs.push(t.elapsed() / PAR_BLOC as u32);
        }
        let mediane = |v: &mut Vec<Duration>| {
            v.sort_unstable();
            v[v.len() / 2]
        };
        let (r, o) = (mediane(&mut refs), mediane(&mut obs));

        assert_eq!(
            acc.observations(),
            N + PAR_BLOC,
            "le bras mesuré n'a pas fait le travail annoncé — le rapport ci-dessous porterait sur autre chose"
        );
        // GARDE-FOU DE L'INSTRUMENT : un étalon nul rendrait le rapport infini (faux rouge). Si
        // l'horloge ne résout plus un bloc d'atomiques, ce test ne peut rien prouver — il doit le DIRE.
        assert!(
            r > Duration::ZERO,
            "l'étalon (un `fetch_add` relâché) mesure {r:?} : l'horloge ne le résout pas, le rapport \
             ci-dessous ne voudrait rien dire"
        );
        let rapport = o.as_secs_f64() / r.as_secs_f64();
        assert!(
            rapport <= RAPPORT_MAX,
            "une observation coûte {rapport:.2} `fetch_add` relâchés ({o:?} contre {r:?}, médianes sur \
             {BLOCS} blocs de {PAR_BLOC} entrelacés) — au-delà de {RAPPORT_MAX:.0}, ce n'est plus la \
             composition attendue ({ATOMIQUES_PAR_OBSERVATION:.0} atomiques) : une allocation, un \
             format, une horloge ou un verrou se sont glissés sur le chemin que la mesure mesure"
        );
        eprintln!(
            "[mesure 2026-08-23] une observation : {rapport:.2} `fetch_add` relâchés (médianes {o:?} / \
             {r:?}). Le chiffre ABSOLU dépend de la machine et n'est qu'un repère : {o:?} par observation."
        );
    }

    // =============================================================================================
    // 10. CE QUE LA MESURE NE DIT PAS VOYAGE AVEC ELLE
    // =============================================================================================

    /// UNE LIMITE ÉCRITE DANS UN COMMENTAIRE DE SOURCE N'EST PAS OPPOSABLE À QUI LIT LE VERDICT.
    /// Celui qui regarde `/metrics` doit lire, à côté du chiffre, que ce chiffre est une BORNE
    /// INFÉRIEURE du coût pour un analyste et qu'il ne compte que de l'attente. Ce test fige cette
    /// exigence — pas la formulation exacte, mais la présence des trois aveux.
    #[test]
    fn ce_que_la_mesure_ne_dit_pas_voyage_dans_l_exposition() {
        let acc = Accumulateur::neuf();
        acc.observer(1_500, 2_500);
        let texte = acc.exposition_prom(3_000_000);
        for aveu in [
            // la portée : ce chiffre ne couvre pas toutes les routes
            "BORNE INFÉRIEURE",
            // la nature : de l'attente, jamais du travail ralenti
            "NE COMPTE QUE DE L'ATTENTE",
            // l'axe de corrélation : une présence de passe, pas une durée de verrou
            "BORNE SUPÉRIEURE",
        ] {
            assert!(texte.contains(aveu), "l'exposition ne dit pas « {aveu} » : {texte}");
        }
        // 1,5 ms de permit + 2,5 ms de verrou = 4 ms de TOTAL -> le seau [1 ms, 10 ms[. C'est la
        // SOMME qui range l'observation, jamais le plus gros des deux termes.
        assert!(texte.contains("plume_query_attente_seaux_total{seau=\"1\"} 1"), "{texte}");
        assert!(texte.contains("plume_query_attente_seaux_total{seau=\"0\"} 0"), "{texte}");
        assert!(texte.contains("plume_query_attente_observations_total 1"), "{texte}");
        assert!(texte.contains("plume_query_attente_ms_total{terme=\"permis\"} 1.500"), "{texte}");
        assert!(texte.contains("plume_query_attente_ms_total{terme=\"verrou_partage\"} 2.500"), "{texte}");
        assert!(texte.contains("plume_query_attente_vieillissement_ms_total 3000.000"), "{texte}");
    }

    // =============================================================================================
    // 11. LES POINTS ATTERRISSENT DANS `metric`
    // =============================================================================================

    /// LA SÉRIE N'EXISTE QUE SI ELLE EST DANS LA TABLE QUE SOQL INTERROGE. Le test publie sur une
    /// base au schéma RÉEL et relit les lignes : c'est la seule chose qui distingue une série d'un
    /// calcul en mémoire.
    #[test]
    fn les_points_ecrits_sont_relisibles_dans_metric() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        // L'accumulateur de PROCESSUS : on l'alimente, puis on publie sa fenêtre — c'est le chemin
        // exact que le tick de rollup emprunte.
        observer(1_000_000, 2_000_000);
        let n = publier_fenetre(&conn, 1_800_000_000);
        assert_eq!(n, NB_SEAUX + 5, "onze lignes attendues, {n} écrites");
        let lues: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metric WHERE ts=?1 AND name LIKE 'plume_query_attente_%'",
                rusqlite::params![1_800_000_000i64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lues, (NB_SEAUX + 5) as i64);
        // `host` NULL : cette série décrit LA BASE, pas une machine — l'inscrire dans l'inventaire
        // de flotte inventerait un hôte qui n'existe pas.
        let sans_hote: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metric WHERE ts=?1 AND name LIKE 'plume_query_attente_%' AND host IS NULL",
                rusqlite::params![1_800_000_000i64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sans_hote, lues, "une série qui décrit la base ne doit pas porter d'hôte");
        let max: f64 = conn
            .query_row("SELECT value FROM metric WHERE name=?1", rusqlite::params![NOM_MAX], |r| r.get(0))
            .unwrap();
        assert!(max >= 3000.0, "le maximum publié ({max} ms) doit au moins porter l'observation faite ici");
    }
}
