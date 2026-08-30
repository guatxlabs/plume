    // ==============================================================================================
    // `P10.7-f` — UN RÉSULTAT PARTIEL NE SE SERT PLUS COMME UN TOTAL.
    //
    // LA FAMILLE, ET POURQUOI CE MEMBRE-CI EST LE PIRE. `P10.7-e` a fermé le cas d'une lecture qui
    // N'A PAS EU LIEU et rendait la forme attendue, vide, sans un mot : un refus servi comme une
    // absence. Ici la lecture a bien eu lieu — elle n'est simplement pas allée au bout. La garde de
    // budget de `read_with_watchdog` interrompt l'énoncé EN COURS D'ITÉRATION ; l'idiome livré
    // (`query_map(..).flatten()`) jette le `Err` et garde les lignes déjà lues. Le corps servi est
    // une LISTE PLUS COURTE, bien formée, sans marque : un analyste ne peut pas même soupçonner qu'il
    // manque quelque chose, puisqu'il n'y a rien à lire et rien à compter.
    //
    // CE QUI A ÉTÉ MESURÉ LE 2026-08-30 (interruption rendue DÉTERMINISTE — fonction scalaire qui
    // appelle `interrupt()` à la 51e ligne, jamais un chronomètre) : `.flatten()` rend 51 lignes sur
    // 200 sans erreur ; `collect::<Result<_>>()` rend `Err("interrupted")` ; sans interruption, le
    // même parcours rend 200. Deux faits mesurés le même jour gouvernent la forme du correctif et
    // sont tenus ici par les deux témoins de `parcourir` :
    //   · une erreur du MAPPEUR ne tarit PAS l'itérateur (la ligne est sautée, le parcours continue) —
    //     donc un parcours qui s'arrêterait à la première erreur échangerait une troncature contre une
    //     AUTRE troncature, sur un chemin nominal ;
    //   · une interruption ne porte que sur l'énoncé EN VOL (l'énoncé suivant de la même closure va au
    //     bout) — donc « la garde a tiré » n'est pas « une liste a été tronquée », et l'aveu est adossé
    //     à l'erreur que le PARCOURS voit, jamais à l'armement de la garde.
    //
    // LE TÉMOIN NÉGATIF EST LA MOITIÉ QUI COMPTE. Deux correctifs dégénérés ont déjà été refusés dans
    // ce dépôt pour la raison inverse : un corps qui avoue TOUJOURS n'avoue rien. Chaque témoin joue
    // donc d'abord le chemin NOMINAL, vérifie que la lecture a réellement rendu sa population entière
    // (sans quoi « pas d'aveu » serait vrai par vacuité), et exige qu'AUCUN aveu n'y paraisse.
    //
    // CE QUE CES DEUX TÉMOINS NE TIENNENT PAS : ils ferment `/api/alerts`. Les autres parcours
    // atteignables depuis un `read_with_watchdog` gardent l'idiome muet ; la garde de famille reste à
    // écrire, et le relevé des sites est dans le rapport de la clé.
    // ==============================================================================================

    /// Une table de `n` alertes, dans l'ordre où la page les rendra (ts décroissant).
    fn tsb_base(n: i64) -> Connection {
        let conn = test_db();
        for i in 0..n {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) \
                 VALUES(?1,'rule.1',2,?2,'','new','T1046','')",
                params![1000 + i, format!("A{i}")],
            )
            .unwrap();
        }
        conn
    }

    /// COUPE L'ÉNONCÉ EN VOL, SANS CHRONOMÈTRE. Le rappel de progression de SQLite est appelé tous les
    /// `PAS` opcodes ; il rend `true` UNE seule fois, au `tir`-ième appel, ce qui fait sortir l'énoncé
    /// courant en `SQLITE_INTERRUPT` — exactement le code que la garde de budget provoque — et laisse
    /// les énoncés suivants intacts (la coupe est un loquet, pas un régime).
    ///
    /// Un chronomètre serait ici un faux témoin : sur une machine chargée il couperait ailleurs, et
    /// sur une machine rapide il ne couperait pas du tout.
    const TSB_PAS: std::os::raw::c_int = 8;
    fn tsb_couper_au_tir(conn: &Connection, tir: usize) {
        let vus = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        conn.progress_handler(
            TSB_PAS,
            Some(move || vus.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == tir),
        );
    }
    fn tsb_ne_plus_couper(conn: &Connection) {
        conn.progress_handler(TSB_PAS, None::<fn() -> bool>);
    }

    /// ① LA PAGE D'ALERTES SERVIE PAR LA ROUTE LA PLUS LOURDE DU DÉMON.
    ///
    /// Le chemin nominal rend la page entière et le corps ne porte AUCUN aveu. Puis, à filtre, base et
    /// bornes IDENTIQUES, l'énoncé est coupé en vol : la valeur qui change est la présence de la clé
    /// `error` dans le corps servi — et la longueur de `alerts`, qui devient un PRÉFIXE strict pendant
    /// que `total`, lui, reste le compte VRAI. C'est précisément l'écart qu'aucun corps ne portait.
    #[test]
    fn une_page_d_alertes_tronquee_ne_se_sert_plus_comme_complete() {
        const N: i64 = 60;
        let conn = tsb_base(N);
        let filtre = FiltreAlertes::default();

        // ---- ① NOMINAL. L'instrument d'abord : la page a-t-elle vraiment tout rendu ? ----
        let (page, total, fin) = alerts_query_page(&conn, &filtre, None, "", 200, 0, true);
        assert_eq!(page.len() as i64, N, "instrument : la fixture doit tenir dans la page, sinon « complet » ne veut rien dire");
        assert_eq!(total, Some(N), "instrument : le COUNT doit avoir abouti sur le chemin nominal");
        assert!(fin.cause().is_none(), "un parcours complet ne doit porter AUCUNE cause");
        let corps_nominal = corps_de_liste_d_alertes(page, total, &fin);
        assert!(
            corps_nominal.get("error").is_none(),
            "un aveu posé sur le chemin NOMINAL : un corps qui avoue toujours n'avoue rien — {corps_nominal}"
        );

        // ---- ② L'ÉNONCÉ EST COUPÉ EN VOL. Rien d'autre ne change. ----
        // Le tir est CHERCHÉ, pas deviné : on veut la coupe APRÈS le COUNT (donc `total` établi) et
        // APRÈS au moins une ligne (donc un vrai préfixe, pas une page vide qui relèverait de P10.7-e).
        let mut coupe: Option<(Vec<Value>, Option<i64>, FinDeParcours)> = None;
        for tir in 1..400usize {
            tsb_couper_au_tir(&conn, tir);
            let r = alerts_query_page(&conn, &filtre, None, "", 200, 0, true);
            tsb_ne_plus_couper(&conn);
            if r.1 == Some(N) && !r.0.is_empty() && (r.0.len() as i64) < N {
                coupe = Some(r);
                break;
            }
        }
        let (page, total, fin) = coupe.expect(
            "instrument : aucun tir n'a produit une page TRONQUÉE avec un total établi — le témoin ne \
             conclut pas plutôt que de conclure sur une coupe qu'il n'a pas obtenue",
        );

        let cause = fin.cause().unwrap_or_else(|| panic!("page tronquée rendue SANS cause : {} lignes sur {N}", page.len()));
        assert!(
            cause.contains("interrupted"),
            "la cause du MOTEUR est conservée telle qu'il l'a dite, jamais réécrite : {cause}"
        );
        let servies = page.len();
        let corps = corps_de_liste_d_alertes(page, total, &fin);
        let aveu = corps["error"]
            .as_str()
            .unwrap_or_else(|| panic!("préfixe servi comme une page complète — c'est le défaut que cette clé ferme : {corps}"));
        assert!(aveu.starts_with(CAUSE_LISTE_D_ALERTES_TRONQUEE), "l'aveu dit d'abord ce que le corps n'établit PAS : {aveu}");
        assert!(aveu.contains("interrupted"), "puis il laisse la cause du moteur : {aveu}");
        assert_eq!(
            corps["alerts"].as_array().map(|a| a.len()),
            Some(servies),
            "l'aveu s'AJOUTE : il ne retire aucune des lignes réellement lues — {corps}"
        );
        assert!((servies as i64) < N, "le préfixe est STRICT : {servies} lignes servies sur {N}");
        assert_eq!(
            corps["total"], json!(N),
            "le COUNT a abouti : son résultat reste un FAIT, et c'est lui qui rend l'écart lisible — {corps}"
        );
    }

    /// ② LE PARCOURS LUI-MÊME, DANS LES TROIS SENS QUI LE DÉFINISSENT.
    ///
    /// La fin normale, l'interruption de `step()` (celle que la garde de budget provoque) et l'erreur
    /// du MAPPEUR — cette dernière parce que le remède évident (« s'arrêter à la première erreur »)
    /// aurait tronqué un chemin nominal pour fermer l'autre. La coupe est déterministe : une fonction
    /// scalaire appelle `interrupt()` à la ligne choisie.
    #[test]
    fn le_parcours_distingue_la_fin_normale_de_l_interruption() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(v)").unwrap();
        for i in 0..200i64 {
            conn.execute("INSERT INTO t(v) VALUES (?1)", params![i]).unwrap();
        }
        let poser_coupe = |seuil: usize| {
            let h = conn.get_interrupt_handle();
            let vus = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            conn.create_scalar_function("tsb_coupe", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |_c| {
                if vus.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == seuil {
                    h.interrupt();
                }
                Ok(1i64)
            })
            .unwrap();
        };

        // ---- ① FIN NORMALE. L'instrument d'abord : le parcours voit-il bien toute la table ? ----
        poser_coupe(usize::MAX);
        let mut s = conn.prepare("SELECT v FROM t WHERE tsb_coupe(v)").unwrap();
        let complet = parcourir(s.query_map([], |r| r.get::<_, i64>(0)).unwrap());
        assert_eq!(complet.lignes.len(), 200, "instrument : sans coupe, le parcours doit tout rendre");
        assert!(complet.fin.cause().is_none(), "une fin normale ne porte AUCUNE cause : sinon l'aveu serait inconditionnel");

        // ---- ② INTERRUPTION DE `step()`. Les lignes lues restent lues, ET la coupe est DITE. ----
        poser_coupe(50);
        let mut s = conn.prepare("SELECT v FROM t WHERE tsb_coupe(v)").unwrap();
        let tronque = parcourir(s.query_map([], |r| r.get::<_, i64>(0)).unwrap());
        assert!(
            !tronque.lignes.is_empty() && tronque.lignes.len() < 200,
            "la coupe doit produire un PRÉFIXE STRICT, sinon le témoin ne prouve rien : {} lignes",
            tronque.lignes.len()
        );
        assert_eq!(
            tronque.lignes,
            complet.lignes[..tronque.lignes.len()].to_vec(),
            "ce qui est rendu est le DÉBUT de la réponse, aux mêmes valeurs : le parcours ne réordonne ni ne saute"
        );
        let cause = tronque.fin.cause().expect("préfixe rendu SANS cause : c'est exactement le défaut");
        assert!(cause.contains("interrupted"), "la cause vient du moteur : {cause}");
        assert_eq!(
            tronque.fin.erreurs(), 1,
            "UNE erreur solde ici un reste de cardinalité INCONNUE : ce compte n'est pas un déficit de lignes"
        );

        // ---- ③ ERREUR DU MAPPEUR. Le parcours CONTINUE (il ne troque pas une troncature contre une
        //      autre) et la ligne perdue cesse pourtant d'être perdue en silence. ----
        conn.execute_batch("CREATE TABLE u(v); INSERT INTO u VALUES (1),(2),('texte'),(4),(5)").unwrap();
        let mut s = conn.prepare("SELECT v FROM u").unwrap();
        let saute = parcourir(s.query_map([], |r| r.get::<_, i64>(0)).unwrap());
        assert_eq!(
            saute.lignes,
            vec![1i64, 2, 4, 5],
            "une erreur de mappeur ne doit PAS tarir le parcours : les lignes d'après sont rendues"
        );
        assert!(
            saute.fin.cause().is_some(),
            "la ligne sautée était perdue SANS UN MOT : elle doit désormais être avouée — {:?}",
            saute.lignes
        );
        assert_eq!(
            saute.fin.erreurs(), 1,
            "ici le compte VAUT une ligne sautée — même nombre que ci-dessus, sens opposé : seule la cause les sépare"
        );
    }
