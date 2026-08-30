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
    // CE QUE CES DEUX TÉMOINS NE TIENNENT PAS : ils ferment `/api/alerts`, et RIEN D'AUTRE. La suite
    // du fichier (2026-08-30, second lot) en ferme quatre de plus ; le reste des parcours atteignables
    // depuis un `read_with_watchdog` garde l'idiome muet, et le relevé par site est dans le rapport de
    // la clé. La garde de famille, elle, EXISTE depuis `P10.7-g` — cette phrase disait le contraire le
    // jour même où elle a été écrite.
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

    // ==============================================================================================
    // `P10.7-f` (SUITE, 2026-08-30) — LES PARCOURS QUI RESTAIENT MUETS SUR LES ROUTES LES PLUS EXPOSÉES.
    //
    // Les deux témoins ci-dessus ferment `/api/alerts` et prouvent le PARCOURS. Ceux qui suivent
    // ferment les trois autres routes qui balaient la table `alert` en entier, et le parcours en FLUX
    // qui a dû être écrit pour elles. Deux FORMES d'aveu se distinguent ici, et les confondre serait
    // avouer à faux :
    //
    //   · UNE LISTE TRONQUÉE — la réponse est un PRÉFIXE (groupes d'alertes, rapport de détection).
    //     L'aveu dit qu'il MANQUE des entrées, et qu'une entrée absente ne prouve rien.
    //   · UN COMPTE NON ÉTABLI — la liste servie n'est PAS raccourcie (la matrice ATT&CK parcourt le
    //     catalogue, le partage de fraîcheur rend toujours ses quatre nombres) mais les NOMBRES posés
    //     dessus sont trop BAS. Rien ne raccourcit, rien ne manque à l'œil : la somme a l'air juste et
    //     porte sur moins d'alertes qu'il n'y en a. C'est la forme la plus silencieuse des deux, et
    //     c'est pourquoi elle a sa propre phrase.
    //
    // CHAQUE TÉMOIN JOUE D'ABORD LE CHEMIN NOMINAL et exige qu'aucun aveu n'y paraisse — après avoir
    // vérifié que la lecture a bien rendu sa population entière, sans quoi « pas d'aveu » serait vrai
    // par vacuité. C'est la mutation qui compte : un corps qui avoue toujours n'avoue rien.
    // ==============================================================================================

    /// ③ LE PARCOURS EN FLUX — celui qu'il a fallu écrire, et pourquoi `parcourir` ne suffisait pas.
    ///
    /// `parcourir` est un remplaçant direct de `.flatten().collect()` : l'appelant voulait déjà le
    /// vecteur. Il n'en est PAS un pour `for x in rows.flatten() { … }`, qui consomme ligne à ligne et
    /// n'en garde aucune — y substituer `parcourir` matérialiserait toute la sélection avant la
    /// première itération, sur une base qui doit tenir dans 2 Go. Ce témoin tient les deux moitiés :
    /// le parcours dit sa coupe, ET il ne matérialise rien. La seconde est prouvée SANS chronomètre
    /// ni mesure de mémoire — un compteur placé DANS l'itérateur dit combien de lignes en sont sorties
    /// au moment où la première est traitée. S'il y avait matérialisation, ce nombre serait la table.
    #[test]
    fn un_parcours_en_flux_ne_materialise_rien_et_dit_sa_coupe() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(v)").unwrap();
        for i in 0..200i64 {
            conn.execute("INSERT INTO t(v) VALUES (?1)", params![i]).unwrap();
        }

        // ---- ① NOMINAL : mêmes lignes, même ordre, AUCUNE cause — et rien n'est matérialisé. ----
        let sorties = std::sync::Arc::new(AtomicUsize::new(0));
        let s2 = sorties.clone();
        let mut s = conn.prepare("SELECT v FROM t").unwrap();
        let it = s.query_map([], |r| r.get::<_, i64>(0)).unwrap().map(move |r| {
            s2.fetch_add(1, Ordering::SeqCst);
            r
        });
        let mut vues: Vec<i64> = Vec::new();
        let mut sorties_au_premier = usize::MAX;
        let fin = parcourir_chaque(it, |v: i64| {
            if vues.is_empty() {
                sorties_au_premier = sorties.load(Ordering::SeqCst);
            }
            vues.push(v);
        });
        assert_eq!(vues.len(), 200, "instrument : sans coupe, le parcours doit tout rendre");
        assert_eq!(vues, (0..200i64).collect::<Vec<_>>(), "mêmes lignes, même ordre que l'idiome précédent");
        assert!(fin.cause().is_none(), "une fin normale ne porte AUCUNE cause : sinon l'aveu serait inconditionnel");
        assert_eq!(
            sorties_au_premier, 1,
            "la PREMIÈRE ligne est traitée alors qu'UNE SEULE est sortie de l'itérateur : rien n'est \
             matérialisé. Une valeur de 200 dirait que le remède a chargé toute la sélection en \
             mémoire — ce qui, sur `alert WHERE status='new'`, est le défaut qu'on refuse de créer"
        );

        // ---- ② COUPE DÉTERMINISTE : le corps de boucle a bien tourné sur un PRÉFIXE, et la coupe est DITE. ----
        let h = conn.get_interrupt_handle();
        let vus = std::sync::Arc::new(AtomicUsize::new(0));
        conn.create_scalar_function("tsb_flux_coupe", 1, rusqlite::functions::FunctionFlags::SQLITE_UTF8, move |_c| {
            if vus.fetch_add(1, Ordering::SeqCst) == 50 {
                h.interrupt();
            }
            Ok(1i64)
        })
        .unwrap();
        let mut s = conn.prepare("SELECT v FROM t WHERE tsb_flux_coupe(v)").unwrap();
        let mut coupees: Vec<i64> = Vec::new();
        let fin = parcourir_chaque(s.query_map([], |r| r.get::<_, i64>(0)).unwrap(), |v: i64| coupees.push(v));
        assert!(
            !coupees.is_empty() && coupees.len() < 200,
            "la coupe doit produire un PRÉFIXE STRICT, sinon le témoin ne prouve rien : {} lignes",
            coupees.len()
        );
        assert_eq!(coupees, vues[..coupees.len()].to_vec(), "ce qui est traité est le DÉBUT de la réponse, aux mêmes valeurs");
        let cause = fin.cause().expect("préfixe traité SANS cause : c'est exactement le défaut");
        assert!(cause.contains("interrupted"), "la cause vient du moteur, jamais réécrite : {cause}");

        // ---- ③ ERREUR DE MAPPEUR : le corps de boucle CONTINUE (pas de troncature échangée), et la ligne
        //      sautée cesse d'être perdue en silence. ----
        conn.execute_batch("CREATE TABLE u(v); INSERT INTO u VALUES (1),(2),('texte'),(4),(5)").unwrap();
        let mut s = conn.prepare("SELECT v FROM u").unwrap();
        let mut lues: Vec<i64> = Vec::new();
        let fin = parcourir_chaque(s.query_map([], |r| r.get::<_, i64>(0)).unwrap(), |v: i64| lues.push(v));
        assert_eq!(lues, vec![1i64, 2, 4, 5], "une erreur de mappeur ne doit PAS tarir le parcours");
        assert!(fin.cause().is_some(), "la ligne sautée était perdue SANS UN MOT : elle doit être avouée");
        assert_eq!(fin.erreurs(), 1, "ici le compte VAUT une ligne sautée — c'est la CAUSE qui le sépare d'une interruption");
    }

    /// ④ FORME « LISTE TRONQUÉE », ROUTE `/api/alerts/groups` — le triage groupé.
    ///
    /// Cet énoncé agrège la table `alert` ENTIÈRE (GROUP BY + deux sous-requêtes corrélées, un seek
    /// par groupe) : c'est la lecture la plus lourde du démon après la page plate. Tronqué, il rendait
    /// des GROUPES ENTIERS en moins — et un triage mené dessus conclut « ce groupe n'existe pas » sur
    /// un groupe qui existe. Le `total` (COUNT DISTINCT séparé) reste un fait et rend l'écart lisible.
    #[test]
    fn une_liste_de_groupes_tronquee_ne_se_sert_plus_comme_complete() {
        const G: i64 = 40;
        let conn = test_db();
        for i in 0..G {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) \
                 VALUES(?1,?2,2,?3,'','new','T1046','')",
                params![1000 + i, format!("rule.{i}"), format!("A{i}")],
            )
            .unwrap();
        }
        let filtre = FiltreAlertes::default();

        // ---- ① NOMINAL. L'instrument d'abord. ----
        let (groupes, total, fin) = alert_groups_query_page(&conn, "rule", &filtre, 500, 0);
        assert_eq!(groupes.len() as i64, G, "instrument : un groupe par règle, tous dans la page");
        assert_eq!(total, Some(G), "instrument : le COUNT DISTINCT doit avoir abouti");
        assert!(fin.cause().is_none(), "un parcours complet ne doit porter AUCUNE cause");
        let corps_nominal = corps_de_liste_de_groupes(groupes, total, "rule", &fin);
        assert!(
            corps_nominal.get("error").is_none(),
            "un aveu posé sur le chemin NOMINAL : un corps qui avoue toujours n'avoue rien — {corps_nominal}"
        );

        // ---- ② L'ÉNONCÉ EST COUPÉ EN VOL. Rien d'autre ne change. ----
        // LA COUPE SE CHERCHE SUR UNE PROPRIÉTÉ OBSERVABLE — une liste STRICTEMENT plus courte que la
        // population, jamais sur la présence de la cause. Chercher la cause ferait REFUSER DE CONCLURE
        // le jour où un correctif la rejette, au lieu d'ACCUSER : le témoin passerait de « il manque un
        // aveu » à « je n'ai rien pu montrer », et c'est un canal de détection rétréci, pas un rouge.
        let mut coupe: Option<(Vec<Value>, Option<i64>, FinDeParcours)> = None;
        for tir in 1..4000usize {
            tsb_couper_au_tir(&conn, tir);
            let r = alert_groups_query_page(&conn, "rule", &filtre, 500, 0);
            tsb_ne_plus_couper(&conn);
            if r.1 == Some(G) && !r.0.is_empty() && (r.0.len() as i64) < G {
                coupe = Some(r);
                break;
            }
        }
        let (groupes, total, fin) = coupe.expect(
            "instrument : aucun tir n'a produit une liste de groupes TRONQUÉE avec un total établi — \
             le témoin REFUSE DE CONCLURE plutôt que de conclure sur une coupe qu'il n'a pas obtenue",
        );
        let servis = groupes.len();
        let cause = fin.cause().unwrap_or_else(|| panic!("liste tronquée rendue SANS cause : {servis} groupes sur {G}"));
        assert!(cause.contains("interrupted"), "la cause du MOTEUR est conservée telle qu'il l'a dite : {cause}");
        let corps = corps_de_liste_de_groupes(groupes, total, "rule", &fin);
        let aveu = corps["error"]
            .as_str()
            .unwrap_or_else(|| panic!("préfixe de groupes servi comme une page complète : {corps}"));
        assert!(aveu.starts_with(CAUSE_LISTE_DE_GROUPES_TRONQUEE), "l'aveu dit d'abord ce que le corps n'établit PAS : {aveu}");
        assert!(aveu.contains("interrupted"), "puis il laisse la cause du moteur : {aveu}");
        assert_eq!(
            corps["groups"].as_array().map(|a| a.len()), Some(servis),
            "l'aveu s'AJOUTE : il ne retire aucun des groupes réellement lus — {corps}"
        );
        assert_eq!(corps["total"], json!(G), "le COUNT DISTINCT a abouti : c'est lui qui rend l'écart lisible — {corps}");
    }

    /// ⑤ FORME « LISTE TRONQUÉE », ROUTE `/api/coverage/detections` — et ce qu'elle coûte VRAIMENT.
    ///
    /// Ce rapport est joint, côté Forge, aux techniques TIRÉES pour rendre `detected` / `missed`. Une
    /// technique absente de la liste s'y lit « non détectée » : un rapport tronqué ne rend pas une
    /// réponse plus courte, il FABRIQUE des faux `missed` sur des techniques que la détection a bel et
    /// bien vues. C'est le défaut exact que le filtre d'engagement de cette fonction a corrigé une
    /// fois — revenu par la troncature au lieu du filtre.
    #[test]
    fn un_rapport_de_couverture_tronque_ne_fabrique_plus_de_faux_manques() {
        const T: i64 = 40;
        let conn = test_db();
        let (ws, we) = (1000i64, 9000i64);
        conn.execute(
            "INSERT INTO engagement(id,name,box,scope,window_start,window_end,status) \
             VALUES('engT','n','blackbox','[\"198.51.100.0/24\"]',?1,?2,'active')",
            params![ws, we],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO event(ts,source,category,severity,message,src_ip,engagement_id) \
             VALUES(1400,'portscan','network',3,'scan','198.51.100.9','engT')",
            [],
        )
        .unwrap();
        for i in 0..T {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(?1,'rule.20',3,'scan',?2)",
                params![1500 + i, format!("T1{:03}", 100 + i)],
            )
            .unwrap();
        }

        // ---- ① NOMINAL. ----
        let (rapport, fin) = scoped_coverage_detections(&conn, "engT", 0, ws, we);
        assert_eq!(rapport.len() as i64, T, "instrument : chaque technique doit être présente, sinon « complet » ne veut rien dire");
        assert!(fin.cause().is_none(), "un parcours complet ne doit porter AUCUNE cause");
        let corps_nominal = corps_de_couverture_des_detections(rapport, None, &fin);
        assert!(
            corps_nominal.get("error").is_none(),
            "un aveu posé sur le chemin NOMINAL : un corps qui avoue toujours n'avoue rien — {corps_nominal}"
        );

        // ---- ② COUPE. ----
        let mut coupe: Option<(Vec<Value>, FinDeParcours)> = None;
        for tir in 1..4000usize {
            tsb_couper_au_tir(&conn, tir);
            let r = scoped_coverage_detections(&conn, "engT", 0, ws, we);
            tsb_ne_plus_couper(&conn);
            if !r.0.is_empty() && (r.0.len() as i64) < T {
                coupe = Some(r);
                break;
            }
        }
        let (rapport, fin) = coupe.expect(
            "instrument : aucun tir n'a produit un rapport TRONQUÉ non vide — le témoin REFUSE DE \
             CONCLURE plutôt que de conclure sur une coupe qu'il n'a pas obtenue",
        );
        let servies = rapport.len();
        assert!((servies as i64) < T, "le préfixe est STRICT : {servies} techniques sur {T}");
        let corps = corps_de_couverture_des_detections(rapport, None, &fin);
        let aveu = corps["error"]
            .as_str()
            .unwrap_or_else(|| panic!("rapport tronqué servi comme complet — les techniques manquantes deviennent des faux `missed` : {corps}"));
        assert!(aveu.starts_with(CAUSE_COUVERTURE_DES_DETECTIONS_TRONQUEE), "l'aveu dit d'abord ce que le rapport n'établit PAS : {aveu}");
        assert!(aveu.contains("interrupted"), "puis il laisse la cause du moteur : {aveu}");
        assert_eq!(
            corps["detections"].as_array().map(|a| a.len()), Some(servies),
            "l'aveu s'AJOUTE : il ne retire aucune des techniques réellement lues — {corps}"
        );
    }

    /// ⑥ FORME « COMPTE NON ÉTABLI », ROUTE `/api/coverage/attack` — la plus silencieuse des deux.
    ///
    /// Ici RIEN ne raccourcit : la matrice parcourt le catalogue ATT&CK, donc toutes les techniques
    /// restent servies quoi qu'il arrive. Ce que la coupe abîme, ce sont les `alerts` posés dessus —
    /// trop BAS, jamais trop hauts. Une technique qui a réellement tiré peut afficher `alerts: 0`,
    /// c'est-à-dire la valeur la plus rassurante, servie précisément quand la lecture n'a pas abouti.
    /// Le témoin exige donc DEUX choses qu'un aveu de liste ne dirait pas : que le compte servi soit
    /// STRICTEMENT inférieur au vrai, et que la COUVERTURE (qui vient des règles, pas de cette
    /// lecture) reste intacte — sans quoi l'aveu accuserait à faux.
    #[test]
    fn un_compte_d_alertes_par_technique_non_etabli_cesse_d_etre_un_zero() {
        const T: i64 = 40;
        let conn = test_db();
        for i in 0..T {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,mitre) VALUES(?1,'rule.20',3,'scan',?2)",
                params![1500 + i, format!("T1{:03}", 100 + i)],
            )
            .unwrap();
        }

        // ---- ① NOMINAL. ----
        let (comptes, fin) = lire_les_alertes_par_technique(&conn, 0);
        let vrai_total: i64 = comptes.values().sum();
        assert_eq!(vrai_total, T, "instrument : toutes les alertes doivent être comptées, sinon « complet » ne veut rien dire");
        assert!(fin.cause().is_none(), "un parcours complet ne doit porter AUCUNE cause");
        let matrice_nominale = corps_de_matrice_attack(build_attack_matrix(&[], &[], &comptes), &fin);
        assert!(
            matrice_nominale.get("error").is_none(),
            "un aveu posé sur le chemin NOMINAL : un corps qui avoue toujours n'avoue rien — {}",
            matrice_nominale["totals"]
        );

        // ---- ② COUPE. Le compte devient un SOUS-COMPTE, et la matrice garde exactement sa taille. ----
        let mut coupe: Option<(std::collections::HashMap<String, i64>, FinDeParcours)> = None;
        for tir in 1..4000usize {
            tsb_couper_au_tir(&conn, tir);
            let r = lire_les_alertes_par_technique(&conn, 0);
            tsb_ne_plus_couper(&conn);
            let somme: i64 = r.0.values().sum();
            if somme > 0 && somme < T {
                coupe = Some(r);
                break;
            }
        }
        let (comptes, fin) = coupe.expect(
            "instrument : aucun tir n'a produit un SOUS-COMPTE non nul — le témoin REFUSE DE CONCLURE \
             plutôt que de conclure sur une coupe qu'il n'a pas obtenue",
        );
        let sous_total: i64 = comptes.values().sum();
        assert!(sous_total < vrai_total, "le compte est STRICTEMENT trop bas : {sous_total} au lieu de {vrai_total}");
        let matrice = corps_de_matrice_attack(build_attack_matrix(&[], &[], &comptes), &fin);
        let aveu = matrice["error"]
            .as_str()
            .unwrap_or_else(|| panic!("sous-compte servi comme un compte : un `alerts: 0` s'y lit « rien n'a tiré » — {}", matrice["totals"]));
        assert!(aveu.starts_with(CAUSE_COMPTES_D_ALERTES_NON_ETABLIS), "l'aveu dit d'abord ce que la matrice n'établit PAS : {aveu}");
        assert!(aveu.contains("interrupted"), "puis il laisse la cause du moteur : {aveu}");
        // CE QUE L'AVEU NE DOIT PAS ACCUSER : la couverture, qui ne vient pas de cette lecture.
        assert_eq!(
            matrice["totals"]["techniques_covered"], matrice_nominale["totals"]["techniques_covered"],
            "la COUVERTURE vient des règles activées, pas de ce parcours : elle doit être INCHANGÉE, \
             sinon l'aveu ferait douter d'un nombre qui, lui, est établi"
        );
        assert_eq!(
            matrice["tactics"].as_array().map(|a| a.len()),
            matrice_nominale["tactics"].as_array().map(|a| a.len()),
            "aucune liste n'est raccourcie : c'est bien un COMPTE qui manque, pas une entrée — et c'est \
             pourquoi cette forme a sa propre phrase"
        );
    }

    /// ⑦ FORME « COMPTE NON ÉTABLI », ROUTE `/api/freshness` — LE PIRE SITE DE LA FAMILLE.
    ///
    /// Sa closure porte quinze énoncés et balaie les DEUX grandes tables. Le parcours mesuré ici lit
    /// `alert WHERE status='new'` EN ENTIER, sans borne de fenêtre, et alimente à la fois les quatre
    /// familles de `P11.3-d` — qui doivent se retrouver entre elles — et les cloches par source.
    /// Tronqué, il rend une somme qui a l'air juste et qui porte sur moins d'alertes qu'il n'y en a :
    /// `actives` lui-même est trop bas, donc AUCUNE vérification interne ne peut le trahir.
    ///
    /// LE TÉMOIN TIENT AUSSI LA MESURE QUI GOUVERNE LA FORME : une interruption ne porte que sur
    /// l'énoncé EN VOL. Le relevé nomme donc CE parcours-là, et un relevé où seul un autre a été coupé
    /// ne doit PAS accuser celui-ci.
    #[test]
    fn le_partage_des_alertes_actives_tronque_cesse_de_passer_pour_le_tout() {
        const A: i64 = 40;
        let conn = test_db();
        for i in 0..A {
            conn.execute(
                "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,sources) \
                 VALUES(?1,'rule.1',2,?2,'','new','T1046',?3)",
                params![1000 + i, format!("A{i}"), format!("src{i}")],
            )
            .unwrap();
        }

        // ---- ① NOMINAL. ----
        let (imp, fin) = lire_l_imputation_des_alertes(&conn, "");
        assert_eq!(imp.actives, A, "instrument : toutes les alertes actives doivent être vues");
        assert_eq!(
            imp.avec_cloche + imp.sans_source_nommee + imp.sans_imputation, imp.actives,
            "instrument : les quatre nombres se retrouvent — c'est ce qui les rend vérifiables"
        );
        assert!(fin.cause().is_none(), "un parcours complet ne doit porter AUCUNE cause");
        let mut releve = ParcoursDeFraicheur::default();
        releve.noter("le partage des alertes actives", &fin);
        assert!(
            releve.aveu().is_none() && releve.cause_de_l_imputation().is_none(),
            "un aveu posé sur le chemin NOMINAL : un relevé qui avoue toujours n'avoue rien"
        );

        // ---- ② COUPE. ----
        let mut coupe: Option<(ImputationDesAlertes, FinDeParcours)> = None;
        for tir in 1..4000usize {
            tsb_couper_au_tir(&conn, tir);
            let r = lire_l_imputation_des_alertes(&conn, "");
            tsb_ne_plus_couper(&conn);
            if r.0.actives > 0 && r.0.actives < A {
                coupe = Some(r);
                break;
            }
        }
        let (imp, fin) = coupe.expect(
            "instrument : aucun tir n'a produit un partage TRONQUÉ non vide — le témoin REFUSE DE \
             CONCLURE plutôt que de conclure sur une coupe qu'il n'a pas obtenue",
        );
        assert!(imp.actives < A, "le compte est STRICTEMENT trop bas : {} actives sur {A}", imp.actives);
        assert_eq!(
            imp.avec_cloche + imp.sans_source_nommee + imp.sans_imputation, imp.actives,
            "LA SOMME A TOUJOURS L'AIR JUSTE : c'est précisément pourquoi rien, dans le corps servi, ne \
             pouvait trahir la coupe — et pourquoi l'aveu est le seul moyen de la dire"
        );
        let mut releve = ParcoursDeFraicheur::default();
        releve.noter("le partage des alertes actives", &fin);
        let cause = releve.cause_de_l_imputation().expect("partage tronqué rendu SANS cause : c'est le défaut");
        assert!(cause.contains("interrupted"), "la cause vient du moteur, jamais réécrite : {cause}");
        let aveu = releve.aveu().expect("le relevé doit porter une phrase de racine dès qu'un parcours a été coupé");
        assert!(aveu.starts_with(CAUSE_FRAICHEUR_INCOMPLETE), "l'aveu dit d'abord ce que le relevé n'établit PAS : {aveu}");
        assert!(aveu.contains("le partage des alertes actives"), "et il NOMME le parcours coupé : {aveu}");

        // ---- ③ L'INTERRUPTION NE PORTE QUE SUR L'ÉNONCÉ EN VOL : un AUTRE parcours coupé ne doit pas
        //      accuser celui-ci. Sans cette séparation, la console lirait « les alertes sont
        //      sous-comptées » chaque fois qu'un flux de métriques a été coupé. ----
        let mut voisin = ParcoursDeFraicheur::default();
        voisin.noter("les séries de métriques", &FinDeParcours::Interrompu { erreurs: 1, cause: "interrupted".into() });
        assert!(
            voisin.cause_de_l_imputation().is_none(),
            "un parcours VOISIN coupé ne doit pas faire avouer le partage des alertes : l'aveu serait FAUX"
        );
        assert!(
            voisin.aveu().is_some_and(|p| p.contains("les séries de métriques")),
            "la phrase de racine nomme ce qui est réellement incomplet, et rien d'autre"
        );
    }
