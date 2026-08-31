    // ================================================================================================
    // UN ANCRAGE QUI MENT — `P10.7-u`, mesuré le 2026-08-31.
    //
    // LE DÉFAUT, ET C'EST LA MOITIÉ QUI MANQUAIT À `P10.7-t`. Le lot précédent a fermé l'ÉCRITURE : le
    // démon ne peut plus SIGNER un point de contrôle attestant une valeur qu'il n'a pas lue. Il n'a rien
    // fermé du côté LECTURE : le vérificateur contrôlait la SIGNATURE d'un point de contrôle, jamais la
    // CONCORDANCE entre ce qu'il atteste et la chaîne qu'il ancre.
    //
    // LES DEUX MESURES FONDATRICES, COPIES VERBATIM DE `verify_ledger_conn` AVANT CE LOT — trois maillons
    // écrits par le VRAI chemin (`ledger_append`), un point de contrôle posé par ÉCRITURE SQL DIRECTE et
    // CORRECTEMENT SIGNÉ :
    //   · attestant `genesis` (ce que la panne de `P10.7-t` laissait derrière elle) ... `Ok((3, 1, 0, None))`
    //   · attestant une valeur FABRIQUÉE ..................................................... `Ok((3, 1, 0, None))`
    // Dans les DEUX cas : « UNE SIGNATURE COMPTÉE VALIDE », `plume-daemon verify` imprimant
    // « ledger OK … OK=1 KO=0 » et sortant en 0. Le mensonge est PERMANENT — il survit à la résorption de
    // la panne — et INDISCERNABLE d'un point de contrôle légitime.
    //
    // ET LA TROISIÈME MESURE EST CELLE QUI A DÉCIDÉ DE LA FORME DU REMÈDE, PAS DE SON EXISTENCE. Un point
    // de contrôle atteste LA TÊTE D'ALORS, pas la tête ACTUELLE (mesuré : trois ancrages successifs
    // occupent les positions 0, 1 et 2 de la chaîne). Comparer à la tête COURANTE accuse donc
    // **2 points de contrôle légitimes sur 3** sur un journal parfaitement sain. La vérification est un
    // RATTACHEMENT à la chaîne, jamais une égalité — et (U1) épingle ce chiffre-là pour que le jour où
    // quelqu'un « simplifie » en égalité, le rouge dise POURQUOI.
    //
    // AUCUN TÉMOIN CHRONOMÉTRIQUE : les deux horodatages qui décident sont des DONNÉES passées en
    // argument à une fonction PURE (U2), jamais une durée mesurée. Le répertoire temporaire de ce poste
    // est en mémoire : une mesure de durée y serait verte par construction.
    //
    // AUCUN TÉMOIN N'EST ADOSSÉ À UN DÉFAUT VIVANT : chacun asserte l'état CORRIGÉ et NOMME dans son
    // message la réponse que l'arbre rendait avant.
    // ================================================================================================

    /// La clé qui SIGNE dans cette section (déterministe : jamais un fichier, jamais l'environnement).
    fn anc_cle() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[11u8; 32])
    }

    /// Un journal ET des points de contrôle réellement VIERGES : `test_db()` fait tourner la chaîne de
    /// migrations. Pour mesurer une ORIGINE il faut des tables vides, pas « presque vides ».
    fn anc_journal_vierge() -> Connection {
        let conn = test_db();
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle vidés");
        conn
    }

    /// LE GESTE ADVERSE, ET C'EST CELUI QUE L'ÉNONCÉ EXIGE DE COUVRIR : poser un point de contrôle par
    /// ÉCRITURE SQL DIRECTE, **correctement signé** sur la valeur qu'on lui fait attester. C'est à la
    /// fois ce qu'une base ayant connu `P10.7-t` porte DÉJÀ (le démon ne peut plus l'écrire, mais il ne
    /// l'efface pas) et ce qu'un adversaire disposant de la clé de signature poserait.
    fn anc_poser_un_point_de_controle(conn: &Connection, ts: i64, atteste: &str) {
        use ed25519_dalek::Signer;
        let k = anc_cle();
        let sig = k.sign(atteste.as_bytes());
        let n = conn
            .execute(
                "INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4)",
                params![ts, atteste, hex_encode(&sig.to_bytes()), hex_encode(k.verifying_key().as_bytes())],
            )
            .expect("point de contrôle posé");
        assert_eq!(n, 1, "fixture : exactement UN point de contrôle posé");
    }

    fn anc_tete(conn: &Connection) -> String {
        conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("tête lisible")
    }

    fn anc_attestations(conn: &Connection) -> Vec<String> {
        let mut s = conn.prepare("SELECT ledger_hash FROM checkpoint ORDER BY id").expect("points listables");
        let v = s.query_map([], |r| r.get::<_, String>(0)).expect("scan").map(|x| x.expect("attestation")).collect();
        v
    }

    fn anc_compte(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).expect("table comptable")
    }

    // ------------------------------------------------------------------------------------------------

    /// (U1) TÉMOIN NÉGATIF DE TOUTE LA SECTION — UN JOURNAL SAIN, ANCRÉ AU RYTHME DE LA PRODUCTION,
    /// RESTE INTÈGRE ET MUET.
    ///
    /// LE RYTHME EST CELUI DES DEUX VOIES RÉELLES (`rollups::retention_run` horaire, `server` au boot) :
    /// on ancre, la chaîne CONTINUE de s'écrire, on ancre de nouveau. Les trois points de contrôle
    /// attestent donc TROIS TÊTES DIFFÉRENTES, dont deux ne sont plus la tête à la fin.
    ///
    /// ET C'EST CE QUE CE TÉMOIN MESURE, PAS SEULEMENT CE QU'IL ASSERTE : il RECALCULE ce qu'une
    /// comparaison naïve à la tête ACTUELLE aurait accusé, et exige que ce nombre soit **2**. Sans cette
    /// assertion-là, un jour où la fixture dégénérerait en un seul point de contrôle, le témoin serait
    /// vert par vacuité — il ne distinguerait plus un rattachement d'une égalité.
    #[test]
    fn un_journal_sain_ancre_trois_fois_reste_integre_et_muet() {
        let conn = anc_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
            sign_checkpoint(&conn, &anc_cle());
        }
        assert_eq!(anc_compte(&conn, "checkpoint"), 3, "fixture : le vrai chemin a posé TROIS ancrages");

        let attestations = anc_attestations(&conn);
        let tete_actuelle = anc_tete(&conn);
        let accuses_par_une_egalite = attestations.iter().filter(|h| *h != &tete_actuelle).count();
        assert_eq!(
            accuses_par_une_egalite, 2,
            "CONTRÔLE POSITIF de la fixture : deux des trois ancrages LÉGITIMES n'attestent plus la tête \
             actuelle. C'est exactement ce qu'une comparaison naïve accuserait — et ce que ce témoin \
             exige de ne PAS voir accusé : {attestations:?}"
        );

        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None).expect(
            "un journal SAIN se conclut : une fausse accusation sur un instrument d'intégrité est pire \
             que l'angle mort qu'elle comble",
        );
        assert_eq!((n, sig_ok, sig_ko, rupture), (3, 3, 0, None), "trois maillons, trois signatures OK, aucune rupture");
    }

    /// (U2) LA FRONTIÈRE DE LA LOI D'ORIGINE, ÉPROUVÉE SUR LE CŒUR PUR ET DANS LES DEUX SENS.
    ///
    /// POURQUOI SUR LA FONCTION PURE, ET PAS SUR UNE BASE : le cas qui décide est « le maillon et
    /// l'ancrage d'origine tombent dans la MÊME seconde ». `now()` est en secondes, donc le reproduire
    /// par le vrai chemin serait un pari sur l'horloge — un témoin chronométrique, vert ou rouge selon
    /// la charge. `attestation_discordante` prend les deux horodatages en ARGUMENT : le cas se FABRIQUE,
    /// il ne se guette pas.
    ///
    /// LES DEUX SENS, ET C'EST L'INÉGALITÉ STRICTE QUI LES SÉPARE :
    ///  · maillon à la MÊME seconde que l'ancrage d'origine -> MUET (un `<=` accuserait ici, et il
    ///    accuserait toute base neuve dont le tick d'ancrage et la première mutation de config tombent
    ///    dans la même seconde) ;
    ///  · maillon STRICTEMENT antérieur -> ACCUSÉ (c'est la loi qui rattrape rétroactivement `P10.7-t`).
    /// Plus la frontière basse : sur un journal réellement VIDE, l'origine est toujours concordante.
    #[test]
    fn l_origine_est_concordante_a_la_meme_seconde_et_discordante_apres_un_maillon_anterieur() {
        let h = sha256_hex(b"un maillon quelconque");
        let origine = vec![(100i64, ATTESTATION_ORIGINE.to_string())];

        assert_eq!(
            attestation_discordante(&[], &origine),
            None,
            "chaîne VIDE : l'origine est la seule attestation possible — refuser ici priverait toute base neuve d'ancrage"
        );
        assert_eq!(
            attestation_discordante(&[(100, h.clone())], &origine),
            None,
            "MÊME seconde : l'ancrage d'origine a pu précéder le maillon — un `<=` accuserait ce journal sain"
        );
        let accuse = attestation_discordante(&[(99, h.clone())], &origine)
            .expect("maillon STRICTEMENT antérieur : l'ancrage d'origine ne concorde avec AUCUN état de cette chaîne");
        assert!(accuse.contains("ORIGINE"), "le refus nomme ce qui est attesté : {accuse}");
        assert!(accuse.contains("AUCUN verdict"), "et il dit qu'aucun verdict n'est rendu : {accuse}");

        // Et l'attestation qui SE RATTACHE reste muette, quelle que soit la date : c'est le rattachement
        // qui décide, jamais la fraîcheur.
        assert_eq!(
            attestation_discordante(&[(99, h.clone()), (99, sha256_hex(b"un autre"))], &[(100, h)]),
            None,
            "un ancrage sur un maillon qui n'est PLUS la tête reste concordant : la tête d'alors, pas la tête actuelle"
        );
    }

    /// (U3) L'ÉPISODE `P10.7-t` REJOUÉ EN ENTIER — ET C'EST LE RATTRAPAGE RÉTROACTIF.
    ///
    /// LE SCÉNARIO EST CELUI DE LA PRODUCTION, ET IL A TROIS TEMPS : la tête devient illisible (colonne
    /// d'un type inattendu après une restauration partielle, verrou) ; l'arbre d'AVANT écrivait alors un
    /// point de contrôle SIGNÉ attestant l'ORIGINE ; puis la panne se résorbe — et le mensonge, lui, ne
    /// se résorbe pas. `sign_checkpoint` REFUSE désormais d'écrire cette ligne (c'est `P10.7-t`, témoin
    /// à côté), mais **aucun rattrapage rétroactif n'existe** : une base qui a connu l'épisode la porte
    /// TOUJOURS. On la pose donc ici comme la base la porte, par écriture SQL directe et correctement
    /// signée, et c'est ce que le vérificateur doit voir.
    ///
    /// L'ANCIENNE RÉPONSE EST NOMMÉE DANS L'ASSERTION : `Ok((3, 1, 0, None))` — trois maillons intègres,
    /// UNE SIGNATURE COMPTÉE VALIDE, donc « ledger OK … OK=1 KO=0 » et une sortie 0.
    #[test]
    fn un_ancrage_d_origine_survivant_a_la_panne_cesse_d_etre_compte_valide() {
        let conn = anc_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let id_tete: i64 = conn
            .query_row("SELECT id FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("tête identifiable");
        let vraie_tete = anc_tete(&conn);

        // TEMPS 1 — la tête devient illisible (la LIGNE reste : illisible, pas absente) et le geste de
        // production REFUSE d'écrire. C'est `P10.7-t`, et c'est l'état de départ de ce témoin.
        conn.execute("UPDATE ledger SET hash=X'FF' WHERE id=?1", params![id_tete]).expect("tête abîmée");
        sign_checkpoint(&conn, &anc_cle());
        assert_eq!(anc_compte(&conn, "checkpoint"), 0, "état de départ : le démon d'aujourd'hui n'écrit PLUS ce mensonge");

        // TEMPS 2 — ce que la base porte DÉJÀ si elle a connu l'épisode avant le correctif.
        anc_poser_un_point_de_controle(&conn, now() + 5, ATTESTATION_ORIGINE);

        // TEMPS 3 — la panne se résorbe. Le mensonge, lui, reste.
        conn.execute("UPDATE ledger SET hash=?1 WHERE id=?2", params![vraie_tete, id_tete]).expect("panne résorbée");
        assert_eq!(anc_compte(&conn, "ledger"), 3, "le journal porte toujours ses trois maillons");

        let message = verify_ledger_conn(&conn, None)
            .map(|v| format!("{v:?}"))
            .expect_err(
                "un ancrage d'origine sur une chaîne qui portait déjà des maillons ne se conclut pas — \
                 l'ancienne réponse était Ok((3, 1, 0, None)), soit UNE SIGNATURE COMPTÉE VALIDE",
            );
        assert!(message.contains("ORIGINE"), "le refus NOMME ce qui est attesté : {message}");
        assert!(message.contains("AUCUN verdict"), "et il dit qu'aucun verdict n'est rendu : {message}");
    }

    /// (U4) L'ÉCRITURE SQL DIRECTE — UNE TÊTE FABRIQUÉE, CORRECTEMENT SIGNÉE.
    ///
    /// L'ÉNONCÉ EXIGEAIT QUE LE LOT NE SE CONTENTE PAS D'EMPÊCHER : ce point de contrôle-là, le démon ne
    /// l'écrira jamais, et il ne vient d'aucune panne. Il vient d'une main sur la base, avec la clé de
    /// signature. Ancienne réponse, MESURÉE : `Ok((3, 1, 0, None))` — la signature donnait à une valeur
    /// arbitraire exactement l'autorité qu'elle ne mérite pas.
    ///
    /// LES DEUX SENS SONT DANS LE MÊME TÉMOIN, et c'est ce qui le sépare d'un refus inconditionnel : la
    /// MÊME écriture directe, avec la MÊME clé, attestant la VRAIE tête, est ACCEPTÉE et comptée OK.
    ///
    /// TROISIÈME ASSERTION, D'HYGIÈNE : une attestation forgée n'a aucune longueur imposée. Le refus est
    /// BORNÉ — il n'imprime pas dans un flux d'exploitation les cinq mille caractères qu'on lui donne.
    #[test]
    fn une_tete_fabriquee_et_signee_est_refusee_la_vraie_tete_signee_est_acceptee() {
        let conn = anc_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }

        // SENS 1 — la VRAIE tête, posée par la même écriture directe et la même clé : ACCEPTÉE.
        anc_poser_un_point_de_controle(&conn, now(), &anc_tete(&conn));
        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None)
            .expect("une attestation qui SE RATTACHE est concordante, d'où qu'elle vienne");
        assert_eq!((n, sig_ok, sig_ko, rupture), (3, 1, 0, None), "l'instrument n'est pas un refus inconditionnel");

        // SENS 2 — une valeur FABRIQUÉE, tout aussi bien signée : REFUSÉE.
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle remis à zéro");
        anc_poser_un_point_de_controle(&conn, now(), &sha256_hex(b"une tete qui n'a jamais existe"));
        let message = verify_ledger_conn(&conn, None)
            .map(|v| format!("{v:?}"))
            .expect_err("une tête fabriquée ne se conclut pas — l'ancienne réponse était Ok((3, 1, 0, None))");
        assert!(message.contains("AUCUNE entrée de ce journal"), "le refus NOMME le défaut de rattachement : {message}");
        assert!(message.contains("AUCUN verdict"), "et il dit qu'aucun verdict n'est rendu : {message}");

        // SENS 3 — le refus est BORNÉ : une attestation de 5000 caractères ne se déverse pas dans le flux.
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle remis à zéro");
        anc_poser_un_point_de_controle(&conn, now(), &"Z".repeat(5000));
        let long = verify_ledger_conn(&conn, None).map(|v| format!("{v:?}")).expect_err("refusée elle aussi");
        assert!(long.len() < 400, "l'aveu reste borné ({} octets) : une attestation forgée n'a pas de longueur imposée", long.len());
    }

    /// (U5) L'ATTESTATION VIDE — UN ANCRAGE QUI NE NOMME AUCUN ÉTAT DE CETTE CHAÎNE.
    ///
    /// CE TÉMOIN A DÉPLACÉ UNE FRONTIÈRE ÉCRITE LA VEILLE, ET C'EST ÉCRIT PLUTÔT QUE TU. `P10.7-q` avait
    /// posé la loi « `Err` est réservé à ce que la LECTURE ne rend pas ; un NULL se LIT et vaut un
    /// verdict », et son témoin (D4) l'épinglait sur un point de contrôle dont les TROIS colonnes de
    /// contenu sont NULL. Cette loi-là est INTACTE : elle porte sur la LISIBILITÉ. `P10.7-u` en ajoute
    /// une SECONDE, orthogonale — une attestation doit se RATTACHER à la chaîne — et un `ledger_hash`
    /// NULL n'en nomme aucune. (D4) a donc été RESSERRÉ sur ce qu'il affirme vraiment (« un point de
    /// contrôle SANS SIGNATURE est compté KO ») : son `ledger_hash` est désormais concordant, ses deux
    /// colonnes de signature restent NULL, et son verdict `(0, 1)` est inchangé.
    ///
    /// POURQUOI NE PAS AVOIR EXEMPTÉ LE VIDE, ce qui aurait laissé (D4) intact : une signature Ed25519
    /// sur la chaîne VIDE est parfaitement calculable. Un adversaire tenant la clé aurait remplacé tous
    /// les ancrages par des attestations vides et valides -> `sig_ok = N, sig_ko = 0`, « ledger OK », une
    /// sortie 0. L'exemption aurait fabriqué exactement le trou que ce lot ferme.
    #[test]
    fn une_attestation_vide_est_refusee_et_une_signature_absente_reste_un_verdict() {
        let conn = anc_journal_vierge();
        for i in 0..2 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }

        // SENS 1 — LA FRONTIÈRE DE `P10.7-q`, TENUE : les deux colonnes de SIGNATURE nulles, l'attestation
        // concordante -> la ligne se LIT, elle est comptée KO, et AUCUN refus.
        conn.execute(
            "INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,?2,NULL,NULL)",
            params![now(), anc_tete(&conn)],
        )
        .expect("point de contrôle sans signature inséré");
        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None)
            .expect("un NULL de SIGNATURE se LIT : il ne refuse rien");
        assert_eq!((n, sig_ok, sig_ko, rupture), (2, 0, 1, None), "sans signature = compté KO, ni escamoté ni refusé");

        // SENS 2 — L'ATTESTATION elle-même nulle : elle se lit tout aussi bien, mais elle ne nomme AUCUN
        // état de cette chaîne. Ancienne réponse : comptée `sig_ko`, donc « ledger OK … KO=1 » et sortie 0.
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle remis à zéro");
        conn.execute("INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,NULL,NULL,NULL)", params![now()])
            .expect("point de contrôle sans attestation inséré");
        let message = verify_ledger_conn(&conn, None)
            .map(|v| format!("{v:?}"))
            .expect_err("une attestation VIDE ne se rattache à rien — l'ancienne réponse était Ok((2, 0, 1, None))");
        assert!(message.contains("attestation VIDE"), "le refus NOMME le vide au lieu de n'imprimer rien : {message}");
    }

    /// (U6) LA VRAIE ACCUSATION SURVIT AU NOUVEAU REFUS — ET ELLE EST TESTÉE LÀ OÙ ELLE POUVAIT MOURIR.
    ///
    /// « Un correctif qui ferme une fausse accusation peut faire TAIRE une vraie : il ne casse rien, ne
    /// fait rougir personne, et RÉTRÉCIT le canal de détection. Le signal d'alerte est un verdict qui
    /// passe d'ACCUSE à REFUSE DE CONCLURE. » Ce témoin est ce signal-là, et sa fixture est choisie pour
    /// que les deux verdicts se DISPUTENT la même ligne : on réécrit le `hash` de la tête par un autre
    /// hexadécimal valide. La chaîne est alors ROMPUE à ce maillon **et** le point de contrôle
    /// légitime, qui attestait l'ancien `hash`, ne se rattache plus à rien.
    ///
    /// LE VERDICT ATTENDU EST LA RUPTURE NOMMÉE, PAS LE REFUS : `Ok((3, 1, 0, Some(id)))`. C'est le
    /// verdict le plus fort que cet instrument sache rendre — une compromission NOMMÉE, sortie 1 — et
    /// aucun contrôle de concordance ne doit le convertir en « aucun verdict », sortie 2. Retirer la
    /// garde `if broken.is_none()` fait rougir CE témoin et lui seul.
    #[test]
    fn une_rupture_reelle_reste_nommee_et_ne_devient_pas_un_refus_de_concordance() {
        let conn = anc_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        sign_checkpoint(&conn, &anc_cle());
        let id_tete: i64 = conn
            .query_row("SELECT id FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("tête identifiable");

        // SENS 1 — la MÊME connexion, avant qu'on touche à quoi que ce soit : elle conclut, et OK.
        let (n, sig_ok, _, rupture) = verify_ledger_conn(&conn, None).expect("chaîne saine");
        assert_eq!((n, sig_ok, rupture), (3, 1, None), "état de départ : trois maillons, un ancrage valide");

        // SENS 2 — LA FALSIFICATION, LISIBLE : un autre hexadécimal, parfaitement convertible.
        let autre = sha256_hex(b"un hachage substitue apres coup");
        conn.execute("UPDATE ledger SET hash=?1 WHERE id=?2", params![autre, id_tete]).expect("tête réécrite");
        assert_ne!(
            anc_attestations(&conn)[0],
            autre,
            "fixture : l'ancrage n'atteste plus AUCUN maillon — les deux verdicts se disputent bien cette ligne"
        );

        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None)
            .expect("une falsification LISIBLE se CONCLUT : elle ne devient pas un refus de concordance");
        assert_eq!(rupture, Some(id_tete), "la rupture est NOMMÉE — c'est la sortie 1, la compromission, pas la sortie 2");
        assert_eq!((n, sig_ok, sig_ko), (3, 1, 0), "et le compte rendu reste celui des lignes LUES, toutes lues");
    }
