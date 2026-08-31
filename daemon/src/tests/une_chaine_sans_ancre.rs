    // ================================================================================================
    // UNE CHAÎNE SANS ANCRE — `P10.7-v`, mesuré le 2026-08-31.
    //
    // LES DEUX MESURES FONDATRICES, PRISES AVEC LE VRAI BINAIRE (`plume-daemon verify`) SUR DES BASES
    // FICHIER CONSTRUITES PAR LE VRAI CHEMIN D'ÉCRITURE :
    //   · journal de trois maillons étalés sur 30 jours, TOUS les points de contrôle effacés
    //     .......... « ledger OK : 3 entrées chaînées intègres ; checkpoints signés OK=0 KO=0 » — exit 0
    //   · journal de trois maillons nés dans la même seconde, jamais ancré (cas LÉGITIME)
    //     .......... « ledger OK : 3 entrées chaînées intègres ; checkpoints signés OK=0 KO=0 » — exit 0
    // Les deux lignes sont IDENTIQUES au caractère près. L'instrument ne séparait pas « rien à
    // vérifier » de « tout a été effacé », et le second cas est celui qu'on n'a PAS le droit d'accuser.
    //
    // LA QUESTION A DÉCIDÉ DE LA FORME AVANT LE CODE : la grandeur qui sépare les deux n'est pas
    // « y a-t-il des ancres » (les deux en ont zéro) mais DEPUIS COMBIEN DE TEMPS il n'y en a pas. Elle
    // se lit dans le schéma existant — `ledger.ts` et `checkpoint.ts` sont tous deux `INTEGER NOT
    // NULL` — et se compare à une CADENCE lue dans le code, pas choisie ici. AUCUNE MIGRATION.
    //
    // AUCUN TÉMOIN CHRONOMÉTRIQUE : la frontière qui décide est éprouvée sur le cœur PUR, à qui les
    // trois horodatages sont PASSÉS. Les témoins de bout en bout, eux, fabriquent l'ÂGE DE LA DONNÉE
    // (des maillons datés), jamais une durée guettée sur une horloge.
    //
    // AUCUN TÉMOIN N'EST ADOSSÉ À UN DÉFAUT VIVANT : chacun asserte l'état CORRIGÉ et nomme dans son
    // message ce que l'arbre rendait avant.
    // ================================================================================================

    /// La clé qui SIGNE dans cette section (déterministe : jamais un fichier, jamais l'environnement).
    fn sa_cle() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[23u8; 32])
    }

    /// Une base FICHIER au schéma réel, journal ET points de contrôle réellement VIDES (la chaîne de
    /// migrations écrit des maillons : pour mesurer un âge il faut partir de rien).
    fn sa_base(etiquette: &str) -> (crate::tmp_possede::TmpDb, Connection) {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = Connection::open(coffre.as_str()).expect("base fichier ouverte");
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle vidés");
        (coffre, conn)
    }

    /// UN MAILLON DATÉ, chaîné par la MÊME formule que `ledger_append` — qui, lui, lit l'horloge et ne
    /// permettrait donc pas de fabriquer un âge. Le `prev_hash` est pris par `ledger_prev_hash` : la
    /// chaîne produite est celle que le vérificateur RECALCULE, sans rupture fabriquée.
    fn sa_maillon_date(conn: &Connection, ts: i64, detail: &str) {
        let prev = ledger_prev_hash(conn).expect("tête lisible");
        let hash = sha256_hex(format!("{prev}|{ts}|config.mode|{detail}").as_bytes());
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)",
            params![ts, "config.mode", detail, prev, hash],
        )
        .expect("maillon daté");
    }

    /// UN POINT DE CONTRÔLE DATÉ, attestant la TÊTE RÉELLE et CORRECTEMENT SIGNÉ — c'est-à-dire un
    /// ancrage que `P10.7-u` accepte : ce témoin mesure l'ÂGE de l'ancrage, jamais sa concordance.
    fn sa_ancrer_a(conn: &Connection, ts: i64) {
        use ed25519_dalek::Signer;
        let k = sa_cle();
        let tete = match ledger_prev_hash(conn).expect("tête lisible") {
            t if t.is_empty() => ATTESTATION_ORIGINE.to_string(),
            t => t,
        };
        let sig = k.sign(tete.as_bytes());
        conn.execute(
            "INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4)",
            params![ts, tete, hex_encode(&sig.to_bytes()), hex_encode(k.verifying_key().as_bytes())],
        )
        .expect("point de contrôle daté");
    }

    fn sa_compte(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).expect("table comptable")
    }

    // ------------------------------------------------------------------------------------------------

    /// (V1) LA FRONTIÈRE DE LA LOI, ÉPROUVÉE SUR LE CŒUR PUR ET DANS LES DEUX SENS — AUCUNE HORLOGE.
    ///
    /// POURQUOI SUR LA FONCTION PURE : le cas qui décide est « l'attente vaut EXACTEMENT la tolérance ».
    /// Le reproduire en guettant une horloge est impossible à la seconde près, et le répertoire
    /// temporaire de ce poste est en mémoire — une mesure de durée y serait verte par construction. Les
    /// trois horodatages sont donc des DONNÉES.
    ///
    /// L'INÉGALITÉ EST STRICTE : une attente égale à deux cadences est encore ce qu'un ordonnancement à
    /// la seconde près produit. On n'accuse qu'au-DELÀ, et le témoin épingle les deux côtés.
    #[test]
    fn la_frontiere_de_la_tolerance_d_ancrage_est_stricte_et_tient_des_deux_cotes() {
        let t0 = 1_000_000i64;

        // ---- ① EXACTEMENT la tolérance : MUET. ----
        assert_eq!(
            ancrage_en_retard(t0 + TOLERANCE_D_ANCRAGE_S, Some(t0), Some(t0)),
            None,
            "une attente ÉGALE à la tolérance ({TOLERANCE_D_ANCRAGE_S} s) reste dans ce qu'un \
             ordonnancement sain produit : accuser ici, c'est accuser une instance saine"
        );

        // ---- ② UNE SECONDE DE PLUS : la loi mord, et elle NOMME la durée. ----
        let retard = ancrage_en_retard(t0 + TOLERANCE_D_ANCRAGE_S + 1, Some(t0), Some(t0))
            .expect("une seconde AU-DELÀ de la tolérance : c'est la valeur qui bascule le verdict");
        assert_eq!(
            retard,
            AncrageEnRetard { depuis: t0, secondes: TOLERANCE_D_ANCRAGE_S + 1, jamais_ancree: false },
            "le verdict porte la DURÉE et l'instant depuis lequel la chaîne est sans ancre"
        );

        // ---- ③ LE JOURNAL JEUNE — aucune ancre, mais né il y a une minute : MUET. ----
        assert_eq!(
            ancrage_en_retard(t0 + 60, Some(t0), None),
            None,
            "un journal JEUNE n'a légitimement AUCUN point de contrôle : le tick d'ancrage n'est pas \
             encore passé. L'accuser serait pire que l'angle mort que ce lot comble"
        );

        // ---- ④ LE MÊME JOURNAL, VINGT JOURS PLUS TARD, TOUJOURS SANS ANCRE : accusé, et `jamais`. ----
        let vingt_jours = 20 * 86_400i64;
        let retard = ancrage_en_retard(t0 + vingt_jours, Some(t0), None)
            .expect("vingt jours sans le moindre ancrage : ce n'est plus un journal jeune");
        assert_eq!(
            retard,
            AncrageEnRetard { depuis: t0, secondes: vingt_jours, jamais_ancree: true },
            "sans aucune ancre, l'instant de référence de l'attente est le PLUS ANCIEN MAILLON — le \
             seul témoin, dans ce schéma, de l'instant où la chaîne a commencé"
        );

        // ---- ⑤ RIEN À ANCRER : ni maillon ni ancre -> AUCUN verdict. ----
        assert_eq!(
            ancrage_en_retard(t0 + vingt_jours, None, None),
            None,
            "une base sans le moindre maillon n'a rien à ancrer : rendre un verdict ici serait \
             fabriquer une accusation à partir de rien"
        );

        // ---- ⑥ L'ANCRE LA PLUS RÉCENTE GAGNE SUR LE PLUS ANCIEN MAILLON. ----
        assert_eq!(
            ancrage_en_retard(t0 + vingt_jours, Some(t0), Some(t0 + vingt_jours)),
            None,
            "une chaîne ANCIENNE mais ancrée à l'instant est saine : tant qu'une ancre existe, c'est \
             elle qui date la dernière preuve, jamais le premier maillon"
        );
    }

    /// (V2) LE COUPLE QUI DÉCIDE, SUR LE VRAI CHEMIN — DEUX JOURNAUX QUE TOUT RAPPROCHE SAUF L'ÂGE.
    ///
    /// Mêmes trois maillons, écrits par la même formule de chaînage, ZÉRO point de contrôle des deux
    /// côtés. La SEULE valeur qui change d'un côté à l'autre est l'horodatage des maillons. C'est
    /// exactement la question que l'énoncé posait, et c'est le témoin qui y répond.
    ///
    /// LE CONTRÔLE POSITIF EST DANS LE CORPS : le témoin RECALCULE ce qu'une loi naïve — « aucun point
    /// de contrôle => accuse » — aurait fait des deux journaux, et exige qu'elle les ait accusés TOUS
    /// LES DEUX. Sans cette assertion-là, le silence sur le journal jeune serait vrai par vacuité.
    #[test]
    fn un_journal_jeune_reste_muet_la_ou_un_journal_vide_est_accuse() {
        let _env = VERROU_ENV_PROCESSUS.read(); // `verify_ledger` lit PLUME_DB_KEY / PLUME_LEDGER_PUBKEY
        let jour = 86_400i64;

        // ---- ① LE JOURNAL VIDÉ : trente jours de chaîne, plus une seule ancre. ----
        let (coffre_vide, conn) = sa_base("p107v-vide");
        for (i, recul) in [30i64, 20, 10].iter().enumerate() {
            sa_maillon_date(&conn, 1_700_000_000 - recul * jour, &format!("maillon {i}"));
        }
        assert_eq!(sa_compte(&conn, "ledger"), 3, "fixture : trois maillons");
        assert_eq!(sa_compte(&conn, "checkpoint"), 0, "fixture : plus aucun ancrage");
        drop(conn);

        // ---- ② LE JOURNAL JEUNE : les mêmes trois maillons, nés à l'instant. ----
        let (coffre_jeune, conn) = sa_base("p107v-jeune");
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        assert_eq!(sa_compte(&conn, "ledger"), 3, "fixture : trois maillons");
        assert_eq!(
            sa_compte(&conn, "checkpoint"),
            0,
            "CONTRÔLE POSITIF : le journal jeune porte lui aussi ZÉRO ancrage. Une loi qui accuserait \
             sur ce seul compte accuserait les DEUX — c'est précisément ce que ce témoin interdit"
        );
        drop(conn);

        // ---- ③ LES DEUX VERDICTS. ----
        let (n, sig_ok, sig_ko, rupture) = verify_ledger(coffre_jeune.as_str()).expect(
            "un journal JEUNE se conclut : il n'a pas encore eu de tick d'ancrage, et l'accuser serait \
             une fausse accusation sur une instance saine",
        );
        assert_eq!((n, sig_ok, sig_ko, rupture), (3, 0, 0, None), "trois maillons intègres, aucun ancrage, aucun reproche");

        let message = verify_ledger(coffre_vide.as_str()).expect_err(
            "AVANT ce lot, ce journal-là rendait le MÊME `Ok((3, 0, 0, None))` que le journal jeune, \
             et `plume-daemon verify` imprimait la même ligne au caractère près en sortant en 0",
        );
        assert!(
            message.contains("CHAÎNE NON ANCRÉE") && message.contains("JAMAIS"),
            "le refus DIT ce qu'il a mesuré : {message}"
        );
        assert!(
            message.contains(&format!("{}", 20 * jour)),
            "il NOMME la durée pendant laquelle la chaîne est restée sans ancre (ici l'écart entre le \
             plus ancien et le plus récent maillon) : {message}"
        );
        assert!(
            message.contains("La cause n'est PAS établie"),
            "il RÉCUSE explicitement de nommer une cause : effacement, clé de signature absente et \
             boucle d'ancrage arrêtée produisent le MÊME état, et rien dans le schéma ne les sépare. \
             Choisir l'une des trois serait une accusation que la mesure ne soutient pas — {message}"
        );
    }

    /// (V3) LE TÉMOIN NÉGATIF DE PRODUCTION — UNE INSTANCE SAINE, ANCRÉE AU RYTHME RÉEL, RESTE MUETTE.
    ///
    /// LE RYTHME EST CELUI DE LA BOUCLE QUI ANCRE : un maillon, un tick, un maillon, un tick — sur une
    /// chaîne VIEILLE de trente jours, pour que le silence ne vienne pas de la jeunesse de la fixture.
    #[test]
    fn une_instance_saine_ancree_a_la_cadence_reste_muette_meme_apres_trente_jours() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let jour = 86_400i64;
        let t0 = 1_700_000_000i64;
        let (coffre, conn) = sa_base("p107v-saine");

        // Trente jours de vie : un maillon, puis le tick qui l'ancre, une heure plus tard.
        for j in 0..30i64 {
            sa_maillon_date(&conn, t0 + j * jour, &format!("mutation du jour {j}"));
            sa_ancrer_a(&conn, t0 + j * jour + CADENCE_D_ANCRAGE_S);
        }
        assert_eq!(sa_compte(&conn, "ledger"), 30, "fixture : trente maillons");
        assert_eq!(sa_compte(&conn, "checkpoint"), 30, "fixture : trente ancrages");
        // CONTRÔLE POSITIF : la chaîne est VIEILLE. Sans cela, « muet » serait vrai par jeunesse.
        let etendue: i64 = conn
            .query_row("SELECT MAX(ts) - MIN(ts) FROM ledger", [], |r| r.get(0))
            .expect("étendue lisible");
        assert_eq!(etendue, 29 * jour, "la fixture couvre bien vingt-neuf jours, pas une seconde");
        drop(conn);

        let (n, sig_ok, sig_ko, rupture) = verify_ledger(coffre.as_str())
            .expect("une instance SAINE se conclut : c'est la moitié du remède qui compte");
        assert_eq!((n, sig_ok, sig_ko, rupture), (30, 30, 0, None), "trente maillons, trente signatures, aucune rupture");
    }

    /// (V4) L'ARCHIVE — POURQUOI LA RÉFÉRENCE DE `verify` EST LE DERNIER MAILLON ET NON L'HORLOGE.
    ///
    /// `plume-daemon verify` reçoit un CHEMIN : ce fichier peut être une sauvegarde restaurée ou une
    /// copie forensique, dont l'ancienneté n'accuse personne. Ce témoin MESURE ce qu'aurait coûté le
    /// choix inverse : sur la MÊME base, la même loi appliquée à l'horloge du lecteur ACCUSE, et
    /// appliquée au dernier maillon se TAIT. La valeur qui bascule le verdict est l'instant de
    /// référence — et c'est la raison écrite pour laquelle il est un ARGUMENT et pas un `now()`.
    #[test]
    fn une_archive_saine_n_est_pas_accusee_du_seul_fait_d_etre_ancienne() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let jour = 86_400i64;
        let archive = now() - 400 * jour; // une sauvegarde restaurée, plus d'un an après
        let (coffre, conn) = sa_base("p107v-archive");
        for j in 0..3i64 {
            sa_maillon_date(&conn, archive + j * jour, &format!("mutation {j}"));
            sa_ancrer_a(&conn, archive + j * jour + CADENCE_D_ANCRAGE_S);
        }
        let (plus_ancien, dernier_maillon): (i64, i64) = conn
            .query_row("SELECT MIN(ts), MAX(ts) FROM ledger", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("bornes lisibles");
        let derniere_ancre: i64 = conn.query_row("SELECT MAX(ts) FROM checkpoint", [], |r| r.get(0)).expect("ancre lisible");
        drop(conn);

        // CE QUE L'HORLOGE DU LECTEUR AURAIT DIT — la mesure qui condamne ce choix-là.
        let selon_l_horloge = ancrage_en_retard(now(), Some(plus_ancien), Some(derniere_ancre))
            .expect("MESURE : l'horloge du lecteur accuse TOUTE archive du seul fait d'être une archive");
        assert!(
            selon_l_horloge.secondes > 300 * jour,
            "l'écart mesuré contre l'horloge se compte en centaines de jours : {selon_l_horloge:?}"
        );

        // CE QUE LE FICHIER DIT DE LUI-MÊME — le dernier instant qu'il PROUVE, sans horloge.
        assert_eq!(
            ancrage_en_retard(dernier_maillon, Some(plus_ancien), Some(derniere_ancre)),
            None,
            "daté sur son dernier maillon, ce fichier est celui d'une instance qui ancrait correctement"
        );

        let (n, _ok, _ko, rupture) = verify_ledger(coffre.as_str())
            .expect("une archive SAINE se conclut : accuser une sauvegarde parce qu'elle est vieille \
                     serait la fausse accusation la plus facile à produire");
        assert_eq!((n, rupture), (3, None), "trois maillons intègres");
    }

    /// (V5) LA RUPTURE PASSE D'ABORD — UNE COMPROMISSION NOMMÉE NE DEVIENT JAMAIS UN REFUS DE CONCLURE.
    ///
    /// La fixture fait se DISPUTER les deux verdicts sur la même base : une chaîne à la fois ROMPUE et
    /// sans le moindre ancrage depuis trente jours. « Un correctif qui ferme une fausse accusation peut
    /// faire TAIRE une vraie » — le signal d'alerte étant un verdict qui passe d'ACCUSE à REFUSE DE
    /// CONCLURE, ce témoin l'interdit explicitement.
    #[test]
    fn une_rupture_nommee_ne_devient_pas_un_refus_de_conclure_faute_d_ancrage() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let jour = 86_400i64;
        let (coffre, conn) = sa_base("p107v-rupture");
        for (i, recul) in [30i64, 20, 10].iter().enumerate() {
            sa_maillon_date(&conn, 1_700_000_000 - recul * jour, &format!("maillon {i}"));
        }
        // La falsification : réécrire le `detail` du deuxième maillon (le recalcul ne retombe plus).
        conn.execute("UPDATE ledger SET detail='FALSIFIÉ' WHERE id=(SELECT id FROM ledger ORDER BY id LIMIT 1 OFFSET 1)", [])
            .expect("falsification posée");
        assert_eq!(sa_compte(&conn, "checkpoint"), 0, "fixture : la chaîne est AUSSI sans ancre");
        drop(conn);

        let (_n, _ok, _ko, rupture) = verify_ledger(coffre.as_str()).expect(
            "une chaîne ROMPUE se conclut : c'est le verdict le PLUS FORT que cet instrument sache \
             rendre, et aucun contrôle d'ancrage n'a le droit de le convertir en « aucun verdict »",
        );
        assert!(rupture.is_some(), "la rupture est NOMMÉE par l'`id` du maillon, comme avant ce lot");
    }

    /// (V6) LE CŒUR RESTE INTACT — LE VERDICT D'ANCRAGE N'ATTEINT PAS `verify_ledger_conn`.
    ///
    /// CE N'EST PAS UN DÉTAIL DE PLACEMENT, C'EST UNE FAUSSE ACCUSATION ÉVITÉE, ET ELLE EST MESURÉE
    /// ICI : `crypto::prouver_l_equivalence` se sert du cœur pour prouver qu'une CONVERSION de base au
    /// repos a recopié le journal fidèlement, et traduit tout `Err` en « journal inaltérable ILLISIBLE
    /// dans la copie chiffrée » — puis ABANDONNE la conversion. Router la loi dans le cœur aurait donc
    /// fait échouer, sous une phrase fausse, la conversion d'une base parfaitement copiée dont le seul
    /// tort est de ne plus être ancrée. Le témoin exige que la MÊME base fasse REFUSER le wrapper et
    /// CONCLURE le cœur.
    #[test]
    fn le_coeur_de_verification_garde_son_contrat_pour_son_second_consommateur() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let jour = 86_400i64;
        let (coffre, conn) = sa_base("p107v-coeur");
        for (i, recul) in [30i64, 20, 10].iter().enumerate() {
            sa_maillon_date(&conn, 1_700_000_000 - recul * jour, &format!("maillon {i}"));
        }

        assert_eq!(
            verify_ledger_conn(&conn, None).expect("le cœur CONCLUT sur cette base"),
            (3, 0, 0, None),
            "le contrat du cœur est INCHANGÉ : trois maillons intègres, aucune signature, aucune \
             rupture. C'est ce que la preuve d'équivalence d'une conversion at-rest a besoin de lire"
        );
        drop(conn);

        let message = verify_ledger(coffre.as_str()).expect_err("le WRAPPER, lui, refuse de conclure");
        assert!(message.contains("CHAÎNE NON ANCRÉE"), "et c'est bien la loi d'ancrage qui parle : {message}");
    }

    // ------------------------------------------------------------------------------------------------
    // LA CADENCE N'EST PAS CHOISIE ICI — ELLE EST LUE DANS LA BOUCLE QUI ANCRE.
    // ------------------------------------------------------------------------------------------------

    /// Les durées de sommeil écrites DANS la boucle de `<nom>`, en secondes. Le préchauffage qui précède
    /// la boucle est délibérément HORS tranche : ce n'est pas la période. `Err` nomme ce qui manque —
    /// une tranche qu'on ne sait pas découper ne vaut JAMAIS « aucune contrainte ».
    fn sa_periodes_de_la_boucle(source: &str, nom: &str) -> Result<Vec<i64>, String> {
        let entete = format!("fn {nom}(");
        let debut = source.find(&entete).ok_or_else(|| format!("fonction `{nom}` introuvable"))?;
        let corps = &source[debut..];
        let fin = corps[1..].find("\nfn ").map(|i| i + 1).unwrap_or(corps.len());
        let corps = &corps[..fin];
        let boucle = corps.find("loop {").ok_or_else(|| format!("aucune boucle dans `{nom}`"))?;
        let mut out = Vec::new();
        let mut reste = &corps[boucle..];
        while let Some(i) = reste.find("from_secs(") {
            reste = &reste[i + "from_secs(".len()..];
            let n: String = reste.chars().take_while(|c| c.is_ascii_digit()).collect();
            if n.is_empty() {
                return Err(format!("`from_secs(` non littéral dans `{nom}` — la période n'est plus lisible"));
            }
            out.push(n.parse::<i64>().map_err(|e| format!("{e}"))?);
        }
        Ok(out)
    }

    /// (V7) LA GARDE DÉRIVÉE — LE SEUIL NE PEUT PLUS VIEILLIR EN SILENCE.
    ///
    /// `CADENCE_D_ANCRAGE_S` est un nombre recopié : la période de la boucle qui ancre est un littéral
    /// au milieu d'un corps de fonction, qu'aucun module ne peut importer. Un tel nombre est une liste
    /// d'un élément qui vieillit sans rougir — sauf s'il est RELU. Ce témoin le relit, et il relit aussi
    /// LES DEUX MAILLONS de la chaîne qui rendent la cadence vraie : la boucle appelle la passe de
    /// rétention, et la passe de rétention signe un point de contrôle.
    ///
    /// L'INSTRUMENT EST VALIDÉ DANS LES DEUX SENS SUR DES CORPUS FABRIQUÉS, AVANT D'ÊTRE CRU : un
    /// dépouilleur qui rendrait toujours la bonne valeur, ou toujours rien, serait vert par
    /// construction dans les deux cas.
    #[test]
    fn la_cadence_d_ancrage_est_celle_de_la_boucle_qui_ancre() {
        // ---- ① L'INSTRUMENT, SUR DES CORPUS FABRIQUÉS. ----
        let avec_prechauffage = "fn f(x: u8) {\n    sleep(Duration::from_secs(60));\n    loop {\n        travail();\n        sleep(Duration::from_secs(900));\n    }\n}\n";
        assert_eq!(
            sa_periodes_de_la_boucle(avec_prechauffage, "f").expect("tranche découpée"),
            vec![900],
            "le préchauffage qui PRÉCÈDE la boucle n'est pas la période : le confondre avec elle \
             rendrait 60 et la garde tiendrait un nombre qui n'ancre rien"
        );
        let sans_boucle = "fn f(x: u8) {\n    sleep(Duration::from_secs(60));\n}\n";
        assert!(
            sa_periodes_de_la_boucle(sans_boucle, "f").is_err(),
            "une fonction sans boucle ne vaut PAS « aucune contrainte » : le dépouilleur doit le DIRE"
        );
        assert!(sa_periodes_de_la_boucle(avec_prechauffage, "g").is_err(), "une fonction absente est un refus, pas un vide");
        let voisine_apres = "fn f(x: u8) {\n    loop {\n        sleep(Duration::from_secs(900));\n    }\n}\nfn g() {\n    loop {\n        sleep(Duration::from_secs(7));\n    }\n}\n";
        assert_eq!(
            sa_periodes_de_la_boucle(voisine_apres, "f").expect("tranche découpée"),
            vec![900],
            "la tranche s'arrête à la fonction SUIVANTE : déborder ferait lire le sommeil d'une voisine"
        );

        // ---- ② LA MESURE, SUR LE VRAI CORPS. ----
        let boucles = include_str!("../server/boucles_de_fond.rs");
        let periodes = sa_periodes_de_la_boucle(boucles, "spawn_retention_loop")
            .expect("la boucle qui ancre doit rester lisible : sinon la cadence n'est plus établie");
        assert_eq!(
            periodes.len(),
            1,
            "la boucle qui ancre doit porter UNE période et une seule ; elle en porte {} ({periodes:?}) \
             — la cadence est à ré-établir à la main avant que ce seuil ne veuille dire quelque chose",
            periodes.len()
        );
        assert_eq!(
            periodes[0], CADENCE_D_ANCRAGE_S,
            "la période de `spawn_retention_loop` vaut {} s, la constante en dit {CADENCE_D_ANCRAGE_S}. \
             Le seuil d'ancrage (tolérance {TOLERANCE_D_ANCRAGE_S} s) est dérivé de cette valeur : le \
             corriger ici, et nulle part ailleurs",
            periodes[0]
        );

        // ---- ③ LES DEUX MAILLONS QUI RENDENT LA CADENCE VRAIE. ----
        let corps_boucle = {
            let d = boucles.find("fn spawn_retention_loop(").expect("fonction présente");
            let c = &boucles[d..];
            let f = c[1..].find("\nfn ").map(|i| i + 1).unwrap_or(c.len());
            &c[..f]
        };
        assert!(
            corps_boucle.contains("retention_run_tenant("),
            "la boucle n'appelle plus la passe de rétention : la cadence d'ancrage ne se déduit plus \
             d'elle, et la tolérance ne repose plus sur rien"
        );
        let rollups = include_str!("../rollups.rs");
        let corps_passe = {
            let d = rollups.find("fn retention_run_tenant(").expect("passe présente");
            let c = &rollups[d..];
            let f = c[1..].find("\npub(crate) fn ").map(|i| i + 1).unwrap_or(c.len());
            &c[..f]
        };
        assert!(
            corps_passe.contains("sign_checkpoint(&conn"),
            "la passe de rétention ne signe plus de point de contrôle : ce n'est plus elle qui ancre, \
             et la période de sa boucle a cessé d'être la cadence d'ancrage"
        );
    }

    // ------------------------------------------------------------------------------------------------
    // LA SECONDE MOITIÉ : LA DURÉE D'ABSENCE, DANS LA PIÈCE DE CONFORMITÉ QUI LA RAPPORTAIT SANS RIEN
    // EN DIRE. `handlers/compliance.rs` lisait l'horodatage du dernier point de contrôle et le SERVAIT.
    // Une panne d'ancrage pouvait donc durer une heure, un jour, une semaine : le rapport continuait de
    // rendre un nombre que personne ne comparait à rien.
    // ------------------------------------------------------------------------------------------------

    /// L'identité qui interroge : admin, pour qu'aucun masque de champ ne s'interpose.
    fn sa_au() -> AuthUser {
        AuthUser {
            name: "p107v".into(), role: "admin".into(), tenant: "default".into(),
            is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// Une base FICHIER servie par le pool de lecture (le rapport ouvre par chemin : une base en
    /// mémoire ne conviendrait pas), journal ET points de contrôle vidés.
    fn sa_base_servie(etiquette: &str) -> (crate::tmp_possede::TmpDb, AppState) {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = open_db(coffre.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle vidés");
        drop(conn);
        let st = ds_file_state(coffre.as_str());
        (coffre, st)
    }

    /// (V8) LE RAPPORT DE CONFORMITÉ REND UN VERDICT SUR LA DURÉE, DANS LES TROIS ÉTATS.
    ///
    /// LA RÉFÉRENCE EST `now()` ICI, ET SEULEMENT ICI : ce corps est servi par le démon SUR SA PROPRE
    /// BASE VIVANTE, donc l'horloge du lecteur EST celle de l'instance. C'est aussi le SEUL des deux
    /// sites qui attrape une chaîne DÉLAISSÉE QUI NE GROSSIT PLUS — plus aucune mutation de config, donc
    /// plus aucun maillon neuf, donc rien que le fichier puisse dire de lui-même.
    ///
    /// LE TÉMOIN NÉGATIF EST LA MOITIÉ QUI COMPTE : la clé n'apparaît QUE quand elle accuse, et le
    /// chemin nominal est vérifié MUET après qu'on s'est assuré que la lecture avait bien EU LIEU.
    /// AUCUNE HORLOGE N'EST GUETTÉE : ce qu'on fabrique est l'ÂGE DE LA DONNÉE, des maillons datés.
    #[tokio::test]
    async fn le_rapport_de_conformite_rend_un_verdict_quand_l_ancrage_a_cesse() {
        let jour = 86_400i64;
        let lire = |st: &AppState| {
            let (st, au) = (st.clone(), sa_au());
            async move { compliance_report(State(st), Extension(au), Query(HashMap::new())).await.0 }
        };

        // ---- ① NOMINAL : un journal JEUNE, jamais ancré. La lecture a lieu, et RIEN n'est reproché. ----
        let (coffre_jeune, st) = sa_base_servie("p107v-rapport-jeune");
        {
            let conn = st.db.lock();
            for i in 0..3 {
                ledger_append(&conn, "config.mode", &format!("maillon {i}"));
            }
        }
        let ev = lire(&st).await["evidence"].clone();
        assert_eq!(ev["ledger_entries"], json!(3), "INSTRUMENT : la lecture a bien eu lieu — {ev}");
        assert_eq!(
            ev["anchoring_cadence_s"], json!(CADENCE_D_ANCRAGE_S),
            "le rapport DIT la cadence à laquelle il attend un ancrage — {ev}"
        );
        assert_eq!(ev["last_checkpoint_ts"], json!(null), "aucun ancrage : c'est un FAIT, servi comme avant — {ev}");
        assert!(
            ev.get("anchoring_overdue").is_none(),
            "un journal JEUNE n'a légitimement aucun point de contrôle : un verdict ici serait une \
             fausse accusation, et un corps qui accuse toujours n'accuse rien — {ev}"
        );
        drop(coffre_jeune);

        // ---- ② JAMAIS ANCRÉ, et le journal a trente jours. ----
        let (coffre_vide, st) = sa_base_servie("p107v-rapport-vide");
        {
            let conn = st.db.lock();
            for (i, recul) in [30i64, 20, 10].iter().enumerate() {
                sa_maillon_date(&conn, now() - recul * jour, &format!("maillon {i}"));
            }
        }
        let ev = lire(&st).await["evidence"].clone();
        let verdict = ev.get("anchoring_overdue").unwrap_or_else(|| {
            panic!("AVANT ce lot, ce corps servait `last_checkpoint_ts: null` et s'arrêtait là : {ev}")
        });
        assert_eq!(verdict["never_anchored"], json!(true), "cette chaîne n'a JAMAIS porté d'ancre — {verdict}");
        assert!(
            verdict["seconds"].as_i64().unwrap_or(0) >= 29 * jour,
            "la durée rendue est celle qui s'est écoulée depuis le plus ancien maillon — {verdict}"
        );
        assert_eq!(verdict["tolerance_s"], json!(TOLERANCE_D_ANCRAGE_S), "et la tolérance qu'elle dépasse — {verdict}");
        assert!(
            verdict["statement"].as_str().unwrap_or_default().contains("CHAÎNE NON ANCRÉE"),
            "la phrase est celle que la CLI imprime aussi : un exploitant lit le MÊME texte des deux \
             côtés — {verdict}"
        );
        drop(coffre_vide);

        // ---- ③ ANCRÉ PUIS DÉLAISSÉ — le défaut nommé : la durée d'absence n'était bornée par rien. ----
        // La chaîne a été ancrée normalement, puis PLUS RIEN pendant dix jours. Elle ne grossit même
        // plus : aucun maillon neuf. C'est l'état qu'aucun aveu horaire ne rattrape (l'aveu vit DANS le
        // tick qui ne tourne plus) et que seule cette lecture-ci peut voir.
        let (coffre_delaisse, st) = sa_base_servie("p107v-rapport-delaisse");
        {
            let conn = st.db.lock();
            for (i, recul) in [30i64, 20, 10].iter().enumerate() {
                sa_maillon_date(&conn, now() - recul * jour, &format!("maillon {i}"));
                sa_ancrer_a(&conn, now() - recul * jour + CADENCE_D_ANCRAGE_S);
            }
        }
        let ev = lire(&st).await["evidence"].clone();
        assert!(ev["last_checkpoint_ts"].as_i64().is_some(), "INSTRUMENT : cette chaîne A été ancrée — {ev}");
        let verdict = ev.get("anchoring_overdue").unwrap_or_else(|| {
            panic!("une chaîne ancrée puis DÉLAISSÉE depuis dix jours : c'est la durée que rien ne \
                    bornait, et le nombre servi ne se comparait à rien — {ev}")
        });
        assert_eq!(
            verdict["never_anchored"], json!(false),
            "elle a bien porté des ancres : le verdict ne dit pas la même chose que sur un journal qui \
             n'en a jamais eu — {verdict}"
        );
        assert_eq!(
            verdict["since_ts"], ev["last_checkpoint_ts"],
            "et il se date sur le DERNIER point de contrôle, c'est-à-dire exactement la valeur que ce \
             corps se contentait de rapporter — {verdict}"
        );
        drop(coffre_delaisse);
    }
