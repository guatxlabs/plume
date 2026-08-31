    // ================================================================================================
    // ON NE SIGNE PAS CE QU'ON N'A PAS PU LIRE — `P10.7-t` et `P10.7-s`, mesurés le 2026-08-31.
    //
    // LE FIL COMMUN, ET IL EST PIRE QUE « UN VERDICT TROP OPTIMISTE » : ici, ce qui n'a pas été lu est
    // ATTESTÉ. Un point de contrôle signé Ed25519 sur une chaîne qu'on n'a pas su lire ; une copie WORM
    // déclarée « intègre » alors qu'elle est vide ou tronquée. Dans les deux cas la sortie n'est pas
    // seulement fausse : elle porte l'AUTORITÉ d'un instrument d'intégrité, exactement celle qu'elle ne
    // mérite pas. C'est la forme la plus grave de la famille que ce dépôt poursuit.
    //
    //   (T) `P10.7-t` — LA SIGNATURE. `sign_checkpoint` repliait sur `genesis` quand la lecture de la
    //       tête échouait. MESURÉ, et c'est la mesure qui décide : trois maillons du vrai chemin, `hash`
    //       de la tête remplacé par un blob, puis REMIS (la panne se résorbe, comme un verrou se relâche).
    //       Le point de contrôle mensonger, lui, RESTE — et `verify_ledger_conn` rendait alors
    //       `Ok((3, 1, 0, None))` : trois maillons intègres, UNE SIGNATURE COMPTÉE OK, aucune rupture.
    //       Aucun vérificateur ne compare `checkpoint.ledger_hash` à la tête réelle ; le mensonge est donc
    //       permanent et indistinguable d'un point de contrôle légitime.
    //
    //   (S) `P10.7-s` — L'EXPORT. `ledger_export_lines` aplatissait, et LE PIRE N'EST PAS LE VERDICT,
    //       C'EST LE CURSEUR : le maillon sauté n'entre jamais dans la copie inaltérable, et les envois
    //       suivants annoncent « exported: 0 ». Une lacune permanente ET silencieuse dans une preuve.
    //
    // AUCUN TÉMOIN CHRONOMÉTRIQUE : tout est adossé à un GESTE (une colonne d'un type inattendu, une
    // table retirée), à un COMPTE (lignes en base, lignes exportées, curseur) ou à une PROPRIÉTÉ
    // STRUCTURELLE (le verdict, le code de statut). Le répertoire temporaire de ce poste est en mémoire :
    // une mesure de durée y serait verte par construction.
    //
    // AUCUN TÉMOIN N'EST ADOSSÉ À UN DÉFAUT VIVANT : chacun asserte l'état CORRIGÉ et NOMME dans son
    // message la réponse que l'arbre rendait avant, pour que le rouge d'une régression soit lisible.
    // ================================================================================================

    /// La clé qui SIGNE dans cette section (déterministe : jamais un fichier, jamais l'environnement).
    fn oss_cle() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
    }

    /// Un journal ET des points de contrôle réellement VIERGES : `test_db()` fait tourner la chaîne de
    /// migrations, qui consigne. Pour mesurer l'ORIGINE il faut des tables vides, pas « presque vides ».
    fn oss_journal_vierge() -> Connection {
        let conn = test_db();
        conn.execute("DELETE FROM ledger", []).expect("journal vidé");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle vidés");
        conn
    }

    fn oss_compte(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).expect("table comptable")
    }

    /// LE GESTE, PARTAGÉ PAR LES DEUX CLÉS : rendre UNE ligne du journal illisible SANS la retirer.
    /// SQLite range un BLOB tel quel dans une colonne d'affinité TEXT -> la LECTURE TYPÉE de ce maillon
    /// meurt, l'écriture et le comptage restent parfaitement vivants. C'est ce qui rend ces témoins
    /// DISCRIMINANTS : sous une panne globale (base fermée, table retirée) l'écriture échouerait AUSSI et
    /// « aucun point de contrôle écrit » serait vrai pour la mauvaise raison — vert par construction.
    /// Rend le `hash` réel de la ligne abîmée, pour pouvoir RÉSORBER la panne.
    fn oss_abimer(conn: &Connection, id: i64) -> String {
        let vrai: String = conn
            .query_row("SELECT hash FROM ledger WHERE id=?1", params![id], |r| r.get(0))
            .expect("maillon lisible avant le geste");
        let n = conn.execute("UPDATE ledger SET hash=X'FF' WHERE id=?1", params![id]).expect("maillon abîmé");
        assert_eq!(n, 1, "fixture : exactement UNE ligne abîmée");
        vrai
    }

    fn oss_ids(conn: &Connection) -> Vec<i64> {
        let mut s = conn.prepare("SELECT id FROM ledger ORDER BY id").expect("journal listable");
        let v = s.query_map([], |r| r.get::<_, i64>(0)).expect("scan").map(|x| x.expect("id")).collect();
        v
    }

    /// Les aveux SOC de refus de signature RÉELLEMENT posés (`P10.7-t`). Non-purgeables : `origin='daemon'`
    /// ET `source='plume-config'` sont ASSERTÉS ici, pas supposés — un aveu purgeable serait un aveu qui
    /// s'efface tout seul, c'est-à-dire pas un aveu.
    ///
    /// LE `LIKE` EST ANCRÉ SUR LE SUFFIXE, ET CE N'EST PAS UNE APPROXIMATION : la clé `event.dedup`
    /// STOCKÉE est CLOISONNÉE PAR HÔTE (`dedup_scoped_by_host` — la seule écriture de cette colonne sur le
    /// chemin chaud), donc préfixée de la longueur et du nom d'hôte. Un ancrage en tête rendrait ZÉRO
    /// ligne et ce témoin serait vert-par-absence : mesuré, il l'était.
    fn oss_aveux(conn: &Connection) -> Vec<String> {
        let mut s = conn
            .prepare(
                "SELECT fields FROM event WHERE source='plume-config' AND category='health' AND origin='daemon' \
                 AND severity=4 AND dedup LIKE '%plume-ledger-checkpoint-refused-%' ORDER BY id",
            )
            .expect("events lisibles");
        let v = s.query_map([], |r| r.get::<_, String>(0)).expect("scan").map(|x| x.expect("fields")).collect();
        v
    }

    // ------------------------------------------------------------------------------------------------
    // (T) `P10.7-t` — UN POINT DE CONTRÔLE N'ATTESTE PLUS UNE ORIGINE SUR UN JOURNAL QUI PORTE DES MAILLONS.
    // ------------------------------------------------------------------------------------------------

    /// (T1) TÉMOIN NÉGATIF DE TOUTE LA SECTION — LE CHEMIN NOMINAL SIGNE, ET IL EST MUET.
    ///
    /// Un instrument qui refuserait TOUJOURS de signer ne vaut pas mieux qu'un instrument qui signe
    /// toujours n'importe quoi : il rend le même service (aucun) en coûtant la disponibilité en plus.
    /// Ce témoin rougit le jour où quelqu'un « durcit » la signature en un refus inconditionnel.
    ///
    /// TROIS ASSERTIONS, PAS UNE : le point de contrôle EXISTE, il atteste la VRAIE tête (pas une valeur
    /// plausible), et AUCUN aveu n'est émis. Un correctif qui signerait la bonne valeur en criant à chaque
    /// passage passerait les deux premières.
    #[test]
    fn un_point_de_controle_legitime_est_ecrit_atteste_la_vraie_tete_et_ne_dit_rien() {
        let conn = oss_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let vraie_tete: String = conn
            .query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("tête lisible");

        sign_checkpoint(&conn, &oss_cle());

        assert_eq!(oss_compte(&conn, "checkpoint"), 1, "le chemin nominal ÉCRIT le point de contrôle");
        let atteste: String = conn
            .query_row("SELECT ledger_hash FROM checkpoint ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("point de contrôle lisible");
        assert_eq!(atteste, vraie_tete, "il atteste la VRAIE tête de chaîne, pas une valeur de repli");
        assert!(oss_aveux(&conn).is_empty(), "le chemin nominal n'avoue RIEN : {:?}", oss_aveux(&conn));

        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None).expect("chaîne saine");
        assert_eq!((n, sig_ok, sig_ko, rupture), (3, 1, 0, None), "et le vérificateur le compte OK");
    }

    /// (T2) L'ORIGINE RESTE SIGNABLE, ET C'EST LA FRONTIÈRE EXACTE DU CORRECTIF.
    ///
    /// Un journal VIERGE n'est pas un journal illisible : `ledger_prev_hash` sépare les deux depuis
    /// `P10.7-m` (aucune ligne = `QueryReturnedNoRows` = l'origine LÉGITIME). Un correctif qui aurait
    /// refusé « quand la lecture ne rend rien » — c'est-à-dire qui n'aurait pas discriminé sur l'ERREUR —
    /// rougirait ICI, et il aurait rendu toute base NEUVE incapable d'ancrer sa chaîne dès le premier tick.
    ///
    /// LA VALEUR `genesis` EST CELLE DE L'ARBRE, délibérément conservée : la changer ferait diverger les
    /// points de contrôle d'origine anciens et neufs sans rien gagner (aucune migration, aucune
    /// re-signature). Ce témoin l'ÉPINGLE pour qu'un « nettoyage » futur soit une décision, pas un effet.
    #[test]
    fn un_journal_vierge_signe_son_origine_et_reste_muet() {
        let conn = oss_journal_vierge();
        assert_eq!(oss_compte(&conn, "ledger"), 0, "fixture : le journal part VIERGE");

        sign_checkpoint(&conn, &oss_cle());

        assert_eq!(oss_compte(&conn, "checkpoint"), 1, "l'origine S'ANCRE : refuser ici priverait toute base neuve de point de contrôle");
        let atteste: String = conn
            .query_row("SELECT ledger_hash FROM checkpoint ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("point de contrôle lisible");
        assert_eq!(atteste, "genesis", "l'origine d'un journal vierge garde sa valeur historique");
        assert!(oss_aveux(&conn).is_empty(), "et rien n'est avoué : c'est le chemin nominal d'une base neuve");
    }

    /// (T3) LE DÉFAUT, ET SA FORME LA PLUS COÛTEUSE — RIEN N'EST SIGNÉ, ET LE MENSONGE N'EXISTE PLUS
    /// APRÈS LA RÉSORPTION DE LA PANNE.
    ///
    /// LE SCÉNARIO EST CELUI DE LA PRODUCTION : une lecture échoue à un instant (verrou, colonne d'un type
    /// inattendu après une restauration partielle), puis la base redevient normale. Ce qui reste en base,
    /// lui, ne redevient jamais normal. L'ANCIENNE RÉPONSE EST NOMMÉE DANS LES ASSERTIONS : un point de
    /// contrôle attestant `genesis` sur un journal de trois maillons, et `verify_ledger_conn` rendant
    /// `Ok((3, 1, 0, None))` — donc `plume-daemon verify` imprimant « ledger OK … OK=1 KO=0 » et sortant
    /// en 0. C'est cette signature-là, comptée VALIDE, qui donnait au mensonge son autorité.
    ///
    /// LE TÉMOIN EXIGE LES DEUX MOITIÉS : aucune ligne écrite (rien à quoi la panne donnerait autorité)
    /// ET, après résorption, `sig_ok == 0` — la fenêtre est NON ANCRÉE, ce qui est VISIBLE, et la chaîne
    /// reste vérifiable par recalcul (le verdict d'intégrité, lui, est toujours rendu).
    #[test]
    fn une_tete_illisible_n_est_plus_attestee_et_ne_laisse_aucune_signature_derriere_elle() {
        let conn = oss_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let ids = oss_ids(&conn);

        // SENS 1 — la MÊME connexion, avant qu'on abîme quoi que ce soit : elle signe.
        sign_checkpoint(&conn, &oss_cle());
        assert_eq!(oss_compte(&conn, "checkpoint"), 1, "état de départ : le nominal signe");
        conn.execute("DELETE FROM checkpoint", []).expect("points de contrôle remis à zéro");

        // SENS 2 — la tête devient illisible. La ligne RESTE en base : illisible, pas absente.
        let vraie_tete = oss_abimer(&conn, *ids.last().expect("trois maillons"));
        assert_eq!(oss_compte(&conn, "ledger"), 3, "le journal PORTE toujours ses trois maillons");

        sign_checkpoint(&conn, &oss_cle());

        assert_eq!(
            oss_compte(&conn, "checkpoint"),
            0,
            "AUCUN point de contrôle n'est écrit — l'ancienne réponse était UNE ligne attestant `genesis` \
             sur un journal de trois maillons"
        );

        // LA PANNE SE RÉSORBE. C'est ici que l'ancien défaut devenait PERMANENT.
        conn.execute("UPDATE ledger SET hash=?1 WHERE id=?2", params![vraie_tete, ids[2]])
            .expect("panne résorbée");
        let (n, sig_ok, sig_ko, rupture) = verify_ledger_conn(&conn, None).expect("la chaîne se relit entièrement");
        assert_eq!(n, 3, "les trois maillons sont lus");
        assert!(rupture.is_none(), "et la chaîne est intègre : refuser de signer n'abîme RIEN : {rupture:?}");
        assert_eq!(
            (sig_ok, sig_ko),
            (0, 0),
            "AUCUNE signature ne survit à la panne — l'ancienne réponse était Ok((3, 1, 0, None)), c'est-à-dire \
             une attestation d'origine COMPTÉE VALIDE sur une chaîne qui porte des maillons"
        );
    }

    /// (T4) LE REFUS EST LU PAR QUELQU'UN, ET C'EST CE QUI REND LE REMÈDE UTILE.
    ///
    /// MESURÉ AVANT D'ÉCRIRE LE CORRECTIF : les DEUX voies de production (`rollups::retention_run`,
    /// horaire, et `server` au boot) appellent `sign_checkpoint` depuis un BRAS DE `match` TYPÉ `()`.
    /// Elles ne bouclent pas, n'alertent pas, et n'ont aucune valeur à examiner. Un refus rendu par le
    /// type serait tombé dans le vide : on aurait remplacé un MENSONGE SIGNÉ par une DISPARITION
    /// SILENCIEUSE des points de contrôle — le même défaut, déplacé d'un cran.
    ///
    /// D'OÙ L'AVEU, ET D'OÙ CE TÉMOIN : un event SOC sévérité 4, `origin='daemon'` + `source='plume-config'`
    /// (donc NON-PURGEABLE — asserté par la requête d'`oss_aveux`), qui nomme la cause. Il n'est émis QUE
    /// sur le refus : (T1) et (T2) en exigent l'absence sur les deux chemins nominaux.
    #[test]
    fn un_refus_de_signer_laisse_un_aveu_soc_non_purgeable() {
        let conn = oss_journal_vierge();
        for i in 0..2 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let ids = oss_ids(&conn);
        oss_abimer(&conn, ids[1]);

        sign_checkpoint(&conn, &oss_cle());

        let aveux = oss_aveux(&conn);
        assert_eq!(aveux.len(), 1, "le refus est AVOUÉ une fois : {aveux:?}");
        assert!(aveux[0].contains("\"signing\":\"refused\""), "l'aveu nomme le refus : {}", aveux[0]);
        assert!(
            aveux[0].contains("ledger-head-unreadable"),
            "et il nomme la CAUSE, pas seulement l'effet : {}",
            aveux[0]
        );
        let msg: String = conn
            .query_row(
                "SELECT message FROM event WHERE source='plume-config' AND category='health' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("message lisible");
        assert!(msg.contains("NON ÉCRIT"), "le message dit ce qui n'a PAS eu lieu : {msg}");
    }

    /// (T5) L'AVEU NE FAIT PAS DE TEMPÊTE, ET LA BORNE EST ARITHMÉTIQUE — PAS CHRONOMÉTRIQUE.
    ///
    /// POURQUOI ÇA COMPTE ICI PRÉCISÉMENT : la voie qui refuse est HORAIRE (`retention_run`), et un boot
    /// en crashloop la rejoue à chaque redémarrage. Un aveu par tick sur une panne qui dure une semaine
    /// noierait la console — c'est-à-dire ferait taire l'aveu par le volume, après l'avoir fait taire par
    /// le silence. Le `now_ts` est INJECTÉ : on compare deux SEAUX (`now_ts / 3600`), on ne mesure aucune
    /// durée. Sur ce poste, un témoin qui chronométrerait serait vert par construction.
    #[test]
    fn deux_refus_dans_la_meme_heure_n_avouent_qu_une_fois_et_l_heure_suivante_reparle() {
        let conn = oss_journal_vierge();
        let t = 1_700_000_000i64;

        assert!(emit_ledger_checkpoint_refused(&conn, t, "tête illisible"), "le premier aveu passe");
        assert!(
            !emit_ledger_checkpoint_refused(&conn, t + 59, "tête illisible"),
            "le second, DANS LE MÊME SEAU HORAIRE, est absorbé : pas de tempête"
        );
        assert_eq!(oss_aveux(&conn).len(), 1, "une seule ligne en base pour l'heure en cours");

        assert!(
            emit_ledger_checkpoint_refused(&conn, t + 3600, "tête illisible"),
            "l'heure SUIVANTE reparle : une panne qui dure ne devient jamais muette"
        );
        assert_eq!(oss_aveux(&conn).len(), 2, "deux heures, deux aveux");
    }

    // ------------------------------------------------------------------------------------------------
    // (S) `P10.7-s` — L'EXPORT NE REND PLUS « INTÈGRE » SUR UNE COPIE VIDE OU TRONQUÉE.
    // ------------------------------------------------------------------------------------------------

    /// (S1) TÉMOIN NÉGATIF DE TOUTE LA SECTION, ET IL PORTE LE PARAVENT EXPLICITEMENT REFUSÉ.
    ///
    /// DEUX CHOSES DOIVENT CONTINUER DE PASSER, ET LA SECONDE EST LA PLUS IMPORTANTE :
    ///  1. une chaîne saine s'exporte et se vérifie (sinon l'export ne sert plus à rien) ;
    ///  2. UN EXPORT INCRÉMENTAL LÉGITIMEMENT VIDE RESTE UN SUCCÈS, et `ledger_verify_export` continue de
    ///     rendre `Ok(0)` dessus. On a REFUSÉ de durcir le vérificateur à rejeter un export vide : rien de
    ///     neuf depuis le dernier envoi est le cas NORMAL d'un sink qui tourne, et l'y forcer troquerait
    ///     le faux vert contre une FAUSSE ACCUSATION quotidienne. La distinction « vide » / « illisible »
    ///     se fait à la LECTURE, où elle est connue — jamais par une heuristique sur une longueur.
    #[test]
    fn un_export_sain_se_verifie_et_un_export_legitimement_vide_reste_un_succes() {
        let conn = oss_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }

        let (lignes, dernier_id, dernier_hash) = ledger_export_lines(&conn, 0, 0).expect("une chaîne saine s'exporte");
        assert_eq!(lignes.len(), 3, "les trois maillons sortent");
        assert_eq!(ledger_verify_export(&lignes, "").expect("et la copie se vérifie"), 3);

        // RIEN DE NEUF : la tranche suivante est VIDE, et c'est un SUCCÈS, pas un refus.
        let (rien, id2, hash2) = ledger_export_lines(&conn, dernier_id, 0).expect("une tranche vide n'est PAS une erreur");
        assert!(rien.is_empty(), "rien de neuf -> aucune ligne");
        assert_eq!((id2, hash2.as_str()), (dernier_id, ""), "le curseur ne bouge pas de lui-même");
        assert_eq!(
            ledger_verify_export(&rien, &dernier_hash).expect("un export vide reste VÉRIFIABLE"),
            0,
            "le paravent est REFUSÉ : forcer le vérificateur à rejeter le vide créerait une fausse accusation"
        );
    }

    /// (S2) PREMIÈRE FORME — UN PRÉPARATIF RATÉ NE REND PLUS UNE COPIE VIDE « INTÈGRE ».
    ///
    /// LE GESTE : la table `ledger` retirée — la classe d'échec d'une clé SQLCipher absente/incorrecte ou
    /// d'une base à laquelle il manque son schéma. L'ANCIENNE RÉPONSE EST NOMMÉE : `(0 lignes, curseur
    /// inchangé)`, que `ledger_verify_export` déclarait `Ok(0)`, soit « export OK : 0 entrées chaînées
    /// intègres » — un verdict d'intégrité rendu sur une copie jamais lue.
    #[test]
    fn un_preparatif_rate_refuse_l_export_au_lieu_de_rendre_une_copie_vide() {
        let conn = test_db();
        conn.execute("DROP TABLE ledger", []).expect("table retirée");

        let message = ledger_export_lines(&conn, 0, 0)
            .map(|t| format!("{t:?}"))
            .expect_err("l'ancienne réponse était (0 lignes, curseur inchangé) que le vérificateur déclarait Ok(0)");
        assert!(message.contains("lecture ledger"), "le refus NOMME la lecture qui a échoué : {message}");
        assert!(message.contains("AUCUN export"), "et il dit qu'aucune copie n'est produite : {message}");
    }

    /// (S3) SECONDE FORME, SOUS-CAS « DERNIÈRE LIGNE » — LE FAUX VERT LITTÉRAL.
    ///
    /// L'ANCIENNE RÉPONSE, MESURÉE : trois maillons, le TROISIÈME illisible -> DEUX lignes exportées, que
    /// `ledger_verify_export` déclarait `Ok(2)` — « intègre ». Et le curseur s'arrêtait à 2, si bien que
    /// l'envoi suivant relisait la même ligne illisible, rendait zéro, et la route répondait
    /// `"exported": 0` : la copie inaltérable GELÉE, définitivement, sans un mot.
    #[test]
    fn une_derniere_ligne_illisible_refuse_l_export_au_lieu_de_le_declarer_integre() {
        let conn = oss_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let ids = oss_ids(&conn);

        // SENS 1 — la MÊME base, intacte : elle s'exporte et se vérifie.
        let (saines, _, _) = ledger_export_lines(&conn, 0, 0).expect("état de départ : chaîne saine");
        assert_eq!(ledger_verify_export(&saines, "").expect("saine"), 3);

        oss_abimer(&conn, ids[2]);
        assert_eq!(oss_compte(&conn, "ledger"), 3, "la ligne est TOUJOURS en base : illisible, pas absente");

        let message = ledger_export_lines(&conn, 0, 0)
            .map(|t| format!("{t:?}"))
            .expect_err("l'ancienne réponse était 2 lignes que le vérificateur déclarait Ok(2) — « intègre »");
        assert!(message.contains("ILLISIBLE"), "le refus NOMME ce qui n'a pas pu être lu : {message}");
        assert!(message.contains("curseur"), "et il dit que le curseur ne bouge pas : {message}");
    }

    /// (S4) SECONDE FORME, SOUS-CAS « LIGNE DU MILIEU » — ET UNE RÉFUTATION DE L'ÉNONCÉ FONDATEUR.
    ///
    /// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ QUI A OUVERT CETTE CLÉ : il disait qu'une ligne illisible rendait
    /// « deux maillons sur trois, ÉGALEMENT déclarés intègres ». MESURÉ le 2026-08-31, ce n'est vrai que
    /// du sous-cas (S3). Quand la ligne illisible est au MILIEU, les deux lignes rendues sont bel et bien
    /// REJETÉES par `ledger_verify_export` (`rupture de chaîne`, ancrage `prev_hash`) : le vérificateur
    /// d'export faisait son travail.
    ///
    /// CE QUI ÉTAIT VRAI, ET PIRE, C'EST LE CURSEUR — mesuré à 3 alors que le maillon #2 n'était PAS
    /// exporté. Le maillon sauté n'entrait donc JAMAIS dans la copie inaltérable : une lacune PERMANENTE,
    /// et non un blocage. Et le refus du vérificateur n'était lu par PERSONNE sur ce chemin :
    /// `ledger_sink_flush` écrit puis avance, il ne vérifie rien. Un instrument correct que personne
    /// n'interroge ne protège rien — c'est pourquoi la distinction est faite à la LECTURE.
    ///
    /// LES DEUX SOUS-CAS SONT SÉPARÉS ICI parce qu'ils ne rougissaient pas pour la même raison : un
    /// correctif qui n'aurait fermé que (S3) laisserait ce témoin vert par accident.
    #[test]
    fn une_ligne_illisible_au_milieu_refuse_l_export_au_lieu_de_sauter_le_maillon() {
        let conn = oss_journal_vierge();
        for i in 0..3 {
            ledger_append(&conn, "config.mode", &format!("maillon {i}"));
        }
        let ids = oss_ids(&conn);
        oss_abimer(&conn, ids[1]);

        let message = ledger_export_lines(&conn, 0, 0)
            .map(|t| format!("{t:?}"))
            .expect_err("l'ancienne réponse était 2 lignes AVEC UN CURSEUR À 3 : le maillon #2 n'entrait jamais dans la copie");
        assert!(message.contains("ILLISIBLE"), "le refus NOMME ce qui n'a pas pu être lu : {message}");
        assert!(message.contains("#2"), "et il nomme le RANG dans la tranche, pas l'id qu'on n'a pas su lire : {message}");
    }

    /// (S5) LE SEUL NULLABLE DE LA TABLE RESTE EXPORTÉ, et c'est la frontière du refus.
    ///
    /// `ledger.detail` est nullable au schéma (les quatre autres colonnes lues sont `NOT NULL`). Un NULL
    /// se LIT : il vaut chaîne vide, exactement comme en production. Un correctif qui l'aurait lu en
    /// `String` aurait transformé un maillon LÉGITIME en refus d'export — c'est-à-dire troqué le faux vert
    /// contre un mutisme, ce que ce lot refuse explicitement.
    #[test]
    fn un_maillon_sans_detail_reste_exporte_et_verifie() {
        let conn = oss_journal_vierge();
        ledger_append(&conn, "config.mode", "maillon 0");
        let prev: String = conn
            .query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("tête lisible");
        let (ts, kind) = (now(), "config.mode");
        conn.execute(
            "INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,NULL,?3,?4)",
            params![ts, kind, prev, sha256_hex(format!("{prev}|{ts}|{kind}|").as_bytes())],
        )
        .expect("maillon sans detail inséré");

        let (lignes, _, _) = ledger_export_lines(&conn, 0, 0).expect("un `detail` NULL se LIT : il ne refuse rien");
        assert_eq!(lignes.len(), 2, "le maillon sans `detail` est EXPORTÉ, pas retiré ni refusé");
        assert_eq!(ledger_verify_export(&lignes, "").expect("et la copie se vérifie"), 2);
    }

    // ------------------------------------------------------------------------------------------------
    // (S bis) LE CURSEUR, PAR LA ROUTE RÉELLE. C'est le point le plus coûteux de la clé : il ne se prouve
    // pas sur le cœur seul, parce que c'est `ledger_sink_flush` qui décide d'avancer.
    // ------------------------------------------------------------------------------------------------

    fn oss_sink_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = ff_tmp_path(tag);
        {
            let conn = open_db(chemin.as_str()).expect("base créée");
            conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
            assert!(migrate(&conn), "fixture : migrations complètes");
            conn.execute("DELETE FROM ledger", []).expect("journal vidé");
            conn.execute(
                "INSERT INTO ledger_sink(name,kind,target,enabled,last_id,last_hash) VALUES('worm','stdout','',1,0,'')",
                [],
            )
            .expect("sink déclaré");
        }
        (ds_file_state(chemin.as_str()), chemin)
    }

    fn oss_au_admin() -> AuthUser {
        AuthUser {
            name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn oss_curseur(st: &AppState) -> (i64, String) {
        let conn = st.db.lock();
        conn.query_row("SELECT last_id,last_hash FROM ledger_sink WHERE name='worm'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("curseur lisible")
    }

    /// (S6) LE CURSEUR N'AVANCE PAS SUR UNE TRANCHE QU'ON N'A PAS SU LIRE — ET IL AVANCE QUAND ELLE EST LUE.
    ///
    /// LES DEUX SENS SONT DANS LE MÊME TÉMOIN, ET C'EST VOULU : un flush qui refuserait TOUJOURS gèlerait
    /// la copie WORM aussi sûrement que l'ancien défaut la trouait. Le sens 1 (nominal) l'interdit.
    ///
    /// LA TRANCHE DE SENS 2 PORTE SON MAILLON ILLISIBLE AU MILIEU, ET C'EST LE POINT DU TÉMOIN : c'est la
    /// SEULE forme où l'ancien code AVANÇAIT le curseur. `flatten()` rendait alors les deux maillons
    /// ENCADRANTS et `last_id` sautait jusqu'au DERNIER — la route répondait `{"ok":true,"exported":2}`,
    /// écrivait une copie TROUÉE, et le maillon du milieu n'y entrait plus JAMAIS : les envois suivants
    /// n'ont plus rien à dire. Une tranche dont c'est la DERNIÈRE ligne qui est illisible se contentait,
    /// elle, de GELER la copie (rendue vide, curseur immobile) — c'est (S3) qui la couvre, au cœur.
    ///
    /// LE TÉMOIN EXIGE LES DEUX : un `500` ET un curseur INCHANGÉ. La tranche sera RE-TENTÉE une fois la
    /// ligne redevenue lisible : at-least-once préservé, aucun trou définitif.
    #[tokio::test]
    async fn le_flux_d_export_n_avance_pas_son_curseur_sur_une_tranche_illisible() {
        let (st, _garde) = oss_sink_state("oss-sink");
        let ids = {
            let conn = st.db.lock();
            for i in 0..3 {
                ledger_append(&conn, "config.mode", &format!("maillon {i}"));
            }
            oss_ids(&conn)
        };

        // SENS 1 — NOMINAL : la tranche se lit, le sink reçoit, le curseur AVANCE.
        let r = ledger_sink_flush(State(st.clone()), Extension(oss_au_admin()), Path(1)).await;
        assert_eq!(r.status().as_u16(), 200, "une tranche lisible s'exporte");
        assert_eq!(oss_curseur(&st).0, ids[2], "et le curseur avance jusqu'au dernier maillon LU");

        // SENS 2 — TROIS maillons neufs, celui du MILIEU illisible : la forme qui TROUAIT la copie.
        let saute = {
            let conn = st.db.lock();
            for i in 3..6 {
                ledger_append(&conn, "config.mode", &format!("maillon {i}"));
            }
            let tous = oss_ids(&conn);
            let milieu = tous[tous.len() - 2];
            oss_abimer(&conn, milieu);
            milieu
        };
        let avant = oss_curseur(&st);

        let r = ledger_sink_flush(State(st.clone()), Extension(oss_au_admin()), Path(1)).await;

        // LES DEUX PROPRIÉTÉS SONT RELEVÉES AVANT D'ÊTRE ASSERTÉES, et le CURSEUR passe en premier :
        // sinon le code de statut mordrait toujours le premier et l'ancrage du curseur — le plus coûteux
        // des deux — ne serait jamais celui qu'une mutation fait rougir. Mesuré : il l'était.
        let code = r.status().as_u16();
        let apres = oss_curseur(&st);
        assert_eq!(
            apres, avant,
            "le curseur NE BOUGE PAS : l'ancien code le poussait AU-DELÀ du maillon #{saute}, qui n'entrait \
             alors JAMAIS dans la copie inaltérable — une lacune permanente et silencieuse"
        );
        assert_eq!(
            code, 500,
            "et la tranche illisible rend une ERREUR — l'ancienne réponse était 200, `exported: 2`, sur une copie amputée"
        );
    }

    /// (S7) LA ROUTE DE LECTURE NE REND PLUS UN CORPS VIDE EN SUCCÈS SUR UNE CHAÎNE QU'ELLE N'A PAS LUE.
    ///
    /// LES DEUX SENS, ENCORE : un `200` à corps vide reste la réponse JUSTE quand la tranche demandée est
    /// réellement vide (`from_id` au-delà du dernier maillon) — l'y interdire serait la fausse accusation
    /// que ce lot refuse. C'est `200` + corps vide sur une chaîne ILLISIBLE qui devient `500` : sans quoi
    /// la sortie se sauvegarde, se vérifie (`Ok(0)`) et se classe comme une copie légitime.
    #[tokio::test]
    async fn la_route_d_export_distingue_une_tranche_vide_d_une_chaine_illisible() {
        let (st, _garde) = oss_sink_state("oss-route");
        let ids = {
            let conn = st.db.lock();
            for i in 0..2 {
                ledger_append(&conn, "config.mode", &format!("maillon {i}"));
            }
            oss_ids(&conn)
        };
        let q = |from: i64| Query(HashMap::from([("from_id".to_string(), from.to_string())]));

        // SENS 1 — tranche réellement VIDE : 200, corps vide, et c'est JUSTE.
        let r = ledger_export_get(State(st.clone()), Extension(oss_au_admin()), q(ids[1])).await;
        assert_eq!(r.status().as_u16(), 200, "rien de neuf reste un succès");
        let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps");
        assert!(corps.is_empty(), "et son corps est vide : {}", String::from_utf8_lossy(&corps));

        // SENS 2 — chaîne ILLISIBLE : plus de 200 à corps vide.
        {
            let conn = st.db.lock();
            oss_abimer(&conn, ids[0]);
        }
        let r = ledger_export_get(State(st.clone()), Extension(oss_au_admin()), q(0)).await;
        assert_eq!(
            r.status().as_u16(),
            500,
            "une chaîne illisible rend une ERREUR — l'ancienne réponse était 200 avec un corps VIDE, \
             qu'un vérificateur externe déclarait Ok(0)"
        );
    }
