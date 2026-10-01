// =====================================================================================
// `P10.27-k` — LA COPIE DU REGISTRE : UNE LIGNE RÉPÉTÉE À L'IDENTIQUE EST ÉCARTÉE ET DITE, UNE FOURCHE RESTE ACCUSÉE.
// `P10.27-l` — LE TÉLÉCHARGEMENT DU JOURNAL DE CONTRÔLE NE SORT QUE LE VALIDÉ.
//
// LE DÉFAUT DE `P10.27-k`, MESURÉ AVANT CORRECTIF (témoin `brev_` (7), 2026-09-24 ; reproduit le 2026-09-29 par la
// mutation qui retire la reconnaissance des répétitions) : un `COMMIT` refusé après l'écriture de la copie laisse le
// curseur du puits en arrière ; l'envoi suivant réécrit la tranche depuis l'ancien curseur. Le vérificateur hors ligne
// (`ledger-verify-export`) lisait la première ligne répétée comme une « rupture de chaîne » et sortait en « EXPORT
// COMPROMIS » (code 1) — le témoin `brev_` (7) de `P10.26-u` figeait ce verdict, la cause servie l'annonçait. Relancer
// `ledger-export --out` sur un fichier existant (ouverture en ajout) produisait la même accusation.
//
// LA RÈGLE (`copie_chainee`) : une ligne identique octet pour octet à une ligne déjà retenue est écartée et comptée, où
// qu'elle se trouve ; toute autre ligne passe par les deux ancrages. RÉFUTÉ le 2026-09-29, la première forme de la
// règle — une répétition devait être une tranche contiguë rejoignant la tête avant toute autre ligne : elle accusait des
// copies intègres (une tranche rejouée interrompue sur une fin de ligne puis réécrite, `1,2,3 | 1,2 | 1,2,3,4` ; des
// téléchargements recouvrants de bornes différentes), sans tenir aucune propriété de la chaîne. Le témoin (1) les
// porte désormais comme intègres, le témoin (2) garde accusé tout ce qui n'est pas une copie exacte, y compris juste
// après une répétition interrompue.
//
// LE DÉFAUT DE `P10.27-l`, MESURÉ LE 2026-09-29 PAR LA MUTATION DU TÉMOIN (5) — la route rendue à sa lecture sur
// l'écrivain (il était « lu, non mesuré ») : une transaction restée PENDANTE sur l'écrivain du plan de contrôle, un
// maillon ajouté dedans, et le téléchargement rendait DEUX lignes pour UN maillon validé. Le plan de contrôle n'a ni
// pool de lecture ni clé au registre des lectures : la tranche est lue sur une connexion NEUVE, en lecture seule, avec
// la clé du plan de contrôle — jamais relue sur l'écrivain quand cette lecture échoue (témoin (6)).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'aiguillage de `main` vers `commande_ledger_verify_export` (la suite n'exécute
// pas `main` ; le témoin (7) joue la sous-commande elle-même dans un processus, et mesure son code de sortie) ; une
// ligne TRONQUÉE au milieu (écriture interrompue hors d'une fin de ligne) reste un « JSON invalide », hors de cette
// clé ; l'identifiant d'un maillon n'est pas couvert par son hachage, donc une copie RENUMÉROTÉE dont la chaîne reste
// valide n'est pas vue — c'était vrai avant, rien ici ne l'aggrave ; que la lecture du plan de contrôle soit faite hors
// de l'exécuteur (`spawn_blocking`) n'est pas observable par un témoin, seul son résultat l'est ; aucun module de
// `web/` n'est exercé.
// =====================================================================================
mod copie_du_registre_doublon_exact_et_journal_de_controle_valide {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Une chaîne du registre écrite par le chemin de production (`ledger_append`) et exportée par le chemin de
    /// production (`ledger_export_lines`) : `n` lignes, dans l'ordre.
    fn cdej_chaine_du_registre(n: usize) -> Vec<String> {
        let conn = test_db();
        for i in 0..n {
            ledger_append(&conn, "config.cdej", &format!("maillon {i}"));
        }
        let (lignes, _, _) = ledger_export_lines(&conn, 0, 0).expect("fixture : la chaîne s'exporte");
        assert_eq!(lignes.len(), n, "fixture : {n} maillons exportés");
        lignes
    }

    /// Une FOURCHE de `ligne` : même identifiant, même prédécesseur, autre `detail`, et un hachage recalculé qui la
    /// rend cohérente avec elle-même — ce qu'un faussaire soigneux écrirait à la place du maillon.
    fn cdej_fourche_du_registre(ligne: &str, detail: &str) -> String {
        let v: Value = serde_json::from_str(ligne).expect("fixture : ligne JSON");
        let (id, ts) = (v["id"].as_i64().expect("id"), v["ts"].as_i64().expect("ts"));
        let (kind, prev) = (v["kind"].as_str().expect("kind"), v["prev_hash"].as_str().expect("prev_hash"));
        let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
        ledger_export_line(id, ts, kind, detail, prev, &hash)
    }

    /// Assemble une copie à partir des rangs (0-based) de `chaine`, dans l'ordre donné.
    fn cdej_copie(chaine: &[String], rangs: &[usize]) -> Vec<String> {
        rangs.iter().map(|&r| chaine[r].clone()).collect()
    }

    fn cdej_id(ligne: &str) -> i64 {
        serde_json::from_str::<Value>(ligne).expect("fixture : ligne JSON")["id"].as_i64().expect("id")
    }

    fn cdej_verifiee(maillons: usize, lignes_repetees: usize, reprises: usize, reprise_inachevee: bool) -> crate::governance::CopieChaineeVerifiee {
        crate::governance::CopieChaineeVerifiee { maillons, lignes_repetees, reprises, reprise_inachevee }
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.27-k` — DES LIGNES RÉPÉTÉES À L'IDENTIQUE, OÙ QU'ELLES SOIENT, SE VÉRIFIENT ET SE COMPTENT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur cinq maillons écrits par le chemin de production :
    ///  * la forme de l'envoi dont le `COMMIT` a été refusé — `1,2,3` puis `2,3` rejoués depuis l'ancien curseur, suivis de
    ///    `4,5` neufs : cinq maillons, deux lignes répétées, une reprise ;
    ///  * deux refus de suite — `2,3` rejoués DEUX fois : deux reprises, quatre lignes répétées ;
    ///  * `ledger-export --out` relancé sur le même fichier — la chaîne entière deux fois : cinq répétées, une reprise ;
    ///  * une copie qui s'ARRÊTE au milieu d'une reprise : intègre, et le verdict le porte ;
    ///  * LES FORMES QUE LA PREMIÈRE RÈGLE ACCUSAIT À TORT : une tranche rejouée interrompue sur une fin de ligne puis
    ///    réécrite (`1,2,3 | 1,2 | 1,2,3,4`) ; des téléchargements recouvrants de bornes différentes (`1..4`, `3`, `5`) ;
    ///    un maillon neuf juste après une répétition qui n'a pas rejoint la tête (`1,2,3,2,4`) ; une répétition qui
    ///    revient en arrière (`1,2,3,2,1`) — chaque ligne écartée y est une copie exacte, chaque ligne retenue s'accroche ;
    ///  * le compte de `ledger_verify_export` est celui des maillons distincts ;
    ///  * la phrase de `ledger-verify-export` : code 0, elle COMPTE les répétitions ; TÉMOIN NÉGATIF — sans répétition, la
    ///    phrase d'avant, octet pour octet, et aucun mot de répétition.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : la reconnaissance des répétitions retirée — la première copie rejouée est lue
    /// comme une « rupture de chaîne » ; la règle stricte rétablie (une répétition doit rejoindre la tête avant toute autre
    /// ligne) — la tranche rejouée interrompue puis réécrite est accusée.
    #[test]
    fn cdej_une_tranche_rejouee_puis_des_maillons_neufs_se_verifie_et_se_dit() {
        let c = cdej_chaine_du_registre(5);
        let verifier = |rangs: &[usize]| crate::governance::verifier_la_copie_du_registre(&cdej_copie(&c, rangs), "");

        assert_eq!(verifier(&[0, 1, 2, 1, 2, 3, 4]), Ok(cdej_verifiee(5, 2, 1, false)), "tranche rejouée depuis l'ancien curseur, puis maillons neufs");
        assert_eq!(verifier(&[0, 1, 2, 1, 2, 1, 2, 3, 4]), Ok(cdej_verifiee(5, 4, 2, false)), "deux refus de suite : deux reprises");
        assert_eq!(verifier(&[0, 1, 2, 3, 4, 0, 1, 2, 3, 4]), Ok(cdej_verifiee(5, 5, 1, false)), "un export complet relancé sur le même fichier");
        assert_eq!(verifier(&[0, 1, 2, 3, 4, 4]), Ok(cdej_verifiee(5, 1, 1, false)), "la tête seule, répétée : la reprise est close aussitôt");
        assert_eq!(verifier(&[0, 1, 2, 1]), Ok(cdej_verifiee(3, 1, 1, true)), "une copie qui s'arrête pendant une reprise : rien n'y manque, et c'est porté");
        assert_eq!(ledger_verify_export(&cdej_copie(&c, &[0, 1, 2, 1, 2, 3, 4]), ""), Ok(5), "le compte est celui des maillons DISTINCTS");

        assert_eq!(
            verifier(&[0, 1, 2, 0, 1, 0, 1, 2, 3]),
            Ok(cdej_verifiee(4, 5, 2, false)),
            "une tranche rejouée interrompue sur une fin de ligne, puis réécrite en entier par l'envoi suivant : intègre"
        );
        assert_eq!(verifier(&[0, 1, 2, 3, 2, 4]), Ok(cdej_verifiee(5, 1, 1, false)), "trois téléchargements recouvrants de bornes différentes, bout à bout");
        assert_eq!(verifier(&[0, 1, 2, 1, 3]), Ok(cdej_verifiee(4, 1, 1, false)), "un maillon neuf, accroché à la tête, juste après une répétition inachevée");
        assert_eq!(verifier(&[0, 1, 2, 1, 0]), Ok(cdej_verifiee(3, 2, 2, true)), "une répétition qui revient en arrière : deux reprises, la dernière inachevée");

        let (code, phrase) = crate::governance::verdict_hors_ligne_de_la_copie_du_registre(&cdej_copie(&c, &[0, 1, 2, 1, 2, 3, 4]), "");
        assert_eq!(code, 0, "une copie qui porte une répétition exacte est intègre : {phrase}");
        assert!(
            phrase.starts_with("export OK : 5 entrées chaînées intègres (vérifié hors-ligne) ; 2 ligne(s) RÉPÉTÉE(S) À L'IDENTIQUE écartée(s), en 1 reprise(s)"),
            "la phrase COMPTE les répétitions et les reprises : {phrase}"
        );
        assert!(phrase.contains("ni des événements distincts, ni une altération") && !phrase.contains("se termine au milieu"), "{phrase}");
        let (_, inachevee) = crate::governance::verdict_hors_ligne_de_la_copie_du_registre(&cdej_copie(&c, &[0, 1, 2, 1]), "");
        assert!(inachevee.contains("se termine au milieu d'une reprise"), "la reprise inachevée est dite : {inachevee}");

        let (code, phrase) = crate::governance::verdict_hors_ligne_de_la_copie_du_registre(&c, "");
        assert_eq!(
            (code, phrase.as_str()),
            (0, "export OK : 5 entrées chaînées intègres (vérifié hors-ligne)"),
            "TÉMOIN NÉGATIF : sans répétition, la phrase d'avant, octet pour octet"
        );
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.27-k` — CE QUI N'EST PAS UNE COPIE EXACTE RESTE ACCUSÉ, Y COMPRIS JUSTE APRÈS UNE RÉPÉTITION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : chaque forme d'altération qu'une règle trop large laisserait passer rend une ERREUR nommée, et la
    /// phrase de `ledger-verify-export` sort en code 1 « EXPORT COMPROMIS » :
    ///  * une FOURCHE dans la reprise (`1,2,3` puis `2` et le maillon 3 réécrit, hachage recalculé) ;
    ///  * une fourche hors reprise (le maillon 2 réécrit, accroché au maillon 1, après la tête) ;
    ///  * une ligne de même identifiant ET de même hachage mais d'un autre contenu ;
    ///  * une ligne qui ne diffère d'une ligne vérifiée que par UN octet (espace final) : pas une répétition exacte ;
    ///  * une suppression (`1,2,4,5`) et une réorganisation (`1,3,2`) : rupture, sans mot de fourche ;
    ///  * une SUPPRESSION juste après une répétition interrompue (`1,2,3,2,5` : le maillon 4 manque) et une
    ///    RÉORGANISATION après une répétition close (`1,2,3,2,3,5,4`) : rupture, et la première dit la répétition
    ///    interrompue qu'elle rompt ;
    ///  * un maillon neuf ALTÉRÉ (contenu changé, hachage porté conservé : seul le recalcul l'accuse) : « hash altéré »,
    ///    sans répétition comme avant, juste après une répétition INTERROMPUE (`1,2,3,2,4'`) et juste après une répétition
    ///    CLOSE (`1,2,3,2,3,4'`) — le `prev_hash` de ces trois lignes est juste, c'est le recalcul qui porte l'accusation.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : la répétition reconnue par l'IDENTIFIANT au lieu du texte exact — les fourches
    /// passent ; une ligne qui interrompt une répétition écartée sans passer par les ancrages — la suppression qui suit
    /// une répétition interrompue, et la fourche dans la reprise, passent ; le RECALCUL relâché sur la ligne qui
    /// interrompt une répétition (`retenues.interrompue.is_none() && …`) — le maillon altéré qui suit la répétition
    /// interrompue passe ; le recalcul relâché après une répétition close (`(retenues.reprises == 0 ||
    /// retenues.interrompue.is_some()) && …`) — le maillon altéré qui suit la répétition close passe.
    #[test]
    fn cdej_une_fourche_une_suppression_une_reorganisation_et_une_alteration_restent_accusees_meme_apres_une_repetition() {
        let c = cdej_chaine_du_registre(5);
        let (id2, id3, id4, id5) = (cdej_id(&c[1]), cdej_id(&c[2]), cdej_id(&c[3]), cdej_id(&c[4]));
        let verifier = |copie: &[String]| crate::governance::verifier_la_copie_du_registre(copie, "");
        let accuse = |copie: &[String], mots: &[&str], quoi: &str| {
            let verdict = verifier(copie);
            let e = verdict.clone().expect_err(&format!("{quoi} : ACCUSÉ ({verdict:?})"));
            for m in mots {
                assert!(e.contains(m), "{quoi} : l'accusation nomme « {m} » : {e}");
            }
            let (code, phrase) = crate::governance::verdict_hors_ligne_de_la_copie_du_registre(copie, "");
            assert_eq!(code, 1, "{quoi} : `ledger-verify-export` sort en 1 : {phrase}");
            assert!(phrase.starts_with("EXPORT COMPROMIS : "), "{quoi} : {phrase}");
            e
        };

        let mut dans_la_reprise = cdej_copie(&c, &[0, 1, 2, 1]);
        dans_la_reprise.push(cdej_fourche_du_registre(&c[2], "maillon RÉÉCRIT"));
        accuse(&dans_la_reprise, &["fourche", &format!("entrée #{id3}")], "fourche dans la reprise");

        let mut hors_reprise = cdej_copie(&c, &[0, 1, 2]);
        hors_reprise.push(cdej_fourche_du_registre(&c[1], "maillon RÉÉCRIT"));
        accuse(&hors_reprise, &["rupture de chaîne", "fourche", &format!("entrée #{id2}")], "fourche hors reprise");

        let v2: Value = serde_json::from_str(&c[1]).expect("ligne JSON");
        let meme_hachage = ledger_export_line(id2, v2["ts"].as_i64().expect("ts"), v2["kind"].as_str().expect("kind"), "FALSIFIÉ", v2["prev_hash"].as_str().expect("prev"), v2["hash"].as_str().expect("hash"));
        let mut meme_id_meme_hachage = cdej_copie(&c, &[0, 1, 2]);
        meme_id_meme_hachage.push(meme_hachage);
        accuse(&meme_id_meme_hachage, &["fourche"], "même id, même hachage, autre contenu");

        let mut un_octet = cdej_copie(&c, &[0, 1, 2]);
        un_octet.push(format!("{} ", c[1]));
        accuse(&un_octet, &["rupture de chaîne"], "un octet de différence");

        let suppression = accuse(&cdej_copie(&c, &[0, 1, 3, 4]), &["rupture de chaîne"], "suppression");
        assert!(!suppression.contains("fourche"), "une suppression n'est pas une fourche : {suppression}");
        accuse(&cdej_copie(&c, &[0, 2, 1]), &["rupture de chaîne"], "réorganisation");
        let apres_repetition = accuse(
            &cdej_copie(&c, &[0, 1, 2, 1, 4]),
            &["rupture de chaîne", &format!("entrée #{id5}"), "une tranche répétée s'interrompt ici", &format!("entrée #{id3} attendue")],
            "suppression juste après une répétition interrompue",
        );
        assert!(!apres_repetition.contains("fourche"), "{apres_repetition}");
        accuse(&cdej_copie(&c, &[0, 1, 2, 1, 2, 4, 3]), &["rupture de chaîne"], "réorganisation après une répétition close");

        // LE MAILLON 4 ALTÉRÉ : contenu changé, hachage PORTÉ conservé, `prev_hash` juste — seul le recalcul l'accuse.
        let v4: Value = serde_json::from_str(&c[3]).expect("ligne JSON");
        let quatre_altere = ledger_export_line(id4, v4["ts"].as_i64().expect("ts"), "config.cdej", "FALSIFIÉ", v4["prev_hash"].as_str().expect("prev"), v4["hash"].as_str().expect("hash"));
        let mut altere = c.clone();
        altere[3] = quatre_altere.clone();
        accuse(&altere, &["hash altéré"], "maillon neuf altéré");

        let mut altere_apres_interrompue = cdej_copie(&c, &[0, 1, 2, 1]);
        altere_apres_interrompue.push(quatre_altere.clone());
        accuse(&altere_apres_interrompue, &["hash altéré", &format!("entrée #{id4}")], "maillon altéré juste après une répétition INTERROMPUE");
        let mut altere_apres_close = cdej_copie(&c, &[0, 1, 2, 1, 2]);
        altere_apres_close.push(quatre_altere);
        accuse(&altere_apres_close, &["hash altéré", &format!("entrée #{id4}")], "maillon altéré juste après une répétition CLOSE");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.27-k` — LE JOURNAL DE CONTRÔLE SUIT LA MÊME RÈGLE, ÉCRITE UNE FOIS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : quatre maillons du journal de contrôle écrits par `control_ledger_append`, exportés par
    /// `control_ledger_export_lines`. Deux téléchargements recouvrants mis bout à bout (`1..4` puis `3,4`) : quatre
    /// maillons, deux répétées ; le maillon 3 réécrit (tenant changé, hachage recalculé selon la recette du journal de
    /// contrôle) dans la reprise : fourche accusée. PAR LA ROUTE, un cinquième maillon écrit, trois téléchargements
    /// recouvrants de bornes différentes (`from_id=0&limit=4`, `from_id=2&limit=1`, puis tout ce qui suit le quatrième)
    /// mis bout à bout se vérifient : cinq maillons, une ligne répétée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : la règle stricte rétablie — le troisième téléchargement, qui n'est pas la suite de
    /// la répétition du maillon 3, est accusé.
    #[tokio::test]
    async fn cdej_le_journal_de_controle_suit_la_meme_regle() {
        // La route lit la clé du plan de contrôle dans l'environnement du processus : même verrou que ses lecteurs.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        assert!(crate::state::control_key().is_none(), "précondition : aucun PLUME_CONTROL_KEY dans l'environnement de la suite");
        let (cp, _cptmp) = mk_test_control();
        let st = tenant_test_state("cdej-adm", "cdej-edi", "cdej-sa", Some(cp));
        for i in 0..4 {
            assert!(control_ledger_append(&st, "test.cdej", "cdej-sa", "tenant-x", &format!("geste {i}")).cause_de_non_inscription().is_none(), "fixture : maillon inscrit");
        }
        let c = {
            let cp = st.tenants.control.as_ref().expect("plan de contrôle");
            let conn = cp.conn.lock();
            crate::governance::control_ledger_export_lines(&conn, 0, 0).expect("fixture : la chaîne s'exporte").0
        };
        assert_eq!(c.len(), 4, "fixture : quatre maillons");
        let mut recouvrante = c.clone();
        recouvrante.extend(cdej_copie(&c, &[2, 3]));
        assert_eq!(crate::governance::verifier_la_copie_du_journal_de_controle(&recouvrante, ""), Ok(cdej_verifiee(4, 2, 1, false)));
        assert_eq!(crate::governance::control_ledger_verify_export(&recouvrante, ""), Ok(4), "maillons distincts");

        let v: Value = serde_json::from_str(&c[2]).expect("ligne JSON");
        let (id, ts, prev) = (v["id"].as_i64().expect("id"), v["ts"].as_i64().expect("ts"), v["prev_hash"].as_str().expect("prev"));
        let (kind, actor, detail) = (v["kind"].as_str().expect("kind"), v["actor"].as_str().expect("actor"), v["detail"].as_str().expect("detail"));
        let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{actor}|AUTRE-TENANT|{detail}").as_bytes());
        let mut fourchue = c.clone();
        fourchue.extend(cdej_copie(&c, &[1]));
        fourchue.push(crate::governance::control_ledger_export_line(id, ts, kind, actor, "AUTRE-TENANT", detail, prev, &hash));
        let e = crate::governance::verifier_la_copie_du_journal_de_controle(&fourchue, "").expect_err("une fourche du journal de contrôle est accusée");
        assert!(e.contains("fourche") && e.contains(&format!("entrée #{id}")), "{e}");

        assert!(control_ledger_append(&st, "test.cdej", "cdej-sa", "tenant-x", "geste 4").cause_de_non_inscription().is_none(), "fixture : cinquième maillon");
        let (id2, id4) = (cdej_id(&c[1]), cdej_id(&c[3]));
        let mut bout_a_bout = Vec::new();
        for parametres in [vec![("from_id", "0".to_string()), ("limit", "4".to_string())], vec![("from_id", id2.to_string()), ("limit", "1".to_string())], vec![("from_id", id4.to_string())]] {
            let (statut, _, corps) = cdej_telecharger_avec(&st, &parametres).await;
            assert_eq!(statut, 200, "téléchargement {parametres:?} : {corps}");
            bout_a_bout.extend(cdej_lignes(&corps));
        }
        assert_eq!(bout_a_bout.len(), 6, "fixture : quatre lignes, puis la troisième, puis la cinquième");
        assert_eq!(bout_a_bout[..4], c[..], "fixture : le premier téléchargement est la chaîne exportée");
        assert_eq!(
            crate::governance::verifier_la_copie_du_journal_de_controle(&bout_a_bout, ""),
            Ok(cdej_verifiee(5, 1, 1, false)),
            "trois téléchargements recouvrants de bornes différentes, mis bout à bout, se vérifient"
        );
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.27-k` — DE BOUT EN BOUT : L'ENVOI DONT LE COMMIT EST REFUSÉ, PUIS L'ENVOI SUIVANT, PUIS LE VERDICT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la vraie route `ledger_sink_flush` et un puits `file` : un maillon validé ; `COMMIT` refusé
    /// (autorisateur) — 503 `CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE`, la tranche est dans la copie ; deux maillons neufs ;
    /// l'envoi suivant rend 200 `exported: 3` et la copie porte QUATRE lignes (le maillon 1 deux fois, puis 2 et 3). Le
    /// verdict hors ligne est intègre, compte une ligne répétée et une reprise — ce que la cause servie annonce, et elle
    /// n'annonce plus de rupture.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : la reconnaissance des répétitions retirée — « EXPORT COMPROMIS », code 1.
    #[tokio::test]
    async fn cdej_apres_un_commit_refuse_la_copie_de_l_envoi_suivant_se_verifie() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let racine = crate::tmp_possede::TmpPossede::neuf("cdej-puits");
        let _pose = ReglageBackupPose::neuf("PLUME_LEDGER_EXPORT_DIR", &racine.to_string_lossy());
        let (st, _p) = sp_state("cdej-puits");
        let copie = racine.join("cdej-puits.jsonl");
        let id = {
            let c = st.db.lock();
            c.execute("DELETE FROM ledger", []).expect("fixture : registre vidé");
            ledger_append(&c, "config.cdej", "maillon validé 1");
            c.execute(
                "INSERT INTO ledger_sink(name,kind,target,enabled,last_id,last_hash) VALUES('worm','file',?1,1,0,'')",
                params![copie.to_string_lossy()],
            )
            .expect("fixture : puits déclaré");
            c.last_insert_rowid()
        };
        let envoyer = |st: AppState| async move {
            let r = ledger_sink_flush(State(st), Extension(sp_au("adm", "admin")), axum::extract::Path(id)).await;
            let statut = r.status().as_u16();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            (statut, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null))
        };
        let lignes = || -> Vec<String> {
            std::fs::read_to_string(&copie).unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()
        };

        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = envoyer(st.clone()).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "fixture : le COMMIT de l'envoi est refusé : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE), "{corps}");
        assert_eq!(lignes().len(), 1, "fixture : la tranche est dans la copie");

        {
            let c = st.db.lock();
            ledger_append(&c, "config.cdej", "maillon validé 2");
            ledger_append(&c, "config.cdej", "maillon validé 3");
        }
        let (statut, corps) = envoyer(st.clone()).await;
        assert_eq!((statut, corps["exported"].clone()), (200, json!(3)), "l'envoi suivant rejoue depuis l'ancien curseur : {corps}");
        let copie_lue = lignes();
        assert_eq!(copie_lue.len(), 4, "le maillon 1 deux fois, puis 2 et 3");
        assert_eq!(copie_lue[0], copie_lue[1], "la répétition est exacte, octet pour octet");

        assert_eq!(crate::governance::verifier_la_copie_du_registre(&copie_lue, ""), Ok(cdej_verifiee(3, 1, 1, false)));
        let (code, phrase) = crate::governance::verdict_hors_ligne_de_la_copie_du_registre(&copie_lue, "");
        assert_eq!(code, 0, "la copie est intègre : {phrase}");
        assert!(phrase.contains("1 ligne(s) RÉPÉTÉE(S) À L'IDENTIQUE"), "et le verdict la compte : {phrase}");
        assert!(
            CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE.contains("reconnaît cette tranche répétée à l'identique") && !CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE.contains("rupture"),
            "la cause servie dit ce que fait le vérificateur, et n'annonce plus de rupture"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.27-l` — LE TÉLÉCHARGEMENT DU JOURNAL DE CONTRÔLE NE SORT QUE LE VALIDÉ
    // -------------------------------------------------------------------------------------

    fn cdej_adm() -> AuthUser {
        sp_au("cdej-adm", "admin")
    }

    /// Un téléchargement par la vraie route, avec ses paramètres de requête : (statut, tête annoncée, corps).
    async fn cdej_telecharger_avec(st: &AppState, parametres: &[(&str, String)]) -> (u16, Option<String>, String) {
        let q: HashMap<String, String> = parametres.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        let r = control_ledger_export_get(State(st.clone()), Extension(cdej_adm()), Query(q)).await;
        let tete = r.headers().get("x-plume-ledger-last-id").and_then(|v| v.to_str().ok()).map(String::from);
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, tete, String::from_utf8_lossy(&b).into_owned())
    }

    async fn cdej_telecharger(st: &AppState) -> (u16, Option<String>, String) {
        cdej_telecharger_avec(st, &[]).await
    }

    fn cdej_lignes(corps: &str) -> Vec<String> {
        corps.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()
    }

    /// CE QU'IL TIENT : un plan de contrôle en WAL (sa forme de production), un maillon validé, puis une transaction
    /// laissée PENDANTE sur l'écrivain avec un maillon ajouté dedans. Le téléchargement rend 200 et UNE ligne, la tête
    /// annoncée est le maillon validé, la copie se vérifie ; la transaction est toujours pendante, et l'écrivain voit
    /// toujours ses deux maillons (le téléchargement n'a rien fermé). TÉMOIN POSITIF : la transaction validée, le
    /// téléchargement suivant rend les DEUX lignes — la lecture voit le validé, elle n'est ni figée ni vide.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : la tranche relue sous `cp.conn.lock()` (la forme d'avant) — deux lignes pendant
    /// la transaction pendante.
    #[tokio::test]
    async fn cdej_le_telechargement_du_journal_de_controle_ne_sort_que_le_valide() {
        // La route lit la clé du plan de contrôle dans l'environnement du processus : même verrou que ses lecteurs.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        assert!(crate::state::control_key().is_none(), "précondition : aucun PLUME_CONTROL_KEY dans l'environnement de la suite");
        let (cp, _cptmp) = mk_test_control();
        cp.conn.lock().execute_batch("PRAGMA journal_mode=WAL;").expect("fixture : WAL, comme `init_control_plane`");
        let st = tenant_test_state("cdej-adm", "cdej-edi", "cdej-sa", Some(cp));
        assert!(control_ledger_append(&st, "test.cdej", "cdej-sa", "tenant-x", "geste validé").cause_de_non_inscription().is_none(), "fixture");
        let cp = st.tenants.control.as_ref().expect("plan de contrôle").clone();
        let valide: i64 = cp.conn.lock().query_row("SELECT MAX(id) FROM control_ledger", [], |r| r.get(0)).expect("fixture");

        cp.conn.lock().execute_batch("BEGIN IMMEDIATE").expect("fixture : la transaction d'un autre geste s'ouvre");
        assert!(control_ledger_append(&st, "test.cdej", "cdej-sa", "tenant-x", "geste JAMAIS validé").cause_de_non_inscription().is_none(), "fixture : maillon écrit dans la transaction pendante");

        let (statut, tete, corps) = cdej_telecharger(&st).await;
        let (pendante, vus_par_l_ecrivain) = {
            let c = cp.conn.lock();
            (!c.is_autocommit(), c.query_row("SELECT COUNT(*) FROM control_ledger", [], |r| r.get::<_, i64>(0)).expect("lecture de l'écrivain"))
        };
        assert_eq!(statut, 200, "le téléchargement se lit : {corps}");
        let lignes = cdej_lignes(&corps);
        assert_eq!(lignes.len(), 1, "UNE ligne : le maillon jamais validé ne sort pas : {corps}");
        assert_eq!(tete, Some(valide.to_string()), "la tête annoncée est le dernier maillon VALIDÉ");
        assert_eq!(crate::governance::control_ledger_verify_export(&lignes, ""), Ok(1), "et la copie se vérifie");
        assert!(pendante, "la transaction de l'autre geste n'est pas fermée par le téléchargement");
        assert_eq!(vus_par_l_ecrivain, 2, "ni annulée : l'écrivain voit toujours ses deux maillons");

        cp.conn.lock().execute_batch("COMMIT").expect("fixture : l'autre geste valide sa transaction");
        let (statut, tete, corps) = cdej_telecharger(&st).await;
        let lignes = cdej_lignes(&corps);
        assert_eq!((statut, lignes.len()), (200, 2), "TÉMOIN POSITIF : validé, le maillon sort : {corps}");
        assert_eq!(tete, Some((valide + 1).to_string()), "et la tête avance");
        assert_eq!(crate::governance::control_ledger_verify_export(&lignes, ""), Ok(2));
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.27-l` — LA LECTURE DU PLAN DE CONTRÔLE : SA CLÉ, SA LECTURE SEULE, ET SES REFUS, JUSQU'À LA ROUTE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur un plan de contrôle CHIFFRÉ dont l'écrivain reste ouvert :
    ///  * par la fonction de lecture : avec sa clé, elle rend la tranche ; sans clé ou avec une autre, elle REFUSE (jamais
    ///    une tranche vide) ; une écriture par cette connexion est refusée et la ligne reste ; un fichier absent est
    ///    refusé et n'est pas créé ;
    ///  * PAR LA ROUTE, la clé posée dans l'environnement comme en production (`PLUME_CONTROL_KEY`) : 200 et la ligne ; une
    ///    AUTRE clé dans l'environnement : 500 nommé ;
    ///  * PAR LA ROUTE, un plan de contrôle ILLISIBLE (chemin absent) dont l'ÉCRIVAIN, lui, lit très bien — il porte le
    ///    maillon validé et, dans une transaction pendante, un second : 500 nommé, jamais un 200. Que l'écrivain lise est
    ///    vérifié dans le même témoin (deux maillons vus) : une relecture sur lui rendrait 200 ;
    ///  * aucun de ces deux 500 — servis à un administrateur de TENANT, la route ne demande que `is_admin` — ne porte la
    ///    clé du plan de contrôle (celle de la PLATEFORME), ni son chemin sur le serveur.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : la clé non appliquée (`appliquer_une_cle_explicite` sans effet) — la lecture avec
    /// la clé refuse ; la route qui ne passe pas la clé du plan de contrôle à sa lecture — 500 au lieu de 200 ; la route
    /// qui, sa lecture dédiée refusée, relit sur l'écrivain — 200 au lieu de 500 ; la route qui ajoute la clé au texte de
    /// son erreur — la clé est servie ; l'erreur d'ouverture du moteur recopiée (`({e})`) — rusqlite y ajoute le chemin
    /// ABSOLU du fichier (`SQLITE_CANTOPEN`), qui est servi.
    /// CE QU'IL NE TIENT PAS : `query_only` seul n'est pas éprouvable — l'ouverture `SQLITE_OPEN_READ_ONLY` refuse déjà
    /// l'écriture (retirer l'un des deux laisse ce témoin vert ; il faut retirer les deux).
    #[tokio::test]
    async fn cdej_la_lecture_du_plan_de_controle_applique_sa_cle_et_refuse_sans_elle() {
        const CLE: &str = "cle-de-test-du-plan-de-controle";
        let p = crate::tmp_possede::TmpDb::neuf("cdej-cle");
        // L'écrivain reste OUVERT pendant les lectures, comme en production (le démon le tient tout au long).
        let ecrivain = open_db_keyed(p.as_str(), Some(CLE)).expect("fixture : plan de contrôle chiffré");
        migrate_control(&ecrivain);
        ecrivain.execute_batch("PRAGMA journal_mode=WAL;").expect("fixture : WAL");
        ecrivain.execute("INSERT INTO control_ledger(ts,kind,actor,tenant,detail,prev_hash,hash) VALUES(1,'test.cdej','sa','t','d','','h')", []).expect("fixture : un maillon");
        let lire = |cle: Option<&str>| {
            crate::state::lecture_validee_du_plan_de_controle(p.as_str(), cle)
                .and_then(|c| crate::governance::control_ledger_export_lines(&c, 0, 0))
                .map(|(lignes, _, _)| lignes.len())
        };
        assert_eq!(lire(Some(CLE)), Ok(1), "avec sa clé, la lecture rend la tranche");
        assert!(lire(None).is_err(), "sans clé : REFUS, jamais une tranche vide ({:?})", lire(None));
        assert!(lire(Some("une-autre-cle")).is_err(), "une autre clé : REFUS");

        let lecture = crate::state::lecture_validee_du_plan_de_controle(p.as_str(), Some(CLE)).expect("ouverture");
        assert!(lecture.execute("DELETE FROM control_ledger", []).is_err(), "une écriture par la connexion de lecture est refusée");
        drop(lecture);
        let reste: i64 = ecrivain.query_row("SELECT COUNT(*) FROM control_ledger", [], |r| r.get(0)).expect("compte");
        assert_eq!(reste, 1, "et la ligne est toujours là");

        let absent = crate::tmp_possede::TmpPossede::neuf("cdej-absent");
        let chemin_absent = absent.join("plume-control.db");
        assert!(crate::state::lecture_validee_du_plan_de_controle(&chemin_absent.to_string_lossy(), None).is_err(), "fichier absent : refusé");
        assert!(!chemin_absent.exists(), "et non créé par la lecture");

        // PAR LA ROUTE. Elle lit la clé du plan de contrôle dans l'environnement du processus ; ce témoin l'y POSE, donc il
        // exclut tout lecteur de l'environnement le temps de sa portée.
        let _reglages = VERROU_ENV_PROCESSUS.write();
        let _cle = ReglageBackupPose::neuf("PLUME_CONTROL_KEY", CLE);
        let ecrivain = Arc::new(Mutex::new(ecrivain));
        let chiffre = ControlPlane { conn: ecrivain.clone(), db_path: Arc::new(p.as_str().to_string()) };
        let st = tenant_test_state("cdej-adm", "cdej-edi", "cdej-sa", Some(chiffre));
        let (statut, _, corps) = cdej_telecharger(&st).await;
        assert_eq!((statut, cdej_lignes(&corps).len()), (200, 1), "la route passe la clé du plan de contrôle à sa lecture : {corps}");
        {
            let _autre = ReglageBackupPose::neuf("PLUME_CONTROL_KEY", "une-autre-cle");
            let (statut, _, corps) = cdej_telecharger(&st).await;
            assert_eq!(statut, 500, "une autre clé dans l'environnement : 500, jamais un 200 à corps vide : {corps}");
            assert!(corps.contains("export du journal de contrôle impossible"), "{corps}");
            assert!(!corps.contains("une-autre-cle"), "la clé du plan de contrôle n'entre dans aucun message servi : {corps}");
            assert!(!corps.contains(p.as_str()), "ni le chemin du plan de contrôle : {corps}");
        }

        ecrivain.lock().execute_batch("BEGIN IMMEDIATE").expect("fixture : une transaction pendante sur l'écrivain");
        ecrivain
            .lock()
            .execute("INSERT INTO control_ledger(ts,kind,actor,tenant,detail,prev_hash,hash) VALUES(2,'test.cdej','sa','t','d2','h','h2')", [])
            .expect("fixture : un maillon jamais validé");
        let illisible = ControlPlane { conn: ecrivain.clone(), db_path: Arc::new(chemin_absent.to_string_lossy().into_owned()) };
        let st = tenant_test_state("cdej-adm", "cdej-edi", "cdej-sa", Some(illisible));
        let (statut, _, corps) = cdej_telecharger(&st).await;
        let vus_par_l_ecrivain: i64 = ecrivain.lock().query_row("SELECT COUNT(*) FROM control_ledger", [], |r| r.get(0)).expect("l'écrivain lit");
        assert_eq!(vus_par_l_ecrivain, 2, "précondition : l'écrivain, LUI, lit ses deux maillons — une relecture sur lui rendrait 200");
        assert_eq!(statut, 500, "un plan de contrôle illisible : 500, jamais une relecture sur l'écrivain ni un 200 à corps vide : {corps}");
        assert!(corps.contains("export du journal de contrôle impossible"), "{corps}");
        assert!(!corps.contains(CLE), "la clé du plan de contrôle n'entre dans aucun message servi : {corps}");
        assert!(
            !corps.contains(absent.to_string_lossy().as_ref()),
            "ni le chemin du plan de contrôle, que l'ouverture ajoute au texte de son erreur : {corps}"
        );
        assert!(!chemin_absent.exists(), "et la route n'a pas créé le fichier");
        ecrivain.lock().execute_batch("ROLLBACK").expect("fixture : transaction fermée");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.27-k` — `ledger-verify-export` SORT DU PROCESSUS AVEC LE CODE DE SON VERDICT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, sur de VRAIS processus — ré-exécution de CE binaire de test, dont l'enfant appelle la sous-commande
    /// telle que `main` l'appelle (`commande_ledger_verify_export`) : une copie intègre qui porte une répétition exacte
    /// sort en 0 et le dit ; une copie à laquelle il manque un maillon sort en 1, « EXPORT COMPROMIS » ; un fichier absent
    /// sort en 2. C'est le code de sortie qu'un script d'exploitation lit : une accusation imprimée qui sortirait en 0
    /// serait un verdict vert. GARDE ANTI-FAUX-VERT : chaque enfant doit avoir imprimé la phrase de la sous-commande — un
    /// nom de test qui change ferait tourner zéro test dans l'enfant, qui sortirait en 0 sans rien dire.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : la sortie en erreur réservée aux codes supérieurs à 1 — la copie compromise sort
    /// en 0.
    #[test]
    fn cdej_ledger_verify_export_sort_avec_le_code_de_son_verdict() {
        const COPIE_A_VERIFIER: &str = "CDEJ_COPIE_A_VERIFIER_PAR_L_ENFANT";
        if let Ok(chemin) = std::env::var(COPIE_A_VERIFIER) {
            crate::commande_ledger_verify_export(&["plume-daemon".to_string(), "ledger-verify-export".to_string(), chemin]);
        }
        let c = cdej_chaine_du_registre(4);
        let racine = crate::tmp_possede::TmpPossede::neuf("cdej-sortie");
        let jouer = |nom: &str, rangs: Option<&[usize]>| -> (Option<i32>, String, String) {
            let chemin = racine.join(nom);
            if let Some(r) = rangs {
                std::fs::write(&chemin, format!("{}\n", cdej_copie(&c, r).join("\n"))).expect("fixture : copie écrite");
            }
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::copie_du_registre_doublon_exact_et_journal_de_controle_valide::cdej_ledger_verify_export_sort_avec_le_code_de_son_verdict",
                ])
                .env(COPIE_A_VERIFIER, &chemin)
                .output()
                .expect("ré-exécution du binaire de test");
            (sortie.status.code(), String::from_utf8_lossy(&sortie.stdout).into_owned(), String::from_utf8_lossy(&sortie.stderr).into_owned())
        };

        let (code, sortie, erreurs) = jouer("repetee.jsonl", Some(&[0, 1, 2, 1, 2, 3]));
        assert!(
            sortie.contains("export OK : 4 entrées chaînées intègres (vérifié hors-ligne) ; 2 ligne(s) RÉPÉTÉE(S) À L'IDENTIQUE"),
            "l'enfant a VRAIMENT joué la sous-commande, sur une copie intègre qui porte une répétition : {sortie}\n{erreurs}"
        );
        assert_eq!(code, Some(0), "une copie intègre sort en 0 : {sortie}");

        let (code, sortie, erreurs) = jouer("compromise.jsonl", Some(&[0, 1, 3]));
        assert!(sortie.contains("EXPORT COMPROMIS : ligne 2"), "l'enfant a VRAIMENT jugé la copie compromise : {sortie}\n{erreurs}");
        assert_eq!(code, Some(1), "une copie compromise sort en 1, jamais en 0 : {sortie}");

        let (code, sortie, erreurs) = jouer("absente.jsonl", None);
        assert!(erreurs.contains("ledger-verify-export: lecture"), "l'enfant a VRAIMENT tenté de lire la copie : {sortie}\n{erreurs}");
        assert_eq!(code, Some(2), "une copie illisible n'est pas vérifiée : sortie 2 : {erreurs}");
    }
}
