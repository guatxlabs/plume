// P10.16-a — L'EMPREINTE DU JOURNAL D'ÉCRITURE ANTICIPÉE : ce que ces tests prouvent, et dans quel ordre.
//
//   1. LA BORNE EST DÉRIVÉE, PAS POSÉE. La formule est exercée : chacun de ses deux termes porte, et
//      retirer celui du lot d'ingest rendrait la borne insuffisante — c'est une MESURE qui le dit, pas
//      une relecture.
//   2. LA BORNE COUVRE UNE TRANSACTION RÉELLE. Un lot d'ingest est INDIVISIBLE : une borne plus petite
//      ferait tronquer puis réétendre le fichier à chaque passage. On écrit une vraie transaction sur
//      le schéma réel et on compare au journal qu'elle produit.
//   3. LA BORNE REND LES OCTETS, ET SON ABSENCE NE LES REND PAS. Le témoin négatif est la moitié du
//      test : sans lui, on prouverait seulement que le fichier finit petit, pas que c'est la borne qui
//      l'a fait.
//   4. LA BORNE NE CHANGE PAS LE VERDICT DE LA VOIE UNIQUE. C'est la question de goulot : un point de
//      reprise refusé doit rester un `Refuse` LISIBLE, jamais un blocage ni un faux succès. On l'exerce
//      dans les DEUX états (lecteur tenu / relâché) AVEC la borne posée.
//   5. LE SEUIL D'AUTO-CHECKPOINT A UN SEUL AUTEUR. Garde DÉRIVÉE de la source : la borne est calculée
//      à partir de ce seuil, donc un second littéral ailleurs ferait diverger la formule de ce que le
//      moteur applique vraiment.
//
// CE QU'AUCUN DE CES TESTS NE PROUVE, ÉCRIT POUR ÊTRE OPPOSABLE : que la CRÊTE est bornée. Elle ne
// l'est pas, et le module le dit — `journal_size_limit` n'agit qu'après un point de reprise qui a
// réussi à réinitialiser le journal.

#[cfg(test)]
mod wal_empreinte_tests {
    use crate::db_open::{checkpoint_wal_tronque, Checkpoint};
    use crate::tmp_possede::TmpDb;
    use crate::wal_empreinte::*;
    use rusqlite::Connection;

    /// Une base FICHIER au schéma RÉEL du produit. Le journal ne se mesure pas sur une imitation : ce
    /// sont les six index de `event` et le déclencheur de l'index plein texte qui salissent des pages,
    /// donc qui font les trames.
    fn base_reelle(etiquette: &str) -> (TmpDb, Connection) {
        let tmp = TmpDb::neuf(etiquette);
        let conn = Connection::open(tmp.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(crate::migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// La taille du `-wal` de cette base, en octets. `0` quand le fichier n'existe pas encore.
    fn taille_wal(tmp: &TmpDb) -> i64 {
        std::fs::metadata(format!("{}-wal", tmp.as_str())).map(|m| m.len() as i64).unwrap_or(0)
    }

    /// Écrit `n` événements en UNE transaction, par la même forme que l'ingest (`BEGIN IMMEDIATE` /
    /// `INSERT OR IGNORE` / `COMMIT`). Les cardinalités sont celles du profil de production : elles
    /// décident combien de pages de b-tree sont salies, donc combien de trames sont écrites.
    fn une_transaction(conn: &Connection, depart: i64, n: i64) {
        conn.execute_batch("BEGIN IMMEDIATE").expect("transaction");
        {
            let mut st = conn
                .prepare(
                    "INSERT OR IGNORE INTO event(ts,source,category,severity,host,message,fields,dedup) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                )
                .expect("insert préparable");
            for k in depart..depart + n {
                st.execute(rusqlite::params![
                    1_785_000_000_i64 + k,
                    format!("source-{}", k % 32),
                    format!("cat-{}", k % 19),
                    k % 5,
                    format!("host-{}", k % 2),
                    format!("evenement {k} — {}", "x".repeat(170)),
                    format!("{{\"action\":\"a{}\",\"pad\":\"{}\"}}", k % 7, "y".repeat(120)),
                    format!("d-{k}"),
                ])
                .expect("insertion");
            }
        }
        conn.execute_batch("COMMIT").expect("commit");
    }

    // =============================================================================================
    // 1. LA BORNE EST DÉRIVÉE — chacun de ses deux termes porte
    // =============================================================================================

    /// LA FORMULE, EXERCÉE. Une borne « configurable avec un défaut justifié » ne vaut que si le défaut
    /// SUIT ses entrées : relever le plafond d'événements par transaction doit la déplacer, et une base
    /// en pages plus grandes doit la déplacer aussi.
    ///
    /// MUTATION : remplacer le terme du lot par une constante ⇒ la 2ᵉ assertion passe au ROUGE (la borne
    /// cesserait de suivre le plafond d'ingest) ; oublier l'en-tête de trame ⇒ la 4ᵉ passe au ROUGE.
    #[test]
    fn la_borne_suit_ses_entrees_au_lieu_detre_posee() {
        // Le terme de RÉSERVE seul, quand aucun événement n'est acceptable : exactement ce que SQLite
        // s'accorde entre deux points de reprise.
        assert_eq!(
            borne_octets_pour(0, 4096),
            SEUIL_AUTOCHECKPOINT_PAGES * (4096 + 24),
            "à plafond d'ingest nul, la borne DOIT valoir la seule réserve d'auto-checkpoint"
        );

        // Le terme du LOT porte, et il est monotone : doubler le plafond d'événements augmente la borne.
        let (petit, grand) = (borne_octets_pour(10_000, 4096), borne_octets_pour(20_000, 4096));
        assert!(
            grand > petit,
            "la borne doit SUIVRE le plafond d'événements par transaction ({petit} -> {grand})"
        );

        // Et elle le suit PROPORTIONNELLEMENT : l'écart entre les deux est celui des lots, pas un
        // arrondi. Sans cette assertion, un terme de lot écrasé par un plancher passerait la précédente.
        assert_eq!(
            grand - petit,
            (10_000 * 154 / 1000) * (4096 + 24),
            "l'écart entre deux plafonds DOIT être celui des trames du lot"
        );

        // La taille de PAGE porte aussi — et avec son en-tête de trame de 24 octets, sans quoi la borne
        // serait sous-évaluée de ~0,6 % et le fichier dépasserait la borne annoncée.
        assert_eq!(
            borne_octets_pour(0, 8192),
            SEUIL_AUTOCHECKPOINT_PAGES * (8192 + 24),
            "une base en pages de 8 Kio n'a pas la même arithmétique"
        );

        // Le plancher : une taille de page absurde ne doit pas produire une borne quasi nulle, qui
        // ferait tronquer le journal à chaque point de reprise.
        assert!(borne_octets_pour(0, 0) >= SEUIL_AUTOCHECKPOINT_PAGES * 512, "plancher de page_size");
    }

    /// LES TROIS ÉTATS SONT DISTINCTS, et le compilateur les tient. « pas de variable posée » n'est pas
    /// « posée à zéro », qui n'est pas « posée à une valeur » — trois phrases différentes, trois PRAGMA
    /// différents.
    ///
    /// MUTATION : faire retomber `Some(0)` sur la dérivation ⇒ la 2ᵉ assertion passe au ROUGE, et un
    /// exploitant qui a DEMANDÉ l'ancien comportement ne l'aurait pas obtenu, en silence.
    #[test]
    fn les_trois_etats_de_la_borne_ne_se_confondent_pas() {
        assert_eq!(borne_pour(None, 42_000), Borne::Derivee(42_000), "absente -> dérivation");
        assert_eq!(borne_pour(Some(0), 42_000), Borne::Aucune, "0 -> ancien comportement, explicitement");
        assert_eq!(borne_pour(Some(7), 42_000), Borne::Imposee(7 * 1048576), "valeur -> imposée, en Mio");

        // `Aucune` n'écrit RIEN. Poser `journal_size_limit=-1` aurait le même effet pour SQLite, mais la
        // garde de voie unique compte les endroits où ce PRAGMA est écrit : un « désactivé » qui écrit
        // quand même le PRAGMA rendrait cette garde illisible.
        assert!(Borne::Aucune.pragma().is_empty(), "désactivée, la borne n'écrit aucun PRAGMA");
        assert!(
            Borne::Derivee(42_000).pragma().contains("journal_size_limit=42000"),
            "dérivée, la borne écrit sa valeur : {}",
            Borne::Derivee(42_000).pragma()
        );

        // LA PHRASE DOIT AVOUER CE QU'ELLE NE BORNE PAS. C'est le point du chantier : une borne qui
        // laisserait croire qu'elle tient la crête serait pire que pas de borne du tout.
        for b in [Borne::Derivee(42_000), Borne::Imposee(42_000), Borne::Aucune] {
            let p = b.phrase();
            assert!(
                p.contains("CRETE") || p.contains("crete"),
                "la phrase de {b:?} doit nommer la crête, bornée ou non : {p}"
            );
        }
    }

    // =============================================================================================
    // 2. LA BORNE COUVRE UNE TRANSACTION RÉELLE — mesuré, pas supposé
    // =============================================================================================

    /// UN LOT D'INGEST EST INDIVISIBLE. SQLite ne peut pas tronquer un journal au milieu d'une
    /// transaction : si la borne était plus petite que ce qu'un seul `COMMIT` produit, le fichier serait
    /// tronqué puis réétendu à chaque passage — du travail pur, exactement le contraire du but.
    ///
    /// CE QUE CE TEST MESURE : le journal produit par UNE transaction, auto-checkpoint COUPÉ (sinon le
    /// fichier serait replié en cours de route et on mesurerait autre chose que la transaction).
    ///
    /// CE QU'IL NE MESURE PAS, ET C'EST DIT : la calibration de `TRAMES_POUR_MILLE_EVENEMENTS` au lot
    /// MAXIMAL (50 000 événements). Ce test tourne à une taille que la suite peut se payer ; c'est le
    /// banc décrit dans l'en-tête du module qui a fixé la constante.
    ///
    /// MUTATION : retirer le terme du lot de la formule (ne garder que la réserve) ⇒ la 3ᵉ assertion
    /// passe au ROUGE, et c'est la MESURE qui le dit — la réserve seule ne couvre pas cette transaction.
    #[test]
    fn la_borne_couvre_une_transaction_reelle() {
        const LOT: i64 = 12_000;
        let (tmp, conn) = base_reelle("wal-borne-lot");
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;").expect("mode WAL");
        // RÉGIME ÉTABLI : sur une table vide les b-trees tiennent en quelques pages et une transaction
        // salit bien moins qu'en service. Mesurer à vide sous-estimerait la borne nécessaire.
        une_transaction(&conn, 0, 8_000);
        assert!(checkpoint_wal_tronque(&conn, "test-preremplissage").a_tronque(), "journal remis à zéro");

        une_transaction(&conn, 8_000, LOT);
        let journal = taille_wal(&tmp);
        let page_size = page_size_de(&conn);

        // PRÉCONDITION : l'instrument a bien mesuré quelque chose. Sans elle, un `-wal` resté vide (mode
        // journal mal posé, chemin faux) rendrait les deux assertions suivantes VRAIES pour rien.
        assert!(journal > 1_048_576, "précondition : la transaction doit produire un journal mesurable ({journal} o)");

        // CE QU'ON VEUT : la borne couvre la transaction. Le chiffre est PUBLIÉ (`--nocapture`) : une
        // mesure qui ne sort que dans un message d'échec ne sert qu'à celui qui casse le test.
        let borne = borne_octets_pour(LOT, page_size);
        println!(
            "[wal-empreinte] {LOT} evenements en UNE transaction -> journal {journal} o ; \
             borne derivee {borne} o ; reserve d'auto-checkpoint seule {} o",
            SEUIL_AUTOCHECKPOINT_PAGES * (page_size + 24)
        );
        assert!(
            borne >= journal,
            "la borne ({borne} o) doit couvrir le journal d'UNE transaction de {LOT} événements \
             ({journal} o), sinon le fichier est tronqué puis réétendu à chaque lot"
        );

        // LE TÉMOIN QUI FAIT PORTER LE TERME DU LOT : la réserve d'auto-checkpoint SEULE ne suffit pas.
        // Sans cette assertion, une formule réduite à sa réserve passerait la précédente sans qu'on le voie.
        let reserve_seule = SEUIL_AUTOCHECKPOINT_PAGES * (page_size + 24);
        assert!(
            reserve_seule < journal,
            "témoin : la réserve d'auto-checkpoint seule ({reserve_seule} o) ne doit PAS couvrir cette \
             transaction ({journal} o) — sinon ce test ne prouve rien sur le terme du lot"
        );
    }

    // =============================================================================================
    // 3. LA BORNE REND LES OCTETS — et son absence ne les rend pas
    // =============================================================================================

    /// LE RÉSIDU, MESURÉ DANS LES DEUX SENS. Un lecteur qui tient une transaction empêche tout point de
    /// reprise : le journal enfle. Quand il relâche, le point de reprise suivant réinitialise le
    /// journal — et c'est LÀ, et seulement là, que la borne agit.
    ///
    /// POURQUOI ON MESURE UN MINIMUM ET NON LA TAILLE FINALE. Après une troncature, le journal se
    /// REMPLIT de nouveau jusqu'au point de reprise suivant : lire le fichier à un instant arbitraire
    /// mesurerait où l'on est tombé dans ce cycle, pas si la borne a mordu. On échantillonne donc à
    /// chaque transaction et on retient le PLUS PETIT — la question posée est « ce fichier redescend-il
    /// un jour », et un minimum y répond ; une valeur finale n'y répond pas.
    ///
    /// LES DEUX BRAS SONT LE TEST. Le bras BORNÉ prouve que le fichier redescend ; le bras SANS BORNE
    /// prouve que ce n'est pas la nature des choses mais bien la borne qui l'a fait. Sans le second, on
    /// aurait mesuré un fichier petit et conclu n'importe quoi.
    ///
    /// MUTATION : retirer le fragment `journal_size_limit` de `Borne::pragma` ⇒ le bras borné rend le
    /// même minimum que le témoin, et l'assertion nomme les deux chiffres.
    #[test]
    fn la_borne_rend_les_octets_quand_le_point_de_reprise_reprend() {
        // LA BORNE DU TEST EST DÉRIVÉE PAR LE PRODUIT LUI-MÊME, pour un plafond de 1 000 événements par
        // transaction : une borne écrite à la main ici pourrait tomber SOUS la réserve d'auto-checkpoint
        // plus un lot, et le test reprocherait alors au code une troncature qu'il a lui-même provoquée.
        let borne_du_test = borne_octets_pour(1_000, 4096);
        let mesurer_un_bras = |etiquette: &str, borne: Borne| -> (i64, i64) {
            let (tmp, ecrivain) = base_reelle(etiquette);
            ecrivain
                .execute_batch(&format!(
                    "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint={SEUIL_AUTOCHECKPOINT_PAGES};{}",
                    borne.pragma()
                ))
                .expect("politique de journal");

            // LE LECTEUR QUI REFUSE LE POINT DE REPRISE — une transaction de lecture TENUE, exactement
            // la forme que le démon produit lui-même (le parcours `dbstat` de la série du budget).
            let lecteur = Connection::open(tmp.as_str()).expect("seconde connexion");
            lecteur.execute_batch("BEGIN").expect("lecture ouverte");
            let _: i64 = lecteur.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).expect("marque de lecture posée");

            for lot in 0..10 {
                une_transaction(&ecrivain, lot * 1_000, 1_000);
            }
            let crete = taille_wal(&tmp);

            // Le lecteur relâche : le point de reprise redevient possible. On ne passe PAS par un
            // TRUNCATE explicite — il ramènerait le fichier à zéro dans les DEUX bras et le test ne
            // prouverait plus rien. C'est l'auto-checkpoint, celui qui tourne en service, qu'on observe.
            lecteur.execute_batch("COMMIT").expect("lecture close");
            drop(lecteur);
            let mut plus_petit = crete;
            for lot in 10..20 {
                une_transaction(&ecrivain, lot * 1_000, 1_000);
                plus_petit = plus_petit.min(taille_wal(&tmp));
            }
            (crete, plus_petit)
        };

        let (crete_bornee, residu_borne) = mesurer_un_bras("wal-residu-borne", Borne::Imposee(borne_du_test));
        let (crete_temoin, residu_temoin) = mesurer_un_bras("wal-residu-temoin", Borne::Aucune);

        // PRÉCONDITION : le lecteur tenu a bien fait enfler le journal au-delà de la borne dans les deux
        // bras. Sans ça, « le résidu est sous la borne » serait vrai sans que la borne ait rien fait.
        assert!(
            crete_bornee > borne_du_test && crete_temoin > borne_du_test,
            "précondition : la crête doit dépasser la borne (bornée {crete_bornee}, témoin {crete_temoin}, borne {borne_du_test})"
        );

        assert!(
            residu_borne <= borne_du_test,
            "sous la borne, le journal doit redescendre à {borne_du_test} o au plus après un point de \
             reprise — obtenu {residu_borne} o (crête {crete_bornee} o)"
        );

        // LE TÉMOIN NÉGATIF : sans borne, le fichier GARDE sa plus haute marque. C'est ce que le chantier
        // ferme, et c'est la moitié du test.
        assert!(
            residu_temoin > borne_du_test,
            "témoin : SANS borne, le journal doit garder sa crête ({crete_temoin} o) — obtenu \
             {residu_temoin} o. Si ce chiffre est petit, ce n'est pas la borne qui rendait les octets \
             dans l'autre bras et le test ne prouve rien"
        );
    }

    // =============================================================================================
    // 4. LE GOULOT — la voie unique rend le MÊME verdict sous la borne
    // =============================================================================================

    /// LA QUESTION DE GOULOT, POSÉE À LA VOIE UNIQUE. Borner un journal ne doit pas transformer un point
    /// de reprise en blocage : `checkpoint_wal_tronque` doit continuer à rendre `Refuse` quand un
    /// lecteur tient le journal, et `Tronque` quand il relâche. On ne réessaie pas, on ne force aucun
    /// verrou — la base d'un SOC ne gèle pas pour une troncature refusée (P10.17-a).
    ///
    /// CE QUE CE TEST AJOUTE À P10.17-a : les deux verdicts sont exercés AVEC `journal_size_limit` POSÉ.
    /// C'était l'inconnue du chantier — un réglage d'espace qui changerait la sémantique d'un point de
    /// reprise en échangerait une crête mesurée contre une contention non mesurée.
    ///
    /// MUTATION : faire poser à `Borne` un `wal_checkpoint` au lieu d'un `journal_size_limit` ⇒ la
    /// première assertion passe au ROUGE (le refus deviendrait un blocage ou un faux succès).
    #[test]
    fn la_borne_ne_change_pas_le_verdict_de_la_voie_unique() {
        let (tmp, ecrivain) = base_reelle("wal-verdict-sous-borne");
        ecrivain
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;{}",
                Borne::Imposee(1_048_576).pragma()
            ))
            .expect("politique de journal");
        une_transaction(&ecrivain, 0, 2_000);

        let lecteur = Connection::open(tmp.as_str()).expect("seconde connexion");
        lecteur.execute_batch("BEGIN").expect("lecture ouverte");
        let _: i64 = lecteur.query_row("SELECT count(*) FROM event", [], |r| r.get(0)).expect("marque de lecture posée");
        une_transaction(&ecrivain, 2_000, 1_000);

        // LECTEUR TENU : la troncature est REFUSÉE, et elle le DIT. La borne ne masque pas ce refus et
        // ne le transforme pas en attente.
        match checkpoint_wal_tronque(&ecrivain, "test-sous-borne") {
            Checkpoint::Refuse { restant_pages } => assert!(
                restant_pages > 0,
                "un refus doit dire COMBIEN de pages restent dans le journal — obtenu {restant_pages}"
            ),
            autre => panic!("un lecteur tient le journal : le verdict doit être `Refuse`, obtenu {autre:?}"),
        }

        // LECTEUR RELÂCHÉ : la troncature a lieu, sous la borne comme sans elle.
        lecteur.execute_batch("COMMIT").expect("lecture close");
        drop(lecteur);
        let v = checkpoint_wal_tronque(&ecrivain, "test-sous-borne");
        assert!(v.a_tronque(), "sans lecteur, la troncature doit avoir lieu sous la borne — obtenu {v:?}");
        assert_eq!(taille_wal(&tmp), 0, "un TRUNCATE réussi ramène le journal à zéro, pas à la borne");
    }

    // =============================================================================================
    // 5. LE SEUIL D'AUTO-CHECKPOINT A UN SEUL AUTEUR
    // =============================================================================================

    /// GARDE DÉRIVÉE DE LA SOURCE. La borne est CALCULÉE à partir du seuil d'auto-checkpoint : un second
    /// littéral posé ailleurs ferait diverger la formule de ce que le moteur applique, et la borne
    /// décrirait alors une configuration que personne ne déploie. C'est la faute déjà payée par les
    /// quatre `cache_size` que `sqlite_plafond` a dû réunir — ici elle est fermée par CONSTRUCTION.
    ///
    /// CE QUE LE PÉRIMÈTRE EXCLUT, comme la garde jumelle de P10.17-a : les fichiers de test (un banc a
    /// le droit de couper l'auto-checkpoint pour mesurer une transaction), les modules `#[cfg(test)]`
    /// internes à un fichier de production, et les COMMENTAIRES — une garde qui compterait le texte
    /// interdirait d'écrire pourquoi elle existe.
    ///
    /// MUTATION : réécrire `PRAGMA wal_autocheckpoint=1000` en clair dans `server::tune` ⇒ la seconde
    /// assertion passe au ROUGE en nommant le fichier.
    #[test]
    fn le_seuil_dauto_checkpoint_a_un_seul_auteur() {
        use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, sans_commentaire, texte_de_production};
        use std::path::PathBuf;

        const VOIE_UNIQUE: &str = "wal_empreinte.rs";
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let marques = fichiers_de_test(&fichiers);

        let (mut hors_voie, mut vu_dans_la_voie) = (Vec::<String>::new(), false);
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let porte = texte_de_production(f, &src)
                .into_iter()
                .any(|(_, l)| sans_commentaire(&l).contains("wal_autocheckpoint"));
            if !porte {
                continue;
            }
            if f.file_name().is_some_and(|n| n == VOIE_UNIQUE) {
                vu_dans_la_voie = true;
            } else {
                hors_voie.push(f.display().to_string());
            }
        }

        // PRÉCONDITION : si la voie unique ne portait plus le réglage, la garde deviendrait vide et
        // rendrait VERT en étant aveugle — le défaut d'instrument que cette campagne poursuit ailleurs.
        assert!(
            vu_dans_la_voie,
            "`wal_autocheckpoint` a disparu de {VOIE_UNIQUE} : la garde ne garde plus rien"
        );
        assert!(
            hors_voie.is_empty(),
            "`wal_autocheckpoint` posé HORS de la voie unique ({VOIE_UNIQUE}) :\n  {}\n\
             La borne du journal est DÉRIVÉE de ce seuil : un second littéral la ferait décrire une \
             configuration que le moteur n'applique pas. Passer par \
             `wal_empreinte::pragmas_journal(page_size)`.",
            hors_voie.join("\n  ")
        );
    }
}
