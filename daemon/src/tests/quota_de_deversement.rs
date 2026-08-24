// ================================================================================================
// P10.1-b — LA TAILLE DU DÉVERSEMENT EST BORNÉE, OU L'ABSENCE DE BORNE EST DITE
// ================================================================================================
// LE DÉFAUT. `P10.1-a` a fait du déversement des tris un échange qui se prend EXPLICITEMENT : au
// défaut, aucune valeur d'événement ne quitte la base chiffrée. Mais une fois l'échange pris, RIEN
// ne bornait la TAILLE de ce qui est écrit en clair. Le budget mémoire ne protège pas le volume :
// une requête pathologique le remplit, et un volume plein n'est plus un échange, c'est une panne
// pour toutes les sessions.
//
// CE QUE LE PRODUIT PEUT RÉELLEMENT OBSERVER, ET C'EST CE QUI A DÉCIDÉ DE LA FORME. Le moteur DÉLIE
// son temporaire aussitôt après l'avoir ouvert : pendant qu'un tri déverse, le répertoire est VIDE
// de tout nom. Une garde bâtie sur le listage du répertoire aurait donc été un no-op silencieux, et
// c'est mesuré ici même — le premier témoin fabrique un fichier délié, montre que la mesure le VOIT
// et que le listage du répertoire ne le voit PAS. Ce qui reste observable est le DESCRIPTEUR : le
// processus le détient, le système en publie la cible et la taille courante.
//
// CE QUI IMPOSE LA BORNE. Le rappel de progression du moteur est la seule prise sur une instruction
// EN COURS ; un retour non nul l'arrête. Au franchissement, la requête est REFUSÉE et le refus
// NOMME ce qui a été mesuré, le quota, et les deux leviers — celui qui agrandit la borne et celui
// qui retire le déversement.
//
// LES DEUX SENS, ET LA VALEUR QUI CHANGE. La mutation nomme UNE valeur : l'issue d'un tri qui
// déverse au-delà de la borne. Quota étroit -> la requête ÉCHOUE et le refus nomme sa cause ; quota
// large -> LA MÊME requête, sur LES MÊMES données, ABOUTIT et rend toutes ses lignes. Sans ce second
// témoin, on ne prouverait que la capacité à tout refuser.
//
// ET LES DEUX CAS QUI NE BORNENT RIEN SONT DITS. Un quota retiré (`…=0`) et un quota demandé mais
// NON MESURABLE sur l'hôte ne se confondent ni entre eux ni avec un quota armé : chacun a sa phrase,
// et un quota qu'on croirait armé sans qu'il mesure quoi que ce soit serait pire qu'aucun quota.

#[cfg(test)]
mod quota_de_deversement {
    use crate::mesure_environnement::Mesure;
    use crate::sqlite_plafond::{
        self, controle_positif_de_la_mesure, octets_ouverts_sous, phrase_du_quota,
        poser_la_surveillance_du_quota, quota_pour, QuotaDeversement, LEVIER_QUOTA_DEVERSEMENT,
    };
    use crate::tmp_possede::TmpPossede;
    use rusqlite::Connection;

    /// Le répertoire où le système publie les descripteurs du processus. Écrit ICI, du côté du
    /// témoin : la fonction mesurée, elle, le reçoit en argument et ne le nomme jamais.
    const DESCRIPTEURS: &str = "/proc/self/fd";

    fn descripteurs() -> std::path::PathBuf {
        std::path::PathBuf::from(DESCRIPTEURS)
    }

    /// La taille de la charge du témoin — assez grande pour être lisible dans un compte d'octets,
    /// assez petite pour ne rien coûter.
    const CHARGE: usize = 128 * 1024;

    /// Les octets détenus sous `dir`. Le second nombre de la mesure — les descripteurs DISPARUS entre
    /// le listage et leur lecture — est RELU ici plutôt qu'ignoré : un descripteur fermé ne détient
    /// plus rien, donc il ne manque pas au compte, mais une mesure qui en abandonnerait sans le dire
    /// serait le défaut que ce dépôt poursuit.
    fn octets(dir: &std::path::Path) -> i64 {
        match octets_ouverts_sous(&descripteurs(), dir) {
            Mesure::Lue(d) => {
                assert!(
                    d.octets >= 0,
                    "un compte d'octets détenus ne peut pas être négatif ({} disparus)",
                    d.disparus
                );
                d.octets
            }
            Mesure::Illisible { cause, detail } => {
                panic!("la mesure doit se prendre sur cet hôte : {cause} ({detail})")
            }
        }
    }

    /// LES NOMS QUI SUBSISTENT DANS LE RÉPERTOIRE — ce qu'une garde bâtie sur le listage aurait vu.
    fn noms_dans(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("le répertoire du témoin doit être listable")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// UN FICHIER FABRIQUÉ COMME LE MOTEUR FABRIQUE SES TEMPORAIRES : créé, ouvert, puis DÉLIÉ
    /// pendant qu'on le tient. Rend le descripteur, qu'il faut garder en vie pour que le fichier le
    /// soit aussi.
    fn temporaire_delie(dir: &std::path::Path, nom: &str, taille: usize) -> std::fs::File {
        let chemin = dir.join(nom);
        std::fs::write(&chemin, vec![0u8; taille]).expect("écriture du témoin");
        let tenu = std::fs::File::open(&chemin).expect("ouverture du témoin");
        std::fs::remove_file(&chemin).expect("déliaison du témoin");
        tenu
    }

    /// UNE BASE QUI DÉVERSE POUR DE VRAI, dans un répertoire QUE LE TÉMOIN POSSÈDE.
    ///
    /// `temp_store_directory` est le seul levier qui redirige les temporaires d'un processus DÉJÀ
    /// démarré : `SQLITE_TMPDIR` n'est lu qu'une fois, à la première initialisation du moteur, donc
    /// une suite de tests ne peut pas s'en servir. Le répertoire pris par le moteur est RELU, jamais
    /// supposé : sans cette relecture, un déversement parti ailleurs rendrait tout ce fichier vert et
    /// aveugle.
    ///
    /// `cache_size` est délibérément petit : c'est LUI qui décide du tampon RAM du trieur avant
    /// déversement, donc de la quantité de données nécessaire pour qu'un tri écrive vraiment.
    fn base_qui_deverse(dir: &std::path::Path, lignes: i64) -> Connection {
        let conn = Connection::open_in_memory().expect("base d'épreuve ouvrable");
        conn.execute_batch(&format!(
            "PRAGMA temp_store_directory='{}'; PRAGMA temp_store=FILE; PRAGMA cache_size=-2048;",
            dir.display()
        ))
        .expect("les réglages de déversement doivent être acceptés");
        let pris: String =
            conn.query_row("PRAGMA temp_store_directory", [], |r| r.get(0)).unwrap_or_default();
        assert_eq!(
            pris.trim_matches('\''),
            dir.display().to_string(),
            "PRÉMISSE RÉFUTÉE : le moteur n'a pas pris le répertoire du témoin, le déversement irait \
             ailleurs et la mesure ne verrait rien"
        );
        conn.execute_batch(&format!(
            "CREATE TABLE t(a TEXT); \
             INSERT INTO t(a) WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{lignes}) \
             SELECT hex(randomblob(80)) FROM s;"
        ))
        .expect("le jeu d'épreuve doit se construire");
        conn
    }

    /// LE TRI QUI DÉVERSE, exécuté jusqu'au bout. Rend le nombre de lignes lues, ou le message que le
    /// TRADUCTEUR DU PRODUIT (`message_erreur`) rend à l'exploitant — c'est cette phrase-là qui compte,
    /// pas l'erreur brute du moteur.
    fn trier(conn: &Connection) -> Result<usize, String> {
        let mut st = conn.prepare("SELECT a FROM t ORDER BY a").map_err(|e| sqlite_plafond::message_erreur(&e))?;
        let mut rows = st.query([]).map_err(|e| sqlite_plafond::message_erreur(&e))?;
        let mut n = 0usize;
        loop {
            match rows.next() {
                Ok(Some(_)) => n += 1,
                Ok(None) => return Ok(n),
                Err(e) => return Err(sqlite_plafond::message_erreur(&e)),
            }
        }
    }

    /// Remet le répertoire des temporaires du processus au silence : ce réglage est GLOBAL au
    /// processus, et le laisser pointer sur un répertoire que la fixture va effacer serait laisser
    /// derrière soi un état que personne n'a demandé.
    fn rendre_le_repertoire_au_silence(conn: &Connection) {
        let _ = conn.execute_batch("PRAGMA temp_store_directory=''");
    }

    // ============================================================================================

    /// CE QUE LE PRODUIT PEUT RÉELLEMENT OBSERVER — ET CE QU'IL NE PEUT PAS.
    ///
    /// TROIS TÉMOINS SUR LE MÊME MÉCANISME :
    ///   * POSITIF — un fichier DÉLIÉ mais tenu ouvert est VU, et pour sa taille ;
    ///   * RÉFUTATION — le LISTAGE du répertoire ne le voit PAS. C'est la mesure qui a écarté la
    ///     « surveillance du répertoire de déversement » : elle aurait rendu zéro pendant qu'un tri
    ///     écrit des centaines de Mio, sans une erreur ;
    ///   * NÉGATIF — un fichier tenu ouvert AILLEURS n'entre pas dans le compte, et le compte
    ///     redescend quand le descripteur est relâché. Sans ces deux-là, une mesure qui rendrait
    ///     toujours un grand nombre passerait pour correcte.
    #[test]
    fn la_mesure_voit_un_temporaire_delie_que_le_listage_du_repertoire_ne_voit_pas() {
        let cible = TmpPossede::neuf("quota-cible");
        let ailleurs = TmpPossede::neuf("quota-ailleurs");

        let reference = octets(&cible);
        assert_eq!(reference, 0, "prémisse : le répertoire du témoin ne doit rien détenir au départ");

        let tenu = temporaire_delie(&cible, "temoin", CHARGE);
        let vu = octets(&cible);
        assert!(
            vu >= CHARGE as i64,
            "TÉMOIN POSITIF RÉFUTÉ : un fichier délié de {CHARGE} o tenu ouvert n'est pas compté (mesure \
             {vu} o). Le quota ne pourrait rien borner."
        );

        assert!(
            noms_dans(&cible).is_empty(),
            "RÉFUTATION ATTENDUE : le listage du répertoire voit encore quelque chose. La forme retenue \
             repose sur le fait qu'un temporaire DÉLIÉ n'a plus de nom — si ce n'était pas vrai, une \
             surveillance du répertoire serait la voie simple, et c'est elle qu'il faudrait livrer."
        );

        let ailleurs_tenu = temporaire_delie(&ailleurs, "temoin", CHARGE);
        assert_eq!(
            octets(&cible),
            vu,
            "TÉMOIN NÉGATIF RÉFUTÉ : un fichier tenu ouvert HORS de la cible entre dans le compte. Le \
             quota compterait ce qu'il ne borne pas."
        );
        drop(ailleurs_tenu);

        drop(tenu);
        assert_eq!(
            octets(&cible),
            reference,
            "le compte doit redescendre quand le descripteur est relâché : sans quoi il ne suit pas ce \
             que le processus détient"
        );
    }

    /// UNE MESURE QUI NE SE PREND PAS NE REND PAS ZÉRO (`S32`).
    ///
    /// C'est la propriété qui rend le verdict `NonMesurable` atteignable : sur un hôte qui ne publie
    /// pas les descripteurs de ses processus, la mesure doit DIRE qu'elle n'a rien lu. Un zéro serait
    /// la valeur la plus calme de la série — un quota parfaitement respecté — précisément quand la
    /// mesure a disparu.
    #[test]
    fn une_mesure_impraticable_rend_un_verdict_et_pas_un_compte() {
        let cible = TmpPossede::neuf("quota-sans-descripteurs");
        let inexistant = cible.join("descripteurs-qui-nexistent-pas");
        match octets_ouverts_sous(&inexistant, &cible) {
            Mesure::Lue(d) => panic!(
                "UNE MESURE IMPRATICABLE A RENDU UN COMPTE ({} o) : le quota se croirait respecté alors \
                 que rien n'est mesuré",
                d.octets
            ),
            Mesure::Illisible { cause, detail } => {
                assert!(!cause.is_empty(), "la cause doit être une clé stable");
                assert!(
                    detail.contains(&inexistant.display().to_string()),
                    "le détail doit NOMMER le chemin tenté, sinon l'aveu n'est pas actionnable : {detail}"
                );
            }
        }
    }

    /// LE CONTRÔLE POSITIF DU DÉMARRAGE MORD SUR UN VRAI RÉPERTOIRE.
    ///
    /// C'est lui qui décide entre « quota ARMÉ » et « quota NON MESURABLE » : s'il rendait vrai sans
    /// rien vérifier, un hôte incapable de mesurer démarrerait en annonçant une borne inexistante.
    #[test]
    fn le_controle_positif_du_demarrage_valide_la_mesure_sur_un_repertoire_reel() {
        let dir = TmpPossede::neuf("quota-controle");
        controle_positif_de_la_mesure(&dir)
            .unwrap_or_else(|e| panic!("le contrôle positif doit passer sur un répertoire inscriptible : {e}"));
        assert!(
            noms_dans(&dir).is_empty(),
            "le contrôle ne doit RIEN laisser derrière lui : sa sonde est déliée, et un nom qui \
             subsisterait serait compté comme un résidu"
        );
    }

    /// LES QUATRE VERDICTS DU QUOTA NE SE CONFONDENT PAS, ET LES DEUX QUI NE BORNENT RIEN LE DISENT.
    ///
    /// PURS sur leurs entrées, donc éprouvés sans toucher au disque ni à l'environnement.
    #[test]
    fn les_verdicts_du_quota_disent_ce_qui_borne_et_ce_qui_ne_borne_pas() {
        let arme = quota_pour(64 * 1048576, Ok(()));
        assert_eq!(arme, QuotaDeversement::Arme(64 * 1048576));
        let phrase = phrase_du_quota(&arme);
        assert!(phrase.contains("ARMÉ") && phrase.contains(LEVIER_QUOTA_DEVERSEMENT), "{phrase}");

        // `…=0` : le quota est RETIRÉ. Comportement accessible, jamais subi en silence.
        let aucun = quota_pour(0, Ok(()));
        assert_eq!(aucun, QuotaDeversement::Aucun);
        let phrase = phrase_du_quota(&aucun);
        assert!(
            phrase.contains("AUCUN") && phrase.contains("RIEN ne borne"),
            "un quota retiré doit être DIT, sinon il ne se distingue pas d'un quota armé : {phrase}"
        );

        // Demandé mais impraticable : la borne n'est PAS appliquée, et la cause remonte.
        let casse = quota_pour(64 * 1048576, Err("interface absente".into()));
        let phrase = phrase_du_quota(&casse);
        assert!(
            phrase.contains("NON MESURABLE") && phrase.contains("interface absente"),
            "un quota qu'on croirait armé sans qu'il mesure serait pire qu'aucun quota : {phrase}"
        );
        assert!(
            phrase != phrase_du_quota(&aucun),
            "« retiré » et « impraticable » ne se réparent pas de la même façon et ne doivent pas se dire \
             de la même façon"
        );

        // Déversement éteint : rien à borner, rien à dire.
        assert!(
            phrase_du_quota(&QuotaDeversement::SansObjet).is_empty(),
            "un déversement éteint ne doit pas faire parler d'un quota : rien ne sort de la base chiffrée"
        );
    }

    /// LA MUTATION, DANS LES DEUX SENS — SUR UN TRI QUI DÉVERSE POUR DE VRAI.
    ///
    /// LA VALEUR QUI CHANGE est l'issue de CE tri : quota étroit, il ÉCHOUE et le refus nomme le
    /// quota et le levier ; quota large, LE MÊME tri sur LES MÊMES données rend toutes ses lignes.
    /// Le second témoin n'est pas décoratif : sans lui, une surveillance qui refuserait TOUT
    /// passerait la première assertion.
    ///
    /// LE REFUS N'EST SERVI QU'UNE FOIS. La note que le rappel laisse est CONSOMMÉE par le
    /// traducteur : une note qui survivrait ferait passer l'annulation ou le budget d'une requête
    /// suivante pour un franchissement de quota, c'est-à-dire un refus qui nomme la mauvaise cause.
    #[test]
    fn un_tri_qui_deverse_au_dela_du_quota_est_refuse_et_le_dit() {
        const LIGNES: i64 = 40_000;
        let dir = TmpPossede::neuf("quota-deversement");

        // ── SENS 1 : quota étroit. Le tri franchit la borne et doit être REFUSÉ.
        let etroit = 1048576;
        let conn = base_qui_deverse(&dir, LIGNES);
        assert_eq!(octets(&dir), 0, "prémisse : rien ne doit être détenu avant le tri");
        poser_la_surveillance_du_quota(&conn, dir.to_path_buf(), etroit);
        let refuse = trier(&conn);
        rendre_le_repertoire_au_silence(&conn);

        let message = match refuse {
            Ok(n) => panic!(
                "LE QUOTA NE BORNE RIEN : le tri a rendu {n} lignes en déversant au-delà des {} Mio \
                 concédés. C'est le défaut P10.1-b dans sa forme exacte — le volume se remplit sans que \
                 rien ne s'y oppose.",
                etroit / 1048576
            ),
            Err(m) => m,
        };
        assert!(
            message.contains("quota de déversement dépassé"),
            "LE REFUS NE DIT PAS SA CAUSE : l'analyste lit une interruption et n'a aucune action. \
             Message : {message}"
        );
        assert!(
            message.contains(LEVIER_QUOTA_DEVERSEMENT),
            "LE REFUS NE NOMME PAS SON LEVIER : un refus sans levier n'est pas actionnable. \
             Message : {message}"
        );
        assert!(
            sqlite_plafond::refus_de_quota_de_deversement().is_none(),
            "LA NOTE DE REFUS SURVIT À SA REQUÊTE : la suivante se verrait refuser pour une cause qui \
             n'est pas la sienne"
        );
        drop(conn);

        // ── SENS 2, TÉMOIN INVERSE : quota large. LE MÊME tri, LES MÊMES données, il ABOUTIT.
        let large = 1024 * 1048576;
        let conn = base_qui_deverse(&dir, LIGNES);
        poser_la_surveillance_du_quota(&conn, dir.to_path_buf(), large);
        let abouti = trier(&conn);
        rendre_le_repertoire_au_silence(&conn);
        match abouti {
            Ok(n) => assert_eq!(
                n as i64, LIGNES,
                "TÉMOIN INVERSE RÉFUTÉ : le tri sous quota large n'a pas rendu toutes ses lignes"
            ),
            Err(m) => panic!(
                "TÉMOIN INVERSE RÉFUTÉ : la surveillance refuse un tri qui tient LARGEMENT sous la \
                 borne. Une garde qui refuse toujours ne prouve rien et apprend à ne plus la lire. \
                 Message : {m}"
            ),
        }
        assert_eq!(
            octets(&dir),
            0,
            "le déversement doit avoir été rendu au système à la fin du tri : sans ça, la mesure du \
             quota suivant partirait d'un compte qui n'est plus dû à personne"
        );
    }
}
