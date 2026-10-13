// ================================================================================================
// P10.31-y — L'ANNULATION RÉITÈRE JUSQU'À LA FIN, ET UNE INTERRUPTION PENDANT L'ANALYSE EST CLASSÉE
// ================================================================================================
// `/api/cancel` appelait `interrupt()` UNE fois. SQLite efface le drapeau d'interruption au début de
// la préparation et au premier pas quand aucune instruction de la connexion n'est active : une
// annulation tombée avant le premier pas était perdue, et la requête courait jusqu'à son budget. Et
// une interruption vue PENDANT l'analyse (`conn.prepare`) sortait avec le texte brut du moteur.
//
// Témoins DÉTERMINISTES, aucun chronomètre : ils comptent les interruptions que la garde émet
// (`temoin_des_interruptions_de_ce_fil`) et placent l'annulation ou l'échéance par un point d'arrêt
// AVANT la préparation (`avant_la_preparation_de_ce_fil`). Pour placer une interruption DANS
// l'analyse, un énoncé est laissé ACTIF sur la connexion : `sqlite3RunParser` n'efface alors plus le
// drapeau (`if( db->nVdbeActive==0 )`, `sqlcipher/sqlite3.c:175396` de `libsqlite3-sys` 0.28), et
// l'analyse le lit au premier blanc. En production cette fenêtre est une course ; ici elle est forcée.
//
//   · `annulation_une_fois` (l'annulation ne réveille pas la garde : une seule interruption) ;
//   · `borne_huit` (la garde cesse d'interrompre après huit) ;
//   · `annulation_perdue` (le drapeau `cancelled` n'est plus lu : rendu « budget ») ;
//   · `analyse_non_classee` (la préparation rend le texte brut du moteur, comportement d'avant) ;
//   · `classe_par_texte` (interruption reconnue au texte « interrupted » et non au code) ;
//   · `garde_detachee` (le `Drop` de la garde ne signale ni ne joint : elle survit à sa portée) ;
//   · `periode_1500` (la boucle attend 1500 ms, la constante reste à 10 ms).
// Reprise après vérification :
//   · `periode_arg_200` et `periode_arg_1` (l'ARGUMENT de l'attente change, la variable relevée par
//     l'ancien instrument restait à 10 ms : il fallait mesurer l'attente, pas lire la variable) ;
//   · `qid_toutes_bases` (`annuler_les_requetes` ne compare que le qid : une base annule les requêtes
//     d'une autre) ;
//   · `gestionnaire_coupe` (la route `/api/cancel` appelle `annuler_les_requetes` sur une autre clé).
// Seconde reprise :
//   · `P5` (une seconde attente de 200 ms, hors de l'attente que l'instrument précédent chronométrait :
//     la période réelle passait à ~210 ms sans rien faire rougir). La période est désormais jugée sur
//     l'INTERVALLE entre deux `interrupt()` émis, horodatés au moment de l'émission ; `W200` et `W1`
//     (argument de l'attente à 200 ms et à 1 ms) rejoués sur cet instrument ;
//   · `cfg_ouvert` (l'entrée sans réveil `From<Arc<AtomicBool>>` redevient constructible hors des
//     tests : le témoin statique `l_entree_sans_reveil_n_existe_que_dans_les_tests` rougit).
// Troisième reprise :
//   · `B4` (`interrupt()` émis un tour sur vingt, la note et le compte gardés à chaque tour : la période
//     réelle passait à 200 ms et tout restait vert, l'instrument ne lisant que des notes). La note est
//     désormais posée par la fonction qui émet (`Interrupteur::interrompre`), et la période est AUSSI
//     jugée sur l'EFFET : chaque `SQLITE_INTERRUPT` rendu par le moteur, horodaté par le fil qui joue
//     les énoncés (`la_periode_est_jugee_sur_les_interruptions_recues`) ;
//   · `E2` (`annuler_les_requetes` s'arrête à la première entrée de la clé : le COUNT de pagination
//     continuait) — témoin à deux entrées sous le même `(db_path, qid)`, une garde chacune ;
//   · `I2` (la route rend au moins 1 : elle prétendait avoir annulé un qid inconnu) — témoin de route
//     sur un qid jamais enregistré et sur un qid déjà fini.
// Quatrième reprise (témoins neufs dans `annulation_cle_et_classement.rs`) :
//   · `Y9` (`annuler_les_requetes` annule toute entrée de la base, quel que soit le qid : en mono-tenant,
//     un seul `/api/cancel` d'un lecteur tuait les requêtes de tous) — deux qid sur la même base ;
//   · `Y11` (toute `SqliteFailure` classée interruption) et `Y12` (le texte brut rendu à la place du refus
//     d'exploitant) — une erreur de pas (`integer overflow`) et un `SQLITE_NOMEM` passés par `run_on_conn` ;
//   · `F5` (le quota de déversement n'est plus reconnu dans `classer_l_echec`) — un tri qui déverse au-delà
//     du quota, passé par `run_on_conn` ;
//   · `Y2` (le réveil de la garde sans `notify_all`) — une annulation posée APRÈS que la garde attend ;
//   · `Y18` (la boucle alterne 10 et 200 ms) — la borne haute de la période porte sur l'agrégat ;
//   · `S1` (la sonde de l'entrée sans réveil ne compte que le texte `reveil: None`) — contrôles hostiles.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   · la réitération est suivie jusqu'à SOIXANTE-QUATRE interruptions : une garde qui s'arrêterait
//     plus loin (cent, mille) passerait. Aucun témoin fini ne peut exclure toutes les bornes ; le
//     tenir sans borne demanderait une requête sans fin et un chronomètre, ce que ce fichier refuse ;
//   · la période est bornée au chronomètre, sur l'intervalle entre deux interruptions émises, par en
//     dessous (structurel) et, par au-dessus, sur l'agrégat de quinze intervalles émis puis REÇUS : au
//     plus cinq d'entre eux atteignent cinq périodes (50 ms). Une boucle dont deux tours sur trois restent
//     sous 50 ms passe, quelle que soit la longueur du troisième (allonger un tour sur trois, ou
//     alterner 10 et 40 ms, reste vert). La borne haute reste chronométrique dans les deux témoins : une
//     machine saturée au point de retarder six intervalles sur quinze au-delà de 50 ms la ferait rougir.
//     La borne basse ne lit que les notes : une boucle qui noterait toutes les 10 ms en émettant PLUS
//     souvent passerait ;
//   · tester l'annulation AVANT le quota dans `classer_l_echec` (`F4`) n'a pas de témoin : il faudrait une
//     annulation et un franchissement de quota sur la même instruction ;
//   · l'ordre « drapeau d'abord » de `CancelEntry::annuler` n'est pas témoigné : réveil, interruption puis
//     drapeau (`Y8`) reste vert. Conséquence : pendant la fenêtre entre l'interruption et le drapeau (de
//     l'ordre de la nanoseconde, sur le fil de `/api/cancel`), la requête lirait `cancelled = false` et
//     sortirait classée budget au lieu d'annulée — une phrase fausse, aucune requête qui survit ;
//   · la sonde de l'entrée sans réveil est TEXTUELLE : elle voit `reveil: <valeur>` pour toute valeur autre
//     que `Some(..)`, pas une entrée bâtie par la forme abrégée (`let reveil = None; … { cancelled, reveil }`)
//     ni un `Some(..)` vidé ensuite ;
//   · `/api/cancel` n'exige pas que l'appelant soit celui qui a lancé la requête : sur une même base, qui
//     connaît un qid peut l'annuler. Le qid est tiré par le client et n'est jamais listé ; ce n'est pas
//     jugé ici ;
//   · l'ordre de destruction (l'entrée sort du registre, PUIS la garde est jointe) n'est pas témoigné :
//     l'inverser (`H2`) reste vert. Conséquence nulle par raisonnement, non par témoin : une
//     interruption posée sur une connexion oisive est effacée à la préparation suivante ;
//   · l'interruption immédiate de `CancelEntry::annuler` est redondante avec la garde réveillée : elle
//     n'est pas témoignée ici. L'entrée sans réveil (`From<Arc<AtomicBool>>`) n'existe plus que sous
//     `#[cfg(test)]` : la tenue est STRUCTURELLE (un appelant de production ne compile pas) et le
//     témoin qui la garde est STATIQUE (il lit le source, il ne joue rien).

#[cfg(test)]
mod annulation_reiteree {
    use rusqlite::functions::FunctionFlags;
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Dix millions d'itérations : sans interruption, plusieurs secondes de calcul. La requête se
    /// TERMINE, donc le rouge d'un mutant est un compte rendu, pas un blocage.
    pub(super) const LONGUE: &str =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000000) SELECT count(*) FROM c";

    /// Deux millions d'itérations : les requêtes SUIVANTES, sans annulation ni échéance. Elles durent
    /// des centaines de périodes de réitération : une garde qui interromprait encore les casserait.
    pub(super) const SUIVANTE: &str =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2000000) SELECT count(*) FROM c";

    /// Bien au-delà de huit : une garde bornée à quelques interruptions n'y arrive jamais. Une garde
    /// bornée AU-DELÀ de ce nombre n'est PAS rejetée (limite avouée en tête de fichier).
    const BIEN_AU_DELA_DE_HUIT: usize = 64;

    /// Nombre d'intervalles entre interruptions successives mesurés par le témoin de la période.
    const INTERVALLES_MESURES: usize = 15;

    /// Borne haute de la période, jugée sur l'AGRÉGAT des quinze intervalles : au plus un tiers d'entre eux
    /// atteint cinq périodes. Le plus court intervalle seul ne bornait rien (une boucle qui alterne 10 et
    /// 200 ms, mutant `Y18`, en garde un court sur deux) ; un tiers toléré laisse passer quelques
    /// retards d'ordonnancement sans laisser passer une boucle qui s'allonge un tour sur deux.
    const INTERVALLES_LONGS_TOLERES: usize = INTERVALLES_MESURES / 3;

    /// Les intervalles, parmi les `INTERVALLES_MESURES` premiers, qui atteignent cinq périodes.
    fn intervalles_longs(intervalles: &[Duration]) -> Vec<Duration> {
        let periode = crate::query_exec::REITERATION_DE_L_INTERRUPTION;
        intervalles.iter().take(INTERVALLES_MESURES).copied().filter(|d| *d >= periode * 5).collect()
    }

    /// Borne d'attente de l'instrument : au-delà, le témoin refuse de conclure (il ne passe pas vert).
    pub(super) const ATTENTE_MAX: Duration = Duration::from_secs(20);

    pub(super) fn attendre_au_moins(n: &AtomicUsize, seuil: usize) -> bool {
        let t0 = Instant::now();
        while n.load(Ordering::SeqCst) < seuil {
            if t0.elapsed() > ATTENTE_MAX {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// Les instruments de ce fil, retirés à la sortie même en panique (un témoin suivant sur le même
    /// fil ne doit pas hériter d'un point d'arrêt).
    pub(super) struct Instruments;
    impl Instruments {
        pub(super) fn poser(n: &Arc<AtomicUsize>) -> Self {
            crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n.clone()));
            Instruments
        }
    }
    impl Drop for Instruments {
        fn drop(&mut self) {
            crate::query_exec::temoin_des_interruptions_de_ce_fil(None);
            crate::query_exec::temoin_de_la_periode_de_ce_fil(None);
            crate::query_exec::avant_la_preparation_de_ce_fil(None);
        }
    }

    /// Le geste de `/api/cancel` (`annuler_les_requetes`, appelé tel quel par le gestionnaire) posé
    /// juste avant la préparation. `posees` reçoit le nombre de requêtes atteintes.
    fn annuler_avant_la_preparation(cle: &'static str, qid: &'static str, posees: &Arc<AtomicU32>) {
        let posees = posees.clone();
        crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
            posees.store(crate::query_exec::annuler_les_requetes(cle, qid), Ordering::SeqCst);
        })));
    }

    /// État de la première ligne de `requete_qui_attend_la_garde` : jamais atteinte (l'énoncé a été
    /// abandonné AVANT elle — ce qui n'est possible que par une interruption tombée pendant le parcours,
    /// donc par la garde), atteinte et la garde a réinterrompu, ou atteinte et la garde s'est TUE.
    const NON_ATTEINTE: u8 = 0;
    const GARDE_VUE: u8 = 1;
    const GARDE_MUETTE: u8 = 2;

    /// Une requête longue dont la PREMIÈRE ligne attend que la garde ait émis une interruption de plus
    /// qu'à cet instant. L'énoncé est alors ACTIF (SQLite n'efface plus le drapeau) : la requête est
    /// abandonnée parce que la garde réitère ENCORE — sans parier sur la durée du calcul.
    fn requete_qui_attend_la_garde(c: &Connection, n: &Arc<AtomicUsize>, ligne: &Arc<AtomicU8>) -> &'static str {
        let (n, ligne) = (n.clone(), ligne.clone());
        c.create_scalar_function("ar_attendre_la_garde", 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
            let x: i64 = ctx.get(0)?;
            if x == 1 {
                let seuil = n.load(Ordering::SeqCst) + 1;
                ligne.store(if attendre_au_moins(&n, seuil) { GARDE_VUE } else { GARDE_MUETTE }, Ordering::SeqCst);
            }
            Ok(x)
        })
        .unwrap();
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10000000) \
         SELECT count(ar_attendre_la_garde(x)) FROM c"
    }

    /// Laisse un énoncé ACTIF (une ligne lue, une restante) : tant qu'il vit, SQLite n'efface plus le
    /// drapeau d'interruption au début de l'analyse.
    fn enonce_actif(c: &Connection) -> rusqlite::Statement<'_> {
        let mut s = c.prepare("SELECT 1 UNION ALL SELECT 2").unwrap();
        // `raw_query` + `step` sans réinitialisation : l'énoncé reste en vol jusqu'à son `Drop`.
        {
            let mut rows = s.raw_query();
            assert!(rows.next().unwrap().is_some(), "instrument : l'énoncé actif n'a rendu aucune ligne");
            std::mem::forget(rows);
        }
        s
    }

    pub(super) fn compte(v: &serde_json::Value) -> i64 {
        v["rows"][0][0].as_i64().unwrap_or(-1)
    }

    /// Une annulation posée AVANT le premier pas (le drapeau est effacé par la préparation et le premier
    /// pas) abandonne quand même la requête : la garde, réveillée par l'annulation, réitère.
    #[test]
    fn une_annulation_posee_avant_le_premier_pas_abandonne_la_requete() {
        let c = Connection::open_in_memory().unwrap();
        let (cle, qid) = (":memory:annulation-avant-le-premier-pas", "qid-avant-le-premier-pas");
        let n = Arc::new(AtomicUsize::new(0));
        let ligne = Arc::new(AtomicU8::new(NON_ATTEINTE));
        let posees = Arc::new(AtomicU32::new(0));
        let sql = requete_qui_attend_la_garde(&c, &n, &ligne);
        let r = {
            let _i = Instruments::poser(&n);
            annuler_avant_la_preparation(cle, qid, &posees);
            crate::query_exec::run_on_conn(&c, cle, sql, 600_000, Some(qid))
        };
        assert_eq!(posees.load(Ordering::SeqCst), 1, "instrument : l'annulation n'a atteint aucune requête enregistrée");
        let err = r.expect_err("une annulation posée avant le premier pas DOIT abandonner la requête ; elle a couru jusqu'au bout");
        assert_eq!(err, "requête annulée par l'utilisateur");
        assert_ne!(ligne.load(Ordering::SeqCst), GARDE_MUETTE, "la garde ne réinterrompait plus pendant le parcours");
    }

    /// Une annulation vue PENDANT l'analyse sort classée « annulée par l'utilisateur », jamais avec le
    /// texte brut du moteur.
    #[test]
    fn une_annulation_pendant_l_analyse_est_classee_annulation() {
        let c = Connection::open_in_memory().unwrap();
        let (cle, qid) = (":memory:annulation-pendant-l-analyse", "qid-pendant-l-analyse");
        let n = Arc::new(AtomicUsize::new(0));
        let posees = Arc::new(AtomicU32::new(0));
        let actif = enonce_actif(&c);
        let r = {
            let _i = Instruments::poser(&n);
            annuler_avant_la_preparation(cle, qid, &posees);
            crate::query_exec::run_on_conn(&c, cle, LONGUE, 600_000, Some(qid))
        };
        drop(actif);
        assert_eq!(posees.load(Ordering::SeqCst), 1, "instrument : l'annulation n'a atteint aucune requête enregistrée");
        let err = r.expect_err("une annulation vue pendant l'analyse DOIT abandonner la requête");
        assert_eq!(err, "requête annulée par l'utilisateur", "l'interruption pendant l'analyse doit être classée");
    }

    /// Une échéance de budget vue PENDANT l'analyse sort classée « budget », jamais « interrupted ».
    #[test]
    fn une_echeance_pendant_l_analyse_est_classee_budget() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let vue = Arc::new(AtomicBool::new(false));
        let actif = enonce_actif(&c);
        let r = {
            let _i = Instruments::poser(&n);
            let (n, vue) = (n.clone(), vue.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                vue.store(attendre_au_moins(&n, 1), Ordering::SeqCst);
            })));
            crate::query_exec::run_on_conn(&c, ":memory:echeance-pendant-l-analyse", LONGUE, 1, None)
        };
        drop(actif);
        assert!(vue.load(Ordering::SeqCst), "instrument : la garde n'a émis aucune interruption avant l'analyse");
        let err = r.expect_err("une échéance vue pendant l'analyse DOIT abandonner la requête");
        assert!(err.contains("budget"), "l'interruption pendant l'analyse doit être classée budget : {err}");
        assert!(!err.contains("annulée"), "un dépassement de budget n'est pas une annulation client : {err}");
    }

    /// Une erreur d'analyse qui CITE le mot « interrupted » (identifiant de la requête) n'est pas une
    /// interruption : elle sort telle quelle, jamais en dépassement de budget.
    #[test]
    fn une_erreur_d_analyse_qui_cite_interrupted_n_est_pas_un_budget() {
        let c = Connection::open_in_memory().unwrap();
        let r = crate::query_exec::run_on_conn(&c, ":memory:colonne-interrupted", "SELECT interrupted FROM (SELECT 1 AS x)", 600_000, None);
        let err = r.expect_err("la colonne n'existe pas");
        assert!(err.contains("no such column"), "l'erreur du moteur doit sortir telle quelle : {err}");
        assert!(!err.contains("budget") && !err.contains("annulée"), "ce n'est pas une interruption : {err}");
    }

    /// Après une annulation, la connexion poolée sert DEUX requêtes enchaînées entières : l'entrée a
    /// quitté le registre, la garde est jointe, rien ne les interrompt.
    #[test]
    fn deux_requetes_enchainees_apres_une_annulation_rendent_leur_compte() {
        let c = Connection::open_in_memory().unwrap();
        let (cle, qid) = (":memory:annulation-puis-deux-requetes", "qid-puis-deux-requetes");
        let n = Arc::new(AtomicUsize::new(0));
        let ligne = Arc::new(AtomicU8::new(NON_ATTEINTE));
        let posees = Arc::new(AtomicU32::new(0));
        let sql = requete_qui_attend_la_garde(&c, &n, &ligne);
        let _i = Instruments::poser(&n);
        annuler_avant_la_preparation(cle, qid, &posees);
        let annulee = crate::query_exec::run_on_conn(&c, cle, sql, 600_000, Some(qid));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        assert_eq!(annulee.expect_err("la requête annulée doit être abandonnée"), "requête annulée par l'utilisateur");
        let apres = n.load(Ordering::SeqCst);
        let premiere = crate::query_exec::run_on_conn(&c, cle, SUIVANTE, 600_000, Some(qid));
        let seconde = crate::query_exec::run_on_conn(&c, cle, SUIVANTE, 600_000, None);
        for (nom, r) in [("première", premiere), ("seconde", seconde)] {
            let v = r.unwrap_or_else(|e| panic!("la {nom} requête après l'annulation a été interrompue : {e}"));
            assert_eq!(compte(&v), 2_000_000, "la {nom} requête après l'annulation doit être entière");
        }
        assert_eq!(n.load(Ordering::SeqCst), apres, "une garde a interrompu après sa portée");
        assert_eq!(crate::query_exec::annuler_les_requetes(cle, qid), 0, "l'entrée annulée est restée au registre");
    }

    /// La garde expirée réitère BIEN AU-DELÀ de huit interruptions, et la requête lancée ensuite est
    /// encore abandonnée.
    #[test]
    fn la_garde_expiree_reitere_bien_au_dela_de_huit_interruptions() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let ligne = Arc::new(AtomicU8::new(NON_ATTEINTE));
        let sql = requete_qui_attend_la_garde(&c, &n, &ligne);
        let _i = Instruments::poser(&n);
        let r = {
            let _garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
            assert!(
                attendre_au_moins(&n, BIEN_AU_DELA_DE_HUIT),
                "la garde expirée a cessé d'interrompre avant {BIEN_AU_DELA_DE_HUIT} interruptions ({} émises)",
                n.load(Ordering::SeqCst)
            );
            c.query_row(sql, [], |row| row.get::<_, i64>(0))
        };
        match r {
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted => {}
            autre => panic!("la requête sous la garde expirée DOIT être abandonnée ; rendu : {autre:?}"),
        }
        assert_ne!(ligne.load(Ordering::SeqCst), GARDE_MUETTE, "la garde ne réinterrompait plus pendant le parcours");
    }

    /// L'annulation réitère, elle aussi, BIEN AU-DELÀ de huit interruptions jusqu'à la fin : la garde
    /// réveillée par l'annulation en émet soixante-quatre AVANT la préparation (toutes effacées, aucune
    /// instruction n'est active), et elle abandonne encore la requête lancée ensuite.
    #[test]
    fn l_annulation_reitere_bien_au_dela_de_huit_interruptions() {
        let c = Connection::open_in_memory().unwrap();
        let (cle, qid) = (":memory:annulation-au-dela-de-huit", "qid-au-dela-de-huit");
        let n = Arc::new(AtomicUsize::new(0));
        let ligne = Arc::new(AtomicU8::new(NON_ATTEINTE));
        let vue = Arc::new(AtomicBool::new(false));
        let posees = Arc::new(AtomicU32::new(0));
        let sql = requete_qui_attend_la_garde(&c, &n, &ligne);
        let r = {
            let _i = Instruments::poser(&n);
            let (n, vue, posees) = (n.clone(), vue.clone(), posees.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                posees.store(crate::query_exec::annuler_les_requetes(cle, qid), Ordering::SeqCst);
                vue.store(attendre_au_moins(&n, BIEN_AU_DELA_DE_HUIT), Ordering::SeqCst);
            })));
            crate::query_exec::run_on_conn(&c, cle, sql, 600_000, Some(qid))
        };
        assert_eq!(posees.load(Ordering::SeqCst), 1, "instrument : l'annulation n'a atteint aucune requête enregistrée");
        assert!(
            vue.load(Ordering::SeqCst),
            "la garde annulée a cessé d'interrompre avant {BIEN_AU_DELA_DE_HUIT} interruptions ({} émises)",
            n.load(Ordering::SeqCst)
        );
        assert_eq!(r.expect_err("la requête annulée doit être abandonnée"), "requête annulée par l'utilisateur");
        assert_ne!(ligne.load(Ordering::SeqCst), GARDE_MUETTE, "la garde ne réinterrompait plus pendant le parcours");
    }

    /// La période est jugée AU SITE D'USAGE, sur l'INTERVALLE entre deux interruptions successives, chacune
    /// notée par `Interrupteur::interrompre` juste après l'avoir émise. Tout ce que la boucle fait entre
    /// deux interruptions y entre : l'attente, une seconde attente, un détour. Par en dessous, propriété
    /// structurelle : l'interruption suivante n'est émise qu'après une attente achevée sans signal de fin,
    /// donc à son échéance, donc au moins une période après. Par au-dessus : au plus un tiers des quinze
    /// intervalles atteint cinq périodes. Ce témoin lit des NOTES : une note posée sans émission (mutant
    /// `B4`) le laisse vert. L'émission elle-même est jugée par son effet au témoin
    /// `la_periode_est_jugee_sur_les_interruptions_recues`.
    #[test]
    fn la_periode_de_reiteration_est_jugee_au_site_d_usage() {
        let c = Connection::open_in_memory().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let horodatages = Arc::new(parking_lot::Mutex::new(Vec::<Instant>::new()));
        let _i = Instruments::poser(&n);
        crate::query_exec::temoin_de_la_periode_de_ce_fil(Some(horodatages.clone()));
        {
            let _garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
            // L'horodatage de rang k est posé AVANT que le compte ne passe à k.
            assert!(
                attendre_au_moins(&n, INTERVALLES_MESURES + 1),
                "instrument : la garde n'a pas émis {} interruptions ({} émises)",
                INTERVALLES_MESURES + 1,
                n.load(Ordering::SeqCst)
            );
        } // garde jointe : plus aucune interruption ne s'ajoute
        let emis = horodatages.lock().clone();
        assert_eq!(emis.len(), n.load(Ordering::SeqCst), "instrument : une interruption émise n'a pas été horodatée");
        let intervalles: Vec<Duration> = emis.windows(2).map(|w| w[1].duration_since(w[0])).collect();
        let periode = crate::query_exec::REITERATION_DE_L_INTERRUPTION;
        assert_eq!(periode, Duration::from_millis(10), "la constante de réitération a changé");
        assert!(intervalles.len() >= INTERVALLES_MESURES, "instrument : {} intervalle(s) mesuré(s)", intervalles.len());
        assert!(
            intervalles.iter().all(|d| *d >= periode),
            "deux interruptions successives ont été émises à MOINS d'une période de 10 ms : {intervalles:?}"
        );
        let longs = intervalles_longs(&intervalles);
        assert!(
            longs.len() <= INTERVALLES_LONGS_TOLERES,
            "{} des {INTERVALLES_MESURES} intervalles entre deux interruptions émises atteignent cinq périodes (au plus \
             {INTERVALLES_LONGS_TOLERES} tolérés) : la boucle ne réinterrompt pas toutes les 10 ms : {intervalles:?}",
            longs.len()
        );
    }

    /// La période jugée sur l'EFFET, pas sur une note : chaque `SQLITE_INTERRUPT` que le moteur rend est
    /// horodaté par le fil qui joue les énoncés. Sous une garde expirée, des énoncés de deux millions de
    /// pas s'enchaînent sur la connexion ; chacun ne s'arrête que si une interruption ÉMISE tombe pendant
    /// qu'il court (SQLite efface le drapeau au premier pas d'un énoncé quand aucun autre n'est actif :
    /// une interruption tombée entre deux énoncés est perdue, jamais comptée deux fois). Aucune note de
    /// l'instrument ne peut fabriquer cet effet : une boucle qui noterait toutes les 10 ms mais
    /// n'émettrait qu'un tour sur vingt (mutant `B4`) n'arrête un énoncé que toutes les 200 ms. Par
    /// au-dessus seulement : au plus un tiers des quinze intervalles entre deux arrêts reçus atteint cinq
    /// périodes. La borne basse n'a pas de sens ici (un arrêt reçu tard puis un arrêt reçu tôt sont
    /// plus proches que leurs émissions) : elle reste jugée sur les émissions, au témoin précédent.
    #[test]
    fn la_periode_est_jugee_sur_les_interruptions_recues() {
        let c = Connection::open_in_memory().unwrap();
        let mut recues: Vec<Instant> = Vec::new();
        let mut entieres = 0usize;
        let t0 = Instant::now();
        {
            let _garde = crate::query_exec::budget_guard(c.get_interrupt_handle(), 1);
            while recues.len() < INTERVALLES_MESURES + 1 && t0.elapsed() < ATTENTE_MAX {
                match c.query_row(SUIVANTE, [], |row| row.get::<_, i64>(0)) {
                    Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::OperationInterrupted => {
                        recues.push(Instant::now())
                    }
                    Ok(_) => entieres += 1,
                    Err(autre) => panic!("instrument : l'énoncé a échoué autrement que par une interruption : {autre:?}"),
                }
            }
        } // garde jointe
        assert!(
            recues.len() > INTERVALLES_MESURES,
            "la garde expirée n'a arrêté que {} énoncé(s) en {:?} ({entieres} entier(s)) : elle n'émet plus",
            recues.len(),
            ATTENTE_MAX
        );
        let intervalles: Vec<Duration> = recues.windows(2).map(|w| w[1].duration_since(w[0])).collect();
        let longs = intervalles_longs(&intervalles);
        assert!(
            longs.len() <= INTERVALLES_LONGS_TOLERES,
            "{} des {INTERVALLES_MESURES} intervalles entre deux interruptions REÇUES atteignent cinq périodes (au plus \
             {INTERVALLES_LONGS_TOLERES} tolérés) : la garde n'émet pas toutes les 10 ms, quoi qu'en notent ses \
             instruments : {intervalles:?}",
            longs.len()
        );
    }

    /// Un même `(db_path, qid)` porte DEUX requêtes en vol (la page et le COUNT de pagination) : le geste
    /// de `/api/cancel` les annule TOUTES les deux — drapeau posé ET garde réveillée pour chacune, jugé sur
    /// un compteur d'interruptions PAR garde.
    #[test]
    fn l_annulation_atteint_toutes_les_entrees_d_une_meme_cle() {
        let (cle, qid) = (":memory:deux-entrees-meme-cle", "qid-page-et-count");
        let (c_page, c_count) = (Connection::open_in_memory().unwrap(), Connection::open_in_memory().unwrap());
        let (n_page, n_count) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (d_page, d_count) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let _i = Instruments::poser(&n_page);
        let g_page = crate::query_exec::budget_guard(c_page.get_interrupt_handle(), 600_000);
        crate::query_exec::temoin_des_interruptions_de_ce_fil(Some(n_count.clone()));
        let g_count = crate::query_exec::budget_guard(c_count.get_interrupt_handle(), 600_000);
        let e_page = crate::query_exec::cancel_register(
            cle,
            qid,
            c_page.get_interrupt_handle(),
            crate::query_exec::DrapeauDAnnulation::avec_reveil(d_page.clone(), g_page.reveil()),
        );
        let e_count = crate::query_exec::cancel_register(
            cle,
            qid,
            c_count.get_interrupt_handle(),
            crate::query_exec::DrapeauDAnnulation::avec_reveil(d_count.clone(), g_count.reveil()),
        );
        assert_eq!(crate::query_exec::annuler_les_requetes(cle, qid), 2, "les DEUX requêtes en vol du qid doivent être atteintes");
        assert!(d_page.load(Ordering::SeqCst) && d_count.load(Ordering::SeqCst), "les deux drapeaux doivent être posés");
        assert!(attendre_au_moins(&n_page, 1), "la garde de la page n'a pas été réveillée");
        assert!(attendre_au_moins(&n_count, 1), "la garde du COUNT n'a pas été réveillée");
        drop((e_page, e_count));
        drop((g_page, g_count));
        assert_eq!(crate::query_exec::annuler_les_requetes(cle, qid), 0, "les entrées sont restées au registre");
    }

    /// La route rend `cancelled: 0` pour un qid qui n'est pas en vol (inconnu, ou requête déjà finie) :
    /// elle ne prétend pas avoir annulé ce qu'elle n'a pas atteint.
    #[test]
    fn la_route_cancel_rend_zero_pour_un_qid_qui_n_est_pas_en_vol() {
        let (st, _p) = super::sp_state("ar-route-cancel-inconnu");
        let au = super::sp_au("adm", "admin");
        assert_eq!(annuler_par_la_route(&st, &au, "qid-jamais-enregistre"), 0, "qid inconnu : rien n'a été annulé");
        let c = Connection::open_in_memory().unwrap();
        let qid = "qid-deja-fini";
        let entree = crate::query_exec::cancel_register(
            &crate::req_db_path(&st, &au),
            qid,
            c.get_interrupt_handle(),
            Arc::new(AtomicBool::new(false)),
        );
        drop(entree);
        assert_eq!(annuler_par_la_route(&st, &au, qid), 0, "requête déjà finie : rien n'a été annulé");
    }

    /// L'entrée d'annulation SANS réveil (une seule interruption, le défaut d'avant `P10.31-y`) n'est
    /// constructible que dans les tests : l'`impl From<Arc<AtomicBool>> for DrapeauDAnnulation` est sous
    /// `#[cfg(test)]`, et c'est le seul site du démon qui pose `reveil: None`. Témoin STATIQUE : il lit le
    /// source livré, rien n'y est joué.
    #[test]
    fn l_entree_sans_reveil_n_existe_que_dans_les_tests() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let qe = std::fs::read_to_string(racine.join("query_exec.rs")).expect("query_exec.rs lisible");
        let lignes: Vec<&str> = qe.lines().collect();
        let sites: Vec<usize> = lignes
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("for DrapeauDAnnulation") && l.trim_start().starts_with("impl From<"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(sites.len(), 1, "instrument : l'impl From pour DrapeauDAnnulation est introuvable (sonde cassée)");
        let precedente = lignes[..sites[0]].iter().rev().find(|l| !l.trim().is_empty()).map(|l| l.trim()).unwrap_or("");
        assert!(
            precedente.starts_with("#[cfg(test)]"),
            "l'entrée sans réveil `From<Arc<AtomicBool>>` est constructible hors des tests : un appelant de \
             production y retrouverait l'annulation à interruption unique (ligne précédente : {precedente:?})"
        );
        let poses = poses_de_reveil_sans_garde(&qe);
        assert_eq!(
            poses.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![sites[0] + 2],
            "query_exec.rs pose le champ `reveil` d'une valeur qui n'est pas `Some(..)` hors de l'impl gardée par \
             #[cfg(test)] : {poses:?}"
        );
        // Contrôles HOSTILES de la sonde : chaque forme d'une entrée sans réveil est vue, pas seulement le
        // texte `reveil: None`.
        for hostile in [
            "        DrapeauDAnnulation { cancelled, reveil: Default::default() }",
            "        DrapeauDAnnulation { cancelled, reveil: Option::None }",
            "        DrapeauDAnnulation { cancelled, reveil: None::<ReveilDeLaGarde> }",
            "        CancelEntry { slot, interrupt, cancelled, reveil: None }",
        ] {
            assert_eq!(poses_de_reveil_sans_garde(hostile).len(), 1, "la sonde ne voit pas l'entrée sans réveil : {hostile}");
        }
        for licite in [
            "    reveil: Option<ReveilDeLaGarde>,",
            "    pub(crate) fn avec_reveil(cancelled: Arc<AtomicBool>, reveil: ReveilDeLaGarde) -> Self {",
            "        DrapeauDAnnulation { cancelled, reveil: Some(reveil) }",
            "    // reveil: None dans un commentaire",
        ] {
            assert!(poses_de_reveil_sans_garde(licite).is_empty(), "la sonde accuse une ligne licite : {licite}");
        }
    }

    /// Les lignes de CODE (commentaires exclus) qui posent le champ `reveil` d'une autre valeur que
    /// `Some(..)` : `None`, mais aussi `Default::default()`, `Option::None`, `None::<_>`. Les déclarations
    /// de type (`reveil: Option<ReveilDeLaGarde>`, `reveil: ReveilDeLaGarde`) n'en sont pas. Rend le rang
    /// (à partir de zéro) et la ligne.
    fn poses_de_reveil_sans_garde(source: &str) -> Vec<(usize, String)> {
        source
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim_start().starts_with("//"))
            .filter(|(_, l)| {
                l.match_indices("reveil:").any(|(k, m)| {
                    let valeur = l[k + m.len()..].trim_start();
                    !(valeur.starts_with("Some(") || valeur.starts_with("Option<ReveilDeLaGarde>") || valeur.starts_with("ReveilDeLaGarde"))
                })
            })
            .map(|(i, l)| (i, l.trim().to_string()))
            .collect()
    }

    /// Le geste de la ROUTE `/api/cancel` elle-même (gestionnaire `handlers::query::cancel`, clé
    /// `(req_db_path, qid)`), joué dans un exécuteur à part depuis le point d'arrêt. Rend le
    /// `cancelled` du corps servi.
    pub(super) fn annuler_par_la_route(st: &super::AppState, au: &super::AuthUser, qid: &str) -> u64 {
        let exec = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("exécuteur de test");
        exec.block_on(async {
            let r = crate::handlers::query::cancel(
                axum::extract::State(st.clone()),
                axum::Extension(au.clone()),
                axum::Json(serde_json::json!({ "qid": qid })),
            )
            .await;
            assert_eq!(r.status().as_u16(), 200, "la route d'annulation doit répondre 200");
            let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
            let v: serde_json::Value = serde_json::from_slice(&corps).expect("corps JSON");
            v["cancelled"].as_u64().expect("champ cancelled")
        })
    }

    /// SÉCURITÉ ENTRE BASES : la route `/api/cancel` n'atteint QUE la base de l'appelant. Deux états à deux
    /// bases distinctes portent le MÊME qid en vol (le qid est fourni par le client). L'annulation venue de
    /// B annule l'entrée de B et laisse la requête de A finir ENTIÈRE ; l'annulation venue de A abandonne
    /// la requête de A et laisse l'entrée de B intacte.
    #[test]
    fn la_route_cancel_n_annule_que_la_base_de_l_appelant() {
        let (st_a, _pa) = super::sp_state("ar-route-cancel-a");
        let (st_b, _pb) = super::sp_state("ar-route-cancel-b");
        let au = super::sp_au("adm", "admin");
        let base_a = crate::req_db_path(&st_a, &au);
        let base_b = crate::req_db_path(&st_b, &au);
        assert_ne!(base_a, base_b, "instrument : les deux états doivent porter deux bases distinctes");
        let qid = "qid-partage-entre-deux-bases";
        let c_a = Connection::open_in_memory().unwrap();
        let c_b = Connection::open_in_memory().unwrap();
        let _i = Instruments::poser(&Arc::new(AtomicUsize::new(0)));

        // (1) annulation venue de B, pendant que A et B ont chacune une requête en vol sous le même qid.
        let drapeau_b = Arc::new(AtomicBool::new(false));
        let entree_b = crate::query_exec::cancel_register(&base_b, qid, c_b.get_interrupt_handle(), drapeau_b.clone());
        let atteintes_par_b = Arc::new(AtomicU32::new(u32::MAX));
        {
            let (st_b, au, atteintes) = (st_b.clone(), au.clone(), atteintes_par_b.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                atteintes.store(annuler_par_la_route(&st_b, &au, qid) as u32, Ordering::SeqCst);
            })));
        }
        let r = crate::query_exec::run_on_conn(&c_a, &base_a, SUIVANTE, 600_000, Some(qid));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        drop(entree_b);
        assert_eq!(atteintes_par_b.load(Ordering::SeqCst), 1, "l'annulation de B doit atteindre sa SEULE requête, jamais celle de A");
        assert!(drapeau_b.load(Ordering::SeqCst), "l'annulation de B doit annuler la requête de B");
        let v = r.unwrap_or_else(|e| panic!("la requête de A a été interrompue par l'annulation de B : {e}"));
        assert_eq!(compte(&v), 2_000_000, "la requête de A doit finir entière malgré l'annulation de B");

        // (2) annulation venue de A : la requête de A est abandonnée, l'entrée de B n'est pas touchée.
        let drapeau_b = Arc::new(AtomicBool::new(false));
        let entree_b = crate::query_exec::cancel_register(&base_b, qid, c_b.get_interrupt_handle(), drapeau_b.clone());
        let atteintes_par_a = Arc::new(AtomicU32::new(u32::MAX));
        {
            let (st_a, au, atteintes) = (st_a.clone(), au.clone(), atteintes_par_a.clone());
            crate::query_exec::avant_la_preparation_de_ce_fil(Some(Box::new(move || {
                atteintes.store(annuler_par_la_route(&st_a, &au, qid) as u32, Ordering::SeqCst);
            })));
        }
        let r = crate::query_exec::run_on_conn(&c_a, &base_a, LONGUE, 600_000, Some(qid));
        crate::query_exec::avant_la_preparation_de_ce_fil(None);
        drop(entree_b);
        assert_eq!(atteintes_par_a.load(Ordering::SeqCst), 1, "l'annulation de A doit atteindre sa requête, et elle seule");
        assert!(!drapeau_b.load(Ordering::SeqCst), "l'annulation de A ne doit pas toucher la requête de B");
        assert_eq!(r.expect_err("la requête de A annulée par la route doit être abandonnée"), "requête annulée par l'utilisateur");
    }
}
