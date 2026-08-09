// LA SÉRIE DU BUDGET — ce que ces tests prouvent, et dans quel ordre.
//
//   1. UN REFUS DE MESURER NE DEVIENT JAMAIS UN ZÉRO. C'est l'invariant du chantier : `mesurer` refuse
//      déjà de publier quand sa comptabilité ne ferme pas, et ce refus doit SE PROPAGER jusqu'à la
//      série et jusqu'à `/metrics`. On le prouve sur le vrai refus (produit par une base réelle), puis
//      sur les trois surfaces (points écrits, exposition Prometheus, JSON).
//   2. LES TROIS ÉTATS SONT DISTINCTS. « jamais mesuré » n'est pas « mesuré et refusé », qui n'est pas
//      « mesuré ». Une jauge absente, une jauge à 0 et une jauge à N sont trois phrases différentes.
//   3. LA SÉRIE SUFFIT À CALCULER UNE PART. La somme des seaux publiés EST le fichier — donc « la part
//      FTS5 a-t-elle baissé ? » se répond depuis la série SEULE, sans seconde mesure et sans relevé.
//   4. LE PARCOURS NE PREND PAS LE VERROU D'ÉCRITURE. Mesuré en tenant le verrou pendant la mesure.
//   5. LE COÛT EST BORNÉ PAR CONSTRUCTION — en CPU (`prochain_sommeil`) et en DISQUE (la rétention
//      complète de la série, MESURÉE sur le schéma réel, pas estimée).
//
// AUCUN de ces tests n'assère un état global au processus : les fonctions qui portent la logique sont
// PURES (elles prennent l'instant et la mesure en paramètres), et les tests qui touchent une base
// utilisent chacun leur propre fichier temporaire. Le cache `DERNIERE` n'est jamais asserté.

#[cfg(test)]
mod ventilation_serie_tests {
    use crate::db_ventilation::{self, Echec};
    use crate::tmp_possede::TmpDb;
    use crate::ventilation_serie::*;
    use crate::ingest::store::SqlcipherEventStore;
    use crate::{migrate, read_with, MetricRow, RETENTION_FIELDS};
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::sync::Arc;
    use std::time::Duration;

    /// Une base FICHIER au schéma RÉEL du produit (`db/schema.sql` + toute la chaîne de migrations) —
    /// `dbstat` compte des PAGES, il lui faut un vrai pager, et la borne disque ne vaut rien si elle
    /// est mesurée sur une imitation du schéma.
    fn base_reelle(etiquette: &str) -> (TmpDb, Connection) {
        let tmp = TmpDb::neuf(etiquette);
        let conn = Connection::open(tmp.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// Une mesure PRISE, FABRIQUÉE sans base. Réservée aux tests qui portent sur la FORME de ce qui est
    /// publié (noms, étiquettes, DTO). **Jamais** pour un test qui COMPTE les seaux : une liste écrite à
    /// la main resterait intacte si le code cessait d'en publier un — le compte tomberait toujours juste
    /// et la garde ne garderait rien (constaté en mutant `seaux()`).
    fn prise_fabriquee(ts: i64) -> Mesure {
        Mesure::Prise {
            ts,
            octets: vec![("donnees", 900), ("index", 400), ("fts", 160), ("non_classe", 0), ("libres", 40)],
            duree_ms: 35_433,
        }
    }

    /// Une mesure PRISE sur une VRAIE base : sa liste de seaux sort de `seaux()`, donc elle suit le code.
    /// C'est par ici que passent tous les tests qui comptent ou qui somment.
    fn mesure_reelle(etiquette: &str) -> Mesure {
        let (tmp, conn) = base_reelle(etiquette);
        drop(conn);
        let m = mesurer_une_fois(tmp.as_str(), 1_800_000_000);
        match &m {
            Mesure::Prise { .. } => m,
            Mesure::NonPrise { cause, phrase, .. } => panic!("précondition : mesure refusée ({cause}) : {phrase}"),
        }
    }

    // =============================================================================================
    // 1. LE REFUS SE PROPAGE — et il ne se traduit jamais en zéro
    // =============================================================================================

    /// LE VRAI REFUS, SUR UNE VRAIE BASE. On ne fabrique pas un `Echec` à la main : on donne à
    /// `mesurer` un `page_count` qui ne correspond pas au fichier — exactement ce qui arrive quand une
    /// écriture est committée pendant le parcours — et on suit ce que ça produit jusqu'à la série.
    ///
    /// MUTATION : faire retomber la branche d'erreur sur des octets à zéro (publier les seaux avec la
    /// valeur 0 quand la comptabilité ne ferme pas) ⇒ `aucun_octet` devient faux et l'assertion nomme
    /// la série fautive.
    #[test]
    fn une_comptabilite_qui_ne_ferme_pas_produit_un_trou_pas_un_zero() {
        let (_tmp, conn) = base_reelle("vent-refus");
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();

        // Précondition : sur le VRAI compte, la mesure passe. Sans ça, le test ci-dessous prouverait
        // seulement que tout échoue toujours.
        assert!(
            db_ventilation::mesurer(&conn, page_size, page_count, 0).is_ok(),
            "précondition : la ventilation doit être publiable sur une base saine"
        );

        // Le refus : une page de plus que ce que le fichier contient.
        let refus = db_ventilation::mesurer(&conn, page_size, page_count + 1, 0);
        let echec = match refus {
            Err(e) => e,
            Ok(_) => panic!("la comptabilité a fermé sur un page_count FAUX — la garde ne garde rien"),
        };
        assert_eq!(echec.cause(), "comptabilite_non_fermee");

        let m = depuis_resultat(1_800_000_000, 42, Err(echec));
        let pts = points(&m);
        let aucun_octet = pts.iter().all(|p| p.nom != NOM_POSTE);
        assert!(
            aucun_octet,
            "un refus a publié des octets : un 0 octet se lit « ce poste est vide », pas « je n'ai pas mesuré »"
        );
        let ok: Vec<f64> = pts.iter().filter(|p| p.nom == NOM_OK).map(|p| p.valeur).collect();
        assert_eq!(ok, vec![0.0], "le refus doit être DIT par `{NOM_OK}` = 0, une seule fois");
        assert!(
            pts.iter().any(|p| p.nom == NOM_OK
                && p.etiquettes.as_deref() == Some("{\"cause\":\"comptabilite_non_fermee\"}")),
            "la CAUSE doit voyager avec le refus, sinon la série dit « raté » sans dire pourquoi"
        );
    }

    /// La même exigence sur l'exposition Prometheus : l'ABSENCE d'une jauge est la façon dont
    /// Prometheus dit « pas de valeur ». Un `0` n'en est pas une.
    ///
    /// MUTATION : émettre `plume_db_poste_bytes{...} 0` sur la branche `NonPrise` ⇒ rouge ici.
    #[test]
    fn lexposition_dun_refus_ne_porte_aucune_jauge_doctets() {
        let m = Mesure::NonPrise {
            ts: 1_800_000_000,
            cause: "comptabilite_non_fermee",
            phrase: "écart de 1 page".into(),
            duree_ms: 42,
        };
        let texte = exposition_prom(&Some(m), 1_800_000_060);
        assert!(
            !texte.contains(NOM_POSTE),
            "l'exposition d'un refus contient une jauge d'octets :\n{texte}"
        );
        assert!(texte.contains("plume_db_ventilation_ok{cause=\"comptabilite_non_fermee\"} 0"), "{texte}");
        assert!(texte.contains("plume_db_ventilation_age_seconds 60"), "{texte}");
    }

    /// TROIS ÉTATS, TROIS SORTIES. « jamais mesuré » ne doit surtout pas se dire `ok 0` : ça
    /// accuserait une panne qui n'a pas eu lieu, et au démarrage ce serait le cas de TOUS les pods.
    ///
    /// MUTATION : rendre `ok 0` quand le cache est vide ⇒ la première assertion rougit.
    #[test]
    fn jamais_mesure_nest_pas_mesure_et_refuse() {
        assert_eq!(exposition_prom(&None, 1_800_000_000), "", "« jamais mesuré » doit être MUET, pas un échec");
        assert!(crate::ventilation_serie::json(&None, 1_800_000_000).is_null(), "idem côté JSON : absent, pas un objet de zéros");

        let refuse = exposition_prom(
            &Some(Mesure::NonPrise { ts: 1, cause: "dbstat_indisponible", phrase: "x".into(), duree_ms: 1 }),
            2,
        );
        let mesure = exposition_prom(&Some(prise_fabriquee(1)), 2);
        assert!(refuse.contains("plume_db_ventilation_ok{cause=\"dbstat_indisponible\"} 0"));
        assert!(mesure.contains("plume_db_ventilation_ok{cause=\"aucune\"} 1"));
        assert!(mesure.contains(NOM_POSTE) && !refuse.contains(NOM_POSTE), "les trois états doivent être DISTINCTS");
    }

    /// Chaque cause d'échec DOIT pouvoir se publier : une cause muette rendrait un refus indiscernable
    /// d'un autre, et la série ne dirait plus pourquoi elle a un trou.
    ///
    /// MUTATION : ajouter une variante à `Echec` sans lui donner de clé ⇒ `cause()` ne compile pas
    /// (match exhaustif, E0004). Ce test, lui, refuse une clé vide ou instable.
    #[test]
    fn chaque_cause_de_refus_porte_une_cle_stable() {
        let causes = [
            Echec::LectureSchema("x".into()).cause(),
            Echec::Dbstat("x".into()).cause(),
            Echec::ComptabiliteNonFermee { pages_vues: 1, freelist: 0, lock_byte: 0, page_count: 2 }.cause(),
            CAUSE_AUCUNE,
        ];
        for c in causes {
            assert!(!c.is_empty(), "une cause sans nom ne peut pas être publiée");
            assert!(
                c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "clé d'étiquette instable : {c:?} — une étiquette qui suit la traduction coupe la série en deux"
            );
        }
        let mut d = causes.to_vec();
        d.sort_unstable();
        d.dedup();
        assert_eq!(d.len(), causes.len(), "deux causes partagent une clé -> les refus se confondraient");
    }

    // =============================================================================================
    // 2. LA COLLECTE ÉCRIT VRAIMENT — dans la table que les consommateurs lisent
    // =============================================================================================

    /// LA SÉRIE ARRIVE DANS `metric`. C'est la table que la commande SOQL `metric` interroge (elle
    /// UNIONNE `metric` et `metric_rollup`), celle des panneaux et celle des règles. Le test relit ce
    /// qui a été écrit : nom, étiquette, valeur, et `host` NULL (la ventilation décrit LA BASE, pas une
    /// machine — un hôte l'inscrirait dans l'inventaire de flotte).
    ///
    /// MUTATION : retirer un seau de `seaux()` (ou l'`INSERT` de `publier`) ⇒ le compte attendu, DÉRIVÉ
    /// de `db_ventilation::TOUS`, ne tombe plus et l'assertion nomme le seau manquant.
    #[test]
    fn publier_ecrit_la_serie_dans_metric() {
        let (_tmp, conn) = base_reelle("vent-publie");
        let m = mesure_reelle("vent-publie-src"); // la liste des seaux vient du CODE, pas d'une fixture
        let attendus = points(&m).len();
        assert_eq!(publier(&conn, &m), attendus, "toutes les lignes de la mesure doivent être écrites");

        let n_postes: i64 = conn
            .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", rusqlite::params![NOM_POSTE], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n_postes as usize,
            db_ventilation::TOUS.len() + 1,
            "la série publie UN point par poste de `db_ventilation::TOUS`, plus les pages libres"
        );

        let (lab, host): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT labels, host FROM metric WHERE name=?1 AND labels=?2",
                rusqlite::params![NOM_POSTE, "{\"poste\":\"fts\"}"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(lab.as_deref(), Some("{\"poste\":\"fts\"}"));
        assert!(host.is_none(), "la ventilation décrit LA BASE : lui donner un hôte inventerait une machine");
        // Le seau des pages libres doit être là AUSSI : sans lui la somme ne ferait plus le fichier.
        let n_libres: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metric WHERE name=?1 AND labels=?2",
                rusqlite::params![NOM_POSTE, format!("{{\"poste\":\"{}\"}}", db_ventilation::CLE_LIBRES)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_libres, 1, "le seau des pages libres n'est pas publié -> la somme ne fait plus le fichier");
    }

    /// LE TROU EST UN TROU DANS LA TABLE AUSSI. Un refus ne doit pas laisser de ligne d'octets — sinon
    /// le `timechart` tracerait une chute à zéro là où il n'y a eu qu'une absence de mesure, et on
    /// conclurait à un gain de place qui n'a pas eu lieu.
    ///
    /// MUTATION : publier les seaux à 0 sur refus ⇒ `n_postes` passe à 5 et l'assertion rougit.
    #[test]
    fn un_refus_necrit_aucune_ligne_doctets() {
        let (_tmp, conn) = base_reelle("vent-trou");
        let m = Mesure::NonPrise { ts: 1_800_000_000, cause: "lecture_schema", phrase: "x".into(), duree_ms: 7 };
        publier(&conn, &m);
        let n_postes: i64 = conn
            .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", rusqlite::params![NOM_POSTE], |r| r.get(0))
            .unwrap();
        assert_eq!(n_postes, 0, "un refus a laissé des octets dans la série");
        let ok: f64 = conn
            .query_row("SELECT value FROM metric WHERE name=?1", rusqlite::params![NOM_OK], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, 0.0, "le refus doit tout de même laisser une trace EXPLICITE, sinon le trou est muet");
    }

    // =============================================================================================
    // 3. LA SÉRIE SUFFIT À RÉPONDRE « LA PART FTS A-T-ELLE BAISSÉ ? »
    // =============================================================================================

    /// LA SOMME DES SEAUX EST LE FICHIER. C'est ce que la comptabilité fermée garantit, et c'est ce qui
    /// rend une PART calculable depuis la série seule, à n'importe quel instant passé, sans avoir
    /// gardé un second chiffre à côté. Mesuré ici sur une vraie base, par le vrai chemin de mesure.
    ///
    /// MUTATION : retirer les pages libres de `seaux()` ⇒ la somme ne fait plus le fichier et
    /// l'assertion affiche l'écart en pages.
    #[test]
    fn la_somme_des_seaux_publies_fait_le_fichier() {
        let (tmp, conn) = base_reelle("vent-somme");
        // De quoi occuper plusieurs pages dans les trois postes (données, index, FTS).
        for i in 0..2000 {
            conn.execute(
                "INSERT INTO event(ts,source,category,message,host) VALUES(?1,'sshd','auth',?2,'h1')",
                rusqlite::params![1_700_000_000i64 + i, format!("session opened for user u{i} from 10.0.0.{}", i % 251)],
            )
            .unwrap();
        }
        drop(conn);

        let m = mesurer_une_fois(tmp.as_str(), 1_800_000_000);
        let octets = match &m {
            Mesure::Prise { octets, .. } => octets.clone(),
            Mesure::NonPrise { cause, phrase, .. } => panic!("mesure refusée ({cause}) : {phrase}"),
        };
        let somme: i64 = octets.iter().map(|(_, v)| *v).sum();

        let c = Connection::open(tmp.as_str()).unwrap();
        let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        let page_count: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        assert_eq!(
            somme,
            page_size * page_count,
            "la somme des seaux publiés ne fait pas le fichier ({} pages d'écart) -> une PART calculée \
             depuis la série serait fausse",
            (page_size * page_count - somme) / page_size
        );
        assert!(
            octets.iter().any(|(c, v)| *c == "fts" && *v > 0),
            "précondition : la fixture doit remplir le poste FTS, sinon ce test ne mesure pas ce qu'il annonce"
        );
    }

    // =============================================================================================
    // 4. LE PARCOURS NE PREND PAS LE VERROU D'ÉCRITURE
    // =============================================================================================

    /// L'INGESTION N'ATTEND PAS APRÈS LA MESURE. `mesurer_une_fois` ne reçoit qu'un CHEMIN : elle n'a
    /// structurellement pas de quoi prendre le mutex d'écriture. Ce test le VÉRIFIE au lieu de le
    /// croire : le verrou est tenu par le fil de test PENDANT toute la mesure, qui tourne sur un AUTRE
    /// fil et doit aboutir quand même.
    ///
    /// Le fil séparé n'est pas une précaution de style : si la mesure prenait le verrou, un appel
    /// direct depuis ce test s'auto-verrouillerait (parking_lot n'est pas ré-entrant) et la suite se
    /// BLOQUERAIT au lieu de rougir. Ici la régression se voit en 5 s, avec une phrase.
    ///
    /// MUTATION : faire passer la mesure par le mutex writer ⇒ le canal expire et l'assertion nomme la
    /// conséquence (l'ingestion attendrait la durée du parcours).
    #[test]
    fn le_parcours_naboutit_pas_au_verrou_decriture() {
        let (tmp, conn) = base_reelle("vent-verrou");
        let chemin = tmp.as_str().to_string();
        let ecrivain = Arc::new(Mutex::new(conn));
        let tenu = ecrivain.lock(); // l'ingestion tient le verrou writer PENDANT toute la mesure
        let (tx, rx) = std::sync::mpsc::channel();
        let fil = std::thread::spawn(move || {
            let _ = tx.send(matches!(mesurer_une_fois(&chemin, 1_800_000_000), Mesure::Prise { .. }));
        });
        let verdict = rx.recv_timeout(Duration::from_secs(5));
        drop(tenu); // débloque le fil s'il attendait le verrou, pour que la suite n'ait pas de fuite
        let _ = fil.join();
        assert_eq!(
            verdict.ok(),
            Some(true),
            "la mesure n'aboutit pas tant que le verrou d'écriture est tenu -> elle le prend, donc \
             l'ingestion attendrait la durée du parcours (35,4 s mesurés en production)"
        );
    }

    /// LE TOUR COMPLET — la wiring : parcourir, puis publier. Ce qui compte ici est que le tour laisse
    /// la série dans la table ET rende le verrou d'écriture (le fil de test le reprend juste après).
    #[test]
    fn le_tour_publie_et_rend_le_verrou() {
        let (tmp, conn) = base_reelle("vent-tour");
        let db = Arc::new(Mutex::new(conn));
        crate::ventilation_serie::tour(&db, tmp.as_str());
        let c = db.lock(); // si le tour ne rendait pas le verrou, cette ligne bloquerait
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM metric WHERE name=?1", rusqlite::params![NOM_POSTE], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n as usize,
            db_ventilation::TOUS.len() + 1,
            "le tour n'a pas publié la ventilation -> la série resterait vide sans que rien ne le dise"
        );
    }

    /// LE TOUR NE VERROUILLE PAS LUI-MÊME. La régression plausible n'est pas exotique : c'est la
    /// « simplification » qui ouvre le verrou d'écriture en tête du tour et le garde jusqu'à la fin —
    /// l'ingestion attendrait alors la durée COMPLÈTE du parcours, une fois par heure. Aucun test de
    /// comportement ne l'attrape (le parcours passe par le pool, il n'y a donc pas d'interblocage à
    /// observer) : la propriété est STRUCTURELLE, donc elle se garde sur la structure.
    ///
    /// MUTATION : remettre un `db.lock()` dans le corps de `tour` ⇒ ce test rougit en citant la ligne.
    #[test]
    fn le_tour_ne_verrouille_pas_lui_meme() {
        let source = include_str!("../ventilation_serie.rs");
        let debut = source
            .find("pub(crate) fn tour(")
            .expect("`tour` a été renommée -> ce test ne garde plus rien, il doit être relu");
        // Corps de la fonction, par profondeur d'accolades (robuste aux accolades imbriquées).
        let apres = &source[debut..];
        let ouvrante = apres.find('{').expect("corps de `tour` introuvable");
        let mut profondeur = 0i32;
        let mut fin = ouvrante;
        for (i, c) in apres[ouvrante..].char_indices() {
            match c {
                '{' => profondeur += 1,
                '}' => {
                    profondeur -= 1;
                    if profondeur == 0 {
                        fin = ouvrante + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let corps = &apres[ouvrante..=fin];
        assert!(corps.len() > 100, "extraction du corps de `tour` ratée ({} octets) — ce test mentirait", corps.len());
        for (n, ligne) in corps.lines().enumerate() {
            let code = ligne.split("//").next().unwrap_or("");
            assert!(
                !code.contains(".lock()"),
                "`tour` prend le verrou d'écriture (ligne {n} de son corps : {}) -> l'ingestion \
                 attendrait la durée du parcours. Le verrou n'appartient qu'à `publier_sous_verrou`.",
                code.trim()
            );
        }
    }

    /// La lecture est bien servie par le POOL (connexion `query_only`), pas par une ouverture
    /// écrivable : la mesure ne doit rien pouvoir écrire, même par accident.
    #[test]
    fn la_connexion_de_mesure_est_en_lecture_seule() {
        let (tmp, conn) = base_reelle("vent-ro");
        drop(conn);
        let ecrit = read_with(tmp.as_str(), true, |c| {
            c.execute("INSERT INTO metric(ts,name,value) VALUES(1,'x',1.0)", []).is_ok()
        });
        assert!(!ecrit, "la connexion de mesure accepte une écriture -> ce n'est pas le pool de lecture");
    }

    // =============================================================================================
    // 5. LE COÛT EST BORNÉ — CPU et DISQUE
    // =============================================================================================

    /// LA BORNE CPU. Le sommeil ne descend jamais sous `PART_MAX_INVERSE` fois la durée du dernier
    /// parcours : quelle que soit la taille de la base, la mesure ne peut pas dépasser 1/20 = 5 % d'un
    /// cœur. À la taille de la production (35,4 s mesurés le 2026-08-09), le tick reste horaire.
    ///
    /// MUTATION : remplacer le `max` par l'intervalle nu ⇒ le cas « base énorme » rougit, et il rougit
    /// en NOMMANT la part de cœur consommée.
    #[test]
    fn le_parcours_ne_peut_pas_depasser_sa_part_de_coeur() {
        let heure = Duration::from_secs(3600);
        // Production mesurée : 35,4 s -> le tick horaire n'est pas repoussé (0,98 % d'un cœur).
        assert_eq!(prochain_sommeil(heure, Duration::from_millis(35_433)), heure);
        // Une base 10x plus grosse (354 s) -> le sommeil s'allonge TOUT SEUL. La grandeur ASSERTÉE est
        // la PART DE CŒUR, pas le sommeil : c'est elle que la borne promet, et c'est elle qui doit être
        // nommée quand la garde saute.
        let gros = Duration::from_secs(354);
        let dors = prochain_sommeil(heure, gros);
        let part = gros.as_secs_f64() / dors.as_secs_f64();
        assert!(
            part <= 1.0 / PART_MAX_INVERSE as f64 + f64::EPSILON,
            "le parcours consommerait {:.1} % d'un cœur (parcours {:?}, sommeil {:?}) — la borne promet {:.1} %",
            part * 100.0,
            gros,
            dors,
            100.0 / PART_MAX_INVERSE as f64
        );
        assert_eq!(dors, gros * PART_MAX_INVERSE, "le sommeil doit être EXACTEMENT la borne, pas davantage");
    }

    /// LA BORNE DISQUE, MESURÉE — pas estimée. La série vit dans une base qu'on essaie justement de
    /// réduire : son coût doit être un CHIFFRE, sur le SCHÉMA RÉEL (les index de `metric` et de
    /// `metric_rollup` comptent autant que les lignes).
    ///
    /// Les deux comptes sont DÉRIVÉS, jamais écrits en dur : le nombre de points par tour vient de
    /// `points()`, la fenêtre brute de `metric_raw_hours` et la fenêtre agrégée de `metric_days` —
    /// les valeurs par défaut de `RETENTION_FIELDS`. Changer une rétention change ce test.
    ///
    /// MUTATION : publier un point par MINUTE au lieu d'un par heure ⇒ le coût est multiplié par 60 et
    /// l'assertion rougit en nommant les Mio.
    #[test]
    fn le_cout_disque_de_la_serie_est_mesure_et_borne() {
        let defaut = |cle: &str| -> i64 {
            RETENTION_FIELDS
                .iter()
                .find(|(k, ..)| *k == cle)
                .map(|(_, _, d, ..)| *d)
                .unwrap_or_else(|| panic!("clé de rétention `{cle}` introuvable — la borne ne serait dérivée de rien"))
        };
        let raw_h = defaut("metric_raw_hours"); // 48 h de points BRUTS
        let jours = defaut("metric_days"); // puis 90 j de buckets HORAIRES
        // Les lignes RÉELLES : mêmes noms, mêmes étiquettes que ce que `publier` écrit — dérivées d'une
        // mesure prise sur une vraie base, jamais d'une fixture (une fixture ne suivrait pas le code).
        let modele = points(&mesure_reelle("vent-cout-src"));
        let par_tour = modele.len() as i64;
        let n_raw = par_tour * raw_h;
        let n_roll = par_tour * 24 * jours;

        let (tmp, conn) = base_reelle("vent-cout");
        conn.execute_batch("VACUUM").unwrap();
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        let avant: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..n_raw {
            let p = &modele[(i % par_tour) as usize];
            conn.execute(
                "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,?3,?4)",
                rusqlite::params![1_800_000_000i64 + (i / par_tour) * 3600, p.nom, p.etiquettes, p.valeur],
            )
            .unwrap();
        }
        for i in 0..n_roll {
            let p = &modele[(i % par_tour) as usize];
            conn.execute(
                "INSERT INTO metric_rollup(ts,name,labels,avg,min,max,n) VALUES(?1,?2,?3,?4,?4,?4,1)",
                rusqlite::params![1_700_000_000i64 + (i / par_tour) * 3600, p.nom, p.etiquettes, p.valeur],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        conn.execute_batch("VACUUM").unwrap();
        let apres: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        drop(conn);
        drop(tmp);

        let octets = (apres - avant) * page_size;
        let mib = octets as f64 / (1024.0 * 1024.0);
        // La borne est DITE en part du budget : 2 Gio est la promesse du produit.
        let part = octets as f64 * 100.0 / (2.0 * 1024.0 * 1024.0 * 1024.0);
        assert!(
            mib < 8.0,
            "la rétention COMPLÈTE de la série coûte {mib:.2} Mio ({n_raw} points bruts + {n_roll} buckets \
             horaires, schéma réel, après VACUUM) = {part:.3} % du budget 2 Gio — au-delà de 8 Mio, ce \
             n'est plus un instrument, c'est un poste de dépense"
        );
        // Le plancher : un coût NUL voudrait dire que rien n'a été écrit, donc que ce test ne mesure rien.
        assert!(octets > 0, "coût mesuré nul -> la fixture n'a rien écrit, ce test ne prouve rien");
        eprintln!("[mesure] rétention complète de la série : {mib:.2} Mio ({part:.3} % du budget 2 Gio) pour {n_raw}+{n_roll} lignes");
    }

    /// LE NOMBRE DE POINTS PAR TOUR EST CE QU'ON CROIT. La borne disque ci-dessus en dépend : si un
    /// jour la mesure publiait dix fois plus de séries, la borne devrait être rediscutée, pas subie.
    #[test]
    fn un_tour_publie_autant_de_points_quil_y_a_de_seaux_plus_deux() {
        assert_eq!(
            points(&mesure_reelle("vent-compte")).len(),
            db_ventilation::TOUS.len() + 1 /* pages libres */ + 2, /* ok + durée */
            "le nombre de points par tour a changé -> relire `le_cout_disque_de_la_serie_est_mesure_et_borne`"
        );
    }

    /// La publication ne doit rien écrire d'autre que ses propres séries — une ligne inattendue dans
    /// `metric` polluerait l'autocomplétion et les panneaux des exploitants.
    #[test]
    fn la_serie_ne_publie_que_ses_trois_noms() {
        let (_tmp, conn) = base_reelle("vent-noms");
        publier(&conn, &prise_fabriquee(1_800_000_000));
        publier(&conn, &Mesure::NonPrise { ts: 1_800_003_600, cause: "dbstat_indisponible", phrase: "x".into(), duree_ms: 1 });
        let mut st = conn.prepare("SELECT DISTINCT name FROM metric ORDER BY name").unwrap();
        let noms: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        assert_eq!(noms, vec![NOM_POSTE.to_string(), NOM_DUREE.to_string(), NOM_OK.to_string()]);
    }

    /// Ce que `publier` écrit est relisible par le MÊME DTO que l'ingestion : la série n'invente pas
    /// une deuxième façon d'écrire une métrique.
    #[test]
    fn la_serie_passe_par_le_dto_dingestion() {
        let (_tmp, conn) = base_reelle("vent-dto");
        let m = prise_fabriquee(1_800_000_000);
        publier(&conn, &m);
        // Une ligne écrite par le DTO d'ingestion, au même endroit, doit être indiscernable.
        let temoin = MetricRow { ts: 1_800_000_001, name: NOM_POSTE.into(), labels: Some("{\"poste\":\"fts\"}".into()), value: 160.0, host: None };
        crate::store().insert_metric(&conn, &temoin).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM metric WHERE name=?1 AND labels=?2 AND value=160.0 AND host IS NULL",
                rusqlite::params![NOM_POSTE, "{\"poste\":\"fts\"}"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2, "la ligne de la série et celle du DTO d'ingestion doivent être indiscernables");
    }
}
