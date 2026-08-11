// CE QUE COÛTE UN VIEILLISSEMENT FROID — ce que ces tests prouvent, et dans quel ordre.
//
//   1. UN SUCCÈS N'EST PLUS MUET, ET UN ÉCHEC NON PLUS. Une passe qui a eu lieu publie ses compteurs
//      MÊME À ZÉRO (« j'ai regardé, il n'y avait rien ») ; une passe SUSPENDUE n'en publie AUCUN et
//      NOMME sa cause. Les deux sorties sont DISTINCTES — c'est tout l'enjeu : un trou doit vouloir dire
//      « pas mesuré », jamais « zéro ».
//   2. UN COMPTEUR FAUX EST PIRE QU'UN TROU. Si la comptabilité des jours ne ferme pas, les compteurs de
//      travail ne sortent pas et la cause est publiée.
//   3. L'INSTRUMENT DE CRÊTE RSS EST VALIDÉ, avec son témoin NÉGATIF. `VmHWM` est un maximum cumulé
//      DEPUIS LE DÉMARRAGE : on prouve ici qu'un gros transitoire ANTÉRIEUR à la fenêtre n'entre pas
//      dans la mesure, et qu'une fenêtre où rien ne se passe n'hérite pas de la précédente.
//   4. LE TEMPS CPU EST CELUI DU FIL, pas du processus — prouvé en faisant brûler un AUTRE fil.
//   5. LE COÛT EST BORNÉ ET MESURÉ (disque, sur le schéma RÉEL), et la publication ne peut pas être
//      contournée par un retour anticipé (garde DÉRIVÉE du source de `cold_age_run`).
//
// Les fonctions qui portent la logique sont PURES (elles reçoivent le bilan) : elles se testent sans
// processus, sans base et sans tier froid compilé. Seuls les tests d'INSTRUMENT touchent `/proc`, et ils
// se sérialisent entre eux (le reset de `VmHWM` est un état de PROCESSUS, cf. `FENETRES`).

#[cfg(test)]
mod vieillissement_serie_tests {
    use crate::tmp_possede::TmpDb;
    use crate::vieillissement_serie::*;
    use crate::{migrate, RETENTION_FIELDS};
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::hint::black_box;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// LE RESET DE `VmHWM` EST UN ÉTAT DE PROCESSUS : deux tests d'instrument qui tourneraient en même
    /// temps (cargo test est multi-fils) se voleraient leur ligne de base et l'un des deux mesurerait
    /// « fenêtre concurrente » au hasard. Ce verrou les met en file — il ne masque rien, il rend les
    /// tests DÉTERMINISTES. (Les autres fils du binaire de test, eux, ne font qu'AJOUTER de la RSS :
    /// toutes les assertions ci-dessous sont écrites pour rester vraies sous cette inflation.)
    static FENETRES: Mutex<()> = Mutex::new(());

    /// Une base au schéma RÉEL du produit — la série finit dans `metric`, dont les index comptent autant
    /// que les lignes dès qu'on parle de coût disque. (Helper local : chaque module de test porte les
    /// siens, ceux de `ventilation_serie` sont privés à son module.)
    fn base_reelle(etiquette: &str) -> (TmpDb, Connection) {
        let tmp = TmpDb::neuf(etiquette);
        let conn = Connection::open(tmp.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    /// Un compte de passe PLEINE dont la comptabilité des jours FERME (5 = 2 + 1 + 1 + 1 + 0). Le
    /// `jours_sans_travail` n'est pas décoratif : c'est la suite que `P10.12-a` a ajoutée parce que
    /// « agé » recouvrait DEUX situations sans travail, et la production a publié 10 pour 10 no-op.
    fn compte_plein() -> Compte {
        Compte {
            jours_candidats: 5,
            jours_columnarises: 2,
            jours_sans_travail: 1,
            jours_differes: 1,
            jours_echoues: 1,
            jours_ecartes: 0,
            fichiers_ecrits: 3,
            fichiers_purges: 2,
            lignes_ecrites: 12_345,
            lignes_retirees: 12_000,
            octets_froid: 3_879_731, // 3,70 Mio : l'ordre de grandeur MESURÉ en production le 2026-08-10
        }
    }

    fn bilan(issue: Issue, compte: Compte, crete: Crete) -> Bilan {
        Bilan { issue, compte, duree_ms: 4_210, cpu_ms: Some(3_980), crete }
    }

    /// Une crête MESURÉE plausible : 700 Mio de pic sur une base de 580 Mio (+120 Mio — l'ordre de
    /// grandeur de ce qu'un vieillissement libère, mesuré en production le 2026-08-10).
    fn crete_typique() -> Crete {
        Crete::Mesuree { pic: 700 * 1024 * 1024, base: 580 * 1024 * 1024 }
    }

    fn valeur(pts: &[crate::ventilation_serie::Point], nom: &str, etiquette: Option<&str>) -> Option<f64> {
        pts.iter()
            .find(|p| p.nom == nom && p.etiquettes.as_deref() == etiquette)
            .map(|p| p.valeur)
    }

    fn noms(pts: &[crate::ventilation_serie::Point]) -> Vec<&'static str> {
        pts.iter().map(|p| p.nom).collect()
    }

    // =============================================================================================
    // 1. LE SUCCÈS PARLE, LA SUSPENSION AUSSI — et les deux ne se ressemblent pas
    // =============================================================================================

    /// UNE PASSE SUSPENDUE NE PUBLIE AUCUN COMPTEUR DE TRAVAIL. Le legal-hold, la clé absente et la
    /// rétention trop courte arrêtent la passe AVANT qu'elle ne regarde quoi que ce soit : publier des
    /// jours/lignes/octets (fussent-ils à zéro) affirmerait « le vieillissement a tourné et n'a rien
    /// trouvé », ce qui est une AUTRE phrase, et fausse. Le compte passé ici est volontairement PLEIN :
    /// si la suspension laissait fuiter des compteurs, ils seraient VISIBLEMENT non nuls.
    ///
    /// MUTATION (exécutée le 2026-08-10) : publier les compteurs quel que soit le verdict (`if true` à la
    /// place du `if travail.is_ok()` de `points`) ⇒ 3 tests rougissent — celui-ci sur
    /// `plume_cold_aging_jours`, `zero_jour_traite_...` et `une_comptabilite_...` sur la même série.
    #[test]
    fn une_passe_suspendue_ne_publie_aucun_compteur_de_travail() {
        let b = bilan(Issue::Suspendu(CAUSE_LEGAL_HOLD), compte_plein(), crete_typique());
        let pts = points(&b);
        let sortis = noms(&pts);
        for interdit in [NOM_JOURS, NOM_LIGNES, NOM_FICHIERS, NOM_OCTETS_FROID, NOM_CRETE, NOM_CRETE_SURCROIT] {
            assert!(
                !sortis.contains(&interdit),
                "`{interdit}` publié alors que la passe n'a PAS eu lieu -> la série affirmerait un \
                 vieillissement qui n'a jamais regardé la base"
            );
        }
        assert_eq!(
            valeur(&pts, NOM_OK, Some("{\"cause\":\"legal_hold\"}")),
            Some(0.0),
            "la suspension doit laisser une trace EXPLICITE et NOMMÉE, sinon le trou est muet"
        );
        assert_eq!(
            valeur(&pts, NOM_CRETE_OK, Some("{\"cause\":\"aging_suspendu\"}")),
            Some(0.0),
            "une crête publiée sur une passe suspendue se lirait comme un coût de vieillissement TRÈS bas"
        );
        // La durée, elle, sort toujours : elle est réellement mesurée, même pour une passe qui s'arrête.
        assert_eq!(valeur(&pts, NOM_DUREE, None), Some(4_210.0));
    }

    /// « 0 JOUR TRAITÉ » N'EST PAS « JE N'AI PAS TOURNÉ ». C'est l'invariant central du chantier : une
    /// passe qui a eu lieu et n'a rien trouvé publie des ZÉROS (une valeur mesurée), alors qu'un tick
    /// qui n'a pas eu lieu ne publie RIEN (un trou). Les deux formes doivent être distinctes dans la
    /// table, pas seulement dans les intentions.
    ///
    /// MUTATION : ne publier les compteurs que si `jours_candidats > 0` ⇒ la passe vide redevient un
    /// trou, l'assertion sur le zéro explicite rougit.
    #[test]
    fn zero_jour_traite_ne_se_confond_pas_avec_une_passe_qui_na_pas_eu_lieu() {
        let vide = points(&bilan(Issue::Balaye, Compte::default(), crete_typique()));
        assert_eq!(
            valeur(&vide, NOM_JOURS, Some("{\"issue\":\"candidat\"}")),
            Some(0.0),
            "une passe qui n'a rien trouvé doit publier un ZÉRO explicite — sinon « rien à faire » et \
             « le démon ne vieillit plus » ont exactement la même signature dans la série"
        );
        assert_eq!(valeur(&vide, NOM_OK, Some("{\"cause\":\"aucune\"}")), Some(1.0));

        let suspendue = points(&bilan(Issue::Suspendu(CAUSE_CLE_ABSENTE), Compte::default(), crete_typique()));
        assert!(
            !noms(&suspendue).contains(&NOM_JOURS),
            "la passe suspendue publie des jours -> elle serait indiscernable de la passe vide"
        );
        assert!(
            vide.len() > suspendue.len(),
            "les deux états publient la MÊME chose ({} points chacun) -> ils ne se distinguent pas",
            vide.len()
        );
    }

    /// LA LIGNE DE JOURNAL EXISTE DANS LES DEUX CAS. La série se lit 90 jours plus tard en SOQL ; la
    /// phrase se lit tout de suite dans `kubectl logs`, sans requête. C'est elle qui manquait
    /// intégralement : le seul message `[cold]` du journal de production était la bannière de démarrage.
    ///
    /// MUTATION : rendre `phrase` vide sur succès ⇒ les deux premières assertions rougissent.
    #[test]
    fn la_phrase_dit_le_travail_et_la_suspension() {
        let faite = phrase(&bilan(Issue::Balaye, compte_plein(), crete_typique()));
        assert!(faite.starts_with("[cold] "), "la ligne doit porter le préfixe que les exploitants grepent");
        for attendu in [
            "2 jour(s) columnarisé(s) sur 5",
            "1 sans travail",
            "12345 ligne(s)",
            "3,70 Mio",
            "4210 ms",
            "CPU fil 3980 ms",
        ] {
            assert!(faite.contains(attendu), "la phrase ne dit pas `{attendu}` :\n{faite}");
        }
        let arretee = phrase(&bilan(Issue::Suspendu(CAUSE_RETENTION_COURTE), compte_plein(), crete_typique()));
        assert!(
            arretee.contains("NON EXÉCUTÉ") && arretee.contains(CAUSE_RETENTION_COURTE),
            "une passe suspendue doit se lire comme telle, avec sa cause :\n{arretee}"
        );
        assert!(
            !arretee.contains("12345"),
            "la phrase d'une passe suspendue ne doit pas réciter des compteurs qui ne décrivent rien :\n{arretee}"
        );
        assert!(
            !arretee.contains("crête"),
            "la phrase annonce une crête RSS pour une passe qui n'a RIEN agé -> elle se lirait « le \
             vieillissement a coûté si peu », alors qu'il n'a pas eu lieu :\n{arretee}"
        );
    }

    // =============================================================================================
    // 2. UN COMPTEUR FAUX EST PIRE QU'UN TROU
    // =============================================================================================

    /// LA COMPTABILITÉ DES JOURS DOIT FERMER. Tout jour candidat finit agé, différé, échoué ou écarté.
    /// Le jour où un chemin est ajouté sans se compter, les compteurs cessent de décrire la passe : on
    /// refuse alors de les publier et on NOMME la cause, plutôt que de servir un chiffre faux.
    ///
    /// MUTATION (exécutée le 2026-08-10) : retirer la branche `Balaye if !fermee` de `verdict` ⇒ le
    /// verdict passe de `Err("comptabilite_jours")` à `Ok(())`, les compteurs faux sont publiés, et ce
    /// test est le SEUL des 15 à rougir.
    #[test]
    fn une_comptabilite_de_jours_qui_ne_ferme_pas_refuse_de_publier_ses_compteurs() {
        let mut boiteux = compte_plein();
        boiteux.jours_echoues -= 1; // un chemin qui « oublie » de se compter
        assert!(!boiteux.comptabilite_jours_fermee(), "précondition : ce compte ne doit PAS fermer");
        let b = bilan(Issue::Balaye, boiteux, crete_typique());
        assert_eq!(verdict(&b), Err(CAUSE_COMPTABILITE));
        let pts = points(&b);
        for interdit in [NOM_JOURS, NOM_LIGNES, NOM_FICHIERS, NOM_OCTETS_FROID, NOM_CRETE] {
            assert!(!noms(&pts).contains(&interdit), "`{interdit}` publié depuis une comptabilité qui ne ferme pas");
        }
        assert_eq!(valeur(&pts, NOM_OK, Some("{\"cause\":\"comptabilite_jours\"}")), Some(0.0));

        // TÉMOIN POSITIF : le même compte, fermé, publie bel et bien. Sans lui, un `verdict` qui
        // refuserait TOUT passerait ce test.
        let sain = bilan(Issue::Balaye, compte_plein(), crete_typique());
        assert_eq!(verdict(&sain), Ok(()));
        assert_eq!(valeur(&points(&sain), NOM_JOURS, Some("{\"issue\":\"columnarise\"}")), Some(2.0));
        assert_eq!(valeur(&points(&sain), NOM_JOURS, Some("{\"issue\":\"sans_travail\"}")), Some(1.0));
        assert_eq!(
            valeur(&points(&sain), NOM_JOURS, Some("{\"issue\":\"age\"}")),
            None,
            "l'étiquette `age` est REVENUE : elle recouvrait deux situations sans travail, et un nom \
             gardé pour un sens changé est un chiffre faux SILENCIEUX (cf. `NOM_JOURS`)"
        );
    }

    /// CHAQUE CAUSE PORTE UNE CLÉ STABLE ET UNIQUE. Une cause vide, traduite, ou partagée avec une autre
    /// rendrait les trous indiscernables — la série ne dirait plus POURQUOI elle a un trou.
    #[test]
    fn chaque_cause_porte_une_cle_stable_et_unique() {
        let causes = [
            CAUSE_AUCUNE,
            CAUSE_LEGAL_HOLD,
            CAUSE_CLE_ABSENTE,
            CAUSE_RETENTION_COURTE,
            CAUSE_COMPTABILITE,
            CAUSE_DECOUVERTE,
            CRETE_PROC_ABSENT,
            CRETE_RESET_REFUSE,
            CRETE_FENETRE_CONCURRENTE,
            CRETE_SUSPENDU,
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
        assert_eq!(d.len(), causes.len(), "deux causes partagent une clé -> les trous se confondraient");
    }

    // =============================================================================================
    // 3. LA SÉRIE ARRIVE DANS `metric` — la table que les consommateurs lisent
    // =============================================================================================

    /// LA PUBLICATION ÉCRIT VRAIMENT, ET REND LE VERROU. `metric` est la table qu'interroge la commande
    /// SOQL `metric` (elle UNIONNE `metric` et `metric_rollup`), celle des panneaux et celle des règles.
    /// On relit ce qui a été écrit : compte, valeur, étiquette, et `host` NULL (la série décrit une
    /// BASE, pas une machine — un hôte l'inscrirait dans l'inventaire de flotte).
    ///
    /// MUTATION : retirer un point de `points()` ⇒ le compte attendu, DÉRIVÉ de `points()`, ne tombe
    /// plus. Retirer le `host: None` ⇒ l'assertion sur l'inventaire de flotte rougit.
    #[test]
    fn publier_ecrit_la_serie_dans_metric_et_rend_le_verrou() {
        let (_tmp, conn) = base_reelle("age-publie");
        let db = Arc::new(Mutex::new(conn));
        let b = bilan(Issue::Balaye, compte_plein(), crete_typique());
        let attendus = points(&b).len();
        assert_eq!(publier(&db, 1_800_000_000, &b), attendus, "toutes les lignes du bilan doivent être écrites");

        let conn = db.lock(); // si `publier` ne rendait pas le verrou, cette ligne bloquerait
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM metric", [], |r| r.get(0)).unwrap();
        assert_eq!(n as usize, attendus);
        let (v, host): (f64, Option<String>) = conn
            .query_row(
                "SELECT value, host FROM metric WHERE name=?1",
                rusqlite::params![NOM_OCTETS_FROID],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(v, 3_879_731.0, "les octets écrits au froid n'arrivent pas intacts dans la série");
        assert!(host.is_none(), "la série décrit LA BASE : lui donner un hôte inventerait une machine");
        let jours_columnarises: f64 = conn
            .query_row(
                "SELECT value FROM metric WHERE name=?1 AND labels=?2",
                rusqlite::params![NOM_JOURS, "{\"issue\":\"columnarise\"}"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(jours_columnarises, 2.0);
    }

    /// LA SÉRIE NE PUBLIE QUE SES PROPRES NOMS. Une ligne inattendue dans `metric` polluerait
    /// l'autocomplétion et les panneaux des exploitants.
    #[test]
    fn la_serie_ne_publie_que_ses_propres_noms() {
        let (_tmp, conn) = base_reelle("age-noms");
        let db = Arc::new(Mutex::new(conn));
        publier(&db, 1_800_000_000, &bilan(Issue::Balaye, compte_plein(), crete_typique()));
        publier(&db, 1_800_003_600, &bilan(Issue::Suspendu(CAUSE_CLE_ABSENTE), Compte::default(), Crete::NonMesuree(CRETE_PROC_ABSENT)));
        let conn = db.lock();
        let mut st = conn.prepare("SELECT DISTINCT name FROM metric ORDER BY name").unwrap();
        let vus: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
        let connus = [
            NOM_OK,
            NOM_JOURS,
            NOM_LIGNES,
            NOM_FICHIERS,
            NOM_OCTETS_FROID,
            NOM_DUREE,
            NOM_CPU,
            NOM_CRETE,
            NOM_CRETE_SURCROIT,
            NOM_CRETE_OK,
        ];
        for nom in &vus {
            assert!(connus.contains(&nom.as_str()), "série inattendue dans `metric` : {nom}");
        }
        assert!(vus.len() >= 8, "seulement {} séries écrites -> la publication a perdu des points", vus.len());
    }

    // =============================================================================================
    // 4. L'INSTRUMENT — et son témoin négatif
    // =============================================================================================

    /// LA CRÊTE EST CELLE DE LA FENÊTRE, PAS DE LA VIE DU PROCESSUS. C'est LE piège de cet axe : `VmHWM`
    /// est un maximum cumulé depuis le démarrage, et le lire tel quel après un vieillissement rend le
    /// plus gros pic de tout l'historique du démon — c'est exactement ce qui a rendu la crête RAM
    /// « inconnue » alors qu'un chiffre était disponible. On le prouve dans les deux sens :
    ///   * TÉMOIN NÉGATIF : un transitoire de 256 Mio ANTÉRIEUR à la fenêtre ne doit PAS y apparaître
    ///     (fenêtre B, qui n'alloue rien, doit rester plate même si A a alloué juste avant) ;
    ///   * TÉMOIN POSITIF : 64 Mio alloués DANS la fenêtre A doivent y apparaître, même s'ils sont
    ///     libérés avant sa fermeture (c'est un PIC, pas une lecture instantanée).
    ///
    /// MUTATIONS, EXÉCUTÉES LE 2026-08-10 (chiffres relevés dans le message d'échec) :
    ///   (a) lire `VmRSS` au lieu de `VmHWM` à la fermeture ⇒ « pic 11,7 Mio, base 11,5 Mio » : les 64 Mio
    ///       de la fenêtre ont disparu (ils sont libérés avant `clore`) — le témoin POSITIF rougit ;
    ///   (b) ne pas écrire `clear_refs` ⇒ la ligne de base reste le pic de TOUTE la vie du processus, la
    ///       validation le voit et la crête devient `NonMesuree(reset_refuse)` — l'assertion
    ///       « l'instrument s'est armé » rougit ;
    ///   (c) ni reset NI validation (le piège dans sa forme pure) ⇒ « pic 265,4 Mio, base 265,4 Mio » : la
    ///       mesure publierait 265 Mio de crête pour une fenêtre qui n'a alloué que 64 Mio, et un surcroît
    ///       de ZÉRO. C'est très exactement le chiffre que `VmHWM` nu aurait rendu.
    /// Le témoin NÉGATIF (fenêtre B) n'a, lui, aucune mutation qui le fasse rougir SEUL : toute façon de
    /// casser le reset est interceptée AVANT par la validation ou par le témoin positif. Il reste une
    /// OBSERVATION (+0,0 Mio mesuré), pas une garde — c'est écrit ici pour ne pas le croire plus fort
    /// qu'il n'est.
    #[test]
    fn la_crete_rss_est_bornee_a_la_fenetre() {
        let _serialise = FENETRES.lock();
        if !cfg!(target_os = "linux") {
            eprintln!("[mesure] non-Linux : /proc/self/{{status,clear_refs}} absents -> instrument sans objet ici");
            return;
        }
        // Le passé du processus : un gros transitoire AVANT toute fenêtre. C'est lui que `VmHWM`
        // retiendrait indéfiniment si on ne le ramenait pas à la fenêtre.
        toucher(256 * 1024 * 1024);

        let f = Fenetre::ouvrir();
        toucher(64 * 1024 * 1024); // alloué ET libéré À L'INTÉRIEUR de la fenêtre
        let a = f.clore(Issue::Balaye, Compte::default());
        // Fenêtre B : la plus courte possible, sans rien allouer.
        let b = Fenetre::ouvrir().clore(Issue::Balaye, Compte::default());

        let (pic_a, base_a) = match a.crete {
            Crete::Mesuree { pic, base } => (pic, base),
            Crete::NonMesuree(cause) => panic!(
                "l'instrument ne s'est pas armé ({cause}) alors qu'on tourne sous Linux -> la crête RSS \
                 serait un axe NON MESURÉ, ce que ce chantier ferme"
            ),
        };
        let (pic_b, base_b) = match b.crete {
            Crete::Mesuree { pic, base } => (pic, base),
            Crete::NonMesuree(cause) => panic!("seconde fenêtre non armée ({cause})"),
        };
        let mio = |o: u64| o as f64 / (1024.0 * 1024.0);
        assert!(
            pic_a - base_a >= 32 * 1024 * 1024,
            "TÉMOIN POSITIF : 64 Mio alloués DANS la fenêtre n'y apparaissent pas (pic {:.1} Mio, base \
             {:.1} Mio) -> la mesure lit un instantané, pas un PIC",
            mio(pic_a),
            mio(base_a)
        );
        assert!(
            pic_b - base_b < 32 * 1024 * 1024,
            "TÉMOIN NÉGATIF : la fenêtre suivante, qui n'alloue RIEN, hérite d'un surcroît de {:.1} Mio \
             -> `VmHWM` n'a pas été ramené à la fenêtre et la crête publiée serait celle du passé",
            mio(pic_b - base_b)
        );
        eprintln!(
            "[mesure 2026-08-10] fenêtre A : pic {:.1} Mio / base {:.1} Mio (+{:.1} Mio) — fenêtre B (vide) : +{:.1} Mio",
            mio(pic_a),
            mio(base_a),
            mio(pic_a - base_a),
            mio(pic_b - base_b)
        );
    }

    /// Alloue `octets` et TOUCHE une page sur deux pour que la RSS monte réellement (une allocation non
    /// touchée n'est que de l'adressage virtuel), puis libère. `black_box` empêche l'élision.
    fn toucher(octets: usize) {
        let mut v = vec![0u8; octets];
        let pas = 4096;
        for i in (0..v.len()).step_by(pas) {
            v[i] = 1;
        }
        black_box(&v);
    }

    /// LA VALIDATION DE L'INSTRUMENT EST UNE FONCTION, pas une intention. Un reset qui n'a pas pris
    /// laisse la ligne de base très au-dessus du RSS courant : c'est le seul cas où la crête mentirait,
    /// et c'est exactement ce que `reset_effectif` refuse.
    #[test]
    fn la_validation_du_reset_accepte_le_bruit_et_refuse_le_passe() {
        let rss = 300 * 1024 * 1024;
        assert!(reset_effectif(rss, rss), "un reset parfait doit être accepté");
        assert!(
            reset_effectif(rss + TOLERANCE_RESET_OCTETS, rss),
            "quelques Mio alloués ENTRE les deux lectures ne sont pas un reset raté"
        );
        assert!(
            !reset_effectif(rss + TOLERANCE_RESET_OCTETS + 1, rss),
            "une ligne de base au-dessus de la tolérance = pic ANTÉRIEUR à la fenêtre -> à refuser"
        );
        assert!(!reset_effectif(2 * rss, rss), "un pic de vie entière doit être refusé sans hésiter");
    }

    /// DEUX FENÊTRES QUI SE CHEVAUCHENT NE MESURENT PAS DEUX FOIS. Le reset est PROCESSUS : la seconde
    /// fenêtre volerait sa ligne de base à la première. Elle ne mesure donc pas — et le dit. Et le
    /// drapeau est RENDU à la fermeture : sans ça, une seule imbrication condamnerait silencieusement
    /// toutes les mesures suivantes du processus.
    ///
    /// MUTATION (exécutée le 2026-08-10) : vider l'`impl Drop` de `Fenetre` ⇒ la 3e fenêtre reste
    /// `fenetre_concurrente` et la dernière assertion rougit (« le drapeau n'a pas été rendu »).
    #[test]
    fn deux_fenetres_qui_se_chevauchent_ne_mesurent_pas_deux_fois() {
        let _serialise = FENETRES.lock();
        let externe = Fenetre::ouvrir();
        let interne = Fenetre::ouvrir().clore(Issue::Balaye, Compte::default());
        assert_eq!(
            interne.crete,
            Crete::NonMesuree(CRETE_FENETRE_CONCURRENTE),
            "la fenêtre imbriquée a rendu une crête -> les deux se sont volé leur ligne de base"
        );
        let dehors = externe.clore(Issue::Balaye, Compte::default());
        if !cfg!(target_os = "linux") {
            return; // le reste porte sur `/proc`, absent ailleurs
        }
        assert!(matches!(dehors.crete, Crete::Mesuree { .. }), "la fenêtre EXTERNE, elle, doit mesurer");
        let apres = Fenetre::ouvrir().clore(Issue::Balaye, Compte::default());
        assert!(
            matches!(apres.crete, Crete::Mesuree { .. }),
            "le drapeau d'exclusivité n'a pas été rendu -> toutes les mesures suivantes seraient muettes"
        );
    }

    /// LE TEMPS CPU EST CELUI DU FIL, PAS DU PROCESSUS. Pendant un vieillissement, l'ingest tourne : un
    /// CPU-processus compterait son travail comme celui de l'aging. On le prouve en faisant brûler un
    /// AUTRE fil pendant que le nôtre DORT — le compteur doit rester bas —, puis en brûlant nous-mêmes.
    ///
    /// MUTATION (exécutée le 2026-08-10) : passer à `CLOCK_PROCESS_CPUTIME_ID` ⇒ « un fil qui a DORMI
    /// 300 ms s'est vu imputer **294 ms** de CPU ». Sans mutation, le même fil est mesuré à **0 ms**.
    #[test]
    fn le_temps_cpu_est_celui_du_fil_pas_du_processus() {
        let _serialise = FENETRES.lock();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let brûleur = std::thread::spawn(move || {
            let mut x = 0u64;
            while !s.load(Ordering::Relaxed) {
                x = x.wrapping_add(black_box(1));
            }
            black_box(x);
        });
        let f = Fenetre::ouvrir();
        std::thread::sleep(Duration::from_millis(300));
        let dormeur = f.clore(Issue::Balaye, Compte::default());
        stop.store(true, Ordering::Relaxed);
        brûleur.join().unwrap();

        let f = Fenetre::ouvrir();
        let t0 = Instant::now();
        let mut x = 0u64;
        while t0.elapsed() < Duration::from_millis(200) {
            x = x.wrapping_add(black_box(1));
        }
        black_box(x);
        let travailleur = f.clore(Issue::Balaye, Compte::default());

        let cpu_dormeur = dormeur.cpu_ms.expect("le CPU du fil doit être mesurable sous Linux");
        let cpu_travailleur = travailleur.cpu_ms.expect("le CPU du fil doit être mesurable sous Linux");
        assert!(dormeur.duree_ms >= 300, "précondition : la fenêtre du dormeur doit bien durer (mesuré {} ms)", dormeur.duree_ms);
        assert!(
            cpu_dormeur < 100,
            "un fil qui a DORMI 300 ms s'est vu imputer {cpu_dormeur} ms de CPU -> c'est le CPU du \
             PROCESSUS (un autre fil brûlait), donc le coût de l'ingest serait facturé au vieillissement"
        );
        assert!(
            cpu_travailleur >= 50,
            "un fil qui a brûlé 200 ms ne s'est vu imputer que {cpu_travailleur} ms -> le compteur ne \
             mesure pas le travail de ce fil"
        );
        eprintln!("[mesure 2026-08-10] CPU du fil : dormeur {cpu_dormeur} ms, travailleur {cpu_travailleur} ms");
    }

    // =============================================================================================
    // 5. LE COÛT EST BORNÉ, ET LA PUBLICATION N'EST PAS CONTOURNABLE
    // =============================================================================================

    /// CE QUE L'INSTRUMENT COÛTE — un CHIFFRE, pas une intention. La fenêtre s'ouvre et se ferme UNE
    /// FOIS par vieillissement (cadence horaire de `retention_run`), jamais dans une boucle chaude ; son
    /// coût doit donc être négligeable devant une passe qui dure des secondes. Ce n'est pas une évidence :
    /// `/proc/self/clear_refs` accepte d'autres valeurs que `5`, et elles, elles PARCOURENT toute la
    /// table des pages du processus (`1`/`2`/`3` : bits soft-dirty, avec purge de TLB). Écrire la
    /// mauvaise valeur transformerait une mesure gratuite en balayage de tout l'espace d'adressage.
    ///
    /// CE QUE CE TEST ATTRAPE, ET CE QU'IL N'ATTRAPE PAS — mesuré le 2026-08-10, pas supposé. J'ai cru
    /// que ce test serait la garde contre `clear_refs=1` : FAUX. Mutation exécutée (`b"5"` -> `b"1"`) : le
    /// coût par fenêtre passe de **179 µs à 303 µs** (×1,7), très en dessous de la borne — le test reste
    /// VERT. La table des pages d'un binaire de test (~20 Mio résidents) est trop petite pour que le
    /// balayage se voie. Ce qui attrape VRAIMENT la mauvaise valeur est le test SÉMANTIQUE
    /// `la_crete_rss_est_bornee_a_la_fenetre` : `1` ne remet PAS le pic à zéro, la validation le voit, et
    /// il rougit sur `reset_refuse` (vérifié le 2026-08-10). Ce test-ci ne garde donc qu'une chose, et
    /// elle est écrite dans son message : un changement d'ORDRE DE GRANDEUR du coût de l'instrument.
    #[test]
    fn ouvrir_et_clore_une_fenetre_ne_coute_presque_rien() {
        let _serialise = FENETRES.lock();
        if !cfg!(target_os = "linux") {
            eprintln!("[mesure] non-Linux : instrument absent, coût sans objet ici");
            return;
        }
        // Chauffe : le tout premier accès à `/proc/self/status` paie le cache de dentry.
        let _ = Fenetre::ouvrir().clore(Issue::Balaye, Compte::default());
        const N: u32 = 200;
        let t0 = Instant::now();
        for _ in 0..N {
            let _ = Fenetre::ouvrir().clore(Issue::Balaye, Compte::default());
        }
        let par_fenetre = t0.elapsed() / N;
        assert!(
            par_fenetre < Duration::from_micros(500),
            "ouvrir+fermer une fenêtre coûte {par_fenetre:?} — au-delà de ~0,5 ms ce n'est plus une \
             lecture de `/proc` mais un parcours de la table des pages : vérifier que `clear_refs` reçoit \
             bien `5` (remise à zéro du pic) et pas `1`/`2`/`3` (bits soft-dirty, TLB flush)"
        );
        eprintln!(
            "[mesure 2026-08-10] ouverture+fermeture d'une fenêtre : {par_fenetre:?} — soit {:.6} % d'une \
             passe horaire même si la passe ne durait qu'une seconde",
            par_fenetre.as_secs_f64() * 100.0
        );
    }

    /// LA BORNE DISQUE, MESURÉE — pas estimée. La série vit dans la base qu'on cherche justement à
    /// réduire : son coût doit être un CHIFFRE, sur le SCHÉMA RÉEL (les index de `metric` et de
    /// `metric_rollup` comptent autant que les lignes). Les deux fenêtres sont DÉRIVÉES de
    /// `RETENTION_FIELDS`, le nombre de points par passe vient de `points()` : changer l'un change ce
    /// test. La cadence est celle de `retention_run` — HORAIRE (`spawn_retention_loop`, 3600 s).
    ///
    /// MUTATION : publier un point par jour agé plutôt qu'un par passe (série non bornée) ⇒ le coût
    /// grimpe avec le nombre de jours et l'assertion rougit en nommant les Mio.
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
        let modele = points(&bilan(Issue::Balaye, compte_plein(), crete_typique()));
        let par_passe = modele.len() as i64;
        let n_raw = par_passe * raw_h;
        let n_roll = par_passe * 24 * jours;

        let (tmp, conn) = base_reelle("age-cout");
        conn.execute_batch("VACUUM").unwrap();
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        let avant: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..n_raw {
            let p = &modele[(i % par_passe) as usize];
            conn.execute(
                "INSERT INTO metric(ts,name,labels,value) VALUES(?1,?2,?3,?4)",
                rusqlite::params![1_800_000_000i64 + (i / par_passe) * 3600, p.nom, p.etiquettes, p.valeur],
            )
            .unwrap();
        }
        for i in 0..n_roll {
            let p = &modele[(i % par_passe) as usize];
            conn.execute(
                "INSERT INTO metric_rollup(ts,name,labels,avg,min,max,n) VALUES(?1,?2,?3,?4,?4,?4,1)",
                rusqlite::params![1_700_000_000i64 + (i / par_passe) * 3600, p.nom, p.etiquettes, p.valeur],
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
        let part = octets as f64 * 100.0 / (2.0 * 1024.0 * 1024.0 * 1024.0);
        assert!(octets > 0, "coût mesuré nul -> la fixture n'a rien écrit, ce test ne prouve rien");
        assert!(
            mib < 12.0,
            "la rétention COMPLÈTE de la série coûte {mib:.2} Mio ({n_raw} points bruts + {n_roll} buckets \
             horaires, schéma réel, après VACUUM) = {part:.3} % du budget 2 Gio — au-delà, ce n'est plus \
             un instrument, c'est un poste de dépense"
        );
        eprintln!(
            "[mesure 2026-08-10] rétention complète de la série : {mib:.2} Mio ({part:.3} % du budget 2 Gio) \
             pour {n_raw}+{n_roll} lignes, {par_passe} points par passe horaire"
        );
    }

    /// LE NOMBRE DE POINTS PAR PASSE EST CE QU'ON CROIT. La borne disque ci-dessus en dépend : si la
    /// publication se mettait à écrire dix fois plus de séries, la borne devrait être rediscutée, pas subie.
    #[test]
    fn une_passe_publie_dix_sept_points() {
        assert_eq!(
            points(&bilan(Issue::Balaye, compte_plein(), crete_typique())).len(),
            17, // 6 jours + 2 lignes + 2 fichiers + octets + durée + CPU + ok + crête_ok + crête + surcroît
            "le nombre de points par passe a changé -> relire `le_cout_disque_de_la_serie_est_mesure_et_borne`"
        );
    }

    /// LE TRAVAIL SE DÉRIVE DU COMPTE, IL NE SE DÉCLARE PAS (`P10.12-a`). C'est la fonction qui
    /// départage « jour columnarisé » de « jour traité sans rien faire ». Elle ne regarde PAS une liste
    /// de compteurs de travail : elle compare le compte MOINS la comptabilité des jours. Un compteur de
    /// travail ajouté demain entre donc dans la comparaison sans que personne n'y pense — et c'est
    /// exactement ce que ce test vérifie, en bougeant CHAQUE compteur l'un après l'autre.
    ///
    /// MUTATION (exécutée le 2026-08-11) : faire rendre `false` à `a_travaille_depuis` ⇒ les 5 cas de
    /// travail rougissent. La faire rendre `true` ⇒ les 6 cas « comptabilité des jours seule » rougissent.
    #[test]
    fn le_travail_dun_jour_se_derive_du_compte_pas_du_chemin_de_retour() {
        let base = Compte::default();
        assert!(!base.a_travaille_depuis(&base), "un compte identique ne peut pas décrire du travail");

        // BOUGER UN COMPTEUR DE TRAVAIL = du travail. Les cinq, un par un.
        let travaux: [(&str, fn(&mut Compte)); 5] = [
            ("fichiers_ecrits", |c| c.fichiers_ecrits += 1),
            ("fichiers_purges", |c| c.fichiers_purges += 1),
            ("lignes_ecrites", |c| c.lignes_ecrites += 1),
            ("lignes_retirees", |c| c.lignes_retirees += 1),
            ("octets_froid", |c| c.octets_froid += 1),
        ];
        for (nom, bouge) in travaux {
            let mut apres = base;
            bouge(&mut apres);
            assert!(
                apres.a_travaille_depuis(&base),
                "`{nom}` a bougé et le jour n'est pas compté comme columnarisé -> un vrai drainage \
                 serait publié comme un no-op"
            );
        }

        // BOUGER LA COMPTABILITÉ DES JOURS N'EST PAS DU TRAVAIL. C'est la moitié qui compte : sans elle,
        // le premier jour d'une passe rendrait « columnarisé » simplement parce qu'un compteur de JOURS
        // a bougé entre-temps.
        let jours: [(&str, fn(&mut Compte)); 6] = [
            ("jours_candidats", |c| c.jours_candidats += 1),
            ("jours_columnarises", |c| c.jours_columnarises += 1),
            ("jours_sans_travail", |c| c.jours_sans_travail += 1),
            ("jours_differes", |c| c.jours_differes += 1),
            ("jours_echoues", |c| c.jours_echoues += 1),
            ("jours_ecartes", |c| c.jours_ecartes += 1),
        ];
        for (nom, bouge) in jours {
            let mut apres = base;
            bouge(&mut apres);
            assert!(
                !apres.a_travaille_depuis(&base),
                "`{nom}` (comptabilité des JOURS) est lu comme du TRAVAIL -> tout jour traité passerait \
                 pour columnarisé, et le défaut de `P10.12-a` serait rouvert"
            );
        }
    }

    /// LA COMPTABILITÉ FERME AVEC CINQ SUITES, PAS QUATRE. Ajouter `sans_travail` sans l'ajouter à
    /// `comptabilite_jours_fermee` aurait fait REFUSER toute publication dès le premier jour no-op :
    /// la série serait passée d'un chiffre faux à un TROU permanent, ce qui n'est pas mieux.
    #[test]
    fn la_comptabilite_ferme_avec_les_jours_sans_travail() {
        let c = compte_plein();
        assert!(c.comptabilite_jours_fermee(), "le compte de référence doit fermer : {c:?}");
        let mut sans = c;
        sans.jours_sans_travail -= 1; // le jour no-op « disparaît » de la comptabilité
        assert!(
            !sans.comptabilite_jours_fermee(),
            "un jour no-op peut s'évaporer sans que la comptabilité ne s'en aperçoive -> les jours \
             sans travail ne sont PAS dans l'invariant, et un chemin no-op ajouté demain passerait"
        );
        assert_eq!(verdict(&bilan(Issue::Balaye, sans, crete_typique())), Err(CAUSE_COMPTABILITE));
    }

    /// LA PUBLICATION N'EST PAS CONTOURNABLE. Le défaut fermé ici est un SILENCE : la régression
    /// plausible n'est pas exotique, c'est un `return` anticipé ajouté dans `cold_age_run` « pour sortir
    /// vite », qui rendrait de nouveau une passe entière muette. Le corps de `cold_age_run` est donc
    /// DÉRIVÉ DU SOURCE et vérifié : une seule sortie anticipée (le gate runtime), et la publication en
    /// dernier. Ce test tourne dans le profil PAR DÉFAUT alors que `cold_age_run` n'y est même pas
    /// compilé — c'est justement pour ça qu'il lit le source.
    ///
    /// MUTATION (exécutée le 2026-08-10) : ajouter un `return;` dans `cold_age_run` ⇒ « `cold_age_run` a
    /// 2 sortie(s) anticipée(s) » — le test rougit alors même que ce code n'est pas compilé dans ce profil.
    #[test]
    fn la_passe_ne_peut_pas_sortir_sans_publier() {
        let source = include_str!("../cold_store/aging.rs");
        let debut = source
            .find("pub(crate) fn cold_age_run(")
            .expect("`cold_age_run` a été renommée -> ce test ne garde plus rien, il doit être relu");
        let corps = &source[debut..];
        let fin = corps.find("\n}\n").expect("fin du corps de `cold_age_run` introuvable");
        let corps = &corps[..fin];
        // VALIDATION DE L'INSTRUMENT : l'extraction doit avoir attrapé le corps, pas trois lignes.
        assert!(
            corps.len() > 200 && corps.contains("PLUME_COLD_TIER"),
            "extraction du corps de `cold_age_run` ratée ({} octets) — ce test mentirait",
            corps.len()
        );
        // Les COMMENTAIRES sont retirés avant de compter : le mot « return » y apparaît légitimement
        // (c'est même le sujet de la doc), et un test qui compterait la prose changerait de verdict à
        // chaque relecture du commentaire — il ne garderait plus le CODE.
        let code: String =
            corps.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n");
        let sorties = code.matches("return").count();
        assert_eq!(
            sorties, 1,
            "`cold_age_run` a {sorties} sortie(s) anticipée(s) : au-delà du gate runtime, une sortie \
             saute la publication et la passe redevient MUETTE (le défaut mesuré le 2026-08-10)"
        );
        for attendu in ["Fenetre::ouvrir()", "vieillissement_serie::phrase", "vieillissement_serie::publier"] {
            assert!(corps.contains(attendu), "`cold_age_run` n'appelle plus `{attendu}` -> la passe ne rend plus compte");
        }
    }
}
