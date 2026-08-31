    // ================================================================================================
    // `P10.7-x` + `P10.7-n` — UN AVEU JUSTE QUE PERSONNE NE SERT.
    //
    // CE QUI A ÉTÉ MESURÉ SUR CET ARBRE, LE 2026-08-31, AVANT DE CORRIGER.
    //   · `bilan_de_tick::BOUCLES` était un `[&str; 6]` ÉCRIT À LA MAIN, recopié à côté des six
    //     constantes de nom, et c'est LUI que `gather_json` et `gather_prom` parcouraient. Or HUIT
    //     clés étaient publiées dans le registre par du code de PRODUCTION : les six de la table, plus
    //     `retention` (`server::boucles_de_fond`, la boucle qui ANCRE la chaîne d'intégrité) et
    //     `overlays` (`overlays_adossement::PASSE_OVERLAYS`, la passe `config.d`). DEUX aveux justes,
    //     lisibles par `dernier()`, servis par AUCUNE surface. `P10.7-w` avait écrit le premier dans
    //     son « ce que le lot ne tient pas » ; le second était là depuis plus longtemps, et personne
    //     ne l'avait écrit. Ce n'était donc pas deux accidents : c'est ce que produit une table qu'il
    //     faut PENSER à tenir.
    //   · TROISIÈME MEMBRE DE LA MÊME FAMILLE, DANS UN AUTRE REGISTRE : `ioc_reload_dernier` sait dire
    //     que le cache d'indicateurs tourne sur un jeu PÉRIMÉ (la table `ioc` n'a pas pu être relue,
    //     le jeu précédent est CONSERVÉ, la détection continue dessus). Il est servi par
    //     `/api/threat-intel/coverage` et par personne d'autre : ni `component_health`, ni
    //     `gather_json`, ni `/metrics`.
    //
    // L'ÉNONCÉ FONDATEUR EST FAUX SUR UN POINT, ET LE FAUX COMPTE. « Les deux surfaces itèrent une
    // table de boucles à laquelle rien n'a été ajouté » est vrai pour `P10.7-x` et FAUX pour
    // `P10.7-n` : ajouter une entrée à `BOUCLES` n'aurait rien fait pour le cache d'indicateurs. Sa
    // mesure vit dans un registre SÉPARÉ (`threat_intel::IOC_RELOAD`), keyé par `db_path` — donc par
    // TENANT — et aucune clé `&'static str` ne peut l'y représenter. Les deux clés partagent la
    // FIGURE (un aveu juste que personne ne sert), pas le mécanisme ; les traiter comme un seul geste
    // aurait fermé la première en croyant fermer la seconde.
    //
    // LA QUESTION A DÉCIDÉ DE LA FORME AVANT TOUTE ÉCRITURE : la table est-elle DÉRIVABLE ? OUI, et
    // sans rien inventer — le registre `DERNIERS` CONTIENT déjà l'ensemble exact des passes qui ont
    // publié. La surface parcourt donc `boucles_publiees()`, dérivé du registre. Ce qui publie est
    // servi ; l'oubli n'est plus une option offerte. Deux entrées de plus dans une liste écrite
    // auraient laissé la TROISIÈME passe s'oublier en silence, et c'eût été la quatrième fois.
    //
    // CE QUE LA DÉRIVATION CHANGE ENCORE, ET QUI N'AVAIT PAS ÉTÉ DEMANDÉ : elle RETIRE UNE FAUSSE
    // ACCUSATION. La table écrite nommait les six boucles DÈS LE DÉMARRAGE, avant leur premier tick ;
    // `poser_bilan(None)` ne posait alors aucune clé, et le helper `lisible()` de l'exposition
    // Prometheus retombe sur `VERDICT_ILLISIBLE` quand il ne trouve pas son verdict — six jauges
    // `plume_scheduler_<boucle>_bilan_lisible 0` au boot, c'est-à-dire « ce tick était AVEUGLE » sur
    // des boucles qui n'avaient tout simplement pas encore tourné. Dérivée, la table ne contient que
    // des clés PUBLIÉES : le verdict existe toujours, et l'accusation ne peut plus être portée à vide.
    //
    // LA MOITIÉ QUI NE SE DÉRIVE PAS, ET COMMENT ELLE EST RENDUE INOFFENSIVE. « Quel composant nommé
    // porte quelle passe » est une question de SENS : que les règles et les incidents de risque soient
    // tous deux « la détection » ne se déduit d'aucune propriété du code. Cette table-là reste donc
    // écrite (`bilan_de_tick::COMPOSANTS`) — mais son OUBLI ne fait plus disparaître personne : ce
    // qu'elle ne revendique pas tombe dans `bilans_orphelins()`, qui est le COMPLÉMENT
    // (`publiées − revendiquées`), et que la surface porte dans un composant à part. La pire faute
    // possible y est « montré deux fois », jamais « montré nulle part ».
    //
    // CE QUE CE LOT NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE. Aucune garde ne prouve que les passes
    // TOURNENT — un fil mort ne publie rien, et `None` reste lu « pas encore » (c'est délibéré : un
    // bilan inventé avant le premier passage serait un zéro rassurant). Le nom de série est ASSAINI
    // pour Prometheus ; deux clés ne différant que par un caractère non conforme se rejoindraient sur
    // le même nom de métrique, et seul le composant de santé — qui porte les noms BRUTS — les
    // distinguerait alors. Et le second reste de `P10.7-n` n'est PAS fermé ici : `ti_coverage` lit
    // `total`/`active` en `unwrap_or(0)`, donc le magasin se dit « vide » quand sa lecture échoue ; le
    // site est `handlers/threat_intel.rs`, hors du périmètre de ce lot, et le témoin qui le CONSTATE
    // est `le_panneau_de_couverture_dit_avec_quoi_on_detecte`.
    // ================================================================================================

    /// Le nom de série tel que l'exposition le fabrique, pour une clé de passe donnée.
    fn tps_nom_de_serie(passe: &str) -> String {
        crate::bilan_de_tick::nom_de_serie(passe)
    }

    /// Une base + un spool RÉELS et vides — la surface d'état lit les deux, et un spool absent la rend
    /// jaune pour une raison qui n'a rien à voir avec ce fichier.
    fn tps_socle(nom: &'static str) -> (Connection, crate::tmp_possede::TmpPossede) {
        (test_db(), crate::tmp_possede::TmpPossede::neuf(nom))
    }

    /// `P10.7-x` — UNE PASSE QUE PERSONNE N'A DÉCLARÉE EST SERVIE DÈS QU'ELLE PUBLIE.
    ///
    /// C'EST LE TÉMOIN QUI PORTE LE LOT, et sa force tient à la clé choisie : elle n'existe dans AUCUNE
    /// constante du démon, dans aucune table, dans aucun `COMPOSANTS`. Rien ne la connaît. Si la surface
    /// la sert, c'est qu'elle ne parcourt plus une liste. Le contrôle NÉGATIF passe d'abord — sans lui,
    /// une surface qui imprimerait tout et n'importe quoi passerait ce test sans rien prouver.
    #[test]
    fn une_passe_que_personne_n_a_declaree_est_servie_des_qu_elle_publie() {
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE};
        // Clé PROPRE à ce témoin : le registre est de PROCESSUS et la suite tourne en parallèle.
        const JAMAIS_DECLAREE: &str = "p107x-passe-jamais-declaree";
        let serie = tps_nom_de_serie(JAMAIS_DECLAREE);
        let (c, tmp) = tps_socle("p107x-inconnue");
        let spool = tmp.to_str().unwrap();

        // ① CONTRÔLE NÉGATIF — avant toute publication, la surface ne connaît pas cette passe, et
        //    n'invente aucun zéro à sa place.
        let j0 = gather_json(&c, spool, "", 1, 80);
        assert!(
            j0["scheduler"].get(format!("{JAMAIS_DECLAREE}_abandons_verdict").as_str()).is_none(),
            "avant publication : aucune clé, et surtout pas un zéro — {}", j0["scheduler"]
        );
        let p0 = gather_prom(&c, spool, "", 1, 80);
        assert!(!p0.contains(&serie), "avant publication : aucune série pour cette passe");

        // ② LA PUBLICATION EST LE SEUL GESTE. Aucune table n'est touchée, aucune constante ajoutée.
        crate::bilan_de_tick::publier(
            JAMAIS_DECLAREE,
            Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: "liste des éléments dus : no such table".into() },
        );

        let j = gather_json(&c, spool, "", 1, 80);
        assert_eq!(
            j["scheduler"][format!("{JAMAIS_DECLAREE}_abandons_verdict").as_str()], VERDICT_ILLISIBLE,
            "le JSON du panneau porte l'aveu d'une passe que rien ne déclarait : {}", j["scheduler"]
        );
        assert_eq!(j["scheduler"][format!("{JAMAIS_DECLAREE}_abandons_cause").as_str()], CAUSE_FORME_INCONNUE);
        assert!(
            j["scheduler"].get(format!("{JAMAIS_DECLAREE}_abandons").as_str()).is_none(),
            "STRUCTUREL : aucun nombre ne sort d'un aveu, donc aucune jauge ne peut publier « 0 abandon »"
        );

        let p = gather_prom(&c, spool, "", 1, 80);
        assert!(
            p.contains(&format!("plume_scheduler_{serie}_bilan_lisible{{cause=\"{CAUSE_FORME_INCONNUE}\"}} 0")),
            "/metrics SERT l'aveu, avec sa cause en étiquette"
        );
        assert!(
            !p.contains(&format!("\nplume_scheduler_{serie}_abandons ")),
            "et AUCUNE valeur : la série de nombre est ABSENTE quand la passe a été aveugle"
        );

        // ③ LE MÊME REGISTRE, LU SAINEMENT : la valeur revient, l'aveu s'efface. Sans ce second sens,
        //    une exposition qui crierait toujours passerait aussi le point ②.
        crate::bilan_de_tick::publier(JAMAIS_DECLAREE, Mesure::Lue(7));
        let p2 = gather_prom(&c, spool, "", 1, 80);
        assert!(p2.contains(&format!("\nplume_scheduler_{serie}_abandons 7\n")), "le compte est servi : {serie}");
        assert!(p2.contains(&format!("plume_scheduler_{serie}_bilan_lisible{{cause=\"aucune\"}} 1")));

        // ④ NETTOYAGE NOMMÉ — le registre est de PROCESSUS. On ne peut pas retirer une clé (le registre
        //    n'offre que `publier`), on la ramène donc à un VRAI zéro, qui ne rougit aucun composant.
        crate::bilan_de_tick::publier(JAMAIS_DECLAREE, Mesure::Lue(0));
    }

    /// `P10.7-x` — LES DEUX PASSES QUI PUBLIAIENT SANS ÊTRE SERVIES ATTEIGNENT LA SURFACE.
    ///
    /// `overlays` est NOMMABLE (`overlays_adossement` est un module de crate). `retention` ne l'est pas :
    /// `mod boucles_de_fond;` est PRIVÉ dans `server`. Le littéral est donc relu DANS LE SOURCE, pour
    /// qu'un renommage là-bas fasse rougir ici au lieu de rendre ce témoin vert sur une clé morte.
    #[test]
    fn les_deux_passes_qui_publiaient_sans_etre_servies_atteignent_la_surface() {
        use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE, VERDICT_ILLISIBLE};
        let boucles = include_str!("../server/boucles_de_fond.rs");
        assert!(
            boucles.contains("BOUCLE_RETENTION: &str = \"retention\""),
            "la clé de la boucle qui ANCRE a changé de nom : ce témoin garderait une clé morte"
        );
        // Les deux clés RÉELLES. On ne les publie pas sous leur vrai nom (d'autres témoins de la suite
        // les lisent) : on vérifie que la surface les SERT quand elles sont dans le registre, ce que le
        // témoin précédent a déjà prouvé pour une clé quelconque. Ici, ce qui est vérifié est qu'elles
        // ne sont revendiquées par AUCUN composant nommé — donc qu'elles tombent dans le complément.
        for cle in ["retention", crate::overlays_adossement::PASSE_OVERLAYS] {
            assert!(
                !crate::bilan_de_tick::COMPOSANTS.iter().any(|(_, portees)| portees.contains(&cle)),
                "`{cle}` n'est portée par aucun composant nommé — c'est le complément qui doit la porter"
            );
        }
        // Et le complément la porte VRAIMENT, aveu compris.
        let orphelines = [(
            "retention",
            Mesure::Illisible {
                cause: CAUSE_SOURCE_ILLISIBLE,
                detail: "tenant t1 : le corps du tick a paniqué".to_string(),
            },
        )];
        let (etat, detail) = crate::bilan_de_tick::etat_des_passes_orphelines(&orphelines);
        assert_eq!(etat, "red", "une passe d'ancrage AVEUGLE n'est pas un état calme : {detail}");
        assert!(detail.contains("retention"), "l'aveu NOMME la passe : {detail}");
        assert!(detail.contains("paniqué"), "et il porte la cause remontée par la passe : {detail}");
        assert_eq!(Mesure::<u64>::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: String::new() }.verdict(), VERDICT_ILLISIBLE);
    }

    /// `P10.7-x` — CE QUE LA SURFACE DIT DES PASSES ORPHELINES EST PUR, ET LE PASSAGE SAIN RESTE MUET.
    ///
    /// Fonction PURE : entrées FABRIQUÉES, aucun registre de processus, aucune base, aucune horloge —
    /// donc aucun aléa de parallélisme, et les QUATRE cas sont exerçables, y compris ceux qu'un état
    /// réel ne produit qu'exceptionnellement. Les deux premiers sont les contrôles négatifs : sans eux,
    /// une fonction qui rendrait TOUJOURS rouge passerait les deux derniers.
    #[test]
    fn l_etat_des_passes_orphelines_est_pur_et_muet_sur_un_passage_sain() {
        use crate::bilan_de_tick::etat_des_passes_orphelines as etat;
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE};

        // ① AUCUNE passe orpheline : `idle`, et RIEN qui ressemble à un aveu.
        let (e, d) = etat(&[]);
        assert_eq!(e, "idle", "aucune passe hors composant nommé : {d}");
        assert!(!d.contains("AVEUGLE") && !d.contains("ABANDONN"), "aucun aveu sans rien à avouer : {d}");

        // ② PASSAGE SAIN : vert, la passe est NOMMÉE (un exploitant doit savoir ce qui est couvert),
        //    et l'axe de l'aveu reste MUET.
        let (e, d) = etat(&[("retention", Mesure::Lue(0)), ("overlays", Mesure::Lue(0))]);
        assert_eq!(e, "green", "deux passages sains : {d}");
        assert!(d.contains("retention") && d.contains("overlays"), "le vert DIT ce qu'il couvre : {d}");
        assert!(!d.contains("AVEUGLE") && !d.contains("ABANDONN"), "un aveu INCONDITIONNEL n'est pas un aveu : {d}");

        // ③ ABANDONS : jaune, la passe et son COMPTE.
        let (e, d) = etat(&[("retention", Mesure::Lue(0)), ("overlays", Mesure::Lue(3))]);
        assert_eq!(e, "yellow", "des éléments dus non traités : {d}");
        assert!(d.contains("overlays") && d.contains('3'), "le jaune nomme la passe ET son compte : {d}");
        assert!(!d.contains("retention"), "et ne met pas en cause la passe saine : {d}");

        // ④ AVEUGLE : rouge, et il PASSE DEVANT un simple abandon — une passe qui n'a rien fait n'est
        //    pas une passe qui a fait la moitié.
        let (e, d) = etat(&[
            ("overlays", Mesure::Lue(3)),
            ("retention", Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: "no such table: ledger".into() }),
        ]);
        assert_eq!(e, "red", "une passe aveugle est ROUGE : {d}");
        assert!(d.contains("retention") && d.contains("no such table"), "l'aveu nomme la passe ET la cause : {d}");
    }

    /// `P10.7-x` — TOUTE PASSE PUBLIÉE EST PORTÉE PAR UN COMPOSANT DE LA SURFACE, ET LE CÂBLAGE TIENT.
    ///
    /// Trois faits STRUCTURELS, tous dérivés — aucun ne cite une liste :
    ///   · chaque composant NOMMÉ dans `COMPOSANTS` existe VRAIMENT sur la surface (une faute de frappe
    ///     y ferait taire un composant sans rien casser ailleurs) ;
    ///   · le composant du complément existe, toujours, même quand rien n'est orphelin ;
    ///   · toute clé publiée est soit revendiquée, soit orpheline — la couverture est une PARTITION.
    /// Puis le CÂBLAGE : une passe orpheline AVEUGLE rougit la surface et s'y NOMME. Ce sens-là est
    /// robuste au parallélisme (une pollution concurrente ne peut que renforcer le rouge) ; le sens
    /// inverse est tenu par le témoin PUR ci-dessus, et non ici, précisément pour cette raison.
    #[test]
    fn toute_passe_publiee_est_portee_par_un_composant_de_la_surface() {
        use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};
        const ORPHELINE: &str = "p107x-orpheline-cablage";
        let (c, tmp) = tps_socle("p107x-cablage");
        let spool = tmp.to_str().unwrap();

        let comps = component_health(&c, spool, "", 80);
        let nomme = |n: &str| comps.iter().any(|v| v["component"] == n);
        for (composant, _) in crate::bilan_de_tick::COMPOSANTS {
            assert!(nomme(composant), "le composant `{composant}` de la table n'existe pas sur la surface");
        }
        assert!(
            nomme(crate::bilan_de_tick::COMPOSANT_PASSES_DE_FOND),
            "le composant du COMPLÉMENT existe toujours : son absence se lirait « rien à signaler »"
        );

        let publiees = crate::bilan_de_tick::boucles_publiees();
        let orphelines: Vec<&str> = crate::bilan_de_tick::bilans_orphelins().into_iter().map(|(n, _)| n).collect();
        for p in &publiees {
            let revendiquee = crate::bilan_de_tick::COMPOSANTS.iter().any(|(_, portees)| portees.contains(p));
            assert!(
                revendiquee ^ orphelines.contains(p),
                "`{p}` doit être revendiquée par UN composant nommé ou tomber dans le complément, jamais ni l'un ni l'autre, jamais les deux"
            );
        }

        // CÂBLAGE : l'aveu d'une passe que rien ne revendique atteint le voyant.
        crate::bilan_de_tick::publier(
            ORPHELINE,
            Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: "p107x : liste illisible".into() },
        );
        let comps = component_health(&c, spool, "", 80);
        let bloc = comps
            .iter()
            .find(|v| v["component"] == crate::bilan_de_tick::COMPOSANT_PASSES_DE_FOND)
            .expect("le composant du complément est servi")
            .clone();
        assert_eq!(bloc["state"], "red", "une passe orpheline AVEUGLE rougit le voyant : {bloc}");
        assert!(
            bloc["detail"].as_str().unwrap_or_default().contains(ORPHELINE),
            "et le détail NOMME la passe — un aveu sans le sujet ne se répare pas : {bloc}"
        );
        assert_eq!(worst_state(&comps), "red", "la posture globale suit : {bloc}");

        // NETTOYAGE NOMMÉ.
        crate::bilan_de_tick::publier(ORPHELINE, Mesure::Lue(0));
    }

    /// `P10.7-x` — UNE CLÉ DE PASSE NE PEUT PLUS PRODUIRE UN NOM DE MÉTRIQUE INVALIDE.
    ///
    /// LA DÉRIVATION A UN COÛT, ET IL EST PAYÉ ICI. La table écrite portait six noms choisis à la main,
    /// tous conformes ; dérivée, elle prend ce que le code publie. Un caractère hors `[a-zA-Z0-9_]`
    /// dans une clé produirait un nom de métrique INVALIDE — et Prometheus rejette alors le relevé
    /// ENTIER, pas seulement la série fautive : l'observabilité du démon disparaîtrait d'un coup.
    #[test]
    fn une_cle_de_passe_ne_peut_pas_produire_un_nom_de_metrique_invalide() {
        use crate::mesure_environnement::Mesure;
        const AVEC_TIRETS: &str = "p107x-cle.avec/ponctuation";
        assert_eq!(tps_nom_de_serie(AVEC_TIRETS), "p107x_cle_avec_ponctuation");
        assert_eq!(tps_nom_de_serie("regles"), "regles", "une clé déjà conforme n'est PAS altérée");

        let (c, tmp) = tps_socle("p107x-nom-de-serie");
        let spool = tmp.to_str().unwrap();
        crate::bilan_de_tick::publier(AVEC_TIRETS, Mesure::Lue(1));
        let prom = gather_prom(&c, spool, "", 1, 80);
        // La PROPRIÉTÉ, pas la ligne : AUCUN nom de métrique du relevé ne sort de l'alphabet admis.
        for ligne in prom.lines().filter(|l| l.starts_with("# TYPE ")) {
            let nom = ligne.split_whitespace().nth(2).unwrap_or_default();
            assert!(
                !nom.is_empty() && nom.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'),
                "nom de métrique INVALIDE — Prometheus rejette le relevé entier : {ligne:?}"
            );
        }
        // ET LE SECOND PIÈGE, TROUVÉ PAR CE TÉMOIN AU PREMIER TIR : l'objet JSON garde la clé BRUTE,
        // mais l'exposition la retrouve par un POINTEUR RFC 6901, dont `/` est le séparateur de niveau.
        // Sans échappement, le pointeur descendait de deux niveaux, `g()` ne trouvait rien — la série
        // de valeur DISPARAISSAIT — et `lisible()`, qui retombe sur « illisible » faute de verdict,
        // accusait d'un passage AVEUGLE une passe qui venait de rendre un compte parfaitement lu.
        assert!(prom.contains("\nplume_scheduler_p107x_cle_avec_ponctuation_abandons 1\n"), "la passe est bien servie");
        assert!(
            prom.contains("plume_scheduler_p107x_cle_avec_ponctuation_bilan_lisible{cause=\"aucune\"} 1"),
            "et un passage LU n'est pas accusé d'avoir été aveugle"
        );
        crate::bilan_de_tick::publier(AVEC_TIRETS, Mesure::Lue(0));
    }

    /// `P10.7-n` — L'AVEU DE LA DÉTECTION ATTEINT LA SANTÉ ET LES MÉTRIQUES.
    ///
    /// LA MOITIÉ PURE D'ABORD, exhaustive et sans aléa : la règle d'état d'une mesure dont le JEU
    /// PRÉCÉDENT EST CONSERVÉ. Elle n'est PAS celle d'un bilan de tick — là, illisible veut dire « rien
    /// n'a été évalué », donc rouge ; ici le service CONTINUE sur un jeu qui vieillit, et rouge serait
    /// une SUR-ACCUSATION (la détection n'est pas éteinte) comme vert serait un mensonge.
    #[test]
    fn l_etat_d_un_jeu_conserve_est_jaune_et_le_chemin_sain_reste_muet() {
        use crate::bilan_de_tick::etat_de_surface_jeu_conserve as etat;
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE};

        // ① AUCUNE MESURE (démarrage) et ② MESURE SAINE : l'état et le détail sont RENDUS INTACTS.
        let (e, d) = etat("green", "tick récent".into(), "le cache d'indicateurs", None);
        assert_eq!((e, d.as_str()), ("green", "tick récent"), "aucun rechargement encore : rien n'est affirmé");
        let (e, d) = etat("green", "tick récent".into(), "le cache d'indicateurs", Some(&Mesure::Lue(1200)));
        assert_eq!((e, d.as_str()), ("green", "tick récent"), "un rechargement RÉUSSI ne dit rien de plus");

        // ③ JEU PÉRIMÉ : jamais vert, jamais idle, et le détail porte le SUJET et la CAUSE.
        let perime = Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: "table `ioc` masquée ; 1200 indicateur(s) conservé(s)".into() };
        let (e, d) = etat("green", "tick récent".into(), "le cache d'indicateurs", Some(&perime));
        assert_eq!(e, "yellow", "le service continue : jaune, pas rouge — {d}");
        assert!(d.contains("PÉRIMÉ") && d.contains("cache d'indicateurs"), "le détail nomme le sujet : {d}");
        assert!(d.contains("1200"), "et sur COMBIEN la détection tourne encore : {d}");

        // ④ LE PIRE L'EMPORTE : un composant déjà rouge ne redevient pas jaune pour un jeu périmé.
        assert_eq!(etat("red", "bloqué".into(), "le cache d'indicateurs", Some(&perime)).0, "red");
    }

    /// `P10.7-n` — LE CÂBLAGE : la santé PAR COMPOSANT et `/metrics` portent l'aveu du cache
    /// d'indicateurs, et NE PORTENT RIEN quand aucun rechargement n'a encore eu lieu.
    ///
    /// L'état est FABRIQUÉ dans le registre, jamais attendu d'une boucle : le `db_path` est propre à ce
    /// témoin (les caches d'indicateurs sont de PROCESSUS et keyés par `db_path`, et la suite tourne en
    /// parallèle). Le troisième point est celui qui compte le plus : une jauge de lisibilité qui
    /// s'imprimerait à vide accuserait un démon qui vient de démarrer.
    #[test]
    fn le_cache_d_indicateurs_perime_atteint_la_sante_et_les_metriques() {
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE, VERDICT_LU};
        let dbp = "p107n-surface";
        let (c, tmp) = tps_socle("p107n-surface");
        let spool = tmp.to_str().unwrap();
        let detection = |c: &Connection, spool: &str| {
            component_health(c, spool, dbp, 80).into_iter().find(|v| v["component"] == "detection").expect("composant détection")
        };

        // ① AUCUN RECHARGEMENT ENCORE — la surface se tait, et ne publie AUCUNE jauge de lisibilité :
        //    l'absence se lit « pas encore », jamais « le cache est périmé ».
        crate::ioc_reload_etat().write().remove(dbp);
        let d0 = detection(&c, spool);
        assert!(d0.get("cache_indicateurs").is_none() && d0.get("cache_indicateurs_verdict").is_none(), "démarrage : rien n'est posé — {d0}");
        let p0 = gather_prom(&c, spool, dbp, 1, 80);
        assert!(!p0.contains("plume_ioc_cache_lisible"), "aucune accusation portée à vide au démarrage");

        // ② RECHARGEMENT SAIN — le nombre est publié, l'axe de l'aveu reste MUET.
        crate::ioc_reload_etat().write().insert(dbp.to_string(), Mesure::Lue(2));
        let d1 = detection(&c, spool);
        assert_eq!(d1["cache_indicateurs"], 2, "la DÉTECTION tourne sur deux indicateurs : {d1}");
        assert_eq!(d1["cache_indicateurs_verdict"], VERDICT_LU);
        assert!(!d1["detail"].as_str().unwrap_or_default().contains("PÉRIMÉ"), "chemin sain MUET : {d1}");
        let p1 = gather_prom(&c, spool, dbp, 1, 80);
        assert!(p1.contains("\nplume_ioc_cache_indicateurs 2\n"), "et /metrics sert le compte");
        assert!(p1.contains("plume_ioc_cache_lisible{cause=\"aucune\"} 1"));

        // ③ JEU PÉRIMÉ — le voyant cesse d'être vert, le nombre DISPARAÎT, l'aveu et sa cause sortent.
        crate::ioc_reload_etat().write().insert(
            dbp.to_string(),
            Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: "no such table: ioc ; 2 indicateur(s) conservé(s)".into() },
        );
        let d2 = detection(&c, spool);
        assert_ne!(d2["state"], "green", "un jeu périmé n'est pas un état sain : {d2}");
        assert_ne!(d2["state"], "idle", "et surtout pas « rien à signaler » : {d2}");
        assert!(d2["detail"].as_str().unwrap_or_default().contains("PÉRIMÉ"), "l'exploitant le LIT sur le voyant : {d2}");
        assert!(d2.get("cache_indicateurs").is_none(), "aucun nombre à lire quand la lecture a échoué : {d2}");
        assert_eq!(d2["cache_indicateurs_verdict"], VERDICT_ILLISIBLE);
        assert_eq!(d2["cache_indicateurs_cause"], CAUSE_FORME_INCONNUE);
        let p2 = gather_prom(&c, spool, dbp, 1, 80);
        assert!(p2.contains(&format!("plume_ioc_cache_lisible{{cause=\"{CAUSE_FORME_INCONNUE}\"}} 0")), "/metrics porte l'aveu");
        assert!(!p2.contains("\nplume_ioc_cache_indicateurs "), "et AUCUN nombre à côté");
        let j2 = gather_json(&c, spool, dbp, 1, 80);
        assert_eq!(j2["detection"]["cache_indicateurs_verdict"], VERDICT_ILLISIBLE, "le panneau Système aussi : {}", j2["detection"]);

        // NETTOYAGE NOMMÉ.
        crate::ioc_reload_etat().write().remove(dbp);
    }
