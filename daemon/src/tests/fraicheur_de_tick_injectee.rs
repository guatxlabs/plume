// LA FRAÎCHEUR D'UN TICK SE DÉCIDE SUR UN ÉTAT INJECTÉ, JAMAIS SUR L'AMBIANT DU PROCESSUS
// (`P11.24-e`).
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE DÉFAUT, MESURÉ SUR CET ARBRE
// ─────────────────────────────────────────────────────────────────────────────────────────────
// Le portail de déploiement a rougi le 2026-09-01 sur un unique témoin de santé : il attendait
// qu'une détection cesse d'être verte après un tick ancien, et la trouvait VERTE. Rejoué SEUL sur
// la même machine avec le même profil, il passait. Le canal de refus, interrogé au même moment,
// disait qu'aucun test n'avait refusé de conclure : ce n'était donc pas un aveuglement, mais une
// vraie assertion, fausse sous charge.
//
// LE MÉCANISME ANNONCÉ — « un seuil d'âge franchi ou non pendant que quarante autres tests se
// disputent la machine » — EST RÉFUTÉ PAR L'ARITHMÉTIQUE DU TÉMOIN. Il posait un âge de MILLE
// secondes contre un plafond de CENT VINGT : pour que le verdict bascule par retard, il aurait
// fallu que l'ordonnanceur lui vole huit cent quatre-vingts secondes entre son écriture et sa
// lecture. La cause est ailleurs, et elle est banale : l'âge n'était pas une valeur du témoin,
// c'était une ATOMIQUE DE PROCESSUS, que `day2_metrics_exposition_shape_and_auth` — dans le même
// binaire, sans en avoir le moindre besoin — remettait à `maintenant`. La charge n'a jamais fait
// que d'élargir la fenêtre où cette écriture s'intercale.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QUE CETTE GARDE REND NON-ÉCRIVABLE, ET POURQUOI PAS PLUS
// ─────────────────────────────────────────────────────────────────────────────────────────────
// La surface d'état reçoit désormais sa fraîcheur EN ARGUMENT (`FraicheurDesTicks`), et un seul
// site la dérive du processus. Cela suffit au témoin d'aujourd'hui ; cela n'empêche pas celui de
// demain d'écrire de nouveau dans l'atomique commune. C'est ce que cette garde ferme : aucun code
// de TEST n'écrit une grandeur que la surface d'état lit en ambiant. Le geste de remédiation est
// nommé dans le message, et il tient en une ligne — donc ce n'est pas une rançon.
//
// LES NOMS NE SONT PAS RECOPIÉS ICI : ils sont DÉRIVÉS de la couture elle-même — ce que
// `FraicheurDesTicks::du_processus` LIT est, par définition, l'ambiant. Une troisième boucle
// ajoutée à la couture demain est gardée sans qu'on y pense ; un renommage fait ROUGIR la
// dérivation au lieu de la rendre muette.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QU'ELLE NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
// ─────────────────────────────────────────────────────────────────────────────────────────────
//   · LE TEXTE, PAS L'EXÉCUTION. Elle établit qu'aucune ligne de test n'écrit ces atomiques ; une
//     écriture faite depuis une fonction de PRODUCTION appelée par un test lui échappe.
//   · LES COMMENTAIRES DE LIGNE SEULEMENT. Une ligne dont le texte commence par `//` est ignorée
//     (on DÉCRIT un défaut sans le recopier) ; un commentaire de BLOC qui porterait la forme
//     accusée serait pris pour du code. La borne est dite.
//   · LES AUTRES AMBIANTS. Le produit porte d'autres atomiques de processus (compteurs d'ingest,
//     horodatage de démarrage, réservoir de latences). Cette garde ne couvre QUE celles que la
//     surface d'état lit par la couture de fraîcheur. `day2_search_metric_updates` porte, pour le
//     réservoir de latences, sa propre défense — écrite en 2026-08-09 et documentée sur place.
//   · UNE SEULE CAISSE, celle du démon.

    /// La forme accusée, sur UNE ligne : `<AMBIANT>` suivi d'une écriture. Le motif est CONSTRUIT à
    /// partir du nom dérivé — ce fichier ne contient donc nulle part la forme qu'il refuse, ce qui
    /// est exactement la règle qu'il applique aux autres.
    fn ecriture_ambiante_sur_la_ligne(ligne: &str, ambiantes: &[String]) -> Option<String> {
        let code = ligne.trim_start();
        if code.starts_with("//") {
            return None;
        }
        for nom in ambiantes {
            if ligne.contains(&format!("{nom}.store(")) {
                return Some(nom.clone());
            }
        }
        None
    }

    /// AUCUN TEST N'ÉCRIT LA FRAÎCHEUR AMBIANTE DES BOUCLES DE FOND.
    ///
    /// Deux témoins d'instrument encadrent le verdict : une ligne FABRIQUÉE portant la forme doit
    /// être vue, et une LECTURE de la même atomique ne doit PAS l'être. Sans eux, un détecteur qui
    /// ne mordrait plus rendrait « aucune faute » sur tout l'arbre.
    #[test]
    fn aucun_test_n_ecrit_la_fraicheur_ambiante_des_boucles_de_fond() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

        // ① LES AMBIANTES SONT DÉRIVÉES DE LA COUTURE, JAMAIS ÉNUMÉRÉES ICI.
        let metrics = std::fs::read_to_string(racine.join("metrics.rs"))
            .expect("`metrics.rs` illisible : la dérivation des atomiques ambiantes n'a pas de source");
        let depart = metrics.find("fn du_processus()").expect(
            "`FraicheurDesTicks::du_processus` INTROUVABLE dans `metrics.rs` : la couture qui isole \
             l'ambiant de la surface d'état a disparu ou changé de nom. Cette garde jugerait contre \
             rien — elle refuse de le faire en silence.",
        );
        let reste = &metrics[depart..];
        let fin = reste
            .find("\n    }")
            .expect("le corps de `du_processus` n'est pas délimité comme attendu");
        let corps = &reste[..fin];
        let mut ambiantes: Vec<String> = Vec::new();
        for (i, _) in corps.match_indices(".load(") {
            let nom: String = corps[..i]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<Vec<char>>()
                .into_iter()
                .rev()
                .collect();
            if !nom.is_empty() && nom.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                ambiantes.push(nom);
            }
        }
        ambiantes.sort();
        ambiantes.dedup();
        assert!(
            !ambiantes.is_empty(),
            "INSTRUMENT : aucune atomique dérivée du corps de `du_processus` — la garde serait verte \
             par construction sur n'importe quel arbre"
        );
        // ET CHAQUE NOM DÉRIVÉ EST BIEN UNE ATOMIQUE DE PROCESSUS : sans cette vérification, une
        // dérivation qui ramasserait n'importe quel identifiant garderait un ensemble vide de sens.
        for nom in &ambiantes {
            assert!(
                metrics.contains(&format!("static {nom}: AtomicI64")),
                "INSTRUMENT : `{nom}` est lu par la couture mais n'est pas déclaré comme atomique de \
                 processus dans `metrics.rs` — la dérivation a ramassé autre chose qu'un ambiant"
            );
        }

        // ② LES DEUX TÉMOINS D'INSTRUMENT, FABRIQUÉS ICI.
        let fabriquee = format!("        {}.store(now(), MOrd::Relaxed);", ambiantes[0]);
        assert_eq!(
            ecriture_ambiante_sur_la_ligne(&fabriquee, &ambiantes).as_deref(),
            Some(ambiantes[0].as_str()),
            "INSTRUMENT : le détecteur ne voit pas la forme qu'il existe pour refuser"
        );
        let lecture = format!("        let t = {}.load(MOrd::Relaxed);", ambiantes[0]);
        assert!(
            ecriture_ambiante_sur_la_ligne(&lecture, &ambiantes).is_none(),
            "INSTRUMENT : une LECTURE de l'ambiant est accusée comme une écriture — la garde \
             refuserait un usage légitime"
        );
        let decrite = format!("        // on n'écrit plus {}.store( depuis un test", ambiantes[0]);
        assert!(
            ecriture_ambiante_sur_la_ligne(&decrite, &ambiantes).is_none(),
            "INSTRUMENT : une ligne de COMMENTAIRE est accusée — décrire un défaut deviendrait \
             impossible sans le rejouer"
        );

        // ③ L'ARBRE. Zone de test = tout fichier sous `src/tests/` ou nommé `tests.rs`, et, pour les
        //    autres, tout ce qui suit le premier `#[cfg(test)]`.
        let mut fautes: Vec<String> = Vec::new();
        let mut zones = 0usize;
        let mut pile = vec![racine.clone()];
        while let Some(d) = pile.pop() {
            for e in std::fs::read_dir(&d).expect("arbre des sources illisible") {
                let p = e.expect("entrée illisible").path();
                if p.is_dir() {
                    pile.push(p);
                    continue;
                }
                if p.extension().map(|x| x != "rs").unwrap_or(true) {
                    continue;
                }
                let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
                let texte = std::fs::read_to_string(&p).expect("source illisible");
                let tout_est_test = rel.starts_with("tests/") || rel.ends_with("/tests.rs") || rel == "tests.rs";
                let debut = if tout_est_test { Some(0) } else { texte.find("#[cfg(test)]") };
                let Some(debut) = debut else { continue };
                zones += 1;
                let mut offset = 0usize;
                for (n, ligne) in texte.lines().enumerate() {
                    if offset >= debut {
                        if let Some(nom) = ecriture_ambiante_sur_la_ligne(ligne, &ambiantes) {
                            fautes.push(format!("{rel}:{} écrit `{nom}` : {}", n + 1, ligne.trim()));
                        }
                    }
                    offset += ligne.len() + 1;
                }
            }
        }
        assert!(
            zones >= 40,
            "INSTRUMENT : seulement {zones} zone(s) de test parcourue(s) — l'arbre n'a pas été lu, \
             et « aucune faute » ne voudrait rien dire"
        );
        assert!(
            fautes.is_empty(),
            "UN TEST ÉCRIT UNE GRANDEUR AMBIANTE QUE LA SURFACE D'ÉTAT LIT ({} site(s)) :\n  {}\n\
             \nCette atomique est PARTAGÉE par tout le binaire de test : un autre témoin peut y \
             écrire entre votre écriture et votre lecture, et votre verdict bascule sans que rien \
             ne soit cassé — c'est `P11.24-e`, et cela abat un déploiement en accusant le code \
             alors que la machine est en cause. LE GESTE : passer la valeur voulue à \
             `component_health_avec(…, FraicheurDesTicks {{ … }})` et ne rien écrire dans \
             l'ambiant. Le témoin décide alors sur un état INJECTÉ, et rend le même verdict seul \
             et sous charge.",
            fautes.len(),
            fautes.join("\n  ")
        );
    }
