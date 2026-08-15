// `P10.14-a` — TOUTE CLÉ QUI NOMME UN TROU DOIT AVOIR UN TEST QUI LA NOMME, ELLE, ET PAS SES SŒURS.
//
// D'OÙ VIENT CETTE GARDE. Deux lots consécutifs ont livré un chemin `fail-*` NON GARDÉ, et les deux
// fois la seule chose qui tenait la propriété était une PHRASE : `d81897f` (le `fail-loud` de
// `detect_aging_stall` — réintroduire `unwrap_or(0)` laissait la suite VERTE) puis `e19bf4d` (« le tir
// n'est jamais marqué sur un échec » — déplacer l'écriture avant le `return` d'échec laissait 6 tests
// verts, et un dead-man's-switch se serait tu 24 H au lieu d'une heure). Une promesse en prose est
// écrite au moment où le code est JUSTE : le compilateur ne la vérifie pas, et une relecture la prend
// pour une garantie. L'instrument qui a trouvé la seconde était un simple COMPTAGE — `RETARD_REQUETE`
// citée UNE fois dans les tests contre 7/6/3 pour ses sœurs. Ce fichier fait de ce comptage une garde.
//
// LE BRUIT A ÉTÉ MESURÉ AVANT DE CHOISIR LA PORTÉE, parce qu'une garde qui crie sur trente cas
// légitimes est débranchée le premier jour (ce dépôt l'a déjà vécu deux fois). Mesures du 2026-08-14 :
//   * la règle BRUTE telle qu'elle était formulée — « une clé qui n'apparaît qu'UNE FOIS dans le dépôt »
//     — accuse **0 constante sur 113** : une constante déclarée porte déjà son nom une fois, et une
//     constante jamais utilisée est un `dead_code` que `rustc` refuse. La règle brute ne peut RIEN
//     attraper ; ce n'est pas elle qui a trouvé le trou.
//   * la règle utile compte les citations DANS LES TESTS. Appliquée à toutes les constantes `&str` du
//     démon, elle en accuse **48 sur 107** (36 jamais citées, 12 citées une fois) — 45 % : inexploitable.
//   * appliquée aux seules clés d'étiquette des modules de série, elle en accuse **2 sur 15**.
// C'est cette dernière portée qui est retenue, et sa RAISON n'est pas « ça fait moins de bruit » : un
// module de série est le seul endroit du démon dont le contrat ÉCRIT est « un trou est NOMMÉ, jamais
// publié comme un zéro » (cf. l'en-tête de `vieillissement_serie`). Ailleurs, une constante `&str` est
// un nom de fichier, une variable d'environnement ou un fragment de DDL : rien ne promet qu'un test
// l'oppose. La portée est donc l'ensemble des constantes qui portent CETTE promesse-là, et aucune autre.
//
// LA GARDE EST DÉRIVÉE, ET ELLE NE PORTE AUCUN NOM DE CAUSE. Trois dérivations en chaîne, toutes lues
// dans le source :
//   1. LE PÉRIMÈTRE — un fichier de production est un MODULE DE SÉRIE s'il construit une étiquette dont
//      la clé est `cause`, c.-à-d. s'il porte `("cause",`. Un troisième module de série écrit demain
//      entre dans la garde le jour où il publie sa première cause, sans que personne n'y pense.
//   2. LES NOMS DE SÉRIE — parmi les constantes de ces fichiers, celles que le code de production
//      utilise comme `nom:` d'un `Point`. Ce sont des noms de série, pas des clés d'étiquette : elles
//      sont hors sujet et sortent PAR CONSTRUCTION, sans être nommées.
//   3. LES CLÉS QUI NOMMENT UN TROU — tout le reste. Une cause ajoutée demain dans un module de série
//      est couverte du seul fait d'y être déclarée. C'est le complément, jamais une liste ; la même
//      figure que `Compte::travail_seul`, qui obtient les compteurs de travail en remettant la
//      comptabilité des jours à zéro plutôt qu'en les énumérant.
//
// LE SEUIL RETENU, ET POURQUOI CE N'EST PAS « UNE OCCURRENCE ». Une citation qui ne peut pas
// DISTINGUER cette cause de ses sœurs ne garde rien : elle est satisfaite à l'identique que la cause
// soit atteignable ou morte. Deux formes, toutes deux reconnues par leur STRUCTURE et non par leur
// contenu — un item `use`, et une région `[ … ]` qui contient au moins deux clés (c'est la forme du
// `for cause in [A, B, C]` et celle du `let causes = [ … ];` étalé sur dix lignes). Une clé doit donc
// avoir au moins une citation SPÉCIFIQUE : une occurrence hors de ces régions.
// CE CHOIX EST MESURÉ, PAS POSTULÉ. Sur l'arbre reconstruit tel qu'il était AVANT le correctif de
// `e19bf4d` (le test `une_requete_de_retard_en_echec_ne_consomme_pas_le_tir` retiré) :
//   * seuil « au moins une citation SPÉCIFIQUE » -> accuse `RETARD_REQUETE`. Il RETROUVE le trou.
//   * seuil « au moins une citation hors `use` » -> n'accuse RIEN : la boucle
//     `for cause in [ … RETARD_REQUETE … ]` lui suffisait. Ce seuil-là aurait laissé passer le défaut
//     que cette garde existe pour attraper. Il est écarté par la mesure, pas par goût.
//
// CE QUE LA GARDE NE PROUVE PAS, écrit pour être opposable. Elle prouve qu'un test NOMME la cause seule ;
// elle ne prouve pas que ce test exerce le chemin de production qui l'émet — aucun scanner de source ne
// peut le faire. C'est une condition NÉCESSAIRE, et c'est exactement celle qui manquait deux fois de suite.

#[cfg(test)]
mod cles_de_cause_gardees_tests {
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, sans_commentaire, texte_de_production};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    /// Ce qu'un fichier de production doit porter pour être un MODULE DE SÉRIE. Pas un nom de fichier :
    /// la construction d'une étiquette dont la clé est `cause`.
    const MARQUE_DU_MODULE_DE_SERIE: &str = "(\"cause\",";

    fn racine() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    // =============================================================================================
    // LE LECTEUR DE CITATIONS — PUR, donc validable sur des témoins avant d'être cru sur 46 000 lignes
    // =============================================================================================

    /// `const NOM: &str = "VALEUR"` -> `(NOM, VALEUR)`. Écrit à la main plutôt qu'avec une expression
    /// rationnelle (le démon a pourtant `regex`) : la forme cherchée est figée par `rustfmt`, et un
    /// analyseur explicite dit à la lecture ce qu'il refuse — un motif compact ne le dit pas. Il est
    /// éprouvé sur témoins juste en dessous, ce qu'un motif aurait exigé de toute façon.
    pub(super) fn declaration_de_constante(ligne: &str) -> Option<(String, String)> {
        let l = ligne.trim_start();
        let l = l.strip_prefix("pub(crate) ").or_else(|| l.strip_prefix("pub ")).unwrap_or(l);
        let l = l.strip_prefix("const ")?;
        let (nom, reste) = l.split_once(':')?;
        let nom = nom.trim();
        if nom.is_empty() || !nom.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
            return None;
        }
        let reste = reste.trim_start().strip_prefix("&str")?.trim_start().strip_prefix('=')?.trim_start();
        let reste = reste.strip_prefix('"')?;
        let fin = reste.find('"')?;
        Some((nom.to_string(), reste[..fin].to_string()))
    }

    /// Vrai si `p` est une frontière de mot dans `txt` (ni lettre, ni chiffre, ni `_`).
    fn frontiere(txt: &str, p: usize) -> bool {
        match txt.as_bytes().get(p) {
            None => true,
            Some(b) => !(b.is_ascii_alphanumeric() || *b == b'_'),
        }
    }

    /// Les positions où `mot` apparaît comme IDENTIFIANT ENTIER.
    pub(super) fn positions_de_lidentifiant(txt: &str, mot: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut base = 0usize;
        while let Some(rel) = txt[base..].find(mot) {
            let p = base + rel;
            let avant = p == 0 || frontiere(txt, p - 1);
            if avant && frontiere(txt, p + mot.len()) {
                out.push(p);
            }
            base = p + mot.len();
        }
        out
    }

    /// Les positions où `valeur` apparaît ENTRE GUILLEMETS. Une assertion cite souvent la VALEUR et
    /// jamais l'identifiant (`Some("{\"cause\":\"aging_suspendu\"}")`), et compter les seuls
    /// identifiants fabriquerait des faux positifs. L'échappement `\"` est toléré des deux côtés :
    /// dans une chaîne Rust imbriquée, la valeur est encadrée par `\"` … `\"`.
    pub(super) fn positions_de_la_valeur(txt: &str, valeur: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let o = txt.as_bytes();
        let mut base = 0usize;
        while let Some(rel) = txt[base..].find(valeur) {
            let p = base + rel;
            let fin = p + valeur.len();
            let ouvre = p > 0 && o[p - 1] == b'"';
            let ferme = matches!(o.get(fin), Some(b'"') | Some(b'\\'));
            if ouvre && ferme {
                out.push(p);
            }
            base = fin;
        }
        out
    }

    /// Les régions `[ … ]`, MULTI-LIGNES. Une énumération de causes s'écrit couramment sur dix lignes
    /// (`let causes = [\n CAUSE_A,\n CAUSE_B,\n …];`) : une règle qui raisonne LIGNE PAR LIGNE y verrait
    /// dix citations spécifiques et rendrait la garde aveugle exactement là où l'énumération est.
    /// Une `[` jamais refermée est simplement ignorée (sa pile n'est jamais dépilée).
    pub(super) fn regions_entre_crochets(txt: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut pile: Vec<usize> = Vec::new();
        for (i, c) in txt.char_indices() {
            match c {
                '[' => pile.push(i),
                ']' => {
                    if let Some(a) = pile.pop() {
                        out.push((a, i));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Les régions couvertes par un item `use`, du mot-clé jusqu'à son `;`. Un import est la citation la
    /// plus vide qui soit : il rend le nom VISIBLE, il n'affirme rien.
    pub(super) fn regions_des_items_use(txt: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut debut_de_ligne = 0usize;
        for ligne in txt.split_inclusive('\n') {
            let decale = ligne.len() - ligne.trim_start().len();
            let t = ligne.trim_start();
            let t = t.strip_prefix("pub(crate) ").or_else(|| t.strip_prefix("pub ")).unwrap_or(t);
            if t.starts_with("use ") || t == "use" {
                let d = debut_de_ligne + decale;
                let f = txt[d..].find(';').map_or(txt.len(), |r| d + r);
                out.push((d, f));
            }
            debut_de_ligne += ligne.len();
        }
        out
    }

    /// LE TEXTE DE TEST d'un fichier, avec les numéros de ligne — c'est-à-dire le COMPLÉMENT de
    /// `texte_de_production`. Il n'y a donc pas deux découpeurs qui pourraient diverger : un fichier
    /// entièrement de test (marqué par un `#[cfg(test)] mod x;`) rend toutes ses lignes, un fichier de
    /// production rend exactement ce que l'extracteur de production a écarté.
    fn texte_de_test(
        f: &std::path::Path,
        src: &str,
        marques: &BTreeSet<PathBuf>,
    ) -> Vec<(usize, String)> {
        let lignes: Vec<&str> = src.lines().collect();
        if est_test(f, marques) {
            return lignes.iter().enumerate().map(|(i, l)| (i + 1, sans_commentaire(l))).collect();
        }
        let prod: BTreeSet<usize> = texte_de_production(f, src).into_iter().map(|(n, _)| n).collect();
        lignes
            .iter()
            .enumerate()
            .filter(|(i, _)| !prod.contains(&(i + 1)))
            .map(|(i, l)| (i + 1, sans_commentaire(l)))
            .collect()
    }

    // =============================================================================================
    // LA VALIDATION DE L'INSTRUMENT — avant de lui faire confiance sur le dépôt
    // =============================================================================================

    /// Sans ce test, un lecteur cassé (qui ne trouverait jamais rien, ou qui trouverait partout) rendrait
    /// la garde verte pour toujours : la panne la plus silencieuse qu'un scanner puisse avoir. Chaque
    /// primitive est éprouvée sur un témoin POSITIF et sur un témoin NÉGATIF.
    ///
    /// LES TÉMOINS N'EMPLOIENT AUCUN NOM NI AUCUNE VALEUR RÉELS, et ce n'est pas de la coquetterie :
    /// ce fichier vit sous `src/tests/`, donc TOUTES ses lignes sont du texte de TEST. Un témoin qui
    /// citerait `RETARD_CADENCE` compterait comme une citation spécifique de cette cause — la garde se
    /// créditerait elle-même et tiendrait une cause MORTE pour gardée. Mesuré avant correction : la
    /// première version de ce fichier faisait passer `RETARD_CADENCE` de 4 à 16 citations spécifiques
    /// et `CRETE_SUSPENDU` de 1 à 7. La ceinture (témoins synthétiques) est doublée d'une bretelle
    /// (ce fichier est retiré du corpus balayé, cf. `file!()` dans la garde).
    #[test]
    fn le_lecteur_de_citations_voit_ce_quil_doit_voir_et_rien_dautre() {
        // --- la déclaration de constante ---
        assert_eq!(
            declaration_de_constante("pub(crate) const TEMOIN_PREMIER: &str = \"temoin_un\";"),
            Some(("TEMOIN_PREMIER".into(), "temoin_un".into()))
        );
        assert_eq!(
            declaration_de_constante("const TEMOIN_SECOND: &str = \"temoin_deux\";"),
            Some(("TEMOIN_SECOND".into(), "temoin_deux".into()))
        );
        for innocent in [
            "pub(crate) const TEMOIN_OCTETS: u64 = 4 * 1024 * 1024;", // pas un `&str`
            "    let cause = \"temoin_un\";",                         // pas une constante
            "pub(crate) const Temoin: &str = \"x\";",                 // pas un nom de constante
            "/// const TEMOIN_PREMIER: &str = \"temoin_un\";",        // de la prose
        ] {
            assert_eq!(declaration_de_constante(innocent), None, "faux positif : {innocent}");
        }

        // --- l'identifiant, mot ENTIER ---
        assert_eq!(positions_de_lidentifiant("a TEMOIN_PREMIER,", "TEMOIN_PREMIER"), vec![2]);
        assert!(
            positions_de_lidentifiant("TEMOIN_PREMIER_BIS", "TEMOIN_PREMIER").is_empty(),
            "un préfixe d'identifiant n'est PAS une citation"
        );
        assert!(positions_de_lidentifiant("X_TEMOIN_PREMIER", "TEMOIN_PREMIER").is_empty());

        // --- la valeur, entre guillemets, échappement compris ---
        assert_eq!(positions_de_la_valeur("Some(\"temoin_un\")", "temoin_un"), vec![6]);
        assert_eq!(
            positions_de_la_valeur("Some(\"{\\\"cause\\\":\\\"temoin_deux\\\"}\")", "temoin_deux").len(),
            1,
            "la valeur citée DANS une chaîne Rust imbriquée doit compter"
        );
        assert!(
            positions_de_la_valeur("// le temoin_un du détecteur", "temoin_un").is_empty(),
            "une valeur NON guillemetée n'est pas une citation"
        );

        // --- les régions ---
        let txt = "let causes = [\n  A,\n  B,\n];\nassert_eq!(x, A);\n";
        let regions = regions_entre_crochets(txt);
        assert_eq!(regions.len(), 1, "une région multi-lignes doit être vue comme UNE région");
        let (a, b) = regions[0];
        let dans_la_liste = positions_de_lidentifiant(txt, "A")[0];
        let hors_la_liste = *positions_de_lidentifiant(txt, "A").last().unwrap();
        assert!(a < dans_la_liste && dans_la_liste < b, "la citation de la liste doit tomber DANS la région");
        assert!(hors_la_liste > b, "la citation de l'assertion doit tomber HORS de la région");

        let u = regions_des_items_use("use crate::x::{\n    A,\n    B,\n};\nlet y = A;\n");
        assert_eq!(u.len(), 1, "un `use` multi-lignes est UNE région");
        assert!(u[0].1 > u[0].0 + 20, "la région `use` doit courir jusqu'à son `;`");
        assert!(
            regions_des_items_use("    let usage = 3;\n").is_empty(),
            "un identifiant qui COMMENCE par `use` n'ouvre pas un item `use`"
        );
    }

    // =============================================================================================
    // LA GARDE
    // =============================================================================================

    /// TOUTE CLÉ QUI NOMME UN TROU A UN TEST QUI LA NOMME, ELLE SEULE.
    ///
    /// MUTATION (exécutée le 2026-08-14) : retirer la seule citation spécifique de `RETARD_REQUETE`
    /// (`daemon/src/cold_store/tests.rs:2238`, l'assertion du correctif de `e19bf4d`) ⇒ cette garde
    /// rougit en la nommant EN PLUS des clés déjà accusées, et elle est la seule à rougir — le code
    /// compile et se comporte à l'identique, ce qui est précisément pourquoi seule une garde de SOURCE
    /// l'attrape.
    #[test]
    fn toute_cle_qui_nomme_un_trou_a_un_test_qui_la_nomme_seule() {
        let racine = racine();
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner n'a trouvé que {} source(s)", fichiers.len());
        let marques = fichiers_de_test(&fichiers);
        assert!(!marques.is_empty(), "précondition : aucun module de test FICHIER déclaré");

        // CE FICHIER-CI EST RETIRÉ DU CORPUS. Il vit sous `src/tests/`, donc chacune de ses lignes est du
        // texte de test : une clé citée ICI (ne serait-ce que dans un message d'échec) se compterait comme
        // sa propre garde. Le chemin est pris de `file!()`, jamais écrit à la main, et l'exclusion est
        // VÉRIFIÉE : si elle ne désigne plus un fichier balayé, la garde refuse de conclure.
        //
        // `P10.14-a` (résiduel) — CE QU'ELLE VAUT AUJOURD'HUI, MESURÉ LE 2026-08-15 PAR MUTATION.
        // Les trois lignes `if *f == moi { continue; }` retirées ⇒ le test passe QUAND MÊME. Elle est donc
        // **INERTE en l'état** : ce fichier ne cite aujourd'hui aucune clé en dur — ses messages d'échec
        // CONSTRUISENT les noms depuis le corpus au lieu de les écrire. Elle est gardée comme ASSURANCE et
        // non comme garde active : la première personne qui écrira un nom de clé littéral ici la rendra
        // porteuse sans y penser, et c'est justement le geste qu'on ne veut pas avoir à surveiller.
        //
        // CE QUE JE N'AI PAS PROUVÉ, ET JE LE DIS PLUTÔT QUE DE LAISSER CROIRE : qu'elle SAURAIT mordre.
        // Le démontrer demanderait de fabriquer une clé factice dépourvue de garde ailleurs puis de la
        // citer ici — un test du test, pour une branche que la mesure dit sans objet. Ce qui EST vérifié à
        // chaque exécution, en revanche, c'est sa PRÉCONDITION : l'`assert!` ci-dessous refuse de conclure
        // si `file!()` cesse de désigner un fichier réellement balayé. Une assurance qui pointerait à côté
        // serait pire que pas d'assurance du tout.
        //
        // Contrôlé au passage, hors dépôt, parce que je le soupçonnais d'être la cause de l'inertie : dans
        // un fichier tiré par `include!`, `file!()` rend bien le chemin du fichier INCLUS et non celui de
        // l'incluant. Ce n'est donc PAS l'explication — l'inertie vient de l'absence de citations, point.
        let moi = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file!());
        assert!(
            fichiers.iter().any(|f| *f == moi),
            "ANTI-AUTO-CRÉDIT : `file!()` rend `{}`, qui n'est pas dans les sources balayées. L'exclusion \
             de ce fichier ne s'applique donc plus et la garde se créditerait elle-même.",
            moi.display()
        );

        // ---- 1. LE PÉRIMÈTRE, DÉRIVÉ : qui construit une étiquette `cause` ? ----
        let mut modules_de_serie: Vec<(PathBuf, Vec<(usize, String)>)> = Vec::new();
        let mut production_du_demon: Vec<(usize, String)> = Vec::new();
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{} illisible : {e}", f.display()));
            let prod = texte_de_production(f, &src);
            if prod.iter().any(|(_, l)| l.contains(MARQUE_DU_MODULE_DE_SERIE)) {
                modules_de_serie.push((f.clone(), prod.clone()));
            }
            production_du_demon.extend(prod);
        }
        assert!(
            modules_de_serie.len() >= 2,
            "ANTI-FAUX-VERT : {} module(s) de série trouvé(s) via `{MARQUE_DU_MODULE_DE_SERIE}`. Soit la \
             voie d'étiquetage a changé de forme, soit ce test ne regarde plus le bon arbre — dans les \
             deux cas il ne garde plus rien.",
            modules_de_serie.len()
        );

        // ---- 2. LES NOMS DE SÉRIE, DÉRIVÉS : ce que le code utilise comme `nom:` d'un `Point` ----
        let mut noms_de_serie: BTreeSet<String> = BTreeSet::new();
        for (_, l) in &production_du_demon {
            let mut base = 0usize;
            while let Some(rel) = l[base..].find("nom: ") {
                let debut_du_champ = base + rel;
                base = debut_du_champ + "nom: ".len();
                // `nom:` doit être le CHAMP, pas la fin d'un autre identifiant (`prenom:`, `x_nom:`) :
                // sur-capturer ici retirerait SILENCIEUSEMENT une clé du jeu gardé.
                if debut_du_champ > 0 && !frontiere(l, debut_du_champ - 1) {
                    continue;
                }
                let p = base;
                let fin = l[p..]
                    .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                    .map_or(l.len(), |r| p + r);
                if fin > p {
                    noms_de_serie.insert(l[p..fin].to_string());
                }
            }
        }

        // ---- 3. LES CLÉS QUI NOMMENT UN TROU : le COMPLÉMENT, jamais une liste ----
        let mut cles: BTreeMap<String, (String, String)> = BTreeMap::new(); // nom -> (valeur, où)
        let mut constantes_du_perimetre = 0usize;
        for (f, prod) in &modules_de_serie {
            let court = f.strip_prefix(&racine).unwrap_or(f).display().to_string();
            for (n, l) in prod {
                let Some((nom, valeur)) = declaration_de_constante(l) else { continue };
                constantes_du_perimetre += 1;
                if noms_de_serie.contains(&nom) {
                    continue; // un nom de série n'est pas une clé d'étiquette
                }
                cles.insert(nom, (valeur, format!("{court}:{n}")));
            }
        }
        assert!(
            constantes_du_perimetre >= 20 && noms_de_serie.len() >= 8 && cles.len() >= 10,
            "ANTI-FAUX-VERT : {constantes_du_perimetre} constante(s) dans le périmètre, \
             {} nom(s) de série, {} clé(s) retenue(s). Une garde qui n'a presque rien examiné est verte \
             pour la mauvaise raison : elle REFUSE de conclure.",
            noms_de_serie.len(),
            cles.len()
        );

        // ---- 4. LES CITATIONS DE TEST, classées ----
        let mut specifiques: BTreeMap<&str, Vec<String>> = cles.keys().map(|k| (k.as_str(), Vec::new())).collect();
        let mut generiques: BTreeMap<&str, Vec<String>> = cles.keys().map(|k| (k.as_str(), Vec::new())).collect();
        let mut lignes_de_test = 0usize;
        for f in &fichiers {
            if *f == moi {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{} illisible : {e}", f.display()));
            let lignes = texte_de_test(f, &src, &marques);
            if lignes.is_empty() {
                continue;
            }
            lignes_de_test += lignes.len();
            // Le texte APLATI du fichier : les régions d'énumération traversent les lignes.
            let mut plat = String::new();
            let mut depart: Vec<(usize, usize)> = Vec::new(); // (offset, numéro de ligne)
            for (n, l) in &lignes {
                depart.push((plat.len(), *n));
                plat.push_str(l);
                plat.push('\n');
            }
            let mut trouvees: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
            for (nom, (valeur, _)) in &cles {
                let mut p = positions_de_lidentifiant(&plat, nom);
                p.extend(positions_de_la_valeur(&plat, valeur));
                if !p.is_empty() {
                    p.sort_unstable();
                    p.dedup();
                    trouvees.insert(nom.as_str(), p);
                }
            }
            if trouvees.is_empty() {
                continue;
            }
            let mut aveugles: Vec<(usize, usize)> = regions_des_items_use(&plat);
            for (a, b) in regions_entre_crochets(&plat) {
                let combien = trouvees.values().filter(|ps| ps.iter().any(|p| a < *p && *p < b)).count();
                if combien >= 2 {
                    aveugles.push((a, b)); // une région qui contient DEUX clés ne distingue ni l'une ni l'autre
                }
            }
            let court = f.strip_prefix(&racine).unwrap_or(f).display().to_string();
            for (nom, positions) in trouvees {
                for p in positions {
                    let n = depart.partition_point(|(o, _)| *o <= p).saturating_sub(1);
                    let ou = format!("{court}:{}", depart[n].1);
                    if aveugles.iter().any(|(a, b)| *a <= p && p <= *b) {
                        generiques.get_mut(nom).expect("clé connue").push(ou);
                    } else {
                        specifiques.get_mut(nom).expect("clé connue").push(ou);
                    }
                }
            }
        }
        let total_spec: usize = specifiques.values().map(Vec::len).sum();
        let total_gen: usize = generiques.values().map(Vec::len).sum();
        assert!(
            lignes_de_test >= 10_000 && total_spec >= 20,
            "ANTI-FAUX-VERT : {lignes_de_test} ligne(s) de test balayée(s), {total_spec} citation(s) \
             spécifique(s). Le lecteur a raté le corpus."
        );
        assert!(
            total_gen >= 2,
            "ANTI-FAUX-VERT : AUCUNE citation générique reconnue ({total_gen}) alors que le dépôt en porte \
             (les imports, au minimum). Le classement ne distingue donc plus rien et TOUT passerait pour \
             spécifique — la garde serait verte en ne gardant rien."
        );

        // ---- 5. LE VERDICT ----
        let sans_garde: Vec<String> = cles
            .iter()
            .filter(|(nom, _)| specifiques[nom.as_str()].is_empty())
            .map(|(nom, (valeur, ou))| {
                format!(
                    "{nom} = {valeur:?} (déclarée {ou}) — {} citation(s), TOUTES génériques : {}",
                    generiques[nom.as_str()].len(),
                    if generiques[nom.as_str()].is_empty() {
                        "aucune".to_string()
                    } else {
                        generiques[nom.as_str()].join(", ")
                    }
                )
            })
            .collect();
        println!(
            "[clés de cause] {} module(s) de série, {constantes_du_perimetre} constante(s), {} nom(s) de \
             série écarté(s), {} clé(s) gardée(s) ; {lignes_de_test} lignes de test balayées, \
             {total_spec} citation(s) spécifique(s) et {total_gen} générique(s)",
            modules_de_serie.len(),
            noms_de_serie.len(),
            cles.len()
        );
        // LE DÉTAIL PAR CLÉ est imprimé MÊME QUAND LA GARDE PASSE : c'est lui qui rend le comptage
        // relisible, et c'est un comptage de cette forme qui a trouvé le trou de `e19bf4d`.
        for (nom, (valeur, _)) in &cles {
            println!(
                "[clés de cause]   {nom:<26} {valeur:<24} spécifiques={:<3} génériques={}",
                specifiques[nom.as_str()].len(),
                generiques[nom.as_str()].len()
            );
        }
        assert!(
            sans_garde.is_empty(),
            "{} clé(s) qui NOMMENT UN TROU sans qu'aucun test ne les nomme SEULES. Une citation dans un \
             `use` ou dans une énumération de causes est satisfaite à l'identique que la cause soit \
             atteignable ou morte : elle ne garde rien. Ce sont des promesses en PROSE — c'est le mode de \
             panne de `d81897f` et de `e19bf4d`.\n  {}",
            sans_garde.len(),
            sans_garde.join("\n  ")
        );
    }
}
