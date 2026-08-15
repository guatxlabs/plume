// =================================================================================================
// `P8.9-b` — UNE LIGNE QUI SE DÉCLARE `*(clé neuve)*` DOIT ÊTRE LA SEULE DÉFINITION DE SA CLÉ
//
// CE QUI S'EST PASSÉ, LE 2026-08-15. J'ai ouvert la clé `P4.4-j` pour un constat sur la porte de
// déploiement. Elle était PRISE depuis le 08-11 — elle désignait le banc de tests qui exécutait
// `curl https://get.k3s.io | sh` sur sa propre machine. Deux constats sans aucun rapport sous une seule
// clé, et je m'en suis aperçu APRÈS avoir commité et poussé. Le schéma de clés promet qu'une clé se suit
// *du rapport jusqu'au commit* ; la promesse était rompue dès la première citation.
//
// EN CHERCHANT LA MIENNE, J'EN AI TROUVÉ UNE PLUS VIEILLE : `P8.5-a` était la tête de DEUX lignes
// décrivant LE MÊME constat, dont une copie périmée qui disait encore « correctif dans l'arbre, non
// commité » alors qu'il l'était depuis le 08-10 — c'est-à-dire exactement le défaut que `P8.9-a` avait
// nommé cinq jours plus tôt, DANS LE MÊME DOCUMENT. Deux occurrences, deux causes différentes, aucune
// visible dans un diff : une collision ne se voit qu'en regardant TOUT le document.
//
// POURQUOI CE N'EST PAS LA GARDE « UNE CLÉ = UNE LIGNE », ET C'EST LE POINT IMPORTANT. C'est la règle que
// j'ai écrite en premier, et LA MESURE L'A RÉFUTÉE : elle accusait `P4.1-p`, `P10.2-a`, `P10.2-c`,
// `P10.2-d`, `P4.4-a` et `P4.5-b` — six entrées parfaitement légitimes, parce que ce document a une
// convention établie où une clé nomme un THÈME et plusieurs lignes le détaillent. Même faute que
// `P10.14-a`, dont ma règle de départ attrapait 0 constat sur 113 : une règle inventée par moi contre une
// règle que le document se donne à lui-même.
//
// LA RÈGLE RETENUE EST CELLE DU DOCUMENT. `*(clé neuve)*` n'est pas une décoration : c'est une
// AFFIRMATION que l'auteur écrit noir sur blanc — « cette clé n'existait pas ». Elle est donc vérifiable
// mécaniquement, et une contradiction est une contradiction du document AVEC LUI-MÊME, pas avec mon
// opinion sur les conventions. Mesuré à l'écriture : 25 lignes se déclarent `*(clé neuve)*`, **0** en
// contradiction une fois les deux collisions corrigées — et la règle les aurait attrapées TOUTES LES DEUX.
//
// CE QU'ELLE NE GARDE PAS, ÉCRIT POUR ÊTRE OPPOSABLE : une clé réutilisée SANS se déclarer `*(clé
// neuve)*` passe. C'est assumé — c'est le prix d'une règle qui ne produit aucun faux positif sur une
// convention légitime. Ce qui est gardé, c'est le cas où le document se contredit lui-même, et c'est
// exactement celui qui s'est produit deux fois.
//
// CE QUE CETTE GARDE IMPOSE À QUI TRAVAILLE ICI, et qui n'existait pas avant elle : c'est le PREMIER test
// du dépôt qui lit un fichier de `docs/`. **Éditer `docs/ROADMAP.md` pendant qu'une suite tourne peut donc
// la faire vaciller** — la suite froide dure ~30 min, et consigner un constat pendant ce temps était
// jusqu'ici sans danger. Ça ne l'est plus. C'est le prix accepté pour que l'index soit tenu par le
// compilateur plutôt que par la vigilance ; il est écrit ici parce qu'une contrainte qu'on découvre en la
// heurtant est une contrainte mal posée.
#[cfg(test)]
mod cles_de_roadmap_uniques_tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// LE DOCUMENT GARDÉ. `docs/ROADMAP.md` vit à côté du crate, pas dedans.
    fn chemin_de_la_roadmap() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/ROADMAP.md")
    }

    /// UNE CLÉ : `P<chiffres>(.<chiffres>)*-<une lettre minuscule>`. Écrit à la main plutôt qu'en regex —
    /// la forme est simple, et une dépendance de moins dans une garde est une garde de plus qui tourne.
    fn est_une_cle(s: &str) -> bool {
        let Some(reste) = s.strip_prefix('P') else { return false };
        let Some((nombres, lettre)) = reste.rsplit_once('-') else { return false };
        let mut car = lettre.chars();
        if !matches!(car.next(), Some(c) if c.is_ascii_lowercase()) || car.next().is_some() {
            return false;
        }
        !nombres.is_empty()
            && nombres.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    }

    /// LA CLÉ NUE d'une cellule : on retire le gras et les annotations `*(...)*` (`*(clé neuve)*`,
    /// `*(reste)*`, …). Ce qui reste doit être la clé et rien d'autre.
    fn cle_nue(cellule: &str) -> String {
        let mut sortie = String::new();
        let mut dans_annotation = false;
        let octets: Vec<char> = cellule.chars().collect();
        let mut i = 0;
        while i < octets.len() {
            if !dans_annotation && octets[i] == '*' && octets.get(i + 1) == Some(&'(') {
                dans_annotation = true;
                i += 2;
                continue;
            }
            if dans_annotation {
                if octets[i] == ')' && octets.get(i + 1) == Some(&'*') {
                    dans_annotation = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if octets[i] != '*' {
                sortie.push(octets[i]);
            }
            i += 1;
        }
        sortie.trim().to_string()
    }

    /// UNE LIGNE DE DÉFINITION : une ligne de tableau dont la PREMIÈRE cellule est une clé. C'est ce
    /// critère — la première cellule — qui inclut les entrées anciennes (`| P3.6-a | ... |`, sans gras)
    /// et exclut les listes ordonnées, dont la première cellule est un rang (`| 12 | **P3.2-a** | ...`).
    /// Un premier jet qui exigeait le gras ne voyait que 40 clés sur 87 : un périmètre partiel qui se
    /// serait présenté comme complet.
    fn definitions(texte: &str) -> BTreeMap<String, Vec<(usize, bool, String)>> {
        let mut sortie: BTreeMap<String, Vec<(usize, bool, String)>> = BTreeMap::new();
        for (n, ligne) in texte.lines().enumerate() {
            if !ligne.starts_with('|') {
                continue;
            }
            let cellules: Vec<&str> = ligne.split('|').collect();
            if cellules.len() < 3 {
                continue;
            }
            let brute = cellules[1].trim();
            let cle = cle_nue(brute);
            if est_une_cle(&cle) {
                let apercu: String = ligne.chars().take(120).collect();
                sortie.entry(cle).or_default().push((n + 1, brute.contains("clé neuve"), apercu));
            }
        }
        sortie
    }

    /// `P8.9-b` — LA GARDE.
    ///
    /// TROIS REFUS DE CONCLURE, parce qu'un contrôle qui ne trouve rien doit dire « je n'ai pas mesuré »
    /// et jamais « ça passe » :
    ///   1. document illisible -> on NOMME le chemin cherché ;
    ///   2. ZÉRO ligne de définition -> l'analyseur est cassé (format du tableau changé), pas le
    ///      document propre ;
    ///   3. ZÉRO ligne `*(clé neuve)*` -> le marqueur a disparu du vocabulaire, donc la règle ne garde
    ///      plus rien. Un vert dans ce cas serait le pire des deux mondes.
    ///
    /// MUTATION : renommer une clé existante en une clé déjà prise, avec `*(clé neuve)*` ⇒ le test
    /// rougit en nommant la clé, les DEUX numéros de ligne et le début des deux lignes.
    #[test]
    fn une_ligne_qui_se_dit_cle_neuve_est_la_seule_definition_de_sa_cle() {
        let chemin = chemin_de_la_roadmap();
        let texte = std::fs::read_to_string(&chemin).unwrap_or_else(|e| {
            panic!(
                "docs/ROADMAP.md ILLISIBLE ({}) : {e}\n  Cette garde ne peut pas conclure sans le \
                 document. Un test vert ici voudrait dire « aucune collision » alors qu'il n'a rien lu.",
                chemin.display()
            )
        });

        let defs = definitions(&texte);
        let total: usize = defs.values().map(Vec::len).sum();
        assert!(
            total >= 50,
            "PÉRIMÈTRE INVRAISEMBLABLE : seulement {total} ligne(s) de définition pour {} clé(s) dans \
             {}. Le format du tableau a dû changer et l'analyseur ne voit plus les entrées — un verdict \
             « aucune collision » serait rendu sur un document que ce test ne lit plus. (Mesuré le \
             2026-08-15 : 100 lignes pour 87 clés.)",
            defs.len(),
            chemin.display()
        );

        let neuves: Vec<(&String, usize)> = defs
            .iter()
            .flat_map(|(k, v)| v.iter().filter(|(_, n, _)| *n).map(move |(l, _, _)| (k, *l)))
            .collect();
        assert!(
            !neuves.is_empty(),
            "AUCUNE ligne ne se déclare `*(clé neuve)*` dans {}. Le marqueur a disparu du vocabulaire du \
             document : cette garde ne garde plus RIEN, et son vert ne veut plus rien dire. (Mesuré le \
             2026-08-15 : 25 lignes le déclaraient.)",
            chemin.display()
        );

        let mut fautes = Vec::new();
        for (cle, ligne_neuve) in &neuves {
            let autres: Vec<&(usize, bool, String)> =
                defs[*cle].iter().filter(|(l, ..)| l != ligne_neuve).collect();
            if autres.is_empty() {
                continue;
            }
            let mut bloc = format!(
                "  * `{cle}` se déclare `*(clé neuve)*` en ligne {ligne_neuve}, mais la clé est DÉJÀ \
                 définie {} fois :\n",
                autres.len()
            );
            for (l, _, apercu) in autres {
                bloc.push_str(&format!("      ligne {l} : {apercu}\n"));
            }
            fautes.push(bloc);
        }

        assert!(
            fautes.is_empty(),
            "LE DOCUMENT SE CONTREDIT LUI-MÊME : une ligne affirme ouvrir une clé neuve alors que cette \
             clé désigne déjà un autre constat. Le schéma promet qu'une clé se suit DU RAPPORT JUSQU'AU \
             COMMIT — deux constats sous une clé rompent la promesse dès la première citation, et la \
             collision ne se voit dans AUCUN diff.\n{}\n  {} clé(s) examinée(s), {} ligne(s) de \
             définition, {} ligne(s) se déclarant neuves.",
            fautes.join(""),
            defs.len(),
            total,
            neuves.len()
        );
    }

    /// L'ANALYSEUR SE VALIDE AVANT QU'ON LE CROIE — sur des cas fabriqués, y compris ceux que le document
    /// réel ne contient pas aujourd'hui. Sans ce test, `est_une_cle` pourrait ne rien reconnaître et la
    /// garde ci-dessus passerait au vert en n'ayant examiné aucune ligne.
    #[test]
    fn l_analyseur_de_cles_reconnait_les_deux_formes_et_refuse_le_reste() {
        for bon in ["P3.6-a", "P10.15-a", "P4.4-k", "P8-a", "P10.2.3-z"] {
            assert!(est_une_cle(bon), "`{bon}` devrait être reconnue comme une clé");
        }
        // TÉMOIN NÉGATIF : ce que la garde ne doit JAMAIS prendre pour une clé — sinon les rangs des
        // listes ordonnées et les en-têtes de colonne entreraient dans le périmètre et produiraient des
        // « collisions » qui n'existent pas (faute déjà commise le 2026-08-11 sur ce même document).
        for mauvais in ["12", "X", "Date", "`plume`", "---", "P10.15", "P10.15-ab", "P-a", "10.15-a", ""] {
            assert!(!est_une_cle(mauvais), "`{mauvais}` NE devrait PAS être prise pour une clé");
        }
        // Le décapage des annotations : la clé nue est la même, quelle que soit la décoration.
        for (brute, attendu) in [
            ("**P4.4-k** *(clé neuve)*", "P4.4-k"),
            ("P3.6-a", "P3.6-a"),
            ("**P10.5-a** *(reste)*", "P10.5-a"),
            ("**P8.5-a** *(clé neuve → MA PRÉMISSE RÉFUTÉE)*", "P8.5-a"),
        ] {
            assert_eq!(cle_nue(brute), attendu, "décapage incorrect de `{brute}`");
        }
    }
}
