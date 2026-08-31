// LE CANAL DU REFUS DE CONCLURE (`P11.23-b`) — un test qui SAIT n'avoir rien mesuré le DIT à
// celui qui décide, sans jamais lui présenter la note.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// LE DÉFAUT, MESURÉ SUR CET ARBRE LE 2026-08-31
// ─────────────────────────────────────────────────────────────────────────────────────────────
// QUATORZE chemins de `daemon/src/tests/` rendent la main sans exercer l'assertion qui justifie
// leur test — levier de configuration éteint, `/proc` illisible, plate-forme non-Linux, clé
// SQLCipher posée dans l'environnement. Ils sortent en 0. Le portail de déploiement
// (`bootstrap/14-build-images.sh` du dépôt des manifestes) et les jobs `test`/`cold-tier` de
// `ci.yml` ne lisent que ce 0 : un test qui ne peut pas voir se présente donc comme un test qui a
// vu. C'est la famille de défaut que toute la batterie de gardes poursuit — un composant qui sait
// son résultat incomplet et le présente comme complet — logée dans l'instrument qui la poursuit.
//
// ET L'AVEU N'ALLAIT PAS PLUS LOIN QUE LE PROCESSUS. Sur les quatorze, CINQ imprimaient leur refus
// et NEUF ne disaient rien du tout. Les cinq ne servaient à rien de plus que les neuf : MESURÉ sur
// une caisse d'essai jetable, `cargo test` nu rend ZÉRO occurrence d'un `eprintln!` émis par un
// test qui RÉUSSIT (3 occurrences sous `--nocapture`, 3 sous `--show-output`). Ce n'est pas cargo
// qui trie : c'est `libtest`, qui détourne les sorties du fil de chaque test et ne les rend que
// pour les tests qui ÉCHOUENT. Un aveu imprimé depuis un test vert part dans le vide.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QUE CE CANAL EST, ET CE QU'IL N'EST PAS
// ─────────────────────────────────────────────────────────────────────────────────────────────
// IL NE FAIT PAS ÉCHOUER. Un conteneur durci sans `/proc`, une machine non-Linux, une suite jouée
// levier éteint : aucun geste ne pourrait refermer un rouge posé là. Ce serait une RANÇON — une
// intégration rouge que la remédiation nommée ne peut pas éteindre. Le test reste VERT ; ce qui
// change, c'est qu'il n'est plus MUET pour celui qui lit le verdict.
//
// IL EST INERTE PAR DÉFAUT. Sans `PLUME_JOURNAL_DES_REFUS` dans l'environnement, cette fonction
// n'ouvre rien, ne crée rien, n'écrit rien : la suite est exactement celle d'avant. Le canal
// s'arme du côté de CELUI QUI DÉCIDE (un pas de CI, le portail), jamais du côté du test.
//
// IL SORT DU FLOT DE `libtest`. Une ligne par refus dans un fichier que l'appelant nomme, et que
// l'appelant relit APRÈS la suite. Chaque ligne EST un refus, par construction : le lecteur n'a
// aucun motif à apparier, donc aucun mot trop générique ne peut le rendre vert à tort.
//
// POURQUOI PAS `--nocapture`, MESURÉ ET NON SUPPOSÉ : il révèle bien l'aveu, mais il le noie dans
// la sortie de toute la suite, et c'est ce volume-là qui fait que personne ne lit le journal du
// portail. Le compte exact est reporté par le lot qui a posé ce fichier. Même objection pour
// `--show-output`, à quoi s'ajoute que ni l'un ni l'autre ne distingue un aveu d'une impression
// ordinaire : il faudrait y chercher un MOT, et une garde qui cherche un mot est verte le jour où
// le mot est trop générique.
//
// POURQUOI PAS UNE ÉCRITURE NUE SUR LE DESCRIPTEUR 2 (`File::from_raw_fd(2)`, sans dépendance) :
// elle échappe bien à `libtest` — MESURÉ, l'aveu ressort d'un `cargo test` nu — mais elle
// s'entrelace avec la sortie de `libtest` elle-même. Le relevé montre l'aveu SOUDÉ à la ligne de
// progression (`.AVEU-…`) : ce canal-là peut couper en deux la ligne `test result: ok. N passed`
// que la CI somme pour tenir le compte de tests. On ne répare pas un instrument en abîmant l'autre.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// CE QUE CE FICHIER NE TIENT PAS
// ─────────────────────────────────────────────────────────────────────────────────────────────
//   · Il ne peut pas distinguer, du côté du LECTEUR, « aucun test n'a refusé » de « l'écrivain est
//     cassé » : les deux rendent un fichier absent. Ce qui tient cette moitié-là est la garde
//     `check_a_test_that_declines_to_conclude_says_so.py`, qui lit dans CE fichier le nom de la
//     variable et la forme de l'écriture, et vérifie que chaque chemin de refus l'emprunte.
//   · Il ne voit pas un refus écrit SANS `return` — des assertions enfermées dans une branche dont
//     la jumelle est vide. La garde tient la forme `return`, celle des quatorze sites mesurés.
//   · L'atomicité entre fils repose sur `O_APPEND` + UN seul `write` : la cause est donc tronquée à
//     800 caractères et ramenée à une seule ligne, pour que deux refus simultanés ne s'entrelacent
//     pas au milieu d'une ligne.
pub(crate) mod canal_de_refus {
    use std::io::Write;

    /// LA VARIABLE QUI ARME LE CANAL. Elle est lue ici et NULLE PART AILLEURS dans le produit ; la
    /// garde la LIT dans ce fichier plutôt que de la recopier — deux copies divergent, et c'est
    /// exactement le défaut que ce canal ferme.
    pub(crate) const VARIABLE_DU_CANAL: &str = "PLUME_JOURNAL_DES_REFUS";

    /// Une cause tient sur UNE ligne et ne dépasse pas ce nombre de caractères : au-delà, deux
    /// écritures concurrentes cesseraient d'être un `write` chacune, et pourraient s'entrelacer.
    const CAUSE_MAX: usize = 800;

    fn sur_une_seule_ligne(cause: &str) -> String {
        let plat: String = cause
            .chars()
            .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
            .collect();
        let mut serre = String::with_capacity(plat.len());
        let mut espace = false;
        for c in plat.trim().chars() {
            if c == ' ' {
                if !espace {
                    serre.push(' ');
                }
                espace = true;
            } else {
                serre.push(c);
                espace = false;
            }
        }
        if serre.chars().count() > CAUSE_MAX {
            serre = serre.chars().take(CAUSE_MAX - 1).collect::<String>() + "…";
        }
        serre
    }

    /// LE SEUL CHEMIN PAR LEQUEL UN TEST A LE DROIT DE RENDRE LA MAIN SANS CONCLURE.
    ///
    /// `module` est `module_path!()`, évalué AU SITE D'APPEL — il n'y a donc pas de nom de module à
    /// tenir à jour. `test` est le nom de la fonction de test, et la garde REFUSE qu'il diverge du
    /// nom réel : un aveu qui nomme le voisin envoie chercher au mauvais endroit.
    pub(crate) fn refuser_de_conclure(module: &str, test: &str, cause: &str) {
        let site = format!("{module}::{test}");
        let cause = sur_une_seule_ligne(cause);

        // Pour l'humain qui joue la suite à la main sous `--nocapture` : gratuit, et ce n'est PAS
        // le canal — `libtest` l'avale pour un test qui réussit (mesuré).
        eprintln!("[REFUS DE CONCLURE] {site} — {cause}");

        // INERTE PAR DÉFAUT : sans la variable, on sort avant d'avoir touché au système de fichiers.
        let Some(chemin) = std::env::var_os(VARIABLE_DU_CANAL) else {
            return;
        };
        if chemin.is_empty() {
            return;
        }

        let ligne = format!("{site}\t{cause}\n");
        let ecrit = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&chemin)
            .and_then(|mut f| f.write_all(ligne.as_bytes()));

        // ARMÉ MAIS INÉCRIVABLE : le refus serait PERDU, c'est-à-dire le défaut d'origine remis en
        // place par le remède. Ce n'est pas une rançon : l'appelant a CHOISI ce chemin et le
        // corrige d'un geste. Le message dit que c'est le CANAL qui est en cause, pas la propriété.
        if let Err(e) = ecrit {
            panic!(
                "[CANAL DE REFUS INÉCRIVABLE] `{VARIABLE_DU_CANAL}` désigne « {} » et l'écriture a \
                 échoué ({e}). Le refus « {site} » serait perdu en silence — exactement ce que ce \
                 canal existe pour empêcher. Ce n'est PAS une propriété du produit qui est violée : \
                 c'est le canal qui est mal armé. Désigner un chemin inscriptible, ou retirer la \
                 variable (le canal redevient inerte et la suite est identique).",
                std::path::Path::new(&chemin).display()
            );
        }
    }
}
