// =================================================================================================
// `P10.18-a` — UNE PHRASE POSÉE POUR CORRIGER UN COMMENTAIRE FAUX PORTAIT UN CHIFFRE INVÉRIFIABLE
//
// CE QUI S'EST PASSÉ. Le commentaire de `handlers::dashboards::panel_data_masked_live` annonçait un
// mécanisme que la fonction n'a pas (une prise de permit). Le commit du 2026-08-28 l'a corrigé — la
// fonction ne prend AUCUN permit, c'est vrai — mais la correction a adossé sa phrase à un COMPTE des
// acquisitions du module. MESURÉ LE 2026-08-30, deux fois : ce module porte DEUX appels réels
// (`refresh_sem.try_acquire_owned()` et `st.refresh_sem.clone().try_acquire_owned()`) ; les autres
// occurrences du fichier sont de la PROSE — des commentaires qui parlent du mécanisme. Le chiffre écrit
// comptait donc des occurrences de TEXTE. À l'échelle de `daemon/src` hors tests, le même balayage rend
// ONZE appels réels sur HUIT fichiers (le 2026-08-30) : le nombre écrit ne désignait ni le module, ni
// la caisse.
//
// POURQUOI ON NE LE REMPLACE PAS PAR LE BON CHIFFRE. Un compte gravé dans un commentaire redevient faux
// au lot suivant, en silence, et c'est exactement la faute que ce dépôt paye en boucle. Ce qu'on écrit
// à la place est une PROPRIÉTÉ — « aucune acquisition de permis de ce module ne se trouve dans le corps
// de cette fonction » — dont la VIOLATION ÉCHOUE ici au lieu de passer.
//
// L'INSTRUMENT EST VALIDÉ SUR DES CORPUS FABRIQUÉS, JAMAIS SUR L'ARBRE. Compter des appels dans du Rust
// exige de distinguer un appel d'une mention ; un compteur naïf (`grep`) rend 7 là où il y en a 2. Le
// dépouilleur est donc éprouvé dans les DEUX sens sur des textes écrits DANS ce fichier :
//   * un corpus POSITIF qui mêle appels réels, mentions en commentaire de ligne, en commentaire de
//     bloc, dans un littéral de chaîne MULTILIGNE et dans un littéral de caractère -> le compte attendu
//     est celui des seuls appels, ET LEURS LIGNES sont vérifiées (c'est la faute qui a été commise en
//     écrivant cet instrument : blanchir un littéral multiligne en avalant ses retours à la ligne
//     décale tous les numéros de ligne suivants, ici de sept — un rapport d'erreur qui nomme la
//     mauvaise ligne est pire qu'aucun rapport) ;
//   * un corpus NÉGATIF entièrement en prose -> zéro.
//   * un corpus de MUTATION — une fonction fabriquée qui prend un permit DANS son corps -> le verdict
//     doit accuser, sans quoi la garde serait verte par construction.
//
// CE QUE CE TÉMOIN NE TIENT PAS, DIT SANS L'ADOUCIR :
//   * il ne garde PAS que les acquisitions du module restent nombreuses. Supprimer un `try_acquire`
//     ailleurs dans `dashboards.rs` le laisse VERT. Un `exiger(compte > 0)` sur l'arbre le rendrait
//     sensible — au prix d'une rançon : il rougirait le jour où le bornage déménagerait légitimement
//     dans une fonction partagée. Le compromis est pris dans ce sens-là, et il est écrit.
//   * il ne dit RIEN de la concurrence réelle de ce chemin. Que la fonction ne prenne pas de permit est
//     une propriété de SOURCE ; ce que ça coûte est une question d'exécution, et elle reste ouverte
//     (cf. le commentaire de la fonction : la seule borne restante est le pool `spawn_blocking`).
//   * il porte sur UN fichier. La propriété « ce chemin n'acquiert rien » serait fausse si le corps
//     appelait un helper d'un AUTRE module qui, lui, acquiert. Rien ici ne l'interdit.
// =================================================================================================

mod chemin_masque_sans_permis {
    use std::path::PathBuf;

    fn source_du_module_dashboards() -> String {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/dashboards.rs");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("INSTRUMENT : {} illisible : {e}", p.display()))
    }

    /// Rend `src` privé de tout ce qui n'engage RIEN : commentaires de ligne, commentaires de bloc
    /// (imbriqués, comme Rust les accepte), littéraux de chaîne (bruts compris) et de caractère. Chaque
    /// octet retiré est remplacé par une espace, SAUF les retours à la ligne, qui sont conservés : la
    /// position en lignes du code restant doit rester celle du fichier d'origine, sans quoi un verdict
    /// qui nomme une ligne nomme la mauvaise.
    ///
    /// UN `'` N'EST PAS TOUJOURS UN LITTÉRAL : `'static` est une durée de vie. On n'ouvre donc un
    /// littéral de caractère que sur les deux formes qui se referment (`'x'` et `'\x'`) ; tout le reste
    /// est laissé au code. L'inverse — avaler `'static ...` jusqu'au `'` suivant — masquerait du code.
    fn blanchir(src: &str) -> String {
        let o: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0usize;
        let blancs = |out: &mut String, t: &[char]| {
            for c in t {
                out.push(if *c == '\n' { '\n' } else { ' ' });
            }
        };
        while i < o.len() {
            let c = o[i];
            // chaîne brute r"…" / r#"…"# — avant la chaîne ordinaire (le `r` la précède).
            if c == 'r' && (i == 0 || !(o[i - 1].is_alphanumeric() || o[i - 1] == '_')) {
                let mut d = 0usize;
                let mut j = i + 1;
                while j < o.len() && o[j] == '#' {
                    d += 1;
                    j += 1;
                }
                if j < o.len() && o[j] == '"' {
                    j += 1;
                    while j < o.len() {
                        if o[j] == '"' && o[j + 1..].iter().take(d).filter(|&&x| x == '#').count() == d {
                            j += 1 + d;
                            break;
                        }
                        j += 1;
                    }
                    let fin = j.min(o.len());
                    blancs(&mut out, &o[i..fin]);
                    i = fin;
                    continue;
                }
            }
            if c == '/' && i + 1 < o.len() && o[i + 1] == '/' {
                let mut j = i;
                while j < o.len() && o[j] != '\n' {
                    j += 1;
                }
                blancs(&mut out, &o[i..j]);
                i = j;
                continue;
            }
            if c == '/' && i + 1 < o.len() && o[i + 1] == '*' {
                let mut prof = 1usize;
                let mut j = i + 2;
                while j < o.len() && prof > 0 {
                    if o[j] == '/' && j + 1 < o.len() && o[j + 1] == '*' {
                        prof += 1;
                        j += 2;
                    } else if o[j] == '*' && j + 1 < o.len() && o[j + 1] == '/' {
                        prof -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                let fin = j.min(o.len());
                blancs(&mut out, &o[i..fin]);
                i = fin;
                continue;
            }
            if c == '"' {
                let mut j = i + 1;
                while j < o.len() {
                    if o[j] == '\\' {
                        j += 2;
                        continue;
                    }
                    if o[j] == '"' {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                let fin = j.min(o.len());
                blancs(&mut out, &o[i..fin]);
                i = fin;
                continue;
            }
            if c == '\'' {
                // `'x'` (i+2) ou `'\x'` (i+3) ; sinon c'est une durée de vie -> on ne touche à rien.
                let ferme = (i + 2 < o.len() && o[i + 2] == '\'').then_some(i + 3).or_else(|| {
                    (i + 1 < o.len() && o[i + 1] == '\\' && i + 3 < o.len() && o[i + 3] == '\'').then_some(i + 4)
                });
                if let Some(fin) = ferme {
                    let fin = fin.min(o.len());
                    blancs(&mut out, &o[i..fin]);
                    i = fin;
                    continue;
                }
            }
            out.push(c);
            i += 1;
        }
        out
    }

    /// Les positions (octet, ligne 1-indexée) des APPELS de permis dans un texte DÉJÀ blanchi : le nom
    /// `try_acquire…` suivi — modulo espaces — d'une parenthèse ouvrante. Une mention qui n'appelle pas
    /// (`« le try_acquire du module »`) n'en est pas un ; c'est toute la différence que `grep` ne fait
    /// pas.
    fn appels_de_permis(blanchi: &str) -> Vec<(usize, usize)> {
        let b = blanchi.as_bytes();
        let mut v = Vec::new();
        let mut d = 0usize;
        while let Some(rel) = blanchi[d..].find("try_acquire") {
            let deb = d + rel;
            let mut j = deb + "try_acquire".len();
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            while j < b.len() && (b[j] as char).is_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j] == b'(' {
                v.push((deb, blanchi[..deb].matches('\n').count() + 1));
            }
            d = deb + "try_acquire".len();
        }
        v
    }

    /// L'intervalle d'octets du CORPS de `nom` dans un texte blanchi, par appariement d'accolades
    /// depuis la première qui suit la signature. Un échec ne conclut pas : il fait échouer le test.
    fn corps_de(blanchi: &str, nom: &str) -> (usize, usize) {
        let sig = blanchi
            .find(nom)
            .unwrap_or_else(|| panic!("INSTRUMENT : `{nom}` introuvable — la fonction a été renommée ou déplacée ; REPRENDRE la propriété, pas ce test"));
        let b = blanchi.as_bytes();
        let ouvre = sig + blanchi[sig..].find('{').unwrap_or_else(|| panic!("INSTRUMENT : aucun corps après `{nom}`"));
        let (mut prof, mut j) = (0i32, ouvre);
        while j < b.len() {
            if b[j] == b'{' {
                prof += 1;
            } else if b[j] == b'}' {
                prof -= 1;
                if prof == 0 {
                    return (ouvre, j + 1);
                }
            }
            j += 1;
        }
        panic!("INSTRUMENT : accolades non appariées à partir de `{nom}` — le dépouilleur a mangé du code");
    }

    /// LE DÉPOUILLEUR SE VALIDE DANS LES DEUX SENS, SUR DES TEXTES ÉCRITS ICI.
    ///
    /// Le corpus positif place ses appels APRÈS un littéral multiligne et un commentaire de bloc
    /// multiligne : c'est ce qui distingue un dépouilleur correct d'un dépouilleur qui rend le bon
    /// COMPTE en nommant les mauvaises LIGNES. L'assertion porte donc sur les lignes, pas seulement sur
    /// le nombre.
    #[test]
    fn le_depouilleur_distingue_un_appel_dune_mention_et_garde_les_lignes() {
        // Corpus POSITIF fabriqué : 3 appels réels, 5 mentions qui n'appellent rien.
        // (Les lignes sont comptées à partir de 1 sur la chaîne ci-dessous.)
        let positif = "fn a() {\n\
             // le try_acquire du module vit ailleurs\n\
             let s = \"un texte qui parle de try_acquire(\n\
             sur plusieurs lignes, pour décaler les numéros\n\
             et qui mentionne encore try_acquire_owned(\";\n\
             /* un bloc\n\
                qui mentionne try_acquire( sur deux lignes */\n\
             let p = sem.try_acquire_owned();\n\
             let guillemet = '\"';\n\
             let q = autre.try_acquire();\n\
             let r = encore.try_acquire_many (3);\n\
             }\n";
        let lignes: Vec<usize> = appels_de_permis(&blanchir(positif)).into_iter().map(|(_, l)| l).collect();
        assert_eq!(
            lignes,
            vec![8, 10, 11],
            "TÉMOIN POSITIF : trois appels réels, aux lignes 8/10/11 — un compte juste aux mauvaises lignes \
             signifie que le blanchiment a mangé des retours à la ligne. Obtenu : {lignes:?}"
        );
        // Le guillemet en littéral de caractère ne doit pas avoir ouvert une chaîne : si c'était le cas,
        // les deux appels suivants auraient disparu — ce que l'assertion ci-dessus vient d'exclure.

        // Corpus NÉGATIF fabriqué : QUE de la prose, y compris à la position exacte d'un appel.
        let negatif = "fn a() {\n\
             // let p = sem.try_acquire_owned();\n\
             /* let q = autre.try_acquire(); */\n\
             let s = \"sem.try_acquire_owned()\";\n\
             }\n";
        assert!(
            appels_de_permis(&blanchir(negatif)).is_empty(),
            "TÉMOIN NÉGATIF : un texte entièrement en prose ne contient AUCUN appel — sinon la garde \
             accuserait un commentaire : {:?}",
            appels_de_permis(&blanchir(negatif))
        );

        // MUTATION FABRIQUÉE : un corps qui acquiert VRAIMENT doit être vu DANS son corps, sinon la
        // garde de propriété ci-dessous serait verte quoi qu'il arrive.
        let mutant = "async fn cible() -> Response {\n\
             let _p = st.refresh_sem.clone().try_acquire_owned();\n\
             faire();\n\
             }\n";
        let bl = blanchir(mutant);
        let (d, f) = corps_de(&bl, "async fn cible");
        let dedans: Vec<usize> =
            appels_de_permis(&bl).into_iter().filter(|(o, _)| *o >= d && *o < f).map(|(_, l)| l).collect();
        assert_eq!(dedans, vec![2], "MUTANT : un permit pris dans le corps doit être VU, à sa ligne : {dedans:?}");
    }

    /// LA PROPRIÉTÉ, DÉRIVÉE DU FICHIER : le chemin panneau MASQUÉ n'acquiert aucun permit.
    ///
    /// Ce n'est pas un compte recopié : c'est une INCLUSION vide, et sa violation nomme la ligne
    /// fautive. Elle ne rançonne rien — ajouter ou retirer une acquisition AILLEURS dans le module la
    /// laisse indifférente, ce qui est précisément ce qu'on veut d'une propriété qui doit survivre au
    /// prochain lot.
    #[test]
    fn aucune_acquisition_de_permis_dans_le_chemin_masque() {
        let bl = blanchir(&source_du_module_dashboards());
        let (deb, fin) = corps_de(&bl, "async fn panel_data_masked_live");
        // ANTI-NO-OP : un corps vide ou mal apparié rendrait la propriété vraie sans rien mesurer. On
        // exige donc que la tranche trouvée porte bien le geste que cette fonction fait — dériver le
        // travail sur le pool bloquant. Si elle cesse de le faire, c'est le corps qui a changé, pas la
        // garde qui doit céder.
        assert!(
            bl[deb..fin].contains("spawn_blocking"),
            "INSTRUMENT : la tranche retenue ({} octets) ne porte pas le geste de la fonction — l'appariement \
             d'accolades a désigné autre chose que son corps",
            fin - deb
        );
        let dedans: Vec<usize> =
            appels_de_permis(&bl).into_iter().filter(|(o, _)| *o >= deb && *o < fin).map(|(_, l)| l).collect();
        assert!(
            dedans.is_empty(),
            "`panel_data_masked_live` acquiert un permit ligne(s) {dedans:?} de daemon/src/handlers/dashboards.rs. \
             Son commentaire affirme le contraire, et le choix est DOCUMENTÉ : ce chemin est HORS cache, donc un \
             `try_acquire` qui échoue y devient un REFUS servi au lieu d'une réponse plus vieille — prendre le \
             permit CHANGE ce que l'appelant reçoit. Reprendre la décision et le commentaire ensemble, jamais ce \
             test seul."
        );
    }
}
