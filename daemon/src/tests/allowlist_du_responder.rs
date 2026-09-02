// =================================================================================================
// `P4.7-a` — UN MÊME FICHIER D'ALLOWLIST PORTAIT DEUX POLITIQUES, ET CHAQUE LECTEUR LISAIT L'AUTRE
//            DE TRAVERS SANS SE PLAINDRE
//
// CE QUI A ÉTÉ MESURÉ SUR L'ARBRE le 2026-08-27. `/etc/plume/responder.allow` est ÉCRIT par les DEUX
// installateurs et LU par DEUX composants, avec deux significations qui ne se recouvrent pas :
//   * côté CENTRAL — `bootstrap.sh` y sème des NOMS DE SERVICE autorisés pour `stop_service`, et
//     `respond_run` (ce module) les lit ainsi ;
//   * côté AGENT — `bootstrap-agent.sh` sème le MÊME chemin avec des ADRESSES à NE JAMAIS bannir, et
//     `collectors/respond.sh` les lit ainsi, fail-closed.
// Les deux installateurs ne créent le fichier que s'il est ABSENT : sur une machine qui est à la fois
// centrale et agent — que rien n'interdit — le second hérite du contenu du premier.
//
// LA DIRECTION DANGEREUSE EST CELLE DE L'AGENT, et elle a été MESURÉE, pas supposée : en semant
// `nginx.service` dans la liste et en jouant `collectors/respond.sh` tel qu'il est livré (harnais de
// `.github/scripts/check_enforcer_lists_fail_closed.py`), le ban PARTAIT —
// `nft add element inet plume blocklist { 203.0.113.7 }` — et remontait au central en `done`. La
// liste d'IP épargnées de l'exploitant était vide sans que rien ne l'ait jamais dite vide.
//
// DE CE CÔTÉ-CI — le démon — la conséquence n'était pas dangereuse mais elle était MAL DITE : un nom
// de service ne figure pas dans une liste d'adresses, donc tout `stop_service` était BLOQUÉ, avec le
// message « service hors allowlist ». L'exploitant ajoutait alors son service à un fichier que ce
// lecteur-ci n'aurait de toute façon jamais dû lire.
//
// CE QUE CE LOT A CHANGÉ, ET CE QUE CES TÉMOINS TIENNENT :
//   * `allowlist_stop_service` REJETTE une liste qui porte l'autre politique, au lieu de la lire
//     comme une liste de services qui ne contient jamais rien. Le critère n'est pas une liste de
//     mots : c'est un CLASSIFICATEUR de forme d'adresse. ⚠️ `P4.7-a` écrivait ici « DÉRIVÉ du
//     prédicat d'adresse que le produit emploie déjà pour la cible d'un ban » — c'est FAUX depuis
//     `P4.7-b`, et délibérément : la cible d'un ban et la ligne d'une liste sont DEUX questions
//     (voir le bloc `P4.7-b` ci-dessous), et un témoin interdit désormais qu'on en refasse une ;
//   * une lecture IMPOSSIBLE cesse d'être rendue comme une liste VIDE : c'est un refus NOMMÉ ;
//   * le chemin se pose (`PLUME_STOP_SERVICE_ALLOW`), ce qui permet de SÉPARER les deux politiques
//     sur une machine qui porte les deux rôles — et rend ce lecteur exerçable, ce qu'il n'était pas.
//
// CE QUE CES TÉMOINS NE PROUVENT PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU :
//   * ils exercent la FONCTION, pas la sous-commande `respond` entière (qui ouvre une base et parle
//     à systemd). Le lien entre les deux est un seul appel, visible à la relecture ;
//   * le versant AGENT du même constat est tenu ailleurs, et il est ARMÉ :
//     `check_enforcer_lists_fail_closed.py`, témoins `liste-de-l-autre-politique` et
//     `liste-cidr-non-appariable` — dont la mutation (retirer la boucle de forme de
//     `verdict_liste_epargne`) a été jouée et fait bien repartir le ban.
//
// =================================================================================================
// `P4.7-b` — LE PRÉDICAT ANNONCÉ COMMUN N'ÉTAIT NI COMMUN NI UNIQUE, ET AUCUN TÉMOIN NE POUVAIT LE
//            VOIR PARCE QUE LES DEUX NE SE RENCONTRAIENT JAMAIS SUR UNE MÊME CHAÎNE
//
// CE QUI ÉTAIT FAUX, MESURÉ LE 2026-08-28 :
//   * le prédicat du démon exigeait un POINT. Une liste d'épargne écrite en IPv6 hexadécimale pure
//     (`2001:db8::1`, `::1`, `fe80::1`) n'était donc pas reconnue comme une adresse et tombait dans
//     `services.push(...)` : lue comme une liste de NOMS DE SERVICE, sans un mot, alors que le
//     fichier que l'exploitant a sous les yeux affirme que « les deux lecteurs REFUSENT le contenu
//     de l'autre politique ». C'est précisément le « au lieu de l'ignorer » que `P4.7-a` promettait ;
//   * il y avait DEUX définitions côté démon, pas une : `Slot::target_ok(Slot::Ip)` recopiait les
//     quatre clauses mot pour mot, sous un en-tête de module qui écrivait « nulle part ailleurs » ;
//   * ET CE TÉMOIN-CI CERTIFIAIT LA FRONTIÈRE À L'ENVERS. Son unique échantillon IPv6 était
//     `::ffff:203.0.113.7` — la SEULE forme IPv6 qui portait un point, donc la seule qui
//     s'échappait du défaut. Un correctif validé sur ce seul échantillon n'aurait rien fermé.
//
// CE QUI A CHANGÉ, ET LE MOT QUI COMPTE EST « DEUX QUESTIONS » : le nom unique répondait à la fois
// à « ce produit sait-il BANNIR cette cible ? » (une borne de CAPACITÉ, qui décide de ce qui PART
// vers un pare-feu) et à « cette LIGNE est-elle une adresse ? » (une CLASSIFICATION, dont le seul
// effet est un refus). Seule la seconde est promise commune avec `collectors/respond.sh`. Les deux
// sont séparées : `cible_de_ban_acceptee` (corps INCHANGÉ, clause pour clause) et
// `ressemble_a_une_adresse` (élargi à la famille IPv6 par la disjonction que `extract_src_ip`
// écrit déjà à l'ingestion). `Slot::target_ok(Slot::Ip)` APPELLE la première au lieu de la recopier.
//
// ET L'INSTRUMENT EST FERMÉ AVEC LE DÉFAUT, parce que c'est lui qui l'a laissé passer :
// `collectors/predicat-adresse.corpus` est la définition COMMUNE, et elle est rejouée sur LES DEUX
// lecteurs — la colonne `demon` ici, la colonne `agent` par
// `.github/scripts/check_enforcer_lists_fail_closed.py`, qui EXÉCUTE `is_ip` extrait du script livré.
// AUCUN DES DEUX TÉMOINS NE PROUVE SEUL LA PROPRIÉTÉ : celui-ci prend la colonne `agent` pour
// acquise, l'autre prend la colonne `demon` pour acquise. C'est le FICHIER PARTAGÉ qui les relie, et
// c'est pourquoi les deux refusent de conclure s'il manque ou s'il maigrit.
// =================================================================================================
#[cfg(test)]
mod allowlist_du_responder_tests {
    use crate::handlers::actions::{allowlist_stop_service, cible_de_ban_acceptee, ressemble_a_une_adresse};
    use std::path::{Path, PathBuf};

    fn racine_du_depot() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("INSTRUMENT : le crate n'a pas de répertoire parent")
            .to_path_buf()
    }

    fn lue(contenu: &str) -> Result<Vec<String>, String> {
        allowlist_stop_service(Ok(contenu.to_string()))
    }

    /// LE DÉFAUT LUI-MÊME. Le contenu que l'installateur d'AGENT sème — des adresses — présenté au
    /// lecteur du CENTRAL. Avant, il en faisait une liste de « services » qu'aucune cible ne
    /// rencontrait jamais ; le refus mentait sur sa raison.
    #[test]
    fn une_liste_d_adresses_est_refusee_et_le_refus_nomme_l_autre_politique() {
        let contenu = "# IP a NE JAMAIS bannir (1 par ligne).\n203.0.113.7\n198.51.100.9\n";
        let verdict = lue(contenu);
        let Err(pourquoi) = verdict else {
            panic!("une liste d'ADRESSES a été acceptée comme une liste de services : {verdict:?}");
        };
        assert!(pourquoi.contains("203.0.113.7"), "le refus ne montre pas la ligne fautive : {pourquoi}");
        assert!(pourquoi.contains("ADRESSE"), "le refus ne dit pas CE QUE la ligne est : {pourquoi}");
        assert!(pourquoi.contains("PLUME_STOP_SERVICE_ALLOW"),
                "le refus ne dit pas comment SÉPARER les deux politiques : {pourquoi}");
    }

    /// Une ligne CIDR est de la politique de l'agent elle aussi — un exploitant l'écrit
    /// spontanément dans une liste d'adresses. Elle doit être reconnue comme étrangère.
    #[test]
    fn une_ligne_cidr_est_reconnue_comme_l_autre_politique() {
        assert!(lue("203.0.113.0/24\n").is_err(), "un préfixe CIDR reste une adresse");
    }

    /// TÉMOIN INVERSE, ET IL EST INDISPENSABLE : une fonction qui refuserait TOUT passerait le témoin
    /// précédent sans rien prouver, et aurait simplement supprimé `stop_service`.
    #[test]
    fn une_liste_de_services_est_lue_normalement() {
        assert_eq!(
            lue("nginx.service\n  sshd.service  \ncontainerd.service\n"),
            Ok(vec!["nginx.service".into(), "sshd.service".into(), "containerd.service".into()]),
            "une liste de services doit être lue, espaces de bord rognés comme avant"
        );
    }

    /// SECOND TÉMOIN INVERSE — celui qui protège les installations NEUVES. Les deux installateurs
    /// posent un fichier qui ne contient QUE des commentaires : il doit valoir « liste vide », c'est-
    /// à-dire « aucun `stop_service` autorisé », et surtout PAS un refus qui se lirait comme une
    /// panne. Le contenu n'est pas recopié ici : il est LU dans l'installateur livré, si bien qu'un
    /// jour où l'en-tête change, ce témoin le voit.
    #[test]
    fn le_fichier_que_pose_l_installateur_du_central_est_une_liste_vide_pas_un_refus() {
        let installateur = std::fs::read_to_string(racine_du_depot().join("bootstrap.sh"))
            .expect("INSTRUMENT : `bootstrap.sh` illisible — ce témoin refuse de conclure");
        // Le bloc qui ÉCRIT le fichier : la ligne `printf … > /etc/plume/responder.allow`.
        let ligne = installateur
            .lines()
            .find(|l| l.contains("> /etc/plume/responder.allow") && l.contains("printf"))
            .expect("INSTRUMENT : `bootstrap.sh` n'écrit plus ce fichier par un `printf` — la forme a \
                    changé, ce témoin refuse de conclure");
        // Le gabarit `printf` porte les lignes séparées par `\n` littéraux : on les rend réelles.
        let debut = ligne.find('\'').expect("INSTRUMENT : gabarit `printf` sans apostrophe");
        let fin = ligne.rfind('\'').expect("INSTRUMENT : gabarit `printf` sans apostrophe fermante");
        let seme = ligne[debut + 1..fin].replace("\\n", "\n");
        assert!(seme.lines().count() >= 2, "INSTRUMENT : gabarit vide, ce témoin refuse de conclure");
        assert_eq!(lue(&seme), Ok(Vec::new()),
                   "le fichier POSÉ par l'installateur du central doit valoir « liste vide » — un \
                    refus ici transformerait chaque installation neuve en panne apparente. Semé : {seme:?}");
    }

    /// UNE LECTURE IMPOSSIBLE N'EST PAS UNE LISTE VIDE. Avant, `read_to_string(..).unwrap_or_default()`
    /// rendait la même chose dans les deux cas : le refus qui suivait disait « ce service n'est pas
    /// dans l'allowlist », c'est-à-dire un FAIT, là où rien n'avait été établi.
    #[test]
    fn une_lecture_impossible_est_un_refus_nomme_pas_une_liste_vide() {
        let erreur = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "acces refuse");
        let verdict = allowlist_stop_service(Err(erreur));
        let Err(pourquoi) = verdict else {
            panic!("une lecture en échec a été rendue comme une liste : {verdict:?}");
        };
        assert!(pourquoi.contains("lecture impossible"),
                "le refus ne dit pas que la LECTURE a échoué : {pourquoi}");
    }

    /// LE CLASSIFICATEUR ET SA FRONTIÈRE — ⚠️ il n'est PAS « le prédicat partagé », et ce titre-là
    /// était faux : le lecteur d'hôte en a un autre, plus ÉTROIT (`P4.7-b`). Ce qui est partagé est
    /// la CONTENANCE, tenue par les témoins de balayage plus bas. C'est ce classificateur-ci qui
    /// décide ce qui est « de l'autre politique » ; les deux sens sont exercés — un nom d'unité
    /// n'est jamais une adresse, une adresse en est toujours une.
    #[test]
    fn le_predicat_d_adresse_separe_les_deux_politiques_dans_les_deux_sens() {
        for unite in ["nginx.service", "sshd.service", "containerd.service", "plume-daemon.service",
                      "dev-sda.device", "var-lib.mount", "cafe.socket", "add.timer"] {
            assert!(!ressemble_a_une_adresse(unite),
                    "`{unite}` est un nom d'unité systemd et serait pris pour une adresse : \
                     l'allowlist du central serait refusée à tort");
        }
        // `P4.7-b` — CETTE LISTE NE PORTAIT QU'UN SEUL ÉCHANTILLON IPv6, `::ffff:203.0.113.7`,
        // c'est-à-dire la seule forme IPv6 qui porte un POINT : la seule qui s'échappait du défaut.
        // La famille hexadécimale PURE est ajoutée ici, et le corpus partagé la tient au complet.
        for adresse in ["203.0.113.7", "10.0.0.1", "192.168.1.254", "::ffff:203.0.113.7",
                        "2001:db8::1", "::1", "fe80::1", "::", "2001:0db8:0000:0000:0000:0000:0000:0001"] {
            assert!(ressemble_a_une_adresse(adresse),
                    "`{adresse}` n'est pas reconnue comme une adresse : la liste de l'autre politique \
                     passerait pour une liste de services");
        }
    }
    /// LE MIROIR DU TROU QUI ÉTAIT DU CÔTÉ SHELL (`P4.7-a`). MESURÉ le 2026-08-27 :
    /// `collectors/respond.sh` lisait sa liste par `while IFS= read -r`, dont le corps n'est PAS
    /// exécuté sur une dernière ligne dépourvue de saut de ligne final — une liste valant
    /// exactement `nginx.service` SANS `\n` passait donc pour bien formée et LE BAN PARTAIT.
    /// DE CE CÔTÉ-CI, `contenu.lines()` rend la dernière ligne partielle : le trou n'existe pas, et
    /// ce témoin l'ÉPINGLE. ⚠️ Cette phrase disait « les deux lecteurs promettent le même critère » :
    /// c'est FAUX (`P4.7-b`) et ce n'est pas ce qui est promis. Ce qui l'est ici est plus étroit et
    /// vrai : LIRE UNE LIGNE, les deux lecteurs le font de la même façon — c'est-à-dire jusqu'au
    /// bout, y compris sur un fichier que personne ne termine.
    #[test]
    fn une_liste_sans_saut_de_ligne_final_est_lue_jusqu_a_sa_derniere_ligne() {
        // POSITIF : la ligne fautive est la DERNIÈRE et n'est pas terminée -> la liste est REFUSÉE.
        let refus = lue("# services autorises\n203.0.113.7");
        assert!(refus.is_err(),
                "la dernière ligne non terminée n'a pas été lue : une ADRESSE y serait passée pour \
                 une liste de services vide, exactement le défaut du versant shell — rendu : {refus:?}");
        // NÉGATIF : une liste bien formée et non terminée doit être LUE, pas refusée.
        let ok = lue("# services autorises\nnginx.service");
        assert_eq!(ok.as_deref(), Ok(&["nginx.service".to_string()][..]),
                   "une liste valide sans saut de ligne final doit être lue entièrement : {ok:?}");
    }

    // =============================================================================================
    // `P4.7-b` — LE CORPUS PARTAGÉ, REJOUÉ SUR LE LECTEUR DU DÉMON
    // =============================================================================================

    /// Une ligne du corpus : la chaîne, le verdict attendu du DÉMON, le verdict attendu de l'AGENT.
    struct LigneDeCorpus {
        chaine: String,
        demon: String,
        agent: String,
    }

    /// LIT le corpus partagé. Il REFUSE DE CONCLURE plutôt que de rendre une liste vide : un corpus
    /// introuvable, vide ou mal formé rendrait tous les témoins qui suivent verts en n'exerçant
    /// rien — exactement l'angle mort que `P4.7-b` a payé une fois.
    fn corpus_partage() -> Vec<LigneDeCorpus> {
        let chemin = racine_du_depot().join("collectors").join("predicat-adresse.corpus");
        let texte = std::fs::read_to_string(&chemin).unwrap_or_else(|e| {
            panic!("INSTRUMENT : corpus partagé illisible ({}) : {e} — ce témoin REFUSE de conclure",
                   chemin.display())
        });
        let mut lignes = Vec::new();
        for (rang, brute) in texte.lines().enumerate() {
            if brute.starts_with('#') || brute.trim().is_empty() {
                continue;
            }
            let champs: Vec<&str> = brute.split('\t').collect();
            assert_eq!(champs.len(), 3,
                       "INSTRUMENT : ligne {} du corpus mal formée (3 champs séparés par TAB attendus) : {brute:?}",
                       rang + 1);
            assert!(["refuse", "nom-de-service"].contains(&champs[1]),
                    "INSTRUMENT : colonne `demon` hors vocabulaire fermé, ligne {} : {:?}", rang + 1, champs[1]);
            assert!(["adresse", "forme-inconnue"].contains(&champs[2]),
                    "INSTRUMENT : colonne `agent` hors vocabulaire fermé, ligne {} : {:?}", rang + 1, champs[2]);
            lignes.push(LigneDeCorpus {
                chaine: champs[0].to_string(),
                demon: champs[1].to_string(),
                agent: champs[2].to_string(),
            });
        }
        // `P11.23-e` — L'ARGUMENT DE RACINE, ET IL MANQUAIT À TROIS CONSOMMATEURS SUR CINQ. Un corpus
        // réduit à ses commentaires est LISIBLE — le `unwrap_or_else` ci-dessus ne mord pas — et rend
        // zéro ligne. Les témoins qui bouclent dessus SANS plancher (`chaque_ligne_du_corpus_…`,
        // `aucune_ligne_n_est_retenue_…`) sortiraient alors VERTS sans avoir exercé une seule
        // assertion : c'est la forme de `P11.23-e` sans aucune sortie anticipée. Deux de leurs
        // voisins portaient déjà leur propre plancher (`exercees >= 8`, `services.len() >= 5`) ; le
        // plancher est ici remonté DANS l'instrument, donc tout consommateur en hérite — y compris
        // celui qu'on écrira demain.
        assert!(
            !lignes.is_empty(),
            "INSTRUMENT : le corpus partagé ({}) ne porte AUCUNE ligne de matière — tout témoin qui \
             boucle dessus serait vert sans rien prouver",
            chemin.display()
        );
        lignes
    }

    /// VALIDATION DE L'INSTRUMENT, ET ELLE PRÉCÈDE TOUT VERDICT. Un corpus qui aurait perdu sa
    /// famille IPv6, ou l'une des trois combinaisons admissibles, laisserait passer le défaut sans
    /// que rien ne rougisse. La QUATRIÈME combinaison — retenue par le démon ET lue comme une
    /// adresse par l'agent — EST le défaut : elle est refusée jusque dans le fichier.
    #[test]
    fn le_corpus_partage_couvre_les_trois_combinaisons_et_jamais_la_quatrieme() {
        let corpus = corpus_partage();
        assert!(corpus.len() >= 25,
                "INSTRUMENT : corpus partagé trop maigre ({} lignes) — il a maigri, ce témoin refuse \
                 de conclure", corpus.len());
        for (demon, agent) in [("refuse", "adresse"), ("refuse", "forme-inconnue"),
                               ("nom-de-service", "forme-inconnue")] {
            assert!(corpus.iter().any(|l| l.demon == demon && l.agent == agent),
                    "INSTRUMENT : la combinaison `{demon}`/`{agent}` a disparu du corpus — la \
                     couverture n'est plus celle que ces témoins annoncent");
        }
        assert!(!corpus.iter().any(|l| l.demon == "nom-de-service" && l.agent == "adresse"),
                "le corpus DÉCLARE une ligne que les DEUX lecteurs acceptent : c'est le défaut de \
                 `P4.7-b` écrit noir sur blanc, pas un cas à couvrir");
        // La famille IPv6 hexadécimale pure DOIT y être : c'est elle que le défaut laissait passer.
        for pure in ["2001:db8::1", "::1", "fe80::1"] {
            assert!(corpus.iter().any(|l| l.chaine == pure),
                    "INSTRUMENT : `{pure}` a disparu du corpus — la famille que `P4.7-b` a trouvée \
                     n'est plus exercée");
        }
    }

    /// LE VERDICT DU DÉMON, LIGNE À LIGNE, SUR LE CORPUS COMMUN — c'est-à-dire le LECTEUR entier
    /// (`allowlist_stop_service`), pas seulement son prédicat : ce qui compte à l'exploitant est ce
    /// que le fichier DEVIENT, pas ce qu'une fonction rend.
    #[test]
    fn chaque_ligne_du_corpus_recoit_du_demon_le_verdict_annonce() {
        for l in corpus_partage() {
            let verdict = lue(&format!("{}\n", l.chaine));
            match l.demon.as_str() {
                "refuse" => {
                    let Err(pourquoi) = &verdict else {
                        panic!("`{}` : le corpus annonce `refuse` et le démon l'a RETENUE comme un \
                                nom de service — {verdict:?}", l.chaine);
                    };
                    assert!(pourquoi.contains("ADRESSE"),
                            "`{}` : refusée sans dire CE QUE la ligne est : {pourquoi}", l.chaine);
                }
                _ => assert_eq!(verdict.as_deref(), Ok(&[l.chaine.clone()][..]),
                                "`{}` : le corpus annonce `nom-de-service` et le démon ne l'a pas \
                                 retenue — {verdict:?}", l.chaine),
            }
        }
    }

    /// (P1) CONTENANCE — LA PROPRIÉTÉ QUE `P4.7-b` A TROUVÉE FAUSSE. Tout ce que le lecteur d'AGENT
    /// accepte comme une adresse, le lecteur du DÉMON le REFUSE comme étant de l'autre politique.
    /// C'est la seule direction qui protège l'exploitant : une liste d'épargne parfaitement
    /// utilisable par l'agent ne peut plus être avalée en silence par le démon.
    /// LA RÉCIPROQUE N'EST PAS PROMISE, et le témoin ne la teste pas : le démon refuse EN PLUS des
    /// formes que l'agent ne sait pas lire, et sur celles-là l'agent refuse aussi (fail-closed).
    #[test]
    fn tout_ce_que_l_agent_lit_comme_adresse_est_refuse_par_le_demon() {
        let mut exercees = 0;
        for l in corpus_partage().into_iter().filter(|l| l.agent == "adresse") {
            exercees += 1;
            assert!(lue(&format!("{}\n", l.chaine)).is_err(),
                    "`{}` est une adresse pour `collectors/respond.sh` (colonne `agent` du corpus, \
                     MESURÉE par `check_enforcer_lists_fail_closed.py`) et le démon en fait un NOM \
                     DE SERVICE : la liste d'épargne de l'exploitant est lue comme une allowlist \
                     `stop_service`, sans un mot — c'est `P4.7-b`", l.chaine);
        }
        assert!(exercees >= 8,
                "INSTRUMENT : seulement {exercees} lignes `agent=adresse` exercées — le corpus a \
                 perdu sa matière, ce témoin refuse de conclure");
    }

    /// (P2) AUCUN SILENCE À DEUX. Les deux politiques sont disjointes par construction : une ligne
    /// est une adresse (l'agent la retient, le démon doit la refuser) ou un nom de service
    /// (l'inverse). Une ligne retenue DES DEUX CÔTÉS signifie qu'un des deux s'est trompé sans que
    /// rien ne le dise — c'est la forme générale du défaut, et c'est elle qu'on épingle.
    #[test]
    fn aucune_ligne_n_est_retenue_en_silence_par_les_deux_lecteurs() {
        for l in corpus_partage() {
            let retenue_par_le_demon = lue(&format!("{}\n", l.chaine)).is_ok();
            let retenue_par_l_agent = l.agent == "adresse";
            assert!(!(retenue_par_le_demon && retenue_par_l_agent),
                    "`{}` est RETENUE par les deux lecteurs : l'agent l'épargne, le démon l'autorise \
                     à `stop_service`, et aucun des deux ne dit que le fichier porte l'autre \
                     politique", l.chaine);
        }
    }

    /// LA DIRECTION INVERSE, ET ELLE EST INDISPENSABLE : `stop_service` doit encore EXISTER. Un
    /// classificateur qui refuserait tout tiendrait (P1) et (P2) sans rien prouver — il aurait
    /// simplement supprimé l'action. Le corpus porte donc sa propre contrepartie.
    #[test]
    fn le_demon_retient_encore_les_noms_de_service_du_corpus() {
        let services: Vec<String> = corpus_partage().into_iter()
            .filter(|l| l.demon == "nom-de-service").map(|l| l.chaine).collect();
        assert!(services.len() >= 5,
                "INSTRUMENT : {} noms de service dans le corpus — trop peu pour prouver que \
                 `stop_service` survit", services.len());
        let liste = format!("{}\n", services.join("\n"));
        assert_eq!(lue(&liste), Ok(services.clone()),
                   "une liste faite des noms de service du corpus doit être LUE en entier");
    }

    /// LA BORNE D'ENFORCEMENT NE S'ÉLARGIT JAMAIS — ET L'ÉCART EST DÉRIVÉ, PAS ÉNUMÉRÉ.
    ///
    /// CE TÉMOIN A CHANGÉ DE FORME LE 2026-08-28, ET IL FAUT DIRE POURQUOI. `P4.7-b` l'avait écrit
    /// comme une ÉGALITÉ — « les quatre clauses d'origine donnent le MÊME verdict » — parce que ce
    /// lot-là n'avait le droit de bouger NI dans un sens NI dans l'autre. `P4.7-h` a mesuré que la
    /// borne devait se RESSERRER : `10.0.0.01`, `010.0.0.1`, `127.000.000.001` étaient des cibles
    /// de ban ACCEPTÉES que le produit ne savait PAS analyser, si bien que la protection des plages
    /// réservées — la seule qui marche sans configuration — ne s'exécutait pas du tout sur elles.
    /// Une égalité aurait interdit la correction ; la retirer sans rien mettre à la place aurait
    /// retiré la garde. La propriété qui compte est donc écrite en CONTENANCE :
    ///
    ///     (E)  `cible_de_ban_acceptee(s)`  =>  `avant(s)`      — la borne n'ACCEPTE jamais plus
    ///     (R)  `avant(s) && !cible_de_ban_acceptee(s)`  <=>  `s` ne dénote pas une valeur IPv4
    ///     (L)  `cible_de_levee_acceptee(s)`  =  `avant(s)`      — la LEVÉE, elle, n'a PAS bougé
    ///
    /// (E) est la garantie de `P4.7-b` intégralement conservée : rien de NEUF ne part vers un
    /// pare-feu. (R) borne le resserrement à sa cause EXACTE — pas à une liste de chaînes — donc un
    /// resserrement supplémentaire écrit demain sur un AUTRE critère fait rougir ce témoin.
    ///
    /// (R) A ÉTÉ RESSERRÉE LE 2026-08-29, ET IL FAUT DIRE POURQUOI. Elle disait « l'écart est le
    /// refus d'ANALYSE ». Mesuré : `2001:db8::192.0.2.1` — une ligne DU CORPUS PARTAGÉ — et la forme
    /// IPv4-compatible obsolète `::127.0.0.1` s'analysent parfaitement et restaient donc des cibles
    /// de ban ACCEPTÉES, tout en étant INVISIBLES à la denylist (aucun item v4 ne peut apparier une
    /// valeur v6, `to_ipv4_mapped` ne replie que `::ffff:`, et `Ipv6Addr::is_loopback` ne couvre que
    /// `::1`) : les deux conditions de la fuite que cette famille poursuit, sur une autre écriture.
    /// La borne exige désormais une VALEUR IPv4 — la borne « v1 : IPv4 » écrite depuis toujours,
    /// enfin tranchée sur la valeur et non sur la présence d'un point.
    ///
    /// (L) EST NEUVE, ET C'EST UNE CORRECTION DE CE LOT. Le premier jet appliquait la borne
    /// RESSERRÉE aux DEUX sens : un ban posé au pare-feu sous une notation que la nouvelle borne
    /// refuse devenait NON LEVABLE par plume, et toute action `unban_ip` pendante sur cette cible
    /// passait à `blocked` à la mise à jour. Une soupape doit LEVER PLUS, jamais moins.
    #[test]
    fn la_borne_de_ban_ne_s_elargit_jamais_et_son_resserrement_est_derive() {
        // Les quatre clauses telles qu'elles étaient AVANT (`ressemble_a_une_adresse` de `P4.7-a`,
        // puis `cible_de_ban_acceptee` de `P4.7-b`). Recopiées ICI À DESSEIN : point de comparaison.
        fn avant(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 45
                && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                && s.contains('.')
        }
        let mut chaines: Vec<String> = corpus_partage().into_iter().map(|l| l.chaine).collect();
        for extra in ["", "0.0.0.0", "255.255.255.255", "10.0.0.1", "192.168.1.254", "8.8.8.8",
                      "01.02.03.04", "203.0.113.7 ", " 203.0.113.7", "nginx", "1234",
                      "10.0.0.01", "010.0.0.1", "127.000.000.001", "192.168.001.1",
                      "::127.0.0.1", "2001:db8::192.0.2.1", "::ffff:203.0.113.7",
                      "0000:0000:0000:0000:0000:ffff:255.255.255.255",
                      "00000:0000:0000:0000:0000:ffff:255.255.255.255"] {
            chaines.push(extra.to_string());
        }
        let (mut resserrees, mut conservees) = (0usize, 0usize);
        for s in &chaines {
            let apres = cible_de_ban_acceptee(s);
            // (E) — AUCUN ÉLARGISSEMENT. C'est la garantie que `P4.7-b` a posée, intacte.
            if apres {
                assert!(avant(s),
                        "`{s}` est devenue une cible de ban : la borne d'enforcement s'est ÉLARGIE, \
                         ce qui est interdit — c'est ce qui part vers `nft`/`cscli`/`fail2ban`");
                conservees += 1;
            }
            // (R) — LE RESSERREMENT EST EXACTEMENT « la cible ne dénote pas une valeur IPv4 ».
            let denote_une_v4 = matches!(crate::ledger::ssrf_norm_ip(s), Some(std::net::IpAddr::V4(_)));
            assert_eq!(avant(s) && !apres, !denote_une_v4 && avant(s),
                       "`{s}` : l'écart entre l'ancienne borne et la nouvelle n'est PAS « ne dénote \
                        pas une valeur IPv4 » — un second critère de resserrement est apparu sans être dit");
            if avant(s) && !apres { resserrees += 1; }
            // (L) — LA BORNE DE LA LEVÉE EST CELLE D'AVANT LE LOT, CLAUSE POUR CLAUSE. C'est
            // l'égalité que `P4.7-b` exigeait, conservée là où elle doit l'être : sur la SOUPAPE.
            assert_eq!(crate::handlers::actions::cible_de_levee_acceptee(s), avant(s),
                       "`{s}` : la borne de la LEVÉE a bougé — un ban posé au pare-feu sous cette \
                        notation ne serait plus levable par plume, ce qui est le verrouillage même \
                        que la valve doit empêcher");
        }
        // NON-VACUITÉ DANS LES DEUX SENS : sans cela, une borne qui accepterait TOUT ou RIEN
        // satisferait (E) et (R) sans rien mesurer.
        assert!(resserrees >= 4, "INSTRUMENT : {resserrees} chaîne(s) resserrée(s) — le corpus ne porte \
                                  plus le défaut de `P4.7-h`, ce témoin REFUSE de conclure");
        assert!(conservees >= 4, "INSTRUMENT : {conservees} cible(s) toujours acceptée(s) — la borne a \
                                  été vidée, ce témoin REFUSE de conclure");
        // Et le fond : l'IPv6 hexadécimale pure reste HORS du ban, comme avant le lot.
        for hors in ["2001:db8::1", "::1", "fe80::1", "::"] {
            assert!(!cible_de_ban_acceptee(hors),
                    "`{hors}` est devenue une cible de ban : le lot a élargi ce qui part vers un \
                     pare-feu, ce qui lui est interdit");
        }
    }

    /// LES DEUX QUESTIONS SONT BIEN DEUX. Si un jour quelqu'un refait de ces deux fonctions une
    /// seule, ce témoin le dit : elles DIVERGENT, et c'est leur divergence qui est la correction.
    /// Le classificateur reconnaît l'IPv6 ; la borne de ban ne la reconnaît pas et ne doit pas.
    #[test]
    fn le_classificateur_et_la_borne_de_ban_ne_repondent_pas_a_la_meme_question() {
        for ipv6 in ["2001:db8::1", "::1", "fe80::1", "::", "dead:beef"] {
            assert!(ressemble_a_une_adresse(ipv6),
                    "`{ipv6}` n'est pas classée comme une adresse : une liste d'épargne IPv6 \
                     redeviendrait une allowlist `stop_service` silencieuse");
            assert!(!cible_de_ban_acceptee(ipv6),
                    "`{ipv6}` est devenue bannissable — la borne d'enforcement a été élargie par \
                     mégarde en corrigeant le classificateur");
        }
        // Et la borne de longueur appartient à la BORNE, pas au classificateur : c'est ce qui
        // fermait le dernier silence à deux (49 caractères, acceptés par `is_ip`).
        let long = "dead:beef:cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe";
        assert_eq!(long.len(), 49, "INSTRUMENT : l'échantillon long a changé de taille");
        assert!(ressemble_a_une_adresse(long),
                "le classificateur a repris une borne de longueur : `is_ip` accepte cette chaîne \
                 sans borne, elle redeviendrait un nom de service");
        assert!(!cible_de_ban_acceptee(long), "la borne de ban a perdu son plafond de 45");
    }

    /// LE DÉFAUT LUI-MÊME, ÉCRIT COMME UN EXPLOITANT L'ÉCRIT. Une liste d'épargne IPv6 présentée au
    /// lecteur du central : avant le lot, elle était lue comme trois noms de service autorisés.
    #[test]
    fn une_liste_d_epargne_ipv6_est_refusee_et_nomme_l_autre_politique() {
        let contenu = "# IP a NE JAMAIS bannir (1 par ligne).\n2001:db8::1\nfe80::1\n::1\n";
        let verdict = lue(contenu);
        let Err(pourquoi) = verdict else {
            panic!("une liste d'épargne IPv6 a été acceptée comme une liste de services : {verdict:?}");
        };
        assert!(pourquoi.contains("2001:db8::1"), "le refus ne montre pas la ligne fautive : {pourquoi}");
        assert!(pourquoi.contains("ADRESSE"), "le refus ne dit pas CE QUE la ligne est : {pourquoi}");
        assert!(pourquoi.contains("PLUME_STOP_SERVICE_ALLOW"),
                "le refus ne dit pas comment SÉPARER les deux politiques : {pourquoi}");
        // Les habillages qu'un exploitant écrit AUTOUR d'une adresse : masque et zone. La zone est
        // l'ajout de `P4.7-b` — `fe80::1%eth0` tombait dans `services.push(...)` alors que l'agent
        // la refuse (mesuré : `is_ip` n'admet pas le `%`).
        assert!(lue("2001:db8::/32\n").is_err(), "un préfixe CIDR IPv6 reste une adresse");
        assert!(lue("fe80::1%eth0\n").is_err(), "un identifiant de zone reste une adresse");
    }


    // =============================================================================================
    // `P4.7-b` (reprise du 2026-08-28) — (P1) N'ÉTAIT TENUE QUE SUR 30 LIGNES ÉCRITES À LA MAIN
    //
    // CE QUI A ÉTÉ RELEVÉ, ET C'EST JUSTE : le corpus s'annonçait « LA DÉFINITION COMMUNE » et les
    // installateurs écrivaient « AUCUNE ligne n'est acceptée EN SILENCE par les deux » — un
    // UNIVERSEL —, alors que les deux témoins ne comparaient que des colonnes DÉCLARÉES sur un
    // ÉCHANTILLON. Une clause ajoutée demain à `is_ip` sur une forme ABSENTE du corpus (`[`, `]`,
    // une forme mixte non échantillonnée) aurait cassé (P1) sans faire rougir personne.
    //
    // CE QUI EST TENU DEPUIS : (P1) est DÉCOMPOSÉE en deux moitiés, chacune BALAYÉE sur un ALPHABET
    // au lieu d'être échantillonnée, chacune jouée sur un lecteur RÉEL, et reliées par une borne
    // STRUCTURELLE écrite une fois dans l'en-tête du corpus :
    //
    //     (S)  s ≠ "" ∧ tous les caractères de s ∈ [0-9a-fA-F.:] ∧ au moins un ∈ {'.', ':'}
    //
    //   MOITIÉ AGENT — « tout ce que `is_ip` accepte satisfait (S) » : mesurée par
    //     `.github/scripts/check_enforcer_lists_fail_closed.py`, qui EXTRAIT `is_ip` du script livré
    //     et le joue sur le MÊME balayage.
    //   MOITIÉ DÉMON — « tout ce qui satisfait (S) est REFUSÉ par le lecteur » : c'est le témoin
    //     ci-dessous, et il exerce `allowlist_stop_service` en entier, pas seulement son prédicat.
    //   COMPOSITION : tout ce que l'agent lit comme une adresse, le démon le refuse. (P1), sur un
    //     balayage et non sur un échantillon.
    //
    // TROIS LIMITES, ÉCRITES PLUTÔT QUE SOUS-ENTENDUES :
    //   ① (S) est écrit DEUX FOIS, une par langage — la même impossibilité que le prédicat lui-même
    //     (aucun littéral n'est partageable entre un binaire Rust et un script shell). Ce qui change
    //     est la NATURE de ce qui est écrit deux fois : trois clauses structurelles au lieu de deux
    //     prédicats complets, et le corpus continue de mesurer les verdicts CONCRETS des deux
    //     lecteurs ligne à ligne — une dérive de (S) d'un côté fait rougir cette moitié-là dès
    //     qu'une ligne du corpus la traverse.
    //   ② LES DEUX BALAYAGES NE SONT PAS LE MÊME ENSEMBLE. Côté CI l'alphabet est DÉRIVÉ de la ligne
    //     `is_ip` livrée (on n'élargit pas un ERE sans écrire les caractères qu'on y admet) ; ici il
    //     porte UN REPRÉSENTANT PAR CLASSE que le classificateur distingue, sur toutes les longueurs
    //     ≤ 4. La composition est donc PONCTUELLE là où les deux se rencontrent, et par CLASSE
    //     au-delà : les deux lecteurs sont caractère-à-caractère sur l'hexadécimal, donc `1` se
    //     comporte comme `0`/`9` et `E` comme `A`/`F`. CE PAS-LÀ EST UNE LECTURE, PAS UNE MESURE.
    //   ③ LES LONGUEURS SONT BORNÉES (≤ 4 ici, ≤ 3 en CI) ; les chaînes plus longues sont CIBLÉES,
    //     pas balayées. C'est plus large que 30 lignes ; ce n'est pas total.
    // =============================================================================================

    /// L'ALPHABET DU BALAYAGE — UN REPRÉSENTANT PAR CLASSE QUE LE LECTEUR DISTINGUE : les deux bornes
    /// du chiffre (`0`, `9`), les deux bornes de l'hexadécimal en minuscules (`a`, `f`) ET en
    /// majuscules (`A`, `F`), une lettre HORS hexadécimal (`g`), les deux séparateurs d'adresse
    /// (`.`, `:`), les deux habillages que le lecteur COUPE (`/`, `%`), le commentaire (`#`), le
    /// blanc (que `trim` retire) et le tiret d'un nom d'unité.
    const ALPHABET_DU_BALAYAGE: &[char] =
        &['0', '9', 'a', 'f', 'A', 'F', 'g', '.', ':', '%', '/', '#', ' ', '-'];

    /// (S) — LA BORNE STRUCTURELLE, écrite ici dans les mots de l'en-tête du corpus.
    fn satisfait_la_borne_structurelle(s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
            && s.chars().any(|c| c == '.' || c == ':')
    }

    /// Toutes les chaînes de 1 à 4 caractères sur l'alphabet, plus des chaînes LONGUES ciblées que la
    /// longueur du balayage ne peut pas atteindre (c'est une borne de longueur qui avait laissé le
    /// dernier silence à deux : elle ne doit pas revenir par la fenêtre).
    /// CE BALAYAGE-CI VA JUSQU'À 4, celui de la garde CI s'arrête à 3 (il paie deux processus par
    /// chaîne). C'est un SUR-ENSEMBLE, et c'est le bon sens pour la composition : la moitié DÉMON
    /// « (S) ⇒ refusé » est alors vérifiée sur toutes les chaînes où la moitié AGENT « `is_ip` ⇒ (S) »
    /// l'est, et sur davantage.
    fn balayage() -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for a in ALPHABET_DU_BALAYAGE {
            v.push(a.to_string());
            for b in ALPHABET_DU_BALAYAGE {
                v.push(format!("{a}{b}"));
                for c in ALPHABET_DU_BALAYAGE {
                    v.push(format!("{a}{b}{c}"));
                    for d in ALPHABET_DU_BALAYAGE {
                        v.push(format!("{a}{b}{c}{d}"));
                    }
                }
            }
        }
        for longue in ["dead:beef:cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe",
                       "0000:0000:0000:0000:0000:ffff:255.255.255.255",
                       "00000:0000:0000:0000:0000:ffff:255.255.255.255",
                       &"f".repeat(45), &format!("{}:{}", "f".repeat(45), "f".repeat(45)),
                       &":".repeat(100), &"dead:".repeat(20),
                       "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1", "FE80::DEAD",
                       "999.999.999.999", "01.02.03.04", "plume-daemon.service", "soc.example.com"] {
            v.push(longue.to_string());
        }
        v
    }

    /// MOITIÉ DÉMON DE (P1), BALAYÉE : toute chaîne qui satisfait (S) est REFUSÉE par le lecteur.
    /// Composée à la moitié AGENT (mesurée en CI sur le script livré), elle donne (P1) sans passer
    /// par un échantillon. Le témoin exige aussi sa propre NON-DÉGÉNÉRESCENCE dans les deux sens :
    /// assez de chaînes satisfont (S) pour que l'universel dise quelque chose, et assez ne la
    /// satisfont PAS et sont RETENUES — un lecteur qui refuserait tout passerait sinon sans rien
    /// prouver.
    #[test]
    fn la_contenance_est_derivee_d_une_borne_structurelle_pas_echantillonnee() {
        let mut sous_la_borne = 0usize;
        let mut retenues_hors_borne = 0usize;
        for c in balayage() {
            let verdict = lue(&format!("{c}\n"));
            if satisfait_la_borne_structurelle(&c) {
                sous_la_borne += 1;
                assert!(verdict.is_err(),
                        "`{c}` satisfait la borne structurelle (S) — donc `is_ip` peut l'accepter — \
                         et le démon la RETIENT comme un nom de service : (P1) est fausse, la liste \
                         d'épargne de l'exploitant redevient une allowlist `stop_service` muette");
            } else if verdict.is_ok() && !verdict.as_ref().unwrap().is_empty() {
                retenues_hors_borne += 1;
            }
        }
        assert!(sous_la_borne >= 1000,
                "INSTRUMENT : seulement {sous_la_borne} chaînes du balayage satisfont (S) — \
                 l'universel ne dit presque rien, ce témoin refuse de conclure");
        assert!(retenues_hors_borne >= 15000,
                "INSTRUMENT : seulement {retenues_hors_borne} chaînes hors (S) sont RETENUES — un \
                 lecteur qui refuse tout tiendrait (P1) sans rien prouver");
    }

    /// ET LE PRÉDICAT DU DÉMON EST EXACTEMENT (S) SUR LE BALAYAGE — c'est ce qui rend la composition
    /// légitime : sans cette égalité, la moitié ci-dessus serait plus faible que ce qu'elle annonce.
    #[test]
    fn le_classificateur_du_demon_est_exactement_la_borne_structurelle() {
        for c in balayage() {
            assert_eq!(ressemble_a_une_adresse(&c), satisfait_la_borne_structurelle(&c),
                       "`{c}` : le classificateur du démon a divergé de la borne structurelle (S) \
                        que l'en-tête du corpus publie et que la garde CI emploie de son côté — la \
                        composition des deux moitiés de (P1) ne tient plus");
        }
    }

    // =============================================================================================
    // `P4.7-b` (reprise) — LE RENDU TYPÉ SE DISAIT « JAMAIS PLUS PERMISSIF », ET IL L'ÉTAIT
    // =============================================================================================

    /// LA PHRASE ÉTAIT INVERSÉE, ET SUR LA SEULE PROPRIÉTÉ QUI JUSTIFIE `Slot::target_ok`.
    /// Le premier jet de `P4.7-b` a écrit : « `Slot::Pid`/`Slot::Service` restent des miroirs de
    /// charset écrits ici — plus étroits que la validation amont (`p > 0` contre `p > 300`), donc
    /// jamais plus permissifs qu'elle. » `p > 0` accepte 1..=300 que `p > 300` REFUSE : le miroir
    /// était STRICTEMENT PLUS PERMISSIF. Aucun chemin livré ne passait (`respond_run` valide avant
    /// de rendre), mais `target_ok` existe précisément pour le rendu appelé ISOLÉMENT.
    /// CE TÉMOIN TIENT LA PROPRIÉTÉ, PAS LA PHRASE : une cible que la validation amont refuse pour
    /// une raison de FORME ne peut pas être rendue en commande native, sur aucune plateforme.
    #[test]
    fn le_rendu_type_n_est_jamais_plus_permissif_que_la_validation_amont() {
        use crate::handlers::actions::{action_valid_ctx, cible_de_forme_portable, platform_command};
        let grille: &[(&str, &str)] = &[
            ("kill_pid", "1"), ("kill_pid", "42"), ("kill_pid", "300"), ("kill_pid", "301"),
            ("kill_pid", "5150"), ("kill_pid", "-1"), ("kill_pid", "0"), ("kill_pid", "abc"),
            ("kill_pid", ""), ("stop_service", ""), ("stop_service", "nginx.service"),
            ("stop_service", "a b"), ("stop_service", &"x".repeat(101)),
            ("ban_ip", "203.0.113.7"), ("ban_ip", "2001:db8::1"), ("ban_ip", "::1"),
            ("ban_ip", ""), ("unban_ip", "2001:db8::1"), ("unban_ip", "198.51.100.9"),
        ];
        let mut refus_de_forme = 0usize;
        let mut rendus = 0usize;
        for (kind, target) in grille {
            let amont = action_valid_ctx(kind, target, false, "");
            let forme = cible_de_forme_portable(kind, target);
            // ① LA BORNE DE FORME EST CONTENUE DANS LA VALIDATION AMONT : elle n'accepte jamais ce
            //    que l'amont refuse pour une raison de forme. C'est la clause que `p > 0` violait.
            if !forme {
                refus_de_forme += 1;
                assert!(amont.is_err(),
                        "`{kind}`/`{target}` : la borne de forme refuse et la validation amont \
                         accepte — le rendu serait plus STRICT que l'exécution, ce qui casserait \
                         une riposte légitime");
            }
            // ② ET LE RENDU NATIF SUIT LA BORNE DE FORME, SUR TOUTE PLATEFORME NON-LINUX (le chemin
            //    linux ne passe pas par un gabarit typé).
            for plateforme in ["windows", "pfsense"] {
                let rendu = platform_command(plateforme, kind, target, "nft", "sshd", None);
                if !forme {
                    assert!(rendu.is_err(),
                            "{plateforme} : `{kind}`/`{target}` a été RENDU en commande native alors \
                             que la borne de forme le refuse — c'est la phrase « jamais plus \
                             permissif que la validation amont » prise en défaut");
                } else if rendu.is_ok() {
                    rendus += 1;
                }
            }
        }
        // TÉMOIN INVERSE, INDISPENSABLE : un `target_ok` qui refuserait TOUT tiendrait ① sans rien
        // prouver — il aurait simplement supprimé le rendu par gabarit.
        assert!(refus_de_forme >= 6, "INSTRUMENT : {refus_de_forme} refus de forme exercés — trop peu");
        assert!(rendus >= 8, "INSTRUMENT : {rendus} rendus réussis — le rendu typé ne rend plus rien");
        // LA BORNE QUI ÉTAIT FAUSSE, NOMMÉE : un PID sous le plancher de sûreté ne se rend plus.
        assert!(platform_command("windows", "kill_pid", "1", "nft", "sshd", None).is_err(),
                "`taskkill /PID 1 /F` a été rendu : le miroir `p > 0` est revenu");
        assert!(platform_command("pfsense", "kill_pid", "300", "nft", "sshd", None).is_err(),
                "`kill -TERM 300` a été rendu : le plancher de sûreté n'est pas celui de l'amont");
        assert!(platform_command("pfsense", "kill_pid", "301", "nft", "sshd", None).is_ok(),
                "le plancher a été resserré au-delà de l'amont : une riposte légitime est bloquée");
    }

    /// ET LA SÉPARATION QUE `cible_de_forme_portable` PORTE EST BIEN CELLE QU'ELLE ANNONCE : la
    /// FORME d'un côté, la POLITIQUE de l'autre. Sans ce témoin, `run_playbooks` compterait un jour
    /// les IP protégées comme des abandons — c'est-à-dire un bilan de tick que personne ne lirait.
    #[test]
    fn la_borne_de_forme_ne_dit_rien_de_la_politique() {
        use crate::handlers::actions::{action_valid_ctx, cible_de_forme_portable};
        // POLITIQUE : bien formée, refusée quand même (plage réservée). La forme dit OUI.
        for protegee in ["10.0.0.1", "192.168.1.254", "127.0.0.1"] {
            assert!(cible_de_forme_portable("ban_ip", protegee),
                    "`{protegee}` : la borne de FORME refuse une IPv4 bien formée — elle a absorbé \
                     la politique, et le bilan du tick va compter les IP privées");
            assert!(action_valid_ctx("ban_ip", protegee, false, "").is_err(),
                    "`{protegee}` n'est plus protégée du ban : garde M2 perdue");
        }
        // FORME : le produit ne sait pas porter la cible. C'est CELA qui se compte.
        for hors_capacite in ["2001:db8::66", "::1", "fe80::1"] {
            assert!(!cible_de_forme_portable("ban_ip", hors_capacite),
                    "`{hors_capacite}` est devenue portable : la borne d'enforcement a été élargie \
                     à l'IPv6, ce que ce lot s'interdit");
        }
        assert!(!cible_de_forme_portable("action_inconnue", "203.0.113.7"),
                "une action hors vocab fermé n'a AUCUN gabarit : rien ne peut en partir");
    }


    // =============================================================================================
    // `P4.7-d` — UNE RIPOSTE QUE LE PRODUIT NE SAIT PAS PORTER ÉTAIT JETÉE SANS UN CHIFFRE
    //
    // CE QUI ÉTAIT MESURÉ, ET C'EST LA MOITIÉ QUE `P4.7-b` NE FERMAIT PAS. `extract_src_ip` garde un
    // IPv6 nu ENTIER : `2001:db8::66` arrive donc dans `event.src_ip`, un playbook `ban_ip` en mode
    // actif le sélectionne — et `run_playbooks` faisait `if … action_valid(…).is_err() { continue }`
    // SANS incrémenter `abandonnes`, alors que ce compteur EST le bilan rendu du tick et qu'il est
    // incrémenté sept fois ailleurs dans le même bloc. Résultat : aucune ligne dans `action`, aucun
    // compteur, un tick VERT sur une réponse qui n'est jamais partie, et rien qui distingue « aucune
    // cible » de « cible jetée ».
    // LE TÉMOIN INVERSE EST INDISPENSABLE ET IL PORTE L'ARBITRAGE : une cible BIEN FORMÉE que la
    // POLITIQUE refuse (IP protégée) ne se compte PAS. Compter les deux ferait du bilan du tick un
    // compteur d'IP privées — un chiffre que personne ne lirait plus, c'est-à-dire le même défaut
    // sous une autre forme.
    // =============================================================================================

    /// Arme une base neuve avec UN playbook dû dont la requête rend la cible voulue, puis rend le
    /// bilan du tick et le nombre d'actions posées.
    fn tick_de_playbook(etiquette: &str, kind: &str, cible: &str) -> (crate::mesure_environnement::Mesure<u32>, i64) {
        use std::sync::Arc;
        let tmp = crate::tmp_possede::TmpPossede::neuf(etiquette);
        let chemin = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let db = Arc::new(parking_lot::Mutex::new(crate::db_open::open_db(&chemin).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(crate::migrate::migrate(&conn));
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES(?1,1,?2,0,?3,0,3600,0,NULL,'admin')",
                rusqlite::params![etiquette, format!("SELECT '{cible}'"), kind],
            ).unwrap();
        }
        let bilan = crate::handlers::playbooks::run_playbooks(&db, &chemin);
        let posees: i64 = db.lock()
            .query_row("SELECT COUNT(*) FROM action WHERE reason=?1", rusqlite::params![format!("playbook:{etiquette}")], |r| r.get(0))
            .unwrap();
        (bilan, posees)
    }

    /// LE DÉFAUT : une cible IPv6 sélectionnée par un playbook `ban_ip`. Rien ne part, rien n'est
    /// posé — et le bilan doit le DIRE, au lieu de publier « 0 abandon ».
    #[test]
    fn une_cible_hors_capacite_est_comptee_au_bilan_du_tick_et_non_jetee_en_silence() {
        use crate::mesure_environnement::Mesure;
        let (bilan, posees) = tick_de_playbook("p47c-ipv6", "ban_ip", "2001:db8::66");
        assert_eq!(posees, 0, "INSTRUMENT : une action a été posée sur une cible IPv6 — la borne \
                               d'enforcement aurait été élargie");
        assert_eq!(bilan, Mesure::Lue(1),
                   "une riposte `ban_ip` sur une `src_ip` IPv6 — que l'ingestion garde ENTIÈRE — a \
                    été jetée sans un chiffre : le tick publie « 0 abandon » sur une réponse qui \
                    n'est jamais partie, et l'exploitant ne peut pas distinguer « aucune cible » de \
                    « cible jetée »");
        // La même chose sur l'autre borne de forme : un PID sous le plancher de sûreté.
        let (bilan_pid, posees_pid) = tick_de_playbook("p47c-pid", "kill_pid", "42");
        assert_eq!(posees_pid, 0, "INSTRUMENT : un kill a été posé sur un PID sous le plancher");
        assert_eq!(bilan_pid, Mesure::Lue(1),
                   "un `kill_pid` sous le plancher de sûreté est jeté sans un chiffre");
    }

    /// TÉMOIN INVERSE ① — LA POLITIQUE NE SE COMPTE PAS. Une IPv4 bien formée mais PROTÉGÉE est
    /// refusée délibérément, la détection continue, rien n'est perdu : le bilan reste un VRAI zéro.
    /// Sans ce témoin, « compter tout ce que `action_valid` refuse » passerait pour la correction.
    #[test]
    fn une_cible_refusee_par_la_politique_ne_gonfle_pas_le_bilan_du_tick() {
        use crate::mesure_environnement::Mesure;
        let (bilan, posees) = tick_de_playbook("p47c-protegee", "ban_ip", "10.0.0.1");
        assert_eq!(posees, 0, "INSTRUMENT : une IP protégée a été mise en file — garde M2 perdue");
        assert_eq!(bilan, Mesure::Lue(0),
                   "une IP PROTÉGÉE est comptée comme un abandon : le bilan du tick devient un \
                    compteur d'IP privées, et le chiffre qui disait « une riposte s'est perdue » ne \
                    veut plus rien dire");
    }

    /// TÉMOIN INVERSE ② — LE CHEMIN NOMINAL POSE ENCORE. Un `ban_ip` sur une IPv4 publique : action
    /// posée, bilan à zéro. Un correctif qui compterait (ou jetterait) tout échouerait ici.
    #[test]
    fn une_riposte_portable_est_posee_et_le_bilan_reste_un_vrai_zero() {
        use crate::mesure_environnement::Mesure;
        let (bilan, posees) = tick_de_playbook("p47c-nominal", "ban_ip", "203.0.113.7");
        assert_eq!(posees, 1, "la riposte nominale n'est plus posée : le correctif a cassé le chemin");
        assert_eq!(bilan, Mesure::Lue(0), "rien n'a été abandonné, le bilan doit être un vrai zéro");
    }

}
