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
//     comme une liste de services qui ne contient jamais rien. Le critère est DÉRIVÉ du prédicat
//     d'adresse que le produit emploie déjà pour la cible d'un ban (`ressemble_a_une_adresse`),
//     pas d'une liste de mots ;
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
// =================================================================================================
#[cfg(test)]
mod allowlist_du_responder_tests {
    use crate::handlers::actions::{allowlist_stop_service, ressemble_a_une_adresse};
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

    /// LE PRÉDICAT PARTAGÉ, ET SA FRONTIÈRE. C'est lui qui décide ce qui est « de l'autre
    /// politique » ; s'il dérivait, les deux lecteurs se remettraient à se croire. Les deux sens sont
    /// exercés — un nom d'unité n'est jamais une adresse, une adresse en est toujours une.
    #[test]
    fn le_predicat_d_adresse_separe_les_deux_politiques_dans_les_deux_sens() {
        for unite in ["nginx.service", "sshd.service", "containerd.service", "plume-daemon.service",
                      "dev-sda.device", "var-lib.mount", "cafe.socket", "add.timer"] {
            assert!(!ressemble_a_une_adresse(unite),
                    "`{unite}` est un nom d'unité systemd et serait pris pour une adresse : \
                     l'allowlist du central serait refusée à tort");
        }
        for adresse in ["203.0.113.7", "10.0.0.1", "192.168.1.254", "::ffff:203.0.113.7"] {
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
    /// ce témoin l'ÉPINGLE — les deux lecteurs promettent le même critère, il faut que les deux le
    /// tiennent, y compris sur un fichier que personne ne termine.
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

}
