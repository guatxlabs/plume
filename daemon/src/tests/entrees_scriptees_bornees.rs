// =================================================================================================
// `P4.6-a` / `P4.6-b` — LES DEUX BORNES DE L'ENTRÉE SCRIPTÉE COUPENT EN LE DISANT
//
// LE DÉFAUT, MESURÉ SUR L'ARBRE le 2026-08-27 avec `collectors/custom.sh` TEL QU'IL ÉTAIT LIVRÉ :
//   (a) SANS BORNE DE DURÉE. La commande déclarée par l'exploitant était exécutée par `sh -c` et le
//       capteur ATTENDAIT sa sortie, sans minuterie ; son unit est un `oneshot` qui ne pose pas de
//       délai propre. Avec `CMD=sh -c 'echo debut; sleep 300'` : le capteur ne rendait PAS la main
//       (tué à 8 s par le harnais) et le spool restait VIDE — la ligne `debut`, pourtant lue,
//       n'était jamais publiée, pendant que le timer réarmait à la minute.
//   (b) PLAFOND MUET. Avec `CMD=seq 1 10` et `MAX=3` : 3 événements publiés, 7 lignes jetées, AUCUN
//       aveu, code de sortie 0. Rien ne distinguait cette source tronquée d'une source calme.
//   (c) BORNE MAL ÉCRITE = ENTRÉE PERDUE. `MAX=deux` faisait échouer `head` ; le code de retour d'un
//       tube étant celui de son DERNIER maillon, le capteur sortait en 0 avec un spool VIDE.
//
// POURQUOI CES TÉMOINS SONT ICI ET PAS DANS UNE GARDE `.github/scripts/`. Le geste manquant est un
// geste d'EXÉCUTION : il faut lancer le capteur et regarder ce qu'il écrit. Aucune garde câblée du
// dépôt n'a `custom.sh` dans sa population dérivée — `check_collector_reads_are_honest.py` ne porte
// que sur les capteurs qui AFFIRMENT un nombre (enveloppe `metrics` ou battement), et `custom.sh`
// n'émet que ce qu'il a vu ; `check_read_failure_is_not_acknowledged.py` ne porte que sur ceux qui
// mettent un MARQUEUR en attente, et `custom.sh` n'en met aucun. Écrire une garde neuve aurait exigé
// une strophe de CI, que ce lot n'a pas le droit d'écrire, et une garde non câblée ne refuse rien.
// La suite du démon, elle, est exécutée par la CI : c'est le seul témoin ARMÉ disponible.
//
// CE QUE CES TÉMOINS NE PROUVENT PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU :
//   * ils exercent le capteur sur CETTE machine, avec `sh`/`awk`/`timeout` réels. Ils ne bornent pas
//     ce qu'un autre `awk` ferait d'une ligne portant des octets NUL (le tube en aval les retire de
//     toute façon, `tr -d '\000-\037'`) ;
//   * ils ne disent rien de l'unit systemd ni de la cadence : seul le SCRIPT est exercé ;
//   * si l'un des utilitaires manque, ils REFUSENT DE CONCLURE au lieu de rendre vert.
// =================================================================================================
#[cfg(test)]
mod entrees_scriptees_bornees_tests {
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    fn racine_du_depot() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("INSTRUMENT : le crate n'a pas de répertoire parent")
            .to_path_buf()
    }

    /// VALIDATION DE L'INSTRUMENT : sans ces utilitaires, le capteur ne peut pas tourner du tout et un
    /// « aucun aveu » ne prouverait rien. On ne rend pas vert : on refuse de conclure.
    fn outils_presents() -> Result<(), String> {
        for outil in ["sh", "awk", "timeout", "seq", "cksum", "paste", "cut", "tr", "mktemp"] {
            let trouve = std::env::var("PATH")
                .unwrap_or_default()
                .split(':')
                .any(|d| !d.is_empty() && Path::new(d).join(outil).exists());
            if !trouve {
                return Err(format!("`{outil}` introuvable sur le PATH"));
            }
        }
        Ok(())
    }

    /// LE BAC À SABLE SE POSSÈDE : `TmpPossede` efface son répertoire RÉCURSIVEMENT à la
    /// destruction — y compris les temporaires que le capteur y crée sous des noms que personne
    /// n'a écrits ici (les `.xx.XXXXXX` de `spool_write`). C'est la fixture du dépôt, pas une
    /// racine temporaire empruntée : `build.rs` refuse la seconde.
    struct Bac {
        racine: crate::tmp_possede::TmpPossede,
    }

    impl Bac {
        fn neuf(nom: &str) -> Bac {
            let racine = crate::tmp_possede::TmpPossede::neuf(nom);
            for sous in ["inputs.d", "spool", "state"] {
                std::fs::create_dir_all(racine.join(sous)).expect("INSTRUMENT : bac à sable non créé");
            }
            Bac { racine }
        }

        fn declare(&self, contenu: &str) {
            std::fs::write(self.racine.join("inputs.d/t.input"), contenu)
                .expect("INSTRUMENT : déclaration non écrite");
        }

        /// UN `PATH` FABRIQUÉ D'OÙ UN SEUL UTILITAIRE EST ABSENT — DÉRIVÉ, JAMAIS ÉNUMÉRÉ.
        /// On lie TOUT ce que le `PATH` réel expose, sauf le nom demandé. Énumérer les utilitaires
        /// nécessaires serait une liste à tenir : la première tentative de ce témoin a échoué deux
        /// fois (`chmod` puis `sync` manquants) avant qu'on cesse d'énumérer.
        /// Rend `None` si l'outil à retirer n'est PAS sur le `PATH` réel : le témoin ne prouverait
        /// alors rien, et il doit le DIRE plutôt que rendre vert.
        fn path_sans(&self, outil: &str) -> Option<String> {
            let bin = self.racine.join("bin-sans-".to_owned() + outil);
            std::fs::create_dir_all(&bin).expect("INSTRUMENT : répertoire de PATH non créé");
            let reel = std::env::var("PATH").unwrap_or_default();
            let mut vu_l_outil = false;
            for rep in reel.split(':').filter(|d| !d.is_empty()) {
                let Ok(entrees) = std::fs::read_dir(rep) else { continue };
                for e in entrees.filter_map(|e| e.ok()) {
                    let nom = e.file_name();
                    let nom = nom.to_string_lossy();
                    if nom == outil {
                        vu_l_outil = true;
                        continue;
                    }
                    let cible = bin.join(nom.as_ref());
                    if !cible.exists() {
                        let _ = std::os::unix::fs::symlink(e.path(), &cible);
                    }
                }
            }
            if !vu_l_outil {
                return None;
            }
            Some(bin.to_string_lossy().into_owned())
        }

        /// Lance le capteur TEL QU'IL EST LIVRÉ. L'environnement est passé au processus fils, JAMAIS
        /// posé dans celui de la suite (une variable globale mutée casserait les tests voisins).
        /// Le cas COURANT : le capteur DOIT rendre la main. S'il ne la rend pas, ce n'est pas un
        /// verdict à interpréter — c'est le défaut que tout ce module poursuit, et on le dit.
        fn joue(&self) -> (std::process::ExitStatus, u128) {
            let (etat, ms) = self.joue_avec_path(
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()));
            match etat {
                Some(e) => (e, ms),
                None => panic!("LA MAIN N'EST PAS RENDUE : le capteur tournait encore après {ms} ms \
                                et a dû être tué avec tout son groupe de processus"),
            }
        }

        /// LE CAPTEUR EST LANCÉ SOUS UN DÉLAI, ET C'EST UNE LEÇON DE CE LOT.
        ///
        /// La première écriture de ces témoins appelait `status()`, qui ATTEND. Sous la mutation qui
        /// remet l'ancien `awk` (celui qui lit tout le surplus), le capteur ne rend jamais la main
        /// sur `CMD=yes` : le témoin ne devenait pas ROUGE, il PENDAIT — mesuré, une suite tuée à
        /// 10 minutes. Un témoin qui pend est pire qu'un témoin absent : il ne dit rien et il bloque
        /// tout le monde. Le capteur tourne donc dans SON PROPRE GROUPE DE PROCESSUS, et le groupe
        /// entier est tué au délai — sans quoi `yes` et `awk`, petits-enfants du shell, survivraient
        /// à la mort de leur parent.
        ///
        /// LE DÉLAI EST DÉRIVÉ, PAS CHOISI : la plus longue attente LÉGITIME de ce module est le
        /// `sleep 3` de `la_borne_retiree_explicitement_ne_coupe_pas_et_n_avoue_rien` (borne retirée
        /// par l'exploitant). Le délai vaut six fois cela. Il ne sert jamais de verdict : il rend
        /// `None`, et c'est l'appelant qui dit ce que `None` signifie pour LUI.
        const DELAI_MAX_MS: u128 = 18_000;

        fn joue_avec_path(&self, path: String) -> (Option<std::process::ExitStatus>, u128) {
            use std::os::unix::process::CommandExt;
            let depart = Instant::now();
            let mut enfant = std::process::Command::new("sh")
                .arg(racine_du_depot().join("collectors/custom.sh"))
                .env_clear()
                .env("PATH", path)
                .env("PLUME_LIB", racine_du_depot().join("collectors/lib.sh"))
                .env("PLUME_INPUTS_DIR", self.racine.join("inputs.d"))
                .env("PLUME_SPOOL", self.racine.join("spool"))
                .env("PLUME_STATE", self.racine.join("state"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .spawn()
                .expect("INSTRUMENT : le capteur n'a pas pu être lancé");
            let pgid = enfant.id() as i32;
            loop {
                match enfant.try_wait().expect("INSTRUMENT : attente du capteur impossible") {
                    Some(etat) => return (Some(etat), depart.elapsed().as_millis()),
                    None => {
                        if depart.elapsed().as_millis() >= Self::DELAI_MAX_MS {
                            // Le GROUPE, pas le seul shell : `yes` et `awk` sont ses enfants.
                            unsafe { libc::kill(-pgid, libc::SIGKILL) };
                            let _ = enfant.wait();
                            return (None, depart.elapsed().as_millis());
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                }
            }
        }

        /// Le contenu de chaque enveloppe publiée, indexé par nom de fichier.
        fn spool(&self) -> Vec<(String, String)> {
            let mut sortie: Vec<(String, String)> = std::fs::read_dir(self.racine.join("spool"))
                .expect("INSTRUMENT : spool illisible")
                .filter_map(|e| e.ok())
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        std::fs::read_to_string(e.path()).unwrap_or_default(),
                    )
                })
                .collect();
            sortie.sort();
            sortie
        }

        /// Les clés de dédoublonnage des aveux publiés — ce que le central regarde pour décider
        /// qu'un aveu est le MÊME que le précédent.
        fn cles_d_aveu(&self) -> Vec<String> {
            let mut cles: Vec<String> = self
                .aveux()
                .iter()
                .filter_map(|c| {
                    let i = c.find("\"dedup\":\"")? + 9;
                    let reste = &c[i..];
                    Some(reste[..reste.find('"')?].to_string())
                })
                .collect();
            cles.sort();
            cles.dedup();
            cles
        }

        /// Les aveux de disponibilité — le canal sur lequel la règle livrée alerte.
        fn aveux(&self) -> Vec<String> {
            self.spool()
                .into_iter()
                .filter(|(n, _)| n.starts_with("config-availability-"))
                .map(|(_, c)| c)
                .collect()
        }

        /// Les événements de la source, dans l'ordre où ils ont été composés.
        fn evenements(&self) -> Vec<String> {
            self.spool()
                .into_iter()
                .filter(|(n, _)| n.starts_with("custom-"))
                .flat_map(|(_, c)| {
                    c.split("\"category\":\"custom\"")
                        .skip(1)
                        .map(|m| m.to_string())
                        .collect::<Vec<_>>()
                })
                .collect()
        }
    }

    // ---------------------------------------------------------------------------------------------
    // `P4.6-b` — LE PLAFOND COMPTE CE QU'IL ÉCARTE, ET LE DIT
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn le_plafond_par_passage_avoue_la_troncature_avec_son_compte() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("plafond");
        bac.declare("SOURCE=t\nCMD=seq 1 10\nMAX=3\n");
        let (etat, _) = bac.joue();
        assert!(etat.success(), "le capteur doit sortir en 0 : une troncature n'est pas une panne d'unit");

        let evenements = bac.evenements();
        assert_eq!(
            evenements.len(), 3,
            "LE PLAFOND DOIT TOUJOURS BORNER : 3 événements attendus pour MAX=3 sur 10 lignes"
        );

        let aveux = bac.aveux();
        assert_eq!(aveux.len(), 1, "un aveu et un seul : la troncature est un fait, pas un flot");
        let aveu = &aveux[0];
        // LE CANAL : c'est `collect_status=unavailable` que la règle livrée
        // `de-collector-unavailable.json` interroge. Un aveu qui ne le porterait pas n'alerterait
        // personne — il serait une ligne de configuration au milieu des autres.
        assert!(aveu.contains("\"collect_status\":\"unavailable\""),
                "l'aveu n'emprunte pas le canal sur lequel la règle livrée alerte : {aveu}");
        assert!(aveu.contains("\"reason\":\"collection-capped\""),
                "la cause n'est pas dans le vocabulaire fermé attendu : {aveu}");
        assert!(aveu.contains("plafond-de-lignes"), "la BORNE qui a coupé n'est pas nommée : {aveu}");
        // LA GRANDEUR, ET C'EST ELLE QUI MANQUAIT : 10 lignes produites, 3 publiées, 7 écartées.
        assert!(aveu.contains("7 ligne(s) écartée(s)"),
                "le NOMBRE de lignes écartées n'est pas rendu — « j'ai tronqué » sans chiffre laisse \
                 dimensionner à l'aveugle : {aveu}");
        // L'IMPUTATION : l'aveu porte le nom de LA source tronquée, pas celui du capteur générique.
        assert!(aveu.contains("\"source\":\"t\""),
                "l'aveu ne s'impute pas à la source tronquée : sa pastille ne basculerait pas : {aveu}");
    }

    /// TÉMOIN INVERSE, ET IL EST INDISPENSABLE. Sans lui, un capteur qui avouerait une troncature à
    /// CHAQUE passage — y compris quand il n'a rien coupé — passerait le témoin précédent
    /// brillamment, et l'aveu cesserait de vouloir dire quoi que ce soit.
    #[test]
    fn sans_troncature_le_capteur_n_avoue_rien_et_publie_tout() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("sans-troncature");
        bac.declare("SOURCE=t\nCMD=seq 1 10\nMAX=100\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        assert_eq!(bac.evenements().len(), 10, "les 10 lignes doivent être publiées sous le plafond");
        assert!(bac.aveux().is_empty(),
                "AUCUN aveu ne doit partir quand rien n'a été coupé : {:?}", bac.aveux());
    }

    // ---------------------------------------------------------------------------------------------
    // `P4.6-a` — LA COMMANDE DE L'EXPLOITANT EST BORNÉE EN DURÉE, ET LA COUPURE SE DIT
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn une_commande_qui_ne_se_termine_pas_est_coupee_et_la_coupure_est_dite() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("borne-duree");
        // La forme EXACTE que le document d'accueil donnait en exemple : émettre, puis suivre un flux.
        bac.declare("SOURCE=t\nCMD=sh -c 'echo debut; sleep 20'\nTIMEOUT=1\n");
        let (etat, duree_ms) = bac.joue();
        assert!(etat.success(), "une coupure à la borne n'est pas une panne d'unit");
        assert!(duree_ms < 10_000,
                "LA MAIN N'EST PAS RENDUE : {duree_ms} ms pour une borne de 1 s — la commande n'est \
                 pas bornée, et le capteur reste aveugle pendant qu'il attend");
        // CE QUI AVAIT ÉTÉ LU EST PUBLIÉ : avant, la ligne `debut` mourait avec le processus tué.
        let evenements = bac.evenements();
        assert_eq!(evenements.len(), 1, "la ligne déjà émise doit être publiée : {evenements:?}");
        assert!(evenements[0].contains("debut"), "ce n'est pas la ligne lue : {evenements:?}");
        let aveux = bac.aveux();
        assert_eq!(aveux.len(), 1, "la coupure doit être avouée, une fois : {aveux:?}");
        assert!(aveux[0].contains("\"reason\":\"collection-capped\"") && aveux[0].contains("borne-de-duree"),
                "la coupure n'est pas nommée comme une borne de DURÉE : {}", aveux[0]);
    }

    /// TÉMOIN INVERSE DE LA BORNE : `TIMEOUT=0` la retire, et c'est un choix EXPLICITE de
    /// l'exploitant. Il prouve deux choses d'un coup — que c'est bien la borne qui rend la main (le
    /// même capteur, la même commande, sans elle, attend la fin), et qu'on n'avoue pas une coupure
    /// qui n'a pas eu lieu.
    #[test]
    fn la_borne_retiree_explicitement_ne_coupe_pas_et_n_avoue_rien() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("borne-retiree");
        bac.declare("SOURCE=t\nCMD=sh -c 'echo debut; sleep 3'\nTIMEOUT=0\n");
        let (etat, duree_ms) = bac.joue();
        assert!(etat.success());
        assert!(duree_ms >= 2_500,
                "MUTATION INOPÉRANTE : sans borne, le capteur aurait dû attendre la fin de la \
                 commande ({duree_ms} ms) — si ce n'est pas le cas, ce n'est pas la borne que le \
                 témoin précédent mesure");
        assert!(bac.aveux().is_empty(),
                "aucune coupure n'a eu lieu, rien ne doit être avoué : {:?}", bac.aveux());
        assert_eq!(bac.evenements().len(), 1);
    }

    // ---------------------------------------------------------------------------------------------
    // UNE BORNE MAL ÉCRITE NE FAIT PLUS DISPARAÎTRE L'ENTRÉE
    // ---------------------------------------------------------------------------------------------

    #[test]
    fn une_borne_non_entiere_retombe_sur_son_defaut_et_le_dit() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("borne-non-entiere");
        bac.declare("SOURCE=t\nCMD=seq 1 4\nMAX=deux\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        assert_eq!(bac.evenements().len(), 4,
                   "l'entrée ENTIÈRE disparaissait quand la borne n'était pas un entier");
        let aveux = bac.aveux();
        assert_eq!(aveux.len(), 1, "le repli sur le défaut doit être dit : {aveux:?}");
        assert!(aveux[0].contains("\"reason\":\"missing-config\""),
                "un réglage illisible est un défaut de CONFIGURATION, et il se nomme : {}", aveux[0]);
        // BORNE ÉCRITE, PARCE QU'ELLE COÛTE : cet aveu emprunte `collect_status=unavailable`, donc la
        // règle livrée `de-collector-unavailable` ALERTE et la pastille de la source BASCULE — alors
        // que la source est INTÉGRALEMENT collectée (les 4 événements ci-dessus). Le mot dit une
        // incapacité qui n'a pas eu lieu. Le corriger demande un `collect_status` que `docs/CIM.md`
        // ne déclare pas — donc le contrat, le démon et les règles livrées : hors de la zone de ce
        // lot. Ce témoin ÉPINGLE le fait pour qu'il ne se perde pas.
        assert_eq!(bac.evenements().len(), 4,
                   "la source est collectée ENTIÈREMENT malgré l'aveu d'indisponibilité");
    }

    // ---------------------------------------------------------------------------------------------
    // LA DERNIÈRE LIGNE SANS SAUT DE LIGNE FINAL — MÊME FAMILLE QUE `collectors/respond.sh`
    // ---------------------------------------------------------------------------------------------

    /// LE DÉFAUT, MESURÉ le 2026-08-27 sur le capteur tel qu'il était livré : `while read` n'exécute
    /// PAS son corps sur une dernière ligne dépourvue de saut de ligne final. Une déclaration écrite
    /// `SOURCE=t\nCMD=seq 1 3` SANS `\n` terminal perdait donc sa dernière ligne ; `CMD` restait vide,
    /// l'entrée ENTIÈRE était écartée, et le capteur sortait en 0 avec un spool VIDE. Une source
    /// déclarée par l'exploitant ne collectait rien et ne le disait pas.
    #[test]
    fn une_declaration_sans_saut_de_ligne_final_est_lue_entierement() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("sans-saut-final");
        bac.declare("SOURCE=t\nCMD=seq 1 3");   // PAS de "\n" final : c'est tout le témoin
        let (etat, _) = bac.joue();
        assert!(etat.success());
        assert_eq!(bac.evenements().len(), 3,
                   "la DERNIÈRE ligne de la déclaration (CMD) n'a pas été lue : l'entrée entière \
                    disparaissait en silence. Aveux : {:?}", bac.aveux());
    }

    /// TÉMOIN NÉGATIF DU PRÉCÉDENT : la MÊME déclaration AVEC son saut de ligne final. Sans lui,
    /// « 3 événements » ne dirait pas que c'est le saut de ligne qui faisait la différence.
    #[test]
    fn la_meme_declaration_avec_saut_de_ligne_final_donne_le_meme_resultat() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("avec-saut-final");
        bac.declare("SOURCE=t\nCMD=seq 1 3\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        assert_eq!(bac.evenements().len(), 3);
    }

    // ---------------------------------------------------------------------------------------------
    // QUI BORNE L'EXÉCUTION QUAND LA BORNE DE DURÉE N'EST PAS ARMÉE
    // ---------------------------------------------------------------------------------------------

    /// LA RÉGRESSION QUE CE TÉMOIN FERME, MESURÉE le 2026-08-27 sur un `PATH` fabriqué SANS
    /// `timeout`, entrée `CMD=yes / MAX=3` :
    ///   AVANT ce lot (`head -n MAX`) — rc=0 en 37 ms, 3 événements publiés : `head` fermait le tube
    ///   et tuait la commande par SIGPIPE, si bien que le PLAFOND bornait aussi la DURÉE ;
    ///   PREMIER JET de `P4.6-a` (`awk` qui compte tout le surplus) — le capteur NE REND JAMAIS LA
    ///   MAIN (tué à 8 s), spool ne portant que l'aveu `missing-dependency`, ZÉRO événement.
    /// Le correctif de la clé produisait donc, sur cette population, exactement ce que la clé
    /// condamne. Le capteur ne lit plus le surplus quand rien ne borne la durée : il s'arrête à la
    /// MAX+1-ième ligne — assez pour ÉTABLIR la troncature, pas assez pour la COMPTER.
    #[test]
    fn sans_borne_de_duree_le_plafond_borne_encore_l_execution_et_l_avoue() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("sans-timeout");
        let Some(path) = bac.path_sans("timeout") else {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — `timeout` n'est pas sur le \
                    PATH réel : le retirer ne prouverait rien");
        };
        bac.declare("SOURCE=t\nCMD=yes\nMAX=3\n");
        let (etat, duree_ms) = bac.joue_avec_path(path);
        let Some(etat) = etat else {
            panic!("LA MAIN N'EST PAS RENDUE : le capteur tournait encore après {duree_ms} ms sur \
                    une commande INFINIE alors que la borne de durée n'est pas armée — le plafond \
                    ne borne plus l'exécution, et le capteur est aveugle pendant qu'il attend");
        };
        assert!(etat.success(), "une troncature n'est pas une panne d'unit");
        assert!(duree_ms < 5_000,
                "{duree_ms} ms sur une commande infinie sans borne de durée : le plafond ne borne \
                 plus l'exécution assez tôt");
        assert_eq!(bac.evenements().len(), 3, "le plafond doit toujours publier MAX lignes");
        let aveux = bac.aveux();
        assert!(aveux.iter().any(|a| a.contains("\"reason\":\"missing-dependency\"")),
                "l'absence de `timeout` doit être avouée : {aveux:?}");
        let tronq: Vec<&String> = aveux.iter().filter(|a| a.contains("collection-capped")).collect();
        assert_eq!(tronq.len(), 1, "la troncature doit être avouée, une fois : {aveux:?}");
        assert!(tronq[0].contains("plafond-de-lignes"), "la BORNE qui a coupé n'est pas nommée : {}", tronq[0]);
        assert!(tronq[0].contains("nombre inconnu"),
                "sans borne de durée le surplus n'est PAS lu : le nombre ne peut pas être connu, et \
                 écrire un zéro se lirait « rien de perdu » : {}", tronq[0]);
    }

    /// TÉMOIN NÉGATIF : la borne ARMÉE rend le compte EXACT. Sans lui, « nombre inconnu » pourrait
    /// devenir la réponse universelle, et la grandeur que `P4.6-b` ajoute disparaîtrait.
    #[test]
    fn avec_la_borne_armee_le_plafond_rend_le_compte_exact() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("compte-exact");
        bac.declare("SOURCE=t\nCMD=seq 1 10\nMAX=3\nTIMEOUT=5\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        let aveux = bac.aveux();
        assert_eq!(aveux.len(), 1, "un aveu et un seul : {aveux:?}");
        assert!(aveux[0].contains("7 ligne(s) écartée(s)"),
                "la borne est armée, le surplus est lu : le compte doit être EXACT : {}", aveux[0]);
    }

    // ---------------------------------------------------------------------------------------------
    // UN AVEU NE S'ÉCRIT QUE SUR CE QUI A ÉTÉ MESURÉ
    // ---------------------------------------------------------------------------------------------

    /// LE FAUX AVEU, MESURÉ le 2026-08-27 : entrée `CMD=sh -c "echo une-ligne; exit 124"` avec
    /// `TIMEOUT=0`. AUCUNE borne n'était armée et RIEN n'était tronqué, et le capteur publiait
    /// pourtant « COLLECTE TRONQUÉE (borne-de-duree) : nombre inconnu écartée(s) … coupée à
    /// TIMEOUT=0s (code 124) » — une phrase qui se contredit elle-même —, levait l'alerte livrée
    /// `de-collector-unavailable` et faisait basculer la pastille d'une source SAINE. 124 et 137
    /// sont des codes de sortie ordinaires pour une commande d'exploitant.
    #[test]
    fn un_code_124_sans_borne_armee_n_avoue_aucune_troncature() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("faux-aveu");
        bac.declare("SOURCE=t\nCMD=sh -c \"echo une-ligne; exit 124\"\nTIMEOUT=0\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        assert_eq!(bac.evenements().len(), 1, "la ligne émise doit être publiée");
        assert!(bac.aveux().is_empty(),
                "AUCUNE borne n'était armée et RIEN n'a été tronqué : le capteur ne doit rien \
                 avouer. Aveux : {:?}", bac.aveux());
    }

    // ---------------------------------------------------------------------------------------------
    // LA GRANDEUR EST DANS LE MESSAGE, PAS DANS LA CLÉ
    // ---------------------------------------------------------------------------------------------

    /// LE DÉFAUT, MESURÉ le 2026-08-27 : `_av_dd` prenait l'empreinte du DÉTAIL, donc du NOMBRE de
    /// lignes écartées. Quatre passages dans la même heure sur la même source (`seq 1 10`,
    /// `seq 1 10`, `seq 1 12`, `seq 1 15`, `MAX=3`) donnaient TROIS clés distinctes : le
    /// dédoublonnage horaire du central ne tenait que si le compte ne bougeait pas — c'est-à-dire
    /// presque jamais sur une source assez bavarde pour heurter son plafond. Jusqu'à 60 lignes par
    /// heure et par source sur un canal qui LÈVE UNE ALERTE.
    #[test]
    fn l_aveu_de_troncature_garde_sa_cle_quand_le_compte_change() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("cle-stable");
        for n in ["10", "12", "15"] {
            bac.declare(&format!("SOURCE=t\nCMD=seq 1 {n}\nMAX=3\nTIMEOUT=5\n"));
            let (etat, _) = bac.joue();
            assert!(etat.success());
        }
        let cles = bac.cles_d_aveu();
        // L'INSTRUMENT D'ABORD : sans aveu, « une seule clé » serait vrai et ne prouverait rien.
        assert!(!bac.aveux().is_empty(), "aucun aveu publié : ce témoin ne mesure rien");
        assert_eq!(cles.len(), 1,
                   "trois comptes différents dans la même heure doivent porter LA MÊME clé : {cles:?}");
        // ET LA GRANDEUR N'EST PAS PERDUE POUR AUTANT : elle vit dans le message.
        assert!(bac.aveux().iter().any(|a| a.contains("ligne(s) écartée(s)")),
                "le nombre a disparu du message : ce n'est plus le même aveu");
    }

    /// TÉMOIN NÉGATIF, ET IL EST INDISPENSABLE : une clé rendue constante PAR SOURCE ferait
    /// disparaître le second aveu quand les DEUX bornes coupent dans le même passage. Les deux faits
    /// n'appellent pas le même geste d'exploitant : ils doivent rester CUMULABLES.
    #[test]
    fn les_deux_bornes_gardent_deux_cles_distinctes_dans_le_meme_passage() {
        if let Err(pourquoi) = outils_presents() {
            panic!("INSTRUMENT INVALIDE, ce témoin REFUSE DE CONCLURE — {pourquoi}");
        }
        let bac = Bac::neuf("deux-bornes");
        bac.declare("SOURCE=t\nCMD=yes\nMAX=3\nTIMEOUT=1\n");
        let (etat, _) = bac.joue();
        assert!(etat.success());
        let aveux = bac.aveux();
        assert!(aveux.iter().any(|a| a.contains("plafond-de-lignes")),
                "le plafond a bien coupé, il doit être avoué : {aveux:?}");
        assert!(aveux.iter().any(|a| a.contains("borne-de-duree")),
                "la durée a bien coupé, elle doit être avouée : {aveux:?}");
        assert_eq!(bac.cles_d_aveu().len(), 2,
                   "les deux bornes doivent porter DEUX clés : sinon le second aveu s'efface");
    }
}
