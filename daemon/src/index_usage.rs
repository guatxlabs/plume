//! index_usage — QUELS INDEX LE PLANIFICATEUR NOMME VRAIMENT, ET POUR QUELLE CLASSE DE CONSOMMATEUR.
//!
//! CE QUI MANQUAIT, ET POURQUOI CE N'EST PAS UN CONFORT. L'index b-tree est un poste MAJEUR du
//! fichier, et le produit doit tenir sous 2 Gio. La première mesure d'usage (`P10.9-a`,
//! `tests/index_usage_event.rs`) rejoue `EXPLAIN QUERY PLAN` sur le corpus FERMÉ de ce que le produit
//! LIVRE — panneaux, règles, gabarits — et c'est un instrument utile. Mais son verdict porte deux
//! limites que rien, dans le produit, ne comblait :
//!
//!   ① LE CORPUS EST FERMÉ PAR CONSTRUCTION. Une requête d'analyste, une route non-GXQL, un rollup,
//!      une purge n'écrivent aucune ligne dans `rule`/`panel` : ils sont HORS du corpus. Un index que
//!      le corpus ne nomme pas peut donc être celui du chemin interactif le plus chaud.
//!   ② LE PLAN EST LU SOUS DES STATISTIQUES SYNTHÉTISÉES. Le rejeu écrit un `sqlite_stat1` déduit du
//!      profil de cardinalités ; il n'écrit AUCUNE statistique d'index DÉTAILLÉE (`sqlite_stat4`,
//!      c'est-à-dire des échantillons de valeurs par index). Or ce sont elles, et elles seules, qui
//!      estiment le rendement d'un prédicat de BORNE (`severity >= 3`, `ts >= …`) : sans elles le
//!      planificateur retombe sur une supposition fixe. Le verdict des index dont la colonne de tête
//!      n'est interrogée QUE par bornes est donc, dans le rejeu, le moins solide de tous — et c'est
//!      exactement le cas de l'unique candidat que la mesure fait ressortir.
//!
//! CE QUE CE MODULE FAIT, ET EN QUOI ÇA COMBLE LE TROU. Il lit le plan À L'EXÉCUTION, sur la base
//! DÉPLOYÉE, au POINT DE PASSAGE UNIQUE de toute lecture (`query_exec::run_on_conn`, emprunté aussi
//! par l'union chaud∪froid). À cet endroit le planificateur travaille avec les statistiques RÉELLES
//! de cette base — celles que `maintenance::analyze_full_background` produit, `sqlite_stat4` compris
//! quand la SQLite embarquée les porte. Le plan observé est donc celui qui a réellement servi, et non
//! celui qu'une approximation aurait fait choisir. Le module PUBLIE en outre le régime de
//! statistiques sous lequel il a lu (`plume_index_usage_stats_regime`) : un verdict lu sans
//! statistiques détaillées ne doit pas se lire comme un verdict lu avec.
//!
//! CE QU'IL NE PROUVE PAS — et c'est écrit dans le `# HELP` de la série, pas seulement ici, parce
//! qu'un lecteur de `/metrics` ne lit pas ce fichier (cf. `LIMITES`) :
//!   * un compteur à zéro dit « aucun énoncé ÉCHANTILLONNÉ, PENDANT CETTE OBSERVATION, n'a nommé cet
//!     index ». Il ne dit pas « cet index est inutile » : la requête trimestrielle d'un auditeur, un
//!     export annuel, une enquête d'incident ne tombent pas forcément dans la fenêtre d'observation ;
//!   * les compteurs sont EN MÉMOIRE et repartent de zéro à chaque redémarrage ;
//!   * l'échantillonnage 1/N ne voit qu'une part des énoncés : un index employé par un chemin RARE
//!     peut passer entre les mailles là où le chemin chaud, lui, sera vu ;
//!   * une charge de test ne prouve rien d'une charge réelle : ce que l'instrument mesure est la
//!     charge qu'on lui a donnée, jamais celle d'un autre déploiement ;
//!   * ET LE PLUS COÛTEUX DES QUATRE, parce qu'il a été appris en RÉFUTANT une lecture qu'on croyait
//!     acquise (`P10.9-a`, campagne du 2026-08-23) : un index ABSENT de la série n'a été nommé par
//!     aucun plan lu — la série ne porte QUE les index qu'un plan a nommés, donc le verdict se tire
//!     par SOUSTRACTION depuis la liste des index du schéma, jamais en cherchant des zéros. Et cette
//!     liste-là N'EST PAS UNE LISTE DE RETRAIT : l'hypothèse « ces index servent des surfaces que
//!     personne n'a ouvertes » a été mise à l'épreuve par une traversée délibérée de toutes les
//!     routes de lecture et RÉFUTÉE ; ce qui restait est que les tables concernées sont assez petites
//!     pour que le planificateur préfère un parcours complet. **Un observatoire d'usage ne sait pas
//!     distinguer « cet index ne sert à rien » de « cette table est trop petite pour qu'il serve ».**
//!     Il ne l'apprendra pas — ce n'est pas ce qu'il mesure. Ce qu'il peut faire, et fait désormais,
//!     c'est PUBLIER le chiffre qui laisse le lecteur trancher : `plume_index_usage_lignes_estimees`,
//!     l'estimation dont le planificateur s'est lui-même servi pour choisir.
//!
//! CE QUE ÇA COÛTE, ET POURQUOI C'EST BORNÉ.
//!   * ÉTEINT (défaut) : `Observatoire::observer` lit UN entier atomique et rend la main. Aucune
//!     préparation, aucune allocation, aucun accès à la base — et `exposition_prom` rend la chaîne
//!     VIDE tant qu'aucun plan n'a été lu, donc `/metrics` est inchangé octet pour octet.
//!   * ALLUMÉ : un `EXPLAIN QUERY PLAN` (une préparation de plus, quelques lignes lues) tous les N
//!     énoncés. C'est une PRÉPARATION, pas une exécution : elle ne touche aucune page de données.
//!     Le coût réel est MESURÉ par le test `le_cout_de_lobservation_est_mesure`, qui l'imprime au
//!     lieu de le promettre.
//!   * L'observation est faite APRÈS que la durée rendue à l'appelant a été arrêtée : elle ne peut
//!     pas gonfler la latence que l'analyste lit dans `stats.elapsed_ms`.
//!   * MÉMOIRE : un compteur par (index NOMMÉ par un plan) × (classe de consommateur), le registre
//!     étant PLAFONNÉ à `INDEX_CAP` étiquettes plus une de débordement. La cardinalité de `/metrics`
//!     ne dépend donc ni du nombre de requêtes ni de la taille du schéma. Une étiquette par requête
//!     serait non bornée ; il n'y en a pas.
//!
//! OÙ LA SÉRIE VIT, ET CE QUE CE CHOIX ÉCARTE. Elle est exposée sur `/metrics` et NULLE PART
//! AILLEURS : les compteurs vivent en mémoire et ne survivent pas à un redémarrage. C'est un choix, et
//! son contre-argument est déjà écrit dans ce dépôt (`ventilation_serie` : « le piège à éviter est la
//! jauge que personne ne collecte »). Il est retenu ici pour une raison qui ne vaut PAS pour la
//! ventilation : cet instrument est une CAMPAGNE, pas une série permanente — on l'allume pour observer
//! une charge sur une fenêtre choisie, on lit, on l'éteint. Une série permanente écrite dans `metric`
//! demanderait une voie d'écriture, une rétention et un plafond de cardinalité en base, pour une
//! mesure qu'on ne veut justement pas payer en continu. **Ce que cela coûte est réel et se dit** : une
//! fenêtre d'observation qui n'a pas couvert une requête rare la rendra invisible, et un redémarrage
//! efface le décompte. Une observation longue durée demanderait cette voie-là ; ce lot ne la construit
//! pas, et un verdict d'usage ne doit pas être tiré d'une fenêtre plus courte que la période de la
//! charge qu'on prétend juger.
//!
//! LE RÉGLAGE PASSE PAR `cfg()`, JAMAIS PAR `env::var`. `configurer` est appelée au démarrage avec la
//! configuration résolue (`env > PLUME_CONFIG > défaut`) : un opérateur d'hôte qui écrit la clé dans
//! son fichier de configuration obtient l'effet annoncé, ce qu'une lecture d'environnement nue ne
//! donnerait pas (garde `tests/partition_config.rs`).
use crate::*;
use parking_lot::RwLock;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

/// Le réglage, LU PAR LA VOIE CANONIQUE. `0` (défaut) = observatoire ÉTEINT : aucun plan lu, aucune
/// série publiée. `N > 0` = un plan lu tous les N énoncés de lecture exécutés.
pub(crate) const CLE_ECHANTILLON: &str = "PLUME_INDEX_USAGE_SAMPLE_N";
/// ÉTEINT PAR DÉFAUT. Un instrument de mesure qui s'allume tout seul est une dépense que personne n'a
/// décidée ; celui-ci se demande.
pub(crate) const ECHANTILLON_DEFAUT: u32 = 0;

/// PLAFOND DU REGISTRE D'ÉTIQUETTES. Le schéma livré porte moins de deux cents index toutes tables
/// confondues, et un plan n'en nomme qu'une poignée ; ce plafond n'est pas un confort, c'est ce qui
/// rend la cardinalité de `/metrics` INDÉPENDANTE du schéma — y compris des index d'expression que
/// `maintenance` crée depuis la configuration, dont le nombre n'est pas fixé par ce dépôt.
pub(crate) const INDEX_CAP: usize = 64;
/// L'étiquette des index vus AU-DELÀ du plafond : la mesure survit, son attribution non. Sans ce
/// seau, un plafond qui mord PERDRAIT des observations en silence.
pub(crate) const ETIQUETTE_DEBORDEMENT: &str = "(au-dela-du-plafond)";

/// TOUS LES COMBIEN DE PLANS LUS le catalogue est RECONSTATÉ. Le reconstat est NÉCESSAIRE :
/// l'analyse complète est une tâche de FOND lancée après le bind, donc les premiers énoncés d'un
/// démarrage sont lus sous des statistiques qui ne sont pas celles du régime de croisière, et un
/// régime figé à la première lecture mentirait pour tout le reste de la vie du processus. Mais il
/// interroge le catalogue : sans ce pas, il coûterait plus cher que la lecture de plan qu'il
/// accompagne.
///
/// DEUX GRANDEURS Y SONT CONSTATÉES, ET ELLES N'ONT PAS LA MÊME RÈGLE D'ARRÊT — c'est écrit ici parce
/// que la version précédente de cette phrase (« une fois le régime au maximum, il n'est plus
/// reconstaté du tout ») a cessé d'être vraie pour le pas lui-même :
///   * le RÉGIME ne peut que MONTER (`Aucune` -> `Agregees` -> `Detaillees`) : arrivé au maximum, il
///     n'est plus interrogé ;
///   * l'ESTIMATION DE LIGNES (`P10.9-a`) BOUGE dans les deux sens et continue donc d'être constatée
///     à chaque pas. Le coût du pas reste UNE petite interrogation du catalogue tous les
///     `PAS_DE_RECONSTAT_DU_REGIME` plans LUS, c'est-à-dire tous les `N x 64` énoncés observables.
pub(crate) const PAS_DE_RECONSTAT_DU_REGIME: u64 = 64;

/// LA TABLE dont le régime de statistiques est publié. C'est celle dont les index pèsent le poste
/// mesuré (`docs/DESIGN-P10-echelle-2go.md`) ; publier le régime de toutes les tables ferait une
/// étiquette par table sans rien apprendre de plus sur la décision en jeu.
pub(crate) const TABLE_OBSERVEE: &str = "event";

/// CE QUE LA SÉRIE NE PROUVE PAS — écrit ICI parce que c'est ce texte qui part dans le `# HELP`, donc
/// sous les yeux de qui lit le verdict, et pas seulement sous ceux de qui lit ce fichier.
pub(crate) const LIMITES: &str = "un zero dit qu'aucun enonce ECHANTILLONNE n'a nomme cet index PENDANT CETTE OBSERVATION, jamais que l'index est inutile (compteurs en memoire, remis a zero au redemarrage ; echantillonnage 1/N ; une charge de test ne prouve rien d'une charge reelle) ; et le verdict depend du regime de statistiques, cf. plume_index_usage_stats_regime. UN INDEX ABSENT de cette serie n'a ete nomme par aucun plan lu : le verdict se tire en soustrayant les index observes de la liste des index du SCHEMA, pas en cherchant des zeros ici. ET CETTE LISTE N'EST PAS UNE LISTE DE RETRAIT : un observatoire d'usage ne sait pas distinguer « cet index ne sert a rien » de « cette table est trop petite pour que le planificateur le prefere a un parcours complet », et sur une installation modeste c'est la seconde qui domine — cf. plume_index_usage_lignes_estimees, l'estimation dont le planificateur lui-meme se sert";

// =================================================================================================
// LE LECTEUR DE PLAN — UNE SEULE COPIE, PARTAGÉE PAR L'OBSERVATOIRE ET PAR LE REJEU DE TEST
//
// Une règle de lecture écrite deux fois finit par diverger, et c'est alors le tableau d'usage qui
// ment. Le rejeu du corpus fermé (`tests/index_usage_event.rs`) utilise CES fonctions-ci : ses deux
// témoins — chaque index forcé par `INDEXED BY` doit être LU, un balayage `NOT INDEXED` ne doit RIEN
// rendre — valident donc le lecteur que la production emploie, pas une copie qui lui ressemble.
// =================================================================================================

/// Ce qu'un plan d'exécution NOMME. Les index nommés d'un côté ; de l'autre les mentions SANS nom
/// (`AUTOMATIC …` = index transitoire construit pour la requête, `INTEGER PRIMARY KEY` = le rowid),
/// qu'il serait faux de compter comme un index du schéma et faux de jeter en silence.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanLu {
    pub(crate) index: BTreeSet<String>,
    pub(crate) sans_nom: BTreeSet<String>,
}

/// Extrait d'un `detail` d'`EXPLAIN QUERY PLAN` ce qui suit chaque ` USING `. Écrit à la main plutôt
/// qu'en regex parce que la forme est fixée par SQLite et tient en quatre cas :
///   `SEARCH event USING INDEX <nom> (…)` · `… USING COVERING INDEX <nom> (…)` ·
///   `… USING AUTOMATIC COVERING INDEX (…)` · `… USING INTEGER PRIMARY KEY (rowid=?)`.
pub(crate) fn lire_detail(detail: &str, dans: &mut PlanLu) {
    let mut reste = detail;
    while let Some(p) = reste.find(" USING ") {
        let apres = &reste[p + 7..];
        reste = apres;
        let apres = apres.strip_prefix("COVERING ").unwrap_or(apres);
        if let Some(q) = apres.strip_prefix("INDEX ") {
            let nom: String = q.chars().take_while(|c| !c.is_whitespace() && *c != '(').collect();
            if !nom.is_empty() {
                dans.index.insert(nom);
            }
        } else {
            // `AUTOMATIC COVERING INDEX`, `INTEGER PRIMARY KEY`, `ROWID SEARCH`… : pas un index du schéma.
            let jeton: String = apres.chars().take_while(|c| *c != '(').collect();
            dans.sans_nom.insert(jeton.trim().to_string());
        }
    }
}

/// Le plan de `sql`, LU. `Err` porte le refus de SQLite tel quel : un énoncé dont le planificateur
/// refuse le plan est un objet dont on NE PEUT PAS CONCLURE — jamais un objet « sans index ».
pub(crate) fn plan_de(conn: &Connection, sql: &str) -> Result<PlanLu, String> {
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).map_err(|e| e.to_string())?;
    let lignes: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(3))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut lu = PlanLu::default();
    for l in &lignes {
        lire_detail(l, &mut lu);
    }
    Ok(lu)
}

// =================================================================================================
// LE RÉGIME DE STATISTIQUES — CE QUI REND UN CHOIX DE PLAN REPRÉSENTATIF, OU NON
// =================================================================================================

/// SOUS QUELLES STATISTIQUES le planificateur a choisi. Trois états, ordonnés : chaque cran ajoute ce
/// que le précédent ne sait pas estimer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum RegimeStatistiques {
    /// Aucune statistique : SQLite DEVINE (nombre de lignes supposé, sélectivité par défaut). Un
    /// verdict lu ici ne parle d'aucune base réelle.
    Aucune = 0,
    /// `sqlite_stat1` seul : des MOYENNES d'égalité par index. Suffisant pour `col = ?`, aveugle au
    /// rendement d'une BORNE (`col >= ?`), pour laquelle SQLite retombe sur une supposition fixe.
    Agregees = 1,
    /// `sqlite_stat1` + `sqlite_stat4` : des ÉCHANTILLONS de valeurs par index, donc une estimation
    /// du rendement d'une borne. C'est le seul régime sous lequel le verdict d'un index dont la
    /// colonne de tête n'est interrogée QUE par bornes peut être qualifié de représentatif.
    Detaillees = 2,
}

/// Le régime de la base OUVERTE, DEMANDÉ au catalogue — jamais supposé depuis les options de
/// compilation. Une SQLite compilée avec les statistiques détaillées qui n'a pas encore analysé la
/// table est en régime `Agregees` ou `Aucune`, et c'est bien ce qu'il faut publier.
pub(crate) fn regime_statistiques(conn: &Connection, table: &str) -> RegimeStatistiques {
    let porte = |t: &str| -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            params![t],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
            == 1
    };
    let lignes = |t: &str| -> bool {
        porte(t)
            && conn
                .query_row(&format!("SELECT EXISTS(SELECT 1 FROM {t} WHERE tbl=?1)"), params![table], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_or(0)
                == 1
    };
    if lignes("sqlite_stat4") {
        RegimeStatistiques::Detaillees
    } else if lignes("sqlite_stat1") {
        RegimeStatistiques::Agregees
    } else {
        RegimeStatistiques::Aucune
    }
}

/// `P10.9-a` — L'ESTIMATION DE LIGNES DONT LE PLANIFICATEUR SE SERT, POUR LA TABLE OBSERVÉE.
///
/// POURQUOI ELLE MANQUAIT, ET CE QUE SON ABSENCE A COÛTÉ. La campagne d'observation en production a
/// rendu une liste d'index que AUCUN plan n'a nommés, et l'hypothèse naturelle — « ils servent des
/// surfaces que personne n'a ouvertes » — a été RÉFUTÉE par une traversée délibérée de toutes les
/// routes de lecture. L'explication qui reste est ailleurs : les tables concernées sont assez petites
/// pour que le planificateur préfère un parcours complet. **Un observatoire d'usage ne sait pas
/// distinguer « cet index ne sert à rien » de « cette table est trop petite pour qu'il serve »** — et
/// il ne le SAURA pas : ce n'est pas ce qu'il mesure. Ce qu'il peut faire, et ne faisait pas, c'est
/// publier le chiffre qui permet au LECTEUR de trancher.
///
/// CE QUE CE CHIFFRE EST, EXACTEMENT. La première grandeur de `sqlite_stat1` pour la table : le
/// nombre de lignes tel que le planificateur le CROIT au moment où il choisit. Ce n'est ni un
/// `COUNT(*)` — qui coûterait un parcours et répondrait à une autre question — ni une vérité : c'est
/// l'estimation datant de la dernière analyse, celle qui a réellement décidé du plan lu. `None` quand
/// `sqlite_stat1` n'existe pas ou ne porte pas la table : le planificateur devine alors une constante,
/// et publier cette constante ferait passer une supposition pour une mesure.
///
/// `P7.19-f` — LA LIGNE RETENUE EST CHOISIE, ELLE N'EST PLUS LA PREMIÈRE VENUE.
///
/// LE DÉFAUT. Cette lecture retenait la première ligne que `sqlite_stat1` rendait pour la table
/// (`… WHERE tbl=?1 … LIMIT 1`), sans ordre. Or une ligne de `sqlite_stat1` décrit **l'index qui la
/// porte**, et sa première grandeur est le nombre de lignes que CET index indexe : pour un index
/// **PARTIEL**, c'est le compte du SOUS-ENSEMBLE, pas celui de la table.
///
/// CE QUE LA MESURE DIT EXACTEMENT, sans l'arrondir dans le mauvais sens. L'ordre dans lequel
/// `sqlite_stat1` rend ses lignes n'est spécifié nulle part, et il dépend du schéma :
///   · sur la base d'épreuve au schéma RÉEL, l'unique index partiel de `event` sort en SIXIÈME
///     position et la lecture sans ordre rendait le BON nombre — le défaut y est donc LATENT, pas
///     visible ;
///   · sur un schéma où l'index partiel est créé en DERNIER, la même lecture rend la ligne PARTIELLE
///     en premier — MESURÉ hors caisse sur trois moteurs (3.39.4, 3.46.1, 3.51.3) : `1200` publié là
///     où la table portait `3000` lignes.
/// Autrement dit : ce que la jauge publie dépend de l'ordre de création des index, et rien ne le
/// garantit. Et à partir de 3.46.1 le défaut cesse d'être latent sur une base NEUVE, où les seules
/// lignes écrites décrivent les index partiels et valent ZÉRO.
///
/// CE QUI EST RETENU MAINTENANT, DANS CET ORDRE :
///   ① la ligne qui décrit la TABLE elle-même (`idx IS NULL`) — ce que `ANALYZE` écrit pour une table
///      SANS index, et ce que le rejeu du corpus fermé synthétise ;
///   ② sinon la ligne d'un index que le catalogue déclare NON partiel — un tel index porte exactement
///      une entrée par ligne de table, donc sa première grandeur EST le compte de la table ;
///   ③ sinon RIEN. Une base neuve sous un moteur récent ne porte QUE des lignes d'index partiels, à
///      `0` : les publier dirait « table vide » d'une table qui ne l'est pas.
///
/// LA PARTIALITÉ EST DEMANDÉE AU CATALOGUE (`pragma_index_list`), jamais énumérée : un nom d'index
/// écrit ici serait faux le jour où un index partiel est ajouté, et c'est exactement la classe de
/// défaut que cette correction ferme. Le test d'appartenance est POSITIF (`partial = 0` doit être
/// constaté) : une ligne dont le catalogue ne connaît plus l'index n'est pas retenue faute de pouvoir
/// être classée — refuser de publier vaut mieux que publier un nombre qu'on ne sait pas lire.
pub(crate) fn lignes_estimees(conn: &Connection, table: &str) -> Option<i64> {
    let stat: String = conn
        .query_row(
            "SELECT s.stat FROM sqlite_stat1 AS s \
             WHERE s.tbl=?1 AND s.stat IS NOT NULL AND s.stat<>'' \
               AND (s.idx IS NULL \
                    OR EXISTS (SELECT 1 FROM pragma_index_list(?1) AS il \
                               WHERE il.name = s.idx AND il.partial = 0)) \
             ORDER BY (s.idx IS NULL) DESC, s.idx \
             LIMIT 1",
            params![table],
            |r| r.get(0),
        )
        .ok()?;
    stat.split_whitespace().next()?.parse::<i64>().ok()
}

/// La SQLite embarquée sait-elle produire des statistiques d'index DÉTAILLÉES ? DEMANDÉ à SQLite
/// (`pragma_compile_options`), jamais lu dans un `Cargo.toml` : c'est la seule façon de distinguer
/// « la base n'a pas encore été analysée » de « ce binaire ne peut PAS produire ces statistiques »,
/// et les deux se lisent autrement.
pub(crate) fn statistiques_detaillees_compilees(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_compile_options WHERE compile_options LIKE 'ENABLE_STAT4%')",
        [],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        == 1
}

// =================================================================================================
// LA CLASSE DE CONSOMMATEUR — L'ÉTIQUETTE « PAR QUOI », ET SA BORNE
// =================================================================================================

/// PAR QUI L'ÉNONCÉ EST DEMANDÉ. Énumération FERMÉE : c'est elle qui borne la seconde dimension de la
/// cardinalité (`INDEX_CAP + 1` étiquettes d'index × `Consommateur::TOUS`).
///
/// ELLE EST DÉDUITE AU POINT DE PASSAGE, PAS PASSÉE PAR LES APPELANTS. Une étiquette qu'une
/// cinquantaine de sites d'appel doivent penser à poser finit par manquer là où elle compte ; celle-ci
/// se dérive de ce que `run_on_conn` a DÉJÀ en main. Ce que cela ne distingue pas est écrit sur
/// chaque variante : c'est une classification à trois cases, pas un nom de route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Consommateur {
    /// Un énoncé porteur d'un identifiant d'ANNULATION. Seul le chemin de recherche/pagination/export
    /// de l'analyste en enregistre un : c'est le chemin interactif principal, celui qu'un index retiré
    /// à tort transformerait en balayage sous les yeux d'un opérateur.
    Analyste,
    /// Un énoncé servi sous le BUDGET INTERACTIF sans identifiant d'annulation : les routes que le
    /// produit sert à un humain qui attend (triage d'alertes, détection avancée, rapports à la
    /// demande). NE DISTINGUE PAS ces routes entre elles — c'est une classe, pas une route.
    Interactif,
    /// Tout le reste : rafraîchissement de panneaux, moteur de règles, rollups, playbooks, conformité.
    /// Un travail de fond peut être fréquent ET sans témoin humain : c'est la case où un index
    /// « employé souvent » ne dit rien de l'expérience d'un analyste.
    Automatique,
}

impl Consommateur {
    /// Les trois classes, DANS L'ORDRE des rangs de compteur. Une variante ajoutée sans sa case ici
    /// ferait sortir `rang()` de la table : c'est le `match` exhaustif qui l'interdit à la compilation.
    pub(crate) const TOUS: [Consommateur; 3] =
        [Consommateur::Analyste, Consommateur::Interactif, Consommateur::Automatique];

    pub(crate) fn cle(self) -> &'static str {
        match self {
            Consommateur::Analyste => "analyste",
            Consommateur::Interactif => "interactif",
            Consommateur::Automatique => "automatique",
        }
    }

    fn rang(self) -> usize {
        match self {
            Consommateur::Analyste => 0,
            Consommateur::Interactif => 1,
            Consommateur::Automatique => 2,
        }
    }

    /// LA DÉDUCTION, PURE — donc opposable sans démarrer un serveur. `budget_interactif` est passé
    /// plutôt que lu, pour que la propriété « le budget interactif classe en `Interactif` » se teste
    /// sans dépendre d'un réglage de processus.
    pub(crate) fn deduit(budget_ms: u64, qid: Option<&str>, budget_interactif: u64) -> Self {
        if qid.is_some() {
            Consommateur::Analyste
        } else if budget_ms == budget_interactif {
            Consommateur::Interactif
        } else {
            Consommateur::Automatique
        }
    }
}

// =================================================================================================
// L'OBSERVATOIRE
// =================================================================================================

/// UNE VALEUR D'ÉTIQUETTE QUI NE PEUT PAS CASSER L'EXPOSITION. Un nom d'index vient du CATALOGUE de
/// SQLite ; la plupart sont posés par le schéma, mais `maintenance` en crée aussi depuis une liste de
/// champs venue de la CONFIGURATION. Un guillemet dans une valeur d'étiquette ne casserait pas
/// seulement cette ligne : il casserait la lecture de TOUT le document `/metrics` par le collecteur,
/// c'est-à-dire de toutes les autres séries du démon. Le jeu de caractères est donc restreint à ce
/// qu'un identifiant SQL sain contient, et le reste est remplacé — jamais retiré en silence, pour que
/// l'étiquette reste discernable de sa voisine.
fn etiquette_sure(nom: &str) -> String {
    nom.chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-' | '(' | ')') { c } else { '_' })
        .collect()
}

/// Les compteurs d'UN index : un par classe de consommateur. La longueur est celle de
/// `Consommateur::TOUS`, et `rang()` est l'unique façon d'y entrer.
struct Compteurs {
    par_consommateur: [AtomicU64; Consommateur::TOUS.len()],
}

impl Compteurs {
    fn neuf() -> Self {
        Compteurs { par_consommateur: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)] }
    }
    fn compte(&self, c: Consommateur) -> u64 {
        self.par_consommateur[c.rang()].load(Ordering::Relaxed)
    }
}

/// UNE STRUCTURE, PAS UN JEU DE `static`. Un plafond ne se prouve qu'en le FAISANT MORDRE, et un
/// plafond qu'on ne peut faire mordre que sur l'instance du processus est un plafond dont l'essai
/// contamine tout le reste de la suite. (Même figure que `semaphore_interactif::Registre`.)
pub(crate) struct Observatoire {
    /// `0` = ÉTEINT. Lu à chaque énoncé : c'est LA dépense du mode éteint, et il n'y en a pas d'autre.
    echantillon: AtomicU32,
    plafond: usize,
    entrees: RwLock<Vec<(String, Arc<Compteurs>)>>,
    tronque: AtomicBool,
    /// Énoncés observables VUS (le compteur qui pilote l'échantillonnage). Il monte même quand le
    /// plan n'est pas lu : sans lui, « 1 sur N » ne voudrait rien dire.
    vus: AtomicU64,
    plans_lus: AtomicU64,
    /// Plans que SQLite a REFUSÉS. Un trou de mesure NOMMÉ : sans ce compteur, un énoncé illisible
    /// pour le planificateur se lirait « énoncé qui n'emploie aucun index ».
    plans_refuses: AtomicU64,
    /// Plans lus qui ne nomment AUCUN index du schéma. C'est le TÉMOIN NÉGATIF EN VOL : un
    /// observatoire dont tous les compteurs montent toujours ne prouve rien.
    plans_sans_index: AtomicU64,
    /// Dernier régime de statistiques constaté ; `-1` = pas encore constaté (aucun plan lu).
    regime: AtomicI64,
    /// `P10.9-a` — dernière estimation de lignes constatée pour `TABLE_OBSERVEE` ; `-1` = pas encore
    /// constatée, ou constatée ABSENTE (aucune statistique ne la porte). Les deux se publient pareil :
    /// rien. Un observatoire qui publierait `0` affirmerait une table vide.
    lignes_estimees: AtomicI64,
}

impl Observatoire {
    pub(crate) fn neuf(plafond: usize, echantillon: u32) -> Self {
        Observatoire {
            echantillon: AtomicU32::new(echantillon),
            plafond,
            entrees: RwLock::new(Vec::with_capacity(8)),
            tronque: AtomicBool::new(false),
            vus: AtomicU64::new(0),
            plans_lus: AtomicU64::new(0),
            plans_refuses: AtomicU64::new(0),
            plans_sans_index: AtomicU64::new(0),
            regime: AtomicI64::new(-1),
            lignes_estimees: AtomicI64::new(-1),
        }
    }

    pub(crate) fn echantillon(&self) -> u32 {
        self.echantillon.load(Ordering::Relaxed)
    }
    pub(crate) fn regler(&self, echantillon: u32) {
        self.echantillon.store(echantillon, Ordering::Relaxed);
    }
    pub(crate) fn plans_lus(&self) -> u64 {
        self.plans_lus.load(Ordering::Relaxed)
    }
    pub(crate) fn plans_refuses(&self) -> u64 {
        self.plans_refuses.load(Ordering::Relaxed)
    }
    pub(crate) fn plans_sans_index(&self) -> u64 {
        self.plans_sans_index.load(Ordering::Relaxed)
    }
    /// Le compte d'un index pour une classe. `0` pour un index jamais vu : l'absence d'entrée et un
    /// compteur à zéro se lisent pareil ICI, et c'est le `# HELP` qui dit ce que ce zéro vaut.
    pub(crate) fn compte(&self, index: &str, c: Consommateur) -> u64 {
        self.entrees
            .read()
            .iter()
            .find(|(n, _)| n == index)
            .map(|(_, k)| k.compte(c))
            .unwrap_or(0)
    }
    /// Le total d'un index, toutes classes confondues — DÉRIVÉ de `Consommateur::TOUS`, jamais d'une
    /// somme écrite à la main qui oublierait la classe ajoutée demain.
    pub(crate) fn total(&self, index: &str) -> u64 {
        Consommateur::TOUS.iter().map(|c| self.compte(index, *c)).sum()
    }
    /// (étiquettes enregistrées, plafond, le plafond a-t-il mordu).
    pub(crate) fn etat_registre(&self) -> (usize, usize, bool) {
        (self.entrees.read().len(), self.plafond, self.tronque.load(Ordering::Relaxed))
    }
    /// Le régime constaté, ou `None` tant qu'aucun plan n'a été lu — jamais `Aucune` par défaut : un
    /// observatoire qui n'a rien lu ne sait pas sous quelles statistiques il aurait lu.
    pub(crate) fn regime(&self) -> Option<RegimeStatistiques> {
        match self.regime.load(Ordering::Relaxed) {
            0 => Some(RegimeStatistiques::Aucune),
            1 => Some(RegimeStatistiques::Agregees),
            2 => Some(RegimeStatistiques::Detaillees),
            _ => None,
        }
    }

    /// `P10.9-a` — la dernière estimation de lignes constatée, ou `None` si aucune ne l'a été. Elle
    /// n'est PAS lue à la demande : la publier coûterait un accès catalogue à chaque scrutation de
    /// `/metrics`, sur une connexion que l'exposition n'a pas.
    pub(crate) fn lignes_estimees(&self) -> Option<i64> {
        match self.lignes_estimees.load(Ordering::Relaxed) {
            n if n >= 0 => Some(n),
            _ => None,
        }
    }

    /// Les compteurs d'une étiquette, créés à la première observation. Au-delà du plafond, tout tombe
    /// dans le seau de débordement : la mesure survit, son attribution non.
    fn compteurs_de(&self, nom: &str) -> Arc<Compteurs> {
        if let Some((_, k)) = self.entrees.read().iter().find(|(n, _)| n == nom) {
            return k.clone();
        }
        let mut g = self.entrees.write();
        if let Some((_, k)) = g.iter().find(|(n, _)| n == nom) {
            return k.clone();
        }
        if g.len() >= self.plafond && nom != ETIQUETTE_DEBORDEMENT {
            self.tronque.store(true, Ordering::Relaxed);
            drop(g);
            return self.compteurs_de(ETIQUETTE_DEBORDEMENT);
        }
        let k = Arc::new(Compteurs::neuf());
        g.push((nom.to_string(), k.clone()));
        k
    }

    /// UN ÉNONCÉ OBSERVABLE. Éteint, c'est un chargement atomique et rien d'autre — pas de
    /// préparation, pas d'allocation, aucun accès à la base.
    pub(crate) fn observer(&self, conn: &Connection, sql: &str, c: Consommateur) {
        let n = self.echantillon.load(Ordering::Relaxed);
        if n == 0 {
            return;
        }
        // Le rang de l'énoncé décide, pas une horloge ni un tirage : le 1er, le (N+1)e, … sont lus.
        // Un échantillonnage reproductible est le seul dont une mutation peut prouver quoi que ce soit.
        if self.vus.fetch_add(1, Ordering::Relaxed) % (n as u64) != 0 {
            return;
        }
        let lu = match plan_de(conn, sql) {
            Ok(lu) => lu,
            Err(_) => {
                // NOMMÉ, jamais absorbé : un plan refusé n'est pas un énoncé sans index.
                self.plans_refuses.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // Le régime est reconstaté tant qu'il n'est pas au maximum, et AU PAS BORNÉ : cf.
        // `PAS_DE_RECONSTAT_DU_REGIME` — nécessaire parce que l'analyse complète tourne en fond après
        // le bind, borné parce qu'il interroge le catalogue.
        let deja_lus = self.plans_lus.fetch_add(1, Ordering::Relaxed);
        if deja_lus % PAS_DE_RECONSTAT_DU_REGIME == 0 {
            // Le RÉGIME ne se reconstate que tant qu'il n'est pas au maximum : il ne peut que monter.
            if self.regime.load(Ordering::Relaxed) < RegimeStatistiques::Detaillees as i64 {
                self.regime.store(regime_statistiques(conn, TABLE_OBSERVEE) as i64, Ordering::Relaxed);
            }
            // `P10.9-a` — L'ESTIMATION DE LIGNES, elle, se reconstate TOUJOURS, et c'est délibéré :
            // elle BOUGE (la base grossit, l'analyse repasse), alors que le régime ne fait que monter.
            // Une estimation figée à la première lecture ferait passer une installation devenue grande
            // pour celle qu'elle était au démarrage — exactement la lecture fautive que ce chiffre
            // existe pour empêcher. Le pas est le même, donc le coût reste UNE petite interrogation du
            // catalogue tous les `PAS_DE_RECONSTAT_DU_REGIME` plans LUS.
            self.lignes_estimees
                .store(lignes_estimees(conn, TABLE_OBSERVEE).unwrap_or(-1), Ordering::Relaxed);
        }
        if lu.index.is_empty() {
            self.plans_sans_index.fetch_add(1, Ordering::Relaxed);
        }
        for nom in &lu.index {
            self.compteurs_de(nom).par_consommateur[c.rang()].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// L'EXPOSITION PROMETHEUS. **Chaîne VIDE tant qu'aucun plan n'a été lu** — donc, observatoire
    /// éteint, `/metrics` est inchangé octet pour octet. Publier `0` partout dirait « mesuré, rien
    /// trouvé » là où il faut lire « pas mesuré » : c'est la même règle que la ventilation par poste.
    pub(crate) fn exposition_prom(&self) -> String {
        if self.plans_lus() == 0 && self.plans_refuses() == 0 {
            return String::new();
        }
        let mut o = String::with_capacity(1024);
        o.push_str(&format!(
            "# HELP plume_index_usage_total Enonces de lecture dont le PLAN nomme cet index, par classe de consommateur — {LIMITES}\n"
        ));
        o.push_str("# TYPE plume_index_usage_total counter\n");
        let entrees = self.entrees.read();
        for (nom, k) in entrees.iter() {
            for c in Consommateur::TOUS {
                o.push_str(&format!(
                    "plume_index_usage_total{{index=\"{}\",consommateur=\"{}\"}} {}\n",
                    etiquette_sure(nom),
                    c.cle(),
                    k.compte(c)
                ));
            }
        }
        drop(entrees);
        let (n_index, plafond, tronque) = self.etat_registre();
        let ligne = |o: &mut String, nom: &str, typ: &str, aide: &str, v: String| {
            o.push_str(&format!("# HELP {nom} {aide}\n# TYPE {nom} {typ}\n{nom} {v}\n"));
        };
        ligne(
            &mut o,
            "plume_index_usage_plans_lus_total",
            "counter",
            "Plans d'execution echantillonnes et LUS (le denominateur des compteurs par index)",
            self.plans_lus().to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_plans_refuses_total",
            "counter",
            "Plans que SQLite a REFUSES : trou de mesure NOMME, jamais compte comme un enonce sans index",
            self.plans_refuses().to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_plans_sans_index_total",
            "counter",
            "Plans lus ne nommant AUCUN index du schema — le temoin negatif : sans lui, des compteurs qui montent toujours ne prouveraient rien",
            self.plans_sans_index().to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_echantillon",
            "gauge",
            "Un plan lu tous les N enonces (0 = observatoire eteint)",
            self.echantillon().to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_index",
            "gauge",
            "Etiquettes d'index enregistrees (cardinalite reelle)",
            n_index.to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_index_cap",
            "gauge",
            "Plafond du registre d'etiquettes (cardinalite au pire)",
            plafond.to_string(),
        );
        ligne(
            &mut o,
            "plume_index_usage_index_tronque",
            "gauge",
            "1 si le plafond a mordu : les observations au-dela sont comptees sous une etiquette de debordement, donc non attribuees",
            u8::from(tronque).to_string(),
        );
        // `P10.9-a` — L'ESTIMATION DE LIGNES DE LA TABLE OBSERVÉE, PUBLIÉE À CÔTÉ DES COMPTEURS parce
        // que c'est elle qui décide comment ils se lisent. Absente tant qu'aucune statistique ne la
        // porte : le planificateur devine alors une constante, et publier une supposition sous le nom
        // d'une estimation serait le défaut même que cette série est là pour empêcher.
        if let Some(lignes) = self.lignes_estimees() {
            o.push_str(&format!(
                "# HELP plume_index_usage_lignes_estimees Lignes de la table que le PLANIFICATEUR croit y trouver (premiere grandeur de sqlite_stat1, datant de la derniere analyse — ni un COUNT(*), ni une verite). ELLE DECIDE COMMENT LIRE LE RESTE : sous un petit nombre de lignes un parcours complet bat l'index, et un index que nul plan ne nomme n'est PAS pour autant un index inutile\n# TYPE plume_index_usage_lignes_estimees gauge\nplume_index_usage_lignes_estimees{{table=\"{TABLE_OBSERVEE}\"}} {lignes}\n"
            ));
        }
        // LE RÉGIME EST ABSENT tant qu'aucun plan n'a été lu sous un régime constaté : publier `0`
        // affirmerait « aucune statistique », ce qui est une mesure, pas une absence de mesure.
        if let Some(r) = self.regime() {
            o.push_str(&format!(
                "# HELP plume_index_usage_stats_regime Statistiques sous lesquelles les plans ont ete lus (0=aucune, 1=agregees sqlite_stat1, 2=DETAILLEES sqlite_stat1+sqlite_stat4). Un verdict lu sous 0 ou 1 n'est PAS representatif pour un index dont la colonne de tete n'est interrogee que par bornes\n# TYPE plume_index_usage_stats_regime gauge\nplume_index_usage_stats_regime{{table=\"{TABLE_OBSERVEE}\"}} {}\n",
                r as i64
            ));
        }
        o
    }
}

// =================================================================================================
// L'INSTANCE DU PROCESSUS
// =================================================================================================

static OBSERVATOIRE: std::sync::OnceLock<Observatoire> = std::sync::OnceLock::new();

/// L'observatoire du processus. Construit ÉTEINT : tant que `configurer` n'est pas passée (outils en
/// ligne de commande, migrations, tests), il ne lit aucun plan.
pub(crate) fn observatoire() -> &'static Observatoire {
    OBSERVATOIRE.get_or_init(|| Observatoire::neuf(INDEX_CAP, ECHANTILLON_DEFAUT))
}

/// LE RÉGLAGE, POSÉ AU DÉMARRAGE depuis la configuration RÉSOLUE (`env > fichier > défaut`). Un
/// réglage lu directement dans l'environnement serait invisible depuis le fichier de configuration
/// d'un déploiement host-natif — le défaut que `tests/partition_config.rs` garde.
pub(crate) fn configurer(conf: &HashMap<String, String>) {
    let n: u32 = cfg(conf, CLE_ECHANTILLON, &ECHANTILLON_DEFAUT.to_string())
        .parse()
        .unwrap_or(ECHANTILLON_DEFAUT);
    observatoire().regler(n);
    if n > 0 {
        eprintln!(
            "[index-usage] observatoire ALLUMÉ : un plan lu tous les {n} énoncés de lecture — \
             série `plume_index_usage_total` (par index × classe de consommateur, cardinalité plafonnée \
             à {INDEX_CAP}+1). Ce que ça ne prouve pas est écrit dans le `# HELP` de la série."
        );
    }
}
