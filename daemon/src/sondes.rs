//! LES SONDES DE FRAÎCHEUR — ce qu'une sonde OBSERVE, la requête qui en est DÉRIVÉE, et CE QUI BORNE
//! SON COÛT. Les trois vivent ici parce que c'est le seul endroit où une sonde peut naître : donc le
//! seul endroit où l'on peut rendre INEXPRIMABLE une sonde dont personne ne sait ce qu'elle coûte.
//! Extrait de `main.rs` (P3.7-a) — le type et la table y étaient, la garde nulle part.
use crate::*;

// ====================================================================================================
// LA SONDE DE FRAÎCHEUR — CE QU'ELLE OBSERVE EST TYPÉ, SA REQUÊTE EN EST DÉRIVÉE.
//
// CE QUI ÉTAIT CASSÉ. Le descripteur d'un capteur portait une CHAÎNE SQL LIBRE, et celle des deux
// capteurs d'INSTANTANÉ était `SELECT MAX(ts) FROM snapshot WHERE kind='…'` — sans filtre d'hôte, donc
// la donnée la PLUS FRAÎCHE du parc. MESURÉ le 2026-08-02 par le vrai chemin d'ingestion, parc de 50
// machines dont 49 se taisent depuis 2 h : la sonde livrée déclarait un âge de 101 s et le statut
// « actif », alors que la machine la plus en retard avait 7301 s de retard et que 49 hôtes sur 50
// étaient muets. `check_heartbeats` levait ZÉRO alerte. Un SOC qui affiche « frais » pendant que 49
// machines sur 50 se sont tues est pire qu'un SOC en retard : il donne une confiance FAUSSE.
//
// LA FORME DÉRIVÉE. Une sonde de fraîcheur répond « quand la donnée de ce capteur est-elle arrivée pour
// la dernière fois ». Sur un parc, la réponse utile n'est PAS celle de la machine la plus fraîche mais
// celle de la machine la PLUS EN RETARD : `MIN` sur les `MAX(ts)` PAR HÔTE. Propriété qui rend la
// bascule sûre : sur un déploiement MONO-HÔTE (le défaut PME) il n'y a qu'un groupe, donc
// `MIN(MAX(ts)) == MAX(ts)` — valeur IDENTIQUE, à la seconde près, aucune bascule de statut.
//
// POURQUOI UN TYPE ET PAS UNE RELECTURE DES DEUX LIGNES. Le champ n'est plus une chaîne : c'est ce que
// la sonde OBSERVE. Il n'existe AUCUNE façon d'ÉCRIRE une sonde d'instantané qui confonde les hôtes —
// `Sonde::Instantane` ne prend qu'un `kind`, et le `GROUP BY host` est posé par `derniere_collecte()`,
// pas par l'auteur du descripteur. Un 24ᵉ capteur ajouté demain par quelqu'un qui n'a jamais lu ce
// fichier est couvert PAR CONSTRUCTION : le défaut ne compile pas.
//
// ────────────────────────────────────────────────────────────────────────────────────────────────
// P3.7-a — CE QUE LA CHAÎNE LIBRE LAISSAIT PASSER : UNE SONDE DONT LE COÛT SUIT LE VOLUME.
//
// CE QUI ÉTAIT CASSÉ. `EventFlotteConfondue { predicat: &'static str }` prenait une chaîne SQL LIBRE,
// interpolée dans `SELECT MAX(ts) FROM event WHERE {predicat}`. Le type garantissait la TABLE et la
// COLONNE, jamais le COÛT. 8 des 20 sondes d'events portaient `AND category='health'` — une colonne
// ABSENTE de `idx_event_src_ts(source, ts)`. Le planificateur SEEK bien la source, mais doit ensuite
// REMONTER la plage de cette source en `ts` décroissant, en lisant la LIGNE de chaque candidat (la
// catégorie n'est pas dans l'index), jusqu'à en trouver une de catégorie `health`.
//
// LA LOI, MESURÉE le 2026-08-03 (EXPLAIN QUERY PLAN + compteur `SQLITE_STMTSTATUS_VM_STEP`, déterministe
// donc insensible à la charge machine ; base au schéma EXACT de `db/schema.sql`, 217 280 puis 817 280
// lignes, `ANALYZE` fait) :
//
//     VM steps = 5 x (lignes de la source POSTÉRIEURES à son dernier battement `health`) + c
//
// La PENTE vaut EXACTEMENT 5 par ligne remontée, sur 5 points : 340 -> 1 720 ; 1 340 -> 6 720 ;
// 3 010 -> 15 070 ; 4 670 -> 23 370 ; 8 000 -> 40 013. `c` est une petite constante (13 à 20 selon
// l'implémentation SQLite et le cas) et n'a aucune importance : c'est la pente qui fait la loi. Le
// 6ᵉ point, 0 ligne -> 20, est le cas DÉGÉNÉRÉ (le dernier battement EST la ligne la plus récente de
// la source) : la loi n'y dit rien d'autre qu'un coût constant, et c'est le cas nominal.
// À volume x4, les 5 sondes dont la source n'a JAMAIS émis de battement passent EXACTEMENT x4
// (40 013 -> 160 013, 20 013 -> 80 013, 10 013 -> 40 013, 5 013 -> 20 013 deux fois) pendant que les
// 15 autres ne bougent PAS (15 ou 63). C'est la définition d'un coût O(N) : le facteur 4,000 exact
// est aussi le CONTRÔLE POSITIF de l'instrument.
//
// CONFIRMÉE SUR UNE SECONDE IMPLÉMENTATION — le SQLCipher EMBARQUÉ, pas seulement le CLI 3.53 :
// mêmes sondes, base bâtie par `db/schema.sql` + toute la chaîne de migrations, 4 000 puis 16 000
// lignes -> 2 014 puis 8 014 VM steps (pente 5, x4,000 exact) sans l'index, 13 CONSTANT avec.
// Deux planificateurs indépendants, même loi : l'instrument n'invente pas la mesure.
//
// CE QUE ÇA DONNE COMME PANNE. La sonde `-health` est un DEAD-MAN'S-SWITCH : elle existe pour crier
// quand le collecteur MEURT. Or son coût est exactement « le nombre de lignes de la source depuis le
// dernier battement » — c'est-à-dire QUASI NUL tant que le collecteur va bien, et CROISSANT SANS BORNE
// à partir de l'instant où il meurt (le flux réel de la source, lui, continue : CrowdSec bannit encore
// quand le script de santé est mort). La sonde devient donc la plus chère précisément quand elle sert.
// Et elle tourne dans `check_heartbeats`, SOUS LE VERROU D'ÉCRITURE, tous les 20 s (`server.rs`) : ce
// qu'elle consomme, l'ingestion ne l'a pas. C'est une panne AUTO-AMPLIFIANTE.
//
// LA FORME DÉRIVÉE. Une sonde ne peut plus porter de SQL : elle nomme ce qu'elle OBSERVE (le FLUX
// d'une ou plusieurs sources, ou le BATTEMENT DE SANTÉ d'un collecteur), et `requete()` FABRIQUE le
// SQL. Comme il n'y a plus de chaîne à écrire, il n'y a plus de prédicat non couvert à écrire. Et
// chaque variante doit répondre `Cout` : `Cout` n'a pas de variante « on ne sait pas ». Une 5ᵉ sonde
// ajoutée demain ne compile pas tant qu'elle n'a pas dit ce qui borne son coût (match exhaustif,
// E0004), et le test `sonde_cout_independant_du_volume` REFUSE la réponse si elle est fausse.
//
// L'INDEX QUI FERME LES 8. `idx_event_health_beat ON event(source, ts) WHERE category='health'` —
// PARTIEL À DESSEIN. Le composite plein `(source, category, ts)` ferme les mêmes 8, mais il indexe
// TOUTE ligne ingérée : MESURÉ 25,5 o/ligne (5 537 792 o pour 217 280 lignes de banc), soit quelques
// dizaines de Mio EXTRAPOLÉS au million et demi de lignes de l'installation de référence (volume relevé
// le 2026-08-05 par `db-stats --par-objet`), plus une insertion btree sur le CHEMIN D'INGEST CHAUD. Le partiel n'indexe que les battements : MESURÉ 21,8 o/ligne de battement (376 832 o pour
// 17 280), soit ~1,5 Mio pour 8 collecteurs battant toutes les 5 min sur 30 j de rétention — 26x moins,
// et une insertion btree toutes les ~37 s au lieu d'une par event. NOTER LEQUEL DES DEUX ÉCARTS PORTE
// LA DÉCISION : celui du DISQUE dépend du volume (il valait 166x sous l'hypothèse, réfutée, d'une base
// six fois plus grosse ; il vaut 26x sur le volume mesuré, soit 2,0 % du budget 2 Go au lieu de 12,5 %), tandis que
// celui des INSERTIONS — une par event contre une toutes les ~37 s — n'en dépend PAS. C'est l'objection
// qui avait fait ÉCARTER le correctif en v104 (cf. `handlers/freshness.rs`, « amplification d'écriture
// sur le chemin d'ingest chaud ») : elle visait juste, elle ne visait que le composite plein.
//
// POURQUOI `category='health'` RESTE UN LITTÉRAL DANS LE SQL (et n'est pas lié). SQLite n'utilise un
// index PARTIEL que s'il peut PROUVER, à la préparation, que le `WHERE` de la requête implique celui
// de l'index. `category=?2` ne se prouve pas : le partiel serait ignoré et les 8 sondes retomberaient
// en O(N) EN SILENCE. La source, elle, est LIÉE (jamais interpolée). Ce n'est pas une préférence de
// style : c'est la condition d'usage de l'index, et le test de coût la tient.
//
// CE QUE ÇA NE FERME PAS (écrit pour être opposable, pas pour rassurer) : les 20 sondes d'EVENTS et
// celle des MÉTRIQUES gardent leur portée « tous hôtes confondus ». C'est le MÊME défaut de famille —
// mesuré identique — mais il n'a PAS le même coût : `snapshot` ne garde qu'une ligne vivante par
// (kind, hôte) (le heartbeat la TOUCHE au lieu d'en insérer une), donc son `GROUP BY host` porte sur
// la cardinalité de la FLOTTE ; `event` compte plus d'un million de lignes sur une base réelle (relevé
// du 2026-08-05 par `db-stats --par-objet`). La portée est donc DÉCLARÉE — par le type (`Sonde::portee`, match exhaustif),
// comptée par `snapshot_sonde_instantanee_ancrage_de_portee`, et LISIBLE par l'exploitant (champ
// `portee` de `/api/integrations`) — au lieu d'être accidentelle : c'est une dette nommée.
//
// ────────────────────────────────────────────────────────────────────────────────────────────────
// P3.2-a — DEUX ALLÉGATIONS DE CE BANDEAU ÉTAIENT FAUSSES, ET C'EST L'UNE D'ELLES QUI TENAIT LE
// CHANTIER FERMÉ. Elles sont corrigées ici plutôt qu'effacées : c'est leur contenu qui explique
// pourquoi la voie retenue n'est pas celle que ce texte annonçait.
//
// (1) « dont 12 sont CONTINUES, donc leur statut dépend VRAIMENT de la valeur (les 9 autres sont
//     événementielles) » — le COMPTE 12/9 est juste, l'ATTRIBUTION ne l'est pas. Ce qui décide, c'est
//     le drapeau `event_based` du tuple, PAS la variante de `Sonde` : `statut_capteur` tire le statut
//     de la VALEUR quand `event_based=false`, et de `pipeline_is_fresh` sinon. Or les 8 sondes de
//     BATTEMENT sont toutes `event_based=false` (ce sont des dead-man's-switches : c'est leur raison
//     d'être) et 9 des 12 sondes de FLUX sont `event_based=true`. Les 12 « tirées de la valeur » sont
//     donc 8 battements + 3 flux (`audit`, `web`, `kube-audit`) + la métrique — pas les 12 flux. Deux
//     partitions différentes qui rendent le même nombre : c'est exactement le genre de coïncidence
//     qu'un compte ancré sans son AXE laisse passer. L'axe est désormais ancré lui aussi.
//
// (2) « les 9 autres … leur statut suit `pipeline_is_fresh` [donc elles ne masquent pas] » — RÉFUTÉ
//     par lecture de `pipeline_is_fresh` : c'est `MAX(ts)` sur event∪metric∪snapshot SANS filtre
//     d'hôte, c'est-à-dire un agrégat « tous hôtes confondus » de plus. Sur un parc dont une seule
//     machine parle encore, il rend `true` — donc les sondes événementielles rendent « actif » elles
//     aussi. Les 21 sondes à portée flotte confondue masquent, les unes par leur propre agrégat, les
//     autres par celui du pipeline. Il n'y avait pas de moitié saine.
//
// CE QUI A ÉTÉ CONSTRUIT, ET CE QUI NE L'A PAS ÉTÉ. Repasser ces 21 sondes PAR HÔTE multiplierait la
// cardinalité par la taille de la flotte (des centaines à des milliers de machines) : 21 séries
// deviendraient des dizaines de milliers, et chaque sonde d'event perdrait son index — `GROUP BY host`
// n'est servi par AUCUN index de `event`, donc le coût redeviendrait celui de P3.7-a, multiplié par le
// nombre de sondes, sous le verrou d'écriture, toutes les 20 s. La mesure est dans
// `daemon/src/tests/hotes_muets.rs` (mutation du volume x4). La voie retenue est donc l'AUTRE : une
// SEULE sonde de FLOTTE (`sonde_de_flotte.rs`) qui rend un COMPTE d'hôtes muets et non une série par
// hôte, servie par l'inventaire pré-agrégé `host_rollup` dont la cardinalité EST la flotte.
// CE QU'ELLE NE COUVRE PAS : elle voit un hôte qui se tait ENTIÈREMENT, jamais un hôte dont UN
// collecteur est mort pendant que les autres parlent. Ce trou-là reste ouvert, et il reste ouvert
// exprès — le fermer est précisément la multiplication de cardinalité ci-dessus.
//
// RÉSIDU ASSUMÉ, écrit parce qu'il compte : une machine DÉCOMMISSIONNÉE continue de tirer la sonde vers
// le retard tant que ses lignes `snapshot` n'ont pas expiré (`snapshot_days`, 30 j par défaut) — donc une
// alerte « capteur muet » qui NOMME cette machine reste ouverte jusque-là. L'échange est délibéré et il
// est asymétrique : le coût est une alerte bruyante mais VRAIE (« une machine qui rapportait ne rapporte
// plus ») et auto-résorbable, contre un angle mort silencieux qui, lui, ne se résorbe jamais. Le retirer
// exigerait un INVENTAIRE DÉCLARÉ des machines attendues, que Plume n'a pas. (La phrase qui suivait —
// « l'inventaire `host_rollup` est DÉCOUVERT : une machine qui se tait entièrement en sortirait » — est
// RÉFUTÉE par `rollup_hosts` : cette table n'est JAMAIS prunée et son `last_ts` COLLE, donc un hôte
// muet y reste visible indéfiniment. C'est ce qui rend la sonde de flotte possible ; et c'est aussi
// pourquoi son résidu à elle n'est PAS auto-résorbable — cf. `sonde_de_flotte.rs`.)
// ====================================================================================================

/// L'index PARTIEL qui sert les sondes de BATTEMENT DE SANTÉ. Nommé ICI, à côté des sondes qui en
/// dépendent : `maintenance.rs` (création en fond sur base migrée) et `db/schema.sql` (base neuve)
/// le RÉFÉRENCENT au lieu de le réécrire, et `sonde_index_battement_declare_partout` refuse la dérive.
pub(crate) const IDX_BATTEMENT_SANTE: &str = "idx_event_health_beat";
/// La DDL, à l'octet près, partagée par la création en fond et l'assertion sur `db/schema.sql`.
pub(crate) const DDL_IDX_BATTEMENT_SANTE: &str =
    "CREATE INDEX IF NOT EXISTS idx_event_health_beat ON event(source, ts) WHERE category='health'";

/// CE QUI BORNE LE COÛT D'UNE SONDE. Il n'existe PAS de variante « on ne sait pas » : une sonde dont
/// personne ne peut dire ce qui borne son coût est INEXPRIMABLE. C'est la garde de P3.7-a — le défaut
/// mesuré n'était pas une chaîne SQL fautive, c'était une chaîne SQL dont le coût n'était nulle part.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Cout {
    /// Le planificateur SEEK cet index : coût INDÉPENDANT du volume ingéré, VÉRIFIÉ par mutation du
    /// volume (x4) et non par relecture du plan. NB : l'étiquette du plan varie avec la version —
    /// MESURÉ le 2026-08-03 sur la MÊME requête, le CLI 3.53 rend `USING COVERING INDEX` là où le
    /// SQLCipher EMBARQUÉ rend `USING INDEX`. Même chemin, même coût constant (13 VM steps) : c'est
    /// pourquoi le juge est la mutation de volume, jamais la chaîne du plan.
    IndexCouvrant(&'static str),
    /// Coût borné par la CARDINALITÉ D'UNE TABLE — nommée ici — et non par le volume d'events. La
    /// sonde d'instantané en est le seul cas : `SELECT MIN(l) FROM (… GROUP BY host)` est servi par un
    /// BALAYAGE de `snapshot` (MESURÉ le 2026-08-03 : `SCAN snapshot | USE TEMP B-TREE FOR GROUP BY` —
    /// le planificateur n'utilise PAS idx_snapshot(kind, ts), le `GROUP BY host` l'en empêche). Ce n'est
    /// PAS le défaut P3.7-a : `snapshot` ne garde qu'une ligne vivante par (kind, hôte) — le heartbeat
    /// TOUCHE le `ts` au lieu d'insérer — et la rétention (`snapshot_days`, 30 j) borne le reste. Le coût
    /// suit donc la FLOTTE, jamais le million et plus de lignes d'`event` d'une base réelle (relevé du
    /// 2026-08-05 par `db-stats --par-objet` ; invariance vérifiée par mutation du
    /// volume dans `sonde_cout_independant_du_volume`). Dette DÉCLARÉE, pas angle mort.
    BorneParLaTable(&'static str),
}

/// CE QUE LA SONDE COUVRE — LA PORTÉE, DÉCLARÉE PLUTÔT QUE DEVINÉE (P3.2-a).
///
/// Une sonde de fraîcheur rend un âge. Sur un parc, cet âge peut vouloir dire deux choses très
/// différentes : « la machine la plus en retard a cet âge » ou « la machine la plus FRAÎCHE a cet âge ».
/// La seconde déclare la source vivante tant qu'UNE machine parle encore. L'écart n'était lisible
/// qu'en lisant le SQL dérivé — donc invisible à l'exploitant qui regarde un panneau ou reçoit une
/// alerte. Il devient une PROPRIÉTÉ du type, rendue à toutes les surfaces (`/api/integrations`).
///
/// Il n'existe PAS de variante « ça dépend » : comme `Cout`, une 5ᵉ sonde ne compile pas tant qu'elle
/// n'a pas dit ce qu'elle couvre (match exhaustif -> E0004).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Portee {
    /// Chaque machine est jugée séparément et la sonde rend la PLUS EN RETARD. Une machine qui se tait
    /// fait donc vieillir la sonde, même si tout le reste du parc parle.
    ParHote,
    /// Tous hôtes confondus : la sonde rend la donnée la plus FRAÎCHE du parc. Un parc dont une seule
    /// machine parle encore est vu comme sain. DETTE DÉCLARÉE — cf. le bandeau P3.2-a.
    FlotteConfondue,
}

impl Portee {
    /// Le jeton STABLE rendu aux surfaces (JSON, détail d'alerte). En toutes lettres et non un booléen :
    /// un booléen `par_hote: false` se lit « pas par hôte » et n'apprend pas ce qui EST couvert.
    pub(crate) fn etiquette(&self) -> &'static str {
        match self {
            Portee::ParHote => "par-hôte",
            Portee::FlotteConfondue => "tous hôtes confondus",
        }
    }
}

/// LA REQUÊTE D'UNE SONDE — indissociable de ce qui borne son coût : c'est le MÊME objet.
/// Champs PRIVÉS : hors de ce module, `Requete { sql: …, cout: … }` ne compile pas (E0451), et il
/// n'existe aucun constructeur public. On ne peut donc pas fabriquer une requête de sonde sans passer
/// par `Sonde::requete`, c'est-à-dire sans avoir répondu `Cout`.
pub(crate) struct Requete {
    sql: String,
    /// Valeurs LIÉES (jamais interpolées). `category='health'` n'est PAS ici : cf. bandeau (un
    /// paramètre rendrait l'index partiel inutilisable).
    binds: Vec<&'static str>,
    cout: Cout,
}

impl Requete {
    pub(crate) fn sql(&self) -> &str {
        &self.sql
    }
    pub(crate) fn binds(&self) -> &[&'static str] {
        &self.binds
    }
    pub(crate) fn cout(&self) -> Cout {
        self.cout
    }
}

/// CE QU'UNE SONDE DE FRAÎCHEUR OBSERVE — et donc, par dérivation, la requête qu'elle émet.
/// Aucune variante ne porte de SQL : c'est la garde. Cf. bandeau P3.7-a.
pub(crate) enum Sonde {
    /// INSTANTANÉ (`snapshot`) — un instantané décrit UNE machine (`firewall.sh` hashe le ruleset de
    /// CETTE machine, `controls.sh` n'inclut un contrôle que s'il s'applique SUR cette machine), donc la
    /// fraîcheur du PARC est celle de la machine la plus en retard. Le `kind` est LIÉ (paramètre), jamais
    /// interpolé.
    Instantane { kind: &'static str },
    /// EVENT — le FLUX RÉEL d'un ou plusieurs collecteurs. Portée FLOTTE CONFONDUE, DÉCLARÉE (cf.
    /// bandeau) : `MAX(ts)` tous hôtes confondus. Le descripteur ne porte que des NOMS DE SOURCE ; la
    /// table, l'opérateur et l'index sont figés par le variant.
    EventFlux { sources: &'static [&'static str] },
    /// EVENT — le BATTEMENT DE SANTÉ d'un collecteur (dead-man's-switch) : `category='health'` sur SA
    /// source. C'est la famille dont P3.7-a a rendu le coût CONSTANT sous mutation du volume ; elle ne
    /// s'écrit plus à la main, donc elle ne peut plus s'écrire hors de l'index qui la sert.
    EventBattementSante { source: &'static str },
    /// MÉTRIQUES — portée FLOTTE CONFONDUE, DÉCLARÉE. Aucun prédicat (toutes séries confondues).
    MetriqueFlotteConfondue,
}

impl Sonde {
    /// LA requête émise, et ce qui borne son coût. UN SEUL endroit : `derniere_collecte` l'exécute et
    /// les tests l'inspectent, donc aucune des deux ne peut diverger de l'autre.
    ///
    /// Le `match` est EXHAUSTIF : une 5ᵉ sonde ne compile pas tant qu'elle n'a pas dit ce qui borne
    /// son coût (E0004). C'est la même mécanique que `HoteIngere::resoudre`.
    pub(crate) fn requete(&self) -> Requete {
        match self {
            // MIN sur les MAX PAR HÔTE = la machine la plus EN RETARD. Mono-hôte : un seul groupe ->
            // valeur strictement identique à l'ancien `MAX(ts) … WHERE kind=…`.
            Sonde::Instantane { kind } => Requete {
                sql: "SELECT MIN(l) FROM (SELECT host, MAX(ts) AS l FROM snapshot WHERE kind=?1 GROUP BY host)"
                    .to_string(),
                binds: vec![kind],
                cout: Cout::BorneParLaTable("snapshot"),
            },
            // `source=?1` (une source) ou `source IN (?1,…,?n)` : les DEUX sont servis par le composite
            // (source, ts) en INDEX-ONLY — le `MAX(ts)` est un saut en fin de plage, sans lecture de ligne.
            Sonde::EventFlux { sources } => {
                let trous = (1..=sources.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(",");
                let ou = if sources.len() == 1 { "source=?1".to_string() } else { format!("source IN ({trous})") };
                Requete {
                    sql: format!("SELECT MAX(ts) FROM event WHERE {ou}"),
                    binds: sources.to_vec(),
                    cout: Cout::IndexCouvrant("idx_event_src_ts"),
                }
            }
            // `category='health'` LITTÉRAL — condition d'usage de l'index PARTIEL (cf. bandeau). La
            // source est LIÉE. Sans le partiel, cette requête est le O(N) mesuré de P3.7-a.
            Sonde::EventBattementSante { source } => Requete {
                sql: "SELECT MAX(ts) FROM event WHERE source=?1 AND category='health'".to_string(),
                binds: vec![source],
                cout: Cout::IndexCouvrant(IDX_BATTEMENT_SANTE),
            },
            Sonde::MetriqueFlotteConfondue => Requete {
                sql: "SELECT MAX(ts) FROM metric".to_string(),
                binds: Vec::new(),
                cout: Cout::IndexCouvrant("idx_metric_ts"),
            },
        }
    }

    /// CE QUE CETTE SONDE COUVRE. Dérivée du même descripteur typé que la requête et que le coût — donc
    /// une sonde ne peut pas AFFICHER une portée et en EXÉCUTER une autre : `Instantane` est la seule
    /// variante dont `requete()` pose un `GROUP BY host`, et c'est la seule qui répond `ParHote`.
    /// Le `match` est EXHAUSTIF (E0004) : une 5ᵉ variante ne compile pas tant qu'elle n'a pas répondu.
    pub(crate) fn portee(&self) -> Portee {
        match self {
            Sonde::Instantane { .. } => Portee::ParHote,
            Sonde::EventFlux { .. } | Sonde::EventBattementSante { .. } | Sonde::MetriqueFlotteConfondue => {
                Portee::FlotteConfondue
            }
        }
    }

    /// Dernière collecte OBSERVÉE. Le SQL ne SORT PAS de ce type : aucun appelant ne peut le réécrire,
    /// l'oublier, ni en dériver une variante sans hôte. `None` = jamais rien vu (statut « inconnu »),
    /// exactement comme un `MAX(ts)` sur table vide auparavant.
    ///
    /// DETTE DÉCLARÉE (antérieure à P3.7-a, NON traitée ici — la traiter change la surface d'alerte et
    /// mérite sa propre mesure) : `.ok()` CONFOND « la table n'a rien » et « je n'ai pas pu regarder »
    /// (erreur SQL, verrou, interruption watchdog). Les deux rendent `None` -> `StatutCapteur::Inconnu`
    /// -> AUCUNE alerte. C'est exactement l'invariant que la campagne défend ailleurs : une surface qui
    /// n'a pas pu observer ne doit pas se taire comme si elle avait observé le vide. Fermer ça demande
    /// un troisième état porté jusqu'aux deux surfaces (`check_heartbeats` ET `compute_integrations`),
    /// pas un `unwrap_or` de plus ici.
    pub(crate) fn derniere_collecte(&self, conn: &Connection) -> Option<i64> {
        let r = self.requete();
        conn.query_row(r.sql(), rusqlite::params_from_iter(r.binds().iter()), |row| {
            row.get::<_, Option<i64>>(0)
        })
        .ok()
        .flatten()
    }

    /// Les machines dont la dernière collecte est ANTÉRIEURE à `avant_ts`, la plus en retard d'abord.
    /// Sert à ce que l'alerte « capteur muet » NOMME les machines au lieu de dire « le capteur » :
    /// sur le parc mesuré (49 muettes sur 50), sans ça l'opérateur ne sait pas où regarder. Bornée à
    /// `max` entrées + le reste compté par l'appelant. Vide pour les sondes à portée flotte confondue
    /// (elles n'ont pas de notion d'hôte — c'est précisément la dette déclarée).
    pub(crate) fn hotes_en_retard(&self, conn: &Connection, avant_ts: i64, max: usize) -> Vec<(String, i64)> {
        let Sonde::Instantane { kind } = self else { return Vec::new() };
        let Ok(mut s) = conn.prepare(
            "SELECT COALESCE(host,''), MAX(ts) AS l FROM snapshot WHERE kind=?1 GROUP BY host \
             HAVING l < ?2 ORDER BY l ASC",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = s.query_map(params![kind, avant_ts], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) else {
            return Vec::new();
        };
        rows.flatten().take(max).collect()
    }
}

/// Les 4 sources que le collecteur `journal` expédie (le FLUX ; son BATTEMENT, lui, porte
/// `source='journal'` — cf. `journal-health` plus bas, ce n'est pas la même chose).
const SOURCES_JOURNAL: &[&str] = &["sshd", "sshd-session", "sudo", "su"];

/// Capteurs attendus : (id, libellé, intervalle attendu s, SONDE (ce qu'elle observe), ÉVÉNEMENTIEL ?).
/// FIX #2 — `event_based=true` : capteur dont le débit dépend d'une ACTIVITÉ externe (ici les logins
/// SSH/sudo/su) et non d'un timer. Un hôte calme = pas de login = silence NORMAL -> ne JAMAIS le déclarer
/// MUET tant que le pipeline d'ingestion GLOBAL est frais (logique alignée sur compute_freshness, où
/// crowdsec/fail2ban/ufw/nft sont déjà de type « événement »). `false` = capteur CONTINU (timer/flux
/// régulier) : un silence > 5x son intervalle est un vrai angle mort -> alerte MUET légitime (auditd
/// inclus : sur un hôte vivant l'auditd exec/privesc remonte en continu, son silence = daemon mort).
pub(crate) const COLLECTORS: [(&str, &str, i64, Sonde, bool); 23] = [
    ("journal", "journald (auth)", 60, Sonde::EventFlux { sources: SOURCES_JOURNAL }, true),
    ("resources", "ressources/réseau", 60, Sonde::MetriqueFlotteConfondue, false),
    ("firewall", "firewall", 120, Sonde::Instantane { kind: "firewall" }, false),
    ("controls", "Control Catalog", 300, Sonde::Instantane { kind: "controls" }, false),
    ("audit", "auditd (exec/privesc)", 120, Sonde::EventFlux { sources: &["auditd"] }, false),
    // YARA (scan) — intégration OFF par défaut : le collecteur host yara.sh est inerte tant que `yara`
    // n'est pas installé / aucune règle n'est déposée (cf. bootstrap PLUME_WITH_YARA=1). event_based=true ->
    // statut 'inconnu' (UI : « en attente ») tant qu'aucun event source=yara n'arrive, et JAMAIS « muet »
    // sur son propre silence (le muet d'un capteur événementiel ne se juge que sur la santé du pipeline
    // global). Quand un match YARA remonte -> 'actif'. Présence ici = la pastille « Non branché : YARA »
    // (web app.js) s'efface d'elle-même (data-driven : l'intégration off devient une vraie intégration).
    ("yara", "YARA (scan)", 900, Sonde::EventFlux { sources: &["yara"] }, true),
    // ── FIX (audit cohérence v56) — capteurs ÉVÉNEMENTIELS/ÉPARS : leur débit dépend d'une ACTIVITÉ externe
    // (un ban, un scan, un accès à un fichier sensible, un changement FIM) ET le débruitage les rend calmes
    // par construction (dataaccess = écritures seules, integrity = FIM, k8s-log = sev≥3). event_based=true ->
    // ils ne crient JAMAIS « muet » sur leur PROPRE silence (hôte calme = NORMAL) ; le « muet » ne se juge que
    // sur la santé du pipeline GLOBAL (pipeline_is_fresh). Sans ce flag ils alerteraient à tort dès qu'ils se
    // taisent — observé sur l'instance : k8s-log calme ~20 h, crowdsec ~3 j, portscan ~7 h, pipeline pourtant
    // frais. su/sudo/sshd sont DÉJÀ couverts (et event_based) par `journal` ci-dessus -> pas de doublon.
    ("dataaccess", "accès données sensibles (FIM)", 300, Sonde::EventFlux { sources: &["dataaccess"] }, true),
    ("integrity", "intégrité fichiers (FIM)", 900, Sonde::EventFlux { sources: &["integrity"] }, true),
    ("k8s-log", "logs pods k8s (sev≥3)", 300, Sonde::EventFlux { sources: &["k8s-log"] }, true),
    // DEAD-MAN'S-SWITCH pod-logs (calque EXACT de crowdsec-health) — battement de SANTÉ ÉMIS À CHAQUE RUN par
    // collectors/pod-logs.sh (timer 5 min) MÊME quand 0 ligne sev≥3 : source=k8s-log category=health
    // {files_scanned,lines_scanned,sev3_shipped}. CONTINU (event_based=false) -> son SILENCE > 5x l'intervalle
    // (25 min) = collecteur pod-logs MORT -> alerte MUET (le vrai dead-man's-switch). Distingue « 0 ligne sev≥3
    // (normal : la ligne `k8s-log` ÉVÉNEMENTIELLE ci-dessus tolère le calme) » de « collecteur pod-logs mort ».
    // La requête matche sur source+category -> NE se confond PAS avec le flux d'events k8s (category=k8s).
    // Avant le 1er battement (PVC neuf) : last_seen NULL -> statut 'inconnu', jamais 'muet'. Pas de seed DB.
    ("k8s-log-health", "Pod-logs santé (collecteur)", 300, Sonde::EventBattementSante { source: "k8s-log" }, false),
    ("crowdsec", "CrowdSec (décisions)", 3600, Sonde::EventFlux { sources: &["crowdsec"] }, true),
    // DEAD-MAN'S-SWITCH CrowdSec — battement de SANTÉ ÉMIS À CHAQUE RUN par collectors/crowdsec.sh (timer
    // 5 min) MÊME quand 0 ban : source=crowdsec category=health {scenarios_loaded,scenarios_broken,...}.
    // CONTINU (event_based=false, le SEUL de la famille crowdsec) -> son SILENCE > 5x l'intervalle (25 min)
    // = collecteur OU moteur CrowdSec MORT -> alerte MUET (le vrai dead-man's-switch). Distingue « 0 attaque
    // (normal : la ligne `crowdsec` ÉVÉNEMENTIELLE ci-dessus tolère le calme des bans) » de « CrowdSec
    // aveugle/cassé » (incident : moteur deadlock aveugle 3,3 j sans aucune alerte). La requête matche sur
    // source+category -> NE se confond PAS avec le flux de bans (category=network) -> 0 bruit pendant les
    // accalmies de ban normales. Avant le 1er battement (PVC neuf) : last_seen NULL -> statut 'inconnu', jamais
    // 'muet' (la logique CONTINU ne déclenche que sur Some(t) trop ancien). scenarios_broken>0 -> règle v57.
    ("crowdsec-health", "CrowdSec santé (moteur)", 300, Sonde::EventBattementSante { source: "crowdsec" }, false),
    ("fail2ban", "fail2ban (bans actifs)", 3600, Sonde::EventFlux { sources: &["fail2ban"] }, true),
    ("ufw", "UFW (blocages firewall)", 300, Sonde::EventFlux { sources: &["ufw"] }, true),
    ("portscan", "port-scan (nft PORTSCAN)", 900, Sonde::EventFlux { sources: &["portscan"] }, true),
    // ── CONTINUS (event_based=false) : flux réguliers sur un hôte vivant -> un silence > 5x l'intervalle EST
    // un vrai angle mort -> alerte « muet » LÉGITIME (à garder, comme auditd/resources). web = accès/4xx d'un
    // site public (débit soutenu quand sain) ; kube-audit = audit de l'API k8s (flux constant). Ils DOIVENT
    // crier s'ils se taisent. Intervalles généreux pour tolérer les accalmies normales sans faux positif.
    ("web", "web (accès / 4xx)", 1800, Sonde::EventFlux { sources: &["web"] }, false),
    ("kube-audit", "audit API k8s", 120, Sonde::EventFlux { sources: &["kube-audit"] }, false),
    // ── DEAD-MAN'S-SWITCH des collecteurs ÉVÉNEMENTIELS SANS compagnon -health (calque EXACT de
    // crowdsec-health / k8s-log-health). Les feeds RÉELS ci-dessus (portscan/ufw/fail2ban/dataaccess/
    // integrity/journal) sont event_based=true -> ils NE crient JAMAIS « muet » sur leur propre silence
    // (hôte calme = normal). Mais un collecteur qui MEURT (timer stoppé, script cassé, host down) se tairait
    // sans un mot. Chaque collecteur émet donc à CHAQUE run un battement source=<x> category=health severity 0
    // MÊME quand 0 event réel (pas de dedup -> chaque battement s'INSÈRE -> MAX(ts) avance). Ces entrées
    // CONTINUES (event_based=false) surveillent CE battement : silence > 5x l'intervalle (25-75 min) = le
    // collecteur est mort -> alerte MUET (le VRAI dead-man's-switch). La requête matche source+category='health'
    // -> ne se confond PAS avec le flux réel (category='firewall'/'ban'/'data'/'integrity'/'auth'). Avant le 1er
    // battement (opt-in jamais activé / PVC neuf) : last_seen NULL -> statut 'inconnu', JAMAIS 'muet' (la logique
    // CONTINU ne déclenche que sur Some(t) trop ancien) -> zéro faux positif sur un collecteur non déployé.
    // Intervalles = max(300, cadence_timer) pour garder mute ≥ 25 min et ≥ 5 runs manqués. Chaque tuple obtient
    // AUSSI sa carte dans le panneau intégrations (integrations() est data-driven sur COLLECTORS). CODE-only :
    // aucune migration DB (comme crowdsec-health/k8s-log-health). Les entrées event_based ci-dessus NE bougent PAS.
    ("portscan-health",   "port-scan santé (nft)",         300, Sonde::EventBattementSante { source: "portscan" }, false),
    ("ufw-health",        "UFW santé (collecteur)",        300, Sonde::EventBattementSante { source: "ufw" }, false),
    ("fail2ban-health",   "bans santé (collecteur)",       600, Sonde::EventBattementSante { source: "fail2ban" }, false),
    ("dataaccess-health", "accès données santé (FIM)",     300, Sonde::EventBattementSante { source: "dataaccess" }, false),
    ("integrity-health",  "intégrité santé (FIM)",         900, Sonde::EventBattementSante { source: "integrity" }, false),
    ("journal-health",    "journald santé (shipper auth)", 300, Sonde::EventBattementSante { source: "journal" }, false),
];
