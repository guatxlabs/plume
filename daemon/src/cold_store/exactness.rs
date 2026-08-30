//! cold_store::exactness — L'INVARIANT DE CORRECTION DU TIER FROID, RENDU NON REPRÉSENTABLE.
//!
//! LE DÉFAUT QU'IL FERME. Le chemin d'union hot∪cold (`reader::open_cold_union`) hydrate le froid
//! dans SQLite BORNÉ à `cold_hydrate_row_cap` (= `PLUME_QUERY_MAX`, défaut 5 000) puis exécute le SQL
//! compilé SUR CET ÉCHANTILLON. Mesuré (banc du 31/07, même requête, même fenêtre, même binaire) :
//!
//!     sans tier froid : search source=auditd severity>=2 | stats count -> 58 747
//!     avec tier froid : la MÊME requête                              ->    289
//!
//! Un drapeau `truncated` accompagnait le nombre. Ça ne suffit pas : un drapeau à côté d'un nombre
//! faux laisse le nombre lisible, copiable, traçable dans un graphe. Ce n'était pas un plantage —
//! c'était une PERTE D'HISTORIQUE SILENCIEUSE.
//!
//! LA DISTINCTION QUI FONDE LA CORRECTION.
//!   • Tronquer une MATÉRIALISATION est LÉGITIME. L'utilisateur demande des lignes ; il en reçoit
//!     une partie ; chaque ligne rendue est un ÉVÉNEMENT VRAI ; `truncated` dit qu'il en manque.
//!     Rien à réparer.
//!   • Tronquer un AGRÉGAT est un RÉSULTAT FAUX. À « combien ? », une valeur calculée sur un
//!     échantillon n'est pas une réponse partielle : c'est un MAUVAIS NOMBRE. Il n'existe aucune
//!     façon honnête de le rendre.
//!
//! L'INVARIANT : **aucune valeur dérivée d'un ensemble tronqué ne doit JAMAIS être rendue comme un
//! nombre.**
//!
//! POURQUOI NON REPRÉSENTABLE PLUTÔT QU'ÉNUMÉRÉ. La forme naïve — `if truncated { … }` à chaque site
//! d'agrégat — se réfute toute seule : le prochain agrégat ajouté n'aura pas le `if`, et personne ne
//! le remarquera (c'est la leçon la plus chère de ce projet). Ici :
//!   1. `ColdAnswer::Truncated` SÉQUESTRE son `Value` : il n'y a AUCUN accesseur qui rende un
//!      `Value` sérialisable sans passer par `render`.
//!   2. `render` EXIGE une `AnswerShape`.
//!   3. Une `AnswerShape` n'a AUCUN constructeur public : elle ne s'obtient que par DÉRIVATION
//!      depuis la requête (`AnswerShape::of_gxql`) ou par l'aveu qu'on ne peut rien dériver
//!      (`AnswerShape::undecidable`, qui vaut REFUS). Un site d'appel ne peut donc pas AFFIRMER
//!      « ma requête ne dérive rien » : il ne peut que le faire ÉTABLIR.
//!   4. La dérivation est DÉFAUT-REFUS : tout étage de pipeline hors de la liste des étages
//!      PAR-ÉVÉNEMENT — y compris un étage AJOUTÉ DEMAIN, y compris un agrégat qui n'existe pas
//!      encore — est `SetDerived`. Un futur `| stats p95(latence)` est couvert sans être nommé ici.
//!
//! Conséquence : le seul moyen de rendre un agrégat tronqué serait d'ajouter un étage à
//! `PER_EVENT_STAGES` — c'est-à-dire d'AFFIRMER qu'il est par-événement, dans le fichier qui porte
//! l'invariant, sous les yeux du test qui l'exerce.
//!
//! CE QUI MANQUAIT À L'INVARIANT : SON SUJET (`P10.5-c`, mesuré le 2026-08-28). Il disait « une valeur
//! dérivée d'un ensemble TRONQUÉ », et prenait pour ensemble ce que la CONNEXION avait hydraté, jamais
//! ce que la RÉPONSE avait lu. Or le déclencheur d'union est une propriété de la seule FENÊTRE : une
//! requête de la base `metric` — que le cœur compile en `metric ∪ metric_rollup`, deux tables de `main`
//! que le vieillissement ne touche jamais — arrivait ici avec le `truncated` d'une hydratation qu'elle
//! ne lit pas. MESURÉ sur banc : `metric plume_sonde | stats avg(value)` rendait 3, exactement la
//! moyenne de ses trois points, et se faisait REFUSER en nommant un plafond de 5 000 lignes d'`event`.
//! Un refus faux n'est pas plus honnête qu'un nombre faux : il envoie l'exploitant chercher une cause
//! qui n'existe pas. Le sujet manquant est `LectureDuBrasFroid`, construit comme `AnswerShape` — dérivé,
//! jamais déclaré — et la troncature ne s'applique qu'à une réponse qui a PU lire le bras froid.
//!
//! ET LE REFUS DIT DÉSORMAIS LAQUELLE (`P10.5-b`). Le motif était unique — « cette requête calcule une
//! valeur » — pour toutes les familles, y compris celles qui n'en calculent aucune. La FAMILLE est
//! l'étage qui a rendu la réponse dérivée ; il est donc CONSERVÉ par `AnswerShape` et rendu par le
//! refus, avec un dernier bras qui NOMME l'étage inconnu au lieu de lui prêter un motif.

use super::*;

// ====================================================================================================
// LA FORME D'UNE RÉPONSE — DÉRIVÉE de la requête, jamais déclarée par le site d'appel.
// ====================================================================================================

/// Étages de pipeline GXQL dont CHAQUE ligne de sortie est fonction d'UN SEUL événement d'entrée,
/// plus les étages purement POSITIONNELS (`head`/`limit`). Sur un ensemble tronqué, un tel résultat
/// ne contient que des événements VRAIS : il est INCOMPLET (ce que `truncated` dit), jamais FAUX.
///
/// CE QUI N'Y EST PAS, ET POURQUOI — chaque exclusion est une valeur qui dépend des AUTRES lignes :
///   `stats`/`timechart`/`top`/`rare`  agrègent (count/sum/avg/dc/min/max/…) ;
///   `eventstats`/`rate`               ajoutent une COLONNE calculée sur l'ensemble ;
///   `dedup`                           choisit un représentant EN FONCTION des autres lignes ;
///   `join`/`append`/`lookup`          introduisent des lignes étrangères ;
///   `sort`                            ne fabrique aucune valeur, mais son « les N premiers » porte
///                                     sur l'ensemble : sur un préfixe, l'extremum affiché n'est pas
///                                     l'extremum. Exclu — c'est un classement, donc une dérivation.
/// Et surtout : TOUT LE RESTE, connu ou non. La liste est la SEULE porte d'entrée.
///
/// CONSTAT OUVERT, ET IL PORTE SUR CETTE LISTE-CI (relevé le 2026-08-28, NON corrigé, aucune clé).
///   VU      — `head`/`limit` sont déclarés PAR-ÉVÉNEMENT, deux lignes au-dessus du motif qui EXCLUT
///             `sort` au nom de « les N premiers ne sont pas les N premiers sur un préfixe ». Or c'est
///             mot pour mot la sémantique de `head N`. Et l'hydratation froide retient les lignes les
///             PLUS ANCIENNES (`reader` : tri canonique `(day, seq)` puis arrêt au plafond), donc sur
///             une fenêtre froide portant plus de `PLUME_QUERY_MAX` lignes, `search … | head 20` rend
///             les 20 plus récentes des 5 000 plus ANCIENNES — pas les 20 plus récentes de la fenêtre.
///   ATTENDU — soit `head`/`limit` sortent d'ici (leur SÉLECTION dépend de l'ensemble), soit la raison
///             pour laquelle ils y restent alors que `sort` en est exclu est ÉCRITE.
///   QUESTION NON MESURÉE — les sortir convertirait en REFUS toute pagination froide qui porte un
///             `| head`, et le drapeau `truncated:true` que ces réponses portent déjà se lit « il y en
///             a d'autres » et non « ce ne sont pas les bonnes ». Ce qui n'est pas mesuré : combien de
///             vues livrées et de requêtes réelles passent par cette forme, et si le refus est
///             préférable à une réponse incomplète-mais-vraie. C'est un ARBITRAGE, pas un correctif
///             évident — il n'est donc pas pris ici, et ce paragraphe existe pour qu'il ne soit pas
///             pris par oubli.
const PER_EVENT_STAGES: &[&str] = &["where", "head", "limit", "eval", "rex", "rename", "table", "fields"];

/// Ce qu'une réponse peut PROMETTRE vis-à-vis de l'ensemble sur lequel elle a été calculée.
/// Volontairement PRIVÉ : voir `AnswerShape`.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Shape {
    /// Chaque ligne rendue EST un événement d'entrée (projeté/filtré/limité).
    PerEvent,
    /// Au moins une valeur rendue est calculée SUR L'ENSEMBLE. Porte l'ÉTAGE qui l'a rendue telle —
    /// `None` quand rien n'a pu être dérivé (`undecidable`). C'est de LUI que le refus tire la FAMILLE
    /// de question qu'il refuse (`P10.5-b`) : sans lui, un `| sort` recevait mot pour mot le motif d'un
    /// `| stats`, c'est-à-dire une raison FAUSSE.
    SetDerived(Option<String>),
}

/// La forme d'une réponse. **Aucun constructeur littéral** : les variantes sont privées, donc un
/// appelant ne peut pas écrire `AnswerShape::PerEvent`. Il ne dispose que de `of_gxql` (dérivation)
/// et de `undecidable` (aveu d'ignorance = refus). C'est CE point qui rend l'invariant non
/// représentable plutôt que discipliné.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct AnswerShape(Shape);

impl AnswerShape {
    /// DÉRIVE la forme d'une requête GXQL. DÉFAUT = REFUS : un seul étage hors de
    /// `PER_EVENT_STAGES` — inconnu compris — suffit à rendre la réponse `SetDerived`.
    /// Un `|` à l'intérieur d'une valeur citée peut produire un FAUX `SetDerived` : c'est le
    /// côté SÛR (au pire un refus de trop, jamais un nombre faux de trop).
    pub(crate) fn of_gxql(soql: &str) -> Self {
        for stage in soql.split('|').skip(1) {
            let cmd = stage.trim().split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if cmd.is_empty() {
                continue; // pipe terminal / étage vide
            }
            if !PER_EVENT_STAGES.contains(&cmd.as_str()) {
                return Self(Shape::SetDerived(Some(cmd)));
            }
        }
        Self(Shape::PerEvent)
    }

    /// AVEU : on ne peut RIEN dériver de cette requête (SQL brut admin, forme non analysable).
    /// Vaut REFUS — on ne rend pas un nombre dont on ne sait pas s'il est dérivé.
    pub(crate) fn undecidable() -> Self {
        Self(Shape::SetDerived(None))
    }

    /// La réponse est-elle par-événement ? (Lecture seule : observer ne fabrique rien.)
    pub(crate) fn is_per_event(&self) -> bool {
        self.0 == Shape::PerEvent
    }

    /// L'ÉTAGE qui a rendu la réponse dérivée, consommé par le refus pour NOMMER la famille refusée.
    /// `None` sur une forme par-événement comme sur l'aveu — dans les deux cas il n'y a pas d'étage
    /// fautif à nommer.
    fn etage_derivant(self) -> Option<String> {
        match self.0 {
            Shape::PerEvent => None,
            Shape::SetDerived(e) => e,
        }
    }
}

// ====================================================================================================
// L'ENSEMBLE QUE LA RÉPONSE A LU — DÉRIVÉ du SQL exécuté, jamais déclaré par le site d'appel (`P10.5-c`).
// ====================================================================================================

/// Portée de la troncature vis-à-vis d'UNE réponse. Volontairement PRIVÉ : voir `LectureDuBrasFroid`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BrasFroid {
    /// Le SQL exécuté NOMME l'un des deux objets qui portent les lignes froides -> la troncature de
    /// l'hydratation est une propriété de SON ensemble.
    Lu,
    /// Le SQL exécuté n'en nomme AUCUN -> aucune ligne froide n'a pu entrer dans cette réponse, donc
    /// le plafond de l'hydratation ne dit RIEN d'elle.
    HorsDePortee,
}

/// CE QUE LA RÉPONSE A PU LIRE DU BRAS FROID. Même construction que `AnswerShape`, et pour la même
/// raison : la variante est privée, donc un site d'appel ne peut pas AFFIRMER « ma requête ne lit pas
/// le froid » — il ne peut que le faire ÉTABLIR (`derivee_du_sql`). Le seul chemin vers la variante
/// permissive passe donc par la dérivation, ce qui est la bonne asymétrie : on peut toujours se
/// refuser une réponse, jamais s'en autoriser une.
///
/// ET EN PRODUCTION IL N'Y A MÊME PAS D'AUTRE CHEMIN : `indecidable` — l'aveu, qui vaut « lu », donc
/// conserve le refus — est `#[cfg(test)]`. Le site d'appel unique (`reader::cold_union_query`) DÉRIVE,
/// toujours. C'est plus fort que la discipline promise par `AnswerShape::undecidable`, qui existe, elle,
/// en production parce que le SQL brut admin n'offre rien à dériver.
pub(crate) struct LectureDuBrasFroid(BrasFroid);

impl LectureDuBrasFroid {
    /// DÉRIVE la portée du SQL **RÉELLEMENT EXÉCUTÉ** sur la connexion d'union (page ET count : il
    /// suffit que l'UN des deux lise le froid). CE QUI FONDE LA DÉRIVATION : sur cette connexion, les
    /// lignes froides ne vivent qu'à deux endroits — la table temp d'hydratation et la vue qui shadowe
    /// la table chaude (`COLD_TEMP_TABLE`, `UNION_SHADOWED_TABLE`) — et SQLite ne peut lire une table
    /// que par un identifiant qui la NOMME. Un SQL où aucun de ces deux identifiants n'apparaît ne peut
    /// donc pas en lire une ligne.
    ///
    /// DÉFAUT-REFUS DANS LE SENS QUI COMPTE : la comparaison porte sur des JETONS d'identifiant, donc
    /// `event_rollup` ou `cold_seal` ne comptent pas, mais un littéral de chaîne qui contiendrait le mot
    /// (`message ~ "event"`) compte — c'est-à-dire un refus de trop, jamais un nombre faux de trop.
    ///
    /// CE QU'ELLE NE TIENT PAS, ET C'EST GARDÉ AILLEURS : une INDIRECTION qui lirait la table sans la
    /// nommer. La seule que SQLite offre en lecture est une VUE ; le témoin
    /// `aucune_vue_du_schema_ne_peut_lire_le_bras_froid_sans_le_nommer` exige du catalogue d'une base
    /// fraîchement migrée par CE binaire qu'il n'en déclare aucune.
    pub(crate) fn derivee_du_sql(sqls: &[&str]) -> Self {
        let nomme_le_froid = |sql: &&str| {
            sql.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).any(|jeton| {
                jeton.eq_ignore_ascii_case(super::reader::UNION_SHADOWED_TABLE)
                    || jeton.eq_ignore_ascii_case(super::reader::COLD_TEMP_TABLE)
            })
        };
        if sqls.iter().any(nomme_le_froid) {
            Self(BrasFroid::Lu)
        } else {
            Self(BrasFroid::HorsDePortee)
        }
    }

    /// AVEU : on ne sait pas ce que ce SQL lit. Vaut « lu » -> la troncature garde tout son effet.
    #[cfg(test)]
    pub(super) fn indecidable() -> Self {
        Self(BrasFroid::Lu)
    }

    pub(super) fn a_pu_lire_le_froid(&self) -> bool {
        self.0 == BrasFroid::Lu
    }
}

// ====================================================================================================
// LA RÉPONSE — le `Value` d'un ensemble TRONQUÉ est séquestré derrière `render`.
// ====================================================================================================

/// REFUS motivé : la requête dérive une valeur d'un ensemble qui a été tronqué. Porte de quoi
/// NOMMER la cause et PROPOSER la voie exacte — une erreur qui ne dit pas quoi faire est un mur.
#[derive(Debug)]
pub(crate) struct TruncatedAggregate {
    pub(crate) rows_hydrated: usize,
    pub(crate) cap: usize,
    /// L'ÉTAGE qui a rendu la réponse dérivée (`None` = forme non analysable). C'est la FAMILLE de
    /// question refusée, et c'est de lui que le message tire son motif.
    etage: Option<String>,
}

impl TruncatedAggregate {
    /// CE QUE L'ÉTAGE FAIT DE L'ENSEMBLE — LA PHRASE QUI VARIE (`P10.5-b`).
    ///
    /// LE DÉFAUT QU'ELLE FERME, MESURÉ. Le motif était UNIQUE : « cette requête calcule une valeur
    /// (count/sum/dc/stats … by …) ». Il est FAUX pour les familles qui ne calculent aucune valeur —
    /// un `| sort` ne fait que CLASSER, un `| dedup` ne fait que CHOISIR — et ce sont, dans l'inventaire
    /// des vues livrées de `P10.5-b`, vingt-et-une des soixante-et-une refusées. Un refus qui donne une
    /// raison fausse est un mur avec une pancarte mensongère.
    ///
    /// LE DERNIER BRAS N'EST PAS UN FOURRE-TOUT : il NOMME l'étage qu'il ne connaît pas. Un étage ajouté
    /// demain au langage reçoit donc une phrase VRAIE le jour même, sans être listé ici — c'est la même
    /// discipline que `PER_EVENT_STAGES`, qui condamne l'inconnu sans le nommer.
    fn famille(&self) -> String {
        let Some(e) = self.etage.as_deref() else {
            return "la forme de cette requête n'est pas analysable (SQL brut) : rien n'établit qu'elle ne \
                    dérive aucune valeur de l'ensemble"
                .to_string();
        };
        match e {
            // Ce que `PER_EVENT_STAGES` dit de chaque exclusion, rendu à l'exploitant au lieu d'être
            // gardé dans le code.
            "sort" => format!(
                "l'étage `{e}` CLASSE l'ensemble. L'hydratation froide retient les lignes les PLUS \
                 ANCIENNES : « les N premiers » calculés sur ce préfixe seraient FAUX, pas seulement \
                 incomplets"
            ),
            "dedup" => format!("l'étage `{e}` choisit un représentant EN FONCTION des autres lignes de l'ensemble"),
            "join" | "append" | "lookup" => {
                format!("l'étage `{e}` introduit dans la réponse des lignes étrangères à l'ensemble lu")
            }
            "eventstats" | "rate" => format!("l'étage `{e}` ajoute une colonne CALCULÉE sur l'ensemble"),
            "stats" | "timechart" | "top" | "rare" => format!(
                "l'étage `{e}` AGRÈGE l'ensemble : la valeur porterait sur l'échantillon hydraté, pas sur \
                 la fenêtre demandée"
            ),
            _ => format!("l'étage `{e}` n'est pas par-événement : sa sortie dépend des AUTRES lignes de l'ensemble"),
        }
    }

    /// Message rendu au client. Trois blocs, et chacun doit être VRAI pour TOUTE famille :
    ///   1. la FAMILLE refusée (`famille`, ci-dessus) ;
    ///   2. le PLAFOND chiffré, avec la variable qui le déplace ;
    ///   3. les voies qui ÉCHAPPENT à ce plafond — énoncées comme des FAITS, chacune avec ce qu'elle
    ///      rend VRAIMENT.
    ///
    /// POURQUOI LES DEUX MOTEURS, ET PAS SEULEMENT LE COLONNAIRE. Le message n'en nommait qu'UN, et ses
    /// colonnes étaient recopiées à la main. Deux défauts en découlaient, tous deux mesurés le
    /// 2026-08-28 : la liste avait DÉRIVÉ (elle omettait `fields`, que `planner::phys_proj_cols`
    /// accepte) — elle est désormais dérivée de ce que le moteur accepte réellement ; et ne nommer que
    /// le colonnaire ÉCARTAIT de la seule voie qui sert les dimensions extraites de `fields`, le
    /// pré-agrégé PAR DIMENSION (`rollups::DIM_ROLLUP_SPECS` + `PLUME_ROLLUP_DIMS`).
    ///
    /// ET C'EST LÀ QUE CE MODULE A COMMIS LE DÉFAUT QU'IL EXISTE POUR INTERDIRE (mesuré le 2026-08-28).
    /// Il annonçait cette voie-là sous « EXACT AUJOURD'HUI », en la conditionnant à « <dim> est une
    /// dimension PRÉ-AGRÉGÉE de cette source ». **C'est la condition du ROUTAGE, pas celle de
    /// l'EXACTITUDE** — deux questions différentes, et la seconde n'était pas posée. Ce que la route
    /// rend est écrit dans `rollup_route` : `RollupRoute { approx: true, cap: Cap::top_n(…) }`, des deux
    /// côtés de la frontière ; `apply_rollup_stats` publie donc `stats.approx=true` et OR-e
    /// `stats.truncated` avec le plafond mesuré. La CAUSE est écrite dans `rollups` : les dimensions à
    /// forte cardinalité sont plafonnées top-N par seau (`PLUME_ROLLUP_DIM_TOPN`), et le SQL de la route
    /// est `… GROUP BY val ORDER BY "count" DESC LIMIT N` — donc `| sort -count | head N` est SERVI, sur
    /// des sommes de top-N PAR SEAU. Une seconde approximation s'y ajoute, indépendante du plafond :
    /// `rollup_time_conds` borne à `bucket >= (from/3600)*3600` et `bucket <= to`, donc les seaux qui
    /// COUVRENT les bornes de la fenêtre sont comptés ENTIERS. La correction n'est pas de retirer la
    /// voie — elle reste la bonne réponse — c'est de dire ce qu'elle rend, et de renvoyer à la réponse
    /// elle-même, qui publie son exactitude au lieu de la faire promettre par un message.
    ///
    /// LA MÊME CONFUSION ÉTAIT REPRODUITE UNE CLAUSE PLUS LOIN, DANS LA MÊME PHRASE (mesuré le
    /// 2026-08-28). (c) annonçait EXACT — « jamais un nombre faux » — un `stats count by <colonnes>`
    /// dont l'ensemble admissible était `planner::phys_proj_cols()`. **C'est l'ensemble de la
    /// ROUTABILITÉ du moteur colonnaire, pas celui de l'EXACTITUDE de la réponse**, et il MÉLANGE les
    /// deux : pour `source`, la ROUTE A du pré-agrégé (`rollup_route`, `by_fields == ["source"]`) est
    /// essayée AVANT tout chemin froid (le succès EFFACE `cold_boundary`), rend
    /// `RollupRoute { approx: true }` et `apply_rollup_stats` publie `stats.approx = true` ; `severity`
    /// s'y ajoute par la ROUTE A-multi (`ROLLUP_EXACT_DIMS`), dont l'`approx` suit `split.approx`. Pour
    /// `host`, aucune route rollup ne prend, le colonnaire sert, et la clause était VRAIE — c'est ce
    /// témoin négatif qui montre que l'ensemble ne peut pas porter la promesse : elle est vraie pour
    /// certains de ses membres et fausse pour d'autres.
    ///
    /// LE PARTAGE EXACT/APPROXIMATIF NE SE DÉRIVE PAS ICI, ET LE MESSAGE LE DIT. Il dépend de ce que la
    /// base porte à l'instant de la requête (couverture des rollups, bandes témoignées), de réglages
    /// d'exécution (`PLUME_ROLLUP_MULTIDIM`, `PLUME_ROLLUP_DIMS`) et de l'alignement de la fenêtre sur
    /// l'heure. Un texte statique ne peut donc pas le trancher — alors il ne le tranche plus : il dit
    /// ce que le moteur colonnaire vaut QUAND C'EST LUI QUI SERT, il dit qu'une route pré-agrégée peut
    /// le devancer sur la MÊME forme, et il renvoie à la seule chose qui sache : la réponse elle-même,
    /// `stats.served_from` (la voie qui a servi — le pré-agrégé s'y écrit `rollup` et publie alors
    /// `stats.approx`) — SOUS RÉSERVE DU SITE QUI L'ÉCRIT, cf. `P10.5-m` ci-dessous : `apply_rollup_stats`
    /// N'EST PAS la seule écriture de ce champ de premier niveau — CORRIGÉ LE 2026-08-30 PAR UNE
    /// RELECTURE ADVERSE, ET LA PHRASE FAUSSE AVAIT ÉTÉ ÉCRITE ICI EN CORRIGEANT `P10.5-m`, C'EST-À-DIRE
    /// AU SITE MÊME DONT LE DÉFAUT EST « UNE PHRASE QUI NE CORRESPOND PAS AU CODE ». Mesuré : le champ
    /// de premier niveau a DEUX écrivains — la fonction nommée ci-dessus, et une affectation DIRECTE sur
    /// la voie colonnaire vectorisée, dans le corps de la route de requête. La phrase d'origine disait
    /// que cette voie « ne passe pas par elle », ce qui laissait entendre qu'elle ne publie RIEN : c'est
    /// l'inverse qui est vrai, elle s'annonce elle-même, et l'erreur allait donc dans le sens PESSIMISTE
    /// — elle décrivait un silence qui n'existe pas. CE QUI RESTE VRAI ET QUI EST L'OBJET DE LA CLÉ :
    /// les deux écritures ne se dérivent pas l'une de l'autre, et rien ne garantit qu'elles restent
    /// d'accord — c'est la MULTIPLICITÉ des sites, pas leur silence, qui est le défaut. La liste des colonnes reste publiée, mais pour ce qu'elle est : ce que le
    /// moteur colonnaire sait ROUTER.
    ///
    /// `| table <colonnes>` SANS `head N` retombe sous CE MÊME plafond (`exec_agg` : `cap =
    /// head.unwrap_or(cold_hydrate_row_cap)`) : ses lignes sont vraies, en nombre incomplet, et
    /// `stats.truncated` le dit — ce n'est pas une échappatoire au plafond, et l'annoncer comme telle
    /// était la même confusion.
    ///
    /// (a) A ÉTÉ REVÉRIFIÉE PAR LA MÊME QUESTION, ET ELLE TIENT — mais son sujet a été rendu explicite.
    /// Elle ne promet plus « la seule voie EXACTE pour toute question » (une promesse sur la RÉPONSE,
    /// que la route peut démentir) : elle promet ce qu'elle fait réellement, rendre COMPLET l'ensemble
    /// lu, donc supprimer la cause de CE refus. Une forme qu'un pré-agrégé intercepte n'arrive de toute
    /// façon jamais jusqu'ici — l'interception efface la frontière froide avant que le chemin froid ne
    /// s'exécute — sauf lorsqu'un masque de champ désactive toute route, et dans ce cas la fenêtre
    /// restreinte est bien servie en brut, donc exacte.
    ///
    /// `P10.5-m` — LE MODE D'EMPLOI D'UN REFUS DOIT ÊTRE DÉCIDABLE, SINON IL RENVOIE À UNE CASE ABSENTE.
    /// Ce message est le SEUL endroit où un exploitant à qui le froid vient de refuser un nombre apprend
    /// comment en obtenir un vrai. Trois de ses clauses ne l'étaient pas (mesuré le 2026-08-30) :
    ///   ① (b) faisait de `stats.topn_ecartes == 0` le critère d'exactitude. Ce n'est pas décidable : la
    ///      case est publiée par `apply_rollup_stats` UNIQUEMENT quand `CapMesure::chiffres()` rend
    ///      `Some`, c'est-à-dire sur l'état `Etablie` seul. Une voie sans plafond (`Cap::Aucun`) et une
    ///      fenêtre dont l'ampleur n'a pas pu être établie (`NonEtablie`) laissent la case ABSENTE — et
    ///      la doctrine du site producteur est « une case absente est une case non mesurée, jamais un
    ///      zéro ». Publier un zéro là serait retourner le défaut ; le critère est donc REFORMULÉ sur
    ///      les cases toujours présentes : `stats.truncated` (que `CapMesure::tronque()` rend dans les
    ///      DEUX sens, `NonEtablie` comprise) et la PRÉSENCE de `stats.rollup_note`.
    ///   ② (b) ne citait que le plafond top-N et le débordement de seaux. Un TROISIÈME écart emprunte la
    ///      même réponse et n'affecte NI `approx` NI `truncated` : `dim_coverage_conds` restreint le SQL
    ///      aux bandes témoignées et publie ce qui manque par `join_notes(cov_note, recency_note())` ->
    ///      `stats.rollup_note`. Une fenêtre alignée à l'heure, `topn_ecartes` à 0, et pourtant des
    ///      heures entières ABSENTES du compte : c'est exactement le cas que l'ancien critère déclarait
    ///      exact. La note est donc nommée, et elle entre DANS le critère.
    ///   ③ la clause qui tranche renvoyait au seul `stats.served_from`. `apply_rollup_stats` en est
    ///      PAS l'unique écriture (corrigé le 2026-08-30, voir plus haut : la voie vectorisée écrit le
    ///      champ directement), et `handlers::query::cold_keyset_vectorized_page` ne l'appelle pas : sa
    ///      page rend par `keyset_reponse` avec le seul champ IMBRIQUÉ `stats.cold.served_from`. Or
    ///      `| table <colonnes> [| head N]` — la dernière voie que ce message propose — est
    ///      keyset-applicable (`KEYSET_ROW_PRESERVING`) et c'est précisément ce parcours qui la sert. Le
    ///      lecteur qui suivait le conseil cherchait une case qui n'existe pas là où il était. C'est une
    ///      correction de TEXTE au site du message : aucun aveu n'est déplacé.
    ///
    /// ET LA LISTE DE COLONNES EST QUALIFIÉE, PAS FILTRÉE. `phys_proj_cols()` = `PARQUET_COLS` ∩
    /// `Schema::events().default.select_cols` rend ONZE colonnes (mesuré par intersection le
    /// 2026-08-30). DEUX d'entre elles portent une valeur PAR ÉVÉNEMENT — le champ étendu brut
    /// (`json_field`) et le texte libre (`freetext_col`) — et un `stats count by` sur l'une d'elles est
    /// VRAI en rendant un groupe par ligne : exact, et inutilisable. Les RETIRER de la liste rendrait la
    /// liste FAUSSE sur ce qu'elle prétend être (ce que le moteur sait ROUTER — il les route), et
    /// rejouerait le défaut d'omission de 2026-08-28 sur `fields`. Elles sont donc GARDÉES et
    /// QUALIFIÉES, par `caveat_des_colonnes_sans_dimension` — DÉRIVÉ du cœur comme la liste elle-même,
    /// jamais recopié : si le schéma déclare demain un autre champ JSON, le caveat le suit.
    pub(crate) fn message(&self) -> String {
        format!(
            "refus de rendre un résultat FAUX : {} — mais la lecture froide a dû s'arrêter à {} lignes \
             (plafond RAM PLUME_QUERY_MAX={}). CE QUI ÉCHAPPE À CE PLAFOND, ET CE QUE CHAQUE VOIE REND \
             VRAIMENT : (a) restreindre la fenêtre jusqu'à ce que la lecture froide tienne sous le \
             plafond — l'ensemble lu redevient COMPLET, donc plus aucune valeur n'est dérivée d'un \
             échantillon ; c'est la seule voie qui vaille pour TOUTE forme, y compris celles qu'aucun \
             pré-agrégé ne sert ; (b) « search source=<src> | \
             stats count by <dim> [| sort -count] [| head N] » quand <dim> est une dimension PRÉ-AGRÉGÉE \
             de cette source (défauts par source + PLUME_ROLLUP_DIMS) : servi depuis la base, sans ouvrir \
             un fichier froid, mais APPROXIMATIF — les dimensions à forte cardinalité sont plafonnées \
             top-N par seau horaire (PLUME_ROLLUP_DIM_TOPN) et les seaux qui couvrent les bornes de la \
             fenêtre sont comptés entiers. LE CRITÈRE SE LIT SUR LA RÉPONSE, ET IL TIENT EN DEUX CASES \
             TOUJOURS PRÉSENTES : ce compte n'est EXACT que si `stats.truncated` vaut `false` ET \
             qu'AUCUNE `stats.rollup_note` n'accompagne la réponse, sur une fenêtre alignée à l'heure. \
             `stats.approx` dit qu'une voie pré-agrégée a servi ; `stats.rollup_note` PARAÎT dès qu'il \
             reste quelque chose à dire, et elle porte les trois écarts possibles : des heures que le \
             pré-agrégé ne couvre PAS — ces heures-là sont ABSENTES du compte, ce n'est pas un zéro de \
             données —, le seau courant non encore matérialisé, et l'ampleur du plafond top-N. \
             `stats.topn_ecartes` CHIFFRE cette dernière là où elle a pu être établie ; sur une voie qui \
             ne pose aucun plafond, comme sur une fenêtre dont l'ampleur n'a pas pu être établie, LA CASE \
             EST ABSENTE — une case absente est une case NON MESURÉE, jamais un zéro, et c'est \
             `stats.truncated` qui tranche alors, pas elle ; (c) le moteur colonnaire : « search \
             <filtres> | stats count [by <colonnes>] » balaye TOUT le froid sans hydrater, donc QUAND \
             C'EST LUI QUI SERT sa réponse ne repose sur aucun échantillon, et s'il ne peut pas router \
             vous recevez ce refus plutôt qu'un nombre faux. MAIS CE N'EST PAS LUI QUI DÉCIDE : sur cette \
             forme exacte, une route PRÉ-AGRÉGÉE est essayée AVANT tout chemin froid et l'emporte dès \
             qu'elle sait servir ce group-by — vous recevez alors le nombre APPROXIMATIF de (b), pas ce \
             refus. La liste ci-dessous n'est donc PAS une promesse d'exactitude : c'est l'ensemble des \
             colonnes que le moteur colonnaire sait ROUTER. Ce qui tranche l'exactitude est publié par la \
             RÉPONSE : `stats.served_from` nomme la voie qui a servi (le pré-agrégé s'y écrit `rollup` et \
             publie alors `stats.approx`). CE CHAMP-LÀ N'EST PAS SUR TOUTES LES RÉPONSES : le parcours \
             page-à-page colonnaire ne pose que le champ IMBRIQUÉ `stats.cold.served_from`, dont la \
             valeur se termine par `-vectorized-keyset` — sur une réponse qui porte celui-ci, c'est LUI \
             qu'il faut lire, et l'absence de `stats.served_from` n'y vaut aucune voie. Enfin « search \
             <filtres> | table <colonnes> [| head N] » rend des lignes VRAIES mais retombe sous CE MÊME \
             plafond quand aucun `head N` ne le borne (`stats.truncated` le dit) — et c'est ce \
             parcours-là qui le sert. <colonnes> se prend dans {}.{}",
            self.famille(),
            self.rows_hydrated,
            self.cap,
            super::planner::phys_proj_cols().join("/"),
            caveat_des_colonnes_sans_dimension()
        )
    }
}

/// LA PART DE LA LISTE PUBLIÉE QUI NE SERT AUCUNE DIMENSION, ÉNONCÉE OU TUE — DÉRIVÉE, JAMAIS RECOPIÉE.
///
/// LE DÉFAUT FERMÉ (`P10.5-m`, mesuré le 2026-08-30). Le message propose `stats count [by <colonnes>]`
/// et publie l'ensemble que le moteur colonnaire sait ROUTER. Deux de ses membres portent une valeur par
/// ÉVÉNEMENT : un group-by dessus est VRAI et rend un groupe par ligne — donc exact, et inutilisable.
/// Rien ne le disait, et le refus renvoyait ainsi vers une réponse aussi inexploitable que celle qu'il
/// venait de refuser.
///
/// POURQUOI QUALIFIER ET NON FILTRER. Les retirer rendrait la liste FAUSSE sur ce qu'elle affirme être
/// (ce que le moteur ROUTE — il les route), et rejouerait à l'envers l'omission de `fields` mesurée le
/// 2026-08-28. `phys_proj_cols()` a d'ailleurs d'autres lecteurs (`planner::phys_proj`, les témoins de
/// `cold_store::tests`) : la qualification vit donc ICI, au site du message, et pas dans le moteur.
///
/// LA SOURCE EST LE CŒUR, PAS UNE LISTE. `json_field` (le champ étendu brut) et `freetext_col` (le texte
/// libre) sont DÉCLARÉS par `Schema::events()` ; on les intersecte avec ce que le moteur route. Un
/// schéma qui en déclarerait d'autres les verrait apparaître sans qu'on touche ici, et un schéma qui
/// n'en déclare aucun rend la chaîne VIDE — la phrase disparaît au lieu de mentir au singulier.
fn caveat_des_colonnes_sans_dimension() -> String {
    let base = guatx_core::soql::Schema::events().default;
    let par_evenement: Vec<String> = super::planner::phys_proj_cols()
        .iter()
        .filter(|c| base.json_field.as_deref() == Some(**c) || base.freetext_col.as_deref() == Some(**c))
        .map(|c| format!("`{c}`"))
        .collect();
    if par_evenement.is_empty() {
        return String::new();
    }
    format!(
        " TOUTES NE SONT PAS DES DIMENSIONS, et le moteur ne le dit pas : {} portent une valeur par \
         ÉVÉNEMENT — le champ étendu brut et le texte libre déclarés par le schéma — donc un `stats \
         count by` sur l'une d'elles est vrai en rendant UN GROUPE PAR LIGNE. Pour compter par un \
         sous-champ du champ étendu, c'est la voie (b), le pré-agrégé PAR DIMENSION, qui répond.",
        par_evenement.join(" et ")
    )
}

/// Réponse issue d'une lecture qui A PU tronquer son ensemble source.
///
/// `#[must_use]` : une `ColdAnswer` ignorée serait une réponse jetée en silence.
#[must_use]
pub(crate) enum ColdAnswer {
    /// L'ensemble a été lu INTÉGRALEMENT -> la valeur est exacte, quelle que soit la requête.
    Exact { value: Value, total: Option<i64> },
    /// L'ensemble a été TRONQUÉ. Le `Value` est SÉQUESTRÉ : `render` est le seul chemin de sortie.
    Truncated { value: Value, rows_hydrated: usize, cap: usize },
}

/// Ce qu'un handler a le droit de sérialiser.
pub(crate) struct Rendered {
    pub(crate) value: Value,
    /// Total de pagination. `None` sur un ensemble tronqué : un `COUNT(*)` de pagination est
    /// TOUJOURS une valeur dérivée de l'ensemble — sur un ensemble tronqué il est FAUX, donc il
    /// n'est pas rendu (le client pagine alors sans numéros, comme pour tout total best-effort).
    pub(crate) total: Option<i64>,
    /// L'ensemble source était incomplet (vrai UNIQUEMENT pour une réponse par-événement — une
    /// réponse dérivée tronquée n'arrive jamais jusqu'ici, elle est refusée).
    pub(crate) truncated: bool,
}

impl ColdAnswer {
    /// Construit la réponse à partir du drapeau de couverture du lecteur. C'est le SEUL point où un
    /// `truncated` booléen se transforme en type : après lui, l'incomplétude n'est plus une donnée
    /// qu'on peut oublier de regarder, c'est une variante qu'il faut traiter.
    pub(crate) fn new(
        value: Value,
        total: Option<i64>,
        truncated: bool,
        cap: usize,
        rows_hydrated: usize,
        lecture: LectureDuBrasFroid,
    ) -> Self {
        // `P10.5-c` — LA TRONCATURE EST CELLE D'UN ENSEMBLE, PAS D'UNE CONNEXION. `truncated` dit que
        // l'HYDRATATION a plafonné ; il ne dit rien d'une réponse qui n'a pas lu le bras froid. Le `&&`
        // ne rend donc pas l'invariant plus permissif : il lui donne le sujet qui lui manquait. Le seul
        // chemin vers `HorsDePortee` est la dérivation depuis le SQL exécuté (cf. `LectureDuBrasFroid`).
        if truncated && lecture.a_pu_lire_le_froid() {
            ColdAnswer::Truncated { value, rows_hydrated, cap }
        } else {
            ColdAnswer::Exact { value, total }
        }
    }

    /// SORTIE UNIQUE vers la sérialisation. Rend `Err` — donc une erreur NOMMÉE au client — dès
    /// qu'une valeur dérivée reposerait sur un ensemble tronqué. Une erreur vaut mieux qu'un nombre
    /// faux : c'est la position de repli, pas l'échec.
    pub(crate) fn render(self, shape: AnswerShape) -> Result<Rendered, TruncatedAggregate> {
        match self {
            ColdAnswer::Exact { value, total } => Ok(Rendered { value, total, truncated: false }),
            ColdAnswer::Truncated { value, rows_hydrated, cap } => {
                if shape.is_per_event() {
                    // Lignes VRAIES, en nombre incomplet -> réponse partielle honnête. Le total de
                    // pagination, lui, reste écarté (c'est un COUNT, donc dérivé).
                    Ok(Rendered { value, total: None, truncated: true })
                } else {
                    Err(TruncatedAggregate { rows_hydrated, cap, etage: shape.etage_derivant() })
                }
            }
        }
    }

    /// Réponse d'un chemin STRUCTURELLEMENT exact (aucune hydratation froide n'a eu lieu : la
    /// fenêtre passée au lecteur est vide côté froid). Un `Truncated` ici serait un BUG du chemin
    /// appelant, pas une requête trop large -> `Err` fail-closed, jamais une valeur.
    pub(crate) fn expect_exact(self, what: &str) -> Result<(Value, Option<i64>), String> {
        match self {
            ColdAnswer::Exact { value, total } => Ok((value, total)),
            ColdAnswer::Truncated { rows_hydrated, .. } => Err(format!(
                "{what}: troncature INATTENDUE sur un chemin sans hydratation froide ({rows_hydrated} lignes) — \
                 refus de rendre un résultat dont la complétude n'est pas prouvée"
            )),
        }
    }

    /// TEST SEULEMENT — expose la valeur SÉQUESTRÉE, pour que le harnais puisse PROUVER qu'elle est
    /// fausse (c'est ainsi qu'on mesure le ×203) et pour que les tests P3, qui portent sur le SQL
    /// EXÉCUTÉ (masquage, authorizer, union) et non sur la correction, restent lisibles. Aucun chemin
    /// de production ne l'appelle : le nom dit ce qu'il vaut. Le `total` d'un ensemble tronqué est
    /// rendu `None` ici comme en production — il n'est même pas conservé.
    #[cfg(test)]
    pub(super) fn into_value_even_if_wrong(self) -> (Value, Option<i64>) {
        match self {
            ColdAnswer::Exact { value, total } => (value, total),
            ColdAnswer::Truncated { value, .. } => (value, None),
        }
    }

    #[cfg(test)]
    pub(super) fn is_truncated(&self) -> bool {
        matches!(self, ColdAnswer::Truncated { .. })
    }
}

// ====================================================================================================
// `P10.5-m` — LE MODE D'EMPLOI DU REFUS, TENU PAR CE QUI LE PRODUIT
//
// CE TÉMOIN VIT ICI, ET NON DANS `cold_store::tests`, PARCE QUE CE QU'IL TIENT EST PRIVÉ à ce module :
// la qualification de la liste (`caveat_des_colonnes_sans_dimension`) est DÉRIVÉE du cœur, et un témoin
// qui la recopierait n'aurait rien mesuré. Il ne compare donc pas deux textes : il MESURE ce que le
// schéma déclare, puis il LIT ce que le message publie.
// ====================================================================================================
#[cfg(test)]
mod aveu_dexactitude_decidable {
    fn message_de_refus() -> String {
        super::TruncatedAggregate { rows_hydrated: 5000, cap: 5000, etage: Some("stats".to_string()) }.message()
    }

    /// ① LA MESURE : l'ensemble publié est MIXTE — il porte des dimensions ET des colonnes à
    ///    cardinalité d'événement. Les deux jambes sont exigées : sans la première le caveat serait
    ///    muet et ce test ne mesurerait rien ; sans la seconde, la liste entière serait inutilisable et
    ///    c'est la PROPOSITION du message qu'il faudrait reprendre, pas sa qualification.
    /// ② LA LECTURE : chaque colonne mesurée est NOMMÉE, et la qualification est placée APRÈS la liste
    ///    — un lecteur qui va de haut en bas ne peut pas prendre la liste pour un ensemble de
    ///    dimensions avant d'avoir lu ce qu'elle n'est pas.
    #[test]
    fn la_liste_publiee_dit_lesquelles_de_ses_colonnes_ne_sont_pas_des_dimensions() {
        let base = guatx_core::soql::Schema::events().default;
        let routables = super::super::planner::phys_proj_cols();
        let (par_evenement, dimensions): (Vec<&str>, Vec<&str>) = routables
            .iter()
            .copied()
            .partition(|c| base.json_field.as_deref() == Some(c) || base.freetext_col.as_deref() == Some(c));
        assert!(
            !par_evenement.is_empty(),
            "TÉMOIN POSITIF EN ÉCHEC : le schéma ne déclare ni champ étendu ni texte libre parmi ce que le \
             moteur route — il n'y aurait alors rien à qualifier, et ce test ne mesurerait rien"
        );
        assert!(
            !dimensions.is_empty(),
            "TÉMOIN NÉGATIF EN ÉCHEC : aucune colonne routable ne servirait de dimension — ce n'est plus la \
             qualification qu'il faut corriger, c'est la voie que le message PROPOSE : {routables:?}"
        );

        let m = message_de_refus();
        let liste = routables.join("/");
        let i_liste = m.find(&liste).expect("le message publie l'ensemble des colonnes routables");
        for c in &par_evenement {
            let cite = format!("`{c}`");
            let i = m[i_liste..]
                .find(&cite)
                .unwrap_or_else(|| panic!("la colonne {cite} porte une valeur par ÉVÉNEMENT et le message ne le dit nulle part APRÈS la liste : {m}"));
            assert!(i > 0, "INSTRUMENT : {cite} doit être citée APRÈS la liste, pas dans la liste");
        }
        for c in &dimensions {
            assert!(
                !m[i_liste + liste.len()..].contains(&format!("`{c}`")),
                "la qualification accuse `{c}`, qui EST une dimension : le message écarterait d'une voie qui répond"
            );
        }
    }

    /// LE CRITÈRE D'EXACTITUDE DE LA VOIE PRÉ-AGRÉGÉE EST DÉCIDABLE — IL NE REPOSE PLUS SUR UNE CASE QUI
    /// PEUT ÊTRE ABSENTE.
    ///
    /// LE DÉFAUT MESURÉ (2026-08-30). La clause (b) faisait de `stats.topn_ecartes == 0` le critère.
    /// `apply_rollup_stats` ne publie cette case que sur `CapMesure::chiffres() == Some`, donc jamais
    /// sur une voie sans plafond ni sur une fenêtre dont l'ampleur n'a pas pu être établie ; et un
    /// écart ENTIER — les heures que le pré-agrégé ne couvre pas — n'y apparaît d'aucune façon, il
    /// voyage par `stats.rollup_note`. Le critère est donc reformulé sur ce qui est TOUJOURS là.
    ///
    /// CE QUE CE TÉMOIN NE TIENT PAS : il lit le message. Il ne rejoue pas `apply_rollup_stats` et ne
    /// prouve pas que les cases citées apparaissent bien sur une réponse — c'est le contrat du site
    /// producteur, tenu chez lui.
    #[test]
    fn le_critere_dexactitude_ne_repose_pas_sur_une_case_qui_peut_etre_absente() {
        let m = message_de_refus();
        let deb = m.find("(b)").expect("le message garde sa clause (b)");
        let fin = m[deb..].find("(c)").expect("le message garde sa clause (c)") + deb;
        let clause_b = &m[deb..fin];
        for toujours_la in ["stats.truncated", "stats.rollup_note"] {
            assert!(
                clause_b.contains(toujours_la),
                "le critère doit se lire sur `{toujours_la}`, publiée quelle que soit la voie : {clause_b}"
            );
        }
        // La case chiffrée reste citée — mais JAMAIS sans dire qu'elle peut manquer. C'est la phrase qui
        // rendait le critère indécidable, et c'est sa présence qu'on exige, pas son absence.
        let i_ecartes = clause_b.find("topn_ecartes").expect("l'ampleur chiffrée reste nommée : elle renseigne quand elle est là");
        assert!(
            clause_b[i_ecartes..].contains("ABSENTE"),
            "`topn_ecartes` est citée sans que la clause dise qu'elle peut être ABSENTE — un lecteur qui la \
             trouve vide y lirait un zéro : {clause_b}"
        );
        assert!(
            !clause_b.contains("vaut 0"),
            "la clause fait de nouveau d'une case chiffrée LE critère : {clause_b}"
        );
        // ET LA VOIE VERS LAQUELLE LE MESSAGE RENVOIE POUR TRANCHER EXISTE SUR LA RÉPONSE QU'IL DÉCRIT :
        // le parcours page-à-page colonnaire ne pose que le champ imbriqué.
        assert!(
            m.contains("stats.cold.served_from"),
            "le message renvoie au seul champ de premier niveau, que le parcours colonnaire ne publie pas : {m}"
        );
    }
}
