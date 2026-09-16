#!/usr/bin/env python3
"""Une liste TRONQUÉE n'est jamais servie comme une liste COMPLÈTE — garde de CI (`P10.7-f`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un itérateur de lignes de rusqlite (`query_map`, `query_and_then`) rend des `Result<T>`, une ligne à
la fois : le mappeur peut échouer sur UNE ligne sans que la requête ait échoué. L'idiome aplati —
`.flatten()`, `.filter_map(Result::ok)`, `.filter_map(|r| r.ok())`, `.flat_map(|r| r.ok())` — jette
cette ligne-là et rend la SUITE. Le corps servi est alors une liste qui a la forme d'une liste
complète : aucune clé n'a changé, aucun total ne dit qu'il manque quelque chose, et le lecteur ne
peut pas distinguer « il y a quatre règles activées » de « il y en avait cinq et la cinquième ne
s'est pas décodée ».

La cause n'est pas exotique. Elle est banale : un cache de schéma de pool périmé fait réussir le
`prepare` et sortir l'échec comme une ERREUR DE LIGNE (`P10.7-f`, famille mesurée dans la note
`flatten-avale-no-such-table-au-premier-pas`), une colonne ajoutée par une migration n'est pas encore
vue par la connexion qui sert, un `TEXT` corrompu ne se convertit pas. Dans les trois cas la route
rend 200 et la liste est plus courte qu'elle ne devrait, SANS UN MOT.

CE QUE L'ARBRE PORTE, MESURÉ LE 2026-09-16
-------------------------------------------
Relevé ligne par ligne sur `daemon/src/handlers/*.rs` (les quatre écritures d'aplatissement passées
au `grep -n`, puis chaque occurrence relue dans son contexte) :

  * QUATRE-VINGTS occurrences d'un aplatissement dans le répertoire ;
  * QUATORZE d'entre elles sont dans un COMMENTAIRE — la moitié sont des notes de lots qui racontent
    le défaut qu'ils viennent de fermer (`alerts.rs`, `liste_bornee.rs`, `destinations.rs`,
    `threat_intel.rs`). Un texte qui NOMME la forme n'est jamais un site : c'est exactement sous
    cette écriture qu'un site « connu » cesse d'exister sans qu'un `grep` le voie ;
  * SOIXANTE-SIX sont du CODE. Huit sont HORS FAMILLE, parce que leur RECEVEUR n'est pas un itérateur
    de lignes : un `Option<Option<_>>` rendu par une fonction, trois `.ok().flatten()` sur un
    `query_row` (famille VOISINE, dite plus bas), un `capture_names().flatten()` d'expression
    régulière, un `.await.ok().flatten()` de tâche, et deux lectures aplaties gardées pour les
    témoins. CES DEUX DERNIÈRES MÉRITENT D'ÊTRE DITES : elles vivent sous une FONCTION
    `#[cfg(test)]`, et `coupe_tests` NE LES COUPE PAS — il coupe au premier `#[cfg(test)] mod`, et
    aucun aplatissement de ce répertoire n'est dans un tel module (mesuré : 66 avant la coupe, 66
    après). C'est le receveur qui les tient hors famille, pas la coupe de test ;
  * restent CINQUANTE-HUIT SITES de la famille, sur trente et un fichiers. TROIS sont admis pour une
    raison écrite (deux arbitrages ASSUMÉS, un INDÉCIDABLE) ; CINQUANTE-CINQ sont des défauts.

CE QUE LES CINQUANTE-CINQ SERVENT, MESURÉ PAR UN CRITÈRE ÉCRIT (le type de retour de la fonction
englobante, rejouable sur l'arbre) : QUARANTE-CINQ rendent DIRECTEMENT un type porteur de corps —
`Response` 27, `Json<Value>` 11, `Value` 5, `Option<Value>` 1, `Vec<Value>` 1. QUATRE rendent un type
métier qui entre dans un corps servi un cran plus loin (`dominant_tactic_and_target`, `index_stats`,
`soql_known_sources_bornees`, `sources_declarees_par_connecteurs`), soit QUARANTE-NEUF servis. Les SIX
dernières ne servent AUCUN corps : `respond_run`, `load_policies`, `load_active_silences`,
`load_active_engagements`, `eval_baseline`, `sla_recalcule_la_priorite_bornee` — et ce sont celles que
cette garde sait le moins bien formuler, parce qu'il n'y existe aucun corps où poser un aveu.

POURQUOI UNE SŒUR, ET NON UNE EXTENSION DE `P10.7-g`
-----------------------------------------------------
`check_a_read_that_did_not_happen_is_never_served_as_a_fact.py` juge la même espèce de faute, mais sa
POPULATION est la VOIE : tout appel à `read_with_watchdog`, `read_with`, `with_write`, `run_query_ex`
ou `run_query`. Derrière cette population, l'avalement n'est qu'un SYMPTÔME parmi d'autres, et la
garde ne le voit que là où la voie le lui présente. Deux angles morts de FORME y sont mesurés, et ce
fichier les prouve plutôt que de les alléguer (les deux extraits sont soumis à `lectures_avalees` de
la garde sœur dans les épreuves internes, et elle n'en rend AUCUN) :

  * `chaine_apres` ne lit que le jeton COLLÉ à la fermante de la lecture. Sur
    `query_map(…).map(|x| x.flatten().collect())`, ce jeton est `map(…)` — absent du vocabulaire
    `AVALE` — et le `.flatten()` vit DANS l'argument, que ce lecteur-là n'ouvre pas. Sites prouvés :
    `daemon/src/handlers/caseops.rs:323` et `:363` ;
  * un aplatissement posé sur une VARIABLE LIÉE n'est relié à aucune lecture. Site prouvé :
    `daemon/src/handlers/soql_meta.rs:218` (`let Ok(rows) = s.query_map(…) else { … }; for src in
    rows.flatten()`).

Et la population des cinq voies laisse hors jugement tout ce qui vit derrière `req_conn!` ou derrière
un `&Connection` passé en argument — c'est-à-dire la grande majorité des gestionnaires, et la
quasi-totalité des cinquante-huit sites ci-dessus. ÉLARGIR LA GARDE SŒUR NE LES AURAIT PAS ATTEINTS :
sa mesure du 2026-08-30 a refusé `req_conn!` pour son GRAIN (une seule lecture avalée y compte autant
de fois qu'il y a de gestionnaires), et ce refus est toujours vrai. La population de CETTE garde
n'est donc pas une voie : c'est LE GESTE. Un aplatissement dont le receveur est un itérateur de
lignes est un site, quelle que soit la façon dont la connexion est arrivée là — et le grain est
exact, parce qu'un geste ne se démultiplie pas par le nombre de ses appelants.

POURQUOI UN ENSEMBLE NOMMÉ, ET NON UN COMPTE
---------------------------------------------
Un cliquet de compte a deux angles morts, tous deux mesurés sur la garde sœur : une accusation fermée
et une accusation ouverte le même jour laissent le compte immobile (le site neuf entre en silence),
et une descente réelle n'est qu'une note que personne n'est obligé de lire. `SITES_ADMIS` est donc
une LISTE DE SITES, jugée DANS LES DEUX SENS : une accusation hors ensemble est une FORME NEUVE
(rouge), une entrée sans accusation est une EXEMPTION SANS OBJET (rouge). La liste ne peut que
descendre, et zéro est atteignable — une garde dont l'ensemble serait vide ne réclame rien, donc elle
n'est pas une rançon.

RELEVÉ APRÈS LE RANG UN (2026-09-16, même jour, lot suivant) : les huit sites de sécurité et
d'administration sont ENTIÈRES OU AVOUÉES (collecte en bloc, `corps_de_liste_illisible`, cinq cents
nommé pour le tableau nu des fournisseurs d'identité, cinq cent trois pour la remise d'actions, tick
aveugle compté pour le responder local) et leurs entrées ont quitté l'ensemble : la garde rendait
alors cinquante sites sur vingt-six fichiers, quarante-sept défauts connus.

RELEVÉ APRÈS LE RANG DEUX (2026-09-16, lot suivant) : les dix sites de DÉTECTION sont fermés à leur
tour — cinq listes servies avouent (`rules_list`, `parsers_list`, `baselines_list`, `playbooks_list`,
le vocabulaire de complétion, dont le cache SWR n'accueille plus un aveu), cinq lectures INTERNES
rendent un `Result` et chaque appelant agit en connaissance (tour de dispatch sauté et compté sans
marquer aucune alerte envoyée ; cache d'engagements CONSERVÉ et compté plutôt que vidé ; ligne de base
« non évaluée » ; source « indéterminée » et jamais « inattendue »). La garde rend désormais QUARANTE
sites sur vingt-deux fichiers, trente-sept défauts connus. Les comptes des paragraphes ci-dessus sont
le RELEVÉ DU MATIN, gardés tels quels comme point de départ ; les planchers ne montent jamais.

RELEVÉ APRÈS LE RANG TROIS (2026-09-16, lot suivant) : les cinq sites où la ligne avalée FAUSSAIT UN
NOMBRE sont fermés. Le recensement des entités à risque (`risk_entities_page`) solde sa passe bornée en
bloc AVANT de compter, si bien que `total`, `over_threshold_total` et `over_threshold_hors_parc`
retombent ENSEMBLE sur `TotalBorne::sans_lecture()` et deux `null` — un compte dont une ligne n'a pas pu
être lue est « non établi », jamais un entier plus petit. La progression d'un case (`case_steps_json`),
qui DÉRIVE de `steps.len()`, est `null` sous l'aveu plutôt que `0/0`. Les deux lectures qui alimentent
`indexes` (`index_stats`, désormais porteuse d'un `rusqlite::Result`, et la liste des politiques) avouent
ensemble : plus aucun index ne s'affiche « 0 event », plus aucun n'est absent de la liste, et aucune
politique perdue ne se relit « hérite du global » (`ok` retombe à `false`, comme le catalogue des rôles
du rang un). Le recalcul d'échéances SLA (`sla_recalcule_la_priorite_bornee`), dernière lecture INTERNE
de l'ensemble, porte sa ligne illisible dans `manque` : la route ne rend plus `204` = « tout recalculé »
au-dessus d'un dossier qu'elle n'a pas su lire. La garde rend désormais TRENTE-CINQ sites sur VINGT
fichiers, trente-deux défauts connus — tous de rang quatre.

RELEVÉ APRÈS LA VAGUE A DU RANG QUATRE (2026-09-16, lot suivant) : treize accusations de rang quatre
tombent sur SIX fonctions de CONTENU ET DE MODÈLES. Trois listes servies avouent sous la forme du dépôt
(`liste_bornee::corps_de_liste_illisible` : la clé existe, VIDE, et `error` nomme la cause) — le
sélecteur de vues (`views_list`), les panneaux d'un tableau de bord (`dash_get`, qui PANIQUAIT sur deux
`unwrap()` et dont le solde en bloc précède désormais le filtre de portée, pour qu'un échec de ligne ne
puisse pas se cacher derrière « ce panneau était privé ») et la liste des datasets (`datasets_list`).
Deux corps portent PLUSIEURS listes — SIX familles de savoir (`knowledge_list`) et les TROIS étages de
l'arbre de modèles (`datamodels_list`) — et l'aveu y NOMME la lecture ratée
(`liste_bornee::corps_de_listes_illisibles` : `non_lus` porte les clés concernées, chacune présente et
vide, les autres restant servies), parce qu'un `error` global y suspecterait cinq familles honnêtes avec
la sixième ; c'est la forme que `case_metrics_json` (`non_etablis`) et `freshness.rs` (`non_lus`)
emploient déjà. Le SEUL site du lot qui REFUSE au lieu d'avouer dans son corps est la CAPTURE
d'instantané (`capture_dashboard_data`, qui rend désormais un `rusqlite::Result`) : son produit n'est pas
une page relue en ligne mais un artefact FIGÉ dans `dashboard_snapshot.data` et partageable par jeton à
des tiers — un aveu embarqué y serait relu par quelqu'un qui ne peut plus rien recouper, donc
`snapshot_create` rend un cinq cent trois nommé et n'écrit RIEN. La garde rend désormais VINGT-DEUX sites
sur DIX-SEPT fichiers, dix-neuf défauts connus, tous de rang quatre.

LES PLANCHERS SE RELISENT, AVEC LEUR DATE (2026-09-16, après la vague A du rang quatre). Ils valaient
24/13 après le rang trois, re-dérivés alors du relevé de ce jour-là (35 sites sur 20 fichiers) ; l'arbre
porte maintenant 22 sites sur 17 fichiers pour de VRAIES corrections, et un plancher laissé à 24 rougirait
sur le dépôt que cette garde vient d'aider à guérir. La MÊME règle des deux tiers est réappliquée au relevé
DU JOUR : 69 % de 22 = 15, 65 % de 17 = 11. Ils ne montent jamais, et le filet de l'ensemble nommé jugé
dans les deux sens reste, lui, insensible au volume.

CE QUE LA RELECTURE DES PLANCHERS VALAIT APRÈS LE RANG TROIS, GARDÉ POUR QUE LA RÈGLE SE VÉRIFIE SUR DEUX
PASSAGES. Ils valaient alors 40/20, dérivés du relevé du matin (58 sites sur 31 fichiers, soit 69 % et
65 %) ; l'arbre portait 35 sites sur 20 fichiers pour de VRAIES corrections, et un plancher laissé à 40
aurait rendu la garde rouge sur le dépôt qu'elle venait d'aider à guérir. Ils ont été re-dérivés du relevé
de ce jour-là par la même règle — 69 % de 35 = 24, 65 % de 20 = 13 —, ils ne montent jamais, et ils se
relisent de la même façon à chaque descente.
Ce n'est pas le seul filet : une découverte PARTIELLEMENT aveugle est déjà prise par le jugement de
l'ensemble nommé dans les deux sens (chaque site qui cesse d'être vu sans que son entrée soit retirée
devient une « exemption sans objet », rouge). Le plancher ne couvre que le cas où la découverte s'effondre
ASSEZ pour que le rouge de l'ensemble puisse être pris pour une guérison.

LES CINQUANTE-CINQ DÉFAUTS SONT ADMIS AUJOURD'HUI, ET C'EST UN AVEU, PAS UN ACQUITTEMENT
------------------------------------------------------------------------------------------
Ils entrent dans l'ensemble pour que la garde puisse être câblée VERTE le jour où elle est écrite :
une garde qui naît rouge sur cinquante-cinq sites ne se branche pas, et une garde qui ne se branche
pas ne tient rien. Chaque entrée porte SA raison, en une ligne, qui dit ce qui est servi tronqué et
le geste LOCAL qui la ferme. Corriger un site SANS retirer son entrée fait rougir la garde en
« exemption sans objet » : c'est voulu, et c'est ce qui empêche l'ensemble de devenir un décor.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from check_every_help_trigger_has_a_section import sans_commentaires_rust  # noqa: E402

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LA GARDE SŒUR EST IMPORTÉE POUR SES TROIS LECTEURS DE FORME (`apparier`, `coupe_tests`,
# `fonctions`) : les recopier ferait deux appariements de parenthèses qui pourraient diverger, et ce
# dépôt paie cher les lecteurs jumeaux. L'import est SAIN — il n'exécute qu'une compilation de
# regexes (mesuré à 23 ms) — MAIS son module évalue sa propre `RACINE` À L'IMPORT, par un
# `git rev-parse` quand aucun argument ne lui est passé. On lui passe donc la racine DÉJÀ calculée
# ici : l'import ne cherche plus de dépôt git (une archive dépliée en est dépourvue) et ne peut pas
# juger un arbre différent de celui que cette garde juge.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        apparier, coupe_tests, fonctions)
finally:
    sys.argv = _ARGV

HANDLERS = os.path.join(RACINE, "daemon", "src", "handlers")
DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "liste-tronquee"

# --- LE GESTE, ET SON RECEVEUR -------------------------------------------------------------------
# LA LECTURE : les deux méthodes de rusqlite qui rendent un ITÉRATEUR DE `Result<T>`. `query_row` n'y
# est PAS — il rend UNE ligne, son `.ok()` confond « aucune ligne » et « pas lu », et c'est une
# famille VOISINE que cette garde ne juge pas (elle le dit dans son verdict). Au 2026-09-16,
# `query_and_then` n'a AUCUN site dans `daemon/src/handlers/` (`grep -rn query_and_then` : 0) ; il est
# nommé parce qu'il porte la MÊME forme, et le jour où il entre, il entre jugé.
LECTURE_LIGNES = re.compile(r"\.\s*(?:query_map|query_and_then)\s*\(")
# L'AVALEMENT, SOUS SES QUATRE ÉCRITURES DE SURFACE. Les espaces sont tolérés partout : un `rustfmt`
# qui coupe la ligne ne doit pas faire disparaître un site.
AVALE_LIGNE = re.compile(
    r"\.\s*(?:flatten\s*\(\s*\)"
    r"|filter_map\s*\(\s*Result\s*::\s*ok\s*\)"
    r"|filter_map\s*\(\s*\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)\s*\)"
    r"|flat_map\s*\(\s*\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)\s*\))")
# Les jetons TRANSPARENTS d'une chaîne directe : ils changent la façon dont l'échec de la REQUÊTE est
# traité, jamais celui d'une LIGNE. `?` et `unwrap()` propagent ou tuent ; `expect(..)` aussi.
TRANSPARENT = ("?", "unwrap", "expect")
# La liaison d'une lecture à un nom, sous les quatre formes que l'arbre porte (`let`, `let Ok(..)`
# d'un `let ... else`, `if let Ok(..)`, et le bras d'un `match` dont la lecture est le scrutateur).
LIE_PAR_LET = re.compile(
    r"\b(?:if\s+)?let\s+(?:Ok\s*\(\s*)?(?:mut\s+)?([A-Za-z_]\w*)\s*\)?\s*(?::[^=]*)?=\s*[^;]*$", re.S)
MATCH_EN_TETE = re.compile(r"\bmatch\s+[^;{}]*$", re.S)
LIE_PAR_BRAS = re.compile(r"\bOk\s*\(\s*(?:mut\s+)?([A-Za-z_]\w*)\s*\)\s*=>")
# `for <motif> in <nom>.flatten()` : le même site que la liaison, isolé pour que la phrase imprimée
# nomme la BOUCLE — c'est là que le lecteur ira, pas sur le `let` qui est vingt lignes plus haut.
BOUCLE_AVANT = re.compile(r"\bfor\s+[^;{}]*\bin\s+$", re.S)

ECRITURES = {
    "i": "écriture (i), chaîne directe",
    "ii": "écriture (ii), chaîne enveloppée",
    "iii": "écriture (iii), liaison",
    "iv": "écriture (iv), boucle sur une liaison",
}
# Une accusation par OCCURRENCE d'aplatissement : quand deux écritures désignent la MÊME occurrence,
# la plus SPÉCIFIQUE gagne, et le site n'est jamais compté deux fois.
RANG_ECRITURE = {"i": 0, "ii": 1, "iv": 2, "iii": 3}

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (relu le 2026-09-16, après la vague A du rang quatre) ---------
# Ils ne réclament PAS un volume de code : ils constatent qu'une LECTURE est cassée. Sous eux, rendre
# vert serait rendre vert en étant aveugle, et c'est le défaut que cette garde nomme, appliqué à
# elle-même : la découverte est cassée, pas le dépôt guéri.
#
# PREMIÈRE ÉCRITURE (relevé du matin, 2026-09-16) : 58 sites sur 31 fichiers -> 40/20, soit 69 % et
# 65 %. PREMIÈRE RELECTURE (même jour, après les rangs un, deux et trois) : 35 sites sur 20 fichiers
# -> 24/13, par la même règle. SECONDE RELECTURE (même jour, après la VAGUE A du rang quatre) :
# l'arbre porte 22 sites sur 17 fichiers pour de VRAIES corrections — 36 entrées retirées de l'ensemble
# nommé depuis le matin, aucune amnistiée — et un plancher laissé à 24 rougirait sur le dépôt que cette
# garde vient d'aider à guérir. La MÊME règle est réappliquée au relevé DU JOUR : 69 % de 22 = 15,
# 65 % de 17 = 11. Les planchers ne montent jamais ; à la prochaine descente pour de vraies
# corrections, ils se reliront de la même façon, avec leur date. Et ils ne sont pas le seul filet : une
# découverte PARTIELLEMENT aveugle est prise par le jugement de l'ensemble nommé (un site qui cesse
# d'être vu devient une « exemption sans objet »), et ce filet-là, lui, ne dépend d'aucun volume.
PLANCHER_SITES = 15
PLANCHER_FICHIERS = 11

# ================================================================================================
# L'ENSEMBLE NOMMÉ — TROIS CLASSES, JUGÉES DANS LES DEUX SENS
# ================================================================================================
# --- CLASSE 1 : LES ARBITRAGES ASSUMÉS. Ce ne sont PAS des défauts : l'aplatissement y est le
# moindre mal, et l'arbitrage est écrit DANS LE CODE, pas ici. Ces deux entrées survivent à une
# campagne de correction ; elles ne disparaissent que si l'arbitrage lui-même change.
SITES_ASSUMES = {
    # `liste_bornee.rs:41-44` l'écrit : perdre la LISTE ENTIÈRE pour une ligne échangerait une
    # troncature contre une indisponibilité, et ce module rend déjà `Illisible` quand la REQUÊTE
    # échoue. RÉSERVE À DIRE : une liste amputée d'une ligne se déclare `Lues`, donc le `served <
    # window` du corps borné s'y lit « la borne ne mord pas » alors qu'une ligne manque. Le jour où
    # `lire` rend un `Result` par ligne, cette entrée doit DISPARAÎTRE.
    ("daemon/src/handlers/liste_bornee.rs", "lire"): 1,
    # FAIL-CLOSED, documenté en `datamodels.rs:257-259` : une allowlist AMPUTÉE fait REFUSER le champ
    # au Pivot (400), elle n'en invente aucun. L'absence y est un refus, pas une valeur rassurante —
    # c'est ce que cette garde réclame ailleurs, et l'accuser poserait un rouge qu'aucun geste local
    # ne referme.
    ("daemon/src/handlers/datamodels.rs", "object_field_allow"): 1,
}

# --- CLASSE 2 : L'INDÉCIDABLE. Ni défaut ni arbitrage tant que la question n'est pas tranchée ;
# l'entrée porte la question, pas une excuse.
SITE_INDECIDABLE = {
    # AUCUN appelant de production. Le doc-commentaire `fleet.rs:39` dit « partagé par
    # /api/integrations » et c'est FAUX depuis que `freshness.rs:315` passe par
    # `hotes_du_panneau_bornes`. À trancher : code MORT (le supprimer ferme le site) ou lecteur à
    # REBRANCHER (il redevient alors un défaut de rang 3, un inventaire d'hôtes servi comme complet).
    # Tant que la question n'est pas tranchée, l'entrée reste et dit qu'elle ne l'est pas.
    ("daemon/src/handlers/fleet.rs", "host_inventory_simple"): 1,
}

# --- CLASSE 3 : LES DÉFAUTS CONNUS, NON CORRIGÉS. Chaque entrée dit ce qui est servi tronqué et le
# geste LOCAL qui la ferme. Trois gestes reviennent, et aucun ne demande de toucher à cette garde :
# rendre un `Result` au lieu d'un `Vec`, solder le parcours en bloc
# (`collect::<rusqlite::Result<Vec<_>>>()`), ou poser `error`/`non_lu` dans le `json!` DÉJÀ construit.
# Les rangs ordonnent la dette par ce qu'un lecteur CROIT quand la liste est courte.

# RANG 1 — SÉCURITÉ ET ADMINISTRATION : une ligne avalée retire un accès, une règle de blocage ou une
# action de la vue de celui qui décide. C'est la classe où « la liste est courte » se lit « il n'y a
# rien de plus », et où cette lecture-là est une décision de sécurité.
#
# RANG UN CLOS LE 2026-09-16 — HUIT SITES, SIX FICHIERS, PLUS UNE SEULE ENTRÉE. Les huit entrées qui
# vivaient ici (`tokens_list`, `users_list`, `roles_list`, `idp_providers_list`, `netban_list`,
# `field_filters_list`, `actions_pending`, `respond_run`) sont RETIRÉES parce que leurs sites sont
# corrigés, pas amnistiés : chaque parcours est soldé en bloc (`collect::<rusqlite::Result<Vec<_>>>()`)
# et l'échec sort sous la forme que le dépôt emploie déjà — `error` dans le corps déjà construit
# (`liste_bornee::corps_de_liste_illisible`) pour les cinq listes JSON, un 5xx nommé pour la liste SSO
# (son corps est un TABLEAU NU, il n'a aucune clé où poser l'aveu), un 503 nommé pour la remise TSV aux
# agents (son seul lecteur écarte toute ligne non numérique, donc une ligne d'aveu n'y serait lue par
# personne), et un tour SAUTÉ ET COMPTÉ (`metrics::compter_un_tick_aveugle("responder_local", ..)`) pour
# la seule lecture interne du rang, qui ne sert aucun corps. Le dictionnaire reste, VIDE : le rang est
# une classe de l'ensemble, et son vide est le seul état qui dise « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_1_SECURITE = {}

# RANG 2 — DÉTECTION : une ligne avalée n'est pas une ligne d'affichage en moins, c'est de la
# DÉTECTION EN MOINS. Le produit continue de tourner, plus aveugle, et rien ne l'écrit.
#
# RANG DEUX CLOS LE 2026-09-16 — DIX SITES, SEPT FICHIERS, PLUS UNE SEULE ENTRÉE. Les dix entrées qui
# vivaient ici (`rules_list`, `parsers_list`, `baselines_list`, `playbooks_list`, `eval_baseline`,
# `load_policies`, `load_active_silences`, `load_active_engagements`, `soql_known_sources_bornees`,
# `sources_declarees_par_connecteurs`) sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés.
# CINQ listes SERVIES soldent leur parcours en bloc et avouent sous la forme du dépôt
# (`liste_bornee::corps_de_liste_illisible`) ; le vocabulaire de complétion y ajoute la distinction que
# son type déclarait ne pas tenir (`SourcesConnues::non_lue`) et son cache SWR de deux minutes N'ACCUEILLE
# PLUS un aveu — une lecture ratée ne se ressert pas. CINQ lectures INTERNES rendent désormais un `Result`,
# et chaque appelant agit en connaissance : le dispatch de notifications SAUTE son tour en le comptant
# (`dispatch_policies` / `dispatch_silences`) plutôt que de router à plat ou de notifier ce qu'un silence
# non lu aurait tu, et il ne marque aucune alerte `notified=1` (le tour suivant relit) ; le cache de portée
# des engagements GARDE sa valeur précédente et compte le tour (`engagement_scope_refresh`) plutôt que de
# se vider — se vider arme l'auto-ban contre une cible de pentest autorisée —, la route `GET
# /api/engagements/active` rendant un cinq cent trois nommé parce que son corps est un TABLEAU NU et que
# son unique consommateur (`collectors/engagement-adapter.sh`) porte déjà un fail-closed gradué sur le
# statut ; l'évaluation de ligne de base sur un historique non lu rend `ok=false` — « non évalué », ni
# anomalie ni normalité — que `run_baselines` compte sans avancer `last_bucket` ; et une source dont la
# déclaration par connecteur n'a pas pu être lue est servie `indeterminee`, jamais `unexpected`. Le
# dictionnaire reste, VIDE : le rang est une classe de l'ensemble, et son vide est le seul état qui dise
# « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_2_DETECTION = {}

# RANG 3 — DES COMPTES SERVIS COMME DES FAITS : ici la ligne avalée ne manque pas seulement dans une
# liste, elle FAUSSE un nombre que le corps affirme (un total, un recensement, un cumul d'index).
#
# RANG TROIS CLOS LE 2026-09-16 — CINQ SITES, QUATRE FICHIERS, PLUS UNE SEULE ENTRÉE. Les cinq entrées
# qui vivaient ici (`risk_entities_page`, `case_steps_json`, `index_stats`, `index_policies_list`,
# `sla_recalcule_la_priorite_bornee`) sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés.
# Le geste est le même qu'aux deux rangs précédents — solder le parcours en bloc
# (`collect::<rusqlite::Result<Vec<_>>>()`) — mais la conséquence est propre à ce rang : c'est le NOMBRE
# qui retombe, jamais un entier plus petit servi comme un fait. `risk_entities_page` compte APRÈS avoir
# soldé sa passe bornée, donc `total`, `over_threshold_total` et `over_threshold_hors_parc` valent
# ensemble `null` (`TotalBorne::sans_lecture()`, la règle « jamais (0, false) » que `liste_bornee` écrit
# pour lui-même) ; `case_steps_json`, dont `progress.total` DÉRIVE de `steps.len()`, sert `steps: []`
# avec `error` (`liste_bornee::corps_de_liste_illisible`) et `progress: null` plutôt qu'un `0/0` qui se
# lirait « ce case n'a aucune étape, et c'est établi » ; les DEUX lectures qui alimentent `indexes`
# avouent ensemble — `index_stats` rend désormais un `rusqlite::Result`, donc plus aucun index géré ne
# s'affiche « 0 event » et plus aucun index non géré ne DISPARAÎT de la liste (elle était dérivée des
# clés de cette map), et plus aucune politique perdue ne se relit « hérite du global », `ok` retombant
# à `false` comme le catalogue des rôles du rang un ; `sla_recalcule_la_priorite_bornee`, la DERNIÈRE
# lecture interne de l'ensemble, porte sa ligne illisible dans `manque`, de sorte que la route d'upsert
# SLA ne rend plus `204` = « tout recalculé » au-dessus d'un dossier qu'elle n'a pas su lire. Le
# dictionnaire reste, VIDE : le rang est une classe de l'ensemble, et son vide est le seul état qui
# dise « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_3_COMPTES = {}

# RANG 4 — LISTES DE CONFIGURATION ET DE CONTENU : la ligne avalée fait disparaître un objet d'une
# liste que l'opérateur lit comme exhaustive. Moins grave que les trois rangs précédents, jamais
# anodin : c'est sur ces listes qu'on conclut « ce n'est pas configuré ».
#
# VAGUE A CLOSE LE 2026-09-16 — TREIZE ACCUSATIONS, SIX FONCTIONS, QUATRE FICHIERS. Les entrées de
# `capture_dashboard_data`, `dash_get`, `views_list`, `knowledge_list` (SIX lectures), `datamodels_list`
# (TROIS) et `datasets_list` sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés. Trois
# listes servies soldent leur parcours en bloc et avouent par `liste_bornee::corps_de_liste_illisible` ;
# les DEUX corps qui portent plusieurs listes avouent PAR LECTURE — `corps_de_listes_illisibles` pose
# `non_lus` avec le NOM des familles non lues, chacune présente et vide, les autres restant servies,
# parce qu'un aveu qui couvre tout ne couvre rien. La capture d'instantané, elle, REFUSE : elle rend un
# `rusqlite::Result` et `snapshot_create` répond 503 sans rien écrire, parce que son produit est FIGÉ et
# PARTAGEABLE PAR JETON — un aveu embarqué dans l'artefact serait relu par un tiers qui ne peut plus
# rien recouper. Reste la VAGUE B : les dix-neuf entrées ci-dessous.
DEFAUTS_RANG_4_CONFIGURATION = {
    # Les liens d'un case : un lien avalé fait lire « ce case n'a pas ce lien ». Le corps est déjà
    # celui du fabricant borné (`liste_bornee::corps`) — la coupe s'y écrit sans changer de type.
    ("daemon/src/handlers/caseops.rs", "case_links_json"): 1,
    # Les files par assigné : une file avalée retire un assigné de la vue qui existe pour le montrer.
    ("daemon/src/handlers/caseops.rs", "case_queues_json"): 1,
    # Les réglages d'hôtes déclarés : un hôte avalé se lit « pas de réglage pour cet hôte ».
    ("daemon/src/handlers/hotes_declares.rs", "host_settings_get"): 1,
    # La liste des politiques d'alerte SERVIE (distincte du chargement interne du rang 2).
    ("daemon/src/handlers/alerting.rs", "policies_list"): 1,
    # La liste des silences SERVIE : un silence avalé se lit « cette alerte n'est pas silencée ».
    ("daemon/src/handlers/alerting.rs", "silences_list"): 1,
    # Les fournisseurs d'IA configurés : un fournisseur avalé se lit « non configuré ».
    ("daemon/src/handlers/ai.rs", "ai_providers_list"): 1,
    # La fiche d'un engagement : une ligne de portée avalée RÉTRÉCIT la portée affichée d'un pentest.
    ("daemon/src/handlers/engagement.rs", "engagement_get"): 1,
    # Les rapports planifiés : un rapport avalé se lit « aucun rapport planifié » pour cette entrée.
    ("daemon/src/handlers/scheduled_reports.rs", "reports_list"): 1,
    # La tactique et la cible DOMINANTES d'un case sont dérivées d'un parcours aplati : une ligne
    # avalée peut CHANGER le vainqueur, et le corps sert le résultat comme un fait.
    ("daemon/src/handlers/incidents.rs", "dominant_tactic_and_target"): 1,
    # Les runbooks attachés à un case : un runbook avalé se lit « pas de procédure ».
    ("daemon/src/handlers/incidents.rs", "case_runbooks_json"): 1,
    # La liste d'administration des runbooks : idem, côté admin.
    ("daemon/src/handlers/incidents.rs", "runbooks_admin_list"): 1,
    # La fiche d'un runbook : une étape avalée fait suivre une procédure AMPUTÉE.
    ("daemon/src/handlers/incidents.rs", "runbook_get"): 1,
    # Les notifieurs : un notifieur avalé se lit « aucune notification configurée sur ce canal ».
    ("daemon/src/handlers/notifiers.rs", "notifiers_list"): 1,
    # Les destinations d'export : une destination avalée se lit « rien n'est exporté vers là ».
    ("daemon/src/handlers/destinations.rs", "destinations_list"): 1,
    # Les processeurs d'ingestion : un processeur avalé se lit « cette transformation n'existe pas »,
    # alors qu'elle s'applique bel et bien aux événements.
    ("daemon/src/handlers/processors.rs", "processors_list"): 1,
    # Les requêtes sauvegardées d'un propriétaire : une requête avalée se lit « supprimée ».
    ("daemon/src/handlers/saved_queries.rs", "list_for_owner"): 1,
    # Les réglages d'une source : une ligne avalée se lit « ce réglage n'est pas posé ».
    ("daemon/src/handlers/sources.rs", "source_settings_get"): 1,
    # Les lookups : une table de correspondance avalée se lit « pas de lookup », et un enrichissement
    # qu'on croit absent est en fait invisible.
    ("daemon/src/handlers/users_lookups.rs", "lookups_list"): 1,
    # Les actions de workflow : une action avalée disparaît du workflow affiché.
    ("daemon/src/handlers/workflow_actions.rs", "workflow_actions_list"): 1,
}

CLASSES = (
    ("assumé", SITES_ASSUMES),
    ("indécidable", SITE_INDECIDABLE),
    ("défaut connu — rang 1 sécurité/administration", DEFAUTS_RANG_1_SECURITE),
    ("défaut connu — rang 2 détection", DEFAUTS_RANG_2_DETECTION),
    ("défaut connu — rang 3 comptes servis comme des faits", DEFAUTS_RANG_3_COMPTES),
    ("défaut connu — rang 4 configuration et contenu", DEFAUTS_RANG_4_CONFIGURATION),
)
SITES_ADMIS = {}
for _libelle, _classe in CLASSES:
    for _cle, _n in _classe.items():
        SITES_ADMIS[_cle] = SITES_ADMIS.get(_cle, 0) + _n
DEFAUTS_CONNUS = {c: n for lib, cl in CLASSES if lib.startswith("défaut") for c, n in cl.items()}


# ================================================================================================
# LES LECTEURS DE FORME
# ================================================================================================
def positions_de_coupe(code):
    """Indices des `;`, `{` et `}` HORS chaîne : les bornes d'instruction. Une accolade dans un
    littéral SQL ne coupe rien."""
    out, j, n = [], 0, len(code)
    while j < n:
        c = code[j]
        if c == '"':
            j += 1
            while j < n and code[j] != '"':
                j += 2 if code[j] == "\\" else 1
            j += 1
            continue
        if c in ";{}":
            out.append(j)
        j += 1
    return out


def debut_instruction(coupes, i):
    """Index du premier caractère de l'instruction qui contient `i`."""
    bas, haut = 0, len(coupes)
    while bas < haut:
        mil = (bas + haut) // 2
        if coupes[mil] < i:
            bas = mil + 1
        else:
            haut = mil
    return coupes[bas - 1] + 1 if bas else 0


def chaine_detaillee(code, fin):
    """Les méthodes chaînées après la fermante en `fin`, AVEC les bornes de leurs arguments :
    `[(nom, index du jeton, début d'argument, fin d'argument)]` et l'index de fin d'expression.

    C'EST LA DIFFÉRENCE AVEC `chaine_apres` DE LA GARDE SŒUR, ET C'EST TOUT LE PREMIER ANGLE MORT :
    là-bas l'argument est élidé en `(…)`, donc `map(|x| x.flatten().collect())` rend le jeton
    `map(…)`, qui n'appartient à aucun vocabulaire d'avalement. Ici l'argument est RENDU, et
    l'écriture (ii) l'ouvre."""
    jetons, k = [], fin + 1
    while k < len(code):
        c = code[k]
        if c in " \t\n":
            k += 1
            continue
        if c == "?":
            jetons.append(("?", k, -1, -1))
            k += 1
            continue
        if c != ".":
            break
        m = re.match(r"\.\s*([A-Za-z_]\w*)\s*", code[k:])
        if not m:
            break
        nom, debut_jeton = m.group(1), k
        k += m.end()
        if code.startswith("::", k):  # turbofish : `.collect::<Vec<_>>()`
            g = code.find("<", k)
            if g < 0:
                break
            prof, j = 0, g
            while j < len(code):
                if code[j] == "<":
                    prof += 1
                elif code[j] == ">":
                    prof -= 1
                    if prof == 0:
                        break
                j += 1
            if j >= len(code):
                break
            k = j + 1
            while k < len(code) and code[k] in " \t\n":
                k += 1
        a1 = a2 = -1
        if k < len(code) and code[k] == "(":
            e = apparier(code, k)
            if e < 0:
                break
            a1, a2 = k + 1, e
            k = e + 1
        jetons.append((nom, debut_jeton, a1, a2))
    return jetons, k


def jeton_avale(nom, code, a1, a2):
    """Le jeton lui-même EST un avalement de ligne."""
    if nom == "flatten":
        return a1 >= 0 and not code[a1:a2].strip()
    if nom in ("filter_map", "flat_map") and a1 >= 0:
        arg = code[a1:a2].strip()
        return bool(re.fullmatch(r"Result\s*::\s*ok", arg)
                    or re.fullmatch(r"\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)", arg))
    return False


def portee_englobante(fns, i):
    """(nom, début, fin) de la plus petite fonction qui contient `i`, ou None."""
    dedans = [f for f in fns if f[2] < i < f[3]]
    return min(dedans, key=lambda f: f[3] - f[2]) if dedans else None


def liaisons(code, coupes, debut_lecture, apres, fns):
    """Les noms auxquels CETTE lecture est liée, avec la portée où les chercher :
    `[(nom, début de portée, fin de portée)]`.

    Deux formes, et elles couvrent l'arbre du 2026-09-16 : le préfixe d'instruction qui ouvre par
    `let`/`let Ok(..)`/`if let Ok(..)`, et le `match` dont la lecture est le SCRUTATEUR, dont les bras
    lient par `Ok(<nom>)`. La portée s'arrête à la fonction englobante — un nom n'est pas suivi d'une
    fonction à l'autre, et le dire est plus honnête que de fouiller le fichier entier."""
    out = []
    prefixe = code[debut_instruction(coupes, debut_lecture):debut_lecture]
    englobante = portee_englobante(fns, debut_lecture)
    fin_portee = englobante[3] if englobante else len(code)
    m = LIE_PAR_LET.search(prefixe)
    if m:
        out.append((m.group(1), apres, fin_portee))
    # LE BRAS DU `match` DONT LA LECTURE EST LE SCRUTATEUR. La portée est le BLOC du `match`, jamais
    # la fonction : un `Ok(rows)` de bras ne vit pas au-delà de son accolade.
    j = apres
    while j < len(code) and code[j] in " \t\n":
        j += 1
    if j < len(code) and code[j] == "{" and MATCH_EN_TETE.search(prefixe):
        f = apparier(code, j)
        if f > 0:
            for b in LIE_PAR_BRAS.finditer(code, j, f):
                out.append((b.group(1), b.end(), f))
    return out


# ================================================================================================
# LA DÉCOUVERTE — UN SITE EST UNE OCCURRENCE D'APLATISSEMENT, PAS UN APPEL
# ================================================================================================
def analyser(chemin_relatif, texte, journal):
    """[(chemin, ligne, fonction, écriture, extrait)] pour UN fichier. `journal` recueille ce que le
    lecteur avoue avoir perdu : un aveu vaut refus de conclure, jamais un compte amputé rendu vert."""
    code = coupe_tests(sans_commentaires_rust(texte))
    fns = fonctions(code)
    coupes = positions_de_coupe(code)
    trouves = {}

    def poser(index, ecriture, extrait):
        ancien = trouves.get(index)
        if ancien and RANG_ECRITURE[ancien[0]] <= RANG_ECRITURE[ecriture]:
            return
        trouves[index] = (ecriture, extrait)

    for m in LECTURE_LIGNES.finditer(code):
        ouvrante = m.end() - 1
        fin = apparier(code, ouvrante)
        if fin < 0:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur la lecture "
                           "de lignes : le lecteur a perdu la fin de l'expression")
            continue
        jetons, apres = chaine_detaillee(code, fin)

        # --- (i) CHAÎNE DIRECTE : seuls `?`, `unwrap()` et `expect(..)` s'intercalent.
        for nom, index, a1, a2 in jetons:
            if jeton_avale(nom, code, a1, a2):
                poser(index, "i", code[index:index + 60].split("\n")[0].strip())
                break
            if nom not in TRANSPARENT:
                break

        # --- (ii) CHAÎNE ENVELOPPÉE : l'avalement vit DANS l'argument d'un jeton de la chaîne.
        for nom, _index, a1, a2 in jetons:
            if a1 < 0:
                continue
            for av in AVALE_LIGNE.finditer(code, a1, a2):
                poser(av.start(), "ii", code[av.start():av.start() + 60].split("\n")[0].strip())

        # --- (iii)/(iv) LIAISON : la lecture porte un nom, et le nom porte l'avalement.
        for nom_lie, portee_deb, portee_fin in liaisons(code, coupes, m.start(), apres, fns):
            motif = re.compile(r"\b" + re.escape(nom_lie) + r"\s*(" + AVALE_LIGNE.pattern + r")")
            for u in motif.finditer(code, portee_deb, portee_fin):
                amont = code[max(0, u.start() - 200):u.start()]
                ecriture = "iv" if BOUCLE_AVANT.search(amont) else "iii"
                poser(u.start(1), ecriture, code[u.start():u.start() + 60].split("\n")[0].strip())

    sites = []
    for index in sorted(trouves):
        ecriture, extrait = trouves[index]
        englobante = portee_englobante(fns, index)
        if not englobante:
            ligne = code.count("\n", 0, index) + 1
            journal.append(f"{chemin_relatif}:{ligne} — aplatissement HORS de toute fonction : la portée "
                           "est introuvable, et un site sans fonction ne peut pas entrer dans l'ensemble")
            continue
        sites.append((chemin_relatif, code.count("\n", 0, index) + 1, englobante[0], ecriture, extrait))
    return sites


def fichiers_du_corpus():
    """`daemon/src/handlers/*.rs` — le répertoire PLAT, et rien d'autre pour cette première forme.
    Les sous-répertoires (`handlers/connectors/`) en sont dehors, et le verdict le dit."""
    if not os.path.isdir(HANDLERS):
        return []
    return [os.path.join(HANDLERS, n) for n in sorted(os.listdir(HANDLERS))
            if n.endswith(".rs") and os.path.isfile(os.path.join(HANDLERS, n))]


def decouvrir():
    sites, journal = [], []
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        sites += analyser(os.path.relpath(chemin, RACINE), texte, journal)
    return sites, journal


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS
# ================================================================================================
def juger_contre_l_ensemble(sites, admis):
    """[(genre, fichier, phrase)] — `forme neuve` quand une accusation dépasse ce qui est admis,
    `exemption sans objet` quand une entrée n'est plus accusée autant qu'elle le déclare."""
    vus = {}
    for chemin, _ligne, fn, _ecriture, _extrait in sites:
        vus[(chemin, fn)] = vus.get((chemin, fn), 0) + 1
    ecarts = []
    for (chemin, fn), n in sorted(vus.items()):
        admise = admis.get((chemin, fn), 0)
        if n > admise:
            ecarts.append(("forme neuve", chemin,
                           f"FORME NEUVE — `{fn}` aplatit {n} fois un itérateur de lignes pour "
                           f"{admise} admise(s) dans SITES_ADMIS. La forme doit solder son parcours "
                           "(`collect::<rusqlite::Result<Vec<_>>>()`), rendre un `Result`, ou entrer "
                           "dans l'ensemble AVEC sa raison — jamais en silence."))
    for (chemin, fn), n in sorted(admis.items()):
        if vus.get((chemin, fn), 0) < n:
            ecarts.append(("exemption sans objet", chemin,
                           f"EXEMPTION SANS OBJET — `{fn}` est admis {n} fois dans SITES_ADMIS et n'est "
                           f"accusé que {vus.get((chemin, fn), 0)} fois : le site solde désormais son "
                           "parcours, ou n'existe plus, ou cette garde a cessé de le voir. Dans les trois "
                           "cas l'entrée se retire à la main EN DISANT LEQUEL — un canal qui rétrécit ne "
                           "doit pas passer pour un défaut fermé."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES INTERNES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Les extraits sont FABRIQUÉS ici, jamais pris sur l'arbre : adosser un témoin à `tokens_list` ou à
# `knowledge_list` en ferait une RANÇON — il rougirait le jour où le site est réparé, et aucun geste
# ne pourrait le refermer.
EPREUVES = [
    # (nom, source Rust, écritures attendues — vide = aucune accusation)
    ("(i) chaîne directe, `unwrap()` intercalé",
     'fn e1(conn: &Connection) -> Vec<i64> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '    s.query_map([], |r| r.get(0)).unwrap().flatten().collect()\n}\n', {"i"}),
    ("(i) chaîne directe, `?` intercalé, avalement par `filter_map(Result::ok)`",
     'fn e1b(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    Ok(s.query_map([], |r| r.get(0))?.filter_map(Result::ok).collect())\n}\n', {"i"}),
    ("(ii) chaîne enveloppée, l'avalement vit dans l'argument de `map`",
     'fn e2(conn: &Connection) -> Vec<i64> {\n'
     '    conn.prepare("SELECT a FROM t")\n'
     '        .and_then(|mut s| s.query_map([], |r| r.get(0)).map(|x| x.flatten().collect()))\n'
     '        .unwrap_or_default()\n}\n', {"ii"}),
    ("(iii) liaison par `let ... else`",
     'fn e3(conn: &Connection) -> Vec<i64> {\n'
     '    let Ok(mut s) = conn.prepare("SELECT a FROM t") else { return Vec::new() };\n'
     '    let Ok(rows) = s.query_map([], |r| r.get(0)) else { return Vec::new() };\n'
     '    rows.flat_map(|r| r.ok()).collect()\n}\n', {"iii"}),
    ("(iii) liaison par un bras de `match` dont la lecture est le scrutateur",
     'fn e3b(conn: &Connection, mut s: Statement) -> Vec<i64> {\n'
     '    match s.query_map([], |r| r.get(0)) {\n'
     '        Ok(rows) => rows.flatten().collect(),\n'
     '        Err(_) => Vec::new(),\n'
     '    }\n}\n', {"iii"}),
    ("(iv) boucle sur une liaison posée par `if let Ok(..)`",
     'fn e4(conn: &Connection) -> Vec<i64> {\n'
     '    let mut o = Vec::new();\n'
     '    if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        if let Ok(rows) = s.query_map([], |r| r.get(0)) {\n'
     '            for a in rows.flatten() { o.push(a); }\n'
     '        }\n    }\n    o\n}\n', {"iv"}),
    # --- LES TÉMOINS NÉGATIFS : chacun est une forme que la garde DOIT laisser passer.
    ("témoin négatif : `query_row(..).ok().flatten()` (famille voisine, Option imbriquée)",
     'fn n1(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT MAX(ts) FROM t", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()\n}\n',
     set()),
    # CE TÉMOIN-CI A ÉTÉ AJOUTÉ PARCE QUE LE PRÉCÉDENT NE TENAIT PAS CE QUE SON NOM ANNONÇAIT, ET
    # C'EST MESURÉ (2026-09-16) : en faisant entrer `query_row` dans le RECEVEUR — la mutation qui
    # fait entrer la famille voisine — le témoin ci-dessus reste VERT, parce que son `.ok()` casse la
    # chaîne directe avant l'avalement. Il tue autre chose (l'intercalation d'un `.ok()`), et il est
    # gardé pour cela ; la mutation du receveur, elle, est tuée ICI, où le `query_row` est LIÉ et son
    # nom aplati — exactement la forme que la garde accuserait si son receveur débordait.
    ("témoin négatif : un `query_row` LIÉ puis aplati — le receveur, pas l'intercalation",
     'fn n1b(conn: &Connection) -> Option<i64> {\n'
     '    let dernier = conn.query_row("SELECT MAX(ts) FROM t", [], |r| r.get::<_, Option<i64>>(0)).ok();\n'
     '    dernier.flatten()\n}\n', set()),
    ("témoin négatif : `capture_names().flatten()` (aucune lecture de lignes)",
     'fn n2(re: &Regex) -> Vec<String> {\n'
     '    let mut o = Vec::new();\n'
     '    for name in re.capture_names().flatten() { o.push(name.to_string()); }\n'
     '    o\n}\n', set()),
    ("témoin négatif : `.await.ok().flatten()` (une tâche, pas un itérateur de lignes)",
     'async fn n3(db_path: String, sql: String) -> Option<Value> {\n'
     '    tokio::task::spawn_blocking(move || eval_value(&db_path, &sql)).await.ok().flatten()\n}\n',
     set()),
    ("témoin négatif : `Option<Option<_>>` rendu par une fonction",
     'fn n4(ref_bib: &RefBibliotheque) -> Option<i64> { ref_bib.a_ecrire().flatten() }\n', set()),
    ("témoin négatif : l'aplatissement est dans un commentaire `//`",
     'fn n5(conn: &Connection) -> Vec<i64> {\n'
     '    // l\'idiome d\'avant : s.query_map([], f).flatten().collect() — remplacé par un solde en bloc\n'
     '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '    s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()\n}\n',
     set()),
    ("témoin négatif : l'aplatissement est dans un `#[cfg(test)] mod`",
     'fn n6() -> i64 { 0 }\n'
     '#[cfg(test)]\nmod tests {\n    use super::*;\n'
     '    #[test]\n    fn t(conn: &Connection) {\n'
     '        let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '        let v: Vec<i64> = s.query_map([], |r| r.get(0)).unwrap().flatten().collect();\n'
     '        assert!(v.is_empty());\n    }\n}\n', set()),
    ("témoin négatif : le parcours est SOLDÉ EN BLOC — c'est la forme que la garde réclame",
     'fn n7(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()\n}\n', set()),
    ("témoin négatif : un `map` SANS avalement dedans",
     'fn n8(conn: &Connection) -> rusqlite::Result<Vec<rusqlite::Result<i64>>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    Ok(s.query_map([], |r| r.get(0))?.map(|r| r.map(|x| x + 1)).collect())\n}\n', set()),
]


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict, et dans les deux sens. Un instrument qui
    prétend mesurer ce qu'il n'atteint pas est pire qu'une garde absente.

    CHAQUE ÉPREUVE A ÉTÉ ÉPROUVÉE PAR MUTATION le 2026-09-16, et la phrase dit ce qui a été MESURÉ,
    pas ce qui serait joli. Onze mutations jouées contre ce lot, onze tuées : débrancher l'écriture
    (ii), débrancher la liaison, forcer `jeton_avale` à vrai, élargir le receveur à `query_row`,
    débrancher `coupe_tests`, débrancher le dépouillement des commentaires, cesser de distinguer la
    boucle, vider `TRANSPARENT`, débrancher le jugement de l'ensemble, rendre `apparier` aveugle, et
    élider les arguments de la chaîne (c'est-à-dire RECOPIER l'angle mort de la garde sœur).

    ET UN TÉMOIN A DÛ ÊTRE AJOUTÉ PARCE QUE LE LOT NE TENAIT PAS CE QU'IL ANNONÇAIT. La mutation « le
    receveur s'élargit à `query_row` » a d'abord SURVÉCU : le témoin négatif de la famille voisine
    s'écrit `query_row(..).ok().flatten()`, et son `.ok()` casse la chaîne directe AVANT l'avalement —
    il reste vert quel que soit le receveur. Il est gardé pour ce qu'il tue vraiment (l'intercalation
    d'un `.ok()`), et la mutation est désormais tuée par un témoin qui LIE le `query_row` puis aplatit
    son nom, plus deux témoins au niveau du prédicat."""
    errs = []
    for nom, src, attendues in EPREUVES:
        journal = []
        sites = analyser("/epreuve.rs", src, journal)
        vues = {e for _c, _l, _f, e, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if attendues and vues != attendues:
            errs.append(f"épreuve « {nom} » : écritures vues {sorted(vues) or 'aucune'}, attendu "
                        f"{sorted(attendues)} — la garde ne voit plus la forme qu'elle nomme, ou elle la "
                        "range sous la mauvaise écriture et la phrase imprimée ment sur le site")
        if not attendues and vues:
            errs.append(f"épreuve « {nom} » : accusée sous {sorted(vues)} alors qu'elle est HORS FAMILLE "
                        "ou HONNÊTE — la garde accuse une forme qu'aucun geste local ne referme")

    # --- LE RECEVEUR, ÉPROUVÉ À SON PROPRE NIVEAU ET DANS LES DEUX SENS. Le témoin `n1b` ci-dessus
    # tue la mutation qui fait entrer `query_row` dans la population, mais il pourrait passer pour une
    # raison ÉTRANGÈRE (un `let` qui ne se lierait pas). Ces deux-ci n'interrogent que le prédicat.
    if not LECTURE_LIGNES.search("stmt.query_map([], f)") or not LECTURE_LIGNES.search("s.query_and_then([], f)"):
        errs.append("épreuve du RECEVEUR (positif, au niveau du prédicat) : `query_map` ou "
                    "`query_and_then` n'est plus reconnu comme une lecture de LIGNES — la population "
                    "de cette garde est vide, et son vert ne dit plus rien")
    if LECTURE_LIGNES.search("conn.query_row(sql, [], f)"):
        errs.append("épreuve du RECEVEUR (négatif, au niveau du prédicat) : `query_row` est entré dans "
                    "la population. C'est la famille VOISINE — une seule ligne, où le défaut est de "
                    "confondre « aucune ligne » et « pas lu » — et l'y faire entrer sans la mesurer est "
                    "la faute que la garde sœur a payée deux fois")

    # --- LES DEUX ANGLES MORTS DE LA GARDE SŒUR SONT PROUVÉS, PAS ALLÉGUÉS. Sans cette épreuve, la
    # raison d'être de ce fichier serait une affirmation d'en-tête ; le jour où la sœur apprend l'une
    # des deux formes, c'est ICI qu'on l'apprend, et la question « faut-il encore deux gardes ? » se
    # repose avec une mesure. L'épreuve est DÉFENSIVE dans un seul sens : elle rougit si la sœur se
    # met à voir, elle n'exige jamais qu'un défaut survive.
    lectures_avalees = None
    sys.argv = [_ARGV[0], RACINE]
    try:
        from check_a_read_that_did_not_happen_is_never_served_as_a_fact import lectures_avalees
    except Exception as e:  # noqa: BLE001 — l'aveu vaut mieux qu'un silence
        errs.append(f"épreuve des ANGLES MORTS : la garde sœur n'est pas importable ({e})")
    finally:
        sys.argv = _ARGV
    if lectures_avalees is not None:
        enveloppe = ('let v = conn.prepare(sql).and_then(|mut s| '
                     's.query_map(params![id], |r| r.get(0)).map(|x| x.flatten().collect()));')
        liaison = ('let Ok(rows) = s.query_map(params![n], |r| r.get::<_, String>(0)) else { return out; };\n'
                   'for src in rows.flatten() { out.push(src); }')
        for libelle, extrait, site in (("CHAÎNE ENVELOPPÉE", enveloppe, "caseops.rs:323/363"),
                                       ("LIAISON", liaison, "soql_meta.rs:218")):
            if lectures_avalees(extrait):
                errs.append(f"épreuve des ANGLES MORTS ({libelle}) : la garde sœur VOIT désormais cette "
                            f"forme (site prouvé {site}). Ce n'est pas une panne — c'est que la raison "
                            "d'être de cette garde-ci a changé, et l'en-tête doit être re-mesuré avant "
                            "que le verdict reprenne.")
            if not analyser("/angle_mort.rs", "fn a(conn: &Connection) -> Vec<Value> { let mut out = "
                            "Vec::new(); " + extrait + " out }", []):
                errs.append(f"épreuve des ANGLES MORTS ({libelle}) : CETTE garde ne voit pas non plus la "
                            "forme qu'elle existe pour voir — les deux sœurs sont aveugles au même "
                            "endroit, et le verdict ne vaut rien")

    # --- L'ENSEMBLE NOMMÉ EST JUGÉ DANS LES DEUX SENS, À SON PROPRE NIVEAU. Sans ces deux épreuves,
    # un `juger_contre_l_ensemble` débranché rendrait la garde verte quoi que l'arbre porte.
    faux_site = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "i", ".flatten()")]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(faux_site, {})}
    if genres != {"forme neuve"}:
        errs.append(f"épreuve de l'ENSEMBLE (forme neuve) : genres {sorted(genres) or 'aucun'} au lieu de "
                    "['forme neuve'] — une accusation hors ensemble ne rougit plus, et l'ensemble ne "
                    "peut plus que grandir en silence")
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        [], {("daemon/src/handlers/fabrique.rs", "fn_fantome"): 1})}
    if genres != {"exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (exemption sans objet) : genres {sorted(genres) or 'aucun'} au "
                    "lieu de ['exemption sans objet'] — une entrée sans objet ne rougit plus, et la liste "
                    "cesse de descendre quand le dépôt guérit")
    if juger_contre_l_ensemble(faux_site, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): 1}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site EXACTEMENT admis produit un écart — la garde "
                    "serait rouge sur l'arbre qu'elle déclare elle-même admis")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * une LECTURE INTERNE sans corps servi est jugée comme les autres, et le geste qui la ferme "
          "n'est PAS le même : il faut rendre un `Result` à l'appelant, pas poser un aveu dans un corps "
          "qui n'existe pas. Elles étaient SIX au relevé du matin (`respond_run`, `load_policies`, "
          "`load_active_silences`, `load_active_engagements`, `eval_baseline`, "
          "`sla_recalcule_la_priorite_bornee`) ; les rangs un, deux et trois les ont TOUTES SIX fermées, "
          "et il n'en reste AUCUNE dans l'ensemble. La phrase est corrigée à chaque rang plutôt que gardée "
          "telle quelle : une garde qui énumère des entrées qui n'existent plus enseigne un arbre qui "
          "n'est pas celui qu'elle juge. Ce que la garde ne sait toujours pas faire n'a pas changé — elle "
          "ne distingue pas une lecture interne d'une liste servie, et le rouge qu'elle poserait sur la "
          "prochaine ne se refermerait pas par le geste qu'elle nomme.\n"
          "  * elle ne dit PAS si un aveu de région couvre la lecture accusée. Une fonction qui pose déjà "
          "`error` pour une AUTRE de ses lectures reste accusée pour celle-ci — c'est voulu (un aveu qui "
          "couvre tout ne couvre rien), mais cela veut dire que le rouge ne mesure pas la distance qui "
          "reste à parcourir.\n"
          "  * elle ne tient pas ce que la CONSOLE affiche. Le démon peut avouer une troncature ; qu'un "
          "module de `web/` lise l'aveu se juge ailleurs "
          "(`check_a_refusal_is_not_rendered_as_an_absence.py`).\n"
          "  * elle ne tient pas les `.ok()` sur `query_row` — famille VOISINE, pas la même : là-bas c'est "
          "UNE ligne, et le défaut est de confondre « aucune ligne » (fait légitime) avec « pas lu » (fait "
          "inventé). Trois occurrences de code sur l'arbre au 2026-09-16 ; à MESURER avant d'élargir, "
          "parce qu'élargir sans mesurer est exactement la faute que la garde sœur a payée deux fois.\n"
          "  * elle ne lit que `daemon/src/handlers/` À PLAT. Les modules hors handlers qui servent des "
          "corps ne sont pas mesurés, et `handlers/connectors/` non plus (un site y porte la forme au "
          "2026-09-16). Ce n'est pas un oubli, c'est la borne de cette première forme — mais un corps "
          "servi peut naître ailleurs, et tant que la mesure n'est pas faite, le vert ne dit rien d'eux.\n"
          "  * elle ne suit pas la liaison à travers un APPEL. Un itérateur rendu par une fonction et "
          "aplati chez son appelant n'est relié à aucune lecture ; la portée d'un nom lié s'arrête à sa "
          "fonction, et c'est dit plutôt que sous-entendu.\n"
          "  * elle ne juge pas ce que le MAPPEUR fait. Un mappeur qui ne peut pas échouer rend "
          "l'aplatissement inoffensif ; la garde l'accuse quand même, parce qu'elle lit du texte et qu'un "
          "mappeur infaillible aujourd'hui gagne un `r.get()` demain.\n"
          "  * elle ne prouve RIEN à l'exécution. Elle constate qu'une forme est absente du dépôt, jamais "
          "qu'une réponse réelle avoue sa troncature.")


def main():
    # --- LES ÉPREUVES D'ABORD : aucune lecture du dépôt tant que l'instrument n'a pas été éprouvé.
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    # --- L'ANCRAGE : `query_map` doit être la méthode rusqlite que cette garde croit lire. Sans cet
    # ancrage, un dépôt qui aurait changé de bibliothèque rendrait zéro site et la garde serait verte
    # pour la pire des raisons.
    cargo = os.path.join(RACINE, "daemon", "Cargo.toml")
    manifeste = ""
    if os.path.isfile(cargo):
        with open(cargo, encoding="utf-8", errors="replace") as fh:
            manifeste = fh.read()
    hors_handlers = 0
    for dossier, sous, noms in os.walk(DEMON):
        sous[:] = [d for d in sous if d not in ("tests", "handlers")]
        for nom in noms:
            if not nom.endswith(".rs"):
                continue
            with open(os.path.join(dossier, nom), encoding="utf-8", errors="replace") as fh:
                hors_handlers += fh.read().count(".query_map(")
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M) and hors_handlers == 0:
        print("::error::ni `rusqlite` dans daemon/Cargo.toml ni un seul `.query_map(` dans daemon/src "
              "hors handlers : `query_map` n'est plus la méthode que cette garde croit lire, et sa "
              "population n'a plus d'ancrage. Elle REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, journal = decouvrir()
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression ; il ne "
              "rend pas un compte amputé en vert.")
        ce_qui_n_est_pas_tenu()
        return 2

    fichiers = {c for c, _l, _f, _e, _x in sites}
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} (relus le 2026-09-16 après le rang trois, aux deux "
              "tiers du relevé de ce jour-là : 35 sites sur 20 fichiers). La DÉCOUVERTE est cassée, pas "
              "le dépôt guéri : la garde REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle. "
              "Si la descente est RÉELLE, ce sont les planchers qui se relisent, avec leur date — jamais "
              "la découverte qu'on élargit pour les satisfaire.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, ecriture, extrait in sorted(sites):
        print(f"::error file={chemin},line={ligne}::`{fn}` aplatit un itérateur de lignes "
              f"({ECRITURES[ecriture]}) : une ligne illisible est avalée et la liste est servie comme "
              f"complète, sans un mot — `{extrait}`")

    par_ecriture = {}
    for _c, _l, _f, e, _x in sites:
        par_ecriture[e] = par_ecriture.get(e, 0) + 1
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} site(s) sur "
          f"{len(fichiers)} fichier(s) de daemon/src/handlers — "
          + " · ".join(f"{ECRITURES[e]} {n}" for e, n in sorted(par_ecriture.items(),
                                                                key=lambda p: RANG_ECRITURE[p[0]]))
          + ". Commentaires DÉPOUILLÉS et modules de test COUPÉS : une occurrence citée en commentaire "
            "ou écrite dans un `#[cfg(test)] mod` n'est jamais un site.")

    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    if ecarts:
        for _genre, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre les accusations du jour et l'ensemble nommé. "
              "L'ensemble se corrige à la main, AVEC la raison ; zéro reste atteignable.")
        ce_qui_n_est_pas_tenu()
        return 1

    print(f"[{ETIQUETTE}] ADMIS, par classe : "
          + " · ".join(f"{lib} {sum(cl.values())}" for lib, cl in CLASSES) + ".")
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte ({len(sites)} site(s)) — "
          "ni forme neuve, ni exemption sans objet.")
    print(f"[{ETIQUETTE}] CE QUE LE VERT NE DIT PAS : les {sum(DEFAUTS_CONNUS.values())} accusations de "
          "la classe (3) sont des DÉFAUTS CONNUS ET NON CORRIGÉS, admis pour que cette garde puisse être "
          "câblée verte AUJOURD'HUI plutôt que d'attendre une campagne. Chacune sert une liste tronquée "
          "comme complète. CHAQUE correction doit RETIRER son entrée de SITES_ADMIS, sous peine "
          "d'« exemption sans objet » — c'est ce qui fait descendre la liste au lieu de la laisser "
          "devenir un décor.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
