#!/usr/bin/env python3
"""Une lecture de LIGNE UNIQUE qui a ÉCHOUÉ n'est jamais servie comme un FAIT — garde de CI (`P10.20-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`query_row` de rusqlite rend un `Result<T>` qui porte TROIS états dans un seul canal : la ligne a été
lue, il n'y avait AUCUNE ligne (`QueryReturnedNoRows`), ou la lecture N'A PAS EU LIEU (table absente
d'un cache de schéma de pool périmé, colonne qu'une migration vient d'ajouter et que la connexion qui
sert ne voit pas encore, `TEXT` corrompu qui ne se convertit pas, verrou indisponible). Le troisième
état est le seul qui ne soit pas un fait sur les données — c'est un fait sur l'INSTRUMENT.

L'idiome qui ABSORBE l'échec écrase ces trois états en un seul :

  * `.ok()` rend `Option<T>` — « aucune ligne » et « pas lu » deviennent le même `None` ;
  * `.unwrap_or(v)`, `.unwrap_or_default()`, `.unwrap_or_else(|_| v)` rendent une VALEUR FABRIQUÉE —
    il ne reste même plus une absence à interroger ;
  * `.map(f).unwrap_or(v)` / `.map_or(v, f)` font la même chose un cran plus loin, et se lisent comme
    une transformation honnête ;
  * `.is_ok()` / `.is_err()` transforment la lecture en test d'EXISTENCE : une lecture ratée s'y lit
    « la ligne n'existe pas » (ou « elle existe »), selon le sens du test.

Le corps servi, la décision prise ou l'écriture faite ensuite ont alors exactement la forme qu'ils
auraient si la base avait répondu. Personne ne peut distinguer « ce compte n'a pas de second
facteur » de « la table du second facteur n'a pas été lue ».

POURQUOI CETTE GARDE EXISTE, ET CE QUI A ÉTÉ RÉFUTÉ EN L'ÉCRIVANT (2026-09-16)
------------------------------------------------------------------------------
`P10.20-b` pose la QUESTION dans ces termes : « la garde de famille sait-elle juger cette forme par le
même geste — un `query_row(` dont le PREMIER JETON CHAÎNÉ est `ok` — avec un ensemble nommé de
départ ? » La réponse mesurée est OUI POUR LE GESTE, NON POUR SON PÉRIMÈTRE, et le contre-exemple est
DANS LA CLÉ ELLE-MÊME :

  * la clé écrit que le pire défaut du rang un — `mfa_enabled_for`, où une lecture ratée de `user_mfa`
    posait la session d'un compte à MFA active sur le mot de passe SEUL — « n'était pas dans les
    cinquante » parce qu'il s'écrivait `.map(..).unwrap_or(false)`, dont le premier jeton chaîné est
    `map`. Le geste que la QUESTION propose ne voit donc PAS le site qui l'a motivée ;
  * re-mesuré sur l'arbre du 2026-09-16 (HEAD `655de62`), `daemon/src/handlers/` sous-répertoires
    compris porte 210 appels à `query_row`. QUATRE-VINGT-DOUZE en absorbent l'échec. Le geste
    « premier jeton `ok` » n'en voit que TRENTE-SIX. Les CINQUANTE-SIX autres sont : `unwrap_or` 22,
    `is_err` 19, `is_ok` 6, `unwrap_or_else` 5, `map.unwrap_or` 3, `unwrap_or_default` 1 ;
  * et parmi ces cinquante-six invisibles il y a un site de RANG UN, sur l'arbre aujourd'hui :
    `dashboards.rs:160` (`dash_update`) et `dashboards.rs:358` (`panel_update`) lisent la visibilité
    COURANTE par `.unwrap_or_else(|_| "shared".into())`. `panneau_resolu::est_un_geste_de_partage`
    rend `true` seulement si la visibilité courante N'EST PAS déjà `shared` ; une lecture ratée la
    déclare `shared`, le geste n'est donc PAS un partage, et la porte `P11.20-m` — celle qui refuse de
    publier un tableau de bord contenant un élément moins visible — est ENJAMBÉE avant l'écriture qui
    publie. `view_update` (`dashboards.rs:1135`), même forme, retombe sur `"private"` et la porte
    s'applique : le dépôt connaît déjà le bon défaut, à deux sites sur trois près.

D'où le geste de CETTE garde, qui n'est pas « le premier jeton est `ok` » mais : **un `query_row(`
dont la chaîne atteint un jeton ABSORBANT avant tout jeton PROPAGATEUR**. Il contient la famille que
la clé nomme, et il contient le contre-exemple qui l'a réfutée.

CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ, ET QUI EST CORRIGÉ ICI
-------------------------------------------------------
`docs/ROADMAP.md` écrit, dans les RESTES du rang un : « cent vingt et une occurrences hors
`handlers/` (quarante-neuf fichiers, cent deux fonctions) comptées, non classées ». C'est un REPORT
DE MAUVAISE ÉTIQUETTE, vérifiable dans le relevé qui l'a produit : `121 / 49 / 102` est le total de
`daemon/src` ENTIER pour le geste `ok`, dont `50 / 20 / 46` étaient DANS `handlers/`. Le vrai HORS
`handlers/` de ce moment-là valait `71 / 29 / 56`. Sur l'arbre d'aujourd'hui, le geste `ok` donne
`36` dans `handlers/` et `106` sur `daemon/src`, soit `70` hors `handlers/` ; le geste ÉLARGI de cette
garde donne `90` dans `handlers/` et `249` sur `daemon/src`, soit **159 hors `handlers/`**. C'est ce
dernier chiffre que le verdict d'ici déclare HORS PÉRIMÈTRE, et non les cent vingt et une.

CE QUE LA POPULATION VAUT AU JOUR DE L'ÉCRITURE (2026-09-16, 15 h 40)
---------------------------------------------------------------------
`daemon/src/handlers/`, SOUS-RÉPERTOIRES COMPRIS, commentaires DÉPOUILLÉS et modules `#[cfg(test)]`
COUPÉS par les lecteurs partagés, littéraux de chaîne EXCLUS :

  * 209 appels à `query_row` ;
  * 90 ABSORBENT l'échec — 28 fichiers, 74 fonctions. C'est la population de cette garde ;
  * 12 le PROPAGENT (`?`, `.optional()?`, `unwrap`, `expect`) ou portent un jeton que le lecteur ne
    connaît pas : aucune accusation ;
  * 107 laissent la chaîne NUE — le `Result` est lié à un nom, rendu à l'appelant, ou SCRUTÉ par un
    `match`. C'est le plus gros angle mort de cette garde, il est mesuré et il est écrit plus bas.

LE CLASSEMENT DES QUATRE-VINGT-DOUZE, par un critère écrit : ce que le repli fait au moment où la
lecture rate. RANG UN, il OUVRE une porte (le repli est moins restrictif que la vérité) ou pose un
fait de santé ; RANG DEUX, il est SERVI dans un corps ou ÉCRIT en base ; RANG TROIS, il est INTERNE —
il fait sauter un tour ou recalculer, sans corps ni écriture ; RANG QUATRE, il REFUSE (404, 400, 409,
contrainte `UNIQUE` qui reprend la main) : la cause servie est fausse, aucun fait n'est inventé. Un
cinquième cas n'est pas un défaut : l'ARBITRAGE ASSUMÉ, où l'échec de la lecture EST le fait servi.

  rang 1 :  3 sites,  2 fonctions
  rang 2 : 18 sites, 11 fonctions
  rang 3 : 16 sites, 13 fonctions
  rang 4 : 52 sites, 47 fonctions
  assumé :  1 site,   1 fonction

L'ARBRE A BOUGÉ PENDANT L'ÉCRITURE, ET C'EST DIT : relevés à 12 h 37, les deux `unwrap_or` de
`freshness.rs::compute_freshness` (`P10.20-g`) faisaient 92 sites sur 29 fichiers ; un lot voisin les a
fermés à 15 h 31. Le relevé ci-dessus est celui de l'ARBRE DE TRAVAIL, c'est-à-dire de ce que la CI
verra quand le lot partira — pas celui de `HEAD`, qui en porte encore deux.

CE QUE LE CLASSEMENT DE `P10.20-b` AVAIT DE FAUX OU DE TU, MESURÉ ICI. Le classement du matin rangeait
`incidents.rs:730 runbook_admin_json` au rang deux ; la clé l'a elle-même reclassé rang quatre après
lecture de son consommateur, et il est ici en rang quatre. Et les sites que le geste `ok` ne voyait pas
ne sont pas des broutilles : le compte d'administrateurs qui garde le DERNIER admin
(`users_lookups.rs:110/155`) retombe à zéro — fail-closed, mais la phrase servie dit « dernier
administrateur » sur une lecture qui n'a pas eu lieu ; les DEUX plafonds anti-DoS de runbooks custom
(`incidents.rs:845/886`) et le plafond par propriétaire des requêtes sauvegardées
(`saved_queries.rs:58`) retombent à zéro, donc s'effacent ; la garde « un runbook est déjà attaché »
(`incidents.rs:404`) retombe à zéro et laisse ÉCRASER une progression existante ; deux filigranes
(`connectors/mod.rs:606`, `destinations.rs:828`) sont relus après coup et leur repli entre dans une
ligne de REGISTRE tamper-evident ; `actions.rs:1260` écrit dans ce même registre « verdict `` déjà
posé » quand le statut conservé n'a pas pu être relu.

POURQUOI UNE GARDE NEUVE, ET NON UNE SECONDE FAMILLE DANS `check_a_truncated_list_…`
-------------------------------------------------------------------------------------
La garde de famille (`P10.7-f`) partage TOUS ses lecteurs avec celle-ci — ils sont IMPORTÉS ici, pas
recopiés — mais trois mesures séparent les deux verdicts, et c'est le verdict qui décide du fichier :

  * SON NOM. `check_a_truncated_list_is_never_served_as_a_complete_one` dit ce qu'elle tient. Une
    lecture de LIGNE UNIQUE n'est pas une liste tronquée : y loger cette famille rendrait le nom faux
    pour la moitié de son contenu, et ce dépôt juge les noms (`hugo-explicit-naming`) ;
  * SON REFUS. `main()` de la garde de famille rend `2` — aucun verdict — dès que son lecteur avoue,
    que son plancher est franchi ou qu'une de ses épreuves tombe. Partagé, l'effondrement du plancher
    d'UNE famille ferait TAIRE l'autre, qui serait verte. Deux populations de tailles très
    différentes (2 sites contre 92) n'ont aucune raison de partager un interrupteur ;
  * SON ÉPREUVE NÉGATIVE. La garde de famille contient une épreuve, jouée à chaque exécution, qui
    ROUGIT si `query_row` entre dans SA population (« c'est la famille VOISINE, et l'y faire entrer
    sans la mesurer est la faute que la garde sœur a payée deux fois »). Cette épreuve reste vraie et
    reste là : les deux gestes sont disjoints par construction, et c'est cette garde-ci qui prend la
    famille voisine, une fois la mesure faite.

LE COÛT DE CE CHOIX EST MESURÉ ET IL N'EST PAS NUL : `check_every_guard_written_is_a_guard_wired.py`
lit le RÉPERTOIRE, pas l'index, et compte ORPHELINE toute garde qu'aucun flux n'exécute. Tant que
`.github/workflows/ci.yml` ne porte pas le pas qui appelle ce fichier, cette garde-là est ROUGE. Le
câblage (un pas `id: garde_68` et une ligne d'agrégation) est le prix d'entrée, et il se paie dans la
même livraison.

POURQUOI UN ENSEMBLE NOMMÉ, ET POURQUOI IL PORTE LES FORMES
------------------------------------------------------------
Un cliquet de COMPTE se laisse compenser : une accusation fermée et une ouverte le même jour laissent
le total immobile. `SITES_ADMIS` est donc une liste de SITES, jugée DANS LES DEUX SENS — une
accusation hors ensemble est une FORME NEUVE (rouge, avec fichier, fonction et forme), une entrée qui
n'est plus accusée est une EXEMPTION SANS OBJET (rouge).

Et l'ensemble porte les FORMES, pas un nombre — c'est la différence avec la garde de famille, et elle
est là pour un défaut mesuré. Si l'entrée ne portait qu'un compte, réécrire `mfa_verify` de `.ok()` en
`.unwrap_or((String::new(), 0))` laisserait le compte à 1 et RIEN ne rougirait, alors que le repli
serait passé d'une absence à une valeur fabriquée. Une entrée admet donc EXACTEMENT les formes
constatées ; changer la forme d'un site admis rougit des deux côtés à la fois (forme neuve pour la
nouvelle, exemption sans objet pour l'ancienne), ce qui est la bonne lecture — ce n'est pas le même
site.

CE QUE CE VERT NE DIRA PAS
---------------------------
Écrit ici parce qu'un vert qu'on ne sait pas lire est pire qu'un rouge : la liste complète est dans
`ce_qui_n_est_pas_tenu()`, et son premier terme est le plus lourd — les 105 `query_row` dont la chaîne
est NUE, dont le `match … { Err(_) => … }` qui est la même faute écrite autrement.

TOUS LES LECTEURS DE FORME SONT IMPORTÉS, ET LEURS TÉMOINS SONT JOUÉS (`P10.20-r`, 2026-09-16)
------------------------------------------------------------------------------------------------
Ce fichier portait encore UN lecteur en propre : `spans_de_chaines`, avec sa propre grammaire du
littéral de caractère. C'était le cinquième exemplaire de cette grammaire sous `.github/scripts/`, et
c'est la recopie qui a fait vivre quatre grammaires divergentes (`P10.20-c` à `-e`). Il vit désormais
dans `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py` sous le nom
`spans_de_chaines_rust`, à côté de `_saut_de_litteral_rust` dont il tient sa règle, et il est importé
ici. COMPORTEMENT INCHANGÉ, vérifié par re-mesure avant/après sur instantané : sortie identique.

ET LES TÉMOINS DE CES LECTEURS SONT APPELÉS (`temoins_des_lecteurs_de_forme`), au même endroit que
`temoins_du_lecteur` : un import n'exécute aucun témoin. CE QUE LA MESURE A DIT, ET QUI NUANCE
L'ÉNONCÉ DE `P10.20-r` : cette garde-ci n'était PAS sans filet sur `apparier` — sous une mutation qui
retire la règle du littéral de caractère, son `epreuve_du_litteral_d_octet` la faisait déjà REFUSER DE
CONCLURE (code 2, mesuré le 2026-09-16). L'appel ajouté ici ne la sauve donc pas d'un trou qu'elle
avait ; il fait deux choses PLUS PETITES, et elles sont dites plutôt que gonflées : il nomme la cause
au NIVEAU DU LECTEUR (le message dit « `'\"'` n'est plus sauté » au lieu de « je ne trouve plus le site
d'`/angle_mort_octet.rs` »), et il couvre `arguments` et `bras_du_match` — que cette garde N'APPELLE
PAS, ni directement ni par ses lecteurs importés. Ce dernier point est DÉFENSIF ET DÉCLARÉ TEL : son
seul mérite est qu'aucun des trois points d'entrée ne peut plus charger un lecteur partagé régressé
sans le dire, quelle que soit celle des trois gardes que la CI joue en premier.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS DE LA GARDE DE FAMILLE, JAMAIS RECOPIÉS. Ce dépôt paie cher les lecteurs
# jumeaux : deux appariements de parenthèses ou deux dépouillements de commentaires finissent par
# diverger, et le jour où l'un apprend quelque chose l'autre ment. La garde de famille évalue sa
# propre `RACINE` À L'IMPORT (par `sys.argv`), et elle-même importe la garde sœur de la même façon ;
# on lui passe donc la racine DÉJÀ calculée ici, pour qu'aucun des trois modules ne cherche un dépôt
# git (une archive dépliée en est dépourvue) ni ne juge un arbre différent de celui-ci.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_truncated_list_is_never_served_as_a_complete_one import (  # noqa: E402
        ARBRE_FABRIQUE, SOURCES_ATTENDUES, apparier, chaine_detaillee, coupe_tests,
        dans_une_chaine_rust, debut_instruction, fonctions, parcours_des_sources, portee_englobante,
        positions_de_coupe, refuser_sur_aveu, sans_commentaires_rust, spans_de_chaines_rust,
        temoins_des_lecteurs_de_forme, temoins_du_lecteur)
finally:
    sys.argv = _ARGV

HANDLERS = os.path.join(RACINE, "daemon", "src", "handlers")
DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "lecture-unique-avalee"

# --- LE GESTE -------------------------------------------------------------------------------------
# LA LECTURE : la méthode rusqlite qui rend UNE ligne dans un `Result`. Les espaces sont tolérés :
# un `rustfmt` qui coupe entre le receveur et la méthode ne doit pas faire disparaître un site.
LECTURE_UNE_LIGNE = re.compile(r"\.\s*query_row\s*\(")

# LES JETONS ABSORBANTS — ils convertissent l'ÉCHEC en valeur ou en absence, et c'est là que le fait
# s'invente. Chacun est nommé parce qu'il existe sur l'arbre ou parce qu'il est la réécriture d'un
# jeton qui y existe : `map_or`/`map_or_else` sont la forme condensée de `map(..).unwrap_or(..)`, qui,
# elle, est la forme du pire défaut de la clé (`mfa_enabled_for`).
ABSORBANTS = ("ok", "unwrap_or", "unwrap_or_default", "unwrap_or_else", "map_or", "map_or_else",
              "is_ok", "is_err")
# LES JETONS TRAVERSANTS — ils rendent encore un `Result`, donc l'échec vit toujours : on continue de
# lire la chaîne. `optional` en fait partie ET C'EST DÉLIBÉRÉ : `.optional()?` est le geste HONNÊTE
# (l'absence devient `Ok(None)` et l'échec se propage), mais `.optional().ok()` ré-absorbe l'échec un
# cran plus loin, et il doit rougir.
TRAVERSANTS = ("map", "and_then", "map_err", "or_else", "inspect", "inspect_err", "optional",
               "filter")
# LES JETONS PROPAGATEURS — l'échec SORT de la fonction. `?` le rend à l'appelant ; `unwrap` et
# `expect` TUENT le processus. Aucun des trois n'invente un fait, et c'est la seule question que cette
# garde pose. Qu'un `unwrap()` dans un gestionnaire soit un défaut d'une AUTRE famille est vrai, et
# c'est dit dans le verdict plutôt que jugé ici.
PROPAGATEURS = ("?", "unwrap", "expect")

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-09-16) -------------------------------
# Ils ne réclament PAS un volume de code : ils constatent qu'une LECTURE est cassée. Sous eux, rendre
# vert serait rendre vert en étant aveugle — le défaut que cette garde nomme, appliqué à elle-même.
#
# DÉRIVÉS DU RELEVÉ DU JOUR par la règle des deux tiers, celle de la garde de famille : 90 sites sur
# 28 fichiers -> 69 % de 90 = 62,1 -> 62 (troncature et arrondi s'accordent) et 65 % de 28 = 18,2 ->
# 18 (ils s'accordent aussi). D'où 62/18. ILS NE MONTENT JAMAIS. À chaque lot qui ferme des sites, ils
# se RE-DÉRIVENT du relevé de ce moment-là par la même règle, avec sa date écrite ici : un plancher
# laissé au-dessus de la population rendrait la garde rouge sur le dépôt qu'elle vient d'aider à
# guérir, et le rouge accuserait la DÉCOUVERTE là où le dépôt aurait été corrigé.
#
# CE QU'ILS NE SÉPARENT PAS, ET C'EST LE FILET QUI COMPTE : une découverte PARTIELLEMENT aveugle passe
# sous eux sans les franchir. C'est le jugement de l'ensemble nommé DANS LES DEUX SENS qui la prend —
# chaque site qui cesse d'être vu sans que son entrée soit retirée devient une « exemption sans
# objet ». Le plancher ne couvre que l'effondrement ASSEZ large pour que ce rouge-là passe pour une
# guérison.
PLANCHER_SITES = 62
PLANCHER_FICHIERS = 18

# ================================================================================================
# L'ENSEMBLE NOMMÉ — CINQ CLASSES, JUGÉES DANS LES DEUX SENS
# ================================================================================================
# La valeur d'une entrée est le TUPLE DES FORMES admises pour cette fonction, une forme par site (les
# doublons sont significatifs : `retention_preview` admet CINQ `unwrap_or`). La forme est la suite des
# jetons chaînés, jusqu'à quatre, telle que le lecteur la lit.

# --- CLASSE 1 : L'ARBITRAGE ASSUMÉ. Ce n'est PAS un défaut : l'échec de la lecture EST le fait servi.
SITES_ASSUMES = {
    # `readyz` interroge la connexion par un `SELECT 1` qui ne touche AUCUNE table. Un `Err` n'y est
    # pas « la ligne n'a pas pu être lue », c'est « la base ne répond pas » — exactement ce que
    # `db_ok: false` publie, et le corps le sert tel quel. RÉSERVE ÉCRITE, la même que la décision de
    # route consignée dans `P10.20-b` : `SELECT 1` ne prouve rien sur les tables, et un `meta`
    # illisible laisserait cette sonde verte. Elle ne prétend pas le contraire.
    ("daemon/src/handlers/system.rs", "readyz"): ("map.unwrap_or",),
}

# --- CLASSE 2 : RANG UN — LE REPLI OUVRE UNE PORTE. La valeur substituée est MOINS RESTRICTIVE que
# la vérité, et elle entre dans une décision de sécurité. C'est la classe où « je n'ai pas lu » se
# lit « rien ne s'y oppose ».
DEFAUTS_RANG_1_LE_REPLI_OUVRE = {
    # CLASSE VIDÉE LE 2026-09-16 PAR `P10.20-k`. Elle portait DEUX entrées, `dashboards.rs::dash_update`
    # (`is_ok`, `unwrap_or_else`) et `dashboards.rs::panel_update` (`unwrap_or_else`) : la visibilité
    # COURANTE lue par `unwrap_or_else(|_| "shared")` faisait rendre `false` à
    # `est_un_geste_de_partage` (il exige `visibilite_courante != "shared"`), donc la porte `P11.20-m`
    # — celle qui REFUSE de publier un contenant portant un élément moins visible — n'était pas jouée,
    # et l'écriture qui publie suivait. LES DEUX SITES LISENT DÉSORMAIS L'EXISTENCE ET LA VISIBILITÉ EN
    # UN SEUL ÉNONCÉ rendu en `Result<Option<_>>` : `Ok(None)` = 404, `Err(..)` = 503 nommé
    # (`panneau_resolu::CAUSE_VISIBILITE_NON_LUE`) posé AVANT tout jugement de partage. Les entrées
    # sont retirées parce que les formes ont disparu — les garder ferait rougir « exemption sans objet ».
    # La classe reste déclarée : un rang un neuf s'y écrit sans qu'on ait à la ré-inventer.
}

# --- CLASSE 3 : RANG DEUX — LA VALEUR FABRIQUÉE EST SERVIE OU ÉCRITE. Un lecteur humain, une ligne de
# registre ou le tour suivant la prennent pour un fait.
DEFAUTS_RANG_2_FAIT_SERVI_OU_ECRIT = {
    # ENTRÉE RETIRÉE LE 2026-09-16 PAR `P10.20-q`. Elle disait : le statut CONSERVÉ d'une action déjà
    # tranchée retombait à `""` par `unwrap_or_default()` et partait dans le REGISTRE tamper-evident
    # (« verdict `` déjà posé, conservé »), donc la trace non purgeable portait un verdict vide
    # qu'aucune relecture ne pouvait recouper — et « la ligne a DISPARU » s'y écrivait exactement
    # comme « la ligne n'a PAS ÉTÉ LUE ». La relecture est désormais un énoncé typé,
    # `verdict_conserve_relu` -> `VerdictConserve::{Lu, LigneDisparue, NonRelu}` : les trois issues
    # ont leur phrase, et la lecture non faite porte son PROPRE `kind` de registre
    # (`action.exec.verdict-non-relu`), donc elle se filtre dans la trace. La forme a disparu du
    # site — la garder ferait rougir « exemption sans objet ».
    # CINQ lectures d'aperçu de rétention retombent sur `(0, None)`. L'opérateur lit « rien à purger »
    # sur cinq familles d'objets, juste avant de décider d'une purge. GESTE : solder les cinq en
    # `Result` et servir `null` + la cause, jamais un zéro.
    ("daemon/src/handlers/admin_ui.rs", "retention_preview"):
        ("unwrap_or", "unwrap_or", "unwrap_or", "unwrap_or", "unwrap_or"),
    # L'échéance SLA du dossier qui vient d'être créé retombe à `None` et part dans le corps de
    # création : « ce dossier n'a pas d'échéance » est servi là où la ligne n'a pas été relue.
    ("daemon/src/handlers/cases.rs", "case_create"): ("unwrap_or",),
    # DEUX sites. `ok` sur la configuration du connecteur (fail-closed) ; `unwrap_or((0, None))` sur
    # `last_count`/`last_error` relus APRÈS le poll, dont le `0` entre dans la ligne d'AUDIT
    # (`config.connector.poll … count=0`). Une trace d'audit qui affirme zéro événement collecté.
    ("daemon/src/handlers/connectors/mod.rs", "connector_poll"): ("ok", "unwrap_or"),
    # `has_children` retombe à `false` sur une lecture ratée, et la SUPPRESSION de l'objet de modèle
    # passe alors la garde qui existait pour protéger ses enfants. Une destruction sur un fait inventé.
    ("daemon/src/handlers/datamodels.rs", "object_delete"): ("map.unwrap_or",),
    # DEUX sites. `ok` sur la définition de la destination (fail-closed) ; `unwrap_or((watermark, 0,
    # None))` sur l'état relu après l'envoi, servi dans le corps ET dans l'audit de gouvernance
    # `P11.13-c` — le filigrane et le compte y sont affirmés sans avoir été relus.
    ("daemon/src/handlers/destinations.rs", "destination_flush"): ("ok", "unwrap_or"),
    # PAS D'ENTRÉE POUR `freshness.rs::compute_freshness`, ET C'EST UNE MESURE, PAS UN OUBLI. Les DEUX
    # comptes de métriques (`n_24h`, nombre de séries) y retombaient à zéro par `unwrap_or` et
    # partaient dans `/api/freshness` — la trouvaille consignée sous `P10.20-g`. Relevés à 12 h 37 le
    # 2026-09-16, ils ont été FERMÉS à 15 h 31 par le lot voisin, qui les a remplacés par un `match`
    # rendant `(volume_24h, nombre_de_series, cause_des_comptes)`. La fonction ne porte plus AUCUNE
    # chaîne absorbante, et lui laisser une entrée aurait fait rougir cette garde en « exemption sans
    # objet » le jour de son câblage. C'est écrit ici parce que l'absence d'une entrée attendue est
    # exactement ce que personne ne relit.
    # DEUX sites. `is_err` sur l'existence du dossier (fail-closed) ; `unwrap_or(0)` sur le compte
    # d'étapes DÉJÀ attachées, dont le zéro fait sauter la garde « un runbook est déjà attaché à cet
    # incident (progression existante) » — une progression réelle est alors ÉCRASÉE par une seconde
    # attache. GESTE : `.optional()?` et refuser, le geste étant idempotent-refusant par ailleurs.
    ("daemon/src/handlers/incidents.rs", "attach_runbook"): ("is_err", "unwrap_or"),
    # Le compte de runbooks custom retombe à zéro : le PLAFOND anti-DoS (`RUNBOOK_MAX_CUSTOM`) cesse
    # d'exister, et l'écriture suit.
    ("daemon/src/handlers/incidents.rs", "clone_runbook"): ("unwrap_or",),
    ("daemon/src/handlers/incidents.rs", "create_custom_runbook"): ("unwrap_or",),
    # Le MODE global retombe sur `"observe"` et part dans le corps de la liste, à côté d'une liste qui
    # sait déjà avouer. La console affiche « ce playbook PROPOSE » alors que le démon peut être en
    # `active` et EXÉCUTER : la conséquence servie est l'inverse de la conséquence réelle.
    ("daemon/src/handlers/playbooks.rs", "playbooks_list"): ("unwrap_or_else",),
    # Le compte par propriétaire retombe à zéro : le plafond per-user des requêtes sauvegardées
    # s'efface. Le doc-commentaire du module décrit déjà ce plafond comme le point où un trou de liste
    # se referme — ici c'est le plafond lui-même qui disparaît.
    ("daemon/src/handlers/saved_queries.rs", "count_for_owner"): ("unwrap_or",),
}

# --- CLASSE 4 : RANG TROIS — INTERNE. Le repli ne sert aucun corps et n'écrit rien : il fait sauter
# un tour, recalculer, ou retomber sur un défaut. Jamais anodin, jamais un fait inventé non plus.
DEFAUTS_RANG_3_INTERNE = {
    # Le throttle d'alerte n'est pas lu -> l'alerte TIRE. Le sens est BRUYANT (jamais un silence),
    # c'est ce qui le tient au rang trois plutôt qu'au rang deux.
    ("daemon/src/handlers/alerting.rs", "run_advanced_rules"): ("ok",),
    # Les quatre lectures du chrono SLA : politique non lue -> repli muet sur le régime legacy ;
    # échéances non recalculées ; chrono ni mis en pause ni repris ; tour multi-niveaux SAUTÉ parce
    # que `EXISTS(sla_policy)` retombe à zéro. Aucun corps servi ; le temps, lui, avance.
    ("daemon/src/handlers/caseops.rs", "sla_policy_for"): ("ok",),
    ("daemon/src/handlers/caseops.rs", "sla_apply_policy"): ("ok",),
    ("daemon/src/handlers/caseops.rs", "sla_on_status_change"): ("ok",),
    ("daemon/src/handlers/caseops.rs", "sla_multilevel_tick"): ("unwrap_or",),
    # Coût de panneau recalculé, TTL de cache global, cache de panneau manqué : replis bénins, dits
    # bénins, et gardés dans l'ensemble pour que leur forme ne change pas en silence.
    ("daemon/src/handlers/dashboards.rs", "read_panel_cost"): ("ok",),
    ("daemon/src/handlers/dashboards.rs", "panel_cache_ttl"): ("ok.flatten",),
    ("daemon/src/handlers/panneau_avoue.rs", "cache_lire"): ("ok",),
    # L'override ADMIN d'affichage retombe sur la variable d'environnement : le réglage posé par
    # l'opérateur est silencieusement remplacé par celui du déploiement.
    ("daemon/src/handlers/dashboards.rs", "excl_display_csv"): ("ok.map.unwrap_or_else",),
    # DEUX sites dans `premier` : le compte de retenus retombe à zéro et la ligne elle-même devient
    # `None` — « rien ne retient », donc le partage passe. Rang TROIS et non UN parce que la doc de
    # `P11.20-m` établit que ce refus-là ne ferme aucune fuite (règle PRODUIT) ; si cette doc change,
    # cette entrée monte au rang un.
    ("daemon/src/handlers/panneau_resolu.rs", "premier"): ("ok", "unwrap_or"),
    # Le mode retombe sur `"observe"` : aucune action n'est exécutée. Fail-SAFE, et c'est pour cela
    # que ce jumeau de `playbooks_list` est au rang trois quand l'autre est au rang deux — celui-ci ne
    # sert rien, il s'abstient.
    ("daemon/src/handlers/playbooks.rs", "run_playbooks"): ("unwrap_or_else",),
    # TROIS sondes d'existence du rollup de risque retombent à `false` : le tour de rollup est sauté,
    # et aucune alerte de risque n'est levée. Rien n'est servi ; la détection, elle, n'a pas eu lieu.
    ("daemon/src/handlers/rba.rs", "rollup_risk"): ("unwrap_or", "unwrap_or", "unwrap_or"),
    # `.ok()?` sur la ligne du dossier : la projection ENTIÈRE (tactique dominante, recommandation,
    # catalogue) disparaît du corps de dossier. RÉSERVE ÉCRITE : son unique appelant de production
    # (`incidents.rs:608`) n'a PAS été relu pour ce lot, donc le rang trois est le plus prudent des
    # deux lectures possibles ; si cet appelant sert un corps où la section manque en silence, cette
    # entrée est un rang deux.
    ("daemon/src/handlers/incidents.rs", "case_runbooks_json"): ("ok.?",),
}

# --- CLASSE 5 : RANG QUATRE — FAIL-CLOSED. Le repli REFUSE (404, 400, 401, 409, ou une contrainte
# `UNIQUE` qui reprend la main sur l'insertion). La CAUSE servie est fausse — « introuvable » pour une
# ligne qui existe, « aucune MFA enrôlée » pour une table qui n'a pas répondu — mais aucun fait n'est
# inventé et aucune porte ne s'ouvre. C'est la classe la plus nombreuse, et la moins urgente.
DEFAUTS_RANG_4_FAIL_CLOSED = {
    ("daemon/src/handlers/ai.rs", "ai_provider_delete"): ("ok",),
    ("daemon/src/handlers/ai.rs", "ai_provider_update"): ("ok",),
    ("daemon/src/handlers/alerting.rs", "policy_delete"): ("is_err",),
    ("daemon/src/handlers/alerting.rs", "policy_update"): ("is_err",),
    ("daemon/src/handlers/alerting.rs", "silence_delete"): ("is_err",),
    ("daemon/src/handlers/caseops.rs", "case_link_add"): ("is_err",),
    ("daemon/src/handlers/caseops.rs", "case_merge"): ("ok", "ok"),
    ("daemon/src/handlers/caseops.rs", "case_unmerge"): ("ok",),
    ("daemon/src/handlers/cases.rs", "case_apply_update"): ("ok",),
    ("daemon/src/handlers/cases.rs", "case_item_add"): ("is_err",),
    ("daemon/src/handlers/cases.rs", "case_set_archived"): ("is_err",),
    ("daemon/src/handlers/connectors/mod.rs", "connector_test"): ("ok",),
    ("daemon/src/handlers/connectors/mod.rs", "connector_update"): ("is_err",),
    ("daemon/src/handlers/dash_ergonomics.rs", "library_panel_delete"): ("is_err",),
    ("daemon/src/handlers/dash_ergonomics.rs", "playlist_delete"): ("is_err",),
    ("daemon/src/handlers/dash_ergonomics.rs", "playlist_update"): ("is_err",),
    ("daemon/src/handlers/dashboards.rs", "dash_get"): ("ok",),
    # DEUX `.ok()?` dans la porte d'accès aux panneaux : la porte rend `None`, l'appelant refuse. La
    # porte est bien fail-closed ; ce qui manque est la DISTINCTION entre « ce panneau n'existe pas »
    # et « je n'ai pas pu lire s'il existe ».
    ("daemon/src/handlers/dashboards.rs", "panel_access"): ("ok.?", "ok.?"),
    # `dashboards.rs::view_update` VIVAIT ICI, et son entrée est retirée le 2026-09-16 par `P10.20-k`.
    # Elle disait vrai : son repli `"private"` retombait du BON côté, la porte de partage s'appliquait,
    # et ce site servait de contrôle POSITIF au rang un. Il est pourtant RALLIÉ à la forme de ses deux
    # voisins, parce que le refus qu'il servait alors était un 409 NOMMANT un élément moins visible —
    # une cause FAUSSE pour une lecture qui n'a pas eu lieu, qui envoie l'appelant partager un élément
    # quand il doit réessayer. La forme `unwrap_or_else` a disparu avec les deux autres ; laisser
    # l'entrée ferait rougir « exemption sans objet ». CE QUE L'ÉNONCÉ DE `P10.20-k` N'AVAIT PAS VU :
    # il demandait de rallier `view_update` ET de ne retirer que DEUX entrées — c'en fait trois.
    ("daemon/src/handlers/datamodels.rs", "field_create"): ("is_err",),
    ("daemon/src/handlers/datamodels.rs", "object_create"): ("is_err",),
    ("daemon/src/handlers/detection.rs", "rule_test"): ("ok",),
    ("daemon/src/handlers/detection_advanced.rs", "correlation_test"): ("ok",),
    # `.map(..).unwrap_or(false)` : un permis de pentest dont la fenêtre n'a pas pu être lue est
    # DEHORS. Le doc-commentaire de la fonction écrit déjà que refuser est la bonne réponse pour le
    # cas ambigu ; ce qu'il ne distingue pas, c'est l'ambiguïté et la lecture ratée.
    ("daemon/src/handlers/engagement.rs", "engagement_cred_within_window"): ("map.unwrap_or",),
    ("daemon/src/handlers/engagement.rs", "engagement_end"): ("is_ok",),
    # `is_ok` sur un nom déjà pris : la lecture ratée fait sauter le 409 explicite, et l'INSERT tombe
    # sur la contrainte `UNIQUE` de la colonne (vérifié dans `migrate.rs`) — « échec de transaction
    # opaque », exactement ce que le commentaire du site dit vouloir éviter. Fail-closed par la BASE,
    # pas par le code.
    ("daemon/src/handlers/governance.rs", "ledger_sink_create"): ("is_ok",),
    ("daemon/src/handlers/governance.rs", "legal_hold_create"): ("is_ok",),
    ("daemon/src/handlers/idp.rs", "idp_provider_delete"): ("ok",),
    ("daemon/src/handlers/idp.rs", "idp_provider_update"): ("is_err",),
    # Les quatre lectures d'identité : provider LDAP/OIDC non lu -> « aucun provider activé » (la
    # connexion échoue), secret MFA non lu -> « aucune MFA enrôlée » / « aucune MFA active pour ce
    # compte » (le second facteur refuse). Tous REFUSENT ; aucun n'avoue pourquoi.
    ("daemon/src/handlers/idp.rs", "ldap_login_post"): ("ok.map",),
    ("daemon/src/handlers/idp.rs", "load_provider"): ("ok.map",),
    ("daemon/src/handlers/idp.rs", "login_mfa_post"): ("ok",),
    ("daemon/src/handlers/idp.rs", "mfa_disable"): ("ok",),
    ("daemon/src/handlers/idp.rs", "mfa_verify"): ("ok",),
    ("daemon/src/handlers/incidents.rs", "incident_apply_tier"): ("is_err",),
    # RECLASSÉ PAR LA CLÉ ELLE-MÊME : le classement du matin le rangeait au rang deux (« le runbook
    # DISPARAÎT de la vue d'authoring ») ; la relecture de son unique consommateur a montré un 404
    # « runbook introuvable » sur une procédure qui existe. Cause fausse, aucun fait inventé.
    ("daemon/src/handlers/incidents.rs", "runbook_admin_json"): ("ok",),
    # `while … .is_ok()` : une lecture ratée fait SORTIR de la boucle avec une clé peut-être prise.
    # `runbook.key` est `TEXT NOT NULL UNIQUE` (vérifié dans `migrate.rs`) : l'insertion échoue, la
    # création est refusée avec une cause d'insertion plutôt qu'avec la vraie.
    ("daemon/src/handlers/incidents.rs", "unique_custom_key"): ("is_ok",),
    ("daemon/src/handlers/index_policies.rs", "index_policy_create"): ("is_ok",),
    ("daemon/src/handlers/notifiers.rs", "notifier_test"): ("ok",),
    # L'état COURANT du panneau non lu -> `None` -> `panel_access` (`dashboards.rs:42`) rend `None` et
    # l'accès est refusé.
    ("daemon/src/handlers/panneau_resolu.rs", "courante"): ("ok",),
    ("daemon/src/handlers/playbooks.rs", "playbook_test"): ("ok",),
    ("daemon/src/handlers/scheduled_reports.rs", "report_create"): ("is_err", "is_err"),
    ("daemon/src/handlers/scheduled_reports.rs", "report_run_now"): ("is_err",),
    ("daemon/src/handlers/tokens.rs", "token_delete"): ("unwrap_or",),
    ("daemon/src/handlers/users_lookups.rs", "lookup_delete"): ("is_err",),
    # DEUX sites chacun. `ok` sur la cible -> 404. `unwrap_or(0)` sur le COMPTE D'ADMINISTRATEURS :
    # zéro est `<= 1`, donc la garde « dernier administrateur — suppression refusée » se DÉCLENCHE.
    # Fail-closed, et c'est le bon côté ; la phrase servie, elle, affirme un fait sur le parc des
    # comptes qui n'a pas été lu.
    ("daemon/src/handlers/users_lookups.rs", "user_delete"): ("ok", "unwrap_or"),
    ("daemon/src/handlers/users_lookups.rs", "user_update"): ("ok", "unwrap_or"),
}

CLASSES = (
    ("assumé", SITES_ASSUMES),
    ("défaut connu — rang 1, le repli ouvre une porte", DEFAUTS_RANG_1_LE_REPLI_OUVRE),
    ("défaut connu — rang 2, fait servi ou écrit", DEFAUTS_RANG_2_FAIT_SERVI_OU_ECRIT),
    ("défaut connu — rang 3, interne", DEFAUTS_RANG_3_INTERNE),
    ("défaut connu — rang 4, fail-closed", DEFAUTS_RANG_4_FAIL_CLOSED),
)
SITES_ADMIS = {}
for _libelle, _classe in CLASSES:
    for _cle, _formes in _classe.items():
        SITES_ADMIS[_cle] = tuple(sorted(SITES_ADMIS.get(_cle, ()) + tuple(_formes)))
DEFAUTS_CONNUS = {c: f for lib, cl in CLASSES if lib.startswith("défaut") for c, f in cl.items()}


# ================================================================================================
# LE LECTEUR DES LITTÉRAUX DE CHAÎNE — IMPORTÉ, PLUS RECOPIÉ (`P10.20-r`, 2026-09-16)
# ================================================================================================
# LE BESOIN EST RÉEL ET MESURÉ, ET IL N'A PAS CHANGÉ : le motif `.query_row(` est cherché dans du
# TEXTE, et un `query_row(..).ok()` cité DANS une chaîne (une phrase d'aveu, un gabarit de message, un
# extrait de doc SQL) deviendrait un site fantôme qu'aucun geste local ne referme. Ce lecteur-ci n'est
# PAS un jumeau de `positions_de_coupe` — là-bas « où sont les bornes d'instruction », ici « où sont
# les littéraux » — et les deux restent noués par une épreuve : aucune borne d'instruction ne doit
# tomber DANS un littéral.
#
# CE QUI A CHANGÉ : jusqu'au 2026-09-16 ce fichier en portait sa PROPRE copie (`spans_de_chaines`,
# `CHAINE_BRUTE`, `CARACTERE`), avec sa propre grammaire du littéral de caractère. C'était le
# cinquième exemplaire de cette grammaire sous `.github/scripts/`, et la recopie est exactement ce qui
# a fait vivre quatre grammaires divergentes (`P10.20-c` à `-e`). Le lecteur vit désormais dans
# `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py`, à côté de `_saut_de_litteral_rust`
# et de `RE_CARACTERE_RUST` dont il tient sa règle, et il est IMPORTÉ ici par la garde de famille.
# LE COMPORTEMENT EST LE MÊME (vérifié par les épreuves de ce fichier et par une re-mesure avant/après
# sur instantané : sortie identique octet pour octet).
#
# ET LA PROPRIÉTÉ QU'IL TIENT VAUT TOUJOURS LA PEINE D'ÊTRE ÉCRITE : le littéral de caractère a coûté
# une accusation fausse à ce dépôt sous `P10.20-c`, et MESURÉ le 2026-09-16, sans lui, le `'"'` de
# `actions.rs:889`, le `b'"'` de `freshness.rs:496` et le `'"'` de `panneau_avoue.rs:237` ouvraient une
# fausse chaîne qui avalait la fin du fichier — TROIS fichiers et QUATRE sites disparaissaient de la
# population (88 au lieu de 92), en silence et en VERT.


# ================================================================================================
# LE VERDICT DE CHAÎNE
# ================================================================================================
def verdict_de_la_chaine(jetons):
    """`(genre, forme)` — `genre` dans {`absorbe`, `propage`, `nu`}.

    On lit la chaîne de gauche à droite. Un TRAVERSANT laisse l'échec vivant, on continue. Un
    ABSORBANT le convertit : c'est un site. Un PROPAGATEUR le rend ou tue : ce n'en est pas un. Un
    jeton INCONNU arrête la lecture SANS accuser — ne pas conclure est la seule réponse honnête quand
    le lecteur ne sait pas ce que le jeton fait du `Result`."""
    for nom, _index, _a1, _a2 in jetons:
        if nom in ABSORBANTS:
            return "absorbe", forme_de(jetons)
        if nom in PROPAGATEURS or nom not in TRAVERSANTS:
            return "propage", forme_de(jetons)
    return ("nu", "") if not jetons else ("propage", forme_de(jetons))


def forme_de(jetons):
    """La suite chaînée, jusqu'à QUATRE jetons : `ok`, `ok.?`, `ok.flatten`, `map.unwrap_or`…

    Quatre parce que c'est ce qu'il faut pour distinguer les variantes que l'arbre porte
    (`ok.map.unwrap_or_else` en a trois) sans faire dépendre l'ensemble nommé d'une queue de chaîne
    qu'un refactoring déplace."""
    return ".".join(j[0] for j in jetons[:4])


# ================================================================================================
# LA DÉCOUVERTE — UN SITE EST UNE LECTURE, PAS UN APPELANT
# ================================================================================================
def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """[(chemin, ligne, fonction, forme, extrait)] pour UN fichier.

    `journal` recueille ce que CETTE garde avoue avoir perdu (une parenthèse non appariée) ;
    `aveux_du_lecteur` ce que le LECTEUR PARTAGÉ avoue (`P10.20-d`). Deux causes, deux remèdes, jamais
    mélangés : sans le second, une région avalée par le lecteur retirerait des sites SANS UN MOT et le
    plancher accuserait le dépôt là où la cause est l'instrument."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    fns = fonctions(code)
    coupes = positions_de_coupe(code)
    spans = spans_de_chaines_rust(code)
    sites = []
    for m in LECTURE_UNE_LIGNE.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        ouvrante = m.end() - 1
        fin = apparier(code, ouvrante)
        if fin < 0:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur la lecture "
                           "de ligne unique : le lecteur a perdu la fin de l'expression")
            continue
        jetons, apres = chaine_detaillee(code, fin)
        genre, forme = verdict_de_la_chaine(jetons)
        if genre != "absorbe":
            continue
        englobante = portee_englobante(fns, m.start())
        if not englobante:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — lecture HORS de toute fonction : la portée est "
                           "introuvable, et un site sans fonction ne peut pas entrer dans l'ensemble")
            continue
        extrait = " ".join(code[debut_instruction(coupes, m.start()):apres].split())[:150]
        sites.append((chemin_relatif, code.count("\n", 0, m.start()) + 1, englobante[0], forme, extrait))
    return sites


def fichiers_du_corpus(racine=None):
    """Tous les `.rs` de `daemon/src/handlers/`, SOUS-RÉPERTOIRES COMPRIS, artefacts ÉLAGUÉS.

    L'élagage passe par le geste PARTAGÉ (`parcours_des_sources`, `P11.8-m`) : il exclut PAR NOM DANS
    la descente, et porter une liste à la main ici serait la « copie divergente » que
    `check_no_guard_walks_the_tree_unpruned.py` juge. `racine` n'est là que pour les ÉPREUVES
    INTERNES, qui doivent soumettre un arbre FABRIQUÉ à ce lecteur-ci sans toucher au dépôt."""
    racine = HANDLERS if racine is None else racine
    if not os.path.isdir(racine):
        return []
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine):
        trouves += [os.path.join(dossier, n) for n in fichiers
                    if n.endswith(".rs") and os.path.isfile(os.path.join(dossier, n))]
    return sorted(trouves)


def decouvrir():
    sites, journal, aveux_du_lecteur = [], [], {}
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        sites += analyser(os.path.relpath(chemin, RACINE), texte, journal, aveux_du_lecteur)
    return sites, journal, aveux_du_lecteur


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS, ET SUR LES FORMES
# ================================================================================================
def juger_contre_l_ensemble(sites, admis):
    """[(genre, fichier, phrase)] — `forme neuve` quand une forme accusée dépasse ce qui est admis,
    `exemption sans objet` quand une forme admise n'est plus accusée autant qu'elle le déclare."""
    vus = {}
    for chemin, ligne, fn, forme, _extrait in sites:
        vus.setdefault((chemin, fn), []).append((forme, ligne))
    ecarts = []
    for cle in sorted(set(vus) | set(admis)):
        chemin, fn = cle
        formes_vues, formes_admises = {}, {}
        for forme, ligne in vus.get(cle, []):
            formes_vues.setdefault(forme, []).append(ligne)
        for forme in admis.get(cle, ()):
            formes_admises[forme] = formes_admises.get(forme, 0) + 1
        for forme in sorted(set(formes_vues) | set(formes_admises)):
            n_vu, n_admis = len(formes_vues.get(forme, [])), formes_admises.get(forme, 0)
            if n_vu > n_admis:
                lignes = ", ".join(str(x) for x in sorted(formes_vues[forme])[n_admis:])
                ecarts.append(("forme neuve", chemin,
                               f"FORME NEUVE — `{fn}` ({chemin}) absorbe l'échec d'un `query_row` sous "
                               f"la forme `{forme}` {n_vu} fois pour {n_admis} admise(s) ; ligne(s) en "
                               f"trop : {lignes}. Une lecture de ligne unique se propage "
                               "(`.optional()?`, ou un `Result` rendu à l'appelant) ou AVOUE dans le "
                               "corps qu'elle n'a pas eu lieu — sinon elle entre dans SITES_ADMIS AVEC "
                               "son rang et sa raison, jamais en silence."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est admis {n_admis} fois sous "
                               f"la forme `{forme}` et n'est accusé que {n_vu} fois : le site propage "
                               "désormais, ou il a CHANGÉ DE FORME (regardez la « forme neuve » qui "
                               "l'accompagne : ce n'est pas le même site), ou il n'existe plus, ou "
                               "cette garde a cessé de le voir. Dans les quatre cas l'entrée se retire "
                               "à la main EN DISANT LEQUEL — un canal qui rétrécit ne doit pas passer "
                               "pour un défaut fermé."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES INTERNES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Les extraits sont FABRIQUÉS, jamais pris sur l'arbre : adosser un témoin à `mfa_verify` ou à
# `dash_update` en ferait une RANÇON — il rougirait le jour où le site est réparé, et aucun geste ne
# pourrait le refermer.
EPREUVES = [
    # --- LES QUATRE VARIANTES QUE `P10.20-b` NOMME, PLUS CELLES QUE LA MESURE A AJOUTÉES.
    ("(1) `.ok()` — la famille que la clé nomme",
     'fn e1(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT a FROM t WHERE id=?1", params![id], |r| r.get(0)).ok()\n}\n',
     {"ok"}),
    ("(2) `.ok()?` — l'absence propagée, la cause perdue",
     'fn e2(conn: &Connection) -> Option<i64> {\n'
     '    let a: i64 = conn.query_row("SELECT a FROM t", [], |r| r.get(0)).ok()?;\n'
     '    Some(a + 1)\n}\n', {"ok.?"}),
    ("(3) `.ok().flatten()` — deux absences écrasées en une",
     'fn e3(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()\n}\n',
     {"ok.flatten"}),
    ("(4) `.ok().and_then(..)`",
     'fn e4(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get::<_, String>(0)).ok().and_then(|s| s.parse().ok())\n}\n',
     {"ok.and_then"}),
    ("(5) `.unwrap_or(<valeur>)` chaîné DIRECTEMENT — une valeur fabriquée, pas même une absence",
     'fn e5(conn: &Connection) -> i64 {\n'
     '    conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0)\n}\n',
     {"unwrap_or"}),
    # C'EST L'ÉPREUVE QUI JUSTIFIE TOUT LE PÉRIMÈTRE DE CETTE GARDE. La forme de `mfa_enabled_for` —
    # le pire défaut de `P10.20-b`, invisible au geste « premier jeton `ok` » que la QUESTION propose.
    ("(6) `.map(..).unwrap_or(false)` — la forme du site qui DÉSARMAIT le second facteur",
     'fn e6(conn: &Connection, user: &str) -> bool {\n'
     '    conn.query_row("SELECT enabled FROM user_mfa WHERE user=?1", params![user], |r| r.get::<_, i64>(0))\n'
     '        .map(|n| n != 0)\n'
     '        .unwrap_or(false)\n}\n', {"map.unwrap_or"}),
    ("(7) `.unwrap_or_else(|_| ..)` — le repli qui se lit comme un défaut de produit",
     'fn e7(conn: &Connection, id: i64) -> String {\n'
     '    conn.query_row("SELECT COALESCE(visibility,\'shared\') FROM dashboard WHERE id=?1", params![id], |r| r.get(0))\n'
     '        .unwrap_or_else(|_| "shared".into())\n}\n', {"unwrap_or_else"}),
    ("(8) `.is_err()` — la lecture ratée se lit « la ligne n'existe pas »",
     'fn e8(conn: &Connection, id: i64) -> bool {\n'
     '    conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).is_err()\n}\n',
     {"is_err"}),
    ("(9) `.is_ok()` — la lecture ratée se lit « le nom est libre », et l'écriture suit",
     'fn e9(conn: &Connection, name: &str) -> bool {\n'
     '    conn.query_row("SELECT 1 FROM legal_hold WHERE name=?1", params![name], |r| r.get::<_, i64>(0)).is_ok()\n}\n',
     {"is_ok"}),
    ("(10) `.optional().ok()` — le geste honnête RÉ-ABSORBÉ un cran plus loin",
     'fn e10(conn: &Connection) -> Option<Option<i64>> {\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get(0)).optional().ok()\n}\n',
     {"optional.ok"}),
    # LE TROU DE `P10.20-c`, REJOUÉ SUR CE SCANNER-CI. Sans le littéral de caractère dans
    # `spans_de_chaines_rust`, ces deux témoins deviennent VERTS — c'est-à-dire que la garde cesse de voir
    # une lecture parfaitement visible, parce qu'un guillemet d'un tout autre littéral a ouvert une
    # fausse chaîne. Mesuré : trois fichiers de `handlers/` portent ce cas aujourd'hui.
    ("(11) la lecture suit un littéral de CARACTÈRE `'\"'` (le cas d'`actions.rs`)",
     "const META: [char; 3] = [';', '\"', '\\\\'];\n"
     'fn e11(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get(0)).ok()\n}\n', {"ok"}),
    # --- LES TÉMOINS NÉGATIFS : chacun est une forme que la garde DOIT laisser passer.
    ("témoin négatif : `.optional()?` — LE geste que cette garde réclame",
     'fn n1(conn: &Connection) -> rusqlite::Result<Option<i64>> {\n'
     '    conn.query_row("SELECT a FROM t WHERE id=?1", params![id], |r| r.get(0)).optional()\n}\n',
     set()),
    ("témoin négatif : `.optional()?` consommé puis re-rendu",
     'fn n1b(conn: &Connection) -> rusqlite::Result<Value> {\n'
     '    let a: Option<i64> = conn.query_row("SELECT a FROM t", [], |r| r.get(0)).optional()?;\n'
     '    Ok(json!({ "a": a }))\n}\n', set()),
    ("témoin négatif : `?` nu — l'échec sort de la fonction",
     'fn n2(conn: &Connection) -> rusqlite::Result<i64> {\n'
     '    let a: i64 = conn.query_row("SELECT a FROM t", [], |r| r.get(0))?;\n'
     '    Ok(a)\n}\n', set()),
    # `unwrap`/`expect` TUENT : c'est un autre défaut, et l'accuser ici poserait un rouge qu'aucun
    # geste de CETTE famille ne referme. Le verdict le dit plutôt que de le taire.
    ("témoin négatif : `.unwrap()` — une panique, jamais un fait inventé",
     'fn n3(conn: &Connection) -> i64 {\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get(0)).unwrap()\n}\n', set()),
    ("témoin négatif : la forme est dans un commentaire `//`",
     'fn n4(conn: &Connection) -> rusqlite::Result<i64> {\n'
     '    // AVANT : conn.query_row("SELECT a FROM t", [], |r| r.get(0)).ok() — remplacé par .optional()?\n'
     '    conn.query_row("SELECT a FROM t", [], |r| r.get(0))\n}\n', set()),
    ("témoin négatif : la forme est DANS UNE CHAÎNE (phrase d'aveu, gabarit de message)",
     'fn n5() -> &\'static str {\n'
     '    "le site d\'avant s\'écrivait conn.query_row(sql, [], f).ok() et se lisait comme un fait"\n}\n',
     set()),
    ("témoin négatif : la forme est dans une CHAÎNE BRUTE `r#\"…\"#`",
     'fn n5b() -> &\'static str {\n'
     '    r#"motif interdit : .query_row(..).unwrap_or(0) — voir P10.20-b"#\n}\n', set()),
    ("témoin négatif : la forme est dans un `#[cfg(test)] mod`",
     'fn n6() -> i64 { 0 }\n'
     '#[cfg(test)]\nmod tests {\n    use super::*;\n'
     '    #[test]\n    fn t(conn: &Connection) {\n'
     '        let a: i64 = conn.query_row("SELECT a FROM t", [], |r| r.get(0)).unwrap_or(-1);\n'
     '        assert_eq!(a, -1);\n    }\n}\n', set()),
    ("témoin négatif : `query_map(..).flatten()` — l'AUTRE famille, celle de la garde de famille",
     'fn n7(conn: &Connection) -> Vec<i64> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '    s.query_map([], |r| r.get(0)).unwrap().flatten().collect()\n}\n', set()),
    ("témoin négatif : `.ok()` sur autre chose qu'une lecture de ligne",
     'async fn n8(h: JoinHandle<i64>) -> Option<i64> { h.await.ok() }\n', set()),
    # L'ANGLE MORT EST PROUVÉ, PAS ALLÉGUÉ — comme la garde de famille prouve ceux de sa sœur. Ce
    # témoin est DÉFENSIF dans un seul sens : il rougit si la garde se met à voir le `match`, ce qui
    # veut dire que le paragraphe « ce que ce vert ne dit pas » doit être réécrit AVANT que le verdict
    # reprenne. Il n'exige jamais qu'un défaut survive.
    ("angle mort MESURÉ : le `match` dont la lecture est le scrutateur (105 sites sur l'arbre)",
     'fn a1(conn: &Connection, id: i64) -> String {\n'
     '    match conn.query_row("SELECT name FROM t WHERE id=?1", params![id], |r| r.get(0)) {\n'
     '        Ok(v) => v,\n'
     '        Err(_) => "inconnu".into(),\n'
     '    }\n}\n', set()),
    ("angle mort MESURÉ : le `Result` LIÉ à un nom, absorbé plus bas",
     'fn a2(conn: &Connection) -> i64 {\n'
     '    let lu = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0));\n'
     '    lu.unwrap_or(0)\n}\n', set()),
]

# LA DESCENTE S'ÉPROUVE SUR UN ARBRE FABRIQUÉ, JAMAIS SUR `handlers/connectors/` : l'adosser au
# sous-répertoire réel en ferait une rançon, qui rougirait le jour où ce répertoire est renommé. Les
# CHEMINS du faux arbre sont ceux de la garde de famille (`ARBRE_FABRIQUE`, `SOURCES_ATTENDUES`),
# IMPORTÉS et non recopiés — c'est le même élagage qui est jugé, et deux listes jumelles finiraient
# par diverger. Seule la SOURCE change, parce que ce sont deux gestes différents qu'on éprouve.
SOURCE_FABRIQUEE = ('fn lire(conn: &Connection, id: i64) -> Option<i64> {\n'
                    '    conn.query_row("SELECT a FROM t WHERE id=?1", params![id], |r| r.get(0)).ok()\n}\n')


SOURCE_LITTERAL_D_OCTET = ('fn a3(conn: &Connection, bytes: &[u8], j: usize) -> Option<i64> {\n'
                           '    let _q = bytes[j] == b\'"\';\n'
                           '    conn.query_row("SELECT a FROM t", [], |r| r.get(0)).ok()\n}\n')


def epreuve_du_litteral_d_octet():
    """UN ANCIEN ANGLE MORT DES LECTEURS PARTAGÉS, DEVENU UNE PROPRIÉTÉ TENUE — mesuré le 2026-09-16.

    `apparier` et `fonctions` sont les lecteurs PARTAGÉS de
    `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py`. Jusqu'à `P10.20-m` (le même jour),
    `apparier` sautait les chaînes mais PAS les littéraux de caractère : sur `b'"'` il ouvrait une fausse
    chaîne, perdait des accolades, et `fonctions` laissait tomber la portée — la lecture tombait HORS de
    toute fonction, `analyser` l'écrivait dans son JOURNAL et `main` REFUSAIT DE CONCLURE. Cette épreuve
    tenait alors les deux moitiés de ce comportement fail-safe : aucun site, ET un aveu.

    DEPUIS `P10.20-m`, `apparier` saute les littéraux de caractère et d'octet (règle importée du module
    partagé, `RE_CARACTERE_RUST`) et `fonctions` ne prend plus une déclaration pour un corps : la portée
    est trouvée, le site est ACCUSÉ, et le journal est vide. L'épreuve tient donc désormais l'INVERSE :
    le site DOIT être trouvé, et il ne DOIT y avoir aucun aveu. Si elle retombe (site perdu, ou aveu),
    c'est que le lecteur partagé a régressé — la garde le DIT au lieu de rendre un compte amputé. La
    propriété elle-même (littéral reconnu) est tenue par témoin et par mutation dans le fichier qui
    possède ces lecteurs ; ici on tient seulement qu'elle est CONSOMMÉE."""
    errs = []
    journal = []
    sites = analyser("/angle_mort_octet.rs", SOURCE_LITTERAL_D_OCTET, journal)
    if not sites:
        errs.append("épreuve du LITTÉRAL D'OCTET : la garde ne TROUVE plus le site qui suit un littéral "
                    "d'octet — `apparier` ou `fonctions` a régressé sur les littéraux de caractère "
                    "(`P10.20-m`). Un compte amputé serait rendu vert : la garde refuse de conclure.")
    if journal:
        errs.append(f"épreuve du LITTÉRAL D'OCTET : le lecteur partagé AVOUE une portée introuvable "
                    f"({journal}) là où il doit la situer depuis `P10.20-m` — la propriété n'est plus "
                    "consommée, la garde refuse de conclure.")
    return errs


def epreuve_de_la_descente():
    """Le CORPUS descend dans les sous-répertoires, et il élague — jugé DANS LES DEUX SENS.

    Sans le sens POSITIF, la descente pourrait être débranchée sans qu'aucun témoin ne tombe, et la
    garde redeviendrait plate en silence — l'état où un site de `handlers/connectors/` a vécu un an
    sous la garde de famille. Sans le sens NÉGATIF, un `target/` posé sous l'arbre entrerait dans le
    corpus et la garde accuserait du code dérivé qu'aucun geste local ne referme. Le troisième volet
    est le plus important : un fichier LISTÉ mais non ANALYSÉ ne prouve rien."""
    errs = []
    with tempfile.TemporaryDirectory(prefix="plume-lecture-unique-") as racine:
        for rel in ARBRE_FABRIQUE:
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(SOURCE_FABRIQUEE)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        manquants = sorted(SOURCES_ATTENDUES - vus)
        if manquants:
            errs.append(f"épreuve de la DESCENTE (positif) : {manquants} n'est pas dans le corpus — la "
                        "découverte est redevenue PLATE, et un site écrit sous `handlers/connectors/` "
                        "ne serait plus jamais vu")
        artefacts = sorted(v for v in vus - SOURCES_ATTENDUES)
        if artefacts:
            errs.append(f"épreuve de la DESCENTE (élagage) : {artefacts} est entré dans le corpus — le "
                        "parcours n'élague plus les artefacts d'outil par le geste partagé "
                        "(`parcours_des_sources`), et la garde accuserait du code dérivé")
        sites = analyser("sous_repertoire_fabrique/mod.rs", SOURCE_FABRIQUEE, [])
        if {f for _c, _l, _fn, f, _x in sites} != {"ok"}:
            errs.append("épreuve de la DESCENTE (analyse) : le fichier d'un sous-répertoire est LISTÉ "
                        "mais son site n'est pas ACCUSÉ — un corpus qui s'élargit sans que le lecteur "
                        "suive ne vaut rien")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict, et dans les deux sens.

    CHAQUE ÉPREUVE A ÉTÉ ÉPROUVÉE PAR MUTATION le 2026-09-16, et la phrase dit ce qui a été MESURÉ :
    vider `ABSORBANTS`, retirer `unwrap_or` d'`ABSORBANTS`, faire de `optional` un propagateur
    terminal, débrancher l'exclusion des littéraux de chaîne, débrancher `coupe_tests`, débrancher le
    dépouillement des commentaires, élargir la lecture à `query_map`, vider l'ensemble nommé, y
    ajouter une entrée bidon, débrancher le jugement de l'ensemble, et rendre `apparier` aveugle."""
    errs = []
    # LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR (`P10.20-d`). Il est IMPORTÉ, donc ses témoins ne
    # tournent pas à l'import : sans cet appel, un lecteur amputé de sa reconnaissance des chaînes
    # brutes ou des littéraux de caractère ne serait épinglé que par la garde qui le PORTE.
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    # LES LECTEURS DE FORME RUST AUSSI (`P10.20-r`, 2026-09-16), ET POUR LA MÊME RAISON MESURÉE :
    # `apparier`, `fonctions`, `arguments`, `bras_du_match` et `spans_de_chaines_rust` sont IMPORTÉS
    # (par ré-import à travers la garde de famille), donc leurs témoins ne tournent pas à l'import.
    # Tant qu'ils vivaient dans le `valider_instrument` de la garde qui les PORTE, un `apparier`
    # amputé de sa règle du littéral laissait CETTE garde-ci verte à sortie identique — mesuré. Le
    # coût est de 0,23 ms, contre 1,3 s pour cette garde entière (0,02 %).
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `arguments`, "
                    f"`bras_du_match`, `spans_de_chaines_rust`) : {e}")

    for nom, src, attendues in EPREUVES:
        journal = []
        sites = analyser("/epreuve.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if attendues and vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu "
                        f"{sorted(attendues)} — la garde ne voit plus la forme qu'elle nomme, ou elle "
                        "l'étiquette autrement et l'ensemble nommé ne peut plus la reconnaître")
        if not attendues and vues:
            errs.append(f"épreuve « {nom} » : accusée sous {sorted(vues)} alors qu'elle PROPAGE, qu'elle "
                        "est hors famille, ou qu'elle est un angle mort ÉCRIT — la garde accuse une "
                        "forme qu'aucun geste local ne referme, ou elle a cessé d'être aveugle là où "
                        "son verdict déclare l'être (auquel cas c'est le verdict qu'il faut réécrire)")

    # --- LA LECTURE, ÉPROUVÉE À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    if not LECTURE_UNE_LIGNE.search("conn.query_row(sql, [], f)") \
            or not LECTURE_UNE_LIGNE.search("conn\n        .query_row(sql, [], f)"):
        errs.append("épreuve de la LECTURE (positif) : `query_row` n'est plus reconnu — la population "
                    "de cette garde est vide, et son vert ne dit plus rien")
    if LECTURE_UNE_LIGNE.search("stmt.query_map([], f)") or LECTURE_UNE_LIGNE.search("s.query_and_then([], f)"):
        errs.append("épreuve de la LECTURE (négatif) : `query_map`/`query_and_then` est entré dans la "
                    "population. C'est la famille de `check_a_truncated_list_is_never_served_as_a_"
                    "complete_one.py` — un ITÉRATEUR de lignes, pas une ligne unique — et les deux "
                    "ensembles nommés compteraient alors les mêmes sites deux fois")

    # --- LES DEUX LECTEURS DE TEXTE SONT NOUÉS : aucune borne d'instruction ne tombe DANS un littéral.
    # Sans cette épreuve, `spans_de_chaines_rust` pourrait diverger de `positions_de_coupe` sans qu'aucun
    # témoin ne tombe, et c'est exactement la dérive que les lecteurs jumeaux produisent.
    fabrique = 'fn f() { let c = \'"\'; let s = "a;b{c}"; let t = r#"d;e{f}"#; }'
    spans = spans_de_chaines_rust(fabrique)
    if len(spans) != 2 or fabrique[spans[0][0]:spans[0][1]] != '"a;b{c}"':
        errs.append(f"épreuve des LITTÉRAUX : {len(spans)} littéral(aux) vu(s) sur une source qui en "
                    "porte DEUX (une chaîne simple, une chaîne brute) précédés d'un littéral de "
                    "CARACTÈRE — l'exclusion des chaînes ne tient plus. Dans un sens une forme CITÉE "
                    "dans une phrase deviendrait un site fantôme ; dans l'autre (le cas mesuré) un "
                    "`'\"'` ouvrirait une fausse chaîne qui avale la fin du fichier et fait "
                    "DISPARAÎTRE des sites réels, en vert")
    dedans = [c for c in positions_de_coupe(fabrique) if dans_une_chaine_rust(spans, c)]
    if dedans:
        errs.append(f"épreuve des LITTÉRAUX (accord des deux lecteurs) : {len(dedans)} borne(s) "
                    "d'instruction tombe(nt) DANS un littéral — `spans_de_chaines_rust` et "
                    "`positions_de_coupe` ne lisent plus le même texte, et l'un des deux ment")

    # --- L'ANGLE MORT DES LECTEURS PARTAGÉS SE SOLDE PAR UN AVEU, jamais par un site retiré.
    errs += epreuve_du_litteral_d_octet()

    # --- LE CORPUS DESCEND, ET IL ÉLAGUE — sur un arbre FABRIQUÉ, dans les deux sens.
    errs += epreuve_de_la_descente()

    # --- L'ENSEMBLE NOMMÉ EST JUGÉ DANS LES DEUX SENS ET SUR LES FORMES, À SON PROPRE NIVEAU. Sans
    # ces épreuves, un `juger_contre_l_ensemble` débranché rendrait la garde verte quoi que l'arbre
    # porte — et un ensemble qui ne regarderait que les COMPTES laisserait une réécriture de forme
    # passer en silence.
    faux_site = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "ok", ".ok()")]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(faux_site, {})}
    if genres != {"forme neuve"}:
        errs.append(f"épreuve de l'ENSEMBLE (forme neuve) : genres {sorted(genres) or 'aucun'} au lieu "
                    "de ['forme neuve'] — une accusation hors ensemble ne rougit plus, et l'ensemble ne "
                    "peut plus que grandir en silence")
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        [], {("daemon/src/handlers/fabrique.rs", "fn_fantome"): ("ok",)})}
    if genres != {"exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (exemption sans objet) : genres {sorted(genres) or 'aucun'} "
                    "au lieu de ['exemption sans objet'] — une entrée sans objet ne rougit plus, et la "
                    "liste cesse de descendre quand le dépôt guérit")
    if juger_contre_l_ensemble(faux_site, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): ("ok",)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site EXACTEMENT admis produit un écart — la "
                    "garde serait rouge sur l'arbre qu'elle déclare elle-même admis")
    mute = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "unwrap_or", ".unwrap_or(0)")]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        mute, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): ("ok",)})}
    if genres != {"forme neuve", "exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (changement de FORME) : genres {sorted(genres) or 'aucun'} "
                    "au lieu des DEUX — un site admis en `.ok()` réécrit en `.unwrap_or(0)` passerait "
                    "sans un mot, alors qu'il est passé d'une absence à une valeur FABRIQUÉE. C'est "
                    "précisément pour ce cas que l'ensemble porte des formes et non des comptes")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * LE PLUS LOURD, ET IL EST MESURÉ : elle ne lit que la CHAÎNE posée sur le `query_row`. "
          "Au 2026-09-16, `daemon/src/handlers/` porte 209 appels, dont 90 absorbent par une chaîne "
          "(jugés ici) et CENT SEPT laissent la chaîne NUE — le `Result` est lié à un nom, rendu à "
          "l'appelant, ou SCRUTÉ par un `match … { Ok(v) => …, Err(_) => <valeur> }`. Ce dernier est "
          "la MÊME faute écrite autrement, et deux témoins de ce fichier la reproduisent pour que "
          "l'angle mort soit prouvé et non allégué. La fermer demanderait de lire le BRAS `Err`, "
          "c'est-à-dire de décider si son corps propage ou fabrique — ce n'est pas fait, et tant que "
          "ce n'est pas fait, un site neuf peut s'écrire en `match` sans rougir.\n"
          "  * elle ne juge PAS `unwrap()` ni `expect(..)` sur un `query_row`. Ils TUENT le "
          "processus : c'est un défaut, ce n'est pas CELUI-CI (aucun fait n'est servi), et l'accuser "
          "ici poserait un rouge qu'aucun geste de cette famille ne referme.\n"
          "  * elle ne lit QUE `daemon/src/handlers/` et ses sous-répertoires. Le même geste, mesuré "
          "sur `daemon/src` entier au 2026-09-16, donne 249 chaînes absorbantes : CENT CINQUANTE-NEUF "
          "vivent HORS `handlers/` et ne sont ni jugées ni classées. Parmi elles, `state.rs` porte à "
          "lui seul onze résolutions de jeton et `scim.rs` trois — de l'authentification. HORS "
          "PÉRIMÈTRE, ET DIT. (Le chiffre « cent vingt et une » qu'écrivait `docs/ROADMAP.md` était "
          "le TOTAL de `daemon/src` pour le geste `ok`, pas son hors-`handlers/` : l'en-tête de ce "
          "fichier refait le calcul.)\n"
          "  * elle ne dit RIEN du rang. Les cinq classes de `SITES_ADMIS` portent un rang et une "
          "raison LUS À LA MAIN le 2026-09-16 ; la garde, elle, ne sait pas les recalculer. Un site "
          "neuf est accusé sans rang, et c'est à la lecture de le lui donner en entrant dans "
          "l'ensemble.\n"
          "  * elle ne dit pas si un aveu de région couvre la lecture accusée. Une fonction qui pose "
          "déjà `error` pour une AUTRE de ses lectures reste accusée pour celle-ci — voulu (un aveu "
          "qui couvre tout ne couvre rien), mais le rouge ne mesure pas la distance restante.\n"
          "  * elle ne tient pas ce que la CONSOLE affiche. Le démon peut avouer ; qu'un module de "
          "`web/` lise l'aveu se juge ailleurs "
          "(`check_a_refusal_is_not_rendered_as_an_absence.py`).\n"
          "  * elle ne juge pas ce que le MAPPEUR fait. Un mappeur infaillible rend l'absorption "
          "inoffensive ; la garde accuse quand même, parce qu'elle lit du texte et qu'un mappeur "
          "infaillible aujourd'hui gagne un `r.get()` demain.\n"
          "  * elle ne prouve RIEN à l'exécution. Elle constate qu'une forme est absente du dépôt, "
          "jamais qu'une réponse réelle avoue que la lecture n'a pas eu lieu.")


def main():
    # --- LES ÉPREUVES D'ABORD : aucune lecture du dépôt tant que l'instrument n'a pas été éprouvé.
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    # --- L'ANCRAGE : `query_row` doit être la méthode rusqlite que cette garde croit lire. Sans lui,
    # un dépôt qui aurait changé de bibliothèque rendrait zéro site et la garde serait verte pour la
    # pire des raisons.
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
                hors_handlers += fh.read().count(".query_row(")
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M) and hors_handlers == 0:
        print("::error::ni `rusqlite` dans daemon/Cargo.toml ni un seul `.query_row(` dans daemon/src "
              "hors handlers : `query_row` n'est plus la méthode que cette garde croit lire, et sa "
              "population n'a plus d'ancrage. Elle REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, journal, aveux_du_lecteur = decouvrir()
    # L'AVEU DU LECTEUR PASSE AVANT CELUI DE LA GARDE (`P10.20-d`) : une région avalée par le lecteur
    # est la cause AMONT, et la nommer évite d'accuser une parenthèse qu'il a lui-même déplacée.
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression ; il ne "
              "rend pas un compte amputé en vert.")
        ce_qui_n_est_pas_tenu()
        return 2

    fichiers = {c for c, _l, _f, _fo, _x in sites}
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} (dérivés le 2026-09-16 du relevé de ce jour-là : "
              "90 sites sur 28 fichiers, règle des deux tiers). La DÉCOUVERTE est cassée, ou un lot a "
              "fermé assez de sites pour que les planchers doivent être RE-DÉRIVÉS du relevé du jour "
              "— dans le second cas, ils descendent, avec leur date écrite dans le fichier. La garde "
              "REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::error file={chemin},line={ligne}::`{fn}` absorbe l'échec d'une lecture de LIGNE "
              f"UNIQUE (forme `{forme}`) : « aucune ligne » et « pas lu » deviennent indiscernables, "
              f"et ce qui suit est servi, décidé ou écrit comme un fait — `{extrait}`")

    par_forme = {}
    for _c, _l, _f, forme, _x in sites:
        par_forme[forme] = par_forme.get(forme, 0) + 1
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} site(s) sur "
          f"{len(fichiers)} fichier(s) de daemon/src/handlers (sous-répertoires compris) — "
          + " · ".join(f"{f} {n}" for f, n in sorted(par_forme.items(), key=lambda p: (-p[1], p[0])))
          + ". Commentaires DÉPOUILLÉS, modules `#[cfg(test)]` COUPÉS, littéraux de chaîne EXCLUS : "
            "une forme citée dans une note ou dans une phrase n'est jamais un site.")

    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    if ecarts:
        for _genre, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre les accusations du jour et l'ensemble nommé. "
              "L'ensemble se corrige à la main, AVEC le rang et la raison ; zéro reste atteignable.")
        ce_qui_n_est_pas_tenu()
        return 1

    print(f"[{ETIQUETTE}] ADMIS, par classe : "
          + " · ".join(f"{lib} {sum(len(f) for f in cl.values())} site(s)/{len(cl)} fonction(s)"
                       for lib, cl in CLASSES) + ".")
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte ({len(sites)} site(s)) — "
          "ni forme neuve, ni exemption sans objet, ni forme CHANGÉE.")
    restants = sum(len(f) for f in DEFAUTS_CONNUS.values())
    print(f"[{ETIQUETTE}] CE QUE CE VERT NE DIT PAS : les {restants} accusations des rangs un à quatre "
          "sont des DÉFAUTS CONNUS ET NON CORRIGÉS, admis pour que cette garde puisse être câblée "
          "VERTE le jour où elle est écrite plutôt que d'attendre une campagne — une garde qui naît "
          "rouge sur quatre-vingt-neuf sites ne se branche pas, et une garde qui ne se branche pas ne "
          "tient rien. Le vert dit UNE chose et une seule : AUCUNE FORME NEUVE n'est entrée depuis le "
          "2026-09-16. Il ne dit pas que l'arbre est sain — trois de ces sites ouvrent une porte, "
          "dix-huit servent ou écrivent un fait fabriqué. CHAQUE correction doit RETIRER son entrée de "
          "SITES_ADMIS, sous peine d'« exemption sans objet » : c'est ce qui fait descendre la liste "
          "au lieu de la laisser devenir un décor.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
