#!/usr/bin/env python3
"""Un REFUS ne se rend jamais comme une ABSENCE — garde de CI (`P11.14-c`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Le panneau d'accès données (DLP) décidait de son affichage sur UNE condition :

    if (!j || j.error || !Array.isArray(j.rows) || !j.rows.length) { … muted(emptyTxt) … }

Quatre situations y entraient — un REFUS du démon, une réponse ILLISIBLE, une PANNE réseau, et un
VRAI vide — et une seule phrase en sortait : « Aucun changement récent (<fenêtre>) — ou capteur
inactif ». Cette phrase AFFIRME une absence de données, et suggère une panne de collecte, dans les
trois cas où rien n'a été établi.

CE QUE CE DÉFAUT PRODUIT, ET QUI A ÉTÉ RELEVÉ EN USAGE RÉEL le 2026-08-25 : une CONTRADICTION.
Demander TOUTE la rétention rendait « aucun changement récent » ; demander SEPT JOURS rendait des
lignes — un sur-ensemble affichant moins que son sous-ensemble. Mesuré le même jour, aucun chemin de
REQUÊTE ne rend moins quand la fenêtre s'élargit : pour les cinq requêtes de ce panneau, le SQL émis
avec `from=0` est EXACTEMENT celui émis avec `from=maintenant-7j` MOINS son seul conjoint
`ts >= <borne>`, et joué sur une base de 6 000 lignes réparties sur 30 jours il rend toujours au moins
autant de lignes (60 contre 15 sur le panneau agrégé). Ce que la fenêtre large rend de DIFFÉRENT,
c'est un REFUS — le 422 que forme `TruncatedAggregate::message`
(`daemon/src/cold_store/exactness.rs`) quand la valeur porterait sur un historique froid tronqué, ou le
400 que forme `run_query_ex` (`daemon/src/query_exec.rs`) quand le budget est dépassé. LES DEUX SONT
NOMMÉS PAR LEUR SITE, JAMAIS CITÉS : la citation qui vivait ici a dérivé sans que rien ne le voie — le
démon dit « résultat », ce commentaire disait un autre substantif, dont `daemon/src` ne porte aucune
occurrence au 2026-08-29. C'est le défaut de `P11.21-a`, et il n'est pas qu'une citation soit fausse : c'est
qu'elle soit écrite. Le démon disait la vérité dans les deux fenêtres ; la contradiction
était FABRIQUÉE à l'affichage, par cette condition.

LA RÈGLE, ÉCRITE COMME UNE PROPRIÉTÉ DE FORME
---------------------------------------------
    Aucune expression conditionnelle de `web/` ne doit décider, DANS LE MÊME TEST, qu'une lecture a
    ÉCHOUÉ et qu'elle est VIDE.

Ce sont deux faits de nature différente : l'un dit « je ne sais pas », l'autre dit « je sais, et il
n'y a rien ». Les fondre dans une condition, c'est s'interdire de les rendre différemment — quelle
que soit la phrase choisie ensuite. La garde ne juge donc PAS le texte affiché (une phrase se
reformule, et une garde de phrase se contourne d'un synonyme) : elle juge la CONDITION, c'est-à-dire
l'endroit où l'information se perd. Après elle, la distinction n'existe plus dans le programme.

POURQUOI LA FORME PLUTÔT QUE LA LISTE DES PANNEAUX. La population est DÉCOUVERTE (tous les modules de
`web/`, par parcours du dossier — le même que celui du harnais ESM), jamais énumérée : un panneau
écrit demain est couvert sans être nommé ici. Relevé le 2026-08-25 : sur 49 modules, UN SEUL portait
cette forme (`web/dataaccess.js`) ; les autres consommateurs de `/api/query` (`web/viz.js`,
`web/dashboards.js`, `web/multitenant.js`) rendaient déjà l'erreur à part.

LA SECONDE JAMBE : UNE CONDITION ABSENTE N'EST PAS UNE CONDITION FAUTIVE (`P10.7-d`)
------------------------------------------------------------------------------------
La règle ci-dessus a un ANGLE MORT, et il a été MESURÉ le 2026-08-29, en fermant `P10.7-d`. Elle juge
les conditions qui TESTENT un échec. Un module qui ne teste l'échec NULLE PART n'en offre aucune —
elle rendait donc vert sur `alerts.js`, `fleet.js`, `datamodels.js` et `attack.js`, dont aucun ne lisait
`error`. Et c'est précisément la famille qu'a ouverte `P10.7-c` en fermant le démon : depuis elle, le
portillon de concurrence CLOS rend un corps **200** qui garde la forme attendue et y AJOUTE sa cause
sous `error`. `api()`/`apiSend()` ne jettent que sur `!r.ok` : la cause arrive donc dans un corps que le
consommateur lit comme un succès, et un `j.alerts || []` en refait une absence.
La JAMBE B ferme cet angle. Sa population est DÉRIVÉE du démon — les routes qui servent un corps 200
portant `error`, l'indirection comprise — et jamais énumérée ; elle exige que le corps rendu par un tel
appel atteigne une lecture de `error`, DANS LA PORTÉE de l'appel. Voir son en-tête, plus bas, pour ce
qu'elle ne tient pas et pour les fautes d'instrument mesurées en l'écrivant.

CE QUI A CHANGÉ LE 2026-09-16 (`P10.20-a`), ET CE QUE ÇA A COÛTÉ
----------------------------------------------------------------
La jambe B ancrait sa population sur UN NOM — `portillon::corps_de_refus` — soit quatorze chemins. Un nom
posé n'est pas une propriété : le démon avoue par bien d'autres endroits, et la garde ne les voyait pas.
La population est désormais dérivée de TROIS ÉCRITURES (la cause AJOUTÉE à un corps déjà formé, INSÉRÉE
dans sa carte, ou NÉE avec un corps qui garde au moins une autre clé) : 84 sites d'aveu, 77 chemins, 69
sites de la console — et TREIZE sites SOURDS révélés d'un coup, tous corrigés AVANT l'extension parce
qu'un cliquet ne s'élargit pas. La couverture des écritures est elle-même jugée : toute occurrence du
littéral `"error"` dans `daemon/src/handlers/` est classée, et une QUATRIÈME écriture fait rougir au lieu
de rétrécir la population en silence. Le seul reste admis — les corps servis en 200 qui ne portent QUE la
cause, sans forme de succès à imiter — est un ENSEMBLE NOMMÉ, jugé dans les deux sens.

CE QUE CETTE GARDE NE PROUVE PAS
--------------------------------
Qu'un module qui SÉPARE les deux tests rende ensuite une phrase honnête : séparer la condition rend la
distinction POSSIBLE, il ne la rend pas VRAIE. Cette part-là est tenue par le harnais ESM
(`web_esm_harnais.mjs`, témoin 16), qui exerce la fonction de rendu du panneau sur des réponses
fabriquées et exige trois issues DISTINCTES — un refus qui nomme sa cause sans accuser la collecte,
un vrai vide qui reste une absence, des lignes qui rendent une table — dans les deux sens. La jambe B
a la MÊME limite : lire `error` et le taire y resterait vert.
Elle ne voit pas non plus un `.catch()` qui rendrait une absence : un gestionnaire de rejet n'est pas
une condition. C'est écrit ici plutôt que sous-entendu.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Un corpus de contrôle exerce les deux sens : des formes que la lecture DOIT épingler (la condition
historique, ses variantes `&&`, le ternaire), et des formes qu'elle NE DOIT PAS compter (une
condition qui ne teste QUE l'échec, une qui ne teste QUE le vide, les deux SÉPARÉES en branches
successives, la forme écrite dans un commentaire, la forme écrite dans une chaîne). Puis un PLANCHER
sur l'arbre réel : sous un nombre minimal de conditions d'échec réellement vues, c'est la lecture qui
est cassée, et la garde REFUSE DE CONCLURE au lieu de rendre vert en étant aveugle.
La DÉRIVATION de la jambe B se valide de même, sur un démon FABRIQUÉ : chaque écriture rend la fonction
qu'elle doit et aucune autre, le dépouilleur Rust mange les commentaires sans manger le code, une
écriture inconnue est vue comme telle, et un tableau d'attentes déconstruit lie bien chacun de ses corps.
Six mutations d'instrument le prouvent — retirer une écriture, neutraliser le dépouilleur, vider le reste
nommé ou aveugler le lecteur de la console rend la garde ROUGE par un témoin NOMMÉ, jamais par un silence.

CE QUE CETTE GARDE NE TIENT PAS, RÉCAPITULÉ
--------------------------------------------
La phrase RENDUE ensuite (harnais ESM, témoins 16 et 92 à 98) ; un `.catch()` qui rendrait une absence ;
les appels `fetch` NUS, qui rendent une RÉPONSE et non un corps ; les corps servis en 200 qui ne portent
QUE la cause ; et les échecs qui rendent encore des corps vides NUS côté démon (`P10.7-e`).
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    aveugler_litteraux_js, refuser_sur_aveu, sans_commentaires_js, temoins_du_lecteur)

RACINE = (sys.argv[1] if len(sys.argv) > 1
          else subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip())
WEB = os.path.join(RACINE, "web")

ETIQUETTE = "refus-vs-absence"

# `sw.js` n'est pas un module ES et ne rend rien à l'analyste : hors population, comme dans le harnais.
HORS_POPULATION = {"sw.js"}

# --- LES DEUX NATURES DE FAIT, RECONNUES PAR CE QUE LE CODE EN LIT ------------------------------
# ÉCHEC : le serveur a refusé, la réponse n'est pas exploitable, ou la requête n'est jamais partie.
# `.error` (corps JSON du démon : `bad_req`, `server_err`, `refuse_truncated_aggregate` le posent
# tous), `!r.ok` / `r.status` (statut HTTP), et l'absence même de réponse (`!j`, `j == null`).
ECHEC = re.compile(r"""
      \.\s*error\b                                  # j.error, res.error
    | \.\s*status\b                                 # r.status
    | (?<![\w.])!\s*\w+\s*\.\s*ok\b                 # !r.ok
    | (?<![\w.])\w+\s*(?:===|==)\s*null\b           # j === null
""", re.X)
# VIDE : la réponse est là, et elle ne porte rien. `.length`, `Array.isArray(...)`, `.rows`/`.items`
# nus (`!j.rows` teste à la fois la forme et le contenu — c'est précisément le mélange visé).
VIDE = re.compile(r"""
      \.\s*length\b
    | \bArray\s*\.\s*isArray\s*\(
    | \.\s*(?:rows|items|list|results)\b
""", re.X)

# Une CONDITION, au sens de cette garde : le test d'un `if`/`while` (parenthèses appariées) ou la
# partie gauche d'un `?` de ternaire. C'est là que la décision se prend.
DEBUT_CONDITION = re.compile(r"(?<![\w$.])(?:if|while)\s*\(")

# PLANCHER de non-dégénérescence. MESURÉ le 2026-08-25 sur `web/` : 98 conditions d'échec lues sur
# 49 modules. Le plancher ferme le seul mode de panne réel de la découverte — un motif cassé qui ne
# trouve RIEN et rapporte un vert joyeux.
PLANCHER_CONDITIONS_D_ECHEC = 40
PLANCHER_MODULES = 20


def echec(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def conditions(code):
    """Rend `(ligne, texte)` pour chaque condition du texte DÉPOUILLÉ (commentaires retirés, hauteur
    conservée). Les parenthèses sont appariées : une condition qui appelle une fonction à arguments
    (`if (!j || !Array.isArray(j.rows))`) est lue en ENTIER, jamais coupée à la première `)`."""
    for m in DEBUT_CONDITION.finditer(code):
        i = m.end()          # juste après la `(` ouvrante
        prof, j, n = 1, i, len(code)
        while j < n and prof:
            c = code[j]
            if c == "(":
                prof += 1
            elif c == ")":
                prof -= 1
            j += 1
        if prof == 0:
            yield code.count("\n", 0, m.start()) + 1, code[i:j - 1]
    # Ternaire : `<test> ? … : …`. On prend la portion de ligne qui précède le `?`, ce qui suffit à
    # voir les deux natures de fait fondues (`j.error || !j.rows.length ? vide() : table()`).
    for m in re.finditer(r"[^\n?]{4,240}\?(?![.?:])", code):
        yield code.count("\n", 0, m.start()) + 1, m.group(0)[:-1]


def depouiller(src, journal=None):
    """Le texte à JUGER : commentaires retirés ET contenu des littéraux blanchi, hauteur conservée.
    Les DEUX sont nécessaires — la forme fautive écrite dans une chaîne (un message d'aide, un
    exemple) ne décide de rien, et l'y compter serait un faux positif que personne ne pourrait
    corriger sans réécrire un texte."""
    return aveugler_litteraux_js(sans_commentaires_js(src, journal), journal)


def fautes_du_texte(code):
    """Les conditions qui décident À LA FOIS de l'échec et du vide. Rend `(ligne, texte, n_echec)`
    où `n_echec` compte les conditions d'échec vues (mesure de non-dégénérescence)."""
    fautes, vues = [], 0
    for ligne, texte in conditions(code):
        a_echec = bool(ECHEC.search(texte))
        if a_echec:
            vues += 1
        if a_echec and VIDE.search(texte):
            fautes.append((ligne, " ".join(texte.split())))
    return fautes, vues


def temoins_de_la_lecture():
    """LA LECTURE SE VALIDE DANS LES DEUX SENS avant de juger l'arbre. Sans le témoin INVERSE, une
    lecture qui épinglerait TOUT passerait le premier brillamment."""
    doit_epingler = [
        # la forme historique, mot pour mot (web/dataaccess.js avant `P11.14-c`)
        "if (!j || j.error || !Array.isArray(j.rows) || !j.rows.length) { u(x); return; }",
        # la même en `&&`, et sans `Array.isArray`
        "if (j.error && !j.rows.length) { u(x); }",
        # ternaire
        "const c = (j.error || !j.rows.length) ? vide() : table();",
        # statut HTTP fondu avec le vide
        "if (!r.ok || !j.items.length) { u(x); }",
    ]
    doit_ignorer = [
        # échec SEUL : l'erreur est rendue à part (web/dashboards.js)
        "if (!r.ok || j.error) { panelBad(j.error || r.status); return; }",
        # vide SEUL
        "if (!j.rows.length) { u(x); }",
        # les deux, SÉPARÉES : c'est exactement ce que la règle demande
        "if (j.error) { refus(j.error); return; }\nif (!j.rows.length) { u(x); return; }",
        # la forme fautive écrite dans un COMMENTAIRE (elle ne décide de rien)
        "// if (j.error || !j.rows.length) { u(x); }\nconst a = 1;",
        # … et dans une CHAÎNE
        "const s = 'if (j.error || !j.rows.length)';",
    ]
    for src in doit_epingler:
        f, _ = fautes_du_texte(depouiller(src))
        assert f, f"témoin : la forme fautive n'est pas épinglée — {src}"
    for src in doit_ignorer:
        f, _ = fautes_du_texte(depouiller(src))
        assert not f, f"témoin INVERSE : une forme saine est épinglée ({f}) — {src}"



# =================================================================================================
# JAMBE B — UNE ROUTE QUI PEUT REFUSER EN 200 EST INTERROGÉE PAR UN MODULE QUI LIT LA CAUSE
# (`P10.7-d`).
#
# POURQUOI LA JAMBE A NE POUVAIT PAS VOIR CE DÉFAUT, MESURÉ LE 2026-08-29. La jambe A juge les
# CONDITIONS qui testent un échec, et refuse qu'une seule d'entre elles décide aussi du vide. Un module
# qui ne teste l'échec NULLE PART n'a aucune condition à juger : une condition ABSENTE n'est pas une
# condition fautive, et la jambe A rendait vert sur `web/alerts.js`, `web/fleet.js`, `web/datamodels.js`
# et `web/attack.js`, dont aucun ne lisait `error`. C'est l'angle mort exact que `P10.7-c` a ouvert en
# fermant le démon : depuis elle, le portillon de concurrence CLOS rend un corps **200** qui garde la
# forme attendue (`{"alerts":[]}`, `{"cases":[],"total":0}`, `{"columns":[],"rows":[]}`…) et y AJOUTE la
# cause sous `error`. `api()`/`apiSend()` (web/core.js) ne jettent que sur `!r.ok` : la cause arrive donc
# dans un corps que le consommateur lit comme un succès, et un `j.alerts || []` en fait une absence.
#
# LA POPULATION EST DÉRIVÉE DU DÉMON, EN TROIS PAS, ET N'EST ÉNUMÉRÉE NULLE PART :
#   (1) les fonctions de `daemon/src/handlers/` qui posent la clé `error` dans un corps SERVI EN 200,
#       par l'une des trois ÉCRITURES ci-dessous — et non par un NOM posé (voir juste après) ;
#   (2) celles qui les APPELLENT, tant qu'elles ne sont pas routées — sans ce pas, `run_generated_soql`
#       sortirait de l'ensemble et le Pivot avec lui ;
#   (3) l'intersection avec la table de routage : les CHEMINS servis par ces fonctions.
# Puis, côté console : tout appel de `api`/`apiSend`/`fetchInto` dont l'URL peut être l'un de ces chemins.
# Une route qu'on ajoutera demain à l'une des trois écritures entre dans la population sans être nommée ici.
#
# POURQUOI LA FORME A REMPLACÉ LE NOM, ET CE QUE ÇA A COÛTÉ DE LE MESURER (`P10.20-a`, 2026-09-16). La
# population était ancrée sur UN point, `portillon::corps_de_refus` : quatorze chemins. Le démon avoue
# pourtant par bien d'autres endroits — `liste_bornee::corps_de_liste_illisible` et son frère
# `corps_de_listes_illisibles`, le corps de liste bornée `liste_bornee::corps`, et une quinzaine de sites
# qui posent la cause à la main. Ce ne sont pas des NOMS à ajouter un par un : ce sont TROIS ÉCRITURES.
#   * AJOUTÉE  — `corps["error"] = …` : un corps DÉJÀ formé reçoit la cause. 17 sites.
#   * INSÉRÉE  — `.insert("error", …)` : la même chose sur une carte JSON. 4 sites.
#   * NÉE      — `json!({ …, "error": … })` : le corps naît avec sa cause, ET GARDE AU MOINS UNE AUTRE
#                CLÉ — c'est cette autre clé qui le rend lisible comme un succès. 63 sites.
# 84 sites, 51 fonctions fabricantes, 77 chemins, 68 sites de `web/` — contre 14 et 14 par le nom seul.
#
# CE QUE LA DÉRIVATION PAR FORME A COÛTÉ EN INSTRUMENT, ÉCRIT PLUTÔT QUE TU :
#   (a) ELLE LISAIT LES COMMENTAIRES COMME DU CODE. Le pas (2) cherche les appelants par le NOM de la
#       fonction, et `liste_bornee::corps` s'appelle `corps` — un mot français. `daemon/src/handlers/
#       detection.rs:818` porte « …OBLIGATOIRE du corps ({enabled:bool})… » dans un commentaire de
#       documentation : `\bcorps\s*\(` y mordait, `set_content_enabled_tx` entrait dans la population,
#       et avec lui SES TROIS APPELANTS — `/api/rules/{id}/enabled`, `/api/parsers/{id}/enabled`,
#       `/api/playbooks/{id}/enabled`, trois routes dont l'échec passe par `err_json` et ne peut donc
#       JAMAIS servir un 200 portant `error`. Trois accusations sans cause. Le démon est désormais lu
#       SANS ses commentaires, et le témoin qui le prouve fabrique ce commentaire-là.
#   (b) UN CORPS À STATUT N'EST PAS UN CORPS SERVI EN 200. `(StatusCode::INTERNAL_SERVER_ERROR,
#       Json(json!({ "error": … })))` est un REJET : `api()`/`apiSend()` jettent sur `!r.ok`, et la cause
#       y voyage par le porteur commun (`avecLaCauseDuDemon`, web/core.js, `P10.20-b`). Le confondre avec
#       un aveu en 200 accusait `web/cases.js` deux fois. Un site dont l'INSTRUCTION porte `StatusCode::`
#       est donc hors population, par construction et non par exemption.
#   (c) UN CORPS QUI NE PORTE **QUE** `error` N'A PAS DE FORME DE SUCCÈS. `json!({ "error": "réservé
#       admin" })` ne se lit pas comme une liste vide : un consommateur qui lit `j.rows` y trouve
#       `undefined`, pas `[]`. C'est un autre défaut de rendu, et il n'est pas tenu ici. Ces sites-là
#       sont le RESTE ADMIS, et il est NOMMÉ (`CORPS_A_CAUSE_SEULE`), jugé dans les deux sens.
#
# ET LA COUVERTURE DES FORMES EST ELLE-MÊME JUGÉE. Toute occurrence du littéral `"error"` dans
# `daemon/src/handlers/` est CLASSÉE — l'une des trois écritures, une LECTURE (`get("error")`), ou une
# VALEUR (`3 => "error"`). Une occurrence qu'aucune classe ne reçoit est une QUATRIÈME écriture, donc un
# fabricant d'aveu que cette garde ne dérive pas : elle ROUGIT en la nommant, au lieu de l'ignorer.
#
# CE QUE LA GARDE EXIGE, ET POURQUOI LE CRITÈRE DIFFÈRE SELON L'APPEL. Ce que le consommateur doit lire
# est le CORPS. `api`/`apiSend`/`fetchInto` rendent le corps DÉJÀ analysé : la valeur liée à l'appel EST
# le corps, et la garde exige que cette valeur atteigne une lecture de `error` — directement
# (`j.error`) ou par une fonction du module qui la lit (`causeDuRefusServi(j)`, `refusDeMatrice(d)`,
# `renderResults(host, d)`). Une DÉCONSTRUCTION (`({ cases } = await api(…))`) ne lie pas le corps : elle
# le jette, avec l'aveu qu'il porte — c'est le défaut mesuré sur `detection_admin.js` et sur trois
# sélecteurs de `cases.js`, et la garde le voit comme tel. `fetch` nu, lui, rend une RÉPONSE : le corps
# n'est analysé que quelques lignes plus bas, dans une AUTRE variable, et la garde exige alors que la
# PORTÉE de l'appel lise `error` (c'est ce que font `web/viz.js` et `web/dashboards.js`).
#
# CE QUE CETTE JAMBE NE PROUVE PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU :
#   * que la phrase RENDUE soit honnête — lire `error` et le taire resterait vert ici. Cette part se
#     tient en EXERÇANT le module (harnais ESM), jamais en le lisant ;
#   * les appels `fetch` NUS ne sont pas jugés — ils rendent une réponse, pas un corps (voir plus haut).
#     Relevé le 2026-09-16 : il n'en reste qu'UN dans `web/` sur une route à aveu, et il a été porté sur
#     la voie commune (`web/fieldfilters.js`, qui lisait pourtant DÉJÀ `data.error` — ce que rien ne
#     tenait d'un lot à l'autre, faute qu'il soit dans la population) ;
#   * un corps servi en 200 qui ne porte QUE `error` — le RESTE NOMMÉ ci-dessous ;
#   * la correspondance d'URL est CONSERVATRICE : un segment inconnu (`'/cases/' + id`) n'apparie qu'un
#     segment PARAMÈTRE de la route, et un segment mixte (`'/cases' + filtre`) n'apparie que le dernier
#     segment, par son préfixe littéral. Une URL trop dynamique pour être appariée sort donc de la
#     population : les biais vont vers le SOUS-compte, jamais vers l'accusation ;
#   * un corps LIÉ puis rendu à l'appelant (`return j`) sans être lu est compté SOURD : la garde ne suit
#     pas un flot de données. Aucun site du dépôt n'est dans ce cas aujourd'hui ; le jour où il y en aura
#     un, c'est une accusation à instruire, pas un verdict.
#
# DEUX FAUTES D'INSTRUMENT ONT ÉTÉ MESURÉES EN L'ÉCRIVANT, ET ELLES SONT ÉCRITES PLUTÔT QUE TUES.
# (1) La lecture cherchait le nom de la réponse dans le MODULE entier : `r` et `j` nomment une réponse dans
#     une dizaine de fonctions d'`alerts.js` et de `cases.js`, si bien qu'un site cessant de lire sa cause
#     restait vert grâce à un AUTRE site qui lisait la sienne — deux mutations sur six passaient. La lecture
#     est désormais bornée à la PORTÉE de l'appel, et la reconnaissance des portées a dû être corrigée avec
#     elle (elle interdisait les parenthèses entre `function` et `{`, donc ne reconnaissait AUCUNE
#     déclaration à paramètre, donc rendait toute portée égale au module).
# (2) La MÉTHODE n'était pas lue, et la garde accusait `apiSend('/cases', 'POST', …)` — la CRÉATION d'un
#     cas, qui n'a pas de portillon — parce qu'elle l'appariait à `GET /api/cases`. Une accusation sans
#     cause est pire qu'un silence : les chemins dérivés portent maintenant leur verbe, et l'appel le sien.

DAEMON = os.path.join(RACINE, "daemon", "src")

# LES TROIS ÉCRITURES D'UN AVEU DANS UN CORPS SERVI EN 200. Elles ne nomment aucune fonction : c'est la
# FORME qui est reconnue, de sorte qu'un fabricant écrit demain entre dans la population sans être ajouté
# ici. Voir l'en-tête pour ce que chacune vaut, et pour les trois fautes d'instrument qu'elles ont coûtées.
FORME_AJOUTEE = re.compile(r'\[\s*"error"\s*\]\s*=')
FORME_INSEREE = re.compile(r'insert\(\s*(?:String::from\(\s*)?"error"')
DEBUT_JSON = re.compile(r"json!\s*\(\s*\{")
CLE_JSON = re.compile(r'"([A-Za-z_]\w*)"\s*:')
TOUT_ERROR = re.compile(r'"error"')
ENTETE_FN = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)", re.M)

# LE RESTE ADMIS, NOMMÉ ET JUGÉ DANS LES DEUX SENS. Ces fonctions servent, en 200, un corps qui ne porte
# QUE `error` : un refus nu (« réservé admin », « motif vide », « exécution échouée »), sans forme de
# succès à imiter. Un consommateur qui y lit une clé de données trouve `undefined`, jamais une liste vide
# — le défaut que cette garde tient ne s'y produit pas, et c'est pourquoi elles en sortent. Un ENSEMBLE
# plutôt qu'un compte : un compte se laisse compenser (une entrée neuve pour une retirée), un ensemble
# non. Il est jugé dans les DEUX sens — une fonction qui se met à servir un tel corps sans être ici fait
# ROUGIR (forme neuve non dérivée), et une entrée qui n'a plus de site fait rougir aussi (exemption sans
# objet). Relevé le 2026-09-16 : 33 sites, 11 fonctions.
CORPS_A_CAUSE_SEULE = {
    ("actions.rs", "action_create"),
    ("caseops.rs", "case_metrics"),
    ("detection.rs", "parser_reparse"),
    ("detection.rs", "parser_test"),
    ("detection.rs", "rule_test"),
    ("detection.rs", "rule_test_adhoc"),
    ("detection_advanced.rs", "baseline_test"),
    ("detection_advanced.rs", "correlation_test"),
    # `P10.28-c` (2026-09-25) — `notifier_create` RETIRÉE : ses refus ne sont plus des deux cents `{error}` ; le rôle
    # rend la phrase TEXTE de `rbac_gate` (403), une URL refusée un 400 nommé, un `BEGIN` ou un `COMMIT` refusé un 503
    # nommé, une écriture refusée un 500 nommé — tous par `err_json` ou un statut, donc hors population (b).
    ("notifiers.rs", "notifier_test"),
    ("playbooks.rs", "playbook_test"),
}

# LES TROIS APPELS QUI RENDENT UN CORPS, et l'index de l'argument qui porte l'URL + la MÉTHODE (None =
# lue sur l'appel : `apiSend(chemin, methode, corps)`, défaut `POST`). Tous trois préfixent `/api`
# (web/core.js). LE `fetch` NU EST HORS POPULATION, et pas par exemption : il rend une RÉPONSE, pas un
# corps — le corps est analysé plus bas, dans une autre variable, souvent RENDU à l'appelant qui le lira
# (`web/viz.js` le fait trois fois). Le suivre demanderait un flot de données que cette garde ne fait
# pas, et le juger à la portée accuse un relais qui ne consomme rien. Les trois consommateurs de
# `/api/query` par `fetch` nu sont tenus ailleurs : `P11.14-c` pour le panneau d'accès données, et le
# témoin 16 du harnais ESM pour la phrase rendue.
APPELS_WEB = {"api": (0, "GET"), "apiSend": (0, None), "fetchInto": (1, "GET")}

# PLANCHERS DE NON-DÉGÉNÉRESCENCE. Relevé le 2026-09-16, dérivation par FORME : 84 sites d'aveu dans
# `daemon/src/handlers/`, 51 fonctions fabricantes, 77 chemins routés, 68 sites de `web/` qui les
# interrogent. Sous ces planchers, c'est la DÉRIVATION qui est cassée (une écriture renommée, la table de
# routage déplacée, les appels de la console réécrits) et la garde refuse de conclure plutôt que de rendre
# un vert aveugle. Ils sont posés à environ soixante pour cent du relevé, comme les précédents : assez bas
# pour qu'une refonte honnête passe, assez haut pour qu'un motif cassé — qui rend ZÉRO — soit vu.
#
# LE « 20 SITES » QUI ÉTAIT ÉCRIT ICI ÉTAIT FAUX, ET IL L'ÉTAIT DÉJÀ LE JOUR OÙ IL A ÉTÉ ÉCRIT. La garde
# imprimait « 14 site(s) de web/ les interrogent » au MÊME commit où ce commentaire en annonçait 20 : un
# chiffre recopié à la main à côté d'un chiffre dérivé, et c'est toujours le recopié qui vieillit. La
# valeur qui fait foi reste celle que la garde IMPRIME, jamais celle-ci.
PLANCHER_CHEMINS_A_AVEU = 45
PLANCHER_SITES_WEB = 40

# PLAFOND DE SITES SOURDS PAR MODULE — un CLIQUET, pas une exemption. Relevé le 2026-08-29 en fermant
# `P10.7-d` : sur les 14 sites dérivés, PLUS AUCUN n'est sourd. La table est donc VIDE, et vide est sa
# forme la plus forte : un module absent est jugé à ZÉRO, donc toute régression, dans n'importe quel
# module de `web/`, est désormais un échec — il n'existe plus une seule case où un site sourd soit toléré.
#
# ELLE EST RESTÉE VIDE EN PASSANT DE 14 À 77 CHEMINS (`P10.20-a`, 2026-09-16), ET C'EST CE QUI A COÛTÉ LE
# LOT. La dérivation par forme a révélé TREIZE sites sourds d'un coup — la liste des tableaux de bord qui
# peignait « Aucun dashboard » sous un bouton « + Dashboard », la file des actions EN ATTENTE
# D'APPROBATION qui se présentait vide, l'interrupteur de mode qui peignait « Observation (sûr) » sur le
# repli du démon, le journal d'AUDIT qui se disait vierge, l'inventaire des environnements qui se lisait
# « ce tenant n'en a qu'un ». Les treize ont été CORRIGÉS avant l'extension, et c'est le sens du cliquet :
# élargir la population en s'accordant une case tolérée aurait rendu vert un dépôt plus sourd qu'avant.
#
# CE QUE LES DEUX DERNIÈRES ENTRÉES DISAIENT, ET CE QUI A ÉTÉ CORRIGÉ (mesuré en EXERÇANT les deux rendus
# sur le corps exact que le démon sert, pas en les relisant) :
#   fleet.js — `/api/fleet`, via `fetchInto(wrap, '/fleet?…')` et NON `api(…)` comme l'annonçait la ligne
#              qui vivait ici. Le corps du refus n'ayant pas de `pipeline_fresh`, la vue ne rendait pas
#              « aucun hôte » : elle rendait D'ABORD, en rouge, « Ingestion en panne — aucune donnée reçue
#              récemment ». Un refus de lire s'y présentait donc comme un INCIDENT CONSTATÉ, ce qui est
#              strictement pire qu'une absence. `renderFleetInventory` lit maintenant `d.error` avant
#              toute lecture de la forme, et ne pose ni bannière, ni lignes, ni barre d'export.
#   detection_admin.js — `/api/coverage/detections` : `({ detections } = await api(…))` DÉCONSTRUISAIT la
#              réponse et jetait l'aveu avec elle ; `renderCoverage` sortait « aucune technique détectée »,
#              c'est-à-dire un VERDICT DE COUVERTURE tiré d'une lecture jamais faite. Le corps est
#              désormais lié (`rep`), sa cause lue, et le test du refus précède celui du vide.
# Un plafond ne monte pas sans raison écrite à côté ; le faire descendre est le seul mouvement qui ne se
# discute pas. Il est descendu à ce qui est mesuré, et ce qui est mesuré est zéro.
PLAFOND_SOURDS = {}


def _bloc(code, i):
    """Fin du bloc ouvert par le délimiteur en `i` (parenthèses/crochets/accolades appariés)."""
    prof, j, n = 1, i + 1, len(code)
    while j < n and prof:
        c = code[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        j += 1
    return j


def _arguments(code, i):
    """Les arguments de l'appel dont la `(` est en `i`, et l'offset qui suit la `)` fermante."""
    prof, j, n, args, deb = 1, i + 1, len(code), [], i + 1
    while j < n and prof:
        c = code[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
            if prof == 0:
                args.append(code[deb:j])
                break
        elif c == "," and prof == 1:
            args.append(code[deb:j])
            deb = j + 1
        j += 1
    return args, j + 1


def sans_commentaires_rs(src):
    r"""Le texte Rust SANS ses commentaires, hauteur et offsets CONSERVÉS (chaque octet retiré devient une
    espace). Les littéraux de chaîne sont gardés — c'est là que vivent les URL de routes et les causes.

    POURQUOI CETTE FONCTION EXISTE, ET CE QU'ELLE A FERMÉ (mesuré le 2026-09-16). La dérivation cherche
    les APPELANTS d'une fonction d'aveu par son NOM. `liste_bornee::corps` s'appelle `corps` — un mot
    français, qui apparaît en toutes lettres dans la prose du dépôt. `daemon/src/handlers/detection.rs`
    porte, en commentaire de documentation, « …le booléen `enabled` OBLIGATOIRE du corps ({enabled:bool}) »
    : le motif `\bcorps\s*\(` y mordait, et `set_content_enabled_tx` — qui ne sert JAMAIS un 200 portant
    `error`, son échec passant par `err_json` — entrait dans la population avec ses trois appelants. Trois
    accusations sans cause, nées d'une phrase en français."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _objets_json(code):
    """(début, fin) de chaque littéral d'objet `json!({ … })`, accolades APPARIÉES."""
    for m in DEBUT_JSON.finditer(code):
        i = code.index("{", m.end() - 1)
        yield i, _bloc(code, i)


def _cles_de_tete(bloc):
    """Les clés de PREMIER niveau d'un littéral d'objet : ce que le consommateur lit directement. Les
    sous-objets et sous-tableaux sont SAUTÉS — `json!({ "error": e, "a": { "b": 1 } })` a deux clés de
    tête, pas trois, et c'est bien la présence d'`a` À CÔTÉ d'`error` qui donne au corps sa forme."""
    out, i, n = [], 1, len(bloc) - 1
    while i < n:
        if bloc[i] in "{[(":
            i = _bloc(bloc, i)
            continue
        m = CLE_JSON.match(bloc, i)
        if m:
            out.append(m.group(1))
            i = m.end()
            continue
        i += 1
    return out


def _a_un_statut(code, debut):
    """Le site est-il DANS une réponse à STATUT EXPLICITE ? On remonte au début de l'instruction (le
    dernier `;`, `{` ou `}`) : `(StatusCode::…, Json(json!({ "error": … })))` est un REJET, que
    `api()`/`apiSend()` voient par `!r.ok` et dont la cause voyage par le porteur commun."""
    d = max(code.rfind(";", 0, debut), code.rfind("{", 0, debut), code.rfind("}", 0, debut))
    return "StatusCode::" in code[d + 1:debut]


def _fonction_de(debuts, position):
    avant = [f for (p, f) in debuts if p < position]
    return avant[-1] if avant else None


def sites_d_aveu(textes):
    """LES SITES OÙ LE DÉMON POSE SA CAUSE DANS UN CORPS SERVI EN 200, par FORME.

    Rend `(sites, reste, inconnus)` :
      * `sites`   — `(fichier, ligne, fonction, forme)` pour les trois écritures ;
      * `reste`   — `(fichier, fonction)` des corps servis en 200 qui ne portent QUE `error` ;
      * `inconnus`— les occurrences du littéral `"error"` qu'aucune classe ne reçoit : une QUATRIÈME
                    écriture, donc un fabricant que cette garde ne dérive pas. Elle rougit dessus."""
    sites, reste, inconnus = [], set(), []
    for nom, code in sorted(textes.items()):
        debuts = [(m.start(), m.group(1)) for m in ENTETE_FN.finditer(code)]
        objets = list(_objets_json(code))
        for mot, forme in ((FORME_AJOUTEE, "ajoutée"), (FORME_INSEREE, "insérée")):
            for m in mot.finditer(code):
                if _a_un_statut(code, m.start()):
                    continue
                f = _fonction_de(debuts, m.start())
                if f:
                    sites.append((nom, code.count("\n", 0, m.start()) + 1, f, forme))
        for i, j in objets:
            cles = _cles_de_tete(code[i:j])
            if "error" not in cles or _a_un_statut(code, i):
                continue
            f = _fonction_de(debuts, i)
            if not f:
                continue
            if len(set(cles)) >= 2:
                sites.append((nom, code.count("\n", 0, i) + 1, f, "née"))
            else:
                reste.add((nom, f))
        # LA COUVERTURE DES FORMES, JUGÉE : toute occurrence de `"error"` reçoit une classe, ou rougit.
        for m in TOUT_ERROR.finditer(code):
            q, ap = m.start(), code[m.end():m.end() + 8]
            av = code[max(0, q - 60):q]
            if re.search(r"\[\s*$", av) and re.match(r"\s*\]\s*=", ap):
                continue                                    # AJOUTÉE
            if re.search(r"insert\(\s*(?:String::from\(\s*)?$", av):
                continue                                    # INSÉRÉE
            if re.search(r"get(?:_mut)?\(\s*$", av):
                continue                                    # une LECTURE, pas une écriture
            if re.match(r"\s*:", ap):
                if any(i < q < j for i, j in objets):
                    continue                                # NÉE
                inconnus.append((nom, code.count("\n", 0, q) + 1,
                                 "la clé `error` est posée hors d'un littéral `json!({…})`"))
                continue
            continue                                        # `"error"` comme VALEUR (`3 => "error"`)
    return sites, reste, inconnus


def chemins_a_aveu(racine=None):
    """LES CHEMINS QU'UN AVEU SERVI EN 200 PEUT ATTEINDRE — dérivés du démon, jamais énumérés.

    Rend `(chemins, fabricantes, sites, reste, inconnus)`."""
    base = racine or DAEMON
    handlers = os.path.join(base, "handlers")
    if not os.path.isdir(handlers):
        return [], set(), [], set(), []
    textes = {}
    for dossier, _, fichiers in os.walk(handlers):
        for nom in sorted(fichiers):
            if not nom.endswith(".rs"):
                continue
            chemin = os.path.join(dossier, nom)
            with open(chemin, encoding="utf-8") as fh:
                textes[os.path.relpath(chemin, handlers)] = sans_commentaires_rs(fh.read())
    sites, reste, inconnus = sites_d_aveu(textes)
    fabricantes = {f for _, _, f, _ in sites}
    routes = []
    for dossier, _, fichiers in os.walk(base):
        for nom in sorted(fichiers):
            if not nom.endswith(".rs"):
                continue
            with open(os.path.join(dossier, nom), encoding="utf-8") as fh:
                code = sans_commentaires_rs(fh.read())
            for m in re.finditer(r'\.route\(\s*"([^"]+)"\s*,\s*([^\n]+)', code):
                for v, f in re.findall(r"\b(get|post|put|delete|patch)\s*\(\s*([A-Za-z_]\w*)", m.group(2)):
                    routes.append((m.group(1), v.upper(), f))
    routees = {f for _, _, f in routes}
    # (2) l'INDIRECTION : une fonction d'aveu non routée est atteinte par celles qui l'appellent.
    atteintes = set(fabricantes)
    for _ in range(4):
        neuves = set()
        for f in atteintes - routees:
            for nom, code in textes.items():
                debuts = [(m.start(), m.group(1)) for m in ENTETE_FN.finditer(code)]
                for m in re.finditer(r"\b" + re.escape(f) + r"\s*\(", code):
                    g = _fonction_de(debuts, m.start())
                    if g and g != f:
                        neuves.add(g)
        if neuves <= atteintes:
            break
        atteintes |= neuves
    return sorted({(c, v) for c, v, f in routes if f in atteintes}), fabricantes, sites, reste, inconnus


TROU = "\x00"


def motif_d_url(expr):
    """Le CHEMIN qu'une expression d'URL peut produire : littéraux gardés, tout le reste -> un TROU."""
    out, i, n = [], 0, len(expr)
    while i < n:
        c = expr[i]
        if c in "'\"`":
            j = i + 1
            while j < n and expr[j] != c:
                j += 2 if expr[j] == "\\" else 1
            dedans = expr[i + 1:j]
            out.append(re.sub(r"\$\{[^}]*\}", TROU, dedans) if c == "`" else dedans)
            i = j + 1
        else:
            if not out or out[-1] != TROU:
                out.append(TROU)
            i += 1
    return "".join(out)


def apparie(chemin, candidat):
    """La route `chemin` peut-elle être CELLE que produit `candidat` ? Conservateur par construction :
    un TROU n'apparie qu'un segment PARAMÈTRE (`{id}`) — sans quoi `'/cases/' + id` passerait pour
    `/cases/metrics` ; un segment MIXTE (littéral collé à un trou) n'apparie que le DERNIER segment de la
    route, par son seul préfixe littéral — au-delà, ce que le trou contient est inconnu (il peut porter
    `/` comme `?`), et la garde ne devine pas."""
    candidat = candidat.split("?")[0].split("#")[0]
    rs = chemin.strip("/").split("/")
    cs = candidat.strip("/").split("/")
    for i, seg in enumerate(cs):
        if TROU in seg and seg != TROU:
            return len(rs) == i + 1 and rs[i] == seg.split(TROU)[0]
    if len(rs) != len(cs):
        return False
    for a, b in zip(rs, cs):
        if b == TROU:
            if not a.startswith("{"):
                return False
        elif not a.startswith("{") and a != b:
            return False
    return True


def _portees(code):
    """(début, fin) du CORPS de chaque fonction — déclaration (`function f(a, b) {`) comme flèche à
    accolades (`(a) => {`). Les parenthèses sont APPARIÉES : une première écriture les interdisait entre
    `function` et `{`, ce qui ne reconnaissait AUCUNE déclaration à paramètre et rendait la portée de tout
    site égale au module — la cécité même que la restriction de portée existe pour fermer."""
    out = []
    for m in re.finditer(r"\bfunction\b", code):
        i = code.find("(", m.end())
        if i < 0 or i - m.end() > 80:
            continue
        j = _bloc(code, i)
        while j < len(code) and code[j] in " \t\r\n":
            j += 1
        if j < len(code) and code[j] == "{":
            out.append((j, _bloc(code, j)))
    for m in re.finditer(r"=>\s*\{", code):
        d = m.end() - 1
        out.append((d, _bloc(code, d)))
    return out


DESTRUCTURATION_PROMISE_ALL = re.compile(
    r"(?:const|let|var)\s*\[([^\]]*)\]\s*=\s*await\s+Promise\s*\.\s*all\s*\(\s*\[")


def _noms_de_promise_all(code):
    """`const [sc, tp] = await Promise.all([api(a), api(b)])` LIE chaque corps à un nom : le i-ième
    élément du tableau au i-ième nom. La garde lisait cette forme comme « la réponse n'est liée à aucun
    nom » et accusait `web/soql_complete.js`, qui lit pourtant la cause — c'est la faute d'instrument (2)
    du 2026-08-29 retrouvée sous une autre forme, et une accusation sans cause est pire qu'un silence.
    Rend `[(début, fin, nom)]`, une entrée par élément du tableau dont le nom est un identifiant."""
    out = []
    for m in DESTRUCTURATION_PROMISE_ALL.finditer(code):
        noms = [n.strip() for n in m.group(1).split(",")]
        i = m.end() - 1                       # la `[` du tableau d'attentes
        fin = _bloc(code, i)
        prof, j, deb, k = 1, i + 1, i + 1, 0
        while j < fin:
            c = code[j]
            if c in "([{":
                prof += 1
            elif c in ")]}":
                prof -= 1
                if prof == 0:
                    if k < len(noms):
                        out.append((deb, j, noms[k]))
                    break
            elif c == "," and prof == 1:
                if k < len(noms):
                    out.append((deb, j, noms[k]))
                k += 1
                deb = j + 1
            j += 1
    return [(a, b, n) for (a, b, n) in out if re.fullmatch(r"[A-Za-z_$]\w*", n)]


def sites_sourds_du_module(src, chemins):
    """Les sites de ce module qui interrogent une route à portillon SANS lire la cause qu'elle sert.
    Rend `(sites, sourds)` : le nombre de sites appariés, et la liste `(ligne, chemin, pourquoi)`."""
    texte = sans_commentaires_js(src)          # les URL sont dans les littéraux : on les garde
    code = aveugler_litteraux_js(texte)        # même longueur, littéraux blanchis : on juge le CODE
    # les fonctions du module qui LISENT la cause (dérivé, jamais énuméré)
    lecteurs = set()
    for m in re.finditer(r"function\s+([A-Za-z_$]\w*)\s*\(", code):
        _, apres = _arguments(code, m.end() - 1)
        k = code.find("{", apres - 1)
        if k >= 0 and ".error" in code[k:_bloc(code, k)]:
            lecteurs.add(m.group(1))
    # les URL nommées par une variable, résolues par PROXIMITÉ (la plus proche affectation qui précède)
    variables = {}
    for m in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*([^;\n]+)", texte):
        p = motif_d_url(m.group(2))
        if p.startswith("/"):
            variables.setdefault(m.group(1), []).append((m.start(), p))
    portees = _portees(code)
    destructurees = _noms_de_promise_all(code)
    sites, sourds = 0, []
    for m in re.finditer(r"(?<![\w.$])(api|apiSend|fetchInto)\s*\(", code):
        appel = m.group(1)
        idx, verbe = APPELS_WEB[appel]
        args, _ = _arguments(texte, m.end() - 1)
        if len(args) <= idx:
            continue
        if verbe is None:      # `apiSend(chemin, methode, corps)` — défaut POST (web/core.js)
            lit = re.fullmatch(r"\s*['\"]([A-Za-z]+)['\"]\s*", args[1]) if len(args) > 1 else None
            verbe = lit.group(1).upper() if lit else "POST"
        expr = args[idx].strip()
        if re.fullmatch(r"[A-Za-z_$]\w*", expr):
            avant = [p for (pos, p) in variables.get(expr, []) if pos < m.start()]
            candidat = avant[-1] if avant else None
        else:
            candidat = motif_d_url(expr)
        if not candidat or not candidat.startswith("/"):
            continue
        vise = next((c for (c, v) in chemins if v == verbe and apparie(c[len("/api"):] or "/", candidat)), None)
        if not vise:
            continue
        sites += 1
        ligne = code.count("\n", 0, m.start()) + 1
        # LA PORTÉE DE L'APPEL, ET RIEN DE PLUS. Chercher dans le MODULE entier était une CÉCITÉ mesurée le
        # 2026-08-29 par mutation : `r` et `j` nomment une réponse dans une dizaine de fonctions de
        # `alerts.js` et de `cases.js`, si bien qu'un site qui cessait de lire sa cause restait vert grâce à
        # un AUTRE site qui lisait la sienne. Deux mutations sur six passaient. Le nom n'a de sens que dans
        # sa portée, et c'est là — et là seulement — qu'il doit être lu.
        dedans = [(d, f) for (d, f) in portees if d < m.start() < f]
        if dedans:
            d, f = max(dedans, key=lambda x: x[0])
            corps = code[d:f]
        else:
            corps = code
        # `api`/`apiSend`/`fetchInto` rendent le CORPS : il doit être LIÉ, puis lu.
        amont = code[max(0, m.start() - 90):m.start()]
        lie = re.search(r"([A-Za-z_$]\w*)\s*=\s*(?:await\s+)?$", amont)
        # Un tableau d'attentes déconstruit lie CHAQUE corps à son nom, positionnellement : le site n'est
        # pas anonyme, et l'accuser de l'être serait une accusation sans cause.
        par_tableau = next((n for (a, b, n) in destructurees if a <= m.start() < b), None)
        if not lie and not par_tableau:
            if re.search(r"\{[^{}]*\}\s*=\s*(?:await\s+)?$", amont):
                sourds.append((ligne, vise, "la réponse est DÉCONSTRUITE : le corps n'est pas lié, et l'aveu part avec lui"))
            else:
                sourds.append((ligne, vise, "la réponse n'est liée à aucun nom : rien ne peut en lire la cause"))
            continue
        nom = lie.group(1) if lie else par_tableau
        vu = bool(re.search(r"\b" + re.escape(nom) + r"\s*\.\s*error\b", corps))
        for lecteur in lecteurs:
            if re.search(r"\b" + re.escape(lecteur) + r"\s*\([^;]{0,160}?\b" + re.escape(nom) + r"\b", corps):
                vu = True
        if not vu:
            sourds.append((ligne, vise, "`" + nom + ".error` n'est lu nulle part, et `" + nom + "` n'est passé à aucune fonction qui le lise"))
    return sites, sourds


def temoins_de_la_derivation():
    """LA DÉRIVATION PAR FORME SE VALIDE DANS LES DEUX SENS, sur un démon FABRIQUÉ. Sans ces témoins,
    une écriture qui cesserait d'être reconnue rendrait une population plus PETITE — donc un vert plus
    facile — sans que rien ne le dise."""
    # (a) le dépouilleur Rust : le code est lu, le commentaire ne l'est PAS. C'est la faute d'instrument
    #     du 2026-09-16, reproduite ici mot pour mot sur le site qui l'a révélée.
    avec_commentaire = ('/// Extrait le booléen `enabled` OBLIGATOIRE du corps ({enabled:bool}).\n'
                        'fn body_enabled(b: &Value) -> Result<bool, Response> { bad_req("x") }\n')
    nu = sans_commentaires_rs(avec_commentaire)
    assert "corps (" not in nu, "témoin : un commentaire Rust est encore lu comme du code — la dérivation accusera par une phrase française"
    assert nu.count("\n") == avec_commentaire.count("\n"), "témoin : le dépouilleur Rust ne conserve plus la hauteur — les numéros de ligne mentiraient"
    assert 'bad_req("x")' in nu, "témoin INVERSE : le dépouilleur mange du CODE"
    assert '"//pas-un-commentaire"' in sans_commentaires_rs('let s = "//pas-un-commentaire";'), \
        "témoin INVERSE : une barre double DANS une chaîne est prise pour un commentaire"
    # (b) les trois écritures, et ce que chacune rend — sur un démon FABRIQUÉ, jamais sur l'arbre réel.
    faux = {"faux.rs": sans_commentaires_rs(
        'pub(crate) async fn a_ajoutee() -> Json<Value> { let mut c = json!({ "rows": [] }); c["error"] = json!("x"); Json(c) }\n'
        'pub(crate) async fn b_inseree() -> Json<Value> { let mut o = serde_json::Map::new(); o.insert("error".into(), json!("x")); Json(Value::Object(o)) }\n'
        'pub(crate) async fn c_nee() -> Json<Value> { Json(json!({ "rows": [], "error": "x" })) }\n'
        'pub(crate) async fn d_cause_seule() -> Json<Value> { Json(json!({ "error": "réservé admin" })) }\n'
        'pub(crate) async fn e_a_statut() -> Response { (StatusCode::BAD_REQUEST, Json(json!({ "rows": [], "error": "x" }))).into_response() }\n'
        'pub(crate) async fn f_lecture(v: &Value) -> bool { v.get("error").is_none() }\n'
        'pub(crate) fn g_valeur(n: i64) -> &\'static str { match n { 3 => "error", _ => "info" } }\n'
        '// pub(crate) async fn h_commentee() -> Json<Value> { Json(json!({ "rows": [], "error": "x" })) }\n')}
    sites, reste, inconnus = sites_d_aveu(faux)
    par_forme = {f: sorted(n for _, _, n, g in sites if g == f) for f in ("ajoutée", "insérée", "née")}
    assert par_forme["ajoutée"] == ["a_ajoutee"], f"témoin : la forme AJOUTÉE ne rend pas ce qu'elle doit — {par_forme}"
    assert par_forme["insérée"] == ["b_inseree"], f"témoin : la forme INSÉRÉE ne rend pas ce qu'elle doit — {par_forme}"
    assert par_forme["née"] == ["c_nee"], f"témoin : la forme NÉE ne rend pas ce qu'elle doit — {par_forme}"
    assert reste == {("faux.rs", "d_cause_seule")}, f"témoin : le RESTE (corps à cause seule) n'est pas celui attendu — {reste}"
    assert not inconnus, f"témoin INVERSE : une occurrence classable est rendue INCONNUE — {inconnus}"
    # (c) l'INCONNU : une clé `error` posée hors d'un littéral `json!` est une QUATRIÈME écriture.
    _, _, quatrieme = sites_d_aveu({"faux.rs": 'struct R { }\nconst T: &str = "x";\nfn z() { let m = maplit!{ "error": 1, "rows": 2 }; }\n'})
    assert quatrieme, "témoin : une écriture de `error` hors `json!` passe INAPERÇUE — une forme neuve rendrait la garde muette"
    # (d) le lecteur de la console : un tableau d'attentes déconstruit LIE chaque corps.
    d = _noms_de_promise_all("const [sc, tp] = await Promise.all([api('/a'), api('/b')]);")
    assert [n for _, _, n in d] == ["sc", "tp"], f"témoin : un `Promise.all` déconstruit ne lie plus ses corps — {d}"
    assert not _noms_de_promise_all("const x = await api('/a');"), "témoin INVERSE : un appel simple est lu comme un tableau d'attentes"


def temoins_de_la_jambe_b():
    """LA LECTURE DE LA JAMBE B SE VALIDE DANS LES DEUX SENS, sur les formes du dépôt."""
    ch = [("/api/alerts", "GET"), ("/api/cases", "GET"), ("/api/cases/metrics", "GET"),
          ("/api/datasets/{id}/run", "POST"), ("/api/query", "POST")]
    # (a) l'appariement d'URL, dans les deux sens
    assert apparie("/alerts", "/alerts?" + TROU), "témoin : une URL à requête n'apparie plus sa route"
    assert apparie("/datasets/{id}/run", "/datasets/" + TROU + "/run"), "témoin : un paramètre n'apparie plus un trou"
    assert apparie("/cases", "/cases" + TROU + "&" + TROU), "témoin : un segment mixte n'apparie plus sa route par son préfixe"
    assert not apparie("/cases/metrics", "/cases/" + TROU), "témoin INVERSE : un trou apparie un segment LITTÉRAL — `/cases/{id}` passerait pour `/cases/metrics`"
    assert not apparie("/alerts", "/dashboards" + TROU), "témoin INVERSE : un préfixe littéral qui diffère apparie quand même"
    assert not apparie("/alerts/groups", "/alerts?" + TROU), "témoin INVERSE : une route plus profonde apparie une URL plus courte"
    # (b) la lecture des sites, dans les deux sens
    doit_epingler = [
        ("const d = await api('/alerts?x=1'); render(d.rows);", "corps lié, jamais lu"),
        ("async function f(){ ({ cases } = await api('/cases')); u(cases); }", "réponse déconstruite"),
        # LA CÉCITÉ FERMÉE LE 2026-08-29, ÉCRITE COMME UN TÉMOIN : un site qui NE lit PAS sa cause reste
        # sourd même si un AUTRE site du module lit la sienne sous le MÊME nom. Sans lui, deux mutations
        # sur six passaient.
        ("async function a(){ const r = await api('/alerts'); if (r.error) return bad(r.error); }\n"
         "async function b(){ const r = await api('/cases'); u(r.cases); }", "un nom réutilisé dans une autre portée", 2, 1),
    ]
    for entree in doit_epingler:
        src, quoi = entree[0], entree[1]
        sites_attendus, sourds_attendus = (entree[2], entree[3]) if len(entree) > 2 else (1, 1)
        n, s = sites_sourds_du_module(src, ch)
        assert (n, len(s)) == (sites_attendus, sourds_attendus), "témoin (" + quoi + ") : " + str((n, s))
    doit_ignorer = [
        ("const d = await api('/alerts?x=1'); if (d.error) { bad(d.error); return; } render(d.rows);", "lecture directe"),
        ("function cause(r){ return r.error ? String(r.error) : ''; }\nasync function f(){ const d = await api('/alerts'); const c = cause(d); if (c) return bad(c); }", "lecture par une fonction du module"),
        ("async function f(){ const r = await fetch('/api/query', {}); const j = JSON.parse(await r.text()); u(j.rows); }", "un `fetch` nu : hors population, il ne rend pas un corps"),
        ("async function f(){ const j = await apiSend('/cases', 'POST', b); u(j.id); }", "une MÉTHODE hors population (`POST /api/cases` crée, il n'a pas de portillon)"),
        ("async function f(){ const [sc, tp] = await Promise.all([api('/alerts'), api('/cases')]);\n"
         " if (sc.error) return bad(sc.error); if (tp.error) return bad(tp.error); u(sc.rows); }",
         "un tableau d'attentes DÉCONSTRUIT, dont chaque corps est lié et lu"),
        ("const d = await api('/cases/' + id); u(d.title);", "route HORS population (`/api/cases/{id}` n'a pas de portillon)"),
        ("const s = \"const d = await api('/alerts'); u(d.rows);\";", "la forme fautive écrite dans une CHAÎNE"),
        ("async function a(){ const r = await api('/alerts'); if (r.error) return bad(r.error); }\n"
         "async function b(){ const r = await api('/cases'); if (r.error) return bad(r.error); }", "deux portées qui lisent chacune la leur"),
        ("// const d = await api('/alerts'); u(d.rows);\nconst a = 1;", "la forme fautive écrite dans un COMMENTAIRE"),
    ]
    for src, quoi in doit_ignorer:
        n, s = sites_sourds_du_module(src, ch)
        assert not s, "témoin INVERSE (" + quoi + ") : un site sain est épinglé — " + str(s)
    # (c) l'INSTRUMENT DE LA PORTÉE, dans les deux sens : une déclaration à paramètres est une portée.
    assert len(_portees("function f(a, b) { const x = 1; }")) == 1, "témoin : une déclaration à PARAMÈTRES n'est pas reconnue comme une portée — tout site retomberait sur le module entier"
    assert len(_portees("const g = (a) => { const x = 1; };")) == 1, "témoin : une flèche à accolades n'est pas reconnue comme une portée"
    assert len(_portees("const h = 1;")) == 0, "témoin INVERSE : une portée est vue là où il n'y a pas de fonction"
    # (d) l'instrument se voit lui-même : sans population, aucun site n'est jugé.
    n, s = sites_sourds_du_module("const d = await api('/alerts'); u(d.rows);", [])
    assert n == 0 and not s, "témoin : la lecture juge encore sans population dérivée"


def jambe_b(modules):
    """Rend `(chemins, sites, sourds_par_module, sites_demon)` ou lève le verdict d'un refus de conclure."""
    temoins_de_la_derivation()
    temoins_de_la_jambe_b()
    chemins, fonctions, sites_demon, reste, inconnus = chemins_a_aveu()
    # (i) UNE QUATRIÈME ÉCRITURE EST UN FABRICANT QUE CETTE GARDE NE DÉRIVE PAS. Elle le NOMME et rougit :
    # taire une forme neuve, c'est rendre un vert dont la population a rétréci sans que rien ne le dise.
    if inconnus:
        for nom, ligne, pourquoi in sorted(inconnus):
            print("::error file=daemon/src/handlers/" + nom + ",line=" + str(ligne) + "::" + pourquoi
                  + " — c'est une QUATRIÈME écriture d'aveu, qu'aucune des trois formes de cette garde ne "
                    "dérive. Tant qu'elle n'y entre pas, les routes qu'elle sert sortent de la population "
                    "et aucun site de la console n'est jugé sur elles. Ajouter la forme, ou passer par un "
                    "constructeur qui en emprunte une.")
        print("[" + ETIQUETTE + "] " + str(len(inconnus)) + " écriture(s) d'aveu non dérivée(s).")
        sys.exit(1)
    # (ii) LE RESTE ADMIS EST UN ENSEMBLE NOMMÉ, JUGÉ DANS LES DEUX SENS.
    neuves, perimees = sorted(reste - CORPS_A_CAUSE_SEULE), sorted(CORPS_A_CAUSE_SEULE - reste)
    if neuves or perimees:
        for nom, fn in neuves:
            print("::error file=daemon/src/handlers/" + nom + "::`" + fn + "` sert, en 200, un corps qui "
                  "ne porte QUE `error` — sans forme de succès à imiter, donc hors de la population de "
                  "cette garde. Ce choix ne se fait pas en silence : l'ajouter à `CORPS_A_CAUSE_SEULE`, ou "
                  "lui donner la forme attendue du consommateur pour qu'il entre dans la population.")
        for nom, fn in perimees:
            print("::error file=daemon/src/handlers/" + nom + "::`" + fn + "` est nommée dans "
                  "`CORPS_A_CAUSE_SEULE` et n'y sert plus aucun corps à cause seule : une exemption SANS "
                  "OBJET. La retirer — un reste qu'on n'a pas relu est un reste qu'on ne mesure plus.")
        print("[" + ETIQUETTE + "] reste admis : " + str(len(neuves)) + " entrée(s) neuve(s), "
              + str(len(perimees)) + " sans objet.")
        sys.exit(1)
    if len(chemins) < PLANCHER_CHEMINS_A_AVEU:
        print("::error::" + str(len(chemins)) + " chemin(s) à aveu dérivés du démon (par " + str(len(fonctions))
              + " fonction(s) fabricante(s), " + str(len(sites_demon)) + " site(s)), plancher "
              + str(PLANCHER_CHEMINS_A_AVEU) + " : la dérivation est cassée, la garde refuse de conclure.")
        sys.exit(2)
    total, sourds = 0, {}
    for nom in modules:
        with open(os.path.join(WEB, nom), encoding="utf-8") as fh:
            n, s = sites_sourds_du_module(fh.read(), chemins)
        total += n
        if s:
            sourds[nom] = s
    if total < PLANCHER_SITES_WEB:
        print("::error::" + str(total) + " site(s) de web/ interrogent une route à aveu, plancher "
              + str(PLANCHER_SITES_WEB) + " : la lecture des appels est cassée, la garde refuse de conclure.")
        sys.exit(2)
    return chemins, total, sourds, sites_demon

def main():
    temoins_du_lecteur()        # le dépouilleur partagé, dans les deux sens
    temoins_de_la_lecture()     # la lecture propre à cette garde, dans les deux sens

    if not os.path.isdir(WEB):
        echec(f"{WEB} : dossier introuvable — la découverte est cassée")
    modules = sorted(f for f in os.listdir(WEB) if f.endswith(".js") and f not in HORS_POPULATION)
    if len(modules) < PLANCHER_MODULES:
        print(f"::error::{len(modules)} module(s) découverts sous web/, plancher {PLANCHER_MODULES} : "
              f"la découverte est cassée, la garde refuse de conclure.")
        sys.exit(2)

    aveux, fautes, vues = {}, [], 0
    for nom in modules:
        chemin = os.path.join(WEB, nom)
        with open(chemin, encoding="utf-8") as fh:
            src = fh.read()
        journal = []
        code = depouiller(src, journal)
        if journal:
            aveux[os.path.join("web", nom)] = journal
            continue
        f, v = fautes_du_texte(code)
        vues += v
        for ligne, texte in f:
            fautes.append((f"web/{nom}", ligne, texte))

    if aveux and refuser_sur_aveu(ETIQUETTE, aveux):
        sys.exit(2)
    if vues < PLANCHER_CONDITIONS_D_ECHEC:
        print(f"::error::{vues} condition(s) d'échec lue(s) sur {len(modules)} modules, plancher "
              f"{PLANCHER_CONDITIONS_D_ECHEC} : la lecture est cassée, la garde refuse de conclure.")
        sys.exit(2)

    chemins, sites, sourds, sites_demon = jambe_b(modules)
    regressions = []
    for nom, liste in sorted(sourds.items()):
        if len(liste) > PLAFOND_SOURDS.get(nom, 0):
            regressions.append((nom, liste))
    for nom, liste in regressions:
        for ligne, chemin, pourquoi in liste:
            print(f"::error file=web/{nom},line={ligne}::ce module interroge `{chemin}`, une route qui peut "
                  f"REFUSER en rendant un corps 200 portant sa cause sous `error` — et {pourquoi}. Le corps "
                  f"garde la forme attendue et ses clés de données VIDES : le refus se rendra donc comme une "
                  f"absence ÉTABLIE, c'est-à-dire comme un fait. Lire la cause et la rendre TELLE QUELLE, par "
                  f"un test SÉPARÉ de celui du vide — c'est ce que fait `daRenduDeReponse` dans "
                  f"web/dataaccess.js, et ce que le harnais ESM exige ensuite de la phrase rendue.")
    for fichier, ligne, texte in fautes:
        print(f"::error file={fichier},line={ligne}::une SEULE condition y décide qu'une lecture a "
              f"ÉCHOUÉ et qu'elle est VIDE : `{texte}`. Après elle, la distinction n'existe plus dans "
              f"le programme : un refus du démon, une réponse illisible et un vrai vide rendront la "
              f"MÊME chose — et ce qui sera rendu se lira comme une absence de données, c'est-à-dire "
              f"comme un fait. Séparer les deux tests : d'abord l'échec (rendre la cause TELLE QUELLE "
              f"— celle du démon nomme le plafond franchi et les voies exactes), ensuite le vide.")
    if fautes or regressions:
        if fautes:
            print(f"[{ETIQUETTE}] {len(fautes)} condition(s) fondent un échec et un vide.")
        if regressions:
            print(f"[{ETIQUETTE}] {sum(len(l) for _, l in regressions)} site(s) interrogent une route à "
                  f"portillon sans lire la cause qu'elle sert, au-dessus du plafond de leur module "
                  f"({', '.join(n for n, _ in regressions)}).")
        sys.exit(1)

    restants = sorted((nom, len(liste)) for nom, liste in sourds.items())
    jeu = sorted((nom, plafond - len(sourds.get(nom, [])))
                 for nom, plafond in PLAFOND_SOURDS.items() if plafond > len(sourds.get(nom, [])))
    print(f"[{ETIQUETTE}] JAMBE A — {len(modules)} modules web lus, {vues} conditions d'échec vues, AUCUNE "
          f"ne décide aussi du vide : un refus ne peut plus se rendre comme une absence par cette voie.")
    par_forme = {}
    for _, _, _, forme in sites_demon:
        par_forme[forme] = par_forme.get(forme, 0) + 1
    print(f"[{ETIQUETTE}] JAMBE B — {len(sites_demon)} site(s) d'aveu du démon DÉRIVÉS par leur FORME "
          f"({', '.join(f + ' ' + str(n) for f, n in sorted(par_forme.items()))} ; reste admis, nommé et "
          f"rejugé : {len(CORPS_A_CAUSE_SEULE)} fonction(s) dont le corps ne porte QUE la cause), "
          f"{len(chemins)} chemin(s) routés, {sites} site(s) de web/ les interrogent ; "
          + (f"{sum(n for _, n in restants)} site(s) encore SOURDS, tous sous leur plafond : "
             + ', '.join(f'{n} {c}' for n, c in restants) if restants
             else "aucun site sourd") + ".")
    if jeu:
        print(f"[{ETIQUETTE}] JEU DU CLIQUET : {len(jeu)} plafond(s) au-dessus de leur relevé du jour "
              f"({', '.join(f'{n} +{c}' for n, c in jeu)}) — un cliquet REFUSE une hausse, il ne force pas "
              f"une descente ; le faire descendre au relevé est le seul mouvement qui ne se discute pas.")
    print(f"[{ETIQUETTE}] CE QUE CETTE GARDE NE TIENT PAS : la phrase rendue ensuite (harnais ESM, témoins 16 "
          f"et 92 à 98) — lire la cause et la taire resterait vert ici ; un `.catch()` qui rendrait une "
          f"absence, un gestionnaire de rejet n'étant pas une condition ; les corps servis en 200 qui ne "
          f"portent QUE la cause, sans forme de succès à imiter (le reste NOMMÉ, jugé dans les deux sens) ; "
          f"les appels `fetch` NUS, qui rendent une réponse et non un corps ; et les échecs qui rendent "
          f"encore des corps vides NUS côté démon (`P10.7-e`), qu'aucun consommateur ne peut distinguer "
          f"d'une absence, quelque soin qu'il y mette.")


if __name__ == "__main__":
    main()
