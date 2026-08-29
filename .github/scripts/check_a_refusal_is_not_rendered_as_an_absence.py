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
La JAMBE B ferme cet angle. Sa population est DÉRIVÉE du démon — les routes qui passent par le point
unique d'aveu, l'indirection comprise — et jamais énumérée ; elle exige que le corps rendu par un tel
appel atteigne une lecture de `error`, DANS LA PORTÉE de l'appel. Voir son en-tête, plus bas, pour ce
qu'elle ne tient pas et pour les deux fautes d'instrument mesurées en l'écrivant.

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
#   (1) les fonctions de `daemon/src/handlers/` qui appellent le point unique d'aveu du portillon
#       (`portillon::corps_de_refus`, posé par `P10.7-c`) ;
#   (2) celles qui les APPELLENT, tant qu'elles ne sont pas routées — sans ce pas, `run_generated_soql`
#       sortirait de l'ensemble et le Pivot avec lui ;
#   (3) l'intersection avec la table de routage : les CHEMINS servis par ces fonctions.
# Puis, côté console : tout appel de `api`/`apiSend`/`fetchInto`/`fetch` dont l'URL peut être l'un de ces
# chemins. Une route qu'on ajoutera demain au point unique entre dans la population sans être nommée ici.
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
#   * les appels `fetch` NUS ne sont pas jugés — ils rendent une réponse, pas un corps (voir plus haut) ;
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
POINT_UNIQUE = "portillon::corps_de_refus"

# LES TROIS APPELS QUI RENDENT UN CORPS, et l'index de l'argument qui porte l'URL + la MÉTHODE (None =
# lue sur l'appel : `apiSend(chemin, methode, corps)`, défaut `POST`). Tous trois préfixent `/api`
# (web/core.js). LE `fetch` NU EST HORS POPULATION, et pas par exemption : il rend une RÉPONSE, pas un
# corps — le corps est analysé plus bas, dans une autre variable, souvent RENDU à l'appelant qui le lira
# (`web/viz.js` le fait trois fois). Le suivre demanderait un flot de données que cette garde ne fait
# pas, et le juger à la portée accuse un relais qui ne consomme rien. Les trois consommateurs de
# `/api/query` par `fetch` nu sont tenus ailleurs : `P11.14-c` pour le panneau d'accès données, et le
# témoin 16 du harnais ESM pour la phrase rendue.
APPELS_WEB = {"api": (0, "GET"), "apiSend": (0, None), "fetchInto": (1, "GET")}

# PLANCHERS DE NON-DÉGÉNÉRESCENCE. Relevé le 2026-08-29 : 13 fonctions du démon passent par le point
# unique, 14 chemins en sortent, et 14 sites de `web/` les interrogent. Sous ces planchers, c'est la
# DÉRIVATION qui est cassée (point unique renommé, table de routage déplacée, appels de la console
# réécrits) et la garde refuse de conclure plutôt que de rendre un vert aveugle.
#
# LE « 20 SITES » QUI ÉTAIT ÉCRIT ICI ÉTAIT FAUX, ET IL L'ÉTAIT DÉJÀ LE JOUR OÙ IL A ÉTÉ ÉCRIT. La garde
# imprimait « 14 site(s) de web/ les interrogent » au MÊME commit où ce commentaire en annonçait 20 : un
# chiffre recopié à la main à côté d'un chiffre dérivé, et c'est toujours le recopié qui vieillit. Il est
# remis à ce que la garde mesure ; la valeur qui fait foi reste celle qu'elle imprime, jamais celle-ci.
PLANCHER_CHEMINS_A_PORTILLON = 8
PLANCHER_SITES_WEB = 10

# PLAFOND DE SITES SOURDS PAR MODULE — un CLIQUET, pas une exemption. Relevé le 2026-08-29 en fermant
# `P10.7-d` : sur les 14 sites dérivés, PLUS AUCUN n'est sourd. La table est donc VIDE, et vide est sa
# forme la plus forte : un module absent est jugé à ZÉRO, donc toute régression, dans n'importe quel
# module de `web/`, est désormais un échec — il n'existe plus une seule case où un site sourd soit toléré.
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


def chemins_a_portillon(racine=None):
    """LES CHEMINS QU'UN REFUS DU PORTILLON PEUT SERVIR — dérivés du démon, jamais énumérés."""
    base = racine or DAEMON
    handlers = os.path.join(base, "handlers")
    if not os.path.isdir(handlers):
        return [], set()
    entete = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)", re.M)
    rend_refus, textes = set(), {}
    for nom in sorted(os.listdir(handlers)):
        if not nom.endswith(".rs"):
            continue
        src = open(os.path.join(handlers, nom), encoding="utf-8").read()
        textes[nom] = src
        debuts = [(m.start(), m.group(1)) for m in entete.finditer(src)]
        for m in re.finditer(re.escape(POINT_UNIQUE) + r"\s*\(", src):
            avant = [f for (p, f) in debuts if p < m.start()]
            if avant:
                rend_refus.add(avant[-1])
    routes = []
    for dossier, _, fichiers in os.walk(base):
        for nom in sorted(fichiers):
            if not nom.endswith(".rs"):
                continue
            src = open(os.path.join(dossier, nom), encoding="utf-8").read()
            for m in re.finditer(r'\.route\(\s*"([^"]+)"\s*,\s*([^\n]+)', src):
                for v, f in re.findall(r"\b(get|post|put|delete|patch)\s*\(\s*([A-Za-z_]\w*)", m.group(2)):
                    routes.append((m.group(1), v.upper(), f))
    routees = {f for _, _, f in routes}
    # (2) l'INDIRECTION : une fonction d'aveu non routée est atteinte par celles qui l'appellent.
    atteintes = set(rend_refus)
    for _ in range(4):
        neuves = set()
        for f in atteintes - routees:
            for nom, src in textes.items():
                debuts = [(m.start(), m.group(1)) for m in entete.finditer(src)]
                for m in re.finditer(r"\b" + re.escape(f) + r"\s*\(", src):
                    avant = [g for (p, g) in debuts if p < m.start()]
                    if avant and avant[-1] != f:
                        neuves.add(avant[-1])
        if neuves <= atteintes:
            break
        atteintes |= neuves
    return sorted({(c, v) for c, v, f in routes if f in atteintes}), rend_refus


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
        if not lie:
            if re.search(r"\{[^{}]*\}\s*=\s*(?:await\s+)?$", amont):
                sourds.append((ligne, vise, "la réponse est DÉCONSTRUITE : le corps n'est pas lié, et l'aveu part avec lui"))
            else:
                sourds.append((ligne, vise, "la réponse n'est liée à aucun nom : rien ne peut en lire la cause"))
            continue
        nom = lie.group(1)
        vu = bool(re.search(r"\b" + re.escape(nom) + r"\s*\.\s*error\b", corps))
        for lecteur in lecteurs:
            if re.search(r"\b" + re.escape(lecteur) + r"\s*\([^;]{0,160}?\b" + re.escape(nom) + r"\b", corps):
                vu = True
        if not vu:
            sourds.append((ligne, vise, "`" + nom + ".error` n'est lu nulle part, et `" + nom + "` n'est passé à aucune fonction qui le lise"))
    return sites, sourds


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
    """Rend `(sites, sourds_par_module)` ou lève le verdict d'un refus de conclure."""
    temoins_de_la_jambe_b()
    chemins, fonctions = chemins_a_portillon()
    if len(chemins) < PLANCHER_CHEMINS_A_PORTILLON:
        print("::error::" + str(len(chemins)) + " chemin(s) à portillon dérivés du démon (par " + str(len(fonctions))
              + " fonction(s) passant par `" + POINT_UNIQUE + "`), plancher " + str(PLANCHER_CHEMINS_A_PORTILLON)
              + " : la dérivation est cassée, la garde refuse de conclure.")
        sys.exit(2)
    total, sourds = 0, {}
    for nom in modules:
        with open(os.path.join(WEB, nom), encoding="utf-8") as fh:
            n, s = sites_sourds_du_module(fh.read(), chemins)
        total += n
        if s:
            sourds[nom] = s
    if total < PLANCHER_SITES_WEB:
        print("::error::" + str(total) + " site(s) de web/ interrogent une route à portillon, plancher "
              + str(PLANCHER_SITES_WEB) + " : la lecture des appels est cassée, la garde refuse de conclure.")
        sys.exit(2)
    return chemins, total, sourds

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

    chemins, sites, sourds = jambe_b(modules)
    regressions = []
    for nom, liste in sorted(sourds.items()):
        if len(liste) > PLAFOND_SOURDS.get(nom, 0):
            regressions.append((nom, liste))
    for nom, liste in regressions:
        for ligne, chemin, pourquoi in liste:
            print(f"::error file=web/{nom},line={ligne}::ce module interroge `{chemin}`, une route qui peut "
                  f"REFUSER en rendant un corps 200 portant sa cause sous `error` (`P10.7-c`, point unique "
                  f"`daemon/src/handlers/portillon.rs`) — et {pourquoi}. Le corps garde la forme attendue et "
                  f"toutes ses clés VIDES : le refus se rendra donc comme une absence ÉTABLIE, c'est-à-dire "
                  f"comme un fait. Lire la cause et la rendre TELLE QUELLE, par un test SÉPARÉ de celui du "
                  f"vide — c'est ce que fait `daRenduDeReponse` dans web/dataaccess.js.")
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
    print(f"[{ETIQUETTE}] JAMBE B — {len(chemins)} chemin(s) à portillon DÉRIVÉS du démon "
          f"({', '.join(v + ' ' + c for c, v in chemins)}), {sites} site(s) de web/ les interrogent ; "
          + (f"{sum(n for _, n in restants)} site(s) encore SOURDS, tous sous leur plafond : "
             + ', '.join(f'{n} {c}' for n, c in restants) if restants
             else "aucun site sourd") + ".")
    if jeu:
        print(f"[{ETIQUETTE}] JEU DU CLIQUET : {len(jeu)} plafond(s) au-dessus de leur relevé du jour "
              f"({', '.join(f'{n} +{c}' for n, c in jeu)}) — un cliquet REFUSE une hausse, il ne force pas "
              f"une descente ; le faire descendre au relevé est le seul mouvement qui ne se discute pas.")
    print(f"[{ETIQUETTE}] CE QUE CETTE GARDE NE TIENT PAS : la phrase rendue ensuite (harnais ESM, témoin 16) "
          f"— lire la cause et la taire resterait vert ici ; un `.catch()` qui rendrait une absence, un "
          f"gestionnaire de rejet n'étant pas une condition ; et les échecs POSTÉRIEURS au portillon, qui "
          f"rendent encore des corps vides NUS côté démon (`P10.7-e`) et qu'aucun consommateur ne peut donc "
          f"distinguer d'une absence, quelque soin qu'il y mette.")


if __name__ == "__main__":
    main()
