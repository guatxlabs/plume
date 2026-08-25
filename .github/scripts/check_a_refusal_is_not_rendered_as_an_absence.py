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
c'est un REFUS — 422 « refus de rendre un nombre FAUX … » quand la valeur porterait sur un historique
froid tronqué (`daemon/src/cold_store/exactness.rs`), ou 400 « budget dépassé »
(`daemon/src/query_exec.rs`). Le démon disait la vérité dans les deux fenêtres ; la contradiction
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

CE QUE CETTE GARDE NE PROUVE PAS
--------------------------------
Qu'un module qui SÉPARE les deux tests rende ensuite une phrase honnête : séparer la condition rend la
distinction POSSIBLE, il ne la rend pas VRAIE. Cette part-là est tenue par le harnais ESM
(`web_esm_harnais.mjs`, témoin 16), qui exerce la fonction de rendu du panneau sur des réponses
fabriquées et exige trois issues DISTINCTES — un refus qui nomme sa cause sans accuser la collecte,
un vrai vide qui reste une absence, des lignes qui rendent une table — dans les deux sens.
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

    for fichier, ligne, texte in fautes:
        print(f"::error file={fichier},line={ligne}::une SEULE condition y décide qu'une lecture a "
              f"ÉCHOUÉ et qu'elle est VIDE : `{texte}`. Après elle, la distinction n'existe plus dans "
              f"le programme : un refus du démon, une réponse illisible et un vrai vide rendront la "
              f"MÊME chose — et ce qui sera rendu se lira comme une absence de données, c'est-à-dire "
              f"comme un fait. Séparer les deux tests : d'abord l'échec (rendre la cause TELLE QUELLE "
              f"— celle du démon nomme le plafond franchi et les voies exactes), ensuite le vide.")
    if fautes:
        print(f"[{ETIQUETTE}] {len(fautes)} condition(s) fondent un échec et un vide.")
        sys.exit(1)

    print(f"[{ETIQUETTE}] {len(modules)} modules web lus, {vues} conditions d'échec vues, AUCUNE ne "
          f"décide aussi du vide : un refus ne peut plus se rendre comme une absence par cette voie. "
          f"Ce que cette garde NE tient PAS : la phrase rendue ensuite (harnais ESM, témoin 16) et un "
          f"`.catch()` qui rendrait une absence — un gestionnaire de rejet n'est pas une condition.")


if __name__ == "__main__":
    main()
