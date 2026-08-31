#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`P11.21-k` `P11.21-l` — UN AVEU SE PROUVE LÀ OÙ IL SE VOIT, PAS LÀ OÙ IL EST ÉCRIT.

LE CONSTAT, ET LE HARNAIS LE DÉCLARE LUI-MÊME. Le banc de la console
(`.github/scripts/web_esm_harnais.mjs`) juge le RANG d'un nœud dans le document. Sa
section 0 publie, sur son propre simulacre, que « la mise en page » et « le style
calculé » NE SONT PAS TENUS — et pour le second, que le poids de la limite porte sur
TOUS les sites de `web/*.css`. Conséquence, écrite par le harnais lui-même : « un
masquage, une troncature ou une couleur imposés par la feuille de style sont
invisibles ici — seul l'attribut du document est lu ; la preuve passe alors par un
vrai moteur de rendu ». Ce fichier EST ce moteur.

CE QUI EST EN JEU — QUATRE AVEUX, DANS DEUX VUES. `web/attack.js` (`loadAttackMatrix`)
rend, quand le démon sert une matrice ET en nomme la cause, un AVEU — « couverture
ATT&CK PARTIELLEMENT LUE … » — qu'il pose AVANT la matrice, parce qu'un démenti
rencontré APRÈS le tableau est rencontré après que le lecteur a compté. Et
`techniqueCell` colle un signe « au moins » au SEUL nombre qui est un minorant.

`web/alerts.js` porte les DEUX AVEUX JUMEAUX de la liste d'alertes, et c'est `P11.21-l` :
`bandeauDePageIncomplete` pose « Alertes PARTIELLEMENT LUES … » en TÊTE du corps, avant
la barre et avant les lignes ; et `motDuCompteIncomplet` colle « · LECTURE INCOMPLÈTE :
ce nombre compte les lignes lues, pas celles qui existent » à la FIN de `countLabel`,
dans le MÊME nœud de texte que le nombre — donc juste après le seul nombre que
l'exploitant lise. Le second est le plus fragile des quatre : sa marque est la QUEUE
d'une étiquette posée dans un conteneur en boîte flexible, et un rognage de fin de
ligne la coupe en laissant le NOMBRE parfaitement lisible.

Ces quatre propriétés étaient, avant ce fichier, tenues UNIQUEMENT par le rang dans le
document. Une règle de feuille de style qui masquerait un aveu, le rendrait transparent,
le repousserait hors du document, le ROGNERAIT ou INVERSERAIT sa position peinte les
laisserait VERTES.

MESURÉ LE 2026-08-31, ET C'EST PIRE QUE « TENU PAR LE RANG » POUR LES DEUX AVEUX
D'ALERTES : `.github/scripts/web_esm_harnais.mjs` appelle `dessinerLaListePlate` HUIT
fois (lignes 2980, 2985, 2988, 2999, 3004, 4283, 4285, 5204) et ne lui passe JAMAIS son
cinquième argument (`etat`). La fonction retombe alors
sur `{ cause:'', refus:false, incomplet:false }`, `bandeauDePageIncomplete` rend la
chaîne vide et `motDuCompteIncomplet` n'est appelé nulle part. Aucun banc de ce dépôt
ne fait donc EXISTER ces deux aveux : leur rang n'est tenu que par la lecture de la
source. Ce fichier les fait exister et juge ce qui en est PEINT ; il ne referme pas
l'angle mort du harnais, qui est nommé ici et reste ouvert.

POURQUOI PAS UN SUBSTITUT STATIQUE — LA RAISON EST MESURÉE DANS CE DÉPÔT. Une garde
qui interdirait quelques propriétés de masquage sur un sélecteur serait un PROXY :
verte sur une règle que sa grammaire ne reconnaît pas, et verte sur tout masquage
venu d'un ANCÊTRE. Ce dépôt en porte l'exemple exact — `web/index.html` embarque
`html:not(.app-ready) main { visibility: hidden; }`, une règle INLINE qui masque
TOUTE la surface depuis un ancêtre, sans jamais nommer l'aveu. Aucune grammaire de
sélecteur ne relie ces deux faits ; un moteur de rendu, si.

CE QUE CETTE GARDE FAIT. Elle ne lit AUCUNE propriété CSS. Elle sert la VRAIE
`web/index.html` et la VRAIE `web/style.css` sur une origine HTTP locale — donc avec
les polices, les chemins absolus et la chaîne d'ancêtres de production — y peint DEUX
balisages DÉRIVÉS, l'un de `web/attack.js` et l'autre de `web/alerts.js`, dans leurs
VRAIS hôtes respectifs et dans le MÊME rendu, et demande à un moteur de rendu ce qui
est réellement peint. Sept propriétés jugées ; les quatre premières portent sur la
matrice, les quatre suivantes sur les alertes (la 4 est partagée par les deux vues) :

  1. L'aveu de la matrice n'est ni masqué, ni transparent, ni SANS ENCRE, ni de
     rectangle vide, ni repoussé hors du document — chez lui OU chez n'importe lequel
     de ses ancêtres. « Sans encre » couvre le cas que ni `display`, ni `visibility`,
     ni `opacity`, ni la géométrie ne voient : `color:transparent`, ou une encre
     IDENTIQUE à son fond. Ce n'est PAS un critère de CONTRASTE — aucun rapport WCAG
     n'est imposé ici, et une encre simplement PÂLE passe.
  2. Il est peint AU-DESSUS de la première cellule de données : son bord bas est
     au-dessus du bord haut de la première cellule, en coordonnées PEINTES.
  3. Le signe « au moins » n'est coupé par aucun débordement — le sien, celui de la
     cellule, ou celui d'un ancêtre qui rogne.
  4. `P11.21-l` — L'AVEU DE PAGE INCOMPLÈTE DES ALERTES est peint : mêmes cinq sondes
     que la propriété 1, sur son propre nœud et sur sa propre lignée d'ancêtres.
  5. `P11.21-l` — Il est peint AU-DESSUS DU COMPTE QU'IL QUALIFIE et au-dessus de la
     première ligne de données. C'est la raison écrite dans le module lui-même : il
     doit être lu AVANT le nombre, sans quoi le nombre a déjà été pris pour une
     population.
  6. `P11.21-l` — L'AVEU DU COMPTE INCOMPLET est peint : masquage, encre, rectangle
     PEINT de la seule marque (un `Range` sur la sous-chaîne, pas la boîte de son
     porteur), sortie du document, ET rognage par un débordement — le sien ou celui
     d'un ancêtre. Le rognage est ici le défaut RÉALISTE : la marque est la queue
     d'une étiquette, et la couper laisse le nombre intact et faussement exact.
  7. `P11.21-l` — La marque du compte est peinte AU-DESSUS de la première ligne.
  8. L'INSTRUMENT EST VALIDÉ DANS LES DEUX SENS, ET AVANT TOUT VERDICT : la même
     page, avec une règle INJECTÉE, doit rendre ROUGE ; sans elle, VERTE. Les
     mutations passent par des ANCÊTRES et par des syntaxes qu'aucune grammaire
     écrite ici ne connaît (`@media`, `:has()`), précisément pour prouver que le
     verdict ne vient pas d'une liste de propriétés.
  9. REFUS DE CONCLURE (code 2), JAMAIS UN VERT SILENCIEUX : aucun moteur, aucune
     dérivation, aucun verdict rendu par la page, une mutation NON attrapée — tout
     cela sort en 2, qui est un canal DISTINCT de la propriété violée (code 1).

LE MOTEUR, ICI ET EN INTÉGRATION CONTINUE (mesuré le 2026-08-30). Aucune
installation : `--dump-dom` d'un Chrome/Chromium sans tête suffit, et rend le style
calculé ET la géométrie (mesuré : `display:none` -> rectangle 0x0 ; une boîte de 40px
sur un texte de 224px -> `scrollWidth` 224 > `clientWidth` 40). Un rendu coûte 630 ms.
Le poste porte Google Chrome 151.0.7922.169. TOUS les jobs de `.github/workflows/ci.yml`
tournent sur `ubuntu-24.04` ÉPINGLÉ, dont l'image de coureur publie Google Chrome
151.0.7922.173 installé PAR DÉFAUT (manifeste `actions/runner-images`, lu le
2026-08-30) : la garde n'ajoute donc aucune dépendance à installer, et son refus de
conclure n'est pas un bruit permanent — c'est le canal du jour où le moteur
disparaîtrait de l'image.

CE QUE `P11.21-l` A COÛTÉ, MESURÉ SUR CE POSTE LE 2026-08-31, ET DIT PLUTÔT QUE CACHÉ :
la garde passe de 11 rendus (11,9 s) à 22 rendus (24,7 s puis 24,8 s sur deux passes) —
+108 %, ELLE A DONC PLUS QUE DOUBLÉ. Onze rendus de plus pour onze mutations de plus ;
le coût unitaire monte aussi (1,08 s -> 1,13 s) parce que la page peint désormais deux
panneaux. Ce qui a été évité : peindre les alertes dans un SECOND rendu par mutation
aurait porté le total à 42 rendus. Les deux balisages partagent un rendu parce que les
deux hôtes existent dans la même `index.html` et que toutes les propriétés jugées sont
RELATIVES — un bord contre un autre bord, une lignée contre elle-même.

UNE TROISIÈME FAUTE D'INSTRUMENT ATTRAPÉE PAR UNE MUTATION, ET NON PAR RELECTURE
(2026-08-31, après les deux du 2026-08-30) — ELLE ÉTAIT DÉJÀ LÀ AVANT CETTE CLÉ, DANS LA
DÉRIVATION DE LA MATRICE. Les entrées de dérivation cherchaient `find("function X")`
SANS la parenthèse ouvrante. Un module qui perd la fonction en la RENOMMANT
(`motDuCompteIncomplet` -> `motDuCompteIncompletRenomme`) était encore retrouvé par
simple PRÉFIXE : la garde dérivait la phrase d'une fonction que plus rien n'appelle, et
rendait VERT. C'est très exactement le défaut que ce fichier poursuit — un instrument
vert là où il ne mesure plus rien — écrit dans l'instrument lui-même. Les quatre entrées
(`loadAttackMatrix`, `motDeLaMatriceIncomplete`, `motDeLaPageIncomplete`,
`motDuCompteIncomplet`) exigent désormais la parenthèse, et les quatre renommages
rendent 2.

CE QUE CETTE GARDE NE TIENT PAS — écrit ici plutôt que découvert plus tard :
  · Les balisages peints sont DÉRIVÉS de `web/attack.js` et de `web/alerts.js`, pas
    produits en appelant `loadAttackMatrix` ni `dessinerLaListePlate` (l'un exige un
    démon, l'autre un document complet). Ce qui est jugé est donc la FEUILLE DE
    STYLE et la chaîne d'ancêtres, sur la forme que les modules déclarent émettre. Si
    l'un cesse d'émettre l'une des marques dérivées, la garde REFUSE (code 2) au
    lieu de verdir sur une fiction — mais elle ne remplace pas le harnais ESM, qui
    seul tient que le module produit bien cet arbre-là.
  · ET POUR LES ALERTES, LE HARNAIS NE LE TIENT PAS NON PLUS (mesuré le 2026-08-31) :
    ses huit appels à `dessinerLaListePlate` omettent l'argument `etat`, donc aucun
    banc ne fait exister ces deux aveux. Le complément manquant n'est PAS dans ce
    fichier — il est dans `web_esm_harnais.mjs`, et il reste à écrire.
  · L'ORDRE des nœuds est LU dans la source — `noeuds.push(aveu)` avant
    `noeuds.push(matrix)` pour la matrice ; `const bar = aveu + alertActionBarHtml`
    puis `b.innerHTML = bar + affichees.map(…)` pour les alertes — et rejoué tel
    quel : inverser la source fait rougir la propriété 2 ou la 5. Mais la garde ne
    tient pas ce que ces modules font des AUTRES chemins (refus, lecture entière,
    liste vide, vue groupée, occurrences dépliées).
  · Les panneaux sont RÉVÉLÉS ici comme `showView` les révèle (`section.hidden =
    false`, `html.app-ready`), et les DEUX sont peints dans le MÊME rendu — ce qui
    n'arrive jamais dans la console, où la navigation n'en montre qu'un. Les
    propriétés jugées sont toutes RELATIVES (un bord contre un autre bord, une
    lignée contre elle-même), donc le décalage vertical qui en résulte ne les
    change pas ; mais une règle qui ne se déclencherait QUE lorsqu'un seul panneau
    est ouvert n'est pas vue. Un défaut de la NAVIGATION qui n'ouvrirait jamais l'un
    de ces panneaux n'est pas vu non plus.
  · Un seul gabarit de fenêtre est rendu (1600x1400). Une règle sous `@media` étroite
    qui masquerait un aveu à une AUTRE largeur n'est pas vue. C'est le manque le plus
    net pour la propriété 6 : le rognage d'une étiquette dépend de la largeur, et la
    garde n'en éprouve qu'une.
  · AUCUN TEST DE RECOUVREMENT : un nœud opaque peint PAR-DESSUS un aveu (`z-index`,
    `position`), un `clip-path: inset(100%)`, ou une encre seulement PÂLE, passent.
    La garde interroge l'élément et sa lignée, elle ne fait pas de test de collision.
  · La langue jugée est le FRANÇAIS : les deux phrases d'alertes et celle de la
    matrice sont dérivées de leur branche `LANG !== 'en'`. Une règle qui ne
    masquerait que la branche anglaise — plus longue, donc plus rognable — passerait.
  · UNE VRAIE VIOLATION PEUT SORTIR EN 2 AU LIEU DE 1, ET C'EST MESURÉ (2026-08-31).
    Les mutations sont jouées AVANT tout verdict, et une mutation de RANG (propriétés
    2, 5, 7) devient inattrapable quand la feuille RÉELLE masque déjà son sujet : un
    nœud non peint n'a plus de bord à comparer. Une règle réelle `display:none` sur
    l'aveu de page rend donc 2 — le manquement (4) est bien calculé et IMPRIMÉ dans le
    message de refus, mais le canal est celui de l'instrument aveugle, pas celui de la
    propriété violée. Ce n'est jamais un vert ; c'est un verdict moins précis qu'il ne
    devrait. Les violations qui laissent le nœud PEINT (encre transparente, sortie du
    document, rognage) rendent bien 1, vérifié dans les deux vues.
  · La marque du compte est mesurée par l'UNION des rectangles de son `Range`. Sur une
    étiquette qui RETOURNE À LA LIGNE, cette union est plus large que chaque fragment ;
    au gabarit rendu ici la marque tient sur une ligne (mesuré : 478,1 x 15,0 px), donc
    le cas ne se pose pas — mais il se poserait à une autre largeur, et ce serait dans
    le sens de la FAUSSE ACCUSATION, pas du faux vert.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# LA RACINE SE DÉRIVE DE LA POSITION DE CE FICHIER, JAMAIS D'UN CHEMIN ÉCRIT : un chemin
# de machine d'auteur en dur a déjà coûté une intégration continue rouge (P8.9-k, et la
# garde `check_no_instrument_hardcodes_an_author_machine_path.py` tient cette propriété).
RACINE = Path(__file__).resolve().parents[2]
WEB = RACINE / "web"

CODE_OK, CODE_VIOLATION, CODE_REFUS = 0, 1, 2

# Les noms de binaires cherchés SUR LE CHEMIN, plus une porte d'entrée d'exploitant. Aucun
# chemin absolu écrit : `shutil.which` fait la dérivation.
NOMS_DE_MOTEUR = (
    "google-chrome-stable", "google-chrome", "chromium", "chromium-browser",
    "chrome", "headless_shell",
)
VARIABLE_DE_MOTEUR = "PLUME_NAVIGATEUR"

# Le verdict sort par un NŒUD, pas par un marqueur textuel : `--dump-dom` recrache aussi le
# SOURCE du script, où tout marqueur littéral se retrouverait — et la garde lirait sa propre
# question au lieu de la réponse. Un `<pre id=…>` n'existe QUE si la page l'a peint.
ID_VERDICT = "verdict-p11-21-k"


def refuser(motif: str) -> None:
    """Code 2 — canal DISTINCT d'une propriété violée. Un instrument qui ne mesure pas
    ne rend pas vert : il se tait bruyamment."""
    print(f"::error::(2-refus) {motif}", file=sys.stderr)
    print("REFUS DE CONCLURE — cette garde n'a rien mesuré ; ce n'est PAS un vert.", file=sys.stderr)
    sys.exit(CODE_REFUS)


# =====================================================================================
# 1. LE MOTEUR — DÉRIVÉ, JAMAIS SUPPOSÉ
# =====================================================================================
def trouver_le_moteur() -> str:
    impose = os.environ.get(VARIABLE_DE_MOTEUR, "").strip()
    if impose:
        if not (os.path.isfile(impose) and os.access(impose, os.X_OK)):
            refuser(f"`{VARIABLE_DE_MOTEUR}={impose}` ne désigne aucun exécutable : "
                    "la garde ne se replie pas en silence sur un autre moteur.")
        return impose
    for nom in NOMS_DE_MOTEUR:
        chemin = shutil.which(nom)
        if chemin:
            return chemin
    refuser(
        "AUCUN MOTEUR DE RENDU SANS TÊTE sur le chemin. Cherchés : "
        + ", ".join(NOMS_DE_MOTEUR)
        + f" ; porte d'entrée `{VARIABLE_DE_MOTEUR}=<chemin>`. Cette propriété — un aveu "
        "PEINT là où il est lu — ne se mesure pas sans moteur, et un substitut statique "
        "serait un proxy (aveugle à tout masquage venu d'un ANCÊTRE). L'image de coureur "
        "`ubuntu-24.04` publiait Google Chrome installé par défaut le 2026-08-30 : si ce "
        "refus paraît en intégration continue, c'est l'image qui a changé."
    )
    raise AssertionError("inatteignable")


# =====================================================================================
# 2. LA DÉRIVATION — CE QUE `web/attack.js` DÉCLARE ÉMETTRE
#    Chaque jeton absent fait REFUSER : une garde qui peindrait une forme que le module
#    n'émet plus jugerait une fiction, et son vert serait faux.
# =====================================================================================
def deriver_du_module() -> dict:
    fichier = WEB / "attack.js"
    if not fichier.is_file():
        refuser(f"`{fichier.relative_to(RACINE)}` est introuvable : rien à dériver.")
    src = fichier.read_text(encoding="utf-8")

    def un(motif: str, quoi: str, dans: str = None) -> str:
        m = re.search(motif, dans if dans is not None else src)
        if not m:
            refuser(
                f"la dérivation ne retrouve plus {quoi} dans `web/attack.js` (motif "
                f"`{motif}`) : la forme émise a changé, et peindre l'ancienne jugerait "
                "une fiction."
            )
        return m.group(1)

    # Le corps de `loadAttackMatrix` — l'hôte et l'ordre s'y lisent, et nulle part ailleurs.
    # LA PARENTHÈSE OUVRANTE FAIT PARTIE DU MOTIF, ET C'EST UNE CORRECTION MESURÉE LE 2026-08-31,
    # ATTRAPÉE PAR UNE MUTATION ET NON PAR RELECTURE : sans elle, `find("function X")` retrouve
    # `function XRenomme` par simple PRÉFIXE. Un module qui perd la fonction en la renommant
    # laissait alors la garde VERTE sur une dérivation qui ne correspondait plus à rien
    # d'appelé — un vert là où l'instrument ne mesurait plus, exactement le défaut poursuivi ici.
    i = src.find("async function loadAttackMatrix(")
    if i < 0:
        refuser("`loadAttackMatrix` a disparu de `web/attack.js` : la garde ne sait plus "
                "quel arbre reproduire.")
    corps = src[i:]

    jetons = {
        "hote": un(r"const host = \$\('#([A-Za-z0-9_-]+)'\)", "l'hôte de la matrice", corps),
        "tag_aveu": un(r"const aveu = document\.createElement\('([a-z]+)'\)", "le tag de l'aveu", corps),
        "classe_aveu": un(r"aveu\.className = '([^']+)'", "la classe de l'aveu", corps),
        "classe_matrice": un(r"matrix\.className = '([^']+)'", "la classe de la matrice", corps),
        "classe_colonne": un(r"col\.className = '([^']+)'", "la classe d'une colonne"),
        "classe_entete": un(r"\bh\.className = '([^']+)'", "la classe d'en-tête de colonne"),
        "classe_sous_entete": un(r"sub\.className = '([^']+)'", "la classe de sous-en-tête"),
        "tag_cellule": un(r"const cell = document\.createElement\('([a-z]+)'\)", "le tag d'une cellule"),
        "classe_cellule": un(r"cell\.className = '([^']+)'", "la classe d'une cellule"),
        "classe_compte": un(r"cnt\.className = '([^']+)'", "la classe du compte d'une cellule"),
        "classe_tid": un(r"idEl\.className = '([^']+)'", "la classe de l'identifiant de technique"),
        "classe_nom": un(r"nameEl\.className = '([^']+)'", "la classe du nom de technique"),
        # LE SIGNE « AU MOINS » — la marque de sous-compte, lue là où elle est écrite.
        "signe": un(r"\(minorant \? '([^']+)' : ''\)", "le signe de sous-compte"),
    }

    # LA PHRASE DE L'AVEU, dérivée de la branche FRANÇAISE de `motDeLaMatriceIncomplete` :
    # sa LONGUEUR décide de la hauteur peinte, donc elle ne s'invente pas.
    j = src.find("function motDeLaMatriceIncomplete(")  # la parenthèse : voir plus haut, un préfixe suffisait
    if j < 0:
        refuser("`motDeLaMatriceIncomplete` a disparu : la phrase de l'aveu ne se dérive plus.")
    fonction = src[j: src.find("\n}", j) + 2]
    apres_en = fonction.find("     :")
    branche_fr = fonction[apres_en:] if apres_en > 0 else fonction
    morceaux = re.findall(r'"([^"]*)"', branche_fr)
    if len(morceaux) < 2:
        refuser(
            f"la branche française de `motDeLaMatriceIncomplete` rend {len(morceaux)} "
            "littéral(aux), 2 attendus au moins : la phrase de l'aveu ne se dérive plus, "
            "et une phrase inventée aurait une AUTRE longueur donc une autre hauteur peinte."
        )
    jetons["phrase"] = (
        morceaux[0]
        + "cause FABRIQUÉE par ce banc — aucune lecture réelle"
        + "".join(morceaux[1:])
    )

    # L'ORDRE DES DEUX NŒUDS, LU DANS LA SOURCE ET REJOUÉ TEL QUEL. Inverser la source fait
    # donc rougir la propriété 2 au lieu de passer inaperçu.
    p_aveu = corps.find("noeuds.push(aveu)")
    p_mat = corps.find("noeuds.push(matrix)")
    if p_aveu < 0 or p_mat < 0:
        refuser("l'assemblage `noeuds.push(aveu)` / `noeuds.push(matrix)` n'est plus "
                "reconnaissable dans `loadAttackMatrix` : l'ordre à rejouer ne se dérive plus.")
    jetons["aveu_avant_matrice"] = p_aveu < p_mat
    return jetons


# =====================================================================================
# 2 bis. `P11.21-l` — CE QUE `web/alerts.js` DÉCLARE ÉMETTRE POUR SES DEUX AVEUX JUMEAUX
#    MÊME RÈGLE, SANS EXCEPTION : chaque jeton absent fait REFUSER (code 2). Une garde qui
#    peindrait une forme que le module n'émet plus jugerait une fiction, et son vert serait
#    faux — c'est précisément le défaut que toute cette feuille de route poursuit.
# =====================================================================================
def deriver_des_alertes() -> dict:
    fichier = WEB / "alerts.js"
    if not fichier.is_file():
        refuser(f"`{fichier.relative_to(RACINE)}` est introuvable : rien à dériver.")
    src = fichier.read_text(encoding="utf-8")

    def un(motif: str, quoi: str, groupe: int = 1, dans: str = None) -> str:
        m = re.search(motif, dans if dans is not None else src)
        if not m:
            refuser(
                f"la dérivation ne retrouve plus {quoi} dans `web/alerts.js` (motif "
                f"`{motif}`) : la forme émise a changé, et peindre l'ancienne jugerait "
                "une fiction."
            )
        return m.group(groupe)

    def branche_francaise(nom: str) -> list:
        """Les littéraux de la branche `LANG !== 'en'`. Leur LONGUEUR décide de la largeur
        peinte, donc de ce qu'un rognage coupe : elle ne s'invente pas."""
        # LA PARENTHÈSE OUVRANTE EST OBLIGATOIRE — voir `deriver_du_module` : sans elle, un
        # renommage de la fonction est retrouvé par PRÉFIXE et la garde verdit sur une fiction.
        i = src.find(f"function {nom}(")
        if i < 0:
            refuser(f"`{nom}` a disparu de `web/alerts.js` : la phrase ne se dérive plus.")
        corps_f = src[i: src.find("\n}", i) + 2]
        k = corps_f.find(": quoi +")
        if k < 0:
            k = re.search(r"\n\s*: '", corps_f)
            k = k.start() if k else -1
        if k < 0:
            refuser(f"la branche française de `{nom}` n'est plus reconnaissable : la phrase "
                    "ne se dérive plus, et une phrase inventée aurait une AUTRE longueur.")
        return re.findall(r"""["']([^"']*)["']""", corps_f[k:])

    # L'HÔTE DE LA LISTE — un SÉLECTEUR, pas un identifiant, et c'est ainsi que le module l'écrit.
    hote = un(r"const b = \$\('(#[a-z-]+ \.[a-z-]+)'\); if \(!b\) return;",
              "l'hôte de la liste plate (`$('#… .…')`)")
    section = hote.split()[0]

    # L'AVEU DE PAGE INCOMPLÈTE — son tag et sa classe, lus dans `bandeauDePageIncomplete`.
    tag_aveu = un(r"etat\.incomplet \? '<([a-z]+) class=\"([^\"]+)\">'",
                  "le tag du bandeau de page incomplète", 1)
    classe_aveu = un(r"etat\.incomplet \? '<([a-z]+) class=\"([^\"]+)\">'",
                     "la classe du bandeau de page incomplète", 2)

    # LE MOT « QUOI » EST CELUI DE L'APPELANT DE LA VUE PLATE — pas une invention : la phrase
    # commence par lui, donc il compte dans la largeur peinte.
    quoi = un(r"const aveu = bandeauDePageIncomplete\(LANG === 'en' \? '[^']*' : '([^']*)', etat\)",
              "le mot que la vue plate passe au bandeau")

    lits_page = branche_francaise("motDeLaPageIncomplete")
    if len(lits_page) < 2:
        refuser(f"la branche française de `motDeLaPageIncomplete` rend {len(lits_page)} "
                "littéral(aux), 2 attendus au moins : la phrase de l'aveu ne se dérive plus.")
    phrase_page = (quoi + lits_page[0]
                   + "cause FABRIQUÉE par ce banc — aucune lecture réelle"
                   + "".join(lits_page[1:]))

    lits_compte = branche_francaise("motDuCompteIncomplet")
    if len(lits_compte) < 1:
        refuser("la branche française de `motDuCompteIncomplet` ne rend aucun littéral : la "
                "marque du compte ne se dérive plus, et c'est ELLE que le rognage coupe.")
    phrase_compte = lits_compte[0]

    # LA BARRE, L'EN-TÊTE DU COMPTE, ET LE BLOC D'ACTIONS — lus dans `alertActionBarHtml`.
    classe_barre = un(r"return `<div class=\"([^\"]+)\" role=\"toolbar\"", "la classe de la barre")
    classe_tete = un(r"<div class=\"([^\"]+)\"><span>\$\{esc\(loaded\.countLabel",
                     "la classe de l'en-tête qui porte le compte")
    classe_actions = un(r"<span class=\"([^\"]+)\">\$\{ack\}", "la classe du bloc d'actions")

    # L'ÉTIQUETTE DU COMPTE — sa TÊTE (le nombre et ce qui le suit) et la preuve que la marque
    # d'incomplétude en est la QUEUE. `${etat.incomplet ? motDuCompteIncomplet() : ''}` doit être
    # la DERNIÈRE interpolation avant l'accent grave fermant : c'est cela, « collé au nombre ».
    apres_compte = un(r"countLabel: `\$\{count\}([^$]*)\$\{portee\}", "la tête de l'étiquette du compte")
    if not re.search(r"\$\{etat\.incomplet \? motDuCompteIncomplet\(\) : ''\}`", src):
        refuser("la marque d'incomplétude n'est plus la DERNIÈRE chose de `countLabel` : ce banc "
                "peindrait une queue là où le module en met une autre, et jugerait une fiction.")
    portee_a = un(r"\(m\.scopeAll \? '[^']*' : '([^']*)'\) \+ \(m\.uncased \? '([^']*)'",
                  "la portée en mots (statuts)", 1)
    portee_b = un(r"\(m\.scopeAll \? '[^']*' : '([^']*)'\) \+ \(m\.uncased \? '([^']*)'",
                  "la portée en mots (filtre d'affichage)", 2)

    # LA LIGNE DE DONNÉES — le repère des propriétés 5 et 7.
    classe_ligne = un(r"<div class=\"([a-z]+) (sev-)\$\{a\.severity\}\">", "la classe d'une ligne", 1)
    prefixe_sev = un(r"<div class=\"([a-z]+) (sev-)\$\{a\.severity\}\">", "le préfixe de sévérité", 2)
    classe_sev = un(r"<span class=\"(sev)\">\$\{sev\(a\.severity\)\}</span>", "la pastille de sévérité")
    classe_titre = un(r"<span class=\"(title)\"><span class=\"alertdrill\"", "la classe du titre d'une ligne")
    classe_act = un(r"<span class=\"(alertact)\">\$\{cas\}", "la classe des actions d'une ligne")

    # L'ORDRE, LU DANS LA SOURCE ET REJOUÉ TEL QUEL — jamais SUPPOSÉ. Les deux sens sont
    # reconnus : une source INVERSÉE est rejouée inversée, et fait donc rougir la propriété 5
    # ou la 7 au lieu de faire refuser. Une source qu'aucun des deux sens ne décrit, elle,
    # fait REFUSER : l'ordre ne se dérive plus, et le supposer serait juger une fiction.
    if re.search(r"const bar = aveu \+ alertActionBarHtml\(", src):
        aveu_avant_barre = True
    elif re.search(r"const bar = alertActionBarHtml\([^;]*\) \+ aveu", src):
        aveu_avant_barre = False
    else:
        refuser("l'assemblage `const bar = aveu + alertActionBarHtml(…)` n'est plus "
                "reconnaissable dans `dessinerLaListePlate`, dans AUCUN des deux sens : le rang "
                "de l'aveu de page incomplète ne se dérive plus.")
    if re.search(r"b\.innerHTML = bar \+ affichees\.map\(", src):
        barre_avant_lignes = True
    elif re.search(r"b\.innerHTML = affichees\.map\([^;]*\) \+ bar", src):
        barre_avant_lignes = False
    else:
        refuser("l'assemblage `b.innerHTML = bar + affichees.map(…)` n'est plus reconnaissable "
                "dans `dessinerLaListePlate`, dans AUCUN des deux sens : le rang des deux aveux "
                "par rapport aux LIGNES qu'ils commentent ne se dérive plus.")

    return {
        "hote": hote, "section": section,
        "tag_aveu": tag_aveu, "classe_aveu": classe_aveu, "phrase_page": phrase_page,
        "phrase_compte": phrase_compte,
        "classe_barre": classe_barre, "classe_tete": classe_tete, "classe_actions": classe_actions,
        # Le NOMBRE est fabriqué ; la FORME qui l'entoure est dérivée. C'est la forme qui décide
        # de la largeur peinte, donc de ce qu'un rognage de fin de ligne emporte.
        "compte": "49" + apres_compte + portee_a + portee_b,
        "classe_ligne": classe_ligne, "prefixe_sev": prefixe_sev,
        "classe_sev": classe_sev, "classe_titre": classe_titre, "classe_act": classe_act,
        "aveu_avant_barre": aveu_avant_barre, "barre_avant_lignes": barre_avant_lignes,
    }


# =====================================================================================
# 3. LA PAGE FABRIQUÉE — la VRAIE `index.html`, la VRAIE `style.css`, un balisage DÉRIVÉ
# =====================================================================================
def batir_la_page(j: dict, ja: dict) -> str:
    gabarit = (WEB / "index.html").read_text(encoding="utf-8")
    if "</head>" not in gabarit or "</body>" not in gabarit:
        refuser("`web/index.html` n'a plus de `</head>` ou de `</body>` : la page fabriquée "
                "ne peut pas être assemblée sans deviner.")

    # Les scripts partent TOUS : aucun module ne peut se lier sans démon, et le script
    # inline de repli (6 s) révélerait une bannière d'échec qui n'a rien à faire ici.
    sans_scripts, retires = re.subn(r"<script\b[^>]*>.*?</script>", "", gabarit, flags=re.S)
    if retires == 0:
        refuser("aucun `<script>` retiré de `web/index.html` : la page a changé de forme, "
                "et la laisser s'exécuter ferait juger autre chose que ce qui est peint ici.")

    # La feuille de MUTATION est chargée en DERNIER : elle gagne les égalités de cascade
    # sans `!important`, exactement comme une règle ajoutée à la fin de `style.css`.
    tete = sans_scripts.replace(
        "</head>", '<link rel="stylesheet" href="/__mutation__.css">\n</head>', 1
    )

    donnees = {
        "hote": j["hote"],
        "tagAveu": j["tag_aveu"], "classeAveu": j["classe_aveu"], "phrase": j["phrase"],
        "classeMatrice": j["classe_matrice"], "classeColonne": j["classe_colonne"],
        "classeEntete": j["classe_entete"], "classeSousEntete": j["classe_sous_entete"],
        "tagCellule": j["tag_cellule"], "classeCellule": j["classe_cellule"],
        "classeCompte": j["classe_compte"], "classeTid": j["classe_tid"],
        "classeNom": j["classe_nom"], "signe": j["signe"],
        "aveuAvantMatrice": j["aveu_avant_matrice"],
        "idVerdict": ID_VERDICT,
        # `P11.21-l` — LA VUE DES ALERTES, DÉRIVÉE DE `web/alerts.js`. Peinte dans le MÊME rendu
        # que la matrice : les deux hôtes existent dans la vraie `index.html`, chacun avec sa
        # propre lignée d'ancêtres, et les propriétés jugées sont toutes RELATIVES — un bord
        # contre un autre bord — donc le décalage vertical que cela produit ne les change pas.
        # Le prix évité est un rendu de plus par mutation, soit la moitié du coût de la garde.
        "al": {
            "hote": ja["hote"], "section": ja["section"],
            "tagAveu": ja["tag_aveu"], "classeAveu": ja["classe_aveu"],
            "phrasePage": ja["phrase_page"], "phraseCompte": ja["phrase_compte"],
            "classeBarre": ja["classe_barre"], "classeTete": ja["classe_tete"],
            "classeActions": ja["classe_actions"], "compte": ja["compte"],
            "classeLigne": ja["classe_ligne"], "prefixeSev": ja["prefixe_sev"],
            "classeSev": ja["classe_sev"], "classeTitre": ja["classe_titre"],
            "classeAct": ja["classe_act"],
            "aveuAvantBarre": ja["aveu_avant_barre"],
            "barreAvantLignes": ja["barre_avant_lignes"],
        },
    }

    script = """
<script>
(async function () {
  const D = __DONNEES__;
  const sortir = (o) => {
    const pre = document.createElement('pre');
    pre.id = D.idVerdict;
    pre.textContent = JSON.stringify(o);
    document.body.appendChild(pre);
  };
  try {
    // — LA SURFACE EST RÉVÉLÉE COMME `showView` LA RÉVÈLE, pas autrement : `app-ready` sur
    //   la racine (sans quoi la règle INLINE `html:not(.app-ready) main{visibility:hidden}`
    //   masque TOUT depuis un ancêtre), puis `hidden = false` sur la seule section visée.
    document.documentElement.classList.add('app-ready');
    const hote = document.getElementById(D.hote);
    if (!hote) return sortir({ refus: 'hote-absent', hote: D.hote });
    for (let n = hote; n && n !== document.body; n = n.parentNode) {
      if (n.nodeType === 1 && n.hidden) n.hidden = false;
    }

    // — LE BALISAGE DÉRIVÉ. Données FABRIQUÉES : aucune lecture du dépôt, aucun démon.
    const aveu = document.createElement(D.tagAveu);
    aveu.className = D.classeAveu;
    aveu.textContent = D.phrase;

    const matrice = document.createElement('div');
    matrice.className = D.classeMatrice;
    const TACTIQUES = [
      { nom: 'Initial Access', techniques: [
          { tid: 'T1190', nom: 'Exploit Public-Facing Application', r: 12, a: 4821 },
          { tid: 'T1078', nom: 'Valid Accounts', r: 3, a: 97 } ] },
      { nom: 'Credential Access', techniques: [
          { tid: 'T1110.003', nom: 'Brute Force: Password Spraying', r: 7, a: 128 } ] },
      { nom: 'Persistence', techniques: [
          { tid: 'T1053.005', nom: 'Scheduled Task/Job: Scheduled Task', r: 2, a: 6 } ] },
    ];
    for (const tac of TACTIQUES) {
      const col = document.createElement('div'); col.className = D.classeColonne;
      const h = document.createElement('div'); h.className = D.classeEntete;
      h.textContent = tac.nom;
      const sub = document.createElement('span'); sub.className = D.classeSousEntete;
      sub.textContent = tac.techniques.length + ' / ' + tac.techniques.length + ' couverte(s)';
      h.appendChild(sub); col.appendChild(h);
      for (const t of tac.techniques) {
        const cell = document.createElement(D.tagCellule);
        cell.type = 'button';
        cell.className = D.classeCellule;
        const cnt = document.createElement('span'); cnt.className = D.classeCompte;
        // LE SIGNE EST DANS CE NŒUD, ET SEULEMENT DANS CELUI-CI.
        cnt.textContent = t.r + 'r/' + D.signe + t.a + 'a';
        const idEl = document.createElement('span'); idEl.className = D.classeTid;
        idEl.textContent = t.tid;
        const nameEl = document.createElement('span'); nameEl.className = D.classeNom;
        nameEl.textContent = t.nom;
        cell.append(cnt, idEl, nameEl);
        col.appendChild(cell);
      }
      matrice.appendChild(col);
    }
    const noeuds = D.aveuAvantMatrice ? [aveu, matrice] : [matrice, aveu];
    hote.replaceChildren.apply(hote, noeuds);

    // ================================================================================
    // `P11.21-l` — LA VUE DES ALERTES ET SES DEUX AVEUX JUMEAUX, DÉRIVÉS DE `alerts.js`.
    // ================================================================================
    const A = D.al;
    const corpsAlertes = document.querySelector(A.hote);
    if (!corpsAlertes) return sortir({ refus: 'hote-alertes-absent', hote: A.hote });
    for (let n = corpsAlertes; n && n !== document.body; n = n.parentNode) {
      if (n.nodeType === 1 && n.hidden) n.hidden = false;
    }

    // PREMIER AVEU : la page incomplète, un bandeau posé en tête du corps.
    const aveuPage = document.createElement(A.tagAveu);
    aveuPage.className = A.classeAveu;
    aveuPage.textContent = A.phrasePage;

    // La barre d'outils — elle n'est pas jugée, elle est peinte parce qu'elle SÉPARE l'aveu
    // du compte : la retirer rapprocherait les deux bords que la propriété 5 compare.
    const barre = document.createElement('div');
    barre.className = A.classeBarre;
    barre.setAttribute('role', 'toolbar');
    const motBarre = document.createElement('span');
    motBarre.className = 'muted';
    motBarre.textContent = 'Tri · Portée · Affiche';
    barre.appendChild(motBarre);

    // SECOND AVEU : la marque du compte incomplet, COLLÉE au nombre dans le MÊME nœud de
    // texte — c'est ce que `countLabel` compose, et c'est exactement ce qu'un rognage de fin
    // de ligne coupe en laissant le nombre parfaitement lisible.
    const tete = document.createElement('div');
    tete.className = A.classeTete;
    const etiquette = document.createElement('span');
    etiquette.textContent = A.compte + A.phraseCompte;
    const actions = document.createElement('span');
    actions.className = A.classeActions;
    const boutonAck = document.createElement('button');
    boutonAck.type = 'button';
    boutonAck.className = 'btn btn-sm';
    boutonAck.textContent = 'Tout acquitter';
    actions.appendChild(boutonAck);
    tete.append(etiquette, actions);

    // LES LIGNES DE DONNÉES — le repère des propriétés 5 et 7. Données FABRIQUÉES.
    const LIGNES = [
      { sev: '1', mot: 'CRIT', titre: 'Pulvérisation de mots de passe FABRIQUÉE par ce banc', ts: '2026-08-31 04:11:07' },
      { sev: '2', mot: 'HAUT', titre: 'Exploitation d\\u2019une application exposée (banc)', ts: '2026-08-31 03:58:42' },
      { sev: '3', mot: 'MOY', titre: 'Tâche planifiée créée (banc)', ts: '2026-08-31 03:40:19' },
    ];
    const lignes = LIGNES.map((l) => {
      const row = document.createElement('div');
      row.className = A.classeLigne + ' ' + A.prefixeSev + l.sev;
      const s = document.createElement('span'); s.className = A.classeSev; s.textContent = l.mot;
      const t = document.createElement('span'); t.className = A.classeTitre; t.textContent = l.titre;
      const h = document.createElement('time'); h.textContent = l.ts;
      const ac = document.createElement('span'); ac.className = A.classeAct;
      const b2 = document.createElement('button'); b2.type = 'button'; b2.textContent = 'Acquitter';
      ac.appendChild(b2);
      row.append(s, t, h, ac);
      return row;
    });

    // L'ORDRE EST CELUI QUI A ÉTÉ LU DANS LA SOURCE, rejoué tel quel dans les deux sens.
    const bloc = A.aveuAvantBarre ? [aveuPage, barre, tete] : [barre, tete, aveuPage];
    const suite = A.barreAvantLignes ? bloc.concat(lignes) : lignes.concat(bloc);
    corpsAlertes.replaceChildren.apply(corpsAlertes, suite);

    // — LES POLICES DÉCIDENT DES MÉTRIQUES : mesurer avant leur chargement mesurerait une
    //   AUTRE page (le repli n'a pas les mêmes chasses, et la propriété 3 se joue au pixel).
    //   MESURÉ le 2026-08-30, et c'est la raison pour laquelle il n'y a AUCUNE attente de
    //   trame ici : sous `--dump-dom`, le moteur ne produit pas de trame et un
    //   `requestAnimationFrame` n'est JAMAIS rappelé — un banc qui l'attendrait n'écrirait
    //   jamais son verdict. `document.fonts.ready`, lui, se résout. Et la géométrie n'a pas
    //   besoin de trame : `getBoundingClientRect` force la mise en page SYNCHRONE, ce qu'un
    //   témoin fabriqué a vérifié (boîte de 40px sur un texte de 224px -> 224 > 40).
    if (document.fonts && document.fonts.ready) { try { await document.fonts.ready; } catch (e) {} }

    // ---- LES OUTILS DE MESURE. Aucune propriété n'est LUE d'une feuille : tout est
    //      demandé au moteur, sur l'élément ET sur ses ancêtres.
    const nommer = (n) => n.tagName.toLowerCase()
      + (n.id ? '#' + n.id : '')
      + (n.className && typeof n.className === 'string' ? '.' + n.className.trim().split(/\\s+/).join('.') : '');
    const masquePar = (el) => {
      for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
        const cs = getComputedStyle(n);
        if (cs.display === 'none') return 'display:none sur ' + nommer(n);
        if (cs.visibility === 'hidden' || cs.visibility === 'collapse') return 'visibility:' + cs.visibility + ' sur ' + nommer(n);
        const o = parseFloat(cs.opacity);
        if (!isNaN(o) && o < 0.05) return 'opacity:' + cs.opacity + ' sur ' + nommer(n);
        if (cs.contentVisibility === 'hidden') return 'content-visibility:hidden sur ' + nommer(n);
      }
      return null;
    };
    // L'ENCRE, ET NON LA SEULE OPACITÉ. `opacity:0` est vu plus haut ; `color:transparent` ne
    // l'est PAS — le nœud reste opaque, de rectangle plein, et ne peint AUCUN glyphe. La sonde
    // lit la couleur calculée du texte et le premier fond NON transparent de la lignée : encre
    // sans alpha, ou encre IDENTIQUE à son fond, = rien de peint. Ce n'est PAS un critère de
    // contraste (aucun rapport WCAG n'est imposé ici) : c'est le cas dégénéré, et lui seul.
    const alpha = (c) => { const m = /rgba?\\(([^)]+)\\)/.exec(c || ''); if (!m) return 1;
      const v = m[1].split(',').map((x) => parseFloat(x)); return v.length > 3 ? v[3] : 1; };
    const fondDe = (el) => {
      for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
        const b = getComputedStyle(n).backgroundColor;
        if (b && alpha(b) > 0.05) return b;
      }
      return 'rgb(255, 255, 255)';
    };
    const encreInvisible = (el) => {
      const c = getComputedStyle(el).color, f = fondDe(el);
      if (alpha(c) < 0.05) return 'encre transparente (' + c + ') : le nœud est opaque et ne peint aucun glyphe';
      if (c === f) return 'encre IDENTIQUE au fond (' + c + ') : la phrase est peinte, et illisible';
      return null;
    };
    const boite = (el) => { const r = el.getBoundingClientRect();
      return { g: r.left, d: r.right, h: r.top, b: r.bottom, l: r.width, ht: r.height }; };
    // Rectangle PEINT du signe lui-même, pas de son porteur : un `Range` sur le seul
    // caractère. Sans cela, un signe rogné dans une boîte large passerait.
    const boiteDuSigne = (porteur, signe) => {
      const t = porteur.firstChild;
      if (!t || t.nodeType !== 3) return null;
      const i = t.data.indexOf(signe);
      if (i < 0) return null;
      const rg = document.createRange();
      rg.setStart(t, i); rg.setEnd(t, i + signe.length);
      const r = rg.getBoundingClientRect();
      return { g: r.left, d: r.right, h: r.top, b: r.bottom, l: r.width, ht: r.height };
    };
    // Le premier nœud qui ROGNE et qui coupe la boîte donnée. `clientTop/Left/Width/Height`
    // = la boîte de rembourrage, qui est exactement ce que `overflow` rogne.
    // LA MARCHE PART DU PORTEUR LUI-MÊME, PAS DE SON PARENT, et c'est une correction
    // MESURÉE : partant du parent, la mutation « marque coupée par son propre débordement »
    // — la formulation même de la clé — passait au VERT, parce que le rognage se produit sur
    // `.attack-cnt` en personne. L'instrument était aveugle au défaut qu'il nomme.
    const rogneur = (el, bt) => {
      for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
        const cs = getComputedStyle(n);
        const rx = cs.overflowX, ry = cs.overflowY;
        if (rx === 'visible' && ry === 'visible') continue;
        const rr = n.getBoundingClientRect();
        const cg = rr.left + n.clientLeft, ch = rr.top + n.clientTop;
        const cd = cg + n.clientWidth, cb = ch + n.clientHeight;
        const deborde = (rx !== 'visible' && (bt.g < cg - 0.5 || bt.d > cd + 0.5))
                     || (ry !== 'visible' && (bt.h < ch - 0.5 || bt.b > cb + 0.5));
        if (deborde) return { par: nommer(n), overflow: rx + '/' + ry,
          clip: { g: cg, d: cd, h: ch, b: cb }, coupe: bt };
      }
      return null;
    };

    const porteur = matrice.querySelector('.' + D.classeCompte.trim().split(/\\s+/).join('.'));
    const premiereCellule = matrice.querySelector(D.tagCellule + '.' + D.classeCellule.trim().split(/\\s+/).join('.'));

    sortir({
      refus: null,
      aveu: {
        masque: masquePar(aveu),
        encre: encreInvisible(aveu),
        boite: boite(aveu),
        texte: (aveu.textContent || '').trim().length,
        // Le DOCUMENT, pas la fenêtre : « repoussé hors de l'écran » se lit en
        // coordonnées de document (un `left:-9999px` sort du document, pas seulement du cadre).
        docG: aveu.getBoundingClientRect().left + window.scrollX,
        docH: aveu.getBoundingClientRect().top + window.scrollY,
        docL: document.documentElement.scrollWidth,
      },
      premiereCellule: premiereCellule ? boite(premiereCellule) : null,
      signe: {
        present: !!porteur && (porteur.textContent || '').indexOf(D.signe) >= 0,
        masque: porteur ? masquePar(porteur) : 'porteur-absent',
        boite: porteur ? boiteDuSigne(porteur, D.signe) : null,
        coupe: porteur && boiteDuSigne(porteur, D.signe)
          ? rogneur(porteur, boiteDuSigne(porteur, D.signe)) : null,
      },
      // `P11.21-l` — LES DEUX AVEUX JUMEAUX DES ALERTES, mesurés par les MÊMES sondes.
      alertes: {
        aveuPage: {
          masque: masquePar(aveuPage),
          encre: encreInvisible(aveuPage),
          boite: boite(aveuPage),
          texte: (aveuPage.textContent || '').trim().length,
          docG: aveuPage.getBoundingClientRect().left + window.scrollX,
          docH: aveuPage.getBoundingClientRect().top + window.scrollY,
        },
        // Le repère : l'en-tête qui porte le compte, et la première ligne de données.
        tete: boite(tete),
        premiereLigne: lignes.length ? boite(lignes[0]) : null,
        compte: (function () {
          const b = boiteDuSigne(etiquette, A.phraseCompte);
          return {
            present: (etiquette.textContent || '').indexOf(A.phraseCompte) >= 0,
            colleAuNombre: (etiquette.textContent || '').indexOf(A.compte) === 0
              && (etiquette.textContent || '').indexOf(A.phraseCompte) === A.compte.length,
            masque: masquePar(etiquette),
            encre: encreInvisible(etiquette),
            boite: b,
            docG: b ? b.g + window.scrollX : null,
            docH: b ? b.h + window.scrollY : null,
            coupe: b ? rogneur(etiquette, b) : null,
          };
        })(),
      },
    });
  } catch (e) {
    sortir({ refus: 'exception', message: String((e && e.stack) || e) });
  }
})();
</script>
"""
    script = script.replace("__DONNEES__", json.dumps(donnees, ensure_ascii=False))
    return tete.replace("</body>", script + "\n</body>", 1)


# =====================================================================================
# 4. L'ORIGINE HTTP LOCALE — la page est servie DEPUIS `web/`, donc `/style.css`,
#    `/fonts/*.woff2` et tout chemin absolu résolvent comme en production. Sous `file://`
#    ils ne résoudraient pas, les polices tomberaient sur un repli, et les métriques
#    mesurées seraient celles d'une AUTRE page — ce qui fait toute la propriété 3.
# =====================================================================================
class Serveur(SimpleHTTPRequestHandler):
    pages = {}

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        chemin = self.path.split("?", 1)[0]
        if chemin in self.pages:
            corps, mime = self.pages[chemin]
            octets = corps.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(octets)))
            self.end_headers()
            self.wfile.write(octets)
            return
        super().do_GET()


def rendre(moteur: str, page: str, mutation: str) -> dict:
    """Sert la page, la rend, et rapporte ce que le MOTEUR a peint. Tout ce qui n'est pas
    un verdict complet est un REFUS, jamais un vert."""
    Serveur.pages = {"/__banc__.html": (page, "text/html"),
                     "/__mutation__.css": (mutation, "text/css")}
    fabrique = partial(Serveur, directory=str(WEB))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), fabrique)
    port = httpd.server_address[1]
    fil = threading.Thread(target=httpd.serve_forever, daemon=True)
    fil.start()
    try:
        with tempfile.TemporaryDirectory(prefix="banc-p11-21-k-") as profil:
            try:
                r = subprocess.run(
                    [moteur, "--headless", "--no-sandbox", "--disable-gpu",
                     "--disable-dev-shm-usage", "--hide-scrollbars",
                     "--force-device-scale-factor=1", "--window-size=1600,1400",
                     "--virtual-time-budget=15000", f"--user-data-dir={profil}",
                     "--dump-dom", f"http://127.0.0.1:{port}/__banc__.html"],
                    capture_output=True, text=True, timeout=180,
                )
            except FileNotFoundError:
                refuser(f"le moteur `{moteur}` a disparu entre sa découverte et son appel.")
            except subprocess.TimeoutExpired:
                refuser(f"le moteur `{moteur}` n'a pas rendu la page en 180 s : rien n'a été "
                        "mesuré, et un vert ici serait un mensonge.")
    finally:
        httpd.shutdown()
        httpd.server_close()

    dom = r.stdout or ""
    trouve = re.search(rf'<pre id="{ID_VERDICT}">([\s\S]*?)</pre>', dom)
    if not trouve:
        refuser(
            f"le moteur `{moteur}` n'a rendu AUCUN verdict (code {r.returncode}, "
            f"{len(dom)} octets de DOM) : le nœud `#{ID_VERDICT}` est absent, donc la page "
            "n'a pas exécuté sa mesure. Il n'y a rien à conclure, ni rouge ni vert."
            "\n--- stderr ---\n" + (r.stderr or "")[-2000:]
        )
    brut = trouve.group(1)
    # Le DOM sort échappé : le verdict est un texte de nœud.
    brut = (brut.replace("&quot;", '"').replace("&lt;", "<")
                .replace("&gt;", ">").replace("&amp;", "&"))
    try:
        return json.loads(brut)
    except json.JSONDecodeError as e:
        refuser(f"le verdict rendu par la page n'est pas lisible ({e}) : {brut[:400]!r}")
    raise AssertionError("inatteignable")


# =====================================================================================
# 5. LES CINQ PROPRIÉTÉS, LUES SUR CE QUE LE MOTEUR A PEINT
# =====================================================================================
def juger(v: dict) -> list:
    """Rend la liste des manquements. Une liste VIDE est un vert ; un verdict que la page
    n'a pas su rendre est un REFUS, pas un vert."""
    if v.get("refus"):
        refuser(f"la page a refusé de se mesurer : {v.get('refus')} "
                f"{v.get('message', '') or v.get('hote', '')}")
    manques = []

    a = v["aveu"]
    if a["masque"]:
        manques.append(f"(1) L'AVEU N'EST PAS PEINT : {a['masque']}. Le nœud est pourtant "
                       "dans le document — c'est exactement ce qu'un verdict de RANG laisse passer.")
    if a["encre"]:
        manques.append(f"(1) L'AVEU EST PEINT SANS ENCRE VISIBLE : {a['encre']}. Le rectangle "
                       "est plein, le nœud est opaque, et il n'y a rien à lire.")
    if a["texte"] == 0:
        manques.append("(1) l'aveu ne porte AUCUN texte : un rectangle sans phrase n'avoue rien.")
    if a["boite"]["l"] <= 0 or a["boite"]["ht"] <= 0:
        manques.append(f"(1) l'aveu est de rectangle VIDE ({a['boite']['l']}x{a['boite']['ht']}) : "
                       "il occupe zéro pixel, donc il ne se lit pas.")
    if a["docG"] + a["boite"]["l"] <= 0 or a["docH"] + a["boite"]["ht"] <= 0:
        manques.append(f"(1) l'aveu est REPOUSSÉ hors du document (coin {a['docG']}, {a['docH']}) : "
                       "présent dans l'arbre, absent de l'écran.")

    c = v["premiereCellule"]
    if c is None:
        refuser("aucune cellule de données n'a été peinte : la propriété 2 (« au-dessus de "
                "la première ligne ») n'a pas de repère, et la garde ne devine pas.")
    elif a["boite"]["b"] > c["h"] + 0.5:
        manques.append(
            f"(2) L'AVEU N'EST PAS PEINT AU-DESSUS de la première cellule : son bord bas est "
            f"à y={a['boite']['b']:.1f}, le bord haut de la cellule à y={c['h']:.1f}. Le RANG "
            "dans le document ne dit rien de la position peinte, et c'est ce défaut-là."
        )

    s = v["signe"]
    if not s["present"]:
        refuser("le signe de sous-compte n'a pas été peint dans la cellule fabriquée : "
                "la propriété 3 n'a pas de sujet.")
    if s["masque"]:
        manques.append(f"(3) la marque de sous-compte n'est pas peinte : {s['masque']}.")
    elif s["boite"] is None or s["boite"]["l"] <= 0:
        manques.append("(3) la marque de sous-compte a un rectangle peint VIDE : le nombre "
                       "se lit alors comme un compte, pas comme un minorant.")
    elif s["coupe"]:
        d = s["coupe"]
        manques.append(
            f"(3) LA MARQUE EST COUPÉE par un débordement : rognée par `{d['par']}` "
            f"(overflow {d['overflow']}), clip x[{d['clip']['g']:.1f}..{d['clip']['d']:.1f}] "
            f"y[{d['clip']['h']:.1f}..{d['clip']['b']:.1f}], marque "
            f"x[{d['coupe']['g']:.1f}..{d['coupe']['d']:.1f}] "
            f"y[{d['coupe']['h']:.1f}..{d['coupe']['b']:.1f}]. Un « ≥ » à moitié rogné rend "
            "le nombre PIRE que sans marque : il paraît exact."
        )

    # =================================================================================
    # `P11.21-l` — LES DEUX AVEUX JUMEAUX DE LA VUE DES ALERTES (propriétés 4 à 7)
    # =================================================================================
    al = v.get("alertes")
    if al is None:
        refuser("la page n'a rendu aucune mesure pour la vue des alertes : les propriétés 4 à 7 "
                "n'ont pas de sujet, et un vert sans elles serait un vert sur rien.")
    ligne = al["premiereLigne"]
    if ligne is None:
        refuser("aucune ligne d'alerte n'a été peinte : les propriétés 5 et 7 (« au-dessus de la "
                "première ligne ») n'ont pas de repère, et la garde ne devine pas.")

    # --- (4) L'AVEU DE PAGE INCOMPLÈTE EST-IL PEINT ? Mêmes cinq sondes que la propriété 1.
    p = al["aveuPage"]
    if p["masque"]:
        manques.append(f"(4) L'AVEU DE PAGE INCOMPLÈTE DES ALERTES N'EST PAS PEINT : {p['masque']}. "
                       "Le nœud est pourtant en tête du corps — c'est exactement ce qu'un verdict "
                       "de RANG laisse passer.")
    if p["encre"]:
        manques.append(f"(4) L'AVEU DE PAGE INCOMPLÈTE EST PEINT SANS ENCRE VISIBLE : {p['encre']}. "
                       "Le rectangle est plein, le nœud est opaque, et il n'y a rien à lire.")
    if p["texte"] == 0:
        manques.append("(4) l'aveu de page incomplète ne porte AUCUN texte : un rectangle sans "
                       "phrase n'avoue rien.")
    if p["boite"]["l"] <= 0 or p["boite"]["ht"] <= 0:
        manques.append(f"(4) l'aveu de page incomplète est de rectangle VIDE "
                       f"({p['boite']['l']}x{p['boite']['ht']}) : il occupe zéro pixel.")
    if p["docG"] + p["boite"]["l"] <= 0 or p["docH"] + p["boite"]["ht"] <= 0:
        manques.append(f"(4) l'aveu de page incomplète est REPOUSSÉ hors du document (coin "
                       f"{p['docG']}, {p['docH']}) : présent dans l'arbre, absent de l'écran.")

    # --- (5) EST-IL PEINT AVANT CE QU'IL QUALIFIE ? Le module écrit lui-même sa raison : il doit
    #     être lu AVANT le compte, sans quoi le nombre a déjà été pris pour une population.
    t = al["tete"]
    if p["boite"]["b"] > t["h"] + 0.5:
        manques.append(
            f"(5) L'AVEU DE PAGE INCOMPLÈTE N'EST PAS PEINT AU-DESSUS DU COMPTE QU'IL QUALIFIE : "
            f"son bord bas est à y={p['boite']['b']:.1f}, le bord haut de l'en-tête du compte à "
            f"y={t['h']:.1f}. Le RANG dans le document ne dit rien de la position peinte."
        )
    if p["boite"]["b"] > ligne["h"] + 0.5:
        manques.append(
            f"(5) L'AVEU DE PAGE INCOMPLÈTE N'EST PAS PEINT AU-DESSUS DE LA PREMIÈRE LIGNE : son "
            f"bord bas est à y={p['boite']['b']:.1f}, le bord haut de la première ligne à "
            f"y={ligne['h']:.1f}. Un démenti rencontré APRÈS les lignes est rencontré après que "
            "le lecteur a compté."
        )

    # --- (6) LA MARQUE DU COMPTE INCOMPLET EST-ELLE PEINTE ? C'est le plus fragile des quatre
    #     aveux : sa marque est la QUEUE d'une étiquette, et un rognage la coupe en laissant le
    #     NOMBRE parfaitement lisible.
    q = al["compte"]
    if not q["present"]:
        refuser("la marque de compte incomplet n'a pas été peinte dans l'étiquette fabriquée : "
                "la propriété 6 n'a pas de sujet.")
    if not q["colleAuNombre"]:
        refuser("la marque de compte incomplet n'est plus la QUEUE de l'étiquette du compte dans "
                "l'arbre peint : ce banc ne juge plus ce que le module compose, et son vert "
                "porterait sur une autre forme.")
    if q["masque"]:
        manques.append(f"(6) LA MARQUE DU COMPTE INCOMPLET N'EST PAS PEINTE : {q['masque']}. Le "
                       "nombre, lui, reste lu — et il se lit alors comme une population.")
    if q["encre"]:
        manques.append(f"(6) LA MARQUE DU COMPTE INCOMPLET EST PEINTE SANS ENCRE VISIBLE : "
                       f"{q['encre']}.")
    if q["boite"] is None or q["boite"]["l"] <= 0 or q["boite"]["ht"] <= 0:
        manques.append("(6) la marque du compte incomplet a un rectangle peint VIDE : le nombre "
                       "se lit alors comme une population, pas comme un sous-compte.")
    else:
        if q["docG"] + q["boite"]["l"] <= 0 or q["docH"] + q["boite"]["ht"] <= 0:
            manques.append(f"(6) la marque du compte incomplet est REPOUSSÉE hors du document "
                           f"(coin {q['docG']}, {q['docH']}) : présente dans l'arbre, absente de "
                           "l'écran.")
        if q["coupe"]:
            d = q["coupe"]
            manques.append(
                f"(6) LA MARQUE DU COMPTE INCOMPLET EST COUPÉE par un débordement : rognée par "
                f"`{d['par']}` (overflow {d['overflow']}), clip "
                f"x[{d['clip']['g']:.1f}..{d['clip']['d']:.1f}] "
                f"y[{d['clip']['h']:.1f}..{d['clip']['b']:.1f}], marque "
                f"x[{d['coupe']['g']:.1f}..{d['coupe']['d']:.1f}] "
                f"y[{d['coupe']['h']:.1f}..{d['coupe']['b']:.1f}]. C'est le défaut RÉALISTE de "
                "cette étiquette : la marque en est la QUEUE, la couper laisse le NOMBRE intact, "
                "et un nombre sans son démenti paraît exact."
            )

    # --- (7) LA MARQUE DU COMPTE EST-ELLE PEINTE AVANT LES LIGNES QU'ELLE DÉNOMBRE ?
    if q["boite"] and q["boite"]["b"] > ligne["h"] + 0.5:
        manques.append(
            f"(7) LA MARQUE DU COMPTE INCOMPLET N'EST PAS PEINTE AU-DESSUS DE LA PREMIÈRE LIGNE : "
            f"son bord bas est à y={q['boite']['b']:.1f}, le bord haut de la première ligne à "
            f"y={ligne['h']:.1f}. Le lecteur compte les lignes avant de rencontrer ce qui les "
            "qualifie."
        )
    return manques


# =====================================================================================
# 6. L'INSTRUMENT SE VALIDE DANS LES DEUX SENS — ET AVANT TOUT VERDICT
#    Une garde qui rendrait vert sans savoir voir le rouge est le défaut que cette
#    feuille de route poursuit. Les mutations attaquent par des ANCÊTRES et par des
#    syntaxes qu'aucune grammaire écrite ici ne connaît : le verdict ne peut donc pas
#    venir d'une liste de propriétés interdites.
# =====================================================================================
def mutations(j: dict, ja: dict) -> list:
    a = "." + j["classe_aveu"].strip().split()[0]
    hote = "#" + j["hote"]
    cnt = "." + j["classe_compte"].strip().split()[0]
    # `P11.21-l` — LES SÉLECTEURS DE LA VUE DES ALERTES SONT SCOPÉS À LEUR HÔTE, et ce n'est pas
    # une coquetterie : la classe du bandeau d'alertes est LA MÊME que celle de l'aveu de la
    # matrice (`.bad`). Une règle non scopée frapperait les deux, et une mutation censée prouver
    # la propriété 4 prouverait en réalité la 1.
    hal = ja["hote"]                                   # `#alerts .body`
    sec = ja["section"]                                # `#alerts`
    corps = ja["hote"].split()[1]                      # `.body`
    aal = "." + ja["classe_aveu"].strip().split()[0]   # `.bad`, scopé ci-dessous
    tete = "." + ja["classe_tete"].strip().split()[0]  # `.alerthead`
    lbl = f"{hal} {tete} > span:first-child"           # l'étiquette qui porte compte + marque
    return [
        ("masquage direct de l'aveu", f"{hote} {a} {{ display: none; }}", 1),
        ("aveu rendu transparent", f"{hote} {a} {{ opacity: 0.01; }}", 1),
        # DEUX MUTATIONS D'ANCÊTRE, ET LA SECONDE EST LA PREUVE. `visibility` s'HÉRITE : une
        # garde qui ne lirait QUE l'aveu la verrait quand même, et croirait tenir les ancêtres.
        # `display` ne s'hérite PAS — le style calculé de l'aveu reste `block` — donc SEULE la
        # marche vers les ancêtres peut l'attraper. Toutes deux passent par `@media` et `:has()`,
        # que rien ici ne sait analyser : le verdict ne peut pas venir d'une grammaire.
        ("masquage venu d'un ANCÊTRE, propriété héritée, en `@media` + `:has()`",
         f"@media all {{ .card:has(> {hote}) {{ visibility: hidden; }} }}", 1),
        ("MASQUAGE VENU D'UN ANCÊTRE PAR UNE PROPRIÉTÉ NON HÉRITÉE — seule la marche vers "
         "les ancêtres peut le voir",
         f"@media all {{ .card:has(> {hote}) {{ display: none; }} }}", 1),
        # L'ENCRE : deux cas que NI `display`, NI `visibility`, NI `opacity`, NI la géométrie
        # ne voient — le nœud reste opaque et de rectangle plein dans les deux.
        ("aveu peint SANS ENCRE (transparente)", f"{hote} {a} {{ color: transparent; }}", 1),
        ("aveu peint à l'ENCRE DE SON FOND",
         f"{hote} {a} {{ color: rgb(17, 21, 28); }} {hote} {{ background-color: rgb(17, 21, 28); }}", 1),
        ("aveu repoussé hors du document",
         f"{hote} {a} {{ position: absolute; left: -99999px; }}", 1),
        ("aveu réduit à un rectangle vide",
         f"{hote} {a} {{ display: block; height: 0; overflow: hidden; }}", 1),
        # LA MUTATION QUI PROUVE QUE RANG != POSITION : le document est inchangé, l'aveu
        # reste écrit AVANT la matrice, et il est PEINT EN DESSOUS.
        ("ORDRE PEINT INVERSÉ alors que le RANG dans le document est intact",
         f"{hote} {{ display: flex; flex-direction: column-reverse; }}", 2),
        ("marque de sous-compte coupée par son propre débordement",
         f"{cnt} {{ display: inline-block; max-width: 3px; overflow: hidden; }}", 3),

        # =============================================================================
        # `P11.21-l` — LES DEUX AVEUX JUMEAUX DE LA VUE DES ALERTES. Chaque cas neuf est
        # éprouvé sous les QUATRE attaques que la clé nomme : un masquage, un
        # déplacement hors écran, une transparence, et un masquage venu d'un ANCÊTRE par
        # une propriété QUI NE S'HÉRITE PAS. Plus, pour la marque du compte, le rognage
        # — qui est son défaut RÉALISTE — et pour les deux, l'inversion de l'ordre peint.
        # =============================================================================
        ("ALERTES · masquage direct de l'aveu de PAGE INCOMPLÈTE",
         f"{hal} > {aal} {{ display: none; }}", 4),
        ("ALERTES · aveu de PAGE INCOMPLÈTE repoussé hors du document",
         f"{hal} > {aal} {{ position: absolute; left: -99999px; }}", 4),
        ("ALERTES · aveu de PAGE INCOMPLÈTE rendu transparent",
         f"{hal} > {aal} {{ opacity: 0.01; }}", 4),
        ("ALERTES · aveu de PAGE INCOMPLÈTE peint SANS ENCRE (transparente)",
         f"{hal} > {aal} {{ color: transparent; }}", 4),
        # LA MUTATION QUI DÉCIDE, ET ELLE DÉCIDE POUR LES DEUX AVEUX À LA FOIS : `display` ne
        # s'hérite PAS — le style calculé de chaque aveu reste `block`/`inline` — donc SEULE la
        # marche vers les ancêtres peut la voir, et elle doit nommer le nœud fautif. Elle passe
        # par `@media` et `:has()`, qu'aucune grammaire écrite ici ne sait analyser. Les DEUX
        # propriétés doivent rougir : une seule suffirait à cacher que l'une des deux marches
        # ne se fait pas.
        ("ALERTES · MASQUAGE VENU D'UN ANCÊTRE PAR UNE PROPRIÉTÉ NON HÉRITÉE, sur les DEUX "
         "aveux à la fois — seule la marche vers les ancêtres peut le voir",
         f"@media all {{ {sec}:has(> {corps}) {{ display: none; }} }}", (4, 6)),

        ("ALERTES · masquage direct de l'étiquette qui porte la MARQUE DU COMPTE",
         f"{lbl} {{ display: none; }}", 6),
        ("ALERTES · MARQUE DU COMPTE repoussée hors du document",
         f"{lbl} {{ position: absolute; left: -99999px; }}", 6),
        ("ALERTES · MARQUE DU COMPTE rendue transparente",
         f"{lbl} {{ opacity: 0.01; }}", 6),
        ("ALERTES · MARQUE DU COMPTE peinte SANS ENCRE (transparente)",
         f"{lbl} {{ color: transparent; }}", 6),
        # LE DÉFAUT RÉALISTE, ET LE PIRE : la marque est la QUEUE de l'étiquette. Un rognage de
        # fin de ligne — l'ellipse ordinaire d'un en-tête en boîte flexible — la fait disparaître
        # en laissant le NOMBRE parfaitement lisible. Rien de ce qui précède ne le voit : le nœud
        # reste affiché, opaque, encré, dans le document et de rectangle plein.
        ("ALERTES · MARQUE DU COMPTE COUPÉE par un rognage de fin de ligne, le NOMBRE restant "
         "lisible — le cas où l'écran ment le plus discrètement",
         f"{lbl} {{ display: inline-block; white-space: nowrap; overflow: hidden; "
         f"text-overflow: ellipsis; max-width: 120px; }}", 6),

        # RANG != POSITION, DANS LA VUE DES ALERTES AUSSI : le document est inchangé, l'aveu
        # reste écrit AVANT la barre et les lignes, et les DEUX aveux sont PEINTS EN DESSOUS.
        ("ALERTES · ORDRE PEINT INVERSÉ alors que le RANG dans le document est intact — les DEUX "
         "aveux passent sous les lignes",
         f"{hal} {{ display: flex; flex-direction: column-reverse; }}", (5, 7)),
    ]


def main() -> int:
    moteur = trouver_le_moteur()
    if not WEB.is_dir():
        refuser(f"`web/` est introuvable sous `{RACINE}` : rien à rendre.")
    j = deriver_du_module()
    ja = deriver_des_alertes()
    page = batir_la_page(j, ja)

    print(f"[moteur] {moteur}")
    print(f"[dérivé de web/attack.js] hôte=#{j['hote']} · aveu=<{j['tag_aveu']} class=\"{j['classe_aveu']}\"> "
          f"· matrice=.{j['classe_matrice']} · cellule=<{j['tag_cellule']} class=\"{j['classe_cellule']}\"> "
          f"· compte=.{j['classe_compte']} · signe=« {j['signe']} » · aveu avant matrice={j['aveu_avant_matrice']}")
    print(f"[dérivé de web/alerts.js] hôte=`{ja['hote']}` · aveu de page=<{ja['tag_aveu']} "
          f"class=\"{ja['classe_aveu']}\"> · en-tête du compte=.{ja['classe_tete']} "
          f"· ligne=.{ja['classe_ligne']} · étiquette=« {ja['compte']} » + marque=« "
          f"{ja['phrase_compte'].strip()} » · aveu avant barre={ja['aveu_avant_barre']} "
          f"· barre avant lignes={ja['barre_avant_lignes']}")

    # --- SENS ROUGE, D'ABORD. Une mutation non attrapée = instrument aveugle = REFUS.
    aveugles = []
    for nom, regle, propriete in mutations(j, ja):
        # Une mutation peut être attendue sur PLUSIEURS propriétés — le masquage d'ancêtre des
        # alertes doit faire rougir les deux aveux, l'inversion d'ordre les deux rangs. Toutes
        # doivent être accusées : n'en exiger qu'une cacherait qu'une des deux marches est morte.
        attendues = propriete if isinstance(propriete, tuple) else (propriete,)
        vus = juger(rendre(moteur, page, regle))
        manquantes = [p for p in attendues if not any(m.startswith(f"({p})") for m in vus)]
        if manquantes:
            aveugles.append(f"« {nom} » (règle `{regle}`) attendue sur la/les propriété(s) "
                            f"{', '.join(str(p) for p in attendues)} — non accusée(s) : "
                            f"{', '.join(str(p) for p in manquantes)} ; la page est rendue avec "
                            f"cette règle et la garde n'accuse rien de tel ({len(vus)} "
                            f"manquement(s) : {vus})")
        else:
            for p in attendues:
                touche = [m for m in vus if m.startswith(f"({p})")]
                print(f"[mutation vue] {nom} -> {touche[0][:160]}")
    if aveugles:
        refuser("L'INSTRUMENT NE MESURE PAS CE QU'IL PRÉTEND MESURER — "
                f"{len(aveugles)} mutation(s) INJECTÉE(S) n'ont pas fait rougir :\n  · "
                + "\n  · ".join(aveugles)
                + "\nAucun verdict n'est rendu : une garde aveugle qui verdit est pire que "
                  "pas de garde."
                + "\nLIRE D'ABORD LES MANQUEMENTS ÉNUMÉRÉS CI-DESSUS, ET C'EST MESURÉ (2026-08-31) : "
                  "une mutation de RANG (propriétés 2, 5, 7) devient inattrapable quand la feuille "
                  "de style RÉELLE masque déjà son sujet — un nœud non peint n'a plus de bord à "
                  "comparer. Ce refus peut donc être le SECOND symptôme d'une vraie violation, "
                  "déjà nommée dans la liste ci-dessus. Ce n'est pas un vert, mais ce n'est pas "
                  "non plus toujours un défaut d'instrument : corriger le masquage rend au banc "
                  "son canal d'accusation.")

    # --- SENS VERT. La MÊME page, sans règle injectée.
    temoin_vert = juger(rendre(moteur, page, "/* aucune mutation */"))

    # --- LE VERDICT sur la feuille de style RÉELLE.
    if temoin_vert:
        print(f"::error::(1) {len(temoin_vert)} propriété(s) VIOLÉE(S) — un aveu n'est pas "
              "peint là où il est lu :", file=sys.stderr)
        for m in temoin_vert:
            print(f"::error::  · {m}", file=sys.stderr)
        return CODE_VIOLATION

    print(f"[P11.21-k P11.21-l] VERT — {len(mutations(j, ja))} mutations injectées ont TOUTES été "
          "vues rouges (dont DEUX masquages venus d'un ANCÊTRE en `:has()`/`@media` par une "
          "propriété qui NE S'HÉRITE PAS, deux ordres PEINTS inversés à rang de document "
          f"INCHANGÉ, et un rognage de fin de ligne qui coupe un démenti en laissant son nombre) ; "
          f"sans elles, `{moteur}` peint les QUATRE aveux visibles, opaques, encrés, de rectangle "
          "non vide et dans le document : celui de la matrice ATT&CK AU-DESSUS de la première "
          "cellule avec sa marque de sous-compte non rognée, celui de la PAGE INCOMPLÈTE des "
          "alertes AU-DESSUS du compte qu'il qualifie ET de la première ligne, et la marque du "
          "COMPTE INCOMPLET collée à son nombre, non rognée, au-dessus de la première ligne. "
          "CE QUE CE VERT NE DIT PAS : les balisages sont DÉRIVÉS de `web/attack.js` et de "
          "`web/alerts.js`, non produits par `loadAttackMatrix` ni `dessinerLaListePlate` — ce qui "
          "est jugé est la FEUILLE DE STYLE et la chaîne d'ANCÊTRES sur la forme que les modules "
          "déclarent émettre, et pour les alertes AUCUN autre banc ne fait exister ces deux aveux "
          "(les huit appels du harnais ESM omettent l'argument `etat`, mesuré le 2026-08-31) ; les "
          "deux panneaux sont peints dans le MÊME rendu, ce qui n'arrive pas dans la console ; un "
          "seul gabarit de fenêtre est rendu (1600x1400), et c'est le manque le plus net pour un "
          "rognage, qui dépend de la largeur ; il n'y a AUCUN test de recouvrement (un nœud peint "
          "par-dessus, un `clip-path`, ou une encre seulement PÂLE passent) ; et seule la branche "
          "FRANÇAISE des trois phrases est jugée.")
    return CODE_OK


if __name__ == "__main__":
    sys.exit(main())
