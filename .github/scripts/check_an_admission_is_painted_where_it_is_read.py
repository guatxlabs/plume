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
est réellement peint. Et elle le fait dans QUATRE CELLULES à la fois — deux gabarits de
fenêtre (1600 et 640 px) × deux langues (française et anglaise) —, chacune étant un
document complet de même origine dans son propre cadre, donc avec SA lignée d'ancêtres
et SON viewport, qui est ce qui décide des `@media`. Sept propriétés jugées ; les quatre
premières portent sur la matrice, les quatre suivantes sur les alertes (la 4 est partagée
par les deux vues) :

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

CE QU'ONT COÛTÉ LE SECOND GABARIT ET LA SECONDE LANGUE, MESURÉ LE 2026-08-31 SUR LE MÊME
POSTE, ET C'EST BEAUCOUP MOINS QUE LE LOT PRÉCÉDENT : 22 rendus (25,4 s puis 26,6 s) ->
25 rendus (31,1 s ; 30,7 s depuis un autre chemin absolu), soit +14 % de rendus et +20 %
de temps. QUATRE FOIS PLUS DE SURFACE JUGÉE POUR TROIS RENDUS DE PLUS, et la raison est
mesurée : un rendu se paie au DÉMARRAGE du moteur, pas à la mise en page — QUATRE
documents dans un passage coûtent 1,92 s là où UN en coûtait 2,23 s. Jouer les quatre
cellules dans quatre rendus séparés aurait fait 100 rendus (~110 s) ; les jouer dans un
seul en fait 25. Les trois rendus de plus ne sont donc PAS le prix du gabarit ni celui de
la langue : ce sont trois MUTATIONS de plus (deux règles sous condition de largeur, une
sonde de forme).

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

UNE QUATRIÈME FAUTE D'INSTRUMENT, ATTRAPÉE LE 2026-08-31 PAR COMPARAISON — NI PAR
RELECTURE, NI PAR MUTATION — ET ELLE FAISAIT PEINDRE À CE BANC UNE PHRASE QUE LE MODULE
N'ÉMET PAS. Le découpage des deux branches de langue de `motDeLaMatriceIncomplete` se
faisait sur le repère littéral `"     :"` (CINQ espaces puis deux-points). Mesuré : ce
repère n'existe PAS dans la fonction (la branche française tient sur `\\n    : "`, QUATRE
espaces), donc `find` rendait -1, le repli prenait TOUTE la fonction, et l'extraction des
littéraux — une simple classe `"([^"]*)"` — attrapait comme premier « littéral » un
morceau de CODE pris entre les deux guillemets doubles qui vivent à l'intérieur des
chaînes ANGLAISES : `' + cause\\n      + '`. L'aveu peint valait donc, en toutes lettres,
« ' + cause + 'cause FABRIQUÉE… couverture ATT&CK PARTIELLEMENT LUE … : «  » Ce qui est
affiché… » — un fragment de source collé devant, et la place de la cause laissée VIDE. Le
banc mesurait une phrase d'une ligne de trop, donc une hauteur peinte fausse. Le remède
est double et il est structurel : le découpage se fait désormais sur `\\n\\s*\\? ` puis
`\\n\\s*: ` et REFUSE si les deux ne s'ordonnent pas, et les littéraux sont extraits par un
motif qui ferme sur le MÊME délimiteur que celui qui ouvre (`_LITTERAL`), donc un
guillemet double vivant dans une chaîne à apostrophes ne peut plus ouvrir un faux
littéral. Effet mesuré sur l'arbre intact : la phrase peinte est enfin la vraie, l'aveu
perd la ligne de trop, et les deux accusations qui citent une ordonnée se déplacent de
23,2 px — AUCUNE accusation n'apparaît ni ne disparaît.

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
  · DEUX gabarits sont rendus (1600 et 640), pas tous. Entre les deux — et au-dessus de
    1600 — une règle `@media` calée sur une largeur qu'aucune cellule ne prend n'est pas
    vue. Ce qui EST tenu depuis ce lot : qu'une condition de largeur ne passe pas
    inaperçue, prouvé par deux mutations qui MORDENT à 640 et restent SANS EFFET à 1600.
    Et sous 500 px la question ne se pose plus : ce moteur BORNE la fenêtre à 500 px
    (`--window-size=480` -> `innerWidth = 500`, mesuré le 2026-08-31), et la mise en page
    ne bouge plus en dessous de 640 de toute façon (600, 560, 520, 480 et 360 rendent le
    MÊME document de 605 px de large).
  · AUCUN ROGNAGE N'EXISTE DANS LA FEUILLE RÉELLE, À AUCUNE LARGEUR, ET C'EST MESURÉ
    (2026-08-31, de 1600 à 360 px, dans les DEUX langues) : la lignée entière de la
    marque du compte est `overflow: visible` du `span` jusqu'à `html`, et l'étiquette ne
    déborde JAMAIS (`clientWidth == scrollWidth` à toutes les largeurs — elle retourne à
    la ligne au lieu de déborder) ; le seul rogneur de la lignée du signe,
    `.attack-matrix` en `overflow:auto`, ne défile à aucune de ces largeurs. Ce que les
    propriétés 3 et 6 tiennent est donc la capacité de VOIR un rognage, pas l'existence
    d'un rognage à corriger. Le corollaire est une limite : le rognage attrapé par cette
    garde a toujours été INJECTÉ, jamais rencontré.
  · AUCUN TEST DE RECOUVREMENT, ET C'EST UN REFUS ARGUMENTÉ, PAS UN OUBLI. Un nœud opaque
    peint PAR-DESSUS un aveu (`z-index`, `position`) passe toujours. MESURÉ le 2026-08-31 :
    le seul test de collision que ce moteur offre, `elementFromPoint`, ne répond pas « ce
    qui est PEINT ici » mais « ce qui INTERCEPTE le pointeur ici » — sous une nappe opaque
    posée en `pointer-events: none`, l'idiome ORDINAIRE d'un recouvrement, il rend l'aveu
    LUI-MÊME (`div.bad`), et `elementsFromPoint` ne liste même pas la nappe ; avec
    `pointer-events: auto` il rend la nappe. Une jambe bâtie là-dessus serait donc VERTE
    sur la forme la plus courante du défaut, ce qui est pire que pas de jambe. La voie
    honnête existe et n'est pas prise ici : rendre DEUX fois — avec et sans l'aveu — et
    comparer les PIXELS de sa région ; elle double le nombre de rendus et demande un
    décodeur d'image, et elle reste à faire.
  · LE RAPPORT DE CONTRASTE N'EST NI IMPOSÉ NI APPROXIMÉ, ET LA RAISON EST MESURÉE. Une
    encre seulement PÂLE passe. Le calculer JUSTEMENT demande l'encre COMPOSÉE sur son
    fond : un rapport tiré nu de `getComputedStyle().color` IGNORE l'alpha de l'encre et
    annoncerait 6,67:1 pour une encre à 94 % transparente — un FAUX VERT, exactement ce
    que ce fichier poursuit. Et le fond n'est flat que par chance : un dégradé, une image,
    un `mix-blend-mode`, un `filter` ou une `opacity` d'ancêtre rendent la composition
    impossible sans lire le pixel. Mesuré ce jour, pour que la décision ait une base :
    6,82:1 pour l'étiquette du compte, 6,67:1 pour les deux aveux, 13,20:1 pour une ligne
    — donc aucune violation cachée derrière ce refus aujourd'hui.
  · UN ROGNAGE PAR UNE FORME NE FAIT PLUS VERDIR — IL FAIT REFUSER. `clip-path`/`clip` ne
    sont reflétés par AUCUNE géométrie du document (mesuré : sous `inset(100%)`,
    `getBoundingClientRect` rend 853,03 x 46,5 avant comme après). La garde ne rejoue pas
    une géométrie de forme arbitraire — ce serait la grammaire qu'elle refuse — mais elle
    NOMME le nœud et sort en 2. Elle ne dit donc pas si la marque est encore lisible ;
    elle dit qu'elle ne sait plus le mesurer.
  · LES DEUX LANGUES SONT JUGÉES, et la raison écrite ici avant ce lot était FAUSSE :
    « la branche anglaise, plus longue, donc plus rognable » est DÉMENTIE par la mesure —
    l'anglais est plus COURT sur les trois phrases (aveu de matrice 46,5 px de haut contre
    69,8 en français à 1600 ; marque du compte 434,9 px contre 478,1). Ce qui reste
    OUVERT : les deux cellules ne diffèrent que par le TEXTE dérivé, et aucune règle de
    feuille de style ne peut viser l'une sans l'autre — parce que `web/index.html` déclare
    `lang="fr"` en dur et qu'AUCUN module ne pose jamais `document.documentElement.lang`
    (mesuré le 2026-08-31 : `LANG` vient de `lireLeStockageDuSite('soc_lang')` dans
    `web/core.js`, et rien n'en informe le document). Une console rendue en anglais annonce
    donc le français à `:lang()` et aux technologies d'assistance. C'est un défaut de
    `web/`, il est NOMMÉ ici et pas corrigé ici ; sa conséquence pour cette garde est
    qu'une mutation visant la seule cellule anglaise n'est pas exprimable, et que ce que
    les cellules anglaises tiennent est la GÉOMÉTRIE de leurs chaînes, pas une règle qui
    leur serait propre.
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
    étiquette qui RETOURNE À LA LIGNE, cette union est plus large que chaque fragment. Ce
    cas N'EST PLUS HYPOTHÉTIQUE et il est désormais RENDU : à 1600 la marque tient sur une
    ligne (478,1 x 15,0 px en français), à 640 elle passe à DEUX (478,2 x 33,6) et le
    document entier est jugé vert dessus. Ce que la mesure du 2026-08-31 ajoute : l'union
    élargie ne peut produire une FAUSSE ACCUSATION que s'il existe un rogneur dans la
    lignée, et il n'y en a aucun — donc le risque est nommé, borné, et il ne s'est pas
    matérialisé. Il redeviendrait réel le jour où un `overflow` apparaîtrait au-dessus de
    l'étiquette.
  · LES QUATRE CELLULES SONT PEINTES DANS UN SEUL RENDU, ce qui n'arrive jamais dans la
    console : un exploitant voit UNE langue à UNE largeur. Les propriétés jugées étant
    toutes relatives à l'intérieur d'une cellule, la cohabitation ne les change pas
    (vérifié au pixel contre les mêmes documents rendus SEULS), mais une règle qui ne se
    déclencherait qu'en l'absence des autres cadres n'est pas vue.
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

# =====================================================================================
# LES CELLULES JOUÉES — DEUX GABARITS × DEUX LANGUES, ET LE SECOND GABARIT EST DÉRIVÉ
# D'UNE MESURE, PAS CHOISI.
#
# MESURÉ LE 2026-08-31 SUR CE POSTE (Google Chrome 151.0.7922.169), viewport de 1600 à 360 px,
# dans LES DEUX LANGUES, sur la feuille de style RÉELLE :
#   · 640 est le PLUS ÉTROIT gabarit où le document tient encore dans sa propre largeur
#     (`scrollWidth` 640 = viewport 640). À 600 le document déborde déjà (`scrollWidth` 605)
#     et ce 605 ne bouge plus : 600, 560, 520, 480 et 360 rendent la MÊME mise en page, donc
#     un gabarit plus étroit que 640 n'ajoute AUCUNE information.
#   · Ce moteur BORNE la fenêtre à 500 px : `--window-size=480,1400` rend `innerWidth = 500`.
#     Un gabarit annoncé sous 500 px mesurerait donc autre chose que son nom — mesuré, et
#     c'est la raison pour laquelle il n'y en a pas.
#   · 640 traverse CINQ règles `@media` de `web/style.css` que 1600 ne traverse pas
#     (`max-width` 1024, 820, 760, 700, 640) et change la peinture : `.attack-col` passe de
#     168 à 150 px, la carte des alertes de 853 à 574 px, et la marque du compte passe d'UNE
#     ligne (478,1 x 15,0 px) à DEUX (478,2 x 33,6 px) — c'est le cas de RETOUR À LA LIGNE que
#     ce fichier ne faisait que nommer, désormais rendu et jugé.
#
# LES DEUX LANGUES SONT JOUÉES, ET LA RAISON ÉCRITE ICI AVANT CE LOT ÉTAIT FAUSSE : « la branche
# anglaise, plus longue, donc plus rognable » est DÉMENTIE par la mesure. L'anglais est plus
# COURT sur les trois phrases (aveu de matrice 46,5 px de haut contre 69,8 en français à 1600 ;
# marque du compte 434,9 px de large contre 478,1) : il est donc MOINS exposé, pas plus. Ce que
# la branche anglaise apporte vraiment : elle est DÉRIVÉE (un module qui casserait sa seule
# branche anglaise fait REFUSER ici au lieu de passer) et PEINTE (une géométrie qui ne nuirait
# qu'à ses chaînes est vue).
#
# LES QUATRE CELLULES SONT PEINTES DANS UN SEUL RENDU, chacune dans son propre document de même
# origine — donc avec SA lignée d'ancêtres réelle, `html` compris, et son propre viewport, qui
# est ce qui décide des `@media`. MESURÉ LE 2026-08-31 : la géométrie d'une cellule est
# IDENTIQUE AU PIXEL à celle du même document rendu seul à la même taille (fr-1600 : aveu
# 853,0 x 69,8 et marque 478,1 x 15,0 ; fr-640 : aveu 574,0 x 93,0 et marque 478,2 x 33,6 —
# les mêmes nombres des deux façons), et QUATRE documents coûtent 1,92 s là où UN en coûtait
# 2,23 s : le prix d'un rendu est celui du DÉMARRAGE du moteur, pas celui de la mise en page.
LARGEUR_DE_REFERENCE, LARGEUR_ETROITE, HAUTEUR = 1600, 640, 1400
CELLULES = tuple(
    (f"{langue}-{largeur}", langue, largeur, HAUTEUR)
    for largeur in (LARGEUR_DE_REFERENCE, LARGEUR_ETROITE)
    for langue in ("fr", "en")
)

# La cause est FABRIQUÉE par ce banc : aucune lecture réelle n'est citée, et le mot le dit.
CAUSE_FABRIQUEE = "cause FABRIQUÉE par ce banc — aucune lecture réelle"

# UN LITTÉRAL DE CHAÎNE JAVASCRIPT, ET PAS UNE CLASSE DE CARACTÈRES. Une simple classe
# `["']([^"']*)["']` COUPE au premier guillemet INTÉRIEUR : la branche anglaise de
# `motDeLaPageIncomplete` porte `… names a cause: "` dans une chaîne à apostrophes, et la classe
# en rendait un morceau tronqué PUIS un faux littéral fait du code entre deux chaînes. Ce motif-ci
# ferme sur le MÊME délimiteur que celui qui ouvre, échappements compris.
_LITTERAL = re.compile(r"""'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)\"""")


def litteraux(texte: str) -> list:
    return [(m.group(1) if m.group(1) is not None else m.group(2))
            for m in _LITTERAL.finditer(texte)]

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

    # LES DEUX PHRASES DE L'AVEU — LA FRANÇAISE **ET** L'ANGLAISE, dérivées des DEUX branches de
    # `motDeLaMatriceIncomplete`. Leur LONGUEUR décide de la hauteur peinte, donc elles ne
    # s'inventent pas ; et l'anglaise est dérivée pour que la casser SEULE fasse REFUSER ici.
    j = src.find("function motDeLaMatriceIncomplete(")  # la parenthèse : voir plus haut, un préfixe suffisait
    if j < 0:
        refuser("`motDeLaMatriceIncomplete` a disparu : la phrase de l'aveu ne se dérive plus.")
    fonction = src[j: src.find("\n}", j) + 2]
    d_en = re.search(r"\n\s*\? ", fonction)
    d_fr = re.search(r"\n\s*: ", fonction)
    if not d_en or not d_fr or d_en.start() >= d_fr.start():
        refuser("les DEUX branches de langue de `motDeLaMatriceIncomplete` ne se distinguent plus "
                "(`? …` d'abord, `: …` ensuite) : les phrases ne se dérivent plus, et une phrase "
                "inventée aurait une AUTRE longueur donc une autre hauteur peinte.")
    branches = {"en": fonction[d_en.start():d_fr.start()], "fr": fonction[d_fr.start():]}
    jetons["phrases"] = {}
    for langue, texte in branches.items():
        morceaux = litteraux(texte)
        if len(morceaux) < 2:
            refuser(
                f"la branche {langue} de `motDeLaMatriceIncomplete` rend {len(morceaux)} "
                "littéral(aux), 2 attendus au moins : la phrase de l'aveu ne se dérive plus, "
                "et une phrase inventée aurait une AUTRE longueur donc une autre hauteur peinte."
            )
        jetons["phrases"][langue] = morceaux[0] + CAUSE_FABRIQUEE + "".join(morceaux[1:])

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

    def branches_de_langue(nom: str) -> dict:
        """Les littéraux des DEUX branches de `LANG === 'en' ? … : …`. Leur LONGUEUR décide de la
        largeur peinte, donc de ce qu'un rognage coupe : elles ne s'inventent pas. L'anglaise est
        dérivée exactement comme la française — un module qui casserait la SEULE branche anglaise
        fait donc REFUSER ici, au lieu de laisser un aveu que personne ne rend jamais."""
        # LA PARENTHÈSE OUVRANTE EST OBLIGATOIRE — voir `deriver_du_module` : sans elle, un
        # renommage de la fonction est retrouvé par PRÉFIXE et la garde verdit sur une fiction.
        i = src.find(f"function {nom}(")
        if i < 0:
            refuser(f"`{nom}` a disparu de `web/alerts.js` : les phrases ne se dérivent plus.")
        corps_f = src[i: src.find("\n}", i) + 2]
        reperes = {}
        for langue, colle, nue in (("en", "? quoi +", r"\n\s*\? '"), ("fr", ": quoi +", r"\n\s*: '")):
            k = corps_f.find(colle)
            if k < 0:
                m = re.search(nue, corps_f)
                k = m.start() if m else -1
            if k < 0:
                refuser(f"la branche {langue} de `{nom}` n'est plus reconnaissable : la phrase "
                        "ne se dérive plus, et une phrase inventée aurait une AUTRE longueur.")
            reperes[langue] = k
        if reperes["en"] >= reperes["fr"]:
            refuser(f"les deux branches de langue de `{nom}` ne s'ordonnent plus (l'anglaise doit "
                    "précéder la française) : le découpage des littéraux ne se dérive plus, et "
                    "prendre la mauvaise moitié peindrait une phrase dans l'autre langue.")
        return {"en": litteraux(corps_f[reperes["en"]:reperes["fr"]]),
                "fr": litteraux(corps_f[reperes["fr"]:])}

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
    # commence par lui, donc il compte dans la largeur peinte. LES DEUX MOTS SONT LUS, un par
    # langue, et ils ne font pas la même largeur (`Alerts` contre `Alertes`).
    _mot = r"const aveu = bandeauDePageIncomplete\(LANG === 'en' \? '([^']*)' : '([^']*)', etat\)"
    mots = {"en": un(_mot, "le mot ANGLAIS que la vue plate passe au bandeau", 1),
            "fr": un(_mot, "le mot FRANÇAIS que la vue plate passe au bandeau", 2)}

    lits_page = branches_de_langue("motDeLaPageIncomplete")
    phrases_page = {}
    for langue in ("fr", "en"):
        if len(lits_page[langue]) < 2:
            refuser(f"la branche {langue} de `motDeLaPageIncomplete` rend "
                    f"{len(lits_page[langue])} littéral(aux), 2 attendus au moins : la phrase de "
                    "l'aveu ne se dérive plus.")
        phrases_page[langue] = (mots[langue] + lits_page[langue][0]
                                + CAUSE_FABRIQUEE + "".join(lits_page[langue][1:]))

    lits_compte = branches_de_langue("motDuCompteIncomplet")
    phrases_compte = {}
    for langue in ("fr", "en"):
        if len(lits_compte[langue]) < 1:
            refuser(f"la branche {langue} de `motDuCompteIncomplet` ne rend aucun littéral : la "
                    "marque du compte ne se dérive plus, et c'est ELLE que le rognage coupe.")
        phrases_compte[langue] = lits_compte[langue][0]

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
        "tag_aveu": tag_aveu, "classe_aveu": classe_aveu, "phrases_page": phrases_page,
        "phrases_compte": phrases_compte,
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
def batir_le_document(j: dict, ja: dict, langue: str, cellule: str) -> str:
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
        "cellule": cellule, "langue": langue,
        "hote": j["hote"],
        "tagAveu": j["tag_aveu"], "classeAveu": j["classe_aveu"], "phrase": j["phrases"][langue],
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
            "phrasePage": ja["phrases_page"][langue],
            "phraseCompte": ja["phrases_compte"][langue],
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
    // CHAQUE CELLULE ANNONCE SON VERDICT À LA COQUILLE. Le document reste jugeable SEUL (il écrit
    // son `<pre>` de toute façon) : l'annonce s'ajoute, elle ne déplace rien.
    try {
      if (window.parent !== window) {
        window.parent.postMessage({ cellule: D.cellule, verdict: o }, location.origin);
      }
    } catch (e) {}
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
    // UN ROGNAGE PAR UNE FORME — ET POURQUOI CETTE SONDE NOMME AU LIEU DE JUGER. MESURÉ LE
    // 2026-08-31 : sous `clip-path: inset(100%)`, `getBoundingClientRect` rend EXACTEMENT la même
    // boîte qu'avant (853,03 x 46,5 des deux côtés), et ni `display`, ni `visibility`, ni
    // `opacity`, ni l'encre ne bougent. AUCUNE géométrie du document ne reflète donc un rognage
    // par une forme. Le juger demanderait de rejouer une géométrie ARBITRAIRE (`polygon()`,
    // `path()`, `circle()`, `url(#…)`) — c'est-à-dire la GRAMMAIRE que la préface de ce fichier
    // refuse, et qu'une forme un peu exotique défait. Ce que fait donc cette sonde : elle NOMME le
    // nœud qui rogne par une forme, et la garde REFUSE DE CONCLURE (code 2) au lieu de verdir sur
    // une marque peut-être invisible. La feuille RÉELLE n'en porte aucun sur ces lignées (mesuré
    // le 2026-08-31 : `clip-path` absent de `web/style.css`, et le seul `clip:rect(0 0 0 0)` est
    // sur `.sronly`), donc ce refus n'est pas un bruit permanent — c'est le canal du jour où l'un
    // apparaîtrait au-dessus d'un aveu.
    const rognageParForme = (el) => {
      for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
        const cs = getComputedStyle(n);
        if (cs.clipPath && cs.clipPath !== 'none') return 'clip-path:' + cs.clipPath + ' sur ' + nommer(n);
        if (cs.clip && cs.clip !== 'auto') return 'clip:' + cs.clip + ' sur ' + nommer(n);
      }
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
      cellule: D.cellule, langue: D.langue,
      gabarit: { l: window.innerWidth, h: window.innerHeight },
      aveu: {
        masque: masquePar(aveu),
        encre: encreInvisible(aveu),
        forme: rognageParForme(aveu),
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
        forme: porteur ? rognageParForme(porteur) : null,
        boite: porteur ? boiteDuSigne(porteur, D.signe) : null,
        coupe: porteur && boiteDuSigne(porteur, D.signe)
          ? rogneur(porteur, boiteDuSigne(porteur, D.signe)) : null,
      },
      // `P11.21-l` — LES DEUX AVEUX JUMEAUX DES ALERTES, mesurés par les MÊMES sondes.
      alertes: {
        aveuPage: {
          masque: masquePar(aveuPage),
          encre: encreInvisible(aveuPage),
          forme: rognageParForme(aveuPage),
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
            forme: rognageParForme(etiquette),
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


def chemin_de_cellule(nom: str) -> str:
    return f"/__cellule_{nom}__.html"


# =====================================================================================
# 3 bis. LA COQUILLE — LES QUATRE CELLULES DANS UN SEUL RENDU, ET POURQUOI C'EST HONNÊTE
#    Chaque cellule est un DOCUMENT COMPLET de même origine, chargé dans un cadre à la taille du
#    gabarit. Le cadre donne à ce document SON PROPRE viewport — c'est lui qui décide des `@media`
#    et des unités `vw`/`vh` — et il n'ajoute AUCUN ancêtre à la lignée jugée : la marche
#    `parentElement` de chaque sonde s'arrête au `html` du document de la cellule, qui est le VRAI
#    `web/index.html`. La coquille ne porte donc ni style ni classe qui pourrait déteindre.
#    MESURÉ LE 2026-08-31, ET C'EST LA VALIDATION DE CE CHOIX : la géométrie d'une cellule est
#    IDENTIQUE AU PIXEL à celle du même document rendu SEUL à la même taille de fenêtre
#    (fr-1600 : aveu 853,0 x 69,8 et marque 478,1 x 15,0 ; fr-640 : aveu 574,0 x 93,0 et marque
#    478,2 x 33,6 — les mêmes nombres des deux façons). Le prix : QUATRE documents coûtent 1,92 s
#    là où UN en coûtait 2,23 s, parce qu'un rendu se paie au DÉMARRAGE du moteur et non à la mise
#    en page. Un second gabarit et une seconde langue ne coûtent donc AUCUN rendu de plus.
# =====================================================================================
def batir_la_coquille() -> str:
    cellules = [{"nom": n, "url": chemin_de_cellule(n), "largeur": lg, "hauteur": ht}
                for (n, _langue, lg, ht) in CELLULES]
    return """<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>banc</title>
<style>html,body{margin:0;padding:0;background:#000} iframe{border:0;display:block}</style>
</head><body>
<script>
(function () {
  const CELLULES = __CELLULES__, ID = __ID__;
  const recu = {};
  let ecrit = false;
  const ecrire = (manquantes) => {
    if (ecrit) return;
    ecrit = true;
    const pre = document.createElement('pre');
    pre.id = ID;
    pre.textContent = JSON.stringify({ cellules: recu, manquantes: manquantes || [] });
    document.body.appendChild(pre);
  };
  window.addEventListener('message', (e) => {
    if (e.origin !== location.origin || !e.data || !e.data.cellule) return;
    recu[e.data.cellule] = e.data.verdict;
    if (CELLULES.every((c) => Object.prototype.hasOwnProperty.call(recu, c.nom))) ecrire([]);
  });
  // FILET : si une cellule ne répond jamais, la coquille écrit quand même ce qu'elle tient et
  // NOMME les manquantes — la garde refuse alors en disant LAQUELLE, au lieu de refuser sur un
  // « aucun verdict » muet. Le délai est en temps VIRTUEL, donc sous le budget du moteur.
  setTimeout(() => ecrire(CELLULES.map((c) => c.nom).filter(
    (n) => !Object.prototype.hasOwnProperty.call(recu, n))), 12000);
  for (const c of CELLULES) {
    const f = document.createElement('iframe');
    f.loading = 'eager';
    f.width = String(c.largeur); f.height = String(c.hauteur);
    f.style.width = c.largeur + 'px'; f.style.height = c.hauteur + 'px';
    f.src = c.url;
    document.body.appendChild(f);
  }
})();
</script>
</body></html>""".replace("__CELLULES__", json.dumps(cellules, ensure_ascii=False)) \
                 .replace("__ID__", json.dumps(ID_VERDICT))


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


def rendre(moteur: str, documents: dict, coquille: str, mutation: str) -> dict:
    """Sert la coquille et SES QUATRE CELLULES, rend le tout en UN passage, et rapporte ce que le
    MOTEUR a peint dans chacune. Tout ce qui n'est pas un verdict complet — coquille muette,
    cellule manquante, JSON illisible — est un REFUS, jamais un vert."""
    Serveur.pages = {"/__banc__.html": (coquille, "text/html"),
                     "/__mutation__.css": (mutation, "text/css")}
    for nom, doc in documents.items():
        Serveur.pages[chemin_de_cellule(nom)] = (doc, "text/html")
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
        agrege = json.loads(brut)
    except json.JSONDecodeError as e:
        refuser(f"le verdict rendu par la page n'est pas lisible ({e}) : {brut[:400]!r}")
        raise AssertionError("inatteignable")
    cellules = agrege.get("cellules") or {}
    absentes = [n for (n, _l, _lg, _h) in CELLULES if n not in cellules]
    if absentes:
        refuser(
            f"la coquille n'a pas reçu le verdict de {len(absentes)} cellule(s) sur "
            f"{len(CELLULES)} : {', '.join(absentes)}. Ces gabarits n'ont donc RIEN mesuré, et "
            "conclure sur les autres seuls masquerait exactement ce que la seconde largeur et la "
            "seconde langue sont là pour voir."
        )
    return cellules


# =====================================================================================
# 5. LES CINQ PROPRIÉTÉS, LUES SUR CE QUE LE MOTEUR A PEINT
# =====================================================================================
def juger(v: dict, cellule: str = "") -> list:
    """Rend la liste des manquements D'UNE CELLULE. Une liste VIDE est un vert ; un verdict que la
    page n'a pas su rendre est un REFUS, pas un vert."""
    ou = f"[{cellule}] " if cellule else ""

    def refuser_ici(motif: str) -> None:
        refuser(ou + motif)

    if v.get("refus"):
        refuser_ici(f"la page a refusé de se mesurer : {v.get('refus')} "
                    f"{v.get('message', '') or v.get('hote', '')}")
    manques = []

    # LE ROGNAGE PAR UNE FORME EST NOMMÉ, ET IL FAIT REFUSER — JAMAIS VERDIR. Voir la sonde
    # `rognageParForme` : aucune géométrie du document ne reflète un `clip-path`/`clip`, mesuré le
    # 2026-08-31 (`getBoundingClientRect` inchangé sous `inset(100%)`). La garde ne rejoue donc pas
    # une géométrie de forme arbitraire — ce serait la grammaire que ce fichier refuse — mais elle
    # ne se tait pas non plus : elle dit qu'elle ne sait plus mesurer, et sur QUEL nœud.
    for chemin, quoi in (
        (("aveu", "forme"), "l'aveu de la matrice"),
        (("signe", "forme"), "la marque de sous-compte de la matrice"),
        (("alertes", "aveuPage", "forme"), "l'aveu de page incomplète des alertes"),
        (("alertes", "compte", "forme"), "la marque du compte incomplet"),
    ):
        n = v
        for cle in chemin:
            n = (n or {}).get(cle) if isinstance(n, dict) else None
        if n:
            refuser_ici(
                f"{quoi} est ROGNÉ PAR UNE FORME : {n}. Ce que peint réellement une forme, "
                "aucune géométrie du document ne le dit — MESURÉ le 2026-08-31 : sous "
                "`clip-path: inset(100%)` la boîte rendue est IDENTIQUE (853,03 x 46,5 avant "
                "comme après), et ni le masquage, ni l'encre, ni le débordement ne bougent. "
                "Juger cela demanderait de rejouer une géométrie de forme ARBITRAIRE — la "
                "grammaire que cette garde refuse. Elle ne verdit donc pas : elle dit qu'elle "
                "ne mesure plus."
            )

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
        refuser_ici("aucune cellule de données n'a été peinte : la propriété 2 (« au-dessus de "
                "la première ligne ») n'a pas de repère, et la garde ne devine pas.")
    elif a["boite"]["b"] > c["h"] + 0.5:
        manques.append(
            f"(2) L'AVEU N'EST PAS PEINT AU-DESSUS de la première cellule : son bord bas est "
            f"à y={a['boite']['b']:.1f}, le bord haut de la cellule à y={c['h']:.1f}. Le RANG "
            "dans le document ne dit rien de la position peinte, et c'est ce défaut-là."
        )

    s = v["signe"]
    if not s["present"]:
        refuser_ici("le signe de sous-compte n'a pas été peint dans la cellule fabriquée : "
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
        refuser_ici("la page n'a rendu aucune mesure pour la vue des alertes : les propriétés 4 à 7 "
                "n'ont pas de sujet, et un vert sans elles serait un vert sur rien.")
    ligne = al["premiereLigne"]
    if ligne is None:
        refuser_ici("aucune ligne d'alerte n'a été peinte : les propriétés 5 et 7 (« au-dessus de la "
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
        refuser_ici("la marque de compte incomplet n'a pas été peinte dans l'étiquette fabriquée : "
                "la propriété 6 n'a pas de sujet.")
    if not q["colleAuNombre"]:
        refuser_ici("la marque de compte incomplet n'est plus la QUEUE de l'étiquette du compte dans "
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
def partout(*proprietes) -> dict:
    """Attendue ROUGE dans les QUATRE cellules. C'est le cas normal : une règle inconditionnelle
    doit mordre aux deux largeurs et dans les deux langues, et n'en exiger qu'une cacherait qu'une
    cellule ne mesure rien."""
    return {nom: tuple(proprietes) for (nom, _l, _lg, _h) in CELLULES}


def seulement_etroit(*proprietes) -> dict:
    """Attendue ROUGE aux gabarits ÉTROITS et VERTE aux LARGES — et le vert est ici la moitié qui
    prouve. Une règle sous condition de largeur est INVISIBLE au gabarit de référence : exiger
    zéro manquement à 1600 démontre que le premier gabarit est aveugle, et exiger le rouge à 640
    démontre que le second voit. Sans les deux moitiés, le second gabarit serait décoratif."""
    return {nom: (tuple(proprietes) if lg <= LARGEUR_ETROITE else ())
            for (nom, _l, lg, _h) in CELLULES}


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
        ("masquage direct de l'aveu", f"{hote} {a} {{ display: none; }}", partout(1)),
        ("aveu rendu transparent", f"{hote} {a} {{ opacity: 0.01; }}", partout(1)),
        # DEUX MUTATIONS D'ANCÊTRE, ET LA SECONDE EST LA PREUVE. `visibility` s'HÉRITE : une
        # garde qui ne lirait QUE l'aveu la verrait quand même, et croirait tenir les ancêtres.
        # `display` ne s'hérite PAS — le style calculé de l'aveu reste `block` — donc SEULE la
        # marche vers les ancêtres peut l'attraper. Toutes deux passent par `@media` et `:has()`,
        # que rien ici ne sait analyser : le verdict ne peut pas venir d'une grammaire.
        ("masquage venu d'un ANCÊTRE, propriété héritée, en `@media` + `:has()`",
         f"@media all {{ .card:has(> {hote}) {{ visibility: hidden; }} }}", partout(1)),
        ("MASQUAGE VENU D'UN ANCÊTRE PAR UNE PROPRIÉTÉ NON HÉRITÉE — seule la marche vers "
         "les ancêtres peut le voir",
         f"@media all {{ .card:has(> {hote}) {{ display: none; }} }}", partout(1)),
        # L'ENCRE : deux cas que NI `display`, NI `visibility`, NI `opacity`, NI la géométrie
        # ne voient — le nœud reste opaque et de rectangle plein dans les deux.
        ("aveu peint SANS ENCRE (transparente)", f"{hote} {a} {{ color: transparent; }}", partout(1)),
        ("aveu peint à l'ENCRE DE SON FOND",
         f"{hote} {a} {{ color: rgb(17, 21, 28); }} {hote} {{ background-color: rgb(17, 21, 28); }}", partout(1)),
        ("aveu repoussé hors du document",
         f"{hote} {a} {{ position: absolute; left: -99999px; }}", partout(1)),
        ("aveu réduit à un rectangle vide",
         f"{hote} {a} {{ display: block; height: 0; overflow: hidden; }}", partout(1)),
        # LA MUTATION QUI PROUVE QUE RANG != POSITION : le document est inchangé, l'aveu
        # reste écrit AVANT la matrice, et il est PEINT EN DESSOUS.
        ("ORDRE PEINT INVERSÉ alors que le RANG dans le document est intact",
         f"{hote} {{ display: flex; flex-direction: column-reverse; }}", partout(2)),
        ("marque de sous-compte coupée par son propre débordement",
         f"{cnt} {{ display: inline-block; max-width: 3px; overflow: hidden; }}", partout(3)),

        # =============================================================================
        # `P11.21-l` — LES DEUX AVEUX JUMEAUX DE LA VUE DES ALERTES. Chaque cas neuf est
        # éprouvé sous les QUATRE attaques que la clé nomme : un masquage, un
        # déplacement hors écran, une transparence, et un masquage venu d'un ANCÊTRE par
        # une propriété QUI NE S'HÉRITE PAS. Plus, pour la marque du compte, le rognage
        # — qui est son défaut RÉALISTE — et pour les deux, l'inversion de l'ordre peint.
        # =============================================================================
        ("ALERTES · masquage direct de l'aveu de PAGE INCOMPLÈTE",
         f"{hal} > {aal} {{ display: none; }}", partout(4)),
        ("ALERTES · aveu de PAGE INCOMPLÈTE repoussé hors du document",
         f"{hal} > {aal} {{ position: absolute; left: -99999px; }}", partout(4)),
        ("ALERTES · aveu de PAGE INCOMPLÈTE rendu transparent",
         f"{hal} > {aal} {{ opacity: 0.01; }}", partout(4)),
        ("ALERTES · aveu de PAGE INCOMPLÈTE peint SANS ENCRE (transparente)",
         f"{hal} > {aal} {{ color: transparent; }}", partout(4)),
        # LA MUTATION QUI DÉCIDE, ET ELLE DÉCIDE POUR LES DEUX AVEUX À LA FOIS : `display` ne
        # s'hérite PAS — le style calculé de chaque aveu reste `block`/`inline` — donc SEULE la
        # marche vers les ancêtres peut la voir, et elle doit nommer le nœud fautif. Elle passe
        # par `@media` et `:has()`, qu'aucune grammaire écrite ici ne sait analyser. Les DEUX
        # propriétés doivent rougir : une seule suffirait à cacher que l'une des deux marches
        # ne se fait pas.
        ("ALERTES · MASQUAGE VENU D'UN ANCÊTRE PAR UNE PROPRIÉTÉ NON HÉRITÉE, sur les DEUX "
         "aveux à la fois — seule la marche vers les ancêtres peut le voir",
         f"@media all {{ {sec}:has(> {corps}) {{ display: none; }} }}", partout(4, 6)),

        ("ALERTES · masquage direct de l'étiquette qui porte la MARQUE DU COMPTE",
         f"{lbl} {{ display: none; }}", partout(6)),
        ("ALERTES · MARQUE DU COMPTE repoussée hors du document",
         f"{lbl} {{ position: absolute; left: -99999px; }}", partout(6)),
        ("ALERTES · MARQUE DU COMPTE rendue transparente",
         f"{lbl} {{ opacity: 0.01; }}", partout(6)),
        ("ALERTES · MARQUE DU COMPTE peinte SANS ENCRE (transparente)",
         f"{lbl} {{ color: transparent; }}", partout(6)),
        # LE DÉFAUT RÉALISTE, ET LE PIRE : la marque est la QUEUE de l'étiquette. Un rognage de
        # fin de ligne — l'ellipse ordinaire d'un en-tête en boîte flexible — la fait disparaître
        # en laissant le NOMBRE parfaitement lisible. Rien de ce qui précède ne le voit : le nœud
        # reste affiché, opaque, encré, dans le document et de rectangle plein.
        ("ALERTES · MARQUE DU COMPTE COUPÉE par un rognage de fin de ligne, le NOMBRE restant "
         "lisible — le cas où l'écran ment le plus discrètement",
         f"{lbl} {{ display: inline-block; white-space: nowrap; overflow: hidden; "
         f"text-overflow: ellipsis; max-width: 120px; }}", partout(6)),

        # RANG != POSITION, DANS LA VUE DES ALERTES AUSSI : le document est inchangé, l'aveu
        # reste écrit AVANT la barre et les lignes, et les DEUX aveux sont PEINTS EN DESSOUS.
        ("ALERTES · ORDRE PEINT INVERSÉ alors que le RANG dans le document est intact — les DEUX "
         "aveux passent sous les lignes",
         f"{hal} {{ display: flex; flex-direction: column-reverse; }}", partout(5, 7)),

        # =============================================================================
        # LE SECOND GABARIT, ET CE QU'IL EST SEUL À VOIR. Les deux règles qui suivent sont
        # SOUS CONDITION DE LARGEUR : elles doivent faire ROUGIR à 640 et laisser VERT à
        # 1600. Le vert est la moitié qui décide — il démontre que le gabarit de référence
        # est AVEUGLE à ces règles, donc que le second gabarit n'est pas décoratif. Le seuil
        # 800 px est choisi ENTRE les deux gabarits joués, et il n'est pas une largeur de la
        # feuille réelle : la garde n'a pas à deviner les points de rupture d'autrui, elle a
        # à prouver qu'une condition de largeur ne lui échappe pas.
        # =============================================================================
        ("LARGEUR · MARQUE DU COMPTE COUPÉE PAR UN ROGNAGE DE FIN DE LIGNE QUI NE MORD QU'EN "
         "DESSOUS DE 800 px — le mensonge le plus discret du lot, et invisible au gabarit "
         "de référence",
         f"@media (max-width: 800px) {{ {lbl} {{ display: inline-block; white-space: nowrap; "
         f"overflow: hidden; text-overflow: ellipsis; max-width: 120px; }} }}",
         seulement_etroit(6)),
        ("LARGEUR · AVEU DE PAGE INCOMPLÈTE MASQUÉ DEPUIS UN ANCÊTRE, ET SEULEMENT EN DESSOUS "
         "DE 800 px — par une propriété qui NE S'HÉRITE PAS, en `:has()`",
         f"@media (max-width: 800px) {{ {sec}:has(> {corps}) > {corps} {{ display: none; }} }}",
         seulement_etroit(4, 6)),
    ]


# =====================================================================================
# 6 bis. LA SONDE DE FORME SE VALIDE ELLE AUSSI — ET SON CANAL EST LE REFUS, PAS LE ROUGE
#    Un `clip-path` ne produit AUCUN manquement : il produit un REFUS (code 2), parce que la
#    géométrie du document ne le reflète pas (mesuré le 2026-08-31). Sa validation ne peut donc
#    pas passer par la boucle des mutations, qui exige un manquement numéroté ; elle lit le champ
#    `forme` du verdict, dans les DEUX sens : sous la règle il NOMME le nœud fautif, sans elle il
#    vaut `null` sur les quatre sujets et les quatre cellules.
# =====================================================================================
def mutation_de_forme(ja: dict) -> tuple:
    hal = ja["hote"]
    aal = "." + ja["classe_aveu"].strip().split()[0]
    return ("FORME · aveu de page incomplète rogné par une FORME depuis un ANCÊTRE, en `@media` "
            "+ `:has()` — aucune géométrie ne le reflète, donc la garde doit REFUSER et le NOMMER",
            f"@media all {{ {hal}:has(> {aal}) {{ clip-path: inset(100%); }} }}",
            ("alertes", "aveuPage", "forme"))


def main() -> int:
    moteur = trouver_le_moteur()
    if not WEB.is_dir():
        refuser(f"`web/` est introuvable sous `{RACINE}` : rien à rendre.")
    j = deriver_du_module()
    ja = deriver_des_alertes()
    documents = {nom: batir_le_document(j, ja, langue, nom)
                 for (nom, langue, _lg, _h) in CELLULES}
    coquille = batir_la_coquille()

    print(f"[moteur] {moteur}")
    print("[cellules] " + " · ".join(f"{nom} ({langue}, {lg}x{ht})"
                                     for (nom, langue, lg, ht) in CELLULES))
    print(f"[dérivé de web/attack.js] hôte=#{j['hote']} · aveu=<{j['tag_aveu']} class=\"{j['classe_aveu']}\"> "
          f"· matrice=.{j['classe_matrice']} · cellule=<{j['tag_cellule']} class=\"{j['classe_cellule']}\"> "
          f"· compte=.{j['classe_compte']} · signe=« {j['signe']} » · aveu avant matrice={j['aveu_avant_matrice']}")
    for langue in ("fr", "en"):
        print(f"[phrase {langue} de web/attack.js] « {j['phrases'][langue]} »")
    print(f"[dérivé de web/alerts.js] hôte=`{ja['hote']}` · aveu de page=<{ja['tag_aveu']} "
          f"class=\"{ja['classe_aveu']}\"> · en-tête du compte=.{ja['classe_tete']} "
          f"· ligne=.{ja['classe_ligne']} · étiquette=« {ja['compte']} » "
          f"· aveu avant barre={ja['aveu_avant_barre']} "
          f"· barre avant lignes={ja['barre_avant_lignes']}")
    for langue in ("fr", "en"):
        print(f"[marque {langue} du compte] « {ja['phrases_compte'][langue].strip()} » "
              f"({len(ja['phrases_compte'][langue])} car.)")

    # --- SENS ROUGE, D'ABORD. Une mutation non attrapée = instrument aveugle = REFUS.
    #     CHAQUE MUTATION EST JUGÉE DANS LES QUATRE CELLULES, et son attente est un TABLEAU par
    #     cellule : `partout(...)` exige le rouge dans les quatre ; `seulement_etroit(...)` exige
    #     le rouge aux gabarits étroits ET LE VERT aux larges — cette moitié verte est ce qui
    #     démontre que le second gabarit voit ce que le premier ne peut pas voir.
    liste = mutations(j, ja)
    aveugles = []
    for nom, regle, attentes in liste:
        cellules_vues = rendre(moteur, documents, coquille, regle)
        resume, juges, avant = [], {}, len(aveugles)
        for (nc, _langue, _lg, _h) in CELLULES:
            attendues = attentes[nc]
            vus = juges[nc] = juger(cellules_vues[nc], nc)
            if not attendues:
                # LE VERT EXIGÉ : la règle ne doit RIEN accuser ici. Un manquement quelconque
                # démentirait que ce gabarit est aveugle à la règle, donc l'énoncé de la mutation.
                if vus:
                    aveugles.append(
                        f"« {nom} » (règle `{regle}`) attendue SANS EFFET dans la cellule `{nc}` "
                        f"— elle y accuse pourtant {len(vus)} manquement(s) : {vus}. Une règle "
                        "sous condition de largeur qui mord au MAUVAIS gabarit ne prouve plus "
                        "que le second gabarit apporte quoi que ce soit.")
                else:
                    resume.append(f"{nc}:vert(attendu)")
                continue
            manquantes = [p for p in attendues if not any(m.startswith(f"({p})") for m in vus)]
            if manquantes:
                aveugles.append(
                    f"« {nom} » (règle `{regle}`) attendue sur la/les propriété(s) "
                    f"{', '.join(str(p) for p in attendues)} DANS LA CELLULE `{nc}` — non "
                    f"accusée(s) : {', '.join(str(p) for p in manquantes)} ; la page est rendue "
                    f"avec cette règle et la garde n'accuse rien de tel ({len(vus)} "
                    f"manquement(s) : {vus})")
            else:
                resume.append(f"{nc}:" + ",".join(f"({p})" for p in attendues))
        if len(aveugles) == avant:
            premier = ""
            for (nc, _l, _lg, _h) in CELLULES:
                touches = [m for m in juges[nc] if attentes[nc]
                           and m.startswith(f"({attentes[nc][0]})")]
                if touches:
                    premier = touches[0][:150]
                    break
            print(f"[mutation vue] {nom} -> " + " ".join(resume) + (f" | {premier}" if premier else ""))

    # --- LA SONDE DE FORME, DANS LES DEUX SENS ET SUR SON PROPRE CANAL (le refus, pas le rouge).
    nom_f, regle_f, chemin_f = mutation_de_forme(ja)
    cellules_f = rendre(moteur, documents, coquille, regle_f)
    for (nc, _langue, _lg, _h) in CELLULES:
        n = cellules_f[nc]
        for cle in chemin_f:
            n = (n or {}).get(cle) if isinstance(n, dict) else None
        if not n:
            aveugles.append(
                f"« {nom_f} » (règle `{regle_f}`) : la cellule `{nc}` ne NOMME aucun rognage par "
                "une forme sur " + ".".join(chemin_f) + ". La garde verdirait donc sur une marque "
                "qu'une forme peut avoir entièrement effacée — et aucune géométrie du document ne "
                "le dirait (mesuré le 2026-08-31).")
    if not aveugles:
        print(f"[mutation vue] {nom_f} -> les {len(CELLULES)} cellules NOMMENT le rognage par une "
              f"forme ({(cellules_f[CELLULES[0][0]] or {}).get('alertes', {}).get('aveuPage', {}).get('forme')})"
              " · canal = REFUS DE CONCLURE (2), pas violation (1)")

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

    # --- SENS VERT. LES MÊMES QUATRE CELLULES, sans règle injectée.
    cellules_vertes = rendre(moteur, documents, coquille, "/* aucune mutation */")
    temoin_vert = []
    for (nc, langue, lg, ht) in CELLULES:
        for m in juger(cellules_vertes[nc], nc):
            temoin_vert.append(f"[{nc} · {langue} · {lg}x{ht}] {m}")

    # --- LE VERDICT sur la feuille de style RÉELLE.
    if temoin_vert:
        print(f"::error::(1) {len(temoin_vert)} propriété(s) VIOLÉE(S) — un aveu n'est pas "
              "peint là où il est lu :", file=sys.stderr)
        for m in temoin_vert:
            print(f"::error::  · {m}", file=sys.stderr)
        return CODE_VIOLATION

    rendus = len(liste) + 2
    print(f"[P11.21-k P11.21-l] VERT — {len(liste)} mutations injectées, jugées dans les "
          f"{len(CELLULES)} cellules ({' · '.join(nom for (nom, _l, _lg, _h) in CELLULES)}), ont "
          "TOUTES été vues rouges là où elles devaient l'être (dont DEUX masquages venus d'un "
          "ANCÊTRE en `:has()`/`@media` par une propriété qui NE S'HÉRITE PAS, deux ordres PEINTS "
          "inversés à rang de document INCHANGÉ, un rognage de fin de ligne qui coupe un démenti "
          "en laissant son nombre, et DEUX règles SOUS CONDITION DE LARGEUR qui mordent à 640 et "
          "restent SANS EFFET à 1600 — c'est cette moitié VERTE qui démontre qu'un seul gabarit "
          "ne suffisait pas) ; une mutation de plus NOMME un rognage par une FORME dans les "
          f"quatre cellules, sur le canal du REFUS. Sans elles, `{moteur}` peint les QUATRE aveux "
          "visibles, opaques, encrés, de rectangle non vide et dans le document, AUX DEUX "
          "GABARITS ET DANS LES DEUX LANGUES : celui de la matrice ATT&CK AU-DESSUS de la "
          "première cellule avec sa marque de sous-compte non rognée, celui de la PAGE INCOMPLÈTE "
          "des alertes AU-DESSUS du compte qu'il qualifie ET de la première ligne, et la marque "
          "du COMPTE INCOMPLET collée à son nombre, non rognée, au-dessus de la première ligne. "
          "CE QUE CE VERT NE DIT PAS : les balisages sont DÉRIVÉS de `web/attack.js` et de "
          "`web/alerts.js`, non produits par `loadAttackMatrix` ni `dessinerLaListePlate` — ce qui "
          "est jugé est la FEUILLE DE STYLE et la chaîne d'ANCÊTRES sur la forme que les modules "
          "déclarent émettre, et pour les alertes AUCUN autre banc ne fait exister ces deux aveux "
          "(les huit appels du harnais ESM omettent l'argument `etat`, mesuré le 2026-08-31) ; les "
          "deux panneaux sont peints dans le MÊME rendu, ce qui n'arrive pas dans la console ; "
          "AUCUN ROGNAGE N'EXISTE DANS LA FEUILLE RÉELLE À AUCUNE LARGEUR (mesuré le 2026-08-31 "
          "de 1600 à 360 px : la lignée entière de la marque du compte est `overflow: visible` et "
          "l'étiquette ne déborde jamais — elle retourne à la ligne ; le seul rogneur de la lignée "
          "du signe, `.attack-matrix`, ne défile à aucune de ces largeurs), donc ce que la "
          "propriété 3 et la propriété 6 tiennent est la capacité de VOIR un rognage, pas "
          "l'existence d'un rognage à corriger ; IL N'Y A TOUJOURS AUCUN TEST DE RECOUVREMENT — un "
          "nœud opaque peint PAR-DESSUS un aveu passe, et c'est un REFUS ARGUMENTÉ, mesuré le "
          "2026-08-31 : le seul test de collision qu'offre ce moteur, `elementFromPoint`, répond "
          "« ce qui INTERCEPTE le pointeur », et sous une nappe opaque en `pointer-events: none` "
          "— l'idiome ORDINAIRE d'un recouvrement — il rend l'aveu LUI-MÊME, donc un VERT sur la "
          "forme la plus courante du défaut ; le RAPPORT DE CONTRASTE n'est pas davantage imposé, "
          "et pas non plus approximé : le calculer justement demande l'encre COMPOSÉE sur son fond "
          "(mesuré le 2026-08-31, un rapport tiré nu de `getComputedStyle().color` IGNORE l'alpha "
          "de l'encre et annoncerait 6,67:1 pour une encre à 94 % transparente — un faux vert), et "
          "les valeurs du jour sont 6,82:1 pour l'étiquette du compte et 6,67:1 pour les deux "
          "aveux, donc aucune violation à cacher aujourd'hui.")
    print(f"[coût] {rendus} rendus ({len(liste)} mutations + 1 sonde de forme + 1 témoin vert), "
          f"chacun peignant les {len(CELLULES)} cellules dans UN seul passage du moteur.")
    return CODE_OK


if __name__ == "__main__":
    sys.exit(main())
