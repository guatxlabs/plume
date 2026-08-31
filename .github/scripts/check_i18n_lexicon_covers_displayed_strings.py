#!/usr/bin/env python3
"""Le lexique fr/en couvre les chaînes AFFICHÉES de chaque module web — garde de CI (`P11.8-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
La console traduit par DICTIONNAIRE : `web/i18n.js` porte une table FR -> EN, et `i18nWalk`
remplace un nœud texte (ou un attribut `title`/`placeholder`/`aria-label`) dont la valeur,
une fois les blancs retirés, est EXACTEMENT une clé. Une chaîne sans clé reste en français :
la dégradation est silencieuse, et elle s'accumule module après module sans qu'aucun outil ne
la voie. Un analyste en langue anglaise lit alors une console bilingue par accident.

CE QU'EST UNE « CHAÎNE AFFICHÉE » — LE CRITÈRE, ÉCRIT
-----------------------------------------------------
Une chaîne est AFFICHÉE si le code la pose dans un puits de rendu, c'est-à-dire :
  (1) une affectation `.textContent = `, `.innerText = `, `.title = `, `.placeholder = ` ;
  (2) une clé d'objet `label:`, `title:`, `placeholder:`, `okText:`, `cancelText:`, `message:`,
      `emptyText:`, `hint:`, `text:` ;
  (3) un appel `createTextNode(`, `muted(`, `toast(`, `showErr(`, `confirmModal(`,
      `confirmWithConsequence(`, `append(`, `prepend(`, `emptyRow(`, ou `setAttribute(` dont le PREMIER
      argument est un attribut affiché
      (`title`, `placeholder`, `aria-label`, `label`) ;
  (4) le TEXTE entre balises et les attributs `title`/`placeholder`/`aria-label` d'un littéral
      HTML (chaîne contenant une balise, posée en `innerHTML` ou construite en gabarit) ;
  (5) le texte et les mêmes attributs de `web/index.html`.
Le mécanisme ne peut traduire qu'une chaîne STATIQUE : une chaîne concaténée (`'a' + x`) ou
interpolée (`${x}`) ne sera jamais égale à une clé — elle est comptée À PART (« dynamique »),
hors du dénominateur, et rendue pour information. En fait PARTIE un littéral qui n'est qu'un FRAGMENT
d'une valeur composée : la branche d'un ternaire opérande de `+` (`a + (c ? 'x' : 'y')`), et le texte de
BORD d'un littéral HTML collé à une expression (`'<div>erreur : ' + msg`). Le nœud rendu vaut alors le
littéral PLUS ce qui s'y colle ; lui donner une clé produirait une entrée morte, jamais un affichage
traduit. Mesuré le 2026-08-23 : 15 chaînes sortent ainsi de la population, 7 d'entre elles étant apparues
comme des « trous » que le lexique n'aurait pas pu combler. Une chaîne composée UNIQUEMENT de
minuscules ASCII, chiffres et de ponctuation technique (`src_ip`, `count`, `/api/x`) est un identifiant
technique, identique dans les deux langues : hors population. LA CLASSE INCLUT L'ESPACE, et une phrase
française entière tout en minuscules (`aucun runbook`) y entrait donc comme `src_ip` — MÊME dans un puits
reconnu, une seule majuscule suffisant à faire basculer le verdict (mesuré le 2026-08-23 : 64 chaînes sur
25 modules, cause de trou INDÉPENDANTE de la forme d'écriture). La règle est désormais dérivée : DEUX MOTS
ALPHABÉTIQUES CONSÉCUTIFS font une phrase, pas un identifiant ; de même un code en MAJUSCULES
sans espace qui porte un chiffre ou tient en quatre signes (`T1110`, `CSV`, `OK`). Une chaîne
sans lettre (un symbole, un nombre) est hors population. Le texte d'un ÉCHANTILLON DE CODE
(`<code>`, `<kbd>`, `<pre>`, `<samp>`) est montré tel quel dans les deux langues : hors population,
comme un `<script>`. Une chaîne choisie par `LANG === 'en' ? … : …` ou posée dans un bloc
`if (LANG === 'en') { … }` est bilingue PAR CONSTRUCTION (son pendant FR est ailleurs) : couverte
sans passer par le lexique ; de même une valeur posée sous une clé `fr:` ou `en:` d'un objet (`{ fr: '…',
en: '…' }`, choisi par LANG à l'endroit du rendu) : les deux langues sont côte à côte. Les attributs
affichés sont `title`, `placeholder`, `aria-label` et `label` (groupe d'options) — ce sont ceux que
`i18nWalk` traduit.

CE QUE LA GARDE NE VOIT PAS — MESURÉ, PUBLIÉ, ET GARDÉ
------------------------------------------------------
Le critère de puits ci-dessus est ÉTROIT, et une garde qui rend vert sur ce qu'elle ne regarde pas est
pire qu'une garde absente. Elle publie donc, par module et à chaque exécution, une colonne HORS-REGARD :
les littéraux qui ont la forme d'un libellé (candidats, statiques, pas bilingues par construction) et
qu'aucun puits reconnu ne porte — argument d'une fabrique propre au module (`opt(...)` dans alerts.js,
`tile(...)` / `mesureTile(...)` dans system.js, `kv(...)` ailleurs), branche de ternaire hors puits, entrée
de tableau, valeur de retour, valeur sous une clé d'objet qui ne nomme aucune propriété du document
(`emptyText:`, `page:`, `servies:`), et un SIXIÈME poste qui ne nomme rien — « forme non classée », le repli
du classeur quand rien avant le littéral n'est reconnu. Ce poste n'est pas un détail : relevé le 2026-08-26,
il pesait 114 occurrences sur 716 (15,9 %), quatrième de la répartition. Il tient surtout le repli d'un `||`
(`toast((e && e.message) || '…')`), qui est bien de l'indécidable, et aussi des opérandes de COMPARAISON
(`if (e.key === 'Escape')`) qui, eux, n'affichent jamais rien : c'est du BRUIT dans l'aveu, du même genre que
les classes CSS avant leur retrait, et ce n'est PAS corrigé ici — c'est dit. CETTE RÉPARTITION EST PUBLIÉE, PAS DÉCRITE : elle est dérivée du
contexte de chaque littéral à chaque exécution, postes et clés portantes en tête, et l'anti-corpus vérifie
que chaque forme reçoit bien le nom qu'elle doit recevoir — un aveu qui dirait COMBIEN sans dire QUOI ne
désignerait plus rien. Un littéral
posé dans un NON-PUITS reconnu (classe CSS, identifiant, style, attribut non affiché) n'y figure PAS : la
colonne ne nomme que ce dont la garde ne peut pas décider, jamais ce qu'elle sait déjà hors sujet.
LA CONFESSION EST DÉRIVÉE DU DÉPÔT, PAS ÉCRITE À LA MAIN : la garde compte combien de ces hors-regard sont
DÉJÀ des clés du lexique. Relevé le 2026-08-23 : 680 hors-regard, dont 169 (24,9 %) au lexique — c'est le
dépôt lui-même qui atteste qu'ils sont affichés, et donc que le périmètre regardé est plus étroit que
l'affichage. Le chiffre est GARDÉ par un cliquet au même titre que les trous (`PLAFOND_HORS_REGARD`).
Restent hors de tout compte, et donc invisibles même à cette colonne : un mot en minuscules ASCII
(`frais`, `statut`) exclu par le critère d'identifiant alors qu'il peut être un libellé, une chaîne
dynamique, et un texte posé par un nœud puis RETRAITÉ par une concaténation. Les biais vont dans le sens
d'un SOUS-compte ; la garde mesure un plancher de la dette, jamais son plafond.
Elle ne juge pas non plus si le MÉCANISME applique le lexique : c'est le harnais ESM
(`web_esm_harnais.mjs`, témoin 10) qui rend un panneau sous `LANG='en'` et lit le texte. Une paire
`{ fr, en }` dont les deux valeurs seraient le même texte n'est pas jugée ici (le registre l'est par le
témoin 13 du harnais : chaque section rend un anglais distinct du français).

LA GARDE NE MESURAIT QUE LE MANQUE — ELLE MESURE AUSSI L'EXCÈS (`P11.8-g`)
---------------------------------------------------------------------------
Tout ce qui précède ne va que dans UN SENS : une chaîne affichée a-t-elle une entrée ? L'INVERSE n'était
mesuré par rien — une entrée dont la chaîne source a été RETIRÉE du code survit, et la batterie reste
verte. Mesuré le 2026-08-29 : la clé « Gouvernance d'accès (style Varonis) : … » vivait encore à
`web/i18n.js:527` alors que `web/dataaccess.js` ne servait plus ce bandeau, et `web/help_registry.js`
en sert une AUTRE. Un instrument qui sait ne regarder qu'une moitié et rend son vert comme un verdict
complet est exactement le défaut que ce fichier combat partout ailleurs.
CE QUE « MORTE » VEUT DIRE, ET POURQUOI L'ACCUSATION EST RARE. `i18nWalk` ne remplace un nœud que si son
texte ENTIER, blancs retirés, ÉGALE une clé. Une clé est donc vivante s'il existe, quelque part, un nœud
qui vaut exactement ce texte — et ce nœud naît de trois façons, dont la garde ne sait lire qu'une :
  1. un littéral posé dans un PUITS RECONNU : c'est la population déjà mesurée. VERDICT : VIVANTE.
  2. un texte présent dans le dépôt mais hors d'un puits reconnu — hors-regard, littéral dynamique,
     attribut non lu, valeur rendue par le démon. VERDICT : INDÉCIDABLE, la clé est NOMMÉE.
  3. un nœud COMPOSÉ (`'connecteur ' + etat`) : le texte entier n'est écrit nulle part, il s'ASSEMBLE.
     VERDICT : INDÉCIDABLE dès qu'un littéral de l'arbre servi peut en former le BORD, sur une frontière
     de mot — un assemblage coupe entre les mots, jamais au milieu de l'un d'eux.
N'est ACCUSÉE qu'une clé dont AUCUN de ces trois chemins n'existe. Le reste est nommé, jamais accusé :
une sonde qui accuse sur la seule absence a rendu 138 clés le 2026-08-29, en écrasante majorité des
concaténations et du texte d'`index.html` — elle aurait fait retirer des clés VIVANTES, c'est-à-dire
cassé l'anglais en croyant faire le ménage. LE SENS DE L'ERREUR EST CHOISI : taire une orpheline coûte
une entrée morte, en inventer une coûte un libellé français servi à un lecteur anglophone.
LE CORPUS EST DÉRIVÉ, ET CHACUNE DE SES EXCLUSIONS EST MOTIVÉE. Tout fichier texte du dépôt, sauf le lexique
lui-même, tout ce qui PORTE un nom qui ne livre rien à un navigateur — répertoire OU fichier (`.git`,
`target`, `node_modules`, et `.github` — sans quoi la garde ressusciterait toute clé qu'elle NOMME dans son
propre commentaire) —, et
les `*.md`, qui ne sont pas SERVIS : une phrase citée dans un document ne fait pas vivre une clé — et le
2026-08-29 DEUX des orphelines alors prouvées ne subsistaient QUE dans `docs/`, dette de documentation en
plus de la dette de lexique, l'une et l'autre payées ce jour-là (le titre servi, « Identité fédérée (SSO) »
comme « Politiques de notification », était DÉJÀ une clé : l'anglais n'a rien perdu au retrait du doublon).
Le corpus porte le source TEL QU'ÉCRIT **et**, quand elles en diffèrent, DEUX copies : DÉSÉCHAPPÉE
(`qu\\'aucun` -> `qu'aucun`) et ENTITÉS RÉSOLUES (`ATT&amp;CK` -> `ATT&CK`). Sans la première, la sonde
accuse les DEUX titres que `web/alerts.js` sert dans une interpolation à guillemets échappés (« Toutes les
alertes sont listées… » et « Seules les alertes qu'aucun cas n'a encore reprises… ») ; sans la seconde, elle
a RÉELLEMENT accusé « (standard ouvert) pour combler les angles morts ATT&CK. » au motif « texte absent du
dépôt ENTIER » alors que `web/sigmaimport.js:194` l'écrit — trois accusations dont le MOTIF est faux, et
`web/index.html` porte à lui seul 59 entités (21 `&amp;`, 12 `&rarr;`…) qui attendaient le même sort.
LES COMMENTAIRES RESTENT DANS LE CORPUS, DÉLIBÉRÉMENT. Un commentaire ne devient jamais un nœud, et les
retirer élargirait l'accusation (« ← Retour », que `web/app.js` dit lui-même « supprimé » ; « (drillé) » ;
« voir le détail → »…). La garde préfère TAIRE une orpheline que d'en inventer une : un commentaire qui cite
encore la phrase EMPÊCHE l'accusation. C'est dit, ce n'est pas corrigé — le biais va vers l'INDÉCIDABLE,
jamais vers l'accusation.
CHAQUE MOITIÉ DE CE CHOIX EST CHIFFRÉE À PART, PAR CROISEMENT SUR UN SEUL ARBRE (2026-08-29, arbre du jour,
les dix-huit orphelines déjà retirées) : ce qui est LIVRÉ -> 0 orpheline · sans déséchappement -> +2 ·
commentaires retirés -> +8 · ni l'un ni l'autre -> +10 · sans résolution d'entités -> +0 aujourd'hui, mais
+1 la veille, sur un jeu de clés qui portait encore celle d'`ATT&amp;CK`. Un ÉCART se refait sur n'importe
quel arbre, un ABSOLU se périme sous les autres agents : ce sont le +2 et le +8 qui sont des propriétés de
l'INSTRUMENT, et eux seuls que ce paragraphe a le droit d'affirmer — REFAITS À L'IDENTIQUE le 2026-08-29
sur un arbre et un jeu de clés différents de celui qui les avait produits, ce qui est la seule chose qui
distingue une propriété d'un relevé. Le +0 des entités, lui, est un ABSOLU du jour : il ne dit pas que la
copie est inutile, il dit qu'aucune clé SURVIVANTE n'en dépend.
TROIS VERDICTS, TROIS CANAUX SÉPARÉS. Orpheline PROUVÉE au-dessus de son cliquet = RÉGRESSION (code 1) ;
compte des INDÉCIDABLES au-dessus du sien = REFUS DE CONCLURE (code 2) — une clé que la sonde ne sait pas
trancher n'est pas une faute, c'est un aveu, et le confondre avec une faute ferait rougir qui écrit un
libellé légitime dans une forme non lue. Les deux comptes sont PUBLIÉS à chaque exécution ; `--exces`
nomme chaque clé avec le verdict qui la tient.

L'EXEMPTION EST UNE SURFACE, PAS UN MODULE
-----------------------------------------
Le REGISTRE des sections d'aide (`{clé: {fr:{title,body}, en:{title,body}}}`) est le seul texte de la
console qui porte ses deux langues dans des objets imbriqués que le critère ci-dessus ne lit pas (la valeur
est sous `title:`/`body:`, à l'intérieur de `fr:`/`en:`). Seule la PORTÉE de sa définition `const HELP = {
… }` est exemptée : le module qui la porte est DÉRIVÉ (celui de `web/` qui la contient, commentaires
retirés — dérivation et portée importées de `check_every_help_trigger_has_a_section.py`), et ce qui
l'entoure dans ce module est jugé au plafond zéro comme tout autre. S'il n'est pas retrouvé, la garde
refuse de conclure plutôt que de le rendre sans le juger. Avant (2026-08-22) : la mécanique de l'aide
(`help.js`) était exemptée en ENTIER au motif que ses modales choisissaient leur langue par `LANG` — et
cette exemption cachait tout ce que le module pouvait poser en dur : l'anglais d'un titre dupliqué hors
lexique, un mot nu sans clé. Une exemption de module ne voit rien ; une exemption de surface voit le reste.

LA GARDE REFUSE UNE RÉGRESSION, PAS UN ÉTAT
-------------------------------------------
Le taux de couverture (clés présentes / population) est mesuré et rendu PAR MODULE ; ce qui
est GARDÉ est DOUBLE : le nombre de chaînes affichées SANS entrée (les « trous ») et le nombre de
littéraux HORS-REGARD, chacun comparé à un PLAFOND écrit ici avec sa date. Pourquoi le compte et non le
taux : un taux ne voit pas UNE chaîne de plus parmi six cents (20,6 % -> 20,4 %), le compte la voit.
Ajouter une chaîne affichée sans l'inscrire au lexique fait dépasser le plafond : rouge. Poser un libellé
neuf dans une forme que la garde ne lit pas fait dépasser l'autre : rouge aussi, alors même que la garde
ne sait pas lire cette forme — c'est le seul moyen qu'un périmètre étroit ne serve pas d'échappatoire.
Traduire abaisse le premier compte, déplacer un libellé vers un puits reconnu abaisse le second ; abaisser
un plafond est le seul sens de modification admis sans raison écrite à côté.
CE QUE LE CLIQUET LAISSE PASSER EST PUBLIÉ AVEC LE VERDICT. Un plafond peut rester AU-DESSUS de son relevé :
ce n'est pas une régression, c'est du JEU — la place exacte que des libellés neufs peuvent prendre sans faire
rougir personne. Écrit à la main dans un commentaire, ce jeu est daté d'un jour et faux le lendemain (mesuré :
`dashboards.js` a porté 25 pour 22 relevés). La garde le DÉRIVE donc de la mesure du jour et le rend à chaque
exécution, module par module (ligne « JEU DU CLIQUET »). Elle ne force pas la descente — elle refuse la
hausse et dit ce qu'elle laisse passer.
UN MODULE MESURÉ SANS PLAFOND FAIT REFUSER DE CONCLURE. Le verdict parcourait les PLAFONDS, pas les
modules : un module absent de la table était rendu au tableau et jamais jugé (`composer_depuis_lexistant.js`
l'a été de sa création au 2026-08-23). L'asymétrie est levée : plafond sans module = régression, module
sans plafond = code 2.

LE DÉCOUPEUR AVOUE CE QU'IL N'A PAS SU LIRE
-------------------------------------------
Tout ce qui précède repose sur un DÉCOUPEUR : un lecteur de source qui isole les littéraux du code qui les
entoure. Un découpeur qui se trompe ne rougit pas — il ne voit simplement plus rien dans la région qu'il a
mal lue, et le compte tombe SANS QUE PERSONNE NE LE SACHE. C'est arrivé : le sauteur d'interpolation
`${…}` savait éviter les chaînes et les gabarits imbriqués, mais pas les littéraux d'expression régulière.
Un `"` à l'intérieur d'un motif (`` `"${String(v).replace(/"/g, '')}"` ``) ouvrait donc une fausse chaîne,
et le lecteur avalait la suite. Mesuré le 2026-08-24 par comparaison de deux lecteurs sur `web/` : UNE
région, dans UN module (`viz.js`, lignes 46 à 179), 118 littéraux disparus — dont une chaîne affichée que
le lexique ne couvrait pas, et deux littéraux INVENTÉS (un morceau de code source lu comme du texte).
La colonne HORS-REGARD ne pouvait rien y faire : la région n'existait plus pour elle non plus.
DEUX RÉPONSES, PARCE QU'UNE SEULE NE SUFFIT PAS :
  1. LE DÉCOUPEUR RECONNAÎT LE LITTÉRAL D'EXPRESSION RÉGULIÈRE, partout et par le même code
     (`saute_regex`, règle `RE_AVANT_REGEX`) — la désambiguïsation du `/` se fait sur le JETON PRÉCÉDENT,
     et cette règle est écrite une fois, avec ce qu'elle ne sait pas faire, à côté de `RE_AVANT_REGEX`.
  2. IL DIT QUAND IL A PERDU LE FIL. La règle du jeton précédent ne peut pas être juste dans tous les cas
     sans une grammaire complète ; alors le lecteur surveille ce qu'un module JS valide ne peut PAS
     produire — une chaîne qui se termine sur une fin de ligne, un littéral qui atteint la fin du fichier.
     L'un de ces signes prouve qu'il a ouvert un littéral qui n'en était pas un. La garde refuse alors de
     conclure (code 2) en NOMMANT la ligne, au lieu de rendre un compte amputé en vert. L'aveu nomme
     l'endroit où le lecteur s'aperçoit de la perte, pas forcément celui où elle a commencé (sur `viz.js`,
     il l'aurait dite à la ligne 153 pour une désynchronisation née à la ligne 44) : il borne la confiance,
     il ne remplace pas la lecture.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Un extracteur rend vert de deux façons : tout va bien, ou son motif ne reconnaît plus rien.
La garde exécute d'abord un corpus de contrôle (chaînes qu'elle DOIT reconnaître dans chaque
puits, chaînes qu'elle NE DOIT PAS compter : classe CSS, identifiant, chaîne dynamique,
commentaire), puis un ANTI-CORPUS — les formes qu'elle NE VOIT PAS, avec l'assertion qu'elle ne les voit
pas et qu'elle les rend en hors-regard. Un corpus qui n'a que des « ne doit pas compter » ne peut jamais
dire que le périmètre a bougé ; l'anti-corpus le dit : si la garde apprend à lire une de ces formes, le
témoin CASSE et force la mise à jour de l'aveu avant tout verdict. Elle exige ensuite un PLANCHER de
population sur l'arbre réel, la présence d'une clé témoin connue, et qu'aucun module mesuré ne soit hors du
cliquet. Sans ces jambes, elle refuse de conclure (code 2), elle ne rend pas vert.

Usage :  python3 .github/scripts/check_i18n_lexicon_covers_displayed_strings.py
             [--mesure] [--trous MODULE] [--hors-regard MODULE] [--exces] [--noeuds]
Sortie :  0 = aucun module au-dessus de ses plafonds et aucune orpheline de trop ;
          1 = régression (trous, hors-regard, ou ORPHELINE PROUVÉE au-dessus du cliquet) ;
          2 = instrument invalide, module mesuré hors du cliquet, découpeur désynchronisé, ou compte
          d'INDÉCIDABLES au-dessus du sien — la garde refuse alors de conclure au lieu d'accuser.
          `--mesure` imprime le tableau par module sans verdict (c'est ce qui sert à relever le compte
          d'un module neuf) ; `--trous MODULE` liste les chaînes du module sans entrée au lexique ;
          `--hors-regard MODULE` liste ce que la garde ne regarde pas dans ce module, en marquant celles
          qui sont déjà des clés du lexique ; `--exces` nomme chaque clé du lexique que rien ne sert
          (orpheline prouvée) et chaque clé que la sonde ne sait pas trancher, avec son motif ;
          `--noeuds` nomme chaque NŒUD RENDU sans clé qui traverse une borne de littéral, et chaque
          fragment de balisage que l'analyseur refuse de lire (`P11.8-i`).
"""
from __future__ import annotations

import collections
import html.parser
import html
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    RE_AVANT_REGEX, journaliser_perte, module_du_registre, portee_du_registre, refuser_sur_aveu,
    sans_commentaires_js, saute_regex, temoins_du_lecteur)

RACINE = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB = os.path.join(RACINE, "web")
LEXIQUE = os.path.join(WEB, "i18n.js")
# LA RECETTE DES TROIS PLANCHERS, ÉCRITE UNE FOIS ET APPLIQUÉE PAR LE CODE (`P11.8-k`, 2026-08-31).
# CE FICHIER A TENU PENDANT CINQ JOURS UNE PROPRIÉTÉ PLUS FAIBLE QUE CELLE QU'IL ÉCRIVAIT. La recette
# « le relevé moins un vingtième » était écrite à trois endroits, et les trois valeurs étaient POSÉES À LA
# MAIN : rien ne les rattachait à la phrase, et le retard ne se voyait pas dans le chiffre. Mesuré le
# 2026-08-31 sur HEAD `6f0a5ad`, arbre PROPRE : la population regardée tolérait 10,44 % de perte pour 5 %
# affichés — PLUS DU DOUBLE de ce qu'elle affirmait tolérer (plancher 1 845 pour un relevé de 2 060, dérivé
# 1 957) ; le corpus 7,17 % (32 803 575 pour 35 335 969, dérivé 33 569 170) ; les clés vivantes 5,10 %
# (1 507 pour 1 588, dérivé 1 508). Un lecteur qui croyait la recette croyait une tolérance deux fois plus
# étroite que celle qui était tenue.
# ET IL FAUT LIRE CE « DOUBLE » AVEC CE QUI SUIT, SANS QUOI IL FAIT CROIRE À UN TROU QUI N'EXISTAIT PAS.
# Le facteur 2,09 est vrai DE LA CONSTANTE ; il est FAUX DE LA GARDE, et c'est la mesure qui le dit, pas la
# prudence. Trois mutations calibrées le 2026-08-31 pour tomber DANS le retard — dans un `git archive HEAD`,
# des puits neutralisés sans qu'un octet de texte quitte l'arbre : `cases.js` (population 1 955),
# `dashboards.js`+`risk.js` (1 945), `help.js` (1 887), toutes AU-DESSUS de l'ancien plancher de 1 845 :
# l'ANCIENNE garde a refusé de conclure les TROIS FOIS. Jamais sur la population — celle-là se taisait bien —
# mais sur `MIN_CLES_VIVANTES` (1 502 puis 1 499 pour un plancher de 1 507) et sur `PLAFOND_INDECIDABLES`.
# LA RAISON EST STRUCTURELLE, ET ELLE VAUT POUR TOUTE FAMILLE DE PLANCHERS : ces trois grandeurs NE SONT PAS
# INDÉPENDANTES. Perdre 105 chaînes affichées a coûté 86 clés vivantes ; le plancher le plus LÂCHE était
# masqué par le plus SERRÉ, qui n'avait qu'une unité de retard. Ce que ce resserrage achète n'est donc PAS
# un rattrapage mesurable sur cet axe — aucune mutation n'a été trouvée où l'ancienne garde rendait vert et
# la neuve refuse. Il achète que le fichier dise vrai, et que le retard ne puisse plus se rouvrir en
# silence. Un lot qui prétendrait avoir fermé un angle mort ici mentirait ; celui-ci ferme un ÉCART ENTRE
# UNE PHRASE ET UNE VALEUR, ce qui est un autre défaut et se paie quand même.
# LE GESTE N'EST PAS D'AMENDER LA PHRASE POUR QU'ELLE DISE 10 %. Ce serait ratifier une dérive que personne
# n'a décidée, et il faudrait la ré-amender à chaque fois que l'arbre grossit : la recette deviendrait « ce
# que le retard vaut aujourd'hui », c'est-à-dire rien. C'est la VALEUR qui suit la recette, et c'est le CODE
# qui l'applique. Seul le RELEVÉ reste écrit à la main — avec sa date ET le commit d'où il sort. L'écart
# entre la recette et la constante n'est plus une question de discipline : il est devenu IMPOSSIBLE à écrire.
# CE QUE CETTE DÉRIVATION NE FERME PAS, ET IL FAUT LE DIRE : le RELEVÉ, lui, peut encore prendre du retard
# quand l'arbre grossit. C'est la ligne « MARGE DES PLANCHERS » du verdict qui le publie à chaque exécution,
# et elle ne rougit pas — délibérément (voir sa propre note). Ce lot ferme l'arithmétique, pas l'oubli.
# LA DOCTRINE, TRANCHÉE ICI PARCE QUE CE FICHIER EN PORTAIT DEUX MOITIÉS QU'ON POUVAIT LIRE COMME
# CONTRAIRES : à côté de `MIN_CORPUS` il était écrit que le plancher SUIT le relevé, à côté de
# `MIN_POPULATION` qu'il NE BOUGE PAS. Les deux disent la même règle dès que la DIRECTION est nommée, et
# c'est la direction qui manquait : LE PLANCHER MONTE AVEC UN RELEVÉ ATTRIBUABLE — un arbre commité, daté,
# nommé — ET NE DESCEND JAMAIS POUR SUIVRE UNE MESURE PLUS BASSE. Ce qui reste interdit, et que ce fichier
# ne fera pas : dériver un plancher du corpus COURANT à l'exécution. Il suivrait exactement la baisse qu'il
# a pour tâche de refuser — un cliquet qui descend tout seul, c'est-à-dire l'inverse d'un cliquet.
# `MIN_CLES` n'est PAS de cette famille et n'a pas à suivre la recette : il ne garde que la LECTURE du
# lexique, il est bas EXPRÈS, et sa note le dit à côté de lui. Trois planchers suivent la recette, un
# quatrième s'en exempte avec sa raison écrite ; il n'y en a pas d'autre.


def plancher_depuis_releve(releve: int) -> int:
    """Le relevé moins un vingtième, en ENTIER EXACT (`* 19 // 20`), jamais un flottant.

    C'EST LA TRONCATURE QUI EST LA BONNE VALEUR, PAS L'ARRONDI À 5,00 %. Mesuré le 2026-08-30 en livrant
    le témoin de `P8.27-g` : comparé à un seuil de 5,00 % en flottant, un plancher posé EXACTEMENT selon
    cette recette se faisait accuser — `1588 * 19 // 20` vaut 1 508, et 1 588 - 1 508 fait 5,04 %, au-dessus
    de 5,00 par la seule troncature entière. Un témoin qui accuse un geste juste est un témoin qui ment.
    La ligne « MARGE DES PLANCHERS » du verdict appelle donc cette MÊME fonction : la valeur gardée et la
    valeur publiée ne peuvent plus diverger, puisqu'elles sortent du même calcul."""
    return (releve * 19) // 20


# Plancher de population sur l'arbre réel : en dessous, c'est l'extraction qui est cassée.
# DÉRIVÉ DU RELEVÉ, PAS CHOISI. Relevé le 2026-08-23 : 1 926 chaînes statiques affichées REGARDÉES, tous
# modules confondus (échantillons de code, fragments de concaténation et blocs `if (LANG === 'en')` retirés de
# la population ; 1 834 avant que la règle des deux mots ne fasse entrer les phrases tout en minuscules). Le
# plancher est ce relevé moins un vingtième : une extraction qui perdrait plus de 5 % de sa portée refuse de
# conclure.
# La valeur précédente (1 000, pour un relevé annoncé à 1 579 et réel à 1 834) laissait l'extraction perdre
# 45 % de sa portée sans que la validation d'instrument bronche : un plancher sous la moitié du réel ne garde
# rien, il donne seulement l'apparence d'un garde-fou.
# 2026-08-24 (`P11.8-e`) : le relevé passe de 1 926 à 1 928 — deux chaînes affichées de `web/viz.js` que le
# découpeur ne voyait plus depuis qu'un `"` dans une expression régulière le désynchronisait à la ligne 44.
# Le plancher suit la même dérivation (relevé moins un vingtième) : 1 831.
# 2026-08-26 (`P11.8-c`) : +15 chaînes affichées que le critère de puits ne lisait pas — la valeur posée sous
# une clé d'objet qui NOMME une propriété d'affichage (`Object.assign(el, { textContent: … })`). L'écart est
# ISOLÉ (deux instruments, même arbre) parce que l'arbre bougeait sous six agents : 1 928 + 15 = 1 943, et le
# plancher suit la même dérivation (relevé moins un vingtième) : 1 845.
# CE QUE L'ARBRE MESURE VRAIMENT, ET CE QUI A ÉTÉ RÉFUTÉ DEUX FOIS. La même ligne annonçait « l'arbre du jour
# en mesure 1 945 » : aucun instrument ne rend ce chiffre. Mais les deux nombres écrits ICI pour le réfuter
# (« 1 940 sur l'arbre livré, 1 929 avec l'instrument de HEAD ») ne se retrouvent pas non plus — rejoués le
# 2026-08-26 à 21 h sur l'arbre de travail, les deux instruments rendent 1 946 et 1 957, soit +17 de chacun.
# LA CAUSE EST MESURÉE, PAS SUPPOSÉE : `web/` bouge sous plusieurs agents (`web/alerts.js` a été réécrit à
# 20 h 26 min 26 s, la garde ci-présente à 20 h 26 min 02 s — 24 secondes plus tôt). UN NOMBRE ABSOLU DE
# POPULATION N'EST PAS UNE PROPRIÉTÉ DE L'INSTRUMENT, C'EST UNE PROPRIÉTÉ DE L'ARBRE, et le citer sans dire
# QUEL arbre le rend non reproductible avant la fin de la journée. Il s'en écrit donc désormais deux choses,
# toutes deux vérifiables sans dépendre du jour :
#   1. L'ANCRE EST UN ARBRE IMMUABLE. Sur `web/` de HEAD `207f51a` (que rien ne peut plus réécrire) :
#      instrument de HEAD -> 1 922 ; instrument du jour -> 1 933. Ces deux nombres se refont en deux commandes,
#      aujourd'hui comme dans un mois (`git archive HEAD web` dans un miroir, la garde copiée dedans — elle
#      dérive sa racine de `__file__` et IGNORE `argv[1]`).
#   2. CE QUI EST UNE PROPRIÉTÉ DE L'INSTRUMENT, C'EST L'ÉCART, et il est INVARIANT PAR L'ARBRE : +11 sur
#      `web/` de HEAD (1 922 -> 1 933) comme sur `web/` de travail (1 946 -> 1 957). C'est l'écart qui vaut
#      +11 et non +15, et c'est lui seul que ce commentaire avait le droit d'affirmer.
# CETTE LIGNE DISAIT « le plancher, lui, ne bouge pas », ET C'ÉTAIT UNE MOITIÉ DE RÈGLE QUI A COÛTÉ CINQ
# JOURS DE RETARD (`P11.8-k`, amendée le 2026-08-31). Ce qu'elle voulait dire est vrai et reste écrit : un
# plancher ne DESCEND jamais pour suivre une mesure plus basse — il ne garderait plus rien. Ce qu'elle
# laissait croire est faux : il MONTE avec un relevé ATTRIBUABLE, sans quoi la propriété qu'il affirme
# devient fausse en silence. Ancré sur le relevé de 1 943 du 2026-08-26, il a laissé l'extraction perdre
# 10,44 % de sa portée en en annonçant 5.
# 2026-08-31 (`P11.8-k`) : relevé 2 060 sur HEAD `6f0a5ad`, arbre PROPRE — `git status --porcelain` vide,
# aucun fichier de l'arbre touché depuis 30 min, empreinte `git ls-files -s` identique à trois relevés
# espacés. LA RAISON POUR LAQUELLE LE RESSERRAGE N'AVAIT PAS ÉTÉ FAIT LA VEILLE A CESSÉ D'EXISTER, ET C'EST
# MESURÉ, PAS SUPPOSÉ : la valeur aurait alors été dérivée d'un arbre portant du travail NON COMMITÉ, ce
# qui aurait fait d'elle un rouge faux. Elle est aujourd'hui attribuable à un commit qu'on peut citer.
# Le plancher n'est plus écrit : il est DÉRIVÉ du relevé par la recette de ce fichier.
RELEVE_POPULATION = 2060      # 2026-08-31, HEAD `6f0a5ad`, arbre propre (avant : 1 943 le 2026-08-26)
MIN_POPULATION = plancher_depuis_releve(RELEVE_POPULATION)   # 1 957 — marge mesurée : 103 chaînes affichées
# Une clé dont on SAIT qu'elle est affichée par `web/index.html` (bouton d'exécution de la barre).
CLE_TEMOIN = "Exécuter"
# Plancher de clés du lexique : relevé le 2026-08-22, 223 clés avant complément, 1 594 après ; 1 719 au
# 2026-08-23, puis 1 772 après le complément des phrases tout en minuscules. Ce plancher ne garde que la
# LECTURE du lexique, pas sa taille : il reste bas exprès.
MIN_CLES = 150

# PLAFOND DE TROUS PAR MODULE (chaînes affichées statiques sans entrée au lexique). Relevé le 2026-08-22 par
# `--mesure` : chaque module suivi est à ZÉRO après complément du lexique (1 579 chaînes affichées, toutes
# couvertes ; 1 594 clés) ; toujours zéro partout au 2026-08-23 (1 834 chaînes regardées, 1 719 clés). Le
# cliquet est donc au plancher : toute chaîne affichée neuve entre au lexique ou rougit. Un module absent
# d'ici n'est plus rendu sans être jugé : depuis le 2026-08-23 il fait REFUSER de conclure (code 2).
# Relever un plafond exige une raison écrite à côté.
# Historique du cliquet : 2026-08-22, index.html 513 -> 496 (`P11.2-c`, `P11.7-a`), puis 496 -> 0 ; app.js 143 -> 0 ;
# connectors.js 49 -> 0 ; detadv.js 37 -> 0 ; detection_admin.js 35 -> 0 ; freshness.js 31 -> 0 ; retention.js 30 -> 0 ;
# admin_users.js 29 -> 0 ; sigmaimport.js 27 -> 0 ; sources.js 26 -> 0 ; idp.js 23 -> 0 ; suppressions.js inscrit à 0
# (41 trous avant, module jusque-là rendu sans être jugé) ; les quinze modules sous 20 trous à 0 (`P11.8-a`) ;
# help.js inscrit à 0 le 2026-08-22 (`P11.8-b`) : 32 trous sous l'exemption de module, dont 20 libellés d'interface
# en ternaire `en ? … : …` que la garde ne lisait pas et 12 fragments de deux corps d'aide déplacés au registre.
# i18n_observer.js inscrit à 0 à sa création (amorçage du lexique extrait d'app.js, déplacement pur : 0 trou mesuré).
# dataaccess.js inscrit à 0 à sa création (panneau d'accès données extrait d'app.js, déplacement pur : 0 trou mesuré).
# lookups.js inscrit à 0 à sa création (lookups extraits d'app.js, déplacement pur : 0 trou mesuré).
# dashboards.js inscrit à 0 à sa création (dashboards extraits d'app.js, déplacement pur : 0 trou mesuré).
# login.js inscrit à 0 à sa création (écran de connexion extrait d'app.js, déplacement pur : 0 trou mesuré).
# navigation.js inscrit à 0 à sa création (navigation à 2 niveaux extraite d'app.js, déplacement pur : 0 trou mesuré).
# recherche_de_liste.js inscrit à 0 à sa création (`P11.12-a`) : le champ de recherche partagé ne porte AUCUN
# mot de domaine — les deux phrases d'un résumé de recherche lui arrivent en nœuds de texte, écrits par le
# panneau appelant et jugés dans SON module (0 chaîne affichée mesurée ici).
# composer_depuis_lexistant.js inscrit le 2026-08-23 à son compte RELEVÉ : 6 chaînes affichées, 0 trou. Le module
# était MESURÉ et rendu au tableau depuis sa création sans figurer ici — donc jamais jugé, parce que le verdict
# parcourait les PLAFONDS et non les modules. Le sens de la garde s'est inversé sur ce point : un module mesuré
# sans plafond fait maintenant refuser de conclure (code 2).
# copie_et_selection.js inscrit à 0 à sa création (`P11.4-h`) : le geste de copie partagé porte SES propres
# mots (le mot du bouton, son accusé, l'aveu d'un presse-papier refusé) et aucun mot de domaine — les
# phrases de survol lui arrivent de l'appelant et sont jugées dans SON module (2 trous mesurés, comblés).
PLAFOND_DE_TROUS = {
    "admin_users.js": 0, "ai.js": 0, "alerting.js": 0, "alerts.js": 0, "app.js": 0, "attack.js": 0,
    "audit.js": 0, "cases.js": 0, "connectors.js": 0, "core.js": 0, "dataaccess.js": 0, "dashboards.js": 0, "datamodels.js": 0, "destinations.js": 0,
    "detadv.js": 0, "detection_admin.js": 0, "fieldfilters.js": 0, "fleet.js": 0, "freshness.js": 0,
    "help.js": 0, "i18n_observer.js": 0, "idp.js": 0, "index.html": 0, "index_policies.js": 0, "keys.js": 0, "knowledge.js": 0, "login.js": 0, "lookups.js": 0,
    "composer_depuis_lexistant.js": 0,
    "multitenant.js": 0, "navigation.js": 0, "prefs.js": 0, "processors.js": 0, "producer_ui.js": 0, "retention.js": 0,
    "copie_et_selection.js": 0, "recherche_de_liste.js": 0, "risk.js": 0, "runbooks.js": 0, "savedqueries.js": 0, "sigmaimport.js": 0, "soql_complete.js": 0,
    "sources.js": 0, "state.js": 0, "suppressions.js": 0, "system.js": 0, "threatintel.js": 0, "viz.js": 0,
}

# PLAFOND DE HORS-REGARD PAR MODULE (littéraux qui ont la forme d'un libellé et qu'AUCUN puits reconnu ne
# porte : la garde ne sait pas dire s'ils sont affichés). Relevé le 2026-08-23 par `--mesure` : 609 au total,
# dont 163 (26,8 %) sont DÉJÀ des clés du lexique — c'est le dépôt qui atteste que le périmètre regardé est
# plus étroit que l'affichage, et c'est pourquoi ce compte est GARDÉ comme celui des trous.
# RELEVÉ SUIVANT, AVEC SA RAISON — 2026-08-23, 609 -> 784 : le critère d'identifiant a cessé de prendre une
# phrase tout en minuscules pour un identifiant technique (`RE_DEUX_MOTS_CONSECUTIFS`), donc des littéraux
# jusque-là hors population sont devenus des CANDIDATS, et ceux qu'aucun puits ne porte tombent dans cette
# colonne. C'est le SEUL sens de hausse admis : la garde regarde plus large, le code n'a pas empiré. La part
# déjà au lexique passe de 163/609 (26,8 %) à 168/784 (21,4 %) sur cette base élargie.
# PUIS ABAISSÉ, 784 -> 680 : un littéral posé dans un NON-PUITS RECONNU (classe CSS, identifiant, style,
# attribut non affiché) sort de l'aveu — la garde SAIT qu'il n'affiche rien, et le mêler à l'indécidable
# faisait rougir le cliquet sur une classe CSS neuve. La part déjà au lexique remonte à 169/680
# (24,9 %) : c'est du bruit qui est parti, pas de la dette.
# CE CLIQUET NE REMONTE PAS. Un module neuf qui pose ses libellés dans une forme inconnue ROUGIT même si la
# garde ne sait pas lire cette forme : rendre vert sur ce qu'on ne regarde pas est pire qu'une garde absente.
# L'abaisser est le sens attendu (déplacer un libellé vers un puits reconnu, ou apprendre la forme à la
# garde). Le relever exige une raison écrite ici, à côté du chiffre.
PLAFOND_HORS_REGARD = {
    "admin_users.js": 14, "ai.js": 1, "alerting.js": 2, "alerts.js": 18, "app.js": 22, "attack.js": 6,
    "audit.js": 0, "cases.js": 68, "composer_depuis_lexistant.js": 6, "connectors.js": 26,
    "copie_et_selection.js": 3, "core.js": 29, "dashboards.js": 22, "dataaccess.js": 11, "datamodels.js": 1,
    "destinations.js": 36, "detadv.js": 10, "detection_admin.js": 28, "fieldfilters.js": 19, "fleet.js": 7,
    "freshness.js": 10, "help.js": 30, "i18n_observer.js": 0, "idp.js": 25, "index.html": 0,
    "index_policies.js": 16, "keys.js": 5, "knowledge.js": 7, "login.js": 6, "lookups.js": 9,
    "multitenant.js": 6, "navigation.js": 2, "prefs.js": 0, "processors.js": 10, "producer_ui.js": 7,
    "recherche_de_liste.js": 1, "retention.js": 16, "risk.js": 4, "runbooks.js": 20, "savedqueries.js": 2,
    "sigmaimport.js": 12, "soql_complete.js": 16, "sources.js": 5, "state.js": 0, "suppressions.js": 16,
    "system.js": 33, "threatintel.js": 6, "viz.js": 21,
}
# QUATRE DESCENTES AU RAS, 2026-08-30 (`P8.27-g`) — LE JEU EST FERMÉ, ET C'EST TOUT CE QU'ELLES FONT.
#   alerts.js 20 -> 18 · destinations.js 37 -> 36 · fieldfilters.js 21 -> 19 · risk.js 5 -> 4.
# Chaque chiffre est le RELEVÉ du 2026-08-30 sur un arbre vérifié STABLE (même `git status` et même empreinte
# de `web/` à neuf minutes d'intervalle), pas une valeur ronde : la ligne « JEU DU CLIQUET » de l'exécution
# de ce jour donnait 4 plafonds au-dessus de leur relevé pour SIX crans au total, exactement ces quatre-là,
# et zéro cran sur les trous. Aucun de ces quatre modules n'est en écriture concurrente ce jour-là (aucun ne
# figure au `git status` de l'arbre mesuré) : la raison écrite ci-dessous pour NE PAS descendre — deux d'entre
# eux étaient alors sous une autre main, et un cliquet posé au ras aurait rendu la CI rouge sur le travail
# d'un autre — a CESSÉ DE VALOIR, et c'est pourquoi la descente est faite maintenant plutôt qu'alors.
# CE QUE LA DESCENTE PORTE, MESURÉ PAR MUTATION SUR UNE COPIE DE L'ARBRE (2026-08-30, copie dont les quatre
# modules ont la MÊME empreinte sha256 que l'arbre réel) : six libellés français neufs, aucun au lexique,
# posés dans les formes non lues que ces quatre modules emploient déjà (entrée de tableau, valeur de clé
# d'objet, argument de fabrique locale) — deux dans `alerts.js`, deux dans `fieldfilters.js`, un dans
# `destinations.js`, un dans `risk.js`. Sous les ANCIENS plafonds : code 0, aucune erreur, et la ligne
# « JEU DU CLIQUET » annonce alors que chaque cliquet est au ras — la garde déclarait n'avoir plus de jeu
# au moment même où elle venait d'en laisser passer six. Sous les NOUVEAUX plafonds, MÊME arbre muté :
# code 1, les quatre modules nommés. Corpus restauré et nouveaux plafonds : code 0.
# CE QUE CES DESCENTES NE FERMENT PAS, ET IL FAUT LE REDIRE ICI : le cliquet garde un COMPTE NET, pas un
# ENSEMBLE de textes. Sur un module au ras, un libellé neuf posé dans une forme non lue passe VERT dès
# qu'il en REMPLACE un autre — mesuré par mutation le 2026-08-29 et publié à chaque exécution. Descendre
# les plafonds ferme la HAUSSE NETTE et rien d'autre. Seule une garde portant sur l'ENSEMBLE des textes
# fermerait ce chemin, et elle rougirait sur toute réécriture de libellé : ce n'est pas fait.
# QUINZE BAISSES, 2026-08-29 (`P11.8-c`) — la garde a APPRIS DEUX FORMES, elle n'a pas cessé de regarder :
# la clé d'objet `emptyText:`/`message:`/`cancelText:` (fabriques de `core.js`, chemin lu dans la fabrique)
# et le premier argument de `confirmWithConsequence(` (qui devient le `title` d'une modale, donc un `<h3>`).
#   admin_users 16->14 · audit 1->0 · cases 70->68 · composer_depuis_lexistant 7->6 · connectors 27->26 ·
#   datamodels 6->1 · detadv 14->10 · fleet 9->7 · idp 29->25 · knowledge 11->7 · multitenant 7->6 ·
#   retention 17->16 · risk 6->5 · sources 7->5 · suppressions 21->16.
# CHAQUE PLAFOND DESCEND DU DELTA DE LA RÈGLE, PAS JUSQU'AU RELEVÉ DU JOUR, et la raison est celle que ce
# fichier écrit déjà plus haut : un ÉCART est une propriété de l'INSTRUMENT et se refait sur n'importe quel
# arbre, un ABSOLU est une propriété de l'ARBRE et se périme sous les autres agents. Le delta est mesuré sur
# un arbre GELÉ (copie de `web/` prise à un instant, les deux instruments joués dessus) : population +36,
# hors-regard -36, 31 chaînes qui entrent comme des TROUS. `risk.js` garde donc son cran de jeu (6->5, relevé
# 4) plutôt que de tomber au ras : sa descente au relevé avait déjà été annulée une fois pour écriture
# concurrente, et rien n'a changé de ce côté.
# TRENTE ET UNE ENTRÉES DE LEXIQUE SUIVENT CES BAISSES, sur DOUZE modules qu'aucun autre lot ne touche.
# Ce ne sont pas des chaînes neuves : ce sont des textes d'état vide, des titres de modale et des messages
# de confirmation qui s'affichaient en français sous `LANG='en'` depuis leur écriture, sous un plafond de
# trous de ZÉRO que rien ne faisait rougir — la démonstration exacte de `P11.8-c` sur douze modules d'un coup.
# CE QUE CES BAISSES NE FONT PAS : elles ne ferment pas le JEU préexistant de `alerts.js`, `destinations.js`,
# `fieldfilters.js` et `risk.js`. Deux de ces quatre modules sont en écriture concurrente à l'heure de ce
# relevé (`git status` les donne modifiés, et `alerts.js` porte déjà un trou qui n'appartient pas à ce lot) :
# poser leur cliquet au ras rendrait la CI rouge sur le travail d'un autre sans qu'aucun libellé n'ait empiré.
# CETTE DETTE EST PAYÉE LE 2026-08-30 (`P8.27-g`) : les quatre plafonds sont descendus à leur relevé, la
# raison d'attendre ayant cessé d'exister avec l'écriture concurrente. Le bloc daté du 2026-08-30 posé
# juste sous le dictionnaire porte les chiffres et la preuve par mutation.
# UNE BAISSE ET UNE HAUSSE, 2026-08-26 (`P11.13-f`), toutes deux dues au MÊME changement de règle — la
# reconnaissance d'un texte affiché ne dépend plus du niveau de parenthèses, elle repose sur ce qui atteint
# l'écran (voir « CE QUI SE COLLE À UN LITTÉRAL DANS LE NŒUD RENDU »).
#   detection_admin.js 30 -> 28 : le plafond était en RETARD de deux crans sur son propre relevé (28 mesurés)
#     depuis la correction de `P11.14-g`. Un cliquet qui descend est le seul mouvement qui ne se discute pas.
#   viz.js 21 -> 21 : LE PLAFOND NE BOUGE PAS, C'EST LA DETTE QUI EST PAYÉE. La règle élargie a RÉVÉLÉ un
#     littéral que la garde prenait pour un fragment de concaténation alors que rien ne s'y colle
#     (`x >= 0 ? (…) : 'total inconnu'`, affecté à une const) : `web/viz.js` passait à 22 sans qu'une seule
#     de ses lignes bouge (croisement 2x2 le 2026-08-26, instrument de HEAD `207f51a` contre celui du jour,
#     `web/viz.js` identique à l'octet — sha256 cef1b64d… des deux côtés : 21 / 21 / 22 / 22). Une dette
#     RÉVÉLÉE se PAIE ; relever le plafond est justement ce que le paragraphe ci-dessus interdit par écrit.
#     ELLE A ÉTÉ PAYÉE, ET PAS PAR LE CHEMIN ATTENDU — LA MESURE A ÉCARTÉ CELUI-LÀ. Le chemin ordinaire
#     (« poser le libellé dans un puits reconnu ») le ferait entrer dans la POPULATION sous un plafond de
#     trous de ZÉRO, donc exigerait une entrée au lexique ; or `total inconnu` n'est JAMAIS un nœud texte à
#     lui seul : il est interpolé dans la ligne d'état (« page X/Y · … · serveur … ms · total … ms »), et
#     `i18nWalk` ne remplace que sur l'égalité du nœud ENTIER après `trim()`. TÉMOIN JOUÉ (vrai `i18nWalk`
#     importé, shim DOM minimal, clé `"total inconnu"` AJOUTÉE au lexique d'une copie) : nœud « Annulé » ->
#     « Cancelled » (POSITIF, c'est un nœud entier) ; nœud « page 1/? · total inconnu · serveur 12 ms ·
#     total 30 ms » -> INCHANGÉ (NÉGATIF). La clé serait MORTE — un vert sans traduction, le piège que
#     `web/i18n.js` nomme lui-même à côté de ses fragments. Le libellé est donc devenu BILINGUE PAR
#     CONSTRUCTION (`LANG === 'en' ? 'unknown total' : 'total inconnu'`), la forme que `web/viz.js` emploie
#     déjà pour ses libellés composés (l. 650, 663-672, 695) : il quitte l'aveu parce qu'il est TRADUIT,
#     pas parce qu'on cesse de le regarder. Relevé après correction : viz.js 21, trous 0, total 655 -> 654.
#   CE QUE CETTE CORRECTION NE TIENT PAS : les autres mots de la MÊME ligne d'état (`lignes`, `serveur`,
#     `page`) restent français sous `LANG='en'`. Ce sont des fragments de concaténation, hors population par
#     la convention écrite plus haut — dette CONNUE et ANCIENNE de la ligne d'état, ni révélée ni close ici.
# HUIT BAISSES, RELEVÉES LE 2026-08-26 EN JOUANT LES DEUX INSTRUMENTS SUR LE MÊME `web/` (celui du jour) :
#   cases.js 77 -> 70 · connectors.js 28 -> 27 · dashboards.js 30 -> 22 · freshness.js 11 -> 10 ·
#   multitenant.js 8 -> 7 · producer_ui.js 8 -> 7 · runbooks.js 23 -> 20 · threatintel.js 8 -> 6.
#   Chacun est posé sur le RELEVÉ du jour, pas sur un chiffre annoncé : `dashboards.js` avait été inscrit à 25
#   au motif d'une baisse « 30 -> 25 » alors que les deux instruments en mesuraient 22 — un cliquet laissé
#   trois crans au-dessus de son propre relevé, ce que le paragraphe voisin reproche justement à
#   `detection_admin.js`. Des littéraux quittent l'aveu parce que la garde SAIT désormais les lire :
#   les uns sont posés sous une clé d'objet qui NOMME une propriété d'affichage du document
#   (`{ textContent: … }`), la liste de ces clés étant DÉRIVÉE des propriétés déjà déclarées au lieu d'être
#   tenue à côté d'elles (`P11.8-c`) ; les autres sont des branches de ternaire que la règle de colle ne
#   prend plus pour des fragments (`P11.13-f`). Ils entrent donc dans la POPULATION, et huit d'entre eux y
#   sont entrés comme des TROUS — au lexique depuis. C'est le sens attendu de la baisse : apprendre une
#   forme à la garde, pas déplacer un libellé.
# LE DELTA EST CELUI DES DEUX RÈGLES ENSEMBLE, ET IL EST DIT COMME TEL. Les deux changements ont été livrés
# dans le même lot : rien sur l'arbre livré ne permet de les séparer, et une attribution par clé serait une
# affirmation non reproductible. Ce qui EST reproductible, mesuré le 2026-08-26 (instrument de HEAD `207f51a`
# contre celui du jour, même `web/`, `--mesure` des deux côtés) : hors-regard 676 -> 655 (-21), population
# +11, mouvement dans QUATORZE modules. LES QUATRE NOMBRES SONT ANCRÉS SUR UN ARBRE IMMUABLE, `web/` de HEAD
# `207f51a` : hors-regard 676 -> 655, population 1 922 -> 1 933 (voir « CE QUE L'ARBRE MESURE VRAIMENT »
# ci-dessus — un absolu pris sur l'arbre de travail se périme sous les autres agents, l'écart non).
# Le relevé précédent annonçait « -15 hors-regard,
# +15 population, et zéro déplacement ailleurs » : ces trois chiffres ne se retrouvent pas, et c'est cette
# ligne-ci qui vaut — les deux instruments sont côte à côte, la mesure se refait en deux commandes.
# UN CHIFFRE DE CLIQUET RÉFUTÉ, ET C'EST LE PRINCIPAL SERVICE DE CE RELEVÉ : `alerts.js` a été annoncé
# « 23 pour 20, dépassement délibérément non réparé ». Les DEUX instruments joués sur l'arbre du jour rendent
# 20 (celui de HEAD, plafond exactement TENU) et 18 (celui du lot) : la valeur 23 n'existe dans aucune des
# deux mesures. Le défaut réel de ce module n'était pas un hors-regard mais un TROU (« groupes
# indisponibles »), que la règle élargie a révélé et que le lexique couvre depuis. Une non-réparation écrite
# à côté d'un chiffre que l'instrument contredit dans la même exécution ne couvre rien : elle déplace le
# regard du défaut qui rougit vers un défaut qui n'existe pas.
# ON NE POSE PAS UN CLIQUET AU RAS D'UN MODULE QUI BOUGE, ET LA RAISON EST MESURÉE, PAS INVOQUÉE.
#
# ┌─ AVERTISSEMENT POSÉ AVANT LE PARAGRAPHE, ET NON APRÈS (2026-08-30) ─────────────────────────────┐
# │ LES DEUX CHIFFRES DE PLAFOND CITÉS CI-DESSOUS SONT PÉRIMÉS. Le dictionnaire fait foi, pas cette  │
# │ prose. Ils ont été descendus à leur relevé le 2026-08-30 (voir le bloc daté sous le             │
# │ dictionnaire). LA RÈGLE de ce paragraphe reste VRAIE et c'est pourquoi il n'est pas supprimé —   │
# │ seuls ses exemples ont vieilli.                                                                 │
# │ POURQUOI CET AVERTISSEMENT EST ICI ET NON PLUS BAS : une relecture adverse a mesuré le           │
# │ 2026-08-30 qu'une correction posée APRÈS l'erreur laisse un lecteur qui va de haut en bas        │
# │ rencontrer les chiffres faux COMME DES AFFIRMATIONS avant d'atteindre la note qui les dément.    │
# │ Corriger n'est pas seulement écrire le vrai : c'est le placer là où le faux serait lu.           │
# └─────────────────────────────────────────────────────────────────────────────────────────────────┘
# `alerts.js`
# restait à 20 : deux relevés du MÊME 2026-08-26, à quelques minutes d'écart, en rendent 18 puis 19 — le fichier
# a changé entre les deux sous un autre agent (la ligne du repli de chargement des groupes est passée de 706
# à 795). Un cliquet posé au ras du premier relevé aurait rendu la CI ROUGE sur le travail d'un autre, sans
# qu'aucun libellé n'ait empiré. `risk.js` restait à 6 pour la même raison et de la même façon mesurée : sa
# descente à 5 avait été écrite, puis le module est entré en écriture concurrente dans l'heure, et elle a été
# ANNULÉE avant livraison. Ce n'est pas une hausse (aucun de ces deux chiffres ne dépasse celui de `HEAD`) ni
# un silence (c'est écrit ici, et le jeu restant est PUBLIÉ à chaque exécution) : c'est une descente RETARDÉE,
# à faire sur un module stable. Le mouvement à surveiller sur un module qui bouge est celui des TROUS, dont le
# plafond est à ZÉRO et le reste dans tous les relevés du jour.
# DEUX CHIFFRES DE CE PARAGRAPHE SONT PÉRIMÉS, ET C'EST LE PARAGRAPHE LUI-MÊME QUI LE DIT MAL : il annonce
# deux valeurs de plafond pour `alerts.js` et `risk.js` que le dictionnaire ne porte plus — celle de
# `risk.js` avait déjà été démentie par la baisse du 2026-08-29, celle d'`alerts.js` l'est par la descente
# du 2026-08-30. Ce qui reste vrai de ce paragraphe est sa RÈGLE (ne pas poser un cliquet au ras d'un
# module qu'un autre agent écrit) ; ce qui n'en reste pas, ce sont ses deux chiffres. Le dictionnaire est
# la seule source des plafonds, et la ligne « JEU DU CLIQUET » la seule source de leur jeu.
# CE QUE CE CLIQUET NE TIENT PAS : il refuse une HAUSSE, il ne force pas une DESCENTE. Un plafond peut donc
# rester au-dessus de son relevé — c'est du JEU, pas une régression, mais ce jeu est exactement la place que
# des libellés neufs peuvent prendre sans faire rougir personne. Ce jeu n'est plus écrit dans ce commentaire
# (où il datait d'un jour et s'est révélé faux de trois crans sur `dashboards.js`) : la garde le PUBLIE à
# chaque exécution, module par module, DÉRIVÉ de la mesure du jour. Le lire est le seul moyen de savoir ce
# que ce cliquet laisse passer aujourd'hui, et un plafond qu'on oublierait de faire descendre s'y voit.
# RAISON DE LA SEULE HAUSSE ÉCRITE ICI — viz.js 18 -> 21 le 2026-08-24 (`P11.8-e`). Le code n'a pas empiré :
# le découpeur a cessé de perdre 134 lignes de ce module. Les cinq littéraux qui reviennent à l'aveu
# (`Escape`, `Ko`, `Mo`, `Go`, `depuis la recherche`) y étaient déjà, invisibles ; les deux qui en sortent
# étaient FAUX — l'un (`(sans sujet)`) appartient à une interpolation et non au texte d'un gabarit, l'autre
# était un morceau de CODE SOURCE (`").join(''); box.innerHTML =`) que le lecteur désynchronisé avait pris
# pour un littéral. Un cliquet nourri d'une lecture fausse gardait une valeur qui ne mesurait rien.

# ---------------------------------------------------------------------------------------------
# L'EXCÈS DU LEXIQUE — une entrée dont la chaîne source n'existe plus (`P11.8-g`).
# ---------------------------------------------------------------------------------------------
# NOMS HORS CORPUS : ce qu'ils désignent ne livre rien à un navigateur. `.github` en fait partie POUR UNE
# RAISON QUI SE MESURE — les dix-huit orphelines sont NOMMÉES dans le commentaire du cliquet ci-dessous ; un
# corpus qui lirait ce fichier les trouverait toutes « présentes dans le dépôt », donc indécidables. La garde
# se rendrait aveugle en s'écrivant elle-même.
# L'EXCLUSION PORTE SUR LE NOM, PAS SUR LE TYPE (`P11.8-l`, 2026-08-31), ET CE FUT UN INSTRUMENT DONT LA
# MESURE DÉPENDAIT DE LA FAÇON DONT L'ARBRE AVAIT ÉTÉ SORTI. Elle ne retirait que des RÉPERTOIRES ; or
# `git worktree` — et un sous-module — posent un `.git` qui est un FICHIER, et son contenu est un CHEMIN.
# MESURÉ le 2026-08-31 sur un même commit de CE dépôt, sorti de TROIS façons. Ce qui porte la
# connaissance est l'ÉCART, jamais la taille absolue : clone ordinaire et archive de la tête rendent
# le MÊME corpus ; un arbre de travail LIÉ rend **cinquante-trois octets de plus**, soit exactement la
# taille de son pointeur plus celle du séparateur. ET LE NOMBRE SUIT LA LONGUEUR DU CHEMIN : un second
# arbre lié, même commit, dont le seul nom d'administration était plus long, rendait cent quinze octets
# de plus — l'écart entre les deux valant exactement la différence de longueur des deux pointeurs.
# LA PRÉCISION QUI REND LE DÉFAUT PIRE QU'IL N'EN A L'AIR : ce n'est pas la profondeur où l'arbre est
# posé — deux arbres liés de même nom à des profondeurs différentes rendent le MÊME pointeur. C'est le
# chemin du dépôt PRINCIPAL plus le nom d'administration, si bien que le MÊME arbre lié, sous deux
# clones, donne DEUX nombres. Et le code sortait à ZÉRO dans les trois cas : le défaut était SILENCIEUX.
# 112 octets). Deux sorties du même commit ne rendaient donc pas le même nombre. Sans effet sur le verdict —
# la marge des planchers se compte en millions d'octets — mais un relevé pris là aurait ancré TROIS planchers
# sur un accident de chemin, et personne ne l'aurait su. PRÉCISION MESURÉE QUE L'ÉNONCÉ N'AVAIT PAS : ce n'est
# pas la profondeur où l'arbre est posé qui compte, c'est la longueur du chemin du dépôt PRINCIPAL plus le nom
# d'administration de l'arbre — deux arbres liés de même nom placés à des profondeurs différentes rendent le
# MÊME nombre (51 octets chacun, vérifié), deux noms de longueurs différentes non.
# VÉRIFIÉ AVANT D'EXCLURE, PARCE QU'UNE EXCLUSION QUI RETIRE UN FICHIER LÉGITIME EST PIRE QUE LE DÉFAUT :
# aucun fichier de ce dépôt ne porte un de ces quatre noms — ni parmi les 656 fichiers que le corpus lit, ni
# dans `git ls-files` entier, où `.github` n'apparaît QUE comme segment de répertoire (67 fichiers).
# NEUF NOMS AJOUTÉS LE 2026-08-31, ET LE CORPUS NE BOUGE PAS — prouvé avant/après. Une garde
# sœur, qui refuse un parcours d'arbre non élagué depuis une racine dominante, a relevé que cette
# liste était une COPIE DIVERGENTE du geste partagé : elle en manquait neuf. Aucun de ces neuf
# répertoires n'existe dans l'arbre aujourd'hui (le seul présent est sous un nom déjà exclu),
# donc l'ajout est INERTE sur la mesure — et c'est exactement pourquoi il fallait le faire
# MAINTENANT : le jour où l'un d'eux apparaît, il entrerait dans le corpus et gonflerait les trois
# relevés qui fondent les planchers, SANS QU'AUCUN NE ROUGISSE — un plancher ne garde que la BAISSE.
NOMS_HORS_CORPUS = (
    ".git", "target", "node_modules", ".github",
    "vendor", "__pycache__", ".venv", "venv", "site-packages",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
)
RE_ECHAPPEMENT = re.compile(r"\\(['\"`\\])")
SEPARATEUR_CORPUS = "\n\x1e\n"
RE_CORPS_DE_MOT = re.compile(r"[0-9A-Za-zÀ-ÖØ-öø-ÿ]")

# PLANCHERS DE LA SONDE D'EXCÈS. Une sonde d'orphelines validée sur un corpus VIDE accuse TOUTES les clés et
# se croit juste — c'est la faute que ce dépôt a déjà commise (garde à corpus `git ls-files` validée sur un
# fichier non suivi). Les deux planchers suivent la MÊME recette que `MIN_POPULATION`, et depuis le
# 2026-08-31 ils la suivent PAR LE CODE et non plus à la main : une sonde qui perdrait plus de 5 % de son
# corpus, ou de ses clés vivantes, refuse de conclure au lieu d'accuser.
# LES DEUX ÉTAIENT EN RETARD, ET LE PREMIER LE DISAIT DÉJÀ SANS SE L'APPLIQUER : la note ci-dessous nommait
# « un cliquet qui se desserre tout seul » et c'est exactement ce qui lui est arrivé — 7,17 % tolérés pour
# 5 % affirmés au 2026-08-31 — un retard de plusieurs centaines de milliers d'octets sur le corpus de CE
# DÉPÔT, mesuré dans un clone ordinaire de la tête, jamais sur une donnée d'exploitation. Nommer un défaut
# à côté de la valeur qui le porte ne
# l'empêche pas ; seule la dérivation l'empêche.
# LE RELEVÉ DU CORPUS NE DÉPEND PLUS DU MODE DE SORTIE DE L'ARBRE (`P11.8-l`, fermée le 2026-08-31) : le
# pointeur `.git` d'un arbre lié est un FICHIER, il entrait dans le corpus, et il déplaçait la mesure de la
# longueur de son propre chemin. `NOMS_HORS_CORPUS` porte désormais sur le NOM, fichier comme répertoire, et
# les trois modes de sortie du MÊME commit rendent le MÊME nombre — la note de cette constante porte les trois
# mesures. Le relevé ci-dessous se prend toujours dans un CLONE ORDINAIRE, non plus parce que l'autre mode
# mentait, mais parce que c'est le mode qu'un tiers peut refaire sans rien savoir de mon poste.
RELEVE_CORPUS = 35335969     # 2026-08-31, HEAD `6f0a5ad`, clone ordinaire (banc : le corpus dérivé que
                             # cette garde construit elle-même — sources suivies, pas une installation ;
                             # `stat1.db`, ignoré et non décodable en UTF-8, n'y entre pas).
                             # Historique : 31 992 507 puis 34 530 079 le 2026-08-29, à l'ajout de la copie
                             # aux ENTITÉS RÉSOLUES — le plancher SUIT le relevé, sinon la propriété qu'il
                             # affirme (« perdre plus de 5 % du corpus fait refuser de conclure ») devient
                             # fausse en silence ; laissé à l'ancienne valeur, il aurait toléré 12 % de perte.
# ET LE RELEVÉ SE PREND SUR UN ARBRE PROPRE, CE QUI N'EST PAS UNE PRÉCAUTION MAIS UNE MESURE : le
# 2026-08-31, entre deux exécutions espacées de quatre minutes, le corpus est passé de 35 335 969 à
# 35 340 986 — un AUTRE lot venait d'écrire `daemon/src/tests/un_ancrage_qui_ment.rs`, encore NON SUIVI, et
# de modifier `daemon/src/tests/mod.rs`. Ancrer là aurait posé une constante sur 5 017 octets que personne
# ne peut retrouver depuis un commit. Le sens de l'erreur est le seul point rassurant, et il vaut d'être
# écrit : un ajout concurrent ne peut que GROSSIR la mesure, donc un plancher pris sur l'arbre PROPRE reste
# franchi en intégration — l'inverse (ancrer sur un arbre sale) ne l'est pas.
MIN_CORPUS = plancher_depuis_releve(RELEVE_CORPUS)          # 33 569 170 — marge : 1 766 799 octets
RELEVE_CLES_VIVANTES = 1588  # 2026-08-31, HEAD `6f0a5ad` : 1 588 clés vues comme chaîne affichée dans un
                             # puits reconnu (1 586 au 2026-08-29).
MIN_CLES_VIVANTES = plancher_depuis_releve(RELEVE_CLES_VIVANTES)   # 1 508 — marge : 80 clés

# CLIQUET DES ORPHELINES PROUVÉES — À ZÉRO depuis le 2026-08-29 : les DIX-HUIT que le lot précédent avait
# laissées (il ne touchait qu'à la clé de `P11.20-e`, `web/` étant alors en écriture concurrente) sont
# retirées, chacune revérifiée À LA MAIN sur les 758 fichiers texte du dépôt — `docs/`, `.github/` et
# `daemon/src/` compris, ce que la garde n'a PAS le droit de lire — sous SIX normalisations : brute,
# déséchappée, entités HTML résolues, et les trois mêmes à blancs normalisés. La revérification a payé :
# elle a réfuté le MOTIF d'une accusation sur dix-huit (voir `corpus_du_depot`) et établi que les dix-sept
# autres sont des libellés d'une écriture ANTÉRIEURE dont la console sert aujourd'hui une AUTRE — le titre
# servi étant lui-même déjà une clé dans quatre cas (« Contenu », « Identité fédérée (SSO) »,
# « Politiques de notification », « Inventaire des sources ») : l'anglais ne perd rien, ce sont des doublons
# périmés. Deux de ces libellés ne subsistaient que dans `docs/`, qui n'est PAS servi : `docs/CONSOLE.md` a
# été corrigé dans le même lot ; `docs/NATIVE-IDP.md:15` nomme encore « Identité (SSO) » et reste dû.
# LA PREUVE QUE LE RETRAIT NE CASSE RIEN EST UN INVARIANT, PAS UNE RELECTURE : le compte des clés VIVANTES
# est resté à 1 586 de part et d'autre du retrait — une clé vivante retirée l'aurait fait baisser — et le
# harnais ESM rend 0 avant comme après.
# CE CLIQUET NE REMONTE PAS : une clé neuve dont rien ne sert le texte rougit (code 1). Le laisser à ZÉRO
# est l'état visé, et il n'y a plus rien à en descendre.
PLAFOND_ORPHELINES = 0

# CLIQUET DES INDÉCIDABLES — relevé le 2026-08-29 : 230, dont 198 dont le TEXTE est ailleurs dans le dépôt
# hors d'un puits reconnu, et 32 qu'un littéral de BORD peut composer. C'est l'AVEU, pas la dette : il dit
# combien de clés la sonde ne sait pas trancher, et il est plus utile qu'un vert qui tairait la question.
# Une HAUSSE fait REFUSER DE CONCLURE (code 2), elle ne fait pas rougir : ajouter une clé légitime que le
# critère de puits ne lit pas n'est pas une faute — c'est la raison qui gouverne déjà PLAFOND_HORS_REGARD,
# appliquée à l'autre sens de la mesure. L'abaisser (élargir le critère de puits, ou retirer une clé morte)
# est le seul mouvement qui ne se discute pas.
# LE JEU DE CE CLIQUET A ÉTÉ MESURÉ, PAS SUPPOSÉ (2026-08-29). Il est à ZÉRO : le relevé vaut exactement le
# plafond, cinq exécutions d'affilée pendant qu'un autre agent écrivait sous `web/` l'ont rendu à 230 sans
# varier, et le retrait des dix-huit orphelines ne l'a pas fait bouger d'un cran — retirer une ORPHELINE ne
# touche pas au compte des INDÉCIDABLES, les verdicts étant exclusifs. Ce que « zéro jeu » coûte est écrit
# ici : la PROCHAINE clé qu'un module posera dans une forme non lue fait REFUSER DE CONCLURE (code 2), et
# c'est voulu — mais la charge de la mesure retombe alors sur qui écrit le libellé, pas sur qui l'a réglé.
# ET LA FRAGILITÉ EST AILLEURS QUE DANS LE JEU : sur les 198 indécidables tenues par un TEXTE présent,
# 79 (40 %) ne tiennent qu'à UN SEUL fichier — 78 sous `web/`, 1 sous `daemon/` — de sorte qu'une seule
# suppression de libellé les fait basculer ORPHELINES et rougir `PLAFOND_ORPHELINES` à 0. Ce n'est pas un
# défaut du cliquet, c'est sa raison d'être : un libellé qu'on retire doit emporter sa clé.
# 2026-08-30 (`P11.8-i`), 230 -> 228 : DEUX clés retirées qui n'étaient que des MORCEAUX d'un nœud rendu
# (« Déposez un », « de docs Sigma. »). Elles étaient INDÉCIDABLES par construction et le seraient restées
# pour toujours — leur texte EST dans le dépôt, la sonde ne pouvait donc jamais les accuser. C'est le compte
# des nœuds À CHEVAL, plus bas, qui les a désignées. Le cliquet descend d'exactement ce que le lot retire :
# le laisser à 230 le DESSERRERAIT de deux crans, et son jeu était mesuré à ZÉRO la veille.
PLAFOND_INDECIDABLES = 228

# CLIQUET DES NŒUDS À CHEVAL (`P11.8-i`) — un nœud RENDU qui traverse une borne de littéral et qu'aucune
# clé ne couvre. Relevé le 2026-08-30 : DEUX, tous deux dans la modale d'import Sigma, comblés dans le même
# lot ; le plafond est donc à ZÉRO et il n'y a plus rien à en descendre. C'est un MANQUE au même titre
# qu'un trou — la chaîne est affichée, elle n'a pas d'entrée — donc son canal est la RÉGRESSION (code 1),
# pas le refus de conclure. Ce cliquet ne double PAS celui des trous : il ne compte que ce qu'aucun
# littéral pris seul ne rend, c'est-à-dire exactement ce que la lecture par littéral ne peut pas voir.
PLAFOND_NOEUDS_A_CHEVAL = 0

# CLIQUET DES FRAGMENTS NON ANALYSABLES (`P11.8-i`) — relevé le 2026-08-30 : HUIT, tous du même motif
# (une interpolation tombe dans une balise), sur trois modules : alerts.js 3, core.js 2, freshness.js 3.
# C'EST UN AVEU, PAS UNE DETTE, et son canal est donc le REFUS DE CONCLURE (code 2), comme pour les
# indécidables. Le rendre rouge à la première occurrence rendrait la garde rouge en permanence ; le taire
# rendrait vert sur ce qu'elle ne lit pas. Le cliquet est la seule voie honnête entre les deux : le compte
# est PUBLIÉ à chaque exécution avec le nom de chaque fragment, et une HAUSSE fait refuser de conclure.
# CE QU'IL FAUT FAIRE POUR L'ABAISSER : sortir l'interpolation de la balise (`class="${c}"` au lieu de
# `<b ${c}>`), ce qui est aussi la forme la plus sûre côté injection. Le relever exige une raison écrite ici.
# AUCUN des trois modules concernés n'est en écriture concurrente à l'heure de ce relevé ; poser le cliquet
# au ras ne rend donc rouge le travail de personne.
PLAFOND_FRAGMENTS_ILLISIBLES = 8

# LA SEULE SURFACE EXEMPTE : la définition `const HELP = { … }` du registre des sections d'aide, DÉRIVÉE
# (module et portée) de `check_every_help_trigger_has_a_section.py` — pas un nom de fichier, pas un module
# entier. Le module qui la porte est jugé au plafond zéro sur tout ce qui l'entoure. La raison est écrite :
# une exemption sans raison est une trappe.
RAISON_DU_REGISTRE = "registre {fr:{title,body}, en:{title,body}} choisi par LANG : bilingue par construction ; exempt sur la portée de sa définition seulement"


def registre_d_aide(aveux: dict | None = None) -> tuple[str, str] | None:
    """(nom du module de `web/` qui définit `const HELP = {`, son texte sans commentaires) ; None si aucun ou
    plusieurs. `aveux` recueille les pertes de synchronisation : le dépouillement est le LECTEUR PARTAGÉ
    (`P11.8-f`), et une région avalée ici déplacerait la PORTÉE exemptée du registre — donc la population."""
    corpus = {}
    for f in sorted(os.listdir(WEB)):
        if f.endswith(".js") and f != "sw.js":
            with open(os.path.join(WEB, f), encoding="utf-8") as fh:
                brut = fh.read()
            journal: list[tuple[str, int]] = []
            corpus[f] = sans_commentaires_js(brut, journal)
            if journal and aveux is not None:
                aveux[f] = [f"ligne {brut.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
    nom = module_du_registre(corpus)
    return (nom, corpus[nom]) if nom else None


def hors_registre(texte_sans_commentaires: str) -> str:
    """Le texte du module du registre SANS la portée de `const HELP = { … }` (remplacée par des blancs, lignes
    conservées) : ce qui reste est jugé comme n'importe quel module."""
    portee = portee_du_registre(texte_sans_commentaires)
    if portee is None:
        return texte_sans_commentaires
    d, f = portee
    return texte_sans_commentaires[:d] + re.sub(r"[^\n]", " ", texte_sans_commentaires[d:f]) + texte_sans_commentaires[f:]
# Une chaîne choisie par `LANG === 'en' ? … : …` est bilingue PAR CONSTRUCTION, dans n'importe quel
# module : elle compte comme couverte sans passer par le lexique.
RE_CHOIX_PAR_LANG = re.compile(r"\bLANG\b[^;]*\?")
# De même une valeur sous une clé `fr:` ou `en:` d'un objet : sa jumelle dans l'autre langue est à côté.
RE_CLE_FR_EN = re.compile(r"[{,]\s*(fr|en)\s*:\s*$")

SINKS_AFFECTATION = ("textContent", "innerText", "title", "placeholder", "ariaLabel")
SINKS_APPEL = ("createTextNode", "muted", "toast", "showErr", "confirmModal", "confirmWithConsequence",
               "append", "prepend", "emptyRow")
ATTRS_HTML = ("title", "placeholder", "aria-label", "label")


def _propriete(attribut: str) -> str:
    """Le nom de PROPRIÉTÉ du document que porte un attribut HTML : `aria-label` -> `ariaLabel`. C'est la
    seule différence d'écriture entre les deux formes du MÊME puits."""
    return re.sub(r"-(\w)", lambda m: m.group(1).upper(), attribut.strip())


# LES CLÉS D'OBJET NE SONT PLUS ÉNUMÉRÉES, ELLES SONT DÉRIVÉES (`P11.8-c`). Une clé d'objet qui NOMME une
# propriété d'affichage du document EST le même puits que l'affectation de cette propriété : la valeur y
# rejoint le document par `Object.assign(el, {…})` ou par une fabrique qui recopie ses clés. La liste
# n'est donc pas à tenir — elle se dérive de ce que la garde déclare DÉJÀ afficher : les propriétés
# affectées (`SINKS_AFFECTATION`) et les attributs affichés (`ATTRS_HTML`, sous leur nom de propriété).
# Avant (jusqu'au 2026-08-26), la liste des clés était écrite À CÔTÉ de celle des affectations et avait
# divergé : `textContent` y manquait. Mesuré ce jour-là sur `web/` : 15 littéraux entraient dans la
# population par cette seule dérivation, dont HUIT chaînes françaises affichées SANS entrée au lexique
# (`web/cases.js` 4, `web/dashboards.js` 3, `web/runbooks.js` 1) — toutes posées par
# `Object.assign(document.createElement(…), { textContent: … })`, toutes invisibles à un plafond de zéro.
# C'est EXACTEMENT le défaut de `P11.8-c` : un module affichait du français non traduit en tenant zéro.
# CE QUI RESTE ÉNUMÉRÉ, ET POURQUOI : ces clés ne nomment AUCUNE propriété du document ; ce sont des
# conventions d'appel des fabriques de `web/core.js`. Chacune est écrite avec le CHEMIN, LU DANS LA FABRIQUE,
# par lequel sa valeur atteint un nœud texte entier — pas au motif que son nom sonne comme un libellé :
#   `emptyText`  -> `muted(opts.emptyText || …)` (`pagedList`), et `muted(t)` rend
#                   `Object.assign(div, { className: 'muted', textContent: t })` : le nœud vaut ce texte SEUL.
#   `message`    -> `modal()` : `<p class="modal-msg">${esc(opts.message)}</p>` — nœud entier.
#   `cancelText` -> `modal()` : `<button class="m-cancel">${esc(opts.cancelText || 'Annuler')}</button>`.
#   `okText`     -> `modal()` : le bouton jumeau du précédent. `hint`, `text` : champs des fabriques de saisie.
# LA LISTE ÉCRITE A DIVERGÉ UNE DEUXIÈME FOIS, ET SUR LA MÊME LIGNE DE `core.js` QUE LA PREMIÈRE. Le
# 2026-08-26, `textContent` manquait ici et huit chaînes françaises s'affichaient dans l'autre langue.
# Le 2026-08-29 : `okText` y était, `cancelText` — son jumeau, écrit dans le MÊME `html +=` de `modal()` —
# n'y était pas, ni `message`, ni `emptyText`, qui pesait à lui seul le PREMIER poste de l'aveu (22
# occurrences, clé d'objet la plus portante de `web/`). Une liste tenue à la main diverge de la fabrique
# qu'elle est censée décrire : c'est mesuré deux fois, à trois jours d'écart.
# LA DÉRIVATION PAR SUIVI DE FLUX — l'étape que l'ancienne rédaction annonçait ici comme « l'étape
# suivante » — EST RÉFUTÉE COMME ROUTE, ET C'EST MESURÉ (`P11.8-c`, 2026-08-29). Trois variantes jouées sur
# `web/` : (R1) une lecture de propriété `X.k` posée EXACTEMENT là où un littéral serait un puits, en
# réutilisant `_est_puits` -> 137 clés ; (R2) une lecture n'importe où dans l'appel d'un puits ou dans le
# membre droit d'une affectation de puits -> 262 clés ; (R3) une interpolation en position de texte HTML,
# restreinte aux expressions qui ne valent QUE cette lecture -> 48 clés. Les trois font entrer `value`,
# `name`, `id`, `type` — que `NON_PUITS_CONNUS` déclare, à côté, n'afficher JAMAIS de texte —, plus
# `length`, `join`, `slice`, `stringify`. LA CAUSE N'EST PAS UN RÉGLAGE : la console affiche les CHAMPS DE
# SES DONNÉES par les mêmes puits que ses libellés (`el.textContent = r.name`), donc un flux qui remonte
# d'un puits ne sépare pas une convention d'appel d'un nom de colonne. Direction de l'erreur : rendre TROP —
# `{ name: 'admin' }` deviendrait une chaîne affichée, exigerait une clé, et cette clé serait MORTE.
# Ce qui trancherait vraiment est de suivre le flux depuis le SITE D'APPEL jusqu'au paramètre de la
# fabrique ; ce n'est pas fait, et ce n'est plus annoncé comme prochain pas sans son coût.
# UNE CLÉ ÉCARTÉE, ET LA MESURE QUI L'ÉCARTE : `consequence` (`<p class="modal-consequence">`) a été
# essayée et RETIRÉE. Ses neuf littéraux de `web/` sont tous des concaténations — donc zéro chaîne révélée —
# et, par la règle du ternaire (qui cherche un puits dans la TÊTE de l'expression, pas dans la clé
# immédiate), elle faisait entrer `summary: cond ? 'défaut' : …` de `web/runbooks.js` : un FAUX trou, sur
# un texte que `producer_ui.js` pose dans un `<code class="rulecond">` — c'est-à-dire dans la balise même
# que `TAGS_HORS_POPULATION` met hors population. Un gain nul contre une clé morte : la clé n'entre pas.
CLES_APPLICATIVES = ("okText", "cancelText", "hint", "text", "message", "emptyText")
SINKS_CLE = tuple(sorted(set(SINKS_AFFECTATION) | {_propriete(a) for a in ATTRS_HTML} | set(CLES_APPLICATIVES)))
# Le texte d'un échantillon de code (`<code>`, `<kbd>`, `<pre>`, `<samp>`) est montré tel quel dans les deux
# langues : hors population, comme le contenu d'un `<script>`.
TAGS_HORS_POPULATION = ("script", "style", "code", "kbd", "pre", "samp")

# Un identifiant technique : minuscules ASCII, chiffres, ponctuation de chemin. Identique en FR et EN.
# LA CLASSE INCLUT L'ESPACE, et c'est nécessaire : `search by field`, `a-z, . _ -` en sont. Mais l'espace y
# faisait aussi entrer une PHRASE française entière tout en minuscules (`aucun runbook`), classée
# « identifiant technique » même posée dans un puits reconnu, alors qu'une seule majuscule la faisait
# basculer de l'autre côté. Ce qui sépare les deux n'est pas une liste de mots : c'est que l'identifiant
# accroche ses mots par de la ponctuation (`src_ip`, `/api/x`, `sort -count`) là où la phrase les pose
# côte à côte, séparés par une espace et rien d'autre. DEUX MOTS ALPHABÉTIQUES CONSÉCUTIFS = une phrase.
# Mesuré le 2026-08-23 : la règle fait entrer 64 chaînes sur 25 modules (40 dans un puits JS reconnu sur
# 22 modules, 24 dans le texte d'un littéral HTML sur 6 modules) ; `src_ip`, `/api/x`, `count`, `t1110.001`
# restent dehors.
RE_IDENTIFIANT = re.compile(r"^[a-z0-9_.:/\-+*%#@&=?|,;<>()\[\]{}!~^$\\' ]*$")
RE_DEUX_MOTS_CONSECUTIFS = re.compile(r"[a-z]+[ \t]+[a-z]+")
RE_LETTRE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ]")
SENTINELLE = "\x00"


# ---------------------------------------------------------------------------------------------
# Tokenisation JavaScript : on ne garde que les littéraux de chaîne, avec le code qui les précède.
# ---------------------------------------------------------------------------------------------
# LA DÉSAMBIGUÏSATION DU `/` N'EST PLUS ÉCRITE ICI (`P11.8-f`). « Écrite une fois » ne valait que DANS ce
# module : quatre autres lecteurs du dépôt, dans quatre gardes, n'en savaient rien et portaient tous la
# cécité au littéral d'expression régulière. La règle, ce qu'elle NE SAIT PAS FAIRE et son aveu de perte de
# synchronisation vivent désormais à un seul endroit pour tout le dépôt, importés ci-dessous — le geste de
# `sans_commentaires_css`, que la garde du chrome importe de la garde des sélecteurs.
# `saute_regex` et `RE_AVANT_REGEX` viennent du LECTEUR PARTAGÉ (voir l'import en tête de module).


def _lire_gabarit(src: str, i: int, journal: list[tuple[str, int]] | None = None) -> tuple[str, int]:
    """Lit un gabarit `` `...` `` à partir du backtick ouvrant ; rend (texte avec SENTINELLE pour
    chaque `${…}`, index après le backtick fermant)."""
    assert src[i] == "`"
    depart = i
    i += 1
    out = []
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            out.append(src[i : i + 2])
            i += 2
            continue
        if c == "`":
            return "".join(out), i + 1
        if c == "$" and i + 1 < n and src[i + 1] == "{":
            # saute l'expression interpolée (accolades équilibrées, chaînes, gabarits ET LITTÉRAUX
            # D'EXPRESSION RÉGULIÈRE imbriqués). Sans le dernier, un `"` de regex (`.replace(/"/g, '')`)
            # ouvrait une fausse chaîne et le lecteur avalait une région entière du fichier : mesuré le
            # 2026-08-24 sur `web/viz.js`, 118 littéraux disparus sur 134 lignes, dont une chaîne affichée
            # que le lexique ne couvrait pas (`P11.8-e`). `expr` accumule le code de l'expression, littéraux
            # et regex réduits, pour que la MÊME règle de désambiguïsation qu'au niveau supérieur s'applique.
            depth = 1
            i += 2
            expr: list[str] = []
            while i < n and depth:
                ch = src[i]
                if ch in "'\"":
                    _, i = _lire_chaine(src, i, journal)
                    expr.append('""')
                    continue
                if ch == "`":
                    _, i = _lire_gabarit(src, i, journal)
                    expr.append('""')
                    continue
                if ch == "/" and RE_AVANT_REGEX.search("".join(expr[-40:])):
                    i = saute_regex(src, i)
                    expr.append("/re/")
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                expr.append(ch)
                i += 1
            out.append(SENTINELLE)
            continue
        out.append(c)
        i += 1
    journaliser_perte(journal, "un gabarit `…` atteint la fin du fichier sans son accent grave fermant", depart)
    return "".join(out), i


def _lire_chaine(src: str, i: int, journal: list[tuple[str, int]] | None = None) -> tuple[str, int]:
    q = src[i]
    depart = i
    i += 1
    out = []
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            nxt = src[i + 1] if i + 1 < n else ""
            # `\uXXXX` / `\xXX` : une clé qui porte une espace insécable s'écrit ainsi pour rester lisible
            if nxt in ("u", "x"):
                largeur = 4 if nxt == "u" else 2
                hexa = src[i + 2 : i + 2 + largeur]
                if len(hexa) == largeur and all(ch in "0123456789abcdefABCDEF" for ch in hexa):
                    out.append(chr(int(hexa, 16)))
                    i += 2 + largeur
                    continue
            out.append({"n": "\n", "t": "\t", "'": "'", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        if c == q:
            return "".join(out), i + 1
        if c == "\n":
            # Un littéral de chaîne JS ne franchit PAS une fin de ligne : arriver ici prouve que ce
            # guillemet n'ouvrait pas une chaîne (il appartenait à une expression régulière, ou le lecteur
            # était déjà désynchronisé plus haut).
            journaliser_perte(journal, "une chaîne \u00ab\u202f'\u202f\u00bb ou \u00ab\u202f\"\u202f\u00bb se termine sur une fin de ligne", depart)
            return "".join(out), i
        out.append(c)
        i += 1
    journaliser_perte(journal, "une chaîne atteint la fin du fichier sans son guillemet fermant", depart)
    return "".join(out), i


def chaines_js(src: str, journal: list[tuple[str, int]] | None = None) -> list[tuple]:
    """Rend [(texte, code_avant, code_apres, bloc_en, contexte)] pour chaque littéral de chaîne/gabarit.
    `code_avant` = le code (sans commentaires ni chaînes) depuis le dernier `;` ou retour à la ligne
    significatif ; `code_apres` = les quelques caractères de code qui suivent ; `contexte` = le triplet
    (code réduit ENTIER, position du littéral dedans, {position: texte}) dont `_voisin_de_concatenation`
    a besoin pour retrouver les littéraux COLLÉS à celui-ci (`P11.13-f`)."""
    n = len(src)
    i = 0
    code: list[str] = []  # code accumulé sans commentaires ni littéraux (les littéraux deviennent `""`)
    trouves: list[tuple[str, int]] = []  # (texte, position dans `code`)
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "'\"":
            s, i = _lire_chaine(src, i, journal)
            trouves.append((s, len(code)))
            code.append('""')
            continue
        if c == "`":
            s, i = _lire_gabarit(src, i, journal)
            trouves.append((s, len(code)))
            code.append('""')
            continue
        if c == "/":
            if RE_AVANT_REGEX.search("".join(code[-40:])):
                i = saute_regex(src, i)  # même règle et même lecteur qu'à l'intérieur d'un `${…}`
                code.append("/re/")
                continue
        code.append(c)
        i += 1
    texte_code = "".join(code)
    # positions -> contexte. On recalcule les offsets : chaque entrée de `code` est de longueur variable.
    offsets = []
    pos = 0
    for seg in code:
        offsets.append(pos)
        pos += len(seg)
    litteraux = {offsets[idx]: s for s, idx in trouves}
    out = []
    for s, idx in trouves:
        p = offsets[idx]
        avant = texte_code[max(0, p - 400) : p]
        # contexte = depuis le dernier `;` (les retours à la ligne ne coupent pas : appels multi-lignes)
        k = avant.rfind(";")
        if k >= 0:
            avant = avant[k + 1 :]
        apres = texte_code[p + 2 : p + 12]
        out.append((s, avant, apres, _dans_bloc_lang_en(texte_code, p), (texte_code, p, litteraux)))
    return out


# Un bloc `if (LANG === 'en') { … }` (le littéral 'en' est déjà remplacé par `""` dans le code réduit).
RE_BLOC_LANG_EN = re.compile(r"\bif\s*\(\s*LANG\s*===\s*\"\"\s*\)\s*\{")


def _dans_bloc_lang_en(texte_code: str, p: int) -> bool:
    """Vrai si la position `p` est à l'intérieur du dernier bloc `if (LANG === 'en') {` ouvert avant elle.

    ON SORT D'UN BLOC POUR TOUJOURS (`P11.8-c`). Le solde d'accolades était comparé à zéro À LA FIN
    seulement : une fois le bloc refermé (solde -1), la première accolade ouverte plus loin — n'importe quel
    objet, n'importe quelle fonction — ramenait le solde à 0 et TOUT le reste du fichier redevenait « dans le
    bloc anglais », donc BILINGUE PAR CONSTRUCTION, donc COUVERT SANS ENTRÉE AU LEXIQUE. Un vert silencieux :
    la chaîne est comptée dans la population et jamais réclamée. Ce qui décide n'est pas le solde final mais
    le fait qu'il soit passé sous zéro EN CHEMIN. Le défaut s'est vu en ajoutant un témoin au corpus de
    contrôle — deux chaînes affichées y sont devenues « bilingues » parce qu'elles portaient une accolade.
    MESURÉ SUR L'ARBRE le 2026-08-26, DANS LES DEUX SENS : un seul module de `web/` porte un
    `if (LANG === 'en') {` (`i18n_observer.js`), et le correctif ne déplace AUCUNE chaîne, AUCUN trou,
    AUCUN module. Le chemin est donc fermé sans qu'aucun chiffre ne bouge : c'est un vert silencieux qu'un
    module à venir aurait déclenché, pas une dette d'aujourd'hui."""
    ouvert = None
    for m in RE_BLOC_LANG_EN.finditer(texte_code, 0, p):
        ouvert = m.end()
    if ouvert is None:
        return False
    solde = 0
    for c in texte_code[ouvert:p]:
        if c == "{":
            solde += 1
        elif c == "}":
            solde -= 1
            if solde < 0:
                return False  # le bloc est refermé : on n'y rentre plus
    return True


RE_SINK_AFFECT = re.compile(r"\.(%s)\s*=\s*$" % "|".join(SINKS_AFFECTATION))
RE_SINK_CLE = re.compile(r"[{,]\s*(%s)\s*:\s*$" % "|".join(SINKS_CLE))
RE_SINK_APPEL = re.compile(r"\b(%s)\(\s*$" % "|".join(SINKS_APPEL))
# `setAttribute(` : le NOM de l'attribut est le littéral qui PRÉCÈDE la valeur (la tokenisation l'a réduit
# à `""`, il est donc relu dans la liste des littéraux). Sans cette vérification, `setAttribute('d', …)` d'un
# tracé SVG était compté comme un puits d'affichage — mesuré le 2026-08-23 : 5 occurrences dans `web/viz.js`,
# toutes sur l'attribut `d`, portées à la colonne « dynamiques » d'un module qui n'affiche pas ce texte.
RE_SINK_SETATTR = re.compile(r"setAttribute\(\s*\"\"\s*,\s*$")
# UNE CLÉ D'OBJET PEUT ÊTRE ÉCRITE ENTRE GUILLEMETS (`{ 'aria-label': 'Valeur' }`) — obligatoire dès que le
# nom porte un tiret. La tokenisation l'a réduite à `""` comme n'importe quel littéral : le NOM est donc le
# littéral qui PRÉCÈDE, exactement comme pour `setAttribute('aria-label', 'Valeur')`. Sans cette lecture, la
# forme la plus naturelle d'écrire un `aria-label` sous une clé serait hors-regard pour toujours. Aucune
# occurrence sur l'arbre au 2026-08-26 : ce que ce motif ferme est un chemin, pas une dette.
RE_CLE_LITTERALE = re.compile(r"[{,]\s*\"\"\s*:\s*$")
RE_TERNAIRE = re.compile(r"[?:]\s*$")
# DES NON-PUITS RECONNUS. La valeur d'une classe CSS, d'un identifiant, d'un chemin ou d'un champ de
# formulaire n'est JAMAIS du texte affiché. Un littéral posé là n'est pas un libellé qu'on aurait ignoré,
# c'est une donnée : il sort de la colonne hors-regard, qui ne doit nommer que ce dont la garde ne peut PAS
# décider. Sans cette liste, `el.className = 'ueditor hidden'` (deux mots minuscules, donc candidat depuis
# la règle des deux mots) gonflait l'aveu et faisait rougir le cliquet sur une classe CSS neuve. Mesuré le
# 2026-08-23 : 125 occurrences sur 872, soit 14,3 % de bruit retiré.
NON_PUITS_CONNUS = ("className", "id", "href", "src", "value", "type", "name", "cssText", "accept",
                    "autocomplete", "spellcheck", "htmlFor", "action", "method", "rel", "target", "role")
RE_NON_PUITS = re.compile(
    r"\.(?:%s)\s*=\s*$|\.(?:dataset|style)\.\w+\s*=\s*$|\bclassList\.(?:add|remove|toggle|replace)\(\s*$"
    % "|".join(NON_PUITS_CONNUS))
RE_SINK_AFFECT_DANS = re.compile(r"\.(%s)\s*=[^=]" % "|".join(SINKS_AFFECTATION))
RE_SINK_CLE_DANS = re.compile(r"[{,]\s*(%s)\s*:" % "|".join(SINKS_CLE))
RE_SINK_APPEL_DANS = re.compile(r"\b(%s)\(" % "|".join(SINKS_APPEL))
RE_CLE_AUTRE = re.compile(r"[{,]\s*([A-Za-z_]\w*)\s*:\s*$")
RE_HTML = re.compile(r"<[a-zA-Z][^<>]*>|</[a-zA-Z]+>")


def _est_puits(avant: str, attribut: str = "") -> bool:
    """`attribut` = le littéral qui précède immédiatement celui qu'on juge ; pour `setAttribute(` c'est le NOM
    de l'attribut, et seul un attribut AFFICHÉ (`ATTRS_HTML`) fait de l'appel un puits."""
    a = avant.rstrip()
    if RE_SINK_AFFECT.search(a) or RE_SINK_CLE.search(a) or RE_SINK_APPEL.search(a):
        return True
    if RE_SINK_SETATTR.search(a):
        return attribut.strip() in ATTRS_HTML
    if RE_CLE_LITTERALE.search(a):
        # clé d'objet CITÉE : le nom est le littéral précédent, la règle est celle des clés nues
        return _propriete(attribut) in SINKS_CLE
    # ternaire `x.title = cond ? 'A' : 'B'` : le puits est AVANT le `?`, séparé de la chaîne par la
    # condition ; on le cherche dans ce qui précède le `?` (le contexte s'arrête déjà au dernier `;`).
    if RE_TERNAIRE.search(a):
        # une clé d'objet ordinaire (`value: 'x'`) se termine aussi par `:` -> ce n'est pas un puits
        if RE_CLE_AUTRE.search(a):
            return False
        q = a.rfind("?")
        if q > 0:
            tete = a[:q]
            return bool(RE_SINK_AFFECT_DANS.search(tete) or RE_SINK_CLE_DANS.search(tete) or RE_SINK_APPEL_DANS.search(tete))
    return False


# =====================================================================================================
# CE QUI SE COLLE À UN LITTÉRAL DANS LE NŒUD RENDU (`P11.13-f`)
# =====================================================================================================
# LE DÉFAUT CORRIGÉ, MESURÉ LE 2026-08-26. La règle précédente décidait « ce littéral n'est qu'un FRAGMENT
# d'une valeur composée » en remontant à la dernière PARENTHÈSE OUVERTE : elle lisait donc la MISE EN FORME
# de l'expression, pas ce qui atteint l'écran. Mesuré par mutation sur `web/detection_admin.js` : remplacer
# `a + (c ? 'ACTIF' : 'OBSERVE')` par `a + (c ? 'ACTIF' : (lu ? 'OBSERVE' : 'OBSERVE'))` — un niveau de
# parenthèses de plus, AUCUN changement du texte affiché — faisait passer `OBSERVE` d'« exclu » à
# « hors-regard », et le compte du module de 28 à 29 sous un plafond de 30. Le cliquet devenait un piège
# pour qui remanie : le verdict bougeait sans que rien d'affiché ne bouge.
#
# LA RÈGLE EST DÉSORMAIS CELLE DU NŒUD TEXTE, et elle est DÉRIVÉE de celle que la branche HTML applique
# déjà à ses bords : un `+` ne fabrique un fragment que s'il colle du TEXTE à du TEXTE. Quand ce qui se
# colle est une FRONTIÈRE DE BALISE (`…>` à gauche, `<…` à droite), le navigateur ouvre un nouveau nœud et
# le texte rendu est ce littéral SEUL — il est affiché, il se traduit, et il doit être au lexique.
# Les deux branches d'un même ternaire ne se collent PAS (elles s'excluent), et la CONDITION d'un ternaire
# n'est pas un voisin : on sort donc des ternaires et de leurs groupes avant de chercher le `+`. C'est ce
# qui rend le verdict indépendant du nombre de parenthèses.
#
# CE QUE LA RÈGLE NE TIENT PAS, ÉCRIT ICI. Elle lit une concaténation, pas un programme : un opérande qui
# n'est pas un littéral (`'<b>' + nom`) est traité comme du TEXTE collé — c'est le sens prudent, il
# maintient le littéral hors du dénominateur. Une balise écrite dans une chaîne posée en `textContent`
# (donc affichée LITTÉRALEMENT, jamais interprétée) serait lue comme une frontière de nœud alors qu'elle
# n'en est pas une : la garde regarderait alors une chaîne de PLUS, jamais une de moins.
OUVRANTES, FERMANTES, ARRETS = "([{", ")]}", ";,"


def _voisin_de_concatenation(contexte: tuple, sens: int) -> tuple[bool, str | None]:
    """(y a-t-il une colle `+` de ce côté ?, texte du littéral collé — None si l'opérande n'en est pas un).

    On sort des ternaires et des groupes : `?` (en remontant) précède une CONDITION, `:` sépare deux
    branches qui S'EXCLUENT — ni l'une ni l'autre n'est un voisin. Sortir d'un groupe (`(` en remontant,
    `)` en descendant) remet la lecture au niveau de la concaténation qui le porte, et c'est ce qui rend
    le résultat INDÉPENDANT du niveau de parenthèses (`P11.13-f`)."""
    code, p, litteraux = contexte
    j = p - 1 if sens < 0 else p + 2
    entrant, sortant = (FERMANTES, OUVRANTES) if sens < 0 else (OUVRANTES, FERMANTES)
    profondeur, hors_concat = 0, False
    while 0 <= j < len(code):
        c = code[j]
        if c in entrant:
            profondeur += 1
        elif c in sortant:
            profondeur -= 1
            if profondeur < 0:  # on sort du groupe : retour au niveau de la concaténation qui le porte
                profondeur, hors_concat = 0, False
        elif profondeur == 0:
            if c in ARRETS:
                return False, None
            if c in "?:" and not hors_concat:
                # condition d'un ternaire, ou branche jumelle : rien de tout cela ne se colle au nœud
                hors_concat = True
            elif c == "+" and not hors_concat:
                k = j + sens
                while 0 <= k < len(code) and code[k] in " \t\n":
                    k += sens
                debut = k - 1 if sens < 0 else k
                return True, (litteraux.get(debut) if code[debut:debut + 2] == '""' else None)
        j += sens
    return False, None


RE_BORD_BALISE_FIN = re.compile(r"<[a-zA-Z/][^<>]*>\s*$")
RE_BORD_BALISE_DEBUT = re.compile(r"^\s*<[a-zA-Z/][^<>]*>")


def _colle_dans_le_texte(cote: tuple[bool, str | None], fin: bool) -> bool:
    """Vrai si la colle de ce côté tombe DANS le nœud texte — le littéral n'en est alors qu'un fragment.
    Elle tombe sur une FRONTIÈRE quand le voisin ferme une balise (à gauche) ou en ouvre une (à droite)."""
    colle, voisin = cote
    if not colle:
        return False
    if voisin is None:
        return True  # opérande non littéral : on ne sait pas, et le sens prudent est « du texte se colle »
    return not (RE_BORD_BALISE_FIN if fin else RE_BORD_BALISE_DEBUT).search(voisin)


def _noeud_de_composition_html(gauche: tuple[bool, str | None], droite: tuple[bool, str | None]) -> bool:
    """Vrai si le littéral est le TEXTE ENTRE BALISES d'une composition HTML écrite en plusieurs morceaux
    (`'<span>' + (c ? 'A' : 'B') + '</span>'`) : au moins un côté est une frontière de balise, et aucun
    côté ne colle du texte. Le nœud rendu vaut alors ce littéral SEUL — c'est un texte AFFICHÉ, au même
    titre que le texte entre balises d'un littéral HTML d'un seul tenant."""
    if _colle_dans_le_texte(gauche, True) or _colle_dans_le_texte(droite, False):
        return False
    return (gauche[0] and gauche[1] is not None) or (droite[0] and droite[1] is not None)


def _non_puits_reconnu(avant: str, attribut: str = "") -> bool:
    """Vrai si le littéral est posé dans un emplacement dont on SAIT qu'il n'affiche pas de texte."""
    a = avant.rstrip()
    if RE_SINK_SETATTR.search(a):
        return attribut.strip() not in ATTRS_HTML
    return bool(RE_NON_PUITS.search(a))


# LA FORME D'UN HORS-REGARD EST DÉRIVÉE DU CONTEXTE, PAS ÉNUMÉRÉE (`P11.8-c`). L'aveu disait COMBIEN la
# garde ne regarde pas ; il ne disait pas QUOI, et la répartition ne vivait qu'en commentaire — donc datée
# d'un jour et fausse le lendemain. Elle est maintenant recalculée à chaque exécution à partir du seul texte
# qui précède le littéral, et c'est elle qui nomme la prochaine forme à apprendre.
RE_RETOUR = re.compile(r"\breturn\s*$")


def forme_hors_regard(avant: str, attribut: str = "") -> str:
    """La forme par laquelle un littéral rejoint (peut-être) le document, quand aucun puits ne le porte."""
    a = avant.rstrip()
    m = RE_CLE_AUTRE.search(a)
    if m:
        return f"valeur sous la clé d'objet « {m.group(1)} »"
    if RE_CLE_LITTERALE.search(a):
        return f"valeur sous la clé d'objet « {attribut.strip()} »"
    if RE_RETOUR.search(a):
        return "valeur de retour"
    if a.endswith("("):
        return "argument d'un appel"
    if a.endswith(",") or a.endswith("["):
        return "entrée de tableau ou argument suivant"
    if a.endswith("?") or a.endswith(":"):
        return "branche de ternaire"
    return "forme non classée"


def _dynamique(s: str, gauche: tuple[bool, str | None], droite: tuple[bool, str | None]) -> bool:
    """Le nœud rendu vaut-il PLUS que ce littéral ? Une interpolation `${…}` le dit d'elle-même ; sinon
    c'est une colle `+` QUI TOMBE DANS LE TEXTE (`P11.13-f`) — une colle qui tombe sur une frontière de
    balise laisse au contraire le littéral seul dans son nœud, et il est alors affiché tel quel."""
    if SENTINELLE in s:
        return True
    return _colle_dans_le_texte(gauche, True) or _colle_dans_le_texte(droite, False)


RE_CODE_MAJUSCULE = re.compile(r"^[A-Z0-9_.:/\-]+$")


def _candidat(s: str) -> bool:
    t = s.strip()
    if len(t) < 2 or not RE_LETTRE.search(t):
        return False
    if RE_IDENTIFIANT.match(t) and not RE_DEUX_MOTS_CONSECUTIFS.search(t):
        return False
    # Un code en majuscules sans espace (`T1110`, `CSV`, `OK`) est identique dans les deux langues :
    # hors population s'il porte un chiffre ou tient en quatre signes. `RETARD` (six lettres) reste.
    if RE_CODE_MAJUSCULE.match(t) and (any(ch.isdigit() for ch in t) or len(t) <= 4):
        return False
    return True


def _noeuds_html(fragment: str) -> tuple[list[str], list[str], list[str]]:
    """(attributs affichés statiques, attributs affichés dynamiques, nœuds TEXTE EN ORDRE DE DOCUMENT).
    L'ordre des nœuds texte est nécessaire pour savoir lesquels sont aux BORDS du littéral : ce sont les
    seuls qu'une concaténation puisse coller à autre chose."""
    stat, dyn, donnees = [], [], []

    class P(html.parser.HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.skip = 0

        def handle_starttag(self, tag, attrs):
            if tag in TAGS_HORS_POPULATION:
                self.skip += 1
            for k, v in attrs:
                if k in ATTRS_HTML and v:
                    (dyn if SENTINELLE in v else stat).append(v)

        def handle_endtag(self, tag):
            if tag in TAGS_HORS_POPULATION and self.skip:
                self.skip -= 1

        def handle_data(self, data):
            if self.skip:
                return
            donnees.append(data)

    p = P()
    try:
        p.feed(fragment)
    except Exception:
        pass
    return stat, dyn, donnees


def _textes_html(fragment: str) -> tuple[list[str], list[str]]:
    """Texte entre balises + attributs affichés d'un fragment HTML ; rend (statiques, dynamiques)."""
    a_st, a_dy, donnees = _noeuds_html(fragment)
    return a_st + [d for d in donnees if SENTINELLE not in d], a_dy + [d for d in donnees if SENTINELLE in d]


def extraire_module(src: str, journal: list[tuple[str, int]] | None = None) -> tuple[list[str], list[str], list[str], list[str]]:
    """(statiques affichées, dynamiques affichées, bilingues par construction, HORS-REGARD) d'un module JS.

    HORS-REGARD : un littéral qui a la FORME d'un libellé (candidat, statique, pas bilingue par construction)
    et que le critère de puits ne reconnaît PAS. La garde ne sait pas dire s'il est affiché — c'est justement
    ce qu'elle publie, plutôt que de rendre vert sur un périmètre qu'elle tait. Chaque entrée est un couple
    (texte, FORME dérivée du contexte) : c'est la forme qui nomme la prochaine à apprendre."""
    statiques, dynamiques, par_construction, hors_regard = [], [], [], []
    precedent = ""
    for s, avant, apres, bloc_en, contexte in chaines_js(src, journal):
        # le littéral qui PRÉCÈDE : c'est le nom d'attribut d'un `setAttribute('x', 'valeur')`
        courant, attribut_precedent, precedent = s, precedent, s
        # CE QUI SE COLLE À CE LITTÉRAL DANS LE NŒUD RENDU (`P11.13-f`) — la MÊME lecture pour un littéral
        # HTML et pour un littéral nu : ce sont les deux moitiés d'une seule question, « le nœud vaut-il
        # plus que ce texte ? ». Elle ne dépend plus du niveau de parenthèses.
        gauche = _voisin_de_concatenation(contexte, -1)
        droite = _voisin_de_concatenation(contexte, +1)
        if RE_CLE_FR_EN.search(avant.rstrip()):
            # valeur d'une paire `{ fr: '…', en: '…' }` : bilingue par construction, HTML ou non
            if _candidat(courant.replace(SENTINELLE, "")):
                par_construction.append(courant)
            continue
        if RE_HTML.search(courant):
            att_st, att_dy, donnees = _noeuds_html(courant)
            if bloc_en:
                # version EN dédiée d'un bloc riche (`if (LANG === 'en') { el.innerHTML = '…' }`) : bilingue par
                # construction, son pendant FR est dans index.html
                par_construction += [x for x in att_st + [d for d in donnees if SENTINELLE not in d] if _candidat(x)]
                continue
            # UN LITTÉRAL HTML COLLÉ À UNE EXPRESSION (`'<div>erreur : ' + msg`) : le nœud texte rendu n'est pas
            # ce littéral, c'est lui PLUS ce qui s'y colle — jamais égal à une clé, donc dynamique et hors
            # dénominateur. Seuls les nœuds de BORD sont concernés (un texte encadré par des balises reste un
            # nœud entier), et seulement du côté où la colle a lieu et où le littéral ne finit/commence pas
            # par une balise.
            colles = set()
            if donnees:
                if _colle_dans_le_texte(droite, False) and not courant.rstrip().endswith(">"):
                    colles.add(len(donnees) - 1)
                if _colle_dans_le_texte(gauche, True) and not courant.lstrip().startswith("<"):
                    colles.add(0)
            st, dy = list(att_st), list(att_dy)
            for i, d in enumerate(donnees):
                (dy if (SENTINELLE in d or i in colles) else st).append(d)
            statiques += [x for x in st if _candidat(x)]
            dynamiques += [x for x in dy if _candidat(x.replace(SENTINELLE, ""))]
            continue
        candidat = _candidat(courant.replace(SENTINELLE, ""))
        # LE TEXTE ENTRE BALISES D'UNE COMPOSITION ÉCRITE EN PLUSIEURS MORCEAUX (`P11.13-f`). Le puits n'est
        # pas dans le code qui précède ce littéral : il est dans les BALISES qui l'encadrent, exactement
        # comme pour le texte entre balises d'un littéral HTML d'un seul tenant. Le nœud rendu vaut ce
        # littéral SEUL, `i18nWalk` le compare donc bien à une clé — il est AFFICHÉ.
        if candidat and SENTINELLE not in courant and _noeud_de_composition_html(gauche, droite):
            (par_construction if (bloc_en or RE_CHOIX_PAR_LANG.search(avant)) else statiques).append(courant)
            continue
        if not _est_puits(avant, attribut_precedent):
            # AUCUN puits reconnu : la garde ne regarde pas là. On le DIT au lieu de l'oublier.
            if (candidat and not _dynamique(courant, gauche, droite)
                    and not (bloc_en or RE_CHOIX_PAR_LANG.search(avant))
                    and not _non_puits_reconnu(avant, attribut_precedent)):
                hors_regard.append((courant, forme_hors_regard(avant, attribut_precedent)))
            continue
        if not candidat:
            continue
        if _dynamique(courant, gauche, droite):
            dynamiques.append(courant)
        elif bloc_en or RE_CHOIX_PAR_LANG.search(avant):
            par_construction.append(courant)
        else:
            statiques.append(courant)
    return statiques, dynamiques, par_construction, hors_regard


def extraire_index_html(src: str) -> list[str]:
    st, _ = _textes_html(src)
    return [x for x in st if _candidat(x)]


# ---------------------------------------------------------------------------------------------
# LE NŒUD RENDU, PAS LE LITTÉRAL ÉCRIT (`P11.8-i`).
# ---------------------------------------------------------------------------------------------
# Tout ce qui précède lit UN littéral à la fois. `i18nWalk`, lui, compare un NŒUD TEXTE entier, blancs
# retirés. Les deux coïncident tant qu'une balise borne le littéral ; ils divergent dès qu'un nœud
# TRAVERSE une borne de littéral (`'…ATT&CK. ' + 'Déposez un <b>…'` rend UN nœud « …ATT&CK. Déposez un »).
# Ce nœud-là n'était jugé par personne : la lecture par littéral le voit en DEUX moitiés, les range en
# « dynamique » — donc hors dénominateur — et le compte de trous ne bouge pas. Pire, depuis que le corpus
# de la sonde d'excès porte une copie aux entités résolues, une clé qui n'est que le DÉBUT d'un tel nœud
# n'est plus accusée à tort : elle est rangée en INDÉCIDABLE, c'est-à-dire TUE. Le remède avait éteint le
# seul signal qui désignait cette famille.
# LA SORTIE EST D'ÉNUMÉRER LES NŒUDS, PAS DE DÉCOUPER DES LITTÉRAUX, et elle demande un analyseur de
# balisage. `html.parser` est de la BIBLIOTHÈQUE STANDARD (la CI n'installe rien) et cette garde s'en sert
# déjà pour les littéraux HTML d'un seul tenant. LA RÉPONSE EST DONC OUI, ET ELLE EST MESURÉE — 2026-08-30,
# sur `web/` hors la portée exempte du registre : 183 chaînes de concaténation portent du balisage, 15 sont
# écrites en PLUSIEURS littéraux, et 175 (95,6 %) sont lues sans le moindre aveu. Les 8 restantes (4,4 %)
# ne sont PAS lisibles, et c'est le point qui décide de tout : une garde bâtie sur un analyseur qui se
# trompe EN SILENCE serait pire que l'angle mort qu'elle comble. Elle refuse donc de conclure sur celles-là
# et les NOMME, une par une. Le motif relevé aujourd'hui est UN seul, sur trois modules (alerts.js 3,
# core.js 2, freshness.js 3) : UNE INTERPOLATION TOMBE DANS UNE BALISE, hors d'une valeur d'attribut entre
# guillemets (`` `<button …${dis}>` ``) — l'expression peut y poser un attribut, voire refermer la balise,
# et l'arbre rendu n'est alors pas celui qui est lu. Trois autres motifs sont armés et muets aujourd'hui
# (l'analyseur lève ; une balise hors-population jamais refermée ; un nœud texte qui porte un chevron de
# balise, `lookup <nom> <champ>`) ; le corpus de contrôle les exerce, faute de quoi ils seraient morts sans
# que rien ne le dise.
# CE QUI A ÉTÉ ÉCARTÉ PAR LA MESURE, ET NON PAR L'AVIS : un premier jeu de règles avouait 14 fragments au
# lieu de 8. SIX de ces aveux étaient FAUX. Quatre venaient de corps d'aide en TEXTE PUR que `RE_HTML`
# prenait pour du balisage parce qu'ils citent `lookup <nom>` — ils sont dans la portée exempte du registre
# et n'ont jamais atteint cette mesure. Les deux autres venaient d'un test de chevron trop large : `&lt;`
# résolu en `<` par l'analyseur (« frais (donnée < 15 min) »), et un `>` sans `<` (`'"></span>'`). Un aveu
# qui crie au loup use son propre crédit : le test porte donc sur `<` SUIVI d'un début de nom de balise.
# CE QUE CETTE MESURE NE PRÉTEND PAS. Elle ne joint QUE `litt + litt` au MÊME niveau de groupe : elle
# refuse de traverser une parenthèse ou un ternaire, parce qu'un ternaire rend DEUX nœuds possibles et
# qu'en choisir un serait inventer. Le prix est mesuré : `web/fleet.js` assemble « … muet(s) » puis, sous
# condition, « · <b>…</b> muet(s) attendu(s) » — deux nœuds réels, aucun des deux jugé ici. C'est un
# SOUS-compte assumé, du même sens que tous les autres biais de ce fichier.
def _colle_directe(contexte: tuple, sens: int) -> tuple[bool, int | None]:
    """(y a-t-il une colle `+` de ce côté ?, position du littéral collé — None si l'opérande n'en est pas un).

    STRICTE À DESSEIN, et c'est ce qui la distingue de `_voisin_de_concatenation` : celle-là répond « ce
    littéral est-il le nœud ENTIER ? » et a raison de sortir des groupes ; celle-ci construit le TEXTE
    assemblé, et sortir d'un groupe y ferait choisir une branche de ternaire au hasard."""
    code, p, litteraux = contexte
    j = p - 1 if sens < 0 else p + 2
    entrant, sortant = (FERMANTES, OUVRANTES) if sens < 0 else (OUVRANTES, FERMANTES)
    profondeur = 0
    while 0 <= j < len(code):
        c = code[j]
        if c in entrant:
            profondeur += 1
        elif c in sortant:
            profondeur -= 1
            if profondeur < 0:
                return False, None  # on SORT du groupe : l'assemblage cesse d'être inconditionnel
        elif profondeur == 0:
            if c in ARRETS or c in "?:":
                return False, None
            if c == "+":
                k = j + sens
                while 0 <= k < len(code) and code[k] in " \t\n":
                    k += sens
                debut = k - 1 if sens < 0 else k
                if code[debut : debut + 2] == '""' and debut in litteraux:
                    return True, debut
                return True, None
        j += sens
    return False, None


RE_CHEVRON_DE_BALISE = re.compile(r"<[a-zA-Z/!?]")


def _interpolation_dans_une_balise(fragment: str) -> bool:
    """Vrai si une interpolation `${…}` tombe DANS une balise ailleurs que dans une valeur d'attribut
    entre guillemets. Là, elle peut poser un attribut entier ou refermer la balise : ce que l'analyseur
    lit n'est plus ce que le navigateur construira."""
    i, n = 0, len(fragment)
    while i < n:
        if fragment[i] == "<" and i + 1 < n and (fragment[i + 1].isalpha() or fragment[i + 1] == "/"):
            j, guillemet = i + 1, ""
            while j < n:
                c = fragment[j]
                if guillemet:
                    if c == guillemet:
                        guillemet = ""
                elif c in "\"'":
                    guillemet = c
                elif c == ">":
                    break
                elif c == SENTINELLE:
                    return True
                j += 1
            i = j
        i += 1
    return False


def lire_fragment_de_balisage(fragment: str) -> tuple[list[str], list[str]]:
    """(nœuds TEXTE en ordre de document, AVEUX). Un aveu non vide = fragment NON ANALYSABLE : ses nœuds
    ne sont PAS jugés et il est NOMMÉ. Rendre un compte sur un fragment mal lu serait un vert menteur."""
    aveux: list[str] = []
    donnees: list[str] = []
    ouverts: list[str] = []

    class P(html.parser.HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.skip = 0

        def handle_starttag(self, tag, attrs):
            if tag in TAGS_HORS_POPULATION:
                self.skip += 1
                ouverts.append(tag)

        def handle_endtag(self, tag):
            if tag in TAGS_HORS_POPULATION:
                if self.skip:
                    self.skip -= 1
                if ouverts and ouverts[-1] == tag:
                    ouverts.pop()

        def handle_data(self, data):
            if not self.skip:
                donnees.append(data)

    p = P()
    try:
        p.feed(fragment)
        p.close()
    except Exception as e:  # noqa: BLE001 — un analyseur qui lève est un analyseur qui n'a pas lu
        aveux.append(f"l'analyseur de balisage a levé {type(e).__name__}")
    if _interpolation_dans_une_balise(fragment):
        aveux.append("une interpolation `${…}` tombe DANS une balise, hors d'une valeur d'attribut entre "
                     "guillemets : elle peut y poser un attribut ou refermer la balise")
    if ouverts:
        aveux.append(f"la balise hors-population <{ouverts[0]}> n'est jamais refermée : tout ce qui suit "
                     f"serait tu sans qu'on sache s'il est montré tel quel")
    for d in donnees:
        if RE_CHEVRON_DE_BALISE.search(d):
            aveux.append(f"un nœud texte porte un chevron de balise ({d.strip()[:60]!r}) : texte montré tel "
                         f"quel, ou balisage que le fragment n'a pas fini d'écrire ?")
            break
    if getattr(p, "rawdata", ""):
        aveux.append(f"l'analyseur laisse un reste non consommé ({p.rawdata[:60]!r})")
    return donnees, aveux


def noeuds_a_cheval(src: str, cles: set[str], journal: list[tuple[str, int]] | None = None
                    ) -> tuple[list[str], list[str]]:
    """(nœuds RENDUS sans clé qui TRAVERSENT une borne de littéral, fragments NON ANALYSABLES nommés).

    Un nœud « à cheval » est celui que la lecture littéral-par-littéral ne voit JAMAIS entier. Il est
    reconnu par DIFFÉRENCE : c'est un nœud du fragment JOINT qu'aucun littéral pris seul ne rend. Le reste
    des nœuds est déjà jugé par `extraire_module` — les compter ici les compterait deux fois."""
    res = chaines_js(src, journal)
    if not res:
        return [], []
    texte_code = res[0][4][0]
    litteraux = res[0][4][2]
    manquants: list[str] = []
    illisibles: list[str] = []
    vues: set[tuple[int, ...]] = set()
    for _, avant, _, bloc_en, contexte in res:
        p = contexte[1]
        if bloc_en or RE_CHOIX_PAR_LANG.search(avant) or RE_CLE_FR_EN.search(avant.rstrip()):
            continue  # bilingue par construction : son pendant est ailleurs, pas au lexique
        positions, bord_gauche, bord_droit = [p], False, False
        q = p
        while True:
            colle, r = _colle_directe((texte_code, q, litteraux), -1)
            if r is None:
                bord_gauche = colle  # une colle dont l'opérande n'est PAS un littéral : bord ouvert
                break
            positions.insert(0, r)
            q = r
        q = p
        while True:
            colle, r = _colle_directe((texte_code, q, litteraux), +1)
            if r is None:
                bord_droit = colle
                break
            positions.append(r)
            q = r
        cle_chaine = tuple(positions)
        if cle_chaine in vues:
            continue
        vues.add(cle_chaine)
        morceaux = [litteraux[x] for x in positions]
        fragment = "".join(morceaux)
        if not RE_HTML.search(fragment):
            continue
        donnees, aveux = lire_fragment_de_balisage(fragment)
        if aveux:
            illisibles.append(f"{aveux[0]} — fragment : {fragment[:90]!r}")
            continue
        if len(positions) < 2:
            continue  # un seul littéral : aucun nœud ne peut être à cheval, `extraire_module` les tient tous
        par_litteral = set()
        for m in morceaux:
            par_litteral |= {d.strip() for d in _noeuds_html(m)[2] if d.strip()}
        # UN NŒUD DE BORD COLLÉ À UNE EXPRESSION vaut PLUS que ce fragment : même règle qu'`extraire_module`.
        exclus = set()
        if donnees:
            if bord_droit and not fragment.rstrip().endswith(">"):
                exclus.add(len(donnees) - 1)
            if bord_gauche and not fragment.lstrip().startswith("<"):
                exclus.add(0)
        for i, d in enumerate(donnees):
            t = d.strip()
            if not t or i in exclus or SENTINELLE in d or t in par_litteral:
                continue
            if _candidat(d) and t not in cles:
                manquants.append(t)
    return manquants, illisibles



def cles_du_lexique(src: str) -> set[str]:
    m = re.search(r"const I18N_EN\s*=\s*\{(.*?)\n\};", src, re.S)
    if not m:
        return set()
    corps = m.group(1)
    cles = set()
    for s, avant, _, _, _ in chaines_js(corps):
        # une CLÉ est un littéral suivi de `:` ; la tokenisation remplace les littéraux par `""`,
        # donc on regarde le code qui PRÉCÈDE : une clé est précédée de `{`, `,` ou d'un début de ligne.
        a = avant.rstrip()
        if a == "" or a.endswith(",") or a.endswith("{"):
            cles.add(s.strip())
    return cles


# ---------------------------------------------------------------------------------------------
# L'excès : ce que le lexique porte et que plus rien ne sert (`P11.8-g`).
# ---------------------------------------------------------------------------------------------
def corpus_du_depot() -> tuple[str, set[str]]:
    """(TEXTE du dépôt qui peut atteindre un nœud rendu, LITTÉRAUX de l'arbre servi).

    Le texte porte chaque source TEL QU'ÉCRIT et, quand elles en diffèrent, sa copie DÉSÉCHAPPÉE et sa copie
    aux ENTITÉS HTML RÉSOLUES : sans la première, une phrase servie dans une interpolation à guillemets
    échappés paraît ABSENTE du dépôt et sa clé se fait accuser à tort (mesuré le 2026-08-29 sur
    `web/alerts.js`, « Toutes les alertes sont listées… ») ; sans la seconde, une phrase servie à travers une
    entité subit le MÊME sort, et c'est le même défaut sous une autre écriture — le navigateur rend `&amp;`
    comme `&`, si bien que le nœud vaut la clé alors que le source, lu tel quel, ne la contient nulle part.
    MESURÉ le 2026-08-29 : la clé « (standard ouvert) pour combler les angles morts ATT&CK. » était accusée
    au motif « texte absent du dépôt ENTIER » alors que `web/sigmaimport.js:194` l'écrit `ATT&amp;CK` — motif
    FAUX. Et le risque n'est pas anecdotique : `web/index.html` porte 59 entités à lui seul (21 `&amp;`,
    12 `&rarr;`, 8 `&lt;`, 8 `&gt;`…), les modules de `web/` une douzaine de plus. La clé était morte pour une AUTRE raison
    (le nœud rendu porte « … Déposez un » en plus, donc la clé n'en est qu'un MORCEAU) et elle est retirée,
    mais un motif faux qui tombe juste reste un instrument qui ment. Cette copie ne peut que faire passer une
    clé d'ORPHELINE à INDÉCIDABLE, jamais l'inverse : le biais va toujours vers le refus d'accuser.
    Les LITTÉRAUX, eux, ne viennent que de l'arbre servi et de sources SANS COMMENTAIRES : un littéral cité
    dans un commentaire n'en est pas un, et c'est avec eux seuls qu'on juge si un nœud COMPOSÉ peut valoir la
    clé. Le texte, lui, GARDE les commentaires — voir l'en-tête : le biais va vers l'indécidable."""
    morceaux: list[str] = []
    litteraux: set[str] = set()
    for base, dossiers, fichiers in os.walk(RACINE):
        # LE MÊME NOM EXCLUT LES DEUX, ET LES DEUX LIGNES SE LISENT ENSEMBLE POUR QU'ELLES NE DÉRIVENT PLUS
        # (`P11.8-l`) : un `.git` RÉPERTOIRE et un `.git` FICHIER sont le même artefact sous deux modes de
        # sortie de l'arbre ; n'en retirer qu'un rendait la mesure dépendante de celui qu'on avait sous la main.
        dossiers[:] = [d for d in dossiers if d not in NOMS_HORS_CORPUS]
        for f in sorted(fichiers):
            if f in NOMS_HORS_CORPUS:
                continue
            chemin = os.path.join(base, f)
            if chemin == LEXIQUE or f.endswith(".md"):
                continue
            try:
                with open(chemin, encoding="utf-8") as fh:
                    src = fh.read()
            except (UnicodeDecodeError, OSError, ValueError):
                continue  # binaire ou illisible : il ne sert aucun libellé
            morceaux.append(src)
            for copie in (RE_ECHAPPEMENT.sub(r"\1", src), html.unescape(src)):
                if copie != src:
                    morceaux.append(copie)
            if os.path.dirname(chemin) == WEB and f.endswith(".js"):
                for s, *_ in chaines_js(sans_commentaires_js(src)):
                    litteraux.add(s)
                    morceaux.append(s)
            elif chemin == os.path.join(WEB, "index.html"):
                textes, attributs = _textes_html(src)
                litteraux.update(textes)
                litteraux.update(attributs)
                morceaux += textes + attributs
    return SEPARATEUR_CORPUS.join(morceaux), litteraux


def _coupe_entre_deux_mots(texte: str, i: int) -> bool:
    """La coupe à l'indice `i` tombe-t-elle sur une frontière de mot ? Un assemblage de libellés coupe ENTRE
    les mots (`'connecteur ' + 'activé'`), jamais au milieu de l'un d'eux. Sans cette condition, n'importe
    quel littéral de deux lettres prétendrait pouvoir commencer n'importe quelle phrase : mesuré le
    2026-08-29, le littéral `Go` (une unité d'octets de `web/viz.js`) se donnait pour le début de
    « Gouvernance d'accès … » et rendait la clé de `P11.20-e` indécidable."""
    return (i <= 0 or i >= len(texte)
            or not (RE_CORPS_DE_MOT.match(texte[i - 1]) and RE_CORPS_DE_MOT.match(texte[i])))


def fragment_de_bord(cle: str, litteraux: set[str]) -> str | None:
    """Le plus long littéral de l'arbre servi qui pourrait former le BORD d'un nœud composé valant `cle` :
    un préfixe ou un suffixe, coupé sur une frontière de mot, portant au moins une lettre. Un fragment sans
    lettre (`.`, `)`) ne porte aucun texte — l'admettre rendrait composable toute phrase ponctuée."""
    meilleur = None
    for lit in litteraux:
        if not lit or lit == cle or not RE_LETTRE.search(lit):
            continue
        if cle.startswith(lit):
            if not _coupe_entre_deux_mots(cle, len(lit)):
                continue
        elif cle.endswith(lit):
            if not _coupe_entre_deux_mots(cle, len(cle) - len(lit)):
                continue
        else:
            continue
        if meilleur is None or len(lit) > len(meilleur):
            meilleur = lit
    return meilleur


def verdict_d_une_cle(cle: str, vivantes: set[str], corpus: str, litteraux: set[str]) -> tuple[str, str]:
    """« vivante » / « indecidable » / « orpheline », avec son MOTIF. C'est le SEUL chemin de classement :
    les témoins de l'instrument passent par lui, faute de quoi ils vaudraient pour un autre code que celui
    qui rend le verdict."""
    if cle in vivantes:
        return "vivante", "vue comme chaîne affichée dans un puits reconnu"
    if cle in corpus:
        return "indecidable", "texte présent dans le dépôt, hors d'un puits reconnu"
    bord = fragment_de_bord(cle, litteraux)
    if bord is not None:
        return "indecidable", f"composable — un littéral de l'arbre en formerait le bord : « {bord} »"
    return "orpheline", "texte absent du dépôt entier, et aucun littéral n'en formerait le bord"


def excedent_du_lexique(cles: set[str], vivantes: set[str], corpus: str,
                        litteraux: set[str]) -> dict[str, list[tuple[str, str]]]:
    verdicts: dict[str, list[tuple[str, str]]] = {"vivante": [], "indecidable": [], "orpheline": []}
    for cle in sorted(cles):
        verdict, motif = verdict_d_une_cle(cle, vivantes, corpus, litteraux)
        verdicts[verdict].append((cle, motif))
    return verdicts


# LE TÉMOIN NÉGATIF SE CHOISIT, IL NE S'IMPROVISE PAS. Premier essai le 2026-08-29 : « Libellé témoin de la
# sonde d'excès… » — rendu INDÉCIDABLE, et à raison, parce que `Libellé` EST un littéral de l'arbre et en
# formait le bord. Le témoin doit donc commencer ET finir par un mot qu'aucun littéral ne peut porter, sans
# quoi il ne prouve pas ce qu'il prétend prouver. Il ne vit que dans ce fichier, et `.github` est hors corpus :
# c'est cette exclusion, et elle seule, qui garde ce témoin absent du dépôt.
TEMOIN_JAMAIS_ECRIT = "Zzyxqv témoin négatif de la sonde d'excès, écrit nulle part Wqxzzy"


def valider_sonde_d_exces(vivantes: set[str], corpus: str, litteraux: set[str],
                          hors_regard: set[str]) -> list[str]:
    """QUATRE TÉMOINS, JOUÉS SUR L'ARBRE RÉEL ET PAR LE CHEMIN DU VERDICT. Une sonde d'orphelines qui ne
    trouve plus son corpus accuse TOUTES les clés et se croit juste ; une sonde validée sur un corpus VIDE
    passe au vert en ne mesurant rien. Les deux planchers ferment ces deux morts, et les témoins ferment les
    trois verdicts : POSITIF (une clé qu'on SAIT affichée est vivante), NÉGATIF (une clé jamais écrite est
    accusée), COMPOSITION (un littéral de l'arbre suivi d'un mot inventé n'est PAS accusé — c'est le témoin
    qui garde le sens de l'erreur), CORPUS (un texte que la garde publie comme hors-regard est indécidable,
    donc la lecture du corpus fonctionne sur du texte RÉEL, pas seulement sur des chaînes inventées)."""
    errs: list[str] = []
    if len(corpus) < MIN_CORPUS:
        errs.append(f"corpus de {len(corpus)} octets, plancher {MIN_CORPUS} : la lecture du dépôt est cassée. "
                    f"Une sonde d'orphelines sur un corpus amputé ACCUSE des clés vivantes.")
    if len(vivantes) < MIN_CLES_VIVANTES:
        errs.append(f"{len(vivantes)} clés vues comme chaîne affichée, plancher {MIN_CLES_VIVANTES} : "
                    f"l'appariement lexique/population est cassé, et tout le reste serait accusé.")
    # TÉMOIN DU MODE DE SORTIE (`P11.8-l`, 2026-08-31). Un pointeur `gitdir:` en tête d'un morceau du corpus
    # signe un artefact de PLOMBERIE git lu comme du texte servi : le `.git` FICHIER que pose un arbre de
    # travail lié ou un sous-module. Il ne fait pas ROUGIR le lexique, il fait REFUSER DE CONCLURE — la
    # grandeur mesurée dépendrait de la longueur du chemin où l'arbre a été posé, et aucun relevé pris là ne
    # serait attribuable à un commit. Le motif est cherché en TÊTE de morceau — début du corpus, ou juste
    # après un séparateur — et non n'importe où : un texte qui PARLE de `gitdir` n'est pas un pointeur, et une
    # garde qui refuserait de conclure sur une phrase de documentation serait une rançon.
    # CE QU'IL N'ACHÈTE PAS, ET C'EST LA MOITIÉ QUI COMPTE : en intégration continue l'arbre est un clone
    # ordinaire, ce témoin y est vert QUOI QU'IL ARRIVE, et il ne garde donc PAS la CI contre un retour en
    # arrière de `NOMS_HORS_CORPUS`. Il ne garde que celui qui PREND un relevé depuis un arbre lié — c'est-
    # à-dire exactement le geste par lequel le défaut est entré, et le seul où la valeur fausse serait écrite.
    if corpus.startswith("gitdir: ") or "\x1e\ngitdir: " in corpus:
        errs.append("le corpus porte un pointeur `gitdir:` : un `.git` de plomberie (arbre de travail LIÉ ou "
                    "sous-module) y est entré comme s'il était du texte servi. La mesure dépend alors de la "
                    "LONGUEUR DU CHEMIN où l'arbre a été posé — deux sorties du même commit ne rendent pas le "
                    "même nombre, et aucun relevé pris ici n'est attribuable à un commit.")
    if errs:
        return errs  # les témoins qui suivent n'auraient plus de corpus à quoi se mesurer
    verdict, _ = verdict_d_une_cle(CLE_TEMOIN, vivantes, corpus, litteraux)
    if verdict != "vivante":
        errs.append(f"témoin POSITIF : la clé « {CLE_TEMOIN} », affichée par `web/index.html`, est rendue "
                    f"« {verdict} » — la sonde ne reconnaît plus une clé vivante et va accuser le lexique entier.")
    verdict, _ = verdict_d_une_cle(TEMOIN_JAMAIS_ECRIT, vivantes, corpus, litteraux)
    if verdict != "orpheline":
        errs.append(f"témoin NÉGATIF : une clé que rien n'écrit est rendue « {verdict} » au lieu d'orpheline — "
                    f"la sonde ne sait plus rien accuser, et son vert ne mesure plus rien.")
    socle = max((lit for lit in litteraux
                 if RE_LETTRE.search(lit) and SENTINELLE not in lit and lit.strip() == lit),
                key=len, default="")
    verdict, _ = verdict_d_une_cle(socle + " témoinjamaisécrit", vivantes, corpus, litteraux)
    if verdict != "indecidable":
        errs.append(f"témoin de COMPOSITION : un littéral RÉEL de l'arbre suivi d'un mot inventé est rendu "
                    f"« {verdict} » au lieu d'indécidable — la sonde accuserait les nœuds composés "
                    f"(`'connecteur ' + etat`), c'est-à-dire ferait retirer des clés VIVANTES.")
    temoin_corpus = max((h for h in hors_regard if h not in vivantes and RE_LETTRE.search(h)),
                        key=len, default=None)
    if temoin_corpus is None:
        errs.append("témoin de CORPUS : aucun hors-regard non vivant sur l'arbre — le témoin ne peut plus se "
                    "dériver du dépôt, et la lecture du corpus n'est plus éprouvée sur du texte réel.")
    else:
        verdict, _ = verdict_d_une_cle(temoin_corpus, vivantes, corpus, litteraux)
        if verdict != "indecidable":
            errs.append(f"témoin de CORPUS : un texte que la garde publie elle-même en hors-regard "
                        f"(« {temoin_corpus[:60]} ») est rendu « {verdict} » au lieu d'indécidable — la sonde "
                        f"ne retrouve plus dans le corpus un texte dont le dépôt atteste qu'il y est.")
    return errs


# ---------------------------------------------------------------------------------------------
# Témoins de l'instrument : ce qu'il DOIT voir, ce qu'il NE DOIT PAS compter.
# ---------------------------------------------------------------------------------------------
CORPUS_TEMOIN = r"""
// commentaire : 'Pas affiché'
const a = document.createElement('div'); a.className = 'pas-une-chaine affichée';
a.textContent = 'Affiché un';
b.title = "Affiché deux";
c.placeholder = 'Affiché trois';
d.innerText = cond ? 'Affiché quatre' : 'Affiché cinq';
const f = [{ name: 'x', label: 'Affiché six', value: 'valeur_technique' }];
host.appendChild(muted('Affiché sept'));
toast('Affiché huit', 'ok');
el.setAttribute('aria-label', 'Affiché neuf');
el.innerHTML = `<span class="k">Affiché dix</span><b title="Affiché onze">${x}</b>`;
el.innerHTML = '<div class="muted">Affiché douze</div>';
e.textContent = 'Dynamique un : ' + n;
g.textContent = `Dynamique deux ${n}`;
q.textContent = n + (cond ? 'Fragment de ternaire' : '');
r.innerHTML = '<div class="bad">Fragment HTML de bord : ' + msg + '</div>';
const re = /tronqué|'pas une chaîne'/i; h.textContent = 'Affiché treize';
i.textContent = 'src_ip';
i2.textContent = '/api/v1/alerts'; i3.textContent = 'count'; i4.textContent = 'sort -count';
p1.textContent = 'aucun runbook'; p2.textContent = 'nom et champ requis';
j.textContent = 'T1110';
k.textContent = '…';
l.textContent = LANG === 'en' ? 'Bilingual' : 'Bilingue';
if (LANG === 'en') { m.textContent = 'English only'; if (x) { n.innerHTML = '<b>English rich</b>'; } }
o.textContent = 'Affiché quatorze';
el.innerHTML = '<p>Affiché quinze <code>pas_un_libellé(x)</code> <kbd>Ctrl</kbd></p><optgroup label="Affiché seize"></optgroup>';
const paires = [{ t: 'x', fr: 'Paire française <nom>', en: 'English pair <name>' }];
const lit = `"${String(v).replace(/"/g, '')}"`; u.textContent = 'Affiché dix-sept';
host.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'Affiché dix-huit' }));
w.appendChild(Object.assign(document.createElement('i'), { 'aria-label': 'Affiché dix-neuf' }));
const dur = { storeKey: 'Sous une clé que le document ne connaît pas' };
const fab = { emptyText: 'Affiché vingt', message: 'Affiché vingt et un', cancelText: 'Affiché vingt-deux' };
confirmWithConsequence('Affiché vingt-trois', 'xx');
z1.innerHTML = '<span class="mtl">' + (cond ? 'Noeud entre balises' : 'z') + '</span>';
z2.textContent = (cond ? 'Fragment colle a droite' : 'z') + ' suite du texte';
"""
# Un module qui porte le registre : sa définition est la seule surface exempte, ce qui l'entoure est jugé.
CORPUS_TEMOIN_REGISTRE = """export const HELP = {
  alpha: { fr: { title: 'Titre du registre <b>riche</b>', body: `Corps {fr}` }, en: { title: 'Registry title', body: `Body {en}` } },
};
x.textContent = 'Hors registre';
"""
# Témoin POSITIF de la règle des deux mots : une phrase tout en minuscules est comptée.
# « Affiché dix-sept » est le TÉMOIN DU LITTÉRAL D'EXPRESSION RÉGULIÈRE (`P11.8-e`) : il est posé APRÈS
# un `${… .replace(/"/g, '') …}` en fin de corpus. Un découpeur qui ne reconnaît pas la regex prend le `"`
# du motif pour l'ouverture d'une chaîne, avale le reste, et cette chaîne-là disparaît du décompte.
# « Affiché dix-huit » et « Affiché dix-neuf » sont les TÉMOINS DE LA CLÉ-PROPRIÉTÉ (`P11.8-c`) : la valeur
# rejoint le document sous une CLÉ (`{ textContent: … }`, `{ 'aria-label': … }`) et non par une affectation.
# La forme citée entre guillemets est là parce qu'un nom d'attribut à tiret ne peut PAS s'écrire nu.
# « Noeud entre balises » est le TÉMOIN DU NŒUD DE COMPOSITION (`P11.13-f`) : le texte n'est pas DANS un
# littéral HTML, il est COLLÉ entre deux littéraux HTML dont les bords sont des balises. Ce qui atteint
# l'écran est ce texte SEUL, donc il est affiché et doit être au lexique. « Fragment colle a droite » est
# son NÉGATIF : même forme, mais ce qui se colle est du TEXTE — le nœud vaut plus que le littéral, une clé
# pour lui serait morte. L'ancienne règle voyait le premier comme un fragment et le second comme affiché :
# elle lisait les parenthèses, pas l'écran.
# « Affiché vingt » à « Affiché vingt-trois » sont les TÉMOINS DES CLÉS DE FABRIQUE (`P11.8-c`,
# 2026-08-29) : la valeur ne rejoint le document ni par une affectation ni par une propriété du document,
# mais par la CONVENTION D'APPEL d'une fabrique de `core.js` — `emptyText:` que `muted()` pose en
# `textContent`, `message:` et `cancelText:` que `modal()` pose en nœuds texte, et le premier argument de
# `confirmWithConsequence(` qui devient le `title` de cette modale. Sans ces quatre témoins, retirer une clé
# de `CLES_APPLICATIVES` — ce qui est arrivé DEUX FOIS par simple divergence avec `core.js` — repasserait
# sans bruit, et le module retomberait au vert en n'affichant plus rien de traduit.
ATTENDUS_STATIQUES = {"aucun runbook", "nom et champ requis", "Affiché dix-sept",
                      "Affiché dix-huit", "Affiché dix-neuf", "Noeud entre balises",
                      "Affiché vingt", "Affiché vingt et un", "Affiché vingt-deux", "Affiché vingt-trois",
                      "Affiché un", "Affiché deux", "Affiché trois", "Affiché quatre", "Affiché cinq",
                      "Affiché six", "Affiché sept", "Affiché huit", "Affiché neuf", "Affiché dix",
                      "Affiché onze", "Affiché douze", "Affiché treize", "Affiché quatorze", "Affiché quinze",
                      "Affiché seize"}
# Les deux derniers sont des FRAGMENTS d'une valeur composée : le nœud rendu vaut le littéral PLUS ce qui
# s'y colle, donc jamais une clé. Ils sont dynamiques, pas des trous — une clé pour eux serait morte.
ATTENDUS_DYNAMIQUES = 5
# Témoin NÉGATIF de la même règle : un identifiant qui accroche ses mots par de la ponctuation reste dehors.
# « Sous une clé que le document ne connaît pas » est le TÉMOIN NÉGATIF de la clé-propriété : la règle est
# DÉRIVÉE des propriétés d'affichage, elle ne dit donc pas oui à n'importe quelle clé. Sans lui, remplacer la
# dérivation par « toute clé d'objet est un puits » passerait sans bruit et compterait des données.
# SA CLÉ D'EXEMPLE A CHANGÉ, ET C'EST UN DÉFAUT MESURÉ, PAS UN GOÛT (`P11.8-c`, 2026-08-29). Elle était
# `emptyText:` — or `web/core.js` rend TOUT `opts.emptyText` par `muted()`, donc en `textContent` : le
# témoin qui gardait la prudence de la règle AFFIRMAIT une chose fausse du code qu'il juge, et cette
# affirmation a tenu la clé la plus portante de `web/` hors du regard pendant qu'elle l'attestait
# indécidable. Le choix se porte sur `storeKey:`, dont `identiteDeLaListe()` fait une identité de rangement
# jamais rendue : un témoin négatif doit citer une clé dont on peut PROUVER qu'elle n'affiche rien.
INTERDITS = {"Sous une clé que le document ne connaît pas",
             "src_ip", "/api/v1/alerts", "count", "sort -count",
             "Fragment de ternaire", "Fragment HTML de bord :", "Fragment colle a droite",
             "Pas affiché", "pas-une-chaine affichée", "valeur_technique", "pas une chaîne", "T1110", "…", "x",
             "English only", "English rich", "pas_un_libellé(x)", "Ctrl", "Paire française", "English pair"}

# L'ANTI-CORPUS — LES FORMES QUE LA GARDE NE VOIT PAS, ET L'ASSERTION QU'ELLE NE LES VOIT PAS.
# Le corpus ci-dessus n'a que des « doit compter » et des « ne doit pas compter » : il ne peut donc jamais
# dire que le PÉRIMÈTRE a bougé. Celui-ci le dit. Chaque forme ci-dessous porte un libellé qui a toutes les
# apparences d'un affichage et qu'aucun critère de puits ne reconnaît ; le témoin exige qu'elle sorte en
# HORS-REGARD, ni comptée ni oubliée. Si la garde apprend un jour à lire l'une d'elles, ce témoin CASSE
# (code 2) et force la mise à jour de l'aveu — la colonne « hors-regard » et son cliquet — avant tout verdict.
# Parts mesurées le 2026-08-23 sur `web/`, 747 occurrences hors-regard classées par la forme du contexte :
# argument d'un appel (fabrique propre au module) 38,8 %, valeur sous une clé d'objet non reconnue 26,6 %,
# reste non classé 16,9 %, branche de ternaire 10,2 %, entrée de tableau 5,0 %, valeur de retour 2,5 %.
CORPUS_ANTI_REGARD = r"""
const cols = ['Entrée de tableau'];
function nom() { return 'Valeur de retour'; }
host.appendChild(opt('Argument de fabrique partagée'));
const t = cond ? 'Branche de ternaire vraie' : 'Branche de ternaire fausse';
const phrases = { page: 'Phrase sous une clé inconnue' };
toast((e && e.message) || 'Repli apres un ou logique');
el.setAttribute('d', 'Attribut non affiché');
el.className = 'classe css composee';
"""
ATTENDUS_HORS_REGARD = {"Entrée de tableau", "Valeur de retour", "Argument de fabrique partagée",
                        "Branche de ternaire vraie", "Branche de ternaire fausse",
                        "Phrase sous une clé inconnue", "Repli apres un ou logique"}
# Ceux-là ne sont ni comptés ni avoués : la garde SAIT qu'ils n'affichent rien. Un aveu qui les nommerait
# mélangerait l'INDÉCIDABLE et le DÉJÀ TRANCHÉ, et ferait rougir le cliquet sur une classe CSS neuve.
ATTENDUS_HORS_POPULATION = {"Attribut non affiché", "classe css composee"}

# LE TÉMOIN POSITIF DE L'AVEU DE PERTE DE SYNCHRONISATION — et, dans le même geste, la LIMITE AVOUÉE de la
# règle de désambiguïsation du `/`. Ici le `/` suit une parenthèse FERMANTE : la règle dit « division »,
# alors que JavaScript y admet une expression régulière. Le `"` du motif ouvre donc une fausse chaîne, qui
# se termine sur une fin de ligne — ce qu'un littéral JS ne fait jamais. Le lecteur DOIT le dire.
# Un détecteur qui ne se déclenche sur rien ne garde rien : ce corpus est ce qui prouve qu'il est vivant.
CORPUS_DESYNCHRONISATION = r"""
if (x) /"/.test(y);
"""

# LE TÉMOIN DE LA PARENTHÈSE (`P11.13-f`) — LE SEUL QUI TIENNE L'ATTENDU DE LA CLÉ. Deux corpus qui ne
# diffèrent QUE par un niveau de parenthèses : un ternaire simple, puis le même ternaire dont la branche
# fausse est elle-même un ternaire. AUCUN texte affiché ne change. Le classement doit donc être MOT POUR
# MOT le même. Sans ce témoin, un retour à une règle qui remonte à « la dernière parenthèse ouverte »
# repasserait sans bruit — et c'est exactement ce qui faisait basculer trois libellés d'un module réel.
# Le témoin est DOUBLE : l'égalité seule serait satisfaite par une garde devenue aveugle aux deux formes,
# donc la première forme doit AUSSI être vue affichée.
PAIRE_PARENTHESES = (
    """el.innerHTML = \'<span class="k">\' + (c ? \'Parenthese temoin\' : \'z\') + \'</span>\';\n""",
    """el.innerHTML = \'<span class="k">\' + (c ? \'Parenthese temoin\' : (d ? \'z\' : \'z\')) + \'</span>\';\n""",
)


# TÉMOIN DU NŒUD À CHEVAL (`P11.8-i`) — CINQ ATTENDUS SUR QUATRE CORPUS FABRIQUÉS ICI, JAMAIS SUR L'ÉTAT
# DU DÉPÔT. La raison est une faute mesurée le 2026-08-29 : une borne qui exigeait qu'un module PORTE ENCORE
# son défaut « sinon le motif ne mesure plus rien » aurait rougi LE JOUR OÙ LE TRAVAIL SERAIT FINI. Un témoin
# qui ne peut être vert que tant que le chantier est ouvert n'est pas une garde, c'est une rançon. Ceux-ci
# restent vrais quand `web/` est parfait, et ils tiennent les DEUX SENS de chaque question : le nœud coupé
# est vu ET le nœud bien coupé ne déclenche rien ; l'interpolation mal placée fait refuser ET la MÊME
# interpolation bien placée est lue sans aveu — sans ce dernier, un refus qui se déclencherait sur toute
# interpolation satisferait le témoin en ne mesurant plus rien.
CORPUS_NOEUD_A_CHEVAL = (
    """el.innerHTML = '<p>Ouverture <b>grasse</b>fin de ' + 'phrase coupee en deux</p>';\n""",
    """el.innerHTML = '<p>Ouverture <b>grasse</b>fin de phrase coupee en deux</p>' + '<i>suite</i>';\n""",
    """el.innerHTML = `<b ${cls}>fin de ` + `phrase coupee en deux</b>`;\n""",
    """el.innerHTML = `<b class="${cls}">fin de ` + `phrase coupee en deux</b>`;\n""",
)
NOEUD_TEMOIN = "fin de phrase coupee en deux"


def valider_instrument() -> list[str]:
    errs = []
    # `P11.8-i` — L'ÉNUMÉRATION DES NŒUDS SE VALIDE DANS LES DEUX SENS, SUR DES ENTRÉES FABRIQUÉES.
    coupe = noeuds_a_cheval(CORPUS_NOEUD_A_CHEVAL[0], set())
    entier = noeuds_a_cheval(CORPUS_NOEUD_A_CHEVAL[1], set())
    balise = noeuds_a_cheval(CORPUS_NOEUD_A_CHEVAL[2], set())
    attribut = noeuds_a_cheval(CORPUS_NOEUD_A_CHEVAL[3], set())
    couvert = noeuds_a_cheval(CORPUS_NOEUD_A_CHEVAL[0], {NOEUD_TEMOIN})
    if coupe != ([NOEUD_TEMOIN], []):
        errs.append(f"témoin de NŒUD À CHEVAL (positif) : un nœud coupé par une borne de littéral n'est pas vu "
                    f"entier ({coupe}) — la mesure de `P11.8-i` ne mesure plus rien, et les trois négatifs "
                    f"qui suivent seraient satisfaits par une sonde morte.")
    if entier != ([], []):
        errs.append(f"témoin de NŒUD À CHEVAL (négatif) : la MÊME phrase, dont la borne tombe sur une frontière "
                    f"de balise, est signalée ({entier}) — la mesure accuserait un code correct, et elle "
                    f"doublerait le compte des trous au lieu de le compléter.")
    if balise[0] != [] or len(balise[1]) != 1:
        errs.append(f"témoin de NON-ANALYSABLE : une interpolation posée DANS une balise doit faire REFUSER de "
                    f"conclure sur ce fragment, en le nommant, et ses nœuds ne doivent pas être jugés ({balise}).")
    if attribut != ([NOEUD_TEMOIN], []):
        errs.append(f"témoin de NON-ANALYSABLE (négatif) : la MÊME interpolation dans une valeur d'attribut "
                    f"entre guillemets doit être LUE sans aveu ({attribut}) — un refus qui se déclencherait sur "
                    f"toute interpolation rendrait l'aveu vrai en ne lisant plus rien.")
    if couvert != ([], []):
        errs.append(f"témoin de NŒUD À CHEVAL (couverture) : un nœud à cheval DÉJÀ au lexique est signalé "
                    f"({couvert}) — la mesure réclamerait une entrée qui existe.")
    # LE LECTEUR PARTAGÉ SE VALIDE ICI AUSSI (`P11.8-f`) : `registre_d_aide` s'appuie sur son
    # dépouillement, et il est IMPORTÉ — ses témoins ne tournent pas à l'import.
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur JavaScript partagé : {e}")
    # LA PARENTHÈSE NE CHANGE PAS LE VERDICT (`P11.13-f`) — témoin positif ET égalité, dans cet ordre :
    # une garde aveugle aux deux formes satisferait l'égalité toute seule.
    classes = [({x.strip() for x in r[0]}, {x.strip() for x in r[1]}, {t.strip() for t, _ in r[3]})
               for r in (extraire_module(PAIRE_PARENTHESES[0]), extraire_module(PAIRE_PARENTHESES[1]))]
    if "Parenthese temoin" not in classes[0][0]:
        errs.append(f"témoin de PARENTHÈSE (positif) : un texte collé entre deux balises n'est pas vu affiché "
                    f"({sorted(classes[0][0])}) — l'égalité qui suit ne prouverait plus rien.")
    elif classes[0] != classes[1]:
        errs.append(f"témoin de PARENTHÈSE : le classement dépend du NIVEAU DE PARENTHÈSES — ternaire simple "
                    f"{classes[0]}, ternaire imbriqué {classes[1]}. Aucun texte affiché ne diffère entre les deux "
                    f"corpus : la garde lit la mise en forme du code, pas ce qui atteint l'écran, et son cliquet "
                    f"devient un piège pour qui remanie.")
    st, dy, pc, _hr = extraire_module(CORPUS_TEMOIN)
    sst = {s.strip() for s in st}
    if {x.strip() for x in pc} != {"Bilingual", "Bilingue", "English only", "English rich", "Paire française <nom>", "English pair <name>"}:
        errs.append(f"témoin : le choix par LANG (ternaire ou bloc `if (LANG === 'en')`) ou la paire `{{fr, en}}` n'est pas "
                    f"reconnu comme bilingue par construction : {pc}")
    # La surface exempte est la définition du registre, pas le module : hors d'elle, une chaîne est jugée ;
    # et c'est bien l'exemption qui retire le titre du registre, pas une cécité de l'extracteur.
    vus_nus = {x.strip() for x in extraire_module(CORPUS_TEMOIN_REGISTRE)[0]}
    vus_hors = {x.strip() for x in extraire_module(hors_registre(CORPUS_TEMOIN_REGISTRE))[0]}
    if "Registry title" not in vus_nus:
        errs.append(f"témoin : le titre d'une section du registre n'est pas vu par l'extracteur à nu ({sorted(vus_nus)}) — "
                    f"l'exemption de surface ne prouverait rien")
    if vus_hors != {"Hors registre"}:
        errs.append(f"témoin : hors de la portée du registre, la garde doit voir « Hors registre » et rien du registre : {sorted(vus_hors)}")
    manquants = ATTENDUS_STATIQUES - sst
    if manquants:
        errs.append(f"témoin : chaînes affichées NON reconnues : {sorted(manquants)}")
    trop = sst & INTERDITS
    if trop:
        errs.append(f"témoin : chaînes comptées alors qu'elles ne sont pas affichées : {sorted(trop)}")
    if len(dy) != ATTENDUS_DYNAMIQUES:
        errs.append(f"témoin : {len(dy)} chaîne(s) dynamique(s) vue(s) au lieu de {ATTENDUS_DYNAMIQUES}")
    # ANTI-CORPUS : le périmètre n'a pas bougé sans que l'aveu bouge avec lui.
    st_a, dy_a, pc_a, hr_a = extraire_module(CORPUS_ANTI_REGARD)
    vus_a = {x.strip() for x in st_a} | {x.strip() for x in dy_a} | {x.strip() for x in pc_a}
    hors_a = {t.strip() for t, _ in hr_a}
    formes_a = {t.strip(): f for t, f in hr_a}
    appris = sorted(ATTENDUS_HORS_REGARD & vus_a)
    if appris:
        errs.append(f"anti-corpus : la garde COMPTE désormais une forme qu'elle déclarait ne pas regarder : {appris}. "
                    f"C'est un élargissement du périmètre : retirez ces formes de `ATTENDUS_HORS_REGARD`, refaites la "
                    f"mesure et abaissez `PLAFOND_HORS_REGARD` avant de conclure.")
    perdus = sorted(ATTENDUS_HORS_REGARD - hors_a - vus_a)
    if perdus:
        errs.append(f"anti-corpus : {perdus} n'est ni compté ni rendu hors-regard — l'aveu ne couvre plus ces formes.")
    su = sorted(ATTENDUS_HORS_POPULATION & (vus_a | hors_a))
    if su:
        errs.append(f"anti-corpus : {su} est compté ou avoué alors que son emplacement n'affiche jamais de texte "
                    f"(classe CSS, attribut non affiché) : l'aveu doit nommer ce dont la garde ne peut PAS décider, "
                    f"pas ce qu'elle sait déjà hors sujet.")
    # LA RÉPARTITION PUBLIÉE EST UN INSTRUMENT, ELLE SE VALIDE AUSSI. Sans ce témoin, la dérivation des
    # formes pourrait tomber sur « forme non classée » pour tout, et l'aveu resterait vert en ne disant
    # plus rien. Chaque forme de l'anti-corpus porte donc le NOM qu'elle doit recevoir.
    formes_attendues = {
        "Entrée de tableau": "entrée de tableau ou argument suivant",
        "Valeur de retour": "valeur de retour",
        "Argument de fabrique partagée": "argument d'un appel",
        "Branche de ternaire vraie": "branche de ternaire",
        "Branche de ternaire fausse": "branche de ternaire",
        "Phrase sous une clé inconnue": "valeur sous la clé d'objet « page »",
        # LE SIXIÈME POSTE PUBLIÉ A LUI AUSSI SON NOM GARDÉ. « forme non classée » est le repli du classeur :
        # il pesait 114 occurrences sur 716 (15,9 %) le 2026-08-26, quatrième poste de l'aveu, et l'anti-corpus
        # ne l'exerçait pas — un aveu peut donc glisser vers ce repli sans que rien ne casse, et ne plus rien
        # désigner tout en restant vert. Le repli d'un `||` (`toast((e && e.message) || '…')`) en est la forme
        # la plus courante sur `web/` : le littéral est bien un candidat à l'affichage, mais rien avant lui ne
        # nomme un puits. CE QUE CE TÉMOIN NE TIENT PAS : il garde le NOM du poste, pas sa COMPOSITION — le
        # poste mêle ce repli à des opérandes de comparaison (`if (e.key === 'Escape')`) qui, eux, n'affichent
        # jamais rien et sont du BRUIT dans l'aveu, comme l'étaient les classes CSS avant leur retrait.
        "Repli apres un ou logique": "forme non classée",
    }
    ecarts = {t: (formes_a.get(t), f) for t, f in formes_attendues.items() if formes_a.get(t) != f}
    if ecarts:
        errs.append(f"anti-corpus : la FORME publiée pour un hors-regard n'est plus celle attendue {ecarts} — "
                    f"la répartition rendue à chaque exécution ne nomme plus ce que la garde ne regarde pas, "
                    f"et un aveu qui ne dit plus QUOI est un aveu mort.")
    en_trop = sorted(hors_a - ATTENDUS_HORS_REGARD)
    if en_trop:
        errs.append(f"anti-corpus : hors-regard inattendu {en_trop} — l'anti-corpus doit nommer EXACTEMENT ce que la "
                    f"garde ne regarde pas.")
    # L'AVEU DE PERTE DE SYNCHRONISATION : vivant sur la forme qu'il doit attraper, muet sur les corpus sains.
    j_sain: list[tuple[str, int]] = []
    chaines_js(CORPUS_TEMOIN, j_sain)
    chaines_js(CORPUS_ANTI_REGARD, j_sain)
    chaines_js(CORPUS_TEMOIN_REGISTRE, j_sain)
    if j_sain:
        errs.append(f"témoin : le découpeur s'avoue désynchronisé sur un corpus SAIN ({j_sain}) — l'aveu crie "
                    f"au loup et fera refuser de conclure sur du code correct.")
    j_perdu: list[tuple[str, int]] = []
    chaines_js(CORPUS_DESYNCHRONISATION, j_perdu)
    if len(j_perdu) != 1:
        errs.append(f"témoin : {len(j_perdu)} aveu(x) de désynchronisation au lieu de 1 sur `if (x) /\"/.test(y);` — "
                    f"le détecteur de perte de synchronisation est mort, ou la règle du `/` a changé sans son témoin. "
                    f"Un lecteur qui ne sait plus dire qu'il a sauté une région rend un compte faux EN SILENCE.")
    lex = cles_du_lexique('const I18N_EN = {\n  "Clé un": "Key one", "Clé deux": "Key two",\n  // c\n  "Clé trois": "Key three",\n  "Clé\\u00a0quatre": "Key four",\n};')
    if lex != {"Clé un", "Clé deux", "Clé trois", "Clé\xa0quatre"}:
        errs.append(f"témoin : lecture du lexique fausse : {sorted(lex)}")
    return errs


# ---------------------------------------------------------------------------------------------
# Mesure sur l'arbre réel.
# ---------------------------------------------------------------------------------------------
def mesurer(registre: tuple[str, str] | None) -> tuple[dict[str, dict], set[str], dict[str, list[str]]]:
    """`registre` = (module, texte sans commentaires) : ce module est jugé HORS de la portée de `const HELP`.
    Le 3e retour = LES AVEUX DE PERTE DE SYNCHRONISATION du découpeur, `module -> [« motif, ligne N »]`."""
    with open(LEXIQUE, encoding="utf-8") as fh:
        cles = cles_du_lexique(fh.read())
    resultats: dict[str, dict] = {}
    desynchronisations: dict[str, list[str]] = {}
    for f in sorted(os.listdir(WEB)):
        chemin = os.path.join(WEB, f)
        if f == "sw.js" or not (f.endswith(".js") or f == "index.html"):
            continue
        with open(chemin, encoding="utf-8") as fh:
            src = fh.read()
        journal: list[tuple[str, int]] = []
        lu = src
        a_cheval: list[str] = []
        illisibles: list[str] = []
        if f == "index.html":
            # `web/index.html` est analysé D'UN SEUL TENANT : ses nœuds sont déjà des nœuds rendus,
            # aucun ne peut être à cheval sur une borne de littéral.
            st, dy, pc, hr = extraire_index_html(src), [], [], []
        elif f == "i18n.js":
            # le lexique n'affiche rien, mais il doit être LU sans perte : `cles_du_lexique` s'appuie sur le
            # même découpeur, et une région avalée y ferait disparaître des clés — donc des trous fantômes.
            chaines_js(src, journal)
            st, dy, pc, hr = [], [], [], []
        elif registre and f == registre[0]:
            lu = hors_registre(registre[1])  # la surface du registre est exempte, le reste jugé
            st, dy, pc, hr = extraire_module(lu, journal)
        else:
            st, dy, pc, hr = extraire_module(src, journal)
        if f not in ("index.html", "i18n.js"):
            a_cheval, illisibles = noeuds_a_cheval(lu, cles)
        if journal:
            desynchronisations[f] = [f"ligne {lu.count(chr(10), 0, o) + 1} : {motif}" for motif, o in journal]
        if f == "i18n.js":
            continue
        uniques = sorted({s.strip() for s in st})
        bilingues = {s.strip() for s in pc}
        couvertes = [s for s in uniques if s in cles] + sorted(bilingues)
        trous = [s for s in uniques if s not in cles]
        total = len(uniques) + len(bilingues)
        aveugles = sorted({t.strip() for t, _ in hr})
        formes = collections.Counter(f for _, f in hr)
        resultats[f] = {
            "population": total,
            "couvertes": len(couvertes),
            "couvertes_liste": couvertes,
            "trous": trous,
            "dynamiques": len({s for s in dy}),
            "hors_regard": aveugles,
            "formes": formes,
            # LA CONFESSION, ÉCRITE PAR LE DÉPÔT : parmi ce que la garde ne regarde pas, ce que le lexique
            # porte DÉJÀ. Aucun humain ne l'écrit — c'est le dépôt qui prouve que le périmètre du critère de
            # puits est plus étroit que l'affichage réel.
            "hors_regard_au_lexique": [s for s in aveugles if s in cles],
            # `P11.8-i` — LE NŒUD RENDU, PAS LE LITTÉRAL ÉCRIT. Ces deux colonnes ne recoupent AUCUNE des
            # précédentes : la première ne compte que les nœuds qu'aucun littéral pris seul ne rend, la
            # seconde ne compte que les fragments sur lesquels l'analyseur refuse de conclure.
            "a_cheval": sorted(set(a_cheval)),
            "illisibles": illisibles,
            "taux": (100.0 * len(couvertes) / total) if total else 100.0,
        }
    return resultats, cles, desynchronisations


def main(argv: list[str]) -> int:
    mesure = "--mesure" in argv
    liste_exces = "--exces" in argv
    trous_de = None
    if "--trous" in argv:
        trous_de = argv[argv.index("--trous") + 1]
    hors_de = None
    if "--hors-regard" in argv:
        hors_de = argv[argv.index("--hors-regard") + 1]
    liste_noeuds = "--noeuds" in argv

    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nL'instrument ne reconnaît pas son propre corpus : la garde refuse de conclure.")
        return 2

    aveux_du_registre: dict[str, list[str]] = {}
    registre = registre_d_aide(aveux_du_registre)
    if aveux_du_registre and refuser_sur_aveu("lexique", aveux_du_registre):
        return 2
    if registre is None:
        print("::error::le module du registre d'aide (`const HELP = {` sous web/) n'est pas dérivable — aucun ou plusieurs porteurs : "
              "la garde refuse de conclure (il serait rendu sans être jugé, ou jugé sans sa raison d'exemption).")
        return 2
    # Le module du registre est jugé au plafond zéro hors de la portée exempte (entrée dérivée, pas nommée).
    plafonds = {**PLAFOND_DE_TROUS, registre[0]: 0}
    plafonds_hr = {**PLAFOND_HORS_REGARD, registre[0]: 0}
    resultats, cles, desynchronisations = mesurer(registre)
    if desynchronisations:
        for m, aveux in sorted(desynchronisations.items()):
            for a in aveux:
                print(f"::error::{m}:{a} — le découpeur a PERDU LA SYNCHRONISATION : il a ouvert un littéral "
                      f"qui n'en est pas un, et tout ce qu'il a lu depuis est faux. Cause la plus fréquente : "
                      f"un `/` que la règle de désambiguïsation (jeton précédent, cf. `RE_AVANT_REGEX`) a pris "
                      f"pour une division alors qu'il ouvrait une expression régulière — après `)` ou `]`, "
                      f"typiquement `if (x) /re/.test(y)`. Écrivez `if (x) {{ return /re/.test(y); }}` ou "
                      f"`new RegExp(...)`, ou apprenez la forme à `RE_AVANT_REGEX`.")
        print("\nLe découpeur avoue avoir sauté une région : la garde refuse de conclure. Un compte amputé "
              "rendu en silence est pire qu'une garde absente — c'est ce qu'un `\"` dans une expression "
              "régulière a fait pendant un jour sur `web/viz.js` (118 littéraux perdus, `P11.8-e`).")
        return 2
    population = sum(r["population"] for r in resultats.values())
    if len(cles) < MIN_CLES:
        print(f"::error::{len(cles)} clés lues dans le lexique, plancher {MIN_CLES} : la lecture de `web/i18n.js` est cassée.")
        return 2
    if population < MIN_POPULATION:
        print(f"::error::{population} chaînes affichées découvertes, plancher {MIN_POPULATION} : l'extraction ne reconnaît plus l'arbre.")
        return 2
    index = resultats.get("index.html")
    if not index or CLE_TEMOIN not in cles or CLE_TEMOIN not in index["couvertes_liste"]:
        print(f"::error::la clé témoin « {CLE_TEMOIN} » n'est pas vue à la fois au lexique et dans `web/index.html` : "
              f"la garde refuse de conclure.")
        return 2

    if trous_de:
        r = resultats.get(trous_de)
        if not r:
            print(f"module inconnu : {trous_de}")
            return 2
        for s in r["trous"]:
            print(s)
        return 0

    if hors_de:
        r = resultats.get(hors_de)
        if not r:
            print(f"module inconnu : {hors_de}")
            return 2
        for s in r["hors_regard"]:
            print(f"{'AU LEXIQUE' if s in cles else '          '}  {s}")
        return 0

    if liste_noeuds:
        for m, r in resultats.items():
            for t in r["a_cheval"]:
                print(f"À CHEVAL SANS CLÉ  {m}  {t}")
            for x in r["illisibles"]:
                print(f"NON ANALYSABLE     {m}  {x}")
        return 0

    # L'EXCÈS : la moitié que cette garde ne mesurait pas. Calculé ICI, après les sorties courtes
    # (`--trous`, `--hors-regard`), parce qu'il lit tout le dépôt et qu'aucune de ces deux-là n'en a besoin.
    corpus, litteraux = corpus_du_depot()
    vivantes = {c for r in resultats.values() for c in r["couvertes_liste"] if c in cles}
    hors_regard_global = {h for r in resultats.values() for h in r["hors_regard"]}
    errs_exces = valider_sonde_d_exces(vivantes, corpus, litteraux, hors_regard_global)
    if errs_exces:
        for e in errs_exces:
            print(f"::error::{e}")
        print("\nLa sonde d'excès ne se reconnaît pas elle-même : la garde refuse de conclure. Une sonde "
              "d'orphelines qui a perdu son corpus n'est pas silencieuse, elle est CALOMNIEUSE — elle accuse "
              "tout ce qu'elle ne retrouve plus.")
        return 2
    exces = excedent_du_lexique(cles, vivantes, corpus, litteraux)
    orphelines = exces["orpheline"]
    indecidables = exces["indecidable"]
    if liste_exces:
        for c, motif in orphelines:
            print(f"ORPHELINE PROUVÉE  {c}\n                   ({motif})")
        for c, motif in indecidables:
            print(f"INDÉCIDABLE        {c}\n                   ({motif})")
        return 0

    largeur = max(len(m) for m in resultats)
    print(f"{'module':<{largeur}}  population  couvertes  trous  dynamiques  hors-regard  dont au lexique   taux")
    for m, r in resultats.items():
        print(f"{m:<{largeur}}  {r['population']:>10}  {r['couvertes']:>9}  {len(r['trous']):>5}  {r['dynamiques']:>10}  "
              f"{len(r['hors_regard']):>11}  {len(r['hors_regard_au_lexique']):>15}  {r['taux']:>5.1f} %")
    couvertes = sum(r["couvertes"] for r in resultats.values())
    aveugles = sum(len(r["hors_regard"]) for r in resultats.values())
    aveugles_au_lexique = sum(len(r["hors_regard_au_lexique"]) for r in resultats.values())
    print(f"\n{population} chaînes statiques affichées REGARDÉES, {couvertes} couvertes ({100.0 * couvertes / population:.1f} %), "
          f"{len(cles)} clés au lexique. Surface exempte : la définition `const HELP` de {registre[0]} — {RAISON_DU_REGISTRE}.")
    print(f"HORS-REGARD : {aveugles} littéraux qui ont la forme d'un libellé et que le critère de puits ne reconnaît PAS — "
          f"la garde ne les juge pas, elle les publie. {aveugles_au_lexique} d'entre eux "
          f"({100.0 * aveugles_au_lexique / aveugles if aveugles else 0.0:.1f} %) sont DÉJÀ des clés du lexique : c'est le "
          f"dépôt lui-même qui atteste qu'ils sont affichés, et donc que le périmètre regardé est plus étroit que "
          f"l'affichage. `--hors-regard MODULE` les liste.")
    # LA RÉPARTITION EST RECALCULÉE, PAS RECOPIÉE (`P11.8-c`). Un aveu qui dit COMBIEN sans dire QUOI ne
    # désigne pas la prochaine forme à apprendre ; et une répartition figée dans un commentaire est datée
    # d'un jour. Les postes sortent du contexte de chaque littéral, à chaque exécution.
    formes = collections.Counter()
    for r in resultats.values():
        formes.update(r["formes"])
    postes = collections.Counter()
    cles_d_objet = collections.Counter()
    for forme, n in formes.items():
        tete = forme.split(" « ")[0]
        postes[tete] += n
        if len(forme.split(" « ")) > 1:
            cles_d_objet[forme.split(" « ")[1].rstrip(" »")] += n
    # LE DÉNOMINATEUR EST CELUI DES OCCURRENCES, PAS DES TEXTES DISTINCTS. La colonne hors-regard compte des
    # textes DÉDUPLIQUÉS par module (c'est ce que garde le cliquet) ; une même phrase posée deux fois y
    # compte une fois et ici deux. Rapporter les postes au compte dédupliqué ferait des parts qui dépassent
    # 100 % — un instrument qui rend un pourcentage impossible n'est pas cru, à raison.
    occurrences = sum(postes.values())
    print(f"PAR FORME, sur {occurrences} OCCURRENCES (dérivée du contexte à chaque exécution — c'est elle qui "
          f"nomme la prochaine à apprendre ; le compte gardé, lui, est celui des {aveugles} textes distincts) :")
    for forme, n in postes.most_common():
        print(f"    {n:>4}  {100.0 * n / occurrences if occurrences else 0.0:>5.1f} %  {forme}")
    if cles_d_objet:
        tete = ", ".join(f"{k} {v}" for k, v in cles_d_objet.most_common(8))
        print(f"    clés d'objet les plus portantes ({len(cles_d_objet)} distinctes) : {tete}. Une clé qui NOMME "
              f"une propriété d'affichage du document est déjà lue ; celles-ci n'en nomment aucune — il "
              f"faudrait suivre le flux jusqu'à l'écriture pour trancher, et ce n'est pas fait.")
    # LE JEU DU CLIQUET EST PUBLIÉ, PAS ÉCRIT À CÔTÉ DU CHIFFRE. Un plafond qui reste AU-DESSUS de son relevé
    # n'est pas une régression — c'est la place que des libellés neufs peuvent prendre sans faire rougir
    # personne, et c'est donc ce que la garde laisse passer aujourd'hui. Écrit à la main dans un commentaire,
    # ce jeu est daté d'un jour et faux le lendemain : `dashboards.js` a porté 25 pour 22 mesurés pendant que
    # le commentaire d'à côté reprochait à un autre module d'être « en RETARD de deux crans sur son propre
    # relevé ». Il est donc DÉRIVÉ de la mesure du jour, à chaque exécution, et nommé module par module.
    jeu = sorted(((m, plafonds_hr[m] - len(r["hors_regard"])) for m, r in resultats.items()
                  if m in plafonds_hr and plafonds_hr[m] > len(r["hors_regard"])),
                 key=lambda x: (-x[1], x[0]))
    jeu_trous = sorted(((m, plafonds[m] - len(r["trous"])) for m, r in resultats.items()
                        if m in plafonds and plafonds[m] > len(r["trous"])),
                       key=lambda x: (-x[1], x[0]))
    if jeu or jeu_trous:
        detail = ", ".join(f"{m} +{n}" for m, n in jeu) or "aucun"
        print(f"JEU DU CLIQUET : {len(jeu)} plafond(s) de hors-regard au-dessus de leur relevé du jour "
              f"(total {sum(n for _, n in jeu)} cran(s)) — {detail} ; et {len(jeu_trous)} plafond(s) de trous "
              f"(total {sum(n for _, n in jeu_trous)}). Un cliquet REFUSE une hausse ; il ne force pas une "
              f"descente. Ce jeu est ce que la garde laisse passer sans rougir : le faire descendre au relevé "
              f"est le seul mouvement qui ne se discute pas.")
    else:
        print("JEU DU CLIQUET : aucun plafond au-dessus de son relevé du jour — chaque cliquet est au ras de sa "
              "mesure. La phrase qui suivait ici (« le moindre libellé neuf posé dans une forme non lue rougit ») "
              "est RÉFUTÉE et retirée : voir la ligne suivante, un cliquet au ras ne dit pas cela.")
    # LA MARGE DES PLANCHERS EST PUBLIÉE POUR LA MÊME RAISON QUE LE JEU DES PLAFONDS (`P8.27-g`, 2026-08-30).
    # Trois planchers de ce fichier sont dérivés d'un relevé « moins un vingtième », et ils affirment donc une
    # PROPRIÉTÉ : perdre plus de 5 % du corpus, de la population regardée ou des clés vivantes fait REFUSER de
    # conclure. L'arbre grossit, le plancher ne bouge pas, et cette propriété devient fausse EN SILENCE. Le
    # fichier nomme déjà ce défaut à côté de `MIN_CORPUS` (« un cliquet qui se desserre tout seul ») sans que
    # rien ne le MESURE — c'est exactement ce qui est arrivé au jeu des plafonds quand il était écrit à la main.
    # La perte que chaque plancher tolère AUJOURD'HUI est donc dérivée à chaque exécution, comme le jeu.
    # ELLE NE FAIT PAS ROUGIR, ET C'EST DÉLIBÉRÉ : un plancher qui rougirait parce que l'arbre a grossi serait
    # une rançon payable le jour où le travail avance, pas une garde. Elle se LIT, et un plancher qu'on a
    # oublié de resserrer s'y voit — c'est le seul service qu'un aveu dérivé rend et qu'un commentaire ne rend
    # pas. Le relever reste un GESTE, à faire sur un arbre dont on sait de quels lots il est fait.
    planchers = (("corpus (octets)", MIN_CORPUS, len(corpus)),
                 ("population regardée", MIN_POPULATION, population),
                 ("clés vivantes", MIN_CLES_VIVANTES, len(vivantes)))
    # LE SEUIL EST LE PLANCHER QUE LA RECETTE DU FICHIER DONNERAIT AUJOURD'HUI, PAS UN POURCENTAGE COMPARÉ À
    # 5,00. Écrit en pourcentage, ce témoin CRIAIT AU LOUP sur un plancher posé exactement selon la recette :
    # `1588 * 19 // 20` vaut 1508, et 1588 - 1508 fait 5,04 % — au-dessus de 5,00 par la seule troncature.
    # Mesuré en jouant le témoin sur une copie dont les trois planchers étaient posés au dérivé du jour :
    # deux redevenaient muets, le troisième restait accusé. Le seuil est donc le DÉRIVÉ lui-même, en entier
    # exact, et l'écart est publié en UNITÉS, pas en points de pourcentage.
    # 2026-08-31 (`P11.8-k`) : ce témoin RECOPIAIT la recette au lieu de l'appeler. Il ne pouvait donc pas
    # accuser le défaut qui comptait — deux écritures d'une même règle dérivent l'une de l'autre sans bruit —
    # et il aurait pu à l'inverse innocenter un plancher faux si la copie s'était trompée pareil. Il appelle
    # désormais `plancher_depuis_releve`, la MÊME fonction qui pose les trois planchers : la valeur gardée et
    # la valeur publiée sortent du même calcul, et ne peuvent plus diverger.
    print("MARGE DES PLANCHERS — ce que chacun tolère aujourd'hui, contre le plancher que la recette de ce "
          "fichier (relevé du jour moins un vingtième) donnerait maintenant :")
    for nom, plancher, releve in planchers:
        derive = plancher_depuis_releve(releve)
        perte = 100.0 * (releve - plancher) / releve if releve else 0.0
        retard = f" — EN RETARD de {derive - plancher} sur son relevé" if plancher < derive else ""
        print(f"    {nom} : plancher {plancher}, relevé du jour {releve}, dérivé du jour {derive} — "
              f"{perte:.2f} % de perte tolérée{retard}")
    # CE QUE LE CLIQUET NE VOIT PAS, MÊME AU RAS (`P8.27-g`). La colonne gardée est un COMPTE NET, pas un
    # ENSEMBLE : elle refuse une HAUSSE. Descendre un plafond au relevé — le remède que la clé proposait —
    # ferme la hausse nette et RIEN D'AUTRE. Le publier est le minimum qu'une garde doive à qui la lit :
    # elle rend vert sur un chemin qu'elle ne regarde pas, et le taire serait pire que ne pas garder.
    au_ras = sorted(m for m, r in resultats.items()
                    if m in plafonds_hr and plafonds_hr[m] == len(r["hors_regard"]))
    print(f"CE QUE LE CLIQUET NE VOIT PAS, MÊME AU RAS : il garde un COMPTE NET, pas un ENSEMBLE de textes. "
          f"Sur les {len(au_ras)} module(s) dont le plafond de hors-regard est EXACTEMENT à son relevé, un "
          f"libellé neuf posé dans une forme non lue passe VERT dès qu'il en REMPLACE un autre — le compte ne "
          f"bouge pas. Mesuré par MUTATION le 2026-08-29 sur `web/cases.js`, plafond au ras de son relevé et aucun "
          f"jeu (70/70 avec l'instrument d'alors, refait 68/68 avec celui-ci) : substituer un hors-regard par "
          f"un libellé français jamais écrit et absent du lexique rend le code 0 et zéro erreur ; le MÊME "
          f"libellé ajouté sans retrait rend le code 1. Abaisser les plafonds ne ferme "
          f"donc pas ce chemin-là ; seule une garde portant sur l'ENSEMBLE des textes le fermerait, et elle "
          f"rougirait sur toute réécriture de libellé. C'est DIT, ce n'est pas corrigé (`P8.27-g`).")
    # L'EXCÈS, PUBLIÉ AVEC SES TROIS VERDICTS (`P11.8-g`). Le compte des INDÉCIDABLES est l'aveu : il dit
    # combien de clés la sonde ne sait pas trancher, et il vaut mieux qu'un vert qui tairait la question.
    ailleurs = sum(1 for _, m in indecidables if m.startswith("texte présent"))
    print(f"EXCÈS DU LEXIQUE : sur {len(cles)} clés, {len(vivantes)} sont VIVANTES (vues comme chaîne affichée "
          f"dans un puits reconnu), {len(indecidables)} sont INDÉCIDABLES — {ailleurs} dont le texte est ailleurs "
          f"dans le dépôt hors d'un puits reconnu, {len(indecidables) - ailleurs} qu'un littéral de bord pourrait "
          f"composer — et {len(orphelines)} sont des ORPHELINES PROUVÉES (texte absent du dépôt ENTIER, et aucun "
          f"littéral n'en formerait le bord). Corpus dérivé : {len(corpus)} octets, {len(litteraux)} littéraux de "
          f"l'arbre servi ; `*.md` et tout {'/'.join(NOMS_HORS_CORPUS)} — répertoire OU fichier, le pointeur "
          f"`.git` d'un arbre de travail lié en est un — exclus (rien de cela n'atteint un "
          f"navigateur, et lire `.github` ferait ressusciter toute clé que ce fichier NOMME). `--exces` les liste.")
    for c, _ in orphelines:
        print(f"    ORPHELINE PROUVÉE  {c}")
    print(f"CE QUE LA MESURE DE L'EXCÈS NE TIENT PAS : (1) un COMMENTAIRE qui cite encore la phrase EMPÊCHE "
          f"l'accusation — 8 clés de plus seraient prouvées sans lui (écart mesuré le 2026-08-29) ; c'est le prix "
          f"assumé pour ne jamais accuser à tort. (2) Une clé dont le texte ne naîtrait qu'à l'exécution, "
          f"d'une donnée absente du dépôt, serait accusée — la borne est que le source du démon EST dans le "
          f"corpus. (3) Le cliquet des indécidables est un COMPTE NET, pas un ENSEMBLE : une indécidable qui "
          f"en remplace une autre passe sans que rien ne bouge, exactement comme pour le hors-regard "
          f"(`P8.27-g`). (4) Elle ne juge PAS la VALEUR anglaise d'une clé vivante — qu'elle soit juste, ou "
          f"seulement différente du français, c'est le témoin 13 du harnais ESM qui le tient, pas ceci. "
          f"(5) LA PLUS COÛTEUSE, TROUVÉE EN PAYANT `P11.8-g` le 2026-08-29 : une clé qui n'est qu'un MORCEAU "
          f"d'un nœud rendu est MORTE — `i18nWalk` n'égale que le nœud ENTIER après `trim()` — et cette sonde "
          f"ne sait pas la voir, puisque son texte EST dans le dépôt : elle la range en INDÉCIDABLE, pour "
          f"toujours. C'EST LA LIGNE SUIVANTE QUI TIENT CE POINT DEPUIS `P11.8-i` : elle ne mesure plus des "
          f"littéraux, elle énumère des NŒUDS. Ce que cette sonde-ci ne tient toujours pas, c'est le SENS "
          f"INVERSE — une clé morte parce qu'elle n'est qu'un morceau de nœud reste rangée en INDÉCIDABLE "
          f"ici ; c'est le compte des nœuds À CHEVAL qui la désigne, en nommant le nœud entier qu'elle "
          f"aurait dû être.")
    # `P11.8-i` — LE NŒUD RENDU, PAS LE LITTÉRAL ÉCRIT. Publié comme tout le reste : le compte, le nom de
    # chaque nœud manquant, et surtout le compte de ce que l'analyseur REFUSE DE LIRE. Un analyseur qui se
    # tromperait en silence serait pire que l'angle mort qu'il comble ; celui-ci dit où il s'arrête.
    a_cheval = sorted({t for r in resultats.values() for t in r["a_cheval"]})
    illisibles = [(m, x) for m, r in resultats.items() for x in r["illisibles"]]
    print(f"LE NŒUD RENDU, PAS LE LITTÉRAL ÉCRIT (`P11.8-i`) : `i18nWalk` ne remplace qu'un nœud texte "
          f"ENTIER, blancs retirés ; un nœud qui TRAVERSE une borne de littéral (`'…ATT&CK. ' + 'Déposez "
          f"un <b>…'`) n'est donc vu entier par aucune des mesures ci-dessus — elles le lisent en deux "
          f"moitiés et les rangent en « dynamique ». Les chaînes `litt + litt` porteuses de balisage sont "
          f"donc JOINTES puis analysées, et leurs nœuds énumérés : {len(a_cheval)} nœud(s) à cheval sans "
          f"clé au lexique (plafond {PLAFOND_NOEUDS_A_CHEVAL}), et {len(illisibles)} fragment(s) que "
          f"l'analyseur REFUSE de lire (plafond {PLAFOND_FRAGMENTS_ILLISIBLES}). `--noeuds` les nomme.")
    for t in a_cheval:
        print(f"    À CHEVAL SANS CLÉ  {t}")
    for m, x in illisibles:
        print(f"    NON ANALYSABLE     {m} : {x}")
    print(f"CE QUE `P11.8-i` NE TIENT PAS : (1) la jointure s'arrête à toute PARENTHÈSE et à tout TERNAIRE — "
          f"`'… muet(s)' + (c ? ' · <b>…</b> attendu(s)' : '')` rend DEUX nœuds possibles et en choisir un "
          f"serait inventer, donc `web/fleet.js` garde là un nœud que rien ne juge. (2) Elle ne joint que "
          f"des LITTÉRAUX : un fragment assemblé par une variable intermédiaire lui échappe entièrement. "
          f"(3) Un nœud à cheval dont le texte existe PAR AILLEURS comme nœud d'un littéral seul n'est pas "
          f"reconnu comme à cheval (la reconnaissance est une différence d'ensembles, pas un calcul "
          f"d'offsets). Les trois biais vont dans le sens du SOUS-compte, comme partout ailleurs ici.")
    if mesure:
        return 0

    # UN MODULE MESURÉ SANS PLAFOND N'EST PAS JUGÉ. Il paraissait au tableau et le verdict le comptait vert
    # sans qu'aucun cliquet ne le tienne ; la garde refuse désormais de conclure. `--mesure` reste utilisable
    # pour relever le compte à inscrire.
    sans_plafond = sorted(m for m in resultats if m not in plafonds or m not in plafonds_hr)
    if sans_plafond:
        print(f"::error::module(s) mesuré(s) mais hors du cliquet : {', '.join(sans_plafond)} — inscrivez chacun dans "
              f"`PLAFOND_DE_TROUS` ET dans `PLAFOND_HORS_REGARD` à son compte relevé par `--mesure`. La garde refuse "
              f"de conclure : un module rendu sans être jugé fait rendre vert sur ce que personne ne garde.")
        return 2

    # UNE CLÉ QUE LA SONDE NE SAIT PAS TRANCHER N'EST PAS UNE FAUTE : c'est un aveu, et son canal est le REFUS
    # DE CONCLURE, pas la régression. Confondre les deux ferait rougir qui écrit un libellé légitime dans une
    # forme que le critère de puits ne lit pas — le contraire de ce que cette garde cherche à obtenir.
    if len(indecidables) > PLAFOND_INDECIDABLES:
        exemples = " · ".join(c for c, _ in indecidables[:6])
        print(f"::error::{len(indecidables)} clés INDÉCIDABLES au lexique, plafond {PLAFOND_INDECIDABLES} — la sonde "
              f"ne sait dire ni qu'elles sont servies, ni qu'elles sont mortes. P. ex. : {exemples}. "
              f"`--exces` les nomme toutes avec leur motif. Faites-les entrer dans un puits reconnu, ou relevez "
              f"ce plafond avec la raison écrite à côté.")
        print("\nLa garde refuse de conclure : elle ne rendra pas vert sur une moitié de lexique qu'elle ne sait "
              "pas trancher, et elle n'accusera pas ce qu'elle n'a pas prouvé.")
        return 2

    # UN FRAGMENT QUE L'ANALYSEUR NE SAIT PAS LIRE N'EST PAS UNE FAUTE : c'est un aveu, et son canal est le
    # REFUS DE CONCLURE (`P11.8-i`), exactement comme pour les indécidables. Le rendre rouge à la première
    # occurrence rendrait la garde rouge en permanence ; le taire rendrait vert sur ce qu'elle ne lit pas.
    if len(illisibles) > PLAFOND_FRAGMENTS_ILLISIBLES:
        for m, x in illisibles:
            print(f"::error::{m} : fragment de balisage NON ANALYSABLE — {x}")
        print(f"::error::{len(illisibles)} fragment(s) de balisage que l'analyseur refuse de lire, plafond "
              f"{PLAFOND_FRAGMENTS_ILLISIBLES} — les nœuds de ces fragments ne sont jugés par personne. La forme "
              f"la plus fréquente est une interpolation POSÉE DANS UNE BALISE (`` `<b ${{c}}>` ``) : sortez-la "
              f"dans une valeur d'attribut entre guillemets (`` `<b class=\"${{c}}\">` ``), ce qui est aussi la "
              f"forme la plus sûre côté injection. Ou relevez ce plafond avec la raison écrite à côté.")
        print("\nLa garde refuse de conclure : un analyseur de balisage qui se tromperait EN SILENCE serait "
              "pire que l'angle mort qu'il comble.")
        return 2

    regressions = []
    for m in sorted(set(plafonds) | set(plafonds_hr)):
        r = resultats.get(m)
        if r is None:
            regressions.append(f"{m} : plafond écrit mais module absent — retirez l'entrée ou restaurez le module.")
            continue
        plafond = plafonds[m]
        if len(r["trous"]) > plafond:
            ex = ", ".join(f"« {s} »" for s in r["trous"][:8])
            regressions.append(
                f"{m} : {len(r['trous'])} chaîne(s) affichée(s) sans entrée au lexique, plafond {plafond} "
                f"(couverture {r['taux']:.1f} %) — p. ex. {ex}. Inscrivez chaque chaîne affichée dans "
                f"`web/i18n.js` (clé FR -> valeur EN) ; une chaîne dynamique se compose à partir de clés traduites."
            )
        plafond_hr = plafonds_hr[m]
        if len(r["hors_regard"]) > plafond_hr:
            ex = ", ".join(f"« {s} »" for s in r["hors_regard"][:5])
            regressions.append(
                f"{m} : {len(r['hors_regard'])} littéral(aux) HORS-REGARD, plafond {plafond_hr} — p. ex. {ex}. "
                f"Un libellé neuf posé dans une forme que la garde ne lit pas ne doit pas passer en silence : "
                f"posez-le dans un puits reconnu (`textContent`, `label:`, `muted(`, littéral HTML…), ou faites "
                f"lire cette forme à la garde et abaissez le plafond. Ce cliquet n'est pas relevable sans raison "
                f"écrite : il garde ce que la garde IGNORE, et rendre vert sur ce qu'on ne regarde pas est pire "
                f"qu'une garde absente. `--hors-regard {m}` les liste."
            )
    if len(a_cheval) > PLAFOND_NOEUDS_A_CHEVAL:
        regressions.append(
            f"lexique : {len(a_cheval)} nœud(s) RENDU(S) sans entrée, plafond {PLAFOND_NOEUDS_A_CHEVAL} — "
            + " · ".join(f"« {t} »" for t in a_cheval[:6])
            + ". Chacun TRAVERSE une borne de littéral : la lecture littéral par littéral le voit en deux "
              "moitiés et les range en « dynamique », alors que `i18nWalk` compare le nœud ENTIER. Deux "
              "sorties, l'une et l'autre valides : déplacer la borne du littéral sur une FRONTIÈRE DE BALISE "
              "(le nœud redevient un littéral entier, et la mesure ordinaire le réclame), ou inscrire le nœud "
              "tel quel au lexique. Inscrire une MOITIÉ produirait une entrée morte. `--noeuds` les liste."
        )
    if len(orphelines) > PLAFOND_ORPHELINES:
        regressions.append(
            f"lexique : {len(orphelines)} ORPHELINE(S) PROUVÉE(S), plafond {PLAFOND_ORPHELINES} — "
            + " · ".join(f"« {c} »" for c, _ in orphelines[:6])
            + ". Le texte de chacune est absent du dépôt ENTIER et aucun littéral de l'arbre servi n'en "
              "formerait le bord : plus aucun nœud ne peut valoir cette clé, elle ne traduira jamais rien. "
              "Retirez-la de `web/i18n.js` et abaissez `PLAFOND_ORPHELINES` d'autant. `--exces` les liste."
        )
    if regressions:
        for e in regressions:
            print(f"::error::{e}")
        print(f"\n{len(regressions)} dépassement(s) de plafond (trous du lexique, hors-regard, ou orphelines).")
        return 1
    print(f"Aucun module au-dessus de son plafond de trous ni de hors-regard "
          f"({len(plafonds)} plafonds de trous et {len(plafonds_hr)} plafonds de hors-regard tenus) ; "
          f"{len(orphelines)} orpheline(s) prouvée(s) pour un plafond de {PLAFOND_ORPHELINES}, "
          f"{len(indecidables)} indécidable(s) pour un plafond de {PLAFOND_INDECIDABLES}, "
          f"{len(a_cheval)} nœud(s) à cheval sans clé pour un plafond de {PLAFOND_NOEUDS_A_CHEVAL} et "
          f"{len(illisibles)} fragment(s) non analysable(s) pour un plafond de {PLAFOND_FRAGMENTS_ILLISIBLES}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
