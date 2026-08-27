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
  (2) une clé d'objet `label:`, `title:`, `placeholder:`, `okText:`, `hint:`, `text:` ;
  (3) un appel `createTextNode(`, `muted(`, `toast(`, `showErr(`, `confirmModal(`, `append(`,
      `prepend(`, `emptyRow(`, ou `setAttribute(` dont le PREMIER argument est un attribut affiché
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
             [--mesure] [--trous MODULE] [--hors-regard MODULE]
Sortie :  0 = aucun module au-dessus de ses plafonds ; 1 = régression (trous ou hors-regard) ;
          2 = instrument invalide, module mesuré hors du cliquet, ou découpeur désynchronisé. `--mesure` imprime le tableau par
          module sans verdict (c'est ce qui sert à relever le compte d'un module neuf) ; `--trous MODULE`
          liste les chaînes du module sans entrée au lexique ; `--hors-regard MODULE` liste ce que la
          garde ne regarde pas dans ce module, en marquant celles qui sont déjà des clés du lexique.
"""
from __future__ import annotations

import collections
import html.parser
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
# Le plancher, lui, ne bouge pas : il est dérivé du relevé ATTRIBUABLE (1 943), pas de celui du jour, et
# aucune des mesures ci-dessus ne s'en approche. Un plancher ne DESCEND jamais pour suivre une mesure plus
# basse — il ne garderait plus rien.
MIN_POPULATION = 1845
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
    "admin_users.js": 16, "ai.js": 1, "alerting.js": 2, "alerts.js": 20, "app.js": 22, "attack.js": 6,
    "audit.js": 1, "cases.js": 70, "composer_depuis_lexistant.js": 7, "connectors.js": 27,
    "copie_et_selection.js": 3, "core.js": 29, "dashboards.js": 22, "dataaccess.js": 11, "datamodels.js": 6,
    "destinations.js": 37, "detadv.js": 14, "detection_admin.js": 28, "fieldfilters.js": 21, "fleet.js": 9,
    "freshness.js": 10, "help.js": 30, "i18n_observer.js": 0, "idp.js": 29, "index.html": 0,
    "index_policies.js": 16, "keys.js": 5, "knowledge.js": 11, "login.js": 6, "lookups.js": 9,
    "multitenant.js": 7, "navigation.js": 2, "prefs.js": 0, "processors.js": 10, "producer_ui.js": 7,
    "recherche_de_liste.js": 1, "retention.js": 17, "risk.js": 6, "runbooks.js": 20, "savedqueries.js": 2,
    "sigmaimport.js": 12, "soql_complete.js": 16, "sources.js": 7, "state.js": 0, "suppressions.js": 21,
    "system.js": 33, "threatintel.js": 6, "viz.js": 21,
}
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
# ON NE POSE PAS UN CLIQUET AU RAS D'UN MODULE QUI BOUGE, ET LA RAISON EST MESURÉE, PAS INVOQUÉE. `alerts.js`
# reste à 20 : deux relevés du MÊME 2026-08-26, à quelques minutes d'écart, en rendent 18 puis 19 — le fichier
# a changé entre les deux sous un autre agent (la ligne du repli de chargement des groupes est passée de 706
# à 795). Un cliquet posé au ras du premier relevé aurait rendu la CI ROUGE sur le travail d'un autre, sans
# qu'aucun libellé n'ait empiré. `risk.js` reste à 6 pour la même raison et de la même façon mesurée : sa
# descente à 5 avait été écrite, puis le module est entré en écriture concurrente dans l'heure, et elle a été
# ANNULÉE avant livraison. Ce n'est pas une hausse (aucun de ces deux chiffres ne dépasse celui de `HEAD`) ni
# un silence (c'est écrit ici, et le jeu restant est PUBLIÉ à chaque exécution) : c'est une descente RETARDÉE,
# à faire sur un module stable. Le mouvement à surveiller sur un module qui bouge est celui des TROUS, dont le
# plafond est à ZÉRO et le reste dans tous les relevés du jour.
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
SINKS_APPEL = ("createTextNode", "muted", "toast", "showErr", "confirmModal", "append", "prepend", "emptyRow")
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
# CE QUI RESTE ÉNUMÉRÉ, ET POURQUOI : ces trois clés ne nomment AUCUNE propriété du document ; ce sont des
# conventions d'appel des fabriques de la console (`confirmModal({okText})`, champs à `hint`, `text`).
# Aucune dérivation ne peut les trouver — seul un suivi de flux jusqu'à l'écriture le pourrait, et c'est
# l'étape suivante, pas celle-ci. Elles sont donc écrites, avec cette raison.
CLES_APPLICATIVES = ("okText", "hint", "text")
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
const dur = { emptyText: 'Sous une clé que le document ne connaît pas' };
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
ATTENDUS_STATIQUES = {"aucun runbook", "nom et champ requis", "Affiché dix-sept",
                      "Affiché dix-huit", "Affiché dix-neuf", "Noeud entre balises",
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


def valider_instrument() -> list[str]:
    errs = []
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
        if f == "index.html":
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
            "taux": (100.0 * len(couvertes) / total) if total else 100.0,
        }
    return resultats, cles, desynchronisations


def main(argv: list[str]) -> int:
    mesure = "--mesure" in argv
    trous_de = None
    if "--trous" in argv:
        trous_de = argv[argv.index("--trous") + 1]
    hors_de = None
    if "--hors-regard" in argv:
        hors_de = argv[argv.index("--hors-regard") + 1]

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
              "mesure, et le moindre libellé neuf posé dans une forme non lue rougit.")
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
    if regressions:
        for e in regressions:
            print(f"::error::{e}")
        print(f"\n{len(regressions)} dépassement(s) de plafond (trous du lexique ou hors-regard).")
        return 1
    print(f"Aucun module au-dessus de son plafond de trous ni de hors-regard "
          f"({len(plafonds)} plafonds de trous et {len(plafonds_hr)} plafonds de hors-regard tenus).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
