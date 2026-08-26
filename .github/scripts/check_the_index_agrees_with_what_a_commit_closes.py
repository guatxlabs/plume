#!/usr/bin/env python3
"""L'index CONCORDE avec ce qu'un commit déclare FERMÉ — garde de CI POSÉE SOUS `P8.9-f`.

ELLE N'AURAIT ATTRAPÉ AUCUN DES DEUX INCIDENTS QUI LA FONDENT — REJEU MESURÉ
-----------------------------------------------------------------------------
Cette garde est POSÉE sous `P8.9-f` ; elle ne la ferme PAS, et ce n'est pas une prudence de style,
c'est un rejeu. Le 2026-08-25, la comparaison a été rejouée sur l'arbre TEL QU'IL ÉTAIT juste avant
chacun des deux correctifs qui fondent la clé — index lu par `git show <ref>:docs/ROADMAP.md`,
histoire par `git log <ref>`, lexique dérivé de l'index de CET arbre-là. ELLE REND ZÉRO LES DEUX
FOIS :

    juste avant 92c1be3 (incident 1, `P11.14-a`)     372 commits, 250 clés, 546 couples → 0 écart
    juste avant aaf219b (incident 2, `P11.18-j/k`)   377 commits, 271 clés, 578 couples → 0 écart

LES DEUX CAUSES SONT DISTINCTES, ET AUCUNE N'EST UN DÉFAUT DE SEUIL.

  INCIDENT 1 — LE LEXIQUE ARRIVE APRÈS LA FERMETURE QU'IL DEVRAIT VOIR. Le commit `0a3327e` écrit
  « P11.14-a corrigée », l'index portait ⬜, et le mot est ATTACHÉ : la lecture, elle, le voit. Ce
  qui manque est le LEXIQUE — sur l'arbre de ce jour-là, CORRIG* valait 0 cellule ✅ pour 1 cellule
  ouverte, pureté 0. Par le témoignage de l'index lui-même, « corrigé » n'était pas encore un mot de
  fermeture. Abaisser le support ne récupère rien : à support ≥ 1, le lexique de cet arbre vaut
  {extrait, ferm, posee, remesur, resserr} et CORRIG* reste dehors, faute de pureté. PROUVÉ PAR
  MUTATION, la valeur qui change étant le LEXIQUE : même arbre, même histoire, lexique d'aujourd'hui
  {corrig, ferm} → 1 écart, `P11.14-a` et lui seul. CONSÉQUENCE GÉNÉRALE, écrite pour être
  opposable : une famille n'entre qu'après TROIS déclarations datées déjà posées dans des cellules
  ✅ — les PREMIÈRES fermetures écrites avec un mot neuf sont donc toujours manquées.

  INCIDENT 2 — LE VOCABULAIRE DES COMMITS ET CELUI DE L'INDEX DIVERGENT, ET DEUX FOIS. Le commit
  `92c1be3` écrit « P11.18-j — RÉGRESSION RÉPARÉE ». D'abord RÉPAR* n'a JAMAIS figuré dans une
  déclaration datée de l'index — 0 occurrence au 2026-08-25 comme la veille, alors que RÉPARÉ et
  RÉPARÉE y sont écrits ailleurs, sans date — donc ce mot n'est pas dérivable. Ensuite le mot
  ADJACENT à la clé n'est pas le participe : c'est le substantif « RÉGRESSION », et l'attachement ne
  lit que le mot adjacent. Mesuré sur l'arbre d'avant : ajouter `repar` au lexique SEUL → 0 écart ;
  élargir la fenêtre d'attachement à deux mots SEULE → 0 écart ; les deux ENSEMBLE → 1 écart sur
  `P11.18-j`, au prix d'une accusation à tort sur `P8.8-a`, dont la ligne porte « NON corrigé » et
  que l'adjacence protège aujourd'hui.

CE QUI A ÉTÉ PESÉ POUR COMBLER CET ANGLE MORT, ET CE QUE LA MESURE EN A DIT
----------------------------------------------------------------------------
  · DÉRIVER DES DEUX SURFACES — le vocabulaire des COMMITS en plus de celui de l'index. RÉFUTÉ par
    le bruit, mesuré le 2026-08-25 aux seuils mêmes de cette garde (support ≥ 3, pureté ≥ 90 %) : la
    surface des commits ajoute VINGT familles, dont dix-huit ne sont pas des fermetures — `et`, `ce`,
    `qui`, `ne`, `se`, `sont`, `n`, `les`, `avait`, `passe`, `vient`, `dan`, `cot`, `pert`, `regl`,
    `portaient`, `residuel`, `regression`. Les revendications passent de 29 à 92 (× 3,2) et DEUX
    accusations neuves apparaissent, toutes deux FAUSSES : `P10.9-a` sur « mesure », un substantif,
    cellule 🔵 ; `P11.14-d` sur « les », un article, cellule ⬜. Zéro accusation légitime ajoutée. Et
    les deux incidents restent hors de portée : CORRIG* ne pèse qu'UNE clé sur la surface des
    commits, et l'incident 2 ne serait attrapé que par `regression`, un substantif pur par accident.
  · RESSERRER LA CONVENTION EN AMONT — « un commit qui ferme l'annonce avec le vocabulaire de
    l'index, et une garde le vérifie ». RÉFUTÉ deux fois. PAR LE TAUX : sur les 110 bascules vers ✅
    que porte l'histoire de l'index, 21 seulement (19 %) sont annoncées par leur propre commit avec
    le vocabulaire de l'index ; une garde qui l'exigerait refuserait 89 commits de fermeture sur 110,
    et un instrument qui rend 89 lignes rouges se désarme — c'est l'argument que cette garde oppose
    déjà au sens inverse. PAR LA NATURE DU DÉFAUT : les deux incidents sont une bascule ABSENTE, or
    une règle sur la façon d'annoncer les bascules qui ONT lieu ne dit rien de celles qui n'ont pas
    lieu.
  · ASSUMER QU'ELLE NE VOIT QU'UNE PART — RETENU, et c'est ce que ce fichier écrit désormais. Ce
    qu'elle voit : une fermeture annoncée dans le vocabulaire que l'index emploie DÉJÀ, attachée à sa
    clé. Ce qu'elle ne voit pas : la première fermeture écrite avec un mot neuf, et toute fermeture
    écrite dans un vocabulaire que l'index n'emploie pas en déclaration datée. `P8.9-f` RESTE
    OUVERTE ; le remède qui la fermerait est structurel, et il est nommé en fin de ce document.

LE DÉFAUT QUE CETTE GARDE VOIT — UNE PART, PAS LE TOUT
------------------------------------------------------
L'index public des clés (`docs/ROADMAP.md`) porte, pour chaque clé, un ÉTAT dans une colonne, et un
TEXTE dans une autre. Les deux sont écrits à la main, et rien ne les relie : ils PEUVENT donc
diverger. MESURÉ le 2026-08-25, DEUX FOIS DANS LA MÊME JOURNÉE : des clés dont le correctif était
commité, déployé et vérifié figuraient encore parmi les clés OUVERTES. La première fois, une cellule
avait été réécrite sans que sa colonne d'état bascule ; la seconde, la cellule n'avait pas été
réécrite du tout. Les deux fois, l'écart a été trouvé À L'ŒIL en affichant la liste des clés
ouvertes, jamais par une garde.

QUI LIT « CE QUI EST OUVERT » NE VOIT DONC PAS CE QUI EST FAIT — et c'est le reproche exact que ce
document adresse au produit : une surface qui présente un état PÉRIMÉ comme un état COURANT. Aucune
garde du dépôt ne le voyait, pour une raison de fond : celle des restes lit le TEXTE des cellules,
celle des tableaux lit la FORME des lignes, celle des collisions lit les CLÉS. Aucune ne compare ce
qu'un commit AFFIRME avec ce que l'index DÉCLARE.

LA PROPRIÉTÉ DÉRIVABLE, ET POURQUOI ELLE N'ÉNUMÈRE RIEN
--------------------------------------------------------
Les messages de commit de ce dépôt CITENT leur clé — c'est une règle tenue, et elle se mesure :
sur 378 commits au 2026-08-25, 237 citent au moins une clé, 234 clés distinctes sont citées, et
UNE SEULE clé citée est absente de l'index — 1 sur 234, et non zéro comme il a d'abord été écrit.
C'est `P99.9-z`, posée le 2026-08-09 par le commit `2b977e8` comme TÉMOIN NÉGATIF d'un contrôle de
couverture : une clé fabriquée pour n'exister nulle part. Elle n'est jamais annoncée fermée, donc
elle n'accuse rien — et elle vaut mieux qu'un zéro, puisqu'elle prouve, sur les données réelles, que
la branche « citée mais sans entrée » a de quoi mordre. Les commits disent aussi quand ils ferment.
Une clé annoncée fermée par un commit et encore marquée ouverte dans l'index est donc détectable
sans énumérer une seule clé, un seul commit, ni un seul fichier.

CE QUI EST DÉRIVÉ, ET CE QUE LA MESURE A RÉFUTÉ
------------------------------------------------
Le vocabulaire de fermeture n'est PAS écrit ici à la main. Trois dérivations ont été essayées ; deux
sont RÉFUTÉES, et les chiffres sont ceux du 2026-08-25 sur cet arbre :

  (1) RÉFUTÉE — « les mots qui, en position de fermeture, ne qualifient que des clés ✅ ». Le taux de
      base tue ce critère : 212 des 272 clés de l'index sont ✅, soit 78 %. Mesuré en position
      d'adjacence sur toute l'histoire, l'article « le » qualifie 66 clés DISTINCTES dont 85 % sont
      ✅ (73 occurrences, 86 %), « une » 22 clés à 86 %, « un » 22 clés à 82 %. Le relevé d'origine
      annonçait 26 clés pour « le » ; remesuré, c'est 66, et la réfutation en sort plus forte, pas
      plus faible. Un seuil de pureté y ferait entrer les articles — et la mesure le montre en
      grand : aux seuils de cette garde, la surface des commits fait entrer `et`, `ce`, `qui`, `ne`,
      `se`, `sont`, `les`. Une dérivation qui ne distingue pas « le » de « fermée » n'en est pas une.
  (2) RÉFUTÉE — « les mots que l'index emploie dans une cellule ✅ et quasiment jamais dans une
      cellule ouverte ». Ce critère laisse passer ASSUMÉ — 18 cellules ✅ contre 1 ouverte au
      2026-08-25 (`P11.5-d`), soit 95 % de pureté, au-dessus du seuil que cette garde applique — or
      ASSUMÉ qualifie un reste DÉLIBÉRÉ, l'exact contraire d'une fermeture. Le relevé d'origine
      annonçait « 11 cellules ✅, 0 ouverte » ; remesuré, c'est 18 et 1, et la réfutation tient.
  (3) RETENUE — LA DÉCLARATION DATÉE. Ce document ferme une clé en écrivant, dans sa cellule, un mot
      en MAJUSCULES suivi de sa date : « FERMÉE le 2026-08-22 ». C'est la forme par laquelle l'index
      dit lui-même qu'une clé est close.

      LE MOTIF N'IMPOSE PAS UN PARTICIPE, et l'énoncé qui le prétendait était faux :
      `DECLARATION_DATEE` accepte N'IMPORTE QUEL mot d'au moins quatre lettres majuscules suivi de
      « le <date> ». C'est délibéré — un motif qui présumerait la grammaire du français manquerait la
      forme neuve — et cela se paie en clair : au 2026-08-25 le motif admet SIX familles qui ne sont
      pas des participes, PRODUCTION (24 déclarations), RÉEL (12), MAIN, GARDES, FOIS, BANC (1
      chacune), venues de « … EN PRODUCTION le <date> » et « RELEVÉ EN USAGE RÉEL le <date> ». Ce
      n'est donc pas le motif qui DISCRIMINE, ce sont le SUPPORT et la PURETÉ appliqués après lui —
      et c'est pourquoi le verdict imprime PRODUCTION* (18/24) et RÉEL* (6/12) parmi les rejetés :
      ils ont été pesés, pas ignorés. LE RISQUE QUE CELA LAISSE, nommé plutôt que sous-entendu : si
      assez de cellules ✅ écrivaient « EN PRODUCTION le <date> », PRODUCTION passerait le seuil, et
      un commit disant « P1.2-a production … » serait lu comme une fermeture. Le lexique est IMPRIMÉ
      dans le verdict pour qu'un tel mot se voie entrer, et un témoin de la dérivation tient cette
      propriété-là.

      La discrimination, elle, est nette :

          FERM*   60 cellules ✅ /  0 cellule ouverte     ← retenu
          CORRIG*  4 cellules ✅ /  0 cellule ouverte     ← retenu
          DÉPLOY*  4 cellules ✅ /  3 cellules ouvertes   ← rejeté : DÉPLOYÉ N'EST PAS FERMÉ
          MESUR*  19 cellules ✅ / 16 cellules ouvertes   ← rejeté
          LIVR*    3 cellules ✅ /  2 cellules ouvertes   ← rejeté
          REPRI*   0 cellule  ✅ /  7 cellules ouvertes   ← rejeté

      Le rejet de DÉPLOY* n'est pas un détail de seuil : il porte le fait mesuré qui a fondé cette
      clé. Un correctif DÉPLOYÉ peut rester ouvert à dessein, et l'index l'écrit ainsi. Une garde qui
      lirait « déployée » comme une fermeture accuserait ces lignes-là.

      La famille est obtenue en retirant l'accord (`FERMÉE`, `FERMÉ`, `FERMÉES` → `ferm`) : c'est une
      règle de grammaire, pas une liste. Le seuil est un SUPPORT (≥ 3 déclarations) et une PURETÉ
      (≥ 90 %), tous deux appliqués à la même mesure — et le lexique dérivé est IMPRIMÉ dans le
      verdict, pour qu'un mot qui entre ou qui sort se voie.

L'ATTACHEMENT — CE QUI SÉPARE « FERMER » DE « CITER », ET POURQUOI IL NE FAUT PAS SE TROMPER
---------------------------------------------------------------------------------------------
Un commit qui écrit « P11.5-d ouverte » ou « à ne pas confondre avec P11.14-b » CITE une clé sans la
fermer. Ces citations sont l'ÉCRASANTE MAJORITÉ : sur 581 couples (commit, clé) distincts,
551 ne portent aucune fermeture attachée — 95 %. Une garde qui confondrait citer et fermer
accuserait donc à tort, et une accusation à tort est pire qu'un silence : elle apprend à ignorer la
garde. Mesuré le 2026-08-25 sur cet arbre, à lexique dérivé identique :

    « le message cite la clé ET contient un mot de fermeture »  → 23 clés ouvertes accusées à tort
    « la LIGNE cite la clé ET contient un mot de fermeture »     →  6 clés ouvertes accusées à tort
    « le mot de fermeture SUIT le groupe de clés »               →  0

Le critère retenu est le troisième, et il est GRAMMATICAL : une revendication est un GROUPE de clés
— une suite de clés séparées par les seuls connecteurs que ce dépôt emploie (`,` `et` `+` `/`) —
IMMÉDIATEMENT suivi d'un mot du lexique dérivé. Les six accusations à tort du critère par ligne sont
réelles, et les voici toutes :

    « P11.5-c et P11.11-a fermees, P11.5-d ouverte — deployees et verifiees en production »
    « P4.4-m fermee et P4.4-p posee »
    « P11.17-c FERMÉE, P11.15-b avancée »
    « P6.9-a fermee et P7.18-a quatrieme lot »
    « P11.18-j et P11.18-k FERMÉES, et P8.9-f : l'index présentait comme ouvert ce qui est déployé »
    « … même famille que P8.5-a. Consigné en P8.8-a, NON corrigé : … »

Dans chacune, le mot de fermeture appartient au groupe qui le précède, et à lui seul. La dernière
porte le cas limite gratuitement : le français place la NÉGATION avant le participe, si bien que le
mot adjacent à la clé est « NON » et non « corrigé ». L'adjacence lit cela, et rien d'autre.

LE SENS INVERSE A ÉTÉ PESÉ, ET IL EST REFUSÉ
----------------------------------------------
« Une clé marquée FERMÉE qu'aucun commit ne ferme est-elle suspecte ? » Mesuré le 2026-08-25 :
212 clés sont ✅ ; 22 ne sont citées par AUCUN commit ; et sur les 190 restantes, 29 seulement
portent une fermeture attachée. DEUX COMPTES ONT UN SENS, et la soustraction d'origine mêlait les
deux — de « 190 restantes, 29 avec fermeture » on tire 161, pas 183. Les voici tous les deux : un
test inverse qui accuserait TOUTE clé ✅ sans fermeture attachée en rendrait 183 sur 212 (86 %) ;
s'il excusait les 22 qu'aucun commit ne cite — faute de quoi que ce soit à comparer — il en
rendrait 161 sur 190 (85 %). La cause est connue et légitime : la règle de citation est plus jeune
que la plupart de ces clés, et une fermeture s'écrit souvent dans le commit du CODE, sous une phrase
qui décrit le correctif plutôt que l'état. Un instrument qui rend 161 lignes rouges au mieux et 183
au pire ne se lit pas, il se désarme. Le sens inverse n'est donc PAS tenu, et c'est écrit ici plutôt
que sous-entendu.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT, ET UN ZÉRO S'INTERPRÈTE
---------------------------------------------------------------------------
Quatre épreuves, avant tout verdict :
  · LA DÉRIVATION, dans les deux sens — une famille pure et soutenue DOIT entrer, une famille
    partagée entre cellules fermées et ouvertes NE DOIT PAS entrer, une famille pure mais rare non
    plus.
  · LA LECTURE, dans les deux sens — les formes de revendication réelles DOIVENT être vues, et les
    formes de citation sans fermeture NE DOIVENT PAS l'être. Ce corpus porte son propre lexique :
    il éprouve l'ATTACHEMENT, pas la dérivation, qui a ses témoins à elle.
  · LE DÉCOUPAGE DU CORPUS, dans les deux sens — une ligne d'index montrée dans un BLOC DE CODE est
    un échantillon et NE DOIT PAS entrer dans l'index ; la même ligne, hors du bloc, DOIT y entrer.
    Sans ce second sens, un découpeur devenu aveugle à tout passerait le premier témoin.
  · UN CONTRÔLE POSITIF SUR LES DONNÉES RÉELLES — une revendication vraie de l'histoire est
    confrontée à un état MUTÉ (la clé passée à ⬜ dans une copie en mémoire de l'index). Si la
    comparaison ne la signale pas, aucun verdict n'est rendu. Sans ce contrôle, « aucun écart » et
    « aucun écart VISIBLE À CET INSTRUMENT » se ressemblent trop.

LEUR COMPTE N'EST PAS ÉCRIT ICI — il est CALCULÉ sur les listes elles-mêmes et imprimé dans le
verdict, parce qu'un compte écrit à la main dérive de ce qu'il compte : il a déjà été annoncé
« 18 et 12 » pour des sections qui en portaient 6 et 13. Compter les témoins de la lecture demande
d'ailleurs de dire SELON QUOI : par section du fichier, ou par attente non vide — plusieurs témoins
portent une citation À NE PAS lire ET une fermeture réelle à lire, et éprouvent les deux sens d'un
coup. Le verdict imprime la seconde lecture, la seule qui ne dépende pas de la mise en page.

Puis des PLANCHERS : historique tronqué (`--depth 1` d'un `actions/checkout` par défaut), index
introuvable, trop peu de clés, trop peu de citations, trop peu de revendications, lexique vide. Sous
un plancher la garde SORT EN 2 — « je refuse de conclure » — et jamais en 0.

CE QU'ELLE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE
---------------------------------------------------
  · ELLE NE FERME PAS `P8.9-f`, ET D'ABORD CELA : rejouée sur l'arbre d'avant chacun des deux
    correctifs qui la fondent, elle rend ZÉRO les deux fois. Les deux causes sont mesurées en tête de
    ce document, et les deux voies pesées pour les combler y sont réfutées par la mesure.
  · Elle ne tient que le vocabulaire DÉRIVÉ de la déclaration datée. « P8.15-a close » et
    « P8.11-a close » sont deux fermetures réelles de l'histoire que ce lexique ne reconnaît pas :
    l'index n'emploie pas CLOS dans une déclaration datée. Elles seraient manquées — silence, jamais
    accusation.
  · Elle ne voit qu'une fermeture ATTACHÉE au groupe de clés. « P11.1-b + P11.4-b + P11.8-a +
    P3.8-a : cinq restes fermes » ferme bien ces clés, et cette garde ne le voit pas. C'est le prix
    assumé des 6 accusations à tort qu'éviter coûte.
  · Elle lit LIGNE par LIGNE. Une revendication coupée par un retour à la ligne lui échapperait ;
    mesuré sur les 378 commits du 2026-08-25 : zéro.
  · Elle ne juge pas la VÉRITÉ d'une fermeture. Un commit qui annonce à tort une clé fermée est cru
    sur parole, et la garde exigera que l'index le suive.
  · Elle compare avec l'état COURANT. Une clé délibérément RÉOUVERTE après un commit qui la fermait
    serait signalée, et cette garde ne sait pas distinguer une réouverture d'un oubli. LE CONSEIL QUI
    FIGURAIT ICI — « la cellule doit dire la réouverture » — ÉTAIT INERTE, et c'est PROUVÉ PAR
    MUTATION le 2026-08-25 : sur `P10.13-a` passée à ⬜, écrire « RÉOUVERTE le <date> » dans la
    cellule change le CORPS de la cellule et RIEN D'AUTRE ; la comparaison ne lit que la colonne
    d'état, et l'accusation reste mot pour mot. La seule valeur qui agit est l'ÉTAT — remis à ✅,
    l'accusation disparaît. LE GESTE EFFECTIF est celui que ce document se donne déjà pour du travail
    qui reprend sous une clé fermée : la cellule RESTE ✅ et NOMME une clé NEUVE, ouverte, qui porte
    la reprise — la convention que tient `check_every_residue_belongs_to_an_open_key.py`. C'est cela
    que le verdict conseille désormais, et non plus le geste sans effet.
  · Elle n'a AUCUN vocabulaire de réouverture à dériver, et ce n'est pas faute d'avoir cherché. La
    dérivation MIROIR — les familles dont les déclarations datées tombent dans des cellules OUVERTES,
    aux mêmes seuils — ne rend qu'une famille au 2026-08-25 : REPRI* (0 cellule ✅ / 7 ouvertes).
    Les sept cellules ont été LUES : « REPRIS le 2026-08-24 d'une tâche restée ouverte » signifie
    repris d'un plan de tâches EXTÉRIEUR, jamais rouvert après fermeture. La dérivation miroir est
    donc RÉFUTÉE, et l'index n'écrit aujourd'hui aucune réouverture qu'une garde pourrait lire.
  · Elle ne lit aucun dépôt voisin : une clé fermée par un commit de l'outillage de déploiement, qui
    vit hors de ce dépôt, lui est invisible.

LE REMÈDE EN AMONT EXISTE, ET IL EST PLUS FORT QUE CETTE GARDE
---------------------------------------------------------------
L'état vit aujourd'hui dans une COLONNE, séparée du TEXTE qui le décrit ; deux champs écrits à la
main peuvent diverger, et c'est la condition même du défaut. Une clé dont l'état serait DÉRIVÉ de sa
prose — ou une clé par SECTION, où l'état et le texte ne font qu'un — rendrait la divergence
inécrivable au lieu de la rendre détectable. Ce remède est nommé sous `P8.9-d` ; il n'est pas posé
ici. Cette garde est ce qui tient la forme actuelle, pas ce qui la remplace.
"""
import collections
import os
import re
import subprocess
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import racine_designee  # noqa: E402  (geste partagé, écrit UNE fois)

ETIQUETTE = "index-vs-fermeture"

# ─── PLANCHERS DE NON-DÉGÉNÉRESCENCE. En dessous, ce n'est pas l'arbre qui est propre, c'est la
# lecture qui est cassée. Relevés sur cet arbre le 2026-08-25 : 378 commits, 272 clés définies,
# 581 couples (commit, clé), 30 couples portant une fermeture attachée pour 29 clés distinctes
# (une clé fermée deux fois), lexique soutenu par 64 déclarations datées.
# Les abaisser demande une raison écrite à côté.
MIN_COMMITS = 150
MIN_CLES = 100
MIN_CITATIONS = 200
MIN_REVENDICATIONS = 10
MIN_SUPPORT_LEXIQUE = 20

# ─── SEUILS DE LA DÉRIVATION. Une famille de participes est retenue comme FERMETURE si l'index la
# pose dans une déclaration datée au moins SUPPORT fois, et si la PURETÉ de ces déclarations —
# la part qui tombe dans une cellule ✅ — atteint le seuil. Mesuré le 2026-08-25 : FERM* 60/60,
# CORRIG* 4/4, contre DÉPLOY* 4/7, MESUR* 19/35, LIVR* 3/5, REPRI* 0/7.
SUPPORT_MIN_FAMILLE = 3
PURETE_MIN = 0.90

# L'ÉTAT qui promet que le travail est fait. Les autres états promettent le contraire.
FERMEE = "✅"

# La CLÉ, dans le schéma que l'index déclare : P<phase>.<chantier>-<constat>.
CLE = re.compile(r"P\d+(?:\.\d+)*-[a-z]\b")
CLE_SEULE = re.compile(r"^P\d+(?:\.\d+)*-[a-z]$")

# LA DÉCLARATION DATÉE : un mot d'au moins QUATRE LETTRES MAJUSCULES suivi de sa date. C'est la
# forme par laquelle l'index dit lui-même qu'une clé est close, et c'est de là que le vocabulaire est
# dérivé. LE MOTIF N'EXIGE PAS UN PARTICIPE et il ne faut pas le lire comme tel : au 2026-08-25 il
# admet PRODUCTION (24 déclarations), RÉEL (12), MAIN, GARDES, FOIS, BANC. Ce sont le SUPPORT et la
# PURETÉ, appliqués après, qui trient — le témoin de la dérivation tient cette propriété.
DECLARATION_DATEE = re.compile(r"\b([A-ZÀ-ÖØ-Þ]{4,})\s+le\s+\d{4}-\d{2}-\d{2}")
# La CLÔTURE d'un bloc de code : ce qu'il montre est un ÉCHANTILLON, jamais un tableau du document.
# Lecture reprise telle quelle de `check_every_table_row_carries_the_shape_its_header_declares.py`,
# qui a traité ce cas le premier — une règle écrite deux fois finit par diverger, celle-ci est donc
# écrite pareil et éprouvée ici par ses propres témoins.
CLOTURE_DE_BLOC = re.compile(r"^ {0,3}(```|~~~)")

# Les CONNECTEURS que ce dépôt emploie entre deux clés d'un même groupe, et eux seuls. Un tiret
# cadratin, un deux-points ou un mot quelconque ROMPENT le groupe : « P4.4-m fermee et P4.4-p posee »
# est DEUX groupes, et c'est ce qui empêche la garde d'accuser P4.4-p.
CONNECTEUR = re.compile(r"^\s*(?:[,+/]\s*)?(?:et\s+)?$")
# Ce qui se franchit entre la fin d'un groupe et le mot qui le qualifie : ponctuation et balisage.
LIAISON = re.compile(r"^[\s:—–,\.;«»\"'*`()\[\]-]+")
MOT = re.compile(r"[^\W\d_]+", re.UNICODE)


def echec(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def refus(msg):
    """« Je refuse de conclure » — distinct de « rien trouvé ». Un vert rendu ici n'attesterait rien."""
    print(f"::error::[{ETIQUETTE}] REFUS DE CONCLURE — {msg}")
    sys.exit(2)


def sans_accents(texte):
    return "".join(c for c in unicodedata.normalize("NFD", texte) if unicodedata.category(c) != "Mn")


def famille(mot):
    """Le participe DÉPOUILLÉ DE SON ACCORD : `FERMÉE`, `FERMÉ`, `FERMÉES` → `ferm`.

    C'est une règle de grammaire — le français accorde le participe avec « la clé », féminin, et le
    met au pluriel quand le groupe porte plusieurs clés — et non une liste de formes écrite à la
    main. Un mot qui se dissoudrait entièrement (`ses`) garde sa forme plutôt que de devenir vide.
    """
    nu = sans_accents(mot).lower().rstrip("es")
    return nu if len(nu) >= 3 else sans_accents(mot).lower()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# LE CORPUS : DÉRIVÉ D'UNE PROPRIÉTÉ, JAMAIS D'UN NOM DE FICHIER
# ─────────────────────────────────────────────────────────────────────────────────────────────
def documents_du_corpus(racine):
    """Les documents Markdown PUBLIÉS OU EN PASSE DE L'ÊTRE : suivis, ou présents et non ignorés.

    Le `--others` n'est pas une commodité : une garde dont le corpus se limite aux fichiers suivis
    rend VERT sur un fichier tant qu'il n'est pas indexé, puis rougit au premier commit — mesuré sur
    ce dépôt le 2026-08-22.
    """
    fait = subprocess.run(["git", "-C", racine, "ls-files", "--cached", "--others", "--exclude-standard"],
                          capture_output=True, text=True)
    if fait.returncode:
        refus(f"`git ls-files` a échoué dans {racine} : le corpus ne peut pas être dérivé.")
    return sorted({c for c in fait.stdout.split("\n") if c.endswith(".md")})


def lignes_de_definition(texte):
    """Les lignes de tableau dont la PREMIÈRE cellule est une clé NUE — la forme que l'index se donne.

    C'est la même lecture que les gardes sœurs de ce document, et c'est ce qui fait le PÉRIMÈTRE :
    est un index tout document qui DÉFINIT des clés ainsi. Un index qui déménage reste jugé.

    LES BLOCS DE CODE CLÔTURÉS SONT SAUTÉS : ce qu'ils montrent est un ÉCHANTILLON, pas un tableau du
    document. Sans ce saut, une ligne d'exemple qui montre une clé entrerait dans l'index avec son
    état d'échantillon — au mieux un DOUBLON qui fait refuser la garde, au pire un état fabriqué
    opposé à celui que le document publie, et alors la comparaison porte sur une ligne que personne
    ne lit. Mesuré sur cet arbre le 2026-08-25 : ZÉRO ligne concernée. C'est donc un trou LATENT,
    fermé avant de s'ouvrir, et les témoins du découpage l'empêchent de se rouvrir.
    """
    out, dans_code = [], False
    for n, ligne in enumerate(texte.split("\n"), 1):
        if CLOTURE_DE_BLOC.match(ligne):
            dans_code = not dans_code
            continue
        if dans_code or not ligne.startswith("|"):
            continue
        cellules = ligne.split("|")
        if len(cellules) < 5:
            continue
        nue = re.sub(r"\*\([^)]*\)\*", "", cellules[1].strip()).replace("*", "").strip()
        if not CLE_SEULE.match(nue):
            continue
        corps = "|".join(cellules[4:]).rstrip()
        if corps.endswith("|"):
            corps = corps[:-1]
        out.append((n, nue, cellules[3].strip(), corps.strip()))
    return out


def index_du_corpus(racine):
    """L'index des clés, DÉCOUVERT : clé → (document, ligne, état, corps de cellule)."""
    index, doublons = {}, []
    for chemin in documents_du_corpus(racine):
        absolu = os.path.join(racine, chemin)
        try:
            with open(absolu, encoding="utf-8") as fh:
                texte = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        for n, cle, etat, corps in lignes_de_definition(texte):
            if cle in index:
                doublons.append((cle, index[cle][0], index[cle][1], chemin, n))
                continue
            index[cle] = (chemin, n, etat, corps)
    return index, doublons


# ─────────────────────────────────────────────────────────────────────────────────────────────
# LA DÉRIVATION DU VOCABULAIRE DE FERMETURE
# ─────────────────────────────────────────────────────────────────────────────────────────────
def lexique_de_fermeture(cellules):
    """Le vocabulaire de fermeture, DÉRIVÉ des déclarations datées de l'index.

    `cellules` est une suite de `(état, corps)`. Rend `(lexique, détail)` où `détail` porte, par
    famille, le couple (déclarations tombant dans une cellule ✅, total) — c'est lui qui est imprimé
    dans le verdict, pour qu'un mot qui entre ou qui sort du lexique se voie.
    """
    tally = collections.defaultdict(lambda: [0, 0])
    for etat, corps in cellules:
        for m in DECLARATION_DATEE.finditer(corps):
            f = famille(m.group(1))
            tally[f][1] += 1
            if etat == FERMEE:
                tally[f][0] += 1
    lexique, detail = set(), {}
    for f, (fermes, total) in tally.items():
        detail[f] = (fermes, total)
        if total >= SUPPORT_MIN_FAMILLE and fermes / total >= PURETE_MIN:
            lexique.add(f)
    return lexique, detail


# ─────────────────────────────────────────────────────────────────────────────────────────────
# LA LECTURE : UN GROUPE DE CLÉS, PUIS LE MOT QUI LE QUALIFIE
# ─────────────────────────────────────────────────────────────────────────────────────────────
def groupes_de_cles(ligne):
    """Rend `(clés, position de fin)` pour chaque GROUPE de la ligne.

    Un groupe est une suite de clés que seuls des connecteurs séparent. Tout le reste rompt : c'est
    l'unique raison pour laquelle « P4.4-m fermee et P4.4-p posee » n'attribue pas la fermeture à
    P4.4-p.
    """
    reperes, out, i = list(CLE.finditer(ligne)), [], 0
    while i < len(reperes):
        cles, fin = [reperes[i].group(0)], reperes[i].end()
        while i + 1 < len(reperes) and CONNECTEUR.match(ligne[fin:reperes[i + 1].start()]):
            i += 1
            cles.append(reperes[i].group(0))
            fin = reperes[i].end()
        out.append((cles, fin))
        i += 1
    return out


def revendications(message, lexique):
    """Les fermetures qu'un message REVENDIQUE : `(clé, mot employé, ligne du message)`.

    Lecture LIGNE PAR LIGNE, et le mot doit SUIVRE le groupe : une fermeture énoncée ailleurs dans
    la phrase appartient à autre chose. Mesuré le 2026-08-25 : le critère « même ligne » accuserait
    à tort six clés ouvertes, celui-ci aucune.
    """
    out = []
    for ligne in message.split("\n"):
        for cles, fin in groupes_de_cles(ligne):
            suite = LIAISON.sub("", ligne[fin:])
            m = MOT.match(suite)
            if m and famille(m.group(0)) in lexique:
                for cle in cles:
                    out.append((cle, m.group(0), ligne.strip()))
    return out


def histoire(racine):
    """Les commits, lus SANS ÉCRIRE : `(empreinte, date, message)`."""
    fait = subprocess.run(["git", "-C", racine, "log", "--format=%H%x01%ad%x01%B%x02", "--date=short"],
                          capture_output=True, text=True)
    if fait.returncode:
        refus("`git log` a échoué : sans historique, un vert voudrait dire « aucune clé fermée ne "
              "traîne ouverte » alors que rien n'a été lu.")
    out = []
    for bloc in fait.stdout.split("\x02"):
        if not bloc.strip():
            continue
        empreinte, date, message = bloc.strip("\n").split("\x01", 2)
        out.append((empreinte, date, message))
    return out


def ecarts(revendiquees, index):
    """La comparaison, ÉCRITE UNE FOIS — c'est elle que le contrôle positif éprouve.

    `revendiquees` : clé → (empreinte, date, mot, ligne). Rend `(marquees_ouvertes, sans_entree)`.
    """
    ouvertes, absentes = [], []
    for cle, (empreinte, date, mot, ligne) in sorted(revendiquees.items()):
        if cle not in index:
            absentes.append((cle, empreinte, date, mot, ligne))
        elif index[cle][2] != FERMEE:
            ouvertes.append((cle, empreinte, date, mot, ligne, index[cle]))
    return ouvertes, absentes


# ─────────────────────────────────────────────────────────────────────────────────────────────
# LES TÉMOINS — L'INSTRUMENT SE RECONNAÎT AVANT DE JUGER QUOI QUE CE SOIT
# ─────────────────────────────────────────────────────────────────────────────────────────────
# Le corpus de la LECTURE porte son PROPRE lexique : il éprouve l'ATTACHEMENT du mot à la clé, pas
# la dérivation du mot, qui a ses témoins juste au-dessus. Sans quoi les deux épreuves se
# couvriraient mutuellement et aucune ne prouverait rien.
LEXIQUE_TEMOIN = {"ferm", "corrig"}

TEMOINS_DE_LA_LECTURE = [
    # ── CE QUI DOIT ÊTRE VU : les formes de revendication réellement employées ──────────────────
    ("P11.16-d FERMÉE — et une pagination par clé aurait ROMPU la chaîne", {"P11.16-d"}),
    ("P11.18-j et P11.18-k FERMÉES, et P8.9-f : l'index présentait comme ouvert ce qui est déployé",
     {"P11.18-j", "P11.18-k"}),                      # le troisième est CITÉ, pas fermé
    ("P4.4-l P4.5-c : fermees par l'outillage de deploiement", {"P4.4-l", "P4.5-c"}),
    ("P11.14-a corrigée, et trois défauts trouvés EN LA CORRIGEANT", {"P11.14-a"}),
    ("ROADMAP : P10.14-a fermée (8b0db16) — la garde dérivée existe", {"P10.14-a"}),
    ("P8.27-a et P8.27-b fermees", {"P8.27-a", "P8.27-b"}),
    # ── CE QUI NE DOIT PAS L'ÊTRE : citer n'est pas fermer. Plusieurs de ces témoins portent AUSSI
    #    une fermeture RÉELLE sur la même ligne : ils éprouvent alors les deux sens d'un coup, ce qui
    #    est la forme la plus forte — la lecture doit voir l'une SANS voir l'autre. ──────────────
    ("P11.5-c et P11.11-a fermees, P11.5-d ouverte — deployees et verifiees en production",
     {"P11.5-c", "P11.11-a"}),                       # P11.5-d est déployée ET ouverte
    ("P4.4-m fermee et P4.4-p posee : un REJEU qui se nomme", {"P4.4-m"}),
    ("P11.17-c FERMÉE, P11.15-b avancée — et la file est TRONQUÉE", {"P11.17-c"}),
    ("P6.9-a fermee et P7.18-a quatrieme lot, deployes en production", {"P6.9-a"}),
    ("P10.5-c reste ouverte, et rien ne la ferme", set()),
    ("à ne pas confondre avec P11.14-b, qui est fermée depuis longtemps", set()),
    # CINQ TÉMOINS NÉGATIFS ÉTAIENT VIDES : aucun ne portait un mot que LEXIQUE_TEMOIN puisse
    # attraper, si bien qu'ils rendaient vert sans rien éprouver — un témoin qui ne peut pas échouer
    # ne prouve rien. Chacun porte désormais un mot du lexique témoin, placé là où il NE DOIT PAS
    # attacher, et `valider_la_lecture` refuse de conclure si l'un d'eux redevient vide.
    ("P9.6-a TRANCHÉE par l'opérateur : base neuve chiffrée, et P9.4-b fermée", {"P9.4-b"}),
    ("P8.13-a VÉRIFIÉE en production, P8.13-b fermée le même jour", {"P8.13-b"}),
    ("P11.4-j, P11.5-d, P11.8-c, P11.12-a : deployees et VERIFIEES en production, aucune fermee",
     set()),                                          # le mot de fermeture ne SUIT aucun groupe
    ("fermée depuis longtemps, P3.9-a n'est ici que citée", set()),  # le mot PRÉCÈDE : il n'attache pas
    ("P11.1-b + P11.4-b + P3.8-a : cinq restes fermes", set()),  # angle mort DÉCLARÉ
    ("P7.18-a : deuxieme lot d'extractions, et rien n'est fermé", set()),
    # la NÉGATION occupe le mot adjacent : c'est la grammaire qui protège, pas une liste d'exceptions
    ("même famille que P8.5-a. Consigné en P8.8-a, NON corrigé : sa cause reste à établir", set()),
]

# `(état, corps de cellule)` fabriqués. La dérivation doit retenir la famille pure et soutenue,
# rejeter celle que les deux états se partagent, et rejeter celle qui est pure mais rare.
TEMOINS_DE_LA_DERIVATION = [
    ("✅", "FERMÉE le 2026-01-01. Mesure faite."), ("✅", "POSÉE ET FERMÉE le 2026-01-02."),
    ("✅", "FERMÉ le 2026-01-03 par un index partiel."), ("✅", "RELEVÉE ET FERMÉE le 2026-01-04."),
    ("✅", "DÉPLOYÉE le 2026-01-05, et la mesure tient."), ("✅", "DÉPLOYÉE le 2026-01-06."),
    ("⬜", "DÉPLOYÉE le 2026-01-07, et pourtant ouverte : le reste est nommé."),
    ("⬜", "DÉPLOYÉE le 2026-01-08 derrière un drapeau, la décision manque."),
    ("✅", "ÉLUCIDÉE le 2026-01-09."),  # pure mais RARE : sous le support, elle n'entre pas
    # CE QUE LE MOTIF ADMET SANS QUE CE SOIT UN PARTICIPE — la propriété que l'en-tête énonce, rendue
    # OPPOSABLE : PRODUCTION doit être COMPTÉ (le motif l'admet) et REJETÉ (la pureté le trie).
    ("✅", "Vérifié EN PRODUCTION le 2026-01-10."), ("✅", "Vérifié EN PRODUCTION le 2026-01-11."),
    ("⬜", "Déployé EN PRODUCTION le 2026-01-12, la décision manque."),
]

# Un substantif que le motif admet, que le tri doit écarter : si `production` cessait d'être COMPTÉ,
# l'en-tête mentirait sur ce que le motif accepte ; s'il entrait au lexique, un commit disant
# « P1.2-a production … » serait lu comme une fermeture.
NON_PARTICIPE_TEMOIN = "production"


def valider_la_derivation():
    lexique, detail = lexique_de_fermeture(TEMOINS_DE_LA_DERIVATION)
    attendu = {"ferm"}
    if lexique != attendu:
        refus(f"LA DÉRIVATION NE SE RECONNAÎT PLUS : sur le corpus témoin elle rend {sorted(lexique)}, "
              f"attendu {sorted(attendu)} (détail {detail}). Une dérivation qui prendrait DÉPLOYÉE "
              f"pour une fermeture accuserait des lignes délibérément ouvertes ; une qui perdrait "
              f"FERMÉE ne garderait plus rien. Aucun verdict n'est rendu.")
    if detail.get(NON_PARTICIPE_TEMOIN) != (2, 3):
        refus(f"LE MOTIF NE FAIT PLUS CE QUE L'EN-TÊTE DIT : `{NON_PARTICIPE_TEMOIN}` devrait être "
              f"compté 2/3 sur le corpus témoin, il vaut {detail.get(NON_PARTICIPE_TEMOIN)}. "
              f"`DECLARATION_DATEE` accepte N'IMPORTE QUEL mot de quatre lettres majuscules suivi "
              f"d'une date — ce n'est pas le motif qui trie, ce sont le support et la pureté. Si "
              f"cette propriété change, l'en-tête ment, et aucun verdict n'est rendu.")


def valider_la_lecture():
    for message, attendu in TEMOINS_DE_LA_LECTURE:
        # LA VACUITÉ D'ABORD : un témoin qui ne porte AUCUN mot que le lexique témoin puisse
        # attraper ne peut pas échouer, donc il ne prouve rien — cinq des témoins négatifs étaient
        # dans ce cas au 2026-08-25. La propriété est vérifiée AVANT le verdict du témoin, pour que
        # l'épreuve elle-même soit éprouvée.
        if not {famille(m) for m in MOT.findall(message)} & LEXIQUE_TEMOIN:
            refus(f"UN TÉMOIN DE LA LECTURE EST VIDE : « {message} » ne contient aucun mot du "
                  f"lexique témoin {sorted(LEXIQUE_TEMOIN)}. Il rendrait vert quoi que fasse "
                  f"l'attachement, donc il n'éprouve rien. Aucun verdict n'est rendu.")
        vues = {cle for cle, _mot, _ligne in revendications(message, LEXIQUE_TEMOIN)}
        if vues != attendu:
            refus(f"LA LECTURE NE SE RECONNAÎT PLUS : « {message} » rend {sorted(vues)}, attendu "
                  f"{sorted(attendu)}. Une lecture qui ne distingue plus CITER de FERMER accuse à "
                  f"tort — mesuré le 2026-08-25 : six clés ouvertes pour le critère « même ligne ». "
                  f"Aucun verdict n'est rendu.")


# Le DÉCOUPAGE du corpus : ce qu'un bloc de code montre est un ÉCHANTILLON. Un témoin par sens, plus
# le CONTRÔLE que la même ligne, hors du bloc, est bien lue — sans quoi un découpeur qui ne verrait
# plus AUCUNE ligne passerait le premier témoin sans rien tenir.
TEMOINS_DU_DECOUPAGE = [
    ("une ligne d'index MONTRÉE dans un bloc de code",
     "```\n| **P42.1-a** | Exemple | ⬜ | ÉCHANTILLON, pas une définition. |\n```\n", []),
    ("la MÊME ligne hors du bloc — contrôle positif du découpeur",
     "| **P42.1-a** | Exemple | ⬜ | ÉCHANTILLON, pas une définition. |\n", [("P42.1-a", "⬜")]),
    ("un bloc REFERMÉ ne masque pas la suite du document",
     "```\n| **P42.1-a** | Exemple | ⬜ | Échantillon. |\n```\n"
     "| **P42.2-b** | Vrai | ✅ | FERMÉE le 2026-01-01. |\n", [("P42.2-b", "✅")]),
]


def valider_le_decoupage():
    for quoi, texte, attendu in TEMOINS_DU_DECOUPAGE:
        vues = [(cle, etat) for _n, cle, etat, _corps in lignes_de_definition(texte)]
        if vues != attendu:
            refus(f"LE DÉCOUPAGE DU CORPUS NE SE RECONNAÎT PLUS — {quoi} : le lecteur rend {vues}, "
                  f"attendu {attendu}. Une garde qui prend un échantillon pour une définition "
                  f"compare l'histoire à un état que personne ne publie. Aucun verdict n'est rendu.")


def controle_positif(revendiquees, index, deja):
    """UN ZÉRO NE S'INTERPRÈTE PAS SEUL. Une revendication VRAIE de l'histoire est confrontée à un
    état MUTÉ : la clé passée à ⬜ dans une copie en mémoire de l'index. La VALEUR qui change est la
    colonne d'état de cette clé, et l'écart qui DOIT apparaître est celui-là et RIEN D'AUTRE — la
    différence se prend contre les écarts DÉJÀ constatés, sans quoi le contrôle se casserait le jour
    où la garde a quelque chose à dire, c'est-à-dire le seul jour qui compte. Si la mutation ne
    change rien, « aucun écart » ne veut rien dire d'autre que « rien n'est visible à cet
    instrument ».
    """
    for cle in sorted(revendiquees):
        if cle in index and index[cle][2] == FERMEE:
            mute = dict(index)
            chemin, ligne, _etat, corps = mute[cle]
            mute[cle] = (chemin, ligne, "⬜", corps)
            ouvertes, _absentes = ecarts(revendiquees, mute)
            apparu = {e[0] for e in ouvertes} - deja
            if apparu != {cle}:
                refus(f"LE CONTRÔLE POSITIF ÉCHOUE : l'état de `{cle}` muté de {FERMEE} à ⬜ fait "
                      f"apparaître {sorted(apparu) or 'aucun écart'}, attendu `{cle}` et lui seul. "
                      f"La comparaison ne voit pas ce qu'elle est censée voir ; un zéro rendu par "
                      f"cet instrument ne prouverait rien.")
            return cle
    refus("LE CONTRÔLE POSITIF EST IMPOSSIBLE : aucune revendication de fermeture ne porte sur une "
          "clé que l'index déclare fermée. Il n'y a alors rien contre quoi éprouver la comparaison, "
          "et un zéro serait indistinguable d'une cécité.")


# ─────────────────────────────────────────────────────────────────────────────────────────────
def main():
    racine = racine_designee()

    valider_la_derivation()
    valider_la_lecture()
    valider_le_decoupage()

    fait = subprocess.run(["git", "-C", racine, "rev-parse", "--is-shallow-repository"],
                          capture_output=True, text=True)
    if fait.stdout.strip() == "true":
        refus("l'historique est TRONQUÉ (clone superficiel). Cette garde compare ce qu'un commit "
              "AFFIRME à ce que l'index DÉCLARE : sur un clone `--depth 1` elle ne lirait qu'un "
              "commit et rendrait vert en étant aveugle. Le pas de CI doit poser `fetch-depth: 0`.")

    index, doublons = index_du_corpus(racine)
    if doublons:
        refus("une clé est DÉFINIE DEUX FOIS dans le corpus, et son état est donc ambigu : "
              + " ; ".join(f"`{c}` en {d1}:{l1} et {d2}:{l2}" for c, d1, l1, d2, l2 in doublons[:5]))
    if len(index) < MIN_CLES:
        refus(f"{len(index)} clé(s) définie(s) dans les documents du corpus, plancher {MIN_CLES}. "
              f"Soit l'index a déménagé sous une forme que cette lecture ne reconnaît plus, soit "
              f"elle est cassée — dans les deux cas le verdict porterait sur rien.")

    lexique, detail = lexique_de_fermeture([(e, c) for _d, _l, e, c in index.values()])
    support = sum(detail[f][1] for f in lexique)
    if not lexique or support < MIN_SUPPORT_LEXIQUE:
        refus(f"le vocabulaire de fermeture ne se dérive plus : lexique {sorted(lexique)}, soutenu "
              f"par {support} déclaration(s) datée(s), plancher {MIN_SUPPORT_LEXIQUE}. Si l'index a "
              f"cessé d'écrire « FERMÉE le <date> » dans ses cellules, cette garde doit être "
              f"réécrite sur la nouvelle convention, pas laissée verte à ne rien garder.")

    commits = histoire(racine)
    if len(commits) < MIN_COMMITS:
        refus(f"{len(commits)} commit(s) lu(s), plancher {MIN_COMMITS} : l'historique n'est pas "
              f"celui de ce dépôt, ou il n'a pas été récupéré en entier.")

    citations, revendiquees = set(), {}
    for empreinte, date, message in commits:              # du plus récent au plus ancien
        for cle in set(CLE.findall(message)):
            citations.add((empreinte, cle))
        for cle, mot, ligne in revendications(message, lexique):
            revendiquees.setdefault(cle, (empreinte, date, mot, ligne))   # la fermeture la plus récente

    if len(citations) < MIN_CITATIONS:
        refus(f"{len(citations)} couple(s) (commit, clé) lus, plancher {MIN_CITATIONS} : la règle de "
              f"citation a cessé d'être tenue, ou la lecture des clés est cassée. Une garde qui ne "
              f"voit plus les citations ne peut plus voir les fermetures.")
    if len(revendiquees) < MIN_REVENDICATIONS:
        refus(f"{len(revendiquees)} revendication(s) de fermeture lue(s) sur {len(citations)} "
              f"citations, plancher {MIN_REVENDICATIONS} : la forme par laquelle ce dépôt annonce "
              f"une fermeture a changé, et cette garde ne la reconnaît plus.")

    ouvertes, absentes = ecarts(revendiquees, index)
    temoin = controle_positif(revendiquees, index, {e[0] for e in ouvertes})

    for cle, empreinte, date, mot, ligne, (chemin, n, etat, _corps) in ouvertes:
        print(f"::error file={chemin},line={n}::`{cle}` est ANNONCÉE FERMÉE par le commit "
              f"{empreinte[:8]} du {date} (« …{mot} »), et l'index la porte encore « {etat} ». "
              f"Qui lit « ce qui est ouvert » ne voit donc pas ce qui est fait. Ligne du commit : "
              f"« {ligne[:180]} ». À FAIRE : soit la clé est bien fermée et sa colonne d'état doit "
              f"passer à {FERMEE}, avec dans sa cellule la déclaration datée que ce document emploie "
              f"(« FERMÉE le <date> ») et ce qui le prouve ; soit elle ne l'est pas — et c'est le "
              f"MESSAGE DE COMMIT qui a annoncé une fermeture qu'il n'apportait pas ; soit elle a "
              f"été RÉOUVERTE depuis — et alors le geste est celui que ce document se donne déjà "
              f"pour du travail qui reprend sous une clé fermée : la cellule RESTE {FERMEE} et NOMME "
              f"une clé NEUVE, ouverte, qui porte la reprise. ÉCRIRE LA RÉOUVERTURE DANS LA CELLULE "
              f"NE SUFFIT PAS et n'éteindra pas ce message : la comparaison ne lit que la colonne "
              f"d'état — prouvé par mutation le 2026-08-25. Cette garde ne sait pas distinguer une "
              f"réouverture d'un oubli : elle expose les trois issues et laisse trancher la relecture.")
    for cle, empreinte, date, mot, ligne in absentes:
        print(f"::error::`{cle}` est ANNONCÉE FERMÉE par le commit {empreinte[:8]} du {date} "
              f"(« …{mot} ») et AUCUNE entrée de l'index ne la porte : la clé citée est une "
              f"référence dans le vide, et le lecteur n'a aucun moyen de savoir ce qu'elle "
              f"désignait. Ligne du commit : « {ligne[:180]} ».")

    if ouvertes or absentes:
        print(f"[{ETIQUETTE}] {len(ouvertes)} clé(s) annoncée(s) fermée(s) et encore marquée(s) "
              f"ouverte(s), {len(absentes)} sans entrée dans l'index.")
        sys.exit(1)

    print(
        f"[{ETIQUETTE}] {len(commits)} commits, {len(index)} clés définies dans "
        f"{len({d for d, _l, _e, _c in index.values()})} document(s) du corpus, {len(citations)} "
        f"couples (commit, clé), {len(revendiquees)} revendications de fermeture ATTACHÉES à leur "
        f"clé — aucune ne porte sur une clé que l'index laisse ouverte, aucune sur une clé sans "
        f"entrée. Lexique DÉRIVÉ des déclarations datées de l'index : "
        f"{', '.join(f'{f}* {detail[f][0]}/{detail[f][1]}' for f in sorted(lexique))} ; rejetés "
        f"faute de pureté : "
        f"{', '.join(f'{f}* {detail[f][0]}/{detail[f][1]}' for f in sorted(detail) if f not in lexique and detail[f][1] >= SUPPORT_MIN_FAMILLE)}. "
        f"Comparaison éprouvée par MUTATION sur `{temoin}` : sa colonne d'état passée de {FERMEE} à "
        f"⬜ fait apparaître exactement un écart. Épreuves passées : "
        f"{len(TEMOINS_DE_LA_DERIVATION)} témoins de dérivation, {len(TEMOINS_DU_DECOUPAGE)} de "
        f"découpage du corpus, {len(TEMOINS_DE_LA_LECTURE)} de lecture — dont "
        f"{sum(1 for _m, a in TEMOINS_DE_LA_LECTURE if a)} qui doivent voir au moins une clé et "
        f"{sum(1 for _m, a in TEMOINS_DE_LA_LECTURE if not a)} qui ne doivent en voir aucune, tous "
        f"porteurs d'un mot que le lexique témoin POURRAIT attraper.\n"
        f"CE QUE CETTE GARDE NE TIENT PAS, ET D'ABORD LE PLUS COÛTEUX : REJOUÉE LE 2026-08-25 SUR "
        f"L'ARBRE D'AVANT CHACUN DES DEUX CORRECTIFS QUI LA FONDENT, ELLE REND ZÉRO LES DEUX FOIS "
        f"(92c1be3 → 0 écart, aaf219b → 0 écart). Elle est POSÉE sous `P8.9-f` et ne la ferme pas. "
        f"Les deux causes sont mesurées : le lexique n'admet une famille qu'après trois déclarations "
        f"datées déjà posées en cellule {FERMEE}, si bien que la PREMIÈRE fermeture écrite avec un "
        f"mot neuf est toujours manquée (CORRIG* valait 0/1 le jour de l'incident 1) ; et le "
        f"vocabulaire des commits déborde celui de l'index — « RÉGRESSION RÉPARÉE » ne se dérive "
        f"d'aucune déclaration datée. Ensuite : le vocabulaire hors déclaration datée (« close » "
        f"ferme deux clés de l'histoire et n'est pas dérivé) ; une fermeture non ATTACHÉE au groupe "
        f"de clés ; une revendication coupée par un retour à la ligne (zéro sur cet arbre) ; la "
        f"VÉRITÉ d'une fermeture annoncée ; le sens INVERSE — une clé fermée que nul commit ne "
        f"ferme, qui vaut 183 clés sur 212, ou 161 sur 190 si l'on excuse les 22 qu'aucun commit ne "
        f"cite, et n'accuserait que du bruit ; et les dépôts voisins. Le remède EN AMONT n'est pas "
        f"ici : tant que l'état vit dans une colonne séparée du texte qui le décrit, les deux "
        f"PEUVENT diverger — c'est le remède structurel nommé sous `P8.9-d`."
    )


if __name__ == "__main__":
    main()
