# Règles pour tout agent ou contributeur travaillant sur ce dépôt

Ce dépôt est **public**. Ce fichier existe parce que les règles ci-dessous ont déjà été
enfreintes, et que la mémoire d'une session ne survit ni à un changement d'agent, ni à une
perte de contexte. Ce qui suit est donc **appliqué par des gardes**, pas seulement écrit.

## 1. Identité — `guatxlabs <noreply@guatx.com>`, sans exception

La configuration git **globale** d'une station peut valoir autre chose ; tout clone frais en
hérite. Poser l'identité **localement**, dans chaque clone :

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks     # arme les gardes
```

`.githooks/pre-commit` refuse un commit dont l'auteur n'est pas celui-là.

**AUCUN TRAILER `Co-Authored-By`.** GitHub ne construit pas la page Contributors a partir du
seul auteur : il compte aussi ces trailers sur la branche par defaut, et il apparie par
ADRESSE. Un seul trailer suffit a faire figurer un compte de plus comme contributeur du
projet. Ce depot n'affiche qu'une identite, celle qui engage sa responsabilite sur le code.
Le verificateur refuse le trailer, et il lit le FICHIER du message et non le corps nettoye —
ce corps retire deja ces lignes, donc une garde qui le lirait ne pourrait jamais rien
trouver et rendrait vert en etant aveugle.

## 2. Écrire pour le lecteur du code — jamais pour une personne

Un message de commit dit **ce qui change et pourquoi**. Il ne raconte pas le déroulement du
travail. Sont **refusés** par `.githooks/commit-msg` et par la CI :

| Famille | Exemple refusé |
|---|---|
| récit à la première personne | « j'ai corrigé », « je pensais que » |
| possessif renvoyant à l'auteur | « ma faute », « mon correctif », « mes deux verdicts » |
| repère de session | « hier », « à ce jour » au sens temporel, « 4e fois de la session » |
| adressé à une personne, ou citant un échange | « demandé par X », « X m'a dit » |
| chemin machine | `/home/<compte>` |
| compte personnel, adresse hors `@guatx.com` | — |

**Ce qui a de la valeur et doit rester** : la mesure (un chiffre **avec sa date**), ce qui a
été **réfuté**, et la **raison** d'un choix de conception. Le journal de travail — qui a
essayé quoi, dans quel ordre, en combien de tentatives — appartient à un dépôt interne.

Même règle pour la **documentation** et les **commentaires de code** : ils s'adressent au
lecteur, pas à un interlocuteur.

## 3. Comment la règle est tenue

```
.github/scripts/verifier-message-de-commit.sh   la règle, écrite UNE fois
.githooks/commit-msg                            boucle de retour locale (contournable)
.github/workflows/message-public.yml            application qui LIE, sur la plage poussée
```

Le hook **délègue** au script de la CI : une règle écrite deux fois finit par diverger. Le
hook se contourne (`--no-verify`) et se perd à chaque clone ; la CI, non. Pour vérifier un
message avant de committer :

```sh
git log -1 --format=%B > /tmp/m && ./.github/scripts/verifier-message-de-commit.sh /tmp/m
```

## 4. Ce qui ne se publie pas

Ce depot est public, et deux categories de contenu n'y ont pas leur place. Aucune garde
mecanique ne les attrape : elles tiennent a la relecture, et c'est pourquoi elles sont
ecrites ici.

**LES CHIFFRES D'EXPLOITATION D'UN DEPLOIEMENT REEL.** Taille de base, nombre d'evenements,
occupation disque ou memoire observee, duree mesuree sur une machine donnee, date de mesure,
nom d'hote, adresse IP, nom de conteneur ou de namespace. Un chiffre de conception se publie
(le budget memoire de 2 Gio est une contrainte du projet) ; un chiffre releve sur une
installation ne se publie pas. Il renseigne un attaquant sur une cible et n'apprend rien a
un lecteur du code.

**LE JOURNAL DE TRAVAIL.** docs/ROADMAP.md, dans ce depot, est un INDEX PUBLIC : une ligne
par cle, son etat, ce qu'un lecteur a besoin de savoir, et les limites connues nommees
franchement. Ce n'est pas un journal de campagne. Le journal detaille — hypotheses refutees,
mesures d'exploitation, deroulement du travail — vit sur le depot interne, branche
journal-interne-avant-sommaire, et n'est jamais pousse ici.

POURQUOI L'INDEX SURVIT ALORS QUE LE JOURNAL PART : les messages de commit de ce depot
CITENT des cles de roadmap. Une cle citee dont l'index public ne contiendrait pas l'entree
serait une reference dans le vide. Le test daemon/src/tests/cles_de_roadmap_uniques.rs lit
ce fichier et refuse une cle en double ; il suppose des lignes de tableau Markdown
commencant par une barre verticale. Changer la forme du document casse cette garde.

## 5. Ce que la garde ne fait pas

Elle ne juge que des familles **objectives**. Elle ne peut pas décider si une phrase
« s'adresse au public » : une garde qui prétendrait le faire produirait du bruit et
finirait désarmée. Cette part-là tient à la relecture — et la règle écrite ci-dessus est ce
qui la rend possible.
