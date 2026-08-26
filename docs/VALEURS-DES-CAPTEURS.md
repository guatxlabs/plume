# Ce qu'un capteur émet — les valeurs, et ce qu'elles veulent dire

**État : 📐 conception.** Le contrat décrit ici est **partiellement présent dans les producteurs
livrés** et **n'est câblé nulle part** : aucune de ces déclarations n'atteint le fil ni l'écran. Ce
document dit ce qui existe, ce qui manque, et pourquoi l'écart ne se comble pas à la main. Clés de
feuille de route : `P11.19-a` (rien ne DÉCLARE ce qu'un capteur émet) et `P11.19-b` (les
déclarations Rust ne sont TENUES que hors de l'artefact livré).

---

## Le problème, tel qu'il se mesure

Un exploitant lit dans la console des valeurs abrégées — `collection-reducing`, `subsystem-absent`,
`illisible`, `@status` — qu'aucune surface n'explique. L'explication ne peut pas être écrite à la
main, et ce n'est pas une question de courage : elle serait **fausse d'emblée**.

**La clé n'est pas le champ, c'est le couple (source, champ).** Mesuré sur l'arbre du dépôt le
2026-08-26 : onze fichiers livrés de la surface d'extraction inventoriée écrivent un champ étendu du
même nom — `fields.type` — avec **cinq espaces de valeurs disjoints** : réduction de collecte,
disponibilité d'un capteur, couverture de règles, genre d'hôte, genre de fichier. Trois producteurs
Rust de plus l'écrivent hors de cette surface. Une explication indexée par le **nom** du champ serait
donc juste pour un producteur et fausse pour les dix autres.

**L'ensemble se dérive du prédicat du producteur, pas de l'alphabet de son outil.** Le capteur
d'ACL de données classe des entrées de système de fichiers avec `find -printf %y`, dont l'alphabet
compte huit lettres ; son propre prédicat de sélection n'en laisse passer que **deux**. Publier
l'alphabet de l'outil au lieu de l'ensemble du capteur, c'est promettre à l'analyste des valeurs qui
n'arriveront jamais.

**Le modèle commun ne déclare qu'un vocabulaire, et il est plus large que chaque capteur.**
`config.d/cim/cim.v1.json` déclare un `action_vocab` neutre de onze mots ; le producteur Windows de
l'agent, lui, n'écrit `fields.action` que sur quatre issues (les autres cas sont soit résolus depuis
l'enregistrement, soit **déclarés sans issue**). Le vocabulaire commun est un **sur-ensemble** : il
dit ce qu'un champ peut valoir dans le produit, jamais ce que **ce** capteur peut écrire.

---

## Ce qui existe déjà dans les producteurs livrés

Le geste n'est pas absent — il est **partiel et non dérivable**. Plusieurs capteurs livrés déclarent
déjà l'ensemble fermé d'un champ qu'ils émettent, chacun dans la forme de son langage :

| Forme | Où elle vit | Le contrôle est-il dans l'artefact **livré** ? |
|---|---|---|
| Table de mots + `debug_assert!` | producteurs Rust (agent d'endpoint, collecteurs mail et syslog) | **non** — voir ci-dessous : le contrôle est effacé par la compilation de release |
| Table `@(…)` + `-notcontains` + `throw` | collecteur Windows | **oui** — le script EST l'artefact ; une valeur inventée lève, elle ne se glisse pas dans la base |
| Bloc de commentaire « vocabulaire fermé de `<champ>` » | bibliothèque shell des capteurs | **non** — c'est de la prose : un script POSIX n'offre pas de site d'échec bon marché |

**CE DOCUMENT AFFIRMAIT LE CONTRAIRE POUR LA LIGNE RUST, ET C'ÉTAIT FAUX.** Il écrivait « une valeur
hors table fait tomber le site ». Mesuré le 2026-08-26 : les six déclarations Rust sont tenues par
`debug_assert!`, et les trois `[profile.release]` des caisses productrices ne posent pas
`debug-assertions` — `cargo build --release` efface donc ces contrôles, et c'est en `--release` que
les binaires sont bâtis. **Le producteur livré n'a aucun contrôle sur ces valeurs.** Le code le
disait déjà à sa manière (« en production le contrôle s'efface ») ; c'est le document et la garde qui
présentaient l'effacement comme une garantie. Ce n'est pas un correctif d'écriture : ce qu'un
producteur doit FAIRE d'un mot étranger en production — tomber, le remplacer par une sentinelle, ou
l'avouer dans un champ — est une décision de produit, prise dans les caisses Rust. Elle porte sa clé
ouverte : `P11.19-b`.

Ces déclarations sont **dérivées, pas listées** : la garde
[`check_a_producer_declares_the_values_it_emits.py`](../.github/scripts/check_a_producer_declares_the_values_it_emits.py)
les reconnaît à leur forme, les exige **attachées à une clé que le producteur écrit réellement** dans
le sac `fields`, et **NOMME la portée de chaque contrôle** — `livrée`, `développement`, ou refusée
quand le site d'échec ne se lit pas. Cette portée est elle-même dérivée : la garde lit le
`[profile.release]` de la caisse, si bien qu'y poser `debug-assertions = true` demain la fait
reclasser sans que personne ne réécrive un nombre. Deux cliquets, disjoints, qui ne peuvent que
descendre : la prose shell ne peut pas croître, et le nombre de contrôles qui n'atteignent pas
l'artefact livré non plus. Un producteur ajouté demain entre d'office dans sa portée.

**Elles ne s'accordent pas entre elles, et c'est délibéré.** Le même champ `fields.reason` est
déclaré par cinq fichiers livrés avec **trois cardinalités différentes** : la bibliothèque shell et
le collecteur Windows portent le vocabulaire complet ; l'agent en retire le mot qui désigne un
interrupteur d'opérateur, qu'aucune de ses sources ne porte ; les collecteurs mail et syslog n'en
gardent que les deux mots que leur lecture peut produire. Chacun a raison **pour lui**. C'est la
démonstration la plus courte que la clé doit être le couple : une explication unique de `reason`
serait fausse pour trois producteurs sur cinq.

**Et même la meilleure d'entre elles est un sur-ensemble.** La table d'issues du collecteur Windows
contient deux **sentinelles** — « pas d'issue à porter » et « issue à lire dans l'enregistrement » —
qui ne sont jamais écrites dans le sac : le champ n'est posé que pour les mots restants. Déclarer un
ensemble fermé ne suffit donc pas ; il faut déclarer **celui qui est émis**.

---

## Ce qui manque, et où exactement

1. **Rien ne relie une déclaration à sa source.** Les déclarations vivent dans les fichiers des
   producteurs ; le nom de source sous lequel leurs événements arrivent est décidé ailleurs (au
   moment de l'appel). Le couple (source, champ) n'est reconstitué nulle part.
2. **Rien ne sert ces ensembles.** La route de schéma de complétion sert déjà un objet `values` —
   c'est **exactement** la surface qu'une couverture lirait — mais ses clés sont des **noms de
   champ** (`category`, `action`, `severity`, `source`), pas des couples. Les champs étendus n'y
   figurent pas du tout, faute d'amont qui les déclare.
3. **L'inventaire des champs collectés ne parle pas de valeurs.** Il associe un champ étendu à **un**
   fichier livré qui l'émet — sa question est « plume collecte-t-il ce champ ? », pas « que peut-il
   valoir ? ». Sur les onze producteurs de `fields.type`, il n'en cite qu'un : c'est correct pour son
   usage, et inutilisable pour celui-ci.
4. **La console ne peut pas distinguer ce qu'un capteur a vu de ce que l'ingestion a estampillé.**
   Le démon pose lui-même une clé de version de contrat dans le sac de **chaque** événement, et les
   voies de réception en posent d'autres (métadonnées d'enveloppe de protocole). À l'écran, elles
   s'affichent au même rang qu'une observation de capteur. Le mécanisme voisin qui écarte certaines
   clés d'une liste de facettes est une **liste littérale** : y ajouter le marqueur suivant à la main
   est précisément le geste à ne pas faire.

---

## La forme visée

* **Le capteur déclare**, dans son propre fichier, à côté du site d'émission : pour chaque champ
  qu'il écrit, l'ensemble **fermé** des valeurs qu'il peut prendre **et le sens de chacune**. Cet
  ensemble se dérive du prédicat du capteur, jamais de l'alphabet de l'outil employé.
* **La déclaration est tenue DANS L'ARTEFACT LIVRÉ** : une valeur hors ensemble ne se glisse pas dans
  la base, et le contrôle qui l'en empêche est celui que le binaire de production exécute — pas
  celui qu'une compilation de développement seule aurait gardé. C'est l'écart mesuré aujourd'hui,
  porté par `P11.19-b`.
* **Le démon la sert** à côté du vocabulaire existant, **indexée par le couple (source, champ)** —
  la même surface que `values`, un cran plus précis. Il y déclare aussi, distinctement, les clés
  qu'il **estampille lui-même**, dérivées des sites d'écriture de l'ingestion et non d'une liste.
* **La console porte l'explication en un seul endroit** : la boîte de valeur que la fabrique de
  cellules pose déjà sur chaque cellule. Là où la déclaration manque, l'écran **le dit** — un blanc
  se lirait comme une valeur évidente.

Tant que ce chemin n'existe pas, **aucune explication de valeur n'est écrite** dans la console : une
explication devinée est pire qu'une absence, parce qu'elle fait cesser de chercher.
