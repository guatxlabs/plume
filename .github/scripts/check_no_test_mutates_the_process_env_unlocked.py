#!/usr/bin/env python3
"""Aucun test ne MUTE l'environnement du processus sans prendre LE verrou d'environnement (`P11.18-w`).

LA POPULATION EST CELLE DES CAISSES QUI TOURNENT, PAS UNE CAISSE ÉCRITE À LA MAIN (`P8.9-m`)
---------------------------------------------------------------------------------------------
Cette garde a lu `daemon/src` et rien d'autre pendant que QUATRE caisses compilent et font tourner
une suite en intégration continue (`daemon`, `agent`, `collector-mail`, `collector-syslog`). Le
chemin était écrit en dur ; les trois autres n'étaient regardées par personne. Les caisses sont
désormais DÉCOUVERTES : un répertoire de premier niveau qui porte un `Cargo.toml` avec `[package]`
et un `src/`. C'est la même dérivation que le pas `cargo-deny` de `ci.yml`, et pour la même raison :
couvrir une caisse neuve ne doit demander AUCUNE édition ici. Découverte sur le SYSTÈME DE FICHIERS
et non `git ls-files`, comme le corpus `.rs` juste en dessous et pour la même raison (`P11.13-d`).

CE QUE LA DÉRIVATION A TROUVÉ, MESURÉ LE 2026-08-30 — et ce n'est pas ce qu'on croyait :
  · `agent`            : 166 `#[test]`, ZÉRO mutation d'environnement. Rien à tenir.
  · `collector-syslog` :  49 `#[test]`, UN test mutateur, aucun verrou dans la caisse.
  · `collector-mail`   :   5 `#[test]`, UN test mutateur (par `executer()`, qui pose SIX variables
                           puis lance `crate::run()`), aucun verrou dans la caisse.
  · `daemon`           : 1759 `#[test]`, 72 mutateurs, tous sous `VERROU_ENV_PROCESSUS.write()`.
Les « onze violations » qu'on croyait voir dans les caisses jumelles sont ONZE SITES `set_var` —
DEUX tests, un par collecteur. L'unité de la propriété est le test, pas l'appel.

UN TROU DE FRONTIÈRE, TROUVÉ PAR LA MÊME DÉRIVATION ET FERMÉ ICI. Un fichier peut être test-only
par son attribut INTERNE `#![cfg(test)]` en tête, sans que son `mod` porte `#[cfg(test)]`. La
frontière ne lisait que la seconde forme : `collector-mail/src/garde_lisibilite.rs` (six mutations)
et `agent/src/source/garde_lisibilite.rs` étaient donc, ENTIÈREMENT, hors du regard — un faux
NÉGATIF silencieux. `daemon` n'en porte aucun aujourd'hui : ce trou ne changeait pas son verdict,
il attendait le premier fichier de cette forme. Les deux formes sont maintenant lues.

ET POURQUOI CETTE GARDE N'ACCUSE PAS CES DEUX TESTS — DIT PLUTÔT QUE TU (`P8.9-m`)
----------------------------------------------------------------------------------
Le verrou `VERROU_ENV_PROCESSUS` vit dans `daemon/src/tests/common.rs`. Il n'existe pas dans les
caisses collectrices, et une caisse ne peut pas tenir le verrou d'une autre : exiger son nom là-bas
serait exiger un geste IMPOSSIBLE, c'est-à-dire une rançon — une CI rouge que la remédiation
nommée ne peut pas refermer.

La propriété, écrite honnêtement, n'est pas « tenir CE verrou-là » : c'est « les tests d'une caisse
qui mutent l'environnement sont sérialisés ENTRE EUX par L'UNIQUE verrou de leur caisse ». Elle est
donc dérivée par caisse, et elle ne MORD qu'à partir de DEUX tests mutateurs — en dessous, il n'y a
personne avec qui se disputer la ressource, et l'exiger n'achèterait rien. Le seuil n'est pas une
tolérance : c'est l'arité à laquelle la propriété cesse d'être vide. Il fait de cette garde un
CLIQUET QUI S'ARME TOUT SEUL : le jour où quelqu'un ajoute un SECOND test mutateur à
`collector-mail` ou `collector-syslog`, la garde rougit, et le geste — poser UN verrou dans cette
caisse — est possible, local, et le bon.

Un mutateur solitaire n'est pas passé sous silence pour autant : il est NOMMÉ à chaque exécution,
avec le seuil, pour que « rien à signaler » ne se confonde jamais avec « pas encore deux ».

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`cfg()` (daemon/src/main.rs) résout toute clé dans l'ordre `env > conf > défaut`. Un test qui écrit
`std::env::set_var("PLUME_COLD_TIER", "1")` ne règle donc pas SON tier froid : il règle celui de tous
les tests qui tournent au même instant dans le même processus, y compris ceux qui croyaient contrôler
cette clé par leur propre `conf` — puisque l'environnement passe DEVANT la conf.

Ce n'est pas une hypothèse. Mesuré le 2026-08-25 sur cet arbre : le test froid
`search_declares_what_it_did_not_search_only_when_cold_history_exists` a échoué une fois sur deux
exécutions complètes de la suite froide, sur l'assertion « tier froid OFF -> aucune note, aucun coût ».
Sa `conf` portait bien `PLUME_COLD_TIER=0` ; un test de plafonds voisin posait `PLUME_COLD_TIER=1` dans
l'environnement. Le message accusait le tier d'être éteint alors qu'il était allumé — c'est-à-dire qu'une
intégration continue rouge ne se distinguait plus d'une régression réelle.

LA CAUSE N'ÉTAIT PAS L'ABSENCE DE VERROU : IL Y EN AVAIT NEUF
------------------------------------------------------------
Relevé du 2026-08-25, par la dérivation ci-dessous : 72 tests du démon mutent l'environnement. Ils se
répartissaient entre NEUF verrous distincts — un par « famille » de variables — et douze n'en prenaient
aucun. DEUX VERROUS POUR UNE RESSOURCE, C'EST ZÉRO VERROU : chaque famille obtenait la sérialisation
qu'elle croyait avoir vis-à-vis d'elle-même, et aucune vis-à-vis des autres. Le compilateur ne pouvait
pas le voir : les verrous n'avaient pas le même type.

La ressource n'est pas « PLUME_COLD_TIER », ni « PLUME_ROLLUP_MULTIDIM », ni « les réglages de
sauvegarde » : c'est L'ENVIRONNEMENT, un seul objet global au processus. Il a donc UN verrou,
`VERROU_ENV_PROCESSUS` (daemon/src/tests/common.rs), lecteurs/écrivain : `.write()` pour qui MUTE,
`.read()` pour qui LIT. LE MODE FAIT PARTIE DE LA RÈGLE — muter sous `.read()` n'exclut personne, les
lecteurs étant parallèles entre eux, et cette garde exige donc le mode ÉCRITURE de tout mutateur.

LA PROPRIÉTÉ, ET POURQUOI C'EST UNE PROPRIÉTÉ ET PAS UNE LISTE
--------------------------------------------------------------
    Tout `#[test]` du démon dont le corps MUTE une variable d'environnement — directement, ou à travers
    un utilitaire écrit CÔTÉ TEST qui la mute — doit tenir `VERROU_ENV_PROCESSUS` EN ÉCRITURE.

Rien n'est énuméré : ni les noms de tests, ni les noms de fichiers, ni les clés d'environnement.
  · La POPULATION est découverte en parcourant le `src/` de CHAQUE caisse découverte (le système de
    fichiers, PAS `git ls-files` :
    une garde à corpus `git ls-files` valide un arbre où un fichier NEUF n'est pas encore suivi, puis
    rougit en CI — le dépôt s'est déjà fait mordre par là, `P11.13-d`).
  · Les MUTATEURS sont DÉRIVÉS des sources en DEUX temps. (a) Toute fonction côté test dont le corps
    écrit `env::set_var` / `env::remove_var` — fonctions LIBRES comme fonctions ASSOCIÉES d'un `impl`.
    C'est ce terme-là qui fait apparaître `cold_env_on` (par lequel quatre tests de plafonds posent
    `PLUME_COLD_TIER` sans jamais écrire `set_var`) et `ReglageBackupPose::neuf` (une fonction associée,
    donc invisible à un parseur qui ne lirait que les fonctions libres) : chercher `set_var` dans les
    corps de `#[test]` les aurait tous laissés passer. (b) La FERMETURE sur les appels : une fonction
    qui appelle un mutateur en est un. Elle n'ajoute AUCUN nom sur l'arbre d'aujourd'hui — la chaîne
    d'appels y est courte — et c'est un témoin synthétique, pas l'arbre, qui la valide ; sans quoi
    « elle n'a rien ajouté » et « elle est cassée » se liraient pareil.
  · Les PORTEURS du verrou EN ÉCRITURE sont dérivés de la même façon : un test qui prend le verrou à
    travers `p4a_lock_env_mute()` ou `rba_env_lock()` le prend bel et bien.

CÔTÉ TEST vs CÔTÉ PRODUCTION — LA FRONTIÈRE EST DÉRIVÉE, PAS DÉCRÉTÉE
---------------------------------------------------------------------
Le code de PRODUCTION mute lui aussi l'environnement (`sqlite_plafond.rs` pose `SQLITE_TMPDIR` en
ouvrant la base) : c'est le comportement du produit, pas le levier d'un test, et l'exiger sous verrou
sérialiserait toute la suite pour rien. La frontière est donc lue dans les sources : est « côté test »
tout fichier atteint par un `mod` déclaré `#[cfg(test)]` (et les fichiers qu'il `include!`), plus tout
bloc `#[cfg(test)] mod … { … }` écrit dans un fichier de production. Un fichier de test créé demain
entre par construction ; aucun nom n'est écrit ici.

LE DÉPOUILLEUR RUST TIRE SA GRAMMAIRE DU LECTEUR DU DÉPÔT (`P10.20-h`, mesuré le 2026-09-16)
---------------------------------------------------------------------------------------------
Cette garde portait DEUX lecteurs de commentaires Rust. Le premier, `sans_commentaire(ligne)`, coupait
une ligne au premier `//` — sans notion de chaîne, donc une adresse `"https://…"` aurait coupé la
ligne. MESURE, ET ELLE RÉFUTE LE CONSTAT QUI OUVRAIT CETTE CLÉ : il n'était appelé que par `appelle()`,
sur des corps DÉJÀ DÉPOUILLÉS — sur les 145 212 lignes de corps des 4 caisses, ZÉRO portait encore un
`//`. C'était un geste MORT, pas un défaut mordant ; il est supprimé, et `appelle()` dit désormais que
son entrée est du texte dépouillé.

Le second, `depouiller_rust`, est le vrai lecteur de cette garde, et le constat ne le nommait pas. Il
est complet (chaînes, chaînes brutes, littéraux de caractère, commentaires de bloc imbriqués) mais il
était une QUATRIÈME grammaire Rust écrite à la main sous `.github/scripts/`. Sa GRAMMAIRE est
désormais celle du lecteur du dépôt — `saute_chaine`, `saute_chaine_brute_rust`, `_prefixe_brut_rust`,
`RE_CARACTERE_RUST`, importés de `check_every_help_trigger_has_a_section` —, éprouvée par `P10.20-c`,
`P10.20-d` et `P10.20-e`, et son JOURNAL est branché : une chaîne jamais refermée fait REFUSER DE
CONCLURE (code 2) en nommant la ligne, au lieu d'avaler la fin du fichier en silence. Mesuré le
2026-09-16 sur l'arbre du dépôt, les 366 fichiers `src/` des 4 caisses (207 371 lignes) : 830 lignes étaient lues autrement par
l'ancienne grammaire — 587 où elle EFFAÇAIT l'apostrophe d'une durée de vie (`&'static str`) et 243 où
elle effaçait le préfixe `b` d'une chaîne d'octets. AUCUNE ne déplaçait ce que la garde cherche (ni
mutation, ni verrou, ni accolade, ni en-tête) : le ralliement est INERTE sur cet arbre.

ET IL FAUT LE DIRE DANS L'AUTRE SENS, PARCE QUE LA MESURE L'IMPOSE : l'ancienne grammaire n'était PAS
la famille de défaut de `P10.20-c`/`-d`/`-e`. Sur les DIX-NEUF témoins fabriqués ci-dessous, elle en
passe DIX-SEPT — littéral `'"'`, chaîne brute à guillemet nu, commentaire de bloc imbriqué, chaîne
multiligne, accolade de gabarit : elle les tenait déjà. DEUX seulement la tuent, et ce sont les deux
vrais acquis mesurables : l'apostrophe d'une durée de vie RENDUE plutôt qu'effacée, et l'AVEU — elle
n'en avait aucun, donc une chaîne jamais refermée lui faisait blanchir la fin du fichier EN SILENCE.
Les dix-sept autres sont des témoins de NON-RÉGRESSION, et ils le disent : ce lot rallie une grammaire
à sa source unique, il ne répare pas un lecteur cassé, et prétendre l'inverse serait la faute que ce
dépôt poursuit. Le troisième acquis n'est pas témoignable ici : une correction faite demain dans le
lecteur partagé arrive désormais dans cette garde sans que personne ait à y penser.

CE QUI RESTE LOCAL, ET POURQUOI — LE CONTRAT N'EST PAS CELUI DU LECTEUR PARTAGÉ. `sans_commentaires_rust`
rend les littéraux TELS QUELS ; cette garde ne le peut pas. Elle compte les accolades pour borner le
corps de chaque fonction, et une accolade écrite dans un gabarit (`format!("… {} …")`) déplacerait la
fin de chaque corps ; un `set_var(` ou un `VERROU_ENV.write()` cité dans un message d'assertion
compterait pour du code. Le contenu des littéraux est donc BLANCHI — hauteur ET longueur conservées.
C'est l'équivalent Rust de `aveugler_litteraux_js`, que le module partagé n'expose pas ; ce qui est
partagé est la GRAMMAIRE (où commence et où finit un littéral), c'est-à-dire exactement ce que la
famille de défauts `P10.20-c`/`-d`/`-e` a corrigé. UNE SEULE DIVERGENCE SUBSISTE, ASSUMÉE ET DITE : les
commentaires de BLOC sont lus IMBRIQUÉS ici (`/* a /* b */ c */`), comme Rust les définit, alors que le
lecteur partagé s'arrête au premier `*/`. Aucun commentaire de bloc imbriqué sur les 366 fichiers
(mesuré à zéro le 2026-09-16) ; la divergence est donc latente des deux côtés.

LA FRONTIÈRE CÔTÉ TEST EST NOURRIE D'UN TEXTE SANS COMMENTAIRES, corrigée par CONSTRUCTION : un
`#![cfg(test)]` ou un `#[cfg(test)] mod … {` écrit dans un commentaire de BLOC faisait basculer un
fichier de PRODUCTION entier du côté test, et les mutations d'environnement du produit devenaient des
infractions de test — une accusation FABRIQUÉE. Mesuré le 2026-09-16 : aucun fichier de l'arbre ne
change de côté ni de plage, inerte ici, pas ailleurs.

DEUX CONTRATS, UNE GRAMMAIRE — ET LA DIFFÉRENCE PORTE. La frontière lit `sans_commentaires_rust` (les
littéraux RENDUS TELS QUELS) et non `depouiller_rust` (les littéraux BLANCHIS), parce que
`include!("common.rs")` nomme son fichier par une CHAÎNE. Ce lot a commencé par lui donner le texte
blanchi : le côté test du démon est tombé de 159 fichiers à 3, et c'est le PLANCHER de cette garde —
pas une relecture — qui l'a dit, en REFUSANT DE CONCLURE plutôt qu'en acquittant 82 tests devenus
invisibles. Un témoin fige désormais les deux sens, pour ne plus dépendre du plancher.

CE QUE CETTE GARDE NE PROUVE PAS
--------------------------------
1. Elle tient le côté MUTATEUR. Le côté LECTEUR — « ce test dépend de l'environnement, il doit prendre
   `.read()` » — n'est pas une propriété syntaxique : tout appel à `cfg()` lit l'environnement. Cette
   part-là tient à la relecture, et aux gardes de famille qui existent déjà (celle des sauvegardes,
   `aucune_sauvegarde_de_test_ne_lit_les_reglages_sans_le_verrou`, DÉDUIT qui déclenche une sauvegarde).
2. Elle voit qu'un verrou est PRIS, pas qu'il est TENU ASSEZ LONGTEMPS. Un test qui prendrait le verrou
   puis le relâcherait avant de muter passerait. Le patron du dépôt — `let _env = …write();` en tête de
   corps — rend ce cas visible à la relecture.
3. Elle ne suit pas une indirection à travers un pointeur de fonction, une macro ou un trait objet.
   L'appel doit être écrit avec le nom (`nom(` ou `Type::nom(`). Une indirection plus profonde est
   INVISIBLE — donc elle produit un faux NÉGATIF, jamais une accusation à tort.
4. Le corps des MACROS, les apostrophes d'ATTRIBUT et le code GÉNÉRÉ restent hors de la grammaire du
   dépouilleur (dit en tête de `sans_commentaires_rust`). Et un commentaire de bloc JAMAIS refermé
   blanchit la fin du fichier sans aveu : il n'invente aucune accusation, il en perd — dit, pas tu.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Témoin POSITIF (un corps synthétique qui mute sans verrou doit être accusé), témoin NÉGATIF (le même
corps avec le verrou doit être acquitté, et un corps qui ne mute rien aussi), témoin de MODE (un corps
qui mute sous `.read()` ne doit PAS être acquitté), témoin de la FERMETURE dans les deux sens, témoin du
corps d'UNE SEULE LIGNE (`fn nom(&self) -> &str { "x" }` : la lecture doit s'arrêter là, sinon l'unité
avale la suite du fichier — mesuré le 2026-08-25, cette faute-là faisait entrer trois méthodes d'un
double de test à la fois dans les mutateurs et dans les porteurs), CONTRÔLE POSITIF sur l'arbre réel (la
dérivation doit retrouver `cold_env_on` ET `ReglageBackupPose::neuf` — une fonction libre et une fonction
associée ; sans elles, elle ne voit plus les mutations indirectes et son « aucune infraction » ne dit
rien), et PLANCHERS de non-dégénérescence. Sous un plancher, la garde REFUSE DE CONCLURE (sortie 2) au
lieu de rendre vert en étant aveugle.

Usage :  python3 .github/scripts/check_no_test_mutates_the_process_env_unlocked.py [--repo CHEMIN]
Sortie :  0 = sain ; 1 = violation (chaque test nommé) ; 2 = la garde refuse de conclure.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# LA GRAMMAIRE RUST DU DÉPÔT, SOURCE UNIQUE (`P10.20-h`). Les quatre premiers noms DÉFINISSENT où
# commence et où finit un littéral ; ils sont importés — et non recopiés — parce que c'est précisément
# la recopie qui a fait vivre quatre grammaires divergentes sous `.github/scripts/` (`P10.20-c` à `-e`).
# Le soulignement de tête dit « détail du lecteur », pas « privé au module » : il n'y a pas d'autre
# façon d'avoir UNE grammaire sans la réécrire.
from check_every_help_trigger_has_a_section import (  # noqa: E402
    RE_CARACTERE_RUST, _blanc, _prefixe_brut_rust, refuser_sur_aveu, saute_chaine,
    saute_chaine_brute_rust, sans_commentaires_rust, temoins_du_lecteur)

ETIQUETTE = "verrou-env-processus"

# LA CAISSE DE RÉFÉRENCE : la seule dont on sache, par mesure, ce que la dérivation DOIT y trouver.
# Elle n'est pas la portée de la garde (la portée est découverte) — elle est son CONTRÔLE POSITIF :
# si la lecture s'y dégrade, la garde refuse de conclure au lieu de verdir partout en étant aveugle.
CAISSE_DE_REFERENCE = "daemon"
VERROU_DE_REFERENCE = "VERROU_ENV_PROCESSUS"

# LE VERROU D'ENVIRONNEMENT D'UNE CAISSE, DÉRIVÉ : un identifiant en majuscules qui contient `ENV`
# et sur lequel du code de test appelle `.write()`. C'est la forme du patron du dépôt
# (`let _env = VERROU_ENV_PROCESSUS.write();`). Il n'est écrit ici AUCUN nom de verrou en dur : la
# caisse qui en pose un demain est couverte, et une caisse qui en pose DEUX est accusée — « deux
# verrous pour une ressource, c'est zéro verrou » est précisément le défaut mesuré le 2026-08-25.
PRISE_EN_ECRITURE = re.compile(r"\b([A-Z][A-Z0-9_]*)\s*\.\s*write\s*\(")

# L'ARITÉ À LAQUELLE LA PROPRIÉTÉ CESSE D'ÊTRE VIDE. Un test mutateur SEUL dans sa caisse n'a
# personne à exclure : le sérialiser n'achète rien, et l'exiger dans une caisse SANS verrou serait
# exiger un geste impossible. À DEUX, la course existe, et le verrou devient la seule réponse.
ARITE_OU_LA_PROPRIETE_MORD = 2

# La MUTATION, telle qu'elle s'écrit : `std::env::set_var(…)`, `env::remove_var(…)`, ou l'un des deux
# importé. Le `(` est exigé : une mention en prose ou en identifiant plus long ne mute rien.
MUTATION = re.compile(r"(?<![\w:])(?:(?:std\s*::\s*)?env\s*::\s*)?(set_var|remove_var)\s*\(")
# En-tête de fonction, à N'IMPORTE QUELLE indentation (les fonctions associées d'un `impl` vivent plus
# profond que les fonctions libres, et ce sont précisément elles que le défaut a utilisées pour passer).
EN_TETE_FN = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)")
EN_TETE_IMPL = re.compile(r"^(\s*)(?:unsafe\s+)?impl(?:\s*<[^>]*>)?\s+(.+?)\s*\{\s*$")
MOD_FICHIER = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;")
INCLUDE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')


def appelle(corps: str, nom: str) -> bool:
    """APPEL de `nom`, pas simple occurrence : le caractère qui précède ne doit pas être un caractère de
    nom (sinon `domain(` compterait pour un appel à `main`).

    SON ENTRÉE EST DU TEXTE DÉJÀ DÉPOUILLÉ — c'est le contrat, et c'est une MESURE, pas un vœu : tous
    les corps que cette garde lui passe sortent de `depouiller_rust`. Elle a longtemps recoupé chaque
    ligne à son premier `//` par précaution ; sur l'arbre, dans les 145 212 lignes de corps des quatre caisses, ZÉRO
    en portait encore un (`P10.20-h`, 2026-09-16). Ce geste mort est retiré plutôt qu'entretenu : un
    second lecteur qui ne lit jamais rien finit par diverger du premier sans que personne le voie."""
    motif = nom + "("
    for ligne in corps.splitlines():
        l = ligne
        i = 0
        while True:
            i = l.find(motif, i)
            if i < 0:
                break
            avant = l[i - 1] if i else ""
            if not (avant.isalnum() or avant == "_"):
                return True
            i += 1
    return False


class Unite:
    """Une fonction : son nom nu, son nom QUALIFIÉ (`Type::nom` dans un `impl`), s'il porte `#[test]`,
    son corps, et où il commence."""

    __slots__ = ("fichier", "ligne", "nom", "qualifie", "test", "corps")

    def __init__(self, fichier, ligne, nom, qualifie, test, corps):
        self.fichier, self.ligne, self.nom, self.qualifie = fichier, ligne, nom, qualifie
        self.test, self.corps = test, corps

    def __repr__(self):
        return f"{self.fichier}::{self.qualifie or self.nom}"


def _fin_du_bloc_rust(src: str, depart: int) -> int:
    """Index APRÈS le `*/` qui referme le commentaire de bloc ouvert en `depart` — IMBRICATION COMPRISE,
    comme Rust la définit. C'est la SEULE divergence assumée avec le lecteur partagé, qui s'arrête au
    premier `*/` ; aucun commentaire de bloc imbriqué sur les 366 fichiers des quatre caisses (mesuré à
    zéro le 2026-09-16), la divergence est latente des deux côtés. Un bloc jamais refermé blanchit la
    fin du fichier : il fait PERDRE des sites, il n'en invente aucun."""
    prof, j, n = 0, depart, len(src)
    while j < n:
        if src.startswith("/*", j):
            prof += 1
            j += 2
            continue
        if src.startswith("*/", j):
            prof -= 1
            j += 2
            if prof <= 0:
                return j
            continue
        j += 1
    return n


def depouiller_rust(src: str, journal=None) -> str:
    """Le texte à LIRE : commentaires (ligne et bloc, imbriqués) et littéraux (chaînes, chaînes brutes,
    chaînes d'octets, caractères) remplacés par des espaces, hauteur ET longueur CONSERVÉES. Sans cela,
    une accolade écrite dans un gabarit (`format!("… {} …")`) déplacerait la fin de chaque corps de
    fonction, et un mot cité dans un message d'assertion compterait pour du code.

    LA GRAMMAIRE EST CELLE DU DÉPÔT (`P10.20-h`, 2026-09-16) : où commence et où finit un littéral est
    décidé par `saute_chaine`, `saute_chaine_brute_rust`, `_prefixe_brut_rust` et `RE_CARACTERE_RUST`,
    importés du lecteur partagé et éprouvés par `P10.20-c`, `P10.20-d` et `P10.20-e`. Ce qui reste
    local est le CONTRAT — blanchir au lieu de rendre tel quel —, parce que cette garde compte les
    accolades. Une apostrophe qui n'ouvre pas un littéral de caractère (`'static`, `'a`, `'outer:`)
    reste une durée de vie et RESTE DANS LE CODE ; le préfixe `b` de `b"…"` aussi.

    `journal` recueille les AVEUX du lecteur (chaîne, chaîne brute ou littéral qui atteint la fin du
    fichier sans son délimiteur fermant). Le passer est ce qui distingue un refus de conclure d'un
    compte amputé rendu en vert (`P10.20-d`)."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            f = n if j < 0 else j
            out.append(_blanc(src[i:f]))
            i = f
            continue
        if c == "/" and src.startswith("/*", i):
            f = _fin_du_bloc_rust(src, i)
            out.append(_blanc(src[i:f]))
            i = f
            continue
        if _prefixe_brut_rust(src, i):
            # `r"…"`, `r#"…"#`, `br#"…"#`, `cr#"…"#` — et ce qui n'en est pas une (`r#type`, un `r`
            # ordinaire) rend None et repart dans le code, sans rien ouvrir.
            f = saute_chaine_brute_rust(src, i, journal)
            if f is not None:
                out.append(_blanc(src[i:f]))
                i = f
                continue
        if c == '"':
            # La chaîne Rust a le droit de FRANCHIR une fin de ligne : `multiligne=True`.
            f = saute_chaine(src, i, journal, multiligne=True)
            out.append(_blanc(src[i:f]))
            i = f
            continue
        if c == "'":
            m = RE_CARACTERE_RUST.match(src, i)
            if m:
                out.append(_blanc(m.group(0)))
                i = m.end()
                continue
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def unites(chemin_relatif: str, src: str, journal=None) -> list[Unite]:
    """Dépouille PUIS découpe — le tout-venant, et ce que jouent les témoins sur du texte brut."""
    return unites_du_texte_nu(chemin_relatif, depouiller_rust(src, journal))


def unites_du_texte_nu(chemin_relatif: str, nu: str) -> list[Unite]:
    """Découpe un texte DÉJÀ DÉPOUILLÉ en fonctions. Le dépouillement est séparé pour n'avoir lieu
    qu'UNE FOIS par fichier, là où un NOM DE FICHIER existe : c'est ce qui permet à l'AVEU du lecteur
    d'être entendu plutôt que prononcé dans le vide (`P10.20-d`, `P10.20-h`). Le corps d'une fonction va de son en-tête à l'accolade qui
    REFERME celle de son corps, comptée sur le texte DÉPOUILLÉ — pas à la première ligne qui ressemble à
    une fermeture. La différence n'est pas cosmétique : un corps d'une seule ligne
    (`fn kind_name(&self) -> &'static str { "all-true" }`) faisait, avec la règle d'indentation, avaler
    tout le fichier jusqu'à la prochaine fermeture de même profondeur — et cette unité-là contenait
    alors des mutations et des prises de verrou qui ne lui appartenaient pas. Une fonction IMBRIQUÉE est
    une unité de plus, ET reste incluse dans le corps de celle qui la contient : une mutation écrite
    dans une fonction imbriquée ne peut pas échapper au test qui la porte."""
    lignes_nues = nu.split("\n")

    def fin_du_corps(i: int) -> int:
        """Numéro (exclusif) de la dernière ligne du corps ouvert sur la ligne `i`."""
        prof, vu = 0, False
        for j in range(i, len(lignes_nues)):
            for c in lignes_nues[j]:
                if c == "{":
                    prof += 1
                    vu = True
                elif c == "}":
                    prof -= 1
                    if vu and prof <= 0:
                        return j + 1
            if vu and prof <= 0:
                return j + 1
        return len(lignes_nues)

    impls: list[tuple[int, str, int]] = []   # (indentation, type, fin de bloc)
    out: list[Unite] = []
    marque_test = False
    for i, l in enumerate(lignes_nues):
        t = l.strip()
        m_impl = EN_TETE_IMPL.match(l)
        if m_impl:
            ind = len(m_impl.group(1))
            cible = m_impl.group(2)
            if " for " in cible:                       # `impl Trait for Type`
                cible = cible.split(" for ", 1)[1]
            impls.append((ind, cible.split("<")[0].strip(), fin_du_corps(i)))
        m = EN_TETE_FN.match(l)
        if m:
            ind = len(m.group(1))
            nom = m.group(2)
            porteur = next((b for (a, b, f) in reversed(impls) if a < ind and i < f), None)
            fin = fin_du_corps(i)
            # LE CORPS RETENU EST LE TEXTE DÉPOUILLÉ : une mutation citée en commentaire ne mute
            # rien, et un `VERROU_ENV_PROCESSUS` cité en commentaire ne tient aucun verrou. Juger le
            # texte brut acquitterait le second cas — c'est-à-dire rendrait vert un test NU.
            out.append(Unite(chemin_relatif, i + 1, nom, f"{porteur}::{nom}" if porteur else None,
                             marque_test, "\n".join(lignes_nues[i:fin])))
            marque_test = False
        elif t.startswith("#["):
            # `#[test]` ET `#[tokio::test]` ; `#[cfg(test)]` finit par `test)]` -> exclu.
            marque_test = marque_test or t.rstrip().endswith("test]")
        elif t and not t.startswith("//"):
            marque_test = False
    return out


def fichiers_rs(racine: Path) -> list[Path]:
    out = []
    for d, _, fs in os.walk(racine):
        for f in fs:
            if f.endswith(".rs"):
                out.append(Path(d) / f)
    return sorted(out)


def verrous_env(texte: str) -> set[str]:
    """Les verrous d'ENVIRONNEMENT pris EN ÉCRITURE dans un texte : un statique en majuscules dont le
    nom parle d'environnement. Le mode compte — `.read()` n'exclut personne et n'entre donc pas."""
    return {n for n in PRISE_EN_ECRITURE.findall(texte) if "ENV" in n}


def porte_attribut_interne_cfg_test(lignes: list[str]) -> bool:
    """`#![cfg(test)]` — l'attribut INTERNE qui rend un FICHIER entier test-only. Il ne peut être
    écrit qu'en tête de fichier (avant tout item), donc le voir en début de ligne suffit. La forme
    EXTERNE `#[cfg(test)]` (sans `!`) ne dit rien du fichier : elle qualifie l'item qui SUIT."""
    for l in lignes:
        if l.strip().replace(" ", "") == "#![cfg(test)]":
            return True
    return False


def cote_test(repo: Path, chemins: list[Path], sans_com: dict = None) -> set[Path]:
    """LA FRONTIÈRE, LUE DANS LES SOURCES, SOUS SES DEUX FORMES. Un `mod X;` précédé de
    `#[cfg(test)]` rend `X.rs` (ou `X/mod.rs`) test-only, et les fichiers qu'il `include!` avec lui.
    ET un fichier qui porte l'attribut INTERNE `#![cfg(test)]` en tête est test-only par lui-même —
    son `mod` n'a alors aucune raison d'être annoté, et il ne l'est pas. Ne lire que la première
    forme laissait DEHORS, entièrement, `collector-mail/src/garde_lisibilite.rs` (six mutations
    d'environnement) et `agent/src/source/garde_lisibilite.rs` : un faux NÉGATIF muet, mesuré le
    2026-08-30. Aucun nom n'est écrit ici.

    LE TEXTE LU EST DÉPOUILLÉ DE SES COMMENTAIRES (`P10.20-h`) : un `#![cfg(test)]` ou un
    `#[cfg(test)] mod …;` écrit dans un commentaire de BLOC faisait basculer un fichier de PRODUCTION
    entier du côté test, et ses mutations d'environnement — le comportement du produit — devenaient des
    infractions. C'est une accusation FABRIQUÉE, corrigée par construction ; inerte sur cet arbre
    (aucun fichier ne change de côté, mesuré le 2026-09-16).

    ET C'EST `sans_commentaires_rust` QU'ELLE LIT, PAS `depouiller_rust` — LA DIFFÉRENCE EST LOAD-BEARING,
    et elle a été trouvée par le PLANCHER de cette garde, pas par une relecture : `include!("common.rs")`
    nomme son fichier par une CHAÎNE, et le dépouilleur de cette garde BLANCHIT le contenu des chaînes.
    Lui donner le texte blanchi faisait tomber le côté test du démon de 159 fichiers à 3 — la garde a
    REFUSÉ DE CONCLURE au lieu d'acquitter 82 tests devenus invisibles. Les deux lecteurs partagent la
    même grammaire et avouent les mêmes pertes ; seul leur contrat diffère (rendre les littéraux tels
    quels, ou les blanchir), et chaque lecture prend celui dont elle a besoin."""
    sans_com = sans_com or {}
    test_only: set[Path] = set()
    a_voir: list[Path] = []
    for p in chemins:
        texte = sans_com.get(p)
        if texte is None:
            texte = sans_commentaires_rust(p.read_text(encoding="utf-8", errors="replace"))
        lignes = texte.split("\n")
        # SECONDE FORME : l'attribut INTERNE, lu par une fonction PURE pour être témoignable sans
        # toucher le disque.
        if porte_attribut_interne_cfg_test(lignes):
            a_voir.append(p)
        precede_cfg_test = False
        for l in lignes:
            t = l.strip()
            m = MOD_FICHIER.match(l)
            if m and precede_cfg_test:
                for cand in (p.parent / f"{m.group(1)}.rs", p.parent / m.group(1) / "mod.rs"):
                    if cand.exists():
                        a_voir.append(cand)
            if t.startswith("#["):
                precede_cfg_test = precede_cfg_test or t.replace(" ", "") == "#[cfg(test)]"
            elif t and not t.startswith("//"):
                precede_cfg_test = False
    while a_voir:
        p = a_voir.pop()
        if p in test_only:
            continue
        test_only.add(p)
        src = sans_com.get(p)
        if src is None:
            src = sans_commentaires_rust(p.read_text(encoding="utf-8", errors="replace"))
        for rel in INCLUDE.findall(src):
            cand = (p.parent / rel).resolve()
            if cand.exists():
                a_voir.append(cand)
    return test_only


def blocs_mod_test(src: str) -> list[tuple[int, int]]:
    """Les plages `#[cfg(test)] mod … { … }` écrites DANS un fichier de production : leurs fonctions
    sont, elles aussi, du code de test. SON ENTRÉE EST LE TEXTE DÉPOUILLÉ (`P10.20-h`) : une plage
    fabriquée depuis un commentaire de bloc ferait juger du code de PRODUCTION comme du code de test.
    La fonction reste PURE sur le texte qu'on lui donne — ses témoins la jouent sur les deux."""
    lignes = src.split("\n")
    plages = []
    precede = False
    for i, l in enumerate(lignes):
        t = l.strip()
        if precede and re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z0-9_]+\s*\{", l):
            ind = len(l) - len(l.lstrip())
            fermeture = " " * ind + "}"
            fin = len(lignes)
            for j in range(i + 1, len(lignes)):
                if lignes[j].rstrip() == fermeture:
                    fin = j + 1
                    break
            plages.append((i + 1, fin))
        if t.startswith("#["):
            precede = precede or t.replace(" ", "") == "#[cfg(test)]"
        elif t and not t.startswith("//"):
            precede = False
    return plages


def fermeture(depart: set[str], candidats: list[Unite], tours: int = 6) -> set[str]:
    """Ferme un ensemble de NOMS sur les unités candidates : une unité qui APPELLE un nom de l'ensemble
    entre à son tour. Les fonctions associées n'entrent que par leur nom QUALIFIÉ (`Type::nom`) — un nom
    de constructeur comme `neuf` ou `build` est trop commun pour être suivi nu."""
    vus = set(depart)
    for _ in range(tours):
        neuf = set()
        for u in candidats:
            cle = u.qualifie or u.nom
            if cle in vus or u.test:
                continue
            if any(appelle(u.corps, n) for n in vus):
                neuf.add(cle)
        if not neuf:
            break
        vus |= neuf
    return vus


def temoins():
    """L'INSTRUMENT DANS LES DEUX SENS, avant tout verdict sur l'arbre."""
    # LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR (`P10.20-d`, `P10.20-h`) : cette garde tire sa
    # grammaire Rust de lui, et une garde qui sert un lecteur non éprouvé rend un compte amputé en vert.
    temoins_du_lecteur()
    doit_accuser = [
        '    #[test]\n    fn t() {\n        std::env::set_var("PLUME_X", "1");\n    }\n',
        '    #[test]\n    fn t() {\n        env::remove_var("PLUME_X");\n    }\n',
    ]
    doit_acquitter = [
        '    #[test]\n    fn t() {\n        let _e = VERROU_ENV_TEMOIN.write();\n'
        '        std::env::set_var("PLUME_X", "1");\n    }\n',
        '    #[test]\n    fn t() {\n        let v = std::env::var("PLUME_X");\n    }\n',
        '    #[test]\n    fn t() {\n        // std::env::set_var("PLUME_X", "1");\n    }\n',
    ]
    for src in doit_accuser:
        us = unites("t.rs", src)
        assert us and MUTATION.search(us[0].corps) and not verrous_env(us[0].corps), \
            f"témoin POSITIF : un corps qui mute sans verrou n'est pas accusé — {src!r}"
    for src in doit_acquitter:
        us = unites("t.rs", src)
        assert us, f"témoin : corps illisible — {src!r}"
        mute = bool(MUTATION.search(us[0].corps))
        assert (not mute) or verrous_env(us[0].corps), \
            f"témoin NÉGATIF : un corps sain est accusé — {src!r}"
    # LE MODE : `.read()` ne suffit PAS pour muter — les lecteurs sont parallèles entre eux.
    lecteur_qui_mute = ('    #[test]\n    fn t() {\n        let _e = VERROU_ENV_TEMOIN.read();\n'
                        '        std::env::set_var("PLUME_X", "1");\n    }\n')
    us = unites("t.rs", lecteur_qui_mute)
    assert MUTATION.search(us[0].corps) and not verrous_env(us[0].corps), \
        "témoin : un test qui MUTE sous `.read()` serait acquitté — le mode n'est pas lu"
    # borne de mot : `domain(` n'est pas un appel à `main`
    assert not appelle("    let d = domain(x);", "main"), \
        "témoin : la borne de mot ne tient pas — un nom court accuserait tout"
    assert appelle("    let d = main(x);", "main"), "témoin INVERSE : un vrai appel n'est plus vu"
    # une fonction associée doit être vue, et son nom nu ne doit pas suffire
    us = unites("t.rs", "impl R {\n    fn neuf() {\n        std::env::set_var(\"A\", \"b\");\n    }\n}\n")
    assert any(u.qualifie == "R::neuf" for u in us), \
        "témoin : les fonctions associées d'un `impl` ne sont pas lues — c'est par là que le défaut passait"
    # un corps d'UNE SEULE LIGNE ne doit pas avaler ce qui suit : c'est la faute qui, mesurée le
    # 2026-08-25, faisait entrer trois méthodes d'un double de test dans la liste des mutateurs ET dans
    # celle des porteurs du verrou — le même corps, avalé, contenait les deux.
    us = unites("t.rs", 'impl R {\n    fn nom(&self) -> &str { "x" }\n}\n'
                        'fn ailleurs() {\n    std::env::set_var("A", "b");\n}\n')
    court = next(u for u in us if u.nom == "nom")
    assert "set_var" not in court.corps, \
        "témoin : un corps d'une seule ligne avale la suite du fichier — toute la lecture devient fausse"
    # LA FERMETURE : un utilitaire qui appelle un mutateur EST un mutateur. Sans ce témoin, la fermeture
    # n'est vérifiée par rien sur cet arbre (elle n'y ajoute aujourd'hui aucun nom).
    us = unites("t.rs", 'fn pose() {\n    std::env::set_var("A", "b");\n}\n'
                        'fn prepare() {\n    pose();\n}\n'
                        'fn prepare_plus() {\n    prepare();\n}\n')
    ferme = fermeture({"pose"}, us)
    assert ferme == {"pose", "prepare", "prepare_plus"}, \
        f"témoin : la fermeture ne remonte pas la chaîne d'appels — {sorted(ferme)}"
    assert fermeture({"pose"}, [u for u in us if u.nom == "prepare_plus"]) == {"pose"}, \
        "témoin INVERSE : la fermeture ajoute un nom qu'aucun corps n'appelle"

    # --- LA FRONTIÈRE, SOUS SA SECONDE FORME (`P8.9-m`) --------------------------------------------
    # Le trou mesuré le 2026-08-30 : un fichier test-only par son attribut INTERNE, dont le `mod`
    # n'est pas annoté, était ENTIÈREMENT hors du regard — six mutations d'environnement comprises.
    assert porte_attribut_interne_cfg_test(["//! doc", "", "#![cfg(test)]", "use crate::x;"]), \
        "témoin : l'attribut INTERNE `#![cfg(test)]` n'est pas lu — un fichier de test entier échappe"
    assert porte_attribut_interne_cfg_test(["#! [ cfg(test) ]"]), \
        "témoin : la forme espacée de l'attribut interne n'est pas lue"
    assert not porte_attribut_interne_cfg_test(["#[cfg(test)]", "mod tests {"]), \
        "témoin INVERSE : l'attribut EXTERNE rendrait tout un fichier de PRODUCTION test-only"
    assert not porte_attribut_interne_cfg_test(["// #![cfg(test)] (cité en prose)"]), \
        "témoin INVERSE : un attribut cité en commentaire ne rend rien test-only"

    # --- LE VERROU DE LA CAISSE, DÉRIVÉ ------------------------------------------------------------
    # Aucun nom de verrou n'est écrit dans cette garde : elle cherche la FORME du patron du dépôt.
    assert verrous_env("let _e = VERROU_ENV_PROCESSUS.write();") == {"VERROU_ENV_PROCESSUS"}, \
        "témoin : la dérivation du verrou ne voit plus le patron du dépôt"
    assert verrous_env("let _e = ENV_LOCK . write ( ) ;") == {"ENV_LOCK"}, \
        "témoin : la dérivation du verrou ne survit pas aux espaces"
    assert verrous_env("A_ENV.write(); B_ENV.write();") == {"A_ENV", "B_ENV"}, \
        "témoin : DEUX verrous concurrents ne sont pas vus comme deux — c'est le défaut de 2026-08-25"
    for muet in ("VERROU_ENV_PROCESSUS.read()",   # le mode qui n'exclut personne
                 "let x = CONF_GLOBALE.write();",  # un verrou qui n'est pas celui de l'environnement
                 "fn env_lock() { }",              # une fonction, pas un statique pris en écriture
                 "buf.write(b);"):                 # une écriture ordinaire
        assert not verrous_env(muet), \
            f"témoin NÉGATIF : `{muet}` est pris pour le verrou d'environnement d'une caisse"
    # RÉSIDU ASSUMÉ, FIGÉ ICI plutôt que découvert en CI : le nom est jugé sur la sous-chaîne `ENV`,
    # donc `MON_ENVELOPPE` en est un. Le pire cas est alors que la caisse de RÉFÉRENCE paraisse en
    # avoir deux : la garde REFUSE DE CONCLURE (sortie 2). Faux refus possible, faux vert jamais.
    assert verrous_env("MON_ENVELOPPE.write()") == {"MON_ENVELOPPE"}

    # --- L'ARITÉ À LAQUELLE LA PROPRIÉTÉ MORD ------------------------------------------------------
    # Elle vaut 2, et pas 1 : à un seul mutateur il n'y a personne à exclure. Le figer ici empêche
    # qu'un « durcissement » silencieux le passe à 1 et transforme la garde en rançon sur une caisse
    # qui n'a pas de verrou à prendre.
    assert ARITE_OU_LA_PROPRIETE_MORD == 2, \
        "témoin : l'arité a bougé — à 1 la garde exige un verrou que rien ne peut avoir posé"

    # --- LE DÉPOUILLEMENT (`P10.20-h`, 2026-09-16) -------------------------------------------------
    # Les formes sur lesquelles une grammaire Rust écrite à la main se trompe, éprouvées À TRAVERS les
    # lectures de cette garde : c'est son VERDICT qui est tenu, pas seulement le texte rendu. MESURÉ,
    # un par un, contre l'ancienne grammaire locale : SEULS (f)-apostrophe-rendue et (i)-aveu-qui-parle
    # rougissent ; les dix-sept autres sont de NON-RÉGRESSION et le disent. Ils ne sont pas pour autant
    # décoratifs — ils épinglent que le ralliement à la grammaire du dépôt n'a rien rendu aveugle.
    def mute_le_seul_corps(source):
        us = unites("t.rs", source)
        assert us, f"témoin : corps illisible — {source!r}"
        return bool(MUTATION.search(us[0].corps))

    # (a) Un littéral de caractère guillemet n'ouvre pas de chaîne : le `//` qui suit reste un
    #     commentaire, et la mutation qu'il cite ne mute rien.
    assert not mute_le_seul_corps(
        '    #[test]\n    fn t() {\n        let sep = \'"\';'
        ' // std::env::set_var("PLUME_X", "1");\n    }\n'), \
        "témoin : après le littéral de caractère `\'\"\'`, un commentaire est lu comme du code"
    # (b) SENS INVERSE, celui qui ne dit rien : une chaîne brute à guillemet nu n'avale pas la suite.
    assert mute_le_seul_corps(
        '    #[test]\n    fn t() {\n        let m = r#"un " nu"#;'
        ' std::env::set_var("PLUME_X", "1");\n    }\n'), \
        "témoin : une chaîne brute à guillemet nu avale la mutation qui la suit — cécité muette"
    # (c) Un commentaire de BLOC sur plusieurs lignes ne mute rien, et la HAUTEUR est préservée.
    bloc = ('    #[test]\n    fn t() {\n        /* provisoirement retiré :\n'
            '        std::env::set_var("PLUME_X", "1");\n        */\n    }\n')
    assert not mute_le_seul_corps(bloc), \
        "témoin : une mutation écrite dans un commentaire de BLOC est comptée comme une mutation"
    assert len(depouiller_rust(bloc).split("\n")) == len(bloc.split("\n")) \
        and len(depouiller_rust(bloc)) == len(bloc), \
        "témoin : le dépouillement ne préserve plus la hauteur ET la longueur — la découpe devient fausse"
    # (d) Un commentaire de bloc IMBRIQUÉ se referme sur SON `*/`, comme Rust le définit : le code qui
    #     suit le premier `*/` ne redevient pas du code.
    assert not mute_le_seul_corps(
        '    #[test]\n    fn t() {\n        /* a /* b */ std::env::set_var("PLUME_X", "1"); */\n    }\n'), \
        "témoin : un commentaire de bloc IMBRIQUÉ se referme trop tôt — ce qu'il cache redevient du code"
    # (e) Une chaîne qui FRANCHIT une fin de ligne : le `//` d'une adresse posée dedans ne coupe rien.
    assert mute_le_seul_corps(
        '    #[test]\n    fn t() {\n        let aide = "voir\n'
        '            https://exemple"; std::env::set_var("PLUME_X", "1");\n    }\n'), \
        "témoin : un `//` d\'URL dans une chaîne multiligne fait MANGER la fin de cette ligne"
    # (f) NON-RÉGRESSION : une durée de vie n'ouvre rien, et elle RESTE dans le code.
    vie = ('    #[test]\n    fn t() {\n        let s: &\'static str = nom();'
           ' std::env::set_var("PLUME_X", "1");\n    }\n')
    assert mute_le_seul_corps(vie), \
        "témoin de NON-RÉGRESSION : une durée de vie `\'static` ouvre un littéral"
    assert "&\'static str" in depouiller_rust(vie), \
        "témoin : l\'apostrophe d\'une durée de vie est EFFACÉE — le lecteur ne rend plus le code tel qu\'il est"
    # (g) LE CONTRAT QUI INTERDIT DE BRANCHER ICI LE LECTEUR PARTAGÉ TEL QUEL : le CONTENU des littéraux
    #     est BLANCHI. Une mutation citée dans un message d'assertion ne mute pas, un verrou cité dans
    #     une chaîne ne tient rien, et une accolade de gabarit ne déplace pas la fin du corps.
    assert not mute_le_seul_corps(
        '    #[test]\n    fn t() {\n        panic!("appelez std::env::set_var(k, v) ailleurs");\n    }\n'), \
        "témoin : une mutation citée DANS UNE CHAÎNE est comptée comme une mutation"
    assert not verrous_env(depouiller_rust('let m = "prendre VERROU_ENV_PROCESSUS.write() en tête";')), \
        "témoin : un verrou cité DANS UNE CHAÎNE est compté comme un verrou pris — un test NU passerait vert"
    us = unites("t.rs", 'fn f() {\n    let t = format!("… {} …", x);\n}\n'
                        'fn ailleurs() {\n    std::env::set_var("A", "b");\n}\n')
    assert not MUTATION.search(next(u for u in us if u.nom == "f").corps), \
        "témoin : une accolade écrite dans un gabarit déplace la fin du corps — l'unité avale la suivante"
    # (h) LA FRONTIÈRE CÔTÉ TEST NE SE FABRIQUE PAS DEPUIS UN COMMENTAIRE DE BLOC. Les deux formes,
    #     jouées sur le texte DÉPOUILLÉ (ce que la garde lit) et sur le texte BRUT (ce qu'elle lisait).
    faux_attribut = "/*\n#![cfg(test)]\n*/\nfn produit() { std::env::set_var(\"A\", \"b\"); }\n"
    assert porte_attribut_interne_cfg_test(faux_attribut.split("\n")), \
        "témoin de contrôle : le texte BRUT fait bien basculer tout le fichier — c'est le défaut"
    assert not porte_attribut_interne_cfg_test(sans_commentaires_rust(faux_attribut).split("\n")), \
        "témoin : un `#![cfg(test)]` écrit dans un commentaire de BLOC rend un fichier de PRODUCTION " \
        "test-only — toutes ses mutations deviennent des infractions FABRIQUÉES"
    faux_bloc = "/*\n#[cfg(test)]\nmod tests {\n}\n*/\nfn produit() { }\n"
    assert blocs_mod_test(faux_bloc) and not blocs_mod_test(depouiller_rust(faux_bloc)), \
        "témoin : une plage `#[cfg(test)] mod` est fabriquée depuis un commentaire de BLOC"
    # (h bis) LE NOM DE FICHIER D'UN `include!` EST UNE CHAÎNE : la frontière doit lire un texte qui la
    #     REND, pas un texte qui la blanchit. C'est le plancher de cette garde qui a attrapé l'inverse
    #     (159 fichiers côté test tombés à 3) ; le témoin le fige plutôt que d'attendre le plancher.
    inclus = '#![cfg(test)]\ninclude!("common.rs");\n// include!("fantome.rs");\n'
    assert INCLUDE.findall(sans_commentaires_rust(inclus)) == ["common.rs"], \
        "témoin : la frontière ne lit plus le nom de fichier d'un `include!` — le côté test s'effondre " \
        "en silence, ou un `include!` COMMENTÉ est suivi"
    assert INCLUDE.findall(depouiller_rust(inclus)) == [], \
        "témoin de contrôle : le dépouilleur de cette garde BLANCHIT les chaînes — c'est pourquoi la " \
        "frontière ne peut pas le lire, et ce témoin fige la raison"
    # (i) L'AVEU, DANS LES DEUX SENS : muet sur du Rust valide, parlant sur une chaîne jamais refermée.
    propre = []
    depouiller_rust('fn f() {\n  let u = "https://h/x";\n  let c = \'"\';\n  let r = r#"a " b"#;\n}\n', propre)
    assert not propre, f"témoin inverse : le lecteur avoue une perte sur du Rust valide ({propre})"
    perdu = []
    depouiller_rust('fn f() {\n  let x = "jamais refermee;\n  std::env::set_var("A", "b");\n}\n', perdu)
    assert perdu, \
        "témoin : le lecteur ne dit plus qu'il a perdu la synchronisation — il avalerait la fin du " \
        "fichier et rendrait un compte amputé en vert"
    # (j) `appelle` reçoit du texte DÉPOUILLÉ : un appel COMMENTÉ n'est pas un appel, et le geste qui
    #     le garantit est le dépouillement, plus un second lecteur par ligne (`P10.20-h`).
    us = unites("t.rs", 'fn t() {\n    // pose();\n    autre();\n}\n')
    assert not appelle(us[0].corps, "pose") and appelle(us[0].corps, "autre"), \
        "témoin : un appel CITÉ en commentaire compte pour un appel"


def refuser(msg: str) -> int:
    print(f"::error::[{ETIQUETTE}] {msg}")
    return 2


def caisses(repo: Path) -> list[str]:
    """LES CAISSES QUI TOURNENT, DÉCOUVERTES — jamais écrites. Un répertoire de premier niveau qui
    porte un `Cargo.toml` avec `[package]` et un `src/`. Même dérivation que le pas `cargo-deny` de
    `ci.yml` (`find -mindepth 2 -maxdepth 2 -name Cargo.toml`), et pour la même raison : couvrir une
    caisse neuve ne doit demander aucune édition ici. Système de fichiers, pas `git ls-files` : une
    caisse écrite et pas encore suivie est du code au même titre (`P11.13-d`)."""
    out = []
    for d in sorted(repo.iterdir()):
        if not d.is_dir() or d.name.startswith(".") or d.name == "target":
            continue
        manifeste = d / "Cargo.toml"
        if not manifeste.is_file() or not (d / "src").is_dir():
            continue
        if "[package]" not in manifeste.read_text(encoding="utf-8", errors="replace"):
            continue
        out.append(d.name)
    return out


class Bilan:
    """Ce qu'une caisse rend : de quoi juger, et de quoi AVOUER ce qui n'est pas jugé."""

    __slots__ = ("caisse", "fichiers", "cote_test", "tests", "mutateurs", "verrous", "mutants", "nus",
                 "aveux")

    def __init__(self, caisse, fichiers, cote_test, tests, mutateurs, verrous, mutants, nus, aveux):
        self.caisse, self.fichiers, self.cote_test = caisse, fichiers, cote_test
        self.tests, self.mutateurs, self.verrous = tests, mutateurs, verrous
        self.mutants, self.nus = mutants, nus
        self.aveux = aveux


def analyser_caisse(repo: Path, caisse: str) -> Bilan:
    """La MÊME dérivation qu'avant, appliquée à une caisse quelconque. Rien n'y est spécifique au
    démon : ni le nom du verrou (dérivé de la caisse), ni les noms d'utilitaires."""
    chemins = fichiers_rs(repo / caisse / "src")

    # LE DÉPOUILLEMENT A LIEU ICI, UNE FOIS PAR FICHIER, ET AVEC SON NOM : c'est ce qui permet à l'AVEU
    # du lecteur d'être entendu plutôt que prononcé dans le vide (`P10.20-d`, `P10.20-h`). Tout ce qui
    # suit — la frontière côté test, les plages `#[cfg(test)] mod`, la découpe en unités — est dérivé
    # du texte DÉPOUILLÉ, jamais du texte brut.
    # DEUX CONTRATS, UNE GRAMMAIRE : `depouiller_rust` BLANCHIT le contenu des littéraux (la découpe en
    # unités compte les accolades), `sans_commentaires_rust` les rend TELS QUELS (la frontière côté test
    # lit le nom de fichier d'un `include!("…")`, qui est une chaîne). Les deux tirent de la même source
    # la question « où commence et où finit un littéral », donc ils avouent les mêmes pertes ; le journal
    # est recueilli une fois, sur le premier.
    nus: dict = {}
    sans_com: dict = {}
    aveux: dict = {}
    for c in chemins:
        texte = c.read_text(encoding="utf-8", errors="replace")
        journal = []
        nus[c] = depouiller_rust(texte, journal)
        sans_com[c] = sans_commentaires_rust(texte)
        if journal:
            aveux[os.path.relpath(c, repo)] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                               for m, o in journal]
    test_only = cote_test(repo, chemins, sans_com)

    unites_test_side: list[Unite] = []
    tests: list[Unite] = []
    for c in chemins:
        rel = os.path.relpath(c, repo)
        nu = nus[c]
        us = unites_du_texte_nu(rel, nu)
        if c in test_only:
            unites_test_side.extend(us)
        else:
            plages = blocs_mod_test(nu)
            unites_test_side.extend(u for u in us if any(a <= u.ligne <= b for a, b in plages))
        tests.extend(u for u in us if u.test)

    directs = {(u.qualifie or u.nom) for u in unites_test_side
               if not u.test and MUTATION.search(u.corps)}
    mutateurs = fermeture(directs, unites_test_side)

    # LE VERROU DE CETTE CAISSE, DÉRIVÉ de son propre code de test. Zéro nom écrit ici.
    verrous: set[str] = set()
    for u in unites_test_side:
        verrous |= verrous_env(u.corps)

    def mute(u: Unite) -> bool:
        return bool(MUTATION.search(u.corps)) or any(appelle(u.corps, n) for n in mutateurs)

    mutants = [u for u in tests if mute(u)]

    nus_du_verrou: list[Unite] = []
    if len(verrous) == 1:
        ecriture = f"{next(iter(verrous))}.write()"
        porteurs = fermeture({u.qualifie or u.nom for u in unites_test_side
                              if not u.test and ecriture in u.corps}, unites_test_side)
        nus_du_verrou = [u for u in mutants
                         if ecriture not in u.corps and not any(appelle(u.corps, n) for n in porteurs)]
    else:
        # ZÉRO verrou : rien n'exclut personne. DEUX ou plus : « deux verrous pour une ressource,
        # c'est zéro verrou » — le défaut mesuré le 2026-08-25, avec NEUF verrous dans le démon.
        nus_du_verrou = list(mutants)

    return Bilan(caisse, len(chemins), len(test_only), tests, mutateurs, verrous, mutants, nus_du_verrou,
                 aveux)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    temoins()

    # PLANCHER DE DÉCOUVERTE. Le seul mode de panne réel d'une dérivation est de ne RIEN trouver et
    # de rendre un vert joyeux. Quatre caisses le 2026-08-30 — le même plancher, pour la même raison,
    # que le pas `cargo-deny` de `ci.yml`.
    noms = caisses(repo)
    if len(noms) < 4:
        return refuser(f"{len(noms)} caisse(s) découverte(s) sous {repo} ({noms}), plancher 4 "
                       f"(mesuré le 2026-08-30 : daemon, agent, collector-mail, collector-syslog) — "
                       f"la découverte est cassée, cette garde ne vérifierait RIEN.")
    print(f"[{ETIQUETTE}] caisses découvertes (Cargo.toml + [package] + src/) : {noms}")

    bilans = [analyser_caisse(repo, n) for n in noms]
    par_nom = {b.caisse: b for b in bilans}

    # --- L'AVEU DU LECTEUR, JUGÉ AVANT TOUT VERDICT (`P10.20-d`, `P10.20-h`) ----------------------
    # Un lecteur qui a ouvert un littéral qui n'en était pas un a AVALÉ du code : tout ce qu'il a
    # compté depuis est faux, et un compte amputé rendu en vert est pire qu'une garde absente.
    aveux = {}
    for b in bilans:
        aveux.update(b.aveux)
    if aveux:
        refuser_sur_aveu(ETIQUETTE, aveux, "Rust")
        return 2

    # --- CONTRÔLE POSITIF SUR LA CAISSE DE RÉFÉRENCE ----------------------------------------------
    # Les planchers ne sont pas des seuils de qualité : ce sont les valeurs sous lesquelles la
    # LECTURE est cassée. Ils portent sur la caisse dont on a mesuré ce qu'elle contient. Une garde
    # multi-caisses sans ce contrôle rendrait « aucune infraction » sur quatre lectures mortes.
    ref = par_nom.get(CAISSE_DE_REFERENCE)
    if ref is None:
        return refuser(f"la caisse de référence `{CAISSE_DE_REFERENCE}` n'a pas été découverte : le "
                       f"contrôle positif de cette garde n'a plus de support.")
    for valeur, plancher, quoi in ((ref.fichiers, 100, "fichier(s) .rs"),
                                   (ref.cote_test, 40, "fichier(s) côté test"),
                                   (len(ref.tests), 900, "`#[test]`"),
                                   (len(ref.mutants), 40, "test(s) mutateur(s))")):
        if valeur < plancher:
            return refuser(f"`{CAISSE_DE_REFERENCE}` : {valeur} {quoi}, plancher {plancher} "
                           f"(mesuré le 2026-08-30 : 261 fichiers, 100 côté test, 1759 `#[test]`, "
                           f"72 mutateurs) — la lecture est cassée, la garde refuse de conclure.")
    # `cold_env_on` est une fonction LIBRE (quatre tests de plafonds mutent par elle) ;
    # `ReglageBackupPose::neuf` est une fonction ASSOCIÉE (invisible à un parseur de fonctions
    # libres). Sans elles, la dérivation ne voit plus les mutations INDIRECTES.
    for controle in ("cold_env_on", "ReglageBackupPose::neuf"):
        if controle not in ref.mutateurs:
            return refuser(f"la dérivation n'a pas retrouvé `{controle}` dans "
                           f"`{CAISSE_DE_REFERENCE}` : elle ne voit plus les mutations INDIRECTES, "
                           f"et son verdict ne vaudrait rien.")
    if ref.verrous != {VERROU_DE_REFERENCE}:
        return refuser(f"le verrou d'environnement de `{CAISSE_DE_REFERENCE}` dérivé vaut "
                       f"{sorted(ref.verrous)} au lieu de {{'{VERROU_DE_REFERENCE}'}} : soit la "
                       f"dérivation du verrou est cassée, soit la caisse en a repris DEUX — et deux "
                       f"verrous pour une ressource, c'est zéro verrou. La garde refuse de conclure "
                       f"plutôt que d'acquitter ou d'accuser sur une lecture qu'elle ne comprend pas.")

    # --- LE VERDICT, CAISSE PAR CAISSE ------------------------------------------------------------
    fautifs: list[Bilan] = []
    for b in sorted(bilans, key=lambda x: x.caisse):
        print(f"[{ETIQUETTE}] {b.caisse} : {b.fichiers} fichier(s) .rs, {b.cote_test} côté test, "
              f"{len(b.tests)} `#[test]`, {len(b.mutants)} mutent l'environnement, "
              f"verrou(s) dérivé(s) {sorted(b.verrous) or 'AUCUN'}.")
        if not b.mutants:
            continue
        if len(b.mutants) < ARITE_OU_LA_PROPRIETE_MORD:
            # L'AVEU, ET IL EST NOMMÉ. « Rien à signaler » et « pas encore deux » ne doivent pas se
            # lire pareil : un mutateur solitaire est une course qui n'attend qu'un voisin.
            for u in b.mutants:
                print(f"[{ETIQUETTE}]   ↳ AVEU : `{u.nom}` ({u.fichier}:{u.ligne}) mute "
                      f"l'environnement et sa caisse ne porte aucun verrou. Sous "
                      f"{ARITE_OU_LA_PROPRIETE_MORD} tests mutateurs il n'a personne à exclure : "
                      f"la garde ne l'accuse pas, et elle ne le cache pas. Le SECOND la fera rougir, "
                      f"et le geste sera de poser UN verrou dans `{b.caisse}`.")
            continue
        if b.nus:
            fautifs.append(b)

    for b in fautifs:
        unique = f"`{next(iter(b.verrous))}.write()`" if len(b.verrous) == 1 else \
                 (f"AUCUN verrou dans `{b.caisse}`" if not b.verrous
                  else f"{len(b.verrous)} verrous concurrents {sorted(b.verrous)}")
        for u in b.nus:
            print(f"::error file={u.fichier},line={u.ligne}::le test `{u.nom}` MUTE une variable "
                  f"d'environnement du processus sans tenir le verrou UNIQUE de sa caisse "
                  f"({unique}). L'environnement est UNE ressource pour tout le binaire de test : ce "
                  f"que ce test pose, il le pose pour tous ceux qui tournent au même instant — et "
                  f"`cfg()` fait passer l'environnement DEVANT la `conf`, donc il écrase même la "
                  f"conf d'un voisin qui croyait décider seul. `{b.caisse}` porte "
                  f"{len(b.mutants)} test(s) mutateur(s) : ils se disputent la ressource. Prendre le "
                  f"verrou en tête de corps : `let _env = <VERROU>.write();`. `.read()` NE SUFFIT "
                  f"PAS pour muter : les lecteurs sont parallèles entre eux, donc la mutation "
                  f"s'appliquerait pendant qu'un voisin lit (`.read()` est le mode de qui DÉPEND de "
                  f"l'environnement sans y toucher). Ne pas ajouter un verrou de plus : deux verrous "
                  f"pour une ressource, c'est zéro verrou.")
    if fautifs:
        total = sum(len(b.nus) for b in fautifs)
        print(f"[{ETIQUETTE}] {total} test(s) mutent l'environnement sans le verrou unique de leur "
              f"caisse, dans : {[b.caisse for b in fautifs]}.")
        return 1

    total_mutants = sum(len(b.mutants) for b in bilans)
    print(f"[{ETIQUETTE}] OK — sur {len(noms)} caisses découvertes, les {total_mutants} tests qui "
          f"mutent l'environnement du processus sont, dans chaque caisse où ils sont au moins "
          f"{ARITE_OU_LA_PROPRIETE_MORD}, tous sous le verrou UNIQUE de cette caisse, dans le mode "
          f"qui exclut. Ce que cette garde NE tient PAS : le côté LECTEUR (« ce test dépend de "
          f"l'environnement »), qui n'est pas une propriété syntaxique ; la DURÉE de tenue du "
          f"verrou ; et le mutateur SOLITAIRE d'une caisse, avoué ci-dessus et pas accusé.")
    return 0



if __name__ == "__main__":
    sys.exit(main())
