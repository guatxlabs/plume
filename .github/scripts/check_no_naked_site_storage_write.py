#!/usr/bin/env python3
"""Une écriture NUE au stockage du site jette AU MILIEU d'un geste, et laisse l'interface à moitié basculée.

CE QUI A ÉTÉ MESURÉ (2026-08-30). `window.localStorage` ne rend pas `null` quand le navigateur BLOQUE le
stockage de site (Chrome « bloquer tous les cookies » sur l'origine, contextes durcis, profils
d'entreprise) : l'ACCÈS LUI-MÊME jette `SecurityError`. `P4.13-a` a gardé les LECTURES faites à
l'évaluation des modules ; les ÉCRITURES, elles, s'exécutent DANS un gestionnaire — après qu'un état a
été posé, avant que la vue ne soit repeinte. Le geste ne rend alors pas MOINS, il rend un état
INCOHÉRENT, ce qui est pire qu'un refus : l'exploitant n'a RIEN à lire pour le comprendre. Trois
exemples exercés sous le mode « stockage refusé » du banc ESM : le thème basculait sans que l'icône
suive, le fuseau se posait en mémoire sans qu'un seul horodatage soit re-rendu, et un glisser-déposer
ne réordonnait ni ne gardait quoi que ce soit.

LE CRITÈRE EST DÉRIVÉ, ET IL N'ÉNUMÈRE AUCUN FICHIER. La population, c'est TOUT `web/**/*.js` lu sur le
DISQUE — un module neuf est vu avant même d'être suivi par le dépôt, ce qui est le moment exact où on
oublie la garde (une garde sœur a été mesurée verte en local et rouge en intégration pour avoir lu
l'index). La propriété, c'est : « toute expression qui MUTE le stockage du site est enclose dans un
`try` de SA PROPRE fonction ». Deux mots comptent :
  - MUTER se déduit de DEUX listes écrites ici (les objets de stockage, les méthodes mutantes) plus la
    forme syntaxique de l'affectation et de `delete` — pas d'une liste d'appels connus ;
  - SA PROPRE FONCTION, parce qu'un `try` qui ENTOURE la *création* d'un rappel ne protège pas son
    EXÉCUTION, qui arrive bien plus tard. `try { b.onclick = () => localStorage.setItem(…) } catch {}`
    est NU, et cette garde le dit.

CE QUI EST LU N'EST PAS LE TEXTE. Un analyseur lexical écarte commentaires, chaînes, gabarits et
littéraux d'expression régulière avant toute décision : une garde sœur a été prise en défaut le
2026-08-29 sur exactement ce point (un motif ancré sur du texte brut voyait une écriture dans un
commentaire). Un `//` DANS une chaîne n'ouvre donc pas un commentaire, et une écriture citée dans un
commentaire n'est pas une écriture.

L'INSTRUMENT SE VALIDE SUR DES ENTRÉES FABRIQUÉES ICI, JAMAIS SUR L'ÉTAT DU DÉPÔT. C'est une faute
mesurée le 2026-08-29 qui l'impose : une borne exigeait qu'un module porte ENCORE le défaut « sinon le
motif ne mesure plus rien » — elle aurait rougi LE JOUR OÙ LE TRAVAIL SERAIT FINI. Un témoin qui ne
peut être vert que tant que le chantier est ouvert n'est pas une garde, c'est une rançon. Les témoins
d'ici portent donc leurs deux sens : ce qui DOIT être vu, et ce qui NE DOIT PAS l'être.

`P4.13-d` — ET LA CAPTURE ELLE-MÊME EST MAINTENANT JUGÉE. Ce qui précède ne demandait qu'une capture ;
la clôture de cette garde le disait sans détour : « une capture VIDE la satisfait, et elle échange l'état
incohérent contre une perte MUETTE ». MESURÉ le 2026-08-31 sur `web/` : DOUZE captures au corps
LITTÉRALEMENT VIDE entouraient un accès au stockage, sur SIX modules — toutes vertes. La propriété
ajoutée exige que le fait SORTE de la capture (`return` porteur d'une valeur, ou `throw`) : aucun mot
d'aveu n'est cherché dans le corps, parce qu'une liste de mots rend une garde VERTE sur le site le plus
grave dès qu'un mot trop générique y figure. S'y ajoute son jumeau, que `web/state.js` nommait par écrit
sans que rien ne le tienne : l'écrivain à VERDICT ne doit jamais être appelé en INSTRUCTION (valeur
jetée), et la porte SILENCIEUSE ne doit jamais être LUE comme une valeur (elle ne rend rien, donc le
test serait toujours faux). Les deux portes sont DÉRIVÉES du corpus — qui mute, qui rend — et aucun nom
de fonction n'est écrit ici.

`P4.13-e` — ET LE VERDICT REÇU PUIS LAISSÉ TOMBER. Ce qui précède accuse le verdict JETÉ À L'APPEL
(`f(…);` en instruction). Il ne voyait RIEN du verdict REÇU puis abandonné : `const retenu = f(k, v);`
suivi de rien. La valeur a été rendue, elle est liée, personne ne la consulte — et pour l'exploitant
c'est mot pour mot la perte MUETTE que `P4.13-b` a fermée. La propriété ajoutée est structurelle : une
liaison `const`/`let` qui reçoit un écrivain à verdict doit être RELUE dans sa portée. MESURÉ le
2026-08-31 par mutation sur les CINQ sites réels du corpus (core.js, multitenant.js ×2, dataaccess.js,
detection_admin.js) : retirer la relecture de l'un d'eux fait rougir, la remplacer par une AUTRE
relecture ne fait rien rougir.

LE SEUL PLANCHER QUI SUBSISTE PORTE SUR LES ÉCRITURES, PAS SUR LES FAUTES. Si le corpus ne contient
AUCUNE écriture au stockage, la garde REFUSE DE CONCLURE au lieu de rendre un vert par vacuité : un
analyseur cassé trouve zéro écriture, exactement comme un dépôt qui n'en contient plus.
"""
import os
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ICI)
from check_every_style_selector_has_a_target import (  # noqa: E402  (GESTES PARTAGÉS, source unique — `P11.8-m`, `P11.8-n`)
    parcours_des_sources, racine_designee)

# ── LA RACINE EXAMINÉE — GESTE PARTAGÉ, PAS UNE QUATRIÈME COPIE (`P11.8-n`) ───────────────
# LE DÉFAUT QUE CECI FERME, MESURÉ LE 2026-08-31. Cette garde ACCEPTAIT un argument — lui passer une
# racine ne provoquait aucune plainte — et elle l'AVALAIT : sa racine venait de la POSITION DE CE
# FICHIER. Pointée sur un répertoire VIDE, elle rendait un verdict VERT sur le dépôt réel, sortie
# identique OCTET POUR OCTET à celle du dépôt réel. C'est la famille exacte que `P8.27-a` a déjà
# payée : un outil qui mesure un arbre que personne ne lui a désigné et présente son verdict comme
# portant sur celui qu'on lui montrait — son rouge accuse un innocent, et son vert, plus grave parce
# que silencieux, n'atteste rien. La validation (nombre d'arguments, racine inutilisable, refus code
# 2, message) n'est donc PAS réécrite ici : c'est celle de `racine_designee()`, importée.
#
# CE QUI RESTE PROPRE À CETTE GARDE, ET C'EST TOUT : LA RACINE RETENUE QUAND ON N'EN DÉSIGNE AUCUNE.
# Sans argument, `racine_designee()` retombe sur le `git rev-parse` du RÉPERTOIRE COURANT. Adopter
# cette retombée ICI serait une PERTE DE PORTÉE, mesurée le 2026-08-31 : jouée depuis un répertoire
# courant situé HORS de tout arbre git, la garde sœur du style REFUSE (code 2) sur un arbre SAIN,
# tandis que les trois gardes ralliées ici rendaient 0 — et `jouer-la-batterie-de-gardes.sh` lance
# chaque garde SANS se placer dans le dépôt (ligne 264). La racine par défaut reste donc celle-ci,
# calculée EXACTEMENT comme avant ce correctif, et elle est DÉSIGNÉE à la fonction partagée plutôt
# que devinée par elle : ce qui pouvait diverger (la validation) est unique, ce qui reste écrit ici
# (un défaut connu valide) ne peut pas mentir sur l'arbre mesuré.
DEPOT_DE_CETTE_GARDE = os.path.realpath(os.path.join(ICI, "..", ".."))
# Renseignées par `main()` : une racine ne se devine pas à l'IMPORT (ce module est importable, et
# lire `sys.argv` à l'import ferait juger l'argument d'un AUTRE programme).
RACINE = None
CORPUS = None

# --- LE CRITÈRE, ÉCRIT ------------------------------------------------------------------------
# Les deux magasins de site de la plateforme web. Un accès à l'un ou l'autre JETTE quand le navigateur
# refuse le stockage — c'est la propriété d'accès elle-même qui lève, pas la méthode.
MAGASINS = {"localStorage", "sessionStorage"}
# Les porteurs licites devant un magasin : `window.localStorage` est le MÊME objet que `localStorage`.
PORTEURS = {"window", "globalThis", "self"}
# Ce qui MUTE le magasin. Tout le reste (`getItem`, `key`, `length`) LIT, et une lecture est déjà gardée
# ailleurs (`lireLeStockageDuSite`, web/state.js — `P4.13-a`).
METHODES_MUTANTES = {"setItem", "removeItem", "clear"}
# Le cliquet, à la valeur MESURÉE le 2026-08-30 après le correctif de `P4.13-b` : plus une seule
# écriture nue dans `web/`. Il ne se relève pas sans une décision écrite.
CLIQUET_ECRITURES_NUES = 0

# Mots-clés après lesquels un `/` ouvre un littéral d'expression régulière et non une division.
AVANT_REGEX = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
    "else", "yield", "await",
}
# Mots-clés dont la parenthèse est une PARENTHÈSE DE CONTRÔLE : le `{` qui la suit ouvre un bloc, pas
# un corps de fonction.
CONTROLE = {"if", "for", "while", "switch", "catch", "with"}
AFFECTATIONS = {
    "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=",
}
# Les opérateurs à plusieurs caractères, du plus long au plus court : un `>>>=` ne doit jamais être lu
# comme `>>` puis `>=`.
OPERATEURS = sorted(
    [">>>=", "===", "!==", "**=", "<<=", ">>=", "&&=", "||=", "??=", ">>>", "...",
     "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "=>", "++", "--", "+=", "-=", "*=", "/=", "%=",
     "&=", "|=", "^=", "**", "<<", ">>"],
    key=len, reverse=True,
)

IDENT_DEBUT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
IDENT_SUITE = IDENT_DEBUT | set("0123456789")


class Jeton:
    __slots__ = ("genre", "valeur", "ligne")

    def __init__(self, genre, valeur, ligne):
        self.genre = genre      # "nom" | "chaine" | "nombre" | "op"
        self.valeur = valeur
        self.ligne = ligne

    def __repr__(self):
        return f"{self.genre}:{self.valeur}@{self.ligne}"


class LectureImpossible(Exception):
    """L'analyseur ne sait pas lire ce texte — la garde doit REFUSER DE CONCLURE, pas conclure au vert."""


def analyser(texte):
    """Les jetons SIGNIFIANTS : commentaires, chaînes, gabarits et regex sont écartés ou opacifiés.

    Une chaîne rend un jeton `chaine` porteur de son CONTENU (il faut pouvoir lire
    `localStorage['setItem']`), mais son contenu n'est jamais re-analysé comme du code. Les
    substitutions `${…}` d'un gabarit, elles, SONT du code et sont analysées.
    """
    jetons = []
    i, n, ligne = 0, len(texte), 1
    # Pile des gabarits ouverts : chaque entrée est la profondeur d'accolades à laquelle la
    # substitution `${` a commencé, pour savoir quel `}` referme la substitution et rend au gabarit.
    pile_gabarits = []
    profondeur_accolades = 0

    def precedent():
        return jetons[-1] if jetons else None

    def regex_possible():
        p = precedent()
        if p is None:
            return True
        if p.genre in ("nombre", "chaine"):
            return False
        if p.genre == "nom":
            return p.valeur in AVANT_REGEX
        return p.valeur not in (")", "]", "}", "++", "--")

    while i < n:
        c = texte[i]
        if c == "\n":
            ligne += 1
            i += 1
            continue
        if c in " \t\r\f\v ﻿":
            i += 1
            continue
        # commentaire de ligne
        if c == "/" and i + 1 < n and texte[i + 1] == "/":
            j = texte.find("\n", i)
            i = n if j < 0 else j
            continue
        # commentaire de bloc
        if c == "/" and i + 1 < n and texte[i + 1] == "*":
            j = texte.find("*/", i + 2)
            if j < 0:
                raise LectureImpossible(f"commentaire de bloc non refermé (ligne {ligne})")
            ligne += texte.count("\n", i, j)
            i = j + 2
            continue
        # chaîne simple ou double
        if c in "'\"":
            debut, j, contenu = ligne, i + 1, []
            while j < n and texte[j] != c:
                if texte[j] == "\\":
                    if j + 1 >= n:
                        raise LectureImpossible(f"échappement en fin de fichier (ligne {ligne})")
                    if texte[j + 1] == "\n":
                        ligne += 1
                    contenu.append(texte[j + 1])
                    j += 2
                    continue
                if texte[j] == "\n":
                    raise LectureImpossible(f"chaîne non refermée (ligne {debut})")
                contenu.append(texte[j])
                j += 1
            if j >= n:
                raise LectureImpossible(f"chaîne non refermée (ligne {debut})")
            jetons.append(Jeton("chaine", "".join(contenu), debut))
            i = j + 1
            continue
        # gabarit : le texte est écarté, les substitutions `${…}` sont du code
        if c == "`":
            debut = ligne
            j = i + 1
            while j < n:
                if texte[j] == "\\":
                    if j + 1 < n and texte[j + 1] == "\n":
                        ligne += 1
                    j += 2
                    continue
                if texte[j] == "\n":
                    ligne += 1
                    j += 1
                    continue
                if texte[j] == "`":
                    jetons.append(Jeton("chaine", "", debut))
                    i = j + 1
                    break
                if texte[j] == "$" and j + 1 < n and texte[j + 1] == "{":
                    pile_gabarits.append(profondeur_accolades)
                    profondeur_accolades += 1
                    jetons.append(Jeton("op", "{", ligne))
                    i = j + 2
                    break
                j += 1
            else:
                raise LectureImpossible(f"gabarit non refermé (ligne {debut})")
            if j >= n:
                raise LectureImpossible(f"gabarit non refermé (ligne {debut})")
            continue
        # littéral d'expression régulière
        if c == "/" and regex_possible():
            debut, j, classe = ligne, i + 1, False
            while j < n:
                d = texte[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "\n":
                    raise LectureImpossible(f"expression régulière non refermée (ligne {debut})")
                if d == "[":
                    classe = True
                elif d == "]":
                    classe = False
                elif d == "/" and not classe:
                    break
                j += 1
            if j >= n:
                raise LectureImpossible(f"expression régulière non refermée (ligne {debut})")
            j += 1
            while j < n and texte[j] in IDENT_SUITE:
                j += 1
            jetons.append(Jeton("chaine", "", debut))   # opaque : ce n'est ni un nom ni un opérateur
            i = j
            continue
        # nom / mot-clé
        if c in IDENT_DEBUT:
            j = i + 1
            while j < n and texte[j] in IDENT_SUITE:
                j += 1
            jetons.append(Jeton("nom", texte[i:j], ligne))
            i = j
            continue
        # nombre (y compris 0x…, 1e3, 1_000, 10n)
        if c.isdigit() or (c == "." and i + 1 < n and texte[i + 1].isdigit()):
            j = i
            while j < n and (texte[j] in IDENT_SUITE or texte[j] == "." or
                             (texte[j] in "+-" and j > i and texte[j - 1] in "eE")):
                j += 1
            jetons.append(Jeton("nombre", texte[i:j], ligne))
            i = j
            continue
        # accolades : compte de profondeur + retour de substitution de gabarit
        if c == "{":
            profondeur_accolades += 1
            jetons.append(Jeton("op", "{", ligne))
            i += 1
            continue
        if c == "}":
            profondeur_accolades -= 1
            if pile_gabarits and profondeur_accolades == pile_gabarits[-1]:
                # fin de la substitution : on revient dans le gabarit
                pile_gabarits.pop()
                jetons.append(Jeton("op", "}", ligne))
                j = i + 1
                debut = ligne
                while j < n:
                    if texte[j] == "\\":
                        if j + 1 < n and texte[j + 1] == "\n":
                            ligne += 1
                        j += 2
                        continue
                    if texte[j] == "\n":
                        ligne += 1
                        j += 1
                        continue
                    if texte[j] == "`":
                        i = j + 1
                        break
                    if texte[j] == "$" and j + 1 < n and texte[j + 1] == "{":
                        pile_gabarits.append(profondeur_accolades)
                        profondeur_accolades += 1
                        jetons.append(Jeton("op", "{", ligne))
                        i = j + 2
                        break
                    j += 1
                else:
                    raise LectureImpossible(f"gabarit non refermé (ligne {debut})")
                continue
            jetons.append(Jeton("op", "}", ligne))
            i += 1
            continue
        # opérateurs
        for op in OPERATEURS:
            if texte.startswith(op, i):
                jetons.append(Jeton("op", op, ligne))
                i += len(op)
                break
        else:
            jetons.append(Jeton("op", c, ligne))
            i += 1
    if pile_gabarits:
        raise LectureImpossible("gabarit non refermé en fin de fichier")
    return jetons


def _fin_de_membre(jetons, k):
    """Après `magasin`, l'accès : rend (position_apres, cle_litterale_ou_None, forme)."""
    t = jetons[k]
    if t.genre == "op" and t.valeur in (".", "?."):
        if k + 1 < len(jetons) and jetons[k + 1].genre == "nom":
            return k + 2, jetons[k + 1].valeur, "point"
        return None, None, None
    if t.genre == "op" and t.valeur == "[":
        prof, j, contenu = 1, k + 1, []
        while j < len(jetons) and prof:
            v = jetons[j]
            if v.genre == "op" and v.valeur in ("[", "{", "("):
                prof += 1
            elif v.genre == "op" and v.valeur in ("]", "}", ")"):
                prof -= 1
                if not prof:
                    break
            contenu.append(v)
            j += 1
        if prof:
            return None, None, None
        cle = contenu[0].valeur if len(contenu) == 1 and contenu[0].genre == "chaine" else None
        return j + 1, cle, "crochet"
    return None, None, None


def ecritures(jetons):
    """Toute expression qui MUTE le stockage du site, avec sa ligne et sa forme.

    Trois formes, déduites de la syntaxe et non d'une liste d'appels : l'appel d'une méthode mutante,
    l'affectation d'une propriété du magasin, et `delete` sur une propriété du magasin.
    """
    vues = []
    for k, t in enumerate(jetons):
        if t.genre != "nom" or t.valeur not in MAGASINS:
            continue
        # `x.localStorage` n'est le magasin que si `x` est un porteur du global
        if k >= 1 and jetons[k - 1].genre == "op" and jetons[k - 1].valeur in (".", "?."):
            if k < 2 or jetons[k - 2].genre != "nom" or jetons[k - 2].valeur not in PORTEURS:
                continue
            avant = k - 2
        else:
            avant = k
        if k + 1 >= len(jetons):
            continue
        apres, cle, forme = _fin_de_membre(jetons, k + 1)
        if apres is None:
            continue
        suivant = jetons[apres] if apres < len(jetons) else None
        prec = jetons[avant - 1] if avant >= 1 else None
        if prec is not None and prec.genre == "nom" and prec.valeur == "delete":
            vues.append((t.ligne, k, f"delete {t.valeur}.{cle or '…'}"))
            continue
        if suivant is not None and suivant.genre == "op" and suivant.valeur == "(" and cle in METHODES_MUTANTES:
            vues.append((t.ligne, k, f"{t.valeur}.{cle}(…)"))
            continue
        if suivant is not None and suivant.genre == "op" and suivant.valeur in AFFECTATIONS:
            nom = cle if forme == "point" else (cle or "…")
            vues.append((t.ligne, k, f"{t.valeur}[{nom!r}] = …" if forme == "crochet" else f"{t.valeur}.{nom} = …"))
    return vues


def couverture(jetons):
    """Pour chaque indice de jeton, si une capture de SA PROPRE fonction l'entoure.

    Rend un dict {indice_de_jeton: indice_du_jeton_`try`_couvrant ou None}. Un `try` traversé par une
    frontière de fonction ne couvre rien : le rappel s'exécute plus tard, hors de la capture.
    """
    # pile d'accolades : (genre, profondeur_a_l_ouverture) ; genre ∈ {"try", "fonc", "bloc"}
    pile = []
    # parenthèses ouvertes : le jeton qui les précède décide si le `{` suivant est un corps de fonction
    parens = []
    crochets = 0
    # flèches à corps d'EXPRESSION en cours : leur profondeur d'ouverture
    fleches = []
    attend_corps = False       # un `function`/`=>` a été vu, le prochain `{` est un corps
    couvert = {}

    def profondeur():
        return len(pile) + len(parens) + crochets

    for k, t in enumerate(jetons):
        # une flèche à corps d'expression se referme sur `,` `;` au même niveau, ou en remontant
        while fleches and (profondeur() < fleches[-1]):
            fleches.pop()
        if fleches and t.genre == "op" and t.valeur in (",", ";") and profondeur() == fleches[-1]:
            fleches.pop()

        if t.genre == "nom":
            if t.valeur == "function":
                attend_corps = True
            couvert[k] = _try_couvrant(pile, fleches)
            continue
        if t.genre != "op":
            couvert[k] = _try_couvrant(pile, fleches)
            continue
        v = t.valeur
        if v == "(":
            parens.append(jetons[k - 1] if k else None)
        elif v == ")":
            if parens:
                parens.pop()
        elif v == "[":
            crochets += 1
        elif v == "]":
            crochets = max(0, crochets - 1)
        elif v == "=>":
            if k + 1 < len(jetons) and jetons[k + 1].genre == "op" and jetons[k + 1].valeur == "{":
                attend_corps = True
            else:
                fleches.append(profondeur())
        elif v == "{":
            prec = jetons[k - 1] if k else None
            if prec is not None and prec.genre == "nom" and prec.valeur == "try":
                pile.append(("try", k - 1))
            elif attend_corps:
                pile.append(("fonc", k))
            elif prec is not None and prec.genre == "op" and prec.valeur == ")":
                # `if (…) {` est un bloc ; `f(…) {` / `method(…) {` est un corps de fonction
                ouvreur = _ouvreur_de_la_parenthese(jetons, k - 1)
                est_controle = (ouvreur is not None and ouvreur.genre == "nom" and ouvreur.valeur in CONTROLE)
                pile.append(("bloc" if est_controle else "fonc", k))
            else:
                pile.append(("bloc", k))
            attend_corps = False
        elif v == "}":
            if pile:
                pile.pop()
        couvert[k] = _try_couvrant(pile, fleches)
    return couvert


def _ouvreur_de_la_parenthese(jetons, k_fermante):
    """Le jeton qui précède la `(` appariée à la `)` d'indice `k_fermante`."""
    prof, j = 0, k_fermante
    while j >= 0:
        t = jetons[j]
        if t.genre == "op" and t.valeur == ")":
            prof += 1
        elif t.genre == "op" and t.valeur == "(":
            prof -= 1
            if prof == 0:
                return jetons[j - 1] if j >= 1 else None
        j -= 1
    return None


def _try_couvrant(pile, fleches):
    """L'INDICE du `try` qui couvre, dans sa propre fonction, ou `None`.

    Rendait un booléen jusqu'à `P4.13-d`. Le booléen répondait « une capture existe » ; il ne permettait
    pas de REGARDER cette capture, et c'est exactement l'angle mort que la clôture de cette garde
    déclarait : « une capture VIDE la satisfait ». L'indice, lui, désigne le `try` — donc son `catch`,
    donc son corps.
    """
    dernier_try = max((i for i, (g, _k) in enumerate(pile) if g == "try"), default=-1)
    dernier_fonc = max((i for i, (g, _k) in enumerate(pile) if g == "fonc"), default=-1)
    if dernier_try < 0 or dernier_try < dernier_fonc:
        return None
    # une flèche à corps d'expression OUVERTE À L'INTÉRIEUR du `try` est une frontière de fonction
    if fleches and fleches[-1] > dernier_try:
        return None
    return pile[dernier_try][1]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# `P4.13-d` — CE QUE LA CLÔTURE DE CETTE GARDE DÉCLARAIT NE PAS TENIR, ET QUI EST TENU MAINTENANT.
#
# LE DÉFAUT, MESURÉ LE 2026-08-31 SUR `web/` : DOUZE captures au corps LITTÉRALEMENT VIDE entouraient
# un accès au stockage de site (treize accès — une capture en portait deux), sur SIX modules. Toutes
# satisfaisaient cette garde, qui le disait elle-même en clôture : « une capture VIDE la satisfait, et
# elle échange l'état incohérent contre une perte MUETTE ». Le refus n'était pas rendu, pas dit, pas
# même déclaré tu : rien ne distinguait le site qui SE TAIT À DESSEIN de celui qui a simplement oublié.
#
# LA PROPRIÉTÉ AJOUTÉE EST STRUCTURELLE, PAS UN VOCABULAIRE D'AVEU. Elle ne cherche AUCUN mot dans le
# corps de la capture — ni `toast`, ni `console`, ni quoi que ce soit d'autre. Une liste de mots serait
# le piège mesuré ailleurs ce jour-là : un mot trop générique y figure comme un aveu et rend la garde
# VERTE sur le site le plus grave. Ce qui est exigé est que le fait SORTE de la capture — un `return`
# porteur d'une valeur, ou un `throw`. C'est ce que fait l'écrivain partagé (`catch (e) { return false; }`)
# et c'est ce qu'un `catch (e) {}`, un `catch (e) { console.warn(e); }` ou un `catch (e) { void 0; }` ne
# font pas : dans les trois cas l'appelant ne peut RIEN apprendre, et c'est l'appelant — lui seul — qui
# sait si le choix perdu doit être annoncé.
# CE QU'ELLE REFUSE AUSSI, ET CE N'EST PAS UN EFFET DE BORD : un `try` SANS capture (`try {…} finally {…}`).
# Il ne rattrape rien — la mutation JETTE au milieu du geste, le défaut de `P4.13-b` — alors que la
# mesure de couverture, elle, le comptait pour couvert.
#
# ET LE DÉPLACEMENT QUE LE CORRECTIF DE `P4.13-d` PRODUIT LUI-MÊME, FERMÉ ICI DANS LE MÊME GESTE. Quand
# les douze sites passent par les deux portes de `web/state.js`, la surface du défaut ne disparaît pas :
# elle SE DÉPLACE. Le treizième ne s'écrira plus `catch (e) {}` — il s'écrira
# `ecrireDansLeStockageDuSite(k, v);` en INSTRUCTION, valeur jetée, ce qui avale le refus exactement de
# la même façon. Son jumeau était déjà nommé, par écrit, dans `web/state.js` : « LE GESTE QUI FERMERAIT
# VRAIMENT CE PIÈGE est une propriété dérivée — la porte silencieuse n'est jamais LUE comme une valeur —
# à ajouter à `check_no_naked_site_storage_write.py` […]. Elle n'EST PAS écrite. » Les deux sens sont
# écrits ici.
#
# LES DEUX PORTES SONT DÉRIVÉES, PAS ÉNUMÉRÉES. Aucun nom de fonction et aucun nom de fichier n'est
# écrit dans cette garde :
#   · UN ÉCRIVAIN À VERDICT est une fonction DÉCLARÉE du corpus dont le corps porte une mutation du
#     magasin et qui REND une valeur à son propre niveau ;
#   · UNE PORTE SILENCIEUSE est une fonction déclarée dont le corps ENTIER est UN appel — un seul — à un
#     écrivain à verdict, valeur jetée. C'est la définition même du silence par déclaration, et elle
#     distingue la porte d'un appelant ordinaire qui, lui, LIT le verdict avant de faire autre chose.
# Renommer les portes ne change rien ; en écrire une troisième non plus. Les supprimer fait retomber la
# population sur les mutations nues, que la propriété d'origine juge déjà.
#
# LES DEUX SENS DE MESURE SOUS-COMPTENT, ET C'EST VOULU. « En instruction » est reconnu par une forme
# ÉTROITE (précédé de `;` `{` `}` `else` `do` ou de la parenthèse d'un mot-clé de contrôle, ET suivi de
# `;` ou `}`) ; « lu comme une valeur » par une liste d'opérateurs qui EXIGENT un opérande. Un appel qui
# ne tombe dans ni l'une ni l'autre n'est jugé par aucune des deux : la garde préfère taire un cas qu'en
# inventer un. La direction de l'erreur est donc le SOUS-compte des deux côtés, jamais la fausse accusation.
# ══════════════════════════════════════════════════════════════════════════════════════════════

# Les opérateurs après lesquels un appel est FORCÉMENT un opérande (sa valeur est lue). `=>` n'y figure
# PAS : le corps d'expression d'une flèche est en droit une position de valeur, mais `() => f()` est
# l'écriture courante d'un rappel dont personne ne lit le retour — l'y ranger accuserait à tort.
OPERANDE_AVANT_OP = set(AFFECTATIONS) | {
    "(", "[", ",", "?", ":", "!", "&&", "||", "??", "===", "!==", "==", "!=", "<", ">", "<=", ">=",
    "+", "-", "*", "/", "%", "**", "...",
}
OPERANDE_AVANT_NOM = {"return", "typeof", "await", "yield", "void", "throw", "new", "in", "of", "delete", "case"}
# Les opérateurs qui, APRÈS l'appel, consomment sa valeur.
OPERANDE_APRES = {".", "?.", "?", "&&", "||", "??", "===", "!==", "==", "!=", "<", ">", "<=", ">=",
                  "+", "-", "*", "/", "%", "**", "["}
# Ce qui, AVANT un appel, ouvre une INSTRUCTION.
INSTRUCTION_AVANT_OP = {";", "{", "}"}
INSTRUCTION_AVANT_NOM = {"else", "do"}


def _fin_de_parenthese(jetons, k_ouvrante):
    """L'indice qui SUIT la `)` appariée à la `(` d'indice `k_ouvrante`, ou None."""
    prof = 0
    for j in range(k_ouvrante, len(jetons)):
        t = jetons[j]
        if t.genre != "op":
            continue
        if t.valeur == "(":
            prof += 1
        elif t.valeur == ")":
            prof -= 1
            if prof == 0:
                return j + 1
    return None


def _fin_daccolade(jetons, k_ouvrante):
    """L'indice de la `}` appariée à la `{` d'indice `k_ouvrante`, ou None."""
    prof = 0
    for j in range(k_ouvrante, len(jetons)):
        t = jetons[j]
        if t.genre != "op":
            continue
        if t.valeur == "{":
            prof += 1
        elif t.valeur == "}":
            prof -= 1
            if prof == 0:
                return j
    return None


def _au_niveau_du_corps(jetons, k_ouvre, k_ferme):
    """Les indices de `]k_ouvre, k_ferme[` qui sont AU NIVEAU de ce corps.

    Hors de toute fonction imbriquée — corps d'accolades comme flèche à corps d'expression : un `return`
    posé dans un rappel rend au RAPPEL, pas à la fonction qui l'a écrit, et le compter reviendrait à
    croire qu'un refus est remonté alors qu'il est resté enfermé.
    """
    dedans = set()
    pile, parens, crochets, fleches = [], 0, 0, []
    attend_corps = False

    def prof():
        return len(pile) + parens + crochets

    for k in range(k_ouvre + 1, k_ferme):
        t = jetons[k]
        while fleches and prof() < fleches[-1]:
            fleches.pop()
        if fleches and t.genre == "op" and t.valeur in (",", ";") and prof() == fleches[-1]:
            fleches.pop()
        au_niveau = not any(g == "fonc" for g in pile) and not fleches
        if t.genre == "nom":
            if t.valeur == "function":
                attend_corps = True
            if au_niveau:
                dedans.add(k)
            continue
        if t.genre != "op":
            if au_niveau:
                dedans.add(k)
            continue
        v = t.valeur
        if v == "(":
            parens += 1
        elif v == ")":
            parens = max(0, parens - 1)
        elif v == "[":
            crochets += 1
        elif v == "]":
            crochets = max(0, crochets - 1)
        elif v == "=>":
            if k + 1 < k_ferme and jetons[k + 1].genre == "op" and jetons[k + 1].valeur == "{":
                attend_corps = True
            else:
                fleches.append(prof())
        elif v == "{":
            p = jetons[k - 1]
            if p.genre == "nom" and p.valeur == "try":
                pile.append("try")
            elif attend_corps:
                pile.append("fonc")
            elif p.genre == "op" and p.valeur == ")":
                o = _ouvreur_de_la_parenthese(jetons, k - 1)
                pile.append("bloc" if (o is not None and o.genre == "nom" and o.valeur in CONTROLE) else "fonc")
            else:
                pile.append("bloc")
            attend_corps = False
        elif v == "}":
            if pile:
                pile.pop()
        if au_niveau:
            dedans.add(k)
    return dedans


def _rend_le_fait(jetons, k_ouvre, k_ferme):
    """Le corps `]k_ouvre, k_ferme[` fait-il SORTIR le fait — `return <valeur>` ou `throw`, à SON niveau ?

    `return;` NU ne compte pas : il rend `undefined`, que l'appelant ne distingue pas d'un succès.
    """
    for k in sorted(_au_niveau_du_corps(jetons, k_ouvre, k_ferme)):
        t = jetons[k]
        if t.genre != "nom":
            continue
        if t.valeur == "throw":
            return True
        if t.valeur == "return":
            suivant = jetons[k + 1] if k + 1 < k_ferme else None
            if suivant is not None and not (suivant.genre == "op" and suivant.valeur in (";", "}")):
                return True
    return False


def capture_du_try(jetons, k_try):
    """La capture appariée au `try` d'indice `k_try` : (k_ouvre, k_ferme), ou None s'il n'y en a pas.

    Pas de capture = `try { … } finally { … }` : rien n'est RATTRAPÉ, la mutation jette au milieu du
    geste. L'appelant l'accuse, il ne le range pas parmi les silences.
    """
    j = k_try + 1
    while j < len(jetons) and not (jetons[j].genre == "op" and jetons[j].valeur == "{"):
        j += 1
    if j >= len(jetons):
        return None
    f = _fin_daccolade(jetons, j)
    if f is None:
        return None
    n = f + 1
    if n >= len(jetons) or not (jetons[n].genre == "nom" and jetons[n].valeur == "catch"):
        return None
    m = n + 1
    if m < len(jetons) and jetons[m].genre == "op" and jetons[m].valeur == "(":
        m = _fin_de_parenthese(jetons, m)
        if m is None:
            return None
    if m >= len(jetons) or not (jetons[m].genre == "op" and jetons[m].valeur == "{"):
        return None
    fin = _fin_daccolade(jetons, m)
    return None if fin is None else (m, fin)


def refus_avales(texte):
    """Les mutations dont la capture N'EN REND RIEN : (ligne, forme, motif).

    Deux motifs, et ils ne se confondent pas : « capture qui ne rend rien » (le corps ne fait sortir ni
    valeur ni jet — un `catch` VIDE en est le cas le plus pur) et « aucune capture » (un `try` à
    `finally` seul, qui laisse la mutation JETER). Une mutation qu'AUCUN `try` n'enveloppe n'est PAS
    comptée ici : c'est la faute d'origine de cette garde, comptée à part, et l'accuser deux fois
    rendrait deux avis pour un seul défaut.
    """
    jetons = analyser(texte)
    couvre = couverture(jetons)
    vus = []
    for ligne, k, forme in ecritures(jetons):
        k_try = couvre.get(k)
        if k_try is None:
            continue
        bornes = capture_du_try(jetons, k_try)
        if bornes is None:
            vus.append((ligne, forme, "aucune capture — un `try` à `finally` seul ne rattrape rien"))
            continue
        if not _rend_le_fait(jetons, bornes[0], bornes[1]):
            vus.append((ligne, forme, "capture qui NE REND RIEN — le refus est avalé sur place"))
    return vus


def fonctions_declarees(jetons):
    """Les fonctions écrites `function <nom>(…) { … }` : (nom, k_ouvre, k_ferme)."""
    trouvees = []
    for k, t in enumerate(jetons):
        if not (t.genre == "nom" and t.valeur == "function"):
            continue
        if k + 1 >= len(jetons) or jetons[k + 1].genre != "nom":
            continue
        nom = jetons[k + 1].valeur
        j = k + 2
        if j >= len(jetons) or not (jetons[j].genre == "op" and jetons[j].valeur == "("):
            continue
        j = _fin_de_parenthese(jetons, j)
        if j is None or j >= len(jetons) or not (jetons[j].genre == "op" and jetons[j].valeur == "{"):
            continue
        f = _fin_daccolade(jetons, j)
        if f is None:
            continue
        trouvees.append((nom, j, f))
    return trouvees


def ecrivains_a_verdict(jetons):
    """Les fonctions déclarées qui MUTENT le magasin et RENDENT une valeur : le nom des portes à verdict."""
    mutations = {k for _l, k, _f in ecritures(jetons)}
    noms = set()
    for nom, k_ouvre, k_ferme in fonctions_declarees(jetons):
        if not any(k_ouvre < k < k_ferme for k in mutations):
            continue
        if _rend_le_fait(jetons, k_ouvre, k_ferme):
            noms.add(nom)
    return noms


def portes_silencieuses(jetons, verdicts):
    """Les fonctions dont le corps ENTIER est UN appel à un écrivain à verdict, valeur jetée.

    « ENTIER » et « UN » sont la borne, et elle est écrite : une fonction qui fait AUTRE CHOSE en plus
    de jeter le verdict n'est pas une porte, c'est un site d'appel qui a perdu le refus. Cette forme-ci
    ne peut tromper personne — elle ne rend rien, donc aucun appelant ne peut croire lire un verdict —
    et le sens INVERSE (la lire comme une valeur) est justement l'autre moitié de `fautes_de_porte`.
    """
    noms = set()
    for nom, k_ouvre, k_ferme in fonctions_declarees(jetons):
        corps = jetons[k_ouvre + 1:k_ferme]
        if corps and corps[-1].genre == "op" and corps[-1].valeur == ";":
            corps = corps[:-1]
        if len(corps) < 3 or corps[0].genre != "nom" or corps[0].valeur not in verdicts:
            continue
        if not (corps[1].genre == "op" and corps[1].valeur == "("):
            continue
        if _fin_de_parenthese(jetons, k_ouvre + 2) != k_ferme - (1 if jetons[k_ferme - 1].valeur == ";" else 0):
            continue
        noms.add(nom)
    return noms


def _appels(jetons, noms):
    """Les appels `<nom>(` du corpus, hors déclaration et hors accès à un membre : (k, ligne, nom)."""
    for k, t in enumerate(jetons):
        if t.genre != "nom" or t.valeur not in noms:
            continue
        if k >= 1 and jetons[k - 1].genre == "op" and jetons[k - 1].valeur in (".", "?."):
            continue
        if k >= 1 and jetons[k - 1].genre == "nom" and jetons[k - 1].valeur == "function":
            continue
        if k + 1 >= len(jetons) or not (jetons[k + 1].genre == "op" and jetons[k + 1].valeur == "("):
            continue
        yield k, t.ligne, t.valeur


def _en_instruction(jetons, k):
    """L'appel d'indice `k` est-il, DE FORME ÉTROITE, une instruction dont la valeur est jetée ?"""
    prec = jetons[k - 1] if k >= 1 else None
    if prec is None:
        ouvert = True
    elif prec.genre == "op" and prec.valeur in INSTRUCTION_AVANT_OP:
        ouvert = True
    elif prec.genre == "nom" and prec.valeur in INSTRUCTION_AVANT_NOM:
        ouvert = True
    elif prec.genre == "op" and prec.valeur == ")":
        o = _ouvreur_de_la_parenthese(jetons, k - 1)
        ouvert = o is not None and o.genre == "nom" and o.valeur in CONTROLE
    else:
        ouvert = False
    if not ouvert:
        return False
    fin = _fin_de_parenthese(jetons, k + 1)
    if fin is None:
        return False
    suivant = jetons[fin] if fin < len(jetons) else None
    return suivant is None or (suivant.genre == "op" and suivant.valeur in (";", "}"))


def _lu_comme_valeur(jetons, k):
    """L'appel d'indice `k` est-il, DE FORME ÉTROITE, un OPÉRANDE — donc lu comme une valeur ?"""
    prec = jetons[k - 1] if k >= 1 else None
    if prec is not None:
        if prec.genre == "op" and prec.valeur in OPERANDE_AVANT_OP:
            return True
        if prec.genre == "nom" and prec.valeur in OPERANDE_AVANT_NOM:
            return True
    fin = _fin_de_parenthese(jetons, k + 1)
    if fin is None or fin >= len(jetons):
        return False
    suivant = jetons[fin]
    return suivant.genre == "op" and suivant.valeur in OPERANDE_APRES


def _fin_du_bloc_englobant(jetons, k):
    """L'indice de la `}` qui referme le bloc contenant l'indice `k`, ou None au niveau du module.

    Le premier `}` rencontré en avançant sans `{` ouvert à son crédit referme ce bloc — c'est la portée
    exacte d'un `const`/`let`, donc la seule fenêtre où sa relecture est en droit possible.
    """
    prof = 0
    for j in range(k, len(jetons)):
        t = jetons[j]
        if t.genre != "op":
            continue
        if t.valeur == "{":
            prof += 1
        elif t.valeur == "}":
            if prof == 0:
                return j
            prof -= 1
    return None


def _liaison_qui_recoit(jetons, k):
    """Le nom lié par `const|let <ident> = … <appel d'indice k> …`, ou None.

    LA BORNE, ET C'EST ELLE QUI ÉVITE LA FAUSSE ACCUSATION : l'appel doit être HORS de toute parenthèse
    ou de tout crochet resté ouvert depuis le `=`. `const x = f(…)` et `const x = !c || f(…)` font tous
    deux couler le verdict dans `x` ; `const x = g(f(…))` NON — le verdict a été REMIS à `g`, qui en fait
    ce qu'il veut, et l'accuser reviendrait à inventer un défaut. La marche arrière s'arrête au premier
    `;`, `,`, `{` ou `}` de niveau : au-delà, ce n'est plus le même initialiseur.
    """
    prof, j, bornes = 0, k - 1, 0
    while j >= 0 and bornes < 400:
        bornes += 1
        t = jetons[j]
        if t.genre == "op":
            if t.valeur in (")", "]", "}"):
                prof += 1
            elif t.valeur in ("(", "[", "{"):
                if prof == 0:
                    return None
                prof -= 1
            elif prof == 0 and t.valeur in (";", ","):
                return None
            elif prof == 0 and t.valeur == "=":
                if (j >= 2 and jetons[j - 1].genre == "nom"
                        and jetons[j - 2].genre == "nom" and jetons[j - 2].valeur in ("const", "let")):
                    return jetons[j - 1].valeur
                return None
        elif prof == 0 and t.genre == "nom" and t.valeur in ("return", "throw", "case", "do", "else"):
            return None
        j -= 1
    return None


def verdicts_recus_puis_laisses_tomber(jetons, verdicts):
    """`const x = <écrivain à verdict>(…)` dont `x` n'est JAMAIS RELU dans sa portée : (ligne, motif).

    `P4.13-e` — L'AUTRE MOITIÉ DU MÊME PIÈGE, ET CELLE QUI RESTAIT OUVERTE. `fautes_de_porte` accuse le
    verdict JETÉ à l'appel (`f(…);` en instruction). Elle ne voit RIEN du verdict REÇU puis abandonné :
    `const retenu = f(k, v);` suivi de rien. La valeur existe, elle a été rendue, elle est liée — et
    personne ne la consulte. Pour l'exploitant, c'est mot pour mot le défaut que `P4.13-b` a fermé : il
    croit son choix retenu, il ne l'est pas, et rien ne le lui dit. Un `catch` vide et une liaison morte
    perdent le même fait ; les distinguer serait une distinction d'auteur, pas de lecteur.

    LA FORME EST ÉTROITE, ET LA DIRECTION DE L'ERREUR EST LE SOUS-COMPTE. Seules `const` et `let` sont
    jugées : leur portée est le BLOC, donc l'absence de relecture avant la `}` qui le referme est une
    absence de relecture tout court. `var` déborde son bloc et n'est pas jugé ; une liaison posée au
    niveau du module non plus (aucun bloc ne la referme) ; une déstructuration non plus. Une occurrence
    du nom SUFFIT à innocenter — y compris dans un rappel écrit plus bas, qui peut très bien le lire
    plus tard. Ce qui reste accusé ne peut pas être relu : c'est une valeur morte.

    AUCUN MOT N'EST CHERCHÉ, ICI NON PLUS. Ce que la relecture fait du verdict — un avis peint, une
    branche, un journal — n'est PAS de ce ressort : la garde lit du texte, elle ne peut pas voir la
    surface. C'est le banc ESM qui juge l'aveu PEINT (`web_esm_harnais.mjs`, témoin 61, deux jouées du
    même geste sous refus posé et retiré) ; ces deux mesures ne se remplacent pas.
    """
    vus = []
    for k, ligne, nom in _appels(jetons, verdicts):
        identifiant = _liaison_qui_recoit(jetons, k)
        if identifiant is None:
            continue
        fin = _fin_du_bloc_englobant(jetons, k)
        if fin is None:
            continue
        relu = False
        for j in range(k + 1, fin):
            t = jetons[j]
            if t.genre != "nom" or t.valeur != identifiant:
                continue
            if jetons[j - 1].genre == "op" and jetons[j - 1].valeur in (".", "?."):
                continue      # `o.retenu` est un MEMBRE homonyme, pas cette liaison
            relu = True
            break
        if not relu:
            vus.append((ligne, f"le verdict de `{nom}(…)` est RETENU dans `{identifiant}` puis JAMAIS RELU "
                               "dans sa portée : le refus du stockage est bien REÇU, et il est laissé tomber "
                               "sur place — l'exploitant croit son choix retenu exactement comme si rien "
                               "n'avait été rendu"))
    return vus


def fautes_de_porte(jetons, verdicts, silencieuses):
    """Les DEUX SENS du même piège : (ligne, motif).

    (1) un écrivain à VERDICT appelé en INSTRUCTION, hors du corps d'une porte silencieuse : sa valeur
        est jetée, donc le refus est avalé — la forme que prendra le prochain défaut, une fois les
        captures vides fermées ;
    (2) une porte SILENCIEUSE lue comme une VALEUR : elle ne rend RIEN, donc le test est TOUJOURS
        faux, donc l'avertissement partirait TOUJOURS — y compris quand l'écriture a réussi.
    """
    interieurs = []
    for nom, k_ouvre, k_ferme in fonctions_declarees(jetons):
        if nom in silencieuses:
            interieurs.append((k_ouvre, k_ferme))
    vus = []
    for k, ligne, nom in _appels(jetons, verdicts):
        if any(a < k < b for a, b in interieurs):
            continue
        if _en_instruction(jetons, k):
            vus.append((ligne, f"`{nom}(…)` est appelé en INSTRUCTION : son verdict est JETÉ, et le "
                               "refus du stockage redevient une perte MUETTE"))
    for k, ligne, nom in _appels(jetons, silencieuses):
        if _lu_comme_valeur(jetons, k):
            vus.append((ligne, f"`{nom}(…)` est LU COMME UNE VALEUR : cette porte ne rend RIEN, donc le "
                               "test est toujours faux et l'avis partirait même quand l'écriture a RÉUSSI"))
    # (3) `P4.13-e` — le verdict REÇU dans une liaison que personne ne relit : voir la fonction ci-dessus.
    vus.extend(verdicts_recus_puis_laisses_tomber(jetons, verdicts))
    return vus


def nues(texte):
    """Les écritures NON enclosés dans une capture de leur propre fonction : (ligne, forme)."""
    jetons = analyser(texte)
    couvre = couverture(jetons)
    return [(ligne, forme) for ligne, k, forme in ecritures(jetons) if couvre.get(k) is None]


def toutes(texte):
    jetons = analyser(texte)
    return [(ligne, forme) for ligne, _k, forme in ecritures(jetons)]


def portes_du_corpus(sources):
    """Les deux ensembles de noms, DÉRIVÉS d'un corpus `{nom: texte}`.

    UNE PORTE SILENCIEUSE NE SE DÉCLARE QUE LÀ OÙ LE MAGASIN EST RÉELLEMENT MUTÉ, et c'est ce qui la
    sépare d'un enrobage écrit ailleurs. `web/state.js` porte les deux portes PARCE QU'il porte l'accès
    au magasin ; un module de vue qui écrirait le même enrobage d'une ligne ne déclare rien du tout —
    il ne fait que reperdre le refus une couche plus loin, sous un nom que personne n'a pesé. La
    dérivation ne connaît toujours AUCUN nom : elle regarde qui mute.
    """
    verdicts, silencieuses = set(), set()
    for _nom, texte in sources.items():
        jetons = analyser(texte)
        locaux = ecrivains_a_verdict(jetons)
        if not locaux:
            continue
        verdicts |= locaux
        silencieuses |= portes_silencieuses(jetons, locaux)
    return verdicts, silencieuses


def fautes_de_porte_du_corpus(sources):
    """Les fautes de porte d'un corpus `{nom: texte}` : (nom, ligne, motif)."""
    verdicts, silencieuses = portes_du_corpus(sources)
    vues = []
    for nom, texte in sources.items():
        jetons = analyser(texte)
        for ligne, motif in fautes_de_porte(jetons, verdicts, silencieuses):
            vues.append((nom, ligne, motif))
    return vues


# --- LES TÉMOINS, FABRIQUÉS ICI ----------------------------------------------------------------
# Chacun porte SON SENS : ce qui doit être VU, et ce qui ne doit PAS l'être. Aucun ne lit le dépôt,
# aucun n'exige qu'un défaut subsiste quelque part.
TEMOINS = [
    # (nom, source fabriquée, nombre d'écritures TOTAL attendu, nombre d'écritures NUES attendu)
    ("écriture nue",
     "function f(){ localStorage.setItem('k', v); }", 1, 1),
    ("écriture sous capture, même fonction",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) {} }", 1, 0),
    ("écriture en commentaire de ligne",
     "function f(){ // localStorage.setItem('k', v);\n return 1; }", 0, 0),
    ("écriture en commentaire de bloc",
     "function f(){ /* localStorage.setItem('k', v); */ return 1; }", 0, 0),
    ("`//` DANS une chaîne n'ouvre pas un commentaire",
     "function f(){ const u = 'http://x'; localStorage.setItem('k', u); }", 1, 1),
    ("`/*` DANS une chaîne n'ouvre pas un commentaire",
     "function f(){ const u = \"/* pas un commentaire\"; localStorage.setItem('k', u); }", 1, 1),
    ("écriture citée dans un gabarit",
     "function f(){ const s = `localStorage.setItem('k', v)`; return s; }", 0, 0),
    ("substitution de gabarit : le code y est bien du code",
     "function f(){ const s = `x${localStorage.setItem('k', v)}y`; return s; }", 1, 1),
    ("écriture citée dans une expression régulière",
     "function f(){ return /localStorage.setItem\\(/.test(s); }", 0, 0),
    ("division n'est pas une expression régulière",
     "function f(){ const r = a / b; localStorage.setItem('k', r); }", 1, 1),
    ("lecture : ce n'est pas une écriture",
     "function f(){ return localStorage.getItem('k'); }", 0, 0),
    ("`window.localStorage` est le même magasin",
     "function f(){ window.localStorage.removeItem('k'); }", 1, 1),
    ("`sessionStorage` aussi",
     "function f(){ sessionStorage.clear(); }", 1, 1),
    ("un objet homonyme n'est pas le magasin",
     "function f(){ faux.localStorage.setItem('k', v); }", 0, 0),
    ("affectation de propriété : c'est une écriture",
     "function f(){ localStorage.choix = '1'; }", 1, 1),
    ("`delete` sur le magasin : c'est une écriture",
     "function f(){ delete localStorage.choix; }", 1, 1),
    ("clé littérale entre crochets",
     "function f(){ localStorage['setItem']('k', v); }", 1, 1),
    ("capture qui n'entoure QUE la création du rappel : l'écriture reste NUE",
     "function f(){ try { b.onclick = () => { localStorage.setItem('k', v); }; } catch (e) {} }", 1, 1),
    ("capture qui n'entoure QUE la création d'un rappel à corps d'expression",
     "function f(){ try { b.onclick = () => localStorage.setItem('k', v); } catch (e) {} }", 1, 1),
    ("flèche refermée : l'écriture qui SUIT reste couverte",
     "function f(){ try { const g = () => 1; localStorage.setItem('k', g); } catch (e) {} }", 1, 0),
    ("capture DANS le rappel : couverte",
     "function f(){ b.onclick = () => { try { localStorage.setItem('k', v); } catch (e) {} }; }", 1, 0),
    ("écriture dans la capture elle-même : NUE (un jet s'y propage)",
     "function f(){ try { g(); } catch (e) { localStorage.setItem('k', e); } }", 1, 1),
    ("`if (…) {` n'est pas un corps de fonction",
     "function f(){ try { if (a) { localStorage.setItem('k', v); } } catch (e) {} }", 1, 0),
    ("méthode abrégée d'objet : c'est bien un corps de fonction",
     "const o = { try_: 1, m() { localStorage.setItem('k', v); } };", 1, 1),
    ("écriture derrière un `try` d'une fonction ENGLOBANTE : nue",
     "function f(){ try { return function g(){ localStorage.setItem('k', v); }; } catch (e) {} }", 1, 1),
    ("deux écritures dans la même ligne gardée",
     "function f(){ try { if (v) localStorage.setItem('k', v); else localStorage.removeItem('k'); } catch (e) {} }", 2, 0),
]


# --- `P4.13-d` — LES TÉMOINS DES DEUX PROPRIÉTÉS AJOUTÉES, FABRIQUÉS ICI EUX AUSSI ------------
# Aucun ne lit le dépôt ; aucun n'exige qu'un défaut subsiste quelque part. Chacun porte SON SENS : ce
# qui DOIT être accusé, et ce qui ne doit PAS l'être — sans quoi une garde qui accuserait TOUT serait
# indiscernable d'une garde juste.
TEMOINS_AVEU = [
    # (nom, source fabriquée, nombre de refus AVALÉS attendu)
    ("capture VIDE : le refus est avalé",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) {} }", 1),
    ("capture qui REND le fait : rien à dire",
     "function f(){ try { localStorage.setItem('k', v); return true; } catch (e) { return false; } }", 0),
    ("capture qui JETTE : le fait sort aussi",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) { throw e; } }", 0),
    ("UN MOT DANS LA CAPTURE N'EST PAS UN AVEU — c'est le piège mesuré le 2026-08-31",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) { console.warn(e); } }", 1),
    ("`return` NU : rend `undefined`, que l'appelant ne distingue pas d'un succès",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) { return; } }", 1),
    ("un `return` enfermé dans un rappel DE la capture ne remonte rien",
     "function f(){ try { localStorage.setItem('k', v); } catch (e) { g(() => { return false; }); } }", 1),
    ("`try` SANS capture (`finally` seul) : la mutation JETTE, rien n'est rattrapé",
     "function f(){ try { localStorage.setItem('k', v); } finally { g(); } }", 1),
    ("mutation NUE : comptée par la propriété d'origine, jamais deux fois",
     "function f(){ localStorage.setItem('k', v); }", 0),
    ("une LECTURE sous capture vide n'est pas dans cette population",
     "function f(){ try { return localStorage.getItem('k'); } catch (e) {} }", 0),
    ("la capture d'une fonction ENGLOBANTE ne compte pas comme la sienne",
     "function f(){ try { return function g(){ localStorage.setItem('k', v); }; } catch (e) { return null; } }", 0),
]

# La fabrique commune des témoins de porte : un écrivain à VERDICT et une porte SILENCIEUSE, tous deux
# nommés ARBITRAIREMENT — c'est ce qui prouve que la garde les DÉRIVE au lieu de les connaître. Les
# témoins sont des CORPUS (plusieurs sources), parce que la propriété l'est : une porte silencieuse ne
# se déclare que dans le module qui mute le magasin, et un enrobage écrit AILLEURS est une faute.
_SOCLE = ("function poserOuNon(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }\n"
          "function poserSansRienDire(k, v) { poserOuNon(k, v); }\n")
_SOCLE_AUTRES_NOMS = _SOCLE.replace("poserOuNon", "zz1").replace("poserSansRienDire", "zz2")
TEMOINS_PORTES = [
    # (nom, corpus fabriqué {source: texte}, nombre de fautes de porte attendu)
    ("le socle seul : les deux portes sont dérivées, et aucune n'est en faute",
     {"magasin.js": _SOCLE}, 0),
    ("un appelant qui LIT le verdict",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ if (!poserOuNon('k', 1)) g('perdu'); }"}, 0),
    ("un appelant qui garde le verdict dans une variable",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = poserOuNon('k', 1); g(retenu); }"}, 0),
    ("LE VERDICT JETÉ dans un module qui ne mute pas : l'enrobage ne déclare rien",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ poserOuNon('k', 1); }"}, 1),
    ("LE VERDICT JETÉ dans une fonction qui fait AUTRE CHOSE — la forme du prochain défaut",
     {"magasin.js": _SOCLE + "function a(){ g(1); poserOuNon('k', 1); h(2); }"}, 1),
    ("LA PORTE SILENCIEUSE LUE COMME UNE VALEUR : le test serait toujours faux",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ if (!poserSansRienDire('k', 1)) g('perdu'); }"}, 1),
    ("la porte silencieuse appelée en instruction : c'est son emploi juste",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ poserSansRienDire('k', 1); }"}, 0),
    ("RENOMMER LES DEUX PORTES NE CHANGE RIEN — la dérivation ne connaît aucun nom",
     {"magasin.js": _SOCLE_AUTRES_NOMS, "vue.js": "function a(){ zz1('k', 1); }"}, 1),
    ("un verdict jeté sous une branche d'`if` sans accolades",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ if (c) poserOuNon('k', 1); }"}, 1),
    ("sans écrivain à verdict déclaré, la propriété est VIDE et n'accuse personne",
     {"magasin.js": "function f(){ try { localStorage.setItem('k', v); } catch (e) {} }",
      "vue.js": "function a(){ f(); }"}, 0),
    ("ni instruction étroite ni opérande : jugé par aucun des deux sens, et c'est le SOUS-compte assumé",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const t = [poserSansRienDire]; t[0]('k', 1); }"}, 0),
    ("LA BORNE, ÉCRITE : dans le module qui mute, un corps réduit à l'appel jeté EST une porte",
     {"magasin.js": _SOCLE + "function a(){ poserOuNon('k', 1); }"}, 0),
    # `P4.13-e` — LE VERDICT REÇU PUIS LAISSÉ TOMBER : le troisième sens du même piège.
    ("LE VERDICT REÇU PUIS LAISSÉ TOMBER : lié, jamais relu",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = poserOuNon('k', 1); g('fait'); }"}, 1),
    ("le verdict reçu PUIS relu : c'est son emploi juste",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = poserOuNon('k', 1); if (!retenu) g('perdu'); }"}, 0),
    ("relu DANS un rappel écrit plus bas : innocenté, et c'est le sous-compte assumé",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = poserOuNon('k', 1); h(() => g(retenu)); }"}, 0),
    ("`let` est jugé comme `const` — même portée de bloc",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ let retenu = poserOuNon('k', 1); g('fait'); }"}, 1),
    ("`var` n'est PAS jugé : sa portée déborde le bloc qui le referme",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ var retenu = poserOuNon('k', 1); g('fait'); }"}, 0),
    ("un MEMBRE homonyme ne compte pas comme une relecture",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = poserOuNon('k', 1); g(o.retenu); }"}, 1),
    ("le verdict PASSÉ par une expression, lié, jamais relu — la forme du site réel de `web/core.js`",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = !cle || poserOuNon('k', 1); g('fait'); }"}, 1),
    ("le verdict ARGUMENT d'un autre appel n'est PAS jugé : il a été REMIS, pas jeté",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const t = g(poserOuNon('k', 1)); h('fait'); }"}, 0),
    ("le verdict passé par une expression PUIS relu : rien à dire",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const retenu = !cle || poserOuNon('k', 1); if (!retenu) g('perdu'); }"}, 0),
    ("relu HORS du bloc qui referme la liaison : la relecture est impossible, la faute reste",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ if (c) { const retenu = poserOuNon('k', 1); } g(retenu); }"}, 1),
    ("liaison au niveau du MODULE : aucun bloc ne la referme, elle n'est pas jugée",
     {"magasin.js": _SOCLE, "vue.js": "const retenu = poserOuNon('k', 1);"}, 0),
    ("une PORTE SILENCIEUSE liée à un nom est accusée UNE fois — par l'ancien sens, pas deux",
     {"magasin.js": _SOCLE, "vue.js": "function a(){ const rien = poserSansRienDire('k', 1); g('fait'); }"}, 1),
]



def epreuves():
    for nom, source, att_total, att_nues in TEMOINS:
        try:
            t = toutes(source)
            u = nues(source)
        except LectureImpossible as e:
            return f"témoin « {nom} » : l'analyseur a refusé de lire une source fabriquée ({e})"
        except Exception as e:                                    # noqa: BLE001 — un instrument qui casse doit le dire
            return f"témoin « {nom} » : l'analyseur a levé {type(e).__name__} ({e})"
        if len(t) != att_total:
            return f"témoin « {nom} » : {len(t)} écriture(s) vue(s), attendu {att_total} — {t}"
        if len(u) != att_nues:
            return f"témoin « {nom} » : {len(u)} écriture(s) NUE(s), attendu {att_nues} — {u}"
    for nom, source, att in TEMOINS_AVEU:
        try:
            u = refus_avales(source)
        except LectureImpossible as e:
            return f"témoin d'aveu « {nom} » : l'analyseur a refusé de lire une source fabriquée ({e})"
        except Exception as e:                                    # noqa: BLE001
            return f"témoin d'aveu « {nom} » : l'analyseur a levé {type(e).__name__} ({e})"
        if len(u) != att:
            return f"témoin d'aveu « {nom} » : {len(u)} refus avalé(s), attendu {att} — {u}"
    for nom, corpus, att in TEMOINS_PORTES:
        try:
            u = fautes_de_porte_du_corpus(corpus)
        except LectureImpossible as e:
            return f"témoin de porte « {nom} » : l'analyseur a refusé de lire une source fabriquée ({e})"
        except Exception as e:                                    # noqa: BLE001
            return f"témoin de porte « {nom} » : l'analyseur a levé {type(e).__name__} ({e})"
        if len(u) != att:
            return f"témoin de porte « {nom} » : {len(u)} faute(s) de porte, attendu {att} — {u}"
    # LE SOCLE DES TÉMOINS DE PORTE DOIT VRAIMENT PORTER DEUX PORTES : sans ce contrôle, une dérivation
    # cassée rendrait DEUX ensembles VIDES, donc zéro faute partout, et neuf témoins sur onze passeraient.
    _v, _p = portes_du_corpus({"magasin.js": _SOCLE})
    if len(_v) != 1 or len(_p) != 1:
        return ("témoin de dérivation : le socle fabriqué porte UN écrivain à verdict et UNE porte "
                f"silencieuse, la dérivation en trouve {len(_v)} et {len(_p)}")
    # témoin de l'analyseur lui-même : un texte illisible doit FAIRE REFUSER, pas rendre zéro
    for mauvais in ("const s = 'jamais refermée\n", "/* jamais refermé", "const t = `jamais refermé"):
        try:
            toutes(mauvais)
        except LectureImpossible:
            continue
        return "témoin « source illisible » : l'analyseur a conclu sur un texte qu'il ne sait pas lire"
    return None


def modules_du_corpus(racine):
    """Population DÉRIVÉE : tout `*.js` sous `web/`, lu sur le DISQUE (pas dans l'index du dépôt).

    LE DISQUE RESTE LA SOURCE — c'est écrit en tête, et c'est ce qui fait voir un module neuf avant qu'il
    soit suivi. Mais le parcours passe par l'ÉLAGAGE PARTAGÉ (`P11.8-m`) : cette garde est la seule à
    descendre `web/` RÉCURSIVEMENT (ses sœurs y font un `listdir` PLAT, immunisé par sa platitude), donc
    la seule où un `web/node_modules/` — que rien n'interdit le jour où la console gagne une étape de
    construction — entrerait dans la population des modules à juger."""
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine):
        for f in fichiers:
            if f.endswith(".js"):
                trouves.append(os.path.join(dossier, f))
    return sorted(trouves)


def main():
    global RACINE, CORPUS
    RACINE = racine_designee(sys.argv if len(sys.argv) > 1 else [sys.argv[0], DEPOT_DE_CETTE_GARDE])
    CORPUS = os.path.join(RACINE, "web")

    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    if not os.path.isdir(CORPUS):
        print(f"::error::`web/` introuvable sous {RACINE} : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    modules = modules_du_corpus(CORPUS)
    if not modules:
        print("::error::aucun module `web/**/*.js` : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    fautes, avalees, total_ecritures, modules_avec_ecriture = [], [], 0, 0
    sources = {}
    for chemin in modules:
        rel = os.path.relpath(chemin, RACINE)
        try:
            texte = open(chemin, encoding="utf-8").read()
        except OSError as e:
            print(f"::error file={rel}::module illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
            return 2
        try:
            jetons = analyser(texte)
        except LectureImpossible as e:
            print(f"::error file={rel}::l'analyseur lexical ne sait pas lire ce module ({e}) : la garde "
                  "REFUSE DE CONCLURE plutôt que de le déclarer sans écriture nue", file=sys.stderr)
            return 2
        sources[rel] = texte
        couvre = couverture(jetons)
        vues = ecritures(jetons)
        if vues:
            modules_avec_ecriture += 1
        total_ecritures += len(vues)
        for ligne, k, forme in vues:
            if couvre.get(k) is None:
                fautes.append((rel, ligne, forme))
        for ligne, forme, motif in refus_avales(texte):
            avalees.append((rel, ligne, forme, motif))

    # `P4.13-d` — LES DEUX PORTES SONT DÉRIVÉES DU CORPUS ENTIER, PAS DU MODULE COURANT : l'écrivain à
    # verdict vit dans un module, ses appelants dans quarante autres.
    verdicts, silencieuses = portes_du_corpus(sources)
    fautes_portes = fautes_de_porte_du_corpus(sources)

    # CONTRÔLE POSITIF : zéro écriture dans TOUT le corpus, c'est ce que rend un analyseur cassé.
    if total_ecritures == 0:
        print("::error::CONTRÔLE POSITIF PERDU — aucune écriture au stockage du site trouvée dans "
              f"{len(modules)} module(s) : c'est exactement ce que rendrait un analyseur cassé, donc la "
              "garde REFUSE DE CONCLURE au lieu de rendre un vert par vacuité.", file=sys.stderr)
        return 2

    for rel, ligne, forme, motif in avalees:
        print(f"::error file={rel},line={ligne}::REFUS AVALÉ au stockage du site (`{forme}`) — {motif}. La "
              "mutation est bien enclose, donc rien ne JETTE : mais le refus s'arrête là, et l'appelant — "
              "le seul à savoir si le choix perdu doit être annoncé — n'apprend RIEN. L'exploitant croit "
              "son choix retenu ; il ne l'est pas. Faire SORTIR le fait (`return` porteur d'une valeur, ou "
              "`throw`), ou passer par la porte partagée qui le rend déjà, `ecrireDansLeStockageDuSite` "
              "(web/state.js) — et, quand le silence est VOULU, par celle qui le déclare, "
              "`ecrireSansDireLeRefus`, en écrivant POURQUOI il n'y a rien à annoncer.", file=sys.stderr)

    for rel, ligne, motif in fautes_portes:
        print(f"::error file={rel},line={ligne}::{motif}.", file=sys.stderr)

    for rel, ligne, forme in fautes:
        print(f"::error file={rel},line={ligne}::écriture NUE au stockage du site (`{forme}`) : chez un "
              "navigateur qui refuse le stockage, cet accès JETTE `SecurityError` AU MILIEU du geste — "
              "un état est déjà posé, la vue n'est pas repeinte, et l'exploitant n'a rien à lire. "
              "Passer par `ecrireDansLeStockageDuSite` (web/state.js), qui REND le refus, puis DIRE la "
              "perte (un `catch` vide l'échangerait contre une perte muette).", file=sys.stderr)

    # AUCUN CLIQUET SUR CES DEUX-LÀ, ET C'EST ÉCRIT PLUTÔT QUE TU : elles naissent à ZÉRO le jour où
    # `P4.13-d` est payée (douze captures fermées, treize accès), et un cliquet à zéro n'est rien d'autre
    # qu'un refus. Poser un cliquet AU-DESSUS de zéro exigerait de nommer les sites tolérés, c'est-à-dire
    # d'énumérer — exactement ce que cette garde refuse depuis sa première ligne.
    if avalees or fautes_portes:
        print(f"\n{len(avalees)} refus AVALÉ(S) et {len(fautes_portes)} faute(s) de porte. Un refus avalé "
              "n'est pas un état incohérent : c'est une PERTE MUETTE, et elle est pire pour l'exploitant, "
              "parce qu'il n'a RIEN à lire pour la comprendre (`P4.13-d`, mesuré le 2026-08-31 : douze "
              "captures au corps littéralement vide sur six modules).", file=sys.stderr)
        return 1

    if len(fautes) > CLIQUET_ECRITURES_NUES:
        print(f"\n{len(fautes)} écriture(s) nue(s) au stockage du site, cliquet à {CLIQUET_ECRITURES_NUES} "
              f"(mesuré le 2026-08-30, `P4.13-b`). Une écriture nue ne rend pas MOINS : elle rend un état "
              "INCOHÉRENT, ce qui est pire qu'un refus.", file=sys.stderr)
        return 1
    if len(fautes) < CLIQUET_ECRITURES_NUES:
        print(f"::error::le cliquet vaut {CLIQUET_ECRITURES_NUES} alors que le corpus n'en porte plus que "
              f"{len(fautes)} : abaisser le cliquet fait partie du correctif, sans quoi la garde cesse de "
              "refuser ce qui vient d'être fermé.", file=sys.stderr)
        return 1

    print(f"check_no_naked_site_storage_write : {total_ecritures} écriture(s) au stockage du site dans "
          f"{modules_avec_ecriture} des {len(modules)} modules de `web/`, toutes encloses dans une capture "
          f"de LEUR PROPRE fonction ; cliquet à {CLIQUET_ECRITURES_NUES}. La population est DÉRIVÉE du "
          "disque (`web/**/*.js`), jamais énumérée ; « muter » est déduit de deux listes écrites (magasins, "
          "méthodes mutantes) plus l'affectation et `delete` ; commentaires, chaînes, gabarits et "
          "expressions régulières sont écartés par un analyseur lexical, et un `//` dans une chaîne n'ouvre "
          "pas un commentaire.\n"
          f"`P4.13-d` — ET AUCUNE DE CES CAPTURES N'AVALE LE REFUS : chacune le fait SORTIR (`return` "
          "porteur d'une valeur, ou `throw`), sans qu'aucun mot d'aveu ne soit cherché dans son corps — une "
          "liste de mots rendrait la garde verte sur le site le plus grave dès qu'un mot trop générique y "
          f"figurerait. Les deux portes sont DÉRIVÉES du corpus, jamais nommées ici : {len(verdicts)} "
          f"écrivain(s) à verdict ({', '.join(sorted(verdicts)) or 'aucun'}) et {len(silencieuses)} porte(s) "
          f"silencieuse(s) ({', '.join(sorted(silencieuses)) or 'aucune'}) ; aucun verdict n'est JETÉ en "
          "instruction, et aucune porte silencieuse n'est LUE comme une valeur — le piège que `web/state.js` "
          "nommait par écrit sans que rien ne le tienne.\n"
          "`P4.13-e` — ET AUCUN VERDICT N'EST REÇU PUIS LAISSÉ TOMBER : une liaison `const`/`let` qui reçoit "
          "un écrivain à verdict est RELUE dans sa portée. Une valeur rendue puis abandonnée perd le refus "
          "exactement comme une capture vide ; la borne qui évite la fausse accusation est écrite et "
          "fabriquée ici — un verdict REMIS en argument à un autre appel (`g(f(…))`) n'est pas jugé, `var` "
          "non plus, ni une liaison au niveau du module.\n"
          f"{len(TEMOINS)} + {len(TEMOINS_AVEU)} + {len(TEMOINS_PORTES)} témoins FABRIQUÉS ICI valident "
          "l'instrument dans les deux sens — y compris un `catch (e) { console.warn(e); }`, qui est ACCUSÉ, "
          "et un corpus sans écrivain à verdict, où la propriété des portes est VIDE et n'accuse personne. "
          "Zéro écriture dans tout le corpus fait REFUSER DE CONCLURE.\n"
          "CE QU'ELLE NE TIENT PAS : que l'aveu atteigne la SURFACE où le choix est lu. La moitié "
          "STRUCTURELLE de ce trou est fermée depuis `P4.13-e` (le verdict reçu doit être RELU) ; l'autre "
          "moitié — que la relecture DÉBOUCHE sur quelque chose de peint — ne se lit pas dans le texte, et "
          "chercher un mot d'aveu dans un corps est précisément ce qui rend une garde VERTE sur le site le "
          "plus grave. Elle se juge au banc ESM (`web_esm_harnais.mjs`, témoin 61), qui joue DEUX fois le "
          "même geste — refus du stockage posé, puis retiré — et lit les avis PEINTS : l'aveu doit "
          "apparaître sur le refus, et lui seul. Les deux mesures ne se remplacent pas. "
          "Que le silence VOULU soit MOTIVÉ n'est PAS tenu non plus, et le remède a été MESURÉ puis "
          "REFUSÉ deux fois plutôt qu'une : (1) exiger un commentaire adjacent serait vert par "
          "construction — les 9 sites d'appel de la porte silencieuse en portent DÉJÀ 4 à 6 lignes "
          "(relevé du 2026-08-31), et un `// x` suffirait ensuite ; (2) porter la raison en TROISIÈME "
          "ARGUMENT, forme lisible par une garde, fait ROUGIR "
          "`check_i18n_lexicon_covers_displayed_strings.py` — rejoué le 2026-08-31 sur `web/prefs.js` "
          "(plafond hors-regard 0) et `web/app.js` (plafond 22), les deux en rouge, et la ligne « JEU DU "
          "CLIQUET » du jour dit que les 48 plafonds sont AU RAS, donc les 9 sites seraient concernés, pas "
          "les deux qu'annonçait `P4.13-c`. Qu'un `return;` NU dans une "
          "capture n'apprenne rien à l'appelant (il est ACCUSÉ, mais `return undefined` explicite ne le "
          "serait pas) ; les LECTURES sous capture vide, hors de cette population — un refus de lecture rend "
          "ce que rend une clé absente, et l'initialisation de la variable fait office de repli, de sorte "
          "qu'un `catch` vide n'y est pas fautif par construction ; les deux formes d'appel sont reconnues "
          "ÉTROITEMENT (« en instruction » et « lu comme une valeur »), donc un appel qui ne tombe dans ni "
          "l'une ni l'autre — `t[0](k, v)`, un rappel passé en argument — n'est jugé par aucune des deux ; "
          "une fonction HOMONYME d'une porte, déclarée dans un module qui ne mute pas, serait jugée comme "
          "la porte (l'analyseur lexical ne suit pas les imports) ; que la capture soit assez ÉTROITE (un "
          "`try` qui enveloppe tout un gestionnaire la satisfait) ; les écritures faites depuis "
          "`index.html`, une chaîne évaluée, `document.cookie`, IndexedDB ou l'API Cache, qui ne sont pas le "
          "stockage de site ; et un magasin atteint par un alias (`const m = localStorage; m.setItem(…)`).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
