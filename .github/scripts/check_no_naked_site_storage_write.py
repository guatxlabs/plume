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

LE SEUL PLANCHER QUI SUBSISTE PORTE SUR LES ÉCRITURES, PAS SUR LES FAUTES. Si le corpus ne contient
AUCUNE écriture au stockage, la garde REFUSE DE CONCLURE au lieu de rendre un vert par vacuité : un
analyseur cassé trouve zéro écriture, exactement comme un dépôt qui n'en contient plus.
"""
import os
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CORPUS = os.path.join(RACINE, "web")

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

    Rend un dict {indice_de_jeton: bool}. Un `try` traversé par une frontière de fonction ne couvre
    rien : le rappel s'exécute plus tard, hors de la capture.
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
            couvert[k] = _est_couvert(pile, fleches)
            continue
        if t.genre != "op":
            couvert[k] = _est_couvert(pile, fleches)
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
                pile.append("try")
            elif attend_corps:
                pile.append("fonc")
            elif prec is not None and prec.genre == "op" and prec.valeur == ")":
                # `if (…) {` est un bloc ; `f(…) {` / `method(…) {` est un corps de fonction
                ouvreur = _ouvreur_de_la_parenthese(jetons, k - 1)
                est_controle = (ouvreur is not None and ouvreur.genre == "nom" and ouvreur.valeur in CONTROLE)
                pile.append("bloc" if est_controle else "fonc")
            else:
                pile.append("bloc")
            attend_corps = False
        elif v == "}":
            if pile:
                pile.pop()
        couvert[k] = _est_couvert(pile, fleches)
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


def _est_couvert(pile, fleches):
    dernier_try = max((i for i, g in enumerate(pile) if g == "try"), default=-1)
    dernier_fonc = max((i for i, g in enumerate(pile) if g == "fonc"), default=-1)
    if dernier_try < 0 or dernier_try < dernier_fonc:
        return False
    # une flèche à corps d'expression OUVERTE À L'INTÉRIEUR du `try` est une frontière de fonction
    if fleches and fleches[-1] > dernier_try:
        return False
    return True


def nues(texte):
    """Les écritures NON enclosés dans une capture de leur propre fonction : (ligne, forme)."""
    jetons = analyser(texte)
    couvre = couverture(jetons)
    return [(ligne, forme) for ligne, k, forme in ecritures(jetons) if not couvre.get(k, False)]


def toutes(texte):
    jetons = analyser(texte)
    return [(ligne, forme) for ligne, _k, forme in ecritures(jetons)]


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
    # témoin de l'analyseur lui-même : un texte illisible doit FAIRE REFUSER, pas rendre zéro
    for mauvais in ("const s = 'jamais refermée\n", "/* jamais refermé", "const t = `jamais refermé"):
        try:
            toutes(mauvais)
        except LectureImpossible:
            continue
        return "témoin « source illisible » : l'analyseur a conclu sur un texte qu'il ne sait pas lire"
    return None


def modules_du_corpus(racine):
    """Population DÉRIVÉE : tout `*.js` sous `web/`, lu sur le DISQUE (pas dans l'index du dépôt)."""
    trouves = []
    for dossier, _sous, fichiers in os.walk(racine):
        for f in sorted(fichiers):
            if f.endswith(".js"):
                trouves.append(os.path.join(dossier, f))
    return sorted(trouves)


def main():
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

    fautes, total_ecritures, modules_avec_ecriture = [], 0, 0
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
        couvre = couverture(jetons)
        vues = ecritures(jetons)
        if vues:
            modules_avec_ecriture += 1
        total_ecritures += len(vues)
        for ligne, k, forme in vues:
            if not couvre.get(k, False):
                fautes.append((rel, ligne, forme))

    # CONTRÔLE POSITIF : zéro écriture dans TOUT le corpus, c'est ce que rend un analyseur cassé.
    if total_ecritures == 0:
        print("::error::CONTRÔLE POSITIF PERDU — aucune écriture au stockage du site trouvée dans "
              f"{len(modules)} module(s) : c'est exactement ce que rendrait un analyseur cassé, donc la "
              "garde REFUSE DE CONCLURE au lieu de rendre un vert par vacuité.", file=sys.stderr)
        return 2

    for rel, ligne, forme in fautes:
        print(f"::error file={rel},line={ligne}::écriture NUE au stockage du site (`{forme}`) : chez un "
              "navigateur qui refuse le stockage, cet accès JETTE `SecurityError` AU MILIEU du geste — "
              "un état est déjà posé, la vue n'est pas repeinte, et l'exploitant n'a rien à lire. "
              "Passer par `ecrireDansLeStockageDuSite` (web/state.js), qui REND le refus, puis DIRE la "
              "perte (un `catch` vide l'échangerait contre une perte muette).", file=sys.stderr)

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
          f"pas un commentaire. {len(TEMOINS)} témoins FABRIQUÉS ICI valident l'instrument dans les deux "
          "sens, et zéro écriture dans tout le corpus fait REFUSER DE CONCLURE.\n"
          "CE QU'ELLE NE TIENT PAS : que le refus soit DIT à l'exploitant — une capture VIDE la satisfait, "
          "et elle échange l'état incohérent contre une perte MUETTE (cela se juge au banc ESM, sous "
          "`PLUME_HARNAIS_STOCKAGE_REFUSE=1`) ; que la capture soit assez ÉTROITE (un `try` qui enveloppe "
          "tout un gestionnaire la satisfait aussi) ; les écritures faites depuis `index.html`, une chaîne "
          "évaluée, `document.cookie`, IndexedDB ou l'API Cache, qui ne sont pas le stockage de site ; et "
          "un magasin atteint par un alias (`const m = localStorage; m.setItem(…)`), que l'analyseur "
          "lexical ne suit pas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
