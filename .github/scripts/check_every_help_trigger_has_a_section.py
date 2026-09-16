#!/usr/bin/env python3
"""Chaque déclencheur d'aide de la console ouvre une section qui existe — garde de CI (`P11.4-e`).

LE DÉFAUT. Un bouton « ? » porte `data-help="<clé>"` et l'ouvreur (`web/help.js`) lit `HELP[<clé>]` dans le
registre des sections (`web/help_registry.js`, contenu seul — `P11.4-e`).
Quand la section manque, rien ne le dit à l'écriture : le bouton « Jetons » est resté des semaines à ne
rien ouvrir (mesuré par le harnais ESM : zéro nœud rendu). Le guide intégré a le même trou, par un autre
chemin : une entrée de son sommaire (`{ k: '<clé>' }`) appelle le même ouvreur.

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE.
  DÉCLENCHEURS — tout ce qui, sous `web/`, finit dans `openHelp(<clé>)` avec une clé LITTÉRALE :
    (1) `data-help="<clé>"` dans `index.html` et dans les gabarits des modules (un gabarit est de l'HTML) ;
    (2) `dataset.help = '<clé>'` ;
    (3) `openHelp('<clé>')` ;
    (4) `{ k: '<clé>', … }` DANS LA PORTÉE du sommaire `HELP_INDEX` du guide, dont les entrées sont rendues
        en boutons. Cette portée est DÉRIVÉE de la définition `const HELP_INDEX = [ … ]`, comme celle du
        registre l'est de la sienne — le motif `{ k: … }` est trop banal pour être lâché sur tout `web/`,
        et le fichier qui l'héberge n'est pas une propriété du sommaire (`P11.13-d`).
    Le corpus est lu SANS ses commentaires : une clé citée dans un commentaire n'ouvre rien. Un déclencheur
    dont la clé est construite (`data-help="${x}"`) n'est pas décidable et n'est pas compté.

  CE QUE LE NOM DE FICHIER COÛTAIT, MESURÉ PAR MUTATION LE 2026-08-26 (`P11.13-d`). Le motif du sommaire
    n'était accepté que dans un fichier NOMMÉ `help.js`. En déplaçant la seule définition `const HELP_INDEX`
    dans un module voisin — un découpage banal, le dépôt en a déjà fait plusieurs — la garde tombait de
    **29 à 28 clés déclenchées et de 56 à 29 sites**, et restait VERTE : moins de déclencheurs vus, moins de
    contrôles à passer, aucun mot. Une seule clé (`processors`) n'était plus tenue par rien.
    LE CHIFFRE DE CADRAGE DE LA CELLULE EST RÉFUTÉ AU PASSAGE : elle annonçait « 28 déclencheurs distincts
    tombant à 1 ». Mesuré : 29 -> 28 en clés distinctes, 56 -> 29 en sites. Le mécanisme était juste, son
    ampleur non — `data-help` et `openHelp(` portent 28 des 29 clés à eux seuls, le sommaire n'en apporte
    qu'une que personne d'autre ne déclenche.

  LE COMPTE VU EST GARDÉ PAR UN CLIQUET (`P11.13-d`). Une garde de couverture ne rougit pas quand elle voit
    MOINS : elle a moins de contrôles à passer, donc elle verdit. Le compte des SITES est donc un PLANCHER —
    c'est lui qui s'effondre quand une portée est perdue (56 -> 29 sur la mutation ci-dessus, quand les clés
    distinctes ne bougeaient que de 1) et c'est lui que la garde contrôle réellement. Le nombre de clés
    distinctes est PUBLIÉ et non gardé : il baisse légitimement quand deux déclencheurs sont ramenés sur une
    même section, et le garder ferait rougir un remaniement qui ne perd aucune couverture.
    Le sens inverse n'a PAS besoin de cliquet, et c'est dit : moins de SECTIONS fait rougir la garde toute
    seule (des déclencheurs se retrouvent sans section). C'est la seule asymétrie, elle est mesurée.
  SECTIONS — les clés de premier niveau de l'objet `const HELP = { … }`, lues en suivant la profondeur des
    accolades hors chaînes et gabarits (les corps d'aide contiennent des accolades). Le MODULE qui porte
    cette définition est lui-même DÉRIVÉ (le seul fichier de `web/` qui la contient, commentaires retirés) :
    le registre peut changer de fichier sans qu'aucune garde le perde. Zéro ou plusieurs porteurs = la
    dérivation ne conclut pas.
  VERDICT — un déclencheur sans section est une ERREUR (l'ouvreur rendrait un aveu à l'utilisateur : la
    garde l'attrape avant). Une section sans déclencheur est rendue POUR INFORMATION : elle n'est pas un
    défaut (une section peut être ouverte par une entrée du sommaire ou par un appel direct, tous deux
    comptés ici comme déclencheurs ; ce qui reste est une section que rien n'ouvre, à relire, pas à rougir).

L'INSTRUMENT SE VALIDE AVANT DE JUGER : un corpus témoin où un déclencheur sans section DOIT rougir, où un
déclencheur cité en commentaire NE DOIT PAS compter, où une section sans déclencheur est rendue en
information seulement, et où le registre, déplacé sous un autre nom, est retrouvé — et ne l'est plus s'il
est absent ou défini deux fois. Il refuse de conclure sous un plancher de déclencheurs et de sections. Cette
garde lit `web/` seulement : elle ne se lit pas elle-même, ni le harnais, qui citent le motif.
La dérivation du module du registre et de la PORTÉE de sa définition (`portee_du_registre`) est importée par
`check_i18n_lexicon_covers_displayed_strings.py`, qui exempte cette portée seule — pas le module — de son
plafond de trous (source unique : une règle écrite deux fois diverge).

CE FICHIER HÉBERGE AUSSI LE LECTEUR RUST PARTAGÉ (`sans_commentaires_rust`, quatre gardes le lisent).
LE DÉFAUT, VU LE 2026-09-16 (`P10.20-c`) : il prenait TOUTE apostrophe pour une durée de vie, donc le
littéral de caractère `'"'` (métacaractères d'interpréteur, `daemon/src/handlers/actions.rs`) ouvrait une
FAUSSE chaîne et le dépouillement repartait de travers jusqu'au guillemet suivant — dans un sens un
COMMENTAIRE lu comme du code (une accusation fabriquée), dans l'autre du CODE lu comme un commentaire
(une garde aveugle, sans un mot). CE QU'IL TIENT DÉSORMAIS : les littéraux de caractère `'x'` et d'octet
`b'"'`, leurs séquences d'échappement (la liste exacte est écrite au-dessus de `RE_CARACTERE_RUST` — une
chaîne Python ne peut pas les porter sans les interpréter), et les durées de vie et étiquettes de boucle
`'a`, `'static`, `'_`, `'outer:` (témoins dans `temoins_du_lecteur`).
LES CHAÎNES BRUTES SONT TENUES DEPUIS LE 2026-09-16 (`P10.20-d`) : `r"…"`, `r#"…"#`, `r##"…"##` et les
formes d'octets ou de chaîne C (`br#"…"#`, `cr#"…"#`) sont lues jusqu'au `"` suivi d'AUTANT de dièses que
l'ouvrant en portait, puis rendues telles quelles ; un identifiant brut (`r#type`) n'en est pas une. Lues
comme des chaînes ordinaires, elles fermaient sur le premier `"` posé dedans : DEUX fichiers du corpus
(`agent/src/config.rs`, `collector-mail/src/url_extract.rs`) faisaient AVOUER le lecteur, et aucun de ses
quatre consommateurs ne lui passait le `journal` qui porte cet aveu — il avouait dans le vide. Les quatre
le passent désormais, et `refuser_sur_aveu` en fait un REFUS DE CONCLURE.
CE QU'IL NE TIENT PAS, ÉCRIT ICI : le corps des
MACROS (`macro_rules!` peut porter des apostrophes de fragment `$l:lifetime` et du texte qui n'est pas du
Rust), les apostrophes d'un ATTRIBUT ou d'une chaîne de documentation `#[doc = "…'…"]` (elles sont dans
une chaîne, donc sautées — mais rien ne vérifie l'attribut lui-même), et le CODE GÉNÉRÉ, que ce dépôt ne
relit pas. Ce lecteur reste un DÉPOUILLEUR, pas un analyseur syntaxique Rust.
"""
import os, re, subprocess, sys

PLANCHER_SECTIONS = 20
# CLIQUET DES DÉCLENCHEURS VUS (`P11.13-d`) — relevé sur l'arbre le 2026-08-26 : 56 SITES de déclenchement.
# C'est un PLANCHER, et le sens est écrit : une garde de couverture qui voit MOINS a moins de contrôles à
# passer, donc elle VERDIT — une chute est un échec, jamais un silence.
# POURQUOI LES SITES ET NON LES CLÉS DISTINCTES, mesuré le même jour : c'est le compte des SITES qui
# s'effondre quand une PORTÉE est perdue (le sommaire déplacé hors de son fichier : 56 -> 29 sites, mais
# 29 -> 28 clés seulement), et c'est lui que la garde CONTRÔLE réellement — un site sans section est ce
# qu'elle refuse. Le nombre de clés distinctes, lui, baisse légitimement quand deux déclencheurs sont
# ramenés sur une même section : le garder ferait rougir un remaniement qui ne perd aucune couverture.
# Il reste PUBLIÉ à chaque exécution, il n'est pas gardé.
# Le sens inverse n'a PAS besoin de cliquet, et c'est dit : moins de SECTIONS fait rougir la garde toute
# seule (des déclencheurs se retrouvent sans section). C'est la seule asymétrie, elle est mesurée.
# Abaisser ce nombre exige une raison écrite ici, à côté du chiffre ; le relever est le sens attendu.
CLIQUET_SITES_DECLENCHEURS = 56
CLE = r"([A-Za-z][\w-]*)"
# La définition du registre : `const HELP = {` (exporté ou non), hors commentaires. Même ancre pour le
# localiser dans `web/` et pour en lire les clés.
RE_DEFINITION_DU_REGISTRE = re.compile(r"\bconst HELP\s*=\s*\{")
# La définition du SOMMAIRE du guide : `const HELP_INDEX = [ … ]`. C'est l'ancre du quatrième motif —
# la PROPRIÉTÉ qui distingue le sommaire, là où un nom de fichier ne disait que son hébergement du jour.
RE_DEFINITION_DU_SOMMAIRE = re.compile(r"\bconst HELP_INDEX\s*=\s*\[")
SOMMAIRE = "sommaire"  # portée dérivée, pas un nom de fichier
MOTIFS_DECLENCHEUR = [  # (motif, portée où il vaut — None : partout sous web/ ; SOMMAIRE : dans HELP_INDEX)
    (re.compile(r"""data-help\s*=\s*["']""" + CLE + r"""["']"""), None),
    (re.compile(r"""dataset\.help\s*=\s*["'`]""" + CLE + r"""["'`]"""), None),
    (re.compile(r"""\bopenHelp\(\s*["'`]""" + CLE + r"""["'`]\s*\)"""), None),
    # `{ k: '…' }` est un motif BANAL : lâché sur tout `web/` il accuserait le premier objet venu portant une
    # clé `k`. Il ne vaut donc que DANS la portée dérivée de `const HELP_INDEX = [ … ]`, où qu'elle vive.
    (re.compile(r"""\{\s*k:\s*["']""" + CLE + r"""["']"""), SOMMAIRE),
]


# =====================================================================================================
# LE LECTEUR JAVASCRIPT — ÉCRIT UNE FOIS, IMPORTÉ PAR LES GARDES SŒURS (`P11.8-f`)
# =====================================================================================================
# POURQUOI ICI. Cinq fonctions de lecture recopiées dans quatre gardes portaient la MÊME cécité, écrite
# quatre fois : aucune ne reconnaissait le LITTÉRAL D'EXPRESSION RÉGULIÈRE. Deux formes, toutes deux
# mesurées le 2026-08-24 sur `web/` :
#   (1) une séquence `/*` DANS un motif (`/a\/*b/`) était prise pour une ouverture de commentaire, et
#       tout ce qui suivait était blanchi — perte silencieuse ;
#   (2) un `"` ou un `'` DANS un motif ouvrait une fausse chaîne, et les commentaires de la région
#       jusqu'au guillemet suivant N'ÉTAIENT PLUS RETIRÉS — une clé citée en commentaire redevenait un
#       déclencheur. Mesuré : `core.js` 124 lignes, `viz.js` 4 lignes, `app.js` 2 lignes de code MANGÉES
#       (`/^\/api\//` : le `//` final lu comme un commentaire de ligne).
# Le geste est celui de `sans_commentaires_css`, que la garde du chrome IMPORTE au lieu de la recopier :
# une règle de lecture écrite deux fois finit par diverger, et ici elle avait divergé quatre fois sans
# que rien ne rougisse. La règle de désambiguïsation du `/` est celle de `P11.8-e`, désormais unique
# pour tout le dépôt (la garde du lexique l'importe d'ici au lieu de la porter).
#
# LA DÉSAMBIGUÏSATION DU `/`. En JavaScript, `/` est soit une division, soit le début d'une expression
# régulière, et rien dans le caractère ne le dit : c'est le JETON PRÉCÉDENT qui tranche. RÈGLE RETENUE :
# le `/` ouvre une expression régulière si le dernier caractère significatif qui le précède est un début
# d'expression — rien (début de source), une ouvrante ou un opérateur, ou l'un des mots-clés `return` /
# `typeof` / `case`.
# CE QU'ELLE NE SAIT PAS FAIRE, ÉCRIT À CÔTÉ D'ELLE : elle tranche sur un caractère, pas sur une
# grammaire. Après `)` et après `]` elle dit TOUJOURS division — vrai pour `(a + b) / 2`, FAUX pour
# `if (x) /re/.test(y)`. Les mots-clés hors de la liste (`in`, `of`, `new`, `delete`, `void`, `do`,
# `else`, `yield`, `await`) suivis d'une expression régulière sont lus comme des divisions. C'est
# pourquoi la règle est DOUBLÉE d'un AVEU (`journal`) : le lecteur surveille ce qu'un module valide ne
# peut PAS produire — une chaîne `'…` / `"…` qui se termine sur une fin de ligne, un littéral qui atteint
# la fin du fichier — et l'appelant refuse alors de conclure (code 2) en NOMMANT la ligne, au lieu de
# rendre un compte amputé en vert. Un instrument qui blanchit une région ne se plaint jamais : il rend un
# chiffre plus petit, et rien ne le distingue d'un code plus propre.
RE_AVANT_REGEX = re.compile(r"(?:^|[\(\[,=:!&|?{};+\-*%<>~^]|\breturn|\btypeof|\bcase)\s*$")
# Délimiteurs de chaîne par langage. En Rust, `'` n'ouvre PAS une chaîne : il ouvre soit une DURÉE DE VIE
# (`&'static str`), soit un LITTÉRAL DE CARACTÈRE (`'"'`, `'\n'`, `b'"'`) — et le lire toujours comme le
# premier est ce qui faisait dérailler le dépouillement (`P10.20-c`). Il n'y a pas de gabarit, et `/` est
# toujours une division : pas de littéral d'expression régulière.
CHAINES_JS, CHAINES_RUST = "\"'`", '"'
# UN LITTÉRAL DE CARACTÈRE RUST, ANCRÉ SUR SON APOSTROPHE OUVRANTE (`P10.20-c`, mesuré le 2026-09-16) :
# `'` + UN caractère, ou une séquence d'échappement (`\n`, `\'`, `\\`, `\"`, `\x41`, `\u{1F600}`), + `'`.
# Un littéral d'OCTET `b'"'` est la même forme — l'apostrophe est au même endroit, le `b` qui précède est
# du code ordinaire. Ce que ce motif N'APPARIE PAS est une durée de vie ou une étiquette de boucle (`'a`,
# `'static`, `'_`, `'outer:`) : en Rust valide, aucune des deux n'est JAMAIS suivie d'une apostrophe, et
# c'est ce qui rend la règle décidable avec un seul caractère d'avance. La fin de ligne est exclue des
# deux côtés : un littéral de caractère ne la franchit pas, et l'exclure empêche une apostrophe isolée
# (`// don't`, déjà retiré par ailleurs) d'avaler la suite du fichier.
RE_CARACTERE_RUST = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|[^\n])|[^\\'\n])'")
# UNE CHAÎNE BRUTE RUST, ANCRÉE SUR SON PRÉFIXE (`P10.20-d`, mesuré le 2026-09-16) : `r"…"`, `r#"…"#`,
# `r##"…"##`, et les formes d'octets `br#"…"#` ou de chaîne C `cr#"…"#`. IL N'Y A AUCUNE SÉQUENCE
# D'ÉCHAPPEMENT DEDANS : elle se ferme au premier `"` suivi d'AUTANT de dièses que l'ouvrant en portait,
# et un `"` seul — ou suivi de TROP PEU de dièses — n'y est qu'un caractère. Lue comme une chaîne
# ordinaire, `Regex::new(r#"https?://[^\s<>"'\)\]\}]+"#)` (collector-mail/src/url_extract.rs:19) fermait
# sur le `"` de sa classe de caractères, et le dépouillement repartait à contretemps jusqu'à la fin du
# fichier : un AVEU que personne n'écoutait.
# UN IDENTIFIANT BRUT (`r#type`, `r#fn`) N'EST PAS UNE CHAÎNE : le motif exige le guillemet APRÈS les
# dièses, donc `r#type` n'apparie pas et le `r` repart dans le code. Et le préfixe ne vaut qu'en DÉBUT
# DE JETON (`_prefixe_brut_rust`) : la fin d'un nom ne doit jamais ouvrir une chaîne.
RE_OUVERTURE_BRUTE_RUST = re.compile(r'(?:b|c)?r(#*)"')


def journaliser_perte(journal, motif, depart):
    """L'AVEU. `depart` = l'offset où le faux littéral s'est OUVERT : c'est l'endroit où le lecteur
    S'APERÇOIT de la perte, pas nécessairement celui où elle a commencé."""
    if journal is not None:
        journal.append((motif, depart))


def saute_regex(src, i):
    """`src[i]` est le `/` ouvrant d'un littéral d'expression régulière : rend l'index APRÈS le `/`
    fermant et ses drapeaux. Un `/` à l'intérieur d'une classe `[…]` ne ferme pas, et une expression
    régulière ne franchit pas une fin de ligne."""
    j, n, in_cls = i + 1, len(src), False
    while j < n and src[j] != "\n":
        if src[j] == "\\":
            j += 2; continue
        if src[j] == "[":
            in_cls = True
        elif src[j] == "]":
            in_cls = False
        elif src[j] == "/" and not in_cls:
            break
        j += 1
    j += 1
    while j < n and src[j].isalpha():
        j += 1
    return j


def saute_chaine(src, i, journal=None, multiligne=False):
    """`src[i]` est le guillemet ouvrant : rend l'index APRÈS le fermant. `multiligne` vaut pour les
    chaînes qui ont le droit de franchir une fin de ligne (Rust) ; en JavaScript une chaîne `'…` ou `"…`
    n'en a pas le droit, et y arriver PROUVE que ce guillemet n'ouvrait pas une chaîne."""
    q, j, n = src[i], i + 1, len(src)
    while j < n:
        if src[j] == "\\":
            j += 2; continue
        if src[j] == q:
            return j + 1
        if src[j] == "\n" and not multiligne:
            journaliser_perte(journal, "une chaîne « ' » ou « \" » se termine sur une fin de ligne", i)
            return j
        j += 1
    journaliser_perte(journal, "un littéral atteint la fin du fichier sans son guillemet fermant", i)
    return n


def _prefixe_brut_rust(src, i):
    """`src[i]` peut-il ouvrir une chaîne brute ? Vrai pour `r`, `br`, `cr` EN DÉBUT DE JETON — le
    caractère qui précède ne doit pas être un caractère d'identifiant, sinon la fin d'un nom ouvrirait
    une fausse chaîne. Le filtre est là pour ne tenter l'appariement que là où il peut aboutir."""
    if src[i] not in "rbc":
        return False
    if src[i] != "r" and not src.startswith("r", i + 1):
        return False
    return i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")


def saute_chaine_brute_rust(src, i, journal=None):
    """`src[i]` est le premier caractère du PRÉFIXE d'une chaîne brute Rust : rend l'index APRÈS son
    délimiteur fermant, ou None si ce n'en est pas une (le caractère repart alors dans le code — c'est
    le cas d'un identifiant brut `r#type` et de tout `r` ordinaire). Le délimiteur fermant est `"`
    suivi d'EXACTEMENT autant de dièses que l'ouvrant ; il n'y a pas d'échappement à respecter, le
    premier qui apparaît ferme."""
    m = RE_OUVERTURE_BRUTE_RUST.match(src, i)
    if not m:
        return None
    ferme = '"' + m.group(1)
    j = src.find(ferme, m.end())
    if j < 0:
        journaliser_perte(journal, f"une chaîne brute ouverte par `{m.group(0)}` atteint la fin du "
                                   f"fichier sans son délimiteur fermant `{ferme}`", i)
        return len(src)
    return j + len(ferme)


def saute_gabarit(src, i, journal=None):
    """`src[i]` est l'accent grave ouvrant : rend l'index APRÈS le fermant, EN SAUTANT LES
    INTERPOLATIONS `${…}` (accolades équilibrées, chaînes, gabarits ET littéraux d'expression régulière
    imbriqués). Sans le saut d'interpolation, un accent grave posé DANS un `${…}` refermerait le gabarit
    trop tôt et tout ce qui suit serait lu à contretemps."""
    j, n = i + 1, len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2; continue
        if c == "`":
            return j + 1
        if c == "$" and j + 1 < n and src[j + 1] == "{":
            prof, j, expr = 1, j + 2, []
            while j < n and prof:
                ch = src[j]
                if ch in "'\"":
                    j = saute_chaine(src, j, journal); expr.append('""'); continue
                if ch == "`":
                    j = saute_gabarit(src, j, journal); expr.append('""'); continue
                if ch == "/" and RE_AVANT_REGEX.search("".join(expr[-40:])):
                    j = saute_regex(src, j); expr.append("/re/"); continue
                if ch == "{":
                    prof += 1
                elif ch == "}":
                    prof -= 1
                expr.append(ch); j += 1
            continue
        j += 1
    journaliser_perte(journal, "un gabarit `…` atteint la fin du fichier sans son accent grave fermant", i)
    return n


def _blanc(texte):
    """Des blancs de MÊME HAUTEUR : les numéros de ligne rendus restent ceux du fichier."""
    return re.sub(r"[^\n]", " ", texte)


def _sans_commentaires(src, delimiteurs, regex_litterales, journal, grammaire_rust=False):
    out, i, n, code = [], 0, len(src), []
    while i < n:
        c = src[i]
        if c in delimiteurs:
            f = saute_gabarit(src, i, journal) if c == "`" else \
                saute_chaine(src, i, journal, multiligne=(delimiteurs == CHAINES_RUST))
            out.append(src[i:f]); code.append('""'); i = f; continue
        if grammaire_rust and _prefixe_brut_rust(src, i):
            # La chaîne BRUTE se ferme sur son propre délimiteur, jamais sur un `"` posé dedans : elle
            # est rendue telle quelle, comme une chaîne. Ce qui n'en est pas une (`r#type`, un `r`
            # ordinaire) rend None et repart dans le code, sans rien ouvrir.
            f = saute_chaine_brute_rust(src, i, journal)
            if f is not None:
                out.append(src[i:f]); code.append('""'); i = f; continue
        if grammaire_rust and c == "'":
            # Le littéral de caractère est rendu TEL QUEL (comme une chaîne l'est) ; ce qui n'en est pas
            # un est une durée de vie, et l'apostrophe repart dans le code, seule, sans rien ouvrir.
            m = RE_CARACTERE_RUST.match(src, i)
            if m:
                out.append(m.group(0)); code.append("'c'"); i = m.end(); continue
            out.append(c); code.append(c); i += 1; continue
        if src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2); f = n if j < 0 else j + 2
            out.append(_blanc(src[i:f])); i = f; continue
        if regex_litterales and c == "/" and RE_AVANT_REGEX.search("".join(code[-40:])):
            f = saute_regex(src, i); out.append(src[i:f]); code.append("/re/"); i = f; continue
        out.append(c); code.append(c); i += 1
    return "".join(out)


def sans_commentaires_js(src, journal=None):
    """Retire `//…` et `/*…*/` en respectant les chaînes ('', "", ``) ET les littéraux d'expression
    régulière : un `//` dans une URL reste, un `/*` ou un `"` dans un motif n'ouvre plus rien.
    Un commentaire de bloc devient des blancs de même hauteur ; les lignes rendues sont celles du
    fichier. `journal` (facultatif) recueille les AVEUX de perte de synchronisation."""
    return _sans_commentaires(src, CHAINES_JS, True, journal)


def sans_commentaires_rust(src, journal=None):
    """Le même dépouillement pour du Rust : `"` seul délimite une chaîne, elle peut franchir une fin de
    ligne, et `/` est toujours une division. L'APOSTROPHE EST DÉSAMBIGUÏSÉE (`P10.20-c`, 2026-09-16) :
    `'x'`, `b'"'` et les séquences d'échappement (liste au-dessus de `RE_CARACTERE_RUST`) sont des LITTÉRAUX
    DE CARACTÈRE rendus tels quels ; `'a`, `'static`, `'_`, `'outer:` sont des durées de vie et
    étiquettes. LA CHAÎNE BRUTE EST TENUE (`P10.20-d`, 2026-09-16) : `r"…"`, `r#"…"#`, `r##"…"##`,
    `br#"…"#` et `cr#"…"#` sont lues jusqu'au `"` suivi d'AUTANT de dièses que l'ouvrant en portait, donc
    un `"` ou un `"#` posé dedans ne ferme plus rien ; un identifiant brut `r#type` n'est pas une chaîne.
    Avant ces deux correctifs, le `"` de `'"'` ou celui d'une chaîne brute ouvrait une fausse chaîne et
    tout ce qui suivait était lu à contretemps jusqu'au guillemet suivant : un commentaire redevenait du
    code (accusation fabriquée) et, de l'autre côté du guillemet, du code devenait un commentaire (cécité
    muette). CE QUI RESTE NON COUVERT, ET C'EST DIT : le corps des MACROS (`macro_rules!` porte des
    apostrophes de fragment et du texte qui n'est pas du Rust), les apostrophes d'un ATTRIBUT et le CODE
    GÉNÉRÉ ne sont pas des grammaires que ce dépouilleur connaît.
    `journal` (facultatif) recueille les AVEUX de perte de synchronisation : le passer est ce qui
    distingue un refus de conclure d'un compte amputé rendu en vert (`P10.20-d`)."""
    return _sans_commentaires(src, CHAINES_RUST, False, journal, grammaire_rust=True)


def aveugler_litteraux_js(src, journal=None):
    """MÊME LONGUEUR que `src`, le CONTENU des littéraux (chaînes, gabarits, expressions régulières)
    remplacé par des blancs de même hauteur : les accolades et les guillemets d'un littéral ne comptent
    plus dans l'appariement des blocs. Sans la reconnaissance de l'expression régulière, un `"` posé dans
    un motif (`/[|\\[\\]"\\n\\r]/g`, `web/viz.js`) ouvrait une fausse chaîne et blanchissait les accolades
    de tout ce qui suivait — mesuré le 2026-08-24 : 8 portées de fonction lues au lieu de 138."""
    out, i, n, code = [], 0, len(src), []
    while i < n:
        c = src[i]
        if c in CHAINES_JS:
            f = saute_gabarit(src, i, journal) if c == "`" else saute_chaine(src, i, journal)
            # les deux délimiteurs restent en place, le contenu devient des blancs : la longueur ne bouge
            # pas (les offsets rendus sont ceux du texte reçu). Un littéral que l'aveu dit NON FERMÉ n'a
            # pas de délimiteur de fin à conserver.
            ferme = f - 1 > i and src[f - 1] == c
            out.append(c + _blanc(src[i + 1:f - 1] if ferme else src[i + 1:f]) + (src[f - 1] if ferme else ""))
            code.append('""'); i = f; continue
        if src.startswith("//", i):
            j = src.find("\n", i); f = n if j < 0 else j
            out.append(_blanc(src[i:f])); i = f; continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2); f = n if j < 0 else j + 2
            out.append(_blanc(src[i:f])); i = f; continue
        if c == "/" and RE_AVANT_REGEX.search("".join(code[-40:])):
            f = saute_regex(src, i)
            out.append(src[i] + _blanc(src[i + 1:f])); code.append("/re/"); i = f; continue
        out.append(c); code.append(c); i += 1
    return "".join(out)[:n]


# LA CAUSE LA PLUS FRÉQUENTE, PAR LANGAGE — la seule partie du refus qui diffère. Une seule phrase par
# lecteur : écrite deux fois, elle finirait par nommer un remède que le lecteur n'applique plus.
CAUSE_DE_DESYNCHRONISATION = {
    "JavaScript": "un `/` que la règle de désambiguïsation (jeton précédent, cf. `RE_AVANT_REGEX`) a pris "
                  "pour une division alors qu'il ouvrait une expression régulière — après `)` ou `]`, "
                  "typiquement `if (x) /re/.test(y)`. Écrire `if (x) { return /re/.test(y); }` ou "
                  "`new RegExp(…)`, ou apprendre la forme à `RE_AVANT_REGEX`.",
    "Rust": "une grammaire que le dépouilleur ne connaît pas et qui pose un `\"` — le corps d'une MACRO, "
            "une apostrophe d'ATTRIBUT, du code GÉNÉRÉ — ou une chaîne, brute ou non, qui n'est vraiment "
            "jamais fermée. Les chaînes brutes `r\"…\"`, `r#\"…\"#`, `r##\"…\"##`, `br#\"…\"#` et les "
            "littéraux de caractère `'\"'` sont tenus (`P10.20-c`, `P10.20-d`) ; ce qui reste hors "
            "grammaire est écrit en tête de `sans_commentaires_rust`.",
}


def refuser_sur_aveu(etiquette, aveux, langage="JavaScript"):
    """L'AVEU RENDU À L'APPELANT. `aveux` = {fichier: ["ligne N : motif", …]}. Imprime chaque aveu et rend
    True — l'appelant SORT alors en code 2 sans verdict. Un lecteur qui a ouvert un littéral qui n'en était
    pas un a AVALÉ du code : tout ce qu'il a compté depuis est faux, et un compte amputé rendu en vert est
    pire qu'une garde absente. C'est ce qu'un `"` dans une expression régulière a fait pendant un jour sur
    `web/viz.js` (118 littéraux perdus, `P11.8-e`).
    `langage` nomme le lecteur qui a avoué — le défaut de `JavaScript` garde la phrase des sept gardes qui
    l'appelaient déjà ; les quatre consommateurs du lecteur RUST passent `"Rust"` (`P10.20-d`), sans quoi
    le refus nommerait une cause qui n'existe pas dans le fichier accusé."""
    for fichier, lignes in sorted(aveux.items()):
        for ligne in lignes:
            print(f"::error::{fichier}:{ligne} — le lecteur {langage} a PERDU LA SYNCHRONISATION : il a "
                  f"ouvert un littéral qui n'en est pas un, et tout ce qu'il a lu depuis est faux. Cause la "
                  f"plus fréquente : {CAUSE_DE_DESYNCHRONISATION[langage]}")
    print(f"[{etiquette}] REFUS DE CONCLURE — le lecteur avoue avoir sauté une région ; il ne rend pas un "
          f"compte amputé en vert.")
    return True


def sans_commentaires_html(src):
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)


def declencheurs(corpus, sommaire=None):
    """{clé: [fichier:ligne, …]} — chaque déclencheur à clé littérale du corpus (textes sans commentaires).

    `sommaire` = (nom du module, (début, fin)) de la définition `const HELP_INDEX = [ … ]`, DÉRIVÉE par
    `portee_du_sommaire` — jamais un nom de fichier écrit ici (`P11.13-d`). Le motif `{ k: … }` ne vaut que
    dans cette fenêtre : hors d'elle il accuserait n'importe quel objet portant une clé `k`. Sans sommaire
    dérivé, le motif ne vaut NULLE PART — et l'appelant refuse alors de conclure plutôt que de rendre un
    compte amputé en vert."""
    trouves = {}
    for nom, texte in corpus.items():
        for motif, portee in MOTIFS_DECLENCHEUR:
            if portee is SOMMAIRE:
                if not sommaire or sommaire[0] != nom: continue
                sites = motif.finditer(texte, sommaire[1][0], sommaire[1][1])
            elif portee and nom != portee: continue
            else:
                sites = motif.finditer(texte)
            for m in sites:
                trouves.setdefault(m.group(1), []).append(f"{nom}:{texte.count(chr(10), 0, m.start()) + 1}")
    return trouves


def _module_qui_definit(corpus_js, ancre):
    """Nom du SEUL module de `web/` (textes sans commentaires) où `ancre` apparaît ; None si aucun ou
    plusieurs — la dérivation ne tranche pas à la place de qui lit."""
    porteurs = sorted(nom for nom, texte in corpus_js.items() if nom.endswith(".js") and ancre.search(texte))
    return porteurs[0] if len(porteurs) == 1 else None


def module_du_registre(corpus_js):
    """Nom du SEUL module (textes sans commentaires) qui définit `const HELP = { … }` ; None si aucun ou plusieurs."""
    return _module_qui_definit(corpus_js, RE_DEFINITION_DU_REGISTRE)


def module_du_sommaire(corpus_js):
    """Nom du SEUL module qui définit `const HELP_INDEX = [ … ]` ; None si aucun ou plusieurs (`P11.13-d`)."""
    return _module_qui_definit(corpus_js, RE_DEFINITION_DU_SOMMAIRE)


def _portee_appariee(texte, depart, ouvrant, fermant, journal=None):
    """(début, fin) du bloc ouvert par le caractère d'index `depart - 1` : appariement `ouvrant`/`fermant`
    HORS LITTÉRAUX (le saut est celui du LECTEUR PARTAGÉ, sinon une accolade de chaîne ou une expression
    régulière déplacerait la fin). `fin` = index APRÈS le fermant ; None si le bloc n'est pas refermé."""
    i, n, prof, code = depart, len(texte), 1, []
    while i < n and prof:
        c = texte[i]
        if c in CHAINES_JS:
            i = saute_gabarit(texte, i, journal) if c == "`" else saute_chaine(texte, i, journal)
            code.append('""'); continue
        if c == "/" and RE_AVANT_REGEX.search("".join(code[-40:])):
            i = saute_regex(texte, i); code.append("/re/"); continue
        if c == ouvrant: prof += 1
        elif c == fermant: prof -= 1
        code.append(c); i += 1
    return None if prof else (i,)


def portee_du_sommaire(texte, journal=None):
    """(début, fin) de la définition `const HELP_INDEX = [ … ]` — la fenêtre où le motif `{ k: … }` du
    sommaire vaut. None si la définition est absente ou son crochet jamais refermé (`P11.13-d`)."""
    m = RE_DEFINITION_DU_SOMMAIRE.search(texte)
    if not m:
        return None
    fin = _portee_appariee(texte, m.end(), "[", "]", journal)
    return (m.start(), fin[0]) if fin else None


def _parcourir_registre(help_js, journal=None):
    """Parcourt `const HELP = { … }` par profondeur d'accolades hors littéraux ; rend
    (clés de premier niveau, index du début de la définition, index après l'accolade fermante), ou None.
    Le saut de littéral est celui du LECTEUR PARTAGÉ (`P11.8-f`) : un corps d'aide contient des accolades,
    et une expression régulière posée dans le registre y ouvrirait sinon une fausse chaîne."""
    debut = RE_DEFINITION_DU_REGISTRE.search(help_js)
    if not debut: return None
    i, n, prof, cles, ligne_vide = debut.end(), len(help_js), 1, set(), True
    code = []
    while i < n and prof > 0:
        c = help_js[i]
        if c in CHAINES_JS:
            i = saute_gabarit(help_js, i, journal) if c == "`" else saute_chaine(help_js, i, journal)
            code.append('""'); ligne_vide = False; continue
        if c == "/" and RE_AVANT_REGEX.search("".join(code[-40:])):
            # un `"` posé dans un motif ouvrirait une fausse chaîne et AVALERAIT l'accolade fermante de
            # l'entrée : les clés suivantes cesseraient d'être de premier niveau, en silence (`P11.8-f`).
            i = saute_regex(help_js, i); code.append("/re/"); ligne_vide = False; continue
        if c == "{": prof += 1
        elif c == "}": prof -= 1
        elif prof == 1 and ligne_vide:
            m = re.match(r"\s*" + CLE + r"\s*:", help_js[i:])
            if m: cles.add(m.group(1)); i += m.end(); ligne_vide = False; code.append('k:'); continue
        ligne_vide = c == "\n" or (ligne_vide and c.isspace())
        code.append(c); i += 1
    return cles, debut.start(), i


def sections(help_js, journal=None):
    """Clés de premier niveau de `const HELP = { … }`, par profondeur d'accolades hors littéraux."""
    p = _parcourir_registre(help_js, journal)
    return p[0] if p else set()


def portee_du_registre(help_js, journal=None):
    """(début, fin) de la définition `const HELP = { … }` dans le texte — la SURFACE du contenu d'aide, que la
    garde du lexique exempte sans exempter le module qui la porte ; None si la définition est absente."""
    p = _parcourir_registre(help_js, journal)
    return (p[1], p[2]) if p else None


def juger(corpus, help_js, sommaire=None, journal=None):
    decl, sect = declencheurs(corpus, sommaire), sections(help_js, journal)
    sans_section = {k: v for k, v in decl.items() if k not in sect}
    sans_declencheur = sorted(sect - set(decl))
    return decl, sect, sans_section, sans_declencheur


def temoins_du_lecteur():
    """LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR — dans les DEUX SENS (`P11.8-f`).
    Un dépouilleur ne rougit jamais quand il se trompe : il rend un texte plus court (il a mangé du code)
    ou plus long (il n'a pas retiré un commentaire), et les deux passent pour un verdict. Chaque forme
    mesurée sur `web/` le 2026-08-24 a donc son témoin, et le témoin INVERSE épingle qu'à force de ne plus
    prendre un motif pour un commentaire, le lecteur n'est pas devenu aveugle aux vrais commentaires."""
    # (1) `/*` DANS un motif : ce n'était pas une ouverture de commentaire, la suite ne disparaît pas.
    assert "garde" in sans_commentaires_js("const re = /a\\/*b/;\nconst a = 'garde';"), \
        "témoin : un `/*` dans une expression régulière blanchit encore tout ce qui suit"
    # (2) `"` ou `'` DANS un motif : n'ouvre pas de fausse chaîne, donc le commentaire d'après EST retiré.
    # RÉFUTÉ EN CHEMIN — un motif à NOMBRE PAIR de guillemets (`/name\s*=\s*'(\w+)'/`, `web/viz.js`) ne
    # désynchronise PAS le lecteur d'avant : les deux faux guillemets s'apparient et il se recale seul.
    # Ce qui mord est le nombre IMPAIR, et c'est la forme qui existe sur l'arbre (`/[&<>"]/g`, `web/core.js`).
    for motif in ('/[&<>"]/g', "/[\",\\n\\r]/", "/l'un/"):
        lu = sans_commentaires_js("const e = " + motif + ";\n// data-help=\"fantome\"\nconst b = 2;")
        assert "fantome" not in lu, f"témoin : après {motif}, un commentaire n'est plus retiré (fausse chaîne ouverte)"
        assert "const b = 2;" in lu, f"témoin : après {motif}, le code qui suit a disparu"
    # (3) `//` DANS un motif (`/^\/api\//`) : ce n'est pas un commentaire de ligne, la fin de ligne reste.
    assert ".test(path)" in sans_commentaires_js("if (x && /^\\/api\\//.test(path)) { y(); }"), \
        "témoin : un `//` dans une expression régulière mange encore la fin de la ligne"
    # (4) INVERSE — les vrais commentaires sont toujours retirés, et une URL dans une chaîne reste.
    assert "secret_ligne" not in sans_commentaires_js("const a = 1; // secret_ligne\nconst b = 2;"), \
        "témoin inverse : un commentaire de ligne n'est plus retiré"
    assert "secret_bloc" not in sans_commentaires_js("const a = 1; /* secret_bloc */ const b = 2;"), \
        "témoin inverse : un commentaire de bloc n'est plus retiré"
    assert "posted-one" in sans_commentaires_js("const u = 'http://h/posted-one'; // .commented-one"), \
        "témoin inverse : un `//` d'URL dans une chaîne est pris pour un commentaire"
    # (5) La hauteur est conservée : les numéros de ligne rendus sont ceux du fichier.
    src5 = "a;\n/* deux\n   lignes */\nb; // fin\nc;"
    assert sans_commentaires_js(src5).count("\n") == src5.count("\n"), \
        "témoin : le dépouillement change le nombre de lignes, tout numéro rendu serait faux"
    # (6) Le saut d'INTERPOLATION : un accent grave posé dans un `${…}` ne referme pas le gabarit.
    assert "fantome" not in sans_commentaires_js("const t = `a${ x ? `b` : 'c' }d`;\n// fantome\n"), \
        "témoin : un gabarit imbriqué dans une interpolation désynchronise encore le lecteur"
    # (7) L'AVEU, dans les deux sens : il se tait sur du code valide, il parle sur une désynchronisation.
    propre = []
    sans_commentaires_js("const a = 'x';\nconst b = `y${ a }z`;\nconst c = /[\"]/g;\n", propre)
    assert not propre, f"témoin inverse : le lecteur avoue une perte sur du code valide ({propre})"
    perdu = []
    # `)` suivi d'une expression régulière : la règle du jeton précédent dit « division » (limite écrite
    # à côté de `RE_AVANT_REGEX`), le `'` du motif ouvre une fausse chaîne — le lecteur DOIT le dire.
    sans_commentaires_js("if (x) /l'un/.test(y);\nconst a = 2;\n", perdu)
    assert perdu, "témoin : le lecteur ne dit plus qu'il a perdu la synchronisation, il rendrait un compte amputé en silence"
    # (8) LE REGISTRE : une expression régulière posée dans une entrée n'avale plus l'accolade fermante,
    #     donc les clés suivantes restent de PREMIER NIVEAU. Une section perdue ici est un vert silencieux.
    registre_avec_regex = ("export const HELP = {\n  alpha: { fr: { title: 'A', body: 'a' } },\n"
                           "  beta: { re: /[\"']/g },\n  gamma: { fr: { title: 'G', body: 'g' } },\n};\n")
    assert sections(registre_avec_regex) == {"alpha", "beta", "gamma"}, \
        f"témoin : {sorted(sections(registre_avec_regex))} — une expression régulière dans le registre fait " \
        f"encore disparaître les sections qui la suivent"
    # (9) L'AVEUGLEMENT DES LITTÉRAUX garde la longueur, blanchit les accolades d'un littéral, garde
    #     celles du code — et n'est plus dupé par un `"` posé dans une classe d'expression régulière.
    src8 = 'function f(v) { return \'"\' + String(v).replace(/[|\\[\\]"\\n\\r]/g, \' \').trim() + \'"\'; }\nfunction g() { }\n'
    vu8 = aveugler_litteraux_js(src8)
    assert len(vu8) == len(src8), "témoin : l'aveuglement des littéraux ne conserve plus la longueur, les offsets rendus seraient faux"
    assert vu8.count("{") == 2 and vu8.count("}") == 2, \
        f"témoin : {vu8.count('{')} ouvrante(s) et {vu8.count('}')} fermante(s) lues au lieu de 2 et 2 — un " \
        f"littéral en fabrique ou en mange, et l'appariement des blocs devient faux"
    assert 'function g() { }' in vu8, "témoin : l'aveuglement a blanchi du code après une expression régulière"
    assert aveugler_litteraux_js('const s = "{{{";').count("{") == 0, \
        "témoin inverse : les accolades d'une chaîne comptent encore dans l'appariement des blocs"

    # ================================================================================================
    # (10) LE LECTEUR RUST — UNE APOSTROPHE N'EST PAS TOUJOURS UNE DURÉE DE VIE (`P10.20-c`, 2026-09-16)
    # ================================================================================================
    # Le lecteur prenait TOUTE apostrophe pour une durée de vie : le `"` du littéral `'"'` ouvrait une
    # FAUSSE chaîne et le dépouillement repartait à contretemps jusqu'au guillemet suivant. Les deux sens
    # ont leur témoin, parce que les deux sont arrivés : un COMMENTAIRE rendu comme du code fabrique une
    # accusation, du CODE rendu comme un commentaire rend la garde aveugle SANS UN MOT.
    # (a) SENS « commentaire lu comme du code » : le commentaire qui SUIT le littéral est bien retiré.
    lu = sans_commentaires_rust("const META: [char; 2] = [';', '\"'];\nlet x = 1; // data-help=\"fantome\"\nlet y = 2;\n")
    assert "fantome" not in lu, "témoin : après le littéral de caractère `'\"'`, un commentaire n'est plus retiré (fausse chaîne ouverte)"
    assert "let y = 2;" in lu, "témoin : après le littéral de caractère `'\"'`, le code qui suit a disparu"
    # (b) SENS INVERSE, celui qui ne dit rien : la chaîne qui suit reste une CHAÎNE, son `//` n'est pas
    #     un commentaire. Sans le correctif, `http://h/lecture_reelle` était mangé jusqu'à la fin de ligne.
    lu = sans_commentaires_rust("let c = '\"';\nlet u = \"http://h/lecture_reelle\";\nlet n = 8;\n")
    assert "lecture_reelle" in lu, "témoin : du CODE a été lu comme un commentaire après un littéral de caractère — la garde devient aveugle sans un mot"
    assert "let n = 8;" in lu, "témoin : la fin du fichier a disparu après un littéral de caractère"
    # (c) LA DURÉE DE VIE RESTE UNE DURÉE DE VIE, et un `//` d'URL dans une chaîne reste.
    lu = sans_commentaires_rust("fn f<'a>(u: &'a str) -> &'a str { let v = \"http://h/garde\"; v } // secret_vie\n")
    assert "http://h/garde" in lu, "témoin inverse : un `//` d'URL dans une chaîne Rust est pris pour un commentaire"
    assert "secret_vie" not in lu, "témoin inverse : un vrai commentaire Rust n'est plus retiré"
    assert lu.count("'a") == 3, f"témoin : {lu.count(chr(39) + 'a')} durée(s) de vie `'a` rendue(s) au lieu de 3"
    # (d) UNE DURÉE DE VIE ET UN LITTÉRAL D'UN MÊME CARACTÈRE COHABITENT sur la même ligne.
    lu = sans_commentaires_rust("fn g<'a>(c: char, s: &'a str) -> bool { c == 'a' && !s.is_empty() } // secret_ab\n")
    assert "c == 'a'" in lu and "&'a str" in lu, f"témoin : `'a` durée de vie et `'a'` littéral ne sont plus distingués ({lu!r})"
    assert "secret_ab" not in lu, "témoin : le commentaire qui suit `'a'` n'est plus retiré"
    # (e) LES SÉQUENCES D'ÉCHAPPEMENT sont DANS le littéral : `'\''`, `'\n'`, `'\\'`, `'\"'`, `'\x41'`,
    #     `'\u{1F600}'`. Le `"` échappé est celui qui mordait le plus loin (aucun guillemet après lui :
    #     l'ancien lecteur ouvrait une chaîne qui courait jusqu'à la fin du fichier).
    lu = sans_commentaires_rust("let a = '\\''; let b = '\\n'; let c = '\\\\'; let d = '\\\"'; let e = '\\x41'; let f = '\\u{1F600}'; // secret_echap\nlet z = 3;\n")
    assert "secret_echap" not in lu, "témoin : après une séquence d'échappement, un commentaire n'est plus retiré"
    assert "let z = 3;" in lu, "témoin : après une séquence d'échappement, le code qui suit a disparu"
    # (f) LE LITTÉRAL D'OCTET `b'"'` est la même forme, l'apostrophe est au même endroit.
    lu = sans_commentaires_rust("const GUILLEMET: u8 = b'\"';\nlet v = 4; // secret_octet\nlet w = 5;\n")
    assert "secret_octet" not in lu, "témoin : le littéral d'OCTET `b'\"'` ouvre encore une fausse chaîne"
    assert "let w = 5;" in lu, "témoin : le code qui suit un littéral d'octet a disparu"
    # (g) `'static` ET LES ÉTIQUETTES DE BOUCLE (`'outer:`, `break 'outer`) ne sont pas des littéraux.
    lu = sans_commentaires_rust("const S: &'static str = \"s\"; // secret_statique\nfn h() { 'outer: loop { break 'outer; } }\n")
    assert "secret_statique" not in lu, "témoin : le commentaire qui suit `'static` n'est plus retiré"
    assert "&'static str" in lu and "'outer: loop" in lu and "break 'outer;" in lu, \
        f"témoin : `'static` ou une étiquette de boucle a été mangée comme un littéral ({lu!r})"
    # (h) UN COMMENTAIRE DE BLOC portant une apostrophe et un littéral reste un commentaire ENTIER : la
    #     règle de l'apostrophe ne doit pas s'appliquer À L'INTÉRIEUR de ce que le lecteur retire déjà.
    lu = sans_commentaires_rust("/* l'idiome '\"' cité : let t = \"secret_bloc_rust\"; */\nlet u = 6; // secret_ligne_rust\nlet w = 7;\n")
    assert "secret_bloc_rust" not in lu and "secret_ligne_rust" not in lu, "témoin inverse : un commentaire Rust n'est plus retiré"
    assert "let u = 6;" in lu and "let w = 7;" in lu, "témoin : le code autour d'un commentaire de bloc a disparu"
    # (i) UNE CHAÎNE BRUTE `r#"…"#` portant une apostrophe et un `//` : l'apostrophe y est DANS une
    #     chaîne, elle n'ouvre rien.
    lu = sans_commentaires_rust("let r = r#\"il n'y a pas de commentaire // ici\"#; // secret_brut\nlet s = 7;\n")
    assert "// ici" in lu, "témoin : le contenu d'une chaîne brute Rust a été mangé"
    assert "secret_brut" not in lu, "témoin : le commentaire qui suit une chaîne brute n'est plus retiré"
    # (j) L'AVEU RUST, DANS LES DEUX SENS. Il se TAIT sur du Rust valide plein d'apostrophes — avant le
    #     correctif, `'"'` lui faisait avouer une chaîne courant jusqu'à la fin du fichier — et il PARLE
    #     encore sur une vraie chaîne non fermée, sinon un compte amputé passerait pour vert.
    propre = []
    sans_commentaires_rust("let c = '\"'; let d = '\\''; let s = \"ok\";\nfn i<'a>(x: &'a str) {}\n", propre)
    assert not propre, f"témoin inverse : le lecteur Rust avoue une perte sur du code valide ({propre})"
    perdu = []
    sans_commentaires_rust("let s = \"pas fermee;\nlet t = 1;\n", perdu)
    assert perdu, "témoin : une chaîne Rust non fermée ne fait plus avouer le lecteur — il rendrait un compte amputé en silence"

    # ================================================================================================
    # (k) LA CHAÎNE BRUTE SE FERME SUR SES DIÈSES, PAS SUR UN `"` (`P10.20-d`, 2026-09-16)
    # ================================================================================================
    # Les six premiers sont EXTRAITS d'un fichier fabriqué que `rustc --edition 2021` compile : ce ne
    # sont pas des formes inventées pour l'occasion. Sur le lecteur d'avant, (k1) rendait un commentaire
    # comme du CODE (accusation fabriquée) et (k4) mangeait du CODE comme un commentaire (cécité muette).
    # (k1) LA FORME DE L'ARBRE — un `"` ET un `//` dans le motif (collector-mail/src/url_extract.rs:19).
    lu = sans_commentaires_rust("let motif = r#\"https?://[^\\s<>\"'\\)\\]\\}]+\"#; // secret_brut_guillemet\nlet n = 1;\n")
    assert "secret_brut_guillemet" not in lu, "témoin : le `\"` d'une chaîne brute la ferme encore trop tôt (un commentaire reste lu comme du code)"
    assert "https?://" in lu and "let n = 1;" in lu, f"témoin : le contenu d'une chaîne brute ou le code qui suit a disparu ({lu!r})"
    # (k2) DEUX NIVEAUX DE DIÈSES, avec un `"` nu dedans. LE NOMBRE DE GUILLEMETS INTÉRIEURS EST IMPAIR
    #      À DESSEIN : avec un nombre PAIR, le lecteur fautif s'apparie tout seul et se recale, et le
    #      témoin ne discrimine plus rien (c'est la faute qu'a faite la première écriture de (k3)).
    lu = sans_commentaires_rust("let d = r##\"un \"guillemet nu\"##; // secret_deux_dieses\nlet n = 2;\n")
    assert "secret_deux_dieses" not in lu, "témoin : `r##\"…\"##` n'est pas lu jusqu'à ses deux dièses fermants"
    assert "guillemet nu" in lu and "let n = 2;" in lu, f"témoin : le contenu de `r##\"…\"##` a été mangé ({lu!r})"
    # (k3) LA CHAÎNE BRUTE D'OCTETS `br#"…"#` ET CELLE DE CHAÎNE C `cr#"…"#` — même forme, une lettre
    #      devant. TÉMOIN RÉÉCRIT APRÈS UNE MUTATION SURVIVANTE, et c'est dit : sa première écriture
    #      posait `br#"{"access_token":"T"}"#`, où les guillemets intérieurs sont en nombre PAIR — le
    #      lecteur privé des préfixes `br`/`cr` s'y recalait seul et la mutation passait en vert.
    for prefixe in ("br", "cr"):
        lu = sans_commentaires_rust("let o = " + prefixe + "#\"a \" b\"#; // secret_" + prefixe + "\nlet n = 3;\n")
        assert ("secret_" + prefixe) not in lu, f"témoin : `{prefixe}#\"…\"#` n'est pas reconnu comme une chaîne brute"
        assert "let n = 3;" in lu, f"témoin : le code qui suit `{prefixe}#\"…\"#` a disparu ({lu!r})"
    # (k4) LE PIÈGE DES DIÈSES : un `"#` DEDANS quand la fermeture en exige DEUX ne ferme pas. C'est le
    #      sens muet — l'ancien lecteur fermait là et mangeait la fin de la ligne comme un commentaire.
    lu = sans_commentaires_rust("let p = r##\"ceci \"# n'est pas la fin // ni un commentaire\"##; // secret_piege\nlet n = 4;\n")
    assert "secret_piege" not in lu, "témoin : un `\"#` posé dans `r##\"…\"##` ferme encore la chaîne trop tôt"
    assert "// ni un commentaire" in lu and "let n = 4;" in lu, f"témoin : du CODE a été mangé après un `\"#` intérieur ({lu!r})"
    # (k5) LA FORME SANS DIÈSE `r"…"` : le premier `"` la ferme, et rien avant.
    lu = sans_commentaires_rust("let s = r\"c:\\chemin\\sans\\echappement\"; // secret_brut_nu\nlet n = 5;\n")
    assert "secret_brut_nu" not in lu, "témoin : `r\"…\"` n'est pas fermé par son premier guillemet"
    assert "c:\\chemin" in lu and "let n = 5;" in lu, f"témoin : le contenu de `r\"…\"` a disparu ({lu!r})"
    # (k6) TÉMOIN INVERSE — UN IDENTIFIANT BRUT N'EST PAS UNE CHAÎNE. `r#type` suivi d'un `"` ouvrirait
    #      une chaîne courant jusqu'au guillemet suivant si le motif n'exigeait pas le `"` après les dièses.
    lu = sans_commentaires_rust("let r#type = \"un type\"; // secret_identifiant_brut\nlet n = 6;\n")
    assert "secret_identifiant_brut" not in lu, "témoin inverse : l'identifiant brut `r#type` ouvre une fausse chaîne"
    assert "un type" in lu and "let n = 6;" in lu, f"témoin inverse : du code a disparu après un identifiant brut ({lu!r})"
    # (k7) TÉMOIN INVERSE — LES FORMES QUI PARTAGENT LES LETTRES DU PRÉFIXE ET N'EN SONT PAS : la chaîne
    #      d'OCTETS `b"…"`, la chaîne C `c"…"`, et un nom qui commence par `r`. Aucune n'ouvre de chaîne
    #      brute, et le commentaire qui suit est retiré.
    #      CE QUE CE TÉMOIN NE TUE PAS, ET C'EST DIT : retirer la condition « le préfixe est en DÉBUT DE
    #      JETON » (`_prefixe_brut_rust`) est un MUTANT ÉQUIVALENT sur du Rust valide — pour qu'elle
    #      morde, il faudrait un caractère d'identifiant collé devant un `r"`, ce qu'aucun Rust valide
    #      n'écrit. La condition est gardée pour ce que le lecteur voit d'AUTRE (un fichier à moitié
    #      écrit, une fixture), pas tuée par un témoin artificiel.
    lu = sans_commentaires_rust("let b = b\"octets\"; let c = c\"zero\"; let rouge = 1; // secret_lettres_partagees\nlet n = 7;\n")
    assert "secret_lettres_partagees" not in lu, "témoin inverse : `b\"…\"`, `c\"…\"` ou un nom en `r` ouvre une fausse chaîne brute"
    assert "octets" in lu and "let n = 7;" in lu, f"témoin inverse : du code a disparu autour de `b\"…\"` ou `c\"…\"` ({lu!r})"
    # (k8) L'AVEU, DANS LES DEUX SENS. Il se TAIT sur des chaînes brutes valides — c'est exactement ce
    #      que `agent/src/config.rs` et `collector-mail/src/url_extract.rs` lui faisaient dire — et il
    #      PARLE sur une chaîne brute dont le délimiteur fermant n'existe pas.
    propre = []
    sans_commentaires_rust("let a = r#\"\"#; let b = r##\"\"# \"##; let c = br#\"x\"#;\nlet d = r\"y\";\n", propre)
    assert not propre, f"témoin inverse : le lecteur Rust avoue une perte sur des chaînes brutes valides ({propre})"
    perdu = []
    sans_commentaires_rust("let s = r##\"jamais refermee\"#;\nlet t = 1;\n", perdu)
    assert perdu, "témoin : une chaîne brute non fermée ne fait plus avouer le lecteur — il rendrait un compte amputé en silence"


def temoins():
    temoins_du_lecteur()
    # Le registre vit sous un nom qui n'est PAS help.js : la garde doit le retrouver par sa définition.
    registre = ("// const HELP = { cite: { } } — en commentaire, ne compte pas\nexport const HELP = {\n"
                "  alpha: { fr: { title: `A`, body: `x { y } z` }, en: { title: `A`, body: `{` } },\n"
                "  beta: { fn: () => 1 },\n  gamma: { fr: { title: 'G', body: 'g' } },\n};\n")
    # LE SOMMAIRE VIT SOUS UN NOM QUI N'EST NI `help.js` NI CELUI DU REGISTRE (`P11.13-d`) : la garde doit le
    # retrouver par sa DÉFINITION. Le module porte AUSSI un `{ k: … }` HORS du sommaire — c'est le témoin
    # négatif : anciennement borné à un nom de fichier, le motif comptait tout ce que le fichier contenait.
    aide = ("import { HELP } from './registre_temoin.js';\nconst AUTRE = [ { k: 'pas-un-declencheur', v: 1 } ];\n"
            "const HELP_INDEX = [ { k: 'beta', fr: 'b', re: /[\"']/ } ];\n"
            "// openHelp('commentee')\n/* data-help=\"commentee-bloc\" */\n")
    html = "<button data-help=\"alpha\"></button><button data-help=\"orpheline\"></button><!-- data-help=\"commentee-html\" -->"
    corpus = {"index.html": sans_commentaires_html(html), "guide_temoin.js": sans_commentaires_js(aide), "registre_temoin.js": sans_commentaires_js(registre)}
    assert module_du_registre(corpus) == "registre_temoin.js", f"témoin : le registre déplacé n'est pas retrouvé par sa définition ({module_du_registre(corpus)})"
    assert module_du_registre({k: v for k, v in corpus.items() if k != "registre_temoin.js"}) is None, "témoin : sans définition, la dérivation doit ne rien conclure"
    assert module_du_registre({**corpus, "double.js": "const HELP = {};"}) is None, "témoin : deux définitions, la dérivation doit ne rien conclure"
    assert module_du_sommaire(corpus) == "guide_temoin.js", f"témoin : le sommaire déplacé hors de `help.js` n'est pas retrouvé par sa définition ({module_du_sommaire(corpus)})"
    assert module_du_sommaire({k: v for k, v in corpus.items() if k != "guide_temoin.js"}) is None, "témoin : sans définition de sommaire, la dérivation doit ne rien conclure"
    assert module_du_sommaire({**corpus, "double.js": "const HELP_INDEX = [];"}) is None, "témoin : deux sommaires, la dérivation doit ne rien conclure"
    portee_s = portee_du_sommaire(corpus["guide_temoin.js"])
    assert portee_s and corpus["guide_temoin.js"][portee_s[0]:portee_s[1]].startswith("const HELP_INDEX = [") \
        and corpus["guide_temoin.js"][portee_s[0]:portee_s[1]].endswith("]"), f"témoin : la portée du sommaire ne va pas de sa définition à son crochet fermant ({portee_s})"
    assert portee_du_sommaire("const x = 1;") is None, "témoin : sans définition, la portée du sommaire doit être None"
    sommaire = (module_du_sommaire(corpus), portee_s)
    decl_hors = declencheurs(corpus, None)
    assert "beta" not in decl_hors, "témoin : sans portée de sommaire dérivée, le motif `{ k: … }` doit ne valoir NULLE PART (l'appelant refuse alors de conclure)"
    decl, sect, sans_section, sans_declencheur = juger(corpus, corpus[module_du_registre(corpus)], sommaire)
    assert "pas-un-declencheur" not in decl, f"témoin NÉGATIF : un `{{ k: … }}` HORS de la portée du sommaire est compté comme déclencheur ({sorted(decl)}) — le motif est trop banal pour valoir ailleurs"
    assert sect == {"alpha", "beta", "gamma"}, f"témoin : sections lues {sorted(sect)} — les accolades des corps d'aide faussent la lecture"
    portee = portee_du_registre(corpus["registre_temoin.js"])
    assert portee and corpus["registre_temoin.js"][portee[0]:portee[1]].startswith("const HELP = {") and corpus["registre_temoin.js"][portee[0]:portee[1]].endswith("}") \
        and corpus["registre_temoin.js"][portee[1]:].strip() == ";", f"témoin : la portée du registre ne va pas de sa définition à son accolade fermante ({portee})"
    assert portee_du_registre("const x = 1;") is None, "témoin : sans définition, la portée doit être None"
    assert set(sans_section) == {"orpheline"}, f"témoin positif : déclencheur sans section attendu «orpheline», lu {sorted(sans_section)}"
    assert not any(k.startswith("commentee") for k in decl), "témoin négatif : un déclencheur cité en COMMENTAIRE a été compté"
    assert "beta" in decl and "alpha" in decl, "témoin : une entrée de sommaire `{ k: }` ou un `data-help` HTML n'est pas lu comme déclencheur"
    assert sans_declencheur == ["gamma"], f"témoin : section sans déclencheur attendue «gamma», lu {sans_declencheur}"


def main():
    temoins()
    racine = (sys.argv[1] if len(sys.argv) > 1 else subprocess.run(["git", "rev-parse", "--show-toplevel"],
              capture_output=True, text=True, check=True).stdout.strip())
    web = os.path.join(racine, "web")
    corpus, aveux = {}, {}
    for f in sorted(os.listdir(web)):
        chemin = os.path.join(web, f)
        if not os.path.isfile(chemin): continue
        if f.endswith(".js"):
            journal, brut = [], open(chemin, encoding="utf-8").read()
            corpus[f] = sans_commentaires_js(brut, journal)
            if journal: aveux[f] = [f"ligne {brut.count(chr(10), 0, o) + 1} : {motif}" for motif, o in journal]
        elif f.endswith(".html"): corpus[f] = sans_commentaires_html(open(chemin, encoding="utf-8").read())
    if aveux and refuser_sur_aveu("aide", aveux): return 2
    registre = module_du_registre(corpus)
    if registre is None:
        porteurs = [n for n, t in corpus.items() if n.endswith(".js") and RE_DEFINITION_DU_REGISTRE.search(t)]
        print(f"[aide] ÉCHEC — {len(porteurs)} module(s) de web/ définissent `const HELP = {{` ({', '.join(porteurs) or 'aucun'}) : un seul attendu, la garde refuse de conclure"); return 2
    # LA PORTÉE DU SOMMAIRE EST DÉRIVÉE, PAS NOMMÉE (`P11.13-d`). Sans elle le quatrième motif ne vaudrait
    # nulle part : la garde verrait MOINS et verdirait. Elle refuse donc de conclure plutôt que d'acquitter
    # ce qu'elle n'a pas pu délimiter.
    mod_sommaire = module_du_sommaire(corpus)
    porteurs_s = [n for n, t in corpus.items() if n.endswith(".js") and RE_DEFINITION_DU_SOMMAIRE.search(t)]
    portee_s = portee_du_sommaire(corpus[mod_sommaire]) if mod_sommaire else None
    if portee_s is None:
        print(f"[aide] ÉCHEC — {len(porteurs_s)} module(s) de web/ définissent `const HELP_INDEX = [` "
              f"({', '.join(porteurs_s) or 'aucun'}) et sa portée n'est pas délimitable : le motif du sommaire "
              f"ne vaudrait nulle part et la garde verrait moins de déclencheurs — elle refuse de conclure"); return 2
    sommaire = (mod_sommaire, portee_s)
    journal_registre = []
    decl, sect, sans_section, sans_declencheur = juger(corpus, corpus[registre], sommaire, journal_registre)
    if journal_registre and refuser_sur_aveu("aide", {registre: [f"offset {o} : {m}" for m, o in journal_registre]}): return 2
    sites = sum(len(v) for v in decl.values())
    print(f"[aide] {len(decl)} clés déclenchées ({sites} déclencheurs dans {len(corpus)} fichiers), {len(sect)} sections dans {registre} (module du registre dérivé de sa définition) ; sommaire dérivé dans {mod_sommaire} (portée {portee_s[0]}-{portee_s[1]})")
    if len(sect) < PLANCHER_SECTIONS:
        print("[aide] ÉCHEC — sous le plancher de sections : la dérivation est cassée, la garde refuse de conclure"); return 2
    # LE CLIQUET (`P11.13-d`). Voir moins de déclencheurs, c'est avoir moins de contrôles à passer : sans ce
    # plancher, une portée perdue rend la garde plus verte. Le compte est publié, et sa chute est un ÉCHEC.
    if sites < CLIQUET_SITES_DECLENCHEURS:
        print(f"[aide] ÉCHEC — le compte de déclencheurs VUS a chuté : {sites} sites pour un cliquet à "
              f"{CLIQUET_SITES_DECLENCHEURS} ({len(decl)} clés distinctes, non gardées). Soit une PORTÉE a été "
              f"perdue (le registre ou le sommaire a changé de forme, et la dérivation ne la retrouve plus), soit "
              f"des déclencheurs ont vraiment été retirés — dans ce second cas, abaisser le cliquet AVEC sa raison "
              f"écrite à côté du chiffre. La garde ne verdit pas sur moins de vue."); return 2
    for k in sans_declencheur: print(f"    i section « {k} » sans déclencheur à clé littérale (information, pas une erreur)")
    for k, sites in sorted(sans_section.items()): print(f"    - « {k} » déclenché sans section : {', '.join(sites)}")
    if sans_section:
        print(f"[aide] ÉCHEC — {len(sans_section)} clé(s) déclenchée(s) sans section dans {registre} : écrire la section, ou retirer le déclencheur"); return 1
    print(f"[aide] OK — chaque déclencheur ouvre une section ; {len(sans_declencheur)} section(s) sans déclencheur (information)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
