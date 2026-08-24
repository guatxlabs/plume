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
    (4) `{ k: '<clé>', … }` — les entrées du sommaire `HELP_INDEX` du guide, rendues en boutons.
    Le corpus est lu SANS ses commentaires : une clé citée dans un commentaire n'ouvre rien. Un déclencheur
    dont la clé est construite (`data-help="${x}"`) n'est pas décidable et n'est pas compté.
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
"""
import os, re, subprocess, sys

PLANCHER_DECLENCHEURS, PLANCHER_SECTIONS = 20, 20
CLE = r"([A-Za-z][\w-]*)"
# La définition du registre : `const HELP = {` (exporté ou non), hors commentaires. Même ancre pour le
# localiser dans `web/` et pour en lire les clés.
RE_DEFINITION_DU_REGISTRE = re.compile(r"\bconst HELP\s*=\s*\{")
MOTIFS_DECLENCHEUR = [  # (motif, fichier où il vaut — None : partout sous web/)
    (re.compile(r"""data-help\s*=\s*["']""" + CLE + r"""["']"""), None),
    (re.compile(r"""dataset\.help\s*=\s*["'`]""" + CLE + r"""["'`]"""), None),
    (re.compile(r"""\bopenHelp\(\s*["'`]""" + CLE + r"""["'`]\s*\)"""), None),
    (re.compile(r"""\{\s*k:\s*["']""" + CLE + r"""["']"""), "help.js"),  # le sommaire du guide vit dans help.js seulement
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
# Délimiteurs de chaîne par langage. En Rust, `'` n'en est PAS un (c'est une durée de vie `&'static str`),
# il n'y a pas de gabarit, et `/` est toujours une division : pas de littéral d'expression régulière.
CHAINES_JS, CHAINES_RUST = "\"'`", '"'


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


def _sans_commentaires(src, delimiteurs, regex_litterales, journal):
    out, i, n, code = [], 0, len(src), []
    while i < n:
        c = src[i]
        if c in delimiteurs:
            f = saute_gabarit(src, i, journal) if c == "`" else \
                saute_chaine(src, i, journal, multiligne=(delimiteurs == CHAINES_RUST))
            out.append(src[i:f]); code.append('""'); i = f; continue
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
    """Le même dépouillement pour du Rust : `"` seul délimite (un `'` est une durée de vie), une chaîne
    peut franchir une fin de ligne, et `/` est toujours une division. Une chaîne brute `r#"…"#` est lue
    comme une chaîne ordinaire — cas non couvert, et il est dit."""
    return _sans_commentaires(src, CHAINES_RUST, False, journal)


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


def refuser_sur_aveu(etiquette, aveux):
    """L'AVEU RENDU À L'APPELANT. `aveux` = {fichier: ["ligne N : motif", …]}. Imprime chaque aveu et rend
    True — l'appelant SORT alors en code 2 sans verdict. Un lecteur qui a ouvert un littéral qui n'en était
    pas un a AVALÉ du code : tout ce qu'il a compté depuis est faux, et un compte amputé rendu en vert est
    pire qu'une garde absente. C'est ce qu'un `"` dans une expression régulière a fait pendant un jour sur
    `web/viz.js` (118 littéraux perdus, `P11.8-e`)."""
    for fichier, lignes in sorted(aveux.items()):
        for ligne in lignes:
            print(f"::error::{fichier}:{ligne} — le lecteur JavaScript a PERDU LA SYNCHRONISATION : il a "
                  f"ouvert un littéral qui n'en est pas un, et tout ce qu'il a lu depuis est faux. Cause la "
                  f"plus fréquente : un `/` que la règle de désambiguïsation (jeton précédent, cf. "
                  f"`RE_AVANT_REGEX`) a pris pour une division alors qu'il ouvrait une expression régulière "
                  f"— après `)` ou `]`, typiquement `if (x) /re/.test(y)`. Écrire `if (x) {{ return "
                  f"/re/.test(y); }}` ou `new RegExp(…)`, ou apprendre la forme à `RE_AVANT_REGEX`.")
    print(f"[{etiquette}] REFUS DE CONCLURE — le lecteur avoue avoir sauté une région ; il ne rend pas un "
          f"compte amputé en vert.")
    return True


def sans_commentaires_html(src):
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)


def declencheurs(corpus):
    """{clé: [fichier:ligne, …]} — chaque déclencheur à clé littérale du corpus (textes sans commentaires)."""
    trouves = {}
    for nom, texte in corpus.items():
        for motif, fichier in MOTIFS_DECLENCHEUR:
            if fichier and nom != fichier: continue
            for m in motif.finditer(texte):
                trouves.setdefault(m.group(1), []).append(f"{nom}:{texte.count(chr(10), 0, m.start()) + 1}")
    return trouves


def module_du_registre(corpus_js):
    """Nom du SEUL module (textes sans commentaires) qui définit `const HELP = { … }` ; None si aucun ou plusieurs."""
    porteurs = sorted(nom for nom, texte in corpus_js.items() if nom.endswith(".js") and RE_DEFINITION_DU_REGISTRE.search(texte))
    return porteurs[0] if len(porteurs) == 1 else None


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


def juger(corpus, help_js, journal=None):
    decl, sect = declencheurs(corpus), sections(help_js, journal)
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


def temoins():
    temoins_du_lecteur()
    # Le registre vit sous un nom qui n'est PAS help.js : la garde doit le retrouver par sa définition.
    registre = ("// const HELP = { cite: { } } — en commentaire, ne compte pas\nexport const HELP = {\n"
                "  alpha: { fr: { title: `A`, body: `x { y } z` }, en: { title: `A`, body: `{` } },\n"
                "  beta: { fn: () => 1 },\n  gamma: { fr: { title: 'G', body: 'g' } },\n};\n")
    aide = ("import { HELP } from './registre_temoin.js';\nconst HELP_INDEX = [ { k: 'beta', fr: 'b' } ];\n"
            "// openHelp('commentee')\n/* data-help=\"commentee-bloc\" */\n")
    html = "<button data-help=\"alpha\"></button><button data-help=\"orpheline\"></button><!-- data-help=\"commentee-html\" -->"
    corpus = {"index.html": sans_commentaires_html(html), "help.js": sans_commentaires_js(aide), "registre_temoin.js": sans_commentaires_js(registre)}
    assert module_du_registre(corpus) == "registre_temoin.js", f"témoin : le registre déplacé n'est pas retrouvé par sa définition ({module_du_registre(corpus)})"
    assert module_du_registre({k: v for k, v in corpus.items() if k != "registre_temoin.js"}) is None, "témoin : sans définition, la dérivation doit ne rien conclure"
    assert module_du_registre({**corpus, "double.js": "const HELP = {};"}) is None, "témoin : deux définitions, la dérivation doit ne rien conclure"
    decl, sect, sans_section, sans_declencheur = juger(corpus, corpus[module_du_registre(corpus)])
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
    journal_registre = []
    decl, sect, sans_section, sans_declencheur = juger(corpus, corpus[registre], journal_registre)
    if journal_registre and refuser_sur_aveu("aide", {registre: [f"offset {o} : {m}" for m, o in journal_registre]}): return 2
    print(f"[aide] {len(decl)} clés déclenchées ({sum(len(v) for v in decl.values())} déclencheurs dans {len(corpus)} fichiers), {len(sect)} sections dans {registre} (module du registre dérivé de sa définition)")
    if len(decl) < PLANCHER_DECLENCHEURS or len(sect) < PLANCHER_SECTIONS:
        print("[aide] ÉCHEC — sous le plancher : la dérivation est cassée, la garde refuse de conclure"); return 2
    for k in sans_declencheur: print(f"    i section « {k} » sans déclencheur à clé littérale (information, pas une erreur)")
    for k, sites in sorted(sans_section.items()): print(f"    - « {k} » déclenché sans section : {', '.join(sites)}")
    if sans_section:
        print(f"[aide] ÉCHEC — {len(sans_section)} clé(s) déclenchée(s) sans section dans {registre} : écrire la section, ou retirer le déclencheur"); return 1
    print(f"[aide] OK — chaque déclencheur ouvre une section ; {len(sans_declencheur)} section(s) sans déclencheur (information)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
