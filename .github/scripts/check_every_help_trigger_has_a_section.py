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


def sans_commentaires_js(src):
    """Retire `//…` et `/*…*/` en respectant les chaînes ('', "", ``) : un `//` dans une URL reste."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"`":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2); fin = n if j < 0 else j + 2; out.append(re.sub(r"[^\n]", " ", src[i:fin])); i = fin
        else:
            out.append(c); i += 1
    return "".join(out)


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


def _parcourir_registre(help_js):
    """Parcourt `const HELP = { … }` par profondeur d'accolades hors chaînes et gabarits ; rend
    (clés de premier niveau, index du début de la définition, index après l'accolade fermante), ou None."""
    debut = RE_DEFINITION_DU_REGISTRE.search(help_js)
    if not debut: return None
    i, n, prof, cles, ligne_vide = debut.end(), len(help_js), 1, set(), True
    while i < n and prof > 0:
        c = help_js[i]
        if c in "'\"`":
            j = i + 1
            while j < n and help_js[j] != c:
                j += 2 if help_js[j] == "\\" else 1
            i = j + 1; ligne_vide = False; continue
        if c == "{": prof += 1
        elif c == "}": prof -= 1
        elif prof == 1 and ligne_vide:
            m = re.match(r"\s*" + CLE + r"\s*:", help_js[i:])
            if m: cles.add(m.group(1)); i += m.end(); ligne_vide = False; continue
        ligne_vide = c == "\n" or (ligne_vide and c.isspace())
        i += 1
    return cles, debut.start(), i


def sections(help_js):
    """Clés de premier niveau de `const HELP = { … }`, par profondeur d'accolades hors chaînes et gabarits."""
    p = _parcourir_registre(help_js)
    return p[0] if p else set()


def portee_du_registre(help_js):
    """(début, fin) de la définition `const HELP = { … }` dans le texte — la SURFACE du contenu d'aide, que la
    garde du lexique exempte sans exempter le module qui la porte ; None si la définition est absente."""
    p = _parcourir_registre(help_js)
    return (p[1], p[2]) if p else None


def juger(corpus, help_js):
    decl, sect = declencheurs(corpus), sections(help_js)
    sans_section = {k: v for k, v in decl.items() if k not in sect}
    sans_declencheur = sorted(sect - set(decl))
    return decl, sect, sans_section, sans_declencheur


def temoins():
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
    corpus = {}
    for f in sorted(os.listdir(web)):
        chemin = os.path.join(web, f)
        if not os.path.isfile(chemin): continue
        if f.endswith(".js"): corpus[f] = sans_commentaires_js(open(chemin, encoding="utf-8").read())
        elif f.endswith(".html"): corpus[f] = sans_commentaires_html(open(chemin, encoding="utf-8").read())
    registre = module_du_registre(corpus)
    if registre is None:
        porteurs = [n for n, t in corpus.items() if n.endswith(".js") and RE_DEFINITION_DU_REGISTRE.search(t)]
        print(f"[aide] ÉCHEC — {len(porteurs)} module(s) de web/ définissent `const HELP = {{` ({', '.join(porteurs) or 'aucun'}) : un seul attendu, la garde refuse de conclure"); return 2
    decl, sect, sans_section, sans_declencheur = juger(corpus, corpus[registre])
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
