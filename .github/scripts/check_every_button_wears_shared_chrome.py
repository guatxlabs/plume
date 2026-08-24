#!/usr/bin/env python3
"""Aucun bouton de la surface web ne retombe au rendu natif du navigateur — garde de CI (`P11.4-b`).

LE DÉFAUT. Plume n'avait aucune classe de bouton : le chrome venait du CONTEXTE (`.panelhead button`,
`.rulerow button`…), et tout bouton posé hors de ces contextes prenait le rendu natif, clair et biseauté,
dans une interface sombre. Mesuré par dérivation à l'ouverture de la clé : 302 sites, 69 nus.

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE. De `style.css` on tire (1) les CONTEXTES : la classe ou l'identifiant
qui précède immédiatement `button` dans un sélecteur dont la règle pose du chrome (`border` ou
`background`) — un `.x button:disabled{opacity}` n'habille rien ; (2) les CLASSES DE BOUTON : toute classe
ou tout identifiant dont la règle propre déclare `cursor:pointer` (le jeu partagé `.btn*`, `.picon`,
`.linklike`, les boutons de gabarit `.banbtn`, `.rmp`…). Des modules on tire chaque SITE :
`createElement('button')`, `mk('button', …)`, l'appel d'un helper qui rend un bouton (`return b` dans sa
fenêtre), `<button` dans un gabarit ou dans `index.html`. Un site est HABILLÉ s'il porte une classe de
bouton, ou s'il est posé dans un parent dont la classe ou l'identifiant est un contexte (parent résolu par
`append`/`appendChild`/`prepend`, par la cible d'un `innerHTML`, ou par la pile des balises ouvertes d'un
gabarit ; un `$('#id')` est résolu sur les classes de cet élément dans `index.html`). Tout autre site est NU.

LIMITE ASSUMÉE : la résolution du parent est lexicale (fenêtre de lignes), pas une exécution. Un bouton
habillé par un contexte posé ailleurs rougit ici ; la réponse est de lui donner la classe partagée, ce qui
est précisément la règle. L'instrument se valide sur deux témoins (une forme nue DOIT rougir, une forme
habillée NE DOIT PAS) et refuse de conclure sous un plancher de sites, de contextes et de classes.

LA RACINE EXAMINÉE est lue par le geste partagé `racine_designee()`, importé de la garde sœur
`check_every_style_selector_has_a_target.py` plutôt que recopié (`P8.27-a`).
"""
import os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import racine_designee  # noqa: E402  (source unique de vérité)

WEB = None  # renseigné par main() : la racine ne se devine pas à l'import (voir `racine_designee`)
PLANCHER_SITES, PLANCHER_CONTEXTES, PLANCHER_CLASSES = 250, 10, 12
HELPERS = {}    # nom -> classe inconditionnelle (None : la classe vient de l'appel `cls:` ou du contexte)
ID_HTML = {}    # id d'index.html -> ses classes
SEL = re.compile(r"([#.])([\w-]+)")
VIDES = ("input", "br", "img", "hr", "meta", "link", "path", "circle", "rect", "line", "use", "polyline", "polygon")


def deriver(css):
    ctx, cls = set(), set()
    for sels, corps in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        chrome, pointeur = re.search(r"\b(border|background)\b", corps), "cursor:pointer" in corps.replace(" ", "")
        for sel in sels.split(","):
            comp = sel.strip().replace(">", " ").split()
            if not comp: continue
            if re.match(r"button\b", comp[-1]):
                if chrome and len(comp) > 1 and not re.search(r":(disabled|hover|focus)", comp[-1]): ctx |= {m.group(0) for m in SEL.finditer(comp[-2])}
            elif pointeur:
                cls |= {m.group(0) for m in SEL.finditer(comp[-1])}
    return ctx, cls


def noms(chaine):
    """Classes d'un littéral `'btn btn-sm'` ou d'un attribut `class="a b"` (avant toute interpolation `${`)."""
    chaine = re.sub(r"\$\{.*", '"', chaine)  # `class="agseg${…}"` : la partie statique seule, refermée
    return {"." + c for lit in re.findall(r"'([^']*)'|\"([^\"]*)\"", chaine) for c in " ".join(lit).split()}


def ids(attrs):
    return {"#" + x for x in re.findall(r'id="([\w-]+)"', attrs)}


def source_parent(lignes, i, var, ctx):
    """Le parent `var` porte-t-il un contexte ? Résolution lexicale : classe posée, `$('#id')`, `mk('div', {className})`."""
    if not var: return False
    zone, cand = "\n".join(lignes[max(0, i - 80): i + 16]), set()
    for m in re.finditer(r"\b" + var + r"\.className\s*=\s*([^;\n]+)", zone): cand |= noms(m.group(1))
    for m in re.finditer(r"\b" + var + r"\.classList\.add\(([^)]*)\)", zone): cand |= noms(m.group(1))
    for m in re.finditer(r"\b" + var + r"\s*=\s*mk\('\w+'\s*,\s*\{[^}]*className:\s*('[^']*')", zone): cand |= noms(m.group(1))
    for m in re.finditer(r"\b" + var + r"\s*=\s*(?:\$|\w+\.querySelector)\('([#.])([\w-]+)", zone):
        cand.add(m.group(1) + m.group(2)); cand |= ID_HTML.get(m.group(2), set()) if m.group(1) == "#" else set()
    return bool(cand & ctx)


def habille_js(lignes, i, var, ctx, cls):
    fen, port = "\n".join(lignes[i: i + 16]), set()
    for m in re.finditer(r"\b" + var + r"\.className\s*=\s*([^;\n]+)", fen): port |= noms(m.group(1))
    for m in re.finditer(r"\b" + var + r"\.classList\.add\(([^)]*)\)", fen): port |= noms(m.group(1))
    if port & cls: return True
    return any(source_parent(lignes, i, m.group(1), ctx) for m in
               re.finditer(r"(\w+)\.(?:append|appendChild|prepend|replaceChildren|insertBefore)\([^;]*\b" + var + r"\b", fen))


def sites_js(nom, texte, ctx, cls, compter):
    lignes, nus, n, pile = texte.split("\n"), [], 0, []
    for i, l in enumerate(lignes):
        for m in re.finditer(r"(\w+)\s*=\s*document\.createElement\('button'\)", l):
            v, fen = m.group(1), "\n".join(lignes[i: i + 10])
            if re.search(r"\breturn " + v + r"\b", fen):  # un helper : ses APPELS sont les sites
                f = re.findall(r"function (\w+)\(", "\n".join(lignes[max(0, i - 3): i + 1]))
                if f:
                    sans_if = [st.split("=", 1)[1] for st in re.split(r"[;\n]", fen) if st.strip().startswith(v + ".className")]
                    HELPERS[f[-1]] = next((c for x in sans_if for c in noms(x) & cls), None); continue  # inconditionnelle seule
            if not compter: continue
            n += 1
            if not habille_js(lignes, i, v, ctx, cls): nus.append(f"{nom}:{i + 1} createElement")
        if not compter: continue
        for m in re.finditer(r"(\w+)\s*=\s*mk\('button'\s*,\s*\{([^}]*)\}", l):
            n += 1
            if not (noms(m.group(2)) & cls or habille_js(lignes, i, m.group(1), ctx, cls)): nus.append(f"{nom}:{i + 1} mk")
        for m in re.finditer(r"(?:(\w+)\s*=\s*)?\b(\w+)\((?=['\"])", l):
            h = m.group(2)
            if h not in HELPERS or re.search(r"function " + h + r"\(", l): continue
            n += 1
            c = re.search(h + r"\([^)]*cls:\s*('[^']*')", l)
            parent = re.search(r"(\w+)\.(?:append|appendChild|prepend)\([^;]*\b" + h + r"\(", l)
            ok = HELPERS[h] or (c and noms(c.group(1)) & cls) or (m.group(1) and habille_js(lignes, i, m.group(1), ctx, cls)) \
                or source_parent(lignes, i, parent and parent.group(1), ctx)
            if not ok: nus.append(f"{nom}:{i + 1} {h}()")
        for m in re.finditer(r"<(/?)([a-zA-Z][\w-]*)([^<>]*)>", l):
            fin, tag, attrs = m.groups()
            if fin:
                if pile: pile.pop()
                continue
            if tag == "button":
                n += 1
                ok = (noms(attrs) | ids(attrs)) & cls or any(p & ctx for p in pile)
                if not ok:  # cible d'un innerHTML à portée courte
                    cible = re.search(r"(\w+)\.innerHTML\s*\+?=", "\n".join(lignes[max(0, i - 3): i + 1]))
                    ok = cible and source_parent(lignes, i, cible.group(1), ctx)
                if not ok: nus.append(f"{nom}:{i + 1} <button")
            if tag not in VIDES and not attrs.rstrip().endswith("/"): pile.append(noms(attrs) | ids(attrs))
    return n, nus


def main():
    global WEB
    WEB = os.path.join(racine_designee(), "web")
    ctx, cls = deriver(open(os.path.join(WEB, "style.css"), encoding="utf-8").read())
    html = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    for m in re.finditer(r"<\w+\s+([^<>]*)>", html):
        for i in ids(m.group(1)): ID_HTML[i[1:]] = noms(m.group(1))
    # Témoins : l'instrument rougit sur une forme nue et se tait sur une forme habillée, AVANT de juger l'arbre.
    nu = "function r() {\n  const b = document.createElement('button'); b.textContent = 'x';\n  host.appendChild(b);\n}\n"
    ok = ("const host = document.createElement('div'); host.className = 'rulerow';\n" + nu
          + "const c = document.createElement('button'); c.className = 'btn btn-sm';\nel.innerHTML = `<div class=\"rf-actions\"><button type=\"submit\">ok</button></div>`;\n")
    assert sites_js("temoin", nu, ctx, cls, True)[1], "témoin : une forme NUE n'a pas rougi, l'instrument est aveugle"
    assert not sites_js("temoin", ok, ctx, cls, True)[1], "témoin : une forme HABILLÉE a rougi, l'instrument hallucine"
    fichiers = sorted(f for f in os.listdir(WEB) if f.endswith(".js") and f != "sw.js")
    sources = {f: open(os.path.join(WEB, f), encoding="utf-8").read() for f in fichiers + ["index.html"]}
    for f in fichiers: sites_js(f, sources[f], ctx, cls, False)  # passe 1 : les helpers, quel que soit leur module
    total, nus = 0, []
    for f in fichiers + ["index.html"]:
        n, liste = sites_js(f, sources[f], ctx, cls, True)
        total += n; nus += liste
    print(f"[boutons] {total} sites, {len(ctx)} contextes, {len(cls)} classes de bouton dérivés de style.css, {len(HELPERS)} helpers")
    if total < PLANCHER_SITES or len(ctx) < PLANCHER_CONTEXTES or len(cls) < PLANCHER_CLASSES:
        print("[boutons] ÉCHEC — sous le plancher : la dérivation est cassée, la garde refuse de conclure"); return 2
    for s in nus: print("    - " + s)
    if nus: print(f"[boutons] ÉCHEC — {len(nus)} bouton(s) NU(s) : classe partagée (.btn, .btn-primary, .btn-danger, .btn-link, .picon) ou contexte stylant"); return 1
    print("[boutons] OK — aucun bouton nu"); return 0


if __name__ == "__main__":
    sys.exit(main())
