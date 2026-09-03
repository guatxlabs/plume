#!/usr/bin/env python3
"""Aucune COMMANDE de la surface web ne retombe au rendu natif du navigateur — garde de CI (`P11.4-b`, `P11.20-c`).

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

ON DÉRIVE DE RÈGLES, PAS DE PROSE (`P8.27-b`). La dérivation ne dépouillait pas les commentaires de la
feuille. Un commentaire qui CITE un corps de règle portant `cursor:pointer` et dont une tranche séparée par
une virgule finit sur un jeton de la forme `.nom` — une virgule suffit, sans elle le mot `button` suivant
dans la même tranche fait prendre l'autre branche et rien ne bouge — FABRIQUAIT une classe de bouton. Le
sens de l'erreur est ce qui la rend grave : la garde n'inventait pas un refus, elle ÉLARGISSAIT en silence
l'ensemble des classes tenues pour habillées, si bien qu'un bouton réellement nu pouvait être déclaré
conforme par une phrase écrite ailleurs. Une garde qu'on rend plus permissive en lui PARLANT ne fait aucun
bruit. Le dépouillement est celui de la garde sœur, `sans_commentaires_css()`, IMPORTÉ et non recopié : la
sœur, elle, ne souffrait pas du défaut, et deux exemplaires d'une même règle finissent par diverger. Un
témoin épingle qu'aucun commentaire ne change plus un compte, un autre que les vraies règles sont toujours
lues — sans quoi le dépouillement rendrait l'instrument aveugle au lieu de le rendre exact.

ELLE ÉTAIT VERTE PAR CONSTRUCTION SUR TOUT CE QUI N'EST PAS UN BOUTON (`P11.20-c`, 2026-09-03). Elle ne
collectait que `document.createElement('button')` et `<button` : sur un `select` ou un `input`, aucune
entrée ne pouvait la faire rougir, et un `select` sans classe rend l'apparence par défaut du navigateur au
milieu d'une console qui habille tout le reste. La DÉRIVATION EST ÉTENDUE, PAS DOUBLÉE : `sites_js` prend
la famille de balises en argument et sert les deux jambes ; seule la signature de classe change, et
`deriver_controles` dit pourquoi (`cursor:pointer` n'existe pas sur un champ de saisie). Le compte du jour
est publié : 199 sites de contrôle, 51 que la dérivation ne peut pas dire habillés. Exiger zéro aurait
fait de la clé une RANÇON, donc la deuxième jambe est tenue par un CLIQUET par module
(`PLAFOND_CONTROLES_NUS`) qui ne peut que descendre, et tout module absent de la table est jugé à zéro.

LA RACINE EXAMINÉE est lue par le geste partagé `racine_designee()`, importé de la même garde sœur
`check_every_style_selector_has_a_target.py` plutôt que recopié (`P8.27-a`).
"""
import os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import (  # noqa: E402  (source unique de vérité)
    racine_designee, sans_commentaires_css)

WEB = None  # renseigné par main() : la racine ne se devine pas à l'import (voir `racine_designee`)
PLANCHER_SITES, PLANCHER_CONTEXTES, PLANCHER_CLASSES = 250, 10, 12
# `P11.20-c` — LES CONTRÔLES QUI NE SONT PAS DES BOUTONS. Cette garde ne collectait que `button` : sur un
# `select` ou un `input`, elle ne pouvait STRUCTURELLEMENT pas rougir, c'est-à-dire qu'elle était verte par
# construction — exactement la famille de faux témoins que ce dépôt poursuit. La dérivation est donc
# ÉTENDUE (la même fonction sert les deux familles), pas doublée par une seconde garde.
CONTROLES = ("select", "input", "textarea")
PLANCHER_SITES_C, PLANCHER_CONTEXTES_C, PLANCHER_CLASSES_C = 150, 8, 150
# PLAFOND DE CONTRÔLES NUS PAR MODULE — un CLIQUET, pas une exemption (`P11.20-c`, relevé le 2026-09-03).
#
# POURQUOI UN PLAFOND ET NON ZÉRO, ET LE CHIFFRE QUI L'A DÉCIDÉ. L'extension mesure 199 sites
# `select`/`input`/`textarea` dans `web/`, dont 51 que la dérivation ne peut pas dire habillés. Exiger zéro
# ferait de ce lot une RANÇON : un rouge d'intégration qu'on ne referme qu'en rhabillant 51 commandes, dans
# un lot qui parlait d'autre chose. Le cliquet tient la ligne SANS la rançon — un module absent de cette
# table est jugé à ZÉRO, donc tout contrôle nu POSÉ AILLEURS, dans n'importe quel module de `web/`, est
# désormais un échec, et c'est ce que la garde ne pouvait STRUCTURELLEMENT pas voir avant.
#
# CE QUE CE CHIFFRE N'EST PAS : un compte de défauts visuels. La résolution du parent est LEXICALE (la
# limite assumée en tête), et trois entrées au moins sont des contrôles réellement habillés AILLEURS :
# `#alert-search`, `#rule-search` et le champ de `web/recherche_de_liste.js` reçoivent `.field` par
# `champ.classList.add('field')` dans ce module-là, ce que `web/style.css` dit en toutes lettres à la
# règle `#rule-search,#alert-search`. Le plafond compte donc ce que la dérivation NE PEUT PAS CONCLURE,
# ce qui est le seul compte honnête pour un cliquet ; le faire descendre demande soit d'habiller le
# contrôle, soit de le rendre résoluble là où il est posé.
PLAFOND_CONTROLES_NUS = {
    "admin_users.js": 1,
    "cases.js": 5,
    "composer_depuis_lexistant.js": 1,
    "copie_et_selection.js": 1,
    "core.js": 2,
    "dashboards.js": 3,
    "datamodels.js": 1,
    "destinations.js": 4,
    "detection_admin.js": 1,
    "fieldfilters.js": 2,
    "idp.js": 4,
    "index.html": 15,
    "index_policies.js": 3,
    "processors.js": 2,
    "producer_ui.js": 1,
    "runbooks.js": 3,
    "viz.js": 2,
}
HELPERS = {}    # nom -> classe inconditionnelle (None : la classe vient de l'appel `cls:` ou du contexte)
ID_HTML = {}    # id d'index.html -> ses classes
SEL = re.compile(r"([#.])([\w-]+)")
VIDES = ("input", "br", "img", "hr", "meta", "link", "path", "circle", "rect", "line", "use", "polyline", "polygon")


def deriver(css):
    css = sans_commentaires_css(css)  # on dérive de RÈGLES, pas de prose — voir `P8.27-b` en tête
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


def deriver_controles(css):
    """Contextes et classes qui HABILLENT un `select`, un `input` ou un `textarea` (`P11.20-c`).

    MÊME FORME QUE `deriver`, UNE SIGNATURE DE CLASSE DIFFÉRENTE, ET LA DIFFÉRENCE EST LA MESURE. Pour un
    bouton, la classe qui l'habille se reconnaît à `cursor:pointer` : c'est la signature d'un contrôle
    qu'on a délibérément dessiné. Un champ de saisie n'a pas ce curseur — le reprendre ici rendrait la
    dérivation VIDE côté `input`, donc verte par construction une seconde fois. La signature d'un contrôle
    habillé est son CHROME (`border` ou `background`) : c'est exactement ce qui remplace le rendu natif du
    navigateur, et c'est ce que la feuille pose sur `.field`, `select.picon`, `#range`…

    CE QUE ÇA REND, MESURÉ LE 2026-09-03 sur `web/style.css` : 12 contextes (`.ruleform`, `.modal-f`,
    `.hdr-tools`, `.viewbar`, `.pv-row`…) et 220 classes. L'ensemble des classes est LARGE, et c'est le
    sens JUSTE : la question posée est « ce contrôle porte-t-il une classe que la feuille peint ? », pas
    « cette classe a-t-elle été écrite pour un contrôle ». Un `select` qui porte `.card` n'est PAS au rendu
    natif. Restreindre aux règles à un seul composant (`len(comp) == 1`) rend une soixantaine de classes de
    moins et TROIS nus de plus (54 au lieu de 51) : la borne est peu sensible à ce choix, et le choix retenu
    est celui qui n'accuse pas à tort.

    ANGLE MORT NOMMÉ, PLUTÔT QU'UNE RÈGLE PLUS LARGE. Une règle de BALISE NUE (`select{border:…}`) habille
    TOUS les contrôles de cette balise ; cette dérivation ne la reconnaît pas et continuerait d'accuser.
    La feuille n'en porte aucune aujourd'hui (mesuré le 2026-09-03 : tout le chrome de contrôle y est
    contextuel ou porté par une classe), et le sens de l'omission est CONSERVATEUR — elle accuse trop,
    jamais trop peu. Le jour où une telle règle est écrite, c'est ici qu'il faut la lire, pas dans le
    plafond : monter un plafond pour cacher une accusation à tort serait payer la rançon à l'envers.
    """
    css = sans_commentaires_css(css)  # on dérive de RÈGLES, pas de prose — voir `P8.27-b` en tête
    ctx, cls = set(), set()
    for sels, corps in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if not re.search(r"\b(border|background)\b", corps): continue
        for sel in sels.split(","):
            comp = sel.strip().replace(">", " ").split()
            if not comp: continue
            balise = re.match(r"[a-zA-Z][\w-]*", comp[-1])
            tag = balise.group(0) if balise else None
            if tag in CONTROLES:
                if len(comp) > 1 and not re.search(r":(disabled|hover|focus|checked)", comp[-1]):
                    ctx |= {m.group(0) for m in SEL.finditer(comp[-2])}
                else:  # `select.picon` : la classe est portée PAR le contrôle
                    cls |= {m.group(0) for m in SEL.finditer(comp[-1][balise.end():])}
            elif tag is None and not re.search(r":(disabled|hover|focus|checked)", comp[-1]):
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


def sans_prose_js(ligne):
    """La ligne PRIVÉE de son commentaire de fin de ligne — ou vide si elle n'est QUE du commentaire.

    POURQUOI, MESURÉ LE 2026-08-30. Cette garde dépouillait déjà les commentaires de la FEUILLE (`P8.27-b`,
    en tête) : « on dérive de RÈGLES, pas de prose ». Le même dépouillement manquait du côté JS, où elle
    cherche les balises. Un commentaire qui explique POURQUOI un contrôle est un bouton natif — donc qui
    écrit le nom de la balise entre chevrons — était compté comme un site de bouton NU, et la garde
    accusait une ligne de prose. Même défaut, un côté plus loin : ce qui est dérivé doit l'être du CODE.

    Le dépouillement est délibérément MINIMAL et il le dit : il ne traite que le commentaire de ligne. Un
    bloc `/* … */` étalé sur plusieurs lignes reste vu comme du code — la convention de ce dépôt est le
    commentaire de ligne, et un dépouillement plus large risquerait de manger une chaîne contenant `//`
    (une URL, par exemple), donc de rendre la garde AVEUGLE à de vrais sites. On préfère un angle mort
    NOMMÉ à un dépouillement qui retire trop.
    """
    hors = ligne.find("//")
    if hors < 0:
        return ligne
    avant = ligne[:hors]
    if avant.count("'") % 2 or avant.count('"') % 2 or avant.count("`") % 2:
        return ligne  # le `//` est DANS une chaîne : on ne touche à rien
    return avant


def sites_js(nom, texte, ctx, cls, compter, famille=("button",)):
    """Sites de la `famille` de balises dans un module (ou dans `index.html`), et ceux qui sont NUS.

    `P11.20-c` — LA MÊME FONCTION SERT LES DEUX FAMILLES. Seule la machinerie des HELPERS reste réservée
    aux boutons : elle reconnaît une fabrique à son `return b`, et ce motif n'a pas d'équivalent mesuré
    pour un contrôle (une fabrique de champ écrite en flèche, comme `mkInput` dans `web/fieldfilters.js`,
    n'est pas reconnue — son site est alors compté à sa DÉFINITION, ce qui ne perd rien).
    """
    balises = "|".join(famille)
    lignes, nus, n, pile = texte.split("\n"), [], 0, []
    for i, brute in enumerate(lignes):
        l = sans_prose_js(brute)
        for m in re.finditer(r"(\w+)\s*=\s*document\.createElement\('(" + balises + r")'\)", l):
            v, fen = m.group(1), "\n".join(lignes[i: i + 10])
            if famille == ("button",) and re.search(r"\breturn " + v + r"\b", fen):  # un helper : ses APPELS sont les sites
                f = re.findall(r"function (\w+)\(", "\n".join(lignes[max(0, i - 3): i + 1]))
                if f:
                    sans_if = [st.split("=", 1)[1] for st in re.split(r"[;\n]", fen) if st.strip().startswith(v + ".className")]
                    HELPERS[f[-1]] = next((c for x in sans_if for c in noms(x) & cls), None); continue  # inconditionnelle seule
            if not compter: continue
            n += 1
            if not habille_js(lignes, i, v, ctx, cls): nus.append(f"{nom}:{i + 1} createElement {m.group(2)}")
        if not compter: continue
        for m in re.finditer(r"(\w+)\s*=\s*mk\('(" + balises + r")'\s*,\s*\{([^}]*)\}", l):
            n += 1
            if not (noms(m.group(3)) & cls or habille_js(lignes, i, m.group(1), ctx, cls)): nus.append(f"{nom}:{i + 1} mk {m.group(2)}")
        for m in re.finditer(r"(?:(\w+)\s*=\s*)?\b(\w+)\((?=['\"])", l) if famille == ("button",) else ():
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
            if tag in famille:
                n += 1
                ok = (noms(attrs) | ids(attrs)) & cls or any(p & ctx for p in pile)
                if not ok:  # cible d'un innerHTML à portée courte
                    cible = re.search(r"(\w+)\.innerHTML\s*\+?=", "\n".join(lignes[max(0, i - 3): i + 1]))
                    ok = cible and source_parent(lignes, i, cible.group(1), ctx)
                if not ok: nus.append(f"{nom}:{i + 1} <{tag}")
            if tag not in VIDES and not attrs.rstrip().endswith("/"): pile.append(noms(attrs) | ids(attrs))
    return n, nus


def main():
    global WEB
    WEB = os.path.join(racine_designee(), "web")
    css = open(os.path.join(WEB, "style.css"), encoding="utf-8").read()
    ctx, cls = deriver(css)
    # Témoins de la DÉRIVATION, dans les deux sens. (1) Aucun commentaire ne change plus un compte : la
    # prose ci-dessous cite un corps de règle et finit une tranche sur `d'index.html` — la virgule est
    # nécessaire — et elle faisait naître une classe de bouton de plus, donc habillait des boutons nus.
    # (2) Le dépouillement ne rend pas la dérivation aveugle : une vraie règle reste vue, une règle
    # commentée ne l'est pas. Sans ce second témoin, retirer les commentaires pourrait tout retirer.
    prose = "\n/* la regle vit dans d'index.html, sous la forme button{cursor:pointer} */\n"
    # TÉMOINS DU DÉPOUILLEMENT JS, DANS LES DEUX SENS — posés le 2026-08-30 avec le dépouillement.
    # Sans le second, retirer la prose pourrait tout retirer et la garde passerait au vert en ne
    # mesurant plus rien : c'est exactement la faute que le témoin sœur de la feuille prévient.
    assert sans_prose_js("  // un <button> cité dans un commentaire") == "  ", \
        "témoin : un commentaire de ligne n'est plus dépouillé — une ligne de PROSE serait comptée comme un site de bouton"
    assert "<button" in sans_prose_js("  h += `<button class=\"btn\">ok</button>`;"), \
        "témoin : le dépouillement a mangé du CODE — la garde deviendrait aveugle aux vrais sites"
    assert "//" in sans_prose_js("  const u = 'https://exemple/x'; // note"), \
        "témoin : un `//` situé DANS une chaîne a été pris pour un commentaire"
    assert deriver(css + prose) == (ctx, cls), "témoin : un commentaire de style.css fabrique encore un contexte ou une classe"
    assert deriver("/* .commentee{cursor:pointer} */\n.reelle{cursor:pointer}\n")[1] == {".reelle"}, \
        "témoin : le dépouillement des commentaires a rendu la dérivation aveugle aux vraies règles"
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
    plancher_boutons = total < PLANCHER_SITES or len(ctx) < PLANCHER_CONTEXTES or len(cls) < PLANCHER_CLASSES

    # ---------------------------------------------------------------------------------------------
    # JAMBE B (`P11.20-c`) — LES CONTRÔLES QUI NE SONT PAS DES BOUTONS.
    # ---------------------------------------------------------------------------------------------
    ctx_c, cls_c = deriver_controles(css)
    # TÉMOINS DE L'EXTENSION, DANS LES TROIS SENS. Sans le premier, l'extension serait verte par
    # construction — c'est-à-dire le défaut qu'elle corrige, reproduit un cran plus loin. Sans le
    # deuxième, une extension qui accuserait TOUT passerait. Sans le troisième, les deux familles
    # pourraient se mélanger : la jambe des boutons compterait des `select` et son verdict changerait
    # de sens sans que personne ne le voie.
    nu_c = "function r() {\n  const s = document.createElement('select');\n  host.appendChild(s);\n}\n"
    ok_c = ("const host = document.createElement('div'); host.className = 'ruleform';\n" + nu_c
            + "const i = document.createElement('input'); i.className = 'field';\n"
            + "el.innerHTML = `<div class=\"modal-f\"><select id=\"z\"></select><textarea></textarea></div>`;\n")
    assert sites_js("temoin", nu_c, ctx_c, cls_c, True, CONTROLES)[1], \
        "témoin : un contrôle NU n'a pas rougi — l'extension serait verte par construction, le défaut même de `P11.20-c`"
    assert not sites_js("temoin", ok_c, ctx_c, cls_c, True, CONTROLES)[1], \
        "témoin : un contrôle HABILLÉ a rougi, l'instrument hallucine"
    assert not sites_js("temoin", nu_c, ctx, cls, True)[1], \
        "témoin : la famille des BOUTONS voit un `select` — les deux jambes se sont mélangées"
    total_c, nus_c = 0, {}
    for f in fichiers + ["index.html"]:
        n, liste = sites_js(f, sources[f], ctx_c, cls_c, True, CONTROLES)
        total_c += n
        if liste: nus_c[f] = liste
    print(f"[contrôles] {total_c} sites select/input/textarea, {len(ctx_c)} contextes, {len(cls_c)} classes "
          f"dérivés de style.css ; {sum(len(v) for v in nus_c.values())} nu(s) répartis sur {len(nus_c)} module(s)")
    if plancher_boutons or total_c < PLANCHER_SITES_C or len(ctx_c) < PLANCHER_CONTEXTES_C or len(cls_c) < PLANCHER_CLASSES_C:
        print("[chrome] ÉCHEC — sous le plancher : la dérivation est cassée, la garde refuse de conclure"); return 2

    for s in nus: print("    - " + s)
    regressions = [(f, l) for f, l in sorted(nus_c.items()) if len(l) > PLAFOND_CONTROLES_NUS.get(f, 0)]
    for f, l in regressions:
        for site in l: print("    - " + site)
    if nus:
        print(f"[boutons] ÉCHEC — {len(nus)} bouton(s) NU(s) : classe partagée (.btn, .btn-primary, .btn-danger, .btn-link, .picon) ou contexte stylant")
    if regressions:
        print(f"[contrôles] ÉCHEC — {len(regressions)} module(s) au-dessus de leur plafond de contrôles nus : "
              + ", ".join(f"{f} {len(l)} > {PLAFOND_CONTROLES_NUS.get(f, 0)}" for f, l in regressions)
              + ". Donner au contrôle une classe que la feuille peint (`.field`, `.picon`, `.k-theme`…) ou le "
                "poser dans un contexte qui l'habille (`.ruleform`, `.modal-f`, `.pv-row`…) — puis ABAISSER le "
                "plafond de son module d'autant. Le cliquet ne monte pas.")
    if nus or regressions: return 1
    jeu = sorted((f, PLAFOND_CONTROLES_NUS[f] - len(nus_c.get(f, [])))
                 for f in PLAFOND_CONTROLES_NUS if PLAFOND_CONTROLES_NUS[f] > len(nus_c.get(f, [])))
    print("[boutons] OK — aucun bouton nu")
    print(f"[contrôles] OK — {sum(len(v) for v in nus_c.values())} contrôle(s) nu(s), tous sous le plafond de leur module "
          f"({len(PLAFOND_CONTROLES_NUS)} plafonds tenus ; un module absent de la table est jugé à ZÉRO)")
    if jeu:
        print(f"[contrôles] JEU DU CLIQUET : {len(jeu)} plafond(s) au-dessus de leur relevé du jour "
              f"({', '.join(f'{f} +{d}' for f, d in jeu)}) — à abaisser, c'est le seul mouvement qui ne se discute pas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
