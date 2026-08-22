#!/usr/bin/env python3
"""Aucune règle de `web/style.css` ne cible un identifiant ou une classe que la surface ne pose nulle part
— instrument de mesure et garde de CI (`P11.4-d`).

LE DÉFAUT. Quand un bouton passe au chrome partagé (`.btn`) ou qu'une vue est retirée, ses règles de style
restent : `#ack-all{…}` habillait un bouton qui ne porte plus d'identifiant depuis qu'il porte `data-act`
et `.btn`. Une règle morte n'est pas un bug visible ; c'est une feuille de style qui ment sur la surface,
et qu'un lecteur suit pour rien.

L'INSTRUMENT EST DÉRIVÉ, PAS ÉNUMÉRÉ.
  (1) De `style.css` on tire chaque IDENTIFIANT (`#x`) et chaque CLASSE (`.x`) cité dans un SÉLECTEUR —
      le texte qui précède un `{`, hors commentaires, hors corps de déclaration (un `url(#x)` ou une
      opacité `.5` dans un corps n'est pas un sélecteur), hors préludes d'at-rules (`@media`, `@keyframes`).
  (2) Du reste de `web/` (index.html, chaque module, le service worker) on tire le CORPUS où un nom peut
      être posé : le code SANS ses commentaires (un nom cité dans un commentaire n'habille rien), chaînes et
      gabarits compris (c'est là que vivent `class="…"`, `className = '…'`, `classList.add('…')`, `$('#…')`).
  (3) Un nom est POSÉ s'il apparaît dans le corpus comme mot entier (bornes : ni lettre, ni chiffre, ni `_`,
      ni `-` de part et d'autre). Cette lecture est VOLONTAIREMENT large — `id="x"`, `'#x'`, `'.x'`,
      `getElementById('x')`, `class="a x b"`, `x:` dans un objet — et son biais va vers « posé » :
      l'instrument sous-compte les orphelins, jamais l'inverse.
  (4) Un nom ABSENT du corpus n'est pas orphelin d'office : le code construit des classes par concaténation
      (`className = 'badge role-' + u.role`) ou interpolation (`` `sev-${s}` ``). On dérive du corpus tous les
      PRÉFIXES et SUFFIXES statiques adjacents à un `+` ou à un `${…}` ; un nom absent qui commence par un
      tel préfixe (ou finit par un tel suffixe) est INDÉCIDABLE — il est nommé, avec le préfixe qui le rend
      tel, jamais compté orphelin. Un nom absent sans aucun préfixe ni suffixe dynamique est ORPHELIN.

CE QUE L'INSTRUMENT NE VOIT PAS — DIT FRANCHEMENT. Une classe dont le nom ENTIER vient d'une valeur servie
par le démon et posée telle quelle (`'posture ' + h.posture` où `h.posture` vaut `green`) n'est vue que si
le mot (`green`) existe ailleurs dans le code ; sinon elle est comptée ORPHELINE à tort. C'est pourquoi la
liste est rendue nom par nom : la suppression d'une règle est une décision de lecture, la garde ne tient
que le COMPTE. Un sélecteur d'attribut (`[data-x]`) ou d'élément n'est pas jugé.

LA GARDE REFUSE UNE RÉGRESSION, PAS UN ÉTAT. Le nombre d'orphelins est comparé à un PLAFOND écrit ici avec
sa date ; une règle morte de plus rougit, en retirer une autorise à abaisser le plafond. L'instrument se
valide d'abord sur deux témoins (une règle `#inexistant{}` DOIT rougir, `.btn` NE DOIT PAS) et refuse de
conclure sous un plancher de sélecteurs et de fichiers de corpus.
"""
import os, re, subprocess, sys

RACINE = (sys.argv[1] if len(sys.argv) > 1 else subprocess.run(["git", "rev-parse", "--show-toplevel"],
          capture_output=True, text=True, check=True).stdout.strip())
WEB = os.path.join(RACINE, "web")
FEUILLE = "style.css"
PLANCHER_SELECTEURS, PLANCHER_FICHIERS = 300, 20
# PLAFOND D'ORPHELINS. Relevé le 2026-08-22 après retrait des règles mortes : zéro. Une règle de style dont
# la cible n'est posée nulle part est une régression ; l'abaisser est le seul sens admis sans raison écrite.
PLAFOND_ORPHELINS = 0

TOKEN = re.compile(r"([#.])(-?[_a-zA-Z][\w-]*)")


def sans_commentaires_css(css):
    """Un commentaire devient des blancs de même hauteur : les numéros de ligne rendus restent ceux du fichier."""
    return re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), css, flags=re.S)


def selecteurs(css):
    """Chaque (`#x` | `.x`, ligne) cité dans un prélude de règle — jamais dans un corps ni une at-rule."""
    css = sans_commentaires_css(css)
    trouves, tampon, lignes, ligne = [], [], [], 1
    for ch in css:
        if ch == "{":
            prelude = "".join(tampon)
            if prelude.strip() and not prelude.lstrip().startswith("@"):
                for m in TOKEN.finditer(prelude):
                    trouves.append((m.group(1) + m.group(2), lignes[m.start()]))
            tampon, lignes = [], []
        elif ch in "};":
            tampon, lignes = [], []
        else:
            tampon.append(ch); lignes.append(ligne)
        if ch == "\n": ligne += 1
    return trouves


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


def corpus_web():
    """{fichier: texte sans commentaires} pour tout ce qui, sous `web/`, peut poser un nom — sauf la feuille."""
    corpus = {}
    for f in sorted(os.listdir(WEB)):
        chemin = os.path.join(WEB, f)
        if not os.path.isfile(chemin) or f == FEUILLE: continue
        if f.endswith(".js"): corpus[f] = sans_commentaires_js(open(chemin, encoding="utf-8").read())
        elif f.endswith((".html", ".svg", ".webmanifest")): corpus[f] = sans_commentaires_html(open(chemin, encoding="utf-8").read())
    return corpus


def bords_dynamiques(corpus):
    """Préfixes (texte statique juste AVANT un `+` / `${`) et suffixes (juste APRÈS) des chaînes construites."""
    prefixes, suffixes = set(), set()
    for texte in corpus.values():
        for lit in re.findall(r"'((?:[^'\\\n]|\\.)*)'\s*\+|\"((?:[^\"\\\n]|\\.)*)\"\s*\+", texte):
            mots = "".join(lit).split()
            if mots and not "".join(lit).endswith((" ", "\t")): prefixes.add(mots[-1])
        for lit in re.findall(r"\+\s*'((?:[^'\\\n]|\\.)*)'|\+\s*\"((?:[^\"\\\n]|\\.)*)\"", texte):
            mots = "".join(lit).split()
            if mots and not "".join(lit).startswith((" ", "\t")): suffixes.add(mots[0])
        for m in re.finditer(r"`((?:[^`\\]|\\.)*?)`", texte, flags=re.S):
            segments = re.split(r"\$\{[^}]*\}", m.group(1))
            for k, seg in enumerate(segments):
                if k < len(segments) - 1 and seg and not seg[-1].isspace() and seg.split(): prefixes.add(seg.split()[-1])
                if k > 0 and seg and not seg[0].isspace() and seg.split(): suffixes.add(seg.split()[0])
    # Un bord se termine ou commence sur un fragment de nom : on ne garde que ce fragment (lettres, chiffres, - _).
    couper = lambda s, fin: (re.search(r"[\w-]+$", s) if fin else re.match(r"[\w-]+", s))
    # Un bord d'une seule lettre (`(h / 3600) + 'h'`) rendrait indécidable tout nom qui la porte : deux signes au moins.
    prefixes = {couper(p, True).group(0) for p in prefixes if couper(p, True) and len(couper(p, True).group(0)) >= 2}
    suffixes = {couper(s, False).group(0) for s in suffixes if couper(s, False) and len(couper(s, False).group(0)) >= 2}
    return prefixes, suffixes


def juger(noms, corpus, prefixes, suffixes):
    """-> (posés, indécidables {nom: bord}, orphelins) sur l'ensemble des noms (`#x` / `.x`)."""
    texte = "\n".join(corpus.values())
    poses, indecidables, orphelins = set(), {}, set()
    for nom in noms:
        brut = nom[1:]
        # Un identifiant n'est posé que par `id=`, `id:`, `.id =`, `getElementById(` ou un `#x` (sélecteur, ancre) :
        # `data-act="ack-all"` ne pose PAS `#ack-all`. Une classe est posée par tout mot entier du code.
        devant = r"(?:#|\bid\s*[=:]\s*[\"'`]?|getElementById\(\s*[\"'`])" if nom[0] == "#" else r"(?<![\w-])"
        if re.search(devant + re.escape(brut) + r"(?![\w-])", texte): poses.add(nom); continue
        bord = next((p for p in sorted(prefixes, key=len, reverse=True) if brut.startswith(p) and len(brut) > len(p)), None) \
            or next((s for s in sorted(suffixes, key=len, reverse=True) if brut.endswith(s) and len(brut) > len(s)), None)
        if bord: indecidables[nom] = bord
        else: orphelins.add(nom)
    return poses, indecidables, orphelins


def main():
    css = open(os.path.join(WEB, FEUILLE), encoding="utf-8").read()
    corpus = corpus_web()
    prefixes, suffixes = bords_dynamiques(corpus)
    # Témoins : l'instrument DOIT accuser une règle sans cible et se taire sur une classe partagée, avant de juger.
    temoin = selecteurs(css + "\n#inexistant-temoin{color:red}\n.btn{color:red}\n")
    noms_temoin = {n for n, _ in temoin}
    assert "#inexistant-temoin" in noms_temoin and ".btn" in noms_temoin, "témoin : l'extracteur de sélecteurs ne lit plus une règle ajoutée"
    _, _, orph_temoin = juger({"#inexistant-temoin", ".btn"}, corpus, prefixes, suffixes)
    assert "#inexistant-temoin" in orph_temoin, "témoin positif : `#inexistant-temoin{}` n'a pas rougi, l'instrument est aveugle"
    assert ".btn" not in orph_temoin, "témoin négatif : `.btn` est accusée à tort, l'instrument hallucine"
    assert not selecteurs("a{opacity:.5;background:url(#x)} /* .commente */ @media(min-width:1px){}"), "témoin : un corps, un commentaire ou une at-rule est lu comme sélecteur"
    assert ".x" in {n for n, _ in selecteurs("@media print{ .x{display:none} }")}, "témoin : un sélecteur sous @media n'est pas lu"
    assert "posted-one" in sans_commentaires_js("const u = 'http://h/posted-one'; // .commented-one") and "commented-one" not in sans_commentaires_js("const u = 'http://h/posted-one'; // .commented-one"), "témoin : le dépouillement des commentaires JS coupe une chaîne ou garde un commentaire"

    trouves = selecteurs(css)
    noms = {n for n, _ in trouves}
    lignes = {}
    for n, l in trouves: lignes.setdefault(n, []).append(l)
    print(f"[style] {len(noms)} identifiants/classes distincts dans {len(trouves)} citations de sélecteurs de {FEUILLE} ; corpus de {len(corpus)} fichiers ; {len(prefixes)} préfixes et {len(suffixes)} suffixes dynamiques dérivés")
    if len(noms) < PLANCHER_SELECTEURS or len(corpus) < PLANCHER_FICHIERS:
        print("[style] ÉCHEC — sous le plancher : la dérivation est cassée, la garde refuse de conclure"); return 2
    poses, indecidables, orphelins = juger(noms, corpus, prefixes, suffixes)
    print(f"[style] {len(poses)} posés, {len(indecidables)} indécidables (construits dynamiquement), {len(orphelins)} orphelins")
    for n in sorted(indecidables): print(f"    ? {n}  (bord dynamique « {indecidables[n]} », lignes {', '.join(map(str, lignes[n]))})")
    for n in sorted(orphelins): print(f"    - {n}  (lignes {', '.join(map(str, lignes[n]))})")
    if len(orphelins) > PLAFOND_ORPHELINS:
        print(f"[style] ÉCHEC — {len(orphelins)} règle(s) de style sans cible dans web/, plafond {PLAFOND_ORPHELINS} : retirer la règle, ou poser le nom"); return 1
    print(f"[style] OK — {len(orphelins)} orphelin(s), plafond {PLAFOND_ORPHELINS} tenu")
    return 0


if __name__ == "__main__":
    sys.exit(main())
