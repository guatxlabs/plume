#!/usr/bin/env python3
# DOCSTRING BRUTE : elle cite une expression régulière (`/^\/api\//`). Non brute, `\/` est une séquence
# d'échappement INVALIDE — un `SyntaxWarning` aujourd'hui, une `SyntaxError` demain — et le bruit sortait
# sur `stderr` de CHAQUE garde qui importe ce module (`P11.8-m`). Contenu inchangé : vérifié, la docstring
# ne porte aucune séquence d'échappement VALIDE, les deux littéraux sont le même texte.
r"""Aucune règle de `web/style.css` ne cible un identifiant ou une classe que la surface ne pose nulle part
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

LE DÉPOUILLEUR JAVASCRIPT N'EST PLUS ÉCRIT ICI (`P11.8-f`). Le corpus du point (2) est le code SANS ses
commentaires, et cette garde en portait sa PROPRE copie — la cinquième du dépôt. Elle avait la cécité que
les quatre autres ont perdue : un `"` ou un `'` posé dans un littéral d'EXPRESSION RÉGULIÈRE y ouvrait une
fausse chaîne, si bien que les commentaires de la région n'étaient PLUS retirés ; et une séquence `//` dans
un motif était prise pour un commentaire de ligne, ce qui MANGEAIT la fin de la ligne. Mesuré le 2026-08-26
sur `web/` : 8 462 caractères de commentaire gardés en trop (`core.js` 89 lignes après `/[&<>"]/g`,
`viz.js` 4) et 32 caractères de code mangés (`app.js`, `/^\/api\//`). Le sens du défaut ICI est le PIRE des
deux : un nom cité dans un commentaire non retiré est compté POSÉ, donc une règle de style morte passe en
VERT SILENCIEUX. Prouvé par mutation le 2026-08-26 — une règle `.fantome-en-commentaire{}` citée seulement
dans un commentaire placé après cette expression régulière : l'ancien dépouilleur rendait 0 (« 0 orphelin,
plafond tenu »), le lecteur partagé rend 1 en la nommant ; le même nom posé dans du vrai code reste vert des
deux côtés. Le lecteur vient donc de `check_every_help_trigger_has_a_section.py`, comme pour les gardes du
lexique, des verdicts et des routes sensibles, et il est VALIDÉ (`temoins_du_lecteur()`) avant de servir :
importé, il ne joue pas ses témoins tout seul. Il DIT aussi quand il perd la synchronisation, et la garde
REFUSE ALORS DE CONCLURE (code 2) au lieu de juger sur un corpus dont la frontière code/commentaire a
bougé — la sortie sur l'arbre du jour est inchangée mot pour mot.

LA RACINE EXAMINÉE EST UN GESTE PARTAGÉ, ÉCRIT ICI ET NULLE PART AILLEURS. `racine_designee()` est
IMPORTÉE par les deux gardes sœurs qui lisent la même surface (`check_every_button_wears_shared_chrome.py`,
`check_no_operational_figure_is_published.py`) plutôt que recopiée : trois recopies, c'est ce qui a
permis à l'une des trois de diverger et d'ignorer en silence la racine qu'on lui désignait (`P8.27-a`).
"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (LECTEUR PARTAGÉ, source unique — `P11.8-f`)
    refuser_sur_aveu, sans_commentaires_js, temoins_du_lecteur)

WEB = None  # renseigné par main() : la racine ne se devine pas à l'import (voir `racine_designee`)
FEUILLE = "style.css"
PLANCHER_SELECTEURS, PLANCHER_FICHIERS = 300, 20
# PLAFOND D'ORPHELINS. Relevé le 2026-08-22 après retrait des règles mortes : zéro. Une règle de style dont
# la cible n'est posée nulle part est une régression ; l'abaisser est le seul sens admis sans raison écrite.
PLAFOND_ORPHELINS = 0

TOKEN = re.compile(r"([#.])(-?[_a-zA-Z][\w-]*)")


# ── CE QUI N'EST JAMAIS DE LA SOURCE — GESTE PARTAGÉ, ÉCRIT ICI ET NULLE PART AILLEURS (`P11.8-m`) ──
# LE DÉFAUT QUE CECI FERME, ET LE RECENSEMENT QUI LE BORNE (2026-08-31). QUINZE gardes de
# `.github/scripts/` énumèrent l'arbre DEPUIS LE DISQUE (`os.walk`, `rglob`, `listdir`) au lieu de passer
# par l'arbre suivi ; les autres passent par `git ls-files` et sont immunisées par construction. QUATRE de
# ces quinze partent de la RACINE DU DÉPÔT — la garde du lexique (corrigée sous `P11.8-l`), celle-ci n'en
# est pas, `manifestes()` de la garde des déploiements, et les deux découvertes de caisses (producteurs,
# verrous d'environnement). UNE SEULE descend `web/` RÉCURSIVEMENT (la garde du stockage de site) ; les
# trois autres gardes de `web/` y font un `listdir` PLAT et sont immunisées par leur PLATITUDE, pas par
# une exclusion. Le reste part de `daemon/src` ou de `<caisse>/src`, où ni cargo ni npm n'écrivent jamais.
# L'ÉNONCÉ « onze n'excluaient RIEN » est donc FAUX et il est corrigé ici : quatre élaguaient déjà, mais
# CHACUNE AVEC SA PROPRE LISTE — trois noms et des répertoires SEULEMENT pour les déploiements, `.`+`target`
# pour les verrous d'env, `tests` pour les lectures manquantes, quatre noms pour le lexique. C'est la
# DIVERGENCE de ces copies qui est le défaut, pas leur absence : élargir une racine rouvrait EN SILENCE le
# trou que `P11.8-l` venait de fermer, un artefact d'outil entrant dans un corpus de sources.
#
# POURQUOI PAS ONZE COPIES. Le dépôt a déjà payé la recopie : trois copies de la racine désignée avaient
# divergé, et l'une mesurait un arbre qu'on ne lui avait pas désigné (`P8.27-a`, l'en-tête ci-dessus).
# La règle est donc écrite ICI, à côté de `racine_designee()`, et IMPORTÉE.
#
# POURQUOI PAS `git ls-files`, QUI FERMERAIT LE TROU PAR CONSTRUCTION. Parce que ce dépôt a mesuré l'autre
# bord et l'a écrit cinq fois : un corpus pris dans l'INDEX rend vert sur un fichier ÉCRIT ET PAS ENCORE
# SUIVI — le moment exact où il porte encore ses défauts (`P11.13-d` dans la garde des verrous d'env,
# `check_no_naked_site_storage_write.py`, `check_every_guard_written_is_a_guard_wired.py`,
# `check_no_instrument_hardcodes_an_author_machine_path.py`, `check_coverage_loss_is_never_silent.py`).
# Convertir échangerait un risque LATENT de gonflement contre un angle mort ACTIF. Le disque reste la
# source, et c'est l'élagage qui devient une propriété.
#
# L'EXCLUSION PORTE SUR LE NOM, FICHIER COMME RÉPERTOIRE (`P11.8-l`) : un `.git` de `git worktree` — ou de
# sous-module — est un FICHIER dont le contenu est un CHEMIN, et n'élaguer que les répertoires rendait la
# mesure dépendante de la façon dont l'arbre avait été sorti.
#
# VÉRIFIÉ AVANT D'EXCLURE, PARCE QU'UNE EXCLUSION QUI RETIRE UN FICHIER LÉGITIME EST PIRE QUE LE DÉFAUT :
# le 2026-08-31, aucun des 791 fichiers de `git ls-files` ne porte l'un de ces noms, à aucune profondeur
# de son chemin (0 pour chacun des douze). `dist` et `build` en sont volontairement ABSENTS : ils nomment
# aussi bien un artefact qu'un répertoire de sources, et le doute doit aller vers LIRE, pas vers exclure.
NOMS_HORS_ARBRE = (
    ".git", "target", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
)


def hors_arbre(nom):
    """Ce nom désigne-t-il un artefact d'outil ou une dépendance tierce, jamais une source du dépôt ?"""
    return nom in NOMS_HORS_ARBRE


def parcours_des_sources(racine, hors=()):
    """`os.walk` dont les artefacts sont ÉLAGUÉS PAR NOM — le seul parcours à la main admis (`P11.8-m`).

    Rend `(dossier, fichiers)` comme `os.walk`, mais : les répertoires portant un nom hors arbre ne sont
    pas descendus, et les fichiers portant un tel nom ne sont pas rendus. `hors` ajoute les noms propres
    à un appelant (la garde des lectures manquantes élague `tests`) sans qu'il ait à réécrire l'élagage.

    L'élagage est fait DANS la descente (`dossiers[:] = …`), jamais après : un `node_modules` filtré à la
    sortie aurait déjà été LU, et un répertoire de construction porte par conception des ordres de
    grandeur plus de fichiers que les sources dont il dérive : le lire pour le jeter rendrait la garde
    inutilisable."""
    interdits = set(NOMS_HORS_ARBRE) | set(hors)
    for base, dossiers, fichiers in os.walk(racine):
        dossiers[:] = [d for d in dossiers if d not in interdits]
        yield base, sorted(f for f in fichiers if f not in interdits)


def racine_designee(argv=None):
    """La racine EXAMINÉE, écrite UNE fois pour les trois gardes sœurs qui la lisent (`P8.27-a`).

    Deux d'entre elles honoraient leur premier argument, la troisième l'AVALAIT sans effet et
    dérivait toujours sa racine du répertoire courant. Un outil qui accepte une racine et en mesure
    une autre ment sur ce qu'il fait : son rouge accuse un arbre qu'on n'a pas désigné — le symptôme
    par lequel le défaut s'est vu — et son vert, plus grave parce que silencieux, n'atteste rien de
    celui qu'on voulait juger. Une racine inutilisable est donc REFUSÉE (code 2, aucun verdict), et
    jamais remplacée par une devinette : c'est la retombée muette qui rendait l'argument mensonger.
    """
    argv = sys.argv if argv is None else argv
    if len(argv) > 2:
        print(f"[racine] REFUS — une seule racine attendue, {len(argv) - 1} arguments reçus.", file=sys.stderr)
        raise SystemExit(2)
    if len(argv) == 2:
        if not os.path.isdir(argv[1]):
            print(f"[racine] REFUS — la racine désignée « {argv[1]} » n'est pas un répertoire ; retomber "
                  f"sur le dépôt courant rendrait un verdict sur un arbre qu'on n'a pas choisi.", file=sys.stderr)
            raise SystemExit(2)
        return os.path.abspath(argv[1])
    fait = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if fait.returncode or not fait.stdout.strip():
        print("[racine] REFUS — aucune racine désignée et le répertoire courant n'est pas un arbre git.",
              file=sys.stderr)
        raise SystemExit(2)
    return fait.stdout.strip()


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


def sans_commentaires_html(src):
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.S)


def corpus_web(aveux=None):
    """{fichier: texte sans commentaires} pour tout ce qui, sous `web/`, peut poser un nom — sauf la feuille.
    `aveux` recueille les PERTES DE SYNCHRONISATION du lecteur partagé : une région mal lue déplace la
    frontière entre le code et ses commentaires, donc le verdict « posé / orphelin » (voir `main`)."""
    corpus = {}
    for f in sorted(os.listdir(WEB)):
        chemin = os.path.join(WEB, f)
        if not os.path.isfile(chemin) or f == FEUILLE: continue
        if f.endswith(".js"):
            journal, brut = [], open(chemin, encoding="utf-8").read()
            corpus[f] = sans_commentaires_js(brut, journal)
            if journal and aveux is not None:
                aveux[f] = [f"ligne {brut.count(chr(10), 0, o) + 1} : {motif}" for motif, o in journal]
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
    global WEB
    WEB = os.path.join(racine_designee(), "web")
    css = open(os.path.join(WEB, FEUILLE), encoding="utf-8").read()
    aveux = {}
    corpus = corpus_web(aveux)
    # LE LECTEUR AVOUE, LA GARDE REFUSE DE CONCLURE (`P11.8-f`). Un dépouilleur désynchronisé ne rougit
    # pas : il rend un corpus où un nom cité en commentaire redevient « posé » (orphelin manqué, vert
    # silencieux) ou bien mange le code qui posait un nom (orphelin inventé). Les deux passent pour un
    # verdict, aucun ne se plaint.
    if aveux and refuser_sur_aveu("style", aveux): return 2
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
    # LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR (`P11.8-f`) : il est IMPORTÉ, ses témoins ne tournent
    # pas à l'import. C'est le geste des trois gardes sœurs qui le partagent déjà.
    temoins_du_lecteur()
    # ET IL EST VALIDÉ SUR CE QUE CETTE GARDE-CI EN FAIT : le corpus sert à décider si un nom est POSÉ.
    # Un commentaire qui n'est pas retiré rend « posé » un nom que personne ne pose — l'orphelin passe en
    # VERT SILENCIEUX. C'est ce que faisait la copie locale du dépouilleur : un `"` dans une expression
    # régulière ouvrait une fausse chaîne, et les commentaires jusqu'au guillemet suivant restaient.
    # Mesuré le 2026-08-26 sur `web/` : 8 462 caractères de commentaire gardés en trop (`core.js` 89 lignes,
    # `viz.js` 4) et 32 caractères de CODE mangés (`app.js`, `/^\/api\//` lu comme un commentaire de ligne).
    fausse_chaine = 'const esc = s => String(s).replace(/[&<>"]/g, c => X[c]);\n// .fantome-en-commentaire\n'
    assert "fantome-en-commentaire" not in sans_commentaires_js(fausse_chaine), \
        "témoin : après une expression régulière porteuse d'un guillemet, un commentaire n'est plus retiré — " \
        "un nom cité là serait compté POSÉ et une règle de style morte passerait en vert"
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
