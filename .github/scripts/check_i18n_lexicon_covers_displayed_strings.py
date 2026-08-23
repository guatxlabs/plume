#!/usr/bin/env python3
"""Le lexique fr/en couvre les chaînes AFFICHÉES de chaque module web — garde de CI (`P11.8-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
La console traduit par DICTIONNAIRE : `web/i18n.js` porte une table FR -> EN, et `i18nWalk`
remplace un nœud texte (ou un attribut `title`/`placeholder`/`aria-label`) dont la valeur,
une fois les blancs retirés, est EXACTEMENT une clé. Une chaîne sans clé reste en français :
la dégradation est silencieuse, et elle s'accumule module après module sans qu'aucun outil ne
la voie. Un analyste en langue anglaise lit alors une console bilingue par accident.

CE QU'EST UNE « CHAÎNE AFFICHÉE » — LE CRITÈRE, ÉCRIT
-----------------------------------------------------
Une chaîne est AFFICHÉE si le code la pose dans un puits de rendu, c'est-à-dire :
  (1) une affectation `.textContent = `, `.innerText = `, `.title = `, `.placeholder = ` ;
  (2) une clé d'objet `label:`, `title:`, `placeholder:`, `okText:`, `hint:`, `text:` ;
  (3) un appel `createTextNode(`, `muted(`, `toast(`, `showErr(`, `confirmModal(`, `append(`,
      `prepend(`, ou `setAttribute('title'|'placeholder'|'aria-label', ` ;
  (4) le TEXTE entre balises et les attributs `title`/`placeholder`/`aria-label` d'un littéral
      HTML (chaîne contenant une balise, posée en `innerHTML` ou construite en gabarit) ;
  (5) le texte et les mêmes attributs de `web/index.html`.
Le mécanisme ne peut traduire qu'une chaîne STATIQUE : une chaîne concaténée (`'a' + x`) ou
interpolée (`${x}`) ne sera jamais égale à une clé — elle est comptée À PART (« dynamique »),
hors du dénominateur, et rendue pour information. Une chaîne composée UNIQUEMENT de
minuscules ASCII, chiffres et `_ . : / -` (`src_ip`, `count`, `/api/x`) est un identifiant
technique, identique dans les deux langues : hors population ; de même un code en MAJUSCULES
sans espace qui porte un chiffre ou tient en quatre signes (`T1110`, `CSV`, `OK`). Une chaîne
sans lettre (un symbole, un nombre) est hors population. Le texte d'un ÉCHANTILLON DE CODE
(`<code>`, `<kbd>`, `<pre>`, `<samp>`) est montré tel quel dans les deux langues : hors population,
comme un `<script>`. Une chaîne choisie par `LANG === 'en' ? … : …` ou posée dans un bloc
`if (LANG === 'en') { … }` est bilingue PAR CONSTRUCTION (son pendant FR est ailleurs) : couverte
sans passer par le lexique ; de même une valeur posée sous une clé `fr:` ou `en:` d'un objet (`{ fr: '…',
en: '…' }`, choisi par LANG à l'endroit du rendu) : les deux langues sont côte à côte. Les attributs
affichés sont `title`, `placeholder`, `aria-label` et `label` (groupe d'options) — ce sont ceux que
`i18nWalk` traduit.

CE QUE LA GARDE NE VOIT PAS — DIT FRANCHEMENT
---------------------------------------------
Un puits propre à un module (`opt(...)` dans alerts.js, `tile(...)` / `mesureTile(...)` dans
system.js, `kv(...)` ailleurs) n'est pas reconnu : les chaînes qui y passent ne sont PAS comptées
(les libellés des tuiles Système sont au lexique sans être comptés ici). Un mot en minuscules
ASCII (`frais`, `statut`) est exclu par le critère d'identifiant alors qu'il peut être un libellé,
et un fragment de phrase riche en minuscules (`) du message`, `puis`) l'est de même : le lexique
les porte pour que la phrase ANGLAISE se lise entière, la garde ne les exige pas. Les biais vont
dans le sens d'un SOUS-compte des trous ; la garde mesure donc un plancher de la dette, jamais
son plafond. Un texte posé par un nœud puis RETRAITÉ par une concaténation n'est pas suivi.
Elle ne juge pas non plus si le MÉCANISME applique le lexique : c'est le harnais ESM
(`web_esm_harnais.mjs`, témoin 10) qui rend un panneau sous `LANG='en'` et lit le texte. Une paire
`{ fr, en }` dont les deux valeurs seraient le même texte n'est pas jugée ici (le registre l'est par le
témoin 13 du harnais : chaque section rend un anglais distinct du français).

L'EXEMPTION EST UNE SURFACE, PAS UN MODULE
-----------------------------------------
Le REGISTRE des sections d'aide (`{clé: {fr:{title,body}, en:{title,body}}}`) est le seul texte de la
console qui porte ses deux langues dans des objets imbriqués que le critère ci-dessus ne lit pas (la valeur
est sous `title:`/`body:`, à l'intérieur de `fr:`/`en:`). Seule la PORTÉE de sa définition `const HELP = {
… }` est exemptée : le module qui la porte est DÉRIVÉ (celui de `web/` qui la contient, commentaires
retirés — dérivation et portée importées de `check_every_help_trigger_has_a_section.py`), et ce qui
l'entoure dans ce module est jugé au plafond zéro comme tout autre. S'il n'est pas retrouvé, la garde
refuse de conclure plutôt que de le rendre sans le juger. Avant (2026-08-22) : la mécanique de l'aide
(`help.js`) était exemptée en ENTIER au motif que ses modales choisissaient leur langue par `LANG` — et
cette exemption cachait tout ce que le module pouvait poser en dur : l'anglais d'un titre dupliqué hors
lexique, un mot nu sans clé. Une exemption de module ne voit rien ; une exemption de surface voit le reste.

LA GARDE REFUSE UNE RÉGRESSION, PAS UN ÉTAT
-------------------------------------------
Le taux de couverture (clés présentes / population) est mesuré et rendu PAR MODULE ; ce qui
est GARDÉ est le nombre de chaînes affichées SANS entrée (les « trous »), comparé à un PLAFOND
écrit ici avec sa date. Pourquoi le compte et non le taux : un taux ne voit pas UNE chaîne de
plus parmi six cents (20,6 % -> 20,4 %), le compte la voit. Ajouter une chaîne affichée sans
l'inscrire au lexique fait dépasser le plafond : rouge. Traduire abaisse le compte et autorise
à ABAISSER le plafond — c'est le seul sens de modification admis sans raison écrite à côté.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Un extracteur rend vert de deux façons : tout va bien, ou son motif ne reconnaît plus rien.
La garde exécute d'abord un corpus de contrôle (chaînes qu'elle DOIT reconnaître dans chaque
puits, chaînes qu'elle NE DOIT PAS compter : classe CSS, identifiant, chaîne dynamique,
commentaire), puis exige un PLANCHER de population sur l'arbre réel et la présence d'une clé
témoin connue. Sans ces trois jambes, elle refuse de conclure (code 2), elle ne rend pas vert.

Usage :  python3 .github/scripts/check_i18n_lexicon_covers_displayed_strings.py [--mesure] [--trous MODULE]
Sortie :  0 = aucun module au-dessus de son plafond ; 1 = régression ; 2 = instrument invalide.
          `--mesure` imprime le tableau par module sans verdict ; `--trous MODULE` liste les
          chaînes du module sans entrée au lexique.
"""
from __future__ import annotations

import html.parser
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import module_du_registre, portee_du_registre, sans_commentaires_js  # noqa: E402  (source unique)

RACINE = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB = os.path.join(RACINE, "web")
LEXIQUE = os.path.join(WEB, "i18n.js")

# Plancher de population sur l'arbre réel : en dessous, c'est l'extraction qui est cassée.
# Relevé le 2026-08-22 : 1 579 chaînes statiques affichées, tous modules confondus (échantillons de code et
# blocs `if (LANG === 'en')` retirés de la population).
MIN_POPULATION = 1000
# Une clé dont on SAIT qu'elle est affichée par `web/index.html` (bouton d'exécution de la barre).
CLE_TEMOIN = "Exécuter"
# Plancher de clés du lexique : relevé le 2026-08-22, 223 clés avant complément, 1 594 après.
MIN_CLES = 150

# PLAFOND DE TROUS PAR MODULE (chaînes affichées statiques sans entrée au lexique). Relevé le 2026-08-22 par
# `--mesure` : chaque module suivi est à ZÉRO après complément du lexique (1 579 chaînes affichées, toutes
# couvertes ; 1 594 clés). Le cliquet est donc au plancher : toute chaîne affichée neuve entre au lexique ou
# rougit. Un module absent d'ici est rendu, pas jugé ; l'y inscrire est le geste attendu quand on le crée.
# Relever un plafond exige une raison écrite à côté.
# Historique du cliquet : 2026-08-22, index.html 513 -> 496 (`P11.2-c`, `P11.7-a`), puis 496 -> 0 ; app.js 143 -> 0 ;
# connectors.js 49 -> 0 ; detadv.js 37 -> 0 ; detection_admin.js 35 -> 0 ; freshness.js 31 -> 0 ; retention.js 30 -> 0 ;
# admin_users.js 29 -> 0 ; sigmaimport.js 27 -> 0 ; sources.js 26 -> 0 ; idp.js 23 -> 0 ; suppressions.js inscrit à 0
# (41 trous avant, module jusque-là rendu sans être jugé) ; les quinze modules sous 20 trous à 0 (`P11.8-a`) ;
# help.js inscrit à 0 le 2026-08-22 (`P11.8-b`) : 32 trous sous l'exemption de module, dont 20 libellés d'interface
# en ternaire `en ? … : …` que la garde ne lisait pas et 12 fragments de deux corps d'aide déplacés au registre.
# i18n_observer.js inscrit à 0 à sa création (amorçage du lexique extrait d'app.js, déplacement pur : 0 trou mesuré).
# dataaccess.js inscrit à 0 à sa création (panneau d'accès données extrait d'app.js, déplacement pur : 0 trou mesuré).
# lookups.js inscrit à 0 à sa création (lookups extraits d'app.js, déplacement pur : 0 trou mesuré).
# dashboards.js inscrit à 0 à sa création (dashboards extraits d'app.js, déplacement pur : 0 trou mesuré).
# login.js inscrit à 0 à sa création (écran de connexion extrait d'app.js, déplacement pur : 0 trou mesuré).
# navigation.js inscrit à 0 à sa création (navigation à 2 niveaux extraite d'app.js, déplacement pur : 0 trou mesuré).
# recherche_de_liste.js inscrit à 0 à sa création (`P11.12-a`) : le champ de recherche partagé ne porte AUCUN
# mot de domaine — les deux phrases d'un résumé de recherche lui arrivent en nœuds de texte, écrits par le
# panneau appelant et jugés dans SON module (0 chaîne affichée mesurée ici).
PLAFOND_DE_TROUS = {
    "admin_users.js": 0, "ai.js": 0, "alerting.js": 0, "alerts.js": 0, "app.js": 0, "attack.js": 0,
    "audit.js": 0, "cases.js": 0, "connectors.js": 0, "core.js": 0, "dataaccess.js": 0, "dashboards.js": 0, "datamodels.js": 0, "destinations.js": 0,
    "detadv.js": 0, "detection_admin.js": 0, "fieldfilters.js": 0, "fleet.js": 0, "freshness.js": 0,
    "help.js": 0, "i18n_observer.js": 0, "idp.js": 0, "index.html": 0, "index_policies.js": 0, "keys.js": 0, "knowledge.js": 0, "login.js": 0, "lookups.js": 0,
    "multitenant.js": 0, "navigation.js": 0, "prefs.js": 0, "processors.js": 0, "producer_ui.js": 0, "retention.js": 0,
    "recherche_de_liste.js": 0, "risk.js": 0, "runbooks.js": 0, "savedqueries.js": 0, "sigmaimport.js": 0, "soql_complete.js": 0,
    "sources.js": 0, "state.js": 0, "suppressions.js": 0, "system.js": 0, "threatintel.js": 0, "viz.js": 0,
}

# LA SEULE SURFACE EXEMPTE : la définition `const HELP = { … }` du registre des sections d'aide, DÉRIVÉE
# (module et portée) de `check_every_help_trigger_has_a_section.py` — pas un nom de fichier, pas un module
# entier. Le module qui la porte est jugé au plafond zéro sur tout ce qui l'entoure. La raison est écrite :
# une exemption sans raison est une trappe.
RAISON_DU_REGISTRE = "registre {fr:{title,body}, en:{title,body}} choisi par LANG : bilingue par construction ; exempt sur la portée de sa définition seulement"


def registre_d_aide() -> tuple[str, str] | None:
    """(nom du module de `web/` qui définit `const HELP = {`, son texte sans commentaires) ; None si aucun ou plusieurs."""
    corpus = {}
    for f in sorted(os.listdir(WEB)):
        if f.endswith(".js") and f != "sw.js":
            with open(os.path.join(WEB, f), encoding="utf-8") as fh:
                corpus[f] = sans_commentaires_js(fh.read())
    nom = module_du_registre(corpus)
    return (nom, corpus[nom]) if nom else None


def hors_registre(texte_sans_commentaires: str) -> str:
    """Le texte du module du registre SANS la portée de `const HELP = { … }` (remplacée par des blancs, lignes
    conservées) : ce qui reste est jugé comme n'importe quel module."""
    portee = portee_du_registre(texte_sans_commentaires)
    if portee is None:
        return texte_sans_commentaires
    d, f = portee
    return texte_sans_commentaires[:d] + re.sub(r"[^\n]", " ", texte_sans_commentaires[d:f]) + texte_sans_commentaires[f:]
# Une chaîne choisie par `LANG === 'en' ? … : …` est bilingue PAR CONSTRUCTION, dans n'importe quel
# module : elle compte comme couverte sans passer par le lexique.
RE_CHOIX_PAR_LANG = re.compile(r"\bLANG\b[^;]*\?")
# De même une valeur sous une clé `fr:` ou `en:` d'un objet : sa jumelle dans l'autre langue est à côté.
RE_CLE_FR_EN = re.compile(r"[{,]\s*(fr|en)\s*:\s*$")

SINKS_AFFECTATION = ("textContent", "innerText", "title", "placeholder", "ariaLabel")
SINKS_CLE = ("label", "title", "placeholder", "okText", "hint", "text")
SINKS_APPEL = ("createTextNode", "muted", "toast", "showErr", "confirmModal", "append", "prepend", "emptyRow")
ATTRS_HTML = ("title", "placeholder", "aria-label", "label")
# Le texte d'un échantillon de code (`<code>`, `<kbd>`, `<pre>`, `<samp>`) est montré tel quel dans les deux
# langues : hors population, comme le contenu d'un `<script>`.
TAGS_HORS_POPULATION = ("script", "style", "code", "kbd", "pre", "samp")

# Un identifiant technique : minuscules ASCII, chiffres, ponctuation de chemin. Identique en FR et EN.
RE_IDENTIFIANT = re.compile(r"^[a-z0-9_.:/\-+*%#@&=?|,;<>()\[\]{}!~^$\\' ]*$")
RE_LETTRE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ]")
SENTINELLE = "\x00"


# ---------------------------------------------------------------------------------------------
# Tokenisation JavaScript : on ne garde que les littéraux de chaîne, avec le code qui les précède.
# ---------------------------------------------------------------------------------------------
RE_AVANT_REGEX = re.compile(r"(?:^|[\(\[,=:!&|?{};+\-*%<>~^]|\breturn|\btypeof|\bcase)\s*$")


def _lire_gabarit(src: str, i: int) -> tuple[str, int]:
    """Lit un gabarit `` `...` `` à partir du backtick ouvrant ; rend (texte avec SENTINELLE pour
    chaque `${…}`, index après le backtick fermant)."""
    assert src[i] == "`"
    i += 1
    out = []
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            out.append(src[i : i + 2])
            i += 2
            continue
        if c == "`":
            return "".join(out), i + 1
        if c == "$" and i + 1 < n and src[i + 1] == "{":
            # saute l'expression interpolée (accolades équilibrées, chaînes et gabarits imbriqués compris)
            depth = 1
            i += 2
            while i < n and depth:
                ch = src[i]
                if ch in "'\"":
                    _, i = _lire_chaine(src, i)
                    continue
                if ch == "`":
                    _, i = _lire_gabarit(src, i)
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            out.append(SENTINELLE)
            continue
        out.append(c)
        i += 1
    return "".join(out), i


def _lire_chaine(src: str, i: int) -> tuple[str, int]:
    q = src[i]
    i += 1
    out = []
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            nxt = src[i + 1] if i + 1 < n else ""
            # `\uXXXX` / `\xXX` : une clé qui porte une espace insécable s'écrit ainsi pour rester lisible
            if nxt in ("u", "x"):
                largeur = 4 if nxt == "u" else 2
                hexa = src[i + 2 : i + 2 + largeur]
                if len(hexa) == largeur and all(ch in "0123456789abcdefABCDEF" for ch in hexa):
                    out.append(chr(int(hexa, 16)))
                    i += 2 + largeur
                    continue
            out.append({"n": "\n", "t": "\t", "'": "'", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        if c == q:
            return "".join(out), i + 1
        if c == "\n":
            return "".join(out), i
        out.append(c)
        i += 1
    return "".join(out), i


def chaines_js(src: str) -> list[tuple[str, str, str]]:
    """Rend [(texte, code_avant, code_apres)] pour chaque littéral de chaîne/gabarit du source.
    `code_avant` = le code (sans commentaires ni chaînes) depuis le dernier `;` ou retour à la ligne
    significatif ; `code_apres` = les quelques caractères de code qui suivent."""
    n = len(src)
    i = 0
    code: list[str] = []  # code accumulé sans commentaires ni littéraux (les littéraux deviennent `""`)
    trouves: list[tuple[str, int]] = []  # (texte, position dans `code`)
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "'\"":
            s, i = _lire_chaine(src, i)
            trouves.append((s, len(code)))
            code.append('""')
            continue
        if c == "`":
            s, i = _lire_gabarit(src, i)
            trouves.append((s, len(code)))
            code.append('""')
            continue
        if c == "/":
            avant = "".join(code[-40:])
            if RE_AVANT_REGEX.search(avant):
                # littéral regex : on saute jusqu'au `/` fermant non échappé hors classe
                j = i + 1
                in_cls = False
                while j < n and src[j] != "\n":
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_cls = True
                    elif src[j] == "]":
                        in_cls = False
                    elif src[j] == "/" and not in_cls:
                        break
                    j += 1
                i = j + 1
                while i < n and src[i].isalpha():
                    i += 1
                code.append("/re/")
                continue
        code.append(c)
        i += 1
    texte_code = "".join(code)
    # positions -> contexte. On recalcule les offsets : chaque entrée de `code` est de longueur variable.
    offsets = []
    pos = 0
    for seg in code:
        offsets.append(pos)
        pos += len(seg)
    out = []
    for s, idx in trouves:
        p = offsets[idx]
        avant = texte_code[max(0, p - 400) : p]
        # contexte = depuis le dernier `;` (les retours à la ligne ne coupent pas : appels multi-lignes)
        k = avant.rfind(";")
        if k >= 0:
            avant = avant[k + 1 :]
        apres = texte_code[p + 2 : p + 12]
        out.append((s, avant, apres, _dans_bloc_lang_en(texte_code, p)))
    return out


# Un bloc `if (LANG === 'en') { … }` (le littéral 'en' est déjà remplacé par `""` dans le code réduit).
RE_BLOC_LANG_EN = re.compile(r"\bif\s*\(\s*LANG\s*===\s*\"\"\s*\)\s*\{")


def _dans_bloc_lang_en(texte_code: str, p: int) -> bool:
    """Vrai si la position `p` est à l'intérieur du dernier bloc `if (LANG === 'en') {` ouvert avant elle :
    les accolades ouvertes entre l'ouverture du bloc et `p` (littéraux et regex déjà réduits) n'ont pas
    toutes été refermées."""
    ouvert = None
    for m in RE_BLOC_LANG_EN.finditer(texte_code, 0, p):
        ouvert = m.end()
    if ouvert is None:
        return False
    corps = texte_code[ouvert:p]
    return corps.count("{") - corps.count("}") >= 0


RE_SINK_AFFECT = re.compile(r"\.(%s)\s*=\s*$" % "|".join(SINKS_AFFECTATION))
RE_SINK_CLE = re.compile(r"[{,]\s*(%s)\s*:\s*$" % "|".join(SINKS_CLE))
RE_SINK_APPEL = re.compile(r"\b(%s)\(\s*$" % "|".join(SINKS_APPEL))
RE_SINK_SETATTR = re.compile(r"setAttribute\(\s*\"\"\s*,\s*$")
RE_TERNAIRE = re.compile(r"[?:]\s*$")
RE_SINK_AFFECT_DANS = re.compile(r"\.(%s)\s*=[^=]" % "|".join(SINKS_AFFECTATION))
RE_SINK_CLE_DANS = re.compile(r"[{,]\s*(%s)\s*:" % "|".join(SINKS_CLE))
RE_SINK_APPEL_DANS = re.compile(r"\b(%s)\(" % "|".join(SINKS_APPEL))
RE_CLE_AUTRE = re.compile(r"[{,]\s*([A-Za-z_]\w*)\s*:\s*$")
RE_HTML = re.compile(r"<[a-zA-Z][^<>]*>|</[a-zA-Z]+>")


def _est_puits(avant: str) -> bool:
    a = avant.rstrip()
    if RE_SINK_AFFECT.search(a) or RE_SINK_CLE.search(a) or RE_SINK_APPEL.search(a):
        return True
    if RE_SINK_SETATTR.search(a):
        return True
    # ternaire `x.title = cond ? 'A' : 'B'` : le puits est AVANT le `?`, séparé de la chaîne par la
    # condition ; on le cherche dans ce qui précède le `?` (le contexte s'arrête déjà au dernier `;`).
    if RE_TERNAIRE.search(a):
        # une clé d'objet ordinaire (`value: 'x'`) se termine aussi par `:` -> ce n'est pas un puits
        if RE_CLE_AUTRE.search(a):
            return False
        q = a.rfind("?")
        if q > 0:
            tete = a[:q]
            return bool(RE_SINK_AFFECT_DANS.search(tete) or RE_SINK_CLE_DANS.search(tete) or RE_SINK_APPEL_DANS.search(tete))
    return False


def _dynamique(s: str, avant: str, apres: str) -> bool:
    if SENTINELLE in s:
        return True
    a = avant.rstrip()
    if a.endswith("+"):
        return True
    if apres.lstrip().startswith("+"):
        return True
    return False


RE_CODE_MAJUSCULE = re.compile(r"^[A-Z0-9_.:/\-]+$")


def _candidat(s: str) -> bool:
    t = s.strip()
    if len(t) < 2 or not RE_LETTRE.search(t):
        return False
    if RE_IDENTIFIANT.match(t):
        return False
    # Un code en majuscules sans espace (`T1110`, `CSV`, `OK`) est identique dans les deux langues :
    # hors population s'il porte un chiffre ou tient en quatre signes. `RETARD` (six lettres) reste.
    if RE_CODE_MAJUSCULE.match(t) and (any(ch.isdigit() for ch in t) or len(t) <= 4):
        return False
    return True


def _textes_html(fragment: str) -> tuple[list[str], list[str]]:
    """Texte entre balises + attributs affichés d'un fragment HTML ; rend (statiques, dynamiques)."""
    stat, dyn = [], []

    class P(html.parser.HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.skip = 0

        def handle_starttag(self, tag, attrs):
            if tag in TAGS_HORS_POPULATION:
                self.skip += 1
            for k, v in attrs:
                if k in ATTRS_HTML and v:
                    (dyn if SENTINELLE in v else stat).append(v)

        def handle_endtag(self, tag):
            if tag in TAGS_HORS_POPULATION and self.skip:
                self.skip -= 1

        def handle_data(self, data):
            if self.skip:
                return
            (dyn if SENTINELLE in data else stat).append(data)

    p = P()
    try:
        p.feed(fragment)
    except Exception:
        pass
    return stat, dyn


def extraire_module(src: str) -> tuple[list[str], list[str]]:
    """(statiques affichées, dynamiques affichées, bilingues par construction) d'un module JS."""
    statiques, dynamiques, par_construction = [], [], []
    for s, avant, apres, bloc_en in chaines_js(src):
        if RE_CLE_FR_EN.search(avant.rstrip()):
            # valeur d'une paire `{ fr: '…', en: '…' }` : bilingue par construction, HTML ou non
            if _candidat(s.replace(SENTINELLE, "")):
                par_construction.append(s)
            continue
        if RE_HTML.search(s):
            st, dy = _textes_html(s)
            if bloc_en:
                # version EN dédiée d'un bloc riche (`if (LANG === 'en') { el.innerHTML = '…' }`) : bilingue par
                # construction, son pendant FR est dans index.html
                par_construction += [x for x in st if _candidat(x)]
                continue
            statiques += [x for x in st if _candidat(x)]
            dynamiques += [x for x in dy if _candidat(x.replace(SENTINELLE, ""))]
            continue
        if not _est_puits(avant):
            continue
        if not _candidat(s.replace(SENTINELLE, "")):
            continue
        if _dynamique(s, avant, apres):
            dynamiques.append(s)
        elif bloc_en or RE_CHOIX_PAR_LANG.search(avant):
            par_construction.append(s)
        else:
            statiques.append(s)
    return statiques, dynamiques, par_construction


def extraire_index_html(src: str) -> list[str]:
    st, _ = _textes_html(src)
    return [x for x in st if _candidat(x)]


def cles_du_lexique(src: str) -> set[str]:
    m = re.search(r"const I18N_EN\s*=\s*\{(.*?)\n\};", src, re.S)
    if not m:
        return set()
    corps = m.group(1)
    cles = set()
    for s, avant, _, _ in chaines_js(corps):
        # une CLÉ est un littéral suivi de `:` ; la tokenisation remplace les littéraux par `""`,
        # donc on regarde le code qui PRÉCÈDE : une clé est précédée de `{`, `,` ou d'un début de ligne.
        a = avant.rstrip()
        if a == "" or a.endswith(",") or a.endswith("{"):
            cles.add(s.strip())
    return cles


# ---------------------------------------------------------------------------------------------
# Témoins de l'instrument : ce qu'il DOIT voir, ce qu'il NE DOIT PAS compter.
# ---------------------------------------------------------------------------------------------
CORPUS_TEMOIN = r"""
// commentaire : 'Pas affiché'
const a = document.createElement('div'); a.className = 'pas-une-chaine affichée';
a.textContent = 'Affiché un';
b.title = "Affiché deux";
c.placeholder = 'Affiché trois';
d.innerText = cond ? 'Affiché quatre' : 'Affiché cinq';
const f = [{ name: 'x', label: 'Affiché six', value: 'valeur_technique' }];
host.appendChild(muted('Affiché sept'));
toast('Affiché huit', 'ok');
el.setAttribute('aria-label', 'Affiché neuf');
el.innerHTML = `<span class="k">Affiché dix</span><b title="Affiché onze">${x}</b>`;
el.innerHTML = '<div class="muted">Affiché douze</div>';
e.textContent = 'Dynamique un : ' + n;
g.textContent = `Dynamique deux ${n}`;
const re = /tronqué|'pas une chaîne'/i; h.textContent = 'Affiché treize';
i.textContent = 'src_ip';
j.textContent = 'T1110';
k.textContent = '…';
l.textContent = LANG === 'en' ? 'Bilingual' : 'Bilingue';
if (LANG === 'en') { m.textContent = 'English only'; if (x) { n.innerHTML = '<b>English rich</b>'; } }
o.textContent = 'Affiché quatorze';
el.innerHTML = '<p>Affiché quinze <code>pas_un_libellé(x)</code> <kbd>Ctrl</kbd></p><optgroup label="Affiché seize"></optgroup>';
const paires = [{ t: 'x', fr: 'Paire française <nom>', en: 'English pair <name>' }];
"""
# Un module qui porte le registre : sa définition est la seule surface exempte, ce qui l'entoure est jugé.
CORPUS_TEMOIN_REGISTRE = """export const HELP = {
  alpha: { fr: { title: 'Titre du registre <b>riche</b>', body: `Corps {fr}` }, en: { title: 'Registry title', body: `Body {en}` } },
};
x.textContent = 'Hors registre';
"""
ATTENDUS_STATIQUES = {"Affiché un", "Affiché deux", "Affiché trois", "Affiché quatre", "Affiché cinq",
                      "Affiché six", "Affiché sept", "Affiché huit", "Affiché neuf", "Affiché dix",
                      "Affiché onze", "Affiché douze", "Affiché treize", "Affiché quatorze", "Affiché quinze",
                      "Affiché seize"}
ATTENDUS_DYNAMIQUES = 2
INTERDITS = {"Pas affiché", "pas-une-chaine affichée", "valeur_technique", "pas une chaîne", "src_ip", "T1110", "…", "x",
             "English only", "English rich", "pas_un_libellé(x)", "Ctrl", "Paire française", "English pair"}


def valider_instrument() -> list[str]:
    errs = []
    st, dy, pc = extraire_module(CORPUS_TEMOIN)
    sst = {s.strip() for s in st}
    if {x.strip() for x in pc} != {"Bilingual", "Bilingue", "English only", "English rich", "Paire française <nom>", "English pair <name>"}:
        errs.append(f"témoin : le choix par LANG (ternaire ou bloc `if (LANG === 'en')`) ou la paire `{{fr, en}}` n'est pas "
                    f"reconnu comme bilingue par construction : {pc}")
    # La surface exempte est la définition du registre, pas le module : hors d'elle, une chaîne est jugée ;
    # et c'est bien l'exemption qui retire le titre du registre, pas une cécité de l'extracteur.
    vus_nus = {x.strip() for x in extraire_module(CORPUS_TEMOIN_REGISTRE)[0]}
    vus_hors = {x.strip() for x in extraire_module(hors_registre(CORPUS_TEMOIN_REGISTRE))[0]}
    if "Registry title" not in vus_nus:
        errs.append(f"témoin : le titre d'une section du registre n'est pas vu par l'extracteur à nu ({sorted(vus_nus)}) — "
                    f"l'exemption de surface ne prouverait rien")
    if vus_hors != {"Hors registre"}:
        errs.append(f"témoin : hors de la portée du registre, la garde doit voir « Hors registre » et rien du registre : {sorted(vus_hors)}")
    manquants = ATTENDUS_STATIQUES - sst
    if manquants:
        errs.append(f"témoin : chaînes affichées NON reconnues : {sorted(manquants)}")
    trop = sst & INTERDITS
    if trop:
        errs.append(f"témoin : chaînes comptées alors qu'elles ne sont pas affichées : {sorted(trop)}")
    if len(dy) != ATTENDUS_DYNAMIQUES:
        errs.append(f"témoin : {len(dy)} chaîne(s) dynamique(s) vue(s) au lieu de {ATTENDUS_DYNAMIQUES}")
    lex = cles_du_lexique('const I18N_EN = {\n  "Clé un": "Key one", "Clé deux": "Key two",\n  // c\n  "Clé trois": "Key three",\n  "Clé\\u00a0quatre": "Key four",\n};')
    if lex != {"Clé un", "Clé deux", "Clé trois", "Clé\xa0quatre"}:
        errs.append(f"témoin : lecture du lexique fausse : {sorted(lex)}")
    return errs


# ---------------------------------------------------------------------------------------------
# Mesure sur l'arbre réel.
# ---------------------------------------------------------------------------------------------
def mesurer(registre: tuple[str, str] | None) -> tuple[dict[str, dict], set[str]]:
    """`registre` = (module, texte sans commentaires) : ce module est jugé HORS de la portée de `const HELP`."""
    with open(LEXIQUE, encoding="utf-8") as fh:
        cles = cles_du_lexique(fh.read())
    resultats: dict[str, dict] = {}
    for f in sorted(os.listdir(WEB)):
        chemin = os.path.join(WEB, f)
        if f == "sw.js" or not (f.endswith(".js") or f == "index.html"):
            continue
        with open(chemin, encoding="utf-8") as fh:
            src = fh.read()
        if f == "index.html":
            st, dy, pc = extraire_index_html(src), [], []
        elif f == "i18n.js":
            continue  # le lexique n'affiche rien
        elif registre and f == registre[0]:
            st, dy, pc = extraire_module(hors_registre(registre[1]))  # la surface du registre est exempte, le reste jugé
        else:
            st, dy, pc = extraire_module(src)
        uniques = sorted({s.strip() for s in st})
        bilingues = {s.strip() for s in pc}
        couvertes = [s for s in uniques if s in cles] + sorted(bilingues)
        trous = [s for s in uniques if s not in cles]
        total = len(uniques) + len(bilingues)
        resultats[f] = {
            "population": total,
            "couvertes": len(couvertes),
            "couvertes_liste": couvertes,
            "trous": trous,
            "dynamiques": len({s for s in dy}),
            "taux": (100.0 * len(couvertes) / total) if total else 100.0,
        }
    return resultats, cles


def main(argv: list[str]) -> int:
    mesure = "--mesure" in argv
    trous_de = None
    if "--trous" in argv:
        trous_de = argv[argv.index("--trous") + 1]

    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nL'instrument ne reconnaît pas son propre corpus : la garde refuse de conclure.")
        return 2

    registre = registre_d_aide()
    if registre is None:
        print("::error::le module du registre d'aide (`const HELP = {` sous web/) n'est pas dérivable — aucun ou plusieurs porteurs : "
              "la garde refuse de conclure (il serait rendu sans être jugé, ou jugé sans sa raison d'exemption).")
        return 2
    # Le module du registre est jugé au plafond zéro hors de la portée exempte (entrée dérivée, pas nommée).
    plafonds = {**PLAFOND_DE_TROUS, registre[0]: 0}
    resultats, cles = mesurer(registre)
    population = sum(r["population"] for r in resultats.values())
    if len(cles) < MIN_CLES:
        print(f"::error::{len(cles)} clés lues dans le lexique, plancher {MIN_CLES} : la lecture de `web/i18n.js` est cassée.")
        return 2
    if population < MIN_POPULATION:
        print(f"::error::{population} chaînes affichées découvertes, plancher {MIN_POPULATION} : l'extraction ne reconnaît plus l'arbre.")
        return 2
    index = resultats.get("index.html")
    if not index or CLE_TEMOIN not in cles or CLE_TEMOIN not in index["couvertes_liste"]:
        print(f"::error::la clé témoin « {CLE_TEMOIN} » n'est pas vue à la fois au lexique et dans `web/index.html` : "
              f"la garde refuse de conclure.")
        return 2

    if trous_de:
        r = resultats.get(trous_de)
        if not r:
            print(f"module inconnu : {trous_de}")
            return 2
        for s in r["trous"]:
            print(s)
        return 0

    largeur = max(len(m) for m in resultats)
    print(f"{'module':<{largeur}}  population  couvertes  trous  dynamiques  taux")
    for m, r in resultats.items():
        print(f"{m:<{largeur}}  {r['population']:>10}  {r['couvertes']:>9}  {len(r['trous']):>5}  {r['dynamiques']:>10}  {r['taux']:>5.1f} %")
    couvertes = sum(r["couvertes"] for r in resultats.values())
    print(f"\n{population} chaînes statiques affichées, {couvertes} couvertes ({100.0 * couvertes / population:.1f} %), "
          f"{len(cles)} clés au lexique. Surface exempte : la définition `const HELP` de {registre[0]} — {RAISON_DU_REGISTRE}.")
    if mesure:
        return 0

    regressions = []
    for m, plafond in sorted(plafonds.items()):
        r = resultats.get(m)
        if r is None:
            regressions.append(f"{m} : plafond écrit mais module absent — retirez l'entrée ou restaurez le module.")
            continue
        if len(r["trous"]) > plafond:
            ex = ", ".join(f"« {s} »" for s in r["trous"][:8])
            regressions.append(
                f"{m} : {len(r['trous'])} chaîne(s) affichée(s) sans entrée au lexique, plafond {plafond} "
                f"(couverture {r['taux']:.1f} %) — p. ex. {ex}. Inscrivez chaque chaîne affichée dans "
                f"`web/i18n.js` (clé FR -> valeur EN) ; une chaîne dynamique se compose à partir de clés traduites."
            )
    if regressions:
        for e in regressions:
            print(f"::error::{e}")
        print(f"\n{len(regressions)} module(s) au-dessus de leur plafond de trous du lexique.")
        return 1
    print(f"Aucun module au-dessus de son plafond de trous ({len(plafonds)} plafonds tenus).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
