#!/usr/bin/env python3
"""Le nom qu'un document donne à un onglet est celui que la console SERT (`P11.21-c`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Depuis `P11.18-o` (2026-08-25) un libellé d'onglet n'est plus ÉCRIT : il est DÉRIVÉ — du titre du
panneau que l'onglet ouvre, ou du lien de barre latérale quand l'espace n'a qu'un onglet. La console
a donc cessé d'avoir un endroit où un libellé se recopie. La DOCUMENTATION, elle, en avait un : une
colonne de tableau, tenue à la main. Elle a cessé d'être maintenue le jour même, sans que rien ne le
dise, parce qu'aucun instrument ne liait les deux.

MESURÉ SUR L'ARBRE SUIVI LE 2026-08-30, avant le lot qui accompagne cette garde : sur les 37 onglets
que la console déclare, 37 avaient une ligne documentée et **24** y portaient un nom que la console
ne sert plus. Deux autres avaient été corrigées à la main la veille (2026-08-29) — c'est-à-dire que
le remède à la main avait déjà été tenté, et qu'il laissait 24 lignes derrière lui.

CE QU'ELLE FAIT, ET DANS QUEL ORDRE
------------------------------------
Elle REJOUE la dérivation du module de navigation sur le document servi, puis compare le nom obtenu
au nom écrit dans le corpus. Le sens de la comparaison compte : la page est la SOURCE, le document
est le COPISTE. Un écart accuse le document, jamais la page.

LES TROIS SOURCES SONT DÉRIVÉES PAR LEUR PROPRIÉTÉ, JAMAIS NOMMÉES
-------------------------------------------------------------------
  (A) LE MODÈLE DE NAVIGATION : l'unique fichier suivi de `web/` qui porte la définition
      `const SPACES = [`. Même ancrage que `check_operator_surface_is_documented.py`, et pour la
      même raison mesurée : ce dépôt a déjà payé une garde aveugle parce qu'elle nommait un fichier
      qu'on a déplacé. Zéro ou plusieurs porteurs -> REFUS DE CONCLURE.
  (B) LE DOCUMENT SERVI : l'unique fichier suivi de `web/` en `.html` qui porte la barre latérale
      des espaces (des liens `data-space=`). Zéro ou plusieurs -> REFUS DE CONCLURE.
  (C) LE CORPUS DOCUMENTAIRE : tout tableau Markdown d'un document suivi dont CHAQUE ligne de
      données a pour première cellule un jeton entre accents graves qui est un identifiant d'onglet
      DÉCLARÉ PAR LE MODÈLE. La population des lignes vient donc du modèle, pas d'un nom de colonne.

CE QUE LA DÉRIVATION REJOUE, ET POURQUOI ELLE SE LIT SUR LE DOCUMENT STATIQUE
-----------------------------------------------------------------------------
Le module pose les libellés À SON ÉVALUATION, donc avant qu'aucune charge n'ait peint quoi que ce
soit : le document statique EST le corpus que la dérivation voit. L'ordre rejoué est celui du
module, dans cet ordre exact :
  1. l'onglet n'ouvre qu'UN panneau et ce panneau porte un titre -> ce titre ;
  2. sinon, l'espace n'a qu'UN onglet -> le libellé de son lien de barre latérale ;
  3. sinon, l'onglet est un GROUPE et déclare son libellé -> ce libellé ;
  4. sinon -> un AVEU, que ce document ne sait pas recopier (voir les refus).
Le titre d'un panneau est fait de ses nœuds de TEXTE DIRECTS, gestes exclus : le « ? » de l'aide et
les boutons d'outil vivent DANS le titre sans en faire partie. Les lire ferait entrer un point
d'interrogation dans le nom — c'est exactement le piège qu'un dépouillement naïf des balises tend.

LES SEPT REFUS, ET POURQUOI UN REFUS VAUT MIEUX QU'UNE DEVINETTE
-----------------------------------------------------------------
Réécrire une ligne avec un instrument validé À MOITIÉ remplace une documentation PÉRIMÉE par une
documentation FAUSSE, ce qui est pire : la première se soupçonne, la seconde se croit. La garde
REFUSE DE CONCLURE (code 2) et NOMME le cas plutôt que de trancher, quand :
  (1) le porteur du modèle ou le document servi est absent ou dédoublé ;
  (2) le modèle se lit en corpus DÉGÉNÉRÉ — moins de deux espaces ou moins de deux onglets. C'est
      la panne EXACTE que `P11.18-o` a mesurée sur une autre garde : en ôtant les libellés écrits,
      l'inventaire est tombé de 37 onglets à 2, et seul un refus l'a empêchée de verdir ;
  (3) un `label:` est un identifiant que le module ne déclare pas comme constante de chaîne ;
  (4) une section déclarée par le modèle n'existe pas dans le document servi ;
  (5) la dérivation retombe sur le lien de barre latérale d'un espace qui n'en a pas ;
  (6) le nom dérivé serait l'AVEU : la console y admet ne pas savoir nommer la destination, et une
      documentation qui recopierait cet aveu comme un libellé mentirait sur ce qu'on voit ;
  (7) un titre de panneau porte un COMMENTAIRE en enfant direct : le code le PLIERAIT dans le nom
      (un nœud commentaire n'a pas de balise et rend son texte), un lecteur humain ne le verrait
      pas. Les deux lectures divergeraient sans qu'aucune soit fautive.

CE QU'ELLE NE TIENT PAS, ÉCRIT PLUTÔT QUE TU
---------------------------------------------
  * Elle ne juge que la DEUXIÈME cellule d'une ligne qualifiée, et cette position est une
    convention de forme qu'elle DÉCLARE — elle imprime l'en-tête qu'elle a lu, pour qu'un lecteur
    voie quelle colonne a été jugée. Une colonne de libellé déplacée ailleurs lui échapperait.
  * Elle ne voit AUCUN nom cité en PROSE. `docs/NATIVE-IDP.md` en portait un, périmé, corrigé à la
    main dans le même lot : cette famille-là reste hors de portée, et c'est dit ici pour qu'on ne
    lise pas le vert de cette garde comme une couverture du corpus entier.
  * Elle ne dit pas qu'un onglet EST documenté — c'est l'objet de
    `check_operator_surface_is_documented.py`, et deux gardes qui mesureraient la même chose
    finiraient par diverger.
  * Elle lit le FRANÇAIS servi par le document statique. Un nom traduit passe par le lexique, dont
    la couverture est jugée ailleurs.
"""
import html.parser
import os
import re
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))

VIDES = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
         "source", "track", "wbr"}


# --------------------------------------------------------------------------------------------
# LE DOCUMENT — un arbre, pas un dépouillement de balises. La différence n'est pas de confort :
# le nom d'un panneau est fait de ses nœuds de texte DIRECTS, ce qu'aucune expression régulière
# sur le source ne sait distinguer d'un texte porté par un bouton enfant.
# --------------------------------------------------------------------------------------------
class Arbre(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.racine = {"tag": "#racine", "attrs": {}, "enfants": []}
        self.pile = [self.racine]

    def handle_starttag(self, tag, attrs):
        n = {"tag": tag, "attrs": dict(attrs), "enfants": []}
        self.pile[-1]["enfants"].append(n)
        if tag not in VIDES:
            self.pile.append(n)

    def handle_startendtag(self, tag, attrs):
        self.pile[-1]["enfants"].append({"tag": tag, "attrs": dict(attrs), "enfants": []})

    def handle_endtag(self, tag):
        for i in range(len(self.pile) - 1, 0, -1):
            if self.pile[i]["tag"] == tag:
                del self.pile[i:]
                return

    def handle_data(self, d):
        self.pile[-1]["enfants"].append({"tag": None, "texte": d})

    def handle_comment(self, d):
        self.pile[-1]["enfants"].append({"tag": None, "commentaire": True, "texte": d})


def _descendants(n):
    for e in n["enfants"]:
        if e["tag"] is not None:
            yield e
            yield from _descendants(e)


def par_id(racine, ident):
    """Le PREMIER élément qui porte cet identifiant, dans l'ordre du document."""
    for e in _descendants(racine):
        if e["attrs"].get("id") == ident:
            return e
    return None


def premier(n, tag, predicat=None):
    for e in _descendants(n):
        if e["tag"] == tag and (predicat is None or predicat(e)):
            return e
    return None


def blanc(t):
    return re.sub(r"\s+", " ", t).strip()


def texte_entier(n):
    """`textContent` : tout le texte des descendants."""
    if n["tag"] is None:
        return n.get("texte", "")
    return "".join(texte_entier(e) for e in n["enfants"])


# --------------------------------------------------------------------------------------------
# LA DÉRIVATION — l'ordre du module, rejoué.
# --------------------------------------------------------------------------------------------
def nom_ecrit_sur_le_panneau(doc, id_section):
    """Le titre d'un panneau : ses nœuds de texte DIRECTS, gestes exclus.

    Rend (nom, commentaire_direct). Le second dit qu'un commentaire est enfant direct du titre :
    le code le plierait dans le nom, un lecteur ne le verrait pas — d'où un refus, pas un choix.
    """
    sec = par_id(doc, id_section)
    if sec is None:
        return (None, False)
    h = premier(sec, "h2")
    if h is None:
        return ("", False)
    directs = [e for e in h["enfants"] if e["tag"] is None]
    return (blanc("".join(e.get("texte", "") for e in directs)),
            any(e.get("commentaire") for e in directs))


def nom_ecrit_sur_la_barre_laterale(doc, id_espace):
    nav = par_id(doc, "nav")
    if nav is None:
        return None
    a = premier(nav, "a", lambda e: e["attrs"].get("data-space") == id_espace)
    if a is None:
        return None
    s = premier(a, "span")
    return blanc(texte_entier(s)) if s is not None else None


# --------------------------------------------------------------------------------------------
# LE MODÈLE — lu par sa forme, sans exécuter le module.
# --------------------------------------------------------------------------------------------
RE_ESPACE = re.compile(r"\{\s*id:\s*'([A-Za-z0-9_-]+)'\s*,(?:\s*admin:\s*true\s*,)?\s*tabs:\s*\[")
RE_ONGLET = re.compile(
    r"\{\s*id:\s*'([A-Za-z0-9_-]+)'\s*,\s*label:\s*("
    r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[A-Za-z_$][A-Za-z0-9_$]*"
    r")\s*,\s*sections:\s*\[([^\]]*)\]")
RE_CONST = re.compile(r"\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s*;")
RE_CHAINE = re.compile(r"'([^']*)'")


def lire_le_modele(source):
    """(espaces, onglets, constantes) — chaque onglet est rattaché au DERNIER espace ouvert avant lui.

    Le rattachement est POSITIONNEL parce que la seule chose que le texte garantit est l'ordre :
    un onglet écrit après l'ouverture d'un espace appartient à cet espace. Rien n'est énuméré.
    """
    i = source.find("const SPACES = [")
    if i < 0:
        return None, None, None
    j = source.find("\n];", i)
    bloc = source[i:j if j > 0 else len(source)]
    constantes = {m.group(1): m.group(2)[1:-1] for m in RE_CONST.finditer(source)}
    espaces = [(m.start(), m.group(1)) for m in RE_ESPACE.finditer(bloc)]
    onglets = []
    for m in RE_ONGLET.finditer(bloc):
        precedents = [e for e in espaces if e[0] < m.start()]
        if not precedents:
            continue
        sections = RE_CHAINE.findall(m.group(3))
        onglets.append({"espace": precedents[-1][1], "id": m.group(1),
                        "label_expr": m.group(2), "sections": sections})
    return [e[1] for e in espaces], onglets, constantes


def aveu(cle):
    return "« " + cle + " » (destination non nommée)"


def deriver(doc, espaces, onglets, constantes):
    """Rend {id_onglet: nom} et la liste des refus, chacun NOMMÉ."""
    noms, refus = {}, []
    combien_d_onglets = {}
    for t in onglets:
        combien_d_onglets[t["espace"]] = combien_d_onglets.get(t["espace"], 0) + 1
    for t in onglets:
        cle = t["espace"] + " / " + t["id"]
        # 1. un seul panneau, et il porte un titre
        if len(t["sections"]) == 1:
            nom, commentaire = nom_ecrit_sur_le_panneau(doc, t["sections"][0])
            if nom is None:
                refus.append(f"{cle} : la section « {t['sections'][0] } » que le modèle déclare "
                             "n'existe pas dans le document servi")
                continue
            if commentaire:
                refus.append(f"{cle} : le titre du panneau « {t['sections'][0]} » porte un "
                             "COMMENTAIRE en enfant direct — le code le plierait dans le nom, un "
                             "lecteur ne le verrait pas")
                continue
            if nom:
                noms[t["id"]] = nom
                continue
        # 2. l'espace n'a qu'un onglet : son lien de barre latérale nomme
        if combien_d_onglets.get(t["espace"], 0) == 1:
            nom = nom_ecrit_sur_la_barre_laterale(doc, t["espace"])
            if nom is None:
                refus.append(f"{cle} : la dérivation retombe sur le lien de barre latérale de "
                             f"l'espace « {t['espace']} », que le document servi ne porte pas")
                continue
            if nom:
                noms[t["id"]] = nom
                continue
        # 3. un GROUPE déclare son libellé
        expr = t["label_expr"]
        if expr[:1] in ("'", '"'):
            valeur = expr[1:-1]
        elif expr in constantes:
            valeur = constantes[expr]
        else:
            refus.append(f"{cle} : le libellé est l'identifiant « {expr} », que le module ne "
                         "déclare pas comme constante de chaîne")
            continue
        if valeur:
            noms[t["id"]] = valeur
            continue
        # 4. l'AVEU — la console dit ne pas savoir nommer ; un document ne recopie pas un aveu
        refus.append(f"{cle} : la console rend ici l'AVEU {aveu(t['id'])} — elle admet ne pas "
                     "savoir nommer cette destination, et le document ne peut pas le recopier "
                     "comme un libellé")
    return noms, refus


# --------------------------------------------------------------------------------------------
# LE CORPUS DOCUMENTAIRE — les lignes sont qualifiées par le MODÈLE, pas par un nom de colonne.
# --------------------------------------------------------------------------------------------
RE_JETON = re.compile(r"^`([A-Za-z0-9_-]+)`$")


def cellules(ligne):
    l = ligne.strip()
    if not l.startswith("|"):
        return None
    return [c.strip() for c in l.strip("|").split("|")]


def est_separatrice(cs):
    return bool(cs) and all(re.fullmatch(r":?-{2,}:?", c) for c in cs)


def tableaux_d_onglets(texte, ids_declares):
    """Chaque tableau dont TOUTES les lignes de données ont pour 1re cellule un id d'onglet déclaré.

    Rend [(en_tete, [(no_de_ligne, id, cellules)])].
    """
    lignes = texte.split("\n")
    trouves, i = [], 0
    while i < len(lignes):
        cs = cellules(lignes[i])
        if cs is None or len(cs) < 2 or i + 1 >= len(lignes) or not est_separatrice(cellules(lignes[i + 1]) or []):
            i += 1
            continue
        entete, donnees, j = cs, [], i + 2
        while j < len(lignes):
            d = cellules(lignes[j])
            if d is None:
                break
            donnees.append((j + 1, d))
            j += 1
        qualifie = bool(donnees)
        rows = []
        for no, d in donnees:
            m = RE_JETON.match(d[0]) if d else None
            if not m or m.group(1) not in ids_declares:
                qualifie = False
                break
            rows.append((no, m.group(1), d))
        if qualifie:
            trouves.append((entete, rows))
        i = j
    return trouves


def fichiers_suivis(motif):
    r = subprocess.run(["git", "-C", RACINE, "ls-files", motif],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return [f for f in r.stdout.split("\n") if f]


# --------------------------------------------------------------------------------------------
# LES TÉMOINS — sur des entrées FABRIQUÉES ICI, jamais sur l'état du dépôt. Une borne posée sur le
# dépôt rougirait le jour où le travail est fini : ce serait une rançon, pas une garde.
# --------------------------------------------------------------------------------------------
MODELE_TEMOIN = """
const NOM_DERIVE = '';
const SPACES = [
  { id: 'seul', tabs: [
    { id: 'seul', label: NOM_DERIVE, sections: ['panneau-muet'] },
  ] },
  { id: 'plusieurs', tabs: [
    { id: 'titre', label: NOM_DERIVE, sections: ['panneau-titre'] },
    { id: 'groupe', label: 'Groupe déclaré', sections: ['a', 'b'] },
    { id: 'aveugle', label: NOM_DERIVE, sections: ['panneau-nu'] },
  ] },
];
"""

DOC_TEMOIN = """<body>
<nav id="nav">
  <a href="#seul" data-space="seul"><svg class="ic"><path d="M3 11"/></svg> <span>Nom de barre</span></a>
  <a href="#titre" data-space="plusieurs"><span>Plusieurs</span></a>
</nav>
<section id="panneau-muet"><h2 id="muet-h"></h2></section>
<section id="panneau-titre"><div class="panelhead">
  <h2 id="t-h">Jetons &amp; secrets <button class="ihelp" type="button">?</button></h2>
</div></section>
<section id="a"><h2>A</h2></section>
<section id="b"><h2>B</h2></section>
<section id="panneau-nu"><h2></h2></section>
</body>"""


def _derive_temoin(doc_src, modele_src):
    p = Arbre()
    p.feed(doc_src)
    espaces, onglets, constantes = lire_le_modele(modele_src)
    if espaces is None:
        return None, ["modèle illisible"]
    return deriver(p.racine, espaces, onglets, constantes)


def epreuves():
    # --- TÉMOIN POSITIF : les quatre chemins de la dérivation, sur un corpus NON VIDE ---
    noms, refus = _derive_temoin(DOC_TEMOIN, MODELE_TEMOIN)
    attendu = {"seul": "Nom de barre", "titre": "Jetons & secrets", "groupe": "Groupe déclaré"}
    if noms != attendu:
        return f"témoin positif : dérivé {noms}, attendu {attendu}"
    # le « ? » du bouton d'aide ne doit PAS entrer dans le nom
    if "?" in noms["titre"]:
        return "témoin positif : un geste porté par le titre est entré dans le nom"
    # --- TÉMOIN DE REFUS (aveu) : l'onglet aveugle n'a ni titre, ni lien, ni libellé ---
    if len(refus) != 1 or "aveugle" not in refus[0]:
        return f"témoin d'aveu : {len(refus)} refus, attendu 1 nommant « aveugle » — {refus}"
    # --- TÉMOIN DE REFUS : une section déclarée qui n'existe pas dans le document ---
    _, r = _derive_temoin(DOC_TEMOIN.replace('id="panneau-titre"', 'id="ailleurs"'), MODELE_TEMOIN)
    if not any("panneau-titre" in x and "n'existe pas" in x for x in r):
        return f"témoin de section absente : aucun refus ne la nomme — {r}"
    # --- TÉMOIN DE REFUS : un identifiant de libellé non déclaré ---
    _, r = _derive_temoin(DOC_TEMOIN, MODELE_TEMOIN.replace("const NOM_DERIVE = '';", ""))
    if not any("NOM_DERIVE" in x for x in r):
        return f"témoin d'identifiant : aucun refus ne le nomme — {r}"
    # --- TÉMOIN DE REFUS : un commentaire en enfant direct d'un titre ---
    _, r = _derive_temoin(DOC_TEMOIN.replace(">Jetons &amp; secrets ", "><!-- caché -->Jetons "),
                          MODELE_TEMOIN)
    if not any("COMMENTAIRE" in x for x in r):
        return f"témoin de commentaire : aucun refus ne le nomme — {r}"
    # --- TÉMOIN DE REFUS : le lien de barre latérale manque là où la dérivation y retombe ---
    _, r = _derive_temoin(DOC_TEMOIN.replace('data-space="seul"', 'data-space="autre"'), MODELE_TEMOIN)
    if not any("barre latérale" in x for x in r):
        return f"témoin de barre latérale : aucun refus ne le nomme — {r}"
    # --- TÉMOIN DE CORPUS DÉGÉNÉRÉ : le modèle sans ses libellés (la panne de `P11.18-o`) ---
    e2, o2, _ = lire_le_modele(MODELE_TEMOIN.replace(" label: NOM_DERIVE,", "")
                                            .replace(" label: 'Groupe déclaré',", ""))
    if len(o2) >= 2:
        return f"témoin dégénéré : {len(o2)} onglets lus sur un modèle sans libellé, attendu < 2"
    # --- TÉMOINS DU CORPUS DOCUMENTAIRE : ce qui qualifie une ligne, et ce qui ne qualifie pas ---
    ids = {"titre", "groupe"}
    bon = "| Onglet | Libellé |\n|---|---|\n| `titre` | Jetons & secrets |\n| `groupe` | Groupe déclaré |\n"
    t = tableaux_d_onglets(bon, ids)
    if len(t) != 1 or [r[1] for r in t[0][1]] != ["titre", "groupe"]:
        return f"témoin de tableau : {t}"
    if tableaux_d_onglets("| Marque | Sens |\n|---|---|\n| **espace admin** | réservé |\n", ids):
        return "témoin négatif de tableau : un tableau sans identifiant d'onglet a été qualifié"
    if tableaux_d_onglets("| Onglet | Libellé |\n|---|---|\n| `titre` | X |\n| `inconnu` | Y |\n", ids):
        return "témoin négatif de tableau : un tableau portant un identifiant INCONNU a été qualifié"
    # --- TÉMOIN NÉGATIF DE LA COMPARAISON, DANS LES DEUX SENS ---
    ecarts = [r[1] for r in tableaux_d_onglets(bon, ids)[0][1] if r[2][1] != attendu.get(r[1])]
    if ecarts:
        return f"témoin de comparaison (documentation juste) : {ecarts} accusés à tort"
    faux = bon.replace("| `groupe` | Groupe déclaré |", "| `groupe` | Ancien nom |")
    ecarts = [r[1] for r in tableaux_d_onglets(faux, ids)[0][1] if r[2][1] != attendu.get(r[1])]
    if ecarts != ["groupe"]:
        return f"témoin de comparaison (documentation périmée) : {ecarts}, attendu ['groupe']"
    # le MÊME écart doit apparaître quand c'est la PAGE qui bouge, documentation inchangée
    n2, _ = _derive_temoin(DOC_TEMOIN.replace("Jetons &amp; secrets", "Jetons renommés"), MODELE_TEMOIN)
    ecarts = [r[1] for r in tableaux_d_onglets(bon, ids)[0][1] if r[2][1] != n2.get(r[1])]
    if ecarts != ["titre"]:
        return f"témoin de comparaison (page renommée) : {ecarts}, attendu ['titre']"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    modules = fichiers_suivis("web/*")
    if modules is None:
        print("::error::`git ls-files` ne répond pas : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    porteurs, documents = [], []
    for f in modules:
        try:
            texte = open(os.path.join(RACINE, f), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        if "const SPACES = [" in texte:
            porteurs.append((f, texte))
        if f.endswith(".html") and "data-space=" in texte:
            documents.append((f, texte))

    if len(porteurs) != 1:
        print(f"::error::{len(porteurs)} fichier(s) suivi(s) de web/ portent `const SPACES = [` — "
              "la dérivation n'a pas d'ancre unique, la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if len(documents) != 1:
        print(f"::error::{len(documents)} document(s) servi(s) portent la barre latérale des espaces "
              "— la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    chemin_modele, source = porteurs[0]
    chemin_doc, page = documents[0]

    espaces, onglets, constantes = lire_le_modele(source)
    if espaces is None:
        print(f"::error file={chemin_modele}::le bloc `const SPACES = [` est illisible — la garde "
              "REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if len(espaces) < 2 or len(onglets) < 2:
        print(f"::error file={chemin_modele}::corpus DÉGÉNÉRÉ — {len(espaces)} espace(s) et "
              f"{len(onglets)} onglet(s) lus. C'est la panne exacte de `P11.18-o` : un modèle dont "
              "la forme a changé se lit presque vide, et un verdict rendu là-dessus serait vert par "
              "aveuglement. La garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    p = Arbre()
    p.feed(page)
    noms, refus = deriver(p.racine, espaces, onglets, constantes)

    if refus:
        for r in refus:
            print(f"::error file={chemin_doc}::{r}", file=sys.stderr)
        print(f"\n{len(refus)} destination(s) sur {len(onglets)} que l'instrument ne sait pas "
              "trancher. Réécrire une ligne de documentation sur une dérivation partielle "
              "remplacerait une documentation périmée par une documentation FAUSSE — la première se "
              "soupçonne, la seconde se croit. La garde REFUSE DE CONCLURE.", file=sys.stderr)
        return 2

    ids = set(noms)
    docs = fichiers_suivis("*.md")
    if docs is None:
        print("::error::`git ls-files` ne répond pas : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    juges, ecarts, entetes = 0, [], []
    for f in docs:
        try:
            texte = open(os.path.join(RACINE, f), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        for entete, rows in tableaux_d_onglets(texte, ids):
            entetes.append((f, entete))
            for no, ident, cs in rows:
                if len(cs) < 2:
                    continue
                juges += 1
                if cs[1] != noms[ident]:
                    ecarts.append((f, no, ident, cs[1], noms[ident]))

    if not entetes:
        print("::error::aucun tableau d'onglets dans le corpus suivi : l'instrument n'a pas d'objet, "
              "la garde REFUSE DE CONCLURE plutôt que de rendre un vert qui ne mesure rien",
              file=sys.stderr)
        return 2

    for f, no, ident, ecrit, servi in ecarts:
        print(f"::error file={f},line={no}::`{ident}` : la ligne nomme cet onglet autrement que la "
              f"console — elle sert « {servi} ». Le nom n'est plus écrit dans le module depuis "
              "`P11.18-o` : il est DÉRIVÉ du titre du panneau, et c'est ce titre qui fait foi.",
              file=sys.stderr)

    if ecarts:
        print(f"\n{len(ecarts)} ligne(s) sur {juges} jugée(s) nomment un onglet autrement que la "
              "console. La page est la SOURCE, le document est le COPISTE : l'écart accuse le "
              "document.", file=sys.stderr)
        return 1

    lus = ", ".join(f"{f} (« {' | '.join(e)} »)" for f, e in entetes)
    print(f"check_a_documented_tab_label_is_the_name_the_console_serves : {len(onglets)} onglet(s) "
          f"déclarés par {chemin_modele}, {len(noms)} nom(s) DÉRIVÉS du document servi "
          f"({chemin_doc}) sans un seul refus, et les {juges} ligne(s) documentées nomment "
          "exactement ce que la console sert.\n"
          f"COLONNE JUGÉE — la DEUXIÈME de chaque tableau qualifié, en-têtes lus : {lus}.\n"
          "CE QU'ELLE NE TIENT PAS : un nom cité en PROSE lui échappe (`docs/NATIVE-IDP.md` en "
          "portait un, périmé, corrigé à la main) ; une colonne de libellé déplacée hors de la "
          "deuxième position lui échapperait aussi ; et qu'un onglet SOIT documenté se juge "
          "ailleurs, par `check_operator_surface_is_documented.py`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
