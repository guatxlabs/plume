#!/usr/bin/env python3
"""Un chemin cité en PROSE mène là où il dit (`P11.21-d`).

CE QUE CETTE PASSE ATTEINT QUE `check_a_documented_tab_label_is_the_name_the_console_serves.py`
N'ATTEINT PAS. Cette garde-là juge une COLONNE de tableau, à une position fixe, et elle le DIT à
chaque exécution : « un nom cité en PROSE lui échappe ». La prose n'est pas un reste du même
travail, c'est la moitié que l'instrument ne peut pas atteindre.

LA SOURCE DE VÉRITÉ N'EST PAS RÉÉCRITE ICI. Ce module IMPORTE la garde des libellés et emploie SES
fonctions (`epreuves`, `lire_le_modele`, `deriver`, `nom_ecrit_sur_la_barre_laterale`,
`fichiers_suivis`). Trois lectures d'une même liste dont aucune ne fait foi est un défaut déjà payé
dans ce dépôt : il n'y en a qu'une, et si elle se dit invalide, cette passe REFUSE DE CONCLURE.

LE CORPUS EST DU TEXTE CONTINU. Une citation qui court sur deux lignes échappe à un contrôle ligne
à ligne, et ce n'est pas une hypothèse : `docs/NATIVE-IDP.md` en porte une (l'espace en fin de
ligne, sa destination sur la suivante, derrière une indentation de continuation). Le texte est donc
normalisé — tout blanc réduit à une espace — avec une carte des décalages qui rend malgré tout le
numéro de ligne d'ORIGINE.

CE QU'EST UNE CITATION, ET POURQUOI L'ANCRE EST LE NOM JUSTE. Un nom PÉRIMÉ ne s'énumère pas : on
ne peut pas chercher ce qu'on ne connaît plus. C'est donc l'autre moitié du couple — celle qui est
encore JUSTE — qui déclare la chaîne navigationnelle. Une flèche est retenue quand le texte qui la
précède FINIT par un nom que la console sert, ou quand celui qui la suit COMMENCE par un tel nom,
la frontière étant un caractère non alphanumérique. Le plus LONG nom gagne (« Détection & Réponse »
avant « Détection »).
"""
import importlib.util, os, re, sys

RACINE = "/home/guat/wslRecover/guat/GUATX/ops/plume-oss"
GARDE = os.path.join(RACINE, ".github/scripts/check_a_documented_tab_label_is_the_name_the_console_serves.py")

_spec = importlib.util.spec_from_file_location("garde_libelles", GARDE)
G = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(G)

FLECHE = re.compile(r"\s*(?:→|->|⟶)\s*")
ALNUM = re.compile(r"[^\W_]", re.U)
# Bornes d'un segment BRUT — servent seulement à NOMMER ce qu'on a lu quand aucun nom servi ne
# correspond ; jamais à décider. Ornements de balisage compris (accents graves, gras, crochets).
BORNES = set("|.;:!?,()[]«»`*\"'—–\n")


# ---------------------------------------------------------------------------- le texte continu
def continu(texte):
    """(texte_normalisé, carte) ; carte[i] = décalage d'ORIGINE du i-ème caractère normalisé."""
    out, carte, blanc = [], [], False
    for i, ch in enumerate(texte):
        if ch.isspace():
            if not blanc:
                out.append(" "); carte.append(i); blanc = True
        else:
            out.append(ch); carte.append(i); blanc = False
    return "".join(out), carte


def debuts_de_ligne(texte):
    d = [0]
    for i, ch in enumerate(texte):
        if ch == "\n":
            d.append(i + 1)
    return d


def no_de_ligne(debuts, off):
    lo, hi = 0, len(debuts) - 1
    while lo < hi:
        mi = (lo + hi + 1) // 2
        if debuts[mi] <= off:
            lo = mi
        else:
            hi = mi - 1
    return lo + 1


# ------------------------------------------------- les blocs de code : une DÉCISION, pas un silence
# * un bloc CLÔTURÉ (``` / ~~~) n'est PAS de la prose : une flèche y appartient à un exemple de
#   configuration ou à une sortie de commande, pas à un chemin qu'un lecteur suit. Il est RETIRÉ du
#   corpus de prose — et ce que le retrait COÛTE est compté et PUBLIÉ, jamais escamoté.
# * un code EN LIGNE (`…`) EST de la prose : les citations de `docs/NATIVE-IDP.md` sont écrites À
#   L'INTÉRIEUR d'accents graves. L'exclure aveuglerait la passe sur la famille même qu'elle chasse.
RE_CLOTURE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


def separer_les_blocs(texte):
    """(prose_masquée_aux_MÊMES_décalages, texte_des_blocs_clôturés)."""
    dedans, marque, prose, blocs = False, None, [], []
    for l in texte.split("\n"):
        m = RE_CLOTURE.match(l)
        if not dedans and m:
            dedans, marque = True, m.group(1)[0]
            prose.append(" " * len(l)); blocs.append(l); continue
        if dedans:
            blocs.append(l); prose.append(" " * len(l))
            if m and m.group(1)[0] == marque:
                dedans = False
            continue
        prose.append(l); blocs.append("")
    return "\n".join(prose), "\n".join(blocs)


# ------------------------------------------------------------------- l'appariement d'un nom SERVI
def nom_en_suffixe(t, fin, noms):
    """Le plus LONG nom servi qui termine `t[:fin]`, frontière non alphanumérique. (nom, début)."""
    trouve = (None, fin)
    for n in noms:
        d = fin - len(n)
        if d >= 0 and t[d:fin] == n and (d == 0 or not ALNUM.match(t[d - 1])):
            if trouve[0] is None or len(n) > len(trouve[0]):
                trouve = (n, d)
    return trouve


def nom_en_prefixe(t, debut, noms):
    """Le plus LONG nom servi qui commence en `debut`, frontière non alphanumérique."""
    trouve = None
    for n in noms:
        f = debut + len(n)
        if t[debut:f] == n and (f >= len(t) or not ALNUM.match(t[f])):
            if trouve is None or len(n) > len(trouve):
                trouve = n
    return trouve


def brut_avant(t, fin):
    i = fin
    while i > 0 and t[i - 1] not in BORNES:
        i -= 1
    return t[i:fin].strip()


def brut_apres(t, debut):
    i, n = debut, len(t)
    while i < n and t[i] not in BORNES and not FLECHE.match(t, i):
        i += 1
    return t[debut:i].strip()


# ------------------------------------------------------------------------------------ le verdict
def couples(t, v):
    """Chaque flèche du texte, jugée comme un COUPLE (départ, destination).

    Rend [(verdict, decalage, cite, detail)] ; verdict ∈
      'hors-sujet'   aucune moitié ne nomme quoi que ce soit que la console serve
      'conforme'     un espace servi, et une destination servie QUI LUI APPARTIENT
      'ecart'        un espace servi, et une destination qu'il ne porte pas (ou plus)
      'a-trancher'   ancré sur un nom servi, mais la passe ne sait pas dire si c'est un chemin
    """
    esp = v["nom_espace"]           # id -> nom
    ong = v["nom_onglet"]           # id -> nom
    inv_esp = {n: i for i, n in esp.items()}
    inv_ong = {}
    for i, n in ong.items():
        inv_ong.setdefault(n, []).append(i)
    tous = list(inv_esp) + list(inv_ong)
    out, i = [], 0
    while True:
        m = FLECHE.search(t, i)
        if not m:
            return out
        i = m.end()
        g_nom, g_deb = nom_en_suffixe(t, m.start(), tous)
        d_nom = nom_en_prefixe(t, m.end(), tous)
        if g_nom is None and d_nom is None:
            out.append(("hors-sujet", m.start(), "", ""))
            continue
        gauche = g_nom if g_nom else brut_avant(t, m.start())
        droite = d_nom if d_nom else brut_apres(t, m.end())
        cite, off = f"{gauche} → {droite}", (g_deb if g_nom else m.start())
        if g_nom is None:
            out.append(("a-trancher", off, cite,
                        "le DÉPART ne nomme aucun espace ni aucune destination que la console "
                        "sert : ou bien ce n'est pas un chemin, ou bien le nom de départ est "
                        "lui-même périmé — la passe ne sait pas dire lequel"))
            continue
        if g_nom not in inv_esp:
            out.append(("a-trancher", off, cite,
                        f"le départ « {g_nom} » est une DESTINATION servie, pas un espace : une "
                        "chaîne qui part d'un onglet n'est pas un chemin d'espace"))
            continue
        espace = inv_esp[g_nom]
        if d_nom is not None and d_nom in inv_esp and d_nom not in inv_ong:
            out.append(("a-trancher", off, cite,
                        "deux noms d'ESPACE se suivent : ce n'est pas un chemin espace→onglet"))
            continue
        if d_nom is not None and d_nom in inv_ong:
            ids = inv_ong[d_nom]
            bons = [x for x in ids if v["espace_de"][x] == espace]
            if bons:
                out.append(("conforme", off, cite, f"`{bons[0]}`"))
            else:
                vrai = esp[v["espace_de"][ids[0]]]
                out.append(("ecart", off, cite,
                            f"« {d_nom} » est bien une destination servie, mais elle vit sous "
                            f"« {vrai} », pas sous « {g_nom} »"))
            continue
        servies = sorted(n for x, n in ong.items() if v["espace_de"][x] == espace)
        out.append(("ecart", off, cite,
                    f"« {droite} » n'est aucune des destinations que « {g_nom} » sert : "
                    + ", ".join(f"« {s} »" for s in servies)))


# -------------------------------------------------------------- la source de vérité, celle de la garde
def _lire(rel):
    try:
        return open(os.path.join(RACINE, rel), encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return ""


def source_de_verite():
    faute = G.epreuves()
    if faute:
        return None, f"la garde des libellés se dit elle-même INVALIDE ({faute})"
    modules = G.fichiers_suivis("web/*")
    if modules is None:
        return None, "`git ls-files` ne répond pas"
    porteurs = [f for f in modules if "const SPACES = [" in _lire(f)]
    pages = [f for f in modules if f.endswith(".html") and "data-space=" in _lire(f)]
    if len(porteurs) != 1 or len(pages) != 1:
        return None, f"{len(porteurs)} porteur(s) de modèle, {len(pages)} document(s) servi(s)"
    espaces, onglets, constantes = G.lire_le_modele(_lire(porteurs[0]))
    if espaces is None or len(espaces) < 2 or len(onglets) < 2:
        return None, "modèle illisible ou corpus DÉGÉNÉRÉ"
    p = G.Arbre(); p.feed(_lire(pages[0]))
    noms, refus = G.deriver(p.racine, espaces, onglets, constantes)
    if refus:
        return None, f"{len(refus)} destination(s) que la dérivation ne tranche pas"
    v = {"nom_espace": {e: G.nom_ecrit_sur_la_barre_laterale(p.racine, e) for e in espaces},
         "nom_onglet": noms, "espace_de": {t["id"]: t["espace"] for t in onglets},
         "modele": porteurs[0], "page": pages[0]}
    if not all(v["nom_espace"].values()):
        return None, "un espace n'a pas de nom de barre latérale"
    return v, None


# ---------------------------------------------------------------------------------- les témoins
# Sur des entrées FABRIQUÉES ICI, jamais sur l'état du dépôt : une borne posée sur le dépôt
# rougirait le jour où le travail est FINI — ce serait une rançon, pas une garde.
V = {"nom_espace": {"data": "Données", "detresp": "Détection & Réponse", "admin": "Administration"},
     "nom_onglet": {"connectors": "Connecteurs de sources", "users": "Comptes & accès",
                    "idp": "Identité fédérée (SSO)", "detection": "Détection"},
     "espace_de": {"connectors": "data", "users": "admin", "idp": "admin", "detection": "detresp"}}


def _lus(texte):
    prose, _ = separer_les_blocs(texte)
    t, _c = continu(prose)
    return couples(t, V)


def _retenus(texte):
    return [(a, d) for a, _o, _c, d in _lus(texte) if a != "hors-sujet"]


def epreuves():
    # (1) POSITIF — une citation JUSTE, sur UNE ligne, n'est pas accusée.
    r = _retenus("Créez-le dans l'UI (Données → Connecteurs de sources) ou via l'API.")
    if [a for a, _ in r] != ["conforme"]:
        return f"témoin positif, citation juste sur une ligne : {r}"
    # (2) POSITIF — la MÊME citation COUPÉE EN DEUX, indentation de continuation comprise. C'est le
    #     trou EXACT d'un contrôle ligne à ligne, et la seule raison d'être du texte continu.
    r = _retenus("- il n'est pas révocable depuis `Données →\n  Connecteurs de sources` ; voyez.")
    if [a for a, _ in r] != ["conforme"]:
        return f"témoin de citation COUPÉE sur deux lignes : {r}"
    # (2 bis) et le MÊME texte, lu LIGNE À LIGNE, doit être MANQUÉ — sinon le témoin (2) ne prouve
    #     rien : il faut que la coupure fasse une différence MESURABLE.
    coupe = "- il n'est pas révocable depuis `Données →\n  Connecteurs de sources` ; voyez."
    par_ligne = [x for l in coupe.split("\n") for x in couples(l, V) if x[0] != "hors-sujet"]
    if any(a == "conforme" for a, _o, _c, _d in par_ligne):
        return "témoin de coupure : la lecture LIGNE À LIGNE voit la citation, le témoin ne prouve rien"
    # (3) NÉGATIF — un ESPACE périmé est ACCUSÉ, et l'accusation NOMME celui que la console sert.
    r = _retenus("1. **Détection & Réponse → Connecteurs de sources** (ou l'API) → un connecteur.")
    if [a for a, _ in r] != ["ecart"] or "Données" not in r[0][1]:
        return f"témoin d'espace périmé : {r}"
    # (4) NÉGATIF — une DESTINATION que la console ne sert plus est ACCUSÉE, et l'accusation
    #     ÉNUMÈRE ce que l'espace sert vraiment.
    r = _retenus("Ouvrez `Données → Connecteurs` puis créez-le.")
    if [a for a, _ in r] != ["ecart"] or "Connecteurs de sources" not in r[0][1]:
        return f"témoin de destination périmée : {r}"
    # (5) NÉGATIF — un nom d'espace employé HORS citation (aucune flèche) n'est PAS vu.
    if _lus("L'espace Données regroupe les sources, et Administration tient les comptes."):
        return "témoin hors-citation : une phrase SANS flèche a été lue comme une citation"
    # (6) NÉGATIF — une flèche qui ne cite aucun nom servi est VUE puis ÉCARTÉE, pas ignorée.
    l = _lus("Le flux va de syslog → parseur → index, sans passer par la console.")
    if len(l) != 2 or any(a != "hors-sujet" for a, _o, _c, _d in l):
        return f"témoin hors-sujet : {l}"
    # (7) DÉCISION — une flèche dans un bloc CLÔTURÉ n'est pas de la prose.
    if _lus("Avant.\n\n```\nDétection & Réponse → Connecteurs de sources\n```\n\nAprès."):
        return "témoin de bloc clôturé : une chaîne y a été lue comme de la prose"
    # (8) DÉCISION, L'AUTRE SENS — le code EN LIGNE reste de la prose, et un nom À PARENTHÈSES
    #     n'est pas tronqué par elles.
    r = _retenus("via l'UI (`Administration → Identité fédérée (SSO)`) ou l'API `/api/idp`.")
    if [a for a, _ in r] != ["conforme"]:
        return f"témoin de code EN LIGNE + nom parenthésé : {r}"
    # (9) L'AVEU — ancré sur une destination servie mais SANS espace de départ : PUBLIÉ, pas deviné.
    r = _retenus("Le chemin Espace Perdu → Comptes & accès est documenté ailleurs.")
    if [a for a, _ in r] != ["a-trancher"]:
        return f"témoin d'aveu (départ non servi) : {r}"
    # (10) LE PLUS LONG NOM GAGNE — « Détection & Réponse » ne doit pas se lire « Détection ».
    r = _retenus("Allez dans Détection & Réponse → Détection pour la couverture.")
    if [a for a, _ in r] != ["conforme"]:
        return f"témoin du plus long nom : {r}"
    # (11) LA FRONTIÈRE — un nom servi COLLÉ à d'autres lettres n'est pas un nom.
    l = _lus("La Recherche GXQL → résultats est une capture, pas un chemin.")
    if any(a != "hors-sujet" for a, _o, _c, _d in l):
        return f"témoin de frontière : {l}"
    # (12) LA CARTE DES DÉCALAGES rend la ligne d'ORIGINE, pas celle du texte normalisé.
    brut = "a\nb\nc\n- `Données →\n  Connecteurs de sources`\n"
    prose, _ = separer_les_blocs(brut)
    t, carte = continu(prose)
    c = [x for x in couples(t, V) if x[0] != "hors-sujet"]
    if len(c) != 1 or no_de_ligne(debuts_de_ligne(brut), carte[c[0][1]]) != 4:
        return f"témoin de carte des décalages : {c}"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE — la passe REFUSE DE CONCLURE : {faute}", file=sys.stderr)
        return 2
    v, pourquoi = source_de_verite()
    if v is None:
        print(f"::error::source de vérité illisible ({pourquoi}) — REFUS DE CONCLURE", file=sys.stderr)
        return 2
    docs = G.fichiers_suivis("*.md")
    if docs is None:
        print("::error::`git ls-files` ne répond pas — REFUS DE CONCLURE", file=sys.stderr)
        return 2
    ecarts, trancher, conformes, en_bloc, vues = [], [], [], [], 0
    for f in docs:
        brut = _lire(f)
        if not brut:
            continue
        prose, blocs = separer_les_blocs(brut)
        t, carte = continu(prose)
        debuts = debuts_de_ligne(brut)
        for verdict, off, cite, detail in couples(t, v):
            vues += 1
            if verdict == "hors-sujet":
                continue
            no = no_de_ligne(debuts, carte[off]) if off < len(carte) else 0
            {"ecart": ecarts, "a-trancher": trancher, "conforme": conformes}[verdict].append(
                (f, no, cite, detail))
        tb, cb = continu(blocs)
        db = debuts_de_ligne(brut)
        for verdict, off, cite, _d in couples(tb, v):
            if verdict != "hors-sujet":
                en_bloc.append((f, no_de_ligne(db, cb[off]) if off < len(cb) else 0, cite))

    for f, no, cite, detail in ecarts:
        print(f"::error file={f},line={no}::citation « {cite} » : {detail}", file=sys.stderr)
    for f, no, cite, detail in trancher:
        print(f"::warning file={f},line={no}::citation « {cite} » : {detail}", file=sys.stderr)
    retenues = len(ecarts) + len(trancher) + len(conformes)
    print(f"\nCORPUS : {len(docs)} document(s) suivis, lus en TEXTE CONTINU (blancs et sauts de "
          f"ligne réduits). SOURCE : {v['modele']} + {v['page']}, via la garde des libellés.\n"
          f"{vues} flèche(s) de prose examinée(s) ; {retenues} ANCRÉE(S) sur un nom que la console "
          f"sert — {len(conformes)} conforme(s), {len(ecarts)} en ÉCART, {len(trancher)} que la "
          f"passe NE SAIT PAS TRANCHER et publie plutôt que de deviner.\n"
          f"HORS PROSE, publié plutôt qu'escamoté : {len(en_bloc)} chaîne(s) ancrée(s) dans un "
          f"bloc de code CLÔTURÉ, écartées par DÉCISION.")
    for f, no, cite, _d in conformes:
        print(f"  conforme    {f}:{no}  {cite}")
    for f, no, cite, d in trancher:
        print(f"  À TRANCHER  {f}:{no}  {cite}  — {d}")
    for f, no, cite in en_bloc:
        print(f"  bloc de code {f}:{no}  {cite}")
    return 1 if ecarts else 0


if __name__ == "__main__":
    sys.exit(main())
