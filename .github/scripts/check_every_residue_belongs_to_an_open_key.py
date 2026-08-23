#!/usr/bin/env python3
"""Un RESTE écrit sous une clé fermée appartient à une clé ouverte, ou se déclare — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-RÉÉCRIVABLE
-----------------------------------------------
`docs/ROADMAP.md` est l'index des clés du projet, et une clé y porte un état : ✅ fermée, 🔵
mesurée non construite, ⬜ ouverte, 🔒 gestes de l'exploitant. Mesuré le 2026-08-23, avant
réparation : sur 155 lignes ✅, **20** portaient dans leur propre cellule un énoncé de la famille
« Reste : », « Reste ouvert : », « Résidu nommé : » — et **17** de ces énoncés n'étaient ni
qualifiés d'assumés, ni renvoyés à une clé, ni déclarés fermés. Le document SAVAIT que le travail
était incomplet et l'affichait comme complet. Qui lisait « ce qui est ouvert » ne voyait pas ces
dix-sept-là : c'est la famille de défaut que ce projet poursuit — un composant qui connaît son
résultat partiel et le présente comme entier — appliquée à l'index qui sert à la poursuivre.

LE CRITÈRE EST DÉRIVÉ DE LA GRAMMAIRE DU DOCUMENT, PAS D'UNE LISTE DE CLÉS
--------------------------------------------------------------------------
Une garde qui nommerait `P3.2-a` serait morte au prochain ajout : elle tiendrait les dix-sept
lignes d'hier et aucune de celles de demain. Ce qui est reconnu ici est une FORME que le document
se donne à lui-même et qu'il emploie depuis longtemps — le substantif `Reste` / `Restent` /
`Résidu` / `Résidus` en TÊTE d'énoncé, c'est-à-dire en début de cellule ou après une ponctuation
forte. Le VERBE ne compte pas : « le dépôt reste détecté », « une machine décommissionnée reste
comptée » sont de la prose ordinaire, et une garde qui les prendrait pour des restes noierait le
document sous des faux positifs jusqu'à être désarmée. Cette séparation porte ses deux témoins
ci-dessous.

LA RÈGLE TENUE : UN RESTE APPARTIENT À UNE CLÉ OUVERTE, OU IL DIT QU'IL EST ASSUMÉ
-----------------------------------------------------------------------------------
Sous ✅ — et sous ✅ seulement, car une ligne ⬜ ou 🔵 nomme légitimement ce qui lui reste à faire —
un énoncé de reste doit porter, dans le texte qui le suit jusqu'au reste suivant, l'une de ces
trois choses :

  (i)   un RENVOI : une clé du schéma, autre que la sienne, qui porte le travail. Un renvoi peut
        parfaitement viser un commit d'un dépôt voisin plutôt qu'une clé — la forme reconnue reste
        la clé, parce qu'une ligne qui cite un commit cite aussi la clé sous laquelle il tombe ;
  (ii)  une QUALIFICATION : le texte dit que la limite est assumée, délibérée, hors périmètre ou
        hors de portée. Le vocabulaire est fermé et court, pour qu'on ne puisse pas y ranger n'importe
        quoi ;
  (iii) une CLÔTURE : le document annonce, dans sa convention majuscule, que le reste est FERMÉ,
        LEVÉ, LIVRÉ, COMBLÉ ou RÉSOLU. Une clôture ferme aussi les restes qui la PRÉCÈDENT dans la
        même cellule : c'est ainsi que les cellules de ce document sont écrites — le constat, puis
        ses restes, puis la fermeture de ces restes, dans l'ordre du temps.

CE QU'UNE CITATION N'EST PAS
-----------------------------
Un fragment entre accents graves est une CITATION, pas de la prose : une ligne qui explique le
défaut en montrant `Reste ouvert :` ne porte pas de reste, elle en parle. Les fragments cités sont
donc retirés avant la recherche — sauf lorsqu'ils sont une clé nue, qui est justement la forme d'un
renvoi. Sans cette exception, la garde effacerait les renvois qu'elle exige. C'est aussi ce qui
empêche l'entrée d'index de cette garde de se compter elle-même, et le contrôle en porte le témoin.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son motif ne
reconnaît plus rien. Avant tout verdict, celle-ci exécute un corpus de contrôle portant ses DEUX
témoins — des formes qu'elle DOIT refuser, des formes qu'elle DOIT laisser passer — puis vérifie
sur l'arbre réel qu'elle voit encore des lignes de définition, des lignes fermées et des restes.
Si le vocabulaire du reste disparaissait du document, cette garde ne garderait plus rien, et son
vert serait le pire des deux mondes : elle échoue alors au lieu de se taire.

CE QU'ELLE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE
---------------------------------------------------
Elle ne juge que la famille lexicale du RESTE. Un travail en attente écrit sans ce mot — « Limite :
», « Non couvert : », une phrase qui décrit un manque sans le nommer — lui échappe, et c'est
assumé : le mot « Limite » dit déjà, dans ce document, une borne et non une dette, et étendre le
motif à cette famille produirait des dizaines de faux positifs sur des lignes légitimement fermées.
Elle ne lit pas non plus les dépôts voisins : un reste fermé ailleurs reste, pour elle, un reste —
c'est à la ligne de le DIRE. La rendre capable de le savoir la ferait dépendre d'un chemin de poste,
donc d'une machine, donc de rien.
"""
import os
import re
import sys
import unicodedata

DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "ROADMAP.md")

# ─── PLANCHERS. En dessous, ce n'est pas le document qui est propre, c'est l'analyseur qui est
# cassé — et un verdict rendu sous un plancher serait rendu sur ce que la garde ne lit plus.
# Relevé le 2026-08-23, après réparation : 175 lignes de définition, 156 fermées, 20 porteuses.
MIN_DEFINITIONS = 100
MIN_FERMEES = 90
MIN_PORTEUSES = 8

# L'ÉTAT qui promet que plus rien n'est en attente. Les autres états nomment légitimement leur reste.
FERMEE = "✅"

# LE MARQUEUR : le SUBSTANTIF en tête d'énoncé — début de cellule, après une ponctuation forte, ou
# après un tiret cadratin. Le verbe conjugué au fil d'une phrase n'est pas un marqueur.
MARQUEUR = re.compile(
    r"(?:^|(?<=[.;:!?)»])\s|(?<=—)\s)\*{0,2}"
    r"(RESTE|RESTENT|Reste|Restent|RÉSIDU|RÉSIDUS|Résidu|Résidus)\b"
)

# (i) UN RENVOI : une clé du schéma `P<phase>.<chantier>-<constat>`.
CLE = re.compile(r"P\d+(?:\.\d+)*-[a-z]\b")
CLE_SEULE = re.compile(r"^P\d+(?:\.\d+)*-[a-z]$")

# (ii) UNE QUALIFICATION. Vocabulaire fermé, comparé sans accents pour couvrir les lignes du
# document qui sont écrites en ASCII.
QUALIFICATION = re.compile(
    r"\b(delibere|deliberee|deliberes|deliberees|deliberement"
    r"|assume|assumee|assumes|assumees"
    r"|a dessein|hors perimetre|hors de portee)\b"
)

# (iii) UNE CLÔTURE, dans la convention majuscule du document.
CLOTURE = re.compile(
    r"\b(FERME|FERMEE|FERMES|FERMEES|LEVE|LEVEE|LEVES|LEVEES"
    r"|LIVRE|LIVREE|LIVRES|LIVREES|COMBLE|COMBLEE|RESOLU|RESOLUE)\b"
)

CITATION = re.compile(r"`([^`]*)`")


def sans_accents(texte):
    """Comparer sans accents : le document mélange des lignes accentuées et des lignes ASCII."""
    return "".join(c for c in unicodedata.normalize("NFD", texte) if unicodedata.category(c) != "Mn")


def depouiller(texte):
    """Retire les CITATIONS, en gardant les clés nues — elles sont la forme d'un renvoi.

    Les positions sont préservées (remplacement par des espaces de même longueur) pour que les
    bornes des énoncés restent celles du texte d'origine.
    """
    def remplace(m):
        dedans = m.group(1)
        if CLE_SEULE.match(dedans.strip()):
            return " " + dedans + " "
        return " " * len(m.group(0))
    return CITATION.sub(remplace, texte)


def est_une_cle(brut):
    """La clé NUE d'une première cellule : sans gras ni annotation `*(clé neuve)*`."""
    nue = re.sub(r"\*\([^)]*\)\*", "", brut).replace("*", "").strip()
    return nue if CLE_SEULE.match(nue) else None


def lignes_de_definition(texte):
    """Les lignes de tableau dont la PREMIÈRE cellule est une clé — la forme que l'index se donne."""
    out = []
    for n, ligne in enumerate(texte.split("\n"), 1):
        if not ligne.startswith("|"):
            continue
        cellules = ligne.split("|")
        if len(cellules) < 5:
            continue
        cle = est_une_cle(cellules[1].strip())
        if cle is None:
            continue
        etat = cellules[2 + 1].strip()
        corps = "|".join(cellules[4:]).rstrip()
        if corps.endswith("|"):
            corps = corps[:-1]
        out.append((n, cle, etat, corps.strip()))
    return out


def restes_orphelins(cle, corps):
    """Les énoncés de reste de cette cellule que rien ne rattache. Vide = la ligne est en règle."""
    texte = depouiller(corps)
    marqueurs = list(MARQUEUR.finditer(texte))
    if not marqueurs:
        return []
    bornes = [m.start() for m in marqueurs] + [len(texte)]
    en_attente = []
    for i in range(len(marqueurs)):
        enonce = texte[bornes[i]:bornes[i + 1]]
        nu = sans_accents(enonce)
        clot = CLOTURE.search(nu)
        qual = QUALIFICATION.search(nu.lower())
        renvoi = [k for k in CLE.findall(enonce) if k != cle]
        if clot:
            # Une clôture ferme aussi ce qui la précède : les cellules sont écrites dans l'ordre
            # du temps — le constat, ses restes, puis la fermeture de ces restes.
            en_attente = []
        if not (clot or qual or renvoi):
            en_attente.append(enonce.strip())
    return en_attente


# ─────────────────────────────────────────────────────────────────────────────────────────────
# L'INSTRUMENT SE VALIDE — DEUX TÉMOINS, AVANT TOUT VERDICT
# ─────────────────────────────────────────────────────────────────────────────────────────────
# Chaque cas est (clé, corps de cellule, orphelin attendu ?). Le corpus est fabriqué : il porte
# des formes que le document réel ne contient pas aujourd'hui, pour que la garde tienne aussi
# celles-là.
CORPUS = [
    # ── TÉMOINS POSITIFS : ce que la garde DOIT refuser ────────────────────────────────────────
    ("P1.1-a", "Fermé par un index. Reste ouvert : l'ablation n'est pas faite.", True),
    ("P1.1-b", "Reste : la table est prouvée par un harnais jetable.", True),
    ("P1.1-c", "Corrigé. Résidu nommé : un hôte muet reste invisible.", True),
    ("P1.1-d", "Corrigé. Restent nommés : deux surfaces sans avertissement.", True),
    ("P1.1-e", "Reste à confirmer sur une base réelle que l'index est créé.", True),
    ("P1.1-f", "Fait. RÉSIDU : la porte accepte tout nom.", True),
    # Un renvoi vers SA PROPRE clé n'est pas un renvoi : il ne mène nulle part.
    ("P1.1-g", "Reste : le quota manque, voir `P1.1-g`.", True),
    # Une clôture ne vaut que pour ce qui la PRÉCÈDE : un reste écrit APRÈS elle est orphelin.
    ("P1.1-h", "Reste : le premier trou. RESTE FERMÉ : mesuré à zéro. Reste : le second trou.", True),
    # ── TÉMOINS NÉGATIFS : ce que la garde NE DOIT PAS refuser ─────────────────────────────────
    #    a) le VERBE, en pleine phrase — la faute qui noierait la garde sous les faux positifs
    ("P2.1-a", "Hors fenêtre, le dépôt reste détecté, et c'est prouvé par mutation.", False),
    ("P2.1-b", "Les drop-ins de durcissement restent alertés, à dessein.", False),
    ("P2.1-c", "Le mode annoncé restait « temps réel » et la couverture celle de la configuration.", False),
    ("P2.1-d", "La reproductibilité de la construction reste un résidu hors de cet outillage.", False),
    #    b) les trois rattachements
    ("P2.2-a", "Reste ouvert : l'ablation n'est pas faite — portée par `P2.9-a`.", False),
    ("P2.2-b", "Reste hors de portée délibérément : le mode d'escrow.", False),
    ("P2.2-c", "RESTE, comme COUT ASSUME et non comme defaut : le job dure longtemps.", False),
    ("P2.2-d", "Reste : le premier trou. RESTE FERMÉ le 2026-01-01 : remesuré à zéro.", False),
    ("P2.2-e", "Résidu nommé et ASSUMÉ : la part sans imputation n'a pas de pivot.", False),
    #    c) une CITATION du vocabulaire n'est pas un reste — sans quoi la ligne qui documente
    #       ce défaut serait elle-même accusée par la garde qui le tient.
    ("P2.3-a", "Les énoncés de la famille `Reste :` / `Résidu nommé :` sont désormais tenus.", False),
    #    d) une cellule sans une seule occurrence du vocabulaire
    ("P2.4-a", "La garde est le complément calculé du flot de contrôle.", False),
]


def valider_instrument():
    ecarts = []
    for cle, corps, attendu in CORPUS:
        obtenu = bool(restes_orphelins(cle, corps))
        if obtenu != attendu:
            ecarts.append(
                f"    {cle} : attendu {'REFUS' if attendu else 'ACCEPTATION'}, "
                f"obtenu {'REFUS' if obtenu else 'ACCEPTATION'} — {corps}"
            )
    if ecarts:
        print(
            "L'INSTRUMENT NE SE RECONNAÎT PLUS LUI-MÊME. Le corpus de contrôle de cette garde, qui "
            "porte ses deux témoins, ne rend plus le verdict attendu. Aucun verdict n'est rendu sur "
            "le document réel : une garde qui ne sait plus distinguer un reste d'un verbe conjugué "
            "rendrait vert en n'ayant rien mesuré.\n" + "\n".join(ecarts),
            file=sys.stderr,
        )
        sys.exit(1)


def main():
    valider_instrument()

    chemin = os.path.normpath(DOC)
    try:
        with open(chemin, encoding="utf-8") as f:
            texte = f.read()
    except OSError as e:
        print(
            f"docs/ROADMAP.md ILLISIBLE ({chemin}) : {e}\n"
            "  Cette garde ne peut pas conclure sans le document. Un vert ici voudrait dire "
            "« aucun reste orphelin » alors qu'elle n'a rien lu.",
            file=sys.stderr,
        )
        sys.exit(1)

    definitions = lignes_de_definition(texte)
    fermees = [d for d in definitions if d[2] == FERMEE]
    porteuses = [d for d in definitions if MARQUEUR.search(depouiller(d[3]))]

    if len(definitions) < MIN_DEFINITIONS:
        print(
            f"PÉRIMÈTRE INVRAISEMBLABLE : {len(definitions)} ligne(s) de définition dans {chemin}, "
            f"plancher {MIN_DEFINITIONS}. La forme du tableau a dû changer et l'analyseur ne voit "
            "plus les entrées — un verdict serait rendu sur un document que cette garde ne lit plus.",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(fermees) < MIN_FERMEES:
        print(
            f"PÉRIMÈTRE INVRAISEMBLABLE : {len(fermees)} ligne(s) « {FERMEE} » sur "
            f"{len(definitions)}, plancher {MIN_FERMEES}. Le marqueur d'état a dû changer : cette "
            "garde ne regarde plus aucune ligne fermée, donc elle ne garde plus rien.",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(porteuses) < MIN_PORTEUSES:
        print(
            f"LE VOCABULAIRE DU RESTE A DISPARU DU DOCUMENT : {len(porteuses)} ligne(s) portent un "
            f"énoncé « Reste » / « Résidu », plancher {MIN_PORTEUSES}. Soit le document a changé de "
            "vocabulaire — auquel cas cette garde doit être réécrite sur le nouveau, pas laissée "
            "verte — soit le motif ne reconnaît plus rien.",
            file=sys.stderr,
        )
        sys.exit(1)

    fautes = []
    for n, cle, _etat, corps in fermees:
        for orphelin in restes_orphelins(cle, corps):
            fautes.append((n, cle, orphelin))

    if fautes:
        print(
            "UNE LIGNE FERMÉE PORTE DU TRAVAIL EN ATTENTE, ET L'INDEX LA PRÉSENTE COMME COMPLÈTE.\n"
            "Qui lit « ce qui est ouvert » ne verra pas ces restes-là.\n",
            file=sys.stderr,
        )
        for n, cle, orphelin in fautes:
            extrait = orphelin if len(orphelin) <= 220 else orphelin[:217] + "..."
            print(f"  * `{cle}` — docs/ROADMAP.md ligne {n}\n      {extrait}", file=sys.stderr)
        print(
            "\nCE QU'IL FAUT FAIRE, au choix, sur CHAQUE ligne nommée ci-dessus :\n"
            "  1. si c'est du TRAVAIL EN ATTENTE — ouvrez-lui sa propre clé, au format "
            "`P<phase>.<chantier>-<constat>`, en état ⬜ ou 🔵, avec son constat mesuré, sa date et "
            "son attendu ; puis CITEZ cette clé dans l'énoncé ci-dessus. Une clé déjà prise ne se "
            "réutilise jamais : la garde `P8.9-b` (daemon/src/tests/cles_de_roadmap_uniques.rs) "
            "refuse une collision.\n"
            "  2. si c'est une LIMITE ASSUMÉE — écrivez-le : « assumé », « délibéré », « à dessein », "
            "« hors périmètre » ou « hors de portée » dans le même énoncé. Le texte doit porter la "
            "décision, pas la sous-entendre.\n"
            "  3. si le reste est en réalité FERMÉ — dites-le dans l'énoncé, en majuscules "
            "(FERMÉ / LEVÉ / LIVRÉ / COMBLÉ / RÉSOLU), avec sa date et ce qui le prouve. S'il a été "
            "fermé dans un dépôt voisin, nommez le commit : rien ici ne peut le deviner.\n"
            "  4. si la ligne n'est PAS fermée — c'est son état ✅ qui est faux, corrigez-le.\n"
            f"\n{len(definitions)} ligne(s) de définition, {len(fermees)} fermée(s), "
            f"{len(porteuses)} porteuse(s) d'un énoncé de reste, {len(fautes)} orphelin(s).",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"check_every_residue_belongs_to_an_open_key : {len(definitions)} ligne(s) de définition, "
        f"{len(fermees)} fermée(s), {len(porteuses)} porteuse(s) d'un énoncé de reste, 0 orphelin. "
        "Un reste sous une clé fermée renvoie à une clé ouverte, se déclare assumé, ou se déclare "
        "fermé. Ne tient que la famille lexicale du reste, et ne lit aucun dépôt voisin."
    )


if __name__ == "__main__":
    main()
