#!/usr/bin/env python3
"""Une ligne de tableau porte la FORME que l'en-tête de son tableau déclare — garde de CI (`P8.9-d`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`docs/ROADMAP.md` est l'index public des clés du projet, et il est écrit en tableaux Markdown. Le
2026-08-25, un traitement automatique de cet index a REFUSÉ D'ÉCRIRE sur une ligne dont la cellule
finale ne se terminait pas par la barre qui clôt une cellule ; le comptage a établi qu'elles étaient
QUINZE dans ce cas, dont TROIS antérieures à la campagne du jour. AUCUNE GARDE DU DÉPÔT NE VOYAIT CE
DÉFAUT : celle des restes, celle des chiffres publiés et celle des collisions de clés lisent le TEXTE
des cellules et se moquent de la forme du tableau. Une ligne cassée passait donc verte partout, tout
en se rendant MAL au lecteur et en cassant tout outil qui la traite. C'est la famille que ce dépôt
poursuit — un instrument qui ne mesure pas la propriété qu'il semble garantir — appliquée au document
qui sert à la poursuivre.

LE CRITÈRE EST DÉRIVÉ DE CE QUE LE DOCUMENT SE DONNE COMME STRUCTURE
--------------------------------------------------------------------
Rien ici n'est écrit à la main : ni « il faut quatre cellules », ni le nom d'un fichier. En Markdown
(GFM), un tableau est DÉCLARÉ par sa LIGNE DE DÉLIMITATION — la ligne de tirets qui suit son en-tête.
Cette ligne est la déclaration que le document fait de sa propre forme : elle fixe le NOMBRE DE
COLONNES, et elle montre le style de barres employé (barre de tête, barre de queue). La règle tenue
est donc celle du document lui-même :

    toute ligne du corps d'un tableau porte le nombre de cellules que la ligne de délimitation
    de CE tableau déclare, et se termine (ou non) par une barre comme elle.

Une constante écrite ici serait morte au premier tableau à cinq colonnes ; un nom de fichier serait
mort au premier déplacement — le dépôt a déjà été mordu par cette faute (`P11.13-d` : une garde ancrée
sur un nom de fichier voyait 28 déclencheurs et n'en aurait vu qu'UN après un déplacement, en restant
VERTE). Le PÉRIMÈTRE est lui aussi dérivé d'une PROPRIÉTÉ et non d'une liste : est jugé tout document
Markdown de l'arbre QUI DÉCLARE UN TABLEAU. Un index qui déménage reste jugé ; un document neuf est
jugé du jour où il porte un tableau, sans que personne n'ait à l'inscrire ici.

CE QUE LE LECTEUR PERD, ET QUI N'EST PAS LA MÊME CHOSE DANS LES DEUX SENS
-------------------------------------------------------------------------
GFM ne refuse pas une ligne mal formée, il la RÉPARE en silence, et les deux réparations coûtent :
  · TROP DE CELLULES — « l'excédent est ignoré ». Le texte au-delà de la dernière colonne déclarée
    n'atteint JAMAIS la page, et tout ce qui suit la cellule surnuméraire est DÉCALÉ d'une colonne :
    des valeurs se rangent sous des en-têtes qui ne sont pas les leurs. La cause est presque toujours
    la même : une barre verticale ÉCRITE DANS LE TEXTE sans être échappée. Une barre entre accents
    graves n'est PAS protégée — le découpage des cellules se fait au niveau du BLOC, avant que les
    accents graves ne veuillent dire quoi que ce soit. Ce dépôt connaît la convention : ses documents
    écrivent déjà `\\|` là où il faut.
  · PAS ASSEZ DE CELLULES — des cellules vides sont insérées. La ligne se lit mal, mais rien ne
    disparaît.
  · BARRE DE QUEUE MANQUANTE — le rendu est identique, et c'est bien pourquoi le défaut a vécu :
    RIEN ne le montre au lecteur. Il ne se voit que d'un outil qui traite le document, et c'est
    exactement ainsi qu'il s'est vu, le 2026-08-25, par un script qui a refusé d'écrire.

CE QUE CETTE GARDE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE
-----------------------------------------------------------
Elle ne juge que la FORME. Une ligne parfaitement formée dont le texte est faux lui échappe, et c'est
le travail des trois gardes de contenu qui lisent le même document. Elle ne lit pas les tableaux d'un
bloc de code clôturé (```` ``` ````) : ce qui y est montré est un ÉCHANTILLON, pas un tableau du
document. Elle ne juge pas non plus l'alignement déclaré (`:---:`), qui ne change rien à ce qu'un
lecteur reçoit. Enfin, un document Markdown NON SUIVI et IGNORÉ par `.gitignore` sort du corpus : il
n'est pas publié.

LE CORPUS EST « CE QUI EST PUBLIÉ OU EN PASSE DE L'ÊTRE », PAS « CE QUI EST DÉJÀ INDEXÉ »
------------------------------------------------------------------------------------------
Il est dérivé de `git ls-files --cached --others --exclude-standard` : les fichiers SUIVIS **et** les
fichiers présents dans l'arbre que rien n'ignore. Le `--others` n'est pas une commodité, c'est une
correction : mesuré le 2026-08-22 sur ce dépôt, une garde dont le corpus se limitait aux fichiers
suivis rendait VERT sur un fichier tant qu'il n'était pas ajouté à l'index, puis rougissait au premier
commit — un instrument qui ne voit son sujet qu'une fois publié valide un travail qu'il n'a pas lu.
Un document neuf est donc jugé dès qu'il existe.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son découpeur
ne reconnaît plus rien. Celle-ci exécute d'abord un corpus de contrôle portant ses DEUX témoins — des
tableaux qu'elle DOIT refuser en nommant la ligne, des tableaux qu'elle NE DOIT PAS refuser (une barre
échappée, un tableau sans barres de bord, un tableau montré dans un bloc de code, de la prose qui
contient une barre) — puis vérifie sur l'arbre réel des PLANCHERS de documents, de tableaux et de
lignes de corps. Sous un plancher, elle ÉCHOUE au lieu de se taire : un vert rendu par un découpeur
cassé serait le pire des deux mondes.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import racine_designee  # noqa: E402  (geste partagé, écrit UNE fois)

# ─── PLANCHERS DE NON-DÉGÉNÉRESCENCE. En dessous, ce n'est pas l'arbre qui a maigri, c'est le découpeur
# qui est cassé. Relevés sur l'arbre le 2026-08-25 : 42 documents à tableau, 265 tableaux, 3 882 lignes
# de corps. Les abaisser demande une raison écrite à côté.
MIN_DOCUMENTS = 20
MIN_TABLEAUX = 100
MIN_LIGNES = 1500

# LA DÉCLARATION DE FORME : la ligne de délimitation d'un tableau GFM. Au moins une colonne, des tirets,
# un alignement facultatif. C'est elle qui porte le nombre de colonnes ET le style de barres du tableau.
DELIMITATION = re.compile(r"^ {0,3}\|?(?:\s*:?-+:?\s*\|)+\s*:?-+:?\s*\|?\s*$")
# Ce qui ROMPT le corps d'un tableau : une ligne vide, ou le début d'un autre bloc. La COUPURE
# THÉMATIQUE de tirets (`---`) en fait partie, et ce document l'écrit collée à la dernière ligne de ses
# tableaux : sans elle ici, la garde aurait accusé deux coupures d'être des lignes à une seule cellule —
# une accusation qu'un rendu réel dément (`<hr>`, pas une rangée). Elle ne peut pas être confondue avec
# une ligne de délimitation, qui porte des barres.
AUTRE_BLOC = re.compile(
    r"^ {0,3}(?:#{1,6}\s|>|```|~~~|[-*+]\s|\d+[.)]\s|(?:-\s*){3,}$|(?:\*\s*){3,}$|(?:_\s*){3,}$|=+\s*$)")
# Une clôture de bloc de code : ce qu'il contient est un ÉCHANTILLON, pas un tableau du document.
CLOTURE = re.compile(r"^ {0,3}(```|~~~)")


def decouper(ligne):
    """Les morceaux d'une ligne de tableau, coupés comme GFM le fait : sur les barres NON ÉCHAPPÉES.

    Le découpage a lieu au niveau du BLOC, donc AVANT que les accents graves ne veuillent dire quoi que
    ce soit : une barre dans un `code span` coupe la cellule comme une autre. Une barre précédée d'une
    contre-oblique est du contenu ; une contre-oblique échappée (`\\\\`) ne protège rien de ce qui suit,
    et c'est pourquoi ce découpage est écrit à la main plutôt qu'en regard arrière.
    """
    morceaux, tampon, i = [], [], 0
    while i < len(ligne):
        c = ligne[i]
        if c == "\\" and i + 1 < len(ligne):
            tampon.append(ligne[i:i + 2]); i += 2; continue
        if c == "|":
            morceaux.append("".join(tampon)); tampon = []; i += 1; continue
        tampon.append(c); i += 1
    morceaux.append("".join(tampon))
    return morceaux


def forme(ligne):
    """La FORME d'une ligne de tableau : (cellules, barre de tête, barre de queue).

    Les barres de bord sont facultatives en GFM ; ce qu'on tient ici n'est pas qu'elles soient là, mais
    que la ligne porte LES MÊMES que la déclaration de son tableau.
    """
    nu = ligne.strip()
    morceaux = decouper(nu)
    tete = nu.startswith("|")
    queue = len(morceaux) > 1 and morceaux[-1] == ""
    cellules = morceaux[1:] if tete else list(morceaux)
    if queue:
        cellules = cellules[:-1]
    return cellules, tete, queue


def tableaux(lignes):
    """Chaque tableau du document : (ligne de délimitation, forme déclarée, lignes de corps).

    Un tableau est reconnu à sa DÉCLARATION — une ligne de délimitation dont l'en-tête qui la précède
    porte le même nombre de cellules qu'elle. Cette égalité est la condition que GFM lui-même impose :
    sans elle, ce n'est pas un tableau, et une ligne de tirets isolée n'en déclare aucun.
    """
    # Le balayage part de la PREMIÈRE ligne — une clôture de bloc de code posée en tête doit être vue,
    # sans quoi tout un échantillon serait lu comme un tableau du document — mais une délimitation n'est
    # reconnue qu'à partir de la seconde, puisqu'elle exige un en-tête qui la précède.
    out, i, dans_code = [], 0, False
    while i < len(lignes):
        if CLOTURE.match(lignes[i]):
            dans_code = not dans_code
            i += 1
            continue
        if i == 0 or dans_code or "|" not in lignes[i] or not DELIMITATION.match(lignes[i]):
            i += 1
            continue
        entete = lignes[i - 1]
        if not entete.strip() or "|" not in entete:
            i += 1
            continue
        cd, td, qd = forme(lignes[i])
        ce, _, _ = forme(entete)
        if len(cd) != len(ce):
            i += 1
            continue
        corps, j = [], i + 1
        while j < len(lignes) and lignes[j].strip() and not AUTRE_BLOC.match(lignes[j]) and not CLOTURE.match(lignes[j]):
            corps.append((j + 1, lignes[j]))
            j += 1
        out.append((i + 1, (len(cd), td, qd), corps))
        i = j
    return out


def fautes_du_document(lignes):
    """[(numéro, motif)] pour ce document. Vide = toutes ses lignes portent la forme déclarée."""
    out = []
    for _n_delim, (n_col, tete_d, queue_d), corps in tableaux(lignes):
        for n, ligne in corps:
            cellules, tete, queue = forme(ligne)
            if len(cellules) > n_col:
                perdu = "|".join(cellules[n_col:])
                out.append((n, f"{len(cellules)} cellules là où le tableau en déclare {n_col} : le rendu "
                               f"IGNORE l'excédent — {len(perdu)} caractère(s) de cette ligne n'atteignent "
                               f"pas la page, et tout ce qui suit la colonne {n_col} est décalé. Presque "
                               f"toujours une barre verticale écrite dans le texte : échappez-la « \\| » "
                               f"(les accents graves ne la protègent pas)"))
            elif len(cellules) < n_col:
                out.append((n, f"{len(cellules)} cellules là où le tableau en déclare {n_col} : le rendu "
                               f"complète par des cellules VIDES, et la ligne ne dit plus ce qu'elle "
                               f"prétend dire"))
            elif queue != queue_d or tete != tete_d:
                manquantes = " et ".join(
                    m for m, present, attendu in (("de tête", tete, tete_d), ("de queue", queue, queue_d))
                    if present != attendu)
                out.append((n, f"barre {manquantes} : la ligne ne se ferme pas comme son tableau le "
                               f"déclare. Le rendu est le même — c'est pour cela que ce défaut vit "
                               f"longtemps — mais tout outil qui traite ce document s'y casse, et c'est "
                               f"ainsi qu'il s'est vu"))
    return out


# ─────────────────────────────────────────────────────────────────────────────────────────────
# L'INSTRUMENT SE VALIDE — TÉMOIN POSITIF ET TÉMOIN NÉGATIF, AVANT TOUT VERDICT
# ─────────────────────────────────────────────────────────────────────────────────────────────
# Chaque cas est (nom, document, lignes attendues en faute). Le corpus est fabriqué : il porte des
# formes que l'arbre réel ne contient pas aujourd'hui, pour que la garde tienne aussi celles-là.
CORPUS = [
    # ── CE QUE LA GARDE DOIT REFUSER, EN NOMMANT LA LIGNE ──────────────────────────────────────
    ("barre de queue manquante — le défaut de `P8.9-d`",
     ["| Clé | État |", "|---|---|", "| `P1.1-a` | ✅ |", "| `P1.1-b` | ✅"], [4]),
    ("barre de tête manquante",
     ["| Clé | État |", "|---|---|", "`P1.1-a` | ✅ |"], [3]),
    ("une cellule de trop — une barre écrite dans le texte",
     ["| Clé | Constat |", "|---|---|", "| `P1.1-a` | `metric x | stats max(value)` mesuré |"], [3]),
    ("une cellule de trop — une barre dans de la prose",
     ["| Clé | Constat |", "|---|---|", "| `P1.1-a` | un ET | OU mal placé |"], [3]),
    ("une cellule de moins",
     ["| Clé | État | Constat |", "|---|---|---|", "| `P1.1-a` | ✅ |"], [3]),
    ("deux lignes fautives dans le même tableau, chacune nommée",
     ["| A | B |", "|---|---|", "| 1 | 2", "| 3 | 4 |", "| 5 | 6 | 7 |"], [3, 5]),
    ("un tableau à cinq colonnes — le nombre est DÉRIVÉ, jamais écrit dans la garde",
     ["| a | b | c | d | e |", "|---|---|---|---|---|", "| 1 | 2 | 3 | 4 |"], [3]),
    ("un tableau SANS barres de bord dont une ligne en porte une",
     ["a | b", "---|---", "1 | 2", "| 3 | 4"], [4]),
    # ── CE QUE LA GARDE NE DOIT PAS REFUSER ────────────────────────────────────────────────────
    ("un tableau bien formé",
     ["| Clé | État |", "|---|---|", "| `P1.1-a` | ✅ |", "| `P1.1-b` | ⬜ |"], []),
    ("une barre ÉCHAPPÉE est du contenu, pas une cellule — la convention du dépôt",
     ["| Clé | Constat |", "|---|---|", "| `P1.1-a` | `metric x \\| stats max(value)` mesuré |"], []),
    ("un tableau SANS barres de bord, tenu à sa propre forme",
     ["a | b", "---|---", "1 | 2", "3 | 4"], []),
    ("un tableau avec alignement déclaré",
     ["| a | b | c |", "|:---|:---:|---:|", "| 1 | 2 | 3 |"], []),
    ("de la prose qui contient une barre, hors de tout tableau",
     ["Un pipeline s'écrit `search x | stats count`.", "", "Et rien d'autre."], []),
    ("un tableau MONTRÉ dans un bloc de code : un échantillon, pas un tableau du document",
     ["```", "| a | b |", "|---|---|", "| 1 | 2", "```"], []),
    ("une ligne de tirets isolée ne déclare aucun tableau",
     ["Un titre", "---", "du texte | avec une barre"], []),
    ("le corps s'arrête à la ligne vide : la prose qui suit n'est pas une ligne de tableau",
     ["| a | b |", "|---|---|", "| 1 | 2 |", "", "Une phrase | avec une barre."], []),
    ("le corps s'arrête au bloc suivant",
     ["| a | b |", "|---|---|", "| 1 | 2 |", "## Titre | pas une ligne"], []),
    ("une coupure thématique COLLÉE à la dernière ligne ferme le tableau — un rendu réel la donne "
     "pour `<hr>`, jamais pour une rangée à une cellule (deux de ces coupures existent dans l'index)",
     ["| a | b |", "|---|---|", "| 1 | 2 |", "---", "", "## Titre"], []),
]


def valider_instrument():
    ecarts = []
    for nom, lignes, attendu in CORPUS:
        obtenu = sorted(n for n, _ in fautes_du_document(lignes))
        if obtenu != sorted(attendu):
            ecarts.append(f"    « {nom} » : lignes attendues en faute {sorted(attendu)}, obtenues {obtenu}")
    return ecarts


def documents_markdown(racine):
    """Les documents Markdown PUBLIÉS OU EN PASSE DE L'ÊTRE — suivis, plus ce que rien n'ignore."""
    lu = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                        cwd=racine, capture_output=True, text=True)
    if lu.returncode:
        return None
    return sorted({f for f in lu.stdout.split("\n") if f.lower().endswith(".md")})


def main():
    racine = racine_designee()

    ecarts = valider_instrument()
    if ecarts:
        print("::error::l'INSTRUMENT NE SE RECONNAÎT PLUS LUI-MÊME. Le corpus de contrôle de cette garde, "
              "qui porte ses deux témoins, ne rend plus le verdict attendu. Aucun verdict n'est rendu sur "
              "l'arbre : un découpeur qui ne sait plus lire un tableau rendrait vert en n'ayant rien mesuré.")
        for e in ecarts:
            print(e, file=sys.stderr)
        return 2

    fichiers = documents_markdown(racine)
    if fichiers is None:
        print(f"::error::racine « {racine} » : `git ls-files` échoue, il n'y a pas d'arbre à lire — donc "
              f"pas de corpus. Aucun verdict n'est rendu.")
        return 2

    documents, n_tableaux, n_lignes, fautes = 0, 0, 0, []
    for f in fichiers:
        chemin = os.path.join(racine, f)
        if not os.path.isfile(chemin):
            continue
        try:
            with open(chemin, encoding="utf-8") as fh:
                lignes = fh.read().split("\n")
        except (OSError, UnicodeDecodeError) as e:
            print(f"::error::{f} : illisible ou non décodable en UTF-8 ({e}) — le dépouillement est "
                  f"incomplet, aucun verdict n'est rendu.")
            return 2
        tabs = tableaux(lignes)
        if not tabs:
            continue
        documents += 1
        n_tableaux += len(tabs)
        n_lignes += sum(len(corps) for _, _, corps in tabs)
        fautes.extend((f, n, motif) for n, motif in fautes_du_document(lignes))

    for cle, valeur, mini in (("documents à tableau", documents, MIN_DOCUMENTS),
                              ("tableaux", n_tableaux, MIN_TABLEAUX),
                              ("lignes de corps", n_lignes, MIN_LIGNES)):
        if valeur < mini:
            print(f"::error::seulement {valeur} {cle} reconnu(s), plancher {mini} : les témoins passent "
                  f"mais l'arbre réel n'est plus reconnu — soit le découpeur est cassé (cette garde ne "
                  f"vérifierait alors RIEN), soit l'arbre a vraiment changé de forme ; dans ce cas "
                  f"abaissez le plancher en écrivant la raison à côté.")
            return 2

    if fautes:
        for f, n, motif in fautes:
            print(f"::error file={f},line={n}::{motif}")
        print(f"\n{len(fautes)} ligne(s) de tableau ne portent pas la forme que l'en-tête de leur tableau "
              f"DÉCLARE, sur {n_lignes} lignes de corps réparties dans {n_tableaux} tableaux de "
              f"{documents} documents. Une ligne de tableau se répare là où elle est écrite : échappez la "
              f"barre qui traîne dans le texte (« \\| »), ou rendez à la ligne les cellules et les barres "
              f"de bord que sa ligne de délimitation annonce. Aucune autre garde de ce dépôt ne voit ce "
              f"défaut : les trois qui lisent le même index lisent le TEXTE des cellules, pas la forme.")
        return 1

    print(f"check_every_table_row_carries_the_shape_its_header_declares : {n_lignes} lignes de corps dans "
          f"{n_tableaux} tableaux de {documents} documents Markdown ; chacune porte le nombre de cellules "
          f"et les barres de bord que la ligne de délimitation de son tableau déclare. Forme seulement : "
          f"le TEXTE des cellules est tenu ailleurs ; les tableaux montrés dans un bloc de code sont des "
          f"échantillons et ne sont pas jugés.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
