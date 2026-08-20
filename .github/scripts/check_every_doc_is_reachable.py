#!/usr/bin/env python3
"""Un document suivi doit être ATTEIGNABLE depuis la page d'accueil — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un document à jour que rien ne référence est invisible, et un document invisible n'existe pas
pour le lecteur, quelle que soit sa qualité. Mesuré sur cet arbre : **11 des 45 documents suivis**
n'étaient la cible d'aucun lien Markdown — parmi eux le document de conception qui portait l'état
le plus frais des travaux d'échelle, l'agent d'endpoint, le récepteur syslog, la détection mail et
le harnais de mesure. Aucun n'était brouillon : chacun était fini, exact, et introuvable autrement
qu'en listant le dépôt fichier par fichier.

CE N'EST PAS « ÊTRE CITÉ », C'EST « ÊTRE ATTEIGNABLE »
------------------------------------------------------
Le document d'échelle ÉTAIT nommé — en texte brut, dans la dernière phrase de la roadmap. Une
garde qui aurait accepté la simple MENTION serait passée au vert sur le défaut même qu'elle est
censée attraper. On exige donc un LIEN, et pas seulement un lien : un CHEMIN de liens depuis
`README.md`, la page que voit un arrivant. Un document lié uniquement par un autre document
lui-même orphelin reste invisible ; la fermeture transitive le dit, un simple compte de liens
entrants ne le dirait pas.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son motif
ne reconnaît plus rien. Les deux se ressemblent en CI. Avant tout verdict, cette garde exécute
donc un corpus de contrôle qui porte ses DEUX témoins : des formes de liens qu'elle DOIT
reconnaître (en ligne, avec ancre, avec titre, relatif `../`, style référence) et des formes
qu'elle NE DOIT PAS compter (mention entre accents graves, chemin nu, lien externe, cible qui
n'est pas un document suivi). Elle vérifie ensuite qu'elle trouve toujours un PLANCHER de liens
dans l'arbre réel : un motif qui passerait les témoins mais ne reconnaîtrait plus le corpus — un
reformatage de masse, une bascule vers une autre syntaxe — la ferait échouer au lieu de la faire
taire.

LES EXEMPTIONS NE SONT PAS UN CHOIX ÉDITORIAL
----------------------------------------------
Trois fichiers de la racine sont ouverts PAR LEUR NOM, par une plateforme ou par un outil, et pas
par un lien : la forge affiche le code de conduite et l'avis de tierces parties dans son interface,
et le fichier de règles d'agent est lu par nom. Les lier serait un artifice pour satisfaire une
garde. La liste est donc courte, elle vient de conventions EXTÉRIEURES au dépôt, et elle est
elle-même vérifiée : une exemption qui ne désigne plus un fichier suivi de la racine est une
erreur, pour qu'elle ne puisse pas devenir une trappe où l'on range ce qu'on ne veut pas indexer.
"""
import os
import re
import subprocess
import sys

# La page qu'un arrivant voit en premier. Tout document suivi doit s'atteindre depuis elle.
RACINE = "README.md"

# Plancher de découverte : en dessous, c'est la découverte qui est cassée, pas l'arbre qui a
# maigri — et une garde qui ne trouve aucun document rendrait vert en ne vérifiant rien.
# Relevé le 2026-08-20 : 45 documents suivis.
MIN_DOCS = 40

# Plancher de liens RÉSOLUS dans l'arbre réel. Relevé le 2026-08-20 : 72.
MIN_LIENS = 40

# Fichiers de la RACINE qu'une plateforme ou un outil ouvre par leur NOM, jamais par un lien.
# La raison est écrite à côté : une exemption sans raison est une exemption qu'on n'ose plus
# retirer.
EXEMPTES = {
    "CODE_OF_CONDUCT.md": "fichier de santé communautaire : la forge l'affiche dans son interface",
    "THIRD-PARTY-NOTICES.md": "avis de licences tierces : obligation de distribution, lu par nom",
    "AGENTS.md": "règles d'agent : lu par nom par les outils, avant toute navigation",
}

# `](cible)`, avec ou sans chevrons, avec ou sans titre entre guillemets.
LIEN = re.compile(r'\]\(\s*<?([^)>\s]+?)>?(?:\s+"[^"]*")?\s*\)')
# `[id]: cible`, définition de lien en style référence.
REFDEF = re.compile(r'^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?\s*$', re.M)


def cibles(texte, depuis, suivis):
    """Les documents SUIVIS que `texte` (situé en `depuis`) atteint par un lien Markdown."""
    base = os.path.dirname(depuis)
    out = set()
    for m in list(LIEN.finditer(texte)) + list(REFDEF.finditer(texte)):
        brut = m.group(1).split("#")[0].strip()
        if not brut or "://" in brut or brut.startswith("mailto:"):
            continue
        cible = os.path.normpath(os.path.join(base, brut))
        if cible in suivis and cible != depuis:
            out.add(cible)
    return out


def valider_instrument():
    """TÉMOIN POSITIF ET TÉMOIN NÉGATIF, sur un corpus de contrôle — avant tout verdict."""
    suivis = {"README.md", "docs/A.md", "docs/B.md", "autre/C.md"}
    doit_trouver = (
        "[a](A.md) "                      # en ligne, même répertoire
        "[b](B.md#une-ancre) "            # ancre : la cible reste le document
        '[b2](<B.md> "titre") '           # chevrons + titre
        "[c](../autre/C.md) "             # relatif remontant
        "[r][ref]\n\n[ref]: ../README.md\n"  # style référence
    )
    trouve = cibles(doit_trouver, "docs/index.md", suivis | {"docs/index.md"})
    attendu = {"docs/A.md", "docs/B.md", "autre/C.md", "README.md"}
    if trouve != attendu:
        return [f"témoin POSITIF en échec : attendu {sorted(attendu)}, obtenu {sorted(trouve)} — "
                "le motif de lien ne reconnaît plus les formes qu'il doit reconnaître."]

    ne_doit_pas_trouver = (
        "voir `docs/A.md` pour le détail, "      # mention entre accents graves
        "ou docs/B.md, "                          # chemin nu
        "[x](https://example.invalid/docs/A.md) " # lien externe qui finit en .md
        "[y](docs/INEXISTANT.md) "                # cible non suivie
        "[z](docs/A.txt)"                         # cible qui n'est pas un document
    )
    trouve = cibles(ne_doit_pas_trouver, "index.md", suivis | {"index.md"})
    if trouve:
        return [f"témoin NÉGATIF en échec : {sorted(trouve)} compté(s) comme lien alors qu'une "
                "MENTION n'est pas un lien — c'est exactement le défaut que cette garde attrape."]
    return []


def main():
    racine_depot = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                                  capture_output=True, text=True, check=True).stdout.strip()
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nl'INSTRUMENT est faux : aucun verdict n'est rendu (un vert l'aurait été pour de "
              "mauvaises raisons).")
        return 2

    docs = subprocess.run(["git", "ls-files", "*.md"], cwd=racine_depot,
                          capture_output=True, text=True, check=True).stdout.split()
    suivis = set(docs)

    if len(docs) < MIN_DOCS:
        print(f"::error::seulement {len(docs)} documents suivis découverts, plancher {MIN_DOCS} : "
              f"soit la découverte est cassée (cette garde ne vérifierait alors RIEN), soit des "
              f"documents ont légitimement disparu — dans ce cas baissez MIN_DOCS depuis votre "
              f"propre compte.")
        return 2

    if RACINE not in suivis:
        print(f"::error::`{RACINE}` n'est pas un document suivi : la racine d'atteignabilité "
              f"n'existe pas, la garde n'a plus de point de départ.")
        return 2

    liens = {}
    total = 0
    for d in docs:
        with open(os.path.join(racine_depot, d), encoding="utf-8", errors="replace") as fh:
            liens[d] = cibles(fh.read(), d, suivis)
        total += len(liens[d])

    if total < MIN_LIENS:
        print(f"::error::seulement {total} liens entre documents résolus, plancher {MIN_LIENS} : "
              f"les témoins passent mais l'arbre réel n'est plus reconnu (reformatage de masse, "
              f"autre syntaxe de lien). Corrigez l'extraction — ne baissez ce plancher que sur "
              f"votre propre compte.")
        return 2

    # Fermeture transitive depuis la page d'accueil.
    atteints = {RACINE}
    pile = [RACINE]
    while pile:
        cur = pile.pop()
        for t in liens[cur]:
            if t not in atteints:
                atteints.add(t)
                pile.append(t)

    for nom, raison in sorted(EXEMPTES.items()):
        if nom not in suivis:
            errs.append(f"exemption `{nom}` ({raison}) : ce fichier n'est pas suivi — une exemption "
                        f"qui ne désigne plus rien doit être RETIRÉE, pas gardée.")
        elif os.path.dirname(nom):
            errs.append(f"exemption `{nom}` : les exemptions ne valent QUE pour la racine du dépôt "
                        f"(conventions de plateforme). Un document de sous-répertoire s'indexe.")

    orphelins = [d for d in sorted(suivis - atteints) if d not in EXEMPTES]
    for d in orphelins:
        errs.append(
            f"{d} : document suivi INATTEIGNABLE depuis `{RACINE}` par un chemin de liens. "
            f"Ajoutez-lui une entrée dans l'index `docs/README.md` (ou un lien depuis un document "
            f"déjà atteignable). Une MENTION en texte brut ne compte pas : un lecteur ne peut pas "
            f"la suivre."
        )

    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n{len(orphelins)} document(s) suivi(s) sur {len(docs)} n'existent pas pour le "
              f"lecteur : rien ne mène à eux.")
        return 1

    print(f"{len(docs)} documents suivis, {total} liens : tous atteignables depuis `{RACINE}` "
          f"({len(EXEMPTES)} exemptions de convention, toutes à la racine et toutes suivies).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
