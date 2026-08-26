#!/usr/bin/env python3
"""Une clé citée par le code mais absente de l'index désigne un travail que rien ne suit.

Mesuré le 2026-08-26 : trois clés étaient citées dans des modules de la console, dans une garde et
dans un document publié — l'une avec un cliquet posé à son nom — sans exister nulle part dans la
feuille de route. Le contrôle des restes ne lit que l'index : il ne pouvait pas les voir. Un lecteur
qui rencontre la clé dans le code la cherche dans l'index et ne trouve rien ; le travail qu'elle
désigne n'est ni ouvert, ni fermé, ni compté.

Le sens de lecture n'est pas symétrique, et c'est voulu : une clé DÉFINIE que nul ne cite est
ordinaire (la plupart des clés fermées ne sont citées nulle part). C'est la citation SANS définition
qui est une promesse sans registre.
"""
import os, re, subprocess, sys

RACINE = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
# Une citation de clé porte ses accents graves ou vit dans un commentaire : on exige la FORME exacte,
# bornée, pour ne pas ramasser une référence de version ou un identifiant qui lui ressemble.
CITATION = re.compile(r"(?<![0-9A-Za-z_.-])(P\d{1,2}\.\d{1,2}-[a-z])(?![0-9A-Za-z_-])")
DEFINITION = re.compile(r"^\| +\*\*(P\d{1,2}\.\d{1,2}-[a-z])\*\*", re.M)
# Les gardes de ce dépôt fabriquent des clés FACTICES dans leurs témoins internes. Elles se
# distinguent sans être énumérées : une clé factice porte un numéro de phase que l'index ne
# titre PAS. La borne vient donc de l'index — la même dérivation que la garde de placement —
# et non d'une liste de fichiers ou de fonctions à tenir à jour.
PHASE_TITREE = re.compile(r"^## +P(\d{1,2}) +— ", re.M)
LISIBLE = (".py", ".js", ".mjs", ".rs", ".sh", ".yml", ".yaml", ".md", ".css", ".html", ".ps1", ".toml")
INDEX = os.path.join("docs", "ROADMAP.md")


def corpus():
    """Fichiers suivis PLUS fichiers neufs non ignorés : une clé citée dans un fichier pas encore
    suivi est déjà une citation, et c'est le moment où l'oubli se produit."""
    out = []
    for args in (["git", "ls-files"], ["git", "ls-files", "--others", "--exclude-standard"]):
        try:
            r = subprocess.run(args, cwd=RACINE, capture_output=True, text=True, check=True)
        except Exception:
            return None
        out += [f for f in r.stdout.split("\n") if f.strip()]
    return sorted({f for f in out if f.endswith(LISIBLE)})


def epreuves():
    cas = [
        ("citation nue", "voir P1.1-h ici", ["P1.1-h"]),
        ("citation entre accents graves", "voir `P1.1-h` ici", ["P1.1-h"]),
        ("clé collée à un mot", "xP1.1-h", []),
        ("suffixe qui prolonge", "P1.1-had", []),
        ("numéro de version", "v1.2-a", []),
        ("deux chiffres de phase", "P11.13-h et P2.4-q", ["P11.13-h", "P2.4-q"]),
        ("point de version proche", "0.11.1-a", []),
    ]
    for nom, texte, attendu in cas:
        vu = CITATION.findall(texte)
        if vu != attendu:
            return f"témoin « {nom} » : {vu}, attendu {attendu}"
    if DEFINITION.findall("| **P1.1-a** | x |") != ["P1.1-a"]:
        return "témoin de définition : une ligne d'index n'est pas reconnue"
    if DEFINITION.findall("voir **P1.1-a** dans le texte"):
        return "témoin de définition : une mention en prose est prise pour une définition"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    fichiers = corpus()
    if not fichiers:
        print("::error::corpus illisible : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    chemin_index = os.path.join(RACINE, INDEX)
    try:
        texte_index = open(chemin_index, encoding="utf-8").read()
    except OSError as e:
        print(f"::error::index illisible ({e}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    definies = set(DEFINITION.findall(texte_index))
    phases = set(PHASE_TITREE.findall(texte_index))
    if not phases:
        print("::error::aucune phase titrée dans l'index : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if not definies:
        print("::error::aucune clé définie dans l'index : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    orphelines = {}
    for f in fichiers:
        if f == INDEX:
            continue
        try:
            texte = open(os.path.join(RACINE, f), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for n, ligne in enumerate(texte.split("\n"), 1):
            for cle in CITATION.findall(ligne):
                if cle.split(".")[0][1:] not in phases:
                    continue  # phase non titrée -> clé fabriquée par un témoin, pas une citation
                if cle not in definies:
                    orphelines.setdefault(cle, []).append((f, n))

    for cle in sorted(orphelines):
        f, n = orphelines[cle][0]
        autres = len(orphelines[cle]) - 1
        suite = f" (et {autres} autre(s) citation(s))" if autres else ""
        print(f"::error file={f},line={n}::`{cle}` est citée ici{suite} mais n'existe pas dans "
              f"{INDEX} — le travail qu'elle désigne n'est ni ouvert, ni fermé, ni compté", file=sys.stderr)

    if orphelines:
        total = sum(len(v) for v in orphelines.values())
        print(f"\n{len(orphelines)} clé(s) citée(s) {total} fois sans exister dans l'index. Ouvrir la "
              "clé, ou retirer la citation — une clé qui vit dans le code et pas dans l'index est une "
              "promesse sans registre, et le contrôle des restes ne peut pas la voir.", file=sys.stderr)
        return 1

    print(f"check_every_key_cited_in_the_code_exists_in_the_index : {len(fichiers)} fichier(s) lus, "
          f"{len(definies)} clé(s) définies dans l'index ; toute clé citée ailleurs y est définie. Le "
          "corpus comprend les fichiers NEUFS non encore suivis, parce que c'est là que l'oubli se "
          "produit.\n"
          "CE QU'ELLE NE TIENT PAS, et le sens de lecture est délibéré : une clé DÉFINIE que nul ne "
          "cite n'est pas signalée — la plupart des clés fermées ne sont citées nulle part. Elle ne "
          "juge ni l'ÉTAT d'une clé, ni la VÉRITÉ de ce que la citation en dit, ni qu'une citation "
          "désigne le bon constat. Et une clé dont le numéro de PHASE n'est pas titré dans l'index "
          "est tenue pour fabriquée par un témoin : c'est ainsi que les clés factices des gardes "
          "sortent du corpus sans qu'aucune liste de fichiers soit tenue à jour — mais un témoin qui "
          "emploierait une phase EXISTANTE serait, lui, signalé.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
