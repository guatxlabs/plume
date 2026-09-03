#!/usr/bin/env python3
"""`P8.9-n` — L'IDENTITÉ CANONIQUE A UNE SEULE SOURCE, ET C'EST VÉRIFIABLE.

CE QUI A ÉTÉ MESURÉ LE 2026-09-03. Deux fichiers affirmaient CHACUN être l'endroit unique où vit
l'identité canonique de publication : le script de vérification (« ECRITE UNE SEULE FOIS ») et le
crochet de pré-commit (« son canonique vit donc ici, à un seul endroit »). Le second APPELLE le
premier dès sa ligne 3. La phrase était donc fausse aux deux endroits, et elle était écrite là où
elle aurait dû être garantie.

ET LA DUPLICATION ÉTAIT PORTEUSE, ce qui interdisait de la supprimer sans regarder : la copie du
crochet lisait l'identité EFFECTIVE, le script ne lisait que la CONFIGURATION. Avec
`GIT_AUTHOR_NAME` posé dans l'environnement, la config reste canonique et le script ACCEPTAIT un
commit qui serait parti sous un autre nom. Le contrôle fort a rejoint le canonique ; c'est cette
garde qui empêche la copie de repousser.

LA PROPRIÉTÉ TENUE, ET SES DEUX MOITIÉS :
  1. UNE SEULE SOURCE QUI DÉCIDE. Un seul fichier exécutable AFFECTE le canonique ; les autres le
     LISENT ou l'appellent. Une seconde affectation est refusée, où qu'elle soit.
  2. AUCUNE MENTION DIVERGENTE. Les documents ont parfaitement le droit de CITER l'identité — c'est
     leur rôle. Ce qu'ils n'ont pas le droit d'être, c'est FAUX. Toute chaîne de la forme
     `nom <adresse>` portant le domaine du canonique doit lui être IDENTIQUE.

CE QUE CETTE GARDE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
  - elle ne lit que l'arbre SUIVI de CE dépôt ; une copie vivant dans un autre dépôt lui échappe ;
  - elle apparie sur le DOMAINE du canonique : une identité écrite sous un tout autre domaine n'est
    pas une divergence à ses yeux, c'est une autre identité, et elle ne juge pas ça ;
  - elle ne prouve pas que la source unique est APPELÉE — c'est le rôle du crochet et de la CI.

Sorties : 0 = une seule source, aucune divergence · 1 = REFUS nommé · 2 = REFUS DE CONCLURE.
"""
import re
import subprocess
import sys
from pathlib import Path

SOURCE = Path(".github/scripts/verifier-identite.sh")


def canonique_depuis(texte: str):
    """Le canonique, LU dans la source — jamais recopié ici. `None` si la source ne le porte pas."""
    nom = re.search(r'^CANONIQUE_NOM="([^"]+)"', texte, re.M)
    mel = re.search(r'^CANONIQUE_MEL="([^"]+)"', texte, re.M)
    return (nom.group(1), mel.group(1)) if nom and mel else None


def sites_qui_affectent(textes: dict) -> list:
    """Les fichiers qui AFFECTENT un canonique d'identité (ils décident), par opposition à ceux qui
    le citent. Dérivé de la forme d'affectation, pas d'une liste de noms de fichiers."""
    motif = re.compile(r'^\s*(?:export\s+)?CANONIQUE(?:_NOM|_MEL)?\s*=', re.M)
    return sorted(f for f, t in textes.items() if motif.search(t))


def mentions_divergentes(textes: dict, nom: str, mel: str) -> list:
    """Toute identité `x <y@domaine-du-canonique>` qui n'est pas EXACTEMENT le canonique."""
    domaine = re.escape(mel.split("@", 1)[1])
    forme = re.compile(r'([^\s<>`"\']+(?:[ \t][^\s<>`"\']+)*)\s*<([^<>@\s]+@' + domaine + r')>')
    attendu = (nom, mel)
    out = []
    for f, t in textes.items():
        for i, ligne in enumerate(t.split("\n"), 1):
            for m in forme.finditer(ligne):
                if (m.group(1).strip(), m.group(2)) != attendu:
                    out.append(f"{f}:{i} — `{m.group(0).strip()}` diverge du canonique `{nom} <{mel}>`")
    return out


def valider_linstrument() -> list:
    """L'INSTRUMENT EST ÉPROUVÉ DANS LES DEUX SENS SUR DES CORPUS FABRIQUÉS. Sans cette moitié, une
    garde qui n'apparie plus rien serait verte pour toujours."""
    faux = []
    src = 'CANONIQUE_NOM="alpha"\nCANONIQUE_MEL="a@exemple.test"\n'
    c = canonique_depuis(src)
    if c != ("alpha", "a@exemple.test"):
        faux.append(f"lecture du canonique cassée : {c!r}")
    if canonique_depuis("rien du tout") is not None:
        faux.append("une source SANS canonique devrait rendre None")

    nom, mel = "alpha", "a@exemple.test"
    sain = {"doc.md": f"publie sous `{nom} <{mel}>`.", "autre.md": "aucune identité ici"}
    if mentions_divergentes(sain, nom, mel):
        faux.append("un corpus SAIN est accusé à tort")
    abime = {"doc.md": f"publie sous `beta <{mel}>`."}
    if not mentions_divergentes(abime, nom, mel):
        faux.append("un NOM divergent sur le même domaine n'est pas vu")
    autre_adresse = {"doc.md": f"publie sous `{nom} <bis@exemple.test>`."}
    if not mentions_divergentes(autre_adresse, nom, mel):
        faux.append("une ADRESSE divergente sur le même domaine n'est pas vue")
    hors_domaine = {"doc.md": "contact `quelquun <x@ailleurs.invalid>`."}
    if mentions_divergentes(hors_domaine, nom, mel):
        faux.append("une identité d'un AUTRE domaine ne doit pas être jugée ici")

    if sites_qui_affectent({"a.sh": 'CANONIQUE_NOM="x"'}) != ["a.sh"]:
        faux.append("une affectation n'est pas reconnue")
    if sites_qui_affectent({"a.md": "le canonique est `x <y@z>`"}) != []:
        faux.append("une simple MENTION est comptée comme une affectation")
    if len(sites_qui_affectent({"a.sh": 'CANONIQUE="x"', "b.sh": 'export CANONIQUE_MEL="y"'})) != 2:
        faux.append("une seconde affectation, même exportée, n'est pas vue")
    return faux


def main() -> int:
    faux = valider_linstrument()
    if faux:
        for f in faux:
            print(f"::error::instrument invalide — {f}")
        print("\nLa garde ne peut pas conclure : elle ne se croit pas elle-même.")
        return 2

    if not SOURCE.exists():
        print(f"::error::{SOURCE} est introuvable — la source du canonique ne peut pas être lue.")
        return 2
    canon = canonique_depuis(SOURCE.read_text(encoding="utf-8"))
    if canon is None:
        print(f"::error::{SOURCE} ne porte plus de canonique lisible (CANONIQUE_NOM / CANONIQUE_MEL).")
        return 2
    nom, mel = canon

    try:
        suivis = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    except Exception as e:  # noqa: BLE001
        print(f"::error::l'arbre suivi n'est pas énumérable ({e}) — aucun verdict.")
        return 2

    textes = {}
    for f in suivis:
        p = Path(f)
        try:
            if p.is_file():
                textes[f] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

    defauts = []
    sources = sites_qui_affectent(textes)
    if sources != [str(SOURCE)]:
        for s in sources:
            if s != str(SOURCE):
                defauts.append(
                    f"::error::{s} AFFECTE un canonique d'identité. Il n'en existe qu'un, et il vit "
                    f"dans {SOURCE} : ce fichier doit l'APPELER ou le LIRE, pas s'en faire une copie."
                )
        if str(SOURCE) not in sources:
            defauts.append(f"::error::{SOURCE} n'affecte plus le canonique — la source unique a disparu.")

    for d in mentions_divergentes(textes, nom, mel):
        defauts.append(f"::error::{d}")

    if defauts:
        for d in defauts:
            print(d)
        print(
            f"\n{len(defauts)} divergence(s). Le canonique de publication vit dans {SOURCE} et NULLE "
            "PART ailleurs comme décision. Les documents peuvent le CITER — à l'identique."
        )
        return 1

    n_mentions = sum(
        1
        for f, t in textes.items()
        for _ in re.finditer(re.escape(f"{nom} <{mel}>"), t)
    )
    print(
        f"{len(textes)} fichiers suivis lus : UNE source qui décide ({SOURCE}), "
        f"{n_mentions} mention(s) du canonique, toutes identiques. Aucune copie divergente."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
