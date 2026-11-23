#!/usr/bin/env python3
"""Un compte de règles publié dans la documentation est le compte des règles livrées.

LE DÉFAUT, CONSTATÉ SUR L'ARBRE. La page d'accueil annonçait « 3 règles d'exemple » dans
`config.d/sigma/` quand l'arbre en suivait 4, et `docs/DETECTION-CATALOG.md` annonçait 35 règles de
catalogue quand `config.d/rules/catalog/` en suivait 37. Les deux chiffres avaient été justes un jour ;
rien ne les reliait à l'arbre, donc rien n'a rougi quand des règles ont été ajoutées. Le premier avait
un effet de plus : c'était le SEUL compte de détection de la page d'accueil, et un lecteur pressé en
concluait que Plume livrait trois règles.

LA GARDE. Chaque phrase de la table `ANNONCES` porte un nombre ; la garde relit ce nombre et le compare
au compte DÉRIVÉ de l'arbre suivi (`git ls-files`, donc ni artefact ni fichier local non suivi). Le
compte n'est écrit qu'à un endroit — la phrase publiée — et c'est cet endroit qui est jugé.

CODES DE SORTIE. `0` tous les comptes concordent ; `1` un compte publié diffère de l'arbre ; `2` rien n'a
été mesuré : épreuve interne en échec, `git ls-files` illisible, ou phrase introuvable (ou trouvée
plusieurs fois). Une phrase introuvable n'est pas un compte juste : si la phrase est reformulée, son
motif se met à jour ici, dans le même changement.

CE QU'ELLE NE TIENT PAS. Les règles semées par le binaire (`daemon/src/seeds.rs`) ne sont pas comptées :
aucune phrase publiée n'en donne le nombre, et ce n'est pas un compte de fichiers. Les autres comptes du
catalogue (techniques, tactiques, règles décrites) ne sont pas jugés ici.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))


def suivis(racine: str) -> list[str] | None:
    try:
        sortie = subprocess.run(["git", "-C", racine, "ls-files", "-z"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p.decode("utf-8", "surrogateescape") for p in sortie.split(b"\0") if p]


def sigma_exemples(fichiers, lire):
    return sum(1 for f in fichiers if f.startswith("config.d/sigma/") and f.endswith((".yml", ".yaml", ".json")))


def catalogue(fichiers, lire):
    return sum(1 for f in fichiers if f.startswith("config.d/rules/catalog/") and f.endswith(".json"))


def overlays_racine(fichiers, lire):
    return [f for f in fichiers if re.fullmatch(r"config\.d/rules/[^/]+\.json", f)]


def overlays_racine_compte(fichiers, lire):
    return len(overlays_racine(fichiers, lire))


def overlays_racine_actives(fichiers, lire):
    n = 0
    for f in overlays_racine(fichiers, lire):
        if json.loads(lire(f)).get("enabled") is True:
            n += 1
    return n


# (fichier publié, motif à UN groupe qui capture le nombre, compte dérivé de l'arbre, ce que c'est)
ANNONCES = [
    ("README.md", r"\*\*(\d+) règles Sigma d'exemple\*\*", sigma_exemples, "règles Sigma d'exemple (config.d/sigma/)"),
    ("README.md", r"\*\*(\d+) règles de catalogue\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
    ("README.md", r"\*\*(\d+) règles overlay\*\*", overlays_racine_compte, "règles overlay à la racine de config.d/rules/"),
    ("README.md", r"\*\*dont (\d+) actives\*\*", overlays_racine_actives, "règles overlay racine à enabled=true"),
    ("docs/DETECTION-CATALOG.md", r"\*\*(\d+) règles LIVRÉES\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
]


def juger(annonces, fichiers, lire):
    """Rend (desaccords, introuvables). Pur : le disque n'est lu qu'à travers `lire`."""
    desaccords, introuvables = [], []
    for publie, motif, compter, quoi in annonces:
        trouves = re.findall(motif, lire(publie))
        if len(trouves) != 1:
            introuvables.append(f"{publie} : motif {motif!r} trouvé {len(trouves)} fois (attendu : 1)")
            continue
        annonce, reel = int(trouves[0]), compter(fichiers, lire)
        if annonce != reel:
            desaccords.append(f"{publie} annonce {annonce} {quoi}, l'arbre suivi en porte {reel}")
    return desaccords, introuvables


def epreuves() -> list[str]:
    """Témoins positifs et négatifs, hors du disque."""
    fichiers = ["README.md", "config.d/sigma/a.yml", "config.d/sigma/b.yml",
                "config.d/rules/x.json", "config.d/rules/y.json", "config.d/rules/catalog/c.json"]
    contenus = {"config.d/rules/x.json": '{"enabled": true}', "config.d/rules/y.json": '{"enabled": false}',
                "config.d/rules/catalog/c.json": '{"enabled": true}'}
    annonces = [("README.md", r"\*\*(\d+) règles Sigma d'exemple\*\*", sigma_exemples, "s"),
                ("README.md", r"\*\*(\d+) règles overlay\*\*", overlays_racine_compte, "o"),
                ("README.md", r"\*\*dont (\d+) actives\*\*", overlays_racine_actives, "a")]
    cas = [
        ("concordant", "**2 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 0, 0),
        ("compte périmé", "**3 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 1, 0),
        ("catalogue hors racine", "**2 règles Sigma d'exemple** **3 règles overlay** **dont 2 actives**", 2, 0),
        ("phrase disparue", "**2 règles Sigma d'exemple** **dont 1 actives**", 0, 1),
        ("phrase en double", "**2 règles Sigma d'exemple** **2 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 0, 1),
    ]
    echecs = []
    for nom, readme, att_d, att_i in cas:
        lire = lambda f, r=readme: r if f == "README.md" else contenus[f]
        d, i = juger(annonces, fichiers, lire)
        if (len(d), len(i)) != (att_d, att_i):
            echecs.append(f"épreuve « {nom} » : {len(d)} désaccord(s), {len(i)} introuvable(s) ; attendu {att_d}, {att_i}")
    return echecs


def main() -> int:
    echecs = epreuves()
    if echecs:
        print("[comptes-de-regles] REFUSE DE CONCLURE — épreuve interne en échec :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    fichiers = suivis(RACINE)
    if not fichiers:
        print("[comptes-de-regles] REFUSE DE CONCLURE — `git ls-files` n'a rien rendu.")
        return 2

    def lire(chemin):
        with open(os.path.join(RACINE, chemin), encoding="utf-8") as fh:
            return fh.read()

    try:
        desaccords, introuvables = juger(ANNONCES, fichiers, lire)
    except (OSError, ValueError) as e:
        print(f"[comptes-de-regles] REFUSE DE CONCLURE — lecture impossible : {e}")
        return 2
    if introuvables:
        print("[comptes-de-regles] REFUSE DE CONCLURE — phrase publiée introuvable ; mettre son motif à jour ici :")
        for e in introuvables:
            print(f"    - {e}")
        return 2
    if desaccords:
        print("[comptes-de-regles] ÉCHEC — un compte publié n'est plus celui de l'arbre :")
        for e in desaccords:
            print(f"    - {e}")
        return 1
    print(f"[comptes-de-regles] OK — {len(ANNONCES)} comptes publiés, tous égaux au compte de l'arbre suivi")
    return 0


if __name__ == "__main__":
    sys.exit(main())
