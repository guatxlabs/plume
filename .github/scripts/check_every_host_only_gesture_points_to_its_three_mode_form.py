#!/usr/bin/env python3
"""`P9.6-b` — UN GESTE QUI N'A DE SENS QUE SUR L'HÔTE NATIF RENVOIE À SA FORME DANS LES TROIS MODES.

CE QUI ÉTAIT MESURÉ (2026-08-24, re-mesuré le 2026-09-09). Le document d'accueil invoque les installateurs
(`bootstrap.sh`, `bootstrap-agent.sh`) pour poser ou changer un réglage, ajouter un collecteur, créer un
jeton. Sur un hôte natif le geste a un sens ; en conteneur ou en cluster il n'en a AUCUN (image immuable,
pod remplacé). La page `docs/TROIS-MODES.md` porte chaque geste en trois colonnes et nomme ceux qui
n'existent pas — mais rien ne liait un site du README à cette page : cinq invocations sur cinq en étaient
à plus de douze lignes, et un lecteur en conteneur lisait une commande sans sens chez lui.

LA POPULATION EST DÉRIVÉE DE LA FORME DE LA COMMANDE, pas de la prose : toute ligne du README qui invoque
`bash bootstrap.sh` ou `bash bootstrap-agent.sh` (bloc de code ou citation). Le critère est LOCAL : un lien
vers `docs/TROIS-MODES.md` à au plus FENETRE lignes, citant un numéro de section (`§3.3`) qui EXISTE dans la
page — dérivé de ses titres, jamais recopié. Plafond ZÉRO.

Sortie 0 = chaque invocation renvoie ; 1 = une invocation orpheline ou un renvoi vers une section absente ;
2 = refus de conclure (corpus illisible, aucune invocation, page sans sections).
"""
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, os.pardir, os.pardir))
README = "README.md"
PAGE = "docs/TROIS-MODES.md"
FENETRE = 12
MIN_INVOCATIONS = 3
MIN_SECTIONS = 5

INVOCATION = re.compile(r"\bbash bootstrap(?:-agent)?\.sh\b")
RENVOI = re.compile(r"docs/TROIS-MODES\.md(?:#[^)\s]*)?\)?[^\n]*?§\s*([0-9]+(?:\.[0-9]+)?)|§\s*([0-9]+(?:\.[0-9]+)?)[^\n]*?docs/TROIS-MODES\.md")
SECTION = re.compile(r"^#{2,3}\s+([0-9]+(?:\.[0-9]+)?)\b")


def sections(page_texte):
    return {m.group(1) for l in page_texte.split("\n") for m in [SECTION.match(l)] if m}


def fautes(readme_lignes, sections_connues):
    """[(numéro, motif)] ; [] quand chaque invocation renvoie vers une section existante."""
    out = []
    for i, l in enumerate(readme_lignes):
        if not INVOCATION.search(l):
            continue
        debut, fin = max(0, i - FENETRE), min(len(readme_lignes), i + FENETRE + 1)
        cibles = []
        for v in readme_lignes[debut:fin]:
            for m in RENVOI.finditer(v):
                cibles.append(m.group(1) or m.group(2))
        if not cibles:
            out.append((i + 1, f"invocation d'un installateur sans renvoi vers {PAGE} à moins de {FENETRE} lignes : "
                               f"en conteneur ou en cluster ce geste n'a pas cette forme, et le lecteur ne le sait pas"))
        elif not all(c in sections_connues for c in cibles):
            absentes = sorted(c for c in cibles if c not in sections_connues)
            out.append((i + 1, f"renvoi vers des sections que {PAGE} ne porte pas : §{', §'.join(absentes)}"))
    return out


def valider_instrument():
    ecarts = []
    page = "## 1. Un\n### 3.2 Réglage\n### 3.3 Source\n"
    secs = sections(page)
    if secs != {"1", "3.2", "3.3"}:
        ecarts.append(f"sections dérivées {sorted(secs)} au lieu de 1, 3.2, 3.3")
    def cas(nom, lignes, attendu):
        obtenu = [n for n, _ in fautes(lignes, secs)]
        if obtenu != attendu:
            ecarts.append(f"« {nom} » : lignes attendues {attendu}, obtenues {obtenu}")
    cas("orpheline", ["```sh", "sudo bash bootstrap-agent.sh", "```"], [2])
    cas("renvoi proche", ["```sh", "sudo bash bootstrap-agent.sh", "```", "", "> En conteneur : voir [docs/TROIS-MODES.md §3.3](docs/TROIS-MODES.md)."], [])
    cas("renvoi en tête", ["> ce geste : [§3.2 de docs/TROIS-MODES.md](docs/TROIS-MODES.md)", "```sh", "sudo env X=1 bash bootstrap.sh", "```"], [])
    cas("renvoi trop loin", ["> voir [docs/TROIS-MODES.md §3.3](docs/TROIS-MODES.md)"] + [""] * 13 + ["sudo bash bootstrap.sh"], [15])
    cas("section absente", ["sudo bash bootstrap.sh", "> voir [docs/TROIS-MODES.md §9.9](docs/TROIS-MODES.md)"], [1])
    cas("pas une invocation", ["`bootstrap-agent.sh` n'installe que trois collecteurs", "bootstrap.sh refuse de continuer"], [])
    return ecarts


def main():
    ecarts = valider_instrument()
    if ecarts:
        print("::error::l'INSTRUMENT NE SE RECONNAÎT PLUS LUI-MÊME — aucun verdict sur l'arbre :")
        for e in ecarts:
            print("  " + e, file=sys.stderr)
        return 2
    try:
        readme = open(os.path.join(RACINE, README), encoding="utf-8").read().split("\n")
        page = open(os.path.join(RACINE, PAGE), encoding="utf-8").read()
    except OSError as e:
        print(f"::error::corpus illisible ({e}) : aucun verdict.")
        return 2
    secs = sections(page)
    invocations = sum(1 for l in readme if INVOCATION.search(l))
    if invocations < MIN_INVOCATIONS or len(secs) < MIN_SECTIONS:
        print(f"::error::{invocations} invocation(s) dans {README} (plancher {MIN_INVOCATIONS}), {len(secs)} section(s) dans {PAGE} "
              f"(plancher {MIN_SECTIONS}) : le corpus n'est plus reconnu, aucun verdict.")
        return 2
    f = fautes(readme, secs)
    if f:
        for n, motif in f:
            print(f"::error file={README},line={n}::{motif}")
        print(f"\n{len(f)} invocation(s) d'installateur sur {invocations} ne renvoient pas à leur forme dans les trois modes "
              f"({PAGE}). Ajoutez à côté : « En conteneur ou en cluster, ce geste n'a pas cette forme : voir "
              f"[docs/TROIS-MODES.md §3.x](docs/TROIS-MODES.md) », avec le numéro de la section qui le porte.")
        return 1
    print(f"check_every_host_only_gesture_points_to_its_three_mode_form : {invocations} invocation(s) d'installateur dans "
          f"{README}, chacune renvoie à une section existante de {PAGE} ({len(secs)} sections dérivées) à moins de {FENETRE} lignes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
