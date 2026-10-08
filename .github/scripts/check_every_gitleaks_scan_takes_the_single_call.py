#!/usr/bin/env python3
"""Tout scan gitleaks des flux passe par l'appel UNIQUE `$RUNNER_TEMP/gitleaks-detect.sh` (`P10.31-n`).

POURQUOI (mesuré par la vérification du correctif `P10.31-n`). Deux voies taisent un constat HORS de
la configuration `.gitleaks-ci.toml` : un commentaire `gitleaks:allow` sur la ligne d'un secret, et un
fichier `.gitleaksignore`. L'enveloppe `gitleaks-detect.sh`, écrite par le pas de configuration du
travail `security`, les ferme toutes deux (`--ignore-gitleaks-allow`, refus d'un `.gitleaksignore`).
Le témoin du scan joue ces deux voies, mais SUR L'ENVELOPPE : il prouve qu'elle tient, pas que le
scan PRINCIPAL la prenne. Un pas principal remis sous sa forme d'avant — `/tmp/gitleaks detect …`
appelé directement — rouvrait les deux voies dans le scan qui garde le dépôt (mesuré : une clé sur
une ligne `gitleaks:allow` donne 1 constat par l'enveloppe, 0 par l'appel direct ; la même avec un
`.gitleaksignore` qui porte son empreinte, refus par l'enveloppe, 0 par l'appel direct), et aucun
témoin ni aucune garde ne rougissait.

CE QUE LA GARDE EXIGE, dans TOUS les flux de `.github/workflows/` (pas seulement `ci.yml` : un scan
ajouté ailleurs serait la même brèche) :
  (1) une SEULE ligne de commande lance le binaire gitleaks avec une sous-commande de scan
      (`detect`, `git`, `dir`, `directory`, `file`, `protect`, `stdin`, drapeaux globaux `--x` ou `--x=v`
      admis avant elle) — et c'est l'`exec` de l'enveloppe,
      qui porte `--ignore-gitleaks-allow` ;
  (2) l'enveloppe refuse un `.gitleaksignore` (sa ligne `find … -name .gitleaksignore` existe) ;
  (2b) `P10.31-o` : l'enveloppe force le texte — elle résout `--git-path info/attributes` du dépôt
      scanné et y ajoute `* diff`, que git fait primer sur tout `.gitattributes` (sans quoi un
      attribut `-diff` ou la macro `binary`, même committés après la clé, font sauter le fichier
      au scan d'historique : mesuré en 8.24.3) ;
  (3) le pas principal (`id: gitleaks`) appelle l'enveloppe.
Les lignes de commentaire (`#` en tête) ne comptent pas : la prose peut nommer la forme interdite.

CE QUI NE TIENT PAS : la lecture est TEXTUELLE. Un binaire appelé par une variable
(`G=/tmp/gitleaks; $G detect`), une construction dynamique, un drapeau global à valeur séparée
(`gitleaks --config c dir`) ou une image de conteneur au nom inhabituel échappent au motif (1) ;
dans le pas principal, le contrôle (3) les refuse quand même (il exige l'enveloppe), ailleurs seule
la relecture les voit. Le contrôle (2b) est textuel lui aussi : il exige les deux lignes dans les flux,
pas qu'elles soient dans l'enveloppe ni exécutées ; c'est le témoin du scan qui le prouve (dépôts
jetables marqués `-diff`, joués sur l'enveloppe).

Usage : python3 .github/scripts/check_every_gitleaks_scan_takes_the_single_call.py [FLUX.yml …]
Sortie : 0 = tenu ; 1 = propriété violée ; 2 = instrument invalide ou flux illisible (aucun verdict).
"""
from __future__ import annotations

import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
FLUX = os.path.join(RACINE, ".github", "workflows")

# Un jeton qui NOMME le binaire (`/tmp/gitleaks`, `gitleaks`, `"${GITLEAKS_BIN:-/tmp/gitleaks}"`,
# `zricethezav/gitleaks:v8`) suivi d'une sous-commande de scan. `gitleaks-detect.sh` n'y répond pas :
# `gitleaks` y est suivi de `-`, pas d'un blanc.
APPEL = re.compile(
    r"""(?:gitleaks(?::[^\s"']+)?|GITLEAKS_BIN[^}\s]*\})["']?(?:\s+--?[\w-]+(?:=\S+)?)*\s+(detect|git|dir|directory|file|protect|stdin)\b"""
)
TEXTE_FORCE = re.compile(r"""printf\s+(['"])\*\s+diff\\n\1\s*>>""")
ENVELOPPE = re.compile(r"""\$\{?RUNNER_TEMP[^/]*/gitleaks-detect\.sh""")


def lignes_de_commande(texte: str):
    for n, ligne in enumerate(texte.splitlines(), 1):
        if ligne.lstrip().startswith("#"):
            continue
        yield n, ligne


def pas_principal(texte: str) -> str | None:
    """Le bloc du pas `id: gitleaks` (jusqu'au pas suivant), ou None."""
    lignes = texte.splitlines()
    for i, l in enumerate(lignes):
        if re.fullmatch(r"\s*id:\s*gitleaks\s*", l):
            debut = i
            while debut > 0 and not re.match(r"\s*- name:", lignes[debut]):
                debut -= 1
            fin = i + 1
            while fin < len(lignes) and not re.match(r"\s*- (name|uses):", lignes[fin]):
                fin += 1
            return "\n".join(lignes[debut:fin])
    return None


def juger(textes: dict[str, str]) -> list[str]:
    defauts: list[str] = []
    appels = []
    for f, t in textes.items():
        for n, l in lignes_de_commande(t):
            if APPEL.search(l):
                appels.append((f, n, l.strip()))
    uniques = [a for a in appels if a[2].startswith("exec ") and "--ignore-gitleaks-allow" in a[2]]
    if len(uniques) != 1:
        defauts.append(
            f"{len(uniques)} appel(s) `exec … gitleaks detect … --ignore-gitleaks-allow` (l'enveloppe) ; "
            "il en faut exactement un"
        )
    for f, n, l in appels:
        if uniques and (f, n, l) == uniques[0]:
            continue
        defauts.append(
            f"{f}:{n} lance gitleaks HORS de l'enveloppe `$RUNNER_TEMP/gitleaks-detect.sh` : `{l}` — "
            "un tel scan rouvre `gitleaks:allow` et `.gitleaksignore` ; appeler l'enveloppe"
        )
    if not any(
        re.search(r"find\b.*-name\s+\.gitleaksignore", l)
        for t in textes.values()
        for _, l in lignes_de_commande(t)
    ):
        defauts.append("l'enveloppe ne cherche plus de `.gitleaksignore` à refuser")
    commandes = [l for t in textes.values() for _, l in lignes_de_commande(t)]
    if not any(re.search(r"--git-path\s+info/attributes\b", l) for l in commandes) or not any(
        TEXTE_FORCE.search(l) for l in commandes
    ):
        defauts.append(
            "l'enveloppe ne force plus le texte (`* diff` ajouté à `--git-path info/attributes`) : "
            "un attribut `-diff` tairait le fichier au scan d'historique (P10.31-o)"
        )
    principaux = [(f, pas_principal(t)) for f, t in textes.items()]
    principaux = [(f, b) for f, b in principaux if b is not None]
    if not principaux:
        defauts.append("aucun pas `id: gitleaks` (le scan principal) n'est trouvé")
    for f, b in principaux:
        if not any(ENVELOPPE.search(l) for _, l in lignes_de_commande(b)):
            defauts.append(f"{f} : le pas `id: gitleaks` n'appelle pas `$RUNNER_TEMP/gitleaks-detect.sh`")
    return defauts


ENV_OK = (
    "      - name: config\n        run: |\n"
    "          ign=\"$(find \"$src\" -name .gitleaksignore -print -quit)\"\n"
    "          if att=\"$(git -C \"$src\" rev-parse --path-format=absolute --git-path info/attributes)\"; then\n"
    "            printf '* diff\\n' >> \"$att\"; fi\n"
    "          exec \"${GITLEAKS_BIN:-/tmp/gitleaks}\" detect --source . --ignore-gitleaks-allow \"$@\"\n"
)
PRINCIPAL_OK = (
    "      - name: Secret scan\n        id: gitleaks\n        run: |\n"
    "          # jadis : /tmp/gitleaks detect --source .\n"
    "          tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks\n"
    "          bash \"$RUNNER_TEMP/gitleaks-detect.sh\" . --config c.toml\n"
    "      - name: suite\n"
)


def valider_linstrument() -> list[str]:
    """Témoins positif et négatifs, fabriqués : la garde ne se croit pas elle-même."""
    faux = []
    if juger({"ok.yml": ENV_OK + PRINCIPAL_OK}):
        faux.append("le flux sain fabriqué est refusé : " + "; ".join(juger({"ok.yml": ENV_OK + PRINCIPAL_OK})))
    hostiles = {
        "scan principal direct": ENV_OK + PRINCIPAL_OK.replace(
            'bash "$RUNNER_TEMP/gitleaks-detect.sh" . --config c.toml',
            '/tmp/gitleaks detect --source . --config c.toml'),
        "appel direct en plus de l'enveloppe": ENV_OK + PRINCIPAL_OK.replace(
            "      - name: suite\n", "          gitleaks git . --config c.toml\n      - name: suite\n"),
        "appel par GITLEAKS_BIN": ENV_OK + PRINCIPAL_OK.replace(
            "      - name: suite\n", "          \"${GITLEAKS_BIN}\" dir .\n      - name: suite\n"),
        "conteneur": ENV_OK + PRINCIPAL_OK.replace(
            "      - name: suite\n", "          docker run zricethezav/gitleaks:v8 detect\n      - name: suite\n"),
        "enveloppe sans --ignore-gitleaks-allow": ENV_OK.replace(" --ignore-gitleaks-allow", "") + PRINCIPAL_OK,
        "enveloppe sans refus de .gitleaksignore": ENV_OK.replace("-name .gitleaksignore", "-name x") + PRINCIPAL_OK,
        "pas principal absent": ENV_OK,
        # `P10.31-o` : seul le contrôle (2b) refuse ceux-là.
        "enveloppe sans texte forcé": ENV_OK.replace("            printf '* diff\\n' >> \"$att\"; fi\n", "            fi\n") + PRINCIPAL_OK,
        "texte forcé désarmé": ENV_OK.replace("printf '* diff", "printf '* -diff") + PRINCIPAL_OK,
        "texte forcé hors de info/attributes": ENV_OK.replace("--git-path info/attributes", "--git-dir") + PRINCIPAL_OK,
        # Seul le contrôle (3) refuse ceux-ci : le motif (1) ne voit pas un binaire lancé par une variable.
        "scan principal par une variable": ENV_OK + PRINCIPAL_OK.replace(
            'bash "$RUNNER_TEMP/gitleaks-detect.sh" . --config c.toml',
            'GL=/tmp/gitleaks; "$GL" detect --source . --config c.toml'),
        # Seul le compte des `exec` (exactement un) refuse ceux-là.
        "enveloppe sans exec reconnu": ENV_OK.replace(
            '"${GITLEAKS_BIN:-/tmp/gitleaks}" detect', '"$GITLEAKS_BIN" detect') + PRINCIPAL_OK,
        "alias file": ENV_OK + PRINCIPAL_OK.replace(
            "      - name: suite\n", "          gitleaks file . --config c.toml\n      - name: suite\n"),
        "drapeau global avant la sous-commande": ENV_OK + PRINCIPAL_OK.replace(
            "      - name: suite\n", "          /tmp/gitleaks --no-banner dir .\n      - name: suite\n"),
    }
    for nom, t in hostiles.items():
        if not juger({"h.yml": t}):
            faux.append(f"le flux hostile « {nom} » est admis")
    return faux


def main(argv: list[str]) -> int:
    faux = valider_linstrument()
    if faux:
        for f in faux:
            print(f"::error::instrument invalide — {f}")
        return 2
    chemins = argv or sorted(
        os.path.join(FLUX, f) for f in os.listdir(FLUX) if f.endswith((".yml", ".yaml"))
    )
    textes = {}
    for c in chemins:
        try:
            with open(c, encoding="utf-8") as fh:
                textes[os.path.relpath(c, RACINE)] = fh.read()
        except OSError as e:
            print(f"::error::{c} illisible ({e}) — aucun verdict.")
            return 2
    defauts = juger(textes)
    if defauts:
        for d in defauts:
            print(f"::error::{d}")
        print(f"\n{len(defauts)} défaut(s) : tout scan gitleaks passe par l'enveloppe unique (P10.31-n).")
        return 1
    print(f"{len(textes)} flux lus : un seul lancement de gitleaks (l'enveloppe, --ignore-gitleaks-allow, "
          "refus de .gitleaksignore, texte forcé), pris par le scan principal.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
