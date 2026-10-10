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
  (2c) `P10.31-r` : l'`exec` de l'enveloppe porte `--log-opts="--full-history --all --diff-merges=separate"`
      (gitleaks lance `git log -p -U0 --full-history --all`, qui n'affiche aucun diff de fusion : une clé
      ajoutée dans la résolution d'une fusion était tue ; `--log-opts` REMPLACE les options par défaut,
      d'où leur reprise — mesuré en 8.24.3) ;
  (3) le pas principal (`id: gitleaks`) appelle l'enveloppe.
Les lignes de commentaire (`#` en tête) ne comptent pas : la prose peut nommer la forme interdite.

`P10.31-r` — JUGEMENT PAR EXÉCUTION, au-delà du texte. Le corps de l'enveloppe (le heredoc qui écrit
`gitleaks-detect.sh`) est EXTRAIT des flux et JOUÉ, dans un dépôt jetable, contre un faux binaire
(`GITLEAKS_BIN`) qui journalise ses arguments. Il faut : exactement UN lancement (un second, par une
variable, scannerait hors des options exigées ; aucun = le binaire n'est pas celui de `GITLEAKS_BIN`),
lancé depuis le dépôt, `detect --source .`, `--ignore-gitleaks-allow`, l'option d'historique ci-dessus
EXACTE et seule, les arguments de l'appelant transmis en fin, `* diff` en dernière ligne de
`info/attributes` ; un `.gitleaksignore` refusé (code 3) et un `--log-opts` de l'appelant refusé (code 5),
sans lancement. Puis des enveloppes HOSTILES, dérivées de la vraie (une retouche chacune), doivent être
refusées par ce même jugement ; une retouche dont l'ancre est introuvable invalide l'instrument (code 2).
Sans corps d'enveloppe trouvé (ou non fermé), la garde REFUSE DE CONCLURE (code 2).

CE QUI NE TIENT PAS : le contrôle (1) est TEXTUEL. Un binaire appelé par une variable
(`G=/tmp/gitleaks; $G detect`), une construction dynamique, un drapeau global à valeur séparée
(`gitleaks --config c dir`) ou une image de conteneur au nom inhabituel échappent au motif (1) ;
dans le pas principal, le contrôle (3) les refuse quand même (il exige l'enveloppe), ailleurs seule
la relecture les voit. DANS l'enveloppe, l'exécution les voit (un second lancement est compté) ; HORS
d'elle et du pas principal (un autre pas, un autre flux), seule la lecture textuelle juge. L'exécution
ne joue que le chemin d'un dépôt git sain sans arguments piégés : une branche de l'enveloppe qui ne
s'ouvrirait que sous une condition absente du dépôt jetable (variable d'environnement, contenu de
l'arbre) lui échappe. Le faux binaire prouve les ARGUMENTS, pas leur effet : que gitleaks 8.24.3 lise
les fusions avec eux, c'est le témoin du scan qui le prouve (dépôt de fusion jetable, joué sur
l'enveloppe, avec ses contre-épreuves).

Usage : python3 .github/scripts/check_every_gitleaks_scan_takes_the_single_call.py [FLUX.yml …]
Sortie : 0 = tenu ; 1 = propriété violée ; 2 = instrument invalide ou flux illisible (aucun verdict).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

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
# `P10.31-r` : les options d'historique exigées, telles que gitleaks les découpe (sur l'espace).
OPTIONS_HISTORIQUE = "--full-history --all --diff-merges=separate"
LOG_OPTS = re.compile(r"""--log-opts=(["'])""" + re.escape(OPTIONS_HISTORIQUE) + r"""\1(?:\s|$)""")
DEBUT_ENVELOPPE = re.compile(
    r"""^(\s*)cat\s+>\s*"?\$\{?RUNNER_TEMP[^/\s]*/gitleaks-detect\.sh"?\s+<<-?\s*(['"]?)(\w+)\2\s*$"""
)


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
    elif not LOG_OPTS.search(uniques[0][2]):
        defauts.append(
            f"{uniques[0][0]}:{uniques[0][1]} : l'appel unique ne porte pas `--log-opts=\"{OPTIONS_HISTORIQUE}\"` : "
            "une clé ajoutée dans la résolution d'une fusion serait tue (P10.31-r)"
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
    "          exec \"${GITLEAKS_BIN:-/tmp/gitleaks}\" detect --source . --ignore-gitleaks-allow"
    " --log-opts=\"--full-history --all --diff-merges=separate\" \"$@\"\n"
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
        # `P10.31-r` : seul le contrôle (2c) refuse ceux-là.
        "enveloppe sans lecture des fusions": ENV_OK.replace(" --diff-merges=separate", "") + PRINCIPAL_OK,
        "enveloppe avec -m seul": ENV_OK.replace('--log-opts="--full-history --all --diff-merges=separate"', "--log-opts=-m") + PRINCIPAL_OK,
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


class AncreIntrouvable(Exception):
    """Une retouche hostile ne trouve pas son ancre dans l'enveloppe réelle : l'instrument ne juge plus."""


def extraire_enveloppes(textes: dict[str, str]) -> list[tuple[str, int, str | None]]:
    """(flux, ligne, corps) de chaque heredoc qui écrit `gitleaks-detect.sh` ; corps None s'il n'est pas fermé.
    Le retrait du bloc YAML (celui de la ligne `cat >`) est ôté de chaque ligne du corps."""
    trouves = []
    for f, t in textes.items():
        lignes = t.splitlines()
        for i, l in enumerate(lignes):
            m = DEBUT_ENVELOPPE.match(l)
            if not m:
                continue
            retrait, fin, corps = m.group(1), m.group(3), None
            for j in range(i + 1, len(lignes)):
                if lignes[j].strip() == fin:
                    corps = "".join((x[len(retrait):] if x.startswith(retrait) else x.lstrip()) + "\n"
                                    for x in lignes[i + 1:j])
                    break
            trouves.append((f, i + 1, corps))
    return trouves


FAUX_BINAIRE = (
    "#!/usr/bin/env bash\n"
    "{ printf 'APPEL\\t%s\\n' \"$PWD\"; for a in \"$@\"; do printf 'ARG\\t%s\\n' \"$a\"; done; } >> \"$GARDE_JOURNAL\"\n"
)
CANARI = ["--config", "canari-p10-31-r.toml", "--exit-code", "1"]


def _jouer(dossier: str, corps: str, depot: str, args: list[str]) -> tuple[int, list[tuple[str, list[str]]], str]:
    """Joue `corps` (l'enveloppe) sur `depot` ; rend (code, lancements du faux binaire, sortie)."""
    env_sh = os.path.join(dossier, "enveloppe.sh")
    with open(env_sh, "w", encoding="utf-8") as fh:
        fh.write(corps)
    journal = os.path.join(dossier, "journal")
    open(journal, "w").close()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GITLEAKS_BIN=os.path.join(dossier, "faux-gitleaks"), GARDE_JOURNAL=journal)
    r = subprocess.run(["bash", env_sh, depot, *args], cwd=dossier, env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, errors="replace", timeout=60)
    appels: list[tuple[str, list[str]]] = []
    with open(journal, encoding="utf-8", errors="replace") as fh:
        for l in fh.read().splitlines():
            genre, _, val = l.partition("\t")
            if genre == "APPEL":
                appels.append((val, []))
            elif genre == "ARG" and appels:
                appels[-1][1].append(val)
    return r.returncode, appels, (r.stdout + r.stderr).strip()[-300:]


def _log_opts(args: list[str]) -> list[str]:
    vals = []
    for i, a in enumerate(args):
        if a.startswith("--log-opts="):
            vals.append(a[len("--log-opts="):])
        elif a == "--log-opts":
            vals.append(args[i + 1] if i + 1 < len(args) else "")
    return vals


def juger_execution(corps: str) -> list[str]:
    """Joue l'enveloppe contre un faux binaire, dans un dépôt jetable ; rend les défauts constatés."""
    defauts: list[str] = []
    dossier = tempfile.mkdtemp(prefix="garde-gitleaks-")
    try:
        faux = os.path.join(dossier, "faux-gitleaks")
        with open(faux, "w") as fh:
            fh.write(FAUX_BINAIRE)
        os.chmod(faux, 0o755)
        depot = os.path.join(dossier, "depot")
        os.mkdir(depot)
        for c in (["init", "-q"], ["-c", "user.name=garde", "-c", "user.email=garde@invalid",
                                   "commit", "-q", "--allow-empty", "-m", "garde"]):
            subprocess.run(["git", "-C", depot, *c], check=True, capture_output=True, timeout=30)
        rc, appels, sortie = _jouer(dossier, corps, depot, CANARI)
        if rc != 0:
            defauts.append(f"sur un dépôt sain, l'enveloppe rend le code {rc} (attendu 0, celui du faux binaire) : {sortie}")
        if len(appels) != 1:
            defauts.append(
                f"{len(appels)} lancement(s) du binaire de `GITLEAKS_BIN` ; il en faut exactement un "
                "(un second scannerait hors des options exigées ; aucun : le binaire lancé n'est pas celui de `GITLEAKS_BIN`)")
        for cwd, args in appels:
            if os.path.realpath(cwd) != os.path.realpath(depot):
                defauts.append(f"le binaire est lancé depuis {cwd}, pas depuis le dépôt scanné")
            if args[:3] != ["detect", "--source", "."]:
                defauts.append(f"le lancement ne commence pas par `detect --source .` : {args[:3]}")
            if "--ignore-gitleaks-allow" not in args:
                defauts.append("le lancement ne porte pas `--ignore-gitleaks-allow` (un `gitleaks:allow` tairait une clé)")
            lo = _log_opts(args)
            if lo != [OPTIONS_HISTORIQUE]:
                defauts.append(f"options d'historique {lo}, attendu exactement [{OPTIONS_HISTORIQUE!r}] : "
                               "sans elles une clé ajoutée dans la résolution d'une fusion est tue (P10.31-r)")
            if args[-len(CANARI):] != CANARI:
                defauts.append("les arguments de l'appelant ne sont pas transmis en fin du lancement")
        att = subprocess.run(["git", "-C", depot, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes"],
                             check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        try:
            with open(att, encoding="utf-8") as fh:
                derniere = [l for l in fh.read().splitlines() if l.strip()][-1:]
        except OSError:
            derniere = []
        if derniere != ["* diff"]:
            defauts.append(f"après l'appel, la dernière ligne de info/attributes est {derniere}, attendu ['* diff'] (texte non forcé)")
        with open(os.path.join(depot, ".gitleaksignore"), "w") as fh:
            fh.write("x:y:private-key:1\n")
        rc, appels, _ = _jouer(dossier, corps, depot, CANARI)
        if rc != 3 or appels:
            defauts.append(f"un `.gitleaksignore` rend le code {rc} et {len(appels)} lancement(s), attendu 3 et aucun")
        os.remove(os.path.join(depot, ".gitleaksignore"))
        for lo in (["--log-opts=--first-parent"], ["--log-opts", "--first-parent"]):
            rc, appels, _ = _jouer(dossier, corps, depot, [*CANARI, *lo])
            if rc != 5 or appels:
                defauts.append(f"un appel avec {' '.join(lo)} rend le code {rc} et {len(appels)} lancement(s), "
                               "attendu 5 et aucun (il remplacerait les options d'historique)")
    finally:
        shutil.rmtree(dossier, ignore_errors=True)
    return defauts


# Retouches HOSTILES de l'enveloppe RÉELLE, chacune doit être refusée par l'exécution (`P10.31-r`).
# (nom, ancre, remplacement) ; une ancre `^exec ` insère le remplacement AVANT la ligne `exec` de l'appel.
HOSTILES_EXECUTION = [
    ("sans option d'historique", ' --log-opts="--full-history --all --diff-merges=separate"', ""),
    ("-m seul (perd --all)", ' --log-opts="--full-history --all --diff-merges=separate"', " --log-opts=-m"),
    ("sans --ignore-gitleaks-allow", " --ignore-gitleaks-allow", ""),
    ("second lancement par une variable", "^exec ",
     'GL="${GITLEAKS_BIN:-/tmp/gitleaks}"; "$GL" detect --source . "$@" || true\n'),
    ("binaire hors de GITLEAKS_BIN", '"${GITLEAKS_BIN:-/tmp/gitleaks}"', '"/inexistant-p10-31-r/gitleaks"'),
    ("sans refus de --log-opts", "--log-opts|--log-opts=*)", "--log-optz)"),
    ("arguments de l'appelant perdus", '--diff-merges=separate" "$@"', '--diff-merges=separate"'),
    ("sans texte forcé", "printf '* diff\\n' >>", "printf '' >>"),
    ("sans refus de .gitleaksignore", "-name .gitleaksignore", "-name .gitleaksignore-p10-31-r"),
]


def valider_execution(corps: str) -> list[str]:
    """L'enveloppe réelle tient : chaque retouche hostile doit être refusée par le même jugement."""
    faux = []
    for nom, ancre, remplacement in HOSTILES_EXECUTION:
        if ancre == "^exec ":
            lignes = corps.splitlines(keepends=True)
            idx = [i for i, l in enumerate(lignes) if l.startswith("exec ")]
            if len(idx) != 1:
                raise AncreIntrouvable(f"« {nom} » : {len(idx)} ligne(s) `exec` dans l'enveloppe, attendu 1")
            hostile = "".join(lignes[:idx[0]] + [remplacement] + lignes[idx[0]:])
        else:
            if corps.count(ancre) != 1:
                raise AncreIntrouvable(f"« {nom} » : ancre {ancre!r} trouvée {corps.count(ancre)} fois, attendu 1")
            hostile = corps.replace(ancre, remplacement)
        if not juger_execution(hostile):
            faux.append(f"l'enveloppe hostile « {nom} » est admise par l'exécution")
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
    enveloppes = extraire_enveloppes(textes)
    if not enveloppes or any(corps is None for _, _, corps in enveloppes):
        print("::error::aucun corps d'enveloppe complet (heredoc `cat > \"${RUNNER_TEMP:?}/gitleaks-detect.sh\" <<'EOF'` "
              "… `EOF`) dans les flux : l'exécution n'est pas jugée — aucun verdict (P10.31-r).")
        return 2
    if len(enveloppes) > 1:
        defauts.append("plusieurs enveloppes écrites (" + ", ".join(f"{f}:{n}" for f, n, _ in enveloppes)
                       + ") : il en faut exactement une")
    else:
        try:
            corps = enveloppes[0][2]
            joue = juger_execution(corps)
            defauts += [f"{enveloppes[0][0]}:{enveloppes[0][1]} (enveloppe jouée) : {d}" for d in joue]
            if not joue:
                faux = valider_execution(corps)
        except (OSError, subprocess.SubprocessError, AncreIntrouvable) as e:
            print(f"::error::instrument invalide — exécution de l'enveloppe impossible ({e}) — aucun verdict.")
            return 2
        if not joue and faux:
            for f in faux:
                print(f"::error::instrument invalide — {f}")
            return 2
    if defauts:
        for d in defauts:
            print(f"::error::{d}")
        print(f"\n{len(defauts)} défaut(s) : tout scan gitleaks passe par l'enveloppe unique (P10.31-n).")
        return 1
    print(f"{len(textes)} flux lus : un seul lancement de gitleaks (l'enveloppe, --ignore-gitleaks-allow, "
          "refus de .gitleaksignore, texte forcé, fusions lues), pris par le scan principal ; l'enveloppe "
          f"jouée contre un faux binaire tient, et {len(HOSTILES_EXECUTION)} enveloppes hostiles dérivées sont refusées.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
