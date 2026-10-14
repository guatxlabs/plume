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
  (3) le pas principal (`id: gitleaks`) appelle l'enveloppe ;
  `P10.31-t` — le pas principal ne NEUTRALISE pas l'enveloppe qu'il appelle (`|| true` après l'appel, un préfixe
  `GITLEAKS_BIN=/tmp/neutre` laissaient tout vert sur cc71144 ; puis, sur 1f50949, un drapeau de l'appelant —
  `--no-git`, `--config /dev/null`, `--gitleaks-ignore-path`, `--baseline-path`, qui taisent un vrai secret en
  8.24.3 — et neuf formes de verdict neutralisé). Règles FERMÉES plutôt que motifs à empiler :
  (a) GRAMMAIRE FERMÉE du pas : hors du corps de `run: |`, chaque ligne est une clé NON CITÉE, collée à son deux-points,
      au retrait des clés du pas, parmi `name`, `id: gitleaks`, `if: always()`, `continue-on-error: true`, `run: |`
      (toutes présentes, une fois, valeur exigée) — `shell:`, `env:`, `working-directory:`, `"shell":`, `shell :`, une
      clé enfouie dans un scalaire replié, une clé posée APRÈS le corps de `run: |` sont refusés sans être nommés ; son `run:` est un GABARIT FERMÉ de sept
      commandes (`set -euo pipefail`, version, empreinte, `curl`, `sha256sum -c`, `tar`, puis l'appel EXACT
      `bash "$RUNNER_TEMP/gitleaks-detect.sh" . --config "$GITHUB_WORKSPACE/.gitleaks-ci.toml" --no-banner --redact
      --exit-code 1`), commentaires mis à part ; un seul pas `id: gitleaks` dans les flux ;
  (c) le pas de verdict porte exactement une ligne `[ "${{ steps.gitleaks.outcome }}" = success ] || { …; rc=1; }`,
      dans le TRAVAIL du pas principal et après lui, avec la grammaire fermée `name`, `if: always()`, `run: |`, et
      des commandes prises dans une grammaire fermée qui ne dépend pas de l'environnement (`set -u`, `echo` d'une
      issue, `rc=0`, une ligne de verdict, `exit $rc`) ; puis il est JOUÉ (voir plus bas) ;
  (c2) le travail du pas principal n'a que `name`, `runs-on`, `permissions`, `steps`, `timeout-minutes`
      (`continue-on-error` le rendrait vert, `defaults:` changerait le shell) ; le flux n'a pas de `defaults:` ;
  (d) `GITLEAKS_BIN`, `GITLEAKS_DETECT`, `GITLEAKS_CONF` n'apparaissent dans un flux qu'en LECTURE avec repli
      (`${GITLEAKS_BIN:-…}`) : aucune affectation (`env:`, préfixe, `export`, `$GITHUB_ENV`, `${…:=…}`) ;
  (e) aucun caractère AMBIGU dans un flux : contrôle autre que `\\t`/`\\n` (dont `\\v`, `\\f`, `\\x1c`-`\\x1e`, U+0085),
      séparateur U+2028/U+2029, caractère de format (U+202E, U+200B), blanc autre que l'espace (U+00A0). Les flux sont
      ainsi découpés par la garde comme par bash et par YAML : sur `\\n` seul. `\\r` n'atteint pas ce contrôle depuis
      un fichier : la garde lit les flux en retours à la ligne universels, `\\r` et `\\r\\n` y deviennent `\\n` ; YAML
      les tient lui aussi pour une fin de ligne, et bash ne voit que le `run:` qu'il rend (mesuré : `ci.yml` avec un
      `\\r` en fin de ligne, YAML valide, garde verte). Seul un texte fabriqué en mémoire (les témoins) le porte.
      Sans ce contrôle, `str.splitlines()` coupait sur U+2028 et un `#||true` qui le suivait était un commentaire pour
      la garde, une commande pour bash (mesuré sur le run rendu par PyYAML, gitleaks 8.24.3 : scan à 1 constat rendu
      vert ; idem `trap 'exit 0' EXIT` dans le verdict, `export GITLEAKS_BIN=/bin/true` derrière le `tar`, que (d)
      ne voyait pas non plus).
Les lignes de commentaire (`#` en tête) ne comptent pas : la prose peut nommer la forme interdite.

`P10.31-r` — JUGEMENT PAR EXÉCUTION, au-delà du texte. Le corps de l'enveloppe (le heredoc qui écrit
`gitleaks-detect.sh`) est EXTRAIT des flux et JOUÉ, dans un dépôt jetable, contre un faux binaire
(`GITLEAKS_BIN`) qui journalise ses arguments. Il faut : exactement UN lancement (un second, par une
variable, scannerait hors des options exigées ; aucun = le binaire n'est pas celui de `GITLEAKS_BIN`),
lancé depuis le dépôt, `detect --source .`, `--ignore-gitleaks-allow`, l'option d'historique ci-dessus
EXACTE et seule, les arguments de l'appelant transmis en fin, `* diff` en dernière ligne de
`info/attributes` ; un `.gitleaksignore` refusé (code 3) et un `--log-opts` de l'appelant refusé (code 5),
sans lancement. Puis des enveloppes HOSTILES, dérivées de la vraie (une retouche chacune), doivent être
refusées par ce même jugement, et par l'ensemble EXACT de contrôles annoncé (`P10.31-t` : chaque contrôle —
lancements, dépôt courant, `detect --source .`, code 0 sur un dépôt sain, arguments de l'appelant EN FIN,
dernière ligne de `info/attributes` — a au moins une retouche qu'il est seul à refuser) ; une retouche dont
l'ancre est introuvable invalide l'instrument (code 2). Le dépôt jetable commit avec `commit.gpgsign=false`
(une configuration globale qui signe tout faisait échouer la garde, code 2).
`P10.31-t` (b) — LE PAS PRINCIPAL JOUÉ. Son `run:` est extrait et joué (`bash -e`, le shell d'un pas
GitHub sans `shell:` selon sa documentation, non mesuré sur un exécuteur) avec l'enveloppe réelle sous `$RUNNER_TEMP`, le faux binaire sous `GITLEAKS_BIN`, et de faux
`curl`/`sha256sum`/`tar` en tête de PATH : sur un dépôt sain il rend 0 après UN lancement, depuis l'espace de travail,
portant EXACTEMENT les arguments de l'enveloppe puis ceux de l'appel (l'enveloppe jouée seule est jugée de même :
aucun drapeau qu'elle ajouterait) ; quand le binaire rend 1 il sort non nul ; quand `sha256sum` rend 1 il sort non
nul SANS lancer. Des pas HOSTILES dérivés du vrai (`|| true`, préfixes `GITLEAKS_BIN=`, `set +e`, empreinte avalée,
appel direct, `cd` vers un dépôt vide, drapeaux `--no-git`, `--config /dev/null`, `--gitleaks-ignore-path`,
`--baseline-path`, `--exit-code 0`) doivent être refusés par ce parcours seul, chacun par l'ensemble exact annoncé.
`P10.31-t` (c) — LE VERDICT JOUÉ. Les issues `${{ steps.<id>.outcome }}` substituées, le `run:` du verdict est joué :
0 quand tout passe, non nul quand le scan est `failure`, `cancelled` ou `skipped`, QUELLE QUE SOIT l'issue des autres
pas (`success`, `failure`, `cancelled`, `skipped`). Des verdicts hostiles dérivés du vrai (`rc=0` avant la sortie,
`exit 0`, `trap 'exit 0' EXIT`, issue non lue, toujours en échec, `rc=0` sous l'issue d'un autre pas) doivent être
refusés par cette exécution seule. Les flux hostiles FABRIQUÉS déclarent eux aussi l'ensemble exact des contrôles
textuels qui les refusent : retirer un contrôle change un ensemble, la garde refuse alors de conclure.
`P10.31-t` — LES GRAMMAIRES ÉPROUVÉES PAR ÉNUMÉRATION, pas par témoins posés un à un (un témoin manquait à chaque
relecture : backquote des messages, `rc=0`, `rc=1`, `set -u`). Chaque règle de `GRAMMAIRE_VERDICT` et du gabarit est
aussi écrite en composants (`COMPOSANTS_VERDICT`, `COMPOSANTS_GABARIT`) jugés sans `re` ; toute commande à une retouche
d'un échantillon doit recevoir le même verdict des deux écritures, et pour chaque composant (caractère de littéral,
caractère exclu d'une classe, borne, ancre) un flux qui ne diffère du sain que par lui doit être refusé par la garde
entière. Les retouches que bash lit comme l'original (blancs de bord, `#` en tête d'une ligne ajoutée) sont la liste
fermée `EQUIVALENTS_DE_FLUX`, chacune exigée ADMISE. Toute divergence : code 2.
Sans corps d'enveloppe trouvé (ou non fermé), sans `run: |` extractible du pas principal, ou avec une
expression `${{ … }}` dans ce `run:`, la garde REFUSE DE CONCLURE (code 2).

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
`P10.31-t` NE TIENT PAS : le pas principal et son verdict sont jugés tels qu'ils sont ÉCRITS, joués sur bash avec
de faux outils et des issues substituées ; ce qui agit AVANT eux hors de leur texte échappe au jugement : une
variable d'environnement de flux ou de travail autre que `GITLEAKS_*` (`BASH_ENV`, `PATH`, `SHELLOPTS` dans un `env:`
de flux — le travail, lui, n'en admet pas), une écriture d'un pas antérieur dans `$GITHUB_ENV` ou `$GITHUB_PATH`
(sauf `GITLEAKS_*` nommée en clair), un fichier de l'enveloppe réécrit par un pas intermédiaire autrement que par le
heredoc reconnu, un nom de variable construit dynamiquement (`"GITLEAKS_""BIN=…" >> $GITHUB_ENV`). Le gabarit
contraint le TEXTE du pas, pas ce que deviennent `/tmp/gitleaks.tgz` ou `.gitleaks-ci.toml` avant lui (l'empreinte
vérifiée couvre l'un, le témoin du scan l'autre). La garde ne lit que `.github/workflows/` : un flux posé ailleurs
(action composite locale, flux réutilisable d'un autre dépôt) n'est pas lu. Le travail est délimité par le retrait
(`  <nom>:`) et les pas par le retrait de leur `- ` ; le CROISEMENT avec PyYAML (`croiser_avec_yaml`, chargeur sûr qui
refuse une clé répétée) exige en plus que le pas jugé et joué soit le SEUL pas `id == "gitleaks"` lu par YAML dans les
flux, qu'il commence à la même ligne, que son `run` soit le même octet pour octet, ses clés et valeurs celles de (a) ;
de même pour le verdict (même ligne, même travail, après le pas principal, même `run`, clés de (c)) ; et que le travail
lu par YAML n'ait que les clés de (c2), le flux aucune clé `defaults`. Un pas et son verdict réindentés EN TEXTE dans le
`run: |` de porteurs qui sortent 0 (garde verte, aucun scan, mesuré sur 2460bf55), le corps du travail réindenté d'un
blanc avec `continue-on-error: true`, une clé de flux échappée (`"\\x64efaults":`) ou explicite (`? defaults`) sont
ainsi refusés. PyYAML absent : code 2. Le croisement ne lit que les clés `jobs.<t>.steps[]` de PyYAML (YAML 1.1) : un
écart de lecture entre PyYAML et le lecteur de GitHub sur ces clés (forme YAML que l'un accepte et l'autre lit
autrement) lui échappe ; une forme que PyYAML refuse est refusée (`yaml_illisible`). Reste hors d'atteinte pour (d) :
un nom échappé dans un `env:` de flux (`"GITLEAKS_\\x42IN": /bin/true`), dont le pouvoir est celui de `BASH_ENV` en
`env:` de flux. L'agrégat `ci-ok` n'est pas lu ici : c'est `check_the_ci_aggregate_waits_for_every_other_job.py` qui
exige que ses `needs` couvrent tous les autres travaux, dont `security`. L'énumération des
grammaires ne voit que le VOISINAGE d'une retouche de chaque échantillon, sur l'alphabet ASCII imprimable et la
tabulation : une expression élargie seulement pour des commandes à deux retouches ou plus, ou pour des caractères hors
de cet alphabet, n'y diverge pas, et RIEN n'oblige à changer aussi les composants : l'expression élargie SEULE laisse
la garde verte, et le flux hostile qu'elle admet passe (mesuré par la vérification : `$` admis devant `{` seulement dans
la classe du message `echo`, ou `set -u|set -${X:+n}u` — un verdict qui rend 0 sur GitHub devant un scan en échec est
alors admis, que la garde non retouchée refuse). Seuls les témoins posés à la main et la RELECTURE de la ligne de
l'expression au diff voient un tel élargissement. L'exclusion de la barre inverse des messages est NÉCESSAIRE, même le guillemet exclu :
`\\"` ne ferme pas la chaîne, qui court jusqu'au guillemet de la ligne suivante (`echo "x\\"` puis `echo "; exit 0 #"`
forment UNE chaîne suivie de `exit 0` : bash rend 0, mesuré sur la garde de l'agrégat `ci-ok`) ; elle est tenue par
l'énumération comme les autres. Cinq méta-contrôles
ne sont vus que par croisement : retirer l'exécution du verdict RÉEL ne rougit qu'avec un verdict qui passe la
grammaire et échoue à l'exécution (`rc=0` inséré avant `exit $rc`) ; retirer l'auto-épreuve des verdicts hostiles,
celle des pas hostiles, ou la comparaison de leurs ensembles de contrôles, ne rougit qu'avec un contrôle d'exécution
affaibli en même temps ; retirer l'auto-épreuve énumérée des grammaires ne rougit qu'avec une grammaire affaiblie en
même temps (et seulement là où un témoin posé à la main la couvre encore). Retirer l'auto-épreuve du croisement YAML
(`valider_croisement`) ne rougit qu'avec un contrôle du croisement affaibli en même temps ET un flux réel qu'il laisse
passer ; retirer l'APPEL du croisement dans `main()` n'est vu par aucune auto-épreuve : seul le leurre joué sur un flux
réel le montre (rendu 0 au lieu de 1).
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
import unicodedata

try:
    import yaml  # paquet de la distribution (`python3-yaml`), comme check_every_feature_is_compiled_somewhere.py
except ImportError:  # sans analyseur, le croisement est impossible : `main()` refuse de conclure (code 2)
    yaml = None

ICI =os.path.dirname(os.path.abspath(__file__))
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
# `P10.31-t` : le `run:` du pas principal est un GABARIT FERMÉ — exactement ces commandes, dans cet ordre (les
# commentaires `#` mis à part), seules les valeurs de version et d'empreinte libres. Une règle structurelle plutôt
# qu'un empilement de motifs : `|| true`, `; true`, `&`, un préfixe d'affectation, `set +e`, `trap`, une fonction
# `bash`, un `cd`, une ligne continuée, un drapeau de plus ou de moins à l'appel (`--no-git`, `--config /dev/null`,
# `--gitleaks-ignore-path`, `--baseline-path`, `--exit-code 0` taisent un vrai secret : mesuré en 8.24.3) sont tous
# hors du gabarit, sans qu'aucun ait à être nommé.
APPEL_ARGS = ["--config", "$GITHUB_WORKSPACE/.gitleaks-ci.toml", "--no-banner", "--redact", "--exit-code", "1"]
APPEL_EXACT = 'bash "$RUNNER_TEMP/gitleaks-detect.sh" . ' + " ".join(
    f'"{a}"' if "$" in a else a for a in APPEL_ARGS)
GABARIT_PAS_PRINCIPAL = [
    r"set -euo pipefail",
    r"GL_VER=\d+\.\d+\.\d+",
    r"GL_SHA=[0-9a-f]{64}",
    re.escape('curl -sSfL -o /tmp/gitleaks.tgz '
              '"https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz"'),
    re.escape('echo "${GL_SHA}  /tmp/gitleaks.tgz" | sha256sum -c -'),
    re.escape("tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks"),
    re.escape(APPEL_EXACT),
]
# `P10.31-t` : la ligne du pas de verdict qui rend le job rouge quand le pas principal (sous
# `continue-on-error: true`) échoue ; sans elle, un secret trouvé laisse le travail vert. Elle LOCALISE le pas de
# verdict ; ce qui le juge, c'est sa grammaire fermée et son EXÉCUTION (`controler_verdict`).
VERDICT = re.compile(
    r"""\[\s*"\$\{\{\s*steps\.gitleaks\.outcome\s*\}\}"\s*=\s*success\s*\]\s*\|\|\s*\{[^{}]*;\s*rc=1;\s*\}"""
)
# `P10.31-t` : grammaire FERMÉE des commandes du pas de verdict. Aucune ne dépend de l'environnement (pas de `$`
# hors `rc` et des issues de pas, pas de backquote, pas de barre inverse dans les messages) : l'exécution du verdict
# contre des issues substituées le juge donc comme GitHub le jouera.
GRAMMAIRE_VERDICT = [
    r"set -u",
    r'echo "[^"$`\\]*\$\{\{ steps\.[\w-]+\.outcome \}\}"',
    r"rc=0",
    r'\[ "\$\{\{ steps\.[\w-]+\.outcome \}\}" = success \] \|\| \{ echo "::error::[^"$`\\]*"; rc=1; \}',
    r"exit \$rc",
]
ISSUE = re.compile(r"\$\{\{\s*steps\.([\w-]+)\.outcome\s*\}\}")


def commande_de_verdict_admise(c: str) -> bool:
    """La commande `c` du pas de verdict est-elle dans la grammaire fermée ? (seul point d'application)"""
    return any(re.fullmatch(g, c) for g in GRAMMAIRE_VERDICT)


def commande_du_gabarit(n: int, c: str) -> bool:
    """La commande `c` est-elle la `n`-ième du gabarit du pas principal ? (seul point d'application)"""
    return re.fullmatch(GABARIT_PAS_PRINCIPAL[n], c) is not None


# `P10.31-t` — AUTO-ÉPREUVE DES DEUX GRAMMAIRES FERMÉES (`GRAMMAIRE_VERDICT`, `GABARIT_PAS_PRINCIPAL`). Poser un témoin
# par restriction, à la main, en laissait toujours une sans témoin (le backquote des messages `::error::`, `rc=0`
# remplaçable par `rc=.*`, `rc=1` par `rc=\d`, `set -u` par `set .*` : mutants verts, chacun exploitable sur GitHub).
# Chaque règle est donc AUSSI écrite ici en composants — littéral, classe « tout sauf », classe « parmi » bornée —,
# jugés par un appariement glouton qui n'emploie pas `re`. `valider_grammaires` ÉNUMÈRE ces composants :
#   - différentiel EXHAUSTIF : chaque commande à une retouche de l'échantillon d'une règle (insertion, retrait ou
#     remplacement d'un caractère de `ALPHABET_SONDE`, à chaque position) doit recevoir le même verdict de l'expression
#     et des composants ; une restriction retirée, affaiblie ou ajoutée d'un seul côté les fait diverger ;
#   - un FLUX par composant (chaque caractère de chaque littéral — donc chaque option de `set` —, chaque caractère exclu
#     d'une classe, chaque borne de compte, les deux ancres pour CHAQUE caractère), qui ne diffère du flux sain que par
#     ce composant, doit être refusé par `juger_codes` tout entier — ce qui éprouve aussi le point d'application
#     (`fullmatch`, ligne par ligne).
# Une retouche de bord que la garde admet parce que bash la lit comme l'original est un ÉQUIVALENT : la liste en est
# fermée (`EQUIVALENTS_DE_FLUX`) et jugée dans les deux sens (l'ensemble des bords admis doit lui être ÉGAL).
ALPHABET_SONDE = "".join(chr(c) for c in range(0x20, 0x7F)) + "\t"
_IDENTIFIANT = ("parmi", "identifiant de pas", frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"), 1, None, "autre")
_CHIFFRES = ("parmi", "chiffres", frozenset("0123456789"), 1, None, "1")
_HEX64 = ("parmi", "empreinte hexadécimale", frozenset("0123456789abcdef"), 64, 64, "0" * 64)
_MESSAGE = ("sauf", '"$`\\', "m")
COMPOSANTS_VERDICT = [
    ("set -u", [("lit", "set -u")]),
    ("echo d'une issue", [("lit", 'echo "'), _MESSAGE, ("lit", "${{ steps."), _IDENTIFIANT, ("lit", '.outcome }}"')]),
    ("rc=0", [("lit", "rc=0")]),
    ("ligne de verdict", [("lit", '[ "${{ steps.'), _IDENTIFIANT, ("lit", '.outcome }}" = success ] || { echo "::error::'),
                          _MESSAGE, ("lit", '"; rc=1; }')]),
    ("exit $rc", [("lit", "exit $rc")]),
]
COMPOSANTS_GABARIT = [
    ("set", [("lit", "set -euo pipefail")]),
    ("version", [("lit", "GL_VER="), _CHIFFRES, ("lit", "."), _CHIFFRES, ("lit", "."), _CHIFFRES]),
    ("empreinte", [("lit", "GL_SHA="), _HEX64]),
    ("curl", [("lit", 'curl -sSfL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/'
                      'gitleaks_${GL_VER}_linux_x64.tar.gz"')]),
    ("empreinte vérifiée", [("lit", 'echo "${GL_SHA}  /tmp/gitleaks.tgz" | sha256sum -c -')]),
    ("tar", [("lit", "tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks")]),
    ("appel", [("lit", 'bash "$RUNNER_TEMP/gitleaks-detect.sh" . --config "$GITHUB_WORKSPACE/.gitleaks-ci.toml" '
                       "--no-banner --redact --exit-code 1")]),
]
# (famille, bord, caractère) -> pourquoi bash lit la retouche comme l'original. Rien d'autre n'est dispensé.
EQUIVALENTS_DE_FLUX = {
    ("verdict", "debut", " "): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("verdict", "debut", "\t"): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("verdict", "debut", "#"): "la ligne ajoutée devient un commentaire, pour la garde comme pour bash",
    ("verdict", "fin", " "): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("verdict", "fin", "\t"): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("gabarit", "debut", " "): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("gabarit", "debut", "\t"): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("gabarit", "fin", " "): "blanc de bord : ôté par la garde, sans effet pour bash",
    ("gabarit", "fin", "\t"): "blanc de bord : ôté par la garde, sans effet pour bash",
}


def _admis_par(seg, ch: str) -> bool:
    return ch not in seg[1] if seg[0] == "sauf" else ch in seg[2]


def composants_acceptent(composants, c: str) -> bool:
    """Appariement glouton, sans `re` : déterministe parce que le littéral qui suit une classe commence par un caractère
    qu'elle n'admet pas (vérifié par `valider_grammaires`)."""
    i = 0
    for seg in composants:
        if seg[0] == "lit":
            if not c.startswith(seg[1], i):
                return False
            i += len(seg[1])
            continue
        mini, maxi = (0, None) if seg[0] == "sauf" else (seg[3], seg[4])
        j = i
        while j < len(c) and _admis_par(seg, c[j]) and (maxi is None or j - i < maxi):
            j += 1
        if j - i < mini:
            return False
        i = j
    return i == len(c)


def _echantillon(composants) -> str:
    return "".join(seg[1] if seg[0] == "lit" else seg[2] if seg[0] == "sauf" else seg[5] for seg in composants)
# `P10.31-t` : variables qui détournent l'appel (binaire, enveloppe, configuration) ; un flux ne peut que
# les LIRE avec repli (`${GITLEAKS_BIN:-…}`), jamais les poser (`env:`, préfixe, `export`, `$GITHUB_ENV`, `:=`).
VARIABLES_DETOURNANTES = re.compile(r"""GITLEAKS_(?:BIN|DETECT|CONF)\b""")
# `P10.31-t` : grammaire FERMÉE des pas : clé -> valeur exigée (None : libre). Toute autre ligne hors du corps de
# `run: |` — clé citée (`"shell":`), espace avant le deux-points, `env:`, `shell:`, `working-directory:`, ancre de
# fusion `<<:` — est refusée sans avoir à être nommée.
CLES_DU_PAS_PRINCIPAL = {"name": None, "id": "gitleaks", "if": "always()", "continue-on-error": "true", "run": "|"}
CLES_DU_VERDICT = {"name": None, "if": "always()", "run": "|"}
# Clés admises au niveau du TRAVAIL qui porte le pas principal (`continue-on-error` y rendrait le flux vert sur un
# travail rouge ; `defaults:` y changerait le shell de tous ses pas ; `container:` l'environnement).
CLES_DU_TRAVAIL = {"name", "runs-on", "permissions", "steps", "timeout-minutes"}
LIGNE_DE_CLE = re.compile(r"( *)(- )?([a-z][a-z-]*):(?: (.*))?")


class ExtractionImpossible(Exception):
    """Le `run:` du pas principal (ou son verdict) n'est pas extractible : aucun verdict (code 2)."""


def _retrait(l: str) -> int:
    return len(l) - len(l.lstrip(" "))


def _commentaire(l: str) -> bool:
    return l.lstrip(" \t").startswith("#")


def lignes_de_commande(texte: str):
    for n, ligne in enumerate(texte.splitlines(), 1):
        if _commentaire(ligne):
            continue
        yield n, ligne


def localiser_principaux(lignes: list[str]) -> list[int]:
    """Indices des lignes `id: gitleaks` (le pas principal)."""
    return [i for i, l in enumerate(lignes) if re.fullmatch(r"\s*id:\s*gitleaks\s*", l)]


def bloc_du_pas(lignes: list[str], i: int) -> tuple[int, int]:
    """Bornes [debut, fin) du pas qui contient la ligne i : de l'élément de liste `- ` qui l'ouvre jusqu'à la
    première ligne non vide, hors commentaire, dont le retrait revient à celui de ce `- ` (ou moins)."""
    debut = i
    while debut >= 0 and not re.match(r" *- ", lignes[debut]):
        debut -= 1
    if debut < 0:
        raise ExtractionImpossible(f"ligne {i + 1} : aucun élément de liste `- ` n'ouvre son pas")
    fin = debut + 1
    while fin < len(lignes):
        l = lignes[fin]
        if l.strip() and not _commentaire(l) and _retrait(l) <= _retrait(lignes[debut]):
            break
        fin += 1
    return debut, fin


def travail_du_pas(lignes: list[str], i: int) -> tuple[int, int]:
    """Bornes [debut, fin) du travail (`  <nom>:` sous `jobs:`) qui contient la ligne i."""
    debut = i
    while debut >= 0 and not re.fullmatch(r"  [\w-]+:\s*", lignes[debut]):
        debut -= 1
    if debut < 0:
        raise ExtractionImpossible(f"ligne {i + 1} : aucun travail `  <nom>:` ne la contient")
    fin = debut + 1
    while fin < len(lignes) and not (lignes[fin].strip() and not _commentaire(lignes[fin]) and _retrait(lignes[fin]) <= 2):
        fin += 1
    return debut, fin


def structure_du_pas(f: str, lignes: list[str], debut: int, fin: int, attendues: dict, code: str) -> list[tuple[str, str]]:
    """`P10.31-t` : grammaire FERMÉE d'un pas. Hors du corps de `run: |`, chaque ligne non vide et hors commentaire
    est une clé de `attendues`, non citée, collée à son deux-points, au retrait des clés du pas ; chaque clé une
    fois, présente, avec la valeur exigée."""
    defauts = []
    k = _retrait(lignes[debut]) + 2
    vues: dict[str, str] = {}
    corps = False
    for j in range(debut, fin):
        l = lignes[j]
        if corps and (not l.strip() or _retrait(l) > k):
            continue
        corps = False
        if not l.strip() or _commentaire(l):
            continue
        m = LIGNE_DE_CLE.fullmatch(l)
        placee = m is not None and (
            (j == debut and m.group(2) is not None and len(m.group(1)) + 2 == k)
            or (j != debut and m.group(2) is None and len(m.group(1)) == k))
        if not placee or m.group(3) not in attendues:
            defauts.append((code, f"{f}:{j + 1} : ligne hors de la grammaire fermée du pas (clés {sorted(attendues)}, "
                                  f"non citées, une par ligne) : `{l.strip()}` — elle peut détourner son `run:` (P10.31-t)"))
            continue
        cle, val = m.group(3), (m.group(4) or "").strip()
        if cle in vues:
            defauts.append((code + "_repetee", f"{f}:{j + 1} : clé `{cle}:` répétée dans le pas (P10.31-t)"))
        vues[cle] = val
        corps = cle == "run"
    for cle, exige in attendues.items():
        if cle not in vues:
            defauts.append((code + "_absente", f"{f}:{debut + 1} : le pas n'a pas de clé `{cle}:` (P10.31-t)"))
        elif exige is not None and vues[cle] != exige:
            defauts.append((code + "_valeur", f"{f}:{debut + 1} : `{cle}: {vues[cle]}`, attendu `{cle}: {exige}` (P10.31-t)"))
    return defauts


def extraire_run(bloc: str) -> str:
    """Le corps du `run: |` d'un bloc de pas, retrait ôté ; ExtractionImpossible sinon."""
    lignes = bloc.splitlines()
    for i, l in enumerate(lignes):
        m = re.fullmatch(r"(\s*)run:\s*\|[-+]?\s*", l)
        if not m:
            continue
        corps = []
        for x in lignes[i + 1:]:
            if x.strip() and len(x) - len(x.lstrip()) <= len(m.group(1)):
                break
            corps.append(x)
        while corps and not corps[-1].strip():
            corps.pop()
        retraits = [len(x) - len(x.lstrip()) for x in corps if x.strip()]
        if not retraits:
            raise ExtractionImpossible("le `run: |` du pas est vide")
        r = min(retraits)
        return "".join(x[r:] + "\n" for x in corps)
    raise ExtractionImpossible("le pas n'a pas de `run: |` (bloc littéral) extractible")


def commandes(run: str) -> list[str]:
    # Blancs et tabulations seulement : un retour chariot resterait collé au dernier mot pour bash.
    return [l.strip(" \t") for l in run.splitlines() if l.strip(" \t") and not _commentaire(l)]


def juger_pas_principal_texte(f: str, lignes: list[str], debut: int, fin: int) -> list[tuple[str, str]]:
    """`P10.31-t` (a) : le pas principal ne neutralise pas l'enveloppe qu'il appelle — grammaire fermée de ses
    clés, `run:` conforme au gabarit fermé."""
    defauts = structure_du_pas(f, lignes, debut, fin, CLES_DU_PAS_PRINCIPAL, "cles_pas")
    run = extraire_run("\n".join(lignes[debut:fin]))
    if "${{" in run:
        raise ExtractionImpossible("le `run:` du pas principal porte une expression `${{ … }}` : il n'est pas jouable tel quel")
    cmds = commandes(run)
    ecart = next((n for n, c in enumerate(cmds[:len(GABARIT_PAS_PRINCIPAL)]) if not commande_du_gabarit(n, c)),
                 None if len(cmds) == len(GABARIT_PAS_PRINCIPAL) else min(len(cmds), len(GABARIT_PAS_PRINCIPAL)))
    if ecart is not None:
        vu = cmds[ecart] if ecart < len(cmds) else "(fin du run)"
        defauts.append(("gabarit", f"{f} : le `run:` du pas `id: gitleaks` sort du gabarit fermé à sa commande {ecart + 1} : "
                                   f"`{vu}` — seules les {len(GABARIT_PAS_PRINCIPAL)} commandes exigées (version et empreinte "
                                   f"libres), l'appel exact `{APPEL_EXACT}` en dernier : sinon son code serait avalé, son "
                                   "binaire, sa configuration ou son dépôt remplacés (P10.31-t)"))
    return defauts


def localiser_verdict(lignes: list[str]) -> list[int]:
    return [i for i, l in enumerate(lignes) if not _commentaire(l) and VERDICT.fullmatch(l.strip())]


def juger_verdict(f: str, lignes: list[str], principal: tuple[int, int], travail: tuple[int, int]) -> list[tuple[str, str]]:
    """`P10.31-t` (c) : le pas de verdict existe une fois, dans le travail du pas principal et après lui, avec une
    grammaire fermée de clés et de commandes ; son EXÉCUTION est jugée à part (`controler_verdict`)."""
    idx = localiser_verdict(lignes)
    if len(idx) != 1:
        return [("verdict_compte", f"{f} : {len(idx)} ligne(s) `[ \"${{{{ steps.gitleaks.outcome }}}}\" = success ] || {{ …; rc=1; }}`, "
                 "il en faut exactement une : sous `continue-on-error: true`, sans elle un secret trouvé laisse le travail vert (P10.31-t)")]
    debut, fin = bloc_du_pas(lignes, idx[0])
    defauts = structure_du_pas(f, lignes, debut, fin, CLES_DU_VERDICT, "verdict_cles")
    if not (travail[0] <= debut < travail[1] and debut >= principal[1]):
        defauts.append(("verdict_travail", f"{f}:{idx[0] + 1} : le pas de verdict n'est pas APRÈS le pas principal dans son travail "
                                           f"(lignes {travail[0] + 1}-{travail[1]}) : `steps.gitleaks` n'y désigne pas le scan (P10.31-t)"))
    for c in commandes(extraire_run("\n".join(lignes[debut:fin]))):
        if not commande_de_verdict_admise(c):
            defauts.append(("verdict_grammaire", f"{f}:{idx[0] + 1} : commande hors de la grammaire fermée du pas de verdict : `{c}` "
                                                 "(admises : `set -u`, `echo \"… ${{ steps.<id>.outcome }}\"`, `rc=0`, "
                                                 "`[ \"${{ steps.<id>.outcome }}\" = success ] || { echo \"::error::…\"; rc=1; }`, `exit $rc`) (P10.31-t)"))
    return defauts


def juger_travail(f: str, lignes: list[str], travail: tuple[int, int]) -> list[tuple[str, str]]:
    """`P10.31-t` : le travail du pas principal n'a que des clés admises ; le flux ne pose pas de `defaults:`."""
    defauts = []
    for j in range(*travail):
        l = lignes[j]
        if j == travail[0] or not l.strip() or _commentaire(l) or _retrait(l) != 4:
            continue
        m = LIGNE_DE_CLE.fullmatch(l)
        if m is None or m.group(2) is not None or m.group(3) not in CLES_DU_TRAVAIL:
            defauts.append(("travail_cles", f"{f}:{j + 1} : le travail du pas principal porte `{l.strip()}` (clés admises : "
                                            f"{', '.join(sorted(CLES_DU_TRAVAIL))}) : `continue-on-error` le rendrait vert, "
                                            "`defaults:` changerait le shell de ses pas (P10.31-t)"))
    for j, l in enumerate(lignes):
        if re.match(r"""["']?defaults["']?\s*:""", l):
            defauts.append(("defauts_flux", f"{f}:{j + 1} : `defaults:` de flux : il changerait le shell ou le répertoire de "
                                            "tous les pas, dont le scan et son verdict (P10.31-t)"))
    return defauts


def juger_variables(textes: dict[str, str]) -> list[tuple[str, str]]:
    """`P10.31-t` (d) : aucune affectation de GITLEAKS_BIN / GITLEAKS_DETECT / GITLEAKS_CONF dans les flux."""
    defauts = []
    for f, t in textes.items():
        for n, l in lignes_de_commande(t):
            for m in VARIABLES_DETOURNANTES.finditer(l):
                if l[max(0, m.start() - 2):m.start()] != "${" or l[m.end():m.end() + 2] != ":-":
                    defauts.append(("variables", f"{f}:{n} : `{m.group(0)}` hors d'une lecture avec repli `${{{m.group(0)}:-…}}` : "
                                                 f"`{l.strip()}` — poser cette variable remplace le binaire, l'enveloppe ou la configuration (P10.31-t)"))
    return defauts


def caractere_ambigu(c: str) -> bool:
    """`P10.31-t` : un caractère dont la lecture diffère entre la garde, un analyseur YAML et bash — séparateur de
    ligne que `str.splitlines()` coupe et bash non (U+2028, U+2029, U+0085, `\\v`, `\\f`, `\\x1c`-`\\x1e`), autre
    contrôle, caractère de format (U+202E, U+200B), blanc autre que l'espace (U+00A0, que `str.lstrip()` prend pour un
    retrait et YAML non). `\\r` serait refusé, mais `main()` lit les flux en retours universels : il y devient `\\n`
    avant ce contrôle, comme pour YAML."""
    cat = unicodedata.category(c)
    return (cat[0] == "C" and c not in "\t\n") or (cat[0] == "Z" and c != " ")


def juger_caracteres(textes: dict[str, str]) -> list[tuple[str, str]]:
    """`P10.31-t` : les flux sont jugés TELS QUE bash et YAML les lisent, donc découpés sur `\\n` seul ; un caractère
    ambigu est refusé partout (un `#…` posé après U+2028 était un commentaire pour la garde, une commande pour bash)."""
    defauts = []
    for f, t in textes.items():
        for n, ligne in enumerate(t.split("\n"), 1):
            vus = sorted({c for c in ligne if caractere_ambigu(c)})
            if vus:
                defauts.append(("caracteres", f"{f}:{n} : caractère(s) {', '.join(f'U+{ord(c):04X}' for c in vus)} : la garde, "
                                              "YAML et bash ne découpent ni ne lisent cette ligne de la même façon ; une commande "
                                              "peut s'y cacher derrière un commentaire apparent (P10.31-t)"))
    return defauts


def juger_codes(textes: dict[str, str]) -> list[tuple[str, str]]:
    """Jugement TEXTUEL des flux : (contrôle, message) de chaque défaut."""
    defauts: list[tuple[str, str]] = juger_caracteres(textes)
    appels = []
    for f, t in textes.items():
        for n, l in lignes_de_commande(t):
            if APPEL.search(l):
                appels.append((f, n, l.strip()))
    uniques = [a for a in appels if a[2].startswith("exec ") and "--ignore-gitleaks-allow" in a[2]]
    if len(uniques) != 1:
        defauts.append(("appel_unique",
            f"{len(uniques)} appel(s) `exec … gitleaks detect … --ignore-gitleaks-allow` (l'enveloppe) ; "
            "il en faut exactement un"))
    elif not LOG_OPTS.search(uniques[0][2]):
        defauts.append(("log_opts",
            f"{uniques[0][0]}:{uniques[0][1]} : l'appel unique ne porte pas `--log-opts=\"{OPTIONS_HISTORIQUE}\"` : "
            "une clé ajoutée dans la résolution d'une fusion serait tue (P10.31-r)"))
    for f, n, l in appels:
        if uniques and (f, n, l) == uniques[0]:
            continue
        defauts.append(("hors_enveloppe",
            f"{f}:{n} lance gitleaks HORS de l'enveloppe `$RUNNER_TEMP/gitleaks-detect.sh` : `{l}` — "
            "un tel scan rouvre `gitleaks:allow` et `.gitleaksignore` ; appeler l'enveloppe"))
    if not any(re.search(r"find\b.*-name\s+\.gitleaksignore", l) for t in textes.values() for _, l in lignes_de_commande(t)):
        defauts.append(("gitleaksignore", "l'enveloppe ne cherche plus de `.gitleaksignore` à refuser"))
    toutes = [l for t in textes.values() for _, l in lignes_de_commande(t)]
    if not any(re.search(r"--git-path\s+info/attributes\b", l) for l in toutes) or not any(TEXTE_FORCE.search(l) for l in toutes):
        defauts.append(("texte_force",
            "l'enveloppe ne force plus le texte (`* diff` ajouté à `--git-path info/attributes`) : "
            "un attribut `-diff` tairait le fichier au scan d'historique (P10.31-o)"))
    principaux = [(f, i) for f, t in textes.items() for i in localiser_principaux(t.splitlines())]
    if not principaux:
        defauts.append(("principal_absent", "aucun pas `id: gitleaks` (le scan principal) n'est trouvé"))
    elif len(principaux) > 1:
        defauts.append(("principaux", "plusieurs pas `id: gitleaks` (" + ", ".join(f"{f}:{i + 1}" for f, i in principaux)
                                      + ") : il en faut exactement un, le seul jugé et joué (P10.31-t)"))
    for f, i in principaux[:1]:
        lignes = textes[f].splitlines()
        debut, fin = bloc_du_pas(lignes, i)
        travail = travail_du_pas(lignes, i)
        if not any(ENVELOPPE.search(l) for l in lignes[debut:fin] if not _commentaire(l)):
            defauts.append(("principal_enveloppe", f"{f} : le pas `id: gitleaks` n'appelle pas `$RUNNER_TEMP/gitleaks-detect.sh`"))
        defauts += juger_pas_principal_texte(f, lignes, debut, fin)
        defauts += juger_verdict(f, lignes, (debut, fin), travail)
        defauts += juger_travail(f, lignes, travail)
    defauts += juger_variables(textes)
    return defauts


def juger(textes: dict[str, str]) -> list[str]:
    return [m for _, m in juger_codes(textes)]


# `P10.31-t` — CROISEMENT AVEC UN ANALYSEUR YAML. La localisation ci-dessus découpe par lignes et par retrait : un pas
# `id: gitleaks` et son verdict réindentés EN TEXTE dans le `run: |` de pas porteurs qui sortent 0 étaient jugés et
# joués alors que GitHub ne les lance jamais (mesuré sur 2460bf55 : garde verte, aucun scan). Le pas jugé doit donc
# être le pas que YAML lit : un seul pas `id == "gitleaks"` dans les flux, qui commence à la ligne du pas jugé, dont
# le `run` est OCTET POUR OCTET celui qui est jugé et joué ; de même pour le verdict, dans le même travail et après.
class _Correspondance(dict):
    """Mapping lu par YAML, avec la ligne (comptée depuis 0) où il commence."""
    ligne = -1


def _construire_correspondance(chargeur, noeud):
    donnees = _Correspondance()
    donnees.ligne = noeud.start_mark.line
    yield donnees
    # Une clé répétée : PyYAML garde la dernière, un autre lecteur peut garder la première. Refusée (hors fusion `<<`).
    vues = set()
    for cle, _ in noeud.value:
        if cle.tag == "tag:yaml.org,2002:merge":
            continue
        k = chargeur.construct_object(cle, deep=True)
        try:
            repetee = k in vues
        except TypeError:
            continue
        if repetee:
            raise yaml.constructor.ConstructorError(None, None, f"clé `{k}` répétée dans un même mapping", cle.start_mark)
        vues.add(k)
    donnees.update(chargeur.construct_mapping(noeud))


def _chargeur():
    class Chargeur(yaml.SafeLoader):
        pass
    Chargeur.add_constructor("tag:yaml.org,2002:map", _construire_correspondance)
    return Chargeur


def lire_yaml(textes: dict[str, str]) -> tuple[dict, list[tuple[str, str]]]:
    docs, defauts = {}, []
    chargeur = _chargeur()
    for f, t in textes.items():
        try:
            docs[f] = yaml.load(t, Loader=chargeur)
        except yaml.YAMLError as e:
            defauts.append(("yaml_illisible", f"{f} : illisible pour l'analyseur YAML ({' '.join(str(e).split())}) : le pas "
                                              "jugé ne peut être croisé avec le pas que GitHub lance (P10.31-t)"))
    return docs, defauts


def _pas_des_travaux(doc):
    """(travail, rang, pas) de chaque pas de chaque travail d'un flux lu par YAML."""
    travaux = doc.get("jobs") if isinstance(doc, dict) else None
    for travail in (travaux.values() if isinstance(travaux, dict) else ()):
        pas = travail.get("steps") if isinstance(travail, dict) else None
        for rang, p in enumerate(pas if isinstance(pas, list) else ()):
            if isinstance(p, dict):
                yield travail, rang, p


def localiser_pas_juges(textes: dict[str, str]):
    """(flux, début du pas principal, son run, ligne de verdict, début du pas de verdict, son run) tels que la garde
    les JUGE et les JOUE ; None sans pas `id: gitleaks` ; ligne et run du verdict à None sans ligne de verdict unique."""
    principaux = [(f, i) for f, t in textes.items() for i in localiser_principaux(t.splitlines())]
    if not principaux:
        return None
    f, i = principaux[0]
    lignes = textes[f].splitlines()
    debut, fin = bloc_du_pas(lignes, i)
    run = extraire_run("\n".join(lignes[debut:fin]))
    verdicts = localiser_verdict(lignes)
    if len(verdicts) != 1:
        return f, debut, run, None, None, None
    vd, vf = bloc_du_pas(lignes, verdicts[0])
    return f, debut, run, verdicts[0], vd, extraire_run("\n".join(lignes[vd:vf]))


def croiser_avec_yaml(textes: dict[str, str], juges=None) -> list[tuple[str, str]]:
    """Le pas principal et le verdict JUGÉS sont ceux que YAML lit (voir plus haut) ; le travail lu par YAML n'a que
    les clés admises, le flux pas de `defaults` (ce que (c2) lit par le retrait, YAML le lit par les clés)."""
    docs, defauts = lire_yaml(textes)
    if defauts:
        return defauts
    juges = localiser_pas_juges(textes) if juges is None else juges
    if juges is None:
        return []  # aucun pas `id: gitleaks` dans le texte : le contrôle textuel `principal_absent` refuse déjà
    f, debut, run, _, vdebut, run_verdict = juges
    trouves = [(g, travail, rang, p) for g, doc in docs.items() for travail, rang, p in _pas_des_travaux(doc)
               if p.get("id") == "gitleaks"]
    if len(trouves) != 1:
        return [("yaml_principal_compte", f"{len(trouves)} pas `id: gitleaks` lus par YAML ("
                 + ", ".join(f"{g}:{p.ligne + 1}" for g, _, _, p in trouves) + f") ; la garde a jugé et joué {f}:{debut + 1} : "
                 "il en faut exactement un, celui-là — sinon le pas jugé n'est pas celui que GitHub lance (P10.31-t)")]
    g, travail, rang, p = trouves[0]
    if (g, p.ligne) != (f, debut):
        defauts.append(("yaml_principal_lieu", f"le pas `id: gitleaks` lu par YAML commence en {g}:{p.ligne + 1}, la garde a "
                                               f"jugé et joué celui de {f}:{debut + 1} (P10.31-t)"))
    if p.get("run") != run:
        defauts.append(("yaml_principal_run", f"{g}:{p.ligne + 1} : le `run` du pas `id: gitleaks` lu par YAML n'est pas, "
                                              "octet pour octet, celui que la garde a jugé et joué (P10.31-t)"))
    if set(p) != set(CLES_DU_PAS_PRINCIPAL) or p.get("if") != "always()" or p.get("continue-on-error") is not True:
        defauts.append(("yaml_principal_cles", f"{g}:{p.ligne + 1} : clés lues par YAML {sorted(map(str, p))}, `if` "
                                               f"{p.get('if')!r}, `continue-on-error` {p.get('continue-on-error')!r} ; exigés "
                                               f"{sorted(CLES_DU_PAS_PRINCIPAL)}, `always()`, `true` (P10.31-t)"))
    if set(map(str, travail)) - CLES_DU_TRAVAIL or "defaults" in docs[g]:
        defauts.append(("yaml_travail_cles", f"{g} : le travail du pas `id: gitleaks` lu par YAML porte "
                                             f"{sorted(set(map(str, travail)) - CLES_DU_TRAVAIL)}, le flux "
                                             f"{'un' if 'defaults' in docs[g] else 'aucun'} `defaults` (admis : "
                                             f"{', '.join(sorted(CLES_DU_TRAVAIL))}, et aucun `defaults`) (P10.31-t)"))
    if run_verdict is None:
        return defauts  # pas de ligne de verdict unique : le contrôle textuel `verdict_compte` refuse déjà
    # Dans le flux du pas lu (`g`) : si ce n'est pas celui du pas jugé, `yaml_principal_lieu` refuse déjà.
    verdicts = [(r, q) for r, q in enumerate(travail["steps"]) if isinstance(q, dict) and q.ligne == vdebut]
    if len(verdicts) != 1 or verdicts[0][0] <= rang:
        defauts.append(("yaml_verdict_lieu", f"aucun pas lu par YAML ne commence en {f}:{vdebut + 1} (le verdict jugé et joué) "
                                             f"dans le travail du pas `id: gitleaks`, après lui (P10.31-t)"))
        return defauts
    q = verdicts[0][1]
    if q.get("run") != run_verdict:
        defauts.append(("yaml_verdict_run", f"{f}:{vdebut + 1} : le `run` du verdict lu par YAML n'est pas, octet pour octet, "
                                            "celui que la garde a jugé et joué (P10.31-t)"))
    if set(q) != set(CLES_DU_VERDICT) or q.get("if") != "always()":
        defauts.append(("yaml_verdict_cles", f"{f}:{vdebut + 1} : clés du verdict lues par YAML {sorted(map(str, q))}, `if` "
                                             f"{q.get('if')!r} ; exigés {sorted(CLES_DU_VERDICT)}, `always()` (P10.31-t)"))
    return defauts


TETE_OK = "name: f\non: push\njobs:\n  security:\n    runs-on: ubuntu-24.04\n    steps:\n"
ENV_OK = (
    "      - name: config\n        run: |\n"
    "          ign=\"$(find \"$src\" -name .gitleaksignore -print -quit)\"\n"
    "          if att=\"$(git -C \"$src\" rev-parse --path-format=absolute --git-path info/attributes)\"; then\n"
    "            printf '* diff\\n' >> \"$att\"; fi\n"
    "          exec \"${GITLEAKS_BIN:-/tmp/gitleaks}\" detect --source . --ignore-gitleaks-allow"
    " --log-opts=\"--full-history --all --diff-merges=separate\" \"$@\"\n"
)
APPEL_OK = APPEL_EXACT
# Les sept commandes du pas principal fabriqué, une par entrée du gabarit (la première suivie d'un commentaire).
GABARIT_OK_LIGNES = [
    "set -euo pipefail",
    "GL_VER=8.24.3",
    "GL_SHA=" + "0" * 64,
    "curl -sSfL -o /tmp/gitleaks.tgz \"https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz\"",
    "echo \"${GL_SHA}  /tmp/gitleaks.tgz\" | sha256sum -c -",
    "tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks",
    APPEL_OK,
]
PRINCIPAL_OK = (
    "      - name: Secret scan\n        id: gitleaks\n        if: always()\n        continue-on-error: true\n"
    "        run: |\n"
    "          " + GABARIT_OK_LIGNES[0] + "\n"
    "          # jadis : /tmp/gitleaks detect --source .\n"
    + "".join(f"          {l}\n" for l in GABARIT_OK_LIGNES[1:]) +
    "      - name: verdict\n        if: always()\n        run: |\n"
    "          set -u\n"
    "          echo \"gitleaks : ${{ steps.gitleaks.outcome }}\"\n"
    "          rc=0\n"
    "          [ \"${{ steps.gitleaks.outcome }}\" = success ] || { echo \"::error::scan.\"; rc=1; }\n"
    "          exit $rc\n"
    "      - name: suite\n        run: |\n          echo suite\n"
)
VERDICT_OK = '          [ "${{ steps.gitleaks.outcome }}" = success ] || { echo "::error::scan."; rc=1; }\n'
SAIN = TETE_OK + ENV_OK + PRINCIPAL_OK


def _principal(remplace: str, par: str) -> str:
    if SAIN.count(remplace) != 1:
        raise AncreIntrouvable(f"retouche fabriquée sans ancre unique : {remplace!r}")
    return SAIN.replace(remplace, par)


def valider_linstrument() -> list[str]:
    """Témoins positif et négatifs, fabriqués : la garde ne se croit pas elle-même. Chaque flux hostile déclare
    l'ensemble EXACT des contrôles textuels qui le refusent : retirer un contrôle change un ensemble, la garde
    refuse alors de conclure."""
    faux = []
    if juger_codes({"ok.yml": SAIN}):
        faux.append("le flux sain fabriqué est refusé : " + "; ".join(juger({"ok.yml": SAIN})))
    principal_avant = "        continue-on-error: true\n        run: |\n"
    verdict_avant = "      - name: verdict\n        if: always()\n"
    hostiles = {
        "scan principal direct": (_principal(APPEL_OK, '/tmp/gitleaks detect --source . --config c.toml'),
                                  {"hors_enveloppe", "principal_enveloppe", "gabarit"}),
        "appel direct en plus de l'enveloppe": (SAIN + "          gitleaks git . --config c.toml\n", {"hors_enveloppe"}),
        "appel par GITLEAKS_BIN": (SAIN + "          \"${GITLEAKS_BIN}\" dir .\n", {"hors_enveloppe", "variables"}),
        "conteneur": (SAIN + "          docker run zricethezav/gitleaks:v8 detect\n", {"hors_enveloppe"}),
        "enveloppe sans --ignore-gitleaks-allow": (SAIN.replace(" --ignore-gitleaks-allow", ""), {"appel_unique", "hors_enveloppe"}),
        # `P10.31-r` : seul le contrôle (2c) refuse ceux-là.
        "enveloppe sans lecture des fusions": (SAIN.replace(" --diff-merges=separate", ""), {"log_opts"}),
        "enveloppe avec -m seul": (SAIN.replace('--log-opts="--full-history --all --diff-merges=separate"', "--log-opts=-m"), {"log_opts"}),
        "enveloppe sans refus de .gitleaksignore": (SAIN.replace("-name .gitleaksignore", "-name x"), {"gitleaksignore"}),
        "pas principal absent": (TETE_OK + ENV_OK, {"principal_absent"}),
        # `P10.31-o` : seul le contrôle (2b) refuse ceux-là.
        "enveloppe sans texte forcé": (SAIN.replace("            printf '* diff\\n' >> \"$att\"; fi\n", "            fi\n"), {"texte_force"}),
        "texte forcé désarmé": (SAIN.replace("printf '* diff", "printf '* -diff"), {"texte_force"}),
        "texte forcé hors de info/attributes": (SAIN.replace("--git-path info/attributes", "--git-dir"), {"texte_force"}),
        # Le motif (1) ne voit pas un binaire lancé par une variable ; (3) et le gabarit le refusent.
        "scan principal par une variable": (_principal(APPEL_OK, 'GL=/tmp/gitleaks; "$GL" detect --source . --config c.toml'),
                                            {"principal_enveloppe", "gabarit"}),
        # Seul le compte des `exec` (exactement un) refuse ceux-là (et (d) la lecture sans repli).
        "enveloppe sans exec reconnu": (SAIN.replace('"${GITLEAKS_BIN:-/tmp/gitleaks}" detect', '"$GITLEAKS_BIN" detect'),
                                        {"appel_unique", "variables"}),
        "alias file": (SAIN + "          gitleaks file . --config c.toml\n", {"hors_enveloppe"}),
        "drapeau global avant la sous-commande": (SAIN + "          /tmp/gitleaks --no-banner dir .\n", {"hors_enveloppe"}),
        # `P10.31-t` (a) : le pas principal neutralise l'enveloppe qu'il appelle ; le gabarit fermé les refuse tous.
        "code avalé par || true": (_principal(APPEL_OK, APPEL_OK + " || true"), {"gabarit"}),
        "code avalé par ; true": (_principal(APPEL_OK, APPEL_OK + "; true"), {"gabarit"}),
        "appel suivi d'un &": (_principal(APPEL_OK, APPEL_OK + " &"), {"gabarit"}),
        "binaire posé en préfixe": (_principal(APPEL_OK, "GITLEAKS_X=/tmp/neutre " + APPEL_OK), {"gabarit"}),
        "set +e avant l'appel": (_principal("set -euo pipefail\n", "set -euo pipefail\n          set +e\n"), {"gabarit"}),
        "sans set -euo pipefail": (_principal("          set -euo pipefail\n", ""), {"gabarit"}),
        "trap qui force la sortie": (_principal("set -euo pipefail\n", "set -euo pipefail\n          trap 'exit 0' EXIT\n"), {"gabarit"}),
        "fonction bash": (_principal("          " + APPEL_OK, "          bash() { return 0; }\n          " + APPEL_OK), {"gabarit"}),
        "appel continué depuis la ligne d'avant": (_principal("          " + APPEL_OK, "          true || \\\n          " + APPEL_OK), {"gabarit"}),
        "commande après l'appel": (_principal(APPEL_OK, APPEL_OK + "\n          exit 0"), {"gabarit"}),
        "répertoire courant changé": (_principal("          " + APPEL_OK, "          cd \"$RUNNER_TEMP\"\n          " + APPEL_OK), {"gabarit"}),
        "--no-git avant --exit-code 1": (_principal("--exit-code 1\n", "--no-git --exit-code 1\n"), {"gabarit"}),
        "configuration vide": (_principal('--config "$GITHUB_WORKSPACE/.gitleaks-ci.toml"', "--config /dev/null"), {"gabarit"}),
        "fichier d'ignorés": (_principal("--exit-code 1\n", '--gitleaks-ignore-path "$GITHUB_WORKSPACE/i.txt" --exit-code 1\n'), {"gabarit"}),
        "code de sortie 0": (_principal("--exit-code 1\n", "--exit-code 0\n"), {"gabarit"}),
        # `P10.31-t` : clés du pas principal hors de la grammaire fermée.
        "shell détourné": (_principal(principal_avant, "        continue-on-error: true\n        shell: true {0}\n        run: |\n"), {"cles_pas"}),
        "shell en clé citée": (_principal(principal_avant, "        continue-on-error: true\n        \"shell\": true {0}\n        run: |\n"), {"cles_pas"}),
        "shell avec espace avant le deux-points": (_principal(principal_avant, "        continue-on-error: true\n        shell : true {0}\n        run: |\n"), {"cles_pas"}),
        "env BASH_ENV sur le pas": (_principal(principal_avant, "        continue-on-error: true\n        env:\n          BASH_ENV: /tmp/x\n        run: |\n"), {"cles_pas"}),
        "working-directory cité": (_principal(principal_avant, "        continue-on-error: true\n        \"working-directory\": /tmp\n        run: |\n"), {"cles_pas"}),
        "pas principal sauté": (_principal("        id: gitleaks\n        if: always()\n", "        id: gitleaks\n        if: false\n"), {"cles_pas_valeur"}),
        "clé répétée": (_principal("        id: gitleaks\n        if: always()\n", "        id: gitleaks\n        if: always()\n        if: always()\n"), {"cles_pas_repetee"}),
        "continue-on-error absent": (_principal("        continue-on-error: true\n        run: |\n", "        run: |\n"), {"cles_pas_absente"}),
        # Une clé admise ENFOUIE dans un scalaire replié (`name: >`) n'est pas une clé du pas : seule sa position la refuse.
        "clé enfouie dans un scalaire": (_principal("      - name: Secret scan\n        id: gitleaks\n        if: always()\n",
                                                    "      - name: >\n          if: always()\n        id: gitleaks\n"), {"cles_pas", "cles_pas_absente"}),
        "second pas id: gitleaks": (SAIN + "      - name: bis\n        id: gitleaks\n        run: |\n          echo bis\n", {"principaux"}),
        # `P10.31-t` (c) : le verdict ne rougit plus le travail.
        "ligne de verdict retirée": (_principal(VERDICT_OK, ""), {"verdict_compte"}),
        "verdict sous continue-on-error": (_principal(verdict_avant, verdict_avant + "        continue-on-error: true\n"), {"verdict_cles"}),
        "verdict conditionnel": (_principal(verdict_avant, "      - name: verdict\n        if: success()\n"), {"verdict_cles_valeur"}),
        "verdict sans if": (_principal(verdict_avant, "      - name: verdict\n"), {"verdict_cles_absente"}),
        "shell sur le verdict": (_principal(verdict_avant, verdict_avant + "        shell: true {0}\n"), {"verdict_cles"}),
        "shell cité sur le verdict": (_principal(verdict_avant, verdict_avant + "        \"shell\": true {0}\n"), {"verdict_cles"}),
        "verdict qui sort 0": (_principal("          exit $rc\n", "          exit 0\n"), {"verdict_grammaire"}),
        "trap dans le verdict": (_principal("          set -u\n", "          set -u\n          trap 'exit 0' EXIT\n"), {"verdict_grammaire"}),
        "rc remis à zéro par true;": (_principal("          exit $rc\n", "          true; rc=0\n          exit $rc\n"), {"verdict_grammaire"}),
        "rc redéclaré": (_principal("          exit $rc\n", "          declare rc=0\n          exit $rc\n"), {"verdict_grammaire"}),
        "verdict sous if false": (_principal(VERDICT_OK, "          if false; then\n" + VERDICT_OK + "          fi\n"), {"verdict_grammaire"}),
        "verdict dans un heredoc": (_principal(VERDICT_OK, "          : <<'X'\n" + VERDICT_OK + "          X\n"), {"verdict_grammaire"}),
        "verdict dans un autre travail": (_principal(verdict_avant, "  autre:\n    runs-on: ubuntu-24.04\n    steps:\n" + verdict_avant), {"verdict_travail"}),
        # `P10.31-t` : le travail ou le flux détournent le pas principal sans le toucher.
        "travail sous continue-on-error": (_principal("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    continue-on-error: true\n"), {"travail_cles"}),
        "shell par défaut du travail": (_principal("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    defaults:\n      run:\n        shell: true {0}\n"), {"travail_cles"}),
        "shell par défaut du flux": (_principal("on: push\n", "on: push\ndefaults:\n  run:\n    shell: true {0}\n"), {"defauts_flux"}),
        # `P10.31-t` (d) : une variable qui détourne l'appel est posée.
        "GITLEAKS_BIN en env de flux": (_principal("on: push\n", "on: push\nenv:\n  GITLEAKS_BIN: /bin/true\n"), {"variables"}),
        "GITLEAKS_BIN par GITHUB_ENV": (_principal("          ign=", "          echo \"GITLEAKS_BIN=/bin/true\" >> \"$GITHUB_ENV\"\n          ign="), {"variables"}),
        "GITLEAKS_BIN affecté par :=": (_principal("          ign=", "          set -a; : \"${GITLEAKS_BIN:=/bin/true}\"\n          ign="), {"variables"}),
        "GITLEAKS_BIN en préfixe": (_principal(APPEL_OK, "GITLEAKS_BIN=/bin/true " + APPEL_OK), {"gabarit", "variables"}),
        "GITLEAKS_CONF exporté": (SAIN + "          export GITLEAKS_CONF=x\n", {"variables"}),
        "GITLEAKS_DETECT lu sans repli": (SAIN + "          echo \"$GITLEAKS_DETECT\"\n", {"variables"}),
        # `P10.31-t` : caractères ambigus. U+2028 coupe la ligne pour `str.splitlines()`, pas pour bash ni pour YAML :
        # le `#…` qui suit est un commentaire pour la garde, une commande pour bash (mesuré : `|| true` après l'appel,
        # `trap 'exit 0' EXIT` dans le verdict, `export GITLEAKS_BIN=` derrière le `tar`, garde verte, scan neutralisé).
        "U+2028 qui masque une affectation dans un autre pas": (
            SAIN + "          echo suite2\u2028#;echo \"GITLEAKS_BIN=/bin/true\" >> \"$GITHUB_ENV\"\n", {"caracteres"}),
        "U+2028 qui masque un || true après l'appel": (_principal(APPEL_OK + "\n", APPEL_OK + "\u2028#||true\n"), {"caracteres"}),
        "U+0085 qui masque un trap dans le verdict": (
            _principal('outcome }}"\n          rc=0', 'outcome }}"\x85#;trap \'exit 0\' EXIT\n          rc=0'),
            {"caracteres", "verdict_cles"}),
        "blanc insécable dans le run": (_principal("# jadis :", "#\u00a0jadis :"), {"caracteres"}),
        "caractère de format dans le run": (_principal("# jadis :", "# jadis\u202e :"), {"caracteres"}),
        # `P10.31-t` : une clé posée APRÈS le corps de `run: |`, au retrait des clés, en sort (bord `_retrait(l) > k`).
        "shell après le corps du run principal": (_principal(APPEL_OK + "\n", APPEL_OK + "\n        shell: true {0}\n"), {"cles_pas"}),
        "shell après le corps du verdict": (_principal("          exit $rc\n", "          exit $rc\n        shell: true {0}\n"),
                                            {"verdict_cles"}),
        # `P10.31-t` : un message du verdict qui lit l'environnement : rouge sous la garde (jouée sans
        # `GITHUB_ACTIONS`), vert sur GitHub (mesuré). Seule la grammaire le refuse, l'exécution ne le voit pas.
        "echo du verdict qui lit l'environnement": (
            _principal("          exit $rc\n", "          echo \"${GITHUB_ACTIONS:+$((rc=0))}${{ steps.gitleaks.outcome }}\"\n"
                                                 "          exit $rc\n"), {"verdict_grammaire"}),
        "echo du verdict qui substitue une commande": (
            _principal("          exit $rc\n", "          echo \"`true`${{ steps.gitleaks.outcome }}\"\n          exit $rc\n"),
            {"verdict_grammaire"}),
        # Un message libre ferme sa chaîne et sort 0 sur GitHub seulement (`set -u` le fait échouer sous la garde).
        "message d'erreur du verdict qui sort 0 sur GitHub": (
            _principal('"::error::scan."', '"::error::scan."; [ -z "$GITHUB_ACTIONS" ] || exit 0; echo "x"'), {"verdict_grammaire"}),
        # Un témoin par exclusion de la classe `[^"$`\\]*` (le précédent porte `"` ET `$`, il n'isole ni l'un ni l'autre).
        # Le guillemet seul, sans `$` : la chaîne fermée, `printenv` lit l'environnement. Scan à failure, verdict joué
        # (`bash -eo pipefail`, bash 5.2) : rc=1 sans GITHUB_ACTIONS, rc=0 avec (mesuré, pour l'echo comme pour le message).
        "echo du verdict qui ferme sa chaîne": (
            _principal("          exit $rc\n", "          echo \"x\"; printenv GITHUB_ACTIONS >/dev/null && exit 0; "
                                                 "echo \"${{ steps.gitleaks.outcome }}\"\n          exit $rc\n"), {"verdict_grammaire"}),
        "message d'erreur du verdict qui ferme sa chaîne": (
            _principal('"::error::scan."', '"::error::scan."; printenv GITHUB_ACTIONS >/dev/null && exit 0; echo "x"'),
            {"verdict_grammaire"}),
        # Le `$` seul, sans guillemet ni accolade (une accolade ferait refuser la ligne par la localisation, pas par la
        # grammaire) : le message lit une variable que l'exécution de la garde ne porte pas. Aucune forme sans guillemet ni
        # accolade n'a été trouvée qui rende 0 sur GitHub (`$((IFS=GITHUB_RUN_ATTEMPT))` : `exit $rc` sort 2) ; le témoin
        # tient la règle de principe, un message qui dépend de l'environnement n'est pas jugé par l'exécution.
        "message d'erreur du verdict qui lit l'environnement": (
            _principal('"::error::scan."', '"::error::scan $GITHUB_ACTIONS."'), {"verdict_grammaire"}),
    }
    for nom, (t, attendus) in hostiles.items():
        try:
            codes = {c for c, _ in juger_codes({"h.yml": t})}
        except ExtractionImpossible as e:
            faux.append(f"le flux hostile « {nom} » fait refuser de conclure ({e}), attendu un refus par {sorted(attendus)}")
            continue
        if not codes:
            faux.append(f"le flux hostile « {nom} » est admis")
        elif codes != attendus:
            faux.append(f"le flux hostile « {nom} » est refusé par {sorted(codes)}, attendu {sorted(attendus)}")
    # Flux que la garde doit refuser de JUGER (code 2) : le `run:` principal n'est pas jouable tel quel.
    sans_verdict = {
        "expression dans le pas principal": _principal("          tar -xzf", "          echo '${{ github.sha }}'\n          tar -xzf"),
        "run principal non littéral": _principal("        run: |\n          set -euo pipefail\n", "        run: set -euo pipefail\n"),
    }
    for nom, t in sans_verdict.items():
        try:
            juger_codes({"h.yml": t})
            faux.append(f"le flux « {nom} » est jugé, attendu un refus de conclure (code 2)")
        except ExtractionImpossible:
            pass
    return faux + valider_grammaires() + valider_croisement()


def _voisins(s: str) -> set[str]:
    """Toutes les commandes à UNE retouche de `s` : insertion, retrait ou remplacement d'un caractère de l'alphabet."""
    vus = set()
    for i in range(len(s) + 1):
        for p in ALPHABET_SONDE:
            vus.add(s[:i] + p + s[i:])
            if i < len(s):
                vus.add(s[:i] + p + s[i + 1:])
        if i < len(s):
            vus.add(s[:i] + s[i + 1:])
    vus.discard(s)
    return vus


def _flux_temoin(famille: str, n: int, commande: str) -> str:
    """Le flux sain, à ceci près : une commande AJOUTÉE au verdict (avant `exit $rc`), ou la `n`-ième du pas principal
    REMPLACÉE."""
    if famille == "verdict":
        return _principal("          exit $rc\n", f"          {commande}\n          exit $rc\n")
    return _principal(f"          {GABARIT_OK_LIGNES[n]}\n", f"          {commande}\n")


def _flux_refuse(t: str) -> bool:
    try:
        return bool(juger_codes({"h.yml": t}))
    except ExtractionImpossible:
        return True  # la garde refuse de conclure : elle ne rend pas vert


def _temoins_de_composants(famille: str, composants, refuse) -> list[tuple[str, str | None]]:
    """(composant, commande) : pour CHAQUE composant, la commande qui ne diffère de l'échantillon que par lui, et que les
    composants refusent. Un littéral : chacun de ses caractères remplacé (par le premier caractère de l'alphabet qui
    fasse refuser, hors équivalents déclarés). Une classe : chacun de ses caractères exclus inséré ; son compte une
    unité sous le minimum et au-dessus du maximum. Les ancres sont éprouvées à part, pour chaque caractère."""
    s = _echantillon(composants)

    def premier(construire, bord):
        for p in ALPHABET_SONDE:
            if bord and (famille, bord, p) in EQUIVALENTS_DE_FLUX:
                continue
            c = construire(p)
            if c != s and refuse(c):
                return c
        return None

    temoins: list[tuple[str, str | None]] = []
    pos = 0
    for seg in composants:
        if seg[0] == "lit":
            for j, ch in enumerate(seg[1]):
                i = pos + j
                temoins.append((f"littéral {seg[1]!r}, caractère {j + 1} {ch!r}",
                                premier(lambda p, i=i: s[:i] + p + s[i + 1:], "debut" if i == 0 else None)))
            pos += len(seg[1])
            continue
        e = seg[2] if seg[0] == "sauf" else seg[5]
        reste = s[pos + len(e):]
        exclus = sorted(seg[1]) if seg[0] == "sauf" else [ch for ch in ALPHABET_SONDE if ch not in seg[2]]
        nom = f"classe sauf {seg[1]!r}" if seg[0] == "sauf" else f"classe {seg[1]}"
        for ch in exclus:
            temoins.append((f"{nom} : {ch!r} exclu", s[:pos] + ch + e + reste))
        if seg[0] == "parmi":
            if seg[3] > 0:
                temoins.append((f"{nom} : {seg[3] - 1} caractère(s), minimum {seg[3]}", s[:pos] + e[:seg[3] - 1] + reste))
            if seg[4] is not None:
                temoins.append((f"{nom} : {seg[4] + 1} caractères, maximum {seg[4]}",
                                s[:pos] + e + e[-1] * (seg[4] + 1 - len(e)) + reste))
        pos += len(e)
    return temoins


def valider_grammaires() -> list[str]:
    """`P10.31-t` : l'auto-épreuve ÉNUMÉRÉE des deux grammaires fermées (voir `COMPOSANTS_VERDICT`)."""
    faux: list[str] = []
    familles = [
        ("verdict", COMPOSANTS_VERDICT, GRAMMAIRE_VERDICT,
         lambda n, c: commande_de_verdict_admise(c),
         lambda n, c: any(composants_acceptent(k, c) for _, k in COMPOSANTS_VERDICT)),
        ("gabarit", COMPOSANTS_GABARIT, GABARIT_PAS_PRINCIPAL,
         commande_du_gabarit,
         lambda n, c: composants_acceptent(COMPOSANTS_GABARIT[n][1], c)),
    ]
    for famille, regles, expressions, expression_admet, composants_admettent in familles:
        if len(regles) != len(expressions):
            faux.append(f"{famille} : {len(expressions)} règle(s) écrite(s) en expressions, {len(regles)} en composants : "
                        "une règle sans composants n'est pas éprouvée")
            continue
        for n, (nom, composants) in enumerate(regles):
            for k, seg in enumerate(composants):
                if seg[0] == "lit":
                    continue
                suivant = composants[k + 1] if k + 1 < len(composants) else None
                if suivant is not None and (suivant[0] != "lit" or _admis_par(seg, suivant[1][0])):
                    faux.append(f"{famille} « {nom} » : la classe {k + 1} n'est pas suivie d'un littéral qu'elle exclut "
                                "(appariement glouton indéterminé)")
            s = _echantillon(composants)
            if not composants_acceptent(composants, s) or not re.fullmatch(expressions[n], s):
                faux.append(f"{famille} « {nom} » : l'échantillon {s!r} n'est pas admis par ses composants et par "
                            f"l'expression de même rang {expressions[n]!r}")
                continue
            # Différentiel exhaustif : chaque voisin reçoit le même verdict de l'expression et des composants.
            ecarts = [v for v in sorted(_voisins(s)) if expression_admet(n, v) != composants_admettent(n, v)]
            for v in ecarts[:3]:
                faux.append(f"{famille} « {nom} » : la commande {v!r} est {'admise' if expression_admet(n, v) else 'refusée'} "
                            f"par l'expression, {'admise' if composants_admettent(n, v) else 'refusée'} par ses composants "
                            "(restriction retirée, affaiblie ou ajoutée sans composant)")
            if ecarts:
                continue
            if _flux_refuse(_flux_temoin(famille, n, s)):
                faux.append(f"{famille} « {nom} » : le flux qui porte l'échantillon {s!r} est refusé")
                continue
            # Les ancres, EXHAUSTIVEMENT : chaque caractère avant ou après l'échantillon que les composants refusent doit
            # faire refuser le flux, sauf les équivalents déclarés — et ceux-là seulement, chacun admis (deux sens).
            admis_aux_bords = set()
            for bord in ("debut", "fin"):
                for p in ALPHABET_SONDE:
                    c = p + s if bord == "debut" else s + p
                    if not composants_admettent(n, c) and not _flux_refuse(_flux_temoin(famille, n, c)):
                        admis_aux_bords.add((famille, bord, p))
            declares = {k for k in EQUIVALENTS_DE_FLUX if k[0] == famille}
            for fam, bord, p in sorted(admis_aux_bords - declares):
                faux.append(f"{famille} « {nom} » : ancre de {bord} — le flux où {p!r} est ajouté est ADMIS sans être un "
                            "équivalent déclaré (P10.31-t)")
            for fam, bord, p in sorted(declares - admis_aux_bords):
                faux.append(f"{famille} « {nom} » : l'équivalent déclaré {p!r} en {bord} ({EQUIVALENTS_DE_FLUX[(fam, bord, p)]}) "
                            "est refusé : il ne dispense rien et doit sortir de la liste fermée")
            for composant, c in _temoins_de_composants(famille, composants, lambda c, n=n: not composants_admettent(n, c)):
                if c is None or composants_admettent(n, c):
                    faux.append(f"{famille} « {nom} », {composant} : aucune retouche que les composants refusent")
                elif not _flux_refuse(_flux_temoin(famille, n, c)):
                    faux.append(f"{famille} « {nom} », {composant} : le flux qui ne diffère du sain que par {c!r} est "
                                "ADMIS (P10.31-t)")
    return faux


PORTEUR_SCAN = "      - name: porteur du scan\n        run: |\n          exit 0\n"
PORTEUR_VERDICT = "      - name: porteur du verdict\n        if: always()\n        run: |\n          exit 0\n"
DEBUT_PRINCIPAL, DEBUT_VERDICT, DEBUT_SUITE = "      - name: Secret scan\n", "      - name: verdict\n", "      - name: suite\n"


def _bloc(t: str, debut: str, fin: str) -> tuple[int, int]:
    """Bornes du texte de la ligne `debut` (en tête de ligne) à la ligne `fin` exclue, chacune unique."""
    if t.count("\n" + debut) != 1 or t.count("\n" + fin) != 1:
        raise AncreIntrouvable(f"bloc fabriqué sans ancres uniques : {debut!r} … {fin!r}")
    return t.index("\n" + debut) + 1, t.index("\n" + fin) + 1


def _enfouir(t: str, debut: str, fin: str, porteur: str) -> str:
    """Le bloc réindenté de 4, en TEXTE dans le `run: |` d'un porteur qui sort 0."""
    i, j = _bloc(t, debut, fin)
    return t[:i] + porteur + "".join("    " + l for l in t[i:j].splitlines(True)) + t[j:]


def valider_croisement() -> list[str]:
    """Témoins du croisement YAML : le flux sain est admis ; chaque flux hostile est refusé par l'ensemble EXACT des
    contrôles de `croiser_avec_yaml` annoncé (chaque contrôle, et chaque moitié de condition, en a un qu'il est seul
    à refuser)."""
    faux = []
    # Admis : le flux sain, et une fusion `<<` (sa clé n'est pas une clé répétée, et n'a pas de constructeur propre).
    fusion = SAIN + "      - &pas\n        name: x\n        run: echo x\n      - <<: *pas\n        name: y\n"
    for nom, t in (("sain", SAIN), ("avec une fusion `<<`", fusion)):
        if croiser_avec_yaml({"ok.yml": t}):
            faux.append(f"le flux {nom} fabriqué est refusé par le croisement YAML : " + "; ".join(m for _, m in croiser_avec_yaml({"ok.yml": t})))
    leurre = _enfouir(_enfouir(SAIN, DEBUT_PRINCIPAL, DEBUT_VERDICT, PORTEUR_SCAN), DEBUT_VERDICT, DEBUT_SUITE, PORTEUR_VERDICT)
    # Le leurre mesuré : le texte seul l'admet (garde verte, aucun scan) ; seul le croisement le refuse.
    if juger_codes({"h.yml": leurre}):
        faux.append(f"le leurre YAML est refusé par le texte ({sorted({c for c, _ in juger_codes({'h.yml': leurre})})}) : "
                    "son témoin n'isole plus le croisement")
    i, j = _bloc(SAIN, DEBUT_PRINCIPAL, DEBUT_VERDICT)
    principal_cite = SAIN[i:j].replace("        id: gitleaks\n", '        id: "gitleaks"\n')
    vi, vj = _bloc(SAIN, DEBUT_VERDICT, DEBUT_SUITE)
    sain = localiser_pas_juges({"ok.yml": SAIN})
    hostiles = [
        ("leurre : pas principal et verdict en texte sous des porteurs `exit 0`", {"h.yml": leurre}, None, {"yaml_principal_compte"}),
        ("leurre du verdict seul", {"h.yml": _enfouir(SAIN, DEBUT_VERDICT, DEBUT_SUITE, PORTEUR_VERDICT)}, None, {"yaml_verdict_lieu"}),
        ("vrai pas à `id` cité, sa copie jugée en texte",
         {"h.yml": SAIN[:i] + PORTEUR_SCAN + "".join("    " + l for l in SAIN[i:j].splitlines(True)) + principal_cite + SAIN[j:]},
         None, {"yaml_principal_lieu"}),
        ("pas jugé dans un autre flux, au même rang de ligne",
         {"a.yml": leurre, "b.yml": TETE_OK + ENV_OK + PORTEUR_SCAN + principal_cite + SAIN[j:]}, None,
         {"yaml_principal_lieu", "yaml_verdict_lieu"}),
        ("run jugé autre que le run lu", {"ok.yml": SAIN}, sain[:2] + (sain[2] + "true\n",) + sain[3:], {"yaml_principal_run"}),
        ("run de verdict jugé autre que le run lu", {"ok.yml": SAIN}, sain[:5] + (sain[5] + "true\n",), {"yaml_verdict_run"}),
        ("clé de plus sur le pas principal", {"h.yml": _principal("        continue-on-error: true\n", "        continue-on-error: true\n        shell: bash\n")},
         None, {"yaml_principal_cles"}),
        ("pas principal conditionnel", {"h.yml": _principal("        if: always()\n        continue-on-error", "        if: success()\n        continue-on-error")},
         None, {"yaml_principal_cles"}),
        ("pas principal sans continue-on-error vrai", {"h.yml": _principal("continue-on-error: true", "continue-on-error: false")},
         None, {"yaml_principal_cles"}),
        ("travail sous continue-on-error", {"h.yml": _principal("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    continue-on-error: true\n")},
         None, {"yaml_travail_cles"}),
        ("defaults de flux en clé échappée", {"h.yml": _principal("on: push\n", 'on: push\n"\\x64efaults":\n  run:\n    shell: bash\n')},
         None, {"yaml_travail_cles"}),
        ("defaults de flux en clé explicite", {"h.yml": _principal("on: push\n", "on: push\n? defaults\n: run:\n    shell: bash\n")},
         None, {"yaml_travail_cles"}),
        # Le texte (c2) ne lit que le retrait 4 : le corps du travail réindenté d'un blanc lui cache la clé.
        ("travail réindenté d'un blanc sous continue-on-error",
         {"h.yml": TETE_OK.replace("    steps:", "    continue-on-error: true\n    steps:").replace("    ", "     ")
          + "".join(" " + l for l in (ENV_OK + PRINCIPAL_OK).splitlines(True))}, None, {"yaml_travail_cles"}),
        ("clé de plus sur le verdict", {"h.yml": _principal(DEBUT_VERDICT + "        if: always()\n", DEBUT_VERDICT + "        if: always()\n        shell: bash\n")},
         None, {"yaml_verdict_cles"}),
        ("verdict conditionnel", {"h.yml": _principal(DEBUT_VERDICT + "        if: always()\n", DEBUT_VERDICT + "        if: success()\n")},
         None, {"yaml_verdict_cles"}),
        ("verdict avant le pas principal", {"h.yml": SAIN[:i] + SAIN[vi:vj] + SAIN[i:j] + SAIN[vj:]}, None, {"yaml_verdict_lieu"}),
        ("second pas `id` cité", {"h.yml": SAIN + '      - name: bis\n        id: "gitleaks"\n        run: |\n          echo bis\n'},
         None, {"yaml_principal_compte"}),
        ("clé répétée", {"h.yml": _principal("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    runs-on: ubuntu-24.04\n")},
         None, {"yaml_illisible"}),
        ("YAML invalide", {"h.yml": SAIN + "  x: [\n"}, None, {"yaml_illisible"}),
        ("clé non hachable", {"h.yml": SAIN + "  ? [a, b]\n  : c\n"}, None, {"yaml_illisible"}),
    ]
    for nom, textes, juges, attendus in hostiles:
        codes = {c for c, _ in croiser_avec_yaml(textes, juges)}
        if codes != attendus:
            faux.append(f"le flux hostile « {nom} » est refusé par le croisement YAML par {sorted(codes)}, attendu {sorted(attendus)}")
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
    "exit \"${GARDE_RC:-0}\"\n"
)
CANARI = ["--config", "canari-p10-31-r.toml", "--exit-code", "1"]


def _lire_journal(journal: str) -> list[tuple[str, list[str]]]:
    appels: list[tuple[str, list[str]]] = []
    with open(journal, encoding="utf-8", errors="replace") as fh:
        for l in fh.read().splitlines():
            genre, _, val = l.partition("\t")
            if genre == "APPEL":
                appels.append((val, []))
            elif genre == "ARG" and appels:
                appels[-1][1].append(val)
    return appels


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
    return r.returncode, _lire_journal(journal), (r.stdout + r.stderr).strip()[-300:]


def _preparer(dossier: str) -> str:
    """Faux binaire et dépôt jetable (un commit, jamais signé : `P10.31-t`) ; rend le chemin du dépôt."""
    faux = os.path.join(dossier, "faux-gitleaks")
    with open(faux, "w") as fh:
        fh.write(FAUX_BINAIRE)
    os.chmod(faux, 0o755)
    depot = os.path.join(dossier, "depot")
    os.mkdir(depot)
    for c in (["init", "-q"], ["-c", "user.name=garde", "-c", "user.email=garde@invalid", "-c", "commit.gpgsign=false",
                               "commit", "-q", "--allow-empty", "-m", "garde"]):
        subprocess.run(["git", "-C", depot, *c], check=True, capture_output=True, timeout=30)
    return depot


def _log_opts(args: list[str]) -> list[str]:
    vals = []
    for i, a in enumerate(args):
        if a.startswith("--log-opts="):
            vals.append(a[len("--log-opts="):])
        elif a == "--log-opts":
            vals.append(args[i + 1] if i + 1 < len(args) else "")
    return vals


# `P10.31-t` : un lancement porte EXACTEMENT ces arguments, puis ceux de l'appelant et rien d'autre. Un drapeau
# ajouté (`--no-git`, `--baseline-path`, `--gitleaks-ignore-path`, `--config /dev/null`), par l'enveloppe ou par
# l'appelant, taisait un vrai secret (mesuré en 8.24.3) en laissant passer tous les contrôles d'option ci-dessous.
LANCEMENT_ENVELOPPE = ["detect", "--source", ".", "--ignore-gitleaks-allow", "--log-opts=" + OPTIONS_HISTORIQUE]


def _juger_lancement(args: list[str], appelant: list[str]) -> list[tuple[str, str]]:
    """Les options qu'un lancement de l'enveloppe doit porter (communes à l'enveloppe et au pas principal)."""
    d = []
    if args != LANCEMENT_ENVELOPPE + appelant:
        d.append(("exact", f"le lancement porte {args}, attendu EXACTEMENT {LANCEMENT_ENVELOPPE + appelant} : un drapeau "
                           "de plus ou de moins peut taire un secret (P10.31-t)"))
    if args[:3] != ["detect", "--source", "."]:
        d.append(("debut", f"le lancement ne commence pas par `detect --source .` : {args[:3]}"))
    if "--ignore-gitleaks-allow" not in args:
        d.append(("allow", "le lancement ne porte pas `--ignore-gitleaks-allow` (un `gitleaks:allow` tairait une clé)"))
    lo = _log_opts(args)
    if lo != [OPTIONS_HISTORIQUE]:
        d.append(("historique", f"options d'historique {lo}, attendu exactement [{OPTIONS_HISTORIQUE!r}] : "
                                "sans elles une clé ajoutée dans la résolution d'une fusion est tue (P10.31-r)"))
    return d


def controler_execution(corps: str) -> list[tuple[str, str]]:
    """Joue l'enveloppe contre un faux binaire, dans un dépôt jetable ; rend les défauts (contrôle, message)."""
    defauts: list[tuple[str, str]] = []
    dossier = tempfile.mkdtemp(prefix="garde-gitleaks-")
    try:
        depot = _preparer(dossier)
        rc, appels, sortie = _jouer(dossier, corps, depot, CANARI)
        if rc != 0:
            defauts.append(("rc_sain", f"sur un dépôt sain, l'enveloppe rend le code {rc} (attendu 0, celui du faux binaire) : {sortie}"))
        if len(appels) != 1:
            defauts.append(("lancements",
                f"{len(appels)} lancement(s) du binaire de `GITLEAKS_BIN` ; il en faut exactement un "
                "(un second scannerait hors des options exigées ; aucun : le binaire lancé n'est pas celui de `GITLEAKS_BIN`)"))
        for cwd, args in appels:
            if os.path.realpath(cwd) != os.path.realpath(depot):
                defauts.append(("cwd", f"le binaire est lancé depuis {cwd}, pas depuis le dépôt scanné"))
            defauts += _juger_lancement(args, CANARI)
            if args[-len(CANARI):] != CANARI:
                defauts.append(("fin", "les arguments de l'appelant ne sont pas transmis en fin du lancement"))
        att = subprocess.run(["git", "-C", depot, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes"],
                             check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        try:
            with open(att, encoding="utf-8") as fh:
                derniere = [l for l in fh.read().splitlines() if l.strip()][-1:]
        except OSError:
            derniere = []
        if derniere != ["* diff"]:
            defauts.append(("attributs", f"après l'appel, la dernière ligne de info/attributes est {derniere}, attendu ['* diff'] (texte non forcé)"))
        with open(os.path.join(depot, ".gitleaksignore"), "w") as fh:
            fh.write("x:y:private-key:1\n")
        rc, appels, _ = _jouer(dossier, corps, depot, CANARI)
        if rc != 3 or appels:
            defauts.append(("ignore3", f"un `.gitleaksignore` rend le code {rc} et {len(appels)} lancement(s), attendu 3 et aucun"))
        os.remove(os.path.join(depot, ".gitleaksignore"))
        for lo in (["--log-opts=--first-parent"], ["--log-opts", "--first-parent"]):
            rc, appels, _ = _jouer(dossier, corps, depot, [*CANARI, *lo])
            if rc != 5 or appels:
                defauts.append(("logopts5", f"un appel avec {' '.join(lo)} rend le code {rc} et {len(appels)} lancement(s), "
                                            "attendu 5 et aucun (il remplacerait les options d'historique)"))
    finally:
        shutil.rmtree(dossier, ignore_errors=True)
    return defauts


def juger_execution(corps: str) -> list[str]:
    return [m for _, m in controler_execution(corps)]


# Le shell d'un pas GitHub SANS `shell:` sur un exécuteur Linux : `bash -e {0}` (documentation GitHub, non mesuré sur un
# exécuteur). `pipefail` n'en fait pas partie : le gabarit du pas principal le pose lui-même, la grammaire du verdict
# n'admet aucun tube. `--noprofile --norc` n'y change rien pour un script (bash non interactif ne lit ni l'un ni l'autre).
SHELL_DES_PAS = ["bash", "--noprofile", "--norc", "-e"]
FAUX_OUTILS = {
    # Le pas principal télécharge, vérifie l'empreinte et extrait le binaire : rien de cela n'est joué pour de
    # vrai (ni réseau, ni écriture sous /tmp) ; `sha256sum` lit son entrée (sans quoi `echo |` meurt de SIGPIPE
    # sous `pipefail`) et rend `GARDE_SHA_RC`.
    "curl": "#!/usr/bin/env bash\nexit 0\n",
    "sha256sum": "#!/usr/bin/env bash\ncat >/dev/null\nexit \"${GARDE_SHA_RC:-0}\"\n",
    "tar": "#!/usr/bin/env bash\nexit 0\n",
}


def controler_pas(corps: str, run: str) -> list[tuple[str, str]]:
    """`P10.31-t` (b) : joue le `run:` du pas principal, enveloppe RÉELLE écrite sous `$RUNNER_TEMP`, faux binaire
    sous `GITLEAKS_BIN`, faux curl/sha256sum/tar sur PATH, avec `SHELL_DES_PAS` (`bash -e`, GitHub sans `shell:`).
    Trois parcours : sain (le pas rend 0 et lance UNE fois le binaire, par l'enveloppe), secret trouvé (le binaire
    rend 1 : le pas doit sortir non nul), empreinte fausse (`sha256sum` rend 1 : le pas sort non nul SANS lancer)."""
    defauts: list[tuple[str, str]] = []
    dossier = tempfile.mkdtemp(prefix="garde-gitleaks-pas-")
    try:
        depot = _preparer(dossier)
        outils = os.path.join(dossier, "outils")
        temp = os.path.join(dossier, "runner-temp")
        os.mkdir(outils)
        os.mkdir(temp)
        for nom, src in FAUX_OUTILS.items():
            with open(os.path.join(outils, nom), "w") as fh:
                fh.write(src)
            os.chmod(os.path.join(outils, nom), 0o755)
        with open(os.path.join(temp, "gitleaks-detect.sh"), "w", encoding="utf-8") as fh:
            fh.write(corps)
        pas = os.path.join(dossier, "pas.sh")
        with open(pas, "w", encoding="utf-8") as fh:
            fh.write(run)
        journal = os.path.join(dossier, "journal")

        def jouer(rc_binaire: int, rc_empreinte: int):
            open(journal, "w").close()
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("GIT_", "GITLEAKS_")) and k not in ("BASH_ENV", "ENV")}
            env.update(PATH=outils + os.pathsep + os.environ.get("PATH", ""), RUNNER_TEMP=temp, GITHUB_WORKSPACE=depot,
                       GITLEAKS_BIN=os.path.join(dossier, "faux-gitleaks"), GARDE_JOURNAL=journal,
                       GARDE_RC=str(rc_binaire), GARDE_SHA_RC=str(rc_empreinte))
            r = subprocess.run(SHELL_DES_PAS + [pas], cwd=depot, env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=60)
            return r.returncode, _lire_journal(journal), (r.stdout + r.stderr).strip()[-300:]

        rc, appels, sortie = jouer(0, 0)
        if rc != 0:
            defauts.append(("pas_sain", f"pas principal joué sur un dépôt sain : code {rc}, attendu 0 : {sortie}"))
        if len(appels) != 1:
            defauts.append(("pas_lancements", f"pas principal sain : {len(appels)} lancement(s) du binaire de `GITLEAKS_BIN`, "
                                              "attendu un (aucun : le binaire est remplacé, par un préfixe ou une variable)"))
        for cwd, args in appels:
            if os.path.realpath(cwd) != os.path.realpath(depot):
                defauts.append(("pas_cwd", f"pas principal : binaire lancé depuis {cwd}, pas depuis l'espace de travail"))
            attendus = [a.replace("$GITHUB_WORKSPACE", depot) for a in APPEL_ARGS]
            defauts += [("pas_" + c, "pas principal : " + m) for c, m in _juger_lancement(args, attendus)]
        rc, appels, _ = jouer(1, 0)
        if rc == 0 or len(appels) != 1:
            defauts.append(("pas_code", f"pas principal, le binaire rend 1 (secret trouvé) : le pas rend {rc} après "
                                        f"{len(appels)} lancement(s), attendu non nul après un : le code est avalé"))
        rc, appels, _ = jouer(0, 1)
        if rc == 0 or appels:
            defauts.append(("pas_empreinte", f"pas principal, empreinte sha256 fausse : le pas rend {rc} après {len(appels)} "
                                             "lancement(s), attendu non nul sans lancement (binaire non vérifié exécuté)"))
    finally:
        shutil.rmtree(dossier, ignore_errors=True)
    return defauts


# Retouches HOSTILES de l'enveloppe RÉELLE, chacune doit être refusée par l'exécution (`P10.31-r`).
# (nom, ancre, remplacement, contrôles) ; une ancre `^exec ` insère le remplacement AVANT la ligne `exec` de
# l'appel. `P10.31-t` : `contrôles` est l'ensemble EXACT des contrôles qui doivent la refuser ; une retouche
# refusée par un seul contrôle prouve que ce contrôle est nécessaire (le retirer la laisserait passer).
HOSTILES_EXECUTION = [
    ("sans option d'historique", ' --log-opts="--full-history --all --diff-merges=separate"', "", {"historique", "exact"}),
    ("-m seul (perd --all)", ' --log-opts="--full-history --all --diff-merges=separate"', " --log-opts=-m", {"historique", "exact"}),
    ("sans --ignore-gitleaks-allow", " --ignore-gitleaks-allow", "", {"allow", "exact"}),
    ("second lancement par une variable", "^exec ",
     'GL="${GITLEAKS_BIN:-/tmp/gitleaks}"; "$GL" detect --source . "$@" || true\n', {"lancements", "allow", "historique", "exact"}),
    ("binaire hors de GITLEAKS_BIN", '"${GITLEAKS_BIN:-/tmp/gitleaks}"', '"/inexistant-p10-31-r/gitleaks"',
     {"rc_sain", "lancements"}),
    ("sans refus de --log-opts", "--log-opts|--log-opts=*)", "--log-optz)", {"logopts5"}),
    ("arguments de l'appelant perdus", '--diff-merges=separate" "$@"', '--diff-merges=separate"', {"fin", "exact"}),
    ("sans texte forcé", "printf '* diff\\n' >>", "printf '' >>", {"attributs"}),
    ("sans refus de .gitleaksignore", "-name .gitleaksignore", "-name .gitleaksignore-p10-31-t", {"ignore3"}),
    # `P10.31-t` : une retouche par contrôle qui n'en avait pas d'isolée.
    ("lancé hors du dépôt", 'cd "$src"\n', "cd /\n", {"cwd"}),
    ("source hors du dépôt", " detect --source . ", " detect --source / ", {"debut", "exact"}),
    ("code du binaire inversé", 'exec "${GITLEAKS_BIN', '! "${GITLEAKS_BIN', {"rc_sain"}),
    ("arguments de l'appelant hors de la fin",
     ' --ignore-gitleaks-allow --log-opts="--full-history --all --diff-merges=separate" "$@"',
     ' "$@" --ignore-gitleaks-allow --log-opts="--full-history --all --diff-merges=separate"', {"fin", "exact"}),
    ("texte forcé puis désarmé", "printf '* diff\\n' >> \"$att\"",
     "printf '* diff\\n' >> \"$att\"; printf '* -diff\\n' >> \"$att\"", {"attributs"}),
    # `P10.31-t` : seul l'argumentaire EXACT refuse un drapeau que l'enveloppe ajoute (`--no-git` : 0 constat, mesuré).
    ("drapeau ajouté par l'enveloppe", '--diff-merges=separate" "$@"', '--diff-merges=separate" --no-git "$@"', {"exact"}),
]


def _retoucher(corps: str, nom: str, ancre: str, remplacement: str) -> str:
    if ancre == "^exec ":
        lignes = corps.splitlines(keepends=True)
        idx = [i for i, l in enumerate(lignes) if l.startswith("exec ")]
        if len(idx) != 1:
            raise AncreIntrouvable(f"« {nom} » : {len(idx)} ligne(s) `exec` dans l'enveloppe, attendu 1")
        return "".join(lignes[:idx[0]] + [remplacement] + lignes[idx[0]:])
    if corps.count(ancre) != 1:
        raise AncreIntrouvable(f"« {nom} » : ancre {ancre!r} trouvée {corps.count(ancre)} fois, attendu 1")
    return corps.replace(ancre, remplacement)


def valider_execution(corps: str) -> list[str]:
    """L'enveloppe réelle tient : chaque retouche hostile doit être refusée, et par les contrôles annoncés."""
    faux = []
    for nom, ancre, remplacement, attendus in HOSTILES_EXECUTION:
        codes = {c for c, _ in controler_execution(_retoucher(corps, nom, ancre, remplacement))}
        if not codes:
            faux.append(f"l'enveloppe hostile « {nom} » est admise par l'exécution")
        elif codes != attendus:
            faux.append(f"l'enveloppe hostile « {nom} » est refusée par {sorted(codes)}, attendu {sorted(attendus)}")
    return faux


# `P10.31-t` (b) : retouches HOSTILES du `run:` RÉEL du pas principal ; chacune doit être refusée par l'exécution
# du pas seule (le jugement textuel les refuse aussi, mais c'est le parcours joué qu'on éprouve ici).
HOSTILES_PAS = [
    ("code avalé par || true", "--exit-code 1\n", "--exit-code 1 || true\n", {"pas_code"}),
    ("binaire neutre en préfixe", 'bash "$RUNNER_TEMP/gitleaks-detect.sh"',
     'GITLEAKS_BIN=/bin/true bash "$RUNNER_TEMP/gitleaks-detect.sh"', {"pas_lancements", "pas_code"}),
    ("binaire absent en préfixe", 'bash "$RUNNER_TEMP/gitleaks-detect.sh"',
     'GITLEAKS_BIN=/tmp/neutre-p10-31-t bash "$RUNNER_TEMP/gitleaks-detect.sh"', {"pas_sain", "pas_lancements", "pas_code"}),
    ("set +e (empreinte ignorée)", "set -euo pipefail\n", "set -euo pipefail\nset +e\n", {"pas_empreinte"}),
    ("empreinte ignorée par || true", "sha256sum -c -\n", "sha256sum -c - || true\n", {"pas_empreinte"}),
    # Une retouche par moitié de `pas_empreinte` : les deux précédentes trahissent les deux à la fois (code 0 ET lancement).
    ("empreinte fausse puis sortie 0 sans lancer", "sha256sum -c -\n", "sha256sum -c - || exit 0\n", {"pas_empreinte"}),
    ("empreinte fausse puis lancement", "sha256sum -c -\n", 'sha256sum -c - || { "$GITLEAKS_BIN"; exit 1; }\n',
     {"pas_empreinte"}),
    ("appel direct du binaire", 'bash "$RUNNER_TEMP/gitleaks-detect.sh" .', '"${GITLEAKS_BIN:-/tmp/gitleaks}" detect --source .',
     {"pas_allow", "pas_historique", "pas_exact"}),
    # Seul le répertoire courant du lancement refuse celui-ci : l'enveloppe scanne un dépôt vide (0 constat, mesuré).
    ("dépôt vide en répertoire courant", 'bash "$RUNNER_TEMP/gitleaks-detect.sh"',
     'cd "$RUNNER_TEMP" && git init -q autre && cd autre\nbash "$RUNNER_TEMP/gitleaks-detect.sh"', {"pas_cwd"}),
    # Seul l'argumentaire EXACT refuse ceux-là ; chacun tait un vrai secret en 8.24.3 (mesuré).
    ("--no-git avant --exit-code 1", "--exit-code 1\n", "--no-git --exit-code 1\n", {"pas_exact"}),
    ("configuration vide", '--config "$GITHUB_WORKSPACE/.gitleaks-ci.toml"', "--config /dev/null", {"pas_exact"}),
    ("fichier d'ignorés", "--exit-code 1\n", '--gitleaks-ignore-path "$GITHUB_WORKSPACE/i.txt" --exit-code 1\n', {"pas_exact"}),
    ("ligne de base", "--exit-code 1\n", '--baseline-path "$GITHUB_WORKSPACE/b.json" --exit-code 1\n', {"pas_exact"}),
    ("code de sortie 0", "--exit-code 1\n", "--exit-code 0\n", {"pas_exact"}),
]


def valider_pas(corps: str, run: str) -> list[str]:
    faux = []
    for nom, ancre, remplacement, attendus in HOSTILES_PAS:
        if run.count(ancre) != 1:
            raise AncreIntrouvable(f"« {nom} » : ancre {ancre!r} trouvée {run.count(ancre)} fois dans le pas principal, attendu 1")
        codes = {c for c, _ in controler_pas(corps, run.replace(ancre, remplacement))}
        if not codes:
            faux.append(f"le pas principal hostile « {nom} » est admis par l'exécution")
        elif codes != attendus:
            faux.append(f"le pas principal hostile « {nom} » est refusé par {sorted(codes)}, attendu {sorted(attendus)}")
    return faux


def controler_verdict(run: str) -> list[tuple[str, str]]:
    """`P10.31-t` (c) — LE VERDICT JOUÉ, pas lu. Les `${{ steps.<id>.outcome }}` sont substitués (toutes les issues à
    `success`, puis celle de `gitleaks` à `failure`, `cancelled`, `skipped`, chacune sous chaque issue commune des AUTRES
    pas — GitHub rend leur vraie issue, pas `success` : une ligne `[ "${{ steps.<autre>.outcome }}" = success ] || rc=0`
    remettait le verdict à 0 quand cet autre pas était sauté) et le `run:` est joué avec `SHELL_DES_PAS` : sain il rend
    0, sinon il sort non nul. Un `trap`, une remise à zéro de `rc`, une sortie forcée, une ligne enveloppée ou mise en
    heredoc sont vus par leur EFFET, sans motif qui les nomme."""
    if "${{" in ISSUE.sub("", run):
        raise ExtractionImpossible("le `run:` du pas de verdict porte une expression `${{ … }}` autre qu'une issue de pas")
    defauts: list[tuple[str, str]] = []
    dossier = tempfile.mkdtemp(prefix="garde-gitleaks-verdict-")
    try:
        def jouer(issue: str, autres: str) -> tuple[int, str]:
            script = os.path.join(dossier, "verdict.sh")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(ISSUE.sub(lambda m: issue if m.group(1) == "gitleaks" else autres, run))
            r = subprocess.run(SHELL_DES_PAS + [script], cwd=dossier,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=30)
            return r.returncode, (r.stdout + r.stderr).strip()[-200:]

        rc, sortie = jouer("success", "success")
        if rc != 0:
            defauts.append(("verdict_sain", f"pas de verdict joué, toutes issues à success : code {rc}, attendu 0 : {sortie}"))
        for issue in ("failure", "cancelled", "skipped"):
            for autres in ("success", "failure", "cancelled", "skipped"):
                rc, sortie = jouer(issue, autres)
                if rc == 0:
                    defauts.append(("verdict_code", f"pas de verdict joué, scan à `{issue}`, autres pas à `{autres}` : code 0 — "
                                                    "le travail reste vert sur un secret trouvé (P10.31-t)"))
    finally:
        shutil.rmtree(dossier, ignore_errors=True)
    return defauts


# `P10.31-t` (c) : retouches HOSTILES du `run:` RÉEL du pas de verdict ; chacune doit être refusée par son EXÉCUTION
# seule (la grammaire fermée les refuse aussi, sauf la remise à zéro de `rc`, que seule l'exécution voit).
HOSTILES_VERDICT = [
    ("rc remis à zéro avant la sortie", "exit $rc\n", "rc=0\nexit $rc\n", {"verdict_code"}),
    ("sortie forcée à 0", "exit $rc\n", "exit 0\n", {"verdict_code"}),
    ("trap qui force la sortie", "set -u\n", "set -u\ntrap 'exit 0' EXIT\n", {"verdict_code"}),
    ("issue du scan non lue", '[ "${{ steps.gitleaks.outcome }}" = success ]', "[ success = success ]", {"verdict_code"}),
    ("verdict toujours en échec", "exit $rc\n", "exit 1\n", {"verdict_sain"}),
    # Seules les issues des AUTRES pas, jouées autrement qu'à `success`, refusent celui-ci.
    ("rc remis à zéro par l'issue d'un autre pas", "exit $rc\n",
     '[ "${{ steps.autre.outcome }}" = success ] || rc=0\nexit $rc\n', {"verdict_code"}),
]


def valider_verdict(run: str) -> list[str]:
    faux = []
    for nom, ancre, remplacement, attendus in HOSTILES_VERDICT:
        if run.count(ancre) != 1:
            raise AncreIntrouvable(f"« {nom} » : ancre {ancre!r} trouvée {run.count(ancre)} fois dans le pas de verdict, attendu 1")
        codes = {c for c, _ in controler_verdict(run.replace(ancre, remplacement))}
        if not codes:
            faux.append(f"le pas de verdict hostile « {nom} » est admis par l'exécution")
        elif codes != attendus:
            faux.append(f"le pas de verdict hostile « {nom} » est refusé par {sorted(codes)}, attendu {sorted(attendus)}")
    return faux


def main(argv: list[str]) -> int:
    if yaml is None:
        print("::error::PyYAML absent (`python3-yaml`) : le pas jugé ne peut être croisé avec le pas que GitHub lance "
              "— aucun verdict (P10.31-t).")
        return 2
    try:
        faux = valider_linstrument()
    except (AncreIntrouvable, ExtractionImpossible) as e:
        faux = [f"témoins fabriqués injouables ({e})"]
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
    try:
        defauts = juger(textes)
        # Le pas principal et le verdict jugés ci-dessus, et joués plus bas, sont ceux que YAML lit (P10.31-t).
        juges = localiser_pas_juges(textes)
        defauts += [m for _, m in croiser_avec_yaml(textes, juges)]
    except ExtractionImpossible as e:
        print(f"::error::instrument invalide — {e} — aucun verdict (P10.31-t).")
        return 2
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
            faux = valider_execution(corps) if not joue else []
            # `P10.31-t` (b) et (c) : le pas principal, joué avec l'enveloppe réelle, puis son verdict, joué. Le seul
            # pas `id: gitleaks` jugé est le premier (le texte refuse qu'il y en ait plusieurs) ; ses `run` sont ceux
            # que le croisement a comparés à la lecture YAML.
            if juges is not None:
                f, _, run, ligne_verdict, _, run_verdict = juges
                joue_pas = [m for _, m in controler_pas(corps, run)]
                defauts += [f"{f} (pas principal joué) : {d}" for d in joue_pas]
                if run_verdict is not None:
                    joue_verdict = [m for _, m in controler_verdict(run_verdict)]
                    defauts += [f"{f}:{ligne_verdict + 1} (pas de verdict joué) : {d}" for d in joue_verdict]
                # Éprouvé seulement sur un flux déjà admis (comme l'enveloppe) : un pas refusé par le texte peut
                # avoir perdu l'ancre d'une retouche, et l'instrument tairait le défaut sous un code 2.
                if not defauts:
                    faux += valider_pas(corps, run) + valider_verdict(run_verdict)
        except (OSError, subprocess.SubprocessError, AncreIntrouvable, ExtractionImpossible) as e:
            print(f"::error::instrument invalide — exécution de l'enveloppe, du pas principal ou du verdict impossible ({e}) — aucun verdict.")
            return 2
        if faux:
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
          f"jouée contre un faux binaire tient, et {len(HOSTILES_EXECUTION)} enveloppes hostiles dérivées sont refusées ; "
          f"le pas principal (gabarit fermé) joué rend le code du binaire, avec les arguments EXACTS, et ne lance qu'après "
          f"l'empreinte, {len(HOSTILES_PAS)} pas hostiles refusés ; le verdict joué rend le travail rouge, "
          f"{len(HOSTILES_VERDICT)} verdicts hostiles refusés ; aucune variable GITLEAKS_* n'est posée ; le pas principal et le verdict jugés et joués sont ceux que YAML lit (P10.31-t).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
