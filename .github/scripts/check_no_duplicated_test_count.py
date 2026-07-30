#!/usr/bin/env python3
"""Le compte de tests vivant ne doit exister QU'À UN SEUL endroit, et toute mesure doit être datée.

POURQUOI (mesuré, pas supposé). Le compte de la suite par défaut était recopié dans quatre
fichiers, et `CONTRIBUTING.md` allait jusqu'à *prescrire* de mettre les quatre à jour. Relevé le
2026-07-30, alors que la CI était juste (`EXPECTED_TESTS` valait 762) :

    CONTRIBUTING.md            disait 758   (périmé)
    daemon/.cargo/audit.toml   disait 762   (juste par accident de génération)
    daemon/src/tests/saml.rs   disait 600   (périmé de 162)
    daemon/src/tests/ai.rs     disait 600   (périmé de 162)

Un compteur dupliqué n'a qu'une issue : il pourrit. Et il pourrit vers le DANGEREUX — un lecteur
qui croit la prose pense la suite plus petite qu'elle n'est, donc qu'un écart de comptage est
normal, alors que la CONSTANCE de ce compte est précisément l'invariant qui prouve qu'une feature
OFF laisse le build par défaut inchangé.

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE. Elle ne connaît aucun fichier par son nom et ne porte aucune
liste d'exceptions. Elle lit la valeur VIVANTE dans `ci.yml` — la seule que la CI fasse respecter
— puis applique deux jambes à tous les fichiers texte suivis. Un fichier créé demain est couvert
par construction.

  (A) La valeur vivante n'apparaît nulle part ailleurs comme affirmation de taille de suite.
      Aucune liste d'exceptions n'est nécessaire, et c'est ce qui rend la garde tenable : une
      mesure historique citée avec sa date porte un ANCIEN nombre (749, 752, 757, 758…), donc
      elle ne peut pas déclencher une garde qui ne cherche que la valeur COURANTE. Ces citations
      sont légitimes — elles disent ce qui était vrai à leur date — et il ne faut surtout pas les
      « corriger » vers la valeur du jour : ce serait falsifier une mesure.

  (B) Toute affirmation chiffrée sur la taille de la suite porte son ANNÉE sur la même ligne.
      C'est la jambe qui attrape le nombre PÉRIMÉ, que (A) ne voit pas : 600 n'était plus la
      valeur vivante, donc rien ne rougissait, et l'affirmation est restée fausse des mois. Exiger
      une année rend « daté » vérifiable par la machine sans liste de mots-clés — et c'est de toute
      façon la bonne règle documentaire : une mesure sans date n'est pas une mesure.

CALIBRAGE DU MOTIF — fait par mesure sur l'arbre réel, pas au jugé. Une première version cherchait
tout nombre de 3+ chiffres près d'un mot contenant « test » : **30+ faux positifs** (ID d'événements
Windows 4624/4625, adresses `169.254.169.254`, `TEST-NET`, `TESTTOKEN`, `pentest`, techniques
`T1595.002`). Une garde qui crie à tort est désarmée le premier jour. Le motif retenu exige que le
nombre soit COLLÉ au mot (`600 tests`, `758 passed`, `752 green`), avec de vraies frontières de mot
et sans caractère de chemin/version autour — ce qui a ramené la liste à 5 candidats, dont 4 réels.
Le seul faux positif restant (« RFC 6238 test ») est exclu nommément : une référence de RFC n'est
pas un compte.

RÉSIDUS ASSUMÉS, écrits parce qu'ils comptent :
  · le motif ne voit que la forme « nombre puis mot ». Une phrase qui écrit le nombre APRÈS le mot
    (« la suite est restée verte à 757 ») lui échappe. Élargir rouvrait le bruit mesuré ci-dessus ;
    le compromis est explicite, pas ignoré.
  · si la suite revenait un jour exactement à un nombre déjà cité dans une phrase historique, (A)
    rougirait à tort. La sortie nomme le fichier et la ligne, et redater la phrase lève
    l'ambiguïté. Un faux positif bruyant et réparable en une ligne contre un faux négatif
    silencieux qui durait des mois : l'échange est bon.
  · (B) vérifie la PRÉSENCE d'une année, pas son EXACTITUDE. Elle supprime l'absence de date, pas
    le mensonge sur la date.

Usage :  python3 .github/scripts/check_no_duplicated_test_count.py [--repo CHEMIN]
Sortie :  0 = sain ; 1 = violation (chaque fichier:ligne nommé, avec la jambe violée).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

CI = ".github/workflows/ci.yml"

# Un nombre de 3-4 chiffres qui n'est ni un fragment de chemin/version/adresse, ni une référence
# de RFC. Les frontières excluent `T1595.002`, `169.254.169.254`, `v0.2.2`, `4624/4625`.
NUM_CORE = r"(?<![\w./\-])(?<!RFC )%s(?![\w./\-])"
# Mots qui font d'un nombre une AFFIRMATION sur la taille de la suite.
WORDS = r"(?:tests?|passed|pass[ée]s|green|verte?)"


def claim_re(value: str) -> re.Pattern[str]:
    """« <nombre> <mot-de-test> » — la forme canonique d'une affirmation de taille de suite."""
    return re.compile((NUM_CORE % re.escape(value)) + rf"[ \t]*{WORDS}\b", re.I)


ANY_CLAIM = re.compile((NUM_CORE % r"\d{3,4}") + rf"[ \t]*{WORDS}\b", re.I)
YEAR = re.compile(r"\b(?:19|20)\d{2}\b")


def tracked_text_files(repo: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    keep = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode("utf-8", "surrogateescape")
        try:
            with open(repo / rel, "rb") as fh:
                if b"\x00" in fh.read(1 << 16):  # binaire — voir check_no_stray_nul.py
                    continue
        except (IsADirectoryError, FileNotFoundError, PermissionError):
            continue
        keep.append(rel)
    return keep


def live_counters(repo: Path) -> dict[str, str]:
    """Les compteurs que la CI fait respecter, lus dans ci.yml — la source de vérité."""
    text = (repo / CI).read_text(encoding="utf-8", errors="replace")
    found: dict[str, str] = {}
    for name in ("EXPECTED_TESTS", "EXPECTED_COLD_TESTS"):
        m = re.search(rf'^\s*{name}\s*:\s*"?(\d+)"?\s*$', text, re.M)
        if m:
            found[name] = m.group(1)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    counters = live_counters(repo)
    if not counters:
        print(f"[count-guard] ÉCHEC — aucun compteur trouvé dans {CI}.")
        print("  La garde lit la valeur vivante là ; sans elle, elle ne garde rien.")
        return 1

    print("[count-guard] compteurs vivants : " + ", ".join(f"{k}={v}" for k, v in counters.items()))
    pats = {name: claim_re(val) for name, val in counters.items()}

    dup: list[tuple[str, int, str, str]] = []
    undated: list[tuple[str, int, str]] = []
    for rel in tracked_text_files(repo):
        if rel == CI:  # l'unique endroit autorisé à porter la valeur vivante
            continue
        try:
            lines = (repo / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except (IsADirectoryError, FileNotFoundError, PermissionError):
            continue
        for i, line in enumerate(lines, 1):
            for name, pat in pats.items():
                if pat.search(line):
                    dup.append((rel, i, name, line.strip()[:120]))
            if ANY_CLAIM.search(line) and not YEAR.search(line):
                undated.append((rel, i, line.strip()[:120]))

    if dup:
        print(
            "\n[count-guard] ÉCHEC (A) — le compte de tests VIVANT est recopié hors de ci.yml.\n"
            "  Un compteur dupliqué pourrit : quatre copies l'ont déjà fait ici pendant que la CI\n"
            "  restait juste. Citez la variable (`EXPECTED_TESTS`) au lieu de recopier sa valeur."
        )
        for rel, line_no, name, text in dup:
            print(f"    - {rel}:{line_no}  [{name}]  {text}")

    if undated:
        print(
            "\n[count-guard] ÉCHEC (B) — affirmation chiffrée sur la taille de la suite, SANS DATE.\n"
            "  Une mesure sans date devient fausse en silence : c'est exactement ce qui est arrivé\n"
            "  aux « 600 tests » restés 162 en dessous du réel. Soit vous citez `EXPECTED_TESTS`\n"
            "  sans recopier sa valeur, soit vous datez la mesure (une année sur la ligne suffit)."
        )
        for rel, line_no, text in undated:
            print(f"    - {rel}:{line_no}  {text}")

    if dup or undated:
        return 1

    print(
        "[count-guard] OK — chaque compte vivant n'existe qu'à un seul endroit, "
        "et toute affirmation chiffrée porte sa date"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
