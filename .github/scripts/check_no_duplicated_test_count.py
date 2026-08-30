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

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE. Elle ne porte aucune liste de fichiers tolérés. Elle lit les
valeurs VIVANTES dans les workflows — les seules que la CI fasse respecter — puis applique deux
jambes à tous les fichiers texte suivis. Un fichier créé demain est couvert par construction.

LES COMPTEURS AUSSI SONT DÉRIVÉS — ILS NE L'ÉTAIENT PAS, ET L'EN-TÊTE PROMETTAIT DÉJÀ QU'ILS LE
SOIENT (`P8.9-m`). MESURÉ le 2026-08-30 : ce fichier portait la liste écrite à la main
`("EXPECTED_TESTS", "EXPECTED_COLD_TESTS")` pendant que les workflows en faisaient respecter CINQ —
`EXPECTED_TESTS` (1448), `EXPECTED_COLD_TESTS` (1693), `EXPECTED_S3_TESTS` (12),
`EXPECTED_SYSLOG_TESTS` (49), `EXPECTED_MAIL_TESTS` (5). TROIS compteurs vivants sur cinq pouvaient
donc être recopiés n'importe où sans que rien ne rougisse, et c'est exactement le défaut que ce
fichier raconte. La liste est remplacée par une DÉRIVATION : tout `EXPECTED_…TESTS: "<nombre>"`
écrit dans un fichier de `.github/workflows/` est un compteur vivant, à n'importe quelle
indentation (les trois manquants vivaient au niveau d'un `step`, pas du workflow). Un compteur
ajouté demain — dans un workflow qui n'existe pas encore — entre par construction.

CE QUE LA DÉRIVATION A COÛTÉ EN FAUX POSITIFS : ZÉRO, et c'est mesuré, pas espéré. Les trois
compteurs neufs valent 12, 49 et 5 — des nombres COURTS, donc a priori le pire cas pour la jambe
(A), qui cherche « <valeur> <mot-de-test> ». Balayage du 2026-08-30 sur tous les fichiers texte
suivis : `12 tests`, `49 tests`, `5 tests` — 0 occurrence, pour les cinq valeurs. Le risque à
terme est réel et il est dit : « 5 tests » est une phrase qu'on peut écrire innocemment d'un
FICHIER, pas de la suite. La sortie nomme alors fichier et ligne, et le geste est d'une ligne.

ET CE QUI N'A PAS ÉTÉ ÉLARGI, PARCE QUE LA MESURE L'INTERDIT. La jambe (B) ne cherche que des
nombres de 3-4 chiffres. L'élargir aux nombres courts pour « couvrir » 12, 49 et 5 a été MESURÉ le
2026-08-30 : à 2 chiffres, 2 lignes légitimes sont accusées (« 72 tests mutateurs », « 52 tests de
cette suite ») ; à 1 chiffre, 18 (« running 3 tests », « 2 passed; 1 failed », « ses 4 tests »).
La jambe (B) reste donc à 3-4 chiffres, et cette borne-là est un CHOIX mesuré, pas un oubli.

DEUX FICHIERS SONT HORS PORTÉE, et il faut dire pourquoi ce ne sont pas des exceptions : ce sont
les deux fichiers AUTO-RÉFÉRENTS. `ci.yml` PORTE la valeur — c'est tout l'objet de la garde — et
ce script DÉFINIT le motif, donc il contient forcément des exemples de ce qu'il détecte et le
récit du défaut qui l'a fait naître. Les dater serait faux : ce sont des EXEMPLES, pas des
mesures. Une règle ne peut pas être sa propre violation. Mesuré, et c'est ce qui a imposé la
règle : sans cette exemption, la garde a échoué d'abord sur son propre message d'erreur, puis sur
sa propre documentation — deux tours, deux faux positifs, aucun signal utile.

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
Sortie :  0 = sain ; 1 = violation (chaque fichier:ligne nommé, avec la jambe violée) ;
          2 = la garde REFUSE DE CONCLURE (la dérivation ne retrouve plus les compteurs).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

CI = ".github/workflows/ci.yml"
WORKFLOWS = ".github/workflows"

# UN COMPTEUR VIVANT, TEL QU'IL S'ÉCRIT dans un workflow : `EXPECTED_<quelque chose>TESTS: "<n>"`,
# à N'IMPORTE QUELLE indentation. L'indentation n'est pas un détail : `EXPECTED_TESTS` vit au niveau
# du workflow, les trois compteurs qui manquaient (`EXPECTED_S3_TESTS`, `EXPECTED_SYSLOG_TESTS`,
# `EXPECTED_MAIL_TESTS`) vivent dans le bloc `env:` d'un STEP, dix colonnes plus loin. Le nom doit
# FINIR par TEST/TESTS : `EXPECTED_SCHEMA` ou `MIN_SCRIPTS` ne sont pas des tailles de suite.
COMPTEUR = re.compile(r'^\s*(EXPECTED_[A-Z0-9_]*TESTS?)\s*:\s*"?(\d+)"?\s*(?:#.*)?$', re.M)

# Un nombre de 3-4 chiffres qui n'est ni un fragment de chemin/version/adresse, ni une référence
# de RFC. Les frontières excluent `T1595.002`, `169.254.169.254`, `v0.2.2`, `4624/4625`.
NUM_CORE = r"(?<![\w./\-])(?<!RFC )%s(?![\w./\-])"
# Mots qui font d'un nombre une AFFIRMATION sur la taille de la suite.
#
# CALIBRAGE, SUITE — une classe de faux positif NEUVE, trouvée le 2026-08-10 par la garde
# elle-même. La forme précédente écrivait `pass[ée]s`, une classe de caractères qui accepte
# l'accent OU son absence : elle matchait donc « 758 passés » (des tests) MAIS AUSSI
# « 500 passes » (des passes de fusion FTS5, `daemon/src/tests/compactage_fts.rs`). En français
# les deux mots ne diffèrent que par un accent, et seul l'accentué parle de tests. Conséquence
# mesurée : la CI publique était ROUGE depuis `4ca6339` sur un compte d'itérations qui n'a rien
# d'une taille de suite. Une garde qui crie à tort est désarmée le premier jour — le fichier le
# disait déjà pour les ID d'événements Windows, et l'a réappris ici.
# L'accent est donc EXIGÉ côté français ; `passed` reste accepté sans condition (l'anglais n'a
# pas l'ambiguïté).
WORDS = r"(?:tests?|passed|pass(?:és|ées)|green|verte?)"


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


def live_counters(repo: Path) -> tuple[dict[str, str], set[str]]:
    """Les compteurs que la CI fait respecter, DÉRIVÉS des workflows — la source de vérité.

    Rend aussi l'ensemble des workflows qui en PORTENT un : ce sont eux, et eux seuls, qui sont
    auto-référents et donc hors portée des deux jambes. Un workflow qui ne porte aucun compteur
    n'est PAS exempté — l'exempter d'avance élargirait l'angle mort au lieu de le fermer.
    """
    found: dict[str, str] = {}
    porteurs: set[str] = set()
    d = repo / WORKFLOWS
    for chemin in sorted(d.glob("*.yml")) + sorted(d.glob("*.yaml")):
        text = chemin.read_text(encoding="utf-8", errors="replace")
        rel = os.path.relpath(chemin, repo)
        for nom, val in COMPTEUR.findall(text):
            found[nom] = val
            porteurs.add(rel)
    return found, porteurs


def temoins() -> None:
    """L'INSTRUMENT SE VALIDE SUR DES ENTRÉES FABRIQUÉES ICI, avant tout verdict sur l'arbre. Aucune
    de ces entrées ne vient du dépôt : une garde qui se valide sur l'arbre qu'elle juge se vérifie
    contre elle-même et est verte par construction. Les nombres employés (8765, 4321) ne sont AUCUN
    compteur vivant — sinon les témoins bougeraient au rythme de la suite."""
    # --- LA DÉRIVATION DES COMPTEURS, dans les deux sens ------------------------------------------
    wf = (
        "env:\n"
        '  EXPECTED_TESTS: "8765"\n'
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        "      - env:\n"
        '          EXPECTED_MAIL_TESTS: "5"\n'
        '          EXPECTED_S3_TEST: "12"   # singulier, et commenté en bout de ligne\n'
        '  EXPECTED_SCHEMA: "42"\n'
        '  MIN_SCRIPTS: "43"\n'
        '  EXPECTED_TESTS_SECONDS: "30"\n'
        '  EXPECTED_TESTS_BIS: "99"\n'
    )
    vu = dict(COMPTEUR.findall(wf))
    attendu = {"EXPECTED_TESTS": "8765", "EXPECTED_MAIL_TESTS": "5", "EXPECTED_S3_TEST": "12"}
    assert vu == attendu, (
        f"témoin de DÉRIVATION : {vu} au lieu de {attendu}. La forme lue est « EXPECTED_…TESTS: \"n\" » "
        f"à n'importe quelle indentation — c'est l'indentation d'un `step` qui masquait trois "
        f"compteurs sur cinq (mesuré le 2026-08-30) — et un nom qui ne FINIT pas par TEST/TESTS "
        f"(`EXPECTED_SCHEMA`, `MIN_SCRIPTS`, `EXPECTED_TESTS_SECONDS`) n'est pas une taille de suite."
    )
    assert not COMPTEUR.findall("env:\n  # EXPECTED_TESTS: \"8765\"\n"), \
        "témoin INVERSE : un compteur CITÉ EN COMMENTAIRE serait pris pour un compteur vivant"

    # --- LA JAMBE (A) : la valeur vivante recopiée ailleurs ----------------------------------------
    a = claim_re("8765")
    for accuse in ("la suite fait 8765 tests", "8765 passed", "8765 green", "8765 passés",
                   "reste verte : 8765 tests"):
        assert a.search(accuse), f"témoin POSITIF (A) : « {accuse} » n'est pas accusé"
    for acquitte in ("T1595.8765 tests", "RFC 8765 test", "8765 passes", "18765 tests",
                     "8765 tentatives", "v8765.0 tests", "8765/8766 tests"):
        assert not a.search(acquitte), f"témoin NÉGATIF (A) : « {acquitte} » est accusé À TORT"

    # LE CAS NEUF, et c'est celui qui coûte : un compteur à UN chiffre. `EXPECTED_MAIL_TESTS` vaut 5.
    # La jambe (A) est ancrée sur la VALEUR EXACTE avec de vraies frontières de mot — « 15 tests » et
    # « T1595.005 tests » ne la déclenchent pas —, mais « 5 tests » la déclenche, et ce sera parfois
    # une phrase légitime sur un FICHIER. Le témoin fige ce comportement au lieu de le découvrir en CI.
    court = claim_re("5")
    assert court.search("ce lot ajoute 5 tests"), "témoin : un compteur COURT n'accuse plus rien"
    for acquitte in ("15 tests", "T1595.005 tests", "5.2 tests", "5 tentatives"):
        assert not court.search(acquitte), f"témoin NÉGATIF (A, court) : « {acquitte} » accusé à tort"

    # --- LA JAMBE (B) : toute affirmation chiffrée porte son année --------------------------------
    assert ANY_CLAIM.search("4321 tests") and not YEAR.search("4321 tests"), \
        "témoin POSITIF (B) : une affirmation chiffrée SANS date n'est plus attrapée"
    assert YEAR.search("mesuré le 2026-08-30 : 4321 tests"), \
        "témoin NÉGATIF (B) : une mesure DATÉE serait accusée"
    # ET LA BORNE DE (B) EST UN CHOIX MESURÉ : à 1-2 chiffres elle accuserait « running 3 tests »
    # et « 72 tests mutateurs » (18 et 2 lignes légitimes, mesuré le 2026-08-30). Le témoin fige la
    # borne pour qu'un élargissement « évident » se heurte à une assertion, pas à une CI rouge.
    for hors_portee in ("running 3 tests", "72 tests mutateurs", "2 passed; 1 failed"):
        assert not ANY_CLAIM.search(hors_portee), \
            f"témoin de BORNE (B) : « {hors_portee} » entre dans la portée — le bruit mesuré revient"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    temoins()

    counters, porteurs = live_counters(repo)
    # PLANCHER DE NON-DÉGÉNÉRESCENCE, et il rend **2**, pas 1. Une garde qui ne trouve plus de
    # compteur n'a pas constaté une violation : elle n'a rien pu mesurer, et confondre les deux
    # laisse lire « le dépôt est fautif » là où il faut lire « l'instrument est cassé ». Le plancher
    # est 2 (les deux suites du démon) ; MESURÉ le 2026-08-30 : cinq compteurs vivants.
    if len(counters) < 2:
        print(f"[count-guard] REFUS DE CONCLURE — {len(counters)} compteur(s) dérivé(s) de "
              f"{WORKFLOWS}/, plancher 2 (mesuré le 2026-08-30 : 5).")
        print("  Le format des workflows a changé sous la dérivation ; la garde ne garde plus rien,")
        print("  et elle le DIT au lieu de rendre un vert d'aveugle ou d'accuser le dépôt.")
        return 2

    print("[count-guard] compteurs vivants DÉRIVÉS de "
          + ", ".join(sorted(porteurs)) + " : "
          + ", ".join(f"{k}={v}" for k, v in sorted(counters.items())))
    pats = {name: claim_re(val) for name, val in counters.items()}

    # DEUX exemptions, et ce ne sont pas des exceptions à une liste : ce sont les deux fichiers
    # AUTO-RÉFÉRENTS. `ci.yml` PORTE la valeur (c'est le point), et ce script DÉFINIT le motif —
    # il doit donc contenir des exemples de ce qu'il détecte (`600 tests`, `758 passed`,
    # `752 green`) et le récit du défaut qui l'a fait naître. Les dater serait faux : ce sont des
    # EXEMPLES, pas des mesures. Une règle ne peut pas être sa propre violation. Mesuré : sans
    # cette exemption, la garde échouait sur son propre message d'erreur puis sur sa propre
    # documentation — deux tours, deux faux positifs, aucun signal.
    myself = os.path.relpath(os.path.abspath(__file__), repo)
    exempt = set(porteurs) | {myself}

    dup: list[tuple[str, int, str, str]] = []
    undated: list[tuple[str, int, str]] = []
    for rel in tracked_text_files(repo):
        if rel in exempt:
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
            # Cette ligne est elle-même DATÉE, et pas par coquetterie : sans l'année, la garde
            # attrapait son propre message d'erreur. Elle mange donc sa propre nourriture.
            "  aux « 600 tests » de 2026, restés 162 en dessous du réel. Soit vous citez\n"
            "  `EXPECTED_TESTS`\n"
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
