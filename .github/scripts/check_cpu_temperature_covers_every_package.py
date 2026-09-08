#!/usr/bin/env python3
"""La température CPU porte sur TOUS les processeurs, et dit sur combien — garde de CI (`P11.20-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE. Le capteur d'hôte lisait la première sonde CPU
(`coretemp`/`k10temp`, une par processeur) et s'ARRÊTAIT : sur une machine à deux sockets, `temp_c`
publiait le socket 0 seul, en silence — un nombre présenté comme « la température CPU » qui n'en
couvrait que la moitié. Mesuré le 2026-09-03, corrigé le 2026-09-08 : `temp_c` est la température du
processeur LE PLUS CHAUD (ce qu'une règle à seuil veut savoir) et `temp_cpu_packages` DIT sur combien
de processeurs elle porte, puisque le fil ne transporte qu'un couple nom-valeur.

CE QUE CETTE GARDE VÉRIFIE — TROIS TÉMOINS, sur le capteur EXÉCUTÉ TEL QU'IL EST LIVRÉ, contre un
`/sys` FABRIQUÉ (le capteur paramètre `/sys` comme `/proc`, ce qui rend la machine de CI indifférente) :
  (1) DEUX processeurs (45 °C et 61 °C) plus une sonde NVMe plus chaude (70 °C) -> `temp_c` = 61.0 et
      `temp_cpu_packages` = 2 ; la NVMe n'est jamais choisie. Un capteur qui s'arrêterait au premier
      rendrait 45.0 et 1 ; un capteur qui prendrait « le plus chaud » rendrait 70.0.
  (2) UNE sonde CPU présente mais ILLISIBLE (fichier vide) -> AUCUN `temp_c`, et un aveu qui nomme la
      clé : une sonde présente qui ne se lit pas est une lecture RATÉE, pas une absence de sonde.
  (3) AUCUN hwmon, une zone thermique `x86_pkg_temp` à 50 °C -> `temp_c` = 50.0, portée 1 (le repli).
L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU : le capteur doit avoir publié ses autres mesures d'hôte
(sinon c'est l'exécution qui a échoué, pas la température) — la garde ÉCHOUE alors au lieu de conclure.

CE QUI EST HORS PÉRIMÈTRE, ET POURQUOI C'EST DIT : la règle « aucune sonde -> rien n'est publié, rien
n'est avoué » est éprouvée par `check_host_measures_are_honest.py`, dont le `/sys` fabriqué est vide.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_host_measures_are_honest import MIN_MESURES, arborescence, echec, executer  # noqa: E402


def sonde(base, nom_hwmon, nom, millidegres):
    """Un hwmon fabriqué : `name` + `temp1_input` (None = fichier présent mais VIDE)."""
    d = os.path.join(base, "sys", "class", "hwmon", nom_hwmon)
    os.makedirs(d)
    open(os.path.join(d, "name"), "w").write(nom + "\n")
    open(os.path.join(d, "temp1_input"), "w").write("" if millidegres is None else f"{millidegres}\n")


def zone(base, nom_zone, genre, millidegres):
    d = os.path.join(base, "sys", "class", "thermal", nom_zone)
    os.makedirs(d)
    open(os.path.join(d, "type"), "w").write(genre + "\n")
    open(os.path.join(d, "temp"), "w").write(f"{millidegres}\n")


def jouer(fabrique):
    with tempfile.TemporaryDirectory() as base:
        proc, binz = arborescence(base, exploitable=True)
        fabrique(base)
        r, mesures, aveux = executer(base, proc, binz)
        if r.returncode != 0:
            echec(f"le capteur a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        autres = {k: v for k, v in mesures.items() if not k.startswith("temp_")}
        if len(autres) < MIN_MESURES:
            echec(f"instrument : seulement {len(autres)} mesure(s) hors température publiée(s) — l'exécution du capteur est en cause, pas la sonde")
        return mesures, aveux


def main():
    # (1) deux processeurs + une NVMe plus chaude
    def deux_processeurs(base):
        sonde(base, "hwmon0", "nvme", 70000)
        sonde(base, "hwmon1", "coretemp", 45000)
        sonde(base, "hwmon2", "coretemp", 61000)
    mesures, aveux = jouer(deux_processeurs)
    if float(mesures.get("temp_c", -1)) != 61.0:
        echec(f"deux processeurs (45 °C, 61 °C) : temp_c vaut {mesures.get('temp_c')!r} au lieu de 61.0 — le capteur s'arrête au premier socket (45.0) ou prend la sonde la plus chaude quelle qu'elle soit (70.0)")
    if float(mesures.get("temp_cpu_packages", -1)) != 2:
        echec(f"deux processeurs : temp_cpu_packages vaut {mesures.get('temp_cpu_packages')!r} au lieu de 2 — la portée de la valeur n'est pas dite")
    if aveux:
        echec(f"deux processeurs lisibles : le capteur a tout de même avoué — {[a['fields']['detail'][:120] for a in aveux]}")

    # (2) une sonde CPU présente mais illisible
    mesures, aveux = jouer(lambda base: sonde(base, "hwmon0", "k10temp", None))
    if "temp_c" in mesures or "temp_cpu_packages" in mesures:
        echec(f"sonde présente mais VIDE : une température a été publiée quand même ({ {k: v for k, v in mesures.items() if k.startswith('temp_')} })")
    if not any("temp_c" in a["fields"]["detail"] for a in aveux):
        echec("sonde présente mais VIDE : aucun aveu ne nomme `temp_c` — une lecture ratée est passée pour une absence de sonde")

    # (3) aucun hwmon, une zone thermique de processeur
    mesures, aveux = jouer(lambda base: zone(base, "thermal_zone0", "x86_pkg_temp", 50000))
    if float(mesures.get("temp_c", -1)) != 50.0 or float(mesures.get("temp_cpu_packages", -1)) != 1:
        echec(f"repli par zone thermique : attendu temp_c=50.0 et temp_cpu_packages=1, lu { {k: v for k, v in mesures.items() if k.startswith('temp_')} }")

    print("OK — temp_c porte sur TOUS les processeurs (le plus chaud), temp_cpu_packages dit sur combien, une sonde présente mais illisible s'avoue, le repli par zone reste lu")


if __name__ == "__main__":
    main()
