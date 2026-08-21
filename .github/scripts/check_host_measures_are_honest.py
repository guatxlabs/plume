#!/usr/bin/env python3
"""Une mesure d'hôte qui n'a pas pu être prise n'est pas publiée comme un zéro — garde de CI (`S33`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`collectors/resources.sh` publie des séries qui ARMENT des règles à seuil : « mémoire > 90 % »,
« disque / > 90 % », « CPU > 90 % », « fuite slab noyau > 2,5 Go » (cf. `daemon/src/seeds.rs`). Quand
la source d'une de ces séries n'était pas exploitable, le capteur publiait quand même un nombre — et
ce nombre était le plus CALME de la série. Une règle dont l'entrée vaut 0 n'est pas en retard : elle
est STRUCTURELLEMENT INERTE, et rien ne le dit. Quatre formes menaient au même zéro :
  * un bloc `END` d'awk qui imprime `0` quand le motif cherché n'a jamais matché (`/proc/meminfo`
    tronqué, masqué par un bac à sable, ou d'un noyau qui n'expose pas `SUnreclaim`) ;
  * le code de retour de `df` avalé par le tube vers `awk` — le pipeline sort 0 en rendant `0 %` ;
  * un motif de noms d'interface codé en dur (`wlan0|eth|enp`) qui ne matche AUCUN des noms usuels
    (`ens3`, `eno1`, `wlp3s0`, `bond0`) : le débit valait alors zéro POUR TOUJOURS ;
  * une variable vide interpolée DANS un programme awk, qui en devenait un fragment de programme et
    produisait un delta négatif, donc un `print 0`.

CE QUE CETTE GARDE VÉRIFIE — DEUX TÉMOINS, ET LE SECOND EST LE CŒUR
--------------------------------------------------------------------
Le capteur est exécuté TEL QU'IL EST LIVRÉ, contre une arborescence fabriquée dans un temporaire et un
`df` stubé sur le PATH. Aucune lecture de la machine qui exécute la garde n'entre dans le verdict.
  (1) SOURCES PRÉSENTES, VALEURS RÉELLEMENT NULLES -> chaque mesure est PUBLIÉE, et vaut 0. Sans ce
      témoin, une version qui n'émettrait JAMAIS rien passerait le témoin (2) sans rien prouver : elle
      serait le défaut symétrique, et tout aussi grave — elle ferait disparaître un hôte au repos.
  (2) SOURCES PRÉSENTES MAIS NON EXPLOITABLES -> AUCUN nombre publié pour ces mesures, et un aveu
      `collector-availability` qui NOMME chaque clé perdue et sa cause.
Les deux témoins portent sur les MÊMES clés, découvertes dans la sortie du témoin (1) : la garde
n'énumère aucune mesure. Une huitième série ajoutée demain au capteur est donc contrôlée d'office.

CE QUI EST HORS PÉRIMÈTRE, ET POURQUOI C'EST DIT
------------------------------------------------
`temp_c` lit `/sys/class/hwmon` et `/sys/class/thermal`, que ce capteur ne paramètre pas : sa présence
dépend de la machine qui exécute la garde. Il est donc EXCLU des deux témoins. Ce n'est pas une
faiblesse : `temp_c` est précisément la mesure qui tenait DÉJÀ la règle (« pas de sonde -> on ne
l'émet pas, sinon faux 0 °C trompeur »), et c'est d'elle que le reste du lot est dérivé.

L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU. Une garde qui ne trouverait rien parce que son exécution est
cassée rendrait vert en étant aveugle. Le témoin (1) sert donc aussi de témoin de non-dégénérescence :
s'il ne publie pas au moins quatre mesures, la garde ÉCHOUE au lieu de conclure.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CAPTEUR = os.path.join(RACINE, "collectors", "resources.sh")
LIB = os.path.join(RACINE, "collectors", "lib.sh")

# `temp_c` lit /sys, que le capteur ne paramètre pas : la machine de CI décide de sa présence.
HORS_PERIMETRE = {"temp_c"}
# Plancher de non-dégénérescence : en dessous, c'est l'instrument qui est cassé, pas le capteur.
MIN_MESURES = 4


def echec(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def arborescence(base, exploitable):
    """Fabrique un `/proc` et un `df`. `exploitable` : sources complètes valant RÉELLEMENT zéro, ou
    sources présentes dont le contenu ne porte rien d'utilisable."""
    proc = os.path.join(base, "proc")
    os.makedirs(os.path.join(proc, "net"))
    binz = os.path.join(base, "bin")
    for d in (binz, os.path.join(base, "spool"), os.path.join(base, "state")):
        os.makedirs(d)
    if exploitable:
        open(os.path.join(proc, "meminfo"), "w").write(
            "MemTotal:       1000000 kB\nMemFree:        1000000 kB\nMemAvailable:   1000000 kB\n"
            "SwapTotal:            0 kB\nSwapFree:             0 kB\nSUnreclaim:           0 kB\n"
        )
        open(os.path.join(proc, "loadavg"), "w").write("0.00 0.01 0.05 1/100 42\n")
        open(os.path.join(proc, "stat"), "w").write("cpu  1000 0 0 9000 0 0 0 0 0 0\n")
        open(os.path.join(proc, "net", "dev"), "w").write(
            "Inter-|   Receive                          |  Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
            "    lo:  500 5 0 0 0 0 0 0  500 5 0 0 0 0 0 0\n"
            "  ens3:  1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n"
        )
        # Un système de fichiers réellement à 0 % : impossible à fabriquer autrement qu'en stubant `df`.
        stub = "#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n" \
               "echo '/dev/fab 1000000 0 1000000 0% /'\n"
        # Échantillon précédent : le delta est ENTIÈREMENT en attente, donc un CPU réellement à 0 %.
        open(os.path.join(base, "state", "resources.prev"), "w").write("1 9000 8000 1000 2000\n")
    else:
        for f in ("meminfo", "loadavg", "stat"):
            open(os.path.join(proc, f), "w").write("")
        open(os.path.join(proc, "net", "dev"), "w").write(
            "Inter-|   Receive                          |  Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
            "    lo:  500 5 0 0 0 0 0 0  500 5 0 0 0 0 0 0\n"
        )
        stub = "#!/bin/sh\nexit 1\n"
    chemin_df = os.path.join(binz, "df")
    open(chemin_df, "w").write(stub)
    os.chmod(chemin_df, 0o755)
    return proc, binz


def executer(base, proc, binz):
    env = dict(
        os.environ,
        PATH=binz + os.pathsep + os.environ.get("PATH", ""),
        PLUME_LIB=LIB,
        PLUME_SPOOL=os.path.join(base, "spool"),
        PLUME_STATE=os.path.join(base, "state"),
        PLUME_PROC_ROOT=proc,
        # Le répertoire de `/proc` fabriqué fait un cible de `df` parfaitement valide pour le témoin (1) ;
        # au témoin (2) c'est le stub qui échoue, quelle que soit la cible.
        PLUME_DISK_TARGET=proc,
    )
    r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True)
    spool = os.path.join(base, "spool")
    mesures, aveux = {}, []
    for nom in sorted(os.listdir(spool)):
        try:
            doc = json.load(open(os.path.join(spool, nom), encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 — un spool illisible est un échec de garde, pas un verdict
            echec(f"enveloppe `{nom}` illisible ({e}) — le capteur a publié du JSON invalide")
        if doc.get("kind") == "metrics":
            for m in doc.get("data", {}).get("metrics", []):
                mesures[m["name"]] = m["value"]
        for ev in doc.get("events", []):
            if ev.get("fields", {}).get("type") == "collector-availability":
                aveux.append(ev)
    return r, mesures, aveux


def main():
    for f in (CAPTEUR, LIB):
        if not os.path.exists(f):
            echec(f"{f} introuvable — la garde ne peut pas rendre de verdict")
    if shutil.which("sh") is None:
        echec("aucun `sh` — la garde ne peut pas rendre de verdict (et ne rendra pas un faux vert)")

    # --- TÉMOIN (1) : LU, VALEUR ZÉRO -----------------------------------------------------------
    with tempfile.TemporaryDirectory() as base:
        proc, binz = arborescence(base, exploitable=True)
        r, mesures, aveux = executer(base, proc, binz)
        if r.returncode != 0:
            echec(f"sources exploitables : le capteur a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        publiees = {k: v for k, v in mesures.items() if k not in HORS_PERIMETRE}
        if len(publiees) < MIN_MESURES:
            echec(
                f"sources exploitables : seulement {len(publiees)} mesure(s) publiée(s) "
                f"({sorted(publiees)}) — sous le plancher de {MIN_MESURES}, c'est l'instrument qui est "
                "cassé, pas le capteur ; la garde refuse de conclure"
            )
        non_nulles = {k: v for k, v in publiees.items() if float(v) != 0.0}
        if non_nulles:
            echec(
                "sources exploitables valant RÉELLEMENT zéro : ces mesures ne rendent pas 0 — "
                f"{non_nulles}. Le témoin ne mesure plus ce qu'il prétend."
            )
        if aveux:
            echec(
                "sources exploitables : le capteur a tout de même avoué une mesure manquante — "
                f"{[a['fields']['detail'][:120] for a in aveux]}. Une version qui rendrait TOUJOURS "
                "« illisible » passerait le témoin inverse sans rien prouver."
            )
        attendues = set(publiees)

    # --- TÉMOIN (2) : ILLISIBLE -> AUCUN NOMBRE, ET UN AVEU QUI NOMME LA CLÉ ---------------------
    with tempfile.TemporaryDirectory() as base:
        proc, binz = arborescence(base, exploitable=False)
        r, mesures, aveux = executer(base, proc, binz)
        if r.returncode != 0:
            echec(f"sources non exploitables : le capteur a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        rassurantes = {k: v for k, v in mesures.items() if k in attendues}
        if rassurantes:
            echec(
                "sources NON exploitables : ces mesures sont tout de même publiées — "
                f"{rassurantes}. Une règle à seuil qui les consomme lira du calme là où il n'y a "
                "plus aucune mesure."
            )
        if not aveux:
            echec(
                "sources NON exploitables : AUCUN aveu `collector-availability` n'a été émis. "
                "L'absence seule ne distingue pas « la lecture a échoué » d'un relevé manqué."
            )
        texte = " ".join(a["fields"]["detail"] for a in aveux)
        muettes = sorted(k for k in attendues if k not in texte)
        if muettes:
            echec(
                f"sources NON exploitables : l'aveu ne NOMME pas {muettes} — une clé peut donc "
                "disparaître sans un mot."
            )
        causes = {"source_absente", "source_refusee", "source_illisible", "forme_inconnue"}
        if not any(c in texte for c in causes):
            echec(
                "l'aveu ne porte aucune cause de l'ensemble fermé "
                f"{sorted(causes)} — la cardinalité de l'étiquette n'est plus bornée"
            )

    print(f"OK — {len(attendues)} mesure(s) d'hôte : publiées à 0 quand la source est lisible, "
          f"ABSENTES et avouées quand elle ne l'est pas ({sorted(attendues)})")


if __name__ == "__main__":
    main()
