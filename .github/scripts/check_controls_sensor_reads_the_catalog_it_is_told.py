#!/usr/bin/env python3
"""Le capteur de contrôles lit le catalogue d'exploitant qu'on lui DÉSIGNE, et le lit entier — garde de CI (`P4.8-a`).

LE TROU QUE CETTE GARDE FERME
-----------------------------
Mesuré le 2026-08-28 : trois capteurs lisent un chemin d'entrée d'exploitant ligne à ligne, et le
correctif « une dernière ligne sans saut de ligne n'est pas perdue » a été posé sur les trois. Deux
lisent un chemin détournable par un levier d'environnement et sont exercés par un témoin ; le
troisième — `collectors/controls.sh`, le catalogue `/etc/plume/controls.d/*.check` — lisait un
chemin LITTÉRAL sous `/etc`, qu'aucun témoin du dépôt ne pouvait exercer sans écrire hors de son
bac. Un trou de COUVERTURE nommé, pas un défaut caché : le correctif y était, personne ne le tenait.

CE QUE LA GARDE FAIT
--------------------
Le capteur lit désormais `PLUME_CONTROLS_ROOT` (défaut `/etc/plume/controls.d`), le motif de ses deux
voisins (`PLUME_PROC_ROOT` / `PLUME_SYS_ROOT`, `PLUME_UNIT_ROOT`). La garde fabrique un catalogue
dans un bac : un contrôle qui réussit, un qui échoue, une ligne de commentaire, et une DERNIÈRE ligne
SANS saut de ligne final ; elle lance le capteur avec le spool, l'état et un PATH réduits à son bac
(aucune publication, aucun outil d'hôte), puis lit l'enveloppe `controls` du spool :
  * `ok` est là, vrai ; `ko` est là, faux ; la dernière ligne est là (le correctif du 2026-08-28 est
    exercé) ; le commentaire n'y est pas ;
  * TÉMOIN NÉGATIF : sans le levier, le capteur lit le chemin d'hôte — sur une machine de CI ce chemin
    n'existe pas — et AUCUN identifiant fabriqué n'apparaît : c'est bien le levier qui route, pas un
    hasard de répertoire courant.
Sortie : 0 tenu · 1 défaut · 2 rien n'a été mesuré (capteur absent, `sh` absent, capteur en échec,
enveloppe absente ou illisible) — jamais un vert par défaut.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CAPTEUR = os.path.join(RACINE, "collectors", "controls.sh")
LIB = os.path.join(RACINE, "collectors", "lib.sh")
ETIQUETTE = "P4.8-a"


def echec(msg):
    print(f"::error::{ETIQUETTE} : {msg} — RIEN N'A ÉTÉ MESURÉ.")
    sys.exit(2)


def lancer(base, catalogue):
    env = dict(
        os.environ,
        PATH=os.path.join(base, "bin") + os.pathsep + "/usr/bin" + os.pathsep + "/bin",
        PLUME_LIB=LIB,
        PLUME_SPOOL=os.path.join(base, "spool"),
        PLUME_STATE=os.path.join(base, "state"),
    )
    if catalogue is not None:
        env["PLUME_CONTROLS_ROOT"] = catalogue
    else:
        env.pop("PLUME_CONTROLS_ROOT", None)
    for d in ("spool", "state", "bin"):
        os.makedirs(os.path.join(base, d), exist_ok=True)
    for f in os.listdir(os.path.join(base, "spool")):
        os.remove(os.path.join(base, "spool", f))
    r = subprocess.run(["sh", CAPTEUR], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        echec(f"le capteur a échoué (rc={r.returncode}) : {r.stderr.strip()[:300]}")
    enveloppes = sorted(os.listdir(os.path.join(base, "spool")))
    if not enveloppes:
        echec("le capteur n'a rien déposé dans le spool")
    try:
        doc = json.load(open(os.path.join(base, "spool", enveloppes[0]), encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        echec(f"enveloppe illisible ({e})")
    if doc.get("kind") != "controls":
        echec(f"enveloppe de genre `{doc.get('kind')}` au lieu de `controls`")
    return {c.get("id"): c.get("ok") for c in (doc.get("data") or {}).get("controls") or []}


def main():
    for f in (CAPTEUR, LIB):
        if not os.path.exists(f):
            echec(f"{f} introuvable")
    if shutil.which("sh") is None:
        echec("aucun `sh`")
    with tempfile.TemporaryDirectory() as base:
        cat = os.path.join(base, "controls.d")
        os.makedirs(cat)
        with open(os.path.join(cat, "temoin.check"), "w", encoding="utf-8") as fh:
            fh.write("temoin_ok|true\ntemoin_ko|false\n#temoin_commente|true\n\ntemoin_derniere_ligne|true")  # pas de \n final
        avec = lancer(base, cat)
        fautes = []
        if avec.get("temoin_ok") is not True:
            fautes.append(f"`temoin_ok` attendu vrai, vu {avec.get('temoin_ok')!r}")
        if avec.get("temoin_ko") is not False:
            fautes.append(f"`temoin_ko` attendu faux, vu {avec.get('temoin_ko')!r}")
        if avec.get("temoin_derniere_ligne") is not True:
            fautes.append("la DERNIÈRE ligne sans saut de ligne final est perdue — le correctif du 2026-08-28 n'est plus tenu")
        if any(k.startswith("#") for k in avec):
            fautes.append("une ligne de commentaire est devenue un contrôle")
        sans = lancer(base, None)
        fuite = [k for k in sans if k.startswith("temoin_")]
        if fuite:
            fautes.append(f"sans `PLUME_CONTROLS_ROOT`, les identifiants fabriqués apparaissent quand même ({fuite}) : le levier ne route pas")
        if fautes:
            for f in fautes:
                print(f"::error file=collectors/controls.sh::{ETIQUETTE} : {f}")
            sys.exit(1)
        print(f"{ETIQUETTE} : le capteur de contrôles lit le catalogue désigné par `PLUME_CONTROLS_ROOT` "
              f"({len([k for k in avec if k.startswith('temoin_')])} contrôles fabriqués lus, commentaire ignoré, dernière ligne sans saut de ligne lue) "
              f"et, sans le levier, le chemin d'hôte — aucun identifiant fabriqué ne fuit. Exercé dans un bac, sans écrire hors de lui.")
        sys.exit(0)


if __name__ == "__main__":
    main()
