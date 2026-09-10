#!/usr/bin/env python3
"""Le tampon de l'hôte est BORNÉ, et chaque perte est COMPTÉE ET DITE (`P9.7-c`, item 4).

Mesuré le 2026-08-27 : trois familles de tampon, deux bornées ; le spool qu'un hôte reçoit par défaut
n'avait ni plafond, ni éviction, ni purge, et l'expédition ne supprimait un fichier que sur un unique
code de succès — une erreur PERMANENTE le faisait croître sans fin, en silence. Tranché : au-delà du
plafond, `ship.sh` évince les PLUS ANCIENS (la doctrine de l'agent Rust ; un réseau sans état durable
refuse le plus récent, ce n'est pas ce tampon-là) et AVOUE par une enveloppe de disponibilité qui PORTE LE COMPTE (l'état de l'hôte n'a qu'une voie d'écriture, celle des marqueurs de progression, et un compte n'en est pas un) ;
un refus permanent du central est mis à l'écart HORS du spool ($STATE/refuses/ — le spool n'a qu'une voie de publication), compté, avoué.

Jambe EXÉCUTÉE : `ship.sh` est lancé pour de vrai, avec un `curl` instrumenté en tête de PATH qui rend le
code que l'épreuve décide. Quatre épreuves : transitoire (rien ne bouge), succès (le fichier part),
refus permanent (mis à l'écart, compté, avoué), spool plein (les plus anciens partent, compté, avoué).
Chaque épreuve VALIDE l'instrument avant de juger (le stub est bien celui qui répond).
"""
import os, shutil, stat, subprocess, sys, tempfile, time

SHIP = "collectors/ship.sh"
LIB = "collectors/lib.sh"


def echec(msg):
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def lancer(base, code, fichiers, plafond=None):
    """Lance ship.sh sur `fichiers` (nom -> contenu) avec un curl qui rend `code` ; rend (rc, stderr, spool, state)."""
    d = tempfile.mkdtemp(dir=base)
    binz, spool, state = os.path.join(d, "bin"), os.path.join(d, "spool"), os.path.join(d, "state")
    os.makedirs(binz); os.makedirs(spool); os.makedirs(state)
    journal = os.path.join(d, "curl.txt")
    with open(os.path.join(binz, "curl"), "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n"
                f'echo "appel" >> "{journal}"\n'
                'cat >/dev/null\n'          # avale l\'auth passée par stdin (-K -)
                f'printf "%s" "{code}"\n')
    os.chmod(os.path.join(binz, "curl"), 0o755)
    for i, (nom, contenu) in enumerate(fichiers):
        p = os.path.join(spool, nom)
        open(p, "w", encoding="utf-8").write(contenu)
        # ordre d'ancienneté explicite : le premier est le plus ancien
        t = time.time() - 1000 + i
        os.utime(p, (t, t))
    env = dict(os.environ, PATH=binz + os.pathsep + os.environ.get("PATH", ""), PLUME_SPOOL=spool,
               PLUME_STATE=state, PLUME_CENTRAL="http://central.invalid", PLUME_TOKEN="t",
               PLUME_LIB=os.path.abspath(LIB))
    if plafond is not None:
        env["PLUME_SPOOL_MAX_FILES"] = str(plafond)
    r = subprocess.run(["sh", os.path.abspath(SHIP)], env=env, capture_output=True, text=True)
    appels = os.path.exists(journal) and open(journal, encoding="utf-8").read().count("appel")
    return r, spool, state, appels


def fichiers_du_spool(spool):
    return sorted(f for f in os.listdir(spool) if not f.startswith("."))


def aveux(spool, motif):
    return [f for f in os.listdir(spool) if f.startswith("config-availability-ship-") and motif in open(os.path.join(spool, f), encoding="utf-8").read()]


def main():
    if shutil.which("sh") is None:
        echec("aucun `sh` : la jambe exécutée ne peut pas rendre de verdict")
    with tempfile.TemporaryDirectory() as base:
        # (1) TRANSITOIRE : rien ne part, rien n'est perdu, l'instrument a bien été appelé.
        r, spool, state, appels = lancer(base, "000", [("a.json", "{}"), ("b.json", "{}")])
        if not appels:
            echec("instrument : le curl instrumenté n'a jamais été appelé — l'épreuve ne mesure rien")
        if fichiers_du_spool(spool) != ["a.json", "b.json"]:
            echec(f"transitoire (000) : le spool a changé — {fichiers_du_spool(spool)}")
        # (2) SUCCÈS : le fichier part.
        r, spool, state, appels = lancer(base, "202", [("a.json", "{}")])
        if fichiers_du_spool(spool):
            echec(f"succès (202) : le fichier expédié est resté — {fichiers_du_spool(spool)}")
        # (3) REFUS PERMANENT : mis à l'écart, compté, avoué — et pas réexpédié au passage suivant.
        r, spool, state, appels = lancer(base, "422", [("poison.json", "{bad"), ("sain.json", "{}")])
        ecartes = sorted(os.listdir(os.path.join(state, "refuses"))) if os.path.isdir(os.path.join(state, "refuses")) else []
        if ecartes != ["poison.json", "sain.json"]:
            echec(f"refus permanent (422) : les fichiers refusés ne sont pas mis à l'écart — refuses/={ecartes}, spool={fichiers_du_spool(spool)}")
        if not aveux(spool, "ingest-refused") or not aveux(spool, "2 fichier(s) refus"):
            echec("refus permanent : aucun aveu `ingest-refused` portant le COMPTE (2) déposé dans le spool — la perte serait silencieuse ou non comptée")
        # (4) SPOOL PLEIN : les PLUS ANCIENS partent, le signal courant reste, compté, avoué.
        noms = [(f"e{i}.json", "{}") for i in range(6)]
        r, spool, state, appels = lancer(base, "000", noms, plafond=3)
        restants = [f for f in fichiers_du_spool(spool) if f.startswith("e")]
        if restants != ["e3.json", "e4.json", "e5.json"]:
            echec(f"spool plein (6 fichiers, plafond 3) : restent {restants}, attendu les trois plus récents")
        if not aveux(spool, "spool-full") or not aveux(spool, "3 fichier(s) les plus anciens"):
            echec("spool plein : aucun aveu `spool-full` portant le COMPTE (3) déposé — l'éviction serait silencieuse ou non comptée")
        # (5) TÉMOIN INVERSE : sous le plafond, rien n'est évincé et aucun aveu n'est déposé.
        r, spool, state, appels = lancer(base, "000", [("x.json", "{}"), ("y.json", "{}")], plafond=3)
        if fichiers_du_spool(spool) != ["x.json", "y.json"] or aveux(spool, "spool-full"):
            echec("témoin inverse : sous le plafond, le spool a bougé ou un aveu a été déposé")
    print("ship.sh : transitoire conservé, succès expédié, refus permanent écarté+compté+avoué, spool plein évincé (plus anciens)+compté+avoué, témoin inverse muet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
