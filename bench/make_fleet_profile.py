#!/usr/bin/env python3
"""bench/make_fleet_profile.py — DÉRIVE un profil FLOTTE depuis le profil MESURÉ.

LE TROU QU'IL BOUCHE
  `bench/profile-prod.json` est mesuré sur une production MONO-NŒUD : ses 32 sources ont toutes
  `distinct_hosts: 1`. Or `host` est l'une des six colonnes indexées. Toute mesure qui filtre ou
  groupe par hôte porte donc sur un cas DÉGÉNÉRÉ de cardinalité 1, et ne dit rien de ce qu'obtient
  quelqu'un qui installe plume sur une flotte. Exemple mesuré : `auditd` pèse 537 272 événements sur
  29 jours POUR UN SEUL HÔTE ; 50 machines en donneraient ~27 M par mois pour cette seule source.

CE QUE CE SCRIPT DÉRIVE, ET CE QU'IL NE TOUCHE PAS
  DÉRIVÉ (et marqué comme tel, section `sources` -> `provenance: "derived"`) :
    * le POIDS `n` de chaque source host-locale, multiplié par le nombre d'hôtes ;
    * `bench_target.hosts` = le nombre d'hôtes, qui devient la cardinalité de la colonne `host`.
  REPRIS TEL QUEL DU MESURÉ (aucune retouche, la provenance `measured` reste vraie) :
    * par source : severity, categories, longueurs de message et de `fields`, clés étendues avec
      leurs types/longueurs/cardinalités, taux de présence de `src_ip` ;
    * la courbe horaire, les histogrammes de longueur, les cardinalités de colonnes, le disque.

CE QU'IL REFUSE DE DEVINER
  Une source qui tourne SUR CHAQUE MACHINE (auditd, sshd, pare-feu hôte) multiplie son volume par le
  nombre d'hôtes. Une source ÉMISE UNE FOIS pour toute la flotte (plan de contrôle, journal d'un
  service, flux d'un fournisseur) ne le multiplie pas. Le profil mesuré étant MONO-HÔTE, il ne
  contient AUCUNE trace permettant de trancher : `distinct_hosts` vaut 1 partout, y compris pour les
  sources qui seraient centrales. Le script REFUSE donc de classer tout seul — `--per-host` est
  OBLIGATOIRE. Lancé sans, il imprime les sources avec les indices disponibles et s'arrête. Un
  classement deviné et présenté comme un profil serait exactement l'erreur que ce banc interdit.

USAGE
  python3 bench/make_fleet_profile.py --hosts 50 --per-host @bench/fleet-per-host.txt \\
      -o bench/profile-fleet-50.json
  python3 bench/make_fleet_profile.py --hosts 50            # imprime les sources et s'arrête
"""
import argparse
import hashlib
import json
import os
import sys

# Indices — PAS une règle de classement. Une clé étendue produite par le contexte d'un PROCESSUS
# LOCAL (pid, uid, exécutable, unité systemd, conteneur) est un signe qu'un émetteur tourne sur la
# machine. L'absence de ces clés ne prouve RIEN dans l'autre sens : un pare-feu d'hôte n'émet que des
# clés réseau et tourne pourtant sur chaque machine. C'est pour ça que ces indices ne décident pas.
LOCAL_PROCESS_KEYS = {
    "pid", "ppid", "uid", "gid", "auid", "comm", "exe", "syscall", "tty", "cwd",
    "unit", "session", "proc", "jail", "container", "pod", "image",
}


def read_list(spec):
    """`a,b,c` ou `@fichier` (un nom par ligne, `#` = commentaire)."""
    if not spec:
        return []
    if spec.startswith("@"):
        out = []
        with open(spec[1:], encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
        return out
    return [x.strip() for x in spec.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=os.path.join(os.path.dirname(__file__), "profile-prod.json"))
    ap.add_argument("--hosts", type=int, required=True, help="taille de la flotte (paramètre EXPLICITE)")
    ap.add_argument("--per-host", default="", help="sources HOST-LOCALES : `a,b` ou `@fichier`. "
                    "OBLIGATOIRE — le profil mesuré étant mono-hôte, rien ne permet de le déduire.")
    ap.add_argument("--events", type=int, default=None, help="bench_target.events du profil produit")
    ap.add_argument("-o", "--out", help="fichier JSON à écrire")
    a = ap.parse_args()

    raw = open(a.profile, "rb").read()
    p = json.loads(raw.decode("utf-8"))
    src_sha = hashlib.sha256(raw).hexdigest()
    names = [s["name"] for s in p["sources"]["list"]]

    per_host = read_list(a.per_host)
    if not per_host:
        print("--per-host est OBLIGATOIRE. Le profil mesuré est MONO-HÔTE (distinct_hosts=1 pour")
        print("les 32 sources) : il ne porte aucune trace disant quelles sources tournent sur CHAQUE")
        print("machine. Deviner à votre place produirait un profil dont la moitié serait inventée.")
        print("\nSources mesurées, avec le SEUL indice disponible (clés de processus local) :\n")
        for s in p["sources"]["list"]:
            keys = {f["key"] for f in (s.get("fields") or [])}
            hit = sorted(keys & LOCAL_PROCESS_KEYS)
            print(f"  {s['name']:22} n={s['n']:>7}  indice={','.join(hit) if hit else '(aucun)'}")
        print("\nL'absence d'indice ne prouve pas qu'une source est centrale : un pare-feu d'hôte")
        print("n'émet que des clés réseau et tourne pourtant sur chaque machine. À vous de trancher.")
        return 2

    unknown = [x for x in per_host if x not in names]
    if unknown:
        sys.exit(f"--per-host nomme des sources absentes du profil : {', '.join(unknown)}")
    if a.hosts < 1:
        sys.exit("--hosts doit valoir au moins 1")

    per_host_set = set(per_host)
    total_measured = sum(s["n"] for s in p["sources"]["list"])
    scaled = []
    for s in p["sources"]["list"]:
        s2 = dict(s)
        mult = a.hosts if s["name"] in per_host_set else 1
        s2["n_measured_mono_host"] = s["n"]
        s2["hosts_multiplier"] = mult
        s2["scaling"] = "per_host" if mult > 1 else "central"
        s2["scaling_declared_by"] = "--per-host (opérateur)" if mult > 1 else "non déclaré host-local"
        s2["n"] = s["n"] * mult
        # `distinct_hosts` MESURÉ vaut 1 : la valeur de flotte est DÉRIVÉE, on garde les deux.
        s2["distinct_hosts_measured"] = s.get("distinct_hosts")
        s2["distinct_hosts"] = a.hosts if mult > 1 else s.get("distinct_hosts")
        scaled.append(s2)
    total_fleet = sum(s["n"] for s in scaled)

    p["sources"] = {
        "provenance": "derived",
        "_derived_what": (
            "SEUL le champ `n` (le POIDS de la source dans le mélange) est dérivé : il est multiplié "
            f"par {a.hosts} pour les sources DÉCLARÉES host-locales, et laissé tel quel pour les "
            "autres. `n_measured_mono_host` garde la valeur mesurée de chaque source. Toutes les "
            "autres distributions (severity, categories, msg_len, fields_len, clés étendues avec "
            "leurs types/longueurs/cardinalités, taux de src_ip) sont REPRISES TELLES QUELLES du "
            "profil mesuré, sans retouche."),
        "_derived_from": {"file": os.path.basename(a.profile), "sha256": src_sha},
        "_classification": (
            "host-local vs central est une DÉCLARATION D'OPÉRATEUR, pas une mesure : le profil source "
            "est mono-nœud (distinct_hosts=1 partout), il ne contient rien qui permette de trancher. "
            "Chaque source porte `scaling` et `scaling_declared_by`."),
        "_non_derive": (
            "NE SONT PAS multipliés, et c'est délibéré : la cardinalité des `src_ip` (une flotte plus "
            "grande ne crée pas plus de clients sur Internet), le vocabulaire des messages, la courbe "
            "horaire, et la densité par hôte (chaque hôte émet ce que l'hôte mesuré émettait)."),
        "list": scaled,
    }
    p["fleet"] = {
        "provenance": "derived",
        "hosts": a.hosts,
        "per_host_sources": sorted(per_host_set),
        "central_sources": sorted(set(names) - per_host_set),
        "events_measured_mono_host": total_measured,
        "events_fleet_derived": total_fleet,
        "multiplier_effective": round(total_fleet / max(total_measured, 1), 3),
        "_note_host_uniform": (
            "le générateur répartit les événements UNIFORMÉMENT sur les hôtes. Une vraie flotte est "
            "déséquilibrée (quelques machines bruyantes). L'uniforme est le cas le PLUS DUR pour un "
            "group-by (tous les groupes sont peuplés) et le plus FACILE pour un filtre sur un hôte "
            "(sélectivité exactement 1/N) — c'est une hypothèse de banc, pas une mesure."),
    }
    bt = dict(p["bench_target"])
    bt["hosts"] = a.hosts
    bt["_hosts_rationale"] = (
        f"DÉRIVÉ : flotte de {a.hosts} hôtes. La production mesurée est MONO-NŒUD (host=1 pour les 32 "
        "sources) : garder sa cardinalité rendrait tout group-by et tout filtre sur `host` "
        "artificiellement gratuit — un seul groupe, un seul seek — et les chiffres publiés ne "
        "vaudraient que pour un laboratoire à une machine.")
    bt["_fleet_derivation"] = (
        f"volume mensuel dérivé : {total_fleet} événements sur la fenêtre mesurée "
        f"({p['volume']['span_days']} j) contre {total_measured} mesurés en mono-hôte, soit "
        f"x{total_fleet/max(total_measured,1):.2f}.")
    if a.events:
        bt["events"] = a.events
    p["bench_target"] = bt
    p["_lisez_moi"] = (
        f"Profil FLOTTE ({a.hosts} hôtes) DÉRIVÉ de {os.path.basename(a.profile)} par "
        "bench/make_fleet_profile.py. Les distributions par source sont celles, MESURÉES, de la "
        "production mono-nœud ; ce qui est dérivé est le nombre d'hôtes et le poids des sources "
        "host-locales. Chaque section porte sa `provenance` : ne jamais lire une section `derived` "
        "comme une mesure.")

    out = json.dumps(p, ensure_ascii=False, indent=1) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"écrit : {a.out}")
    else:
        sys.stdout.write(out)
    print(f"hôtes={a.hosts}  sources host-locales={len(per_host_set)}/{len(names)}  "
          f"poids total {total_measured} -> {total_fleet} (x{total_fleet/max(total_measured,1):.2f})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
